using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

public sealed record VaultManifest(int LayoutVersion, string VaultId, string DirectoryIdentity, string OwnerSid);
public sealed record VersionManifest(int FormatVersion, string VaultId, string StorageVersion, string AttemptId, string KeyId, string MigrationHash, SealedBytes? KeyCheck = null);
public sealed record InitialRecord(string CredentialId, string ContentType, int PayloadFormatVersion, string Payload,
  Dictionary<string, string> Metadata, string? CoordinationKey = null);
public sealed record InitializeRequest(string OperationId, string SourceWatermark, InitialRecord[] Records);
public sealed record InitializeResult(string StorageVersion, string AttemptId, string KeyId, string State, string? MigrationKey);
public sealed record ReadyRequest(string OperationId, string SourceWatermark, string ChallengeId, string Proof);
public sealed record HandoffRequest(string OperationId, string SourceWatermark, string[] RequiredClientIds);
public sealed record ProofChallenge(string ChallengeId, string Nonce, long ExpiresAt);

public sealed class Vault : IDisposable
{
  public BrokerPlatform Platform { get; }
  public string Root { get; }
  public VaultManifest Manifest { get; }
  public string KeysRoot { get; }
  public Database Control { get; }
  private readonly FileStream vaultLock;
  public Action<string>? Fault { get; set; }

  private Vault(string root, string keysRoot, FileStream held, VaultManifest manifest, BrokerPlatform platform)
  {
    Platform = platform;
    Root = root;
    KeysRoot = Platform.Files.CreatePrivateDirectory(keysRoot);
    Manifest = manifest;
    vaultLock = held;
    Control = new Database(Path.Combine(root, "control.db"));
    Control.Execute("""
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS receipts (operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, request_hash TEXT NOT NULL, result TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, grant_json TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS ready (client_id TEXT PRIMARY KEY, storage_version TEXT NOT NULL, watermark TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
      """);
    Control.Execute("INSERT OR IGNORE INTO settings VALUES ('schemaVersion','1')");
    Protocol.Require(Setting("schemaVersion") == "1", "storage-incompatible");
  }

  public static Vault Open(string path, string keysRoot, bool create = false, BrokerPlatform? platform = null)
  {
    platform ??= BrokerPlatform.Current;
    var root = create ? platform.Files.CreatePrivateDirectory(path) : LocalFiles.FullPath(path);
    Protocol.Require(Directory.Exists(root), "vault-not-found");
    platform.Files.ValidateTree(root);
    var runtime = platform.Files.CreatePrivateDirectory(Path.Combine(root, "runtime"));
    var held = LocalFiles.AcquireLock(Path.Combine(runtime, "vault.lock"));
    try
    {
      var manifestPath = Path.Combine(root, "manifest.json");
      VaultManifest manifest;
      if (File.Exists(manifestPath))
      {
        manifest = Protocol.Decode<VaultManifest>(Protocol.Parse(File.ReadAllBytes(manifestPath)));
        Protocol.Require(manifest.LayoutVersion == 1 && manifest.OwnerSid == platform.Identity.CurrentUserId &&
          manifest.DirectoryIdentity == platform.Files.DirectoryIdentity(root), "vault-identity-mismatch");
        Protocol.Id(manifest.VaultId);
        Protocol.Require(File.Exists(Path.Combine(root, "control.db")) || !Directory.Exists(Path.Combine(root, "versions")) ||
          !Directory.EnumerateFileSystemEntries(Path.Combine(root, "versions")).Any(), "control-database-missing");
      }
      else
      {
        Protocol.Require(create && !File.Exists(Path.Combine(root, "control.db")), "manifest-missing");
        manifest = new(1, Crypto.RandomId(), platform.Files.DirectoryIdentity(root), platform.Identity.CurrentUserId);
        LocalFiles.WriteAtomic(manifestPath, Protocol.Encode(manifest));
      }
      platform.Files.CreatePrivateDirectory(Path.Combine(root, "versions"));
      return new(root, keysRoot, held, manifest, platform);
    }
    catch { held.Dispose(); throw; }
  }

  public string? Setting(string name) => Control.Scalar("SELECT value FROM settings WHERE key=$key", ("$key", name)) as string;
  public void Set(string name, string value) => Control.Execute("INSERT INTO settings VALUES ($key,$value) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("$key", name), ("$value", value));
  public string VersionPath(string version) => Path.Combine(Root, "versions", Protocol.Id(version));
  public string KeyPath(string keyId) => Path.Combine(KeysRoot, Manifest.VaultId + "." + Protocol.Id(keyId) + Platform.Secrets.FileExtension);
  public VersionManifest CurrentVersion()
  {
    var version = Setting("currentVersion") ?? throw new BrokerException("vault-uninitialized");
    var path = VersionPath(version);
    Platform.Files.ValidateTree(path);
    var result = Protocol.Decode<VersionManifest>(Protocol.Parse(File.ReadAllBytes(Path.Combine(path, "version.json"))));
    Protocol.Require(result.FormatVersion == 1 && result.StorageVersion == version && result.VaultId == Manifest.VaultId, "version-mismatch");
    var transfer = File.ReadAllBytes(Path.Combine(path, "migration.json"));
    Protocol.Require(Crypto.Hash(transfer) == result.MigrationHash, "migration-digest-mismatch");
    return result;
  }
  public byte[] LoadKey(VersionManifest version) => Platform.Secrets.Unprotect(File.ReadAllBytes(KeyPath(version.KeyId)), KeyPurpose(version));
  private string KeyPurpose(VersionManifest v) => $"vault:{v.VaultId}:{v.StorageVersion}:{v.AttemptId}:{v.KeyId}";
  public static byte[] KeyCheckAad(VersionManifest v) => CanonicalJson.Of(new[] { "astra.key-check.v1", v.VaultId, v.StorageVersion, v.AttemptId, v.KeyId });
  public static void VerifyKey(VersionManifest v, byte[] key)
  {
    Protocol.Require(v.KeyCheck is not null, "key-check-missing");
    var plain = Crypto.Decrypt(key, v.KeyCheck!, KeyCheckAad(v));
    try { Protocol.Require(Encoding.UTF8.GetString(plain) == "astra-key-check-v1", "invalid-master-key"); }
    finally { CryptographicOperations.ZeroMemory(plain); }
  }
  public void SaveKey(VersionManifest version, byte[] key)
  {
    Protocol.Require(key.Length == 32, "invalid-master-key");
    LocalFiles.WriteAtomic(KeyPath(version.KeyId), Platform.Secrets.Protect(key, KeyPurpose(version)));
    var check = LoadKey(version);
    try { Protocol.Require(CryptographicOperations.FixedTimeEquals(check, key), "key-readback-failed"); }
    finally { CryptographicOperations.ZeroMemory(check); }
  }

  public InitializeResult Initialize(Actor actor, InitializeRequest request)
  {
    actor.Demand("initialize");
    Protocol.Id(request.OperationId);
    Protocol.Require(request.SourceWatermark.Length is > 0 and <= 1024 && request.Records.Length <= 1000, "invalid-initialization");
    var hash = Crypto.HashObject(request);
    var receipt = Receipt<InitializeResult>(request.OperationId, "initialize", actor.ClientId, hash);
    if (receipt is not null) return receipt;
    Protocol.Require(Setting("currentVersion") is null, "already-published");
    // A unique directory/version is never reused, including after a failed candidate.
    var versionId = Crypto.RandomId();
    var attemptId = Crypto.RandomId();
    var keyId = Crypto.RandomId();
    // Resolve the key slot before creating a candidate. A missing protection provider
    // must not leave a partially prepared version or mask failure during cleanup.
    var keyPath = KeyPath(keyId);
    var path = Platform.Files.CreatePrivateDirectory(VersionPath(versionId));
    var key = RandomNumberGenerator.GetBytes(32);
    var published = false;
    try
    {
      var records = new List<Credential>();
      var ids = new HashSet<string>(StringComparer.Ordinal);
      var provisional = new VersionManifest(1, Manifest.VaultId, versionId, attemptId, keyId, "");
      provisional = provisional with { KeyCheck = Crypto.Encrypt(key, Encoding.UTF8.GetBytes("astra-key-check-v1"), KeyCheckAad(provisional)) };
      using (var store = new CredentialStore(this, provisional, key, create: true))
      {
        foreach (var input in request.Records)
        {
          Protocol.Require(ids.Add(input.CredentialId), "duplicate-credential-id");
          records.Add(store.InsertInitial(actor, input));
        }
        Fault?.Invoke("initial-records-written");
        var snapshot = new TransferSnapshot(Manifest.VaultId, versionId, attemptId, keyId, Crypto.B64(key), records.ToArray());
        var (package, migrationKey) = Crypto.Pack(snapshot);
        Protocol.Require(Crypto.HashObject(Crypto.Unpack(package, migrationKey)) == Crypto.HashObject(snapshot), "transfer-readback-failed");
        var bytes = Protocol.Encode(package);
        Protocol.Require(bytes.Length <= Protocol.MaxMessageBytes, "message-too-large");
        LocalFiles.WriteAtomic(Path.Combine(path, "migration.json"), bytes);
        var readback = File.ReadAllBytes(Path.Combine(path, "migration.json"));
        Protocol.Require(Crypto.Hash(readback) == Crypto.Hash(bytes) &&
          Crypto.HashObject(Crypto.Unpack(Protocol.Decode<TransferPackage>(Protocol.Parse(readback)), migrationKey)) == Crypto.HashObject(snapshot), "transfer-readback-failed");
        var version = provisional with { MigrationHash = Crypto.Hash(bytes) };
        LocalFiles.WriteAtomic(Path.Combine(path, "version.json"), Protocol.Encode(version));
        Protocol.Require(Crypto.HashObject(Protocol.Decode<VersionManifest>(Protocol.Parse(File.ReadAllBytes(Path.Combine(path, "version.json"))))) ==
          Crypto.HashObject(version), "version-readback-failed");
        Fault?.Invoke("migration-written");
        // Export delivery recovery is separate from the normal receipt. Never expose it via getOperation.
        LocalFiles.WriteAtomic(Path.Combine(KeysRoot, Manifest.VaultId + ".delivery" + Platform.Secrets.FileExtension),
          Platform.Secrets.Protect(Encoding.UTF8.GetBytes(migrationKey), "delivery:" + Manifest.VaultId));
        SaveKey(version, key);
        Fault?.Invoke("key-saved");
        foreach (var item in records)
          Protocol.Require(Crypto.HashObject(store.Get(actor, item.Description.CredentialId)) == Crypto.HashObject(item), "record-readback-failed");
        var result = new InitializeResult(versionId, attemptId, keyId, "exported", null);
        Control.Atomic(() =>
        {
          Set("currentVersion", versionId);
          Set("sourceClientId", actor.ClientId);
          Set("sourceWatermark", request.SourceWatermark);
          Set("ownership", "source");
          WriteReceipt(request.OperationId, "initialize", actor.ClientId, hash, result);
          return true;
        });
        published = true;
        Fault?.Invoke("published");
        return result with { MigrationKey = migrationKey };
      }
    }
    finally
    {
      CryptographicOperations.ZeroMemory(key);
      if (!published && Setting("currentVersion") != versionId)
      {
        // Only this attempt's unpublished directory is eligible for cleanup.
        Directory.Delete(path, true);
        if (File.Exists(keyPath)) File.Delete(keyPath);
      }
    }
  }

  public string RecoverDelivery(Actor actor)
  {
    actor.Demand("initialize");
    Protocol.Require(actor.ClientId == Setting("sourceClientId") && Setting("deliveryAcknowledged") != "true", "delivery-unavailable");
    var bytes = Platform.Secrets.Unprotect(File.ReadAllBytes(Path.Combine(KeysRoot, Manifest.VaultId + ".delivery" + Platform.Secrets.FileExtension)), "delivery:" + Manifest.VaultId);
    try { return Encoding.UTF8.GetString(bytes); }
    finally { CryptographicOperations.ZeroMemory(bytes); }
  }
  public void AcknowledgeDelivery(Actor actor)
  {
    actor.Demand("initialize");
    Protocol.Require(actor.ClientId == Setting("sourceClientId"), "forbidden");
    Set("deliveryAcknowledged", "true");
    var path = Path.Combine(KeysRoot, Manifest.VaultId + ".delivery" + Platform.Secrets.FileExtension);
    if (File.Exists(path)) File.Delete(path);
  }

  public T? Receipt<T>(string operationId, string kind, string clientId, string hash) where T : class
  {
    var rows = Control.Rows("SELECT kind,client_id,request_hash,result FROM receipts WHERE operation_id=$id",
      r => (r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)), ("$id", operationId));
    if (rows.Count == 0) return null;
    var row = rows[0];
    Protocol.Require(row.Item1 == kind && row.Item2 == clientId && row.Item3 == hash, "operation-conflict");
    return Protocol.Decode<T>(Protocol.Parse(Encoding.UTF8.GetBytes(row.Item4)));
  }
  public void WriteReceipt<T>(string id, string kind, string clientId, string hash, T result) => Control.Execute(
    "INSERT INTO receipts VALUES ($id,$kind,$client,$hash,$result)", ("$id", id), ("$kind", kind), ("$client", clientId),
    ("$hash", hash), ("$result", JsonSerializer.Serialize(result, Protocol.Json)));

  public void Dispose() { Control.Dispose(); vaultLock.Dispose(); }
}
