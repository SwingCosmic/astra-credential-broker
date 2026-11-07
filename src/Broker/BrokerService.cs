using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

public sealed record ServiceStatus([property: System.Text.Json.Serialization.JsonPropertyName("serviceStatus")] string ServiceStatusValue, string VaultId, string? StorageVersion,
  string Ownership, string Generation, int Sessions, string? ErrorCode);
public sealed record RegisterClient(string ClientId, string[] Scopes, string[] CredentialIds, bool AllCredentials = false);
public sealed record RegisteredClient(string ClientId, string AccessToken);
public sealed record MigrationValidation(string VaultId, string StorageVersion, string AttemptId, string KeyId, int RecordCount);
public sealed record Session(Actor Actor, long ExpiresAt);
public sealed record UnlockRequest(string MasterKey);
public sealed record ValidateMigration(string MigrationKey);
public sealed record SharingState(string VaultId, string StorageVersion, string AttemptId, string KeyId,
  string SourceWatermark, string SourceClientId, string[] PreparedClientIds, string Ownership);

public sealed class BrokerService : IDisposable
{
  private readonly object gate = new();
  private readonly Vault vault;
  public BrokerPlatform Platform => vault.Platform;
  private CredentialStore? store;
  private byte[]? masterKey;
  private readonly BrokerClock clock;
  private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
  private string? error;
  private bool draining;
  private long? idleSince;
  private long? drainSince;
  private TaskCompletionSource changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
  public string Generation { get; } = Crypto.RandomId();
  public bool ExitRequested { get; private set; }
  public const long SessionTtl = 45_000;
  public const long IdleTimeout = 60_000;
  public const long DrainTimeout = 30_000;
  public Action<string>? Fault { get; set; }
  public BrokerService(Vault vault, BrokerClock? clock = null)
  {
    this.vault = vault;
    this.clock = clock ?? new();
    TryLoad();
  }
  private void TryLoad()
  {
    if (vault.Setting("currentVersion") is null) return;
    var version = vault.CurrentVersion();
    try
    {
      var key = vault.LoadKey(version);
      try { OpenStore(version, key); }
      finally { CryptographicOperations.ZeroMemory(key); }
    }
    catch (Exception ex) when (ex is CryptographicException or FileNotFoundException or UnauthorizedAccessException)
    { error = "key-unavailable"; }
  }
  private void OpenStore(VersionManifest version, byte[] key)
  {
    var candidate = new CredentialStore(vault, version, key, Generation, clock);
    try
    {
      // A key must authenticate actual stored records before it becomes an unlock key.
      var admin = new Actor("management", "management", [], [], true, true);
      _ = candidate.List(admin, new());
    }
    catch { candidate.Dispose(); throw; }
    store?.Dispose();
    if (masterKey is not null) CryptographicOperations.ZeroMemory(masterKey);
    masterKey = key.ToArray();
    store = candidate;
    error = null;
  }
  private CredentialStore Store => store ?? throw new BrokerException("vault-locked");
  private static string SessionKey(Actor actor) => actor.ClientId + ":" + actor.InstanceId;
  public ClientGrant? Grant(string clientId)
  {
    lock (gate)
    {
      var json = vault.Control.Scalar("SELECT grant_json FROM clients WHERE client_id=$id AND revoked=0", ("$id", clientId)) as string;
      return json is null ? null : Protocol.Decode<ClientGrant>(Protocol.Parse(Encoding.UTF8.GetBytes(json)));
    }
  }
  public void Connect(Actor actor)
  {
    lock (gate)
    {
      Protocol.Require(!draining, "service-draining");
      Protocol.Id(actor.ClientId);
      Protocol.Id(actor.InstanceId);
      sessions[SessionKey(actor)] = new(actor, clock.Now + SessionTtl);
      idleSince = null;
    }
  }
  private void Touch(Actor actor)
  {
    var id = SessionKey(actor);
    Protocol.Require(sessions.TryGetValue(id, out var session) && session.ExpiresAt > clock.Now, "session-expired");
    if (!actor.IsAdmin) Protocol.Require(Grant(actor.ClientId) is not null, "client-revoked");
    sessions[id] = new(actor, clock.Now + SessionTtl);
  }
  public ServiceStatus Status()
  {
    lock (gate)
      return new(draining ? "DRAINING" : vault.Setting("currentVersion") is not null && store is null ? "LOCKED" :
        idleSince is not null ? "IDLE" : "READY", vault.Manifest.VaultId, vault.Setting("currentVersion"),
        vault.Setting("ownership") ?? "uninitialized", Generation, sessions.Count, error);
  }
  private void DemandOwnership()
  {
    Protocol.Require(!draining, "service-draining");
    Protocol.Require(vault.Setting("ownership") == "broker", "ownership-not-transferred");
  }
  public object Dispatch(Actor actor, string method, JsonElement parameters)
  {
    lock (gate)
    {
      Touch(actor);
      if (new[] { "status", "getSharingState", "heartbeat", "disconnect", "recoverDelivery", "acknowledgeDelivery", "prepareChallenge", "stop" }.Contains(method, StringComparer.Ordinal))
        _ = Protocol.Decode<EmptyParameters>(parameters);
      switch (method)
      {
        case "status": return Status();
        case "getSharingState": return GetSharingState(actor);
        case "heartbeat": return new { expiresAt = clock.Now + SessionTtl };
        case "disconnect":
          sessions.Remove(SessionKey(actor));
          store?.Disconnect(actor);
          return new { disconnected = true };
        case "listCredentials": return Store.List(actor, Protocol.Decode<ListCredentials>(parameters));
        case "getCredential": return Store.Get(actor, Protocol.Decode<IdRequest>(parameters).CredentialId);
        case "createCredential":
          DemandOwnership();
          var created = Store.Create(actor, Protocol.Decode<CreateCredential>(parameters));
          PublishChange();
          return created;
        case "beginUpdate": DemandOwnership(); return Store.Begin(actor, Protocol.Decode<BeginUpdate>(parameters));
        case "markUpdateStarted": return Store.MarkStarted(actor, Protocol.Decode<LeaseRef>(parameters));
        case "renewUpdate": return Store.Renew(actor, Protocol.Decode<LeaseRef>(parameters));
        case "commitUpdate":
          var committed = Store.Commit(actor, Protocol.Decode<CommitUpdate>(parameters));
          PublishChange();
          return committed;
        case "abortUpdate": return Store.Abort(actor, Protocol.Decode<AbortUpdate>(parameters));
        case "getOperation": return GetOperation(actor, Protocol.Decode<OperationRequest>(parameters));
        case "cancelQueuedUpdate": return Store.CancelQueued(actor, Protocol.Decode<OperationRequest>(parameters).OperationId);
        case "getEvents":
          var events = Protocol.Decode<EventsRequest>(parameters);
          return Store.Events(actor, events.Cursor, events.Limit);
        case "initialize":
          Protocol.Require(!draining, "service-draining");
          var initialized = vault.Initialize(actor, Protocol.Decode<InitializeRequest>(parameters));
          if (store is null) TryLoad();
          PublishChange();
          return initialized;
        case "recoverDelivery": return new { migrationKey = vault.RecoverDelivery(actor) };
        case "acknowledgeDelivery": vault.AcknowledgeDelivery(actor); return new { acknowledged = true };
        case "validateMigration": return Validate(actor, Protocol.Decode<ValidateMigration>(parameters));
        case "prepareChallenge": return Challenge(actor);
        case "prepareClient": return Prepare(actor, Protocol.Decode<ReadyRequest>(parameters));
        case "handoff": return Handoff(actor, Protocol.Decode<HandoffRequest>(parameters));
        case "registerClient": DemandAdmin(actor); return Register(Protocol.Decode<RegisterClient>(parameters));
        case "revokeClient":
          DemandAdmin(actor);
          var clientId = Protocol.Decode<ClientIdRequest>(parameters).ClientId;
          vault.Control.Execute("UPDATE clients SET revoked=1 WHERE client_id=$id", ("$id", Protocol.Id(clientId)));
          foreach (var pair in sessions.Where(p => p.Value.Actor.ClientId == clientId).ToArray())
          { store?.Disconnect(pair.Value.Actor); sessions.Remove(pair.Key); }
          return new { revoked = true };
        case "unlock":
          DemandAdmin(actor);
          var key = Crypto.Unb64(Protocol.Decode<UnlockRequest>(parameters).MasterKey, 32);
          try
          {
            var version = vault.CurrentVersion();
            OpenStore(version, key);
            vault.SaveKey(version, key);
            return Status();
          }
          finally { CryptographicOperations.ZeroMemory(key); }
        case "stop":
          DemandAdmin(actor);
          draining = true;
          drainSince ??= clock.Now;
          return Status();
        default: throw new BrokerException("method-not-found");
      }
    }
  }
  private void PublishChange()
  {
    var previous = changed;
    changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    previous.TrySetResult();
  }
  private SharingState GetSharingState(Actor actor)
  {
    Protocol.Require(actor.IsAdmin || actor.Scopes.Contains("import", StringComparer.Ordinal) ||
      actor.Scopes.Contains("handoff", StringComparer.Ordinal), "forbidden");
    var version = vault.CurrentVersion();
    var watermark = vault.Setting("sourceWatermark") ?? throw new BrokerException("not-published");
    var prepared = vault.Control.Rows("SELECT ready.client_id FROM ready JOIN clients ON clients.client_id=ready.client_id WHERE ready.storage_version=$version AND ready.watermark=$watermark AND clients.revoked=0 ORDER BY ready.client_id",
      r => r.GetString(0), ("$version", version.StorageVersion), ("$watermark", watermark));
    return new(vault.Manifest.VaultId, version.StorageVersion, version.AttemptId, version.KeyId, watermark,
      vault.Setting("sourceClientId")!, prepared.ToArray(), vault.Setting("ownership")!);
  }
  public async Task<EventPage> Watch(Actor actor, WatchEventsRequest request, CancellationToken cancellationToken)
  {
    Protocol.Require(request.WaitMilliseconds is >= 0 and <= 5000, "invalid-watch-timeout");
    Task pending;
    lock (gate)
    {
      Touch(actor);
      var current = Store.Events(actor, request.Cursor, request.Limit);
      if (current.Items.Length > 0 || current.NextCursor != request.Cursor) return current;
      pending = changed.Task;
    }
    try { await pending.WaitAsync(TimeSpan.FromMilliseconds(request.WaitMilliseconds), cancellationToken); }
    catch (TimeoutException) { }
    lock (gate)
    {
      Touch(actor);
      return Store.Events(actor, request.Cursor, request.Limit);
    }
  }
  private object GetOperation(Actor actor, OperationRequest request)
  {
    var rows = vault.Control.Rows("SELECT client_id,result FROM receipts WHERE operation_id=$id", r => (r.GetString(0), r.GetString(1)), ("$id", Protocol.Id(request.OperationId)));
    if (rows.Count == 0) return Store.GetOperation(actor, request.OperationId);
    Protocol.Require(actor.IsAdmin || rows[0].Item1 == actor.ClientId, "forbidden");
    return Protocol.Parse(Encoding.UTF8.GetBytes(rows[0].Item2));
  }
  private static void DemandAdmin(Actor actor) => Protocol.Require(actor.IsAdmin, "management-required");
  private RegisteredClient Register(RegisterClient request)
  {
    Protocol.Id(request.ClientId);
    var allowed = new[] { "describe", "read", "create", "update", "events", "initialize", "import", "handoff", "delete" };
    Protocol.Require(request.Scopes.Length > 0 && request.Scopes.All(s => allowed.Contains(s, StringComparer.Ordinal)) &&
      request.Scopes.Distinct(StringComparer.Ordinal).Count() == request.Scopes.Length && request.CredentialIds.Length <= 1000, "invalid-grant");
    foreach (var id in request.CredentialIds) Protocol.Id(id);
    // Reissuing credentials requires explicit revocation, never silently rotates an existing stable identity.
    Protocol.Require(vault.Control.Scalar("SELECT client_id FROM clients WHERE client_id=$id", ("$id", request.ClientId)) is null, "client-exists");
    var token = RandomNumberGenerator.GetBytes(32);
    try
    {
      var grant = new ClientGrant(request.ClientId, Crypto.Hash(token), request.Scopes, request.CredentialIds, request.AllCredentials);
      vault.Control.Execute("INSERT INTO clients (client_id,grant_json) VALUES ($id,$grant)", ("$id", request.ClientId), ("$grant", JsonSerializer.Serialize(grant, Protocol.Json)));
      return new(request.ClientId, Crypto.B64(token));
    }
    finally { CryptographicOperations.ZeroMemory(token); }
  }
  private MigrationValidation Validate(Actor actor, ValidateMigration request)
  {
    actor.Demand("import");
    var version = vault.CurrentVersion();
    var package = Protocol.Decode<TransferPackage>(Protocol.Parse(File.ReadAllBytes(Path.Combine(vault.VersionPath(version.StorageVersion), "migration.json"))));
    var snapshot = Crypto.Unpack(package, request.MigrationKey);
    Protocol.Require(snapshot.VaultId == vault.Manifest.VaultId && snapshot.StorageVersion == version.StorageVersion &&
      snapshot.AttemptId == version.AttemptId && snapshot.KeyId == version.KeyId, "snapshot-mismatch");
    // Import validates the complete initial encrypted snapshot; current credentials may have advanced after handoff.
    return new(snapshot.VaultId, snapshot.StorageVersion, snapshot.AttemptId, snapshot.KeyId, snapshot.Records.Length);
  }
  private ProofChallenge Challenge(Actor actor)
  {
    actor.Demand("import");
    var result = new ProofChallenge(Crypto.RandomId(), Crypto.B64(RandomNumberGenerator.GetBytes(32)), clock.Now + 60_000);
    vault.Control.Execute("DELETE FROM challenges WHERE expires_at<=$now OR consumed=1", ("$now", clock.Now));
    vault.Control.Execute("INSERT INTO challenges (id,client_id,nonce,expires_at) VALUES ($id,$client,$nonce,$expires)",
      ("$id", result.ChallengeId), ("$client", actor.ClientId), ("$nonce", result.Nonce), ("$expires", result.ExpiresAt));
    return result;
  }
  public static string ReadyProof(byte[] masterKey, string vaultId, string storageVersion, string clientId, ReadyRequest request, string nonce) =>
    Crypto.B64(HMACSHA256.HashData(masterKey, CanonicalJson.Of(new[] { "astra.prepare.v1", vaultId, storageVersion, clientId,
      request.OperationId, request.SourceWatermark, request.ChallengeId, nonce })));
  private object Prepare(Actor actor, ReadyRequest request)
  {
    actor.Demand("import");
    Protocol.Id(request.OperationId);
    var hash = Crypto.HashObject(request);
    var receipt = vault.Receipt<PreparedResult>(request.OperationId, "prepare", actor.ClientId, hash);
    if (receipt is not null) return receipt;
    var version = vault.CurrentVersion();
    _ = Store;
    var challenges = vault.Control.Rows("SELECT client_id,nonce,expires_at,consumed FROM challenges WHERE id=$id",
      r => (r.GetString(0), r.GetString(1), r.GetInt64(2), r.GetBoolean(3)), ("$id", request.ChallengeId));
    Protocol.Require(challenges.Count == 1, "invalid-challenge");
    var challenge = challenges[0];
    Protocol.Require(challenge.Item1 == actor.ClientId && !challenge.Item4 && challenge.Item3 > clock.Now, "invalid-challenge");
    Protocol.Require(request.SourceWatermark == vault.Setting("sourceWatermark") &&
      Crypto.Equal(ReadyProof(masterKey!, vault.Manifest.VaultId, version.StorageVersion, actor.ClientId, request, challenge.Item2), request.Proof), "invalid-proof");
    return vault.Control.Atomic(() =>
    {
      vault.Control.Execute("UPDATE challenges SET consumed=1 WHERE id=$id", ("$id", request.ChallengeId));
      vault.Control.Execute("INSERT INTO ready VALUES ($client,$version,$watermark) ON CONFLICT(client_id) DO UPDATE SET storage_version=excluded.storage_version,watermark=excluded.watermark",
        ("$client", actor.ClientId), ("$version", version.StorageVersion), ("$watermark", request.SourceWatermark));
      var result = new PreparedResult(version.StorageVersion, "prepared");
      vault.WriteReceipt(request.OperationId, "prepare", actor.ClientId, hash, result);
      return result;
    });
  }
  private object Handoff(Actor actor, HandoffRequest request)
  {
    actor.Demand("handoff");
    Protocol.Id(request.OperationId);
    var hash = Crypto.HashObject(request);
    var receipt = vault.Receipt<HandoffResult>(request.OperationId, "handoff", actor.ClientId, hash);
    if (receipt is not null) return receipt;
    Protocol.Require(!draining && actor.ClientId == vault.Setting("sourceClientId"), "forbidden");
    Protocol.Require(request.SourceWatermark == vault.Setting("sourceWatermark"), "source-watermark-changed");
    Protocol.Require(request.RequiredClientIds.Distinct(StringComparer.Ordinal).Count() >= 2 &&
      request.RequiredClientIds.Contains(actor.ClientId, StringComparer.Ordinal), "participants-required");
    var version = vault.CurrentVersion();
    foreach (var client in request.RequiredClientIds)
      Protocol.Require(Grant(client) is not null && vault.Control.Scalar("SELECT client_id FROM ready WHERE client_id=$client AND storage_version=$version AND watermark=$watermark",
        ("$client", client), ("$version", version.StorageVersion), ("$watermark", request.SourceWatermark)) is not null, "client-not-prepared");
    _ = Store;
    vault.SaveKey(version, masterKey!);
    Fault?.Invoke("handoff-key-saved");
    return vault.Control.Atomic(() =>
    {
      Protocol.Require(vault.Setting("ownership") == "source", "already-transferred");
      vault.Set("ownership", "broker");
      var result = new HandoffResult(version.StorageVersion, "broker");
      vault.WriteReceipt(request.OperationId, "handoff", actor.ClientId, hash, result);
      Fault?.Invoke("handoff-before-commit");
      return result;
    });
  }
  public void Tick()
  {
    lock (gate)
    {
      foreach (var item in sessions.Where(p => p.Value.ExpiresAt <= clock.Now).ToArray())
      { store?.Disconnect(item.Value.Actor); sessions.Remove(item.Key); }
      var pending = store?.HasPending ?? false;
      if (draining)
      {
        if (!pending || clock.Now - drainSince >= DrainTimeout) ExitRequested = true;
        return;
      }
      if (sessions.Count == 0 && !pending)
      {
        idleSince ??= clock.Now;
        if (clock.Now - idleSince >= IdleTimeout)
        { draining = true; drainSince = clock.Now; ExitRequested = true; }
      }
      else idleSince = null;
    }
  }
  public void Dispose()
  {
    lock (gate)
    {
      store?.Dispose();
      if (masterKey is not null) CryptographicOperations.ZeroMemory(masterKey);
      sessions.Clear();
    }
  }
}
public sealed record IdRequest(string CredentialId);
public sealed record EmptyParameters();
public sealed record OperationRequest(string OperationId);
public sealed record ClientIdRequest(string ClientId);
public sealed record EventsRequest(string Cursor = "0", int Limit = 100);
public sealed record WatchEventsRequest(string Cursor = "0", int Limit = 100, int WaitMilliseconds = 5000);
public sealed record PreparedResult(string StorageVersion, string State);
public sealed record HandoffResult(string StorageVersion, string Ownership);
