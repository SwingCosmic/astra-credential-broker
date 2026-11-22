using Microsoft.Data.Sqlite;

namespace Astra.Credentials;

public sealed record ExportTarget(string VaultId, string? RetiredVaultId);

public sealed partial class ComponentManager
{
  private (string Full, VaultRegistration? Registration, string Journal) ExportLocation(string root)
  {
    var full = LocalFiles.FullPath(root);
    Protocol.Require(Path.GetDirectoryName(full) is not null && !ContainsPath(Home, full) && !ContainsPath(full, Home),
      "overlapping-service-and-data-paths");
    var vaults = Vaults();
    Protocol.Require(!vaults.Any(v => !v.Root.Equals(full, Platform.Components.PathComparison) &&
      (ContainsPath(v.Root, full) || ContainsPath(full, v.Root))), "overlapping-vault-paths");
    return (full, vaults.SingleOrDefault(v => v.Root.Equals(full, Platform.Components.PathComparison)),
      Path.Combine(Home, "export-reset-" + Crypto.HashObject(full.ToUpperInvariant()) + ".json"));
  }

  private static bool EmptyTarget(string full) => !File.Exists(full) &&
    (!Directory.Exists(full) || !Directory.EnumerateFileSystemEntries(full).Any());

  private VaultManifest ExportManifest(string full, VaultRegistration? registered, string? observedId)
  {
    var manifestPath = Path.Combine(full, "manifest.json");
    Protocol.Require(File.Exists(manifestPath), "vault-directory-not-empty");
    LocalFiles.CheckLinks(manifestPath);
    var manifest = Read<VaultManifest>(manifestPath);
    Protocol.Require(manifest.LayoutVersion == 1 && Guid.TryParseExact(manifest.VaultId, "N", out _) &&
      manifest.OwnerSid == Platform.Identity.CurrentUserId && (registered is null || registered.VaultId == manifest.VaultId) &&
      observedId == manifest.VaultId, "vault-identity-mismatch");
    if (registered is null)
    {
      Protocol.Require(File.Exists(Path.Combine(full, "control.db")), "vault-directory-not-empty");
      Protocol.Require(!Vaults().Any(v => v.VaultId == manifest.VaultId), "vault-identity-mismatch");
    }
    ExportFiles(full);
    return manifest;
  }

  public async Task<ExportTarget> PrepareExport(string root, string clientId, string operationId, string? observedId)
  {
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    _ = ValidateInstallation();
    var (full, registered, journal) = ExportLocation(root);
    if (!EmptyTarget(full))
    {
      var manifest = ExportManifest(full, registered, observedId);
      Protocol.Require(!File.Exists(journal) && CanPublishOrRecover(full, clientId, operationId), "export-target-conflict");
      var current = await RegisterLocked(full, false, expectedVaultId: manifest.VaultId);
      return new(current.VaultId, null);
    }
    if (registered is not null)
    {
      if (File.Exists(AdminPath(registered.VaultId)))
        Protocol.Require(await TryStatus(registered) is null, "vault-in-use");
      RemoveExportRegistration(registered);
    }
    File.Delete(journal);
    var fresh = await RegisterLocked(full, false);
    return new(fresh.VaultId, registered?.VaultId);
  }

  public async Task ClearExport(string root, string clientId, string operationId, string observedId)
  {
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    _ = ValidateInstallation();
    var (full, registered, journal) = ExportLocation(root);
    var manifest = ExportManifest(full, registered, observedId);
    if (registered is null)
    {
      Protocol.Require(!CanPublishOrRecover(full, clientId, operationId), "export-no-longer-conflicts");
      registered = await RegisterLocked(full, false, expectedVaultId: manifest.VaultId);
    }
    if (File.Exists(journal))
      Protocol.Require(Read<VaultRegistration>(journal) == registered, "vault-identity-mismatch");
    else Protocol.Require(!CanPublishOrRecover(full, clientId, operationId), "export-no-longer-conflicts");

    await DrainUnusedExport(registered);
    var runtime = Platform.Files.CreatePrivateDirectory(Path.Combine(full, "runtime"));
    var manifestPath = Path.Combine(full, "manifest.json");
    using (var supervisor = LocalFiles.AcquireLock(Path.Combine(runtime, "supervisor.lock")))
    using (var writer = LocalFiles.AcquireLock(Path.Combine(runtime, "vault.lock")))
    {
      VerifyRegistration(registered);
      if (!File.Exists(journal))
        Protocol.Require(!CanPublishOrRecover(full, clientId, operationId), "export-no-longer-conflicts");
      var entries = ExportFiles(full);
      LocalFiles.WriteAtomic(journal, Protocol.Encode(registered));
      foreach (var file in entries.Where(f => !ContainsPath(runtime, f) && f != manifestPath))
        DeleteExportEntry(file);
    }
    foreach (var file in ExportFiles(full).Where(f => ContainsPath(runtime, f))) DeleteExportEntry(file);
    Protocol.Require(Directory.EnumerateFileSystemEntries(full).SequenceEqual([manifestPath]), "vault-directory-not-empty");
    File.Delete(manifestPath);
    RemoveExportRegistration(registered);
    File.Delete(journal);
  }

  private bool CanPublishOrRecover(string root, string clientId, string operationId)
  {
    var path = Path.Combine(root, "control.db");
    if (!File.Exists(path)) return false;
    using var db = new SqliteConnection(new SqliteConnectionStringBuilder
      { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
    try
    {
      db.Open();
      using var query = db.CreateCommand();
      query.CommandText = """
        SELECT CASE
          WHEN NOT EXISTS(SELECT 1 FROM settings WHERE key='currentVersion') THEN ''
          WHEN EXISTS(SELECT 1 FROM receipts WHERE operation_id=$op AND client_id=$client AND kind='publish')
            AND NOT EXISTS(SELECT 1 FROM settings WHERE key='deliveryAcknowledged' AND value='true')
          THEN (SELECT value FROM settings WHERE key='currentVersion') END
        """;
      query.Parameters.AddWithValue("$op", operationId);
      query.Parameters.AddWithValue("$client", clientId);
      var version = query.ExecuteScalar() as string;
      if (version is null) return false;
      if (version.Length == 0) return true;
      var manifest = Read<VaultManifest>(Path.Combine(root, "manifest.json"));
      var folder = Path.Combine(root, "versions", Protocol.Id(version));
      return File.Exists(Path.Combine(folder, "version.json")) && File.Exists(Path.Combine(folder, "migration.json")) &&
        File.Exists(Path.Combine(KeysRoot, manifest.VaultId + ".delivery" + Platform.Secrets.FileExtension));
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode is 11 or 26) { return false; } // Corrupt/non-database.
  }

  private async Task DrainUnusedExport(VaultRegistration registration)
  {
    var runtime = Path.Combine(registration.Root, "runtime");
    var status = await TryStatus(registration);
    if (status is null)
    {
      foreach (var name in new[] { "endpoint.json", "supervisor.json" })
        Protocol.Require(!ProcessAlive(Path.Combine(runtime, name), Platform), "vault-in-use");
      return;
    }
    await using (var client = await Management(registration))
      await client.Call("stopIfUnused", new { });
    // No unconditional stop here. A failed or ambiguous idle check must preserve every client.
    for (var i = 0; i < 100; i++)
    {
      if (!ProcessAlive(Path.Combine(runtime, "endpoint.json"), Platform) &&
          !ProcessAlive(Path.Combine(runtime, "supervisor.json"), Platform)) return;
      await Task.Delay(100);
    }
    throw new BrokerException("service-exit-unconfirmed");
  }

  private void RemoveExportRegistration(VaultRegistration old)
  {
    Protocol.Require(Guid.TryParseExact(old.VaultId, "N", out _) && old.OwnerSid == Platform.Identity.CurrentUserId,
      "vault-identity-mismatch");
    foreach (var key in Directory.EnumerateFiles(KeysRoot, old.VaultId + ".*" + Platform.Secrets.FileExtension))
      File.Delete(key);
    File.Delete(Path.Combine(Home, "vaults", old.VaultId + ".json"));
  }

  private static void DeleteExportEntry(string path)
  {
    LocalFiles.CheckLinks(path);
    if (Directory.Exists(path)) Directory.Delete(path); // Nonrecursive: concurrent new files are never swept up.
    else File.Delete(path);
  }

  // Postorder, positive list. A plausible manifest beside arbitrary user files is not a disposable vault.
  private static List<string> ExportFiles(string root)
  {
    var entries = new List<string>();
    void Visit(string directory)
    {
      foreach (var item in new DirectoryInfo(directory).EnumerateFileSystemInfos())
      {
        Protocol.Require((item.Attributes & FileAttributes.ReparsePoint) == 0, "vault-directory-not-empty");
        var parts = Path.GetRelativePath(root, item.FullName).Split(Path.DirectorySeparatorChar);
        bool valid = item is DirectoryInfo ? parts switch {
          ["runtime" or "versions"] => true,
          ["versions", var v] => Guid.TryParseExact(v, "N", out _),
          _ => false
        } : parts switch {
          ["manifest.json" or "control.db" or "control.db-wal" or "control.db-shm"] => true,
          ["runtime", "vault.lock" or "supervisor.lock" or "endpoint.json" or "supervisor.json" or "stop.request"] => true,
          ["versions", _, "version.json" or "migration.json" or "credentials.db" or "credentials.db-wal" or "credentials.db-shm"] => true,
          _ => false
        };
        Protocol.Require(valid, "vault-directory-not-empty");
        if (item is DirectoryInfo) Visit(item.FullName);
        entries.Add(item.FullName);
      }
    }
    Visit(root);
    return entries;
  }
}
