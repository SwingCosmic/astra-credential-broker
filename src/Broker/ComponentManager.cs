using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

public sealed record ComponentFile(string Path, long Size, string Sha256);
public sealed record ComponentManifest(string Component, string Version, string Rid, int ProtocolMin, int ProtocolMax,
  int StorageMin, int StorageMax, ComponentFile[] Files, decimal ApiRevision = 0);
public sealed record Installation(string Version, string Directory, string ManifestHash);
public sealed record VaultRegistration(string VaultId, string Root, string DirectoryIdentity, string OwnerSid, string Supervision = "detached-process");
public sealed record InstallJournal(Installation? Previous, Installation? Candidate, string Phase);
public sealed record InstallationStatus(string InstallState, Installation? Installation, string? ErrorCode);
public sealed record RuntimeEndpoint(int Pid, long ProcessStartTime, string Generation, string PipeName, string State);
public sealed class ComponentCommandException(string executable, int exitCode, string diagnostic) : Exception("component-command-failed")
{
  public string Executable { get; } = executable;
  public int ExitCode { get; } = exitCode;
  public string Diagnostic { get; } = diagnostic;
}

public sealed class ComponentManager
{
  public BrokerPlatform Platform { get; }
  public string Home { get; }
  public string KeysRoot => Path.Combine(Home, "keys");
  public string RegistryPath => Path.Combine(Home, "installation.json");
  private string JournalPath => Path.Combine(Home, "install-journal.json");
  private string MaintenancePath => Path.Combine(Home, "maintenance.json");
  private string Components => Path.Combine(Home, "components");
  public ComponentManager(string? home = null, BrokerPlatform? platform = null)
  {
    Platform = platform ?? BrokerPlatform.Current;
    Home = Platform.Files.CreatePrivateDirectory(home ?? Platform.Components.DefaultHome);
    Platform.Files.CreatePrivateDirectory(KeysRoot);
    Platform.Files.CreatePrivateDirectory(Components);
    Platform.Files.CreatePrivateDirectory(Path.Combine(Home, "vaults"));
  }
  public static T Read<T>(string path) => Protocol.Decode<T>(Protocol.Parse(File.ReadAllBytes(path)));
  public Installation? Installed => File.Exists(RegistryPath) ? Read<Installation>(RegistryPath) : null;
  public bool InMaintenance => File.Exists(MaintenancePath);
  public Action<string>? Fault { get; set; }
  public static async Task<FileStream> WaitLock(string path, CancellationToken cancellationToken = default)
  {
    var deadline = Environment.TickCount64 + 60_000;
    while (true)
    {
      try { return LocalFiles.AcquireLock(path); }
      catch (BrokerException ex) when (ex.Code == "lock-busy" && Environment.TickCount64 < deadline)
      { await Task.Delay(100, cancellationToken); }
    }
  }
  public VaultRegistration[] Vaults() => Directory.EnumerateFiles(Path.Combine(Home, "vaults"), "*.json")
    .Select(Read<VaultRegistration>).ToArray();
  public VaultRegistration LocateVault(string vaultId)
  {
    Protocol.Id(vaultId);
    return Vaults().SingleOrDefault(item => item.VaultId == vaultId) ?? throw new BrokerException("vault-not-registered");
  }
  public VaultRegistration Registration(string root)
  {
    var path = LocalFiles.FullPath(root);
    var registration = Vaults().SingleOrDefault(v => v.Root.Equals(path, Platform.Components.PathComparison)) ?? throw new BrokerException("vault-not-registered");
    VerifyRegistration(registration);
    return registration;
  }
  private void VerifyRegistration(VaultRegistration registration)
  {
    Platform.Files.ValidatePrivateDirectory(registration.Root);
    var manifest = Read<VaultManifest>(Path.Combine(registration.Root, "manifest.json"));
    Protocol.Require(registration.OwnerSid == Platform.Identity.CurrentUserId && manifest.OwnerSid == registration.OwnerSid &&
      manifest.VaultId == registration.VaultId && manifest.LayoutVersion == 1, "vault-identity-mismatch");
  }
  public async Task<VaultRegistration> RegisterVault(string root, bool allowRelocation = true,
    string? previousRoot = null, string? expectedVaultId = null, string? expectedVersion = null)
  {
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    _ = ValidateInstallation();
    var full = LocalFiles.FullPath(root);
    Protocol.Require(!ContainsPath(Home, full) && !ContainsPath(full, Home), "overlapping-service-and-data-paths");
    var existing = Vaults().FirstOrDefault(v => v.Root.Equals(full, Platform.Components.PathComparison));
    if (existing is not null)
    {
      VerifyRegistration(existing);
      Protocol.Require(expectedVaultId is null || existing.VaultId == expectedVaultId, "vault-identity-mismatch");
      if (expectedVersion is not null)
      {
        var database = Path.Combine(full, "control.db");
        LocalFiles.CheckLinks(database);
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
        { DataSource = database, Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT value FROM settings WHERE key='currentVersion'";
        Protocol.Require(query.ExecuteScalar() as string == expectedVersion, "version-mismatch");
      }
      return existing;
    }
    if (expectedVaultId is not null)
    {
      Platform.Files.ValidatePrivateDirectory(full);
      Protocol.Require(Read<VaultManifest>(Path.Combine(full, "manifest.json")).VaultId == expectedVaultId, "vault-identity-mismatch");
    }
    using var vault = Vault.Open(full, KeysRoot, create: expectedVaultId is null, Platform);
    Protocol.Require(expectedVaultId is null || vault.Manifest.VaultId == expectedVaultId, "vault-identity-mismatch");
    Protocol.Require(expectedVersion is null || vault.CurrentVersion().StorageVersion == expectedVersion, "version-mismatch");
    var previous = Vaults().FirstOrDefault(v => v.VaultId == vault.Manifest.VaultId);
    Protocol.Require(previousRoot is null || previous is not null, "vault-not-registered");
    if (previous is not null)
    {
      Protocol.Require(allowRelocation && (previousRoot is null ||
        previous.Root.Equals(LocalFiles.FullPath(previousRoot), Platform.Components.PathComparison)), "vault-location-changed");
      foreach (var directory in new[] { previous.Root, full })
        foreach (var name in new[] { "endpoint.json", "supervisor.json" })
          Protocol.Require(!ProcessAlive(Path.Combine(directory, "runtime", name), Platform), "vault-already-running");
      Protocol.Require(await TryStatus(previous) is null, "vault-already-running");
    }
    var registration = new VaultRegistration(vault.Manifest.VaultId, vault.Root, vault.Manifest.DirectoryIdentity, Platform.Identity.CurrentUserId);
    var adminPath = AdminPath(registration.VaultId);
    if (!File.Exists(adminPath))
    {
      var secret = RandomNumberGenerator.GetBytes(32);
      try { LocalFiles.WriteAtomic(adminPath, Platform.Secrets.Protect(secret, "management:" + registration.VaultId)); }
      finally { CryptographicOperations.ZeroMemory(secret); }
    }
    LocalFiles.WriteAtomic(Path.Combine(Home, "vaults", registration.VaultId + ".json"), Protocol.Encode(registration));
    return registration;
  }
  public string AdminPath(string vaultId) => Path.Combine(KeysRoot, Protocol.Id(vaultId) + ".admin" + Platform.Secrets.FileExtension);
  public byte[] AdminToken(string vaultId) => Platform.Secrets.Unprotect(File.ReadAllBytes(AdminPath(vaultId)), "management:" + vaultId);
  public async Task<BrokerClient> Management(VaultRegistration vault, CancellationToken cancellationToken = default, bool allowLegacyLifecycle = false)
  {
    if (!allowLegacyLifecycle) _ = ValidateInstallation();
    return await ConnectManagement(vault, cancellationToken, allowLegacyLifecycle);
  }
  private async Task<BrokerClient> ConnectManagement(VaultRegistration vault, CancellationToken cancellationToken,
    bool allowLegacyLifecycle)
  {
    var token = AdminToken(vault.VaultId);
    try { return await BrokerClient.Connect(vault.VaultId, "management", Crypto.RandomId(), token, true, cancellationToken, Platform, allowLegacyLifecycle); }
    finally { CryptographicOperations.ZeroMemory(token); }
  }
  private bool ContainsPath(string parent, string child) => LocalFiles.ContainsPath(parent, child, Platform.Components.PathComparison);

  public static ComponentManifest MakeManifest(string source, BrokerPlatform? platform = null)
  {
    platform ??= BrokerPlatform.Current;
    var root = LocalFiles.FullPath(source);
    var files = SafeFiles(root).Where(path => Path.GetFileName(path) != "component.json")
      .Select(path => new ComponentFile(Path.GetRelativePath(root, path).Replace('\\', '/'), new FileInfo(path).Length,
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)))))
      .OrderBy(f => f.Path, StringComparer.Ordinal).ToArray();
    var manifest = new ComponentManifest(ComponentContract.Name, ComponentContract.Version, platform.Components.RuntimeIdentifier,
      Protocol.Version, Protocol.Version, ComponentContract.StorageVersion, ComponentContract.StorageVersion, files, ComponentContract.ApiRevision);
    LocalFiles.WriteAtomic(Path.Combine(root, "component.json"), Protocol.Encode(manifest));
    return manifest;
  }
  private static List<string> SafeFiles(string root)
  {
    var result = new List<string>();
    foreach (var path in Directory.EnumerateFileSystemEntries(root))
    {
      LocalFiles.CheckLinks(path);
      if (Directory.Exists(path)) result.AddRange(SafeFiles(path));
      else result.Add(path);
    }
    return result;
  }
  public static ComponentManifest VerifyComponent(string root, BrokerPlatform? platform = null, bool requireCurrentApi = true)
  {
    platform ??= BrokerPlatform.Current;
    LocalFiles.CheckLinks(root);
    var manifest = Read<ComponentManifest>(Path.Combine(root, "component.json"));
    if (requireCurrentApi) ComponentContract.RequireSupported(manifest.Version, manifest.ApiRevision);
    else ComponentContract.RequireVersion(manifest.Version);
    Protocol.Require(manifest.Component == ComponentContract.Name && manifest.Rid == platform.Components.RuntimeIdentifier, "component-incompatible");
    Protocol.Require(manifest.ProtocolMin >= 1 && manifest.ProtocolMax >= manifest.ProtocolMin && manifest.StorageMin >= 1 && manifest.StorageMax >= manifest.StorageMin, "invalid-component-manifest");
    Protocol.Require(manifest.ProtocolMin <= Protocol.Version && manifest.ProtocolMax >= Protocol.Version, "protocol-incompatible");
    Protocol.Require(manifest.StorageMin <= ComponentContract.StorageVersion && manifest.StorageMax >= ComponentContract.StorageVersion, "storage-incompatible");
    var paths = new HashSet<string>(platform.Components.PathComparer);
    Protocol.Require(manifest.Files.Length is > 0 and <= 2000, "invalid-component-manifest");
    foreach (var file in manifest.Files)
    {
      Protocol.Require(!Path.IsPathRooted(file.Path) && file.Path.Split('/').All(s => s.Length > 0 && s is not "." and not ".." &&
        platform.Components.IsSafeFileName(s)) && paths.Add(file.Path), "unsafe-component-path");
      var path = LocalFiles.FullPath(Path.Combine(root, file.Path));
      Protocol.Require(LocalFiles.ContainsPath(root, path, platform.Components.PathComparison) && File.Exists(path) && new FileInfo(path).Length == file.Size &&
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))) == file.Sha256, "component-integrity-failed");
    }
    Protocol.Require(SafeFiles(root).Count == manifest.Files.Length + 1, "unexpected-component-files");
    foreach (var required in platform.Components.RequiredFiles)
      Protocol.Require(paths.Contains(required), "component-incomplete");
    return manifest;
  }
  public Installation ValidateInstallation()
  {
    var installed = Installed ?? throw new BrokerException("not-installed");
    Protocol.Require(ContainsPath(Components, installed.Directory) && !installed.Directory.Equals(Components, Platform.Components.PathComparison), "invalid-installation-registration");
    Platform.Files.ValidateTree(installed.Directory);
    var manifest = VerifyComponent(installed.Directory, Platform);
    Protocol.Require(installed.Version == manifest.Version, "component-integrity-failed");
    Protocol.Require(Crypto.Hash(File.ReadAllBytes(Path.Combine(installed.Directory, "component.json"))) == installed.ManifestHash, "component-integrity-failed");
    return installed;
  }
  public InstallationStatus CheckInstallation()
  {
    // Read-only and never starts a task/service. No lock/journal recovery here.
    try { return new(Installed is null ? "not-installed" : InMaintenance ? "maintenance" : "installed", Installed is null ? null : ValidateInstallation(), null); }
    catch (PlatformFeatureUnavailableException) { throw; }
    catch (BrokerException ex) when (ex.Code is "component-incompatible" or "api-incompatible" or "protocol-incompatible" or "storage-incompatible") { return new("incompatible", Installed, ex.Code); }
    catch (Exception ex) { return new("damaged", null, PipeServer.ErrorCode(ex)); }
  }

  public async Task<Installation> InstallLocal(string source)
  {
    var sourceRoot = LocalFiles.FullPath(source);
    var manifest = VerifyComponent(sourceRoot, Platform);
    Protocol.Require(!ContainsPath(Home, sourceRoot) && !ContainsPath(sourceRoot, Home), "external-publish-source-required");
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    var previous = Installed;
    Protocol.Require(previous is null || !ContainsPath(previous.Directory, Environment.ProcessPath!), "external-controller-required");
    var target = Platform.Files.CreatePrivateDirectory(Path.Combine(Components, manifest.Version + "-" + Crypto.RandomId()));
    var candidate = new Installation(manifest.Version, target, "");
    try
    {
      foreach (var file in manifest.Files.Append(new("component.json", 0, "")))
      {
        var output = Path.Combine(target, file.Path);
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        File.Copy(Path.Combine(sourceRoot, file.Path), output, false);
        Platform.Components.PrepareCopiedFile(Path.Combine(sourceRoot, file.Path), output);
      }
      _ = VerifyComponent(target, Platform);
      Platform.Files.ValidateTree(target);
      candidate = candidate with { ManifestHash = Crypto.Hash(File.ReadAllBytes(Path.Combine(target, "component.json"))) };
      var probe = await Platform.Components.RunTool(Path.Combine(target, Platform.Components.ExecutableName), ["component-info"]);
      var info = Protocol.Decode<ComponentProbe>(Protocol.Parse(Encoding.UTF8.GetBytes(probe)));
      ValidateProbe(manifest, info);
      Fault?.Invoke("staged");
      WriteJournal(new(previous, candidate, "prepared"));
      EnterMaintenance();
      await StopAll();
      Fault?.Invoke("stopped");
      LocalFiles.WriteAtomic(RegistryPath, Protocol.Encode(candidate));
      Fault?.Invoke("registered");
      WriteJournal(new(previous, candidate, "committed"));
      File.Delete(MaintenancePath);
      File.Delete(JournalPath);
      if (previous is not null) DeleteComponent(previous.Directory);
      return candidate;
    }
    catch
    {
      if (File.Exists(JournalPath)) await Recover();
      else if (Installed?.Directory != target) DeleteComponent(target);
      throw;
    }
  }
  private void WriteJournal(InstallJournal journal) => LocalFiles.WriteAtomic(JournalPath, Protocol.Encode(journal));
  public static void ValidateProbe(ComponentManifest manifest, ComponentProbe info)
  {
    Protocol.Require(info.Component == manifest.Component && info.Version == manifest.Version && info.ApiRevision == manifest.ApiRevision &&
      info.ProtocolVersion == Protocol.Version && info.ProtocolVersion >= manifest.ProtocolMin && info.ProtocolVersion <= manifest.ProtocolMax &&
      info.StorageVersion == ComponentContract.StorageVersion && info.StorageVersion >= manifest.StorageMin && info.StorageVersion <= manifest.StorageMax &&
      info.SqliteReady, "component-probe-failed");
    ComponentContract.RequireSupported(info.Version, info.ApiRevision);
  }
  private void EnterMaintenance() => LocalFiles.WriteAtomic(MaintenancePath, Protocol.Encode(new { maintenance = true }));
  private void DeleteComponent(string path)
  {
    var full = LocalFiles.FullPath(path);
    Protocol.Require(ContainsPath(Components, full) && full != Components, "unsafe-delete-path");
    if (!Directory.Exists(full)) return;
    Platform.Files.ValidateTree(full);
    Directory.Delete(full, true);
  }
  private Task Recover()
  {
    if (!File.Exists(JournalPath))
    {
      Protocol.Require(!InMaintenance, "maintenance-recovery-required");
      return Task.CompletedTask;
    }
    var journal = Read<InstallJournal>(JournalPath);
    if (journal.Phase == "committed")
    {
      if (journal.Candidate is not null)
      {
        // Recover an already committed older installer journal without advertising its API as compatible.
        _ = VerifyComponent(journal.Candidate.Directory, Platform, requireCurrentApi: false);
        LocalFiles.WriteAtomic(RegistryPath, Protocol.Encode(journal.Candidate));
      }
      else { if (File.Exists(RegistryPath)) File.Delete(RegistryPath); }
    }
    else if (journal.Previous is not null)
    {
      // Rollback verifies all old file hashes/layout, without treating the old API as usable by new clients.
      _ = VerifyComponent(journal.Previous.Directory, Platform, requireCurrentApi: false);
      LocalFiles.WriteAtomic(RegistryPath, Protocol.Encode(journal.Previous));
    }
    else
    {
      if (File.Exists(RegistryPath)) File.Delete(RegistryPath);
    }
    if (File.Exists(MaintenancePath)) File.Delete(MaintenancePath);
    File.Delete(JournalPath);
    if (journal.Phase != "committed" && journal.Candidate is not null) DeleteComponent(journal.Candidate.Directory);
    return Task.CompletedTask;
  }
  public async Task Uninstall()
  {
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    var previous = Installed;
    if (previous is null) return;
    // The A2 offline controller is invoked from the original publish folder, outside this directory.
    Protocol.Require(!ContainsPath(previous.Directory, Environment.ProcessPath!), "external-controller-required");
    WriteJournal(new(previous, null, "prepared"));
    EnterMaintenance();
    try
    {
      await StopAll();
      if (File.Exists(RegistryPath)) File.Delete(RegistryPath);
      WriteJournal(new(previous, null, "committed"));
      DeleteComponent(previous.Directory);
      File.Delete(MaintenancePath);
      File.Delete(JournalPath);
    }
    catch { await Recover(); throw; }
  }
  public async Task<ServiceStatus> EnsureRunning(string root)
  {
    using var held = await WaitLock(Path.Combine(Home, "component.lock"));
    await Recover();
    Protocol.Require(!InMaintenance, "service-maintenance");
    var installation = ValidateInstallation();
    var vault = Registration(root);
    var status = await TryStatus(vault);
    if (status is not null && status.ServiceStatusValue != "DRAINING") return status;
    var stopPath = Path.Combine(vault.Root, "runtime", "stop.request");
    if (File.Exists(stopPath)) File.Delete(stopPath);
    var supervisorPath = Path.Combine(vault.Root, "runtime", "supervisor.json");
    if (!ProcessAlive(supervisorPath, Platform))
    {
      Platform.Components.LaunchDetached(Path.Combine(installation.Directory, Platform.Components.ExecutableName),
        ["supervise", "--home", Home, "--vault", vault.Root], installation.Directory);
    }
    for (var i = 0; i < 100; i++)
    {
      status = await TryStatus(vault);
      if (status is not null) return status;
      await Task.Delay(100);
    }
    throw new BrokerException("service-start-failed");
  }
  public async Task<ServiceStatus?> TryStatus(VaultRegistration vault, bool allowLegacyLifecycle = false)
  {
    try
    {
      // Hashing the full self-contained component must not consume the short pipe-connect timeout.
      if (!allowLegacyLifecycle) _ = ValidateInstallation();
      using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
      await using var client = await ConnectManagement(vault, timeout.Token, allowLegacyLifecycle);
      var status = Protocol.Decode<ServiceStatus>(await client.Call("status", new { }));
      await client.Call("disconnect", new { });
      return status;
    }
    catch (Exception ex) when (ex is IOException or OperationCanceledException) { return null; }
  }
  public async Task Stop(VaultRegistration vault)
  {
    LocalFiles.WriteAtomic(Path.Combine(vault.Root, "runtime", "stop.request"), Protocol.Encode(new { stop = true }));
    var status = await TryStatus(vault, allowLegacyLifecycle: true);
    if (status is not null)
    {
      try
      {
        await using var client = await Management(vault, allowLegacyLifecycle: true);
        await client.Call("stop", new { });
      }
      catch (Exception ex) when (ex is IOException or OperationCanceledException)
      {
        // The draining ticker may close the pipe before the stop reply is delivered.
        // A lost reply is not proof of shutdown: require process exit and both locks below.
      }
    }
    var endpointPath = Path.Combine(vault.Root, "runtime", "endpoint.json");
    for (var i = 0; i < 400; i++)
    {
      if (!ProcessAlive(endpointPath, Platform))
      {
        try
        {
          using var acquired = LocalFiles.AcquireLock(Path.Combine(vault.Root, "runtime", "vault.lock"));
          using var supervisor = await WaitLock(Path.Combine(vault.Root, "runtime", "supervisor.lock"));
          return;
        }
        catch (BrokerException ex) when (ex.Code == "lock-busy") { }
      }
      await Task.Delay(100);
    }
    throw new BrokerException("service-exit-unconfirmed");
  }
  private async Task StopAll()
  {
    var detached = new List<VaultRegistration>();
    foreach (var vault in Vaults())
    {
      Protocol.Require(vault.OwnerSid == Platform.Identity.CurrentUserId, "vault-identity-mismatch");
      try { VerifyRegistration(vault); }
      catch (Exception ex) when (ex is BrokerException { Code: "vault-identity-mismatch" or "directory-not-found" } or FileNotFoundException)
      {
        // A moved vault may leave an old registration pointing at an unrelated directory.
        // Do not create a stop file or acquire data locks at that location.
        detached.Add(vault);
        continue;
      }
      await Stop(vault);
    }
    foreach (var vault in detached)
    {
      Protocol.Require(await TryStatus(vault, allowLegacyLifecycle: true) is null, "service-exit-unconfirmed");
      foreach (var name in new[] { "endpoint.json", "supervisor.json" })
        Protocol.Require(!ProcessAlive(Path.Combine(vault.Root, "runtime", name), Platform), "service-exit-unconfirmed");
    }
  }
  public async Task ForceRecover(string root)
  {
    // Explicit management action only. Normal ensureRunning never kills a process.
    using (await WaitLock(Path.Combine(Home, "component.lock")))
    {
      await Recover();
      var installation = ValidateInstallation();
      var vault = Registration(root);
      LocalFiles.WriteAtomic(Path.Combine(vault.Root, "runtime", "stop.request"), Protocol.Encode(new { stop = true }));
      foreach (var name in new[] { "endpoint.json", "supervisor.json" })
      {
        var path = Path.Combine(vault.Root, "runtime", name);
        if (!ProcessAlive(path, Platform)) continue;
        var endpoint = Read<RuntimeEndpoint>(path);
        await Platform.Components.TerminateVerified(endpoint, Path.Combine(installation.Directory, Platform.Components.ExecutableName));
      }
      using var writer = await WaitLock(Path.Combine(vault.Root, "runtime", "vault.lock"));
      using var supervisor = await WaitLock(Path.Combine(vault.Root, "runtime", "supervisor.lock"));
    }
    // A new generation is started only after old processes exited and both OS locks were acquired.
    await EnsureRunning(root);
  }
  public static bool ProcessAlive(string path, BrokerPlatform? platform = null)
  {
    if (!File.Exists(path)) return false;
    return (platform ?? BrokerPlatform.Current).Components.IsProcessAlive(Read<RuntimeEndpoint>(path));
  }
  public static Task<string> Run(string exe, string[] args, bool allowFailure = false, BrokerPlatform? platform = null) =>
    (platform ?? BrokerPlatform.Current).Components.RunTool(exe, args, allowFailure);

}
public sealed record ComponentProbe(string Component, string Version, int ProtocolVersion, int StorageVersion, bool SqliteReady, string? RuntimeDirectory = null, decimal ApiRevision = 0);
