using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Astra.Credentials;

if (args.Length == 5 && args[0] == "--crash-install")
{
  var interrupted = new ComponentManager(args[4]);
  interrupted.Fault = point => { if (point == "registered") Environment.Exit(86); };
  await interrupted.InstallLocal(args[2]);
  return 2;
}

var results = new List<string>();
ComponentManager? manager = null;
string? root = null;
var clients = new List<BrokerClient>();
try
{
  Protocol.Require(args.Length == 4 && args[0] == "--publish" && args[2] == "--root", "expected-publish-and-root");
  var publish = LocalFiles.FullPath(args[1]);
  root = BrokerPlatform.Current.Files.CreatePrivateDirectory(args[3]);
  manager = new ComponentManager(Path.Combine(root, "service-home"));
  var data = Path.Combine(root, "vault-data");
  var info = Protocol.Decode<ComponentProbe>(Protocol.Parse(Encoding.UTF8.GetBytes(await ComponentManager.Run(Path.Combine(publish, "brokerctl.exe"), ["component-info"]))));
  Check(info.RuntimeDirectory == publish && info.SqliteReady, "bundled-runtime-and-sqlite");
  Check(manager.CheckInstallation().InstallState == "not-installed", "initial-not-installed");
  var installation = await manager.InstallLocal(publish);
  var vault = await manager.RegisterVault(data);
  Check(manager.CheckInstallation().InstallState == "installed", "local-copy-install-and-register");
  Check(await manager.TryStatus(vault) is null, "discovery-does-not-start-service");
  var starts = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => new ComponentManager(manager.Home).EnsureRunning(data)));
  Check(starts.Select(s => s.Generation).Distinct().Count() == 1, "four-concurrent-starts-one-generation");
  var grants = new List<RegisteredClient>();
  await using (var admin = await manager.Management(vault))
  {
    for (var i = 0; i < 4; i++)
      grants.Add(Protocol.Decode<RegisteredClient>(await admin.Call("registerClient", new RegisterClient("independent-" + i,
        ["initialize", "import", "handoff", "read", "describe", "update", "create", "events"], [], true))));
    await admin.Call("disconnect", new { });
  }
  for (var i = 0; i < 4; i++) clients.Add(await Connect(i));
  var exported = Protocol.Decode<InitializeResult>(await clients[0].Call("initialize", new InitializeRequest("export-once", "source-42",
    [new("usage-record", "application/arbitrary", 1, Payload("C1"), new() { ["supportsUsage"] = "true" }),
      new("inference-only-key", "third-party/key", 1, Payload("opaque-key"), new() { ["supportsUsage"] = "false", ["supportsInference"] = "true" })])));
  Check(exported.State == "exported", "initial-export-independent-of-products");
  await Expect("authentication-failed", () => clients[1].Call("validateMigration", new ValidateMigration("acm1_" + Crypto.B64(new byte[32]))));
  var validation = Protocol.Decode<MigrationValidation>(await clients[1].Call("validateMigration", new ValidateMigration(exported.MigrationKey!)));
  Check(validation.RecordCount == 2, "migration-validation-and-wrong-key-rejection");
  var package = ComponentManager.Read<TransferPackage>(Path.Combine(data, "versions", exported.StorageVersion, "migration.json"));
  var snapshot = Crypto.Unpack(package, exported.MigrationKey!);
  var masterKey = Crypto.Unb64(snapshot.MasterKey, 32);
  for (var i = 0; i < 2; i++)
  {
    var challenge = Protocol.Decode<ProofChallenge>(await clients[i].Call("prepareChallenge", new { }));
    var request = new ReadyRequest("ready-" + i, "source-42", challenge.ChallengeId, "");
    request = request with { Proof = BrokerService.ReadyProof(masterKey, vault.VaultId, exported.StorageVersion, grants[i].ClientId, request, challenge.Nonce) };
    await clients[i].Call("prepareClient", request);
  }
  await clients[0].Call("acknowledgeDelivery", new { });
  var handoff = new HandoffRequest("handoff-once", "source-42", grants.Take(2).Select(g => g.ClientId).ToArray());
  await clients[0].Call("handoff", handoff);
  await clients[0].Call("handoff", handoff);
  Check(true, "prepared-handoff-and-idempotent-receipt");
  var filtered = Protocol.Decode<CredentialPage>(await clients[2].Call("listCredentials", new ListCredentials(MetadataEquals: new() { ["supportsUsage"] = "true" })));
  Check(filtered.Items.Length == 1 && filtered.Items[0].CredentialId == "usage-record", "metadata-discovery-filter");
  for (var i = 0; i < 2; i++)
  {
    var begin = Protocol.Decode<BeginResult>(await clients[i].Call("beginUpdate", new BeginUpdate("usage-record", (i + 1).ToString(), "refresh-" + i)));
    var lease = Lease(begin.Operation!);
    await clients[i].Call("markUpdateStarted", lease);
    var commit = new CommitUpdate(lease, Payload("C" + (i + 2)));
    await clients[i].Call("commitUpdate", commit);
    await clients[i].Call("commitUpdate", commit);
  }
  var current = Protocol.Decode<Credential>(await clients[3].Call("getCredential", new IdRequest("usage-record")));
  Check(current.Description.Revision == "3" && current.Payload == Payload("C3"), "opaque-c1-c2-c3-and-commit-replay");
  var events = Protocol.Decode<EventPage>(await clients[3].Call("getEvents", new EventsRequest()));
  Check(events.Items.Count(e => e.CredentialId == "usage-record") == 3, "durable-replayable-change-events");
  await Expect("management-required", () => clients[3].Call("stop", new { }));
  var before = Protocol.Decode<BeginResult>(await clients[0].Call("beginUpdate", new BeginUpdate("usage-record", "3", "crash-operation")));
  await clients[0].Call("markUpdateStarted", Lease(before.Operation!));
  foreach (var client in clients) await client.DisposeAsync();
  clients.Clear();
  var oldEndpoint = ComponentManager.Read<RuntimeEndpoint>(Path.Combine(data, "runtime", "endpoint.json"));
  using (var crashed = Process.GetProcessById(oldEndpoint.Pid))
  {
    Check(crashed.StartTime.ToUniversalTime().Ticks == oldEndpoint.ProcessStartTime, "verified-crash-target-identity");
    crashed.Kill();
    await crashed.WaitForExitAsync();
  }
  ServiceStatus? recovered = null;
  for (var i = 0; i < 100; i++)
  {
    recovered = await manager.TryStatus(vault);
    if (recovered is not null && recovered.Generation != before.Operation!.Generation) break;
    await Task.Delay(100);
  }
  Check(recovered is not null && recovered.Generation != before.Operation!.Generation, "independent-supervisor-crash-restart");
  clients.Add(await Connect(0));
  var again = Protocol.Decode<BeginResult>(await clients[0].Call("beginUpdate", new BeginUpdate("usage-record", "3", "crash-operation")));
  Check(again.Operation!.HardDeadline == before.Operation!.HardDeadline && again.Operation.ExpiresAt == before.Operation.ExpiresAt, "restart-retains-original-lease-deadlines");
  await Expect("stale-fence", () => clients[0].Call("commitUpdate", new CommitUpdate(Lease(before.Operation), Payload("late"))));
  await clients[0].Call("abortUpdate", new AbortUpdate(Lease(again.Operation), "failed", "upstream-unknown", true, "unknown"));
  await clients[0].Call("disconnect", new { });
  await clients[0].DisposeAsync(); clients.Clear();
  await manager.Stop(vault);
  var version = ComponentManager.Read<VersionManifest>(Path.Combine(data, "versions", exported.StorageVersion, "version.json"));
  File.Delete(Path.Combine(manager.KeysRoot, vault.VaultId + "." + version.KeyId + ".dpapi"));
  var locked = await manager.EnsureRunning(data);
  Check(locked.ServiceStatusValue == "LOCKED", "missing-service-key-is-locked");
  await using (var admin = await manager.Management(vault))
  {
    await admin.Call("unlock", new UnlockRequest(Crypto.B64(masterKey)));
    await admin.Call("disconnect", new { });
  }
  Check((await manager.TryStatus(vault))?.ServiceStatusValue == "READY", "independent-management-unlock");
  manager.Fault = point => { if (point == "registered") throw new IOException("injected"); };
  try { await manager.InstallLocal(publish); throw new BrokerException("expected-install-failure"); }
  catch (IOException) { }
  manager.Fault = null;
  Check(manager.ValidateInstallation().Directory == installation.Directory && !manager.InMaintenance, "interrupted-replacement-restores-old-registration");
  try
  {
    await ComponentManager.Run(Environment.ProcessPath!, ["--crash-install", "--publish", publish, "--home", manager.Home]);
    throw new BrokerException("expected-installer-process-crash");
  }
  catch (ComponentCommandException ex) when (ex.ExitCode == 86) { }
  Check(manager.InMaintenance, "installer-process-crash-leaves-durable-journal");
  await manager.RegisterVault(data);
  Check(manager.ValidateInstallation().Directory == installation.Directory && !manager.InMaintenance, "next-controller-recovers-interrupted-install");
  await manager.EnsureRunning(data);
  var changed = await manager.InstallLocal(publish);
  Check(changed.Directory != installation.Directory, "same-version-reinstall-independent-directory");
  await manager.EnsureRunning(data);
  clients.Add(await Connect(2));
  var retained = Protocol.Decode<Credential>(await clients[0].Call("getCredential", new IdRequest("usage-record")));
  Check(retained.Description.Revision == "3", "reinstall-retains-data-keys-and-client-grants");
  await clients[0].Call("disconnect", new { }); await clients[0].DisposeAsync(); clients.Clear();
  var beforeRecovery = await manager.TryStatus(vault);
  await manager.ForceRecover(data);
  Check((await manager.TryStatus(vault))?.Generation != beforeRecovery?.Generation, "explicit-force-recovery-confirms-old-processes-exit");
  await manager.Uninstall();
  Check(manager.CheckInstallation().InstallState == "not-installed" && File.Exists(Path.Combine(data, "control.db")) &&
    Directory.GetFiles(manager.KeysRoot, "*.dpapi").Length > 0, "uninstall-preserves-vault-keys-and-bindings");
  await manager.InstallLocal(publish);
  await ComponentManager.Run(Path.Combine(publish, "brokerctl.exe"), ["ensure-running", "--home", manager.Home, "--vault", data]);
  Check(await manager.TryStatus(vault) is not null, "service-survives-launching-controller-exit");
  clients.Add(await Connect(1));
  var handoffReceipt = await clients[0].Call("getOperation", new OperationRequest("ready-1"));
  Check(handoffReceipt.GetProperty("state").GetString() == "prepared", "reinstall-restores-control-receipts");
  await clients[0].Call("disconnect", new { }); await clients[0].DisposeAsync(); clients.Clear();
  var cliFile = Path.Combine(root, "cli-private", "access.dpapi");
  var grantOutput = await InvokeCli("grant", new RegisterClient("cli-client", ["read", "describe"], ["usage-record"]), ["--out", cliFile]);
  var accessBytes = BrokerPlatform.Current.Secrets.Unprotect(File.ReadAllBytes(cliFile), "cli-secret:" + vault.VaultId);
  var access = Protocol.Parse(accessBytes);
  Check(!grantOutput.Contains(access.GetProperty("accessToken").GetString()!, StringComparison.Ordinal), "cli-grant-protects-access-material");
  CryptographicOperations.ZeroMemory(accessBytes);
  var responseFile = Path.Combine(root, "cli-private", "read-response.dpapi");
  var readOutput = await InvokeCli("rpc", new { method = "getCredential", @params = new IdRequest("usage-record") },
    ["--client-file", cliFile, "--instance", "cli-instance", "--response-file", responseFile]);
  var readBytes = BrokerPlatform.Current.Secrets.Unprotect(File.ReadAllBytes(responseFile), "cli-secret:" + vault.VaultId);
  Check(Protocol.Decode<Credential>(Protocol.Parse(readBytes)).Payload == Payload("C3") && !readOutput.Contains(Payload("C3"), StringComparison.Ordinal), "cli-read-writes-only-explicit-dpapi-response");
  CryptographicOperations.ZeroMemory(readBytes);
  await manager.Stop(vault);
  var active = manager.ValidateInstallation();
  var start = new ProcessStartInfo(Path.Combine(active.Directory, "brokerctl.exe")) { UseShellExecute = false, CreateNoWindow = true };
  foreach (var arg in new[] { "serve", "--home", manager.Home, "--vault", data }) start.ArgumentList.Add(arg);
  using (var foreground = Process.Start(start)!)
  {
    for (var i = 0; i < 50 && await manager.TryStatus(vault) is null; i++) await Task.Delay(100);
    Check((await manager.TryStatus(vault))?.Ownership == "broker", "foreground-entry-shares-business-and-key-recovery");
    await manager.Stop(vault);
    await foreground.WaitForExitAsync();
    Check(foreground.ExitCode == 0, "foreground-graceful-stop");
  }
  await manager.Uninstall();
  CryptographicOperations.ZeroMemory(masterKey);
  WriteReport(true, null);
  return 0;

  async Task<BrokerClient> Connect(int index) => await BrokerClient.Connect(vault.VaultId, grants[index].ClientId, "instance-" + index, Crypto.Unb64(grants[index].AccessToken));
  async Task<string> InvokeCli(string command, object input, string[] options)
  {
    var launch = new ProcessStartInfo(Path.Combine(publish, "brokerctl.exe"))
    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var arg in new[] { command, "--home", manager.Home, "--vault", data }.Concat(options)) launch.ArgumentList.Add(arg);
    using var child = Process.Start(launch)!;
    var stdout = child.StandardOutput.ReadToEndAsync();
    var stderr = child.StandardError.ReadToEndAsync();
    await child.StandardInput.WriteAsync(JsonSerializer.Serialize(input, Protocol.Json));
    child.StandardInput.Close();
    await child.WaitForExitAsync();
    _ = await stderr;
    Protocol.Require(child.ExitCode == 0, "cli-verification-failed");
    return await stdout;
  }
}
catch (Exception ex)
{
  if (ex is PlatformFeatureUnavailableException unavailable)
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
      error = PlatformFeatureUnavailableException.ErrorCode,
      feature = unavailable.Feature,
      platform = unavailable.Platform
    }, Protocol.Json));
  if (ex is ComponentCommandException component) Console.Error.WriteLine(JsonSerializer.Serialize(new { component.Executable, component.ExitCode, component.Diagnostic }));
  WriteReport(false, PipeServer.ErrorCode(ex));
  return 1;
}
finally
{
  foreach (var client in clients) await client.DisposeAsync();
  if (manager is not null)
  {
    try { await manager.Uninstall(); }
    catch { Console.Error.WriteLine("Validation cleanup needs attention; use the retained service-home registration."); }
  }
}

void Check(bool passed, string name)
{
  if (!passed) throw new BrokerException("smoke-failed-" + name);
  results.Add(name);
  Console.WriteLine("PASS " + name);
}
void WriteReport(bool passed, string? error)
{
  var report = new
  {
    passed,
    error,
    checks = results,
    runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    os = Environment.OSVersion.VersionString,
    root,
    timestamp = DateTimeOffset.UtcNow
  };
  var bytes = Protocol.Encode(report);
  if (root is not null) LocalFiles.WriteAtomic(Path.Combine(root, "validation-result.json"), bytes);
  Console.WriteLine(Encoding.UTF8.GetString(bytes));
}
static async Task Expect(string code, Func<Task<JsonElement>> action)
{
  try { await action(); }
  catch (BrokerException ex) when (ex.Code == code) { return; }
  throw new BrokerException("expected-error-" + code);
}
static string Payload(string value) => Crypto.B64(Encoding.UTF8.GetBytes(value));
static LeaseRef Lease(Operation op) => new(op.OperationId, op.LeaseId!, op.Fence, op.Generation, op.BaseRevision);
