using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Astra.Credentials;

return await Cli.Run(args);

internal sealed record ClientAccess(string ClientId, string AccessToken);
internal sealed record CliRpc(string Method, JsonElement Params);

internal static class Cli
{
  public static async Task<int> Run(string[] args)
  {
    try
    {
      Console.InputEncoding = Encoding.UTF8;
      Console.OutputEncoding = new UTF8Encoding(false);
      if (args.Length == 0 || args[0] is "help" or "--help")
      {
        Console.WriteLine($"""
          Astra Credential Broker {ComponentContract.Version} (protocol/storage v1; API revision {ComponentContract.ApiRevision}; bundled adapters: Windows)
          brokerctl component-info
          brokerctl schema --out <schema.json>
          brokerctl make-manifest --source <complete-publish-directory>
          brokerctl install-local --source <complete-publish-directory> [--home <private-service-home>]
          brokerctl install-status [--home ...]
          brokerctl register-vault --vault <private-data-directory> [--home ...]
          brokerctl ensure-running|status|stop|restart --vault <directory> [--home ...]
          brokerctl recover --force --vault <directory> [--home ...] (explicitly terminate verified broker processes)
          brokerctl serve --vault <directory> [--home ...]   (foreground debugger entry)
          brokerctl grant --vault <directory> --out <private-client-file> [--home ...] < grant.json
          brokerctl rpc --vault <directory> --client-file <file> --instance <stable-id> [--response-file <private-file>] [--home ...] < request.json
          brokerctl rpc --vault <directory> --admin [--response-file <private-file>] [--home ...] < request.json
          brokerctl uninstall [--home ...] (invoke an external publish copy)
          Secrets enter via stdin/DPAPI files, never command arguments. See docs/protocol.md.
          """);
        return 0;
      }
      var command = args[0];
      var options = ParseOptions(args[1..]);
      string Required(string name) => options.GetValueOrDefault(name) ?? throw new BrokerException("missing-option-" + name);
      if (command == "schema")
      {
        var path = Required("out");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, ProtocolSchema.Build().ToJsonString(new JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n", new UTF8Encoding(false));
        return 0;
      }
      if (command == "component-info")
      {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT sqlite_version()";
        Output(new ComponentProbe(ComponentContract.Name, ComponentContract.Version, Protocol.Version, ComponentContract.StorageVersion, query.ExecuteScalar() is string,
          Path.GetDirectoryName(typeof(object).Assembly.Location), ComponentContract.ApiRevision));
        return 0;
      }
      if (command == "make-manifest") { Output(ComponentManager.MakeManifest(Required("source"))); return 0; }
      var manager = new ComponentManager(options.GetValueOrDefault("home"));
      if (command == "install-local") { Output(await manager.InstallLocal(Required("source"))); return 0; }
      if (command == "install-status") { Output(manager.CheckInstallation()); return 0; }
      if (command == "uninstall") { await manager.Uninstall(); Output(new { uninstalled = true, dataAndKeysRetained = true }); return 0; }
      if (command == "register-vault") { Output(await manager.RegisterVault(Required("vault"))); return 0; }
      var vault = manager.Registration(Required("vault"));
      switch (command)
      {
        case "ensure-running": Output(await manager.EnsureRunning(vault.Root)); return 0;
        case "recover":
          Protocol.Require(options.ContainsKey("force"), "force-confirmation-required");
          await manager.ForceRecover(vault.Root);
          Output(await manager.TryStatus(vault));
          return 0;
        case "status":
          Output(new
          {
            installation = manager.CheckInstallation(),
            runtime = await manager.TryStatus(vault),
            offlineState = File.Exists(Path.Combine(vault.Root, "runtime", "endpoint.json")) ?
              ComponentManager.Read<RuntimeEndpoint>(Path.Combine(vault.Root, "runtime", "endpoint.json")).State : "STOPPED"
          });
          return 0;
        case "stop":
        case "restart":
          using (await ComponentManager.WaitLock(Path.Combine(manager.Home, "component.lock"))) await manager.Stop(vault);
          Output<object>(command == "restart" ? await manager.EnsureRunning(vault.Root) : new { stopped = true });
          return 0;
        case "supervise": return await Supervise(manager, vault);
        case "serve": return await Serve(manager, vault, options.ContainsKey("supervised"));
        case "grant":
          await using (var client = await manager.Management(vault))
          {
            var request = Protocol.Decode<RegisterClient>(await Input());
            var result = Protocol.Decode<RegisteredClient>(await client.Call("registerClient", request));
            SaveSecret(manager, Required("out"), vault.VaultId, new ClientAccess(result.ClientId, result.AccessToken));
            await client.Call("disconnect", new { });
            Output(new { result.ClientId, saved = LocalFiles.FullPath(Required("out")) });
          }
          return 0;
        case "rpc":
          var rpc = Protocol.Decode<CliRpc>(await Input());
          var sensitive = new[] { "initialize", "recoverDelivery", "getCredential", "beginUpdate", "createCredential", "registerClient" }.Contains(rpc.Method, StringComparer.Ordinal);
          Protocol.Require(!sensitive || options.ContainsKey("response-file"), "secret-response-file-required");
          await using (var client = await RpcClient(manager, vault, options))
          {
            var result = await client.Call(rpc.Method, rpc.Params);
            if (options.TryGetValue("response-file", out var responseFile))
            { SaveSecret(manager, responseFile!, vault.VaultId, result); Output(new { saved = LocalFiles.FullPath(responseFile!) }); }
            else Output(result);
            if (rpc.Method != "disconnect") await client.Call("disconnect", new { });
          }
          return 0;
        default: throw new BrokerException("unknown-command");
      }
    }
    catch (Exception ex)
    {
      // Never print exception messages, requests, stack traces, tokens or filesystem content.
      if (ex is PlatformFeatureUnavailableException unavailable)
        Console.Error.WriteLine(JsonSerializer.Serialize(new
        {
          error = PlatformFeatureUnavailableException.ErrorCode,
          feature = unavailable.Feature,
          platform = unavailable.Platform,
          message = unavailable.Message
        }, Protocol.Json));
      else Console.Error.WriteLine(JsonSerializer.Serialize(new { error = PipeServer.ErrorCode(ex) }, Protocol.Json));
      return 1;
    }
  }

  private static async Task<int> Serve(ComponentManager manager, VaultRegistration registration, bool supervised)
  {
    Protocol.Require(!manager.InMaintenance, "service-maintenance");
    var stopPath = Path.Combine(registration.Root, "runtime", "stop.request");
    if (File.Exists(stopPath))
    {
      if (supervised) return 0;
      File.Delete(stopPath);
    }
    using var vault = Vault.Open(registration.Root, manager.KeysRoot, platform: manager.Platform);
    using var service = new BrokerService(vault);
    var adminToken = manager.AdminToken(registration.VaultId);
    var verifier = SHA256.HashData(adminToken);
    CryptographicOperations.ZeroMemory(adminToken);
    var endpointPath = Path.Combine(vault.Root, "runtime", "endpoint.json");
    var process = manager.Platform.Components.CurrentProcess;
    var endpoint = new RuntimeEndpoint(process.Pid, process.StartTime, service.Generation,
      PipeProtocol.Name(registration.VaultId, manager.Platform), service.Status().ServiceStatusValue);
    LocalFiles.WriteAtomic(endpointPath, Protocol.Encode(endpoint));
    using var cancel = new CancellationTokenSource();
    ConsoleCancelEventHandler handler = (_, e) =>
    {
      e.Cancel = true;
      var admin = new Actor("management", "foreground", [], [], true, true);
      service.Connect(admin);
      service.Dispatch(admin, "stop", JsonSerializer.SerializeToElement(new { }));
    };
    Console.CancelKeyPress += handler;
    try
    {
      await new PipeServer(service, registration.VaultId, verifier).Run(cancel.Token);
      LocalFiles.WriteAtomic(endpointPath, Protocol.Encode(endpoint with { State = "STOPPED" }));
      return 0;
    }
    finally
    {
      Console.CancelKeyPress -= handler;
      CryptographicOperations.ZeroMemory(verifier);
    }
  }
  private static async Task<int> Supervise(ComponentManager manager, VaultRegistration vault)
  {
    // Independent hidden process, not tied to a client and without inherited console handles.
    if (manager.InMaintenance) return 0;
    var installed = manager.ValidateInstallation();
    Protocol.Require(Path.GetFullPath(Environment.ProcessPath!).Equals(Path.Combine(installed.Directory, manager.Platform.Components.ExecutableName), manager.Platform.Components.PathComparison), "unregistered-executable");
    using var held = LocalFiles.AcquireLock(Path.Combine(vault.Root, "runtime", "supervisor.lock"));
    var self = manager.Platform.Components.CurrentProcess;
    var supervisorPath = Path.Combine(vault.Root, "runtime", "supervisor.json");
    LocalFiles.WriteAtomic(supervisorPath, Protocol.Encode(new RuntimeEndpoint(self.Pid, self.StartTime, "", "", "STARTING")));
    var stopPath = Path.Combine(vault.Root, "runtime", "stop.request");
    for (var attempt = 0; attempt < 4 && !manager.InMaintenance && !File.Exists(stopPath); attempt++)
    {
      var exitCode = await manager.Platform.Components.RunWorker(Path.Combine(installed.Directory, manager.Platform.Components.ExecutableName),
        ["serve", "--supervised", "--home", manager.Home, "--vault", vault.Root]);
      if (exitCode == 0 || manager.InMaintenance || File.Exists(stopPath)) return 0;
      await Task.Delay(TimeSpan.FromSeconds(1 << attempt));
    }
    LocalFiles.WriteAtomic(Path.Combine(vault.Root, "runtime", "endpoint.json"), Protocol.Encode(
      new RuntimeEndpoint(self.Pid, self.StartTime, "", "", "FAILED")));
    return 0; // Finite budget. A user action can retry ensure-running after diagnosing FAILED.
  }
  private static async Task<BrokerClient> RpcClient(ComponentManager manager, VaultRegistration vault, Dictionary<string, string?> options)
  {
    if (options.ContainsKey("admin")) return await manager.Management(vault);
    Protocol.Require(options.TryGetValue("client-file", out var file) && file is not null && options.ContainsKey("instance"), "client-options-required");
    var bytes = manager.Platform.Secrets.Unprotect(File.ReadAllBytes(LocalFiles.FullPath(file!)), "cli-secret:" + vault.VaultId);
    try
    {
      var access = Protocol.Decode<ClientAccess>(Protocol.Parse(bytes));
      var token = Crypto.Unb64(access.AccessToken, 32);
      try { return await BrokerClient.Connect(vault.VaultId, access.ClientId, options["instance"]!, token, platform: manager.Platform); }
      finally { CryptographicOperations.ZeroMemory(token); }
    }
    finally { CryptographicOperations.ZeroMemory(bytes); }
  }
  private static void SaveSecret<T>(ComponentManager manager, string path, string vaultId, T value)
  {
    var full = LocalFiles.FullPath(path);
    manager.Platform.Files.CreatePrivateDirectory(Path.GetDirectoryName(full)!);
    var plain = Protocol.Encode(value);
    try { LocalFiles.WriteAtomic(full, manager.Platform.Secrets.Protect(plain, "cli-secret:" + vaultId)); }
    finally { CryptographicOperations.ZeroMemory(plain); }
  }
  private static Dictionary<string, string?> ParseOptions(string[] args)
  {
    var result = new Dictionary<string, string?>(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i++)
    {
      Protocol.Require(args[i].StartsWith("--", StringComparison.Ordinal), "invalid-option");
      var name = args[i][2..];
      var value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : null;
      Protocol.Require(result.TryAdd(name, value), "duplicate-option");
    }
    return result;
  }
  private static async Task<JsonElement> Input()
  {
    var buffer = new char[4096];
    var text = new StringBuilder();
    int count;
    while ((count = await Console.In.ReadAsync(buffer)) > 0)
    {
      Protocol.Require(text.Length + count <= Protocol.MaxMessageBytes, "message-too-large");
      text.Append(buffer, 0, count);
    }
    return Protocol.Parse(Encoding.UTF8.GetBytes(text.ToString()));
  }
  private static void Output<T>(T value) => Console.WriteLine(JsonSerializer.Serialize(value, Protocol.Json));
}
