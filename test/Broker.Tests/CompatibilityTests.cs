using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class CompatibilityTests
{
  [WindowsFact]
  public async Task IndependentManagementConnectionsDoNotReleaseAnotherControllersSession()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var manager = new ComponentManager(Path.Combine(f.Root, "isolated-home"));
    var id = f.Vault.Manifest.VaultId;
    var registration = new VaultRegistration(id, f.Vault.Root, "", f.Vault.Manifest.OwnerSid);
    var token = RandomNumberGenerator.GetBytes(32);
    try
    {
      LocalFiles.WriteAtomic(manager.AdminPath(id), manager.Platform.Secrets.Protect(token, "management:" + id));
      var serving = new PipeServer(service, id, SHA256.HashData(token)).Run(stop.Token);
      try
      {
        await using var first = await manager.Management(registration, stop.Token, allowLegacyLifecycle: true);
        await using var second = await manager.Management(registration, stop.Token, allowLegacyLifecycle: true);
        await first.Call("status", new { });
        await second.Call("status", new { });
        await first.Call("disconnect", new { });
        var result = Protocol.Decode<ServiceStatus>(await second.Call("status", new { }));
        Assert.Equal(1, result.Sessions);
        await second.Call("disconnect", new { });
      }
      finally { await stop.CancelAsync(); await serving; }
    }
    finally { CryptographicOperations.ZeroMemory(token); }
  }
  [Fact]
  public void ManifestAndProbeUseOneReleaseIdentityAndRejectMissingApiBeforeExecuting()
  {
    var root = Path.Combine(Path.GetTempPath(), "AstraCompatibility-" + Crypto.RandomId());
    Directory.CreateDirectory(root);
    try
    {
      foreach (var file in BrokerPlatform.Current.Components.RequiredFiles) File.WriteAllText(Path.Combine(root, file), "fixture-only");
      var manifest = ComponentManager.MakeManifest(root);
      Assert.Equal(ComponentContract.Version, manifest.Version);
      Assert.Equal(3, manifest.ApiRevision);
      Assert.Equal(manifest, ComponentManager.VerifyComponent(root) with { Files = manifest.Files });
      var json = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "component.json")))!;
      json.AsObject().Remove("apiRevision");
      File.WriteAllText(Path.Combine(root, "component.json"), json.ToJsonString());
      Assert.Equal("api-incompatible", Assert.Throws<BrokerException>(() => ComponentManager.VerifyComponent(root)).Code);
      // The legacy rollback path retains all hashes/required-file checks without making this API usable.
      Assert.Equal(0, ComponentManager.VerifyComponent(root, requireCurrentApi: false).ApiRevision);
      File.WriteAllText(Path.Combine(root, BrokerPlatform.Current.Components.ExecutableName), "changed");
      Assert.Equal("component-integrity-failed", Assert.Throws<BrokerException>(() => ComponentManager.VerifyComponent(root, requireCurrentApi: false)).Code);
    }
    finally { Directory.Delete(root, true); }
  }

  [Fact]
  public void ProbeMustMatchManifestVersionApiWireStorageAndSqlite()
  {
    var manifest = new ComponentManifest(ComponentContract.Name, ComponentContract.Version, "win-x64", 1, 1, 1, 1, [], 3);
    var probe = new ComponentProbe(ComponentContract.Name, ComponentContract.Version, 1, 1, true, "fixture", 3);
    ComponentManager.ValidateProbe(manifest, probe);
    foreach (var different in new[] { probe with { Version = "0.1.0" }, probe with { ApiRevision = 0 }, probe with { ApiRevision = 4 },
      probe with { Version = "0.2.1" }, probe with { ProtocolVersion = 2 }, probe with { StorageVersion = 2 }, probe with { SqliteReady = false } })
      Assert.Throws<BrokerException>(() => ComponentManager.ValidateProbe(manifest, different));
  }

  [Fact]
  public void RuntimeIdentityAndBothApiRevisionsAreAuthenticated()
  {
    var greeting = new Greeting(1, 2, ComponentContract.Version, "vault", "generation", Crypto.B64(new byte[32]));
    var hello = new Hello(1, 2, "client", "instance", Crypto.B64(new byte[32]), "", false);
    var verifier = SHA256.HashData(new byte[32]);
    var proof = PipeProtocol.Proof(verifier, greeting, hello, "client");
    Assert.NotEqual(proof, PipeProtocol.Proof(verifier, greeting with { ApiRevision = 3 }, hello, "client"));
    Assert.NotEqual(proof, PipeProtocol.Proof(verifier, greeting with { ComponentVersion = "0.2.1" }, hello, "client"));
    Assert.NotEqual(proof, PipeProtocol.Proof(verifier, greeting, hello with { ApiRevision = 3 }, "client"));
    Assert.NotEqual(proof, PipeProtocol.Proof(verifier, greeting, hello, "server"));
    var expected = CanonicalJson.Of(new object[] { "astra.pipe-auth.v1", "client", 1, 2, ComponentContract.Version,
      "vault", "generation", greeting.Nonce, 2, "client", "instance", hello.ClientNonce, false });
    Assert.Equal(expected, PipeProtocol.AuthMessage(greeting, hello, "client"));
  }

  [WindowsTheory]
  [InlineData("3.125")]
  [InlineData("4")]
  public async Task ServiceRejectsIncompatibleClientsBeforeCreatingSession(string apiRevision)
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var verifier = SHA256.HashData(new byte[32]);
    var serving = new PipeServer(service, f.Vault.Manifest.VaultId, verifier).Run(cancel.Token);
    try
    {
      using var pipe = await BrokerPlatform.Current.Transport.Connect(PipeProtocol.Name(f.Vault.Manifest.VaultId), cancel.Token);
      var greeting = await PipeProtocol.Read<Greeting>(pipe, cancel.Token);
      Assert.Equal(ComponentContract.Version, greeting.ComponentVersion);
      Assert.Equal(ComponentContract.ApiRevision, greeting.ApiRevision);
      var hello = new Hello(1, ApiLevel.Parse(apiRevision), "management", "test", Crypto.B64(new byte[32]), "", true);
      hello = hello with { Proof = PipeProtocol.Proof(verifier, greeting, hello, "client") };
      await PipeProtocol.Write(pipe, hello, cancel.Token);
      await Assert.ThrowsAnyAsync<IOException>(() => PipeProtocol.Read<Welcome>(pipe, cancel.Token));
      Assert.Equal(0, service.Status().Sessions);
    }
    finally { await cancel.CancelAsync(); await serving; }
  }

  [WindowsTheory]
  [InlineData("1")]
  [InlineData("1.5")]
  [InlineData("2")]
  [InlineData("3")]
  public async Task ServiceAcceptsClientsRequiringLowerApiLevels(string requiredApi)
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var verifier = SHA256.HashData(new byte[32]);
    var serving = new PipeServer(service, f.Vault.Manifest.VaultId, verifier).Run(cancel.Token);
    try
    {
      using var pipe = await BrokerPlatform.Current.Transport.Connect(PipeProtocol.Name(f.Vault.Manifest.VaultId), cancel.Token);
      var greeting = await PipeProtocol.Read<Greeting>(pipe, cancel.Token);
      var hello = new Hello(1, ApiLevel.Parse(requiredApi), "management", "test", Crypto.B64(new byte[32]), "", true);
      hello = hello with { Proof = PipeProtocol.Proof(verifier, greeting, hello, "client") };
      await PipeProtocol.Write(pipe, hello, cancel.Token);
      var welcome = await PipeProtocol.Read<Welcome>(pipe, cancel.Token);
      Assert.Equal(PipeProtocol.Proof(verifier, greeting, hello, "server"), welcome.Proof);
      await PipeProtocol.Write(pipe, new RpcRequest(1, "status", "status", JsonSerializer.SerializeToElement(new { })), cancel.Token);
      Assert.True((await PipeProtocol.Read<RpcResponse>(pipe, cancel.Token)).Ok);
    }
    finally { await cancel.CancelAsync(); await serving; }
  }

  [WindowsTheory]
  [InlineData("0.1.0", "3")]
  [InlineData("0.1.0-alpha.1+test.build", "3.125")]
  [InlineData("99.0.0+future", "9007199254740993")]
  public async Task ManagementUsesApiLevelAndAcceptsDifferentComponentRelease(string version, string level)
  {
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var vaultId = Crypto.RandomId();
    var transport = BrokerPlatform.Current.Transport;
    var accepted = transport.Accept(PipeProtocol.Name(vaultId), cancel.Token);
    var connecting = BrokerClient.Connect(vaultId, "management", "test", new byte[32], management: true, cancellationToken: cancel.Token);
    using var pipe = await accepted;
    var greeting = new Greeting(1, ApiLevel.Parse(level), version, vaultId, "generation", Crypto.B64(new byte[32]));
    await PipeProtocol.Write(pipe, greeting, cancel.Token);
    var hello = await PipeProtocol.Read<Hello>(pipe, cancel.Token);
    var verifier = SHA256.HashData(new byte[32]);
    Assert.Equal(PipeProtocol.Proof(verifier, greeting, hello, "client"), hello.Proof);
    await PipeProtocol.Write(pipe, new Welcome(PipeProtocol.Proof(verifier, greeting, hello, "server")), cancel.Token);
    await using var client = await connecting;
    var business = client.Call("getSharingState", new { });
    var request = await PipeProtocol.Read<RpcRequest>(pipe, cancel.Token);
    Assert.Equal("getSharingState", request.Method);
    await PipeProtocol.Write(pipe, new RpcResponse(request.Id, true, JsonSerializer.SerializeToElement(new { accepted = true }), null), cancel.Token);
    Assert.True((await business).GetProperty("accepted").GetBoolean());
  }

  [WindowsFact]
  public async Task NewerComponentWithInsufficientDecimalApiIsRejectedBeforeAuthentication()
  {
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var vaultId = Crypto.RandomId();
    var accepted = BrokerPlatform.Current.Transport.Accept(PipeProtocol.Name(vaultId), cancel.Token);
    var connecting = BrokerClient.Connect(vaultId, "client", "test", new byte[32], cancellationToken: cancel.Token);
    using var pipe = await accepted;
    await PipeProtocol.Write(pipe, new Greeting(1, 2.9999999999999999999999999999m, "999.0.0+future", vaultId, "generation", Crypto.B64(new byte[32])), cancel.Token);
    Assert.Equal("api-incompatible", (await Assert.ThrowsAsync<BrokerException>(() => connecting)).Code);
    Assert.Equal(0, await pipe.ReadAsync(new byte[1], cancel.Token));
  }

  [WindowsFact]
  public async Task OrdinaryClientRejectsLegacyGreetingWithoutSendingAuthenticationOrBusinessRequest()
  {
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var vaultId = Crypto.RandomId();
    var transport = BrokerPlatform.Current.Transport;
    var accepted = transport.Accept(PipeProtocol.Name(vaultId), cancel.Token);
    var connecting = BrokerClient.Connect(vaultId, "client", "test", new byte[32], cancellationToken: cancel.Token);
    using var pipe = await accepted;
    await PipeProtocol.Write(pipe, new { protocolVersion = 1, vaultId, generation = "generation", nonce = Crypto.B64(new byte[32]) }, cancel.Token);
    Assert.Equal("api-incompatible", (await Assert.ThrowsAsync<BrokerException>(() => connecting)).Code);
    Assert.Equal(0, await pipe.ReadAsync(new byte[1], cancel.Token));
    Assert.Equal("management-required", (await Assert.ThrowsAsync<BrokerException>(() => BrokerClient.Connect(vaultId, "client", "test", new byte[32], allowLegacyLifecycle: true))).Code);
  }

  [WindowsFact]
  public async Task LifecycleWhiteListIsIndependentOfComponentRelease()
  {
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var verifier = SHA256.HashData(new byte[32]);
    foreach (var lifecycle in new[] { false, true })
    {
      var vaultId = Crypto.RandomId();
      var accepted = BrokerPlatform.Current.Transport.Accept(PipeProtocol.Name(vaultId), cancel.Token);
      var connecting = BrokerClient.Connect(vaultId, "management", "test", new byte[32], management: true,
        cancellationToken: cancel.Token, allowLegacyLifecycle: lifecycle);
      using var pipe = await accepted;
      // Release text does not decide API compatibility. A lifecycle connection still has a smaller method allowlist.
      var expectedApi = lifecycle ? ComponentContract.LifecycleApiRevision : ComponentContract.ApiRevision;
      var greeting = new Greeting(1, expectedApi, "0.1.9", vaultId, "generation", Crypto.B64(new byte[32]));
      await PipeProtocol.Write(pipe, greeting, cancel.Token);
      var hello = await PipeProtocol.Read<Hello>(pipe, cancel.Token);
      Assert.Equal(expectedApi, hello.ApiRevision);
      Assert.Equal(PipeProtocol.Proof(verifier, greeting, hello, "client"), hello.Proof);
      await PipeProtocol.Write(pipe, new Welcome(PipeProtocol.Proof(verifier, greeting, hello, "server")), cancel.Token);
      await using var client = await connecting;
      if (lifecycle)
        foreach (var method in new[] { "getCredential", "initialize", "registerClient", "unlock", "getSharingState", "handoff" })
          Assert.Equal("legacy-lifecycle-only", (await Assert.ThrowsAsync<BrokerException>(() => client.Call(method, new { }))).Code);
      foreach (var method in new[] { "status", "stop", "disconnect" })
      {
        var result = client.Call(method, new { });
        var request = await PipeProtocol.Read<RpcRequest>(pipe, cancel.Token);
        Assert.Equal(method, request.Method);
        await PipeProtocol.Write(pipe, new RpcResponse(request.Id, true, JsonSerializer.SerializeToElement(new { accepted = true }), null), cancel.Token);
        Assert.True((await result).GetProperty("accepted").GetBoolean());
      }
    }
  }

  [WindowsFact]
  public async Task LegacyManagementConnectionAuthenticatesButOnlyAllowsLifecycleMethods()
  {
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var vaultId = Crypto.RandomId();
    var nonce = Crypto.B64(new byte[32]);
    var verifier = SHA256.HashData(new byte[32]);
    var accepted = BrokerPlatform.Current.Transport.Accept(PipeProtocol.Name(vaultId), cancel.Token);
    var connecting = BrokerClient.Connect(vaultId, "management", "test", new byte[32], management: true,
      cancellationToken: cancel.Token, allowLegacyLifecycle: true);
    using var pipe = await accepted;
    await PipeProtocol.Write(pipe, new { protocolVersion = 1, vaultId, generation = "generation", nonce }, cancel.Token);
    var hello = await PipeProtocol.Read<JsonElement>(pipe, cancel.Token);
    string Proof(string role) => Crypto.B64(HMACSHA256.HashData(verifier, CanonicalJson.Of(new object[] { "astra.pipe-auth.v1", role,
      1, vaultId, "generation", nonce, "management", "test", hello.GetProperty("clientNonce").GetString()!, true })));
    Assert.Equal(Proof("client"), hello.GetProperty("proof").GetString());
    await PipeProtocol.Write(pipe, new Welcome(Proof("server")), cancel.Token);
    await using var client = await connecting;
    foreach (var method in new[] { "getCredential", "initialize", "registerClient", "unlock", "getSharingState", "handoff" })
      Assert.Equal("legacy-lifecycle-only", (await Assert.ThrowsAsync<BrokerException>(() => client.Call(method, new { }))).Code);
    var status = client.Call("status", new { });
    var request = await PipeProtocol.Read<RpcRequest>(pipe, cancel.Token);
    Assert.Equal("status", request.Method);
    await PipeProtocol.Write(pipe, new RpcResponse(request.Id, true, JsonSerializer.SerializeToElement(new { serviceStatus = "READY" }), null), cancel.Token);
    Assert.Equal("READY", (await status).GetProperty("serviceStatus").GetString());
  }
}
