using System.Security.Cryptography;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class PlatformTests
{
  [Fact]
  public async Task SharedNamedPipeTransportExchangesFramesWithoutIdentityOrStorageAdapters()
  {
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var transport = BrokerPlatform.Current.Transport;
    var address = "astra-transport-test-" + Crypto.RandomId();
    var accepted = transport.Accept(address, timeout.Token);
    using var client = await transport.Connect(address, timeout.Token);
    using var server = await accepted;
    var request = PipeProtocol.Read<IdRequest>(server, timeout.Token);
    await PipeProtocol.Write(client, new IdRequest("request"), timeout.Token);
    Assert.Equal("request", (await request).CredentialId);
    var response = PipeProtocol.Read<IdRequest>(client, timeout.Token);
    await PipeProtocol.Write(server, new IdRequest("response"), timeout.Token);
    Assert.Equal("response", (await response).CredentialId);
  }

  [Fact]
  public async Task CancelledNamedPipeListenerReleasesAddressForReuse()
  {
    using var cancelled = new CancellationTokenSource();
    var transport = BrokerPlatform.Current.Transport;
    var address = "astra-cancel-test-" + Crypto.RandomId();
    var pending = transport.Accept(address, cancelled.Token);
    await cancelled.CancelAsync();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var accepted = transport.Accept(address, timeout.Token);
    using var client = await transport.Connect(address, timeout.Token);
    using var server = await accepted;
    var received = new byte[1];
    var read = server.ReadExactlyAsync(received, timeout.Token);
    await client.WriteAsync(new byte[] { 42 }, timeout.Token);
    await read;
    Assert.Equal(42, received[0]);
  }

  [Theory]
  [InlineData("linux", "user-identity")]
  [InlineData("linux", "private-file-system")]
  [InlineData("macos", "secret-protection")]
  [InlineData("macos", "local-transport")]
  [InlineData("unknown", "component-host")]
  public void MissingCapabilityReportsExactFeatureWithoutRejectingComposition(string os, string feature)
  {
    var platform = BrokerPlatform.Unavailable(os);
    var error = Assert.Throws<PlatformFeatureUnavailableException>(() =>
    {
      switch (feature)
      {
        case "user-identity": _ = platform.Identity.CurrentUserId; break;
        case "private-file-system": platform.Files.CreatePrivateDirectory("unused"); break;
        case "secret-protection": platform.Secrets.Protect([], "unused"); break;
        case "local-transport": _ = platform.Transport.Accept("unused", CancellationToken.None); break;
        case "component-host": platform.Components.LaunchDetached("unused", [], "unused"); break;
      }
    });
    Assert.Equal(feature, error.Feature);
    Assert.Equal(os, error.Platform);
    Assert.Equal("platform-feature-unavailable", PipeServer.ErrorCode(error));
    // Selecting or rejecting a provider never disables independent portable functionality.
    Assert.NotNull(ProtocolSchema.Build()["$defs"]);
    Assert.Equal(Crypto.Hash([1, 2]), Crypto.Hash(Crypto.Unb64(Crypto.B64([1, 2]))));
  }

  [Fact]
  public void MissingPrivateStorageCannotCreateVaultOrComponentDirectories()
  {
    var root = Path.Combine(Path.GetTempPath(), "AstraMissing-" + Crypto.RandomId());
    var platform = BrokerPlatform.Unavailable("linux");
    Assert.Equal("private-file-system", Assert.Throws<PlatformFeatureUnavailableException>(() =>
      Vault.Open(root, root + "-keys", true, platform)).Feature);
    Assert.Equal("private-file-system", Assert.Throws<PlatformFeatureUnavailableException>(() =>
      new ComponentManager(root, platform)).Feature);
    Assert.False(Directory.Exists(root));
    Assert.False(Directory.Exists(root + "-keys"));
  }

  [Fact]
  public async Task MissingTransportIsReportedByClientAndServerUsingTheirInjectedPlatform()
  {
    using var f = new PortableFixture();
    using var vault = f.Open();
    using var service = new BrokerService(vault);
    var clientError = await Assert.ThrowsAsync<PlatformFeatureUnavailableException>(() =>
      BrokerClient.Connect(vault.Manifest.VaultId, "client", "instance", new byte[32], platform: f.Platform));
    Assert.Equal("local-transport", clientError.Feature);
    var serverError = await Assert.ThrowsAsync<PlatformFeatureUnavailableException>(() =>
      new PipeServer(service, vault.Manifest.VaultId, new byte[32]).Run(CancellationToken.None));
    Assert.Equal("local-transport", serverError.Feature);
  }

  [Fact]
  public void MissingKeyProtectionCannotPublishOrSilentlyPersistPlaintextKeys()
  {
    using var f = new PortableFixture();
    var platform = f.Platform with { Secrets = BrokerPlatform.Unavailable("linux").Secrets };
    using var vault = f.Open(platform);
    var error = Assert.Throws<PlatformFeatureUnavailableException>(() =>
      vault.Initialize(Fixture.A, new("export", "source", [])));
    Assert.Equal("secret-protection", error.Feature);
    Assert.Null(vault.Setting("currentVersion"));
    Assert.Empty(Directory.EnumerateDirectories(Path.Combine(vault.Root, "versions")));
    Assert.Empty(Directory.EnumerateFiles(vault.KeysRoot));
  }

  [Fact]
  public void VaultLeaseCommitAndRestartUseInjectedCapabilitiesWithoutTransportOrComponentHost()
  {
    using var f = new PortableFixture();
    string vaultId;
    using (var vault = f.Open())
    {
      vaultId = vault.Manifest.VaultId;
      Assert.Equal("test-user", vault.Manifest.OwnerSid);
      var published = vault.Initialize(Fixture.A, new("export", "source", [new("record", "opaque", 1, Fixture.Payload("C1"), [])]));
      Assert.Equal("exported", published.State);
      Assert.EndsWith(".test-protected", vault.KeyPath(published.KeyId));
      vault.Set("ownership", "broker");
      using var service = new BrokerService(vault);
      var admin = new Actor("management", "portable-test", [], [], true, true);
      service.Connect(admin);
      service.Dispatch(admin, "registerClient", System.Text.Json.JsonSerializer.SerializeToElement(
        new RegisterClient(Fixture.A.ClientId, ["read", "update"], [], true), Protocol.Json));
      service.Connect(Fixture.A);
      var begin = (BeginResult)service.Dispatch(Fixture.A, "beginUpdate",
        System.Text.Json.JsonSerializer.SerializeToElement(new BeginUpdate("record", "1", "refresh"), Protocol.Json));
      var lease = Fixture.Lease(begin.Operation!);
      service.Dispatch(Fixture.A, "markUpdateStarted", System.Text.Json.JsonSerializer.SerializeToElement(lease, Protocol.Json));
      service.Dispatch(Fixture.A, "commitUpdate", System.Text.Json.JsonSerializer.SerializeToElement(new CommitUpdate(lease, Fixture.Payload("C2")), Protocol.Json));
    }
    using (var vault = f.Open())
    using (var service = new BrokerService(vault))
    {
      Assert.Equal(vaultId, vault.Manifest.VaultId);
      Assert.Same(f.Platform, service.Platform);
      service.Connect(Fixture.A);
      var current = (Credential)service.Dispatch(Fixture.A, "getCredential",
        System.Text.Json.JsonSerializer.SerializeToElement(new IdRequest("record"), Protocol.Json));
      Assert.Equal("2", current.Description.Revision);
      Assert.Equal(Fixture.Payload("C2"), current.Payload);
    }
  }

  // Test doubles deliberately provide no production OS permission guarantees. They live
  // only in test/ and let the real business/storage state machine run on any test host.
  private sealed class PortableFixture : IDisposable
  {
    private readonly string root = Path.Combine(Path.GetTempPath(), "AstraPortable-" + Crypto.RandomId());
    private readonly TestSecrets secrets = new();
    public BrokerPlatform Platform { get; }
    public PortableFixture()
    {
      Platform = BrokerPlatform.Unavailable("test") with { Identity = new TestIdentity(), Files = new TestFiles(), Secrets = secrets };
    }
    public Vault Open(BrokerPlatform? platform = null) => Vault.Open(Path.Combine(root, "data"), Path.Combine(root, "keys"), true, platform ?? Platform);
    public void Dispose()
    {
      secrets.Dispose();
      if (Directory.Exists(root)) Directory.Delete(root, true);
    }
  }
  private sealed class TestIdentity : IUserIdentity
  {
    public string CurrentUserId => "test-user";
  }
  private sealed class TestFiles : IPrivateFileSystem
  {
    private readonly Dictionary<string, string> ids = new(StringComparer.Ordinal);
    public string CreatePrivateDirectory(string path)
    {
      var full = LocalFiles.FullPath(path);
      Directory.CreateDirectory(full);
      return full;
    }
    public void ValidatePrivateDirectory(string path)
    {
      LocalFiles.CheckLinks(path);
      Assert.True(Directory.Exists(path));
    }
    public void ValidateTree(string root) => ValidatePrivateDirectory(root);
    public string DirectoryIdentity(string path)
    {
      var full = LocalFiles.FullPath(path);
      if (!ids.TryGetValue(full, out var id)) ids[full] = id = Crypto.RandomId();
      return id;
    }
  }
  private sealed class TestSecrets : ISecretProtector, IDisposable
  {
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
    public string FileExtension => ".test-protected";
    public byte[] Protect(byte[] value, string purpose) => Protocol.Encode(Crypto.Encrypt(key, value, CanonicalJson.Of(purpose)));
    public byte[] Unprotect(byte[] value, string purpose) => Crypto.Decrypt(key, Protocol.Decode<SealedBytes>(Protocol.Parse(value)), CanonicalJson.Of(purpose));
    public void Dispose() => CryptographicOperations.ZeroMemory(key);
  }
}
