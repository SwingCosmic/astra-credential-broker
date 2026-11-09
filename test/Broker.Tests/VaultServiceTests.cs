using System.Security.Cryptography;
using System.Text.Json;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class VaultServiceTests
{
  [WindowsFact]
  public void IdleTicksAndManagementDisconnectDoNotWriteCredentialDatabaseOrGrowWal()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    var database = Path.Combine(f.Vault.VersionPath(f.Published.StorageVersion), "credentials.db");
    using var observer = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database};Pooling=False");
    observer.Open();
    long DataVersion()
    {
      using var command = observer.CreateCommand();
      command.CommandText = "PRAGMA data_version";
      return (long)command.ExecuteScalar()!;
    }
    var before = DataVersion();
    var wal = database + "-wal";
    var initialSize = File.Exists(wal) ? new FileInfo(wal).Length : 0;
    for (var i = 0; i < 200; i++)
    {
      f.Time.Advance(200);
      service.Tick();
    }
    service.Connect(Admin);
    Call(service, Admin, "status", new { });
    Call(service, Admin, "disconnect", new { });
    Assert.Equal(initialSize, File.Exists(wal) ? new FileInfo(wal).Length : 0);
    Assert.Equal(before, DataVersion());
    service.Tick();
    f.Time.Advance(BrokerService.IdleTimeout);
    service.Tick();
    Assert.True(service.ExitRequested);
  }
  [WindowsFact]
  public void OversizedEncryptedMigrationCannotPublishAnUnreadableVersion()
  {
    var root = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraBrokerSize-" + Crypto.RandomId()));
    try
    {
      using var vault = Vault.Open(Path.Combine(root, "data"), Path.Combine(root, "keys"), true);
      var payload = Crypto.B64(new byte[100_000]);
      var records = Enumerable.Range(0, 12).Select(i => new InitialRecord("record-" + i, "opaque", 1, payload, [])).ToArray();
      var request = new InitializeRequest("export", "watermark", records);
      Assert.True(Protocol.Encode(request).Length < Protocol.MaxMessageBytes);
      Assert.Equal("message-too-large", Assert.Throws<BrokerException>(() => vault.Initialize(Fixture.A, request)).Code);
      Assert.Null(vault.Setting("currentVersion"));
      Assert.Empty(Directory.EnumerateDirectories(Path.Combine(vault.Root, "versions")));
    }
    finally { Directory.Delete(root, true); }
  }
  private static object Call(BrokerService service, Actor actor, string method, object parameters) =>
    service.Dispatch(actor, method, JsonSerializer.SerializeToElement(parameters, Protocol.Json));
  private static readonly Actor Admin = new("management", "tests", [], [], true, true);
  private static RegisteredClient Register(BrokerService service, string id)
  {
    service.Connect(Admin);
    return (RegisteredClient)Call(service, Admin, "registerClient", new RegisterClient(id,
      ["read", "describe", "update", "create", "events", "initialize", "import", "handoff"], [], true));
  }
  private static ReadyRequest Prepare(BrokerService service, Fixture fixture, Actor actor, string operation)
  {
    service.Connect(actor);
    var challenge = (ProofChallenge)Call(service, actor, "prepareChallenge", new { });
    var request = new ReadyRequest(operation, fixture.Initial.SourceWatermark, challenge.ChallengeId, "");
    request = request with { Proof = BrokerService.ReadyProof(fixture.Key, fixture.Vault.Manifest.VaultId, fixture.Published.StorageVersion, actor.ClientId, request, challenge.Nonce) };
    Call(service, actor, "prepareClient", request);
    return request;
  }
  [WindowsFact]
  public void PublishRecoversOriginalReceiptAndAllowsRecipientToWriteWhileSourceIsOffline()
  {
    var root = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraPublish-" + Crypto.RandomId()));
    try
    {
      var data = Path.Combine(root, "data");
      var keys = Path.Combine(root, "keys");
      var request = new InitializeRequest("export", "watermark", [new("id", "opaque", 1, Fixture.Payload("C1"), [])]);
      using (var vault = Vault.Open(data, keys, true))
      using (var service = new BrokerService(vault))
      {
        Register(service, Fixture.A.ClientId);
        service.Connect(Fixture.A);
        Assert.Equal("operation-not-found", Assert.Throws<BrokerException>(() =>
          Call(service, Fixture.A, "getOperation", new OperationRequest("export"))).Code);
        vault.Fault = point => { if (point == "published") throw new IOException("lost-response"); };
        Assert.Throws<IOException>(() => Call(service, Fixture.A, "publish", request));
      }
      using (var vault = Vault.Open(data, keys))
      using (var service = new BrokerService(vault))
      {
        Register(service, Fixture.B.ClientId);
        service.Connect(Fixture.B);
        Assert.Equal("broker", service.Status().Ownership);
        var before = (SnapshotWatermark)Call(service, Fixture.B, "getSnapshotWatermark", new { });
        var lease = Fixture.Lease(((BeginResult)Call(service, Fixture.B, "beginUpdate", new BeginUpdate("id", "1", "change"))).Operation!);
        Call(service, Fixture.B, "markUpdateStarted", lease);
        Call(service, Fixture.B, "commitUpdate", new CommitUpdate(lease, Fixture.Payload("C2")));
        Assert.NotEqual(before, (SnapshotWatermark)Call(service, Fixture.B, "getSnapshotWatermark", new { }));
        Assert.Equal("forbidden", Assert.Throws<BrokerException>(() =>
          Call(service, Fixture.B, "getOperation", new OperationRequest("export"))).Code);
        service.Connect(Fixture.A);
        var receipt = (JsonElement)Call(service, Fixture.A, "getOperation", new OperationRequest("export"));
        Assert.Null(receipt.GetProperty("migrationKey").GetString());
        var replay = (InitializeResult)Call(service, Fixture.A, "publish", request);
        Assert.Equal(before.StorageVersion, replay.StorageVersion);
        Assert.Null(replay.MigrationKey);
        Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "initialize", request));
        Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "publish", request with { SourceWatermark = "new" }));
        Assert.Equal(Fixture.Payload("C2"), ((Credential)Call(service, Fixture.A, "getCredential", new IdRequest("id"))).Payload);
        Assert.StartsWith("acm1_", vault.RecoverDelivery(Fixture.A));
        Assert.Equal("broker", service.Status().Ownership);
      }
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void PublishedUniqueKeysUseTheSameIndexAsLaterCreates()
  {
    var root = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraUniquePublish-" + Crypto.RandomId()));
    try
    {
      using var vault = Vault.Open(Path.Combine(root, "data"), Path.Combine(root, "keys"), true);
      var record = new InitialRecord("one", "opaque", 1, "", [], UniqueKey: "same-key");
      var request = new InitializeRequest("export", "watermark", [record, record with { CredentialId = "two" }]);
      Assert.Equal("credential-identity-exists", Assert.Throws<BrokerException>(() => vault.Initialize(Fixture.A, request, true)).Code);
      Assert.Null(vault.Setting("currentVersion"));
      vault.Initialize(Fixture.A, request with { Records = [record] }, true);
      using var service = new BrokerService(vault);
      Register(service, Fixture.B.ClientId);
      service.Connect(Fixture.B);
      Assert.Equal("credential-identity-exists", Assert.Throws<BrokerException>(() =>
        Call(service, Fixture.B, "createCredential", new CreateCredential("second", "create", "opaque", 1, "", [], UniqueKey: "same-key"))).Code);
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void GrantUpgradeMatchesTheExactPriorGrantOnceAndPreservesItsToken()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    service.Connect(Admin);
    string[] previous = ["describe", "read"];
    var upgrade = new UpdateClientGrant("old-client", previous, ["read", "describe", "create"], [], true);
    foreach (var name in new[] { "old-client", "restricted", "revoked" })
      Call(service, Admin, "registerClient", new RegisterClient(name, previous, name == "restricted" ? ["id"] : [], name != "restricted"));
    Call(service, Admin, "revokeClient", new ClientIdRequest("revoked"));
    Assert.Throws<BrokerException>(() => Call(service, Admin, "updateClientGrant", upgrade with { ClientId = "revoked" }));
    Call(service, Admin, "updateClientGrant", upgrade with { ClientId = "restricted" });
    Assert.DoesNotContain("create", service.Grant("restricted")!.Scopes);
    var original = service.Grant("old-client")!;
    Call(service, Admin, "updateClientGrant", upgrade);
    var updated = service.Grant("old-client")!;
    Assert.Equal(original.TokenHash, updated.TokenHash);
    Assert.Contains("create", updated.Scopes);
    Call(service, Admin, "updateClientGrant", upgrade with { PreviousScopes = updated.Scopes, Scopes = [.. updated.Scopes, "delete"] });
    Assert.DoesNotContain("delete", service.Grant("old-client")!.Scopes);
  }
  [WindowsTheory]
  [InlineData("initial-records-written")]
  [InlineData("migration-written")]
  [InlineData("key-saved")]
  public void FailedInitialCandidateNeverPublishesAndRetryUsesNewDirectory(string fault)
  {
    var root = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraBrokerFault-" + Crypto.RandomId()));
    try
    {
      using var vault = Vault.Open(Path.Combine(root, "data"), Path.Combine(root, "keys"), true);
      vault.Fault = point => { if (point == fault) throw new IOException("injected"); };
      var request = new InitializeRequest("export", "watermark", [new("id", "custom", 1, "", [])]);
      Assert.Throws<IOException>(() => vault.Initialize(Fixture.A, request));
      Assert.Null(vault.Setting("currentVersion"));
      Assert.Empty(Directory.EnumerateDirectories(Path.Combine(vault.Root, "versions")));
      vault.Fault = null;
      Assert.Equal("exported", vault.Initialize(Fixture.A, request).State);
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void PublishedResponseLossPreservesCurrentAndRecoversDeliveryOnlyUntilAcknowledged()
  {
    var root = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraBrokerFault-" + Crypto.RandomId()));
    try
    {
      using var vault = Vault.Open(Path.Combine(root, "data"), Path.Combine(root, "keys"), true);
      vault.Fault = point => { if (point == "published") throw new IOException("lost-response"); };
      var request = new InitializeRequest("export", "watermark", []);
      Assert.Throws<IOException>(() => vault.Initialize(Fixture.A, request));
      var version = vault.CurrentVersion();
      var replay = vault.Initialize(Fixture.A, request);
      Assert.Equal(version.StorageVersion, replay.StorageVersion);
      Assert.Null(replay.MigrationKey);
      Assert.StartsWith("acm1_", vault.RecoverDelivery(Fixture.A));
      Assert.Throws<BrokerException>(() => vault.RecoverDelivery(Fixture.B));
      vault.AcknowledgeDelivery(Fixture.A);
      Assert.Throws<BrokerException>(() => vault.RecoverDelivery(Fixture.A));
      Assert.Throws<BrokerException>(() => vault.Initialize(Fixture.A, request with { OperationId = "new-export" }));
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void VaultLockRejectsDuplicateWriterAndIncompleteBackupNeverCreatesControlDatabase()
  {
    using var fixture = new Fixture();
    Assert.Equal("lock-busy", Assert.Throws<BrokerException>(() => Vault.Open(fixture.Vault.Root, fixture.Vault.KeysRoot)).Code);
    var other = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(fixture.Root, "replacement"));
    File.Copy(Path.Combine(fixture.Vault.Root, "manifest.json"), Path.Combine(other, "manifest.json"));
    Assert.Equal("control-database-missing", Assert.Throws<BrokerException>(() => Vault.Open(other, fixture.Vault.KeysRoot)).Code);
    Assert.False(File.Exists(Path.Combine(other, "control.db")));
  }
  [WindowsFact]
  public void MissingKeyEntersLockedAndWrongKeyCannotUnlockEmptyVault()
  {
    using var f = new Fixture(empty: true);
    f.Store.Dispose();
    var version = f.Vault.CurrentVersion();
    File.Delete(f.Vault.KeyPath(version.KeyId));
    using var service = new BrokerService(f.Vault, new(f.Time));
    Assert.Equal("LOCKED", service.Status().ServiceStatusValue);
    service.Connect(Admin);
    Assert.ThrowsAny<Exception>(() => Call(service, Admin, "unlock", new UnlockRequest(Crypto.B64(RandomNumberGenerator.GetBytes(32)))));
    Assert.Equal("LOCKED", service.Status().ServiceStatusValue);
    Call(service, Admin, "unlock", new UnlockRequest(Crypto.B64(f.Key)));
    Assert.Equal("READY", service.Status().ServiceStatusValue);
  }
  [WindowsFact]
  public void SharingStateExposesOnlyCurrentPreparedParticipantsAndRequiresImportOrHandoff()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    Register(service, "client-a"); Register(service, "client-b"); Register(service, "client-c");
    Prepare(service, f, Fixture.A, "ready-a");
    Prepare(service, f, Fixture.B, "ready-b");
    f.Vault.Control.Execute("INSERT INTO ready VALUES ('client-c','old-version','old-watermark')");
    var state = (SharingState)Call(service, Fixture.B, "getSharingState", new { });
    Assert.Equal(f.Vault.Manifest.VaultId, state.VaultId);
    Assert.Equal(f.Published.StorageVersion, state.StorageVersion);
    Assert.Equal(f.Initial.SourceWatermark, state.SourceWatermark);
    Assert.Equal("client-a", state.SourceClientId);
    Assert.Equal(new[] { "client-a", "client-b" }, state.PreparedClientIds);
    Assert.Equal("source", state.Ownership);
    Call(service, Admin, "revokeClient", new ClientIdRequest("client-b"));
    Assert.Equal(new[] { "client-a" }, ((SharingState)Call(service, Fixture.A, "getSharingState", new { })).PreparedClientIds);
    service.Connect(Admin);
    Call(service, Admin, "registerClient", new RegisterClient("limited", ["describe"], [], true));
    var limited = Fixture.Client("limited", "limited", ["describe"]);
    service.Connect(limited);
    Assert.Equal("forbidden", Assert.Throws<BrokerException>(() => Call(service, limited, "getSharingState", new { })).Code);
    Assert.ThrowsAny<Exception>(() => Call(service, Fixture.A, "getSharingState", new { unexpected = true }));
  }
  [WindowsFact]
  public void HandoffRequiresTwoPreparedClientsSameWatermarkAndDurableReceipts()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    Register(service, "client-a");
    Register(service, "client-b");
    service.Connect(Fixture.A);
    Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "beginUpdate", new BeginUpdate("credential-1", "1", "early")));
    Prepare(service, f, Fixture.A, "ready-a");
    var handoff = new HandoffRequest("handoff", f.Initial.SourceWatermark, ["client-a", "client-b"]);
    Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "handoff", handoff));
    var ready = Prepare(service, f, Fixture.B, "ready-b");
    Assert.Equal("prepared", ((PreparedResult)Call(service, Fixture.B, "prepareClient", ready)).State);
    Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "handoff", handoff with { SourceWatermark = "changed" }));
    service.Fault = point => { if (point == "handoff-before-commit") throw new IOException("injected"); };
    Assert.Throws<IOException>(() => Call(service, Fixture.A, "handoff", handoff));
    Assert.Equal("source", f.Vault.Setting("ownership"));
    service.Fault = null;
    var result = (HandoffResult)Call(service, Fixture.A, "handoff", handoff);
    Assert.Equal("broker", result.Ownership);
    Assert.Equal(result, Call(service, Fixture.A, "handoff", handoff));
    Assert.Equal("granted", ((BeginResult)Call(service, Fixture.A, "beginUpdate", new BeginUpdate("credential-1", "1", "now"))).Status);
  }
  [WindowsFact]
  public void ProofChallengeIsBoundToClientAndSingleUse()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    Register(service, "client-a"); Register(service, "client-b");
    var request = Prepare(service, f, Fixture.A, "ready-a");
    Assert.Throws<BrokerException>(() => Call(service, Fixture.A, "prepareClient", request with { OperationId = "replay" }));
    service.Connect(Fixture.B);
    Assert.Throws<BrokerException>(() => Call(service, Fixture.B, "prepareClient", request with { OperationId = "stolen" }));
  }
  [WindowsFact]
  public void RestrictedClientCannotStopGrantUnlockInitializeOrAcquireUnscopedRecords()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    service.Connect(Admin);
    Call(service, Admin, "registerClient", new RegisterClient("limited", ["describe", "read"], ["other-record"]));
    var actor = Fixture.Client("limited", "limited", ["describe", "read"], false, ["other-record"]);
    service.Connect(actor);
    foreach (var method in new[] { "stop", "registerClient", "unlock" })
      Assert.Equal("management-required", Assert.Throws<BrokerException>(() => Call(service, actor, method, new { })).Code);
    Assert.Throws<BrokerException>(() => Call(service, actor, "getCredential", new IdRequest("credential-1")));
    Assert.Empty(((CredentialPage)Call(service, actor, "listCredentials", new ListCredentials())).Items);
  }
  [WindowsFact]
  public void FourIndependentClientsAndSessionExpiryDoNotStopOthers()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault, new(f.Time));
    var actors = Enumerable.Range(0, 4).Select(i => Fixture.Client("client-" + i, "instance-" + i)).ToArray();
    foreach (var actor in actors) { Register(service, actor.ClientId); service.Connect(actor); }
    Call(service, actors[0], "disconnect", new { });
    Assert.Equal("READY", service.Status().ServiceStatusValue);
    f.Time.Advance(40_000);
    Call(service, actors[3], "heartbeat", new { });
    f.Time.Advance(10_000);
    service.Tick();
    Assert.Equal(1, service.Status().Sessions);
    Assert.Equal("READY", service.Status().ServiceStatusValue);
    f.Time.Advance(45_000);
    service.Tick();
    Assert.Equal("IDLE", service.Status().ServiceStatusValue);
    f.Time.Advance(60_000);
    service.Tick();
    Assert.True(service.ExitRequested);
  }
  [WindowsFact]
  public async Task WatchBroadcastsCommittedRevisionToEveryAuthorizedWaiter()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    Register(service, "client-a"); Register(service, "client-b");
    service.Connect(Fixture.A); service.Connect(Fixture.B);
    f.Vault.Set("ownership", "broker");
    var waitA = service.Watch(Fixture.A, new("1"), CancellationToken.None);
    var waitB = service.Watch(Fixture.B, new("1"), CancellationToken.None);
    var op = ((BeginResult)Call(service, Fixture.A, "beginUpdate", new BeginUpdate("credential-1", "1", "change"))).Operation!;
    Call(service, Fixture.A, "markUpdateStarted", Fixture.Lease(op));
    Call(service, Fixture.A, "commitUpdate", new CommitUpdate(Fixture.Lease(op), Fixture.Payload("C2")));
    foreach (var result in await Task.WhenAll(waitA, waitB))
      Assert.Equal("2", Assert.Single(result.Items).Revision);
  }
  [WindowsFact]
  public async Task NamedPipeMutualAuthenticationAndRpcWorkWithoutProducts()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using var service = new BrokerService(f.Vault);
    var registered = Register(service, "third-party");
    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var server = new PipeServer(service, f.Vault.Manifest.VaultId, SHA256.HashData(new byte[32]));
    var task = server.Run(stop.Token);
    try
    {
      await using var client = await BrokerClient.Connect(f.Vault.Manifest.VaultId, registered.ClientId, "independent-instance", Crypto.Unb64(registered.AccessToken));
      var result = Protocol.Decode<CredentialPage>(await client.Call("listCredentials", new ListCredentials()));
      Assert.Single(result.Items);
      var denied = await Assert.ThrowsAsync<BrokerException>(() => client.Call("stop", new { }));
      Assert.Equal("management-required", denied.Code);
      await client.Call("disconnect", new { });
      await Assert.ThrowsAnyAsync<Exception>(() => BrokerClient.Connect(f.Vault.Manifest.VaultId, registered.ClientId, "wrong-key", new byte[32]));
    }
    finally { await stop.CancelAsync(); await task; }
  }
}
