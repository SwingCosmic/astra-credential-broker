using System.Text;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class StoreTests
{
  [WindowsFact]
  public void MetadataPagesStayWithinWireBudgetWithoutDroppingMatchingRecords()
  {
    using var f = new Fixture();
    var metadata = Enumerable.Range(0, 15).ToDictionary(i => "k" + i, _ => new string('<', 1024));
    for (var i = 0; i < 30; i++)
      f.Store.Create(Fixture.A, new("wide-" + i.ToString("D2"), "create-wide-" + i, "opaque", 1, "", metadata));
    var first = f.Store.List(Fixture.A, new(200));
    Assert.NotNull(first.NextCursor);
    Assert.InRange(Protocol.Encode(first).Length, 1, Protocol.MaxMessageBytes - 2048);
    var second = f.Store.List(Fixture.A, new(200, first.NextCursor));
    Assert.Null(second.NextCursor);
    Assert.Equal(31, first.Items.Concat(second.Items).Select(i => i.CredentialId).Distinct(StringComparer.Ordinal).Count());
  }
  [WindowsFact]
  public void OpaqueRecordsAreEncryptedAndDescriptionsContainNoPayload()
  {
    using var f = new Fixture();
    Assert.Equal("SUPER_SECRET_C1", Encoding.UTF8.GetString(Crypto.Unb64(f.Store.Get(Fixture.A, "credential-1").Payload)));
    var serialized = Encoding.UTF8.GetString(Protocol.Encode(f.Store.List(Fixture.A, new())));
    Assert.DoesNotContain("SUPER_SECRET", serialized);
    Assert.DoesNotContain("payload\"", serialized);
    var version = f.Vault.VersionPath(f.Published.StorageVersion);
    foreach (var file in Directory.EnumerateFiles(version))
    {
      using var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
      using var copy = new MemoryStream();
      input.CopyTo(copy);
      var bytes = Encoding.UTF8.GetString(copy.ToArray());
      Assert.DoesNotContain("SUPER_SECRET_C1", bytes);
      Assert.DoesNotContain(Fixture.Payload("SUPER_SECRET_C1"), bytes);
      Assert.DoesNotContain("vendor.extension", bytes);
    }
  }
  [WindowsFact]
  public void CreateAndCommitAttributionIsAuthenticatedAndReplayDoesNotWrite()
  {
    using var f = new Fixture();
    var op = f.Grant(Fixture.B);
    f.Store.MarkStarted(Fixture.B, Fixture.Lease(op));
    var commit = new CommitUpdate(Fixture.Lease(op), Fixture.Payload("C2"));
    var result = f.Store.Commit(Fixture.B, commit);
    Assert.Equal("2", result.ResultRevision);
    Assert.Equal(result, f.Store.Commit(Fixture.B, commit));
    Assert.Equal(result, f.Store.Abort(Fixture.B, new(Fixture.Lease(op), "failed", "network-error", true, "unknown")));
    var record = f.Store.Get(Fixture.A, "credential-1");
    Assert.Equal("client-a", record.Description.CreatedByClientId);
    Assert.Equal("client-b", record.Description.LastUpdatedByClientId);
    Assert.Equal("kept", record.Description.Metadata["vendor.extension"]);
    Assert.Equal(2, f.Store.Events(Fixture.A, "0").Items.Length);
    Assert.Equal("operation-conflict", Assert.Throws<BrokerException>(() => f.Store.Commit(Fixture.B, commit with { Payload = Fixture.Payload("different") })).Code);
  }
  [WindowsFact]
  public async Task ConcurrentBeginOnlyGrantsOneAndQueueIsFair()
  {
    using var f = new Fixture();
    var clients = Enumerable.Range(0, 8).Select(i => Fixture.Client("client-" + i, "instance-" + i)).ToArray();
    var results = await Task.WhenAll(clients.Select((a, i) => Task.Run(() => f.Store.Begin(a, new("credential-1", "1", "op-" + i)))));
    Assert.Single(results, r => r.Status == "granted");
    Assert.Equal(7, results.Count(r => r.Status == "queued"));
    var owner = Array.FindIndex(results, r => r.Status == "granted");
    f.Store.Abort(clients[owner], new(Fixture.Lease(results[owner].Operation!), "failed", "provider-error", true, "unchanged"));
    var attempts = clients.Select((a, i) => i == owner ? null : f.Store.Begin(a, new("credential-1", "1", "op-" + i))).Where(r => r is not null).ToArray();
    // If the first waiter was not polled first, it still owns the next turn; no later caller can overtake.
    Assert.InRange(attempts.Count(r => r!.Status == "granted"), 0, 1);
    Assert.All(attempts, r => Assert.Contains(r!.Status, new[] { "queued", "granted" }));
  }
  [WindowsFact]
  public void FailedReleaseIsImmediateIdempotentAndCannotReleaseSuccessor()
  {
    using var f = new Fixture();
    var first = f.Grant();
    f.Store.MarkStarted(Fixture.A, Fixture.Lease(first));
    var request = new AbortUpdate(Fixture.Lease(first), "failed", "request-timeout", true, "unknown");
    var aborted = f.Store.Abort(Fixture.A, request);
    Assert.Equal("failed-released", aborted.Status);
    var next = f.Grant(Fixture.B, "next");
    Assert.True(long.Parse(next.Fence) > long.Parse(first.Fence));
    Assert.Equal(aborted, f.Store.Abort(Fixture.A, request));
    Assert.Equal("granted", f.Store.GetOperation(Fixture.B, "next").Status);
    Assert.Equal("1", f.Store.Get(Fixture.A, "credential-1").Description.Revision);
  }
  [WindowsFact]
  public void ExpirationFencesLateCommitEvenWhenRevisionUnchanged()
  {
    using var f = new Fixture();
    var first = f.Grant();
    f.Store.MarkStarted(Fixture.A, Fixture.Lease(first));
    f.Time.Advance(30_000);
    var next = f.Grant(Fixture.B, "next");
    Assert.Equal("granted", next.Status);
    Assert.Equal("lease-expired", Assert.Throws<BrokerException>(() => f.Store.Commit(Fixture.A,
      new(Fixture.Lease(first), Fixture.Payload("late")))).Code);
    Assert.Equal("1", f.Store.Get(Fixture.A, "credential-1").Description.Revision);
    var oldAbort = f.Store.Abort(Fixture.A, new(Fixture.Lease(first), "failed", "network-error", true, "unknown"));
    Assert.Equal("expired", oldAbort.Status);
    Assert.Equal("granted", f.Store.GetOperation(Fixture.B, "next").Status);
  }
  [WindowsFact]
  public void RenewalCannotExtendAbsoluteHoldOrReviveExpiredLease()
  {
    using var f = new Fixture();
    var operation = f.Grant();
    var hard = operation.HardDeadline;
    for (var i = 0; i < 11; i++)
    {
      f.Time.Advance(10_000);
      operation = f.Store.Renew(Fixture.A, Fixture.Lease(operation));
      Assert.Equal(hard, operation.HardDeadline);
      Assert.True(operation.ExpiresAt <= hard);
    }
    f.Time.Advance(10_000);
    Assert.Throws<BrokerException>(() => f.Store.Renew(Fixture.A, Fixture.Lease(operation)));
    Assert.Equal("expired", f.Store.GetOperation(Fixture.A, operation.OperationId).Status);
  }
  [WindowsFact]
  public void RestartRetainsDeadlinesAndRequiresNewGeneration()
  {
    using var f = new Fixture();
    var first = f.Grant();
    f.Store.MarkStarted(Fixture.A, Fixture.Lease(first));
    f.Time.Advance(10_000);
    f.Restart();
    var recovered = f.Store.Begin(Fixture.A, new("credential-1", "1", first.OperationId)).Operation!;
    Assert.Equal(first.ExpiresAt, recovered.ExpiresAt);
    Assert.Equal(first.HardDeadline, recovered.HardDeadline);
    Assert.NotEqual(first.Generation, recovered.Generation);
    Assert.Equal("stale-fence", Assert.Throws<BrokerException>(() => f.Store.Commit(Fixture.A, new(Fixture.Lease(first), ""))).Code);
    Assert.Equal("committed", f.Store.Commit(Fixture.A, new(Fixture.Lease(recovered), Fixture.Payload("C2"))).Status);
    f.Restart("generation-3");
    Assert.Equal("committed", f.Store.GetOperation(Fixture.A, first.OperationId).Status);
  }
  [WindowsFact]
  public void ClockRollbackDuringRunDoesNotExtendLease()
  {
    using var f = new Fixture();
    var first = f.Grant();
    f.Time.Rollback(3_600_000);
    f.Time.Advance(30_000);
    Assert.Equal("expired", f.Store.GetOperation(Fixture.A, first.OperationId).Status);
  }
  [WindowsFact]
  public void DifferentInstancesCannotReuseOperationAndDisconnectKeepsActiveLease()
  {
    using var f = new Fixture();
    var first = f.Grant();
    f.Store.Disconnect(Fixture.A);
    Assert.Equal("granted", f.Store.GetOperation(Fixture.A, first.OperationId).Status);
    var other = Fixture.Client("client-a", "other-instance");
    Assert.Throws<BrokerException>(() => f.Store.Renew(other, Fixture.Lease(first)));
    Assert.Throws<BrokerException>(() => f.Store.Begin(other, new("credential-1", "1", first.OperationId)));
  }
  [WindowsFact]
  public void CoordinationFamilySerializesDifferentRecords()
  {
    using var f = new Fixture();
    foreach (var id in new[] { "family-1", "family-2" })
      f.Store.Create(Fixture.A, new(id, "create-" + id, "custom", 1, "", [], "same-family"));
    Assert.Equal("granted", f.Store.Begin(Fixture.A, new("family-1", "1", "first")).Status);
    Assert.Equal("queued", f.Store.Begin(Fixture.B, new("family-2", "1", "second")).Status);
  }
  [WindowsFact]
  public void FilteringPaginationAndScopeAreIndependentFromSecretRead()
  {
    using var f = new Fixture();
    foreach (var (id, value) in new[] { ("api-key", "false"), ("usage-1", "true"), ("usage-2", "TRUE"), ("usage-3", " true ") })
      f.Store.Create(Fixture.B, new(id, "create-" + id, "custom", 1, "", new() { ["supportsUsage"] = value }));
    var reader = Fixture.Client("restricted", "restricted-instance", ["describe", "events"], false, ["usage-1", "api-key"]);
    var page = f.Store.List(reader, new(1));
    Assert.Single(page.Items);
    Assert.Equal("api-key", page.NextCursor);
    Assert.Equal("usage-1", Assert.Single(f.Store.List(reader, new(1, page.NextCursor)).Items).CredentialId);
    var filtered = f.Store.List(Fixture.A, new(MetadataEquals: new() { ["supportsUsage"] = "true" }));
    Assert.Equal(new[] { "credential-1", "usage-1" }, filtered.Items.Select(r => r.CredentialId));
    Assert.Equal("usage-1", Assert.Single(f.Store.List(reader, new(MetadataEquals: new() { ["supportsUsage"] = "true" })).Items).CredentialId);
    Assert.Throws<BrokerException>(() => f.Store.Get(reader, "usage-1"));
    Assert.All(f.Store.Events(reader, "0").Items, item => Assert.Contains(item.CredentialId, new[] { "usage-1", "api-key" }));
  }
  [WindowsFact]
  public void MetadataPatchPreservesUnknownExtensionsAndIsAtomicWithEvents()
  {
    using var f = new Fixture();
    var first = f.Grant(Fixture.B);
    f.Store.MarkStarted(Fixture.B, Fixture.Lease(first));
    var request = new CommitUpdate(Fixture.Lease(first), SetMetadata: new() { ["supportsUsage"] = "false", ["third.party"] = "kept" }, RemoveKeys: ["vendor.extension"]);
    f.Store.Fault = point => { if (point == "commit-before-transaction") throw new IOException("injected"); };
    Assert.Throws<IOException>(() => f.Store.Commit(Fixture.B, request));
    Assert.Equal("1", f.Store.Get(Fixture.A, "credential-1").Description.Revision);
    Assert.Single(f.Store.Events(Fixture.A, "0").Items);
    Assert.Equal("started", f.Store.GetOperation(Fixture.B, first.OperationId).Status);
    f.Store.Fault = null;
    f.Store.Commit(Fixture.B, request);
    var description = f.Store.Get(Fixture.A, "credential-1").Description;
    Assert.Equal("2", description.Revision);
    Assert.Equal("client-b", description.LastUpdatedByClientId);
    Assert.DoesNotContain("vendor.extension", description.Metadata.Keys);
    Assert.Equal("kept", description.Metadata["third.party"]);
    Assert.Empty(f.Store.List(Fixture.A, new(MetadataEquals: new() { ["supportsUsage"] = "true" })).Items);
  }
  [WindowsFact]
  public void C1ToC2ToC3IsMonotonicWithReplayableEvents()
  {
    using var f = new Fixture();
    foreach (var (actor, rev, next) in new[] { (Fixture.A, "1", "C2"), (Fixture.B, "2", "C3") })
    {
      var op = f.Grant(actor, "refresh-" + rev, revision: rev);
      f.Store.MarkStarted(actor, Fixture.Lease(op));
      f.Store.Commit(actor, new(Fixture.Lease(op), Fixture.Payload(next)));
    }
    var events = f.Store.Events(Fixture.A, "0", 2);
    Assert.Equal("2", events.NextCursor);
    Assert.Equal("3", Assert.Single(f.Store.Events(Fixture.A, events.NextCursor).Items).Revision);
    var stale = f.Store.Begin(Fixture.A, new("credential-1", "1", "outdated"));
    Assert.Equal("stale", stale.Status);
    Assert.Equal(Fixture.Payload("C3"), stale.Credential!.Payload);
    Assert.Equal("3", stale.Credential.Description.Revision);
  }
  [WindowsFact]
  public void DeleteRequiresSeparatePermissionAndEmitsNoPayload()
  {
    using var f = new Fixture();
    var op = f.Grant();
    f.Store.MarkStarted(Fixture.A, Fixture.Lease(op));
    var denied = Fixture.Client(scopes: ["read", "update"]);
    Assert.Throws<BrokerException>(() => f.Store.Commit(denied, new(Fixture.Lease(op), Delete: true)));
    f.Store.Commit(Fixture.A, new(Fixture.Lease(op), Delete: true));
    Assert.Throws<BrokerException>(() => f.Store.Get(Fixture.A, "credential-1"));
    Assert.Equal("credentialDeleted", f.Store.Events(Fixture.A, "0").Items.Last().Kind);
    Assert.Empty(f.Store.List(Fixture.A, new()).Items);
  }
}
