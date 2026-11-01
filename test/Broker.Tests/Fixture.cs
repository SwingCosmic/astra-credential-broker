using System.Security.Cryptography;
using System.Text;
using Astra.Credentials;

namespace Broker.Tests;

internal sealed class ManualTime : TimeProvider
{
  private long elapsed;
  private DateTimeOffset utc = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
  public override DateTimeOffset GetUtcNow() => utc;
  public override long GetTimestamp() => elapsed;
  public override long TimestampFrequency => 1000;
  public void Advance(long milliseconds) { elapsed += milliseconds; utc = utc.AddMilliseconds(milliseconds); }
  public void Rollback(long milliseconds) => utc = utc.AddMilliseconds(-milliseconds);
}

internal sealed class Fixture : IDisposable
{
  public string Root { get; } = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(Path.GetTempPath(), "AstraBrokerTests-" + Crypto.RandomId()));
  public Vault Vault { get; }
  public CredentialStore Store { get; private set; }
  public ManualTime Time { get; } = new();
  public byte[] Key { get; }
  public InitializeRequest Initial { get; }
  public InitializeResult Published { get; }
  public static Actor Client(string id = "client-a", string instance = "instance-a", string[]? scopes = null,
    bool all = true, string[]? ids = null) => new(id, instance, scopes ?? ["read", "describe", "update", "create", "events", "initialize", "import", "handoff", "delete"], ids ?? [], all);
  public static readonly Actor A = Client();
  public static readonly Actor B = Client("client-b", "instance-b");
  public static string Payload(string value) => Crypto.B64(Encoding.UTF8.GetBytes(value));
  public static LeaseRef Lease(Operation operation) => new(operation.OperationId, operation.LeaseId!, operation.Fence, operation.Generation, operation.BaseRevision);
  public Fixture(bool empty = false)
  {
    Vault = Vault.Open(Path.Combine(Root, "data"), Path.Combine(Root, "keys"), true);
    Initial = new("initial-export", "source-revision-42", empty ? [] : [new("credential-1", "application/custom", 1, Payload("SUPER_SECRET_C1"),
      new() { ["supportsUsage"] = "true", ["vendor.extension"] = "kept" })]);
    Published = Vault.Initialize(A, Initial);
    Key = Vault.LoadKey(Vault.CurrentVersion());
    Store = new(Vault, Vault.CurrentVersion(), Key, "generation-1", new(Time));
  }
  public void Restart(string generation = "generation-2")
  {
    Store.Dispose();
    Store = new(Vault, Vault.CurrentVersion(), Key, generation, new(Time));
  }
  public Operation Grant(Actor? actor = null, string operation = "refresh-1", string id = "credential-1", string revision = "1") =>
    Store.Begin(actor ?? A, new(id, revision, operation)).Operation!;
  public void Dispose()
  {
    Store.Dispose();
    Vault.Dispose();
    CryptographicOperations.ZeroMemory(Key);
    if (Directory.Exists(Root)) Directory.Delete(Root, true);
  }
}
