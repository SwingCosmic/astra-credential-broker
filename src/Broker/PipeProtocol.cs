using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

public sealed record Greeting(int ProtocolVersion, string VaultId, string Generation, string Nonce);
public sealed record Hello(int ProtocolVersion, string ClientId, string InstanceId, string ClientNonce, string Proof, bool Management = false);
public sealed record Welcome(string Proof);
public sealed record RpcRequest(int ProtocolVersion, string Id, string Method, JsonElement Params);
public sealed record RpcResponse(string Id, bool Ok, JsonElement? Result, string? Error);

public static class PipeProtocol
{
  public static string Name(string vaultId, BrokerPlatform? platform = null)
  {
    return "astra-credentials-v1-" + Crypto.Hash(Encoding.UTF8.GetBytes((platform ?? BrokerPlatform.Current).Identity.CurrentUserId + ":" + vaultId));
  }
  public static byte[] AuthMessage(Greeting greeting, Hello hello, string role) => CanonicalJson.Of(new object[]
  { "astra.pipe-auth.v1", role, greeting.ProtocolVersion, greeting.VaultId, greeting.Generation, greeting.Nonce,
    hello.ClientId, hello.InstanceId, hello.ClientNonce, hello.Management });
  public static string Proof(byte[] verifier, Greeting greeting, Hello hello, string role) => Crypto.B64(HMACSHA256.HashData(verifier, AuthMessage(greeting, hello, role)));
  public static async Task Write<T>(Stream stream, T value, CancellationToken cancellationToken)
  {
    var bytes = Protocol.Encode(value);
    try
    {
      Protocol.Require(bytes.Length <= Protocol.MaxMessageBytes, "message-too-large");
      var prefix = new byte[4];
      BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
      await stream.WriteAsync(prefix, cancellationToken);
      await stream.WriteAsync(bytes, cancellationToken);
      await stream.FlushAsync(cancellationToken);
    }
    finally { CryptographicOperations.ZeroMemory(bytes); }
  }
  public static async Task<T> Read<T>(Stream stream, CancellationToken cancellationToken)
  {
    var prefix = new byte[4];
    await stream.ReadExactlyAsync(prefix, cancellationToken);
    var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
    Protocol.Require(length is > 0 and <= Protocol.MaxMessageBytes, "message-too-large");
    var bytes = new byte[length];
    try
    {
      await stream.ReadExactlyAsync(bytes, cancellationToken);
      return Protocol.Decode<T>(Protocol.Parse(bytes));
    }
    finally { CryptographicOperations.ZeroMemory(bytes); }
  }
}

public sealed class PipeServer(BrokerService service, string vaultId, byte[] adminVerifier)
{
  private readonly ConcurrentDictionary<int, Task> workers = new();
  public async Task Run(CancellationToken cancellationToken)
  {
    using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
    var ticker = Tick(stop);
    var id = 0;
    try
    {
      while (!stop.IsCancellationRequested)
      {
        // Bound idle/malicious connections. The timeout of each connection is also bounded.
        if (workers.Count >= 64) { await Task.Delay(50, stop.Token); continue; }
        var pipe = await service.Platform.Transport.Accept(PipeProtocol.Name(vaultId, service.Platform), stop.Token);
        var currentId = ++id;
        var worker = Handle(pipe, stop.Token);
        workers[currentId] = worker;
        _ = worker.ContinueWith(completed => { workers.TryRemove(currentId, out _); }, TaskScheduler.Default);
      }
    }
    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    finally
    {
      await stop.CancelAsync();
      await ticker;
      await Task.WhenAll(workers.Values);
    }
  }
  private async Task Tick(CancellationTokenSource stop)
  {
    try
    {
      while (!stop.IsCancellationRequested)
      {
        service.Tick();
        if (service.ExitRequested) { await stop.CancelAsync(); break; }
        await Task.Delay(200, stop.Token);
      }
    }
    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    catch
    {
      await stop.CancelAsync();
      throw;
    }
  }
  private async Task Handle(Stream pipe, CancellationToken stop)
  {
    using (pipe)
    using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop))
    {
      try
      {
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var greeting = new Greeting(1, vaultId, service.Generation, Crypto.B64(RandomNumberGenerator.GetBytes(32)));
        await PipeProtocol.Write(pipe, greeting, timeout.Token);
        var hello = await PipeProtocol.Read<Hello>(pipe, timeout.Token);
        Protocol.Require(hello.ProtocolVersion == Protocol.Version, "protocol-incompatible");
        Protocol.Id(hello.ClientId);
        Protocol.Id(hello.InstanceId);
        Protocol.Require(Crypto.Unb64(hello.ClientNonce, 32).Length == 32, "invalid-challenge");
        var grant = hello.Management ? null : service.Grant(hello.ClientId);
        Protocol.Require(hello.Management || grant is not null, "unauthorized");
        var verifier = hello.Management ? adminVerifier.ToArray() : Crypto.Unb64(grant!.TokenHash, 32);
        Actor actor;
        try
        {
          Protocol.Require(Crypto.Equal(PipeProtocol.Proof(verifier, greeting, hello, "client"), hello.Proof), "unauthorized");
          await PipeProtocol.Write(pipe, new Welcome(PipeProtocol.Proof(verifier, greeting, hello, "server")), timeout.Token);
          actor = hello.Management ? new(hello.ClientId, hello.InstanceId, [], [], true, true) :
            new(hello.ClientId, hello.InstanceId, grant!.Scopes, grant.CredentialIds, grant.AllCredentials);
        }
        finally { CryptographicOperations.ZeroMemory(verifier); }
        service.Connect(actor);
        while (!stop.IsCancellationRequested)
        {
          timeout.CancelAfter(TimeSpan.FromSeconds(50));
          var request = await PipeProtocol.Read<RpcRequest>(pipe, timeout.Token);
          RpcResponse response;
          try
          {
            Protocol.Require(request.ProtocolVersion == Protocol.Version, "protocol-incompatible");
            Protocol.Id(request.Id);
            var result = request.Method == "watchEvents" ? await service.Watch(actor,
              Protocol.Decode<WatchEventsRequest>(request.Params), timeout.Token) : service.Dispatch(actor, request.Method, request.Params);
            response = new(request.Id, true, JsonSerializer.SerializeToElement(result, Protocol.Json), null);
          }
          catch (Exception ex) { response = new(request.Id, false, null, ErrorCode(ex)); }
          await PipeProtocol.Write(pipe, response, timeout.Token);
          if (request.Method == "disconnect") break;
        }
      }
      catch (Exception ex) when (ex is IOException or OperationCanceledException or BrokerException or JsonException or CryptographicException or FormatException) { }
    }
  }
  public static string ErrorCode(Exception ex) => ex switch
  {
    BrokerException broker => broker.Code,
    PlatformFeatureUnavailableException => PlatformFeatureUnavailableException.ErrorCode,
    PlatformNotSupportedException => "unsupported-platform",
    ComponentCommandException => "component-command-failed",
    JsonException or FormatException or ArgumentException or NullReferenceException => "invalid-request",
    CryptographicException => "authentication-failed",
    UnauthorizedAccessException => "access-denied",
    IOException => "io-failure",
    _ => "internal-error",
  };
}

public sealed class BrokerClient : IAsyncDisposable
{
  private readonly Stream pipe;
  private readonly SemaphoreSlim serial = new(1, 1);
  private BrokerClient(Stream pipe) { this.pipe = pipe; }
  public static async Task<BrokerClient> Connect(string vaultId, string clientId, string instanceId, byte[] accessToken,
    bool management = false, CancellationToken cancellationToken = default, BrokerPlatform? platform = null)
  {
    platform ??= BrokerPlatform.Current;
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
    timeout.CancelAfter(TimeSpan.FromSeconds(5));
    var pipe = await platform.Transport.Connect(PipeProtocol.Name(vaultId, platform), timeout.Token);
    var verifier = SHA256.HashData(accessToken);
    try
    {
      var greeting = await PipeProtocol.Read<Greeting>(pipe, timeout.Token);
      Protocol.Require(greeting.ProtocolVersion == 1 && greeting.VaultId == vaultId, "server-identity-mismatch");
      var hello = new Hello(1, clientId, instanceId, Crypto.B64(RandomNumberGenerator.GetBytes(32)), "", management);
      hello = hello with { Proof = PipeProtocol.Proof(verifier, greeting, hello, "client") };
      await PipeProtocol.Write(pipe, hello, timeout.Token);
      var welcome = await PipeProtocol.Read<Welcome>(pipe, timeout.Token);
      Protocol.Require(Crypto.Equal(welcome.Proof, PipeProtocol.Proof(verifier, greeting, hello, "server")), "server-identity-mismatch");
      return new(pipe);
    }
    catch { pipe.Dispose(); throw; }
    finally { CryptographicOperations.ZeroMemory(verifier); }
  }
  public async Task<JsonElement> Call(string method, object parameters, CancellationToken cancellationToken = default)
  {
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
    timeout.CancelAfter(TimeSpan.FromSeconds(10));
    await serial.WaitAsync(timeout.Token);
    try
    {
      var request = new RpcRequest(1, Crypto.RandomId(), method, JsonSerializer.SerializeToElement(parameters, Protocol.Json));
      await PipeProtocol.Write(pipe, request, timeout.Token);
      var response = await PipeProtocol.Read<RpcResponse>(pipe, timeout.Token);
      Protocol.Require(response.Id == request.Id, "response-mismatch");
      if (!response.Ok) throw new BrokerException(response.Error ?? "internal-error");
      return response.Result ?? JsonSerializer.SerializeToElement(new { }, Protocol.Json);
    }
    finally { serial.Release(); }
  }
  public ValueTask DisposeAsync() { pipe.Dispose(); serial.Dispose(); return ValueTask.CompletedTask; }
}
