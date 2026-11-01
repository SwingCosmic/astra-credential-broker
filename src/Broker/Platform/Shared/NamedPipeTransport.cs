using System.IO.Pipes;

namespace Astra.Credentials;

// The byte-stream and CurrentUserOnly APIs used here are implemented by .NET on
// Windows and Unix. Do not add Windows ACL/access-rights overloads to this adapter.
internal sealed class NamedPipeTransport : ILocalTransport
{
  public async Task<Stream> Accept(string address, CancellationToken cancellationToken)
  {
    var pipe = new NamedPipeServerStream(address, PipeDirection.InOut, 254,
      PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    try { await pipe.WaitForConnectionAsync(cancellationToken); return pipe; }
    catch { pipe.Dispose(); throw; }
  }

  public async Task<Stream> Connect(string address, CancellationToken cancellationToken)
  {
    var pipe = new NamedPipeClientStream(".", address, PipeDirection.InOut,
      PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    try { await pipe.ConnectAsync(cancellationToken); return pipe; }
    catch { pipe.Dispose(); throw; }
  }
}
