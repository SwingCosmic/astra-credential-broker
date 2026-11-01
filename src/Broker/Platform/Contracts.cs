namespace Astra.Credentials;

public interface IUserIdentity
{
  string CurrentUserId { get; }
}

public interface IPrivateFileSystem
{
  string CreatePrivateDirectory(string path);
  void ValidatePrivateDirectory(string path);
  void ValidateTree(string root);
  string DirectoryIdentity(string path);
}

public interface ISecretProtector
{
  string FileExtension { get; }
  byte[] Protect(byte[] value, string purpose);
  byte[] Unprotect(byte[] value, string purpose);
}

// Each returned stream is owned by the caller. Implementations authenticate the local OS
// user boundary; protocol-level mutual authentication remains in PipeServer/BrokerClient.
public interface ILocalTransport
{
  Task<Stream> Accept(string address, CancellationToken cancellationToken);
  Task<Stream> Connect(string address, CancellationToken cancellationToken);
}

public sealed record ProcessIdentity(int Pid, long StartTime);

public interface IComponentHost
{
  string RuntimeIdentifier { get; }
  string DefaultHome { get; }
  string ExecutableName { get; }
  string[] RequiredFiles { get; }
  StringComparison PathComparison { get; }
  StringComparer PathComparer { get; }
  bool IsSafeFileName(string name);
  void PrepareCopiedFile(string source, string target);
  ProcessIdentity CurrentProcess { get; }
  void LaunchDetached(string executable, string[] arguments, string workingDirectory);
  Task<int> RunWorker(string executable, string[] arguments);
  Task<string> RunTool(string executable, string[] arguments, bool allowFailure = false);
  bool IsProcessAlive(RuntimeEndpoint endpoint);
  Task TerminateVerified(RuntimeEndpoint endpoint, string expectedExecutable);
}

public sealed class PlatformFeatureUnavailableException(string feature, string platform)
  : PlatformNotSupportedException($"Platform feature '{feature}' is not implemented for '{platform}'.")
{
  public const string ErrorCode = "platform-feature-unavailable";
  public string Feature { get; } = feature;
  public string Platform { get; } = platform;
}
