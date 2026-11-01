namespace Astra.Credentials;

internal sealed class UnavailablePlatform(string platform) : IUserIdentity, IPrivateFileSystem,
  ISecretProtector, ILocalTransport, IComponentHost
{
  private PlatformFeatureUnavailableException Missing(string feature) => new(feature, platform);
  public string CurrentUserId => throw Missing("user-identity");
  public string CreatePrivateDirectory(string path) => throw Missing("private-file-system");
  public void ValidatePrivateDirectory(string path) => throw Missing("private-file-system");
  public void ValidateTree(string root) => throw Missing("private-file-system");
  public string DirectoryIdentity(string path) => throw Missing("private-file-system");
  public string FileExtension => throw Missing("secret-protection");
  public byte[] Protect(byte[] value, string purpose) => throw Missing("secret-protection");
  public byte[] Unprotect(byte[] value, string purpose) => throw Missing("secret-protection");
  public Task<Stream> Accept(string address, CancellationToken cancellationToken) => throw Missing("local-transport");
  public Task<Stream> Connect(string address, CancellationToken cancellationToken) => throw Missing("local-transport");
  public string RuntimeIdentifier => throw Missing("component-host");
  public string DefaultHome => throw Missing("component-host");
  public string ExecutableName => throw Missing("component-host");
  public string[] RequiredFiles => throw Missing("component-host");
  public StringComparison PathComparison => throw Missing("component-host");
  public StringComparer PathComparer => throw Missing("component-host");
  public bool IsSafeFileName(string name) => throw Missing("component-host");
  public void PrepareCopiedFile(string source, string target) => throw Missing("component-host");
  public ProcessIdentity CurrentProcess => throw Missing("component-host");
  public void LaunchDetached(string executable, string[] arguments, string workingDirectory) => throw Missing("component-host");
  public Task<int> RunWorker(string executable, string[] arguments) => throw Missing("component-host");
  public Task<string> RunTool(string executable, string[] arguments, bool allowFailure = false) => throw Missing("component-host");
  public bool IsProcessAlive(RuntimeEndpoint endpoint) => throw Missing("component-host");
  public Task TerminateVerified(RuntimeEndpoint endpoint, string expectedExecutable) => throw Missing("component-host");
}
