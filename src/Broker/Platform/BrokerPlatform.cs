using System.Runtime.InteropServices;

namespace Astra.Credentials;

// Composition is immutable and per vault/manager, so clients cannot change a process-wide
// provider while another vault is active. Pure protocol/crypto APIs never resolve this factory.
public sealed record BrokerPlatform(IUserIdentity Identity, IPrivateFileSystem Files,
  ISecretProtector Secrets, ILocalTransport Transport, IComponentHost Components)
{
  private static readonly Lazy<BrokerPlatform> current = new(SelectCurrent);
  public static BrokerPlatform Current => current.Value;

  private static BrokerPlatform SelectCurrent()
  {
    if (OperatingSystem.IsWindows())
      return new(new WindowsUserIdentity(), new WindowsPrivateFileSystem(), new WindowsSecretProtector(),
        new NamedPipeTransport(), new ComponentHost(ComponentHostProfile.ForRuntime(RuntimeInformation.RuntimeIdentifier)));
    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
      return Unavailable(OperatingSystem.IsLinux() ? "linux" : "macos") with
      {
        Transport = new NamedPipeTransport(),
        Components = new ComponentHost(ComponentHostProfile.ForRuntime(RuntimeInformation.RuntimeIdentifier))
      };
    return Unavailable("unknown");
  }

  public static BrokerPlatform Unavailable(string platform)
  {
    var unavailable = new UnavailablePlatform(platform);
    return new(unavailable, unavailable, unavailable, unavailable, unavailable);
  }
}
