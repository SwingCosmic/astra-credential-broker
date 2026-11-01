using System.Runtime.Versioning;
using System.Security.Principal;

namespace Astra.Credentials;

[SupportedOSPlatform("windows")]
internal sealed class WindowsUserIdentity : IUserIdentity
{
  public string CurrentUserId => CurrentSid.Value;
  internal static SecurityIdentifier CurrentSid
  {
    get
    {
      using var identity = WindowsIdentity.GetCurrent();
      return identity.User ?? throw new BrokerException("no-user-identity");
    }
  }
}
