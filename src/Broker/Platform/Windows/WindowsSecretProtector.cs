using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Astra.Credentials;

[SupportedOSPlatform("windows")]
internal sealed class WindowsSecretProtector : ISecretProtector
{
  public string FileExtension => ".dpapi";
  public byte[] Protect(byte[] value, string purpose) => ProtectedData.Protect(value,
    Encoding.UTF8.GetBytes("astra-credential-broker.v1:" + purpose), DataProtectionScope.CurrentUser);
  public byte[] Unprotect(byte[] value, string purpose) => ProtectedData.Unprotect(value,
    Encoding.UTF8.GetBytes("astra-credential-broker.v1:" + purpose), DataProtectionScope.CurrentUser);
}
