namespace Astra.Credentials;

internal enum ComponentSystem { Windows, Linux, MacOS }

// Only platform policy lives here. The lifecycle, probe and process identity code is shared.
internal sealed record ComponentHostProfile(ComponentSystem System, string RuntimeIdentifier)
{
  internal static ComponentHostProfile ForRuntime(string rid) => rid switch
  {
    var value when value.StartsWith("win-", StringComparison.Ordinal) => new(ComponentSystem.Windows, rid),
    var value when value.StartsWith("linux-", StringComparison.Ordinal) => new(ComponentSystem.Linux, rid),
    var value when value.StartsWith("osx-", StringComparison.Ordinal) => new(ComponentSystem.MacOS, rid),
    _ => throw new PlatformFeatureUnavailableException("component-host", rid),
  };

  public string ExecutableName => System == ComponentSystem.Windows ? "brokerctl.exe" : "brokerctl";
  public StringComparison PathComparison => System == ComponentSystem.Windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
  public StringComparer PathComparer => System == ComponentSystem.Windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
  public string[] RequiredFiles => [ExecutableName, "brokerctl.dll", "brokerctl.deps.json", "brokerctl.runtimeconfig.json",
    NativeLibrary("hostfxr"), NativeLibrary("hostpolicy"), NativeLibrary("coreclr"), "System.Private.CoreLib.dll", NativeLibrary("e_sqlite3")];
  private string NativeLibrary(string name) => System switch
  {
    ComponentSystem.Windows => name + ".dll",
    ComponentSystem.Linux => "lib" + name + ".so",
    _ => "lib" + name + ".dylib",
  };

  public bool IsSafeFileName(string name)
  {
    if (name.Length == 0 || name is "." or ".." || name.IndexOfAny(['\0', '/', '\\']) >= 0) return false;
    return System != ComponentSystem.Windows ||
      (!name.Any(character => character < 32 || "<>:\"|?*".Contains(character)) && !name.EndsWith('.') && !name.EndsWith(' '));
  }

  internal string ResolveDefaultHome(string userHome, string localAppData, string? xdgDataHome)
  {
    if (System == ComponentSystem.Windows)
    {
      Protocol.Require(Path.IsPathFullyQualified(localAppData), "user-home-unavailable");
      return Path.Combine(localAppData, "AstraCredentialBroker", "v1");
    }
    string data;
    if (System == ComponentSystem.Linux && !string.IsNullOrEmpty(xdgDataHome) && Path.IsPathFullyQualified(xdgDataHome)) data = xdgDataHome;
    else
    {
      Protocol.Require(Path.IsPathFullyQualified(userHome), "user-home-unavailable");
      data = System == ComponentSystem.MacOS ? Path.Combine(userHome, "Library", "Application Support") : Path.Combine(userHome, ".local", "share");
    }
    return Path.Combine(data, "AstraCredentialBroker", "v1");
  }
}
