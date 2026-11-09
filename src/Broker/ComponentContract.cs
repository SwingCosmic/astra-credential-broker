using System.Reflection;
using System.Text.RegularExpressions;

namespace Astra.Credentials;

/// <summary>Release identity comes only from Directory.Build.props; API revisions are additive contracts.</summary>
public static partial class ComponentContract
{
  public const string Name = "astra-credential-broker";
  public static readonly string Version = typeof(ComponentContract).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
  public const decimal ApiRevision = 3m;
  // Keep the lifecycle-only contract stable across later application API/release upgrades.
  public const decimal LifecycleApiRevision = 2m;
  public const int StorageVersion = 1;

  [GeneratedRegex("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$", RegexOptions.CultureInvariant)]
  private static partial Regex SemVerPattern();
  public static void RequireVersion(string version) => Protocol.Require(SemVerPattern().IsMatch(version), "invalid-component-version");

  public static void RequireSupported(string version, decimal apiRevision)
  {
    RequireVersion(version);
    Protocol.Require(apiRevision >= ApiRevision, "api-incompatible");
  }

  public static void RequireLifecycleCompatible(string version, decimal apiRevision)
  {
    RequireVersion(version);
    Protocol.Require(apiRevision >= LifecycleApiRevision, "api-incompatible");
  }
}
