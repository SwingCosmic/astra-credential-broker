using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class ComponentHostTests
{
  [Theory]
  [InlineData("win-x64", "brokerctl.exe", "hostfxr.dll", "e_sqlite3.dll")]
  [InlineData("win-arm64", "brokerctl.exe", "hostfxr.dll", "e_sqlite3.dll")]
  [InlineData("linux-x64", "brokerctl", "libhostfxr.so", "libe_sqlite3.so")]
  [InlineData("linux-arm64", "brokerctl", "libhostfxr.so", "libe_sqlite3.so")]
  [InlineData("linux-musl-x64", "brokerctl", "libhostfxr.so", "libe_sqlite3.so")]
  [InlineData("osx-x64", "brokerctl", "libhostfxr.dylib", "libe_sqlite3.dylib")]
  [InlineData("osx-arm64", "brokerctl", "libhostfxr.dylib", "libe_sqlite3.dylib")]
  public void PublishLayoutMatchesRuntimeAndRetainsMusl(string rid, string executable, string runtimeLibrary, string sqliteLibrary)
  {
    var host = new ComponentHost(ComponentHostProfile.ForRuntime(rid));
    Assert.Equal(rid, host.RuntimeIdentifier);
    Assert.Equal(executable, host.ExecutableName);
    Assert.Contains(executable, host.RequiredFiles);
    Assert.Contains(runtimeLibrary, host.RequiredFiles);
    Assert.Contains(sqliteLibrary, host.RequiredFiles);
    Assert.Contains("brokerctl.dll", host.RequiredFiles);
    Assert.Equal(9, host.RequiredFiles.Distinct(StringComparer.Ordinal).Count());
  }

  [Theory]
  [InlineData("linux-x64")]
  [InlineData("osx-arm64")]
  public void UnixDetachedLaunchKeepsCallerArgumentsOutOfShellSource(string rid)
  {
    var host = new ComponentHost(ComponentHostProfile.ForRuntime(rid));
    var executable = "/a path/brokerctl;$(touch unexpected)";
    string[] arguments = ["supervise", "--vault", "a'b\"c;$HOME", "", "界"];
    var start = host.DetachedStartInfo(executable, arguments, "/working directory");
    Assert.False(start.UseShellExecute);
    Assert.True(start.RedirectStandardInput && start.RedirectStandardOutput && start.RedirectStandardError);
    Assert.Equal("/usr/bin/nohup", start.FileName);
    Assert.Equal("/working directory", start.WorkingDirectory);
    Assert.Equal(["/bin/sh", "-c", "exec </dev/null >/dev/null 2>&1; exec \"$@\"", "astra-credential-broker", executable, .. arguments], start.ArgumentList);
    Assert.DoesNotContain(executable, start.ArgumentList[2], StringComparison.Ordinal);
  }

  [Fact]
  public void WindowsDetachedLaunchRetainsShellAndHiddenWindow()
  {
    var host = new ComponentHost(ComponentHostProfile.ForRuntime("win-x64"));
    var start = host.DetachedStartInfo("C:\\a path\\brokerctl.exe", ["supervise", "--vault", "C:\\vault path"], "C:\\a path");
    Assert.True(start.UseShellExecute);
    Assert.Equal(System.Diagnostics.ProcessWindowStyle.Hidden, start.WindowStyle);
    Assert.False(start.RedirectStandardInput || start.RedirectStandardOutput || start.RedirectStandardError);
    Assert.Equal(["supervise", "--vault", "C:\\vault path"], start.ArgumentList);
  }

  [Fact]
  public void DefaultDirectoriesUsePlatformPolicyAndIgnoreRelativeXdgPath()
  {
    var user = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "user"));
    var local = Path.Combine(user, "LocalAppData");
    var xdg = Path.Combine(user, "xdg-data");
    Assert.Equal(Path.Combine(local, "AstraCredentialBroker", "v1"),
      ComponentHostProfile.ForRuntime("win-x64").ResolveDefaultHome(user, local, xdg));
    var linux = ComponentHostProfile.ForRuntime("linux-x64");
    Assert.Equal(Path.Combine(xdg, "AstraCredentialBroker", "v1"), linux.ResolveDefaultHome(user, local, xdg));
    Assert.Equal(Path.Combine(xdg, "AstraCredentialBroker", "v1"), linux.ResolveDefaultHome("", "", xdg));
    Assert.Equal(Path.Combine(user, ".local", "share", "AstraCredentialBroker", "v1"), linux.ResolveDefaultHome(user, local, "relative"));
    Assert.Equal(Path.Combine(user, "Library", "Application Support", "AstraCredentialBroker", "v1"),
      ComponentHostProfile.ForRuntime("osx-arm64").ResolveDefaultHome(user, local, xdg));
  }

  [Theory]
  [InlineData("linux-x64")]
  [InlineData("osx-arm64")]
  public void UnixPathAndFilenamePolicyDoesNotInheritWindowsRules(string rid)
  {
    var profile = ComponentHostProfile.ForRuntime(rid);
    Assert.False(profile.PathComparer.Equals("file", "FILE"));
    Assert.True(profile.IsSafeFileName("valid:unix?name"));
    Assert.False(profile.IsSafeFileName("escape/name"));
    Assert.False(profile.IsSafeFileName("escape\\name"));
    Assert.False(profile.IsSafeFileName("\0"));
    var windows = ComponentHostProfile.ForRuntime("win-x64");
    Assert.True(windows.PathComparer.Equals("file", "FILE"));
    Assert.False(windows.IsSafeFileName("valid:unix?name"));
    Assert.False(windows.IsSafeFileName("trailing."));
  }

  [Fact]
  public void SharedHostRecognizesCurrentProcessAndRejectsDifferentStartTime()
  {
    var host = BrokerPlatform.Current.Components;
    var identity = host.CurrentProcess;
    var endpoint = new RuntimeEndpoint(identity.Pid, identity.StartTime, "", "", "");
    Assert.True(host.IsProcessAlive(endpoint));
    Assert.False(host.IsProcessAlive(endpoint with { ProcessStartTime = identity.StartTime + 1 }));
  }

  [UnixFact]
  public void CopiedUnixApphostReceivesOwnerExecutePermission()
  {
    if (OperatingSystem.IsWindows()) return;
    var root = Path.Combine(Path.GetTempPath(), "AstraHostModes-" + Crypto.RandomId());
    Directory.CreateDirectory(root);
    try
    {
      var source = Path.Combine(root, "source");
      var target = Path.Combine(root, "brokerctl");
      File.WriteAllText(source, "test-only");
      File.SetUnixFileMode(source, UnixFileMode.UserRead | UnixFileMode.UserWrite);
      File.Copy(source, target);
      BrokerPlatform.Current.Components.PrepareCopiedFile(source, target);
      Assert.True(File.GetUnixFileMode(target).HasFlag(UnixFileMode.UserExecute));
    }
    finally { Directory.Delete(root, true); }
  }
}

public sealed class UnixFactAttribute : FactAttribute
{
  public UnixFactAttribute()
  {
    if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) Skip = "Unix file mode integration test";
  }
}
