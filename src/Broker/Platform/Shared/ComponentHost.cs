using System.Diagnostics;

namespace Astra.Credentials;

internal sealed class ComponentHost(ComponentHostProfile profile) : IComponentHost
{
  public string RuntimeIdentifier => profile.RuntimeIdentifier;
  public string DefaultHome => profile.ResolveDefaultHome(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Environment.GetEnvironmentVariable("XDG_DATA_HOME"));
  public string ExecutableName => profile.ExecutableName;
  public string[] RequiredFiles => profile.RequiredFiles;
  public StringComparison PathComparison => profile.PathComparison;
  public StringComparer PathComparer => profile.PathComparer;
  public bool IsSafeFileName(string name) => profile.IsSafeFileName(name);

  public void PrepareCopiedFile(string source, string target)
  {
    if (!OperatingSystem.IsWindows())
    {
      // Preserve ordinary permissions, never propagate setuid/setgid/sticky attributes.
      var mode = File.GetUnixFileMode(source) & (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
      if (Path.GetFileName(target) == ExecutableName) mode |= UnixFileMode.UserExecute;
      File.SetUnixFileMode(target, mode);
    }
  }
  public ProcessIdentity CurrentProcess
  {
    get
    {
      using var process = Process.GetCurrentProcess();
      return new(process.Id, process.StartTime.ToUniversalTime().Ticks);
    }
  }

  public void LaunchDetached(string executable, string[] arguments, string workingDirectory)
  {
    var start = DetachedStartInfo(executable, arguments, workingDirectory);
    if (profile.System != ComponentSystem.Windows)
      Protocol.Require(File.Exists(start.FileName) && File.Exists("/bin/sh"), "detached-launcher-unavailable");
    using var process = Process.Start(start) ?? throw new BrokerException("supervisor-start-failed");
  }

  internal ProcessStartInfo DetachedStartInfo(string executable, string[] arguments, string workingDirectory)
  {
    ProcessStartInfo start;
    if (profile.System == ComponentSystem.Windows)
    {
      // Keep the verified Windows Shell launch, without inherited controller handles.
      start = new(executable) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden };
    }
    else
    {
      // nohup handles SIGHUP; the fixed shell program closes inherited stdio before exec.
      // All caller values are separate positional arguments, never shell source text.
      start = new("/usr/bin/nohup")
      { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
      foreach (var argument in new[] { "/bin/sh", "-c", "exec </dev/null >/dev/null 2>&1; exec \"$@\"", "astra-credential-broker", executable })
        start.ArgumentList.Add(argument);
    }
    start.WorkingDirectory = workingDirectory;
    foreach (var argument in arguments) start.ArgumentList.Add(argument);
    return start;
  }

  public async Task<int> RunWorker(string executable, string[] arguments)
  {
    // Worker lifetime belongs to the independent supervisor, not a client controller.
    var result = await Run(executable, arguments, null);
    return result.ExitCode;
  }

  public async Task<string> RunTool(string executable, string[] arguments, bool allowFailure = false)
  {
    var result = await Run(executable, arguments, TimeSpan.FromSeconds(60));
    if (!allowFailure && result.ExitCode != 0)
      throw new ComponentCommandException(Path.GetFileName(executable), result.ExitCode, "component-probe-failed");
    return result.Output;
  }

  private async Task<(int ExitCode, string Output)> Run(string executable, string[] arguments, TimeSpan? limit)
  {
    var start = new ProcessStartInfo(executable)
    {
      UseShellExecute = false,
      CreateNoWindow = profile.System == ComponentSystem.Windows,
      RedirectStandardInput = true,
      RedirectStandardOutput = true,
      RedirectStandardError = true
    };
    foreach (var argument in arguments) start.ArgumentList.Add(argument);
    using var process = Process.Start(start) ?? throw new BrokerException("process-start-failed");
    process.StandardInput.Close();
    var output = process.StandardOutput.ReadToEndAsync();
    var error = process.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource();
    if (limit is not null) timeout.CancelAfter(limit.Value);
    try { await process.WaitForExitAsync(timeout.Token); }
    catch { process.Kill(true); await process.WaitForExitAsync(); throw; }
    _ = await error; // Never expose child diagnostics which could contain secrets.
    return (process.ExitCode, await output);
  }

  public bool IsProcessAlive(RuntimeEndpoint endpoint)
  {
    try
    {
      using var process = Process.GetProcessById(endpoint.Pid);
      return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == endpoint.ProcessStartTime;
    }
    catch (ArgumentException) { return false; }
  }

  public async Task TerminateVerified(RuntimeEndpoint endpoint, string expectedExecutable)
  {
    using var process = Process.GetProcessById(endpoint.Pid);
    Protocol.Require(process.StartTime.ToUniversalTime().Ticks == endpoint.ProcessStartTime &&
      string.Equals(process.MainModule?.FileName, expectedExecutable, PathComparison), "process-identity-mismatch");
    process.Kill();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await process.WaitForExitAsync(timeout.Token);
  }
}
