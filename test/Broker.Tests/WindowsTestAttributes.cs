using Xunit;

namespace Broker.Tests;

// Only integration suites using the shipped Windows adapters need this platform.
// Protocol/crypto and injectable business/platform tests run without these attributes.
public sealed class WindowsFactAttribute : FactAttribute
{
  public WindowsFactAttribute()
  {
    if (!OperatingSystem.IsWindows()) Skip = "Windows adapter integration test";
  }
}

public sealed class WindowsTheoryAttribute : TheoryAttribute
{
  public WindowsTheoryAttribute()
  {
    if (!OperatingSystem.IsWindows()) Skip = "Windows adapter integration test";
  }
}
