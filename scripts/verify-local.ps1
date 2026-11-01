param(
  [string]$Publish = (Join-Path $PSScriptRoot '../artifacts/publish/win-x64'),
  [string]$Tools = (Join-Path $PSScriptRoot '../artifacts/smoke-tools/win-x64'),
  [string]$Root
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw [PlatformNotSupportedException]::new('unsupported-platform: Astra Credential Broker validation requires Windows.')
}
if (-not $Root) { $Root = Join-Path $env:LOCALAPPDATA ('AstraBrokerValidation/' + [guid]::NewGuid().ToString('N')) }
# Uses published EXEs directly. Neither dotnet, node, pnpm nor network access is needed.
& (Join-Path ([IO.Path]::GetFullPath($Tools)) 'broker-smoke.exe') --publish ([IO.Path]::GetFullPath($Publish)) --root ([IO.Path]::GetFullPath($Root))
if ($LASTEXITCODE -ne 0) { throw "Validation failed; retained diagnostics in $Root" }
