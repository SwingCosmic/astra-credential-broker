param([string]$Output = (Join-Path $PSScriptRoot '../artifacts/publish/win-x64'))
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw [PlatformNotSupportedException]::new('unsupported-platform: Astra Credential Broker publishing requires Windows.')
}
$repo = Split-Path $PSScriptRoot -Parent
$Output = [IO.Path]::GetFullPath($Output)
Push-Location $repo
try {
  dotnet restore --locked-mode
  if ($LASTEXITCODE -ne 0) { throw 'Locked restore failed' }
  dotnet publish src/Brokerctl/Brokerctl.csproj -c Release --no-restore -o $Output
  if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
  & (Join-Path $Output 'brokerctl.exe') make-manifest --source $Output | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Manifest failed' }
  dotnet publish test/Broker.Smoke/Broker.Smoke.csproj -c Release --no-restore -o (Join-Path $repo 'artifacts/smoke-tools/win-x64')
  if ($LASTEXITCODE -ne 0) { throw 'Smoke-tool publish failed' }
  Write-Output "Self-contained component: $Output"
  Write-Output "Offline validation tool: $(Join-Path $repo 'artifacts/smoke-tools/win-x64/broker-smoke.exe')"
} finally { Pop-Location }
