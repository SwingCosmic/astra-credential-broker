param(
  [Parameter(Mandatory)][string]$OldPublish,
  [Parameter(Mandatory)][string]$Publish,
  [string]$Root
)
$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Join-Path ([IO.Path]::GetTempPath()) ('astra-broker-upgrade-' + [guid]::NewGuid().ToString('N')) }
$Root = [IO.Path]::GetFullPath($Root)
$oldController = Join-Path ([IO.Path]::GetFullPath($OldPublish)) 'brokerctl.exe'
$newController = Join-Path ([IO.Path]::GetFullPath($Publish)) 'brokerctl.exe'
$serviceHome = Join-Path $Root 'service-home'
$vault = Join-Path $Root 'vault'
$response = Join-Path $Root 'private/initialize.dpapi'
$checks = [Collections.Generic.List[string]]::new()
New-Item -ItemType Directory -Path $Root -Force | Out-Null

function Invoke-Controller([string]$Executable, [string[]]$Arguments, [object]$InputValue = $null) {
  $start = [Diagnostics.ProcessStartInfo]::new($Executable)
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardInput = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
  $process = [Diagnostics.Process]::Start($start)
  try {
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($null -ne $InputValue) { $process.StandardInput.Write(($InputValue | ConvertTo-Json -Depth 20 -Compress)) }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'controller-timeout' }
    $diagnostic = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw ('controller-failed: ' + $diagnostic) }
    return ($stdout.GetAwaiter().GetResult() | ConvertFrom-Json)
  } finally { $process.Dispose() }
}
function Check([bool]$Condition, [string]$Name) {
  if (-not $Condition) { throw ('upgrade-check-failed: ' + $Name) }
  $checks.Add($Name)
}

$complete = $false
try {
  $old = Invoke-Controller $oldController @('install-local', '--home', $serviceHome, '--source', $OldPublish)
  Check ($old.version -in @('0.1.0','0.2.0')) 'installed isolated legacy component'
  $registration = Invoke-Controller $oldController @('register-vault', '--home', $serviceHome, '--vault', $vault)
  $null = Invoke-Controller $oldController @('ensure-running', '--home', $serviceHome, '--vault', $vault)
  $null = Invoke-Controller $oldController @('rpc', '--home', $serviceHome, '--vault', $vault, '--admin', '--response-file', $response) @{
    method = 'initialize'; params = @{ operationId = 'upgrade-export'; sourceWatermark = 'fictional-source'; records = @(@{
      credentialId = 'upgrade-record'; contentType = 'application/custom'; payloadFormatVersion = 1;
      payload = 'RklDVElPTkFMLVVQR1JBREUtQzE'; metadata = @{ supportsUsage = 'true' }
    }) }
  }
  $before = Invoke-Controller $oldController @('status', '--home', $serviceHome, '--vault', $vault)
  Check ($before.runtime.serviceStatus -eq 'READY') 'legacy service remains online before upgrade'
  $incompatible = Invoke-Controller $newController @('install-status', '--home', $serviceHome)
  Check ($incompatible.installState -eq 'incompatible') 'new controller detects legacy installation without business call'
  $upgraded = Invoke-Controller $newController @('install-local', '--home', $serviceHome, '--source', $Publish)
  Check ($upgraded.version -eq '0.3.0' -and $upgraded.directory -ne $old.directory) 'new installer drains legacy service and switches component'
  $null = Invoke-Controller $newController @('ensure-running', '--home', $serviceHome, '--vault', $vault)
  $after = Invoke-Controller $newController @('status', '--home', $serviceHome, '--vault', $vault)
  Check ($after.runtime.serviceStatus -eq 'READY' -and $after.runtime.storageVersion -eq $before.runtime.storageVersion) 'restart retains original vault version and service key'
  $listed = Invoke-Controller $newController @('rpc', '--home', $serviceHome, '--vault', $vault, '--admin') @{ method = 'listCredentials'; params = @{} }
  Check ($listed.items.Count -eq 1 -and $listed.items[0].credentialId -eq 'upgrade-record' -and $listed.items[0].revision -eq '1') 'encrypted credential survives upgrade without new export'
  $current = Invoke-Controller $newController @('component-info')
  Check ($current.version -eq '0.3.0' -and $current.apiRevision -eq 3 -and $current.protocolVersion -eq 1 -and $current.storageVersion -eq 1) 'published binary exposes expected release and API contract'
  $complete = $true
} finally {
  try { $null = Invoke-Controller $newController @('uninstall', '--home', $serviceHome) }
  catch { Write-Warning 'Isolated test cleanup needs attention; use retained service-home registration.' }
  $report = @{ passed = $complete; checks = $checks.ToArray(); root = $Root; oldPublish = [IO.Path]::GetFullPath($OldPublish); publish = [IO.Path]::GetFullPath($Publish) }
  $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root 'upgrade-result.json') -Encoding utf8
  $report | ConvertTo-Json -Depth 10
}
