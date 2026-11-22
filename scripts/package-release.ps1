param(
  [string]$Publish = (Join-Path $PSScriptRoot '../artifacts/publish/win-x64'),
  [string]$Output = (Join-Path $PSScriptRoot '../artifacts/release'),
  [string]$Tag
)
$ErrorActionPreference = 'Stop'
$manifest = Get-Content -LiteralPath (Join-Path $Publish 'component.json') -Raw | ConvertFrom-Json
$version = $manifest.version
$project = [xml](Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Directory.Build.props') -Raw)
if ($manifest.component -cne 'astra-credential-broker' -or $manifest.rid -cne 'win-x64' -or
    $version -cne $project.Project.PropertyGroup.Version) {
  throw 'The published component does not match the release project.'
}
if ($Tag -and $Tag -cne "v$version") { throw "Expected tag v$version, got $Tag." }

$Output = [IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output) | Out-Null
if (Get-ChildItem -LiteralPath $Output -Force) { throw "Release output must be empty: $Output" }
$name = "$($manifest.component)-$version-$($manifest.rid).zip"
$archive = Join-Path $Output $name
[IO.Compression.ZipFile]::CreateFromDirectory([IO.Path]::GetFullPath($Publish), $archive)
$release = [ordered]@{
  schemaVersion = 1
  component = $manifest.component
  version = $version
  apiRevision = $manifest.apiRevision
  protocolMin = $manifest.protocolMin
  protocolMax = $manifest.protocolMax
  storageMin = $manifest.storageMin
  storageMax = $manifest.storageMax
  assets = @([ordered]@{
    rid = $manifest.rid
    name = $name
    size = (Get-Item -LiteralPath $archive).Length
    sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  })
}
$release | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Output 'release.json') -Encoding utf8NoBOM
Write-Output "Packaged $archive"
