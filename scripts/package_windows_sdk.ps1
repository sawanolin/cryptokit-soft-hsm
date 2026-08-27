param(
    [string]$Version = "1.1.4",
    [string]$SourceDirectory = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SourceDirectory)) {
    $SourceDirectory = Join-Path $repoRoot "dist\sdfapi-windows-x64"
}
$source = [IO.Path]::GetFullPath($SourceDirectory)
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "release"))
$stage = [IO.Path]::GetFullPath((Join-Path $releaseRoot "sdfapi-windows-x64"))
$zip = [IO.Path]::GetFullPath((Join-Path $releaseRoot "sdfapi-windows-x64-$Version.zip"))

$requiredFiles = @(
    "README.md",
    "bin\sdfapi_x64.dll",
    "lib\sdfapi_x64.lib",
    "lib\sdfapi_x64.dll.a",
    "include\sdf.h",
    "include\sdf_types.h",
    "include\sdf_err.h",
    "config\sdfapi.ini"
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $relative) -PathType Leaf)) {
        throw "Required SDK file is missing: $relative"
    }
}
$licenseFiles = @(Get-ChildItem -LiteralPath (Join-Path $source "licenses") -File)
if ($licenseFiles.Count -eq 0) {
    throw "The SDK licenses directory is empty."
}

& (Join-Path $PSScriptRoot "verify_windows_sdk.ps1") -SdkDirectory $source

New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null
if (Test-Path -LiteralPath $stage) {
    if (-not $Force) { throw "Release staging already exists; rerun with -Force: $stage" }
    if (-not $stage.StartsWith($releaseRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a staging path outside release/: $stage"
    }
    Remove-Item -LiteralPath $stage -Recurse -Force
}
if (Test-Path -LiteralPath $zip) {
    if (-not $Force) { throw "Release archive already exists; rerun with -Force: $zip" }
    Remove-Item -LiteralPath $zip -Force
}

foreach ($relative in $requiredFiles) {
    $destination = Join-Path $stage $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath (Join-Path $source $relative) -Destination $destination
}
$licenseDestination = Join-Path $stage "licenses"
New-Item -ItemType Directory -Force -Path $licenseDestination | Out-Null
$licenseFiles | Copy-Item -Destination $licenseDestination

$hashLines = Get-ChildItem -LiteralPath $stage -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
[IO.File]::WriteAllLines((Join-Path $stage "SHA256SUMS"), $hashLines, [Text.UTF8Encoding]::new($false))

Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal
Write-Host "Minimal SDK archive: $zip"
Get-FileHash -LiteralPath $zip -Algorithm SHA256
