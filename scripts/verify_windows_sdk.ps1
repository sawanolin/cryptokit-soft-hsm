param(
    [string]$SdkDirectory = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SdkDirectory)) {
    $SdkDirectory = Join-Path $repoRoot "dist\sdfapi-windows-x64"
}
$root = [IO.Path]::GetFullPath($SdkDirectory)
$dll = Join-Path $root "bin\sdfapi_x64.dll"
$header = Join-Path $root "include\sdf.h"

if (-not (Test-Path -LiteralPath $dll) -or -not (Test-Path -LiteralPath $header)) {
    throw "SDK DLL or public header is missing: $root"
}

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
$objdump = Get-Command objdump.exe -ErrorAction SilentlyContinue
if (-not $objdump -and (Test-Path -LiteralPath "C:\msys64\ucrt64\bin\objdump.exe")) {
    $objdump = Get-Item -LiteralPath "C:\msys64\ucrt64\bin\objdump.exe"
}
if ($dumpbin) {
    $exports = (& $dumpbin.Source /nologo /exports $dll) -join "`n"
    $dependencies = (& $dumpbin.Source /nologo /dependents $dll) -join "`n"
} elseif ($objdump) {
    $toolPath = if ($objdump.Source) { $objdump.Source } else { $objdump.FullName }
    $details = (& $toolPath -p $dll) -join "`n"
    $exports = $details
    $dependencies = $details
} else {
    throw "Neither dumpbin.exe nor objdump.exe was found."
}

$declared = Select-String -Path $header -Pattern '\b(SDF_[A-Za-z0-9_]+)\s*\(' -AllMatches |
    ForEach-Object { $_.Matches } |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique
$missing = @($declared | Where-Object { $exports -notmatch "(?m)\b$([regex]::Escape($_))\b" })
if ($missing.Count -ne 0) {
    throw "Missing DLL exports: $($missing -join ', ')"
}
if ($dependencies -match '(?i)libwinpthread-1\.dll') {
    throw "sdfapi_x64.dll still depends on libwinpthread-1.dll; rebuild with static winpthread linking."
}

Write-Host "Verified $($declared.Count) declared SDF exports. No bundled MinGW runtime DLL is required."