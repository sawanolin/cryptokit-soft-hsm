$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dll = Join-Path $root "bin\sdfapi_x64.dll"
$header = Join-Path $root "include\sdf.h"

if (-not (Test-Path $dll) -or -not (Test-Path $header)) {
    throw "SDK DLL or public header is missing."
}
$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
$objdump = Get-Command objdump.exe -ErrorAction SilentlyContinue
if ($dumpbin) {
    $exports = (& $dumpbin.Source /nologo /exports $dll) -join "`n"
} elseif ($objdump) {
    $exports = (& $objdump.Source -p $dll) -join "`n"
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
Write-Host "Verified $($declared.Count) declared SDF exports in sdfapi_x64.dll."
