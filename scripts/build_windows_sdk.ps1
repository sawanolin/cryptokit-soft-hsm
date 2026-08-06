param(
    [string]$MsysRoot = "C:\msys64"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "build"))
$buildDirectory = [IO.Path]::GetFullPath((Join-Path $buildRoot "sdfx-windows-min"))
if (Test-Path -LiteralPath $buildDirectory) {
    if (-not $buildDirectory.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a build path outside build/: $buildDirectory"
    }
    Remove-Item -LiteralPath $buildDirectory -Recurse -Force
}
$bash = Join-Path $MsysRoot "usr\bin\bash.exe"
$cygpath = Join-Path $MsysRoot "usr\bin\cygpath.exe"
$gendef = Join-Path $MsysRoot "ucrt64\bin\gendef.exe"
$dlltool = Join-Path $MsysRoot "ucrt64\bin\dlltool.exe"
foreach ($tool in @($bash, $cygpath, $gendef, $dlltool)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Required MSYS2 tool is missing: $tool"
    }
}

$repoUnix = (& $cygpath -u $repoRoot).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoUnix)) {
    throw "Failed to convert the repository path for MSYS2."
}
$toolchainUnix = "$repoUnix/sdfx/cmake/toolchains/mingw-x64.cmake"
$buildCommand = "export PATH=/ucrt64/bin:/usr/bin:`$PATH; cd '$repoUnix'; cmake -S sdfx -B build/sdfx-windows-min -G 'Unix Makefiles' -DCMAKE_MAKE_PROGRAM=/usr/bin/make.exe -DCMAKE_TOOLCHAIN_FILE='$toolchainUnix' -DSDFX_TRANSPORT_TYPE=tcp -DBUILD_DAEMON=OFF -DBUILD_SDK=ON -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release && cmake --build build/sdfx-windows-min --target sdfx_sdk -j2"
& $bash -lc $buildCommand
if ($LASTEXITCODE -ne 0) { throw "Windows SDK build failed." }

$buildSdk = Join-Path $repoRoot "build\sdfx-windows-min\sdk"
Push-Location $buildSdk
try {
    & $gendef ".\sdfapi_x64.dll"
    if ($LASTEXITCODE -ne 0) { throw "gendef failed." }
    & $dlltool -d ".\sdfapi_x64.def" -D "sdfapi_x64.dll" -l ".\sdfapi_x64.lib" -m "i386:x86-64"
    if ($LASTEXITCODE -ne 0) { throw "dlltool failed." }
} finally {
    Pop-Location
}

$dist = Join-Path $repoRoot "dist\sdfapi-windows-x64"
Copy-Item -LiteralPath (Join-Path $buildSdk "sdfapi_x64.dll") -Destination (Join-Path $dist "bin\sdfapi_x64.dll") -Force
Copy-Item -LiteralPath (Join-Path $buildSdk "sdfapi_x64.dll.a") -Destination (Join-Path $dist "lib\sdfapi_x64.dll.a") -Force
Copy-Item -LiteralPath (Join-Path $buildSdk "sdfapi_x64.lib") -Destination (Join-Path $dist "lib\sdfapi_x64.lib") -Force
foreach ($name in @("sdf.h", "sdf_types.h", "sdf_err.h")) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "sdfx\include\$name") -Destination (Join-Path $dist "include\$name") -Force
}

& (Join-Path $PSScriptRoot "verify_windows_sdk.ps1") -SdkDirectory $dist

$hashLines = Get-ChildItem -LiteralPath $dist -Recurse -File |
    Where-Object Name -ne "SHA256SUMS" |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($dist.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
[IO.File]::WriteAllLines((Join-Path $dist "SHA256SUMS"), $hashLines, [Text.UTF8Encoding]::new($false))
Write-Host "Updated minimal SDK directory: $dist"