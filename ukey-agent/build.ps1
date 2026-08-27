param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $projectDir 'build'
$distDir = Join-Path $projectDir 'dist'
$payloadDir = Join-Path $buildDir 'payload'
$webDownloadDir = Join-Path (Split-Path -Parent $projectDir) 'web\backend\static\downloads'
$vcvars = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat'

if (-not (Test-Path -LiteralPath $vcvars)) {
    throw '未找到 Visual Studio 2022 C++ 编译环境。'
}

New-Item -ItemType Directory -Force -Path $buildDir, $distDir, $payloadDir | Out-Null
$common = if ($Configuration -eq 'Release') { '/nologo /utf-8 /std:c++17 /W4 /WX /O1 /Os /MT /EHsc /DNOMINMAX' } else { '/nologo /utf-8 /std:c++17 /W4 /WX /Od /MTd /EHsc /DNOMINMAX' }

function Invoke-Compiler([string]$Arch, [string]$Source, [string]$Output, [string]$Libraries, [string]$Subsystem, [string]$ExtraInput = '') {
    $objectDir = Join-Path $buildDir $Arch
    New-Item -ItemType Directory -Force -Path $objectDir | Out-Null
    $extraArgument = if ($ExtraInput) { '"{0}"' -f $ExtraInput } else { '' }
    $command = 'call "{0}" {1} >nul && cl {2} /I"{3}\src" "{4}" {9} /Fe:"{5}" /Fo:"{6}\\" /link /INCREMENTAL:NO /OPT:REF /OPT:ICF /SUBSYSTEM:{8} {7}' -f $vcvars, $Arch, $common, $projectDir, $Source, $Output, $objectDir, $Libraries, $Subsystem, $extraArgument
    & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) { throw "编译 $Output 失败。" }
}

Invoke-Compiler 'x86' (Join-Path $projectDir 'src\helper_main.cpp') (Join-Path $payloadDir 'ukey-helper-x86.exe') '/ENTRY:mainCRTStartup' 'WINDOWS'
Invoke-Compiler 'x64' (Join-Path $projectDir 'src\helper_main.cpp') (Join-Path $payloadDir 'ukey-helper-x64.exe') '/ENTRY:mainCRTStartup' 'WINDOWS'

$resourceFile = Join-Path $buildDir 'ukey-agent-resources.res'
$resourceCommand = 'call "{0}" x64 >nul && cd /d "{1}" && rc /nologo /fo"{2}" "{3}"' -f $vcvars, $projectDir, $resourceFile, (Join-Path $projectDir 'resources.rc')
& $env:ComSpec /d /s /c $resourceCommand
if ($LASTEXITCODE -ne 0) { throw '编译内嵌资源失败。' }

Invoke-Compiler 'x64' (Join-Path $projectDir 'src\agent_main.cpp') (Join-Path $distDir 'ukey-agent.exe') 'Ws2_32.lib Gdiplus.lib Comdlg32.lib Shell32.lib Advapi32.lib User32.lib Gdi32.lib Crypt32.lib Cryptui.lib Ole32.lib' 'WINDOWS' $resourceFile

$obsoleteFiles = @('ukey-helper.exe', 'ukey-helper-x86.exe', 'ukey-helper-x64.exe', 'ukey-agent.ini', 'ukey-agent.js', 'logo.png', 'README.md')
foreach ($obsoleteName in $obsoleteFiles) {
    $obsoletePath = Join-Path $distDir $obsoleteName
    if (Test-Path -LiteralPath $obsoletePath -PathType Leaf) {
        Remove-Item -LiteralPath $obsoletePath -Force
    }
}

New-Item -ItemType Directory -Force -Path $webDownloadDir | Out-Null
Copy-Item -LiteralPath (Join-Path $distDir 'ukey-agent.exe') `
    -Destination (Join-Path $webDownloadDir 'ukey-agent-windows-x64-1.1.4.exe') -Force

Write-Host "单文件构建完成：$(Join-Path $distDir 'ukey-agent.exe')"
Write-Host "Web 下载文件已更新：$(Join-Path $webDownloadDir 'ukey-agent-windows-x64-1.1.4.exe')"
