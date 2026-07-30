@echo off
setlocal
where cl.exe >nul 2>nul
if errorlevel 1 (
  echo Please run this script from an x64 Native Tools Command Prompt for Visual Studio.
  exit /b 1
)

if not exist bin mkdir bin
for %%F in (examples\*.c) do (
  echo Building %%~nxF
  cl.exe /nologo /W4 /utf-8 /Iinclude "%%F" /link /LIBPATH:lib sdfapi_x64.lib /OUT:"bin\%%~nF.exe"
  if errorlevel 1 exit /b 1
)
copy /Y config\sdfapi.ini bin\sdfapi.ini >nul
echo All examples built successfully.
