@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Build SrvDbPatch.dll (x86, static CRT) - patches for RelayServer.exe,
rem  ItemRelayServer.exe, OperationServer.exe (P126, 15.11.2026).
rem  Requires Visual Studio 2022 (Community or Build Tools) with the x86 toolset.
rem  Output: out\SrvDbPatch.dll
rem
rem  Shared sources: Log, Hook from ..\AsdaPatch\src; DbReconnectCore from
rem  ..\DbReconnect\src (same module as LoginPatch/DBPatch P125).
rem  Include order matters: src first, so our Config.h / Patches.h win.
rem  (ASCII-only on purpose: cmd.exe reads .bat in the OEM codepage)
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat"
  )
)
for %%E in (Community Professional Enterprise BuildTools) do (
  if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat" (
    set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat"
  )
)
if not defined VCVARS (
  echo [ERROR] vcvars32.bat not found ^(Visual Studio 2022, x86 toolset^).
  exit /b 1
)
echo [1/3] Env: "!VCVARS!"
call "!VCVARS!" >nul || exit /b 1

if not exist out mkdir out
if not exist obj mkdir obj

echo [2/3] Compiling...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /GS- /EHa /D_CRT_SECURE_NO_WARNINGS ^
   /DWIN32 /D_WINDOWS /D_USRDLL ^
   /I src /I ..\AsdaPatch\src /I ..\DbReconnect\src ^
   /Fo:obj\ ^
   src\dllmain.cpp src\Config.cpp src\Registry.cpp src\p126_db_reconnect.cpp ^
   ..\DbReconnect\src\DbReconnectCore.cpp ^
   ..\AsdaPatch\src\Log.cpp ..\AsdaPatch\src\Hook.cpp ^
   /link /DLL /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\SrvDbPatch.dll kernel32.lib user32.lib ole32.lib oleaut32.lib
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo [3/3] Done: %~dp0out\SrvDbPatch.dll
dir /b out\SrvDbPatch.dll
endlocal
