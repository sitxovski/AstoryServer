@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Build AddonNPC.dll (x86, static CRT).
rem  Requires Visual Studio 2022 (Community or Build Tools) with the x86 toolset.
rem  Output: out\AddonNPC.dll
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
   /I src /I ..\AsdaPatch\src ^
   /Fo:obj\ ^
   src\dllmain.cpp src\Config.cpp src\patches\*.cpp ^
   ..\AsdaPatch\src\Log.cpp ..\AsdaPatch\src\Hook.cpp ..\AsdaPatch\src\AcJournal.cpp ^
   /link /DLL /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 ^
   /MAP:out\AddonNPC.map /OUT:out\AddonNPC.dll kernel32.lib user32.lib
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo [3/3] Done: %~dp0out\AddonNPC.dll
dir /b out\AddonNPC.dll
endlocal
