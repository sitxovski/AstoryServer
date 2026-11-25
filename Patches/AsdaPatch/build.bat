@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Build AsdaPatch.dll (x86, static CRT).
rem  Requires Visual Studio 2022 (Community or Build Tools) with the x86 toolset.
rem  Output: out\AsdaPatch.dll
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
echo [1/4] Env: "!VCVARS!"
call "!VCVARS!" >nul || exit /b 1

if not exist out mkdir out
if not exist obj mkdir obj

echo [2/4] Compiling production...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /GS- /EHa /D_CRT_SECURE_NO_WARNINGS ^
   /DWIN32 /D_WINDOWS /D_USRDLL ^
   /I src /I ..\AsdaSecure\src ^
   /Fo:obj\ ^
   src\dllmain.cpp src\Log.cpp src\Config.cpp src\Hook.cpp src\AcJournal.cpp src\ChatJournal.cpp src\patches\*.cpp ^
   ..\AsdaSecure\src\AsdaSecure.cpp ..\AsdaSecure\src\AsdaChannel.cpp ..\AsdaSecure\src\AsdaServerBridge.cpp ^
   /link /DLL /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 ^
   /MAP:out\AsdaPatch.map /OUT:out\AsdaPatch.dll kernel32.lib user32.lib bcrypt.lib ws2_32.lib
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

rem Stand build (EAC 8.6 R3-05): P73 test exports (P73_Test*) and the stand bind table exist ONLY here (/DASDA_PATCH_STAND).
rem The production out\AsdaPatch.dll has none of them (verify_p73.py checks exports of both). Stands of P73 load out\stand\AsdaPatch.dll.
echo [3/4] Compiling stand build (ASDA_PATCH_STAND)...
if not exist out\stand mkdir out\stand
if not exist obj\stand mkdir obj\stand
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /GS- /EHa /D_CRT_SECURE_NO_WARNINGS ^
   /DWIN32 /D_WINDOWS /D_USRDLL /DASDA_PATCH_STAND ^
   /I src /I ..\AsdaSecure\src ^
   /Fo:obj\stand\ ^
   src\dllmain.cpp src\Log.cpp src\Config.cpp src\Hook.cpp src\AcJournal.cpp src\ChatJournal.cpp src\patches\*.cpp ^
   ..\AsdaSecure\src\AsdaSecure.cpp ..\AsdaSecure\src\AsdaChannel.cpp ..\AsdaSecure\src\AsdaServerBridge.cpp ^
   /link /DLL /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 ^
   /MAP:out\stand\AsdaPatch.map /OUT:out\stand\AsdaPatch.dll kernel32.lib user32.lib bcrypt.lib ws2_32.lib
if errorlevel 1 (
  echo [ERROR] Stand build failed.
  exit /b 1
)

echo [4/4] Done: %~dp0out\AsdaPatch.dll (production), %~dp0out\stand\AsdaPatch.dll (stand)
dir /b out\AsdaPatch.dll out\stand\AsdaPatch.dll
endlocal
