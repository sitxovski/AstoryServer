@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  AsdaEacServer (EAC E1, 2026-10-16): x64 build, static CRT /MT, Windows CNG + ODBC + EOS SDK 1.19.2.1.
rem  Requires Visual Studio 2022 with the x64 toolset (vcvars64.bat). ASCII-only (cmd reads .bat in OEM).
rem  Output:
rem    out\AsdaEacServer.exe              production exe (no stand switches)
rem    out\EOSSDK-Win64-Shipping.dll      EOS SDK runtime (delay-loaded; not touched with --no-eos)
rem    out\stand\AsdaEacServer_stand.exe  stand build (ASDA_EAC_STAND: --fake-auth, --fake-eos)
rem    out\stand\stand_asdaid.exe         stand (a): AsdaId client
rem    out\stand\stand_bridge.exe         stand (b): fake P73 on the bridge
rem    out\stand\stand_sidecar.exe        stand (c): 15901 client over AsdaSecure
rem    out\stand\stand_status.exe         stand (g): A6.8 admin status endpoint (127.0.0.1, read-only)
rem    out\stand\e2e_r3.exe               rev.3: reviewer e2e stand adapted (bind, Authenticated, S4.2, S5)
rem    out\stand\e2e_r3rev.exe            8.6: reviewer R3 e2e (stand\review_regress_r3) + out\stand\r3host\stand_r3host.exe (x86)
rem  Usage: build.bat          - build all
rem         build.bat test     - build all and run stand\run_stands.bat
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "EOSSDK=%~dp0..\..\ThirdParty\EOS-SDK-58105819-Release-v1.19.2.1\SDK"
rem  no separate EOS SDK download: use the copy shipped with the client
if not exist "%EOSSDK%\Include\eos_sdk.h" set "EOSSDK=%~dp0..\..\AstoryClient\Source\ThirdParty\AsdaEOSSDK\SDK"
if not exist "%EOSSDK%\Include\eos_sdk.h" (
  echo [ERROR] EOS SDK not found: %EOSSDK%
  exit /b 1
)

set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
  )
)
for %%E in (Community Professional Enterprise BuildTools) do (
  if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo [ERROR] vcvars64.bat not found ^(Visual Studio 2022, x64 toolset^).
  exit /b 1
)
echo [1/6] Env: "!VCVARS!"
call "!VCVARS!" >nul || exit /b 1

if not exist out mkdir out
if not exist out\stand mkdir out\stand
if not exist obj\main mkdir obj\main
if not exist obj\stand mkdir obj\stand
if not exist obj\tools mkdir obj\tools

set "CFLAGS=/nologo /utf-8 /std:c++17 /W4 /wd4100 /wd4996 /O2 /MT /EHsc /Zi /DWIN32 /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /I src /I ..\Patches\AsdaSecure\src /I "%EOSSDK%\Include""
set "SRCS=src\Main.cpp src\Core.cpp src\AdminStatus.cpp src\AsdaId.cpp src\EosLayer.cpp src\SqlAuth.cpp src\Jwt.cpp src\Crypto.cpp src\Json.cpp src\Config.cpp src\Log.cpp ..\Patches\AsdaSecure\src\AsdaSecure.cpp ..\Patches\AsdaSecure\src\AsdaChannel.cpp"
set "LIBS=ws2_32.lib bcrypt.lib odbc32.lib advapi32.lib iphlpapi.lib crypt32.lib "%EOSSDK%\Lib\EOSSDK-Win64-Shipping.lib" delayimp.lib"
set "LFLAGS=/SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X64 /DEBUG /OPT:REF /OPT:ICF /DELAYLOAD:EOSSDK-Win64-Shipping.dll"

echo [2/6] AsdaEacServer.exe (production)...
cl %CFLAGS% /Fo:obj\main\ /Fd:obj\main\vc.pdb %SRCS% /link %LFLAGS% /PDB:out\AsdaEacServer.pdb /OUT:out\AsdaEacServer.exe %LIBS%
if errorlevel 1 ( echo [ERROR] AsdaEacServer build failed. & exit /b 1 )

echo [3/6] AsdaEacServer_stand.exe (ASDA_EAC_STAND)...
cl %CFLAGS% /DASDA_EAC_STAND /Fo:obj\stand\ /Fd:obj\stand\vc.pdb %SRCS% /link %LFLAGS% /PDB:out\stand\AsdaEacServer_stand.pdb /OUT:out\stand\AsdaEacServer_stand.exe %LIBS%
if errorlevel 1 ( echo [ERROR] AsdaEacServer_stand build failed. & exit /b 1 )

set "TSRC=src\Crypto.cpp src\Json.cpp src\Jwt.cpp src\Log.cpp ..\Patches\AsdaSecure\src\AsdaSecure.cpp ..\Patches\AsdaSecure\src\AsdaChannel.cpp"
set "TLIBS=ws2_32.lib bcrypt.lib advapi32.lib"

echo [4/6] stand_asdaid.exe / stand_bridge.exe / stand_sidecar.exe...
for %%S in (stand_asdaid stand_bridge stand_sidecar stand_cases) do (
  if not exist obj\tools\%%S mkdir obj\tools\%%S
  cl %CFLAGS% /Fo:obj\tools\%%S\ /Fd:obj\tools\%%S\vc.pdb stand\%%S.cpp %TSRC% /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X64 /OUT:out\stand\%%S.exe %TLIBS%
  if errorlevel 1 ( echo [ERROR] %%S build failed. & exit /b 1 )
)

rem A6.8 (2026-11-22): stand (g) - admin status endpoint 127.0.0.1 (src\AdminStatus.cpp)
if not exist obj\tools\stand_status mkdir obj\tools\stand_status
cl %CFLAGS% /Fo:obj\tools\stand_status\ /Fd:obj\tools\stand_status\vc.pdb stand\stand_status.cpp %TSRC% /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X64 /OUT:out\stand\stand_status.exe %TLIBS% iphlpapi.lib
if errorlevel 1 ( echo [ERROR] stand_status build failed. & exit /b 1 )

rem rev.3: reviewer end-to-end stand adapted to bind/Authenticated (stand\review_regress\e2e_r3.cpp)
if not exist obj\tools\e2e_r3 mkdir obj\tools\e2e_r3
cl %CFLAGS% /I stand /Fo:obj\tools\e2e_r3\ /Fd:obj\tools\e2e_r3\vc.pdb stand\review_regress\e2e_r3.cpp %TSRC% /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X64 /OUT:out\stand\e2e_r3.exe %TLIBS%
if errorlevel 1 ( echo [ERROR] e2e_r3 build failed. & exit /b 1 )

rem EAC 8.6 (2026-10-16): reviewer R3 end-to-end stand (real P61+P73 in AsdaPatch.dll, client AsdaSecure copy) - stand\review_regress_r3
call stand\review_regress_r3\build_r3.bat
if errorlevel 1 ( echo [ERROR] review_regress_r3 build failed. & exit /b 1 )

echo [5/6] EOS SDK runtime...
copy /y "%EOSSDK%\Bin\EOSSDK-Win64-Shipping.dll" out\ >nul || exit /b 1
copy /y "%EOSSDK%\Bin\EOSSDK-Win64-Shipping.dll" out\stand\ >nul || exit /b 1
copy /y config\EacServer.ini out\EacServer.ini.sample >nul

echo [6/6] Done:
dir /b out\*.exe out\*.dll out\stand\*.exe

if /i "%~1"=="test" (
  call stand\run_stands.bat
  exit /b !errorlevel!
)
endlocal
