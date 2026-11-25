@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Reviewer R3 end-to-end stand (copied from Reports\anticheat\eac\review_r3\e2e, EAC 8.6, 2026-10-16). ASCII only.
rem    out\stand\e2e_r3rev.exe        x64: server AsdaSecure (15901 client) + CLIENT AsdaSecure copy (game connection)
rem    out\stand\r3host\stand_r3host.exe  x86: stock GameServer image + real AsdaPatch.dll (P61 + P73)
rem  Run: out\stand\e2e_r3rev.exe <GameServer.exe> <AsdaPatch.dll> <AsdaPatch.map> <out\stand\r3host\stand_r3host.exe>
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "VSB=%ProgramFiles%\Microsoft Visual Studio\2022"
set "VC="
for %%E in (Community Professional Enterprise BuildTools) do if exist "%VSB%\%%E\VC\Auxiliary\Build\vcvars64.bat" set "VC=%VSB%\%%E\VC\Auxiliary\Build"
if not defined VC ( echo [ERROR] VS2022 not found & exit /b 1 )
set "SRV=%~dp0..\.."
set "SEC=%~dp0..\..\..\Patches\AsdaSecure\src"
set "CLI=%~dp0..\..\..\..\AstoryClient\Source\AsdaNet\Private\Secure"
if not exist "%CLI%\AsdaSecure.cpp" ( echo [ERROR] client AsdaSecure copy not found: %CLI% & exit /b 1 )
set "OBJ=%SRV%\obj\tools\r3rev"
if not exist "%OBJ%\obj64" mkdir "%OBJ%\obj64"
if not exist "%OBJ%\obj64c" mkdir "%OBJ%\obj64c"
if not exist "%OBJ%\obj32" mkdir "%OBJ%\obj32"
if not exist "%SRV%\out\stand\r3host" mkdir "%SRV%\out\stand\r3host"
call "%VC%\vcvars64.bat" >nul || exit /b 1
rem client copy compiled as-is, namespace renamed by preprocessor, UE shims empty
cl /nologo /c /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /DWIN32 /D_WIN32_WINNT=0x0A00 /DAsdaSecure=AsdaSecureCli /I shim /I "%CLI%" /Fo:"%OBJ%\obj64c\\" "%CLI%\AsdaSecure.cpp" "%CLI%\AsdaChannel.cpp" cli_wrap.cpp
if errorlevel 1 exit /b 1
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /DWIN32 /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /I "%SRV%\src" /I "%SRV%\stand" /I "%SEC%" /Fo:"%OBJ%\obj64\\" e2e_r3rev.cpp "%SRV%\src\Crypto.cpp" "%SRV%\src\Json.cpp" "%SRV%\src\Jwt.cpp" "%SRV%\src\Log.cpp" "%SEC%\AsdaSecure.cpp" "%SEC%\AsdaChannel.cpp" "%OBJ%\obj64c\AsdaSecure.obj" "%OBJ%\obj64c\AsdaChannel.obj" "%OBJ%\obj64c\cli_wrap.obj" /link /SUBSYSTEM:CONSOLE /OUT:"%SRV%\out\stand\e2e_r3rev.exe" ws2_32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
endlocal & setlocal
set "VSB=%ProgramFiles%\Microsoft Visual Studio\2022"
for %%E in (Community Professional Enterprise BuildTools) do if exist "%VSB%\%%E\VC\Auxiliary\Build\vcvars32.bat" set "VC=%VSB%\%%E\VC\Auxiliary\Build"
call "%VC%\vcvars32.bat" >nul || exit /b 1
cd /d "%~dp0"
set "SRV=%~dp0..\.."
set "OBJ=%SRV%\obj\tools\r3rev"
cl /nologo /utf-8 /std:c++17 /W3 /O1 /MT /EHa /D_CRT_SECURE_NO_WARNINGS /Fo:"%OBJ%\obj32\\" stand_r3host.cpp /link /BASE:0x30000000 /FIXED /DYNAMICBASE:NO /SUBSYSTEM:CONSOLE /OUT:"%SRV%\out\stand\r3host\stand_r3host.exe" kernel32.lib user32.lib ws2_32.lib
if errorlevel 1 exit /b 1
echo BUILD R3 OK
endlocal
