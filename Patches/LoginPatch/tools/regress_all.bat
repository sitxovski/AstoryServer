@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Regress LoginPatch: build DLL, unit tests L01/L02-L03/L04/L04c/L06, host_load,
rem  and the L08 stand on the live image (5 modes). Exit 0 = all green.
rem  ASCII-only on purpose: cmd.exe reads .bat in the OEM codepage.
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0.."
call "%~dp0..\build.bat" >nul || (echo [FAIL] build.bat & exit /b 1)
set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat"
  )
)
call "!VCVARS!" >nul || exit /b 1
set FAIL=0
set "C=cl /nologo /utf-8 /EHa /MT /I src /I ..\AsdaPatch\src /Fo:obj\"
set "O=obj\Config.obj obj\Log.obj obj\Hook.obj user32.lib kernel32.lib"
%C% tools\test_l01.cpp obj\l01_login_log_mask.obj %O% /Fe:obj\test_l01.exe >nul || set FAIL=1
%C% tools\test_l23.cpp obj\l02_login_sql_log_mask.obj obj\l03_login_sql_refuse.obj obj\l06_login_mac.obj %O% /Fe:obj\test_l23.exe >nul || set FAIL=1
%C% tools\test_l04.cpp obj\l04_login_identity.obj %O% /Fe:obj\test_l04.exe >nul || set FAIL=1
%C% tools\test_l04c.cpp obj\l04_login_identity.obj %O% /Fe:obj\test_l04c.exe >nul || set FAIL=1
%C% tools\test_l06.cpp obj\l06_login_mac.obj obj\l03_login_sql_refuse.obj %O% /Fe:obj\test_l06.exe /link /BASE:0x30000000 /FIXED /DYNAMICBASE:NO >nul || set FAIL=1
rem 21.11.2026 (L09, review 43b N-2): L09 asks L04 whether the L04c trampoline is installed - link l04 too
%C% tools\test_l09.cpp obj\l09_login_maintenance.obj obj\l04_login_identity.obj %O% /Fe:obj\test_l09.exe >nul || set FAIL=1
cl /nologo /EHa /MT /Fo:obj\ tools\host_load.cpp /Fe:obj\host_load.exe >nul || set FAIL=1
if %FAIL% neq 0 (echo [FAIL] test build & exit /b 1)
for %%T in (test_l01 test_l23 test_l04 test_l04c test_l06 test_l09) do (
  obj\%%T.exe > obj\%%T.log 2>&1
  rem 21.11.2026 (L09): the old ">= 1" errorlevel test missed crashes - exit code 0xC0000005 is negative; compare with 0 instead
  if !errorlevel! neq 0 (echo [FAIL] %%T & set FAIL=1) else (echo [OK]   %%T)
)
obj\host_load.exe out\LoginPatch.dll > obj\host_load.log 2>&1
if !errorlevel! neq 0 (echo [FAIL] host_load & set FAIL=1) else (echo [OK]   host_load)
call tools\stand_l08\build_stand.bat >nul || (echo [FAIL] stand build & exit /b 1)
for %%M in (on off parts mismatch all) do (
  tools\stand_l08\stand_l08.exe out\LoginManager.exe.loginpatch.exe out\LoginPatch.dll %%M > tools\stand_l08\run_%%M.log 2>&1
  if !errorlevel! neq 0 (echo [FAIL] stand_l08 %%M & set FAIL=1) else (echo [OK]   stand_l08 %%M)
)
call tools\stand_l09\build_stand.bat >nul || (echo [FAIL] stand_l09 build & exit /b 1)
for %%M in (on off mismatch worldmismatch badcfg badcode noworld all) do (
  tools\stand_l09\stand_l09.exe out\LoginManager.exe.loginpatch.exe out\LoginPatch.dll %%M > tools\stand_l09\run_%%M.log 2>&1
  if !errorlevel! neq 0 (echo [FAIL] stand_l09 %%M & set FAIL=1) else (echo [OK]   stand_l09 %%M)
)
if %FAIL% neq 0 (echo === REGRESS: FAIL === & exit /b 1)
echo === REGRESS: ALL OK ===
endlocal
