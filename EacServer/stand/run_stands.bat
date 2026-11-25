@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Run all AsdaEacServer stands (a)(b)(c) + (e) e2e_r3 + (f) e2e_r3rev + (d) --no-eos / --eos-smoke without secrets.
rem  Each stand starts out\stand\AsdaEacServer_stand.exe itself (ports 18444-18446, 25701-25722).
rem  Exit code 0 = all passed.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0..\out\stand"
set FAIL=0
set "SMOKE=%CD%\run\smoke"

echo.
echo ===== (a) stand_asdaid =====
"%CD%\stand_asdaid.exe" || set FAIL=1
echo.
echo ===== (b) stand_bridge =====
"%CD%\stand_bridge.exe" || set FAIL=1
echo.
echo ===== (c) stand_sidecar =====
"%CD%\stand_sidecar.exe" || set FAIL=1

echo.
echo ===== (g) stand_status: A6.8 admin status endpoint 127.0.0.1 =====
"%CD%\stand_status.exe" || set FAIL=1

echo.
echo ===== (h) stand_cases: 23 Mode=1 decisions of 2026-11-22 replayed in Mode=2 (D1-D4) =====
"%CD%\stand_cases.exe" || set FAIL=1

echo.
echo ===== (e) e2e_r3: reviewer end-to-end stand, rev.3 (S0 real P73 w73 if present) =====
set "GSI=%~dp0..\..\..\reports\anticheat\eac\review_e1\img\gs_stock.exe"
set "P73DLL=%~dp0..\..\_archive_waves\AsdaPatch_w73\out\AsdaPatch.dll"
set "P73HOST=%~dp0..\..\..\reports\anticheat\eac\review_e1\e2e\bin\stand_e2e.exe"
if exist "%P73HOST%" if not exist "%CD%\s0p73" mkdir "%CD%\s0p73"
if exist "%P73HOST%" copy /y "%P73HOST%" "%CD%\s0p73\" >nul
if exist "%GSI%" if exist "%P73DLL%" if exist "%CD%\s0p73\stand_e2e.exe" (
  "%CD%\e2e_r3.exe" "%GSI%" "%P73DLL%" "%CD%\s0p73\stand_e2e.exe" || set FAIL=1
) else (
  "%CD%\e2e_r3.exe" || set FAIL=1
)

echo.
echo ===== (f) e2e_r3rev: reviewer R3 e2e, real P61+P73 in PRODUCTION AsdaPatch.dll; A-E + EAC 8.6 F/F2 (R3-01), G (R3-03), H (R3-04) =====
set "APD=%~dp0..\..\Patches\AsdaPatch\out\AsdaPatch.dll"
set "APM=%~dp0..\..\Patches\AsdaPatch\out\AsdaPatch.map"
if exist "%GSI%" if exist "%APD%" if exist "%CD%\r3host\stand_r3host.exe" (
  "%CD%\e2e_r3rev.exe" "%GSI%" "%APD%" "%APM%" "%CD%\r3host\stand_r3host.exe" || set FAIL=1
) else (
  echo [FAIL] e2e_r3rev: GameServer image, AsdaPatch.dll or stand_r3host.exe not found & set FAIL=1
)

echo.
echo ===== (d) --eos-smoke without secrets must refuse cleanly (exit 2) =====
if not exist "%SMOKE%" mkdir "%SMOKE%"
> "%SMOKE%\EacServer.ini" echo [General]
>> "%SMOKE%\EacServer.ini" echo LogDir=%SMOKE%\logs
>> "%SMOKE%\EacServer.ini" echo [Secrets]
>> "%SMOKE%\EacServer.ini" echo EosJson=%SMOKE%\no_such_eos.json
..\AsdaEacServer.exe --eos-smoke --config "%SMOKE%\EacServer.ini"
if errorlevel 3 ( echo [FAIL] eos-smoke: unexpected code & set FAIL=1 ) else if errorlevel 2 ( echo [ OK ] eos-smoke refused: no secrets ^(check on E2^) ) else ( echo [FAIL] eos-smoke returned 0 or 1 & set FAIL=1 )

echo.
if %FAIL%==0 ( echo ALL STANDS PASSED ) else ( echo SOME STANDS FAILED )
exit /b %FAIL%
