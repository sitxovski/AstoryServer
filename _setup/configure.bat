@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem Astory - one-time setup of the sources for your machines and accounts (see SETUP.md next to this file).
rem Runs configure.ps1; extra arguments are passed through (-NonInteractive, -Check).
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure.ps1" %*
set RC=%errorlevel%
echo.
pause
exit /b %RC%
