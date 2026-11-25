@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem Astory Server - install prerequisites (see README.md next to this file). Arguments: -Server, -Yes
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_prerequisites.ps1" %*
echo.
pause
