@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem build.bat — сборка AsdaLogDrop.exe (csc .NET Framework 4.x, C# 5; без внешних зависимостей) в out\
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%~dp0out" mkdir "%~dp0out"
"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ /warnaserror+ /utf8output /codepage:65001 ^
  /r:System.dll /r:System.Core.dll /r:System.Data.dll /r:System.Numerics.dll /r:System.ServiceProcess.dll ^
  /out:"%~dp0out\AsdaLogDrop.exe" "%~dp0src\AsdaLogDrop.cs"
exit /b %ERRORLEVEL%
