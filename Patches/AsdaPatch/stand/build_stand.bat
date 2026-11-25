@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem Build stand_p73.exe (x86 stand for P73 EAC bridge: codec, KICK queue, LOGIN/LOGOUT sites, fake sidecar over TCP).
rem ASCII-only on purpose: cmd.exe reads .bat in the OEM codepage.
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars32.bat"
  )
)
if not defined VCVARS (
  echo [ERROR] vcvars32.bat not found
  exit /b 1
)
call "!VCVARS!" >nul || exit /b 1
if not exist obj mkdir obj
if not exist ConfigSet mkdir ConfigSet
cl /nologo /utf-8 /std:c++17 /W3 /O1 /MT /EHa /D_CRT_SECURE_NO_WARNINGS /Fo:obj\ stand_p73.cpp ^
   /link /BASE:0x30000000 /FIXED /DYNAMICBASE:NO /SUBSYSTEM:CONSOLE /OUT:stand_p73.exe kernel32.lib user32.lib
if errorlevel 1 exit /b 1
echo Done: %~dp0stand_p73.exe
endlocal
