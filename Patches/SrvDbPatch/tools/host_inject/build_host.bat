@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
setlocal enabledelayedexpansion
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
cl /nologo /utf-8 /O1 /MT host_inject.cpp /Fe:host_inject_plain.exe /link /BASE:0x400000 /FIXED /DYNAMICBASE:NO /FILEALIGN:4096 kernel32.lib user32.lib
endlocal
