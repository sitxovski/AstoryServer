@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  Build DBPatch.dll (x86, static CRT) - patches for DBManager.exe ONLY.
rem  Requires Visual Studio 2022 (Community or Build Tools) with the x86 toolset.
rem  Output: out\DBPatch.dll
rem
rem  Shared sources (Log, Hook, Patches.h) are reused from ..\AsdaPatch\src to
rem  avoid a second copy drifting away. Config.cpp / Registry.cpp / dllmain.cpp
rem  are LOCAL: this DLL has its own ini (dbpatch.ini) and its own patch list.
rem  Include order matters: src first, so our Config.h wins over AsdaPatch's.
rem  (ASCII-only on purpose: cmd.exe reads .bat in the OEM codepage)
rem  P125 (15.11.2026): + ..\DbReconnect\src\DbReconnectCore.cpp, ole32/oleaut32.
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
echo [1/3] Env: "!VCVARS!"
call "!VCVARS!" >nul || exit /b 1

if not exist out mkdir out
if not exist obj mkdir obj

echo [2/3] Compiling...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /GS- /EHa /D_CRT_SECURE_NO_WARNINGS ^
   /DWIN32 /D_WINDOWS /D_USRDLL ^
   /I src /I ..\AsdaPatch\src /I ..\AsdaPatch\src\patches /I ..\DbReconnect\src ^
   /Fo:obj\ ^
   src\dllmain.cpp src\Config.cpp src\Registry.cpp src\p22_db_fame_high.cpp ^
   src\p23_db_title_rank.cpp src\p26_soulmate_note_sqli.cpp src\p28_sql_arg_escape.cpp ^
   src\p37_craft_level_scroll_code.cpp ^
   src\p50_identity_check.cpp src\p53_ac_journal_db.cpp src\p78_soulmate_share_portal.cpp src\p85_db_post_rows.cpp src\p96_db_shell_rows.cpp src\p125_db_reconnect.cpp ^
   ..\DbReconnect\src\DbReconnectCore.cpp ^
   ..\AsdaPatch\src\Log.cpp ..\AsdaPatch\src\Hook.cpp ..\AsdaPatch\src\AcJournal.cpp ^
   /link /DLL /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\DBPatch.dll kernel32.lib user32.lib ole32.lib oleaut32.lib
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo [3/3] Done: %~dp0out\DBPatch.dll
dir /b out\DBPatch.dll
endlocal
