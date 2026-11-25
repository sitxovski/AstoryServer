@echo off
rem Copyright (c) 2026 @sitxovski (Discord)
rem ---------------------------------------------------------------------------
rem  AsdaSecure — сборка стенда и keygen (x86, static CRT /MT), только Windows CNG.
rem  Требует Visual Studio 2022 с x86-тулсетом. ASCII-only (cmd читает .bat в OEM).
rem  Выход: out\stand_secure.exe, out\keygen.exe
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
echo [1/4] Env: "!VCVARS!"
call "!VCVARS!" >nul || exit /b 1

if not exist out mkdir out
if not exist obj mkdir obj

echo [2/4] Compiling stand...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\ ^
   stand\stand_secure.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_secure.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand build failed. & exit /b 1 )

echo [3/4] Compiling keygen...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\ ^
   keygen\keygen.cpp src\AsdaSecure.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\keygen.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] keygen build failed. & exit /b 1 )

echo [4/5] Compiling stand_wire (client ^<-^> layer ^<-^> old server)...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\ ^
   wire\stand_wire.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_wire.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_wire build failed. & exit /b 1 )

echo [5/7] fix2: stand_b7d_locks (lock order / send order regression, review INTEG3 B-1/B-2)...
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\ ^
   stand\stand_b7d_locks.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_b7d_locks.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_b7d_locks build failed. & exit /b 1 )

echo [6/7] fix2: stand_nocng (bridge with CNG failure, separate obj dir)...
if not exist obj\nocng mkdir obj\nocng
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /DASDAWIRE_STAND_NO_CNG ^
   /I src /Fo:obj\nocng\ ^
   wire\stand_nocng.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_nocng.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_nocng build failed. & exit /b 1 )

echo [7/9] fix2c: stand_limit4096 (stock 0x1000 send/recv buffer limits, review FIX2 N-1)...
if not exist obj\lim mkdir obj\lim
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\lim\ ^
   wire\stand_limit4096.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_limit4096.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_limit4096 build failed. & exit /b 1 )

echo [8/9] fix2c: stand_limit4096_old (same stand against fix2b bridge fixture stand\old_fix2b - must reproduce N-1)...
if not exist obj\limold mkdir obj\limold
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /DSTAND_OLD_BRIDGE ^
   /I stand\old_fix2b /I src /Fo:obj\limold\ ^
   wire\stand_limit4096.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp stand\old_fix2b\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_limit4096_old.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_limit4096_old build failed. & exit /b 1 )

echo [9a] fix2d: stand_backlog (stock send backlog 0x9F9C, client not reading, review FIX2 P-1/P-2)...
if not exist obj\blog mkdir obj\blog
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\blog\ ^
   wire\stand_backlog.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_backlog.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_backlog build failed. & exit /b 1 )

echo [9b] fix2d: stand_backlog_old (same stand against fix2c bridge fixture stand\old_fix2c - must reproduce Replay)...
if not exist obj\blogold mkdir obj\blogold
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /DSTAND_OLD_BRIDGE ^
   /I stand\old_fix2c /I src /Fo:obj\blogold\ ^
   wire\stand_backlog.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp stand\old_fix2c\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_backlog_old.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_backlog_old build failed. & exit /b 1 )

echo [9c] fix2e: reviewer stands (..\..\_archive_waves\AsdaSecure_rev4\stand) against the CURRENT bridge (review fix2d F-1: total cap, bad_alloc)...
if not exist obj\rev4c mkdir obj\rev4c
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\rev4c\ ^
   ..\..\_archive_waves\AsdaSecure_rev4\stand\stand_rev4_fix2c.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_rev4_on_fix2e.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_rev4_on_fix2e build failed. & exit /b 1 )
if not exist obj\rev4d mkdir obj\rev4d
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\rev4d\ ^
   ..\..\_archive_waves\AsdaSecure_rev4\stand\stand_rev4_fix2d.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_rev4_fix2d_on_fix2e.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_rev4_fix2d_on_fix2e build failed. & exit /b 1 )

echo [9d] sec2: stand_sec2 (E-1, E-2 fair share, handshake accel, admission kinds 63-65)...
if not exist obj\sec2 mkdir obj\sec2
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\sec2\ ^
   wire\stand_sec2.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_sec2.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_sec2 build failed. & exit /b 1 )

echo [9e] sec2: stand_sec2_old (same stand against fix2e bridge fixture stand\old_fix2e - must reproduce E-1/E-2)...
if not exist obj\sec2old mkdir obj\sec2old
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /DSTAND_OLD_BRIDGE ^
   /I stand\old_fix2e /I src /Fo:obj\sec2old\ ^
   wire\stand_sec2.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp stand\old_fix2e\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_sec2_old.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_sec2_old build failed. & exit /b 1 )

echo [9f] sec2: stand_perf (performance; arg noaccel = old handshake path)...
if not exist obj\perf mkdir obj\perf
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\perf\ ^
   wire\stand_perf.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_perf.exe bcrypt.lib ws2_32.lib
if errorlevel 1 ( echo [ERROR] stand_perf build failed. & exit /b 1 )

echo [9g] sec2b: reviewer stand rev5 (..\..\_archive_waves\AsdaSecure_rev5\stand) against the CURRENT bridge (review SEC2 C-1: must not reproduce)...
if not exist obj\rev5 mkdir obj\rev5
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /I ..\..\_archive_waves\AsdaSecure_rev5\stand /Fo:obj\rev5\ ^
   ..\..\_archive_waves\AsdaSecure_rev5\stand\stand_rev5.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_rev5_on_sec2b.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_rev5_on_sec2b build failed. & exit /b 1 )

echo [9h] EAC red3: stand_bind (channel binding exporter, CONTRACT 8.1; vector tools\gen_bind_vector.py)...
if not exist obj\bind mkdir obj\bind
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS ^
   /I src /Fo:obj\bind\ ^
   stand\stand_bind.cpp src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_bind.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_bind build failed. & exit /b 1 )

echo [9i] EAC red3: stand_bind_keys_old (keys-only checks against pre-red3 AsdaSecure fixture stand\old_red2 - keys must be identical)...
if not exist obj\bindold mkdir obj\bindold
cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /DSTAND_NO_BIND ^
   /I stand\old_red2 /Fo:obj\bindold\ ^
   stand\stand_bind.cpp stand\old_red2\AsdaSecure.cpp stand\old_red2\AsdaChannel.cpp ^
   /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /MACHINE:X86 ^
   /OUT:out\stand_bind_keys_old.exe bcrypt.lib
if errorlevel 1 ( echo [ERROR] stand_bind_keys_old build failed. & exit /b 1 )

echo [9/9] Done:out\stand_secure.exe, out\keygen.exe, out\stand_wire.exe, out\stand_b7d_locks.exe, out\stand_nocng.exe, out\stand_limit4096*.exe, out\stand_backlog*.exe, out\stand_rev4_*_on_fix2e.exe, out\stand_sec2*.exe, out\stand_perf.exe, out\stand_rev5_on_sec2b.exe
dir /b out\*.exe
endlocal
