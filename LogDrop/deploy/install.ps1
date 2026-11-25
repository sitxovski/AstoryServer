# Copyright (c) 2026 @sitxovski (Discord)
# install.ps1 — развёртывание/обновление службы AsdaLogDrop на dev-сервере (запуск от администратора на сервере).
#   Идемпотентен: повтор — обновление exe/ini. Первая версия каждого файла — рядом *.bak_20261019_logdrop.
#   Системные изменения (все — в README, раздел «Откат»): служба AsdaLogDrop (NT SERVICE\AsdaLogDrop, отложенный автозапуск,
#   перезапуск при сбое, sidtype restricted, только SeChangeNotifyPrivilege), ACL на LogDrop (только Administrators, SYSTEM,
#   служба; снимок прежних ACL — service\acl_before_*.txt), SQL-вход logdrop_ro (пароль — secrets\, sql_login.ps1) + SELECT(Us_id). Брандмауэр не трогается.
param([string]$Stage = '@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_tmp_logdrop_stage')
$ErrorActionPreference = 'Stop'
$V2   = '@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2'
$Root = Join-Path $V2 'LogDrop'
$Svc  = Join-Path $Root 'service'
$Logs = Join-Path $Svc 'logs'
$Name = 'AsdaLogDrop'
$Acct = 'NT SERVICE\AsdaLogDrop'
$Tag  = '.bak_20261019_logdrop'

New-Item -ItemType Directory -Force $Root, $Svc, $Logs | Out-Null
$existing = Get-Service $Name -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service $Name; (Get-Service $Name).WaitForStatus('Stopped', '00:00:30') }
foreach ($f in 'AsdaLogDrop.exe', 'LogDrop.ini', 'README.md', 'sql_login.ps1') {
    $dst = Join-Path $Svc $f
    if ((Test-Path $dst) -and -not (Test-Path ($dst + $Tag))) { Copy-Item $dst ($dst + $Tag) }   # бэкап первой версии
    Copy-Item (Join-Path $Stage $f) $dst -Force
    if ((Get-FileHash $dst).Hash -ne (Get-FileHash (Join-Path $Stage $f)).Hash) { throw "копия разошлась: $f" }
}
$exe = Join-Path $Svc 'AsdaLogDrop.exe'
if (-not $existing) {
    & sc.exe create $Name binPath= $exe start= delayed-auto obj= $Acct DisplayName= 'AsdaReborn LogDrop (client log intake)' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc create: $LASTEXITCODE" }
}
& sc.exe description $Name 'POST /api/v1/ingest behind Caddy; 127.0.0.1:8446; stores sealed client logs in v2\LogDrop' | Out-Null
& sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
# ★ ревизия В6: restricted — токен с ограничением записи: писать можно только туда, где служба указана явно (LogDrop, logs).
& sc.exe sidtype $Name restricted | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc sidtype: $LASTEXITCODE" }
& sc.exe privs $Name SeChangeNotifyPrivilege | Out-Null

# ★ ревизия В6/М5: LogDrop без наследования от v2 — только Administrators, SYSTEM и служба (у Users нет ни чтения, ни
#   создания файлов; шара H:\ открыта Everyone на чтение — NTFS этой папки её закрывает). Снимок прежних ACL — один раз.
$snap = Join-Path $Svc 'acl_before_review.txt'
if (-not (Test-Path $snap)) { & icacls $Root /save $snap /t /q | Out-Null }
& icacls $Root /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' "${Acct}:(OI)(CI)M" /q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls root: $LASTEXITCODE" }
& icacls $Root /remove:g 'BUILTIN\Users' 'CREATOR OWNER' /q | Out-Null
# Папка службы — только чтение и запуск для службы; журналы службы — изменение.
& icacls $Svc /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' "${Acct}:(OI)(CI)RX" /q | Out-Null
& icacls $Svc /remove:g 'BUILTIN\Users' 'CREATOR OWNER' /q | Out-Null
& icacls $Logs /inheritance:e /grant:r "${Acct}:(OI)(CI)M" /q | Out-Null
& icacls $Logs /remove:g 'BUILTIN\Users' 'CREATOR OWNER' /q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls: $LASTEXITCODE" }
# Дочерние папки (учётки/даты) — только наследование от корня.
Get-ChildItem $Root -Directory | Where-Object { $_.Name -ne 'service' } | ForEach-Object { & icacls $_.FullName /reset /t /q | Out-Null }

& (Join-Path $Svc 'sql_login.ps1') | Out-Host                     # SQL-вход logdrop_ro + пароль в secrets\ (★ В6)
# SELECT(Us_id) for logdrop_ro is granted by AstoryServer\Prerequisites\setup_server.ps1

Start-Service $Name
(Get-Service $Name).WaitForStatus('Running', '00:00:30')
Start-Sleep -Seconds 1
Get-Service $Name | Format-List Name, Status, StartType | Out-Host
& netstat -ano | Select-String ':8446 ' | Out-Host
