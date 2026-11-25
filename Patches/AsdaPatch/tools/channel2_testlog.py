# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# channel2_testlog.py — разбор живого теста второго полевого канала (26.10.2026; PLAN Reports/channel2/PLAN.md §9).
# ТОЛЬКО ЧТЕНИЕ сервера по SSH (без шары \\@@ASTORY_SERVER_HOSTNAME@@). Собирает в один отчёт всё, по чему видно, прошли ли вход в канал 2 и
# смена 1↔2 (6084 → 6016/6017 через ChannelManager → 6015 → вход 5058 на GS цели):
#   1. БД: dbo.LogInfo учётки (входы/выходы по времени), Joy1 CharPos (Channel / CPoridx / UserNum / State) и Charinpos,
#      SameUser по каналам; журнал P53 (joylog1.ac.*) — строки учётки и сводка по server_name (Ch2_GameServer = канал 2);
#   2. EAC (EacServer\logs\eac_<дата>.log): LOGIN / LOGOUT / REBIND / KICK учётки — по какому GS (pid) шёл вход;
#   3. журналы GameServer × 3 (Log\…_<дата>.txt) — строки с ником / UserIndex, сбои портала и смены канала;
#      RelayServer × 3 и ChannelManager (Error_Log, Log_IocpNet) — строки JumpNearPlayer / SendError / Exception (маршрут 6016/6017);
#   4. PatchLog (AsdaPatch × 3 GS, DBPatch) — отказы P50 / P47 / P73 / кики после --since.
# Запуск: python channel2_testlog.py --user 75210 --since "2026-10-26 19:30" [--char <ник>] [--until "..."]
# Итог: Reports/channel2/test_<дата-время>.md (+ краткая сводка в консоль). Без побочных эффектов при импорте.
import argparse
import datetime as dt
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout as L          # noqa: E402
from stack_parity import run_ps   # noqa: E402  (длинный PS-скрипт — файлом)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "channel2"))

# Признаки маршрута смены канала и входа в журналах стоковых серверов (строки из декомпилов RelayServer.c / ChannelManager.c /
# GameServer.c: Process_GM_JumpNearPlayer_*, GetConnectSockIndex, Recv_UserChannelMove, portal …).
ROUTE_WORDS = ["JumpNearPlayer", "GetConnectSockIndex", "GetChattingSockIndex", "GetGameServerThreadIndexByMapIndex",
               "UserChannelMove", "ChannelMove", "SendError", "Exception"]
PATCH_WORDS = ["P50", "P47", "P73", "P48", "P54", "ОТКАЗ", "KICK", "кик", "4101", "MISMATCH", "FAIL"]


def ps_q(s):
    return "'" + s.replace("'", "''") + "'"


def sql_block(user, since, until):
    """SQL-сводка (только SELECT) — sqlcmd на сервере."""
    return r"""
SET NOCOUNT ON;
PRINT '## LogInfo (joylog1)';
SELECT idx, Seridx, Charidx, IpAddress, CONVERT(varchar(23), Login, 121) AS Login, CONVERT(varchar(23), Logout, 121) AS Logout, State
FROM joylog1.dbo.LogInfo WHERE Userindex = %(u)d AND (Login >= '%(s)s' OR Logout >= '%(s)s') AND Login < '%(t)s' ORDER BY idx;
PRINT '## CharPos (Joy1) — Channel 0 = канал 1, 1 = канал 2, 3 = Indun';
SELECT p.Charidx, c.Charname, p.Channel, p.CPoridx, p.UserNum, p.State FROM Joy1.dbo.CharPos p
  JOIN Joy1.dbo.Charinfo c ON c.Userindex = p.Userindex AND c.Charidx = p.Charidx WHERE p.Userindex = %(u)d;
PRINT '## Charinpos (Joy1) — адрес и порт последнего GS';
SELECT Charidx, Channel, Poridx, Ipaddress, Port, Posx, Posy FROM Joy1.dbo.Charinpos WHERE Userindex = %(u)d;
PRINT '## SameUser (Joy1) — онлайн по каналам';
SELECT Channel, SUM(JoinCount) AS JoinCount, CONVERT(varchar(19), MAX(Edate), 120) AS LastUpdate FROM Joy1.dbo.SameUser GROUP BY Channel ORDER BY Channel;
PRINT '## P53 журнал: строки по server_name после --since (все таблицы ac.*)';
DECLARE @q nvarchar(max) = N'';
SELECT @q = @q + N'SELECT ''' + t.name + N''' AS tbl, server_name, COUNT(*) AS n FROM joylog1.ac.' + QUOTENAME(t.name)
  + N' WHERE ev_local >= ''%(s)s'' AND ev_local < ''%(t)s'' GROUP BY server_name UNION ALL '
FROM joylog1.sys.tables t JOIN joylog1.sys.schemas sc ON sc.schema_id = t.schema_id
WHERE sc.name = 'ac' AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'ev_local')
  AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'server_name');
IF LEN(@q) > 0 BEGIN SET @q = LEFT(@q, LEN(@q) - 10) + N' ORDER BY 1, 2'; EXEC (@q); END
PRINT '## P53 журнал: строки учётки';
SET @q = N'';
SELECT @q = @q + N'SELECT TOP 50 ''' + t.name + N''' AS tbl, CONVERT(varchar(19), ev_local, 120) AS ev, server_name, server_port FROM joylog1.ac.'
  + QUOTENAME(t.name) + N' WHERE user_index = %(u)d AND ev_local >= ''%(s)s'' AND ev_local < ''%(t)s'' UNION ALL '
FROM joylog1.sys.tables t JOIN joylog1.sys.schemas sc ON sc.schema_id = t.schema_id
WHERE sc.name = 'ac' AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'user_index')
  AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'ev_local')
  AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'server_port');
IF LEN(@q) > 0 BEGIN SET @q = LEFT(@q, LEN(@q) - 10) + N' ORDER BY 2'; EXEC (@q); END
""" % {"u": user, "s": since.strftime("%Y-%m-%dT%H:%M:%S"), "t": until.strftime("%Y-%m-%dT%H:%M:%S")}   # ISO 8601 — не зависит от языка сервера


def build_ps(user, since, until, needles):
    days = sorted({since.date() + dt.timedelta(days=i) for i in range((until.date() - since.date()).days + 1)})
    stamps = [d.strftime("%Y%m%d") for d in days]
    gs = L.GS_FOLDERS
    route_dirs = L.RELAY_FOLDERS + ["ChannelManager"]
    sql = sql_block(user, since, until).replace("'", "''")
    return r"""
$ErrorActionPreference = 'Continue'
$v2 = %(v2)s; $since = [datetime]%(since)s; $until = [datetime]%(until)s
$stamps = @(%(stamps)s); $needles = @(%(needles)s); $route = @(%(route)s); $patchw = @(%(patchw)s)
function Read-Shared([string]$p) { try { $fs = New-Object IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $b = New-Object byte[] $fs.Length; [void]$fs.Read($b, 0, $b.Length); $fs.Close()
  $t = [Text.Encoding]::UTF8.GetString($b); if ($t.Contains([char]0xFFFD)) { $t = [Text.Encoding]::GetEncoding(1251).GetString($b) }; $t } catch { '' } }
function Test-AnyWord([string]$l, $words) { foreach ($w in $words) { if ($l.IndexOf($w, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }; $false }
# время строки: GameServer «… HH hou MM min SS sec :», Relay/CM «<tick>\tHH:MM:SS:mmm->»; день — из имени файла (yyyyMMdd)
function Get-FileDay($f) { $m = [regex]::Match($f.Name, '(20\d{6})'); if ($m.Success) { [datetime]::ParseExact($m.Groups[1].Value, 'yyyyMMdd', $null) } else { $f.LastWriteTime.Date } }
function Test-InWindow([string]$l, [datetime]$day) {
  $m = [regex]::Match($l, '(\d\d) hou (\d\d) min (\d\d) sec'); if (-not $m.Success) { $m = [regex]::Match($l, '\t(\d\d):(\d\d):(\d\d):\d+->') }
  if (-not $m.Success) { return $true }
  $ts = $day.AddHours([int]$m.Groups[1].Value).AddMinutes([int]$m.Groups[2].Value).AddSeconds([int]$m.Groups[3].Value)
  return ($ts -ge $since -and $ts -lt $until) }
Write-Output '# SQL'
sqlcmd -S localhost\SQLEXPRESS -E -y 40 -Q %(sql)s
Write-Output '# EAC'
foreach ($s in $stamps) { $f = Join-Path $v2 ('EacServer\logs\eac_' + $s.Substring(0,4) + $s.Substring(4,2) + $s.Substring(6,2) + '.log')
  if (Test-Path -LiteralPath $f) { foreach ($l in ((Read-Shared $f) -split "`n")) {
    if ($l.Length -ge 19) { $ts = [datetime]::MinValue; if ([datetime]::TryParse($l.Substring(0,19), [ref]$ts) -and $ts -ge $since -and $ts -lt $until -and
        ((Test-AnyWord $l $needles) -or $l -match '\] HELLO ') -and $l -notmatch '\[main\] статистика') { Write-Output ('EAC| ' + $l.TrimEnd()) } } } } }
Write-Output '# GS'
foreach ($d in @(%(gs)s)) { $root = Join-Path $v2 ($d + '\Log')
  Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $nm = $_.Name; $_.LastWriteTime -ge $since -and @($stamps | Where-Object { $nm -like ('*' + $_ + '*') }).Count -gt 0 -and $_.FullName -notlike '*\Log_Patch\*' } | ForEach-Object {
    $f = $_; $n = 0; $day = Get-FileDay $f; foreach ($l in ((Read-Shared $f.FullName) -split "`n")) { if (((Test-AnyWord $l $needles) -or (Test-AnyWord $l $route)) -and (Test-InWindow $l $day)) {
      $n++; if ($n -le 60) { Write-Output ('GS|' + $d + '|' + $f.FullName.Substring($root.Length + 1) + '| ' + $l.TrimEnd()) } } }
    if ($n -gt 60) { Write-Output ('GS|' + $d + '|' + $f.Name + '| … ещё ' + ($n - 60) + ' строк') } } }
Write-Output '# ROUTE'
foreach ($d in @(%(rd)s)) { $root = Join-Path $v2 $d
  Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since -and $_.FullName -notlike '*\PatchLog\*' -and $_.Extension -match 'txt|log' } | ForEach-Object {
    $f = $_; $n = 0; $day = Get-FileDay $f; foreach ($l in ((Read-Shared $f.FullName) -split "`n")) { if ((Test-AnyWord $l $route) -and (Test-InWindow $l $day)) {
      $n++; if ($n -le 40) { Write-Output ('RT|' + $d + '|' + $f.FullName.Substring($root.Length + 1) + '| ' + $l.TrimEnd()) } } }
    if ($n -gt 40) { Write-Output ('RT|' + $d + '|' + $f.Name + '| … ещё ' + ($n - 40) + ' строк') } } }
Write-Output '# PATCH'
foreach ($d in @(%(gs)s) + @('DBManager')) { foreach ($s in $stamps) { $f = Join-Path $v2 ($d + '\Log\Log_Patch\PatchLog_' + $s + '.txt')
  if (Test-Path -LiteralPath $f) { $day = [datetime]::ParseExact($s, 'yyyyMMdd', $null)
    foreach ($l in ((Read-Shared $f) -split "`n")) { if ($l -match '^\[(\d\d):(\d\d):(\d\d)\]') {
      $ts = $day.AddHours([int]$matches[1]).AddMinutes([int]$matches[2]).AddSeconds([int]$matches[3]); if ($ts -lt $since -or $ts -ge $until) { continue } }
      # регистр важен: стартовые строки патчей содержат «штатный отказ» строчными — это не событие
      # стартовый блок патчей (описания с отступом и строки [OK]) — не события
      if ($l -match '^\[\d\d:\d\d:\d\d\]\s{3,}' -or $l -match '\[OK\]') { continue }
      if ((Test-AnyWord $l $needles) -or $l -cmatch 'ОТКАЗ|KICK|MISMATCH|\[FAIL') { Write-Output ('PL|' + $d + '| ' + $l.TrimEnd()) } } } } }
Write-Output '# END'
""" % {"v2": ps_q(V2), "since": ps_q(since.strftime("%Y-%m-%d %H:%M:%S")), "until": ps_q(until.strftime("%Y-%m-%d %H:%M:%S")),
       "stamps": ",".join(ps_q(s) for s in stamps), "needles": ",".join(ps_q(n) for n in needles),
       "route": ",".join(ps_q(w) for w in ROUTE_WORDS), "patchw": ",".join(ps_q(w) for w in PATCH_WORDS),
       "sql": "'" + sql + "'", "gs": ",".join(ps_q(d) for d in gs), "rd": ",".join(ps_q(d) for d in route_dirs)}


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Разбор живого теста канала 2 (только чтение по SSH)")
    ap.add_argument("--user", type=int, required=True, help="UserIndex учётки игрока")
    ap.add_argument("--since", required=True, help="начало окна 'YYYY-MM-DD HH:MM'")
    ap.add_argument("--until", help="конец окна (по умолчанию сейчас)")
    ap.add_argument("--char", action="append", default=[], help="ник персонажа (можно несколько)")
    a = ap.parse_args(argv)
    since = dt.datetime.strptime(a.since, "%Y-%m-%d %H:%M")
    until = dt.datetime.strptime(a.until, "%Y-%m-%d %H:%M") if a.until else dt.datetime.now() + dt.timedelta(minutes=1)
    needles = [str(a.user)] + a.char
    rc, out, err = run_ps(build_ps(a.user, since, until, needles), timeout=600)
    if "# END" not in out:
        print("ОШИБКА: разбор не дошёл до конца (код %d): %s" % (rc, err.strip()[-500:]))
        return 7
    sec = {"SQL": [], "EAC": [], "GS": [], "ROUTE": [], "PATCH": []}
    cur = None
    for line in out.splitlines():
        if line.startswith("# "):
            cur = line[2:].strip()
            continue
        if cur in sec and line.strip():
            sec[cur].append(line.rstrip())
    stamp = time.strftime("%Y%m%d_%H%M")
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "test_%s.md" % stamp)
    title = {"SQL": "БД: входы, позиция и канал персонажа, онлайн по каналам, журнал P53",
             "EAC": "EAC: события учётки (LOGIN/LOGOUT/REBIND/KICK) и HELLO",
             "GS": "Журналы GameServer (ник / UserIndex / смена канала / сбои)",
             "ROUTE": "Маршрут 6016/6017: RelayServer × 3 и ChannelManager (JumpNearPlayer / SendError / Exception)",
             "PATCH": "Журналы патчей (P50/P47/P73/P48, отказы и кики)"}
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Тест канала 2 — журналы (%s)\n\nУчётка %d%s; окно %s … %s. Собрано channel2_testlog.py (только чтение по SSH).\n"
                % (time.strftime("%Y-%m-%d %H:%M"), a.user, (", ники " + ", ".join(a.char)) if a.char else "",
                   since.strftime("%Y-%m-%d %H:%M"), until.strftime("%Y-%m-%d %H:%M")))
        for k in ("SQL", "EAC", "GS", "ROUTE", "PATCH"):
            f.write("\n## %s (%d строк)\n\n```\n%s\n```\n" % (title[k], len(sec[k]), "\n".join(sec[k]) or "(пусто)"))
    print("отчёт: %s" % path)
    for k in ("SQL", "EAC", "GS", "ROUTE", "PATCH"):
        print("  %-5s строк %d" % (k, len(sec[k])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
