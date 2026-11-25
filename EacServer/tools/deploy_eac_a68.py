# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""deploy_eac_a68.py — ВЫКЛАДКА / ПРОВЕРКА / ОТКАТ AsdaEacServer с точкой статуса для админ-центра (★ А6.8, вторая часть, 22.11.2026).

Что меняется на сервере (@@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\EacServer):
  * AsdaEacServer.exe — сборка с src/AdminStatus.cpp (закреплённая копия tools/a68_data/AsdaEacServer_a68_<md5>.exe, md5 = WANT_EXE);
    допустимая прежняя — PREV_EXE (живая с 17.10.2026 18:35);
  * EacServer.ini — дописывается секция [AdminStatus] Enabled=1, Port=8447, SecretFile=secrets\\admin_status.key (если её нет; ASCII);
  * secrets\\admin_status.key — общий секрет точки (64 hex, создаётся НА СЕРВЕРЕ, если файла нет; по сети не идёт, не печатается), его копия —
    @@ASTORY_SERVER_ROOT_ESC@@\\AdminCenter\\secrets\\eac_status.key (секрет службы панели; права — наследуются от папок secrets: SYSTEM, Administrators);
  * рестарт службы AsdaEacServer. Игроков он не выкидывает и KICK не даёт (EacServer Mode=1 — KICK в P73 не шлётся вовсе, Core.cpp
    Punish; FailOpenStartupSec=120; P73 переподключается сам с паузой ≤ 5 с и шлёт снимок LOGIN; клиент Astory переподключает канал
    15901 сам — AsdaEacFlow.cpp LoseChannel), но объявления для рестарта службы EAC у announce_restart.py нет — поэтому --apply
    отказывает, если в игре кто-то есть (соединения ESTABLISHED на клиентских портах LoginManager и GameServer).

  python deploy_eac_a68.py              — сухой прогон: что на сервере сейчас и что будет сделано (ничего не меняет)
  python deploy_eac_a68.py --apply      — выкладка (бэкап на сервере и локально, md5, рестарт службы, проверка); сбой старта — откат сам
  python deploy_eac_a68.py --check      — проверка после выкладки (служба, md5, слушатели, /status лаунчера, точка статуса с ключом и без,
                                          не отвечает снаружи, мост P73 трёх GameServer переподключился)
  python deploy_eac_a68.py --rollback   — прежний exe из бэкапа и рестарт службы (секция [AdminStatus] остаётся: прежний exe её не читает)
  --help / -h — эта справка; неизвестный ключ — код 1 без действий.
Журнал — tools/run_a68_deploy/deploy.log. Побочных эффектов при импорте нет.
"""
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PATCH_TOOLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "Patches", "AsdaPatch", "tools")
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
EAC_DIR = V2 + r"\EacServer"
EXE = EAC_DIR + r"\AsdaEacServer.exe"
INI = EAC_DIR + r"\EacServer.ini"
SECRET = EAC_DIR + r"\secrets\admin_status.key"
PANEL_SECRET = r"@@ASTORY_SERVER_ROOT@@\AdminCenter\secrets\eac_status.key"
SERVICE = "AsdaEacServer"
WANT_EXE = "9ac8d95325b06bf4da8ec9faad1a24db"   # ★ ревизия 68: агрегаты поблажки (окна по 24 ч, расход по минутам), согласование ключей, строгий DACL
PREV_EXE = {"154d3d2747f35f8eb687874e01956d57": "AsdaEacServer 17.10.2026 18:35 (GET /status лаунчера), живая до А6.8",
            "a6903cd7ab70645b2b083c23f758c27f": "AsdaEacServer А6.8 22.11.2026 14:15 (до ревизии 61)",
            "37b668cbf70041793a78815b040e4ed8": "AsdaEacServer А6.8 ред. 2 22.11.2026 15:21 (ревизия 61, до Д1–Д4)",
            "8b09e114b810c76237a9a4f5e5dce477": "AsdaEacServer А6.8 ред. 3 22.11.2026 16:13 (Д1–Д4, до ревизии 64)",
            "980bf12dcfe03c66b766ead4fe3e86b2": "AsdaEacServer А6.8 ред. 4 22.11.2026 16:54 (ревизия 64, до ревизии 66)",
            "af5860d97ef028245fb4f54f3085214b": "AsdaEacServer А6.8 ред. 5 22.11.2026 17:45 (ревизия 66, до ревизии 68)",
            "7ccd404a76f55660261979b518cdb9e9": "AsdaEacServer А6.8 ред. 6 22.11.2026 18:32 (ревизия 68, до ревизии 70)"}
BUILT_DIR = os.path.join(HERE, "a68_data")
STATUS_PORT = 8447
INI_SECTION = ("\r\n; A6.8 (2026-11-22): admin-center status endpoint - 127.0.0.1 only, read-only (src/AdminStatus.h); secret - SecretFile\r\n"
               "[AdminStatus]\r\nEnabled=1\r\nPort=%d\r\nSecretFile=secrets\\admin_status.key\r\n" % STATUS_PORT)
SUFFIX = ".bak_20261122_a68r70"                                   # ★ Д1–Д4: прежний exe рядом (р61 — .bak_20261122_a68r61, первая — .bak_20261122_a68)
SRV_BACKUP = V2 + r"\_backup\2026-11-22_a68_eac_r70"              # ★ Д1–Д4: бэкап до этой выкладки (р61 — ..._a68_eac_r61, первая — ..._a68_eac)
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-22_a68_eac/r70/server/v2/EacServer"
GAME_PORTS = (15001, 15601, 15621, 15651)                         # клиентские порты LoginManager и трёх GameServer
GS_FOLDERS = ("GameServer", "Indun_GameServer", "Ch2_GameServer")
RUN_DIR = os.path.join(HERE, "run_a68_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
KNOWN = ("--apply", "--check", "--rollback", "--help", "-h")


def _lib():
    """Общие функции SSH стойки (deploy_p90: ps, q, rmd5, rread, rupload, md5)."""
    if PATCH_TOOLS not in sys.path:
        sys.path.insert(0, PATCH_TOOLS)
    import deploy_p90
    return deploy_p90


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def built_exe():
    """Закреплённая сборка А6.8 (tools/a68_data/AsdaEacServer_a68_<md5[:8]>.exe) или None."""
    p = os.path.join(BUILT_DIR, "AsdaEacServer_a68_%s.exe" % WANT_EXE[:8])
    return p if os.path.isfile(p) else None


def ps_ok(L, script, timeout=180):
    """PowerShell на сервере; код ≠ 0 — исключение с хвостом вывода."""
    rc, out = L.ps(script, timeout=timeout)
    if rc != 0:
        raise RuntimeError("PowerShell по SSH: код %d: %s" % (rc, out[-500:]))
    return out


def players_online(L):
    """Соединений ESTABLISHED на клиентских портах LoginManager и GameServer (кто в игре или входит) — число."""
    out = ps_ok(L, "$n = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { %s -contains $_.LocalPort }).Count; "
                   "Write-Output ('ONLINE=' + $n)" % ("@(" + ",".join(str(p) for p in GAME_PORTS) + ")"))
    m = re.search(r"ONLINE=(\d+)", out)
    if not m:
        raise RuntimeError("число соединений игроков не получено: %s" % out[-300:])
    return int(m.group(1))


def eac_stats(L):
    """Последняя строка «статистика» журнала EacServer (игровые сессии P73, мосты) — текстом или ''."""
    out = ps_ok(L, "$l = Get-ChildItem -LiteralPath %s -Filter 'eac_*.log' | Sort-Object LastWriteTime | Select-Object -Last 1; if ($l) { "
                   "$fs = [IO.File]::Open($l.FullName, 'Open', 'Read', 'ReadWrite'); try { $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8); "
                   "$t = $sr.ReadToEnd() } finally { $fs.Close() }; ($t -split \"`n\") | Where-Object { $_ -match '\\[main\\] статистика' } | "
                   "Select-Object -Last 1 }" % L.q(EAC_DIR + r"\logs"))
    return out.strip().splitlines()[-1] if out.strip() else ""


def state(L, lines):
    """Что на сервере сейчас → dict (без секретов: только есть ли файлы и совпадают ли)."""
    st = {"exe": L.rmd5(EXE), "service": "", "ini_has": False, "secret": "", "panel_secret": ""}
    out = ps_ok(L, "$s = Get-Service -Name %s -ErrorAction SilentlyContinue; Write-Output ('SVC=' + $(if ($s) { $s.Status } else { 'NONE' })); "
                   "$b = [IO.File]::ReadAllBytes(%s); $t = [Text.Encoding]::ASCII.GetString($b); "
                   "Write-Output ('INI=' + $(if ($t -match '(?m)^\\[AdminStatus\\]') { 'HAS' } else { 'NO' })); "
                   "$a = Md5Of %s; $p = Md5Of %s; Write-Output ('SEC=' + $(if ($a -eq 'NONE') { 'NONE' } else { 'HAS' })); "
                   "Write-Output ('PSEC=' + $(if ($p -eq 'NONE') { 'NONE' } elseif ($p -eq $a) { 'SAME' } else { 'DIFF' }))"
                   % (SERVICE, L.q(INI), L.q(SECRET), L.q(PANEL_SECRET)))
    for k, key in (("SVC", "service"), ("SEC", "secret"), ("PSEC", "panel_secret")):
        m = re.search(r"%s=(\w+)" % k, out)
        st[key] = m.group(1) if m else "?"
    st["ini_has"] = "INI=HAS" in out
    return st


def backup(L, lines):
    """Бэкап exe и ini: на сервере (SRV_BACKUP, рядом .bak_20261122_a68) и локально (LOCAL_BACKUP), сверка md5."""
    for src in (EXE, INI):
        name = src.rsplit("\\", 1)[-1]
        dst = SRV_BACKUP + "\\" + name
        h = L.rmd5(src)
        if L.rmd5(dst) != h:
            ps_ok(L, "$d = %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                     "$fs = [IO.File]::Open(%s, 'Open', 'Read', 'ReadWrite'); try { $o = [IO.File]::Create(%s); try { $fs.CopyTo($o) } finally { $o.Close() } } "
                     "finally { $fs.Close() }; Write-Output OK" % (L.q(SRV_BACKUP), L.q(src), L.q(dst)))
        if L.rmd5(dst) != h:
            raise RuntimeError("бэкап на сервере %s не сошёлся по md5" % dst)
        data = L.rread(src)
        os.makedirs(LOCAL_BACKUP, exist_ok=True)
        lp = os.path.join(LOCAL_BACKUP, name)
        if not os.path.isfile(lp) or hashlib.md5(open(lp, "rb").read()).hexdigest() != h:
            with open(lp, "wb") as f:
                f.write(data)
        if hashlib.md5(open(lp, "rb").read()).hexdigest() != h:
            raise RuntimeError("локальный бэкап %s не сошёлся по md5" % lp)
        log(lines, "  бэкап %s: md5 %s — сервер %s, локально %s" % (name, h[:8], dst, lp))


def ensure_secret(L, lines):
    """Секрет точки: создать на сервере, если нет (64 hex из RandomNumberGenerator; не печатается); копия — секрет службы панели."""
    out = ps_ok(L, "$k = %s; $p = %s; if (-not (Test-Path -LiteralPath $k)) { $b = New-Object byte[] 32; "
                   "[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $s = ([BitConverter]::ToString($b) -replace '-', '').ToLower(); "
                   "[IO.File]::WriteAllText($k, $s + \"`r`n\", (New-Object Text.ASCIIEncoding)); $s = $null; Write-Output 'SECRET=CREATED' } "
                   "else { Write-Output 'SECRET=EXISTS' }; "
                   "if ((Md5Of $k) -ne (Md5Of $p)) { $d = Split-Path -Parent $p; if (-not (Test-Path -LiteralPath $d)) { throw 'нет папки secrets службы панели' }; "
                   "Copy-Item -LiteralPath $k -Destination $p -Force; Write-Output 'PANEL=COPIED' } else { Write-Output 'PANEL=SAME' }; "
                   "Write-Output ('CHECK=' + $(if ((Md5Of $k) -eq (Md5Of $p)) { 'SAME' } else { 'DIFF' }))" % (L.q(SECRET), L.q(PANEL_SECRET)))
    if "CHECK=SAME" not in out:
        raise RuntimeError("секрет точки и его копия у службы панели не совпали: %s" % out[-200:])
    log(lines, "  секрет точки: %s; копия службы панели: %s (значение не печатается)" % (
        "создан" if "SECRET=CREATED" in out else "уже был", "положена" if "PANEL=COPIED" in out else "уже совпадала"))


def ensure_ini(L, lines):
    """Дописать [AdminStatus] в EacServer.ini (ASCII, после перевода строки), если секции нет."""
    out = ps_ok(L, "$f = %s; $b = [IO.File]::ReadAllBytes($f); $t = [Text.Encoding]::ASCII.GetString($b); "
                   "if ($t -match '(?m)^\\[AdminStatus\\]') { Write-Output 'INI=HAS' } else { $add = %s; "
                   "if ($b.Length -gt 0 -and $b[$b.Length - 1] -ne 10) { $add = \"`r`n\" + $add }; "
                   "[IO.File]::AppendAllText($f, $add, (New-Object Text.ASCIIEncoding)); Write-Output 'INI=ADDED' }"
                   % (L.q(INI), L.q(INI_SECTION)))
    log(lines, "  EacServer.ini: %s" % ("секция [AdminStatus] уже есть" if "INI=HAS" in out else "дописана секция [AdminStatus] Enabled=1 Port=%d" % STATUS_PORT))


# ★ 22.11.2026 (разбор eac_mode1_kick_decisions_20261122.md): ключи политики, которые выкладка ставит в живом ini (Mode НЕ трогается).
#   OperatorUserIndex=1,2 — Д4 (GMFlag=1 только у учёток 1 и 2, Joy1.dbo.CharGmInfo): решение оператору пишется один раз, KICK не шлётся;
#   FailOpenStartupSec=180 — клиент после рестарта службы возвращается по лестнице 2+4+8+16+32+60 = 122 с плюс Connect, REG и
#   RemoteAuthComplete ~11–13 с ≈ 135 с; 180 — с запасом (было 120: 19.10 клиент вернулся через 51 с, худший случай лестницы не покрыт).
POLICY_KEYS = (("OperatorUserIndex", "1,2"), ("FailOpenStartupSec", "180"))


def ensure_policy(L, lines):
    """Поставить POLICY_KEYS в живом EacServer.ini: побайтная замена значения строки ключа (комментарии UTF-8 не трогаются)."""
    for key, val in POLICY_KEYS:
        out = ps_ok(L, "$f = %s; $enc = [Text.Encoding]::GetEncoding(28591); $t = $enc.GetString([IO.File]::ReadAllBytes($f)); "
                       "$rx = '(?m)^%s=[^\\r\\n]*'; $m = [regex]::Matches($t, $rx); "
                       "if ($m.Count -ne 1) { Write-Output ('KEY=COUNT' + $m.Count) } elseif ($m[0].Value -eq '%s=%s') { Write-Output 'KEY=SAME' } "
                       "else { Write-Output ('KEY=WAS ' + $m[0].Value); $t = [regex]::Replace($t, $rx, '%s=%s'); [IO.File]::WriteAllBytes($f, $enc.GetBytes($t)); "
                       "Write-Output 'KEY=SET' }" % (L.q(INI), key, key, val, key, val))
        if "KEY=SAME" not in out and "KEY=SET" not in out:
            raise RuntimeError("EacServer.ini: ключ %s не поставлен: %s" % (key, out[-200:]))
        m = re.search(r"KEY=WAS (.*)", out)
        log(lines, "  EacServer.ini: %s=%s %s" % (key, val, "(было: %s)" % m.group(1).strip() if m else "(уже стояло)"))


def restart_with(L, lines, new_remote):
    """Остановить службу, заменить exe (new_remote → EXE; прежний — рядом с SUFFIX), запустить; вернуть время старта (часы сервера)."""
    out = ps_ok(L, "$t0 = Get-Date -Format 'HH:mm:ss'; Stop-Service -Name %s -Force; $i = 0; "
                   "while ((Get-Service -Name %s).Status -ne 'Stopped' -and $i -lt 60) { Start-Sleep -Milliseconds 500; $i++ }; "
                   "if ((Get-Service -Name %s).Status -ne 'Stopped') { throw 'служба не остановилась за 30 с' }; "
                   "$e = %s; $n = %s; if (Test-Path -LiteralPath ($e + %s)) { Remove-Item -LiteralPath ($e + %s) -Force }; "
                   "Move-Item -LiteralPath $e -Destination ($e + %s); Move-Item -LiteralPath $n -Destination $e; "
                   "Start-Service -Name %s; $i = 0; while ((Get-Service -Name %s).Status -ne 'Running' -and $i -lt 60) { Start-Sleep -Milliseconds 500; $i++ }; "
                   "Write-Output ('T0=' + $t0); Write-Output ('SVC=' + (Get-Service -Name %s).Status)"
                   % (SERVICE, SERVICE, SERVICE, L.q(EXE), L.q(new_remote), L.q(SUFFIX), L.q(SUFFIX), L.q(SUFFIX), SERVICE, SERVICE, SERVICE), timeout=240)
    m = re.search(r"T0=(\d\d:\d\d:\d\d)", out)
    if "SVC=Running" not in out:
        raise RuntimeError("служба %s не поднялась: %s" % (SERVICE, out[-300:]))
    log(lines, "  служба %s перезапущена (остановка в %s по часам сервера), Running" % (SERVICE, m.group(1) if m else "?"))
    return m.group(1) if m else None


def point_get(L, path, with_key):
    """GET к точке статуса НА СЕРВЕРЕ (127.0.0.1:8447); ключ читается из файла там же и не выводится → (код, тело-начало)."""
    hdr = "$k = ([IO.File]::ReadAllLines(%s))[0].Trim(); $h = @{ 'X-Asda-Key' = $k }; $k = $null; " % L.q(SECRET) if with_key else "$h = @{}; "
    out = ps_ok(L, hdr + "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri %s -Headers $h; Write-Output ('CODE=' + [int]$r.StatusCode); "
                         "Write-Output ('BODY=' + $r.Content.Substring(0, [Math]::Min(400, $r.Content.Length))) } catch [Net.WebException] { "
                         "$x = $_.Exception.Response; Write-Output ('CODE=' + $(if ($x) { [int]$x.StatusCode } else { 0 })) }"
                   % L.q("http://127.0.0.1:%d%s" % (STATUS_PORT, path)))
    m = re.search(r"CODE=(\d+)", out)
    b = re.search(r"BODY=(.*)", out, re.S)
    return (int(m.group(1)) if m else -1), (b.group(1).strip() if b else "")


def check(L, lines, since=None):
    """Проверка после выкладки. since — «ЧЧ:ММ:СС» старта (журнал моста P73 — строки HELLO v2 не раньше). → число провалов."""
    bad = 0

    def ok(cond, what, info=""):
        nonlocal bad
        log(lines, "  [%s] %s%s" % ("OK" if cond else "ПРОВАЛ", what, (" — " + str(info)) if (info and not cond) else ""))
        bad += 0 if cond else 1
    st = state(L, lines)
    ok(st["service"] == "Running", "служба %s работает" % SERVICE, st["service"])
    ok(st["exe"] == WANT_EXE, "exe — сборка А6.8 (md5 %s)" % WANT_EXE[:8], st["exe"])
    ok(st["ini_has"], "EacServer.ini: секция [AdminStatus] есть")
    out = ps_ok(L, "$t = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes(%s)); "
                   "foreach ($k in 'Mode', 'OperatorUserIndex', 'FailOpenStartupSec') { $m = [regex]::Match($t, '(?m)^' + $k + '=([^\\r\\n]*)'); "
                   "Write-Output ('K ' + $k + '=' + $m.Groups[1].Value.Trim()) }" % L.q(INI))
    kv = dict(re.findall(r"K (\w+)=(\S*)", out))
    ok(kv.get("Mode") == "1" and kv.get("OperatorUserIndex") == "1,2" and kv.get("FailOpenStartupSec") == "180",
       "EacServer.ini: Mode=1 (не менялся), OperatorUserIndex=1,2, FailOpenStartupSec=180", kv)
    ok(st["secret"] == "HAS" and st["panel_secret"] == "SAME", "секрет точки есть, копия у службы панели совпадает", (st["secret"], st["panel_secret"]))
    # ★ ревизия 66 Р66-4: папку state\ служба создаёт сама — DACL без наследования, только SYSTEM и Administrators
    out = ps_ok(L, "$d = %s; if (-not (Test-Path -LiteralPath $d)) { Write-Output 'ST=NONE' } else { $a = Get-Acl -LiteralPath $d; "
                   "Write-Output ('ST=' + $(if ($a.AreAccessRulesProtected) { 'PROT' } else { 'INH' })); "
                   "$a.Access | ForEach-Object { 'ACE=' + $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } }"
                   % L.q(EAC_DIR + r"\state"))
    aces = set(re.findall(r"ACE=(\S+)", out))
    ok("ST=PROT" in out and aces and aces <= {"S-1-5-18", "S-1-5-32-544"},
       "папка state\\ истории: DACL без наследования, только SYSTEM и Administrators", out[-200:])
    out = ps_ok(L, "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { @(8444, 8447, 15702, 15901) -contains $_.LocalPort } | "
                   "ForEach-Object { 'L=' + $_.LocalAddress + ':' + $_.LocalPort + ':' + (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }")
    ls_ = set(re.findall(r"L=(\S+)", out))
    ok({"127.0.0.1:8444:AsdaEacServer", "127.0.0.1:8447:AsdaEacServer", "127.0.0.1:15702:AsdaEacServer", "0.0.0.0:15901:AsdaEacServer"} <= ls_
       and not any(x.split(":")[-2] == "8447" and not x.startswith("127.0.0.1:") for x in ls_),
       "слушатели: AsdaId 127.0.0.1:8444, точка 127.0.0.1:8447 (только), мост 127.0.0.1:15702, сайдкар 0.0.0.0:15901", sorted(ls_))
    out = ps_ok(L, "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri 'http://127.0.0.1:8444/status'; Write-Output ('ST=' + $r.Content) } "
                   "catch { Write-Output ('ST=ERR ' + $_.Exception.Message) }")
    m = re.search(r"ST=(\{.*\})", out)
    js = json.loads(m.group(1)) if m else {}
    ok(js.get("login") is True and js.get("game") is True, "лаунчерный /status на сервере отвечает (login и game — true)", out[-200:])
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen("https://@@ASTORY_AUTH_HOST@@/status", timeout=10, context=ctx) as r:
            ext = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as ex:
        ext = {"error": str(ex)[:120]}
    ok(ext.get("online") is True or "error" in ext, "лаунчерный /status снаружи (https://@@ASTORY_AUTH_HOST@@/status) — online"
       + (" (с ПК не достать: %s — не проверено снаружи)" % ext["error"] if "error" in ext else ""), ext)
    c1, b1 = point_get(L, "/eac/v1/summary", True)
    ok(c1 == 200 and '"version":"a68.' in b1 and '"ok":true' in b1, "точка статуса с ключом: 200, схема a68.*", (c1, b1[:120]))
    c2, _b2 = point_get(L, "/eac/v1/summary", False)
    ok(c2 == 401, "точка статуса без ключа: 401", c2)
    out = ps_ok(L, "$r = Test-NetConnection -ComputerName @@ASTORY_SERVER_LAN_IP@@ -Port %d -WarningAction SilentlyContinue; Write-Output ('LAN=' + $r.TcpTestSucceeded)" % STATUS_PORT)
    ok("LAN=False" in out, "точка статуса не отвечает по адресу ЛВС сервера @@ASTORY_SERVER_LAN_IP@@:%d" % STATUS_PORT, out[-120:])
    try:
        s = socket.create_connection(("@@ASTORY_SERVER_VPN_IP@@", STATUS_PORT), timeout=5)
        s.close()
        vpn = "принято"
    except OSError as ex:
        vpn = ex.__class__.__name__
    ok(vpn != "принято", "точка статуса не отвечает снаружи (с ПК на @@ASTORY_SERVER_VPN_IP@@:%d)" % STATUS_PORT, vpn)
    if since:
        n = 0
        for g in GS_FOLDERS:
            out = ps_ok(L, "$f = Get-ChildItem -LiteralPath %s -Filter 'PatchLog_*' | Sort-Object LastWriteTime | Select-Object -Last 1; "
                           "$fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite'); try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms) } finally { $fs.Close() }; "
                           "$t = [Text.Encoding]::GetEncoding(1251).GetString($ms.ToArray()); "
                           "($t -split \"`n\") | Where-Object { $_ -match '^\\[(\\d\\d:\\d\\d:\\d\\d)\\] \\[P73\\] .*127\\.0\\.0\\.1:15702, HELLO v2' } | Select-Object -Last 1"
                           % L.q(V2 + "\\" + g + r"\Log\Log_Patch"))
            mm = re.search(r"^\[(\d\d:\d\d:\d\d)\]", out.strip().splitlines()[-1] if out.strip() else "")
            hit = bool(mm and mm.group(1) >= since)
            n += hit
            ok(hit, "мост P73 %s переподключился после рестарта (PatchLog: HELLO v2 в %s)" % (g, mm.group(1) if mm else "—"))
        out = ps_ok(L, "$l = Get-ChildItem -LiteralPath %s -Filter 'eac_*.log' | Sort-Object LastWriteTime | Select-Object -Last 1; "
                       "$fs = [IO.File]::Open($l.FullName, 'Open', 'Read', 'ReadWrite'); try { $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8); "
                       "$t = $sr.ReadToEnd() } finally { $fs.Close() }; ($t -split \"`n\") | Where-Object { $_ -match '\\[bridge\\] HELLO v2' } | "
                       "ForEach-Object { 'H=' + $_.Substring(11, 8) }" % L.q(EAC_DIR + r"\logs"))
        hs = [x for x in re.findall(r"H=(\d\d:\d\d:\d\d)", out) if x >= since]
        ok(len(hs) >= 3, "журнал EacServer: HELLO v2 от P73 после рестарта — %d (нужно 3)" % len(hs), out[-200:])
    return bad


def main():
    args = sys.argv[1:]
    if any(a not in KNOWN for a in args):
        print("неизвестный ключ: %s (--apply | --check | --rollback | --help)" % " ".join(a for a in args if a not in KNOWN))
        return 1
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    L = _lib()
    lines = ["", "==== %s deploy_eac_a68 %s ====" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(args) or "(сухой прогон)")]
    try:
        if "--check" in args:
            bad = check(L, lines)
            log(lines, "ИТОГ проверки: %s" % ("всё сошлось" if not bad else "провалов %d" % bad))
            return 0 if not bad else 2
        st = state(L, lines)
        online = players_online(L)
        log(lines, "сервер: exe %s (%s), служба %s, [AdminStatus] %s, секрет %s, копия панели %s; соединений игроков %d; %s"
            % (st["exe"][:8], "А6.8" if st["exe"] == WANT_EXE else PREV_EXE.get(st["exe"], "НЕИЗВЕСТНЫЙ"), st["service"],
               "есть" if st["ini_has"] else "нет", st["secret"], st["panel_secret"], online, eac_stats(L)[-160:]))
        if "--rollback" in args:
            if online:
                log(lines, "СТОП: в игре есть соединения (%d) — рестарт службы EAC без объявления не делаю" % online)
                return 3
            bak = SRV_BACKUP + r"\AsdaEacServer.exe"
            if L.rmd5(bak) not in PREV_EXE:
                log(lines, "СТОП: прежнего exe в бэкапе нет или md5 не тот (%s)" % bak)
                return 3
            tmp = EXE + ".a68old"
            ps_ok(L, "Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output OK" % (L.q(bak), L.q(tmp)))
            restart_with(L, lines, tmp)
            log(lines, "ОТКАТ: exe %s (секция [AdminStatus] осталась — прежний exe её не читает)" % L.rmd5(EXE)[:8])
            return 0
        local = built_exe()
        if not local or L.md5(local) != WANT_EXE:
            log(lines, "СТОП: закреплённой сборки %s нет или md5 не тот" % os.path.join(BUILT_DIR, "AsdaEacServer_a68_%s.exe" % WANT_EXE[:8]))
            return 3
        if st["exe"] not in PREV_EXE and st["exe"] != WANT_EXE:
            log(lines, "СТОП: на сервере неизвестный exe %s — не заменяю" % st["exe"])
            return 3
        if st["exe"] == WANT_EXE and "--apply" in args:
            log(lines, "exe А6.8 уже выложен — дописываю недостающее (секрет, ini) без рестарта; проверка — --check")
            ensure_secret(L, lines)
            ensure_ini(L, lines)
            ensure_policy(L, lines)
            return 0
        if "--apply" not in args:
            log(lines, "СУХОЙ ПРОГОН: будет — бэкап exe и ini (%s и локально %s), заливка %s, секция [AdminStatus], секрет (если нет) и его копия "
                       "службе панели, рестарт службы %s (только при 0 соединений игроков), проверка. Ничего не изменено." % (SRV_BACKUP, LOCAL_BACKUP,
                                                                                                                    os.path.basename(local), SERVICE))
            return 0
        if online:
            log(lines, "СТОП: в игре есть соединения (%d). Рестарт службы EAC игроков не выкидывает, но объявления для него нет — "
                       "выкладка только при 0 игроков" % online)
            return 3
        backup(L, lines)
        new_remote = EXE + ".a68new"
        L.rupload(local, new_remote)
        if L.rmd5(new_remote) != WANT_EXE:
            raise RuntimeError("залитый exe не сошёлся по md5")
        log(lines, "  залит %s (md5 %s)" % (new_remote, WANT_EXE[:8]))
        ensure_secret(L, lines)
        ensure_ini(L, lines)
        ensure_policy(L, lines)
        if players_online(L):
            log(lines, "СТОП: пока готовились, появились соединения игроков — рестарт не делаю (exe залит рядом, ini и секрет готовы)")
            return 3
        try:
            t0 = restart_with(L, lines, new_remote)
        except RuntimeError as ex:
            log(lines, "СБОЙ старта: %s — откат на прежний exe" % ex)
            tmp = EXE + ".a68old"
            ps_ok(L, "Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output OK" % (L.q(SRV_BACKUP + r"\AsdaEacServer.exe"), L.q(tmp)))
            restart_with(L, lines, tmp)
            return 4
        time.sleep(15)                       # P73 переподключается с паузой до 5 с, AsdaId и точка — сразу
        bad = check(L, lines, t0)
        log(lines, "ИТОГ выкладки: %s" % ("всё сошлось" if not bad else "провалов проверки %d — смотри строки выше (откат: --rollback)" % bad))
        return 0 if not bad else 2
    except RuntimeError as ex:
        log(lines, "ОШИБКА: %s" % ex)
        return 5
    finally:
        flush(lines)


if __name__ == "__main__":
    sys.exit(main())
