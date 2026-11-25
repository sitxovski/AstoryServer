# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p129.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v86 = v85 (P128) + P129 «журнал и заглушка чата» (22.11.2026, шаг А6.12).
#   Образец — deploy_p128.py. Документ: AstoryServer/Docs/GameServer/chat-log-p129.md; отчёт:
#   ВЫКЛАДКА — ТОЛЬКО по слову владельца (общий рестарт стойки). --apply при ОСТАНОВЛЕННОЙ стойке:
#        объектов (2 таблицы, 4 процедуры, 2 представления);
#     2. в 3 папках GameServer: бэкап patches.ini и AsdaPatch.dll (рядом, в v2\_backup\2026-11-22_p129 и локально), секция
#        [P129_ChatLog] Enabled=1 Mode=0 дописывается в конец patches.ini в его кодировке (UTF-16 LE), если её нет (остальные ключи
#        DLL допишет сама); AsdaPatch.dll ← v86.
#   Допустимая прежняя DLL — v84 612db6fe (живая на 21.11) или v85 e0d08ba5 (если P128 выложен раньше). Секции P127/P128 не трогаются.
#   --help / -h — эта шапка без действий; неизвестный ключ — код 1 без действий. Без ключей — СУХОЙ ПРОГОН (только чтение).
#   Выкладка — с объявлением:
#     py -3.13 restart_stack.py --deploy deploy_p129.py --expect P129_ChatLog --expect P128_EventBadgeAll --expect P127_AdminBridge --expect P47_IdentityOperatorGate
#   После старта: py -3.13 deploy_p129.py --check-started (PatchLog, md5, пульс узлов ver 86, подключение журнала, кэш заглушек).
#   ОТКАТ: --rollback (или ASDA_P129_ROLLBACK=1 + --apply) при остановленной стойке — DLL ← прежняя из бэкапа рядом, затем схема chat:
#   ★ ревизия 60 М-5: если в chat.message / chat.mute есть строки — сначала копия в joylog1.dbo.chat_message_bak_<время> /
#   ★ ревизия 62 Н-2: схема удаляется ТОЛЬКО если DLL откатили (v86 найдена) и во всех папках теперь прежняя DLL без P129 — иначе код 11.
#   Коды: 0 ок, 2 стойка не остановлена, 4 DLL после копии не сошлась, 6 нет прежней DLL в бэкапе, 9/10/11 — SQL (см. выше).
#   Секция P129 в ini остаётся (прежняя DLL её не читает). Мягкий откат без DLL и без SQL — [P129_ChatLog] Enabled=0.
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
# ★ ревизия 65: сборка после Н-2 (SQLSTATE в PatchLog, «база недоступна» при обрыве после ошибки «не связь») и М-1 (HYT00 — SELECT 1,
#   живое соединение не переоткрывается); 729dbc32 / cd69bc46 / 04335753 — НЕ выкладывать
BUILT_DLL = os.path.join(HERE, "p129_data", "AsdaPatch_v86p129r65_0a5e3bd0.dll")   # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "0a5e3bd02b41d6e08ef9e7398147c0d5"                       # AsdaPatch v86 = v85 + P129 (журнал и заглушка чата), ред. р65
PREV_DLL = {"612db6fef6cb800a2e557783b32d4f77": "AsdaPatch v84 + P127 А5.4 (живая на 21.11, tools/p127_data)",
            "e0d08ba5a4ee855451a9e8530d73710c": "AsdaPatch v85 + P128 ред. р49 (tools/p128_data; живая на 22.11 — сухой прогон)"}
SQL_FILE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "Docs", "SQL", "chat_01_migrate.sql"))
SQL_ROLLBACK = os.path.normpath(os.path.join(HERE, "..", "..", "..", "Docs", "SQL", "chat_99_rollback.sql"))
SQL_SERVER = r"lpc:.\SQLEXPRESS"                                     # как deploy_p128 (sqlcmd -E на сервере)
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P129_ChatLog"
SEED = [("Enabled", "1"), ("Mode", "0")]                            # первая выкладка — только журнал (решение §6 п.5: заглушку включает Mode=1)
INI_KEYS = ["Enabled", "Mode", "LogEnabled", "RetentionDays", "MuteRefreshSec", "NoticeMode"]
OTHER_SECTIONS = ["P47_IdentityOperatorGate", "P121_CharRenameGuard", "P128_EventBadgeAll", "P127_AdminBridge", "P73_EacBridge", "P13_ChatWideChannels6560",
                  "P14_ChatMessageLength"]
NEED_LINES = ["P129: журнал и заглушка чата", "P129: журнал чата ВКЛ", "P128: значок события Event.dat всем игрокам",
              "P127: мост админ-центра", "P73: мост EAC"]
KNOWN_KEYS = ("--apply", "--rollback", "--check-started")
INI_VERSION = 86                                                   # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки сверены по нему (stand_p129 ×3 образа, stand_p127/p128)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261122_p129"
SRV_BACKUP = V2 + r"\_backup\2026-11-22_p129"
SRV_TMP = V2 + r"\_backup\2026-11-22_p129\chat_01_migrate.sql"
SRV_TMP_RB = V2 + r"\_backup\2026-11-22_p129\chat_99_rollback.sql"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-22_p129/server/v2"
RUN_DIR = os.path.join(HERE, "run_p129_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]
WANT_OBJECTS = {"U": 2, "P": 4, "V": 2}                            # chat.*: таблицы / процедуры / представления
PANEL_SQL = r"@@ASTORY_SERVER_ROOT@@\AdminCenter\sql\adminc_24_chat.sql"


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def sql(query, db="master"):
    """Запрос sqlcmd -E на сервере (только то, что передано) в базе db; возврат (код, строки «|»)."""
    rc, out = ps("$o = & sqlcmd -S %s -E -b -d %s -h -1 -W -s '|' -Q %s 2>&1; ($o | Out-String).Trim()" % (q(SQL_SERVER), db, q("SET NOCOUNT ON; " + query)))
    return rc, [ln.strip() for ln in out.splitlines() if ln.strip()]


def schema_state():
    """Состояние joylog1.chat на живом (только чтение): {'db': есть ли joylog1, 'U'/'P'/'V': число объектов, 'rows': строк журнала}."""
    rc, rows = sql("SELECT CAST(DB_ID('joylog1') AS VARCHAR(12)), "
                   "(SELECT COUNT(*) FROM joylog1.sys.objects o JOIN joylog1.sys.schemas s ON s.schema_id = o.schema_id WHERE s.name = 'chat' AND o.type = 'U'), "
                   "(SELECT COUNT(*) FROM joylog1.sys.objects o JOIN joylog1.sys.schemas s ON s.schema_id = o.schema_id WHERE s.name = 'chat' AND o.type = 'P'), "
                   "(SELECT COUNT(*) FROM joylog1.sys.objects o JOIN joylog1.sys.schemas s ON s.schema_id = o.schema_id WHERE s.name = 'chat' AND o.type = 'V'), "
                   "CAST(SERVERPROPERTY('ProductMajorVersion') AS VARCHAR(8))")
    for ln in rows:
        f = [x.strip() for x in ln.split("|")]
        if len(f) == 5 and f[1].isdigit():
            return {"db": f[0] not in ("", "NULL"), "U": int(f[1]), "P": int(f[2]), "V": int(f[3]), "major": f[4], "rc": rc}
    raise RuntimeError("состояние joylog1.chat не прочитано: код %d: %s" % (rc, " / ".join(rows)[-300:]))


def dll_login_state(lines):
    """Логин, которым пишет DLL (GAMEUSER из DBManager\\DBMng.ini — только имя, пароль не читается), и его права в joylog1."""
    rc, out = ps("$p = Join-Path %s 'DBManager\\DBMng.ini'; if (Test-Path -LiteralPath $p) { "
                 "(Get-Content -LiteralPath $p | Where-Object { $_ -match '^\\s*GAMEUSER\\s*=' } | Select-Object -First 1) -replace '^\\s*GAMEUSER\\s*=\\s*', '' } "
                 "else { 'NOFILE' }" % q(V2))
    user = out.splitlines()[-1].strip().strip('"').strip() if out else ""   # в DBMng.ini значение в кавычках
    if rc != 0 or not user or user == "NOFILE":
        log(lines, "  логин DLL (GAMEUSER): не прочитан (%s) — права проверить вручную chat_00_precheck.sql" % (user or rc))
        return
    u = user.replace("'", "''")
    rc, rows = sql("SELECT dp.name, IS_ROLEMEMBER('db_owner', dp.name), ISNULL(IS_SRVROLEMEMBER('sysadmin', N'%s'), 0) FROM sys.database_principals dp "
                   "JOIN sys.server_principals sp ON sp.sid = dp.sid WHERE sp.name = N'%s'" % (u, u), db="joylog1")
    got = [r.split("|") for r in rows if r.count("|") >= 2]
    if got:
        owner = got[0][1].strip() == "1" or got[0][2].strip() == "1"
        log(lines, "  логин DLL (GAMEUSER) %s: в joylog1 пользователь %s, db_owner=%s, sysadmin=%s — %s" % (
            user, got[0][0], got[0][1], got[0][2], "права на схему chat будут (владелец dbo)" if owner
            else "НЕ владелец: выдать INSERT chat.message и EXECUTE chat.UP_ChatMuteActive / chat.UP_ChatJournalPurge"))
    else:
        log(lines, "  логин DLL (GAMEUSER) %s: в joylog1 НЕТ пользователя — журнал не сможет писать (выдать права до выкладки)" % user)


def ini_state(folder):
    """Живой patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции, UTF-16 ли)."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    if data[:2] == b"\xfe\xff":
        raise RuntimeError("%s\\%s в UTF-16 BE (BOM FE FF) — так его DLL не пишет, секцию не дописываю — разберись вручную" % (folder, INI_REL))
    wide = data[:2] == b"\xff\xfe"
    text = data.decode("utf-16") if wide else data.decode("latin-1")
    ver, cur, keys, has = None, None, {}, False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
            has = has or cur == SECTION
            continue
        if not s or s.startswith(";") or "=" not in s:
            continue
        k, v = [x.strip() for x in s.split("=", 1)]
        if cur == "General" and k == "Version":
            ver = v
        elif cur == SECTION:
            keys[k] = v
    return hashlib.md5(data).hexdigest(), ver, has, keys, wide


def seed_section(folder, has, keys, wide, lines):
    """Секция [P129_ChatLog] Enabled=1 Mode=0 в конец patches.ini (в его кодировке), если её нет; остальные ключи DLL допишет сама."""
    if has:
        log(lines, "  секция [%s] уже есть: %s — не трогаю" % (SECTION, ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys) or "—"))
        return
    path = V2 + "\\" + folder + "\\" + INI_REL
    enc = "[Text.Encoding]::Unicode" if wide else "[Text.Encoding]::Default"
    body = "`r`n[%s]`r`n" % SECTION + "".join("%s=%s`r`n" % kv for kv in SEED)
    rc, out = ps("$p=%s; $t=\"%s\"; [IO.File]::AppendAllText($p, $t, %s); 'OK'" % (q(path), body, enc))
    if rc != 0 or "OK" not in out:
        raise RuntimeError("секция в %s не дописана: %s" % (path, out[-300:]))
    _, _, has2, k2, _ = ini_state(folder)
    if not has2 or any(k2.get(k) != v for k, v in SEED):
        raise RuntimeError("после дописывания секция [%s] в %s читается не так: %s" % (SECTION, path, k2))
    log(lines, "  [%s] %s дописана в %s (прочие ключи — DLL при старте)" % (SECTION, " ".join("%s=%s" % kv for kv in SEED), INI_REL))


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в SRV_BACKUP и локально; существующие не перезаписываются."""
    src = V2 + "\\" + rel
    want = rmd5(src)
    for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
    loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        if md5(loc) != want:
            raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл" % loc)
        return
    data = rread(src)
    if hashlib.md5(data).hexdigest() != want:
        raise RuntimeError("прочитанное по SSH %s не сошлось по md5" % src)
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p129_upload"
    rupload(local, up)
    if rmd5(up) != want:
        rdel(up)
        raise RuntimeError("залитый %s не сошёлся по md5 — %s не тронут" % (up, dst))
    rcopy(up, dst)
    rdel(up)
    got = rmd5(dst)
    log(lines, "  %s выложено: %s %s" % (rel, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
    if got != want:
        raise RuntimeError("после копии %s = %s, ожидался %s" % (dst, got, want))


def install_sql(lines):
    """Схема joylog1.chat: залить chat_01_migrate.sql во временный файл стойки, выполнить sqlcmd -E -i, сверить объекты."""
    want = md5(SQL_FILE)
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null" % q(SRV_BACKUP))   # 22.11: scp не создаёт папку (сбой выкладки 18:45)
    rupload(SQL_FILE, SRV_TMP)
    if rmd5(SRV_TMP) != want:
        raise RuntimeError("залитый %s не сошёлся по md5" % SRV_TMP)
    rc, out = ps("$o = & sqlcmd -S %s -E -b -x -I -f 65001 -i %s 2>&1; \"RC=$LASTEXITCODE\"; ($o | Out-String).Trim()" % (q(SQL_SERVER), q(SRV_TMP)),
                 timeout=300)   # ★ ревизия 60 М-2: -I (QUOTED_IDENTIFIER ON)
    ok_rc = "RC=0" in out
    log(lines, "  chat_01_migrate.sql (%s): %s" % (want, "выполнен" if ok_rc else "ОШИБКА: " + out[-400:]))
    if rc != 0 or not ok_rc:
        raise RuntimeError("chat_01_migrate.sql не выполнен — DLL не тронуты")
    st = schema_state()
    if any(st[k] != v for k, v in WANT_OBJECTS.items()):
        raise RuntimeError("после миграции объектов chat: таблиц %d, процедур %d, представлений %d (ждали 2/4/2)" % (st["U"], st["P"], st["V"]))
    log(lines, "  схема joylog1.chat: таблиц %d, процедур %d, представлений %d — OK" % (st["U"], st["P"], st["V"]))


def panel_grants(lines):
    """★ А6.12 (панель): права логинов админ-центра на схему chat (asda_admin — чтение, asda_ops — EXECUTE UP_ChatMuteSet / UP_ChatMuteLift) —
    копия adminc_24_chat.sql панели на сервере, sqlcmd -E -b -x -I. Нет файла (панель старше А6.12) или сбой — строка-предупреждение: выкладка
    DLL не останавливается, права выдаст следующая выкладка панели. → True — выданы.
    ★ ревизия 71 М-1: и сбой SSH / таймаут (исключение rmd5 или ps) — тоже только предупреждение, не «ОШИБКА» выкладки."""
    try:
        if rmd5(PANEL_SQL) == "none":
            log(lines, "  права панели на chat.*: %s нет — выдаст следующая выкладка админ-центра (deploy_admin_center.py)" % PANEL_SQL)
            return False
        rc, out = ps("$o = & sqlcmd -S %s -E -b -x -I -f 65001 -i %s 2>&1; \"RC=$LASTEXITCODE\"; ($o | Out-String).Trim()" % (q(SQL_SERVER), q(PANEL_SQL)),
                     timeout=300)
    except Exception as e:
        log(lines, "  права панели на chat.*: НЕ выданы (сбой %s: %s) — повторите deploy_admin_center.py" % (e.__class__.__name__, str(e)[:200]))
        return False
    ok = rc == 0 and "RC=0" in out and "adminc_24: OK" in out
    log(lines, "  права панели на chat.* (adminc_24_chat.sql): %s" % ("выданы" if ok else "НЕ выданы (%s) — повторите deploy_admin_center.py" % out[-300:]))
    return ok


def survey(lines):
    """Сверки по всем папкам и базе (только чтение). → (план [(папка, есть секция, ключи, UTF-16, нужна DLL)], нужна ли SQL, стоп-код)."""
    plan = []
    st = schema_state()
    need_sql = any(st[k] != v for k, v in WANT_OBJECTS.items())
    log(lines, "SQL Server %s (major %s); joylog1 %s; схема chat: таблиц %d, процедур %d, представлений %d → %s" % (
        SQL_SERVER, st["major"], "есть" if st["db"] else "НЕТ", st["U"], st["P"], st["V"],
        "будет выполнен chat_01_migrate.sql" if need_sql else "на месте (миграция идемпотентна — всё равно не нужна)"))
    if not st["db"]:
        log(lines, "СТОП: на %s нет базы joylog1" % SQL_SERVER)
        return plan, need_sql, 8
    if st["major"].isdigit() and int(st["major"]) < 13:
        log(lines, "СТОП: SQL Server %s старше 2016 (нужны DATEDIFF_BIG и CREATE OR ALTER)" % st["major"])
        return plan, need_sql, 8
    dll_login_state(lines)
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        if rmd5(base + INI_REL) == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, need_sql, 8
        ini_md5, ver, has, keys, wide = ini_state(d)
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (v86)" % (
            d, exe, cur, PREV_DLL.get(cur, "уже v86" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
        log(lines, "  patches.ini %s (%s): Version %s → DLL поднимет до %d; секция [%s] %s" % (
            ini_md5, "UTF-16" if wide else "ANSI", ver, INI_VERSION, SECTION,
            ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has
            else "нет — будет дописана " + " ".join("%s=%s" % kv for kv in SEED)))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки v86 сверены по %s" % (d, exe, GS_EXE))
            return plan, need_sql, 8
        if cur != WANT_DLL and cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, need_sql, 8
        plan.append((d, has, keys, wide, cur != WANT_DLL))
    return plan, need_sql, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer — «[OK]» P129 и соседей; DLL = WANT; пульс узлов ver 86; журнал подключился (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, info = patchlog.check_folder(d, [SECTION] + OTHER_SECTIONS, NEED_LINES, log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
        run = (info or {}).get("run") or {}
        rt = run.get("runtime", []) + run.get("install", [])
        conn = [l for l in rt if "[P129] журнал чата: подключено к базе" in l]
        down = [l for l in rt if "[P129] журнал чата: база недоступна" in l]
        mute = [l for l in rt if "[P129] заглушки: действует" in l]
        log(lines, "  P129: база %s; кэш заглушек %s" % ("подключена" if conn else ("НЕДОСТУПНА — пишет в файл" if down else "строки подключения ещё нет"),
                                                      mute[-1].split("действует", 1)[-1].strip() if mute else "ещё не прочитан"))
        good = good and bool(conn)
    rc, out = ps("$o = & sqlcmd -S lpc:.\\SQLEXPRESS -E -d AsdaAdmin -h -1 -W -s '|' -Q \"SET NOCOUNT ON; SELECT node, mode, ver, "
                 "DATEDIFF(second, heartbeat, SYSUTCDATETIME()), present, errors FROM adm.bridge_node\" 2>&1; ($o | Out-String).Trim()")
    seen = {}
    for ln in out.splitlines():
        f = [x.strip() for x in ln.split("|")]
        if len(f) == 6 and f[3].lstrip("-").isdigit():
            seen[f[0]] = f
    for d in GS_FOLDERS:
        f = seen.get(d)
        fresh = bool(f) and int(f[3]) <= 15 and f[2] == str(INI_VERSION)
        log(lines, "%s: узел моста %s" % (d, ("пульс %s с, Mode=%s, v%s, в игре %s, ошибок SQL %s" % (f[3], f[1], f[2], f[4], f[5])) if f
                                          else "НЕТ строки в adm.bridge_node"))
        good = good and fresh
    rc, rows = sql("SELECT COUNT_BIG(*), MAX(written_utc) FROM joylog1.chat.message WHERE written_utc >= DATEADD(MINUTE, -30, SYSUTCDATETIME())")
    log(lines, "журнал чата за 30 мин: %s (строк | последняя запись UTC)" % (rows[-1] if rows else "не прочитан"))
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def rollback_sql(lines):
    """★ ревизия 60 М-5: схема chat — копия данных (если есть строки) со сверкой, затем chat_99_rollback.sql. → код (0 — ок)."""
    st = schema_state()
    if st["U"] == 0 and st["P"] == 0 and st["V"] == 0:
        log(lines, "SQL: схемы chat нет — откатывать нечего")
        return 0
    stamp = time.strftime("%Y%m%d_%H%M%S")
    for tbl in ("message", "mute"):
        rc, rows = sql("IF OBJECT_ID('chat.%s', 'U') IS NULL SELECT -1 ELSE SELECT COUNT_BIG(*) FROM chat.%s" % (tbl, tbl), db="joylog1")
        cnt = int(rows[-1]) if rows and rows[-1].lstrip("-").isdigit() else None
        if cnt is None:
            log(lines, "СТОП SQL: число строк chat.%s не прочитано (%s) — схема НЕ удаляется" % (tbl, " / ".join(rows)[-200:]))
            return 9
        if cnt <= 0:
            log(lines, "SQL: chat.%s — строк %d, копия не нужна" % (tbl, max(cnt, 0)))
            continue
        bak = "dbo.chat_%s_bak_%s" % (tbl, stamp)
        rc, rows = sql("SELECT * INTO %s FROM chat.%s; SELECT COUNT_BIG(*) FROM %s" % (bak, tbl, bak), db="joylog1")
        got = int(rows[-1]) if rows and rows[-1].isdigit() else -1
        log(lines, "SQL: chat.%s — %d строк → копия joylog1.%s: %d %s" % (tbl, cnt, bak, got, "OK" if got == cnt else "НЕ СОШЛОСЬ"))
        if got != cnt:
            log(lines, "СТОП SQL: копия не сошлась — схема chat НЕ удаляется, данные целы")
            return 9
    want = md5(SQL_ROLLBACK)   # (sqlcmd ниже — с -x: $(…) в литералах не подставляются, ревизия 62 Н-1)
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null" % q(SRV_BACKUP))   # 22.11: scp не создаёт папку
    rupload(SQL_ROLLBACK, SRV_TMP_RB)
    if rmd5(SRV_TMP_RB) != want:
        log(lines, "СТОП SQL: залитый %s не сошёлся по md5" % SRV_TMP_RB)
        return 9
    rc, out = ps("$o = & sqlcmd -S %s -E -b -x -I -f 65001 -i %s 2>&1; \"RC=$LASTEXITCODE\"; ($o | Out-String).Trim()" % (q(SQL_SERVER), q(SRV_TMP_RB)),
                 timeout=300)
    st = schema_state()
    ok = "RC=0" in out and st["U"] == 0 and st["P"] == 0 and st["V"] == 0
    log(lines, "SQL: chat_99_rollback.sql — %s" % ("схема chat удалена" if ok else "ОШИБКА: " + out[-300:]))
    return 0 if ok else 10


def sql_rollback_allowed(todo, now):
    """★ ревизия 65 Н-1: можно ли удалять схему chat после шага DLL. todo — папки, где была v86 (откачены сейчас); now — md5 DLL
    всех папок ПОСЛЕ отката. → (можно ли, пояснение, папки не из PREV_DLL). Без побочных эффектов (проверяет test_deploy_p129_rollback.py)."""
    bad = [d for d in GS_FOLDERS if now.get(d) not in PREV_DLL]
    if bad:
        return False, "в папках %s DLL не из прежних без P129" % ", ".join(bad), bad
    if not todo:
        return True, "DLL уже прежние во всех папках (повторный откат после сбоя SQL) — продолжаю откат SQL", bad
    return True, "DLL откачены в %d папк. — откат SQL" % len(todo), bad


def rollback(lines):
    """Вернуть прежнюю DLL из бэкапов рядом (только поверх WANT); секция P129 и схема chat остаются. → код возврата."""
    todo = [d for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
    for d in todo:
        bak = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll" + SUFFIX)
        if bak not in PREV_DLL:
            log(lines, "СТОП: %s\\AsdaPatch.dll%s нет или это не прежняя DLL (%s)" % (d, SUFFIX, bak))
            return 6
    for d in todo:
        rel = d + r"\AsdaPatch.dll"
        rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
        got = rmd5(V2 + "\\" + rel)
        log(lines, "%s: возвращена %s %s" % (rel, got, "OK (" + PREV_DLL[got] + ")" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
        if got not in PREV_DLL:
            return 4
    log(lines, "DLL: откат %d папок; секция [%s] в ini остаётся (прежняя DLL её не читает)" % (len(todo), SECTION))
    # ★ ревизия 62 Н-2 / 65 Н-1: схему chat удалять, только если во ВСЕХ папках сейчас прежняя DLL без P129 (PREV_DLL, по md5; Version в
    #   ini не показатель — её поднимает сама DLL и не опускает). Пустой todo при всех папках в PREV_DLL — не ошибка: это повторный
    #   --rollback после сбоя SQL (9/10), DLL уже откачены — доделываем SQL (копия _bak_ всё равно делается). Папка не из PREV_DLL
    #   (v86 не откатилась или стоит более новая DLL с P129) — стоп 11, схема и журнал целы.
    now = {d: rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") for d in GS_FOLDERS}
    go, why, bad = sql_rollback_allowed(todo, now)
    if not go:
        vers = {d: ini_state(d)[1] for d in GS_FOLDERS}
        for d in GS_FOLDERS:
            log(lines, "  %s: AsdaPatch %s (%s), Version в ini %s" % (d, now[d], PREV_DLL.get(now[d], "v86" if now[d] == WANT_DLL else "НЕ прежняя без P129"), vers[d]))
        log(lines, "СТОП SQL: %s — схема chat НЕ удаляется (P129 может работать)" % why)
        return 11
    log(lines, "SQL: %s" % why)
    rc = rollback_sql(lines)
    log(lines, "ГОТОВО: ОТКАТ%s. Нужен старт стойки." % ("" if rc == 0 else " DLL — да, SQL — НЕТ (см. выше)"))
    return rc


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(open(os.path.abspath(__file__), encoding="utf-8").read().split("\nimport hashlib")[0])
        return 0
    bad = [a for a in args if a not in KNOWN_KEYS]
    if bad:
        print("неизвестный ключ: %s (есть: %s; --help — справка) — ничего не делаю" % (" ".join(bad), ", ".join(KNOWN_KEYS)))
        return 1
    apply = "--apply" in args
    rb = "--rollback" in args or (apply and os.environ.get("ASDA_P129_ROLLBACK") == "1")
    apply = apply and not rb
    lines = []
    mode = "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in args else "сухой прогон"
    log(lines, "== deploy_p129 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
    if "--check-started" in args:
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    try:
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rb):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        if rb:
            rc = rollback(lines)
            flush(lines)
            return rc
        built = md5(BUILT_DLL)
        if built != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, built, WANT_DLL))
            flush(lines)
            return 3
        log(lines, "  собранная DLL %s — OK; SQL %s (%s); откат SQL %s (%s)" % (built, SQL_FILE, md5(SQL_FILE), SQL_ROLLBACK, md5(SQL_ROLLBACK)))
        plan, need_sql, stop = survey(lines)
        if stop:
            flush(lines)
            return stop
        if not apply:
            try:
                have_panel = rmd5(PANEL_SQL) != "none"
            except Exception:                  # ★ р71 М-1: сухой прогон из-за этой строки не падает
                have_panel = None
            log(lines, "  права панели на chat.*: после SQL — %s" % ("adminc_24_chat.sql панели (%s)" % PANEL_SQL if have_panel
                                                                     else "файла %s нет — выдаст выкладка админ-центра" % PANEL_SQL if have_panel is False
                                                                     else "есть ли %s — не прочитано" % PANEL_SQL))
            log(lines, "сухой прогон: всё готово к --apply (SQL — %s; DLL — %d папок из %d; секция [%s] — дописать в %d)"
                % ("выполнить chat_01_migrate.sql" if need_sql else "не нужна", sum(1 for p in plan if p[4]), len(plan), SECTION,
                   sum(1 for p in plan if not p[1])))
            flush(lines)
            return 0
        if need_sql:
            install_sql(lines)
        panel_grants(lines)                    # ★ А6.12: права админ-центра на chat.* (сбой — предупреждение, не стоп)
        for d, has, keys, wide, need_dll in plan:
            log(lines, "%s:" % d)
            backup_one(d + "\\" + INI_REL, lines)
            seed_section(d, has, keys, wide, lines)
            if need_dll:
                backup_one(d + r"\AsdaPatch.dll", lines)
                put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: v86 (AsdaPatch %s) — %d папок, схема chat на месте. Дальше restart_stack: start.bat; затем "
                   "py -3.13 deploy_p129.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
