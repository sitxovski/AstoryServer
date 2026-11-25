# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p94.py — ВЫКЛАДКА / ОТКАТ волны charpos (26.10.2026, баг Player17 «панель Друга показывает своё имя») ОДНИМ рестартом:
#   1. AsdaPatch.dll (P94_SoulmateSelfEcho) во ВСЕ GameServer из stack_layout.GS_FOLDERS (GameServer, Indun_GameServer,
#      Ch2_GameServer): живая 71527096 (v54 P01…P92) → WANT_DLL (+ P94). Секцию [P94_SoulmateSelfEcho] (Enabled=1, Mode=1,
#      ForeignCheck=1, JournalIntervalSec=10, LogChannel=0) DLL дописывает в patches.ini сама при первом старте.
#      процедура dbo.UP_AsdaCharPosReset (её зовёт restart_stack.py шаг 4в перед start.bat — сброс устаревших строк CharPos при
#      остановленной стойке), dbo.UPSameUser = стоковое тело + сброс брошенного портального выхода (раз в ~60 с). Бэкап текста
#      UPSameUser — до применения (сверка md5 со стоком 53B4CE9E…).
#   Документ: AstoryServer/Docs/GameServer/soulmate-self-echo-p94.md; отчёт Reports/soulmate_self_echo/SERVER_FIX.md.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор:
#     python restart_stack.py --deploy deploy_p94.py --expect P94_SoulmateSelfEcho
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем шаг 4в EXEC dbo.UP_AsdaCharPosReset, start.bat).
#   После старта (только чтение): python deploy_p94.py --check-started
#
# Выкладка (--apply; только при ОСТАНОВЛЕННОЙ стойке):
#   1. md5 собранной DLL = WANT_DLL; GameServer.exe каждой папки = e7b4ac38 (площадки сверены по нему; verify_p94, stand_p94).
#   2. Файлы не заняты процессами (занят — код 2).
#   3. AsdaPatch.dll каждой папки = PREV_DLL (или уже WANT — папка пропускается); UPSameUser — стоковый (md5 PROC_MD5) или уже
#      charpos. Иначе — СТОП, код 8, ничего не тронуто.
#   4. Бэкапы: DLL и patches.ini — рядом <файл>.bak_20261026_p94, в v2\_backup\2026-10-26_p94\… и локально
#      @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_charpos\server\v2\…; текст UPSameUser — в v2\_backup\2026-10-26_p94\sql\ и локально (md5).
#   5. Заливка DLL (scp во временный файл, md5, копия поверх, сверка); SQL fix (sqlcmd -b), проверка: метка charpos_20261026 в
#      UPSameUser, процедура UP_AsdaCharPosReset и таблица CharPosResetLog есть.
#   UP_AsdaCharPosReset; журнал остаётся), затем DLL из <файл>.bak_20261026_p94.
#   Быстро без замены: [P94_SoulmateSelfEcho] Enabled=0 (или Mode=0 — только журнал) + рестарт GameServer; SQL-часть можно
#   оставить (не зависит от DLL) — её откатывает только этот скрипт.
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_p94_20261026_deploy/deploy.log (дописывается).
import base64
import hashlib
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)
from deploy_p91 import decode_log

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT_DLL = "f9cdf46117a36c442c31b86f65dbc6a5"                    # AsdaPatch v54 (P01…P92) + P94
PREV_DLL = {"7152709682e4afc52e74d3aad0b5b138": "AsdaPatch v54 P01…P92 (живая на 26.10 23:00)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SQL_DIR = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/SQL"
SQL_FIX = SQL_DIR + "/charpos_fix_20261026.sql"
SQL_ROLLBACK = SQL_DIR + "/charpos_rollback_20261026.sql"
PROC_MD5 = "53B4CE9EA304757B697743ABFBD57EC2"                     # HASHBYTES('MD5', OBJECT_DEFINITION) стоковой dbo.UPSameUser
MARK = "charpos_20261026"
SUFFIX = ".bak_20261026_p94"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_p94"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_charpos/server/v2"
LOG = os.path.join(HERE, "run_p94_20261026_deploy", "deploy.log")
BUSY = stack_layout.expand_list([r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"GameServer\AsdaPatch.dll",
                                 r"Indun_GameServer\AsdaPatch.dll"]) + [r"DBManager\DBManager.exe"]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-26_p94 и локально; существующие не перезаписываются."""
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
    if md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p94_upload"
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


def sql(query, timeout=120, wide=False):
    """sqlcmd -E по SSH (Joy1), запрос в UTF-8 через временный файл. wide — длинная строка целиком. → (код, вывод)."""
    b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    fmt = "-y 0" if wide else "-h -1 -W"
    return ps("$f = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String('%s')); "
              "$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 %s -i $f 2>&1; $c = $LASTEXITCODE; Remove-Item $f; "
              "Write-Output ($o -join \"`n\"); Write-Output (\"RC=\" + $c)" % (b64, fmt), timeout=timeout)


def sql_state():
    """(md5 UPSameUser, метка charpos в UPSameUser, есть UP_AsdaCharPosReset, есть CharPosResetLog)."""
    rc, out = sql("SET NOCOUNT ON; SELECT CONCAT('S|', CONVERT(varchar(32), HASHBYTES('MD5', OBJECT_DEFINITION(OBJECT_ID('dbo.UPSameUser'))), 2), '|', "
                  "CASE WHEN OBJECT_DEFINITION(OBJECT_ID('dbo.UPSameUser')) LIKE '%" + MARK + "%' THEN 1 ELSE 0 END, '|', "
                  "CASE WHEN OBJECT_ID('dbo.UP_AsdaCharPosReset', 'P') IS NULL THEN 0 ELSE 1 END, '|', "
                  "CASE WHEN OBJECT_ID('dbo.CharPosResetLog', 'U') IS NULL THEN 0 ELSE 1 END);")
    line = [l for l in out.splitlines() if l.startswith("S|")]
    if rc != 0 or not line or "RC=0" not in out:
        raise RuntimeError("состояние процедур Joy1: %s" % out[-400:])
    _, h, mk, pr, tb = line[0].split("|")
    return h, mk == "1", pr == "1", tb == "1"


def backup_proc(lines):
    """Текст dbo.UPSameUser → v2\\_backup\\2026-10-26_p94\\sql\\ и локально (до любого изменения; сверка md5)."""
    os.makedirs(LOCAL_BACKUP + "/sql", exist_ok=True)
    rc, out = sql("SET NOCOUNT ON; SET QUOTED_IDENTIFIER ON; SELECT CAST(N'' AS XML).value('xs:base64Binary(sql:column(\"b\"))', 'varchar(max)') FROM "
                  "(SELECT CAST(OBJECT_DEFINITION(OBJECT_ID('dbo.UPSameUser')) AS VARBINARY(MAX)) AS b) t;", timeout=180, wide=True)
    body = [l.strip() for l in out.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", l.strip() or "-")]
    if rc != 0 or "RC=0" not in out or not body:
        raise RuntimeError("снятие текста UPSameUser: %s" % out[-300:])
    raw = base64.b64decode("".join(body))
    if hashlib.md5(raw).hexdigest().upper() != PROC_MD5:
        raise RuntimeError("снятый текст UPSameUser не стоковый (md5 %s)" % hashlib.md5(raw).hexdigest().upper())
    text = raw.decode("utf-16-le")
    loc = LOCAL_BACKUP + "/sql/UPSameUser.sql"
    if not os.path.exists(loc):
        with open(loc, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    rc2, out2 = ps("$d = %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                   "$p = Join-Path $d 'UPSameUser.sql'; if (-not (Test-Path -LiteralPath $p)) { [IO.File]::WriteAllBytes($p, [Convert]::FromBase64String('%s')) }; "
                   "Write-Output OK" % (q(SRV_BACKUP + "\\sql"), b64))
    if rc2 != 0 or not out2.endswith("OK"):
        raise RuntimeError("бэкап текста UPSameUser на сервере: %s" % out2[-300:])
    log(lines, "  бэкап процедуры UPSameUser: %d символов → %s и %s\\sql" % (len(text), loc, SRV_BACKUP))


def run_sql_file(path, lines):
    """Применить .sql (GO-пакеты) через sqlcmd -b: файл заливается по scp в v2\\_backup\\2026-10-26_p94\\sql. → 0 успех."""
    remote = SRV_BACKUP + "\\sql\\" + os.path.basename(path)
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null" % q(SRV_BACKUP + "\\sql"))
    r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", path,
                        "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        log(lines, "  SQL %s: ОШИБКА scp: %s" % (os.path.basename(path), r.stderr.strip()))
        return 5
    rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -i %s 2>&1; Write-Output ($o -join \"`n\"); "
                 "Write-Output (\"RC=\" + $LASTEXITCODE)" % q(remote), timeout=300)
    good = rc == 0 and "RC=0" in out
    log(lines, "  SQL %s: %s" % (os.path.basename(path), "OK" if good else "ОШИБКА: " + out[-500:]))
    return 0 if good else 5


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P94_SoulmateSelfEcho» и строка «P94: сообщения пары»
    (patchlog); DLL = WANT; SQL на месте; журнал сброса CharPos (restart_stack шаг 4в) за сегодня. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P94_SoulmateSelfEcho"], ["P94: сообщения пары"], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        # ★ 31.10.2026: более поздняя сборка цепочки (dll_builds) при подтверждённом журнале — не провал
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    h, mk, pr, tb = sql_state()
    log(lines, "SQL: UPSameUser метка %s, UP_AsdaCharPosReset %s, CharPosResetLog %s" % ("ДА" if mk else "НЕТ", "есть" if pr else "НЕТ", "есть" if tb else "НЕТ"))
    good = good and mk and pr and tb
    if tb:
        rc, out = sql("SET NOCOUNT ON; SELECT CONCAT('L|', Source, '|', COUNT(*), '|', CONVERT(varchar(19), MAX(Edate), 120)) FROM dbo.CharPosResetLog "
                      "WHERE Edate >= CAST(GETDATE() AS DATE) GROUP BY Source; SELECT CONCAT('N|', COUNT(*)) FROM dbo.CharPos c "
                      "INNER JOIN AsdaStoryOp.dbo.Us_member m ON m.Userindex = c.Userindex WHERE c.UserNum <> -1 AND m.Flag = 0 "
                      "AND c.LastDate < DATEADD(SECOND, -180, GETDATE());")
        for l in out.splitlines():
            if l.startswith("L|"):
                log(lines, "  журнал сброса сегодня: %s" % l[2:])
            if l.startswith("N|"):
                log(lines, "  строк «в игре» без учётки в игре старше 180 с сейчас: %s (после ближайшего UPSameUser — 0)" % l[2:])
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p94 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"))
    if "--check-started" in sys.argv:
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
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        h, mk, pr, tb = sql_state()
        log(lines, "SQL сейчас: UPSameUser md5 %s (%s), UP_AsdaCharPosReset %s, CharPosResetLog %s" % (
            h, "charpos" if mk else ("сток" if h == PROC_MD5 else "НЕ СТОК И НЕ charpos"), "есть" if pr else "нет", "есть" if tb else "нет"))

        if rollback:
            todo = [d + r"\AsdaPatch.dll" for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + SUFFIX)
                if bak not in PREV_DLL:
                    log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
                    flush(lines)
                    return 6
            if mk or pr:
                if run_sql_file(SQL_ROLLBACK, lines) != 0:
                    flush(lines)
                    return 5
                h, mk, pr, tb = sql_state()
                log(lines, "  SQL после отката: UPSameUser %s, UP_AsdaCharPosReset %s" % ("сток" if h == PROC_MD5 else "НЕ СТОК (" + h + ")", "есть" if pr else "нет"))
                if h != PROC_MD5 or pr:
                    flush(lines)
                    return 5
            for rel in todo:
                rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
                if got not in PREV_DLL:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок, SQL %s; секция [P94_SoulmateSelfEcho] в ini останется и будет проигнорирована). "
                       "Нужен старт стойки." % (len(todo), "откачен" if (mk or pr) or h == PROC_MD5 else "не трогался"))
            flush(lines)
            return 0

        if md5(BUILT_DLL) != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, md5(BUILT_DLL), WANT_DLL))
            flush(lines)
            return 3
        if not mk and h != PROC_MD5:
            log(lines, "СТОП: dbo.UPSameUser не стоковый и не charpos (%s) — SQL не применяю, ничего не тронуто" % h)
            flush(lines)
            return 8
        plan = []
        for d in GS_FOLDERS:
            exe = rmd5(V2 + "\\" + d + r"\GameServer.exe")
            cur = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P94)" % (
                d, exe, cur, PREV_DLL.get(cur, "уже P94" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P94 сверены по %s" % (d, exe, GS_EXE))
                flush(lines)
                return 8
            if cur == WANT_DLL:
                continue
            if cur not in PREV_DLL:
                log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
                flush(lines)
                return 8
            plan.append(d)
        if not plan and mk and pr and tb:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (DLL — %d папок из stack_layout, SQL — %s)" % (len(plan), "уже стоит" if mk and pr and tb else "применить"))
            flush(lines)
            return 0
        for d in plan:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        if not (mk and pr and tb):
            if not mk:
                backup_proc(lines)
            if run_sql_file(SQL_FIX, lines) != 0:
                log(lines, "СТОП: SQL не применён — DLL уже выложены (P94 от SQL не зависит); откат: python deploy_p94.py --rollback")
                flush(lines)
                return 5
            h, mk, pr, tb = sql_state()
            log(lines, "  SQL после применения: UPSameUser метка %s, UP_AsdaCharPosReset %s, CharPosResetLog %s" % (
                "ДА" if mk else "НЕТ", "есть" if pr else "НЕТ", "есть" if tb else "НЕТ"))
            if not (mk and pr and tb):
                flush(lines)
                return 5
        log(lines, "ГОТОВО: P94 (AsdaPatch %s) в %d папках, SQL charpos на месте. Дальше restart_stack: шаг 4в EXEC dbo.UP_AsdaCharPosReset, "
                   "start.bat; в PatchLog — «[OK] P94_SoulmateSelfEcho»; затем python deploy_p94.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
