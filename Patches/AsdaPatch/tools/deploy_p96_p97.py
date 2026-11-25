# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p96_p97.py — ВЫКЛАДКА / ОТКАТ P96 (инвентарная сумка 30→60) и P97 (вес u16), 30.10.2026.
#   AsdaPatch.dll (P96_InventoryX2, P97_WeightU16) во ВСЕ GameServer из stack_layout.GS_FOLDERS;
#   DBPatch.dll (P96_DbShellRows) в DBManager.
#   Живая AsdaPatch: cc26b995 (v54 P01…P95) → WANT_AP (+ P96 + P97, v56).
#   Живая DBPatch:   9376a6bf (v9 P01…AC0) → WANT_DB (+ P96_DbShellRows, v10).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     python restart_stack.py --deploy deploy_p96_p97.py --expect P96_InventoryX2 --expect P97_WeightU16
#   После старта: python deploy_p96_p97.py --check-started
#
# Выкладка (--apply; при ОСТАНОВЛЕННОЙ стойке):
#   1. md5 собранных DLL = WANT_*; GameServer.exe = GS_EXE; DBManager.exe = DB_EXE.
#   2. Файлы не заняты процессами.
#   3. Текущие DLL = PREV_* (или уже WANT — пропуск). Иначе — СТОП.
#   4. Бэкапы: рядом (.bak_20261030_p96p97), в v2\_backup\…, локально в _backup\….
#   5. Заливка DLL (scp → tmp → md5 → копия → сверка).
# Откат (--rollback): DLL из .bak_20261030_p96p97.
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5
from deploy_p91 import decode_log

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
AP_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
DB_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DBPatch/out/DBPatch.dll"

WANT_AP = "a8480800f903d4f5452df45d1a2b730b"  # AsdaPatch v56 (P01…P97)
WANT_DB = "740562a4b82cb616751a320acf60450e"  # DBPatch v10 (+ P96_DbShellRows)
PREV_AP = {"cc26b99531705a7cbdac4170adbdb0e2": "AsdaPatch v54 P01…P95 (живая 30.10)"}
PREV_DB = {"9376a6bf64f0ba26066c6bb4032b6c13": "DBPatch v9 (живая 30.10)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261030_p96p97"
SRV_BACKUP = V2 + r"\_backup\2026-10-30_p96p97"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-30_p96_p97/server/v2"
LOG = os.path.join(HERE, "run_p96p97_20261030_deploy", "deploy.log")


def log(lines, line):
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
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
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s)" % (dst, have, want))
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


def put(rel, local, want, suffix, lines):
    dst = V2 + "\\" + rel
    up = dst + suffix + "_upload"
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


def do_apply(lines):
    log(lines, "=== deploy_p96_p97 --apply %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))

    # 1. md5 собранных DLL
    ap = md5(AP_DLL)
    db = md5(DB_DLL)
    if ap != WANT_AP:
        raise RuntimeError("собранная AsdaPatch.dll = %s, ожидалось %s" % (ap, WANT_AP))
    if db != WANT_DB:
        raise RuntimeError("собранная DBPatch.dll = %s, ожидалось %s" % (db, WANT_DB))
    log(lines, "  AsdaPatch.dll %s OK" % ap)
    log(lines, "  DBPatch.dll   %s OK" % db)

    # 1б. exe сервера
    for d in GS_FOLDERS:
        h = rmd5(V2 + "\\" + d + "\\GameServer.exe")
        if h != GS_EXE:
            raise RuntimeError("%s\\GameServer.exe = %s, ожидался %s" % (d, h, GS_EXE))
    log(lines, "  GameServer.exe ×%d = %s OK" % (len(GS_FOLDERS), GS_EXE))

    # 2. файлы не заняты
    busy_paths = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]
    busy_paths += [r"DBManager\DBManager.exe", r"DBManager\DBPatch.dll"]
    for rel in busy_paths:
        full = V2 + "\\" + rel
        if rbusy(full) == "BUSY":   # rbusy → "FREE"/"BUSY"/"NONE" (строка всегда истинна; исправлено 30.10 при выкладке)
            raise RuntimeError("%s заблокирован процессом — стойка не остановлена?" % full)
    log(lines, "  файлы свободны (%d)" % len(busy_paths))

    # 3. текущие DLL = PREV
    for d in GS_FOLDERS:
        cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
        if cur == WANT_AP:
            log(lines, "  %s\\AsdaPatch.dll уже = WANT, пропускаю" % d)
            continue
        if cur not in PREV_AP:
            raise RuntimeError("%s\\AsdaPatch.dll = %s, не PREV и не WANT — СТОП" % (d, cur))
    cur_db = rmd5(V2 + "\\DBManager\\DBPatch.dll")
    if cur_db != WANT_DB and cur_db not in PREV_DB:
        raise RuntimeError("DBManager\\DBPatch.dll = %s, не PREV и не WANT — СТОП" % cur_db)
    log(lines, "  текущие DLL проверены")

    # 4. бэкапы
    for d in GS_FOLDERS:
        cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
        if cur == WANT_AP:
            continue
        backup_one(d + "\\AsdaPatch.dll", lines)
        backup_one(d + "\\ConfigSet\\patches.ini", lines)   # patches.ini лежит в ConfigSet (как в deploy_p95; исправлено 30.10)
    if cur_db != WANT_DB:
        backup_one("DBManager\\DBPatch.dll", lines)

    # 5. заливка
    for d in GS_FOLDERS:
        cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
        if cur == WANT_AP:
            continue
        put(d + "\\AsdaPatch.dll", AP_DLL, WANT_AP, ".p96p97", lines)
    if cur_db != WANT_DB:
        put("DBManager\\DBPatch.dll", DB_DLL, WANT_DB, ".p96p97", lines)

    log(lines, "ГОТОВО")
    return 0


def do_rollback(lines):
    log(lines, "=== deploy_p96_p97 --rollback %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))
    for d in GS_FOLDERS:
        cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
        bak = V2 + "\\" + d + "\\AsdaPatch.dll" + SUFFIX
        if cur != WANT_AP:
            log(lines, "  %s\\AsdaPatch.dll = %s, не WANT — пропуск" % (d, cur))
            continue
        bh = rmd5(bak)
        if bh not in PREV_AP:
            raise RuntimeError("бэкап %s = %s, не PREV — откат вручную" % (bak, bh))
        rcopy(bak, V2 + "\\" + d + "\\AsdaPatch.dll")
        log(lines, "  %s\\AsdaPatch.dll откат → %s" % (d, rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")))
    bak_db = V2 + "\\DBManager\\DBPatch.dll" + SUFFIX
    cur_db = rmd5(V2 + "\\DBManager\\DBPatch.dll")
    if cur_db == WANT_DB:
        bh = rmd5(bak_db)
        if bh not in PREV_DB:
            raise RuntimeError("бэкап %s = %s, не PREV — откат вручную" % (bak_db, bh))
        rcopy(bak_db, V2 + "\\DBManager\\DBPatch.dll")
        log(lines, "  DBManager\\DBPatch.dll откат → %s" % rmd5(V2 + "\\DBManager\\DBPatch.dll"))
    log(lines, "ГОТОВО")
    return 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P96_InventoryX2» и «[OK] P97_WeightU16», без
    провалов; PatchLog DBManager — «[OK] P96_DbShellRows» (patchlog); md5 AsdaPatch.dll и DBPatch.dll = WANT или более поздняя
    сборка цепочки (dll_builds) при подтверждённом журнале. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    log(lines, "=== deploy_p96_p97 --check-started %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P96_InventoryX2", "P97_WeightU16"], log=lambda s: log(lines, "  " + s))
        h = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", h, WANT_AP, ok, "  " + d + "\\AsdaPatch.dll", lambda s: log(lines, s)) and ok and good
    ok, _ = patchlog.check_folder("DBManager", ["P96_DbShellRows"], log=lambda s: log(lines, "  " + s))
    h_db = rmd5(V2 + "\\DBManager\\DBPatch.dll")
    good = dll_builds.accept("DBPatch", h_db, WANT_DB, ok, "  DBManager\\DBPatch.dll", lambda s: log(lines, s)) and ok and good
    log(lines, "ИТОГ: %s" % ("OK" if good else "ЕСТЬ ПРОБЛЕМЫ"))
    return 0 if good else 1


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    lines = []
    try:
        if "--apply" in sys.argv:
            rc = do_apply(lines)
        elif "--rollback" in sys.argv:
            rc = do_rollback(lines)
        elif "--check-started" in sys.argv:
            rc = check_started(lines)
        else:
            print("deploy_p96_p97.py --apply | --rollback | --check-started")
            return 1
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        rc = 9
    flush(lines)
    return rc


if __name__ == "__main__":
    sys.exit(main())
