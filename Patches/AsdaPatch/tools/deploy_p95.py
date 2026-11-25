# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p95.py — ВЫКЛАДКА / ОТКАТ P95 «коробки 6096 (раскладка по правилу сервера + мин. уровень), бустер 5468 и расходник 5028
#   (мин. уровень)» (волна bugs6, 29.10.2026; баги игроков «7.Information error in empty inventory», код 11 при вскрытии коробок,
#   «бустер открывается ниже уровня»).
#   AsdaPatch.dll (P95_ItemUseGuard) во ВСЕ GameServer из stack_layout.GS_FOLDERS (GameServer, Indun_GameServer, Ch2_GameServer):
#   живая f9cdf461 (v54 P01…P94) → WANT_DLL (+ P95). Секцию [P95_ItemUseGuard] (Enabled=1, Placement=1, LevelGate=1,
#   PackageLevelCode=3, GachaLevelCode=3, JournalIntervalSec=10, LogChannel=1) DLL дописывает в patches.ini сама при первом старте.
#   SQL и таблицы не меняются; протокол не меняется. Документ: AstoryServer/Docs/GameServer/item-use-guard-p95.md.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     python restart_stack.py --deploy deploy_p95.py --expect P95_ItemUseGuard
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем start.bat).
#   После старта (только чтение): python deploy_p95.py --check-started
#
# Выкладка (--apply; только при ОСТАНОВЛЕННОЙ стойке):
#   1. md5 собранной DLL = WANT_DLL; GameServer.exe каждой папки = e7b4ac38 (площадки сверены по нему; verify_p95, stand_p95).
#   2. Файлы не заняты процессами (занят — код 2).
#   3. AsdaPatch.dll каждой папки = PREV_DLL (или уже WANT — папка пропускается). Иначе — СТОП, код 8, ничего не тронуто.
#   4. Бэкапы: DLL и patches.ini — рядом <файл>.bak_20261029_p95, в v2\_backup\2026-10-29_p95\… и локально
#      @@ASTORY_DEV_ROOT@@\_backup\2026-10-29_bugs6\server\v2\….
#   5. Заливка DLL (scp во временный файл, md5, копия поверх, сверка).
# Откат (--rollback; при остановленной стойке): DLL из <файл>.bak_20261029_p95 (только поверх WANT).
#   Быстро без замены: [P95_ItemUseGuard] Enabled=0 (или Placement=0 / LevelGate=0 по частям) + рестарт GameServer.
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_p95_20261029_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)
from deploy_p91 import decode_log

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT_DLL = "cc26b99531705a7cbdac4170adbdb0e2"                    # AsdaPatch v54 (P01…P94) + P95
PREV_DLL = {"f9cdf46117a36c442c31b86f65dbc6a5": "AsdaPatch v54 P01…P94 (живая на 29.10 20:00)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261029_p95"
SRV_BACKUP = V2 + r"\_backup\2026-10-29_p95"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-29_bugs6/server/v2"
LOG = os.path.join(HERE, "run_p95_20261029_deploy", "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]


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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-29_p95 и локально; существующие не перезаписываются."""
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
    up = dst + ".p95_upload"
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


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P95_ItemUseGuard» и строка «P95: коробки 6096», без
    провалов (patchlog); DLL = WANT. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P95_ItemUseGuard"], ["P95: коробки 6096"], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        # ★ 31.10.2026: более поздняя сборка цепочки (dll_builds) при подтверждённом журнале — не провал
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
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
    log(lines, "== deploy_p95 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
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

        if rollback:
            todo = [d + r"\AsdaPatch.dll" for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + SUFFIX)
                if bak not in PREV_DLL:
                    log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
                if got not in PREV_DLL:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; секция [P95_ItemUseGuard] в ini останется и будет проигнорирована). Нужен старт стойки." % len(todo))
            flush(lines)
            return 0

        if md5(BUILT_DLL) != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, md5(BUILT_DLL), WANT_DLL))
            flush(lines)
            return 3
        plan = []
        for d in GS_FOLDERS:
            exe = rmd5(V2 + "\\" + d + r"\GameServer.exe")
            cur = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P95)" % (
                d, exe, cur, PREV_DLL.get(cur, "уже P95" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P95 сверены по %s" % (d, exe, GS_EXE))
                flush(lines)
                return 8
            if cur == WANT_DLL:
                continue
            if cur not in PREV_DLL:
                log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
                flush(lines)
                return 8
            plan.append(d)
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (DLL — %d папок из stack_layout: %s)" % (len(plan), ", ".join(plan)))
            flush(lines)
            return 0
        for d in plan:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P95 (AsdaPatch %s) в %d папках. Дальше restart_stack: start.bat; в PatchLog — «[OK] P95_ItemUseGuard»; "
                   "затем python deploy_p95.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
