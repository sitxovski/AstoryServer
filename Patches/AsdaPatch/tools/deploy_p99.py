# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p99.py — ВЫКЛАДКА / ОТКАТ P99 «разделение улучшения выдаёт камень своего типа» (31.10.2026, окно 50500; решение
#   владельца «Да, патчить»). AsdaPatch.dll (P99_UpgradeSplitStone) во ВСЕ GameServer из stack_layout.GS_FOLDERS.
#   SQL нет. Секцию [P99_UpgradeSplitStone] (Enabled=1) DLL дописывает сама при старте. Протокол 6549/6550 не меняется.
#   Документ: AstoryServer/Docs/GameServer/upgrade-split-stone-p99.md.
#   ★ ОЧЕРЁДНОСТЬ: сборка P99 включает P98 (собран 30.10, не выложен). P98 идёт со своим SQL-ремонтом (deploy_p98.py), поэтому
#     P99 ставится ТОЛЬКО поверх выложенного P98 (живая DLL = e41618f8). Живая a8480800 (P01…P97) → СТОП с подсказкой:
#     сначала `restart_stack.py --deploy deploy_p98.py --expect P98_PremiumStackAmount`, потом этот скрипт.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     py -3.13 restart_stack.py --deploy deploy_p99.py --expect P99_UpgradeSplitStone
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем start.bat). После старта: deploy_p99.py --check-started
#
# Режимы:
#   (без ключа) — сухой прогон (только чтение по SSH): md5 собранной DLL, образов GameServer.exe и живых DLL по папкам, занятость,
#                 план; наличие места для бэкапов. Ничего не пишет.
#   --apply     — стойка ОСТАНОВЛЕНА: бэкапы (рядом SUFFIX, v2\_backup\2026-10-31_p99, локально) patches.ini и AsdaPatch.dll,
#                 заливка через временный файл со сверкой md5. «ГОТОВО» — только если прошло всё.
#   --rollback  — стойка остановлена: DLL из <файл>.bak_20261031_p99 (только поверх WANT). Быстро без замены: Enabled=0 + рестарт.
#   --check-started — после старта (только чтение): PatchLog «[OK] P99_UpgradeSplitStone» и строка «P99: разделение улучшения»,
#                 MISMATCH/FAIL в хвосте 0, DLL = WANT.
# Журнал: tools/run_p99_20261031_deploy/deploy.log (дописывается).
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
WANT_DLL = "a6e7c425b33f8353b23e4ece69b26157"                    # AsdaPatch v56 (P01…P98) + P99
PREV_DLL = {"e41618f8d974501f683062c0cd627da3": "AsdaPatch v56 P01…P98 (выкладка deploy_p98.py)"}
NOT_YET = {"a8480800f903d4f5452df45d1a2b730b": "AsdaPatch v56 P01…P97 — P98 ещё не выложен"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261031_p99"
SRV_BACKUP = V2 + r"\_backup\2026-10-31_p99"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-31_bug-upgrade-stone/server/v2"
RUN_DIR = os.path.join(HERE, "run_p99_20261031_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-31_p99 и локально; существующие не перезаписываются."""
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
    up = dst + ".p99_upload"
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
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P99_UpgradeSplitStone», строка «P99: разделение
    улучшения», без провалов (patchlog); DLL = WANT (только чтение)."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P99_UpgradeSplitStone"], ["P99: разделение улучшения"], log=lambda s: log(lines, s))
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
    mode = "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p99 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; секция [P99_UpgradeSplitStone] в ini останется и будет проигнорирована). "
                       "Нужен старт стойки." % len(todo))
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
            ini = rmd5(V2 + "\\" + d + r"\ConfigSet\patches.ini")
            log(lines, "%s: GameServer.exe %s; patches.ini %s; AsdaPatch сейчас %s (%s) → %s (P99)" % (
                d, exe, ini, cur, PREV_DLL.get(cur, NOT_YET.get(cur, "уже P99" if cur == WANT_DLL else "НЕ из допустимых")), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P99 сверены по %s" % (d, exe, GS_EXE))
                flush(lines)
                return 8
            if cur == WANT_DLL:
                continue
            if cur in NOT_YET:
                log(lines, "СТОП: в %s ещё нет P98 — сначала restart_stack.py --deploy deploy_p98.py --expect P98_PremiumStackAmount "
                           "(DLL + SQL-ремонт), затем P99" % d)
                flush(lines)
                return 10
            if cur not in PREV_DLL:
                log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
                flush(lines)
                return 8
            if ini == "none":
                log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
                flush(lines)
                return 8
            plan.append(d)

        if not apply:
            log(lines, "сухой прогон: %s (DLL — %d папок из stack_layout: %s)" % (
                "всё готово к --apply" if plan else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan), ", ".join(plan) or "—"))
            flush(lines)
            return 0 if plan else 9

        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "DLL: AsdaPatch (P99) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P99 (AsdaPatch %s) в %d папках. Дальше restart_stack: start.bat; в PatchLog — «[OK] P99_UpgradeSplitStone»; "
                   "затем py -3.13 deploy_p99.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
