# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p92.py — ВЫКЛАДКА / ОТКАТ P92 «вредный эффект навыка игрока — только на враждебного игрока» (волна bowfx, 26.10.2026)
#   ОДНИМ рестартом стойки: AsdaPatch.dll в GameServer и Indun_GameServer (v54 P01…P91 f88f0a2f → + P92). Секцию
#   [P92_HostileTargetGuard] (Enabled=1, Mode=1, SplashSites=1, ReflectSite=1, NpcRecordSite=1, HostileSkills=1004,
#   JournalIntervalSec=10, LogChannel=0) DLL дописывает в patches.ini сама при первом старте.
#   Документ: AstoryServer/Docs/GameServer/hostile-target-guard-p92.md.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор:
#     python restart_stack.py --deploy deploy_p92.py --expect P92_HostileTargetGuard
#   после старта (только чтение): python deploy_p92.py --check-started
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ GameServer/Indun_GameServer):
#   1. md5 собранной DLL = WANT_DLL; md5 GameServer.exe обеих папок = e7b4ac38 (площадки сверены по нему).
#   2. Процессы не держат файлы (занят — код 2).
#   3. На стойке AsdaPatch.dll = PREV_DLL (или уже WANT — папка пропускается). Иначе — СТОП, код 8, ничего не тронуто.
#   4. Бэкап DLL и patches.ini каждой папки: рядом <файл>.bak_20261026_p92, на сервере v2\_backup\2026-10-26_p92\…,
#      локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_bowfx\server\v2\…; сверка md5.
#   5. Заливка scp во временный <файл>.p92_upload (md5), копия поверх, сверка.
# Откат (--rollback; при остановленных процессах): DLL, которая сейчас = WANT, — из <файл>.bak_20261026_p92.
#   Быстро без замены: [P92_HostileTargetGuard] Enabled=0 (или Mode=0 — только журнал) + рестарт GameServer/Indun.
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)
from deploy_p91 import decode_log

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT_DLL = "7152709682e4afc52e74d3aad0b5b138"                    # AsdaPatch v54 (P01…P91) + P92
PREV_DLL = {"f88f0a2fe8fa87e94555c93c933e0e9c": "AsdaPatch v54 P01…P91 (живая на 26.10)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"] (26.10: + Ch2_GameServer)
SUFFIX = ".bak_20261026_p92"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_p92"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_bowfx/server/v2"
LOG = os.path.join(HERE, "run_p92_20261026_deploy", "deploy.log")
BUSY = stack_layout.expand_list([r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"GameServer\AsdaPatch.dll",
                                 r"Indun_GameServer\AsdaPatch.dll"])   # 26.10: + Ch2_GameServer


def log(lines, line):
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-26_p92 и локально; существующие не перезаписываются."""
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
    up = dst + ".p92_upload"
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
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P92_HostileTargetGuard», строка «P92: режим», без
    провалов (patchlog); DLL = WANT. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P92_HostileTargetGuard"], ["P92: режим"], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        # ★ 31.10.2026: более поздняя сборка цепочки (dll_builds) при подтверждённом журнале — не провал
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p92 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
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
            if not todo:
                log(lines, "СТОП: на стойке нет DLL P92 — откатывать нечего")
                flush(lines)
                return 9
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
            log(lines, "ОТКАТ ГОТОВ (секция [P92_HostileTargetGuard] в ini останется и будет проигнорирована). Нужен старт стойки.")
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
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P92)" % (
                d, exe, cur, PREV_DLL.get(cur, "уже P92" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P92 сверены по %s" % (d, exe, GS_EXE))
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
            log(lines, "сухой прогон: всё готово к --apply (%d папок)" % len(plan))
            flush(lines)
            return 0
        for d in plan:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P92 (AsdaPatch %s) выложен. Старт стойки — за координатором; в PatchLog GameServer/Indun — "
                   "«[OK] P92_HostileTargetGuard» и «P92: режим НЕ ПРИМЕНЯТЬ …»; затем python deploy_p92.py --check-started." % WANT_DLL)
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
