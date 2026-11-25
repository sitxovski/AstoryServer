# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# ★ УСТАРЕЛО (22.10.2026): работает через сетевую папку \\@@ASTORY_SERVER_HOSTNAME@@, которая висит. Выкладка — только по SSH по образцу
#   deploy_p77.py (restart_stack.py --deploy ...). Без ASDA_USE_SMB=1 скрипт сразу отказывается (код 3), не висит.
# deploy_p76.py — ВЫКЛАДКА / ОТКАТ P76 «Поля пакетов живых камней 5022/5024/5031» (21.10.2026) на dev-стойку.
#   Производная deploy_p75.py (тот же порядок и те же проверки). AsdaPatch v48 = живая v47 a3680675 (P75 ред. 2) + P76.
#   Документ: AstoryServer/Docs/GameServer/sowel-slot-bounds-p76.md. ★ Выкладка и рестарт — ТОЛЬКО по слову владельца.
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ GameServer/Indun):
#   1. Сверяет md5 собранной DLL с ожидаемым (WANT).
#   2. Проверяет, что процессы не держат файлы (GameServer.exe и AsdaPatch.dll открываются на запись). Занят — код 2.
#   3. На стойке DLL ≠ ожидаемой v47 (PREV) — СТОП, код 8: ничего не затирается (разобраться вручную).
#   4. Бэкап каждой заменяемой DLL и patches.ini (DLL допишет [P76_SowelSlotBounds], Version 47→48): рядом <файл>.bak_20261021_p76,
#      на сервере v2\_backup\2026-10-21_p76\<папка>\..., локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-21_p76\server\v2\<папка>\...;
#      сверка размера и md5; существующий бэкап не перезаписывается.
#   5. Копирует DLL в GameServer и Indun_GameServer, сверяет md5 выложенной.
# Откат (--rollback; тоже при остановленных процессах): DLL из <файл>.bak_20261021_p76 (сверка md5 = PREV).
#   Быстрый откат без замены DLL: в обоих patches.ini [P76_SowelSlotBounds] Enabled=0 (или Mode=0 — только журнал) + рестарт.
# По умолчанию — сухой прогон (ничего не меняет). Журнал: tools/run_p76_20261021/deploy.log (дописывается).
import hashlib
import os
import shutil
import sys
import time

from srv_paths import ROOT as SRV_ROOT, require_smb   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
require_smb(__file__)   # ★ 22.10.2026: устарело — только ASDA_USE_SMB=1
SRV = SRV_ROOT + "/v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT = "bd092e2f2c1ba142e305133a8ed673cd"                                               # v48 (P76)
PREV = "a3680675a992194992dc45b9a1b47070"                       # живая v47 (P75 ред. 2) — ожидаемая на стойке
SUFFIX = ".bak_20261021_p76"
SRV_BACKUP = SRV + "/_backup/2026-10-21_p76"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-21_p76/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_p76_20261021/deploy.log"
FOLDERS = ["GameServer", "Indun_GameServer"]


def md5(path):
    """md5 файла (hex)."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def writable(path):
    """True — файл открывается на запись (процесс его не держит)."""
    try:
        with open(path, "r+b"):
            return True
    except OSError:
        return False


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(src, dst, lines):
    """Бэкап src → dst со сверкой размера и md5; существующий dst не перезаписывается (сверяется)."""
    want = md5(src)
    if os.path.exists(dst):
        have = md5(dst)
        if have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
        log(lines, "  бэкап уже есть: %s (%s)" % (dst, have))
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    if os.path.getsize(dst) != os.path.getsize(src) or md5(dst) != want:
        raise RuntimeError("бэкап %s не сошёлся с оригиналом" % dst)
    log(lines, "  бэкап: %s %d б %s" % (dst, os.path.getsize(dst), want))


def main():
    """Точка входа: сухой прогон, --apply или --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p76 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        busy = [p for d in FOLDERS for p in (SRV + "/" + d + "/GameServer.exe", SRV + "/" + d + "/AsdaPatch.dll")
                if os.path.exists(p) and not writable(p)]
        if busy:
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if apply or rollback:
                log(lines, "СТОП: GameServer/Indun не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")

        if rollback:
            # ★ ревизия 21.10 (М3): откат только поверх v48 — чужую DLL не затираем (сначала проверка обеих папок, потом запись).
            for d in FOLDERS:
                live = SRV + "/" + d + "/AsdaPatch.dll"
                cur = md5(live)
                if cur != WANT:
                    log(lines, "СТОП: в %s сейчас %s, а не v48 %s — откат не нужен или DLL чужая, ничего не трогаю" % (d, cur, WANT))
                    flush(lines)
                    return 9
            for d in FOLDERS:
                live = SRV + "/" + d + "/AsdaPatch.dll"
                bak = live + SUFFIX
                if not os.path.exists(bak) or md5(bak) != PREV:
                    log(lines, "СТОП: %s нет или это не v47 %s" % (bak, PREV))
                    flush(lines)
                    return 6
                shutil.copy2(bak, live)
                log(lines, "%s: DLL возвращена из %s → %s" % (d, bak, md5(live)))
            log(lines, "ОТКАТ ГОТОВ (DLL v47; секция P76 в ini останется — v47 её игнорирует, Version вернёт сама). Нужен старт процессов.")
            flush(lines)
            return 0

        have = md5(BUILT)
        if have != WANT:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
            flush(lines)
            return 3
        # ★ ревизия 21.10 (М2): сначала проверка ОБЕИХ папок, потом запись — чужая DLL в любой папке останавливает до первой замены.
        for d in FOLDERS:
            cur = md5(SRV + "/" + d + "/AsdaPatch.dll")
            log(lines, "%s: сейчас %s%s → будет %s" % (d, cur, "" if cur == PREV else " (НЕ ожидаемая v47 %s!)" % PREV, WANT))
            if cur != PREV:
                log(lines, "СТОП: на стойке в %s не та DLL, что ожидалась (%s ≠ %s) — ничего не затираю, разберись вручную" % (d, cur, PREV))
                flush(lines)
                return 8
        for d in FOLDERS:
            live = SRV + "/" + d + "/AsdaPatch.dll"
            ini = SRV + "/" + d + "/ConfigSet/patches.ini"
            if not apply:
                continue
            for src, rel in ((live, d + "/AsdaPatch.dll"), (ini, d + "/ConfigSet/patches.ini")):
                backup_one(src, src + SUFFIX, lines)
                backup_one(src, SRV_BACKUP + "/" + rel, lines)
                backup_one(src, LOCAL_BACKUP + "/" + rel, lines)
            shutil.copy2(BUILT, live)
            got = md5(live)
            log(lines, "%s выложено: %s %d б %s" % (d, got, os.path.getsize(live), "OK" if got == WANT else "НЕ СОШЛОСЬ"))
            if got != WANT:
                flush(lines)
                return 4
        log(lines, "ГОТОВО: DLL v48 в обеих папках. Старт процессов — за владельцем; в PatchLog — «[OK] P76_SowelSlotBounds», строка «P76:»."
            if apply else "сухой прогон: всё готово к --apply")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
