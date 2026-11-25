# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# ★ УСТАРЕЛО (22.10.2026): работает через сетевую папку \\@@ASTORY_SERVER_HOSTNAME@@, которая висит. Выкладка — только по SSH по образцу
#   deploy_p77.py (restart_stack.py --deploy ...). Без ASDA_USE_SMB=1 скрипт сразу отказывается (код 3), не висит.
# deploy_p74.py — ВЫКЛАДКА P74 «HP игрока соседям по сектору» (синхронизация боя Ф3, 17.10.2026) на dev-стойку.
#   Производная deploy_p71p72n18.py (тот же порядок и те же проверки), только AsdaPatch.dll в GameServer и Indun_GameServer.
#   ★ ред. 2 (17.10, ревизия): AsdaPatch v46 = живая v45 5fe6dddc (P74 ред. 1) + P74 ред. 2 (типы 1/6 соседям тихой копией,
#   .bak_20261017_p74, бэкапы 2026-10-17_patch_4058, журнал run_p74_20261017). Документ: AstoryServer/Docs/GameServer/hp-sector-sync-p74.md.
#
# Что делает (только при остановленных GameServer/Indun):
#   1. Сверяет md5 собранной DLL с ожидаемым.
#   2. Проверяет, что процессы не держат файлы: каждый GameServer.exe и AsdaPatch.dll открываются на запись. Занят — код 2.
#   3. Бэкап каждой заменяемой DLL и patches.ini (DLL допишет ключ InstantToSector, RegenMinIntervalMs 250→0, Version 45→46):
#      рядом <файл>.bak_20261017_p74v2, на сервере v2\_backup\2026-10-17_patch_4058_v2\<папка>\..., локально
#      @@ASTORY_DEV_ROOT@@\_backup\2026-10-17_patch_4058_v2\server\v2\<папка>\...; сверка размера и md5; существующий бэкап не перезаписывается.
#   4. Копирует собранную DLL и сверяет md5 выложенной.
# По умолчанию — сухой прогон. Выкладка — ключ --apply. Журнал: tools/run_p74v2_20261017/deploy.log (дописывается).
import hashlib
import os
import shutil
import sys
import time

from srv_paths import ROOT as SRV_ROOT, require_smb   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
require_smb(__file__)   # ★ 22.10.2026: устарело — только ASDA_USE_SMB=1
SRV = SRV_ROOT + "/v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT = "093e16e27007840fc3da906effa1db94"                       # v46 (P74 ред. 2)
PREV = "5fe6dddc746f40924d26a140044d0333"                       # живая v45 (P74 ред. 1) — ожидаемая на стойке
SUFFIX = ".bak_20261017_p74v2"
SRV_BACKUP = SRV + "/_backup/2026-10-17_patch_4058_v2"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-17_patch_4058_v2/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_p74v2_20261017/deploy.log"
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


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    """Точка входа: сухой прогон или --apply."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    lines = []
    log(lines, "== deploy_p74 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ВЫКЛАДКА" if apply else "сухой прогон"))
    have = md5(BUILT)
    if have != WANT:
        log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
        flush(lines)
        return 3
    busy = [p for d in FOLDERS for p in (SRV + "/" + d + "/GameServer.exe", SRV + "/" + d + "/AsdaPatch.dll")
            if os.path.exists(p) and not writable(p)]
    if busy:
        for p in busy:
            log(lines, "  занят (процесс работает): " + p)
        log(lines, "СТОП: GameServer/Indun не остановлены — ничего не тронуто")
        flush(lines)
        return 2
    for d in FOLDERS:
        live = SRV + "/" + d + "/AsdaPatch.dll"
        ini = SRV + "/" + d + "/ConfigSet/patches.ini"
        cur = md5(live)
        log(lines, "%s: сейчас %s%s → будет %s" % (d, cur, "" if cur == PREV else " (НЕ ожидаемая v45 %s!)" % PREV, WANT))
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
    log(lines, "ГОТОВО" if apply else "сухой прогон: всё готово к --apply")
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
