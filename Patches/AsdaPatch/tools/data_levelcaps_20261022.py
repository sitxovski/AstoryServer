# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# data_levelcaps_20261022.py — правка данных по аудиту потолков уровня (решения владельца 22.10.2026):
#   1) NpcData_Info\LimitationQuest.txt — у всех 55 ограниченных заданий максимальный уровень (столбец 6) 99 → 100 (= MaxLevel P29);
#   2) BattleField_Info\BattleField_BaseInfo.txt — третье поле боя (строка id 2) диапазон 60–70 → 60–99 (последний столбец 70 → 99).
# В обеих папках: GameServer и Indun_GameServer. Бэкап: рядом <файл>.bak_20261022_levelcaps + @@ASTORY_DEV_ROOT@@\_backup\2026-10-22_levelcaps_data\.
# Байты файла сохраняются (CRLF, табы, кодировка); меняются только указанные поля. Сухой прогон по умолчанию, --apply — запись,
# --rollback — вернуть из .bak.
# ★ 22.10.2026: сухой прогон читает локальное зеркало (srv_paths/srv_mirror.py); --apply/--rollback пишут на шару \\@@ASTORY_SERVER_HOSTNAME@@ —
#   УСТАРЕЛО, только с ASDA_USE_SMB=1 (иначе отказ, код 3); правку данных на стойке делать по SSH по образцу deploy_p77.py.
# Сервер читает таблицы при старте — нужен перезапуск GameServer и Indun.
import hashlib
import os
import shutil
import sys

from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2"
LOCAL = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-22_levelcaps_data"
SUFFIX = ".bak_20261022_levelcaps"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2)
FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"]
FILES = ["NpcData_Info/LimitationQuest.txt", "BattleField_Info/BattleField_BaseInfo.txt"]


def md5b(b):
    return hashlib.md5(b).hexdigest()


def edit_limitation(raw):
    lines = raw.split(b"\r\n")
    n = 0
    for i, ln in enumerate(lines[1:], start=1):
        if not ln.strip():
            continue
        f = ln.split(b"\t")
        if len(f) < 8:
            raise SystemExit("LimitationQuest: строка %d — мало полей" % i)
        if f[6].strip() != b"99":
            raise SystemExit("LimitationQuest: строка %d столбец 6 = %r, ожидалось 99 — стоп" % (i, f[6]))
        f[6] = b"100"
        lines[i] = b"\t".join(f)
        n += 1
    if n != int(lines[0].strip()):
        raise SystemExit("LimitationQuest: изменено %d, в заголовке %s" % (n, lines[0]))
    return b"\r\n".join(lines), n


def edit_battlefield(raw):
    lines = raw.split(b"\r\n")
    done = 0
    for i, ln in enumerate(lines[1:], start=1):
        f = ln.split(b"\t")
        if f and f[0].strip() == b"2":
            if f[-2].strip() != b"60" or f[-1].strip() != b"70":
                raise SystemExit("BattleField: строка id 2 диапазон %r–%r, ожидалось 60–70 — стоп" % (f[-2], f[-1]))
            f[-1] = b"99"
            lines[i] = b"\t".join(f)
            done += 1
    if done != 1:
        raise SystemExit("BattleField: строка id 2 найдена %d раз" % done)
    return b"\r\n".join(lines), done


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    if apply or rollback:   # ★ 22.10.2026: запись — только на шару (устарело); сухой прогон читает зеркало srv_mirror.py
        from srv_paths import require_smb
        require_smb(__file__)
    for d in FOLDERS:
        for rel in FILES:
            path = "%s/%s/%s" % (V2, d, rel)
            if rollback:
                bak = path + SUFFIX
                if not os.path.exists(bak):
                    print("нет бэкапа", bak)
                    continue
                shutil.copy2(bak, path)
                print("возвращено", path, md5b(open(path, "rb").read()))
                continue
            raw = open(path, "rb").read()
            if rel.endswith("LimitationQuest.txt"):
                new, n = edit_limitation(raw)
            else:
                new, n = edit_battlefield(raw)
            print("%s %s: %s → %s (полей изменено %d)" % (d, rel, md5b(raw)[:8], md5b(new)[:8], n))
            if not apply:
                continue
            bak = path + SUFFIX
            if not os.path.exists(bak):
                open(bak, "wb").write(raw)
            loc = "%s/%s/%s" % (LOCAL, d, rel)
            os.makedirs(os.path.dirname(loc), exist_ok=True)
            if not os.path.exists(loc):
                open(loc, "wb").write(raw)
            if md5b(open(bak, "rb").read()) != md5b(raw) or md5b(open(loc, "rb").read()) != md5b(raw):
                raise SystemExit("бэкап не сошёлся — стоп")
            open(path, "wb").write(new)
            if md5b(open(path, "rb").read()) != md5b(new):
                raise SystemExit("запись не сошлась — стоп")
            print("   записано, бэкап", bak)
    print("сухой прогон" if not (apply or rollback) else "ГОТОВО")


if __name__ == "__main__":
    main()
