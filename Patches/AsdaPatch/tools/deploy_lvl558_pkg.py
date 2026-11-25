# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_lvl558_pkg.py — БЫСТРЫЙ ВОЗВРАТ «Зелья повышения уровня» 558 в премиум-магазин при живом клиенте 5.1.3 (02.11.2026,
#   приказ владельца «сразу верни в продажу»; разбор — Reports/levelup_potion/REPORT.md §5).
#   Витрина 558 по карте gp7 выдаёт коробку 76405 «Набор уровня на 7 дней»; её пакет PackageItem_Table строка 4572 был «490 ×1»
#   (7-дневный набор) — зелье к игроку не попадало. Правка: строка 4572 → «558 ×1» во всех GameServer стойки
#   (stack_layout.GS_FOLDERS). Карта gp7, item_table, SowelCombine, SellItemTable, DLL и клиент НЕ меняются.
#   Почему так безопасно: пакет 4572 нужен только коробке 76405 (item_table ток.39), 76405 на стойке выдаётся только картой 558;
#   клиент 5.1.3 знает 76405 (item_list/packagetable — 1 спецпредмет → 1 свободная ячейка сумки, ReservePackageSlots), а в сумку
#   кладёт запись из ответа 6097 сервера (ApplyPackageResult → PutRecord), т. е. 558; путь сервера sub_55B7F0 → sub_532B10 у 490
#   и 558 один. PackageItem_Table читается на старте — НУЖЕН РЕСТАРТ GameServer.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_lvl558_pkg.py
#     после старта (только чтение): python deploy_lvl558_pkg.py --check-started
#   python deploy_lvl558_pkg.py --build   — снимок PackageItem_Table по SSH (md5 со стойкой) → data_lvl558/srv_out + манифест
#   python deploy_lvl558_pkg.py           — сухой прогон (md5 базы на стойке = манифесту, новые файлы на месте; ничего не пишет)
#   --apply (GameServer ОСТАНОВЛЕНЫ) / --rollback / --check-started — как deploy_premium_boxes.py (те же функции).
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки (3 GameServer)
import deploy_premium_boxes as DPB                    # бэкап/заливка/откат/проверка старта (без побочных эффектов)

DATA = os.path.join(HERE, "data_lvl558")              # снимок, выход, манифест этой правки
TAG = "20261102_lvl558pkg"                            # суффикс бэкапов стойки .bak_<tag>, локально _backup/2026-11-02_lvl558pkg
REL = "ItemTable_Info\\PackageItem_Table.txt"         # файл правки в каждой папке GameServer
ROW, OLD, NEW = 4572, (490, 1), (558, 1)              # строка пакета коробки 76405: позиция 0 (код, кол-во)
BOX = 76405                                           # коробка витрины 558 (premium_item_map.json)
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SRV_ROOT = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def scp_get(rel, dst):
    """Скачать v2/<rel> со сверкой md5 со стойкой."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    r = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                        "%s:%s/%s" % (SSH_HOST, SRV_ROOT, rel.replace("\\", "/")), dst], capture_output=True, text=True,
                       timeout=600)
    if r.returncode:
        raise SystemExit("scp %s: %s" % (rel, r.stderr.strip()))
    rm = DPB.rmd5(DPB.V2 + "\\" + rel)
    if rm != md5(dst):
        raise SystemExit("md5 снимка %s: локально %s, на стойке %s" % (rel, md5(dst), rm))
    return rm


def build():
    """Снимок 3 PackageItem_Table (+ item_table GameServer для проверки 76405 → 4572), правка строки 4572, манифест."""
    files = {}
    it_rel = "GameServer\\ItemTable_Info\\item_table.txt"
    it_loc = os.path.join(DATA, "srv_in", it_rel)
    scp_get(it_rel, it_loc)
    box = next((ln.split() for ln in open(it_loc, "rb").read().decode("latin1").split("\r\n")
                if ln.split() and ln.split()[0] == str(BOX)), None)
    if not box or box[16] != "11" or box[17] != "200" or int(box[39]) != ROW:
        raise SystemExit("ОТКАЗ: item_table %d не коробка 11/200 с пакетом %d: %r" % (BOX, ROW, box and box[:3] + box[16:18] + box[39:41]))
    for d in stack_layout.GS_FOLDERS:
        rel = d + "\\" + REL
        loc_in = os.path.join(DATA, "srv_in", d, "PackageItem_Table.txt")
        base = scp_get(rel, loc_in)
        lines = open(loc_in, "rb").read().split(b"\r\n")
        hits = [i for i, ln in enumerate(lines[1:], 1) if ln.split()[:1] == [str(ROW).encode()]]
        if len(hits) != 1 or hits[0] != ROW + 1:
            raise SystemExit("ОТКАЗ: %s — строка пакета %d не на месте (%s)" % (rel, ROW, hits))
        t = lines[hits[0]].split(b"\t")
        cur = (int(t[1]), int(t[2]))
        if cur == NEW:
            raise SystemExit("ОТКАЗ: %s — строка %d уже %r (правка на стойке?)" % (rel, ROW, NEW))
        if cur != OLD or any(int(x) not in (-1, 0) for x in t[3:]):
            raise SystemExit("ОТКАЗ: %s — строка %d = %r, ждали %r ×1 без прочих позиций" % (rel, ROW, t, OLD))
        t[1], t[2] = str(NEW[0]).encode(), str(NEW[1]).encode()
        lines[hits[0]] = b"\t".join(t)
        loc_out = os.path.join(DATA, "srv_out", d, "PackageItem_Table.txt")
        os.makedirs(os.path.dirname(loc_out), exist_ok=True)
        with open(loc_out, "wb") as f:
            f.write(b"\r\n".join(lines))
        # сверка: отличается ровно одна строка, счёт и длина файла по строкам те же
        a = open(loc_in, "rb").read().split(b"\r\n")
        o = open(loc_out, "rb").read().split(b"\r\n")
        diff = [i for i in range(max(len(a), len(o))) if (a[i] if i < len(a) else None) != (o[i] if i < len(o) else None)]
        if diff != [ROW + 1]:
            raise SystemExit("ОТКАЗ: %s — изменены строки %s, ждали только %d" % (rel, diff[:5], ROW + 1))
        print("%-50s %s → %s  строка %d: %s" % (rel, base, md5(loc_out), ROW, o[ROW + 1].decode("latin1")))
        files[rel] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": md5(loc_out)}
    man = {"tag": TAG, "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("манифест: %s (файлов %d)" % (os.path.join(DATA, "manifest.json"), len(files)))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        build()
        return 0
    # Дальше — общий путь deploy_premium_boxes (сухой прогон / --apply / --rollback / --check-started) по своему манифесту.
    DPB.MANIFEST = os.path.join(DATA, "manifest.json")
    DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return DPB.main()


if __name__ == "__main__":
    sys.exit(main())
