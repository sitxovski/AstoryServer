# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_pet_potion_20261107.py — таблицы коробки 79940 «Зелье нового уровня питомца x2» (решение владельца 07.11.2026; Reports/pet_potion/REPORT.md).
#   База item_table и PackageItem_Table — выход deploy_box_class_20261107.py, поэтому выкладка идёт ПОСЛЕ него. SowelCombine и SellItemTable — стойка (снимок srv_in).
#   item_table, SowelCombine, PackageItem_Table берутся из srv_out генератора asda_premium_box_add.py: там ровно +1 строка, это сверяется.
#   SellItemTable собирается здесь: build генератора выбрасывает подарочные коды 79935–79939, у нас только +79940. Только локальные файлы; на сервер ничего не пишет.
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # noqa: E402  единый состав стойки
from build_gift_as_buy_20261106 import md5b, patch_sell   # noqa: E402  та же запись таблицы

SRC = os.path.join(HERE, "data_premium_boxes")
OUT = os.path.join(HERE, "data_pet_potion_20261107")
TAG = "20261107_petpotion"
BOX = 79940


def read(*p):
    """Байты файла."""
    with open(os.path.join(*p), "rb") as f:
        return f.read()


def added(old, new, first):
    """Проверить, что таблица отличается только новым счётчиком и одной дописанной строкой, начинающейся с first."""
    a, b = old.split(b"\n"), new.split(b"\n")
    a = [x.rstrip(b"\r") for x in a if x.strip()]
    b = [x.rstrip(b"\r") for x in b if x.strip()]
    if len(b) != len(a) + 1 or int(b[0].split()[0]) != int(a[0].split()[0]) + 1 or a[1:] != b[1:-1] or not b[-1].startswith(first):
        raise SystemExit("ОТКАЗ: таблица изменена не только одной строкой %r" % first)


def main():
    """Сборка файлов и манифеста."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    files = {}
    for g in stack_layout.GS_FOLDERS:
        d = os.path.join(OUT, g)
        os.makedirs(d, exist_ok=True)
        for t, first in (("item_table.txt", b"%d" % BOX), ("SowelCombine.txt", b"%d" % BOX), ("PackageItem_Table.txt", b"5580\t23237\t1\t23237\t1\t")):
            old = read(SRC, "srv_in", g, t)
            new = read(SRC, "srv_out", g, t)
            added(old, new, first)
            with open(os.path.join(d, t), "wb") as f:
                f.write(new)
            files["%s\\ItemTable_Info\\%s" % (g, t)] = {"local": "data_pet_potion_20261107/%s/%s" % (g, t), "base": md5b(old), "new": md5b(new)}
        old = read(SRC, "srv_in", g, "SellItemTable.txt")
        new, got = patch_sell(old, [BOX])
        if list(got) != [BOX]:
            raise SystemExit("ОТКАЗ: белый список %r" % (got,))
        with open(os.path.join(d, "SellItemTable.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\SellItemTable.txt" % g] = {"local": "data_pet_potion_20261107/%s/SellItemTable.txt" % g, "base": md5b(old), "new": md5b(new)}
        print("%s: готово" % g)
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tag": TAG, "files": files}, f, ensure_ascii=False, indent=1)
    print("манифест: %d файлов, метка %s" % (len(files), TAG))


if __name__ == "__main__":
    main()
