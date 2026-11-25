# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_set_prices_20261106.py — таблицы следующей серверной пачки (06.11.2026; Reports/premium_circle_bike/REPORT_VARIANTS.md).
#   1) item_table.txt ток.26: цены 40 наборов по похожим товарам, решение владельца «Подобрать по похожим» (--prices).
#   2) SellItemTable.txt: без коробок 75843–75851 (build_sell_clean_20261106.py), они попали туда как варианты наборов 2257–2265.
#   База — выложенные таблицы data_buy_variants_20261106/. Только локальные файлы; на сервер ничего не пишет. Модуль без побочных эффектов при импорте.
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # noqa: E402  единый состав стойки
from build_gift_as_buy_20261106 import md5b, patch_item_table   # noqa: E402  та же запись таблицы
from build_sell_clean_20261106 import strip_codes   # noqa: E402  та же чистка белого списка

SRC = os.path.join(HERE, "data_buy_variants_20261106")
OUT = os.path.join(HERE, "data_set_prices_20261106")
TAG = "20261106_setprices"


def main():
    """Сборка файлов и манифеста."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--prices", required=True, help="JSON {код: цена}")
    a = ap.parse_args()
    with open(a.prices, encoding="utf-8") as f:
        prices = {int(k): v for k, v in json.load(f).items()}
    files = {}
    for g in stack_layout.GS_FOLDERS:
        d = os.path.join(OUT, g)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(SRC, g, "item_table.txt"), "rb") as f:
            old = f.read()
        new, done = patch_item_table(old, prices)
        if set(done.values()) != {10000}:
            raise SystemExit("ОТКАЗ: в плане есть код не с ценой 10000")
        with open(os.path.join(d, "item_table.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\item_table.txt" % g] = {"local": "data_set_prices_20261106/%s/item_table.txt" % g, "base": md5b(old), "new": md5b(new)}
        with open(os.path.join(SRC, g, "SellItemTable.txt"), "rb") as f:
            old = f.read()
        new = strip_codes(old)
        with open(os.path.join(d, "SellItemTable.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\SellItemTable.txt" % g] = {"local": "data_set_prices_20261106/%s/SellItemTable.txt" % g, "base": md5b(old), "new": md5b(new)}
        print("%s: цен %d, белый список -9" % (g, len(done)))
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tag": TAG, "files": files}, f, ensure_ascii=False, indent=1)
    print("манифест: %d файлов, метка %s" % (len(files), TAG))


if __name__ == "__main__":
    main()
