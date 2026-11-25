# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_buy_variants_20261106.py — SellItemTable.txt для выбора класса и уровня в окне 6000 (06.11.2026; Reports/premium_circle_bike/REPORT_VARIANTS.md).
#   Покупка и подарок идут кодом варианта, GameServer и шлюз пускают только коды белого списка. Сюда дописываются варианты с совпадающей ценой клиента и сервера;
#   цены — по решению владельца 06.11 (--prices, ток.26 item_table; заглушка 10000 заменена ценой похожих товаров).
#   Вход: снимок стойки (--in, папки GameServer/Ch2_GameServer/Indun_GameServer), --add (JSON кодов), --hold (JSON кодов). Выход: data_buy_variants_20261106/ + manifest.json.
#   Только локальные файлы; на сервер ничего не пишет. Модуль без побочных эффектов при импорте.
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # noqa: E402  единый состав стойки
from build_gift_as_buy_20261106 import md5b, patch_item_table, patch_sell   # noqa: E402  та же запись таблицы

OUT = os.path.join(HERE, "data_buy_variants_20261106")
TAG = "20261106_buyvariants"


def main():
    """Сборка файлов и манифеста."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--add", required=True)
    ap.add_argument("--hold", required=True)
    ap.add_argument("--prices", required=True, help="JSON {код: цена} — ток.26 item_table, решение владельца 06.11: цены как у похожих товаров")
    a = ap.parse_args()
    with open(a.add, encoding="utf-8") as f:
        add = set(json.load(f))
    with open(a.hold, encoding="utf-8") as f:
        hold = set(json.load(f))
    with open(a.prices, encoding="utf-8") as f:
        prices = {int(k): v for k, v in json.load(f).items()}
    hold -= set(prices)   # задержанные варианты получили цену и идут в белый список
    files = {}
    for g in stack_layout.GS_FOLDERS:
        p = os.path.join(a.src, g, "SellItemTable.txt")
        with open(p, "rb") as f:
            old = f.read()
        new, added = patch_sell(old, sorted(add - hold))
        print("%s: белый список +%d (задержано %d)" % (g, len(added), len(add & hold)))
        d = os.path.join(OUT, g)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SellItemTable.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\SellItemTable.txt" % g] = {"local": "data_buy_variants_20261106/%s/SellItemTable.txt" % g, "base": md5b(old), "new": md5b(new)}
        with open(os.path.join(a.src, g, "item_table.txt"), "rb") as f:
            old = f.read()
        new, done = patch_item_table(old, prices)
        print("%s: цен изменено %d" % (g, sum(1 for c, p in done.items() if p != prices[c])))
        with open(os.path.join(d, "item_table.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\item_table.txt" % g] = {"local": "data_buy_variants_20261106/%s/item_table.txt" % g, "base": md5b(old), "new": md5b(new)}
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tag": TAG, "files": files}, f, ensure_ascii=False, indent=1)
    print("манифест: %d файлов, метка %s" % (len(files), TAG))


if __name__ == "__main__":
    main()
