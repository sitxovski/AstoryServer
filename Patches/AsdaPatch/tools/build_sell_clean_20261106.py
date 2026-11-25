# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_sell_clean_20261106.py — убрать из SellItemTable.txt коробки 75843–75851, попавшие туда 06.11 как варианты наборов 2257–2265 (Reports/premium_circle_bike/REPORT_VARIANTS.md).
#   Вход: data_buy_variants_20261106/ (выложенные таблицы). Выход: data_sell_clean_20261106/ + manifest.json. Только локальные файлы; на сервер ничего не пишет.
#   Выкладка — в составе deploy_set_prices_20261106.py.
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # noqa: E402  единый состав стойки
from build_gift_as_buy_20261106 import md5b   # noqa: E402  тот же md5

SRC = os.path.join(HERE, "data_buy_variants_20261106")
OUT = os.path.join(HERE, "data_sell_clean_20261106")
TAG = "20261106_sellclean"
DROP = set(range(75843, 75852))


def strip_codes(b):
    """Убрать коды из таблицы: заголовок «макс_код<TAB>число», затем по коду в строке; максимум не меняется."""
    head, _, rest = b.partition(b"\r\n")
    mx, cnt = head.split(b"\t")
    rows = rest.split(b"\r\n")
    keep = [r for r in rows if not (r.strip().isdigit() and int(r) in DROP)]
    gone = len(rows) - len(keep)
    if gone != len(DROP):
        raise SystemExit("ОТКАЗ: убрано %d строк, ждали %d" % (gone, len(DROP)))
    return mx + b"\t" + str(int(cnt) - gone).encode() + b"\r\n" + b"\r\n".join(keep)


def main():
    """Сборка файлов и манифеста."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    files = {}
    for g in stack_layout.GS_FOLDERS:
        with open(os.path.join(SRC, g, "SellItemTable.txt"), "rb") as f:
            old = f.read()
        new = strip_codes(old)
        d = os.path.join(OUT, g)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SellItemTable.txt"), "wb") as f:
            f.write(new)
        files["%s\\ItemTable_Info\\SellItemTable.txt" % g] = {"local": "data_sell_clean_20261106/%s/SellItemTable.txt" % g, "base": md5b(old), "new": md5b(new)}
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tag": TAG, "files": files}, f, ensure_ascii=False, indent=1)
    print("манифест: %d файлов, метка %s" % (len(files), TAG))


if __name__ == "__main__":
    main()
