# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_gift_as_buy_20261106.py — таблицы GameServer для «подарок = покупка себе» (06.11.2026, решение владельца; Reports/premium_circle_bike/REPORT_GIFT.md).
#   GameServer дарит ровно код из 5074, поэтому новый клиент шлёт код выдачи карточки (коробку карты gp7). Нужно на стойке:
#   1) SellItemTable.txt — коды этих коробок: P101 и шлюз пускают в подарок только коды белого списка; заголовок = новый максимум кода, новое число строк;
#   2) item_table.txt ток.26 — цена коробки = цене карточки там, где они расходились: сумму подарка считает GS по таблице.
#   Вход: снимок стойки (--in, папки GameServer/Ch2_GameServer/Indun_GameServer) и карта gp7 (--map). Выход: data_gift_as_buy_20261106/ + manifest.json.
#   Только локальные файлы; на сервер ничего не пишет. Модуль без побочных эффектов при импорте.
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # noqa: E402  единый состав стойки

OUT = os.path.join(HERE, "data_gift_as_buy_20261106")
TAG = "20261106_giftbox"


def md5b(b):
    """md5 байтов."""
    return hashlib.md5(b).hexdigest()


def plan(map_path, shop_path):
    """Карта gp7 + витрина → {коробка: цена карточки} только по карточкам витрины (не причёски); общая коробка с разной ценой — отказ."""
    with open(map_path, encoding="utf-8") as f:
        m = json.load(f)
    with open(shop_path, encoding="utf-8") as f:
        cards = {r["ItemId"] for r in json.load(f) if r["Category"] != 3}
    price = {}
    for k, e in m.items():
        d = e["deliveryItemCode"]
        if d == int(k) or int(k) not in cards:
            continue
        if d in price and price[d] != e["price"]:
            raise SystemExit("ОТКАЗ: коробка %d у карточек с разной ценой" % d)
        price[d] = e["price"]
    return price


def patch_item_table(b, want):
    """Заменить ток.26 у строк из want {код: цена}; остальные байты не трогать."""
    lines = b.split(b"\n")
    done = {}
    for i, l in enumerate(lines):
        t = l.split(b"\t")
        c = t[0].strip()
        if not c.isdigit() or int(c) not in want or len(t) < 27:
            continue
        pad = t[26][len(t[26].rstrip()):]
        old = int(t[26].strip())
        t[26] = str(want[int(c)]).encode() + pad
        lines[i] = b"\t".join(t)
        done[int(c)] = old
    if set(done) != set(want):
        raise SystemExit("ОТКАЗ: не нашлись строки %s" % sorted(set(want) - set(done)))
    return b"\n".join(lines), done


def patch_sell(b, add):
    """Дописать коды в SellItemTable: заголовок «макс_код<TAB>число», затем по коду в строке."""
    head, _, rest = b.partition(b"\r\n")
    mx, cnt = head.split(b"\t")
    body = rest.rstrip(b"\r\n")
    have = set(int(x) for x in body.split())
    if len(body.split()) != int(cnt):
        raise SystemExit("ОТКАЗ: заголовок %s, строк %d" % (head, len(body.split())))
    new = sorted(set(add) - have)
    n = int(cnt) + len(new)
    top = max([int(mx)] + new)
    return b"%d\t%d\r\n" % (top, n) + body + b"\r\n" + b"".join(b"%d\r\n" % c for c in new) + (rest[len(body) + 2:] if len(rest) > len(body) + 2 else b""), new


def main():
    """Сборка файлов и манифеста."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--map", required=True)
    ap.add_argument("--shop", required=True, help="RawAssets/Data/NPC/PremiumShopBin.json")
    a = ap.parse_args()
    files = {}
    for g in stack_layout.GS_FOLDERS:
        rd = lambda n: open(os.path.join(a.src, g, n), "rb").read()
        it, sell = rd("item_table.txt"), rd("SellItemTable.txt")
        price = plan(a.map, a.shop)
        cur = {}
        for l in it.split(b"\n"):
            t = l.split(b"\t")
            if t[0].strip().isdigit() and int(t[0].strip()) in price and len(t) > 26:
                cur[int(t[0].strip())] = int(t[26].strip())
        fix = {c: p for c, p in price.items() if c in cur and cur[c] != p}
        new_it, was = patch_item_table(it, fix)
        new_sell, added = patch_sell(sell, list(cur))
        print("%s: цена коробок %s; белый список +%d" % (g, {c: (was[c], fix[c]) for c in sorted(fix)}, len(added)))
        for name, old, new in (("item_table.txt", it, new_it), ("SellItemTable.txt", sell, new_sell)):
            d = os.path.join(OUT, g)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, name), "wb") as f:
                f.write(new)
            files["%s\\ItemTable_Info\\%s" % (g, name)] = {"local": "data_gift_as_buy_20261106/%s/%s" % (g, name), "base": md5b(old), "new": md5b(new)}
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tag": TAG, "files": files}, f, ensure_ascii=False, indent=1)
    print("манифест: %d файлов, метка %s" % (len(files), TAG))


if __name__ == "__main__":
    main()
