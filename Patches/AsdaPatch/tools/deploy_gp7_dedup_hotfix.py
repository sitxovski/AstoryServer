# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_gp7_dedup_hotfix.py — СРОЧНЫЙ хотфикс шлюза gp7 после этапа 2 дедупликации предметов (01.11.2026,
#   Reports/item_dedup/stage2/HOTFIX_GP7.md). Отдельно от волны F1 и патча зарядов.
#   Причина: этап 2 заменил в премиум-витрине клиента 5.1.2/5.1.3 проданные коды спецпредметов (205, 196, 81, 525, 522,
#   531, 528, 322) основными (36, 31, 272, 437, 439, 440, 441, 298), а в premium_item_map.json шлюза строк для основных
#   нет → server.js: функциональный код без строки карты → delivery = сам код (< 20551) → отказ undeliverable-item-code
#   (без списания; журнал gp7 01.11: 36 ×1 в 19:07, 298 ×3 в 20:13).
#   Хотфикс добавляет основному коду строку карты: коробка выдачи = коробка исходного проданного кода (её набор в
#   PackageItem_Table после этапа 2 уже содержит основной код — сверяется по живым таблицам), цена = цена, которую
#   GameServer присылает в запросе = Function_Table ток.21 основного кода (иначе premium-price-mismatch).
#   298 («Зелье плодовитости питомцев») НЕ добавляется: у основного цена 100000 вместо прежних 500 — продавать за 100000
#   нельзя; чинится клиентом (волна F1 возвращает в витрину код 322). `--no-discount` — не добавлять и маунты
#   437/439/440/441 (у них цена 450 вместо прежних 490/590).
#   Без ключей — сухой прогон (ничего не пишет): сверка живого md5 карты, сборка новой, проверки, печать строк.
#   `--apply` — запись через srv_io.put_live (бэкапы: рядом <файл>.bak_gp7hotfix_20261101, v2\_backup\gp7hotfix_20261101,
#   локально RE/dumps/server_item_dedup/gp7_hotfix_backup; md5 после записи). gp7 перечитывает карту сам
#   (fileChanged → PREMIUM_ITEM_MAP_OK в журнале), перезапуск НЕ нужен ни gp7, ни стойки.
#   `--rollback` — вернуть карту из локального бэкапа (только если живая = новая).
# Без побочных эффектов при импорте.
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
REL = "gp7-server/premium_item_map.json"
LIVE_MD5 = "0d7722d9dcc3ac644c16a72b798452e8"          # живая карта 01.11 после этапа 2 (снимок _work/srv)
TAG = "gp7hotfix_20261101"
SUFFIX = ".bak_" + TAG
SRV_BACKUP = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\\" + TAG
LOCAL_BACKUP = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "RE", "dumps", "server_item_dedup", "gp7_hotfix_backup"))
# основной код витрины 5.1.3 → исходный проданный код (оригинальный PremiumShop.BIN), чья строка карты даёт коробку
ROWS = [(36, 205), (31, 196), (272, 81), (437, 525), (439, 522), (440, 531), (441, 528)]
DISCOUNT = {437, 439, 440, 441}


def table_rows(rel, first=0):
    """Строки живой таблицы стойки (токены через пробелы), начиная со строки first."""
    import srv_io
    return [l.split() for l in srv_io.read_live(rel).decode("latin1").splitlines()[first:]]


def build(raw):
    """Новая карта (байты) и список добавленных строк; проверки по живым таблицам GameServer."""
    gw = json.loads(raw.decode("utf-8-sig"))
    ft = {int(t[0]): int(t[20]) for t in table_rows("GameServer/ItemTable_Info/Function_Table.txt")
          if len(t) > 20 and t[0].isdigit() and t[20].isdigit()}
    it = {int(t[0]): t for t in table_rows("GameServer/ItemTable_Info/item_table.txt", 1) if t and t[0].isdigit()}
    pk = {int(t[0]): t[1:] for t in table_rows("GameServer/ItemTable_Info/PackageItem_Table.txt", 1)
          if len(t) > 1 and t[0].lstrip("-").isdigit()}
    wl = set()
    for gs in ("GameServer", "Indun_GameServer", "Ch2_GameServer"):
        toks = [x for t in table_rows(gs + "/ItemTable_Info/SellItemTable.txt") for x in t]
        s = set(int(x) for x in toks[2:])
        wl = s if not wl else wl & s
    add = {}
    for main, src in ROWS:
        if "--no-discount" in sys.argv and main in DISCOUNT:
            continue
        if str(main) in gw:
            raise SystemExit("ОТКАЗ: строка %d уже есть в карте — хотфикс не нужен или уже выложен" % main)
        m = gw.get(str(src))
        if not m:
            raise SystemExit("ОТКАЗ: у исходного кода %d нет строки карты" % src)
        box = int(m["deliveryItemCode"])
        t = it.get(box)
        if not t or t[16] != "11" or t[17] != "200":
            raise SystemExit("ОТКАЗ: коробка %d не набор 11/200" % box)
        pkg = pk.get(int(t[39]), [])
        inside = [int(pkg[i]) for i in range(0, len(pkg) - 1, 2) if pkg[i].lstrip("-").isdigit() and int(pkg[i]) > 0]
        if main not in inside and box != 76468:
            raise SystemExit("ОТКАЗ: набор коробки %d (%s) не содержит %d" % (box, inside, main))
        if main not in ft:
            raise SystemExit("ОТКАЗ: %d нет в Function_Table" % main)
        if main not in wl:
            raise SystemExit("ОТКАЗ: %d нет в SellItemTable хотя бы одного GameServer" % main)
        add[str(main)] = {"deliveryItemCode": box, "price": ft[main]}
        print("  + %-4d коробка %d (как у %d, набор %s) цена %d (была у %d: %d)%s"
              % (main, box, src, inside, ft[main], src, m["price"], "  [дешевле — до клиента F1]" if ft[main] < m["price"] else ""))
    gw.update(add)
    ind = 2 if b'\n  "' in raw else None
    data = json.dumps(gw, ensure_ascii=False, indent=ind).encode("utf-8")
    chk = json.dumps(json.loads(raw.decode("utf-8-sig")), ensure_ascii=False, indent=ind).encode("utf-8")
    if b"\r\n" in raw:
        data, chk = data.replace(b"\n", b"\r\n"), chk.replace(b"\n", b"\r\n")
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    tail = raw[len(raw.rstrip(b"\r\n")):]
    if bom + chk + tail != raw:
        raise SystemExit("ОТКАЗ: формат premium_item_map.json не воспроизводится")
    data = bom + data + tail
    back = json.loads(data.decode("utf-8-sig"))
    for k, v in back.items():   # та же проверка, что loadPremiumItemMap в server.js
        if not (k.isdigit() and int(k) > 0 and isinstance(v, dict) and int(v["deliveryItemCode"]) > 0 and int(v["price"]) >= 0):
            raise SystemExit("ОТКАЗ: строка %s не пройдёт проверку server.js" % k)
    return data, add


def main():
    import srv_io
    sys.stdout.reconfigure(encoding="utf-8")
    cur = srv_io.live_md5(REL)
    if "--rollback" in sys.argv:
        p = os.path.join(LOCAL_BACKUP, *REL.split("/"))
        old = open(p, "rb").read()
        if hashlib.md5(old).hexdigest() != LIVE_MD5:
            print("ОТКАЗ отката: локальный бэкап не сходится"); return 1
        srv_io.put_live(REL, old, ".bak_gp7hotfix_rollback", SRV_BACKUP + "_rollback", LOCAL_BACKUP + "_rollback")
        print("ГОТОВО: откат карты выполнен (%s)" % srv_io.live_md5(REL)); return 0
    if cur != LIVE_MD5:
        print("ОТКАЗ: живая карта %s ≠ ожидаемой %s — ничего не записано" % (cur, LIVE_MD5)); return 1
    raw = srv_io.read_live(REL)
    if hashlib.md5(raw).hexdigest() != LIVE_MD5:
        print("ОТКАЗ: прочитанная карта не сходится с md5"); return 1
    data, add = build(raw)
    new = hashlib.md5(data).hexdigest()
    print("строк в карте: %d → %d; md5 %s → %s" % (len(json.loads(raw.decode("utf-8-sig"))), len(json.loads(data.decode("utf-8-sig"))), LIVE_MD5[:8], new[:8]))
    if "--apply" not in sys.argv:
        print("сухой прогон: запись — с --apply (перезапуск gp7 и стойки не нужен)"); return 0
    got = srv_io.put_live(REL, data, SUFFIX, SRV_BACKUP, LOCAL_BACKUP)
    if got != new:
        print("ОТКАЗ: после записи %s != %s" % (got, new)); return 1
    print("ГОТОВО: карта gp7 дополнена (%d строк: %s)" % (len(add), ", ".join(sorted(add, key=int))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
