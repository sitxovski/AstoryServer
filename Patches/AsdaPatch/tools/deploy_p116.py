# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p116.py — P116: ВИТРИНА МАГАЗИНА ЧЕСТИ = КЛИЕНТСКАЯ (08.11.2026, пачка 17, баг 2 «коробки «для победившей фракции» не купить»;
#   сессия city-war). Разбор — Reports/batch17/city_war/REPORT.md.
#   ПРИЧИНА. На стойке `ItemTable_Info\HonorPrice_Table.txt` — стоковый файл (121 строка, md5 d16c1abe… = Donors/GameServer_stock),
#   а витрина клиента `Honor_price_table.bin` (= эталон, 140 строк) новее: строк 122–139 (коробки 75322…75344, «только победившей
#   армии», город 0/1/2) на сервере НЕТ → `CharRoseWarStoreBuy@0x514FE0` «Wrong TableIndex» → 6163 код 0 (живой журнал
#   Log_RoseWar 02.11 22:22:25, StorePos:123). Строки 100–121 сдвинуты (клиент вставил 387/448/449 — «Wrong ItemIndex»), цены 0–99 другие.
#   ПРАВКА (решение владельца 08.11: «Да, P116», цены клиентские): файл целиком = 140 строк из клиентского .bin, формат стокового
#   байт в байт (ASCII, TAB, пробел после кода товара и после цены колонки 0, CRLF, CRLF в конце, первая строка — число строк).
#   Загрузчик (GameServer.c:68356) — массив new(31·N), N = i16, потолка нет; номера строк обязаны идти подряд (иначе «Sync Error»).
#   Таблица читается при старте GameServer — нужен рестарт. Клиент не меняется.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_p116.py
#   python deploy_p116.py --build      — снимки HonorPrice_Table + item_table + Function_Table всех GameServer по SSH (только чтение)
#                                        → p116_data/srv_in, новый файл → srv_out, сверки, манифест md5, построчный diff (p116_data/diff.tsv)
#   python deploy_p116.py              — сухой прогон (md5 базы на стойке = манифесту; ничего не пишет)
#   --apply (GameServer ОСТАНОВЛЕНЫ) / --rollback / --check-started — общий путь deploy_premium_boxes.py.
# Модуль без побочных эффектов при импорте.
import hashlib
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки (все GameServer)
import deploy_premium_boxes as DPB                    # бэкап/заливка/откат/проверка старта (без побочных эффектов)

DATA = os.path.join(HERE, "p116_data")                # снимок, выход, манифест, diff этой правки
TAG = "20261108_p116"                                 # суффикс бэкапов стойки .bak_<tag>
CLIENT_BIN = r"@@ASTORY_DEV_ROOT@@\AstoryClient\RawAssets\Data\Character\Honor_price_table.bin"   # витрина клиента (= эталон)
CLIENT_BIN_MD5 = "47f8a3f01d8386ecdb1b4d0bb327e88d"   # = Donors/AsdaChroniclesInterlude/Data/Honor_price_table.bin
HP_REL = "ItemTable_Info\\HonorPrice_Table.txt"       # витрина магазина чести на сервере
IT_REL = "ItemTable_Info\\item_table.txt"           # ★ имя врёт: коды 20551…max (`sub_532A90`), загрузчик GameServer.c:68170
FT_REL = "ItemTable_Info\\Function_Table.txt"       # ★ имя врёт: снаряжение 1…N (`sub_532B10`), загрузчик GameServer.c:70407
EXPECT_BASE_MD5 = "d16c1abe"                          # префикс md5 стокового HonorPrice_Table (все три GameServer на 08.11)
EXPECT_ROWS = 140                                     # строк в витрине клиента
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"        # ключ SSH
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"             # стойка
SRV_ROOT = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"                  # корень стойки
# Колонки 1:1 с загрузчиком: +0 StorePos, +4 код, +8 флаг(i16), +10/+11 типы цен, +12/+16 коды цен, +20/+24 значения цен,
#   +28 категория, +29 «только победившей армии», +30 город (−1 любой).
COLS = ["StorePos", "ItemCode", "Flag8", "PriceType0", "PriceType1", "PriceCode0", "PriceCode1",
        "PriceQty0", "PriceQty1", "Category", "VictorOnly", "Region"]


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def scp_get(rel, dst):
    """Снимок файла стойки (только чтение) → dst; возврат md5."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    src = "%s:%s/%s" % (SSH_HOST, SRV_ROOT, rel.replace("\\", "/"))
    p = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", src, dst],
                       capture_output=True, timeout=600)
    if p.returncode != 0:
        raise SystemExit("ОТКАЗ: scp %s: %s" % (rel, p.stderr.decode("utf-8", "replace")[-200:]))
    return md5(dst)


def read_client():
    """140 записей клиентского .bin (заголовок 20 б, запись 12×i32)."""
    if md5(CLIENT_BIN) != CLIENT_BIN_MD5:
        raise SystemExit("ОТКАЗ: %s md5 ≠ эталонного %s" % (CLIENT_BIN, CLIENT_BIN_MD5))
    raw = open(CLIENT_BIN, "rb").read()
    n = struct.unpack_from("<i", raw, 4)[0]
    if n != EXPECT_ROWS or 20 + 48 * n != len(raw):
        raise SystemExit("ОТКАЗ: в .bin %d строк / длина %d" % (n, len(raw)))
    return [struct.unpack_from("<12i", raw, 20 + 48 * i) for i in range(n)]


def parse_table(path):
    """Строки серверного файла → (число из шапки, [кортеж 12 int]). Разбор как у загрузчика: fscanf %s по пробельным."""
    tok = open(path, "rb").read().split()
    n = int(tok[0])
    body = tok[1:]
    if len(body) != 12 * n:
        raise SystemExit("ОТКАЗ: %s — токенов %d, ждали 12×%d" % (path, len(body), n))
    return n, [tuple(int(x) for x in body[12 * i:12 * i + 12]) for i in range(n)]


def render(rows):
    """Текст файла в формате стокового: шапка-число, TAB, пробел после кода и после цены колонки 0, CRLF, CRLF в конце."""
    out = [str(len(rows))]
    for r in rows:
        f = [str(x) for x in r]
        f[1] += " "
        f[7] += " "
        out.append("\t".join(f))
    return ("\r\n".join(out) + "\r\n").encode("ascii")


def check_format_like_stock(stock_path):
    """Сток, пересобранный нашим же рендером, обязан совпасть байт в байт — значит формат передан точно."""
    _, rows = parse_table(stock_path)
    if render(rows) != open(stock_path, "rb").read():
        raise SystemExit("ОТКАЗ: рендер стокового файла не совпал байт в байт — формат понят неверно")


def first_tokens(path):
    """Множество кодов — первых токенов строк таблицы (кроме шапки)."""
    out = set()
    for ln in open(path, "rb").read().split(b"\n")[1:]:
        t = ln.split()
        if t and t[0].lstrip(b"-").isdigit():
            out.add(int(t[0]))
    return out


def build():
    """Снимки трёх GameServer, новый файл, сверки, манифест, diff."""
    client = read_client()
    # 1) Снимки HonorPrice_Table со всех GameServer — должны быть одинаковыми и стоковыми.
    bases, files = {}, {}
    for d in stack_layout.GS_FOLDERS:
        loc = os.path.join(DATA, "srv_in", d, "HonorPrice_Table.txt")
        bases[d] = scp_get(d + "\\" + HP_REL, loc)
        print("%-50s %s" % (d + "\\" + HP_REL, bases[d]))
    if len(set(bases.values())) != 1:
        raise SystemExit("ОТКАЗ: HonorPrice_Table разный на GameServer: %s" % bases)
    base = next(iter(bases.values()))
    if not base.startswith(EXPECT_BASE_MD5):
        raise SystemExit("ОТКАЗ: база %s ≠ стоковой %s… — файл кто-то менял" % (base, EXPECT_BASE_MD5))
    stock = os.path.join(DATA, "srv_in", stack_layout.GS_FOLDERS[0], "HonorPrice_Table.txt")
    check_format_like_stock(stock)
    n_old, old = parse_table(stock)
    # 2) Новый файл из .bin.
    out_bytes = render(client)
    for d in stack_layout.GS_FOLDERS:
        dst = os.path.join(DATA, "srv_out", d, "HonorPrice_Table.txt")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(out_bytes)
    out0 = os.path.join(DATA, "srv_out", stack_layout.GS_FOLDERS[0], "HonorPrice_Table.txt")
    new_md5 = md5(out0)
    # 3) Независимая сверка выхода с .bin: тем же разбором, что у загрузчика.
    n_new, new = parse_table(out0)
    if n_new != EXPECT_ROWS or new != client:
        raise SystemExit("ОТКАЗ: выход не равен .bin построчно")
    if [r[0] for r in new] != list(range(n_new)):
        raise SystemExit("ОТКАЗ: номера строк не подряд (загрузчик даст Sync Error)")
    # 4) Каждый товар и валюта есть в серверных таблицах (снимок GameServer).
    it_loc = os.path.join(DATA, "srv_in", "ItemTable", "item_table.txt")
    ft_loc = os.path.join(DATA, "srv_in", "ItemTable", "Function_Table.txt")
    scp_get(stack_layout.GS_FOLDERS[0] + "\\" + IT_REL, it_loc)
    scp_get(stack_layout.GS_FOLDERS[0] + "\\" + FT_REL, ft_loc)
    it, ft = first_tokens(it_loc), first_tokens(ft_loc)
    missing = []
    for r in new:
        for code, what in ((r[1], "товар"), (r[5], "валюта")):
            # Диапазоны сервера: 1…N — Function_Table (`sub_532B10`, загрузчик :70407), 20551… — item_table (`sub_532A90`);
            #   7001… (`sub_532AE0`, Cellob_Table) в витрине не встречается — такой код считаем ошибкой.
            known = (code in ft) if code < 7001 else (code in it) if code >= 20551 else False
            if not known:
                missing.append((r[0], what, code))
    if missing:
        raise SystemExit("ОТКАЗ: кодов нет в серверных таблицах: %s" % missing[:10])
    codes = {r[1] for r in new} | {r[5] for r in new}
    print("товары/валюта: все %d кодов есть на сервере (Function_Table — %d, item_table — %d)" % (len(codes), len(codes & ft), len(codes & it)))
    # 5) Построчный diff: что изменится у строк, которые сейчас есть, и какие добавятся.
    changed = added = 0
    with open(os.path.join(DATA, "diff.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("row\tkind\t" + "\t".join("old_" + c for c in COLS[1:]) + "\t" + "\t".join("new_" + c for c in COLS[1:]) + "\n")
        for i, r in enumerate(new):
            o = old[i] if i < n_old else None
            if o == r:
                continue
            kind = "added" if o is None else "changed"
            changed += kind == "changed"
            added += kind == "added"
            ov = "\t".join(str(x) for x in o[1:]) if o else "\t".join("" for _ in COLS[1:])
            f.write("%d\t%s\t%s\t%s\n" % (i, kind, ov, "\t".join(str(x) for x in r[1:])))
    print("строк было %d → станет %d; изменится %d, добавится %d; victor-строк %d" % (
        n_old, n_new, changed, added, sum(1 for r in new if r[10] == 1)))
    for d in stack_layout.GS_FOLDERS:
        files[d + "\\" + HP_REL] = {"local": "p116_data/srv_out/%s/HonorPrice_Table.txt" % d, "base": bases[d], "new": new_md5}
    man = {"tag": TAG, "patch": "P116", "rows_old": n_old, "rows_new": n_new, "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("база %s → новый %s; манифест %s" % (base, new_md5, os.path.join(DATA, "manifest.json")))


def main():
    """--build; иначе общий путь deploy_premium_boxes по своему манифесту."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        build()
        return 0
    DPB.MANIFEST = os.path.join(DATA, "manifest.json")
    DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return DPB.main()


if __name__ == "__main__":
    sys.exit(main())
