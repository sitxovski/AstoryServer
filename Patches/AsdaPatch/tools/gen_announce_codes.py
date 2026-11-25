# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
gen_announce_codes.py — таблица кодов «анонсируемых» предметов для P11.

Фильтр повторяет клиентский CItemManager_NotifyItemInfo@0xD0C8F0 (эталон
item_inventory.c:39497), ОБЕ его ветки:
  • item_list   — грейд ItemGrade >= 3 И (ItemType <= 9 ИЛИ ItemType == 11 && ItemSubType == 200);
  • sowell_list — грейд = GradeColorIndex (== sowelRecord->dropColorIndex[0], +0xA9 u8) >= 3,
                  фильтра по типу у самоцветов НЕТ (item_inventory.c:39524-39536).

★ 2026-08-13 (rarechain-agent): ветка САМОЦВЕТОВ раньше в файл не попадала, поэтому P11
  не мог объявить самоцвет даже после того, как в P11/P01 добавили kIsSowelCode. Диапазоны
  двух таблиц не пересекаются (item 20551..79428, sowel 7001..10925 — проверено), поэтому
  один отсортированный список с двоичным поиском покрывает обе.

Зачем файл: в СЕРВЕРНОЙ ItemTable_Info\Item_Table.txt поля грейда НЕТ (проверены все
42 колонки по 55 920 записям), грейд живёт только в клиентских item_list / sowell_list.
Поэтому список годных кодов готовится офлайн и кладётся рядом с сервером.

Выход: текстовый файл со строками "код" или "начало-конец" (диапазоны), '#' — комментарий.
AsdaPatch.dll читает его при старте и ищет двоичным поиском.

Запуск:  python gen_announce_codes.py [выходной_файл]
"""
import csv
import os
import sys

CSV = "@@ASTORY_DEV_ROOT_FWD@@/AstoryClient/RawAssets/Data/ItemDB/item_list.csv"
SOWEL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryClient/RawAssets/Data/ItemDB/sowell_list.csv"
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "out", "announce_codes.txt")


def main():
    codes, total = set(), 0
    with open(CSV, encoding='utf-8-sig', newline='') as f:
        for r in csv.DictReader(f):
            total += 1
            try:
                c, g = int(r['ItemCode']), int(r['ItemGrade'])
                t, s = int(r['ItemType']), int(r['ItemSubType'])
            except (ValueError, TypeError, KeyError):
                continue
            if g < 3:
                continue
            if not (t <= 9 or (t == 11 and s == 200)):
                continue
            codes.add(c)
    n_items = len(codes)

    sow_total = 0
    with open(SOWEL, encoding='utf-8-sig', newline='') as f:
        for r in csv.DictReader(f):
            sow_total += 1
            try:
                c, g = int(r['Id']), int(r['GradeColorIndex'])
            except (ValueError, TypeError, KeyError):
                continue
            if g >= 3:
                codes.add(c)
    n_sowel = len(codes) - n_items

    cs = sorted(codes)
    runs, st, prev = [], cs[0], cs[0]
    for c in cs[1:]:
        if c == prev + 1:
            prev = c
            continue
        runs.append((st, prev))
        st = prev = c
    runs.append((st, prev))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    # cp1251 — как и остальные текстовые таблицы сервера
    with open(OUT, 'w', encoding='cp1251', newline='\r\n') as f:
        f.write("# Коды, годные для серверного анонса (P11). ДВЕ таблицы, как у клиента.\n")
        f.write("# item_list  : ItemGrade >= 3 И (ItemType <= 9 ИЛИ ItemType == 11 и ItemSubType == 200).\n")
        f.write("# sowell_list: GradeColorIndex (dropColorIndex[0]) >= 3, фильтра по типу нет.\n")
        f.write(f"# Источник: item_list.csv ({total} записей) -> {n_items} кодов; "
                f"sowell_list.csv ({sow_total} записей) -> {n_sowel} кодов.\n")
        f.write(f"# Итого годных кодов {len(cs)}, диапазонов {len(runs)}.\n")
        f.write("# Формат: <код> или <начало>-<конец>. Правка вручную допустима.\n")
        for a, b in runs:
            f.write(f"{a}\n" if a == b else f"{a}-{b}\n")

    print(f"строк в item_list : {total}  -> годных {n_items}")
    print(f"строк в sowell    : {sow_total}  -> годных {n_sowel}")
    print(f"годных кодов      : {len(cs)}  (min {cs[0]}, max {cs[-1]})")
    print(f"диапазонов        : {len(runs)}")
    print(f"выход             : {os.path.normpath(OUT)}")


if __name__ == '__main__':
    main()
