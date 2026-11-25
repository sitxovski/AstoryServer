# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
gen_title_grades_p88.py — таблицы кодов предметов по грейду для P88 (звания 193–198 «создал геройский/легендарный предмет»).

Зачем: в СЕРВЕРНОЙ item_table поля грейда нет (проверено для P11, gen_announce_codes.py: все 42 колонки), грейд живёт только
в клиентском item_list (ItemGrade, +E8 записи; loc 1421 + грейд: 3 = «Герой», 4 = «Легенда»). P88 на ответе БД ремесла 2666
(recvDBCraftEnter) ищет код изготовленного предмета в этих двух файлах.

Выход (формат announce_codes.txt — тот же разбор, что в P11): строки "код" или "начало-конец", '#' — комментарий.
  title_hero_p88.txt   — ItemGrade == 3
  title_legend_p88.txt — ItemGrade == 4
Источник: AstoryClient/RawAssets/Data/ItemDB/item_list.csv (только чтение). Побочных эффектов при импорте нет.

Запуск:  python gen_title_grades_p88.py [каталог_вывода]   (по умолчанию ..\out)
"""
import csv
import os
import sys

CSV = "@@ASTORY_DEV_ROOT_FWD@@/AstoryClient/RawAssets/Data/ItemDB/item_list.csv"   # клиентский item_list (грейд)
FILES = {3: "title_hero_p88.txt", 4: "title_legend_p88.txt"}                 # грейд → имя файла


def ranges(codes):
    """Сжать отсортированные коды в диапазоны [lo, hi]."""
    out = []
    for c in codes:
        if out and c == out[-1][1] + 1:
            out[-1][1] = c
        else:
            out.append([c, c])
    return out


def main():
    """Собрать оба файла; вернуть 0 при успехе."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out")
    os.makedirs(out_dir, exist_ok=True)
    by_grade = {3: [], 4: []}
    total = 0
    with open(CSV, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            total += 1
            try:
                g = int(r["ItemGrade"])
                code = int(r["ItemCode"])
            except (KeyError, ValueError):
                continue
            if g in by_grade and code > 0:
                by_grade[g].append(code)
    for g, name in FILES.items():
        codes = sorted(set(by_grade[g]))
        rg = ranges(codes)
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="ascii", newline="\r\n") as w:
            # ★ файл кладётся рядом с сервером — только ASCII (разбор P88 как у announce_codes.txt)
            w.write("# P88: item codes with ItemGrade == %d (%s) from client item_list.csv (%d rows), gen_title_grades_p88.py\n"
                    % (g, "Hero" if g == 3 else "Legend", total))
            w.write("# codes %d, ranges %d\n" % (len(codes), len(rg)))
            for lo, hi in rg:
                w.write(("%d\n" % lo) if lo == hi else ("%d-%d\n" % (lo, hi)))
        print("%s: грейд %d, кодов %d, диапазонов %d" % (path, g, len(codes), len(rg)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
