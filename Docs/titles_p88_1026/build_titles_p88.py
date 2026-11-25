# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""build_titles_p88.py — staging серверных данных под P88 (звания 187–205, задача владельца 26.10.2026).

Что делает (ТОЛЬКО staging, живой сервер только читается — по SSH, шару \\\\@@ASTORY_SERVER_HOSTNAME@@ не трогаем):
  1. забирает по scp живые ConfigSet/FameInfo.txt из GameServer и Indun_GameServer (они побайтно одинаковы);
  2. правит у 18 строк (187…203, 205; 204 не трогается) четыре поля, заменяя ЧИСЛО внутри поля
     (табы, пробел после очков, CRLF и счётчик-заголовок сохраняются):
       кол. 1  включено        0 → 2   (как у всех включённых строк сервера; сервер читает atol != 0)
       кол. 3  порог           1 → GOAL (число из описания звания; без числа — ПРЕДЛОЖЕНИЕ = умолчание ini P88)
       кол. 42 очки славы      0 → POINT (исходный клиент Interlude title_list.Point, title_conflicts.csv)
       кол. 45 накопитель      0 → 1   (иначе прогресс считает зашитый switch: у 188…205 веток нет)
     кол. 43/44 (второй порог «найдено» 1/1) не меняются;
  3. сверяет побайтово с живыми: изменены только заявленные строки и поля;
  4. кладёт рядом таблицы грейдов для 193–198 (tools/gen_title_grades_p88.py) и пишет MANIFEST.txt.

Запуск: python build_titles_p88.py      Импорт ничего не делает (правило tools-no-import-side-effects).
"""
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
V2 = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "Patches", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2: Ch2_GameServer)
FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"]
REL = "ConfigSet/FameInfo.txt"
GEN = os.path.join(HERE, "..", "..", "Patches", "AsdaPatch", "tools", "gen_title_grades_p88.py")

# id: (порог кол. 3, очки кол. 42, источник порога)
TITLES = {
    187: (25, 9, "описание"), 188: (100, 19, "описание"), 189: (1000, 53, "описание"),
    190: (10, 23, "ПРЕДЛОЖЕНИЕ"), 191: (1, 34, "состояние: склад = 270"), 192: (300, 28, "ПРЕДЛОЖЕНИЕ"),
    193: (1, 17, "описание"), 194: (100, 22, "описание"), 195: (500, 57, "описание"),
    196: (1, 29, "описание"), 197: (50, 34, "описание"), 198: (100, 102, "описание"),
    199: (100, 21, "ПРЕДЛОЖЕНИЕ"), 200: (100, 21, "ПРЕДЛОЖЕНИЕ"), 201: (200, 35, "ПРЕДЛОЖЕНИЕ"),
    202: (50, 77, "ПРЕДЛОЖЕНИЕ"), 203: (100, 113, "ПРЕДЛОЖЕНИЕ"), 205: (500, 67, "ПРЕДЛОЖЕНИЕ"),
}
# ожидаемое живое состояние строки (защита от повторного/чужого применения)
EXPECT = {1: "0", 3: "1", 42: "0", 45: "0"}


def md5(b):
    """md5 байтов (hex)."""
    return hashlib.md5(b).hexdigest()


def fetch(folder):
    """scp живого файла в live/<folder>/; вернуть байты."""
    dst = os.path.join(HERE, "live", folder)
    os.makedirs(dst, exist_ok=True)
    out = os.path.join(dst, "FameInfo.txt")
    subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                    "%s:%s/%s/%s" % (SSH_HOST, V2, folder, REL), out], check=True, timeout=120)
    with open(out, "rb") as f:
        return f.read()


def set_field(field, value):
    """Заменить число внутри поля, сохранив окружающие пробелы."""
    lead = field[:len(field) - len(field.lstrip(" "))]
    trail = field[len(field.rstrip(" ")):]
    return lead + str(value) + trail


def patch(data):
    """Вернуть (новые байты, список правок). Бросает при неожиданном исходном состоянии."""
    lines = data.split(b"\r\n")
    edits = []
    seen = set()
    for i in range(1, len(lines)):
        if not lines[i]:
            continue
        cols = lines[i].decode("ascii").split("\t")
        tid = int(cols[0])
        if tid not in TITLES:
            continue
        if len(cols) != 46:
            raise SystemExit("строка %d: колонок %d, ожидалось 46" % (tid, len(cols)))
        for c, want in EXPECT.items():
            if cols[c].strip() != want:
                raise SystemExit("строка %d кол. %d = %r, ожидалось %r (уже применено или чужая правка)" % (tid, c, cols[c], want))
        goal, point, _ = TITLES[tid]
        new = {1: 2, 3: goal, 42: point, 45: 1}
        for c, v in new.items():
            before = cols[c]
            cols[c] = set_field(cols[c], v)
            edits.append((tid, c, before.strip(), str(v)))
        lines[i] = "\t".join(cols).encode("ascii")
        seen.add(tid)
    missing = set(TITLES) - seen
    if missing:
        raise SystemExit("нет строк: %s" % sorted(missing))
    return b"\r\n".join(lines), edits


def verify(old, new):
    """Изменены только строки TITLES и только поля 1/3/42/45."""
    a, b = old.split(b"\r\n"), new.split(b"\r\n")
    assert len(a) == len(b), "число строк изменилось"
    assert a[0] == b[0], "заголовок-счётчик изменился"
    for x, y in zip(a, b):
        if x == y:
            continue
        cx, cy = x.decode("ascii").split("\t"), y.decode("ascii").split("\t")
        assert int(cx[0]) in TITLES and len(cx) == len(cy) == 46, "лишняя строка %r" % x[:20]
        diff = [k for k in range(46) if cx[k] != cy[k]]
        assert set(diff) <= {1, 3, 42, 45}, "лишние поля %s у %s" % (diff, cx[0])


def main():
    """Собрать staging; 0 при успехе."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    man = ["# MANIFEST staging P88 (звания 187–205), build_titles_p88.py", ""]
    blobs = {}
    for folder in FOLDERS:
        old = fetch(folder)
        new, edits = patch(old)
        verify(old, new)
        dst = os.path.join(HERE, folder, "ConfigSet")
        os.makedirs(dst, exist_ok=True)
        with open(os.path.join(dst, "FameInfo.txt"), "wb") as f:
            f.write(new)
        blobs[folder] = new
        man.append("%s/%s: живой md5 %s (%d б) -> новый md5 %s (%d б), правок %d"
                   % (folder, REL, md5(old), len(old), md5(new), len(new), len(edits)))
        print(man[-1])
    assert len(set(blobs.values())) == 1, "FameInfo.txt в папках GameServer разошлись: %s" % sorted(blobs)
    # таблицы грейдов (193–198) — в ConfigSet обеих папок
    for folder in FOLDERS:
        subprocess.run([sys.executable, GEN, os.path.join(HERE, folder, "ConfigSet")], check=True)
    for folder in FOLDERS:
        for name in ("title_hero_p88.txt", "title_legend_p88.txt"):
            with open(os.path.join(HERE, folder, "ConfigSet", name), "rb") as f:
                b = f.read()
            man.append("%s/ConfigSet/%s: новый файл md5 %s (%d б)" % (folder, name, md5(b), len(b)))
    man.append("")
    man.append("id | порог (кол. 3) | очки (кол. 42) | источник порога")
    for tid, (goal, point, src) in sorted(TITLES.items()):
        man.append("%d | %d | %d | %s" % (tid, goal, point, src))
    with open(os.path.join(HERE, "MANIFEST.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(man) + "\n")
    print("MANIFEST.txt записан")
    return 0


if __name__ == "__main__":
    sys.exit(main())
