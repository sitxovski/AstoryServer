# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# monster_ai_quests_data.py — генератор новых Monster.ai: лишний зачёт заданий за чужих мобов (06.11.2026).
#
# Решение владельца 06.11.2026: прогресс задания идёт только за его цель; это ИЗМЕНЕНИЕ ДАННЫХ ОРИГИНАЛА
#   (записи есть в стоке 2012 года). Отчёт: Reports/quest_mobs/QUEST_STRAY_CREDIT.md.
# Как считает сервер (NpcServer sub_437A30): перебор 5 записей типа моба с +403 (по 12 б: i32 задание, u8 стадия,
#   i16 MCT, i32 предмет, i8 шанс), конец — задание == -1; сравниваются только задание и стадия слота, карта и цель
#   не проверяются. Поэтому запись убирается СО СДВИГОМ следующих вверх, хвост — 12 байт FF.
# База — снимки живых файлов (data_monster_ai_quests/base). Две базы: 5 копий одинаковы, у Indun_GameServer нет части
#   записей (выкладка 12.09 в него не попала); его отличия сохраняются: правка идёт по записям, а не копией файла.
# Запуск: python monster_ai_quests_data.py build | verify. Без побочных эффектов при импорте.
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                         # папка инструментов
DATA = os.path.join(HERE, "data_monster_ai_quests")                       # база и новые файлы
REC = 479                                                                  # длина записи моба
ENT0 = 403                                                                 # смещение первой квест-записи
ENT = 12                                                                   # длина квест-записи
NENT = 5                                                                   # записей у моба
EMPTY = b"\xff" * ENT                                                      # пустая запись (конец перебора)

# База → имя файла базы и нового файла.
BASES = {"42106585299fe4b1c8125a3cf54868dd": "Monster_42106585",           # NpcServer ×3, GameServer, Ch2_GameServer
         "d09877a0be3ea6ea0f0e9e6cc35925b9": "Monster_d09877a0"}           # Indun_GameServer

# (задание, стадия) → типы мобов, у которых запись убирается. Цели задания здесь нет.
REMOVE = {
    # Группа 1: одиночные чужие мобы при живой цели.
    (310, 1): [290, 433, 434, 435],      # цель Violent Panic Parasol; King Spade и боссы t_Palace_of_Queen
    (319, 0): [434],                     # цель Duck Hammer
    (171, 0): [602],                     # цель Violent FangMushroomMan
    (349, 0): [59, 60],                  # цель StripeParasol
    (325, 0): [603],                     # цель PunchRat
    (360, 0): [614],                     # цель Demon Claw
    (317, 0): [567],                     # цель Bad SpottedPickle
    # Группа 2: вторая охотничья зона.
    (178, 0): [265, 627, 628, 646, 654], # цель Ruby Parrot
    (183, 0): [265, 627, 628, 646, 654], # цель Ruby Parrot
    (190, 0): [625, 626, 645, 653],      # цель Metal Helmet Slime
    (195, 0): [265, 627],                # цель Ruby Parrot
    (377, 0): [103, 104, 505, 661],      # цель Violent Duck Hammer
    (390, 0): [420, 421, 518, 519],      # цель Violent Minortos
    (391, 0): [422, 423, 520, 521],      # цель Lios
    (147, 0): [661],                     # цель Shaman Viter
    (383, 0): [113, 114, 662],           # цель Mottle Cogwheel
    (419, 0): [364, 365],                # цель Vicious PatchLinks
    (300, 0): [452, 456],                # предмет 31033: цель Steel Mouse Royd
    # Группа 2, Mt. Flamion: гид и текст этих заданий переведены на настоящие цели (Flammio, Night_Valley) решением владельца.
    (392, 0): [633, 634, 649, 657],      # цель FireGolem, Flammio
    (393, 0): [266, 629, 630, 647, 655], # цель Junkman, Flammio
    (395, 0): [643, 644],                # цель Snider, Night_Valley
    (396, 0): [271, 639, 640, 652, 660], # цель FlameGolem, Flammio
    (397, 0): [592],                     # решение владельца 06.11: зачёт переходит дракону 761, см. ADD
}

# Новые записи (решение владельца 06.11): тип моба → (задание, стадия, MCT, предмет, шанс). Ставятся на первую пустую запись.
ADD = {761: [(397, 0, 229, 31141, 100)],                       # Enkidu в DragonLaiR; тип 568 спавна не имеет
       59: [(126, 0, 59, 21155, 100)], 60: [(126, 0, 59, 21155, 100)],   # крысы-боксёры: условие 126 требовало их предмет, зачёта не было
       75: [(95, 0, 55, 21156, 100)], 76: [(95, 0, 55, 21156, 100)]}     # палачи Conquester; HangMan Outlaw 178/179 спавна не имеет

# (тип моба, задание) → (стадия была, стадия стала): King Spade по тексту 398 считается на стадии 0.
RESTEP = {(290, 398): (1, 0)}


def md5b(data):
    """md5 байтов (hex)."""
    return hashlib.md5(data).hexdigest()


def entries(data, pos):
    """Пять квест-записей моба из записи с началом pos (сырые байты)."""
    return [bytes(data[pos + ENT0 + ENT * k: pos + ENT0 + ENT * (k + 1)]) for k in range(NENT)]


def decode(blob):
    """Квест-запись → (задание, стадия)."""
    return struct.unpack_from("<i", blob, 0)[0], blob[4]


def index(data):
    """Тип моба → смещение записи."""
    out = {}
    for pos in range(0, len(data), REC):
        out[struct.unpack_from("<i", data, pos)[0]] = pos
    return out


def credits(data):
    """Множество (моб, задание, стадия, предмет, шанс) по правилу sub_437A30: перебор до задания == -1."""
    out = set()
    for mob, pos in index(data).items():
        for blob in entries(data, pos):
            q, st = decode(blob)
            if q == -1:
                break
            if q == 0:
                continue                                           # заглушка оригинала (задание 0, стадия 255): зачёта не даёт
            out.add((mob, q, st, struct.unpack_from("<i", blob, 7)[0], struct.unpack_from("<b", blob, 11)[0]))
    return out


def patch(base):
    """Новый файл из базы; возврат (байты, список отсутствующих в базе записей)."""
    data = bytearray(base)
    idx = index(base)
    missing = []
    for (quest, stage), mobs in REMOVE.items():
        for mob in mobs:
            pos = idx[mob]
            cur = entries(data, pos)
            keep = [b for b in cur if decode(b) != (quest, stage)]
            if len(keep) == NENT:
                missing.append((mob, quest, stage))
                continue
            keep += [EMPTY] * (NENT - len(keep))
            data[pos + ENT0: pos + ENT0 + ENT * NENT] = b"".join(keep)
    for mob, rows in ADD.items():
        pos = idx[mob]
        for quest, stage, mct, item, rate in rows:
            cur = entries(data, pos)
            free = [k for k, b in enumerate(cur) if decode(b)[0] == -1]
            if not free:
                missing.append((mob, quest, stage))
                continue
            data[pos + ENT0 + ENT * free[0]: pos + ENT0 + ENT * (free[0] + 1)] = (
                struct.pack("<i", quest) + bytes([stage]) + struct.pack("<h", mct) + struct.pack("<i", item) + struct.pack("<b", rate))
    for (mob, quest), (was, now) in RESTEP.items():
        pos = idx[mob]
        hits = [k for k, b in enumerate(entries(data, pos)) if decode(b) == (quest, was)]
        if len(hits) != 1:
            missing.append((mob, quest, was))
            continue
        data[pos + ENT0 + ENT * hits[0] + 4] = now
    return bytes(data), missing


def expected(old):
    """Ожидаемое множество зачётов нового файла: старое минус убранное, с заменой стадии."""
    out = set()
    for mob, q, st, item, rate in old:
        if mob in REMOVE.get((q, st), []):
            continue
        if (mob, q) in RESTEP and RESTEP[(mob, q)][0] == st:
            st = RESTEP[(mob, q)][1]
        out.add((mob, q, st, item, rate))
    for mob, rows in ADD.items():
        out |= {(mob, q, st, item, rate) for q, st, _mct, item, rate in rows}
    return out


def verify_pair(base, new):
    """Сверка пары файлов; возврат списка ошибок."""
    bad = []
    if len(base) != len(new):
        bad.append("длина изменилась")
    for i in range(min(len(base), len(new))):
        if base[i] != new[i] and not ENT0 <= i % REC < ENT0 + ENT * NENT:
            bad.append("байт вне квест-записей: %d" % i)
            break
    if credits(new) != expected(credits(base)):
        bad.append("зачёты нового файла ≠ ожидаемым")
    return bad


def read(name):
    """Байты файла из папки данных."""
    with open(os.path.join(DATA, name), "rb") as f:
        return f.read()


def build():
    """Собрать новые файлы из баз; печатает md5."""
    rc = 0
    for want, name in BASES.items():
        base = read(os.path.join("base", name + ".ai"))
        if md5b(base) != want:
            print("СТОП: база %s = %s" % (name, md5b(base)))
            return 1
        new, missing = patch(base)
        with open(os.path.join(DATA, name + ".new.ai"), "wb") as f:
            f.write(new)
        bad = verify_pair(base, new)
        print("%s → %s: зачётов %d → %d; нет в базе %s; ошибки %s" % (want[:8], md5b(new), len(credits(base)), len(credits(new)), missing, bad))
        rc = rc or (1 if bad or missing else 0)
    return rc


def main():
    """Точка входа: build или verify."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if len(sys.argv) > 1 and sys.argv[1] == "build":
        return build()
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        rc = 0
        for want, name in BASES.items():
            bad = verify_pair(read(os.path.join("base", name + ".ai")), read(name + ".new.ai"))
            print(name, "OK" if not bad else bad)
            rc = rc or (1 if bad else 0)
        return rc
    print("использование: monster_ai_quests_data.py build | verify")
    return 2


if __name__ == "__main__":
    sys.exit(main())
