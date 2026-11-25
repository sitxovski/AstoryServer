# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# gen_name_corpus_p68.py — корпус имён персонажа для P68 (GameServer) и A13 (SQL): одни и те же байты, один ожидаемый вердикт.
#   Строка корпуса: <charset 0|1> <правило 0..4> <hex байтов имени (без нуля; пусто = "-")> <пояснение>
#   Правила (как P68_NameVerdict и dbo.fn_A13_NameRule): 0 допустимо, 1 пусто, 2 нет нуля в 20 б (≥ 20 б), 3 управляющий байт,
#   4 символ вне правил локали (charset 0: A-Z a-z 0-9; charset 1: + локали 7/8 оригинала и кодеки порта).
#   Честная часть = что пропустил бы клиент: эталон (A-Z a-z 0-9, ≤ 19 б при смене имени / ≤ 18 при создании), порт
#   asda.Text.NameLocale 0 (то же), порт NameLocale 1 (кириллица cp1251 / UTF-8 «похожие на UTF-8», арабица 0x98+cp1256),
#   оригинальные клиенты локалей 7/8 (cp1251 / cp1256 без маркера).
# Запуск: python gen_name_corpus_p68.py [выход]  (по умолчанию name_corpus_p68.txt рядом). Побочных эффектов при импорте нет.
import os
import random
import sys

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
CYR = [chr(c) for c in range(0x0410, 0x0450)] + ["Ё", "ё"]
AR_BYTES = [b for b in range(0xC0, 0x100) if b != 0xD7]          # case 8 оригинала
AR = [bytes([b]).decode("cp1256") for b in AR_BYTES]


def is_strict_utf8_multi(bs):
    """Как FAsdaLoginData::IsStrictUtf8(..., bAllowTruncTail=true) && bMulti — упрощённо: валидный UTF-8 с ≥1 многобайтной."""
    try:
        s = bs.decode("utf-8")
    except UnicodeDecodeError:
        # допуск обрубка-хвоста: отрезать до 3 байт с конца
        for k in (1, 2, 3):
            try:
                s = bs[:-k].decode("utf-8")
                return any(ord(c) > 0x7F for c in s)
            except UnicodeDecodeError:
                pass
        return False
    return any(ord(c) > 0x7F for c in s)


def port_wire(name):
    """Кодек провода порта (asda.Text.WireCodec 1): cp1251 / UTF-8 (если cp1251 «похоже на UTF-8») / 0x98+cp1256 / UTF-8."""
    try:
        b = name.encode("cp1251")
        return name.encode("utf-8") if is_strict_utf8_multi(b) else b
    except UnicodeEncodeError:
        pass
    try:
        return b"\x98" + name.encode("cp1256")
    except UnicodeEncodeError:
        return name.encode("utf-8")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "name_corpus_p68.txt")
    rnd = random.Random(20261013)
    rows = []

    def add(cs, rule, bs, why):
        rows.append((cs, rule, bs, why))

    # ── честные: эталон / порт NameLocale 0 — допустимы при обоих charset ──
    for nm in ("123123", "sitxovski", "sitx", "Rimy", "A", "z", "0", "Z" * 19, "a1B2c3D4e5F6g7H8i9J", "GMsitx", "Okaygood"):
        for cs in (0, 1):
            add(cs, 0, nm.encode(), "честное ASCII " + nm)
    for i in range(1500):
        nm = "".join(rnd.choice(ALNUM) for _ in range(rnd.randint(1, 19)))
        for cs in (0, 1):
            add(cs, 0, nm.encode(), "случайное ASCII")
    # ── честные charset 1: порт NameLocale 1 и оригиналы локалей 7/8 ──
    for i in range(1500):
        nm = "".join(rnd.choice(CYR + list(ALNUM[:10])) for _ in range(rnd.randint(1, 18)))
        bs = port_wire(nm)
        if len(bs) <= 19:
            add(1, 0, bs, "порт: кириллица (%s)" % ("utf8" if bs != nm.encode("cp1251") else "cp1251"))
        add(1, 0, nm.encode("cp1251"), "оригинал case 7: cp1251")
    for i in range(1500):
        nm = "".join(rnd.choice(AR + list(ALNUM)) for _ in range(rnd.randint(1, 18)))
        bs = port_wire(nm)
        if len(bs) <= 19:
            add(1, 0, bs, "порт: арабица (маркер 0x98)" if bs[:1] == b"\x98" else "порт: арабица (cp1251-совместимо)")
        add(1, 0, nm.encode("cp1256"), "оригинал case 8: cp1256 без маркера")
    # Явные «похожие на UTF-8» русские имена (ревизия С1 порта): РЁ, Сё, ЯЁ
    for nm in ("РЁма", "Сёма", "ЯЁж", "ЁЁЁ", "РЁРЁРЁРЁРЁ"):
        bs = port_wire(nm)
        if len(bs) <= 19:      # порт не пустит длиннее 19 б (WireTextByteLen); «РЁ»×5 в UTF-8 = 20 б — в нарушения ниже
            add(1, 0, bs, "порт: «похоже на UTF-8» " + bs.hex())
        else:
            add(1, 2, bs[:20], "порт отказал бы (> 19 б): " + bs.hex())
    # ── нарушения: при обоих charset ──
    for cs in (0, 1):
        add(cs, 1, b"", "пусто")
        add(cs, 2, b"A" * 20, "20 б без нуля")
        add(cs, 2, b"Z" * 20, "20 б без нуля")
        for c in list(range(1, 32)) + [0x7F]:
            add(cs, 3, b"Ab" + bytes([c]) + b"cd", "управляющий 0x%02X" % c)
        add(cs, 3, b"\x7f", "один 0x7F")
        for ch in b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
            add(cs, 4, b"Name" + bytes([ch]) + b"x", "знак 0x%02X" % ch)
        add(cs, 4, b"GM_sitxovski", "имя оператора с '_' (так в dev-БД, создано мимо клиента)")
        add(cs, 4, b"GM_Rimy", "имя оператора с '_'")
        add(cs, 4, b"ADM_sitxovski", "имя оператора с '_'")
        add(cs, 4, b"Bob ", "хвостовой пробел")
        add(cs, 4, b" Bob", "ведущий пробел")
        add(cs, 4, b"Bo`b", "обратная кавычка (P28 так меняет апостроф)")
    # ── нарушения charset 0, допустимые в charset 1 ──
    for bs, why in ((b"\xc0\xc1\xc2", "cp1251 «АБВ»"), (b"Ab\xa8", "Ё"), (b"\x98\xc7\xe1", "маркер+арабица"),
                    ("Ша".encode("utf-8"), "UTF-8 кириллица")):
        add(0, 4, bs, "charset 0: " + why)
        add(1, 0, bs, "charset 1: " + why)
    # ── нарушения charset 1 ──
    for bs, why in ((b"Ab\x80", "0x80 одиночный"), (b"A\x98b", "маркер не в начале"), (b"\x98", "один маркер"),
                    (b"\xa0\xa0", "NBSP cp1251"), (b"\xb0x", "0xB0"), (b"\xd0\x80\x80", "UTF-8: лишнее продолжение"), (b"\xe2\x80", "оборванный 3-байтный UTF-8"),
                    (b"\xd0\x80", "UTF-8 U+0400 (нет в правилах)"),
                    ("Ω".encode("utf-8"), "UTF-8 греческая"), ("Ａ".encode("utf-8"), "UTF-8 полноширинная A (двойник)"),
                    ("​".encode("utf-8") + b"Bob", "UTF-8 пробел нулевой ширины"), (b"\xe0\x80\xc1", "избыточная форма UTF-8"),
                    (b"\x98\xc7\x80", "маркер + 0x80")):
        add(1, 4, bs, "charset 1: " + why)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for cs, rule, bs, why in rows:
            f.write("%d %d %s %s\n" % (cs, rule, bs.hex() if bs else "-", why))
    print("корпус: %d строк -> %s" % (len(rows), out))


if __name__ == "__main__":
    main()
