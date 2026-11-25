# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_job4_rows.py — staging ChangeJobAddSkillTable.txt со строками 6/17/28 (стартовые навыки 4-й профессии
#   Рыцарь / Капканщик / Жрец) для GameServer и Indun_GameServer. 26.10.2026, отчёт Reports/job4/START_SKILLS_6_17_28.md.
#
# Строки НЕ вписаны руками — выводятся признаком и признак проверяется на известных строках 4/15/26 (метод):
#   стартовая строка подкласса = узлы ПЕРВОГО РЯДА дерева 4-й профессии своей полосы:
#     клиент skill_info.sif (273 б): дерево +0xBD == 10/11/12 (полоса бойца/лучника/мага), ряд +0xBC == 0, колонка +0xBB 0..4;
#     сервер SkillInfo.sif (209 б): категория +189 == та же, порог очков +190 == 0, предшественников нет (+200/+203/+206 = −1),
#       маска классов +123 содержит подкласс.
#   Проверка метода: признак обязан дать РОВНО строки 4/15/26 живой таблицы (617 619 632 633 634 / 826 828 841 842 843 /
#   1050 1051 1062 1065 1066), иначе сборка падает (код 3). Дерево 4-й профессии у подклассов одной полосы ОДНО и то же
#   (эталон skillRebuildPageLists@0xE541E0 отбирает по полосе: grade 10/11/12; подкласс меняет только подпись вкладки 9422…9427),
#   поэтому строка 6 = строке 4, 17 = 15, 28 = 26.
# Формат как у стока: TAB-разделители, 36 полей (id, число, 34 кода с хвостом пустых), CRLF; прежние 12 строк — байт в байт,
#   новые три дописываются в конец (порядок строк загрузчику безразличен: id → запись id−1, GameServer.c:71655).
# Запуск: python build_job4_rows.py [--src <живая ChangeJobAddSkillTable.txt>]  (по умолчанию — зеркало стойки srv_mirror).
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MIRROR = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches\AsdaPatch\tools\_srv_mirror\v2"
CLIENT_SIF = r"@@ASTORY_DEV_ROOT@@\AstoryClient\RawAssets\Data\Character\skill_info.sif"   # = Bin.bbz MINE (md5 d412ea82)
SERVER_SIF = MIRROR + r"\GameServer\SkillTable_Info\SkillInfo.sif"                    # живой = сток 1acb5eaa
LIVE_MD5 = "8e0cd3a44563ab0162505b6a924fc848"                                         # живая таблица = сток (12 строк)
KNOWN = {4: [617, 619, 632, 633, 634], 15: [826, 828, 841, 842, 843], 26: [1050, 1051, 1062, 1065, 1066]}
PAIRS = {6: (4, 10), 17: (15, 11), 28: (26, 12)}      # подкласс → (подкласс-образец той же полосы, дерево/категория)
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "Server", "Patches", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/REPORT.md §3.1
FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"]


def first_row(tree, subjob):
    """Узлы первого ряда дерева 4-й профессии (порядок — по колонке, как в сетке окна навыков)."""
    cli = open(CLIENT_SIF, "rb").read()
    srv = open(SERVER_SIF, "rb").read()
    S = {struct.unpack_from("<h", srv, 209 * i)[0]: srv[209 * i:209 * i + 209] for i in range(len(srv) // 209)}
    out = []
    for i in range(len(cli) // 273):
        r = cli[273 * i:273 * i + 273]
        code = struct.unpack_from("<h", r, 0)[0]
        if r[0xBD] != tree or r[0xBC] != 0 or r[0xBB] > 4:
            continue
        s = S.get(code)
        if s is None:
            raise SystemExit("нет навыка %d в серверном SkillInfo.sif" % code)
        pre = [struct.unpack_from("<h", s, o)[0] for o in (200, 203, 206)]
        mask = struct.unpack_from("<Q", s, 123)[0]
        if s[189] != tree or s[190] != 0 or pre != [-1, -1, -1] or not (mask >> subjob) & 1:
            raise SystemExit("навык %d: сервер кат %d порог %d пред %s маска %x — не стартовый" % (code, s[189], s[190], pre, mask))
        out.append((r[0xBB], code))
    return [c for _, c in sorted(out)]


def main():
    src = sys.argv[sys.argv.index("--src") + 1] if "--src" in sys.argv else MIRROR + r"\GameServer\SkillTable_Info\ChangeJobAddSkillTable.txt"
    raw = open(src, "rb").read()
    if hashlib.md5(raw).hexdigest() != LIVE_MD5:
        print("живая таблица %s md5 %s ≠ ждём %s — сначала сверить, что на стойке" % (src, hashlib.md5(raw).hexdigest(), LIVE_MD5))
        return 2
    lines = raw.split(b"\r\n")
    assert lines[-1] == b"" and all(len(l.split(b"\t")) == 36 for l in lines[:-1]), "формат стока: 36 полей, CRLF"
    rows = {int(l.split(b"\t")[0]): [int(x) for x in l.split(b"\t")[2:] if x.strip()] for l in lines[:-1]}
    # ── проверка метода на известных строках ──
    for sj, want in KNOWN.items():
        tree = {4: 10, 15: 11, 26: 12}[sj]
        got = first_row(tree, sj)
        if sorted(got) != sorted(want) or rows.get(sj) != want:
            print("МЕТОД НЕ СХОДИТСЯ: подкласс %d признак %s, в таблице %s" % (sj, got, rows.get(sj)))
            return 3
        print("[OK] метод: подкласс %2d — признак даёт %s = строке таблицы" % (sj, " ".join(map(str, got))))
    if any(sj in rows for sj in PAIRS):
        print("в таблице уже есть строки %s — пересборка не нужна" % [sj for sj in PAIRS if sj in rows])
        return 4
    # ── новые строки ──
    add = []
    for sj, (ref, tree) in PAIRS.items():
        codes = first_row(tree, sj)
        ref_codes = rows[ref]
        if sorted(codes) != sorted(ref_codes):
            print("подкласс %d: признак %s ≠ строке %d %s" % (sj, codes, ref, ref_codes))
            return 3
        fields = [str(sj).encode(), str(len(ref_codes)).encode()] + [str(c).encode() for c in ref_codes]   # порядок кодов — как в строке-образце
        fields += [b""] * (36 - len(fields))
        add.append(b"\t".join(fields))
        print("[OK] строка %2d (по образцу %2d, дерево %d): %s" % (sj, ref, tree, " ".join(map(str, ref_codes))))
    new = raw + b"\r\n".join(add) + b"\r\n"
    for f in FOLDERS:
        d = os.path.join(HERE, f, "SkillTable_Info")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "ChangeJobAddSkillTable.txt"), "wb").write(new)
    md5 = hashlib.md5(new).hexdigest()
    with open(os.path.join(HERE, "MANIFEST.txt"), "w", encoding="utf-8", newline="\r\n") as m:
        m.write("job4_start_skills_1026 — staging; сборка build_job4_rows.py; живой сервер этим скриптом НЕ изменяется\n\n")
        for f in FOLDERS:
            m.write("%s/SkillTable_Info/ChangeJobAddSkillTable.txt\n" % f)
            m.write("  живой  : %d б  md5 %s (12 строк: 1 2 3 4 12 13 14 15 23 24 25 26)\n" % (len(raw), LIVE_MD5))
            m.write("  staging: %d б  md5 %s (15 строк: + 6 17 28 в конце, прежние 12 — байт в байт)\n" % (len(new), md5))
        for l in add:
            m.write("  + " + l.rstrip(b"\t").decode().replace("\t", " ") + "\n")
        m.write("\nПрименение: apply_job4_rows.py (SSH; по умолчанию сухой прогон). Проверка: verify_job4_rows.py.\n")
    print("staging: %d б md5 %s → %s" % (len(new), md5, ", ".join(FOLDERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
