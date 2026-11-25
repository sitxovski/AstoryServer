# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stand_n22_load.py — драйвер стенда stand_n22l (31.10.2026, bug-quest-follow): установка N22 на настоящем образе NpcServer
#   при разных таблицах. Каждый случай — своя папка (текущая папка процесса стенда, как у NpcServer) с Quest\QuestNpcTable.Bin,
#   ConditionTable.Bin и вариантом QuestNpcTableExt.Bin; копия у exe — Quest\ рядом со стендом (только в случае «копии»).
#   Ожидание: годная таблица — установка 0 (Applied), площадки переписаны (A/C imm8 7F, B/D call E8); любой дефект — 3 (Failed),
#   площадки стока не тронуты.
# Запуск: py -3 stand_n22_load.py [AddonNPC.dll]
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
DLL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll"))
EXE = r"@@ASTORY_DEV_ROOT@@\RE\ida\npc_work\NpcServer.exe"
STAND_DIR = os.path.join(HERE, "stand_n22l")
STAND = os.path.join(STAND_DIR, "stand_n22l.exe")
DATA = os.path.join(HERE, "..", "..", "AsdaPatch", "tools", "data_quest_turnin")
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "AsdaReborn", "Tools"))
import asda_quest_cells_ext as QX

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


if not os.path.exists(STAND) or os.path.getmtime(STAND) < os.path.getmtime(os.path.join(STAND_DIR, "stand_n22l.cpp")):
    r = subprocess.run(["cmd", "/c", os.path.join(STAND_DIR, "build_stand.bat")], capture_output=True)
    if r.returncode != 0:
        print(r.stdout.decode("cp866", "replace")[-800:])
        sys.exit(2)
qnt = open(os.path.join(DATA, "QuestNpcTable.Bin"), "rb").read()
ct = open(os.path.join(DATA, "ConditionTable.Bin"), "rb").read()
good = open(os.path.join(DATA, QX.FILE_NAME), "rb").read()
rows = QX.parse(good)
n_npc, n_cond = len(qnt) // 1774, len(ct) // 146


def variant(fn):
    r = [dict(x) for x in rows]
    fn(r)
    return QX.build(r) if all(QX.SLOT_MIN <= x["slot"] <= QX.SLOT_MAX for x in r) else None


def with_key(r, key):
    c = bytearray(r[0]["cell"])
    struct.pack_into("<i", c, 68, key)
    r[0]["cell"] = bytes(c)


over = bytearray(good)
struct.pack_into("<I", over, 8, 1 + (1 << 27))     # 16 + 96·n ≡ размеру по модулю 2^32 — без проверки n до умножения прошло бы
CASES = [
    # (имя, байты таблицы или None — нет файла, копия у exe или None, ожидаемый код установки)
    ("годная таблица (96 у Эллосы, слот 10)", good, None, 0),
    ("нет QuestNpcTableExt.Bin", None, None, 3),
    ("нет шапки QNTX", b"XXXX" + good[4:], None, 3),
    ("версия 2", good[:4] + struct.pack("<I", 2) + good[8:], None, 3),
    ("размер ≠ 16 + 96·N", good + b"\0", None, 3),
    ("переполнение 16 + 96·N (N = 2^27 + 1)", bytes(over), None, 3),
    ("NPC = числу записей QuestNpcTable (%d)" % n_npc, variant(lambda r: r[0].update(npc=n_npc)), None, 3),
    ("ключ = числу записей ConditionTable (%d)" % n_cond, variant(lambda r: with_key(r, n_cond)), None, 3),
    ("ключ = последней записи ConditionTable (%d) — годен" % (n_cond - 1), variant(lambda r: with_key(r, n_cond - 1)), None, 0),
    ("повтор (npc, вид, слот)", QX.build(rows) [:8] + struct.pack("<I", 2) + QX.build(rows)[12:] + QX.build(rows)[16:], None, 3),
    ("копия у exe совпадает", good, good, 0),
    ("копия у exe ДРУГАЯ", good, variant(lambda r: r[0].update(slot=11)), 3),
]
root = tempfile.mkdtemp(prefix="stand_n22l_")
print("== стенд загрузки N22: образ %s, DLL %s" % (os.path.basename(EXE), DLL))
try:
    for i, (name, tbl, exe_copy, want) in enumerate(CASES):
        case = os.path.join(root, "c%02d" % i)
        os.makedirs(os.path.join(case, "Quest"))
        open(os.path.join(case, "Quest", "QuestNpcTable.Bin"), "wb").write(qnt)
        open(os.path.join(case, "Quest", "ConditionTable.Bin"), "wb").write(ct)
        if tbl is not None:
            open(os.path.join(case, "Quest", QX.FILE_NAME), "wb").write(tbl)
        sq = os.path.join(STAND_DIR, "Quest")
        shutil.rmtree(sq, ignore_errors=True)
        if exe_copy is not None:
            os.makedirs(sq)
            open(os.path.join(sq, QX.FILE_NAME), "wb").write(exe_copy)
        p = subprocess.run([STAND, EXE, DLL], cwd=case, capture_output=True, timeout=60)
        out = p.stdout.decode("utf-8", "replace")
        res = [int(l.split()[1]) for l in out.splitlines() if l.startswith("RESULT")]
        sites = {l.split()[1]: l.split()[2:] for l in out.splitlines() if l.startswith("SITE")}
        patched = sites.get("420CB9", [""] * 6)[5] == "7F" and sites.get("420D3A", [""])[0] == "E8" \
            and sites.get("4210AD", [""] * 6)[5] == "7F" and sites.get("42112E", [""])[0] == "E8"
        stock = sites.get("420CB9", [""] * 6)[5] == "09" and sites.get("420D3A", [""])[0] == "0F" \
            and sites.get("4210AD", [""] * 6)[5] == "09" and sites.get("42112E", [""])[0] == "0F"
        got = res[0] if res else None
        ok(p.returncode == 0 and got == want and (patched if want == 0 else stock),
           "%s: установка %s (ждали %d), площадки %s" % (name, got, want, "переписаны" if patched else "сток" if stock else "?? " + str(sites)))
finally:
    shutil.rmtree(os.path.join(STAND_DIR, "Quest"), ignore_errors=True)
    shutil.rmtree(root, ignore_errors=True)
print("== ИТОГ stand_n22_load: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
