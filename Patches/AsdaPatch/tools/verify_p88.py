# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p88.py — СТАТИЧЕСКАЯ проверка P88 TitleEvents (события званий 187–205, 2026-10-26).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) функции-хозяева площадок побайтно одинаковы в трёх образах (SendCharDead, Char_FunctionItem_Use, recvDBCraftEnter,
#     sub_546C00, sub_456D90, CharItemPicking, накопитель sub_54A050);
#  2) байты площадок и соседей = константам p88_title_events.cpp; площадки и точки возврата — начала инструкций (линейный
#     дизасм функции); смысл соседей: MAP_TYPE 4 и «убийца != жертва» до A, call AddRoseWarPoint 0x468080 перед A; call
#     sub_4803A0/sub_480F20 перед B1/B2; зажим 0x10E и 5456 перед C; «ответ БД == 1» перед D; call sub_406D90 перед E и
#     call sub_532A90 в E; push 0E0h (224) и call sub_54A050 в F; call sub_54A050 звания 30/31 перед G; все замещённые
#     jmp B1/B2/C ведут на 0x4F0FF4;
#  3) ни один rel8/rel32/jcc32 из .text и ни один abs32 не ведёт ВНУТРЬ площадок (кроме их первого байта);
#  4) другие патчи (p01…p87) адресов внутри площадок P88 не называют и их площадки с P88 не пересекаются;
#  5) DLL: MAP — Tramp A/B1/B2/C/D/E/G, _P88_OnSite@8, @P88_PetLevel@24, P88_GetStats; трамплины зовут только P88_OnSite с
#     номером площадки, повторяют замещённое и уходят только на свой адрес возврата;
#  6) исходники: секция [P88_TitleEvents] (ключи и умолчания), виды 109/110/111 в AcJournal.cpp, P88 после P87 в реестре;
#  7) staging-данные (AstoryServer/Docs/titles_p88_1026): FameInfo отличается от живого только полями 1/3/42/45 у 18 строк,
#     пороги 190/192/199/200/201/202/203/205 = умолчаниям ini.
# Поведение — стенд tools/stand_p88 (3 образа × on/off/mismatch).
# Запуск: python verify_p88.py [AsdaPatch.dll]   (образы — P88_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
import os
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
STG = os.path.join(HERE, "..", "..", "..", "Docs", "titles_p88_1026")
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P88_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

# функции-хозяева (начало, конец)
FUNCS = {"SendCharDead": (0x004CB480, 0x004CBA90), "FunctionItemUse": (0x004EF270, 0x004F1400),
         "recvDBCraftEnter": (0x0053EE30, 0x0053F480), "DigResult": (0x00546C00, 0x00547030),
         "PetExpProcess": (0x00456D90, 0x00457210), "CharItemPicking": (0x004D43A0, 0x004D5E70),
         "Accumulator": (0x0054A050, 0x0054A610)}
# площадки: имя → (va, байты, функция, возврат)
SITES = {"A": (0x004CBA1A, "8d8da8fbffff", "SendCharDead", 0x004CBA20),
         "B1": (0x004EFE7D, "e972110000", "FunctionItemUse", 0x004F0FF4),
         "B2": (0x004EFEDD, "e912110000", "FunctionItemUse", 0x004F0FF4),
         "C": (0x004EFE24, "e9cb110000", "FunctionItemUse", 0x004F0FF4),
         "D": (0x0053EF2A, "8b85a0fbffff", "recvDBCraftEnter", 0x0053EF30),
         "E": (0x00546F8B, "8b55ea52e8fcbafeff", "DigResult", 0x00546F94),
         "F": (0x00456F45, "e806310f00", "PetExpProcess", None),
         "G": (0x004D5CB8, "8b85a0faffff", "CharItemPicking", 0x004D5CBE)}
NEIGHBORS = [(0x004CB8E3, "83f8040f8586010000"), (0x004CB8EC, "0fbf4d100fbf55083bca"), (0x004CBA15, "e866c6f9ff"),
             (0x004CBA20, "e80b150000"), (0x004EFE78, "e82305f9ff"), (0x004EFED8, "e84310f9ff"),
             (0x004EFE64, "668b8560feffff508b8d78fdffff"), (0x004EFD34, "81f90e010000"), (0x004EFE1F, "e8cc2afdff"),
             (0x004EFD10, "0fbf88ae010000"), (0x0053EED8, "0fbe8da8fbffff83f9017446"), (0x0053EF30, "8a8db1fbffff"),
             (0x00546F86, "e805feebff"), (0x00546F94, "83c40485c07436"), (0x00456F33, "68e0000000"),
             (0x004D5CA5, "8b8d10faffff8b51048b4a34e89a430700eb"), (0x004D5CBE, "89850cfaffff"), (0x0054A050, "558bec83ec38")]
INI_DEFAULTS = {"Enabled": "1", "WarKill": "1", "SkillReset": "1", "SkillResetPartial": "1", "WarehouseMax": "1",
                "WarehouseMaxSlots": "270", "Craft": "1", "PotionCodes": "20594-20603;20620-20623",
                "HeroCodesFile": "ConfigSet\\\\title_hero_p88.txt", "LegendCodesFile": "ConfigSet\\\\title_legend_p88.txt",
                "Dig": "1", "ZonesRuins": "1:352:436:20;1:153:286:20", "ZonesShipwreck": "6:350:277:20", "ZonesOasis": "13",
                "DigSowel": "1", "PetLevel": "1", "Pickup": "1", "TicketCodes": "79382", "Threshold190": "10",
                "Threshold192": "300", "Threshold199": "100", "Threshold200": "100", "Threshold201": "200", "Threshold202": "50",
                "Threshold203": "100", "Threshold205": "500", "LogGrant": "1"}
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def disasm(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return list(md.disasm(bytes(img[lo - base:hi - base]), lo))


def scan_refs(pe, img, base, targets, funcs):
    """Ссылки внутрь интервалов targets {имя: (lo, hi)}: rel8/rel32/jcc32 из .text и abs32 по всему образу.
    Источник внутри funcs, не являющийся началом инструкции (линейный дизасм), не считается (второй метод)."""
    a, b = text_range(pe)
    starts = set()
    for lo, hi in funcs:
        starts |= {i.address for i in disasm(img, base, lo, hi)}
    hits = {n: 0 for n in targets}
    for i in range(a, b - 6):
        o = img[i]
        cands = []
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            cands.append(base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0])
        if o in (0xE8, 0xE9):
            cands.append(base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0])
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            cands.append(base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0])
        for t in cands:
            for n, (lo, hi) in targets.items():
                if lo <= t < hi:
                    src = base + i
                    if any(f0 <= src < f1 for f0, f1 in funcs) and src not in starts:
                        continue
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, (lo, hi) in targets.items():
            if lo <= v < hi:
                hits[n] += 1
    return hits


def rel_target(img, base, va):
    """Цель call/jmp rel32 по адресу va."""
    return va + 5 + struct.unpack("<i", bytes(img[va - base + 1:va - base + 5]))[0]


def main():
    print("== verify_p88: DLL %s" % DLL)
    ref = None
    for title, path in GS_IMAGES:
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        body = b"".join(bytes(img[lo - base:hi - base]) for lo, hi in FUNCS.values())
        if ref is None:
            ref = body
        ok(body == ref, "7 функций-хозяев побайтно совпадают с первым образом (%d б)" % len(body))
        g = lambda va, n: bytes(img[va - base:va - base + n])
        starts = {}
        for fn, (lo, hi) in FUNCS.items():
            starts[fn] = {i.address for i in disasm(img, base, lo, hi)}
        for n, (va, hx, fn, back) in SITES.items():
            b = bytes.fromhex(hx)
            ok(g(va, len(b)) == b, "%s 0x%08X: байты стока %s" % (n, va, hx))
            ok(va in starts[fn] and (back is None or back in starts[fn]), "%s: площадка и возврат — начала инструкций %s" % (n, fn))
        for va, hx in NEIGHBORS:
            ok(g(va, len(hx) // 2) == bytes.fromhex(hx), "сосед 0x%08X: %s" % (va, hx))
        ok(rel_target(img, base, 0x004CBA15) == 0x00468080, "A: перед площадкой call AddRoseWarPoint 0x468080")
        ok(rel_target(img, base, 0x004EFE78) == 0x004803A0 and rel_target(img, base, 0x004EFED8) == 0x00480F20,
           "B1/B2: перед площадками call sub_4803A0 (полный сброс) / sub_480F20 (частичный)")
        ok(all(rel_target(img, base, SITES[n][0]) == 0x004F0FF4 for n in ("B1", "B2", "C")), "B1/B2/C: замещённые jmp ведут на 0x4F0FF4")
        ok(rel_target(img, base, 0x00546F86) == 0x00406D90 and rel_target(img, base, 0x00546F8F) == 0x00532A90,
           "E: перед площадкой call sub_406D90, в площадке call sub_532A90 (IsItemCode)")
        ok(rel_target(img, base, 0x00456F45) == 0x0054A050 and rel_target(img, base, 0x004D5CB1) == 0x0054A050,
           "F: call 0x456F45 → sub_54A050 (звание 224); перед G — call sub_54A050 (30/31)")
        sites = {n: (va + 1, va + len(bytes.fromhex(hx))) for n, (va, hx, fn, back) in SITES.items()}
        hits = scan_refs(pe, img, base, sites, list(FUNCS.values()))
        for n in SITES:
            ok(hits[n] == 0, "%s: переходов/abs32 внутрь площадки нет (%d)" % (n, hits[n]))

    print("-- непересечение с другими патчами")
    rx = re.compile(r"0x0*([45][0-9A-Fa-f]{5})\b")
    pdir = os.path.join(SRC, "patches")
    ranges = [(va, va + len(bytes.fromhex(hx))) for va, hx, fn, back in SITES.values()]
    found = []
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or not re.match(r"p\d\d_", fn) or fn.startswith("p88_"):
            continue
        for ln, line in enumerate(open(os.path.join(pdir, fn), encoding="utf-8", errors="replace"), 1):
            for m in rx.finditer(line):
                v = int(m.group(1), 16)
                if any(lo <= v < hi for lo, hi in ranges):
                    found.append((fn, ln, hex(v)))
    ok(not found, "адресов внутри площадок P88 не называет ни один другой патч%s" % ("" if not found else ": " + str(found)))
    src88 = open(os.path.join(pdir, "p88_title_events.cpp"), encoding="utf-8").read()
    for n, (va, hx, fn, back) in SITES.items():
        ok(("0x%08X" % va) in src88, "p88: площадка %s 0x%08X в исходнике" % (n, va))
    for va, hx in NEIGHBORS:
        ok(("0x%08X" % va) in src88 or ("0x%08x" % va) in src88.lower(), "p88: сосед 0x%08X в исходнике" % va)

    print("-- исходники")
    cfgc = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8-sig").read()
    reg = open(os.path.join(pdir, "Registry.cpp"), encoding="utf-8-sig").read()
    sec = cfgc[cfgc.find("const IniKey kTitleEvents[]"):]
    sec = sec[:sec.find("};")]
    keys = dict(re.findall(r'\{ L"(\w+)", L"([^"]*)"', sec))
    ok(keys == INI_DEFAULTS, "секция [P88_TitleEvents]: ключи и умолчания (%d ключей)" % len(keys))
    ok('{ L"P88_TitleEvents",' in cfgc and "kTitleEvents, ARRAYSIZE(kTitleEvents)" in cfgc, "секция в таблице kSections")
    for k in (109, 110, 111):
        ok(len(re.findall(r"case %d: return L\"P88:" % k, acj)) == 1, "AcJournal.cpp: вид ac.other %d — текст P88" % k)
    i87, i88 = reg.find('{ L"P87_Job4StartSkills"'), reg.find('{ L"P88_TitleEvents"')
    ok(0 < i87 < i88, "реестр: P88 после P87")
    for n, (va, hx, fn, back) in SITES.items():
        pass
    goals = {int(k[9:]): int(v) for k, v in INI_DEFAULTS.items() if k.startswith("Threshold")}
    ok(all(("{ k%s, %d, %d }" % (nm, goals[i], goals[i])) in src88 for nm, i in
           (("TSkillReset", 190), ("TPotion", 192), ("TRuins", 199), ("TShip", 200), ("TOasis", 201), ("TPet", 202),
            ("TSowel", 203), ("TTicket", 205))), "p88: умолчания порогов в коде = умолчаниям ini")

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P88_TitleEvents".encode("utf-16-le") in raw, "реестр: строка секции P88_TitleEvents в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 4 and "p88_title_events" in line:
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    onsite = [v for n, v in names.items() if n == "_P88_OnSite@8"]
    pet = [v for n, v in names.items() if n == "@P88_PetLevel@24"]
    ok(onsite and pet and any("P88_TitleEvents" in n for n in names) and any("P88_GetStats" in n for n in names),
       "MAP: _P88_OnSite@8 (stdcall 2 арг.), @P88_PetLevel@24 (fastcall, 16 б в стеке), P88_TitleEvents, P88_GetStats")
    pref = pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def glob(va):
        return struct.unpack("<I", bytes(img[va - pref:va - pref + 4]))[0]

    spec = {"TrampA": (1, 0x004CBA20, "lea ecx, [ebp - 0x458]"), "TrampB1": (2, 0x004F0FF4, None),
            "TrampB2": (3, 0x004F0FF4, None), "TrampC": (4, 0x004F0FF4, None),
            "TrampD": (5, 0x0053EF30, "mov eax, dword ptr [ebp - 0x460]"), "TrampE": (6, 0x00546F94, "mov edx, dword ptr [ebp - 0x16]"),
            "TrampG": (8, 0x004D5CBE, "mov eax, dword ptr [ebp - 0x560]")}
    for title, (site, back, replay) in spec.items():
        va = [v for n, v in names.items() if n.startswith("?%s@" % title)]
        if not va or not onsite:
            ok(False, "%s: нет в MAP" % title)
            continue
        ins = []
        for i in md.disasm(bytes(img[va[0] - pref:va[0] - pref + 0x40]), va[0]):
            ins.append(i)
            if i.mnemonic == "jmp":
                break
        t = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
        ok(t[:5] == ["pushfd ", "pushal ", "push ebp", "push %d" % site, "call 0x%x" % onsite[0]] and t[5:7] == ["popal ", "popfd "],
           "%s: pushfd/pushad; push ebp; push %d; call P88_OnSite; popad/popfd" % (title, site))
        m = re.match(r"dword ptr \[(0x[0-9a-f]+)\]", ins[-1].op_str)
        ok(ins[-1].mnemonic == "jmp" and m and glob(int(m.group(1), 16)) == back, "%s: выход только на 0x%08X" % (title, back))
        if replay:
            ok(replay in t, "%s: повтор замещённого «%s»" % (title, replay))
        if title == "TrampE":
            cl = [i for i in ins[7:] if i.mnemonic == "call"]
            mm = re.match(r"dword ptr \[(0x[0-9a-f]+)\]", cl[0].op_str) if cl else None
            ok(cl and mm and glob(int(mm.group(1), 16)) == 0x00532A90 and "push edx" in t, "TrampE: повтор push edx ; call sub_532A90")

    print("-- staging-данные")
    live = os.path.join(STG, "live", "GameServer", "FameInfo.txt")
    new = os.path.join(STG, "GameServer", "ConfigSet", "FameInfo.txt")
    if os.path.exists(live) and os.path.exists(new):
        a, b = open(live, "rb").read().split(b"\r\n"), open(new, "rb").read().split(b"\r\n")
        diff = {}
        for x, y in zip(a, b):
            if x != y:
                cx, cy = x.decode().split("\t"), y.decode().split("\t")
                diff[int(cx[0])] = [k for k in range(46) if cx[k] != cy[k]]
        ok(len(a) == len(b) and a[0] == b[0] and sorted(diff) == sorted(set(range(187, 206)) - {204})
           and all(set(v) <= {1, 3, 42, 45} for v in diff.values()), "FameInfo staging: только 18 строк 187…205 (кроме 204), поля 1/3/42/45")
        rows = {int(l.decode().split("\t")[0]): l.decode().split("\t") for l in b[1:] if l}
        ok(all(int(rows[i][3]) == v for i, v in goals.items()), "FameInfo staging: пороги без числа в описании = умолчаниям ini")
        ok(open(new, "rb").read() == open(os.path.join(STG, "Indun_GameServer", "ConfigSet", "FameInfo.txt"), "rb").read(),
           "FameInfo staging: GameServer = Indun")
    else:
        ok(False, "staging не собран (build_titles_p88.py)")
    print("== ИТОГ verify_p88: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
