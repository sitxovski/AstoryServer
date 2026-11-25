# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p75.py — СТАТИЧЕСКАЯ проверка P75 «Зелье повышения уровня» (предмет 558, 2026-10-19).
#
# Сервер НЕ запускается. Грузятся настоящие образы GameServer (сток 4e20f0ad, живой GameServer = Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) md5 образов; исходные байты всех 6 площадок и соседей (аргументы, продолжения, общий выход отказа 0x4EF0C3, чтение +37
#     @0x4EF61D, пролог Recv_BattleServerFromCharParamExp_1, cmp потолка P29 @0x4CBB61); цели вызовов площадок; ret функций-
#     получателей (0x4F27F0/0x4F2640 — 8, SendPacket — 18h, sub_52E6D0 — 14h, кувшин 0x495790 — 10h, 0x4CBA90 — 18h);
#  2) в .text ни один переход и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и продолжения на границах инструкций;
#  3) ★ второй метод для «+37 читается один раз»: скан всех `mov r32,[0x5F5E70]` и ближайшего обращения с двумя регистрами —
#     смещение 0x25 только у загрузчика (запись @0x4B0182) и у шага 2 (@0x4EF61D); у остальных площадок функции P75 — свои
#     получатели (call rel32), без соседей по общим точкам других патчей (grep площадок P01…P74 по src/patches);
#  4) вызовы Recv_BattleServerFromCharParamExp_1 с a5 = 1 (награды) — образец режима P75 (a3 = 0, a6 = 1.0f);
#  5) в DLL: заглушки по .map, g_p* = адреса стока, форма заглушек (хвостовой переход / ret N), экспорт P75_GetStats.
#  ★ ред. 2: площадка S 0x4EF02E (уход 2140 «Use» в БД → замок «зелье в пути») и площадка выхода 0x527374 (ClearUserMemory,
#     общая точка с P63 SessionClear — P75 пишет её, только если P63 не держит); получатели 0x5646C0 (ret 14h), 0x569DF0 (cdecl),
#     геттер Charidx 0x532530 (CUser+0x18C, ret 4); тело 2140: +2 Userindex, +6 Charidx, +7 код (кадр [ebp-118h]).
# Запуск: python verify_p75.py [AsdaPatch.dll]   (P75_IMG_DIR=<папка с gs_stock.exe/gs_live.exe/gs_indun.exe>)
import glob
import hashlib
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
SRC = os.path.join(HERE, "..", "src", "patches")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe", "4e20f0ad0b13a54454405eed31ffe447"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe", "e7b4ac38"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe", "e7b4ac38"),
]
if os.environ.get("P75_IMG_DIR"):
    d = os.environ["P75_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe", "4e20f0ad0b13a54454405eed31ffe447"),
                 ("живой GameServer", d + "/gs_live.exe", "e7b4ac38"),
                 ("живой Indun", d + "/gs_indun.exe", "e7b4ac38")]

BASE = 0x00400000
SITES = [  # (имя, va, байты, цель call)
    ("U шаг 1 Char_FunctionItem_Use", 0x004EDDC7, "e8244a0000", 0x004F27F0),
    ("D шаг 2 sub_4EF270", 0x004EF606, "e835300000", 0x004F2640),
    ("4036 себе", 0x004CBFEC, "e8ff68ffff", 0x004C28F0),
    ("4036 сектору", 0x004CC009, "e8c2260600", 0x0052E6D0),
    ("кувшин (уровень)", 0x004CC08D, "e8fe96fcff", 0x00495790),
    ("кувшин (опыт)", 0x004CC27E, "e80d95fcff", 0x00495790),
    ("S уход 2140 в БД", 0x004EF02E, "e88d560700", 0x005646C0),
    ("выход ClearUserMemory", 0x00527374, "e8772a0400", 0x00569DF0),
]
NEIGHBOURS = [
    ("U аргументы 0x4EDDB5 (код [ebp-16Ch], номер [ebp+8], this [ebp-2F8h])", 0x004EDDB5, "8b8594feffff50668b4d08518b8d08fdffff"),
    ("U продолжение 0x4EDDCC (test; jne 0x4EDDE1; код 8; jmp 0x4EF0C3)", 0x004EDDCC, "85c07511c685dffeffff08e9e7120000"),
    ("общий выход отказа 0x4EF0C3 (movzx eax,[ebp-121h])", 0x004EF0C3, "0fb685dffeffff"),
    ("D аргументы 0x4EF5F4 (код [ebp-140h], номер, this [ebp-288h])", 0x004EF5F4, "8b95c0feffff52668b4508508b8d78fdffff"),
    ("D продолжение 0x4EF60B (… +25h == 2 — бафф)", 0x004EF60B, "8b8dc0feffff83e9016bc9308b15705e5f000fb6440a2583f802"),
    ("пролог 0x4CBA90", 0x004CBA90, "558bec81ec74010000"),
    ("потолок 0x4CBB61 (cmp edx,imm8; jl)", 0x004CBB61, "83fa3b7c05"),
    ("4036 себе аргументы 0x4CBFCC", 0x004CBFCC, "6a01668b4508508d4d8851668b5508526a7568c40f00008b8594feffff8b4804"),
    ("4036 сектору аргументы 0x4CBFF1", 0x004CBFF1, "6a018d4d88516a7568c40f0000668b5508528b8d94feffff"),
    ("после 4036 0x4CC00E", 0x004CC00E, "6a018b85d8feffff508b8d94feffff"),
    ("кувшин (уровень) хвост 0x4CC081", 0x004CC081, "8b8d94feffff8b51048b4a30e8fe96fcffe9ec010000"),
    ("кувшин (опыт) хвост 0x4CC272", 0x004CC272, "8b8d94feffff8b51048b4a30e80d95fcff5f5e8be55dc21800"),
    ("S тело 2140 0x4EF004 (push номер; lea ecx,[ebp-118h]; push; conn; 0C0h; 85Ch; ecx = 7E0538h)", 0x004EF004,
     "668b4508508d8de8feffff518b9508fdffff8b4a04e8121afdff5068c0000000685c080000b938057e00"),
    ("S продолжение 0x4EF033", 0x004EF033, "0fbf852effffff"),
    ("тело 2140: +2 Userindex sub_5324F0 → [ebp-116h], +6 Charidx sub_532530 → [ebp-112h], +7 код [ebp-204h] → [ebp-111h]", None, None),
    ("пролог 0x5646C0", 0x005646C0, "558bec"),
    ("ClearUserMemory 0x527350 (пролог) и аргументы писателя логов", 0x00527350, "558bec51894dfc8b4510500fbf4d08510fbf550852689096590068549659000fb6450c50"),
    ("ClearUserMemory после 0x527379 (add esp,18h)", 0x00527379, "83c418"),
    ("геттер Charidx 0x53255D (mov al,[ecx+18Ch])", 0x0053255D, "8a818c010000"),
]
RETS = [(0x004F27F0, 0x004F2850, "8"), (0x004F2640, 0x004F2710, "8"), (0x004C28F0, 0x004C29C0, "0x18"),
        (0x0052E6D0, 0x0052E730, "0x14"), (0x00495790, 0x00495997, "0x10"), (0x005325F0, 0x00532630, "4"),
        (0x004CABC0, 0x004CAC10, "4"), (0x0052EA20, 0x0052EA60, "4"), (0x005646C0, 0x00564900, "0x14"), (0x00532530, 0x00532570, "4")]
BOUNDARIES = {0x004EDDB5: [0x004EDDC7, 0x004EDDCC, 0x004EDDE1], 0x004EF5F4: [0x004EF606, 0x004EF60B],
              0x004CBFCC: [0x004CBFEC, 0x004CBFF1, 0x004CC009, 0x004CC00E], 0x004CC06C: [0x004CC081, 0x004CC08D, 0x004CC092],
              0x004CC25D: [0x004CC272, 0x004CC27E, 0x004CC283], 0x004EF004: [0x004EF02E, 0x004EF033],
              0x00527350: [0x00527374, 0x00527379, 0x0052737C]}

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    raw = open(path, "rb").read()
    pe = pefile.PE(data=raw)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase, hashlib.md5(raw).hexdigest()


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def scan_into(pe, img, base, ranges):
    a, b = text_range(pe)
    hits = {n: 0 for n, _, _ in ranges}
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
            for n, va, ln in ranges:
                if va < t < va + ln:
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in ranges:
            if va < v < va + ln:
                hits[n] += 1
    return hits


def boundaries(img, base, start, wanted, span=0x100):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    seen = set(i.address for i in md.disasm(bytes(img[start - base:start - base + span]), start))
    return [w for w in wanted if w not in seen]


def rets(img, base, a, b):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(bytes(img[a - base:b - base]), a):
        if i.mnemonic == "ret":
            return i.op_str or "0"
    return None


def ft_disp_scan(img, base, pe):
    """Все обращения к записи Function_Table: `mov r32,[0x5F5E70]` (или A1) и ближайшая команда с [r+r+disp]."""
    a, b = text_range(pe)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    pat = re.compile(rb"(\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]|\xa1)\x70\x5e\x5f\x00")
    out = {}
    for m in pat.finditer(bytes(img), a, b):
        va = base + m.start()
        for i in md.disasm(bytes(img[m.start():m.start() + 40]), va):
            if i.address == va:
                continue
            mm = re.search(r"\+ (0x[0-9a-f]+)\]", i.op_str)
            if mm and i.op_str.count("+") >= 2:
                out.setdefault(int(mm.group(1), 16), []).append(i.address)
                break
            if i.mnemonic in ("call", "ret", "jmp"):
                break
    return out


def calls_a5(pe, img, base):
    """Вызовы 0x4CBA90: значения push (a6, a5, gain_hi, gain_lo, a3, num — ближайшие 6) — где a5 — константа 1."""
    a, b = text_range(pe)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    ins = [(i.address, i.mnemonic, i.op_str) for i in md.disasm(bytes(img[a:b]), base + a)]
    res = []
    for k, (ad, mn, op) in enumerate(ins):
        if mn != "call" or op != "0x4cba90":
            continue
        pushes, j, fld1 = [], k - 1, False
        while j >= 0 and len(pushes) < 6 and k - j < 60:
            if ins[j][1] == "push":
                pushes.append(ins[j][2])
            if ins[j][1] == "fld1":
                fld1 = True
            j -= 1
        if fld1 and len(pushes) == 6 and pushes[5] == "ecx":
            pushes[5] = "1.0f"          # a6: push ecx; fld1; fstp dword [esp] — COERCE_INT(1.0)
        res.append((ad, pushes))     # pushes[0] — ближайший к call (num), pushes[5] — первый (a6)
    return res


imgs = []
for name, path, md5want in GS_IMAGES:
    print("-- %s: %s" % (name, path))
    pe, img, base, md5 = load(path)
    ok(base == BASE, "ImageBase 0x%08X" % base)
    ok(md5.startswith(md5want), "md5 %s (ожидалось %s…)" % (md5, md5want))
    for n, va, hexs, tgt in SITES:
        got = bytes(img[va - base:va - base + 5]).hex()
        real = va + 5 + struct.unpack("<i", bytes(img[va - base + 1:va - base + 5]))[0]
        ok(got == hexs and real == tgt, "площадка %s @0x%08X: %s → call 0x%08X" % (n, va, got, real))
    for n, va, hexs in NEIGHBOURS:
        if va is None:
            continue
        got = bytes(img[va - base:va - base + len(hexs) // 2]).hex()
        ok(got == hexs, "%s: %s" % (n, got))
    # тело 2140: откуда берутся поля (две проверки по коду заполнения, LABEL_145)
    md0 = Cs(CS_ARCH_X86, CS_MODE_32)
    fill = [(i.mnemonic, i.op_str) for i in md0.disasm(bytes(img[0x004EEE40 - base:0x004EF004 - base]), 0x004EEE40)]
    txt = " ; ".join("%s %s" % x for x in fill)
    ok(re.search(r"call 0x5324f0 ; mov dword ptr \[ebp - 0x116\], eax", txt) is not None
       and "call 0x532530 ; mov byte ptr [ebp - 0x112], al" in txt
       and "mov edx, dword ptr [ebp - 0x204] ; mov dword ptr [ebp - 0x111], edx" in txt,
       "тело 2140 заполняется: [ebp-116h] ← sub_5324F0 (Userindex), [ebp-112h] ← sub_532530 (Charidx), [ebp-111h] ← код [ebp-204h]")
    for a, b, want in RETS:
        r = rets(img, base, a, b)
        ok(r == want, "0x%08X: ret %s (ожидалось %s)" % (a, r, want))
    hits = scan_into(pe, img, base, [(n, va, 5) for n, va, _, _ in SITES])
    for n, h in hits.items():
        ok(h == 0, "ссылок внутрь площадки %s: %d" % (n, h))
    for start, wanted in BOUNDARIES.items():
        miss = boundaries(img, base, start, wanted)
        ok(not miss, "границы инструкций от 0x%08X: %s" % (start, "все на месте" if not miss else ["0x%08X" % m for m in miss]))
    disp = ft_disp_scan(img, base, pe)
    ok(sorted(disp.get(0x25, [])) == [0x004B0182, 0x004EF61D],
       "Function_Table +0x25 (+37, бафф): обращения %s — загрузчик 0x4B0182 и шаг 2 0x4EF61D, других нет"
       % ["0x%X" % x for x in disp.get(0x25, [])])
    c = calls_a5(pe, img, base)
    rew = [(ad, p) for ad, p in c if len(p) == 6 and p[4] == "1"]
    ok(len(c) >= 10 and len(rew) >= 3 and all(p[5] in ("0x3f800000", "1.0f") and p[1] == "0" for _, p in rew),
       "Recv_BattleServerFromCharParamExp_1: вызовов %d, «наградных» (a5 = 1, a6 = 1.0f) %d: %s" %
       (len(c), len(rew), ["0x%X a3=%s" % (ad, p[1]) for ad, p in rew]))
    imgs.append((name, pe, img, base))
for a, b in [(0x004EDDB5, 0x004EDDE1), (0x004EF5F4, 0x004EF628), (0x004CBA90, 0x004CC28B), (0x004F2640, 0x004F2850)]:
    ok(all(bytes(imgs[0][2][a - BASE:b - BASE]) == bytes(i[2][a - BASE:b - BASE]) for i in imgs),
       "0x%08X..0x%08X побайтно одинаково на всех образах" % (a, b))

# ── площадки других патчей не пересекаются с P75 ──
print("-- соседи среди P01…P74 (адреса площадок в src/patches)")
mine = [(va, 5) for _, va, _, _ in SITES]
clash = []
for f in glob.glob(os.path.join(SRC, "p*.cpp")):
    if "p75_" in os.path.basename(f):
        continue
    txt = open(f, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"0x00([45][0-9A-Fa-f]{5})", txt):
        v = int(m.group(1), 16)
        if any(va <= v < va + ln for va, ln in mine):
            clash.append((os.path.basename(f), "0x%X" % v))
# ★ ред. 2: 0x527374 (ClearUserMemory) — ОБЩАЯ точка с P63 SessionClear (P75 пишет её, только если P63 не держит: P63_ClearHooked)
# ★ P103 (04.11.2026): 0x4EF02E — задуманная цепочка P75 → P103 (P75_ChainDbSend), P103 байты площадки не пишет, если её держит P75
shared = [c for c in clash if c == ("p63_inflight_lock.cpp", "0x527374")]
chain = [c for c in clash if c == ("p103_inflight_fixes.cpp", "0x4EF02E")]
other = [c for c in clash if c not in shared and c not in chain]
ok(not other and shared, "адреса площадок P75 в других патчах: только общая точка P63 0x527374 %s; прочих нет %s" % (shared, other or ""))

# ── DLL ──
print("-- DLL: %s" % DLL)
dpe = pefile.PE(DLL)
dimg = bytearray(dpe.get_memory_mapped_image())
dbase = dpe.OPTIONAL_HEADER.ImageBase
syms = {}
for line in open(MAP, encoding="utf-8", errors="replace"):
    m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s.*p75_level_up_potion\.obj", line)
    if m:
        syms[m.group(1)] = int(m.group(2), 16)


def sym(needle):
    c = [(n, v) for n, v in syms.items() if needle in n]
    return c[0][1] if len(c) == 1 else None


stubs = {k: sym("?%s@" % k) for k in ("StubUseGate", "StubDbUse", "StubLvSelf", "StubLvSect", "StubJar", "StubDbSend", "StubClear")}
ok(all(stubs.values()), "по .map: %s" % {k: hex(v or 0) for k, v in stubs.items()})
gp = {k: sym("?%s@" % k) for k in ("g_pCoolCheck", "g_pFuncReg", "g_pReject0", "g_pSendPacket", "g_pSendOther", "g_pSoulJar",
                                     "g_pDbSend", "g_pSrvLog")}
want = {"g_pCoolCheck": 0x004F27F0, "g_pFuncReg": 0x004F2640, "g_pReject0": 0x004EF0C3, "g_pSendPacket": 0x004C28F0,
        "g_pSendOther": 0x0052E6D0, "g_pSoulJar": 0x00495790, "g_pDbSend": 0x005646C0, "g_pSrvLog": 0x00569DF0}
for k, a in gp.items():
    v = struct.unpack("<I", bytes(dimg[a - dbase:a - dbase + 4]))[0] if a else None
    ok(v == want[k], "%s = 0x%08X" % (k, v or 0))
exports = [e.name.decode() for e in dpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
ok(any("P75_GetStats" in n for n in exports), "экспорт P75_GetStats: %s" % [n for n in exports if "P75" in n])
md = Cs(CS_ARCH_X86, CS_MODE_32)


def body(a, n=0x40):
    out = []
    for i in md.disasm(bytes(dimg[a - dbase:a - dbase + n]), a):
        out.append(i)
        if i.mnemonic == "ret" or (i.mnemonic == "jmp" and "dword ptr" in i.op_str and len(out) > 12):
            break
    return out


for k, retn, tgt in (("StubLvSelf", "0x18", "g_pSendPacket"), ("StubLvSect", "0x14", "g_pSendOther"), ("StubJar", "0x10", "g_pSoulJar")):
    b = body(stubs[k]) if stubs[k] else []
    txt = " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in b)
    ok(b and b[0].mnemonic == "push" and b[0].op_str == "ecx" and any(i.mnemonic == "jmp" and ("0x%x" % gp[tgt]) in i.op_str for i in b)
       and b[-1].mnemonic == "ret" and b[-1].op_str == retn and not any(r in txt for r in ("ebx", "esi", "edi", "ebp")),
       "%s: push ecx … call P75_SkipSend … pop ecx; хвостовой jmp [%s]; пропуск — xor eax,eax; ret %s: %s" % (k, tgt, retn, txt))
b = body(stubs["StubUseGate"], 0x30) if stubs["StubUseGate"] else []
txt = " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in b)
ok("push dword ptr [esp + 0xc] ; push dword ptr [esp + 0xc] ; push ecx" in txt and ("jmp dword ptr [0x%x]" % gp["g_pCoolCheck"]) in txt
   and "add esp, 0xc ; mov byte ptr [ebp - 0x121], 0" in txt and ("jmp dword ptr [0x%x]" % gp["g_pReject0"]) in txt,
   "StubUseGate: аргументы (this, номер, код), пропуск — jmp [sub_4F27F0], отказ — add esp,0Ch; [ebp-121h]=0; jmp [0x4EF0C3]: %s" % txt)
b = body(stubs["StubDbUse"]) if stubs["StubDbUse"] else []
txt = " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in b)
ok(("call dword ptr [0x%x]" % gp["g_pFuncReg"]) in txt and txt.endswith("mov esp, ebp ; pop ebp ; ret 8") and "push dword ptr [ebp - 4]" in txt,
   "StubDbUse: сток sub_4F2640 (ecx цел), затем P75_AfterDbUse(this, номер, код); ret 8: %s" % txt)

b = body(stubs["StubDbSend"], 0x30) if stubs["StubDbSend"] else []
txt = " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in b)
ok(txt.startswith("push ecx ; push dword ptr [esp + 0x18] ; push dword ptr [esp + 0x18] ; push dword ptr [esp + 0x10] ; "
                  "push dword ptr [ebp - 0x2f8] ; call ") and ("pop ecx ; jmp dword ptr [0x%x]" % gp["g_pDbSend"]) in txt,
   "StubDbSend: P75_OnDbSend(mgr [ebp-2F8h], op, тело, номер), ecx цел, хвостовой jmp [sub_5646C0]: %s" % txt)
b = body(stubs["StubClear"], 0x20) if stubs["StubClear"] else []
txt = " ; ".join(("%s %s" % (i.mnemonic, i.op_str)).strip() for i in b)
ok(txt.startswith("pushal ; movsx ecx, word ptr [ebp + 8] ; push ecx ; call ") and ("popal ; jmp dword ptr [0x%x]" % gp["g_pSrvLog"]) in txt,
   "StubClear: pushad; P75_OnUserClear(слот [ebp+8]); popad; хвостовой jmp [sub_569DF0] (cdecl, стек цел): %s" % txt)
# общая точка P63 → P75: P63_OnUserClear зовёт P75_OnUserClear первым делом
p63 = [(n, v) for n, v in [(m.group(1), int(m.group(2), 16)) for m in
       (re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s.*p63_inflight_lock\.obj", l)
        for l in open(MAP, encoding="utf-8", errors="replace")) if m] if n.startswith("_P63_OnUserClear@")]
oc = sym("_P75_OnUserClear@4")
if p63 and oc:
    first = [i for i in md.disasm(bytes(dimg[p63[0][1] - dbase:p63[0][1] - dbase + 0x30]), p63[0][1]) if i.mnemonic == "call"][:1]
    ok(first and int(first[0].op_str, 16) == oc, "P63_OnUserClear: первый вызов — P75_OnUserClear (общая точка выхода)")
else:
    ok(False, "по .map: P63_OnUserClear=%s P75_OnUserClear=%s" % (p63, oc))

print("== ИТОГ verify_p75: ошибок %d ==" % bad)
sys.exit(1 if bad else 0)
