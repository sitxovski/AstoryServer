# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p81.py — СТАТИЧЕСКАЯ проверка P81 ActionCodeGuard (страж кода 4024 и частоты звания «Dancer», 2026-10-24).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) CharEMotionSync 0x546730…0x5469BF побайтно одинакова в трёх образах; sub_523ED0/sub_542250 (флаг хода) и sub_52ED50
#     (GM-флаг) — тоже;
#  2) площадки: A 0x5468E1 (13 б) `mov edx,[ebp-42Ch] ; mov ax,[ebp-416h]` сразу за проверкой диапазона 100…400 (0x5468C6…
#     0x5468DF) и ПЕРЕД записью статуса `mov [edx+54E4h],ax` (0x5468EE) и курса (0x54692E/0x546940); B 0x546952 (8 б)
#     `mov byte[ebp-414h],cl ; push 1` — за входом 0x546946 (сюда же ведёт трамплин P80 S2) и перед call sub_52E6D0(4025, 13 б);
#     C 0x546978 (13 б) `movsx ecx,[ebp-416h] ; mov [ebp-438h],ecx` — за рассылкой и перед сравнением 0x70/0x71 и call
#     sub_54A050(num, 0x0D, 0, 0); выход 0x5469AF — эпилог; скрытый оператор (300) отбивается ДО площадок (0x5467C9…0x5467DE);
#  3) флаг, который читает B (dword CUser+0x33), — тот же, что возвращает sub_542250 для sub_523ED0 на 0x5468B8 (между ними
#     вызовов, кроме трамплина P80, нет); GM-флаг sub_52ED50 = byte CUser+0x40B9F;
#  4) все точки — начала инструкций; ни один rel8/rel32/jcc32 из .text и ни один abs32 не ведёт ВНУТРЬ площадок;
#  5) площадки P81 не пересекаются с записью P80 (S1 0x558B39 14 б, S2 0x5468C1 5 б) и с его сверяемыми соседями
#     (0x5468B8 9 б, 0x5468C6 7 б, 0x546946 12 б, 0x5469AF 5 б); другие патчи (кроме p80/p81) адресов внутри CharEMotionSync
#     не называют; p81 называет только свои площадки и сверяемых соседей;
#  6) DLL: MAP — TrampA/TrampB/TrampC, P81_ActionCodeGuard, _P81_Check@12, _P81_Dance@4, P81_GetStats; трамплины уходят ТОЛЬКО на
#     0x5468EE/0x5469AF, 0x54695A/0x5469AF, 0x546985/0x5469AF; повторяют замещённые инструкции; зовут только P81_Check/P81_Dance;
#  7) исходники: kVersion 53, секция [P81_ActionCodeGuard] с ключами, виды журнала 88/89/90 в AcJournal.cpp, P81 после P80 в реестре.
# Поведение (законные коды как сток, 200/300/301 от игрока — отказ, оператор — сток, путь P80 S2, флуд танца) — стенд tools/stand_p81.
# Запуск: python verify_p81.py [AsdaPatch.dll]   (образы — P81_IMG_DIR / P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
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
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P81_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

EMOT = (0x00546730, 0x005469BF)        # CharEMotionSync (4024)
HELPERS = [(0x00523ED0, 0x00523F00), (0x00542250, 0x00542299), (0x0052ED50, 0x0052EDA7)]
A, A_LEN, BACK_A = 0x005468E1, 13, 0x005468EE
B, B_LEN, BACK_B = 0x00546952, 8, 0x0054695A
C, C_LEN, BACK_C = 0x00546978, 13, 0x00546985
RELAY, EXIT = 0x00546946, 0x005469AF
P81_SITES = [(A, A_LEN), (B, B_LEN), (C, C_LEN)]
# сверяемые соседи P81 (только чтение) — те же адреса, что в src/patches/p81_action_code_guard.cpp
P81_NEIGHBORS = [(0x005468C6, 12), (0x005468D2, 15), (BACK_A, 9), (RELAY, 12), (BACK_B, 14), (0x00546973, 5), (BACK_C, 20),
                 (0x00546999, 11), (0x005469AA, 5), (EXIT, 5), (0x005467C9, 19)]
P80_WRITES = [(0x00558B39, 14), (0x005468C1, 5)]
P80_NEIGHBORS = [(0x005468B8, 9), (0x005468C6, 7), (RELAY, 12), (EXIT, 5)]
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
    """Ссылки на интервалы targets {имя: (lo, hi)}: переходы rel8/rel32/jcc32 из .text и abs32 по всему образу.
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


def overlap(a, b):
    """Пересекаются ли интервалы (va, len)."""
    return a[0] < b[0] + b[1] and b[0] < a[0] + a[1]


def main():
    print("== verify_p81: DLL %s" % DLL)
    ref = None
    for title, path in GS_IMAGES:
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        body = bytes(img[EMOT[0] - base:EMOT[1] - base]) + b"".join(bytes(img[lo - base:hi - base]) for lo, hi in HELPERS)
        if ref is None:
            ref = body
        ok(body == ref, "CharEMotionSync + sub_523ED0/sub_542250/sub_52ED50 побайтно совпадают с первым образом (%d б)" % len(body))
        g = lambda va, n: bytes(img[va - base:va - base + n])
        em = disasm(img, base, EMOT[0], EMOT[1])
        est = {i.address for i in em}
        at = {i.address: i for i in em}
        txt = lambda va: "%s %s" % (at[va].mnemonic, at[va].op_str) if va in at else "?"
        # ── A ──
        ok(g(A, A_LEN) == bytes.fromhex("8b95d4fbffff668b85eafbffff"), "A 0x5468E1: mov edx,[ebp-42Ch]; mov ax,[ebp-416h]")
        ok(g(0x005468C6, 12) == bytes.fromhex("0fbf85eafbffff83f8647c25") and g(0x005468D2, 15) == bytes.fromhex("0fbf8deafbffff81f9900100007f16"),
           "перед A: код [ebp-416h] < 100 или > 400 → 0x5468F7 (выход) — 0 и прочие вне диапазона сток отбрасывает сам")
        ok(g(0x005468F7, 5) == bytes.fromhex("e9b3000000") and 0x005468F7 + 5 + 0xB3 == EXIT, "0x5468F7: jmp 0x5469AF")
        ok(txt(BACK_A) == "mov word ptr [edx + 0x54e4], ax" and g(BACK_A + 7, 2) == bytes.fromhex("eb05"),
           "0x5468EE: запись статуса word[CUser+0x54E4] := код (за A) ; jmp 0x5468FC")
        ok(txt(0x0054692E) == "fstp dword ptr [ecx + 0x5512]" and txt(0x00546940) == "fstp dword ptr [edx + 0x5516]",
           "курс +0x5512/+0x5516 пишется после A (0x54692E/0x546940)")
        # ── скрытый оператор до площадок ──
        ok(g(0x005467C0, 5) == bytes.fromhex("e82b85feff") and g(0x005467C9, 19) == bytes.fromhex("8b85d4fbffff0fbf883bbc030081f92c010000")
           and g(0x005467DE, 5) == bytes.fromhex("e9cc010000"), "0x5467C0…0x5467DE: IsOperatorIndex и +0x3BC3B == 300 → выход (до площадок)")
        # ── B ──
        ok(g(RELAY, 12) == bytes.fromhex("8b85d4fbffff8a88a6040000"), "0x546946: mov eax,[ebp-42Ch]; mov cl,[eax+4A6h] (вход P80 S2)")
        ok(g(B, B_LEN) == bytes.fromhex("888decfbffff6a01"), "B 0x546952: mov byte[ebp-414h],cl; push 1")
        ok(g(BACK_B, 14) == bytes.fromhex("8d95e8fbffff526a0d68b90f0000"), "0x54695A: lea edx,[ebp-418h]; push edx; push 0Dh; push 0FB9h (4025)")
        ok(g(0x00546973, 5) == bytes.fromhex("e8587dfeff") and 0x00546973 + 5 + struct.unpack("<i", g(0x00546974, 4))[0] == 0x0052E6D0,
           "0x546973: call sub_52E6D0 — рассылка 4025 сектору")
        # ── C ──
        ok(g(C, C_LEN) == bytes.fromhex("0fbf8deafbffff898dc8fbffff"), "C 0x546978: movsx ecx,[ebp-416h]; mov [ebp-438h],ecx")
        ok(g(BACK_C, 20) == bytes.fromhex("83bdc8fbffff707c2183bdc8fbffff717e02eb16"), "0x546985: cmp 70h / jl / cmp 71h / jle / jmp — только 112/113")
        ok(g(0x00546999, 11) == bytes.fromhex("6a006a006a0d668b550852"),"0x546999: push 0; push 0; push 0Dh (индекс «Dancer» 13); push userNum")
        ok(g(0x005469AA, 5) == bytes.fromhex("e8a1360000") and 0x005469AA + 5 + 0x36A1 == 0x0054A050, "0x5469AA: call sub_54A050 (накопитель звания)")
        ok(g(EXIT, 5) == bytes.fromhex("8b4dfc33cd"), "0x5469AF: эпилог mov ecx,[ebp-4]; xor ecx,ebp")
        calls = [i for i in em if i.mnemonic == "call" and A <= i.address < EXIT]
        ok([hex(int(i.op_str, 16)) for i in calls] == ["0x52e6d0", "0x54a050"], "между A и выходом вызовов только sub_52E6D0 и sub_54A050 (%s)"
           % [i.op_str for i in calls])
        ok({A, BACK_A, RELAY, B, BACK_B, C, BACK_C, EXIT, 0x00546999} <= est, "площадки и точки возврата — начала инструкций")
        # ── флаги ──
        ok(g(0x005468B8, 9) == bytes.fromhex("e813d6fdff85c07405") and 0x005468B8 + 5 + struct.unpack("<i", g(0x005468B9, 4))[0] == 0x00523ED0,
           "0x5468B8: call sub_523ED0; test; je 0x5468C6 (стоя → дальше)")
        h1 = disasm(img, base, 0x00523ED0, 0x00523F00)
        h2 = disasm(img, base, 0x00542250, 0x00542299)
        ok(any(i.mnemonic == "call" and i.op_str == "0x542250" for i in h1) and any(i.op_str == "ecx, dword ptr [eax + 0x33]" for i in h2),
           "sub_523ED0 → sub_542250 → dword[CUser+0x33] (флаг, который сверяет B)")
        h3 = disasm(img, base, 0x0052ED50, 0x0052EDA7)
        ok(any(i.op_str == "al, byte ptr [eax + 0x40b9f]" for i in h3) and any(i.op_str == "0x5324a0" for i in h3),
           "sub_52ED50 (P47_IsGmUser): GetUser → byte[CUser+0x40B9F]")
        # ── ссылки внутрь площадок ──
        hits = scan_refs(pe, img, base, {"A": (A + 1, A + A_LEN), "B": (B + 1, B + B_LEN), "C": (C + 1, C + C_LEN)}, [EMOT])
        for n in ("A", "B", "C"):
            ok(hits[n] == 0, "%s: переходов/abs32 внутрь площадки нет (%d)" % (n, hits[n]))

    print("-- непересечение с P80 и другими патчами")
    for s in P81_SITES:
        for w in P80_WRITES + P80_NEIGHBORS:
            ok(not overlap(s, w), "площадка P81 0x%08X+%d не пересекает P80 0x%08X+%d" % (s[0], s[1], w[0], w[1]))
    for nb in P81_NEIGHBORS:
        for w in P80_WRITES:
            ok(not overlap(nb, w), "сосед P81 0x%08X+%d не пересекает запись P80 0x%08X+%d" % (nb[0], nb[1], w[0], w[1]))
    rx = re.compile(r"0x0*(5[0-9A-Fa-f]{5})\b")
    found, p81_named = [], set()
    pdir = os.path.join(SRC, "patches")
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or not re.match(r"p\d\d_", fn):
            continue
        for ln, line in enumerate(open(os.path.join(pdir, fn), encoding="utf-8", errors="replace"), 1):
            for m in rx.finditer(line):
                v = int(m.group(1), 16)
                if EMOT[0] < v < EMOT[1]:
                    if fn.startswith("p81_"):
                        p81_named.add(v)
                    elif not fn.startswith("p80_"):
                        found.append((fn, ln, hex(v)))
    ok(not found, "внутри CharEMotionSync адресов не называют другие патчи (кроме p80/p81)%s" % ("" if not found else ": " + str(found)))
    allowed = set()
    for va, n in P81_SITES + P81_NEIGHBORS:
        allowed |= set(range(va, va + n))
    allowed |= {0x005468B8, 0x005468C1, 0x005468EE, 0x0054692E, 0x00546940, 0x005467C0, 0x005467DE, 0x005468F7, 0x005468FC}   # упоминания в комментариях
    extra = sorted(v for v in p81_named if v not in allowed)
    ok(not extra, "p81 называет только свои площадки и сверяемых соседей%s" % ("" if not extra else ": " + str([hex(x) for x in extra])))
    src81 = open(os.path.join(pdir, "p81_action_code_guard.cpp"), encoding="utf-8").read()
    for va, n in P81_SITES + P81_NEIGHBORS:
        ok(("0x%08X" % va) in src81, "p81: точка 0x%08X описана в исходнике" % va)

    print("-- исходники")
    cfgh = open(os.path.join(SRC, "Config.h"), encoding="utf-8-sig").read()
    cfgc = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8-sig").read()
    reg = open(os.path.join(pdir, "Registry.cpp"), encoding="utf-8-sig").read()
    ver = re.search(r"constexpr int kVersion = (\d+);", cfgh); ver = int(ver.group(1)) if ver else 0
    ok(ver >= 53 and ('{ L"Version", L"%d",' % ver) in cfgc, "Version %d (>= 53, P81) в Config.h и Config.cpp" % ver)
    sec = cfgc[cfgc.find("const IniKey kActionCodeGuard[]"):]
    sec = sec[:sec.find("};")]
    keys = re.findall(r'\{ L"(\w+)", L"([^"]*)"', sec)
    ok(dict(keys) == {"Enabled": "1", "Mode": "1", "AllowedCodes": "100-110;112-117;122;124;127;128;131;400", "DanceCountMinSec": "12",
                      "JournalIntervalSec": "10", "LogChannel": "0"}, "секция [P81_ActionCodeGuard]: %s" % keys)
    ok('{ L"P81_ActionCodeGuard",' in cfgc and "kActionCodeGuard, ARRAYSIZE(kActionCodeGuard)" in cfgc, "секция в таблице kSections")
    for k in (88, 89, 90):
        ok(len(re.findall(r"case %d: return L\"P81:" % k, acj)) == 1, "AcJournal.cpp: вид ac.other %d — текст P81" % k)
    ok(len(re.findall(r"case 91: return L\"P82:", acj)) <= 1 and not re.search(r"case 91: return L\"P81", acj), "вид 91 не у P81 (★ 24.10: занят P82)")
    i80, i81 = reg.find('{ L"P80_CrouchSpeedJumpRelay"'), reg.find('{ L"P81_ActionCodeGuard"')
    ok(0 < i80 < i81, "реестр: P81 после P80")

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P81_ActionCodeGuard".encode("utf-16-le") in raw, "реестр: строка секции P81_ActionCodeGuard в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 4 and "p81_action_code_guard" in line:
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    tr = {k: [v for n, v in names.items() if n.startswith("?%s@" % k)] for k in ("TrampA", "TrampB", "TrampC")}
    chk = [v for n, v in names.items() if n == "_P81_Check@12"]
    dnc = [v for n, v in names.items() if n == "_P81_Dance@4"]
    ok(all(tr.values()) and chk and dnc and any("P81_ActionCodeGuard" in n for n in names) and any("P81_GetStats" in n for n in names),
       "MAP: TrampA/B/C, _P81_Check@12 (stdcall 3 арг.), _P81_Dance@4 (stdcall 1 арг.), P81_ActionCodeGuard, P81_GetStats")
    pref = pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def glob(va):
        return struct.unpack("<I", bytes(img[va - pref:va - pref + 4]))[0]

    def tramp(va):
        out = []
        for i in md.disasm(bytes(img[va - pref:va - pref + 0x80]), va):
            out.append(i)
            if i.mnemonic == "int3":
                break
        return out

    spec = {"TrampA": ({BACK_A, EXIT}, ["mov edx, dword ptr [ebp - 0x42c]", "mov ax, word ptr [ebp - 0x416]"], chk, 3),
            "TrampB": ({BACK_B, EXIT}, ["mov byte ptr [ebp - 0x414], cl", "cmp dword ptr [eax + 0x33], 0"], chk, 3),
            "TrampC": ({BACK_C, EXIT}, ["movsx ecx, word ptr [ebp - 0x416]", "mov dword ptr [ebp - 0x438], ecx"], dnc, 1)}
    for title, (want, reads, callee, nargs) in spec.items():
        if not tr[title] or not callee:
            continue
        ins = tramp(tr[title][0])
        dests = set()
        for i in ins:
            m = re.match(r"dword ptr \[(0x[0-9a-f]+)\]", i.op_str)
            if i.mnemonic == "jmp" and m:
                dests.add(glob(int(m.group(1), 16)))
        t = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
        ok(dests == want, "%s: выходы только на %s (%s)" % (title, sorted(hex(x) for x in want), sorted(hex(x) for x in dests)))
        ok(all(r in t for r in reads), "%s: повторяет замещённое / читает: %s" % (title, "; ".join(reads)))
        cl = [i for i in ins if i.mnemonic == "call"]
        ok(len(cl) == 1 and int(cl[0].op_str, 16) == callee[0], "%s: один вызов — %s" % (title, "P81_Check" if nargs == 3 else "P81_Dance"))
        ci = ins.index(cl[0]) if cl else 0
        pushes = [i for i in ins[:ci] if i.mnemonic == "push"]
        ok(len(pushes) == nargs and not any(i.mnemonic in ("pop", "ret") for i in ins),
           "%s: до вызова %d push (stdcall снимает сам), pop/ret нет" % (title, len(pushes)))
        if title == "TrampB":
            k = [n for n, i in enumerate(ins) if i.mnemonic == "jmp" and "dword ptr" in i.op_str
                 and glob(int(re.match(r"dword ptr \[(0x[0-9a-f]+)\]", i.op_str).group(1), 16)) == BACK_B]
            ok(k and t[k[0] - 1] == "push 1", "TrampB: замещённый push 1 — непосредственно перед возвратом на 0x54695A (на пути отказа его нет)")
    print("== ИТОГ verify_p81: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
