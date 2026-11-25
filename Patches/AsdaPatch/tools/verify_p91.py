# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p91.py — СТАТИЧЕСКАЯ проверка P91 «потолок опыта за моба × рейт события» (волна exprate, 26.10.2026).
#   Логику проверяет stand_p91 (настоящий код площадок, матрица рейтов × уровней, сверка со стоком). Здесь:
#   1. Образы GameServer (сток 4e20f0ad, живой = Indun e7b4ac38): байты обеих площадок (35 б), границы инструкций (линейный
#      проход от начала функции), сплошной перебор переходов rel8/rel32/jcc32 по .text — входов внутрь площадок нет; окна
#      ±32 б одинаковы на всех образах.
#   2. Кадр: обе функции снимают 18h байт аргументов (6 двойных слов: userNum, a3/a4, i64, a5, a6) — fEvent (a6) в [ebp+1Ch];
#      одиночка сама сверяет a5 в [ebp+18h] (0x4CBBEF); после площадок сток читает диапазон из [ebp-0FCh]/[ebp-114h];
#      цикл Lucky Hours GetExpUpDownValue читает ровно глобалы 0x5A7964/0x5E23AC/0x5E2414/0x5E247C/0x5E24E4/0x5E26DC/0x5E2744
#      и GetLocalTime (тот же предикат, что у P91).
#   3. DLL (по .map): стабы St_Solo/St_Party — pushfd/pushad, [ebp-100h]/[ebp-118h], [ebp+1Ch], [ebp+8], площадка 0/1,
#      call P91_Cap, popad/popfd, jmp на 0x4CBC2C/0x4C8035; реестр — P91 после P89; ini-секция; тексты ac.other 118/119.
# Запуск: py -3 verify_p91.py [AsdaPatch.dll]
import hashlib
import os
import re
import struct
import sys

sys.dont_write_bytecode = True
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
IMAGES = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447"),
          ("живой GameServer", os.path.join(IMG, "gs_live.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01"),
          ("живой Indun", os.path.join(IMG, "gs_indun.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01")]
SOLO = bytes.fromhex("6A006A098B9504FFFFFF528B8500FFFFFF50E83022" "0A00898500FFFFFF899504FFFFFF")
PARTY = bytes.fromhex("6A006A098B85ECFEFFFF508B8DE8FEFFFF51E8275E" "0A008985E8FEFFFF8995ECFEFFFF")
SITES = [("одиночка Recv_BattleServerFromCharParamExp_1", 0x4CBC09, SOLO, 0x4CBA90, 0x4CBC2C),
         ("отряд sub_4C7C70", 0x4C8012, PARTY, 0x4C7C70, 0x4C8035)]
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def md5(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def load(path):
    pe = pefile.PE(path)
    return pe, bytes(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe, base):
    for s in pe.sections:
        if s.Name.rstrip(b"\0") == b".text":
            return base + s.VirtualAddress, base + s.VirtualAddress + s.Misc_VirtualSize
    return 0, 0


md = Cs(CS_ARCH_X86, CS_MODE_32)


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


def txt(img, base, va):
    i = insns(img, base, va, va + 16)[0]
    return (i.mnemonic + " " + i.op_str).strip()


def rets(img, base, fva, span=0x1200):
    s = set()
    for i in md.disasm(img[fva - base:fva - base + span], fva):
        if i.mnemonic == "ret":
            s.add(int(i.op_str, 0) if i.op_str else 0)
        if i.mnemonic == "int3":
            break
    return s


print("== 1. образы GameServer")
wins = []
first = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if first is None or "живой" in name:
        first = (pe, img, base)
    lo, hi = text_range(pe, base)
    win = b""
    for sname, va, stock, fn, back in SITES:
        ok(img[va - base:va - base + len(stock)] == stock, "%s %s @0x%06X: 35 б стока (push 0/push 9/…/__alldiv/запись диапазона)" % (name, sname, va))
        starts = [i.address for i in insns(img, base, fn, back + 16)]
        ok(va in starts and back in starts and va + len(stock) == back,
           "%s %s: границы инструкций 0x%06X → 0x%06X (линейный проход от 0x%06X)" % (name, sname, va, back, fn))
        win += img[va - base - 32:back - base + 32]
    inner = [(va + 1, back) for _, va, _, _, back in SITES]
    hits = []
    t = img[lo - base:hi - base]
    for o in range(len(t) - 6):
        b0 = t[o]
        tgt = None
        if b0 == 0xEB or 0x70 <= b0 <= 0x7F:
            tgt = lo + o + 2 + struct.unpack_from("<b", t, o + 1)[0]
        elif b0 in (0xE8, 0xE9):
            tgt = lo + o + 5 + struct.unpack_from("<i", t, o + 1)[0]
        elif b0 == 0x0F and 0x80 <= t[o + 1] <= 0x8F:
            tgt = lo + o + 6 + struct.unpack_from("<i", t, o + 2)[0]
        if tgt is not None and any(a <= tgt < b for a, b in inner):
            hits.append((lo + o, tgt))
    real = []
    for src, tgt in hits:
        for _, va, _, fn, back in SITES:
            if fn <= src < back + 0x800 and src in [i.address for i in insns(img, base, fn, back + 0x800)]:
                real.append((src, tgt))
    ok(not real, "%s: переходов внутрь площадок нет (кандидатов %d, на границах инструкций %d)" % (name, len(hits), len(real)))
    wins.append(win)
if len(wins) == len(IMAGES):
    ok(all(w == wins[0] for w in wins), "окна ±32 б вокруг площадок одинаковы на %d образах" % len(wins))

print("== 2. кадр и Lucky Hours")
if first:
    pe, img, base = first
    ok(rets(img, base, 0x4CBA90) == {0x18}, "Recv_BattleServerFromCharParamExp_1: ret 18h (6 слов аргументов) — a6 = fEvent в [ebp+1Ch]")
    ok(rets(img, base, 0x4C7C70, 0x1400) == {0x18}, "sub_4C7C70: ret 18h — a6 = fEvent в [ebp+1Ch]")
    ok(txt(img, base, 0x4CBBEF) == "cmp dword ptr [ebp + 0x18], 0", "0x4CBBEF: сток сверяет a5 в [ebp+18h] (задания a5 = 1 мимо площадки)")
    ok(txt(img, base, 0x4CBC2C) == "cmp dword ptr [ebp - 0xfc], 0" and txt(img, base, 0x4C8035) == "cmp dword ptr [ebp - 0x114], 0",
       "после площадок сток читает диапазон из [ebp-0FCh] / [ebp-114h] (то, что пишет P91_Cap)")
    ok(txt(img, base, 0x4CBA9B) == "mov dword ptr [ebp - 0x16c], ecx" and txt(img, base, 0x4C7C7B) == "mov dword ptr [ebp - 0x1ac], ecx",
       "обе функции — кадр ebp (push ebp / mov ebp,esp), this в кадре")
    lucky = img[0x4CC410 - base:0x4CC492 - base]
    for g in (0x5A7964, 0x5E23AC, 0x5E2414, 0x5E247C, 0x5E24E4, 0x5E26DC, 0x5E2744):
        ok(struct.pack("<I", g) in lucky, "GetExpUpDownValue: цикл Lucky Hours читает глобал 0x%06X" % g)
    ok(txt(img, base, 0x4CC410) == "movsx eax, word ptr [0x5a7964]", "счётчик строк — WORD со знаком (movsx), как в P91")
    ok(txt(img, base, 0x4CC3F8) == "call dword ptr [0x583020]", "GetLocalTime (IAT 0x583020) — местное время, как у P91")

print("== 3. DLL, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p91_exp_cap_rate\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    cap = sym(r"_P91_Cap@16")
    ok(cap != 0, "P91_Cap (__stdcall, 16 б) @%08X" % cap)
    for st, rng, site, back in (("St_Solo", "0x100", 0, 0x4CBC2C), ("St_Party", "0x118", 1, 0x4C8035)):
        va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "стаб %s @%08X" % (st, va))
        if not va:
            continue
        c = [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + 64], va)][:11]
        print("    %s: %s" % (st, " ; ".join(c)))
        want = ["pushfd", "pushal", "lea eax, [ebp - %s]" % rng, "push eax", "push dword ptr [ebp + 0x1c]",
                "movzx eax, word ptr [ebp + 8]", "push eax", "push %d" % site, "call 0x%x" % cap, "popal", "popfd"]
        ok(c == want, "%s: поля кадра, площадка %d, call P91_Cap, popad/popfd" % (st, site))
        nxt = list(md.disasm(img[va - base + 32:va - base + 64], va + 32))
        j = [i for i in md.disasm(img[va - base:va - base + 64], va) if i.mnemonic == "jmp"]
        ok(bool(j) and j[0].op_str.startswith("dword ptr ["), "%s: возврат jmp [адрес продолжения]" % st)
        if j:
            ptr = int(j[0].op_str.split("[")[1].rstrip("]"), 16)
            val = struct.unpack_from("<I", img, ptr - base)[0]
            ok(val == back, "%s: продолжение = 0x%06X (сток после площадки)" % (st, val))
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    order = [m.group(1) for m in re.finditer(r'\{ L"(P\d+_\w+)",', reg)]
    ok("P91_ExpCapRate" in order and order.index("P91_ExpCapRate") > order.index("P89_Job4GateBranch"), "реестр: P91 после P89")
    cpp = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    ok('L"P91_ExpCapRate",' in cpp and 'L"CapDivisor", L"9",' in cpp and 'L"CapScalesWithRate", L"1",' in cpp,
       "Config.cpp: секция P91, CapDivisor=9, CapScalesWithRate=1")
    aj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8-sig").read()
    ok('case 118: return L"P91:' in aj and 'case 119: return L"P91:' in aj, "AcJournal.cpp: тексты ac.other 118/119")

print("== ИТОГ verify_p91: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
