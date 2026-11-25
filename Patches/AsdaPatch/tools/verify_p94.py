# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p94.py — СТАТИЧЕСКАЯ проверка P94 «сообщения пары — не самому себе и не чужой паре» (волна charpos, 26.10.2026).
#   Логику (решения на НАСТОЯЩИХ обработчиках recv_1 / recvSoulMateStateInfo / sub_4949C0 / sub_494010) проверяет stand_p94.
#   Здесь:
#   1. Образы GameServer (сток 4e20f0ad, живой = Indun = Ch2 e7b4ac38): байты 4 площадок и соседей, границы инструкций
#      (линейный проход от начала функции), сплошной перебор переходов rel8/rel32/jcc32 по .text — входов внутрь площадок нет;
#      окна ±32 б одинаковы на всех образах.
#   2. Разметка пакетов ВТОРЫМ методом (дизасм отправителей, а не декомпил): в sub_4940C0 (3313), sub_493A90 (3309),
#      sub_494870 (3311), sub_493D80 (3319) результат sub_40C960 (карта), sub_4A7EB0 (канал), sub_5324F0 (учётка, только 3313)
#      и +0x182CA (слот Друга = цель) пишутся в те смещения пакета, которые читает P94; получатели читают цель/отправителя
#      из тех же смещений; sub_40C960 = байт [ecx+8E9h], sub_4A7EB0 = байт [5F5EB4h], sub_5324A0 = [ecx+eax*4+40h], sub_5324F0 =
#      [ecx+174h]; каждый обработчик зовётся ровно из одного места (ConnectSocketMsgProcess).
#   3. DLL (по .map): стабы St_S1…St_S4 (P94_Decide, замещённые инструкции, продолжения/пропуски), реестр (P94 после P92),
#      секция ini, тексты ac.other 130–132; чужие патчи в 0x493A90…0x494AA0 не пишут.
# Запуск: py -3 verify_p94.py [AsdaPatch.dll]
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
H = bytes.fromhex
# (имя, VA, байты, начало функции, продолжение, пропуск)
SITES = [
    ("S1 recv_1 (3314→5110)", 0x494631, H("8B95ECFDFFFF"), 0x4945B0, 0x494637, 0x494855),
    ("S2 recvSoulMateStateInfo (3310→5112)", 0x493D2B, H("68A8000000"), 0x493CB0, 0x493D30, 0x493D71),
    ("S3 sub_4949C0 (3312→5227)", 0x494A2F, H("8B55E4668B45F0"), 0x4949C0, 0x494A36, 0x494A98),
    ("S4 sub_494010 (3320→5111)", 0x49407C, H("6A328D4DC9"), 0x494010, 0x494081, 0x4940B0),
]
NEIGH = [   # те же байты сверяет сам P94 (p94_soulmate_self_echo.cpp)
    (0x494637, H("0FB682C5820100")), (0x494855, H("8B4DFC33CDE8")), (0x4945DF, H("6806010000")),
    (0x493D30, H("8D9558FFFFFF")), (0x493D71, H("8BE55DC20400")), (0x493CD5, H("68B8000000")),
    (0x494A36, H("668982CA820100")), (0x494A98, H("8BE55DC20400")), (0x494A21, H("8B45E48B88B98201003B4DEC")),
    (0x494081, H("518D5584")), (0x4940B0, H("8BE55DC20400")), (0x49402F, H("6A43")),
]
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
mdk = Cs(CS_ARCH_X86, CS_MODE_32)
mdk.skipdata = True


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


def func_end(img, base, fva, span=0x2000):
    """Конец функции: первый ret, за которым int3 (линейный проход)."""
    last = fva
    for i in md.disasm(img[fva - base:fva - base + span], fva):
        last = i.address + i.size
        if i.mnemonic == "ret" and img[last - base] == 0xCC:
            return last
    return last


print("== 1. образы GameServer: площадки, соседи, границы, переходы")
wins = []
live = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if "живой GameServer" in name:
        live = (pe, img, base)
    lo, hi = text_range(pe, base)
    g = lambda va, n: img[va - base:va - base + n]
    win = b""
    for sname, va, orig, fn, back, skip in SITES:
        ok(g(va, len(orig)) == orig, "%s %s @0x%06X: %s" % (name, sname, va, orig.hex()))
        end = func_end(img, base, fn)
        starts = {i.address for i in insns(img, base, fn, end)}
        ok(va in starts and back in starts and skip in starts,
           "%s %s: границы инструкций (площадка, продолжение 0x%06X, эпилог 0x%06X; функция 0x%06X…0x%06X)" % (name, sname, back, skip, fn, end))
        win += img[va - base - 32:va - base + len(orig) + 32]
    for va, orig in NEIGH:
        ok(g(va, len(orig)) == orig, "%s сосед 0x%06X: %s" % (name, va, orig.hex()))
    inner = [(va + 1, va + len(orig)) for _, va, orig, _, _, _ in SITES]
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
        for _, va, orig, fn, _, _ in SITES:
            if va <= tgt < va + len(orig):
                end = func_end(img, base, fn)
                if fn <= src < end and src in {i.address for i in insns(img, base, fn, end)}:
                    real.append((src, tgt))
    ok(not real, "%s: переходов внутрь площадок нет (кандидатов-байт %d, настоящих инструкций %d)" % (name, len(hits), len(real)))
    wins.append(win)
if len(wins) == len(IMAGES):
    ok(all(w == wins[0] for w in wins), "окна ±32 б вокруг площадок одинаковы на %d образах" % len(wins))

print("== 2. разметка пакетов вторым методом (дизасм живого GameServer)")
if live:
    pe, img, base = live
    lo, hi = text_range(pe, base)
    allins = list(mdk.disasm(img[lo - base:hi - base], lo))
    idx = {i.address: n for n, i in enumerate(allins)}

    def body(fva):
        end = func_end(img, base, fva)
        return [i for i in allins if fva <= i.address < end]

    def store_after_call(fva, callee):
        """Смещения [ebp-N], куда пишется результат call callee (следующая инструкция mov [ebp-N], al/ax/eax)."""
        res = []
        b = body(fva)
        for k, i in enumerate(b[:-1]):
            if i.mnemonic == "call" and i.op_str == hex(callee):
                m = re.match(r"(?:byte|word|dword) ptr \[ebp - (0x[0-9a-f]+)\], (?:al|ax|eax)$", b[k + 1].op_str)
                if b[k + 1].mnemonic == "mov" and m:
                    res.append(int(m.group(1), 16))
        return res

    def store_of_field(fva, off):
        """Смещения [ebp-N], куда копируется поле CUser+off (mov r,[reg+off] ; mov [ebp-N], r)."""
        res = []
        b = body(fva)
        for k, i in enumerate(b[:-1]):
            if i.mnemonic in ("mov", "movzx") and ("+ %s]" % hex(off)) in i.op_str:
                m = re.match(r"(?:byte|word|dword) ptr \[ebp - (0x[0-9a-f]+)\], \w+$", b[k + 1].op_str)
                if b[k + 1].mnemonic == "mov" and m:
                    res.append(int(m.group(1), 16))
        return res

    # отправители: (имя, функция, база пакета [ebp-N], смещение канала, смещение цели)
    senders = [("3313 sub_4940C0", 0x4940C0, 0x110, 9, 16), ("3309 sub_493A90", 0x493A90, 0xB8, 7, 10),
               ("3311 sub_494870", 0x494870, 0x14, 7, 10), ("3319 sub_493D80", 0x493D80, 0x48, 7, 10)]
    for nm, fva, pb, offCh, offTg in senders:
        maps = store_after_call(fva, 0x40C960)
        chs = store_after_call(fva, 0x4A7EB0)
        tg = store_of_field(fva, 0x182CA)
        ok((pb - 6) in maps, "%s: карта sub_40C960 → пакет @+6 ([ebp-%Xh]; найдено %s)" % (nm, pb - 6, [hex(x) for x in maps]))
        ok((pb - offCh) in chs, "%s: канал sub_4A7EB0 → пакет @+%d ([ebp-%Xh]; найдено %s)" % (nm, offCh, pb - offCh, [hex(x) for x in chs]))
        ok((pb - offTg) in tg, "%s: слот Друга +0x182CA → пакет @+%d (цель relay; найдено %s)" % (nm, offTg, [hex(x) for x in tg]))
        sm = store_of_field(fva, 0x182B9)
        ok(pb in sm, "%s: Smidx +0x182B9 → пакет @+0 (найдено %s)" % (nm, [hex(x) for x in sm]))
    ui = store_after_call(0x4940C0, 0x5324F0)
    ok((0x110 - 12) in ui, "3313: учётка персонажа отправителя sub_5324F0 → пакет @+12 (найдено %s)" % [hex(x) for x in ui])
    # получатели: цель и отправитель читаются из тех же смещений
    want_reads = {0x4945B0: ["mov dx, word ptr [ebp - 0x100]", "movsx ecx, word ptr [ebp - 0x10c]", "mov edx, dword ptr [ebp - 0x104]"],
                  0x493CB0: ["mov dx, word ptr [ebp - 0xae]", "movsx eax, word ptr [ebp - 0xb4]"],
                  0x4949C0: ["mov dx, word ptr [ebp - 0xa]", "mov ax, word ptr [ebp - 0x10]", "cmp ecx, dword ptr [ebp - 0x14]"],
                  0x494010: ["mov dx, word ptr [ebp - 0x3e]", "movsx edx, word ptr [ebp - 0x44]"]}
    for fva, lines in want_reads.items():
        b = [(i.mnemonic + " " + i.op_str) for i in body(fva)]
        ok(all(l in b for l in lines), "получатель 0x%06X: %s" % (fva, "; ".join(lines)))
    ok(any((i.mnemonic + " " + i.op_str) == "mov dword ptr [ecx + 0x182c6], edx" for i in body(0x4945B0)),
       "recv_1: учётка отправителя @+12 → CUser+0x182C6 (Друг) — так эхо записывает Другом самого себя")
    helpers = {0x40C960: "mov al, byte ptr [eax + 0x8e9]", 0x4A7EB0: "mov al, byte ptr [0x5f5eb4]",
               0x5324A0: "mov edx, dword ptr [ecx + eax*4 + 0x40]", 0x5324F0: "mov eax, dword ptr [ecx + 0x174]"}
    for fva, line in helpers.items():
        ok(line in [(i.mnemonic + " " + i.op_str) for i in body(fva)], "0x%06X: %s" % (fva, line))
    calls = lambda tgt: [i.address for i in allins if i.mnemonic == "call" and i.op_str == hex(tgt)]
    for fva in (0x4945B0, 0x493CB0, 0x4949C0, 0x494010):
        c = calls(fva)
        ok(len(c) == 1, "обработчик 0x%06X зовётся из одного места: %s" % (fva, ", ".join("0x%06X" % a for a in c)))
    # отправка клиенту: опкод в каждом обработчике
    for fva, op in ((0x4945B0, 0x13F6), (0x493CB0, 0x13F8), (0x4949C0, 0x146B), (0x494010, 0x13F7)):
        ok(("push " + hex(op)) in [(i.mnemonic + " " + i.op_str) for i in body(fva)], "0x%06X: отправка клиенту %d" % (fva, op))

print("== 3. DLL, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p94_soulmate_self_echo\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    dec = sym(r"_P94_Decide@8")
    ok(dec != 0, "P94_Decide (__stdcall, 8 б) @%08X" % dec)
    ok(sym(r"_P94_GetStats@4") != 0, "экспорт P94_GetStats")

    def code(va, n=96):
        return [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + n], va)]

    def jmpval(line):
        m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]", line)
        return struct.unpack_from("<I", img, int(m.group(1), 16) - base)[0] if m else None

    spec = {
        "St_S1": (1, ["mov edx, dword ptr [ebp - 0x214]"], 0x494637, 0x494855),
        "St_S2": (2, ["push 0xa8"], 0x493D30, 0x493D71),
        "St_S3": (3, ["mov edx, dword ptr [ebp - 0x1c]", "mov ax, word ptr [ebp - 0x10]"], 0x494A36, 0x494A98),
        "St_S4": (4, ["push 0x32", "lea ecx, [ebp - 0x37]"], 0x494081, 0x4940B0),
    }
    for st, (site, repl, back, skip) in spec.items():
        va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "стаб %s @%08X" % (st, va))
        if not va:
            continue
        c = code(va)
        print("    %s: %s" % (st, " ; ".join(c[:14])))
        ok(c[:8] == ["pushfd", "pushal", "push ebp", "push %d" % site, "call 0x%x" % dec, "test eax, eax", "popal", c[7]]
           and c[7].startswith("je "), "%s: pushfd/pushad, P94_Decide(%d, ebp), test, popad, je" % (st, site))
        ok(c[8] == "popfd" and c[9:9 + len(repl)] == repl, "%s: на продолжении popfd и замещённые инструкции %s" % (st, repl))
        jm = [l for l in c[9:14 + len(repl)] if l.startswith("jmp dword ptr")]
        tail = c[9 + len(repl) + 1:9 + len(repl) + 4]
        ok(len(jm) >= 2 and jmpval(jm[0]) == back and jmpval(jm[1]) == skip and tail[:2] == ["popfd", "xor eax, eax"],
           "%s: «отправлять» → 0x%06X, «не отправлять» → popfd, eax = 0, 0x%06X (%s)" % (st, back, skip, ", ".join("0x%06X" % (jmpval(x) or 0) for x in jm)))
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8").read()
    i92 = reg.find('{ L"P92_HostileTargetGuard"')
    i94 = reg.find('{ L"P94_SoulmateSelfEcho"')
    ok(0 < i92 < i94, "реестр: P94_SoulmateSelfEcho после P92")
    cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8").read()
    ok(all(k in cfg for k in ('{ L"P94_SoulmateSelfEcho"', "kSoulmateSelfEcho, ARRAYSIZE(kSoulmateSelfEcho)", 'L"ForeignCheck", L"1"',
                              'L"Mode", L"1"', 'L"JournalIntervalSec", L"10"')), "Config.cpp: секция [P94_SoulmateSelfEcho] и умолчания")
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8").read()
    ok(all(("case %d: return L\"P94:" % k) in acj for k in (130, 131, 132)), "AcJournal: тексты ac.other 130–132")
    ok(not any(("case %d:" % k) in acj.replace("case %d: return L\"P94:" % k, "") for k in (130, 131, 132)),
       "AcJournal: виды 130–132 заняты только P94")
    blob = img.decode("latin-1")
    ok("P94_SoulmateSelfEcho".encode("utf-16-le").decode("latin-1") in blob, "DLL: имя секции в образе")
    # чужие патчи в 0x493A90…0x494AA0 не пишут
    others = []
    pdir = os.path.join(SRC, "patches")
    for fn in os.listdir(pdir):
        if not fn.endswith(".cpp") or fn.startswith("p94_"):
            continue
        for m in re.finditer(r"0x00?(49[34][0-9A-Fa-f]{3})\b", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read()):
            v = int(m.group(1), 16)
            if 0x493A90 <= v < 0x494AA0:
                others.append("%s:0x%06X" % (fn, v))
    ok(not others, "чужих площадок в обработчиках пары нет%s" % (": " + ", ".join(others) if others else ""))

print("== ИТОГ verify_p94: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
