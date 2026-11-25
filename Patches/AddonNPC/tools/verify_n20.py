# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n20.py — СТАТИЧЕСКАЯ проверка N10 ред. 2 и N20 (слот P90, волна exprate, 26.10.2026).
#   Разбор: Reports/exprate/MOB_EXP_AUDIT.md. Сервер НЕ запускается, образы только читаются. Логику проверяет stand_n20.
#   1. Четыре образа NpcServer (сток 16c7a0af, IDB d292e4ec, живой c02486d6, Indun 0de2c559): байты площадок N10 (0x45FED5,
#      0x45FE41) и N20 (0x437ECD) и стокового зажима одиночки (0x437DA6); инструкции начинаются ровно на площадках (линейный
#      проход от начала функции); сплошной перебор переходов rel8/rel32/jcc32 по .text — входов внутрь изменяемых байтов нет;
#      окна ±32 б вокруг площадок побайтово одинаковы на всех образах.
#   2. Кадр: в sub_45FCD0 очередь ударов — [esp+1Ch…28h] (обнуление 0x45FD40…0x45FD4C, копия в 8202 0x45FEB0 `[esp+eax+1Ch]`),
#      [esp+18h] — сохранённый edi (0x45FCE8) = this; между кадром и площадками глубина стека не меняется (sub esp,10h перед
#      call 0x42C4F0, который снимает 10h). В sub_437A30 поле урона записи — [esp+18h] у обеих веток (0x437DAC одиночка,
#      0x437ECD отряд), максимум здоровья — [ebp+7A38h] у обеих (0x437DA6, 0x437ED6).
#   3. DLL (по .map): стабы N10 — `lea eax,[esp+44h]` (1Ch + 24h + 4), N20 — `push [esp+40h]` (18h + 24h + 4), исходные
#      инструкции со сдвигом +4 (`mov cx,[esp+1Ah]`, `mov edx,[esp+1Ch]`), `imul esi,esi,53h`, ret; реестр — N20 после N19 и
#      P53; Config Version = 11; прежней формы N10 (`mov eax,[esp+40h]` первым) в DLL нет.
# Запуск: py -3 verify_n20.py [AddonNPC.dll]
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
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
sys.path.append(os.path.join(HERE, "..", "..", "AsdaPatch", "tools"))
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe", "16c7a0aff498a9f739899d9a2cba9a5b"),
    ("IDB NpcServer", r"@@ASTORY_DEV_ROOT@@\RE\ida\npc_work\NpcServer.exe", "d292e4ec4edfd5040d8fb39382664eab"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe", "c02486d62e803e98eb6fb4fa98d1fcd6"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe", "0de2c55932c2966537e2a8c539decdcd"),
]
# (имя, VA, байты стока, начало функции для линейного прохода, меняемые байты [VA+1, VA+len))
SITES = [
    ("N10 пл.1 sub_45FCD0", 0x45FED5, bytes.fromhex("668B8B94760000"), 0x45FCD0),
    ("N10 пл.2 sub_45FCD0", 0x45FE41, bytes.fromhex("668B4C2416"), 0x45FCD0),
    ("N20 sub_437A30 отряд", 0x437ECD, bytes.fromhex("8B5424186BF653"), 0x437A30),
]
SOLO = (0x437DA6, bytes.fromhex("8B85387A00008B4C241839017E028901"))
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


def text_of(img, base, va):
    i = insns(img, base, va, va + 16)[0]
    return (i.mnemonic + " " + i.op_str).strip()


print("== 1. образы NpcServer")
windows = []
first = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s (зеркало: python srv_mirror.py)" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if first is None:
        first = (pe, img, base)
    lo, hi = text_range(pe, base)
    win = b""
    for sname, va, stock, fn in SITES:
        ok(img[va - base:va - base + len(stock)] == stock, "%s %s @0x%06X: %s" % (name, sname, va, stock.hex(" ").upper()))
        starts = [i.address for i in insns(img, base, fn, va + len(stock) + 16)]
        ok(va in starts and va + len(stock) in starts,
           "%s %s: границы инструкций 0x%06X → 0x%06X (линейный проход от 0x%06X)" % (name, sname, va, va + len(stock), fn))
        win += img[va - base - 32:va - base + len(stock) + 32]
    sva, sb = SOLO
    ok(img[sva - base:sva - base + len(sb)] == sb, "%s сток одиночки @0x%06X: зажим `cmp [ecx],eax / jle / mov [ecx],eax`" % (name, sva))
    win += img[sva - base - 16:sva - base + len(sb) + 16]
    inner = [(va + 1, va + len(stock)) for _, va, stock, _ in SITES]
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
        for _, va, stock, fn in SITES:
            if fn <= src < va + 0x400 and src in [i.address for i in insns(img, base, fn, va + 0x400)]:
                real.append((src, tgt))
    ok(not real, "%s: переходов внутрь изменяемых байтов нет (сплошной перебор .text: кандидатов %d, на границах инструкций %d)"
       % (name, len(hits), len(real)))
    windows.append((name, win))
if len(windows) == len(IMAGES):
    ok(all(w == windows[0][1] for _, w in windows), "окна ±32 б вокруг площадок побайтово одинаковы на %d образах" % len(windows))

print("== 2. кадр")
if first:
    pe, img, base = first
    ok(text_of(img, base, 0x45FCE8) == "mov dword ptr [esp + 0x18], edi", "0x45FCE8: [esp+18h] = edi (this обработчика) — то, что читала ред. 1 N10")
    for va, off in ((0x45FD40, 0x1C), (0x45FD44, 0x20), (0x45FD48, 0x24), (0x45FD4C, 0x28)):
        ok(text_of(img, base, va) == "mov dword ptr [esp + 0x%x], eax" % off, "0x%06X: обнуление удара [esp+%02Xh] (eax = 0)" % (va, off))
    ok(text_of(img, base, 0x45FEB0) == "mov esi, dword ptr [esp + eax + 0x1c]", "0x45FEB0: очередь [esp+1Ch+i·4] уходит в 8202 — та же, что пишет N10")
    ok(text_of(img, base, 0x45FDF2) == "sub esp, 0x10", "0x45FDF2: sub esp,10h — аргументы sub_42C4F0")
    rets = set()
    for i in md.disasm(img[0x42C4F0 - base:0x42C4F0 - base + 0x3000], 0x42C4F0):
        if i.mnemonic == "ret":
            rets.add(int(i.op_str, 0) if i.op_str else 0)
        if i.mnemonic == "int3":
            break
    ok(rets == {0x10}, "sub_42C4F0 снимает 10h (все ret: %s) — у площадки 2 кадр тот же, что у площадки 1" % sorted(rets))
    ok(text_of(img, base, 0x45FE41) == "mov cx, word ptr [esp + 0x16]" and text_of(img, base, 0x45FE85) == "mov edx, dword ptr [esp + 0x14]",
       "сток сам читает кадр без сдвига у обеих веток (0x45FE41 [esp+16h], 0x45FE85 [esp+14h])")
    ok(text_of(img, base, 0x437DAC) == "mov ecx, dword ptr [esp + 0x18]" and text_of(img, base, 0x437ECD) == "mov edx, dword ptr [esp + 0x18]",
       "sub_437A30: поле урона записи — [esp+18h] у одиночки (0x437DAC) и у отряда (0x437ECD)")
    ok(text_of(img, base, 0x437DA6) == "mov eax, dword ptr [ebp + 0x7a38]" and text_of(img, base, 0x437ED6) == "fidiv dword ptr [ebp + 0x7a38]",
       "sub_437A30: максимум здоровья [ebp+7A38h] у обеих веток (монстр в ebp)")
    ok(text_of(img, base, 0x437ED4) == "fild dword ptr [edx]", "0x437ED4: после площадки N20 — fild [edx] (доля читает поле, которое зажал N20)")

print("== 3. DLL: стабы, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map — сначала build.bat" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx, obj):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+%s\.obj\s*$" % (rx, obj), mp, re.M)
        return int(m.group(2), 16) if m else 0

    def code(va, n=16):
        return [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + 96], va)][:n]

    for st, last in (("HateDamageOnSend", "mov cx, word ptr [ebx + 0x7694]"), ("HateDamageOnAlt", "mov cx, word ptr [esp + 0x1a]")):
        va = sym(r"\?%s@\S+" % st, "n10_normal_attack_hate_damage")
        ok(va != 0, "N10 символ %s @%08X" % (st, va))
        if va:
            c = code(va, 20)
            print("    %s: %s" % (st, " ; ".join(c[:6])))
            ok(c[:4] == ["pushal", "pushfd", "lea eax, [esp + 0x44]", "push eax"], "N10 %s: очередь [esp+44h] = кадр+1Ch (+24h pushad/pushfd, +4 адрес возврата)" % st)
            ok(last in c and c[c.index(last) + 1] == "ret" and c[c.index(last) - 2:c.index(last)] == ["popfd", "popal"],
               "N10 %s: popfd/popad, исходная `%s`, ret" % (st, last))
            ok("mov edx, 0x43d2c0" in c and "movzx ecx, word ptr [ebp + 0x7864]" in c, "N10 %s: вызов sub_43D2C0, номер игрока [ebp+7864h]" % st)
    va = sym(r"\?St_PartyShare@\S+", "n20_party_share_clamp")
    ok(va != 0, "N20 символ St_PartyShare @%08X" % va)
    if va:
        c = code(va, 10)
        print("    St_PartyShare: %s" % " ; ".join(c[:9]))
        ok(c[:5] == ["pushfd", "pushal", "push dword ptr [esp + 0x40]", "push ebp"] + c[4:5] and c[4].startswith("call"),
           "N20: поле [esp+40h] = кадр+18h (+24h pushad/pushfd, +4 адрес возврата), монстр ebp, call N20_Clamp")
        ok(c[5:9] == ["popal", "popfd", "mov edx, dword ptr [esp + 0x1c]", "imul esi, esi, 0x53"] and c[9] == "ret",
           "N20: popad/popfd, исходные `mov edx,[esp+1Ch]` (+4) и `imul esi,esi,53h`, ret")
    cl = sym(r"_N20_Clamp@8", "n20_party_share_clamp")
    ok(cl != 0, "N20_Clamp (__stdcall, 8 б) в .map @%08X" % cl)
    ok(bytes.fromhex("609c33f68b442440") not in img, "нет формы ред. 1 N10 (`pushad / pushfd / xor esi,esi / mov eax,[esp+40h]`)")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    order = [m.group(1) for m in re.finditer(r'\{ L"(\w+)",', reg)]
    ok("N20_PartyShareClamp" in order and order.index("N20_PartyShareClamp") > order.index("N19_RestartAttackClock")
       and order.index("N20_PartyShareClamp") > order.index("P53_AcJournal"), "реестр: N20 после N19 и P53 (%s)" % ", ".join(order[-4:]))
    cfg = open(os.path.join(SRC, "Config.h"), encoding="utf-8-sig").read()
    vm = re.search(r"constexpr int kVersion = (\d+);", cfg)   # ★ 26.10.2026 (N21, слот P93): Version 12 — N20 требует не ниже 11
    ok(vm is not None and int(vm.group(1)) >= 11, "Config.h: kVersion >= 11 (%s)" % (vm.group(1) if vm else "?"))
    cpp = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    vc = re.search(r'\{ L"Version", L"(\d+)",', cpp)
    ok(vc is not None and int(vc.group(1)) >= 11 and 'L"N20_PartyShareClamp",' in cpp and 'L"CritHits", L"1",' in cpp,
       "Config.cpp: Version >= 11 (%s), секция N20, ключ N10 CritHits" % (vc.group(1) if vc else "?"))
    aj = open(os.path.join(HERE, "..", "..", "AsdaPatch", "src", "AcJournal.cpp"), encoding="utf-8-sig").read()
    ok("case 115: return L\"N20:" in aj and "case 116: return L\"N20:" in aj, "AcJournal.cpp: тексты видов ac.other 115/116 (N20)")

print("== ИТОГ verify_n20: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
