# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n21.py — СТАТИЧЕСКАЯ проверка N21 (слот P93, волна invismobs, 26.10.2026): появившийся монстр не встаёт в клетку
#   живого монстра. Сервер НЕ запускается, образы только читаются. Логику проверяет stand_n21 (настоящий код ветки).
#   1. Пять образов NpcServer (сток 16c7a0af, IDB d292e4ec, живой c02486d6, Indun 0de2c559, Ch2 7f79b5da): байты площадки
#      0x46292B; инструкции начинаются ровно на площадке и после неё (линейный проход от начала sub_461C80); сплошной перебор
#      rel8/rel32/jcc32 по .text — входов внутрь изменяемых байтов нет; окна ±32 б одинаковы на всех образах.
#   2. Кадр: в 0x46292B сходятся 0x4628CF (jle) и 0x4628F0 (jge) с одной глубиной стека (sub_41AC10 снимает 14h);
#      [esp+1Ch] — номер монстра цикла (0x461DDA/0x461DF0, imul 92F8h, lea edi,[eax+ebx]); [esp+20h] — карта this+11547E4h
#      (0x46206D/0x462076), GetTileState берёт её же (0x4628C0); флаг «живой» [edi+765Ch] бит 0 (0x461E13); число монстров
#      [ebx+2954858h]; x/z пишутся в [ecx+7698h]/[ecx+769Ch] при ecx = edi+8 (0x46292F…0x462939); GetTileState —
#      [ecx+4] ширина, [ecx+28h] число клеток, [ecx+34h] массив по 12 б.
#   3. DLL (по .map): стаб St_RespawnFreeTile — pushfd/pushad, номер [eax+44h], карта [eax+48h], &ebx/&esi кадра pushad,
#      edi, call N21_Pick; popad/popfd, исходные `mov edx,[esp+34h]` (+4) и `lea ecx,[edi+8]`, ret; реестр — N21 после N20;
#      Config Version = 12.
# Запуск: py -3 verify_n21.py [AddonNPC.dll]
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
    ("живой Ch2 NpcServer", V2 + "Ch2_NpcServer/NpcServer.exe", "7f79b5daf74c7754d622853cb1335718"),
]
# (имя, VA, байты стока, начало функции для линейного прохода)
SITES = [("N21 sub_461C80 клетка возрождения", 0x46292B, bytes.fromhex("8B5424308D4F08"), 0x461C80)]
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
        ok(va in starts and va + 4 in starts and va + len(stock) in starts,
           "%s %s: границы инструкций 0x%06X / 0x%06X → 0x%06X (линейный проход от 0x%06X)" % (name, sname, va, va + 4, va + len(stock), fn))
        win += img[va - base - 32:va - base + len(stock) + 32]
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
    fn_ins = set(i.address for i in insns(img, base, 0x461C80, 0x462F80))
    for src, tgt in hits:
        if 0x461C80 <= src < 0x462F80 and src in fn_ins:
            real.append((src, tgt))
    ok(not real, "%s: переходов внутрь изменяемых байтов нет (сплошной перебор .text: кандидатов %d, на границах инструкций функции %d)"
       % (name, len(hits), len(real)))
    windows.append((name, win))
if len(windows) == len(IMAGES):
    ok(all(w == windows[0][1] for _, w in windows), "окна ±32 б вокруг площадки побайтово одинаковы на %d образах" % len(windows))

print("== 2. кадр")
if first:
    pe, img, base = first
    T = lambda va: text_of(img, base, va)
    ok(T(0x4628CF) == "jle 0x46292b" and T(0x4628F0) == "jge 0x46292b", "в 0x46292B сходятся 0x4628CF (jle) и 0x4628F0 (jge)")
    rets = set()
    for i in md.disasm(img[0x41AC10 - base:0x41AC10 - base + 0x400], 0x41AC10):
        if i.mnemonic == "ret":
            rets.add(int(i.op_str, 0) if i.op_str else 0)
    ok(rets == {0x14}, "sub_41AC10 снимает 14h (ret: %s) — у обеих веток кадр один" % sorted(rets))
    ok(T(0x461DDA) == "mov dword ptr [esp + 0x1c], 0" and T(0x461DF0) == "mov eax, dword ptr [esp + 0x1c]"
       and T(0x461DFB) == "imul eax, eax, 0x92f8" and T(0x461E10) == "lea edi, [eax + ebx]",
       "[esp+1Ch] — номер монстра цикла, ячейка edi = this + номер × 92F8h")
    ok(T(0x461DD3) == "cmp dword ptr [ebx + 0x2954858], 0", "число монстров карты — [this + 2954858h]")
    ok(T(0x461E13) == "mov eax, dword ptr [edi + 0x765c]" and T(0x461E19) == "test al, 1", "флаг «живой» — [ячейка + 765Ch] бит 0")
    ok(T(0x46206D) == "add ebx, 0x11547e4" and T(0x462076) == "mov dword ptr [esp + 0x20], ebx", "[esp+20h] = this + 11547E4h (карта)")
    ok(T(0x4628C0) == "mov ecx, dword ptr [esp + 0x20]" and T(0x4628C8) == "call 0x41a310", "GetTileState(0x41A310) получает карту [esp+20h]")
    ok(T(0x46292F) == "lea ecx, [edi + 8]" and T(0x462932) == "mov word ptr [ecx + 0x7698], si" and T(0x462939) == "mov word ptr [ecx + 0x769c], bx",
       "клетка пишется из si/bx в монстр edi+8 (+7698h/+769Ch)")
    ok(T(0x461E08) == "movzx edx, word ptr [eax + ebx + 0x76a0]" and T(0x461E1F) == "movzx ecx, word ptr [edi + 0x76a4]",
       "клетка монстра в ячейке: x [+76A0h], z [+76A4h] (= монстр +7698h/+769Ch)")
    gts = [(i.mnemonic + " " + i.op_str) for i in md.disasm(img[0x41A310 - base:0x41A310 - base + 0x40], 0x41A310)][:14]
    ok(any("[ecx + 4]" in g for g in gts) and any("[ecx + 0x28]" in g for g in gts) and any("[ecx + 0x34]" in g for g in gts),
       "GetTileState: ширина [ecx+4], число клеток [ecx+28h], массив [ecx+34h] (%s)" % " ; ".join(gts[:8]))

print("== 3. DLL: стаб, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map — сначала build.bat" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx, obj):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+%s\.obj\s*$" % (rx, obj), mp, re.M)
        return int(m.group(2), 16) if m else 0

    va = sym(r"\?St_RespawnFreeTile@\S+", "n21_respawn_free_tile")
    ok(va != 0, "N21 символ St_RespawnFreeTile @%08X" % va)
    if va:
        c = [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + 96], va)][:16]
        print("    St_RespawnFreeTile: %s" % " ; ".join(c[:16]))
        ok(c[:8] == ["pushfd", "pushal", "mov eax, esp", "push dword ptr [eax + 0x44]", "push dword ptr [eax + 0x48]",
                     "lea ecx, [eax + 0x10]", "push ecx", "lea ecx, [eax + 4]"],
           "N21: номер [eax+44h] = кадр+1Ch, карта [eax+48h] = кадр+20h (+24h pushad/pushfd, +4 адрес возврата), &ebx = +10h")
        ok(c[8:10] == ["push ecx", "push edi"] and c[10].startswith("call"), "N21: &esi = +4, ячейка edi, call N21_Pick")
        ok(c[11:15] == ["popal", "popfd", "mov edx, dword ptr [esp + 0x34]", "lea ecx, [edi + 8]"] and c[15] == "ret",
           "N21: popad/popfd, исходные `mov edx,[esp+34h]` (+4) и `lea ecx,[edi+8]`, ret")
    ok(sym(r"_N21_Pick@20", "n21_respawn_free_tile") != 0, "N21_Pick (__stdcall, 20 б) в .map")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    order = [m.group(1) for m in re.finditer(r'\{ L"(\w+)",', reg)]
    # ★ 31.10.2026: за N21 может идти следующий патч (N22) — проверяем, что N21 стоит сразу после N20.
    i21 = order.index("N21_RespawnFreeTile") if "N21_RespawnFreeTile" in order else -1
    ok(i21 > 0 and order[i21 - 1] == "N20_PartyShareClamp",
       "реестр: N21 сразу после N20 (%s)" % ", ".join(order[max(i21 - 1, 0):i21 + 2]))
    cfg = open(os.path.join(SRC, "Config.h"), encoding="utf-8-sig").read()
    mv = re.search(r"constexpr int kVersion = (\d+);", cfg)
    ok(mv is not None and int(mv.group(1)) >= 12, "Config.h: kVersion ≥ 12 (N21 — с версии 12; сейчас %s)" % (mv and mv.group(1)))
    cpp = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    mvc = re.search(r'\{ L"Version", L"(\d+)",', cpp)
    ok(mvc is not None and int(mvc.group(1)) >= 12 and 'L"N21_RespawnFreeTile",' in cpp and '{ L"Radius", L"2",' in cpp,
       "Config.cpp: Version ≥ 12, секция N21 (Enabled, Radius=2)")

print("== ИТОГ verify_n21: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
