# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p72.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P72 «обезвреживание закладки CharItemKeeping(11)» (2026-10-15).
#
# Сервер НЕ запускается. Грузятся настоящие образы GameServer (сток 4e20f0ad, живой GameServer = Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) md5 образов; исходные байты обеих площадок и всех «соседей» (адреса переходов) в каждом образе — побайтно одинаковы;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок (0x4C2746..0x4C274A, 0x50A652..0x50A656);
#     площадки и цели переходов лежат на границах инструкций (линейный дизасм от начала блока);
#  3) в DLL: трамплин ArmTrampoline и P72_OnArmed найдены (по .map и экспорту), указатели маршрутов g_pRouteSilent/g_pRouteStock
#     в .data = 0x50A6EB / 0x50A6B6, новые байты меры 1 = `jmp 0x4C2869; nop`;
#  4) unicorn, мера 2: площадка 0x50A651 → трамплин → заглушка P72_OnArmed (маршрут 0/1) → выход ровно на 0x50A6EB / 0x50A6B6,
#     аргументы (mgr, userNum) верны, стек и ВСЕ регистры/флаги сохранены;
#  5) unicorn, мера 1: блок RunProcess 10024 со взведёнными флагами и просроченным тактом: сток — 550 вызовов memset и флаги
#     остаются 1; с P72 — 0 вызовов memset, флаги обнулены, выход на 0x4C28AA.
# Запуск: python verify_p72.py [AsdaPatch.dll]   (P57_IMG_DIR=<папка с gs_stock.exe/gs_live.exe/gs_indun.exe> — локальные копии)
import hashlib
import os
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe", "4e20f0ad0b13a54454405eed31ffe447"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe", "e7b4ac38"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe", "e7b4ac38"),
]
if os.environ.get("P57_IMG_DIR"):
    d = os.environ["P57_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe", "4e20f0ad0b13a54454405eed31ffe447"),
                 ("живой GameServer", d + "/gs_live.exe", "e7b4ac38"),
                 ("живой Indun", d + "/gs_indun.exe", "e7b4ac38")]

BASE = 0x00400000
# ── площадки (пишутся) ──
SITE_TIMER = 0x004C2745
SITE_TIMER_ORIG = "0f851e010000"            # jne 0x4C2869
SITE_TIMER_NEW = "e91f01000090"             # jmp 0x4C2869 ; nop
SITE_ARM = 0x0050A651
SITE_ARM_ORIG = "8b9514faffff"              # mov edx,[ebp-0x5EC]
# ── соседи (только сверка) ──
NEIGHBOURS = [
    ("ветка сброса 0x4C2869 (mov edx,[ebp-0xE4])",            0x004C2869, "8b951cffffff"),
    ("memset по слотам 0x4C2839 (call 0x56A5A0)",             0x004C2839, "e8627d0a00"),
    ("граница цикла 550 0x4C27F2",                            0x004C27F2, "81bd24ffffff26020000"),
    ("первая проверка флага 0x4C273B",                        0x004C273B, "0fb691ac510000"),
    ("порог 600000 0x4C27C7 (cmp [ebp-0xD4],0x927C0)",        0x004C27C7, "81bd2cffffffc0270900"),
    ("знаковое jle 0x4C27D1",                                 0x004C27D1, "0f8e90000000"),
    ("rand(600000..6000000) 0x4C2843",                        0x004C2843, "68808d5b0068c0270900e84e010700"),
    ("выход блока 0x4C28AA (lea ecx,[ebp-0x24])",             0x004C28AA, "8d4ddc51"),
    ("маршрут «молча» 0x50A6EB (jmp 0x50A9B6)",               0x0050A6EB, "e9c6020000"),
    ("маршрут «как сток» 0x50A6B6 (push off_5961EC; push 1Ah)", 0x0050A6B6, "68ec6159006a1a"),
    ("последняя запись взведения 0x50A6B0 (mov [edx+0x51B4],eax)", 0x0050A6B0, "8982b4510000"),
    ("userIndex в кадре 0x50A6D1 (mov cx,[ebp+8])",           0x0050A6D1, "668b4d08"),
    ("шаг 5: первая проверка флага 0x50A5DE",                 0x0050A5DE, "0fb688ac510000"),
    ("P18 D4 площадка 0x50A6E6 (call 0x4C28F0)",              0x0050A6E6, "e80582fbff"),
    ("конструктор CThread обнуляет флаги 0x4BF14A",           0x004BF14A, "c680ac51000000"),
]
BOUNDARIES = {0x004C2735: [SITE_TIMER, 0x004C2869, 0x004C28AA, 0x004C2839, 0x004C27D1],
              0x0050A5A0: [SITE_ARM, 0x0050A6B6, 0x0050A6EB, 0x0050A6B0, 0x0050A6E6]}

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
    """Сколько переходов/абсолютных ссылок ведут СТРОГО ВНУТРЬ (va, va+len) каждой площадки."""
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


def boundaries(img, base, start, wanted, span=0x400):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    seen = set(i.address for i in md.disasm(bytes(img[start - base:start - base + span]), start))
    return [w for w in wanted if w not in seen]


def map_syms(path):
    syms = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s", line)
        if m:
            syms[m.group(1)] = int(m.group(2), 16)
    return syms


def find_sym(syms, needle):
    if needle in syms:
        return syms[needle]
    c = [(n, v) for n, v in syms.items() if needle in n]
    return c[0][1] if len(c) == 1 else None


# ═══════════════════════════════ 1–2. образы ═══════════════════════════════
imgs = []
for name, path, md5want in GS_IMAGES:
    print("-- %s: %s" % (name, path))
    pe, img, base, md5 = load(path)
    ok(base == BASE, "ImageBase 0x%08X" % base)
    ok(md5.startswith(md5want), "md5 %s (ожидалось %s…)" % (md5, md5want))
    for n, va, hexs in [("площадка меры 1 0x4C2745 (jne 0x4C2869)", SITE_TIMER, SITE_TIMER_ORIG),
                        ("площадка меры 2 0x50A651 (mov edx,[ebp-0x5EC])", SITE_ARM, SITE_ARM_ORIG)] + NEIGHBOURS:
        got = bytes(img[va - base:va - base + len(hexs) // 2]).hex()
        ok(got == hexs, "%s: %s" % (n, got))
    hits = scan_into(pe, img, base, [("мера 1", SITE_TIMER, 6), ("мера 2", SITE_ARM, 6)])
    for n, h in hits.items():
        ok(h == 0, "ссылок внутрь площадки «%s»: %d" % (n, h))
    for start, wanted in BOUNDARIES.items():
        miss = boundaries(img, base, start, wanted)
        ok(not miss, "границы инструкций от 0x%08X: %s" % (start, "все на месте" if not miss else ["0x%08X" % m for m in miss]))
    imgs.append((name, pe, img, base))
ok(all(bytes(imgs[0][2][0x4C2735 - BASE:0x4C28B0 - BASE]) == bytes(i[2][0x4C2735 - BASE:0x4C28B0 - BASE]) for i in imgs),
   "блок 10024 (0x4C2735..0x4C28B0) побайтно одинаков на всех образах")
ok(all(bytes(imgs[0][2][0x50A5A0 - BASE:0x50A6F0 - BASE]) == bytes(i[2][0x50A5A0 - BASE:0x50A6F0 - BASE]) for i in imgs),
   "взведение шага 5 (0x50A5A0..0x50A6F0) побайтно одинаково на всех образах")

# ═══════════════════════════════ 3. DLL ═══════════════════════════════
print("-- DLL: %s" % DLL)
dpe = pefile.PE(DLL)
dimg = bytearray(dpe.get_memory_mapped_image())
dbase = dpe.OPTIONAL_HEADER.ImageBase
syms = map_syms(MAP)
tramp = find_sym(syms, "ArmTrampoline")
on_armed = find_sym(syms, "_P72_OnArmed@8")
p_silent = find_sym(syms, "g_pRouteSilent")
p_stock = find_sym(syms, "g_pRouteStock")
ok(tramp is not None and on_armed is not None, "по .map: ArmTrampoline=%s P72_OnArmed=%s" % (hex(tramp or 0), hex(on_armed or 0)))
ok(p_silent is not None and p_stock is not None, "по .map: g_pRouteSilent=%s g_pRouteStock=%s" % (hex(p_silent or 0), hex(p_stock or 0)))
exports = {e.name.decode(): dbase + e.address for e in dpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
ok(any("P72_OnArmed" in n for n in exports), "экспорт P72_OnArmed есть: %s" % [n for n in exports if "P72" in n])
if p_silent and p_stock:
    v1 = struct.unpack("<I", bytes(dimg[p_silent - dbase:p_silent - dbase + 4]))[0]
    v2 = struct.unpack("<I", bytes(dimg[p_stock - dbase:p_stock - dbase + 4]))[0]
    ok(v1 == 0x0050A6EB and v2 == 0x0050A6B6, "указатели маршрутов в .data: silent=0x%08X stock=0x%08X" % (v1, v2))
# тело трамплина: pushfd; pushad; movzx eax,word [ebp+8]; push eax; push [ebp-0x5EC]; call; test eax,eax; popad; jnz; popfd; jmp [..]; popfd; jmp [..]
if tramp:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ins = list(md.disasm(bytes(dimg[tramp - dbase:tramp - dbase + 0x40]), tramp))[:14]
    mn = [i.mnemonic for i in ins]
    print("     трамплин: " + " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in ins))
    ok(mn[:2] == ["pushfd", "pushal"] and "popal" in mn and mn.count("popfd") == 2 and mn.count("jmp") == 2
       and mn.index("test") < mn.index("popal") < mn.index("jne"),
       "трамплин: pushfd/pushad … test; popad; jnz; два popfd, два jmp [маршрут]")
    jmps = [i for i in ins if i.mnemonic == "jmp"]
    tg = sorted(int(i.op_str.split("[")[1].rstrip("]"), 16) for i in jmps)
    ok(tg == sorted([p_silent, p_stock]), "jmp dword ptr [..] разыменовывают g_pRouteSilent/g_pRouteStock")
    calls = [i for i in ins if i.mnemonic == "call"]
    ok(len(calls) == 1 and int(calls[0].op_str, 16) == on_armed, "call ведёт в P72_OnArmed")
ok(bytes.fromhex(SITE_TIMER_NEW)[0] == 0xE9 and struct.unpack("<i", bytes.fromhex(SITE_TIMER_NEW)[1:5])[0] == 0x004C2869 - (SITE_TIMER + 5),
   "новые байты меры 1 = jmp 0x4C2869 (rel32 %#x) + nop" % struct.unpack("<i", bytes.fromhex(SITE_TIMER_NEW)[1:5])[0])

# ═══════════════════════════════ 4–5. unicorn ═══════════════════════════════
name, pe, img, base = imgs[1]
SCR = 0x00100000     # заглушки
FRM = 0x00200000     # кадр
STK = 0x00300000     # стек
MGR = 0x00210000
THR = 0x00220000
POOL = 0x00230000
REGS = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI]
SENT = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666]
FLAGMASK = 0x8D5


def mk():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (len(img) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(base, bytes(img))
    uc.mem_map(dbase, (len(dimg) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(dbase, bytes(dimg))
    uc.mem_map(SCR, 0x10000)
    uc.mem_map(FRM, 0x40000)
    uc.mem_map(STK, 0x100000)
    return uc


def run_arm(route):
    uc = mk()
    # площадка → трамплин (как Hook::WriteJmp): jmp rel32 + nop
    uc.mem_write(SITE_ARM, b"\xE9" + struct.pack("<i", tramp - (SITE_ARM + 5)) + b"\x90")
    # заглушка P72_OnArmed: mov eax, route ; ret 8
    uc.mem_write(on_armed, b"\xB8" + struct.pack("<I", route) + b"\xC2\x08\x00")
    ebp = FRM + 0x800
    uc.mem_write(ebp - 0x5EC, struct.pack("<I", MGR))
    uc.mem_write(ebp + 8, struct.pack("<I", 0x00070000 | 7))     # word 7 (старшее слово — мусор)
    uc.mem_write(MGR + 4, struct.pack("<I", THR))
    uc.mem_write(THR + 0x51AC, b"\x01\x01\x01\x01\x00")
    esp0 = STK + 0x80000
    for r, v in zip(REGS, SENT):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp0)
    fl0 = 0x2C7 if route == 0 else 0x202          # разные наборы флагов
    uc.reg_write(UC_X86_REG_EFLAGS, fl0)
    st = {"end": None, "args": None, "n": 0}

    def hook(u, addr, size, _):
        st["n"] += 1
        if addr == on_armed:
            sp = u.reg_read(UC_X86_REG_ESP)
            st["args"] = struct.unpack("<II", u.mem_read(sp + 4, 8))
        if addr in (0x0050A6EB, 0x0050A6B6):
            st["end"] = addr
            u.emu_stop()
        if st["n"] > 200:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(SITE_ARM, 0, timeout=2000000)
    want = 0x0050A6EB if route == 0 else 0x0050A6B6
    ok(st["end"] == want, "маршрут %d: выход на 0x%08X (ожидалось 0x%08X)" % (route, st["end"] or 0, want))
    ok(st["args"] == (MGR, 7), "маршрут %d: аргументы P72_OnArmed(mgr=0x%08X, userNum=%d)" % (route, *(st["args"] or (0, 0))))
    ok(uc.reg_read(UC_X86_REG_ESP) == esp0, "маршрут %d: стек сбалансирован" % route)
    regs = [uc.reg_read(r) for r in REGS]
    ok(regs == SENT and uc.reg_read(UC_X86_REG_EBP) == ebp, "маршрут %d: все регистры сохранены (%s)" % (route, ["%08X" % r for r in regs]))
    fl = uc.reg_read(UC_X86_REG_EFLAGS)
    ok((fl & FLAGMASK) == (fl0 & FLAGMASK), "маршрут %d: флаги процессора сохранены (%#x → %#x)" % (route, fl0, fl))


print("-- unicorn: мера 2 (трамплин взведения)")
run_arm(0)
run_arm(1)


def run_timer(patched):
    uc = mk()
    if patched:
        uc.mem_write(SITE_TIMER, bytes.fromhex(SITE_TIMER_NEW))
    NOW = 0x9000_0000                      # такт ≥ 2^31 (как на @@ASTORY_SERVER_HOSTNAME@@)
    # заглушки: GetTickCount (IAT 0x583028), sub_4BE060 (thiscall, ret 4), sub_5329A0 (cdecl), memset (cdecl)
    uc.mem_write(SCR + 0x00, b"\xB8" + struct.pack("<I", NOW) + b"\xC3")                 # GetTickCount
    uc.mem_write(SCR + 0x10, b"\xB8" + struct.pack("<I", POOL) + b"\xC2\x04\x00")        # sub_4BE060 → всегда слот
    uc.mem_write(SCR + 0x20, b"\x33\xC0\xC3")                                           # sub_5329A0 → 0
    uc.mem_write(SCR + 0x30, b"\xC3")                                                   # memset — только счёт
    uc.mem_write(0x00583028, struct.pack("<I", SCR))
    uc.mem_write(0x004BE060, b"\xE9" + struct.pack("<i", (SCR + 0x10) - (0x004BE060 + 5)))
    uc.mem_write(0x005329A0, b"\xE9" + struct.pack("<i", (SCR + 0x20) - (0x005329A0 + 5)))
    uc.mem_write(0x0056A5A0, b"\xE9" + struct.pack("<i", (SCR + 0x30) - (0x0056A5A0 + 5)))
    ebp = FRM + 0x800
    uc.mem_write(ebp - 0xE4, struct.pack("<I", THR))
    uc.mem_write(THR + 0x51AC, b"\x01\x01\x01\x01\x01")
    uc.mem_write(THR + 0x51B4, struct.pack("<I", (NOW - 700_000) & 0xFFFFFFFF))         # просрочено > 600000
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, STK + 0x80000)
    st = {"memset": 0, "end": None, "n": 0}

    def hook(u, addr, size, _):
        st["n"] += 1
        if addr == SCR + 0x30:
            st["memset"] += 1
        if addr == 0x004C28AA:
            st["end"] = addr
            u.emu_stop()
        if st["n"] > 200000:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x004C2735, 0, timeout=5000000)
    flags = bytes(uc.mem_read(THR + 0x51AC, 5))
    tick = struct.unpack("<I", uc.mem_read(THR + 0x51B4, 4))[0]
    ok(st["end"] == 0x004C28AA, "%s: блок дошёл до выхода 0x4C28AA" % ("P72" if patched else "сток"))
    if patched:
        ok(st["memset"] == 0, "P72: memset по слотам НЕ вызван (вызовов %d)" % st["memset"])
        ok(flags == b"\0" * 5, "P72: флаги обнулены веткой сброса: %s" % flags.hex())
    else:
        ok(st["memset"] == 550, "сток: memset вызван по всем 550 слотам (вызовов %d) — закладка воспроизведена" % st["memset"])
        ok(flags == b"\1" * 5 and tick == NOW, "сток: флаги остались 1, такт перевзведён (=now+rand): %s, 0x%08X" % (flags.hex(), tick))


print("-- unicorn: мера 1 (таймер затирания, такт ≥ 2^31)")
run_timer(False)
run_timer(True)

print("== ИТОГ verify_p72: ошибок %d ==" % bad)
sys.exit(1 if bad else 0)
