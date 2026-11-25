# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p74.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P74 «HP игрока соседям по сектору» (синхронизация боя Ф3, 2026-10-17).
#
# Сервер НЕ запускается. Грузятся настоящие образы GameServer (сток 4e20f0ad, живой GameServer = Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) md5 образов; исходные байты обеих площадок (call 0x4C28F0) и соседей (аргументы SendPacket, гейт типов 2/4, тип 0 в
#     sub_448850, продолжение после вызова) в каждом образе; функции-получатели одинаковы; ret SendPacket = 18h, sub_52E6D0 = 14h;
#  2) в .text ни один переход и ни один abs32 не ведёт ВНУТРЬ площадок (0x43C855..0x43C858, 0x43CE83..0x43CE86); площадки и
#     продолжения на границах инструкций;
#  3) в DLL: заглушки StubDamage/StubTime и P74_AfterSelfSend найдены (.map, экспорт P74_GetStats), g_pSendPacket = 0x4C28F0,
#     тело заглушки: push ebp … call [g_pSendPacket] … push <площадка> … call P74_AfterSelfSend … ret 18h;
#  4) unicorn: настоящий код площадки (0x43C83A / 0x43CE68) → call заглушки → SendPacket-заглушка (запись аргументов, ret 18h)
#     → P74_AfterSelfSend-заглушка (запись аргументов, ret 14h) → выход ровно на 0x43C859 / 0x43CE87; ecx у SendPacket = net,
#     аргументы те же, что в стоке; аргументы P74_AfterSelfSend (net, 4058, кому, тело, площадка); стек и ebx/esi/edi/ebp сохранены.
#  5) ★ ред. 2 (17.10): маршруты по вызовам в каждом образе — все `call 0x43CB00` (SetCurrentHpTimeValue) с a6 = 1 (8 шт.:
#     CharSpendItemUse ×7, sub_4F3D90) и a6 = 6 (1 шт.: sub_46AB50) идут с a5 = 1 → снимок уходит через ветку «не 2/4» = S2
#     (новая площадка не нужна); `call 0x43C690` (sub_43C690): a5 = 1 — 22 вызова (S1), a5 = 0 — 2 (sub_426B00 удар моба,
#     sub_555800 обычная атака PvP: 4058 не шлётся даже себе — вне охвата P74).
# Запуск: python verify_p74.py [AsdaPatch.dll]   (P74_IMG_DIR=<папка с gs_stock.exe/gs_live.exe/gs_indun.exe> — локальные копии)
import hashlib
import os
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)

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
if os.environ.get("P74_IMG_DIR"):
    d = os.environ["P74_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe", "4e20f0ad0b13a54454405eed31ffe447"),
                 ("живой GameServer", d + "/gs_live.exe", "e7b4ac38"),
                 ("живой Indun", d + "/gs_indun.exe", "e7b4ac38")]

BASE = 0x00400000
SITE_DMG, SITE_TIME = 0x0043C854, 0x0043CE82
SITES = [("S1 урон 0x43C854 (call 0x4C28F0)", SITE_DMG, "e897600800"),
         ("S2 время 0x43CE82 (call 0x4C28F0)", SITE_TIME, "e8695a0800")]
NEIGHBOURS = [
    ("S1 аргументы 0x43C83A (push 1/0/тело/кому/11h/0FDAh; ecx=[[ebp-28h]+4])", 0x0043C83A,
     "6a016a008d55ec52668b4508506a1168da0f00008b4dd88b4904"),
    ("S1 продолжение 0x43C859 (mov dx,[ebp+8])", 0x0043C859, "668b5508"),
    ("S2 аргументы 0x43CE68 (push 1/0/тело/кому/11h/0FDAh; ecx=[[ebp-40h]+4])", 0x0043CE68,
     "6a016a008d55ec52668b4508506a1168da0f00008b4dc08b4904"),
    ("S2 продолжение 0x43CE87 (mov dx,[ebp+8])", 0x0043CE87, "668b5508"),
    ("S2 гейт типов 2/4 0x43CE34", 0x0043CE34, "0fb6551883fa0274090fb6451883f8047522"),
    ("S2 стоковая рассылка сектору 0x43CE61 (call sub_52E630)", 0x0043CE61, "e8ca170f00"),
    ("sub_448850: тип = 0 (0x448876)", 0x00448876, "c6400a00"),
    ("sub_448850: навык = -1 (0x44887D)", 0x0044887D, "66c7410bffff"),
]
SAME = [(0x0043C800, 0x0043C8A0), (0x0043CE00, 0x0043CED0), (0x004C28F0, 0x004C29C0), (0x0052E6D0, 0x0052E730),
        (0x0041EA80, 0x0041EC30), (0x00448850, 0x00448898)]
BOUNDARIES = {0x0043C800: [0x0043C83A, SITE_DMG, 0x0043C859], 0x0043CE34: [0x0043CE68, SITE_TIME, 0x0043CE87]}

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


def boundaries(img, base, start, wanted, span=0x100):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    seen = set(i.address for i in md.disasm(bytes(img[start - base:start - base + span]), start))
    return [w for w in wanted if w not in seen]


def rets(img, base, a, b):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return [i.op_str for i in md.disasm(bytes(img[a - base:b - base]), a) if i.mnemonic == "ret"]


def map_syms(path):
    """Символы ТОЛЬКО объекта p74_hp_sector_sync.obj (имена вида g_pSendPacket есть и в других патчах)."""
    syms = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s.*p74_hp_sector_sync\.obj", line)
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
    for n, va, hexs in SITES + NEIGHBOURS:
        got = bytes(img[va - base:va - base + len(hexs) // 2]).hex()
        ok(got == hexs, "%s: %s" % (n, got))
    for n, va, _ in SITES:
        tgt = va + 5 + struct.unpack("<i", bytes(img[va - base + 1:va - base + 5]))[0]
        ok(tgt == 0x004C28F0, "%s: цель вызова 0x%08X" % (n, tgt))
    ok(rets(img, base, 0x004C28F0, 0x004C29C0) == ["0x18"], "SendPacket 0x4C28F0: ret 18h (6 аргументов, чистит сам)")
    ok(rets(img, base, 0x0052E6D0, 0x0052E730) == ["0x14"], "sub_52E6D0: ret 14h (5 аргументов, чистит сам)")
    hits = scan_into(pe, img, base, [("S1", SITE_DMG, 5), ("S2", SITE_TIME, 5)])
    for n, h in hits.items():
        ok(h == 0, "ссылок внутрь площадки %s: %d" % (n, h))
    for start, wanted in BOUNDARIES.items():
        miss = boundaries(img, base, start, wanted)
        ok(not miss, "границы инструкций от 0x%08X: %s" % (start, "все на месте" if not miss else ["0x%08X" % m for m in miss]))
    imgs.append((name, pe, img, base))
for a, b in SAME:
    ok(all(bytes(imgs[0][2][a - BASE:b - BASE]) == bytes(i[2][a - BASE:b - BASE]) for i in imgs),
       "0x%08X..0x%08X побайтно одинаково на всех образах" % (a, b))

# ═══════════════════════════════ 3. DLL ═══════════════════════════════
print("-- DLL: %s" % DLL)
dpe = pefile.PE(DLL)
dimg = bytearray(dpe.get_memory_mapped_image())
dbase = dpe.OPTIONAL_HEADER.ImageBase
syms = map_syms(MAP)
s_dmg = find_sym(syms, "?StubDamage@")
s_time = find_sym(syms, "?StubTime@")
after = find_sym(syms, "_P74_AfterSelfSend@20")
p_send = find_sym(syms, "?g_pSendPacket@")
ok(s_dmg and s_time and after and p_send, "по .map: StubDamage=%s StubTime=%s P74_AfterSelfSend=%s g_pSendPacket=%s"
   % (hex(s_dmg or 0), hex(s_time or 0), hex(after or 0), hex(p_send or 0)))
exports = {e.name.decode(): dbase + e.address for e in dpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
ok(any("P74_GetStats" in n for n in exports), "экспорт P74_GetStats есть: %s" % [n for n in exports if "P74" in n])
if p_send:
    v = struct.unpack("<I", bytes(dimg[p_send - dbase:p_send - dbase + 4]))[0]
    ok(v == 0x004C28F0, "g_pSendPacket в .data = 0x%08X" % v)
md = Cs(CS_ARCH_X86, CS_MODE_32)
for title, stub, site_id in (("StubDamage", s_dmg, 1), ("StubTime", s_time, 2)):
    if not stub:
        continue
    ins = []
    for i in md.disasm(bytes(dimg[stub - dbase:stub - dbase + 0x60]), stub):
        ins.append(i)
        if i.mnemonic == "ret":
            break
    print("     %s: %s" % (title, " ; ".join("%s %s" % (i.mnemonic, i.op_str) for i in ins)))
    calls = [i for i in ins if i.mnemonic == "call"]
    ok(len(calls) == 2 and ("0x%x" % p_send) in calls[0].op_str and int(calls[1].op_str, 16) == after,
       "%s: call [g_pSendPacket], затем call P74_AfterSelfSend" % title)
    ok(ins[-1].mnemonic == "ret" and ins[-1].op_str == "0x18", "%s: выход ret 18h (как SendPacket)" % title)
    ok(any(i.mnemonic == "push" and i.op_str == str(site_id) for i in ins), "%s: push %d (номер площадки)" % (title, site_id))
    ok(not any(i.mnemonic in ("pushal", "popal") or ("ebx" in i.op_str or "esi" in i.op_str or "edi" in i.op_str) for i in ins),
       "%s: ebx/esi/edi не трогаются" % title)

# ═══════════════════════════════ 4. unicorn ═══════════════════════════════
name, pe, img, base = imgs[1]
SCR = 0x00100000
FRM = 0x00200000
STK = 0x00300000
PARAM, NET = 0x00210000, 0x00220000
SENT = {UC_X86_REG_EBX: 0x22222222, UC_X86_REG_ESI: 0x55555555, UC_X86_REG_EDI: 0x66666666}


def run(site_va, start, end, frame_this, stub):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (len(img) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(base, bytes(img))
    uc.mem_map(dbase, (len(dimg) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(dbase, bytes(dimg))
    for a in (SCR, FRM, STK):
        uc.mem_map(a, 0x100000 if a == STK else 0x40000)
    # площадка → заглушка (как Hook::WriteCall)
    uc.mem_write(site_va, b"\xE8" + struct.pack("<i", stub - (site_va + 5)))
    # SendPacket-заглушка: mov eax,0x5E17 ; ret 18h ;  P74_AfterSelfSend-заглушка: mov eax,0xBADBAD ; ret 14h
    uc.mem_write(0x004C28F0, b"\xB8" + struct.pack("<I", 0x5E17) + b"\xC2\x18\x00")
    uc.mem_write(after, b"\xB8" + struct.pack("<I", 0xBADBAD) + b"\xC2\x14\x00")
    ebp = FRM + 0x800
    uc.mem_write(ebp + frame_this, struct.pack("<I", PARAM))
    uc.mem_write(PARAM + 4, struct.pack("<I", NET))
    uc.mem_write(ebp + 8, struct.pack("<I", 0xBEEF0007))
    esp0 = STK + 0x80000
    for r, v in SENT.items():
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp0)
    st = {"send": None, "ecx": None, "after": None, "end": None, "n": 0}

    def hook(u, addr, size, _):
        st["n"] += 1
        sp = u.reg_read(UC_X86_REG_ESP)
        if addr == 0x004C28F0:
            st["send"] = struct.unpack("<6I", u.mem_read(sp + 4, 24))
            st["ecx"] = u.reg_read(UC_X86_REG_ECX)
        if addr == after:
            st["after"] = struct.unpack("<5I", u.mem_read(sp + 4, 20))
        if addr == end:
            st["end"] = addr
            st["eax"] = u.reg_read(UC_X86_REG_EAX)
            u.emu_stop()
        if st["n"] > 500:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(start, 0, timeout=2000000)
    tag = "0x%08X" % site_va
    ok(st["end"] == end, "%s: выход на 0x%08X" % (tag, end))
    body = ebp - 0x14
    s = st["send"]
    ok(s is not None and st["ecx"] == NET and (s[0] & 0xFFFF) == 0xFDA and (s[1] & 0xFFFF) == 0x11 and (s[2] & 0xFFFF) == 7
       and s[3] == body and s[4] == 0 and s[5] == 1,
       "%s: SendPacket себе — ecx=net, (4058, 17, кому 7, тело [ebp-14h], 0, 1) как в стоке: %s" % (tag, s and ["%#x" % x for x in s]))
    a = st["after"]
    site_id = 1 if site_va == SITE_DMG else 2
    ok(a is not None and a[0] == NET and (a[1] & 0xFFFF) == 0xFDA and (a[2] & 0xFFFF) == 7 and a[3] == body and a[4] == site_id,
       "%s: P74_AfterSelfSend(net, 4058, 7, тело, %d): %s" % (tag, site_id, a and ["%#x" % x for x in a]))
    ok(st.get("eax") == 0x5E17, "%s: eax = результат SendPacket (0x%X)" % (tag, st.get("eax") or 0))
    ok(uc.reg_read(UC_X86_REG_ESP) == esp0, "%s: стек сбалансирован" % tag)
    ok(all(uc.reg_read(r) == v for r, v in SENT.items()) and uc.reg_read(UC_X86_REG_EBP) == ebp,
       "%s: ebx/esi/edi/ebp сохранены" % tag)


if s_dmg and s_time and after:
    print("-- unicorn: S1 (sub_43C690) и S2 (SetCurrentHpTimeValue)")
    run(SITE_DMG, 0x0043C83A, 0x0043C859, -0x28, s_dmg)
    run(SITE_TIME, 0x0043CE68, 0x0043CE87, -0x40, s_time)


# ═══════════════════════════════ 5. маршруты вызовов (ред. 2) ═══════════════════════════════
def call_pushes(pe, img, base, targets):
    """Линейная развёртка .text (capstone, skipdata): для каждого `call target` — значения push перед ним (ближайший — последним)."""
    a, b = text_range(pe)
    md2 = Cs(CS_ARCH_X86, CS_MODE_32)
    md2.skipdata = True
    ins = [(i.address, i.mnemonic, i.op_str) for i in md2.disasm(bytes(img[a:b]), base + a)]
    out = {t: [] for t, _ in targets}
    want = {hex(t): (t, n) for t, n in targets}
    for k, (ad, mn, op) in enumerate(ins):
        if mn != "call" or op not in want:
            continue
        t, npush = want[op]
        vals, j = [], k - 1
        while j >= 0 and len(vals) < npush and k - j < 60:
            if ins[j][1] == "push":
                try:
                    vals.append(int(ins[j][2], 0) & 0xFFFFFFFF)
                except ValueError:
                    vals.append(None)                 # регистр/память
            j -= 1
        out[t].append((ad, list(reversed(vals)) if len(vals) == npush else None))
    return out


print("-- маршруты вызовов: SetCurrentHpTimeValue 0x43CB00 (a6 = 1/6) и sub_43C690 (a5)")
for name, pe, img, base in imgs:
    cp = call_pushes(pe, img, base, [(0x0043CB00, 6), (0x0043C690, 4)])
    hp = cp[0x0043CB00]                                    # push a7, a6, a5, a4, a3, a2
    t1 = [c for c, v in hp if v and v[1] == 1]
    t6 = [c for c, v in hp if v and v[1] == 6]
    unk = [c for c, v in hp if v is None]
    a5_ok = all(v[2] == 1 for c, v in hp if v and v[1] in (1, 6))
    ok(len(t1) == 8 and len(t6) == 1 and a5_ok and not unk,
       "%s: SetCurrentHpTimeValue — a6=1: %d вызовов %s, a6=6: %d %s, у всех a5=1 → ветка «не 2/4» = S2 (вызовов всего %d, без разбора %d)"
       % (name, len(t1), ["0x%X" % c for c in t1], len(t6), ["0x%X" % c for c in t6], len(hp), len(unk)))
    dm = cp[0x0043C690]                                    # push a5, damage, a3, userNum
    d1 = [c for c, v in dm if v and v[0] == 1]
    d0 = [c for c, v in dm if v and v[0] == 0]
    ok(len(d1) == 22 and len(d0) == 2 and len(dm) == 24,
       "%s: sub_43C690 — a5=1: %d (S1), a5=0: %d %s (4058 не шлётся — удар моба / обычная атака PvP)"
       % (name, len(d1), len(d0), ["0x%X" % c for c in d0]))

print("== ИТОГ verify_p74: ошибок %d ==" % bad)
sys.exit(1 if bad else 0)
