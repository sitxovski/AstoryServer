# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n16.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны N16 (2026-10-15): допуск проверки скорости атаки
#   NpcServer = max(100 мс, AttackToleranceRate % длительности) — расширение патча N01 (AddonNPC).
# Сервер НЕ запускается. Образы только читаются.
#   1. Три образа NpcServer (сток 16c7a0af, живой c02486d6, Indun 0de2c559): байты 5 площадок N01 (стоковые) и
#      соседей (загрузка такта/dur, cmp, цели jge), границы площадок по дизасму, перебор rel8/rel32/jcc32/abs32 —
#      входов внутрь площадок нет.
#   2. DLL (по .map): St_TolMain / St_TolTwin / N01_TolSum / g_n01Rate — дизасм стабов.
#   3. unicorn: НАСТОЯЩИЙ код хоста 0x45F596…jae и 0x46014A…jae с байтами N16 (call в стаб DLL) — матрица
#      интервалов dur × (0/−10/−14/−15/−16/−30 %), Rate 15 и 0 (прежние байты N01); сохранность регистров.
# Запуск: py -3 verify_n16.py [AddonNPC.dll] [сток.exe живой.exe indun.exe]
import hashlib
import os
import struct
import sys

sys.dont_write_bytecode = True
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))   # ★ 22.10.2026: srv_paths.py
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe"),
]
if len(sys.argv) > 4:
    IMAGES = [(n, p) for (n, _), p in zip(IMAGES, sys.argv[2:5])]

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


# ── площадки N01 (стоковые байты) и соседи ─────────────────────────────────
SITES = [
    ("N01.1 моб",      0x0045F5A4, "668bd7662b9590fe00006683c2640fb7ca0fb7c9"),
    ("N01.2 PvP",      0x00460151, "668bc7662b8590fe0000660564000fb7c8"),
    ("N01.3 усечение", 0x00460169, "0fb7c9"),
    ("N01.4 jge моб",  0x0045F5BA, "0f8dc1000000"),   # байт условия 0x45F5BB
    ("N01.5 jge PvP",  0x0046016E, "0f8dc1000000"),   # байт условия 0x46016F
]
NEIGH = [
    ("моб: mov edi,[esp+298h] (такт)",             0x0045F596, "8bbc2498020000"),
    ("моб: movsx eax,word [ebp+0FE94h] (dur)",     0x0045F59D, "0fbf8594fe0000"),
    ("моб: cmp ecx,eax",                           0x0045F5B8, "3bc8"),
    ("моб: отказ — add byte [ebp+0FE60h],1",       0x0045F5C0, "808560fe000001"),
    ("моб: принят — mov al,[ebp+0FE60h]",          0x0045F681, "8a8560fe0000"),
    ("моб: push ecx / push eax (Check: сумма, dur)", 0x0045F5D1, "5150"),
    ("моб: cmp byte [ebp+0FE60h],1Eh (порог 30)",  0x0045F608, "80bd60fe00001e"),
    ("PvP: mov edi,[esp+0B0h] (такт)",              0x0046014A, "8bbc24b0000000"),
    ("PvP: movsx eax,word [ebp+0FE94h] (dur)",     0x00460162, "0fbf8594fe0000"),
    ("PvP: cmp ecx,eax",                           0x0046016C, "3bc8"),
    ("PvP: отказ — add byte [ebp+0FE60h],1",       0x00460174, "808560fe000001"),
    ("PvP: принят — mov al,[ebp+0FE60h]",          0x00460235, "8a8560fe0000"),
    ("PvP: push ecx (Check: сумма)",               0x00460185, "51"),
    ("PvP: cmp byte [ebp+0FE60h],1Eh (порог 30)",  0x004601BC, "80bd60fe00001e"),
    ("dur следующего удара: call sub_401900 (моб)", 0x0045F717, "e8e421faff"),
    ("dur следующего удара: call sub_401900 (PvP)", 0x004602BC, "e83f16faff"),
    ("sub_401900: таблица Combo.lst 0x786BA8",     0x0040191C, "668b0455a86b7800"),
    ("навык: dur = Skill.lst (0x786DA0)",          0x00418F9E, "668b0485a06d7800"),
]


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def boundary_ok(img, base, va, ln):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    total, end_ok = 0, False
    for ins in md.disasm(bytes(img[va - base: va - base + ln + 16]), va):
        total += ins.size
        if total >= ln:
            end_ok = total == ln
            break
    start_ok = False
    for back in range(1, 48):
        for ins in md.disasm(bytes(img[va - base - back: va - base + 16]), va - back):
            if ins.address == va:
                start_ok = True
                break
            if ins.address > va:
                break
        if start_ok:
            break
    return start_ok, end_ok


# Ложные «входы»: байт 7x/E8/EB — операнд другой инструкции. Доказательство — байты инструкции-хозяина и то,
# что она начинается на границе после настоящей инструкции (call N14 @0x460131, 5 б → 0x460136).
KNOWN_FALSE = {
    0x00460137: (0x00460131, "e8", 0x00460136, "8b742440",
                 "74 — ModRM в `mov esi,[esp+40h]` @0x460136 (после `call sub_408D40` @0x460131)"),
}


def scan_into(pe, img, base, sites):
    a, b = text_range(pe)
    rng = [(n, va, len(bytes.fromhex(o))) for n, va, o in sites]
    hits = {n: [] for n, _, _ in rng}
    for i in range(a, b - 6):
        if any(va <= base + i < va + ln for _, va, ln in rng):
            continue
        if base + i in KNOWN_FALSE:
            pva, pb, hva, hb, why = KNOWN_FALSE[base + i]
            if bytes(img[pva - base: pva - base + 1]).hex() == pb and bytes(img[hva - base: hva - base + 4]).hex() == hb:
                print("    (ложный вход @0x%08X исключён: %s)" % (base + i, why))
                continue
        o = img[i]
        cands = []
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            cands.append(base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0])
        if o in (0xE8, 0xE9):
            cands.append(base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0])
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            cands.append(base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0])
        for t in cands:
            for n, va, ln in rng:
                if va < t < va + ln:
                    hits[n].append(("переход", base + i))
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in rng:
            if va < v < va + ln:
                hits[n].append(("abs32", base + i))
    return hits


def map_syms(path):
    want = {"_N01_TolSum@8": None, "St_TolMain": None, "St_TolTwin": None, "g_n01Rate": None}
    for line in open(path, encoding="latin-1"):
        p = line.split()
        if len(p) < 3:
            continue
        for k in want:
            if (p[1] == k or ("?%s@" % k) in p[1]) and want[k] is None:
                want[k] = int(p[2], 16)
    return want


def rel(src, dst):
    return struct.pack("<i", dst - (src + 5))


def n16_bytes(st_main, st_twin):
    m = bytes.fromhex("8bd72b9590fe0000") + b"\xe8" + rel(0x0045F5AC, st_main) + b"\x90" * 7
    t = bytes.fromhex("8bc72b8590fe0000") + b"\xe8" + rel(0x00460159, st_twin) + b"\x90" * 4
    return m, t


N01_OLD_MAIN = bytes.fromhex("8bd72b9590fe000083c2648bca") + b"\x90" * 7
N01_OLD_TWIN = bytes.fromhex("8bc72b8590fe000083c0648bc8") + b"\x90" * 4


class Emu:
    def __init__(self, host_img, host_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((host_base, host_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)   # стек
        self.uc.mem_map(0x00300000, 0x00020000)   # запись игрока
        self.stops = set()
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, count=200):
        for r, v in regs.items():
            self.uc.reg_write(r, v)
        self.stopped_at = None
        try:
            self.uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (self.uc.reg_read(0x2A), e))
        return self.stopped_at


def expect(rate, dt, dur):
    if rate == 0:
        return ((dt + 100) & 0xFFFFFFFF) >= (dur & 0xFFFFFFFF)
    if dur <= 0:
        return True
    tol = max(100, dur * rate // 100)
    s = dt + tol
    return s > 0xFFFFFFFF or s >= dur


def emulate(img, base, dimg, dbase, syms):
    REC = 0x00300000
    for rate in (15, 0):
        e = Emu(img, base, dimg, dbase)
        if rate:
            m, t = n16_bytes(syms["St_TolMain"], syms["St_TolTwin"])
        else:
            m, t = N01_OLD_MAIN, N01_OLD_TWIN
        e.uc.mem_write(0x0045F5A4, m)
        e.uc.mem_write(0x00460151, t)
        e.uc.mem_write(0x00460169, b"\x90\x90\x90")
        e.uc.mem_write(0x0045F5BB, b"\x83")
        e.uc.mem_write(0x0046016F, b"\x83")
        e.uc.mem_write(syms["g_n01Rate"], struct.pack("<i", rate))
        e.stops = {0x0045F5C0, 0x0045F681, 0x00460174, 0x00460235}
        print("-- unicorn: Rate %d (%s)" % (rate, "байты N16: call в стаб" if rate else "прежние байты N01"))
        n_ok = 0
        cases = []
        for dur in (900, 1620, 1230, 1290, 1440, 1080, 450, 300):
            for pct in (0, 10, 14, 15, 16, 30):
                cases.append((dur, dur - dur * pct // 100, pct))
        cases += [(900, 65736, -1), (900, 0xFFFFFFFF, -2), (0, 0, -3), (-500, 0, -4)]
        for twin in (0, 1):
            for dur, dt, pct in cases:
                start = 0x7FFFF000
                tick = (start + dt) & 0xFFFFFFFF
                e.uc.mem_write(REC + 0xFE90, struct.pack("<I", start))
                e.uc.mem_write(REC + 0xFE94, struct.pack("<h", dur))
                esp = 0x001F0000
                frame = esp
                e.uc.mem_write(frame + (0xB0 if twin else 0x298), struct.pack("<I", tick))
                regs = {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: REC, UC_X86_REG_EBX: 0x11111111, UC_X86_REG_ESI: 0x22222222,
                        UC_X86_REG_EDI: 0x33333333, UC_X86_REG_EAX: 0, UC_X86_REG_ECX: 0, UC_X86_REG_EDX: 0x44444444}
                stop = e.run(0x0046014A if twin else 0x0045F596, regs)
                passed = stop in (0x0045F681, 0x00460235)
                if rate == 0 and dur < 0:
                    exp = False     # прежние байты N01: jae против знакорасширенного dur < 0 — отказ (сток принимал)
                else:
                    exp = expect(rate, dt, dur)
                good = stop is not None and passed == exp
                good = good and e.uc.reg_read(UC_X86_REG_EBX) == 0x11111111 and e.uc.reg_read(UC_X86_REG_ESI) == 0x22222222
                good = good and e.uc.reg_read(UC_X86_REG_EBP) == REC and e.uc.reg_read(UC_X86_REG_ESP) == esp
                good = good and e.uc.reg_read(UC_X86_REG_EDI) == tick
                if not twin:
                    good = good and e.uc.reg_read(UC_X86_REG_EAX) == (dur & 0xFFFFFFFF)   # dur сохранён для push eax
                ecx = e.uc.reg_read(UC_X86_REG_ECX)
                if rate and dur > 0:
                    tol = max(100, dur * rate // 100)
                    want = min(dt + tol, 0xFFFFFFFF)
                    good = good and ecx == want
                if pct >= 0 and rate == 15 and dur >= 667:
                    good = good and passed == (pct <= 15)
                if good:
                    n_ok += 1
                else:
                    ok(False, "%s dur %d dt %d (−%d%%): стоп 0x%s, принят=%s, ожидание %s, ecx=0x%08X" %
                       ("PvP" if twin else "моб", dur, dt, pct, "%08X" % stop if stop else "—", passed, exp, ecx))
        ok(n_ok == 2 * len(cases), "Rate %d: %d/%d случаев (моб и PvP): решение jae, сумма ecx, сохранность ebx/esi/edi/ebp/esp%s" %
           (rate, n_ok, 2 * len(cases), ", eax=dur у моба" if True else ""))


def main():
    print("DLL: %s" % DLL)
    syms = map_syms(MAP)
    ok(all(syms.values()), "символы из .map: %s" % ", ".join("%s=0x%08X" % (k, v or 0) for k, v in syms.items()))
    dpe, dimg, dbase = load(DLL)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for k in ("St_TolMain", "St_TolTwin"):
        va = syms[k]
        code = bytes(dimg[va - dbase: va - dbase + 0x20])
        lines = []
        for ins in md.disasm(code, va):
            lines.append("%s %s" % (ins.mnemonic, ins.op_str))
            if ins.mnemonic == "ret":
                break
        print("   %s @0x%08X: %s" % (k, va, "; ".join(lines)))
        calls = [l for l in lines if l.startswith("call")]
        ok(len(calls) == 1 and int(calls[0].split()[1], 16) == syms["_N01_TolSum@8"], "%s зовёт N01_TolSum" % k)
    ref = None
    for name, path in IMAGES:
        raw = open(path, "rb").read()
        print("-- %s: %s (md5 %s)" % (name, path, hashlib.md5(raw).hexdigest()))
        pe, img, base = load(path)
        if ref is None:
            ref = (img, base)
        for n, va, o in SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "%-15s 0x%08X = %s" % (n, va, cur.hex()))
            s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
            ok(s and e, "%-15s начало на границе: %s, конец на границе: %s" % (n, s, e))
        for n, va, o in NEIGH:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        for n, h in scan_into(pe, img, base, SITES).items():
            ok(not h, "%-15s входов внутрь: %d %s" % (n, len(h), ", ".join("%s@0x%08X" % x for x in h[:4])))
    img, base = ref
    emulate(img, base, dimg, dbase, syms)
    print("\nИТОГ: %s (ошибок %d)" % ("OK" if bad == 0 else "ЕСТЬ ОШИБКИ", bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
