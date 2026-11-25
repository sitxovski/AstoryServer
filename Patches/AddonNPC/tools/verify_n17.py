# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n17.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны N17 (2026-10-15): ворота ИИ монстра «ждать конца атаки»
#   (8 площадок `sub R2,[M+7A70h]; cmp R2,R1; jl`) — беззнаковое сравнение через стабы AddonNPC.
# Сервер НЕ запускается. Образы только читаются.
#   1. Три образа NpcServer (сток 16c7a0af, живой c02486d6, Indun 0de2c559): байты 8 площадок и соседей (movsx
#      длительности, mov такта), границы инструкций, цель jl — эпилог функции, флаги после ворот никто не читает,
#      перебор rel8/rel32/jcc32/abs32 по образу — входов внутрь изменяемых байтов нет; окна площадок одинаковы.
#   2. DLL (по .map): 6 стабов St17_* — дизасм, раскладка регистров совпадает с площадкой.
#   3. unicorn по НАСТОЯЩЕМУ коду каждой площадки: байты стока и байты N17 (call в стаб DLL + jb) — матрица
#      такт × такт атаки × длительность; ожидание стока = знаковое сравнение, N17 = беззнаковое при длительности > 0;
#      тождество со стоком при неотрицательной разности; сохранность регистров.
#   4. unicorn по ВСЕЙ функции ProcessAction_Move (sub_43E580) от входа: доходит ли монстр до шага (call sub_42CCD0)
#      — живой случай 15.10 (такт 3 083 955 078, такт атаки 0) на стоке стоит, с N17 шагает.
# Запуск: py -3 verify_n17.py [AddonNPC.dll] [сток.exe живой.exe indun.exe]
import hashlib
import os
import struct
import sys

sys.dont_write_bytecode = True
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))   # ★ 22.10.2026: srv_paths.py
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe", "16c7a0aff498a9f739899d9a2cba9a5b"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe", "c02486d62e803e98eb6fb4fa98d1fcd6"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe", "0de2c55932c2966537e2a8c539decdcd"),
]
if len(sys.argv) > 4:
    IMAGES = [(n, p, m) for (n, _, m), p in zip(IMAGES, sys.argv[2:5])]

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


REG = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
       "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "ebp": UC_X86_REG_EBP}
# movsx, sub, jl, R1 (длительность), R2 («прошло»), M (монстр), Rt (такт), стаб, где
GATES = [
    (0x43949C, 0x4394A5, 0x4394AD, "edx", "ecx", "ebx", "eax", "St17_EdxEcxEbx", "sub_439450 BATTLEMOVE"),
    (0x439ACA, 0x439AD3, 0x439ADB, "edx", "ecx", "ebx", "eax", "St17_EdxEcxEbx", "sub_439A70 MOVE_AND_ACTION"),
    (0x43E693, 0x43E69C, 0x43E6A4, "ecx", "edx", "ebx", "esi", "St17_EcxEdxEbx", "sub_43E580 ProcessAction_Move"),
    (0x43F39B, 0x43F3A4, 0x43F3AC, "edx", "ecx", "edi", "eax", "St17_EdxEcxEdi", "sub_43F330 Idle (флаг 0x2000000)"),
    (0x44060F, 0x440618, 0x440620, "edi", "edx", "ebx", "eax", "St17_EdiEdxEbx", "sub_4405B0 CHASE/AROUNDMOVE"),
    (0x4415F9, 0x441602, 0x44160A, "edx", "ecx", "esi", "eax", "St17_EdxEcxEsi", "sub_4415D0 FEAR"),
    (0x447EB1, 0x447EBA, 0x447EC2, "eax", "edx", "ebx", "edi", "St17_EaxEdxEbx", "sub_447B30 OnBattle"),
    (0x44B409, 0x44B412, 0x44B41A, "edx", "ecx", "edi", "eax", "St17_EdxEcxEdi", "sub_44B3D0 действие 19"),
]
FLAG_READERS = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
                "adc", "sbb", "pushfd", "pushf", "lahf", "rcl", "rcr", "into")
FLAG_FULL_WRITERS = ("cmp", "test", "add", "sub", "and", "or", "xor", "neg", "sahf", "popfd")


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def dis(img, base, va, n=1, ln=64):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = []
    for ins in md.disasm(bytes(img[va - base: va - base + ln]), va):
        out.append(ins)
        if len(out) >= n:
            break
    return out


def boundary_ok(img, base, va):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for back in range(1, 48):
        for ins in md.disasm(bytes(img[va - base - back: va - base + 16]), va - back):
            if ins.address == va:
                return True
            if ins.address > va:
                break
    return False


def flags_dead_after(img, base, va, limit=14):
    """Флаги, оставленные воротами, на пути от va никто не читает: до первого читателя есть полный писатель / call / ret."""
    seen = []
    for ins in dis(img, base, va, limit, 160):
        m = ins.mnemonic
        seen.append(m)
        if m.startswith("set") or m.startswith("cmov") or m in FLAG_READERS:
            return False, seen
        if m in FLAG_FULL_WRITERS or m in ("call", "ret", "jmp"):
            return True, seen
    return False, seen


def scan_into(pe, img, base, ranges):
    """Все rel8/rel32/jcc32 и abs32 в образе, указывающие внутрь изменяемых байтов (кроме начала площадки call)."""
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    a, b = t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize
    hits = []
    for i in range(a, b - 6):
        o = img[i]
        cands = []
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            cands.append(base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0])
        if o in (0xE8, 0xE9):
            cands.append(base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0])
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            cands.append(base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0])
        for tg in cands:
            for lo, hi, name in ranges:
                if lo <= tg < hi and not (lo <= base + i < hi):
                    hits.append(("переход", base + i, tg, name))
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for lo, hi, name in ranges:
            if lo <= v < hi:
                hits.append(("abs32", base + i, v, name))
    return hits


_SWEEP = {}


def sweep_starts(pe, img, base):
    """Линейный проход .text (capstone, с пропуском нераспознанных байтов) — множество начал инструкций."""
    key = id(img)
    if key in _SWEEP:
        return _SWEEP[key]
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    a, b = t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    starts, off = set(), a
    while off < b:
        last = off
        for ins in md.disasm(bytes(img[off:b]), base + off):
            starts.add(ins.address)
            last = ins.address - base + ins.size
        off = last if last > off else off + 1
    _SWEEP[key] = starts
    return starts


def host_insn(pe, img, base, starts, va):
    for back in range(1, 16):
        if va - back in starts:
            ins = dis(img, base, va - back)[0]
            if ins.address + ins.size > va:
                return ins.address, "%s %s" % (ins.mnemonic, ins.op_str)
    return 0, "?"


def map_syms(path):
    want = {g[7]: None for g in GATES}
    want["N17_MobActionTimer"] = None
    for line in open(path, encoding="latin-1"):
        p = line.split()
        if len(p) < 3:
            continue
        for k in want:
            if ("?%s@" % k) in p[1] and want[k] is None:
                want[k] = int(p[2], 16)
    return want


def rel32(src, dst):
    return struct.pack("<i", dst - (src + 5))


def n17_site_bytes(g, stub):
    return b"\xe8" + rel32(g[1], stub) + b"\x90\x90\x90"


# ── эмулятор ────────────────────────────────────────────────────────────────
MON = 0x00300000
STACK = 0x00100000
RET_SENTINEL = 0x00080000


class Emu:
    def __init__(self, host_img, host_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((host_base, host_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(STACK, 0x00100000)
        self.uc.mem_map(MON, 0x00020000)
        self.uc.mem_map(RET_SENTINEL, 0x1000)
        self.uc.mem_write(RET_SENTINEL, b"\xcc" * 16)
        self.stops = set()
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, count=4000):
        for r, v in regs.items():
            self.uc.reg_write(r, v)
        self.stopped_at = None
        try:
            self.uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (self.uc.reg_read(UC_X86_REG_EIP), e))
        return self.stopped_at


def s32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def stock_wait(tick, last, delay):
    return s32(tick - last) < delay


def n17_wait(tick, last, delay):
    return delay > 0 and ((tick - last) & 0xFFFFFFFF) < delay


TICKS = [0x00001000, 0x10000000, 0x7FFFFF00, 0x80000000, 3083955078, 0xFFFFFF00, 0x00000100]
DELAYS = [0, 1, 500, 1500, 32767, -1, -500, -32768]


def lasts_for(tick):
    return [0, tick - 1, tick - 499, tick - 500, tick - 501, tick - 1500, tick - 32767, tick - 0x7FFFFFFF,
            tick - 0x80000001, tick + 100]


def emulate_gates(img, base, dimg, dbase, syms):
    for mode in ("сток", "N17"):
        e = Emu(img, base, dimg, dbase)
        if mode == "N17":
            for g in GATES:
                e.uc.mem_write(g[1], n17_site_bytes(g, syms[g[7]]))
                e.uc.mem_write(g[2] + 1, b"\x82")
        print("-- unicorn, ворота по настоящему коду: байты %s" % mode)
        for g in GATES:
            movsx, subva, jlva, r1, r2, m, rt, stub, where = g
            target = dis(img, base, jlva)[0]
            tgt = int(target.op_str, 16)
            e.stops = {jlva + 6, tgt}
            n_ok = n_all = 0
            ident_ok = True
            for tick in TICKS:
                for last in lasts_for(tick):
                    last &= 0xFFFFFFFF
                    for delay in DELAYS:
                        e.uc.mem_write(MON + 0x7A70, struct.pack("<I", last))
                        e.uc.mem_write(MON + 0x7A74, struct.pack("<h", delay))
                        regs = {UC_X86_REG_ESP: 0x001F0000, UC_X86_REG_EBP: 0x0055AA00}
                        sent = {"eax": 0x11111111, "ebx": 0x22222222, "ecx": 0x33333333, "edx": 0x44444444,
                                "esi": 0x55555555, "edi": 0x66666666}
                        for k, v in sent.items():
                            regs[REG[k]] = v
                        regs[REG[m]] = MON
                        regs[REG[rt]] = tick
                        stop = e.run(movsx, regs, 40)
                        waited = stop == tgt
                        exp = stock_wait(tick, last, delay) if mode == "сток" else n17_wait(tick, last, delay)
                        good = stop is not None and waited == exp
                        # регистры: R1 = длительность (знакорасширена), R2 = такт − такт атаки, M и Rt — как были,
                        # прочие — нетронуты; esp/ebp — те же
                        good = good and e.uc.reg_read(REG[r1]) == (delay & 0xFFFFFFFF)
                        good = good and e.uc.reg_read(REG[r2]) == ((tick - last) & 0xFFFFFFFF)
                        good = good and e.uc.reg_read(REG[m]) == MON and e.uc.reg_read(REG[rt]) == tick
                        for k, v in sent.items():
                            if k not in (r1, r2, m, rt):
                                good = good and e.uc.reg_read(REG[k]) == v
                        good = good and e.uc.reg_read(UC_X86_REG_ESP) == 0x001F0000
                        good = good and e.uc.reg_read(UC_X86_REG_EBP) == 0x0055AA00
                        n_all += 1
                        if good:
                            n_ok += 1
                        elif n_all - n_ok <= 3:
                            ok(False, "%s: такт 0x%08X, атака 0x%08X, длит. %d: стоп %s, ждал=%s, ожидание %s" %
                               (where, tick, last, delay, "0x%08X" % stop if stop else "—", waited, exp))
                        if mode == "N17" and s32(tick - last) >= 0 and n17_wait(tick, last, delay) != stock_wait(tick, last, delay):
                            ident_ok = False
            ok(n_ok == n_all, "%s @0x%06X: %d/%d случаев — решение, регистры (R1/R2 как в стоке, прочие целы), esp/ebp" %
               (where, movsx, n_ok, n_all))
            if mode == "N17":
                ok(ident_ok, "    тождество со стоком при неотрицательной разности (такт − такт атаки ≥ 0 как знаковое)")
        # живой случай 15.10
        g = GATES[2]
        tgt = int(dis(img, base, g[2])[0].op_str, 16)
        e.stops = {g[2] + 6, tgt}
        for delay in (0, 900):
            e.uc.mem_write(MON + 0x7A70, struct.pack("<I", 0))
            e.uc.mem_write(MON + 0x7A74, struct.pack("<h", delay))
            stop = e.run(g[0], {UC_X86_REG_ESP: 0x001F0000, UC_X86_REG_EBX: MON, UC_X86_REG_ESI: 3083955078}, 40)
            want_wait = mode == "сток"
            ok((stop == tgt) == want_wait, "живой случай 15.10: такт 3 083 955 078, такт атаки 0, длительность %d — %s" %
               (delay, "ворота ЗАКРЫТЫ (монстр стоит)" if stop == tgt else "ворота открыты (монстр идёт)"))


def emulate_move_function(img, base, dimg, dbase, syms):
    """ProcessAction_Move (sub_43E580, stdcall a1=монстр, a2=такт, a3=игроки) от входа до шага/выхода."""
    STEP = 0x0042CCD0
    for mode in ("сток", "N17"):
        e = Emu(img, base, dimg, dbase)
        if mode == "N17":
            for g in GATES:
                e.uc.mem_write(g[1], n17_site_bytes(g, syms[g[7]]))
                e.uc.mem_write(g[2] + 1, b"\x82")
        e.stops = {STEP, RET_SENTINEL}
        print("-- unicorn, ВСЯ функция ProcessAction_Move от 0x43E580: байты %s" % mode)
        cases = [
            # такт, такт атаки, длительность, ожидание сток, ожидание N17, описание
            (3083955078, 0, 0, False, True, "живой 15.10: такт ≥ 2^31, монстр не атаковал"),
            (3083955078, 0, 900, False, True, "такт ≥ 2^31, не атаковал, длительность 900"),
            (3083955078, 3083955078 - 300, 900, False, False, "такт ≥ 2^31, атака 300 мс назад, длит. 900 — ждать"),
            (3083955078, 3083955078 - 1000, 900, True, True, "такт ≥ 2^31, атака 1000 мс назад, длит. 900 — шаг"),
            (0x10000000, 0, 0, True, True, "такт < 2^31, не атаковал (как в сентябре) — шаг"),
            (0x10000000, 0x10000000 - 300, 900, False, False, "такт < 2^31, атака 300 мс назад — ждать"),
            (0x00000200, 0xFFFFFF00, 900, False, False, "такт перешёл 2^32, атака 768 мс назад — ждать"),
            (0x00000500, 0xFFFFFF00, 900, True, True, "такт перешёл 2^32, атака 1536 мс назад — шаг"),
        ]
        for tick, last, delay, exp_stock, exp_n17, why in cases:
            e.uc.mem_write(MON, b"\x00" * 0x10000)
            e.uc.mem_write(MON + 0, struct.pack("<I", 2500))            # скорость (интервал шага)
            e.uc.mem_write(MON + 4, struct.pack("<h", 50))
            e.uc.mem_write(MON + 30532, struct.pack("<I", 0x00700000))  # SectorManager ≠ 0
            e.uc.mem_write(MON + 30448, struct.pack("<h", 500))         # интервал действия
            e.uc.mem_write(MON + 30444, struct.pack("<I", (tick - 1000) & 0xFFFFFFFF))   # начало действия 1 с назад
            e.uc.mem_write(MON + 30424, struct.pack("<f", 8525.0))      # цель (170·50+25)
            e.uc.mem_write(MON + 30428, struct.pack("<f", 20175.0))     # (403·50+25)
            e.uc.mem_write(MON + 0x7A70, struct.pack("<I", last & 0xFFFFFFFF))
            e.uc.mem_write(MON + 0x7A74, struct.pack("<h", delay))
            esp = 0x001F0000 - 16
            e.uc.mem_write(esp, struct.pack("<IIII", RET_SENTINEL, MON, tick & 0xFFFFFFFF, 0x00680000))
            stop = e.run(0x0043E580, {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: 0x001F8000, UC_X86_REG_EBX: 0x1234,
                                      UC_X86_REG_ESI: 0x5678, UC_X86_REG_EDI: 0x9ABC})
            stepped = stop == STEP
            exp = exp_stock if mode == "сток" else exp_n17
            good = stop is not None and stepped == exp
            if stop == RET_SENTINEL:
                good = good and e.uc.reg_read(UC_X86_REG_ESP) == esp + 16      # ret 0Ch
                good = good and e.uc.reg_read(UC_X86_REG_EBX) == 0x1234 and e.uc.reg_read(UC_X86_REG_ESI) == 0x5678
                good = good and e.uc.reg_read(UC_X86_REG_EDI) == 0x9ABC and e.uc.reg_read(UC_X86_REG_EBP) == 0x001F8000
            ok(good, "%s: %s (ожидание: %s)" % (why, "ДОШЁЛ до шага sub_42CCD0" if stepped else
                                                 ("вышел без шага" if stop == RET_SENTINEL else "стоп ?"),
                                                 "шаг" if exp else "без шага"))


def main():
    print("DLL: %s" % DLL)
    syms = map_syms(MAP)
    ok(all(syms.values()), "символы из .map: %s" % ", ".join("%s=0x%08X" % (k, v or 0) for k, v in syms.items()))
    dpe, dimg, dbase = load(DLL)
    for g in GATES:
        r1, r2, m = g[3], g[4], g[5]
        ins = dis(dimg, dbase, syms[g[7]], 6, 0x20)
        txt = "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in ins)
        want = ["sub %s, dword ptr [%s + 0x7a70]" % (r2, m), "test %s, %s" % (r1, r1), "jle", "cmp %s, %s" % (r2, r1), "ret"]
        got = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
        good = len(got) >= 5 and got[0] == want[0] and got[1] == want[1] and got[2].startswith("jle") \
            and got[3] == want[3] and got[4].strip() == "ret"
        good = good and int(ins[2].op_str, 16) == ins[4].address        # jle → на ret (CF = 0 от test)
        ok(good, "стаб %s @0x%08X для 0x%06X: %s" % (g[7], syms[g[7]], g[0], txt))

    ref = None
    for name, path, md5_want in IMAGES:
        raw = open(path, "rb").read()
        md5 = hashlib.md5(raw).hexdigest()
        print("-- %s: %s (md5 %s)" % (name, path, md5))
        ok(md5 == md5_want, "md5 образа = %s" % md5_want)
        pe, img, base = load(path)
        windows = []
        ranges = []
        for g in GATES:
            movsx, subva, jlva, r1, r2, m, rt, stub, where = g
            ins = dis(img, base, movsx, 5, 40)
            got = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
            want = ["movsx %s, word ptr [%s + 0x7a74]" % (r1, m), "mov %s, %s" % (r2, rt),
                    "sub %s, dword ptr [%s + 0x7a70]" % (r2, m), "cmp %s, %s" % (r2, r1)]
            good = got[:4] == want and ins[2].address == subva and ins[3].address == subva + 6
            good = good and ins[4].address == jlva and ins[4].mnemonic == "jl" and ins[4].size == 6
            good = good and bytes(img[jlva - base:jlva - base + 2]) == b"\x0f\x8c"
            ok(good, "%s @0x%06X: %s" % (where, movsx, "; ".join(got)))
            ok(boundary_ok(img, base, movsx) and boundary_ok(img, base, subva) and boundary_ok(img, base, jlva + 6),
               "    границы: movsx, площадка 0x%06X…0x%06X и конец jl — на границах инструкций" % (subva, subva + 8))
            tgt = int(ins[4].op_str, 16)
            ep = dis(img, base, tgt, 8, 32)
            seq = [i.mnemonic for i in ep]
            epi = "ret" in seq and all(mn in ("pop", "mov", "add", "ret") for mn in seq[:seq.index("ret") + 1])
            ok(epi, "    цель jl 0x%06X — эпилог: %s" % (tgt, "; ".join("%s %s" % (i.mnemonic, i.op_str)
                                                              for i in ep[:seq.index("ret") + 1] if "ret" in seq)))
            dead, seen = flags_dead_after(img, base, jlva + 6)
            ok(dead, "    флаги после ворот на прямом пути не читаются: %s" % ", ".join(seen))
            windows.append(bytes(img[movsx - base: jlva - base + 6]))
            ranges.append((subva + 1, subva + 8, "%s: внутрь sub/cmp" % where))
            ranges.append((jlva, jlva + 6, "%s: на/внутрь jl" % where))
        hits_raw = scan_into(pe, img, base, ranges)
        starts = sweep_starts(pe, img, base)
        hits, false_hits = [], []
        for h in hits_raw:
            src = h[1]
            if h[0] == "переход" and src in starts:
                ins = dis(img, base, src)[0]
                if ins.op_str.startswith("0x") and int(ins.op_str, 16) == h[2]:
                    hits.append(h)
                    continue
            if h[0] == "abs32":
                hits.append(h)
                continue
            false_hits.append(h)
        for h in false_hits:
            host = host_insn(pe, img, base, starts, h[1])
            print("    (ложный вход @0x%08X → 0x%08X исключён: байт — операнд инструкции @0x%08X `%s`)" % (h[1], h[2], host[0], host[1]))
        ok(not hits, "перебор rel8/rel32/jcc32/abs32: входов внутрь изменяемых байтов (и на сам jl) — %d%s" %
           (len(hits), "" if not hits else ": " + ", ".join("%s @0x%08X → 0x%08X (%s)" % h for h in hits[:8])))
        # вход на НАЧАЛО площадки (sub) — допустим, но покажем
        starts = scan_into(pe, img, base, [(g[1], g[1] + 1, g[8]) for g in GATES])
        print("    входов на начало площадки (sub, допустимо — стаб делает то же вычитание): %d" % len(starts))
        if ref is None:
            ref = windows
        else:
            ok(windows == ref, "окна всех 8 ворот побайтно совпадают со стоком")
        emulate_gates(img, base, dimg, dbase, syms)
        emulate_move_function(img, base, dimg, dbase, syms)

    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК: %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
