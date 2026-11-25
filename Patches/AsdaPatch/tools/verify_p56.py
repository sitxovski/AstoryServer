# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p56.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны В5 «серверные лимиты боя» (2026-10-12):
#   AsdaPatch P56 (GameServer: 9 площадок `call rel32` + 12 соседей-кадров), AddonNPC N14 (NpcServer: 2 площадки).
# Функции сверки скопированы из verify_ac0.py (границы инструкций, перебор переходов/abs32 внутрь площадок,
# разыменование `jmp dword ptr [..]` стабов, эмулятор unicorn).
#
# Сервер НЕ запускается. Проверяем:
#  1) исходные байты всех площадок и соседей в стоке 4e20f0ad, живом GameServer и Indun e7b4ac38;
#     в стоке 16c7a0af, живом c02486d6 и Indun 0de2c559 NpcServer (образы NPC различаются — сверяем все три);
#  2) .text живых образов GameServer побайтно равен стоку (иначе — перебор по каждому);
#  3) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки на границах инструкций;
#  4) стабы найдены в DLL по байтам, `jmp dword ptr [..]` каждого разыменован и ведёт в стоковую цель;
#  5) unicorn: GateTail (пропуск → jmp сток с нетронутым стеком/ecx; отказ → ret 8, eax=1), St_Cool
#     (пропуск → jmp сток; отказ → ret 8, eax=0), St_Send8205/St_Resp8206 (jmp сток, стек/регистры целы),
#     N14 WriterTail (jmp писатель, стек цел, ecx цел).
# Запуск: py -3.13 verify_p56.py [AsdaPatch.dll] [AddonNPC.dll]
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
DLL_NPC = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "AddonNPC", "out", "AddonNPC.dll")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
NPC_IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe"),
]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


# (имя, va call, стоковая цель)
P56_GS = [
    ("P56.5256gate", 0x0046FDCF, 0x0052BFF0),
    ("P56.5256cool", 0x00470097, 0x0047BE60),
    ("P56.5256send", 0x00470CCC, 0x005646C0),
    ("P56.8206disp", 0x0043164E, 0x00470DB0),
    ("P56.6158gate", 0x0048E8DF, 0x0052BFF0),
    ("P56.4026gate", 0x004C4B48, 0x0052BFF0),
    ("P56.4028gate", 0x004C5278, 0x0052BFF0),
    ("P56.4201gate", 0x00554DCC, 0x0052BFF0),
    ("P56.4203gate", 0x00555473, 0x0052BFF0),
]
GS_SITES = [(n, va, _call(va, tgt)) for n, va, tgt in P56_GS]
GS_NEIGHBOURS = [   # байты, на которые опираются смещения кадров в стабах (p56_combat_limits.cpp kNeighbours)
    ("5256 iRecvCount [ebp-0x10] 0x46FBB3",          0x0046FBB3, "837df014"),
    ("5256 записи целей ebp-0x25C 0x46FCB2",         0x0046FCB2, "668b8c05a5fdffff"),
    ("5256 CUser [ebp-0x5B4] → +0x54E8 0x46FE71",    0x0046FE71, "8b854cfaffff668b88e8540000"),
    ("5256 откат → код 7 0x47009C",                  0x0047009C, "85c0750cc68578fdffff07"),
    ("5256 skill [ebp-0x59C] (memcpy a4) 0x46FB45",  0x0046FB45, "8d9564faffff"),   # lea edx,[ebp-0x59C] перед memcpy(a4, +33, 7)
    ("6158 iRecvCount [ebp-4] 0x48E797",             0x0048E797, "3b55fc0f8d"),
    ("6158 записи целей ebp-0x250 0x48E7DC",         0x0048E7DC, "0fb68415b0fdffff"),
    ("6158 CUser [ebp-0x570] → +0x54E6 0x48E937",    0x0048E937, "8b8590faffff668b88e6540000"),
    ("4201 цель [ebp-0x2C] 0x554E0D",                0x00554E0D, "668b4dd451"),
    ("4201 CUser [ebp-0x6C] → +0x54E6 0x554EAA",     0x00554EAA, "8b5594668b82e6540000"),
    ("4203 цель [ebp-0x24] 0x555486",                0x00555486, "668b55dc52"),
    ("4203 CUser [ebp-0x60] → +0x54E6 0x5555ED",     0x005555ED, "8b55a0668b82e6540000"),
    ("8206 userNum [ebp-8] 0x43163D",                0x0043163D, "668b4df851"),
    ("цель sub_52BFF0 (пролог)",                     0x0052BFF0, "55"),
    ("цель sub_47BE60 (пролог)",                     0x0047BE60, "55"),
    ("цель sub_5646C0 (пролог)",                     0x005646C0, "55"),
    ("цель sub_470DB0 (пролог)",                     0x00470DB0, "55"),
    ("за 5256gate: movzx ecx,al / test / je",        0x0046FDD4, "0fb6c885c9740c"),
    ("за 4026gate: movzx eax,al / test / je",        0x004C4B4D, "0fb6c085c0743f"),
    ("за 4201gate: movzx ecx,al / test / je",        0x00554DD1, "0fb6c885c97433"),
    ("за 4203gate: movzx ecx,al / test / je",        0x00555478, "0fb6c885c97405"),
]
N14_WRITER = 0x00408D40
N14_NPC = [   # (имя, va call, push строки формата за 5 б до call)
    ("N14.PvE", 0x0045F581, 0x00477638),
    ("N14.PvP", 0x00460131, 0x00478428),
]
NPC_SITES = [(n, va, _call(va, N14_WRITER)) for n, va, _ in N14_NPC]
NPC_NEIGHBOURS = [
    ("PvE: lea ecx,[ebp+0x7714] (имя игрока) перед push fmt", 0x0045F575, "8d8d14770000516838764700"),
    ("PvP: lea edx,[ebp+0x7714] перед push fmt",             0x00460125, "8d9514770000526828844700"),
    ("писатель sub_408D40 (пролог sub esp,0x204)",           0x00408D40, "81ec04020000"),
]

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


def boundary_ok(img, base, va, ln):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    total = 0
    for ins in md.disasm(bytes(img[va - base: va - base + ln + 16]), va):
        total += ins.size
        if total >= ln:
            end_ok = total == ln
            break
    else:
        end_ok = False
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


# Ложные «входы»: байт E8/EB/7x — операнд другой инструкции (доказательство — байты инструкции-хозяина).
KNOWN_FALSE = {
    0x0044CC5E: (0x0044CC5B, "668b45e8", "e8 — смещение в `mov ax,[ebp-0x18]` @0x44CC5B (sub_44CC00)"),
}


def scan_into(pe, img, base, sites):
    a, b = text_range(pe)
    hits = {s[0]: 0 for s in sites}
    rng = [(n, va, len(bytes.fromhex(o))) for n, va, o in sites]
    for i in range(a, b - 6):
        if any(va <= base + i < va + ln for _, va, ln in rng):
            continue   # источник внутри самой площадки (байты rel32) — не вход
        if base + i in KNOWN_FALSE:
            hva, hb, why = KNOWN_FALSE[base + i]
            if bytes(img[hva - base: hva - base + len(bytes.fromhex(hb))]) == bytes.fromhex(hb):
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
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in rng:
            if va < v < va + ln:
                hits[n] += 1
    return hits


def find_all(img, base, sig_hex):
    sig = bytes.fromhex(sig_hex.replace(" ", ""))
    out, start = [], 0
    while True:
        i = img.find(sig, start)
        if i < 0:
            return out
        out.append(base + i)
        start = i + 1


def disasm(img, base, va, n=0x80):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(bytes(img[va - base: va - base + n]), va))


def stub_targets(img, base, va, njmp=1):
    jmps, calls = [], []
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic in ("ret", "int3") or len(jmps) >= njmp:
            break
    return jmps, calls


class Emu:
    def __init__(self, host_img, host_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((host_base, host_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)   # стек + кадр
        self.stops = set()
        self.fake = {}
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        if address in self.fake:
            nb, fn = self.fake[address]
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = struct.unpack("<%dI" % (nb // 4), uc.mem_read(esp + 4, nb)) if nb else ()
            eax = fn(uc, args, esp + 4)
            uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_ESP, esp + 4 + nb)
            uc.reg_write(UC_X86_REG_EIP, ret)
            return
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, mem=(), count=200):
        uc = self.uc
        for addr, data in mem:
            uc.mem_write(addr, data)
        for r, v in regs.items():
            uc.reg_write(r, v)
        self.stopped_at = None
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (uc.reg_read(UC_X86_REG_EIP), e))
        return self.stopped_at

    def r(self, reg):
        return self.uc.reg_read(reg)


def check_sites(name, img, base, sites, neigh):
    for n, va, o in sites:
        cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
        ok(cur == bytes.fromhex(o), "%-14s 0x%08X = %s" % (n, va, cur.hex()))
    for n, va, o in neigh:
        cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
        ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))


def main():
    # ── 1. площадки GameServer в трёх образах ────────────────────────────────
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        check_sites(name, img, base, GS_SITES, GS_NEIGHBOURS)
        if gs_ref[0] is not pe:
            a, b = text_range(pe)
            ra, rb = text_range(gs_ref[0])
            same = (a, b) == (ra, rb) and bytes(img[a:b]) == bytes(gs_ref[1][ra:rb])
            ok(same, ".text побайтно равен стоку (%d б)" % (b - a))
    # ── 2. границы и входы внутрь (сток) ─────────────────────────────────────
    print("-- границы инструкций площадок P56 (сток GameServer)")
    pe, img, base = gs_ref
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, 5)
        ok(s and e, "%-14s начало на границе: %s, конец на границе: %s" % (n, s, e))
    print("-- перебор переходов/abs32 внутрь площадок P56 (сток GameServer; .text живых равен стоку)")
    for n, c in scan_into(pe, img, base, GS_SITES).items():
        ok(c == 0, "%-14s входов внутрь: %d" % (n, c))
    # ── 3. стабы P56 в DLL ──────────────────────────────────────────────────
    print("-- стабы P56 в %s" % DLL)
    dpe, dimg, dbase = load(DLL)
    # ★ integ2b: однозначная привязка коротких стабов по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP):
    #   сигнатуры St_Cool/St_Send8205/St_Resp8206 совпали с такими же стабами других патчей (P60/P62/P63/P65…).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, dpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))

    def by_map(name, cands):
        va, good, msg = resolve(dmap, name, "p56_combat_limits", cands)
        ok(good, msg)
        return [va] if va else []
    # GateTail: pushad / lea eax,[esp+36] / push eax / push ebp / push ecx / push [esp+44] / call
    # Тот же пролог у P53 LogTail — различаем по цели `jmp dword ptr [..]` (0x52BFF0 только у P56).
    gt = [v for v in find_all(dimg, dbase, "60 8d 44 24 24 50 55 51 ff 74 24 2c e8") if stub_targets(dimg, dbase, v)[0] == [0x0052BFF0]]
    ok(len(gt) == 1, "GateTail (jmp → 0x52BFF0) найден %d раз" % len(gt))
    gate_c = None
    if gt:
        jmps, calls = stub_targets(dimg, dbase, gt[0])
        ok(jmps == [0x0052BFF0], "GateTail: jmp dword ptr → 0x%08X (сток sub_52BFF0)" % (jmps[0] if jmps else 0))
        ok(len(calls) == 1 and dbase < calls[0] < dbase + len(dimg), "GateTail: call P56_Gate внутрь DLL")
        gate_c = calls[0] if calls else None
        # шесть входов St_*: push imm8 / jmp rel32 → GateTail
        kinds = []
        for va in find_all(dimg, dbase, "6a"):
            k = dimg[va - dbase + 1]
            if 1 <= k <= 6 and dimg[va - dbase + 2] == 0xE9:
                t = va + 2 + 5 + struct.unpack("<i", bytes(dimg[va - dbase + 3: va - dbase + 7]))[0]
                if t == gt[0]:
                    kinds.append(k)
        ok(sorted(kinds) == [1, 2, 3, 4, 5, 6], "входы St_* с видами 1…6 → GateTail: %s" % sorted(kinds))
    # St_Cool: pushad / lea eax,[esp+32] / push eax / call / test / jnz
    sc = find_all(dimg, dbase, "60 8d 44 24 20 50 e8")
    sc = [v for v in sc if dimg[v - dbase + 11] == 0x85 and dimg[v - dbase + 12] == 0xC0]
    sc = by_map("St_Cool", sc)
    cool_c = None
    if sc:
        jmps, calls = stub_targets(dimg, dbase, sc[0])
        ok(jmps == [0x0047BE60], "St_Cool: jmp dword ptr → 0x%08X (сток sub_47BE60)" % (jmps[0] if jmps else 0))
        cool_c = calls[0] if calls else None
    # St_Send8205: pushad / push ebp / call / popad / jmp [..]
    ss = [v for v in find_all(dimg, dbase, "60 55 e8") if dimg[v - dbase + 7] == 0x61 and dimg[v - dbase + 8] == 0xFF]
    ss = by_map("St_Send8205", ss)
    send_c = None
    if ss:
        jmps, calls = stub_targets(dimg, dbase, ss[0])
        ok(jmps == [0x005646C0], "St_Send8205: jmp dword ptr → 0x%08X (сток sub_5646C0)" % (jmps[0] if jmps else 0))
        send_c = calls[0] if calls else None
    # St_Resp8206: pushad / push [esp+36] / call / popad / jmp [..]
    sr = [v for v in find_all(dimg, dbase, "60 ff 74 24 24 e8") if dimg[v - dbase + 10] == 0x61]
    sr = by_map("St_Resp8206", sr)
    resp_c = None
    if sr:
        jmps, calls = stub_targets(dimg, dbase, sr[0])
        ok(jmps == [0x00470DB0], "St_Resp8206: jmp dword ptr → 0x%08X (сток sub_470DB0)" % (jmps[0] if jmps else 0))
        resp_c = calls[0] if calls else None

    # ── 4. эмуляция стабов GameServer ───────────────────────────────────────
    print("-- эмуляция стабов P56 (unicorn)")
    if gt and sc and ss and sr and gate_c and cool_c and send_c and resp_c:
        emu = Emu(img, base, dimg, dbase)
        emu.stops = {0x0052BFF0, 0x0047BE60, 0x005646C0, 0x00470DB0, 0x00160000}
        seen = {}

        def fake_gate(ret):
            def f(uc, args, argp):
                seen["gate"] = args
                return ret
            return f
        RET = 0x00160000
        for want, label in ((0, "пропуск"), (1, "отказ")):
            emu.fake = {gate_c: (16, fake_gate(want))}
            esp0 = 0x00180000
            stack = struct.pack("<III", RET, 10, 5256)       # [ret][userNum][opcode]
            stop = emu.run(gt[0] - 2 if False else gt[0], {UC_X86_REG_ESP: esp0 - 4, UC_X86_REG_ECX: 0x11111111,
                                                           UC_X86_REG_EBP: 0x00170000, UC_X86_REG_EBX: 0x22222222,
                                                           UC_X86_REG_ESI: 0x33333333, UC_X86_REG_EDI: 0x44444444},
                           mem=[(esp0 - 4, struct.pack("<I", 1)), (esp0, stack)])
            # [esp0-4] = вид (push imm перед jmp GateTail) — здесь 1 (5256)
            a = seen.get("gate", ())
            if want == 0:
                ok(stop == 0x0052BFF0, "GateTail %s: ушёл в сток 0x52BFF0 (stop=0x%08X)" % (label, stop or 0))
                ok(emu.r(UC_X86_REG_ESP) == esp0, "GateTail %s: esp как у стокового вызова (вид снят): 0x%08X" % (label, emu.r(UC_X86_REG_ESP)))
                ok(emu.r(UC_X86_REG_ECX) == 0x11111111 and emu.r(UC_X86_REG_EBP) == 0x00170000 and emu.r(UC_X86_REG_EBX) == 0x22222222,
                   "GateTail %s: ecx/ebp/ebx нетронуты" % label)
            else:
                ok(stop == RET, "GateTail %s: вернулся к вызывающему (stop=0x%08X)" % (label, stop or 0))
                ok(emu.r(UC_X86_REG_ESP) == esp0 + 12, "GateTail %s: ret 8 (снято userNum/opcode): esp=0x%08X" % (label, emu.r(UC_X86_REG_ESP)))
                ok(emu.r(UC_X86_REG_EAX) == 1, "GateTail %s: eax=1 (al≠0 → отказ стоковым путём)" % label)
            ok(len(a) == 4 and a[0] == 1 and a[1] == 0x11111111 and a[2] == 0x00170000 and a[3] == esp0,
               "GateTail %s: P56_Gate(kind=%d, mgr=ecx, ebp, st→[ret]) аргументы верны" % (label, a[0] if a else -1))
        for want, label in ((0, "пропуск"), (1, "отказ")):
            emu.fake = {cool_c: (4, fake_gate(want))}
            esp0 = 0x00180000
            stop = emu.run(sc[0], {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x11111111, UC_X86_REG_EBP: 0x00170000},
                           mem=[(esp0, struct.pack("<III", RET, 10, 600))])
            if want == 0:
                ok(stop == 0x0047BE60 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x11111111,
                   "St_Cool %s: в сток sub_47BE60, esp/ecx целы" % label)
            else:
                ok(stop == RET and emu.r(UC_X86_REG_ESP) == esp0 + 12 and emu.r(UC_X86_REG_EAX) == 0,
                   "St_Cool %s: ret 8, eax=0 → код 7" % label)
            a = seen.get("gate", ())
            ok(len(a) == 1 and a[0] == esp0, "St_Cool %s: P56_Cool(st→[ret]) аргумент верен" % label)
        emu.fake = {send_c: (4, fake_gate(0))}
        esp0 = 0x00180000
        stop = emu.run(ss[0], {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x7E0538, UC_X86_REG_EBP: 0x00170000, UC_X86_REG_EAX: 0x55},
                       mem=[(esp0, struct.pack("<IIIIII", RET, 1, 2, 3, 4, 5))])
        ok(stop == 0x005646C0 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x7E0538 and emu.r(UC_X86_REG_EAX) == 0x55,
           "St_Send8205: в сток sub_5646C0, esp/ecx/eax целы; P56_Mark8205(ebp=0x%08X)" % (seen.get("gate", (0,))[0]))
        ok(seen.get("gate", ()) == (0x00170000,), "St_Send8205: аргумент ebp верен")
        emu.fake = {resp_c: (4, fake_gate(0))}
        stop = emu.run(sr[0], {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x12345678, UC_X86_REG_EBP: 0x00170000},
                       mem=[(esp0, struct.pack("<III", RET, 10, 0x00171000))])
        ok(stop == 0x00470DB0 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x12345678,
           "St_Resp8206: в сток sub_470DB0, esp/ecx целы")
        ok(seen.get("gate", ()) == (10,), "St_Resp8206: P56_Clear8206(userNum=10)")
    else:
        ok(False, "эмуляция пропущена — не все стабы найдены")

    # ── 5. NpcServer: три образа, N14 ────────────────────────────────────────
    npc_ref = None
    for name, path in NPC_IMAGES:
        print("-- %s: %s" % (name, path))
        npe, nimg, nbase = load(path)
        if npc_ref is None:
            npc_ref = (npe, nimg, nbase)
        check_sites(name, nimg, nbase, NPC_SITES, NPC_NEIGHBOURS)
        for n, va, fmt in N14_NPC:
            p = va - nbase - 5
            ok(nimg[p] == 0x68 and struct.unpack("<I", bytes(nimg[p + 1:p + 5]))[0] == fmt,
               "%-10s push строки формата 0x%08X за 5 б до call" % (n, fmt))
            s = fmt - nbase
            e = nimg.find(b"\0", s)
            txt = bytes(nimg[s:e])
            ok(b"px %d, pz %d" in txt and b"(%d)" in txt, "%-10s текст формата: px/pz/(…) на месте (%d б)" % (n, len(txt)))
        for n, va, o in NPC_SITES:
            s, e = boundary_ok(nimg, nbase, va, 5)
            ok(s and e, "%-10s начало на границе: %s, конец на границе: %s" % (n, s, e))
        print("-- перебор переходов/abs32 внутрь площадок N14 (%s)" % name)
        for n, c in scan_into(npe, nimg, nbase, NPC_SITES).items():
            ok(c == 0, "%-10s входов внутрь: %d" % (n, c))
    print("-- стабы N14 в %s" % DLL_NPC)
    ppe, pimg, pbase = load(DLL_NPC)
    tails = find_all(pimg, pbase, "60 8d 44 24 24 50 ff 74 24 24 e8")
    targets = {}
    for t in tails:
        jmps, calls = stub_targets(pimg, pbase, t)
        if jmps:
            targets[jmps[0]] = (t, calls)
    ok(0x00408D40 in targets, "WriterTail N14 → 0x408D40 найден (хвостов %d: %s)" % (len(tails), ", ".join("0x%08X" % k for k in targets)))
    ok(0x00408DC0 in targets, "WriterTail N13 → 0x408DC0 на месте (не задет)")
    if 0x00408D40 in targets:
        t, calls = targets[0x00408D40]
        kinds = []
        for va in find_all(pimg, pbase, "6a"):
            k = pimg[va - pbase + 1]
            if k in (12, 13) and pimg[va - pbase + 2] == 0xE9:
                tt = va + 7 + struct.unpack("<i", bytes(pimg[va - pbase + 3: va - pbase + 7]))[0]
                if tt == t:
                    kinds.append(k)
        ok(sorted(kinds) == [12, 13], "входы St_Pve/St_Pvp (виды 12/13) → WriterTail: %s" % sorted(kinds))
        if calls:
            npe, nimg, nbase = npc_ref
            emu = Emu(nimg, nbase, pimg, pbase)
            emu.stops = {0x00408D40}
            seen = {}

            def f(uc, args, argp):
                seen["a"] = args
                return 0
            emu.fake = {calls[0]: (8, f)}
            esp0 = 0x00180000
            st = struct.pack("<IIIIIIIII", 0x00160000, 0x477638, 0x00171000 + 0x7714, 7, 100, 200, 110, 205, 123456)
            stop = emu.run(t - 2 if False else t, {UC_X86_REG_ESP: esp0 - 4, UC_X86_REG_ECX: 0x0BADF00D, UC_X86_REG_EBP: 0x00171000},
                           mem=[(esp0 - 4, struct.pack("<I", 12)), (esp0, st)])
            ok(stop == 0x00408D40 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x0BADF00D,
               "N14 WriterTail: в писатель 0x408D40, esp (вид снят) и ecx целы")
            a = seen.get("a", ())
            ok(len(a) == 2 and a[0] == 12 and a[1] == esp0, "N14 WriterTail: N14_OnSite(kind=12, st→[ret]) аргументы верны")

    print("\nИТОГ: %s (ошибок %d)" % ("OK" if bad == 0 else "ЕСТЬ ОШИБКИ", bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
