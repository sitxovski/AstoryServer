# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p67.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P67 (античит, волна A7, 2026-10-12):
#   6581 Recv_UserPrimiumGaChaReward — вариант приза ∈ семейству приза (площадка `call sub_4A7EA0` 0x4F75F5),
#   6579 Recv_UserSoulResult — результат рулетки только при активной рулетке (площадка `call sub_524390` 0x49A963).
#
# Сервер НЕ запускается. Грузятся образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и AsdaPatch.dll:
#  1) байты площадок и «соседей» (тело отказа, адреса возврата, прологи целей, якоря таблиц) в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32/abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов — на границе инструкции;
#  3) смещения CUser рулетки (+99252/+99382/+99384) и таблицы dword_5F5F60/word_5F5F5C встречаются в обработчиках 6575/6579;
#  4) стабы найдены в DLL по сигнатурам; `jmp/call dword ptr [..]` разыменованы и ведут куда задумано; C-функции — внутрь DLL;
#  5) unicorn: стабы на подставных кадрах — пропуск/отказ, баланс стека, сохранность регистров, аргументы стока.
# Запуск: python verify_p67.py [AsdaPatch.dll]            (образы: P67_IMG_DIR=<папка с gs_stock/gs_live/gs_indun> или шара)
#         python verify_p67.py --tables [item_table.txt PrimiumGaChaTable.txt item_list.csv]
#           — сверка данных: колонки Item_Table ↔ клиентская запись, призы живой гачи, честные пары (приз, вариант)
#             по правилу клиента и сколько из них отвергнет серверное правило P67 (расхождение таблиц).
import csv
import collections
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
if os.environ.get("P67_IMG_DIR"):
    d = os.environ["P67_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe"), ("живой GameServer", d + "/gs_live.exe"), ("живой Indun", d + "/gs_indun.exe")]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


GS_SITES = [
    ("P67.reward6581", 0x004F75F5, _call(0x004F75F5, 0x004A7EA0)),   # call sub_4A7EA0 (GetServerGroup) после стоковых проверок
    ("P67.soul6579",   0x0049A963, _call(0x0049A963, 0x00524390)),   # call sub_524390 (SecretCheck) в Recv_UserSoulResult
]
GS_NEIGHBOURS = [
    ("6581 стоковые проверки 0x4F7586 (cmp eax,3; je)",        0x004F7586, "83f803745e"),
    ("6581 тело отказа (3) 0x4F758B (mov byte [ebp-44h],0Ah; push 0; mov cx,[ebp+8]; …; push 3Dh; push 19B6h)",
                                                                 0x004F758B, "c645bc0a6a00668b4d08518d55bc52668b4508506a3d68b6190000"),
    ("6581 отказ (3) → sub_4C28F0 0x4F75AF и jmp эпилог 0x4F75E4", 0x004F75AF, "e83cb3fcff"),
    ("6581 ветка успеха 0x4F75E9 (mov byte [ebp-0C8h],1; mov ecx,60AD18h)", 0x004F75E9, "c68538ffffff01b918ad6000"),
    ("6581 возврат 0x4F75FA (mov [ebp-0C7h],al)",              0x004F75FA, "888539ffffff"),
    ("6581 эпилог 0x4F7678 (pop edi; pop esi; mov ecx,[ebp-4])", 0x004F7678, "5f5e8b4dfc"),
    ("6581 таблица предметов 0x4F757B (mov edx,[5F5E98h])",     0x004F757B, "8b15985e5f00"),
    ("6581 вариант [ebp-0D9h] → sub_532A90 0x4F74CE",           0x004F74CE, "8b8d27ffffff51e8b6b50300"),
    ("6581 база [ebp-158h] vs тело [ebp-0E0h] 0x4F7426",         0x004F7426, "8b8520ffffff3b85a8feffff"),
    ("sub_4A7EA0 пролог + mov al,[5F5EB0h]",                     0x004A7EA0, "558bec51894dfca0b05e5f008be55dc3"),
    ("таблица гачи: счётчик this+1D565Ch 0x4BC617",              0x004BC617, "0fbf915c561d00"),
    ("таблица гачи: массив ds:[7E0378h] 0x4BC633",               0x004BC633, "8b0d78037e00"),
    ("таблица цен гачи: счётчик ds:[7E037Ch] 0x4F7042 (6577)",   0x004F7042, "0fbf0d7c037e00"),
    ("sub_4BCAD0: запись 9 б (imul 9) — код +3",                 0x004BCAD0, "558bec"),
    ("6579 после SecretCheck 0x49A968 (test; jne; jmp 0x49B15F)", 0x0049A968, "85c07505e9ee070000"),
    ("6579 тихий выход 0x49B15F (pop edi; pop esi; …; ret 8)",   0x0049B15F, "5f5e8b4df433cde83af20c008be55dc20800"),
    ("6579 this=[ebp-164h] 0x49A8D5",                            0x0049A8D5, "898d9cfeffff"),
    ("6579 userNum=[ebp+8] 0x49A944",                            0x0049A944, "0fbf450850"),
    ("6579 CUserManager = [[this+4]+34h] 0x49A957",              0x0049A957, "8b859cfeffff8b48048b4934"),
    ("sub_524390 пролог",                                        0x00524390, "558bec"),
    ("sub_532A90 (IsItemCode) cmp [ebp+8],20551",                0x00532A90, "558bec817d0847500000"),
    ("sub_5324A0 (GetUser) пролог",                              0x005324A0, "558bec"),
]
BOUNDARY_EXTRA = [0x004F758B, 0x004F75FA, 0x004F75E9, 0x0049A968, 0x0049B15F]
RANGE_6575 = (0x0049A1C0, 0x0049A8C0)
RANGE_6579 = (0x0049A8C0, 0x0049B190)
RANGE_6581 = (0x004F72B0, 0x004F7690)

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    import pefile
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def scan_into(pe, img, base, sites):
    a, b = text_range(pe)
    hits = {s[0]: 0 for s in sites}
    rng = [(n, va, len(bytes.fromhex(o))) for n, va, o in sites]
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
            for n, va, ln in rng:
                if va < t < va + ln:
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in rng:
            if va < v < va + ln:
                hits[n] += 1
    return hits


def boundary_ok(img, base, va, ln):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    total = 0
    end_ok = False
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


def count_imm(img, base, lo, hi, value):
    n = 0
    for i in range(lo - base, hi - base - 4):
        if struct.unpack("<I", bytes(img[i:i + 4]))[0] == value:
            n += 1
    return n


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
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(bytes(img[va - base: va - base + n]), va))


def stub_targets(img, base, va, njmp=1):
    jmps, calls, icalls = [], [], []
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "call" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            icalls.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "int3" or ins.mnemonic == "ret" or len(jmps) >= njmp:
            break
    return jmps, calls, icalls


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP
        self.R = (UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)
        self.stops = set()
        self.fake = {}
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        ESP, EAX, EIP = self.R
        if address in self.fake:
            nb, fn = self.fake[address]
            esp = uc.reg_read(ESP)
            ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = struct.unpack("<%dI" % (nb // 4), uc.mem_read(esp + 4, nb)) if nb else ()
            eax = fn(uc, args, esp + 4)
            uc.reg_write(EAX, eax & 0xFFFFFFFF)
            uc.reg_write(ESP, esp + 4 + nb)
            uc.reg_write(EIP, ret)
            return
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, mem=(), count=300):
        from unicorn import UcError
        uc = self.uc
        for addr, data in mem:
            uc.mem_write(addr, data)
        for r, v in regs.items():
            uc.reg_write(r, v)
        self.stopped_at = None
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (uc.reg_read(self.R[2]), e))
        return self.stopped_at

    def r(self, reg):
        return self.uc.reg_read(reg)


def verify_binary(dll):
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                                   UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        for n, va, o in GS_SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "%-15s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        # якоря данных: смещения CUser рулетки и таблица рулетки в обработчиках 6575/6579
        ok(count_imm(img, base, *RANGE_6575, 99252) >= 1 and count_imm(img, base, *RANGE_6579, 99252) >= 1,
           "CUser+99252 (флаг рулетки) встречается в 6575 и 6579")
        ok(count_imm(img, base, *RANGE_6579, 99382) >= 2 and count_imm(img, base, *RANGE_6579, 99384) >= 2,
           "CUser+99382/+99384 (строка/столбец) встречаются в 6579")
        ok(count_imm(img, base, *RANGE_6579, 0x005F5F60) >= 1 and count_imm(img, base, *RANGE_6575, 0x005F5F5C) >= 1,
           "dword_5F5F60 в 6579 и word_5F5F5C в 6575")
        ok(count_imm(img, base, *RANGE_6581, 0x005F5E98) >= 2, "dword_5F5E98 в 6581 (>=2 чтения класса +36)")
        fmt3 = bytes(img[0x594298 - base: 0x594298 - base + 40]).split(b"\0")[0]
        ok(fmt3 == b"Recv_UserPrimiumGaChaReward(3) %d=%d ", "строка формата отказа (3) 0x594298: %r" % fmt3)
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- переходы/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "%-15s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref
    print("-- границы инструкций (сток)")
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "%-15s 0x%08X: начало %s, конец %s" % (n, va, s, e))
    for va in BOUNDARY_EXTRA:
        s, _ = boundary_ok(img, base, va, 1)
        ok(s, "цель перехода 0x%08X на границе инструкции" % va)
    # между площадкой A и телом отказа нет push/pop: стек в 0x4F75F5 = стек в 0x4F758B (оба после cmp/je 0x4F7586)
    ins = disasm(img, base, 0x004F75E9, 0x4F75F5 - 0x4F75E9)
    ok(all(i.mnemonic not in ("push", "pop", "call", "sub", "add") for i in ins) and ins[-1].address + ins[-1].size == 0x4F75F5,
       "0x4F75E9…0x4F75F5 без изменения esp (%s)" % "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in ins))

    print("-- стабы в %s" % dll)
    lpe, limg, lbase = load(dll)
    lo, hi = lbase, lbase + len(limg)
    stubs = {}
    c = [a for a in find_all(limg, lbase, "6055e8") if bytes(limg[a - lbase + 7: a - lbase + 18]) == bytes.fromhex("8944241c6185c07506ff25")]
    # ★ integ2b: однозначная привязка по MAP (out/AsdaPatch.map, build.bat /MAP) — та же форма стаба у шести стабов отправки
    #   P62 (с integ2 проход P62 — `jmp [слот «следующий вызов»]`, рисунок совпал).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(dll)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X)" % (dmap.map_path, dmap.stamp or 0))
    va, good, msg = resolve(dmap, "St_Reward6581", "p67_gacha_reward_variant", c)
    ok(good, msg)
    if va:
        stubs["St_Reward6581"] = va
    c = [a for a in find_all(limg, lbase, "ff742410ff742410ff742410ff742410ff15")
         if bytes(limg[a - lbase + 22: a - lbase + 24]) == b"\x85\xc0" and limg[a - lbase + 24] == 0x74 and bytes(limg[a - lbase + 26: a - lbase + 29]) == b"\x50\x60\x55"]
    va, good, msg = resolve(dmap, "St_Soul6579", "p67_gacha_reward_variant", c)
    ok(good, msg)
    if va:
        stubs["St_Soul6579"] = va
    cfun = {}
    if "St_Reward6581" in stubs:
        jmps, calls, icalls = stub_targets(limg, lbase, stubs["St_Reward6581"], 2)
        ok(jmps == [0x004A7EA0, 0x004F758B], "St_Reward6581: jmp [..] -> %s (ожид. sub_4A7EA0, тело отказа 0x4F758B)" % ["0x%08X" % x for x in jmps])
        ok(len(calls) == 1 and lo <= calls[0] < hi, "St_Reward6581: call C-функции внутри DLL")
        if calls:
            cfun["St_Reward6581"] = calls[0]
    if "St_Soul6579" in stubs:
        jmps, calls, icalls = stub_targets(limg, lbase, stubs["St_Soul6579"], 1)
        ok(icalls == [0x00524390], "St_Soul6579: call [..] -> %s (сток sub_524390)" % ["0x%08X" % x for x in icalls])
        ok(len(calls) == 1 and lo <= calls[0] < hi, "St_Soul6579: call C-функции внутри DLL")
        if calls:
            cfun["St_Soul6579"] = calls[0]

    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    if "St_Reward6581" in stubs:
        for verdict, want in ((0, 0x004F75FA), (1, 0x004F758B)):
            seen = {}
            def getgroup(uc, a, sp):
                seen["group"] = uc.reg_read(UC_X86_REG_ECX)
                return 0x42
            def onreward(uc, a, sp, v=verdict):
                seen["reward"] = a
                return v
            emu.fake = {0x004A7EA0: (0, getgroup), cfun["St_Reward6581"]: (4, onreward)}
            emu.stops = {0x004F75FA, 0x004F758B}
            sp = ESP0 - 4
            mem = [(sp, struct.pack("<I", 0x004F75FA))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x0060AD18, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Reward6581"], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "St_Reward6581 вердикт=%d -> 0x%08X (ожид. 0x%08X), esp = как до call: %s"
               % (verdict, at or 0, want, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(seen.get("reward") == (FRAME,), "  P67_OnReward6581 получил ebp кадра 6581")
            if verdict == 0:
                ok(seen.get("group") == 0x0060AD18 and (emu.r(UC_X86_REG_EAX) & 0xFF) == 0x42, "  пропуск: сток sub_4A7EA0 вызван с ecx=60AD18h, al = его результат")
            else:
                ok("group" not in seen, "  отказ: сток sub_4A7EA0 не вызван, переход в тело отказа (3)")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    if "St_Soul6579" in stubs:
        for stock_r, verdict, want_eax, want_c in ((0, 9, 0, False), (7, 0, 7, True), (7, 1, 0, True)):
            seen = {}
            def secret(uc, a, sp, r=stock_r):
                seen["secret"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return r
            def onsoul(uc, a, sp, v=verdict):
                seen["soul"] = a
                return v
            emu.fake = {0x00524390: (16, secret), cfun["St_Soul6579"]: (4, onsoul)}
            emu.stops = {0x0049A968}
            sp = ESP0 - 20
            mem = [(sp, struct.pack("<IIIII", 0x0049A968, 0x11223344, 0x55667788, 77, 0x0058DEAC))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Soul6579"], regs, mem)
            ok(at == 0x0049A968 and emu.r(UC_X86_REG_ESP) == ESP0, "St_Soul6579 сток=%d вердикт=%d -> 0x49A968, стек сбалансирован (ret 10h): %s"
               % (stock_r, verdict, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(seen.get("secret") == (0xD00D, (0x11223344, 0x55667788, 77, 0x0058DEAC)), "  сток sub_524390 получил ecx=this и 4 аргумента в том же порядке")
            ok(emu.r(UC_X86_REG_EAX) == want_eax, "  eax = %d (ожид. %d)" % (emu.r(UC_X86_REG_EAX), want_eax))
            ok((seen.get("soul") == (FRAME,)) == want_c, "  P67_OnSoul6579 %s" % ("получил ebp кадра" if want_c else "не вызван (сток отказал)"))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


# ── сверка данных: таблицы сервера ↔ клиентская запись ───────────────────────────────────────────
SRV_COLS = 42          # Item_Table.txt: 42 колонки → запись 71 б (sub_4A96A0)
COL_LEVEL, COL_JOB, COL_TYPE, COL_SUB, COL_CLASS, COL_LW = 4, 7, 16, 17, 24, 40   # +8, +10, +26, +27, +36, +65


def _toi(x):
    try:
        return int(x)
    except Exception:
        return None


def load_server_item_table(path):
    srv = {}
    for ln in open(path, "rb").read().decode("latin-1").split("\n")[1:]:
        p = ln.split()
        if len(p) < SRV_COLS:
            continue
        v = [_toi(x) for x in p[:SRV_COLS]]
        if v[0] is None:
            continue
        srv[v[0]] = v
    return srv


def load_client_items(path):
    cl = {}
    for r in csv.DictReader(open(path, encoding="utf-8-sig", newline="")):
        try:
            cl[int(r["ItemCode"])] = r
        except Exception:
            pass
    return cl


def verify_tables(item_table, gacha_table, client_csv):
    print("-- таблицы: сервер %s, гача %s, клиент %s" % (item_table, gacha_table, client_csv))
    srv = load_server_item_table(item_table)
    cl = load_client_items(client_csv)
    common = [c for c in srv if c in cl]
    print("  записей: сервер %d, клиент %d, общих %d" % (len(srv), len(cl), len(common)))
    lw = lambda k: int(cl[k]["LinkWordCode"] or 0) & 0xFFFF
    sub = lambda k: int(cl[k]["ItemSubType"] or 0)
    # 1) соответствие колонок (по ненулевым значениям клиента)
    for fn, col, off in (("RequiredLevel", COL_LEVEL, 8), ("UsageCategory", COL_JOB, 10), ("ItemType", COL_TYPE, 26),
                         ("ItemSubType", COL_SUB, 27), ("LinkWordCode", COL_LW, 65)):
        nz = [k for k in common if int(cl[k][fn] or 0) != 0]
        eq = sum(1 for k in nz if (int(cl[k][fn] or 0) & 0xFFFF) == ((srv[k][col] or 0) & 0xFFFF))
        ok(eq >= 0.8 * len(nz), "колонка c%d (+%d) == клиент %s: %d/%d ненулевых (%.1f %%)" % (col, off, fn, eq, len(nz), 100.0 * eq / max(1, len(nz))))
    for fn in ("SetCode", "ItemGrade"):
        nz = [k for k in common if int(cl[k][fn] or 0) != 0]
        best = max((sum(1 for k in nz if int(cl[k][fn] or 0) == (srv[k][c] or 0)), c) for c in range(1, SRV_COLS))
        ok(best[0] < 0.5 * len(nz), "клиент %s на сервере ОТСУТСТВУЕТ (лучшая колонка c%d: %d/%d)" % (fn, best[1], best[0], len(nz)))
    # 2) призы гачи
    g = open(gacha_table, "rb").read().decode("latin-1").split("\n")
    codes = sorted({int(p[2]) for p in (ln.split() for ln in g[1:]) if len(p) >= 3 and p[2].lstrip("-").isdigit()})
    pk = [c for c in codes if c in cl and sub(c) in (200, 201)]
    it = [c for c in codes if c in cl and sub(c) not in (200, 201)]
    nocl = [c for c in codes if c not in cl]
    print("  призов (разных кодов): %d — коробок %d, предметов %d, вне таблицы предметов %d %s" % (len(codes), len(pk), len(it), len(nocl), nocl[:8]))
    ok(all(int(cl[c]["SetCode"] or 0) == 0 for c in it), "призы-предметы (не коробки): SetCode == 0 у всех %d (порт не предложит вариантов)" % len(it))
    pk_lw = [c for c in pk if lw(c)]
    notc3 = [(c, srv[c][COL_CLASS] if c in srv else None) for c in pk_lw if not (c in srv and srv[c][COL_CLASS] == 3)]
    ok(not notc3, "призы-коробки с ключом LinkWord (могут дойти до 6581): %d, на сервере класс +36 == 3 у всех (иначе: %s)" % (len(pk_lw), notc3[:8]))
    other = [(c, srv[c][COL_CLASS]) for c in pk if not lw(c) and c in srv and srv[c][COL_CLASS] != 3]
    print("  (коробки с LinkWord==0 и классом != 3 — порт вариантов не предлагает, сток отказал бы сам: %s)" % other)
    # 3) честные пары (приз, вариант) по правилу клиента и серверное правило P67
    fam = collections.defaultdict(list)
    for k in cl:
        if lw(k):
            fam[lw(k)].append(k)
    pairs = 0; passed = 0; fp = []
    for b in pk:
        if lw(b) == 0:
            continue
        bl = (srv[b][COL_LW] or 0) if b in srv else 0
        for m in fam[lw(b)]:
            if cl[m]["ItemGrade"] != cl[b]["ItemGrade"]:
                continue      # ResolveVariant: грейд варианта == грейд приза
            pairs += 1
            ml = (srv[m][COL_LW] or 0) if m in srv else 0
            if m == b or (bl and ml and ml == bl):
                passed += 1
            else:
                fp.append((b, bl, lw(b), m, ml))
    print("  честных пар (приз-коробка, вариант по правилу клиента): %d; серверное правило P67 пропускает %d, отвергнет %d" % (pairs, passed, len(fp)))
    byb = collections.defaultdict(list)
    for b, bl, cbl, m, ml in fp:
        byb[(b, bl, cbl)].append((m, ml))
    for (b, bl, cbl), ms in sorted(byb.items()):
        print("    приз %d (сервер lw %d, клиент lw %d): отвергнутых вариантов %d: %s" % (b, bl, cbl, len(ms), ", ".join("%d(lw %d)" % x for x in ms[:12])))
    ok(len(fp) == 0, "расхождений таблиц на честном пути нет (иначе — синхронизировать LinkWord порта с сервером до Mode=1)")
    print("=== ИТОГ (таблицы): %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ЗАМЕЧАНИЙ %d" % bad))
    return 1 if bad else 0


def main():
    if "--tables" in sys.argv:
        a = [x for x in sys.argv[1:] if x != "--tables"]
        tdir = os.environ.get("P67_TABLE_DIR")
        item = a[0] if len(a) > 0 else (tdir + "/item_table.txt" if tdir else V2 + "GameServer/ItemTable_Info/item_table.txt")
        gacha = a[1] if len(a) > 1 else (tdir + "/PrimiumGaChaTable.txt" if tdir else V2 + "GameServer/ItemTable_Info/PrimiumGaChaTable.txt")
        csvp = a[2] if len(a) > 2 else os.path.join(HERE, "..", "..", "..", "..", "AsdaReborn", "RawAssets", "Data", "ItemDB", "item_list.csv")
        return verify_tables(item, gacha, csvp)
    dll = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
    return verify_binary(dll)


if __name__ == "__main__":
    sys.exit(main())
