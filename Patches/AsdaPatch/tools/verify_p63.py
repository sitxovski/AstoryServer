# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p63.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P63 (общий замок «запрос в БД в полёте», волна A7, 2026-10-12).
#
# Сервер НЕ запускается. Грузятся три образа (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и собранная
# AsdaPatch.dll. Проверяем:
#  1) исходные байты всех 53 площадок (25 `call sub_5646C0`, 25 `call recvDBxxx` в ConnectSocketMsgProcess,
#     2 `call sub_52BFF0`, 1 `call sub_569DF0` в ClearUserMemory) и соседей (пролог `mov [ebp-disp],ecx` каждого
#     обработчика, прологи стоковых приёмов, sub_52BFF0, sub_5646C0, ClearUserMemory) — в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки начинаются и кончаются на
#     границе инструкции; цели call — те самые функции (rel32 пересчитан);
#  3) стабы найдены в DLL по сигнатурам; `jmp/call dword ptr [..]` разыменованы (ConnectSend 0x5646C0, sub_52BFF0,
#     sub_569DF0); 25 стабов `push N; jmp ReplyCommon` ведут в общий хвост (N=3 → хвост с одним аргументом);
#  4) unicorn: St_Send (пропуск → хвостовой переход в сток со стеком как был; подавление → ret 14h, eax=0),
#     St_Busy (сток отказал → его результат; сток 0 → наш гейт), St_Reply_4 → P63_ReplyWrap2(4, this, UserNum, s) → ret 8,
#     St_Clear → P63_OnUserClear(слот из [ebp+8]) → хвост в sub_569DF0 со стеком как был.
#  5) ЦЕПОЧКА P62 → P63 (integ2): на пяти общих площадках (6096/6506/6549/6555/6112) площадка `call` в образе
#     переписывается на стаб P62, его слот «следующий вызов» := St_Send (как делает P62_ChainSend), и исполнение идёт
#     С САМОЙ ИНСТРУКЦИИ call обработчика: P62 чисто + P63 пропуск → sub_5646C0 видит адрес возврата обработчика,
#     те же 5 аргументов, ecx, ebp; P62 чисто + P63 подавление → возврат в обработчик eax=0, sub_5646C0 не зван;
#     P62 отказ → тело отказа, esp до push'ей, P63_OnSend НЕ зван (замок не ставится). Тот же вход напрямую (только P63)
#     даёт P63_OnSend ТЕ ЖЕ аргументы (op, userIdx, ebp) — стаб P63 видит один и тот же кадр на обоих путях.
#     Стабы и C-функции — по MAP компоновщика (out/AsdaPatch.map).
# Запуск: python verify_p63.py [AsdaPatch.dll]   (образы: переменная P63_IMG_DIR или пути из wA7_logs/img)
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
IMG_DIR = os.environ.get("P63_IMG_DIR", r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img")
GS_IMAGES = [("сток", IMG_DIR + "/gs_stock.exe"), ("живой GameServer", IMG_DIR + "/gs_live.exe"), ("живой Indun", IMG_DIR + "/gs_indun.exe")]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


# (клиентский опкод, запрос БД, ответ БД, sendVa, thisDisp, thisKind, prologVa, prologHex, replyVa, replyTarget, nargs, replyKind, обработчик, приём)
FAM = [
    (5048, 2072, 2073, 0x00511B76, 0x170, 0, 0x00511803, "898d90feffff", 0x00430814, 0x00511B90, 2, 0, "CharQuestItemBuy", "sub_511B90"),
    (6162, 2469, 2470, 0x00516896, 0x1A0, 0, 0x00514FF3, "898d60feffff", 0x00433D21, 0x005168B0, 2, 0, "CharRoseWarStoreBuy", "sub_5168B0"),
    (6096, 2272, 2273, 0x0055AE4F, 0x418, 0, 0x0055A835, "898de8fbffff", 0x00432E0E, 0x0055B1C0, 2, 0, "Recv_OpenPackageItem", "sub_55B1C0"),
    (6098, 2270, 2270, 0x00554A17, 0x3E4, 0, 0x00554343, "898d1cfcffff", 0x00432DA6, 0x00559900, 1, 0, "EventItemRequestReq", "sub_559900"),
    (6502, 2302, 2303, 0x004FE8E1, 0x198, 0, 0x004FD9C5, "898d68feffff", 0x00432CB1, 0x004FE900, 2, 0, "Recv_User_Disassemble", "sub_4FE900"),
    (6506, 2306, 2307, 0x00501A5C, 0x4BC, 0, 0x00500F25, "898d44fbffff", 0x00432D19, 0x00501A80, 2, 0, "Recv_User_ShellItemUpgradeReset", "recvDBShellItemUpgradeReset"),
    (6549, 2527, 2528, 0x00535202, 0x618, 2, 0x00534655, "898de8f9ffff", 0x00433AA0, 0x00535260, 2, 2, "Recv_UserUpgradeExtraction", "recvDBUpgradeExtraction"),
    (6551, 2529, 2530, 0x00535F91, 0x1BC, 2, 0x005358D5, "898d44feffff", 0x00433AD4, 0x00535FB0, 2, 2, "Recv_UserUpgradeBless", "recvDBUpgradeBless"),
    (6553, 2531, 2532, 0x005369E5, 0x144, 2, 0x00536473, "898dbcfeffff", 0x00433B08, 0x00536A00, 2, 2, "Recv_UserItemOptionTrans", "recvDBItemOptionTrans"),
    (5433, 2165, 2165, 0x00514C49, 0x260, 0, 0x00513F93, "898da0fdffff", 0x00430BF9, 0x00514C60, 2, 0, "Recv_ShellItemOption_Extraction", "recvDBShellItemOptionExtraction"),
    (5468, 2229, 2229, 0x004F55FC, 0x194, 0, 0x004F48D3, "898d6cfeffff", 0x0043122C, 0x004F5680, 2, 0, "Recv_GachaItemUse", "sendGachaItemUse"),
    (6555, 2533, 2534, 0x005376F3, 0x298, 2, 0x00536EF5, "898d68fdffff", 0x00433B3C, 0x00537750, 2, 2, "Recv_UserPrimiumSum", "recvDBPrimiumSum"),
    (6586, 2568, 2569, 0x00539398, 0x02C, 2, 0x00539216, "894dd4",       0x004342AE, 0x005393B0, 2, 2, "Recv_UserStarPointUpdate", "recvDBStarPointUpdate"),
    (6140, 2452, 2453, 0x0055DC98, 0x0EC, 0, 0x0055D923, "898d14ffffff", 0x0043332A, 0x0055DD50, 2, 2, "RecvClient_CharNameChange", "sub_55DD50"),
    (6102, 2275, 2276, 0x00455828, 0x0F8, 1, 0x00454F83, "898d08ffffff", 0x00432E42, 0x00455860, 2, 1, "Recv_IncubatorReq", "recvDBIncubatorReq"),
    (6108, 2278, 2279, 0x00457DF3, 0x130, 1, 0x004576F5, "898dd0feffff", 0x00432EB2, 0x00457E10, 2, 1, "Recv_PetConditionUp", "sub_457E10"),
    (6110, 2280, 2281, 0x0045873C, 0x040, 1, 0x00458566, "894dc0",       0x00432EE6, 0x004587B0, 2, 1, "Recv_PetLiberate_Req", "recvPetLiberateReq"),
    (6112, 2282, 2283, 0x004590C7, 0x0F0, 1, 0x00458A73, "898d10ffffff", 0x00432F1A, 0x004590E0, 2, 1, "Recv_PetUnion_Req", "sub_4590E0"),
    (6118, 2292, 2293, 0x00459895, 0x070, 1, 0x00459640, "894d90",       0x00432FB6, 0x004598E0, 2, 1, "Recv_PetNameChange_Req", "sub_4598E0"),
    (6121, 2294, 2294, 0x00459F92, 0x084, 1, 0x00459C33, "898d7cffffff", 0x00432FEA, 0x00459FC0, 2, 1, "Recv_PetPossessionCountUp_Req", "recvPetPossessionCountUpReq"),
    (6148, 2464, 2465, 0x0045ADD6, 0x16C, 1, 0x0045A303, "898d94feffff", 0x00433392, 0x0045AE60, 2, 1, "RecvClient_PetMaxLevelUp", "recvDBPetMaxLevelUp"),
    (6171, 2577, 2578, 0x0041041B, 0x228, 1, 0x0040F7F5, "898dd8fdffff", 0x00433F9F, 0x004107C0, 2, 1, "Recv_EndFishing", "sub_4107C0"),
    (6182, 2587, 2588, 0x00413486, 0x0E8, 1, 0x00412D73, "898d18ffffff", 0x004340E9, 0x004134A0, 2, 1, "Recv_FishingBookReward", "sub_4134A0"),
    (6591, 2653, 2654, 0x0053A4B5, 0x0A8, 2, 0x00539D2B, "898d58ffffff", 0x00434354, 0x0053A5F0, 2, 2, "RecvUser_LimitationQuestEnter", "recvDBLimitationEnter"),
    (6593, 2657, 2658, 0x0053BFA3, 0x724, 2, 0x0053AC55, "898ddcf8ffff", 0x004343BC, 0x0053C180, 2, 2, "RecvUser_LimitationQuestResult", "recvDBLimitationResult"),
]
BUSY = [(5048, 0x005118FC), (6162, 0x00515111)]
CLEAR_VA = 0x00527374
CONNECT_SEND, PREAMBLE, SRVLOG, DISPATCH = 0x005646C0, 0x0052BFF0, 0x00569DF0, (0x0042FAB0, 0x00434690)
DB_OPCODES = set(f[1] for f in FAM)

GS_SITES = []
for op, rq, rp, sva, disp, kind, pva, phex, rva, rt, na, rk, hn, rn in FAM:
    GS_SITES.append(("send%d" % op, sva, _call(sva, CONNECT_SEND)))
    GS_SITES.append(("reply%d" % rp, rva, _call(rva, rt)))
for op, va in BUSY:
    GS_SITES.append(("busy%d" % op, va, _call(va, PREAMBLE)))
GS_SITES.append(("clear", CLEAR_VA, _call(CLEAR_VA, SRVLOG)))

GS_NEIGHBOURS = []
for op, rq, rp, sva, disp, kind, pva, phex, rva, rt, na, rk, hn, rn in FAM:
    GS_NEIGHBOURS.append(("пролог %s 0x%X: mov [ebp-0x%X],ecx" % (hn, pva, disp), pva, phex))
    GS_NEIGHBOURS.append(("пролог %s 0x%X" % (rn, rt), rt, "558bec"))
GS_NEIGHBOURS += [
    ("sub_52BFF0 (гейт «занят») пролог", PREAMBLE, "558bec"),
    ("sub_5646C0 (ConnectSend) пролог", CONNECT_SEND, "558bec"),
    ("ClearUserMemory 0x527350 пролог", 0x00527350, "558bec51894dfc"),
    ("ClearUserMemory 0x527379 add esp,18h", 0x00527379, "83c418"),
    ("ClearUserMemory 0x527383 m_lpsUserInfo[slot]=0", 0x00527383, "c7448a4000000000"),
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


def scan_into(pe, img, base, sites):
    """Переходы (rel8/rel32/jcc32) и abs32 ВНУТРЬ площадок (строго внутрь, не на первый байт)."""
    a, b = text_range(pe)
    inside = {}
    for n, va, o in sites:
        for k in range(1, len(bytes.fromhex(o))):
            inside[va + k] = n
    hits = {s[0]: 0 for s in sites}
    opnd = {s[0]: 0 for s in sites}   # ложные: байт операнда `push imm32` (опкод БД) прямо перед площадкой
    push_before = {}                   # va площадки → (адрес push, imm32), если перед call стоит `68 imm32`
    for n, va, o in sites:   # стоковая последовательность: push <опкод БД> (68 imm32) ; mov ecx, imm32 (B9) ; call
        if img[va - base - 10] == 0x68 and img[va - base - 5] == 0xB9:
            push_before[n] = (va - 10, struct.unpack("<I", bytes(img[va - base - 9: va - base - 5]))[0])
    for i in range(a, b - 6):
        o = img[i]
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            t = base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0]
            if t in inside:
                n = inside[t]
                pb = push_before.get(n)
                if pb and pb[0] < base + i < pb[0] + 5 and pb[1] in DB_OPCODES:
                    opnd[n] += 1          # источник — внутри `push <опкод БД>` перед call: не инструкция
                else:
                    hits[n] += 1
        if o in (0xE8, 0xE9):
            t = base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0]
            if t in inside:
                hits[inside[t]] += 1
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            t = base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0]
            if t in inside:
                hits[inside[t]] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        if v in inside:
            hits[inside[v]] += 1
    return hits, opnd


def boundary_ok(img, base, va, ln):
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


def stub_targets(img, base, va, stop_at_ret=True):
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
            break
        if ins.mnemonic == "ret" and stop_at_ret:
            break
    return jmps, calls, icalls


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
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

    def run(self, start, regs, mem=(), count=300):
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

    def rd(self, addr):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]


def main():
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        nbad = 0
        for n, va, o in GS_SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            if cur != bytes.fromhex(o):
                nbad += 1
                ok(False, "%-10s 0x%08X = %s (ожид. %s)" % (n, va, cur.hex(), o))
        ok(nbad == 0, "площадки: %d из %d совпали" % (len(GS_SITES) - nbad, len(GS_SITES)))
        nbad = 0
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            if cur != bytes.fromhex(o):
                nbad += 1
                ok(False, "сосед: %s = %s (ожид. %s)" % (n, cur.hex(), o))
        ok(nbad == 0, "соседи: %d из %d совпали" % (len(GS_NEIGHBOURS) - nbad, len(GS_NEIGHBOURS)))
        hits, opnd = scan_into(pe, img, base, GS_SITES)
        tot = sum(hits.values())
        for n, c in hits.items():
            if c:
                ok(False, "%-10s входов внутрь: %d" % (n, c))
        ok(tot == 0, "переходы/abs32 внутрь площадок: %d" % tot)
        ok(True, "ложные срабатывания rel8 исключены доказательно: %d (байт операнда `push <опкод БД>` перед `mov ecx,imm32; call`: %s)"
           % (sum(opnd.values()), ", ".join(n for n, c in opnd.items() if c) or "нет"))
        # все 25 площадок ответов лежат в ConnectSocketMsgProcess
        inside = all(DISPATCH[0] <= rva < DISPATCH[1] for _, _, _, _, _, _, _, _, rva, _, _, _, _, _ in FAM)
        ok(inside, "площадки ответов внутри ConnectSocketMsgProcess 0x%X..0x%X" % DISPATCH)

    pe, img, base = gs_ref
    print("-- границы инструкций (сток)")
    nbad = 0
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        if not (s and e):
            nbad += 1
            ok(False, "%-10s 0x%08X: начало %s, конец %s" % (n, va, s, e))
    ok(nbad == 0, "границы: %d площадок на границах инструкций" % (len(GS_SITES) - nbad))
    # прологи обработчиков: `mov [ebp-disp],ecx` стоит в первых 32 байтах функции и после `push ebp; mov ebp,esp`
    nbad = 0
    for op, rq, rp, sva, disp, kind, pva, phex, rva, rt, na, rk, hn, rn in FAM:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        fn_start = None
        for back in range(3, 40):
            if bytes(img[pva - base - back: pva - base - back + 3]) == b"\x55\x8b\xec":
                fn_start = pva - back
                break
        good = fn_start is not None and any(i.address == pva for i in md.disasm(bytes(img[fn_start - base: fn_start - base + 48]), fn_start))
        if not good:
            nbad += 1
            ok(False, "пролог %s: mov [ebp-0x%X],ecx @0x%X не на границе после push ebp/mov ebp,esp" % (hn, disp, pva))
    ok(nbad == 0, "прологи: %d обработчиков — `this` в [ebp-disp] сразу в прологе" % (len(FAM) - nbad))

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    sigs = {
        "St_Send":      "6055ff742438ff74242ce8",
        "St_Busy":      "51ff74240cff74240c8b4c2408ff15",
        "ReplyCommon2": "58ff742408ff74240851 50e8",
        "ReplyCommon1": "58ff7424045150e8",
        "St_Clear":     "600fbf450850e8",
    }
    stubs = {}
    for k, s in sigs.items():
        c = find_all(limg, lbase, s)
        if k == "St_Clear":
            # ★ 04.11.2026: голова «pushad; movsx eax,[ebp+8]; push eax; call» есть и у P96 St_Cleanup (30.10, «popad; push 6AEh»);
            #   стаб P63 после call — «popad; jmp [g_pSrvLog]» (61 FF 25)
            c = [a for a in c if limg[a - lbase + 11:a - lbase + 14] == bytes.fromhex("61ff25")]
        ok(len(c) == 1, "%s: найден, кандидатов %d (0x%08X)" % (k, len(c), c[0] if c else 0))
        if c:
            stubs[k] = c[0]
    cfun = {}
    if "St_Send" in stubs:
        jmps, calls, icalls = stub_targets(limg, lbase, stubs["St_Send"])
        ok(jmps == [CONNECT_SEND], "St_Send: jmp [g_pConnectSend] -> %s (сток 0x5646C0)" % ["0x%08X" % x for x in jmps])
        ok(len(calls) == 1 and lo <= calls[0] < hi, "St_Send: call P63_OnSend внутри DLL")
        d = disasm(limg, lbase, stubs["St_Send"], 0x40)
        ok(any(i.mnemonic == "ret" and i.op_str == "0x14" for i in d), "St_Send: ветка подавления — ret 14h (5 аргументов thiscall сняты)")
        cfun["send"] = calls[0] if calls else 0
    if "St_Busy" in stubs:
        jmps, calls, icalls = stub_targets(limg, lbase, stubs["St_Busy"])
        ok(icalls[:1] == [PREAMBLE], "St_Busy: call [g_pPreamble] -> %s (сток 0x52BFF0)" % ["0x%08X" % x for x in icalls])
        ok(len(calls) == 1 and lo <= calls[0] < hi, "St_Busy: call P63_EarlyGate внутри DLL")
        cfun["busy"] = calls[0] if calls else 0
    for k, retn in (("ReplyCommon2", "8"), ("ReplyCommon1", "4")):
        if k in stubs:
            jmps, calls, icalls = stub_targets(limg, lbase, stubs[k])
            d = disasm(limg, lbase, stubs[k], 0x20)
            ok(len(calls) == 1 and lo <= calls[0] < hi and any(i.mnemonic == "ret" and i.op_str in (retn, "0x" + retn) for i in d),
               "%s: call P63_ReplyWrap внутри DLL, ret %sh" % (k, retn))
            cfun[k] = calls[0] if calls else 0
    if "St_Clear" in stubs:
        jmps, calls, icalls = stub_targets(limg, lbase, stubs["St_Clear"])
        ok(jmps == [SRVLOG], "St_Clear: jmp [g_pSrvLog] -> %s (сток 0x569DF0)" % ["0x%08X" % x for x in jmps])
        ok(len(calls) == 1 and lo <= calls[0] < hi, "St_Clear: call P63_OnUserClear внутри DLL")
        cfun["clear"] = calls[0] if calls else 0
    # 25 стабов `push N; jmp ReplyCommonX`
    reply_stubs = {}
    for n in range(len(FAM)):
        want = stubs.get("ReplyCommon1" if FAM[n][10] == 1 else "ReplyCommon2")
        cands = []
        for a in find_all(limg, lbase, "6a%02xe9" % n):
            rel = struct.unpack("<i", bytes(limg[a - lbase + 3: a - lbase + 7]))[0]
            if a + 7 + rel == want:
                cands.append(a)
        if len(cands) == 1:
            reply_stubs[n] = cands[0]
        else:
            ok(False, "St_Reply_%d: push %d; jmp ReplyCommon%d — кандидатов %d" % (n, n, FAM[n][10], len(cands)))
    ok(len(reply_stubs) == len(FAM), "St_Reply_0..%d: %d из %d найдены и ведут в свой ReplyCommon" % (len(FAM) - 1, len(reply_stubs), len(FAM)))

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0, RET = 0x001E0000, 0x001C0000, 0x00511B7B
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    if "St_Send" in stubs and cfun.get("send"):
        for verdict, want in ((1, CONNECT_SEND), (0, RET)):
            seen = {}
            def onsend(uc, a, sp, v=verdict):
                seen["send"] = a
                return v
            emu.fake = {cfun["send"]: (12, onsend)}
            emu.stops = {CONNECT_SEND, RET}
            sp = ESP0 - 24
            args = (RET, 2302, 75, 7, 0x00150000, 0x2A)
            mem = [(sp, struct.pack("<6I", *args))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x7E0534, UC_X86_REG_EAX: 0xDEAD})
            at = emu.run(stubs["St_Send"], regs, mem)
            if verdict == 1:
                ok(at == want and emu.r(UC_X86_REG_ESP) == sp and emu.r(UC_X86_REG_ECX) == 0x7E0534
                   and struct.unpack("<6I", bytes(emu.uc.mem_read(sp, 24))) == args,
                   "St_Send пропуск -> сток 0x5646C0, esp/ecx/аргументы как были")
            else:
                ok(at == want and emu.r(UC_X86_REG_ESP) == sp + 4 + 0x14 and emu.r(UC_X86_REG_EAX) == 0,
                   "St_Send подавление -> ret 14h на 0x%08X, eax=0, стек снят (5 аргументов)" % RET)
            ok(seen.get("send") == (2302, 0x2A, FRAME), "  P63_OnSend(op=2302, userIdx=0x2A, ebp кадра) = %s" % (tuple(hex(x) for x in seen.get("send", ())),))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    if "St_Busy" in stubs and cfun.get("busy"):
        for stock_r, gate_r, want_eax, want_gate in ((0, 1, 1, True), (0, 0, 0, True), (3, 9, 3, False)):
            seen = {}
            def preamble(uc, a, sp, r=stock_r):
                seen["pre"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return r
            def gate(uc, a, sp, r=gate_r):
                seen["gate"] = a
                return r
            emu.fake = {PREAMBLE: (8, preamble), cfun["busy"]: (12, gate)}
            emu.stops = {RET}
            sp = ESP0 - 12
            mem = [(sp, struct.pack("<III", RET, 0x2A, 5048))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
            at = emu.run(stubs["St_Busy"], regs, mem)
            ok(at == RET and emu.r(UC_X86_REG_ESP) == sp + 4 + 8 and (emu.r(UC_X86_REG_EAX) & 0xFF) == want_eax,
               "St_Busy сток=%d гейт=%d -> ret 8, al=%d (ожид. %d)" % (stock_r, gate_r, emu.r(UC_X86_REG_EAX) & 0xFF, want_eax))
            ok(seen.get("pre") == (0xD00D, (0x2A, 5048)), "  сток sub_52BFF0 получил ecx=mgr и (userNum, opcode)")
            ok((seen.get("gate") == (0xD00D, 0x2A, 5048)) if want_gate else ("gate" not in seen),
               "  P63_EarlyGate %s" % ("(mgr, userNum, opcode) вызван" if want_gate else "не вызван (сток уже отказал)"))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    if 4 in reply_stubs and cfun.get("ReplyCommon2"):
        seen = {}
        def wrap(uc, a, sp):
            seen["wrap"] = a
            return 0x77
        emu.fake = {cfun["ReplyCommon2"]: (16, wrap)}
        emu.stops = {RET}
        sp = ESP0 - 12
        mem = [(sp, struct.pack("<III", RET, 0x2A, 0x00150000))]
        regs = dict(REGS0); regs.update({UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
        at = emu.run(reply_stubs[4], regs, mem)
        ok(at == RET and emu.r(UC_X86_REG_ESP) == sp + 4 + 8 and emu.r(UC_X86_REG_EAX) == 0x77, "St_Reply_4 -> ret 8, eax стока возвращён")
        ok(seen.get("wrap") == (4, 0xD00D, 0x2A, 0x00150000), "  P63_ReplyWrap2(4, this, UserNum, s) = %s" % (tuple(hex(x) for x in seen.get("wrap", ())),))
        ok(regs_kept(), "  ebx/esi/edi сохранены")
    if 3 in reply_stubs and cfun.get("ReplyCommon1"):
        seen = {}
        def wrap1(uc, a, sp):
            seen["wrap"] = a
            return 0x78
        emu.fake = {cfun["ReplyCommon1"]: (12, wrap1)}
        emu.stops = {RET}
        sp = ESP0 - 8
        mem = [(sp, struct.pack("<II", RET, 0x00150000))]
        regs = dict(REGS0); regs.update({UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
        at = emu.run(reply_stubs[3], regs, mem)
        ok(at == RET and emu.r(UC_X86_REG_ESP) == sp + 4 + 4 and emu.r(UC_X86_REG_EAX) == 0x78, "St_Reply_3 (2270) -> ret 4")
        ok(seen.get("wrap") == (3, 0xD00D, 0x00150000), "  P63_ReplyWrap1(3, this, s)")

    if "St_Clear" in stubs and cfun.get("clear"):
        seen = {}
        def onclear(uc, a, sp):
            seen["clear"] = a
            return 0
        emu.fake = {cfun["clear"]: (4, onclear)}
        emu.stops = {SRVLOG}
        sp = ESP0 - 28
        args = (0x00527379, 1, 0x599654, 0x599690, 0x2A, 0x2A, 0x00599000)
        mem = [(sp, struct.pack("<7I", *args)), (FRAME + 8, struct.pack("<I", 0x2A))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x5555, UC_X86_REG_EAX: 0x6666})
        at = emu.run(stubs["St_Clear"], regs, mem)
        ok(at == SRVLOG and emu.r(UC_X86_REG_ESP) == sp and struct.unpack("<7I", bytes(emu.uc.mem_read(sp, 28))) == args,
           "St_Clear -> сток sub_569DF0, стек (адрес возврата + 6 аргументов cdecl) как был")
        ok(seen.get("clear") == (0x2A,), "  P63_OnUserClear(userNum=0x2A из [ebp+8])")
        ok(emu.r(UC_X86_REG_EAX) == 0x6666 and emu.r(UC_X86_REG_ECX) == 0x5555 and regs_kept(), "  регистры сохранены")

    # ── 5. цепочка P62 → P63 (integ2) ─────────────────────────────────────────
    print("-- цепочка P62 → P63 → sub_5646C0 на общих площадках (unicorn, вход с инструкции call обработчика)")
    from asdamap import DllMap, map_matches_dll
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X)" % (dmap.map_path, dmap.stamp or 0))
    try:
        st_send = dmap.sym("St_Send", "p63_inflight_lock")
        on_send = dmap.sym("P63_OnSend")
    except ValueError as e:
        st_send = on_send = None
        ok(False, str(e))
    ok(st_send == stubs.get("St_Send"), "St_Send: MAP 0x%08X = сигнатура 0x%08X" % (st_send or 0, stubs.get("St_Send", 0)))
    ok(on_send == cfun.get("send"), "P63_OnSend: MAP 0x%08X = цель call в St_Send 0x%08X" % (on_send or 0, cfun.get("send", 0)))
    SHARED = [  # (опкод клиента, площадка, стаб P62, C-функция P62, тело отказа P62)
        (6096, 0x0055AE4F, "St_OpenPackage6096", "P62_OnOpenPackage6096", 0x0055ACC6),
        (6506, 0x00501A5C, "St_Reset6506",       "P62_OnReset6506",       0x005017AB),
        (6549, 0x00535202, "St_Extraction6549",  "P62_OnExtraction6549",  0x005349DB),
        (6555, 0x005376F3, "St_PrimiumSum6555",  "P62_OnPrimiumSum6555",  0x005370F8),
        (6112, 0x004590C7, "St_PetUnion6112",    "P62_OnPetUnion6112",    0x00458DF7),
    ]
    famby = {f[0]: f for f in FAM}
    nchain = 0
    for op, site, sname, cname, refuse in SHARED:
        f = famby.get(op)
        ok(f is not None and f[3] == site, "%d: площадка P63 0x%08X = площадка P62 0x%08X" % (op, f[3] if f else 0, site))
        try:
            p62s, p62c = dmap.sym(sname, "p62_slot_uniqueness"), dmap.sym(cname)
        except ValueError as e:
            ok(False, str(e))
            continue
        ins = disasm(limg, lbase, p62s, 0x30)
        slots = [int(i.op_str.split("[")[1].split("]")[0], 16) for i in ins if i.mnemonic == "jmp" and "dword ptr [" in i.op_str]
        if not slots or not st_send or not on_send:
            ok(False, "%d: слот «следующий вызов» стаба P62 не найден" % op)
            continue
        slot = slots[0]
        db_req = f[1]
        ret_va = site + 5
        args = (db_req, 0x71, 7, 0x00150040, 0x2A)        # op БД, длина, соединение, тело, индекс слота — как кладёт сток
        orig_site = bytes(emu.uc.mem_read(site, 5))
        orig_slot = bytes(emu.uc.mem_read(slot, 4))
        res = {}
        for path, v62, v63 in (("P62", 0, 1), ("P62", 0, 0), ("P62", 1, 1), ("P63", None, 1), ("P63", None, 0)):
            first = p62s if path == "P62" else st_send
            emu.uc.mem_write(site, b"\xE8" + struct.pack("<i", first - (site + 5)))      # установка площадки
            emu.uc.mem_write(slot, struct.pack("<I", st_send))                         # P62_ChainSend(site, St_Send)
            try:
                emu.uc.ctl_remove_cache(site, site + 5)                                # unicorn кэширует перевод блока — сбросить после правки кода
            except Exception:
                pass
            seen = {}
            def c62(uc, a, sp, v=v62):
                seen["p62"] = a
                return v
            def c63(uc, a, sp, v=v63):
                seen["p63"] = a
                return v
            def connect(uc, a, sp):
                seen["db"] = (uc.reg_read(UC_X86_REG_ECX), uc.reg_read(UC_X86_REG_EBP), a, struct.unpack("<I", bytes(uc.mem_read(sp - 4, 4)))[0])
                return 1
            emu.fake = {p62c: (4, c62), on_send: (12, c63), CONNECT_SEND: (20, connect)}
            emu.stops = {ret_va, refuse}
            sp = ESP0 - 20
            mem = [(sp, struct.pack("<5I", *args))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x007E0538, UC_X86_REG_EAX: 0xDEAD})
            at = emu.run(site, regs, mem, count=600)          # исполнение С ИНСТРУКЦИИ call обработчика
            esp_after = emu.r(UC_X86_REG_ESP)
            kept = regs_kept() and emu.r(UC_X86_REG_EBP) == FRAME
            tag = "%d %s P62=%s P63=%s" % (op, "через P62" if path == "P62" else "напрямую (только P63)", "-" if v62 is None else ("отказ" if v62 else "чисто"),
                                         "пропуск" if v63 else "подавление")
            if path == "P62" and v62 == 1:
                ok(at == refuse and esp_after == ESP0 and "p63" not in seen and "db" not in seen and kept,
                   "%s -> тело отказа 0x%08X, esp до push'ей, P63_OnSend НЕ вызван (замок не ставится), сток не зван" % (tag, refuse))
            elif v63 == 1:
                ok(at == ret_va and esp_after == ESP0 and kept and seen.get("db") == (0x007E0538, FRAME, args, ret_va),
                   "%s -> sub_5646C0(ecx, ebp, 5 аргументов, возврат 0x%08X) и возврат в обработчик ret 14h, стек сбалансирован" % (tag, ret_va))
            else:
                ok(at == ret_va and esp_after == ESP0 and kept and emu.r(UC_X86_REG_EAX) == 0 and "db" not in seen,
                   "%s -> подавлено: возврат в обработчик eax=0, ret 14h, sub_5646C0 не зван" % tag)
            if path == "P62":
                ok(seen.get("p62") == (FRAME,), "  P62 C-функция получила ebp кадра")
            if "p63" in seen:
                res[(path, v63)] = seen["p63"]
                ok(seen["p63"] == (db_req, 0x2A, FRAME), "  P63_OnSend(op=%d, userIdx=0x2A, ebp кадра) = %s" % (db_req, tuple(hex(x) for x in seen["p63"])))
        same = res.get(("P62", 1)) is not None and res.get(("P62", 1)) == res.get(("P63", 1)) == res.get(("P62", 0)) == res.get(("P63", 0))
        ok(same, "%d: P63_OnSend видит один и тот же вход через P62 и напрямую" % op)
        nchain += 1 if same else 0
        emu.uc.mem_write(site, orig_site)
        try:
            emu.uc.ctl_remove_cache(site, site + 5)
        except Exception:
            pass
        emu.uc.mem_write(slot, orig_slot)
    ok(nchain == len(SHARED), "цепочка P62 → P63 подтверждена на %d из %d общих площадок" % (nchain, len(SHARED)))

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
