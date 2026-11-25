# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p60.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P60 ValueGuard (античит, волна A7, 2026-10-12):
#   значения по серверным таблицам — 5020 (количество/сумма), 6180/6150 (знак количества), 5048 (код книги),
#   5041/sub_45DEE0 (номер награды), 6586 (анти-повтор/знак), 6521 (ступень клана).
#
# Сервер НЕ запускается. Грузятся настоящие образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) исходные байты 8 площадок и 16 «соседей» (тела отказов/эпилог/инструкции после call) в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов
#     начинаются/кончаются на границе инструкции; стоковые цели стабов снимают со стека ожидаемое (ret 8/4/10h,
#     cdecl без ret imm); обработчики читают именно те глобальные таблицы, на которые опирается патч;
#  3) стабы найдены в DLL (сигнатуры + цели), `jmp dword ptr [..]`/`call dword ptr [..]` разыменованы;
#  4) unicorn: каждый стаб исполняется на подставном кадре, C-функции и серверные функции подменяются
#     заглушками — ветки (пропуск / штатное тело / тихий выход / eax=0), баланс стека, сохранность регистров.
# ★ fix13 (13.10.2026): стабы St_* и их C-функции P60_On* привязаны по MAP компоновщика (asdamap: имя + объект,
#   метка MAP↔PE); сигнатура — второй метод.
# Запуск: python verify_p60.py [AsdaPatch.dll]   (P60_IMG_DIR=<папка с gs_stock/gs_live/gs_indun.exe>)
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
                               UC_X86_REG_EIP)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
d = os.environ.get("P60_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if d:   # локальные копии образов (те же md5)
    GS_IMAGES = [("сток", d + "/gs_stock.exe"), ("живой GameServer", d + "/gs_live.exe"), ("живой Indun", d + "/gs_indun.exe")]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


GET_USER, STATE_GATE, QBOOK, ANTI_REPLAY = 0x005324A0, 0x0052BFF0, 0x00532B30, 0x00524390
GS_SITES = [
    ("P60.buy5020",   0x0050F3F0, _call(0x0050F3F0, STATE_GATE)),    # CharItemBuy: гейт «занят»
    ("P60.fish6180",  0x004125CC, _call(0x004125CC, GET_USER)),      # Recv_FishingBookUpdate: GetUser
    ("P60.title6150", 0x0055F1AD, _call(0x0055F1AD, GET_USER)),      # RecvClient_TitleItemCheck: GetUser
    ("P60.book5048",  0x00511978, _call(0x00511978, QBOOK)),         # CharQuestItemBuy: sub_532B30
    ("P60.reward5041",0x0045E0F1, _call(0x0045E0F1, GET_USER)),      # sub_45DEE0: GetUser
    ("P60.starReplay",0x00539278, _call(0x00539278, ANTI_REPLAY)),   # Recv_UserStarPointUpdate: sub_524390
    ("P60.star6586",  0x005392DB, _call(0x005392DB, GET_USER)),      # Recv_UserStarPointUpdate: GetUser
    ("P60.clan6521",  0x00409AD0, _call(0x00409AD0, GET_USER)),      # Recv_User_ClanGrade: GetUser
]
GS_NEIGHBOURS = [
    ("5020 тело код 0 0x50F3FC",             0x0050F3FC, "c68558fcffff00"),
    ("5020 тело код 4 0x510A09",             0x00510A09, "c68558fcffff04"),
    ("5020 тело код 3 0x510AC8",             0x00510AC8, "c68558fcffff03"),
    ("5020 после call 0x50F3F5 (movzx edx,al)", 0x0050F3F5, "0fb6d085d2"),
    ("5020 memcpy тела → [ebp-3D4h] 0x50F2D0", 0x0050F2D0, "8d852cfcffff50e8"),
    ("5020 pUser → [ebp-3DCh] 0x50F2F9",     0x0050F2F9, "898524fcffff"),
    ("6180 тело код 8 0x412906",             0x00412906, "c68588feffff08"),
    ("6180 после call 0x4125D1",             0x004125D1, "8985d0fdffff"),
    ("6180 memcpy тела → [ebp-228h] 0x4125A3", 0x004125A3, "8d8dd8fdffff51e8"),
    ("6150 тело код 6 0x55F2CF",             0x0055F2CF, "c645a506"),
    ("6150 после call 0x55F1B2",             0x0055F1B2, "898508ffffff"),
    ("6150 memcpy тела → [ebp-F0h] 0x55F189", 0x0055F189, "8d8d10ffffff51e8"),
    ("5048 после call 0x51197D (add esp,4; test)", 0x0051197D, "83c40485c0"),
    ("5048 this → ecx 0x511994 ([ebp-170h])", 0x00511994, "8b8d90feffff"),
    ("sub_45DEE0 после call 0x45E0F6",       0x0045E0F6, "8985c4faffff"),
    ("sub_45DEE0 return 0 0x45E105",         0x0045E105, "32c0e96c2b0000"),
    ("sub_45DEE0 a3 = [ebp+0Ch] 0x45E113",   0x0045E113, "8b550c"),
    ("6586 после анти-повтора 0x53927D (push 1)", 0x0053927D, "6a01"),
    ("6586 после GetUser 0x5392E0",          0x005392E0, "8945e4"),
    ("6586 эпилог 0x53939D",                 0x0053939D, "8be55dc20800"),
    ("6586 memcpy тела → [ebp-24h] 0x5392BA", 0x005392BA, "8d4ddc51e8"),
    ("6586 this → [ebp-2Ch] 0x53926F",       0x0053926F, "8b45d48b48048b4934"),
    ("6521 тело код 3 0x409C76",             0x00409C76, "c68537ffffff03"),
    ("6521 после call 0x409AD5",             0x00409AD5, "8985e4feffff"),
    ("6521 memcpy тела → [ebp-118h] 0x409AA6", 0x00409AA6, "8d95e8feffff52e8"),
    ("6521 своя ступень CUser+1832Bh 0x409BE6", 0x00409BE6, "0fb6822b830100"),
    ("sub_532B30 пролог",                    0x00532B30, "558bec"),
    ("sub_532A90 пролог",                    0x00532A90, "558bec"),
    ("sub_5324A0 пролог",                    0x005324A0, "558bec"),
]
BOUNDARY_EXTRA = [0x0050F3FC, 0x00510A09, 0x00510AC8, 0x0050F3F5, 0x00412906, 0x004125D1, 0x0055F2CF, 0x0055F1B2,
                  0x0051197D, 0x0045E0F6, 0x0045E105, 0x0053927D, 0x005392E0, 0x0053939D, 0x00409C76, 0x00409AD5]
# Ожидаемые ret imm у стоковых целей (thiscall снимает сам; cdecl — без imm).
RET_EXPECT = {STATE_GATE: 8, GET_USER: 4, ANTI_REPLAY: 0x10, QBOOK: 0}
# Обработчик → глобальные таблицы, на которые опирается патч (abs32 внутри функции).
GLOBALS_EXPECT = [
    ("CharItemBuy читает dword_5F5E98/dword_5F5E8C", 0x0050F170, 0x00510B90, [0x005F5E98, 0x005F5E8C]),
    ("sub_532B30 читает dword_5F5EA8", 0x00532B30, 0x00532B80, [0x005F5EA8]),
    ("sub_45DEE0 читает dword_5F5E74", 0x0045DEE0, 0x00460C8C, [0x005F5E74]),
    ("загрузчик RepayTable sub_4AB950 пишет dword_5F5E74 (Block[0]=count, данные +4)", 0x004AB950, 0x004AC3B0, [0x005F5E74]),
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


def ret_imms(img, base, va, n=0x600):
    """Все `ret`/`ret imm16` функции с va (до первого int3-блока после ret)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = set()
    for ins in md.disasm(bytes(img[va - base: va - base + n]), va):
        if ins.mnemonic == "ret":
            out.add(int(ins.op_str, 16) if ins.op_str else 0)
        if ins.mnemonic == "int3":
            break
    return out


def abs32_in(img, base, lo, hi, value):
    sig = struct.pack("<I", value)
    return img.find(sig, lo - base, hi - base) >= 0


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


def stub_info(img, base, va):
    """Разбор стаба до первого `ret`: jmp [p]→*p, call rel32, call [p]→*p, есть ли `xor eax,eax`."""
    jmps, calls, icalls, xor = [], [], [], False
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "call" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            icalls.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "xor" and ins.op_str == "eax, eax":
            xor = True
        if ins.mnemonic == "ret":
            break
    return jmps, calls, icalls, xor


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
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
            args = struct.unpack("<4I", uc.mem_read(esp + 4, 16))
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


def main():
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
        for target, imm in RET_EXPECT.items():
            r = ret_imms(img, base, target)
            ok(r == {imm}, "стоковая цель 0x%08X: ret %s (ожид. %d)" % (target, sorted(r), imm))
        for n, lo, hi, vals in GLOBALS_EXPECT:
            ok(all(abs32_in(img, base, lo, hi, v) for v in vals), n)
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
    # Загрузчик RepayTable: `mov [eax], count` перед `add eax,4` — проверяем форму «Block[0]=count; данные с +4» по декомпилу
    # (GS:68880): ищем в функции запись в [0x5F5E74] и чтение 126*i. Достаточно abs32 выше; здесь — размер записи 126 (imul ...,7Eh).
    ok(img.find(bytes.fromhex("6b"), 0x4AB950 - base, 0x4AC3B0 - base) >= 0 and img.find(b"\x7e", 0x4AB950 - base, 0x4AC3B0 - base) >= 0,
       "загрузчик RepayTable sub_4AB950: запись 126 б (imul 7Eh) в 0x4AB950..0x4AC3B0")

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    stubs, cfun = {}, {}
    # ★ fix13: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP): сигнатуры `push [esp+N]…;
    #   call [GetUser]` совпадают у стабов других патчей; MAP даёт имя И объект (p60_value_guard), сигнатура с целью
    #   `call dword ptr [..]` — второй метод (стаб по MAP обязан быть среди её кандидатов, прочие — чужие именованные стабы).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))

    def classify(sig, icall_target, want):
        """want: {имя: (jmp-цели, нужен ли xor eax,eax, маркер после сигнатуры или None)}"""
        n = len(bytes.fromhex(sig))
        cands = [a for a in find_all(limg, lbase, sig) if stub_info(limg, lbase, a)[2][:1] == [icall_target]]
        for k, (ej, exor, marker) in want.items():
            a, good, msg = resolve(dmap, k, "p60_value_guard", cands)
            ok(good, msg)
            if a is not None:
                jmps, calls, icalls, xor = stub_info(limg, lbase, a)
                mk = (not marker) or bytes(limg[a - lbase + n + 4: a - lbase + n + 4 + len(bytes.fromhex(marker))]) == bytes.fromhex(marker)
                if mk and jmps == ej and xor == exor and len(calls) == 1 and lo <= calls[0] < hi:
                    stubs[k] = a; cfun[k] = calls[0]
            ok(k in stubs, "%s: найден (0x%08X), C-функция внутри DLL (0x%08X)" % (k, stubs.get(k, 0), cfun.get(k, 0)))
            cname = "P60_On" + k[3:]          # St_Buy5020 → P60_OnBuy5020 (исходник p60_value_guard.cpp)
            try:
                cva = dmap.sym(cname, "p60_value_guard")
            except ValueError as e:
                cva = None
                print("    " + str(e))
            ok(cva is not None and cfun.get(k) == cva, "%s: call → %s по MAP (0x%08X)" % (k, cname, cva or 0))

    classify("ff742408ff742408ff15", STATE_GATE, {"St_Buy5020": ([0x0050F3FC, 0x00510A09, 0x00510AC8], False, None)})
    classify("ff742404ff15", GET_USER, {
        "St_Fish6180":  ([0x00412906], False, None),
        "St_Title6150": ([0x0055F2CF], False, None),
        "St_Clan6521":  ([0x00409C76], False, None),
        "St_Reward5041": ([], True, None),
        "St_Star6586":  ([0x0053939D], True, None),
    })
    classify("ff742404ff15", QBOOK, {"St_QuestBook5048": ([], False, "83c40485c0")})
    classify("ff742410ff742410ff742410ff742410ff15", ANTI_REPLAY, {"St_Star6586Replay": ([0x0053939D], True, None)})

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    USER = 0x00150000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    # St_Buy5020: ecx=this, [esp]=ret, [esp+4]=userNum, [esp+8]=opcode; сток 0x52BFF0 (thiscall, ret 8)
    if "St_Buy5020" in stubs:
        for gate, verdict, want in ((1, 9, 0x0050F3F5), (0, 0, 0x0050F3F5), (0, 1, 0x0050F3FC), (0, 2, 0x00510A09), (0, 3, 0x00510AC8)):
            seen = {}
            def gatefn(uc, a, sp, r=gate):
                seen["gate"] = (uc.reg_read(UC_X86_REG_ECX), a[:2]); return r
            def onbuy(uc, a, sp, v=verdict):
                seen["buy"] = a[:1]; return v
            emu.fake = {STATE_GATE: (8, gatefn), cfun["St_Buy5020"]: (4, onbuy)}
            emu.stops = {0x0050F3F5, 0x0050F3FC, 0x00510A09, 0x00510AC8}
            sp = ESP0 - 12
            mem = [(sp, struct.pack("<III", 0x0050F3F5, 7, 5020))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Buy5020"], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "St_Buy5020 гейт=%d вердикт=%d -> 0x%08X (ожид. 0x%08X), esp сбалансирован: %s"
               % (gate, verdict, at or 0, want, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(seen.get("gate") == (0xD00D, (7, 5020)), "  сток sub_52BFF0 получил ecx=this и (userNum, opcode)")
            if gate:
                ok("buy" not in seen and (emu.r(UC_X86_REG_EAX) & 0xFF) == 1, "  занят → P60 не зовётся, al=1 как сток")
            else:
                ok(seen.get("buy") == (FRAME,), "  P60_OnBuy5020 получил ebp кадра")
                if verdict == 0:
                    ok((emu.r(UC_X86_REG_EAX) & 0xFF) == 0, "  пропуск: al=0 (как сток)")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # GetUser-стабы с переходом в тело: [esp]=ret, [esp+4]=userNum; сток 0x5324A0 (thiscall, ret 4)
    for k, ret_va, body in (("St_Fish6180", 0x004125D1, 0x00412906), ("St_Title6150", 0x0055F1B2, 0x0055F2CF),
                            ("St_Clan6521", 0x00409AD5, 0x00409C76), ("St_Star6586", 0x005392E0, 0x0053939D)):
        if k not in stubs:
            continue
        for user, verdict, want in ((0, 9, ret_va), (USER, 0, ret_va), (USER, 1, body)):
            seen = {}
            def getuser(uc, a, sp, u=user):
                seen["gu"] = (uc.reg_read(UC_X86_REG_ECX), a[0]); return u
            def onx(uc, a, sp, v=verdict):
                seen["c"] = a[:2]; return v
            emu.fake = {GET_USER: (4, getuser), cfun[k]: (8, onx)}
            emu.stops = {ret_va, body}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<II", ret_va, 7))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs[k], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "%s user=%s вердикт=%d -> 0x%08X (ожид. 0x%08X), esp сбалансирован: %s"
               % (k, "да" if user else "нет", verdict, at or 0, want, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(seen.get("gu") == (0xD00D, 7), "  сток GetUser получил ecx=mgr и userNum")
            if not user:
                ok("c" not in seen and emu.r(UC_X86_REG_EAX) == 0, "  пользователя нет → P60 не зовётся, eax=0 как сток")
            else:
                ok(seen.get("c") == (FRAME, USER), "  C-функция получила (ebp, user)")
                if verdict == 0:
                    ok(emu.r(UC_X86_REG_EAX) == USER, "  пропуск: eax = user (как сток)")
                elif k == "St_Star6586":
                    ok(emu.r(UC_X86_REG_EAX) == 0, "  тихий выход: eax=0 на эпилоге")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_Reward5041: отказ = eax=0 при возврате
    if "St_Reward5041" in stubs:
        for user, verdict, want_eax in ((0, 9, 0), (USER, 0, USER), (USER, 1, 0)):
            seen = {}
            def getuser(uc, a, sp, u=user):
                seen["gu"] = a[0]; return u
            def onr(uc, a, sp, v=verdict):
                seen["c"] = a[:2]; return v
            emu.fake = {GET_USER: (4, getuser), cfun["St_Reward5041"]: (8, onr)}
            emu.stops = {0x0045E0F6}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<II", 0x0045E0F6, 7))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Reward5041"], regs, mem)
            ok(at == 0x0045E0F6 and emu.r(UC_X86_REG_ESP) == ESP0 and emu.r(UC_X86_REG_EAX) == want_eax,
               "St_Reward5041 user=%s вердикт=%d -> 0x45E0F6, eax=0x%X (ожид. 0x%X), esp сбалансирован" % ("да" if user else "нет", verdict, emu.r(UC_X86_REG_EAX), want_eax))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_QuestBook5048: cdecl — [esp]=ret, [esp+4]=code; вызывающий снимает 4 б
    if "St_QuestBook5048" in stubs:
        for stock, verdict, want_eax in ((0, 9, 0), (1, 1, 1), (1, 0, 0)):
            seen = {}
            def qb(uc, a, sp, r=stock):
                seen["qb"] = a[0]; return r
            def onq(uc, a, sp, v=verdict):
                seen["c"] = a[:2]; return v
            emu.fake = {QBOOK: (0, qb), cfun["St_QuestBook5048"]: (8, onq)}
            emu.stops = {0x0051197D}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<II", 0x0051197D, 20003))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_QuestBook5048"], regs, mem)
            ok(at == 0x0051197D and emu.r(UC_X86_REG_ESP) == ESP0 - 4 and emu.r(UC_X86_REG_EAX) == want_eax,
               "St_QuestBook5048 сток=%d вердикт=%d -> 0x51197D, eax=%d (ожид. %d), аргумент стока на месте (cdecl)" % (stock, verdict, emu.r(UC_X86_REG_EAX), want_eax))
            ok(seen.get("qb") == 20003, "  сток sub_532B30 получил код")
            if stock:
                ok(seen.get("c") == (FRAME, 20003), "  P60_OnQuestBook5048 получил (ebp, code)")
            else:
                ok("c" not in seen, "  сток отказал → P60 не зовётся")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_Star6586Replay: ecx=mgr, [esp]=ret, 4 аргумента; сток 0x524390 (thiscall, ret 10h)
    if "St_Star6586Replay" in stubs:
        for stock, verdict, want in ((1, 9, 0x0053927D), (0, 0, 0x0053927D), (0, 1, 0x0053939D)):
            seen = {}
            def ar(uc, a, sp, r=stock):
                seen["ar"] = (uc.reg_read(UC_X86_REG_ECX), a); return r
            def onrep(uc, a, sp, v=verdict):
                seen["c"] = a[:1]; return v
            emu.fake = {ANTI_REPLAY: (16, ar), cfun["St_Star6586Replay"]: (4, onrep)}
            emu.stops = {0x0053927D, 0x0053939D}
            sp = ESP0 - 20
            mem = [(sp, struct.pack("<IIIII", 0x0053927D, 0x11, 0x22, 7, 0x59B74C))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Star6586Replay"], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "St_Star6586Replay сток=%d вердикт=%d -> 0x%08X (ожид. 0x%08X), esp сбалансирован (ret 10h)"
               % (stock, verdict, at or 0, want))
            ok(seen.get("ar") == (0xD00D, (0x11, 0x22, 7, 0x59B74C)), "  сток sub_524390 получил ecx и 4 аргумента в том же порядке")
            if stock:
                ok("c" not in seen and emu.r(UC_X86_REG_EAX) == 1, "  анти-повтор прошёл → P60 не зовётся, eax как у стока")
            else:
                ok(seen.get("c") == (FRAME,), "  P60_OnStar6586Replay получил ebp")
                ok(emu.r(UC_X86_REG_EAX) == 0, "  eax=0 (%s)" % ("тихий выход" if verdict else "как сток, результат игнорируется"))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
