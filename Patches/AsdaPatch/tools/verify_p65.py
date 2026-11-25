# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p65.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P65 ConsumableType (античит, волна A7, 2026-10-12):
#   тип расходника по Function_Table в 6551/6553/5433 и «код пакета == код слота» в 5450.
#
# Сервер НЕ запускается. Грузятся три образа (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и собранная
# AsdaPatch.dll. Проверяем:
#  1) исходные байты четырёх площадок `call sub_532B10` и всех «соседей» (push кода из кадра, хвост add/test/jcc,
#     тела стоковых отказов, чтение кода пакета 5450, бонус помощника +9, пролог sub_532B10) в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и цели jcc/отказов —
#     на границе инструкции; цель каждого `E8` — ровно sub_532B10 (0x532B10);
#  3) стабы найдены в DLL по сигнатурам (push ecx/edx/ebp; push [esp+16]; push N; call …; pop; pop; ret) — четыре,
#     с номерами площадок 1..4, и все зовут ОДНУ C-функцию внутри DLL (P65_Check);
#  4) unicorn: каждый стаб исполняется с подставной C-функцией — аргументы (site, code, ebp) в нужном порядке,
#     возврат eax как у C-функции (0 и 1), стек сбалансирован (cdecl: аргумент снимает вызывающий), ecx/edx/ebx/esi/edi
#     и ebp сохранены, возврат на адрес стока.
# ★ fix13 (13.10.2026): стабы St_Bless6551/St_OptTrans6553/St_Helper5433/St_Use5450 и P65_Check — по MAP компоновщика
#   (asdamap: имя + объект, метка MAP↔PE); сигнатура — второй метод.
# Запуск: python verify_p65.py [AsdaPatch.dll]   (образы — P65_IMG_DIR или P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
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
_d = os.environ.get("P65_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

IS_FUNC = 0x00532B10


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


# (имя, VA, байты стока, адрес стокового возврата после площадки)
GS_SITES = [
    ("P65.bless6551",  0x00535B01, _call(0x00535B01, IS_FUNC)),
    ("P65.opt6553",    0x0053664A, _call(0x0053664A, IS_FUNC)),
    ("P65.helper5433", 0x00514A79, _call(0x00514A79, IS_FUNC)),
    ("P65.use5450",    0x004EDD82, _call(0x004EDD82, IS_FUNC)),
]
GS_NEIGHBOURS = [
    ("6551 push кода свитка 0x535AFA (mov edx,[ebp-19Ch]; push edx)",  0x00535AFA, "8b9564feffff52"),
    ("6551 хвост 0x535B06 (add esp,4; test eax,eax; jne 0x535B51)",    0x00535B06, "83c40485c07544"),
    ("6551 отказ 0x535B0D (mov byte [ebp-80h],2 → 6552 код 2)",         0x00535B0D, "c6458002"),
    ("6551 push 0x1998 (6552) 0x535B23",                                0x00535B23, "6898190000"),
    ("6551 pUser 0x535A11 (mov [ebp-18Ch],eax)",                         0x00535A11, "898574feffff"),
    ("6551 код вещи 0x535C26 (mov ecx,[ebp-194h])",                      0x00535C26, "8b8d6cfeffff"),
    ("6553 push кода свитка 0x536643 (mov edx,[ebp-FCh]; push edx)",    0x00536643, "8b9504ffffff52"),
    ("6553 хвост 0x53664F (… jne 0x5366A0)",                             0x0053664F, "83c40485c0754a"),
    ("6553 отказ 0x536656 (mov byte [ebp-B8h],2 → 6554 код 2)",          0x00536656, "c68548ffffff02"),
    ("6553 push 0x199A (6554) 0x536672",                                 0x00536672, "689a190000"),
    ("6553 pUser 0x5365A8 (mov [ebp-ECh],eax)",                          0x005365A8, "898514ffffff"),
    ("6553 код вещи 0x536685 (mov ecx,[ebp-F4h])",                       0x00536685, "8b8d0cffffff"),
    ("5433 push кода помощника 0x514A72 (mov edx,[ebp-134h]; push edx)",0x00514A72, "8b95ccfeffff52"),
    ("5433 хвост 0x514A7E (… je 0x514AAA)",                              0x00514A7E, "83c40485c07425"),
    ("5433 отказ 0x514AAA (mov byte [ebp-E9h],0)",                       0x00514AAA, "c68517ffffff00"),
    ("5433 отказ тело 0x514AC7 (mov byte [ebp-228h],0 → 5434 код 0)",    0x00514AC7, "c685d8fdffff00"),
    ("5433 push 0x153A (5434) 0x514AE3",                                 0x00514AE3, "683a150000"),
    ("5433 бонус +9 0x514A97 (movsx edx,[ecx+eax+9])",                   0x00514A97, "0fbf540109"),
    ("5433 this 0x513F93 (mov [ebp-260h],ecx)",                          0x00513F93, "898da0fdffff"),
    ("5433 Src lea 0x514BB9 (lea eax,[ebp-48h])",                        0x00514BB9, "8d45b8"),
    ("5450 push кода слота 0x4EDD7B (mov ecx,[ebp-16Ch]; push ecx)",    0x004EDD7B, "8b8d94feffff51"),
    ("5450 хвост 0x4EDD87 (… jne 0x4EDDB5)",                             0x004EDD87, "83c40485c07527"),
    ("5450 отказ 0x4EDDA4 (mov byte [ebp-121h],9)",                      0x004EDDA4, "c685dffeffff09"),
    ("5450 код пакета 0x4ED97D (mov edx,[ebp-1FEh])",                    0x004ED97D, "8b9502feffff"),
    ("5450 pUser 0x4ED9CF (mov [ebp-20Ch],eax)",                         0x004ED9CF, "8985f4fdffff"),
    ("sub_532B10 0x532B10 (push ebp; mov ebp,esp; cmp [ebp+8],1; jl; mov eax,[ebp+8]; cmp eax,[5F5EA4h])",
                                                                          0x00532B10, "558bec837d08017c128b45083b05a45e5f00"),
    ("6549 тип 204 у кода 401 0x534DDF (movzx eax,[edx+4B08h]; cmp eax,0CCh)", 0x00534DDF, "0fb682084b00003dcc000000"),
    ("6549 тип 206 у кода 363 0x534E94 (movzx ecx,[eax+43E8h]; cmp ecx,0CEh)", 0x00534E94, "0fb688e843000081f9ce000000"),
]
BOUNDARY_EXTRA = [0x00535B51, 0x005366A0, 0x00514AAA, 0x004EDDB5, 0x00535B0D, 0x00536656, 0x004EDDA4, 0x00532B10]

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
            args = struct.unpack("<%dI" % (nb // 4), uc.mem_read(esp + 4, nb)) if nb else ()
            eax = fn(uc, args, esp + 4)
            uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_ESP, esp + 4 + nb)   # __stdcall
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
            ok(cur == bytes.fromhex(o), "%-16s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        # цель E8 площадок — ровно sub_532B10
        for n, va, o in GS_SITES:
            rel = struct.unpack("<i", bytes(img[va - base + 1: va - base + 5]))[0]
            ok(va + 5 + rel == IS_FUNC, "%-16s цель call = 0x%08X (sub_532B10)" % (n, va + 5 + rel))
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- переходы/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "%-16s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref
    print("-- границы инструкций (сток)")
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "%-16s 0x%08X: начало %s, конец %s" % (n, va, s, e))
    for va in BOUNDARY_EXTRA:
        s, _ = boundary_ok(img, base, va, 1)
        ok(s, "цель перехода/отказа 0x%08X на границе инструкции" % va)
    # jcc после площадок ведут туда, куда задумано
    for va, tgt in ((0x00535B0B, 0x00535B51), (0x00536654, 0x005366A0), (0x00514A83, 0x00514AAA), (0x004EDD8C, 0x004EDDB5)):
        rel = struct.unpack("b", bytes([img[va - base + 1]]))[0]
        ok(va + 2 + rel == tgt, "jcc 0x%08X -> 0x%08X (ожид. 0x%08X)" % (va, va + 2 + rel, tgt))
    # таблица Function_Table: загрузчик пишет счётчик в 0x5F5EA4 (@0x4AFA11 mov [5F5EA4h],eax) и указатель в 0x5F5E70
    ok(bytes(img[0x4AFA10 - base: 0x4AFA10 - base + 5]) == bytes.fromhex("a3a45e5f00"), "загрузчик sub_4AF980: 0x4AFA10 mov [0x5F5EA4],eax (число записей)")
    ok(bytes(img[0x4AFAC3 - base: 0x4AFAC3 - base + 6]) == bytes.fromhex("890d705e5f00"), "загрузчик sub_4AF980: 0x4AFAC3 mov [0x5F5E70],ecx (указатель на записи 48 б)")

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    stubs, cfun = {}, {}
    # ★ fix13: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP) — имя И объект
    #   (p65_consumable_type) решают; сигнатура `push ecx/edx/ebp; push [esp+16]; push n; call` — второй метод.
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))
    NAMES = {1: "St_Bless6551", 2: "St_OptTrans6553", 3: "St_Helper5433", 4: "St_Use5450"}   # push n — исходник p65
    for n in (1, 2, 3, 4):
        c = find_all(limg, lbase, "51 52 55 ff742410 6a%02x e8" % n)
        va, good, msg = resolve(dmap, NAMES[n], "p65_consumable_type", c)
        ok(good, msg)
        ok(va is not None, "St_%d (%s): найден по MAP, кандидатов сигнатуры %d (0x%08X)" % (n, NAMES[n], len(c), va or 0))
        if va is not None:
            stubs[n] = va
            ins = disasm(limg, lbase, va, 0x20)
            mn = [i.mnemonic for i in ins[:9]]
            ok(mn == ["push", "push", "push", "push", "push", "call", "pop", "pop", "ret"], "St_%d: форма push×5; call; pop; pop; ret (%s)" % (n, " ".join(mn)))
            tgt = int(ins[5].op_str, 16) if ins[5].mnemonic == "call" and ins[5].op_str.startswith("0x") else 0
            ok(lo <= tgt < hi, "St_%d: call C-функции внутри DLL (0x%08X)" % (n, tgt))
            cfun[n] = tgt
            ok(ins[6].op_str == "edx" and ins[7].op_str == "ecx", "St_%d: pop edx; pop ecx — регистры стока восстановлены" % n)
    ok(len(set(cfun.values())) == 1, "все четыре стаба зовут одну C-функцию P65_Check (%s)" % ["0x%08X" % x for x in sorted(set(cfun.values()))])
    try:
        chk = dmap.sym("P65_Check", "p65_consumable_type")
    except ValueError as e:
        chk = None
        print("    " + str(e))
    ok(chk is not None and len(cfun) == 4 and set(cfun.values()) == {chk}, "call всех четырёх стабов → P65_Check по MAP (0x%08X)" % (chk or 0))

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функция подменена)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    RET = {1: 0x00535B06, 2: 0x0053664F, 3: 0x00514A7E, 4: 0x004EDD87}
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333, UC_X86_REG_ECX: 0xC0C0, UC_X86_REG_EDX: 0xD0D0}
    for n, stub in stubs.items():
        for verdict in (1, 0):
            seen = {}
            def fake(uc, a, sp, v=verdict, s=seen):
                s["args"] = a
                return v
            emu.fake = {cfun[n]: (12, fake)}
            emu.stops = {RET[n]}
            sp = ESP0 - 8
            code = 0x1900 + n
            mem = [(sp, struct.pack("<II", RET[n], code))]   # [esp] = адрес возврата стока, [esp+4] = code
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp})
            at = emu.run(stub, regs, mem)
            ok(at == RET[n], "St_%d (вердикт %d) -> возврат 0x%08X" % (n, verdict, RET[n]))
            ok(seen.get("args") == (n, code, FRAME), "  P65_Check(site=%d, code=0x%X, ebp=0x%X) = %s" % (n, code, FRAME, seen.get("args")))
            ok(emu.r(UC_X86_REG_EAX) == verdict, "  eax = %d" % emu.r(UC_X86_REG_EAX))
            ok(emu.r(UC_X86_REG_ESP) == sp + 4, "  esp = вход+4 (ret; аргумент cdecl снимает сток add esp,4)")
            ok(emu.r(UC_X86_REG_EBP) == FRAME and emu.r(UC_X86_REG_ECX) == 0xC0C0 and emu.r(UC_X86_REG_EDX) == 0xD0D0
               and emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333,
               "  ebp/ecx/edx/ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
