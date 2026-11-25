# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p43.py — ЭМУЛЯТОРНАЯ проверка P43 (потолок цены личной лавки 100млн->1млрд + защита int32).
#
# Грузятся НАСТОЯЩИЕ образы GameServer.exe и собранной AsdaPatch.dll. Проверяем:
#  1) КАПЫ: подставляем новый imm 0x3B9ACA00 (1млрд) в копию образа по 0x50338C и 0x5056D5 и
#     эмулируем сами cmp-гейты — цена 5e8 (была бы отклонена при 100млн) теперь проходит,
#     цена 1.1e9 отклоняется.
#  2) ГЕЙТЫ ПЕРЕПОЛНЕНИЯ: находим 3 стаба в DLL по сигнатуре, эмулируем imul/add на входных
#     значениях без переполнения (результат = произведение) и с переполнением (результат = 0,
#     чтобы штатная проверка «<=0» отклонила лот/покупку).
#
# ЗАПУСК: python verify_p43.py [AsdaPatch.dll] [GameServer.exe]
import os
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP,
                               UC_X86_REG_GDTR, UC_X86_REG_FS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
EXE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.exe")

NEWCAP = 0x3B9ACA00      # 1 000 000 000
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def find_sig(dimg, dbase, sig_hex):
    sig = bytes.fromhex(sig_hex)
    hits = [i for i in range(len(dimg) - len(sig)) if dimg[i:i + len(sig)] == sig]
    return dbase + hits[0] if len(hits) == 1 else None


def main():
    dll = pefile.PE(DLL)
    exe = pefile.PE(EXE)
    dimg = dll.get_memory_mapped_image()
    dbase = dll.OPTIONAL_HEADER.ImageBase
    eb = exe.OPTIONAL_HEADER.ImageBase

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    eimg = bytearray(exe.get_memory_mapped_image())
    for base, img in ((eb, eimg), (dbase, dimg)):
        uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, bytes(img))
    uc.mem_map(0x00100000, 0x00100000)
    GDT, TEB = 0x00060000, 0x00070000
    uc.mem_map(GDT, 0x1000)
    uc.mem_map(TEB, 0x1000)

    def desc(b, lim, acc, fl):
        return struct.pack("<Q", (lim & 0xFFFF) | ((b & 0xFFFFFF) << 16) | (acc << 40)
                           | (((lim >> 16) & 0xF) << 48) | (fl << 52) | (((b >> 24) & 0xFF) << 56))
    gdt = b"\0" * 8 + desc(0, 0xFFFFF, 0x9A, 0xC) + desc(0, 0xFFFFF, 0x92, 0xC) + desc(TEB, 0xFFF, 0x92, 0x4)
    uc.mem_write(GDT, gdt)
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_FS, 3 << 3)
    for r in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
        uc.reg_write(r, 2 << 3)

    FRAME = 0x001E0000
    stop = {"eip": None}

    def stopper(u, a, s, d):
        stop["eip"] = a
        u.emu_stop()

    # ── 1. КАПЫ ──────────────────────────────────────────────────────────────
    # ставим новый imm в образ и эмулируем cmp-гейты
    def patch_cap(imm_va):
        uc.mem_write(imm_va, struct.pack("<I", NEWCAP))

    # Open: cmp [ebp-0x464], cap; jg 0x5033A5(reject).  price в [ebp-0x464].
    def open_gate(price):
        uc.mem_write(FRAME - 0x464, struct.pack("<i", price))
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
        stop["eip"] = None
        h = [uc.hook_add(UC_HOOK_CODE, stopper, begin=d, end=d) for d in (0x005033A5, 0x00503392)]
        try:
            uc.emu_start(0x00503386, 0, count=4)
        except UcError:
            pass
        [uc.hook_del(x) for x in h]
        return stop["eip"] != 0x005033A5      # True = прошло (не reject)

    # Buy: cmp [ebp-0x170], cap; jle 0x505746(OK) else reject.  total в [ebp-0x170].
    def buy_gate(total):
        uc.mem_write(FRAME - 0x170, struct.pack("<i", total))
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
        stop["eip"] = None
        h = [uc.hook_add(UC_HOOK_CODE, stopper, begin=d, end=d) for d in (0x00505746, 0x005056DB)]
        try:
            uc.emu_start(0x005056CF, 0, count=4)
        except UcError:
            pass
        [uc.hook_del(x) for x in h]
        return stop["eip"] == 0x00505746      # True = прошло

    print("-- капы (imm 0x3B9ACA00 = 1 млрд)")
    patch_cap(0x0050338C)
    patch_cap(0x005056D5)
    ok(open_gate(500000000), "открытие: цена 5e8 проходит (при 100млн была бы отклонена)")
    ok(open_gate(1000000000), "открытие: цена 1e9 проходит (= потолок)")
    ok(not open_gate(1100000000), "открытие: цена 1.1e9 отклоняется (> потолка)")
    ok(buy_gate(1000000000), "покупка: сумма лота 1e9 проходит (= потолок)")
    ok(not buy_gate(1100000000), "покупка: сумма лота 1.1e9 отклоняется (> потолка)")

    # ── 2. ГЕЙТЫ ПЕРЕПОЛНЕНИЯ ────────────────────────────────────────────────
    def run_mul(stub, resume, regs, mems):
        for r, v in regs.items():
            uc.reg_write(r, v & 0xFFFFFFFF)
        for off, v in mems.items():
            uc.mem_write(FRAME + off, struct.pack("<I", v & 0xFFFFFFFF))
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
        stop["eip"] = None
        h = uc.hook_add(UC_HOOK_CODE, stopper, begin=resume, end=resume)
        try:
            uc.emu_start(stub, 0, count=20)
        except UcError as e:
            print("    сбой: %s" % e)
        uc.hook_del(h)

    print("-- гейт переполнения G1 (открытие: v27 = кол-во×цена, imul ecx,[ebp+eax-0x44c])")
    stub = find_sig(dimg, dbase, "0faf8c05b4fbffff71")
    ok(stub is not None, "стаб StubOpenMul найден")
    if stub:
        run_mul(stub, 0x00503340, {UC_X86_REG_EAX: 0, UC_X86_REG_ECX: 1000}, {-0x44c: 1000})
        ok(uc.reg_read(UC_X86_REG_ECX) == 1000000, "без переполнения: v27 = 1000×1000 = 1e6")
        run_mul(stub, 0x00503340, {UC_X86_REG_EAX: 0, UC_X86_REG_ECX: 1000000000}, {-0x44c: 5})
        ok(uc.reg_read(UC_X86_REG_ECX) == 0, "переполнение (1e9×5=5e9): v27 обнулён -> штатный отказ v27<=0")

    print("-- гейт переполнения G2 (покупка: v80 = кол-во×цена, imul edx,[ebp-0x364])")
    stub = find_sig(dimg, dbase, "0faf959cfcffff71")
    ok(stub is not None, "стаб StubBuyMul1 найден")
    if stub:
        run_mul(stub, 0x00505690, {UC_X86_REG_EDX: 2}, {-0x364: 500000000})
        ok(uc.reg_read(UC_X86_REG_EDX) == 1000000000, "без переполнения: v80 = 2×5e8 = 1e9")
        run_mul(stub, 0x00505690, {UC_X86_REG_EDX: 5}, {-0x364: 1000000000})
        ok(uc.reg_read(UC_X86_REG_EDX) == 0, "переполнение (5×1e9=5e9): v80 обнулён -> отказ v80<=0")

    print("-- гейт переполнения G3 (покупка: v44 += кол-во×цена, imul+add)")
    stub = find_sig(dimg, dbase, "0faf959cfcffff70")
    ok(stub is not None, "стаб StubBuyMul2 найден")
    if stub:
        run_mul(stub, 0x005056B7, {UC_X86_REG_EDX: 1}, {-0x364: 1000000000, -0x4e4: 0})
        ok(uc.reg_read(UC_X86_REG_EDX) == 1000000000, "без переполнения: v44 = 1×1e9 + 0 = 1e9")
        run_mul(stub, 0x005056B7, {UC_X86_REG_EDX: 5}, {-0x364: 1000000000, -0x4e4: 0})
        ok(uc.reg_read(UC_X86_REG_EDX) == 0, "переполнение imul (5×1e9): v44 обнулён")
        run_mul(stub, 0x005056B7, {UC_X86_REG_EDX: 1}, {-0x364: 1000000000, -0x4e4: 1500000000})
        ok(uc.reg_read(UC_X86_REG_EDX) == 0, "переполнение add (1e9+1.5e9=2.5e9): v44 обнулён -> отказ v44<=0")

    # ── СРЕДН-3: гейт переполнения денег ПРОДАВЦА (StubSellerCap @0x505BD3) ──
    print("-- гейт денег продавца (зачисление v44 не переполняет i32)")
    seller = {"gold": 0}
    MGRV = 0x30000000

    def money_hook(u, a, s, d):
        if a != 0x004D7690:                # thiscall(mgr, num) -> gold, ret 4
            return
        esp = u.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
        u.reg_write(UC_X86_REG_EAX, seller["gold"] & 0xFFFFFFFF)
        u.reg_write(UC_X86_REG_ESP, esp + 4 + 4)
        u.reg_write(UC_X86_REG_EIP, ret)
    mh = uc.hook_add(UC_HOOK_CODE, money_hook)

    stub = find_sig(dimg, dbase, "608b851cfbffff")   # pushad; mov eax,[ebp-0x4e4]
    ok(stub is not None, "стаб StubSellerCap найден")
    if stub:
        def seller_gate(gold, v44):
            seller["gold"] = gold
            uc.mem_write(FRAME - 0x53c, struct.pack("<I", MGRV))     # mgr
            uc.mem_write(FRAME - 0x490, struct.pack("<H", 9))         # номер продавца
            uc.mem_write(FRAME - 0x4e4, struct.pack("<i", v44))       # v44
            uc.mem_write(FRAME - 0x168, b"\0")                        # код = 0
            uc.mem_write(FRAME - 0x4f8, struct.pack("<i", 0))         # v39 = 0
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
            stop["eip"] = None
            h = [uc.hook_add(UC_HOOK_CODE, stopper, begin=d, end=d) for d in (0x00505C19, 0x00505BDC)]
            try:
                uc.emu_start(stub, 0, count=100000)
            except UcError as e:
                print("    сбой seller: %s" % e)
            [uc.hook_del(x) for x in h]
            code = uc.mem_read(FRAME - 0x168, 1)[0]
            v39 = struct.unpack("<i", uc.mem_read(FRAME - 0x4f8, 4))[0]
            return stop["eip"], code, v39
        # продавец с малым золотом: 1e9 помещается -> покупка идёт
        eip, code, v39 = seller_gate(100000000, 1000000000)
        ok(eip == 0x00505C19 and v39 == 0, "продавец 1e8 + лот 1e9 = 1.1e9 <= INT_MAX -> покупка идёт")
        # продавец у предела: +1e9 переполнит -> штатный отказ 6310 код 6
        eip, code, v39 = seller_gate(2000000000, 1000000000)
        ok(eip == 0x00505BDC and code == 6 and v39 == 1,
           "продавец 2e9 + лот 1e9 = 3e9 > INT_MAX -> отказ 6310 код 6 (v39=1)")
    uc.hook_del(mh)

    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
