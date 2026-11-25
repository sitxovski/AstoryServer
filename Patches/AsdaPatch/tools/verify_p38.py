# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p38.py — ЭМУЛЯТОРНАЯ проверка P38 (лимит мест клана: проверка сверяет прибавку +10).
#
# P38 — байтовая правка ХОСТА (0x40494D: 05 -> 0A), не трамплин в DLL, поэтому проверяем саму
# семантику гейта. Берём РЕАЛЬНУЮ последовательность гейта из живого GameServer.exe вокруг
# 0x40494B (`add ecx,imm; cmp ecx,100; jle`), подставляем imm стока (05) и патча (0A) и
# эмулируем для граничных значений текущего лимита. Контрольные пары показывают: патч
# отклоняет лимиты 91..95 (которые сток пропускал -> итог +10 = 101..105 > 100), а честный
# путь (лимит <= 90) по-прежнему проходит (90 + 10 = 100).
#
# ЗАПУСК: python verify_p38.py [GameServer.exe]
import os
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_EIP

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.exe")

GATE_VA = 0x0040494B      # add ecx,imm
IMM_VA = 0x0040494D       # байт immediate
CMP_VA = 0x0040494E       # cmp ecx,100
JLE_VA = 0x00404951       # jle +0x34
ALLOW = 0x00404987        # цель jle (расширение разрешено)
REJECT = 0x00404953       # fall-through (расширение отклонено)

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def main():
    pe = pefile.PE(EXE)
    ib = pe.OPTIONAL_HEADER.ImageBase
    img = bytearray(pe.get_memory_mapped_image())

    # сверка стоковых байт гейта
    ctx = bytes(img[0x404944 - ib:0x404944 - ib + 14])
    ok(ctx == bytes.fromhex("0fb68d65ffffff83c10583f9647e"),
       "стоковый гейт 0x404944 = movzx ecx,[ebp-0x9B]; add ecx,5; cmp ecx,100; jle")

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    size = (len(img) + 0xFFF) & ~0xFFF
    uc.mem_map(ib, size)

    # пошагово: add, cmp, jle, затем читаем EIP (развязка ALLOW/REJECT)
    def gate(imm, limit):
        img[IMM_VA - ib] = imm
        uc.mem_write(ib, bytes(img))
        uc.reg_write(UC_X86_REG_ECX, limit)
        uc.emu_start(GATE_VA, CMP_VA)                 # add ecx,imm
        uc.emu_start(CMP_VA, JLE_VA)                  # cmp ecx,100
        uc.emu_start(JLE_VA, 0, count=1)             # jle -> EIP на развязку
        return uc.reg_read(UC_X86_REG_EIP)

    print("== P38: гейт лимита клана (add ecx,imm; cmp ecx,100; jle) ==")
    # СТОК (imm=05): +5. Пропускает лимиты до 95 (баг: далее прибавляется +10 -> 105).
    ok(gate(0x05, 90) == ALLOW, "сток +5: лимит 90 -> разрешено (95<=100)")
    ok(gate(0x05, 95) == ALLOW, "сток +5: лимит 95 -> РАЗРЕШЕНО (100<=100), но реальная прибавка +10 -> 105 (баг)")
    # ПАТЧ (imm=0A): +10, как реальная прибавка.
    ok(gate(0x0A, 90) == ALLOW, "патч +10: лимит 90 -> разрешено (100<=100) — честный путь не задет")
    ok(gate(0x0A, 91) == REJECT, "патч +10: лимит 91 -> ОТКЛОНЕНО (101>100)")
    ok(gate(0x0A, 95) == REJECT, "патч +10: лимит 95 -> ОТКЛОНЕНО (105>100) — за 100 клан не уходит")
    ok(gate(0x0A, 100) == REJECT, "патч +10: лимит 100 -> ОТКЛОНЕНО (110>100)")

    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
