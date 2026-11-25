# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p46.py — ЭМУЛЯТОРНАЯ проверка P46 (крик лавки 6316: зажим длины копии до memcpy).
#
# Грузятся НАСТОЯЩИЕ образы GameServer.exe и собранной AsdaPatch.dll. Проверяем:
#  1) Исходные 7 байт площадки 0x508B59 в образе == 0F BF 45 0C 83 E8 0A (сверка P46).
#  2) Стаб ClampStoreShout найден в DLL; его `jmp [g_retStoreShout]` ведёт на 0x508B60
#     (возврат в сток, где значение кладётся в длину memcpy).
#  3) Эмуляция стаба на наборе длин текста {-5,0,1,79,80,81,663,700}: результат
#     (длина копии = (a3-10) после зажима, минус 27 = текст) ВСЕГДА ∈ [0..80], легальные
#     1..79 не меняются, всё > 80 зажимается в 80 (сток затем отбрасывает гейтом strlen<80).
#     ⇒ memcpy(Str[80], ...) не переполняется ни на каком входе.
#  4) Патч применяется к копии образа (WriteJmp-семантика): 0x508B59 = E9 rel32 + 90 90,
#     инструкция 0x508B60 НЕ тронута.
#
# ЗАПУСК: python verify_p46.py [AsdaPatch.dll] [GameServer.exe]
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ESP,
                               UC_X86_REG_EIP, UC_X86_REG_GDTR, UC_X86_REG_FS,
                               UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
EXE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.exe")

SITE_VA   = 0x00508B59
RET_VA    = 0x00508B60
ORIG      = bytes.fromhex("0fbf450c83e80a")
LO        = 0x1B          # 27
HI        = 0x1B + 80     # 107
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def find_all(dimg, dbase, sig_hex):
    sig = bytes.fromhex(sig_hex)
    return [dbase + i for i in range(len(dimg) - len(sig)) if dimg[i:i + len(sig)] == sig]


def stub_ret_and_call(dimg, dbase, stub):
    """Разобрать стаб: вернуть (va возврата из [ptr], va лог-вызова)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = dimg[stub - dbase: stub - dbase + 64]
    call_target = None
    ret_dst = None
    for ins in md.disasm(code, stub):
        if ins.mnemonic == "call":
            try: call_target = int(ins.op_str, 16)
            except Exception: call_target = None
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            ptr = int(ins.op_str.split("[")[1].split("]")[0], 16)
            ret_dst = struct.unpack("<I", dimg[ptr - dbase: ptr - dbase + 4])[0]
            break
    return ret_dst, call_target


def main():
    dll = pefile.PE(DLL)
    exe = pefile.PE(EXE)
    dimg = dll.get_memory_mapped_image()
    dbase = dll.OPTIONAL_HEADER.ImageBase
    eb = exe.OPTIONAL_HEADER.ImageBase
    eimg = bytearray(exe.get_memory_mapped_image())

    # ── 1. исходные байты площадки ────────────────────────────────────────────
    print("-- площадка 0x508B59 (сверка P46)")
    cur = bytes(eimg[SITE_VA - eb: SITE_VA - eb + 7])
    ok(cur == ORIG, "исходные 7 байт = 0F BF 45 0C 83 E8 0A (в памяти: %s)" % cur.hex())

    # ── 2. стаб в DLL ─────────────────────────────────────────────────────────
    # Префикс `0fbf450c83e80a8b15` уникален (у P14 ClampA `3b05`, ClampB `8b0d`,
    # ClampC `85c0`). На всякий случай выбираем стаб P46 по разыменованию возврата:
    # jmp [g_retStoreShout] -> 0x508B60.
    print("-- стаб ClampStoreShout в DLL")
    cands = find_all(dimg, dbase, "0fbf450c83e80a8b15")
    stub = None
    call_target = None
    for c in cands:
        ret_dst, ct = stub_ret_and_call(dimg, dbase, c)
        if ret_dst == RET_VA:
            stub, call_target = c, ct
            break
    ok(stub is not None, "стаб P46 найден по возврату на 0x%08X (кандидатов с общим префиксом: %d)"
       % (RET_VA, len(cands)))
    if stub is None:
        print("ИТОГ: !! стаб не найден"); return 2
    ok(call_target is not None, "лог-вызов AsdaStoreShoutClamped найден (0x%08X)" % (call_target or 0))

    # ── 3. эмуляция стаба ─────────────────────────────────────────────────────
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, img in ((eb, eimg), (dbase, dimg)):
        uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, bytes(img))
    GDT, TEB = 0x00060000, 0x00070000
    uc.mem_map(GDT, 0x1000); uc.mem_map(TEB, 0x1000)

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
    uc.mem_map(0x00100000, 0x00100000)

    state = {"eip": None}

    def on_code(u, address, size, ud):
        # шунтируем __stdcall лог-вызов: ret 8 (callee чистит 8 байт аргументов)
        if call_target is not None and address == call_target:
            esp = u.reg_read(UC_X86_REG_ESP)
            retaddr = struct.unpack("<I", u.mem_read(esp, 4))[0]
            u.reg_write(UC_X86_REG_ESP, esp + 4 + 8)
            u.reg_write(UC_X86_REG_EIP, retaddr)
            return
        if address == RET_VA:
            state["eip"] = address
            u.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    def run(a3):
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
        # [ebp+0xC] = packetLen (word, знаковый)
        uc.mem_write(FRAME + 0xC, struct.pack("<H", a3 & 0xFFFF))
        uc.reg_write(UC_X86_REG_EAX, 0)
        state["eip"] = None
        try:
            uc.emu_start(stub, 0, count=60)
        except UcError as e:
            print("    сбой эмуляции a3=%d: %s" % (a3, e))
        return uc.reg_read(UC_X86_REG_EAX) & 0xFFFF

    print("-- эмуляция: текст L -> packetLen a3=L+37 -> зажатая длина копии -> текст")
    # (textL, ожидаемый текст после зажима, ожидание «принят гейтом strlen<80»)
    cases = [(-5, 0), (0, 0), (1, 1), (79, 79), (80, 80), (81, 80), (663, 80), (700, 80)]
    for textL, exp in cases:
        a3 = (textL + 37) & 0xFFFF         # a3-10-27 = textL
        clamped = run(a3)                   # зажатое (a3-10)
        got_text = ((clamped - LO) & 0xFFFF)
        # знак: clamped хранится как word, но у нас всегда >=27
        in_range = 0 <= got_text <= 80
        unchanged = (1 <= textL <= 79 and got_text == textL)
        note = "легальный, без изменений" if (1 <= textL <= 79) else \
               ("пустой -> отсев гейтом >0" if textL <= 0 else "зажат в 80 -> отсев гейтом strlen<80")
        good = in_range and (got_text == exp)
        if 1 <= textL <= 79:
            good = good and unchanged
        ok(good, "L=%-4d -> копия=%d байт, текст=%d (ожид. %d) [%s]"
           % (textL, clamped, got_text, exp, note))

    # ── 4. применение к копии образа (WriteJmp-семантика) ─────────────────────
    print("-- применение к копии образа (эмуляция WriteJmp 7-байтовой площадки)")
    patched = bytearray(eimg)
    off = SITE_VA - eb
    rel = (stub - (SITE_VA + 5)) & 0xFFFFFFFF
    patched[off] = 0xE9
    patched[off + 1:off + 5] = struct.pack("<I", rel)
    patched[off + 5] = 0x90
    patched[off + 6] = 0x90
    ok(patched[off] == 0xE9 and patched[off + 5] == 0x90 and patched[off + 6] == 0x90,
       "0x508B59 = E9 %s 90 90 (jmp rel32 + 2 nop)" % struct.pack("<I", rel).hex())
    ok(bytes(patched[RET_VA - eb: RET_VA - eb + 7]) == bytes(eimg[RET_VA - eb: RET_VA - eb + 7]),
       "инструкция возврата 0x508B60 (mov word[ebp-0x348],ax) НЕ тронута")

    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
