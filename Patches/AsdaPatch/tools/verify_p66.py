# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p66.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P66 PositionGuard (античит, волна A7, 2026-10-12):
#   5012 подбор (серверная клетка против клетки предмета; возврат снятого предмета на ветках отказа),
#   5427 зов друга (ожидание из доставки 5236, клетка партнёра, гейт), 6093 воскрешение (предложение sub_52B070
#   помнится, цель = отправитель), 5428 конец копания (старт 5028/5429, состояние 4024, MinDigMs).
#
# Сервер НЕ запускается. Грузятся настоящие образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) исходные байты всех площадок и «соседей» (адреса возврата/перехода стабов, прологи стоковых целей) в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов
#     начинаются/кончаются на границе инструкции; строки стоковых отказов на месте;
#  3) стабы найдены в DLL по сигнатурам; каждый `jmp/call dword ptr [..]` разыменован и ведёт туда, куда задумано;
#     вызовы C-функций — внутрь DLL;
#  4) unicorn: каждый стаб исполняется на подставном кадре (C-функции и серверные функции — заглушки): ветки
#     пропуск/отказ (переход в стоковое тело), баланс стека, сохранность регистров, раскладка аргументов стока.
# Запуск: python verify_p66.py [AsdaPatch.dll]   (образы: P66_IMG_DIR или пути из §1 брифа)
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
IMG = os.environ.get("P66_IMG_DIR") or r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
GS_IMAGES = [("сток", IMG + "/gs_stock.exe"), ("живой GameServer", IMG + "/gs_live.exe"), ("живой Indun", IMG + "/gs_indun.exe")]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


GS_SITES = [
    ("P66.pick",       0x004D465A, _call(0x004D465A, 0x0056BD0A)),   # call abs (первый), CharItemPicking
    ("P66.label103",   0x004D5999, "c6854cffffff00"),                 # LABEL_103: mov byte [ebp-0B4h],0
    ("P66.recall5427", 0x0052BBF5, _call(0x0052BBF5, 0x004221D0)),   # call sub_4221D0 (границы клетки пакета)
    ("P66.offer5236",  0x0049ED38, _call(0x0049ED38, 0x004C28F0)),   # доставка 5236 партнёру (sub_49EB60)
    ("P66.resOffer",   0x0052B0CC, _call(0x0052B0CC, 0x004C28F0)),   # предложение 6093 (sub_52B070)
    ("P66.resConfirm", 0x0052B1AC, _call(0x0052B1AC, 0x0052B1C0)),   # call CharRegenSelfPosition (6093)
    ("P66.digStart",   0x004D9BEB, _call(0x004D9BEB, 0x005646C0)),   # 5429 на NpcServer (5028, лопата)
    ("P66.digEnd",     0x00546B21, _call(0x00546B21, 0x005324A0)),   # call sub_5324A0 (5428)
]
GS_NEIGHBOURS = [
    ("ret pick 0x4D465F (add esp,4)",                 0x004D465F, "83c404"),
    ("стоковая проверка 7 клеток 0x4D468A",           0x004D468A, "83f8077d0c"),
    ("ret label103 0x4D59A0 (push 1; push 0)",        0x004D59A0, "6a016a00"),
    ("LABEL_103 push 0x1395 (5013) 0x4D59B2",         0x004D59B2, "6895130000"),
    ("LABEL_104 call sub_41EFD0 0x4D59F8",            0x004D59F8, _call(0x004D59F8, 0x0041EFD0)),
    ("ret recall5427 0x52BBFA (test eax; jne)",       0x0052BBFA, "85c07516"),
    ("5427 стоковая ветка отказа 0x52BBFE",           0x0052BBFE, "6850a359006a02"),
    ("5427 запись клетки CUser+0x54E6 0x52BF4B",      0x0052BF4B, "668b82e6540000"),
    ("ret offer5236 0x49ED3D",                        0x0049ED3D, "8b4df0"),
    ("5236 push 0x1474; mov edx,[ebp-44h] 0x49ED2D",  0x0049ED2D, "68741400008b55bc"),
    ("ret resOffer 0x52B0D1 (эпилог ret 10h)",        0x0052B0D1, "8be55dc21000"),
    ("sub_52B070 запись типа [ebp-4] 0x52B094",       0x0052B094, "8855fc"),
    ("ret resConfirm 0x52B1B1 (эпилог ret 8)",        0x0052B1B1, "8be55dc20800"),
    ("6093 вызов sub_4CB030 (мёртв) 0x52B185",        0x0052B185, _call(0x0052B185, 0x004CB030)),
    ("ret digStart 0x4D9BF0 (jmp эпилог)",            0x004D9BF0, "e90e0d0000"),
    ("5028 push 0x1535 (5429) 0x4D9BE1",              0x004D9BE1, "6835150000"),
    ("ret digEnd 0x546B26 (mov [ebp-424h],eax)",      0x00546B26, "8985dcfbffff"),
    ("5428 ветка Exception Error 0x546ADD",           0x00546ADD, "68b4cc59006800040000"),
    ("5428 обнуление CUser+0x54E4 0x546B40",          0x00546B40, "66c780e45400000000"),
    ("abs 0x56BD0A (mov eax,[esp+4])",                0x0056BD0A, "8b44240485c07d02f7d8c3"),
    ("sub_4221D0 пролог",                             0x004221D0, "558bec"),
    ("sub_4C28F0 пролог",                             0x004C28F0, "558bec81ecd4020000"),
    ("sub_52B1C0 пролог",                             0x0052B1C0, "558bec"),
    ("sub_5646C0 пролог",                             0x005646C0, "558bec81ec50030000"),
    ("sub_5324A0 пролог",                             0x005324A0, "558bec"),
    # [fix13] гейт 5427 читает поля стокового sub_52BFF0 сам (функция шлёт 6001) — опоры всех 5 чтений:
    ("sub_4CB030 мёртв: mov edx,[ecx+4Fh] 0x4CB05D",  0x004CB05D, "8b514f"),
    ("sub_52BFF0 код 2: cmp [eax+145h],0 0x52C070",   0x0052C070, "83b84501000000"),
    ("sub_52BFF0 код 3: cmp [ecx+15Fh],0 0x52C0A6",   0x0052C0A6, "83b95f01000000"),
    ("sub_52BFF0 код 4: cmp [edx+14Dh],0 0x52C0DC",   0x0052C0DC, "83ba4d01000000"),
    ("sub_52BFF0 код 5: movzx [eax+3F6B4h] 0x52C10F", 0x0052C10F, "0fb688b4f60300"),
    ("sub_52BFF0 шлёт 6001 и при коде 0 (push 1771h) 0x52C154", 0x0052C154, "6871170000"),
    # [fix13] LOOT-2, ветка «iAmount <= 0»: предикаты кода, таблица предметов и её поля, сверка количества и лог ветки
    ("sub_532A90 cmp [ebp+8],5047h 0x532A93",         0x00532A93, "817d0847500000"),
    ("sub_532B10 cmp [ebp+8],1 0x532B13",             0x00532B13, "837d0801"),
    ("sub_532B30 cmp [ebp+8],7D1h 0x532B34",          0x00532B34, "817d08d1070000"),
    ("5012 sub edx,5047h; imul 47h 0x4D530E",         0x004D530E, "81ea475000006bd247"),
    ("5012 mov eax,[5F5E98h] 0x4D5317",               0x004D5317, "a1985e5f00"),
    ("5012 таблица +7 0x4D531C",                      0x004D531C, "0fb64c1007"),
    ("5012 таблица +24h 0x4D533E",                    0x004D533E, "0fb64c1024"),
    ("5012 таблица +23h 0x4D5360",                    0x004D5360, "0fb64c1023"),
    ("5012 таблица +1Ah 0x4D5381",                    0x004D5381, "0fb64c101a"),
    ("5012 ветка 84269: 5015 sub_4211F0 0x4D54F3",    0x004D54F3, _call(0x004D54F3, 0x004211F0)),
    ("5012 ветка 84269: mov eax,[ebp-557h] 0x4D54F8", 0x004D54F8, "8b85a9faffff"),
    ("5012 ветка 84269: jmp LABEL_103 0x4D5518",      0x004D5518, "e97c040000"),
    ("sub_41EFD0 (возврат предмета) пролог",          0x0041EFD0, "558bec"),
]
BOUNDARY_EXTRA = [0x004D465F, 0x004D59A0, 0x0052BBFA, 0x0052BBFE, 0x0049ED3D, 0x0052B0D1, 0x0052B1B1, 0x004D9BF0, 0x00546B26, 0x00546ADD]
STRINGS = [
    (0x0059A350, b"if( !m_pcThread->m_cMapMng->IsCheckPosInMaxPos(sJump.iMovePosX, sJump.iMovePosZ) )"),
    (0x0059CCB4, b"MOVE :: CharEMotion_MiningEnd() Exception Error"),
    (0x00592558, b"CharItemPicking()"),
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


def no_gate_refs(dmap, limg, lbase, obj, ok):
    """[fix13] Код объекта obj не ссылается на стоковый sub_52BFF0 (он шлёт клиенту 6001 даже при коде 0):
    в границах функций .text объекта (по MAP) нет imm32 0x0052BFF0 (так компилятор кладёт адрес функции-указателя)."""
    from asdamap import DllMap
    allsyms = dmap.syms
    hits, funcs = [], 0
    for i, (va, dec, o) in enumerate(allsyms):
        if obj.lower() not in o.lower():
            continue
        end = allsyms[i + 1][0] if i + 1 < len(allsyms) else va
        if not (lbase <= va < lbase + len(limg)) or end <= va or end - va > 0x4000:
            continue
        funcs += 1
        blob = bytes(limg[va - lbase: end - lbase])
        if b"\xf0\xbf\x52\x00" in blob:
            hits.append(DllMap._plain(dec))
    ok(funcs > 0 and not hits, "%s: символов проверено %d, ссылок на sub_52BFF0 (imm32 0x0052BFF0) нет%s" % (obj, funcs, (" — ЕСТЬ в " + ", ".join(hits)) if hits else ""))


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


def stub_targets(img, base, va):
    """call rel32 -> цели (E8); jmp/call dword ptr [p] -> *p (в порядке встречи) до первого int3/ret-хвоста."""
    jmps, calls, icalls = [], [], []
    seen_ret = 0
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "call" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            icalls.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "int3":
            break
        if ins.mnemonic == "ret":
            seen_ret += 1
            if seen_ret >= 2:
                break
    return jmps, calls, icalls


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

    def rd(self, addr, n=4):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0] if n == 4 else bytes(self.uc.mem_read(addr, n))


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
        for va, s in STRINGS:
            cur = bytes(img[va - base: va - base + len(s) + 1])
            ok(cur == s + b"\0", "строка стока 0x%08X: %r" % (va, cur[:-1]))
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
        ok(s, "цель перехода 0x%08X на границе инструкции" % va)
    # Все переходы на LABEL_103 ведут на её ПЕРВЫЙ байт (площадка 7 б занята jmp)
    cnt = 0
    a, b = text_range(pe)
    for i in range(a, b - 6):
        o = img[i]
        t = None
        if o == 0xEB or 0x70 <= o <= 0x7F:
            t = base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0]
        elif o == 0xE9:
            t = base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0]
        elif o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            t = base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0]
        if t == 0x004D5999:
            cnt += 1
    ok(cnt >= 20, "переходов на LABEL_103 0x4D5999 (первый байт): %d" % cnt)

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)

    def find_with_tail(head, tail_off, tail):
        return [a for a in find_all(limg, lbase, head) if bytes(limg[a - lbase + tail_off: a - lbase + tail_off + len(bytes.fromhex(tail))]) == bytes.fromhex(tail)]

    # ★ integ2b: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP): сигнатура St_DigEnd5428
    #   совпала с 6 стабами того же вида других патчей (P60/P62/P63/P65/P67…) — брался чужой (тело отказа 6521 P60).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X)" % (dmap.map_path, dmap.stamp or 0))

    def by_map(name, cands):
        va, good, msg = resolve(dmap, name, "p66_position_guard", cands)
        ok(good, msg)
        return va

    stubs = {}
    c = find_with_tail("ff742404ff15", 10, "83c4046055e8"); stubs["St_Pick5012"] = by_map("St_Pick5012", c)
    c = find_with_tail("6055e8", 7, "61c6854cffffff00ff25"); stubs["St_Refuse5012"] = by_map("St_Refuse5012", c)
    c = find_with_tail("ff742408ff742408ff15", 14, "85c074"); stubs["St_Recall5427"] = by_map("St_Recall5427", c)
    c = find_with_tail("ff742418" * 6 + "ff15", 30, "6055e8"); ok(len(c) == 2, "St_Recall5236 / St_ResOffer6093 (одна форма, 6 аргументов): кандидатов %d" % len(c))
    stubs["St_Six_A"], stubs["St_Six_B"] = by_map("St_Recall5236", c), by_map("St_ResOffer6093", c)
    c = [a for a in find_with_tail("6055e8", 7, "85c075") if bytes(limg[a - lbase + 11: a - lbase + 16]) == bytes.fromhex("61ff742410")]; stubs["St_ResConfirm6093"] = by_map("St_ResConfirm6093", c)
    c = find_with_tail("ff742414" * 5 + "ff15", 26, "6055e8"); stubs["St_DigStart5028"] = by_map("St_DigStart5028", c)
    c = find_with_tail("ff742404ff15", 10, "85c074"); stubs["St_DigEnd5428"] = by_map("St_DigEnd5428", c)

    expect_jmp = {"St_Pick5012": [0x004D5999], "St_Refuse5012": [0x004D59A0], "St_DigEnd5428": [0x00546ADD]}
    expect_icall = {"St_Pick5012": [0x0056BD0A], "St_Recall5427": [0x004221D0], "St_Six_A": [0x004C28F0], "St_Six_B": [0x004C28F0],
                    "St_ResConfirm6093": [0x0052B1C0], "St_DigStart5028": [0x005646C0], "St_DigEnd5428": [0x005324A0]}
    cfun = {}
    for k, a in stubs.items():
        if a is None:
            continue
        jmps, calls, icalls = stub_targets(limg, lbase, a)
        if k in expect_jmp:
            ok(jmps[:len(expect_jmp[k])] == expect_jmp[k], "%s: jmp [..] -> %s (ожид. %s)" % (k, ["0x%08X" % x for x in jmps], ["0x%08X" % x for x in expect_jmp[k]]))
        if k in expect_icall:
            ok(icalls[:1] == expect_icall[k], "%s: call [..] -> %s (сток %s)" % (k, ["0x%08X" % x for x in icalls], ["0x%08X" % x for x in expect_icall[k]]))
        ok(len(calls) == 1 and lo <= calls[0] < hi, "%s: call C-функции внутри DLL (0x%08X)" % (k, calls[0] if calls else 0))
        if calls:
            cfun[k] = calls[0]
    ok(cfun.get("St_Six_A") != cfun.get("St_Six_B"), "6-аргументные стабы зовут РАЗНЫЕ C-функции (5236 / предложение 6093)")
    no_gate_refs(dmap, limg, lbase, "p66_position_guard", ok)

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    # St_Pick5012: [esp]=ret 0x4D465F, [esp+4]=arg (−5); сток abs настоящий (0x56BD0A в образе)
    if stubs.get("St_Pick5012"):
        for verdict, want in ((0, 0x004D465F), (1, 0x004D5999)):
            seen = {}
            def onpick(uc, a, sp, v=verdict):
                seen["pick"] = a
                return v
            emu.fake = {cfun["St_Pick5012"]: (4, onpick)}
            emu.stops = {0x004D465F, 0x004D5999}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<Ii", 0x004D465F, -5))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Pick5012"], regs, mem)
            want_esp = ESP0 - 4 if verdict == 0 else ESP0
            ok(at == want and emu.r(UC_X86_REG_ESP) == want_esp, "St_Pick5012 вердикт=%d -> 0x%08X (ожид. 0x%08X), esp %s" % (verdict, at or 0, want, "как у стока" if emu.r(UC_X86_REG_ESP) == want_esp else "НЕ сошёлся"))
            ok(seen.get("pick") == (FRAME,), "  P66_OnPick5012 получил ebp кадра")
            if verdict == 0:
                ok(emu.r(UC_X86_REG_EAX) == 5, "  пропуск: eax = abs(−5) = %d (сток abs выполнен)" % emu.r(UC_X86_REG_EAX))
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_Refuse5012: вытеснен mov byte [ebp-0B4h],0
    if stubs.get("St_Refuse5012"):
        seen = {}
        def onref(uc, a, sp):
            seen["ref"] = a
            return 0
        emu.fake = {cfun["St_Refuse5012"]: (4, onref)}
        emu.stops = {0x004D59A0}
        mem = [(FRAME - 0xB4, b"\x05")]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: 0x4444})
        at = emu.run(stubs["St_Refuse5012"], regs, mem)
        ok(at == 0x004D59A0 and emu.r(UC_X86_REG_ESP) == ESP0, "St_Refuse5012 -> 0x4D59A0, стек сбалансирован")
        ok(seen.get("ref") == (FRAME,), "  P66_OnPickRefuse5012 получил ebp кадра")
        ok(emu.rd(FRAME - 0xB4, 1) == b"\x00", "  вытесненное mov byte [ebp-0B4h],0 выполнено")
        ok(emu.r(UC_X86_REG_EAX) == 0x4444 and regs_kept(), "  eax/ebx/esi/edi сохранены")

    # St_Recall5427: ecx=mapMgr, [esp+4]=x, [esp+8]=z; сток 0x4221D0 (thiscall, ret 8)
    if stubs.get("St_Recall5427"):
        for stock_r, verdict, want_eax in ((1, 0, 1), (1, 1, 0), (0, 9, 0)):
            seen = {}
            def tile(uc, a, sp, r=stock_r):
                seen["tile"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return r
            def onrecall(uc, a, sp, v=verdict):
                seen["recall"] = a
                return v
            emu.fake = {0x004221D0: (8, tile), cfun["St_Recall5427"]: (4, onrecall)}
            emu.stops = {0x0052BBFA}
            sp = ESP0 - 12
            mem = [(sp, struct.pack("<III", 0x0052BBFA, 120, 130))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0x5555})
            at = emu.run(stubs["St_Recall5427"], regs, mem)
            ok(at == 0x0052BBFA and emu.r(UC_X86_REG_ESP) == ESP0 and emu.r(UC_X86_REG_EAX) == want_eax,
               "St_Recall5427 сток=%d вердикт=%d -> 0x52BBFA, eax=%d (ожид. %d), стек сбалансирован (ret 8)" % (stock_r, verdict, emu.r(UC_X86_REG_EAX), want_eax))
            ok(seen.get("tile") == (0xD00D, (120, 130)), "  сток sub_4221D0 получил ecx=mapMgr и те же (x, z)")
            if stock_r:
                ok(seen.get("recall") == (FRAME,), "  P66_OnRecall5427 получил ebp кадра")
            else:
                ok("recall" not in seen, "  сток отказал → P66 не зовётся")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # Шестиаргументные стабы (5236 / предложение 6093): ecx=net, 6 аргументов, сток 0x4C28F0 (ret 18h)
    for k, retva in (("St_Six_A", 0x0049ED3D), ("St_Six_B", 0x0049ED3D)):
        if not stubs.get(k):
            continue
        seen = {}
        def send(uc, a, sp):
            seen["send"] = (uc.reg_read(UC_X86_REG_ECX), a)
            return 0x77
        def onc(uc, a, sp):
            seen["c"] = a
            return 0
        emu.fake = {0x004C28F0: (24, send), cfun[k]: (4, onc)}
        emu.stops = {retva}
        sp = ESP0 - 28
        mem = [(sp, struct.pack("<IIIIIII", retva, 0x1474, 0x2A, 77, 0x00120034, 0, 1))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
        at = emu.run(stubs[k], regs, mem)
        ok(at == retva and emu.r(UC_X86_REG_ESP) == ESP0, "%s -> 0x%08X, стек сбалансирован (ret 18h)" % (k, retva))
        ok(seen.get("send") == (0xD00D, (0x1474, 0x2A, 77, 0x00120034, 0, 1)), "  сток sub_4C28F0 получил ecx=net и 6 аргументов в том же порядке")
        ok(seen.get("c") == (FRAME,), "  C-функция получила ebp кадра")
        ok(emu.r(UC_X86_REG_EAX) == 0x77 and regs_kept(), "  результат стока в eax, ebx/esi/edi сохранены")

    # St_ResConfirm6093: ecx=this, 4 аргумента; проверка ДО стока 0x52B1C0 (ret 10h)
    if stubs.get("St_ResConfirm6093"):
        for verdict in (0, 1):
            seen = {}
            def regen(uc, a, sp):
                seen["regen"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return 1
            def onconf(uc, a, sp, v=verdict):
                seen["conf"] = a
                return v
            emu.fake = {0x0052B1C0: (16, regen), cfun["St_ResConfirm6093"]: (4, onconf)}
            emu.stops = {0x0052B1B1}
            sp = ESP0 - 20
            mem = [(sp, struct.pack("<IIIII", 0x0052B1B1, 9, 2, 7, 50))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0x5555})
            at = emu.run(stubs["St_ResConfirm6093"], regs, mem)
            ok(at == 0x0052B1B1 and emu.r(UC_X86_REG_ESP) == ESP0, "St_ResConfirm6093 вердикт=%d -> 0x52B1B1, стек сбалансирован (ret 10h)" % verdict)
            ok(seen.get("conf") == (FRAME,), "  P66_OnResConfirm6093 получил ebp кадра")
            if verdict == 0:
                ok(seen.get("regen") == (0xD00D, (9, 2, 7, 50)) and emu.r(UC_X86_REG_EAX) == 1, "  пропуск: сток CharRegenSelfPosition получил ecx и 4 аргумента, eax = его результат")
            else:
                ok("regen" not in seen and emu.r(UC_X86_REG_EAX) == 0, "  отказ: сток НЕ вызван, eax=0 (стоковый эпилог вернёт 0)")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_DigStart5028: ecx=0x7E0538, 5 аргументов, сток 0x5646C0 (ret 14h)
    if stubs.get("St_DigStart5028"):
        seen = {}
        def csend(uc, a, sp):
            seen["send"] = (uc.reg_read(UC_X86_REG_ECX), a)
            return 1
        def onstart(uc, a, sp):
            seen["start"] = a
            return 0
        emu.fake = {0x005646C0: (20, csend), cfun["St_DigStart5028"]: (4, onstart)}
        emu.stops = {0x004D9BF0}
        sp = ESP0 - 24
        mem = [(sp, struct.pack("<IIIIII", 0x004D9BF0, 0x1535, 10, 3, 0x00120034, 77))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x007E0538})
        at = emu.run(stubs["St_DigStart5028"], regs, mem)
        ok(at == 0x004D9BF0 and emu.r(UC_X86_REG_ESP) == ESP0, "St_DigStart5028 -> 0x4D9BF0, стек сбалансирован (ret 14h)")
        ok(seen.get("send") == (0x007E0538, (0x1535, 10, 3, 0x00120034, 77)), "  сток sub_5646C0 получил ecx и 5 аргументов в том же порядке")
        ok(seen.get("start") == (FRAME,), "  P66_OnDigStart5028 получил ebp кадра")
        ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_DigEnd5428: ecx=mgr, [esp+4]=userNum; сток 0x5324A0 (ret 4) → user; C(user, ebp)
    if stubs.get("St_DigEnd5428"):
        for user, verdict, want in ((0x00150000, 0, 0x00546B26), (0x00150000, 1, 0x00546ADD), (0, 9, 0x00546B26)):
            seen = {}
            def getuser(uc, a, sp, u=user):
                seen["get"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return u
            def onend(uc, a, sp, v=verdict):
                seen["end"] = a
                return v
            emu.fake = {0x005324A0: (4, getuser), cfun["St_DigEnd5428"]: (8, onend)}
            emu.stops = {0x00546B26, 0x00546ADD}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<II", 0x00546B26, 77))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0x5555})
            at = emu.run(stubs["St_DigEnd5428"], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "St_DigEnd5428 user=0x%X вердикт=%d -> 0x%08X (ожид. 0x%08X), стек сбалансирован" % (user, verdict, at or 0, want))
            ok(seen.get("get") == (0xD00D, (77,)), "  сток sub_5324A0 получил ecx=mgr и userNum")
            if user:
                ok(seen.get("end") == (user, FRAME), "  P66_OnDigEnd5428(user, ebp) = %s" % (tuple(hex(x) for x in seen.get("end", ())),))
                if verdict == 0:
                    ok(emu.r(UC_X86_REG_EAX) == user, "  пропуск: eax = user (как сток)")
            else:
                ok("end" not in seen and emu.r(UC_X86_REG_EAX) == 0, "  user не найден → P66 не зовётся, eax=0 как у стока")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
