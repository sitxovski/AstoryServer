# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p62.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P62 SlotUniqueness (античит, волна A7, 2026-10-12):
#   уникальность пар (контейнер, слот)/uid в 5018/6549/6506/6555/6096/6112, «слот 0 ≠ слот 1» в 6067.
#
# Сервер НЕ запускается. Грузятся три образа (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и собранная
# AsdaPatch.dll. Проверяем:
#  1) исходные байты 7 площадок и «соседей» (тела стоковых отказов, замок 5018, возврат 6067, прологи sub_4D61E0/
#     sub_5646C0/sub_5324A0) в каждом образе; у каждого тела отказа — что оно шлёт ТОТ ЖЕ опкод ответа и код
#     (push <код>; … push <опкод>; call sub_4C28F0) и уходит на эпилог обработчика;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов на границе
#     инструкции;
#  3) стабы найдены в DLL по MAP компоновщика (out/AsdaPatch.map) и сверены с сигнатурой; первый `jmp dword ptr [..]`
#     каждого — слот «следующий вызов» (в образе DLL = sub_5646C0; P63 при установке кладёт туда St_Send — цепочка
#     integ2), второй — своё тело отказа; St_Fame6067 — sub_5324A0; вызовы C-функций — внутрь DLL;
#  4) unicorn: каждый стаб на подставном кадре — вердикт 0 → ХВОСТОВОЙ переход в «следующий вызов» с нетронутым стеком
#     ([esp] = адрес возврата в обработчик, те же 5 аргументов, ecx = CUserMoveManager), сток возвращается прямо в
#     обработчик ret 14h (стек сбалансирован); вердикт 1 → тело отказа с esp до push'ей; 6067 — сток GetUser,
#     user≠0 → C-функция (ebp, user), user=0 → не зовётся; eax стока сохранён.
#     Путь P62 → P63 → сток (оба вкл.) проверяет verify_p63.py (раздел «цепочка»).
# Запуск: python verify_p62.py [AsdaPatch.dll]   (образы: P62_IMG_DIR или wA7_logs/img)
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
IMG = os.environ.get("P62_IMG_DIR", r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img")
GS_IMAGES = [("сток", IMG + "/gs_stock.exe"), ("живой GameServer", IMG + "/gs_live.exe"), ("живой Indun", IMG + "/gs_indun.exe")]

CONNECT_SEND = 0x005646C0
GET_USER = 0x005324A0
GET_ITEM = 0x004D61E0
SEND_PACKET = 0x004C28F0


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


# (имя, площадка, байты, тело отказа, опкод ответа, код ответа, эпилог/выход)
HANDLERS = [
    ("5018", 0x0050E991, _call(0x0050E991, CONNECT_SEND), 0x0050E681, 0x139B, 0, 0x0050E996),
    ("6549", 0x00535202, _call(0x00535202, CONNECT_SEND), 0x005349DB, 0x1996, 2, 0x00535207),
    ("6506", 0x00501A5C, _call(0x00501A5C, CONNECT_SEND), 0x005017AB, 0x196B, 5, 0x00501A61),
    ("6555", 0x005376F3, _call(0x005376F3, CONNECT_SEND), 0x005370F8, 0x199C, 10, 0x005376F8),
    ("6096", 0x0055AE4F, _call(0x0055AE4F, CONNECT_SEND), 0x0055ACC6, 0x17D1, 7, 0x0055AE56),
    ("6112", 0x004590C7, _call(0x004590C7, CONNECT_SEND), 0x00458DF7, 0x17E1, 3, 0x004590CC),
]
SITE_6067 = ("6067", 0x0054C8E5, _call(0x0054C8E5, GET_USER))
GS_SITES = [(n, va, o) for n, va, o, *_ in HANDLERS] + [SITE_6067]
GS_NEIGHBOURS = [
    ("тело отказа 5018 0x50E681 (mov byte [ebp-48h],0; push 1; push 0)", 0x0050E681, "c645b8006a016a00"),
    ("замок 5018 0x50E672 (cmp [pUser+157h],0)",                      0x0050E672, "8b85acfeffff83b85701000000"),
    ("взвод замка 5018 0x50E6AC (mov [pUser+157h],1)",                 0x0050E6AC, "8b8dacfeffffc7815701000001000000"),
    ("тело отказа 6549 0x5349DB (mov byte [ebp-258h],2)",             0x005349DB, "c685a8fdffff02"),
    ("тело отказа 6506 0x5017AB (mov byte [ebp-A8h],5)",              0x005017AB, "c68558ffffff05"),
    ("тело отказа 6555 0x5370F8 (mov byte [ebp-60h],0Ah)",            0x005370F8, "c645a00a"),
    ("тело отказа 6096 0x55ACC6 (mov byte [ebp-3C1h],7)",             0x0055ACC6, "c6853ffcffff07"),
    ("тело отказа 6112 0x458DF7 (mov byte [ebp-B4h],3)",              0x00458DF7, "c6854cffffff03"),
    ("возврат 6067 0x54C8EA (mov [ebp-40h],eax)",                     0x0054C8EA, "8945c0"),
    ("пролог sub_4D61E0 (вещь по (контейнер, слот))",                 GET_ITEM, "558bec83ec"),
    ("пролог sub_5646C0 (отправка в DBManager)",                      CONNECT_SEND, "558bec"),
    ("пролог sub_5324A0 (GetUser)",                                   GET_USER, "558bec"),
    ("5018 запись: тип @4 тела (movzx edx,byte [ebp+ecx-148h]) 0x50D4CB", 0x0050D4CB, "0fb6940db8feffff"),
    ("6506 вид заявки [ebp-1DDh] (movzx edx,byte) 0x50122C",         0x0050122C, "0fb69523feffff"),
    ("6112 цикл до −1 (cmp dword [ebp+edx*4-CEh],-1) 0x458CAC",      0x00458CAC, "83bc9532ffffffff"),
]
BOUNDARY_EXTRA = [h[3] for h in HANDLERS] + [h[6] for h in HANDLERS] + [0x0054C8EA]

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


FN_START = {0x0050E991: 0x0050D240, 0x00535202: 0x00534640, 0x00501A5C: 0x00500F10, 0x005376F3: 0x00536EE0,
            0x0055AE4F: 0x0055A820, 0x004590C7: 0x00458A60, 0x0054C8E5: 0x0054C820}


def insn_starts(img, base, fn_start, upto):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return {i.address for i in md.disasm(bytes(img[fn_start - base: upto - base + 16]), fn_start)}


def scan_into(pe, img, base, sites):
    """Переходы/abs32 внутрь площадок. Байтовый скан .text не выровнен по инструкциям, поэтому «переход» из середины
    инструкции той же функции (например, 0x7D внутри `cmp dword [ebp-2Ch],0EA60h` @0x54C910) отбрасывается после
    сверки с линейным дизасмом функции от её пролога (FN_START)."""
    a, b = text_range(pe)
    hits = {s[0]: 0 for s in sites}
    rng = [(n, va, len(bytes.fromhex(o))) for n, va, o in sites]
    starts = {va: insn_starts(img, base, FN_START[va], va + 0x400) for n, va, o in sites if va in FN_START}
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
                    src = base + i
                    st = starts.get(va)
                    if st is not None and FN_START[va] <= src < va + 0x400 and src not in st:
                        print("    (ложный «переход» из середины инструкции @0x%08X -> 0x%08X — отброшен)" % (src, t))
                        continue
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


def disasm(img, base, va, n=0x80):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(bytes(img[va - base: va - base + n]), va))


def refuse_body_ok(img, base, body, opcode, code, exit_va):
    """Тело отказа: первая инструкция пишет код в байт кадра; дальше (в теле или на его цели jmp — LABEL_43 у 6096)
    push <опкод>, call sub_4C28F0 и выход на эпилог обработчика."""
    ins = disasm(img, base, body, 0x80)
    first = ins[0]
    code_ok = first.mnemonic == "mov" and first.op_str.startswith("byte ptr [ebp") and first.op_str.endswith(hex(code) if code >= 10 else str(code))
    saw_op = saw_send = reaches_exit = False
    chain = []
    for i in ins:
        chain.append(i)
        if i.mnemonic == "jmp" and i.op_str.startswith("0x"):
            tgt = int(i.op_str, 16)
            if tgt == exit_va:
                reaches_exit = True
                chain += disasm(img, base, exit_va, 0x60)   # у 6096 отправка живёт на LABEL_43 = exit_va
            break
        if i.mnemonic == "ret":
            break
    for i in chain:
        if i.mnemonic == "push" and i.op_str == hex(opcode):
            saw_op = True
        if i.mnemonic == "call" and i.op_str == hex(SEND_PACKET):
            saw_send = True
    return code_ok, saw_op, saw_send, reaches_exit


def find_all(img, base, sig):
    import re
    return [base + m.start() for m in re.finditer(sig, bytes(img), re.DOTALL)]


def stub_targets(img, base, va, n=0x40):
    jmps, calls, icalls = [], [], []
    for ins in disasm(img, base, va, n):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "call" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            icalls.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
            break
        if ins.mnemonic == "jmp" and ins.op_str.startswith("0x"):
            calls.append(("jmp", int(ins.op_str, 16)))
        if ins.mnemonic in ("ret", "int3"):
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


def main():
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        for n, va, o in GS_SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "P62.%-5s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        for n, va, o, body, opcode, code, exit_va in HANDLERS:
            c, so, ss, re_ = refuse_body_ok(img, base, body, opcode, code, exit_va)
            ok(c and so and ss and re_, "тело отказа %s 0x%08X: код %d=%s, push %s=%s, call sub_4C28F0=%s, выход 0x%08X=%s"
               % (n, body, code, c, hex(opcode), so, ss, exit_va, re_))
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- переходы/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "P62.%-5s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref
    print("-- границы инструкций (сток)")
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "P62.%-5s 0x%08X: начало %s, конец %s" % (n, va, s, e))
    for va in BOUNDARY_EXTRA:
        s, _ = boundary_ok(img, base, va, 1)
        ok(s, "цель перехода 0x%08X на границе инструкции" % va)
    # 5018: тело отказа идёт сразу за проверкой замка — замок к этому моменту уже взведён (0x50E6B2), снимает C-код
    ok(disasm(img, base, 0x0050E6AC, 16)[1].op_str == "dword ptr [ecx + 0x157], 1", "5018: замок «в полёте» = pUser+0x157 (взводится до нашей площадки)")

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    # P62 (integ2): pushad; push ebp; call C; mov [esp+1Ch],eax; popad; test eax,eax; jne +6; jmp [next]; add esp,18h; jmp [ref]
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X)" % (dmap.map_path, dmap.stamp or 0))
    cands = find_all(limg, lbase, rb"\x60\x55\xe8....\x89\x44\x24\x1c\x61\x85\xc0\x75\x06\xff\x25....\x83\xc4\x18\xff\x25")
    ok(len(cands) == 6, "стабов P62 (DB-send) по сигнатуре: %d (ожид. 6)" % len(cands))
    fame = find_all(limg, lbase, rb"\xff\x74\x24\x04\xff\x15....\x85\xc0\x74\x09\x60\x50\x55\xe8....\x61\xc2\x04\x00")
    va_f, good, msg = resolve(dmap, "St_Fame6067", "p62_slot_uniqueness", fame)
    ok(good, msg)
    fame = [va_f] if va_f else []
    STUB_NAME = {"5018": "St_Sell5018", "6549": "St_Extraction6549", "6506": "St_Reset6506", "6555": "St_PrimiumSum6555",
                 "6096": "St_OpenPackage6096", "6112": "St_PetUnion6112"}
    C_NAME = {"5018": "P62_OnSell5018", "6549": "P62_OnExtraction6549", "6506": "P62_OnReset6506", "6555": "P62_OnPrimiumSum6555",
              "6096": "P62_OnOpenPackage6096", "6112": "P62_OnPetUnion6112"}
    stubs, cfun, nslot = {}, {}, {}
    for n, va, o, body, opcode, code, exit_va in HANDLERS:
        a, good, msg = resolve(dmap, STUB_NAME[n], "p62_slot_uniqueness", cands)
        ok(good, msg)
        if not a:
            continue
        ins = disasm(limg, lbase, a, 0x30)
        mem_jmps = [int(i.op_str.split("[")[1].split("]")[0], 16) for i in ins if i.mnemonic == "jmp" and "dword ptr [" in i.op_str][:2]
        direct = [int(i.op_str, 16) for i in ins if i.mnemonic == "call" and i.op_str.startswith("0x")][:1]
        vals = [struct.unpack("<I", bytes(limg[s - lbase:s - lbase + 4]))[0] for s in mem_jmps]
        ok(len(vals) == 2 and vals[0] == CONNECT_SEND, "St_%s 0x%08X: jmp [слот «следующий» 0x%08X] = 0x%08X (в образе — сток sub_5646C0)"
           % (n, a, mem_jmps[0] if mem_jmps else 0, vals[0] if vals else 0))
        ok(len(vals) == 2 and vals[1] == body, "  jmp [..] отказа -> 0x%08X = тело отказа %s (0x%08X)" % (vals[1] if len(vals) > 1 else 0, n, body))
        try:
            cva = dmap.sym(C_NAME[n])
        except ValueError:
            cva = None
        ok(direct and direct[0] == cva and lo <= cva < hi, "  call %s = 0x%08X (MAP 0x%08X)" % (C_NAME[n], direct[0] if direct else 0, cva or 0))
        stubs[n] = a
        cfun[n] = direct[0] if direct else 0
        nslot[n] = mem_jmps[0] if mem_jmps else 0
    ok(len(set(nslot.values())) == 6, "у шести площадок свои слоты «следующий вызов»: %s" % sorted("0x%08X" % v for v in nslot.values()))
    ok(sorted(stubs) == sorted(h[0] for h in HANDLERS), "все 6 тел отказов покрыты своим стабом: %s" % sorted(stubs))
    for nm in ("P62_SendStubAt", "P62_SendOrigAt", "P62_ChainSend", "P62_GetSendNext"):
        ok(len(dmap.find(nm)) == 1, "общая точка P62 ↔ P63: %s есть в MAP" % nm)
    if fame:
        _, calls, ic = stub_targets(limg, lbase, fame[0])
        direct = [c for c in calls if not isinstance(c, tuple)]
        ok(ic == [GET_USER], "St_Fame6067: call [..] -> %s (сток sub_5324A0)" % ["0x%08X" % x for x in ic])
        ok(len(direct) == 1 and lo <= direct[0] < hi, "St_Fame6067: call C-функции внутри DLL (0x%08X)" % (direct[0] if direct else 0))
        stubs["6067"] = fame[0]
        cfun["6067"] = direct[0]

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    ARGS = (0x7E7, 0x71, 0x0005, 0x00150040, 77)   # opcode, len, conn, body, userNum — как сток кладёт перед call
    for n, va, o, body, opcode, code, exit_va in HANDLERS:
        if n not in stubs:
            continue
        ret_va = va + 5
        for verdict, want in ((0, ret_va), (1, body)):
            seen = {}
            def connect(uc, a, sp):
                seen["db"] = (uc.reg_read(UC_X86_REG_ECX), a)
                seen["ret"] = struct.unpack("<I", bytes(uc.mem_read(sp - 4, 4)))[0]
                seen["ebp"] = uc.reg_read(UC_X86_REG_EBP)
                return 1
            def check(uc, a, sp, v=verdict):
                seen["c"] = a
                return v
            emu.fake = {CONNECT_SEND: (20, connect), cfun[n]: (4, check)}
            emu.stops = {ret_va, body}
            sp = ESP0 - 24
            mem = [(sp, struct.pack("<I5I", ret_va, *ARGS))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0x007E0538, UC_X86_REG_EAX: 0})
            at = emu.run(stubs[n], regs, mem)
            esp_ok = emu.r(UC_X86_REG_ESP) == ESP0
            ok(at == want and esp_ok, "St_%s вердикт=%d -> 0x%08X (ожид. 0x%08X %s), esp=ESP0 (стек сбалансирован): %s"
               % (n, verdict, at or 0, want, "возврат после call" if verdict == 0 else "тело отказа", esp_ok))
            ok(seen.get("c") == (FRAME,), "  C-функция получила ebp кадра")
            if verdict == 0:
                ok(seen.get("db") == (0x007E0538, ARGS), "  сток sub_5646C0 получил ecx=CUserMoveManager и те же 5 аргументов: %s" % (seen.get("db"),))
                ok(seen.get("ret") == ret_va and seen.get("ebp") == FRAME,
                   "  хвостовой переход: сток видит адрес возврата обработчика 0x%08X и ebp кадра (как у стоковой call)" % (seen.get("ret") or 0))
            else:
                ok("db" not in seen, "  отказ: sub_5646C0 НЕ вызван")
            ok(regs_kept() and emu.r(UC_X86_REG_ECX) == 0x007E0538, "  ebx/esi/edi/ecx сохранены")

    if "6067" in stubs:
        for user_ptr in (0x00150000, 0):
            seen = {}
            def getuser(uc, a, sp, u=user_ptr):
                seen["gu"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return u
            def onfame(uc, a, sp):
                seen["f"] = a
                return 0
            emu.fake = {GET_USER: (4, getuser), cfun["6067"]: (8, onfame)}
            emu.stops = {0x0054C8EA}
            sp = ESP0 - 8
            mem = [(sp, struct.pack("<II", 0x0054C8EA, 77))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["6067"], regs, mem)
            ok(at == 0x0054C8EA and emu.r(UC_X86_REG_ESP) == ESP0, "St_Fame6067 user=0x%X -> 0x54C8EA, ret 4 (стек сбалансирован)" % user_ptr)
            ok(seen.get("gu") == (0xD00D, (77,)), "  сток GetUser получил ecx=this и userNum")
            ok(emu.r(UC_X86_REG_EAX) == user_ptr, "  eax стока (CUser*) сохранён для `mov [ebp-40h],eax`")
            if user_ptr:
                ok(seen.get("f") == (FRAME, user_ptr), "  P62_OnFame6067(ebp, user) = %s" % (tuple(hex(x) for x in seen.get("f", ())),))
            else:
                ok("f" not in seen, "  user=0 → C-функция не зовётся")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
