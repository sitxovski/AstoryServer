# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n18.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны N18 (2026-10-15): знаковые сравнения такта в NpcServer
#   (остаток аудита audit_signed_tick_20261015.md после N17): Г1 навыки соулмейта (jl→jb), Г2 событие «1000 предметов»
#   (jle/jg → je/jne, jge → jae, и три площадки СВЕРХ аудита «cmp метка,такт; ja» → «cmp такт,метка; js»),
#   Г3 действие 6 ATTACK_WAIT (стаб + jl→jb, площадка не сплошная).
# Сервер НЕ запускается. Образы только читаются.
#   1. Три образа NpcServer (сток 16c7a0af, живой c02486d6, Indun 0de2c559): байты всех площадок (таблица kAreas
#      читается ПРЯМО из n18_tick_signed.cpp и сверяется с таблицей скрипта), границы инструкций, дизасм ДО и ПОСЛЕ
#      правки (длины инструкций не меняются), флаги после каждого перевёрнутого перехода не читает никто (оба пути),
#      ebx/edi = 0 на площадках «метка ≠ 0», для трёх площадок «js»: ModRM-доказательство перестановки операндов и
#      провенанс регистров (метка ← mov R,[47D2BCh]; такт ← mov R,eax сразу после call [GetTickCount]), перебор
#      rel8/rel32/jcc32/abs32 по образу — входов внутрь изменяемых байтов нет; окна площадок одинаковы на трёх образах;
#      писатели полей +7A68/+7A6C монстра и +10A88 игрока (линейный проход .text) — только нули / свой такт.
#   2. DLL (по .map): стаб St18_AttackWait — дизасм, баланс стека, CF.
#   3. unicorn по НАСТОЯЩЕМУ коду (сток и N18): ворота Г1 (0x415EBA…, 0x41686C…), ворота Г3 и ВСЯ sub_4390A0,
#      ВСЯ sub_41DDD0 (сдача предмета) и хвост кадра sub_44DB70 (0x44E05B…) — матрица такт × метка × длительность /
#      × флаг события × счётчики; ожидание = эталонная модель (сток — знаковая, N18 — модульная/беззнаковая);
#      тождество N18 со стоком, пока такт < 2^31 и перехода через 2^32 нет.
# Запуск: py -3 verify_n18.py [AddonNPC.dll] [сток.exe живой.exe indun.exe]
import hashlib
import os
import re
import struct
import sys

sys.dont_write_bytecode = True
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_REG
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src", "patches", "n18_tick_signed.cpp")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))   # ★ 22.10.2026: srv_paths.py
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe", "16c7a0aff498a9f739899d9a2cba9a5b"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe", "c02486d62e803e98eb6fb4fa98d1fcd6"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe", "0de2c55932c2966537e2a8c539decdcd"),
]
if len(sys.argv) > 4:
    IMAGES = [(n, p, m) for (n, _, m), p in zip(IMAGES, sys.argv[2:5])]

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


REG = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
       "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "ebp": UC_X86_REG_EBP}
REGNO = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esp": 4, "ebp": 5, "esi": 6, "edi": 7}   # номера в ModRM
IAT_TICK, IAT_ENTER, IAT_LEAVE = 0x465054, 0x4650A4, 0x4650A0
G_MARK, G_FLT, G_BACKUP, G_COUNT, G_C60, G_C300, G_SYSIDX = 0x47D2BC, 0x47D324, 0x47D254, 0x47D1EC, 0x47D5EC, 0x47D654, 0x47C06B
G_LASTTICK = 0x4E5C358
FN_LOG, FN_SEND, FN_NOTICE, FN_SETLOG = 0x408DC0, 0x455120, 0x454F40, 0x44D800
HOUR, PRE = 3600000, 300000

# Площадки (зеркало kAreas из n18_tick_signed.cpp; сверяется с исходником при запуске).
# (группа, VA, байты, правки [(va, было, стало)], дизасм ДО, дизасм ПОСЛЕ, где)
AREAS = [
    (1, 0x415EDF, "2BCA 81F9D0070000 7C53", [(0x415EE7, 0x7C, 0x72)],
     ["sub ecx, edx", "cmp ecx, 0x7d0", "jl 0x415f3c"], ["sub ecx, edx", "cmp ecx, 0x7d0", "jb 0x415f3c"],
     "sub_415DE0 соулмейт по игроку: 2 с между «началом» и уроном"),
    (1, 0x416891, "2BD7 81FAD0070000 7C53", [(0x416899, 0x7C, 0x72)],
     ["sub edx, edi", "cmp edx, 0x7d0", "jl 0x4168ee"], ["sub edx, edi", "cmp edx, 0x7d0", "jb 0x4168ee"],
     "sub_416790 соулмейт по монстру: то же"),
    (2, 0x41DE4C, "3BD7 0F8EB5000000", [(0x41DE4F, 0x8E, 0x84)],
     ["cmp edx, edi", "jle 0x41df09"], ["cmp edx, edi", "je 0x41df09"], "sub_41DDD0: событие есть ⇔ метка ≠ 0"),
    (2, 0x41DE54, "3BD1 0F87AD000000", [(0x41DE55, 0xD1, 0xCA), (0x41DE57, 0x87, 0x88)],
     ["cmp edx, ecx", "ja 0x41df09"], ["cmp ecx, edx", "js 0x41df09"], "sub_41DDD0: ещё не началось ⇔ (int)(такт − метка) < 0 ★"),
    (2, 0x41DE62, "2BCA 81F980EE3600 7D3E", [(0x41DE6A, 0x7D, 0x73)],
     ["sub ecx, edx", "cmp ecx, 0x36ee80", "jge 0x41deaa"], ["sub ecx, edx", "cmp ecx, 0x36ee80", "jae 0x41deaa"],
     "sub_41DDD0: кончилось ⇔ (беззн.)(такт − метка) ≥ 1 ч"),
    (2, 0x41DF1C, "3BD7 7E39", [(0x41DF1E, 0x7E, 0x74)],
     ["cmp edx, edi", "jle 0x41df59"], ["cmp edx, edi", "je 0x41df59"], "sub_41DDD0: сбор/резерв ⇔ метка = 0"),
    (2, 0x44E0BA, "3BC3 0F8EBF000000", [(0x44E0BD, 0x8E, 0x84)],
     ["cmp eax, ebx", "jle 0x44e181"], ["cmp eax, ebx", "je 0x44e181"], "кадр/60: событие есть ⇔ метка ≠ 0"),
    (2, 0x44E0C2, "3BC1 0F87B7000000", [(0x44E0C3, 0xC1, 0xC8), (0x44E0C5, 0x87, 0x88)],
     ["cmp eax, ecx", "ja 0x44e181"], ["cmp ecx, eax", "js 0x44e181"], "кадр/60: ещё не началось ★"),
    (2, 0x44E0CA, "2BC8 8BC1 3D80EE3600 7D4B", [(0x44E0D3, 0x7D, 0x73)],
     ["sub ecx, eax", "mov eax, ecx", "cmp eax, 0x36ee80", "jge 0x44e120"],
     ["sub ecx, eax", "mov eax, ecx", "cmp eax, 0x36ee80", "jae 0x44e120"], "кадр/60: кончилось"),
    (2, 0x44E1EC, "3BD3 0F8E9F000000", [(0x44E1EF, 0x8E, 0x84)],
     ["cmp edx, ebx", "jle 0x44e293"], ["cmp edx, ebx", "je 0x44e293"], "кадр/300: событие есть ⇔ метка ≠ 0"),
    (2, 0x44E1F4, "3BD1 0F8797000000", [(0x44E1F5, 0xD1, 0xCA), (0x44E1F7, 0x87, 0x88)],
     ["cmp edx, ecx", "ja 0x44e293"], ["cmp ecx, edx", "js 0x44e293"], "кадр/300: ещё не началось ★"),
    (2, 0x44E1FC, "2BCA 8BC1 3D80EE3600 7D2A", [(0x44E205, 0x7D, 0x73)],
     ["sub ecx, edx", "mov eax, ecx", "cmp eax, 0x36ee80", "jge 0x44e231"],
     ["sub ecx, edx", "mov eax, ecx", "cmp eax, 0x36ee80", "jae 0x44e231"], "кадр/300: кончилось"),
    (2, 0x44E2A6, "3BD3 7F2C", [(0x44E2A8, 0x7F, 0x75)],
     ["cmp edx, ebx", "jg 0x44e2d6"], ["cmp edx, ebx", "jne 0x44e2d6"], "кадр/300: оповещение 8915 ⇔ метка = 0"),
    (3, 0x4390A7, "0FBF8E6C7A0000 8BC3 2B86687A0000 57 3BC1 0F8C89000000", [],
     ["movsx ecx, word ptr [esi + 0x7a6c]", "mov eax, ebx", "sub eax, dword ptr [esi + 0x7a68]", "push edi",
      "cmp eax, ecx", "jl 0x439148"],
     ["movsx ecx, word ptr [esi + 0x7a6c]", "mov eax, ebx", "call STUB", "nop", "push edi", "nop", "nop", "jb 0x439148"],
     "sub_4390A0 действие 6 ATTACK_WAIT"),
]
AW_SUB, AW_CMP, AW_JL = 0x4390B0, 0x4390B7, 0x4390B9
# три площадки сверх аудита: (va cmp, регистр метки, регистр такта, VA «mov R,[47D2BCh]», VA «call [GetTickCount]»)
SWAPS = {0x41DE54: ("edx", "ecx", 0x41DE31, 0x41DE1F),
         0x44E0C2: ("eax", "ecx", 0x44E0B5, 0x44E096),
         0x44E1F4: ("edx", "ecx", 0x44E1D9, 0x44E1C7)}
# площадки «метка ≠ 0»: (va cmp, регистр-ноль, VA его xor, диапазон, куда не должно быть входов извне после xor)
# площадки «метка ≠ 0»: регистр-ноль и функция (lo, hi) — ноль доказывается потоковым анализом по всем путям CFG функции
ZEROS = {0x41DE4C: ("edi", 0x41DDD0, 0x41E08E), 0x41DF1C: ("edi", 0x41DDD0, 0x41E08E),
         0x44E0BA: ("ebx", 0x44DB70, 0x44E2F6), 0x44E1EC: ("ebx", 0x44DB70, 0x44E2F6), 0x44E2A6: ("ebx", 0x44DB70, 0x44E2F6)}
# отрицательный контроль анализа: там регистр заведомо НЕ ноль (после movzx edi,ax / mov ebx,[4DC02Ch])
ZERO_CONTROL = {0x41DF62: ("edi", 0x41DDD0, 0x41E08E), 0x44DFB2: ("ebx", 0x44DB70, 0x44E2F6)}
FLAG_READERS = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
                "adc", "sbb", "pushfd", "pushf", "lahf", "rcl", "rcr", "into")
FLAG_FULL_WRITERS = ("cmp", "test", "add", "sub", "and", "or", "xor", "neg", "sahf", "popfd")


def hexb(s):
    return bytes.fromhex(s.replace(" ", ""))


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def md_new(detail=False):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = detail
    return md


def dis(img, base, va, n=1, ln=64):
    out = []
    for ins in md_new().disasm(bytes(img[va - base: va - base + ln]), va):
        out.append(ins)
        if len(out) >= n:
            break
    return out


def dis_range(img, base, lo, hi, detail=False):
    return list(md_new(detail).disasm(bytes(img[lo - base: hi - base]), lo))


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


_SWEEP = {}


def sweep_starts(pe, img, base):
    """Линейный проход .text (capstone, с пропуском нераспознанных байтов) — множество начал инструкций."""
    key = id(img)
    if key in _SWEEP:
        return _SWEEP[key]
    a, b = text_range(pe)
    md = md_new()
    starts, off = set(), a
    while off < b:
        last = off
        for ins in md.disasm(bytes(img[off:b]), base + off):
            starts.add(ins.address)
            last = ins.address - base + ins.size
        off = last if last > off else off + 1
    _SWEEP[key] = starts
    return starts


def host_insn(img, base, starts, va):
    for back in range(1, 16):
        if va - back in starts:
            ins = dis(img, base, va - back)[0]
            if ins.address + ins.size > va:
                return ins.address, "%s %s" % (ins.mnemonic, ins.op_str)
    return 0, "?"


def branch_target(ins):
    if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop"):
        if ins.op_str.startswith("0x"):
            return int(ins.op_str, 16)
    return None


_REFS = {}


def all_refs(pe, img, base, starts):
    """Один проход по образу: все rel8/rel32/jcc32 (с отметкой, настоящая ли это инструкция по границам) и все abs32
    из байтов, лежащих в файле (bss указателей не содержит). Кэшируется на образ — дальше inbound() только фильтрует."""
    key = id(img)
    if key in _REFS:
        return _REFS[key]
    a, b = text_range(pe)
    rel = []
    for i in range(a, b - 6):
        o = img[i]
        cands = []
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            cands.append(base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0])
        if o in (0xE8, 0xE9):
            cands.append(base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0])
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            cands.append(base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0])
        for tg in cands:
            src = base + i
            real = False
            if src in starts:
                ins = dis(img, base, src)[0]
                real = branch_target(ins) == tg
            rel.append((src, tg, real))
    # ★ 31.10.2026 (память): прежде — один диапазон 0…конец последней секции (.rsrc @0x4A5D000), то есть и 77 МБ нулевого .bss
    #   секции .data: ~78 млн кортежей, ~8 ГБ. Теперь — только байты, лежащие в файле: заголовки и сырые данные каждой секции
    #   (+3 байта перед началом секции — слова, заходящие в неё). Для ненулевых слов набор тот же: слово целиком из нулей .bss
    #   — значение 0, в интервал [lo, hi) не попадает никогда.
    spans = [(0, pe.OPTIONAL_HEADER.SizeOfHeaders)] + [(max(s.VirtualAddress - 3, 0), s.VirtualAddress + s.SizeOfRawData)
                                                        for s in pe.sections]
    abs32 = [(base + i, struct.unpack_from("<I", img, i)[0]) for lo_, hi_ in spans for i in range(lo_, min(hi_, len(img) - 3))]
    _REFS[key] = (rel, abs32)
    return _REFS[key]


def inbound(pe, img, base, starts, lo, hi, exclude_src=()):
    """Все переходы (настоящие — по границам инструкций — и ложные) и abs32 из образа, указывающие в [lo, hi)."""
    rel, abs32 = all_refs(pe, img, base, starts)
    hits = [("переход" if real else "ложный", src, tg) for src, tg, real in rel
            if lo <= tg < hi and not (lo <= src < hi) and src not in exclude_src]
    hits += [("abs32", va, v) for va, v in abs32 if lo <= v < hi]
    return hits


def flags_dead_after(img, base, va, limit=20):
    """Флаги на пути от va никто не читает: до первого читателя есть полный писатель / call / ret."""
    seen = []
    for ins in dis(img, base, va, limit, 160):
        m = ins.mnemonic
        seen.append(m)
        if m.startswith("set") or m.startswith("cmov") or m in FLAG_READERS:
            return False, seen
        if m in FLAG_FULL_WRITERS or m in ("call", "ret", "jmp"):
            return True, seen
    return False, seen


def reg_writers(img, base, lo, hi, reg):
    """Инструкции в [lo,hi), пишущие регистр reg (или его части)."""
    parts = {"ebx": ("ebx", "bx", "bl", "bh"), "edi": ("edi", "di")}[reg]
    out = []
    for ins in dis_range(img, base, lo, hi, True):
        if ins.mnemonic in ("cmp", "test", "push"):
            continue
        names = [ins.reg_name(r) for r in ins.regs_access()[1]]
        if any(p in names for p in parts) and not (ins.mnemonic == "lea" and ins.op_str == "ebx, [ebx]"):
            out.append(ins)
    return out


_DF = {}


def zero_dataflow(img, base, lo, hi, reg):
    """Прямой потоковый анализ по CFG функции [lo,hi): в каких инструкциях reg заведомо = 0 на ВСЕХ путях от входа.
    xor R,R → ноль; любая другая запись R (и его частей), pop R → неизвестно; call регистр не меняет (ebx/edi — callee-saved);
    переходы — внутрь функции; косвенных jmp быть не должно. Возвращает {va: True|False|None(недостижимо)}."""
    key = (id(img), lo, hi, reg)
    if key in _DF:
        return _DF[key]
    parts = {"ebx": ("ebx", "bx", "bl", "bh"), "edi": ("edi", "di")}[reg]
    ins = dis_range(img, base, lo, hi, True)
    idx = {i.address: k for k, i in enumerate(ins)}
    assert not [i for i in ins if i.mnemonic == "jmp" and not i.op_str.startswith("0x")], "косвенный jmp в функции"
    state = [None] * len(ins)
    work = [(0, False)]
    while work:
        k, st = work.pop()
        if state[k] is not None and (state[k] == st or state[k] is False):
            continue
        state[k] = st if state[k] is None else (state[k] and st)
        st = state[k]
        i = ins[k]
        names = [i.reg_name(r) for r in i.regs_access()[1]]
        if i.mnemonic == "xor" and i.op_str == "%s, %s" % (reg, reg):
            out = True
        elif i.mnemonic == "lea" and i.op_str == "%s, [%s]" % (reg, reg):
            out = st
        elif any(p in names for p in parts) and i.mnemonic != "call":
            out = False
        else:
            out = st
        tg = branch_target(i)
        if i.mnemonic == "ret":
            continue
        if tg is not None and i.mnemonic != "call" and tg in idx:
            work.append((idx[tg], out))
        if i.mnemonic != "jmp" and k + 1 < len(ins):
            work.append((k + 1, out))
    res = {i.address: state[k] for k, i in enumerate(ins)}
    _DF[key] = res
    return res


def parse_cpp_areas(path):
    """kAreas из n18_tick_signed.cpp → [(группа, va, байты, [(va, from, to)])]."""
    txt = open(path, encoding="utf-8").read()
    blk = txt[txt.index("const Area kAreas[] ="):]
    blk = blk[:blk.index("};")]
    blk = re.sub(r"//[^\n]*", "", blk)
    blk = re.sub(r'L"(?:[^"\\]|\\.)*"', '""', blk)
    out = []
    for m in re.finditer(r"\{\s*(\d)\s*,\s*0x([0-9A-Fa-f]+)\s*,\s*\{([^}]*)\}\s*,\s*(\d+)\s*,\s*\{(.*?)\}\s*,\s*(\d+)\s*,", blk, re.S):
        grp, va, raw, ln, edits, ne = m.groups()
        data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", raw))
        ed = [(int(a, 16), int(b, 16), int(c, 16)) for a, b, c in
              re.findall(r"\{\s*0x([0-9A-Fa-f]+)\s*,\s*0x([0-9A-Fa-f]+)\s*,\s*0x([0-9A-Fa-f]+)\s*\}", edits)]
        if len(data) != int(ln) or len(ed) != int(ne):
            raise RuntimeError("kAreas: длина/число правок не сходится у 0x%s" % va)
        out.append((int(grp), int(va, 16), data, ed))
    return out


def map_syms(path):
    want = {"St18_AttackWait": None, "N18_TickSigned": None}
    for line in open(path, encoding="latin-1"):
        p = line.split()
        if len(p) < 3:
            continue
        for k in want:
            if ("?%s@" % k) in p[1] and want[k] is None:
                want[k] = int(p[2], 16)
    return want


def rel32(src, dst):
    return struct.pack("<i", dst - (src + 5))


def apply_n18(img_or_uc_write, stub):
    """Правки N18 (как их пишет DLL) в копию образа / память эмулятора: write(va, bytes)."""
    w = img_or_uc_write
    for grp, va, raw, edits, _, _, _ in AREAS:
        for eva, _, to in edits:
            w(eva, bytes([to]))
    w(AW_SUB, b"\xe8" + rel32(AW_SUB, stub) + b"\x90")
    w(AW_CMP, b"\x90\x90")
    w(AW_JL + 1, b"\x82")


def s32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def u32(x):
    return x & 0xFFFFFFFF


# ── эмулятор ────────────────────────────────────────────────────────────────
MON = 0x00300000
PLAYERS = 0x00400000 - 0x00100000            # 0x300000+0x20000… занято монстром → игроки ниже
PLAYERS = 0x00200000
PLAYER_SZ = 0x10AA8
STACK = 0x00100000
RET_SENTINEL = 0x00080000
STUBS = 0x00090000                           # заглушки IAT: +0 GetTickCount, +0x10 Enter, +0x20 Leave
MON_FIELDS = {"action": 0x76B0, "prev": 0x76B4, "act_tick": 0x76EC, "act_iv": 0x76F0, "act_iv2": 0x76F2,
              "wait_tick": 0x7A68, "wait_dur": 0x7A6C, "map": 0x7694}


class Emu:
    # ★ 31.10.2026 (память): образ NpcServer в памяти — 78 МБ (SizeOfImage 0x4A5E000, почти всё — нулевые .data/.bss).
    #   Прежде (1) образ целиком копировался в bytes() на каждый экземпляр и (2) обработчик `hook_add(self._on)` замыкал цикл
    #   ссылок Emu → Uc → обратный вызов → Emu: экземпляры (по ~80 МБ гостевой памяти + кэш трансляции) не освобождались до
    #   конца прогона, 30 штук на 5 образов — 10+ ГБ. Теперь в память эмулятора пишутся только ненулевые куски по 1 МБ, а
    #   `close()` снимает обработчик и отпускает Uc — движок закрывает его финализатор (uc_close) сразу, по счётчику ссылок.
    CHUNK = 1 << 20

    def __init__(self, host_img, host_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((host_base, host_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            mv = memoryview(img)
            for off in range(0, len(img), self.CHUNK):
                ch = mv[off:off + self.CHUNK]
                if any(ch):                                   # нулевые куски не пишем: память эмулятора и так нулевая
                    self.uc.mem_write(base + off, bytes(ch))
        self.uc.mem_map(0, 0x1000)                           # fs:[0] (SEH-цепочка прологов) — база FS = 0
        self.uc.mem_map(STACK, 0x00100000)
        self.uc.mem_map(PLAYERS, 4 * PLAYER_SZ + 0x1000 & ~0xFFF)
        self.uc.mem_map(MON, 0x00020000)
        self.uc.mem_map(RET_SENTINEL, 0x1000)
        self.uc.mem_map(STUBS, 0x1000)
        self.uc.mem_write(RET_SENTINEL, b"\xcc" * 16)
        self.uc.mem_write(STUBS, b"\xc3" + b"\xcc" * 15 + b"\xc2\x04\x00" + b"\xcc" * 13 + b"\xc2\x04\x00")
        # IAT → заглушки; вызываемые из Г2 функции хоста → ret: лог (cdecl), отправка (ret 10h), оповещение (ret 8),
        # SetAction-лог Г3 (cdecl)
        self.uc.mem_write(IAT_TICK, struct.pack("<I", STUBS))
        self.uc.mem_write(IAT_ENTER, struct.pack("<I", STUBS + 0x10))
        self.uc.mem_write(IAT_LEAVE, struct.pack("<I", STUBS + 0x20))
        self.uc.mem_write(FN_LOG, b"\xc3")
        self.uc.mem_write(FN_SEND, b"\xc2\x10\x00")
        self.uc.mem_write(FN_NOTICE, b"\xc2\x08\x00")
        self.uc.mem_write(FN_SETLOG, b"\xc3")
        self.tick = 0
        self.trace = []
        self.stops = set()
        self.stopped_at = None
        self.host_img, self.host_base = host_img, host_base
        self._hook = self.uc.hook_add(UC_HOOK_CODE, self._on)

    def close(self):
        """Снять обработчик (разрыв цикла Emu → Uc → self._on) и отпустить Uc — память эмулятора освобождается сразу."""
        if self.uc is not None:
            self.uc.hook_del(self._hook)
            self.uc = None

    def cstr(self, va):
        raw = bytes(self.host_img[va - self.host_base: va - self.host_base + 40])
        return raw.split(b"\0")[0].decode("latin-1")

    def _on(self, uc, address, size, ud):
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()
            return
        esp = uc.reg_read(UC_X86_REG_ESP)
        if address == STUBS:
            uc.reg_write(UC_X86_REG_EAX, self.tick)
        elif address == FN_LOG:
            self.trace.append("лог:" + self.cstr(struct.unpack("<I", uc.mem_read(esp + 4, 4))[0])[:20])
        elif address == FN_SEND:
            self.trace.append("send %d/%d" % (uc.reg_read(UC_X86_REG_ECX), struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]))
        elif address == FN_NOTICE:
            self.trace.append("notice %d/%d" % (uc.reg_read(UC_X86_REG_ECX), struct.unpack("<I", uc.mem_read(esp + 8, 4))[0]))

    def run(self, start, regs, count=20000):
        for r, v in regs.items():
            self.uc.reg_write(r, v)
        self.stopped_at = None
        self.trace = []
        try:
            self.uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (self.uc.reg_read(UC_X86_REG_EIP), e))
        return self.stopped_at

    def w32(self, va, v):
        self.uc.mem_write(va, struct.pack("<I", u32(v)))

    def w16(self, va, v):
        self.uc.mem_write(va, struct.pack("<H", v & 0xFFFF))

    def r32(self, va):
        return struct.unpack("<I", self.uc.mem_read(va, 4))[0]

    def r16(self, va):
        return struct.unpack("<H", self.uc.mem_read(va, 2))[0]

    def rf(self, va):
        return struct.unpack("<f", self.uc.mem_read(va, 4))[0]

    def wf(self, va, v):
        self.uc.mem_write(va, struct.pack("<f", v))


# ── эталонные модели ────────────────────────────────────────────────────────
def ev_nonzero(mark, n18):
    return mark != 0 if n18 else s32(mark) > 0


def ev_started(tick, mark, n18):
    return s32(tick - mark) >= 0 if n18 else mark <= tick


def ev_ended(diff, n18):
    return diff >= HOUR if n18 else s32(diff) >= HOUR


def minutes_cmp(diff):
    """Минуты до конца ТОЧНО как в коде кадра: ecx = 3600000 − diff (32 бита); `mov eax,45E7B273h; imul ecx; sar edx,14;
    mov eax,edx; shr eax,31; add eax,edx` (деление на 60000 с округлением к нулю); `movzx eax,ax; cmp ax,0Ah` — сравнение
    16-битное знаковое. При разности ≥ 2^31 (дефект стока) остаток «отрицателен» и минуты — мусор младших 16 бит."""
    remain = u32(HOUR - diff)
    q = (s32(remain) * 0x45E7B273) >> 46
    q += 1 if q < 0 else 0
    return s16(q & 0xFFFF)


def L(fmt):
    """Строка лога так, как её пишет след эмулятора (первые 20 символов формата)."""
    return "лог:" + fmt[:20]


def model_handin(tick, mark, flt, count, backup, items, n18):
    """sub_41DDD0 (сдача предмета): → (след вызовов, метка, флаг, count, backup)."""
    tr = []
    v8 = mark
    goto_l7 = True
    if flt > 0 and ev_nonzero(mark, n18) and ev_started(tick, mark, n18):
        diff = u32(tick - mark)
        if ev_ended(diff, n18):
            old_backup = backup
            flt, backup, mark, count = 0.0, 0, 0, old_backup
            tr += ["notice 0/8921", L("Event End...! EventItem %d")]
            v8 = 0
        else:
            backup = s16(backup + items)
            tr += [L("Add EventBackupItem Total %d"), "send 7/8913"]
            goto_l7 = False
    if goto_l7:
        if flt <= 0 or (v8 == 0 if n18 else s32(v8) <= 0):
            old = count
            count = s16(count + items)
            if count >= 1000:
                flt, mark, backup, count = 2.0, u32(tick + PRE), s16(count - 1000), 0
                tr += [L("Event Start...! BackupItem %d"), "send 7/8913", "send 0/8916"]
                return tr, mark, flt, count, backup
            tr += [L("Add Item...! TotalItem %d")]
            if old < count:
                tr += ["send 2/8914"]
        else:
            backup = s16(backup + items)
            tr += [L("Add EventBackupItem Total %d")]
        tr += ["send 7/8913"]
    return tr, mark, flt, count, backup


def model_frame(tick, mark, flt, count, backup, c60, c300, n18):
    """Хвост кадра sub_44DB70 от 0x44E05B: → (след, метка, флаг, count, backup, c60, c300)."""
    tr = []
    c60 += 1
    if c60 >= 60:
        c60 = 0
        if flt > 0 and ev_nonzero(mark, n18) and ev_started(tick, mark, n18):
            diff = u32(tick - mark)
            if ev_ended(diff, n18):
                flt, count, backup, mark = 0.0, backup, 0, 0
                tr += ["notice 0/8921", L("Event End...! EventItem %d")]
                return tr, mark, flt, count, backup, c60, c300
            if minutes_cmp(diff) <= 10:
                tr += ["notice 3/8919"]
                return tr, mark, flt, count, backup, c60, c300
    c300 += 1
    if c300 < 300:
        return tr, mark, flt, count, backup, c60, c300
    c300 = 0
    v25 = mark
    if flt > 0 and ev_nonzero(mark, n18) and ev_started(tick, mark, n18):
        diff = u32(tick - mark)
        if not ev_ended(diff, n18):
            if minutes_cmp(diff) >= 10:
                tr += ["notice 3/8919"]
            return tr, mark, flt, count, backup, c60, c300
        flt, count, backup, mark = 0.0, backup, 0, 0
        tr += ["notice 0/8921", L("Event End...! EventItem %d")]
        v25 = 0
    if (flt <= 0 or (v25 == 0 if n18 else s32(v25) <= 0)) and s16(count) > 0:
        tr += ["notice 2/8915"]
    return tr, mark, flt, count, backup, c60, c300


def stock_wait3(tick, mark, dur):
    return s32(tick - mark) < dur


def n18_wait3(tick, mark, dur):
    return dur > 0 and u32(tick - mark) < dur


TICKS = [0x00001000, 0x10000000, 0x7FFFFF00, 0x80000000, 3083955078, 0xFFFFFF00, 0x00000100, 0x00000200]
DURS = [0, 1, 500, 1500, 32767, -1, -500, -32768]


def no_wrap(tick, mark):
    """Случай «как при малом аптайме»: такт < 2^31 и метка ≤ такт (как знаковые, без перехода)."""
    return tick < 0x80000000 and mark <= tick


# ── unicorn: Г3 ─────────────────────────────────────────────────────────────
def emulate_g3(img, base, dimg, dbase, syms):
    stub = syms["St18_AttackWait"]
    e = None
    for mode in ("сток", "N18"):
        if e is not None:
            e.close()                                     # прежний режим — память эмулятора отпускается
        e = Emu(img, base, dimg, dbase)
        if mode == "N18":
            apply_n18(lambda va, b: e.uc.mem_write(va, b), stub)
        print("-- unicorn Г3 ATTACK_WAIT, байты %s" % mode)
        e.stops = {0x4390BF, 0x439148}
        n_ok = n_all = 0
        ident = True
        for tick in TICKS:
            for mark in [0, tick - 1, tick - 499, tick - 500, tick - 501, tick - 1500, tick - 32767, tick - 0x7FFFFFFF,
                         tick - 0x80000001, tick + 100, 0x7FFFFFFF, 0x80000000]:
                mark = u32(mark)
                for dur in DURS:
                    e.w32(MON + 0x7A68, mark)
                    e.w16(MON + 0x7A6C, dur)
                    regs = {UC_X86_REG_ESP: 0x001F0000, UC_X86_REG_EBP: 0x0055AA00, UC_X86_REG_EAX: 0x11111111,
                            UC_X86_REG_ECX: 0x33333333, UC_X86_REG_EDX: 0x44444444, UC_X86_REG_EDI: 0x66666666,
                            UC_X86_REG_EBX: tick, UC_X86_REG_ESI: MON}
                    stop = e.run(0x4390A7, regs, 40)
                    waited = stop == 0x439148
                    exp = stock_wait3(tick, mark, dur) if mode == "сток" else n18_wait3(tick, mark, dur)
                    good = stop is not None and waited == exp
                    good = good and e.uc.reg_read(UC_X86_REG_EAX) == u32(tick - mark)
                    good = good and e.uc.reg_read(UC_X86_REG_ECX) == u32(dur)
                    good = good and e.uc.reg_read(UC_X86_REG_EBX) == tick and e.uc.reg_read(UC_X86_REG_ESI) == MON
                    good = good and e.uc.reg_read(UC_X86_REG_EDX) == 0x44444444 and e.uc.reg_read(UC_X86_REG_EDI) == 0x66666666
                    good = good and e.uc.reg_read(UC_X86_REG_EBP) == 0x0055AA00
                    good = good and e.uc.reg_read(UC_X86_REG_ESP) == 0x001F0000 - 4          # push edi — в обоих путях
                    good = good and e.r32(0x001F0000 - 4) == 0x66666666                        # и именно edi на стеке
                    n_all += 1
                    if good:
                        n_ok += 1
                    elif n_all - n_ok <= 3:
                        ok(False, "такт 0x%08X, метка 0x%08X, длит. %d: стоп %s, ждал=%s, ожидание %s" %
                           (tick, mark, dur, "0x%08X" % stop if stop else "—", waited, exp))
                    if mode == "N18" and no_wrap(tick, mark) and n18_wait3(tick, mark, dur) != stock_wait3(tick, mark, dur):
                        ident = False
        ok(n_ok == n_all, "ворота 0x4390A7: %d/%d — решение, eax = такт − метка, ecx = длительность, прочие регистры, стек (push edi)" % (n_ok, n_all))
        if mode == "N18":
            ok(ident, "    тождество со стоком при такте < 2^31 и метке ≤ такту")
        # вся функция sub_4390A0: ждать → действие 6 остаётся; иначе → NONE (+76B0 = 0), dword_4E5C358 = такт, ax = такт − метка
        e.stops = {RET_SENTINEL}
        n_ok = n_all = 0
        for tick in TICKS:
            for mark in [0, u32(tick - 100), u32(tick + 100), u32(tick - 5000)]:
                for dur in (0, 1000, -7):
                    e.uc.mem_write(MON, b"\x00" * 0x10000)
                    e.w32(MON + MON_FIELDS["map"], 0x12345)       # ≠ word_47C068 → ветка SetAction-лога не берётся
                    e.w32(MON + MON_FIELDS["action"], 6)
                    e.w32(MON + MON_FIELDS["prev"], 0x77)
                    e.w32(MON + 0x7A68, mark)
                    e.w16(MON + 0x7A6C, dur)
                    e.w32(G_LASTTICK, 0xDEADBEEF)
                    esp = 0x001F0000 - 4
                    e.w32(esp, RET_SENTINEL)
                    stop = e.run(0x4390A0, {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: 0x001F8000, UC_X86_REG_EBX: tick,
                                            UC_X86_REG_ESI: MON, UC_X86_REG_EDI: 0x9ABC})
                    exp_wait = stock_wait3(tick, mark, dur) if mode == "сток" else n18_wait3(tick, mark, dur)
                    act = e.r32(MON + MON_FIELDS["action"])
                    good = stop == RET_SENTINEL and e.uc.reg_read(UC_X86_REG_ESP) == esp + 4
                    good = good and (e.uc.reg_read(UC_X86_REG_EAX) & 0xFFFF) == (u32(tick - mark) & 0xFFFF)
                    good = good and e.uc.reg_read(UC_X86_REG_EBX) == tick and e.uc.reg_read(UC_X86_REG_ESI) == MON
                    good = good and e.uc.reg_read(UC_X86_REG_EDI) == 0x9ABC and e.uc.reg_read(UC_X86_REG_EBP) == 0x001F8000
                    if exp_wait:
                        good = good and act == 6 and e.r32(G_LASTTICK) == 0xDEADBEEF
                    else:
                        good = good and act == 0 and e.r32(MON + MON_FIELDS["prev"]) == 6 and e.r32(G_LASTTICK) == tick \
                            and e.r32(MON + MON_FIELDS["act_tick"]) == tick and e.r16(MON + MON_FIELDS["act_iv"]) == 0
                    n_all += 1
                    if good:
                        n_ok += 1
                    elif n_all - n_ok <= 3:
                        ok(False, "sub_4390A0: такт 0x%08X, метка 0x%08X, длит. %d: стоп %s, действие после %d (ожидание %s)" %
                           (tick, mark, dur, "0x%08X" % stop if stop else "—", act, "ждать" if exp_wait else "NONE"))
        ok(n_ok == n_all, "ВСЯ sub_4390A0 от входа: %d/%d — ждать ⇒ действие 6 остаётся; иначе ⇒ NONE, prev=6, такт действия, ax" % (n_ok, n_all))
        w = stock_wait3(3083955078, 0, 0) if mode == "сток" else n18_wait3(3083955078, 0, 0)
        ok(w == (mode == "сток"), "живой случай 15.10: такт 3 083 955 078, метка 0, длительность 0 — %s" %
           ("ждёт ВЕЧНО (монстр стоит в ATTACK_WAIT)" if w else "не ждёт (как при малом аптайме)"))
    if e is not None:
        e.close()


# ── unicorn: Г1 ─────────────────────────────────────────────────────────────
def emulate_g1(img, base, dimg, dbase, syms):
    gates = [(0x415EBA, 0x415EE9, 0x415F3C, "ecx", "sub_415DE0 по игроку"),
             (0x41686C, 0x41689B, 0x4168EE, "edx", "sub_416790 по монстру")]
    e = None
    for mode in ("сток", "N18"):
        if e is not None:
            e.close()                                     # прежний режим — память эмулятора отпускается
        e = Emu(img, base, dimg, dbase)
        if mode == "N18":
            apply_n18(lambda va, b: e.uc.mem_write(va, b), syms["St18_AttackWait"])
        print("-- unicorn Г1 соулмейт, байты %s" % mode)
        for entry, fall, tgt, rdiff, where in gates:
            e.stops = {fall, tgt}
            n_ok = n_all = 0
            ident = True
            for tick in TICKS:
                for mark in [0, tick - 1, tick - 1999, tick - 2000, tick - 2001, tick - 0x7FFFFFFF, tick - 0x80000000,
                             tick + 5, 0x7FFFFFFF, 0x80000000]:
                    mark = u32(mark)
                    idx = 2
                    esp = 0x001F0000
                    e.w16(esp + 0x214, idx)
                    e.w32(PLAYERS + idx * PLAYER_SZ + 0x10A88, mark)
                    stop = e.run(entry, {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: 0x0055AA00, UC_X86_REG_EAX: tick,
                                         UC_X86_REG_EBX: PLAYERS, UC_X86_REG_ESI: 0x5555, UC_X86_REG_EDI: 0x6666,
                                         UC_X86_REG_ECX: 0x3333, UC_X86_REG_EDX: 0x4444}, 40)
                    start = stop == fall
                    exp = (s32(tick - mark) >= 2000) if mode == "сток" else (u32(tick - mark) >= 2000)
                    good = stop is not None and start == exp
                    good = good and e.uc.reg_read(REG[rdiff]) == u32(tick - mark)
                    good = good and e.uc.reg_read(UC_X86_REG_EAX) == tick and e.uc.reg_read(UC_X86_REG_EBX) == PLAYERS
                    good = good and e.uc.reg_read(UC_X86_REG_ESP) == esp and e.uc.reg_read(UC_X86_REG_EBP) == 0x0055AA00
                    good = good and e.uc.reg_read(UC_X86_REG_ESI) == 0x5555
                    n_all += 1
                    if good:
                        n_ok += 1
                    elif n_all - n_ok <= 3:
                        ok(False, "%s: такт 0x%08X, метка 0x%08X: стоп %s, «начало»=%s, ожидание %s" %
                           (where, tick, mark, "0x%08X" % stop if stop else "—", start, exp))
                    if mode == "N18" and no_wrap(tick, mark) and (u32(tick - mark) >= 2000) != (s32(tick - mark) >= 2000):
                        ident = False
            ok(n_ok == n_all, "%s @0x%06X: %d/%d — фаза «начала» ⇔ (такт − метка) ≥ 2000 (%s), разность в %s, прочие регистры, стек" %
               (where, entry, n_ok, n_all, "знаково" if mode == "сток" else "беззнаково", rdiff))
            if mode == "N18":
                ok(ident, "    тождество со стоком при такте < 2^31 и метке ≤ такту")
        live = (s32(3083955078 - 0) >= 2000) if mode == "сток" else (u32(3083955078) >= 2000)
        ok(live == (mode == "N18"), "живой случай: такт 3 083 955 078, метка 0 — %s" %
           ("фаза «начала» (201/8228)" if live else "«начало» ПРОПУЩЕНО, урон сразу"))
    if e is not None:
        e.close()


# ── unicorn: Г2 ─────────────────────────────────────────────────────────────
def g2_cases():
    for tick in TICKS:
        for mark in [0, tick + PRE, tick + 1, tick, tick - 1000, tick - (HOUR - 1), tick - HOUR, tick - HOUR - 1,
                     tick - 600000, tick - 3000000, tick - 0x7FFFFFFF, 0x7FFFFFFF, 0x80000000, 1]:
            for flt in (0.0, 2.0):
                yield tick, u32(mark), flt


def emulate_g2(img, base, dimg, dbase, syms):
    e = None
    for mode in ("сток", "N18"):
        n18 = mode == "N18"
        if e is not None:
            e.close()                                     # прежний режим — память эмулятора отпускается
        e = Emu(img, base, dimg, dbase)
        if n18:
            apply_n18(lambda va, b: e.uc.mem_write(va, b), syms["St18_AttackWait"])
        print("-- unicorn Г2 событие «1000 предметов», байты %s" % mode)
        # ВСЯ sub_41DDD0 (thiscall: ecx = {userIndex, items}, [esp+4]=a2, [esp+8]=a3; ret 8)
        e.stops = {RET_SENTINEL}
        n_ok = n_all = 0
        ident = True
        wrong = []
        for tick, mark, flt in g2_cases():
            for count, backup, items in ((0, 0, 1), (999, 0, 1), (500, 7, 5)):
                e.tick = tick
                e.w32(G_MARK, mark)
                e.wf(G_FLT, flt)
                e.w16(G_BACKUP, backup)
                e.w32(G_COUNT, count)
                e.uc.mem_write(STACK + 0x100, struct.pack("<ii", 17, items))
                esp = 0x001F0000 - 12
                e.uc.mem_write(esp, struct.pack("<III", RET_SENTINEL, 0x00680000, 0x00690000))
                stop = e.run(0x41DDD0, {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: 0x001F8000, UC_X86_REG_ECX: STACK + 0x100,
                                        UC_X86_REG_EBX: 0x1234, UC_X86_REG_ESI: 0x5678, UC_X86_REG_EDI: 0x9ABC})
                exp = model_handin(tick, mark, flt, count, backup, items, n18)
                got = (e.trace, e.r32(G_MARK), e.rf(G_FLT), s16(e.r16(G_COUNT)), s16(e.r16(G_BACKUP)))
                good = stop == RET_SENTINEL and e.uc.reg_read(UC_X86_REG_ESP) == esp + 12 and got == exp
                good = good and e.uc.reg_read(UC_X86_REG_EBX) == 0x1234 and e.uc.reg_read(UC_X86_REG_ESI) == 0x5678
                good = good and e.uc.reg_read(UC_X86_REG_EDI) == 0x9ABC and e.uc.reg_read(UC_X86_REG_EBP) == 0x001F8000
                n_all += 1
                if good:
                    n_ok += 1
                elif len(wrong) < 3:
                    wrong.append("такт 0x%08X, метка 0x%08X, флаг %g, count %d, backup %d: стоп %s, получено %s, ожидание %s" %
                                 (tick, mark, flt, count, backup, "0x%08X" % stop if stop else "—", got, exp))
                if n18 and no_wrap(tick, mark) and (mark == 0 or tick - mark < 0x80000000) and \
                        model_handin(tick, mark, flt, count, backup, items, True) != model_handin(tick, mark, flt, count, backup, items, False):
                    ident = False
        for w in wrong:
            ok(False, w)
        ok(n_ok == n_all, "ВСЯ sub_41DDD0 от входа: %d/%d — след (лог/8913/8914/8916/8921), метка/флаг/счётчики, ret 8, регистры" % (n_ok, n_all))
        if n18:
            ok(ident, "    тождество со стоком при такте < 2^31 и метке < 2^31 (без перехода)")
        # хвост кадра sub_44DB70 от 0x44E05B до 0x44E2F0
        e.stops = {0x44E2F0}
        n_ok = n_all = 0
        wrong = []
        for tick, mark, flt in g2_cases():
            for count, backup in ((0, 0), (12, 3)):
                for c60, c300 in ((58, 298), (59, 298), (58, 299), (59, 299)):
                    e.tick = tick
                    e.w32(G_MARK, mark)
                    e.wf(G_FLT, flt)
                    e.w16(G_BACKUP, backup)
                    e.w32(G_COUNT, count)
                    e.w32(G_C60, c60)
                    e.w32(G_C300, c300)
                    esp = 0x001F0000 - 0x400
                    stop = e.run(0x44E05B, {UC_X86_REG_ESP: esp, UC_X86_REG_EBP: 0x77, UC_X86_REG_EDI: 0x88, UC_X86_REG_ESI: 0x99})
                    exp = model_frame(tick, mark, flt, count, backup, c60, c300, n18)
                    got = (e.trace, e.r32(G_MARK), e.rf(G_FLT), s16(e.r16(G_COUNT)), s16(e.r16(G_BACKUP)), e.r32(G_C60), e.r32(G_C300))
                    good = stop == 0x44E2F0 and e.uc.reg_read(UC_X86_REG_ESP) == esp + 20 and got == exp     # 5 pop
                    n_all += 1
                    if good:
                        n_ok += 1
                    elif len(wrong) < 3:
                        wrong.append("кадр: такт 0x%08X, метка 0x%08X, флаг %g, c60 %d, c300 %d: стоп %s, получено %s, ожидание %s" %
                                     (tick, mark, flt, c60, c300, "0x%08X" % stop if stop else "—", got, exp))
        for w in wrong:
            ok(False, w)
        ok(n_ok == n_all, "хвост кадра sub_44DB70 (0x44E05B…0x44E2F0): %d/%d — след (8919/8921/8915/лог), метка/флаг/счётчики, стек" % (n_ok, n_all))
        # сценарии словами
        def hand(tick, mark, flt, count=0, backup=0):
            return model_handin(tick, mark, flt, count, backup, 1, n18)[0]
        t = 3083955078
        ok(("send 0/8916" in hand(t, 0, 0.0, 999)) and (model_handin(t, 0, 0.0, 999, 0, 1, n18)[1] == u32(t + PRE)),
           "сценарий: такт ≥ 2^31, тысячный предмет — «Event Start», метка = такт + 300000")
        m = u32(t + PRE)
        r = hand(t + PRE + 10, m, 2.0)
        has = lambda r, pre: any(x.startswith(pre) for x in r)
        ok(has(r, L("Add EventBackupItem")) == n18, "сценарий: такт ≥ 2^31, событие идёт (10 мс после начала) — %s" %
           ("предмет в резерв события" if has(r, L("Add EventBackupItem")) else "как без события (ДЕФЕКТ стока)"))
        r = model_handin(u32(t + PRE + HOUR), m, 2.0, 0, 5, 1, n18)
        ok(("notice 0/8921" in r[0]) == n18, "сценарий: такт ≥ 2^31, прошёл час — %s" %
           ("«Event End» + 8921" if "notice 0/8921" in r[0] else "конца НЕТ (ДЕФЕКТ стока)"))
        # переход через 2^32
        m = u32(0xFFFFFF00 + PRE)                          # метка перевалила за 2^32 при взводе
        r = model_handin(0xFFFFFF00 + 10, m, 2.0, 0, 0, 1, n18)[0]
        ok(has(r, L("Add EventBackupItem")), "сценарий 2^32: метка взведена через 0 (0x%08X), такт 0xFFFFFF0A — предмет в резерв (ещё не началось)" % m)
        r = model_frame(0x00000200, 0xFFFFFF00, 2.0, 0, 0, 58, 299, n18)[0]
        ok(("notice 3/8919" in r) == n18, "сценарий 2^32: событие началось до обнуления (метка 0xFFFFFF00), такт 0x200 — %s" %
           ("идёт, оповещение 8919" if "notice 3/8919" in r else "«ещё не началось» 49,7 сут (ДЕФЕКТ стока)"))
    if e is not None:
        e.close()


# ── главная проверка ─────────────────────────────────────────────────────────
def check_image(name, path, md5_want, dimg, dbase, syms, ref):
    raw = open(path, "rb").read()
    md5 = hashlib.md5(raw).hexdigest()
    print("-- %s: %s (md5 %s)" % (name, path, md5))
    ok(md5 == md5_want, "md5 образа = %s" % md5_want)
    pe, img, base = load(path)
    starts = sweep_starts(pe, img, base)
    stub = syms["St18_AttackWait"]
    patched = bytearray(img)
    apply_n18(lambda va, b: patched.__setitem__(slice(va - base, va - base + len(b)), b), stub)
    windows = []
    ranges = []
    for grp, va, raw_hex, edits, before, after, where in AREAS:
        data = hexb(raw_hex)
        ok(bytes(img[va - base: va - base + len(data)]) == data, "Г%d 0x%06X %s: байты стока %s" % (grp, va, where, raw_hex))
        ins_b = dis_range(img, base, va, va + len(data))
        got_b = ["%s %s" % (i.mnemonic, i.op_str) for i in ins_b]
        ins_a = dis_range(patched, base, va, va + len(data))
        got_a = [("%s %s" % (i.mnemonic, i.op_str)).strip() for i in ins_a]
        exp_a = [s.replace("STUB", "0x%x" % stub) for s in after]
        ok(got_b == before and sum(i.size for i in ins_b) == len(data) and va in starts,
           "    дизасм до: %s" % "; ".join(got_b))
        ok(got_a == exp_a and sum(i.size for i in ins_a) == len(data),
           "    дизасм после (длины те же): %s" % "; ".join(got_a))
        # правки: внутри какой инструкции
        for eva, frm, to in edits:
            host = [i for i in ins_b if i.address <= eva < i.address + i.size]
            ok(len(host) == 1 and img[eva - base] == frm, "    правка 0x%06X %02X→%02X внутри `%s`" %
               (eva, frm, to, "%s %s" % (host[0].mnemonic, host[0].op_str) if host else "?"))
        # флаги после перевёрнутого перехода: оба пути
        jcc = ins_a[-1]
        tgt = int(jcc.op_str, 16)
        d1, s1 = flags_dead_after(img, base, jcc.address + jcc.size)
        d2, s2 = flags_dead_after(img, base, tgt)
        ok(d1 and d2, "    флаги после %s не читаются: прямой путь %s | цель 0x%06X %s" % (jcc.mnemonic, ",".join(s1), tgt, ",".join(s2)))
        windows.append(bytes(img[va - base: va - base + len(data)]))
        if grp == 3:
            ranges.append((AW_SUB + 1, AW_SUB + 6, "внутрь call"))
            ranges.append((AW_CMP, AW_CMP + 2, "nop×2"))
            ranges.append((AW_JL, AW_JL + 6, "на/внутрь jl"))
        else:
            for eva, _, _ in edits:
                ranges.append((eva, eva + 1, "байт правки 0x%06X" % eva))
        # три площадки сверх аудита: ModRM и провенанс регистров
        if va in SWAPS:
            rmark, rtick, mov_va, call_va = SWAPS[va]
            modrm_b, modrm_a = img[va + 1 - base], patched[va + 1 - base]
            ok(img[va - base] == 0x3B and (modrm_b >> 6) == 3 and ((modrm_b >> 3) & 7) == REGNO[rmark] and (modrm_b & 7) == REGNO[rtick],
               "    ModRM до %02X: cmp reg=%s (метка), rm=%s (такт) — `cmp метка,такт; ja` = метка > такт" % (modrm_b, rmark, rtick))
            ok((modrm_a >> 6) == 3 and ((modrm_a >> 3) & 7) == REGNO[rtick] and (modrm_a & 7) == REGNO[rmark] and
               patched[va + 2 - base: va + 4 - base] == b"\x0f\x88",
               "    ModRM после %02X: cmp reg=%s (такт), rm=%s (метка) + 0F 88 js — `(int)(такт − метка) < 0`" % (modrm_a, rtick, rmark))
            mv = dis(img, base, mov_va)[0]
            ok("%s %s" % (mv.mnemonic, mv.op_str) == "mov %s, dword ptr [0x%x]" % (rmark, G_MARK),
               "    метка: @0x%06X `%s %s`" % (mov_va, mv.mnemonic, mv.op_str))
            cl = dis(img, base, call_va)[0]
            ok("%s %s" % (cl.mnemonic, cl.op_str) == "call dword ptr [0x%x]" % IAT_TICK, "    такт: @0x%06X `%s %s` (IAT GetTickCount)" % (call_va, cl.mnemonic, cl.op_str))
            # между call и площадкой: такт попадает в rtick одной mov R,eax до fnstsw; после неё rtick/rmark не пишутся
            path = dis_range(img, base, call_va + 6, va, True)
            mov_t = [i for i in path if i.mnemonic == "mov" and i.op_str == "%s, eax" % rtick]
            good = len(mov_t) == 1
            if good:
                after_mov = [i for i in path if i.address > mov_t[0].address]
                before_mov = [i for i in path if i.address < mov_t[0].address]
                good = all("eax" not in [i.reg_name(r) for r in i.regs_access()[1]] and "ax" not in [i.reg_name(r) for r in i.regs_access()[1]] for i in before_mov)
                good = good and all(not ({rtick, rmark} & set(i.reg_name(r) for r in i.regs_access()[1])) for i in after_mov if i.address != mov_va)
                good = good and all(i.address != mov_va or i.mnemonic == "mov" for i in path)
                inb = [h for h in inbound(pe, img, base, starts, call_va + 6, va + 1) if h[0] == "переход"]
                good = good and not inb
            ok(good, "    провенанс: eax после call не трогается до `mov %s, eax`, затем %s/%s не пишутся до площадки, входов в путь извне нет: %s" %
               (rtick, rtick, rmark, "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in path)))
            # регистр-свидетель: читается только площадкой? флаги после ja/js — уже проверено
        if va in ZEROS:
            rz, lo, hi = ZEROS[va]
            df = zero_dataflow(img, base, lo, hi, rz)
            ext = [h for h in inbound(pe, img, base, starts, lo + 1, hi) if h[0] == "переход" and not (lo <= h[1] < hi)]
            ok(df.get(va) is True and not ext, "    %s = 0 на ВСЕХ путях CFG функции 0x%06X…0x%06X (потоковый анализ; входов в функцию извне, кроме входа, нет: %d)" %
               (rz, lo, hi, len(ext)))
    for cva, (rz, lo, hi) in ZERO_CONTROL.items():
        ok(zero_dataflow(img, base, lo, hi, rz).get(cva) is False, "отрицательный контроль анализа: %s @0x%06X НЕ ноль (%s)" %
           (rz, cva, dis(img, base, cva)[0].mnemonic))
    # 0x41DF1C достижим и после «Event End» (0x41DEAA…): туда входит только jge 0x41DE6A, edi обнуляется @0x41DECC
    inb = [h for h in inbound(pe, img, base, starts, 0x41DEAA, 0x41DF09) if h[0] == "переход"]
    ok([(s, t) for _, s, t in inb] == [(0x41DE6A, 0x41DEAA)], "ветка «Event End» 0x41DEAA…0x41DF09: единственный вход — jge @0x41DE6A (%s)" %
       ", ".join("0x%06X→0x%06X" % (s, t) for _, s, t in inb))
    inb = [h for h in inbound(pe, img, base, starts, 0x41DF09, 0x41DF20) if h[0] == "переход"]
    ok(sorted(s for _, s, t in inb) == [0x41DE46, 0x41DE4E, 0x41DE56] and all(t == 0x41DF09 for _, s, t in inb),
       "0x41DF09 (LABEL_7): входы только из 0x41DE46/0x41DE4E/0x41DE56 (edi = 0 с 0x41DDFD) и проходом с 0x41DF06 (edi = 0 с 0x41DECC)")
    # ebx в хвосте кадра: после xor @0x44E05B до конца функции ebx пишет только pop; переходов из начала функции в хвост нет
    ws = reg_writers(img, base, 0x44E05D, 0x44E2F6, "ebx")
    ok([("%s %s" % (i.mnemonic, i.op_str)) for i in ws] == ["pop ebx"], "sub_44DB70: после `xor ebx,ebx` @0x44E05B ebx пишет только эпилог `pop ebx` (%s)" %
       ", ".join("0x%06X %s" % (i.address, i.mnemonic) for i in ws))
    cross = [(i.address, branch_target(i)) for i in dis_range(img, base, 0x44DB70, 0x44E05B)
             if i.mnemonic != "call" and branch_target(i) and 0x44E05B < branch_target(i) < 0x44E2F6]
    ind = [i.address for i in dis_range(img, base, 0x44DB70, 0x44E2F6) if i.mnemonic == "jmp" and not i.op_str.startswith("0x")]
    dfb = zero_dataflow(img, base, 0x44DB70, 0x44E2F6, "ebx")
    ok(cross == [(0x44DF9E, 0x44E05D)] and dfb.get(0x44E05D) is True and not ind,
       "sub_44DB70: единственный переход из начала функции мимо `xor ebx,ebx` @0x44E05B — jle @0x44DF9E → 0x44E05D (нет AI-потоков), "
       "и там ebx = 0 по потоковому анализу (xor @0x44DE5F без записей до jle); косвенных jmp нет (%d)" % len(ind))
    # Г3: стек/цель jl — эпилог; поле +7A68/+7A6C монстра — писатели; достижимость действия 6
    ep = dis(img, base, 0x439148, 4)
    ok([i.mnemonic for i in ep] == ["pop", "mov", "pop", "ret"] and ep[0].op_str == "edi",
       "цель jl 0x439148 — эпилог: %s (push edi @0x4390B6 ↔ pop edi)" % "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in ep))
    acc = {0x7A68: [], 0x7A6C: [], 0x10A88: []}
    md = md_new(True)
    a, b = text_range(pe)
    off = a
    while off < b:
        last = off
        for ins in md.disasm(bytes(img[off:b]), base + off):
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.disp in acc:
                    acc[op.mem.disp].append((ins.address, "%s %s" % (ins.mnemonic, ins.op_str)))
            last = ins.address - base + ins.size
        off = last if last > off else off + 1
    exp68 = {0x4113EA, 0x4127DA, 0x4129B0, 0x42E4BF, 0x42E4EA, 0x4390B0, 0x44BF73, 0x44C115, 0x460C96, 0x460CB7}
    exp6C = {0x40D492, 0x411953, 0x4127F4, 0x4129CA, 0x42E4B8, 0x42E4E3, 0x4390A7, 0x44BF79, 0x44C10E}
    ok(set(v for v, _ in acc[0x7A68]) == exp68 and set(v for v, _ in acc[0x7A6C]) == exp6C,
       "обращения к +7A68/+7A6C по всему .text: %d/%d — как в разборе (монстр: конструктор 0x44BF73/0x44C115 и AlarmMonsterAction 0x460CB7 пишут 0; "
       "0x4127DA/0x4129B0/0x4113EA/0x411953 — массив навыков ИГРОКА (шаг 28 от +7A5C, 500 записей не помещаются в монстра 37624 б); "
       "0x42E4B8…0x42E4EA — кусок 0x42E480 без ссылок)" % (len(acc[0x7A68]), len(acc[0x7A6C])))
    # ebx = 0 в конструкторе и AlarmMonsterAction
    c1 = dis(img, base, 0x44BF6D)[0]
    c2 = dis(img, base, 0x460C9C)[0]
    ok(c1.op_str == "ebx, ebx" and c1.mnemonic == "xor" and not reg_writers(img, base, 0x44BF6F, 0x44C11B, "ebx") and c2.mnemonic == "xor" and c2.op_str == "ebx, ebx",
       "писатели +7A68 монстра пишут 0: `xor ebx,ebx` @0x44BF6D (ebx не меняется до 0x44C115), @0x460C9C")
    orphan = [h for h in inbound(pe, img, base, starts, 0x42E480, 0x42E4F5) if h[0] != "ложный"]
    prev = dis(img, base, 0x42E47A)[0]
    ok(not orphan and prev.mnemonic == "ret", "кусок 0x42E480…0x42E4F5 (пишет +7A68/+7A70 тактом): входов в срезе нет (%d), перед ним `ret 8` @0x42E47A — не достижим" % len(orphan))
    # +10A88 (метка соулмейта): писатели — свой такт той же функции или 0
    exp88 = {0x415EC8, 0x415EF2, 0x415F50, 0x41687A, 0x41689B, 0x4168F4, 0x428DB6}
    z1 = dis(img, base, 0x415F4A, 2)
    z2 = dis(img, base, 0x4168EE, 1)[0]
    init = dis_range(img, base, 0x428D80, 0x428DBC, True)
    init_ok = any(i.mnemonic == "xor" and i.op_str == "eax, eax" for i in dis_range(img, base, 0x428C20, 0x428DB6)) and \
        not any("eax" in [i.reg_name(r) for r in i.regs_access()[1]] for i in dis_range(img, base, 0x428C20, 0x428DB6, True)
                if i.address > max(j.address for j in dis_range(img, base, 0x428C20, 0x428DB6) if j.mnemonic == "xor" and j.op_str == "eax, eax"))
    ok(set(v for v, _ in acc[0x10A88]) == exp88 and z1[0].op_str == "ecx, ecx" and z2.op_str == "edx, edx" and init_ok,
       "обращения к +10A88: %d — чтения 0x415EC8/0x41687A, записи своим тактом 0x415EF2/0x41689B (eax = GetTickCount той же функции), "
       "нулём 0x415F50 (xor ecx), 0x4168F4 (xor edx), 0x428DB6 (инициализация игрока, eax = 0)" % len(acc[0x10A88]))
    # Г1: eax = GetTickCount на входе ворот
    g1 = dis_range(img, base, 0x415EB4, 0x415EDF, True)
    g2 = dis_range(img, base, 0x416830, 0x41688F, True)
    no_eax = lambda lst: not any("eax" in [i.reg_name(r) for r in i.regs_access()[1]] or i.mnemonic == "call" for i in lst)
    ok(g1[0].op_str == "dword ptr [0x%x]" % IAT_TICK and no_eax(g1[1:]) and g2[0].op_str == "dword ptr [0x%x]" % IAT_TICK and no_eax(g2[1:]),
       "Г1: `call [GetTickCount]` @0x415EB4 → eax цел до `mov ecx, eax` @0x415EDD; @0x416830 → eax цел до `mov edx, eax` @0x41688F")
    # действие 6: SetAction (sub_42C880, edi = действие) вызывается с литералами 18/17/19/15, из +7A4C (пишется только 0) и из пакета GS
    calls = [h for h in inbound(pe, img, base, starts, 0x42C880, 0x42C881) if h[0] == "переход"]
    ok(sorted(s for _, s, _ in calls) == [0x419B2B, 0x419F31, 0x439D00, 0x439D93, 0x43A982, 0x43C379, 0x45B8CE],
       "SetAction sub_42C880: 7 вызовов (%s); действие 6 — только из пакета GS @0x45B8CE (edi = байт пакета)" %
       ", ".join("0x%06X" % s for _, s, _ in sorted(calls, key=lambda h: h[1])))
    # входы внутрь изменяемых байтов
    hits = []
    for lo, hi, nm in ranges:
        for h in inbound(pe, img, base, starts, lo, hi):
            if h[0] == "ложный":
                host = host_insn(img, base, starts, h[1])
                print("    (ложный вход @0x%08X → 0x%08X исключён: байт — операнд инструкции @0x%08X `%s`)" % (h[1], h[2], host[0], host[1]))
            else:
                hits.append((nm,) + h)
    ok(not hits, "перебор rel8/rel32/jcc32/abs32: входов внутрь изменяемых байтов — %d%s" %
       (len(hits), "" if not hits else ": " + ", ".join("%s %s @0x%08X → 0x%08X" % h for h in hits[:8])))
    entry = [h for h in inbound(pe, img, base, starts, AW_SUB, AW_SUB + 1) if h[0] == "переход"]
    print("    входов на начало площадки call 0x4390B0 (допустимо): %d" % len(entry))
    if ref is None:
        ref = windows
    else:
        ok(windows == ref, "окна всех %d площадок побайтно совпадают со стоком" % len(AREAS))
    emulate_g3(img, base, dimg, dbase, syms)
    emulate_g1(img, base, dimg, dbase, syms)
    emulate_g2(img, base, dimg, dbase, syms)
    # ★ 31.10.2026: кэши разбора — на один образ. Ключ id(img) после освобождения образа может достаться следующему
    #   (ложное попадание в чужой кэш) и держит память всех 5 образов — чистим по окончании образа.
    _SWEEP.clear()
    _REFS.clear()
    return ref


def main():
    print("DLL: %s" % DLL)
    syms = map_syms(MAP)
    ok(all(syms.values()), "символы из .map: %s" % ", ".join("%s=0x%08X" % (k, v or 0) for k, v in syms.items()))
    dpe, dimg, dbase = load(DLL)
    ins = dis(dimg, dbase, syms["St18_AttackWait"], 5, 0x20)
    got = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
    want = ["sub eax, dword ptr [esi + 0x7a68]", "test ecx, ecx", "jle", "cmp eax, ecx", "ret"]
    good = len(got) == 5 and got[0] == want[0] and got[1] == want[1] and got[2].startswith("jle") and got[3] == want[3] and got[4].strip() == "ret"
    good = good and int(ins[2].op_str, 16) == ins[4].address
    ok(good, "стаб St18_AttackWait @0x%08X: %s — стек: call/ret без локальных; jle → ret (CF = 0 после test)" % (syms["St18_AttackWait"], "; ".join(got)))
    # таблица площадок в исходнике = таблица скрипта
    src = parse_cpp_areas(SRC)
    mine = [(g, va, hexb(h), [tuple(e) for e in ed]) for g, va, h, ed, _, _, _ in AREAS]
    ok(src == mine, "kAreas в n18_tick_signed.cpp (%d площадок, %d правок) = таблица скрипта" % (len(src), sum(len(e[3]) for e in src)))
    txt = open(SRC, encoding="utf-8").read()
    ok("kAwSub = 0x4390B0" in txt and "kAwCmp = 0x4390B7" in txt and "kAwJl  = 0x4390B9" in txt and "WriteCall(kAwSub" in txt,
       "Г3 в исходнике: call @0x4390B0 (6 б), nop×2 @0x4390B7, jb @0x4390B9+1")
    ref = None
    for name, path, md5_want in IMAGES:
        ref = check_image(name, path, md5_want, dimg, dbase, syms, ref)
    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК: %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
