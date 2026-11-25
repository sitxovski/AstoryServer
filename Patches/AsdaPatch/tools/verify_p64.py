# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p64.py — СТАТИЧЕСКАЯ проверка P64 «общая преамбула состояния персонажа» (античит A7, L4/A8, 2026-10-12).
#
# Сервер НЕ запускается. Своих площадок у P64 нет — он зовётся ВТОРЫМ (после P55) из C-гейта P47 (стаб 0x42AB4F). Проверяем:
#  1) байты площадки P47 0x42AB4F и соседей во всех образах (сток, живой GameServer, живой Indun); ветка userNum < 10000;
#     в .text ни один rel8/rel32/jcc32/abs32 не ведёт ВНУТРЬ площадки; границы инструкций;
#  2) ОПОРНЫЕ ИНСТРУКЦИИ стоковых предикатов (откуда сняты смещения полей CUser) — байты совпадают во всех образах, и тела
#     предикатов sub_4CB030 / sub_52EEA0 / sub_52EE40 / sub_532670 / sub_52BFF0 / sub_5324A0 побайтно одинаковы в трёх образах;
#     писатели полей (sub_4CB070 +0x4F, CharExchangeAcceptReq +0x145, sub_521980 +0x15F, CharSelfStoreReady +0x14D,
#     Recv_StartFishing +0x3F6B4, ClearUserMemory sub_4A2DC0 +0x4F) — те же байты;
#  3) sub_52BFF0 шлёт 6001 (push 0x1771 → call sub_4C28F0) на КАЖДОЙ ветке, включая код 0 → из гейта его звать нельзя
#     (доказательство выбора «чистых чтений»);
#  4) в DLL: GateStub найден, `jmp [..]` → 0x42AB5C / 0x42F036, call → P47_OperatorGate внутри DLL; ПЕРВЫЙ call внутри
#     P47_OperatorGate → P55_PacketGate, ВТОРОЙ → P64_StateGate (оба внутри DLL, разные адреса); P64_StateGate ссылается
#     на sub_5324A0 (GetUser; прямо или через ячейку) и на таблицы g_family/g_mask (.data DLL); экспорт P64_GetStats /
#     P64_ResetState / P64_QueryOpcode; секция P64_StatePreamble в реестре ПОСЛЕ P59_RareDropJournal; тексты видов 40…44
#     в AcJournal; все 9 опорных байт-последовательностей присутствуют в DLL (константы сверки при установке).
#  5) списки опкодов по умолчанию: каждый опкод из шаблона ini есть в дереве диспетчера GameServer.c (sub_42A9D0) и
#     у него в диспетчере НЕТ гейта sub_52EEA0; опкоды «стоковый занят» действительно зовут sub_52BFF0 (по GameServer.c).
# ★ fix13 (13.10.2026): GateStub, P47_OperatorGate, P55_PacketGate, P64_StateGate, ReadState, g_family/g_mask, экспорт —
#   по MAP компоновщика (asdamap: имя + объект, метка MAP↔PE); сигнатура и цели вызовов — второй метод.
# Запуск: py -3.13 verify_p64.py [AsdaPatch.dll]   (образы: переменная ASDA_GS_IMG_DIR или wA7_logs\img)
import os
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
IMG_DIR = os.environ.get("ASDA_GS_IMG_DIR", os.path.join(HERE, "..", "..", "..", "..", "Reports", "anticheat", "wA7_logs", "img"))
GS_IMAGES = [
    ("сток", os.path.join(IMG_DIR, "gs_stock.exe")),
    ("живой GameServer", os.path.join(IMG_DIR, "gs_live.exe")),
    ("живой Indun", os.path.join(IMG_DIR, "gs_indun.exe")),
]
GS_C = os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.c")
CFG = os.path.join(HERE, "..", "src", "Config.cpp")
P64 = os.path.join(HERE, "..", "src", "patches", "p64_state_preamble.cpp")

SITES = [("P47.gate", 0x0042AB4F, "8b45fc0fb74807898d38efffff")]
NEIGHBOURS = [
    ("ветка userNum<10000: jge 0x42F0BC @0x42AA80", 0x0042AA80, "0f8d36460000"),
    ("ret gate 0x42AB5C (дерево сравнений / P01)",   0x0042AB5C, "81bd38efffff75170000"),
    ("хвост switch 0x42F036",                        0x0042F036, "ff1528305800"),
    ("sub_5324A0 GetUser (пролог)",                   0x005324A0, "558bec"),
]
# Опорные инструкции предикатов (смещения полей CUser) — те же константы, что в p64_state_preamble.cpp.
REFS = [
    ("sub_4CB030 +0x4F мёртв",          0x004CB05D, "8b514f"),
    ("sub_52EEA0 +0x182D3 душа",        0x0052EECD, "0fb691d3820100"),
    ("sub_52EE40 +0x182B9 соулмейт",    0x0052EE6D, "83b9b982010000"),
    ("sub_52EE40 +0x182D3 == 2",        0x0052EE79, "0fb682d3820100"),
    ("sub_532670 +0x190 в игре",        0x0053269D, "8a8190010000"),
    ("sub_52BFF0 +0x145 обмен (код 2)", 0x0052C070, "83b84501000000"),
    ("sub_52BFF0 +0x15F биржа (код 3)", 0x0052C0A6, "83b95f01000000"),
    ("sub_52BFF0 +0x14D лавка (код 4)", 0x0052C0DC, "83ba4d01000000"),
    ("sub_52BFF0 +0x3F6B4 рыбалка (5)", 0x0052C10F, "0fb688b4f60300"),
]
WRITERS = [
    ("sub_4CB070 +0x4F = a3 (CharMake тип 3 → 1 / CharRegen* → 0)", 0x004CB0E7, "89484f"),
    ("ClearUserMemory sub_4A2DC0 +0x4F = 0",                         0x004A33EC, "c744024f00000000"),
    ("CharExchangeAcceptReq +0x145 = 1",                              0x004DFF27, "c7814501000001000000"),
    ("sub_521980 +0x15F = a4 (биржа: запрос в полёте)",              0x005219AE, "89915f010000"),
    ("CharSelfStoreReady +0x14D = 1",                                 0x00502D8C, "c7804d01000001000000"),
    ("Recv_StartFishing +0x3F6B4 = 1",                                0x0040F292, "c681b4f6030001"),
]
BODIES = [("sub_4CB030", 0x4CB030, 0x3C), ("sub_52EEA0", 0x52EEA0, 0x48), ("sub_52EE40", 0x52EE40, 0x54),
          ("sub_532670", 0x532670, 0x38), ("sub_52BFF0", 0x52BFF0, 0x180), ("sub_5324A0", 0x5324A0, 0x50)]
STOCK_BUSY = [6162, 6502, 6506, 4201, 4203, 6158, 6165, 6176]
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


def stub_targets(img, base, va, njmp=1):
    jmps, calls = [], []
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic in ("ret", "int3") or len(jmps) >= njmp:
            break
    return jmps, calls


def func_refs(img, base, va, maxlen=0x600):
    calls, abs32 = [], set()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for ins in md.disasm(bytes(img[va - base: va - base + maxlen]), va):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        for op in ins.operands:
            if op.type == 2 and op.imm:
                abs32.add(op.imm & 0xFFFFFFFF)
            if op.type == 3 and op.mem.disp:
                abs32.add(op.mem.disp & 0xFFFFFFFF)
        if ins.mnemonic == "ret":
            break
    return calls, abs32


def sub_52bff0_sends_on_every_branch(img, base):
    """Каждая из 6 веток sub_52BFF0 (код 1..5 и 0) делает push 0x1771 (6001) и call sub_4C28F0."""
    pushes, calls = 0, 0
    for ins in disasm(img, base, 0x52BFF0, 0x180):
        if ins.mnemonic == "push" and ins.op_str == "0x1771":
            pushes += 1
        if ins.mnemonic == "call" and ins.op_str == "0x4c28f0":
            calls += 1
        if ins.mnemonic == "ret":
            break
    return pushes, calls


def dispatcher_opcodes(src):
    """Опкод → (есть ли sub_52EEA0 в его блоке диспетчера, имя обработчика) по GameServer.c sub_42A9D0."""
    lines = src.split("\n")
    lo = next(i for i, l in enumerate(lines) if l.startswith("//---- sub_42A9D0 @"))
    hi = next(i for i in range(lo + 1, len(lines)) if lines[i].startswith("//---- "))
    cur, blocks = None, {}
    for i in range(lo, hi):
        l = lines[i]
        m = re.search(r"case (0x[0-9A-Fa-f]+|\d+):", l)
        m2 = re.search(r"v4 == (\d+)", l)
        if m:
            cur = int(m.group(1), 0)
        elif m2:
            cur = int(m2.group(1))
        if cur is None:
            continue
        blocks.setdefault(cur, []).append(l)
    out = {}
    for op, b in blocks.items():
        soul = any("sub_52EEA0" in l for l in b)
        hnd = None
        for l in b:
            m = re.match(r"^\s*(?:LOBYTE\(\w+\) = |\w+ = )?([A-Za-z_]\w*)\(", l)
            if m and m.group(1) not in ("if", "switch", "sub_52EEA0", "sub_52BFF0", "sub_52EE40", "sub_532670", "sub_52ECF0", "sub_521980", "sub_4CB030"):
                hnd = m.group(1)
                break
        out[op] = (soul, hnd)
    return out


def main():
    # ── 1. площадка P47 во всех образах; 2. опорные инструкции и тела предикатов ─────────────
    ref = None
    bodies_ref = {}
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if ref is None:
            ref = (pe, img, base)
        for n, va, o in SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "%-9s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        for n, c in scan_into(pe, img, base, SITES).items():
            ok(c == 0, "%-9s входов внутрь площадки: %d" % (n, c))
        s, e = boundary_ok(img, base, 0x0042AB4F, 13)
        ok(s and e, "границы инструкций площадки: начало %s, конец %s" % (s, e))
        for n, va, o in REFS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "опорная: %-34s @0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in WRITERS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "писатель: %-50s @0x%08X = %s" % (n, va, cur.hex()))
        for n, va, ln in BODIES:
            body = bytes(img[va - base: va - base + ln])
            if n not in bodies_ref:
                bodies_ref[n] = body
            ok(body == bodies_ref[n], "тело %s (0x%X б) совпадает со стоком" % (n, ln))
        p, c = sub_52bff0_sends_on_every_branch(img, base)
        ok(p == 6 and c == 6, "sub_52BFF0: push 0x1771 (6001) ×%d, call sub_4C28F0 ×%d — шлёт на всех 6 ветках (в т.ч. код 0) → из гейта не зовём" % (p, c))
    pe, img, base = ref

    # ── 4. DLL ───────────────────────────────────────────────────────────────
    print("-- DLL %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    # ★ fix13: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP) — имя И объект решают,
    #   сигнатура/цели вызовов — второй метод (стаб по MAP обязан быть среди кандидатов сигнатуры).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))

    def msym(name, obj=None):
        try:
            return dmap.sym(name, obj)
        except ValueError as e:
            ok(False, str(e))
            return None

    def sym_end(va):   # конец символа по MAP — начало следующего символа
        nxt = [s[0] for s in dmap.syms if s[0] > va]
        return min(nxt) if nxt else va + 0x1000
    c = find_all(limg, lbase, "8b45fc0fb74807898d38efffff60")
    va_g, good, msg = resolve(dmap, "GateStub", "p47_identity_operator_gate", c)
    ok(good, "GateStub P47 — " + msg)
    if not va_g:
        print("ИТОГ: ОШИБОК %d" % (bad + 1)); return 1
    jmps, calls = stub_targets(limg, lbase, va_g, 2)
    ok(jmps[:2] == [0x0042AB5C, 0x0042F036], "GateStub: jmp [..] -> %s (ожид. 0x42AB5C, 0x42F036)" % ["0x%08X" % x for x in jmps])
    ok(len(calls) == 1 and lo <= calls[0] < hi, "GateStub: call P47_OperatorGate внутри DLL (0x%08X)" % (calls[0] if calls else 0))
    gate_map = msym("P47_OperatorGate", "p47_identity_operator_gate")
    ok(bool(calls) and calls[0] == gate_map, "GateStub: call → P47_OperatorGate по MAP (0x%08X)" % (gate_map or 0))
    gate = gate_map or calls[0]
    gcalls, gabs = func_refs(limg, lbase, gate)
    ok(len(gcalls) >= 2 and all(lo <= x < hi for x in gcalls[:2]), "P47_OperatorGate: первые два call внутрь DLL: %s" % ["0x%08X" % x for x in gcalls[:2]])
    ok(len(gcalls) >= 2 and gcalls[0] != gcalls[1], "P47_OperatorGate: ПЕРВЫЙ call (P55_PacketGate 0x%08X) ≠ ВТОРОЙ (P64_StateGate 0x%08X) — цепочка P55→P64" % (gcalls[0] if gcalls else 0, gcalls[1] if len(gcalls) > 1 else 0))
    p55_map = msym("P55_PacketGate", "p55_packet_validator")
    p64_map = msym("P64_StateGate", "p64_state_preamble")
    ok(gcalls[:2] == [p55_map, p64_map], "P47_OperatorGate: call по MAP — ПЕРВЫЙ P55_PacketGate 0x%08X (p55_packet_validator), ВТОРОЙ P64_StateGate 0x%08X (p64_state_preamble)" % (p55_map or 0, p64_map or 0))
    p64 = p64_map or (gcalls[1] if len(gcalls) > 1 else 0)
    pcalls, pabs = func_refs(limg, lbase, p64, 0x800)
    # Второй call — именно гейт состояния: его код (или вызываемый ReadState в окне ±0x1000) читает поля +0x4F/+0x145/+0x15F/+0x14D/+0x3F6B4/+0x182B9/+0x182D3/+0x190.
    win = bytes(limg[p64 - lbase - 0x1000: p64 - lbase + 0x1000])
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disps = set()
    for ins in md.disasm(win, p64 - 0x1000):
        m = re.search(r"\+ 0x([0-9a-f]+)\]", ins.op_str)
        if m:
            disps.add(int(m.group(1), 16))
    need = {0x4F, 0x145, 0x15F, 0x14D, 0x3F6B4, 0x182B9, 0x182D3, 0x190}
    ok(need <= disps, "код P64 (окно ±0x1000 от второго call) читает все 8 смещений CUser: нет %s" % sorted(hex(x) for x in need - disps))
    direct = win.find(struct.pack("<I", 0x005324A0)) >= 0
    cells = find_all(limg, lbase, struct.pack("<I", 0x005324A0).hex())
    indirect = any(win.find(struct.pack("<I", cc)) >= 0 for cc in cells)
    ok(direct or indirect, "код P64 ссылается на sub_5324A0 (GetUser): прямо %s / через ячейку %s" % (direct, indirect))
    # ★ fix13: то же точно по MAP — тела P64_StateGate и ReadState (p64_state_preamble.obj) от символа до следующего.
    rs = msym("ReadState", "p64_state_preamble")
    mbody = b""
    for fv in (p64_map, rs):
        if fv:
            mbody += bytes(limg[fv - lbase: sym_end(fv) - lbase])
    mdisps = set()
    for fv in (p64_map, rs):
        if fv:
            for ins in md.disasm(bytes(limg[fv - lbase: sym_end(fv) - lbase]), fv):
                m = re.search(r"\+ 0x([0-9a-f]+)\]", ins.op_str)
                if m:
                    mdisps.add(int(m.group(1), 16))
    ok(need <= mdisps, "P64_StateGate+ReadState (MAP 0x%08X, 0x%08X) читают все 8 смещений CUser: нет %s" % (p64_map or 0, rs or 0, sorted(hex(x) for x in need - mdisps)))
    d2 = mbody.find(struct.pack("<I", 0x005324A0)) >= 0
    i2 = any(mbody.find(struct.pack("<I", cc)) >= 0 for cc in cells)
    ok(d2 or i2, "P64_StateGate+ReadState (MAP) ссылаются на sub_5324A0 (GetUser): прямо %s / через ячейку %s" % (d2, i2))
    gb = bytes(limg[p64 - lbase: sym_end(p64) - lbase])
    for tn in ("g_family", "g_mask"):
        tv = msym(tn, "p64_state_preamble")
        ok(tv is not None and gb.find(struct.pack("<I", tv)) >= 0, "P64_StateGate ссылается на таблицу %s (MAP 0x%08X, .data p64_state_preamble)" % (tn, tv or 0))
    ok(0x0042AB4F in pabs or win.find(struct.pack("<I", 0x0042AB4F)) >= 0 or limg.find(struct.pack("<I", 0x0042AB4F)) >= 0, "DLL ссылается на площадку 0x42AB4F (проверка jmp при установке)")
    exports = set()
    if hasattr(lpe, "DIRECTORY_ENTRY_EXPORT"):
        exports = {e.name.decode() for e in lpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    ok(all(any(k in e for e in exports) for k in ("P64_GetStats", "P64_ResetState", "P64_QueryOpcode")), "экспорт P64_GetStats/P64_ResetState/P64_QueryOpcode: %s" % sorted(e for e in exports if "P64" in e))
    # ★ fix13: экспорт указывает на функции p64_state_preamble.obj по MAP
    erva = {e.name.decode(): e.address for e in lpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(lpe, "DIRECTORY_ENTRY_EXPORT") else {}
    for en in ("P64_GetStats", "P64_ResetState", "P64_QueryOpcode"):
        mv = msym(en, "p64_state_preamble")
        ev = [lbase + r for k, r in erva.items() if en in k]
        ok(mv is not None and ev == [mv], "экспорт %s = MAP 0x%08X (экспорт %s)" % (en, mv or 0, ["0x%08X" % x for x in ev]))
    raw = bytes(limg)
    s64 = raw.find("P64_StatePreamble".encode("utf-16-le"))
    s59 = raw.find("P59_RareDropJournal".encode("utf-16-le"))
    ok(s64 >= 0 and s59 >= 0, "секции P64_StatePreamble / P59_RareDropJournal в DLL")
    # порядок в реестре: запись {section, title, fn, hosts} — ищем указатели на строки секций
    def entry_pos(str_off):
        va = lbase + str_off
        hits = find_all(limg, lbase, struct.pack("<I", va).hex())
        # запись реестра: за указателем на секцию идёт указатель на title (в образе) и fn (в .text)
        tl, th = text_range(lpe)
        for h in hits:
            i = h - lbase
            title = struct.unpack("<I", raw[i + 4:i + 8])[0]
            fn = struct.unpack("<I", raw[i + 8:i + 12])[0]
            if lo <= title < hi and lbase + tl <= fn < lbase + th:
                return h
        return None
    e59, e64 = entry_pos(s59), entry_pos(s64)
    # ★ integ2b: требование реестра — P64 ПОСЛЕ P47 (стаб 0x42AB4F), P53 (журнал) и P55 (первый в гейте); «сразу после
    #   P59» было верно только в копии w60_p64 — в слитом реестре между ними P60…P63.
    def entry_of(name):   # первая wide-строка name, на которую указывает запись реестра (строка встречается и в других местах)
        needle, k = (name + "\0").encode("utf-16-le"), -1
        while True:
            k = raw.find(needle, k + 1)
            if k < 0:
                return None
            e = entry_pos(k)
            if e is not None:
                return e
    e47, e53, e55 = entry_of("P47_IdentityOperatorGate"), entry_of("P53_AcJournal"), entry_of("P55_PacketValidator")
    ok(None not in (e47, e53, e55, e64) and e64 > e47 and e64 > e53 and e64 > e55 and (e64 - e55) % 16 == 0,
       "реестр: P64 (0x%08X) ПОСЛЕ P47 (0x%08X), P53 (0x%08X), P55 (0x%08X); P59 (0x%08X) — порядок слитого реестра"
       % (e64 or 0, e47 or 0, e53 or 0, e55 or 0, e59 or 0))
    for k in ("P64: не в игре", "P64: мёртв", "P64: занят", "P64: «душа»", "P64: одержим"):
        ok(raw.find(k.encode("utf-16-le")) >= 0, "AcJournal: текст вида «%s»" % k)
    for n, va, o in REFS:
        ok(raw.find(bytes.fromhex(o)) >= 0, "константа опорной инструкции в DLL: %s" % n)
    ok(raw.find("ac.other".encode("utf-16-le")) >= 0, "имя таблицы ac.other в AcJournal (DLL)")

    # ── 5. списки по умолчанию против дерева диспетчера ───────────────────────
    print("-- списки опкодов по умолчанию (Config.cpp) против диспетчера GameServer.c")
    src = open(GS_C, encoding="utf-8", errors="replace").read()
    disp = dispatcher_opcodes(src)
    cfg = open(CFG, encoding="utf-8-sig", errors="replace").read()
    fams = {}
    for key in ("OpcodesEconomy", "OpcodesPets", "OpcodesCombat", "OpcodesFishing", "OpcodesQuest", "OpcodesMisc"):
        m = re.search(r'L"%s",\s*L"([0-9;]+)"' % key, cfg)
        fams[key] = [int(x) for x in m.group(1).split(";")] if m else []
        ok(bool(fams[key]), "%s: %d опкодов в шаблоне" % (key, len(fams[key])))
    allops = [o for v in fams.values() for o in v]
    ok(len(allops) == len(set(allops)), "опкоды в семьях не повторяются (%d)" % len(allops))
    for op in allops:
        d = disp.get(op)
        ok(d is not None, "опкод %d есть в дереве диспетчера (%s)" % (op, d[1] if d else "?"))
        if d:
            ok(not d[0], "опкод %d (%s): в диспетчере НЕТ гейта sub_52EEA0 (сток не гейтит)" % (op, d[1]))
    # «стоковый занят»: обработчик зовёт sub_52BFF0
    funcs = {}
    parts = re.split(r"^//---- (\S+) @ (0x[0-9A-Fa-f]+) ----\s*$", src, flags=re.M)
    for i in range(1, len(parts), 3):
        funcs[parts[i]] = parts[i + 2]
    for op in STOCK_BUSY:
        d = disp.get(op)
        body = funcs.get(d[1], "") if d else ""
        ok("sub_52BFF0(" in body, "стоковый «занят» у %d (%s): sub_52BFF0 внутри обработчика" % (op, d[1] if d else "?"))
    # и наоборот: у остальных опкодов списка sub_52BFF0 в обработчике НЕТ (иначе их надо в kStockBusy)
    for op in allops:
        if op in STOCK_BUSY:
            continue
        d = disp.get(op)
        body = funcs.get(d[1], "") if d else ""
        ok("sub_52BFF0(" not in body, "у %d (%s) sub_52BFF0 в обработчике нет — преамбула не дублирует сток" % (op, d[1] if d else "?"))
    p64src = open(P64, encoding="utf-8", errors="replace").read()
    m = re.search(r"kStockBusy\[\] = \{([^}]*)\}", p64src)
    ok(m is not None and sorted(int(x) for x in re.findall(r"\d+", m.group(1))) == sorted(STOCK_BUSY), "kStockBusy в p64_state_preamble.cpp = %s" % sorted(STOCK_BUSY))

    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
