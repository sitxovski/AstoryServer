# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p55.py — СТАТИЧЕСКАЯ проверка P55 «общий валидатор пакетов» (античит В4, 2026-10-12).
#
# Сервер НЕ запускается. Своих площадок у P55 нет — он зовётся из C-гейта P47 (стаб 0x42AB4F). Проверяем:
#  1) байты площадки P47 0x42AB4F и соседей (возврат 0x42AB5C, хвост 0x42F036, sub_524540, sub_5324A0) во всех
#     образах (сток, живой GameServer, живой Indun); площадка в ветке userNum < 10000 (jge 0x42F0BC @0x42AA80);
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадки; границы инструкций;
#  3) в DLL: GateStub найден, `jmp [..]` → 0x42AB5C / 0x42F036, call → P47_OperatorGate внутри DLL;
#     первый call внутри P47_OperatorGate → P55_PacketGate (внутри DLL); P55_PacketGate ссылается на
#     таблицу OpcodeLengths (kIndex) и на sub_524540 (Hack Packet) / sub_5324A0 (GetUser);
#     экспорт P55_GetStats / P55_ResetState; секция P55_PacketValidator в реестре;
#  4) таблица длин воспроизводима: генератор по GameServer.c даёт тот же OpcodeLengths.h (байт в байт);
#     выборочные записи сверены с декомпилом (10 опкодов: аргумент sub_523F00 + вид конверта).
# ★ fix13 (13.10.2026): стабы/функции/таблица kIndex в DLL привязаны по MAP компоновщика (asdamap: имя + объект,
#   метка MAP↔PE); сигнатура и цели вызовов — второй метод.
# Запуск: py -3.13 verify_p55.py [AsdaPatch.dll]
import os
import re
import struct
import subprocess
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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
GS_C = os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.c")
HDR = os.path.join(HERE, "..", "src", "OpcodeLengths.h")

SITES = [("P47.gate", 0x0042AB4F, "8b45fc0fb74807898d38efffff")]
NEIGHBOURS = [
    ("ветка userNum<10000: jge 0x42F0BC @0x42AA80", 0x0042AA80, "0f8d36460000"),
    ("ret gate 0x42AB5C (дерево сравнений / P01)",   0x0042AB5C, "81bd38efffff75170000"),
    ("хвост switch 0x42F036",                        0x0042F036, "ff1528305800"),
    ("sub_524540 Hack Packet ++ (пролог)",            0x00524540, "558bec83ec08"),
    ("sub_5324A0 GetUser (пролог)",                   0x005324A0, "558bec"),
    ("sub_523F00 PktSignCheck (пролог)",              0x00523F00, "558bec83ec34"),
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


def func_refs(img, base, va, maxlen=0x600, dmap=None):
    """Адреса call rel32 и абсолютные imm32/disp32 внутри функции (до первого ret на границе).
    ★ sec2 (15.10.2026): с dmap — вся функция по MAP (до следующего символа): у P55_PacketGate после учёта доли счётчиков кика
    компилятор поставил ранний `ret` (выход «нарушений нет») раньше ссылок на kIndex/sub_524540 — «до первого ret» их не видел."""
    calls, abs32 = [], set()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    own = dmap.owner(va)[0] if dmap is not None else None
    for ins in md.disasm(bytes(img[va - base: va - base + maxlen]), va):
        if own is not None and dmap.owner(ins.address)[0] != own:
            break
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        for op in ins.operands:
            if op.type == 2 and op.imm:          # X86_OP_IMM
                abs32.add(op.imm & 0xFFFFFFFF)
            if op.type == 3 and op.mem.disp:     # X86_OP_MEM
                abs32.add(op.mem.disp & 0xFFFFFFFF)
        if own is None and ins.mnemonic == "ret":
            break
    return calls, abs32


def main():
    # ── 1–2. площадка P47 во всех образах ───────────────────────────────────
    ref = None
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
        print("-- перебор кодировок переходов/abs32 внутрь площадки (%s)" % name)
        for n, c in scan_into(pe, img, base, SITES).items():
            ok(c == 0, "%-9s входов внутрь: %d" % (n, c))
        s, e = boundary_ok(img, base, 0x0042AB4F, 13)
        ok(s and e, "границы инструкций площадки: начало %s, конец %s" % (s, e))
    pe, img, base = ref

    # ── 3. DLL ───────────────────────────────────────────────────────────────
    print("-- DLL %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    # ★ fix13: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP) — имя И объект решают,
    #   сигнатура/цели вызовов — второй метод (стаб по MAP обязан быть среди кандидатов сигнатуры). Таблица kIndex
    #   есть в DLL ДВАЖДЫ (constexpr OpcodeLengths.h в p55 и p64) — поиск по содержимому брал первую попавшуюся.
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
    ok(len(gcalls) >= 1 and lo <= gcalls[0] < hi, "P47_OperatorGate: ПЕРВЫЙ call — внутрь DLL (0x%08X) = P55_PacketGate" % (gcalls[0] if gcalls else 0))
    p55_map = msym("P55_PacketGate", "p55_packet_validator")
    ok(bool(gcalls) and gcalls[0] == p55_map, "P47_OperatorGate: ПЕРВЫЙ call = P55_PacketGate по MAP (0x%08X, p55_packet_validator.obj)" % (p55_map or 0))
    p55 = p55_map or (gcalls[0] if gcalls else 0)
    pcalls, pabs = func_refs(limg, lbase, p55, 0x1000, dmap if p55_map else None)   # ★ sec2: вся функция по MAP
    # таблица длин: kIndex (WORD[0x2B00]) лежит в .rdata DLL — адрес по MAP (kIndex@p55_packet_validator), содержимое = OpcodeLengths.h
    hdr = open(HDR, encoding="utf-8").read()
    m = re.search(r"kIndex\[kOpcodeMax\] =\s*\{(.*?)\};", hdr, flags=re.S)
    idx = [int(x) for x in re.findall(r"\d+", m.group(1))]
    ok(len(idx) == 0x2B00, "OpcodeLengths.h: kIndex содержит %d записей (0x2B00)" % len(idx))
    sig = struct.pack("<%dH" % len(idx), *idx)
    kc = find_all(limg, lbase, sig.hex())
    kidx = msym("kIndex", "p55_packet_validator") or 0
    others = [(k, dmap.owner(k)) for k in kc if k != kidx]
    ok(kidx in kc and all(o[1] and "p55_packet_validator" not in o[1].lower() for _, o in others),
       "kIndex: MAP 0x%08X (p55_packet_validator), содержимое = OpcodeLengths.h %s; прочие кандидаты по содержимому %d — %s" % (
           kidx, kidx in kc, len(others), ", ".join("0x%08X %s" % (k, o[1]) for k, o in others) or "нет"))
    ok(kidx in pabs or any(abs(a - kidx) < 0x10000 and a in pabs for a in (kidx,)), "P55_PacketGate ссылается на kIndex 0x%08X" % kidx)
    ok(0x00524540 in pabs or 0x00524540 in pcalls, "P55_PacketGate ссылается на sub_524540 (Hack Packet ++)")
    # Report() — отдельная функция с несколькими выходами (первый ret не конец): ищем ссылку на sub_5324A0
    # в окне кода P55 (от P55_PacketGate до +0x1000) по всем imm32/disp32.
    # Report() лежит ПЕРЕД P55_PacketGate (порядок в исходнике) — окно ±0x1000.
    #   /O2 зовёт константный указатель через ячейку .rdata (`call dword ptr [X]`, *X = 0x5324A0) — принимаем и так.
    win = bytes(limg[p55 - lbase - 0x1000: p55 - lbase + 0x1000])
    direct = win.find(struct.pack("<I", 0x005324A0)) >= 0
    cells = [c for c in find_all(limg, lbase, struct.pack("<I", 0x005324A0).hex())]
    indirect = any(win.find(struct.pack("<I", c)) >= 0 for c in cells)
    ok(direct or indirect, "код P55 (окно ±0x1000 от P55_PacketGate) ссылается на sub_5324A0 (GetUser): прямо %s / через ячейку %s" % (direct, indirect))
    # ★ fix13: то же точно — тело Report@p55_packet_validator по MAP (от символа до следующего).
    rep = msym("Report", "p55_packet_validator")
    if rep:
        body = bytes(limg[rep - lbase: sym_end(rep) - lbase])
        d2 = body.find(struct.pack("<I", 0x005324A0)) >= 0
        i2 = any(body.find(struct.pack("<I", c)) >= 0 for c in cells)
        # ★ autoban (2026-10-14): Report читает CUser через общую точку P69_ResolveSession (учётка СЕССИИ, P48_IdentityOf) —
        #   sub_5324A0 зовёт она. Принимаем: прямо/через ячейку в Report ИЛИ call из Report в P69_ResolveSession, тело которой
        #   ссылается на sub_5324A0.
        rs = None
        try:
            rs = dmap.sym("P69_ResolveSession", "p69_integrity_autoblock")
        except ValueError:
            rs = None
        via = False
        if rs:
            calls = [rep + i + 5 + struct.unpack_from("<i", body, i + 1)[0] for i in range(len(body) - 5) if body[i] == 0xE8]
            rbody = bytes(limg[rs - lbase: sym_end(rs) - lbase])
            via = rs in calls and (rbody.find(struct.pack("<I", 0x005324A0)) >= 0 or any(rbody.find(struct.pack("<I", c)) >= 0 for c in cells))
        ok(d2 or i2 or via, "Report (MAP 0x%08X..0x%08X, p55_packet_validator) ссылается на sub_5324A0: прямо %s / через ячейку %s / "
           "через P69_ResolveSession %s" % (rep, sym_end(rep), d2, i2, via))
    exports = set()
    if hasattr(lpe, "DIRECTORY_ENTRY_EXPORT"):
        exports = {e.name.decode() for e in lpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    ok(any("P55_GetStats" in e for e in exports) and any("P55_ResetState" in e for e in exports), "экспорт P55_GetStats/P55_ResetState: %s" % sorted(e for e in exports if "P55" in e))
    # ★ fix13: экспорт указывает на функции p55_packet_validator.obj по MAP
    erva = {e.name.decode(): e.address for e in lpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(lpe, "DIRECTORY_ENTRY_EXPORT") else {}
    for en in ("P55_GetStats", "P55_ResetState"):
        mv = msym(en, "p55_packet_validator")
        ev = [lbase + r for k, r in erva.items() if en in k]
        ok(mv is not None and ev == [mv], "экспорт %s = MAP 0x%08X (экспорт %s)" % (en, mv or 0, ["0x%08X" % x for x in ev]))
    ok(bytes(limg).find("P55_PacketValidator".encode("utf-16-le")) >= 0, "секция P55_PacketValidator в реестре DLL")
    ok(bytes(limg).find("ac.packet_validator".encode("utf-16-le")) >= 0, "имя таблицы ac.packet_validator в AcJournal (DLL)")
    n_info = len(re.findall(r"^\s*\{\s*\d+,\s*\d+,\s*\d+,\s*\d+,\s*\d,\s*\"", hdr, flags=re.M))
    print("   записей в kInfo (опкодов с длиной): %d" % n_info)

    # ── 4. воспроизводимость таблицы и выборочная сверка с декомпилом ─────────
    print("-- таблица длин: воспроизводимость генератора")
    tmp_h = os.path.join(HERE, "obj_verify_OpcodeLengths.h")
    tmp_md = os.path.join(HERE, "obj_verify_coverage.md")
    r = subprocess.run([sys.executable, os.path.join(HERE, "gen_opcode_lengths.py"), GS_C, tmp_h, tmp_md], capture_output=True, text=True, encoding="utf-8", errors="replace")
    ok(r.returncode == 0, "генератор отработал: %s" % r.stdout.strip().splitlines()[0][:120] if r.stdout else "нет вывода")
    same = open(tmp_h, "rb").read() == open(HDR, "rb").read()
    ok(same, "OpcodeLengths.h байт в байт совпадает с перегенерированным из GameServer.c")
    for f in (tmp_h, tmp_md):
        try:
            os.remove(f)
        except OSError:
            pass
    src = open(GS_C, encoding="utf-8", errors="replace").read()
    funcs = {}
    parts = re.split(r"^//---- (\S+) @ (0x[0-9A-Fa-f]+) ----\s*$", src, flags=re.M)
    for i in range(1, len(parts), 3):
        funcs[parts[i]] = parts[i + 2]
    checks = [   # (опкод, обработчик, LEN, секрет) — руками по декомпилу
        (4006, "CharMove", 0x1B, 0), (5020, "CharItemBuy", 0x2A, 1), (4001, "CharLogonReq", 0xC, 1),
        (5058, "CharPortalLogonReq", 0x15, 1), (6146, "RecvClient_TargetJump", 0x1B, 1), (5090, "sub_44F4C0", 3, 0),
        (9903, "Recv_TransAction_InqueryItemReq", 0x17, 1), (6504, "CharShellItemUpgrade_0", 0xC, 1),
        (3410, "Recv_Client_AddMember", 0x20, 1), (6005, "Send_HideCommand", 2, 1),
    ]
    for op, fn, ln, sec in checks:
        row = re.search(r"\{\s*%d,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d),\s*\"%s\"" % (op, re.escape(fn)), hdr)
        found = re.findall(r"sub_523F00\([^;]*?,\s*(0x[0-9A-Fa-f]+|\d+)u?,\s*\(?\s*[A-Za-z_]\w*\s*\)?\s*,\s*(\d)\s*\)", funcs.get(fn, ""))
        dec = {(int(a, 16) if a.lower().startswith("0x") else int(a), int(b)) for a, b in found}
        want_min = 9 + (8 if sec else 0) + 16 + ln + 1
        ok(row is not None and int(row.group(1)) == want_min and int(row.group(3)) == sec and (ln, sec) in dec,
           "%5d %-32s декомпил LEN=%s secret=%s → min %d; таблица min %s secret %s" % (
               op, fn, hex(ln), sec, want_min, row.group(1) if row else "?", row.group(3) if row else "?"))

    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
