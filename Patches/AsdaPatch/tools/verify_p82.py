# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p82.py — СТАТИЧЕСКАЯ проверка P82 FuncCoolTimeExt (откат функциональных предметов с кодом >= 600, 2026-10-24).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) все функции стоковой таблицы отката (sub_4F24E0/sub_4F2640/sub_4F2710/sub_4F27F0, charLogonCoolTimeSaveRes,
#     charPortalLogonCoolTimeSaveRes, sub_52EEF0, ClearUserMemory, TimerProcess) побайтно одинаковы в трёх образах;
#  2) ★ ВТОРОЙ МЕТОД полноты: линейный дизасм всего .text — каждая инструкция с адресацией CUser+0x3BC41/+0x3BC45/+0x3BC49
#     (поля таблицы отката по коду) лежит в одной из известных 9 функций-пользователей; в sub_4F27F0/sub_4F2640/sub_4F24E0/
#     sub_4F2710 — предел `0x258`;
#  3) площадки C/G/T/S/R1/R2/Z и соседи — байты как в исходнике p82; площадки — начала инструкций; ни один rel8/rel32/jcc32
#     из .text и ни один abs32 не ведёт ВНУТРЬ площадок;
#  4) площадки P82 не пересекаются с адресами, которые называют другие патчи (площадки P75 0x4EDDC7/0x4EF606, P63/P75 0x527374);
#  5) DLL: MAP — Tramp*, _P82_*@N (stdcall), P82_GetStats; трампы выходят ТОЛЬКО на стоковые адреса и зовут ровно одну свою функцию;
#  6) исходники: kVersion 54, секция [P82_FuncCoolTimeExt] с ключами, виды журнала 91/92/93 — P82, P82 после P81 в реестре.
# Поведение (проверка/регистрация/такт/сохранение/восстановление/сброс, страж) — стенд tools/stand_p82.
# Запуск: python verify_p82.py [AsdaPatch.dll]   (образы — P82_IMG_DIR / P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
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
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
from srv_paths import ROOT as SRV_ROOT
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P82_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

# функции — пользователи таблицы CUser+0x3BC41 (12 б × 600)
FUNCS = {
    "ctor 0x4A0610":                 (0x004A0610, 0x004A0C60),
    "сброс sub_4A2DC0":              (0x004A2DC0, 0x004A4870),
    "такт sub_4F24E0":               (0x004F24E0, 0x004F2640),
    "регистрация sub_4F2640":        (0x004F2640, 0x004F2710),
    "снятие sub_4F2710":             (0x004F2710, 0x004F27F0),
    "проверка sub_4F27F0":           (0x004F27F0, 0x004F2850),
    "вход charLogonCoolTimeSaveRes": (0x00528EA0, 0x00529300),
    "портал charPortalLogon…":       (0x0052E030, 0x0052E520),
    "сохранение sub_52EEF0":         (0x0052EEF0, 0x0052F510),
}
SAME = list(FUNCS.values()) + [(0x00527350, 0x005273A4), (0x005431C0, 0x005433C0)]   # + ClearUserMemory, TimerProcess
FIELDS = (0x3BC41, 0x3BC45, 0x3BC49)
# площадки (va, исходные байты) — те же, что в src/patches/p82_func_cooltime_ext.cpp
SITES = {
    "C":  (0x004F2820, "817d0c580200007c04"),
    "G":  (0x004F2672, "817d0c580200007c05"),
    "T":  (0x00543353, "e888f1faff"),
    "S":  (0x0052F374, "e847530300"),
    "R1": (0x005290BE, "8b9510f9ffff"),
    "R2": (0x0052E23A, "8b9508f9ffff"),
    "Z":  (0x00527399, "e822baf7ff"),
}
NEIGHBORS = [
    (0x004F27F0, "558bec83ec08894df8"), (0x004F2829, "33c0eb1c"), (0x004F282D, "8b4d0c6bc90c"), (0x004F2849, "8be55dc20800"),
    (0x004F2640, "558bec83ec0856894df8"), (0x004F267B, "e989000000"), (0x004F2680, "8b4d0c6bc90c"), (0x004F2709, "5e8be55dc20800"),
    (0x00543348, "8b55f0668b420c508b4de8"), (0x004F24E0, "558bec83ec20"),
    (0x0052F34A, "668b4d08518d9528fdffff528b851cfcffff8b4804e8cc16f9ff50686e010000686d080000b938057e00"), (0x005646C0, "558bec"),
    (0x005290A9, "8b8d10f9ffff6bc90683bc0de1fdffff007d02ebcf"), (0x005290C4, "6bd2068b8415e1fdffff"), (0x0052908D, "8b8510f9ffff83c001"),
    (0x00528EB6, "898d0cf9ffff"), (0x00529115, "0fbf8c05e5fdffff"), (0x00529155, "8d8c054cffffff"),
    (0x0052E225, "8b8d08f9ffff6bc90683bc0dddfdffff007d02ebcf"), (0x0052E240, "6bd2068b8415ddfdffff"), (0x0052E209, "8b8508f9ffff83c001"),
    (0x0052E046, "898d04f9ffff"), (0x0052E291, "0fbf8c05e1fdffff"), (0x0052E2D1, "8d8c054cffffff"),
    (0x0052738B, "8a450c50668b4d0851b918ad6000"), (0x0052739E, "8be55dc20c00"), (0x004A2DC0, "558bec6aff"), (0x004DA920, "558bec83ec08"),
]
# трампы: выходы (стоковые адреса) и вызываемая функция (имя в MAP, число аргументов stdcall)
TRAMPS = {
    "TrampC":  ({0x004F2849, 0x004F282D}, "_P82_Check@12", 3),
    "TrampG":  ({0x004F2709, 0x004F2680}, "_P82_Register@12", 3),
    "TrampT":  ({0x004F24E0}, "_P82_Tick@8", 2),
    "TrampS":  ({0x005646C0}, "_P82_OnSave@12", 3),
    "TrampR1": ({0x0052908D, 0x005290C4}, "_P82_OnRestore@8", 2),
    "TrampR2": ({0x0052E209, 0x0052E240}, "_P82_OnRestore@8", 2),
    "TrampZ":  ({0x004A2DC0}, "_P82_OnUserClear@4", 1),
}
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


def disasm(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return list(md.disasm(bytes(img[lo - base:hi - base]), lo))


def scan_refs(pe, img, base, targets):
    a, b = text_range(pe)
    hits = {n: 0 for n in targets}
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
            for n, (lo, hi) in targets.items():
                if lo <= t < hi:
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, (lo, hi) in targets.items():
            if lo <= v < hi:
                hits[n] += 1
    return hits


def main():
    print("== verify_p82: DLL %s" % DLL)
    ref = None
    for idx, (title, path) in enumerate(GS_IMAGES):
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        body = b"".join(bytes(img[lo - base:hi - base]) for lo, hi in SAME)
        if ref is None:
            ref = body
        ok(body == ref, "функции таблицы отката + ClearUserMemory + TimerProcess побайтно совпадают с первым образом (%d б)" % len(body))
        g = lambda va, n: bytes(img[va - base:va - base + n])
        for n, (va, hx) in SITES.items():
            ok(g(va, len(hx) // 2).hex() == hx, "площадка %s 0x%08X: %s" % (n, va, hx))
        for va, hx in NEIGHBORS:
            ok(g(va, len(hx) // 2).hex() == hx, "сосед 0x%08X: байты стока" % va)
        starts = set()
        for lo, hi in SAME:
            starts |= {i.address for i in disasm(img, base, lo, hi)}
        for n, (va, hx) in SITES.items():
            ok(va in starts and (va + len(hx) // 2) in starts, "площадка %s: начало и конец — границы инструкций" % n)
        hits = scan_refs(pe, img, base, {n: (va + 1, va + len(hx) // 2) for n, (va, hx) in SITES.items()})
        for n in SITES:
            ok(hits[n] == 0, "%s: переходов/abs32 внутрь площадки нет (%d)" % (n, hits[n]))
        if idx == 1:
            # ★ второй метод полноты: все обращения к полям таблицы отката — только в 9 известных функциях
            a, b = text_range(pe)
            users = {}
            for ins in disasm(img, base, base + a, base + b):
                s = ins.op_str
                if any(("0x%x" % f) in s for f in FIELDS):
                    fn = [k for k, (lo, hi) in FUNCS.items() if lo <= ins.address < hi]
                    users.setdefault(fn[0] if fn else "НЕИЗВЕСТНО 0x%08X" % ins.address, 0)
                    users[fn[0] if fn else "НЕИЗВЕСТНО 0x%08X" % ins.address] += 1
            unknown = [k for k in users if k.startswith("НЕИЗВЕСТНО")]
            ok(not unknown, "все инструкции с CUser+0x3BC41/45/49 — в известных функциях: %s%s" % (
                ", ".join("%s ×%d" % (k, v) for k, v in users.items() if not k.startswith("НЕИЗВЕСТНО")),
                "" if not unknown else "; ЛИШНИЕ: " + ", ".join(unknown)))
            for k in ("такт sub_4F24E0", "регистрация sub_4F2640", "проверка sub_4F27F0", "снятие sub_4F2710"):
                lo, hi = FUNCS[k]
                ok(any(i.op_str.endswith(", 0x258") for i in disasm(img, base, lo, hi)), "%s: предел 0x258 (600)" % k)
            for k in ("вход charLogonCoolTimeSaveRes", "портал charPortalLogon…"):
                lo, hi = FUNCS[k]
                ok(not any(i.op_str.endswith(", 0x258") for i in disasm(img, base, lo, hi)), "%s: предела 0x258 НЕТ — ловушка стока" % k)

    print("-- непересечение с другими патчами")
    rx = re.compile(r"0x0*([45][0-9A-Fa-f]{5})\b")
    clash = []
    pdir = os.path.join(SRC, "patches")
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or not re.match(r"p\d\d_", fn) or fn.startswith("p82_"):
            continue
        for ln, line in enumerate(open(os.path.join(pdir, fn), encoding="utf-8", errors="replace"), 1):
            for m in rx.finditer(line):
                v = int(m.group(1), 16)
                for n, (va, hx) in SITES.items():
                    if va <= v < va + len(hx) // 2:
                        clash.append((fn, ln, n, hex(v)))
    ok(not clash, "площадки P82 не называет ни один другой патч%s" % ("" if not clash else ": " + str(clash)))

    print("-- исходники")
    cfgh = open(os.path.join(SRC, "Config.h"), encoding="utf-8-sig").read()
    cfgc = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8-sig").read()
    reg = open(os.path.join(pdir, "Registry.cpp"), encoding="utf-8-sig").read()
    src82 = open(os.path.join(pdir, "p82_func_cooltime_ext.cpp"), encoding="utf-8").read()
    # ★ 04.11.2026 (v60): P82 ввёл Version 54; позже версия растёт с каждым патчем — проверяется «≥ 54 и шаблон = kVersion»
    mv = re.search(r"constexpr int kVersion = (\d+);", cfgh)
    kv = int(mv.group(1)) if mv else 0
    ok(kv >= 54 and ('{ L"Version", L"%d",' % kv) in cfgc, "Version %d (≥ 54) в Config.h и тот же в шаблоне Config.cpp" % kv)
    sec = cfgc[cfgc.find("const IniKey kFuncCoolTimeExt[]"):]
    sec = sec[:sec.find("};")]
    keys = dict(re.findall(r'\{ L"(\w+)", L"([^"]*)"', sec))
    ok(keys == {"Enabled": "1", "SaveRestore": "1", "RestoreGuard": "1", "LogEvents": "1", "LogChannel": "8", "JournalIntervalSec": "10"},
       "секция [P82_FuncCoolTimeExt]: %s" % keys)
    ok('{ L"P82_FuncCoolTimeExt",' in cfgc and "kFuncCoolTimeExt, ARRAYSIZE(kFuncCoolTimeExt)" in cfgc, "секция в таблице kSections")
    for k in (91, 92, 93):
        ok(len(re.findall(r"case %d: return L\"P82:" % k, acj)) == 1, "AcJournal.cpp: вид ac.other %d — текст P82" % k)
    ok("kKindBadRestore = 91, kKindSaveFull = 92, kKindTableFull = 93" in src82, "p82: enum видов 91/92/93")
    i81, i82 = reg.find('{ L"P81_ActionCodeGuard"'), reg.find('{ L"P82_FuncCoolTimeExt"')
    ok(0 < i81 < i82, "реестр: P82 после P81")
    for n, (va, hx) in SITES.items():
        ok(("0x%08X" % va) in src82, "p82: площадка %s 0x%08X описана в исходнике" % (n, va))

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P82_FuncCoolTimeExt".encode("utf-16-le") in raw, "реестр: строка секции P82_FuncCoolTimeExt в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 4 and "p82_func_cooltime_ext" in line:
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    for f in sorted({v[1] for v in TRAMPS.values()}):
        ok(f in names, "MAP: %s" % f)
    ok(any("P82_GetStats" in n for n in names) and any("P82_FuncCoolTimeExt" in n for n in names), "MAP: P82_GetStats, P82_FuncCoolTimeExt")
    pref = pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def glob(va):
        return struct.unpack("<I", bytes(img[va - pref:va - pref + 4]))[0]

    for t, (want, callee, nargs) in TRAMPS.items():
        va = [v for n, v in names.items() if n.startswith("?%s@" % t)]
        ok(bool(va), "MAP: %s" % t)
        if not va or callee not in names:
            continue
        ins = []
        for i in md.disasm(bytes(img[va[0] - pref:va[0] - pref + 0x60]), va[0]):
            ins.append(i)
            if i.mnemonic == "int3":
                break
        dests = set()
        for i in ins:
            m = re.match(r"dword ptr \[(0x[0-9a-f]+)\]", i.op_str)
            if i.mnemonic == "jmp" and m:
                dests.add(glob(int(m.group(1), 16)))
        ok(dests == want, "%s: выходы только на %s (%s)" % (t, sorted(hex(x) for x in want), sorted(hex(x) for x in dests)))
        cl = [i for i in ins if i.mnemonic == "call"]
        ok(len(cl) == 1 and int(cl[0].op_str, 16) == names[callee], "%s: один вызов — %s" % (t, callee))
        ok(not any(i.mnemonic == "ret" for i in ins), "%s: ret нет (выход только переходом)" % t)
    print("== ИТОГ verify_p82: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
