# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p103.py — статическая проверка P103_InFlightFixes (04.11.2026) без запуска GameServer:
#   1) байты всех площадок и соседей P103 (записи check[n++] = { va, kXxx, sizeof(kXxx) } в src/patches/p103_inflight_fixes.cpp —
#      читаются из исходника) совпадают на 4 образах: сток GameServer и живые GameServer/Indun/Ch2 (зеркало стойки); площадки,
#      которые на живой стойке держат P75 (0x4EF02E) и P100 (0x4F1771), сверяются в образах со стоковыми байтами;
#   2) дизасм: каждая площадка (…Orig) — целые инструкции; продолжения jmp-площадок (0x55B258, 0x4EE5A7) — начало инструкции;
#      call-площадки — `call rel32` на ожидаемую стоковую цель;
#   3) площадки P103 не пересекают call-площадки P100 (verify_p100.CALLS) и адреса прочих патчей, кроме ЗАДУМАННЫХ цепочек:
#      0x4EF02E (P75 StubDbSend → P103 через P75_ChainDbSend), 0x4F1771 (P100 G_AUTOUSE → уведомление P103_OnDbSent);
#   4) DLL: экспорты P103_GetStats / P100_ReleaseRecs, строка секции P103_InFlightFixes, kVersion 60 в шаблоне.
# Итог «ВСЁ СОШЛОСЬ» — код 0. Без побочных эффектов при импорте.
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src", "patches", "p103_inflight_fixes.cpp")
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
SHARED = {0x4EF02E: "P75 (цепочка P75_ChainDbSend)", 0x4F1771: "P100 G_AUTOUSE (уведомление P103_OnDbSent)"}
CALL_TARGETS = {0x4EEE13: 0x5646C0, 0x4EF02E: 0x5646C0, 0x430AB1: 0x4EF270, 0x4F1648: 0x4DA990, 0x4F1771: 0x5646C0, 0x432391: 0x4F3D90}
JMP_BACK = {0x55B251: 0x55B258, 0x4EE5A1: 0x4EE5A7}


def sites_from_source():
    """{адрес: (имя массива, байты)} из записей check[n++] исходника P103."""
    s = open(SRC, encoding="utf-8").read()
    arrays = {n: bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", b))
              for n, b in re.findall(r"const BYTE (k\w+)\[\d+\]\s*=\s*\{([^}]*)\}", s)}
    consts = {n: int(v, 16) for n, v in re.findall(r"(?:const DWORD|DWORD) (\w+) = 0x([0-9A-Fa-f]+)", s)}
    consts.update({n: int(v, 16) for n, v in re.findall(r"\b(k\w+) = 0x([0-9A-Fa-f]+)", s)})
    consts.update({n: int(v, 16) for n, v in re.findall(r"\b(g_\w+) = 0x([0-9A-Fa-f]+)", s)})
    out = {}
    for va, arr in re.findall(r"check\[n\+\+\]\s*=\s*\{\s*(\w+),\s*(k\w+),\s*sizeof", s):
        addr = int(va, 16) if va.startswith("0x") else consts[va]
        out[addr] = (arr, arrays[arr])
    return out


def main():
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    sys.path.insert(0, HERE)
    import stack_layout
    from srv_paths import ROOT as SRV
    sys.stdout.reconfigure(encoding="utf-8")
    dll = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
    bad = []

    def ok(cond, text):
        print("  [%s] %s" % ("OK" if cond else "!!", text))
        if not cond:
            bad.append(text)

    sites = sites_from_source()
    print("== 1. площадки и соседи P103 из исходника: %d" % len(sites))
    images = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"))] + \
             [("живой " + d, os.path.join(SRV, "v2", d, "GameServer.exe")) for d in stack_layout.GS_FOLDERS]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for name, path in images:
        pe = pefile.PE(path)
        mem = bytes(pe.get_memory_mapped_image())
        base = pe.OPTIONAL_HEADER.ImageBase
        diff = [hex(va) for va, (_, want) in sites.items() if mem[va - base:va - base + len(want)] != want]
        ok(not diff, "%s (%s…): байты стока %d мест%s" % (name, hashlib.md5(open(path, "rb").read()).hexdigest()[:8], len(sites),
                                                       (" — расходятся: " + ", ".join(diff)) if diff else ""))
        if not name.startswith("сток"):
            continue
        print("== 2. дизасм площадок")
        for va, (arr, b) in sorted(sites.items()):
            if not arr.endswith("Orig"):
                continue
            ins = list(md.disasm(mem[va - base:va - base + len(b) + 16], va))
            ends = []
            for i in ins:
                ends.append(i.address + i.size)
                if i.address + i.size >= va + len(b):
                    break
            ok(va + len(b) in ends, "%s 0x%X (%d б): целые инструкции (%s)" % (arr, va, len(b), " ".join(hex(e) for e in ends)))
            if va in CALL_TARGETS:
                tgt = va + 5 + int.from_bytes(b[1:5], "little", signed=True)
                ok(b[0] == 0xE8 and tgt == CALL_TARGETS[va], "%s 0x%X: call 0x%X (ждём 0x%X)" % (arr, va, tgt, CALL_TARGETS[va]))
            if va in JMP_BACK:
                back = JMP_BACK[va]
                starts = [i.address for i in md.disasm(mem[va - base:va - base + 32], va)]
                ok(back in starts, "%s 0x%X: продолжение 0x%X — начало инструкции" % (arr, va, back))
    print("== 3. пересечения")
    vt = open(os.path.join(HERE, "verify_p100.py"), encoding="utf-8").read()
    blk = vt[vt.find("CALLS = ["):vt.find("]", vt.find("CALLS = ["))]
    p100_calls = [int(x, 16) for x in re.findall(r"\(0x([0-9A-Fa-f]{6}),", blk)]
    mine = [(va, va + len(b)) for va, (arr, b) in sites.items() if arr.endswith("Orig")]
    hit = [(hex(a), hex(c)) for a, b in mine for c in p100_calls for d in (c + 5,) if a < d and c < b and a not in SHARED]
    ok(not hit, "площадки P103 не пересекают call-площадки P100 (%d), кроме задуманной 0x4F1771%s" % (len(p100_calls), (": %s" % hit) if hit else ""))
    others = {}
    pdir = os.path.dirname(SRC)
    for fn in os.listdir(pdir):
        if fn.endswith(".cpp") and not fn.startswith("p103"):
            t = re.sub(r"//[^\n]*", "", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read())
            for x in re.findall(r"0x00([4-5][0-9A-Fa-f]{5})\b", t):
                others.setdefault(int(x, 16), set()).add(fn)
    inside = sorted("%s (%s)" % (hex(x), ",".join(sorted(f))) for x, f in others.items() for a, b in mine if a <= x < b and a not in SHARED)
    ok(not inside, "адреса других патчей (вне комментариев) не внутри площадок P103%s" % ((": " + ", ".join(inside)) if inside else ""))
    shared = sorted("%s ← %s" % (hex(x), ",".join(sorted(f))) for x, f in others.items() for a, b in mine if a <= x < b and a in SHARED)
    print("  [i] задуманные общие площадки: %s" % ("; ".join(shared) or "—"))
    print("== 4. DLL %s" % hashlib.md5(open(dll, "rb").read()).hexdigest())
    pe = pefile.PE(dll)
    exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    ok(any("P103_GetStats" in e for e in exp) and any("P100_ReleaseRecs" in e for e in exp), "экспорты P103_GetStats, P100_ReleaseRecs")
    raw = open(dll, "rb").read()
    ok("P103_InFlightFixes".encode("utf-16-le") in raw, "имя секции P103_InFlightFixes в образе")
    cfg = open(os.path.join(HERE, "..", "src", "Config.h"), encoding="utf-8-sig").read()
    ok(re.search(r"constexpr int kVersion = 60;", cfg) is not None and '{ L"Version", L"60",' in open(os.path.join(HERE, "..", "src", "Config.cpp"), encoding="utf-8-sig", newline="").read(),
       "kVersion = 60 и шаблон Version 60")
    print("== ИТОГ verify_p103: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
