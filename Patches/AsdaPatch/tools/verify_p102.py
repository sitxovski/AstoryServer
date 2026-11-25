# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p102.py — статическая проверка P102_DefectFixes (02.11.2026) без запуска GameServer:
#   1) байты всех площадок и соседей P102 (таблица Site check[] в src/patches/p102_defect_fixes.cpp — читается из исходника,
#      второй источник — дизасм capstone) совпадают на 4 образах: сток GameServer и живые GameServer/Indun/Ch2 (зеркало стойки);
#   2) дизасм каждой площадки: длина = границам инструкций (площадка не режет инструкцию), продолжение — начало инструкции;
#   3) площадки P102 не пересекаются с площадками P100 (verify_p100.CALLS ±5 б) и с адресами прочих патчей src/patches (по тексту);
#   4) DLL: экспорты P102_GetStats / P100_CountLotMerges, строка секции P102_DefectFixes в образе.
# Итог «ВСЁ СОШЛОСЬ» — код 0. Без побочных эффектов при импорте.
import hashlib
import os
import re
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
SRC = os.path.join(HERE, "..", "src", "patches", "p102_defect_fixes.cpp")
bad = []


def ok(cond, text):
    """Строка проверки; провал — в замечания."""
    print("  [%s] %s" % ("OK" if cond else "!!", text))
    if not cond:
        bad.append(text)


def sites_from_source():
    """Таблица {адрес: байты} площадок и соседей из исходника P102 (именованные массивы kXxx[] и их адреса в check[])."""
    s = open(SRC, encoding="utf-8").read()
    arrays = {}
    for name, body in re.findall(r"const BYTE (k\w+)\[\d+\]\s*=\s*\{([^}]*)\}", s):
        arrays[name] = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body))
    consts = {n: int(v, 16) for n, v in re.findall(r"(?:const DWORD|DWORD) (\w+) = 0x([0-9A-Fa-f]+)", s)}
    blk = s[s.find("const Site check[]"):s.find("VerifyAllSites(L\"P102\"")]
    out = {}
    for va, arr in re.findall(r"\{\s*(\w+),\s*(k\w+),\s*sizeof", blk):
        addr = int(va, 16) if va.startswith("0x") else consts[va]
        out[addr] = (arr, arrays[arr])
    return out, consts


def main():
    import stack_layout
    from srv_paths import ROOT as SRV
    sys.stdout.reconfigure(encoding="utf-8")
    # таблица call-площадок P100 — разбором текста verify_p100.py (импорт его запускает)
    vt = open(os.path.join(HERE, "verify_p100.py"), encoding="utf-8").read()
    calls_blk = vt[vt.find("CALLS = ["):vt.find("]", vt.find("CALLS = ["))]
    p100_calls = [int(x, 16) for x in re.findall(r"\(0x([0-9A-Fa-f]{6}),", calls_blk)]
    sites, consts = sites_from_source()
    print("== 1. площадки и соседи P102 из исходника: %d" % len(sites))
    img = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
    images = [("сток GameServer", os.path.join(img, "gs_stock.exe"))] + \
             [("живой " + d, os.path.join(SRV, "v2", d, "GameServer.exe")) for d in stack_layout.GS_FOLDERS]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for name, path in images:
        pe = pefile.PE(path)
        mem = bytes(pe.get_memory_mapped_image())
        base = pe.OPTIONAL_HEADER.ImageBase
        diff = [hex(va) for va, (_, want) in sites.items() if mem[va - base:va - base + len(want)] != want]
        ok(not diff, "%s (%s…): байты стока %d мест%s" % (name, hashlib.md5(open(path, "rb").read()).hexdigest()[:8], len(sites),
                                                       (" — расходятся: " + ", ".join(diff)) if diff else ""))
        if name.startswith("сток"):
            print("== 2. площадки: границы инструкций (дизасм)")
            for va_name, back_name in (("kS1", "g_s1Back"), ("kS2", "g_s2Back"), ("kS3", "g_s3Back"), ("kS4", "g_s4Back"), ("kS5", "g_s5Back")):
                va, back = consts[va_name], consts[back_name]
                ends, a = [], va
                for ins in md.disasm(mem[va - base:va - base + 40], va):
                    a = ins.address + ins.size
                    ends.append(a)
                    if a >= back:
                        break
                ok(back in ends, "%s 0x%X…0x%X: продолжение на границе инструкции (%s)" % (va_name, va, back, " ".join(hex(e) for e in ends)))
    print("== 3. пересечения")
    mine = [(va, va + len(b)) for va, (arr, b) in sites.items() if arr.endswith("Orig")]
    p100 = [(va, va + 5) for va in p100_calls]
    hit = [(hex(a), hex(c)) for a, b in mine for c, d in p100 if a < d and c < b]
    ok(not hit, "площадки P102 не пересекают call-площадки P100 (%d)%s" % (len(p100), (": %s" % hit) if hit else ""))
    others = set()
    pdir = os.path.dirname(SRC)
    for fn in os.listdir(pdir):
        if fn.endswith(".cpp") and not fn.startswith("p102"):
            t = re.sub(r"//[^\n]*", "", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read())
            others |= {int(x, 16) for x in re.findall(r"0x00([4-5][0-9A-Fa-f]{5})\b", t)}
    inside = sorted(hex(x) for x in others for a, b in mine if a <= x < b)
    ok(not inside, "ни один адрес других патчей (вне комментариев) не внутри площадок P102%s" % ((": " + ", ".join(inside)) if inside else ""))
    print("== 4. DLL %s" % hashlib.md5(open(DLL, "rb").read()).hexdigest())
    pe = pefile.PE(DLL)
    exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    ok(any("P102_GetStats" in e for e in exp) and any("P100_CountLotMerges" in e for e in exp), "экспорты P102_GetStats, P100_CountLotMerges")
    ok("P102_DefectFixes".encode("utf-16-le") in open(DLL, "rb").read(), "имя секции P102_DefectFixes в образе")
    print("== ИТОГ verify_p102: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
