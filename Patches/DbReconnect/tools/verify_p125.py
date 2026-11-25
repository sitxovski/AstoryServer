# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Статическая сверка P125_DbReconnect с живыми образами (сессия srv-db-reconnect, 15.11.2026). Только чтение файлов.

Для LoginManager и DBManager:
  1) образ = живой (md5 снят со стойки по SSH 15.11.2026);
  2) адреса и байты сверки берутся ИЗ ИСХОДНИКА патча (p125_db_reconnect.cpp) и сверяются с образом;
  3) «было/стало» площадки: границы команд, длина 5 байт, следующая команда на месте;
  4) в функции запроса нет переходов внутрь площадки;
  5) площадка не пересекается с адресами других патчей той же DLL (все 0x004xxxxx из их исходников);
  6) собранная DLL: x86, экспорт _P125_GetStats@4, строка секции, импорт CoCreateInstance.
Итог: строки [OK]/[MISMATCH] и счётчик. Побочных эффектов при импорте нет; запуск - main().
Запуск: py -3.13 verify_p125.py
"""
import glob
import hashlib
import os
import re
import sys

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.dirname(os.path.dirname(HERE))

TARGETS = [
    {"name": "LoginManager",
     "image": os.path.join(PATCHES, "LoginPatch", "out", "LoginManager.exe.loginpatch.exe"),
     "live_md5": "51db86b2a1c44b91b11bebfc343e88be",
     "dll": os.path.join(PATCHES, "LoginPatch", "out", "LoginPatch.dll"),
     "src": os.path.join(PATCHES, "LoginPatch", "src", "patches", "p125_db_reconnect.cpp"),
     "others": [os.path.join(PATCHES, "LoginPatch", "src", "patches", "*.cpp"), os.path.join(PATCHES, "LoginPatch", "src", "LoginApi.h")],
     "func": (0x0040F440, 0x00410B90)},
    {"name": "DBManager",
     "image": os.path.join(PATCHES, "DBPatch", "out", "DBManager.exe.dbpatch.exe"),
     "live_md5": "3d05c835b3f953bcde375ef8f13f3104",
     "dll": os.path.join(PATCHES, "DBPatch", "out", "DBPatch.dll"),
     "src": os.path.join(PATCHES, "DBPatch", "src", "p125_db_reconnect.cpp"),
     "others": [os.path.join(PATCHES, "DBPatch", "src", "*.cpp")],
     "func": (0x00447720, 0x00449270)},
]

ok_n = 0
bad_n = 0


def check(cond, text):
    """Одна сверка: печать и счёт."""
    global ok_n, bad_n
    print("  [%s] %s" % ("OK" if cond else "MISMATCH", text))
    if cond:
        ok_n += 1
    else:
        bad_n += 1


def src_consts(path):
    """Адреса и массивы сверки из исходника патча."""
    s = open(path, encoding="utf-8").read()
    va = {m.group(1): int(m.group(2), 16) for m in re.finditer(r"const DWORD (k\w+)\s*=\s*(0x[0-9A-Fa-f]+);", s)}
    arr = {}
    for m in re.finditer(r"const BYTE (k\w+)\[\d+\]\s*=\s*\{([^}]*)\}", s):
        arr[m.group(1)] = bytes(int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", m.group(2)))
    return va, arr


def run(t):
    print("== %s" % t["name"])
    data = open(t["image"], "rb").read()
    check(hashlib.md5(data).hexdigest() == t["live_md5"], "образ %s = живой %s" % (os.path.basename(t["image"]), t["live_md5"]))
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    rd = lambda va, n: pe.get_data(va - base, n)
    va, arr = src_consts(t["src"])
    pairs = [("kSiteVa", "kOrig"), ("kCtxAVa", "kCtxA"), ("kCtxBVa", "kCtxB"), ("kLeaVa", "kLea"), ("kClsidVa", "kClsid")]
    for a, b in pairs:
        got = rd(va[a], len(arr[b]))
        check(got == arr[b], "%s 0x%08X: в исходнике [%s], в образе [%s]" % (a, va[a], arr[b].hex(" "), got.hex(" ")))
    site = va["kSiteVa"]
    check(va["kCtxAVa"] + len(arr["kCtxA"]) == site and site + 5 == va["kCtxBVa"],
          "соседние команды вплотную: 0x%08X+3 = площадка, площадка+5 = 0x%08X" % (va["kCtxAVa"], va["kCtxBVa"]))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    f0, f1 = t["func"]
    insns = list(md.disasm(rd(f0, f1 - f0), f0))
    starts = {i.address for i in insns}
    here = [i for i in insns if site <= i.address < site + 5]
    check(site in starts and (site + 5) in starts and sum(i.size for i in here) == 5 and len(here) == 2,
          "площадка = ровно 2 целые команды, 5 байт: %s" % "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in here))
    check(here[0].mnemonic == "mov" and "+ 0x10]" in here[0].op_str and here[1].mnemonic == "call" and here[1].op_str == here[0].op_str.split(",")[0],
          "команды площадки: взять метод vtbl+0x10 (Execute) и вызвать его через тот же регистр")
    inside = [i for i in insns if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and site < int(i.op_str, 16) < site + 5]
    check(not inside, "переходов внутрь площадки в функции нет (найдено %d)" % len(inside))
    # Через vtbl+0x10 в функции зовутся методы трёх объектов: команды (+0xFC, Execute), набора строк (+0xF8, GetData)
    # и аксессора (+0x104, CreateAccessor). Объект определяем по последней загрузке поля записи сессии перед вызовом.
    objs = []
    for k in range(len(insns) - 1):
        if not (insns[k].mnemonic == "mov" and insns[k].op_str.endswith("+ 0x10]") and insns[k + 1].mnemonic == "call"
                and insns[k + 1].op_str == insns[k].op_str.split(",")[0]):
            continue
        disp = None
        for j in range(k - 1, max(k - 14, 0), -1):
            m = re.search(r"\+ (0xf[08c]|0x10[04])\]$", insns[j].op_str)
            if m and insns[j].mnemonic == "mov":
                disp = m.group(1)
                break
        objs.append((insns[k].address, disp))
    cmd_calls = [a for a, d in objs if d == "0xfc"]
    check(cmd_calls == [site], "вызовы vtbl+0x10 в функции: %s; на объекте команды (+0xFC) — один, и это площадка"
          % ", ".join("0x%08X(поле %s)" % (a, d) for a, d in objs))
    print("    было:")
    for i in insns:
        if va["kCtxAVa"] <= i.address < va["kCtxBVa"] + 6:
            print("      %08X  %-22s %s %s" % (i.address, i.bytes.hex(" "), i.mnemonic, i.op_str))
    patched = bytearray(rd(va["kCtxAVa"], 3 + 5 + 6))
    patched[3:8] = b"\xE8" + (0x10000000 - (site + 5)).to_bytes(4, "little", signed=True)   # условная цель 0x10000000
    print("    стало (цель вызова условная — адрес ExecuteHook в DLL известен только после загрузки):")
    after = list(md.disasm(bytes(patched), va["kCtxAVa"]))
    for i in after:
        print("      %08X  %-22s %s %s" % (i.address, i.bytes.hex(" "), i.mnemonic, i.op_str))
    check(len(after) == 4 and after[2].mnemonic == "call" and after[2].size == 5 and after[3].address == va["kCtxBVa"]
          and after[3].bytes == arr["kCtxB"], "после замены: push cmd → call rel32 (5 б) → mov [ebp-0x1024], eax на прежнем месте")

    # пересечение с другими патчами той же DLL
    hits = []
    for pat in t["others"]:
        for p in glob.glob(pat):
            if os.path.basename(p).startswith("p125_") or ".bak" in p:
                continue
            for m in re.finditer(r"0x00([0-9A-Fa-f]{6})\b", open(p, encoding="utf-8", errors="replace").read()):
                v = int(m.group(1), 16)
                if site - 4 <= v < site + 5:        # чужая площадка до 5 байт, начавшаяся раньше, тоже задела бы нашу
                    hits.append("%s: 0x%08X" % (os.path.basename(p), v))
    check(not hits, "адресов других патчей в окне площадки [0x%08X-4 … +5) нет%s" % (site, "" if not hits else ": " + ", ".join(hits)))

    dll = pefile.PE(t["dll"])
    exports = [e.name.decode() for e in dll.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    imports = {i.name.decode() for e in dll.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name}
    raw = open(t["dll"], "rb").read()
    check(dll.FILE_HEADER.Machine == 0x14C, "DLL %s — x86" % os.path.basename(t["dll"]))
    check("_P125_GetStats@4" in exports, "экспорт _P125_GetStats@4 есть")
    check("P125_DbReconnect".encode("utf-16-le") in raw, "строка секции «P125_DbReconnect» есть в DLL")
    check({"CoCreateInstance", "CoInitializeEx", "GetErrorInfo", "SetErrorInfo"} <= imports, "импорт CoCreateInstance / CoInitializeEx / GetErrorInfo / SetErrorInfo есть")
    check(arr["kOrig"] in raw and arr["kClsid"] in raw, "байты сверки площадки и CLSID лежат в DLL")
    print("    DLL: %s  %d б  md5 %s" % (os.path.basename(t["dll"]), len(raw), hashlib.md5(raw).hexdigest()))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    for t in TARGETS:
        run(t)
    print("=== verify_p125: OK %d, MISMATCH %d ===" % (ok_n, bad_n))
    return 1 if bad_n else 0


if __name__ == "__main__":
    sys.exit(main())
