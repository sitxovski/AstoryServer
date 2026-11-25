# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p96_db.py — СТАТИЧЕСКАЯ проверка DBPatch P96_DbShellRows (сумка 60 строк, 30.10.2026). Сервер НЕ запускается.
#   Образы — локальное зеркало стойки по SSH (AsdaPatch/tools/srv_mirror.py; только чтение): живой DBManager.exe и сток
#   DBManager-Original.exe. По каждому образу:
#    1) четыре сигнатуры площадок (те же байты, что в p96_db_shell_rows.cpp) встречаются в .text РОВНО ОДИН раз и стоят на
#       0x422E61 / 0x422E96 / 0x423785 / 0x4237B4; imm8 = 1Eh;
#    2) дизасм (capstone): cmp [ebp-0x3CE4|0x738C],1Eh → jle ровно за mov той же ячейки; между ними — журнал 0x452BD0 со строкой
#       «UPPlateItem SHELLINVEN_SLOTNUM…»; дальше цикл `cmp i, count / jge` читает ТУ ЖЕ ячейку (граница цикла = обрезка);
#    3) буферы: memset пачки 0x1D6 (472 б), порог отправки 0x19D, приёмник строк 14000/14004 б — 60×57 = 3420 < 14000;
#       расходники (Plate 2) — уже 3Ch (0x423315/0x42334A, 0x423AEA/0x423B19), той же схемой;
#    4) ни один переход (rel8/rel32/jcc/call) и ни один abs32 в .text не ведёт ВНУТРЬ четырёх инструкций;
#    5) имитация патча тем же алгоритмом (поиск по сигнатуре → 1Eh→3Ch) меняет ровно 4 байта;
#   и по проекту:
#    6) другие патчи DBPatch/src не пишут в диапазоны 0x422E61…0x422EA0 и 0x423785…0x4237BE (адреса в исходниках),
#       площадки SITES_DB из AsdaPatch/tools/verify_dll.py (только чтение) не пересекаются;
#    7) DLL: в DBPatch.dll есть строка секции P96_DbShellRows (UTF-16) и все четыре сигнатуры (байты в .rdata).
# Поведение — стенд tools/stand_p96_db (on/off/mismatch/dup, настоящий код 0x7F7 и 2001/2089 с N = 0…70 строк).
# Запуск: python verify_p96_db.py [DBPatch.dll]      Код возврата 0 — ошибок нет.
import os
import re
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.normpath(os.path.join(HERE, "..", ".."))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "DBPatch.dll")
SRC = os.path.join(HERE, "..", "src")
VERIFY_DLL = os.path.join(PATCHES, "AsdaPatch", "tools", "verify_dll.py")
sys.path.insert(0, os.path.join(PATCHES, "AsdaPatch", "tools"))
from srv_paths import V2   # корень v2 зеркала стойки (со слешем)

IMAGES = [("живой DBManager", V2 + "DBManager/DBManager.exe"), ("сток DBManager-Original", V2 + "DBManager/DBManager-Original.exe")]
LIVE_MD5 = "3d05c835b3f953bcde375ef8f13f3104"   # живой образ на 30.10.2026
# (имя, адрес, сигнатура, смещение imm8)
SITES = [
    ("422C20.cmp", 0x00422E61, "83bd1cc3ffff1e7e360f", 6),
    ("422C20.mov", 0x00422E96, "c7851cc3ffff1e000000", 6),
    ("423600.cmp", 0x00423785, "83bd748cffff1e7e300f", 6),
    ("423600.mov", 0x004237B4, "c785748cffff1e000000", 6),
]
PAIRS = [(0, 1, -0x3CE4, 0x00422C20), (2, 3, -0x738C, 0x00423600)]   # cmp, mov, ячейка count, функция
SPEND = [(0x00423315, "83bd24c3ffff3c"), (0x0042334A, "c78524c3ffff3c000000"),
         (0x00423AEA, "83bd748cffff3c"), (0x00423B19, "c785748cffff3c000000")]
bad = 0


def ok(cond, msg):
    """Печать результата проверки и счёт ошибок."""
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    """Образ в памяти (по VA), база, границы .text."""
    pe = pefile.PE(path)
    img = bytes(pe.get_memory_mapped_image())
    base = pe.OPTIONAL_HEADER.ImageBase
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return pe, img, base, base + t.VirtualAddress, base + t.VirtualAddress + t.Misc_VirtualSize


def dis(img, base, lo, hi):
    """Список инструкций [lo, hi)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return list(md.disasm(img[lo - base:hi - base], lo))


def refs_into(img, base, lo, hi, ranges):
    """Переходы/вызовы rel и abs32 из .text внутрь (a, b) любого диапазона — адреса источников."""
    out = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    for i in md.disasm(img[lo - base:hi - base], lo):
        if i.mnemonic.startswith("j") or i.mnemonic == "call":
            m = re.fullmatch(r"0x([0-9a-f]+)", i.op_str)
            if m:
                t = int(m.group(1), 16)
                if any(a < t < b for a, b in ranges):
                    out.append(i.address)
    data = img[lo - base:hi - base]
    for k in range(0, len(data) - 3):
        v = int.from_bytes(data[k:k + 4], "little")
        if any(a < v < b for a, b in ranges):
            out.append(lo + k)
    return out


def apply_sig(img, base, lo, hi):
    """Имитация p96_db_shell_rows.cpp: найти все 4 сигнатуры (ровно по одной) и заменить imm8 1Eh → 3Ch. → новый образ или None."""
    txt = img[lo - base:hi - base]
    out = bytearray(img)
    for name, va, sig, imm in SITES:
        s = bytes.fromhex(sig)
        if txt.count(s) != 1:
            return None
        a = lo + txt.find(s)
        out[a - base + imm] = 0x3C
    return bytes(out)


def check_image(name, path):
    """Проверки 1–5 по одному образу."""
    if not os.path.exists(path):
        ok(False, "%s: образа нет (%s) — снять зеркало: python AsdaPatch/tools/srv_mirror.py" % (name, path))
        return
    import hashlib
    h = hashlib.md5(open(path, "rb").read()).hexdigest()
    print("== %s %s (md5 %s)" % (name, path, h))
    if "живой" in name:
        ok(h == LIVE_MD5, "%s: md5 = %s (по нему сверены площадки 30.10)" % (name, LIVE_MD5))
    pe, img, base, lo, hi = load(path)
    txt = img[lo - base:hi - base]
    for nm, va, sig, imm in SITES:
        s = bytes.fromhex(sig)
        n = txt.count(s)
        at = lo + txt.find(s) if n else 0
        ok(n == 1 and at == va and img[va - base + imm] == 0x1E,
           "%s: сигнатура %s %s — совпадений %d, на 0x%08X (ожидалось 0x%08X), imm8 = 1Eh" % (name, nm, sig, n, at, va))
    for ci, mi, cell, fn in PAIRS:
        c, m = SITES[ci][1], SITES[mi][1]
        ins = dis(img, base, c, m + 10 + 0x80)
        tx = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
        cs = "dword ptr [ebp - 0x%x]" % -cell
        jle = ins[1]
        ok(tx.get(c) == "cmp %s, 0x1e" % cs and jle.mnemonic == "jle" and int(jle.op_str, 16) == m + 10
           and tx.get(m) == "mov %s, 0x1e" % cs,
           "%s: 0x%08X cmp %s,1Eh → jle 0x%08X (за mov) → 0x%08X mov %s,1Eh" % (name, c, cs, m + 10, m, cs))
        between = [i for i in ins if c < i.address < m]
        push_str = [i for i in between if i.mnemonic == "push" and i.op_str.startswith("0x46")]
        s_ok = False
        if push_str:
            sa = int(push_str[-1].op_str, 16)
            s_ok = img[sa - base:sa - base + 34] == b"UPPlateItem SHELLINVEN_SLOTNUM Siz"
        ok(any(i.mnemonic == "call" and i.op_str == "0x452bd0" for i in between) and s_ok,
           "%s: между cmp и mov — журнал 0x452BD0 «UPPlateItem SHELLINVEN_SLOTNUM…»" % name)
        loop = [i for i in ins if i.address > m and i.mnemonic == "cmp" and i.op_str.endswith(cs)]
        ok(bool(loop), "%s: граница цикла пачек `cmp i, %s` (0x%08X) — та же ячейка, что обрезка" % (
            name, cs, loop[0].address if loop else 0))
        body = dis(img, base, fn, m + 0x300)
        ops = " | ".join("%s %s" % (i.mnemonic, i.op_str) for i in body)
        ok("push 0x1d6" in ops and "0x19d" in ops,
           "%s: sub_%X — пачка memset 0x1D6 (472 б), порог отправки 0x19D (4 + 8·57 = 460 ≤ 472)" % (name, fn))
        ok(("0x36b0" in ops or "0x36b4" in ops) and 60 * 57 < 14000,
           "%s: sub_%X — приёмник строк процедуры 14000 б (memset/размер 0x36B0…), 60×57 = %d < 14000" % (name, fn, 60 * 57))
    for va, b in SPEND:
        ok(img[va - base:va - base + len(bytes.fromhex(b))] == bytes.fromhex(b), "%s: расходники 0x%08X = %s (3Ch, не трогаем)" % (name, va, b))
    rng = [(va, va + (7 if sig.startswith("83") else 10)) for _, va, sig, _ in SITES]
    r = refs_into(img, base, lo, hi, rng)
    ok(not r, "%s: переходов/abs32 внутрь 4 инструкций нет (%s)" % (name, ", ".join("0x%08X" % x for x in r[:5]) or "—"))
    new = apply_sig(img, base, lo, hi)
    diff = [i for i in range(len(img)) if new is not None and img[i] != new[i]] if new is not None else None
    ok(diff is not None and len(diff) == 4 and sorted(base + d for d in diff) == sorted(va + imm for _, va, _, imm in SITES),
       "%s: имитация патча по сигнатурам меняет ровно 4 байта (%s)" % (
           name, ", ".join("0x%08X" % (base + d) for d in (diff or []))))


def main():
    """Точка входа: проверки образов, исходников и DLL; итог."""
    for name, path in IMAGES:
        check_image(name, path)
    print("== проект")
    lo_hi = [(0x00422E61, 0x00422EA0), (0x00423785, 0x004237BE)]
    hits = []
    for fn in sorted(os.listdir(SRC)):
        if not fn.endswith(".cpp") or fn.startswith("p96") or fn in ("Registry.cpp", "Config.cpp"):
            continue
        t = open(os.path.join(SRC, fn), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x0*([0-9A-Fa-f]{6})\b", t):
            v = int(m.group(1), 16)
            if any(a <= v < b for a, b in lo_hi):
                hits.append("%s:0x%06X" % (fn, v))
    ok(not hits, "другие патчи DBPatch/src не ссылаются на площадки P96 (%s)" % (", ".join(hits) or "—"))
    vt = open(VERIFY_DLL, encoding="utf-8", errors="replace").read() if os.path.exists(VERIFY_DLL) else ""
    sd = re.search(r"SITES_DB = \[(.*?)\n\]", vt, re.S)
    cross = []
    for m in re.finditer(r'\("([^"]+)",\s*0x([0-9A-Fa-f]+),\s*"([0-9a-f]+)"', sd.group(1) if sd else ""):
        a = int(m.group(2), 16)
        b = a + len(m.group(3)) // 2
        if any(a < y and x < b for x, y in lo_hi):
            cross.append(m.group(1))
    ok(sd is not None and not cross, "площадки SITES_DB (verify_dll.py) не пересекаются с P96 (%s)" % (", ".join(cross) or "—"))
    d = open(DLL, "rb").read() if os.path.exists(DLL) else b""
    ok("P96_DbShellRows".encode("utf-16-le") in d, "DBPatch.dll: строка секции P96_DbShellRows (%s)" % DLL)
    ok(all(bytes.fromhex(sig) in d for _, _, sig, _ in SITES), "DBPatch.dll: все 4 сигнатуры площадок вшиты")
    print("== ИТОГ verify_p96_db: ошибок %d ==" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
