# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p114.py — СТАТИЧЕСКАЯ проверка P114 «опыт заданий доски усиливается, как опыт обычного задания» (07.11.2026, пачка 11, баг 8;
#   AstoryServer/Docs/GameServer/board-exp-bonus-p114.md). Поведение — стенд stand_p114 (образы × 3 режима).
#   1. Образы GameServer (сток; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка совпадает, цель call — начисление, переходов внутрь нет.
#   2. Дизасм: аргументы перед площадкой (a5 = 1, a3 = 0, fEvent = 1.0); начисление не читает a6 (нет множителя) и выходит ret 18h;
#      GetExpUpDownValue выходит ret 10h; в recvDBLimitationResult один вызов начисления.
#   3. Исходник: байты и константы; площадки других патчей не пересекают 0x53C4F9 (в функции есть байт P97 0x53C528). DLL: секция, экспорт; журнал 184.
# Запуск: py -3.13 verify_p114.py [AsdaPatch.dll]
import glob
import hashlib
import os
import re
import struct
import sys

sys.dont_write_bytecode = True
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                       # единый состав стойки и md5 образов
from srv_paths import ROOT as SRV         # корень зеркала стойки

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
SRC = os.path.join(HERE, "..", "src", "patches", "p114_board_exp_bonus.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
JOURNAL_SRC = os.path.join(HERE, "..", "src", "AcJournal.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC = 0x53C180                           # recvDBLimitationResult
SITE, EXP_ADD, EXP_UPDOWN = 0x53C4F9, 0x4CBA90, 0x4CC3A0
OK = 0
BAD = 0


def check(cond, what):
    """Строка «[OK]/[FAIL] что» и счётчики."""
    global OK, BAD
    if cond:
        OK += 1
        print("[OK]   " + what)
    else:
        BAD += 1
        print("[FAIL] " + what)


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


class Img:
    """Образ exe: чтение по VA."""

    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = bytearray(self.pe.get_memory_mapped_image())

    def rd(self, va, n):
        """n байт по VA."""
        return bytes(self.data[va - self.base: va - self.base + n])

    def text(self):
        """(va начала, байты) секции .text."""
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".text":
                va = self.base + s.VirtualAddress
                return va, bytes(self.data[s.VirtualAddress: s.VirtualAddress + s.Misc_VirtualSize])
        raise RuntimeError("нет .text")


def jump_sources(img):
    """{цель: [источники]} всех rel8/rel32 переходов и call по .text."""
    va0, t = img.text()
    out = {}
    for i in range(len(t) - 6):
        b = t[i]
        tg = None
        if 0x70 <= b <= 0x7F or b == 0xEB:
            tg = va0 + i + 2 + struct.unpack_from("<b", t, i + 1)[0]
        elif b in (0xE8, 0xE9):
            tg = va0 + i + 5 + struct.unpack_from("<i", t, i + 1)[0]
        elif b == 0x0F and 0x80 <= t[i + 1] <= 0x8F:
            tg = va0 + i + 6 + struct.unpack_from("<i", t, i + 2)[0]
        if tg is not None:
            out.setdefault(tg, []).append(va0 + i)
    return out


def body(img, va, limit=0x1000):
    """Инструкции функции от va до первой границы int3/след. пролога после ret."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = []
    for i in md.disasm(img.rd(va, limit), va):
        out.append(i)
        if i.mnemonic == "ret":
            nxt = img.rd(i.address + i.size, 3)
            if nxt == b"\x55\x8b\xec" or nxt[:1] in (b"\xcc", b"\x90"):
                break
    return out


def check_image(name, path):
    """Пункты 1–2 для одного образа; возвращает md5 площадки с окрестностью."""
    img = Img(path)
    check(img.rd(SITE, 5) == bytes.fromhex("E892F5F8FF"), "%s: площадка 0x%06X совпадает" % (name, SITE))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    pre = list(md.disasm(img.rd(0x53C4DB, SITE + 5 - 0x53C4DB), 0x53C4DB))
    txt = [("%s %s" % (i.mnemonic, i.op_str)).strip() for i in pre]
    check(txt[0] == "push ecx" and txt[1] == "fld1" and txt[2].startswith("fstp dword ptr [esp]"), "%s: a6 = 1.0f (fld1 / fstp [esp])" % name)
    check(txt[3] == "push 1" and "push 0" in txt, "%s: a5 = 1, a3 = 0" % name)
    check(pre[-1].address == SITE and txt[-1] == "call 0x%x" % EXP_ADD, "%s: на площадке call начисления 0x%06X, граница инструкции" % (name, EXP_ADD))
    js = jump_sources(img)
    inside = [t for t in js if SITE < t < SITE + 5]
    check(not inside, "%s: переходов внутрь площадки нет" % name)
    check(not js.get(SITE), "%s: на площадку никто не прыгает (идём сверху)" % name)
    add = body(img, EXP_ADD, 0x900)
    check(add[-1].mnemonic == "ret" and add[-1].op_str == "0x18", "%s: начисление выходит ret 18h" % name)
    a6 = [i for i in add if "[ebp + 0x1c]" in i.op_str]
    check(not a6, "%s: начисление не читает a6 (нет множителя в нём): %d мест" % (name, len(a6)))
    fl = [i for i in add if i.mnemonic.startswith(("fmul", "fimul"))]
    check(len(fl) == 2 and all(i.op_str == "qword ptr [0x587340]" for i in fl) and struct.unpack("<d", img.rd(0x587340, 8))[0] == 0.30000001192092896,
          "%s: умножения в начислении только 0.3 для шкалы кувшина (%d), опыт игрока не множится" % (name, len(fl)))
    upd = body(img, EXP_UPDOWN, 0x400)
    check(upd[-1].mnemonic == "ret" and upd[-1].op_str == "0x10", "%s: GetExpUpDownValue выходит ret 10h" % name)
    func = body(img, FUNC, 0x900)
    calls = [i for i in func if i.mnemonic == "call" and i.op_str == "0x%x" % EXP_ADD]
    check(len(calls) == 1 and calls[0].address == SITE, "%s: в recvDBLimitationResult один вызов начисления" % name)
    return hashlib.md5(img.rd(0x53C4DB, 0x40) + img.rd(EXP_UPDOWN, 0x300)).hexdigest()


def main():
    print("verify_p114: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    bodies = {n: check_image(n, p) for n, p in imgs}
    check(len(set(bodies.values())) == 1, "площадка и GetExpUpDownValue побайтно одни во всех образах")
    s = open(SRC, encoding="utf-8").read()
    mm = re.search(r"const BYTE\s+kSiteOrig\[[^\]]*\]\s*=\s*\{(.*?)\};", s, re.S)
    got = "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""
    check(got == "E892F5F8FF", "исходник: kSiteOrig = байты площадки")
    consts = {"kSite": "0x0053C4F9", "kExpAdd": "0x004CBA90", "kExpUpDown": "0x004CC3A0", "kKindFault": "184"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p114_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"\b0x00(53[C][0-9A-Fa-f]{3})\b", t):
            v = int(m.group(1), 16)
            if SITE - 4 <= v < SITE + 5:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    check(not hits, "площадки других патчей не пересекают 0x53C4F9 (%s)" % (", ".join(sorted(set(hits))) or "0"))
    d = open(DLL, "rb").read()
    check("P114_BoardExpBonus".encode("utf-16-le") in d, "DLL: секция/реестр P114_BoardExpBonus")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check("_P114_GetStats@4" in ex, "DLL: экспорт _P114_GetStats@4")
    j = open(JOURNAL_SRC, encoding="utf-8", errors="replace").read()
    check(re.search(r'case 184: return L"P114:', j) is not None, "AcJournal: ac.other 184 — текст P114")
    print("verify_p114 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
