# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p112.py — СТАТИЧЕСКАЯ проверка P112 «разброс уровней отряда в опыте» (06.11.2026, сессия pet-hatch-summon; документ
#   AstoryServer/Docs/GameServer/party-exp-spread-p112.md). Поведение — стенд stand_p112 (образы × 6 режимов).
#   1. Образы GameServer (сток; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): участки P112 совпадают; sub_4C7650 побайтно один; площадка на
#      границах инструкций; внутрь площадки переходов нет; на неё ведёт только выход цикла по записям.
#   2. Дизасм: кадр ([ebp-200h] менеджер, [ebp-1B0h] тело, [ebp-150h] максимум, [ebp-1B4h] минимум = 3Bh на старте), поля CUser +402/+436/+372.
#   3. Исходник: байты и константы; площадок других патчей в функции нет. DLL: секция, экспорт. AcJournal: 181–183 только P112.
# Запуск: py -3.13 verify_p112.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src", "patches", "p112_party_exp_spread.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
JOURNAL_SRC = os.path.join(HERE, "..", "src", "AcJournal.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x4C7650, 0x4C7C70       # sub_4C7650 … sub_4C7C70
SITE, BACK, MININIT = 0x4C7A8E, 0x4C7A9A, 0x4C77E7
SITES = {SITE: "8B8DB0FEFFFF2B8D4CFEFFFF", BACK: "83F90A7C05", MININIT: "C7854CFEFFFF3B000000"}
SRC_ARRAYS = {"kSiteOrig": SITE, "kBackOrig": BACK, "kMinInitOrig": MININIT}
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


def check_image(name, path):
    """Пункты 1–2 для одного образа; возвращает md5 тела функции."""
    img = Img(path)
    for va, hx in SITES.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X совпадает" % (name, va))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    f = {i.address: ("%s %s" % (i.mnemonic, i.op_str)).strip() for i in md.disasm(img.rd(FUNC, FUNC_END - FUNC), FUNC)}
    vals = list(f.values())
    check(f.get(SITE) == "mov ecx, dword ptr [ebp - 0x150]" and f.get(SITE + 6) == "sub ecx, dword ptr [ebp - 0x1b4]" and f.get(BACK) == "cmp ecx, 0xa"
          and f.get(BACK + 3) == "jl 0x4c7aa4", "%s: площадка: максимум − минимум, cmp ecx,0Ah, jl — на границах инструкций" % name)
    check(f.get(MININIT) == "mov dword ptr [ebp - 0x1b4], 0x3b", "%s: минимум стартует с 3Bh (59)" % name)
    check("mov dword ptr [ebp - 0x150], 0" in vals, "%s: максимум стартует с 0" % name)
    check(sum(v == "mov ecx, dword ptr [ebp - 0x200]" for v in vals) >= 1, "%s: [ebp-200h] — this (менеджер) перед sub_5324A0" % name)
    check(any("0x192]" in v and "movzx" in v for v in vals) and any("0x1b4]" in v and "movsx" in v for v in vals),
          "%s: уровень CUser+0x192 (402), отряд CUser+0x1B4 (436)" % name)
    check(any(v.startswith("lea") and "[ebp - 0x1b0]" in v for v in vals), "%s: тело 8306 — [ebp-1B0h]" % name)
    js = jump_sources(img)
    inside = sorted(t for t in js if SITE < t < BACK and any(not SITE <= x < BACK for x in js[t]))
    check(not inside, "%s: переходов внутрь площадки нет (%s)" % (name, ", ".join("0x%06X" % b for b in inside) or "0"))
    src = js.get(SITE, [])
    check(len(src) == 1 and FUNC < src[0] < SITE, "%s: на площадку ведёт только выход цикла (%s)" % (name, ", ".join("0x%06X" % x for x in src)))
    # Общий пул: [0x60AD18+0x12E0] = 0x60BFF8; шаг 0x40BA0 (imul …, 40BA0h) и цикл 550 в инициализации sub_4A0… (CThreadManager); свой CUserManager у потока.
    va0, t = img.text()
    check(t.count(bytes.fromhex("A00B0400")) > 100, "%s: шаг записи пула 0x40BA0 в коде (imul, %d мест)" % (name, t.count(bytes.fromhex("A00B0400"))))
    check(t.count(bytes.fromhex("E0120000")) > 50, "%s: поле пула +12E0h объекта 0x60AD18 в коде" % name)
    return hashlib.md5(img.rd(FUNC, FUNC_END - FUNC)).hexdigest()


def main():
    print("verify_p112: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    bodies = {n: check_image(n, p) for n, p in imgs}
    check(len(set(bodies.values())) == 1, "sub_4C7650 побайтно один во всех образах")
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника (hex)."""
        mm = re.search(r"const BYTE\s+%s\[[^\]]*\]\s*=\s*\{(.*?)\};" % name, s, re.S)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""

    check(all(arr(a) == SITES[va] for a, va in SRC_ARRAYS.items()), "исходник: %s = байты verify_p112" % ", ".join(SRC_ARRAYS))
    consts = {"kSite": "0x004C7A8E", "kBack": "0x004C7A9A", "kMinInit": "0x004C77E7", "kOffLevel": "402", "kOffParty": "436", "kOffUserIdx": "372", "kMaxSlots": "0x226",
              "kUserPool": "0x0060BFF8", "kUserStep": "0x40BA0"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    for frame in ("[ebp-0x1B4]", "[ebp-0x150]", "[ebp-0x1B0]", "[ebp-0x200]"):
        check(frame in s, "исходник: трамплин читает кадр %s" % frame)
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p112_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"constexpr DWORD \w+\s*=\s*0x00(4C[0-9A-Fa-f]{4})\b", t):
            v = int(mm.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    check(not hits, "площадок других патчей в 0x%06X…0x%06X нет (%s)" % (FUNC, FUNC_END, ", ".join(hits) or "0"))
    d = open(DLL, "rb").read()
    check("P112_PartyExpSpread".encode("utf-16-le") in d, "DLL: секция/реестр P112_PartyExpSpread")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check("_P112_GetStats@4" in ex, "DLL: экспорт _P112_GetStats@4")
    j = open(JOURNAL_SRC, encoding="utf-8", errors="replace").read()
    mine = re.findall(r"case (18[123]): return L\"(P1\d\d):", j)
    check(sorted(mine) == [("181", "P112"), ("182", "P112"), ("183", "P112")], "AcJournal: ac.other 181–183 — тексты P112 (%s)" % mine)
    print("verify_p112 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
