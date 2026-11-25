# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n24.py — СТАТИЧЕСКАЯ проверка N24 «нет лута с низких мобов» (06.11.2026, сессия pet-hatch-summon; документ
#   AstoryServer/Docs/NpcServer/low-mob-loot-n24.md). Поведение — стенд stand_n24 (образы × 5 режимов + опыт GameServer).
#   1. Образы NpcServer (все папки stack_layout.NPC_FOLDERS, md5 = stack_layout.EXE_MD5): sub_437A30 и sub_42E3A0 побайтно одни; площадка
#      0x4387D7 — call sub_455120 на границе инструкций, сразу за push 206Fh (8303), размер 82h; переходов внутрь площадки нет.
#   2. Вторым методом (дизасм): смещения, которые читает N24, — уровень игрока/моба и порог опыта, номер отряда, список угрозы, порядок
#      выбора владельца стока; блок заданий +79EAh идёт ПОСЛЕ площадки; sub_455120 снимает 10h.
#   3. Сброс слота при выходе: sub_421BD0 → sub_426AB0 → sub_42C530 пишет отряду −1.
#   4. Исходник: байты и константы; площадки других N-патчей вне окна. DLL: строка секции, экспорт; AcJournal: 177–180 только N24.
# Запуск: py -3.13 verify_n24.py [AddonNPC.dll]
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
AP = os.path.join(HERE, "..", "..", "AsdaPatch", "tools")
sys.path.insert(0, AP)
import stack_layout                       # единый состав стойки и md5 образов
from srv_paths import ROOT as SRV         # корень зеркала стойки

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
SRC = os.path.join(HERE, "..", "src", "patches", "n24_low_mob_loot.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
JOURNAL = os.path.join(HERE, "..", "..", "AsdaPatch", "src", "AcJournal.cpp")
FUNC, FUNC_END = 0x437A30, 0x438900       # sub_437A30 Process_MonsterDead
SITE, BACK, SEND = 0x4387D7, 0x4387DC, 0x455120
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


def insns(img, lo, hi):
    """Линейный дизасм диапазона → [(адрес, 'мнемоника операнды')]."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return [(i.address, ("%s %s" % (i.mnemonic, i.op_str)).strip()) for i in md.disasm(img.rd(lo, hi - lo), lo)]


def targets_inside(img, lo, hi):
    """Источники rel-переходов внутрь (lo, hi), кроме байтов самой площадки."""
    va0, t = img.text()
    out = []
    for i in range(len(t) - 6):
        b = t[i]
        tg = None
        if 0x70 <= b <= 0x7F or b == 0xEB:
            tg = va0 + i + 2 + struct.unpack_from("<b", t, i + 1)[0]
        elif b in (0xE8, 0xE9):
            tg = va0 + i + 5 + struct.unpack_from("<i", t, i + 1)[0]
        elif b == 0x0F and 0x80 <= t[i + 1] <= 0x8F:
            tg = va0 + i + 6 + struct.unpack_from("<i", t, i + 2)[0]
        if tg is not None and lo < tg < hi and not lo <= va0 + i < hi:
            out.append(va0 + i)
    return out


def check_image(name, path):
    """Пункты 1–3 для одного образа; возвращает md5 тел функций."""
    img = Img(path)
    check(img.rd(SITE, 5) == bytes.fromhex("E844C90100"), "%s: площадка 0x%06X = call sub_455120" % (name, SITE))
    check(img.rd(SEND, 6) == bytes.fromhex("81ECCC020000"), "%s: пролог sub_455120 = sub esp, 2CCh" % name)
    f = insns(img, FUNC, FUNC_END)
    d = dict(f)
    txt = list(d.values())
    check(d.get(SITE) == "call 0x455120" and BACK in d, "%s: площадка и 0x%06X на границах инструкций" % (name, BACK))
    check(d.get(0x4387C4) == "push 0x206f" and d.get(0x4387CD) == "mov ecx, 0x82" and d.get(0x4387C9) == "lea edi, [esp + 0x68]",
          "%s: перед площадкой push 206Fh (8303), ecx = 82h, edi = тело" % name)
    ins = targets_inside(img, SITE, BACK)
    check(not ins, "%s: переходов внутрь площадки нет (%s)" % (name, ", ".join("0x%06X" % x for x in ins) or "0"))
    rets = [v for _, v in insns(img, SEND, 0x4551E0) if v.startswith("ret")]
    check(rets == ["ret 0x10"], "%s: sub_455120 снимает 10h (%s)" % (name, rets))
    check(any("0x785c]" in v for v in txt) and any("0x788a]" in v for v in txt), "%s: уровень моба +785Ch (30812), уровень игрока +788Ah (30858)" % name)
    check(any(v.startswith("cmp") and v.endswith(", 6") for v in txt), "%s: граница опыта — сравнение с 6 в той же функции" % name)
    check(any("0x7a78]" in v or "0x7a84]" in v for v in txt), "%s: список угрозы +7A78h, урон записи +7A84h" % name)
    quest = [a for a, v in f if "0x79ea]" in v]
    check(quest and min(quest) > SITE, "%s: блок заданий +79EAh (0x%06X) идёт ПОСЛЕ площадки" % (name, min(quest) if quest else 0))
    # выход игрока: сброс номера отряда
    r = insns(img, 0x42C530, 0x42C6A0)
    check(any("0x7706]" in v and "0xffff" in v.lower() or "0x7706], " in v for _, v in r), "%s: сброс слота sub_42C530 пишет отряд +7706h (30470)" % name)
    check(any(v == "call 0x426ab0" for _, v in insns(img, 0x421BD0, 0x421C90)), "%s: sub_421BD0 (ReturnPlayerInfoArray) зовёт sub_426AB0" % name)
    return hashlib.md5(img.rd(FUNC, FUNC_END - FUNC)).hexdigest() + hashlib.md5(img.rd(0x42E3A0, 0x160)).hexdigest()


def main():
    print("verify_n24: DLL %s md5 %s" % (DLL, md5(DLL)))
    bodies = {}
    for d in stack_layout.NPC_FOLDERS:
        p = os.path.join(SRV, "v2", d, "NpcServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\NpcServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        bodies[d] = check_image(d, p)
    check(len(set(bodies.values())) == 1, "sub_437A30 и sub_42E3A0 побайтно одни во всех образах")
    s = open(SRC, encoding="utf-8").read()
    consts = {"kOffMobLevel": "30812", "kOffPlayers": "30536", "kOffThreat": "31352", "kThreatStep": "16", "kThreatOrder": "4", "kThreatDamage": "12",
              "kPlayerStep": "68264", "kOffPlayerLv": "30858", "kOffPlayerPty": "30470", "kBodyGold": "128"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, v), s)]
    check(not bad, "исходник: смещения (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    check("0xE8, 0x44, 0xC9, 0x01, 0x00" in s and "kVa     = 0x004387D7" in s, "исходник: байты площадки")
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("n24_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"0x00(43[0-9A-Fa-f]{4})\b", t):
            v = int(mm.group(1), 16)
            if SITE - 0x20 <= v < BACK + 0x20:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    check(not hits, "площадок других патчей у 0x%06X нет (%s)" % (SITE, ", ".join(hits) or "0"))
    d = open(DLL, "rb").read()
    check("N24_LowMobLoot".encode("utf-16-le") in d, "DLL: секция/реестр N24_LowMobLoot")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check("_N24_GetStats@4" in ex, "DLL: экспорт _N24_GetStats@4")
    j = open(JOURNAL, encoding="utf-8", errors="replace").read()
    mine = re.findall(r"case (1(?:77|78|79|80)): return L\"(N\d\d):", j)
    check(sorted(mine) == [("177", "N24"), ("178", "N24"), ("179", "N24"), ("180", "N24")], "AcJournal: ac.other 177–180 — тексты N24 (%s)" % mine)
    print("verify_n24 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
