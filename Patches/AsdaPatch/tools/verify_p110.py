# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p110.py — СТАТИЧЕСКАЯ проверка P110 «два пула очков навыков» (05.11.2026, сессия job4-points; документ
#   AstoryServer/Docs/GameServer/job4-point-pools-p110.md). Поведение — стенд stand_p110 (3 образа × 5 режимов).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): все 4 сверяемых P110 участка совпадают байт в байт; площадка 0x4778B3 (14 б) и продолжение 0x4778C1
#      на границах инструкций (линейный дизасм Recv_SkillPoint_SkillActive 0x4774C0…0x477B40); сплошной перебор переходов
#      rel8/rel32/jcc32 по .text: внутрь 0x4778B4…0x4778C0 и 0x47787B…0x47787F не ведёт ни один; на 0x4778B3 ведёт ровно один
#      (jge 0x477871 — пройден гейт максимума уровня).
#   2. Вторым методом (дизасм, не декомпил) — смысл полей, которые читает P110:
#      • кадр: [ebp-0D0h] CUser (mov … из sub_5324A0), [ebp-10h] навык, [ebp-0D1h] число, [ebp-0DCh] свободные (sub_52EA20),
#        [ebp-0CCh] код ответа 5254 (push 1486h);
#      • вложено в дерево: cmp [edx+eax*4+0C024h] с деревом byte [SkillInfo+0BDh] (гейт кода 6) и «+= уровень» загрузки sub_475290;
#      • уровень персонажа — байт CUser+0x192 (P29: cmp 3Bh в sub_52E8A0 после movzx [+192h]);
#      • блок отказа 0x47787A…0x4778B2: push 1/0, lea ecx,[ebp-0CCh], push 1486h, call sub_4C28F0, jmp 0x477B21 (выход).
#   3. Исходник: байты kSiteOrig/kBackOrig/kRefuseOrig/kTreeCheckOrig = байты здесь; смещения констант = п. 2.
#   4. DLL: строки секции/реестра «P110_Job4PointPools», журнала «P110: изучение навыка 4-й профессии», стокового журнала, экспорт
#      P110_GetStats; площадок других патчей в Recv_SkillPoint_SkillActive нет; номера журнала 171–173 больше никто не пишет.
# Запуск: py -3.13 verify_p110.py [AsdaPatch.dll]
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
SRC = os.environ.get("ASDA_P110_SRC") or os.path.join(HERE, "..", "src", "patches", "p110_job4_point_pools.cpp")
PATCH_DIR = os.environ.get("ASDA_P110_PATCHES") or os.path.join(HERE, "..", "src", "patches")
JOURNAL_SRC = os.path.join(HERE, "..", "src", "AcJournal.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x4774C0, 0x477B40       # Recv_SkillPoint_SkillActive … sub_477B40
SITE, BACK, REFUSE = 0x4778B3, 0x4778C1, 0x47787A
SITES = {   # va → байты (те же, что сверяет P110_Job4PointPools)
    SITE: "0FBF8D24FFFFFF0FB6952FFFFFFF",
    BACK: "2BCA66898D24FFFFFF",
    0x477873: "C68534FFFFFF026A016A008D8D34FFFFFF51668B55085" "26A6F68861400008B8520FFFFFF8B4804E851B00400C745FCFFFFFFFF8D4DA8E8C21EFBFFE96E020000",
    0x4777BA: "8A4DAC884DD30FB655D30FB6852FFFFFFF03D08855D20FBF4DF069C9D10000008B154C5E5F000FB6840ABD0000000FBF4DF069C9D1000000"
              "8B154C5E5F000FB68C0ABE0000008B9530FFFFFF398C8224C000007D40",
}
SRC_ARRAYS = {"kSiteOrig": SITE, "kBackOrig": BACK, "kRefuseOrig": 0x477873, "kTreeCheckOrig": 0x4777BA}

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
    """{цель: [источники]} всех rel8/rel32 переходов и call по .text (сплошной перебор опкодов, как verify_p108)."""
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


def insns(img, lo, hi):
    """Линейный дизасм диапазона → {адрес: 'мнемоника операнды'}."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return {i.address: ("%s %s" % (i.mnemonic, i.op_str)).strip() for i in md.disasm(img.rd(lo, hi - lo), lo)}


def check_image(name, path):
    """Пункты 1–2 для одного образа."""
    img = Img(path)
    for va, hx in SITES.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X (%d б) совпадает" % (name, va, len(hx) // 2))
    f = insns(img, FUNC, FUNC_END)
    check(f.get(SITE) == "movsx ecx, word ptr [ebp - 0xdc]" and f.get(SITE + 7) == "movzx edx, byte ptr [ebp - 0xd1]"
          and f.get(BACK) == "sub ecx, edx" and f.get(BACK + 2) == "mov word ptr [ebp - 0xdc], cx",
          "%s: площадка 0x%06X…0x%06X на границах инструкций (movsx свободных · movzx числа · sub)" % (name, SITE, BACK))
    js = jump_sources(img)
    inside = sorted(t for t in js if SITE < t < BACK or REFUSE < t < REFUSE + 6)
    check(not inside, "%s: переходов внутрь площадки и входа отказа нет (%s)" % (name, ", ".join("0x%06X" % b for b in inside) or "0"))
    src = js.get(SITE, [])
    check(src == [0x477871] and f.get(0x477871) == "jge 0x4778b3",
          "%s: на 0x4778B3 ведёт только jge 0x477871 (гейт максимума уровня пройден) — %s" % (name, ", ".join("0x%06X" % s for s in src)))
    check(REFUSE not in js, "%s: на вход отказа 0x47787A переходов нет (P110 входит туда сам)" % name)
    # кадр
    check(f.get(0x4776EC) == "mov ecx, dword ptr [eax + 0x34]" and f.get(0x4776EF) == "call 0x52ea20" and f.get(0x4776F4) == "mov word ptr [ebp - 0xdc], ax",
          "%s: свободные [ebp-0DCh] = sub_52EA20 (CUser+0x19B)" % name)
    check(f.get(0x477800) == "mov edx, dword ptr [ebp - 0xd0]" and f.get(0x477806) == "cmp dword ptr [edx + eax*4 + 0xc024], ecx"
          and f.get(0x4777E0) == "movzx eax, byte ptr [edx + ecx + 0xbd]" and f.get(0x4777F8) == "movzx ecx, byte ptr [edx + ecx + 0xbe]"
          and f.get(0x4777D0) == "movsx ecx, word ptr [ebp - 0x10]",
          "%s: гейт кода 6 — [ebp-0D0h] CUser, [ebp-10h] навык, дерево SkillInfo +0xBD, требование +0xBE, вложено CUser+0xC024+4·дерево" % name)
    r = insns(img, REFUSE, 0x4778B3)
    check(r.get(REFUSE) == "push 1" and r.get(0x47787E) == "lea ecx, [ebp - 0xcc]" and r.get(0x47788C) == "push 0x1486"
          and r.get(0x47789A) == "call 0x4c28f0" and r.get(0x4778AE) == "jmp 0x477b21",
          "%s: блок отказа 0x47787A — тело [ebp-0CCh] уходит 5254 (sub_4C28F0), выход 0x477B21" % name)
    # загрузка вложенного по деревьям sub_475290: += уровень по CUser+0xC024
    ld = insns(img, 0x475290, 0x475650)
    check(any("+ 0xc024]" in v and v.startswith("add") for v in ld.values()) and any("+ 0xc024], " in v and v.startswith("mov") for v in ld.values()),
          "%s: sub_475290 (загрузка навыков) прибавляет уровень к CUser+0xC024+4·дерево" % name)
    # уровень персонажа CUser+0x192 (sub_52E8A0: movzx [+192h], cmp 3Bh)
    lv = insns(img, 0x52E8A0, 0x52E900)
    check(any(v == "movzx edx, byte ptr [eax + 0x192]" or ("byte ptr [" in v and "+ 0x192]" in v and v.startswith("movzx")) for v in lv.values()),
          "%s: уровень персонажа — байт CUser+0x192 (sub_52E8A0)" % name)


def main():
    print("verify_p110: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P110 (hex)."""
        mm = re.search(r"const BYTE\s+%s\[[^\]]*\]\s*=\s*\{([^}]*)\}" % name, s)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""

    check(all(arr(a) == SITES[va].upper() for a, va in SRC_ARRAYS.items()), "исходник: %s = байты verify_p110" % ", ".join(SRC_ARRAYS))
    consts = {"kSite": "0x004778B3", "kBack": "0x004778C1", "kRefuseBlock": "0x00477873", "kRefuseEntry": "0x0047787A",
              "kSkillInfo": "0x005F5E4C", "kSkillCount": "0x005F5ECC", "kSkillRec": "209", "kOffRecTree": "0xBD",
              "kOffTreePts": "0xC024", "kOffLevel": "0x192", "kOffUserIdx": "0x174", "kOffCharSlot": "0x18C"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы площадок/кадра/данных = дизасм (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    for frame in ("[ebp+0x08]", "[ebp-0xDC]", "[ebp-0xD1]", "[ebp-0x10]", "[ebp-0xD0]", "[ebp-0xCC]"):
        check(frame in s, "исходник: трамплин читает кадр %s" % frame)
    # DLL.
    d = open(DLL, "rb").read()
    check("P110_Job4PointPools".encode("utf-16-le") in d, "DLL: секция/реестр P110_Job4PointPools")
    check("P110: изучение навыка 4-й профессии".encode("utf-16-le") in d, "DLL: строка журнала P110 (171)")
    check(b"P110 Job4PointPools: UserNum %d" in d, "DLL: строка стокового журнала sub_569DF0")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check("_P110_GetStats@4" in ex, "DLL: экспорт _P110_GetStats@4")
    # Других патчей в Recv_SkillPoint_SkillActive нет.
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p110_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"0x00(47[0-9A-Fa-f]{4})\b", t):
            v = int(mm.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    check(not hits, "площадок других патчей в 0x%06X…0x%06X нет (%s)" % (FUNC, FUNC_END, ", ".join(hits) or "0"))
    # Номера журнала 171–173: тексты только P110.
    j = open(JOURNAL_SRC, encoding="utf-8", errors="replace").read()
    mine = re.findall(r"case (17[123]): return L\"(P1\d\d):", j)
    check(sorted(mine) == [("171", "P110"), ("172", "P110"), ("173", "P110")], "AcJournal: ac.other 171–173 — тексты P110 (%s)" % mine)
    print("verify_p110 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
