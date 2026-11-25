# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p108.py — СТАТИЧЕСКАЯ проверка P108 «выход из данжа сохраняется в точку входа» (05.11.2026, сессия dungeon-relog;
#   документ AstoryServer/Docs/GameServer/dungeon-relog-entry-p108.md). Поведение — стенд stand_p108 (3 образа × 4 режима).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): все 6 сверяемых P108 участков совпадают байт в байт; площадка 0x5257A0 (10 б) и продолжение 0x5257AA
#      на границах инструкций (линейный дизасм DisConnectUser 0x5245D0…0x525EB0); сплошной перебор переходов rel8/rel32/jcc32 по
#      .text: внутрь 0x5257A1…0x5257A9 не ведёт ни один; на 0x5257A0 сходятся обе ветки выбора X/Z (jmp 0x5257A0 и проход).
#   2. Вторым методом (дизасм, не декомпил) — смысл полей, которые читает P108:
#      • пакет 2003: X/Z [ebp-5C0h]/[ebp-5BEh] ← CUser+0x54E6/+0x54E8; карта [ebp-5BBh] ← movsx [ebp-15h]; this = [ebp-ACCh];
#        отправка push 0B7h · push 7D3h · call sub_5646C0;
#      • MapInfo (загрузчик sub_4B3810): +0x3F атрибут, +0x60 число точек, +0x62 + 2j X, +0x6C + 2j Z, шаг 0xEC, массив 0x5F5E18;
#      • сток 9915 (sub_521770): при атрибуте 3 берёт ИМЕННО +0x62/+0x6C записи своей карты (точка старта данжа оригинала);
#      • порталы (LoadPortalServerInfo sub_522930): +0x910 число, +0x914 записи шагом 0x29, STARTPOSX +0x934, STARTPOSZ +0x936;
#      • карта потока sub_40C960 = байт CUserManager+0x8E9.
#   3. Исходник: байты kSiteOrig/kBackOrig/… = байты здесь; смещения констант = п. 2.
#   4. DLL: строки секции/реестра «P108_DungeonRelogEntry», журнала «P108: выход/обрыв в данже», экспорты P108_Decide/P108_GetStats;
#      площадок других патчей в окне площадки нет (в функции — только P35 у входа и P71 у штрафа, известные).
# Запуск: py -3.13 verify_p108.py [AsdaPatch.dll]
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
SRC = os.environ.get("ASDA_P108_SRC") or os.path.join(HERE, "..", "src", "patches", "p108_dungeon_relog_entry.cpp")   # копия исходника вне дерева
PATCH_DIR = os.environ.get("ASDA_P108_PATCHES") or os.path.join(HERE, "..", "src", "patches")                       # исходники прочих патчей
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x5245D0, 0x525EB0       # DisConnectUser … PortalDisConnectUser
SITE, BACK = 0x5257A0, 0x5257AA
SITES = {   # va → байты (те же, что сверяет P108_DungeonRelogEntry)
    SITE: "0FBE4DEB898D45FAFFFF",
    BACK: "B918AD6000",
    0x525778: "8B853CF8FFFF668B88E654000066898D40FAFFFF",
    0x525818: "8D8540FAFFFF508B8D34F5FFFF8B4904",
    0x52582D: "5068B700000068D3070000",
    0x40C96A: "8A80E9080000",
}
SRC_ARRAYS = {"kSiteOrig": SITE, "kBackOrig": BACK, "kPosX": 0x525778, "kBody": 0x525818, "kSend": 0x52582D, "kMgrMapOp": 0x40C96A}

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

    def cstr(self, va):
        """Строка ASCII по VA."""
        b = self.rd(va, 64)
        return b.split(b"\0")[0].decode("latin-1")

    def text(self):
        """(va начала, байты) секции .text."""
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".text":
                va = self.base + s.VirtualAddress
                return va, bytes(self.data[s.VirtualAddress: s.VirtualAddress + s.Misc_VirtualSize])
        raise RuntimeError("нет .text")


def jump_sources(img):
    """{цель: [источники]} всех rel8/rel32 переходов и call по .text (сплошной перебор опкодов, как verify_p106)."""
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
    check(SITE in f and BACK in f and f[SITE] == "movsx ecx, byte ptr [ebp - 0x15]" and f[SITE + 4] == "mov dword ptr [ebp - 0x5bb], ecx",
          "%s: площадка 0x%06X…0x%06X на границах инструкций (movsx карты · mov в пакет)" % (name, SITE, BACK))
    js = jump_sources(img)
    inside = sorted(t for t in js if SITE < t < BACK)
    check(not inside, "%s: переходов внутрь площадки нет (%s)" % (name, ", ".join("0x%06X" % b for b in inside) or "0"))
    src = js.get(SITE, [])
    check(any(FUNC <= s < FUNC_END for s in src) and f.get(0x525776) == "jmp 0x5257a0" and 0x525778 + 0x28 == SITE,
          "%s: на 0x5257A0 сходятся обе ветки X/Z (jmp от 0x525776, проход после 0x525778)" % name)
    # пакет 2003
    check(f.get(0x525778) == "mov eax, dword ptr [ebp - 0x7c4]" and f.get(0x52577E) == "mov cx, word ptr [eax + 0x54e6]"
          and f.get(0x525785) == "mov word ptr [ebp - 0x5c0], cx" and f.get(0x525792) == "mov ax, word ptr [edx + 0x54e8]"
          and f.get(0x525799) == "mov word ptr [ebp - 0x5be], ax", "%s: X/Z пакета [ebp-5C0h]/[ebp-5BEh] ← CUser+0x54E6/+0x54E8" % name)
    check(f.get(0x525818) == "lea eax, [ebp - 0x5c0]" and f.get(0x52581F) == "mov ecx, dword ptr [ebp - 0xacc]"
          and f.get(0x52582E) == "push 0xb7" and f.get(0x525833) == "push 0x7d3" and f.get(0x52583D, "").startswith("call 0x5646c0"),
          "%s: тело [ebp-5C0h] уходит в БД 2003 (длина 0xB7) через sub_5646C0; this = [ebp-ACCh]" % name)
    # MapInfo
    mi = insns(img, 0x4B3810, 0x4B4200)
    check(mi.get(0x4B3B44) == "mov byte ptr [edx + ecx + 0x3f], al" and mi.get(0x4B3F00) == "mov word ptr [edx + ecx + 0x60], ax"
          and mi.get(0x4B3F76) == "mov word ptr [edx + ecx*2 + 0x62], ax" and mi.get(0x4B3FBE) == "mov word ptr [ecx + edx*2 + 0x6c], ax",
          "%s: загрузчик MapInfo sub_4B3810 — +0x3F атрибут, +0x60 число точек, +0x62/+0x6C точки" % name)
    h = insns(img, 0x521770, 0x5218A0)
    check(h.get(0x521834) == "cmp ecx, 3" and h.get(0x521843) == "mov eax, dword ptr [0x5f5e18]"
          and h.get(0x521848) == "mov cx, word ptr [eax + edx + 0x62]" and h.get(0x521863) == "mov cx, word ptr [eax + edx + 0x6c]",
          "%s: сток 9915 sub_521770 — при атрибуте 3 точка старта +0x62/+0x6C своей карты" % name)
    # порталы
    p = insns(img, 0x522930, 0x522E80)
    check(p.get(0x522B5E) == "mov dword ptr [ecx + 0x910], eax" and p.get(0x522BFB) == "imul edx, edx, 0x29"
          and p.get(0x522C04) == "mov dword ptr [ecx + edx + 0x914], eax" and p.get(0x522D99) == "mov word ptr [ecx + edx + 0x934], ax"
          and p.get(0x522DCB) == "mov word ptr [edx + ecx + 0x936], ax" and img.cstr(0x58F014) == "STARTPOSX" and img.cstr(0x58F008) == "STARTPOSZ",
          "%s: LoadPortalServerInfo — +0x910 число, +0x914 шаг 0x29, STARTPOSX +0x934 / STARTPOSZ +0x936" % name)
    m = insns(img, 0x40C960, 0x40C974)
    check(m.get(0x40C96A) == "mov al, byte ptr [eax + 0x8e9]", "%s: sub_40C960 — карта потока = байт CUserManager+0x8E9" % name)


def main():
    print("verify_p108: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    # Исходник: байты площадок = байты этой проверки; константы смещений.
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P108 (hex)."""
        mm = re.search(r"const BYTE\s+%s\[\d*\]\s*=\s*\{([^}]*)\}" % name, s)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""

    check(all(arr(a) == SITES[va] for a, va in SRC_ARRAYS.items()), "исходник: %s = байты verify_p108" % ", ".join(SRC_ARRAYS))
    consts = {"kFrMap": "-0x15", "kFrPosX": "-0x5C0", "kFrPosZ": "-0x5BE", "kFrUser": "-0x7C4", "kFrMgr": "-0xACC", "kMiStride": "0xEC",
              "kMiPtCount": "0x60", "kMiPtX": "0x62", "kMiPtZ": "0x6C", "kMgrMap": "0x8E9", "kMgrPtCount": "0x910", "kMgrPortal": "0x914",
              "kPtStride": "41", "kPtStartX": "0x20", "kPtStartZ": "0x22", "kMapInfoPtr": "0x005F5E18", "kMapCount": "0x005F5EE8"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы кадра/MapInfo/порталов = дизасм (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    check(0x914 + 0x20 == 0x934 and 0x914 + 0x22 == 0x936, "STARTPOSX/Z записи 0 = +0x914 + 0x20/0x22 (0x934/0x936)")
    # DLL.
    d = open(DLL, "rb").read()
    check("P108_DungeonRelogEntry".encode("utf-16-le") in d, "DLL: секция/реестр P108_DungeonRelogEntry")
    check("P108: выход/обрыв в данже".encode("utf-16-le") in d, "DLL: строка журнала P108")
    check(b"P108 DungeonRelogEntry: %s UserIndex" in d, "DLL: строка стокового журнала sub_569DF0")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check({"_P108_Decide@4", "_P108_GetStats@4"} <= ex, "DLL: экспорты _P108_Decide@4, _P108_GetStats@4")
    # Других патчей в диапазоне функции нет.
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p108_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"0x00(52[45][0-9A-Fa-f]{3})\b", t):
            v = int(mm.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    # P35 (вход DisConnectUser 0x5245D0 → 0x5245D9: стоковый пролог повторяется в трамплине, кадр тот же) и P71 (гейт штрафа
    #   0x525C9D…0x525CB2) стоят в той же функции, но не в окне площадки P108; пересечение окна 0x5257A0…0x5257AF — провал.
    near = sorted(set(hits))
    clash = [h for h in near if SITE - 16 < int(h.split(":0x")[1], 16) < BACK + 16]
    known = {"p35_craft_server_defects.cpp", "p71_tick_deadline_wrap.cpp"}
    check(not clash and all(h.split(":")[0] in known for h in near),
          "площадок других патчей в окне 0x%06X…0x%06X нет; в функции только известные P35/P71 (%s)" % (SITE - 16, BACK + 16, ", ".join(near) or "0"))
    print("verify_p108 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
