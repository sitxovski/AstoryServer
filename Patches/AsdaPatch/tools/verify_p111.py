# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p111.py — СТАТИЧЕСКАЯ проверка P111 «добавка вылупления» (05.11.2026, сессия pet-hatch-summon; документ
#   AstoryServer/Docs/GameServer/hatch-supplement-p111.md). Поведение — стенд stand_p111 (3 образа × 5 режимов).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38): все 4 сверяемых P111
#      участка совпадают байт в байт, вся функция Recv_IncubatorReq 0x454F70…0x455860 — кроме площадок других патчей — та же;
#      площадка 0x4556C3 (6 б) и продолжение 0x4556C9 на границах инструкций; сплошной перебор переходов rel8/rel32/jcc32 по .text:
#      внутрь 0x4556C4…0x4556C8 не ведёт ни один; на 0x4556C3 ведут только ветки разбора слота 3.
#   2. Вторым методом (дизасм, не декомпил) — смысл кадра: [ebp-0E8h] CUser (из sub_5324A0), [ebp-0E0h] код слота 3 (−1 в начале),
#      [ebp-8Ch] значение (0 в начале), [ebp-84h] база (= результат), [ebp-0E4h] катализатор, [ebp-58h] результат 1/9, ГСЧ sub_5329A0(0, 100000);
#      блок 0x455699: код 5, 6103 (push 17D7h), выход 0x455849.
#   3. Данные зеркала стойки (все GS) и стока: 298/322 — подтип 108, значение 30; других записей подтипа 108 нет; таблица шансов — в
#      стотысячных; подсказка оригинала обещает +30%; выдержка стенда = зеркало.
#   4. Исходник: байты массивов = байты здесь; константы = дизасм; кадр трамплина. Площадки других патчей в функции — вне окна P111.
#   5. DLL: строки секции/реестра, журнала, стокового журнала, экспорт P111_GetStats; номера журнала 174–176 больше никто не пишет.
# Запуск: py -3.13 verify_p111.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src", "patches", "p111_hatch_supplement.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
JOURNAL_SRC = os.path.join(HERE, "..", "src", "AcJournal.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
DONOR = r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\ItemTable_Info"
STAND_DATA = os.path.join(HERE, "stand_p111", "data")
FUNC, FUNC_END = 0x454F70, 0x455860       # Recv_IncubatorReq … recvDBIncubatorReq
SITE, BACK, REFUSE, READ3 = 0x4556C3, 0x4556C9, 0x455699, 0x455638
SITES = {   # va → байты (те же, что сверяет P111_HatchSupplement)
    SITE: "DB857CFFFFFF",
    BACK: "8B957CFFFFFF",
    REFUSE: "C64590056A016AFF8D558C52668B4508506A1268D71700008B8D08FFFFFF8B09E832D20600E986010000",
    READ3: "899520FFFFFF8B45F050E849D40D0083C40483F801751E8B4DF081E9475000006BC9478B15985E5F008B440A0E898574FFFFFFEB56"
           "8B4DF051E89AD40D0083C40483F801751B8B55F083EA016BD230A1705E5F000FBF4C1009898D74FFFFFFEB2A",
}
SRC_ARRAYS = {"kSiteOrig": SITE, "kBackOrig": BACK, "kRefuseOrig": REFUSE, "kReadSlot3Orig": READ3}
OTHER_SITES = [0x454F83, 0x455103, 0x455828]   # P63 пролог, P32 байт опкода, P63 отправка в БД — читает-правит та же функция

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
    """{цель: [источники]} всех rel8/rel32 переходов и call по .text (сплошной перебор опкодов, как verify_p110)."""
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
    """Пункты 1–2 для одного образа; возвращает md5 тела функции."""
    img = Img(path)
    for va, hx in SITES.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X (%d б) совпадает" % (name, va, len(hx) // 2))
    f = insns(img, FUNC, FUNC_END)
    check(f.get(SITE) == "fild dword ptr [ebp - 0x84]" and f.get(BACK) == "mov edx, dword ptr [ebp - 0x84]",
          "%s: площадка 0x%06X и продолжение 0x%06X на границах инструкций (fild базы · mov базы)" % (name, SITE, BACK))
    js = jump_sources(img)
    # байт 7C на 0x4556C5 — смещение самой команды fild, а не переход: источники внутри площадки — не команды
    inside = sorted(t for t in js if SITE < t < BACK and any(not SITE <= x < BACK for x in js[t]))
    check(not inside, "%s: переходов внутрь площадки нет (%s)" % (name, ", ".join("0x%06X" % b for b in inside) or "0"))
    src = sorted(js.get(SITE, []))
    check(src and all(READ3 - 0x20 <= s < SITE for s in src),
          "%s: на 0x4556C3 ведут только ветки разбора слота 3 — %s" % (name, ", ".join("0x%06X" % s for s in src)))
    rs = sorted(js.get(REFUSE, []))
    check(rs == [0x45567C], "%s: на блок отказа 0x455699 ведёт только jne из разбора слота 3 (глубина стека та же) — %s" % (name, ", ".join("0x%06X" % s for s in rs)))
    # кадр
    vals = list(f.values())
    check("mov dword ptr [ebp - 0xe0], 0xffffffff" in vals and "mov dword ptr [ebp - 0x8c], 0" in vals
          and f.get(0x455638) == "mov dword ptr [ebp - 0xe0], edx" and f.get(0x455665) == "mov dword ptr [ebp - 0x8c], eax"
          and f.get(0x455691) == "mov dword ptr [ebp - 0x8c], ecx",
          "%s: [ebp-0E0h] код слота 3 (−1 в начале), [ebp-8Ch] значение (0 в начале; dword item_table / word Function_Table)" % name)
    check(f.get(0x455661) == "mov eax, dword ptr [edx + ecx + 0xe]" and f.get(0x45568C) == "movsx ecx, word ptr [eax + edx + 9]",
          "%s: значение — item_table +0x0E (dword), Function_Table +9 (word)" % name)
    cu = [a for a, v in f.items() if v == "mov dword ptr [ebp - 0xe8], eax"]
    check(len(cu) == 1 and any(f.get(a) == "call 0x5324a0" for a in range(cu[0] - 8, cu[0])),
          "%s: [ebp-0E8h] CUser = результат sub_5324A0 (0x%06X)" % (name, cu[0] if cu else 0))
    check(f.get(0x4556CF) == "imul edx, dword ptr [ebp - 0xe4]" and f.get(0x4556EA) == "fiadd dword ptr [ebp - 0x8c]"
          and f.get(0x4556F5) == "mov dword ptr [ebp - 0x84], eax",
          "%s: формула: база · [ebp-0E4h] / 100 + база + [ebp-8Ch] → [ebp-84h]" % name)
    check(f.get(0x4556FB) == "push 0x186a0" and f.get(0x455702) == "call 0x5329a0" and f.get(0x45571C) == "jle 0x455724"
          and f.get(0x45571E) == "mov byte ptr [ebp - 0x58], 1" and f.get(0x455724) == "mov byte ptr [ebp - 0x58], 9",
          "%s: ГСЧ sub_5329A0(0, 100000); шанс > числа → [ebp-58h] = 1, иначе 9" % name)
    check(struct.unpack("<d", img.rd(0x584840, 8))[0] == 100.0, "%s: делитель dbl_584840 = 100.0" % name)
    r = insns(img, REFUSE, SITE)
    check(r.get(REFUSE) == "mov byte ptr [ebp - 0x70], 5" and r.get(0x4556AC) == "push 0x17d7" and r.get(0x4556B9) == "call 0x4c28f0"
          and r.get(0x4556BE) == "jmp 0x455849", "%s: блок отказа 0x455699 — код 5, 6103 (sub_4C28F0), выход 0x455849" % name)
    body = bytearray(img.rd(FUNC, FUNC_END - FUNC))
    return hashlib.md5(bytes(body)).hexdigest()


def rows(path, tcol, vcol):
    """{код: (подтип, значение)} таблицы предметов (первая строка — число записей)."""
    out = {}
    for ln in open(path, "rb").read().split(b"\n")[1:]:
        c = ln.split()
        if len(c) > max(tcol, vcol) and c[0].isdigit():
            out[int(c[0])] = (c[tcol].decode("ascii", "replace"), c[vcol].decode("ascii", "replace"))
    return out


def check_data(name, folder):
    """Пункт 3 для одной папки GameServer."""
    fn = rows(os.path.join(folder, "ItemTable_Info", "Function_Table.txt"), 5, 6)
    check(all(fn.get(k) == ("108", "30") for k in (298, 322, 323, 324)) and fn.get(429) == ("108", "30000"),
          "%s: Function_Table 298/322/323/324 — подтип 108, значение 30; 429 — подтип 108, значение 30000 (масштаб)" % name)
    other = sorted(k for k, v in fn.items() if v[0] == "108" and k not in (298, 322, 323, 324, 429))
    check(not other, "%s: других записей подтипа 108 в Function_Table нет (%s)" % (name, other or "0"))
    it = rows(os.path.join(folder, "ItemTable_Info", "item_table.txt"), 17, 9)
    sp = sorted(k for k, v in it.items() if v[0] == "108")
    check(not sp, "%s: записей подтипа 108 в item_table нет (%s)" % (name, sp[:5] or "0"))
    rate = open(os.path.join(folder, "PetData_Info", "PetIncubateRate_Table.txt"), "rb").read().split()
    check(rate[:3] == [b"10", b"0", b"20000"], "%s: PetIncubateRate_Table в стотысячных (грейд 0 = 20000)" % name)
    return it


def main():
    print("verify_p111: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    its = None
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        if os.path.exists(os.path.join(SRV, "v2", d, "ItemTable_Info", "Function_Table.txt")):   # в зеркале Indun таблиц предметов нет
            its = check_data(d, os.path.join(SRV, "v2", d))
    bodies = {n: check_image(n, p) for n, p in imgs}
    check(len(set(bodies.values())) == 1, "Recv_IncubatorReq побайтно один во всех образах (%s)" % ", ".join(sorted(set(bodies.values()))))
    # Подсказка оригинала и данные стока.
    tip = open(os.path.join(DONOR, "SpecialItem_TooltipList.txt"), "rb").read().decode("cp1251")
    lines = {ln.split("\t")[0].strip(): ln for ln in tip.splitlines() if "\t" in ln}
    check(all("Pet hatching probability + 30% additional probability" in lines.get(k, "") for k in ("298", "322", "323", "324")),
          "сток: подсказка 298/322/323/324 — «Pet hatching probability + 30% additional probability»")
    fs = rows(os.path.join(DONOR, "Function_Table.txt"), 5, 6)
    check(fs.get(298) == ("108", "30") and fs.get(322) == ("108", "30") and fs.get(429) == ("108", "30000"),
          "сток: Function_Table 298/322 — значение то же (30), 429 — 30000: дефект данных оригинала, не наших")
    # Выдержка стенда = зеркало.
    ok = open(os.path.join(STAND_DATA, "Function_Table.txt"), "rb").read() == open(os.path.join(SRV, "v2", "GameServer", "ItemTable_Info", "Function_Table.txt"), "rb").read()
    st = {}
    for ln in open(os.path.join(STAND_DATA, "item_rows.txt"), encoding="ascii"):
        c = ln.split()
        st[int(c[0])] = (c[1], c[2])
    check(ok and all(its.get(k) == v for k, v in st.items()) and len(st) == 37, "данные стенда = зеркало стойки (Function_Table, %d строк item_table)" % len(st))
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P111 (hex)."""
        mm = re.search(r"const BYTE\s+%s\[[^\]]*\]\s*=\s*\{(.*?)\};" % name, s, re.S)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""

    check(all(arr(a) == SITES[va].upper() for a, va in SRC_ARRAYS.items()), "исходник: %s = байты verify_p111" % ", ".join(SRC_ARRAYS))
    consts = {"kSite": "0x004556C3", "kBack": "0x004556C9", "kRefuse": "0x00455699", "kReadSlot3": "0x00455638", "kSpecialTbl": "0x005F5E98",
              "kSpecialMax": "0x005F5EAC", "kSpecialFrom": "20551", "kSpecialRec": "71", "kSpecialSub": "27", "kFuncTbl": "0x005F5E70",
              "kFuncMax": "0x005F5EA4", "kFuncRec": "48", "kFuncSub": "8", "kOffUserIdx": "0x174", "kOffCharSlot": "0x18C"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы площадок/данных = дизасм (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    for frame in ("[ebp+0x08]", "[ebp-0xE4]", "[ebp-0x84]", "[ebp-0x8C]", "[ebp-0xE0]", "[ebp-0xE8]"):
        check(frame in s, "исходник: трамплин читает кадр %s" % frame)
    # Площадки других патчей в функции — вне окна P111.
    hits = []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p111_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"0x00(45[0-9A-Fa-f]{4})\b", t):
            v = int(mm.group(1), 16)
            if SITE - 0x40 <= v < BACK + 0x20:
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
    check(not hits, "площадок других патчей в окне 0x%06X…0x%06X нет (%s)" % (SITE - 0x40, BACK + 0x20, ", ".join(hits) or "0"))
    check(all(not (READ3 <= v < BACK + 6) for v in OTHER_SITES), "P32/P63 в этой функции — вне участков P111")
    # DLL.
    d = open(DLL, "rb").read()
    check("P111_HatchSupplement".encode("utf-16-le") in d, "DLL: секция/реестр P111_HatchSupplement")
    check("P111: инкубатор 6102".encode("utf-16-le") in d, "DLL: строка журнала P111")
    check(b"P111 HatchSupplement: UserNum %d" in d, "DLL: строка стокового журнала sub_569DF0")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check("_P111_GetStats@4" in ex, "DLL: экспорт _P111_GetStats@4")
    # Номера журнала 174–176: тексты только P111.
    j = open(JOURNAL_SRC, encoding="utf-8", errors="replace").read()
    mine = re.findall(r"case (17[456]): return L\"(P1\d\d):", j)
    check(sorted(mine) == [("174", "P111"), ("175", "P111"), ("176", "P111")], "AcJournal: ac.other 174–176 — тексты P111 (%s)" % mine)
    print("verify_p111 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
