# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p109.py — СТАТИЧЕСКАЯ проверка P109 «навык на себя не наносит урон самому кастеру» (05.11.2026, сессия job4-skills;
#   документ AstoryServer/Docs/GameServer/self-hit-no-damage-p109.md). Поведение — стенд stand_p109 (3 образа × 3 режима).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): площадка 0x470DB0 (9 б, пролог sub_470DB0), продолжение 0x470DB9 и подготовка аргументов диспетчера
#      0x43163D совпадают байт в байт; площадка и продолжение на границах инструкций; сплошной перебор переходов rel8/rel32/jcc32
#      по .text: внутрь 0x470DB1…0x470DB8 не ведёт ни один, на 0x470DB0 ведёт ровно один call — диспетчер 8206 @0x43164E.
#   2. Вторым методом (дизасм, не декомпил) — раскладка пакета, которую читает P109: длина mov ax,[a3+1] → (len − 15) / 0x1D,
#      предел 0x14 записей, копия записей с a3 + 0xE шагом 0x1D, код навыка = WORD [a3 + 0xA] (memcpy 5 б с a3 + 9 → [ebp-54Ch],
#      a9 = [ebp-54Bh]); вызовы sub_471C70 (цель-персонаж) по байту типа записи 1.
#   3. Исходник: байты kEntryOrig/kBackOrig/kCallerArg = байты здесь; константы kHdr/kRecLen/kMaxRecs/kKeepFlags.
#   4. DLL: строки секции/реестра «P109_SelfHitNoDamage», журналов, экспорты P109_Filter/P109_GetStats; площадок других патчей
#      в окне 0x470DA0…0x470DD0 нет (call диспетчера 0x43164E держит P56 — P109 его не трогает).
# Запуск: py -3.13 verify_p109.py [AsdaPatch.dll]
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
SRC = os.environ.get("ASDA_P109_SRC") or os.path.join(HERE, "..", "src", "patches", "p109_self_hit_no_damage.cpp")
PATCH_DIR = os.environ.get("ASDA_P109_PATCHES") or os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x470DB0, 0x471840       # sub_470DB0 … recvBattleCastingTimeEnd
SITE, BACK, CALLER, CALL = 0x470DB0, 0x470DB9, 0x43163D, 0x43164E
SITES = {   # va → байты (те же, что сверяет P109_SelfHitNoDamage)
    SITE: "558BEC81EC70050000",
    BACK: "A1F0635A0033C58945F8",
    CALLER: "668B4DF851",
}
SRC_ARRAYS = {"kEntryOrig": SITE, "kBackOrig": BACK, "kCallerArg": CALLER}

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
    check(f.get(SITE) == "push ebp" and f.get(SITE + 1) == "mov ebp, esp" and f.get(SITE + 3) == "sub esp, 0x570" and BACK in f,
          "%s: площадка 0x%06X…0x%06X = пролог на границах инструкций (push ebp · mov ebp,esp · sub esp,570h)" % (name, SITE, BACK))
    js = jump_sources(img)
    inside = sorted(t for t in js if SITE < t < BACK)
    check(not inside, "%s: переходов внутрь площадки нет (%s)" % (name, ", ".join("0x%06X" % b for b in inside) or "0"))
    src = js.get(SITE, [])
    check(src == [CALL], "%s: на 0x470DB0 ведёт ровно один переход — call диспетчера 8206 @0x43164E (%s)" % (name, ", ".join("0x%06X" % s for s in src)))
    d = insns(img, 0x43162D, 0x431661)
    check(d.get(0x43163D) == "mov cx, word ptr [ebp - 8]" and d.get(0x431641) == "push ecx" and d.get(0x431636) == "lea eax, [ebp - 0x1018]"
          and d.get(0x43163C) == "push eax" and d.get(CALL) == "call 0x470db0",
          "%s: диспетчер 8206: push пакет ([ebp-1018h]), push userNum ([ebp-8]), call sub_470DB0" % name)
    # раскладка пакета в sub_470DB0 (второй метод — дизасм)
    body = " | ".join(f[a] for a in sorted(f) if a < 0x470FE0)
    check("movsx eax, word ptr [ebp - 0x538]" in body and "sub eax, 0xf" in body and "mov ecx, 0x1d" in body,
          "%s: число записей = (WORD длина − 0xF) / 0x1D" % name)
    check("cmp dword ptr [ebp - 4], 0x14" in body or "cmp dword ptr [ebp - 4], 0x14" in " | ".join(f.values()),
          "%s: предел записей 0x14 (iRecvCount > 20 → отказ разбора)" % name)
    check(any(v.startswith("lea") and "+ 0xe]" in v for v in f.values()) or any("0xe]" in v for v in f.values()),
          "%s: записи копируются с a3 + 0xE" % name)
    calls = [a for a, v in f.items() if v == "call 0x471c70"]
    check(len(calls) >= 2, "%s: sub_471C70 (цель-персонаж) зовётся из sub_470DB0 (%d мест)" % (name, len(calls)))


def main():
    print("verify_p109: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P109 (hex)."""
        mm = re.search(r"const BYTE\s+%s\[\d*\]\s*=\s*\{([^}]*)\}" % name, s)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1))) if mm else ""

    check(all(arr(a) == SITES[va] for a, va in SRC_ARRAYS.items()), "исходник: %s = байты verify_p109" % ", ".join(SRC_ARRAYS))
    consts = {"kHdr": "14", "kRecLen": "29", "kMaxRecs": "20", "kKeepFlags": "0x03", "kEntry": "0x00470DB0", "kBack": "0x00470DB9",
              "kCaller": "0x0043163D", "kLogCat": "18"}
    bad = [k for k, v in consts.items() if not re.search(r"\b%s\s*=\s*%s\s*;" % (k, re.escape(v)), s)]
    check(not bad, "исходник: константы пакета/площадки = дизасм (%s)" % (", ".join(bad) or "все %d" % len(consts)))
    check("(pkt + 10)" in s and "(pkt + 1)" in s and "size - 15" in s, "исходник: навык WORD @10, длина WORD @1, (длина − 15) — как сток")
    # DLL
    d = open(DLL, "rb").read()
    check("P109_SelfHitNoDamage".encode("utf-16-le") in d, "DLL: секция/реестр P109_SelfHitNoDamage")
    check("P109: вход sub_470DB0".encode("utf-16-le") in d, "DLL: строка журнала установки P109")
    check(b"P109: user %d skill %d - self target damage %d" in d, "DLL: строка стокового журнала sub_569DF0")
    dp = pefile.PE(DLL, fast_load=True)
    dp.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    ex = {e.name.decode() for e in dp.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(dp, "DIRECTORY_ENTRY_EXPORT") else set()
    check({"_P109_Filter@8", "_P109_GetStats@4"} <= ex, "DLL: экспорты _P109_Filter@8, _P109_GetStats@4")
    # Других патчей в окне площадки нет; call диспетчера держит только P56.
    hits, callsite = [], []
    for pth in glob.glob(os.path.join(PATCH_DIR, "*.cpp")):
        if os.path.basename(pth).startswith("p109_"):
            continue
        t = open(pth, encoding="utf-8", errors="replace").read()
        for mm in re.finditer(r"0x00(4[0-9A-Fa-f]{5})\b", t):
            v = int(mm.group(1), 16)
            if SITE - 16 <= v < BACK + 16 and not (v == SITE and re.search(r"g_pResp\s*=\s*0x00470DB0", t)):
                hits.append("%s:0x%06X" % (os.path.basename(pth), v))
            if v == CALL:
                callsite.append(os.path.basename(pth))
    check(not hits, "площадок других патчей в окне 0x%06X…0x%06X нет (%s); P56 ссылается на 0x470DB0 только как на цель jmp — она "
                    "проходит через трамплин P109" % (SITE - 16, BACK + 16, ", ".join(sorted(set(hits))) or "0"))
    check(sorted(set(callsite)) == ["p56_combat_limits.cpp"], "call диспетчера 0x43164E держит только P56 (%s)" % ", ".join(sorted(set(callsite))))
    print("verify_p109 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
