# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p99.py — СТАТИЧЕСКАЯ проверка P99 «разделение улучшения выдаёт камень своего типа» (31.10.2026, окно 50500).
#   1. Образы GameServer (сток 4e20f0ad; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): все 7 сверяемых P99 участков совпадают байт в байт; обе площадки (imm8 @0x534DD2 и @0x534E88)
#      лежат ВНУТРИ своих инструкций (линейный проход от начала функции 0x534640) — сплошной перебор переходов rel8/rel32/jcc32
#      по .text: ни один переход не ведёт в 0x534DD1…0x534DD3 и 0x534E87…0x534E89.
#   2. Вторым методом (дизасм, не декомпил): источник v30 — `movzx edx,[ecx+eax+1Ah]; cmp edx,9; jne; mov [ebp-4],2; …1`
#      (Item_Table +0x1A == 9 — оружие); сверка пустых камней: v30 == 2 ⇒ `cmp eax,0CDh` (205), иначе `cmp ecx,0CBh` (203);
#      ветка `cmp ecx,1` берёт запись special +0x4B00 (запись 400 = код 401) и сверяет +0x4B08 с 0CCh (204), ветка
#      `cmp edx,2` — +0x43E0 (запись 362 = код 363) и +0x43E8 с 0CEh (206). После P99 (в памяти копии образа): `cmp ecx,2` /
#      `cmp edx,1`, остальное без изменений — оружие → 401/204, прочее → 363/206. Клиентская таблица special_itemlist
#      (RawAssets ItemDB): 401 — подтип 204, 363 — подтип 206; клиент `itemIsValidColorMixPair`: 204 ↔ itemType 9.
#   3. DLL: строки секции/реестра «P99_UpgradeSplitStone» и строка журнала «P99: разделение улучшения» есть; площадки других
#      патчей в 0x534640…0x535220 (P62/P63: 0x534655, 0x5349DB, 0x535202) не пересекают участки P99 (запас 16 б).
# Запуск: py -3.13 verify_p99.py [AsdaPatch.dll]
import csv
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
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
SPECIAL_CSV = r"@@ASTORY_DEV_ROOT@@\AstoryClient\RawAssets\Data\ItemDB\special_itemlist.csv"
FUNC, FUNC_END = 0x534640, 0x535220
IMM1, IMM2 = 0x534DD2, 0x534E88
SITES = {   # va → байты (те же, что сверяет P99_UpgradeSplitStone)
    0x534DCC: "0FBF4DFC83F9010F85A9000000",
    0x534DD9: "8B15705E5F000FB682084B00003DCC000000",
    0x534E46: "8B15705E5F008B82004B0000",
    0x534E82: "0FBF55FC83FA020F85A5000000",
    0x534E8F: "A1705E5F000FB688E843000081F9CE000000",
    0x534EFB: "A1705E5F008B88E0430000",
    0x534929: "0FB654011A83FA09750866C745FC0200EB0666C745FC0100",
}

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


def jump_targets(img):
    """Все цели rel8/rel32 переходов и call по .text (сплошной перебор опкодов, как verify_p98)."""
    va0, t = img.text()
    out = set()
    for i in range(len(t) - 6):
        b = t[i]
        if 0x70 <= b <= 0x7F or b == 0xEB:
            out.add(va0 + i + 2 + struct.unpack_from("<b", t, i + 1)[0])
        elif b in (0xE8, 0xE9):
            out.add(va0 + i + 5 + struct.unpack_from("<i", t, i + 1)[0])
        elif b == 0x0F and 0x80 <= t[i + 1] <= 0x8F:
            out.add(va0 + i + 6 + struct.unpack_from("<i", t, i + 2)[0])
    return out


def insns(img, lo, hi):
    """Линейный дизасм функции."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(img.rd(lo, hi - lo), lo))


def check_image(name, path):
    """Пункты 1 и 2 для одного образа."""
    img = Img(path)
    for va, hx in SITES.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X (%d б) совпадает" % (name, va, len(hx) // 2))
    ins = insns(img, FUNC, FUNC_END)
    starts = {i.address for i in ins}
    for imm, owner in ((IMM1, 0x534DD0), (IMM2, 0x534E86)):
        check(owner in starts and imm not in starts and imm == owner + 2,
              "%s: imm8 @0x%06X внутри инструкции @0x%06X (граница инструкций)" % (name, imm, owner))
    tg = jump_targets(img)
    bad = [t for t in tg if IMM1 - 1 <= t <= IMM1 + 1 or IMM2 - 1 <= t <= IMM2 + 1]
    check(not bad, "%s: переходов внутрь площадок нет (%s)" % (name, ", ".join("0x%06X" % b for b in bad) or "0"))
    txt = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
    check(txt.get(0x534929, "").startswith("movzx edx, byte ptr [ecx + eax + 0x1a]") and txt.get(0x53492E) == "cmp edx, 9"
          and txt.get(0x534933) == "mov word ptr [ebp - 4], 2" and txt.get(0x53493B) == "mov word ptr [ebp - 4], 1",
          "%s: v30 = (Item_Table +0x1A == 9) ? 2 : 1 (9 — оружие)" % name)
    check(txt.get(0x534AAB) == "cmp edx, 2" and txt.get(0x534AD5) == "cmp eax, 0xcd" and txt.get(0x534B6C) == "cmp ecx, 0xcb",
          "%s: пустые камни: v30 == 2 ⇒ 205, иначе 203 (сток верен)" % name)
    check(txt.get(0x534DD0) == "cmp ecx, 1" and txt.get(0x534DDF) == "movzx eax, byte ptr [edx + 0x4b08]" and txt.get(0x534DE6) == "cmp eax, 0xcc"
          and txt.get(0x534E4C) == "mov eax, dword ptr [edx + 0x4b00]",
          "%s: сток: ветка «v30 == 1» (НЕ оружие) берёт запись 400 (401, подтип 204) — дефект" % name)
    check(txt.get(0x534E86) == "cmp edx, 2" and txt.get(0x534E94) == "movzx ecx, byte ptr [eax + 0x43e8]" and txt.get(0x534E9B) == "cmp ecx, 0xce"
          and txt.get(0x534F00) == "mov ecx, dword ptr [eax + 0x43e0]",
          "%s: сток: ветка «v30 == 2» (оружие) берёт запись 362 (363, подтип 206) — дефект" % name)
    # После P99 — в памяти копии.
    img.data[IMM1 - img.base] = 0x02
    img.data[IMM2 - img.base] = 0x01
    t2 = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in insns(img, FUNC, FUNC_END)}
    same = all(t2.get(a) == txt.get(a) for a in txt if a not in (0x534DD0, 0x534E86))
    check(t2.get(0x534DD0) == "cmp ecx, 2" and t2.get(0x534E86) == "cmp edx, 1" and same and set(t2) == set(txt),
          "%s: после P99 — `cmp ecx,2` / `cmp edx,1`, прочие %d инструкций и их границы без изменений" % (name, len(txt) - 2))


def main():
    print("verify_p99: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)]
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    # Клиентская таблица (код = строка + 1).
    sub = {}
    with open(SPECIAL_CSV, encoding="utf-8-sig", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                sub[int(r["Code"])] = int(r["SubType"])
            except (ValueError, KeyError):
                pass
    check(sub.get(401) == 204 and sub.get(363) == 206 and sub.get(400) == 205 and sub.get(387) == 203,
          "special_itemlist клиента: 401→204 (оружие), 363→206 (доспех), 400→205, 387→203")
    # DLL.
    d = open(DLL, "rb").read()
    check("P99_UpgradeSplitStone".encode("utf-16-le") in d, "DLL: секция/реестр P99_UpgradeSplitStone")
    check("P99: разделение улучшения".encode("utf-16-le") in d, "DLL: строка журнала P99")
    # Других патчей в диапазоне функции нет.
    hits = []
    for p in glob.glob(os.path.join(HERE, "..", "src", "patches", "*.cpp")):
        if os.path.basename(p).startswith("p99_"):
            continue
        s = open(p, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x00(53[45][0-9A-Fa-f]{3})\b", s):
            v = int(m.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(p), v))
    # Чужие площадки в той же функции есть (P62/P63 — вход, проверка слотов, выход); пересечений с участками P99 быть не должно.
    #   Длина чужой врезки неизвестна по одному адресу — берём с запасом 16 байт.
    near = []
    for h in hits:
        v = int(h.split(":0x")[1], 16)
        for va, hx in SITES.items():
            if v < va + len(hx) // 2 and va < v + 16:
                near.append("%s ~ 0x%06X" % (h, va))
    print("       чужие площадки в функции: %s" % (", ".join(sorted(set(hits))) or "нет"))
    check(not near, "чужие площадки (±16 б) не пересекают участки P99 (%s)" % (", ".join(near) or "0"))
    print("verify_p99 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
