# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p122.py — СТАТИЧЕСКАЯ проверка P122 «функция питомца не ниже таблицы» (09.11.2026, пачка 20, баг 4;
#   AstoryServer/Docs/GameServer/pet-func-floor-p122.md). Поведение — стенд stand_p122 (3 образа × on/off/hungry0/mismatch).
#   1. Образы GameServer (сток; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка 0x459C0E и опоры совпадают с исходником;
#      sub_459AD0 побайтно одна во всех образах.
#   2. Дизасм стока: площадка — запись значения i-й функции `mov [ecx+eax+19h],edx` перед `jmp 0x459B0F`; переходов внутрь площадки нет;
#      таблица PetInfo — [0x7E0004] (запись 3Ch, значение +24h), число пород — [0x7E0008], множитель уровня — [0x7E000C]+0Dh·ур+5;
#      пороги сытости 4Fh/3Bh/27h, номер функции [ebp-0Ch].
#   3. Исходники: других площадок в 0x459AD0…0x459C20 у патчей нет.
#   4. DLL: экспорт P122_GetStats, заглушка St_FuncFloor (push [ebp-4]; push ebp; call P122_Floor; запись в [ecx+eax+19h]; переход 0x459C15),
#      реестр и секция patches.ini P122_PetFuncFloor.
# Запуск: py -3.13 verify_p122.py [AsdaPatch.dll] [исходник p122]
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
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "src", "patches", "p122_pet_func_floor.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END, SITE, BACK = 0x459AD0, 0x459C20, 0x459C0E, 0x459C15
OK = 0
BAD = 0
MD = Cs(CS_ARCH_X86, CS_MODE_32)


def check(cond, what):
    """Строка проверки и счёт."""
    global OK, BAD
    OK += bool(cond)
    BAD += not cond
    print(("  ok   " if cond else "  FAIL ") + what)


class Img:
    """Образ exe: чтение по VA."""
    def __init__(self, path):
        pe = pefile.PE(path, fast_load=True)
        self.b = pe.get_memory_mapped_image()
        self.base = pe.OPTIONAL_HEADER.ImageBase

    def rd(self, va, n):
        """n байт по VA."""
        return self.b[va - self.base:va - self.base + n]


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def src_bytes(name):
    """Массив байт из исходника P122 по имени константы."""
    s = open(SRC, encoding="utf-8").read()
    m = re.search(r"const BYTE %s\[\d+\]\s*=\s*\{([^}]*)\}" % name, s)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


def main():
    """Проверки и итог."""
    print("== 1. образы GameServer")
    imgs = {"сток": STOCK} if os.path.exists(STOCK) else {}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = p
    want = {SITE: "kSiteOrig", BACK: "kBackOrig", 0x459B49: "kTableBase", 0x459B55: "kTableRead", 0x459B8B: "kFullRead"}
    bodies = set()
    for k, p in imgs.items():
        im = Img(p)
        for va, nm in want.items():
            b = src_bytes(nm)
            check(im.rd(va, len(b)) == b, "%s: 0x%X = %s" % (k, va, nm))
        bodies.add(hashlib.md5(im.rd(FUNC, FUNC_END - FUNC)).hexdigest())
    check(len(bodies) == 1, "sub_459AD0 побайтно одна во всех образах (%d вариантов)" % len(bodies))

    print("== 2. дизасм стока")
    im = Img(STOCK if os.path.exists(STOCK) else imgs[stack_layout.GS_FOLDERS[0]])
    ins = {i.address: i for i in MD.disasm(im.rd(FUNC, FUNC_END - FUNC), FUNC)}
    txt = {a: ("%s %s" % (i.mnemonic, i.op_str)).strip() for a, i in ins.items()}
    check(txt.get(SITE) == "mov edx, dword ptr [ebp - 4]" and txt.get(SITE + 3) == "mov dword ptr [ecx + eax + 0x19], edx",
          "0x459C0E: mov edx,[ebp-4]; mov [ecx+eax+19h],edx — запись значения функции (7 б на границах инструкций)")
    check(txt.get(BACK) == "jmp 0x459b0f", "0x459C15: jmp 0x459B0F — следующая функция")
    into = [a for a, i in ins.items() if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and SITE < int(i.op_str, 16) < BACK]
    check(not into, "переходов внутрь площадки нет (%s)" % [hex(a) for a in into])
    check(txt.get(0x459C00) == "mov word ptr [ecx + eax + 0x17], dx", "0x459C00: тип функции пишется до площадки (+17h)")
    check(txt.get(0x459B28) == "imul ecx, ecx, 0x3c" and txt.get(0x459B2B) == "add ecx, dword ptr [0x7e0004]",
          "PetInfo: запись 3Ch, база [0x7E0004]")
    check(txt.get(0x459B55) == "mov ecx, dword ptr [edx + eax + 0x24]", "значение функции — +24h записи PetInfo (+6 на номер)")
    check(txt.get(0x459AF0) == "movsx edx, word ptr [0x7e0008]", "число пород — i16 [0x7E0008] (сток отсекает породу ≥ числа)")
    check(txt.get(0x459B66) == "mov ecx, dword ptr [0x7e000c]" and txt.get(0x459B6F) == "imul edx, dword ptr [ecx + eax + 5]",
          "множитель уровня — [0x7E000C] + 0Dh·уровень + 5")
    check(txt.get(0x459B8F) == "cmp ecx, 0x4f" and txt.get(0x459BA3) == "cmp ecx, 0x3b" and txt.get(0x459BCB) == "cmp ecx, 0x27",
          "пороги сытости 79 / 59 / 39")
    check(txt.get(0x459B5F) == "movzx eax, byte ptr [edx + 0x13]" and txt.get(0x459B8B) == "movzx ecx, byte ptr [eax + 0x12]",
          "уровень +13h, сытость +12h слота питомца")
    check(txt.get(0x459B4F) == "mov eax, dword ptr [ebp - 0xc]", "номер функции — [ebp-0Ch]")

    print("== 3. исходники других патчей")
    hit = []
    for f in os.listdir(PATCH_DIR):
        if not f.endswith(".cpp") or f.startswith("p122"):
            continue
        for m in re.finditer(r"0x00(459[A-Ca-c][0-9A-Fa-f]{2})\b", open(os.path.join(PATCH_DIR, f), encoding="utf-8", errors="replace").read()):
            v = int(m.group(1), 16)
            if FUNC <= v < FUNC_END:
                hit.append((f, hex(v)))
    check(not hit, "других площадок в 0x459AD0…0x459C20 нет %s" % hit)

    print("== 4. DLL", os.path.basename(DLL), md5(DLL))
    pe = pefile.PE(DLL)
    exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check(any("P122_GetStats" in e for e in exps), "экспорт P122_GetStats")
    raw = open(DLL, "rb").read()
    check("P122_PetFuncFloor".encode("utf-16-le") in raw, "реестр/секция P122_PetFuncFloor в DLL")
    check("FloorWhenHungry".encode("utf-16-le") in raw, "ключ FloorWhenHungry в DLL")
    mtxt = open(MAP, encoding="utf-8", errors="replace").read()
    m = re.search(r"\?St_FuncFloor@\S+\s+([0-9a-f]{8})", mtxt)
    g = re.search(r"_P122_Floor@8\s+([0-9a-f]{8})", mtxt)
    check(bool(m and g), "в карте: St_FuncFloor и P122_Floor")
    if m and g:
        va = int(m.group(1), 16)
        b = pe.get_memory_mapped_image()
        base = pe.OPTIONAL_HEADER.ImageBase
        seq = [(i.mnemonic, i.op_str) for i in list(MD.disasm(b[va - base:va - base + 0x40], va))[:14]]
        check(seq[:5] == [("pushfd", ""), ("push", "eax"), ("push", "ecx"), ("push", "dword ptr [ebp - 4]"), ("push", "ebp")],
              "заглушка: pushfd; push eax; push ecx; push [ebp-4]; push ebp")
        check(seq[5][0] == "call" and int(seq[5][1], 16) == int(g.group(1), 16), "заглушка: call P122_Floor")
        check(("mov", "dword ptr [ecx + eax + 0x19], edx") in seq, "заглушка: штатная запись в [ecx+eax+19h]")
        jumps = [o for mn, o in seq if mn == "jmp" and o.startswith("dword ptr [")]
        vals = []
        for o in jumps:
            a = int(re.search(r"0x([0-9a-f]+)", o).group(1), 16)
            vals.append(struct.unpack("<I", b[a - base:a - base + 4])[0])
        check(vals == [BACK], "переход заглушки: 0x%X (%s)" % (BACK, [hex(v) for v in vals]))
    print("ИТОГ verify_p122 ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
