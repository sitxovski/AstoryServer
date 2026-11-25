# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p117.py — СТАТИЧЕСКАЯ проверка P117 «набор уровня не применяется, пока действует прежний» (09.11.2026, пачка 19, баг 9;
#   AstoryServer/Docs/GameServer/plus-pack-once-p117.md).
#   1. Образы GameServer (сток 4e20f0ad; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка 0x4EE25B и соседи совпадают с исходником.
#   2. Дизасм стока: 0x4EE25B — первая инструкция case 120 (jumptable 0x4EDEE5), переходов внутрь площадки нет; CUser [ebp-20Ch] — sub_5324A0,
#      пустой отсекается до switch; остаток +0xBFC7 пишет recvDBPlusPakege (0x4F91A1, ×60) и уменьшает таймер sub_4F9210 (0x4F9248);
#      общий выход 0x4EF0C3 шлёт 5451 с [ebp-121h]; case 120 не проходит площадки P75 0x4EDDC7 / 0x4EF02E и P103 S2 0x4EE5A1.
#   3. DLL: экспорт P117_GetStats, заглушка St_PlusGate — сохранение регистров, вызов P117_Gate, отказ пишет 10h в [ebp-121h],
#      переходы через ячейки с 0x4EE261 и 0x4EF0C3. Других площадок в 0x4EE25B…0x4EE261 у патчей нет.
# Запуск: py -3.13 verify_p117.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src", "patches", "p117_plus_pack_once.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, SITE, BACK, REFUSE = 0x4ED780, 0x4EE25B, 0x4EE261, 0x4EF0C3
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
        return self.b[va - self.base:va - self.base + n]


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def src_bytes(name):
    """Массив байт из исходника P117 по имени константы."""
    s = open(SRC, encoding="utf-8").read()
    m = re.search(r"const BYTE %s\[\d+\]\s*=\s*\{([^}]*)\}" % name, s)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


def main():
    """Проверки и итог."""
    print("== 1. образы GameServer")
    imgs = {"сток": STOCK}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = p
    want = {0x4EE25B: "kSiteOrig", 0x4EE261: "kBackOrig", 0x4EF0C3: "kRefuseOrig", 0x4ED9CF: "kUserStore", 0x4F9248: "kTimerRead", 0x4F91A1: "kDbWrite"}
    for k, p in imgs.items():
        im = Img(p)
        for va, nm in want.items():
            b = src_bytes(nm)
            check(im.rd(va, len(b)) == b, "%s: 0x%X = %s" % (k, va, nm))

    print("== 2. дизасм стока")
    im = Img(STOCK)
    code = im.rd(FUNC, 0x1A90)
    ins = list(MD.disasm(code, FUNC))
    into = [i for i in ins if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and SITE < int(i.op_str, 16) < BACK]
    check(not into, "переходов внутрь площадки 0x4EE25B…0x4EE261 нет")
    jt = [i for i in ins if i.address == 0x4EDEE5]
    check(bool(jt) and jt[0].mnemonic == "jmp", "0x4EDEE5 — переход по таблице case")
    tbl = struct.unpack("<I", im.rd(0x4EDEE5 + 3, 4))[0] if jt else 0
    idx = im.rd(0x4EDEDF, 1)
    case_idx = [i for i in ins if 0x4EDED0 <= i.address < 0x4EDEE5]
    # таблица переходов: dword-цели, case 120 → 0x4EE25B (ищем саму цель среди элементов таблицы)
    targets = [struct.unpack("<I", im.rd(tbl + 4 * k, 4))[0] for k in range(64)] if tbl else []
    check(SITE in targets, "0x4EE25B — цель таблицы case (case 120)")
    user = [i for i in ins if i.address == 0x4ED9CA]
    check(bool(user) and user[0].op_str == "0x5324a0", "0x4ED9CA call sub_5324A0 → [ebp-20Ch]")
    nul = [i for i in ins if i.address == 0x4ED9DC]
    check(bool(nul) and nul[0].mnemonic == "jne", "0x4ED9DC: пустой CUser — отказ до switch")
    db = list(MD.disasm(im.rd(0x4F9195, 0x20), 0x4F9195))
    check(any(i.mnemonic == "imul" and i.op_str.endswith("0x3c") for i in db), "recvDBPlusPakege: остаток × 60 (секунды)")
    check(any(i.mnemonic == "mov" and i.op_str == "dword ptr [ecx], edx" for i in db) and any(i.op_str == "word ptr [ecx + 4], ax" for i in db),
          "recvDBPlusPakege: [ecx]=+0xBFC5 (номер + младшие 16 бит остатка), [ecx+4]=старшие 16 → остаток i32 по +0xBFC7")
    tm = list(MD.disasm(im.rd(0x4F9248, 0x28), 0x4F9248))
    check(any(i.op_str == "edx, 1" and i.mnemonic == "sub" for i in tm) and any(i.op_str == "dword ptr [eax + 0xbfc7], edx" for i in tm),
          "таймер sub_4F9210: остаток +0xBFC7 уменьшается на 1")
    ex = list(MD.disasm(im.rd(REFUSE, 0x80), REFUSE))
    check(any(i.mnemonic == "push" and i.op_str == "0x44" for i in ex) and any(i.op_str == "0x154b" for i in ex),
          "0x4EF0C3: 5451 (0x154B) длиной 68 с кодом [ebp-121h]")
    case = list(MD.disasm(im.rd(SITE, 0x150), SITE))
    calls = [i.op_str for i in case if i.mnemonic == "call" and i.address < 0x4EE3A6]
    check("0x5646c0" in calls and all(c not in calls for c in ("0x4f27f0",)), "case 120: уход в БД 0x5646C0 без площадок P75 (0x4EDDC7 до switch)")

    print("== 3. исходники других патчей")
    hit = []
    for f in os.listdir(PATCH_DIR):
        if not f.endswith(".cpp") or f.startswith("p117"):
            continue
        for m in re.finditer(r"0x004EE2[5-6][0-9A-Fa-f]\b", open(os.path.join(PATCH_DIR, f), encoding="utf-8", errors="replace").read()):
            hit.append((f, m.group(0)))
    check(not hit, "другие патчи 0x4EE25B…0x4EE261 не трогают %s" % hit)

    print("== 4. DLL", os.path.basename(DLL), md5(DLL))
    pe = pefile.PE(DLL)
    exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check(any("P117_GetStats" in e for e in exps), "экспорт P117_GetStats")
    txt = open(MAP, encoding="utf-8", errors="replace").read()
    m = re.search(r"\?St_PlusGate@\S+\s+([0-9a-f]{8})", txt)
    g = re.search(r"_P117_Gate@4\s+([0-9a-f]{8})", txt)
    check(bool(m and g), "в карте: St_PlusGate и P117_Gate")
    if m and g:
        va = int(m.group(1), 16)
        b = pe.get_memory_mapped_image()
        base = pe.OPTIONAL_HEADER.ImageBase
        st = list(MD.disasm(b[va - base:va - base + 0x40], va))
        seq = [(i.mnemonic, i.op_str) for i in st[:16]]
        check(seq[0][0] == "pushfd" and seq[1][0] == "pushal" and seq[2] == ("push", "ebp"), "заглушка: pushfd; pushad; push ebp")
        check(seq[3][0] == "call" and int(seq[3][1], 16) == int(g.group(1), 16), "заглушка: call P117_Gate")
        check(("mov", "byte ptr [ebp - 0x121], 0x10") in seq, "отказ: [ebp-121h] = 10h")
        check(("mov", "eax, dword ptr [ebp - 0x204]") in seq, "сток: mov eax,[ebp-204h] повторён")
        jumps = [o for mnem, o in seq if mnem == "jmp" and o.startswith("dword ptr [")]
        vals = []
        for o in jumps:
            a = int(re.search(r"0x([0-9a-f]+)", o).group(1), 16)
            vals.append(struct.unpack("<I", b[a - base:a - base + 4])[0])
        check(sorted(vals) == [BACK, REFUSE], "переходы заглушки: 0x%X и 0x%X (%s)" % (BACK, REFUSE, [hex(v) for v in vals]))
    print("ИТОГ verify_p117 ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
