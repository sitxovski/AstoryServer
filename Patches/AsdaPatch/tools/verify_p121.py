# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p121.py — СТАТИЧЕСКАЯ проверка P121 «предмет смены имени не тратится через 5450» (09.11.2026, пачка 20, баг 8;
#   AstoryServer/Docs/GameServer/char-rename-guard-p121.md).
#   1. Образы GameServer (сток 4e20f0ad; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка 0x4EDEB3 и соседи совпадают с исходником.
#   2. Дизасм стока: 0x4EDEB3 — запись категории в [ebp-2FCh] перед switch (cmp 0C5h, ja 0x4EE5A1, таблица 0x4EF17C/0x4EF14C);
#      категория 111 → индекс 96 → default 0x4EE5A1; переходов внутрь площадки нет; общий выход 0x4EF0C3 шлёт 5451 с [ebp-121h];
#      default (LABEL_69) уходит в БД 2140 (0x5646C0) — то, от чего защищает P121.
#   3. Совместимость: площадки P75 / P102 S5 / P65 / P100 / P15 / P97 / P117 / P103 S2 лежат вне 0x4EDEB3…0x4EDEB9; P117 0x4EE25B и
#      P103 S2 0x4EE5A1 — после switch (их ветки P121 не меняет, кроме категории 111, которая до 0x4EE5A1 больше не доходит);
#      P75 (код 558, категория 6) проходит P121 своей категорией; других площадок в 0x4EDEB3…0x4EDEB9 у патчей нет.
#   4. DLL: экспорт P121_GetStats, заглушка St_RenameGate — сохранение регистров, push eax (категория), push ebp, call P121_Gate,
#      повтор `mov [ebp-2FCh],eax`, отказ — код g_code в [ebp-121h], переходы через ячейки с 0x4EDEB9 и 0x4EF0C3.
# Запуск: py -3.13 verify_p121.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src", "patches", "p121_char_rename_guard.cpp")
if not os.path.exists(SRC):   # до сборки v74 (P118) исходник выведен из src\patches\*.cpp
    SRC = SRC + ".wait_v74"
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, SITE, BACK, REFUSE, DEFAULT = 0x4ED780, 0x4EDEB3, 0x4EDEB9, 0x4EF0C3, 0x4EE5A1
IDX_TBL, JMP_TBL = 0x4EF17C, 0x4EF14C
OK = 0
BAD = 0
MD = Cs(CS_ARCH_X86, CS_MODE_32)
# Площадки соседей в Char_FunctionItem_Use (адрес → патч): ни одна не в 0x4EDEB3…0x4EDEB9.
NEIGHBOURS = {0x4ED8CF: "P49", 0x4ED910: "P53", 0x4ED97D: "P65", 0x4ED9CF: "P117 (чтение)", 0x4ED9F5: "P15", 0x4EDD35: "P100",
              0x4EDD7B: "P65", 0x4EDD82: "P65", 0x4EDD87: "P65", 0x4EDDA4: "P65", 0x4EDDB5: "P75", 0x4EDDC7: "P75", 0x4EDDCC: "P75",
              0x4EDDCE: "P102 S5", 0x4EDDE1: "P102 S5", 0x4EDDE7: "P102 S5", 0x4EDDFC: "P102 S5", 0x4EE218: "P97", 0x4EE221: "P97",
              0x4EE25B: "P117", 0x4EE261: "P117", 0x4EE5A1: "P103 S2", 0x4EE5A7: "P103 S2"}


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
    """Массив байт из исходника P121 по имени константы."""
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
    want = {SITE: "kSiteOrig", BACK: "kBackOrig", 0x4EDEA8: "kLoadCat", 0x4EDEC8: "kSwitch", REFUSE: "kRefuseOrig", 0x4ED9CF: "kUserStore"}
    for k, p in imgs.items():
        im = Img(p)
        for va, nm in want.items():
            b = src_bytes(nm)
            check(im.rd(va, len(b)) == b, "%s: 0x%X = %s" % (k, va, nm))

    print("== 2. дизасм стока")
    im = Img(STOCK)
    ins = list(MD.disasm(im.rd(FUNC, 0x1A90), FUNC))
    by = {i.address: i for i in ins}
    into = [i for i in ins if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and SITE < int(i.op_str, 16) < BACK]
    check(not into, "переходов внутрь площадки 0x4EDEB3…0x4EDEB9 нет")
    ld = by.get(0x4EDEAE)
    check(bool(ld) and ld.mnemonic == "movzx" and ld.op_str == "eax, byte ptr [edx + ecx + 8]", "0x4EDEAE: eax = категория +8 строки Function_Table")
    st = by.get(SITE)
    check(bool(st) and st.mnemonic == "mov" and st.op_str == "dword ptr [ebp - 0x2fc], eax", "0x4EDEB3: mov [ebp-2FCh], eax (площадка)")
    sb = by.get(0x4EDEBF)
    check(bool(sb) and sb.mnemonic == "sub" and sb.op_str == "ecx, 0xf", "0x4EDEBF: категория − 15")
    ja = by.get(0x4EDED2)
    check(bool(ja) and ja.mnemonic == "ja" and int(ja.op_str, 16) == DEFAULT, "0x4EDED2: ja → default 0x4EE5A1")
    jt = by.get(0x4EDEE5)
    check(bool(jt) and jt.mnemonic == "jmp" and "0x4ef14c" in jt.op_str, "0x4EDEE5: jmp [eax*4 + 0x4EF14C]")
    idx = im.rd(IDX_TBL + (111 - 15), 1)[0]
    tgt = struct.unpack("<I", im.rd(JMP_TBL + 4 * idx, 4))[0]
    check(tgt == DEFAULT, "категория 111 → индекс %d → 0x%X = default (LABEL_69)" % (idx, tgt))
    idx120 = im.rd(IDX_TBL + (120 - 15), 1)[0]
    t120 = struct.unpack("<I", im.rd(JMP_TBL + 4 * idx120, 4))[0]
    check(t120 == 0x4EE25B, "категория 120 → 0x%X = площадка P117 (после switch)" % t120)
    ex = list(MD.disasm(im.rd(REFUSE, 0x80), REFUSE))
    check(any(i.mnemonic == "push" and i.op_str == "0x44" for i in ex) and any(i.op_str == "0x154b" for i in ex),
          "0x4EF0C3: 5451 (0x154B) длиной 68 с кодом [ebp-121h]")
    dfl = list(MD.disasm(im.rd(DEFAULT, 0xB00), DEFAULT))
    calls = [i for i in dfl if i.mnemonic == "call" and i.op_str == "0x5646c0"]
    pushes = [i for i in dfl if i.mnemonic == "push" and i.op_str == "0x85c"]
    check(bool(calls) and bool(pushes), "default 0x4EE5A1: запрос в БД 2140 (0x85C) через 0x5646C0 — его P121 не пускает для 111")

    print("== 3. совместимость с соседями")
    for va, who in sorted(NEIGHBOURS.items()):
        check(not (SITE <= va < BACK), "%s 0x%X вне площадки P121" % (who, va))
    hit = []
    for f in os.listdir(PATCH_DIR):
        if not f.endswith(".cpp") or f.startswith("p121"):
            continue
        src_ = open(os.path.join(PATCH_DIR, f), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x004EDEB[3-8]\b", src_):
            # ★ 22.11.2026 (P129, ревизия 60 Н-5): P129 площадку только ЧИТАЕТ (стоит ли jmp P121 — общая точка отказа крика)
            line_ = src_[src_.rfind("\n", 0, m.start()) + 1: src_.find("\n", m.end())]
            if f.startswith("p129") and "*(const BYTE*)0x004EDEB3" in line_:
                continue
            hit.append((f, m.group(0)))
    check(not hit, "другие патчи 0x4EDEB3…0x4EDEB8 не трогают %s" % hit)
    p75 = open(os.path.join(PATCH_DIR, "p75_level_up_potion.cpp"), encoding="utf-8", errors="replace").read()
    check("558" in p75, "P75 работает по коду 558 (категория 6 ≠ 111) — проходит P121 своей категорией")

    print("== 4. DLL", os.path.basename(DLL), md5(DLL))
    pe = pefile.PE(DLL)
    exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check(any("P121_GetStats" in e for e in exps), "экспорт P121_GetStats")
    txt = open(MAP, encoding="utf-8", errors="replace").read()
    m = re.search(r"\?St_RenameGate@\S+\s+([0-9a-f]{8})", txt)
    g = re.search(r"_P121_Gate@8\s+([0-9a-f]{8})", txt)
    c = re.search(r"\?g_code@\S+\s+([0-9a-f]{8})\s+p121_char_rename_guard\.obj", txt)   # у P75 тоже есть g_code
    check(bool(m and g), "в карте: St_RenameGate и P121_Gate")
    if m and g:
        va = int(m.group(1), 16)
        b = pe.get_memory_mapped_image()
        base = pe.OPTIONAL_HEADER.ImageBase
        st = list(MD.disasm(b[va - base:va - base + 0x50], va))
        seq = [(i.mnemonic, i.op_str) for i in st[:18]]
        check(seq[0][0] == "pushfd" and seq[1][0] == "pushal" and seq[2] == ("push", "eax") and seq[3] == ("push", "ebp"),
              "заглушка: pushfd; pushad; push eax; push ebp")
        check(seq[4][0] == "call" and int(seq[4][1], 16) == int(g.group(1), 16), "заглушка: call P121_Gate")
        check(("mov", "dword ptr [ebp - 0x2fc], eax") in seq, "сток: mov [ebp-2FCh],eax повторён")
        check(("mov", "byte ptr [ebp - 0x121], al") in seq, "отказ: [ebp-121h] = g_code")
        movs = [o for mnem, o in seq if mnem == "mov" and o.startswith("al, byte ptr [")]
        if c and movs:
            a = int(re.search(r"0x([0-9a-f]+)", movs[0]).group(1), 16)
            check(a == int(c.group(1), 16), "код отказа читается из g_code (0x%X)" % a)
        jumps = [o for mnem, o in seq if mnem == "jmp" and o.startswith("dword ptr [")]
        vals = []
        for o in jumps:
            a = int(re.search(r"0x([0-9a-f]+)", o).group(1), 16)
            vals.append(struct.unpack("<I", b[a - base:a - base + 4])[0])
        check(sorted(vals) == [BACK, REFUSE], "переходы заглушки: 0x%X и 0x%X (%s)" % (BACK, REFUSE, [hex(v) for v in vals]))
    print("ИТОГ verify_p121 ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
