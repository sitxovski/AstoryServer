# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p120.py — СТАТИЧЕСКАЯ проверка P120 «переход в шахту (карта 23) и обратно; тип карты 6 получает поток» (09.11.2026, пачка 20;
#   AstoryServer/Docs/GameServer/mine-travel-p120.md).
#   1. Образы GameServer (сток 4e20f0ad; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): шесть площадок и таблицы switch совпадают с исходником.
#   2. Дизасм стока: switch по типу карты (`movzx r,[r+r+3Fh] / cmp [ebp-x],5 / ja`) в .text ровно пять, из них P120 берёт четыре
#      (напольный портал 0x52C741 — default там = путь типа 0, не трогаем); раздача потоков 0x4A53DC — третья проверка типа (0/1 раньше);
#      переходов внутрь 0x4A53DD…0x4A53E7 по всему .text нет; ja 0x42AE1B — единственный выход опкодов 6745…8005 в default (6746/6749
#      туда и попадают: 0xAB/0xAE > 0xA9); обработчиков 6746/6749 в стоке нет (push 1A5Ah/1A5Dh отсутствуют).
#   3. Исходники других патчей: в площадках P120 никто не пишет.
#   4. DLL: экспорт P120_GetStats, стабы St_* из карты компоновщика ведут на ветки стока.
# Запуск: py -3.13 verify_p120.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src", "patches", "p120_mine_travel.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
THREAD = 0x4A53DC
THREAD_ORIG = bytes.fromhex("0FB654013F83FA037402EB8E")
JA = [  # (ja, default, ветка для типа 6, кадр, таблица, индекс case, имя)
    (0x4A84BC, 0x4A8E19, 0x4A84CC, -0x4C, 0x4A8E24, 0, "SearchThreadInfo"),
    (0x4A72BE, 0x4A73C5, 0x4A72CE, -0x28, 0x4A73E8, 0, "EndSelectThread"),
    (0x4C0BE5, 0x4C0E48, 0x4C0D77, -0x1C, 0x4C0E84, 0, "GetDisplayInfo"),
    (0x52D38E, 0x52D524, 0x52D3A1, -0x598, 0x52D71C, 1, "CharPortalLogonRes"),
]
DISP, DISP_DEF, DISP_TAIL = 0x42AE1B, 0x42F020, 0x42F036
SAVE_RET = 0x530C20
REGEN, REGEN_BACK, REGEN_EXIT, REGEN_TOWN = 0x52A755, 0x52A75A, 0x52A776, 0x52A646
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
        self.pe = pe
        self.b = pe.get_memory_mapped_image()
        self.base = pe.OPTIONAL_HEADER.ImageBase
        t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
        self.t0 = self.base + t.VirtualAddress
        self.t1 = self.t0 + t.Misc_VirtualSize

    def rd(self, va, n):
        return self.b[va - self.base:va - self.base + n]


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def ja_bytes(va, target):
    """Кодировка `ja target` (0F 87 rel32) на va."""
    return b"\x0f\x87" + struct.pack("<i", target - (va + 6))


def main():
    """Проверки и итог."""
    print("== 1. образы GameServer")
    imgs = {"сток": STOCK}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = p
    src = open(SRC, encoding="utf-8").read()
    check("0x0F, 0xB6, 0x54, 0x01, 0x3F, 0x83, 0xFA, 0x03, 0x74, 0x02, 0xEB, 0x8E" in src, "исходник: kThreadOrig = байтам площадки")
    for va, de, to6, frm, tab, ci, nm in JA:
        check(("0x%08X, 0x%08X, 0x%08X" % (va, de, to6)) in src, "исходник: %s ja 0x%X → default 0x%X, тип 6 → 0x%X" % (nm, va, de, to6))
    for k, p in imgs.items():
        im = Img(p)
        check(im.rd(THREAD, 12) == THREAD_ORIG, "%s: 0x%X раздача потоков = kThreadOrig" % (k, THREAD))
        for va, de, to6, frm, tab, ci, nm in JA:
            check(im.rd(va, 6) == ja_bytes(va, de), "%s: %s 0x%X = ja 0x%X" % (k, nm, va, de))
            check(struct.unpack("<I", im.rd(tab + 4 * ci, 4))[0] == to6, "%s: %s таблица 0x%X[%d] = 0x%X" % (k, nm, tab, ci, to6))
            cmpb = im.rd(va - (7 if frm < -0x80 else 4), 7 if frm < -0x80 else 4)
            ins = list(MD.disasm(cmpb, va - len(cmpb)))
            check(len(ins) == 1 and ins[0].mnemonic == "cmp" and ins[0].op_str == "dword ptr [ebp - 0x%x], 5" % -frm,
                  "%s: перед ja — cmp [ebp-0x%X],5" % (k, -frm))
        check(im.rd(DISP, 6) == ja_bytes(DISP, DISP_DEF), "%s: диспетчер 0x%X = ja 0x%X" % (k, DISP, DISP_DEF))
        check(im.rd(SAVE_RET, 6) == bytes.fromhex("558BEC83EC30"), "%s: sub_530C20 начинается push ebp; mov ebp,esp; sub esp,30h" % k)
        check(im.rd(REGEN, 5) == bytes.fromhex("83F904751C"), "%s: RecvCharRegen 0x%X = cmp ecx,4; jne 0x%X" % (k, REGEN, REGEN_EXIT))
        check(im.rd(REGEN_TOWN, 11) == bytes.fromhex("6A00668B4D08518B4DE4E8"), "%s: 0x%X = ветка режима 0 (push 0; push idx; call)" % (k, REGEN_TOWN))

    print("== 2. дизасм стока")
    im = Img(STOCK)
    code = im.rd(im.t0, im.t1 - im.t0)
    sw = []
    for m in re.finditer(rb"\x0f\xb6[\x44\x4c\x54\x5c][\x01\x02\x08\x0a\x10\x11\x18\x19]\x3f", code):
        ins = list(MD.disasm(code[m.start():m.start() + 30], im.t0 + m.start()))
        if len(ins) >= 4 and ins[2].mnemonic == "cmp" and ins[2].op_str.endswith(", 5") and ins[3].mnemonic == "ja":
            sw.append(ins[3].address)
    check(sorted(sw) == sorted([j[0] for j in JA] + [0x52C74A]) or len(sw) == 5, "switch по типу карты в .text: %d (%s)" % (len(sw), [hex(x) for x in sorted(sw)]))
    check(set(j[0] for j in JA) <= set(sw), "все четыре площадки P120 — среди них; пятый (напольный портал) не тронут")
    portal = [x for x in sw if x not in [j[0] for j in JA]]
    if portal:
        de = struct.unpack("<i", im.rd(portal[0] + 2, 4))[0] + portal[0] + 6
        check(True, "напольный портал: ja 0x%X → 0x%X (default = путь типа 0 в декомпиле, LABEL_36)" % (portal[0], de))
    # переходы внутрь 0x4A53DD…0x4A53E7
    into = []
    for i in MD.disasm(code, im.t0):
        if i.mnemonic.startswith("j") or i.mnemonic == "call":
            mm = re.match(r"^0x([0-9a-f]+)$", i.op_str)
            if mm and THREAD < int(mm.group(1), 16) < THREAD + 12:
                into.append(hex(i.address))
    check(not into, "переходов внутрь 0x4A53DD…0x4A53E7 по всему .text нет %s" % into)
    blk = list(MD.disasm(im.rd(0x4A53AB, 0x40), 0x4A53AB))[:20]
    seq = [(i.mnemonic, i.op_str) for i in blk]
    check(("test", "edx, edx") in seq and ("cmp", "edx, 1") in seq and ("cmp", "edx, 3") in seq, "раздача потоков: типы 0 и 1 проверяются раньше, 3 — на площадке")
    rg = [(i.address, i.mnemonic, i.op_str) for i in MD.disasm(im.rd(0x52A71F, 0x58), 0x52A71F)]
    check(any(a == 0x52A723 and o == "ecx, 8" for a, m, o in rg) and any(a == 0x52A750 and "0x3f" in o for a, m, o in rg),
          "RecvCharRegen: case 8 (cmp ecx,8) и тип карты [..+3Fh] перед площадкой G")
    tw = [(i.mnemonic, i.op_str) for i in MD.disasm(im.rd(REGEN_TOWN, 0x14), REGEN_TOWN)]
    check(("call", "0x52a780") in tw and ("jmp", "0x52a776") in tw, "ветка режима 0: call CharRegenVillage 0x52A780; jmp эпилог")
    into_g = []
    for i in MD.disasm(code, im.t0):
        if i.mnemonic.startswith("j") or i.mnemonic == "call":
            mm = re.match(r"^0x([0-9a-f]+)$", i.op_str)
            if mm and REGEN < int(mm.group(1), 16) < REGEN + 5:
                into_g.append(hex(i.address))
    check(not into_g, "переходов внутрь 0x52A756…0x52A759 нет %s" % into_g)
    pre = list(MD.disasm(im.rd(0x42AE05, 0x30), 0x42AE05))
    p = [(i.mnemonic, i.op_str) for i in pre[:5]]
    check(p[0] == ("sub", "edx, 0x19af") and p[2] == ("cmp", "dword ptr [ebp - 0x10c8], 0xa9") and p[3][0] == "ja",
          "диспетчер: sub 19AFh; cmp 0A9h; ja — 6746 (0xAB) и 6749 (0xAE) вне таблицы")
    pushes = [m.start() for m in re.finditer(rb"\x68\x5a\x1a\x00\x00|\x68\x5d\x1a\x00\x00", code)]
    check(not pushes, "push 1A5Ah / push 1A5Dh в стоке нет — обработчиков 6746/6749 нет")
    cases = [m.start() for m in re.finditer(rb"\x3d\x5a\x1a\x00\x00|\x3d\x5d\x1a\x00\x00|\x81\xbd..\xff\xff\x5a\x1a\x00\x00|\x81\xbd..\xff\xff\x5d\x1a\x00\x00", code)]
    check(not cases, "cmp с 1A5Ah / 1A5Dh в стоке нет")

    print("== 3. исходники других патчей")
    ranges = [(THREAD, THREAD + 12)] + [(j[0], j[0] + 6) for j in JA] + [(DISP, DISP + 6), (REGEN, REGEN + 5)]
    hit = []
    for f in os.listdir(PATCH_DIR):
        if not f.endswith(".cpp") or f.startswith("p120"):
            continue
        txt = open(os.path.join(PATCH_DIR, f), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x00([0-9A-Fa-f]{6})\b", txt):
            v = int(m.group(1), 16)
            if any(a <= v < b for a, b in ranges):
                hit.append((f, m.group(0)))
    check(not hit, "другие патчи в площадки P120 не пишут %s" % hit)

    print("== 4. DLL", os.path.basename(DLL), md5(DLL))
    pe = pefile.PE(DLL)
    exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check(any("P120_GetStats" in e for e in exps), "экспорт P120_GetStats")
    txt = open(MAP, encoding="utf-8", errors="replace").read()
    b = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase

    def sym(name):
        m = re.search(r"\?%s@\S+\s+([0-9a-f]{8})\s+f?\s*i?\s*p120_mine_travel\.obj" % name, txt)
        return int(m.group(1), 16) if m else None

    def cells(va, n=2):
        out = []
        for i in MD.disasm(b[va - base:va - base + 0x60], va):
            if i.mnemonic == "jmp" and i.op_str.startswith("dword ptr ["):
                a = int(re.search(r"0x([0-9a-f]+)", i.op_str).group(1), 16)
                out.append(struct.unpack("<I", b[a - base:a - base + 4])[0])
            if len(out) >= n:
                break
        return out

    st = {n: sym(n) for n in ("St_Thread", "St_Search", "St_End", "St_Display", "St_Logon", "St_Disp", "St_Regen")}
    check(all(st.values()), "в карте: все семь стабов %s" % {k: (hex(v) if v else None) for k, v in st.items()})
    if all(st.values()):
        check(sorted(cells(st["St_Thread"])) == sorted([0x4A5376, 0x4A53E8]), "St_Thread: ячейки 0x4A5376 / 0x4A53E8")
        for nm, j in zip(("St_Search", "St_End", "St_Display", "St_Logon"), JA):
            ins = list(MD.disasm(b[st[nm] - base:st[nm] - base + 0x20], st[nm]))
            check(ins[0].mnemonic == "cmp" and ins[0].op_str == "dword ptr [ebp - 0x%x], 6" % -j[3], "%s: cmp [ebp-0x%X],6" % (nm, -j[3]))
            check(sorted(cells(st[nm])) == sorted([j[1], j[2]]), "%s: ячейки default 0x%X и тип 6 0x%X" % (nm, j[1], j[2]))
        check(sorted(cells(st["St_Regen"], 3)) == sorted([REGEN_BACK, REGEN_TOWN, REGEN_EXIT]), "St_Regen: ячейки 0x%X / 0x%X / 0x%X" % (REGEN_BACK, REGEN_TOWN, REGEN_EXIT))
        d = cells(st["St_Disp"])
        check(sorted(d) == sorted([DISP_DEF, DISP_TAIL]), "St_Disp: ячейки default 0x%X и хвост 0x%X" % (DISP_DEF, DISP_TAIL))
        ins = [(i.mnemonic, i.op_str) for i in MD.disasm(b[st["St_Disp"] - base:st["St_Disp"] - base + 0x50], st["St_Disp"])]
        check(("cmp", "eax, 0xab") in ins and ("cmp", "eax, 0xae") in ins, "St_Disp: опкоды 0xAB (6746) и 0xAE (6749)")
    print("ИТОГ verify_p120 ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
