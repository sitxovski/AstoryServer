# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p123.py — СТАТИЧЕСКАЯ проверка P123 «GM-прыжок на другую карту по клетке» (09.11.2026, пачка 20, решение владельца «Да, P123»;
#   AstoryServer/Docs/GameServer/gm-map-jump-p123.md). Поведение — стенд stand_p123 (3 образа × on/off/mismatch).
#   1. Образы GameServer (GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка 0x54EF50 и все опоры совпадают с исходником;
#      CharJumpCommandPosition 0x54EF50…0x54F401 побайтно одна во всех образах.
#   2. Дизасм стока: площадка — пролог (push ebp; mov ebp,esp; sub esp,80h), переходов на 0x54EF51…0x54EF58 в обработчике нет; эпилог
#      ret 8; MD5 тела стока — push 4 перед sub_523F00; CMapManager = [[this+4]+0Ch] перед sub_4221D0; ширина/высота — [map+8]/[map+0Ah]
#      (sub_4221D0); ret 14h у sub_41EC30, ret 4 у sub_4A83A0 и sub_52ED50, ret 8 у sub_52ECF0.
#   3. Исходники: других площадок в 0x54EF50…0x54EF58 у патчей нет (P41 сверяет 0x54EF59 и ставит 0x54F2F6).
#   4. DLL: экспорт P123_GetStats, реестр и секция patches.ini P123_GmMapJump, Config::kVersion = 79 (★ v79).
#   5. P55: кадр 6010 формы P123 (тело 8 б, без паддинга) = 42 б в пределах OpcodeLengths (38…57).
# Запуск: py -3.13 verify_p123.py [AsdaPatch.dll]
import hashlib
import os
import re
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
SRC_DIR = os.path.join(HERE, "..", "src")
SRC = os.path.join(SRC_DIR, "patches", "p123_gm_map_jump.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END, SITE, BACK = 0x54EF50, 0x54F401, 0x54EF50, 0x54EF59
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
        return bytes(self.b[va - self.base:va - self.base + n])

    def dis(self, va, n):
        """Дизасм n байт с VA."""
        return list(MD.disasm(self.rd(va, n), va))


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def src_sites():
    """Пары (VA, байты) из массива sites[] исходника P123: имя константы-адреса → значение, имя массива → байты."""
    s = open(SRC, encoding="utf-8").read()
    arrays = {m.group(1): bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(2)))
              for m in re.finditer(r"const BYTE (\w+)\[\d+\]\s*=\s*\{([^}]*)\}", s)}
    consts = {m.group(1): int(m.group(2), 16) for m in re.finditer(r"constexpr DWORD (\w+)\s*=\s*0x([0-9A-Fa-f]+)", s)}
    out = []
    body = s[s.index("const Site sites[]"):]
    body = body[:body.index("};")]
    for m in re.finditer(r"\{\s*(0x[0-9A-Fa-f]+|\w+),\s*(\w+),", body):
        va = int(m.group(1), 16) if m.group(1).startswith("0x") else consts[m.group(1)]
        out.append((va, m.group(2), arrays[m.group(2)]))
    return out


def ret_of(img, va):
    """Операнд первого ret функции (строка) или None."""
    for ins in img.dis(va, 0x600):
        if ins.mnemonic == "ret":
            return ins.op_str or "0"
    return None


def main():
    """Проверки и итог."""
    print("== 1. образы GameServer")
    imgs = {}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = Img(p)
    if os.path.exists(STOCK):
        imgs["сток"] = Img(STOCK)
    sites = src_sites()
    check(len(sites) == 12, "в исходнике 12 опор (%d)" % len(sites))
    first = None
    for name, img in imgs.items():
        bad = [("0x%X %s" % (va, nm)) for va, nm, b in sites if img.rd(va, len(b)) != b]
        check(not bad, "%s: все опоры совпали%s" % (name, (" — расходятся: " + ", ".join(bad)) if bad else ""))
        body = img.rd(FUNC, FUNC_END - FUNC)
        if first is None:
            first = body
        check(body == first, "%s: CharJumpCommandPosition побайтно та же" % name)

    print("== 2. дизасм стока")
    img = imgs["GameServer"]
    ins = img.dis(FUNC, FUNC_END - FUNC)
    check([i.mnemonic for i in ins[:3]] == ["push", "mov", "sub"] and ins[2].op_str == "esp, 0x80", "пролог: push ebp; mov ebp,esp; sub esp,80h")
    jumps_in = [i for i in ins if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and SITE < int(i.op_str, 16) < BACK]
    check(not jumps_in, "переходов внутрь площадки (0x54EF51…0x54EF58) нет")
    check(ret_of(img, FUNC) == "8", "обработчик снимает 8 б (ret 8) — как заглушка при обработке P123")
    txt = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
    k = next((n for n, t in enumerate(txt) if t == "call 0x523f00"), -1)
    check(k > 0 and any(t == "push 4" for t in txt[max(0, k - 6):k]), "сток считает MD5 по 4 б (push 4 перед sub_523F00) — 6-байтовая форма стоку не годится")
    k = next((n for n, t in enumerate(txt) if t == "call 0x4221d0"), -1)
    check(k > 0 and any("+ 0xc]" in t for t in txt[max(0, k - 6):k]), "CMapManager = [[this+4]+0Ch] перед IsCheckPosInMaxPos")
    pos = ["%s %s" % (i.mnemonic, i.op_str) for i in img.dis(0x4221D0, 0x40)]
    check(any("word ptr [eax + 8]" in t for t in pos) and any("word ptr [eax + 0xa]" in t for t in pos),
          "sub_4221D0: ширина [map+8], высота [map+0Ah]")
    for va, want in ((0x41EC30, "0x14"), (0x4A83A0, "4"), (0x52ED50, "4"), (0x52ECF0, "8"), (0x524390, "0x10"), (0x523F00, "0x10")):
        check(ret_of(img, va) == want, "ret 0x%X = %s (ждём %s)" % (va, ret_of(img, va), want))

    print("== 3. соседи")
    hits = []
    for fn in os.listdir(os.path.join(SRC_DIR, "patches")):
        if not fn.endswith(".cpp") or fn.startswith("p123_"):
            continue
        s = open(os.path.join(SRC_DIR, "patches", fn), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"(?<!@)0x(00)?54EF5([0-8])\b", s, re.I):   # «@0x54EF50» — имя функции в комментарии, не площадка
            hits.append("%s: %s" % (fn, m.group(0)))
    check(not hits, "у других патчей нет площадок в 0x54EF50…0x54EF58%s" % ((" — " + ", ".join(hits)) if hits else ""))

    print("== 4. DLL и исходники")
    pe = pefile.PE(DLL)
    names = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check("_P123_GetStats@4" in names or "P123_GetStats" in names, "экспорт P123_GetStats")
    raw = open(DLL, "rb").read()
    check("P123_GmMapJump".encode("utf-16-le") in raw, "строка секции P123_GmMapJump в DLL")
    reg = open(os.path.join(SRC_DIR, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    check('{ L"P123_GmMapJump",' in reg and "P123_GmMapJump }" in reg, "реестр: P123_GmMapJump")
    cfg = open(os.path.join(SRC_DIR, "Config.cpp"), encoding="utf-8-sig").read()
    check('{ L"P123_GmMapJump",' in cfg and "kGmMapJump, ARRAYSIZE(kGmMapJump)" in cfg and re.search(r'\{ L"Version", L"(\d+)",', cfg) and int(re.search(r'\{ L"Version", L"(\d+)",', cfg).group(1)) >= 79,
          "Config.cpp: секция P123_GmMapJump и Version >= 79")
    kv = re.search(r"constexpr int kVersion = (\d+);", open(os.path.join(SRC_DIR, "Config.h"), encoding="utf-8-sig").read())
    check(kv and int(kv.group(1)) >= 79, "Config.h: kVersion >= 79 (★ 18.11: P127 поднял до 80)")

    print("== 5. P55")
    ol = open(os.path.join(SRC_DIR, "OpcodeLengths.h"), encoding="utf-8", errors="replace").read()
    m = re.search(r"\{\s*6010,\s*(\d+),\s*(\d+),", ol)
    check(m and int(m.group(1)) <= 42 <= int(m.group(2)), "6010: кадр 42 б (тело 8 б без паддинга) в пределах P55 (%s…%s)" % (m.group(1), m.group(2)) if m else "6010 в OpcodeLengths.h")

    print("ИТОГ: ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
