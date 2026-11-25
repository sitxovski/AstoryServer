# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p76.py — СТАТИЧЕСКАЯ проверка P76 SowelSlotBounds (поля пакетов живых камней 5022/5024/5031, 2026-10-21).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) три площадки — `E8 rel32` ровно на sub_52BFF0 (0x52BFF0), на границе инструкции; хвост `ret 8` у sub_52BFF0;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок;
#  3) DLL: в MAP компоновщика есть стабы St_Detach5022/St_Move5024/St_Holy5031 и P76_Check; каждый стаб зовёт
#     0x52BFF0 через `mov eax, 0x52BFF0; call eax`, затем P76_Check, и выходит `ret 8` (снимает аргументы, как сток);
#  4) регистрация: P76_SowelSlotBounds в реестре DLL (строка-имя секции присутствует).
# Поведение (честные поля, «занят», нарушения в Mode 0/1, журнал) — стенд tools/stand_p76 (run_matrix.py).
# Запуск: python verify_p76.py [AsdaPatch.dll]   (образы — P76_IMG_DIR / P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P76_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

GATE = 0x0052BFF0
SITES = [("P76.detach5022", 0x004DBDEF), ("P76.move5024", 0x004DC51E), ("P76.holy5031", 0x004DE70E)]
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


# Обработчики, внутри которых стоят площадки: (начало, конец). Побайтовый скан ловит и «переходы» из середины инструкций
# (байт 0x70..0x7F внутри другой инструкции) — такие попадания перепроверяются линейным дизасмом обработчика от его начала:
# считается только настоящее начало инструкции (второй метод).
HANDLERS = [(0x004DBC30, 0x004DC390), (0x004DC390, 0x004DE590), (0x004DE590, 0x004DF300)]


def insn_starts(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return {i.address for i in md.disasm(bytes(img[lo - base:hi - base]), lo)}


def scan_into(pe, img, base):
    a, b = text_range(pe)
    hits = {n: 0 for n, _ in SITES}
    starts = set()
    for lo, hi in HANDLERS:
        starts |= insn_starts(img, base, lo, hi)
    for i in range(a, b - 6):
        o = img[i]
        cands = []
        if o == 0xEB or 0x70 <= o <= 0x7F or o in (0xE0, 0xE1, 0xE2, 0xE3):
            cands.append(base + i + 2 + struct.unpack("b", bytes([img[i + 1]]))[0])
        if o in (0xE8, 0xE9):
            cands.append(base + i + 5 + struct.unpack("<i", bytes(img[i + 1:i + 5]))[0])
        if o == 0x0F and 0x80 <= img[i + 1] <= 0x8F:
            cands.append(base + i + 6 + struct.unpack("<i", bytes(img[i + 2:i + 6]))[0])
        for t in cands:
            for n, va in SITES:
                if va < t < va + 5:
                    src = base + i
                    in_handler = any(lo <= src < hi for lo, hi in HANDLERS)
                    if in_handler and src not in starts:
                        print("    (ложное попадание: 0x%08X -> 0x%08X — середина инструкции, не переход)" % (src, t))
                        continue
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va in SITES:
            if va < v < va + 5:
                hits[n] += 1
    return hits


def on_boundary(img, base, va):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for back in range(1, 48):
        for ins in md.disasm(bytes(img[va - base - back: va - base + 16]), va - back):
            if ins.address == va:
                return ins.size == 5
            if ins.address > va:
                break
    return False


def main():
    print("== verify_p76: DLL %s" % DLL)
    for title, path in GS_IMAGES:
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        for n, va in SITES:
            o = va - base
            ok(img[o] == 0xE8 and va + 5 + struct.unpack("<i", bytes(img[o + 1:o + 5]))[0] == GATE,
               "%s @0x%08X: call sub_52BFF0" % (n, va))
            ok(on_boundary(img, base, va), "%s: площадка — целая инструкция на границе" % n)
        g = GATE - base
        ok(bytes(img[g:g + 3]) == bytes.fromhex("558bec"), "sub_52BFF0: пролог push ebp; mov ebp,esp")
        ok(bytes(img[0x0052C169 - base:0x0052C169 - base + 3]) == bytes.fromhex("c20800"), "sub_52BFF0: выход ret 8 @0x0052C169")
        hits = scan_into(pe, img, base)
        for n, _ in SITES:
            ok(hits[n] == 0, "%s: переходов/abs32 внутрь площадки нет (%d)" % (n, hits[n]))

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P76_SowelSlotBounds".encode("utf-16-le") in raw, "реестр: строка секции P76_SowelSlotBounds в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 3 and ("St_Detach5022" in parts[1] or "St_Move5024" in parts[1] or "St_Holy5031" in parts[1]
                                    or "P76_Check" in parts[1]):
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    stubs = {k: v for k, v in names.items() if "St_" in k}
    checks = [v for k, v in names.items() if "P76_Check" in k]
    ok(len(stubs) == 3 and len(checks) >= 1, "MAP: три стаба и P76_Check найдены (%s)" % ", ".join(sorted(names)))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    check_va = checks[0] if checks else None
    pref = pe.OPTIONAL_HEADER.ImageBase
    for k, va in sorted(stubs.items()):
        off = va - pref
        ins = list(md.disasm(bytes(img[off:off + 0x60]), va))
        txt = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
        has_gate = any("mov eax, 0x52bff0" in t for t in txt) and any(t == "call eax" for t in txt)
        calls = [int(i.op_str, 16) for i in ins if i.mnemonic == "call" and i.op_str.startswith("0x")]
        has_check = check_va in calls if check_va else False
        has_ret8 = any(t == "ret 8" for t in txt)
        ok(has_gate and has_check and has_ret8, "%s: зовёт 0x52BFF0 (call eax), затем P76_Check, выход ret 8" % k)
    print("== ИТОГ verify_p76: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
