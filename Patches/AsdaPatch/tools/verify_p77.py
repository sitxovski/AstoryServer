# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p77.py — СТАТИЧЕСКАЯ проверка P77 MoveSyncStopPoint (4009 в точку сервера при молчаливой остановке хода, 2026-10-22).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) MoveSyncProcess 0x5427D0…0x542F90 побайтно одинаков в трёх образах;
#  2) четыре площадки S1…S4 — `E8 rel32` ровно на sub_542520, на границе инструкции; перед ними push строки причины
#     (строка в .rdata — та самая), после — `jmp 0x542F4F`; sub_542520 выходит `ret 8`, флаг стека хода читает [ecx+33h];
#  3) не закрываемые остановки (0x542D6E Portal Move, 0x542F16 Move End, 0x542F77 UserIndex == -1) — тоже `call sub_542520`
#     и P77 их не трогает; ветка 0x5429BA («iDistanceTime …») — переходов/abs32 на неё в .text нет (ссылок в срезе нет);
#  4) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок;
#  5) другие патчи в src/patches не пишут в MoveSyncProcess (текстовый поиск адресов 0x5427D0…0x542F90; P57 — только
#     сверка 0x542F34/0x542F49);
#  6) DLL: в MAP — St_S1…St_S4 (каждый: push номера площадки, call Enter, `ret 8`) и P77_MoveSyncStopPoint/P77_GetStats;
#     в коде DLL есть вызов sub_542520 и отправки 0x4C28F0/0x52E6D0; строка секции P77_MoveSyncStopPoint в реестре.
# Поведение (честный ход, четыре ветки, повтор, скрытый оператор, CharMove после 4009) — стенд tools/stand_p77 (run_matrix.py).
# Запуск: python verify_p77.py [AsdaPatch.dll]   (образы — P77_IMG_DIR / P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
import os
import re
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
SRC = os.path.join(HERE, "..", "src", "patches")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P77_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

REMOVE = 0x00542520
MSP = (0x005427D0, 0x00542F90)
AFTER = 0x00542F4F
# (имя, площадка, адрес строки причины, текст строки)
SITES = [("P77.S1", 0x00542968, 0x0059C814, b"MoveSyncProcess() iMotionStartTime = 0"),
         ("P77.S2", 0x00542ACB, 0x0059C79C, b"MoveSyncProcess() iMovePos - Value2"),
         ("P77.S3", 0x00542B11, 0x0059C788, b"iMovePos Max Over"),
         ("P77.S4", 0x00542B49, 0x0059C778, b"don't move tile")]
OTHER = [("Portal Move", 0x00542D6E, 0x0059C758), ("Move End", 0x00542F16, 0x0059C73C), ("UserIndex == -1", 0x00542F77, 0x0059C718)]
DEAD = 0x005429BA
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


def insn_starts(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return {i.address for i in md.disasm(bytes(img[lo - base:hi - base]), lo)}


def scan_refs(pe, img, base, targets):
    """Ссылки на интервалы targets: {имя: (lo, hi)} (lo < t < hi для площадок, lo <= t < hi для меток)."""
    a, b = text_range(pe)
    hits = {n: 0 for n in targets}
    starts = insn_starts(img, base, MSP[0], MSP[1])
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
            for n, (lo, hi) in targets.items():
                if lo <= t < hi:
                    src = base + i
                    if MSP[0] <= src < MSP[1] and src not in starts:
                        continue      # середина инструкции MoveSyncProcess — не переход (второй метод: линейный дизасм)
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, (lo, hi) in targets.items():
            if lo <= v < hi:
                hits[n] += 1
    return hits


def on_boundary(img, base, va):
    return va in insn_starts(img, base, MSP[0], MSP[1])


def call_target(img, base, va):
    o = va - base
    return va + 5 + struct.unpack("<i", bytes(img[o + 1:o + 5]))[0] if img[o] == 0xE8 else None


def main():
    print("== verify_p77: DLL %s" % DLL)
    ref = None
    for title, path in GS_IMAGES:
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        body = bytes(img[MSP[0] - base:MSP[1] - base])
        if ref is None:
            ref = body
        ok(body == ref, "MoveSyncProcess 0x5427D0…0x542F90 побайтно совпадает с первым образом (%d б)" % len(body))
        for n, va, s_va, s_txt in SITES:
            ok(call_target(img, base, va) == REMOVE, "%s @0x%08X: call sub_542520" % (n, va))
            ok(on_boundary(img, base, va), "%s: площадка — начало инструкции (линейный дизасм MoveSyncProcess)" % n)
            o = va - base
            # 13 б до площадки: push imm32 (строка), mov r16,[ebp-40h], push r32, mov ecx,[ebp-5Ch]
            pre = bytes(img[o - 13:o])
            ok(pre[0] == 0x68 and struct.unpack("<I", pre[1:5])[0] == s_va and pre[5:8] in (b"\x66\x8b\x4d", b"\x66\x8b\x45")
               and pre[8] == 0xC0 and pre[9] in (0x50, 0x51) and pre[10:13] == b"\x8b\x4d\xa4",
               "%s: аргументы — push 0x%08X, номер [ebp-40h], this [ebp-5Ch]" % (n, s_va))
            so = s_va - base
            ok(bytes(img[so:so + len(s_txt) + 1]) == s_txt + b"\0", "%s: строка причины «%s»" % (n, s_txt.decode()))
            post = bytes(img[o + 5:o + 10])
            ok(post[0] == 0xE9 and va + 10 + struct.unpack("<i", post[1:5])[0] == AFTER, "%s: после вызова jmp 0x542F4F" % n)
        r = REMOVE - base
        ok(bytes(img[r:r + 6]) == bytes.fromhex("558bec81ec1c"), "sub_542520: пролог push ebp; mov ebp,esp; sub esp,41Ch")
        ok(bytes(img[0x00542597 - base:0x00542597 - base + 4]) == bytes.fromhex("83793300"), "sub_542520: флаг стека хода cmp [ecx+33h],0 @0x542597")
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        rets = {i.op_str for i in md.disasm(bytes(img[r:0x005427D0 - base]), REMOVE) if i.mnemonic == "ret"}
        ok(rets == {"8"}, "sub_542520: выход только ret 8 (%s)" % sorted(rets))
        for n, va, s_va in OTHER:
            o = va - base
            ok(call_target(img, base, va) == REMOVE and struct.unpack("<I", bytes(img[o - 12:o - 8]))[0] == s_va,
               "не закрывается: «%s» @0x%08X — call sub_542520 (P77 не трогает)" % (n, va))
        targets = {n: (va + 1, va + 5) for n, va, _, _ in SITES}
        targets["DEAD 0x5429BA"] = (DEAD, DEAD + 1)
        hits = scan_refs(pe, img, base, targets)
        for n, _, _, _ in SITES:
            ok(hits[n] == 0, "%s: переходов/abs32 внутрь площадки нет (%d)" % (n, hits[n]))
        ok(hits["DEAD 0x5429BA"] == 0, "ветка «iDistanceTime …» 0x5429BA: переходов/abs32 на неё в .text нет — ссылок в срезе нет (%d)"
           % hits["DEAD 0x5429BA"])

    print("-- исходники других патчей")
    rx = re.compile(r"0x0*(54[23][0-9A-Fa-f]{3})\b")
    found = []
    for fn in sorted(os.listdir(SRC)):
        if not fn.endswith(".cpp") or not re.match(r"p\d\d_", fn) or fn.startswith("p77_"):
            continue
        for ln, line in enumerate(open(os.path.join(SRC, fn), encoding="utf-8", errors="replace"), 1):
            if "P77" in line:
                continue      # описание самого P77 (реестр)
            for m in rx.finditer(line):
                v = int(m.group(1), 16)
                if MSP[0] <= v < MSP[1]:
                    found.append((fn, ln, v))
    foreign = [(f, l, v) for f, l, v in found if not (f.startswith("p57_") and v in (0x542F34, 0x542F49, 0x542F2A, 0x542F4F, 0x5427D0, 0x542EB6, 0x542EBC))]
    ok(not foreign, "в MoveSyncProcess других записей нет (P57 — только сверка/упоминание %s)%s"
       % (sorted({hex(v) for f, l, v in found if f.startswith("p57_")}), "" if not foreign else ": " + str(foreign)))

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P77_MoveSyncStopPoint".encode("utf-16-le") in raw, "реестр: строка секции P77_MoveSyncStopPoint в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 4 and "p77_move_sync_stop_point" in line:
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    stubs = {k: v for k, v in names.items() if re.match(r"\?St_S[1-4]@", k)}
    enter = [v for k, v in names.items() if k.startswith("?Enter@")]
    apply_ = [k for k in names if "P77_MoveSyncStopPoint" in k]
    stats = [k for k in names if "P77_GetStats" in k]
    ok(len(stubs) == 4 and len(enter) == 1 and apply_ and stats, "MAP: St_S1…St_S4, Enter, P77_MoveSyncStopPoint, P77_GetStats (%d/%d/%d/%d)"
       % (len(stubs), len(enter), len(apply_), len(stats)))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    pref = pe.OPTIONAL_HEADER.ImageBase
    for k, va in sorted(stubs.items()):
        site = int(re.match(r"\?St_S([1-4])@", k).group(1))
        ins = list(md.disasm(bytes(img[va - pref:va - pref + 0x20]), va))
        txt = ["%s %s" % (i.mnemonic, i.op_str) for i in ins]
        calls = [int(i.op_str, 16) for i in ins if i.mnemonic == "call" and i.op_str.startswith("0x")]
        good = ("push %d" % site) in txt and enter and calls and calls[0] == enter[0] and "ret 8" in txt
        ok(good, "St_S%d: push %d, call Enter, ret 8 (снимает 8 б, как sub_542520)" % (site, site))
    if enter:
        e = enter[0] - pref
        code = bytes(img[e:e + 0x400])
        has_remove = struct.pack("<I", REMOVE) in code
        ok(has_remove, "Enter: вызов стока sub_542520 (0x542520 в коде)")
    allcode = bytes(img)
    ok(struct.pack("<I", 0x004C28F0) in allcode and struct.pack("<I", 0x0052E6D0) in allcode, "DLL: адреса отправок 0x4C28F0 / 0x52E6D0 присутствуют")
    print("== ИТОГ verify_p77: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
