# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p80.py — СТАТИЧЕСКАЯ проверка P80 CrouchSpeedJumpRelay (ход вприсядку ×0.5 и прыжок с бега соседям, 2026-10-24).
#
# Сервер НЕ запускается. Грузятся три образа (сток, живой GameServer, живой Indun) и собранная AsdaPatch.dll. Проверяем:
#  1) RecalcMoveSpeed 0x5588F0…0x558BB7 и CharEMotionSync 0x546730…0x5469BF побайтно одинаковы в трёх образах;
#  2) S1 0x558B39 (14 б): mov ecx,[ebp-0Ch] / movzx edx,byte[ecx+0A08Eh] / test / jle 0x558B53; перед ней проверка 112
#     (byte[+0x999E], jg 0x558B47); 0x558B47 — fld/fdiv qword[0x5874A0]/fstp, 0x5874A0 = 2.0; 0x558B53 — movzx eax,[ebp+0Ch];
#     массив состояний CUser: база 0x8F1E, шаг 24 б (29/30/230/241/112/186 в этой функции);
#  3) CharMove 0x544EB0: обе записи word[+0x54E4] := статус 4006 стоят ПЕРЕД call 0x5588F0 (скорость считается по новому статусу);
#     статус пересчитывается только для 2/4/6/8;
#  4) S2 0x5468C1: `jmp 0x5469AF` сразу за call sub_523ED0 / test / je 0x5468C6; sub_523ED0 → sub_542250 читает dword[CUser+0x33];
#     0x5468C6 — movsx eax,word[ebp-416h] (код действия); 0x546946 — mov eax,[ebp-42Ch] / mov cl,[eax+4A6h] → call sub_52E6D0
#     с опкодом 0xFB9 (4025) и длиной 13; 0x5469AF — эпилог;
#  5) все точки — начала инструкций (линейный дизасм функций); в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ
#     площадок; другие патчи src/patches не называют адресов внутри обеих функций (★ кроме P81 — его площадки A/B/C в
#     CharEMotionSync сверяются на непересечение с записью и соседями P80);
#  6) DLL: в MAP — SpeedTrampoline, RelayTrampoline, P80_CrouchSpeedJumpRelay, P80_GetStats; трамплины уходят ТОЛЬКО на
#     0x558B47/0x558B53 и 0x546946/0x5469AF (jmp dword ptr [глобальная] → значение глобальной), читают +0xA08E/+0x54E4/[ebp-416h];
#     строка секции P80_CrouchSpeedJumpRelay в реестре.
# Поведение (скорость по статусам/состояниям, CharMove 4006 → 4007, 4024 стоя/в ходу) — стенд tools/stand_p80.
# Запуск: python verify_p80.py [AsdaPatch.dll]   (образы — P80_IMG_DIR / P57_IMG_DIR с gs_stock/gs_live/gs_indun.exe)
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
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P80_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]

SPEED = (0x005588F0, 0x00558BB7)       # RecalcMoveSpeed
EMOT = (0x00546730, 0x005469BF)        # CharEMotionSync (4024)
CHARMOVE = (0x00544EB0, 0x00545C70)
S1, S1_LEN, HALF, AFTER, TWO = 0x00558B39, 14, 0x00558B47, 0x00558B53, 0x005874A0
S2, S2_LEN, RELAY, EXIT = 0x005468C1, 5, 0x00546946, 0x005469AF
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


def disasm(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return list(md.disasm(bytes(img[lo - base:hi - base]), lo))


def scan_refs(pe, img, base, targets, funcs):
    """Ссылки на интервалы targets {имя: (lo, hi)}: переходы rel8/rel32/jcc32 из .text и abs32 по всему образу.
    Источник внутри funcs, не являющийся началом инструкции (линейный дизасм), не считается (второй метод)."""
    a, b = text_range(pe)
    starts = set()
    for lo, hi in funcs:
        starts |= {i.address for i in disasm(img, base, lo, hi)}
    hits = {n: 0 for n in targets}
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
                    if any(f0 <= src < f1 for f0, f1 in funcs) and src not in starts:
                        continue
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, (lo, hi) in targets.items():
            if lo <= v < hi:
                hits[n] += 1
    return hits


def main():
    print("== verify_p80: DLL %s" % DLL)
    ref = None
    for title, path in GS_IMAGES:
        print("-- образ: %s (%s)" % (title, path))
        pe, img, base = load(path)
        body = bytes(img[SPEED[0] - base:SPEED[1] - base]) + bytes(img[EMOT[0] - base:EMOT[1] - base])
        if ref is None:
            ref = body
        ok(body == ref, "RecalcMoveSpeed и CharEMotionSync побайтно совпадают с первым образом (%d б)" % len(body))
        g = lambda va, n: bytes(img[va - base:va - base + n])
        # ── S1 ──
        ok(g(S1, S1_LEN) == bytes.fromhex("8b4df40fb6918ea0000085d27e0c"), "S1 0x558B39: mov ecx,[ebp-0Ch]; movzx edx,byte[ecx+0A08Eh]; test; jle")
        ok(S1 + S1_LEN + 0x0C == AFTER, "S1: jle ведёт на 0x558B53")
        ok(g(0x00558B2B, 14) == bytes.fromhex("8b55f40fb6829e99000085c07f0e") and 0x00558B39 + 0x0E == HALF,
           "проверка 112 до площадки: byte[+0x999E], jg 0x558B47")
        ok(g(HALF, 12) == bytes.fromhex("d945fcdc35a0745800d95dfc"), "0x558B47: fld [ebp-4]; fdiv qword[0x5874A0]; fstp [ebp-4]")
        ok(struct.unpack("<d", g(TWO, 8))[0] == 2.0, "0x5874A0 = 2.0 (делитель)")
        ok(g(AFTER, 4) == bytes.fromhex("0fb6450c"), "0x558B53: movzx eax,byte[ebp+0Ch] (ветка записи/6071)")
        ins = disasm(img, base, SPEED[0], SPEED[1])
        st = {i.address for i in ins}
        ok({S1, HALF, AFTER, 0x00558B2B} <= st, "S1, 0x558B47, 0x558B53, 0x558B2B — начала инструкций (линейный дизасм)")
        offs = sorted({int(m, 16) for i in ins if i.mnemonic == "movzx" for m in re.findall(r"\+ (0x[0-9a-f]+)\]", i.op_str)
                       if 0x8F1E <= int(m, 16) < 0x8F1E + 350 * 24})
        ids = [((o - 0x8F1E) // 24, (o - 0x8F1E) % 24) for o in offs]
        ok(all(r == 0 for _, r in ids) and {112, 186} <= {s for s, _ in ids},
           "массив состояний CUser (база 0x8F1E, шаг 24): флаги функции = состояния %s" % [s for s, _ in ids])
        ok(g(0x00558B5F, 9) == bytes.fromhex("d945fcd999fe540000"), "запись скорости CUser+0x54FE после деления (0x558B62)")
        # ── CharMove: статус 4006 до вызова скорости ──
        cm = disasm(img, base, CHARMOVE[0], CHARMOVE[1])
        wr = [k for k, i in enumerate(cm) if i.mnemonic == "mov" and "word ptr [" in i.op_str and "+ 0x54e4]" in i.op_str]
        pairs = 0
        for k in wr:
            nxt = cm[k + 1:k + 6]
            if any(i.mnemonic == "call" and i.op_str == hex(SPEED[0]) for i in nxt):
                pairs += 1
        ok(pairs == 2, "CharMove: обе записи word[+0x54E4] (статус) — перед call 0x5588F0 (%d из %d записей)" % (pairs, len(wr)))
        cmps = [i.op_str for i in cm if i.mnemonic == "cmp" and re.search(r", (2|4|6|8)$", i.op_str)]
        ok(len(cmps) >= 8, "CharMove: статус пересчитывается для 2/4/6/8 (сравнений %d)" % len(cmps))
        # ── S2 ──
        ok(g(S2, S2_LEN) == bytes.fromhex("e9e9000000") and S2 + 5 + 0xE9 == EXIT, "S2 0x5468C1: jmp 0x5469AF (в ходу — выход)")
        ok(g(0x005468B8, 9) == bytes.fromhex("e813d6fdff85c07405") and 0x005468BD + 0 == 0x005468BD
           and 0x005468B8 + 5 + struct.unpack("<i", g(0x005468B9, 4))[0] == 0x00523ED0, "перед S2: call sub_523ED0; test eax,eax; je 0x5468C6")
        ok(g(0x00542287, 6) == bytes.fromhex("8b45f88b4833"), "sub_542250: флаг хода dword[CUser+0x33]")
        ok(g(0x005468C6, 7) == bytes.fromhex("0fbf85eafbffff"), "0x5468C6: movsx eax,word[ebp-416h] — код действия")
        ok(g(RELAY, 12) == bytes.fromhex("8b85d4fbffff8a88a6040000"), "0x546946: mov eax,[ebp-42Ch]; mov cl,[eax+4A6h] (байт шлема)")
        em = disasm(img, base, EMOT[0], EMOT[1])
        est = {i.address for i in em}
        tail = [i for i in em if RELAY <= i.address < EXIT]
        call52 = [i for i in tail if i.mnemonic == "call" and i.op_str == "0x52e6d0"]
        push = [i.op_str for i in tail if i.mnemonic == "push"]
        ok(len(call52) == 1 and "0xfb9" in push and "0xd" in push, "0x546946…: call sub_52E6D0(4025 = 0xFB9, 13 б) — рассылка сектору")
        wr54 = [i for i in tail if "+ 0x54e4]" in i.op_str and i.mnemonic == "mov" and i.op_str.startswith("word ptr")]
        ok(not wr54, "0x546946…0x5469AF: записи статуса +0x54E4 нет (она в 0x5468EE — до точки входа)")
        ok(g(EXIT, 5) == bytes.fromhex("8b4dfc33cd"), "0x5469AF: эпилог mov ecx,[ebp-4]; xor ecx,ebp")
        ok({S2, 0x005468C6, RELAY, EXIT} <= est, "S2, 0x5468C6, 0x546946, 0x5469AF — начала инструкций")
        # ── ссылки внутрь площадок ──
        hits = scan_refs(pe, img, base, {"S1": (S1 + 1, S1 + S1_LEN), "S2": (S2 + 1, S2 + S2_LEN)}, [SPEED, EMOT])
        ok(hits["S1"] == 0, "S1: переходов/abs32 внутрь 0x558B3A…0x558B46 нет (%d)" % hits["S1"])
        ok(hits["S2"] == 0, "S2: переходов/abs32 внутрь 0x5468C2…0x5468C5 нет (%d)" % hits["S2"])

    print("-- исходники других патчей")
    rx = re.compile(r"0x0*(5[45][0-9A-Fa-f]{4})\b")
    found, p81 = [], []
    for fn in sorted(os.listdir(SRC)):
        if not fn.endswith(".cpp") or not re.match(r"p\d\d_", fn) or fn.startswith("p80_"):
            continue
        for ln, line in enumerate(open(os.path.join(SRC, fn), encoding="utf-8", errors="replace"), 1):
            for m in rx.finditer(line):
                v = int(m.group(1), 16)
                if SPEED[0] <= v < SPEED[1] or EMOT[0] < v < EMOT[1]:
                    (p81 if fn.startswith("p81_") else found).append((fn, ln, v))
    ok(not found, "внутри RecalcMoveSpeed и CharEMotionSync другие патчи (кроме P81) адресов не называют%s"
       % ("" if not found else ": " + str([(f, l, hex(v)) for f, l, v in found])))
    # ★ P81 (страж кода 4024, 24.10.2026) — ИСКЛЮЧЕНИЕ: его площадки в CharEMotionSync — A 0x5468E1 (13 б), B 0x546952 (8 б),
    #   C 0x546978 (13 б). Требуем: (1) p81 пишет только туда (прочие его адреса — сверяемые соседи и комментарии — не внутри
    #   площадок P80); (2) площадки P81 не пересекают ни запись P80 (S1, S2), ни соседей, которые сверяет P80.
    P81_SITES = [(0x005468E1, 13), (0x00546952, 8), (0x00546978, 13)]
    P80_BYTES = [(S1, S1_LEN), (S2, S2_LEN), (0x005468B8, 9), (0x005468C6, 7), (RELAY, 12), (EXIT, 5),
                 (0x00558B2B, 14), (HALF, 12), (AFTER, 4), (TWO, 8)]
    ov = lambda a, b: a[0] < b[0] + b[1] and b[0] < a[0] + a[1]
    ok(all(not ov(s, w) for s in P81_SITES for w in P80_BYTES),
       "P81: площадки A/B/C не пересекают запись и сверяемых соседей P80")
    ok(all(not any(w[0] < v < w[0] + w[1] for w in [(S1, S1_LEN), (S2, S2_LEN)]) for _, _, v in p81),
       "P81: ни один адрес p81 не внутри площадок P80 (S1 0x558B39, S2 0x5468C1; начало площадки — ссылка в комментарии)")
    if p81:
        src81 = open(os.path.join(SRC, "p81_action_code_guard.cpp"), encoding="utf-8", errors="replace").read()
        writes = re.findall(r"Hook::WriteJmp\((\w+),", src81)
        ok(sorted(writes) == ["kSiteA", "kSiteB", "kSiteC"] and all(("0x%08X" % va) in src81 for va, _ in P81_SITES),
           "P81: записывает только площадки kSiteA/kSiteB/kSiteC = 0x5468E1/0x546952/0x546978 (%s)" % writes)

    print("-- DLL")
    pe, img, base = load(DLL)
    raw = open(DLL, "rb").read()
    ok("P80_CrouchSpeedJumpRelay".encode("utf-16-le") in raw, "реестр: строка секции P80_CrouchSpeedJumpRelay в DLL")
    names = {}
    if os.path.exists(MAP):
        for line in open(MAP, encoding="latin-1"):
            parts = line.split()
            if len(parts) >= 4 and "p80_crouch_speed_jump_relay" in line:
                try:
                    names[parts[1]] = int(parts[2], 16)
                except ValueError:
                    pass
    sp = [v for k, v in names.items() if k.startswith("?SpeedTrampoline@")]
    rl = [v for k, v in names.items() if k.startswith("?RelayTrampoline@")]
    ok(sp and rl and any("P80_CrouchSpeedJumpRelay" in k for k in names) and any("P80_GetStats" in k for k in names),
       "MAP: SpeedTrampoline, RelayTrampoline, P80_CrouchSpeedJumpRelay, P80_GetStats")
    pref = pe.OPTIONAL_HEADER.ImageBase
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def glob(va):        # значение DWORD глобальной DLL (адрес возврата трамплина) по VA предпочтительной базы
        return struct.unpack("<I", bytes(img[va - pref:va - pref + 4]))[0]

    def tramp(va):
        out = []
        for i in md.disasm(bytes(img[va - pref:va - pref + 0x60]), va):
            out.append(i)
            if i.mnemonic == "int3":
                break
        return out

    for title, lst, want, reads in (("SpeedTrampoline", sp, {HALF, AFTER}, ("0xa08e", "0x54e4")),
                                    ("RelayTrampoline", rl, {RELAY, EXIT}, ("ebp - 0x416",))):
        if not lst:
            continue
        ins = tramp(lst[0])
        dests = set()
        for i in ins:
            m = re.match(r"dword ptr \[(0x[0-9a-f]+)\]", i.op_str)
            if i.mnemonic == "jmp" and m:
                dests.add(glob(int(m.group(1), 16)))
        txt = " | ".join("%s %s" % (i.mnemonic, i.op_str) for i in ins)
        ok(dests == want, "%s: выходы только на %s (%s)" % (title, sorted(hex(x) for x in want), sorted(hex(x) for x in dests)))
        ok(all(r in txt for r in reads), "%s: читает %s" % (title, ", ".join(reads)))
        ok(not any(i.mnemonic in ("push", "pop", "call", "ret") for i in ins), "%s: стек не трогает (нет push/pop/call/ret)" % title)
    print("== ИТОГ verify_p80: %s" % ("OK" if not bad else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
