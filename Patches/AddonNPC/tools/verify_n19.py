# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n19.py — СТАТИЧЕСКАЯ проверка N19 (слот P86, 25.10.2026): «начало серии 4026/4201 не обнуляет часы атаки».
#   Отчёт: Reports/phantom_damage/REPORT.md. Сервер НЕ запускается, образы только читаются. Логику проверяет stand_n19.
#   1. Три образа NpcServer (сток 16c7a0af, живой c02486d6, Indun 0de2c559): байты обеих площадок, инструкция начинается ровно
#      на площадке и кончается через 10 б, следующая — та, куда выходит стенд; сплошной перебор переходов rel8/rel32/jcc32 по
#      .text — входов внутрь изменяемых байтов нет; окна ±32 б вокруг площадок побайтово одинаковы на трёх образах.
#   2. Кадр: смещение такта у площадки выведено из пролога (sub esp + push'и + аргументы sub_42C4F0) и сверено с местом, где
#      сток сам читает такт для sub_45F3A0/sub_45FF80 (0x45FE4B `mov eax,[esp+84h]`, 0x4608B3 `mov eax,[esp+7Ch]`); вызов из
#      диспетчера (0x2009 / 0x201E) передаёт тот же такт, что получают проверки скорости.
#   3. DLL (по .map): стабы St_Mob/St_Pvp — дизасм: pushfd/pushad, площадка 0/1, такт [esp+0C0h]/[esp+0A8h] (= 24h + 4 + смещение
#      + 4), push ebp, call N19_Restart, обнуление только при eax ≠ 0, popad/popfd/ret; реестр — N19 после N01 и P53.
# Запуск: py -3 verify_n19.py [AddonNPC.dll]
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
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src", "patches")
NPC_C = r"@@ASTORY_DEV_ROOT@@\RE\ida\npc_work\NpcServer.exe.c"
sys.path.append(os.path.join(HERE, "..", "..", "AsdaPatch", "tools"))
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe", "16c7a0aff498a9f739899d9a2cba9a5b"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe", "c02486d62e803e98eb6fb4fa98d1fcd6"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe", "0de2c55932c2966537e2a8c539decdcd"),
]
SITES = [   # (имя, VA площадки, VA следующей инструкции, начало функции, смещение такта, сверка такта стоком)
    ("монстр sub_45FCD0", 0x45FE0C, 0x45FE16, 0x45FCD0, 0x94, (0x45FE4B, "mov eax, dword ptr [esp + 0x84]", 0x84)),
    ("PvP sub_460710", 0x46085F, 0x460869, 0x460710, 0x7C, (0x4608B3, "mov eax, dword ptr [esp + 0x7c]", 0x7C)),
]
STOCK = bytes.fromhex("C78590FE000000000000")
CHK_SITES = [   # ★ ревизия М-5: (имя, VA call, функция, цель) — ветка «цель в дальности», где сток зовёт проверку скорости
    ("монстр: call sub_45F3A0", 0x45FE67, 0x45FCD0, 0x45F3A0),
    ("PvP: call sub_45FF80", 0x4608CC, 0x460710, 0x45FF80),
]
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def md5(path):
    import hashlib
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def load(path):
    pe = pefile.PE(path)
    return pe, bytes(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe, base):
    for s in pe.sections:
        if s.Name.rstrip(b"\0") == b".text":
            return base + s.VirtualAddress, base + s.VirtualAddress + s.Misc_VirtualSize
    return 0, 0


md = Cs(CS_ARCH_X86, CS_MODE_32)


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


print("== 1. образы NpcServer")
windows = []
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s (зеркало: python srv_mirror.py)" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    lo, hi = text_range(pe, base)
    win = b""
    for sname, va, nxt, fn, toff, _ in SITES:
        ok(img[va - base:va - base + 10] == STOCK, "%s %s @0x%06X: C7 85 90 FE 00 00 00 00 00 00" % (name, sname, va))
        # линейный проход от начала функции: инструкция начинается ровно на площадке, следующая — на nxt
        starts = [i.address for i in insns(img, base, fn, nxt + 16)]
        ok(va in starts and nxt in starts, "%s %s: границы инструкций 0x%06X → 0x%06X (линейный проход от 0x%06X)" % (name, sname, va, nxt, fn))
        win += img[va - base - 32:va - base + 42]
    # ★ ревизия М-5: вызовы проверки скорости в ветке «цель в дальности» (подменяются стабом записи журнала)
    for cname, cva, cfn, ctgt in CHK_SITES:
        want_b = b"\xE8" + struct.pack("<i", ctgt - (cva + 5))
        ok(img[cva - base:cva - base + 5] == want_b, "%s %s @0x%06X: call 0x%06X" % (name, cname, cva, ctgt))
        starts = [i.address for i in insns(img, base, cfn, cva + 16)]
        ok(cva in starts and cva + 5 in starts, "%s %s: границы инструкций 0x%06X → 0x%06X" % (name, cname, cva, cva + 5))
        win += img[cva - base - 32:cva - base + 37]
    # входы внутрь площадок: rel8 (EB/7x), rel32 (E8/E9), jcc32 (0F 8x) по всему .text, байт за байтом
    inner = [(va + 1, va + 10) for _, va, _, _, _, _ in SITES] + [(cva + 1, cva + 5) for _, cva, _, _ in CHK_SITES]
    hits = []
    t = img[lo - base:hi - base]
    for o in range(len(t) - 6):
        b0 = t[o]
        tgt = None
        if b0 == 0xEB or 0x70 <= b0 <= 0x7F:
            tgt = lo + o + 2 + struct.unpack_from("<b", t, o + 1)[0]
        elif b0 in (0xE8, 0xE9):
            tgt = lo + o + 5 + struct.unpack_from("<i", t, o + 1)[0]
        elif b0 == 0x0F and 0x80 <= t[o + 1] <= 0x8F:
            tgt = lo + o + 6 + struct.unpack_from("<i", t, o + 2)[0]
        if tgt is not None and any(a <= tgt < b for a, b in inner):
            hits.append((lo + o, tgt))
    # Сплошной перебор ловит и «ложные» кодировки внутри других инструкций; настоящие — только с началом на границе инструкции.
    real = []
    for src, tgt in hits:
        for _, va, _, fn, _, _ in SITES:
            if fn <= src < va + 0x400:
                if src in [i.address for i in insns(img, base, fn, va + 0x400)]:
                    real.append((src, tgt))
    ok(not real, "%s: переходов внутрь изменяемых байтов нет (сплошной перебор .text: кандидатов %d, на границах инструкций %d)"
       % (name, len(hits), len(real)))
    windows.append((name, win))
if len(windows) == 3:
    ok(windows[0][1] == windows[1][1] == windows[2][1], "окна ±32 б вокруг площадок побайтово одинаковы на трёх образах")

print("== 2. кадр: смещение такта у площадки")
pe, img, base = load(IMAGES[0][1]) if os.path.exists(IMAGES[0][1]) else (None, None, None)
if img:
    # Путь от входа до площадки без веток ошибок: отрезки (от, до) — по дизасму (условные переходы ведут в ветки ошибок/else).
    PATHS = {0x45FCD0: [(0x45FCD0, 0x45FCEE), (0x45FD16, 0x45FDB5), (0x45FDBF, 0x45FE0C)],
             0x460710: [(0x460710, 0x46072E), (0x460756, 0x4607DD), (0x4607E4, 0x46085F)]}

    def ret_imm(fva):
        """Сколько байт аргументов снимает вызываемая (`ret N`; все ret функции обязаны совпадать)."""
        seen = set()
        for i in md.disasm(img[fva - base:fva - base + 0x4000], fva):
            if i.mnemonic == "ret":
                seen.add(int(i.op_str, 0) if i.op_str else 0)
            if i.mnemonic == "int3" or (len(seen) and i.address > fva + 0x3000):
                break
        return seen

    for sname, va, nxt, fn, toff, (chk, chk_text, chk_off) in SITES:
        depth = 0           # байт под адресом возврата обработчика на площадке (аргументы — выше)
        steps = []
        for a, b in PATHS[fn]:
            for i in insns(img, base, a, b):
                if i.mnemonic == "push":
                    depth += 4
                elif i.mnemonic == "pop":
                    depth -= 4
                elif i.mnemonic in ("sub", "add") and i.op_str.startswith("esp, "):
                    depth += (1 if i.mnemonic == "sub" else -1) * int(i.op_str.split(", ")[1], 0)
                elif i.mnemonic == "call":
                    tgt = int(i.op_str, 0)
                    rs = ret_imm(tgt)
                    ok(len(rs) == 1, "%s: вызов 0x%06X → 0x%06X: все ret одинаковы %s" % (sname, i.address, tgt, sorted(rs)))
                    depth -= (min(rs) if rs else 0)
                    steps.append("call %06X ret %d" % (tgt, min(rs) if rs else 0))
        ok(depth + 4 == toff, "%s: путь до площадки (%s) → глубина 0x%X, такт (3-й аргумент) в [esp+0x%X] (ждём 0x%X)"
           % (sname, ", ".join(steps), depth, depth + 4, toff))
        ci = insns(img, base, chk, chk + 16)[0]
        ok((ci.mnemonic + " " + ci.op_str) == chk_text, "%s: сток сам читает такт @0x%06X `%s` (кадр без аргументов sub_42C4F0: 0x%X)"
           % (sname, chk, chk_text, chk_off))
        ok(toff - chk_off == (0x10 if toff == 0x94 else 0), "%s: смещения сходятся (разница — аргументы sub_42C4F0 на стеке у площадки)" % sname)
    src = open(NPC_C, encoding="utf-8", errors="replace").read()
    m1 = re.search(r"case 0x2009:\s*\n\s*.*?sub_45FCD0\(\(int\)a1, [^,]+, \(int\)v3\)", src, re.S)
    m2 = re.search(r"case 0x201E:\s*\n\s*.*?sub_460710\(\(int\)a1, [^,]+, \(int\)v3\)", src, re.S)
    m3 = re.search(r"sub_45F3A0\(\(int\)a1, [^,]+, \(int\)v3, 0\)", src)
    ok(bool(m1 and m2 and m3), "диспетчер: 0x2009 → sub_45FCD0(…, v3), 0x201E → sub_460710(…, v3), 4028 → sub_45F3A0(…, v3, 0) — один и тот же такт")

print("== 3. DLL: стабы и реестр")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map — сначала build.bat" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        """Символ из объектного файла N19 (одноимённые стабы есть и у других патчей — St_Pvp у N14)."""
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+n19_restart_attack_clock\.obj\s*$" % rx, mp, re.M)
        return (m.group(1), int(m.group(2), 16)) if m else (None, 0)

    want_disp = {"St_Mob": (0, 0x24 + 4 + 0x94 + 4), "St_Pvp": (1, 0x24 + 4 + 0x7C + 4)}
    n19 = sym(r"_N19_Restart@12")
    ok(n19[1] != 0, "символ N19_Restart в .map: %s @%08X" % (n19[0], n19[1]))
    for st, (site_no, disp) in want_disp.items():
        name, va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "символ стаба %s: %s @%08X" % (st, name, va))
        if not va:
            continue
        code = [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + 64], va)][:12]
        print("    %s: %s" % (st, " ; ".join(code)))
        ok(code[0] == "pushfd" and code[1] == "pushal", "%s: pushfd; pushad — все регистры и флаги сохраняются" % st)
        ok(code[2] == "push %d" % site_no, "%s: площадка = %d" % (st, site_no))
        ok(code[3] == "push dword ptr [esp + 0x%x]" % disp, "%s: такт [esp+0x%X] = 24h (pushfd+pushad) + 4 (возврат) + смещение + 4 (push площадки)" % (st, disp))
        ok(code[4] == "push ebp" and code[5] == "call 0x%x" % n19[1], "%s: push ebp (запись игрока); call N19_Restart" % st)
        ok(code[6] == "test eax, eax" and code[7].startswith("je "), "%s: обнуление только при eax ≠ 0" % st)
        ok(code[8] == "mov dword ptr [ebp + 0xfe90], 0", "%s: обнуление — та же запись, что у стока" % st)
        ok(code[9] == "popal" and code[10] == "popfd" and code[11] == "ret", "%s: popad; popfd; ret — баланс стека" % st)
    # ★ ревизия М-5: стабы ветки «в дальности» — отдать отложенную запись и уйти в ту же функцию стока
    inr = sym(r"_N19_InRange@4")
    ok(inr[1] != 0, "символ N19_InRange в .map: %s @%08X" % (inr[0], inr[1]))
    for st, (site_no, fn) in {"St_InRangeMob": (0, 0x45F3A0), "St_InRangePvp": (1, 0x45FF80)}.items():
        name, va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "символ стаба %s: %s @%08X" % (st, name, va))
        if not va:
            continue
        ins = list(md.disasm(img[va - base:va - base + 48], va))[:7]
        code = [(i.mnemonic + " " + i.op_str).strip() for i in ins]
        print("    %s: %s" % (st, " ; ".join(code)))
        ok(code[:3] == ["pushfd", "pushal", "push %d" % site_no] and code[3] == "call 0x%x" % inr[1],
           "%s: pushfd; pushad; площадка %d; call N19_InRange" % (st, site_no))
        ok(code[4] == "popal" and code[5] == "popfd", "%s: popad; popfd — регистры, флаги и стек как у стока" % st)
        m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]", code[6])
        ptr = int(m.group(1), 16) if m else 0
        tgt = struct.unpack_from("<I", img, ptr - base)[0] if ptr else 0
        ok(tgt == fn, "%s: jmp [0x%X] → 0x%06X (ждём функцию стока 0x%06X)" % (st, ptr, tgt, fn))
    reg = open(os.path.join(SRC, "Registry.cpp"), encoding="utf-8-sig").read()
    order = [reg.find('L"N01_AttackTimer32"'), reg.find('L"P53_AcJournal"'), reg.find('L"N19_RestartAttackClock"')]
    ok(all(o > 0 for o in order) and order[2] > order[0] and order[2] > order[1], "реестр: N19 после N01 (допуск) и P53 (журнал)")
    ok("PatchResult N19_RestartAttackClock();" in open(os.path.join(SRC, "Patches.h"), encoding="utf-8-sig").read(), "Patches.h: объявление N19")
    srcn = open(os.path.join(SRC, "n19_restart_attack_clock.cpp"), encoding="utf-8").read()
    ok("0x0045FE0C" in srcn and "0x0046085F" in srcn and "0xC7, 0x85, 0x90, 0xFE" in srcn, "исходник N19: адреса и байты площадок совпадают с таблицей скрипта")

print("== ИТОГ verify_n19: %s (провалов %d)" % ("OK" if bad == 0 else "ПРОВАЛ", bad))
sys.exit(1 if bad else 0)
