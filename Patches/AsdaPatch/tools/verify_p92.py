# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p92.py — СТАТИЧЕСКАЯ проверка P92 «вредный эффект навыка игрока — только на враждебного игрока» (волна bowfx, 26.10.2026).
#   Логику (правило sub_556DB0 × режимы, решения площадок на НАСТОЯЩЕМ коде) проверяет stand_p92. Здесь:
#   1. Образы GameServer (сток 4e20f0ad, живой = Indun e7b4ac38): байты 5 площадок и всех сверяемых соседей, границы инструкций
#      (линейный проход от начала функции), сплошной перебор переходов rel8/rel32/jcc32 по .text — входов внутрь площадок нет;
#      окна ±32 б одинаковы на всех образах.
#   2. Доказательство дыр вторым методом (скан образа, а не декомпил): функции, перебирающие игроков сектора (список +0x13C8 /
#      массив +0x358 сектора), — EXPLOSION_ARROW 0x486870 и GUARDIAN_NORMAL_ATTACK_AREA 0x486F20 НЕ зовут sub_556DB0, а
#      CHIP_EFFECT 0x486370 / LIGHT_BLOW 0x4873F0 / DAMAGE_REPLEX 0x486C20 зовут (REPLEX — с push 0DCh = 220); все вызовы
#      sub_556DB0 (7) и sub_4283F0 (8: 8009 + 7 внутренних) — ровно разобранные; разметка полей в sub_556DB0.
#   3. Данные стойки (зеркало SSH): SkillInfo.sif +52 у 160/924 = 6, у 173/220/248 = 0 (сверка по ID состояния не работает),
#      1004 = 5, 788 → состояние 173; SoulGuarderSkillTable 1216–1218 → 248.
#   4. DLL (по .map): стабы St_S1…St_S5 (P92_Decide, замещённые инструкции, продолжения/пропуски), реестр (P92 после P91),
#      секция ini, тексты ac.other 121–123; чужие патчи в площадках не пишут.
# Запуск: py -3 verify_p92.py [AsdaPatch.dll]
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
from srv_paths import V2   # зеркало стойки по SSH (srv_mirror.py)

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
IMAGES = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447"),
          ("живой GameServer", os.path.join(IMG, "gs_live.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01"),
          ("живой Indun", os.path.join(IMG, "gs_indun.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01")]
H = bytes.fromhex
# (имя, VA, байты, начало функции, продолжение)
SITES = [
    ("S1 EXPLOSION_ARROW", 0x486B3A, H("668B4DFC66894DE9"), 0x486870, 0x486B42),
    ("S2 GUARDIAN_NORMAL_ATTACK_AREA", 0x48722A, H("668B45FC668945D5"), 0x486F20, 0x487232),
    ("S3 GUARDIAN_DAMAGE_REPLEX", 0x486E1A, H("68DC000000"), 0x486C20, 0x486E1F),
    ("S4 sub_4283F0 (8009)", 0x428453, H("0FB645F983F801"), 0x4283F0, 0x42845A),
    ("S5 RecvChar_SkillUse (5256)", 0x46FCCB, H("668B9564FAFFFF52"), 0x46F900, 0x46FCD3),
]
NEIGH = [   # соседи, которые P92 сверяет сам (те же байты — в p92_hostile_target_guard.cpp)
    (0x486B42, H("C68510FDFFFF00")), (0x486BF9, H("E9E1FDFFFF")), (0x486B2A, H("0FBF55FC0FBF45083BD00F84BF000000")),
    (0x486899, H("668B4D1C66894DF6")), (0x486883, H("898D0CFDFFFF")),
    (0x487232, H("C685F0FCFFFF00")), (0x48720D, H("0FBF55FC0FBF450C3BD0740C0FBF4D080FBF55FC3BCA7505")),
    (0x487225, H("E998FEFFFF")), (0x486F33, H("898DECFCFFFF")),
    (0x486E1F, H("668B55FC52668B4508508B8D24FDFFFF8B51048B4A34E876FF0C000FB6C085C07505E908FFFFFF")),
    (0x42843E, H("6A118B4D08034DE4518D55EC52E8F0")), (0x42845A, H("0F858D030000")), (0x428426, H("8B55E483C211")),
    (0x4314FA, H("E8F16EFFFF")),
    (0x46FCD3, H("8B8570FDFFFF6BC01D668B8C05A5FDFFFF51668B5508528B8538FAFFFF8B48048B4934E8B5700E00")),
]
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def md5(path):
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
mdk = Cs(CS_ARCH_X86, CS_MODE_32)   # сплошной проход по .text: данные между функциями пропускаются
mdk.skipdata = True


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


def func_end(img, base, fva, span=0x2000):
    """Конец функции: первый ret, за которым int3/выравнивание (линейный проход)."""
    last = fva
    for i in md.disasm(img[fva - base:fva - base + span], fva):
        last = i.address + i.size
        if i.mnemonic == "ret":
            nxt = img[last - base]
            if nxt == 0xCC:
                return last
    return last


print("== 1. образы GameServer: площадки, соседи, границы, переходы")
wins = []
live = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if "живой GameServer" in name:
        live = (pe, img, base)
    lo, hi = text_range(pe, base)
    g = lambda va, n: img[va - base:va - base + n]
    win = b""
    for sname, va, orig, fn, back in SITES:
        ok(g(va, len(orig)) == orig, "%s %s @0x%06X: %s" % (name, sname, va, orig.hex()))
        end = func_end(img, base, fn)
        starts = {i.address for i in insns(img, base, fn, end)}
        ok(va in starts and back in starts, "%s %s: границы инструкций (0x%06X и продолжение 0x%06X, функция 0x%06X…0x%06X)"
           % (name, sname, va, back, fn, end))
        win += img[va - base - 32:va - base + len(orig) + 32]
    for va, orig in NEIGH:
        ok(g(va, len(orig)) == orig, "%s сосед 0x%06X: %s" % (name, va, orig.hex()))
    inner = [(va + 1, va + len(orig)) for _, va, orig, _, _ in SITES]
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
    real = []
    for src, tgt in hits:
        for _, va, orig, fn, back in SITES:
            if va <= tgt < va + len(orig):
                end = func_end(img, base, fn)
                if fn <= src < end and src in {i.address for i in insns(img, base, fn, end)}:
                    real.append((src, tgt))
    ok(not real, "%s: переходов внутрь площадок нет (кандидатов-байт %d, настоящих инструкций %d)" % (name, len(hits), len(real)))
    wins.append(win)
if len(wins) == len(IMAGES):
    ok(all(w == wins[0] for w in wins), "окна ±32 б вокруг площадок одинаковы на %d образах" % len(wins))

print("== 2. дыры вторым методом (скан образа живого GameServer)")
if live:
    pe, img, base = live
    lo, hi = text_range(pe, base)
    allins = list(mdk.disasm(img[lo - base:hi - base], lo))
    calls = lambda tgt: [i.address for i in allins if i.mnemonic == "call" and i.op_str == hex(tgt)]
    c556 = calls(0x556DB0)
    ok(c556 == [0x46FCF6, 0x486695, 0x486E35, 0x487605, 0x48E84B, 0x554E1A, 0x555493],
       "sub_556DB0 зовут 7 мест: %s (5256, CHIP 160, REPLEX 220, LIGHT_BLOW 924, 6158 хранитель, 4201, 4203)" % ", ".join("0x%06X" % a for a in c556))
    c428 = calls(0x4283F0)
    ok(len(c428) == 8 and 0x4314FA in c428,
       "sub_4283F0 зовут 8 мест: 0x4314FA (8009 NpcServer) + 7 внутренних SkillState_*: %s" % ", ".join("0x%06X" % a for a in c428))
    funcs = {"CHIP_EFFECT 160": 0x486370, "EXPLOSION_ARROW 173": 0x486870, "DAMAGE_REPLEX 220": 0x486C20,
             "NORMAL_ATTACK_AREA 248": 0x486F20, "LIGHT_BLOW 924": 0x4873F0}
    for nm, fva in funcs.items():
        end = func_end(img, base, fva)
        body = [i for i in allins if fva <= i.address < end]
        users = any("+ 0x13c8]" in i.op_str for i in body) and any("0x358" in i.op_str for i in body)
        has556 = any(i.mnemonic == "call" and i.op_str == "0x556db0" for i in body)
        has428 = any(i.mnemonic == "call" and i.op_str == "0x4283f0" for i in body)
        dmg = any(i.mnemonic == "call" and i.op_str == "0x43c690" for i in body)
        want556 = nm.split()[0] in ("CHIP_EFFECT", "DAMAGE_REPLEX", "LIGHT_BLOW")
        ok(users and has428 and dmg and has556 == want556,
           "%s 0x%06X: перебор игроков сектора, 4102 (sub_4283F0) и урон (sub_43C690); sub_556DB0 %s"
           % (nm, fva, "ЕСТЬ" if has556 else "НЕТ — дыра"))
    rep = {i.address: (i.mnemonic + " " + i.op_str) for i in allins if 0x486E1A <= i.address <= 0x486E35}
    ok(rep.get(0x486E1A) == "push 0xdc" and rep.get(0x486E35) == "call 0x556db0", "REPLEX: sub_556DB0(a2, жертва, 220) — ID состояния, не навыка")
    txt = {i.address: (i.mnemonic + " " + i.op_str) for i in allins if 0x556DB0 <= i.address < 0x5572C4}
    want = {0x556E04: "mov al, byte ptr [edx + 0x3e8d2]", 0x556E83: "mov eax, dword ptr [ecx + 0x3e8d3]",
            0x556E89: "cmp eax, dword ptr [edx + 0xc]", 0x556EA5: "cmp dword ptr [edx + 0x182b9], -1",
            0x556ECC: "movsx ecx, word ptr [eax + 0x18318]", 0x556EFA: "movsx ecx, word ptr [eax + 0x1b4]",
            0x556F3D: "movsx eax, word ptr [edx + 0x3f44c]", 0x556E51: "movzx ecx, byte ptr [eax + edx + 0x34]"}
    for va, s in want.items():
        ok(txt.get(va) == s, "sub_556DB0 0x%06X: %s" % (va, s))
    ok(txt.get(0x5572C1) == "ret 0xc", "sub_556DB0: thiscall, ret 0Ch (3 слова) — P92 зовёт её с a4 = −1")
    ok(func_end(img, base, 0x486870) and any(i.address == 0x486C10 and i.op_str == "0x18" for i in allins if 0x486C00 <= i.address < 0x486C20),
       "EXPLOSION_ARROW: ret 18h (6 слов) — владелец a7 в [ebp+1Ch]")
    ok(any(i.address == 0x486F1C and i.op_str == "0x10" for i in allins if 0x486F00 <= i.address < 0x486F20),
       "DAMAGE_REPLEX: ret 10h (4 слова) — отражающий a2 [ebp+8], состояние a3 [ebp+0Ch]")
    ok(img[0x4314FF - base:0x4314FF - base + 3] == H("8B4D08"), "8009: адрес возврата sub_4283F0 = 0x4314FF (S4 отсеивает внутренние вызовы)")

print("== 3. данные стойки (зеркало)")
sif = V2 + "GameServer/SkillTable_Info/SkillInfo.sif"
if not os.path.exists(sif):
    ok(False, "нет %s (srv_mirror.py)" % sif)
else:
    d = open(sif, "rb").read()
    row = lambda k: d[209 * k:209 * k + 209]
    ok(len(d) == 209 * 1120 and all(struct.unpack_from("<h", row(k), 0)[0] == k for k in (160, 173, 220, 248, 788, 924, 1004)),
       "SkillInfo.sif: 1120 записей по 209 б, id в +0")
    ok(row(160)[52] == 6 and row(924)[52] == 6, "+52: 160 (CHIP) = 6, 924 (LIGHT_BLOW) = 6 — сверка по ID состояния у них работает")
    ok(row(173)[52] == 0 and row(220)[52] == 0 and row(248)[52] == 0, "+52: 173 = 0, 220 = 0, 248 = 0 — сверка по ID состояния не враждебная")
    ok(row(1004)[52] == 5 and row(1004)[42] == 1, "1004 «Клеймо льда»: активный, +52 = 5 (любой игрок) — вредный навык без признака 6")
    ok(struct.unpack_from("<h", row(788), 0x48)[0] == 173, "788 «Взрыв» → состояние 173 (прок обычной атаки)")
sg = V2 + "GameServer/SkillTable_Info/SoulGuarderSkillTable.txt"
if os.path.exists(sg):
    rows = [l.split("\t") for l in open(sg, encoding="cp949", errors="replace").read().splitlines()[1:] if l.strip()]
    has248 = sorted(int(r[0]) for r in rows if len(r) > 22 and "248" in r[20:23])
    has220 = sorted(int(r[0]) for r in rows if len(r) > 22 and "220" in r[20:23])
    ok(has248 == [1216, 1217, 1218], "SoulGuarderSkillTable: состояние 248 у хранителей %s" % has248)
    ok(len(has220) >= 3, "SoulGuarderSkillTable: состояние 220 у хранителей %s" % has220)
else:
    print("  (нет %s в зеркале — пропуск сверки хранителей)" % sg)

print("== 4. DLL, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p92_hostile_target_guard\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    dec = sym(r"_P92_Decide@8")
    ok(dec != 0, "P92_Decide (__stdcall, 8 б) @%08X" % dec)
    ok(sym(r"_P92_GetStats@4") != 0, "экспорт P92_GetStats")

    def code(va, n=96):
        return [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + n], va)]

    def jmpval(line):
        m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]", line)
        return struct.unpack_from("<I", img, int(m.group(1), 16) - base)[0] if m else None

    spec = {
        "St_S1": (1, ["mov cx, word ptr [ebp - 4]", "mov word ptr [ebp - 0x17], cx"], 0x486B42, 0x486BF9),
        "St_S2": (2, ["mov ax, word ptr [ebp - 4]", "mov word ptr [ebp - 0x2b], ax"], 0x487232, 0x4870C2),
        "St_S3": (3, [], 0x486E46, 0x486D4E),
    }
    for st, (site, repl, back, skip) in spec.items():
        va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "стаб %s @%08X" % (st, va))
        if not va:
            continue
        c = code(va)
        print("    %s: %s" % (st, " ; ".join(c[:10])))
        head = c[:5]
        ok(head[0] == "push ebp" and head[1] == "push %d" % site and head[2] == "call 0x%x" % dec and head[3] == "test eax, eax"
           and head[4].startswith("je "), "%s: P92_Decide(%d, ebp), проверка результата" % (st, site))
        ok(c[5:5 + len(repl)] == repl, "%s: замещённые инструкции %s" % (st, repl or "— (S3 заменяет стоковый вызов)"))
        jm = [l for l in c[5:9] if l.startswith("jmp dword ptr")]
        ok(len(jm) >= 2 and jmpval(jm[0]) == back and jmpval(jm[1]) == skip,
           "%s: «можно» → 0x%06X, «нельзя» → 0x%06X (%s)" % (st, back, skip, ", ".join("0x%06X" % (jmpval(x) or 0) for x in jm)))
    va = sym(r"\?St_S4@\S+")
    if va:
        c = code(va, 128)
        print("    St_S4: %s" % " ; ".join(c[:18]))
        ok(c[0] == "mov eax, dword ptr [ebp + 4]" and c[1].startswith("cmp eax, dword ptr [") and "byte ptr [ebp - 0x14], 1" in c[3]
           and "byte ptr [ebp - 7], 1" in c[5] and c[7] == "mov ax, word ptr [ebp - 6]" and c[8] == "cmp ax, word ptr [ebp - 0x13]",
           "St_S4: отсев — адрес возврата 8009, вид 1, «наложить» 1, владелец ≠ цель")
        ptr = int(re.search(r"\[(0x[0-9a-f]+)\]", c[1]).group(1), 16)
        ok(struct.unpack_from("<I", img, ptr - base)[0] == 0x4314FF, "St_S4: сравнение с адресом возврата 0x4314FF")
        ok("push ebp" in c and "push 4" in c and ("call 0x%x" % dec) in c, "St_S4: P92_Decide(4, ebp)")
        i = c.index("movzx eax, byte ptr [ebp - 7]")
        ok(c[i + 1] == "cmp eax, 1" and jmpval(c[i + 2]) == 0x42845A and jmpval(c[i + 3]) == 0x428426,
           "St_S4: замещённое movzx/cmp (флаги для jne), продолжение 0x42845A, пропуск записи 0x428426")
    else:
        ok(False, "стаб St_S4 не найден")
    va = sym(r"\?St_S5@\S+")
    if va:
        c = code(va, 128)
        print("    St_S5: %s" % " ; ".join(c[:14]))
        ok(c[0] == "movzx eax, word ptr [ebp - 0x59c]" and c[1] == "cmp eax, 0x4af", "St_S5: навык [ebp-59Ch], граница 1199")
        ok("push 5" in c and ("call 0x%x" % dec) in c and "push eax" in c, "St_S5: P92_Decide(5, ebp) → push eax (a4)")
        i = c.index("mov dx, word ptr [ebp - 0x59c]")
        ok(c[i + 1] == "push edx" and jmpval(c[i + 2]) == 0x46FCD3, "St_S5: сток — push навыка, продолжение 0x46FCD3")
        ok(sum(1 for l in c[:i] if jmpval(l) == 0x46FCD3) == 1, "St_S5: из ветки списка — тоже на 0x46FCD3")
    else:
        ok(False, "стаб St_S5 не найден")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    order = [m.group(1) for m in re.finditer(r'\{ L"(P\d+_\w+)",', reg)]
    ok("P92_HostileTargetGuard" in order and order.index("P92_HostileTargetGuard") > order.index("P91_ExpCapRate"), "реестр: P92 после P91")
    cpp = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    ok('L"P92_HostileTargetGuard",' in cpp and 'L"HostileSkills", L"1004",' in cpp and "kHostileTargetGuard, ARRAYSIZE(kHostileTargetGuard)" in cpp,
       "Config.cpp: секция P92, HostileSkills=1004")
    aj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8-sig").read()
    ok(all(('case %d: return L"P92:' % k) in aj for k in (121, 122, 123)), "AcJournal.cpp: тексты ac.other 121/122/123")
    ok(not any(('case %d:' % k) in aj.replace('case %d: return L"P92:' % k, "") for k in (121, 122, 123)),
       "AcJournal.cpp: 121–123 не заняты другими патчами")

print("== 5. чужие патчи в площадках")
pd = os.path.join(SRC, "patches")
rng = [(va, va + len(o)) for _, va, o, _, _ in SITES]
hits = []
for fn in sorted(os.listdir(pd)):
    if not fn.endswith(".cpp") or fn.startswith("p92_") or fn == "Registry.cpp":
        continue
    t = open(os.path.join(pd, fn), encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"0x(00)?([0-9A-Fa-f]{6})\b", t):
        a = int(m.group(2), 16)
        if any(lo <= a < hi for lo, hi in rng):
            hits.append("%s:0x%06X" % (fn, a))
ok(not hits, "адреса площадок P92 в других патчах не встречаются (%s)" % (", ".join(hits) or "—"))
p42 = open(os.path.join(pd, "p42_gm_hide_target.cpp"), encoding="utf-8", errors="replace").read()
ok("0x00486B22" in p42 and "0x00486B2A" in p42 and "0x00487205" in p42 and "0x0048720D" in p42,
   "P42 C8 0x486B22…0x486B2A и C9 0x487205…0x48720D — соседи S1 (0x486B3A) и S2 (0x48722A), не пересекаются")

print("== ИТОГ verify_p92: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
