# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p95.py — СТАТИЧЕСКАЯ проверка P95 «коробки 6096 (раскладка по правилу сервера + мин. уровень), бустер 5468 и
#   расходник 5028 (мин. уровень)» (волна bugs6, 29.10.2026). Логику на НАСТОЯЩИХ обработчиках проверяет stand_p95.
#   1. Образы GameServer (сток 4e20f0ad, живой = Indun = Ch2 e7b4ac38): байты 3 площадок и соседей (тот же список, что сверяет
#      сам P95), границы инструкций (линейный проход от начала функции), сплошной перебор переходов rel8/rel32/jcc32 по .text —
#      входов внутрь площадок нет; окна ±32 б одинаковы на всех образах.
#   2. Вторым методом (дизасм, не декомпил): тела отказа шлют нужный опкод с нужным буфером (0x55AE56 → 6097, буфер [ebp-3C8h],
#      код [ebp-3C1h] = буфер+7; 0x4F563E → 5469, [ebp-0D0h]; 0x4DA8DD → 5029 код 0, [ebp-24h]); каждая площадка достижима только
#      после стоковых проверок (6096 — je от кода 9; 5468 — jne после «подтип 200/201»; 5028 — сразу за «тип 11»); стоковые
#      функции, которые зовёт P95 (sub_4D6910, sub_4D6CE0, sub_5325F0, sub_532A90/AE0/B10) — thiscall/cdecl с теми ret;
#      sub_5325F0 читает [CUser+192h]; цикл 6096 читает код позиции [dword_5F5E68 + 34·v18 + 6i + 4] и ячейку тела
#      [ebp+3i-3E2h]/[ebp+3i-3E1h]; каждый обработчик зовётся из одного места.
#   3. DLL (по .map): стабы St_Package/St_Gacha/St_Spend (P95_On*, замещённая инструкция, продолжение/отказ), реестр (P95 после
#      P94), секция ini и умолчания, тексты ac.other 140–144; чужие патчи в трёх обработчиках площадок P95 не задевают.
#   4. Таблицы стойки (зеркало ItemTable_Info): 28229 — мин. уровень 10, тип 13/66; набор 75662 — 5 позиций, 73361 у сервера в
#      сумке; число коробок/бустеров/расходников с мин. уровнем > 1 (масштаб правки).
# Запуск: py -3 verify_p95.py [AsdaPatch.dll]
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
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
TABLES = os.path.join(HERE, "_srv_mirror", "v2", "GameServer", "ItemTable_Info")
IMAGES = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447"),
          ("живой GameServer", os.path.join(IMG, "gs_live.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01"),
          ("живой Indun", os.path.join(IMG, "gs_indun.exe"), "e7b4ac38e8328aaa847bbd9bf261bb01")]
H = bytes.fromhex
# (имя, VA, байты, начало функции, продолжение, отказ)
SITES = [
    ("S1/S2 Recv_OpenPackageItem 6096", 0x55AB2A, H("c78504fcffff00000000"), 0x55A820, 0x55AB34, 0x55AE56),
    ("S3 Recv_GachaItemUse 5468", 0x4F4BC5, H("8b857cffffff"), 0x4F48C0, 0x4F4BCB, 0x4F563E),
    ("S4 CharSpendItemUse 5028", 0x4D8F30, H("8b8564ffffff"), 0x4D8C40, 0x4D8F36, 0x4DA8DD),
]
NEIGH = [   # те же байты сверяет сам P95 (p95_item_use_guard.cpp)
    (0x55AB34, H("eb0f")), (0x55AE56, H("668b4d08518b8de8fbffff")), (0x55AB19, H("c6853ffcffff09")), (0x55AACB, H("66899510fcffff")),
    (0x55A96A, H("8d8514fcffff")), (0x55A925, H("89850cfcffff")), (0x55A835, H("898de8fbffff")), (0x55A9E1, H("8b859cfeffff")),
    (0x55AB45, H("0fb6851afcffff")), (0x55AB84, H("8b441104")), (0x55AC96, H("668b84151ffcffff")), (0x55ACA8, H("660fb6940d1efcffff")),
    (0x4F4BCB, H("2d47500000")), (0x4F563E, H("6a01668b5508528d8530ffffff")), (0x4F4BB4, H("c68530ffffff05")), (0x4F48D3, H("898d6cfeffff")),
    (0x4F4AAC, H("8d857cffffff")),
    (0x4D8F36, H("2d47500000")), (0x4DA8DD, H("c645dc006a016a00")), (0x4D8F27, H("83fa0b0f858e170000")), (0x4D8C53, H("898d18fbffff")),
    (0x4D8EC2, H("8d8d64ffffff")),
    (0x4D6910, H("558bec83ec08")), (0x4D6CE0, H("558bec83ec1c")), (0x5325F0, H("558bec83ec08")), (0x53261D, H("8a8192010000")),
    (0x532A90, H("558bec817d0847500000")), (0x532AE0, H("558bec817d08591b0000")), (0x532B10, H("558bec837d0801")),
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
mdk = Cs(CS_ARCH_X86, CS_MODE_32)
mdk.skipdata = True


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


def func_end(img, base, fva, span=0x2000):
    """Конец функции: первый ret, за которым int3 или пролог следующей функции `push ebp; mov ebp,esp` (линейный проход)."""
    last = fva
    for i in md.disasm(img[fva - base:fva - base + span], fva):
        last = i.address + i.size
        if i.mnemonic == "ret" and (img[last - base] == 0xCC or img[last - base:last - base + 3] == bytes.fromhex("558bec")):
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
    for sname, va, orig, fn, back, refuse in SITES:
        ok(g(va, len(orig)) == orig, "%s %s @0x%06X: %s" % (name, sname, va, orig.hex()))
        end = func_end(img, base, fn, 0x2000 if fn != 0x4D8C40 else 0x2000)
        starts = {i.address for i in insns(img, base, fn, end)}
        ok(va in starts and back in starts and refuse in starts and va + len(orig) == back,
           "%s %s: границы инструкций (площадка %d б, продолжение 0x%06X сразу за ней, отказ 0x%06X; функция 0x%06X…0x%06X)"
           % (name, sname, len(orig), back, refuse, fn, end))
        win += img[va - base - 32:va - base + len(orig) + 32]
    for va, orig in NEIGH:
        ok(g(va, len(orig)) == orig, "%s сосед 0x%06X: %s" % (name, va, orig.hex()))
    inner = [(va + 1, va + len(orig)) for _, va, orig, _, _, _ in SITES]
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
        for _, va, orig, fn, _, _ in SITES:
            if va <= tgt < va + len(orig):
                end = func_end(img, base, fn)
                if fn <= src < end and src in {i.address for i in insns(img, base, fn, end)}:
                    real.append((src, tgt))
    ok(not real, "%s: переходов внутрь площадок нет (кандидатов-байт %d, настоящих инструкций %d)" % (name, len(hits), len(real)))
    wins.append(win)
if len(wins) == len(IMAGES):
    ok(all(w == wins[0] for w in wins), "окна ±32 б вокруг площадок одинаковы на %d образах" % len(wins))

print("== 2. вторым методом (дизасм живого GameServer)")
if live:
    pe, img, base = live
    lo, hi = text_range(pe, base)
    allins = list(mdk.disasm(img[lo - base:hi - base], lo))

    def body(fva):
        end = func_end(img, base, fva)
        return [i for i in allins if fva <= i.address < end]

    def lines(fva, a, b):
        return [(i.mnemonic + " " + i.op_str).strip() for i in body(fva) if a <= i.address < b]

    # тела отказа: опкод и буфер
    l = lines(0x55A820, 0x55AE56, 0x55AE9F)
    ok("push 0x17d1" in l and "lea eax, [ebp - 0x3c8]" in l and "mov word ptr [ebp - 0x3c8], dx" in l and "call 0x4c28f0" in l,
       "0x55AE56 (LABEL_43): 6097 с буфером [ebp-3C8h]; код ответа = [ebp-3C1h] = буфер+7 (туда пишут коды 2…11 стока)")
    codes = sorted({int(m.group(1), 16) for x in lines(0x55A820, 0x55A820, 0x55AE56)
                    for m in [re.match(r"mov byte ptr \[ebp - 0x3c1\], (0x[0-9a-f]+|\d+)$", x)] if m})
    ok(codes == list(range(2, 12)), "6096: стоковые коды отказа в [ebp-3C1h] — %s (P95 пишет туда 3/7 тем же путём)" % codes)
    l = lines(0x4F48C0, 0x4F563E, 0x4F5666)
    ok("push 0x155d" in l and "lea eax, [ebp - 0xd0]" in l and "call 0x4c28f0" in l, "0x4F563E: общий хвост отказа 5469 с буфером [ebp-0D0h]")
    l = lines(0x4D8C40, 0x4DA8DD, 0x4DA903)
    ok(l[:1] == ["mov byte ptr [ebp - 0x24], 0"] and "push 0x13a5" in l and "lea edx, [ebp - 0x24]" in l and "call 0x4c28f0" in l,
       "0x4DA8DD (LABEL_196): 5029 код 0 с буфером [ebp-24h], далее эпилог 0x4DA903")
    # достижимость площадок
    b = {i.address: i for i in body(0x55A820)}
    ok(b[0x55AB17].mnemonic == "je" and b[0x55AB17].op_str == "0x55ab2a", "6096: площадка — цель je после кода 9 (все проверки коробки пройдены)")
    b = {i.address: i for i in body(0x4F48C0)}
    ok(b[0x4F4B82].mnemonic == "jne" and b[0x4F4B82].op_str == "0x4f4bc5", "5468: площадка — цель jne после «подтип ≠ 200/201» (коробки — 6096)")
    b = {i.address: i for i in body(0x4D8C40)}
    ok(b[0x4D8F2A].mnemonic == "jne" and b[0x4D8F2A].op_str == "0x4da6be", "5028: площадка сразу за `cmp edx,0Bh / jne LABEL_181` (только item_list тип 11)")
    # стоковые функции, которые зовёт P95
    rets = {0x4D6910: "ret 0xc", 0x4D6CE0: "ret 0x10", 0x5325F0: "ret 4", 0x532A90: "ret", 0x532AE0: "ret", 0x532B10: "ret"}
    for fva, r in rets.items():
        rr = [(i.mnemonic + " " + i.op_str).strip() for i in insns(img, base, fva, func_end(img, base, fva)) if i.mnemonic == "ret"]
        ok(rr and all(x == r for x in rr), "0x%06X: %s (P95 зовёт с тем же числом аргументов)" % (fva, r))
    ok("mov al, byte ptr [ecx + 0x192]" in [(i.mnemonic + " " + i.op_str) for i in body(0x5325F0)], "sub_5325F0: уровень = [CUser+192h]")
    l = lines(0x55A820, 0x55AB58, 0x55ACC6)
    ok("add ecx, dword ptr [0x5f5e68]" in l and "mov eax, dword ptr [ecx + edx + 4]" in l and "imul ecx, ecx, 0x22" in l,
       "6096: код позиции = [dword_5F5E68 + 34·v18 + 6i + 4] (как читает P95)")
    ok("movzx dx, byte ptr [ebp + ecx - 0x3e2]" in l and "mov ax, word ptr [ebp + edx - 0x3e1]" in l and "call 0x4d6910" in l and "call 0x4d6ce0" in l,
       "6096: ячейка позиции из тела [ebp+3i-3E2h]/[ebp+3i-3E1h], проверки sub_4D6910 / sub_4D6CE0 (как зовёт P95)")
    calls = lambda tgt: [i.address for i in allins if i.mnemonic == "call" and i.op_str == hex(tgt)]
    for fva in (0x55A820, 0x4F48C0, 0x4D8C40):
        c = calls(fva)
        ok(len(c) == 1, "обработчик 0x%06X зовётся из одного места: %s" % (fva, ", ".join("0x%06X" % a for a in c)))

print("== 3. DLL, реестр, конфиг, чужие площадки")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p95_item_use_guard\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    fns = {k: sym(r"_P95_%s@4" % k) for k in ("OnPackage", "OnGacha", "OnSpend", "GetStats")}
    ok(all(fns.values()), "P95_OnPackage/OnGacha/OnSpend (__stdcall, 4 б) и экспорт P95_GetStats: %s" % {k: "%08X" % v for k, v in fns.items()})

    def code(va, n=64):
        return [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + n], va)]

    def jmpval(line):
        m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]", line)
        return struct.unpack_from("<I", img, int(m.group(1), 16) - base)[0] if m else None

    spec = {"St_Package": ("OnPackage", "mov dword ptr [ebp - 0x3fc], 0", 0x55AB34, 0x55AE56),
            "St_Gacha": ("OnGacha", "mov eax, dword ptr [ebp - 0x84]", 0x4F4BCB, 0x4F563E),
            "St_Spend": ("OnSpend", "mov eax, dword ptr [ebp - 0x9c]", 0x4D8F36, 0x4DA8DD)}
    for st, (fn, repl, back, refuse) in spec.items():
        va = sym(r"\?%s@\S+" % st)
        ok(va != 0, "стаб %s @%08X" % (st, va))
        if not va:
            continue
        c = code(va)
        print("    %s: %s" % (st, " ; ".join(c[:12])))
        ok(c[:7] == ["pushfd", "pushal", "push ebp", "call 0x%x" % fns[fn], "test eax, eax", "popal", c[6]] and c[6].startswith("jne "),
           "%s: pushfd/pushad, P95_%s(ebp), test, popad, jne" % (st, fn))
        ok(c[7] == "popfd" and c[8] == repl and jmpval(c[9]) == back, "%s: «сток» → popfd, замещённое `%s`, jmp 0x%06X" % (st, repl, back))
        ok(c[10] == "popfd" and jmpval(c[11]) == refuse, "%s: «отказ» → popfd, jmp 0x%06X" % (st, refuse))
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8").read()
    ok(0 < reg.find('{ L"P94_SoulmateSelfEcho"') < reg.find('{ L"P95_ItemUseGuard"'), "реестр: P95_ItemUseGuard после P94")
    cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8").read()
    ok(all(k in cfg for k in ('{ L"P95_ItemUseGuard"', "kItemUseGuard, ARRAYSIZE(kItemUseGuard)", 'L"Placement", L"1"', 'L"LevelGate", L"1"',
                              'L"PackageLevelCode", L"3"', 'L"GachaLevelCode", L"3"')), "Config.cpp: секция [P95_ItemUseGuard] и умолчания")
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8").read()
    ok(all(("case %d: return L\"P95:" % k) in acj for k in range(140, 145)), "AcJournal: тексты ac.other 140–144")
    ok(not any(("case %d:" % k) in acj.replace("case %d: return L\"P95:" % k, "") for k in range(140, 145)), "AcJournal: виды 140–144 заняты только P95")
    blob = img.decode("latin-1")
    ok("P95_ItemUseGuard".encode("utf-16-le").decode("latin-1") in blob, "DLL: имя секции в образе")
    # чужие патчи: ни один их адрес не попадает в площадки P95 (байты, которые P95 пишет) и в соседей P95 внутри трёх
    #   обработчиков (кроме известных ссылок «только сверка/комментарий кадра»). Прологи стоковых функций (sub_4D6910, sub_532A90 …)
    #   другие патчи только зовут/сверяют — их запись ловит общий прогон стендов (P95 сверяет байты сам при установке).
    hr = [(0x55A820, 0x55AEC0), (0x4F48C0, 0x4F5680), (0x4D8C40, 0x4DA920)]
    spans = [(va, va + len(o)) for _, va, o, _, _, _ in SITES] + [(va, va + len(o)) for va, o in NEIGH if any(a <= va < b for a, b in hr)]
    shared_ok = {0x55A835: "P63 сверяет пролог 6096 (не пишет)", 0x4F48D3: "P63 сверяет пролог 5468 (не пишет)",
                 0x55A925: "P62 — комментарий кадра pUser", 0x55A96A: "P62 — комментарий кадра тела"}
    others, seen = [], []
    pdir = os.path.join(SRC, "patches")
    ranges = [(0x55A820, 0x55AEC0), (0x4F48C0, 0x4F5680), (0x4D8C40, 0x4DA920)]
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or fn.startswith("p95_") or fn == "Registry.cpp":
            continue
        for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read()):
            v = int(m.group(1), 16)
            if any(a <= v < b for a, b in ranges):
                seen.append("%s:0x%06X" % (fn.split("_")[0], v))
            if any(a <= v < b for a, b in spans) and v not in shared_ok:
                others.append("%s:0x%06X" % (fn, v))
    ok(not others, "чужие площадки не задевают площадки и соседей P95%s" % (": " + ", ".join(others) if others else ""))
    print("    чужие адреса в обработчиках 6096/5468/5028: %s" % ", ".join(sorted(set(seen))))

print("== 4. таблицы стойки (зеркало %s)" % TABLES)
OFF = [0, 4, 5, 7, 8, 9, 11, 10, 12, 14, 18, 20, 21, 22, 24, 25, 26, 27, 28, 30, 32, 33, 34, 35, 36, 37, 41, 45, 46, 47, 49, 50, 54, 56,
       57, 58, 59, 60, 62, 63, 65, 67]
try:
    it = {}
    for ln in open(os.path.join(TABLES, "item_table.txt"), "rb").read().decode("latin-1").split("\n")[1:]:
        p = ln.split()
        if len(p) >= 42:
            v = [int(x) for x in p[:42]]
            it[v[0]] = dict(zip(OFF, v))
    pk = {}
    for ln in open(os.path.join(TABLES, "PackageItem_Table.txt"), encoding="latin-1").read().split("\n")[1:]:
        p = ln.split()
        if len(p) >= 11:
            v = [int(x) for x in p[:11]]
            pk[v[0]] = [(v[1 + 2 * i], v[2 + 2 * i]) for i in range(5)]
    r = it[28229]
    ok(r[8] == 10 and r[26] == 13 and r[27] == 66, "28229 Booster-Pig Pang: мин. уровень %d, тип %d/%d (S3)" % (r[8], r[26], r[27]))
    r = it[75662]
    ps = pk.get(r[63], [])
    q = it.get(73361, {})
    ok(r[26] == 11 and r[27] == 200 and len([c for c, _ in ps if c > 0]) == 5 and q and not (q[7] == 4 and q[36] == 1),
       "75662 Cancer Star Set: набор %d, позиции %s; 73361 у сервера — сумка (+7=%s, +36=%s)" % (r[63], [c for c, _ in ps], q.get(7), q.get(36)))
    boxes = [c for c, r in it.items() if r[26] == 11 and r[27] in (200, 201)]
    print("    масштаб: коробок %d, из них с мин. уровнем > 1 — %d; бустеров (5468: +27 ∉ 200/201, +63 > 0) с мин. уровнем > 1 — %d; "
          "item_list тип 11 (5028) не коробок с мин. уровнем > 1 — %d"
          % (len(boxes), sum(1 for c in boxes if it[c][8] > 1),
             sum(1 for c, r in it.items() if r[27] not in (200, 201) and r[63] > 0 and r[8] > 1 and r[26] != 11),
             sum(1 for c, r in it.items() if r[26] == 11 and r[27] not in (200, 201) and r[8] > 1)))
except Exception as e:
    ok(False, "таблицы стойки: %s" % e)

print("== ИТОГ verify_p95: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
