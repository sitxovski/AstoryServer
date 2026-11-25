# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p98.py — СТАТИЧЕСКАЯ проверка P98 «стопочный предмет из премиум-почты приходит 1 шт.» (волна bugs7, 30.10.2026).
#   Логику на НАСТОЯЩИХ обработчиках проверяет stand_p98 (11006 + ответ БД sub_4F89D0, путь P16).
#   1. Образы GameServer (сток 4e20f0ad; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): байты площадки и соседей (тот же список, что сверяет сам P98), границы инструкций (линейный проход
#      от начала функции), сплошной перебор переходов rel8/rel32/jcc32 по .text — входов внутрь площадки нет; окна ±32 б
#      одинаковы на всех образах.
#   2. Вторым методом (дизасм, не декомпил): площадка — цель единственного `je` после `cmp [ebp-228h],1` за `call sub_5340B0`
#      с a4 = `push 0` и шаблоном `lea ecx,[ebp-5Fh]`; тело 2604 = [ebp-6Ch] (шаблон = тело +13), `push 57h; push 0A2Ch`; в
#      sub_5340B0 ветка «стопка»: +35 (`movzx …+23h`), sub_4D6CE0, `mov [ecx+9],edx`, `add eax,[ebp+10h]` (+= a4), вес
#      `imul ecx,[ebp+10h]`; ответ sub_4F89D0 копирует шаблон тела ответа (`rep movsd` 0Eh из [ebp-1FFh] = тело+13) в каждую
#      ячейку и суммирует вес [ebp+57i-1A1h] (= запись +14); DBManager sub_43F3E0 (живой образ зеркала): @Amount = тело +22
#      ([ebp-3B06h]), @Weight = тело +27 ([ebp-3B01h]), эхо 2604 87 б; обработчик 11006 зовётся из одного места.
#   3. DLL (по .map): стаб St_Premium (P98_OnPremium, замещённая инструкция, продолжение), экспорты P98_GetStats /
#      P98_FixPremiumRecord, вызов из P16 сразу после sub_5340B0, реестр (P98 после P97), секция ini и умолчания, тексты
#      ac.other 150–152 (заняты только P98); чужие патчи в 0x4F8340…0x4F89B0 площадку P98 не задевают.
#   4. Таблицы стойки (зеркало item_table.txt): 75521/20936/20946/20952/23229 — стопочные ветки «расходник» (P98 их чинит);
#      масштаб (стопочных кодов, колчанов-исключений); другие вызовы sub_5340B0 с a4 = 0 дефекта не дают
#      (PrimiumSumTable — награды нестопочные, если таблица есть в зеркале).
# Запуск: py -3.13 verify_p98.py [AsdaPatch.dll]
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
SRC = os.path.join(HERE, "..", "src")
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
TABLES = os.path.join(SRV, "v2", "GameServer", "ItemTable_Info")
DBM = os.path.join(SRV, "v2", "DBManager", "DBManager.exe")
LIVE = "e7b4ac38e8328aaa847bbd9bf261bb01"
IMAGES = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447")] + \
         [("живой " + d, os.path.join(SRV, "v2", d, "GameServer.exe"), LIVE) for d in stack_layout.GS_FOLDERS]
H = bytes.fromhex
FN = 0x4F8340                 # Recv_PremiumItemToInven_Req
SITE, ORIG, BACK = 0x4F8636, H("8b8de0fdffff"), 0x4F863C
NEIGH = [   # те же байты сверяет сам P98 (p98_premium_stack_amount.cpp)
    (0x4F863C, H("51e84ea40300")), (0x4F859C, H("83bdd8fdffff010f848d000000")), (0x4F8591, H("e81abb0300")),
    (0x4F8575, H("6a006a008d4da1516a008b95e0fdffff52")), (0x4F858B, H("8b8dc8fdffff")), (0x4F836B, H("898dc8fdffff")),
    (0x4F846A, H("8d8ddcfdffff")), (0x4F8499, H("8985e8fdffff")), (0x4F8802, H("0fb695e4fdffff")), (0x4F881D, H("660fb64da5")),
    (0x4F8957, H("8d4d94")), (0x4F896A, H("6a57682c0a0000")),
    (0x5340B0, H("558bec83ec1c")), (0x5343DA, H("0fb64c1023")), (0x534453, H("895109")), (0x534467, H("034510")),
    (0x532A90, H("558bec817d0847500000")),
]
bad = 0


def ok(cond, msg):
    """Строка проверки; провал считается."""
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def md5(path):
    """md5 файла."""
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def load(path):
    """PE, образ в памяти, база."""
    pe = pefile.PE(path)
    return pe, bytes(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe, base):
    """Границы .text."""
    for s in pe.sections:
        if s.Name.rstrip(b"\0") == b".text":
            return base + s.VirtualAddress, base + s.VirtualAddress + s.Misc_VirtualSize
    return 0, 0


md = Cs(CS_ARCH_X86, CS_MODE_32)
mdk = Cs(CS_ARCH_X86, CS_MODE_32)
mdk.skipdata = True


def insns(img, base, va, end):
    """Линейный дизасм [va, end)."""
    return list(md.disasm(img[va - base:end - base], va))


def func_end(img, base, fva, span=0x2000):
    """Конец функции: первый ret, за которым int3 или пролог `push ebp; mov ebp,esp`."""
    last = fva
    for i in md.disasm(img[fva - base:fva - base + span], fva):
        last = i.address + i.size
        if i.mnemonic == "ret" and (img[last - base] == 0xCC or img[last - base:last - base + 3] == bytes.fromhex("558bec")):
            return last
    return last


def text_of(i):
    """Мнемоника + операнды."""
    return (i.mnemonic + " " + i.op_str).strip()


print("== 1. образы GameServer: площадка, соседи, границы, переходы")
ok(all(stack_layout.EXE_MD5.get(d + r"\GameServer.exe") == LIVE for d in stack_layout.GS_FOLDERS),
   "stack_layout.EXE_MD5: GameServer.exe всех %d папок (%s) = %s" % (len(stack_layout.GS_FOLDERS), ", ".join(stack_layout.GS_FOLDERS), LIVE))
wins = []
live = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if live is None and want == LIVE:
        live = (pe, img, base)
    lo, hi = text_range(pe, base)
    g = lambda va, n: img[va - base:va - base + n]
    ok(g(SITE, len(ORIG)) == ORIG, "%s площадка 0x%06X: %s" % (name, SITE, ORIG.hex()))
    end = func_end(img, base, FN)
    starts = {i.address for i in insns(img, base, FN, end)}
    ok(SITE in starts and BACK in starts and SITE + len(ORIG) == BACK and end == 0x4F89A5,
       "%s: границы инструкций (площадка %d б, продолжение 0x%06X сразу за ней; функция 0x%06X…0x%06X)" % (name, len(ORIG), BACK, FN, end))
    for va, orig in NEIGH:
        ok(g(va, len(orig)) == orig, "%s сосед 0x%06X: %s" % (name, va, orig.hex()))
    t = img[lo - base:hi - base]
    hits = []
    for o in range(len(t) - 6):
        b0 = t[o]
        tgt = None
        if b0 == 0xEB or 0x70 <= b0 <= 0x7F:
            tgt = lo + o + 2 + struct.unpack_from("<b", t, o + 1)[0]
        elif b0 in (0xE8, 0xE9):
            tgt = lo + o + 5 + struct.unpack_from("<i", t, o + 1)[0]
        elif b0 == 0x0F and 0x80 <= t[o + 1] <= 0x8F:
            tgt = lo + o + 6 + struct.unpack_from("<i", t, o + 2)[0]
        if tgt is not None and SITE < tgt < SITE + len(ORIG):
            hits.append((lo + o, tgt))
    real = [(s, d) for s, d in hits if FN <= s < end and s in starts]
    ok(not real, "%s: переходов внутрь площадки нет (кандидатов-байт %d, настоящих инструкций %d)" % (name, len(hits), len(real)))
    wins.append(img[SITE - base - 32:SITE - base + len(ORIG) + 32])
if wins:
    ok(all(w == wins[0] for w in wins), "окна ±32 б вокруг площадки одинаковы на %d образах" % len(wins))

print("== 2. вторым методом (дизасм живого GameServer и DBManager)")
if live:
    pe, img, base = live
    lo, hi = text_range(pe, base)
    allins = list(mdk.disasm(img[lo - base:hi - base], lo))
    def body(fva):
        """Инструкции функции (конец считается один раз)."""
        end = func_end(img, base, fva)
        return [i for i in allins if fva <= i.address < end]
    b = {i.address: i for i in body(FN)}
    ok(text_of(b[0x4F8591]) == "call 0x5340b0" and text_of(b[0x4F8596]) == "mov dword ptr [ebp - 0x228], eax"
       and text_of(b[0x4F859C]) == "cmp dword ptr [ebp - 0x228], 1" and text_of(b[0x4F85A3]) == "je 0x4f8636",
       "11006: площадка — цель `je` после `cmp [ebp-228h],1` за call sub_5340B0 (сюда только при успехе шаблона)")
    jumps = [a for a, i in b.items() if i.mnemonic.startswith("j") and i.op_str == hex(SITE)]
    ok(jumps == [0x4F85A3], "11006: на площадку ведёт ровно один переход: %s" % ", ".join("0x%06X" % a for a in jumps))
    args = [text_of(b[a]) for a in (0x4F8575, 0x4F8577, 0x4F8579, 0x4F857C, 0x4F857D, 0x4F857F, 0x4F8585, 0x4F858B)]
    ok(args == ["push 0", "push 0", "lea ecx, [ebp - 0x5f]", "push ecx", "push 0", "mov edx, dword ptr [ebp - 0x220]", "push edx",
                "mov ecx, dword ptr [ebp - 0x238]"],
       "11006: sub_5340B0(this=[ebp-238h], userNum, код=[ebp-220h], a4 = 0, шаблон=[ebp-5Fh], 0, 0) — %s" % " ; ".join(args))
    l = [text_of(i) for i in body(FN) if 0x4F8950 <= i.address < 0x4F897B]
    ok("lea ecx, [ebp - 0x6c]" in l and "push 0x57" in l and "push 0xa2c" in l and "call 0x5646c0" in l,
       "11006: DB 2604 (87 б) из тела [ebp-6Ch]; шаблон [ebp-5Fh] = тело +13 (0x6C − 0x5F = %d)" % (0x6C - 0x5F))
    l = [text_of(i) for i in body(FN) if 0x4F87DD < i.address < 0x4F8840]
    ok("movzx edx, byte ptr [ebp - 0x21c]" in l and "movzx cx, byte ptr [ebp - 0x5b]" in l and "call 0x4d6740" in l,
       "11006: Count = [ebp-21Ch], ячейки sub_4D6740 в контейнере шаблона [ebp-5Bh] (= шаблон +4)")
    s = {i.address: text_of(i) for i in body(0x5340B0)}
    ok(s.get(0x5343DA) == "movzx ecx, byte ptr [eax + edx + 0x23]" and s.get(0x5343F9) == "call 0x4d6ce0"
       and s.get(0x534453) == "mov dword ptr [ecx + 9], edx" and s.get(0x534467) == "add eax, dword ptr [ebp + 0x10]"
       and s.get(0x53446D) == "mov dword ptr [ecx + 9], eax" and s.get(0x534486) == "imul ecx, dword ptr [ebp + 0x10]"
       and s.get(0x53443B) == "mov dword ptr [ebp - 8], 0",
       "sub_5340B0 ветка «стопка»: +35 → sub_4D6CE0; Amount = стопка или 0 (0x53443B); +9 += a4; вес += a4·штука")
    r = [i for i in body(0x4F89D0)]
    rt = [text_of(i) for i in r]
    ok("mov ecx, 0xe" in rt and "lea esi, [ebp - 0x1ff]" in rt and "rep movsd dword ptr es:[edi], dword ptr [esi]" in rt
       and "movsx ecx, word ptr [ebp + eax - 0x1a1]" in rt and "call 0x4d63f0" in rt and "call 0x43f880" in rt,
       "ответ sub_4F89D0: шаблон тела ответа (+13, 0x38 б) → каждая ячейка (sub_4D63F0), вес — сумма записей +14 (sub_43F880)")
    calls = [i.address for i in allins if i.mnemonic == "call" and i.op_str == hex(FN)]
    ok(len(calls) == 1, "обработчик 11006 0x%06X зовётся из одного места: %s" % (FN, ", ".join("0x%06X" % a for a in calls)))
if os.path.exists(DBM):
    pe, img, base = load(DBM)
    l = [text_of(i) for i in insns(img, base, 0x43F3E0, func_end(img, base, 0x43F3E0, 0x800))]
    ok("mov eax, dword ptr [ebp - 0x3b06]" in l and "movsx edx, word ptr [ebp - 0x3b01]" in l and "push 0xa2c" in l
       and "push 0x57" in l and "lea eax, [ebp - 0x3b1c]" in l,
       "DBManager %s sub_43F3E0: тело [ebp-3B1Ch]; @Amount = +22 ([ebp-3B06h] = шаблон +9), @Weight = +27 ([ebp-3B01h] = шаблон +14); эхо 2604 87 б"
       % md5(DBM)[:8])
else:
    ok(False, "нет DBManager.exe в зеркале (%s)" % DBM)

print("== 3. DLL, реестр, конфиг, P16, чужие площадки")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx):
        """Адрес символа p98_premium_stack_amount.obj по .map."""
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p98_premium_stack_amount\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    fns = {"OnPremium": sym(r"_P98_OnPremium@4"), "GetStats": sym(r"_P98_GetStats@4"), "Fix": sym(r"_P98_FixPremiumRecord@20")}
    ok(all(fns.values()), "P98_OnPremium / P98_GetStats / P98_FixPremiumRecord (__stdcall): %s" % {k: "%08X" % v for k, v in fns.items()})
    exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else set()
    ok(any("P98_GetStats" in e for e in exp) and any("P98_FixPremiumRecord" in e for e in exp), "экспорты DLL: P98_GetStats, P98_FixPremiumRecord")
    va = sym(r"\?St_Premium@\S+")
    ok(va != 0, "стаб St_Premium @%08X" % va)
    if va:
        c = [text_of(i) for i in md.disasm(img[va - base:va - base + 48], va)]
        print("    St_Premium: %s" % " ; ".join(c[:8]))
        m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]", c[7]) if len(c) > 7 else None
        back = struct.unpack_from("<I", img, int(m.group(1), 16) - base)[0] if m else None
        ok(c[:7] == ["pushfd", "pushal", "push ebp", "call 0x%x" % fns["OnPremium"], "popal", "popfd", "mov ecx, dword ptr [ebp - 0x220]"]
           and back == BACK, "St_Premium: pushfd/pushad, P98_OnPremium(ebp), popad/popfd, замещённое `mov ecx,[ebp-220h]`, jmp 0x%06X" % BACK)
    p16 = open(os.path.join(SRC, "patches", "p16_gacha_prize_to_inven.cpp"), encoding="utf-8").read()
    i1 = p16.find("SrvBuildItemRec(mgr, (__int16)userNum, itemCode, 0, req.rec, 0, 0)")
    i2 = p16.find("P98_FixPremiumRecord(mgr, userNum, itemCode, req.rec, count);")
    i3 = p16.find("memcpy(body6578 + 1, req.rec, sizeof(req.rec));")
    ok(0 < i1 < i2 < i3, "P16: P98_FixPremiumRecord сразу после своего sub_5340B0 и до копии шаблона в 6578 / отправки 2604")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8").read()
    ok(0 < reg.find('{ L"P97_WeightU16"') < reg.find('{ L"P98_PremiumStackAmount"'), "реестр: P98_PremiumStackAmount после P97")
    cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8").read()
    ok(all(k in cfg for k in ('{ L"P98_PremiumStackAmount"', "kPremiumStackAmount, ARRAYSIZE(kPremiumStackAmount)",
                              'L"JournalIntervalSec", L"10"', 'L"LogChannel", L"38"')), "Config.cpp: секция [P98_PremiumStackAmount] и умолчания")
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8").read()
    ok(all(("case %d: return L\"P98:" % k) in acj for k in range(150, 153)), "AcJournal: тексты ac.other 150–152")
    ok(not any(("case %d:" % k) in acj.replace("case %d: return L\"P98:" % k, "") for k in range(148, 153)), "AcJournal: виды 148–152 заняты только P98 (150–152)")
    ok("P98_PremiumStackAmount".encode("utf-16-le").decode("latin-1") in img.decode("latin-1"), "DLL: имя секции в образе")
    # чужие патчи: адреса в 11006 (0x4F8340…0x4F89B0) и в sub_5340B0 — только ссылки в комментариях (P16), не площадки P98
    others, seen = [], []
    pdir = os.path.join(SRC, "patches")
    # площадка + соседи ВНУТРИ 11006; прологи/ветка общих функций (sub_5340B0, sub_532A90) другие патчи только зовут или сверяют —
    #   их запись ловит общий прогон стендов (P98 сверяет байты сам при установке). P16 ссылается на строки 11006 в шапке-разборе
    #   (комментарии): его единственная площадка — 0x4F7E40 (Srv::Hooks::kGachaPrizeToInven, другая функция).
    span = [(SITE, SITE + len(ORIG))] + [(a, a + len(o)) for a, o in NEIGH if 0x4F8340 <= a < 0x4F89B0]
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or fn.startswith("p98_") or fn == "Registry.cpp":
            continue
        txt = open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", txt):
            v = int(m.group(1), 16)
            if 0x4F8340 <= v < 0x4F89B0 or 0x5340B0 <= v < 0x534640:
                seen.append("%s:0x%06X" % (fn.split("_")[0], v))
            # ★ P100 (01.11.2026) только СВЕРЯЕТ байт 0x4F8802 (чтение Count в 11006) как соседа своей площадки 0x4F882E — не пишет.
            if any(a <= v < b for a, b in span) and not fn.startswith("p16_") and not (fn.startswith("p100_") and v == 0x4F8802):
                others.append("%s:0x%06X" % (fn, v))
    ok(not others, "чужие площадки не задевают площадку и соседей P98%s" % (": " + ", ".join(others) if others else ""))
    sh = open(os.path.join(SRC, "SrvApi.h"), encoding="utf-8").read()
    p16sites = re.findall(r"Hook::WriteJmp\(([^,]+),", p16)
    ok("kGachaPrizeToInven = 0x004F7E40" in sh and p16sites == ["Srv::Hooks::kGachaPrizeToInven"],
       "P16: единственная площадка — 0x4F7E40 (RecvDB_InsertPremiumItem), адреса 11006 у него — только разбор в комментариях")
    print("    чужие адреса в 11006 / sub_5340B0 (комментарии и вызовы): %s" % ", ".join(sorted(set(seen))))

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
    cont2 = lambda r: not (r[36] == 3 or r[26] in (0, 1, 2, 3, 4, 8, 9, 12, 13, 14, 15))   # sub_5340B0: контейнер 2
    fix = lambda r: cont2(r) and r[35] != 0 and r[26] != 10                                 # правило P98
    for c in (75521, 20936, 20946, 20952, 23229):
        r = it[c]
        ok(fix(r), "%d: контейнер 2, +35 = %d, тип %d/%d, вес штуки %d — P98 чинит" % (c, r[35], r[26], r[27], r[5]))
    print("    масштаб: стопочных кодов ветки «расходник» %d; колчанов/наживки (тип 10, стопочные — не трогаем) %d; "
          "нестопочных контейнера 2 %d" % (sum(1 for r in it.values() if fix(r)), sum(1 for r in it.values() if cont2(r) and r[35] and r[26] == 10),
                                          sum(1 for r in it.values() if cont2(r) and not r[35])))
    pst = os.path.join(TABLES, "PrimiumSumTable.txt")
    if os.path.exists(pst):
        codes = set()
        for ln in open(pst, encoding="latin-1").read().split("\n")[1:]:
            p = ln.split()
            if len(p) >= 16:
                codes |= {int(p[2 + 2 * i]) for i in range(7)}
        ok(not [c for c in codes if c in it and fix(it[c])], "PrimiumSumTable: награды (%d кодов) нестопочные — Recv_UserPrimiumSum (a4 = 0) дефекта не даёт" % len(codes))
    else:
        print("    (PrimiumSumTable.txt нет в зеркале — сверено вручную 30.10: 26 кодов наград, стопочных 0)")
except Exception as e:
    ok(False, "таблицы стойки: %s" % e)

print("== ИТОГ verify_p98: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
