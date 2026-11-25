# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_n22.py — СТАТИЧЕСКАЯ проверка N22 (31.10.2026, bug-quest-follow): ячейки NPC сверх 10 из Quest\QuestNpcTableExt.Bin.
#   Сервер НЕ запускается, образы только читаются. Описание — Reports/bug_quest_follow/N22_PATCH_DESIGN.md.
#   1. Пять образов NpcServer (как у verify_n21): байты 4 площадок (0x420CB9, 0x420D3A, 0x4210AD, 0x42112E); инструкции
#      начинаются ровно на площадках и после них (линейный проход от начала sub_420C10 / sub_421020); сплошной перебор
#      rel8/rel32/jcc32 по .text — входов внутрь изменяемых байтов нет; окна ±32 б одинаковы на всех образах; ссылок на
#      указатель таблицы 0x47DAE4 ровно 8 (загрузчик ×2, обнуление ×2, деструктор ×2, Process_Quest, Start_Quest).
#   2. Кадр: [esp+28h]/[esp+2Ah] (Process_Quest) и [esp+24h]/[esp+26h] (Start_Quest) — первый dword пакета (npc | слот);
#      копия записи — esp+128h / esp+120h; сразу за площадками исходный код сам задаёт ecx, edi, затем eax/edx (их значения
#      до площадки не читаются).
#   3. DLL (по .map): площадки TakeCellEsi/GiveCellEsi — слот ≤ 9 как оригинал (+4 на адрес возврата), ≥ 10 — N22CellExt;
#      реестр — N22 после N21; Config Version = 13 и секция [N22_QuestCellsExt].
#   4. Таблица расширения данных выкладки (tools/data_quest_turnin/QuestNpcTableExt.Bin) — формат, как его проверит DLL.
# Запуск: py -3 verify_n22.py [AddonNPC.dll]
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
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src")
sys.path.append(os.path.join(HERE, "..", "..", "AsdaPatch", "tools"))
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe", "16c7a0aff498a9f739899d9a2cba9a5b"),
    ("IDB NpcServer", r"@@ASTORY_DEV_ROOT@@\RE\ida\npc_work\NpcServer.exe", "d292e4ec4edfd5040d8fb39382664eab"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe", "c02486d62e803e98eb6fb4fa98d1fcd6"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe", "0de2c55932c2966537e2a8c539decdcd"),
    ("живой Ch2 NpcServer", V2 + "Ch2_NpcServer/NpcServer.exe", "7f79b5daf74c7754d622853cb1335718"),
]
PQ, SQ = 0x420C10, 0x421020          # Process_Quest, Start_Quest
# (имя, VA, байты стока, начало функции, диапазон изменяемых байтов [от, до))
SITES = [
    ("A Process_Quest предел слота", 0x420CB9, bytes.fromhex("66837C242A09"), PQ, (0x420CBE, 0x420CBF)),
    ("B Process_Quest адрес ячейки", 0x420D3A, bytes.fromhex("0FBF74242A6BF6588DB434A6040000"), PQ, (0x420D3A, 0x420D49)),
    ("C Start_Quest предел слота", 0x4210AD, bytes.fromhex("66837C242609"), SQ, (0x4210B2, 0x4210B3)),
    ("D Start_Quest адрес ячейки", 0x42112E, bytes.fromhex("0FBF7424266BF6568DB43442010000"), SQ, (0x42112E, 0x42113D)),
]
TABLE_REFS = {0x41F4C3, 0x41F4F3, 0x420B71, 0x420B9C, 0x420CE1, 0x4210D5, 0x421460, 0x4214C7}
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


def insns(img, base, va, end):
    return list(md.disasm(img[va - base:end - base], va))


def seq(img, base, va, n):
    return [(i.mnemonic + " " + i.op_str).strip() for i in insns(img, base, va, va + 8 * n)][:n]


print("== 1. образы NpcServer")
windows = []
first = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s (зеркало: python srv_mirror.py)" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if first is None or "IDB" in name:
        first = (pe, img, base)
    lo, hi = text_range(pe, base)
    win = b""
    for sname, va, stock, fn, _ in SITES:
        ok(img[va - base:va - base + len(stock)] == stock, "%s %s @0x%06X: %s" % (name, sname, va, stock.hex(" ").upper()))
        starts = [i.address for i in insns(img, base, fn, va + len(stock) + 16)]
        ok(va in starts and va + len(stock) in starts,
           "%s %s: границы инструкций 0x%06X → 0x%06X (линейный проход от 0x%06X)" % (name, sname, va, va + len(stock), fn))
        win += img[va - base - 32:va - base + len(stock) + 32]
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
        if tgt is not None and any(a <= tgt < b for _, _, _, _, (a, b) in SITES):
            hits.append((lo + o, tgt))
    fn_ins = set(i.address for i in insns(img, base, PQ, 0x421020)) | set(i.address for i in insns(img, base, SQ, 0x421360))
    real = [h for h in hits if h[0] in fn_ins]
    ok(not real, "%s: переходов внутрь изменяемых байтов нет (сплошной перебор .text: кандидатов %d, на границах инструкций функций %d)"
       % (name, len(hits), len(real)))
    refs = set()
    for m in re.finditer(re.escape(struct.pack("<I", 0x47DAE4)), t):
        refs.add(lo + m.start())
    ok({r for r in TABLE_REFS} == {r for r in refs},
       "%s: ссылок на указатель таблицы 0x47DAE4 — %d (%s)" % (name, len(refs), ", ".join("0x%06X" % r for r in sorted(refs))))
    windows.append((name, win))
if len(windows) == len(IMAGES):
    ok(all(w == windows[0][1] for _, w in windows), "окна ±32 б вокруг 4 площадок побайтово одинаковы на %d образах" % len(windows))

print("== 2. кадр")
if first:
    pe, img, base = first
    T = lambda va, n=1: seq(img, base, va, n)
    ok(T(0x420C4E, 2) == ["mov ecx, dword ptr [eax]", "mov dword ptr [esp + 0x28], ecx"],
       "Process_Quest: [esp+28h] = первый dword пакета (npc i16 | слот i16 → [esp+2Ah])")
    ok(T(0x420CE5, 2) == ["mov ecx, 0x1bb", "lea edi, [esp + 0x128]"], "Process_Quest: копия записи — esp+128h (+894 = 4A6h)")
    ok(T(0x420D49, 5) == ["mov ecx, 0x16", "lea edi, [esp + 0x38]", "rep movsd dword ptr es:[edi], dword ptr [esi]",
                          "mov eax, dword ptr [esp + 0x7c]", "test eax, eax"]
       and T(0x420D5A) == ["mov edx, dword ptr [esp + 0x7a]"],
       "Process_Quest за площадкой: ecx/edi задаются, копия 22 dword, затем eax/edx загружаются заново")
    ok(T(0x421057, 2) == ["mov ecx, dword ptr [eax]", "mov dword ptr [esp + 0x24], ecx"],
       "Start_Quest: [esp+24h] = первый dword пакета (npc | слот → [esp+26h])")
    ok(T(0x4210D9, 2) == ["mov ecx, 0x1bb", "lea edi, [esp + 0x120]"], "Start_Quest: копия записи — esp+120h (+34 = 142h)")
    ok(T(0x42113D, 5) == ["mov ecx, 0x15", "lea edi, [esp + 0x30]", "rep movsd dword ptr es:[edi], dword ptr [esi]",
                          "movsw word ptr es:[edi], word ptr [esi]", "mov ebx, dword ptr [esp + 0x30]"]
       and T(0x421151) == ["mov eax, dword ptr [esp + 0x72]"] and T(0x42115B) == ["lea edx, [esp + 0x32]"],
       "Start_Quest за площадкой: ecx/edi задаются, копия 86 б, затем eax/edx загружаются заново")

print("== 2б. регистры за площадками: все пути от площадки, разбор чтения/записи capstone")
# Площадка портит eax/ecx/edx и арифметические флаги (esi — её выход; путь слота ≤ 9 портит только ecx и флаги). Доказываем:
#   на КАЖДОМ пути от конца площадки (обе ветки условных переходов, до 80 инструкций) каждый из eax/ecx/edx/флагов
#   ЗАПИСЫВАЕТСЯ раньше, чем читается; `call` считается чтением ecx/edx (thiscall/fastcall), `ret` — чтением eax.
#   Флаг направления DF (его читают `rep movs`/`movs`) площадка не меняет — проверяется по её коду в разделе 3 (нет
#   std/cld/popfd/sahf). Печатаются первые 24 инструкции линейного кода.
if first:
    from capstone import x86_const as X
    pe, img, base = first
    mdd = Cs(CS_ARCH_X86, CS_MODE_32)
    mdd.detail = True
    FAM = {"eax": {"eax", "ax", "al", "ah"}, "ecx": {"ecx", "cx", "cl", "ch"}, "edx": {"edx", "dx", "dl", "dh"}}
    ARITH = {X.X86_EFLAGS_MODIFY_CF, X.X86_EFLAGS_MODIFY_ZF, X.X86_EFLAGS_MODIFY_SF, X.X86_EFLAGS_MODIFY_OF}
    TEST = X.X86_EFLAGS_TEST_CF | X.X86_EFLAGS_TEST_ZF | X.X86_EFLAGS_TEST_SF | X.X86_EFLAGS_TEST_OF | X.X86_EFLAGS_TEST_PF

    def one(va):
        return next(mdd.disasm(img[va - base:va - base + 16], va))

    def walk(start):
        """Обход путей: возвращает (проблемы, число путей, число инструкций)."""
        problems, paths, seen, count = [], 0, set(), 0
        stack = [(start, frozenset(["eax", "ecx", "edx", "flags"]), 0)]
        while stack:
            va, dirty, n = stack.pop()
            while dirty and n < 80:
                key = (va, dirty)
                if key in seen:
                    break
                seen.add(key)
                i = one(va)
                count += 1
                n += 1
                r, w = i.regs_access()
                rn = {i.reg_name(x) for x in r}
                wn = {i.reg_name(x) for x in w}
                ef = i.eflags
                reads_flags = bool(ef & TEST)
                writes_flags = any(ef & m for m in ARITH)
                if i.group(X.X86_GRP_CALL):
                    rn |= {"ecx", "edx"}
                if i.group(X.X86_GRP_RET):
                    rn |= {"eax"}
                for k in list(dirty):
                    names = FAM.get(k, set())
                    if (k == "flags" and reads_flags) or (rn & names):
                        problems.append("0x%06X %s %s читает %s до записи" % (i.address, i.mnemonic, i.op_str, k))
                d = set(dirty)
                for k in list(d):
                    if (k == "flags" and writes_flags) or (wn & FAM.get(k, set())):
                        d.discard(k)
                dirty = frozenset(d)
                if i.group(X.X86_GRP_RET):
                    break
                if i.group(X.X86_GRP_JUMP):
                    tgt = int(i.op_str, 16) if i.op_str.startswith("0x") else None
                    if tgt is None:
                        problems.append("0x%06X косвенный переход при незаписанных %s" % (i.address, sorted(dirty)))
                        break
                    if i.mnemonic == "jmp":
                        va = tgt
                        continue
                    stack.append((tgt, dirty, n))
                va = i.address + i.size
            if dirty and n >= 80:
                problems.append("путь от 0x%06X: за 80 инструкций не записаны %s" % (start, sorted(dirty)))
            paths += 1
        return problems, paths, count

    for sname, va, stock, fn, _ in SITES:
        if "адрес ячейки" not in sname:
            continue
        after = va + len(stock)
        lst = list(mdd.disasm(img[after - base:after - base + 160], after))[:24]
        print("    за %s:\n      %s" % (sname, "\n      ".join("0x%06X %s %s" % (i.address, i.mnemonic, i.op_str) for i in lst)))
        problems, paths, count = walk(after)
        ok(len(lst) >= 20 and not problems,
           "%s: на всех %d путях (%d инструкций) eax/ecx/edx/арифм. флаги записываются до чтения%s"
           % (sname, paths, count, ("; " + "; ".join(problems[:6])) if problems else ""))

print("== 3. DLL: площадки, реестр, конфиг")
if not os.path.exists(DLL) or not os.path.exists(MAP):
    ok(False, "нет %s / .map — сначала build.bat" % DLL)
else:
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)

    def sym(rx, obj):
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+%s\.obj\s*$" % (rx, obj), mp, re.M)
        return int(m.group(2), 16) if m else 0

    ext = sym(r"\?N22CellExt@\S+", "n22_quest_cells_ext")
    ok(ext != 0, "N22CellExt @%08X" % ext)
    for nm, slot, npc, mul, off, kind in (("TakeCellEsi", 0x2E, 0x2C, 0x58, 0x4AA, 1), ("GiveCellEsi", 0x2A, 0x28, 0x56, 0x146, 0)):
        va = sym(r"\?%s@\S+" % nm, "n22_quest_cells_ext")
        ok(va != 0, "%s @%08X" % (nm, va))
        if not va:
            continue
        c = seq(img, base, va, 14)
        print("    %s: %s" % (nm, " ; ".join(c)))
        ok(c[0] == "movsx ecx, word ptr [esp + 0x%x]" % slot and c[1] == "cmp ecx, 9" and c[2].startswith("ja ")
           and c[3] == "imul ecx, ecx, 0x%x" % mul and c[4] == "lea esi, [esp + ecx + 0x%x]" % off and c[5] == "ret",
           "%s: слот [esp+%Xh] (+4), ≤ 9 — esi = копия записи + %Xh + %Xh·слот, ret" % (nm, slot, off, mul))
        ok(not any(x.split()[0] in ("std", "cld", "popfd", "popf", "sahf") for x in c),
           "%s: флаг направления DF не меняется (нет std/cld/popfd/sahf) — `rep movs` за площадкой копирует как в стоке" % nm)
        ok(c[6] == "movsx eax, word ptr [esp + 0x%x]" % npc and c[7:10] == ["push ecx", "push eax", "push %d" % kind]
           and c[10] == "call 0x%x" % ext and c[11:14] == ["add esp, 0xc", "mov esi, eax", "ret"],
           "%s: ≥ 10 — N22CellExt(вид %d, npc [esp+%Xh], слот), esi = результат, ret" % (nm, kind, npc))
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    order = [m.group(1) for m in re.finditer(r'\{ L"(\w+)",', reg)]
    # ★ 04.11.2026 (N23, слот P104): N22 — сразу после N21 (последним уже не обязан: следом идёт N23).
    i22 = order.index("N22_QuestCellsExt") if "N22_QuestCellsExt" in order else -1
    ok(i22 > 0 and order[i22 - 1] == "N21_RespawnFreeTile",
       "реестр: N22 сразу после N21 (%s)" % ", ".join(order[max(0, i22 - 1):i22 + 2]))
    cfg = open(os.path.join(SRC, "Config.h"), encoding="utf-8-sig").read()
    mv = re.search(r"constexpr int kVersion = (\d+);", cfg)
    ok(mv is not None and int(mv.group(1)) >= 13, "Config.h: kVersion ≥ 13 (N22 — с версии 13; сейчас %s)" % (mv.group(1) if mv else "?"))
    cpp = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8-sig").read()
    mc = re.search(r'\{ L"Version", L"(\d+)",', cpp)
    ok(mc is not None and int(mc.group(1)) >= 13 and 'L"N22_QuestCellsExt",' in cpp, "Config.cpp: Version ≥ 13, секция N22")

print("== 4. таблица расширения выкладки")
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "AsdaReborn", "Tools"))
import asda_quest_cells_ext as QX
xp = os.path.join(HERE, "..", "..", "AsdaPatch", "tools", "data_quest_turnin", QX.FILE_NAME)
if not os.path.exists(xp):
    ok(False, "нет %s (asda_quest_turnin_restore.py)" % xp)
else:
    try:
        rows = QX.parse(open(xp, "rb").read())
        ok(True, "%s: формат верен, ячеек %d %s" % (QX.FILE_NAME, len(rows),
                                                     [(r["npc"], r["kind"], r["slot"], QX.cell_quest(r)) for r in rows]))
    except ValueError as e:
        ok(False, "%s: %s" % (QX.FILE_NAME, e))

print("== ИТОГ verify_n22: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
