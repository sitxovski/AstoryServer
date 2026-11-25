# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p87.py — СТАТИЧЕСКАЯ проверка P87 (стартовые навыки 4-й профессии по подклассу, 2026-10-26): AsdaPatch P87_Job4StartSkills.
#
# Сервер НЕ запускается. Проверяем по образам (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и собранной DLL:
#  1) площадка 0x4820C9 = movzx eax, byte ptr [edx+190h] (7 б) и соседи (0x4820C6 mov edx,[ebp-0Ch]; 0x4820D0 sub eax,1 …
#     call sub_48A8C0 @0x4820E2) — одинаковы в трёх образах; тела sub_481CE0 (0x481CE0…0x4820EC + таблицы switch) и
#     sub_48A8C0 (0x48A8C0…0x48AF80) побайтно одинаковы в трёх образах;
#  2) площадка на границах инструкций (линейный проход sub_481CE0); 0x4820C6 — цель переходов LABEL_99 (их 24), ни один
#     rel8/rel32/jcc и ни один abs32 .text не ведёт ВНУТРЬ (0x4820C9, 0x4820D0) и ровно на 0x4820C9;
#  3) поток: sub_481CE0 зовут ровно 3 места (2 награды квеста, изучение навыка); switch по CUser+0x191 (movzx ecx,[eax+191h]),
#     категории CUser+0xC024+4·кат; sub_48A8C0 — звание по arg4+1 == 3/0xE/0x19 → 0x18/0x19/0x1A и call 0x54A050 с
#     ecx = [[this+4]+34h]; таблица строк — word [arg4*8+0x600B60] / dword [arg4*8+0x600B64]; загрузчик 0x4B2E63 cmp 0x27 (id ≤ 39);
#  4) данные стойки (зеркало): ChangeJobAddSkillTable GameServer = Indun = сток; строки 4/15/26 — по 5 навыков, строк 6/17/28 нет;
#     навыки строк 4/15/26 — категории 10/11/12, требование очков 0, без предшественников (SkillInfo.sif, запись 209 б);
#  5) DLL: MAP — P87_Job4StartSkills, P87_PickRow, P87_GetStats, трамплин; трамплин начинается стоковой movzx, pushfd/pushad,
#     call P87_PickRow, mov [esp+0x1C],eax, popad/popfd и выходит ТОЛЬКО jmp [g_pRet], g_pRet = 0x4820D0; экспорт P87_GetStats;
#     строка секции P87_Job4StartSkills; Config.cpp — секция, AcJournal.cpp — виды 106/107/108 (ac.other);
#  6) другие патчи src/patches не трогают адреса sub_481CE0 / sub_48A8C0 (текстовый поиск).
# Поведение — стенд tools/stand_p87 (подклассы 4/15/26/6/17/28/0, Enabled=0, Mismatch, журнал).
# Запуск: python verify_p87.py [AsdaPatch.dll]
import hashlib
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
SRC = os.path.join(HERE, "..", "src")
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P87_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]
# ★ 04.11.2026: + Ch2_GameServer (канал 2, с 26.10 — та же таблица)
TABLES = [("GameServer", V2 + "GameServer/SkillTable_Info/"), ("Indun", V2 + "Indun_GameServer/SkillTable_Info/"),
          ("Ch2", V2 + "Ch2_GameServer/SkillTable_Info/")]
# ★ 04.11.2026: решение владельца 26.10 (deploy_p89_job4rows.py, AstoryServer/Docs/job4_start_skills_1026): к стоку дописаны строки
#   6/17/28 с навыками строк 4/15/26; живая таблица = одобренный файл staging (md5 8fa64c23), прежние 12 строк — байт в байт сток.
JOB4_ADDED = {6: 4, 17: 15, 28: 26}   # строка → строка-образец (те же навыки)
APPROVED_TABLE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), r"..\..\..\Docs\job4_start_skills_1026\GameServer\SkillTable_Info\ChangeJobAddSkillTable.txt"))
STOCK_TABLE = r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\SkillTable_Info\ChangeJobAddSkillTable.txt"

SITE, SITE_LEN, SITE_ORIG = 0x004820C9, 7, bytes.fromhex("0fb68290010000")
PRE, PRE_ORIG = 0x004820C6, bytes.fromhex("8b55f4")
POST, POST_ORIG = 0x004820D0, bytes.fromhex("83e80150668b4d08518b55f08b42048b482ce8d9870000")
TITLE, TITLE_ORIG = 0x0048A9A3, bytes.fromhex(
    "0fb6550c83c2018995ecf7ffff83bdecf7ffff03741483bdecf7ffff0e741683bdecf7ffff197418eb1f"
    "66c78574ffffff1800eb1466c78574ffffff1900eb0966c78574ffffff1a000fbf8574ffffff85c07422"
    "6a006a00668b8d74ffffff51668b5508528b85f0f7ffff8b48048b4934e837f60b00")
COUNT, COUNT_ORIG = 0x0048AA3B, bytes.fromhex("0fb6450c0fbf0cc5600b6000")
CODES, CODES_ORIG = 0x0048AA53, bytes.fromhex("0fb6550c8b04d5640b6000")
F481 = (0x00481CE0, 0x0048212C)     # тело sub_481CE0 с таблицами switch jpt_481D49 / byte_48210C
F48A = (0x0048A8C0, 0x0048AF80)     # тело sub_48A8C0
RET = 0x004820D0
WANT_ROWS = {4: [617, 619, 632, 633, 634], 15: [826, 828, 841, 842, 843], 26: [1050, 1051, 1062, 1065, 1066]}
WANT_CAT = {4: 10, 15: 11, 26: 12}
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe, base):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return base + t.VirtualAddress, base + t.VirtualAddress + t.Misc_VirtualSize


def disasm(img, base, lo, hi):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    return list(md.disasm(bytes(img[lo - base:hi - base]), lo))


def refs(img, base, lo, hi, a, b):
    """Переходы rel8/rel32/jcc/call и abs32 на адреса [a, b) — список (источник, цель)."""
    out = []
    for ins in disasm(img, base, lo, hi):
        if ins.mnemonic.startswith("j") or ins.mnemonic == "call":
            m = re.match(r"0x([0-9a-f]+)$", ins.op_str)
            if m and a <= int(m.group(1), 16) < b:
                out.append((ins.address, int(m.group(1), 16)))
    data = bytes(img[lo - base:hi - base])
    for k in range(0, len(data) - 3):
        v = struct.unpack_from("<I", data, k)[0]
        if a <= v < b:
            out.append((lo + k, v))
    return out


def read_table(path):
    """ChangeJobAddSkillTable.txt как загрузчик 0x4B2Dxx: id число коды…  → {id: [коды]}."""
    toks = open(path, encoding="latin-1").read().split()
    rows, i = {}, 0
    while i < len(toks):
        rid, n = int(toks[i]), int(toks[i + 1])
        rows[rid] = [int(x) for x in toks[i + 2:i + 2 + n]]
        i += 2 + n
    return rows


def main():
    print("== verify_p87 ==")
    bodies = {}
    for name, path in GS_IMAGES:
        if not os.path.exists(path):
            ok(False, "%s: образа нет (%s)" % (name, path))
            continue
        pe, img, base = load(path)
        lo, hi = text_range(pe, base)
        g = lambda va, n: bytes(img[va - base:va - base + n])
        ok(g(SITE, SITE_LEN) == SITE_ORIG, "%s: площадка 0x%08X = %s (movzx eax, byte ptr [edx+190h])" % (name, SITE, g(SITE, SITE_LEN).hex()))
        ok(g(PRE, 3) == PRE_ORIG and g(POST, len(POST_ORIG)) == POST_ORIG,
           "%s: соседи — 0x4820C6 mov edx,[ebp-0Ch]; 0x4820D0 sub eax,1 / push / … / call sub_48A8C0 (0x4820E2)" % name)
        ok(g(TITLE, len(TITLE_ORIG)) == TITLE_ORIG, "%s: sub_48A8C0 0x48A9A3 — звание arg4+1 3/0xE/0x19 → 24/25/26, call 0x54A050" % name)
        ok(g(COUNT, len(COUNT_ORIG)) == COUNT_ORIG and g(CODES, len(CODES_ORIG)) == CODES_ORIG,
           "%s: sub_48A8C0 — число строки word [arg4*8+0x600B60], коды dword [arg4*8+0x600B64]" % name)
        bodies.setdefault("481", []).append(hashlib.md5(g(F481[0], F481[1] - F481[0])).hexdigest())
        bodies.setdefault("48A", []).append(hashlib.md5(g(F48A[0], F48A[1] - F48A[0])).hexdigest())
        # границы инструкций: линейный проход тела sub_481CE0 до эпилога
        ins = disasm(img, base, F481[0], 0x004820EC)
        starts = {i.address for i in ins}
        txt = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
        ok(SITE in starts and RET in starts and PRE in starts and 0x004820E2 in starts and 0x004820E7 in starts,
           "%s: площадка на границах инструкций (0x4820C6 / 0x4820C9 / возврат 0x4820D0 / call 0x4820E2 / эпилог 0x4820E7)" % name)
        ok(txt.get(0x00481D22) == "movzx ecx, byte ptr [eax + 0x191]" and txt.get(0x004820E2) == "call 0x48a8c0"
           and txt.get(0x004820DF) == "mov ecx, dword ptr [eax + 0x2c]",
           "%s: switch по подклассу CUser+0x191 (0x481D22), LABEL_99 зовёт sub_48A8C0 со строкой CUser+0x190" % name)
        cats = [i for i in ins if "+ 0xc024]" in i.op_str]
        ok(len(cats) == 6, "%s: категории CUser+0xC024+4·кат в 6 ветках подклассов 4/6/15/17/26/28 (%d)" % (name, len(cats)))
        r = refs(img, base, lo, hi, SITE, RET)
        ok(not r, "%s: переходов/abs32 на [0x4820C9, 0x4820D0) нет (%s)" % (name, ", ".join("0x%08X→0x%08X" % x for x in r[:5]) or "—"))
        to_pre = [x for x in refs(img, base, F481[0], 0x004820EC, PRE, PRE + 1) if x[0] < PRE]
        ok(len(to_pre) == 24, "%s: на 0x4820C6 (LABEL_99) ведут %d переходов sub_481CE0 (ждём 24)" % (name, len(to_pre)))
        allins = disasm(img, base, lo, hi)
        callers = [i.address for i in allins if i.mnemonic == "call" and i.op_str == "0x481ce0"]
        ok(callers == [0x0045D533, 0x0045DE95, 0x0047EDD0],
           "%s: sub_481CE0 зовут 3 места (награда квеста ×2, изучение навыка): %s" % (name, ", ".join("0x%08X" % c for c in callers)))
        ld = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in disasm(img, base, 0x004B2E5D, 0x004B2EA0)}
        ok(ld.get(0x004B2E63) == "cmp dword ptr [ebp - 0x64], 0x27" and ld.get(0x004B2E85) == "sub eax, 1"
           and ld.get(0x004B2E92) == "mov word ptr [ecx*8 + 0x600b60], dx",
           "%s: загрузчик ChangeJobAddSkillTable — id 1…39 (cmp 0x27), запись id−1 по 8 б @0x600B60" % name)
        ok(g(0x0054A050, 3) == bytes.fromhex("558bec"), "%s: sub_54A050 — пролог push ebp / mov ebp,esp" % name)
    for k, v in bodies.items():
        ok(len(v) == 3 and len(set(v)) == 1, "тело %s одинаково в трёх образах (%s)" % ({"481": "sub_481CE0", "48A": "sub_48A8C0"}[k], ", ".join(x[:8] for x in v)))

    # ── данные стойки ──
    stock = read_table(STOCK_TABLE) if os.path.exists(STOCK_TABLE) else None
    ok(stock is not None, "сток ChangeJobAddSkillTable: %s" % STOCK_TABLE)
    for name, d in TABLES:
        p = d + "ChangeJobAddSkillTable.txt"
        if not os.path.exists(p):
            ok(False, "%s: нет %s (srv_mirror.py)" % (name, p))
            continue
        rows = read_table(p)
        want = dict(stock or {})
        want.update({s: WANT_ROWS[src] for s, src in JOB4_ADDED.items()})
        ok(stock is not None and not any(s in stock for s in JOB4_ADDED) and rows == want,
           "%s: ChangeJobAddSkillTable = сток + строки 6/17/28 (решение 26.10) (%d строк: %s)" % (name, len(rows), " ".join(str(x) for x in sorted(rows))))
        ok(os.path.exists(APPROVED_TABLE) and open(p, "rb").read() == open(APPROVED_TABLE, "rb").read(),
           "%s: файл байт в байт = одобренный staging job4_start_skills_1026 (%s)" % (name, hashlib.md5(open(p, "rb").read()).hexdigest()[:8]))
        ok(all(rows.get(s) == c for s, c in WANT_ROWS.items()), "%s: строки 4/15/26 — %s" % (name, "; ".join("%d: %s" % (s, rows.get(s)) for s in WANT_ROWS)))
        ok(all(rows.get(s) == WANT_ROWS[src] for s, src in JOB4_ADDED.items()),
           "%s: строки 6/17/28 = навыки строк 4/15/26 — %s" % (name, "; ".join("%d: %s" % (s, rows.get(s)) for s in JOB4_ADDED)))
        sif = d + "SkillInfo.sif"
        if os.path.exists(sif):
            data = open(sif, "rb").read()
            good = True
            for s, codes in WANT_ROWS.items():
                for c in codes:
                    r = data[209 * c:209 * c + 209]
                    pre = [struct.unpack_from("<h", r, o)[0] for o in (200, 203, 206)]
                    good &= struct.unpack_from("<h", r, 0)[0] == c and r[189] == WANT_CAT[s] and r[190] == 0 and pre == [-1, -1, -1]
            ok(good, "%s: SkillInfo.sif — навыки строк 4/15/26 в категориях 10/11/12, требование очков 0, предшественников нет" % name)
        else:
            ok(False, "%s: нет %s" % (name, sif))

    # ── чужие патчи ──
    hits = []
    pd = os.path.join(SRC, "patches")
    for fn in os.listdir(pd):
        # ★ P89 (26.10.2026): гейт того же sub_481CE0 — площадка 0x481D3F (диспетчер switch), 0x4820C9 P87 не пишет и не сверяет;
        #   его непересечение с P87 проверяет verify_p89 — здесь p89 исключён
        if not fn.endswith(".cpp") or "p87" in fn or "p89" in fn or fn == "Registry.cpp":
            continue
        t = open(os.path.join(pd, fn), encoding="utf-8", errors="replace").read().lower()
        for a in ("0x00481c", "0x481c", "0x00481d", "0x481d", "0x00481e", "0x481e", "0x00481f", "0x481f", "0x004820", "0x4820",
                  "0x0048a8", "0x48a8", "0x0048a9", "0x48a9", "0x0048aa", "0x48aa"):
            if a in t:
                hits.append("%s:%s" % (fn, a))
    ok(not hits, "другие патчи не трогают sub_481CE0 / sub_48A8C0 (%s)" % (", ".join(hits) or "—"))

    # ── DLL ──
    m = open(MAP, encoding="latin-1").read() if os.path.exists(MAP) else ""
    ok(all(s in m for s in ("P87_Job4StartSkills", "_P87_PickRow@20", "_P87_GetStats@4", "PickRowTrampoline")),
       "MAP AsdaPatch: P87_Job4StartSkills, P87_PickRow, P87_GetStats, PickRowTrampoline")
    d = open(DLL, "rb").read()
    ok("P87_Job4StartSkills".encode("utf-16-le") in d, "AsdaPatch.dll: строка секции P87_Job4StartSkills")
    pe = pefile.PE(DLL)
    exp = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
    ok(b"_P87_GetStats@4" in exp or b"P87_GetStats" in exp, "AsdaPatch.dll: экспорт P87_GetStats")

    def sym(pat):
        mm = re.search(r"\s(\S*%s\S*)\s+([0-9a-f]{8})\s" % re.escape(pat), m)
        return int(mm.group(2), 16) if mm else None
    tva, pva, rva = sym("PickRowTrampoline"), sym("_P87_PickRow@20"), sym("g_pRet@?A0x")
    # g_pRet ищем именно из объекта p87 (у других патчей свои g_pRet в анонимных пространствах)
    rv = None
    for line in m.splitlines():
        if "g_pRet@" in line and "p87_job4_start_skills.obj" in line:
            rv = int(line.split()[2], 16)
    dimg = bytearray(pe.get_memory_mapped_image())
    dbase = pe.OPTIONAL_HEADER.ImageBase
    if tva and pva and rv:
        ok(struct.unpack_from("<I", dimg, rv - dbase)[0] == RET, "DLL: g_pRet (P87) = 0x%08X (возврат 0x4820D0)" % struct.unpack_from("<I", dimg, rv - dbase)[0])
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        seq = []
        for i in md.disasm(bytes(dimg[tva - dbase:tva - dbase + 96]), tva):
            seq.append(i)
            if i.mnemonic == "jmp":
                break
        s = [("%s %s" % (i.mnemonic, i.op_str)).strip() for i in seq]
        ok(s and s[0] == "movzx eax, byte ptr [edx + 0x190]", "трамплин: первой — стоковая инструкция площадки (%s)" % (s[0] if s else "—"))
        ok("pushfd" in s and "pushal" in s and "popal" in s and "popfd" in s and s.index("popal") < s.index("popfd"),
           "трамплин: pushfd/pushad … popad/popfd")
        ok("mov dword ptr [esp + 0x1c], eax" in s and s.index("mov dword ptr [esp + 0x1c], eax") < s.index("popal"),
           "трамплин: ответ — в слот EAX кадра pushad ([esp+0x1C]) до popad")
        ok(("call 0x%x" % pva) in s, "трамплин: call P87_PickRow (0x%08X)" % pva)
        exits = [x for x in s if x.startswith("j") or x.startswith("ret")]
        ok(exits == ["jmp dword ptr [0x%x]" % rv], "трамплин: единственный выход — jmp [g_pRet] (%s)" % ", ".join(exits))
        pushes = [x for x in s if x.startswith("push ") and x not in ("pushfd", "pushal")]
        ok(len(pushes) == 5, "трамплин: 5 аргументов P87_PickRow (%s)" % "; ".join(pushes))
    else:
        ok(False, "MAP: адреса трамплина/P87_PickRow/g_pRet не найдены")
    cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8", errors="replace").read()
    ok('L"P87_Job4StartSkills"' in cfg and "kJob4StartSkills" in cfg, "Config.cpp: секция [P87_Job4StartSkills] (Enabled=1)")
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8", errors="replace").read()
    ko = acj[acj.index("case AcJournal::kOther:"):acj.index("case AcJournal::kPacketValidator:")]
    ok(all(("case %d: return L\"P87:" % k) in ko for k in (106, 107, 108)), "AcJournal.cpp: виды ac.other 106/107/108 — тексты P87")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8", errors="replace").read()
    ok(reg.find('L"P87_Job4StartSkills"') > reg.find('L"P85_PremiumCartRows"') > 0, "Registry.cpp: P87 после P85")
    print("== ИТОГ verify_p87: ошибок %d ==" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
