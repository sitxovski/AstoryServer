# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p89.py — СТАТИЧЕСКАЯ проверка P89 (гейт стартовых навыков 4-й профессии по категории ветки, 2026-10-26):
#   AsdaPatch P89_Job4GateBranch.
#
# Сервер НЕ запускается. По образам (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38), данным и собранной DLL:
#  1) тело sub_481CE0 (0x481CE0…0x48212C с таблицами switch) одинаково в трёх образах; площадка 0x481D3F (17 б, диспетчер
#     switch), пролог 0x481CE0…0x481D3F, LABEL_99 0x4820C6 (3 б), эпилог 0x4820E7, jpt 0x4820F0, byte_48210C — как в DLL;
#     FNV-1a веток 0x481D50…0x4820C6 = 0x6299432F (константа P89);
#  2) ДЕФЕКТ вторым методом (дизасм, не декомпил): в каждой из 6 веток switch (цели jpt) — цикл суммы по CUser+0xC024+4·кат с
#     началом 1/4/7 и концом 4/7/10 и 4 сравнения пар категорий: 4/6 → 0xC04C/0xC050 (10/11), 15/17 → 0xC054/0xC058 (12/13),
#     26/28 → 0xC05C/0xC060 (14/15); порог cmp [ebp-4], 3Ch; ветвь a3 cmp [ebp+0Ch], 0;
#  3) границы инструкций: 0x481D3F и 0x481D50 — начала инструкций; переходов/abs32 ВНУТРЬ (0x481D3F, 0x481D50) нет; на 0x4820C6
#     ведут 24 перехода, на 0x4820E7 — ветки «нет выдачи»; 0x4820C9 (P87) площадка P89 не трогает;
#  4) поток: sub_481CE0 зовут 3 места (0x45D533 / 0x45DE95 push 1, 0x47EDD0 push 0), каждое за cmp [reg+1B3h], 4;
#     в sub_47E9B0 порядок: call sub_4760E0 → запись [..+0C024h] (++очки категории SkillInfo+0xBD) → call sub_481CE0;
#     sub_475650 пишет уровень навыка mov byte ptr [..+0C0C4h], 0; загрузка sub_475290 — очки категории += уровень навыка;
#  5) данные: SkillInfo.sif (сток, GameServer, Indun) — навыков категорий 13–15 нет, 10/11/12 — маски классов 1–11 / 12–22 /
#     23–33; staging ChangeJobAddSkillTable (AstoryServer/Docs/job4_start_skills_1026) — 15 строк, 4/6/15/17/26/28 по 5
#     навыков своей категории 10/10/11/11/12/12, требование 0, без предшественников;
#  6) DLL: MAP — P89_Job4GateBranch, _P89_Dispatch@16, _P89_GetStats@4, DispatchTrampoline; трамплин — 4 push кадра,
#     call P89_Dispatch, jmp eax (единственный выход); константы площадки в DLL = байтам образа; экспорт; строка секции;
#     Config.cpp — Enabled/Mode/SkipOwnedRow; AcJournal.cpp — 112/113/114; Registry — P89 после P87;
#  7) другие патчи (кроме P87: LABEL_99 0x4820C6…0x4820E7, площадка 0x4820C9) не трогают 0x481CE0…0x48212C.
# Поведение — стенд tools/stand_p89 (настоящие sub_47E9B0 / sub_481CE0 / sub_48A8C0 / sub_475650; 6 подклассов × 5 сценариев).
# Запуск: python verify_p89.py [AsdaPatch.dll]
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
_d = os.environ.get("P89_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]
SIFS = [("сток", r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\SkillTable_Info\SkillInfo.sif"),
        ("GameServer", V2 + "GameServer/SkillTable_Info/SkillInfo.sif"),
        ("Indun", V2 + "Indun_GameServer/SkillTable_Info/SkillInfo.sif")]
STAGING = os.path.normpath(os.path.join(HERE, "..", "..", "..", "Docs", "job4_start_skills_1026"))
STAGING_TABLES = [os.path.join(STAGING, d, "SkillTable_Info", "ChangeJobAddSkillTable.txt") for d in ("GameServer", "Indun_GameServer")]

F481 = (0x00481CE0, 0x0048212C)
SITE, SITE_ORIG = 0x00481D3F, bytes.fromhex("8b45ec0fb6880c214800ff248df0204800")
HEAD_ORIG = bytes.fromhex(
    "558bec83ec14894df0c745f800000000c745fc00000000c745f400000000668b4508508b4df08b51048b4a34e88f070b008945f4837df4007505"
    "e9c80300008b45f40fb68891010000894dec8b55ec83ea048955ec837dec180f8785030000")
LBL99, LBL99_ORIG = 0x004820C6, bytes.fromhex("8b55f4")
EPI, EPI_ORIG = 0x004820E7, bytes.fromhex("8be55dc20800")
JPT, JPT_ORIG = 0x004820F0, bytes.fromhex("501d4800e91d4800821e48001b1f4800b41f480047204800c4204800")
IDX, IDX_ORIG = 0x0048210C, bytes.fromhex("00060106060606060606060206030606060606060606040605")
CASES = (0x00481D50, 0x004820C6)
CASES_FNV = 0x6299432F
P87_SITE = 0x004820C9
# подкласс → (начало, конец цикла суммы, пара стока, своя категория)
WANT = {4: (1, 4, (0xC04C, 0xC050), 10), 6: (1, 4, (0xC04C, 0xC050), 10), 15: (4, 7, (0xC054, 0xC058), 11),
        17: (4, 7, (0xC054, 0xC058), 11), 26: (7, 10, (0xC05C, 0xC060), 12), 28: (7, 10, (0xC05C, 0xC060), 12)}
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def fnv(b):
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x01000193) & 0xFFFFFFFF
    return h


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


def refs(img, base, lo, hi, a, b, allins=None):
    """Переходы rel8/rel32/jcc/call и abs32 на адреса [a, b) — список (источник, цель)."""
    out = []
    for ins in (allins if allins is not None else disasm(img, base, lo, hi)):
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
    toks = open(path, encoding="latin-1").read().split()
    rows, i = {}, 0
    while i < len(toks):
        rid, n = int(toks[i]), int(toks[i + 1])
        rows[rid] = [int(x) for x in toks[i + 2:i + 2 + n]]
        i += 2 + n
    return rows


def main():
    print("== verify_p89 ==")
    bodies = []
    for name, path in GS_IMAGES:
        if not os.path.exists(path):
            ok(False, "%s: образа нет (%s)" % (name, path))
            continue
        pe, img, base = load(path)
        lo, hi = text_range(pe, base)
        g = lambda va, n: bytes(img[va - base:va - base + n])
        bodies.append(hashlib.md5(g(F481[0], F481[1] - F481[0])).hexdigest())
        ok(g(SITE, len(SITE_ORIG)) == SITE_ORIG, "%s: площадка 0x%08X = %s (mov eax,[ebp-14h] / movzx ecx,byte_48210C[eax] / jmp jpt[ecx*4])"
           % (name, SITE, g(SITE, len(SITE_ORIG)).hex()))
        ok(g(F481[0], len(HEAD_ORIG)) == HEAD_ORIG and g(LBL99, 3) == LBL99_ORIG and g(EPI, 6) == EPI_ORIG,
           "%s: пролог 0x481CE0…0x481D3F, LABEL_99 0x4820C6 mov edx,[ebp-0Ch], эпилог 0x4820E7 mov esp,ebp/pop ebp/retn 8" % name)
        ok(g(JPT, len(JPT_ORIG)) == JPT_ORIG and g(IDX, len(IDX_ORIG)) == IDX_ORIG,
           "%s: jpt_481D49 @0x4820F0 (7 целей) и byte_48210C @0x48210C (25 б)" % name)
        f = fnv(g(CASES[0], CASES[1] - CASES[0]))
        ok(f == CASES_FNV, "%s: FNV веток 0x481D50…0x4820C6 = 0x%08X (ждём 0x%08X)" % (name, f, CASES_FNV))

        ins = disasm(img, base, F481[0], 0x004820EC)
        starts = {i.address for i in ins}
        ok(SITE in starts and SITE + len(SITE_ORIG) in starts and 0x00481D49 in starts and LBL99 in starts and EPI in starts,
           "%s: 0x481D3F, 0x481D49 (jmp jpt), 0x481D50, 0x4820C6, 0x4820E7 — начала инструкций" % name)
        # цели switch по подклассу: jpt[idx[sub-4]]
        jpt = [struct.unpack_from("<I", g(JPT, 28), 4 * k)[0] for k in range(7)]
        idx = list(g(IDX, 25))
        tgt = {s: jpt[idx[s - 4]] for s in WANT}
        ok(sorted(set(tgt.values())) == sorted(jpt[:6]) and all(jpt[idx[s - 4]] == 0x004820C4 for s in range(4, 29) if s not in WANT),
           "%s: switch — 4/6/15/17/26/28 → %s, прочие 4…28 → 0x4820C4 (default)" % (name, ", ".join("%d:0x%X" % (s, t) for s, t in tgt.items())))
        bounds = sorted(set(jpt[:6])) + [LBL99]
        good = True
        detail = []
        for s, (c0, c1, pair, own) in WANT.items():
            a = tgt[s]
            b = bounds[bounds.index(a) + 1]
            body = [i for i in ins if a <= i.address < b]
            txt = ["%s %s" % (i.mnemonic, i.op_str) for i in body]
            init = txt[0] == "mov dword ptr [ebp - 8], %d" % c0
            lim = ("cmp dword ptr [ebp - 8], %s" % (c1 if c1 < 10 else hex(c1))) in txt   # capstone: < 10 — десятичное
            add = sum(1 for t in txt if t.startswith("add ") and "*4 + 0xc024]" in t) == 1
            cmps = [int(m.group(1), 16) for t in txt for m in [re.match(r"cmp dword ptr \[e[a-d]x \+ (0x[0-9a-f]+)\], 0$", t)] if m]
            thr = txt.count("cmp dword ptr [ebp - 4], 0x3c") == 2 and ("cmp dword ptr [ebp + 0xc], 0" in txt)
            one = init and lim and add and cmps == [pair[0], pair[1], pair[0], pair[1]] and thr
            good &= one
            detail.append("%d: сумма кат. %d…%d, пара %s ×2%s" % (s, c0, c1 - 1, "/".join("%d" % ((p - 0xC024) // 4) for p in pair),
                                                                  "" if one else " (НЕ ТАК: %s)" % [hex(c) for c in cmps]))
        ok(good, "%s: ДЕФЕКТ по дизасму — %s; деревья 4-й профессии 10/11/12" % (name, "; ".join(detail)))

        allins = disasm(img, base, lo, hi)
        r = refs(img, base, lo, hi, SITE + 1, SITE + len(SITE_ORIG), allins)
        ok(not r, "%s: переходов/abs32 внутрь площадки (0x481D3F, 0x481D50) нет (%s)" % (name, ", ".join("0x%08X→0x%08X" % x for x in r[:5]) or "—"))
        r0 = refs(img, base, lo, hi, SITE, SITE + 1, allins)
        ok(not r0, "%s: на 0x481D3F переходов нет — вход только проходом после ja 0x4820C4 (%d)" % (name, len(r0)))
        to99 = [x for x in refs(img, base, F481[0], 0x004820EC, LBL99, LBL99 + 1) if x[0] < LBL99]
        toepi = [x for x in refs(img, base, F481[0], 0x004820EC, EPI, EPI + 1) if x[0] < EPI]
        ok(len(to99) == 24 and len(toepi) >= 13, "%s: на LABEL_99 0x4820C6 — %d переходов (24), на эпилог 0x4820E7 — %d" % (name, len(to99), len(toepi)))
        callers = [i for i in allins if i.mnemonic == "call" and i.op_str == "0x481ce0"]
        cs = []
        for c in callers:
            pre = [i for i in allins if c.address - 40 <= i.address < c.address]
            ptxt = ["%s %s" % (i.mnemonic, i.op_str) for i in pre]
            push = [t for t in ptxt if t in ("push 1", "push 0")]
            cnt = any(t.startswith("movzx ecx, byte ptr [eax + 0x1b3]") for t in ptxt) and ("cmp ecx, 4" in ptxt)
            cs.append((c.address, push[-1] if push else "?", cnt))
        ok([(a, p) for a, p, _ in cs] == [(0x0045D533, "push 1"), (0x0045DE95, "push 1"), (0x0047EDD0, "push 0")] and all(x for _, _, x in cs),
           "%s: sub_481CE0 зовут 3 места за cmp [CUser+1B3h], 4: %s" % (name, ", ".join("0x%08X %s" % (a, p) for a, p, _ in cs)))
        lr = disasm(img, base, 0x0047E9B0, 0x0047EDE0)
        pos = {k: None for k in ("lvl", "cat", "gate")}
        for i in lr:
            t = "%s %s" % (i.mnemonic, i.op_str)
            if t == "call 0x4760e0" and pos["lvl"] is None:
                pos["lvl"] = i.address
            if i.mnemonic == "mov" and re.match(r"dword ptr \[e[a-d]x \+ e[a-d]x\*4 \+ 0xc024\], e[a-d]x", i.op_str) and pos["cat"] is None:
                pos["cat"] = i.address
            if t == "call 0x481ce0":
                pos["gate"] = i.address
        ok(None not in pos.values() and pos["lvl"] < pos["cat"] < pos["gate"],
           "%s: sub_47E9B0 — уровень sub_4760E0 @0x%X → ++очки категории @0x%X → гейт sub_481CE0 @0x%X" % (name, pos["lvl"] or 0, pos["cat"] or 0, pos["gate"] or 0))
        z = [i for i in disasm(img, base, 0x00475650, 0x00475700) if i.mnemonic == "mov" and "0xc0c4], 0" in i.op_str]
        ok(len(z) == 1, "%s: sub_475650 — mov byte ptr [..+0C0C4h], 0 (уровень выданного навыка = 0) @%s" % (name, ", ".join("0x%X" % i.address for i in z)))
        ld = ["%s %s" % (i.mnemonic, i.op_str) for i in disasm(img, base, 0x00475290, 0x00475420)]
        ok(any("0xc0c4]" in t and t.startswith("movzx") for t in ld) and any(t.startswith("add ") and "*4 + 0xc024]" in t for t in ld),
           "%s: загрузка sub_475290 — очки категории += уровень навыка (+0xC0C4) — инвариант «очки = сумма уровней»" % name)
    ok(len(bodies) == 3 and len(set(bodies)) == 1, "тело sub_481CE0 одинаково в трёх образах (%s)" % ", ".join(x[:8] for x in bodies))

    # ── данные ──
    for name, p in SIFS:
        if not os.path.exists(p):
            ok(False, "%s: нет %s" % (name, p))
            continue
        d = open(p, "rb").read()
        cnt, masks = {}, {}
        for i in range(len(d) // 209):
            r = d[209 * i:209 * i + 209]
            if struct.unpack_from("<h", r, 0)[0] <= 0:
                continue
            c = r[189]
            cnt[c] = cnt.get(c, 0) + 1
            masks[c] = masks.get(c, 0) | struct.unpack_from("<Q", r, 123)[0]
        bits = lambda m: [b for b in range(64) if m >> b & 1]
        ok(not any(c in cnt for c in (13, 14, 15)) and bits(masks.get(10, 0)) == list(range(1, 12))
           and bits(masks.get(11, 0)) == list(range(12, 23)) and bits(masks.get(12, 0)) == list(range(23, 34)),
           "%s SkillInfo.sif (md5 %s): кат. 10/11/12 — %d/%d/%d навыков, маски классов 1–11 / 12–22 / 23–33; кат. 13–15 — нет"
           % (name, hashlib.md5(d).hexdigest()[:8], cnt.get(10, 0), cnt.get(11, 0), cnt.get(12, 0)))
    sif = open(SIFS[1][1], "rb").read() if os.path.exists(SIFS[1][1]) else b""
    for p in STAGING_TABLES:
        if not os.path.exists(p):
            ok(False, "staging: нет %s" % p)
            continue
        rows = read_table(p)
        good = len(rows) == 15 and all(len(rows.get(s, [])) == 5 for s in WANT)
        for s, (_, _, _, own) in WANT.items():
            for c in rows.get(s, []):
                r = sif[209 * c:209 * c + 209]
                good &= len(r) == 209 and r[189] == own and r[190] == 0 and [struct.unpack_from("<h", r, o)[0] for o in (200, 203, 206)] == [-1, -1, -1]
        ok(good, "staging %s (md5 %s): 15 строк, 4/6/15/17/26/28 — по 5 навыков категорий 10/10/11/11/12/12, требование 0, без предшественников"
           % (os.path.relpath(p, STAGING), hashlib.md5(open(p, "rb").read()).hexdigest()[:8]))

    # ── чужие патчи ──
    hits = []
    pd = os.path.join(SRC, "patches")
    for fn in os.listdir(pd):
        if not fn.endswith(".cpp") or "p89" in fn or fn == "Registry.cpp":
            continue
        t = open(os.path.join(pd, fn), encoding="utf-8", errors="replace").read().lower()
        for m in re.finditer(r"0x(00)?(48[12][0-9a-f]{3})\b", t):
            v = int(m.group(2), 16)
            if F481[0] <= v < F481[1] and not ("p87" in fn and 0x4820C6 <= v <= 0x4820E7):   # P87: LABEL_99…call sub_48A8C0
                hits.append("%s:0x%X" % (fn, v))
    ok(not hits, "другие патчи не трогают 0x481CE0…0x48212C (P87 — только LABEL_99 0x4820C6…0x4820E7): %s" % (", ".join(sorted(set(hits))) or "—"))

    # ── DLL ──
    m = open(MAP, encoding="latin-1").read() if os.path.exists(MAP) else ""
    ok(all(s in m for s in ("P89_Job4GateBranch", "_P89_Dispatch@16", "_P89_GetStats@4", "DispatchTrampoline")),
       "MAP AsdaPatch: P89_Job4GateBranch, P89_Dispatch, P89_GetStats, DispatchTrampoline")
    d = open(DLL, "rb").read()
    ok("P89_Job4GateBranch".encode("utf-16-le") in d, "AsdaPatch.dll (md5 %s): строка секции P89_Job4GateBranch" % hashlib.md5(d).hexdigest()[:8])
    for nm, b in (("площадка", SITE_ORIG), ("пролог", HEAD_ORIG), ("jpt", JPT_ORIG), ("byte_48210C", IDX_ORIG), ("эпилог", EPI_ORIG)):
        ok(d.count(b) >= 1, "AsdaPatch.dll: константа «%s» P89 = байтам образа" % nm)
    pe = pefile.PE(DLL)
    exp = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
    ok(b"_P89_GetStats@4" in exp or b"P89_GetStats" in exp, "AsdaPatch.dll: экспорт P89_GetStats")

    def sym(pat):
        mm = re.search(r"\s(\S*%s\S*)\s+([0-9a-f]{8})\s" % re.escape(pat), m)
        return int(mm.group(2), 16) if mm else None
    tva = None
    for line in m.splitlines():
        if "DispatchTrampoline" in line and "p89_job4_gate_branch.obj" in line:
            tva = int(line.split()[2], 16)
    dva = sym("_P89_Dispatch@16")
    dimg = bytearray(pe.get_memory_mapped_image())
    dbase = pe.OPTIONAL_HEADER.ImageBase
    if tva and dva:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        s = []
        for i in md.disasm(bytes(dimg[tva - dbase:tva - dbase + 64]), tva):
            s.append(("%s %s" % (i.mnemonic, i.op_str)).strip())
            if i.mnemonic == "jmp":
                break
        ok(s == ["push dword ptr [ebp + 0xc]", "movsx eax, word ptr [ebp + 8]", "push eax", "push dword ptr [ebp - 0xc]",
                 "push dword ptr [ebp - 0x10]", "call 0x%x" % dva, "jmp eax"],
           "трамплин: a3 / userNum / CUser / this из кадра sub_481CE0, call P89_Dispatch, единственный выход jmp eax (%s)" % "; ".join(s))
    else:
        ok(False, "MAP: адреса DispatchTrampoline / P89_Dispatch не найдены")
    cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8", errors="replace").read()
    sec = cfg[cfg.index("const IniKey kJob4GateBranch[]"):]
    sec = sec[:sec.index("};")]
    ok('L"P89_Job4GateBranch"' in cfg and all(('{ L"%s", L"1"' % k) in sec for k in ("Enabled", "Mode", "SkipOwnedRow")),
       "Config.cpp: секция [P89_Job4GateBranch] Enabled=1, Mode=1, SkipOwnedRow=1")
    acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8", errors="replace").read()
    ko = acj[acj.index("case AcJournal::kOther:"):acj.index("case AcJournal::kPacketValidator:")]
    ok(all(("case %d: return L\"P89:" % k) in ko for k in (112, 113, 114)), "AcJournal.cpp: виды ac.other 112/113/114 — тексты P89")
    reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8", errors="replace").read()
    ok(reg.find('L"P89_Job4GateBranch"') > reg.find('L"P87_Job4StartSkills"') > 0, "Registry.cpp: P89 после P87 (проверяет площадку P87 после её установки)")
    print("== ИТОГ verify_p89: ошибок %d ==" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
