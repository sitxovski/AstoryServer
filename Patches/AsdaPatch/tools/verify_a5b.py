# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_a5b.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны В5b «остаток меры 9» (2026-10-12):
#   AddonNPC N15 (NpcServer: 6 площадок `call rel32` + 24 соседа — центр навыка против кастера sub_42C4B0 и цель
#   против центра sub_4179D0/sub_414690), AsdaPatch P56-расширение для 6158 (GameServer: 3 площадки + 5 соседей —
#   заявка стража «в пути» 8940→8941). Поверх — ВСЕ прежние площадки/соседи P56/N14 (списки импортируются из
#   verify_p56.py; его main не годится — теперь стабов St_Cool-образных два, St_Send-образных два и т. д.).
# Сервер НЕ запускается. Образы: 3 GameServer (сток 4e20f0ad, живой/Indun e7b4ac38), 3 NpcServer (16c7a0af,
# c02486d6, 0de2c559). Запуск: py -3.13 verify_a5b.py [AsdaPatch.dll] [AddonNPC.dll]
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_p56 as V   # функции сверки + списки площадок/соседей волны В5
from verify_p56 import (ok, load, text_range, boundary_ok, scan_into, find_all, stub_targets, Emu, check_sites,
                        GS_IMAGES, NPC_IMAGES, GS_SITES, GS_NEIGHBOURS, NPC_SITES, NPC_NEIGHBOURS, _call)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                               UC_X86_REG_EBP, UC_X86_REG_ESP)

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
DLL_NPC = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "AddonNPC", "out", "AddonNPC.dll")

# ── P56 для 6158 (GameServer) ────────────────────────────────────────────────
P56B_GS = [
    ("P56b.6158busy", 0x0048EA99, 0x0048B850),
    ("P56b.8940send", 0x0048F1E9, 0x005646C0),
    ("P56b.8941disp", 0x00433BAC, 0x0048F2B0),
]
GS_SITES_B = [(n, va, _call(va, tgt)) for n, va, tgt in P56B_GS]
GS_NEIGH_B = [
    ("6158 sub_48B850: mov cx,[ebp+8]; push; mov ecx,[ebp-0x594] 0x48EA8E", 0x0048EA8E, "668b4d08518b8d6cfaffff"),
    ("6158 «страж занят» → код 5 0x48EA9E",                              0x0048EA9E, "85c07511c68588fdffff05"),
    ("6158 push 8940; mov ecx,0x7E0538 0x48F1DF",                        0x0048F1DF, "68ec220000b938057e00"),
    ("6158 код навыка [ebp-0x560] (sub 1201) 0x48E878",                  0x0048E878, "0fbf95a0faffff81eab1040000"),
    ("8941 userNum [ebp-8] 0x433B98",                                    0x00433B98, "668b55f852"),
    ("8941: this = [[ebp-0x1028]+4]+0x48E8 0x433B9D",                    0x00433B9D, "8b85d8efffff8b48048b89e8480000"),
    ("цель sub_48B850 (пролог)",                                         0x0048B850, "55"),
    ("цель sub_48F2B0 (пролог)",                                         0x0048F2B0, "55"),
]

# ── N15 (NpcServer) ──────────────────────────────────────────────────────────
N15_NPC = [
    ("N15.centerP", 0x00418912, 0x0042C4B0),
    ("N15.centerG", 0x00415061, 0x0042C4B0),
    ("N15.targetP1", 0x00418C72, 0x004179D0),
    ("N15.targetP2", 0x00418F28, 0x004179D0),
    ("N15.targetG1", 0x00415339, 0x00414690),
    ("N15.targetG2", 0x004155B8, 0x00414690),
]
NPC_SITES_B = [(n, va, _call(va, tgt)) for n, va, tgt in N15_NPC]
NPC_NEIGH_B = [
    ("8205 центр: mov edi,20 0x41890D",                        0x0041890D, "bf14000000"),
    ("8205 центр: test al; jne; mov [esp+0x24],10 0x418917",   0x00418917, "84c07509c64424240a"),
    ("8205 центр: movzx edx,[esp+0x1C] (индекс навыка)",       0x004188DA, "0fb754241c"),
    ("8205 центр: регистры 0x4188FC (esi=Y кастера, ebx=cx, ecx=al, eax=X кастера, push esi/eax)",
                                                               0x004188FC, "0fbff60fbfd90fbec80fbfc7560fbff250"),
    ("8940 центр: mov edi,20 0x415055",                        0x00415055, "bf14000000"),
    ("8940 центр: test al; jne; mov [esp+0x18],10 0x415066",   0x00415066, "84c07509c64424180a"),
    ("8940 центр: movzx edx,[esp+0x20] 0x415019",              0x00415019, "0fb7542420"),
    ("8940 центр: регистры 0x41503C (ecx=cx, ebx=si, esi=dx, edx=di, push ecx, ecx=al, push edx)",
                                                               0x0041503C, "0fbfc90fbfde6689b424960400000fbff20fbfd7510fbec852"),
    ("8205 буфер +216 = ebp (кастер) 0x418813",                0x00418813, "89ac2434030000"),
    ("8205 буфер +222/+224 = cx/si (iTargetX/Z) 0x4188A0",     0x004188A0, "66898c243a0300006689b4243c030000"),
    ("8205 буфер +221 = dl (радиус) 0x4188B0",                 0x004188B0, "88942439030000"),
    ("8205 буфер +304 = X цели 0x418B89",                      0x00418B89, "66898c248c03"),
    ("8205 буфер +306 = Y цели 0x418B9E",                      0x00418B9E, "668994248e030000"),
    ("8205 буфер +304/+306 (цель-моб) 0x418E45/0x418E63",      0x00418E45, "66898c248c030000"),
    ("sub_4179D0 читает +222/+221/+224/+304 0x4179EF",         0x004179EF, "0fbf9dde0000000fbe8ddd0000000fbfbde00000000fbfb530010000"),
    ("sub_4179D0 читает +306 0x417A2E",                        0x00417A2E, "0fbf8532010000"),
    ("8205 цель-игрок: push v72,v73 0x418C62",                 0x00418C62, "8d8c2444020000518d94246802000052"),
    ("8205 цель-моб: push v72,v73 0x418F18",                   0x00418F18, "8d842444020000508d8c246802000051"),
    ("8940 буфер +116 = ebp 0x414FB2",                         0x00414FB2, "89ac2490040000"),
    ("8940 буфер +121 = dl 0x415012",                          0x00415012, "88942495040000"),
    ("8940 буфер +124 = cx 0x415034",                          0x00415034, "66898c2498040000"),
    ("8940 буфер +122 = si 0x415042",                          0x00415042, "6689b42496040000"),
    ("8940 буфер +206 (цель-игрок) 0x41524B",                  0x0041524B, "66898424ea040000"),
    ("8940 буфер +204 (цель-игрок) 0x415263",                  0x00415263, "66899424e8040000"),
    ("sub_414690 читает +122/+121/+124/+204 0x4146AF",         0x004146AF, "0fbf5d7a0fbe4d790fbf7d7c0fbfb5cc000000"),
    ("8940 цель-игрок: push v58,v59 0x415329",                 0x00415329, "8d942404040000528d84242804000050"),
    ("8940 цель-моб: push v58,v59 0x4155A8",                   0x004155A8, "8d942404040000528d84242804000050"),
    ("sub_42C4B0 (коробка) первые 32 б",                           0x0042C4B0, "8b5424048bc2558d2c0a2bc18bd62bd12bc703ce3bc37f1c03ef3beb7c168b44"),
]


def emulate_gs(img, base, dimg, dbase):
    print("-- эмуляция стабов P56b (unicorn)")
    RET = 0x00160000
    # St_GuardBusy: тот же пролог, что у St_Cool — различаем по цели jmp.
    cands = [v for v in find_all(dimg, dbase, "60 8d 44 24 20 50 e8") if dimg[v - dbase + 11] == 0x85 and dimg[v - dbase + 12] == 0xC0]
    busy = [v for v in cands if stub_targets(dimg, dbase, v)[0] == [0x0048B850]]
    cool = [v for v in cands if stub_targets(dimg, dbase, v)[0] == [0x0047BE60]]
    ok(len(busy) == 1 and len(cool) == 1, "St_GuardBusy (jmp → 0x48B850) и St_Cool (→ 0x47BE60): %d / %d" % (len(busy), len(cool)))
    sends = [v for v in find_all(dimg, dbase, "60 55 e8") if dimg[v - dbase + 7] == 0x61 and dimg[v - dbase + 8] == 0xFF]
    sends = [v for v in sends if stub_targets(dimg, dbase, v)[0] == [0x005646C0]]
    ok(len(sends) == 2, "St_Send8205 + St_Send8940 (оба jmp → 0x5646C0): %d" % len(sends))
    resps = [v for v in find_all(dimg, dbase, "60 ff 74 24 24 e8") if dimg[v - dbase + 10] == 0x61]
    r8941 = [v for v in resps if stub_targets(dimg, dbase, v)[0] == [0x0048F2B0]]
    r8206 = [v for v in resps if stub_targets(dimg, dbase, v)[0] == [0x00470DB0]]
    ok(len(r8941) == 1 and len(r8206) == 1, "St_Resp8941 (→ 0x48F2B0) и St_Resp8206 (→ 0x470DB0): %d / %d" % (len(r8941), len(r8206)))
    if not (busy and len(sends) == 2 and r8941):
        ok(False, "эмуляция P56b пропущена — стабы не найдены")
        return
    emu = Emu(img, base, dimg, dbase)
    emu.stops = {0x0048B850, 0x005646C0, 0x0048F2B0, RET}
    seen = {}

    def fake(ret):
        def f(uc, args, argp):
            seen["a"] = args
            return ret
        return f
    bc = stub_targets(dimg, dbase, busy[0])[1][0]
    for want, label in ((0, "пропуск"), (1, "отказ")):
        emu.fake = {bc: (4, fake(want))}
        esp0 = 0x00180000
        stop = emu.run(busy[0], {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x11111111, UC_X86_REG_EBP: 0x00170000},
                       mem=[(esp0, struct.pack("<II", RET, 10))])
        if want == 0:
            ok(stop == 0x0048B850 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x11111111,
               "St_GuardBusy %s: в сток sub_48B850, esp/ecx целы" % label)
        else:
            ok(stop == RET and emu.r(UC_X86_REG_ESP) == esp0 + 8 and emu.r(UC_X86_REG_EAX) == 0,
               "St_GuardBusy %s: ret 4, eax=0 → код 5 (esp=0x%08X)" % (label, emu.r(UC_X86_REG_ESP)))
        ok(seen.get("a", ()) == (esp0,), "St_GuardBusy %s: P56_GuardBusy(st→[ret]) аргумент верен" % label)
    for v in sends:
        c = stub_targets(dimg, dbase, v)[1][0]
        emu.fake = {c: (4, fake(0))}
        esp0 = 0x00180000
        stop = emu.run(v, {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x7E0538, UC_X86_REG_EBP: 0x00170000, UC_X86_REG_EAX: 0x55},
                       mem=[(esp0, struct.pack("<IIIIII", RET, 0x22EC, 2, 3, 4, 5))])
        ok(stop == 0x005646C0 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x7E0538 and emu.r(UC_X86_REG_EAX) == 0x55
           and seen.get("a", ()) == (0x00170000,), "St_Send @0x%08X: в сток sub_5646C0, esp/ecx/eax целы, Mark(ebp) верен" % v)
    c = stub_targets(dimg, dbase, r8941[0])[1][0]
    emu.fake = {c: (4, fake(0))}
    esp0 = 0x00180000
    stop = emu.run(r8941[0], {UC_X86_REG_ESP: esp0, UC_X86_REG_ECX: 0x12345678, UC_X86_REG_EBP: 0x00170000},
                   mem=[(esp0, struct.pack("<III", RET, 10, 0x00171000))])
    ok(stop == 0x0048F2B0 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x12345678 and seen.get("a", ()) == (10,),
       "St_Resp8941: в сток sub_48F2B0, esp/ecx целы, P56_Clear8941(userNum=10)")


def emulate_npc(nimg, nbase, pimg, pbase):
    print("-- стабы N15 в %s" % DLL_NPC)
    RET = 0x00160000
    ct = find_all(pimg, pbase, "60 8d 44 24 24 50 55 56 57 53 51 ff 74 24 38 e8")
    ct = [v for v in ct if stub_targets(pimg, pbase, v)[0] == [0x0042C4B0]]
    ok(len(ct) == 1, "CenterTail (jmp → 0x42C4B0) найден %d раз" % len(ct))
    tails = find_all(pimg, pbase, "60 8d 44 24 24 50 ff 74 24 24 e8")
    tt = [v for v in tails if sorted(stub_targets(pimg, pbase, v, njmp=2)[0]) == [0x00414690, 0x004179D0]]
    ok(len(tt) == 1, "TargetTail (jmp → 0x414690 / 0x4179D0) найден %d раз (хвостов с таким прологом %d: N14/N13/N15)" % (len(tt), len(tails)))
    n14 = [v for v in tails if stub_targets(pimg, pbase, v)[0] == [0x00408D40]]
    n13 = [v for v in tails if stub_targets(pimg, pbase, v)[0] == [0x00408DC0]]
    ok(len(n14) == 1 and len(n13) == 1, "хвосты N14 (→0x408D40) и N13 (→0x408DC0) на месте: %d / %d" % (len(n14), len(n13)))
    if not (ct and tt):
        ok(False, "эмуляция N15 пропущена — хвосты не найдены")
        return
    kinds = {ct[0]: [], tt[0]: []}
    for va in find_all(pimg, pbase, "6a"):
        k = pimg[va - pbase + 1]
        if 1 <= k <= 4 and pimg[va - pbase + 2] == 0xE9:
            t = va + 7 + struct.unpack("<i", bytes(pimg[va - pbase + 3: va - pbase + 7]))[0]
            if t in kinds:
                kinds[t].append(k)
    ok(sorted(kinds[ct[0]]) == [1, 2], "входы St_CenterPlayer/Guard (виды 1/2) → CenterTail: %s" % sorted(kinds[ct[0]]))
    ok(sorted(kinds[tt[0]]) == [3, 4], "входы St_TargetPlayer/Guard (виды 3/4) → TargetTail: %s" % sorted(kinds[tt[0]]))
    emu = Emu(nimg, nbase, pimg, pbase)
    emu.stops = {0x0042C4B0, 0x004179D0, 0x00414690, RET}
    seen = {}

    def fake(ret):
        def f(uc, args, argp):
            seen["a"] = args
            return ret
        return f
    cc = stub_targets(pimg, pbase, ct[0])[1][0]
    for want, label in ((0, "пропуск"), (1, "отказ")):
        emu.fake = {cc: (28, fake(want))}
        esp0 = 0x00180000
        stop = emu.run(ct[0], {UC_X86_REG_ESP: esp0 - 4, UC_X86_REG_ECX: 7, UC_X86_REG_EBX: 105, UC_X86_REG_EDI: 20,
                               UC_X86_REG_ESI: 203, UC_X86_REG_EBP: 0x00171000},
                       mem=[(esp0 - 4, struct.pack("<I", 1)), (esp0, struct.pack("<III", RET, 100, 207))])
        a = seen.get("a", ())
        ok(a == (1, 7, 105, 20, 203, 0x00171000, esp0),
           "CenterTail %s: N15_Center(kind=1, ecx=7, ebx=105, edi=20, esi=203, ebp, st→[ret]) = %s" % (label, a))
        if want == 0:
            ok(stop == 0x0042C4B0 and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 7 and emu.r(UC_X86_REG_EBX) == 105
               and emu.r(UC_X86_REG_EDI) == 20 and emu.r(UC_X86_REG_ESI) == 203 and emu.r(UC_X86_REG_EBP) == 0x00171000,
               "CenterTail %s: в сток sub_42C4B0, вид снят, ecx/ebx/edi/esi/ebp целы" % label)
        else:
            ok(stop == RET and emu.r(UC_X86_REG_ESP) == esp0 + 12 and emu.r(UC_X86_REG_EAX) == 0,
               "CenterTail %s: ret 8, eax=0 → код 10 (esp=0x%08X)" % (label, emu.r(UC_X86_REG_ESP)))
    tc = stub_targets(pimg, pbase, tt[0])[1][0]
    for kind, tgt in ((3, 0x004179D0), (4, 0x00414690)):
        for want, label in ((0, "пропуск"), (1, "отказ")):
            emu.fake = {tc: (8, fake(want))}
            esp0 = 0x00180000
            stop = emu.run(tt[0], {UC_X86_REG_ESP: esp0 - 4, UC_X86_REG_ECX: 0x0BADF00D, UC_X86_REG_EBP: 0x00171000},
                           mem=[(esp0 - 4, struct.pack("<I", kind)), (esp0, struct.pack("<IIIII", RET, 0x1000, 0x2000, 0x3000, 0x4000))])
            a = seen.get("a", ())
            ok(a == (kind, esp0), "TargetTail вид %d %s: N15_Target(kind, st→[ret]) = %s" % (kind, label, a))
            if want == 0:
                ok(stop == tgt and emu.r(UC_X86_REG_ESP) == esp0 and emu.r(UC_X86_REG_ECX) == 0x0BADF00D,
                   "TargetTail вид %d %s: в сток 0x%08X, вид снят, ecx цел" % (kind, label, tgt))
            else:
                ok(stop == RET and emu.r(UC_X86_REG_ESP) == esp0 + 20 and emu.r(UC_X86_REG_EAX) == 0,
                   "TargetTail вид %d %s: ret 0x10, eax=0 — цель пропущена (esp=0x%08X)" % (kind, label, emu.r(UC_X86_REG_ESP)))


def main():
    # ── 1. GameServer: три образа, все площадки P56 + P56b ────────────────
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        check_sites(name, img, base, GS_SITES + GS_SITES_B, GS_NEIGHBOURS + GS_NEIGH_B)
        if gs_ref[0] is not pe:
            a, b = text_range(pe)
            ra, rb = text_range(gs_ref[0])
            ok((a, b) == (ra, rb) and bytes(img[a:b]) == bytes(gs_ref[1][ra:rb]), ".text побайтно равен стоку (%d б)" % (b - a))
    pe, img, base = gs_ref
    print("-- границы инструкций и входы внутрь площадок P56b (сток GameServer)")
    for n, va, o in GS_SITES_B:
        s, e = boundary_ok(img, base, va, 5)
        ok(s and e, "%-14s начало на границе: %s, конец на границе: %s" % (n, s, e))
    for n, c in scan_into(pe, img, base, GS_SITES + GS_SITES_B).items():
        ok(c == 0, "%-14s входов внутрь: %d" % (n, c))
    print("-- стабы P56/P56b в %s" % DLL)
    dpe, dimg, dbase = load(DLL)
    gt = [v for v in find_all(dimg, dbase, "60 8d 44 24 24 50 55 51 ff 74 24 2c e8") if stub_targets(dimg, dbase, v)[0] == [0x0052BFF0]]
    ok(len(gt) == 1, "GateTail P56 (jmp → 0x52BFF0) найден %d раз (не задет)" % len(gt))
    emulate_gs(img, base, dimg, dbase)

    # ── 2. NpcServer: три образа, N14 + N15 ───────────────────────────────
    npc_ref = None
    for name, path in NPC_IMAGES:
        print("-- %s: %s" % (name, path))
        npe, nimg, nbase = load(path)
        if npc_ref is None:
            npc_ref = (npe, nimg, nbase)
        check_sites(name, nimg, nbase, NPC_SITES + NPC_SITES_B, NPC_NEIGHBOURS + NPC_NEIGH_B)
        for n, va, o in NPC_SITES_B:
            s, e = boundary_ok(nimg, nbase, va, 5)
            ok(s and e, "%-12s начало на границе: %s, конец на границе: %s" % (n, s, e))
        print("-- перебор переходов/abs32 внутрь площадок N14+N15 (%s)" % name)
        for n, c in scan_into(npe, nimg, nbase, NPC_SITES + NPC_SITES_B).items():
            ok(c == 0, "%-12s входов внутрь: %d" % (n, c))
    ppe, pimg, pbase = load(DLL_NPC)
    npe, nimg, nbase = npc_ref
    emulate_npc(nimg, nbase, pimg, pbase)

    print("\nИТОГ: %s (ошибок %d)" % ("OK" if V.bad == 0 else "ЕСТЬ ОШИБКИ", V.bad))
    return 1 if V.bad else 0


if __name__ == "__main__":
    sys.exit(main())
