# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p73.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P73 «мост EAC» (2026-10-16, этап Э1-В).
#
# Сервер НЕ запускается. Грузятся настоящие образы GameServer (сток 4e20f0ad, живой GameServer = Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) md5 образов; байты площадок (4001 0x527692, 5058 0x52CD3E, SetConnectFlag 0x562910, CheckDisConnectUser 0x526CEB) и всех
#     «соседей» (адреса возврата, поля кадра) — одинаковы во всех образах; в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт
#     ВНУТРЬ площадок; площадки и цели переходов лежат на границах инструкций;
#  2) тип 4101 = 12 стоком не шлётся (все вызовы sub_52EDB0 в .text — типы 0,1,2,3,5,6,14), имя в таблице 0x5A62AC[12] — «HackShield»;
#  3) DLL: стабы найдены по .map, косвенные jmp ведут на 0x527698/0x52CD44/0x562915/0x526CF1/0x526E36, call — в P73_OnLogon/
#     P73_OnConnFlag/P73_OnCheckUser; общие точки: P47_LogonMatch зовёт P73_OnLogon, P61_ResetSlotC — P73_OnConnFlag,
#     P48_OnDisconnectType и P58_OnDisconnect — P73_KickInProgress;
#  4) unicorn: каждый стаб с площадки → заглушка C-функции → выход ровно на нужный адрес, аргументы верны, стек и регистры
#     (кроме тех, что стоковые вытесненные команды сами пишут) сохранены; CheckStub: результат 0 → 0x526CF1 с eax=[CUser+0xC],
#     edx=CUser, результат 1 → 0x526E36;
#  ★ ред. 2: площадка REBIND 0x430B10 (`call charLogonCommunityRes_0` 0x5285F0, ответ БД 2145) — байты, соседи, переходы внутрь,
#     трамплин CommunityTramp (call [→0x5285F0] с теми же аргументами и ecx, затем P73_OnCommunityRes, ret 8), unicorn;
#  5) площадка 0x526CEB не пересекается ни с одной площадкой реестра verify_dll.SITES.
#  ★ ред. 3: тип 6 (новое умолчание KickType) — штатный тип стока, имя таблицы 0x5A62AC[6]; цепочка bind по .map и дизасму:
#     P73_OnLogon → P61_SlotBinding (флаг установки P61) → AsdaWire::SlotChannelBinding → ServerChannel/Session::ChannelBinding;
#     экспорт стенда P73_TestSetBind.
#  ★ §8.6 (REVIEW_R3, 16.10): R3-05 — в РАБОЧЕЙ DLL нет ни одного экспорта P73_Test* и символа подмены bind (g_testBind);
#     стендовая сборка out/stand/AsdaPatch.dll (макрос ASDA_PATCH_STAND) их содержит; R3-06 — поколение соединения слота
#     g_slotGen: P73_OnConnFlag его увеличивает (lock inc), P73_OnLogon читает.
# Запуск: python verify_p73.py [AsdaPatch.dll]   (P73_IMG_DIR=<папка с gs_stock.exe/gs_live.exe/gs_indun.exe> — локальные копии)
import hashlib
import os
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe", "4e20f0ad0b13a54454405eed31ffe447"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe", "e7b4ac38"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe", "e7b4ac38"),
]
if os.environ.get("P73_IMG_DIR"):
    d = os.environ["P73_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe", "4e20f0ad0b13a54454405eed31ffe447"),
                 ("живой GameServer", d + "/gs_live.exe", "e7b4ac38"),
                 ("живой Indun", d + "/gs_indun.exe", "e7b4ac38")]

BASE = 0x00400000
# ── площадки (пишутся P73 или общая точка P47/P61) ──
SITES = [
    ("4001 CharLogonReq успех 0x527692 (mov edx,[ebp-0x428])",       0x00527692, "8b95d8fbffff"),
    ("5058 CharPortalLogonReq успех 0x52CD3E (mov eax,[ebp-0x434])", 0x0052CD3E, "8b85ccfbffff"),
    ("Ciocp::SetConnectFlag 0x562910 (push ebp; mov ebp,esp; push -1)", 0x00562910, "558bec6aff"),
    ("CheckDisConnectUser 0x526CEB (mov edx,[ebp-0Ch]; mov eax,[edx+0Ch])", 0x00526CEB, "8b55f48b420c"),
    ("ред. 2: 2145 call charLogonCommunityRes_0 0x430B10",                 0x00430B10, "e8db7a0f00"),
]
# ── соседи (только сверка) ──
NEIGHBOURS = [
    ("возврат 4001 0x527698 (mov ax,[ebp-0x41C])",                 0x00527698, "668b85e4fbffff"),
    ("4001: запись UserIndex в CUser+0x174 0x5276C0",               0x005276C0, "898874010000"),
    ("4001: ветка проверки тела jne 0x527692 @0x52764B",            0x0052764B, "7545"),
    ("4001: UserIndex тела [ebp-0x424] (cmp ...,0) @0x527639",      0x00527639, "83bddcfbffff00"),
    ("возврат 5058 0x52CD44 (mov ecx,[ebp-0x430])",                 0x0052CD44, "8b8dd0fbffff"),
    ("5058: запись UserIndex в CUser+0x174 0x52CD4A",               0x0052CD4A, "898874010000"),
    ("5058: ветка проверки тела jne 0x52CD3E @0x52CCF7",            0x0052CCF7, "7545"),
    ("возврат SetConnectFlag 0x562915 (push 0x5824D8)",             0x00562915, "68d8245800"),
    ("BufferingDisConnect: call SetConnectFlag(slot,0) @0x563C03",  0x00563C03, "e808edffff"),
    ("BufferingAccept: call SetConnectFlag(slot,1) @0x563D1D",      0x00563D1D, "e8eeebffff"),
    ("CheckDisConnectUser: возврат 0x526CF1 (push eax; mov ecx,[ebp-14h]; call 0x524440)", 0x00526CF1, "508b4dece846d7ffff"),
    ("CheckDisConnectUser: цикл 0x526E36 (jmp 0x526C45)",           0x00526E36, "e90afeffff"),
    ("CheckDisConnectUser: [ebp-14h] = CUserManager @0x526C26",     0x00526C26, "894dec"),
    ("CheckDisConnectUser: [ebp-8] = userNum @0x526C8C",            0x00526C8C, "8945f8"),
    ("CheckDisConnectUser: [ebp-0Ch] = CUser @0x526CC2",            0x00526CC2, "8945f4"),
    ("CheckDisConnectUser: +0x174 >= 0 → площадка @0x526CD5",       0x00526CD5, "8b4df483b97401000000"),
    ("CheckDisConnectUser: стоковый кик Secret → jmp 0x526E36 @0x526D25", 0x00526D25, "e90c010000"),
    ("2145: аргументы call (lea edx,[ebp-0x1018]; push; mov ax,[ebp-8]; push; ecx = [[ebp-0x1028]+4]+0x34) @0x430AF8", 0x00430AF8,
     "8d95e8efffff52668b45f8508b8dd8efffff8b51048b4a34"),
    ("2145: после call 0x430B15 (mov ax,[ebp-8] — eax стока не читается)", 0x00430B15, "668b45f8"),
    ("charLogonCommunityRes_0 вход 0x5285F0",                       0x005285F0, "558bec"),
    ("Send_DisConnectType вход 0x52EDB0",                           0x0052EDB0, "558bec83ec08"),
    ("ExceptionDisConnetUser вход 0x526E40",                         0x00526E40, "558bec81ec0c040000"),
]
SITE_LEN = {va: len(h) // 2 for _, va, h in SITES}
BOUNDARIES = {0x00430AD1: [0x00430AF8, 0x00430B10, 0x00430B15],
              0x00527500: [0x00527692, 0x00527698, 0x005276C0, 0x0052764B],
              0x0052CBE0: [0x0052CD3E, 0x0052CD44, 0x0052CD4A, 0x0052CCF7],
              0x00562910: [0x00562910, 0x00562915],
              0x00526C20: [0x00526CEB, 0x00526CF1, 0x00526E36, 0x00526CD5, 0x00526D25, 0x00526C26, 0x00526C8C, 0x00526CC2]}

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    raw = open(path, "rb").read()
    pe = pefile.PE(data=raw)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase, hashlib.md5(raw).hexdigest()


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def scan_into(pe, img, base, ranges):
    """Сколько переходов/абсолютных ссылок ведут СТРОГО ВНУТРЬ (va, va+len) каждой площадки (перебор всех кодировок)."""
    a, b = text_range(pe)
    hits = {n: 0 for n, _, _ in ranges}
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
            for n, va, ln in ranges:
                if va < t < va + ln:
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in ranges:
            if va < v < va + ln:
                hits[n] += 1
    return hits


def boundaries(img, base, start, wanted, span=0x400):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    seen = set(i.address for i in md.disasm(bytes(img[start - base:start - base + span]), start))
    return [w for w in wanted if w not in seen]


def map_syms(path):
    syms = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s", line)
        if m:
            syms[m.group(1)] = int(m.group(2), 16)
    return syms


def find_sym(syms, needle):
    if needle in syms:
        return syms[needle]
    c = [(n, v) for n, v in syms.items() if needle in n]
    return c[0][1] if len(c) == 1 else None


# ═══════════════════════════════ 1. образы ═══════════════════════════════
imgs = []
for name, path, md5want in GS_IMAGES:
    print("-- %s: %s" % (name, path))
    pe, img, base, md5 = load(path)
    ok(base == BASE, "ImageBase 0x%08X" % base)
    ok(md5.startswith(md5want), "md5 %s (ожидалось %s…)" % (md5, md5want))
    for n, va, hexs in SITES + NEIGHBOURS:
        got = bytes(img[va - base:va - base + len(hexs) // 2]).hex()
        ok(got == hexs, "%s: %s" % (n, got))
    hits = scan_into(pe, img, base, [(n, va, SITE_LEN[va]) for n, va, _ in SITES])
    for n, h in hits.items():
        ok(h == 0, "ссылок внутрь площадки «%s»: %d" % (n.split(" (")[0], h))
    for start, wanted in BOUNDARIES.items():
        miss = boundaries(img, base, start, wanted, 0x500)
        ok(not miss, "границы инструкций от 0x%08X: %s" % (start, "все на месте" if not miss else ["0x%08X" % m for m in miss]))
    imgs.append((name, pe, img, base))
for lo, hi in ((0x430AD1, 0x430B40), (0x5285F0, 0x528780), (0x526C20, 0x526E40), (0x527500, 0x5277D0), (0x52CBE0, 0x52CF90), (0x562910, 0x562990)):
    ok(all(bytes(imgs[0][2][lo - BASE:hi - BASE]) == bytes(i[2][lo - BASE:hi - BASE]) for i in imgs),
       "функция 0x%06X..0x%06X побайтно одинакова на всех образах" % (lo, hi))

# ═══════════════════════════════ 2. тип 12 стоком не шлётся ═══════════════════════════════
print("-- тип 4101 для кика P73")
name, pe, img, base = imgs[0]
a, b = text_range(pe)
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.skipdata = True
ins = list(md.disasm(bytes(img[a:b]), base + a))
types = []
for i, x in enumerate(ins):
    if x.mnemonic == "call" and x.op_str == "0x52edb0":
        pushes = [y for y in ins[max(0, i - 8):i] if y.mnemonic == "push"]
        if pushes:
            types.append((x.address, pushes[0].op_str))
tset = sorted(set(t for _, t in types))
ok(len(types) == 21, "вызовов Send_DisConnectType в .text стока: %d (ожидалось 21)" % len(types))
ok("0xc" not in tset and "12" not in tset, "тип 12 стоком не шлётся; типы стока: %s" % tset)
tbl = struct.unpack("<I", bytes(img[0x1A62AC + 12 * 4:0x1A62AC + 13 * 4]))[0]
nm12 = bytes(img[tbl - base:tbl - base + 16]).split(b"\0")[0]
ok(nm12 == b"HackShield", "таблица 0x5A62AC[12] = %r" % nm12)
# ★ ред. 3 (E1-07): умолчание KickType = 6 — штатный тип стока (клиент: нотис 1106); P48 его не считает только за счёт P73_KickInProgress
tbl6 = struct.unpack("<I", bytes(img[0x1A62AC + 6 * 4:0x1A62AC + 7 * 4]))[0]
nm6 = bytes(img[tbl6 - base:tbl6 - base + 16]).split(b"\0")[0]
ok("0x6" in tset or "6" in tset, "ред. 3: тип 6 — штатный тип стока (есть среди типов вызовов)")
print("     таблица 0x5A62AC[6] = %r (имя причины в Log_RoseWar/P58 стока)" % nm6)

# ═══════════════════════════════ 3. DLL ═══════════════════════════════
print("-- DLL: %s" % DLL)
dpe = pefile.PE(DLL)
dimg = bytearray(dpe.get_memory_mapped_image())
dbase = dpe.OPTIONAL_HEADER.ImageBase
syms = map_syms(MAP)
S = {k: find_sym(syms, k) for k in ("CommunityTramp", "_P73_OnCommunityRes@8", "g_pCommunityRes", "Logon4001Stub", "Logon5058Stub", "SetConnStub", "CheckStub", "_P73_OnLogon@16",
                                    "_P73_OnConnFlag@8", "_P73_OnCheckUser@12", "P73_KickInProgress", "_P47_LogonMatch@16",
                                    "_P61_ResetSlotC", "_P48_OnDisconnectType@16", "_P58_OnDisconnect@16",
                                    "g_ret4001@?A", "g_ret5058@?A", "g_retConn", "g_retCheck", "g_retLoop")}
# g_ret4001/g_ret5058 есть и у P47 — берём именно из p73 (по .map с именем объекта)
for line in open(MAP, encoding="utf-8", errors="replace"):
    m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s.*p73_eac_bridge\.obj", line)
    if m and ("?g_ret4001@" in m.group(1) or "?g_ret5058@" in m.group(1)):
        S["g_ret4001@?A" if "4001" in m.group(1) else "g_ret5058@?A"] = int(m.group(2), 16)
missing = [k for k, v in S.items() if v is None]
ok(not missing, "по .map найдены все символы P73 и общих точек%s" % ("" if not missing else ": НЕТ " + str(missing)))
exports = {e.name.decode() for e in dpe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
ok(any("P73_GetStats" in n for n in exports), "экспорт статистики P73_GetStats есть")
# ★ §8.6 R3-05: тестовые экспорты и подмена bind — только в стендовой сборке
TEST_EXP = ("P73_TestEncode", "P73_TestDecode", "P73_TestKick", "P73_TestSweep", "P73_TestSetBind", "P73_TestLogonHook")
leak = sorted(n for n in exports if "P73_Test" in n)
ok(not leak, "§8.6 R3-05: рабочая DLL НЕ экспортирует P73_Test*%s" % ("" if not leak else ": ЕСТЬ " + str(leak)))
map_txt = open(MAP, encoding="utf-8", errors="replace").read()
ok("g_testBind" not in map_txt and "P73_Test" not in map_txt and "g_testLogonHook" not in map_txt,
   "§8.6 R3-05: в .map рабочей DLL нет символов стенда (g_testBind, g_testLogonHook, P73_Test*)")
SDLL = os.path.join(os.path.dirname(DLL), "stand", "AsdaPatch.dll")
if os.path.exists(SDLL):
    spe = pefile.PE(SDLL)
    sexp = {e.name.decode() for e in spe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    miss = [t for t in TEST_EXP if not any(t in n for n in sexp)]
    ok(not miss, "§8.6 R3-05: стендовая DLL %s экспортирует %s%s" % (SDLL, "/".join(TEST_EXP), "" if not miss else ": НЕТ " + str(miss)))
    base_exp = {n for n in exports}
    # ★ 18.11.2026: у стенда P127 (мост админ-центра) свои тестовые экспорты P127_Test* — тоже только в стендовой сборке
    # ★ 22.11.2026 (P129, А6.12): + P128_Test* (стенд P128, v85 — проверка их не знала) и P129_Test* (стенд P129) — тоже только в стенде
    _stand_only = ("P73_Test", "P127_Test", "P75_Test", "P128_Test", "P129_Test")
    ok(base_exp <= sexp and {n for n in sexp if not any(t in n for t in _stand_only)} == base_exp,   # ★ 18.11: + P75_TestSkip (стенд P127)
       "§8.6 R3-05: стендовая DLL отличается от рабочей по экспортам только P73_Test*/P127_Test*/P75_Test*/P128_Test*/P129_Test* (%d против %d)" % (len(sexp), len(base_exp)))
    ok(not any("P127_Test" in n for n in exports), "рабочая DLL НЕ экспортирует P127_Test*")
    ok(not any("P128_Test" in n or "P129_Test" in n for n in exports), "рабочая DLL НЕ экспортирует P128_Test* / P129_Test*")
else:
    print("     стендовой DLL %s нет — проверка её экспортов пропущена (build.bat собирает обе)" % SDLL)


def rd32(va):
    return struct.unpack("<I", bytes(dimg[va - dbase:va - dbase + 4]))[0]


def dis(va, n=0x50):
    return list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(bytes(dimg[va - dbase:va - dbase + n]), va))


def calls_in(va, n=0x400):
    out = []
    for x in Cs(CS_ARCH_X86, CS_MODE_32).disasm(bytes(dimg[va - dbase:va - dbase + n]), va):
        if x.mnemonic == "call" and x.op_str.startswith("0x"):
            out.append(int(x.op_str, 16))
        if x.mnemonic == "int3":
            break
    return out


if not missing:
    want = {"g_ret4001@?A": 0x00527698, "g_ret5058@?A": 0x0052CD44, "g_retConn": 0x00562915, "g_retCheck": 0x00526CF1, "g_retLoop": 0x00526E36}
    for k, v in want.items():
        ok(rd32(S[k]) == v, "указатель %s в .data = 0x%08X (ожидалось 0x%08X)" % (k, rd32(S[k]), v))
    ok(rd32(S["g_pCommunityRes"]) == 0x005285F0, "указатель g_pCommunityRes = 0x%08X (ожидалось 0x5285F0)" % rd32(S["g_pCommunityRes"]))
    body = []
    for x in dis(S["CommunityTramp"], 0x60):
        body.append(x)
        if x.mnemonic == "ret":
            break
    print("     CommunityTramp: %s" % " ; ".join("%s %s" % (x.mnemonic, x.op_str) for x in body))
    ind = [x for x in body if x.mnemonic == "call" and "dword ptr [" in x.op_str]
    dirc = [x for x in body if x.mnemonic == "call" and x.op_str.startswith("0x")]
    ok(len(ind) == 1 and int(ind[0].op_str.split("[")[1].rstrip("]"), 16) == S["g_pCommunityRes"], "CommunityTramp: call dword ptr [g_pCommunityRes] (сток)")
    ok(len(dirc) == 1 and int(dirc[0].op_str, 16) == S["_P73_OnCommunityRes@8"], "CommunityTramp: затем call P73_OnCommunityRes")
    ok(body[-1].mnemonic == "ret" and body[-1].op_str == "8", "CommunityTramp: ret 8 (как сток thiscall с 2 аргументами)")
    for stub, callee, jmps in (("Logon4001Stub", "_P73_OnLogon@16", ["g_ret4001@?A"]), ("Logon5058Stub", "_P73_OnLogon@16", ["g_ret5058@?A"]),
                               ("SetConnStub", "_P73_OnConnFlag@8", ["g_retConn"]), ("CheckStub", "_P73_OnCheckUser@12", ["g_retCheck", "g_retLoop"])):
        body = []
        for x in dis(S[stub], 0x60):
            body.append(x)
            if x.mnemonic == "int3":
                break
        print("     %s: %s" % (stub, " ; ".join("%s %s" % (x.mnemonic, x.op_str) for x in body if x.mnemonic != "int3")))
        cl = [x for x in body if x.mnemonic == "call"]
        ok(len(cl) == 1 and int(cl[0].op_str, 16) == S[callee], "%s: единственный call → %s" % (stub, callee))
        jt = sorted(int(x.op_str.split("[")[1].rstrip("]"), 16) for x in body if x.mnemonic == "jmp" and "dword ptr [" in x.op_str)
        ok(jt == sorted(S[j] for j in jmps), "%s: jmp dword ptr [..] → %s" % (stub, jmps))
        ok(body[0].mnemonic == "pushal" and any(x.mnemonic == "popal" for x in body), "%s: pushad … popad" % stub)
    ok(S["_P73_OnLogon@16"] in calls_in(S["_P47_LogonMatch@16"]), "общая точка: P47_LogonMatch зовёт P73_OnLogon")
    ok(S["_P73_OnConnFlag@8"] in calls_in(S["_P61_ResetSlotC"]), "общая точка: P61_ResetSlotC зовёт P73_OnConnFlag")
    ok(S["P73_KickInProgress"] in calls_in(S["_P48_OnDisconnectType@16"], 0x800), "P48_OnDisconnectType зовёт P73_KickInProgress (не засчитывать)")
    ok(S["P73_KickInProgress"] in calls_in(S["_P58_OnDisconnect@16"], 0x300), "P58_OnDisconnect зовёт P73_KickInProgress (имя «EAC(P73)»)")

# ═══════════════════════════════ 3а. ред. 3: источник bind (P61 → мост AsdaWire → ServerChannel) ═══════════════════════════════
print("-- ред. 3: цепочка bind")
B = {k: find_sym(syms, k) for k in ("?P61_SlotBinding@@", "?SlotChannelBinding@AsdaWire@@", "?ChannelBinding@ServerChannel@AsdaSecure@@",
                                    "?ChannelBinding@Session@AsdaSecure@@")}
bmiss = [k for k, v in B.items() if v is None]
ok(not bmiss, "по .map найдены символы цепочки bind%s" % ("" if not bmiss else ": НЕТ " + str(bmiss)))
# ★ §8.6 R3-06: поколение соединения слота (g_slotGen) — P73_OnConnFlag увеличивает под замком (lock inc / lock xadd), P73_OnLogon читает
gen_va = None
for line in open(MAP, encoding="utf-8", errors="replace"):
    m = re.match(r"\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s.*p73_eac_bridge\.obj", line)
    if m and "?g_slotGen@" in m.group(1):
        gen_va = int(m.group(2), 16)
ok(gen_va is not None, "§8.6 R3-06: символ g_slotGen (поколение соединения слота) есть в .map")
if gen_va is not None and not missing:
    def touches(fn_va, n=0x400):
        out = []
        for x in Cs(CS_ARCH_X86, CS_MODE_32).disasm(bytes(dimg[fn_va - dbase:fn_va - dbase + n]), fn_va):
            if x.mnemonic == "int3":
                break
            for mm in re.finditer(r"0x([0-9a-f]+)", x.op_str):
                v = int(mm.group(1), 16)
                if gen_va <= v < gen_va + 0x226 * 4:
                    out.append(x)
        return out
    cf = touches(S["_P73_OnConnFlag@8"])
    # адрес элемента может считаться lea, а инкремент идти по регистру: смотрим саму команду и 8 следующих
    body = []
    for x in Cs(CS_ARCH_X86, CS_MODE_32).disasm(bytes(dimg[S["_P73_OnConnFlag@8"] - dbase:S["_P73_OnConnFlag@8"] - dbase + 0x400]), S["_P73_OnConnFlag@8"]):
        if x.mnemonic == "int3":
            break
        body.append(x)
    idx = [i for i, x in enumerate(body) if any(x.address == y.address for y in cf)]
    incs = [body[j] for i in idx for j in range(i, min(i + 9, len(body)))
            if any(k in body[j].mnemonic for k in ("inc", "xadd")) and ("lock" in body[j].mnemonic or body[j].bytes[0] == 0xF0)]
    ok(bool(incs), "§8.6 R3-06: P73_OnConnFlag увеличивает g_slotGen[slot] атомарно (%s → %s)" % (
        "; ".join("%s %s" % (x.mnemonic, x.op_str) for x in cf), "; ".join("%s %s" % (x.mnemonic, x.op_str) for x in incs)))
    lo = touches(S["_P73_OnLogon@16"], 0x600)
    ok(len(lo) >= 2, "§8.6 R3-06: P73_OnLogon читает g_slotGen до SlotBind и сверяет под замком (обращений %d)" % len(lo))
if not bmiss and not missing:
    # P73_OnLogon → (SlotBind, может быть встроен) → P61_SlotBinding
    lc = calls_in(S["_P73_OnLogon@16"], 0x600)
    direct = B["?P61_SlotBinding@@"] in lc
    nested = any(B["?P61_SlotBinding@@"] in calls_in(c, 0x200) for c in lc if dbase <= c < dbase + len(dimg))
    ok(direct or nested, "P73_OnLogon зовёт P61_SlotBinding (%s)" % ("напрямую" if direct else "через SlotBind"))
    tails = [int(x.op_str, 16) for x in dis(B["?P61_SlotBinding@@"], 0x40) if x.mnemonic in ("call", "jmp") and x.op_str.startswith("0x")]
    ok(B["?SlotChannelBinding@AsdaWire@@"] in tails, "P61_SlotBinding зовёт AsdaWire::SlotChannelBinding (call или хвостовой jmp)")
    sc = calls_in(B["?SlotChannelBinding@AsdaWire@@"], 0x300)
    ok(B["?ChannelBinding@ServerChannel@AsdaSecure@@"] in sc or B["?ChannelBinding@Session@AsdaSecure@@"] in sc,
       "AsdaWire::SlotChannelBinding зовёт ServerChannel/Session::ChannelBinding")
    # P61_SlotBinding: первым делом сверяет g_setConnPlaced (P61 поставлен целиком)
    p61b = dis(B["?P61_SlotBinding@@"], 0x30)
    print("     P61_SlotBinding: %s" % " ; ".join("%s %s" % (x.mnemonic, x.op_str) for x in p61b[:8]))
    ok(any(x.mnemonic == "cmp" and "byte ptr [" in x.op_str for x in p61b[:6]), "P61_SlotBinding: проверка флага установки P61 (cmp byte [g_setConnPlaced])")

# ═══════════════════════════════ 4. unicorn ═══════════════════════════════
REGS = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI]
SENT = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666]
FRM, STK, MGR = 0x00200000, 0x00300000, 0x00210000
name, pe, img, base = imgs[1]


def mk():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (len(img) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(base, bytes(img))
    uc.mem_map(dbase, (len(dimg) + 0xFFFF) & ~0xFFFF)
    uc.mem_write(dbase, bytes(dimg))
    uc.mem_map(FRM, 0x40000)
    uc.mem_map(STK, 0x100000)
    return uc


def run(site, stub, callee, retbytes, ret_eax, ebp_fill, ends, setup_stack=None):
    """Площадка → стаб → заглушка C-функции (mov eax,ret_eax; ret N) → один из ends. Возврат: (адрес выхода, аргументы, uc, esp0, ebp)."""
    uc = mk()
    uc.mem_write(site, b"\xE9" + struct.pack("<i", stub - (site + 5)) + b"\x90" * (SITE_LEN[site] - 5))
    uc.mem_write(callee, b"\xB8" + struct.pack("<I", ret_eax) + b"\xC2" + struct.pack("<H", retbytes))
    ebp = FRM + 0x8000
    for off, val in ebp_fill:
        uc.mem_write(ebp + off, struct.pack("<I", val))
    esp0 = STK + 0x80000
    if setup_stack:
        esp0 = setup_stack(uc, esp0)
    for r, v in zip(REGS, SENT):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp0)
    st = {"end": None, "args": None, "n": 0}

    def hook(u, addr, size, _):
        st["n"] += 1
        if addr == callee:
            sp = u.reg_read(UC_X86_REG_ESP)
            st["args"] = struct.unpack("<%dI" % (retbytes // 4), u.mem_read(sp + 4, retbytes))
        if addr in ends:
            st["end"] = addr
            u.emu_stop()
        if st["n"] > 300:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(site, 0, timeout=2000000)
    return st["end"], st["args"], uc, esp0, ebp


if not missing:
    print("-- unicorn: стаб 4001 (0x527692)")
    end, args, uc, esp0, ebp = run(0x00527692, S["Logon4001Stub"], S["_P73_OnLogon@16"], 16, 0,
                                   [(-0x424, 75001), (-0x428, 0x00ABC000), (8, 0xBEEF0007)], [0x00527698])
    ok(end == 0x00527698, "выход на 0x527698")
    ok(args == (1, 7, 0x00ABC000, 75001), "P73_OnLogon(kind 1, userNum 7, CUser, UserIndex 75001): %s" % (args,))
    ok(uc.reg_read(UC_X86_REG_ESP) == esp0 and uc.reg_read(UC_X86_REG_EDX) == 0x00ABC000, "стек сбалансирован, edx = [ebp-0x428] (вытесненная команда)")
    ok([uc.reg_read(r) for r in REGS if r != UC_X86_REG_EDX] == [v for r, v in zip(REGS, SENT) if r != UC_X86_REG_EDX], "прочие регистры сохранены")

    print("-- unicorn: стаб 5058 (0x52CD3E)")
    end, args, uc, esp0, ebp = run(0x0052CD3E, S["Logon5058Stub"], S["_P73_OnLogon@16"], 16, 0,
                                   [(-0x430, 75002), (-0x434, 0x00ABD000), (8, 0x0000FFF0 | 0x0B)], [0x0052CD44])
    ok(end == 0x0052CD44, "выход на 0x52CD44")
    ok(args == (2, 0xFFFFFFFB, 0x00ABD000, 75002),
       "P73_OnLogon(kind 2, userNum movsx(0xFFFB) = −5, CUser, UserIndex 75002): %s" % (args,))
    ok(uc.reg_read(UC_X86_REG_ESP) == esp0 and uc.reg_read(UC_X86_REG_EAX) == 0x00ABD000, "стек сбалансирован, eax = [ebp-0x434] (вытесненная команда)")

    print("-- unicorn: детур SetConnectFlag (0x562910)")
    RET = 0x00401000

    def setup_conn(uc, esp):
        # thiscall(this=ecx, i16 slot, int flag): [esp] возврат, [esp+4] slot (старшее слово — мусор), [esp+8] flag
        esp -= 12
        uc.mem_write(esp, struct.pack("<III", RET, 0xDEAD0000 | 42, 0))
        return esp
    end, args, uc, esp0, ebp = run(0x00562910, S["SetConnStub"], S["_P73_OnConnFlag@8"], 8, 0, [], [0x00562915], setup_conn)
    ok(end == 0x00562915, "выход на 0x562915 (тело SetConnectFlag после украденного пролога)")
    ok(args == (42, 0), "P73_OnConnFlag(slot 42, flag 0): %s" % (args,))
    sp = uc.reg_read(UC_X86_REG_ESP)
    top = struct.unpack("<III", uc.mem_read(sp, 12))
    ok(sp == esp0 - 8 and uc.reg_read(UC_X86_REG_EBP) == esp0 - 4 and top == (0xFFFFFFFF, ebp, RET),
       "кадр как после стокового пролога: [esp]=-1, [esp+4]=старый ebp, [esp+8]=возврат; ebp=esp0-4")
    ok([uc.reg_read(r) for r in REGS] == SENT, "все регистры (eax/ecx/edx — как на входе) сохранены")

    print("-- unicorn: CheckStub (0x526CEB)")
    CUSER = 0x00220000

    def setup_user(uc, esp):
        # CUSER лежит в отображённой области кадра FRM
        uc.mem_write(CUSER + 0x0C, struct.pack("<I", 0x0000007B))
        return esp
    fill = [(-0x14, MGR), (-0x08, 0xFFFF0000 | 123), (-0x0C, CUSER)]
    end, args, uc, esp0, ebp = run(0x00526CEB, S["CheckStub"], S["_P73_OnCheckUser@12"], 12, 0, fill, [0x00526CF1, 0x00526E36], setup_user)
    ok(end == 0x00526CF1, "результат 0 → продолжение стока 0x526CF1")
    ok(args == (MGR, 123, CUSER), "P73_OnCheckUser(mgr, userNum movsx 123, CUser): %s" % (args,))
    ok(uc.reg_read(UC_X86_REG_EDX) == CUSER and uc.reg_read(UC_X86_REG_EAX) == 0x7B and uc.reg_read(UC_X86_REG_ESP) == esp0,
       "вытесненные команды: edx = CUser, eax = [CUser+0xC] = 0x7B; стек сбалансирован")
    ok([uc.reg_read(r) for r in (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_ESI, UC_X86_REG_EDI)] == [SENT[1], SENT[2], SENT[4], SENT[5]],
       "ebx/ecx/esi/edi сохранены")
    end, args, uc, esp0, ebp = run(0x00526CEB, S["CheckStub"], S["_P73_OnCheckUser@12"], 12, 1, fill, [0x00526CF1, 0x00526E36], setup_user)
    ok(end == 0x00526E36 and uc.reg_read(UC_X86_REG_ESP) == esp0, "результат 1 (выведен) → цикл 0x526E36, стек сбалансирован")

if not missing:
    print("-- unicorn: ред. 2 — площадка 2145 0x430B10 → CommunityTramp")
    uc = mk()
    tr = S["CommunityTramp"]
    uc.mem_write(0x00430B10, b"\xE8" + struct.pack("<i", tr - (0x00430B10 + 5)))
    STOCKR = 0x005285F0
    uc.mem_write(STOCKR, b"\xB8\x77\x77\x77\x77\xC2\x08\x00")                       # сток: mov eax,0x77777777; ret 8
    cb = S["_P73_OnCommunityRes@8"]
    uc.mem_write(cb, b"\xB8\x00\x00\x00\x00\xC2\x08\x00")                           # P73_OnCommunityRes: ret 8
    ebp = FRM + 0x8000
    THR, OBJ = FRM + 0x100, FRM + 0x200
    uc.mem_write(ebp - 0x08, struct.pack("<I", 0xABCD0000 | 21))
    uc.mem_write(ebp - 0x1028, struct.pack("<I", OBJ))
    uc.mem_write(OBJ + 4, struct.pack("<I", THR))
    uc.mem_write(THR + 0x34, struct.pack("<I", MGR))
    esp0 = STK + 0x80000
    for r, v in zip(REGS, SENT):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp0)
    st = {"stock": None, "cb": None, "end": False, "n": 0}

    def hk(u, addr, size, _):
        st["n"] += 1
        sp = u.reg_read(UC_X86_REG_ESP)
        if addr == STOCKR:
            st["stock"] = (u.reg_read(UC_X86_REG_ECX),) + struct.unpack("<II", u.mem_read(sp + 4, 8))
        if addr == cb:
            st["cb"] = struct.unpack("<II", u.mem_read(sp + 4, 8))
        if addr == 0x00430B15:
            st["end"] = True
            u.emu_stop()
        if st["n"] > 300:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hk)
    uc.emu_start(0x00430AF8, 0, timeout=2000000)
    ok(st["stock"] is not None and st["stock"][0] == MGR and (st["stock"][1] & 0xFFFF) == 21 and st["stock"][2] == ebp - 0x1018,
       "сток charLogonCommunityRes_0 вызван с ecx=CUserManager, userNum (младшее слово; старшее — мусор eax, как в стоке), пакетом [ebp-0x1018]: %s"
       % (st["stock"],))
    ok(st["cb"] == (MGR, 21), "затем P73_OnCommunityRes(CUserManager, userNum movsx 21): %s" % (st["cb"],))
    ok(st["end"] and uc.reg_read(UC_X86_REG_ESP) == esp0, "выход на 0x430B15, стек сбалансирован")
    ok(uc.reg_read(UC_X86_REG_EAX) == 0x77777777 and uc.reg_read(UC_X86_REG_EBX) == SENT[1] and uc.reg_read(UC_X86_REG_ESI) == SENT[4]
       and uc.reg_read(UC_X86_REG_EDI) == SENT[5], "eax = итог стока, ebx/esi/edi сохранены")

# ═══════════════════════════════ 5. пересечения с площадками других патчей ═══════════════════════════════
#   Единого реестра площадок нет: собираем пары (VA, байты сверки) из ВСЕХ verify_*.py (кроме этого) и из исходников патчей
#   (массивы Site: адрес + sizeof оригинала по объявлению kOrig*). Новая площадка P73 — только 0x526CEB (6 б); 0x527692/0x52CD3E/
#   0x562910 — общие точки P47/P61 (P73 пишет их только когда P47/P61 их не поставили).
print("-- пересечения новой площадки 0x526CEB..0x526CF0 с площадками/соседями других патчей")
spans = []
for fn in sorted(os.listdir(HERE)):
    if not (fn.startswith("verify_") and fn.endswith(".py")) or fn == "verify_p73.py":
        continue
    txt = open(os.path.join(HERE, fn), encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"(0x00[0-9A-Fa-f]{6}),\s*\"([0-9a-fA-F ]{2,})\"", txt):
        va = int(m.group(1), 16)
        n = len(m.group(2).replace(" ", "")) // 2
        spans.append((va, va + n, fn))
src = os.path.join(HERE, "..", "src", "patches")
for fn in sorted(os.listdir(src)):
    if not fn.endswith(".cpp") or fn.startswith("p73_"):
        continue
    txt = open(os.path.join(src, fn), encoding="utf-8", errors="replace").read()
    arrays = {m.group(1): int(m.group(2)) for m in re.finditer(r"BYTE\s+(k\w+)\[(\d+)\]\s*=", txt)}
    for m in re.finditer(r"\{\s*(0x00[0-9A-Fa-f]{6})\s*,\s*(k\w+)\s*,", txt):
        if m.group(2) in arrays:
            va = int(m.group(1), 16)
            spans.append((va, va + arrays[m.group(2)], fn))
clash = sorted(set(f for a0, a1, f in spans if (a0 < 0x00526CEB + 6 and 0x00526CEB < a1) or (a0 < 0x00430B10 + 5 and 0x00430B10 < a1)))
ok(len(spans) > 300, "собрано пар (VA, длина) из verify_*.py и src/patches: %d" % len(spans))
ok(not clash, "0x526CEB..0x526CF0 и 0x430B10..0x430B14 не пересекаются ни с одной площадкой/соседом других патчей%s" % ("" if not clash else ": " + str(clash)))
near = sorted(set("%s 0x%08X" % (f, a0) for a0, a1, f in spans if 0x00526C20 <= a0 < 0x00526E40))
print("     в CheckDisConnectUser 0x526C20..0x526E40 другие патчи держат: %s" % (near if near else "ничего"))
near = sorted(set("%s 0x%08X" % (f, a0) for a0, a1, f in spans if 0x00430AD1 <= a0 < 0x00430B40 or 0x005285F0 <= a0 < 0x00528780))
print("     в ветке 2145 0x430AD1..0x430B40 и в 0x5285F0..0x528780 другие патчи держат: %s" % (near if near else "ничего"))

print("== ИТОГ verify_p73: ошибок %d ==" % bad)
sys.exit(1 if bad else 0)
