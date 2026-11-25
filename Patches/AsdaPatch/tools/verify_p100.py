# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p100.py — СТАТИЧЕСКАЯ проверка P100_ChargeStack «заряды спецпредметов складываются при получении» (01.11.2026, AsdaPatch v57).
#   Логику на НАСТОЯЩИХ обработчиках проверяет stand_p100. Проект: Reports/item_dedup/charges/P100_PROJECT.md, CHARGES_RE.md §2.1.
#   Ревизия 02.11: + площадка 0x4CE562 (CharItemMove, `call sub_52BFF0` «занят» — отказ 18 для ячейки с зарядами в полёте) и
#   соседи кадра перемещения / веса A3; отказ 18 — стоковое тело 0x4CE56E.
#   1. Образы GameServer (сток 4e20f0ad; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — stack_layout.EXE_MD5):
#      площадки (45 call E8 rel32 на sub_4D6740 / sub_4D63F0 / sub_4D6540 / sub_4D7CD0 / sub_4D6A70, 5 чтений FT+13, точка гачи
#      0x4F4F7B) и соседи — те же байты, что сверяет сама DLL; каждая площадка — начало инструкции (линейный проход от начала
#      функции по декомпилу); переходов внутрь площадки нет; окна ±32 б одинаковы на 4 образах.
#   2. Вторым методом: каждая площадка лежит в той функции, что указана в разборе (границы функций — GameServer.c); перед каждым
#      чтением FT+13 — загрузка dword_5F5E70 и `imul …,30h`; полный перебор чтений FT+13 (`movzx …,byte [r+r+0Dh]` после
#      [0x5F5E70]) в образе — ровно 7, из них 5 — площадки P100, 0x5127ED (CharChargeShopBuy → GP7) и 0x5136DA (подарок — P101)
#      не трогаются; адреса возврата sub_5340B0, по которым P100 различает вызывающих, — настоящие (call sub_5340B0 за 5 б до них).
#   3. Исходник DLL: таблица kCalls (адрес → цель) = таблица этого скрипта; соседи и FT+13 в apply совпадают; секция ini,
#      kVersion = шаблон Version = 57; реестр — P100 после P99; ac.other 153–157 заняты только P100; .map — трамплины и экспорты.
#   4. Пересечения: ни один адрес площадок P16/P62/P95/P96/P97/P98 (и прочих патчей src/patches, по тексту) не попадает внутрь
#      площадок P100.
#   5. Данные: tools/p100_data/charge_groups.txt — заголовок, ft_md5 = md5 зеркала живой FT, 637/173/63, 505/506/515 = 300 зарядов.
# Запуск: py -3.13 verify_p100.py [AsdaPatch.dll]
import bisect
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
GSC = r"@@ASTORY_DEV_ROOT@@\RE\ida\server_work\GameServer.c"
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
LIVE = "e7b4ac38e8328aaa847bbd9bf261bb01"
IMAGES = [("сток GameServer", os.path.join(IMG, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447")] + \
         [("живой " + d, os.path.join(SRV, "v2", d, "GameServer.exe"), LIVE) for d in stack_layout.GS_FOLDERS]
FT_MIRROR = os.path.join(SRV, "v2", "GameServer", "ItemTable_Info", "Function_Table.txt")
CG = os.path.join(HERE, "p100_data", "charge_groups.txt")
H = bytes.fromhex
ROUTER, WRITE, ERASE, ROOM, COUNT, BUSY = 0x4D6740, 0x4D63F0, 0x4D6540, 0x4D7CD0, 0x4D6A70, 0x52BFF0
GETCELL, ISF, DBSEND = 0x4D61E0, 0x532B10, 0x5646C0
# адрес, цель, функция (по GameServer.c)
CALLS = [
    (0x53460C, ROUTER, "sub_5340B0"), (0x4F882E, ROUTER, "Recv_PremiumItemToInven_Req"), (0x4F8BA3, ROUTER, "sub_4F89D0"),
    (0x5525B0, ROUTER, "Recv_OperatorCommand_ItemGive"), (0x515D16, ROUTER, "CharRoseWarStoreBuy"), (0x55BD73, ROUTER, "sub_55B7F0"),
    (0x45F0B2, ROUTER, "sub_45DEE0"), (0x4E531C, ROUTER, "CharShellItemExchangeComplete"), (0x4E5B40, ROUTER, "CharShellItemExchangeComplete"),
    (0x4E6348, ROUTER, "CharShellItemExchangeComplete"), (0x4E6B5D, ROUTER, "CharShellItemExchangeComplete"), (0x505DBC, ROUTER, "CharSelfStoreBuyItem"),
    (0x51BB2D, ROUTER, "recvTransActionBuyItemRes"), (0x51EEFA, ROUTER, "recvTransActionDeleteItemRes"), (0x4FE715, ROUTER, "Recv_User_Disassemble"),
    (0x469362, ROUTER, "sub_469010"), (0x50B9C6, ROUTER, "CharItemRetake"),
    # ★ P102 (02.11): экипировка лота аукциона — тот же afterSlot, что у F-лотов (исправление ошибки P100 v57 на 9906/9910)
    (0x51CC90, ROUTER, "recvTransActionBuyItemRes"), (0x52001E, ROUTER, "recvTransActionDeleteItemRes"),
    (0x4F8CCE, WRITE, "sub_4F89D0"), (0x4F5813, WRITE, "sendGachaItemUse"), (0x53402B, WRITE, "recvUserCashKey"),
    (0x5533A6, WRITE, "Recv_OperatorCommand_ItemGive"), (0x516A5A, WRITE, "sub_5168B0"), (0x55B483, WRITE, "sub_55B1C0"),
    (0x559E57, WRITE, "sub_559900"), (0x45F1DF, WRITE, "sub_45DEE0"), (0x410988, WRITE, "sub_4107C0"), (0x4135AE, WRITE, "sub_4134A0"),
    (0x469DDF, WRITE, "sub_469A00"), (0x50CE93, WRITE, "sendCharItemRetake"), (0x507055, WRITE, "sub_506A00"),
    (0x51BE0C, WRITE, "recvTransActionBuyItemRes"), (0x51F1DC, WRITE, "recvTransActionDeleteItemRes"),
    (0x4E91D2, WRITE, "recvDBCharShellExchangeComplelte"), (0x4E977D, WRITE, "recvDBCharShellExchangeComplelte"),
    (0x4E9FCE, WRITE, "recvDBCharShellExchangeComplelte"), (0x4EA579, WRITE, "recvDBCharShellExchangeComplelte"),
    (0x51DBAC, ERASE, "recvDBTransActionBuyItemRes"), (0x520A74, ERASE, "recvDBTransActionDeleteItemRes"),
    (0x45F066, ROOM, "sub_45DEE0"),
    (0x4E4DFE, COUNT, "CharShellItemExchangeComplete"), (0x4E4E29, COUNT, "CharShellItemExchangeComplete"), (0x505ACE, COUNT, "CharSelfStoreBuyItem"),
    (0x51BA5A, COUNT, "recvTransActionBuyItemRes"), (0x51B10F, COUNT, "Recv_TransAction_BuyItemReq"), (0x51EA3E, COUNT, "Recv_TransAction_DeleteItemReq"),
    (0x4CE562, BUSY, "CharItemMove"),   # ревизия 02.11: перемещение ячейки с зарядами в полёте — отказ 18
    # ревизия 02.11 (б): все операции, убирающие ячейку сумки, — стоковый отказ при слиянии в полёте; разборка — вес штуки
    (0x4FEBBC, WRITE, "sub_4FE900"),
    (0x4D353C, BUSY, "CharItemDump"), (0x50961E, BUSY, "CharItemKeeping"), (0x50D463, BUSY, "CharItemSell"),
    (0x4DD76A, BUSY, "CharShellItemVanish"), (0x50300E, BUSY, "CharSelfStoreOpen"), (0x50302A, BUSY, "CharSelfStoreOpen"),
    (0x4F34E7, BUSY, "RecvClient_FunctionItem_Meet"), (0x4F3B03, BUSY, "sub_4F39D0"), (0x4F2A32, BUSY, "RecvClient_FunctionItem_Summon"),
    (0x41191E, BUSY, "Recv_FishingBookRegist"),
    (0x4E1CB9, GETCELL, "CharExchangeDragDropItem"), (0x517EC6, GETCELL, "Recv_TransAction_RegistItemReq"), (0x4EDD35, GETCELL, "Char_FunctionItem_Use"),
    (0x4F32C0, GETCELL, "sub_4F3230"), (0x4FF180, GETCELL, "CharShellItemUpgrade_0"), (0x50115F, GETCELL, "Recv_User_ShellItemUpgradeReset"),
    (0x45A49E, GETCELL, "RecvClient_PetMaxLevelUp"), (0x45A6D0, GETCELL, "RecvClient_PetMaxLevelUp"), (0x459DC8, GETCELL, "Recv_PetPossessionCountUp_Req"),
    (0x45524C, GETCELL, "Recv_IncubatorReq"), (0x4578BA, GETCELL, "Recv_PetConditionUp"), (0x4F741D, GETCELL, "Recv_UserPrimiumGaChaReward"),
    (0x55DA95, GETCELL, "RecvClient_CharNameChange"), (0x5370D0, GETCELL, "Recv_UserPrimiumSum"), (0x5347EE, GETCELL, "Recv_UserUpgradeExtraction"),
    (0x535A49, GETCELL, "Recv_UserUpgradeBless"), (0x5365DD, GETCELL, "Recv_UserItemOptionTrans"), (0x5141B9, GETCELL, "Recv_ShellItemOption_Extraction"),
    (0x533378, GETCELL, "Recv_User_CashKey"), (0x40A82C, GETCELL, "Recv_User_FlagUpdate"), (0x462B2C, GETCELL, "User_Game_SquadReset"),
    (0x4EC73C, GETCELL, "CharItemTradeReq"), (0x53E4B8, ISF, "RecvUser_CraftEnter"), (0x4F1771, DBSEND, "sub_4F1550"),
]
FT13 = [(0x4F4EA2, H("0fb654010d"), "Recv_GachaItemUse"), (0x515DC6, H("0fb6440a0d"), "CharRoseWarStoreBuy"),
        (0x5345EB, H("0fb6440a0d"), "sub_5340B0"), (0x5525F9, H("0fb654010d"), "Recv_OperatorCommand_ItemGive"),
        (0x55BD4B, H("0fb6440a0d"), "sub_55B7F0")]
GACHA = (0x4F4F7B, H("8b8d2cffffff"), "Recv_GachaItemUse")
NEIGH = [   # те же байты сверяет сама DLL (p100_charge_stack.cpp, extra[])
    (0x534609, H("8b4de4")), (0x5345F0, H("8b4d14894109")), (0x4F8802, H("0fb695e4fdffff")), (0x4F8B74, H("0fb6953afeffff")),
    (0x4F8CBB, H("8d940d51feffff")), (0x55257B, H("8b558a8955fc")), (0x515CEA, H("8b8da4feffff")), (0x515E82, H("0fbf955cffffff")),
    (0x45F0B7, H("6689852cfbffff")), (0x45F1C7, H("8d8d80fbffff")), (0x505DC1, H("668985ecfaffff")), (0x50683C, H("668985c7fcffff")),
    (0x51BB32, H("668945b4")), (0x51DB81, H("03859cf3ffff")), (0x520A49, H("0385acf6ffff")), (0x4FE6E8, H("8b8dd4feffff")),
    (0x469348, H("668b9570feffff")), (0x46956F, H("66899578feffff")), (0x50B9B1, H("668b8d38feffff")), (0x4E4DF8, H("8b8decfaffff")),
    (0x4F4F81, H("83e9016bc930")), (0x4F4F74, H("66898594feffff")), (0x41354A, H("0fb64dae")),
    (0x4CE543, H("8d8578ffffff")), (0x4CE56E, H("c68570feffff12")), (0x534045, H("668b85e8feffff")),
    (0x53DBB5, H("898de0f7ffff")), (0x53E513, H("c685d0fdffff03")),
]
RET_5340B0 = [0x533932, 0x40FC57, 0x4131C8, 0x53B891, 0x53BAA9, 0x53E898, 0x53E8D1, 0x49AD4C, 0x4F8596, 0x469300]
RET_55B7F0 = 0x5548AD
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

# функции по декомпилу (второй метод границ)
FUNCS = sorted((int(m.group(2), 16), m.group(1)) for m in
               re.finditer(r"//---- (\S+) @ 0x([0-9A-Fa-f]+)", open(GSC, encoding="utf-8", errors="replace").read()))
FKEYS = [f[0] for f in FUNCS]


def func_of(va):
    """(начало, имя) функции, содержащей va."""
    i = bisect.bisect_right(FKEYS, va) - 1
    return FUNCS[i]


def sites():
    """Все площадки P100: (адрес, байты стока, подпись)."""
    out = []
    for va, tgt, fn in CALLS:
        out.append((va, b"\xE8" + struct.pack("<i", tgt - (va + 5)), "call 0x%06X в %s" % (tgt, fn)))
    for va, orig, fn in FT13:
        out.append((va, orig, "FT+13 в %s" % fn))
    out.append((GACHA[0], GACHA[1], "гача %s" % GACHA[2]))
    return out


SITES = sites()

print("== 1. образы GameServer: площадки, соседи, границы инструкций, переходы внутрь, окна")
ok(all(stack_layout.EXE_MD5.get(d + r"\GameServer.exe") == LIVE for d in stack_layout.GS_FOLDERS),
   "stack_layout.EXE_MD5: GameServer.exe всех %d папок = %s" % (len(stack_layout.GS_FOLDERS), LIVE))
wins = {}
live = None
for name, path, want in IMAGES:
    if not os.path.exists(path):
        ok(False, "%s: нет файла %s" % (name, path))
        continue
    ok(md5(path) == want, "%s: md5 %s" % (name, want))
    pe, img, base = load(path)
    if live is None and want == LIVE:
        live = (pe, img, base)
    g = lambda va, n: img[va - base:va - base + n]
    badb = [("0x%06X" % va) for va, orig, _ in SITES if g(va, len(orig)) != orig]
    ok(not badb, "%s: байты стока %d площадок%s" % (name, len(SITES), (" — НЕ совпали: " + ", ".join(badb)) if badb else ""))
    badn = [("0x%06X" % va) for va, orig in NEIGH if g(va, len(orig)) != orig]
    ok(not badn, "%s: соседи %d%s" % (name, len(NEIGH), (" — НЕ совпали: " + ", ".join(badn)) if badn else ""))
    # границы инструкций: линейный проход от начала функции (по декомпилу)
    nb = []
    for va, orig, what in SITES:
        f0, fname = func_of(va)
        st = {i.address for i in md.disasm(img[f0 - base:va - base + 16], f0)}
        if va not in st or (va + len(orig)) not in st:
            nb.append("0x%06X" % va)
    ok(not nb, "%s: каждая площадка — целые инструкции от начала функции%s" % (name, (" — нет: " + ", ".join(nb)) if nb else ""))
    # переходы внутрь площадок (в середину)
    lo, hi = text_range(pe, base)
    t = img[lo - base:hi - base]
    inner = []
    rngs = sorted((va + 1, va + len(orig)) for va, orig, _ in SITES)
    starts = [r[0] for r in rngs]
    for o in range(len(t) - 6):
        b0 = t[o]
        tgt = None
        if b0 == 0xEB or 0x70 <= b0 <= 0x7F:
            tgt = lo + o + 2 + struct.unpack_from("<b", t, o + 1)[0]
        elif b0 in (0xE8, 0xE9):
            tgt = lo + o + 5 + struct.unpack_from("<i", t, o + 1)[0]
        elif b0 == 0x0F and 0x80 <= t[o + 1] <= 0x8F:
            tgt = lo + o + 6 + struct.unpack_from("<i", t, o + 2)[0]
        if tgt is None:
            continue
        k = bisect.bisect_right(starts, tgt) - 1
        if k >= 0 and rngs[k][0] <= tgt < rngs[k][1]:
            inner.append((lo + o, tgt))
    real = []
    for src, tgt in inner:
        f0, _ = func_of(src)
        if any(i.address == src for i in md.disasm(img[f0 - base:src - base + 8], f0)):
            real.append("0x%06X→0x%06X" % (src, tgt))
    ok(not real, "%s: переходов внутрь площадок нет (кандидатов-байт %d, настоящих %d)%s" % (name, len(inner), len(real),
                                                                                           (": " + ", ".join(real[:5])) if real else ""))
    for va, orig, _ in SITES:
        wins.setdefault(va, []).append(img[va - base - 32:va - base + len(orig) + 32])
diffw = ["0x%06X" % va for va, w in wins.items() if any(x != w[0] for x in w)]
ok(not diffw, "окна ±32 б вокруг %d площадок одинаковы на %d образах%s" % (len(wins), len(IMAGES), (": " + ", ".join(diffw)) if diffw else ""))

print("== 2. вторым методом (декомпил: функции; дизасм: FT+13, вызывающие sub_5340B0)")
wrongf = []
for va, tgt, fn in CALLS:
    f0, name = func_of(va)
    if name != fn:
        wrongf.append("0x%06X в %s (ждали %s)" % (va, name, fn))
ok(not wrongf, "%d call-площадок лежат в функциях разбора%s" % (len(CALLS), (": " + "; ".join(wrongf)) if wrongf else ""))
if live:
    pe, img, base = live
    lo, hi = text_range(pe, base)
    allins = list(mdk.disasm(img[lo - base:hi - base], lo))
    reads = []
    for k, i in enumerate(allins):
        if "0x5f5e70" in i.op_str:
            for j in allins[k + 1:k + 30]:
                if re.search(r"\+ 0xd\]$", j.op_str) and j.mnemonic == "movzx" and "ebp" not in j.op_str:
                    reads.append(j.address)
                    break
    reads = sorted(set(reads))
    ft_sites = sorted(va for va, _, _ in FT13)
    ok(len(reads) == 7 and set(ft_sites) <= set(reads) and set(reads) - set(ft_sites) == {0x5127ED, 0x5136DA},
       "чтений FT+13 (movzx …+0Dh после [0x5F5E70]) в образе %d: %s; площадки P100 — 5, вне P100: 0x5127ED (5070→GP7), 0x5136DA (подарок → P101)"
       % (len(reads), ", ".join("0x%06X" % a for a in reads)))
    gsc = open(GSC, encoding="utf-8", errors="replace").read()
    dec = re.findall(r"dword_5F5E70 \+ 48 \* \([^;]*\) \+ 13\)", gsc)
    ok(len(dec) == 7, "декомпил: выражений «dword_5F5E70 + 48·(код−1) + 13» — %d (= 7 чтений дизасма)" % len(dec))
    calls = {i.address + i.size for i in allins if i.mnemonic == "call" and i.op_str == "0x5340b0"}
    ok(all(r in calls for r in RET_5340B0), "адреса возврата sub_5340B0, по которым P100 различает пути (%d), — настоящие" % len(RET_5340B0))
    calls55 = {i.address + i.size for i in allins if i.mnemonic == "call" and i.op_str == "0x55b7f0"}
    ok(RET_55B7F0 in calls55, "адрес возврата sub_55B7F0 из EventItemRequestReq 0x%06X — настоящий (вызовов sub_55B7F0 %d)" % (RET_55B7F0, len(calls55)))
    s = {i.address: (i.mnemonic + " " + i.op_str) for i in allins if 0x4F4E60 <= i.address < 0x4F4FA0}
    ok(s.get(0x4F4F7B) == "mov ecx, dword ptr [ebp - 0xd4]" and s.get(0x4F4F02) == "jmp 0x4f4f7b" and s.get(0x4F4F74, "").startswith("mov word ptr [ebp - 0x16c]"),
       "гача: 0x4F4F7B — точка схождения веток (jmp 0x4F4F7B из ветки «гача в сумке», проход из ветки роутера)")

print("== 3. исходник и сборка DLL")
p100 = open(os.path.join(SRC, "patches", "p100_charge_stack.cpp"), encoding="utf-8").read()
src_calls = [(int(a, 16), int(t, 16)) for a, t in re.findall(r"\{ 0x00([0-9A-F]{6}), 0x00([0-9A-F]{6}), \(void\*\)&T", p100)]
ok(sorted(src_calls) == sorted((va, tgt) for va, tgt, _ in CALLS), "kCalls исходника (%d) = таблица скрипта (%d)" % (len(src_calls), len(CALLS)))
src_nb = {int(a, 16) for a in re.findall(r"\{ 0x00([0-9A-F]{6}), k(?:Nb|Ft)", p100)}
ok({va for va, _ in NEIGH} | {va for va, _, _ in FT13} | {GACHA[0]} <= src_nb, "соседи/FT+13/гача в apply исходника = таблица скрипта (%d адресов)" % len(src_nb))
cfg = open(os.path.join(SRC, "Config.cpp"), encoding="utf-8").read()
cfh = open(os.path.join(SRC, "Config.h"), encoding="utf-8").read()
_kv = re.search(r"constexpr int kVersion = (\d+);", cfh)   # ★ 02.11.2026 (P101): v58 — P100 вошёл в 57, далее версия растёт
ok(_kv and int(_kv.group(1)) >= 57 and ('{ L"Version", L"%s",' % _kv.group(1)) in cfg, "Config: kVersion (%s) >= 57 и шаблон Version = kVersion" % (_kv.group(1) if _kv else "?"))
ok(all(k in cfg for k in ('{ L"P100_ChargeStack"', 'kChargeStack, ARRAYSIZE(kChargeStack)', '{ L"Cap", L"30000"', '{ L"Sites", L"-1"',
                          '{ L"TradeMerge", L"1"', '{ L"FixCharges", L"1"', '{ L"PendingTtlSec", L"60"')), "Config.cpp: секция [P100_ChargeStack] и умолчания")
reg = open(os.path.join(SRC, "patches", "Registry.cpp"), encoding="utf-8").read()
ok(0 < reg.find('{ L"P99_UpgradeSplitStone"') < reg.find('{ L"P100_ChargeStack"') and reg.find('{ L"P95_ItemUseGuard"') < reg.find('{ L"P100_ChargeStack"'),
   "реестр: P100 после P95/P96/P98/P99")
acj = open(os.path.join(SRC, "AcJournal.cpp"), encoding="utf-8").read()
ok(all(('case %d: return L"P100:' % k) in acj for k in range(153, 158)), "AcJournal: тексты ac.other 153–157")
ok(not any(re.search(r"case %d: return L\"(?!P100:)" % k, acj) for k in range(153, 158)), "AcJournal: 153–157 не заняты чужими (P100; 158–163 — P101)")
p95 = open(os.path.join(SRC, "patches", "p95_item_use_guard.cpp"), encoding="utf-8").read()
p16 = open(os.path.join(SRC, "patches", "p16_gacha_prize_to_inven.cpp"), encoding="utf-8").read()
p62 = open(os.path.join(SRC, "patches", "p62_slot_uniqueness.cpp"), encoding="utf-8").read()
p96 = open(os.path.join(SRC, "patches", "p96_inventory_x2.cpp"), encoding="utf-8").read()
ok("P100_BoxPlace(mgr, userNum, code, i, batch)" in p95 and "P100_ReserveNew(" in p95 and "P100_CancelBatch(" in p95,
   "P95 Place: позиции-спецпредметы ключа — P100_BoxPlace / P100_ReserveNew / P100_CancelBatch")
ok("P100_PremiumSlot(mgr, userNum, itemCode, container, after" in p16, "P16: ячейки копий — P100_PremiumSlot")
ok("P100_IsBoxMergeSlot(userNum, refs[i].slot)" in p62, "P62 6096: повтор ячейки слияния P100 не нарушение")
ok("P96_BagRec(BYTE* pUser, int slot)" in p96, "P96: экспорт P96_BagRec")
ok("0x513558" not in re.sub(r"//.*", "", p100), "площадка подарка 0x513558 (A8) в P100 НЕ ставится (забирает P101)")
if os.path.exists(DLL) and os.path.exists(MAP):
    mp = open(MAP, encoding="latin-1").read()
    pe, img, base = load(DLL)
    exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else set()
    need = ["P100_GetStats", "P100_Active", "P100_SiteOn", "P100_KeyOf", "P100_Charges", "P100_BeginBatch", "P100_FindChargeStack",
            "P100_ReserveNew", "P100_IsReserved", "P100_CancelBatch", "P100_WriteMerged", "P100_IsBoxMergeSlot", "P100_BoxPlace",
            "P100_PremiumSlot", "P96_BagRec"]
    miss = [n for n in need if not any(n + "@" in e or e == n for e in exp)]
    ok(not miss, "экспорты DLL: %d%s" % (len(need), (" — нет: " + ", ".join(miss)) if miss else ""))

    def sym(rx):
        """Адрес символа p100_charge_stack.obj по .map."""
        m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p100_charge_stack\.obj\s*$" % rx, mp, re.M)
        return int(m.group(2), 16) if m else 0

    c3, call3 = sym(r"\?C3Common@\S+"), sym(r"_P100_Call3@24")
    if c3 and call3:
        c = [(i.mnemonic + " " + i.op_str) for i in md.disasm(img[c3 - base:c3 - base + 40], c3)][:9]
        ok(c == ["pop eax", "push dword ptr [esp + 0xc]", "push dword ptr [esp + 0xc]", "push dword ptr [esp + 0xc]", "push ecx", "push ebp",
                 "push eax", "call 0x%x" % call3, "ret 0xc"],
           "трамплин C3Common: id, 3 аргумента стока, this, ebp вызывающей → P100_Call3, ret 0Ch (как thiscall стока)")
    else:
        ok(False, "C3Common / P100_Call3 в .map")
    c2, call2 = sym(r"\?C2Common@\S+"), sym(r"_P100_Call2@20")
    if c2 and call2:
        c = [(i.mnemonic + " " + i.op_str) for i in md.disasm(img[c2 - base:c2 - base + 40], c2)][:8]
        ok(c == ["pop eax", "push dword ptr [esp + 8]", "push dword ptr [esp + 8]", "push ecx", "push ebp", "push eax", "call 0x%x" % call2, "ret 8"],
           "трамплин C2Common → P100_Call2, ret 8 (sub_4D6A70)")
    else:
        ok(False, "C2Common / P100_Call2 в .map")
    ok("P100_ChargeStack".encode("utf-16-le").decode("latin-1") in img.decode("latin-1"), "DLL: имя секции в образе")
else:
    ok(False, "нет %s / .map" % DLL)

print("== 4. пересечения с чужими площадками (по тексту src/patches)")
spans = [(va, va + len(orig)) for va, orig, _ in SITES]
hits = []
pdir = os.path.join(SRC, "patches")
for fn in sorted(os.listdir(pdir)):
    if not fn.endswith(".cpp") or fn.startswith("p100_"):
        continue
    txt = open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read()
    code = re.sub(r"//.*", "", txt)
    for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", code):
        v = int(m.group(1), 16)
        if any(a <= v < b for a, b in spans) and not (fn.startswith("p103_") and v == 0x4F1771):   # ★ P103: G_AUTOUSE зовёт P103_OnDbSent (задуманно)
            hits.append("%s:0x%06X" % (fn, v))
ok(not hits, "ни один адрес чужих патчей (вне комментариев) не внутри площадок P100%s" % (": " + ", ".join(sorted(set(hits))) if hits else ""))
others = {"p16": 0, "p62": 0, "p95": 0, "p96": 0, "p97": 0, "p98": 0}
for fn in sorted(os.listdir(pdir)):
    pre = fn.split("_")[0]
    if pre in others:
        txt = re.sub(r"//.*", "", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read())
        others[pre] = sum(1 for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", txt) if any(a <= int(m.group(1), 16) < b for a, b in spans))
ok(all(v == 0 for v in others.values()), "P16/P62/P95/P96/P97/P98: пересечений %s" % others)

print("== 5. данные charge_groups.txt")
try:
    lines = open(CG, encoding="latin-1").read().splitlines()
    m = re.match(r"# P100 ft_md5=([0-9a-f]{32}) codes=(\d+) merge=(\d+) keys=(\d+)$", lines[0])
    rows = {}
    for ln in lines[1:]:
        p = ln.split("\t")
        if len(p) == 6:
            rows[int(p[0])] = [int(x) for x in p[1:]]
    ok(m is not None and m.group(1) == md5(FT_MIRROR), "заголовок; ft_md5 = md5 зеркала живой FT %s" % md5(FT_MIRROR))
    nm = sum(1 for r in rows.values() if r[0] > 0)
    nk = len({r[0] for r in rows.values() if r[0] > 0})
    ok(m and len(rows) == int(m.group(2)) == 637 and nm == int(m.group(3)) == 173 and nk == int(m.group(4)) == 63,
       "кодов %d, складываемых %d, ключей %d (637/173/63)" % (len(rows), nm, nk))
    ok(all(rows[c][1] == 300 and rows[c][0] > 0 for c in (505, 506, 515)), "505/506/515: заряды 300 (сток u8 → 44), ключи %s" % [rows[c][0] for c in (505, 506, 515)])
    ok(all(r[0] == 0 for c, r in rows.items() if r[2] != 2 or r[3] != 0 or c in (401, 363)), "ключ > 0 только у режима 2 без срока; 401/363 — 0")
except Exception as e:
    ok(False, "charge_groups.txt: %s" % e)

print("== ИТОГ verify_p100: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
