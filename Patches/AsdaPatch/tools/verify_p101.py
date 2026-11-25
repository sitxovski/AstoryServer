# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p101.py — СТАТИЧЕСКАЯ проверка P101_CashGift «подарок из кэш-магазина» (02.11.2026, AsdaPatch v58).
#   Логику на НАСТОЯЩИХ обработчиках проверяет stand_p101. Проект: Reports/cash_gift/PROJECT_P101.md §2; итог p101/DLL_DONE.md.
#   1. Образы GameServer (сток 4e20f0ad; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — stack_layout.EXE_MD5):
#      площадки (стаб диспетчера клиента 0x42AD02 7 б, стаб шлюза 0x42FC62 5 б, FT+13 0x5136DA 6 б, 7 call E8 rel32) и соседи —
#      те же байты, что сверяет сама DLL; каждая площадка — целые инструкции от начала функции (декомпил); переходов внутрь нет;
#      окна ±32 б одинаковы на 4 образах.
#   2. Вторым методом: индекс таблицы диспетчера 0x42F370 для 5072/5074 = default (0x42F020, площадка P13), у 5070 — свой case;
#      в образах нет push 13D0h/13D2h/13D4h/854h (отправляющей половины нет — ВОССТАНОВЛЕНА ПО КОНТРАКТУ); цепочка шлюза
#      0x0B/0x51/0x5B кончается `jmp 0x43462B` @0x42FC62, сравнения с 0x53 нет; call-площадки — в функциях разбора; кадр получателя
#      (тело [ebp-2F8h] 237 б, j [ebp-48h], 5078 [ebp-1B0h]) и sub_513910 (j [ebp-3BCh], записи [ebp-19Ch]) — по дизасму.
#   3. Исходник: таблица call-площадок = скрипт, соседи apply, Config kVersion = шаблон Version = 58, секция [P101_CashGift]
#      Enabled=0, реестр P101 после P100, AcJournal 158–163, ac-journal-p53.md §9; DLL: экспорты, трамплины (ассемблер; косвенные
#      jmp разыменованы — ловушка `mov ecx,[imm]` без ds:).
#   4. Пересечения: ни один адрес площадок других патчей (src/patches, вне комментариев) не внутри площадок P101; P101 не трогает
#      площадки P100 (kCalls p100) и P13 (0x42F020).
# Запуск: py -3.13 verify_p101.py [AsdaPatch.dll]
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


def main():
    """Все проверки; код возврата 0 — сошлось."""
    dll = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
    mapf = os.path.splitext(dll)[0] + ".map"
    src = os.path.join(HERE, "..", "src")
    gsc = r"@@ASTORY_DEV_ROOT@@\RE\ida\server_work\GameServer.c"
    imgd = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
    live_md5 = "e7b4ac38e8328aaa847bbd9bf261bb01"
    images = [("сток GameServer", os.path.join(imgd, "gs_stock.exe"), "4e20f0ad0b13a54454405eed31ffe447")] + \
             [("живой " + d, os.path.join(SRV, "v2", d, "GameServer.exe"), live_md5) for d in stack_layout.GS_FOLDERS]
    jdoc = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Docs\GameServer\ac-journal-p53.md"
    H = bytes.fromhex
    bad = [0]

    def ok(cond, msg):
        """Строка проверки; провал считается."""
        print("  [%s] %s" % ("OK" if cond else "!!", msg))
        if not cond:
            bad[0] += 1

    def md5(path):
        """md5 файла."""
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

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

    # call-площадки: адрес, цель, функция (по GameServer.c)
    calls = [
        (0x4303DE, 0x513240, "ConnectSocketMsgProcess"), (0x430412, 0x513330, "ConnectSocketMsgProcess"),
        (0x430446, 0x513DF0, "ConnectSocketMsgProcess"), (0x43047A, 0x513910, "ConnectSocketMsgProcess"),
        (0x5134B3, 0x4D6A70, "recvChatResponseUserCharChargeShopGift"), (0x513558, 0x4D6740, "recvChatResponseUserCharChargeShopGift"),
        (0x513D31, 0x4D63F0, "sub_513910"),
    ]
    raw = [(0x42AD02, H("ff248dc0f24200"), "sub_42A9D0", "диспетчер клиента: jmp [ecx*4+42F2C0h]"),
           (0x42FC62, H("e9c4490000"), "ConnectSocketMsgProcess", "шлюз: jmp 0x43462B"),
           (0x5136DA, H("660fb654010d"), "recvChatResponseUserCharChargeShopGift", "FT+13 movzx dx")]
    neigh = [(0x42ACD9, H("81ea8a130000899538efffff")), (0x42ACFB, H("0fb68870f34200")), (0x42BA64, H("8d95b8efffff52668b45bc")),
             (0x42FC55, H("83bdd4efffff5b")), (0x4345A9, H("8d85e8efffff506a008b8dd8efffff")), (0x5134B8, H("3b85f8fcffff")),
             (0x5134A5, H("668b8530fdffff")), (0x513511, H("8b55b88b84953afdffff")), (0x5136D4, H("8b0d705e5f00")),
             (0x5136E0, H("8b45b8")), (0x513D1E, H("8d841564feffff")), (0x513D15, H("8b9544fcffff"))]
    sites = [(va, b"\xE8" + struct.pack("<i", tgt - (va + 5)), fn, "call 0x%06X" % tgt) for va, tgt, fn in calls] + raw

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    mdk = Cs(CS_ARCH_X86, CS_MODE_32)
    mdk.skipdata = True
    with open(gsc, encoding="utf-8", errors="replace") as f:
        gtext = f.read()
    funcs = sorted((int(m.group(2), 16), m.group(1)) for m in re.finditer(r"//---- (\S+) @ 0x([0-9A-Fa-f]+)", gtext))
    fkeys = [x[0] for x in funcs]

    def func_of(va):
        """(начало, имя) функции, содержащей va."""
        i = bisect.bisect_right(fkeys, va) - 1
        return funcs[i]

    print("== 1. образы GameServer: площадки, соседи, границы инструкций, переходы внутрь, окна")
    ok(all(stack_layout.EXE_MD5.get(d + r"\GameServer.exe") == live_md5 for d in stack_layout.GS_FOLDERS),
       "stack_layout.EXE_MD5: GameServer.exe всех %d папок = %s" % (len(stack_layout.GS_FOLDERS), live_md5))
    wins, live = {}, None
    for name, path, want in images:
        if not os.path.exists(path):
            ok(False, "%s: нет файла %s" % (name, path))
            continue
        ok(md5(path) == want, "%s: md5 %s" % (name, want))
        pe, img, base = load(path)
        if live is None and want == live_md5:
            live = (pe, img, base)
        g = lambda va, n: img[va - base:va - base + n]
        badb = ["0x%06X" % va for va, orig, _, _ in sites if g(va, len(orig)) != orig]
        ok(not badb, "%s: байты стока %d площадок%s" % (name, len(sites), (" — НЕ совпали: " + ", ".join(badb)) if badb else ""))
        badn = ["0x%06X" % va for va, orig in neigh if g(va, len(orig)) != orig]
        ok(not badn, "%s: соседи %d%s" % (name, len(neigh), (" — НЕ совпали: " + ", ".join(badn)) if badn else ""))
        nb = []
        for va, orig, _, _ in sites:
            f0, _n = func_of(va)
            st = {i.address for i in md.disasm(img[f0 - base:va - base + 16], f0)}
            if va not in st or (va + len(orig)) not in st:
                nb.append("0x%06X" % va)
        ok(not nb, "%s: каждая площадка — целые инструкции от начала функции%s" % (name, (" — нет: " + ", ".join(nb)) if nb else ""))
        lo, hi = text_range(pe, base)
        t = img[lo - base:hi - base]
        rngs = sorted((va + 1, va + len(orig)) for va, orig, _, _ in sites)
        starts = [r[0] for r in rngs]
        inner = []
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
        for s0, tgt in inner:
            f0, _n = func_of(s0)
            if any(i.address == s0 for i in md.disasm(img[f0 - base:s0 - base + 8], f0)):
                real.append("0x%06X→0x%06X" % (s0, tgt))
        ok(not real, "%s: переходов внутрь площадок нет (кандидатов-байт %d, настоящих %d)%s" % (
            name, len(inner), len(real), (": " + ", ".join(real[:5])) if real else ""))
        for va, orig, _, _ in sites:
            wins.setdefault(va, []).append(img[va - base - 32:va - base + len(orig) + 32])
    diffw = ["0x%06X" % va for va, w in wins.items() if any(x != w[0] for x in w)]
    ok(not diffw, "окна ±32 б вокруг %d площадок одинаковы на %d образах%s" % (len(wins), len(images), (": " + ", ".join(diffw)) if diffw else ""))

    print("== 2. вторым методом (декомпил: функции, case; дизасм: таблица диспетчера, push, цепочка шлюза, кадры)")
    wrongf = ["0x%06X в %s (ждали %s)" % (va, func_of(va)[1], fn) for va, _o, fn, _w in sites if func_of(va)[1] != fn]
    ok(not wrongf, "%d площадок лежат в функциях разбора%s" % (len(sites), (": " + "; ".join(wrongf)) if wrongf else ""))
    ok("case 0x13CE:" in gtext and "case 0x13D0:" not in gtext and "case 0x13D2:" not in gtext,
       "декомпил: case 0x13CE (5070) есть, case 0x13D0/0x13D2 (5072/5074) — нет ни в одном switch")
    if live:
        pe, img, base = live
        g = lambda va, n: img[va - base:va - base + n]
        idx = g(0x42F370, 0xFF)
        jt = lambda i: struct.unpack_from("<I", img, 0x42F2C0 - base + 4 * i)[0]
        ok(idx[0x46] == idx[0x48] == 43 and jt(43) == 0x42F020 and jt(idx[0x44]) == 0x42BA41,
           "таблица 0x42F370: индекс 5072/5074 = %d/%d → 0x%06X (default, площадка P13); 5070 → 0x%06X (свой case)" % (
               idx[0x46], idx[0x48], jt(43), jt(idx[0x44])))
        ok(max(idx) == 43 and all(jt(i) != 0x42F020 for i in range(43)), "индекс 43 — единственный вход default в таблице (44 записи)")
        lo, hi = text_range(pe, base)
        t = img[lo - base:hi - base]
        pushes = {op: t.count(b"\x68" + struct.pack("<I", op)) for op in (0x13D0, 0x13D2, 0x13D4, 0x854)}
        ok(all(v == 0 for v in pushes.values()), "push 13D0h/13D2h/13D4h/854h в образе: %s (отправляющей половины нет)" % pushes)
        ok(t.count(b"\x68\xd5\x13\x00\x00") >= 3 and t.count(b"\x68\x58\x08\x00\x00") >= 1,
           "push 13D5h (5077) и 858h (2136) есть — принимающая половина стока на месте")
        ch = [(i.address, i.mnemonic + " " + i.op_str) for i in md.disasm(g(0x42FC3B, 0x2C), 0x42FC3B)]
        ok([c for _a, c in ch] == ["cmp dword ptr [ebp - 0x102c], 0xb", "je 0x43453b", "cmp dword ptr [ebp - 0x102c], 0x51", "je 0x4345a0",
                                  "cmp dword ptr [ebp - 0x102c], 0x5b", "je 0x4345ce", "jmp 0x43462b"],
           "шлюз: цепочка 0x0B/0x51/0x5B → jmp 0x43462B @0x42FC62")
        allins = list(mdk.disasm(t, lo))
        f0 = 0x42FAB0
        cmp53 = [i.address for i in allins if f0 <= i.address < 0x434700 and i.mnemonic == "cmp" and i.op_str == "dword ptr [ebp - 0x102c], 0x53"]
        ok(not cmp53, "ConnectSocketMsgProcess: сравнения кода ответа с 0x53 нет (стоку 0x53 неизвестна)")
        rec = {i.address: (i.mnemonic + " " + i.op_str) for i in allins if 0x513330 <= i.address < 0x513910}
        ok(any(v == "lea ecx, [ebp - 0x2f8]" for v in rec.values()) and rec.get(0x5134AD) == "mov ecx, dword ptr [ebp - 0x314]",
           "получатель: тело 237 б в [ebp-2F8h] (memcpy 0xED), this [ebp-314h]")
        s910 = {i.address: (i.mnemonic + " " + i.op_str) for i in allins if 0x513910 <= i.address < 0x513DF0}
        ok(s910.get(0x51393F) == "lea ecx, [ebp - 0x1b0]" and s910.get(0x513D31) == "call 0x4d63f0" and s910.get(0x513D1B) == "imul edx, edx, 0x39",
           "sub_513910: 5078 [ebp-1B0h] (записи с +20 = [ebp-19Ch], шаг 57), запись sub_4D63F0 @0x513D31")
        ft = []
        for k, i in enumerate(allins):
            if "0x5f5e70" in i.op_str:
                for j in allins[k + 1:k + 30]:
                    if re.search(r"\+ 0xd\]$", j.op_str) and j.mnemonic == "movzx" and "ebp" not in j.op_str:
                        ft.append(j.address)
                        break
        ok(0x5136DA in ft and 0x5127ED in ft, "чтение FT+13 0x5136DA — одно из %d чтений образа (0x5127ED — CharChargeShopBuy, не трогается)" % len(set(ft)))

    print("== 3. исходник и сборка DLL")
    rd = lambda *p: open(os.path.join(src, *p), encoding="utf-8-sig", errors="replace").read()
    p101 = rd("patches", "p101_cash_gift.cpp")
    sc = sorted((int(a, 16), int(b, 16)) for a, b in re.findall(r"\{ 0x00([0-9A-F]{6}), 0x00([0-9A-F]{6}), \(void\*\)&", p101))
    ok(sc == sorted((va, tgt) for va, tgt, _ in calls), "kCalls исходника (%d) = таблица скрипта (%d)" % (len(sc), len(calls)))
    snb = {int(a, 16) for a in re.findall(r"\{ 0x00([0-9A-F]{6}), k(?:Nb|Disp|Gw|Ft)", p101)}
    ok({va for va, _ in neigh} | {va for va, _o, _f, _w in raw} <= snb, "соседи и площадки в apply исходника = таблица скрипта (%d адресов)" % len(snb))
    cfg, cfh = rd("Config.cpp"), rd("Config.h")
    _kv = re.search(r"constexpr int kVersion = (\d+);", cfh)   # ★ 04.11.2026 (P102): v59 — P101 вошёл в 58, далее версия растёт
    ok(_kv and int(_kv.group(1)) >= 58 and ('{ L"Version", L"%s",' % _kv.group(1)) in cfg,
       "Config: kVersion (%s) >= 58 и шаблон Version = kVersion" % (_kv.group(1) if _kv else "?"))
    ok(all(k in cfg for k in ('{ L"P101_CashGift"', "kCashGift, ARRAYSIZE(kCashGift)", '{ L"Sites", L"1"', '{ L"HoldTimeoutSec", L"120"',
                              '{ L"MaxInFlight", L"1"', '{ L"SettleMaxSec", L"1800"', '{ L"RouteMaxAgeSec", L"300"', '{ L"LogChannel", L"22"')) and
       re.search(r'kCashGift\[\] =\s*\{\s*\{ L"Enabled", L"0"', cfg), "Config.cpp: секция [P101_CashGift], Enabled=0, умолчания")
    reg = rd("patches", "Registry.cpp")
    ok(0 < reg.find('{ L"P100_ChargeStack"') < reg.find('{ L"P101_CashGift"'), "реестр: P101 после P100")
    acj = rd("AcJournal.cpp")
    ok(all(('case %d: return L"P101:' % k) in acj for k in range(158, 164)), "AcJournal: тексты ac.other 158–163")
    ok(not any(re.search(r"case %d: return L\"(?!P101:)" % k, acj) for k in range(158, 164)), "AcJournal: 158–163 не заняты чужими")
    with open(jdoc, encoding="utf-8", errors="replace") as f:
        jd = f.read()
    ok("P101_CashGift" in jd and "158–163" in jd, "ac-journal-p53.md §9: P101 занял 158–163")
    p100 = rd("patches", "p100_charge_stack.cpp")
    ok(all(n in p100 for n in ("P100_FindChargeStack(void* mgr", "P100_ReserveNew(void* mgr", "P100_WriteMerged(void* mgr", "P100_CancelBatch(int userNum",
                               "P100_IsReserved(void* mgr", "P100_Charges(int code)", "P100_BeginBatch()", "P100_KeyOf(int code)", "P100_Active()")),
       "экспорты P100, на которые опирается точка D, есть в p100_charge_stack.cpp")
    ok("site != 7 && !SiteOn(site)" in p100 and "bit == 7) { return false; }" in p100,
       "P100: бит 7 (подарок) в P100_SiteOn всегда 0, P100_FindChargeStack принимает site 7 — бит подарка читает P101 (Sites бит 8)")
    if os.path.exists(dll) and os.path.exists(mapf):
        mp = open(mapf, encoding="latin-1").read()
        pe, img, base = load(dll)
        exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else set()
        need = ["P101_GetStats", "P101_Pump", "P100_FindChargeStack", "P100_WriteMerged", "P100_CancelBatch", "P96_BagRec", "P68_NameVerdict"]
        miss = [n for n in need if not any(n + "@" in e or e == n for e in exp)]
        ok(not miss, "экспорты DLL: %d%s" % (len(need), (" — нет: " + ", ".join(miss)) if miss else ""))

        def sym(rx):
            """Адрес символа p101_cash_gift.obj по .map."""
            m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) f\s+p101_cash_gift\.obj\s*$" % rx, mp, re.M)
            return int(m.group(2), 16) if m else 0

        def dis(va, n):
            """Инструкции трамплина текстом."""
            return [(i.mnemonic + " " + i.op_str).strip() for i in md.disasm(img[va - base:va - base + n], va)]

        def deref(ins):
            """Цель `jmp dword ptr [abs]` (разыменование в образе DLL)."""
            m = re.match(r"jmp dword ptr \[(0x[0-9a-f]+)\]$", ins)
            return struct.unpack_from("<I", img, int(m.group(1), 16) - base)[0] if m else None

        stubs = {n: sym(r"\?%s@\S+" % n) for n in ("St_Disp", "St_Gateway", "St_Room", "St_Pick", "St_Write", "St_Ft")}
        ok(all(stubs.values()), "трамплины в .map: %s" % {k: hex(v) for k, v in stubs.items()})
        if all(stubs.values()):
            oc, og = sym(r"_P101_OnClient@24"), sym(r"_P101_OnGateway@12")
            rr, rp, rw, rc = sym(r"_P101_RecvRoom@16"), sym(r"_P101_RecvPick@20"), sym(r"_P101_RecvWrite@20"), sym(r"_P101_ChargesAt@4")
            d = dis(stubs["St_Disp"], 160)
            ok(d[:5] == ["cmp dword ptr [ebp - 0x10c8], 0x46", d[1], "cmp dword ptr [ebp - 0x10c8], 0x48", d[3], "jmp dword ptr [ecx*4 + 0x42f2c0]"]
               and d.count("jmp dword ptr [ecx*4 + 0x42f2c0]") == 2 and "movzx ecx, byte ptr [eax + 0x42f370]" in d and ("call 0x%x" % oc) in d
               and "movsx edx, word ptr [ebp - 0x34]" in d and "lea edx, [ebp - 0x1048]" in d and "movsx edx, word ptr [ebp - 0x44]" in d
               and "mov edx, dword ptr [ebp - 0x10c4]" in d and any(deref(x) == 0x42F036 for x in d),
               "St_Disp: 0x46/0x48 → P101_OnClient(опкод, ebp, mgr, userNum, кадр, длина); иначе/0 — сток jmp [ecx*4+42F2C0h]; хвост → 0x42F036")
            d = dis(stubs["St_Gateway"], 60)
            ok(d[0] == "cmp dword ptr [ebp - 0x102c], 0x53" and "lea eax, [ebp - 0x1018]" in d and "mov eax, dword ptr [ebp - 0x1028]" in d
               and ("call 0x%x" % og) in d and any(deref(x) == 0x43462B for x in d), "St_Gateway: 0x53 → P101_OnGateway(ebp, mgr, кадр); хвост → 0x43462B")
            for nm, fn, n, ret in (("St_Room", rr, 2, "ret 8"), ("St_Pick", rp, 3, "ret 0xc"), ("St_Write", rw, 3, "ret 0xc")):
                d = dis(stubs[nm], 40)
                want = ["push dword ptr [esp + %s]" % ("8" if n == 2 else "0xc")] * n + ["push ecx", "push ebp", "call 0x%x" % fn, ret]
                ok(d[:len(want)] == want, "%s: %d аргумента стока, this, ebp вызывающей → %s, %s (как thiscall стока)" % (nm, n, hex(fn), ret))
            d = dis(stubs["St_Ft"], 40)
            ok(d[:5] == ["pushfd", "push ecx", "push eax", "lea edx, [ecx + eax + 0xd]", "push edx"] and ("call 0x%x" % rc) in d
               and "mov edx, eax" in d and any(deref(x) == 0x5136E0 for x in d), "St_Ft: dx = P101_ChargesAt(FT+13), флаги/eax/ecx целы, продолжение 0x5136E0")
        ok("P101_CashGift".encode("utf-16-le").decode("latin-1") in img.decode("latin-1"), "DLL: имя секции в образе")
    else:
        ok(False, "нет %s / .map" % dll)

    print("== 4. пересечения с чужими площадками (по тексту src/patches)")
    spans = [(va, va + len(orig)) for va, orig, _f, _w in sites]
    hits = []
    pdir = os.path.join(src, "patches")
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".cpp") or fn.startswith("p101_"):
            continue
        code = re.sub(r"//.*", "", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read())
        for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", code):
            v = int(m.group(1), 16)
            if any(a <= v < b for a, b in spans):
                hits.append("%s:0x%06X" % (fn, v))
    ok(not hits, "ни один адрес чужих патчей (вне комментариев) не внутри площадок P101%s" % (": " + ", ".join(sorted(set(hits))) if hits else ""))
    p100c = {int(a, 16) for a in re.findall(r"\{ 0x00([0-9A-F]{6}), 0x00[0-9A-F]{6}, \(void\*\)&T", p100)}
    ok(not any(a <= v < b for v in p100c for a, b in spans) and not any(v <= a < v + 5 for v in p100c for a, b in spans),
       "площадки P100 (%d call) и P101 не пересекаются" % len(p100c))
    ok(not any(a <= 0x42F020 < b or a <= 0x42F024 < b for a, b in spans), "default диспетчера 0x42F020 (P13) P101 не занимает — сток уходит туда через таблицу")
    others = {}
    for pre in ("p13", "p16", "p62", "p63", "p85", "p95", "p96", "p97", "p98", "p100"):
        n = 0
        for fn in os.listdir(pdir):
            if fn.split("_")[0] == pre:
                txt = re.sub(r"//.*", "", open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read())
                n += sum(1 for m in re.finditer(r"0x0{0,2}([4-5][0-9A-Fa-f]{5})\b", txt) if any(a <= int(m.group(1), 16) < b for a, b in spans))
        others[pre] = n
    ok(all(v == 0 for v in others.values()), "P13/P16/P62/P63/P85/P95/P96/P97/P98/P100: пересечений %s" % others)

    print("== ИТОГ verify_p101: %s (замечаний %d)" % ("ВСЁ СОШЛОСЬ" if not bad[0] else "ЕСТЬ РАСХОЖДЕНИЯ", bad[0]))
    return 1 if bad[0] else 0


if __name__ == "__main__":
    sys.exit(main())
