# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p127.py — СТАТИЧЕСКАЯ проверка P127 «мост админ-центра» (18.11.2026, волна А2; AstoryServer/Docs/GameServer/admin-bridge-p127.md).
#   Поведение — стенд tools/stand_p127 (3 образа × exec/listen/off/mismatch). Сервер не запускается.
#   1. Образы GameServer (GameServer / Indun / Ch2 = stack_layout.EXE_MD5): площадка UserTick 0x526CEB и соседи (те же байты, что у P73),
#      начала Send_DisConnectType 0x52EDB0, ___ExceptionDisConnetUser___ 0x526E40, sendNoticeClient 0x547A80 — одинаковы;
#      sendNoticeClient копирует 0x6B (107) байт тела 3113 и шлёт 3113 (0xC29) — как в разметке P127.
#   2. Площадка 0x526CEB пишется ТОЛЬКО кодом p73_eac_bridge.cpp (CheckStub: P73 Mode=1 или P73_UserTickInstall) — других площадок
#      в 0x526CEB…0x526CF0 у патчей нет; P127 своих площадок не ставит (только сверки начал функций).
#   3. DLL (.map): цепочка общих точек — P73_OnCheckUser зовёт P127_OnUserTick, P73_OnLogon — P127_OnLogon, P73_OnConnFlag —
#      P127_OnConnFlag; P48_OnDisconnectType и P58 зовут P127_KickInProgress; P127 зовёт P123_PortalMoveTo и P73_UserTickInstall.
#   4. Экспорты: рабочая DLL — P127_GetStats и ни одного P127_Test*; стендовая — P127_Test*.
#   5. Реестр: P127 после P47/P48/P61/P73/P123; секция [P127_AdminBridge] и Version 80; Config::kVersion = 80; умолчание Enabled=0, Mode=0.
#   7. ★ А2.3 (v82): give/jump — соглашения о вызове функций стока по байтам образа, точки P100, оператор 2231, версия 82.
#   6. В DLL и исходниках нет секретов моста (строк PWD= с паролем, ключа HMAC): пароль и ключ читаются только из файла SecretFile.
# Запуск: python verify_p127.py [AsdaPatch.dll]
import hashlib
import os
import re
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
SDLL = os.path.join(os.path.dirname(DLL), "stand", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC_DIR = os.path.join(HERE, "..", "src")
MD = Cs(CS_ARCH_X86, CS_MODE_32)
OK = 0
BAD = 0

SITES = [   # (VA, байты) — UserTick и соседи (как kOrigCheck/kNb* в p73), начала функций стока, которые зовёт P127
    (0x526CEB, "8b55f48b420c"), (0x526CF1, "508b4dece846d7ff"), (0x526E36, "e90afeffff"), (0x526CC2, "8945f4"),
    (0x526C8C, "8945f8"), (0x526C26, "894dec"),
    (0x52EDB0, "558bec"), (0x526E40, "558bec"), (0x547A80, "558bec"),
]


def check(cond, what):
    """Строка проверки и счёт."""
    global OK, BAD
    OK += bool(cond)
    BAD += not cond
    print(("  ok   " if cond else "  FAIL ") + what)


class Img:
    """Образ exe: чтение по VA."""
    def __init__(self, path):
        pe = pefile.PE(path, fast_load=True)
        self.b = pe.get_memory_mapped_image()
        self.base = pe.OPTIONAL_HEADER.ImageBase

    def rd(self, va, n):
        return bytes(self.b[va - self.base:va - self.base + n])

    def dis(self, va, n):
        return list(MD.disasm(self.rd(va, n), va))


def md5(p):
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def map_syms(path):
    """Имя → VA из .map (Publics by Value)."""
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s", line)
        if m:
            out[m.group(1)] = int(m.group(2), 16)
    return out


def main():
    print("== 1. образы GameServer")
    imgs = {}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = Img(p)
    for d, img in imgs.items():
        bad = ["0x%X" % va for va, h in SITES if img.rd(va, len(h) // 2) != bytes.fromhex(h)]
        check(not bad, "%s: площадка UserTick, соседи и начала функций совпали%s" % (d, (" — расходятся: " + ", ".join(bad)) if bad else ""))
    img = imgs["GameServer"]
    txt = ["%s %s" % (i.mnemonic, i.op_str) for i in img.dis(0x547A80, 0x150)]
    check(any(t == "push 0x6b" for t in txt), "sendNoticeClient: memcpy 0x6B (107) байт тела 3113 с a2+9")
    check(any(t == "push 0xc29" for t in txt), "sendNoticeClient: опкод 3113 (0xC29) в sub_4C28F0")
    check(any(t == "call 0x56a040" for t in txt), "sendNoticeClient: memcpy (0x56A040) тела в свой буфер")
    check(any(t == "add eax, 9" for t in txt), "sendNoticeClient: источник тела — a2 + 9 (стаб P127 кладёт тело в кадр с +9)")

    print("== 2. площадки других патчей")
    hits = []
    for fn in os.listdir(os.path.join(SRC_DIR, "patches")):
        if not fn.endswith(".cpp") or fn.startswith("p73_"):
            continue
        s = open(os.path.join(SRC_DIR, "patches", fn), encoding="utf-8", errors="replace").read()
        s = re.sub(r'L?"(?:[^"\\\n]|\\.)*"', '""', s)   # строки журнала — не площадки
        s = re.sub(r'//[^\n]*', '', s)                     # комментарии — тоже
        for m in re.finditer(r"0x(00)?526CE[B-F]\b|0x(00)?526CF0\b", s, re.I):
            hits.append("%s: %s" % (fn, m.group(0)))
    check(not hits, "0x526CEB…0x526CF0 пишет только p73_eac_bridge.cpp%s" % ((" — " + ", ".join(hits)) if hits else ""))
    src = open(os.path.join(SRC_DIR, "patches", "p127_admin_bridge.cpp"), encoding="utf-8").read()
    check("Hook::Write" not in src, "P127 сам площадок не пишет (UserTick — через P73_UserTickInstall)")
    # ★ ревизия 24 В-1: начала функций, которые P127 зовёт, могут быть заняты врезками патчей раньше в реестре — допустим ТОЛЬКО jmp
    #   (Hook::WriteJmp → E9 в эту DLL; P127 FuncStartOk принимает «55 8B EC» или E9 с целью внутри модуля). Иные записи — провал.
    writers, other = [], []
    for fn in os.listdir(os.path.join(SRC_DIR, "patches")):
        if not fn.endswith(".cpp") or fn.startswith("p127_"):
            continue
        s = open(os.path.join(SRC_DIR, "patches", fn), encoding="utf-8", errors="replace").read()
        for va in ("0x0052EDB0", "0x00526E40", "0x00547A80"):
            for m in re.finditer(r"Hook::(\w+)\(\s*" + va, s):
                (writers if m.group(1) == "WriteJmp" else other).append("%s %s %s" % (fn, m.group(1), va))
    print("     врезки в начала функций P127: %s" % (", ".join(writers) or "нет"))
    check(not other and all("p48_" in w and "0x0052EDB0" in w for w in writers),
          "начала функций P127 других патчей: только jmp P48 на 0x52EDB0 (P127 принимает jmp в DLL)%s" % ((" — ИНОЕ: " + ", ".join(other)) if other else ""))
    check("FuncStartOk" in src and "0xE9" in src and "VerifyAllSites(L\"P127\"" not in src,
          "P127 сверяет начала функций через FuncStartOk (пролог или E9 в DLL), а не побайтно")
    check("v2|%s|%s|%d|%d|%s|%s|%d|%I64d" in src, "подпись v2 включает срок (deadline) — ревизия 24 К-2")

    print("== 3. цепочка общих точек (.map + дизасм)")
    syms = map_syms(MAP)
    pe = pefile.PE(DLL)
    dimg = pe.get_memory_mapped_image()
    dbase = pe.OPTIONAL_HEADER.ImageBase

    def calls(va, n=0x4000):   # до int3 конца функции (тела P127 большие)
        out = []
        for x in MD.disasm(bytes(dimg[va - dbase:va - dbase + n]), va):
            if x.mnemonic in ("call", "jmp") and x.op_str.startswith("0x"):
                out.append(int(x.op_str, 16))
            if x.mnemonic == "int3":
                break
        return out

    def sym(part):
        c = [v for k, v in syms.items() if k.startswith(part)]
        return c[0] if len(c) == 1 else None

    need = {k: sym(k) for k in ("_P73_OnCheckUser@12", "_P127_OnUserTick@12", "_P73_OnLogon@16", "_P127_OnLogon@16", "_P73_OnConnFlag@8",
                                 "_P127_OnConnFlag@8", "?P127_KickInProgress@@", "_P48_OnDisconnectType@16", "?P123_PortalMoveTo@@",
                                 "?P73_UserTickInstall@@", "?P127_AdminBridge@@")}
    miss = [k for k, v in need.items() if v is None]
    check(not miss, "символы найдены в .map%s" % ((": НЕТ " + str(miss)) if miss else ""))
    if not miss:
        def reach(a, b, depth=2):
            front = [a]
            for _ in range(depth):
                nxt = []
                for f in front:
                    c = calls(f)
                    if b in c:
                        return True
                    nxt += [x for x in c if dbase <= x < dbase + len(dimg)]
                front = nxt[:40]
            return False
        check(reach(need["_P73_OnCheckUser@12"], need["_P127_OnUserTick@12"]), "P73_OnCheckUser (UserTick) зовёт P127_OnUserTick")
        check(reach(need["_P73_OnLogon@16"], need["_P127_OnLogon@16"], 1), "P73_OnLogon первым зовёт P127_OnLogon")
        check(reach(need["_P73_OnConnFlag@8"], need["_P127_OnConnFlag@8"], 1), "P73_OnConnFlag первым зовёт P127_OnConnFlag")
        check(reach(need["_P48_OnDisconnectType@16"], need["?P127_KickInProgress@@"], 1), "P48_OnDisconnectType зовёт P127_KickInProgress (код 8)")
        check(reach(need["?P127_AdminBridge@@"], need["?P73_UserTickInstall@@"], 1), "P127_AdminBridge ставит UserTick через P73_UserTickInstall")
        check(reach(need["_P127_OnUserTick@12"], need["?P123_PortalMoveTo@@"], 3), "перенос — общей точкой P123_PortalMoveTo")
    # ★ А2.2 (v81): живые правки — только через общие точки патчей, сверивших свои адреса (P75 опыт, P24 снятие звания, P25 пересчёт)
    a22 = {k: sym(k) for k in ("?P75_GrantTo@@", "?P24_RevokeTitle@@", "?P25_RecalcUser@@", "?P75_Applied@@", "?P24_Applied@@", "?P25_Applied@@")}
    m22 = [k for k, v in a22.items() if v is None]
    check(not m22, "А2.2: общие точки P75/P24/P25 есть в .map%s" % ((": НЕТ " + str(m22)) if m22 else ""))
    if not m22 and not miss:
        rt = need["_P127_OnUserTick@12"]
        check(reach(rt, a22["?P75_GrantTo@@"], 3) and reach(rt, a22["?P24_RevokeTitle@@"], 3) and reach(rt, a22["?P25_RecalcUser@@"], 3),
              "А2.2: такт P127 зовёт P75_GrantTo, P24_RevokeTitle, P25_RecalcUser")
        check(reach(need["?P127_AdminBridge@@"], a22["?P75_Applied@@"], 1) and reach(need["?P127_AdminBridge@@"], a22["?P24_Applied@@"], 1)
              and reach(need["?P127_AdminBridge@@"], a22["?P25_Applied@@"], 1), "А2.2: установка P127 спрашивает P75/P24/P25_Applied")
    for op in ("probe", "exp", "title_add", "title_del", "fame_recalc", "notice"):
        check(('L"%s"' % op) in src, "А2.2: команда %s в DLL" % op)
    # ★ А2.3 (v82): give / jump — соглашения о вызове функций стока по байтам образа (пролог 55 8B EC и ret N в конце функции)
    for op in ("give", "jump"):
        check(('L"%s"' % op) in src, "А2.3: команда %s в DLL" % op)
    conv = [(0x4D6740, "c20c00", 0x4D6740, 0x4D6910), (0x4D6CE0, "c21000", 0x4D6CE0, 0x4D6FB0), (0x43FA00, "c20400", 0x43FA00, 0x43FA50),
            (0x43FB20, "c20400", 0x43FB20, 0x43FB70), (0x43F880, "c21000", 0x43F880, 0x43FA00), (0x5646C0, "c21400", 0x5646C0, 0x564900),
            (0x532530, "c20400", 0x532530, 0x532570), (0x5324F0, "c20400", 0x5324F0, 0x532530), (0x4221D0, "c20800", 0x4221D0, 0x422220),
            (0x523ED0, "c20400", 0x523ED0, 0x523F00), (0x523EA0, "c20800", 0x523EA0, 0x523ED0), (0x41EC30, "c21400", 0x41EC30, 0x41EF00),
            (0x54EBF0, "c20c00", 0x54EBF0, 0x54EF50), (0x4D63F0, "c20c00", 0x4D63F0, 0x4D6540)]
    for d, im in imgs.items():
        bad = []
        for va, ret, lo, hi in conv:
            # ★ ревизия 29 К-11: разбор инструкций функции от пролога; ВСЕ ret в теле (эпилоги) — ровно ret N разметки DLL
            code = im.rd(lo, hi - lo)
            rets = [bytes(x.bytes).hex() for x in MD.disasm(code, lo) if x.mnemonic == "ret"]
            if code[:3] != bytes.fromhex("558bec") or not rets or any(r != ret for r in rets):
                bad.append("0x%X %s" % (va, rets))
        check(not bad, "%s: А2.3 функции стока — пролог и ret N каждого эпилога как в разметке DLL (дизасм 19.11)%s" % (d, (" — НЕТ: " + ", ".join(bad)) if bad else ""))
    t = ["%s %s" % (i.mnemonic, i.op_str) for i in img.dis(0x5532D6, 0x40)]
    check("push 0x44" in t and "push 0x8b7" in t and "mov ecx, 0x7e0538" in t and "call 0x5646c0" in t,
          "А2.3: 2231 (0x8B7) длиной 68 (0x44) через sub_5646C0 с ecx = 0x7E0538 — как в GiveOne")
    t = ["%s %s" % (i.mnemonic, i.op_str) for i in img.dis(0x55241D, 0x10)] + ["%s %s" % (i.mnemonic, i.op_str) for i in img.dis(0x552F7C, 0x10)]
    check(any("0x7dffc4" in x for x in t), "А2.3: SowelCombine — указатель 0x7DFFC4 (+146 MaxUp)")
    # ★ А5.4 (v84): вторым методом (дизасм стока) — EventSet/EventOff шлют тело в RelayServer той же связью и с той же шапкой, что мост
    for d, im in imgs.items():
        es = ["%s %s" % (i.mnemonic, i.op_str) for i in im.dis(0x551BF0, 0x410)]
        eo = ["%s %s" % (i.mnemonic, i.op_str) for i in im.dis(0x5520A0, 0x220)]
        check(all(x in es for x in ("call 0x4a7eb0", "call 0x40c960", "call 0x4c0a90", "push 0x1796", "push 0x1d", "call 0x5646c0"))
              and all(x in eo for x in ("call 0x4c0a90", "push 0x1798", "push 0xf", "call 0x5646c0")),
              "%s: ★ А5.4 сток 6038 (0x551BF0) и 6040 (0x5520A0): sub_4A7EB0 / sub_40C960 в шапку, sub_4C0A90 (Relay), sub_5646C0 с 6038/29 и 6040/15" % d)
        pro = [im.rd(va, 3) for va in (0x4C0A90, 0x4A7EB0, 0x40C960)]
        check(all(p == bytes.fromhex("558bec") for p in pro), "%s: ★ А5.4 пролог 55 8B EC у sub_4C0A90, sub_4A7EB0, sub_40C960" % d)
    p100 = open(os.path.join(SRC_DIR, "patches", "p100_charge_stack.cpp"), encoding="utf-8").read()
    check("P100_GmGivePick" in p100 and "P100_Call3(R_A4, frame + 4" in p100 and "{ 0x005525B0, 0x004D6740, (void*)&T_A4," in p100,
          "А2.3: ячейка F — тот же преобразователь R_A4, что у площадки 0x5525B0 (P100_GmGivePick)")
    check("P100_GmGivePick(mgr, num, code)" in src and "P100_ChargesAt(ft + 13)" in src and "P100_WriteMerged(mgr, num, src, 1)" in src,
          "А2.3: GiveOne — ячейка F, заряды FT+13 и запись в память через общие точки P100 (площадки 0x5525B0 / 0x5525F9 / 0x5533A6)")
    check("kGmOperUid  = 2;" in src and "kGmOperSlot = 11;" in src, "А2.3: оператор 2231 — ADM_sitxovski 2/11 (решение владельца)")
    p58 = open(os.path.join(SRC_DIR, "patches", "p58_disconnect_reason_log.cpp"), encoding="utf-8").read()
    check("P127_KickInProgress()" in p58 and "AdminBridge(P127)" in p58, "P58: имя причины «AdminBridge(P127)»")

    print("== 4. экспорты")
    exp = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    check(any("P127_GetStats" in n for n in exp), "рабочая DLL: экспорт P127_GetStats")
    check(not any("P127_Test" in n for n in exp), "рабочая DLL: ни одного P127_Test*")
    if os.path.exists(SDLL):
        sexp = {e.name.decode() for e in pefile.PE(SDLL).DIRECTORY_ENTRY_EXPORT.symbols if e.name}
        check(sum("P127_Test" in n for n in sexp) >= 10, "стендовая DLL: экспорты P127_Test* (%d)" % sum("P127_Test" in n for n in sexp))

    print("== 5. реестр и ini")
    reg = open(os.path.join(SRC_DIR, "patches", "Registry.cpp"), encoding="utf-8-sig").read()
    pos = {k: reg.find('{ L"%s",' % k) for k in ("P47_IdentityOperatorGate", "P48_KickAutoBlock", "P61_TrafficEncryption", "P73_EacBridge",
                                                   "P123_GmMapJump", "P127_AdminBridge")}
    check(all(v > 0 for v in pos.values()) and all(pos["P127_AdminBridge"] > v for k, v in pos.items() if k != "P127_AdminBridge"),
          "реестр: P127 после P47/P48/P61/P73/P123")
    cfg = open(os.path.join(SRC_DIR, "Config.cpp"), encoding="utf-8-sig").read()
    # ★ 22.11.2026 (P129): Version не ниже 84 — каждая следующая сборка (85 P128, 86 P129) поднимает её; точное 84 ломалось на v85
    _vm = re.search(r'\{ L"Version", L"(\d+)",', cfg)
    check(bool(_vm) and int(_vm.group(1)) >= 84 and 'kAdminBridge, ARRAYSIZE(kAdminBridge)' in cfg,
          "Config.cpp: секция P127_AdminBridge и Version >= 84 (★ А5.4; сейчас %s)" % (_vm.group(1) if _vm else "?"))
    blk = cfg[cfg.index("const IniKey kAdminBridge[]"):]
    blk = blk[:blk.index("};")]
    check('{ L"Enabled", L"0",' in blk and '{ L"Mode", L"0",' in blk, "умолчания: Enabled=0, Mode=0 (первая выкладка — только слушать)")
    _km = re.search(r"constexpr int kVersion = (\d+);", open(os.path.join(SRC_DIR, "Config.h"), encoding="utf-8-sig").read())
    check(bool(_km) and int(_km.group(1)) >= 84, "Config.h: kVersion >= 84 (★ А5.4; сейчас %s)" % (_km.group(1) if _km else "?"))
    src127 = open(os.path.join(SRC_DIR, "patches", "p127_admin_bridge.cpp"), encoding="utf-8-sig").read()
    check('{ L"mob_pop", kOpMobPop }' in src127 and '{ L"mob_return", kOpMobReturn }' in src127 and "pConnSend((void*)Srv::kNetMoveMgr" in src127
          and "c.uid > kOperatorMax" in src127 and "gm != 1" in src127,
          "★ А5.2: mob_pop/mob_return — гейты оператора (UserIndex ≤ 5000) и GM-флага, вызов sub_5646C0 в NpcServer как у стока")
    p25 = open(os.path.join(SRC_DIR, "patches", "p25_gm_rating_recalc.cpp"), encoding="utf-8-sig").read()
    check('{ L"event_set", kOpEventSet }' in src127 and '{ L"rank_recalc", kOpRankRecalc }' in src127 and "pRelayConn(th, nullptr)" in src127
          and "set ? 6038 : 6040, set ? 29 : 15" in src127 and "P25_RunRecalc(mgr, num, c.a[0], &a, &b)" in src127
          and "RunRecalcCore(mgr, idx, what, nullptr, nullptr);" in p25 and "return RunRecalcCore(mgr, (short)userNum, what, outA, outB);" in p25,
          "★ А5.4: event_set/event_off — sub_5646C0 в RelayServer (6038/29, 6040/15); rank_recalc — общая точка P25 (команда 6020 зовёт её же)")
    check("P127_AdminBridge".encode("utf-16-le") in open(DLL, "rb").read(), "строка секции P127_AdminBridge в DLL")

    print("== 6. секреты")
    raw = open(DLL, "rb").read()
    check(re.search(rb"P\x00W\x00D\x00=\x00\{\x00[^%]", raw) is None, "в DLL нет зашитого пароля (PWD={…} только из шаблона %s)")
    check(not re.search(r"HmacKey\s*=\s*[0-9a-fA-F]{32}", src), "в исходнике нет ключа HMAC")

    print("ИТОГ: ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
