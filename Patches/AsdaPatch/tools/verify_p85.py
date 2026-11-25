# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p85.py — СТАТИЧЕСКАЯ проверка P85 (премиум-корзина целиком, 2026-10-25): AsdaPatch P85_PremiumCartRows (GameServer)
#   и DBPatch P85_DbPostRows (DBManager).
#
# Сервер НЕ запускается. Проверяем по образам (сток, живой GameServer, живой Indun; живой DBManager) и собранным DLL:
#  1) площадка GS 0x4F62AC = mov eax,[ebp-0x608] / mov ecx,[eax+4] (9 б) — одинакова в трёх образах, на границе инструкций,
#     ровно перед `call 0x4C0250` → … → `call 0x5646C0` с `push 0xAD` (длина 173) и `push 0x50` (команда 80) ветки 137;
#  2) раскладка запроса в ветке 137: запрос = [ebp-0x110] (конструктор sub_4F9D00 обнуляет +112…+172), поле channel —
#     [ebp-0xA0] = запрос+0x70 (sprintf 0x56A61A), копия корзины [ebp-0x2A8] (rep movsd 0x66), код позиции 0 — [ebp-0x291]
#     = корзина+23 → запрос+66; т. е. расширение @128…@160 лежит внутри обнулённого хвоста и вне строки channel;
#  3) в .text ни один rel8/rel32/jcc и ни один abs32 не ведёт ВНУТРЬ площадок (GS 0x4F62AD…0x4F62B4, DB 0x43F0DD…0x43F0E4);
#  4) площадка DB 0x43F0DC = cmp dword [ebp-0x3D88],0x46 / jbe 0x43F142, за ней ветка SizeOver 0x43F0E5 (push 0x400 …);
#  5) другие патчи src/patches и DBPatch/src не пишут в эти площадки (текстовый поиск адресов);
#  6) DLL: в MAP AsdaPatch — P85_PremiumCartRows и P85_OnCartRequest; строка секции P85_PremiumCartRows в реестре;
#     в DBPatch.dll — строка секции P85_DbPostRows.
# Поведение — стенд tools/stand_p85 (gs/db × on/off/mismatch).
# Запуск: python verify_p85.py [AsdaPatch.dll] [DBPatch.dll]
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
DBDLL = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "DBPatch", "out", "DBPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = [os.path.join(HERE, "..", "src", "patches"), os.path.join(HERE, "..", "..", "DBPatch", "src")]
from srv_paths import ROOT as SRV_ROOT   # корень стойки — локальное зеркало по SSH (srv_mirror.py)
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
_d = os.environ.get("P77_IMG_DIR") or os.environ.get("P57_IMG_DIR")
if _d:
    GS_IMAGES = [("сток", _d + "/gs_stock.exe"), ("живой GameServer", _d + "/gs_live.exe"), ("живой Indun", _d + "/gs_indun.exe")]
DB_IMAGE = V2 + "DBManager/DBManager.exe"

GS_SITE, GS_LEN, GS_ORIG = 0x004F62AC, 9, bytes.fromhex("8b85f8f9ffff8b4804")
DB_SITE, DB_LEN, DB_ORIG = 0x0043F0DC, 9, bytes.fromhex("83bd78c2ffff46765d")
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


def refs_into(img, base, lo, hi, a, b):
    """Переходы rel8/rel32/jcc и abs32 внутрь (a, b] — адреса источников."""
    out = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    for ins in md.disasm(bytes(img[lo - base:hi - base]), lo):
        if ins.mnemonic.startswith("j") or ins.mnemonic == "call":
            m = re.match(r"0x([0-9a-f]+)$", ins.op_str)
            if m and a < int(m.group(1), 16) < b:
                out.append(ins.address)
    data = bytes(img[lo - base:hi - base])
    for k in range(0, len(data) - 3):
        v = struct.unpack_from("<I", data, k)[0]
        if a < v < b:
            out.append(lo + k)
    return out


def main():
    print("== verify_p85 ==")
    # ── GameServer ──
    for name, path in GS_IMAGES:
        if not os.path.exists(path):
            ok(False, "%s: образа нет (%s)" % (name, path))
            continue
        pe, img, base = load(path)
        lo, hi = text_range(pe, base)
        site = bytes(img[GS_SITE - base:GS_SITE - base + GS_LEN])
        ok(site == GS_ORIG, "%s: площадка 0x%08X = %s (mov eax,[ebp-0x608] / mov ecx,[eax+4])" % (name, GS_SITE, site.hex()))
        ins = disasm(img, base, 0x004F61B0, 0x004F6320)
        starts = {i.address for i in ins}
        ok(GS_SITE in starts and GS_SITE + 6 in starts and GS_SITE + GS_LEN in starts,
           "%s: площадка на границе инструкций (0x4F62AC / 0x4F62B2 / возврат 0x4F62B5)" % name)
        txt = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
        ok(txt.get(0x004F62B5) == "call 0x4c0250" and txt.get(0x004F62C2) == "push 0x5d" and txt.get(0x004F62C4) == "push 0xad"
           and txt.get(0x004F62C9) == "push 0x50" and txt.get(0x004F62D0) == "call 0x5646c0",
           "%s: за площадкой — отправка шлюзу 0x5646C0 (команда 0x50, длина 0xAD = 173)" % name)
        ok(txt.get(0x004F61BD) == "lea ecx, [ebp - 0x110]" and txt.get(0x004F61C3) == "call 0x4f9d00"
           and txt.get(0x004F61C8) == "lea ecx, [ebp - 0x2a8]" and txt.get(0x004F61D6) == "mov ecx, 0x66"
           and txt.get(0x004F61F4) == "mov edx, dword ptr [ebp - 0x297]"
           and txt.get(0x004F6214) == "mov ecx, dword ptr [ebp - 0x291]" and txt.get(0x004F621A) == "mov dword ptr [ebp - 0xce], ecx",
           "%s: запрос [ebp-0x110] (ctor 0x4F9D00), корзина [ebp-0x2A8] (408 б), код позиции 0 [ebp-0x291] → запрос+66" % name)
        ok(txt.get(0x004F629D) == "lea edx, [ebp - 0xa0]" and txt.get(0x004F62A4) == "call 0x56a61a",
           "%s: строка channel — [ebp-0xA0] = запрос+0x70 (sprintf 0x56A61A); расширение @128…@160 вне строки" % name)
        ctor = disasm(img, base, 0x004F9D00, 0x004F9DB0)
        ctxt = " | ".join("%s %s" % (i.mnemonic, i.op_str) for i in ctor)
        ok("0x3d" in ctxt and ("0x70" in ctxt or "+ 0x70" in ctxt),
           "%s: конструктор sub_4F9D00 обнуляет хвост +0x70 длиной 0x3D (61 б)" % name)
        r = refs_into(img, base, lo, hi, GS_SITE, GS_SITE + GS_LEN)
        ok(not r, "%s: переходов/abs32 внутрь площадки нет (%s)" % (name, ", ".join("0x%08X" % x for x in r[:5]) or "—"))
        # ★ r2: тело пакета 5070 = a4 − 0xB8 — в CharChargeShopBuy тело копируется в [ebp-0x408] (0xAB б), в 0x4F60E0 уходит &[ebp-0x350]
        cc = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in disasm(img, base, 0x00511DA0, 0x00512BC0)}
        ok(cc.get(0x00511ED9) == "push 0xab" and cc.get(0x00511EED) == "lea eax, [ebp - 0x408]" and cc.get(0x00511EF4) == "call 0x56a040"
           and cc.get(0x00512B93) == "lea ecx, [ebp - 0x350]" and cc.get(0x00512B9F) == "push 0x89" and cc.get(0x00512BAA) == "call 0x4f60e0",
           "%s: r2 — тело 5070 в [ebp-0x408] (memcpy 0xAB), в ветку 137 уходит &[ebp-0x350] ⇒ тело = a4 − 0xB8" % name)
        allins = disasm(img, base, lo, hi)
        sites = [i.address for i in allins if i.mnemonic == "call" and i.op_str == "0x4f60e0"]
        ok(len(sites) == 3 and 0x00512BAA in sites, "%s: вызовов sub_4F60E0 в .text %d (153/121/137), ветка 137 — только из CharChargeShopBuy" % (name, len(sites)))
    # ── DBManager ──
    if os.path.exists(DB_IMAGE):
        pe, img, base = load(DB_IMAGE)
        lo, hi = text_range(pe, base)
        site = bytes(img[DB_SITE - base:DB_SITE - base + DB_LEN])
        ok(site == DB_ORIG, "DBManager: площадка 0x%08X = %s (cmp [ebp-0x3D88],0x46 / jbe 0x43F142)" % (DB_SITE, site.hex()))
        ins = disasm(img, base, 0x0043F0B5, 0x0043F150)
        txt = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
        ok(txt.get(0x0043F0CF) == "mov dword ptr [ebp - 0x3d88], edx" and txt.get(0x0043F0E5) == "push 0x400"
           and txt.get(0x0043F142, "").startswith("mov dword ptr [ebp - 0x3d90], 0"),
           "DBManager: Size = строк×10 → [ebp-0x3D88]; 0x43F0E5 — SizeOver (memset буфера), 0x43F142 — разбор (/10)")
        r = refs_into(img, base, lo, hi, DB_SITE, DB_SITE + DB_LEN)
        ok(not r, "DBManager: переходов/abs32 внутрь площадки нет (%s)" % (", ".join("0x%08X" % x for x in r[:5]) or "—"))
    else:
        ok(False, "DBManager: образа нет (%s)" % DB_IMAGE)
    # ── чужие патчи ──
    hits = []
    for d in SRC:
        for fn in os.listdir(d):
            if not fn.endswith(".cpp") or "p85" in fn or fn in ("Registry.cpp", "Config.cpp"):   # реестр и шаблон ini — описания, не правки
                continue
            t = open(os.path.join(d, fn), encoding="utf-8", errors="replace").read().lower()
            for a in ("0x004f62a", "0x4f62a", "0x004f62b", "0x4f62b", "0x0043f0d", "0x43f0d", "0x0043f0e", "0x43f0e"):
                if a in t:
                    hits.append("%s:%s" % (fn, a))
    ok(not hits, "другие патчи не трогают площадки P85 (%s)" % (", ".join(hits) or "—"))
    # ── DLL ──
    m = open(MAP, encoding="latin-1").read() if os.path.exists(MAP) else ""
    ok("P85_PremiumCartRows" in m and "P85_OnCartRequest" in m, "MAP AsdaPatch: P85_PremiumCartRows и P85_OnCartRequest есть")
    d = open(DLL, "rb").read()
    ok("P85_PremiumCartRows".encode("utf-16-le") in d, "AsdaPatch.dll: секция реестра P85_PremiumCartRows")
    db = open(DBDLL, "rb").read() if os.path.exists(DBDLL) else b""
    ok("P85_DbPostRows".encode("utf-16-le") in db, "DBPatch.dll: секция реестра P85_DbPostRows")
    print("== ИТОГ verify_p85: ошибок %d ==" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
