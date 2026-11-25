# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_sites.py — волна В7: СТАТИЧЕСКОЕ подтверждение точек врезки криптопрослойки.
# Сервер НЕ запускается. По каждому образу читает байты входов функций IOCP-слоя,
# где прослойка встаёт между сокетом и разбором/сборкой старого кадра, и проверяет,
# что эти байты ОДИНАКОВЫ на стоке, деплое и живом образе (точка врезки стабильна).
# Запуск: py -3.13 verify_sites.py
import sys, hashlib
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

import os   # ★ 22.10.2026: для пути к srv_paths.py
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))   # ★ 22.10.2026: srv_paths.py
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
LM_STOCK  = r"@@ASTORY_DEV_ROOT@@\Donors\AsdaChroniclesInterlude_orig_copy\LoginManager.exe.orig"
LM_DEPLOY = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches\LoginPatch\out\LoginManager.exe.loginpatch.exe"
LM_LIVE   = V2 + "LoginManager/LoginManager.exe"
GS_STOCK  = SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"
GS_LIVE   = V2 + "GameServer/GameServer.exe"
GS_INDUN  = V2 + "Indun_GameServer/GameServer.exe"

# (имя точки, VA входа, что это для прослойки)
LM_SITES = [
    ("IoWorkerThread sub_4161E0",     0x4161E0, "рабочий поток IOCP: GQCS → recv-ветка/accept"),
    ("recv CCircleQ sub_418C00",      0x418C00, "ВХОД расшифровки: байты из ReadFile → разбор кадра"),
    ("recv thunk sub_415600",         0x415600, "клиентский под-сервер: recv → CopyToWriteBuffer"),
    ("recv thunk srv sub_415830",     0x415830, "межсерверный: recv → CopyToWriteBuffer"),
    ("Ciocp::Send sub_413AB0",        0x413AB0, "ИСХОД шифрования: единый choke-point перед WriteFile"),
    ("Ciocp::SendTemp sub_4141D0",    0x4141D0, "дослание остатка буфера отправки"),
    ("MakeHeaderSend sub_415860",     0x415860, "сборка старого кадра FB..FE (вызывает Ciocp::Send)"),
    ("Ciocp::SetConnectFlag 0x4144A0",0x4144A0, "accept/disc: сюда вешаем Reset() канала"),
    ("Ciocp::DisConnect 0x4138D0",   0x4138D0, "fix2b: ворота отложенного разрыва (кадры до рукопожатия)"),
]
GS_SITES = [
    ("IoWorkerThread 0x564900",       0x564900, "рабочий поток IOCP: GQCS → recv-ветка/accept"),
    ("recv CCircleQ 0x5656D0",        0x5656D0, "ВХОД расшифровки: байты из ReadFile → разбор кадра"),
    ("recv thunk sub_563C20",         0x563C20, "клиентский под-сервер: recv → CopyToWriteBuffer"),
    ("recv thunk srv sub_563E50",     0x563E50, "межсерверный: recv → CopyToWriteBuffer"),
    ("Ciocp::Send 0x561F20",          0x561F20, "ИСХОД шифрования: единый choke-point перед WriteFile"),
    ("Ciocp::SendTemp 0x562640",      0x562640, "дослание остатка буфера отправки"),
    ("Ciocp::SetConnectFlag 0x562910",0x562910, "accept/disc: сюда вешаем Reset() канала"),
    ("Ciocp::DisConnect 0x561C30",   0x561C30, "fix2b: ворота отложенного разрыва (кадры до рукопожатия)"),
]

def reader(path):
    pe = pefile.PE(path, fast_load=True)
    data = open(path, "rb").read()
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(base + s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    def rd(va, n):
        for sva, vs, raw, rs in secs:
            if sva <= va < sva + max(vs, rs):
                off = raw + (va - sva)
                return data[off:off+n]
        return None
    return rd

md = Cs(CS_ARCH_X86, CS_MODE_32)

def check(title, sites, images):
    print("\n=== %s ===" % title)
    readers = []
    for name, path in images:
        try:
            readers.append((name, reader(path)))
        except Exception as e:
            print("  [!] образ недоступен: %s (%s)" % (name, e))
    ok_all = True
    for sname, va, role in sites:
        digests = []
        first = None
        for iname, rd in readers:
            b = rd(va, 16)
            if b is None:
                digests.append((iname, None)); ok_all = False; continue
            if first is None: first = b
            digests.append((iname, b))
        same = all(b is not None and b == first for _, b in digests)
        ok_all = ok_all and same
        asm = ""
        if first:
            for ins in md.disasm(first, va):
                asm = "%s %s" % (ins.mnemonic, ins.op_str); break
        print("  [%s] 0x%06X %-28s %s" % ("OK " if same else "РАЗЛ", va, sname, role))
        print("        байты=%s  (%s)" % (first.hex() if first else "нет", asm))
        if not same:
            for iname, b in digests:
                print("        %-22s %s" % (iname, b.hex() if b else "нет"))
    return ok_all

a = check("LoginManager (15001) — LoginPatch.dll", LM_SITES,
          [("сток", LM_STOCK), ("деплой", LM_DEPLOY), ("живой", LM_LIVE)])
b = check("GameServer (15601) + Indun — AsdaPatch.dll", GS_SITES,
          [("сток", GS_STOCK), ("живой", GS_LIVE), ("Indun", GS_INDUN)])
print("\n%s" % ("ВСЕ ТОЧКИ ВРЕЗКИ СТАБИЛЬНЫ ВО ВСЕХ ОБРАЗАХ" if (a and b) else "ЕСТЬ РАСХОЖДЕНИЯ — СВЕРИТЬ ВРУЧНУЮ"))
