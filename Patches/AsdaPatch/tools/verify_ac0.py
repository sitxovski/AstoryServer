# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_ac0.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны античита А0 (2026-10-12):
#   AsdaPatch P47 (гейт GM-флага, сверка 20000↔логон, IP в DB-логон), P48 (автоблок),
#   P49 (кик за повторы, подпись 5450), DBPatch P50 (сверка личности при DB-логоне).
#
# Сервер НЕ запускается. Грузятся настоящие образы (сток, живой GameServer, живой Indun,
# живой DBManager) и собранные DLL. Проверяем:
#  1) исходные байты всех площадок в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок;
#  3) стабы найдены в DLL по сигнатурам; каждый `jmp dword ptr [..]` разыменован и ведёт
#     туда, куда задумано; вызовы C-функций — внутрь DLL;
#  4) unicorn: каждый стаб исполняется на подставном кадре, C-функция подменяется
#     заглушкой с заданным результатом — проверяются ветки (пропуск/отказ), стек, регистры,
#     раскладка аргументов отправки 2001/2089, пролог Send_DisConnectType, результат sub_524440;
#  5) DBPatch: цели двух call в диспетчере DBManager после подмены — обёртки внутри DBPatch.dll.
#
# ★ acj (12.10.2026): + площадки P53 (11 call в GameServer), P54 (2 jmp), N13 (4 call в NpcServer, 3 образа):
#   исходные байты во всех образах, переходы/abs32 внутрь, границы инструкций, push строки формата.
# ★ fix13 (13.10.2026): стабы AsdaPatch (P47/P48/P49 + новые сверки P53 St_*/LogTail/NotKnowTail и P54 Code*Stub) — по MAP
#   компоновщика (asdamap: имя + объект, метка MAP↔PE), сигнатура — второй метод. У DBPatch MAP нет (build.bat без /MAP) —
#   его часть (строки секции/запроса) без изменений.
# Запуск: python verify_ac0.py [AsdaPatch.dll] [DBPatch.dll]
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
                               UC_X86_REG_EIP)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
DLL_DB = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "DBPatch", "out", "DBPatch.dll")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
DB_IMAGES = [
    ("живой DBManager", V2 + "DBManager/DBManager.exe"),
    ("сток DBManager", V2 + "DBManager/DBManager-Original.exe"),
]

GS_SITES = [
    ("P47.gate",    0x0042AB4F, "8b45fc0fb74807898d38efffff"),
    ("P47.m4001",   0x00527692, "8b95d8fbffff"),
    ("P47.m5058",   0x0052CD3E, "8b85ccfbffff"),
    ("P47.ip2001",  0x0052773F, "6a0868d1070000"),
    ("P47.ip2089",  0x0052CF05, "6a0c6829080000"),
    ("P48.disc",    0x0052EDB0, "558bec83ec08"),
    ("P49.secret",  0x00524496, "c7400400000000"),
    ("P49.md5len",  0x004ED8CF, "6889000000"),
]
GS_NEIGHBOURS = [   # байты, на которые опираются адреса возврата/переходов стабов
    ("ret gate 0x42AB5C (дерево сравнений / P01)", 0x0042AB5C, "81bd38efffff75170000"),
    ("хвост switch 0x42F036",                     0x0042F036, "ff1528305800"),
    ("ret 4001 0x527698",                         0x00527698, "668b85e4fbffff"),
    ("отказ 4001 0x52764D",                       0x0052764D, "6810975900"),
    ("ret 5058 0x52CD44",                         0x0052CD44, "8b8dd0fbffff"),
    ("отказ 5058 0x52CCF9",                       0x0052CCF9, "68e8a45900"),
    ("ret ip2001 0x527746",                       0x00527746, "b938057e00e870cf0300"),
    ("ret ip2089 0x52CF0C",                       0x0052CF0C, "b938057e00e8aa770300"),
    ("ret disc 0x52EDB6",                         0x0052EDB6, "894df8"),
    ("эпилог sub_524440 0x52449F",                0x0052449F, "8be55dc20400"),
    ("xor eax,eax 0x52449D (ветка <=20)",         0x0052449D, "33c0"),
    ("call MD5 0x4ED8DE (P08-площадка, не трогаем)", 0x004ED8DE, "e81d66030085c07542"),
]
DB_SITES = [
    ("P50.c2001", 0x004026D1, "e8aa4d0000"),
    ("P50.c2089", 0x00402FE3, "e828440100"),
]

# ★ acj (12.10.2026): площадки P53 (журнал античита, GameServer), P54 (сообщение о блоке при входе) и
#   N13 (журнал античита, NpcServer). У P53 на DBManager площадок нет (только фоновый поток).
def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()

P53_GS = [   # (имя, va call, стоковая цель, push строки формата до call — 0 = нет)
    ("P53.CharMove",   0x0054543D, 0x00569DF0, 0x0059CB58),
    ("P53.CharReMove", 0x00545A84, 0x00569DF0, 0x0059CB1C),
    ("P53.HackCheck",  0x005272B4, 0x00569DF0, 0x00599624),
    ("P53.SecretErr",  0x0052440E, 0x00569DF0, 0x00598E64),
    ("P53.SecretDisc", 0x0052448B, 0x00569DF0, 0x00598E90),
    ("P53.Md5Secret",  0x00523FC5, 0x00569DF0, 0x00598E10),
    ("P53.Md5Plain",   0x00524044, 0x00569DF0, 0x00598DC8),
    ("P53.Item5450",   0x004ED910, 0x00569DF0, 0x00593448),
    ("P53.ShopCellob", 0x0050F561, 0x00569DF0, 0x00596730),
    ("P53.ShopNormal", 0x0050F91F, 0x00569DF0, 0x005966F4),
    ("P53.NotKnow",    0x0042F031, 0x005244B0, 0),
]
GS_SITES += [(n, va, _call(va, tgt)) for n, va, tgt, _ in P53_GS]
GS_SITES += [
    ("P54.c4001", 0x00527907, "6a05668b4508"),   # push 5 / mov ax,[ebp+8]  (jmp 6 б)
    ("P54.c2089", 0x0052D07A, "6a05668b4d08"),   # push 5 / mov cx,[ebp+8]  (jmp 6 б)
]
GS_NEIGHBOURS += [
    ("ret P54 4001 0x52790D (push eax)", 0x0052790D, "50"),
    ("ret P54 2089 0x52D080 (push ecx)", 0x0052D080, "51"),
    ("цель P53 писатель логов 0x569DF0 (пролог)", 0x00569DF0, "55"),
    ("цель P53 NotKnow 0x5244B0 (пролог)", 0x005244B0, "55"),
]
NPC_IMAGES = [
    ("сток NpcServer", SRV_ROOT + "/AsdaStory/NpcServer/NpcServer.exe"),
    ("живой NpcServer", V2 + "NpcServer/NpcServer.exe"),
    ("живой Indun NpcServer", V2 + "Indun_NpcServer/NpcServer.exe"),
]
N13_WRITER = 0x00408DC0
N13_NPC = [   # (имя, va call, push строки формата за 10 б до call)
    ("N13.Check",   0x0045F600, 0x004776A8),
    ("N13.Banish",  0x0045F674, 0x00477720),
    ("N13.Check2",  0x004601B4, 0x00478488),
    ("N13.Banish2", 0x00460228, 0x00478500),
]
NPC_SITES = [(n, va, _call(va, N13_WRITER)) for n, va, _ in N13_NPC]


def boundary_ok(img, base, va, ln):
    """Площадка заканчивается ровно на границе инструкции и сама начинается на границе
    (найдена цепочка декодирования из 1..48 байт до va, попадающая точно в va)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    total = 0
    for ins in md.disasm(bytes(img[va - base: va - base + ln + 16]), va):
        total += ins.size
        if total >= ln:
            end_ok = total == ln
            break
    else:
        end_ok = False
    start_ok = False
    for back in range(1, 48):
        for ins in md.disasm(bytes(img[va - base - back: va - base + 16]), va - back):
            if ins.address == va:
                start_ok = True
                break
            if ins.address > va:
                break
        if start_ok:
            break
    return start_ok, end_ok


def push_fmt_ok(img, base, va, fmt, maxback=24):
    for back in range(5, maxback + 1):
        p = va - base - back
        if img[p] == 0x68 and struct.unpack("<I", bytes(img[p + 1:p + 5]))[0] == fmt:
            return True
    return False


def extra_checks(gs_ref, db_ref):
    """★ acj: границы инструкций всех площадок (GS/DB) + N13 на трёх образах NpcServer."""
    print("-- границы инструкций площадок (сток GameServer)")
    pe, img, base = gs_ref
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "%-15s начало на границе: %s, конец на границе: %s" % (n, s, e))
    for n, va, tgt, fmt in P53_GS:
        if fmt:
            ok(push_fmt_ok(img, base, va, fmt), "%-15s push строки формата 0x%08X перед call" % (n, fmt))
    print("-- границы инструкций площадок (живой DBManager)")
    dpe, dimg, dbase = db_ref
    for n, va, o in DB_SITES:
        s, e = boundary_ok(dimg, dbase, va, len(bytes.fromhex(o)))
        ok(s and e, "%-15s начало на границе: %s, конец на границе: %s" % (n, s, e))
    npc_ref = None
    for name, path in NPC_IMAGES:
        print("-- %s: %s" % (name, path))
        npe, nimg, nbase = load(path)
        if npc_ref is None:
            npc_ref = (npe, nimg, nbase)
        for n, va, o in NPC_SITES:
            cur = bytes(nimg[va - nbase: va - nbase + 5])
            ok(cur == bytes.fromhex(o), "%-12s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, fmt in N13_NPC:
            p = va - nbase - 10
            ok(nimg[p] == 0x68 and struct.unpack("<I", bytes(nimg[p + 1:p + 5]))[0] == fmt,
               "%-12s push строки формата 0x%08X за 10 б до call" % (n, fmt))
        cur = bytes(nimg[N13_WRITER - nbase: N13_WRITER - nbase + 1])
        ok(cur == b"\x55", "писатель 0x%08X начинается с push ebp" % N13_WRITER)
        for n, va, o in NPC_SITES:
            s, e = boundary_ok(nimg, nbase, va, 5)
            ok(s and e, "%-12s начало на границе: %s, конец на границе: %s" % (n, s, e))
        print("-- перебор переходов/abs32 внутрь площадок N13 (%s)" % name)
        for n, c in scan_into(npe, nimg, nbase, NPC_SITES).items():
            ok(c == 0, "%-12s входов внутрь: %d" % (n, c))

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    pe = pefile.PE(path)
    return pe, bytearray(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.ImageBase


def text_range(pe):
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize


def scan_into(pe, img, base, sites):
    a, b = text_range(pe)
    hits = {s[0]: 0 for s in sites}
    rng = [(n, va, len(bytes.fromhex(o))) for n, va, o in sites]
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
            for n, va, ln in rng:
                if va < t < va + ln:
                    hits[n] += 1
    for i in range(0, len(img) - 4):
        v = struct.unpack("<I", bytes(img[i:i + 4]))[0]
        for n, va, ln in rng:
            if va < v < va + ln:
                hits[n] += 1
    return hits


def find_all(img, base, sig_hex):
    sig = bytes.fromhex(sig_hex.replace(" ", ""))
    out, start = [], 0
    while True:
        i = img.find(sig, start)
        if i < 0:
            return out
        out.append(base + i)
        start = i + 1


def disasm(img, base, va, n=0x80):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(bytes(img[va - base: va - base + n]), va))


def stub_targets(img, base, va, njmp=1):
    """jmp dword ptr [p] -> *p; call rel32 -> цель. До первого безусловного jmp dword ptr после последнего."""
    jmps, calls = [], []
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic in ("ret", "int3") or len(jmps) >= njmp:
            break
    return jmps, calls


# ── эмулятор ────────────────────────────────────────────────────────────────
class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)   # стек + кадр
        self.stops = set()
        self.fake = {}          # адрес C-функции -> (сколько байт аргументов, обработчик(uc, args)->eax)
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        if address in self.fake:
            nb, fn = self.fake[address]
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = struct.unpack("<%dI" % (nb // 4), uc.mem_read(esp + 4, nb)) if nb else ()
            eax = fn(uc, args, esp + 4)
            uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_ESP, esp + 4 + nb)
            uc.reg_write(UC_X86_REG_EIP, ret)
            return
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, mem=(), count=200):
        uc = self.uc
        for addr, data in mem:
            uc.mem_write(addr, data)
        for r, v in regs.items():
            uc.reg_write(r, v)
        self.stopped_at = None
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (uc.reg_read(UC_X86_REG_EIP), e))
        return self.stopped_at

    def r(self, reg):
        return self.uc.reg_read(reg)

    def rd(self, addr, n=4):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0] if n == 4 else bytes(self.uc.mem_read(addr, n))


def main():
    # ── 1–2. площадки GameServer ─────────────────────────────────────────────
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        for n, va, o in GS_SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "%-11s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- перебор кодировок переходов/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "%-15s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref

    db_ref = None
    for name, path in DB_IMAGES:
        print("-- %s: %s" % (name, path))
        dpe, dimg0, dbase0 = load(path)
        if db_ref is None:
            db_ref = (dpe, dimg0, dbase0)
        for n, va, o in DB_SITES:
            cur = bytes(dimg0[va - dbase0: va - dbase0 + 5])
            ok(cur == bytes.fromhex(o), "%-9s 0x%08X = %s" % (n, va, cur.hex()))
    dpe, dimg0, dbase0 = db_ref
    for n, c in scan_into(dpe, dimg0, dbase0, DB_SITES).items():
        ok(c == 0, "%-9s входов внутрь: %d" % (n, c))
    extra_checks(gs_ref, db_ref)

    # ── 3. стабы AsdaPatch ───────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    sigs = {
        "GateStub":        "8b45fc0fb74807898d38efffff60",
        "LogonMatchStub":  "60ffb5dcfbffffffb5d8fbffff",
        "PortalMatchStub": "60ffb5d0fbffffffb5ccfbffff",
        "LogonIpStub":     "608d4424206a0850",
        "PortalIpStub":    "608d4424206a0c50",
        "DisconnectStub":  "60ff7424200fb644242c50",   # ★ acdb: + адрес возврата 4-м аргументом
        # ★ sec2c (15.10.2026, Н-3): стаб P49 сперва запоминает счётчик Secret ПО CUser — pushad; pushfd; push [eax+4]; push eax;
        #   call P49_NoteSecretPre (cdecl); add esp,8; popfd; popad — затем прежнее тело. Сигнатура по началу стаба, цель call по
        #   MAP, тело и аргументы — эмуляцией ниже. (sec2: 518b4804890d — одна пара глобалов на процесс.)
        "SecretKickStub":  "609cff700450e8",
    }
    expect = {
        "GateStub":        [0x0042AB5C, 0x0042F036],
        "LogonMatchStub":  [0x00527698, 0x0052764D],
        "PortalMatchStub": [0x0052CD44, 0x0052CCF9],
        "LogonIpStub":     [0x00527746],
        "PortalIpStub":    [0x0052CF0C],
        "DisconnectStub":  [0x0052EDB6],
        "SecretKickStub":  [0x0052449F],
    }
    stubs, cfun = {}, {}
    lo, hi = lbase, lbase + len(limg)
    # ★ fix13: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP) — имя И объект решают,
    #   сигнатура — второй метод (стаб по MAP обязан быть среди её кандидатов, прочие — чужие именованные стабы);
    #   цель call сверяется с C-функцией по MAP (исходники p47/p48: GateStub→P47_OperatorGate, *MatchStub→P47_LogonMatch,
    #   *IpStub→P47_PrepareDbBody, DisconnectStub→P48_OnDisconnectType).
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))

    def msym(name, obj=None):
        try:
            return dmap.sym(name, obj)
        except ValueError as e:
            ok(False, str(e))
            return None
    MAP_OBJ = {"GateStub": "p47_identity_operator_gate", "LogonMatchStub": "p47_identity_operator_gate",
               "PortalMatchStub": "p47_identity_operator_gate", "LogonIpStub": "p47_identity_operator_gate",
               "PortalIpStub": "p47_identity_operator_gate", "DisconnectStub": "p48_kick_autoblock",
               "SecretKickStub": "p49_original_checks_restore"}
    MAP_CFUN = {"GateStub": "P47_OperatorGate", "LogonMatchStub": "P47_LogonMatch", "PortalMatchStub": "P47_LogonMatch",
                "LogonIpStub": "P47_PrepareDbBody", "PortalIpStub": "P47_PrepareDbBody", "DisconnectStub": "P48_OnDisconnectType",
                "SecretKickStub": "P49_NoteSecretPre"}   # ★ sec2c
    for k, s in sigs.items():
        c = find_all(limg, lbase, s)
        va, good, msg = resolve(dmap, k, MAP_OBJ[k], c)
        ok(good, msg)
        ok(va is not None, "%s: найден по MAP, кандидатов сигнатуры %d (0x%08X)" % (k, len(c), va or 0))
        if va is None:
            continue
        stubs[k] = va
        jmps, calls = stub_targets(limg, lbase, va, len(expect[k]))
        ok(jmps[:len(expect[k])] == expect[k], "%s: jmp [..] -> %s (ожид. %s)"
           % (k, ["0x%08X" % x for x in jmps], ["0x%08X" % x for x in expect[k]]))
        ok(len(calls) == 1 and lo <= calls[0] < hi, "%s: call C-функции внутри DLL (0x%08X)"
           % (k, calls[0] if calls else 0))
        cv = msym(MAP_CFUN[k], MAP_OBJ[k])
        ok(bool(calls) and calls[0] == cv, "%s: call → %s по MAP (0x%08X)" % (k, MAP_CFUN[k], cv or 0))
        if calls:
            cfun[k] = calls[0]

    # ★ fix13: стабы P53 (журнал античита; площадки сверены выше) и P54 — по MAP: St_* = `push вид; jmp LogTail/NotKnowTail`,
    #   хвосты зовут P53_OnSite и уходят `jmp [..]` в стоковые цели площадок; Code*Stub зовут P54_KickCode и возвращаются
    #   за вытесненные инструкции (исходники p53_ac_journal_gs.cpp / p54_blocked_login_message.cpp).
    print("-- стабы P53/P54 по MAP")
    on_site = msym("P53_OnSite", "p53_ac_journal_gs")
    tails = {}
    for tn, tgt in (("LogTail", 0x00569DF0), ("NotKnowTail", 0x005244B0)):
        tv = msym(tn, "p53_ac_journal_gs")
        if tv is None:
            continue
        c = find_all(limg, lbase, "60 8d 44 24 24 50 55 51 ff 74 24 2c e8")
        va, good, msg = resolve(dmap, tn, "p53_ac_journal_gs", c)
        ok(good, msg)
        tails[tn] = tv
        jmps, calls = stub_targets(limg, lbase, tv)
        ok(jmps == [tgt] and calls == [on_site], "%s: call → P53_OnSite по MAP (%s), jmp [..] → 0x%08X (%s)"
           % (tn, ["0x%08X" % x for x in calls], tgt, ["0x%08X" % x for x in jmps]))
    for kind, (sn, tn, (pn, va53, _t, _f)) in enumerate(zip(
            ("St_CharMove", "St_CharReMove", "St_HackCheck", "St_SecretErr", "St_SecretDisc", "St_Md5Secret",
             "St_Md5Plain", "St_Item5450", "St_ShopCellob", "St_ShopNormal", "St_NotKnow"),
            ["LogTail"] * 10 + ["NotKnowTail"], P53_GS), start=1):
        sv = msym(sn, "p53_ac_journal_gs")
        if sv is None:
            continue
        o = sv - lbase
        tg = sv + 2 + 5 + struct.unpack("<i", bytes(limg[o + 3:o + 7]))[0] if limg[o + 2] == 0xE9 else None
        ok(limg[o] == 0x6A and limg[o + 1] == kind and tg is not None and tg == tails.get(tn),
           "%-14s (%s, MAP 0x%08X): push %d; jmp %s (0x%08X)" % (sn, pn, sv, kind, tn, tg or 0))
    kick = msym("P54_KickCode", "p54_blocked_login_message")
    for sn, sig, ret in (("Code4001Stub", "60 8d 85 e0 fe ff ff 50 e8", 0x0052790D), ("Code2089Stub", "60 8d 85 e8 fe ff ff 50 e8", 0x0052D080)):
        c = find_all(limg, lbase, sig)
        va, good, msg = resolve(dmap, sn, "p54_blocked_login_message", c)
        ok(good, msg)
        if va is None:
            continue
        jmps, calls = stub_targets(limg, lbase, va)
        ok(jmps == [ret] and calls == [kick], "%s: call → P54_KickCode по MAP (%s), jmp [..] → 0x%08X (%s)"
           % (sn, ["0x%08X" % x for x in calls], ret, ["0x%08X" % x for x in jmps]))

    # ── 4. эмуляция ──────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    # GateStub: кадр диспетчера. [ebp-4]=pkt, [ebp-0x44]=userNum, [ebp-0x10C4]=this → [[+4]+0x34]=mgr
    if "GateStub" in stubs:
        PKT, THIS, SUB = 0x00150000, 0x00160000, 0x00161000
        seen = {}
        for verdict, want in ((1, 0x0042AB5C), (0, 0x0042F036)):
            def gate(uc, a, sp, v=verdict):
                seen["args"] = a
                return v
            emu.fake = {cfun["GateStub"]: (16, gate)}
            emu.stops = {0x0042AB5C, 0x0042F036}
            mem = [(FRAME - 4, struct.pack("<I", PKT)), (FRAME - 0x44, struct.pack("<h", 77)),
                   (FRAME - 0x10C4, struct.pack("<I", THIS)), (THIS + 4, struct.pack("<I", SUB)),
                   (SUB + 0x34, struct.pack("<I", 0xC0FFEE)), (PKT + 7, struct.pack("<H", 6005))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: 0xAAAA,
                                             UC_X86_REG_ECX: 0xCCCC})
            at = emu.run(stubs["GateStub"], regs, mem)
            a = seen.get("args", ())
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "GateStub вердикт %d -> 0x%08X (стек сбалансирован: %s)"
               % (verdict, at or 0, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(a == (0xC0FFEE, 6005, 77, PKT), "  аргументы гейта (mgr, op, userNum, pkt) = %s" % (tuple(hex(x) for x in a),))
            ok(emu.rd(FRAME - 0x10C8) == 6005, "  [ebp-0x10C8] = опкод (вытесненная запись)")
            if verdict:
                ok(emu.r(UC_X86_REG_EAX) == PKT and emu.r(UC_X86_REG_ECX) == 6005,
                   "  на выходе eax = pkt, ecx = опкод (как после стоковых команд)")
            ok(emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333,
               "  ebx/esi/edi сохранены")

    # Match-стабы
    for k, uiOff, userOff, ret, refuse, kind, reg in (
            ("LogonMatchStub", 0x424, 0x428, 0x00527698, 0x0052764D, 1, UC_X86_REG_EDX),
            ("PortalMatchStub", 0x430, 0x434, 0x0052CD44, 0x0052CCF9, 2, UC_X86_REG_EAX)):
        if k not in stubs:
            continue
        for verdict, want in ((1, ret), (0, refuse)):
            seen = {}

            def m(uc, a, sp, v=verdict):
                seen["a"] = a
                return v
            emu.fake = {cfun[k]: (16, m)}
            emu.stops = {ret, refuse}
            mem = [(FRAME - uiOff, struct.pack("<i", 12345)), (FRAME - userOff, struct.pack("<I", 0x00170000)),
                   (FRAME + 8, struct.pack("<h", 33))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0})
            at = emu.run(stubs[k], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "%s вердикт %d -> 0x%08X, стек %s"
               % (k, verdict, at or 0, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(seen.get("a") == (kind, 33, 0x00170000, 12345), "  аргументы (вид, userNum, CUser, UserIndex) = %s"
               % (seen.get("a"),))
            if verdict:
                ok(emu.r(reg) == 0x00170000, "  вытесненная загрузка CUser* в регистр выполнена")

    # IP-стабы: на стеке уже dbIdx, &тело, userNum
    for k, stockLen, op, ret in (("LogonIpStub", 8, 0x7D1, 0x00527746), ("PortalIpStub", 12, 0x829, 0x0052CF0C)):
        if k not in stubs:
            continue
        for newLen, newBody in ((stockLen, None), (stockLen + 8, 0x00180000)):
            seen = {}

            def prep(uc, a, sp, nl=newLen, nb=newBody):
                seen["a"] = a
                if nb:   # как P47_PrepareDbBody: args[1] = буфер
                    uc.mem_write(a[1] + 4, struct.pack("<I", nb))
                return nl
            emu.fake = {cfun[k]: (12, prep)}
            emu.stops = {ret}
            sp0 = ESP0 - 12
            mem = [(sp0, struct.pack("<III", 5, 0x00190000, 44)), (FRAME + 8, struct.pack("<h", 44))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp0})
            at = emu.run(stubs[k], regs, mem)
            esp = emu.r(UC_X86_REG_ESP)
            stack = struct.unpack("<5I", emu.uc.mem_read(esp, 20))
            want_stack = (op, newLen, 5, newBody or 0x00190000, 44)
            ok(at == ret and esp == sp0 - 8 and stack == want_stack,
               "%s длина %d: -> 0x%08X, стек [op,len,db,тело,userNum] = %s" % (k, newLen, at or 0, tuple(hex(x) for x in stack)))
            ok(seen.get("a", (None,))[0] == 44 and seen["a"][1] == sp0 and seen["a"][2] == stockLen,
               "  аргументы подготовки (userNum, &args, стоковая длина) = %s" % (seen.get("a"),))

    # DisconnectStub: [esp]=ret, [esp+4]=userNum, [esp+8]=тип, ecx=mgr
    if "DisconnectStub" in stubs:
        seen = {}

        def disc(uc, a, sp):
            seen["a"] = a
            return 0
        emu.fake = {cfun["DisconnectStub"]: (16, disc)}   # ★ acdb: 4 аргумента (+ адрес возврата)
        emu.stops = {0x0052EDB6}
        sp0 = ESP0 - 12
        mem = [(sp0, struct.pack("<IIII", 0xDEADBEEF, 0x0000FFFF & 123, 3, 0))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: 0x0BADF00D, UC_X86_REG_ESP: sp0, UC_X86_REG_ECX: 0xC0FFEE})
        at = emu.run(stubs["DisconnectStub"], regs, mem)
        ok(at == 0x0052EDB6, "DisconnectStub -> 0x52EDB6")
        ok(seen.get("a") == (0xC0FFEE, 123, 3, 0xDEADBEEF), "  аргументы (mgr, userNum, тип, адрес возврата) = %s" % (seen.get("a"),))
        esp, ebp = emu.r(UC_X86_REG_ESP), emu.r(UC_X86_REG_EBP)
        ok(ebp == sp0 - 4 and esp == ebp - 8 and emu.rd(ebp) == 0x0BADF00D and emu.r(UC_X86_REG_ECX) == 0xC0FFEE,
           "  пролог воспроизведён: push ebp / mov ebp,esp / sub esp,8; ecx = mgr сохранён")

    # SecretKickStub: eax = CUser*
    if "SecretKickStub" in stubs and "SecretKickStub" in cfun:
        # ★ sec2c: P49_NoteSecretPre (cdecl, 2 аргумента — стек чистит стаб) подменена: запоминает аргументы и портит
        #   «изменяемые» регистры и флаги — стаб обязан их восстановить (pushad/pushfd … popfd/popad).
        seen = {}

        def note(uc, a, sp):
            seen["a"] = struct.unpack("<2I", uc.mem_read(sp, 8))   # cdecl: аргументы читаем, со стека не снимаем (nb = 0)
            uc.reg_write(UC_X86_REG_ECX, 0x0BADBAD1); uc.reg_write(UC_X86_REG_EDX, 0x0BADBAD2)
            return 0x0BADBAD0
        emu.fake = {cfun["SecretKickStub"]: (0, note)}
        emu.stops = {0x0052449F}
        CU = 0x001A0000
        regs = dict(REGS0); regs.update({UC_X86_REG_EAX: CU, UC_X86_REG_ESP: ESP0, UC_X86_REG_EBP: FRAME})
        regs[UC_X86_REG_ECX] = 0xC0FFEE
        regs[UC_X86_REG_EDX] = 0xD00D
        at = emu.run(stubs["SecretKickStub"], regs, [(CU + 4, struct.pack("<I", 21))])
        ok(at == 0x0052449F and emu.r(UC_X86_REG_EAX) == 1 and emu.rd(CU + 4) == 0,
           "SecretKickStub: счётчик сброшен, eax = 1, переход на эпилог 0x52449F")
        ok(seen.get("a", (None, None))[:2] == (CU, 21),
           "SecretKickStub (sec2c): P49_NoteSecretPre(CUser, счётчик до сброса) = %s (ожид. (0x%08X, 21))"
           % (tuple(hex(x) for x in seen.get("a", ())[:2]), CU))
        ok(emu.r(UC_X86_REG_ECX) == 0xC0FFEE and emu.r(UC_X86_REG_EDX) == 0xD00D and emu.r(UC_X86_REG_ESP) == ESP0
           and emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333,
           "SecretKickStub (sec2c): ecx/edx/ebx/esi/edi и стек сохранены")

    # ── 5. DBPatch: цели call после подмены ─────────────────────────────────
    print("-- DBPatch %s" % DLL_DB)
    bpe, bimg, bbase = load(DLL_DB)
    found = [bytes(bimg).find(s.encode("utf-16-le")) >= 0 for s in ("P50_IdentityCheck",)]
    ok(all(found), "секция P50_IdentityCheck присутствует в DBPatch.dll")
    sqlfmt = bytes(bimg).find(b"EXEC dbo.UP_AC_IdentityCheck %d, %d, '%s'")
    ok(sqlfmt >= 0, "строка запроса UP_AC_IdentityCheck в DBPatch.dll")

    print("\nИТОГ: %s" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
