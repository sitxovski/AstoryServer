# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p71.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P71 (модульные сравнения сроков GameServer при переходе
#   GetTickCount через 2^32; оборона dev-сервера, 2026-10-15). Образец — verify_p57.py.
#
# Сервер НЕ запускается. Грузятся настоящие образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и
# собранная AsdaPatch.dll (+ её MAP). Проверяем:
#  1) исходные байты всех 8 площадок, их «соседей» (jcc/код стока сразу после) и опор (вызовы GetTickCount через ячейку
#     импорта 0x583028, писатели сроков «такт + 15000», гейты «≠ 0», вычисление T = now − 300000) в каждом образе;
#     ячейка импорта 0x583028 = kernel32!GetTickCount;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и соседи начинаются/кончаются
#     на границе инструкции;
#  3) стабы найдены в DLL по MAP (однозначно) и совпадают с ожидаемым кодом (сигнатуры с подстановкой адреса ячейки);
#     переменная g_iatGetTickCount = 0x00583028;
#     [p71fix] C5 0x46C335 — байтовая правка кика голосованием (add → mov: в БД уходит длительность 1800 с), сквозной прогон
#     C1 → сток → C1b, кадр кика до call sub_46AA10 на правленом и неправленом образе, значение > MaxPenaltySec → истёкший срок.
#  4) unicorn: в копию образа стока кладутся те же `call стаб` + nop, что ставит DLL, и КАЖДАЯ площадка исполняется с
#     настоящим jcc стока на кадрах: срок в будущем / в прошлом / равен / срок до перехода 2^32 и now после / now до и
#     срок после / аптайм ≥ 2^31 / поле 0 — ветвь сравнивается с ожидаемым модульным ответом; баланс стека и
#     сохранность регистров (ebx/esi/edi + те, что сток читает после площадки).
# Запуск: python verify_p71.py [AsdaPatch.dll]   (P57_IMG_DIR — папка локальных копий образов)
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
sys.path.insert(0, HERE)
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
if os.environ.get("P57_IMG_DIR"):   # локальные копии образов (те же md5)
    d = os.environ["P57_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe"), ("живой GameServer", d + "/gs_live.exe"), ("живой Indun", d + "/gs_indun.exe")]

IAT_TICK = 0x00583028

# (имя, VA, байты) — площадки (вытесняются `call стаб` + nop)
GS_SITES = [
    ("A.soulCmp",     0x0048B4FD, "3b8861f40300"),                   # cmp ecx,[eax+3F461h]
    ("B.partyCmp",    0x0046C111, "3b940122010000"),                 # cmp edx,[ecx+eax+122h]
    ("C1.penWrite",   0x00466082, "69c0e80300008b4dd4898154f40300"), # imul eax,eax,3E8h; mov ecx,[ebp-2Ch]; mov [ecx+3F454h],eax
    ("C1b.penLogin",  0x004660FD, "3b8154f40300"),                   # cmp eax,[ecx+3F454h]
    ("C2.penTimer",   0x0046A9A8, "3b9154f40300"),                   # cmp edx,[ecx+3F454h]
    ("C3a.penDisc",   0x00525CAC, "8b9154f40300"),                   # mov edx,[ecx+3F454h]
    ("C3b.penPortal", 0x005268BF, "8b9154f40300"),                   # mov edx,[ecx+3F454h]
    ("D.itemCmp",     0x00422650, "8b42253b45fc"),                   # mov eax,[edx+25h]; cmp eax,[ebp-4]
    ("C5.kickAdd",    0x0046C335, "0540771b00"),                     # [p71fix] add eax,1B7740h -> mov eax,1B7740h (байты, без стаба)
]
# соседи (сразу после площадки; не меняются) и опоры
GS_NEIGHBOURS = [
    ("A jb 0x48B503 → 0x48B527",                      0x0048B503, "7222"),
    ("A fire: push 1; push 3 0x48B505",               0x0048B505, "6a016a03"),
    ("A call [GetTickCount] 0x48B4EE",                0x0048B4EE, "ff1528305800"),
    ("A писатель sub_48AFF0 0x48B0FE (+15000)",        0x0048B0FE, "05983a00008b4df889816" + "1f40300"),
    ("A писатель sub_48B4C0 0x48B519 (+15000)",        0x0048B519, "05983a00008b4df8898161f40300"),
    ("A писатель sub_48E0A0 0x48E156 (+15000)",        0x0048E156, "05983a00008b4ddc898161f40300"),
    ("B jb rel32 0x46C118 → 0x46C3B8",                0x0046C118, "0f829a020000"),
    ("B гейт ≠0 0x46C0F4",                            0x0046C0F4, "83bc0a2201000000" + "0f86b6020000"),
    ("B call [GetTickCount] 0x46C0DF",                0x0046C0DF, "ff1528305800"),
    ("B писатель 0x46BE28 (+15000) … 0x46BE37",       0x0046BE28, "05983a00000fbf55e86bd2418b4d8c89841122010000"),
    ("C1 после записи: lea ecx,[ebp-8] 0x466091",     0x00466091, "8d4df8e817590300"),
    ("C1 до записи: mov eax,[ebp-14h] 0x46607F",      0x0046607F, "8b45ec"),
    ("C гейт ≠0 при входе 0x4660EB",                  0x004660EB, "83b854f40300007638"),
    ("C call [GetTickCount] при входе 0x4660F4",      0x004660F4, "ff15283058008b4dd4"),
    ("C1b jae 0x466103 → 0x46612C",                   0x00466103, "7327c645db01"),
    ("C истёк при входе 0x46612C",                    0x0046612C, "8b45d483b854f40300007424"),
    ("C гейт ≠0 TimerProcess 0x46A999",               0x0046A999, "83b854f4030000765f"),
    ("C call [GetTickCount] TimerProcess 0x46A98D",   0x0046A98D, "ff15283058008945fc"),
    ("C2 jb 0x46A9AE → 0x46AA01",                     0x0046A9AE, "72518b45f8c78054f4030000000000"),
    ("C гейт ≠0 разрыв 0x525C9D",                     0x00525C9D, "83b854f40300007623"),
    ("C3a после: push edx; mov ax,[ebp+8] 0x525CB2",  0x00525CB2, "52668b4508508b8d34f5ffff"),
    ("C гейт ≠0 портал 0x5268B0",                     0x005268B0, "83b854f40300007623"),
    ("C3b после: push edx; mov ax,[ebp+8] 0x5268C5",  0x005268C5, "52668b4508508b8d40f9ffff"),
    ("C sub_46AA10 пролог",                           0x0046AA10, "558bec83ec14"),
    ("D ja 0x422656 → 0x4226A9",                      0x00422656, "7751"),
    ("D T = GetTickCount − 300000 → [ebp-4] 0x422555", 0x00422555, "ff15283058002de09304008945fc"),
    ("D удалить: 0x422658",                           0x00422658, "8b8db4f9ffff"),
    ("D цель ja 0x4226A9 (jmp 0x422591)",             0x004226A9, "e9e3feffff"),
    ("C5 call [GetTickCount] 0x46C32F",               0x0046C32F, "ff1528305800"),
    ("C5 push eax; mov dx,[ebp-0B0h]; push edx 0x46C33A", 0x0046C33A, "50668b9550ffffff52"),
    ("C5 mov ecx,[ebp-0B4h]; call sub_46AA10 0x46C343", 0x0046C343, "8b8d4cffffffe8c2e6ffff"),
    ("C5 после вызова: movzx eax,[ebp-9] 0x46C34E",   0x0046C34E, "0fb645f785c0"),
]
BOUNDARY_EXTRA = [0x0048B503, 0x0048B505, 0x0048B527, 0x0046C118, 0x0046C11E, 0x0046C3B8, 0x00466091, 0x00466103, 0x00466105,
                  0x0046612C, 0x0046A9AE, 0x0046A9B0, 0x0046AA01, 0x00525CB2, 0x005268C5, 0x00422656, 0x00422658, 0x004226A9,
                  0x0046C32F, 0x0046C33A, 0x0046C349, 0x0046C34E, 0x00466138, 0x0046615C]

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


def boundary_ok(img, base, va, ln):
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


def match(img, base, va, pat):
    """pat — hex с '??' для любого байта."""
    pat = pat.replace(" ", "")
    for i in range(0, len(pat), 2):
        p = pat[i:i + 2]
        if p == "??":
            continue
        if img[va - base + i // 2] != int(p, 16):
            return False
    return True


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)   # стек + кадры + подставные объекты
        self.uc.mem_map(0x0F000000, 0x00001000)   # «kernel32!GetTickCount» для ячейки импорта
        self.stops = set()
        self.fake = {}
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

    def run(self, start, regs, mem=(), count=400):
        uc = self.uc
        for addr, data in mem:
            uc.mem_write(addr, data)
        for r, v in regs.items():
            uc.reg_write(r, v & 0xFFFFFFFF)
        self.stopped_at = None
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (uc.reg_read(UC_X86_REG_EIP), e))
        return self.stopped_at

    def r(self, reg):
        return self.uc.reg_read(reg)

    def rd(self, addr):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]


def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def main():
    gs_ref = None
    for name, path in GS_IMAGES:
        print("-- %s: %s" % (name, path))
        pe, img, base = load(path)
        if gs_ref is None:
            gs_ref = (pe, img, base)
        for n, va, o in GS_SITES:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "%-14s 0x%08X = %s" % (n, va, cur.hex()))
        for n, va, o in GS_NEIGHBOURS:
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед/опора: %s = %s" % (n, cur.hex()))
        imp = None
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                if i.address == IAT_TICK:
                    imp = (e.dll.decode("ascii", "replace"), (i.name or b"?").decode("ascii", "replace"))
        ok(imp is not None and imp[0].lower() == "kernel32.dll" and imp[1] == "GetTickCount", "ячейка импорта 0x%08X = %s" % (IAT_TICK, imp))
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- переходы/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "%-14s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref
    print("-- границы инструкций (сток)")
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "%-14s 0x%08X: начало %s, конец %s" % (n, va, s, e))
    for va in BOUNDARY_EXTRA:
        s, _ = boundary_ok(img, base, va, 1)
        ok(s, "цель/сосед 0x%08X на границе инструкции" % va)
    # строка лога sub_46AA10 — подтверждение смысла поля (+0x3F454 = штраф, «Convert Penalty Time»)
    s_conv = bytes(img).find(b"[I] Convert Penalty Time..!! UserIndex:%d, CharIdx:%d, Time:%d")
    ok(s_conv > 0, "строка «[I] Convert Penalty Time..!!» в образе (0x%08X)" % (base + s_conv if s_conv > 0 else 0))
    if s_conv > 0:
        ok(bytes(img[0x46AA10 - base: 0x46AAF0 - base]).find(struct.pack("<I", base + s_conv)) > 0, "  sub_46AA10 ссылается на неё (push imm32)")

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    from asdamap import DllMap, map_matches_dll
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))
    OBJ = "p71_tick_deadline_wrap"
    try:
        g_iat = dmap.sym("g_iatGetTickCount", OBJ)
        v = struct.unpack("<I", bytes(limg[g_iat - lbase: g_iat - lbase + 4]))[0]
        ok(v == IAT_TICK, "g_iatGetTickCount @0x%08X = 0x%08X (ожид. 0x%08X)" % (g_iat, v, IAT_TICK))
    except ValueError as e:
        ok(False, str(e))
        g_iat = 0
    iat_hex = struct.pack("<I", g_iat).hex()
    try:
        g_max = dmap.sym("g_maxPenaltySec", OBJ)
        v = struct.unpack("<I", bytes(limg[g_max - lbase: g_max - lbase + 4]))[0]
        ok(v == 604800, "g_maxPenaltySec @0x%08X = %u (умолчание 604800 = 7 сут)" % (g_max, v))
    except ValueError as e:
        ok(False, str(e))
        g_max = 0
    max_hex = struct.pack("<I", g_max).hex()
    try:
        stale_fn = dmap.sym("P71_StalePenalty", OBJ)
        ok(stale_fn > 0, "P71_StalePenalty в MAP @0x%08X" % stale_fn)
    except ValueError as e:
        ok(False, str(e))
        stale_fn = 0
    sigs = {
        "St71_SoulGuarder":     "52 8b9061f40300 85d2 7406 f7da 03d1 d1e2 5a c3",
        "St71_PartyConsent":    "52 2b940122010000 d1e2 5a c3",
        "St71_PenaltyWrite":    "51 52 85c0 7e?? 3b05" + max_hex + " 77?? 69c0e8030000 50 a1" + iat_hex +
                                " ff10 59 03c1 75?? b801000000 eb?? 8b4dd4 51 50 e8???????? 83c408 83e801 75?? 83e801 eb?? 33c0"
                                " 8b4dd4 898154f40300 5a 59 c3",
        "St71_PenaltyLoginCmp": "50 2b8154f40300 d1e0 58 c3",
        "St71_PenaltyTimerCmp": "52 2b9154f40300 d1e2 5a c3",
        "St71_PenaltyRemain":   "50 51 a1" + iat_hex + " ff10 59 8b9154f40300 2bd0 7902 33d2 58 c3",
        "St71_MapItem":         "8b4225 85c0 7407 50 2b45fc d1e0 58 c3",
    }
    stubs = {}
    for k, pat in sigs.items():
        try:
            va = dmap.sym(k, OBJ)
        except ValueError as e:
            ok(False, str(e))
            continue
        good = match(limg, lbase, va, pat)
        ok(good, "%s @0x%08X: код совпадает с разобранным (%d б)" % (k, va, len(pat.replace(" ", "")) // 2))
        stubs[k] = va
        if k == "St71_PenaltyWrite":
            # call rel32 внутри стаба ведёт на P71_StalePenalty
            p = pat.replace(" ", "").find("e8????????") // 2
            rel = struct.unpack("<i", bytes(limg[va - lbase + p + 1: va - lbase + p + 5]))[0]
            ok(va + p + 5 + rel == stale_fn, "  call в стабе -> 0x%08X (P71_StalePenalty 0x%08X)" % (va + p + 5 + rel, stale_fn))
    try:
        ok(dmap.sym("P71_TickDeadlineWrap", OBJ) > 0, "P71_TickDeadlineWrap в MAP (%s)" % OBJ)
    except ValueError as e:
        ok(False, str(e))
    site_stub = {
        "A.soulCmp": "St71_SoulGuarder", "B.partyCmp": "St71_PartyConsent", "C1.penWrite": "St71_PenaltyWrite",
        "C1b.penLogin": "St71_PenaltyLoginCmp", "C2.penTimer": "St71_PenaltyTimerCmp", "C3a.penDisc": "St71_PenaltyRemain",
        "C3b.penPortal": "St71_PenaltyRemain", "D.itemCmp": "St71_MapItem",
    }
    if len(stubs) != 7:
        print("=== ИТОГ: ОШИБОК %d (стабы не найдены — эмуляция пропущена) ===" % bad)
        return 1

    # ── эмуляция: образ стока + те же call/nop, что пишет DLL ────────────────
    print("-- эмуляция площадок (копия образа стока с `call стаб` + nop; jcc стока настоящие)")
    pimg = bytearray(img)
    for n, va, o in GS_SITES:
        ln = len(bytes.fromhex(o))
        if n == "C5.kickAdd":
            pimg[va - base: va - base + ln] = bytes.fromhex("b840771b00")
            continue
        tgt = stubs[site_stub[n]]
        pimg[va - base: va - base + ln] = b"\xe8" + struct.pack("<i", tgt - (va + 5)) + b"\x90" * (ln - 5)
    emu = Emu(pimg, base, limg, lbase)
    FRAME, ESP0, USER, THIS, ITEM = 0x001E0000, 0x001C0000, 0x00150000, 0x001B0000, 0x001A0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}
    # ячейка импорта GetTickCount → подставная функция
    emu.uc.mem_write(IAT_TICK, struct.pack("<I", 0x0F000000))
    now_box = [0]
    emu.fake = {0x0F000000: (0, lambda uc, a, sp: now_box[0])}

    def kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    # кадры «now / срок»: имя, now, срок, ожидание «истёк» по модулю
    W = 0x100000000
    CASES = [
        ("срок в будущем",                     1000,        5000),
        ("срок в прошлом",                     9000,        5000),
        ("срок = now",                         5000,        5000),
        ("срок до 2^32, now после перехода",   0x00000800,  0xFFFFF000),
        ("now до 2^32, срок после перехода",   0xFFFFF000,  0x00000800),
        ("аптайм ≥ 2^31: срок в будущем",      0x90000000,  0x90003A98),
        ("аптайм ≥ 2^31: срок в прошлом",      0x90003A98,  0x90000000),
        ("аптайм ≥ 2^31: срок +15000 ровно",   0x7FFFFFF0,  0x80003A88),
        ("now = 2^32−1, срок = 0x0000000F",    0xFFFFFFFF,  0x0000000F),
    ]

    def expired(now, dl):
        return s32(now - dl) >= 0

    # A: ecx = now, eax = CUser; [ebp-8] = CUser, [ebp-4] = now, [ebp+8] = userNum
    for nm, now, dl in CASES + [("поле 0 (слот не тронут)", 0x90000000, 0), ("поле 0, now < 2^31", 1234, 0)]:
        want = 0x0048B505 if (dl == 0 or expired(now, dl)) else 0x0048B527
        emu.stops = {0x0048B505, 0x0048B527}
        mem = [(USER + 0x3F461, struct.pack("<I", dl)), (FRAME - 8, struct.pack("<I", USER)), (FRAME - 4, struct.pack("<I", now)), (FRAME + 8, struct.pack("<I", 7))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_ECX: now, UC_X86_REG_EAX: USER, UC_X86_REG_EDX: 0x4444})
        at = emu.run(0x0048B4FD, regs, mem)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "A %-36s now=%08X срок=%08X -> %s (ожид. %s), стек %s"
           % (nm, now, dl, "СНЯТЬ МОНЕТУ" if at == 0x0048B505 else "ждать", "снять" if want == 0x0048B505 else "ждать", emu.r(UC_X86_REG_ESP) == ESP0))
        ok(emu.r(UC_X86_REG_ECX) == now and emu.r(UC_X86_REG_EAX) == USER and emu.r(UC_X86_REG_EDX) == 0x4444 and kept(), "  регистры сохранены (eax/ecx/edx/ebx/esi/edi)")

    # B: edx = now, ecx = this, eax = 0x41·i (i = 1); сосед 0x46C11E — подсчёт голосов (истёк), 0x46C3B8 — ждать
    for nm, now, dl in CASES:
        want = 0x0046C11E if expired(now, dl) else 0x0046C3B8
        emu.stops = {0x0046C11E, 0x0046C3B8}
        mem = [(THIS + 0x41 + 0x122, struct.pack("<I", dl))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EDX: now, UC_X86_REG_ECX: THIS, UC_X86_REG_EAX: 0x41})
        at = emu.run(0x0046C111, regs, mem)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "B %-36s now=%08X срок=%08X -> %s (ожид. %s), стек %s"
           % (nm, now, dl, "ИТОГ ГОЛОСОВАНИЯ" if at == 0x0046C11E else "ждать", "итог" if want == 0x0046C11E else "ждать", emu.r(UC_X86_REG_ESP) == ESP0))
        ok(emu.r(UC_X86_REG_EDX) == now and emu.r(UC_X86_REG_ECX) == THIS and emu.r(UC_X86_REG_EAX) == 0x41 and kept(), "  регистры сохранены")

    # C1: запись срока — eax = секунды из БД, [ebp-2Ch] = CUser, GetTickCount подставной; стоп 0x466091.
    #     [p71fix] > MaxPenaltySec (604800) → старое абсолютное значение: поле := now − 1 (истёкший), P71_StalePenalty(secs, user).
    stale_seen = []
    def stale(uc, a, sp):
        secs, user = struct.unpack("<II", uc.mem_read(sp, 8))
        stale_seen.append((secs, user))
        return now_box[0]
    emu.fake[stale_fn] = (0, stale)   # cdecl: стек чистит стаб (add esp,8)
    for nm, now, secs, want_field in [
        ("600 с, малый аптайм",            1000,       600,        1000 + 600000),
        ("600 с, аптайм ≥ 2^31",           0x90000000, 600,        (0x90000000 + 600000) & 0xFFFFFFFF),
        ("600 с, сумма через 2^32",        0xFFFF0000, 600,        (0xFFFF0000 + 600000) & 0xFFFFFFFF),
        ("сумма ровно 0 → 1",              (W - 600000) & 0xFFFFFFFF, 600, 1),
        ("1800 с (кик) при аптайме 36 сут", 0xB9A6A000, 1800,      (0xB9A6A000 + 1800000) & 0xFFFFFFFF),
        ("0 с → нет штрафа",               1000,       0,          0),
        ("−5 с → нет штрафа",              1000,       0xFFFFFFFB, 0),
        ("604800 с = MaxPenaltySec — ещё срок", 1000,  604800,     1000 + 604800000),
        ("604801 с → старое значение: now−1", 1000,    604801,     999),
        ("3 100 000 с (такт/1000 старого кика) → now−1", 0xB9A6A000, 3100000, 0xB9A6A000 - 1),
        ("старое при now = 1 → 0xFFFFFFFF",  1,         3100000,    0xFFFFFFFF),
    ]:
        now_box[0] = now
        del stale_seen[:]
        emu.stops = {0x00466091}
        mem = [(USER + 0x3F454, struct.pack("<I", 0xDEADBEEF)), (FRAME - 0x2C, struct.pack("<I", USER)), (FRAME - 0x14, struct.pack("<I", secs))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: secs, UC_X86_REG_ECX: 0x5555, UC_X86_REG_EDX: 0x6666})
        at = emu.run(0x00466082, regs, mem)
        got = emu.rd(USER + 0x3F454)
        ok(at == 0x00466091 and emu.r(UC_X86_REG_ESP) == ESP0, "C1 %-34s now=%08X: дошли до 0x466091, стек %s" % (nm, now, emu.r(UC_X86_REG_ESP) == ESP0))
        ok(got == want_field, "  [CUser+3F454h] = %08X (ожид. %08X)" % (got, want_field))
        ok(emu.r(UC_X86_REG_EAX) == got and emu.r(UC_X86_REG_ECX) == 0x5555 and emu.r(UC_X86_REG_EDX) == 0x6666 and kept(), "  eax = записанное, ecx/edx/ebx/esi/edi сохранены")
        if 0 < s32(secs) <= 604800:
            ok(not stale_seen, "  P71_StalePenalty не звалась")
        elif s32(secs) > 604800:
            ok(stale_seen == [(secs, USER)], "  P71_StalePenalty(secs=%u, user) вызвана один раз: %s" % (secs, stale_seen))

    # C1 → сток → C1b сквозняком: после записи сток зовёт sub_49B9B0, 6713 (sub_4C28F0), sub_531980, гейт ≠0, GetTickCount, стаб C1b, jae.
    #     Остановки: 0x466105 — штраф действует (6741 флаг 1); 0x466138 — истёк, поле ≠ 0 → обнуление + 2471 Time 0; 0x46615C — поля нет.
    sent = []
    emu.fake[0x0049B9B0] = (0, lambda uc, a, sp: 0)
    emu.fake[0x00531980] = (0, lambda uc, a, sp: 0)
    emu.fake[0x004C28F0] = (24, lambda uc, a, sp: (sent.append(a[0]), 1)[1])
    for nm, now, secs, want in [
        ("1800 с (кик) — действует",             0xB9A6A000, 1800,    0x00466105),
        ("3 100 000 с (старое абсолютное) — обнулить + 2471 Time 0", 0xB9A6A000, 3100000, 0x00466138),
        ("0 с — штрафа нет",                     0xB9A6A000, 0,       0x0046615C),
        ("600 с через переход 2^32 — действует", 0xFFFF0000, 600,     0x00466105),
    ]:
        now_box[0] = now
        del sent[:]
        emu.stops = {0x00466105, 0x00466138, 0x0046615C}
        mem = [(USER + 0x3F454, struct.pack("<I", 0xDEADBEEF)), (FRAME - 0x2C, struct.pack("<I", USER)), (FRAME - 0x30, struct.pack("<I", THIS)),
               (FRAME - 0x14, struct.pack("<I", secs)), (FRAME + 8, struct.pack("<I", 7)), (THIS, struct.pack("<I", THIS + 0x100))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: secs})
        at = emu.run(0x00466082, regs, mem, count=600)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "C1→C1b %-44s -> 0x%08X (ожид. 0x%08X), стек %s" % (nm, at or 0, want, emu.r(UC_X86_REG_ESP) == ESP0))
        ok(6713 in sent, "  6713 (сведения лагеря) ушёл стоком; пакеты %s" % sent)
    for k in (0x0049B9B0, 0x00531980, 0x004C28F0):
        del emu.fake[k]

    # C5: кик голосованием — с площадки 0x46C32F до call sub_46AA10 (0x46C349): в стоке push = now + 1800000, с P71 — 1800000.
    emu.stops = {0x0046C349}
    for nm, now in (("аптайм 36 сут", 0xB9A6A000), ("малый аптайм", 1000), ("перед переходом 2^32", 0xFFFFFFF0)):
        now_box[0] = now
        mem = [(FRAME - 0xB0, struct.pack("<I", 7)), (FRAME - 0xB4, struct.pack("<I", THIS))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: 0, UC_X86_REG_ECX: 0, UC_X86_REG_EDX: 0})
        at = emu.run(0x0046C32F, regs, mem)
        esp = emu.r(UC_X86_REG_ESP)
        pushed_time, pushed_user = emu.rd(esp + 4), emu.rd(esp) & 0xFFFF
        ok(at == 0x0046C349 and esp == ESP0 - 8 and pushed_time == 1800000 and pushed_user == 7 and emu.r(UC_X86_REG_ECX) == THIS,
           "C5 %-22s now=%08X: sub_46AA10(this, 7, Time=%u) — длительность 1800 с (сток дал бы %08X)" % (nm, now, pushed_time, (now + 1800000) & 0xFFFFFFFF))
    # тот же кадр на НЕПРАВЛЕНОМ образе — доказательство КРИТ-1 ревизии (сток шлёт абсолютный такт)
    emu0 = Emu(img, base, limg, lbase)
    emu0.uc.mem_write(IAT_TICK, struct.pack("<I", 0x0F000000))
    emu0.fake = {0x0F000000: (0, lambda uc, a, sp: 0xB9A6A000)}
    emu0.stops = {0x0046C349}
    regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0})
    at = emu0.run(0x0046C32F, regs, [(FRAME - 0xB0, struct.pack("<I", 7)), (FRAME - 0xB4, struct.pack("<I", THIS))])
    ok(at == 0x0046C349 and emu0.rd(emu0.r(UC_X86_REG_ESP) + 4) == (0xB9A6A000 + 1800000) & 0xFFFFFFFF,
       "сток (без P71): sub_46AA10 получает now + 1800000 = %08X — абсолютный такт (КРИТ-1)" % emu0.rd(emu0.r(UC_X86_REG_ESP) + 4))

    # C1b: вход — eax = now, ecx = CUser; 0x466105 — не истёк (6741 флаг 1), 0x46612C — истёк
    for nm, now, dl in CASES:
        want = 0x0046612C if expired(now, dl) else 0x00466105
        emu.stops = {0x00466105, 0x0046612C}
        mem = [(USER + 0x3F454, struct.pack("<I", dl))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: now, UC_X86_REG_ECX: USER, UC_X86_REG_EDX: 0x6666})
        at = emu.run(0x004660FD, regs, mem)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "C1b %-35s now=%08X срок=%08X -> %s (ожид. %s), стек %s"
           % (nm, now, dl, "истёк" if at == 0x0046612C else "ДЕЙСТВУЕТ", "истёк" if want == 0x0046612C else "действует", emu.r(UC_X86_REG_ESP) == ESP0))
        ok(emu.r(UC_X86_REG_EAX) == now and emu.r(UC_X86_REG_ECX) == USER and emu.r(UC_X86_REG_EDX) == 0x6666 and kept(), "  регистры сохранены")

    # C2: TimerProcess — edx = now, ecx = CUser; 0x46A9B0 — истёк (поле := 0, 2471, 6741 флаг 0), 0x46AA01 — ждать
    for nm, now, dl in CASES:
        want = 0x0046A9B0 if expired(now, dl) else 0x0046AA01
        emu.stops = {0x0046A9B0, 0x0046AA01}
        mem = [(USER + 0x3F454, struct.pack("<I", dl))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EDX: now, UC_X86_REG_ECX: USER, UC_X86_REG_EAX: 0x7777})
        at = emu.run(0x0046A9A8, regs, mem)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "C2 %-36s now=%08X срок=%08X -> %s (ожид. %s), стек %s"
           % (nm, now, dl, "ИСТЁК" if at == 0x0046A9B0 else "ждать", "истёк" if want == 0x0046A9B0 else "ждать", emu.r(UC_X86_REG_ESP) == ESP0))
        ok(emu.r(UC_X86_REG_EDX) == now and emu.r(UC_X86_REG_ECX) == USER and emu.r(UC_X86_REG_EAX) == 0x7777 and kept(), "  регистры сохранены")

    # C3a/C3b: остаток на разрыв — ecx = CUser; стоп на следующей инструкции стока; edx = max(0, (int)(срок − now))
    for site, stop in (("C3a", 0x00525CAC), ("C3b", 0x005268BF)):
        for nm, now, dl in CASES:
            now_box[0] = now
            want = max(0, s32(dl - now)) & 0xFFFFFFFF
            emu.stops = {stop + 6}
            mem = [(USER + 0x3F454, struct.pack("<I", dl))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_ECX: USER, UC_X86_REG_EAX: 0x8888, UC_X86_REG_EDX: 0})
            at = emu.run(stop, regs, mem)
            ok(at == stop + 6 and emu.r(UC_X86_REG_ESP) == ESP0 and emu.r(UC_X86_REG_EDX) == want,
               "%s %-36s now=%08X срок=%08X -> edx=%08X (ожид. %08X), стек %s" % (site, nm, now, dl, emu.r(UC_X86_REG_EDX), want, emu.r(UC_X86_REG_ESP) == ESP0))
            ok(emu.r(UC_X86_REG_EAX) == 0x8888 and emu.r(UC_X86_REG_ECX) == USER and kept(), "  eax/ecx/ebx/esi/edi сохранены")

    # D: edx = предмет, [ebp-4] = T = now − 300000; 0x4226A9 — пропустить (моложе 5 мин), 0x422658 — удалить
    DCASES = [
        ("упал 1 мин назад",                     1000000,    1000000 - 60000),
        ("упал 6 мин назад",                     1000000,    1000000 - 360000),
        ("упал ровно 5 мин назад",               1000000,    1000000 - 300000),
        ("упал до 2^32, now после (1 мин)",      0x00000800, (0x00000800 - 60000) & 0xFFFFFFFF),
        ("упал до 2^32, now после (6 мин)",      0x00000800, (0x00000800 - 360000) & 0xFFFFFFFF),
        ("упал после 2^32 (такт свежее now)",    0xFFFFFFF0, 0x00000010),
        ("аптайм ≥ 2^31: 1 мин",                 0x90000000, 0x90000000 - 60000),
        ("аптайм ≥ 2^31: 6 мин",                 0x90000000, 0x90000000 - 360000),
        ("такт 0 (не ставился)",                 0x90000000, 0),
        ("такт 0, now < 2^31",                   1000000,    0),
    ]
    for nm, now, tick in DCASES:
        T = (now - 300000) & 0xFFFFFFFF
        keep = tick != 0 and s32(tick - T) > 0
        want = 0x004226A9 if keep else 0x00422658
        emu.stops = {0x004226A9, 0x00422658}
        mem = [(ITEM + 0x25, struct.pack("<I", tick)), (FRAME - 4, struct.pack("<I", T))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EDX: ITEM, UC_X86_REG_ECX: 0x9999, UC_X86_REG_EAX: 0})
        at = emu.run(0x00422650, regs, mem)
        ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "D %-36s now=%08X такт=%08X -> %s (ожид. %s), стек %s"
           % (nm, now, tick, "оставить" if at == 0x004226A9 else "УДАЛИТЬ", "оставить" if keep else "удалить", emu.r(UC_X86_REG_ESP) == ESP0))
        ok(emu.r(UC_X86_REG_EAX) == tick and emu.r(UC_X86_REG_EDX) == ITEM and emu.r(UC_X86_REG_ECX) == 0x9999 and kept(), "  eax = такт (как сток), edx/ecx/ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
