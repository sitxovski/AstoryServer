# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p57.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка волны античита A6 (2026-10-12):
#   P57 (ход: порог Hack Position → кик, пределы 4006, 4008 из проверенных полей),
#   P58 (причина отключения в общий лог всегда), P59 (журнал редкого дропа с монстров).
#
# Сервер НЕ запускается. Грузятся настоящие образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38)
# и собранная AsdaPatch.dll. Проверяем:
#  1) исходные байты всех площадок и «соседей» (адреса возврата/перехода стабов) в каждом образе;
#  2) в .text ни один rel8/rel32/jcc32 и ни один abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов
#     начинаются/кончаются на границе инструкции; у площадок лога Hack Position перед call стоит push строки формата;
#  3) стабы найдены в DLL по сигнатурам; каждый `jmp dword ptr [..]` разыменован и ведёт туда, куда задумано;
#     вызовы C-функций — внутрь DLL;
#  4) unicorn: каждый стаб исполняется на подставном кадре, C-функции и серверные функции подменяются
#     заглушками — проверяются ветки (пропуск/отказ/переход в стоковое тело), баланс стека, сохранность регистров,
#     раскладка аргументов.
# Запуск: python verify_p57.py [AsdaPatch.dll]
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
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
if os.environ.get("P57_IMG_DIR"):   # локальные копии образов (ускорение; те же md5)
    d = os.environ["P57_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe"), ("живой GameServer", d + "/gs_live.exe"), ("живой Indun", d + "/gs_indun.exe")]


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


GS_SITES = [
    ("P57.move4006",  0x0054531D, _call(0x0054531D, 0x0055FF20)),            # call sub_55FF20 (campwar)
    ("P57.after1",    0x005454DE, _call(0x005454DE, 0x004C58F0)),            # LABEL_41 тела CharMove Hack
    ("P57.after2",    0x00545B25, _call(0x00545B25, 0x004C58F0)),            # LABEL_41 тела CharReMove Hack
    ("P57.stop4008",  0x00546427, "8b85c0fbffffd945d9"),                     # LABEL_35 CharStop (2 инструкции)
    ("P57.logMove",   0x0054543D, _call(0x0054543D, 0x00569DF0)),            # (ставится только если P53 не занял)
    ("P57.logReMove", 0x00545A84, _call(0x00545A84, 0x00569DF0)),
    ("P58.disc",      0x0052EDE4, "83fa047525"),                             # cmp edx,4 / jne 0x52EE0E
    ("P59.drop",      0x004C9370, "558bec81ec9c000000"),                     # пролог recvBattleServerFromItemDrop
]
GS_NEIGHBOURS = [
    ("ret move4006 0x545322 (mov [ebp-9],al)",      0x00545322, "8845f7"),
    ("тело CharMove Hack 0x545425",                  0x00545425, "668b5508528b8d7cfbffffe83bd1feff"),
    ("тело CharReMove Hack 0x545A6C",                0x00545A6C, "668b4508508b8d7cfbffffe8f4cafeff"),
    ("push fmt CharMove 0x545436",                   0x00545436, "6858cb59006a00"),
    ("push fmt CharReMove 0x545A7D",                 0x00545A7D, "681ccb59006a00"),
    ("ret after1 0x5454E3 (xor eax,eax; jmp)",       0x005454E3, "33c0e976070000"),
    ("ret after2 0x545B2A (xor eax,eax; jmp)",       0x00545B2A, "33c0e92f010000"),
    ("ret stop4008 0x546430 (fstp [eax+54EEh])",     0x00546430, "d998ee540000"),
    ("CharStop fstp [ecx+54F2h] 0x54643F",           0x0054643F, "d999f2540000"),
    ("P58 стоковая ветка 0x52EDE9",                  0x0052EDE9, "0fb6450c50"),
    ("P58 пропуск 0x52EE0E (push 1; push 0)",        0x0052EE0E, "6a016a00"),
    ("P58 push fmt; push 31 0x52EDFF",               0x0052EDFF, "68c8a959006a1f"),
    ("P58 таблица off_5A62AC[0..1]",                 0x005A62AC, "44875900" "3c875900"),
    ("P59 ret 0x4C9379 (mov eax,[cookie])",          0x004C9379, "a1f0635a00"),
    ("CharMove GetTickCount 0x54537F",               0x0054537F, "ff1520305800"),
    ("CharMove такт шага := сейчас (старт отрезка) 0x5456C1", 0x005456C1, "898202550000"),
    ("CharMove пройдено на отрезке := 0 0x5456CD",   0x005456CD, "c7800e55000000000000"),
    # [p57fix] опоры бюджета хода: MoveSyncProcess (0x5427D0) LABEL_44 — +0x550E += dt, +0x5502 += dt (такт ШАГА, не старт)
    ("MoveSync add edx,[ebp-0Ch] 0x542F2E",          0x00542F2E, "0355f4"),
    ("MoveSync +0x550E += dt 0x542F34 (опора P57)",  0x00542F34, "89900e550000"),
    ("MoveSync add edx,[ebp-0Ch] 0x542F43",          0x00542F43, "0355f4"),
    ("MoveSync +0x5502 += dt 0x542F49 (опора P57)",  0x00542F49, "899002550000"),
    ("MoveSync новый отрезок: старт X := тек. 0x542DCE", 0x00542DCE, "d9991a550000"),
    ("MoveSync новый отрезок: пройдено := 0 0x542EA3", 0x00542EA3, "c7800e55000000000000"),
    ("MoveSync новый отрезок: такт := сейчас 0x542EB6", 0x00542EB6, "898102550000"),
    ("CharMove старт X 0x54551A",                    0x0054551A, "d9981a550000"),
    ("CharMove скорость 0x5459BF",                   0x005459BF, "d981fe540000"),
    ("Send_DisConnectType пролог (P48) 0x52EDB0",    0x0052EDB0, "558bec83ec08894df8"),
    ("Monster.ai запись 44 б (imul 2Ch) 0x4AF8E3",   0x004AF8E3, "6bc92c"),
    ("sub_41A010 (проходимость) пролог",             0x0041A010, "558bec"),
    ("sub_4221D0 (границы) пролог",                  0x004221D0, "558bec"),
    ("sub_523ED0 (в движении) пролог",               0x00523ED0, "558bec"),
    ("sub_4CB030 мёртв: mov edx,[ecx+4Fh] 0x4CB05D", 0x004CB05D, "8b514f"),   # [fix13] журнал гейта 4008 — чтение поля, не вызов sub_52BFF0
    ("sub_484D20 (гейт контроля) пролог",            0x00484D20, "558bec"),
    ("sub_526E40 (ExceptionDisConnectUser) пролог",  0x00526E40, "558bec"),
]
BOUNDARY_EXTRA = [0x00545425, 0x00545A6C, 0x00546430, 0x0052EDE9, 0x0052EE0E, 0x004C9379, 0x00545322]

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


def no_gate_refs(dmap, limg, lbase, obj, ok):
    """[fix13] Код объекта obj не ссылается на стоковый sub_52BFF0 (он шлёт клиенту 6001 даже при коде 0):
    в границах функций .text объекта (по MAP) нет imm32 0x0052BFF0 (так компилятор кладёт адрес функции-указателя)."""
    from asdamap import DllMap
    allsyms = dmap.syms
    hits, funcs = [], 0
    for i, (va, dec, o) in enumerate(allsyms):
        if obj.lower() not in o.lower():
            continue
        end = allsyms[i + 1][0] if i + 1 < len(allsyms) else va
        if not (lbase <= va < lbase + len(limg)) or end <= va or end - va > 0x4000:
            continue
        funcs += 1
        blob = bytes(limg[va - lbase: end - lbase])
        if b"\xf0\xbf\x52\x00" in blob:
            hits.append(DllMap._plain(dec))
    ok(funcs > 0 and not hits, "%s: символов проверено %d, ссылок на sub_52BFF0 (imm32 0x0052BFF0) нет%s" % (obj, funcs, (" — ЕСТЬ в " + ", ".join(hits)) if hits else ""))


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


def push_fmt_ok(img, base, va, fmt, maxback=24):
    for back in range(5, maxback + 1):
        p = va - base - back
        if img[p] == 0x68 and struct.unpack("<I", bytes(img[p + 1:p + 5]))[0] == fmt:
            return True
    return False


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
    """jmp dword ptr [p] -> *p (в порядке встречи), call rel32 -> цели (E8), call dword ptr [p] -> *p."""
    jmps, calls, icalls = [], [], []
    for ins in disasm(img, base, va, 0xA0):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        if ins.mnemonic == "call" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            icalls.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic == "jmp" and "dword ptr [" in ins.op_str:
            p = int(ins.op_str.split("[")[1].split("]")[0], 16)
            jmps.append(struct.unpack("<I", bytes(img[p - base:p - base + 4]))[0])
        if ins.mnemonic in ("int3",) or len(jmps) >= njmp:
            break
    return jmps, calls, icalls


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)   # стек + кадр
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

    def run(self, start, regs, mem=(), count=300):
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
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        # таблица имён типов отключения: 15 указателей в .rdata, строки известны
        names = []
        for i in range(15):
            p = struct.unpack("<I", bytes(img[0x5A62AC - base + 4 * i: 0x5A62AC - base + 4 * i + 4]))[0]
            e = img.find(b"\0", p - base)
            names.append(bytes(img[p - base:e]).decode("ascii", "replace"))
        ok(names[:8] == ["Default", "Network", "Duplication", "Security", "Notting", "Wrong Info", "SpeedHack", "Block Account"]
           and names[14] == "User Full", "off_5A62AC: 15 имён типов: %s" % ", ".join(names))
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
        ok(s, "цель перехода 0x%08X на границе инструкции" % va)
    ok(push_fmt_ok(img, base, 0x0054543D, 0x0059CB58), "push строки формата перед 0x54543D (CharMove Hack Position)")
    ok(push_fmt_ok(img, base, 0x00545A84, 0x0059CB1C), "push строки формата перед 0x545A84 (CharReMove Hack Position)")
    fmt1 = bytes(img[0x59CB58 - base: 0x59CB58 - base + 32]).split(b"\0")[0]
    fmt2 = bytes(img[0x59CB1C - base: 0x59CB1C - base + 36]).split(b"\0")[0]
    ok(fmt1 == b"CharMove Hack Position %s Error" and fmt2 == b"CharReMove Hack Position %s Error", "строки формата: %r / %r" % (fmt1, fmt2))
    fmt3 = bytes(img[0x59A9C8 - base: 0x59A9C8 - base + 80]).split(b"\0")[0]
    ok(fmt3.startswith(b"[CALL] Send_DisConnectType()"), "строка формата стока 0x59A9C8: %r" % fmt3)

    # ── стабы в DLL ──────────────────────────────────────────────────────────
    print("-- стабы в %s" % DLL)
    lpe, limg, lbase = load(DLL)
    lo, hi = lbase, lbase + len(limg)
    # ★ integ2b: однозначная привязка по MAP компоновщика (out/AsdaPatch.map, build.bat /MAP) — сигнатуры St_Move4006/
    #   St_AfterHack/DropStub совпали со стабами того же вида других патчей (P60/P64/P66…); MAP даёт имя И объект.
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(DLL)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X, база 0x%08X)" % (dmap.map_path, dmap.stamp or 0, dmap.base or 0))
    MAP_OBJ = {"St_Move4006": "p57_move_guard", "St_AfterHack": "p57_move_guard", "DropStub": "p59_rare_drop_journal"}
    no_gate_refs(dmap, limg, lbase, "p57_move_guard", ok)
    sigs = {
        "St_Move4006":  "ff742408ff742408ff15",
        "St_AfterHack": "ff742410ff742410ff742410ff742410ff15",
        "St_Stop4008":  "6055e8",       # уточняется по хвосту ниже
        "LogTail":      "608b44243085c074",
        "DiscLogStub":  "60ff75040fb6450c500fbf450850ff75f8e8",
        "DropStub":     "60ff742428ff74242851e8",
    }
    stubs = {}
    for k, s in sigs.items():
        c = find_all(limg, lbase, s)
        if k == "St_Stop4008":
            c = [a for a in c if bytes(limg[a - lbase + 7: a - lbase + 19]) == bytes.fromhex("618b85c0fbffffd945d9ff25")]
        if k in MAP_OBJ:
            va, good, msg = resolve(dmap, k, MAP_OBJ[k], c)
            ok(good, msg)
            c = [va] if va else []
        else:
            ok(len(c) == 1, "%s: найден, кандидатов %d (0x%08X)" % (k, len(c), c[0] if c else 0))
        if c:
            stubs[k] = c[0]
    # St_LogMove / St_LogReMove: `push 1/2; jmp LogTail(P57)` — у P53 такие же стабы на свой LogTail, различаем целью.
    for k, b in (("St_LogMove", 1), ("St_LogReMove", 2)):
        cands = []
        for a in find_all(limg, lbase, "6a%02xe9" % b):
            rel = struct.unpack("<i", bytes(limg[a - lbase + 3: a - lbase + 7]))[0]
            if a + 7 + rel == stubs.get("LogTail"):
                cands.append(a)
        ok(len(cands) == 1, "%s: push %d; jmp LogTail(P57) — кандидатов %d" % (k, b, len(cands)))
        if cands:
            stubs[k] = cands[0]
    expect_jmp = {
        "St_Move4006":  [0x00545425, 0x00545A6C],
        "St_Stop4008":  [0x00546430],
        "LogTail":      [0x00569DF0],
        "DiscLogStub":  [0x0052EE0E, 0x0052EDE9],
        "DropStub":     [0x004C9379],
    }
    expect_icall = {"St_Move4006": [0x0055FF20], "St_AfterHack": [0x004C58F0]}
    cfun = {}
    for k, a in stubs.items():
        if k in ("St_LogMove", "St_LogReMove"):
            continue
        jmps, calls, icalls = stub_targets(limg, lbase, a, len(expect_jmp.get(k, [])) or 1)
        if k in expect_jmp:
            ok(jmps[:len(expect_jmp[k])] == expect_jmp[k], "%s: jmp [..] -> %s (ожид. %s)"
               % (k, ["0x%08X" % x for x in jmps], ["0x%08X" % x for x in expect_jmp[k]]))
        if k in expect_icall:
            ok(icalls[:1] == expect_icall[k], "%s: call [..] -> %s (сток %s)" % (k, ["0x%08X" % x for x in icalls], ["0x%08X" % x for x in expect_icall[k]]))
        ok(len(calls) == 1 and lo <= calls[0] < hi, "%s: call C-функции внутри DLL (0x%08X)" % (k, calls[0] if calls else 0))
        if calls:
            cfun[k] = calls[0]

    # ── эмуляция ──────────────────────────────────────────────────────────────
    print("-- эмуляция стабов (C-функции и серверные функции заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333

    # St_Move4006: ecx=this, [esp]=ret, [esp+4]=userNum, [esp+8]=posDst; сток 0x55FF20 (thiscall, ret 8)
    if "St_Move4006" in stubs:
        seen = {}
        for stock_r, verdict, want in ((1, 0, 0x00545322), (1, 1, 0x00545425), (1, 2, 0x00545A6C), (0, 9, 0x00545322)):
            seen.clear()
            def campwar(uc, a, sp, r=stock_r):
                seen["campwar"] = (uc.reg_read(UC_X86_REG_ECX), a)
                return r
            def onmove(uc, a, sp, v=verdict):
                seen["onmove"] = a
                return v
            emu.fake = {0x0055FF20: (8, campwar), cfun["St_Move4006"]: (4, onmove)}
            emu.stops = {0x00545322, 0x00545425, 0x00545A6C}
            sp = ESP0 - 12
            mem = [(sp, struct.pack("<III", 0x00545322, 77, 0x00120034)), (FRAME - 0x484, struct.pack("<I", 0xC0FFEE))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D, UC_X86_REG_EAX: 0})
            at = emu.run(stubs["St_Move4006"], regs, mem)
            esp_ok = emu.r(UC_X86_REG_ESP) == ESP0
            ok(at == want and esp_ok, "St_Move4006 сток=%d вердикт=%d -> 0x%08X (ожид. 0x%08X), стек сбалансирован: %s"
               % (stock_r, verdict, at or 0, want, esp_ok))
            ok(seen.get("campwar") == (0xD00D, (77, 0x00120034)), "  сток sub_55FF20 получил ecx=this и те же аргументы (userNum, posDst)")
            if stock_r == 0:
                ok("onmove" not in seen and (emu.r(UC_X86_REG_EAX) & 0xFF) == 0, "  сток отказал → P57 не зовётся, al=0 возвращён как есть")
            else:
                ok(seen.get("onmove") == (FRAME,), "  P57_OnMove4006 получил ebp кадра CharMove")
                if verdict == 0:
                    ok((emu.r(UC_X86_REG_EAX) & 0xFF) == 1, "  пропуск: al=1 (как сток)")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_AfterHack: ecx=this, [esp]=ret, 4 аргумента; сток 0x4C58F0 (thiscall, ret 10h)
    if "St_AfterHack" in stubs:
        seen = {}
        def tonpc(uc, a, sp):
            seen["npc"] = (uc.reg_read(UC_X86_REG_ECX), a)
            return 1
        def after(uc, a, sp):
            seen["after"] = a
            return 0
        emu.fake = {0x004C58F0: (16, tonpc), cfun["St_AfterHack"]: (4, after)}
        emu.stops = {0x005454E3}
        sp = ESP0 - 20
        mem = [(sp, struct.pack("<IIIII", 0x005454E3, 77, 0x12, 0x34, 1))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
        at = emu.run(stubs["St_AfterHack"], regs, mem)
        ok(at == 0x005454E3 and emu.r(UC_X86_REG_ESP) == ESP0, "St_AfterHack -> 0x5454E3, стек сбалансирован (ret 10h)")
        ok(seen.get("npc") == (0xD00D, (77, 0x12, 0x34, 1)), "  сток sub_4C58F0 получил ecx=this и 4 аргумента в том же порядке")
        ok(seen.get("after") == (FRAME,), "  P57_AfterHackBody получил ebp кадра")
        ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_Stop4008: кадр CharStop; вытеснены mov eax,[ebp-440h]; fld [ebp-27h]
    if "St_Stop4008" in stubs:
        seen = {}
        def onstop(uc, a, sp):
            seen["stop"] = a
            return 0
        emu.fake = {cfun["St_Stop4008"]: (4, onstop)}
        emu.stops = {0x00546430}
        mem = [(FRAME - 0x440, struct.pack("<I", 0x00150000)), (FRAME - 0x27, struct.pack("<f", 1234.5)), (FRAME + 8, struct.pack("<I", 77))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EAX: 0})
        at = emu.run(stubs["St_Stop4008"], regs, mem)
        ok(at == 0x00546430 and emu.r(UC_X86_REG_ESP) == ESP0, "St_Stop4008 -> 0x546430, стек сбалансирован")
        ok(seen.get("stop") == (FRAME,), "  P57_OnStop4008 получил ebp кадра")
        ok(emu.r(UC_X86_REG_EAX) == 0x00150000, "  вытесненное mov eax,[ebp-440h] выполнено (eax = pUser)")
        ok(regs_kept(), "  ebx/esi/edi сохранены")

    # St_LogMove → LogTail: [esp]=ret, [esp+4]=канал, [esp+8]=fmt, [esp+12]=имя; ecx=mgr
    if "St_LogMove" in stubs and "LogTail" in stubs:
        for name_ptr, want_call in ((0x00160178, True), (0, False)):
            seen = {}
            def onhack(uc, a, sp):
                seen["hack"] = a
                return 0
            def srvlog(uc, a, sp):
                seen["log"] = (uc.reg_read(UC_X86_REG_ESP), a)
                uc.emu_stop(); return 0
            emu.fake = {cfun["LogTail"]: (12, onhack), 0x00569DF0: (0, srvlog)}
            emu.stops = set()
            sp = ESP0 - 16
            mem = [(sp, struct.pack("<IIII", 0x00545442, 0, 0x0059CB58, name_ptr))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
            emu.run(stubs["St_LogMove"], regs, mem)
            ok(seen.get("log", (0,))[0] == sp, "St_LogMove: сток sub_569DF0 вызван с тем же esp (аргументы и адрес возврата целы)")
            if want_call:
                ok(seen.get("hack") == (1, 0xD00D, name_ptr - 0x178), "  P57_OnHackPosition(kind=1, mgr, user=имя−0x178) = %s" % (tuple(hex(x) for x in seen.get("hack", ())),))
            else:
                ok("hack" not in seen, "  имя NULL → P57 не зовётся")
            ok(regs_kept(), "  ebx/esi/edi сохранены")

    # DiscLogStub: кадр Send_DisConnectType после пролога P48; edx = тип сервера
    if "DiscLogStub" in stubs:
        for srvtype, want in ((4, 0x0052EDE9), (1, 0x0052EE0E), (0, 0x0052EE0E)):
            seen = {}
            def ondisc(uc, a, sp):
                seen["disc"] = a
                return 0
            emu.fake = {cfun["DiscLogStub"]: (16, ondisc)}
            emu.stops = {0x0052EDE9, 0x0052EE0E}
            mem = [(FRAME - 8, struct.pack("<I", 0xD00D)), (FRAME + 4, struct.pack("<I", 0x005271D6)), (FRAME + 8, struct.pack("<I", 0xFFFF0007)),
                   (FRAME + 12, struct.pack("<I", 0x00000106))]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: ESP0, UC_X86_REG_EDX: srvtype, UC_X86_REG_ECX: 0x5555, UC_X86_REG_EAX: 0x6666})
            at = emu.run(stubs["DiscLogStub"], regs, mem)
            ok(at == want and emu.r(UC_X86_REG_ESP) == ESP0, "DiscLogStub тип сервера %d -> 0x%08X (ожид. 0x%08X), стек сбалансирован" % (srvtype, at or 0, want))
            ok(seen.get("disc") == (0xD00D, 7, 6, 0x005271D6), "  P58_OnDisconnect(mgr, userNum=7 (i16), type=6 (u8), retVa) = %s" % (tuple(hex(x) for x in seen.get("disc", ())),))
            ok(emu.r(UC_X86_REG_EDX) == srvtype and emu.r(UC_X86_REG_ECX) == 0x5555 and emu.r(UC_X86_REG_EAX) == 0x6666 and regs_kept(), "  регистры сохранены (edx/ecx/eax/ebx/esi/edi)")

    # DropStub: ecx=mgr, [esp]=ret, [esp+4]=пакет, [esp+8]=рейд; пролог воспроизведён
    if "DropStub" in stubs:
        seen = {}
        def ondrop(uc, a, sp):
            seen["drop"] = a
            return 0
        emu.fake = {cfun["DropStub"]: (12, ondrop)}
        emu.stops = {0x004C9379}
        sp = ESP0 - 12
        mem = [(sp, struct.pack("<III", 0x00444444, 0x00150000, 1))]
        regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xD00D})
        at = emu.run(stubs["DropStub"], regs, mem)
        ok(at == 0x004C9379, "DropStub -> 0x4C9379")
        ok(seen.get("drop") == (0xD00D, 0x00150000, 1), "  P59_OnMonsterDrop(mgr, pkt, raid) = %s" % (tuple(hex(x) for x in seen.get("drop", ())),))
        ok(emu.r(UC_X86_REG_EBP) == sp - 4 and emu.r(UC_X86_REG_ESP) == sp - 4 - 0x9C and emu.rd(sp - 4) == FRAME,
           "  пролог воспроизведён: ebp = esp−4 (сохранён прежний ebp), esp −= 0x9C")
        ok(emu.r(UC_X86_REG_ECX) == 0xD00D and regs_kept(), "  ecx (this) и ebx/esi/edi сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
