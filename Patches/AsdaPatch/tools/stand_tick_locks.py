# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stand_tick_locks.py — ЭМУЛЯТОРНЫЙ стенд замков «в полёте» P33 N-2 и P35 C-3 (fix w33b, 13.10.2026).
#
# Зачем: замок ставился с тактом `GetTickCount() | 1`. При чётном now такт = now+1, и в ТОМ ЖЕ кванте таймера
#   (~15,6 мс, GetTickCount не меняется) `now - tick` = 0xFFFFFFFF ≥ тайм-аута ⇒ замок считался просроченным, и
#   дубль запроса (6504→2304 у P33, 2661/2663/2665/2667 у P35) проходил. Находка стенда P63 (inflight-lock-p63.md).
#   Исправление (как у P63): `tick = now ? now : 1`.
#
# Как: DLL грузится в unicorn по своей ImageBase (без релокаций), адреса C-функций и глобалов — из .map рядом
#   с DLL. Импорты DLL → стабы (`GetTickCount` отдаёт управляемое значение, Enter/LeaveCriticalSection — ret 4,
#   остальное — ret). Серверные адреса (`SrvLog` 0x569DF0 cdecl, `SrvSendPacket` 0x4C28F0 thiscall 6 арг) — стабы.
#   Сервер НЕ запускается, сетевых/файловых действий нет.
# Запуск:  python stand_tick_locks.py [AsdaPatch.dll]    (map = <dll без расширения>.map)
#   Код возврата 0 — все ожидания выполнены; 2 — есть провалы (на DLL до исправления провал ожидаем:
#   «дубль в том же кванте при чётном такте»).
import os
import re
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"

STUBS = 0x00090000          # область стабов импортов
STACK = 0x00200000          # стек
FRAME = 0x00300000          # подставной кадр обработчика (ebp)
OBJS = 0x00380000           # подставные CUserManager / net / CUser / тело
SRV_LO, SRV_HI = 0x00400000, 0x00600000
SENTINEL = 0x00090F00       # адрес возврата из вызываемой функции
SRV_LOG, SRV_SEND = 0x00569DF0, 0x004C28F0

bad = 0


def ok(cond, msg):
    global bad
    print(("  [OK] " if cond else "  [!!] ") + msg)
    if not cond:
        bad += 1


def sym(text, pattern):
    """Адрес символа из .map по регулярному выражению имени (первое совпадение)."""
    m = re.search(r"^\s*\w+:\w+\s+(" + pattern + r")\s+([0-9a-fA-F]{8})\s", text, re.M)
    if not m:
        raise SystemExit("нет символа %s в %s" % (pattern, MAP))
    return int(m.group(2), 16)


class Emu:
    def __init__(self, dll_path, map_text):
        pe = pefile.PE(dll_path)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(self.base, size)
        uc.mem_write(self.base, pe.get_memory_mapped_image()[:size])
        for a, s in ((STUBS, 0x1000), (STACK - 0x10000, 0x20000), (FRAME - 0x1000, 0x2000), (OBJS, 0x10000),
                     (SRV_LO, SRV_HI - SRV_LO)):
            uc.mem_map(a, s)
        self.uc = uc
        self.tick = 0
        # импорты → стабы
        slot = 0
        self.stub_name = {}
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                name = (i.name or b"ord").decode()
                st = STUBS + 0x10 * slot
                slot += 1
                ret = b"\xC2\x04\x00" if name in ("EnterCriticalSection", "LeaveCriticalSection") else b"\xC3"
                uc.mem_write(st, ret)
                uc.mem_write(i.address, struct.pack("<I", st))
                self.stub_name[st] = name
        uc.mem_write(SENTINEL, b"\xC3")
        # серверные функции
        uc.mem_write(SRV_LOG, b"\xC3")                 # cdecl
        uc.mem_write(SRV_SEND, b"\xC2\x18\x00")        # thiscall, 6 аргументов на стеке
        self.sent = 0
        self.logged = 0

        def on_code(u, addr, sz, ud):
            n = self.stub_name.get(addr)
            if n == "GetTickCount":
                u.reg_write(UC_X86_REG_EAX, self.tick & 0xFFFFFFFF)
            elif n is not None:
                u.reg_write(UC_X86_REG_EAX, 0)
            elif addr == SRV_SEND:
                self.sent += 1
            elif addr == SRV_LOG:
                self.logged += 1
        uc.hook_add(UC_HOOK_CODE, on_code, begin=STUBS, end=STUBS + 0xFFF)
        uc.hook_add(UC_HOOK_CODE, on_code, begin=SRV_LOG, end=SRV_LOG)
        uc.hook_add(UC_HOOK_CODE, on_code, begin=SRV_SEND, end=SRV_SEND)

    def call_stdcall1(self, fn, arg):
        uc = self.uc
        esp = STACK - 0x100
        uc.mem_write(esp, struct.pack("<II", SENTINEL, arg))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.emu_start(fn, SENTINEL, count=200000)
        return uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP) - esp

    def call_cdecl1(self, fn, arg):
        uc = self.uc
        esp = STACK - 0x100
        uc.mem_write(esp, struct.pack("<II", SENTINEL, arg))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.emu_start(fn, SENTINEL, count=200000)
        return uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP) - esp

    def call_cdecl(self, fn, *args):
        uc = self.uc
        esp = STACK - 0x100
        uc.mem_write(esp, struct.pack("<I" + "I" * len(args), SENTINEL, *[a & 0xFFFFFFFF for a in args]))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.emu_start(fn, SENTINEL, count=200000)
        return uc.reg_read(UC_X86_REG_EAX)



def p33(emu, m):
    print("-- P33 N-2: замок 6504/2304 (P33_Gate2304)")
    gate = sym(m, r"_P33_Gate2304@4")
    dup = sym(m, r"_P33_DupCheck6504")
    obj = r"[^\n]*p33_gear_upgrade_server_defects\.obj"
    cs_init = int(re.search(r"\?g_lockCsInit@\?A0x\w+@@3_NA\s+([0-9a-f]{8})" + obj, m).group(1), 16)
    lock_on = int(re.search(r"\?g_lockOn@\?A0x\w+@@3_NA\s+([0-9a-f]{8})" + obj, m).group(1), 16)
    g_lock = int(re.search(r"\?g_lock@\?A0x\w+@@3PAULockEntry@1@A\s+([0-9a-f]{8})" + obj, m).group(1), 16)
    uc = emu.uc
    uc.mem_write(cs_init, b"\x01")
    uc.mem_write(lock_on, b"\x01")
    mgr, net, user = OBJS, OBJS + 0x100, OBJS + 0x1000
    uc.mem_write(mgr + 4, struct.pack("<I", net))

    def frame(idx, ui):
        uc.mem_write(FRAME + 8, struct.pack("<h", idx))
        uc.mem_write(FRAME - 0x1C6, struct.pack("<i", ui))
        uc.mem_write(FRAME - 0x2EC, struct.pack("<I", mgr))
        uc.mem_write(FRAME - 0x2C4, struct.pack("<I", user))
        uc.mem_write(user + 0x174, struct.pack("<i", ui))

    def reset(idx):
        uc.mem_write(g_lock + 8 * idx, b"\x00" * 8)

    def gate_call():
        r, d = emu.call_stdcall1(gate, FRAME)
        ok(d == 8, "    стек после P33_Gate2304: +%d (ожидается +8)" % d)
        return r

    idx, ui = 7, 0x1234
    # 1) чётный такт, повтор в том же кванте
    reset(idx); frame(idx, ui); emu.tick = 0x00100000
    r1 = gate_call(); r2 = gate_call()
    ok(r1 == 1, "чётный такт: первый 2304 уходит (вернул %d)" % r1)
    ok(r2 == 0, "чётный такт, ТОТ ЖЕ квант: дубль 2304 подавлен (вернул %d; было-баг: 1)" % r2)
    # P33_DupCheck6504 (ранний отказ 6504) читает тот же замок той же LockActiveNoCs, но обёрнут в __try (SEH через
    #   fs:[0]) — в unicorn без сегмента FS не исполняется; его ветку покрывает тот же вердикт LockActiveNoCs выше.
    ok(dup > 0, "символ P33_DupCheck6504 найден в .map (0x%08X)" % dup)
    # 2) нечётный такт — работало и до исправления
    reset(idx); emu.tick = 0x00100001
    r1 = gate_call(); r2 = gate_call()
    ok(r1 == 1 and r2 == 0, "нечётный такт: 1-й уходит, дубль подавлен (%d, %d)" % (r1, r2))
    # 3) следующий квант (+16 мс) — замок жив
    reset(idx); emu.tick = 0x00200000
    gate_call(); emu.tick += 16
    ok(gate_call() == 0, "через 16 мс замок жив (дубль подавлен)")
    # 4) тайм-аут 15 000 мс — замок снимается
    emu.tick += 15000
    ok(gate_call() == 1, "после тайм-аута (≥15 000 мс) 2304 снова уходит")
    # 5) другая учётка в слоте — замок чужой
    reset(idx); emu.tick = 0x00300000
    gate_call(); frame(idx, ui + 1)
    ok(gate_call() == 1, "другая учётка (UserIndex) в том же слоте — замок не действует")
    # 6) такт 0 (раз в 49,7 сут): хранится 1 — в том же кванте возраст 0xFFFFFFFF (остаточный край, как у P63)
    reset(idx); frame(idx, ui); emu.tick = 0
    gate_call()
    tick_stored = struct.unpack("<I", bytes(uc.mem_read(g_lock + 8 * idx + 4, 4)))[0]
    ok(tick_stored == 1, "такт 0: в замок записан 1 (0 зарезервирован под «свободно»), прочитано %d" % tick_stored)


def p35(emu, m):
    print("-- P35 C-3: замок крафта 2661/2663/2665/2667 (P35_GateSend)")
    gate = sym(m, r"_P35_GateSend@4")
    obj = r"[^\n]*p35_craft_server_defects\.obj"
    cs_init = int(re.search(r"\?g_lockCsInit@\?A0x\w+@@3_NA\s+([0-9a-f]{8})" + obj, m).group(1), 16)
    lock_on = int(re.search(r"\?g_lockOn@\?A0x\w+@@3_NA\s+([0-9a-f]{8})" + obj, m).group(1), 16)
    uc = emu.uc
    uc.mem_write(cs_init, b"\x01")
    uc.mem_write(lock_on, b"\x01")
    args, body = OBJS + 0x2000, OBJS + 0x2100
    uc.mem_write(body, b"\x00" * 16)
    uc.mem_write(body + 2, struct.pack("<i", 0x5555))
    uc.mem_write(args, struct.pack("<iiiIi", 2661, 30, 0, body, 9))
    emu.tick = 0x00400000
    r1, d1 = emu.call_stdcall1(gate, args)
    r2, d2 = emu.call_stdcall1(gate, args)
    ok(d1 == 8 and d2 == 8, "стек после P35_GateSend сбалансирован (+%d, +%d)" % (d1, d2))
    ok(r1 == 1, "чётный такт: первый пакет 2661 уходит (вернул %d)" % r1)
    ok(r2 == 0, "чётный такт, ТОТ ЖЕ квант: дубль 2661 подавлен (вернул %d; было-баг: 1)" % r2)


def p44(emu, m):
    print("-- P44: такт замка «в полёте» менеджера (MarkFlight/YoungLock) и запроса обмена (RecordRequest/AcceptAllowed)")
    mark = sym(m, r"\?P44_MarkFlight@\?A0x\w+@@YAXPAXH@Z")
    young = sym(m, r"\?P44_YoungLock@\?A0x\w+@@YAHPAXH@Z")
    rec = sym(m, r"\?P44_RecordRequest@\?A0x\w+@@YAXHH@Z")
    acc = sym(m, r"\?P44_AcceptAllowed@\?A0x\w+@@YAHHH@Z")
    mgr = OBJS + 0x3000
    emu.tick = 0x00500000
    emu.call_cdecl(mark, mgr, 3)
    r = emu.call_cdecl(young, mgr, 3)
    ok(r == 1, "чётный такт, тот же квант: замок «в полёте» молод (YoungLock=%d; было-баг: 0 — освобождение не откладывалось)" % r)
    emu.tick = 0x00500010
    emu.call_cdecl(rec, 5, 9)
    r = emu.call_cdecl(acc, 5, 9)
    ok(r == 1, "чётный такт, тот же квант: честное согласие на обмен принято (AcceptAllowed=%d; было-баг: 0 — отказ)" % r)


def main():
    print("DLL: %s\nMAP: %s" % (DLL, MAP))
    m = open(MAP, encoding="latin-1").read()
    p33(Emu(DLL, m), m)
    p35(Emu(DLL, m), m)
    p44(Emu(DLL, m), m)
    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ПРОВАЛОВ %d" % bad))
    return 0 if bad == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
