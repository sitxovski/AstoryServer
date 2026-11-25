# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p39.py — СТАТИЧЕСКАЯ ПРОВЕРКА N11/P39 + N12 (скрытый оператор невидим для монстров).
#   27.09 (вечер) расширено доводкой N12: гейт добавления угрозы sub_43D2C0 (H) и одиночной цели
#   навыка монстра (I), переполнение таблицы отметок N11, выключатели N12.
#
# Сервер локально не запускается (запрет владельца). Поэтому проверка идёт в эмуляторе
# unicorn на НАСТОЯЩИХ образах:
#   1. сверка оригинальных байтов всех 7 площадок во всех переданных образах NpcServer.exe;
#   2. в эмуляторе загружаются образ NpcServer.exe и собранная AddonNPC.dll, и исполняется
#      НАСТОЯЩИЙ установщик N11_GmHideNpc() (импорты kernel32 — заглушки). После него
#      проверяется, что на каждой площадке стоит `call` на свою врезку;
#   3. сценарии на исполняемом коде сервера + врезок:
#        A/B/C/D — ветвление при состоянии цели 0 / 1 / 3 (скрыт) / 2 (скрыт и мёртв);
#        E — 8115: бит выставлен штатной AddState, списки угрозы вычищены, отметка записана;
#        G — 4031: скрытому пишется 3, обычному 1, чужому в той же записи 1;
#        F — 8116: бит снят штатной SubState, отметка забыта, возрождение даёт 1;
#        выключатели: при DropTarget=0 площадка A остаётся оригинальной.
#
# ЗАПУСК
#   python verify_p39.py <AddonNPC.dll> <AddonNPC.map> <NpcServer.exe> [ещё образы для сверки...]
#   Код возврата 0 и строка «ВСЁ СОШЛОСЬ» — всё совпало.
import re
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
                               UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_GDTR, UC_X86_REG_FS,
                               UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SITES = {   # va: (оригинал, имя)
    0x447BA7: ("83be5476000000", "A OnBattle: цель"),
    0x41AA44: ("83bf5476000000", "B OnUserSearch"),
    0x40C38C: ("83bf5476000000", "C жертвы навыка"),
    0x40F41E: ("83bf5476000000", "D цель навыка"),
    0x45A11F: ("e8fc2afdff",     "E 8115 AddState"),
    0x45A08E: ("e8dd2afdff",     "F 8116 SubState"),
    0x458D18: ("c7865476000001000000", "G 4031 возрождение"),
    0x43D2C0: ("53558bd8668b44240c", "H N12 добавление угрозы"),
    0x40C649: ("0fbe967c8f0000",     "I N12 одиночная цель"),
}
GATE_OF = {0x447BA7: "GateEsi", 0x41AA44: "GateEdi", 0x40C38C: "GateEdi", 0x40F41E: "GateEdi",
           0x45A11F: "AddStateGate", 0x45A08E: "SubStateGate", 0x458D18: "RespawnGate",
           0x43D2C0: "HateGate", 0x40C649: "SingleVictimGate"}
JMP_SITES = {0x43D2C0}   # на этих площадках jmp (E9), на остальных call (E8)

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load_map(path):
    syms = {}
    for line in open(path, encoding="latin-1"):
        m = re.match(r"\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})", line)
        if m:
            name = m.group(1)
            short = re.sub(r"^\?+", "", name).split("@")[0]
            syms.setdefault(short, int(m.group(2), 16))
    return syms


def map_pe(uc, pe):
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    size = (len(img) + 0xFFF) & ~0xFFF
    uc.mem_map(base, size)
    uc.mem_write(base, img)
    return base, size


def main():
    if len(sys.argv) < 4:
        print(__doc__ if __doc__ else "usage")
        print("usage: verify_p39.py <AddonNPC.dll> <AddonNPC.map> <NpcServer.exe> [images...]")
        return 1
    dll_path, map_path, exe_path = sys.argv[1:4]
    extra = sys.argv[4:]

    print("== 1. оригинальные байты площадок ==")
    for p in [exe_path] + extra:
        pe = pefile.PE(p, fast_load=True)
        img = pe.get_memory_mapped_image()
        good = all(img[va - 0x400000: va - 0x400000 + len(bytes.fromhex(h))] == bytes.fromhex(h)
                   for va, (h, _) in SITES.items())
        ok(good, "%s — все %d площадок совпадают с оригиналом" % (p, len(SITES)))

    syms = load_map(map_path)
    need = ["N11_GmHideNpc", "GateEsi", "GateEdi", "AddStateGate", "SubStateGate", "RespawnGate",
            "g_hidden", "g_addState", "g_subState",
            "N12_GmHideHate", "HateGate", "SingleVictimGate", "g_hateCont", "g_victimSkip"]
    for n in need:
        if n not in syms:
            print("нет символа в map: %s" % n)
            return 2

    # ── эмулятор ──────────────────────────────────────────────────────────────
    exe = pefile.PE(exe_path)
    dll = pefile.PE(dll_path)

    def fresh(ini=None):
        ini = ini or {}
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        map_pe(uc, exe)
        map_pe(uc, dll)
        # стек
        uc.mem_map(0x00100000, 0x00100000)
        # TEB для fs:[0] (кадры SEH в установщике): GDT с сегментом FS на свою страницу
        def desc(base, limit, access, flags):
            return struct.pack("<Q", (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (access << 40)
                               | (((limit >> 16) & 0xF) << 48) | (flags << 52) | (((base >> 24) & 0xFF) << 56))
        GDT, TEB = 0x00060000, 0x00070000
        uc.mem_map(GDT, 0x1000)
        uc.mem_map(TEB, 0x1000)
        uc.mem_write(TEB, struct.pack("<I", 0xFFFFFFFF))
        gdt = b"\0" * 8 + desc(0, 0xFFFFF, 0x9A, 0xC) + desc(0, 0xFFFFF, 0x92, 0xC) + desc(TEB, 0xFFF, 0x92, 0x4)
        uc.mem_write(GDT, gdt)
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT, len(gdt) - 1, 0))
        uc.reg_write(UC_X86_REG_FS, 3 << 3)
        uc.reg_write(UC_X86_REG_SS, 2 << 3)
        uc.reg_write(UC_X86_REG_DS, 2 << 3)
        uc.reg_write(UC_X86_REG_ES, 2 << 3)
        # заглушки импортов DLL
        STUB = 0x00300000
        uc.mem_map(STUB, 0x10000)
        stubs = {}
        k = 0
        for e in dll.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                a = STUB + k * 16
                uc.mem_write(a, b"\xc3" * 16)
                uc.mem_write(imp.address, struct.pack("<I", a))
                stubs[a] = (imp.name or b"?").decode()
                k += 1
        unknown = []
        tick = [100000]

        def hook(uc_, addr, size, _):
            if addr not in stubs:
                return
            name = stubs[addr]
            esp = uc_.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", uc_.mem_read(esp, 4))[0]

            def arg(i):
                return struct.unpack("<I", uc_.mem_read(esp + 4 + 4 * i, 4))[0]

            def wstr(a):
                out = b""
                while True:
                    c = uc_.mem_read(a, 2)
                    if c == b"\0\0":
                        break
                    out += c
                    a += 2
                return out.decode("utf-16le")

            nargs, rv = 0, 0
            if name == "VirtualProtect":
                nargs, rv = 4, 1
                uc_.mem_write(arg(3), struct.pack("<I", 0x20))
            elif name == "FlushInstructionCache":
                nargs, rv = 3, 1
            elif name == "GetCurrentProcess":
                nargs, rv = 0, 0xFFFFFFFF
            elif name == "GetPrivateProfileIntW":
                nargs = 4
                rv = ini.get((wstr(arg(0)), wstr(arg(1))), arg(2))
            elif name in ("InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection"):
                nargs, rv = 1, 0
            elif name in ("GetLastError",):
                nargs, rv = 0, 0
            elif name == "GetTickCount":
                tick[0] += 16
                nargs, rv = 0, tick[0]
            else:
                unknown.append(name)
                nargs, rv = 0, 0
            uc_.reg_write(UC_X86_REG_EAX, rv)
            uc_.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * nargs)
            uc_.reg_write(UC_X86_REG_EIP, ret)

        # заглушки импортов САМОГО NpcServer.exe (настоящий код сервера в сценариях H зовёт
        # GetTickCount через IAT)
        for e in exe.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                a = STUB + k * 16
                uc.mem_write(a, b"\xc3" * 16)
                uc.mem_write(imp.address, struct.pack("<I", a))
                stubs[a] = (imp.name or b"?").decode()
                k += 1
        uc.hook_add(UC_HOOK_CODE, hook, begin=STUB, end=STUB + 0x10000)
        return uc, unknown

    RET_MAGIC = 0x00150000   # адрес возврата «конец сценария»

    def call(uc, fn, regs=None, stop=RET_MAGIC, count=200000):
        esp = 0x001F0000
        uc.mem_write(esp, struct.pack("<I", RET_MAGIC))
        uc.reg_write(UC_X86_REG_ESP, esp)
        for r, v in (regs or {}).items():
            uc.reg_write(r, v)
        try:
            uc.emu_start(fn, stop, count=count)
        except UcError:
            print("    сбой эмуляции: EIP=%#x ESP=%#x EAX=%#x ECX=%#x EDX=%#x ESI=%#x EDI=%#x"
                  % tuple(uc.reg_read(r) for r in (UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EAX,
                                                   UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                                                   UC_X86_REG_EDI)))
            raise

    def run_until(uc, start, stops, regs, count=200000):
        """Исполнить с start до первого адреса из stops; вернуть, где остановились."""
        hit = {"at": None}

        def h(uc_, addr, size, _):
            if addr in stops:
                hit["at"] = addr
                uc_.emu_stop()
        hh = uc.hook_add(UC_HOOK_CODE, h)
        esp = 0x001F0000
        uc.mem_write(esp, struct.pack("<I", RET_MAGIC))
        for r, v in regs.items():
            uc.reg_write(r, v)
        uc.reg_write(UC_X86_REG_ESP, esp)
        try:
            uc.emu_start(start, RET_MAGIC, count=count)
        finally:
            uc.hook_del(hh)
        return hit["at"]

    def install(ini=None, n12=True):
        uc, unknown = fresh(ini)
        call(uc, syms["N11_GmHideNpc"])
        rv = uc.reg_read(UC_X86_REG_EAX)
        install.rv12 = None
        if n12:
            call(uc, syms["N12_GmHideHate"])
            install.rv12 = uc.reg_read(UC_X86_REG_EAX)
        return uc, rv, unknown

    print()
    print("== 2. установщик N11_GmHideNpc в эмуляторе ==")
    uc, rv, unknown = install()
    ok(rv == 0, "N11: результат установки = Applied (0), получено %d" % rv)
    ok(install.rv12 == 0, "N12: результат установки = Applied (0), получено %s" % install.rv12)
    ok(not unknown, "лишних вызовов API нет %s" % (unknown or ""))
    for va, (h, name) in SITES.items():
        b = bytes(uc.mem_read(va, len(bytes.fromhex(h))))
        tgt = (va + 5 + struct.unpack("<i", b[1:5])[0]) & 0xFFFFFFFF
        pad = b[5:]
        op = 0xE9 if va in JMP_SITES else 0xE8
        ok(b[0] == op and tgt == syms[GATE_OF[va]] and pad == b"\x90" * len(pad),
           "%s @%#x → %s %s (+%d nop)" % (name, va, "jmp" if op == 0xE9 else "call", GATE_OF[va], len(pad)))
    ok(struct.unpack("<I", uc.mem_read(syms["g_hateCont"], 4))[0] == 0x43D2C9, "g_hateCont = 0x43D2C9")
    ok(struct.unpack("<I", uc.mem_read(syms["g_victimSkip"], 4))[0] == 0x40C687, "g_victimSkip = 0x40C687")
    ok(struct.unpack("<I", uc.mem_read(syms["g_addState"], 4))[0] == 0x42CC20, "g_addState = 0x42CC20")
    ok(struct.unpack("<I", uc.mem_read(syms["g_subState"], 4))[0] == 0x42CB70, "g_subState = 0x42CB70")

    # ── раскладка тестового мира ──────────────────────────────────────────────
    CTX = 0x20000000                      # объект AI-потока
    USERS = 0x30000000                    # массив игроков
    USZ, MSZ = 68264, 37624
    uc.mem_map(CTX, 0x00100000)                                   # монстры с +8
    uc.mem_map((CTX + 0x0115475C) & ~0xFFF, 0x1000)
    uc.mem_map((CTX + 0x02954858) & ~0xFFF, 0x1000)
    uc.mem_map(USERS, 0x01000000)                                 # ~245 записей игроков
    uc.mem_write(CTX + 0x0115475C, struct.pack("<I", USERS))
    uc.mem_write(CTX + 0x02954858, struct.pack("<i", 3))          # три монстра

    def rec(n):
        return USERS + USZ * n

    def set_state(n, v):
        uc.mem_write(rec(n) + 30292, struct.pack("<I", v))

    def get_state(n):
        return struct.unpack("<I", uc.mem_read(rec(n) + 30292, 4))[0]

    def set_ui(n, v):
        uc.mem_write(rec(n) + 30356, struct.pack("<i", v))

    def mob(i):
        return CTX + 8 + MSZ * i

    def put_hate(i, slot, user, dmg):
        a = mob(i) + 31352 + 16 * slot
        uc.mem_write(a, struct.pack("<hHIII", user, 0, 7, 100, dmg))

    def hate_user(i, slot):
        return struct.unpack("<h", uc.mem_read(mob(i) + 31352 + 16 * slot, 2))[0]

    for i in range(3):
        for s in range(20):
            put_hate(i, s, -1, 0)

    print()
    print("== 3. сценарии ==")
    # A..D: ветвление. Для каждой площадки: (регистр записи, адрес «пропустить/потерять», адрес «дальше»)
    br = {
        0x447BA7: (UC_X86_REG_ESI, 0x4482FD, 0x447BB4, "A: цель → потеря цели"),
        0x41AA44: (UC_X86_REG_EDI, 0x41A9E9, 0x41AA4D, "B: поиск → следующий игрок"),
        0x40C38C: (UC_X86_REG_EDI, 0x40C336, 0x40C395, "C: жертва навыка → пропуск"),
        0x40F41E: (UC_X86_REG_EDI, 0x40F489, 0x40F427, "D: цель навыка → пропуск"),
    }
    for va, (reg, skip, cont, name) in br.items():
        for st, want in ((0, skip), (1, cont), (3, skip), (2, skip)):
            set_state(1, st)
            at = run_until(uc, va, {skip, cont}, {reg: rec(1)})
            ok(at == want, "%s: состояние %d → %s" % (name, st, "пропуск" if want == skip else "дальше"))

    # E: 8115. Игрок #5 (UserIndex 2) жив; в угрозе у монстров 0 и 2, у монстра 1 — другой игрок.
    set_ui(5, 2)
    set_state(5, 1)
    put_hate(0, 3, 5, 555)
    put_hate(2, 0, 5, 1)
    put_hate(2, 7, 5, 9)
    put_hate(1, 4, 6, 77)
    uc.mem_write(rec(5) + 68168, struct.pack("<hHI", 0, 0, 1) * 8)
    at = run_until(uc, 0x45A11F, {0x45A124}, {UC_X86_REG_EDI: 2, UC_X86_REG_ESI: rec(5),
                                             UC_X86_REG_ECX: CTX})
    ok(at == 0x45A124, "E: врезка вернулась за call (0x45A124)")
    ok(get_state(5) == 3, "E: штатная AddState поставила бит: состояние %d (ожидалось 3)" % get_state(5))
    ok(hate_user(0, 3) == -1 and hate_user(2, 0) == -1 and hate_user(2, 7) == -1,
       "E: скрытый вычищен из угрозы монстров 0 и 2 (3 записи)")
    ok(struct.unpack("<I", uc.mem_read(mob(0) + 31352 + 16 * 3 + 12, 4))[0] == 0,
       "E: поле урона +12 обнулено")
    ok(hate_user(1, 4) == 6, "E: чужая запись угрозы (игрок #6) не тронута")
    back = uc.mem_read(rec(5) + 68168, 64)
    ok(all(struct.unpack_from("<h", back, 8 * k)[0] == -1 for k in range(8)),
       "E: обратный список скрытого обнулён")
    hid = uc.mem_read(syms["g_hidden"], 8)
    ok(struct.unpack("<Ii", hid) == (rec(5), 2), "E: отметка «запись → UserIndex 2» сохранена")
    ok(struct.unpack("<I", uc.mem_read(syms["g_hidden"] + 8, 4))[0] != 0, "E: у отметки есть метка времени")

    # E с битом «жив» (не скрытие): ничего не чистит
    put_hate(1, 5, 5, 3)
    run_until(uc, 0x45A11F, {0x45A124}, {UC_X86_REG_EDI: 1, UC_X86_REG_ESI: rec(5), UC_X86_REG_ECX: CTX})
    ok(hate_user(1, 5) == 5, "E: AddState без бита 2 угрозу не трогает")
    put_hate(1, 5, -1, 0)

    # G: возрождение. Смерть = 0, затем 4031.
    def respawn(n):
        set_state(n, 0)
        at = run_until(uc, 0x458D18, {0x458D22}, {UC_X86_REG_ESI: rec(n)})
        return at, get_state(n)

    at, st = respawn(5)
    ok(at == 0x458D22 and st == 3, "G: скрытый после возрождения = 3 (было бы 1)")
    set_ui(7, 75181)
    at, st = respawn(7)
    ok(st == 1, "G: обычный игрок после возрождения = 1")
    set_ui(5, 75187)                        # в запись #5 вошёл другой человек
    at, st = respawn(5)
    ok(st == 1, "G: чужой в той же записи не наследует отметку (= 1)")
    set_ui(5, 2)

    # F: 8116 показ.
    set_state(5, 3)
    at = run_until(uc, 0x45A08E, {0x45A093}, {UC_X86_REG_EAX: 2, UC_X86_REG_ESI: rec(5)})
    ok(at == 0x45A093, "F: врезка вернулась за call (0x45A093)")
    ok(get_state(5) == 1, "F: штатная SubState сняла бит: состояние %d" % get_state(5))
    at, st = respawn(5)
    ok(st == 1, "F: после показа возрождение = 1 (отметка забыта)")

    # ── N12 H: добавление угрозы (настоящая sub_43D2C0 за врезкой) ────────────
    # монстр 0 — вне боя (бит 2 монстра снят — чтобы не идти в ветку «вход в бой»
    # с вызовами помощников, флаг a5 = 0), массив игроков монстра = USERS
    def mob_set(i, off, fmt, v):
        uc.mem_write(mob(i) + off, struct.pack(fmt, v))

    def mob_get(i, off, fmt):
        return struct.unpack(fmt, uc.mem_read(mob(i) + off, struct.calcsize(fmt)))[0]

    def hate_add(i, user, amount, dmg=10, flag=0):
        esp0 = 0x001F0000
        uc.mem_write(esp0, struct.pack("<IIII", RET_MAGIC, user & 0xFFFF, dmg, flag))
        uc.reg_write(UC_X86_REG_ESP, esp0)
        uc.reg_write(UC_X86_REG_EAX, amount)
        uc.reg_write(UC_X86_REG_ECX, mob(i))
        for r, v in ((UC_X86_REG_EBX, 0x11), (UC_X86_REG_EBP, 0x22), (UC_X86_REG_ESI, 0x33),
                     (UC_X86_REG_EDI, 0x44)):
            uc.reg_write(r, v)
        uc.emu_start(0x43D2C0, RET_MAGIC, count=200000)
        return uc.reg_read(UC_X86_REG_ESP) - esp0

    for s_ in range(20):
        put_hate(0, s_, -1, 0)
    mob_set(0, 0x7748, "<I", USERS)
    mob_set(0, 30292, "<I", 2)          # монстр «в бою» (ветка без входа в бой)
    mob_set(0, 31320, "<h", -1)         # текущей цели нет
    mob_set(0, 34368, "<B", 0)
    mob_set(0, 5898, "<B", 0)
    set_ui(8, 111); set_state(8, 1)     # видимый игрок #8
    set_ui(5, 2);   set_state(5, 3)     # скрытый игрок #5 (жив + скрыт)
    t0 = mob_get(0, 33928, "<I")
    d = hate_add(0, 5, 500)
    ok(d == 16, "H: скрытый — возврат ret 0Ch сразу (снято %d б со стека, ждали 16)" % d)
    ok(all(hate_user(0, s_) == -1 for s_ in range(20)), "H: скрытый — список угрозы не тронут")
    ok(mob_get(0, 31320, "<h") == -1, "H: скрытый — цель монстра не выставлена")
    ok(mob_get(0, 33928, "<I") == t0, "H: скрытый — время последней угрозы (+33928) не тронуто")
    ok(all(uc.reg_read(r) == v for r, v in ((UC_X86_REG_EBX, 0x11), (UC_X86_REG_EBP, 0x22),
                                            (UC_X86_REG_ESI, 0x33), (UC_X86_REG_EDI, 0x44))),
       "H: скрытый — регистры вызывающего сохранены")
    d = hate_add(0, 8, 500)
    ok(d == 16, "H: видимый — настоящая sub_43D2C0 дошла до ret 0Ch")
    ok(hate_user(0, 0) == 8 and mob_get(0, 31352 + 8, "<I") == 500 and mob_get(0, 31352 + 12, "<I") == 10,
       "H: видимый — запись угрозы #8 = 500, урон 10")
    ok(mob_get(0, 31320, "<h") == 8, "H: видимый — цель монстра = #8")
    ok(uc.reg_read(UC_X86_REG_EBX) == 0x11 and uc.reg_read(UC_X86_REG_EBP) == 0x22,
       "H: видимый — ebx/ebp восстановлены штатным эпилогом (исходные push исполнены)")
    set_state(5, 2)                     # «мёртв и скрыт» — тоже не добавляется
    hate_add(0, 5, 900)
    ok(all(hate_user(0, s_) != 5 for s_ in range(20)), "H: состояние 2 (скрыт, мёртв) — угрозы нет")
    set_state(5, 1)                     # показался — угроза снова добавляется
    hate_add(0, 5, 900)
    ok(any(hate_user(0, s_) == 5 for s_ in range(20)) and mob_get(0, 31320, "<h") == 5,
       "H: после показа угроза к #5 добавляется, цель = наибольшая угроза (#5)")
    mob_set(0, 0x7748, "<I", 0)         # нет массива игроков — как в оригинале, без гейта
    set_state(5, 3)
    for s_ in range(20):
        put_hate(0, s_, -1, 0)
    hate_add(0, 5, 10)
    ok(hate_user(0, 0) == 5, "H: у монстра нет массива игроков — гейт не срабатывает (как оригинал)")
    mob_set(0, 0x7748, "<I", USERS)
    for s_ in range(20):
        put_hate(0, s_, -1, 0)
    mob_set(0, 31320, "<h", -1)

    # ── N12 I: одиночная цель навыка монстра ─────────────────────────────────
    def victim(kind, idx):
        mob_set(1, 0x91C4, "<B", kind)
        mob_set(1, 0x8F7C, "<b", 3)
        at = run_until(uc, 0x40C649, {0x40C650, 0x40C687},
                       {UC_X86_REG_ESI: mob(1), UC_X86_REG_EBX: USERS, UC_X86_REG_ECX: idx,
                        UC_X86_REG_EDX: 0xDEAD})
        return at, uc.reg_read(UC_X86_REG_EDX)

    set_state(5, 3)
    at, edx = victim(1, 5)
    ok(at == 0x40C687, "I: цель-игрок скрыт — добавление жертвы пропущено (0x40C687)")
    set_state(5, 2)
    at, edx = victim(1, 5)
    ok(at == 0x40C687, "I: цель-игрок «скрыт и мёртв» — пропущено")
    at, edx = victim(1, 8)
    ok(at == 0x40C650 and edx == 3, "I: цель-игрок видим — как оригинал (edx = число жертв 3)")
    set_state(5, 3)
    at, edx = victim(0, 5)
    ok(at == 0x40C650 and edx == 3, "I: цель — монстр (тот же номер) — как оригинал")

    # ── N11: переполнение таблицы отметок (128) — вытесняется самая старая ────
    for n in range(40, 40 + 128):
        set_ui(n, 1000 + n); set_state(n, 1)
        run_until(uc, 0x45A11F, {0x45A124}, {UC_X86_REG_EDI: 2, UC_X86_REG_ESI: rec(n), UC_X86_REG_ECX: CTX})
    # запись #5 (UserIndex 2) была первой — теперь она самая старая и вытесняется 129-й отметкой
    set_ui(5, 2)
    at, st = respawn(5)
    ok(st == 1, "переполнение: #5 — отметка снята 8116 раньше, возрождение = 1 (контроль)")
    n_new = 40 + 128
    set_ui(n_new, 1000 + n_new); set_state(n_new, 1)
    run_until(uc, 0x45A11F, {0x45A124}, {UC_X86_REG_EDI: 2, UC_X86_REG_ESI: rec(n_new), UC_X86_REG_ECX: CTX})
    at, st = respawn(n_new)
    ok(st == 3, "переполнение: 129-е скрытие ЗАПОМНЕНО (вытеснена самая старая), возрождение = 3")
    at, st = respawn(40)
    ok(st == 1, "переполнение: вытеснена самая старая отметка (#40) — возрождение = 1")
    at, st = respawn(41)
    ok(st == 3, "переполнение: следующая по возрасту (#41) цела — возрождение = 3")

    # ── выключатели N12 ───────────────────────────────────────────────────────
    uc4, _, _ = install({("N12_GmHideHate", "Enabled"): 0})
    untouched = all(bytes(uc4.mem_read(va, len(bytes.fromhex(SITES[va][0])))) == bytes.fromhex(SITES[va][0])
                    for va in (0x43D2C0, 0x40C649))
    ok(install.rv12 == 1 and untouched, "N12 Enabled=0: Disabled (1), площадки H/I не тронуты")
    uc5, _, _ = install({("N12_GmHideHate", "BlockHate"): 0})
    ok(install.rv12 == 0 and bytes(uc5.mem_read(0x43D2C0, 9)) == bytes.fromhex(SITES[0x43D2C0][0])
       and uc5.mem_read(0x40C649, 1)[0] == 0xE8, "N12 BlockHate=0: H не тронута, I стоит")
    uc6, _, _ = install({("N12_GmHideHate", "SingleVictim"): 0})
    ok(install.rv12 == 0 and bytes(uc6.mem_read(0x40C649, 7)) == bytes.fromhex(SITES[0x40C649][0])
       and uc6.mem_read(0x43D2C0, 1)[0] == 0xE9, "N12 SingleVictim=0: I не тронута, H стоит")

    # Выключатели: DropTarget=0 → площадка A остаётся оригинальной; Enabled=0 → ничего.
    uc2, rv2, _ = install({("N11_GmHideNpc", "DropTarget"): 0})
    ok(rv2 == 0 and bytes(uc2.mem_read(0x447BA7, 7)) == bytes.fromhex("83be5476000000"),
       "выключатель DropTarget=0: площадка A не тронута, остальное стоит")
    uc3, rv3, _ = install({("N11_GmHideNpc", "Enabled"): 0}, n12=False)
    untouched = all(bytes(uc3.mem_read(va, len(bytes.fromhex(h)))) == bytes.fromhex(h)
                    for va, (h, _) in SITES.items())
    ok(rv3 == 1 and untouched, "Enabled=0: Disabled (1), ни одна площадка не тронута")

    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UcError as e:
        print("ошибка эмуляции: %s" % e)
        sys.exit(3)
