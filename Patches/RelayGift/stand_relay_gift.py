# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stand_relay_gift.py — стенд P101 §3 (01.11 заготовка cash-gift-relay; 02.11.2026 дописан ревизором cash-gift-relay-review):
#   эмуляция x86 (unicorn) НАСТОЯЩЕГО кода RelayServer.exe и ChannelManager.exe — исходных и пропатченных копий
#   из _live_copies (сухой прогон patch_relay_gift.py) — без запуска серверов и без сети.
#
# Почему не живой стенд: RelayServer — оконное приложение (CreateDialogParam+ShowWindow), при старте открывает ODBC «joy1»
#   (ini\DBInfo.ini) и ходит на адреса dev-сервера; CM требует OverLap/Operation. Стойку не трогаем.
#
# Что исполняется кодом exe без подмены:
#   диспетчеры — реле QueueThread sub_40A260 (пакеты от GS), реле Process_Manager sub_4058A8 (пакеты от CM),
#   CM sub_40EE4D; их switch по опкоду; обработчики 5076 (sub_4092D0, sub_404264, CM sub_40DCC2), 5077 (sub_409324,
#   sub_4042F9, CM sub_40DDD0), 5087 (sub_40139D, CM sub_4042C7); сборка заголовка и кадра sub_413930 / sub_4137A0 /
#   CM sub_417760 (memset/memcpy CRT из образа, проверка cookie).
# Подменено (только очередь, сокеты и журналы):
#   выборка из очереди (реле sub_4151A0, CM sub_419170) → в буфер диспетчера кладётся наш слот 4096 б (кадр + хвост);
#   «сокет жив» (реле sub_413210/sub_413620, CM sub_417130) → 1; отправка в сокет (реле sub_412CB0/sub_413250,
#   CM sub_416BD0) → кадр ЗАПИСЫВАЕТСЯ (сокет, длина, байты); выбор сокета (реле sub_4027C5(sys,thread) → 7,
#   CM sub_401C47(канал,сист,поток) → 9, sub_401B79(канал) → 20+канал) → аргументы записываются;
#   журналы (реле sub_415B50/sub_415FE0/sub_40F7FF, CM sub_419B20/sub_4158E0) и импорты Win32/CRT.
# Слот очереди: в живом коде слот обнуляется заранее (sub_415150 memset следующего слота 0x1000), разборщик копирует
#   ровно длину кадра → за 0xFE лежат нули. Сценарий «short_cc» нарочно заливает хвост 0xCC, чтобы показать,
#   откуда берутся байты сверх присланного кадра (только из буфера диспетчера 4096 б, за его пределы не выходим).
#
# Запуск: python stand_relay_gift.py [--out <файл>]   (по умолчанию Reports\cash_gift\p101\stand_relay_out.txt)
# Код возврата 0 = все проверки сошлись, 1 = есть расхождение.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает; unicorn/pefile импортируются в main().
import argparse
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                                 # AstoryServer\Patches\RelayGift
LC = os.path.join(HERE, "_live_copies")                                           # копии живых exe
OUT_DEFAULT = os.path.normpath(os.path.join(HERE, "..", "..", "..", "Reports", "cash_gift", "p101", "stand_relay_out.txt"))

RET_MAGIC = 0x0BAD0000                                                            # адрес возврата «конец эмуляции»
STUB_BASE = 0x10000000                                                            # заглушки импортов (по 16 б)
STACK_BASE, STACK_SIZE = 0x0E000000, 0x00400000                                   # стек
SLOT_BASE = 0x20000000                                                            # наш слот очереди (4096 б)
SLOT_SIZE = 0x1000                                                                # размер слота / буфера диспетчера

OPC_GIFT, OPC_GIFT_ACK, OPC_GCHAT = 5076, 5077, 5087                              # опкоды под проверкой

# Адреса по бинарю (VA, база 0x400000; capstone-дизасм в REVIEW_RELAY.md §1).
#   stubs: адрес → (вид, байт аргументов для ret N, возвращаемое значение)
ADDR = {
    "relay": dict(
        disp_gs=0x40A260, disp_cm=0x4058A8, iocp=0x48E3B0, mgr_base=0x4279E8, mgr_cnt=0x4279E4,
        sys_cnt=0x48E39C, thr_cnt=0x48E3A0,
        builders={0x413930: "sub_413930(MakeHeaderConnectSend → CM)", 0x4137A0: "sub_4137A0(MakeHeaderSend → GS)"},
        handlers={0x4092D0: "sub_4092D0", 0x404264: "sub_404264", 0x409324: "sub_409324", 0x4042F9: "sub_4042F9",
                  0x40139D: "sub_40139D"},
        stubs={0x4151A0: ("deq", 8, 0), 0x413210: ("alive", 4, 1), 0x413620: ("alive", 8, 1),
               0x412CB0: ("send", 0xC, 1), 0x413250: ("send", 0xC, 1), 0x4027C5: ("sock_st", 8, 7),
               0x415B50: ("log", 0, 0), 0x415FE0: ("log", 0, 0), 0x40F7FF: ("log", 0, 0)}),
    "cm": dict(
        disp_gs=0x40EE4D, chan_obj=0x4445E0, chan_cnt=0x4445E0 + 22092,
        builders={0x417760: "sub_417760(MakeHeaderSend → реле канала)"},
        handlers={0x40DCC2: "sub_40DCC2", 0x40DDD0: "sub_40DDD0", 0x4042C7: "sub_4042C7"},
        stubs={0x419170: ("deq", 8, 0), 0x417130: ("alive", 4, 1), 0x416BD0: ("send", 0xC, 1),
               0x401C47: ("sock_cst", 0xC, 9), 0x401B79: ("sock_c", 4, None),
               0x419B20: ("log", 0, 0), 0x4158E0: ("log", 0, 0)}),
}

# Импорты: имя → байт аргументов stdcall (None = cdecl) и возвращаемое значение.
IMPORTS = {"EnterCriticalSection": (4, 0), "LeaveCriticalSection": (4, 0), "GetTickCount": (0, 1000),
           "OutputDebugStringA": (4, 0), "WSAGetLastError": (0, 0), "GetLastError": (0, 0),
           "InterlockedIncrement": (4, 1), "InterlockedDecrement": (4, 0), "Sleep": (4, 0), "SetEvent": (4, 1),
           "printf": (None, 0), "sprintf": (None, 0), "_snprintf": (None, 0), "vsprintf": (None, 0),
           "_vsnprintf": (None, 0)}


def make_frame(opcode, body, a6=0x1234, sock=5):
    """Кадр как в слоте очереди: FB | u16 размер | i16 a6 | u16 сокет | u16 опкод | тело | FE."""
    return struct.pack("<BHhHH", 0xFB, len(body) + 10, a6, sock, opcode) + bytes(body) + b"\xFE"


def make_slot(frame, fill=0):
    """Слот очереди 4096 б: кадр + хвост (0 — как в живом коде; 0xCC — метка «байты не из кадра»)."""
    return frame + bytes([fill]) * (SLOT_SIZE - len(frame))


def body_gift(n=237):
    """Тело 5076 с узнаваемым шаблоном; маршрут получателя +31..+34 = канал 1, система 2, карта 3, поток 4."""
    b = bytearray(((0x40 + 3 * i) ^ 0xA5) & 0xFF for i in range(n))
    b[0:4] = bytes([0, 1, 0, 2])                                                  # маршрут отправителя
    if n > 34:
        b[31:35] = bytes([1, 2, 3, 4])
    return bytes(b)


def body_ack(n=61):
    """Тело 5077: маршрут отправителя +21..+24 = канал 1, система 2, карта 3, поток 4."""
    b = bytearray(((0x11 + 5 * i) ^ 0x3C) & 0xFF for i in range(n))
    b[21:25] = bytes([1, 2, 3, 4])
    return bytes(b)


def body_gchat(n=100, scope=2):
    """Тело 5087 (глобальный чат), байт +2 = область (2 → реле шлёт в CM)."""
    b = bytearray((0x70 + 11 * i) & 0xFF for i in range(n))
    b[2] = scope
    return bytes(b)


class Emu:
    """Образ PE в unicorn + перехват заглушек; один экземпляр = один exe."""

    def __init__(self, path, kind):
        import pefile
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
        from unicorn import x86_const as X
        self.X, self.kind, self.path = X, kind, path
        self.cfg = ADDR[kind]
        raw = open(path, "rb").read()
        self.md5 = hashlib.md5(raw).hexdigest()
        pe = pefile.PE(data=raw)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        uc = self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        uc.mem_map(self.base, size)
        uc.mem_write(self.base, raw[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for s in pe.sections:
            n = min(s.SizeOfRawData, max(s.Misc_VirtualSize, s.SizeOfRawData))
            uc.mem_write(self.base + s.VirtualAddress, raw[s.PointerToRawData:s.PointerToRawData + n])
        uc.mem_map(STUB_BASE, 0x10000)
        uc.mem_write(STUB_BASE, b"\xC3" * 0x10000)
        self.imp = {}
        k = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else "ord%d" % imp.ordinal
                stub = STUB_BASE + 16 * k
                k += 1
                self.imp[stub] = name
                uc.mem_write(imp.address, struct.pack("<I", stub))                # IAT → заглушка
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(SLOT_BASE, 0x10000)
        uc.mem_map(RET_MAGIC, 0x1000)
        uc.mem_write(RET_MAGIC, b"\xF4" * 0x1000)
        self.events, self.error, self.slot, self.deq_left = [], None, b"", 0
        uc.hook_add(UC_HOOK_CODE, self._on_import, begin=STUB_BASE, end=STUB_BASE + 0xFFFF)
        for a in self.cfg["stubs"]:
            uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=a, end=a)
        for a in self.cfg["builders"]:
            uc.hook_add(UC_HOOK_CODE, self._on_builder, begin=a, end=a)
        for a in self.cfg["handlers"]:
            uc.hook_add(UC_HOOK_CODE, self._on_handler, begin=a, end=a)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)

    # --- помощники ---
    def r32(self, a):
        """Прочитать u32."""
        return struct.unpack("<I", self.uc.mem_read(a, 4))[0]

    def w32(self, a, v):
        """Записать u32."""
        self.uc.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))

    def arg(self, i):
        """i-й аргумент (с 0) в точке входа функции: [esp+4+4i]."""
        return self.r32(self.uc.reg_read(self.X.UC_X86_REG_ESP) + 4 + 4 * i)

    def ret(self, nbytes, eax):
        """Симулировать возврат из функции: ret nbytes, eax = значение."""
        uc, X = self.uc, self.X
        esp = uc.reg_read(X.UC_X86_REG_ESP)
        ra = self.r32(esp)
        uc.reg_write(X.UC_X86_REG_ESP, esp + 4 + nbytes)
        uc.reg_write(X.UC_X86_REG_EAX, eax & 0xFFFFFFFF)
        uc.reg_write(X.UC_X86_REG_EIP, ra)

    # --- перехваты ---
    def _on_import(self, uc, addr, size, _):
        name = self.imp.get(addr & ~0xF)
        if name in ("memset", "memcpy", "memmove"):                               # CRT msvcr: делаем по-настоящему (cdecl)
            d, s, n = self.arg(0), self.arg(1), self.arg(2)
            if n > 0x100000:
                self.error = "%s с размером 0x%X" % (name, n)
                uc.emu_stop()
                return
            if name == "memset":
                uc.mem_write(d, bytes([s & 0xFF]) * n)
            else:
                uc.mem_write(d, bytes(uc.mem_read(s, n)))
                self.events.append(("copy", name, d, s, n))
            self.ret(0, d)
            return
        if name in IMPORTS:
            n, v = IMPORTS[name]
            self.events.append(("imp", name))
            self.ret(n or 0, v)
            return
        self.error = "неожиданный импорт %s @0x%X" % (name, addr)
        uc.emu_stop()

    def _on_stub(self, uc, addr, size, _):
        kind, n, v = self.cfg["stubs"][addr]
        if kind == "deq":                                                         # выборка: наш слот один раз
            dst = self.arg(0)
            if self.deq_left > 0:
                self.deq_left -= 1
                uc.mem_write(dst, self.slot)
                self.events.append(("deq", uc.reg_read(self.X.UC_X86_REG_ECX), dst))
                self.ret(n, 1)
            else:
                self.ret(n, 0)
            return
        if kind == "send":
            sock, src, ln = self.arg(0), self.arg(1), self.arg(2) & 0xFFFF
            data = bytes(uc.mem_read(src, ln))
            self.events.append(("send", sock & 0xFFFF, ln, data))
        elif kind == "sock_st":
            self.events.append(("sock_st", self.arg(0) & 0xFF, self.arg(1) & 0xFFFF))
        elif kind == "sock_cst":
            self.events.append(("sock_cst", self.arg(0) & 0xFF, self.arg(1) & 0xFF, self.arg(2) & 0xFF))
        elif kind == "sock_c":
            ch = self.arg(0)
            self.events.append(("sock_c", ch))
            v = 20 + ch
        elif kind == "log":
            self.events.append(("log", hex(addr)))
        self.ret(n, v)

    def _on_builder(self, uc, addr, size, _):
        a = [self.arg(i) for i in range(5)]                                       # (cmd, size, sock, src, a6)
        self.events.append(("build", addr, a[0] & 0xFFFF, a[1] & 0xFFFF, a[2] & 0xFFFF, a[3], a[4] & 0xFFFF))

    def _on_handler(self, uc, addr, size, _):
        self.events.append(("handler", self.cfg["handlers"][addr], [self.arg(i) for i in range(5)]))

    def _on_unmapped(self, uc, access, addr, size, value, _):
        self.error = "обращение к неотображённой памяти 0x%X (eip 0x%X)" % (addr, uc.reg_read(self.X.UC_X86_REG_EIP))
        return False

    # --- запуск ---
    def call(self, fn, args, ecx, slot):
        """Вызвать fn(args) с this=ecx; выборка из очереди отдаст slot один раз. → список событий."""
        uc, X = self.uc, self.X
        self.events, self.error, self.slot, self.deq_left = [], None, slot, 1
        uc.mem_write(SLOT_BASE, slot)
        esp = STACK_BASE + STACK_SIZE - 0x10000
        for v in reversed(args):
            esp -= 4
            self.w32(esp, v)
        esp -= 4
        self.w32(esp, RET_MAGIC)
        for r in (X.UC_X86_REG_EAX, X.UC_X86_REG_EBX, X.UC_X86_REG_EDX, X.UC_X86_REG_ESI, X.UC_X86_REG_EDI,
                  X.UC_X86_REG_EBP):
            uc.reg_write(r, 0)
        uc.reg_write(X.UC_X86_REG_ECX, ecx)
        uc.reg_write(X.UC_X86_REG_ESP, esp)
        try:
            uc.emu_start(fn, RET_MAGIC, count=20_000_000)
        except Exception as e:                                                    # unicorn UcError
            if not self.error:
                self.error = "UcError %s @eip 0x%X" % (e, uc.reg_read(X.UC_X86_REG_EIP))
        if not self.error and uc.reg_read(X.UC_X86_REG_EIP) != RET_MAGIC:
            self.error = "эмуляция не дошла до возврата (eip 0x%X)" % uc.reg_read(X.UC_X86_REG_EIP)
        return self.events


def run_dispatcher(emu, which, frame, fill=0):
    """Подать кадр в диспетчер: relay 'gs' (QueueThread) / 'cm' (Process_Manager), cm 'gs' (CM от реле)."""
    c = emu.cfg
    slot = make_slot(frame, fill)
    if emu.kind == "relay" and which == "gs":
        return emu.call(c["disp_gs"], [0, 0], c["iocp"], slot)
    if emu.kind == "relay" and which == "cm":
        emu.w32(c["mgr_base"], 0)
        emu.w32(c["mgr_cnt"], 1)
        return emu.call(c["disp_cm"], [0, 0], 0x12345678, slot)
    return emu.call(c["disp_gs"], [], c["chan_obj"], slot)


def sends(events):
    """События отправки → [(сокет, длина, опкод, a6, тело, хвост_ок)]."""
    out = []
    for e in events:
        if e[0] == "send":
            _, sock, ln, data = e
            hdr = struct.unpack_from("<BHhHH", data, 0)
            out.append(dict(sock=sock, frame_len=ln, hdr_len=hdr[1], a6=hdr[2], hsock=hdr[3], opcode=hdr[4],
                            body=data[9:ln - 1], fe=data[ln - 1] == 0xFE, fb=data[0] == 0xFB))
    return out


def describe_body(got, sent_body, fill):
    """Откуда байты тела отправки: сколько совпало с присланным телом, что дальше."""
    n = len(sent_body)
    same = sum(1 for i in range(min(n, len(got))) if got[i] == sent_body[i])
    tail = got[n:]
    if not tail:
        return "совпало %d/%d присланных байт" % (same, n)
    return "совпало %d/%d присланных байт; хвост %d б: [0]=%02X (терминатор кадра), далее %s" % (
        same, n, len(tail), tail[0], "все 0x%02X" % fill if all(x == fill for x in tail[1:]) else tail[1:].hex())


def main(argv=None):
    """Прогон сценариев на исходных и пропатченных копиях; отчёт в --out; код 0 = все проверки сошлись."""
    ap = argparse.ArgumentParser(description="P101 §3: эмуляция пересылки 5076/5077/5087 в RelayServer/ChannelManager")
    ap.add_argument("--out", default=OUT_DEFAULT, help="файл вывода")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    lines, fails = [], []

    def log(s=""):
        print(s)
        lines.append(s)

    def check(cond, what):
        log("    [%s] %s" % ("OK" if cond else "FAIL", what))
        if not cond:
            fails.append(what)

    exes = [("RelayServer", "RelayServer\\RelayServer", "relay"), ("Indun_RelayServer", "Indun_RelayServer\\RelayServer", "relay"),
            ("Ch2_RelayServer", "Ch2_RelayServer\\RelayServer", "relay"), ("ChannelManager", "ChannelManager\\ChannelManager", "cm")]
    g237, g153, ack, gc2, gc1 = body_gift(237), body_gift(153), body_ack(61), body_gchat(100, 2), body_gchat(100, 1)
    log("stand_relay_gift.py — эмуляция unicorn; кадр: FB|len|a6=0x1234|sock=5|opcode|тело|FE; слот 4096 б")
    for title, rel, kind in exes:
        res = {}
        for variant in ("orig", "patched"):
            path = os.path.join(LC, rel + (".exe" if variant == "orig" else ".patched.exe"))
            emu = Emu(path, kind)
            log("")
            log("== %s [%s] %s md5 %s" % (title, variant, os.path.relpath(path, HERE), emu.md5))
            if kind == "relay":
                emu.w32(emu.cfg["sys_cnt"], 1)                                    # для рассылки 5087: 1 система × 2 потока
                emu.w32(emu.cfg["thr_cnt"], 2)
                scen = [("5076 GS→реле→CM, тело 237", "gs", OPC_GIFT, g237, 0),
                        ("5076 GS→реле→CM, тело 153 (старый GS), хвост 0", "gs", OPC_GIFT, g153, 0),
                        ("5076 GS→реле→CM, тело 153, хвост 0xCC", "gs", OPC_GIFT, g153, 0xCC),
                        ("5076 CM→реле→GS, тело 237", "cm", OPC_GIFT, g237, 0),
                        ("5076 CM→реле→GS, тело 153, хвост 0xCC", "cm", OPC_GIFT, g153, 0xCC),
                        ("5077 GS→реле→CM, тело 61", "gs", OPC_GIFT_ACK, ack, 0xCC),
                        ("5077 CM→реле→GS, тело 61", "cm", OPC_GIFT_ACK, ack, 0xCC),
                        ("5087 GS→реле (область 2 → CM), тело 100", "gs", OPC_GCHAT, gc2, 0xCC),
                        ("5087 GS→реле (область 1 → рассылка), тело 100", "gs", OPC_GCHAT, gc1, 0xCC),
                        ("5087 CM→реле (рассылка), тело 100", "cm", OPC_GCHAT, gc2, 0xCC)]
            else:
                emu.uc.mem_write(emu.cfg["chan_cnt"], b"\x02")                     # 5087: 2 канала
                scen = [("5076 реле→CM→реле канала, тело 237", "gs", OPC_GIFT, g237, 0),
                        ("5076 реле→CM, тело 153, хвост 0xCC", "gs", OPC_GIFT, g153, 0xCC),
                        ("5077 реле→CM→реле канала, тело 61", "gs", OPC_GIFT_ACK, ack, 0xCC),
                        ("5087 реле→CM (рассылка по каналам), тело 100", "gs", OPC_GCHAT, gc2, 0xCC)]
            for name, which, opc, body, fill in scen:
                frame = make_frame(opc, body)
                ev = run_dispatcher(emu, which, frame, fill)
                ss = sends(ev)
                hs = [e for e in ev if e[0] == "handler"]
                bs = [e for e in ev if e[0] == "build"]
                lk = [e for e in ev if e[0] in ("sock_st", "sock_cst", "sock_c")]
                lg = [e for e in ev if e[0] == "log"]
                log("  -- %s" % name)
                if emu.error:
                    log("    ОШИБКА ЭМУЛЯЦИИ: %s" % emu.error)
                    fails.append("%s %s %s: %s" % (title, variant, name, emu.error))
                    continue
                buf_body = SLOT_BASE                                              # для сверки указателя: тело = буфер+9
                for h in hs:
                    log("    обработчик %s(%s)" % (h[1], ", ".join("0x%X" % x for x in h[2][:5])))
                for l in lk:
                    log("    выбор сокета %s%s" % (l[0], l[1:]))
                for b in bs:
                    log("    сборка %s: cmd %d, size %d, sock %d, src 0x%08X, a6 0x%04X" % (
                        emu.cfg["builders"][b[1]].split("(")[0], b[2], b[3], b[4], b[5], b[6]))
                for s in ss:
                    log("    ОТПРАВКА sock %d: кадр %d б (поле len %d), опкод %d, a6 0x%04X, FB %s, FE %s, тело %d б; %s" % (
                        s["sock"], s["frame_len"], s["hdr_len"], s["opcode"], s["a6"] & 0xFFFF, s["fb"], s["fe"],
                        len(s["body"]), describe_body(s["body"], body, fill)))
                if lg:
                    log("    журнал: %s" % ", ".join(x[1] for x in lg))
                res[(variant, name)] = [(s["sock"], s["frame_len"], s["opcode"], s["a6"], s["body"]) for s in ss]
                # проверки
                if opc == OPC_GIFT:
                    want = 153 if variant == "orig" else 237
                    check(len(ss) == 1 and ss[0]["opcode"] == OPC_GIFT and len(ss[0]["body"]) == want
                          and ss[0]["frame_len"] == want + 10 and ss[0]["fe"] and ss[0]["a6"] == 0x1234,
                          "%s %s: одна отправка 5076, тело %d б, кадр %d, a6 сохранён" % (title, variant, want, want + 10))
                    if ss:
                        exp = (body + frame[len(body) + 9:] + bytes([fill]) * SLOT_SIZE)[:want]
                        check(ss[0]["body"] == exp, "%s %s: тело отправки = байты исходного слота (тело+FE+хвост) %d б"
                              % (title, variant, want))
                        if len(body) >= want:
                            check(ss[0]["body"] == body[:want], "%s %s: ровно наши %d байт тела" % (title, variant, want))
                    if hs and bs:                                                 # указатель-источник сборки
                        bodyp = hs[0][2][1] if kind == "cm" else hs[0][2][2]      # CM: a2; реле: a3 = тело в буфере диспетчера
                        same = bs[0][5] == bodyp
                        log("    источник сборки 0x%08X, тело кадра в буфере диспетчера 0x%08X → %s" % (
                            bs[0][5], bodyp, "ТЕЛО ИСХОДНОГО КАДРА" if same else "локальная копия 153 б"))
                        want_same = variant == "patched" or kind == "cm"
                        check(same == want_same, "%s %s: источник = %s" % (
                            title, variant, "тело исходного кадра" if want_same else "локальная копия"))
                elif opc == OPC_GIFT_ACK:
                    check(len(ss) == 1 and len(ss[0]["body"]) == 61 and ss[0]["body"] == body,
                          "%s %s: 5077 одна отправка, ровно 61 б тела" % (title, variant))
                else:
                    check(len(ss) >= 1 and all(len(s["body"]) == len(body) and s["body"] == body for s in ss),
                          "%s %s: 5087 отправок %d, тело %d б как прислано" % (title, variant, len(ss), len(body)))
        # сравнение исходный ↔ пропатченный: 5077/5087 побайтно одинаковы
        for (variant, name), v in res.items():
            if variant == "orig" and not name.startswith("5076"):
                check(res.get(("patched", name)) == v, "%s: «%s» исходный = пропатченный побайтно" % (title, name))
    # дифф по всему файлу: изменены только байты внутри 4 мест (реле 3, CM 1); функции 5077/5087 не задеты
    places = {"relay": [(0x4042A5, 13), (0x4092F6, 7), (0x4092FF, 5)], "cm": [(0x40DD4A, 5)]}
    funcs = {"relay": [("sub_409324 5077→CM", 0x409324, 0x409370), ("sub_4042F9 5077→GS", 0x4042F9, 0x404363),
                       ("sub_40139D 5087", 0x40139D, 0x4014CB), ("sub_4137A0", 0x4137A0, 0x413930),
                       ("sub_413930", 0x413930, 0x413A90)],
             "cm": [("sub_40DDD0 5077", 0x40DDD0, 0x40DEA0), ("sub_4042C7 5087", 0x4042C7, 0x404363),
                    ("sub_417760", 0x417760, 0x4178F0)]}
    log("")
    log("== дифф исходный ↔ пропатченный по всему файлу (fo = VA − 0x400000: у всех образов .text VA 0x1000 = raw 0x1000)")
    for title, rel, kind in exes:
        o = open(os.path.join(LC, rel + ".exe"), "rb").read()
        p = open(os.path.join(LC, rel + ".patched.exe"), "rb").read()
        diff = [i for i in range(min(len(o), len(p))) if o[i] != p[i]]
        allowed = set()
        for va, n in places[kind]:
            allowed.update(range(va - 0x400000, va - 0x400000 + n))
        log("  %s: размер %d/%d, изменено байт %d по смещениям %s" % (
            title, len(o), len(p), len(diff), ", ".join("0x%X" % i for i in diff)))
        check(len(o) == len(p) and diff and set(diff) <= allowed,
              "%s: все изменённые байты внутри мест %s" % (title, ", ".join("0x%X+%d" % x for x in places[kind])))
        for nm, lo, hi in funcs[kind]:
            check(o[lo - 0x400000:hi - 0x400000] == p[lo - 0x400000:hi - 0x400000],
                  "%s: %s (0x%X..0x%X) побайтно не изменена" % (title, nm, lo, hi))
    log("")
    log("ИТОГ: %s" % ("ВСЕ ПРОВЕРКИ СОШЛИСЬ" if not fails else "РАСХОЖДЕНИЙ %d: %s" % (len(fails), "; ".join(fails))))
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
