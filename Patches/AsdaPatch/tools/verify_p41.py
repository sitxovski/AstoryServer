# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p41.py — ЭМУЛЯТОРНАЯ проверка P41 (4056 скрытого оператора соседям не уходит).
#
# Сервер локально не запускается (запрет). В unicorn загружаются НАСТОЯЩИЕ образы GameServer.exe
# и собранной AsdaPatch.dll (по предпочтительной базе, без релокаций). Площадочные стабы P41
# находятся в DLL по сигнатуре `push VA; [push off;] jmp`. Функции GameServer, которые зовёт
# C-часть (GetUser 0x5324A0, IsOperatorIndex 0x52ECF0, SendPacket 0x4C28F0, Log 0x569DF0),
# и получатели рассылки (0x41EA80, 0x52E630) подменены перехватчиками: они записывают вызов
# (ecx, аргументы, адрес возврата) и возвращаются по своему соглашению (ret N).
#
# Сценарии для каждой из 9 площадок:
#   • обычный игрок / оператор без скрытия / скрытый НЕ оператор → стоковый получатель вызван
#     с тем же ecx и теми же аргументами, возврат — ровно за площадку (site+5), стек сбалансирован;
#   • скрытый оператор, «кроме себя» → получатель НЕ вызван, возврат за площадку, стек
#     сбалансирован (ret 18h), SendPacket не звался;
#   • скрытый оператор, «включая себя» → получатель НЕ вызван, SendPacket вызван ОДИН раз:
#     net = mgr+4, op 4056, len 22, кому = номер, тело = тот же буфер, от = номер, флаг 1;
#     возврат за площадку, стек сбалансирован (ret 14h).
#   • регистры ebx/esi/edi/ebp вызывающего сохранены во всех ветках.
#
# ЗАПУСК: python verify_p41.py [AsdaPatch.dll] [GameServer.exe]
import os
import re
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
                               UC_X86_REG_EIP, UC_X86_REG_GDTR, UC_X86_REG_FS, UC_X86_REG_SS,
                               UC_X86_REG_DS, UC_X86_REG_ES)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
EXE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.exe")

# площадка: (смещение this в кадре или None для «включая себя», получатель)
SITES = {
    0x0052AE41: (-0x58, 0x0041EA80, "CharRegenVillageMove"),
    0x0052BE8B: (-0x78, 0x0041EA80, "CharSoulMateRecallPosition"),
    0x0054EE63: (-0x5C, 0x0041EA80, "CharJumpCommandPosition_0"),
    0x0054F2F6: (-0x78, 0x0041EA80, "CharJumpCommandPosition"),
    0x00550ED9: (-0x8C, 0x0041EA80, "Send_MoveCommand"),
    0x0055E8D7: (-0x94, 0x0041EA80, "RecvClient_TargetJump (1)"),
    0x0055EDBE: (-0x94, 0x0041EA80, "RecvClient_TargetJump (2)"),
    0x0052B8D3: (None,  0x0052E630, "CharRegenSelfPosition"),
    0x0055D599: (None,  0x0052E630, "CharRegenVillageMove_1 (RoseWar)"),
}
RET_N = {0x0041EA80: 0x18, 0x0052E630: 0x14, 0x004C28F0: 0x18, 0x005324A0: 4, 0x0052ECF0: 8,
         # доработка СРЕДН-1: получатель доотправки + хелперы сборки тела 4056
         0x0052E6D0: 0x14, 0x0043CED0: 4, 0x0043D510: 4, 0x004CABC0: 4}

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def main():
    dll = pefile.PE(DLL)
    exe = pefile.PE(EXE)
    dimg = dll.get_memory_mapped_image()
    dbase = dll.OPTIONAL_HEADER.ImageBase

    # стабы по сигнатуре
    stubs = {}
    for va, (off, _, _) in SITES.items():
        if off is None:
            pat = b"\x68" + struct.pack("<I", va) + b"\xe9"
        else:
            pat = b"\x68" + struct.pack("<I", va) + b"\x6a" + struct.pack("<b", off) if -128 <= off < 128 \
                else b"\x68" + struct.pack("<I", va) + b"\x68" + struct.pack("<i", off)
        hits = [m.start() for m in re.finditer(re.escape(pat), dimg)]
        ok(len(hits) == 1, "стаб площадки %#x найден в DLL (совпадений %d)" % (va, len(hits)))
        if len(hits) == 1:
            stubs[va] = dbase + hits[0]
    if bad:
        return 2

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for pe in (exe, dll):
        base = pe.OPTIONAL_HEADER.ImageBase
        img = pe.get_memory_mapped_image()
        uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, img)
    uc.mem_map(0x00100000, 0x00100000)                 # стек
    GDT, TEB = 0x00060000, 0x00070000
    uc.mem_map(GDT, 0x1000)
    uc.mem_map(TEB, 0x1000)
    uc.mem_write(TEB, struct.pack("<I", 0xFFFFFFFF))

    def desc(base, limit, access, flags):
        return struct.pack("<Q", (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (access << 40)
                           | (((limit >> 16) & 0xF) << 48) | (flags << 52) | (((base >> 24) & 0xFF) << 56))
    gdt = b"\0" * 8 + desc(0, 0xFFFFF, 0x9A, 0xC) + desc(0, 0xFFFFF, 0x92, 0xC) + desc(TEB, 0xFFF, 0x92, 0x4)
    uc.mem_write(GDT, gdt)
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_FS, 3 << 3)
    for r in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
        uc.reg_write(r, 2 << 3)

    # мир: менеджер, сетевой объект, записи игроков
    MGR, NET, USERS, BUF = 0x20000000, 0x20100000, 0x21000000, 0x20200000
    for a, sz in ((MGR, 0x1000), (NET, 0x1000), (USERS, 0x00400000), (BUF, 0x1000)):
        uc.mem_map(a, sz)
    uc.mem_write(MGR + 4, struct.pack("<I", NET))
    USZ = 0x40000
    world = {"op": set(), "hidden": set(), "hp": 0x77}   # hp — ответ перехватчика HP 0x43CED0

    def set_user(idx, op, hidden):
        (world["op"].add if op else world["op"].discard)(idx)
        uc.mem_write(USERS + USZ * idx + 0x3BC3B, struct.pack("<h", 300 if hidden else 301))

    calls = []

    def hook(uc_, addr, size, _):
        if addr not in RET_N and addr != 0x00569DF0:
            return
        esp = uc_.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", uc_.mem_read(esp, 4))[0]
        args = struct.unpack("<7I", uc_.mem_read(esp + 4, 28))
        ecx = uc_.reg_read(UC_X86_REG_ECX)
        rv, n = 0, 0
        if addr == 0x005324A0:                             # GetUser(mgr, idx)
            idx = struct.unpack("<h", struct.pack("<H", args[0] & 0xFFFF))[0]
            rv = USERS + USZ * idx if 0 <= idx < 16 else 0
        elif addr == 0x0052ECF0:                           # IsOperatorIndex(mgr, idx, -1)
            idx = struct.unpack("<h", struct.pack("<H", args[0] & 0xFFFF))[0]
            rv = 1 if idx in world["op"] else 0
            calls.append(("isop", ecx, idx, args[1]))
        elif addr == 0x00569DF0:                           # Log (cdecl) — вызывающий чистит сам
            uc_.reg_write(UC_X86_REG_ESP, esp + 4)
            uc_.reg_write(UC_X86_REG_EIP, ret)
            calls.append(("log",))
            return
        else:
            calls.append((addr, ecx, ret, args, esp))
            rv = world["hp"] if addr == 0x0043CED0 else 0x77
        n = RET_N[addr]
        uc_.reg_write(UC_X86_REG_EAX, rv)
        uc_.reg_write(UC_X86_REG_ESP, esp + 4 + n)
        uc_.reg_write(UC_X86_REG_EIP, ret)

    uc.hook_add(UC_HOOK_CODE, hook)

    STOP = 0x00150000
    # STOP лежит внутри уже отображённого стека — отдельной страницы не нужно

    def run(site, who, recipient_idx, map_ecx):
        """Эмулирует `call` с площадки: в стеке аргументы, как их кладёт сток; возврат — site+5."""
        off, target, _ = SITES[site]
        calls.clear()
        uc.mem_write(BUF, struct.pack("<hhh", who, 10, 20) + b"\0" * 16)
        FRAME = 0x001E0000
        uc.mem_write(FRAME - 0x100, b"\0" * 0x200)
        if off is not None:
            uc.mem_write(FRAME + off, struct.pack("<I", MGR))
            args = [3, recipient_idx, 0xFD8, 0x16, BUF, 1]               # сектор, кроме, op, len, тело, 1
        else:
            args = [recipient_idx, 0xFD8, 0x16, BUF, 1]                  # номер, op, len, тело, 1
        esp0 = 0x001F0000
        stack = struct.pack("<I", site + 5) + b"".join(struct.pack("<I", a) for a in args)
        uc.mem_write(esp0, stack)
        # «вызывающий» — это площадка: подменяем возврат site+5 остановкой через хук адреса
        hit = {"at": None, "esp": None}

        def stop_hook(uc_, addr, size, _):
            if addr == site + 5:
                hit["at"] = addr
                hit["esp"] = uc_.reg_read(UC_X86_REG_ESP)
                uc_.emu_stop()
        # на site+5 кладём заглушку (код сервера там есть — остановимся до исполнения)
        hh = uc.hook_add(UC_HOOK_CODE, stop_hook, begin=site + 5, end=site + 5)
        regs = {UC_X86_REG_ESP: esp0, UC_X86_REG_EBP: FRAME, UC_X86_REG_EBX: 0x1111,
                UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333,
                UC_X86_REG_ECX: (0x30000000 if off is not None else MGR), UC_X86_REG_EDX: 0x4444}
        for r, v in regs.items():
            uc.reg_write(r, v)
        try:
            uc.emu_start(stubs[site], STOP, count=100000)
        except UcError as e:
            print("    сбой эмуляции: %s EIP=%#x" % (e, uc.reg_read(UC_X86_REG_EIP)))
        finally:
            uc.hook_del(hh)
        saved = all(uc.reg_read(r) == v for r, v in ((UC_X86_REG_EBX, 0x1111), (UC_X86_REG_ESI, 0x2222),
                                                    (UC_X86_REG_EDI, 0x3333), (UC_X86_REG_EBP, FRAME)))
        balanced = hit["esp"] == esp0 + 4 + 4 * len(args)
        return hit["at"] == site + 5, balanced, saved, list(calls), args

    print("== P41: 9 площадок в эмуляторе (%s) ==" % os.path.basename(DLL))
    for site, (off, target, name) in SITES.items():
        print("-- %#x %s (%s)" % (site, name, "кроме себя" if off is not None else "включая себя"))
        for who, isop, hid, want_stock in ((5, False, False, True), (5, True, False, True),
                                           (5, False, True, True), (5, True, True, False)):
            set_user(who, isop, hid)
            back, bal, saved, cl, args = run(site, who, who, None)
            tag = "оператор=%d скрыт=%d" % (isop, hid)
            stock = [c for c in cl if c[0] == target]
            sends = [c for c in cl if c[0] == 0x004C28F0]
            ok(back and bal and saved, "%s: возврат за площадку, стек сбалансирован, регистры целы" % tag)
            if want_stock:
                good = (len(stock) == 1 and list(stock[0][3][:len(args)]) == args and stock[0][2] == site + 5
                        and stock[0][1] == (0x30000000 if off is not None else MGR) and not sends)
                ok(good, "%s: стоковый получатель %#x вызван с теми же ecx/аргументами/возвратом" % (tag, target))
            elif off is not None:
                ok(not stock and not sends, "%s: соседям НЕ отправлено, себе тоже ничего лишнего" % tag)
            else:
                s = sends[0] if len(sends) == 1 else None
                good = (not stock and s is not None and s[1] == NET
                        and (s[3][0] & 0xFFFF) == 0xFD8 and (s[3][1] & 0xFFFF) == 0x16
                        and (s[3][2] & 0xFFFF) == who and s[3][3] == BUF and (s[3][4] & 0xFFFF) == who
                        and s[3][5] == 1)
                ok(good, "%s: сектору НЕ отправлено, себе — один SendPacket(net, 4056, 22, %d, тело, %d, 1)"
                   % (tag, who, who))
    # тело чужое: рассылка по номеру ИЗ ТЕЛА (скрытый #6 в теле, вызывает #5) — не шлём
    set_user(5, False, False)
    set_user(6, True, True)
    back, bal, saved, cl, args = run(0x0054F2F6, 6, 5, None)
    ok(not [c for c in cl if c[0] == 0x0041EA80], "скрываем того, чей номер в ТЕЛЕ 4056 (#6 скрыт) — не отправлено")

    # ── доработка СРЕДН-1: доотправка 4056 на ПОКАЗЕ (Send_HideCommand, трамплин 0x54EB5A) ──
    print("-- доотправка 4056 на показе (ShowTramp @0x54EB5A)")
    show_sig = bytes.fromhex("515250ff74241cff74241451e8")
    hits = [m for m in re.finditer(re.escape(show_sig), dimg)]
    ok(len(hits) == 1, "стаб ShowTramp найден в DLL (совпадений %d)" % len(hits))
    if len(hits) == 1:
        show_stub = dbase + hits[0].start()
        A5 = BUF + 0x400                                     # тело 4025 {num, state}
        SH_STOP = 0x00151000

        def run_show(num, state):
            calls.clear()
            uc.mem_write(A5, struct.pack("<hh", num, state))
            esp0 = 0x001E8000
            # стоковая раскладка вызова 4025: [ret][arg0=num][4025][13][a5ptr][1]
            uc.mem_write(esp0, struct.pack("<IIIIII", SH_STOP, num & 0xFFFF, 4025, 13, A5, 1))
            uc.reg_write(UC_X86_REG_ESP, esp0)
            uc.reg_write(UC_X86_REG_EBP, 0x001E0000)
            uc.reg_write(UC_X86_REG_ECX, MGR)
            hs = uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: u.emu_stop(), begin=SH_STOP, end=SH_STOP)
            try:
                uc.emu_start(show_stub, SH_STOP, count=200000)
            except UcError as e:
                print("    сбой show-эмуляции: %s EIP=%#x" % (e, uc.reg_read(UC_X86_REG_EIP)))
            finally:
                uc.hook_del(hs)
            return [c for c in calls if c[0] == 0x0052E6D0]

        # мометим #7 подавлением его 4056, затем показываем — ждём ОДНУ доотправку 4056 перед 4025
        set_user(7, True, True)
        run(0x0052AE41, 7, 7, None)                          # OtherGate -> MarkSet(7) в памяти DLL
        sends = run_show(7, 301)
        # args = [a2=num, a3=op, a4=len, a5=body, a6=flag]
        s4056 = [c for c in sends if (c[3][1] & 0xFFFF) == 4056 and (c[3][2] & 0xFFFF) == 22
                 and (c[3][0] & 0xFFFF) == 7]
        s4025 = [c for c in sends if (c[3][1] & 0xFFFF) == 4025]
        ok(len(s4056) == 1 and len(s4025) == 1 and sends.index(s4056[0]) < sends.index(s4025[0]),
           "показ помеченного #7: свежий 4056 (22 б) соседям ПЕРЕД стоковым 4025")
        # контроль 1: тот же #7, но state=300 (скрытие, не показ) -> доотправки НЕТ, только 4025
        run(0x0052AE41, 7, 7, None)                          # снова пометить (MarkTake его снял)
        sends = run_show(7, 300)
        ok(not [c for c in sends if (c[3][1] & 0xFFFF) == 4056] and
           len([c for c in sends if (c[3][1] & 0xFFFF) == 4025]) == 1,
           "скрытие (state=300) #7: 4056 НЕ доотправляется, только стоковый 4025")
        # контроль 2: #9 никогда не помечался -> показ без доотправки
        sends = run_show(9, 301)
        ok(not [c for c in sends if (c[3][1] & 0xFFFF) == 4056] and
           len([c for c in sends if (c[3][1] & 0xFFFF) == 4025]) == 1,
           "показ НЕпомеченного #9: 4056 не доотправляется, только стоковый 4025")
        # МЕЛК-1: помеченный #7 показывается МЁРТВЫМ (HP=0) -> 4056 не шлём, пометку возвращаем;
        #   затем ожил (HP>0) -> при следующем показе доотправка идёт (пометка сохранилась).
        run(0x0052AE41, 7, 7, None)                          # пометить #7
        world["hp"] = 0
        sends = run_show(7, 301)
        ok(not [c for c in sends if (c[3][1] & 0xFFFF) == 4056] and
           len([c for c in sends if (c[3][1] & 0xFFFF) == 4025]) == 1,
           "показ МЁРТВОГО помеченного #7 (HP=0): «появление» 4056 НЕ шлётся, только стоковый 4025")
        world["hp"] = 0x77
        sends = run_show(7, 301)
        ok(len([c for c in sends if (c[3][1] & 0xFFFF) == 4056 and (c[3][0] & 0xFFFF) == 7]) == 1,
           "после оживления (HP>0) показ #7: пометка сохранилась -> свежий 4056 доотправлен")
    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
