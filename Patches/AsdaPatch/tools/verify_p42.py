# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p42.py — ЭМУЛЯТОРНАЯ проверка P42 (скрытый оператор — недопустимая цель боя игроков).
#
# Сервер локально не запускается (запрет). В unicorn грузятся НАСТОЯЩИЕ образы GameServer.exe
# и собранной AsdaPatch.dll (по предпочтительной базе). Каждый из 11 стабов P42 находится в DLL
# по УНИКАЛЬНОМУ косвенному `jmp dword ptr [X]`, где *X = адрес штатного reject/skip этой точки
# (стаб = от предыдущей добивки int3 до этого jmp). Функции GameServer, которые зовёт C-часть
# (GetUser 0x5324A0, IsOperatorIndex 0x52ECF0, Log 0x569DF0), подменяются перехватчиками.
# Для каждой точки — контрольные пары: цель СКРЫТА (и не сам исполнитель) -> стаб уходит в
# штатный reject/skip; цель НЕ скрыта -> стаб доигрывает вытесненные команды и уходит на resume;
# где применимо — цель == исполнитель -> resume (самоприменение не блокируется).
#
# ЗАПУСК: python verify_p42.py [AsdaPatch.dll] [GameServer.exe]
import os
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
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

GETUSER, ISOP, LOG = 0x005324A0, 0x0052ECF0, 0x00569DF0
OFF_HIDE = 0x3BC3B

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


_MD = Cs(CS_ARCH_X86, CS_MODE_32)


def find_stub(dimg, dbase, sig_hex, dest=None):
    """Начало стаба ищем по УНИКАЛЬНОЙ сигнатуре первых команд (голые функции упакованы без
    добивки 0xCC между собой, поэтому границы по 0xCC ненадёжны). Для двух пар с одинаковым
    прологом (C4/C5, C8/C9) уточняем по dest: у нужного стаба среди косвенных `jmp [X]` есть
    *X == dest."""
    sig = bytes.fromhex(sig_hex)
    n, L = len(dimg), len(sig)
    hits = [i for i in range(n - L) if dimg[i:i + L] == sig]
    if not hits:
        return None
    if len(hits) == 1 and dest is None:
        return dbase + hits[0]
    for h in hits:
        derefs = []
        for ins in _MD.disasm(bytes(dimg[h:h + 0x100]), dbase + h):
            if ins.mnemonic == "jmp" and ins.op_str.startswith("dword ptr ["):
                try:
                    ptr = int(ins.op_str.split("[")[1].rstrip("]"), 16)
                except ValueError:
                    continue
                off = ptr - dbase
                if 0 <= off + 4 <= n:
                    derefs.append(struct.unpack_from("<I", dimg, off)[0])
            if ins.mnemonic in ("ret", "int3"):
                break
        if dest is None or dest in derefs:
            return dbase + h
    return None


def main():
    dll = pefile.PE(DLL)
    exe = pefile.PE(EXE)
    dimg = dll.get_memory_mapped_image()
    dbase = dll.OPTIONAL_HEADER.ImageBase

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for pe in (exe, dll):
        base = pe.OPTIONAL_HEADER.ImageBase
        img = pe.get_memory_mapped_image()
        uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, img)
    uc.mem_map(0x00100000, 0x00100000)          # стек/фрейм
    GDT, TEB = 0x00060000, 0x00070000
    uc.mem_map(GDT, 0x1000)
    uc.mem_map(TEB, 0x1000)
    uc.mem_write(TEB, struct.pack("<I", 0xFFFFFFFF))

    def desc(b, lim, acc, fl):
        return struct.pack("<Q", (lim & 0xFFFF) | ((b & 0xFFFFFF) << 16) | (acc << 40)
                           | (((lim >> 16) & 0xF) << 48) | (fl << 52) | (((b >> 24) & 0xFF) << 56))
    gdt = b"\0" * 8 + desc(0, 0xFFFFF, 0x9A, 0xC) + desc(0, 0xFFFFF, 0x92, 0xC) + desc(TEB, 0xFFF, 0x92, 0x4)
    uc.mem_write(GDT, gdt)
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_FS, 3 << 3)
    for r in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
        uc.reg_write(r, 2 << 3)

    # мир: менеджер-цепочка, записи игроков
    MGR, THREAD, THISOBJ, USERS = 0x20000000, 0x20100000, 0x20200000, 0x21000000
    for a, sz in ((MGR, 0x1000), (THREAD, 0x1000), (THISOBJ, 0x1000), (USERS, 0x00800000)):
        uc.mem_map(a, sz)
    uc.mem_write(THISOBJ + 4, struct.pack("<I", THREAD))     # this->m_pcThread
    uc.mem_write(THREAD + 0x34, struct.pack("<I", MGR))      # thread->m_cUserMng
    USZ = 0x40000
    world = {"op": set()}

    def set_user(idx, op, hidden):
        (world["op"].add if op else world["op"].discard)(idx)
        uc.mem_write(USERS + USZ * idx + OFF_HIDE, struct.pack("<h", 300 if hidden else 301))

    def userptr(idx):
        return USERS + USZ * idx

    from unicorn.x86_const import UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI
    SENT = {UC_X86_REG_EBX: 0xB1B1B1B1, UC_X86_REG_ESI: 0x51515151, UC_X86_REG_EDI: 0xD1D1D1D1}
    ESP0 = 0x001F0000
    landed = {"eip": None, "eax": None, "esp": None, "regs": None}

    def stop_at(u, addr, size, _):
        landed["eip"] = addr
        landed["eax"] = u.reg_read(UC_X86_REG_EAX)
        landed["esp"] = u.reg_read(UC_X86_REG_ESP)
        landed["regs"] = {r: u.reg_read(r) for r in (UC_X86_REG_EBX, UC_X86_REG_ESI,
                                                     UC_X86_REG_EDI, UC_X86_REG_EBP)}
        u.emu_stop()

    def balanced(exp_ebp):
        # jmp-детур стек-нейтрален: ESP на посадке == ESP на входе; callee-saved целы
        return (landed["esp"] == ESP0 and landed["regs"] is not None
                and landed["regs"][UC_X86_REG_EBX] == SENT[UC_X86_REG_EBX]
                and landed["regs"][UC_X86_REG_ESI] == SENT[UC_X86_REG_ESI]
                and landed["regs"][UC_X86_REG_EDI] == SENT[UC_X86_REG_EDI]
                and landed["regs"][UC_X86_REG_EBP] == exp_ebp)

    def helper(u, addr, size, _):
        if addr not in (GETUSER, ISOP, LOG):
            return
        esp = u.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
        a = struct.unpack("<3I", u.mem_read(esp + 4, 12))
        if addr == GETUSER:                       # thiscall(mgr, idx) -> CUser*  (ret 4)
            idx = struct.unpack("<h", struct.pack("<H", a[0] & 0xFFFF))[0]
            rv = userptr(idx) if 0 <= idx < 32 else 0
            u.reg_write(UC_X86_REG_EAX, rv)
            u.reg_write(UC_X86_REG_ESP, esp + 4 + 4)
            u.reg_write(UC_X86_REG_EIP, ret)
        elif addr == ISOP:                        # thiscall(mgr, idx, -1) -> BOOL (ret 8)
            idx = struct.unpack("<h", struct.pack("<H", a[0] & 0xFFFF))[0]
            u.reg_write(UC_X86_REG_EAX, 1 if idx in world["op"] else 0)
            u.reg_write(UC_X86_REG_ESP, esp + 4 + 8)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:                                     # Log (cdecl) — сам чистит
            u.reg_write(UC_X86_REG_ESP, esp + 4)
            u.reg_write(UC_X86_REG_EIP, ret)

    uc.hook_add(UC_HOOK_CODE, helper)

    FRAME = 0x001E0000
    RET = 0x00123456                              # фиктивный возврат для C1

    def run(entry, dests, ecx=0):
        landed["eip"] = None
        landed["eax"] = None
        uc.reg_write(UC_X86_REG_ESP, 0x001F0000)
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ECX, ecx)
        hh = []
        for d in dests:
            hh.append(uc.hook_add(UC_HOOK_CODE, stop_at, begin=d, end=d))
        try:
            uc.emu_start(entry, 0, count=200000)
        except UcError as e:
            print("    сбой: %s EIP=%#x" % (e, uc.reg_read(UC_X86_REG_EIP)))
        finally:
            for h in hh:
                uc.hook_del(h)
        return landed["eip"]

    # ── C1: sub_556DB0 вход. ecx=mgr; стек [ret][a2][a3][a4]. reject=ret(RET,eax=0); resume=0x556DB6
    print("-- C1 sub_556DB0 (центральная проверка допустимости цели)")
    stub = find_stub(dimg, dbase, "5152500fbf442414")
    ok(stub is not None, "стаб C1 найден")
    if stub:
        def run_c1(a2, a3):
            uc.mem_write(0x001F0000 - 0x10, struct.pack("<IIII", RET, a2 & 0xFFFF, a3 & 0xFFFF, 0))
            landed["eip"] = None
            uc.reg_write(UC_X86_REG_ESP, 0x001F0000 - 0x10)
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ECX, MGR)
            for r, v in SENT.items():
                uc.reg_write(r, v)
            hh = [uc.hook_add(UC_HOOK_CODE, stop_at, begin=d, end=d) for d in (RET, 0x00556DB6)]
            try:
                uc.emu_start(stub, 0, count=200000)
            except UcError as e:
                print("    сбой C1: %s" % e)
            finally:
                [uc.hook_del(h) for h in hh]
            return landed["eip"], landed["eax"]
        set_user(5, True, True)                    # #5 скрытый оператор
        eip, eax = run_c1(3, 5)                     # атакующий #3 -> цель #5 (скрыт)
        ok(eip == RET and eax == 0, "скрытая цель #5 -> return 0 (недопустима)")
        set_user(5, True, False)
        eip, _ = run_c1(3, 5)
        ok(eip == 0x00556DB6, "нескрытая цель #5 -> стоковый пролог (допустима)")
        set_user(5, True, True)
        eip, _ = run_c1(5, 5)
        ok(eip == 0x00556DB6, "цель == сам исполнитель (#5) -> стоковый путь (самоприменение)")

        # ── баланс стека/регистров C1 на обеих ветках ──
        E = 0x001F0000 - 0x10                       # ESP на входе в sub_556DB0 ([ret][a2][a3][a4])
        def c1_callee_ok(exp_ebp):
            g = landed["regs"] or {}
            return (g.get(UC_X86_REG_EBX) == SENT[UC_X86_REG_EBX] and g.get(UC_X86_REG_ESI) == SENT[UC_X86_REG_ESI]
                    and g.get(UC_X86_REG_EDI) == SENT[UC_X86_REG_EDI] and g.get(UC_X86_REG_EBP) == exp_ebp)
        set_user(5, True, True)
        run_c1(3, 5)
        ok(landed["esp"] == E + 0x10 and c1_callee_ok(FRAME),
           "C1 reject: ret 0Ch снял адрес возврата и 3 аргумента (ESP = вход+0x10), EBX/ESI/EDI/EBP целы")
        set_user(5, True, False)
        run_c1(3, 5)
        saved_ebp = struct.unpack("<I", uc.mem_read(E - 4, 4))[0]
        ok(landed["esp"] == E - 4 - 0x1C and c1_callee_ok(E - 4) and saved_ebp == FRAME,
           "C1 resume: пролог доигран как сток (push ebp; mov ebp,esp; sub esp,1Ch), EBX/ESI/EDI целы")

    # ── общий раннер для «ByIdx через менеджер» и «ByUser» стабов на ebp-кадре ──
    def prep_frame(slots):
        uc.mem_write(FRAME - 0x600, b"\0" * 0xC00)
        for off, val in slots.items():
            a = FRAME + off if off < 0 else FRAME + off
            uc.mem_write(FRAME + off, struct.pack("<I", val & 0xFFFFFFFF))

    def run_stub(stub, dests, tag=None):
        landed["eip"] = None
        landed["esp"] = None
        landed["regs"] = None
        uc.reg_write(UC_X86_REG_ESP, ESP0)
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ECX, 0)
        for r, v in SENT.items():
            uc.reg_write(r, v)
        hh = [uc.hook_add(UC_HOOK_CODE, stop_at, begin=d, end=d) for d in dests]
        try:
            uc.emu_start(stub, 0, count=200000)
        except UcError as e:
            print("    сбой: %s EIP=%#x" % (e, uc.reg_read(UC_X86_REG_EIP)))
        finally:
            [uc.hook_del(h) for h in hh]
        if tag is not None:
            ok(balanced(FRAME), "%s: ESP и callee-saved (EBX/ESI/EDI/EBP) сбалансированы" % tag)
        return landed["eip"]

    def set_word(off, val):
        uc.mem_write(FRAME + off, struct.pack("<H", val & 0xFFFF))

    # ── C2: sub_471C70. this[ebp-0xE0], a2[ebp+8], a6a[ebp-0x24]. reject 0x471D3E / resume 0x471D1E
    print("-- C2 sub_471C70 (результат навыка игрока)")
    stub = find_stub(dimg, dbase, "608b8520ffffff")
    ok(stub is not None, "стаб C2 найден")
    if stub:
        def run_c2(caster, target):
            prep_frame({-0xE0: THISOBJ})
            set_word(8, caster)
            set_word(-0x24, target)
            return run_stub(stub, (0x00471D3E, 0x00471D1E), "C2")
        set_user(6, True, True)
        ok(run_c2(3, 6) == 0x00471D3E, "скрытая цель #6 -> reject (SEH-очистка + эпилог)")
        set_user(6, True, False)
        ok(run_c2(3, 6) == 0x00471D1E, "нескрытая цель #6 -> продолжение")
        set_user(6, True, True)
        ok(run_c2(6, 6) == 0x00471D1E, "цель == исполнитель -> продолжение (самоприменение)")

    # ── C3: sub_48FE40. this[ebp-0xC4], a2[ebp+8], a1[ebp-0x28]. reject 0x48FF2A / resume 0x48FF0A
    print("-- C3 sub_48FE40 (результат навыка стража)")
    stub = find_stub(dimg, dbase, "608b853cffffff")
    ok(stub is not None, "стаб C3 найден")
    if stub:
        def run_c3(caster, target):
            prep_frame({-0xC4: THISOBJ})
            set_word(8, caster)
            set_word(-0x28, target)
            return run_stub(stub, (0x0048FF2A, 0x0048FF0A), "C3")
        set_user(6, True, True)
        ok(run_c3(3, 6) == 0x0048FF2A, "скрытая цель #6 -> reject")
        set_user(6, True, False)
        ok(run_c3(3, 6) == 0x0048FF0A, "нескрытая цель #6 -> продолжение")

    # ── C4: sub_473360. a2[ebp+8], a3[ebp+0xC], CUser*[ebp-0x68]. reject/fall 0x473413 / jne 0x473427
    print("-- C4 sub_473360 (наложение состояния)")
    stub = find_stub(dimg, dbase, "600fbf4d080fbf550c8b4598", 0x00473413)
    ok(stub is not None, "стаб C4 найден")
    if stub:
        def run_c4(caster, target, hidden):
            prep_frame({-0x68: userptr(target)})
            set_word(8, caster)
            set_word(0xC, target)
            set_user(target, True, hidden)
            return run_stub(stub, (0x00473413, 0x00473427), "C4")
        ok(run_c4(3, 6, True) == 0x00473413, "скрытая цель #6 -> reject (dtor v26 + эпилог)")
        ok(run_c4(3, 6, False) == 0x00473427, "нескрытая цель #6 -> стоковое продолжение")
        ok(run_c4(6, 6, True) == 0x00473427, "цель == исполнитель -> продолжение (самоприменение)")

    # ── C5: sub_4913E0. a2[ebp+8], a7[ebp+0xC], CUser*[ebp-0x68]. reject 0x491493 / jne 0x4914A7
    print("-- C5 sub_4913E0 (состояние от стража)")
    stub = find_stub(dimg, dbase, "600fbf4d080fbf550c8b4598", 0x00491493)
    ok(stub is not None, "стаб C5 найден")
    if stub:
        def run_c5(caster, target, hidden):
            prep_frame({-0x68: userptr(target)})
            set_word(8, caster)
            set_word(0xC, target)
            set_user(target, True, hidden)
            return run_stub(stub, (0x00491493, 0x004914A7), "C5")
        ok(run_c5(3, 6, True) == 0x00491493, "скрытая цель #6 -> reject")
        ok(run_c5(3, 6, False) == 0x004914A7, "нескрытая цель #6 -> продолжение")

    # (C6/C7 УБРАНЫ по ревизии: члены площадного 925 = групповое ЛЕЧЕНИЕ, не атака — не блокируем)

    # ── C8: EXPLOSION_ARROW. eax=CUser* жертвы (флаг inline). skip 0x486BF9 / resume 0x486B2A
    print("-- C8 EXPLOSION_ARROW (разлёт стрелы)")
    stub = find_stub(dimg, dbase, "6681b83bbc03002c01", 0x00486BF9)
    ok(stub is not None, "стаб C8 найден")
    if stub:
        def run_c8(target, hidden):
            prep_frame({})
            set_user(target, True, hidden)
            landed["eip"] = None
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_EAX, userptr(target))
            for r, v in SENT.items():
                uc.reg_write(r, v)
            hh = [uc.hook_add(UC_HOOK_CODE, stop_at, begin=d, end=d) for d in (0x00486BF9, 0x00486B2A)]
            try:
                uc.emu_start(stub, 0, count=200000)
            except UcError as e:
                print("    сбой C8: %s" % e)
            finally:
                [uc.hook_del(h) for h in hh]
            return landed["eip"]
        ok(run_c8(7, True) == 0x00486BF9, "скрытая жертва #7 -> пропуск")
        ok(run_c8(7, False) == 0x00486B2A and balanced(FRAME), "нескрытая жертва #7 -> урон (стек/регистры целы)")

    # ── C9: GUARDIAN_AREA. eax=CUser*. skip 0x4873CC / resume 0x48720D
    print("-- C9 GUARDIAN_NORMAL_ATTACK_AREA (разлёт стража)")
    stub = find_stub(dimg, dbase, "6681b83bbc03002c01", 0x004873CC)
    ok(stub is not None, "стаб C9 найден")
    if stub:
        def run_c9(target, hidden):
            prep_frame({})
            set_user(target, True, hidden)
            landed["eip"] = None
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_EAX, userptr(target))
            for r, v in SENT.items():
                uc.reg_write(r, v)
            hh = [uc.hook_add(UC_HOOK_CODE, stop_at, begin=d, end=d) for d in (0x004873CC, 0x0048720D)]
            try:
                uc.emu_start(stub, 0, count=200000)
            except UcError as e:
                print("    сбой C9: %s" % e)
            finally:
                [uc.hook_del(h) for h in hh]
            return landed["eip"]
        ok(run_c9(7, True) == 0x004873CC, "скрытая жертва #7 -> пропуск")
        ok(run_c9(7, False) == 0x0048720D and balanced(FRAME), "нескрытая жертва #7 -> урон (стек/регистры целы)")

    # ── C10: sub_426B00 перенос на соулмейта. this[ebp-0x138], soulmate[ebp-0x54]; обе ветки -> 0x42797A.
    #    отличаем по записи [ebp-0x14]: скрыт -> НЕ записан (перенос отменён), не скрыт -> записан.
    print("-- C10 sub_426B00 (перенос урона на соулмейта)")
    stub = find_stub(dimg, dbase, "608b85c8feffff")
    ok(stub is not None, "стаб C10 найден")
    if stub:
        def run_c10(soulmate, hidden):
            prep_frame({-0x138: THISOBJ})
            set_word(-0x54, soulmate)
            set_word(-0x14, 0xAAAA)                 # сентинел
            set_user(soulmate, True, hidden)
            run_stub(stub, (0x0042797A,), "C10")
            return struct.unpack("<H", uc.mem_read(FRAME - 0x14, 2))[0]
        ok(run_c10(8, True) == 0xAAAA, "скрытый партнёр #8 -> перенос ОТМЕНЁН ([ebp-0x14] не тронут)")
        ok(run_c10(8, False) == 8, "нескрытый партнёр #8 -> перенос выполнен ([ebp-0x14]=#8)")

    # ── C11: sub_49DDA0 цель соулмейт-навыка. target[ebp-0x10], CUser*[ebp-0x1c]. skip 0x49DDD3 / resume 0x49DE70
    print("-- C11 sub_49DDA0 (цели навыка соулмейта)")
    stub = find_stub(dimg, dbase, "600fbf55f0")
    ok(stub is not None, "стаб C11 найден")
    if stub:
        def run_c11(target, hidden):
            prep_frame({-0x1C: userptr(target)})
            set_word(-0x10, target)
            set_word(0x14, 5)                       # [ebp+0x14] для movsx/cmp
            set_user(target, True, hidden)
            return run_stub(stub, (0x0049DDD3, 0x0049DE70), "C11")
        ok(run_c11(7, True) == 0x0049DDD3, "скрытая цель #7 -> пропуск (continue)")
        ok(run_c11(7, False) == 0x0049DE70, "нескрытая цель #7 -> обработка")

    # ── C12: sub_555800 перенос на соулмейта (удар игрока). this[ebp-0x140], партнёр[ebp-0x11c];
    #    обе ветки -> 0x556797, отличаем по записи цели [ebp-0x50].
    print("-- C12 sub_555800 (перенос урона на соулмейта, удар ИГРОКА) [СРЕДН-2]")
    stub = find_stub(dimg, dbase, "608b85c0feffff")   # pushad; mov eax,[ebp-0x140]
    ok(stub is not None, "стаб C12 найден")
    if stub:
        def run_c12(soulmate, hidden):
            prep_frame({-0x140: THISOBJ})
            set_word(-0x11c, soulmate)
            set_word(-0x50, 0xAAAA)
            set_user(soulmate, True, hidden)
            run_stub(stub, (0x00556797,), "C12")
            return struct.unpack("<H", uc.mem_read(FRAME - 0x50, 2))[0]
        ok(run_c12(8, True) == 0xAAAA, "скрытый партнёр #8 -> перенос ОТМЕНЁН ([ebp-0x50] не тронут)")
        ok(run_c12(8, False) == 8, "нескрытый партнёр #8 -> перенос выполнен ([ebp-0x50]=#8)")

    # ── C13: sub_4839D0 перенос на соулмейта (навык монстра). this[ebp-0x48], партнёр[ebp-0x14];
    #    обе ветки -> 0x483C45, отличаем по записи цели [ebp-0x20].
    print("-- C13 sub_4839D0 (перенос урона на соулмейта, навык монстра) [СРЕДН-2]")
    stub = find_stub(dimg, dbase, "608b45b8")          # pushad; mov eax,[ebp-0x48]
    ok(stub is not None, "стаб C13 найден")
    if stub:
        def run_c13(soulmate, hidden):
            prep_frame({-0x48: THISOBJ})
            set_word(-0x14, soulmate)
            set_word(-0x20, 0xAAAA)
            set_user(soulmate, True, hidden)
            run_stub(stub, (0x00483C45,), "C13")
            return struct.unpack("<H", uc.mem_read(FRAME - 0x20, 2))[0]
        ok(run_c13(8, True) == 0xAAAA, "скрытый партнёр #8 -> перенос ОТМЕНЁН ([ebp-0x20] не тронут)")
        ok(run_c13(8, False) == 8, "нескрытый партнёр #8 -> перенос выполнен ([ebp-0x20]=#8)")

    # ── КОНТРОЛЬНАЯ ПАРА для сверки баланса (проверка не слепа) ──
    #   синтетические стабы в свободной странице: «push eax; jmp dest» (оставляет 4 байта в стеке,
    #   как прежние C6/C7) — сверка ОБЯЗАНА провалиться; «nop; jmp dest» — пройти.
    print("-- контроль сверки баланса: синтетический несбалансированный / сбалансированный стаб")
    SYN, DEST = 0x00180000, 0x00180100
    def syn(at, code):                               # разные адреса — без повторного использования TB-кэша
        uc.mem_write(at, code + bytes([0xE9]) + struct.pack("<i", DEST - (at + len(code) + 5)))
        prep_frame({})
        run_stub(at, (DEST,))
        return landed["eip"] == DEST, balanced(FRAME)
    hit, bal = syn(SYN, bytes([0x50]))                   # push eax
    ok(hit and not bal, "несбалансированный стаб (push eax; jmp): сверка баланса ПРОВАЛИВАЕТСЯ, как и должна")
    hit, bal = syn(SYN + 0x200, bytes([0x90]))           # nop
    ok(hit and bal, "сбалансированный стаб (nop; jmp): сверка баланса проходит")

    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
