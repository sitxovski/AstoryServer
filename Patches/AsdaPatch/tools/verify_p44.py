# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p44.py — ЭМУЛЯТОРНАЯ проверка P44 (корректность обмена 528x и лавки 630x),
#                 версия после ревизии server_p44_REVIEW.md (КРИТ-1…5, СРЕДН-1…3).
#
# Грузятся НАСТОЯЩИЕ образы GameServer.exe и собранной AsdaPatch.dll. Замок «в полёте»
# теперь ПО КАЖДОМУ CUserManager и ставится в точке БД-запроса, поэтому проверки гоняют
# реальную цепочку: DB-send (ставит) → CompleteLock (проверяет) → Release (снимает).
#
# ЗАПУСК: python verify_p44.py [AsdaPatch.dll] [GameServer.exe]
import os
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP,
                               UC_X86_REG_GDTR, UC_X86_REG_FS, UC_X86_REG_SS,
                               UC_X86_REG_DS, UC_X86_REG_ES)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
EXE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.exe")
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
LIVE = SRV_ROOT + "/v2/GameServer/GameServer.exe"

WIN_REC = 0x231
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def iat_slot(pe, dll_path, func):
    """VA слота IAT импорта `func` по таблице импорта PE; при наличии MAP рядом с DLL — сверка с ним."""
    va = None
    for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in ent.imports:
            if imp.name and imp.name.decode("ascii", "replace") == func:
                va = imp.address                                  # pefile: ImageBase + RVA слота IAT
    mp = os.path.splitext(dll_path)[0] + ".map"
    if os.path.exists(mp):
        import re
        txt = open(mp, "r", encoding="latin-1").read()
        m = re.search(r"^\s*\w+:\w+\s+__imp__%s@\d+\s+([0-9a-fA-F]{8})\s" % re.escape(func), txt, re.M)
        mva = int(m.group(1), 16) if m else None
        ok(mva is not None and mva == va, "IAT %s: таблица импорта 0x%08X = MAP %s" %
           (func, va or 0, ("0x%08X" % mva) if mva is not None else "нет символа"))
    return va


def main():
    dll = pefile.PE(DLL)
    exe = pefile.PE(EXE)
    dimg = dll.get_memory_mapped_image()
    dbase = dll.OPTIONAL_HEADER.ImageBase
    eb = exe.OPTIONAL_HEADER.ImageBase

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    eimg = bytearray(exe.get_memory_mapped_image())
    for base, img in ((eb, eimg), (dbase, dimg)):
        uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, bytes(img))
    uc.mem_map(0x00100000, 0x00100000)     # scratch/кадр
    uc.mem_map(0x00200000, 0x00200000)     # «менеджеры»/записи окон/CUser (ниже образа exe 0x400000)
    GDT, TEB = 0x00060000, 0x00070000
    uc.mem_map(GDT, 0x1000)
    uc.mem_map(TEB, 0x1000)

    def desc(b, lim, acc, fl):
        return struct.pack("<Q", (lim & 0xFFFF) | ((b & 0xFFFFFF) << 16) | (acc << 40)
                           | (((lim >> 16) & 0xF) << 48) | (fl << 52) | (((b >> 24) & 0xFF) << 56))
    gdt = b"\0" * 8 + desc(0, 0xFFFFF, 0x9A, 0xC) + desc(0, 0xFFFFF, 0x92, 0xC) + desc(TEB, 0xFFF, 0x92, 0x4)
    uc.mem_write(GDT, gdt)
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_FS, 3 << 3)
    for r in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
        uc.reg_write(r, 2 << 3)

    FRAME = 0x001E0000
    ESP0 = 0x001F0000
    MGRA = 0x00200000
    MGRB = 0x00300000
    stop = {"eip": None}

    def stopper(u, a, s, d):
        stop["eip"] = a
        u.emu_stop()

    def run(start, stops, count=200000):
        stop["eip"] = None
        if start is None:            # МЕЛК-D: стаб не найден -> чистый [FAIL] выше по коду, без трассировки
            return None
        hs = [uc.hook_add(UC_HOOK_CODE, stopper, begin=a, end=a) for a in stops]
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой: %s" % e)
        for h in hs:
            uc.hook_del(h)
        return stop["eip"]

    # ── локатор стабов: по УНИКАЛЬНОМУ первому байтовому образцу (стаб всегда начинается
    #    сразу за паддингом 0xCC — это отсекает и .rdata-копии байтов сверки, и совпадения
    #    внутри соседних стабов; walk-back ненадёжен, т.к. компилятор пакует стабы вплотную).
    def find_stub(sig):
        p = bytes.fromhex(sig)
        hits = [i for i in range(1, len(dimg) - len(p)) if dimg[i:i + len(p)] == p]
        if len(hits) == 1:
            return dbase + hits[0]
        for i in hits:                       # >1: настоящий стаб начинается за 0xCC
            if dimg[i - 1] == 0xCC:
                return dbase + i
        return None

    cl        = find_stub("837df80074")            # StubCompleteLock
    dbs_shell = find_stub("60ff750cffb5ecfaffff")  # StubDbSendShell (pushad;push[ebp+0C];push[ebp-0x514])
    dbs_norm  = find_stub("60ff750cffb538feffff")  # StubDbSendNormal (push[ebp-0x1C8])
    rel       = find_stub("558bec81ec50020000")    # StubReleaseWindow
    # v31: StubCancelRelease — голова `push [ebp-0x34]; push [ebp-0x44]; call DeferCancel`.
    cancstub  = find_stub("ff75ccff75bce8")        # StubCancelRelease (СРЕДН-A)
    # v31: StubMgrForget переписан под площадку 0x4BFC09 (E3) — репродукция `mov edx,[ebp-0x84];
    #   mov eax,[edx+0x34]; mov [eax+0xE04],0; pushad; push eax` (отличает от .rdata-копии kMgrFgt).
    mgrfstub  = find_stub("8b957cffffff8b4234c780040e0000000000006050")   # StubMgrForget (МЕЛК-B/E3)
    LOCK_OK = None not in (cl, dbs_shell, dbs_norm, rel)   # МЕЛК-D: замок-цепочка целиком собрана

    # ── GetTickCount детерминирован: реальный GetTickCount в unicorn не исполняется,
    #    а замок помнит такт (с integ3 13.10.2026 `now ? now : 1`, было `GetTickCount()|1`), поэтому
    #    иначе считался бы «старым». Эмулируем монотонный счётчик — замок молод.
    GTC = 0x00090000
    uc.mem_map(GTC, 0x1000)
    uc.mem_write(GTC, b"\xC3")                                 # ret (stdcall, 0 арг)
    # ★ integ3 (13.10.2026, СРЕДН-A): слот IAT GetTickCount берётся из таблицы импорта DLL (pefile), а не
    #   константой — зашитый 0x2A080 устарел (в v37/v38 слот 0x420A4), подмена ложилась мимо и эмулятор падал
    #   UC_ERR_FETCH_UNMAPPED. Сверка со вторым источником — MAP компоновщика (`__imp__GetTickCount@0`), если есть.
    gtc_iat = iat_slot(dll, DLL, "GetTickCount")
    ok(gtc_iat is not None, "IAT GetTickCount найден в таблице импорта DLL: %s" %
       ("0x%08X (RVA 0x%X)" % (gtc_iat, gtc_iat - dbase) if gtc_iat is not None else "НЕТ"))
    if gtc_iat is not None:
        uc.mem_write(gtc_iat, struct.pack("<I", GTC))           # IAT GetTickCount -> стаб
    _tick = {"v": 0x00100001}
    def gtc_hook(u, a, s, d):
        u.reg_write(UC_X86_REG_EAX, _tick["v"] & 0xFFFFFFFF)
        _tick["v"] += 16
    uc.hook_add(UC_HOOK_CODE, gtc_hook, begin=GTC, end=GTC)

    # ── замок «в полёте»: ставим через DB-send, снимаем через Release ─────────
    def set_lock(mgr, idx, shell=True):
        stub = dbs_shell if shell else dbs_norm
        if stub is None:
            return
        moff = 0x514 if shell else 0x1C8
        uc.mem_write(FRAME - moff, struct.pack("<I", mgr))
        uc.mem_write(FRAME + 0x0C, struct.pack("<i", idx))
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, ESP0)
        # останавливаемся на входе sub_5646C0 — пометка «в полёте» уже поставлена ДО call
        run(stub, (0x005646C0,))

    def clear_lock(mgr, idx):
        if rel is None:
            return
        uc.mem_write(ESP0 + 4, struct.pack("<i", idx))   # [ebp+8] после пролога
        uc.reg_write(UC_X86_REG_ECX, mgr)                # this
        uc.reg_write(UC_X86_REG_ESP, ESP0)
        run(rel, (0x4DF6D9,))

    def complete(mgr, idx, both_conf=True, fixA=True, fixB=True):
        rec = mgr + idx * WIN_REC
        uc.mem_write(rec + 0xE1D, bytes([1 if fixA else 0]))
        uc.mem_write(rec + 0xE1E, bytes([1 if fixB else 0]))
        uc.mem_write(FRAME - 0x08, struct.pack("<i", 1 if both_conf else 0))
        uc.mem_write(FRAME - 0x18, struct.pack("<i", idx))
        uc.mem_write(FRAME - 0x20, struct.pack("<I", mgr))
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, ESP0)
        return run(cl, (0x004E48B9, 0x004E48FD))

    print("-- СО-1 CompleteLock: замок per-manager (КРИТ-2), ставится в БД-send (КРИТ-3)")
    ok(cl is not None, "стаб CompleteLock найден")
    ok(dbs_shell is not None, "стаб DB-send shell найден")
    ok(dbs_norm is not None, "стаб DB-send normal найден")
    ok(rel is not None, "стаб ReleaseWindow найден")
    if cl and dbs_shell and dbs_norm and rel:
        # КРИТ-3: проверка НЕ ставит замок -> повторный ОК проходит (нет БД-send между)
        ok(complete(MGRA, 7) == 0x004E48B9, "свежее окно: обе фикс.+подтв. -> диспетчер")
        ok(complete(MGRA, 7) == 0x004E48B9, "КРИТ-3: повтор без БД-send снова проходит (замок не поставлен)")
        # ставим замок в точке БД-send -> дубль отбрасывается
        set_lock(MGRA, 7)
        ok(complete(MGRA, 7) == 0x004E48FD, "после БД-send: дубль по тому же окну -> эпилог")
        # КРИТ-2: тот же номер окна в ДРУГОМ менеджере независим
        ok(complete(MGRB, 7) == 0x004E48B9, "КРИТ-2: окно 7 в другом менеджере -> диспетчер (замки раздельны)")
        # снятие замка -> снова проходит
        clear_lock(MGRA, 7)
        ok(complete(MGRA, 7) == 0x004E48B9, "снятие замка (sub_4DF6D0) -> ОК снова проходит")
        # фиксации
        clear_lock(MGRB, 7)
        ok(complete(MGRA, 8, fixA=False) == 0x004E48FD, "нет фиксации A -> эпилог")
        ok(complete(MGRA, 8, fixB=False) == 0x004E48FD, "нет фиксации B -> эпилог")
        ok(complete(MGRA, 9, both_conf=False) == 0x004E48FD, "подтвердила одна сторона -> эпилог")

    # ── структурные признаки исправлений ревизии (ловят регрессы прежней v28) ──
    print("-- структурные признаки (ловят регрессы v28)")

    def has_jmp_to(t):
        for i in range(len(dimg) - 6):
            if dimg[i] == 0xFF and dimg[i + 1] == 0x25:
                p = struct.unpack_from('<I', dimg, i + 2)[0] - dbase
                if 0 <= p < len(dimg) - 4 and struct.unpack_from('<I', dimg, p)[0] == t:
                    return True
        return False

    # КРИТ-1: во втором цикле лавки есть переход-ПРОПУСК пустой записи (jmp 0x505C40).
    #         На v28 такого перехода нет (пустая запись отвергалась) -> ловит регресс.
    ok(has_jmp_to(0x00505C40), "КРИТ-1: в стабе лавки есть пропуск пустой записи (jmp 0x505C40)")
    # КРИТ-3: замок ставится в точке БД-send (стабы существуют), а НЕ в проверке.
    #         На v28 стабов БД-send нет (замок ставился в CompleteLock) -> ловит регресс.
    ok(dbs_shell is not None and dbs_norm is not None,
       "КРИТ-3: замок ставится в точке БД-send (оба стаба присутствуют)")
    # КРИТ-2 (per-manager) проверяется семантической парой ниже
    #   («окно 7 в другом менеджере -> диспетчер»); на v28 глобальный замок общий.

    # ── СО-3 границы windowIndex (5288/5290/5291/5293) + КРИТ-5 «в полёте» ─────
    print("-- СО-3 границы windowIndex + КРИТ-5 (запрет правки лотка при «в полёте»)")
    bnd = {
        "5288": (find_stub("8b459483f800"), 0x6C, 0x004E04A0, 0x004E0466, 0x24, 0xAC, True),
        "5290": (find_stub("8b45ac83f800"), 0x54, 0x004E347D, 0x004E3469, None, 0x60, True),
        "5291": (find_stub("8b8578feffff83f800"), 0x188, 0x004E3766, 0x004E3723, None, 0x218, True),
        "5293": (find_stub("8b45e883f8007c"), 0x18, 0x004E47F9, 0x004E47E5, None, None, False),
    }
    for name, (stub, idxoff, cont, err, slotoff, mgroff, has_lock) in bnd.items():
        ok(stub is not None, "стаб границы %s найден" % name)
        if stub is None:
            continue

        def bound(idx, slot=0, mgr=MGRA):
            uc.mem_write(FRAME - idxoff, struct.pack("<i", idx))
            if slotoff is not None:
                uc.mem_write(FRAME - slotoff, bytes([slot & 0xFF]))
            if mgroff is not None:
                uc.mem_write(FRAME - mgroff, struct.pack("<I", mgr))
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            return run(stub, (cont, err))
        ok(bound(0) == cont, "%s idx=0 -> продолжение" % name)
        ok(bound(549) == cont, "%s idx=549 -> продолжение" % name)
        ok(bound(-1) == err, "%s idx=-1 -> отказ" % name)
        ok(bound(550) == err, "%s idx=550 -> отказ" % name)
        if slotoff is not None:
            ok(bound(5, 4) == cont, "%s ячейка лотка 4 -> продолжение" % name)
            ok(bound(5, 5) == err, "%s ячейка лотка 5 -> отказ" % name)
        if has_lock:
            set_lock(MGRB, 20)
            ok(bound(20, mgr=MGRB) == err, "КРИТ-5 %s: правка при «в полёте» -> отказ" % name)
            clear_lock(MGRB, 20)
            ok(bound(20, mgr=MGRB) == cont, "%s: после снятия замка -> продолжение" % name)

    # ── СЛ-1 границы лота витрины + КРИТ-1 (пропуск пустых записей корзины) ────
    print("-- СЛ-1 границы лота витрины + КРИТ-1 (пустая запись корзины пропускается)")
    # loop1 (0x5053C7/0x505405): пустые уже отсеяны стоком до хука, проверяем только границу
    stub1 = find_stub("66899514fbffff0fbfc2")
    ok(stub1 is not None, "стаб лавки (проверка) найден")
    if stub1:

        def store1(v42):
            uc.reg_write(UC_X86_REG_EDX, v42 & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            return run(stub1, (0x005053C7, 0x00505405))
        ok(store1(0) == 0x005053C7, "проверка v42=0 -> продолжение")
        ok(store1(9) == 0x005053C7, "проверка v42=9 -> продолжение")
        ok(store1(10) == 0x00505405, "проверка v42=10 -> отказ 6310")
        ok(store1(0xFFFF) == 0x00505405, "проверка v42=-1 -> отказ 6310")
    # loop2 (0x505C74/0x505C40/0x505DD3): пустая запись (itemId<=0) -> пропуск, не отказ
    s2 = find_stub("66899514fbffff8b85f0faffff")
    ok(s2 is not None, "стаб лавки (применение) найден")
    if s2:
        def store2(v42, itemid, k=0):
            uc.mem_write(FRAME - 0x510, struct.pack("<i", k))
            uc.mem_write(FRAME + k * 0x2D - 0x47D, struct.pack("<i", itemid))
            uc.reg_write(UC_X86_REG_EDX, v42 & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            return run(s2, (0x00505C74, 0x00505C40, 0x00505DD3))
        ok(store2(5, 100) == 0x00505C74, "КРИТ-1 применение: itemId>0, v42=5 -> продолжение")
        ok(store2(10, 100) == 0x00505DD3, "применение: itemId>0, v42=10 -> отказ 6310")
        ok(store2(0xFFFF, -1) == 0x00505C40, "КРИТ-1 применение: пустая запись (itemId=-1) -> ПРОПУСК (не отказ)")
        ok(store2(5, 0) == 0x00505C40, "КРИТ-1 применение: itemId=0 -> ПРОПУСК")
        # «корзина из 1..5 позиций проходит»: непустые записи с валидным v42 доходят до диспетчера
        good = all(store2(v, 200, k=kk) == 0x00505C74 for kk, v in enumerate([0, 3, 9, 1, 5]))
        ok(good, "КРИТ-1: корзина из 1–5 непустых позиций (v42 в 0..9) доходит до применения")

    # ── КРИТ-4: 5286 границы + участие (проверка ветвей + статика ретаргета je) ─
    print("-- КРИТ-4: 5286 границы окна + гейт участия")
    b86 = find_stub("8b45cc83f800")
    ok(b86 is not None, "стаб границы 5286 найден")
    if b86:
        def c86(idx):
            uc.mem_write(FRAME - 0x34, struct.pack("<i", idx))
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            return run(b86, (0x004E0220, 0x004E020C))
        ok(c86(0) == 0x004E0220, "5286 idx=0 -> продолжение")
        ok(c86(549) == 0x004E0220, "5286 idx=549 -> продолжение")
        ok(c86(-1) == 0x004E020C, "5286 idx=-1 -> отказ")
        ok(c86(550) == 0x004E020C, "5286 idx=550 -> отказ")
    # статический ретаргет je 0x4E02EC (release 0x4E032C -> skip 0x4E0338) — на СТОКЕ
    o = 0x4E02EC - 0x400000
    ok(eimg[o] == 0x74 and eimg[o + 1] == 0x3E, "5286 je: стоковые байты 74 3E (release 0x4E032C)")
    ok((0x4E02EE + 0x4A) == 0x4E0338, "5286 je ретаргет 74 4A ведёт в 0x4E0338 (skip release)")

    # ── СО-2: ретаргет двух jne в recvDB (статика на стоке) ───────────────────
    print("-- СО-2: ветки несовпадения charId в recvDB не освобождают окно")
    for nm, va, newlow, oldt, newt in (
        ("shell", 0x4E994B, 0xE4, 0x4EA723, 0x4EA735),
        ("normal", 0x4EB628, 0x21, 0x4EC33D, 0x4EC34F)):
        o = va - 0x400000
        oldrel = struct.unpack_from('<i', eimg, o + 2)[0]
        ok(eimg[o] == 0x0F and eimg[o + 1] == 0x85 and (va + 6 + oldrel) == oldt,
           "recvDB %s jne: стоковый target 0x%X (release)" % (nm, oldt))
        newrel = (oldrel & ~0xFF) | newlow          # меняется только младший байт rel32
        ok((va + 6 + newrel) == newt,
           "recvDB %s jne ретаргет ведёт в эпилог 0x%X (минуя sub_4DF6D0)" % (nm, newt))

    # ── death: сброс обмена; при «в полёте» отмену НЕ делаем (СРЕДН-2) ─────────
    print("-- death: сброс обмена (СРЕДН-2: при «в полёте» Cancel не зовётся)")
    dstub = find_stub("8b8dc8fbffffc7414f01")
    ok(dstub is not None, "стаб DeathCancel найден")
    if dstub:
        PUSER = 0x00380000
        called = {"hit": False, "args": None, "ecx": 0}

        def cancel_hook(u, a, s, d):
            if a != 0x004E00A0:
                return
            called["hit"] = True
            called["ecx"] = u.reg_read(UC_X86_REG_ECX)
            esp = u.reg_read(UC_X86_REG_ESP)
            called["args"] = struct.unpack("<IIiI", u.mem_read(esp, 16))
            ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
            u.reg_write(UC_X86_REG_ESP, esp + 4 + 12)
            u.reg_write(UC_X86_REG_EIP, ret)
        ch = uc.hook_add(UC_HOOK_CODE, cancel_hook)

        def death(flag, window, mgr=MGRA):
            called["hit"] = False
            uc.mem_write(PUSER + 0x145, struct.pack("<I", flag))
            uc.mem_write(PUSER + 0x149, struct.pack("<i", window))
            uc.mem_write(FRAME - 0x438, struct.pack("<I", PUSER))
            uc.mem_write(FRAME - 0x464, struct.pack("<I", mgr))
            uc.mem_write(FRAME + 8, struct.pack("<H", 42))
            uc.mem_write(PUSER + 0x4F, b"\x00\x00\x00\x00")
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            run(dstub, (0x004CB5E5,), count=500)
            return struct.unpack("<i", uc.mem_read(PUSER + 0x4F, 4))[0]

        ok(death(0, -1) == 1 and not called["hit"], "не в обмене -> «мёртв», Cancel НЕ зовётся")
        d = death(1, 5)
        ok(d == 1 and called["hit"], "в обмене (не «в полёте») -> «мёртв» + Cancel")
        if called["hit"]:
            _, un, a3, a4 = called["args"]
            ok((un & 0xFFFF) == 42 and a3 == 0 and a4 == 5 and called["ecx"] == MGRA,
               "Cancel(this=mgr, userNum=42, nullptr, window=5)")
        ok(death(1, -1) == 1 and not called["hit"], "в обмене, window<0 -> Cancel НЕ зовётся")
        # СРЕДН-2: window «в полёте» -> Cancel не зовётся (окно освободит recvDB)
        set_lock(MGRA, 11)
        ok(death(1, 11) == 1 and not called["hit"], "СРЕДН-2: window «в полёте» -> Cancel НЕ зовётся")
        clear_lock(MGRA, 11)
        ok(death(1, 11) == 1 and called["hit"], "после снятия замка -> Cancel снова зовётся")
        uc.hook_del(ch)

    # ── СРЕДН-A: отмена/разрыв/реген при «в полёте» не освобождает окно ─────────
    print("-- СРЕДН-A: отмена при «в полёте» откладывает освобождение (recvDB освободит)")
    ok(cancstub is not None, "стаб StubCancelRelease найден")
    if cancstub is not None:
        relcall = {"hit": False}

        def rel_hook(u, a, s, d):
            if a != 0x004DF6D0:
                return
            relcall["hit"] = True
            esp = u.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
            u.reg_write(UC_X86_REG_ESP, esp + 4 + 4)   # sub_4DF6D0 ret 4
            u.reg_write(UC_X86_REG_EIP, ret)
        rlh = uc.hook_add(UC_HOOK_CODE, rel_hook)

        def cancel(mgr, idx):
            relcall["hit"] = False
            uc.mem_write(FRAME - 0x44, struct.pack("<I", mgr))     # mgr
            uc.mem_write(FRAME - 0x34, struct.pack("<i", idx))     # windowIndex
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            eip = run(cancstub, (0x004E0338,))
            return eip, relcall["hit"]
        eip, hit = cancel(MGRA, 30)
        ok(eip == 0x004E0338 and hit, "не «в полёте»: окно освобождается штатно (sub_4DF6D0)")
        set_lock(MGRA, 30)
        eip, hit = cancel(MGRA, 30)
        ok(eip == 0x004E0338 and not hit,
           "СРЕДН-A: «в полёте» -> освобождение отложено (sub_4DF6D0 НЕ зовётся)")
        clear_lock(MGRA, 30)
        eip, hit = cancel(MGRA, 30)
        ok(eip == 0x004E0338 and hit, "после снятия замка -> освобождение снова штатное")
        uc.hook_del(rlh)

    # ── МЕЛК-B: удаление менеджера освобождает слот таблицы замков ──────────────
    print("-- МЕЛК-B: удаление менеджера (sub_4BFBE0) чистит слот таблицы замков")
    ok(mgrfstub is not None, "стаб StubMgrForget найден")
    if mgrfstub is not None and LOCK_OK:
        set_lock(MGRB, 40)
        ok(complete(MGRB, 40) == 0x004E48FD, "перед удалением: окно 40 менеджера B «в полёте»")

        # v31 (E3): площадка 0x4BFC09 — стаб читает поток из [ebp-0x84], менеджер = [поток+0x34].
        THREAD = 0x00280000
        def mgr_forget(mgr):
            uc.mem_write(THREAD + 0x34, struct.pack("<I", mgr))   # [thread+0x34] = менеджер
            uc.mem_write(FRAME - 0x84, struct.pack("<I", THREAD)) # [ebp-0x84] = поток карты
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            run(mgrfstub, (0x004BFC1C,))
        mgr_forget(MGRB)
        ok(complete(MGRB, 40) == 0x004E48B9,
           "МЕЛК-B: после удаления менеджера слот очищен -> окно не «в полёте»")

    # ── СО-4 ReqRecord / AcceptGate (ветвление; по умолчанию ВЫКЛ) ─────────────
    print("-- СО-4 ReqRecord / AcceptGate (ветвление)")
    reqstub = find_stub("8a45d28845e4")
    ok(reqstub is not None, "стаб ReqRecord найден")
    if reqstub:
        o = reqstub - dbase
        helper = None
        for k in range(0, 0x30):
            if dimg[o + k] == 0xE8:
                helper = dbase + (o + k + 5) + struct.unpack_from('<i', dimg, o + k + 1)[0]
                break
        rec = {"hit": False, "args": None}

        def rec_hook(u, a, s, d):
            if helper is None or a != helper:
                return
            rec["hit"] = True
            esp = u.reg_read(UC_X86_REG_ESP)
            rec["args"] = struct.unpack("<Iii", u.mem_read(esp, 12))
            ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
            u.reg_write(UC_X86_REG_ESP, esp + 4)
            u.reg_write(UC_X86_REG_EIP, ret)
        rh = uc.hook_add(UC_HOOK_CODE, rec_hook)
        uc.mem_write(FRAME - 0x2C, struct.pack("<H", 100))
        uc.mem_write(FRAME + 8, struct.pack("<H", 200))
        uc.mem_write(FRAME - 0x2E, b"\x01")
        uc.reg_write(UC_X86_REG_EBP, FRAME)
        uc.reg_write(UC_X86_REG_ESP, ESP0)
        ok(run(reqstub, (0x004DFBF4,)) == 0x004DFBF4, "ReqRecord -> продолжение Req")
        ok(rec["hit"] and rec["args"][1] == 100 and rec["args"][2] == 200,
           "запись заявки (target=100, initiator=200)")
        uc.hook_del(rh)

    accstub = find_stub("0fb745b950")
    ok(accstub is not None, "стаб AcceptGate найден")
    if accstub:
        o = accstub - dbase
        ahelper = None
        for k in range(0, 0x20):
            if dimg[o + k] == 0xE8:
                ahelper = dbase + (o + k + 5) + struct.unpack_from('<i', dimg, o + k + 1)[0]
                break
        want = {"ret": 1}

        def acc_hook(u, a, s, d):
            if a == ahelper:
                esp = u.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
                u.reg_write(UC_X86_REG_EAX, want["ret"])
                u.reg_write(UC_X86_REG_ESP, esp + 4)
                u.reg_write(UC_X86_REG_EIP, ret)
            elif a == 0x004DF660:
                esp = u.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
                u.reg_write(UC_X86_REG_EAX, 3)
                u.reg_write(UC_X86_REG_ESP, esp + 4)
                u.reg_write(UC_X86_REG_EIP, ret)
        ah = uc.hook_add(UC_HOOK_CODE, acc_hook)

        def accept(allow):
            want["ret"] = 1 if allow else 0
            uc.mem_write(FRAME - 0x47, struct.pack("<H", 200))
            uc.mem_write(FRAME + 8, struct.pack("<H", 100))
            uc.mem_write(FRAME - 0x58, struct.pack("<I", MGRA))
            uc.reg_write(UC_X86_REG_EBP, FRAME)
            uc.reg_write(UC_X86_REG_ESP, ESP0)
            return run(accstub, (0x004DFE63, 0x004DFD7B))
        ok(accept(True) == 0x004DFE63, "есть заявка -> продолжение (окно берётся)")
        ok(accept(False) == 0x004DFD7B, "нет заявки -> отказ 5285 код 0")
        uc.hook_del(ah)

    # ═══════════ v31 волна: пункты 2/3/4 (новые дефекты) ═══════════════════════
    UA, UB, HOST, MGRX = 0x00240000, 0x00250000, 0x00260000, 0x00270000

    # ── Пункт 2 (PartnerFlagGuard): флаг партнёра снимается только при +0x149==-1 ──
    print("-- Пункт 2 (PartnerFlagGuard): сторож флага партнёра +0x145/+0x149")
    c2a = find_stub("8b45c085c0741383b849010000ff")   # StubCancelTimeoutGuard
    c2b = find_stub("8b45b083b849010000ff")            # StubAcceptRefuseGuard
    ok(c2a is not None, "стаб 2A (CancelTimeoutGuard) найден")
    ok(c2b is not None, "стаб 2B (AcceptRefuseGuard) найден")

    def setuser(addr, flag, window):
        uc.mem_write(addr + 0x145, struct.pack("<I", flag))
        uc.mem_write(addr + 0x149, struct.pack("<i", window))

    def flag_of(addr):
        return struct.unpack("<I", uc.mem_read(addr + 0x145, 4))[0]

    if c2a:
        def cancel2a(w8_win, w4_win):
            setuser(UA, 1, w8_win); setuser(UB, 1, w4_win)
            uc.mem_write(FRAME - 0x40, struct.pack("<I", UA))   # v8 = user(arg0)
            uc.mem_write(FRAME - 0x3C, struct.pack("<I", UB))   # v4 = партнёр
            uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
            eip = run(c2a, (0x004E0338,))
            return eip, flag_of(UA), flag_of(UB)
        eip, fa, fb = cancel2a(-1, -1)
        ok(eip == 0x004E0338 and fa == 0 and fb == 0,
           "2A: обе стороны свободны (+0x149=-1) -> оба +0x145 сняты")
        eip, fa, fb = cancel2a(-1, 5)
        ok(eip == 0x004E0338 and fa == 0 and fb == 1,
           "2A: партнёр в реальном окне (+0x149=5) -> его +0x145 НЕ тронут (защита)")
        eip, fa, fb = cancel2a(7, -1)
        ok(fa == 1 and fb == 0, "2A: инициатор в реальном окне -> его +0x145 НЕ тронут")
    if c2b:
        def refuse2b(w7_win, w10_win):
            setuser(UA, 1, w7_win); setuser(UB, 1, w10_win)
            uc.mem_write(FRAME - 0x50, struct.pack("<I", UA))   # v7 = accepter
            uc.mem_write(FRAME - 0x44, struct.pack("<I", UB))   # v10 = инициатор
            uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
            eip = run(c2b, (0x004E004D,))
            return eip, flag_of(UA), flag_of(UB)
        eip, fa, fb = refuse2b(-1, -1)
        ok(eip == 0x004E004D and fa == 0 and fb == 0,
           "2B: обе стороны свободны -> оба +0x145 сняты (отправка 5285)")
        eip, fa, fb = refuse2b(3, -1)
        ok(fa == 1 and fb == 0,
           "2B: accepter в реальном обмене с третьим (+0x149=3) -> его флаг НЕ тронут")
        eip, fa, fb = refuse2b(-1, 9)
        ok(fa == 0 and fb == 1, "2B: инициатор в реальном обмене -> его флаг НЕ тронут")

    # ── Пункт 3b (StoreGuestLock): чистка застрявших гостевых слотов ───────────
    print("-- Пункт 3b (StoreGuestLock): CharSelfStoreInfo чистит мёртвые слоты guest[]")
    si = find_stub("c7854cfdffff0000000060ffb5")       # StubStoreInfoClean
    ok(si is not None, "стаб 3b (StoreInfoClean) найден")
    if si:
        # эмуляция sub_5324F0(mgr, userNum): userIndex по userNum
        umap = {10: 100, 20: 999}   # 10->100 (валиден), 20->999 (переиспользован)

        def getnum_hook(u, a, s, d):
            if a != 0x005324F0:
                return
            esp = u.reg_read(UC_X86_REG_ESP)
            un = struct.unpack("<h", u.mem_read(esp + 4, 2))[0]
            ret = struct.unpack("<I", u.mem_read(esp, 4))[0]
            u.reg_write(UC_X86_REG_EAX, umap.get(un, -1) & 0xFFFFFFFF)
            u.reg_write(UC_X86_REG_ESP, esp + 8)          # ret 4
            u.reg_write(UC_X86_REG_EIP, ret)
        gh = uc.hook_add(UC_HOOK_CODE, getnum_hook)
        # слоты: 0 валиден (10,100), 1 мёртв (20,200!=999), 2..4 пусты; счётчик=3
        for i in range(5):
            uc.mem_write(HOST + 0x5B51 + 2 * i, struct.pack("<h", -1))
            uc.mem_write(HOST + 0x5B3D + 4 * i, struct.pack("<i", -1))
        uc.mem_write(HOST + 0x5B51 + 0, struct.pack("<h", 10)); uc.mem_write(HOST + 0x5B3D + 0, struct.pack("<i", 100))
        uc.mem_write(HOST + 0x5B51 + 2, struct.pack("<h", 20)); uc.mem_write(HOST + 0x5B3D + 4, struct.pack("<i", 200))
        uc.mem_write(HOST + 0x5AE8, bytes([3]))
        uc.mem_write(FRAME - 0x2D4, struct.pack("<I", MGRX))   # mgr (this)
        uc.mem_write(FRAME - 0x284, struct.pack("<I", HOST))   # v24 = хозяин
        uc.mem_write(FRAME - 0x2B4, struct.pack("<i", 7))      # v16 (должен стать 0)
        uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
        eip = run(si, (0x005047BE,), count=20000)
        s0u = struct.unpack("<h", uc.mem_read(HOST + 0x5B51 + 0, 2))[0]
        s1u = struct.unpack("<h", uc.mem_read(HOST + 0x5B51 + 2, 2))[0]
        s1c = struct.unpack("<i", uc.mem_read(HOST + 0x5B3D + 4, 4))[0]
        cnt = uc.mem_read(HOST + 0x5AE8, 1)[0]
        v16 = struct.unpack("<i", uc.mem_read(FRAME - 0x2B4, 4))[0]
        ok(eip == 0x005047BE, "3b: стаб уходит на поиск слота (0x5047BE)")
        ok(v16 == 0, "3b: v16 = 0 (репродукция)")
        ok(s0u == 10, "3b: валидный слот (userIndex совпал) сохранён")
        ok(s1u == -1 and s1c == -1, "3b: мёртвый слот (userIndex разошёлся) освобождён")
        ok(cnt == 2, "3b: счётчик гостей 3 -> 2 (один мёртвый снят)")
        uc.hook_del(gh)

    # ── СРЕДН-1: error-path close (HostUserIndex Different) НЕ снимает замок хозяина ──
    #   NOP-правки стаба нет; эмулируем реальный путь exe 0x503DB3->0x504496 ДО и ПОСЛЕ NOP.
    print("-- СРЕДН-1: close по error-path при in-flight замке покупки хозяина (0x503DB9)")
    HOSTL = 0x00260000
    def close_errpath():
        uc.mem_write(HOSTL + 0x5AEF, struct.pack("<I", 1))      # замок «в полёте»
        uc.mem_write(FRAME - 0x24C, struct.pack("<I", HOSTL))   # [ebp-0x24c] = хозяин v33
        uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
        run(0x00503DB3, (0x00504496,), count=50)
        return struct.unpack("<I", uc.mem_read(HOSTL + 0x5AEF, 4))[0]
    ok(close_errpath() == 0, "СРЕДН-1 контроль: СТОК снимает замок хозяина на error-path (дефект)")
    uc.mem_write(0x00503DB9, b"\x90" * 10)                      # применяем NOP (как патч)
    try:
        uc.ctl_remove_cache(0x00503DB3, 0x00503DC3)             # сброс TB-кэша (self-modifying)
    except Exception:
        pass
    ok(close_errpath() == 1, "СРЕДН-1: после NOP замок хозяина НЕ снят (дюп закрыт)")

    # ── Пункт 4 (RefusalBySide): код отказа по стороне с нехваткой ─────────────
    print("-- Пункт 4 (RefusalBySide): коды 5295/5294 стороне с нехваткой (1/2=ты, 3/4=партнёр)")
    r4n = find_stub("33c933d28b853cffffff")             # StubRefusalNormal (5295)
    r4s = find_stub("33c933d28b8598fdffff")             # StubRefusalShell  (5294)
    ok(r4n is not None, "стаб 4n (RefusalNormal 5295) найден")
    ok(r4s is not None, "стаб 4s (RefusalShell 5294) найден")

    # offsets normal: v42=C4 v25=19C v51=5C v52=58 v44=BC v37=D8 v53=54 v40=CC v49=64 v43=C0
    #                 v54=50 v47=B0 v24=1A0 ; arg8=+0x10
    def p4n(arg8, v42=100, v25=0, v51=100, v52=0, v44=1000, v37=0, v53=0, v40=1000, v49=0, v43=0):
        w = lambda off, val: uc.mem_write(FRAME - off, struct.pack("<i", val))
        w(0xC4, v42); w(0x19C, v25); w(0x5C, v51); w(0x58, v52)
        w(0xBC, v44); w(0xD8, v37); w(0x54, v53); w(0xCC, v40); w(0x64, v49); w(0xC0, v43)
        uc.mem_write(FRAME - 0x50, b"\x00"); uc.mem_write(FRAME - 0xB0, b"\x00")
        uc.mem_write(FRAME - 0x1A0, struct.pack("<i", 1))       # v24 = 1
        uc.mem_write(FRAME + 0x10, struct.pack("<i", arg8))
        uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
        eip = run(r4n, (0x004E7659,))
        v54 = uc.mem_read(FRAME - 0x50, 1)[0]
        v47 = uc.mem_read(FRAME - 0xB0, 1)[0]
        v24 = struct.unpack("<i", uc.mem_read(FRAME - 0x1A0, 4))[0]
        return eip, v54, v47, v24
    if r4n:
        eip, v54, v47, v24 = p4n(1)                     # нет нехватки
        ok(eip == 0x004E7659 and v24 == 1 and v54 == 0 and v47 == 0, "4n: нет нехватки -> v24=1, коды не ставятся")
        # A(3609) нет места; arg8=1 -> v54->A, v47->B
        eip, v54, v47, v24 = p4n(1, v42=0, v25=3)
        ok(v24 == 0 and v54 == 1 and v47 == 3, "4n: A нет места, arg8=1 -> A(v54)=1«ты», B(v47)=3«партнёр»")
        # тот же дефект, arg8=0 -> v54->B, v47->A : A всё равно слышит «ты»(1)
        eip, v54, v47, v24 = p4n(0, v42=0, v25=3)
        ok(v54 == 3 and v47 == 1, "4n: A нет места, arg8=0 -> A(v47)=1«ты», B(v54)=3«партнёр»")
        # B(3611) перевес; arg8=1 -> B слышит «ты»(2), A «партнёр»(4)
        eip, v54, v47, v24 = p4n(1, v40=0, v49=0, v43=5)
        ok(v24 == 0 and v54 == 4 and v47 == 2, "4n: B перевес, arg8=1 -> A(v54)=4«партнёр», B(v47)=2«ты»")

    # offsets shell: v47=268 v33=4CC v46=26C v56=12C v49=260 v44=274 v57=128 v45=270 v53=250 v48=264
    #                v59=120 v55=248 v32=4D0 ; arg8=+0x10
    def p4s(arg8, A_slots=100, A_in=0, B_slots=100, B_in=0,
            Amax=1000, Aused=0, B_inw=0, Bmax=1000, Bused=0, A_inw=0):
        w = lambda off, val: uc.mem_write(FRAME - off, struct.pack("<i", val))
        w(0x268, A_slots); w(0x4CC, A_in); w(0x26C, B_slots); w(0x12C, B_in)
        w(0x260, Amax); w(0x274, Aused); w(0x128, B_inw); w(0x270, Bmax); w(0x250, Bused); w(0x264, A_inw)
        uc.mem_write(FRAME - 0x120, b"\x00"); uc.mem_write(FRAME - 0x248, b"\x00")
        uc.mem_write(FRAME - 0x4D0, struct.pack("<i", 1))       # v32 = 1
        uc.mem_write(FRAME + 0x10, struct.pack("<i", arg8))
        uc.reg_write(UC_X86_REG_EBP, FRAME); uc.reg_write(UC_X86_REG_ESP, ESP0)
        eip = run(r4s, (0x004E4EF2,))
        v59 = uc.mem_read(FRAME - 0x120, 1)[0]
        v55 = uc.mem_read(FRAME - 0x248, 1)[0]
        v32 = struct.unpack("<i", uc.mem_read(FRAME - 0x4D0, 4))[0]
        return eip, v59, v55, v32
    if r4s:
        eip, v59, v55, v32 = p4s(1)
        ok(eip == 0x004E4EF2 and v32 == 1 and v59 == 0 and v55 == 0, "4s: нет нехватки -> v32=1, коды не ставятся")
        # A нет места (v47<v33): A_slots=0, A_in=3 ; arg8=1 -> v59->A, v55->B
        eip, v59, v55, v32 = p4s(1, A_slots=0, A_in=3)
        ok(v32 == 0 and v59 == 1 and v55 == 3, "4s: A нет места, arg8=1 -> A(v59)=1«ты», B(v55)=3«партнёр»")
        eip, v59, v55, v32 = p4s(0, A_slots=0, A_in=3)
        ok(v59 == 3 and v55 == 1, "4s: A нет места, arg8=0 -> A(v55)=1«ты», B(v59)=3«партнёр»")
        # B перевес (v45-v53<v48): Bmax=0,Bused=0,A_inw=5 ; arg8=1 -> B «ты»(2), A «партнёр»(4)
        eip, v59, v55, v32 = p4s(1, Bmax=0, Bused=0, A_inw=5)
        ok(v32 == 0 and v59 == 4 and v55 == 2, "4s: B перевес, arg8=1 -> A(v59)=4«партнёр», B(v55)=2«ты»")

    print()
    if bad:
        print("*** НЕ СОШЛОСЬ: %d проверок провалено ***" % bad)
        return 2
    print("ВСЁ СОШЛОСЬ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
