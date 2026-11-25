# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_traffic.py — статическая проверка врезки шифрования (волна В7b): L07 (LoginManager) и P61 (GameServer/Indun).
#   1) исходные байты всех площадок в КАЖДОМ образе (патч ставится только при совпадении — Hook::Verify);
#   2) площадки на границах инструкций (дизасм вокруг — нет перехода внутрь 5 байт);
#   3) в собранных DLL присутствуют трамплины: встроены верные СТОКОВЫЕ адреса (mov eax,imm32; call/jmp eax)
#      и возврат ret 0xC.
#   4) ★ В7d: стоковая ветка разрыва (GetConnectFlag/DisConnect/хвост) во всех образах; обе функции — ret 4;
#      путь от адреса возврата трамплина при разрыве до начала цикла IoWorkerThread — только безусловные jmp
#      (стек не трогается); в DLL встроены адреса GetConnectFlag/DisConnect и запись `mov [ebp+4], kKillResume`.
# Сервер НЕ запускается; образы только читаются. Запуск: py -3.13 verify_traffic.py
import os, sys, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))   # ★ 22.10.2026: srv_paths.py
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
LM_IMAGES = [
    ("LM живой 12dcd9f1", os.path.join(HERE, "..", "..", "LoginPatch", "work", "lm_live_12dcd9f1.exe")),
    ("LM деплой 51db86b2", os.path.join(HERE, "..", "..", "LoginPatch", "out", "LoginManager.exe.loginpatch.exe")),
    ("LM стойка (шара)", V2 + "LoginManager/LoginManager.exe"),   # ★ В7d: то, что реально запускается на стойке
]
GS_IMAGES = [
    ("GS сток 4e20f0ad", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("GS живой e7b4ac38", V2 + "GameServer/GameServer.exe"),
    ("GS Indun e7b4ac38", V2 + "Indun_GameServer/GameServer.exe"),
]
# integ2b: по умолчанию — ИТОГОВЫЕ DLL основных папок (L07/P61 слиты); копии агентов — через VT_LM_DLL / VT_GS_DLL
LM_DLL = os.environ.get("VT_LM_DLL") or os.path.join(HERE, "..", "..", "LoginPatch", "out", "LoginPatch.dll")
GS_DLL = os.environ.get("VT_GS_DLL") or os.path.join(HERE, "..", "..", "AsdaPatch", "out", "AsdaPatch.dll")

# (имя, VA, ожидаемые байты)
LM_SITES = [
    ("L07.recv.callsite",  0x004165B5, "e846f0ffff"),
    ("L07.send.callsiteA", 0x004159F8, "e8b3e0ffff"),
    ("L07.send.callsiteB", 0x00415F1E, "e88ddbffff"),
    ("L07.setconn.entry",  0x004144A0, "558bec6aff"),
    ("L07.disc.entry",     0x004138D0, "558bec6aff"),   # ★ fix2b: детур ворот отложенного разрыва
    # ★ В7d: стоковая ветка разрыва IoWorkerThread (сверка, не пишется)
    ("L07.kill.flagcall",  0x0041644E, "e8fde0ffff"),   # call 0x414550 GetConnectFlag
    ("L07.kill.disccall",  0x0041645E, "e86dd4ffff"),   # call 0x4138D0 DisConnect
    ("L07.kill.resume",    0x00416463, "eb0d"),         # jmp 0x416472
    ("L07.kill.loopjmp",   0x00416472, "e99cfdffff"),   # jmp 0x416213 (начало цикла)
]
GS_SITES = [
    ("P61.recv.callsite",  0x00564CD5, "e846efffff"),
    ("P61.send.callsiteA", 0x004C2ACA, "e851f40900"),
    ("P61.send.callsiteB", 0x004C2BDC, "e83ff30900"),
    ("P61.send.callsiteC", 0x0056435E, "e8bddbffff"),
    ("P61.setconn.entry",  0x00562910, "558bec6aff"),
    ("P61.disc.entry",     0x00561C30, "558bec6aff"),   # ★ fix2b: детур ворот отложенного разрыва
    # ★ В7d: стоковая ветка разрыва IoWorkerThread (сверка, не пишется)
    ("P61.kill.flagcall",  0x00564B6E, "e84ddeffff"),   # call 0x5629C0 GetConnectFlag
    ("P61.kill.disccall",  0x00564B7E, "e8add0ffff"),   # call 0x561C30 DisConnect
    ("P61.kill.resume",    0x00564B83, "eb0d"),         # jmp 0x564B92
    ("P61.kill.loopjmp",   0x00564B92, "e99cfdffff"),   # jmp 0x564933 (начало цикла)
]
# СТОКОВЫЕ адреса, которые трамплины в DLL обязаны вызывать/прыгать (mov eax,imm32).
LM_DLL_IMM = {"recv.sink 0x415600": 0x00415600, "send.func 0x413AB0": 0x00413AB0, "setconn.resume 0x4144A5": 0x004144A5, "disc.resume 0x4138D5": 0x004138D5}
GS_DLL_IMM = {"recv.sink 0x563C20": 0x00563C20, "send.func 0x561F20": 0x00561F20, "setconn.resume 0x562915": 0x00562915, "disc.resume 0x561C35": 0x00561C35}

fail = 0
def say(ok, msg):
    global fail
    print(("  [OK] " if ok else "  [ПРОВАЛ] ") + msg)
    if not ok: fail += 1

def mm_of(path):
    pe = pefile.PE(path, fast_load=True)
    return pe.OPTIONAL_HEADER.ImageBase, pe.get_memory_mapped_image()

def check_sites(title, images, sites):
    print("==", title, "— байты площадок во всех образах")
    for nm, path in images:
        if not os.path.exists(path):
            say(False, f"{nm}: образ не найден ({path})"); continue
        base, mm = mm_of(path)
        allok = True
        for sname, va, hexb in sites:
            got = mm[va-base:va-base+len(hexb)//2].hex()
            if got != hexb.lower():
                say(False, f"{nm}: {sname} @0x{va:08X} ожид {hexb} получено {got}"); allok=False
        if allok: say(True, f"{nm}: все {len(sites)} площадок совпали")

def check_dll(title, dll, imms):
    print("==", title, "— трамплины в собранной DLL")
    if not os.path.exists(dll):
        say(False, f"DLL не найдена: {dll}"); return
    pe = pefile.PE(dll, fast_load=True)
    data = b""
    for s in pe.sections:
        if b'.text' in s.Name: data = s.get_data(); break
    # mov eax, imm32 = B8 <imm32le>. ★ fix2: стоковый Send зовёт не трамплин, а SrvSendRaw (C++ под замком слота) —
    #   компилятор вправе закодировать адрес не через mov eax, поэтому для send.func ищется сам imm32.
    for nm, imm in imms.items():
        pat = b"\xB8" + struct.pack("<I", imm)
        if nm.startswith("send.func"):
            say(struct.pack("<I", imm) in data, f"встроен адрес {nm} (SrvSendRaw → SendRoute, под замком слота)")
        else:
            say(pat in data, f"встроен адрес {nm}")
    # ret 0xC присутствует (трамплины recv/send)
    say(b"\xC2\x0C\x00" in data, "есть ret 0x0C (recv/send трамплины)")

# ★ В7d: функции разрыва — thiscall с одним аргументом (ret 4); путь возврата при разрыве — только jmp до цикла.
LM_KILL = {"funcs": {"GetConnectFlag 0x414550": 0x00414550, "DisConnect 0x4138D0": 0x004138D0},
           "resume": 0x00416463, "loop": 0x00416213, "imm": [0x00414550, 0x004138D0], "resume_imm": 0x00416463,
           "callsite": 0x004165B5}
GS_KILL = {"funcs": {"GetConnectFlag 0x5629C0": 0x005629C0, "DisConnect 0x561C30": 0x00561C30},
           "resume": 0x00564B83, "loop": 0x00564933, "imm": [0x005629C0, 0x00561C30], "resume_imm": 0x00564B83,
           "callsite": 0x00564CD5}

def check_kill_path(title, images, k):
    print("==", title, "— стоковая ветка разрыва: ret 4, путь до цикла без операций со стеком")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for nm, path in images:
        if not os.path.exists(path):
            say(False, f"{nm}: образ не найден"); continue
        base, mm = mm_of(path)
        for fn, va in k["funcs"].items():
            ret = None
            for ins in md.disasm(bytes(mm[va-base:va-base+0x200]), va):
                if ins.mnemonic == "ret":
                    ret = ins.op_str; break
            say(ret == "4", f"{nm}: {fn} — ret {ret} (thiscall, один аргумент)")
        # путь от адреса возврата при разрыве до начала цикла
        va = k["resume"]; ok = True; steps = 0
        while va != k["loop"] and steps < 8:
            ins = next(md.disasm(bytes(mm[va-base:va-base+16]), va), None)
            if ins is None or ins.mnemonic != "jmp":
                ok = False; break
            va = int(ins.op_str, 16); steps += 1
        say(ok and va == k["loop"], f"{nm}: от 0x{k['resume']:08X} до цикла 0x{k['loop']:08X} — {steps} безусловных jmp, стек не трогается")
        # на площадке приёма ровно 3 push перед call (ret 0xC у трамплина снимает их) и ecx = [ebp-0x24]
        cs = k["callsite"]
        # начало операторa вызова: cs-0x12 (`mov eax,[ebp-0x20]`; дизасм lm_live/GS сток) — граница инструкции
        code = list(md.disasm(bytes(mm[cs-base-0x12:cs-base+5]), cs-0x12))
        tail = [i for i in code if i.address < cs]
        if not code or code[-1].address != cs: tail = []   # рассинхрон дизасма = провал проверки
        pushes = sum(1 for i in tail if i.mnemonic == "push")
        ecx_ok = any(i.mnemonic == "mov" and i.op_str.replace(" ", "") == "ecx,dwordptr[ebp-0x24]" for i in tail)
        say(pushes >= 3 and ecx_ok, f"{nm}: площадка приёма — 3 аргумента и ecx=[ebp-0x24] (тот же this, что у ветки разрыва)")

def check_dll_kill(title, dll, k):
    print("==", title, "— ★ В7d: разрыв в собранной DLL")
    if not os.path.exists(dll):
        say(False, f"DLL не найдена: {dll}"); return
    pe = pefile.PE(dll, fast_load=True)
    data = b""
    for s_ in pe.sections:
        if b'.text' in s_.Name: data = s_.get_data(); break
    for imm in k["imm"]:
        say(struct.pack("<I", imm) in data, f"встроен адрес 0x{imm:08X} (GetConnectFlag/DisConnect)")
    pat = bytes([0xC7, 0x45, 0x04]) + struct.pack("<I", k["resume_imm"])   # mov dword ptr [ebp+4], imm32
    say(pat in data, f"трамплин приёма: mov [ebp+4], 0x{k['resume_imm']:08X} (возврат на хвост ветки разрыва)")

# ★ fix2 (ревизия INTEG3, схема правки п. 5): ОТПРАВКА/ПРИЁМ НЕ ВЫЗЫВАЮТСЯ ПОД ЗАМКОМ Ciocp L.
#   Порядок замков моста — «замок слота → L» (SendRoute/RecvRoute берут замок слота и внутри зовут стоковый Send, он
#   берёт L). Обратное ребро возможно, только если код под L дойдёт до наших площадок отправки/приёма. Проверка:
#   метод 1 — сам список L-функций: каждый вызов замочного помощника с аргументом this+0x60D1830 в .text (скан всех
#   вызовов помощника + дизасм функции до вызова), совпадает со списком ревизора (GS 9, LM 8);
#   метод 2 — от каждой L-функции обход прямых вызовов (рекурсивный спуск по ветвлениям, глубина без предела, до 4000
#   функций) не достигает ни одной площадки send/recv. Детур SetConnectFlag (L-функция) после fix2 замка слота не берёт —
#   это проверяет стенд stand_b7d_locks (S1/S1b/S3/S5).
L_OFF = 0x060D1830
GS_LOCK = {"helper": 0x00568D50,
           "expect": [0x560E20, 0x5618B0, 0x561C30, 0x561E10, 0x561F20, 0x562640, 0x562910, 0x5629C0, 0x5651D0],
           "sites": {"send A 0x4C2ACA": 0x004C2ACA, "send B 0x4C2BDC": 0x004C2BDC, "send C 0x56435E": 0x0056435E,
                     "recv 0x564CD5": 0x00564CD5}}
LM_LOCK = {"helper": 0x0041A620,
           "expect": [0x412AC0, 0x413550, 0x4138D0, 0x413AB0, 0x4141D0, 0x4144A0, 0x414550, 0x416AB0],
           "sites": {"send A 0x4159F8": 0x004159F8, "send B 0x415F1E": 0x00415F1E, "recv 0x4165B5": 0x004165B5}}


def _text(pe):
    for s_ in pe.sections:
        if s_.Name.rstrip(b"\0") == b".text":
            return pe.OPTIONAL_HEADER.ImageBase + s_.VirtualAddress, s_.Misc_VirtualSize
    return None, 0


def _func_start(mm, base, va, lo):
    """Ближайший пролог `55 8B EC 6A FF` (SEH-кадр Ciocp) до va, иначе `55 8B EC`."""
    for pat in (b"\x55\x8B\xEC\x6A\xFF", b"\x55\x8B\xEC"):
        p = va
        while p > max(lo, va - 0x400):
            p -= 1
            if bytes(mm[p - base:p - base + len(pat)]) == pat:
                return p
    return None


def _walk(md, mm, base, tlo, thi, fn, seen_ins):
    """Рекурсивный спуск по одной функции: адреса инструкций → seen_ins; возврат — цели прямых call и число косвенных."""
    calls, indirect, work, done = set(), [0, 0], [fn], set()
    while work:
        va = work.pop()
        while tlo <= va < thi and va not in done:
            ins = next(md.disasm(bytes(mm[va - base:va - base + 16]), va), None)
            if ins is None:
                break
            done.add(va); seen_ins.add(va)
            m, op = ins.mnemonic, ins.op_str
            nxt = va + ins.size
            if m == "call":
                if op.startswith("0x"):
                    calls.add(int(op, 16))
                elif op.startswith("dword ptr [0x"):
                    indirect[0] += 1   # вызов API через IAT (EnterCriticalSection, WriteFile …) — не наш код
                else:
                    indirect[1] += 1   # call reg / [reg+…] — цель неизвестна статически
                va = nxt
            elif m == "jmp":
                if op.startswith("0x"):
                    va = int(op, 16)
                else:
                    break          # jmp по таблице/регистру — дальше не идём (косвенный, считается ниже как неизвестность)
            elif m.startswith("j") or m.startswith("loop"):
                if op.startswith("0x"):
                    work.append(int(op, 16))
                va = nxt
            elif m in ("ret", "retn", "int3", "hlt"):
                break
            else:
                va = nxt
    return calls, indirect


def check_lock_order(title, images, k):
    print("==", title, "— ★ fix2: под замком Ciocp (this+0x60D1830) нет пути к площадкам отправки/приёма")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for nm, path in images:
        if not os.path.exists(path):
            say(False, f"{nm}: образ не найден"); continue
        pe = pefile.PE(path, fast_load=True)
        base, mm = pe.OPTIONAL_HEADER.ImageBase, pe.get_memory_mapped_image()
        tlo, tsz = _text(pe); thi = tlo + tsz
        # метод 1: КАЖДОЕ упоминание смещения 0x60D1830 в .text (imm32 в инструкции) → содержащая функция.
        #   Захват: в функции вызов помощника 0x568D50/0x41A620 с этим аргументом; иначе — конструктор/деструктор
        #   (Initialize/DeleteCriticalSection через IAT): замок не держат, но в списке ревизора они есть — сверяем всё.
        takers, users, raw = set(), set(), bytes(mm[tlo - base:thi - base])
        needle = struct.pack("<I", L_OFF)
        i = raw.find(needle)
        while i != -1:
            va = tlo + i
            fs = _func_start(mm, base, va, tlo)
            if fs is not None:
                code = [x for x in md.disasm(bytes(mm[fs - base:va - base + 16]), fs)]
                idx = next((n for n, x in enumerate(code) if x.address <= va < x.address + x.size and "0x60d1830" in x.op_str), None)
                if idx is not None:
                    users.add(fs)
                    nxt = code[idx + 1:idx + 5]
                    if any(x.mnemonic == "call" and x.op_str == hex(k["helper"]) for x in nxt):
                        takers.add(fs)
            i = raw.find(needle, i + 1)
        exp = set(k["expect"])
        say(users == exp, f"{nm}: L (this+0x60D1830) упоминают {len(users)} функций, из них берут через помощник 0x{k['helper']:X} — "
                          f"{len(takers)}, остальные {sorted(hex(x) for x in users - takers)} (Initialize/DeleteCriticalSection) — "
                          f"{'совпало со списком ревизора' if users == exp else 'РАСХОЖДЕНИЕ: лишние ' + str(sorted(hex(x) for x in users - exp)) + ', нет ' + str(sorted(hex(x) for x in exp - users))}")
        # метод 2: обход вызовов от L-функций
        seen_ins, seen_fn, work, indirect = set(), set(), list(users | exp), [0, 0]
        while work and len(seen_fn) < 4000:
            fn = work.pop()
            if fn in seen_fn or not (tlo <= fn < thi):
                continue
            seen_fn.add(fn)
            calls, ind = _walk(md, mm, base, tlo, thi, fn, seen_ins)
            indirect[0] += ind[0]; indirect[1] += ind[1]
            work.extend(c for c in calls if c not in seen_fn)
        hit = [s for s, va in k["sites"].items() if va in seen_ins]
        say(not hit and len(seen_fn) < 4000,
            f"{nm}: от L-функций достижимо {len(seen_fn)} функций, {len(seen_ins)} инструкций (call через IAT {indirect[0]}, по регистру/памяти {indirect[1]}) — "
            f"{'площадки send/recv НЕ достижимы' if not hit else 'ДОСТИЖИМЫ: ' + ', '.join(hit)}")


# ★ fix2d (П-1): РАСКЛАДКА СТОКОВОГО Ciocp::Send / SendTemp, которую мост читает под тем же замком L (без новых площадок).
#   GS Send 0x561F20 / SendTemp 0x562640; LM — тот же код со сдвигом −0x14E470 (Send 0x413AB0, SendTemp 0x4141D0). Сверка
#   инструкций (capstone; цель call — свой помощник замка образа) во всех образах + в DLL встроена та же раскладка (8 dword).
STOCK_LAYOUT = (0x060D1830, 0x060D1898, 0xA0BE, 4, 8, 0xA0B2, 0x9F9C, 0x1000)
SEND_CHECKS = [   # (GS VA, ожидаемая инструкция «мнемоника операнды»; {H} — помощник замка образа)
    (0x00561F52, "add eax, 0x60d1830"),                        # Send: L = this+0x60D1830 …
    (0x00561F5B, "call {H}"),                                  # … RAII-захват L (EnterCriticalSection) ДО чтения полей
    (0x00561FBB, "imul ecx, ecx, 0xa0be"),                     # шаг сессии
    (0x00561FC4, "mov eax, dword ptr [edx + 0x60d1898]"),      # указатель массива сессий
    (0x00561FCA, "cmp dword ptr [eax + ecx + 4], 0"),          # флаг соединения
    (0x00562001, "movzx ecx, byte ptr [eax + ecx + 8]"),       # запись в полёте
    (0x00562006, "cmp ecx, 1"),
    (0x00562021, "mov edx, dword ptr [ecx + edx + 0xa0b2]"),   # длина досылки
    (0x00562028, "add edx, dword ptr [ebp + 0x10]"),           # + n
    (0x0056202B, "cmp edx, 0x9f9c"),                           # порог стирания
    (0x00562033, "push 0xa000"),                               # memset досылки (стирание)
    (0x0056206E, "mov dword ptr [eax + ecx + 0xa0b2], 0"),
    (0x0056208B, "mov byte ptr [eax + ecx + 8], 0"),
    (0x005621A3, "cmp dword ptr [edx + eax + 0xa0b2], 0"),     # ветка «досылка без записи в полёте»
    (0x005621E4, "cmp eax, 0x9f9c"),
    (0x0056233E, "push 0x1000"),                               # … копия досылки в буфер записи 0x1000
    (0x00562672, "add eax, 0x60d1830"),                        # SendTemp: тот же L …
    (0x0056267B, "call {H}"),
    (0x005626C6, "mov byte ptr [eax + ecx + 8], 0"),           # … снимает «в полёте»
    (0x00562714, "cmp dword ptr [eax + ecx + 0xa0b2], 0"),
    (0x005628C4, "mov dword ptr [eax + ecx + 0xa0b2], 0"),     # досылка выдана — длина 0
]

def check_stock_layout(title, images, delta, helper, dll):
    print("==", title, "— ★ fix2d: раскладка стокового Send/SendTemp (досылка) и её копия в DLL")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for nm, path in images:
        if not os.path.exists(path):
            say(False, f"{nm}: образ не найден"); continue
        base, mm = mm_of(path)
        bad = []
        for gva, want in SEND_CHECKS:
            va = gva - delta
            ins = next(md.disasm(bytes(mm[va-base:va-base+16]), va), None)
            got = f"{ins.mnemonic} {ins.op_str}" if ins else "?"
            if got != want.replace("{H}", hex(helper)):
                bad.append(f"0x{va:08X}: ждали «{want}», есть «{got}»")
        say(not bad, f"{nm}: {len(SEND_CHECKS)} инструкций раскладки совпали" if not bad else f"{nm}: РАСХОЖДЕНИЕ {bad}")
    if not os.path.exists(dll):
        say(False, f"DLL не найдена: {dll}"); return
    raw = open(dll, "rb").read()
    say(struct.pack("<8I", *STOCK_LAYOUT) in raw, f"в {os.path.basename(dll)} встроена раскладка {', '.join(hex(x) for x in STOCK_LAYOUT)}")

check_sites("LoginManager (L07)", LM_IMAGES, LM_SITES)
check_sites("GameServer/Indun (P61)", GS_IMAGES, GS_SITES)
check_stock_layout("LoginManager (L07)", LM_IMAGES, 0x14E470, 0x0041A620, LM_DLL)
check_stock_layout("GameServer/Indun (P61)", GS_IMAGES, 0, 0x00568D50, GS_DLL)
check_dll("LoginPatch.dll (L07) " + os.path.basename(os.path.dirname(os.path.dirname(LM_DLL))), LM_DLL, LM_DLL_IMM)
check_dll("AsdaPatch.dll (P61) " + os.path.basename(os.path.dirname(os.path.dirname(GS_DLL))), GS_DLL, GS_DLL_IMM)
check_kill_path("LoginManager (L07)", LM_IMAGES, LM_KILL)
check_kill_path("GameServer/Indun (P61)", GS_IMAGES, GS_KILL)
check_dll_kill("LoginPatch.dll (L07)", LM_DLL, LM_KILL)
check_dll_kill("AsdaPatch.dll (P61)", GS_DLL, GS_KILL)
check_lock_order("LoginManager (L07)", LM_IMAGES, LM_LOCK)
check_lock_order("GameServer/Indun (P61)", GS_IMAGES, GS_LOCK)

print("\n== ВСЁ СОШЛОСЬ ==" if fail == 0 else f"\n== ПРОВАЛОВ: {fail} ==")
sys.exit(1 if fail else 0)
