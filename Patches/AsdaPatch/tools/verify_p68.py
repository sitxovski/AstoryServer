# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p68.py — СТАТИЧЕСКАЯ + ЭМУЛЯТОРНАЯ проверка P68 (античит A13 «имя персонажа», 2026-10-13):
#   6138 RecvClient_CharNameCheck — площадка `call memcpy` 0x55D8CE (копия имени в тело DB 2450),
#   6140 RecvClient_CharNameChange — площадка `call memcpy` 0x55DC6C (копия имени в тело DB 2452),
#   2453 sub_55DD50 — площадка `call memcpy` 0x55DFDF (имя в CUser+0x178; копия только при флаге БД 1).
#
# Сервер НЕ запускается. Грузятся образы (сток 4e20f0ad, живой GameServer и живой Indun e7b4ac38) и AsdaPatch.dll:
#  1) байты площадок и «соседей» (аргументы memcpy, адреса возврата, эпилог 6138, стоковый хвост отказа 6141, якоря кадров,
#     сравнение флага БД с 1) в каждом образе; формат стокового 6139 (5 б, 0x17FB) и 6141 (86 б, 0x17FD);
#  2) в .text ни один rel8/rel32/jcc32/abs32 не ведёт ВНУТРЬ площадок; площадки и цели переходов — на границе инструкции;
#     площадки не пересекаются с площадками P63 (0x55D923/0x55DC98/0x43332A);
#  3) стабы найдены по MAP (out/AsdaPatch.map) + сигнатуре; `jmp dword ptr [..]` разыменованы и ведут куда задумано;
#     C-функции — внутрь DLL и совпадают с символами MAP;
#  4) unicorn: каждый стаб — пропуск (сток memcpy с теми же 3 аргументами, возврат на адрес после call), отказ/пропуск копии
#     (эпилог 6138 / хвост 6141 с кодом 0 / ret без копии), баланс стека, ebx/esi/edi/ebp сохранены.
# Запуск: python verify_p68.py [AsdaPatch.dll]      (образы: P68_IMG_DIR=<папка с gs_stock/gs_live/gs_indun> или шара)
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
V2 = SRV_ROOT + "/v2/"
GS_IMAGES = [
    ("сток", SRV_ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"),
    ("живой GameServer", V2 + "GameServer/GameServer.exe"),
    ("живой Indun", V2 + "Indun_GameServer/GameServer.exe"),
]
if os.environ.get("P68_IMG_DIR"):
    d = os.environ["P68_IMG_DIR"]
    GS_IMAGES = [("сток", d + "/gs_stock.exe"), ("живой GameServer", d + "/gs_live.exe"), ("живой Indun", d + "/gs_indun.exe")]

MEMCPY = 0x0056A040


def _call(va, target):
    return "e8" + struct.pack("<i", target - (va + 5)).hex()


GS_SITES = [
    ("P68.name6138", 0x0055D8CE, _call(0x0055D8CE, MEMCPY)),   # memcpy(тело2450+4, имя, 20) в RecvClient_CharNameCheck
    ("P68.name6140", 0x0055DC6C, _call(0x0055DC6C, MEMCPY)),   # memcpy(тело2452+5, имя, 20) в RecvClient_CharNameChange
    ("P68.keep2453", 0x0055DFDF, _call(0x0055DFDF, MEMCPY)),   # memcpy(CUser+0x178, имя, 20) в sub_55DD50
]
GS_NEIGHBOURS = [
    ("6138 аргументы memcpy 0x55D8C4 (push 14h; lea edx,[ebp-3Ch]; push edx; lea eax,[ebp-18h]; push eax)", 0x0055D8C4, "6a148d55c4528d45e850"),
    ("6138 возврат 0x55D8D3 (add esp,0Ch)",                              0x0055D8D3, "83c40c"),
    ("6138 эпилог 0x55D8FC (cookie; mov esp,ebp; pop ebp; ret 8)",       0x0055D8FC, "8b4dfc33cde89fca00008be55dc20800"),
    ("6138 this=[ebp-4Ch] 0x55D7D0",                                     0x0055D7D0, "894db4"),
    ("6138 CUser*=[ebp-44h] 0x55D885",                                   0x0055D885, "8945bc"),
    ("6138 тело [ebp-40h]: memcpy(тело, пакет+9+16, 18h) 0x55D890",      0x0055D890, "6a180fbf55b88b450c8d4c1009518d55c052"),
    ("6138 charId тела == sub_5324F0 0x55D8B7 (cmp [ebp-40h],eax; je)",  0x0055D8B7, "3945c07402"),
    ("6138 отправка 2450 (24 б) 0x55D8EB (push 18h; push 992h)",          0x0055D8EB, "6a186892090000"),
    ("6140 аргументы memcpy 0x55DC5F (push 14h; lea edx,[ebp-0DCh]; …; lea eax,[ebp-23h])", 0x0055DC5F, "6a148d9524ffffff528d45dd50"),
    ("6140 возврат 0x55DC71 (add esp,0Ch)",                              0x0055DC71, "83c40c"),
    ("6140 код 5 в [ebp-68h] 0x55DA9E",                                  0x0055DA9E, "c6459805"),
    ("6140 стоковый хвост отказа 0x55DAA2 (… push 56h; push 17FDh; sub_4C28F0; jmp 0x55DC9D)", 0x0055DAA2,
     "6a016aff8d558052668b4508506a5668fd1700008b8d14ffffff8b4904e82c4ef6ffe9d4010000"),
    ("6140 CUser*=[ebp-0E4h] 0x55DA0D",                                  0x0055DA0D, "89851cffffff"),
    ("6140 this=[ebp-0ECh] 0x55D9AD",                                    0x0055D9AD, "8b8d14ffffff"),
    ("6140 тело [ebp-0E0h]: memcpy(тело, пакет+9+16, 1Bh) 0x55DA21",     0x0055DA21, "6a1b0fbf9518ffffff8b450c8d4c1009518d9520ffffff52"),
    ("6140 отправка 2452 (32 б) 0x55DC8C (push 20h; push 994h)",          0x0055DC8C, "6a206894090000"),
    ("6140 эпилог 0x55DC9D",                                             0x0055DC9D, "8b4df833cde8fec600008be55dc20800"),
    ("2453 аргументы memcpy 0x55DFC9 (… mov edx,[ebp-0C0h]; add edx,178h; push edx)", 0x0055DFC9, "6a148d8d48ffffff518b9540ffffff81c27801000052"),
    ("2453 возврат 0x55DFE4 (add esp,0Ch)",                              0x0055DFE4, "83c40c"),
    ("2453 сток сравнивает флаг [ebp-9Dh] с 1 0x55DEC4",                  0x0055DEC4, "0fb69563ffffff83fa01"),
    ("2453 ответ 6141 после копии 0x55DFE7 (push 1; push -1; lea eax,[ebp-60h])", 0x0055DFE7, "6a016aff8d45a0"),
    ("2453 CUser*=[ebp-0C0h] 0x55DDB6",                                  0x0055DDB6, "898540ffffff"),
    ("6139 стоковый ответ sub_55DCB0: 5 б, 0x17FB (push 5; push 17FBh)",  None, "6a0568fb170000"),
    ("memcpy 0x56A040 пролог",                                           MEMCPY, "558bec5756"),
]
BOUNDARY_EXTRA = [0x0055D8FC, 0x0055DAA2, 0x0055D8D3, 0x0055DC71, 0x0055DFE4]
P63_SITES = [(0x0055D923, 6), (0x0055DC98, 5), (0x0043332A, 5)]
RANGE_55DCB0 = (0x0055DCB0, 0x0055DD50)

bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def load(path):
    import pefile
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
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    total = 0
    end_ok = False
    for ins in md.disasm(bytes(img[va - base: va - base + ln + 16]), va):
        total += ins.size
        if total >= ln:
            end_ok = total == ln
            break
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


def count_imm(img, base, lo, hi, value):
    n = 0
    for i in range(lo - base, hi - base - 4):
        if struct.unpack("<I", bytes(img[i:i + 4]))[0] == value:
            n += 1
    return n


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
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(bytes(img[va - base: va - base + n]), va))


def stub_targets(img, base, va, njmp=1):
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
        if ins.mnemonic == "int3" or ins.mnemonic == "ret" or len(jmps) >= njmp:
            break
    return jmps, calls, icalls


class Emu:
    def __init__(self, gs_img, gs_base, dll_img, dll_base):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP
        self.R = (UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, img in ((gs_base, gs_img), (dll_base, dll_img)):
            self.uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
            self.uc.mem_write(base, bytes(img))
        self.uc.mem_map(0x00100000, 0x00100000)
        self.stops = set()
        self.fake = {}
        self.stopped_at = None
        self.uc.hook_add(UC_HOOK_CODE, self._on)

    def _on(self, uc, address, size, ud):
        ESP, EAX, EIP = self.R
        if address in self.fake:
            nb, fn = self.fake[address]
            esp = uc.reg_read(ESP)
            ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = struct.unpack("<%dI" % (nb // 4), uc.mem_read(esp + 4, nb)) if nb else ()
            eax = fn(uc, args, esp + 4)
            uc.reg_write(EAX, eax & 0xFFFFFFFF)
            uc.reg_write(ESP, esp + 4 + nb)
            uc.reg_write(EIP, ret)
            return
        if address in self.stops:
            self.stopped_at = address
            uc.emu_stop()

    def run(self, start, regs, mem=(), count=300):
        from unicorn import UcError
        uc = self.uc
        for addr, data in mem:
            uc.mem_write(addr, data)
        for r, v in regs.items():
            uc.reg_write(r, v)
        self.stopped_at = None
        try:
            uc.emu_start(start, 0, count=count)
        except UcError as e:
            print("    сбой эмуляции @0x%08X: %s" % (uc.reg_read(self.R[2]), e))
        return self.stopped_at

    def r(self, reg):
        return self.uc.reg_read(reg)


def verify_binary(dll):
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                                   UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)
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
            if va is None:
                hits = [h for h in find_all(img, base, o) if RANGE_55DCB0[0] <= h < RANGE_55DCB0[1]]
                ok(len(hits) == 1, "сосед: %s — в sub_55DCB0 найдено %d (%s)" % (n, len(hits), ["0x%08X" % h for h in hits]))
                continue
            cur = bytes(img[va - base: va - base + len(bytes.fromhex(o))])
            ok(cur == bytes.fromhex(o), "сосед: %s = %s" % (n, cur.hex()))
        # 6139 отвечает тем же charId: sub_55DCB0 сверяет CUser+174h с ответом БД и шлёт 5 б {charId, флаг}
        ok(count_imm(img, base, RANGE_55DCB0[0], RANGE_55DCB0[1], 372) >= 1, "sub_55DCB0 читает CUser+0x174 (charId ответа 6139)")
        # 6140: тело ответа 6141 = [ebp-80h] (lea [ebp-80h] у всех стоковых отказов), код = [ebp-68h] (= тело +24, клиент a1+24)
        ok(len([h for h in find_all(img, base, "8d5580") if 0x0055D910 <= h < 0x0055DCB0]) >= 3 and
           len([h for h in find_all(img, base, "c64598") if 0x0055D910 <= h < 0x0055DCB0]) == 6,
           "6140: 6 стоковых отказов (коды 5,6,6,5,3,7) пишут код в [ebp-68h], тело [ebp-80h]")
    for name, path in GS_IMAGES:
        xpe, ximg, xbase = load(path)
        print("-- переходы/abs32 внутрь площадок (%s)" % name)
        for n, c in scan_into(xpe, ximg, xbase, GS_SITES).items():
            ok(c == 0, "%-14s входов внутрь: %d" % (n, c))
    pe, img, base = gs_ref
    print("-- границы инструкций (сток) и соседство с P63")
    for n, va, o in GS_SITES:
        s, e = boundary_ok(img, base, va, len(bytes.fromhex(o)))
        ok(s and e, "%-14s 0x%08X: начало %s, конец %s" % (n, va, s, e))
        ok(all(not (va < pv + pl and pv < va + 5) for pv, pl in P63_SITES), "%-14s не пересекается с площадками P63" % n)
    for va in BOUNDARY_EXTRA:
        s, _ = boundary_ok(img, base, va, 1)
        ok(s, "цель перехода 0x%08X на границе инструкции" % va)
    # между площадкой 6140 и хвостом отказа стек одинаковый: оба после стоковых проверок, до push аргументов хвост
    # строит свой кадр вызова сам; эпилог 0x55DC9D восстанавливает esp из ebp — проверяем `mov esp, ebp` в эпилогах.
    ep = disasm(img, base, 0x0055DC9D, 16)
    ok(any(i.mnemonic == "mov" and i.op_str == "esp, ebp" for i in ep), "эпилог 6140 0x55DC9D: mov esp, ebp")
    ep = disasm(img, base, 0x0055D8FC, 16)
    ok(any(i.mnemonic == "mov" and i.op_str == "esp, ebp" for i in ep), "эпилог 6138 0x55D8FC: mov esp, ebp")

    print("-- стабы в %s" % dll)
    lpe, limg, lbase = load(dll)
    lo, hi = lbase, lbase + len(limg)
    from asdamap import DllMap, map_matches_dll, resolve
    dmap = DllMap(dll)
    ok(map_matches_dll(dmap, lpe), "MAP %s от той же сборки, что DLL (метка 0x%08X)" % (dmap.map_path, dmap.stamp or 0))
    cands = [a for a in find_all(limg, lbase, "6055e8")
             if bytes(limg[a - lbase + 7: a - lbase + 14]) == bytes.fromhex("8944241c6185c0") and limg[a - lbase + 14] == 0x75]
    stubs = {}
    want = {
        "St_Name6138": ([MEMCPY, 0x0055D8FC], "P68_OnName6138"),
        "St_Name6140": ([MEMCPY, 0x0055DAA2], "P68_OnName6140"),
        "St_Keep2453": ([MEMCPY], "P68_OnName2453"),
    }
    cfun = {}
    for sname, (jw, cname) in want.items():
        va, good, msg = resolve(dmap, sname, "p68_char_name_guard", cands)
        ok(good, msg)
        if not va:
            continue
        stubs[sname] = va
        jmps, calls, icalls = stub_targets(limg, lbase, va, len(jw))
        ok(jmps == jw, "%s: jmp [..] -> %s (ожид. %s)" % (sname, ["0x%08X" % x for x in jmps], ["0x%08X" % x for x in jw]))
        try:
            cva = dmap.sym(cname, "p68_char_name_guard")
        except ValueError:
            cva = None
        ok(len(calls) == 1 and lo <= calls[0] < hi and calls[0] == cva, "%s: call C-функции %s внутри DLL (MAP 0x%08X)" % (sname, cname, cva or 0))
        if calls:
            cfun[sname] = calls[0]
    ins = disasm(limg, lbase, stubs.get("St_Name6140", lbase), 0x40)
    ok(any(i.mnemonic == "mov" and i.op_str == "byte ptr [ebp - 0x68], 0" for i in ins), "St_Name6140: код 6141 = 0 в [ebp-68h] перед хвостом")

    print("-- эмуляция стабов (C-функции и memcpy заменены заглушками)")
    emu = Emu(img, base, limg, lbase)
    FRAME, ESP0 = 0x001E0000, 0x001C0000
    REGS0 = {UC_X86_REG_EBX: 0x1111, UC_X86_REG_ESI: 0x2222, UC_X86_REG_EDI: 0x3333}

    def regs_kept():
        return (emu.r(UC_X86_REG_EBX) == 0x1111 and emu.r(UC_X86_REG_ESI) == 0x2222 and emu.r(UC_X86_REG_EDI) == 0x3333
                and emu.r(UC_X86_REG_EBP) == FRAME)

    cases = [
        ("St_Name6138", 0x0055D8D3, 0x0055D8FC, "эпилог 6138"),
        ("St_Name6140", 0x0055DC71, 0x0055DAA2, "хвост отказа 6141"),
        ("St_Keep2453", 0x0055DFE4, 0x0055DFE4, "возврат без копии"),
    ]
    for sname, ret, refuse_to, refuse_txt in cases:
        if sname not in stubs:
            continue
        for verdict in (0, 1):
            seen = {}
            def fake_memcpy(uc, a, sp):
                seen["memcpy"] = a
                return a[0]
            def fake_c(uc, a, sp, v=verdict):
                seen["c"] = a
                return v
            # memcpy — cdecl: заглушка Emu снимает nb байт аргументов, поэтому nb=0 и аргументы читаем со стека сами
            def fake_memcpy0(uc, a, sp):
                seen["memcpy"] = struct.unpack("<III", uc.mem_read(sp, 12))
                return seen["memcpy"][0]
            emu.fake = {MEMCPY: (0, fake_memcpy0), cfun[sname]: (4, fake_c)}
            emu.stops = {ret, refuse_to}
            sp = ESP0 - 16
            mem = [(sp, struct.pack("<IIII", ret, 0x00AA0000, 0x00BB0000, 20)), (FRAME - 0x68, b"\x05")]
            regs = dict(REGS0); regs.update({UC_X86_REG_EBP: FRAME, UC_X86_REG_ESP: sp, UC_X86_REG_ECX: 0xC0C0, UC_X86_REG_EAX: 0x77})
            at = emu.run(stubs[sname], regs, mem)
            ok(seen.get("c") == (FRAME,), "%s вердикт=%d: C-функция получила ebp кадра" % (sname, verdict))
            if verdict == 0:
                ok(at == ret and emu.r(UC_X86_REG_ESP) == sp + 4, "  пропуск: сток memcpy, возврат на 0x%08X, esp = после call (аргументы снимет вызывающий): at=0x%08X"
                   % (ret, at or 0))
                ok(seen.get("memcpy") == (0x00AA0000, 0x00BB0000, 20), "  memcpy получил те же 3 аргумента (dst, src, 20)")
            else:
                if sname == "St_Keep2453":
                    ok(at == ret and emu.r(UC_X86_REG_ESP) == sp + 4 and "memcpy" not in seen,
                       "  пропуск копии: memcpy НЕ вызван, ret на 0x%08X, esp = после call" % ret)
                else:
                    ok(at == refuse_to and emu.r(UC_X86_REG_ESP) == sp + 16 and "memcpy" not in seen,
                       "  отказ: %s 0x%08X, адрес возврата и 3 аргумента сняты, memcpy не вызван (at=0x%08X)" % (refuse_txt, refuse_to, at or 0))
                    if sname == "St_Name6140":
                        ok(bytes(emu.uc.mem_read(FRAME - 0x68, 1)) == b"\x00", "  код ответа 6141 [ebp-68h] = 0")
            ok(regs_kept(), "  ebx/esi/edi/ebp сохранены")

    print("=== ИТОГ: %s ===" % ("ВСЁ СОШЛОСЬ" if bad == 0 else "ОШИБОК %d" % bad))
    return 1 if bad else 0


def main():
    dll = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
    return verify_binary(dll)


if __name__ == "__main__":
    sys.exit(main())
