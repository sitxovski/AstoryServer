# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p107.py — СТАТИЧЕСКАЯ проверка P107 «оглушённый не атакует и не применяет навыки» (05.11.2026, сессия stun-attack).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Ch2_GameServer / Indun_GameServer — зеркало стойки,
#      stack_layout.EXE_MD5): шесть сверяемых участков P107 совпадают байт в байт; R1/R2/J12 на границах инструкций (линейный
#      дизасм sub_484E40 0x484E40…0x484F5E); сплошной перебор переходов rel8/rel32/jcc32 по .text: внутрь R1 0x484EBC…0x484EE0 и
#      R2 0x484EF0…0x484F12 переходов нет, кроме стоковых внутренних целей самих R1/R2 (0x484ECF/0x484EDF/0x484F01/0x484F11),
#      которые P107 заменяет целиком.
#   2. Вторым методом (эмуляция всей функции с входа, Unicorn x86-32; GetUser sub_5324A0 — заглушка, возвращающая тестовый
#      CUser): 256 сочетаний состояний {0,1,3,4,8,11,12,14} × навык a3 ∈ {−1, 736, 984, 500}: сток — ровно модель стока
#      (3/4 → 0 всегда), P107 — модель исправления (3/4 → 1, кроме 736/984; 14 → 1); выход — только через эпилог ret 8.
#   3. DLL: строки секции/реестра «P107_CantActGate» и журнала «P107: гейт»; байты исходника = расчёт p107_data/p107_bytes.py;
#      площадок других патчей в 0x484E40…0x484F5E нет.
# Запуск: py -3.13 verify_p107.py [AsdaPatch.dll]
import glob
import hashlib
import importlib.util
import itertools
import os
import re
import struct
import sys

sys.dont_write_bytecode = True
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_ECX, UC_X86_REG_EAX

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                       # единый состав стойки и md5 образов
from srv_paths import ROOT as SRV         # корень зеркала стойки

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
SRC = os.environ.get("ASDA_P107_SRC") or os.path.join(HERE, "..", "src", "patches", "p107_cant_act_gate.cpp")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x484E40, 0x484F5E
GETUSER = 0x5324A0
STATE_OFF = {0: 0x8F1E, 1: 0x8F36, 3: 0x8F66, 4: 0x8F7E, 8: 0x8FDE, 11: 0x9026, 12: 0x903E, 14: 0x906E}   # байт «активно» CUser


def _load_bytes():
    """Модуль расчёта байтов P107 (p107_data/p107_bytes.py)."""
    spec = importlib.util.spec_from_file_location("p107_bytes", os.path.join(HERE, "p107_data", "p107_bytes.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PB = _load_bytes()
R1NEW, R2NEW, J12NEW = PB.build()
SITES_ORIG = {   # va → байты стока (те же, что сверяет P107_CantActGate)
    0x484EBB: "0FBF450C3DE0020000740933C0E98B000000EB100FBF4D0C81F9D8030000740433C0EB79EB75",
    0x484EEF: "0FBF4D0C81F9E0020000740633C0EB59EB100FBF550C81FAD8030000740433C0EB47EB43",
    0x484F4D: "7E07",
    0x484EAD: "8B4DFC0FB691668F000085D27E26",
    0x484EE1: "8B55FC0FB6827E8F000085C07E24",
    0x484F44: "0FB6913E900000" "85D27E07B801000000EB0233C08BE55DC20800",
}
R1, R1_END, R2, R2_END, J12 = PB.R1, PB.R1_END, PB.R2, PB.R2_END, PB.J12
OLD_INNER = {0x484ECF, 0x484EDF, 0x484F01, 0x484F11}   # стоковые цели внутри R1/R2 (их ветки P107 переписывает целиком)

OK = 0
BAD = 0


def check(cond, what):
    """Строка «[OK]/[FAIL] что» и счётчики."""
    global OK, BAD
    if cond:
        OK += 1
        print("[OK]   " + what)
    else:
        BAD += 1
        print("[FAIL] " + what)


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


class Img:
    """Образ exe: чтение по VA."""

    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = bytearray(self.pe.get_memory_mapped_image())

    def rd(self, va, n):
        """n байт по VA."""
        return bytes(self.data[va - self.base: va - self.base + n])

    def wr(self, va, b):
        """Запись байтов по VA (копия в памяти)."""
        self.data[va - self.base: va - self.base + len(b)] = b

    def text(self):
        """(va начала, байты) секции .text."""
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".text":
                va = self.base + s.VirtualAddress
                return va, bytes(self.data[s.VirtualAddress: s.VirtualAddress + s.Misc_VirtualSize])
        raise RuntimeError("нет .text")


def jump_sources(img):
    """(источник, цель) всех переходов rel8/rel32/jcc32/call по .text (сплошной перебор опкодов)."""
    va0, t = img.text()
    out = []
    for i in range(len(t) - 6):
        b = t[i]
        if 0x70 <= b <= 0x7F or b == 0xEB:
            out.append((va0 + i, va0 + i + 2 + struct.unpack_from("<b", t, i + 1)[0]))
        elif b in (0xE8, 0xE9):
            out.append((va0 + i, va0 + i + 5 + struct.unpack_from("<i", t, i + 1)[0]))
        elif b == 0x0F and 0x80 <= t[i + 1] <= 0x8F:
            out.append((va0 + i, va0 + i + 6 + struct.unpack_from("<i", t, i + 2)[0]))
    return out


def insns(img, lo, hi):
    """Линейный дизасм функции."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(img.rd(lo, hi - lo), lo))


def model_stock(st, a3):
    """Сток sub_484E40 (по дизасму)."""
    if 0 in st or 1 in st:
        return 1
    if 3 in st or 4 in st:
        return 0
    return 1 if (8 in st or 11 in st or 12 in st) else 0


def model_p107(st, a3):
    """P107: 3/4 — только 736/984; 14 — нельзя."""
    if 0 in st or 1 in st:
        return 1
    if (3 in st or 4 in st) and a3 not in (736, 984):
        return 1
    if (3 not in st and 4 not in st) and (8 in st or 11 in st or 12 in st):
        return 1
    return 1 if 14 in st else 0


def emulate(img, states, a3):
    """Вызов sub_484E40(this, a2 = 5, a3) с входа; GetUser → тестовый CUser с байтами состояний. (eax, адрес выхода)."""
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    size = (len(img.data) + 0xFFF) & ~0xFFF
    mu.mem_map(img.base, size, UC_PROT_ALL)
    mu.mem_write(img.base, bytes(img.data))
    heap = 0x20000000
    mu.mem_map(heap, 0x40000)
    user = heap + 0x10000
    for s in states:
        mu.mem_write(user + STATE_OFF[s], b"\x01")
    this, thr = heap + 0x100, heap + 0x200
    mu.mem_write(this + 4, struct.pack("<I", thr))
    mu.mem_write(thr + 0x34, struct.pack("<I", heap + 0x300))
    stack = 0x30000000
    mu.mem_map(stack, 0x10000)
    esp = stack + 0x8000
    sentinel = 0x40000000
    mu.mem_map(sentinel, 0x1000)
    mu.mem_write(sentinel, b"\xCC")
    # thiscall: ecx = this, стек: ret, a2, a3 (callee чистит 8)
    esp -= 4; mu.mem_write(esp, struct.pack("<i", a3))
    esp -= 4; mu.mem_write(esp, struct.pack("<i", 5))
    esp -= 4; mu.mem_write(esp, struct.pack("<I", sentinel))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_ECX, this)
    res = {}

    def on_code(uc, addr, sz, _):
        """GetUser — заглушка (ret 4, eax = CUser); выход на страж — стоп; вне функции — стоп."""
        if addr == GETUSER:
            sp = uc.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", uc.mem_read(sp, 4))[0]
            uc.reg_write(UC_X86_REG_EAX, user)
            uc.reg_write(UC_X86_REG_ESP, sp + 8)
            uc.reg_write(UC_X86_REG_EIP, ret)
            return
        if addr == sentinel:
            res["eax"] = uc.reg_read(UC_X86_REG_EAX)
            res["esp"] = uc.reg_read(UC_X86_REG_ESP)
            uc.emu_stop()
            return
        if not (FUNC <= addr < FUNC_END):
            res["out"] = addr
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_code)
    try:
        mu.emu_start(FUNC, sentinel + 1, count=400)
    except Exception as e:
        res["err"] = str(e)
    ok_exit = "eax" in res and res.get("esp") == esp + 12 and "out" not in res and "err" not in res
    return (res.get("eax", -1), ok_exit, res)


def check_image(name, path):
    """Пункты 1–2 для одного образа."""
    img = Img(path)
    for va, hx in SITES_ORIG.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X (%d б) совпадает" % (name, va, len(hx) // 2))
    ins = insns(img, FUNC, FUNC_END)
    starts = {i.address for i in ins}
    check(all(a in starts for a in (R1, R1_END, R2, R2_END, J12, J12 + 2)) and ins[-1].mnemonic == "ret" and ins[-1].address + ins[-1].size == FUNC_END,
          "%s: R1/R2/J12 на границах инструкций; функция кончается ret 8 @0x%06X" % (name, FUNC_END - 3))
    js = jump_sources(img)
    inside = lambda t: (R1 < t < R1_END) or (R2 < t < R2_END)
    from_out = sorted((s, t) for s, t in js if inside(t) and not (FUNC <= s < FUNC_END))
    inner = sorted({t for s, t in js if inside(t) and FUNC <= s < FUNC_END and s in starts})
    check(not from_out, "%s: переходов извне функции внутрь R1/R2 нет (%s)" % (name, ", ".join("0x%06X→0x%06X" % x for x in from_out) or "0"))
    check(set(inner) <= OLD_INNER, "%s: внутренние цели R1/R2 — только стоковые ветки 3/4 (%s)" % (name, ", ".join("0x%06X" % t for t in inner)))
    stock_bad, fix_bad, exits_bad = [], [], 0
    fixed = Img(path)
    fixed.wr(R1, R1NEW); fixed.wr(R2, R2NEW); fixed.wr(J12, J12NEW)
    keys = sorted(STATE_OFF)
    for mask in range(256):
        st = {keys[i] for i in range(8) if mask >> i & 1}
        for a3 in (-1, 736, 984, 500):
            e0, x0, _ = emulate(img, st, a3)
            e1, x1, _ = emulate(fixed, st, a3)
            exits_bad += (not x0) + (not x1)
            if e0 != model_stock(st, a3):
                stock_bad.append((sorted(st), a3, e0))
            if e1 != model_p107(st, a3):
                fix_bad.append((sorted(st), a3, e1))
    check(exits_bad == 0, "%s: эмуляция — все 2048 вызовов выходят через ret 8 (esp +12)" % name)
    check(not stock_bad, "%s: эмуляция стока = модель стока (3/4 → 0 всегда) на 1024 случаях%s" % (name, (" — " + str(stock_bad[:4])) if stock_bad else ""))
    check(not fix_bad, "%s: эмуляция P107 = модель исправления на 1024 случаях%s" % (name, (" — " + str(fix_bad[:4])) if fix_bad else ""))
    # ключевые случаи — в журнал
    for st, a3 in (({3}, -1), ({3}, 736), ({4}, 984), ({14}, -1), ({3, 8}, -1), (set(), -1)):
        print("       %s a3=%d: сток %d, P107 %d" % (sorted(st), a3, emulate(img, st, a3)[0], emulate(fixed, st, a3)[0]))
    ins2 = insns(fixed, FUNC, FUNC_END)
    t1 = {i.address: (i.mnemonic, i.op_str) for i in ins if not (R1 <= i.address < R1_END or R2 <= i.address < R2_END or i.address == J12)}
    t2 = {i.address: (i.mnemonic, i.op_str) for i in ins2 if not (R1 <= i.address < R1_END or R2 <= i.address < R2_END or i.address == J12)}
    check(t1 == t2, "%s: после P107 прочие %d инструкций функции и их границы без изменений" % (name, len(t1)))


def main():
    print("verify_p107: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P107."""
        m = re.search(r"const BYTE %s\[\]\s*=\s*\{([^}]*)\}" % name, s)
        return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1))) if m else b""

    check(arr("kR1New") == R1NEW and arr("kR2New") == R2NEW and arr("kJ12New") == J12NEW, "исходник: kR1New / kR2New / kJ12New = p107_bytes.build()")
    check(all(arr(n).hex().upper() == SITES_ORIG[va] for n, va in (("kR1Orig", R1), ("kR2Orig", R2), ("kJ12Orig", J12), ("kIn3", 0x484EAD),
                                                                       ("kIn4", 0x484EE1), ("kTail", 0x484F44))),
          "исходник: байты стока = байты этой проверки")
    d = open(DLL, "rb").read()
    check("P107_CantActGate".encode("utf-16-le") in d, "DLL: секция/реестр P107_CantActGate")
    check("P107: гейт".encode("utf-16-le") in d, "DLL: строка журнала P107")
    hits = []
    for p in glob.glob(os.path.join(HERE, "..", "src", "patches", "*.cpp")):
        if os.path.basename(p).startswith("p107_"):
            continue
        t = open(p, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x00(48[45][0-9A-Fa-f]{3})\b", t):
            v = int(m.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(p), v))
    check(not hits, "площадок других патчей в 0x%06X…0x%06X нет (%s)" % (FUNC, FUNC_END, ", ".join(sorted(set(hits))) or "0"))
    print("verify_p107 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
