# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p118.py — СТАТИЧЕСКАЯ проверка P118 «обмен отменяется, пока игрок работает с аукционом» (09.11.2026, пачка 20, баг 3, жалоба 10;
#   AstoryServer/Docs/GameServer/auction-trade-block-p118.md).
#   1. Образы GameServer (сток 4e20f0ad; GameServer / Indun / Ch2 = stack_layout.EXE_MD5): все 13 площадок совпадают с исходником.
#   2. Дизасм стока: пять прологов — функции, которые зовёт диспетчер sub_42A9D0 (9901/9903/9905/9907/9909), SEH-imm в заглушках тот же;
#      CharExchangeReq: [ebp-34h]/[ebp-20h] — CUser заявителя/цели (sub_5324A0), блоки 0x4DFA15/0x4DFA52 пишут код 5/4 и шлют 5283
#      (0x14A3), внутрь 0x4DFA09…0x4DFA13 переходов нет; CharExchangeAcceptReq: [ebp-50h]/[ebp-44h] — CUser сторон, 0x4E004D шлёт 5285
#      (0x14A5) дважды ([ebp-47h] и arg0) с телом [ebp-38h], внутрь 0x4DFE27…0x4DFE31 переходов нет; sub_51A980: перед 0x51A9D6
#      push 0 / push a2 / push ecx(тело) / push a2 — тело на [esp+4].
#   3. Исходники других патчей не трогают диапазоны площадок P118.
#   4. DLL: экспорт P118_GetStats; заглушки — вызовы C-частей, переходы через ячейки на нужные адреса, повтор стоковых инструкций.
# Запуск: py -3.13 verify_p118.py [AsdaPatch.dll]
import hashlib
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                       # единый состав стойки и md5 образов
from srv_paths import ROOT as SRV         # корень зеркала стойки

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
SRC = os.path.join(HERE, "..", "src", "patches", "p118_auction_trade_block.cpp")
PATCH_DIR = os.path.join(HERE, "..", "src", "patches")
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
OK = 0
BAD = 0
MD = Cs(CS_ARCH_X86, CS_MODE_32)
PROLOGUES = {0x517AB0: ("kRegOrig", 9901, "St_Reg"), 0x519FB0: ("kInqOrig", 9903, "St_Inq"), 0x51A4E0: ("kMyOrig", 9907, "St_My"),
             0x51AA10: ("kBuyOrig", 9905, "St_Buy"), 0x51E380: ("kDelOrig", 9909, "St_Del")}
SITES = {va: v[0] for va, v in PROLOGUES.items()}
SITES.update({
    0x4DFA09: "kReqOrig", 0x4DFA13: "kReqTail", 0x4DFA52: "kReqTgtOrig",
    0x4DFE27: "kAccOrig", 0x4DFE31: "kAccTail", 0x4E004D: "kAccSendOrig",
    0x51A9D6: "kStormOrig", 0x51A9DD: "kStormTail"})


def check(cond, what):
    """Строка проверки и счёт."""
    global OK, BAD
    OK += bool(cond)
    BAD += not cond
    print(("  ok   " if cond else "  FAIL ") + what)


class Img:
    """Образ exe: чтение по VA."""
    def __init__(self, path):
        pe = pefile.PE(path, fast_load=True)
        self.b = pe.get_memory_mapped_image()
        self.base = pe.OPTIONAL_HEADER.ImageBase

    def rd(self, va, n):
        return self.b[va - self.base:va - self.base + n]

    def dis(self, va, n):
        return list(MD.disasm(self.rd(va, n), va))


def md5(p):
    """md5 файла."""
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def src_bytes(name):
    """Массив байт из исходника P118 по имени константы."""
    s = open(SRC, encoding="utf-8").read()
    m = re.search(r"const BYTE %s\[\d+\]\s*=\s*\{([^}]*)\}" % name, s)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


def no_jumps_into(ins, lo, hi):
    """Переходов внутрь (lo, hi) нет среди инструкций."""
    return [i for i in ins if i.mnemonic.startswith("j") and i.op_str.startswith("0x") and lo < int(i.op_str, 16) < hi]


def main():
    """Проверки и итог."""
    print("== 1. образы GameServer")
    imgs = {"сток": STOCK}
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
        imgs[d] = p
    for k, p in imgs.items():
        im = Img(p)
        for va, nm in sorted(SITES.items()):
            b = src_bytes(nm)
            check(im.rd(va, len(b)) == b, "%s: 0x%X = %s" % (k, va, nm))

    print("== 2. дизасм стока")
    im = Img(STOCK)
    disp = im.dis(0x42A9D0, 0x4700)
    called = {int(i.op_str, 16) for i in disp if i.mnemonic == "call" and i.op_str.startswith("0x")}
    for va, (_, op, _) in sorted(PROLOGUES.items()):
        check(va in called, "0x%X (%d) — обработчик, его зовёт диспетчер sub_42A9D0" % (va, op))
    req = im.dis(0x4DF830, 0x460)
    check(not no_jumps_into(req, 0x4DFA09, 0x4DFA13), "CharExchangeReq: переходов внутрь 0x4DFA09…0x4DFA13 нет")
    stores = [(i.address, i.op_str) for i in req if i.mnemonic == "mov" and i.op_str.startswith("dword ptr [ebp - 0x")]
    prev = {i.address: j for j, i in enumerate(req)}
    def after_getuser(var):
        for j, i in enumerate(req):
            if i.mnemonic == "mov" and i.op_str == "dword ptr [ebp - %s], eax" % var and j > 0 and req[j - 1].mnemonic == "call" \
                    and req[j - 1].op_str == "0x5324a0":
                return True
        return False
    check(after_getuser("0x34") and after_getuser("0x20"), "CharExchangeReq: [ebp-34h] и [ebp-20h] = CUser из sub_5324A0")
    for blk, code in ((0x4DFA15, 5), (0x4DFA52, 4)):
        b = im.dis(blk, 0x34)
        check(b[0].op_str == "byte ptr [ebp - 0x2e], %d" % code and any(i.op_str == "0x14a3" for i in b),
              "0x%X: код %d и 5283 (0x14A3)" % (blk, code))
    acc = im.dis(0x4DFC80, 0x410)
    check(not no_jumps_into(acc, 0x4DFE27, 0x4DFE31), "CharExchangeAcceptReq: переходов внутрь 0x4DFE27…0x4DFE31 нет")
    def acc_user(var):
        return any(acc[j].mnemonic == "mov" and acc[j].op_str == "dword ptr [ebp - %s], eax" % var and acc[j - 1].op_str == "0x5324a0"
                   for j in range(1, len(acc)))
    check(acc_user("0x50") and acc_user("0x44"), "CharExchangeAcceptReq: [ebp-50h] и [ebp-44h] = CUser из sub_5324A0")
    tail = im.dis(0x4E004D, 0x3E)
    check(sum(i.op_str == "0x14a5" for i in tail) == 2 and sum(i.op_str == "eax, [ebp - 0x38]" for i in tail) == 2,
          "0x4E004D: 5285 (0x14A5) дважды с телом [ebp-38h]")
    check(any(i.op_str == "cx, word ptr [ebp - 0x47]" for i in tail) and any(i.op_str == "cx, word ptr [ebp + 8]" for i in tail),
          "0x4E004D: адресаты — заявитель [ebp-47h] и согласившийся arg0")
    fw = im.dis(0x51A980, 0x80)
    seq = [(i.mnemonic, i.op_str) for i in fw if 0x51A9C0 <= i.address < 0x51A9D6]
    pushes = [o for m, o in seq if m == "push"]
    check(pushes[-4:] == ["0", "eax", "ecx", "edx"] and ("add", "ecx, 9") in seq,
          "sub_51A980: перед 0x51A9D6 push 0 / a2 / тело (ecx = пакет+9) / a2 — тело на [esp+4]")

    print("== 3. исходники других патчей")
    ranges = [(va, va + len(src_bytes(nm))) for va, nm in SITES.items()]
    hit = []
    for f in os.listdir(PATCH_DIR):
        if not f.endswith(".cpp") or f.startswith("p118"):
            continue
        text = open(os.path.join(PATCH_DIR, f), encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x00([0-9A-Fa-f]{6})\b", text):
            a = int(m.group(1), 16)
            # 0x4E004D — продолжение у P44 (не площадка, переход туда), его разрешаем.
            if a != 0x4E004D and any(lo <= a < hi for lo, hi in ranges):
                hit.append((f, m.group(0)))
    check(not hit, "другие патчи площадки P118 не трогают %s" % hit)

    print("== 4. DLL", os.path.basename(DLL), md5(DLL))
    pe = pefile.PE(DLL)
    exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    check(any("P118_GetStats" in e for e in exps), "экспорт P118_GetStats")
    txt = open(MAP, encoding="utf-8", errors="replace").read()
    b = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase

    def sym(rx):
        m = re.search(rx, txt)
        return int(m.group(1), 16) if m else 0

    def cells(seq):
        out = []
        for mnem, o in seq:
            if mnem == "jmp" and o.startswith("dword ptr ["):
                a = int(re.search(r"0x([0-9a-f]+)", o).group(1), 16)
                out.append(struct.unpack("<I", b[a - base:a - base + 4])[0])
        return out

    touch = sym(r"_P118_Touch@12\s+([0-9a-f]{8})")
    for va, (nm, op, st) in sorted(PROLOGUES.items()):
        a = sym(r"\?%s@\S+\s+([0-9a-f]{8})" % st)
        seq = [(i.mnemonic, i.op_str) for i in MD.disasm(b[a - base:a - base + 0x40], a)] if a else []
        stock = src_bytes(nm)
        seh = struct.unpack("<I", stock[6:10])[0]
        ok = bool(seq) and seq[0][0] == "pushfd" and seq[1][0] == "pushal" and ("push", hex(op)) in seq \
            and ("call", hex(touch)) in seq and ("push", "ebp") in seq and ("mov", "ebp, esp") in seq \
            and ("push", "-1") in seq and ("push", hex(seh)) in seq and cells(seq) == [va + 10]
        check(ok, "%s: метка %d, пролог стока (SEH 0x%X) и возврат 0x%X" % (st, op, seh, va + 10))
    for st, fn, want, extra in (("St_ReqGate", "_P118_ReqGate@4", [0x4DFA13, 0x4DFA15, 0x4DFA52],
                                 [("mov", "eax, dword ptr [ebp - 0x34]"), ("cmp", "dword ptr [eax + 0x145], 0")]),
                                ("St_AccGate", "_P118_AccGate@4", [0x4DFE31, 0x4E004D],
                                 [("mov", "ecx, dword ptr [ebp - 0x44]"), ("cmp", "dword ptr [ecx + 0x145], 0"), ("mov", "byte ptr [ebp - 0x38], 0")])):
        a = sym(r"\?%s@\S+\s+([0-9a-f]{8})" % st)
        g = sym(r"%s\s+([0-9a-f]{8})" % re.escape(fn))
        seq = [(i.mnemonic, i.op_str) for i in MD.disasm(b[a - base:a - base + 0x50], a)] if a else []
        check(bool(seq) and ("call", hex(g)) in seq and all(e in seq for e in extra) and sorted(cells(seq)) == sorted(want),
              "%s: вызов %s, стоковые инструкции, переходы %s" % (st, fn, [hex(x) for x in want]))
    a = sym(r"\?St_Storm@\S+\s+([0-9a-f]{8})")
    seq = [(i.mnemonic, i.op_str) for i in MD.disasm(b[a - base:a - base + 0x40], a)] if a else []
    check(("movsx", "eax, word ptr [ebp - 4]") in seq and ("sub", "eax, 0xa") in seq and ("mov", "eax, 0x3e") in seq
          and cells(seq) == [0x51A9DD], "St_Storm: длина 0 → тело 62 б, возврат 0x51A9DD")
    print("ИТОГ verify_p118 ok=%d fail=%d" % (OK, BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
