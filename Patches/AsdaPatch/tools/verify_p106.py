# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_p106.py — СТАТИЧЕСКАЯ проверка P106 «принявший дружбу получает 4151 при флаге 2 UPFriendAdd» (05.11.2026, friend-accept).
#   1. Образы GameServer (сток gs_stock.exe; живые GameServer / Indun_GameServer / Ch2_GameServer = e7b4ac38 — зеркало стойки и
#      stack_layout.EXE_MD5): все 6 сверяемых P106 участков совпадают байт в байт; участок 0x406520 (22 б) начинается и кончается
#      на границе инструкций (линейный дизасм sub_406370 0x406370…0x40662D); сплошной перебор переходов rel8/rel32/jcc32 по .text:
#      ни один переход не ведёт внутрь 0x406521…0x406535 (на 0x406536 — законно: цель стокового je).
#   2. Вторым методом (дизасм, не декомпил): вход ветки успеха 0x4063A8 — флаги 1/2/3; 4151 (0x1037, длина 0x20) пригласившему
#      — получатель [ebp+8] (0x406509), принявшему — [ebp-2Bh] = блок+9 (0x406606); сток: `cmp eax,1; je 0x406536; cmp ecx,3;
#      jne 0x40661D`. Эмуляция участка (Unicorn, x86-32) для флагов 0…7, сток против P106: сток идёт в ветку принявшего
#      (0x406536) только при 1 и 3, P106 — при 1, 2, 3; иначе оба — на эпилог 0x40661D.
#   3. После P106 (в памяти копии образа): прочие инструкции функции и их границы без изменений.
#   4. DLL: строки секции/реестра «P106_FriendAcceptNotify» и журнала «P106: ответ дружбы»; байты kCond/kNew в исходнике = SITE/NEW
#      здесь; площадок других патчей в 0x406370…0x40662D нет.
# Запуск: py -3.13 verify_p106.py [AsdaPatch.dll]
import glob
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                       # единый состав стойки и md5 образов
from srv_paths import ROOT as SRV         # корень зеркала стойки

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AsdaPatch.dll")
SRC = os.environ.get("ASDA_P106_SRC") or os.path.join(HERE, "..", "src", "patches", "p106_friend_accept_notify.cpp")   # ASDA_P106_SRC — копия исходника вне дерева
STOCK = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img\gs_stock.exe"
FUNC, FUNC_END = 0x406370, 0x40662D
SITE = 0x406520
COND = "0FB645CC83F801740D0FB64DCC83F9030F85E7000000"      # условие стока (22 б)
NEW = "0FB645CC4883F8020F87EF0000000F1F840000000000"       # P106 (22 б)
TAKEN, EPI = 0x406536, 0x40661D                             # ветка принявшего / эпилог
SITES = {   # va → байты (те же, что сверяет P106_FriendAcceptNotify)
    SITE: COND,
    0x4063A8: "0FB655CC83FA01743C0FB645CC83F80274330FB64DCC83F903742A",
    0x406509: "668B4D08516A206837100000",
    0x406536: "C745A400000000668B550852",
    0x406606: "668B55D5526A206837100000",
    0x40661D: "8B4DFC33CD",
}

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

    def text(self):
        """(va начала, байты) секции .text."""
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".text":
                va = self.base + s.VirtualAddress
                return va, bytes(self.data[s.VirtualAddress: s.VirtualAddress + s.Misc_VirtualSize])
        raise RuntimeError("нет .text")


def jump_targets(img):
    """Все цели rel8/rel32 переходов и call по .text (сплошной перебор опкодов, как verify_p99)."""
    va0, t = img.text()
    out = set()
    for i in range(len(t) - 6):
        b = t[i]
        if 0x70 <= b <= 0x7F or b == 0xEB:
            out.add(va0 + i + 2 + struct.unpack_from("<b", t, i + 1)[0])
        elif b in (0xE8, 0xE9):
            out.add(va0 + i + 5 + struct.unpack_from("<i", t, i + 1)[0])
        elif b == 0x0F and 0x80 <= t[i + 1] <= 0x8F:
            out.add(va0 + i + 6 + struct.unpack_from("<i", t, i + 2)[0])
    return out


def insns(img, lo, hi):
    """Линейный дизасм функции."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(md.disasm(img.rd(lo, hi - lo), lo))


def emulate(code, flag):
    """Участок 0x406520 (22 б) на Unicorn: [ebp-34h] = flag → адрес, куда ушло управление (TAKEN / EPI / прочее)."""
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    page = SITE & ~0xFFF
    mu.mem_map(page, 0x2000)
    mu.mem_write(SITE, code)
    stack = 0x00100000
    mu.mem_map(stack, 0x10000)
    ebp = stack + 0x8000
    mu.reg_write(UC_X86_REG_EBP, ebp)
    mu.reg_write(UC_X86_REG_ESP, ebp - 0x60)
    mu.mem_write(ebp - 0x34, bytes([flag]))
    end = SITE + len(code)
    hit = {}

    def on_code(uc, addr, size, _):
        """Остановка на выходе из участка."""
        if addr < SITE or addr >= end:
            hit["to"] = addr
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_code)
    try:
        mu.emu_start(SITE, TAKEN + 0x200, count=64)
    except Exception as e:
        # выход за отображённую память (переход на 0x40661D вне страницы) — адрес берём из EIP
        hit.setdefault("to", mu.reg_read(UC_X86_REG_EIP))
    return hit.get("to", mu.reg_read(UC_X86_REG_EIP))


def check_image(name, path):
    """Пункты 1–3 для одного образа."""
    img = Img(path)
    for va, hx in SITES.items():
        check(img.rd(va, len(hx) // 2) == bytes.fromhex(hx), "%s: участок 0x%06X (%d б) совпадает" % (name, va, len(hx) // 2))
    ins = insns(img, FUNC, FUNC_END)
    starts = {i.address for i in ins}
    check(SITE in starts and SITE + 22 in starts and ins[-1].mnemonic == "ret" and ins[-1].address + ins[-1].size == FUNC_END,
          "%s: участок 0x%06X…0x%06X на границах инструкций; функция кончается ret 8 @0x%06X" % (name, SITE, SITE + 22, FUNC_END - 3))
    tg = jump_targets(img)
    bad = sorted(t for t in tg if SITE < t < SITE + 22)
    check(not bad, "%s: переходов внутрь участка нет (%s)" % (name, ", ".join("0x%06X" % b for b in bad) or "0"))
    txt = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins}
    check(txt.get(0x4063AC) == "cmp edx, 1" and txt.get(0x4063B5) == "cmp eax, 2" and txt.get(0x4063BE) == "cmp ecx, 3"
          and txt.get(0x4063C1) == "je 0x4063ed", "%s: вход ветки успеха — флаги 1/2/3" % name)
    check(txt.get(0x406509) == "mov cx, word ptr [ebp + 8]" and txt.get(0x406510) == "push 0x1037" and txt.get(0x40650E) == "push 0x20"
          and txt.get(0x40651B, "").startswith("call 0x4c28f0"), "%s: 4151 пригласившему ([ebp+8]) @0x40651B" % name)
    check(txt.get(0x406606) == "mov dx, word ptr [ebp - 0x2b]" and txt.get(0x40660D) == "push 0x1037"
          and txt.get(0x406618, "").startswith("call 0x4c28f0"), "%s: 4151 принявшему ([ebp-2Bh] = блок+9) @0x406618" % name)
    check(txt.get(0x406524) == "cmp eax, 1" and txt.get(0x406527) == "je 0x406536" and txt.get(0x40652D) == "cmp ecx, 3"
          and txt.get(0x406530) == "jne 0x40661d", "%s: сток: ветка принявшего только при флаге 1 и 3 — дефект" % name)
    # Эмуляция: сток против P106.
    stock = {f: emulate(bytes.fromhex(COND), f) for f in range(8)}
    fix = {f: emulate(bytes.fromhex(NEW), f) for f in range(8)}
    check(all(stock[f] == (TAKEN if f in (1, 3) else EPI) for f in range(8)),
          "%s: эмуляция стока — ветка принявшего при {1,3}, эпилог при 0,2,4…7 (%s)" % (name, ", ".join("%d→%X" % (f, stock[f]) for f in range(8))))
    check(all(fix[f] == (TAKEN if f in (1, 2, 3) else EPI) for f in range(8)),
          "%s: эмуляция P106 — ветка принявшего при {1,2,3}, эпилог при 0,4…7 (%s)" % (name, ", ".join("%d→%X" % (f, fix[f]) for f in range(8))))
    # После P106 — в памяти копии.
    img.data[SITE - img.base: SITE - img.base + 22] = bytes.fromhex(NEW)
    ins2 = insns(img, FUNC, FUNC_END)
    t2 = {i.address: "%s %s" % (i.mnemonic, i.op_str) for i in ins2}
    outside = [a for a in txt if not (SITE <= a < SITE + 22)]
    same = all(t2.get(a) == txt[a] for a in outside) and {a for a in t2 if not (SITE <= a < SITE + 22)} == set(outside)
    check(same and t2.get(0x406524) == "dec eax" and t2.get(0x406525) == "cmp eax, 2" and t2.get(0x406528) == "ja 0x40661d"
          and t2.get(0x40652E, "").startswith("nop"),
          "%s: после P106 — `dec eax; cmp eax,2; ja 0x40661D; nop8`, прочие %d инструкций и их границы без изменений" % (name, len(outside)))


def main():
    print("verify_p106: DLL %s md5 %s" % (DLL, md5(DLL)))
    imgs = [("сток", STOCK)] if os.path.exists(STOCK) else []
    for d in stack_layout.GS_FOLDERS:
        p = os.path.join(SRV, "v2", d, "GameServer.exe")
        imgs.append((d, p))
        check(md5(p) == stack_layout.EXE_MD5[d + r"\GameServer.exe"], "%s: образ зеркала = stack_layout.EXE_MD5" % d)
    for n, p in imgs:
        check_image(n, p)
    # Исходник: байты площадки = байты этой проверки.
    s = open(SRC, encoding="utf-8").read()

    def arr(name):
        """Байты массива `name` из исходника P106 (hex)."""
        m = re.search(r"const BYTE %s\[\]\s*=\s*\{([^}]*)\}" % name, s)
        return "".join("%02X" % int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1))) if m else ""

    check(arr("kCond") == COND and arr("kNew") == NEW, "исходник: kCond / kNew = байты verify_p106")
    # DLL.
    d = open(DLL, "rb").read()
    check("P106_FriendAcceptNotify".encode("utf-16-le") in d, "DLL: секция/реестр P106_FriendAcceptNotify")
    check("P106: ответ дружбы".encode("utf-16-le") in d, "DLL: строка журнала P106")
    # Других патчей в диапазоне функции нет.
    hits = []
    for p in glob.glob(os.path.join(HERE, "..", "src", "patches", "*.cpp")):
        if os.path.basename(p).startswith("p106_"):
            continue
        t = open(p, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"0x00(40[56][0-9A-Fa-f]{3})\b", t):
            v = int(m.group(1), 16)
            if FUNC <= v < FUNC_END:
                hits.append("%s:0x%06X" % (os.path.basename(p), v))
    check(not hits, "площадок других патчей в 0x%06X…0x%06X нет (%s)" % (FUNC, FUNC_END, ", ".join(sorted(set(hits))) or "0"))
    print("verify_p106 ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
