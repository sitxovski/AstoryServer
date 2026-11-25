# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stand_n22.py — СТЕНД N22 (31.10.2026, bug-quest-follow): площадки адреса ячейки Process_Quest / Start_Quest — эмуляция Unicorn.
#   Сервер НЕ запускается. Образ NpcServer (IDB d292e4ec = .text живого) и собранная AddonNPC.dll отображаются в эмулятор
#   по своим базам; кадр функции собирается на стеке из НАСТОЯЩИХ записей QuestNpcTable (выход генератора данных).
#   Один и тот же кадр прогоняется дважды: сток (0x420D3A…0x420D54 / 0x42112E…0x42114A — до конца копии ячейки) и патч
#   (на площадке `call` в TakeCellEsi/GiveCellEsi DLL + 10 nop). Сравнивается: esi после копии, 88/86 скопированных байт
#   буфера ячейки, ebx/ebp/esp/edi; путь слота ≥ 10 — аргументы N22CellExt (вид, npc, слот) и скопированная ячейка таблицы
#   расширения; ячейки нет — адрес g_emptyCell.
# Запуск: py -3 stand_n22.py [AddonNPC.dll]
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

HERE = os.path.dirname(os.path.abspath(__file__))
DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "AddonNPC.dll")
MAP = os.path.splitext(DLL)[0] + ".map"
EXE = r"@@ASTORY_DEV_ROOT@@\RE\ida\npc_work\NpcServer.exe"
DATA = os.path.join(HERE, "..", "..", "AsdaPatch", "tools", "data_quest_turnin")
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "AsdaReborn", "Tools"))
import asda_quest_cells_ext as QX

NPC_REC = 1774
STACK, STACK_SZ, ESP0 = 0x00100000, 0x20000, 0x00110000
CELLBUF = 0x00200000                    # сюда подставляется ячейка, которую «вернула» N22CellExt
# (имя, площадка, конец прогона, копия записи, смещение ячеек в записи, размер ячейки, [esp+npc], [esp+слот], буфер, вид, символ)
KINDS = [
    ("Process_Quest «ПРИНИМАЕТ»", 0x420D3A, 0x420D54, 0x128, 894, 88, 0x28, 0x2A, 0x38, 1, "TakeCellEsi"),
    ("Start_Quest «ВЫДАЁТ»", 0x42112E, 0x42114A, 0x120, 34, 86, 0x24, 0x26, 0x30, 0, "GiveCellEsi"),
]
bad = 0


def ok(cond, msg):
    global bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if not cond:
        bad += 1


def mapimg(uc, path):
    pe = pefile.PE(path)
    img = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    size = (len(img) + 0xFFF) & ~0xFFF
    uc.mem_map(base, size)
    uc.mem_write(base, img)
    return base


mp = open(MAP, encoding="latin-1").read()


def sym(rx):
    m = re.search(r"^\s*\w+:\w+\s+(%s)\s+([0-9a-f]{8}) " % rx, mp, re.M)
    return int(m.group(2), 16) if m else 0


S_EXT = sym(r"\?N22CellExt@\S+")
S_EMPTY = sym(r"\?g_emptyCell@\S+")
qnt = open(os.path.join(DATA, "QuestNpcTable.Bin"), "rb").read()
ext = QX.parse(open(os.path.join(DATA, QX.FILE_NAME), "rb").read())


def run(kind, patched, npc, slot, ext_cell=None):
    """Один прогон кадра. ext_cell: bytes — подставить как результат N22CellExt (перехват); None — исполнить её по-настоящему."""
    name, site, end, reccopy, celloff, cellsz, onpc, oslot, obuf, kd, thunk = kind
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    mapimg(uc, EXE)
    if patched:
        mapimg(uc, DLL)
        tva = sym(r"\?%s@\S+" % thunk)
        uc.mem_write(site, b"\xE8" + struct.pack("<i", tva - (site + 5)) + b"\x90" * 10)
    uc.mem_map(STACK, STACK_SZ)
    uc.mem_map(CELLBUF, 0x1000)
    rec = qnt[npc * NPC_REC:(npc + 1) * NPC_REC]
    uc.mem_write(ESP0 + reccopy, rec)
    uc.mem_write(ESP0 + obuf, b"\xCC" * 96)
    uc.mem_write(ESP0 + onpc, struct.pack("<hh", npc, slot))
    regs = {UC_X86_REG_EAX: 0xA0A0A0A0, UC_X86_REG_EBX: 0xB1B1B1B1, UC_X86_REG_ECX: 0xC2C2C2C2, UC_X86_REG_EDX: 0xD3D3D3D3,
            UC_X86_REG_ESI: 0x5E5E5E5E, UC_X86_REG_EDI: 0x7D7D7D7D, UC_X86_REG_EBP: 0xE4E4E4E4, UC_X86_REG_ESP: ESP0}
    for r, v in regs.items():
        uc.reg_write(r, v)
    args = []
    if patched and ext_cell is not None:
        uc.mem_write(CELLBUF, ext_cell + bytes(96 - len(ext_cell)))

        def hook(u, addr, size, _):
            if addr == S_EXT:
                sp = u.reg_read(UC_X86_REG_ESP)
                ret, a, b, c = struct.unpack("<Iiii", u.mem_read(sp, 16))
                args.append((a, b, c))
                u.reg_write(UC_X86_REG_EAX, CELLBUF)
                u.reg_write(UC_X86_REG_ESP, sp + 4)
                u.reg_write(UC_X86_REG_EIP, ret)
        uc.hook_add(UC_HOOK_CODE, hook, begin=S_EXT, end=S_EXT)
    uc.emu_start(site, end, count=10000)
    out = dict(esi=uc.reg_read(UC_X86_REG_ESI), ebx=uc.reg_read(UC_X86_REG_EBX), ebp=uc.reg_read(UC_X86_REG_EBP),
               esp=uc.reg_read(UC_X86_REG_ESP), edi=uc.reg_read(UC_X86_REG_EDI),
               buf=bytes(uc.mem_read(ESP0 + obuf, cellsz)), args=args)
    return out


print("== стенд N22: образ %s, DLL %s" % (os.path.basename(EXE), DLL))
ok(S_EXT and S_EMPTY, "символы .map: N22CellExt @%08X, g_emptyCell @%08X" % (S_EXT, S_EMPTY))
# NPC с непустыми ячейками: Эллоса 56 (все 10 «ПРИНИМАЕТ» заняты), 92, 131, 91, 25, 108; плюс пустая позиция 44.
NPCS = [56, 92, 131, 91, 25, 108, 44]
for kind in KINDS:
    name, cellsz = kind[0], kind[5]
    same = 0
    total = 0
    for npc in NPCS:
        for slot in range(10):
            a = run(kind, False, npc, slot)
            b = run(kind, True, npc, slot)
            total += 1
            eq = all(a[k] == b[k] for k in ("esi", "buf", "ebx", "ebp", "esp", "edi"))
            same += eq
            if not eq:
                ok(False, "%s npc %d слот %d: сток %s / патч %s" % (name, npc, slot,
                   {k: (hex(a[k]) if k != "buf" else a[k][:8].hex()) for k in ("esi", "ebx", "ebp", "esp", "edi", "buf")},
                   {k: (hex(b[k]) if k != "buf" else b[k][:8].hex()) for k in ("esi", "ebx", "ebp", "esp", "edi", "buf")}))
    ok(same == total, "%s: слоты 0…9 у %d NPC — esi после копии, %d б ячейки, ebx/ebp/esp/edi совпали со стоком в %d из %d"
       % (name, len(NPCS), cellsz, same, total))
    # Слот ≥ 10 — ячейка таблицы расширения (перехват N22CellExt: проверяем аргументы и что скопировано именно её содержимое).
    for x in [r for r in ext if r["kind"] == kind[9]]:
        b = run(kind, True, x["npc"], x["slot"], ext_cell=x["cell"])
        ok(b["args"] == [(kind[9], x["npc"], x["slot"])] and b["buf"] == x["cell"][:cellsz] and b["esi"] == CELLBUF + cellsz
           and b["ebx"] == 0xB1B1B1B1 and b["ebp"] == 0xE4E4E4E4 and b["esp"] == ESP0,
           "%s npc %d слот %d: N22CellExt(%s), скопирована ячейка задания %d, ebx/ebp/esp сохранены"
           % (name, x["npc"], x["slot"], b["args"], QX.cell_quest(x)))
    # Слот ≥ 10 без ячейки — N22CellExt исполняется по-настоящему (таблица в эмуляторе пуста) → адрес g_emptyCell.
    b = run(kind, True, 92, 11)
    ok(b["esi"] == S_EMPTY + cellsz and b["esp"] == ESP0 and b["ebx"] == 0xB1B1B1B1 and b["ebp"] == 0xE4E4E4E4,
       "%s npc 92 слот 11 (ячейки нет): копия из g_emptyCell (esi после копии 0x%X), ebx/ebp/esp сохранены" % (name, b["esi"]))

print("== ИТОГ stand_n22: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
sys.exit(1 if bad else 0)
