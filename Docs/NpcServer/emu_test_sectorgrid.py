# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Эмуляция cave-функции rebuild на реальном коде пропатченного NpcServer.exe."""
import struct, sys
from unicorn import *
from unicorn.x86_const import *

EXE = sys.argv[1] if len(sys.argv) > 1 else r'\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\NpcServer\NpcServer.exe'
data = open(EXE, 'rb').read()
TEXT = data[0x1000:0x1000+0x64000]

IMG = 0x400000
HEAP = 0x10000000
STACK = 0x20000000
SECSZ = 0x7F0
CAP = 324
REBUILD = 0x464977
STOP = 0x33330000

def run(mapw, maph, secw, sech):
    cx = -(-mapw // secw); cz = -(-maph // sech); cnt = cx * cz
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(IMG, 0x100000)
    mu.mem_write(IMG + 0x1000, TEXT)
    mu.mem_map(HEAP, 0x100000 * 8)
    mu.mem_map(STACK, 0x100000)
    mgr = HEAP
    pparr = HEAP + 0x100
    sec0 = HEAP + 0x1000
    # менеджер: +0 ppSector, +0x0C MapW, +0x10 MapH, +0x14 SecW, +0x18 SecH,
    #           +0x1C CountX, +0x20 CountZ, +0x24 Count
    m = bytearray(0x40)
    struct.pack_into('<I', m, 0x00, pparr)
    for off, v in ((0x0C, mapw), (0x10, maph), (0x14, secw), (0x18, sech),
                   (0x1C, cx), (0x20, cz), (0x24, cnt)):
        struct.pack_into('<i', m, off, v)
    mu.mem_write(mgr, bytes(m))
    mu.mem_write(pparr, b''.join(struct.pack('<I', sec0 + i * SECSZ) for i in range(CAP)))
    mu.reg_write(UC_X86_REG_ESP, STACK + 0x80000)
    mu.mem_write(STACK + 0x80000, struct.pack('<I', STOP))
    mu.reg_write(UC_X86_REG_ESI, mgr)
    mu.emu_start(REBUILD, STOP)
    res = []
    for i in range(cnt):
        b = mu.mem_read(sec0 + i * SECSZ, 0x7F0)
        idx, x, z = struct.unpack_from('<iii', b, 0x24)
        rect = struct.unpack_from('<4i', b, 0x7D0)
        erect = struct.unpack_from('<4i', b, 0x7E0)
        nb = struct.unpack_from('<9I', b, 0)
        nbi = [(-1 if p == 0 else (p - sec0) // SECSZ) for p in nb]
        res.append((idx, x, z, rect, erect, nbi))
    return cx, cz, cnt, res

def expect_neighbors(i, cx, cz):
    x, z = i % cx, i // cx
    d = [(0, -1), (1, -1), (1, 0), (1, 1), (0, 1), (-1, 1), (-1, 0), (-1, -1), (0, 0)]
    out = []
    for dx, dz in d:
        nx, nz = x + dx, z + dz
        out.append(nz * cx + nx if 0 <= nx < cx and 0 <= nz < cz else -1)
    return out

for secw in (30, 64, 256):
    cx, cz, cnt, res = run(512, 512, secw, secw)
    bad = 0
    for i, (idx, x, z, rect, erect, nbi) in enumerate(res):
        exp_nb = expect_neighbors(i, cx, cz)
        ex_rect = (x * secw, z * secw, min((x + 1) * secw - 1, 511), min((z + 1) * secw - 1, 511))
        ex_er = (max(ex_rect[0] - secw, 0), max(ex_rect[1] - secw, 0),
                 min(ex_rect[2] + secw, 511), min(ex_rect[3] + secw, 511))
        if idx != i or x != i % cx or z != i // cx or nbi != exp_nb or rect != ex_rect or erect != ex_er:
            bad += 1
            if bad <= 3:
                print('  MISMATCH i=%d idx=%d x=%d z=%d rect=%s/%s er=%s/%s nb=%s exp=%s'
                      % (i, idx, x, z, rect, ex_rect, erect, ex_er, nbi, exp_nb))
    print('sector %3d -> grid %dx%d = %d : %s' % (secw, cx, cz, cnt, 'OK' if bad == 0 else '%d BAD' % bad))
    if secw == 256:
        for i, r in enumerate(res):
            print('   sect%d idx=%d x=%d z=%d rect=%s erect=%s nb=%s' % (i, r[0], r[1], r[2], r[3], r[4], r[5]))
