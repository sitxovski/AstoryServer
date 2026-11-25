# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""
NpcServer: пересборка сетки секторов после CSectorManager::SetMapInfo.
Дефект: сетка секторов (m_Index/m_X/m_Z/rect/соседи) строится в конструкторе
sub_41B1A0 по ЖЁСТКИМ константам (map 512x512, sector 30x30, 18x18=324),
а SetMapInfo (sub_41A6C0) потом ПЕРЕЗАПИСЫВАЕТ скалярные поля значениями из
SectorInfo.ini, НЕ перестраивая сами секторы. При любом Sector_Width != 30
индексы/соседи/прямоугольники секторов становятся от чужой сетки.
Фикс: hook на call sub_41A6C0 -> cave, который после SetMapInfo пересчитывает
для i < m_SectorCount: m_Index, m_X, m_Z, rect, расширенный rect и заново
линкует 9 соседей штатной функцией sub_41BEE0.
"""
import sys, shutil, os
import keystone as K
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

VA_CAVE      = 0x464960
VA_SETMAPINFO= 0x41A6C0
VA_SETAROUND = 0x41BEE0
VA_CALLSITE  = 0x4582AD          # call sub_41A6C0 внутри CAi::Initialize (sub_458290)
ORIG_CALL    = bytes.fromhex('e80e24fcff')
CAP_SECTORS  = 324               # столько CSector реально выделено конструктором

def va2off(va):  # .text: raw 0x1000 @ VA 0x401000
    return va - 0x400000

ASM = f"""
hook:
    push esi
    push dword ptr [esp+8]
    call {VA_SETMAPINFO}
    pop  esi
    test al, al
    jnz  hook_done
    call rebuild
hook_done:
    ret 4

rebuild:
    pushad
    mov  edi, [esi]
    test edi, edi
    jz   rb_out
    mov  eax, [esi+0x1C]
    test eax, eax
    jle  rb_out
    mov  ecx, [esi+0x20]
    test ecx, ecx
    jle  rb_out
    imul eax, ecx
    cmp  eax, [esi+0x24]
    jne  rb_out
    cmp  eax, {CAP_SECTORS}
    jg   rb_out
    cmp  dword ptr [esi+0x14], 0
    jle  rb_out
    cmp  dword ptr [esi+0x18], 0
    jle  rb_out
    xor  ebx, ebx
rb_l1:
    mov  eax, ebx
    xor  edx, edx
    div  dword ptr [esi+0x1C]
    mov  ecx, [edi+ebx*4]
    test ecx, ecx
    jz   rb_n1
    mov  [ecx+0x24], ebx
    mov  [ecx+0x28], edx
    mov  [ecx+0x2C], eax
    push eax
    mov  eax, edx
    imul eax, [esi+0x14]
    mov  [ecx+0x7D0], eax
    add  eax, [esi+0x14]
    dec  eax
    cmp  eax, [esi+0x0C]
    jl   rb_r
    mov  eax, [esi+0x0C]
    dec  eax
rb_r:
    mov  [ecx+0x7D8], eax
    pop  eax
    imul eax, [esi+0x18]
    mov  [ecx+0x7D4], eax
    add  eax, [esi+0x18]
    dec  eax
    cmp  eax, [esi+0x10]
    jl   rb_b
    mov  eax, [esi+0x10]
    dec  eax
rb_b:
    mov  [ecx+0x7DC], eax
    mov  eax, [ecx+0x7D0]
    sub  eax, [esi+0x14]
    jns  rb_el
    xor  eax, eax
rb_el:
    mov  [ecx+0x7E0], eax
    mov  eax, [ecx+0x7D4]
    sub  eax, [esi+0x18]
    jns  rb_et
    xor  eax, eax
rb_et:
    mov  [ecx+0x7E4], eax
    mov  eax, [ecx+0x7D8]
    add  eax, [esi+0x14]
    cmp  eax, [esi+0x0C]
    jl   rb_er
    mov  eax, [esi+0x0C]
    dec  eax
rb_er:
    mov  [ecx+0x7E8], eax
    mov  eax, [ecx+0x7DC]
    add  eax, [esi+0x18]
    cmp  eax, [esi+0x10]
    jl   rb_eb
    mov  eax, [esi+0x10]
    dec  eax
rb_eb:
    mov  [ecx+0x7EC], eax
rb_n1:
    inc  ebx
    cmp  ebx, [esi+0x24]
    jl   rb_l1
    xor  ebx, ebx
rb_l2:
    mov  eax, [edi+ebx*4]
    test eax, eax
    jz   rb_n2
    push dword ptr [esi+0x20]
    mov  ecx, [esi+0x1C]
    call {VA_SETAROUND}
rb_n2:
    inc  ebx
    cmp  ebx, [esi+0x24]
    jl   rb_l2
rb_out:
    popad
    ret
"""

def build():
    ks = K.Ks(K.KS_ARCH_X86, K.KS_MODE_32)
    enc, _ = ks.asm(ASM, VA_CAVE)
    return bytes(enc)

def patch(path, dry=False):
    data = bytearray(open(path, 'rb').read())
    off = va2off(VA_CALLSITE)
    cur = bytes(data[off:off+5])
    if cur != ORIG_CALL:
        raise SystemExit('!! %s: в точке хука не исходный call: %s' % (path, cur.hex()))
    cave = build()
    coff = va2off(VA_CAVE)
    zone = bytes(data[coff:coff+len(cave)+16])
    if any(zone):
        raise SystemExit('!! %s: cave не пуст' % path)
    data[coff:coff+len(cave)] = cave
    rel = VA_CAVE - (VA_CALLSITE + 5)
    data[off:off+5] = b'\xe8' + rel.to_bytes(4, 'little', signed=True)
    if not dry:
        open(path, 'wb').write(bytes(data))
    return len(cave)

if __name__ == '__main__':
    code = build()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print('cave %d байт @ %08X' % (len(code), VA_CAVE))
    for ins in md.disasm(code, VA_CAVE):
        print('%08X  %-20s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    for p in sys.argv[1:]:
        n = patch(p)
        print('patched', p, n)
