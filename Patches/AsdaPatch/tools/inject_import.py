# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
inject_import.py — ЕДИНСТВЕННАЯ правка GameServer.exe: инъекция AsdaPatch.dll
в таблицу импорта.

Что делает:
  • в нулевой хвост секции .rdata кладёт НОВЫЙ массив дескрипторов импорта =
    все исходные дескрипторы 1:1 + один наш (AsdaPatch.dll / AsdaPatchInit) +
    терминатор, плюс OriginalFirstThunk, IMAGE_IMPORT_BY_NAME и строки;
  • ★ FirstThunk (IAT нашего импорта) кладёт в нулевой хвост секции .data —
    ЗАПИСЫВАЕМОЙ. Это обязательно: загрузчик снимает защиту только с региона,
    описанного DataDirectory[IAT] (здесь 0x183000..0x18325C), а всё, что вне
    него, обязано лежать на записываемой странице. Иначе ntdll!LdrpSnapModule
    падает с ACCESS_VIOLATION на записи адреса функции (проверено отладчиком);
  • в PE-заголовке меняет ТОЛЬКО DataDirectory[IMPORT].VirtualAddress и .Size.

Чего НЕ делает: не трогает .text, не добавляет секций, не меняет размер файла,
SizeOfImage, число секций, контрольную сумму заголовка.

Итог: загрузчик Windows подгружает AsdaPatch.dll ДО точки входа GameServer.exe.
Все игровые правки живут в DLL и ставятся в памяти; сам exe остаётся стоком.

Откат: вернуть 8 байт DataDirectory[IMPORT] (скрипт печатает исходные значения)
       либо просто подменить exe обратно на исходный файл.

Запуск:
    python inject_import.py                     # по умолчанию: BASE -> out\...
    python inject_import.py <src.exe> <out.exe>
"""
import hashlib
import os
import struct
import sys

# ── пути по умолчанию ───────────────────────────────────────────────────────
from srv_paths import ROOT as SRV_ROOT   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
DEF_SRC = (SRV_ROOT + "/AsdaStory/GameServer/"
           "GameServer.exe_before_mine_patch.exe")
DEF_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "out", "GameServer.exe.dllhost.exe")

DLL_NAME  = b"AsdaPatch.dll\x00"
FUNC_NAME = b"AsdaPatchInit\x00"

# ожидаемый сток
EXP_MD5  = "4e20f0ad0b13a54454405eed31ffe447"
EXP_SIZE = 1740800

# куда класть новый блок дескрипторов (нулевой хвост .rdata, read-only)
BLOCK_RVA = 0x1A5800
# куда класть FirstThunk = IAT нашего импорта (нулевой хвост .data, ЗАПИСЫВАЕМЫЙ)
# .data: raw 0x1A6000..0x1A8000, последний ненулевой байт стока — 0x1A7928.
IAT_RVA = 0x1A7F80


def rva2off(secs, rva):
    """.text/.rdata/.data этого exe отображены 1:1 (RawAddr == VirtualAddress),
    но считаем честно по таблице секций."""
    for _, va, vsz, ra, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    raise ValueError(f"RVA 0x{rva:X} вне секций")


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEF_SRC
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.normpath(DEF_OUT)

    data = bytearray(open(src, 'rb').read())
    md5 = hashlib.md5(bytes(data)).hexdigest()
    print(f"исходник : {src}")
    print(f"           {len(data)} б, MD5 {md5}")
    if len(data) != EXP_SIZE or md5 != EXP_MD5:
        print(f"⚠ ВНИМАНИЕ: ожидался сток {EXP_SIZE} б / {EXP_MD5}.")
        if '--force' not in sys.argv:
            sys.exit("Отказ. Повторить с --force, если это осознанно.")

    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic != 0x10B:
        sys.exit("Не PE32 — отказ.")
    sh = opt + struct.unpack_from('<H', data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = sh + 40 * i
        nm = data[o:o + 8].rstrip(b'\0').decode()
        vsz, va, rsz, ra = struct.unpack_from('<IIII', data, o + 8)
        secs.append((nm, va, vsz, ra, rsz))

    dd_imp = opt + 96 + 8 * 1          # DataDirectory[1] = IMPORT
    imp_rva, imp_size = struct.unpack_from('<II', data, dd_imp)
    print(f"IMPORT   : rva=0x{imp_rva:X} size=0x{imp_size:X}")

    # ── читаем исходные дескрипторы ─────────────────────────────────────────
    off = rva2off(secs, imp_rva)
    descs = []
    while True:
        d = struct.unpack_from('<IIIII', data, off + 20 * len(descs))
        if not any(d):
            break
        nm_off = rva2off(secs, d[3])
        nm = data[nm_off:data.index(b'\x00', nm_off)].decode()
        descs.append(d)
        print(f"  [{len(descs)-1}] {nm}")
        if nm.lower() == 'asdapatch.dll':
            sys.exit("Импорт AsdaPatch.dll УЖЕ присутствует — отказ (идемпотентность).")

    # ── раскладка нового блока ──────────────────────────────────────────────
    n_new = len(descs) + 2                     # исходные + наш + терминатор
    o_desc = 0
    o_int  = o_desc + 20 * n_new               # OriginalFirstThunk: 2 dword
    o_ibn  = o_int + 8
    o_dll  = o_ibn + 2 + len(FUNC_NAME)
    total  = o_dll + len(DLL_NAME)
    total  = (total + 3) & ~3

    secmap = {nm: (va, vsz, ra, rsz) for nm, va, vsz, ra, rsz in secs}
    blk_off = rva2off(secs, BLOCK_RVA)
    rd_end  = secmap['.rdata'][2] + secmap['.rdata'][3]
    if blk_off + total > rd_end:
        sys.exit("Блок дескрипторов не помещается в хвост .rdata — отказ.")
    if any(data[blk_off:blk_off + total]):
        sys.exit(f"Хвост .rdata по 0x{blk_off:X} НЕ ПУСТ — отказ.")

    # FirstThunk — в записываемую .data
    iat_off = rva2off(secs, IAT_RVA)
    dt_end  = secmap['.data'][2] + secmap['.data'][3]
    if iat_off + 8 > dt_end:
        sys.exit("FirstThunk не помещается в хвост .data — отказ.")
    if any(data[iat_off:iat_off + 8]):
        sys.exit(f"Хвост .data по 0x{iat_off:X} НЕ ПУСТ — отказ.")
    dsec = next(s for s in secs if s[0] == '.data')
    if not (dsec[4] and (struct.unpack_from('<I', data, sh + 40 * secs.index(dsec) + 36)[0] & 0x80000000)):
        sys.exit("Секция .data не помечена как записываемая — отказ.")

    blob = bytearray(total)
    for i, d in enumerate(descs):              # исходные дескрипторы 1:1
        struct.pack_into('<IIIII', blob, o_desc + 20 * i, *d)
    struct.pack_into('<IIIII', blob, o_desc + 20 * len(descs),
                     BLOCK_RVA + o_int,        # OriginalFirstThunk (INT, read-only — ок)
                     0, 0,                     # TimeDateStamp, ForwarderChain
                     BLOCK_RVA + o_dll,        # Name
                     IAT_RVA)                  # FirstThunk (IAT — в .data, записываемая)
    # терминатор уже нулевой
    struct.pack_into('<II', blob, o_int, BLOCK_RVA + o_ibn, 0)
    struct.pack_into('<H', blob, o_ibn, 0)     # Hint
    blob[o_ibn + 2:o_ibn + 2 + len(FUNC_NAME)] = FUNC_NAME
    blob[o_dll:o_dll + len(DLL_NAME)] = DLL_NAME

    data[blk_off:blk_off + total] = blob
    struct.pack_into('<II', data, iat_off, BLOCK_RVA + o_ibn, 0)   # IAT в .data
    struct.pack_into('<II', data, dd_imp, BLOCK_RVA, 20 * n_new)

    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'wb').write(bytes(data))

    # ── верификация: перечитываем результат ─────────────────────────────────
    chk = open(out, 'rb').read()
    r, s = struct.unpack_from('<II', chk, dd_imp)
    o = rva2off(secs, r)
    names, i = [], 0
    while True:
        d = struct.unpack_from('<IIIII', chk, o + 20 * i)
        if not any(d):
            break
        no = rva2off(secs, d[3])
        names.append(chk[no:chk.index(b'\x00', no)].decode())
        i += 1

    print("\n═══ РЕЗУЛЬТАТ ═══")
    print(f"  дескрипторы: RVA 0x{BLOCK_RVA:X} (file 0x{blk_off:X}), {total} б  [.rdata, read-only]")
    print(f"  FirstThunk : RVA 0x{IAT_RVA:X} (file 0x{iat_off:X}), 8 б  [.data, ЗАПИСЫВАЕМАЯ]")
    print(f"  IMPORT dir: было rva=0x{imp_rva:X} size=0x{imp_size:X} "
          f"-> стало rva=0x{r:X} size=0x{s:X}")
    print(f"  импорты   : {', '.join(names)}")
    print(f"  размер    : {len(chk)} б (не изменился: {len(chk) == EXP_SIZE})")
    print(f"  выход     : {out}")
    print(f"  MD5       : {hashlib.md5(chk).hexdigest()}")
    print("\n  ОТКАТ: записать по файловому смещению "
          f"0x{dd_imp:X} восемь байт: "
          f"{struct.pack('<II', imp_rva, imp_size).hex(' ')}")
    if names[-1].lower() != 'asdapatch.dll':
        sys.exit("⚠ верификация не прошла: наш импорт не последний")
    print("\n  ✔ верификация пройдена")


if __name__ == '__main__':
    main()
