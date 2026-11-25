# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
inject_import_dbpatch.py — ЕДИНСТВЕННАЯ правка DBManager.exe: инъекция DBPatch.dll
в таблицу импорта. Полный аналог inject_import.py (GameServer), но с адресами
DBManager.

★★★ ПОЧЕМУ ЭТОТ СКРИПТ ВООБЩЕ ПОЯВИЛСЯ.
    В комментарии к Registry.cpp с 2026-08-24 записано, что доставить DLL в
    процессы, работающие с базой, «не вышло: у этих образов в хвосте .rdata нет
    места под новый блок дескрипторов импорта». Это оказалось ЛОЖНЫМ «НЕТ»
    (закон false-negatives-method): смотрели ТОЛЬКО хвост .rdata.
    Пересчёт по ЖИВОМУ образу (2026-08-30):

      нужно  : дескрипторы (8 DLL + наш + терминатор) 10*20 = 200 б
               имя DLL  "AsdaPatch.dll\0"                    =  14 б
               IMAGE_IMPORT_BY_NAME (hint + "AsdaPatchInit\0")= 16 б
               INT (OriginalFirstThunk): 2 dword             =   8 б
               ИТОГО в неизменяемой зоне                     = 238 б
               + IAT (FirstThunk): 2 dword                   =   8 б (нужна ЗАПИСЬ)

      свободно: хвост .rdata  RVA 0x7FF48..0x80000  =  184 б  ← ЭТОГО НЕ ХВАТАЛО
                ★ хвост .text RVA 0x657AB..0x66000  = 2133 б  ← ХВАТАЕТ С ЗАПАСОМ
                ★ хвост .data RVA 0x814FD..0x82000  = 2819 б  (секция ЗАПИСЫВАЕМАЯ)

    Хвост .text — та же зона, где с 24.08 живёт бинарный патч P17 (кодовая
    страница SQL, 0x465790..0x4657AA); он работает на живом сервере, значит зона
    отображается и читается. Наш блок кладём СРАЗУ ЗА НИМ, не задевая.

★ IAT (FirstThunk) обязан лежать на ЗАПИСЫВАЕМОЙ странице: загрузчик снимает
  защиту только с региона DataDirectory[IAT] (здесь RVA 0x66000..0x66288), всё
  остальное он пишет как есть. Поэтому IAT — в хвост .data (C0000040 = R+W).
  Ровно так же сделано в inject_import.py для GameServer (там это подтверждено
  отладчиком: иначе ntdll!LdrpSnapModule падает с ACCESS_VIOLATION).

Что меняется в файле:
  • блок дескрипторов + INT + строки  -> RVA 0x657B0 (хвост .text, было 0);
  • IAT нашего импорта                -> RVA 0x81F80 (хвост .data, было 0);
  • DataDirectory[IMPORT].VirtualAddress и .Size (8 байт заголовка).
Чего НЕ меняется: .text/.rdata/.data по существу, число секций, SizeOfImage,
SizeOfHeaders, размер файла, DataDirectory[IAT].

Откат: вернуть 8 байт DataDirectory[IMPORT] (скрипт печатает исходные значения)
       либо подменить exe обратно на DBManager-Original.exe.

Запуск:
    python inject_import_dbpatch.py                    # живой образ -> out\DBManager.exe.dllhost.exe
    python inject_import_dbpatch.py <src.exe> <out.exe>
"""
import hashlib
import os
import struct
import sys

# ★ ОСНОВА: сток + P17 (кодовая страница SQL), импорта в нём ещё НЕТ.
#   Живой образ брать НЕЛЬЗЯ: с 30.08.2026 в нём уже вшит импорт AsdaPatch.dll,
#   инъекция поверх дала бы вторую запись на несуществующую библиотеку.
DEF_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "AsdaPatch", "out", "p17", "DBManager.exe")
DEF_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "out", "DBManager.exe.dbpatch.exe")

DLL_NAME  = b"DBPatch.dll" + bytes([0])
FUNC_NAME = b"DBPatchInit" + bytes([0])

# ЖИВОЙ образ (пропатчен P17 24.08.2026)
EXP_MD5  = "294c4e0332e2eed305b77855a7004a34"
EXP_SIZE = 536576

# куда класть новый блок дескрипторов/INT/строк — хвост .text, СРАЗУ ЗА площадкой P17
BLOCK_RVA = 0x657B0
# куда класть FirstThunk (IAT нашего импорта) — хвост .data, ЗАПИСЫВАЕМЫЙ
IAT_RVA   = 0x81F80


def sections(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    sh = pe + 24 + optsz
    secs = []
    for i in range(nsec):
        o = sh + 40 * i
        nm = data[o:o + 8].rstrip(b'\0').decode()
        vsz, va, rsz, ra = struct.unpack_from('<IIII', data, o + 8)
        ch = struct.unpack_from('<I', data, o + 36)[0]
        secs.append((nm, va, vsz, ra, rsz, ch))
    return pe, optsz, secs


def rva2off(secs, rva):
    for _nm, va, vsz, ra, rsz, _ch in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    raise ValueError("RVA 0x%X вне секций" % rva)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEF_SRC
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.normpath(DEF_OUT)

    data = bytearray(open(src, 'rb').read())
    md5 = hashlib.md5(bytes(data)).hexdigest()
    print("исходник : %s" % src)
    print("размер   : %d, MD5 %s" % (len(data), md5))
    if len(data) != EXP_SIZE or md5 != EXP_MD5:
        print("!! ОЖИДАЛСЯ размер %d и MD5 %s — это НЕ тот образ. Прерываю."
              % (EXP_SIZE, EXP_MD5))
        return 1

    pe, optsz, secs = sections(data)
    opt = pe + 24
    dd = opt + 96
    imp_va, imp_sz = struct.unpack_from('<II', data, dd + 8 * 1)
    iat_va, iat_sz = struct.unpack_from('<II', data, dd + 8 * 12)
    print("DataDirectory[IMPORT] : VA=%08X size=%04X  <- ЭТО ЕДИНСТВЕННОЕ, ЧТО МЕНЯЕМ"
          % (imp_va, imp_sz))
    print("DataDirectory[IAT]    : VA=%08X size=%04X  (не трогаем)" % (iat_va, iat_sz))

    # ── читаем исходные дескрипторы ────────────────────────────────────────
    src_off = rva2off(secs, imp_va)
    descs = []
    i = 0
    while True:
        o = src_off + 20 * i
        rec = struct.unpack_from('<IIIII', data, o)
        if rec[0] == 0 and rec[3] == 0 and rec[4] == 0:
            break
        no = rva2off(secs, rec[3])
        nm = bytes(data[no:data.index(b'\0', no)]).decode('latin1')
        print("  [%d] %-14s OFT=%08X FirstThunk=%08X" % (i, nm, rec[0], rec[4]))
        descs.append(rec)
        i += 1
    print("исходных DLL: %d" % len(descs))

    # ── проверяем, что целевые зоны ДЕЙСТВИТЕЛЬНО свободны ─────────────────
    need_block = (len(descs) + 2) * 20 + len(DLL_NAME) + (2 + len(FUNC_NAME)) + 8
    blk_off = rva2off(secs, BLOCK_RVA)
    iat_off = rva2off(secs, IAT_RVA)
    print("нужно под блок: %d б (дескрипторы %d + имя %d + hint/имя %d + INT 8)"
          % (need_block, (len(descs) + 2) * 20, len(DLL_NAME), 2 + len(FUNC_NAME)))
    if set(data[blk_off:blk_off + need_block]) != {0}:
        print("!! зона блока RVA %08X не нулевая — прерываю" % BLOCK_RVA)
        return 1
    if set(data[iat_off:iat_off + 8]) != {0}:
        print("!! зона IAT RVA %08X не нулевая — прерываю" % IAT_RVA)
        return 1
    # секция под IAT обязана быть записываемой
    for nm, va, vsz, ra, rsz, ch in secs:
        if va <= IAT_RVA < va + max(vsz, rsz):
            if not (ch & 0x80000000):
                print("!! секция %s под IAT НЕ записываемая (ch=%08X) — прерываю" % (nm, ch))
                return 1
            print("IAT ляжет в секцию %s (ch=%08X, ЗАПИСЫВАЕМАЯ) — ок" % (nm, ch))
    print("зоны свободны: блок RVA %08X (+%d б), IAT RVA %08X (+8 б)"
          % (BLOCK_RVA, need_block, IAT_RVA))

    # ── собираем новый блок ────────────────────────────────────────────────
    n_desc = len(descs) + 2                       # исходные + наш + терминатор
    off_descs = 0
    off_name  = off_descs + n_desc * 20           # "AsdaPatch.dll\0"
    off_ibn   = off_name + len(DLL_NAME)          # hint + "AsdaPatchInit\0"
    off_int   = off_ibn + 2 + len(FUNC_NAME)      # INT: 2 dword
    if off_int % 4:                               # выравнивание INT на dword
        off_int += 4 - (off_int % 4)
    total = off_int + 8

    blk = bytearray(total)
    for k, rec in enumerate(descs):
        struct.pack_into('<IIIII', blk, off_descs + 20 * k, *rec)
    struct.pack_into('<IIIII', blk, off_descs + 20 * len(descs),
                     BLOCK_RVA + off_int,   # OriginalFirstThunk -> INT
                     0, 0,
                     BLOCK_RVA + off_name,  # Name -> "DBPatch.dll"
                     IAT_RVA)               # FirstThunk -> IAT в .data
    # терминатор уже нулевой
    blk[off_name:off_name + len(DLL_NAME)] = DLL_NAME
    struct.pack_into('<H', blk, off_ibn, 0)                       # hint
    blk[off_ibn + 2:off_ibn + 2 + len(FUNC_NAME)] = FUNC_NAME
    struct.pack_into('<II', blk, off_int, BLOCK_RVA + off_ibn, 0) # INT + терминатор

    data[blk_off:blk_off + total] = blk
    # IAT = копия INT (загрузчик перезапишет адресом функции)
    struct.pack_into('<II', data, iat_off, BLOCK_RVA + off_ibn, 0)

    # ── правим ТОЛЬКО DataDirectory[IMPORT] ────────────────────────────────
    struct.pack_into('<II', data, dd + 8 * 1, BLOCK_RVA, n_desc * 20)
    print("новый DataDirectory[IMPORT]: VA=%08X size=%04X" % (BLOCK_RVA, n_desc * 20))
    print("★ ОТКАТ: вернуть по смещению 0x%X восемь байт %s"
          % (dd + 8, struct.pack('<II', imp_va, imp_sz).hex(' ')))

    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'wb').write(bytes(data))
    print("записан  : %s" % out)
    print("размер   : %d, MD5 %s" % (len(data), hashlib.md5(bytes(data)).hexdigest()))
    print("★ файл НЕ подменён на живом сервере — это делает владелец.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
