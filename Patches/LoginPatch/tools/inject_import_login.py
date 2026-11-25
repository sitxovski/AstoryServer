# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
inject_import_login.py — ЕДИНСТВЕННАЯ правка LoginManager.exe: инъекция LoginPatch.dll
в таблицу импорта.

★ Близнец `AsdaPatch/tools/inject_import_npc.py`, но с ОДНИМ принципиальным отличием —
  где лежит FirstThunk (IAT нашего импорта):

  • у GameServer/NpcServer его клали в нулевой хвост файловой части .data. У LoginManager
    так НЕЛЬЗЯ: VirtualSize .data = 0x635248C (~100 МБ) при файловой части 0x2000, то есть
    сразу за инициализированными данными начинаются неинициализированные глобальные
    переменные программы. Нули в хвосте файловой части .data — это ЖИВЫЕ переменные,
    и запись туда адреса функции испортила бы чужое состояние;
  • поэтому FirstThunk кладём в нулевой хвост .rdata сразу за блоком дескрипторов, а
    DataDirectory[IAT] РАСШИРЯЕМ так, чтобы он покрывал и наш FirstThunk. Загрузчик снимает
    защиту ровно с региона DataDirectory[IAT] на время связывания импорта и потом
    возвращает её (та же грабля, что стоила падения в ntdll!LdrpSnapModule у GameServer:
    FirstThunk вне этого региона и на read-only странице = ACCESS_VIOLATION).
    Начало IAT (0x2E000) не меняется — растёт только размер.

Что делает:
  • в нулевой хвост .rdata кладёт НОВЫЙ массив дескрипторов импорта = все исходные
    дескрипторы 1:1 + один наш (LoginPatch.dll / LoginPatchInit) + терминатор, плюс
    OriginalFirstThunk, IMAGE_IMPORT_BY_NAME, имя DLL и FirstThunk;
  • в PE-заголовке меняет DataDirectory[IMPORT] (rva+size) и DataDirectory[IAT].Size.

Чего НЕ делает: не трогает .text, не добавляет секций, не меняет размер файла,
SizeOfImage, число секций, контрольную сумму заголовка. Действующие байтовые правки
живого образа (обход авторизации, `auth-ip-secret-bypass.md`) сохраняются как есть.

Откат: вернуть 12 байт заголовка (скрипт печатает исходные значения) либо подменить
       exe обратно на исходный файл.

Запуск:
    python inject_import_login.py                     # по умолчанию: work\lm_live_12dcd9f1.exe -> out\...
    python inject_import_login.py <src.exe> <out.exe>
    ... --force          — принять образ с другим MD5 (раскладка подбирается по нему же)
    ... --dll X.dll --func Name  — другое имя DLL/функции (для самопроверки механизма)
"""
import hashlib
import os
import struct
import sys

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.join(HERE, "..", "work", "lm_live_12dcd9f1.exe")      # копия ЖИВОГО образа
DEF_OUT = os.path.join(HERE, "..", "out", "LoginManager.exe.loginpatch.exe")

# ожидаемый образ — ЖИВОЙ LoginManager (сток + 4 байтовые правки обхода авторизации)
EXP_MD5  = "12dcd9f14359610dcc045b7317102e81"
EXP_SIZE = 245760
# раскладка, которую автоматический подбор обязан дать на ожидаемом образе
#   .rdata: RVA 0x2E000, vsize 0x9C08, raw 0xA000 ⇒ нулевой хвост 0x37C08..0x38000 (1016 б).
EXP_BLOCK_RVA = 0x37C40


def parse(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    opt = pe + 24
    if struct.unpack_from('<H', data, opt)[0] != 0x10B:
        sys.exit("Не PE32 — отказ.")
    sh = opt + struct.unpack_from('<H', data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = sh + 40 * i
        nm = data[o:o + 8].rstrip(b'\0').decode()
        vsz, va, rsz, ra = struct.unpack_from('<IIII', data, o + 8)
        ch = struct.unpack_from('<I', data, o + 36)[0]
        secs.append((nm, va, vsz, ra, rsz, ch))
    return opt, secs


def rva2off(secs, rva):
    for _, va, vsz, ra, rsz, _ in secs:
        if va <= rva < va + max(vsz, rsz):
            if rva - va >= rsz:
                raise ValueError(f"RVA 0x{rva:X} вне файловой части секции")
            return ra + (rva - va)
    raise ValueError(f"RVA 0x{rva:X} вне секций")


def sec_of(secs, rva):
    for s in secs:
        if s[1] <= rva < s[1] + max(s[2], s[4]):
            return s
    return None


def cstr(data, off):
    return data[off:data.index(b'\x00', off)].decode()


def main():
    args = [a for a in sys.argv[1:]]
    force = '--force' in args
    dll = 'LoginPatch.dll'
    func = 'LoginPatchInit'
    if '--dll' in args:
        dll = args[args.index('--dll') + 1]
    if '--func' in args:
        func = args[args.index('--func') + 1]
    pos = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ('--dll', '--func'):
            skip = True
            continue
        if not a.startswith('--'):
            pos.append(a)
    src = pos[0] if len(pos) > 0 else os.path.normpath(DEF_SRC)
    out = pos[1] if len(pos) > 1 else os.path.normpath(DEF_OUT)
    DLL_NAME = dll.encode('ascii') + b'\x00'
    FUNC_NAME = func.encode('ascii') + b'\x00'

    data = bytearray(open(src, 'rb').read())
    md5 = hashlib.md5(bytes(data)).hexdigest()
    print(f"исходник : {src}")
    print(f"           {len(data)} б, MD5 {md5}")
    expected = (len(data) == EXP_SIZE and md5 == EXP_MD5)
    if not expected:
        print(f"⚠ ВНИМАНИЕ: ожидался живой образ {EXP_SIZE} б / {EXP_MD5}.")
        if not force:
            sys.exit("Отказ. Повторить с --force, если это осознанно.")

    opt, secs = parse(data)
    dd_imp = opt + 96 + 8 * 1           # DataDirectory[1]  = IMPORT
    dd_iat = opt + 96 + 8 * 12          # DataDirectory[12] = IAT
    imp_rva, imp_size = struct.unpack_from('<II', data, dd_imp)
    iat_rva0, iat_size0 = struct.unpack_from('<II', data, dd_iat)
    print(f"IMPORT   : rva=0x{imp_rva:X} size=0x{imp_size:X}")
    print(f"IAT      : rva=0x{iat_rva0:X} size=0x{iat_size0:X}")
    if not iat_rva0:
        sys.exit("DataDirectory[IAT] пуст — эта схема не применима, отказ.")

    # ── исходные дескрипторы ────────────────────────────────────────────────
    off = rva2off(secs, imp_rva)
    descs = []
    while True:
        d = struct.unpack_from('<IIIII', data, off + 20 * len(descs))
        if not any(d):
            break
        nm = cstr(data, rva2off(secs, d[3]))
        descs.append(d)
        print(f"  [{len(descs)-1}] {nm}")
        if nm.lower() == dll.lower():
            sys.exit(f"Импорт {dll} УЖЕ присутствует — отказ (идемпотентность).")

    # ── раскладка: всё в нулевом хвосте секции, где лежит IAT (.rdata) ─────
    rd = sec_of(secs, iat_rva0)
    if rd is None or rd[0] != '.rdata':
        sys.exit("IAT лежит не в .rdata — схема не проверена для такого образа, отказ.")
    rd_name, rd_va, rd_vsz, rd_ra, rd_rsz, rd_ch = rd
    if rd_ch & 0x80000000:
        sys.exit(".rdata записываемая — образ необычный, отказ (проверить вручную).")
    rd_file_end_rva = rd_va + rd_rsz
    page_end = ((rd_va + rd_vsz + 0xFFF) & ~0xFFF)       # конец последней отображаемой страницы
    tail_from = (rd_va + rd_vsz + 0x3F) & ~0x3F           # граница 64 б за VirtualSize
    block_rva = tail_from if tail_from > rd_va + rd_vsz else tail_from + 0x40
    if block_rva - (rd_va + rd_vsz) < 0x10:
        block_rva += 0x40

    n_new = len(descs) + 2                     # исходные + наш + терминатор
    o_desc = 0
    o_int = o_desc + 20 * n_new                # OriginalFirstThunk: 2 dword
    o_ibn = o_int + 8
    o_dll = o_ibn + 2 + len(FUNC_NAME)
    o_iat = (o_dll + len(DLL_NAME) + 7) & ~7   # FirstThunk: 2 dword, выровнен на 8
    total = o_iat + 8

    end_rva = block_rva + total
    if end_rva > min(rd_file_end_rva, page_end):
        sys.exit("Блок не помещается в хвост .rdata (файловая часть/последняя страница) — отказ.")
    blk_off = rva2off(secs, block_rva)
    vend_off = rva2off(secs, rd_va + rd_vsz)   # всё от конца VirtualSize до конца блока — нули
    if any(data[vend_off:blk_off + total]):
        sys.exit(f"Хвост .rdata по 0x{blk_off:X} НЕ ПУСТ — отказ.")
    if expected and block_rva != EXP_BLOCK_RVA:
        sys.exit(f"Подбор дал RVA 0x{block_rva:X}, ожидалось 0x{EXP_BLOCK_RVA:X} — отказ.")
    iat_rva = block_rva + o_iat

    # новый размер DataDirectory[IAT]: от прежнего начала до конца нашего FirstThunk
    new_iat_size = iat_rva + 8 - iat_rva0
    if new_iat_size < iat_size0:
        sys.exit("Наш FirstThunk оказался ДО конца исходного IAT — так не бывает, отказ.")

    blob = bytearray(total)
    for i, d in enumerate(descs):              # исходные дескрипторы 1:1
        struct.pack_into('<IIIII', blob, o_desc + 20 * i, *d)
    struct.pack_into('<IIIII', blob, o_desc + 20 * len(descs),
                     block_rva + o_int,        # OriginalFirstThunk
                     0, 0,                     # TimeDateStamp, ForwarderChain
                     block_rva + o_dll,        # Name
                     iat_rva)                  # FirstThunk — внутри расширенного DataDirectory[IAT]
    struct.pack_into('<II', blob, o_int, block_rva + o_ibn, 0)
    struct.pack_into('<H', blob, o_ibn, 0)     # Hint
    blob[o_ibn + 2:o_ibn + 2 + len(FUNC_NAME)] = FUNC_NAME
    blob[o_dll:o_dll + len(DLL_NAME)] = DLL_NAME
    struct.pack_into('<II', blob, o_iat, block_rva + o_ibn, 0)

    hdr_before = bytes(data[dd_imp:dd_imp + 8]) + bytes(data[dd_iat + 4:dd_iat + 8])
    data[blk_off:blk_off + total] = blob
    struct.pack_into('<II', data, dd_imp, block_rva, 20 * n_new)
    struct.pack_into('<I', data, dd_iat + 4, new_iat_size)

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    open(out, 'wb').write(bytes(data))

    # ── верификация: перечитываем результат ─────────────────────────────────
    chk = open(out, 'rb').read()
    diff = [i for i in range(len(chk)) if chk[i] != data[i]]
    assert not diff
    orig = open(src, 'rb').read()
    changed = [i for i in range(len(orig)) if orig[i] != chk[i]]
    in_hdr = [i for i in changed if i < 0x400]
    in_blk = [i for i in changed if blk_off <= i < blk_off + total]
    if len(in_hdr) + len(in_blk) != len(changed):
        sys.exit("⚠ верификация не прошла: изменены байты вне заголовка и блока")
    r, s = struct.unpack_from('<II', chk, dd_imp)
    ir, isz = struct.unpack_from('<II', chk, dd_iat)
    o = rva2off(secs, r)
    names, i, ours = [], 0, None
    while True:
        d = struct.unpack_from('<IIIII', chk, o + 20 * i)
        if not any(d):
            break
        names.append(cstr(chk, rva2off(secs, d[3])))
        ours = d
        i += 1
    ok_iat = ir <= ours[4] and ours[4] + 8 <= ir + isz
    ibn = struct.unpack_from('<I', chk, rva2off(secs, ours[4]))[0]
    fn = cstr(chk, rva2off(secs, ibn) + 2)

    print("\n═══ РЕЗУЛЬТАТ ═══")
    print(f"  блок      : RVA 0x{block_rva:X} (file 0x{blk_off:X}), {total} б  [.rdata, хвост за VirtualSize]")
    print(f"  FirstThunk: RVA 0x{iat_rva:X}  [внутри DataDirectory[IAT]: {ok_iat}]")
    print(f"  IMPORT dir: было rva=0x{imp_rva:X} size=0x{imp_size:X} -> стало rva=0x{r:X} size=0x{s:X}")
    print(f"  IAT dir   : было rva=0x{iat_rva0:X} size=0x{iat_size0:X} -> стало rva=0x{ir:X} size=0x{isz:X}")
    print(f"  импорты   : {', '.join(names)}")
    print(f"  функция   : {fn}")
    print(f"  изменено  : {len(changed)} б (заголовок {len(in_hdr)}, блок {len(in_blk)}); .text не тронут")
    print(f"  размер    : {len(chk)} б (не изменился: {len(chk) == len(orig)})")
    print(f"  выход     : {out}")
    print(f"  MD5       : {hashlib.md5(chk).hexdigest()}")
    print("\n  ОТКАТ: по файловому смещению "
          f"0x{dd_imp:X} записать 8 байт {hdr_before[:8].hex(' ')}, "
          f"по 0x{dd_iat + 4:X} — 4 байта {hdr_before[8:].hex(' ')} (или вернуть исходный exe)")
    if names[-1].lower() != dll.lower() or not ok_iat or fn != func:
        sys.exit("⚠ верификация не прошла")
    print("\n  ✔ верификация пройдена")


if __name__ == '__main__':
    main()
