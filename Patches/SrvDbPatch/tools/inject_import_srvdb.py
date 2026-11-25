# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
r"""
inject_import_srvdb.py — ЕДИНСТВЕННАЯ правка файлов RelayServer.exe / ItemRelayServer.exe / OperationServer.exe для P126:
инъекция SrvDbPatch.dll в таблицу импорта (15.11.2026).

Схема — 1:1 с `LoginPatch/tools/inject_import_login.py` (тот же расчёт блока, те же проверки), обобщена на четыре образа:
  • в нулевой хвост .rdata (за VirtualSize) кладётся НОВЫЙ массив дескрипторов импорта = все исходные 1:1 + наш
    (SrvDbPatch.dll / SrvDbPatchInit) + терминатор, плюс OriginalFirstThunk, IMAGE_IMPORT_BY_NAME, имя DLL и FirstThunk;
  • в заголовке меняются DataDirectory[IMPORT] (rva+size) и DataDirectory[IAT].Size (начало IAT то же).
★ FirstThunk — в .rdata, а НЕ в хвосте .data: у всех трёх образов .data = ~70 МБ (VirtualSize 0x46D9844…0x473EC20) при
  файловой части 0x1000/0x2000 — нули хвоста файловой части .data являются живыми неинициализированными переменными
  (грабля LoginManager, `AstoryServer/Docs/LoginManager/loginpatch-dll-loader.md`). DataDirectory[IAT] расширяется до
  нашего FirstThunk, чтобы загрузчик снял защиту и с него на время связывания.

Чего НЕ делает: не трогает .text, не добавляет секций, не меняет размер файла, SizeOfImage, число секций.
Действующие байтовые правки живых образов (RelayGift у RelayServer) сохраняются как есть — база = копия живого файла.

Запуск (из этой папки или откуда угодно):
    py -3.13 inject_import_srvdb.py            # все четыре образа: work\*_live_*.exe -> out\*.srvdbpatch.exe
    py -3.13 inject_import_srvdb.py --check    # только проверить уже собранные out\*.srvdbpatch.exe
Побочных эффектов при импорте нет; запуск — main().
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # SrvDbPatch
DLL = "SrvDbPatch.dll"
FUNC = "SrvDbPatchInit"

# Образы: база (копия живого, md5 со стойки 15.11.2026), выход, ожидаемый RVA блока (подбор обязан его дать).
IMAGES = [
    {"key": "relay", "src": "work/relay_live_a8cd94ba.exe", "md5": "a8cd94ba91b32e6ad1a254feb0dd7bc0", "size": 163840,
     "out": "out/RelayServer.exe.srvdbpatch.exe", "where": "RelayServer, Indun_RelayServer"},
    {"key": "relay_ch2", "src": "work/relay_ch2_live_075c41a5.exe", "md5": "075c41a5256eabbbab7c991bef9f47d5", "size": 163840,
     "out": "out/RelayServer_ch2.exe.srvdbpatch.exe", "where": "Ch2_RelayServer"},
    {"key": "itemrelay", "src": "work/itemrelay_live_b8c740b3.exe", "md5": "b8c740b3e527ffbf3095f57874860d5d", "size": 208896,
     "out": "out/ItemRelayServer.exe.srvdbpatch.exe", "where": "ItemRelayServer"},
    {"key": "operation", "src": "work/operation_live_a8209ce5.exe", "md5": "a8209ce51f570bc7affde8c88e07845e", "size": 81920,
     "out": "out/OperationServer.exe.srvdbpatch.exe", "where": "OperationServer"},
]


def parse(data):
    """Смещение OptionalHeader и список секций (имя, va, vsz, raw_off, raw_size, characteristics)."""
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    opt = pe + 24
    if struct.unpack_from('<H', data, opt)[0] != 0x10B:
        raise SystemExit("Не PE32 — отказ.")
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
    """RVA -> смещение в файле (только файловая часть секции)."""
    for _, va, vsz, ra, rsz, _ in secs:
        if va <= rva < va + max(vsz, rsz):
            if rva - va >= rsz:
                raise ValueError("RVA 0x%X вне файловой части секции" % rva)
            return ra + (rva - va)
    raise ValueError("RVA 0x%X вне секций" % rva)


def sec_of(secs, rva):
    for s in secs:
        if s[1] <= rva < s[1] + max(s[2], s[4]):
            return s
    return None


def cstr(data, off):
    return data[off:data.index(b'\x00', off)].decode()


def imports(data, secs, imp_rva):
    """Список (дескриптор, имя DLL) таблицы импорта."""
    off = rva2off(secs, imp_rva)
    out = []
    while True:
        d = struct.unpack_from('<IIIII', data, off + 20 * len(out))
        if not any(d):
            return out
        out.append((d, cstr(data, rva2off(secs, d[3]))))


def inject(src, out, exp_md5, exp_size):
    """Инъекция; возвращает словарь с итогом. Любое отклонение — SystemExit."""
    dll_b = DLL.encode('ascii') + b'\x00'
    fn_b = FUNC.encode('ascii') + b'\x00'
    data = bytearray(open(src, 'rb').read())
    md5 = hashlib.md5(bytes(data)).hexdigest()
    if md5 != exp_md5 or len(data) != exp_size:
        raise SystemExit("%s: ожидался живой образ %d б / %s, а здесь %d б / %s — отказ" % (src, exp_size, exp_md5, len(data), md5))
    opt, secs = parse(data)
    dd_imp = opt + 96 + 8 * 1
    dd_iat = opt + 96 + 8 * 12
    imp_rva, imp_size = struct.unpack_from('<II', data, dd_imp)
    iat_rva0, iat_size0 = struct.unpack_from('<II', data, dd_iat)
    if not iat_rva0:
        raise SystemExit("DataDirectory[IAT] пуст — отказ.")
    descs = imports(data, secs, imp_rva)
    if any(n.lower() == DLL.lower() for _, n in descs):
        raise SystemExit("Импорт %s УЖЕ есть — отказ (идемпотентность)." % DLL)

    rd = sec_of(secs, iat_rva0)
    if rd is None or rd[0] != '.rdata':
        raise SystemExit("IAT лежит не в .rdata — отказ.")
    _, rd_va, rd_vsz, rd_ra, rd_rsz, rd_ch = rd
    if rd_ch & 0x80000000:
        raise SystemExit(".rdata записываемая — отказ.")
    dat = [s for s in secs if s[0] == '.data'][0]
    rd_file_end_rva = rd_va + rd_rsz
    page_end = (rd_va + rd_vsz + 0xFFF) & ~0xFFF
    tail_from = (rd_va + rd_vsz + 0x3F) & ~0x3F
    block_rva = tail_from if tail_from > rd_va + rd_vsz else tail_from + 0x40
    if block_rva - (rd_va + rd_vsz) < 0x10:
        block_rva += 0x40

    n_new = len(descs) + 2
    o_int = 20 * n_new
    o_ibn = o_int + 8
    o_dll = o_ibn + 2 + len(fn_b)
    o_iat = (o_dll + len(dll_b) + 7) & ~7
    total = o_iat + 8
    if block_rva + total > min(rd_file_end_rva, page_end):
        raise SystemExit("Блок не помещается в хвост .rdata — отказ.")
    blk_off = rva2off(secs, block_rva)
    vend_off = rva2off(secs, rd_va + rd_vsz)
    if any(data[vend_off:blk_off + total]):
        raise SystemExit("Хвост .rdata по 0x%X НЕ ПУСТ — отказ." % blk_off)
    iat_rva = block_rva + o_iat
    new_iat_size = iat_rva + 8 - iat_rva0
    if new_iat_size < iat_size0:
        raise SystemExit("FirstThunk ДО конца исходного IAT — отказ.")

    blob = bytearray(total)
    for i, (d, _) in enumerate(descs):
        struct.pack_into('<IIIII', blob, 20 * i, *d)
    struct.pack_into('<IIIII', blob, 20 * len(descs), block_rva + o_int, 0, 0, block_rva + o_dll, iat_rva)
    struct.pack_into('<II', blob, o_int, block_rva + o_ibn, 0)
    struct.pack_into('<H', blob, o_ibn, 0)
    blob[o_ibn + 2:o_ibn + 2 + len(fn_b)] = fn_b
    blob[o_dll:o_dll + len(dll_b)] = dll_b
    struct.pack_into('<II', blob, o_iat, block_rva + o_ibn, 0)

    hdr_before = bytes(data[dd_imp:dd_imp + 8]) + bytes(data[dd_iat + 4:dd_iat + 8])
    data[blk_off:blk_off + total] = blob
    struct.pack_into('<II', data, dd_imp, block_rva, 20 * n_new)
    struct.pack_into('<I', data, dd_iat + 4, new_iat_size)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    open(out, 'wb').write(bytes(data))
    return {"block_rva": block_rva, "blk_off": blk_off, "total": total, "iat_rva": iat_rva, "dd_imp": dd_imp, "dd_iat": dd_iat,
            "hdr_before": hdr_before, "imp": (imp_rva, imp_size), "iat0": (iat_rva0, iat_size0),
            "data_sec": dat}


def check(src, out):
    """Сверка собранного образа с исходным. Возвращает список строк-нарушений (пусто — всё в порядке) и сводку."""
    a = open(src, 'rb').read()
    b = open(out, 'rb').read()
    bad = []
    if len(a) != len(b):
        bad.append("размер изменился")
    opt, secs = parse(b)
    dd_imp = opt + 96 + 8
    dd_iat = opt + 96 + 8 * 12
    r, s = struct.unpack_from('<II', b, dd_imp)
    ir, isz = struct.unpack_from('<II', b, dd_iat)
    blk_off = rva2off(secs, r)
    changed = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    hdr = [i for i in changed if dd_imp <= i < dd_imp + 8 or dd_iat + 4 <= i < dd_iat + 8]
    blk = [i for i in changed if blk_off <= i < blk_off + 0x200]
    if len(hdr) + len(blk) != len(changed):
        bad.append("изменены байты вне заголовка и блока")
    text = [x for x in secs if x[0] == '.text'][0]
    if a[text[3]:text[3] + text[4]] != b[text[3]:text[3] + text[4]]:
        bad.append(".text изменён")
    descs = imports(b, secs, r)
    orig = imports(a, secs, struct.unpack_from('<I', a, dd_imp)[0])
    if [d for d, _ in descs[:-1]] != [d for d, _ in orig] or descs[-1][1] != DLL:
        bad.append("дескрипторы: исходные не 1:1 или наш не последний")
    ft = descs[-1][0][4]
    if not (ir <= ft and ft + 8 <= ir + isz):
        bad.append("FirstThunk вне DataDirectory[IAT]")
    if sec_of(secs, ft)[0] != '.rdata':
        bad.append("FirstThunk не в .rdata")
    ibn = struct.unpack_from('<I', b, rva2off(secs, ft))[0]
    if cstr(b, rva2off(secs, ibn) + 2) != FUNC:
        bad.append("имя функции импорта не %s" % FUNC)
    summary = "изменено %d б (заголовок %d, блок %d), блок RVA 0x%X, FirstThunk RVA 0x%X, импорты: %s" % (
        len(changed), len(hdr), len(blk), r, ft, ", ".join(n for _, n in descs))
    return bad, summary, hashlib.md5(b).hexdigest()


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    argv = sys.argv[1:] if argv is None else argv
    only_check = "--check" in argv
    fail = 0
    for im in IMAGES:
        src = os.path.join(ROOT, im["src"])
        out = os.path.join(ROOT, im["out"])
        print("== %s (%s)" % (im["key"], im["where"]))
        if not only_check:
            info = inject(src, out, im["md5"], im["size"])
            print("  блок RVA 0x%X (файл 0x%X), %d б; FirstThunk RVA 0x%X; .data vsz 0x%X raw 0x%X (BSS — туда не кладём)" % (
                info["block_rva"], info["blk_off"], info["total"], info["iat_rva"], info["data_sec"][2], info["data_sec"][4]))
            print("  IMPORT было rva=0x%X size=0x%X, IAT было rva=0x%X size=0x%X" % (info["imp"] + info["iat0"]))
            print("  ОТКАТ без замены файла: по смещению 0x%X записать %s, по 0x%X — %s" % (
                info["dd_imp"], info["hdr_before"][:8].hex(" "), info["dd_iat"] + 4, info["hdr_before"][8:].hex(" ")))
        bad, summary, md5 = check(src, out)
        print("  %s" % summary)
        print("  выход %s  md5 %s" % (im["out"], md5))
        for b in bad:
            print("  [!!] %s" % b)
        print("  %s" % ("✔ верификация пройдена" if not bad else "✘ верификация НЕ пройдена"))
        fail += 1 if bad else 0
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
