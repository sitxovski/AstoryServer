# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# patch_relay_gift.py — P101_CashGift §3: RelayServer ×3 и ChannelManager пересылают 5076 (подарок кэш-магазина) телом
#   237 б (как читает GS получателя recvChatResponseUserCharChargeShopGift@0x513330), а не 153 б (01.11.2026, cash-gift-relay).
#   Разбор и обоснование мест: Reports/cash_gift/re/relay.md §5, проверка и стенд: Reports/cash_gift/p101/RELAY_DONE.md.
#
# Места (VA образа 0x400000; fo = смещение в файле, считается по заголовкам PE при каждом запуске):
#   ★ в relay.md §5 / PROJECT_P101 §3 адрес первого места указан 0x4042A8 — это начало lea ecx; 13 байт «было»
#     (FF7578 …) начинаются с push [ebp+78] @0x4042A5 (дизасм capstone). Байты те же, адрес исправлен.
#   RelayServer.exe (поле, Indun, Ch2)
#     sub_404264 (реле → GS получателя, вызов sub_4137A0)  0x4042A5: push [ebp+78]; lea ecx,[ebp-34]; push ecx; push eax; push 99h
#                                                          → push [ebp+78]; push [ebp+7C] (= a3, тело в буфере очереди); push eax; push 0EDh; nop
#     sub_4092D0 (реле → ChannelManager, вызов sub_413930) 0x4092F6: lea eax,[ebp-0A0h]; push eax → push [ebp+10] (= a3); nop×4
#                                                          0x4092FF: push 99h → push 0EDh
#   ChannelManager.exe
#     sub_40DCC2 (CM → реле канала получателя, sub_417760) 0x40DD4A: push 99h → push 0EDh (источник уже исходный буфер: push ebx)
#
# Режимы:
#   (без ключей)       СУХОЙ ПРОГОН: скачать живые exe по SSH/scp в _live_copies\<папка>\, применить к копиям
#                      (<имя>.exe остаётся живым оригиналом, рядом <имя>.patched.exe), показать md5. Сервер не меняется.
#   --file <путь>      пропатчить локальный файл НА МЕСТЕ (бэкап до правки — @@ASTORY_DEV_ROOT@@\_backup\<дата>_cashgift_relay\<путь>);
#                      --out <путь> — записать результат в другой файл, исходный не трогать. Вид (реле/CM) — по md5.
#   --remote           выкладка на живой dev: стойка ОБЯЗАНА быть остановлена (ни одного процесса стойки, иначе отказ);
#                      бэкап v2\_backup\cashgift_relay_<дата>\<папка>\<exe>, scp во временное имя, сверка md5, замена,
#                      сверка md5 «после». Перезапуск стойки НЕ делается (его делает координатор: restart_stack.py с объявлением).
#   --rollback         вернуть бэкапы из v2\_backup\cashgift_relay_<дата> (--date ГГГГММДД; по умолчанию ПОСЛЕДНЯЯ такая папка
#                      на сервере, печатается) со сверкой md5: сначала проверка всех файлов, потом возврат; стойка остановлена.
#   ★ 02.11 (ревизия REVIEW_RELAY.md): M1 выкладка «всё или ничего» — бэкап всех → загрузка всех во временные имена →
#     замена по одной с md5; сбой на замене → уже заменённые возвращаются из бэкапа. L1 относительные пути --file/--out.
#     L2 откат проверяет все бэкапы до возврата. L3 дата отката по умолчанию — последний бэкап. Выкладка через
#     restart_stack.py --deploy — обёртка AsdaPatch\tools\deploy_relay_gift.py (--apply, «ГОТОВО», EXE_MD5).
# Отказ при ЛЮБОМ расхождении: md5 «до» не из белого списка, байты «было» не совпали, md5 «после» не равен ожидаемому.
# Уже пропатченный файл (md5 «после») не трогается повторно.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает; всё — в main().
import argparse
import base64
import datetime
import hashlib
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                                 # AstoryServer\Patches\RelayGift
LIVE_COPIES = os.path.join(HERE, "_live_copies")                                  # копии живых exe для сухого прогона
BACKUP_ROOT = r"@@ASTORY_DEV_ROOT@@\_backup"                                               # локальные бэкапы до правки
KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"                                         # ключ SSH к dev-серверу
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"                                              # dev-сервер (Tailscale)
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]  # базовая команда SSH
SCP = ["scp", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]        # базовая команда scp
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                                                    # стойка (Windows-путь на сервере)
V2_SCP = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"                                                 # тот же путь для scp

# Процессы стойки (как stack_layout.PROCS): при --remote/--rollback ни одного не должно быть.
STACK_PROCS = ["ChannelManager", "DBManager", "OperationServer", "OverlapCheckServer", "RelayServer", "ItemRelayServer",
               "LoginManager", "NpcServer", "GameServer"]

# Места правки: вид бинаря → [(VA, «было», «стало», пояснение)].
PATCHES = {
    "relay": [
        (0x4042A5, "FF75788D4DCC51506899000000", "FF7578FF757C5068ED00000090",
         "sub_404264 → sub_4137A0(5076, 237, sock, a3, a2): тело из буфера очереди, не из 153-байтовой копии"),
        (0x4092F6, "8D8560FFFFFF50", "FF751090909090",
         "sub_4092D0 → sub_413930: источник = a3 (буфер очереди), не копия [ebp-0A0h]"),
        (0x4092FF, "6899000000", "68ED000000",
         "sub_4092D0 → sub_413930: размер 153 → 237"),
    ],
    "cm": [
        (0x40DD4A, "6899000000", "68ED000000",
         "sub_40DCC2 → sub_417760: размер 153 → 237 (источник уже исходный буфер, push ebx)"),
    ],
}

# Белый список «до»: md5 → (вид, что это). Сняты с живого 01.11.2026 (ssh Get-FileHash) и с RE/ida/*_work.
MD5_BEFORE = {
    "97cda8509fc1c576adedb741ca123f37": ("relay", "RelayServer.exe (поле и Indun; = relay_work)"),
    "1ceccf1af6acb00cf17710d5bfa1a0cc": ("relay", "Ch2_RelayServer RelayServer.exe (+ 'Ch2WaitTimer' @fo 0x19038)"),
    "e338a9d471853256fe37589303bc343b": ("cm", "ChannelManager.exe (= cm_work)"),
}
# Ожидаемый md5 «после» для каждого md5 «до» (посчитан сухим прогоном 01.11.2026, повторяется детерминированно).
MD5_AFTER = {
    "97cda8509fc1c576adedb741ca123f37": "a8cd94ba91b32e6ad1a254feb0dd7bc0",
    "1ceccf1af6acb00cf17710d5bfa1a0cc": "075c41a5256eabbbab7c991bef9f47d5",
    "e338a9d471853256fe37589303bc343b": "502e940db681a484cb73fcabbe9a88f4",
}

# Живые файлы стойки (относительно v2) и их md5 «до».
TARGETS = [
    (r"RelayServer\RelayServer.exe", "97cda8509fc1c576adedb741ca123f37"),
    (r"Indun_RelayServer\RelayServer.exe", "97cda8509fc1c576adedb741ca123f37"),
    (r"Ch2_RelayServer\RelayServer.exe", "1ceccf1af6acb00cf17710d5bfa1a0cc"),
    (r"ChannelManager\ChannelManager.exe", "e338a9d471853256fe37589303bc343b"),
]


class PatchError(Exception):
    """Любое расхождение — отказ без записи."""


def md5(data):
    """md5 байтов → hex нижним регистром."""
    return hashlib.md5(data).hexdigest()


def va_to_fo(data, va):
    """VA → смещение в файле по заголовкам PE (ImageBase и таблица секций)."""
    if data[:2] != b"MZ":
        raise PatchError("не PE: нет MZ")
    pe = struct.unpack_from("<I", data, 0x3C)[0]                                  # e_lfanew
    if data[pe:pe + 4] != b"PE\0\0":
        raise PatchError("не PE: нет сигнатуры PE")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]                              # NumberOfSections
    optsz = struct.unpack_from("<H", data, pe + 20)[0]                            # SizeOfOptionalHeader
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise PatchError("не PE32")
    base = struct.unpack_from("<I", data, opt + 28)[0]                            # ImageBase
    rva = va - base
    sec = opt + optsz
    for i in range(nsec):
        s = sec + 40 * i
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, s + 8)
        if vaddr <= rva < vaddr + max(vsize, rsize) and rva - vaddr < rsize:
            return rptr + (rva - vaddr)
    raise PatchError("VA 0x%X вне секций файла" % va)


def classify(data):
    """md5 файла → ('before'|'after', вид, md5 «до»); иначе PatchError."""
    h = md5(data)
    if h in MD5_BEFORE:
        return "before", MD5_BEFORE[h][0], h
    for b, a in MD5_AFTER.items():
        if h == a:
            return "after", MD5_BEFORE[b][0], b
    raise PatchError("md5 %s не в белом списке (ни «до», ни «после»)" % h)


def apply_patch(data, log=print):
    """Байты исходного exe → (байты результата, вид, md5 до, md5 после). Сверка «было», запись «стало», сверка md5 после."""
    state, kind, before = classify(data)
    if state == "after":
        log("  уже пропатчен (md5 %s) — без изменений" % md5(data))
        return bytes(data), kind, before, md5(data)
    buf = bytearray(data)
    for va, old, new, note in PATCHES[kind]:
        o, n = bytes.fromhex(old), bytes.fromhex(new)
        if len(o) != len(n):
            raise PatchError("длины было/стало не равны @0x%X" % va)
        fo = va_to_fo(buf, va)
        cur = bytes(buf[fo:fo + len(o)])
        if cur != o:
            raise PatchError("байты «было» не совпали @VA 0x%X fo 0x%X: %s ≠ %s" % (va, fo, cur.hex().upper(), old))
        buf[fo:fo + len(n)] = n
        log("  VA 0x%06X fo 0x%05X: %s → %s  (%s)" % (va, fo, old, new, note))
    for va, old, new, _ in PATCHES[kind]:                                         # сверка «стало»
        fo = va_to_fo(buf, va)
        if bytes(buf[fo:fo + len(new) // 2]) != bytes.fromhex(new):
            raise PatchError("сверка «стало» не прошла @0x%X" % va)
    after = md5(buf)
    exp = MD5_AFTER.get(before)
    if exp and after != exp:
        raise PatchError("md5 «после» %s ≠ ожидаемому %s" % (after, exp))
    return bytes(buf), kind, before, after


def ps(cmd, timeout=300):
    """PowerShell по SSH → (код, вывод)."""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def scp_get(rel, dst):
    """Скачать v2\\<rel> → dst."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    r = subprocess.run(SCP + ["%s:%s/%s" % (HOST, V2_SCP, rel.replace("\\", "/")), dst], capture_output=True, timeout=300)
    if r.returncode != 0:
        raise PatchError("scp get %s: %s" % (rel, (r.stdout + r.stderr).decode("utf-8", "replace")))


def scp_put(src, rel):
    """Загрузить src → v2\\<rel>."""
    r = subprocess.run(SCP + [src, "%s:%s/%s" % (HOST, V2_SCP, rel.replace("\\", "/"))], capture_output=True, timeout=300)
    if r.returncode != 0:
        raise PatchError("scp put %s: %s" % (rel, (r.stdout + r.stderr).decode("utf-8", "replace")))


def remote_md5(rel):
    """md5 файла v2\\<rel> на сервере (нижний регистр) или '' если нет файла."""
    rc, out = ps("$p = '%s\\%s'; if (Test-Path -LiteralPath $p) { (Get-FileHash -Algorithm MD5 -LiteralPath $p).Hash } "
                 "else { 'NOFILE' }" % (V2, rel))
    # 02.11: в выводе бывает CLIXML прогресса «подготовка модулей» (stderr идёт после stdout) — берём строку хэша/NOFILE
    hits = [ln.strip() for ln in out.splitlines() if ln.strip() == "NOFILE" or
            (len(ln.strip()) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in ln.strip()))]
    out = hits[-1] if hits else ""
    if rc != 0 or not out:
        raise PatchError("md5 %s: код %d, вывод %r" % (rel, rc, out))
    return "" if out == "NOFILE" else out.lower()


def require_stack_stopped(log):
    """Отказ, если работает хоть один процесс стойки (по пути под v2 или по имени)."""
    names = ",".join("'%s'" % n for n in STACK_PROCS)
    rc, out = ps("$n = @(%s); $p = Get-Process -ErrorAction SilentlyContinue | Where-Object { $n -contains $_.ProcessName }; "
                 "foreach ($x in $p) { 'RUN ' + $x.Id + ' ' + $x.ProcessName + ' ' + $x.Path }; 'COUNT=' + @($p).Count" % names)
    if rc != 0 or "COUNT=" not in out:
        raise PatchError("не удалось проверить процессы: %r" % out)
    run = [l for l in out.splitlines() if l.startswith("RUN ")]
    if run:
        for l in run:
            log("  " + l)
        raise PatchError("стойка не остановлена (%d процессов) — остановите стойку, перезапуск делает координатор" % len(run))
    log("  стойка остановлена: процессов стойки 0")


def local_backup(path, date):
    """Копия файла до правки → @@ASTORY_DEV_ROOT_ESC@@\\_backup\\<дата>_cashgift_relay\\<путь без диска>."""
    drive, tail = os.path.splitdrive(os.path.abspath(path))
    dst = os.path.join(BACKUP_ROOT, "%s_cashgift_relay" % date, drive.rstrip(":") + tail)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.exists(dst):
        shutil.copy2(path, dst)
    return dst


def write_md5_log(path, rows):
    """Строки «файл | md5 до | md5 после» → файл (L1 02.11: путь абсолютный, makedirs('') не вызывается)."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(" | ".join(r) + "\n")


# ── операции на сервере (вынесены отдельно: локальная проверка логики подменяет только их) ─────────────────────────
def remote_backup(rel, brel):
    """Копия v2\\<rel> → v2\\<brel>, если её ещё нет; → md5 копии."""
    rc, out = ps("$s = '%s\\%s'; $d = '%s\\%s'; New-Item -ItemType Directory -Force (Split-Path $d) | Out-Null; "
                 "if (-not (Test-Path -LiteralPath $d)) { Copy-Item -LiteralPath $s -Destination $d -ErrorAction Stop }; "
                 "'BK'" % (V2, rel, V2, brel))
    if rc != 0 or "BK" not in out:
        raise PatchError("бэкап %s: код %d, %r" % (brel, rc, out))
    return remote_md5(brel)


def remote_move(src_rel, dst_rel):
    """Move-Item -Force v2\\<src_rel> → v2\\<dst_rel>."""
    rc, out = ps("Move-Item -Force -ErrorAction Stop -LiteralPath '%s\\%s' -Destination '%s\\%s'" % (V2, src_rel, V2, dst_rel))
    if rc != 0:
        raise PatchError("перемещение %s → %s: %r" % (src_rel, dst_rel, out))


def remote_copy(src_rel, dst_rel):
    """Copy-Item -Force v2\\<src_rel> → v2\\<dst_rel>."""
    rc, out = ps("Copy-Item -Force -ErrorAction Stop -LiteralPath '%s\\%s' -Destination '%s\\%s'" % (V2, src_rel, V2, dst_rel))
    if rc != 0:
        raise PatchError("копирование %s → %s: %r" % (src_rel, dst_rel, out))


def remote_delete(rel):
    """Удалить временный файл v2\\<rel>, если он есть (без ошибки при отсутствии)."""
    ps("Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath '%s\\%s'" % (V2, rel))


def remote_backup_dates():
    """Даты (ГГГГММДД) папок v2\\_backup\\cashgift_relay_* на сервере, по возрастанию."""
    rc, out = ps("Get-ChildItem -Directory -LiteralPath '%s\\_backup' -Filter 'cashgift_relay_*' -ErrorAction SilentlyContinue | "
                 "ForEach-Object { 'D=' + $_.Name }" % V2)
    if rc != 0:
        raise PatchError("список бэкапов: %r" % out)
    pre = "D=cashgift_relay_"
    return sorted(l.strip()[len(pre):] for l in out.splitlines()
                  if l.strip().startswith(pre) and l.strip()[len(pre):].isdigit())


def mode_dry(log):
    """Сухой прогон по живым копиям → строки (файл, md5 до, md5 после)."""
    rows = []
    for rel, want in TARGETS:
        dst = os.path.join(LIVE_COPIES, rel)
        log("== %s" % rel)
        scp_get(rel, dst)
        data = open(dst, "rb").read()
        h = md5(data)
        log("  живой md5 %s (ожидался %s)%s" % (h, want, "" if h == want else "  ← РАСХОЖДЕНИЕ"))
        if h != want:
            raise PatchError("живой %s md5 %s ≠ %s" % (rel, h, want))
        out, kind, before, after = apply_patch(data, log)
        pdst = dst[:-4] + ".patched.exe"
        with open(pdst, "wb") as f:
            f.write(out)
        log("  → %s md5 %s" % (os.path.relpath(pdst, HERE), after))
        rows.append((rel, before, after))
    write_md5_log(os.path.join(LIVE_COPIES, "md5_after.txt"), rows)
    log("СУХОЙ ПРОГОН OK: %d файлов, md5 → _live_copies\\md5_after.txt; сервер не менялся" % len(rows))
    return rows


def mode_file(path, out_path, log):
    """Локальный файл: на месте (с бэкапом) или в --out (L1 02.11: относительные пути → абсолютные)."""
    path = os.path.abspath(path)
    out_path = os.path.abspath(out_path) if out_path else None
    data = open(path, "rb").read()
    out, kind, before, after = apply_patch(data, log)
    date = datetime.date.today().strftime("%Y-%m-%d")
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(out)
        dst = out_path
    else:
        if out != data:
            log("  бэкап до правки: %s" % local_backup(path, date))
            with open(path, "wb") as f:
                f.write(out)
        dst = path
    got = md5(open(dst, "rb").read())
    if got != after:
        raise PatchError("после записи md5 %s ≠ %s" % (got, after))
    write_md5_log(dst + ".md5_after.txt", [(path, before, after)])
    log("OK: %s (%s) md5 %s → %s" % (dst, kind, before, after))
    return before, after


def _restore_written(written, bdir, log):
    """M1: вернуть уже заменённые файлы из бэкапа (обратный порядок) со сверкой md5 «до» → список не вернувшихся."""
    left = []
    for rel, before in reversed(written):
        try:
            remote_copy("%s\\%s" % (bdir, rel), rel)
            h = remote_md5(rel)
            if h != before:
                raise PatchError("md5 %s ≠ %s" % (h, before))
            log("  возвращён %s md5 %s" % (rel, before))
        except (PatchError, OSError, subprocess.TimeoutExpired) as e:
            log("  !!! НЕ возвращён %s: %s" % (rel, e))
            left.append(rel)
    return left


def mode_remote(log, date=None):
    """Выкладка на живой dev при остановленной стойке, без перезапуска. ВСЁ ИЛИ НИЧЕГО (M1 02.11):
    1) проверка всех файлов и патч копий локально; 2) бэкап ВСЕХ на сервере со сверкой md5 «до»; 3) загрузка ВСЕХ во
    временные имена со сверкой md5 «после»; 4) замена по одной со сверкой md5 после каждой; сбой на шаге 4 → уже
    заменённые возвращаются из бэкапа (md5 «до»), временные удаляются. → (строки md5, дата бэкапа)."""
    date = date or datetime.date.today().strftime("%Y%m%d")
    bdir = r"_backup\cashgift_relay_%s" % date
    run = os.path.join(HERE, "run_remote_%s" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    require_stack_stopped(log)
    plan = []
    log("1) проверка и патч локальных копий")
    for rel, want in TARGETS:
        log("== %s" % rel)
        h = remote_md5(rel)
        if h == MD5_AFTER[want]:
            log("  уже пропатчен (md5 %s) — пропуск" % h)
            continue
        if h != want:
            raise PatchError("%s: живой md5 %s ≠ ожидаемому %s — ничего не заменено" % (rel, h, want))
        src = os.path.join(run, "orig", rel)
        scp_get(rel, src)
        data = open(src, "rb").read()
        if md5(data) != want:
            raise PatchError("%s: скачанный md5 %s ≠ %s" % (rel, md5(data), want))
        out, kind, before, after = apply_patch(data, log)
        pf = os.path.join(run, "patched", rel)
        os.makedirs(os.path.dirname(pf), exist_ok=True)
        with open(pf, "wb") as f:
            f.write(out)
        plan.append((rel, before, after, pf))
    if not plan:
        log("нечего выкладывать: все файлы уже пропатчены")
        return [], date
    require_stack_stopped(log)                                                    # повторно перед записью
    log("2) бэкап на сервере: v2\\%s" % bdir)
    for rel, before, after, pf in plan:
        hb = remote_backup(rel, "%s\\%s" % (bdir, rel))
        if hb != before:
            raise PatchError("%s: бэкап md5 %s ≠ «до» %s (чужой бэкап с этой датой?) — ничего не заменено" % (rel, hb, before))
        log("  %s md5 %s" % (rel, before))
    log("3) загрузка во временные имена")
    tmps = []
    try:
        for rel, before, after, pf in plan:
            tmp = rel + ".cashgift_new"
            tmps.append(tmp)
            scp_put(pf, tmp)
            if remote_md5(tmp) != after:
                raise PatchError("%s: загруженный файл md5 ≠ %s" % (tmp, after))
            log("  %s md5 %s" % (tmp, after))
    except (PatchError, OSError, subprocess.TimeoutExpired):
        for t in tmps:
            remote_delete(t)
        log("  сбой загрузки: временные удалены, живые файлы НЕ тронуты")
        raise
    log("4) замена (md5 после каждой)")
    written, rows = [], []
    try:
        for rel, before, after, pf in plan:
            remote_move(rel + ".cashgift_new", rel)
            written.append((rel, before))
            h = remote_md5(rel)
            if h != after:
                raise PatchError("%s: после замены md5 %s ≠ %s" % (rel, h, after))
            log("  заменён %s: %s → %s" % (rel, before, after))
            rows.append((rel, before, after))
    except (PatchError, OSError, subprocess.TimeoutExpired) as e:
        log("  СБОЙ на замене: %s — возвращаю уже заменённые (%d)" % (e, len(written)))
        for rel, _, _, _ in plan:
            remote_delete(rel + ".cashgift_new")
        left = _restore_written(written, bdir, log)
        if left:
            raise PatchError("СМЕШАННОЕ состояние: не возвращены %s — вручную из v2\\%s" % (", ".join(left), bdir))
        raise PatchError("выкладка отменена целиком (все заменённые возвращены, md5 «до»): %s" % e)
    write_md5_log(os.path.join(run, "md5_after.txt"), rows)
    log("ВЫЛОЖЕНО: %d файлов; бэкап v2\\%s (для отката: --date %s); стойку НЕ перезапускал" % (len(rows), bdir, date))
    return rows, date


def resolve_rollback_date(date, log):
    """L3: дата бэкапа для отката — заданная или ПОСЛЕДНЯЯ папка cashgift_relay_* на сервере (печатается)."""
    if date:
        log("  дата бэкапа (задана): %s" % date)
        return date
    dates = remote_backup_dates()
    if not dates:
        raise PatchError("на сервере нет v2\\_backup\\cashgift_relay_* — откатывать нечего")
    log("  дата бэкапа (последняя на сервере из %s): %s" % (", ".join(dates), dates[-1]))
    return dates[-1]


def mode_rollback(date, log):
    """Вернуть бэкапы v2\\_backup\\cashgift_relay_<дата> со сверкой md5. L2 02.11: СНАЧАЛА проверка всех файлов
    (текущий «до» → пропуск; текущий «после» → бэкап обязан быть и равен «до»; иное → отказ), потом возврат.
    → список возвращённых."""
    require_stack_stopped(log)
    date = resolve_rollback_date(date, log)
    bdir = r"_backup\cashgift_relay_%s" % date
    todo = []
    for rel, want in TARGETS:                                                     # 1) только проверка
        h = remote_md5(rel)
        if h == want:
            log("  %s: уже исходный (md5 %s) — пропуск" % (rel, want))
            continue
        if h != MD5_AFTER[want]:
            raise PatchError("%s: текущий md5 %s ни «до», ни «после» — чужая правка; ничего не возвращено" % (rel, h))
        brel = "%s\\%s" % (bdir, rel)
        hb = remote_md5(brel)
        if not hb:
            raise PatchError("нет бэкапа v2\\%s — ничего не возвращено" % brel)
        if hb != want:
            raise PatchError("бэкап %s md5 %s ≠ «до» %s — ничего не возвращено" % (brel, hb, want))
        todo.append((rel, want, brel))
    done = []
    for rel, want, brel in todo:                                                  # 2) возврат
        remote_copy(brel, rel)
        h = remote_md5(rel)
        if h != want:
            raise PatchError("%s: после возврата md5 %s ≠ %s (уже возвращены: %s)" % (rel, h, want, ", ".join(done) or "—"))
        log("  возвращён %s md5 %s" % (rel, want))
        done.append(rel)
    log("ОТКАТ: возвращено %d файлов из v2\\%s; стойку НЕ перезапускал" % (len(done), bdir))
    return done


def main(argv=None):
    """Разбор ключей и запуск режима; код возврата 0 = успех, 1 = отказ."""
    ap = argparse.ArgumentParser(description="P101: 5076 через RelayServer/ChannelManager телом 237 б")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--file", help="локальный exe (патч на месте с бэкапом или в --out)")
    g.add_argument("--remote", action="store_true", help="выкладка на живой (стойка должна быть остановлена)")
    g.add_argument("--rollback", action="store_true", help="вернуть бэкапы на живом")
    ap.add_argument("--out", help="с --file: куда записать результат")
    ap.add_argument("--date", default=None, help="с --rollback: дата бэкапа ГГГГММДД (по умолчанию — последняя на сервере)")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")             # кириллица и ≠ в любой консоли
    except (AttributeError, ValueError):
        pass
    try:
        if a.file:
            mode_file(a.file, a.out, print)
        elif a.remote:
            mode_remote(print)
        elif a.rollback:
            mode_rollback(a.date, print)
        else:
            mode_dry(print)
    except (PatchError, OSError, subprocess.TimeoutExpired) as e:
        print("ОТКАЗ: %s" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
