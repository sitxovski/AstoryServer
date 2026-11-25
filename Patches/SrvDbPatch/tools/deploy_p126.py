# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p126.py — ВЫКЛАДКА / ОТКАТ / ПРОВЕРКА «P126_DbReconnect — повторное подключение к SQL Server после обрыва связи»
#   (15.11.2026) на dev-стойку: SrvDbPatch.dll + exe с инъекцией импорта в пяти папках — RelayServer, Indun_RelayServer,
#   Ch2_RelayServer, ItemRelayServer, OperationServer.
#   Образец — DbReconnect/tools/deploy_p125.py (примитивы SSH/scp ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5 берутся
#   оттуда импортом без изменений). ВСЕ операции — по SSH (PowerShell, FileStream с совместным доступом) и scp; шару не трогаем.
#   Документ: AstoryServer/Docs/_Common/db-reconnect-p126-srvdbpatch.md. Отчёт: Reports/relay_db_reconnect/REPORT.md.
#   ★ Реальная выкладка и перезапуск стойки — ТОЛЬКО координатор по слову владельца. По умолчанию — сухой прогон (только чтение по SSH).
#       py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/restart_stack.py --deploy @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/SrvDbPatch/tools/deploy_p126.py
#     после старта: py -3.13 deploy_p126.py --check («[OK] P126_DbReconnect» в PatchLog всех пяти папок, ошибок 0).
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ процессах пяти папок):
#   1. Локально: md5 SrvDbPatch.dll = DLL_WANT, md5 каждого собранного exe = want (стенд run_stand_p126.py — всё зелёное,
#      inject_import_srvdb.py --check — пройдено).
#   2. По ВСЕМ пяти папкам до первой записи: exe на стойке = prev (живой образ, на котором сделана инъекция; иначе СТОП, код 8);
#      exe и DLL не заняты (иначе код 2); DLL на стойке — нет или уже DLL_WANT (иначе СТОП, код 8).
#   3. Бэкап exe: рядом <exe>.bak_20261115_p126, на сервере v2\_backup\2026-11-15_relay_db_reconnect\..., локально
#      @@ASTORY_DEV_ROOT@@\_backup\2026-11-15_relay_db_reconnect\server\v2\...; сверка md5. Существующие бэкапы не перезаписываются.
#   4. DLL — по scp во временный <dll>.p126_upload (сверка md5), копия на место, сверка. Exe — так же через <exe>.p126_upload.
#   5. stack_layout.EXE_MD5 трёх RelayServer → «после» (6851e000… ×2, Ch2 418b24a2…): точечно, бэкап stack_layout.py
#      в @@ASTORY_DEV_ROOT@@\_backup\2026-11-15_p126_deploy_layout\ЧЧММСС\, сверка выполнением текста; уже «после» — без записи.
#      Сбой правки → exe на сервере возвращаются из бэкапа, код 4 (иначе stack_parity остановит стойку, как 15.11 17:56).
#      Чужое значение EXE_MD5 (ни «до», ни «после») — СТОП ещё на шаге 2, сервер не тронут. ItemRelay/Operation в EXE_MD5 нет.
#      В конце — «ГОТОВО» (его ждёт restart_stack.py).
# Откат (--rollback; при остановленных процессах): exe из <exe>.bak_20261115_p126 (сверка md5 = prev; уже prev — пропуск),
#   затем EXE_MD5 → «до» (a8cd94ba… ×2, Ch2 075c41a5…), «ОТКАТ ГОТОВО». SrvDbPatch.dll остаётся
#   лежать: без инъекции импорта её никто не грузит. Быстрый откат без замены exe: ConfigSet\srvdbpatch.ini [P126_DbReconnect]
#   Enabled=0 + перезапуск.
# Проверка (--check; после старта): в блоке последнего запуска PatchLog каждой папки — «[OK] P126_DbReconnect», итог «ошибок 0».
# Журнал: SrvDbPatch/tools/run_p126_20261115/deploy.log (дописывается). Побочных эффектов при импорте нет; запуск — main().
import datetime
import hashlib
import os
import re
import shutil
import sys
import time

PATCHES = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches"
ROOT = PATCHES + "/SrvDbPatch"
sys.path.insert(0, os.path.join(PATCHES, "DbReconnect", "tools"))
from deploy_p125 import V2, ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # noqa: E402  примитивы стойки (без побочных эффектов)

SUFFIX = ".bak_20261115_p126"
SRV_BACKUP = V2 + r"\_backup\2026-11-15_relay_db_reconnect"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-15_relay_db_reconnect/server/v2"
LOG = ROOT + "/tools/run_p126_20261115/deploy.log"

DLL_NAME = "SrvDbPatch.dll"
DLL_BUILT = ROOT + "/out/SrvDbPatch.dll"
DLL_WANT = "51a77c74cec3c72a8338634bb8fe6f1b"

# Реестр паритета стойки: restart_stack после --apply зовёт stack_parity, а тот сверяет exe RelayServer с EXE_MD5.
STACK_LAYOUT = os.path.join(PATCHES, "AsdaPatch", "tools", "stack_layout.py")
LAYOUT_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-15_p126_deploy_layout"          # бэкапы stack_layout.py до правки (подпапка ЧЧММСС)
RELAY_KEYS = ("RelayServer", "Indun_RelayServer", "Ch2_RelayServer")       # папки, чьи exe есть в EXE_MD5

# Пять папок. prev — живой exe (md5 снят 15.11.2026, по нему сделана инъекция и сверены площадки); want — exe с инъекцией.
RELAY = {"built": ROOT + "/out/RelayServer.exe.srvdbpatch.exe", "want": "6851e00055560fefc04f44c68956b9a5",
         "prev": "a8cd94ba91b32e6ad1a254feb0dd7bc0"}
TARGETS = [
    dict(RELAY, folder="RelayServer", exe_name="RelayServer.exe"),
    dict(RELAY, folder="Indun_RelayServer", exe_name="RelayServer.exe"),
    {"folder": "Ch2_RelayServer", "exe_name": "RelayServer.exe", "built": ROOT + "/out/RelayServer_ch2.exe.srvdbpatch.exe",
     "want": "418b24a21bf4c2cd222a56d0da53e19b", "prev": "075c41a5256eabbbab7c991bef9f47d5"},
    {"folder": "ItemRelayServer", "exe_name": "ItemRelayServer.exe", "built": ROOT + "/out/ItemRelayServer.exe.srvdbpatch.exe",
     "want": "35d01e2dcf98a0b9ad02251756514ae7", "prev": "b8c740b3e527ffbf3095f57874860d5d"},
    {"folder": "OperationServer", "exe_name": "OperationServer.exe", "built": ROOT + "/out/OperationServer.exe.srvdbpatch.exe",
     "want": "0f54ea7007522d64185a1bee630ccfc4", "prev": "a8209ce51f570bc7affde8c88e07845e"},
]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(src, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в SRV_BACKUP и локально; существующие не перезаписываются (сверка md5)."""
    want = rmd5(src)
    rel = src[len(V2) + 1:]
    for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся с оригиналом (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
        else:
            log(lines, "  бэкап уже есть: %s (%s)" % (dst, have))
    loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        if md5(loc) != want:
            raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл — разберись вручную" % loc)
        log(lines, "  локальный бэкап уже есть: %s" % loc)
        return
    data = rread(src)
    if hashlib.md5(data).hexdigest() != want:
        raise RuntimeError("прочитанное по SSH %s не сошлось по md5" % src)
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    if md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б %s" % (loc, len(data), want))


def put(local, remote, want, lines):
    """Залить файл через <remote>.p126_upload со сверкой md5 и положить на место. False — не сошлось (живой файл не тронут)."""
    up = remote + ".p126_upload"
    rupload(local, up)
    if rmd5(up) != want:
        rdel(up)
        log(lines, "СТОП: залитый %s не сошёлся по md5 — %s не тронут" % (up, remote))
        return False
    rcopy(up, remote)
    rdel(up)
    got = rmd5(remote)
    log(lines, "  выложено: %s %s %s" % (remote, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
    return got == want


def exe_md5_plan(target):
    """Ключ stack_layout.EXE_MD5 → (до, после, нужное) для трёх RelayServer; target — "after" (выкладка) или "before" (откат).
    ItemRelayServer и OperationServer в EXE_MD5 нет и не добавляются: копий-близнецов у них нет, паритет их не сверяет."""
    plan = {}
    for t in TARGETS:
        if t["folder"] in RELAY_KEYS:
            k = t["folder"] + "\\" + t["exe_name"]
            plan[k] = (t["prev"], t["want"], t["want"] if target == "after" else t["prev"])
    return plan


def set_exe_md5(target, lines, dry=False):
    """Точечно заменить md5 трёх RelayServer в stack_layout.EXE_MD5 (образец — AsdaPatch/tools/deploy_relay_gift.py).
    Каждое значение обязано быть «до» или «после», иначе отказ без записи; уже нужное — не трогается. Перед записью бэкап
    stack_layout.py, после — сверка выполнением текста файла (не импортом: мог бы взяться старый .pyc); несошлось — возврат
    из бэкапа и исключение. Возвращает путь бэкапа или None (сухо / правки нет)."""
    text = open(STACK_LAYOUT, encoding="utf-8").read()
    new = text
    changed = 0
    plan = exe_md5_plan(target)
    for k, (b, a, need) in plan.items():
        pat = re.compile(r'(r"%s":\s*")([0-9a-f]{32})(")' % re.escape(k))
        m = pat.findall(new)
        if len(m) != 1:
            raise RuntimeError("stack_layout.py: ключ %s найден %d раз (нужно 1)" % (k, len(m)))
        cur = m[0][1]
        if cur not in (b, a):
            raise RuntimeError("stack_layout.py: %s = %s — ни «до», ни «после», чужая правка; не трогаю" % (k, cur))
        if cur != need:
            new = pat.sub(lambda mm: mm.group(1) + need + mm.group(3), new)
            changed += 1
        log(lines, "  EXE_MD5[%s]: %s → %s%s" % (k, cur, need, " (уже)" if cur == need else " (сухо, без записи)" if dry else ""))
    if dry or not changed:
        return None
    stamp = datetime.datetime.now()
    bk = os.path.join(LAYOUT_BACKUP, stamp.strftime("%H%M%S"), "AstoryServer", "Patches", "AsdaPatch", "tools", "stack_layout.py")
    os.makedirs(os.path.dirname(bk), exist_ok=True)
    shutil.copy2(STACK_LAYOUT, bk)
    log(lines, "  бэкап stack_layout.py: %s" % bk)
    with open(STACK_LAYOUT, "w", encoding="utf-8", newline="") as f:
        f.write(new)
    ns = {"__file__": STACK_LAYOUT, "__name__": "stack_layout_check"}
    exec(compile(open(STACK_LAYOUT, encoding="utf-8").read(), STACK_LAYOUT, "exec"), ns)
    for k, (_b, _a, need) in plan.items():
        if ns["EXE_MD5"].get(k) != need:
            shutil.copy2(bk, STACK_LAYOUT)
            raise RuntimeError("stack_layout.py: после записи EXE_MD5[%s] = %s ≠ %s — возвращён из бэкапа" % (k, ns["EXE_MD5"].get(k), need))
    log(lines, "  stack_layout.py записан и сверен (%d правок)" % changed)
    return bk


def restore_exes(state, lines):
    """Вернуть exe из <exe>.bak_20261115_p126 там, где сейчас не prev. True — все пять = prev."""
    good = True
    for t, exe, _dll, _ce, _cd in state:
        if rmd5(exe) == t["prev"]:
            continue
        rcopy(exe + SUFFIX, exe)
        got = rmd5(exe)
        log(lines, "%s: exe возвращён из %s → %s %s" % (t["folder"], exe + SUFFIX, got, "OK" if got == t["prev"] else "НЕ СОШЛОСЬ"))
        good = good and got == t["prev"]
    return good


def check(lines):
    """После старта: в блоке последнего запуска PatchLog каждой из пяти папок — «[OK] P126_DbReconnect», итог «ошибок 0»."""
    sys.path.insert(0, os.path.join(PATCHES, "AsdaPatch", "tools"))
    import patchlog   # общий разбор журнала патчей (AsdaPatch/tools/patchlog.py), только чтение по SSH
    good = True
    for t in TARGETS:
        ok, _info = patchlog.check_folder(t["folder"], ["P126_DbReconnect"], need=["P126:"], log=lambda s: log(lines, "  " + s))
        good = good and ok
    log(lines, "ПРОВЕРКА: %s" % ("P126 установлен во всех пяти папках" if good else "P126 НЕ подтверждён — смотри PatchLog"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply, --rollback или --check."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p126 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                     "ПРОВЕРКА" if "--check" in sys.argv else "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        if "--check" in sys.argv:
            r = check(lines)
            flush(lines)
            return r

        stop = 0
        if not rollback:
            have = md5(DLL_BUILT)
            if have != DLL_WANT:
                log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (DLL_BUILT, have, DLL_WANT))
                stop = 3

        # ── 1. Проверки по ВСЕМ пяти папкам до первой записи ─────────────────
        state = []
        for t in TARGETS:
            d = V2 + "\\" + t["folder"]
            exe, dll = d + "\\" + t["exe_name"], d + "\\" + DLL_NAME
            st_exe, st_dll = rbusy(exe), rbusy(dll)
            if st_exe == "NONE":
                raise RuntimeError("нет файла %s" % exe)
            busy = [p for p, s in ((exe, st_exe), (dll, st_dll)) if s == "BUSY"]
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if busy and (apply or rollback):
                stop = stop or 2
            cur_exe = rmd5(exe)
            cur_dll = rmd5(dll)
            state.append((t, exe, dll, cur_exe, cur_dll))
            if rollback:
                if cur_exe == t["prev"]:
                    log(lines, "%s: %s уже исходный %s" % (t["folder"], t["exe_name"], cur_exe))
                elif cur_exe != t["want"]:
                    log(lines, "СТОП: %s сейчас %s, а не сборка P126 %s — откат не нужен или exe чужой" % (exe, cur_exe, t["want"]))
                    stop = stop or 9
                elif rmd5(exe + SUFFIX) != t["prev"]:
                    log(lines, "СТОП: %s нет или это не прежний exe %s" % (exe + SUFFIX, t["prev"]))
                    stop = stop or 6
                else:
                    log(lines, "%s: %s %s → вернётся %s" % (t["folder"], t["exe_name"], cur_exe, t["prev"]))
                continue
            have = md5(t["built"])
            if have != t["want"]:
                log(lines, "СТОП: собранный %s = %s, ожидался %s" % (t["built"], have, t["want"]))
                stop = stop or 3
            done = cur_exe == t["want"] and cur_dll == DLL_WANT
            log(lines, "%s: %s сейчас %s%s → будет %s; %s сейчас %s → будет %s%s" % (
                t["folder"], t["exe_name"], cur_exe, "" if cur_exe in (t["prev"], t["want"]) else " (НЕ ожидаемый %s!)" % t["prev"],
                t["want"], DLL_NAME, cur_dll, DLL_WANT, " (уже выложено)" if done else ""))
            if cur_exe not in (t["prev"], t["want"]):
                log(lines, "СТОП: на стойке не тот exe, на котором сделана инъекция — ничего не затираю, разберись вручную")
                stop = stop or 8
            if cur_dll not in ("none", DLL_WANT):
                log(lines, "СТОП: на стойке лежит чужая %s (%s) — ничего не затираю, разберись вручную" % (DLL_NAME, cur_dll))
                stop = stop or 8
        # EXE_MD5 сверяется ДО первой записи: чужое значение в stack_layout.py — СТОП, сервер не тронут.
        log(lines, "stack_layout.EXE_MD5 → %s:" % ("«до»" if rollback else "«после»"))
        try:
            set_exe_md5("before" if rollback else "after", lines, dry=True)
        except RuntimeError as e:
            log(lines, "СТОП: %s" % e)
            stop = stop or 8
        if stop:
            if stop == 2:
                log(lines, "СТОП: процессы не остановлены — ничего не тронуто")
            flush(lines)
            return stop

        # ── 2. Откат ──────────────────────────────────────────────────────────
        if rollback:
            if not restore_exes(state, lines):
                log(lines, "СТОП: не все exe вернулись — EXE_MD5 не трогаю, разберись вручную")
                flush(lines)
                return 4
            log(lines, "%s остаётся в папках — без инъекции импорта не грузится." % DLL_NAME)
            log(lines, "EXE_MD5 → «до»")
            set_exe_md5("before", lines)
            log(lines, "ОТКАТ ГОТОВО: exe и stack_layout.EXE_MD5 исходные; стойку НЕ перезапускал")
            flush(lines)
            return 0

        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (при остановленных процессах пяти папок)")
            flush(lines)
            return 0

        # ── 3. Выкладка ───────────────────────────────────────────────────────
        for t, exe, _dll, cur_exe, _cd in state:
            if cur_exe == t["prev"]:
                backup_one(exe, lines)
        for t, exe, dll, cur_exe, cur_dll in state:
            log(lines, "%s:" % t["folder"])
            if cur_dll != DLL_WANT and not put(DLL_BUILT, dll, DLL_WANT, lines):
                flush(lines)
                return 4
            if cur_exe != t["want"] and not put(t["built"], exe, t["want"], lines):
                flush(lines)
                return 4
        log(lines, "EXE_MD5 → «после»")
        try:
            set_exe_md5("after", lines)
        except (RuntimeError, OSError) as e:
            log(lines, "СБОЙ правки EXE_MD5: %s — откатываю exe на сервере (паритет иначе остановит стойку)" % e)
            restore_exes(state, lines)
            flush(lines)
            return 4
        log(lines, "ГОТОВО: SrvDbPatch.dll и exe с инъекцией (P126_DbReconnect) на месте в пяти папках, stack_layout.EXE_MD5 обновлён. "
                   "Старт стойки — за координатором; "
                   "затем py -3.13 deploy_p126.py --check (в PatchLog — «[OK] P126_DbReconnect»).")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
