# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p125.py — ВЫКЛАДКА / ОТКАТ / ПРОВЕРКА «P125_DbReconnect — повторное подключение к SQL Server после обрыва связи»
#   (15.11.2026, сессия srv-db-reconnect) на dev-стойку: LoginManager\LoginPatch.dll (Version 10) и DBManager\DBPatch.dll (Version 11).
#   Образец — DBPatch/tools/deploy_p96_db.py (функции работы со стойкой взяты оттуда без изменений): ВСЕ операции — по SSH
#   (PowerShell, FileStream с совместным доступом) и scp; шару \\@@ASTORY_SERVER_HOSTNAME@@ не трогаем.
#   Документ: AstoryServer/Docs/_Common/db-reconnect-p125.md. Отчёт: Reports/login_db_reconnect/REPORT.md.
#   ★ Реальная выкладка и перезапуск стойки — ТОЛЬКО координатор по слову владельца. По умолчанию — сухой прогон (только чтение по SSH).
#       py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/restart_stack.py --deploy @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DbReconnect/tools/deploy_p125.py
#     после старта: py -3.13 deploy_p125.py --check («[OK] P125_DbReconnect» в PatchLog LoginManager и DBManager, ошибок 0).
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ LoginManager и DBManager) — по каждой из двух папок:
#   1. md5 собранной DLL = WANT (стенд run_stand_p125.py — всё зелёное, verify_p125.py — MISMATCH 0); живой exe = EXE (по нему сверены площадки;
#      при другом образе патч откажет Mismatch, а не испортит код).
#   2. exe / dll заняты (процесс работает) — код 2, ничего не тронуто (проверяются ОБЕ папки до первой записи).
#   3. На стойке DLL ≠ ожидаемой PREV — СТОП, код 8 (ничего не тронуто).
#   4. Бэкап DLL и ini (DLL допишет [P125_DbReconnect] и поднимет Version): рядом <файл>.bak_20261115_p125,
#      на сервере v2\_backup\2026-11-15_db_reconnect\..., локально @@ASTORY_DEV_ROOT@@\_backup\2026-11-15_db_reconnect\server\v2\...; сверка md5.
#   5. Заливает DLL по scp во временный <dll>.p125_upload (сверка md5), копирует поверх живой, сверяет md5. В конце — «ГОТОВО».
# Откат (--rollback; при остановленных процессах): DLL из <dll>.bak_20261115_p125 (сверка md5 = PREV). Прежняя DLL сама вернёт Version.
#   Быстрый откат без замены DLL: в ConfigSet\patches.ini (LoginManager) и ConfigSet\dbpatch.ini (DBManager) [P125_DbReconnect] Enabled=0
#   + перезапуск этих двух процессов.
# Проверка (--check; после старта): в блоке последнего запуска PatchLog обеих папок — «[OK] P125_DbReconnect», итог «ошибок 0».
# Журнал: DbReconnect/tools/run_p125_20261115/deploy.log (дописывается).
import base64
import hashlib
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
PATCHES = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches"
SUFFIX = ".bak_20261115_p125"
SRV_BACKUP = V2 + r"\_backup\2026-11-15_db_reconnect"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-15_db_reconnect/server/v2"
LOG = PATCHES + "/DbReconnect/tools/run_p125_20261115/deploy.log"

# Две цели выкладки. want — md5 собранной DLL с P125; prev — DLL, ожидаемая на стойке; exe — живой образ, по которому сверены площадки.
TARGETS = [
    {"folder": "LoginManager", "dll": "LoginPatch.dll", "ini": "patches.ini", "exe_name": "LoginManager.exe",
     "built": PATCHES + "/LoginPatch/out/LoginPatch.dll",
     "want": "2dcf9be9008975242692421fe376799d",
     "prev": "1bff1b631329d7e1c2347b3782d33eac",     # живая LoginPatch Version 9 (L08, 27.10.2026)
     "exe": "51db86b2a1c44b91b11bebfc343e88be"},
    {"folder": "DBManager", "dll": "DBPatch.dll", "ini": "dbpatch.ini", "exe_name": "DBManager.exe",
     "built": PATCHES + "/DBPatch/out/DBPatch.dll",
     "want": "f90f0faa50be7584dc0af855acc06cc5",
     "prev": "740562a4b82cb616751a320acf60450e",     # живая DBPatch Version 10 (P96, 30.10.2026)
     "exe": "3d05c835b3f953bcde375ef8f13f3104"},
]

# Общие функции PowerShell на сервере: md5 / «занят» / чтение — через FileStream с совместным доступом (не висит на открытых файлах).
PS_LIB = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Md5Of([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'NONE' }
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { $h = [Security.Cryptography.MD5]::Create().ComputeHash($fs) } finally { $fs.Close() }
  return ([BitConverter]::ToString($h) -replace '-', '').ToLower()
}
function IsBusy([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'NONE' }
  try { $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None'); $fs.Close(); return 'FREE' } catch { return 'BUSY' }
}
"""


def ps(script, stdin=None, timeout=120):
    """PowerShell-скрипт на сервере (-EncodedCommand); возврат (код, вывод utf-8)."""
    enc = base64.b64encode((PS_LIB + script).encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc], input=stdin,
                       capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        out += " | " + p.stderr.decode("utf-8", "replace").strip()[-500:]
    return p.returncode, out


def q(path):
    """Строка PowerShell в одинарных кавычках."""
    return "'" + path.replace("'", "''") + "'"


def rmd5(path):
    rc, out = ps("Write-Output (Md5Of %s)" % q(path))
    h = out.splitlines()[-1].strip().lower() if out else ""
    if rc != 0 or not (h == "none" or (len(h) == 32 and all(c in "0123456789abcdef" for c in h))):
        raise RuntimeError("md5 %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return h


def rbusy(path):
    rc, out = ps("Write-Output (IsBusy %s)" % q(path))
    st = out.splitlines()[-1].strip() if out else ""
    if rc != 0 or st not in ("FREE", "BUSY", "NONE"):
        raise RuntimeError("проверка занятости %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return st


def rread(path):
    """Содержимое файла стойки (чтение с совместным доступом) — для локального бэкапа."""
    rc, out = ps("$fs = [IO.File]::Open(%s, 'Open', 'Read', 'ReadWrite'); try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms) } "
                 "finally { $fs.Close() }; Write-Output ([Convert]::ToBase64String($ms.ToArray()))" % q(path), timeout=300)
    if rc != 0:
        raise RuntimeError("чтение %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return base64.b64decode(out.splitlines()[-1].strip())


def rcopy(src, dst):
    """Копия на сервере src → dst (папка создаётся); существующий dst не трогаем — вызывающий сверяет md5."""
    rc, out = ps("$d = Split-Path -Parent %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                 "Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output OK" % (q(dst), q(src), q(dst)))
    if rc != 0 or not out.endswith("OK"):
        raise RuntimeError("копия %s → %s по SSH: код %d: %s" % (src, dst, rc, out[-300:]))


def rupload(local, remote):
    """Залить локальный файл на сервер по scp (тот же ключ; путь стойки H:\\... → H:/...). Сверку md5 делает вызывающий."""
    dst = "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")
    p = subprocess.run(["scp", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", local, dst],
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        raise RuntimeError("заливка %s → %s по scp: код %d: %s" % (local, remote, p.returncode,
                                                                  (p.stdout + p.stderr).decode("utf-8", "replace")[-300:]))


def rdel(path):
    ps("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; Write-Output OK" % q(path))


def md5(path):
    """md5 локального файла (hex)."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-15_db_reconnect и локально; существующие не перезаписываются (сверка md5)."""
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
    if os.path.getsize(loc) != len(data) or md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б %s" % (loc, len(data), want))


def check(lines):
    """После старта: в блоке последнего запуска PatchLog LoginManager и DBManager — «[OK] P125_DbReconnect», итог «ошибок 0»."""
    sys.path.insert(0, os.path.join(PATCHES, "AsdaPatch", "tools"))
    import patchlog   # общий разбор журнала патчей (AsdaPatch/tools/patchlog.py)
    good = True
    for t in TARGETS:
        ok, _info = patchlog.check_folder(t["folder"], ["P125_DbReconnect"], need=["P125:"], log=lambda s: log(lines, "  " + s))
        good = good and ok
    log(lines, "ПРОВЕРКА: %s" % ("P125 установлен в LoginManager и DBManager" if good else "P125 НЕ подтверждён — смотри PatchLog"))
    return 0 if good else 5


def paths(t):
    """Пути цели на стойке: (живая DLL, ini, exe)."""
    d = V2 + "\\" + t["folder"]
    return d + "\\" + t["dll"], d + "\\ConfigSet\\" + t["ini"], d + "\\" + t["exe_name"]


def main():
    """Точка входа: сухой прогон, --apply, --rollback или --check."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p125 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                     "ПРОВЕРКА" if "--check" in sys.argv else "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        if "--check" in sys.argv:
            r = check(lines)
            flush(lines)
            return r

        # ── 1. Проверки по ОБЕИМ папкам до первой записи ─────────────────────
        stop = 0
        state = []
        for t in TARGETS:
            live, ini, exe = paths(t)
            st = {p: rbusy(p) for p in (exe, live)}
            for p, s in st.items():
                if s == "NONE":
                    raise RuntimeError("нет файла %s" % p)
            busy = [p for p, s in st.items() if s == "BUSY"]
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if busy and (apply or rollback):
                stop = stop or 2
            cur_exe = rmd5(exe)
            if cur_exe != t["exe"]:
                log(lines, "СТОП: %s на стойке %s, а площадки P125 сверены по %s — разберись вручную" % (t["exe_name"], cur_exe, t["exe"]))
                stop = stop or 8
            cur = rmd5(live)
            has_ini = rmd5(ini) != "none"
            state.append((t, live, ini, cur, has_ini))
            if rollback:
                if cur != t["want"]:
                    log(lines, "СТОП: %s сейчас %s, а не сборка P125 %s — откат не нужен или DLL чужая" % (t["dll"], cur, t["want"]))
                    stop = stop or 9
                elif rmd5(live + SUFFIX) != t["prev"]:
                    log(lines, "СТОП: %s нет или это не прежняя DLL %s" % (live + SUFFIX, t["prev"]))
                    stop = stop or 6
                continue
            have = md5(t["built"])
            if have != t["want"]:
                log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (t["built"], have, t["want"]))
                stop = stop or 3
            log(lines, "%s: %s сейчас %s%s → будет %s; %s %s; %s %s (OK)" % (
                t["folder"], t["dll"], cur, "" if cur == t["prev"] else " (НЕ ожидаемая %s!)" % t["prev"], t["want"],
                t["ini"], "есть" if has_ini else "НЕТ", t["exe_name"], cur_exe))
            if cur != t["prev"]:
                log(lines, "СТОП: на стойке не та DLL, что ожидалась — ничего не затираю, разберись вручную")
                stop = stop or 8
        if stop:
            if stop == 2:
                log(lines, "СТОП: LoginManager / DBManager не остановлены — ничего не тронуто")
            flush(lines)
            return stop

        # ── 2. Откат ──────────────────────────────────────────────────────────
        if rollback:
            bad = 0
            for t, live, _ini, _cur, _has in state:
                rcopy(live + SUFFIX, live)
                got = rmd5(live)
                log(lines, "%s: DLL возвращена из %s → %s %s" % (t["folder"], live + SUFFIX, got, "OK" if got == t["prev"] else "НЕ СОШЛОСЬ"))
                bad = bad or (got != t["prev"])
            flush(lines)
            return 4 if bad else 0

        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (при остановленных LoginManager и DBManager)")
            flush(lines)
            return 0

        # ── 3. Выкладка ───────────────────────────────────────────────────────
        for t, live, ini, _cur, has_ini in state:
            backup_one(live, lines)
            if has_ini:
                backup_one(ini, lines)
        for t, live, _ini, _cur, _has in state:
            up = live + ".p125_upload"
            rupload(t["built"], up)
            if rmd5(up) != t["want"]:
                rdel(up)
                log(lines, "СТОП: залитый %s не сошёлся по md5 — живая DLL не тронута" % up)
                flush(lines)
                return 4
            rcopy(up, live)
            rdel(up)
            got = rmd5(live)
            log(lines, "%s выложено: %s %s" % (t["folder"], got, "OK" if got == t["want"] else "НЕ СОШЛОСЬ"))
            if got != t["want"]:
                flush(lines)
                return 4
        log(lines, "ГОТОВО: LoginPatch v10 и DBPatch v11 (P125_DbReconnect) на месте. Старт стойки — за координатором; затем "
                   "py -3.13 deploy_p125.py --check (в PatchLog LoginManager и DBManager — «[OK] P125_DbReconnect»).")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
