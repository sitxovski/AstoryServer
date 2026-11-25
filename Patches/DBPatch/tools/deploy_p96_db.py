# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p96_db.py — ВЫКЛАДКА / ОТКАТ / ПРОВЕРКА DBPatch Version 10 «P96_DbShellRows — сумка 60 строк» (30.10.2026, «инвентарь ×2»)
#   на dev-стойку. Образец — AsdaPatch/tools/deploy_p78.py: ВСЕ операции с файлами стойки — по SSH (PowerShell, FileStream с
#   FileShare.ReadWrite, предел времени на команду) и scp; шару \\@@ASTORY_SERVER_HOSTNAME@@ не трогаем. DBPatch v10 = живая v9+P85 9376a6bf (25.10) + P96.
#   Документ: AstoryServer/Docs/DBManager/db-shell-rows-p96.md. План: Reports/inventory_x2/PLAN.md §3.2, §5.
#   ★ ПАРА: AsdaPatch P96_InventoryX2 (GameServer/Indun/Ch2) + SQL inventory_x2_*_20261030 + клиент — выкладываются ОДНИМ окном
#     стойки (PLAN §5). Этот скрипт — только часть DBManager; его зовёт координатор (сам или из общего deploy_p96.py):
#       python restart_stack.py --deploy @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DBPatch/tools/deploy_p96_db.py ...   (или из deploy_p96.py)
#     после старта: python deploy_p96_db.py --check («[OK] P96_DbShellRows» в PatchLog DBManager).
#   ★ Рестарт DBManager и реальная выкладка — ТОЛЬКО координатор. По умолчанию — сухой прогон (только чтение по SSH).
#
# Выкладка (--apply; только при ОСТАНОВЛЕННОМ DBManager):
#   1. md5 собранной DLL = WANT (verify_p96_db.py 45/0, стенд stand_p96_db on/off/mismatch/dup — 0 ошибок); живой DBManager.exe =
#      EXE_MD5 (по нему сверены сигнатуры; сам патч ставится по сигнатуре и при другом образе откажет Mismatch, а не испортит код).
#   2. DBManager.exe / DBPatch.dll заняты (процесс работает) — код 2, ничего не тронуто.
#   3. На стойке DBPatch.dll ≠ ожидаемой PREV (v9+P85) — СТОП, код 8.
#   4. Бэкап DBPatch.dll и ConfigSet\dbpatch.ini (DLL допишет [P96_DbShellRows], Version 9→10): рядом <файл>.bak_20261030_p96,
#      на сервере v2\_backup\2026-10-30_inventory_x2\..., локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-29_inventory_x2\server\v2\...; сверка md5.
#   5. Заливает DLL по scp во временный DBPatch.dll.p96_upload (сверка md5), копирует поверх живой, сверяет md5. Печатает «ГОТОВО».
# Откат (--rollback; при остановленном DBManager): DLL из DBPatch.dll.bak_20261030_p96 (сверка md5 = PREV). v9 сама вернёт Version=9.
#   Быстрый откат без замены DLL: ConfigSet\dbpatch.ini [P96_DbShellRows] Enabled=0 + рестарт DBManager.
#   ⚠ Любой откат сумки — только вместе с AsdaPatch P96 и после запроса «есть ли Plate 1 Posx >= 30»
# Проверка (--check; после старта): в свежем Log\Log_Patch\PatchLog_*.txt DBManager — «[OK] P96_DbShellRows» и строка «P96db: 0x…»,
#   без «MISMATCH»/«!» по P96.
# Журнал: DBPatch/tools/run_p96_db_20261030/deploy.log (дописывается).
import base64
import hashlib
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DBPatch/out/DBPatch.dll"
WANT = "740562a4b82cb616751a320acf60450e"                      # DBPatch Version 10 (P96), сборка 30.10.2026 00:07
PREV = "9376a6bf64f0ba26066c6bb4032b6c13"                      # живая DBPatch Version 9 + P85 (25.10) — ожидаемая на стойке
SUFFIX = ".bak_20261030_p96"
SRV_BACKUP = V2 + r"\_backup\2026-10-30_inventory_x2"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-29_inventory_x2/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DBPatch/tools/run_p96_db_20261030/deploy.log"
FOLDER = "DBManager"
EXE_MD5 = "3d05c835b3f953bcde375ef8f13f3104"   # живой DBManager.exe (таблица импорта DBPatch); сигнатуры P96 сверены по нему

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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-30_inventory_x2 и локально; существующие не перезаписываются (сверка md5)."""
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
    """После старта DBManager: PatchLog, блок последнего запуска — «[OK] P96_DbShellRows», итог «ошибок 0», без провалов (patchlog) и без
    строк «: !» по P96."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools"))
    import patchlog   # общий разбор журнала патчей (AsdaPatch/tools/patchlog.py)
    ok, info = patchlog.check_folder(FOLDER, ["P96_DbShellRows"], log=lambda s: log(lines, "  " + s))
    run = info.get("run") or {}
    warn = [l.strip() for l in run.get("install", []) + run.get("runtime", []) if "P96" in l and ": !" in l]
    for w in warn:
        log(lines, "  ПРОВАЛ: " + w[:220])
    good = ok and not warn
    log(lines, "ПРОВЕРКА: %s" % ("P96 установлен" if good else "P96 НЕ подтверждён — смотри PatchLog"))
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
    log(lines, "== deploy_p96_db %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ПРОВЕРКА" if "--check" in sys.argv else "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        if "--check" in sys.argv:
            r = check(lines)
            flush(lines)
            return r
        d = V2 + "\\" + FOLDER
        live = d + "\\DBPatch.dll"
        ini = d + "\\ConfigSet\\dbpatch.ini"
        exe = d + "\\DBManager.exe"
        st = {p: rbusy(p) for p in (exe, live)}
        for p, s in st.items():
            if s == "NONE":
                raise RuntimeError("нет файла %s" % p)
        busy = [p for p, s in st.items() if s == "BUSY"]
        if busy:
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if apply or rollback:
                log(lines, "СТОП: DBManager не остановлен — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: DBManager работает — к выкладке его нужно остановить)")
        cur_exe = rmd5(exe)
        if cur_exe != EXE_MD5:
            log(lines, "СТОП: DBManager.exe на стойке %s, а сигнатуры P96 сверены по %s — разберись вручную" % (cur_exe, EXE_MD5))
            flush(lines)
            return 8
        if rollback:
            cur = rmd5(live)
            if cur != WANT:
                log(lines, "СТОП: сейчас %s, а не v10 %s — откат не нужен или DLL чужая, ничего не трогаю" % (cur, WANT))
                flush(lines)
                return 9
            if rmd5(live + SUFFIX) != PREV:
                log(lines, "СТОП: %s нет или это не v9+P85 %s" % (live + SUFFIX, PREV))
                flush(lines)
                return 6
            rcopy(live + SUFFIX, live)
            got = rmd5(live)
            log(lines, "DLL возвращена из %s → %s %s" % (live + SUFFIX, got, "OK" if got == PREV else "НЕ СОШЛОСЬ"))
            flush(lines)
            return 0 if got == PREV else 4
        have = md5(BUILT)
        if have != WANT:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
            flush(lines)
            return 3
        cur = rmd5(live)
        has_ini = rmd5(ini) != "none"
        log(lines, "DBManager: DBPatch.dll сейчас %s%s → будет %s; dbpatch.ini %s; DBManager.exe %s (OK)" % (
            cur, "" if cur == PREV else " (НЕ ожидаемая v9+P85 %s!)" % PREV, WANT, "есть" if has_ini else "НЕТ", cur_exe))
        if cur != PREV:
            log(lines, "СТОП: на стойке не та DLL, что ожидалась — ничего не затираю, разберись вручную")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply")
            flush(lines)
            return 0
        backup_one(live, lines)
        if has_ini:
            backup_one(ini, lines)
        up = live + ".p96_upload"
        rupload(BUILT, up)
        if rmd5(up) != WANT:
            rdel(up)
            log(lines, "СТОП: залитый %s не сошёлся по md5 — живая DLL не тронута" % up)
            flush(lines)
            return 4
        rcopy(up, live)
        rdel(up)
        got = rmd5(live)
        log(lines, "DBManager выложено: %s %s" % (got, "OK" if got == WANT else "НЕ СОШЛОСЬ"))
        if got != WANT:
            flush(lines)
            return 4
        log(lines, "ГОТОВО: DBPatch v10 (P96_DbShellRows) на месте. Старт DBManager — за координатором; затем python deploy_p96_db.py --check "
                   "(в PatchLog — «[OK] P96_DbShellRows» и «P96db: 0x00422E61/…»).")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
