# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p77.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v50 «P77 — 4009 в точку сервера при молчаливой остановке хода» (22.10.2026)
#   на dev-стойку. Порядок и проверки — как deploy_p29r2.py / deploy_p76.py; ★ отличие: ВСЕ операции с файлами стойки — по SSH
#   (PowerShell, FileStream с FileShare.ReadWrite, предел времени на каждую команду), а не по сетевой папке \\@@ASTORY_SERVER_HOSTNAME@@: чтение по SMB
#   файлов, открытых сервером, висло часами (грабля 22.10). AsdaPatch v50 = живая v49 bb20de13 (P29 ред. 2) + P77.
#   Документ: AstoryServer/Docs/GameServer/move-sync-stop-point-p77.md; отчёт Reports/p77_move_sync_point/REPORT.md.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (restart_stack.py --deploy deploy_p77.py --expect P77_MoveSyncStopPoint).
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ GameServer/Indun):
#   1. Сверяет md5 собранной DLL с ожидаемым (WANT).
#   2. Проверяет, что процессы не держат файлы (GameServer.exe и AsdaPatch.dll открываются на запись без совместного доступа). Занят — код 2.
#   3. На стойке DLL ≠ ожидаемой v49 (PREV) в ЛЮБОЙ из папок — СТОП, код 8: ничего не затирается (сначала проверка обеих).
#   4. Бэкап каждой заменяемой DLL и patches.ini (DLL допишет [P77_MoveSyncStopPoint], Version 49→50): рядом <файл>.bak_20261022_p77,
#      на сервере v2\_backup\2026-10-22_p77\<папка>\..., локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-22_p77\server\v2\<папка>\...;
#      сверка размера и md5; существующий бэкап не перезаписывается (сверяется).
#   5. Заливает DLL по scp во временный <папка>\AsdaPatch.dll.p77_upload (сверка md5), копирует поверх живой, сверяет md5 выложенной.
# Откат (--rollback; тоже при остановленных процессах): только поверх v50 (обе папки проверяются до записи);
#   DLL из <файл>.bak_20261022_p77 (сверка md5 = PREV). v49 сама вернёт Version=49; секция P77 в ini останется и будет проигнорирована.
#   Быстрый откат без замены DLL: в обоих patches.ini [P77_MoveSyncStopPoint] Enabled=0 + рестарт (MoveSyncProcess — сток).
# По умолчанию — сухой прогон (ничего не меняет, только чтение по SSH). Журнал: tools/run_p77_20261022/deploy.log (дописывается).
import base64
import hashlib
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT = "1a7484687613429ee175543c0b22ff05"                                               # v50 (P77)
PREV = "bb20de130f3de09ffdd067d7c6667757"                       # живая v49 (P29 ред. 2) — ожидаемая на стойке
SUFFIX = ".bak_20261022_p77"
SRV_BACKUP = V2 + r"\_backup\2026-10-22_p77"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-22_p77/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_p77_20261022/deploy.log"
FOLDERS = ["GameServer", "Indun_GameServer"]

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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-22_p77 и локально; существующие не перезаписываются (сверка md5)."""
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


def main():
    """Точка входа: сухой прогон, --apply или --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p77 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        busy = []
        for d in FOLDERS:
            for f in ("GameServer.exe", "AsdaPatch.dll"):
                p = V2 + "\\" + d + "\\" + f
                st = rbusy(p)
                if st == "NONE":
                    raise RuntimeError("нет файла %s" % p)
                if st == "BUSY":
                    busy.append(p)
        if busy:
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if apply or rollback:
                log(lines, "СТОП: GameServer/Indun не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")

        if rollback:
            # только поверх v50 — чужую DLL не затираем (сначала проверка обеих папок, потом запись)
            for d in FOLDERS:
                cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
                if cur != WANT:
                    log(lines, "СТОП: в %s сейчас %s, а не v50 %s — откат не нужен или DLL чужая, ничего не трогаю" % (d, cur, WANT))
                    flush(lines)
                    return 9
                bak = V2 + "\\" + d + "\\AsdaPatch.dll" + SUFFIX
                if rmd5(bak) != PREV:
                    log(lines, "СТОП: %s нет или это не v49 %s" % (bak, PREV))
                    flush(lines)
                    return 6
            for d in FOLDERS:
                live = V2 + "\\" + d + "\\AsdaPatch.dll"
                rcopy(live + SUFFIX, live)
                got = rmd5(live)
                log(lines, "%s: DLL возвращена из %s → %s %s" % (d, live + SUFFIX, got, "OK" if got == PREV else "НЕ СОШЛОСЬ"))
                if got != PREV:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (DLL v49; секция P77 в ini останется — v49 её игнорирует, Version вернёт сама). Нужен старт процессов.")
            flush(lines)
            return 0

        have = md5(BUILT)
        if have != WANT:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
            flush(lines)
            return 3
        # сначала проверка ОБЕИХ папок, потом запись — чужая DLL в любой папке останавливает до первой замены
        for d in FOLDERS:
            cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
            ini = rmd5(V2 + "\\" + d + "\\ConfigSet\\patches.ini")
            log(lines, "%s: сейчас %s%s → будет %s; patches.ini %s" % (d, cur, "" if cur == PREV else " (НЕ ожидаемая v49 %s!)" % PREV, WANT,
                                                                       "есть" if ini != "none" else "НЕТ"))
            if cur != PREV:
                log(lines, "СТОП: на стойке в %s не та DLL, что ожидалась (%s ≠ %s) — ничего не затираю, разберись вручную" % (d, cur, PREV))
                flush(lines)
                return 8
            if ini == "none":
                log(lines, "СТОП: нет %s\\ConfigSet\\patches.ini — ничего не трогаю" % d)
                flush(lines)
                return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply")
            flush(lines)
            return 0
        for d in FOLDERS:
            live = V2 + "\\" + d + "\\AsdaPatch.dll"
            for src in (live, V2 + "\\" + d + "\\ConfigSet\\patches.ini"):
                backup_one(src, lines)
            up = live + ".p77_upload"
            rupload(BUILT, up)
            if rmd5(up) != WANT:
                rdel(up)
                log(lines, "СТОП: залитый %s не сошёлся по md5 — живая DLL не тронута" % up)
                flush(lines)
                return 4
            rcopy(up, live)
            rdel(up)
            got = rmd5(live)
            log(lines, "%s выложено: %s %s" % (d, got, "OK" if got == WANT else "НЕ СОШЛОСЬ"))
            if got != WANT:
                flush(lines)
                return 4
        log(lines, "ГОТОВО: DLL v50 в обеих папках. Старт процессов — за координатором; в PatchLog — «[OK] P77_MoveSyncStopPoint», "
                   "строки «P77 S1…S4» и «P77: площадок 4».")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
