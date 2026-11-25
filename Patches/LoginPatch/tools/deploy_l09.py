# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""deploy_l09.py — ВЫКЛАДКА / ОТКАТ / ПРОВЕРКА LoginPatch v11 «L09_LoginMaintenance» (режим обслуживания, 21.11.2026; админ-центр А5.3)
на dev-стойку: LoginManager\\LoginPatch.dll. Образец — DbReconnect/tools/deploy_p125.py (функции работы со стойкой взяты оттуда без
изменений): все операции — по SSH (PowerShell, FileStream с совместным доступом) и scp; шару \\\\@@ASTORY_SERVER_HOSTNAME@@ не трогаем.
Документ: AstoryServer/Docs/LoginManager/L09-login-maintenance.md.

★ Реальная выкладка и перезапуск стойки — ТОЛЬКО по слову владельца. По умолчанию — сухой прогон (только чтение по SSH).
    py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/restart_stack.py --deploy @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/LoginPatch/tools/deploy_l09.py
  после старта: py -3.13 deploy_l09.py --check («[OK] L09_LoginMaintenance» в PatchLog LoginManager, ошибок 0).
  DLL без SQL-части L09 безвредна: процедура статус 28 не отдаёт — площадка входа пропускает все ответы как были; гейт входа в мир
  (★ ревизия 43 С-1) без adm.LoginMaintenanceGate пропускает вход как без режима (★ ревизия 43б Н-3: повтор запроса — через 2 с, при сбоях
  подряд окно удваивается до WorldMissingSec, по умолчанию 60 с; каждый сбой — строка «СБОЙ ГЕЙТА ВХОДА В МИР» в PatchLog, её видит панель).
  Порядок по решению ревизии 43: SQL L09 и DLL — в одном окне выкладки (SQL раньше, режим не включать, пока DLL не встала).

Ключи (иначе — отказ без действий):
  (нет)        сухой прогон: md5 сборки = WANT, на стойке PREV, exe = EXE, занятость файлов — стойку только ЧИТАЕТ по SSH;
               ★ ревизия 43 (мелочь 6): на ПК дописывает свой журнал tools/run_l09_20261121/deploy.log (как каждый режим, кроме -h)
  --apply      выкладка при ОСТАНОВЛЕННОМ LoginManager: бэкап DLL и ini рядом (*.bak_20261121_l09), на сервере v2\\_backup\\2026-11-21_l09,
               локально @@ASTORY_DEV_ROOT_ESC@@\\_backup\\2026-11-21_l09\\server\\v2; заливка scp во временный файл (сверка md5), копия поверх, сверка
  --rollback   при остановленном LoginManager: DLL из <dll>.bak_20261121_l09 (сверка md5 = PREV). Без замены DLL: [L09_LoginMaintenance] Enabled=0
  --check      после старта: в последнем запуске PatchLog LoginManager — «[OK] L09_LoginMaintenance», итог «ошибок 0»
  -h, --help   эта справка, ничего не делает
Коды: 0 готово, 2 LoginManager работает, 3 сборка не та, 4 заливка не сошлась, 5 проверка не прошла, 6/8/9 стойка не в ожидаемом
состоянии, 7 ошибка, 1 неизвестный ключ. Журнал — tools/run_l09_20261121/deploy.log (дописывается). Побочных эффектов при импорте нет.
"""
import base64
import hashlib
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
PATCHES = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches"
SUFFIX = ".bak_20261121_l09"
SRV_BACKUP = V2 + r"\_backup\2026-11-21_l09"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-21_l09/server/v2"
LOG = PATCHES + "/LoginPatch/tools/run_l09_20261121/deploy.log"
KNOWN_KEYS = {"--apply", "--rollback", "--check", "-h", "--help"}

TARGET = {"folder": "LoginManager", "dll": "LoginPatch.dll", "ini": "patches.ini", "exe_name": "LoginManager.exe",
          "built": PATCHES + "/LoginPatch/tools/l09_data/LoginPatch_v11_l09_98e5308b.dll",
          "want": "98e5308b8d7f292ff397087b9021e4c9",     # LoginPatch Version 11 (L09 + гейт входа в мир, ревизии 43 и 43б), tools/l09_data
          # (прежние сборки НЕ выкладывать, файлы оставлены в l09_data для истории: d5e97e0c — без гейта входа в мир; 3cbfea52 — гейт на
          #  DSN группы, режим 2 после смены личности, сбой открывал гейт на 60 с молча — ревизия 43б)
          "prev": "2dcf9be9008975242692421fe376799d",     # живая LoginPatch Version 10 (P125, 15.11.2026)
          "exe": "51db86b2a1c44b91b11bebfc343e88be"}       # живой LoginManager.exe, по нему сверена площадка 0x407B2F

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
    """Залить локальный файл на сервер по scp (путь стойки H:\\... → H:/...). Сверку md5 делает вызывающий; scp иногда таймаутит —
    одна повторная попытка."""
    dst = "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")
    last = None
    for _ in range(2):
        try:
            p = subprocess.run(["scp", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", local, dst],
                               capture_output=True, timeout=300)
        except subprocess.TimeoutExpired as ex:
            last = "таймаут scp (%s)" % ex
            continue
        if p.returncode == 0:
            return
        last = "код %d: %s" % (p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")[-300:])
    raise RuntimeError("заливка %s → %s по scp: %s" % (local, remote, last))


def rdel(path):
    ps("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; Write-Output OK" % q(path))


def md5(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def log(lines, line):
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(src, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-21_l09 и локально; существующие не перезаписываются (сверка md5)."""
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


def check(lines):
    """После старта: в блоке последнего запуска PatchLog LoginManager — «[OK] L09_LoginMaintenance», итог «ошибок 0»."""
    sys.path.insert(0, os.path.join(PATCHES, "AsdaPatch", "tools"))
    import patchlog   # общий разбор журнала патчей (AsdaPatch/tools/patchlog.py)
    ok, _info = patchlog.check_folder(TARGET["folder"], ["L09_LoginMaintenance"], need=["L09:"], log=lambda s: log(lines, "  " + s))
    log(lines, "ПРОВЕРКА: %s" % ("L09 установлен в LoginManager" if ok else "L09 НЕ подтверждён — смотри PatchLog"))
    return 0 if ok else 5


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    bad = [a for a in argv if a not in KNOWN_KEYS]
    if bad:
        print("deploy_l09: неизвестный ключ %s — ничего не сделано (-h — справка)" % ", ".join(bad))
        return 1
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    apply, rollback = "--apply" in argv, "--rollback" in argv
    if sum(k in argv for k in ("--apply", "--rollback", "--check")) > 1:
        print("deploy_l09: --apply, --rollback и --check — только по одному")
        return 1
    lines = []
    log(lines, "== deploy_l09 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "ПРОВЕРКА" if "--check" in argv else "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        if "--check" in argv:
            r = check(lines)
            flush(lines)
            return r
        t = TARGET
        d = V2 + "\\" + t["folder"]
        live, ini, exe = d + "\\" + t["dll"], d + "\\ConfigSet\\" + t["ini"], d + "\\" + t["exe_name"]
        st = {p: rbusy(p) for p in (exe, live)}
        for p, s in st.items():
            if s == "NONE":
                raise RuntimeError("нет файла %s" % p)
        busy = [p for p, s in st.items() if s == "BUSY"]
        for p in busy:
            log(lines, "  занят (процесс работает): " + p)
        stop = 2 if busy and (apply or rollback) else 0
        cur_exe = rmd5(exe)
        if cur_exe != t["exe"]:
            log(lines, "СТОП: %s на стойке %s, а площадка L09 сверена по %s — разберись вручную" % (t["exe_name"], cur_exe, t["exe"]))
            stop = stop or 8
        cur = rmd5(live)
        has_ini = rmd5(ini) != "none"
        if rollback:
            if cur != t["want"]:
                log(lines, "СТОП: %s сейчас %s, а не сборка L09 %s — откат не нужен или DLL чужая" % (t["dll"], cur, t["want"]))
                stop = stop or 9
            elif rmd5(live + SUFFIX) != t["prev"]:
                log(lines, "СТОП: %s нет или это не прежняя DLL %s" % (live + SUFFIX, t["prev"]))
                stop = stop or 6
        else:
            have = md5(t["built"])
            if have != t["want"]:
                log(lines, "СТОП: сборка %s = %s, ожидалась %s" % (t["built"], have, t["want"]))
                stop = stop or 3
            log(lines, "%s: %s сейчас %s%s → будет %s; %s %s; %s %s" % (
                t["folder"], t["dll"], cur, "" if cur == t["prev"] else " (НЕ ожидаемая %s!)" % t["prev"], t["want"],
                t["ini"], "есть" if has_ini else "НЕТ", t["exe_name"], cur_exe))
            if cur != t["prev"]:
                log(lines, "СТОП: на стойке не та DLL, что ожидалась — ничего не затираю, разберись вручную")
                stop = stop or 8
        if stop:
            if stop == 2:
                log(lines, "СТОП: LoginManager не остановлен — ничего не тронуто")
            flush(lines)
            return stop
        if rollback:
            rcopy(live + SUFFIX, live)
            got = rmd5(live)
            log(lines, "DLL возвращена из %s → %s %s" % (live + SUFFIX, got, "OK" if got == t["prev"] else "НЕ СОШЛОСЬ"))
            flush(lines)
            return 0 if got == t["prev"] else 4
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (при остановленном LoginManager)")
            flush(lines)
            return 0
        backup_one(live, lines)
        if has_ini:
            backup_one(ini, lines)
        up = live + ".l09_upload"
        rupload(t["built"], up)
        if rmd5(up) != t["want"]:
            rdel(up)
            log(lines, "СТОП: залитый %s не сошёлся по md5 — живая DLL не тронута" % up)
            flush(lines)
            return 4
        rcopy(up, live)
        rdel(up)
        got = rmd5(live)
        log(lines, "LoginManager выложено: %s %s" % (got, "OK" if got == t["want"] else "НЕ СОШЛОСЬ"))
        if got != t["want"]:
            flush(lines)
            return 4
        log(lines, "ГОТОВО: LoginPatch v11 (L09_LoginMaintenance) на месте. Старт стойки — за координатором; затем "
                   "py -3.13 deploy_l09.py --check (в PatchLog LoginManager — «[OK] L09_LoginMaintenance»).")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
