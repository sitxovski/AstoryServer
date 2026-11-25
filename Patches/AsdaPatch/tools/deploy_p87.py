# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p87.py — ВЫКЛАДКА / ОТКАТ AsdaPatch P87 «стартовые навыки 4-й профессии по подклассу» (26.10.2026) на dev-стойку
#   (GameServer и Indun_GameServer) ОДНИМ рестартом. Дефект оригинала: sub_481CE0 LABEL_99 выдавал строку ChangeJobAddSkillTable
#   основного класса (3/14/25) вместо подкласса 4/15/26 — документ AstoryServer/Docs/GameServer/job4-start-skills-p87.md.
#   AsdaPatch: живая 54071b33 (v54, P85 r2, выложена 25.10 11:39) → WANT (v54 + P87; Config Version не меняется, секцию
#   [P87_Job4StartSkills] Enabled=1 DLL дописывает сама слиянием, значения ini не трогает). Общий AcJournal.cpp: тексты видов
#   ac.other 106/107/108 (DBPatch/AddonNPC не пересобираются — их видов это не касается).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (правило «объявление + 3 мин», слово владельца 21.10):
#       python restart_stack.py --deploy deploy_p87.py --expect P87_Job4StartSkills
#     (restart_stack объявляет перезапуск ботом в #test-info EN/AR/RU, ждёт 180 с, останавливает стойку, зовёт этот скрипт с
#     --apply, ждёт «ГОТОВО», запускает start.bat и сверяет «[OK] P87_Job4StartSkills» в PatchLog GameServer/Indun).
#     После старта: python deploy_p87.py --check-live — строки P87 в журнале патчей GameServer/Indun.
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ GameServer/Indun_GameServer):
#   1. md5 собранной DLL = WANT, в ней секция P87_Job4StartSkills; md5 GameServer.exe обеих папок = EXE_MD5 (по нему сверены
#      площадка 0x4820C9 и соседи — verify_p87.py).
#   2. Файлы не заняты процессами (занят — код 2).
#   3. DLL на стойке не из PREVS, уже WANT или разные в двух папках — СТОП, код 8 (ничего не тронуто).
#   4. Бэкап DLL и ConfigSet\patches.ini: рядом <файл>.bak_20261026_p87, на сервере v2\_backup\2026-10-26_p87\<папка>\...,
#      локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_p87\server\v2\<папка>\...; сверка md5; существующий бэкап не перезаписывается.
#   5. Заливка по scp во временный <папка>\AsdaPatch.dll.p87_upload (md5), копия поверх живой, сверка.
# Откат (--rollback; при остановленных процессах): только поверх WANT — DLL из <файл>.bak_20261026_p87 (md5 из PREVS).
#   Быстрое выключение БЕЗ замены DLL: [P87_Job4StartSkills] Enabled=0 + рестарт GameServer/Indun (площадка не ставится — сток).
#   Уже выданные по P87 навыки 4-й профессии откат НЕ снимает (они в БД персонажа — как любые изученные навыки).
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_p87_20261026_deploy/deploy.log (дописывается).
import base64
import hashlib
import os
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
SCP_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT = "cc8f572d209cb12d3e29728a90f771e3"                       # AsdaPatch v54 + P87 (сборка 26.10.2026, регресс run_p87_20261026)
PREVS = {"54071b339a3fc867ef6f8f310db5991a": "AsdaPatch v54 P85 r2 (живая с 25.10 11:39)"}   # допустимые DLL стойки под заменой
EXE_MD5 = "e7b4ac38e8328aaa847bbd9bf261bb01"                    # GameServer.exe (GameServer и Indun) — площадка P87 сверена по нему
SUFFIX = ".bak_20261026_p87"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_p87"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_p87/server/v2"
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_p87_20261026_deploy", "deploy.log")
FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"] (26.10: + Ch2_GameServer)
SECTION = "P87_Job4StartSkills"

# Общие функции PowerShell на сервере: md5 / «занят» — через FileStream с совместным доступом (не висит на открытых файлах).
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


def ps(script, timeout=120):
    """PowerShell-скрипт на сервере (-EncodedCommand); возврат (код, вывод utf-8)."""
    enc = base64.b64encode((PS_LIB + script).encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        out += " | " + p.stderr.decode("utf-8", "replace").strip()[-500:]
    return p.returncode, out


def q(path):
    """Строка PowerShell в одинарных кавычках."""
    return "'" + path.replace("'", "''") + "'"


def rmd5(path):
    """md5 файла стойки ('none' — файла нет)."""
    rc, out = ps("Write-Output (Md5Of %s)" % q(path))
    h = out.splitlines()[-1].strip().lower() if out else ""
    if rc != 0 or not (h == "none" or (len(h) == 32 and all(c in "0123456789abcdef" for c in h))):
        raise RuntimeError("md5 %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return h


def rbusy(path):
    """FREE / BUSY / NONE — держит ли файл процесс стойки."""
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
    """Копия на сервере src → dst (папка создаётся); вызывающий сверяет md5."""
    rc, out = ps("$d = Split-Path -Parent %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                 "Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output OK" % (q(dst), q(src), q(dst)))
    if rc != 0 or not out.endswith("OK"):
        raise RuntimeError("копия %s → %s по SSH: код %d: %s" % (src, dst, rc, out[-300:]))


def rupload(local, remote):
    """Залить локальный файл на сервер по scp (тот же ключ; путь стойки H:\\... → H:/...). Сверку md5 делает вызывающий."""
    dst = SCP_HOST + ":" + remote.replace("\\", "/")
    p = subprocess.run(["scp", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", local, dst],
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        raise RuntimeError("заливка %s → %s по scp: код %d: %s" % (local, remote, p.returncode,
                                                                  (p.stdout + p.stderr).decode("utf-8", "replace")[-300:]))


def rdel(path):
    """Удалить временный файл на сервере (ошибки игнорируются)."""
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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-26_p87 и локально; существующие не перезаписываются (сверка md5)."""
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


def check_live(lines):
    """После старта: PatchLog GameServer/Indun/Ch2, блок последнего запуска — «[OK] P87», без провалов (patchlog)."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import patchlog
    bad = 0
    for folder in FOLDERS:
        ok, _ = patchlog.check_folder(folder, [SECTION], log=lambda s: log(lines, s))
        bad += 0 if ok else 1
    log(lines, "ПРОВЕРКА ЖИВОГО: %s" % ("OK" if not bad else "ЕСТЬ ЗАМЕЧАНИЯ (%d)" % bad))
    return 0 if not bad else 1


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-live."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p87 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ПРОВЕРКА ЖИВОГО" if "--check-live" in sys.argv else
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        if "--check-live" in sys.argv:
            rc = check_live(lines)
            flush(lines)
            return rc
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
                log(lines, "СТОП: GameServer/Indun_GameServer не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")

        if rollback:
            backs = {}
            for d in FOLDERS:
                cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
                if cur != WANT:
                    log(lines, "СТОП: в %s сейчас %s, а не P87 %s — откат не нужен или DLL чужая, ничего не трогаю" % (d, cur, WANT))
                    flush(lines)
                    return 9
                bak = V2 + "\\" + d + "\\AsdaPatch.dll" + SUFFIX
                backs[d] = rmd5(bak)
                if backs[d] not in PREVS:
                    log(lines, "СТОП: %s нет или это не прежняя DLL (%s)" % (bak, backs[d]))
                    flush(lines)
                    return 6
            for d in FOLDERS:
                live = V2 + "\\" + d + "\\AsdaPatch.dll"
                rcopy(live + SUFFIX, live)
                got = rmd5(live)
                log(lines, "%s: DLL возвращена из %s → %s %s" % (d, live + SUFFIX, got, PREVS.get(got, "НЕ СОШЛОСЬ")))
                if got != backs[d]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (Version не менялась; секция [P87_Job4StartSkills] в ini останется и будет проигнорирована). "
                       "Нужен старт GameServer/Indun_GameServer.")
            flush(lines)
            return 0

        have = md5(BUILT)
        if have != WANT or SECTION.encode("utf-16-le") not in open(BUILT, "rb").read():
            log(lines, "СТОП: собранная %s = %s, ожидалась %s с секцией %s" % (BUILT, have, WANT, SECTION))
            flush(lines)
            return 3
        # сначала проверка ОБЕИХ папок, потом запись — чужая DLL или чужой образ в любой папке останавливает до первой замены
        seen = set()
        for d in FOLDERS:
            exe = rmd5(V2 + "\\" + d + "\\GameServer.exe")
            if exe != EXE_MD5:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадка P87 сверена по %s — ничего не трогаю" % (d, exe, EXE_MD5))
                flush(lines)
                return 8
            cur = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
            ini = rmd5(V2 + "\\" + d + "\\ConfigSet\\patches.ini")
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → будет %s (P87); patches.ini %s" % (
                d, exe, cur, PREVS.get(cur, "НЕ из допустимых!"), WANT, "есть" if ini != "none" else "НЕТ"))
            if cur == WANT:
                log(lines, "СТОП: в %s уже P87 — выкладывать нечего" % d)
                flush(lines)
                return 8
            if cur not in PREVS:
                log(lines, "СТОП: на стойке в %s не та DLL, что ожидалась (%s) — ничего не затираю, разберись вручную" % (d, cur))
                flush(lines)
                return 8
            if ini == "none":
                log(lines, "СТОП: нет %s\\ConfigSet\\patches.ini — ничего не трогаю" % d)
                flush(lines)
                return 8
            seen.add(cur)
        if len(seen) != 1:
            log(lines, "СТОП: в папках РАЗНЫЕ DLL — стойка в непоследовательном состоянии, разберись вручную")
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
            up = live + ".p87_upload"
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
        log(lines, "ГОТОВО: AsdaPatch (P87) в GameServer и Indun_GameServer. Старт стойки — за координатором; после старта: "
                   "deploy_p87.py --check-live (в PatchLog «[OK] P87_Job4StartSkills» и «+ секция [P87_Job4StartSkills]» слиянием).")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
