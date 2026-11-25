# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_n24.py — ВЫКЛАДКА / ОТКАТ AddonNPC N24 (06.11.2026, сессия pet-hatch-summon) на dev-стойку: все папки NpcServer из
#   stack_layout.NPC_FOLDERS (NpcServer, Indun_NpcServer, Ch2_NpcServer) ОДНИМ рестартом. Документ: AstoryServer/Docs/NpcServer/low-mob-loot-n24.md.
#   • N24 [ИСПРАВЛЕНИЕ, отклонение от оригинала по решению владельца]: нет лута с мобов при разнице уровней 7 и больше и в отряде с разбросом 10 и
#     больше; не прошедшие выбывают из выбора владельца. Площадка 0x4387D7.
#   AddonNPC: живая 4b03ad7d (N01…N23, Config 14) → WANT (Config 15: секцию [N24_LowMobLoot] DLL дописывает сама, значения ini не трогает).
#   Протокол, GameServer/AsdaPatch, БД и клиент не меняются; от выкладки P111 не зависит.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца: restart_stack.py --deploy deploy_n24.py; после старта NpcServer:
#     python deploy_n24.py --check-started.
#
# Режимы: (без ключа) — сухой прогон (только чтение по SSH); --apply — при ОСТАНОВЛЕННЫХ NpcServer: сверки md5, бэкапы (рядом SUFFIX, v2\_backup,
#   локально) DLL и patches.ini, заливка со сверкой; --rollback — только поверх WANT, DLL из <файл>.bak_20261106_n24 (4b03ad7d);
#   быстрое выключение без замены DLL: [N24_LowMobLoot] Enabled=0 + рестарт; --check-started — PatchLog каждой папки, «[OK]» у N23 и N24.
# Журнал: tools/run_n24_20261106_deploy/deploy.log (дописывается).
import base64
import hashlib
import os
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AddonNPC/tools/n24_data/AddonNPC_n24.dll"   # закреплённая сборка (out/ может пересобраться)
WANT = "621f44f86eac2c86bb688491d9cfc67f"                       # AddonNPC N01…N23 + N24 (Config 15)
PREVS = {"4b03ad7d36e3a0fcd51c0dfff19391c6": "N01…N23 (живая, Config 14)"}   # допустимые DLL стойки под заменой
EXE_MD5 = {"NpcServer": "c02486d62e803e98eb6fb4fa98d1fcd6",      # живой NpcServer.exe (импорт AddonNPC); площадки N24 сверены по нему
           "Indun_NpcServer": "0de2c55932c2966537e2a8c539decdcd",
           "Ch2_NpcServer": stack_layout.EXE_MD5[r"Ch2_NpcServer\NpcServer.exe"]}   # 26.10: копия поля + имена таймеров Ch2_*
SUFFIX = ".bak_20261106_n24"
SRV_BACKUP = V2 + r"\_backup\2026-11-06_n24"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-06_n24/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_n24_20261106_deploy/deploy.log"
FOLDERS = stack_layout.NPC_FOLDERS   # NpcServer, Indun_NpcServer, Ch2_NpcServer — только отсюда

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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-06_n24 и локально; существующие не перезаписываются (сверка md5)."""
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


def check_started(lines):
    """После старта: PatchLog каждой папки NpcServer, блок последнего запуска — [OK] у N23 и N24, итог «ошибок 0», без провалов
    (patchlog). Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import patchlog
    good = True
    for d in FOLDERS:
        ok, _ = patchlog.check_folder(d, ["N23_SkillHideAggro", "N24_LowMobLoot"], [], log=lambda s: log(lines, s))
        good = good and ok
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply или --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_n24 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    if "--check-started" in sys.argv:
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    try:
        busy = []
        for d in FOLDERS:
            for f in ("NpcServer.exe", "AddonNPC.dll"):
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
                log(lines, "СТОП: процессы NpcServer не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")

        if rollback:
            backs = {}
            for d in FOLDERS:
                cur = rmd5(V2 + "\\" + d + "\\AddonNPC.dll")
                if cur != WANT:
                    log(lines, "СТОП: в %s сейчас %s, а не N24 %s — откат не нужен или DLL чужая, ничего не трогаю" % (d, cur, WANT))
                    flush(lines)
                    return 9
                bak = V2 + "\\" + d + "\\AddonNPC.dll" + SUFFIX
                backs[d] = rmd5(bak)
                if backs[d] not in PREVS:
                    log(lines, "СТОП: %s нет или это не прежняя DLL (%s)" % (bak, backs[d]))
                    flush(lines)
                    return 6
            for d in FOLDERS:
                live = V2 + "\\" + d + "\\AddonNPC.dll"
                rcopy(live + SUFFIX, live)
                got = rmd5(live)
                log(lines, "%s: DLL возвращена из %s → %s %s" % (d, live + SUFFIX, got, PREVS.get(got, "НЕ СОШЛОСЬ")))
                if got != backs[d]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (Config вернёт сама до 14; секция [N24_LowMobLoot] в ini останется и будет проигнорирована). "
                       "Нужен старт NpcServer/Indun_NpcServer/Ch2_NpcServer.")
            flush(lines)
            return 0

        have = md5(BUILT)
        if have != WANT:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
            flush(lines)
            return 3
        # сначала проверка ВСЕХ папок, потом запись — чужая DLL или чужой образ в любой папке останавливает до первой замены
        seen = set()
        for d in FOLDERS:
            exe = rmd5(V2 + "\\" + d + "\\NpcServer.exe")
            if exe != EXE_MD5[d]:
                log(lines, "СТОП: NpcServer.exe в %s = %s, а площадки N24 сверены по %s — ничего не трогаю" % (d, exe, EXE_MD5[d]))
                flush(lines)
                return 8
            cur = rmd5(V2 + "\\" + d + "\\AddonNPC.dll")
            ini = rmd5(V2 + "\\" + d + "\\ConfigSet\\patches.ini")
            log(lines, "%s: NpcServer.exe %s; AddonNPC сейчас %s (%s) → будет %s (N24); patches.ini %s" % (
                d, exe, cur, PREVS.get(cur, "НЕ из допустимых!"), WANT, "есть" if ini != "none" else "НЕТ"))
            if cur == WANT:
                log(lines, "СТОП: в %s уже N24 — выкладывать нечего" % d)
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
            live = V2 + "\\" + d + "\\AddonNPC.dll"
            for src in (live, V2 + "\\" + d + "\\ConfigSet\\patches.ini"):
                backup_one(src, lines)
            up = live + ".n24_upload"
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
        log(lines, "ГОТОВО: AddonNPC N24 во всех папках NpcServer. Старт процессов — за координатором; в PatchLog "
                   "NpcServer — «[OK] N24_LowMobLoot», «миграция Version 14 -> 15»; затем python deploy_n24.py --check-started.")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
