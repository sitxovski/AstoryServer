# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p90.py — ВЫКЛАДКА / ОТКАТ слота P90 = AddonNPC N10 ред. 2 + N20 (волна exprate, 26.10.2026) на dev-стойку
#   (NpcServer и Indun_NpcServer) ОДНИМ рестартом. Разбор: Reports/exprate/MOB_EXP_AUDIT.md.
#   • N10 ред. 2 [ИСПРАВЛЕНИЕ НАШЕЙ ПРАВКИ]: стабы обычной атаки читали очередь ударов со сдвигом 4 б (забыт адрес возврата
#     `call`) — к урону игрока в списке угрозы на каждом пакете прибавлялся указатель this (~2·10^8): опыт отряда упирался в
#     1/9 уровня за моба (жалоба владельца «неадекватно много опыта в Rain River»), у одиночки — опыт 1 при переполнении,
#     владелец добычи — по числу пакетов. Теперь очередь [кадр+1Ch], все 4 удара, крит (бит 31) — урон `& 7FFFFFFFh`.
#   • N20 [ИСПРАВЛЕНИЕ]: доля урона в опыте ОТРЯДА (Process_MonsterDead 0x437ECD) зажата максимумом здоровья, как у одиночки
#     (сток 0x437DA6); отрицательная → 0; аномалии — журнал ac.other 115/116.
#   AddonNPC: живая bf7be252 (N01…N19 r2, Config 10) → WANT (Config 11: ключ [N10_NormalAttackHateDamage] CritHits и секцию
#   [N20_PartyShareClamp] DLL дописывает сама, значения ini не трогает). Общий AcJournal.cpp: тексты ac.other 115/116.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: restart_stack.py --deploy deploy_p90.py (GameServer/AsdaPatch не меняются;
#     --expect restart_stack проверяет журналы GameServer — для NpcServer после старта: python deploy_p90.py --check-started).
#   ★ Что увидят игроки: опыт в отряде вернётся к формуле (доля урона × база, бонус 38–67 % на 3–6 человек) вместо 1/9
#     уровня за каждого моба; у одиночки опыт делится по нанесённому урону (раньше любой удар обычной атакой давал полный опыт).
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ NpcServer/Indun_NpcServer):
#   1. md5 собранной DLL = WANT; md5 NpcServer.exe обеих папок = EXE_MD5[папка] (по ним сверены площадки, verify_n20.py).
#   2. Процессы не держат файлы. Занят — код 2.
#   3. DLL на стойке не из PREVS, уже WANT или разные в двух папках — СТОП, код 8.
#   4. Бэкап DLL и ConfigSet\patches.ini: рядом <файл>.bak_20261026_p90, на сервере v2\_backup\2026-10-26_p90\<папка>\...,
#      локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_exprate\server\v2\<папка>\...; сверка md5; существующий бэкап не перезаписывается.
#   5. Заливка по scp во временный <папка>\AddonNPC.dll.p90_upload (md5), копия поверх живой, сверка.
# Откат (--rollback; при остановленных процессах): только поверх WANT — DLL из <файл>.bak_20261026_p90 (bf7be252).
#   Быстрое выключение БЕЗ замены DLL: [N20_PartyShareClamp] Enabled=0 и/или [N10_NormalAttackHateDamage] Enabled=0 (сток:
#   обычная атака без урона в списке) + рестарт NpcServer/Indun_NpcServer. ⚠ Откат DLL возвращает дефект N10 ред. 1.
# Проверка после старта (--check-started; только чтение): последний PatchLog обеих папок — «[OK]» у N10 и N20, «ошибок 0».
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_p90_20261026_deploy/deploy.log (дописывается).
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
BUILT = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AddonNPC/out/AddonNPC.dll"
WANT = "4e916d04a8872bd5d1c05976aa236c5d"                       # AddonNPC N01…N19 r2 + N10 ред. 2 + N20 (Config 11)
PREVS = {"bf7be2526191cccc68c5cac06af2b358": "N01…N19 r2 (живая с 26.10 13:28, Config 10; N10 ред. 1 с дефектом)"}   # допустимые DLL стойки под заменой
EXE_MD5 = {"NpcServer": "c02486d62e803e98eb6fb4fa98d1fcd6",      # живой NpcServer.exe (импорт AddonNPC); площадки N10/N20 сверены по нему
           "Indun_NpcServer": "0de2c55932c2966537e2a8c539decdcd",
           "Ch2_NpcServer": stack_layout.EXE_MD5[r"Ch2_NpcServer\NpcServer.exe"]}   # 26.10: копия поля + имена таймеров Ch2_*
SUFFIX = ".bak_20261026_p90"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_p90"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_exprate/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_p90_20261026_deploy/deploy.log"
FOLDERS = stack_layout.NPC_FOLDERS   # было ["NpcServer", "Indun_NpcServer"] (26.10: + Ch2_NpcServer)

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
    tail = [l for l in out.splitlines() if l.strip()]
    return base64.b64decode(tail[-1].strip()) if tail else b""      # пустой файл → пустой base64 (стоковый Inferion.npc 0 б)


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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-26_p90 и локально; существующие не перезаписываются (сверка md5)."""
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
    """После старта: PatchLog каждой папки NpcServer, блок последнего запуска — [OK] у N10 (ред. 2, строка «4 удара») и N20,
    итог «ошибок 0», без провалов (patchlog). Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import patchlog
    good = True
    for d in FOLDERS:
        ok, _ = patchlog.check_folder(d, ["N10_NormalAttackHateDamage", "N20_PartyShareClamp"], ["4 удара"], log=lambda s: log(lines, s))
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
    log(lines, "== deploy_p90 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
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
                log(lines, "СТОП: NpcServer/Indun_NpcServer не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")

        if rollback:
            backs = {}
            for d in FOLDERS:
                cur = rmd5(V2 + "\\" + d + "\\AddonNPC.dll")
                if cur != WANT:
                    log(lines, "СТОП: в %s сейчас %s, а не P90 %s — откат не нужен или DLL чужая, ничего не трогаю" % (d, cur, WANT))
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
            log(lines, "ОТКАТ ГОТОВ (Config вернёт сама; ключ CritHits и секция [N20_PartyShareClamp] в ini останутся и будут проигнорированы; "
                       "⚠ вернулся дефект N10 ред. 1). "
                       "Нужен старт NpcServer/Indun_NpcServer.")
            flush(lines)
            return 0

        have = md5(BUILT)
        if have != WANT:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT, have, WANT))
            flush(lines)
            return 3
        # сначала проверка ОБЕИХ папок, потом запись — чужая DLL или чужой образ в любой папке останавливает до первой замены
        seen = set()
        for d in FOLDERS:
            exe = rmd5(V2 + "\\" + d + "\\NpcServer.exe")
            if exe != EXE_MD5[d]:
                log(lines, "СТОП: NpcServer.exe в %s = %s, а площадки N10/N20 сверены по %s — ничего не трогаю" % (d, exe, EXE_MD5[d]))
                flush(lines)
                return 8
            cur = rmd5(V2 + "\\" + d + "\\AddonNPC.dll")
            ini = rmd5(V2 + "\\" + d + "\\ConfigSet\\patches.ini")
            log(lines, "%s: NpcServer.exe %s; AddonNPC сейчас %s (%s) → будет %s (P90); patches.ini %s" % (
                d, exe, cur, PREVS.get(cur, "НЕ из допустимых!"), WANT, "есть" if ini != "none" else "НЕТ"))
            if cur == WANT:
                log(lines, "СТОП: в %s уже P90 — выкладывать нечего" % d)
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
            up = live + ".p90_upload"
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
        log(lines, "ГОТОВО: AddonNPC P90 (N10 ред. 2 + N20) в обеих папках. Старт процессов — за координатором; в PatchLog "
                   "NpcServer — «[OK] N10_NormalAttackHateDamage» (строка «… очередь [кадр+1Ch], 4 удара, криты считаются …»), "
                   "«[OK] N20_PartyShareClamp», «миграция Version 10 -> 11»; затем python deploy_p90.py --check-started.")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
