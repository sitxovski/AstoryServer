# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_channel2.py — ВКЛЮЧЕНИЕ / ОТКАТ второго полевого канала (26.10.2026; план Reports/channel2/PLAN.md, одобрен
# владельцем: разметка A — поле 0 и 1, Indun → 3; VillageServerConfig канала 2 = 15621).
#
# Папки Ch2_GameServer / Ch2_NpcServer / Ch2_RelayServer уже созданы и настроены (копии поля, свои порты 15621/15721/15821,
# канал 1, имена таймеров Ch2_*); этот скрипт правит ОБЩИЕ файлы стойки — только при ОСТАНОВЛЕННОЙ стойке:
#   ChannelManager\ini\Server_Info.ini            ChannelCount 2 → 4
#   GameServer, Indun_GameServer ConfigSet\ChannelInfo.ini   Count 1 → 2 (+ [CHANNEL_01] Age = 0)
#   Indun_GameServer\MapData_Info\GroupInfo.ini   CHANNEL_INDEX 1 → 3
#   Indun_RelayServer\ini\ChannelInfo.ini         ChannelIndex 1 → 3
#   Indun_NpcServer\ini\AIInfo.ini                Channel_Index 1 → 3
#   LoginManager\GameServerIP\GameServerIP.ini    [SERVERGROUP_0_CHANNEL_TOTAL] COUNT 1 → 2
#   LoginManager\GameServerIP\0_1_ServerIP.ini    23 × IP @@ASTORY_SERVER_LAN_IP@@ PORT 15621 (было — мусор 3241)
#   LoginManager\GameServerIP\CreateGameServerIP.ini  [SERVERGROUP_0] COUNT 1 → 2 + [Channel_Game0_1] 15621
#   EacServer\EacServer.ini                       AllowedImageDirs + ..\Ch2_GameServer; служба AsdaEacServer — перезапуск
#   start.bat                                     + запуск Ch2_RelayServer / Ch2_NpcServer / Ch2_GameServer
# Бэкап всех этих файлов сделан ДО правок: v2\_backup\2026-10-26_channel2\… и @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_channel2\server_v2\.
# Запуск (только координатор/сессия channel2, через рестарт с объявлением):
#   python restart_stack.py --deploy deploy_channel2.py
#   python deploy_channel2.py            — сухой прогон (что изменится)
#   python deploy_channel2.py --rollback — вернуть все общие файлы из бэкапа (при остановленной стойке) + рестарт службы EAC
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from deploy_p90 import ps, q, rbusy   # общие функции SSH (без побочных эффектов)
from stack_parity import run_ps    # длинный скрипт — файлом (у -EncodedCommand предел длины)


# ★ 26.10.2026 (инцидент: функция Rd = псевдоним Remove-Item удалила 12 файлов в сухом прогоне): скриптам этого
#   инструмента удалять ЗАПРЕЩЕНО — ни команд, ни псевдонимов удаления; откат только копирует из бэкапа.
DELETE_WORDS = re.compile(r"(?i)(?<![\w-])(Remove-Item|rd|rm|rmdir|del|erase|ri|Clear-Content|clc)(?![\w-])")


def psf(script, timeout=300):
    """Длинный PowerShell-скрипт файлом; возврат (код, вывод), как у ps(). Скрипт с командой удаления не отправляется."""
    m = DELETE_WORDS.search(script)
    if m:
        raise RuntimeError("в скрипте команда удаления «%s» — отказ (deploy_channel2 не удаляет)" % m.group(1))
    rc, out, err = run_ps(script, timeout=timeout)
    out = out.strip()
    if rc != 0:
        out += " | " + err.strip()[-500:]
    return rc, out

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BACKUP = V2 + r"\_backup\2026-10-26_channel2"
LOG = os.path.join(HERE, "run_channel2_20261026", "deploy.log")
SHARED = [r"start.bat", r"ChannelManager\ini\Server_Info.ini",
          r"LoginManager\GameServerIP\GameServerIP.ini", r"LoginManager\GameServerIP\0_1_ServerIP.ini",
          r"LoginManager\GameServerIP\CreateGameServerIP.ini",
          r"GameServer\ConfigSet\ChannelInfo.ini", r"Indun_GameServer\ConfigSet\ChannelInfo.ini",
          r"Indun_GameServer\MapData_Info\GroupInfo.ini", r"Indun_RelayServer\ini\ChannelInfo.ini", r"Indun_NpcServer\ini\AIInfo.ini",
          r"EacServer\EacServer.ini"]
BUSY = [r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"Ch2_GameServer\GameServer.exe",
        r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe", r"Ch2_NpcServer\NpcServer.exe",
        r"RelayServer\RelayServer.exe", r"Indun_RelayServer\RelayServer.exe", r"Ch2_RelayServer\RelayServer.exe",
        r"ChannelManager\ChannelManager.exe", r"LoginManager\LoginManager.exe"]

# Правки — PowerShell на сервере, побайтно (кодировка файлов cp949/ANSI сохраняется: Latin-1 туда-обратно).
# Rep: если файл уже в новом виде (шаблон 'done' находится) — пропуск; иначе ровно expect совпадений 'pat', иначе СТОП.
PS_EDITS = r"""
$L1 = [Text.Encoding]::GetEncoding(28591); $script:fail = 0; $DRY = %(dry)s
# ★ 26.10 грабля: короткое имя функции может совпасть со встроенным псевдонимом команды (псевдоним сильнее функции).
foreach ($fn in 'Get-Txt','Set-Txt','Set-Rep') { if (Get-Alias $fn -ErrorAction SilentlyContinue) { Write-Output "FAIL имя $fn занято псевдонимом"; exit 9 } }
function Get-Txt($p) { $L1.GetString([IO.File]::ReadAllBytes((Join-Path '%(v2)s' $p))) }
function Set-Txt($p, $t) { if (-not $DRY) { [IO.File]::WriteAllBytes((Join-Path '%(v2)s' $p), $L1.GetBytes($t)) } }
function Set-Rep($p, $pat, $repl, $expect, $done) {
  $t = Get-Txt $p
  if ($done -and [regex]::IsMatch($t, $done)) { Write-Output "SKIP уже: $p"; return }
  $n = ([regex]::Matches($t, $pat)).Count
  if ($n -ne $expect) { Write-Output "FAIL $p : '$pat' x$n (ожидалось $expect)"; $script:fail++; return }
  Set-Txt $p ([regex]::Replace($t, $pat, $repl)); Write-Output "OK   $p : x$n"
}
# ChannelManager
Set-Rep 'ChannelManager\ini\Server_Info.ini' '(?m)^(ChannelCount\s*=\s*)2' '${1}4' 1 '(?m)^ChannelCount\s*=\s*4'
# ChannelInfo.ini — у обоих GS тот же вид, что у Ch2_GameServer (Count = 2)
foreach ($g in 'GameServer','Indun_GameServer') {
  $p = "$g\ConfigSet\ChannelInfo.ini"; $t = Get-Txt $p
  if ($t -match 'Count\s*=\s*2' -and $t -match '\[CHANNEL_01\]') { Write-Output "SKIP уже: $p" }
  elseif ($t -match '^\[CHANNEL_INFO\]\r\nCount = 1\r\n\r\n\[CHANNEL_00\]\r\nAge = 0\r\n\r\n$') {
    Set-Txt $p "[CHANNEL_INFO]`r`nCount = 2`r`n`r`n[CHANNEL_00]`r`nAge = 0`r`n`r`n[CHANNEL_01]`r`nAge = 0`r`n`r`n"; Write-Output "OK   $p : Count 2" }
  else { Write-Output "FAIL $p : содержимое не совпало со стоковым"; $script:fail++ }
}
# Indun -> индекс 3
Set-Rep 'Indun_GameServer\MapData_Info\GroupInfo.ini' '(\[CHANNEL_INDEX\]\s*\r?\n\s*Index\s*=\s*)1' '${1}3' 1 '\[CHANNEL_INDEX\]\s*\r?\n\s*Index\s*=\s*3'
Set-Rep 'Indun_RelayServer\ini\ChannelInfo.ini' '(ChannelIndex\s*=\s*)1' '${1}3' 1 'ChannelIndex\s*=\s*3'
Set-Rep 'Indun_NpcServer\ini\AIInfo.ini' '(Channel_Index\s*=\s*)1' '${1}3' 1 'Channel_Index\s*=\s*3'
# LoginManager
Set-Rep 'LoginManager\GameServerIP\GameServerIP.ini' '(\[SERVERGROUP_0_CHANNEL_TOTAL\]\s*\r?\nCOUNT\s*=\s*)1' '${1}2' 1 '\[SERVERGROUP_0_CHANNEL_TOTAL\]\s*\r?\nCOUNT\s*=\s*2'
$t0 = Get-Txt 'LoginManager\GameServerIP\0_0_ServerIP.ini'; $t1 = Get-Txt 'LoginManager\GameServerIP\0_1_ServerIP.ini'
$new1 = [regex]::Replace($t0, '(PORT\s*=\s*)15601', '${1}15621')
if ($t1 -eq $new1) { Write-Output "SKIP уже: 0_1_ServerIP.ini" }
elseif (([regex]::Matches($t0, 'PORT\s*=\s*15601')).Count -ne 23) { Write-Output "FAIL 0_0_ServerIP.ini: не 23 записи 15601"; $script:fail++ }
else { Set-Txt 'LoginManager\GameServerIP\0_1_ServerIP.ini' $new1; Write-Output "OK   0_1_ServerIP.ini : 23 x @@ASTORY_SERVER_LAN_IP@@:15621" }
$p = 'LoginManager\GameServerIP\CreateGameServerIP.ini'; $t = Get-Txt $p
if ($t -match '\[Channel_Game0_1\]') { Write-Output "SKIP уже: $p" }
else {
  $n1 = ([regex]::Matches($t, '(\[SERVERGROUP_0\]\s*\r?\nCOUNT\s*=\s*)1')).Count; $n2 = ([regex]::Matches($t, '(\[Channel_Game0_0\]\r\nIP="192\.168\.1\.164"\r\nPORT =15601\r\n)')).Count
  if ($n1 -ne 1 -or $n2 -ne 1) { Write-Output "FAIL $p : COUNT x$n1, Channel_Game0_0 x$n2"; $script:fail++ }
  else { $t = [regex]::Replace($t, '(\[SERVERGROUP_0\]\s*\r?\nCOUNT\s*=\s*)1', '${1}2')
         $t = [regex]::Replace($t, '(\[Channel_Game0_0\]\r\nIP="192\.168\.1\.164"\r\nPORT =15601\r\n)', '${1}' + "`r`n[Channel_Game0_1]`r`nIP=`"@@ASTORY_SERVER_LAN_IP@@`"`r`nPORT =15621`r`n")
         Set-Txt $p $t; Write-Output "OK   $p : COUNT 2 + Channel_Game0_1 15621" }
}
# EAC — мост P73 пускает GameServer.exe только из перечисленных каталогов
Set-Rep 'EacServer\EacServer.ini' '(?m)^(AllowedImageDirs=\.\.\\GameServer;\.\.\\Indun_GameServer)\s*$' '${1};..\Ch2_GameServer' 1 '(?m)^AllowedImageDirs=.*Ch2_GameServer'
# start.bat — три новых процесса сразу за своими Indun-собратьями
$p = 'start.bat'; $t = Get-Txt $p
if ($t -match 'Ch2_GameServer') { Write-Output "SKIP уже: $p" }
else {
  $a = '(cd Indun_RelayServer\r?\nstart RelayServer\.exe\r?\ncd \.\.\r?\n)'
  $b = '(cd Indun_NpcServer\r?\nstart "Indun_NpcServer" /high NpcServer\.exe 21\r?\ncd \.\.\r?\n)'
  $c = '(cd Indun_GameServer\r?\nstart "Indun_GameServer" /high GameServer\.exe\r?\ncd \.\.\r?\n)'
  $nl = $(if ($t -match "`r`n") { "`r`n" } else { "`n" })   # start.bat на стойке — LF
  $na = ([regex]::Matches($t, $a)).Count; $nb = ([regex]::Matches($t, $b)).Count; $nc = ([regex]::Matches($t, $c)).Count
  if ($na -ne 1 -or $nb -ne 1 -or $nc -ne 1) { Write-Output "FAIL start.bat: блоки Indun x$na/$nb/$nc"; $script:fail++ }
  else {
    $t = [regex]::Replace($t, $a, '${1}' + ($nl + "rem 2026-10-26 channel2: vtoroy polevoy kanal (indeks 1), Reports\channel2\PLAN.md" + $nl + "cd Ch2_RelayServer" + $nl + "start RelayServer.exe" + $nl + "cd .." + $nl))
    $t = [regex]::Replace($t, $b, '${1}' + ($nl + "cd Ch2_NpcServer" + $nl + "start `"Ch2_NpcServer`" /high NpcServer.exe 21" + $nl + "cd .." + $nl))
    $t = [regex]::Replace($t, $c, '${1}' + ($nl + "cd Ch2_GameServer" + $nl + "start `"Ch2_GameServer`" /high GameServer.exe" + $nl + "cd .." + $nl))
    Set-Txt $p $t; Write-Output "OK   start.bat : + Ch2_RelayServer, Ch2_NpcServer, Ch2_GameServer" }
}
Write-Output "FAILS=$script:fail"
"""

PS_ROLLBACK = r"""
$v2 = '%(v2)s'; $bk = '%(bk)s'; $n = 0
foreach ($rel in %(files)s) { $s = Join-Path $bk $rel; $d = Join-Path $v2 $rel
  if (-not (Test-Path -LiteralPath $s)) { Write-Output "FAIL нет бэкапа $rel"; continue }
  Copy-Item -LiteralPath $s -Destination $d -Force
  $ok = (Get-FileHash -LiteralPath $s -Algorithm MD5).Hash -eq (Get-FileHash -LiteralPath $d -Algorithm MD5).Hash
  Write-Output ("{0} возвращён {1}" -f ($(if ($ok) { 'OK  ' } else { 'FAIL' })), $rel); if ($ok) { $n++ } }
Write-Output "RESTORED=$n"
"""

PS_EAC = r"""
Restart-Service -Name AsdaEacServer -Force -ErrorAction Stop; Start-Sleep -Seconds 3
$s = Get-Service -Name AsdaEacServer; Write-Output ("EAC " + $s.Status)
"""


def log(lines, line):
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_channel2 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                            "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        rc, out = ps("foreach ($r in @(%s)) { if (-not (Test-Path -LiteralPath (Join-Path %s $r))) { Write-Output ('NOBK|' + $r) } }; Write-Output END"
                     % (",".join(q(r) for r in SHARED), q(BACKUP)))
        nobk = [l[5:] for l in out.splitlines() if l.startswith("NOBK|")]
        if rc != 0 or nobk:
            log(lines, "СТОП: нет бэкапа общих файлов: %s" % (nobk or out[-200:]))
            flush(lines)
            return 6
        if rollback:
            rc, out = psf(PS_ROLLBACK % {"v2": V2, "bk": BACKUP, "files": "@(" + ",".join(q(r) for r in SHARED) + ")"}, timeout=300)
            for l in out.splitlines():
                log(lines, "  " + l)
            if "RESTORED=%d" % len(SHARED) not in out:
                log(lines, "СТОП: откат неполный")
                flush(lines)
                return 4
            rc, out = ps(PS_EAC, timeout=120)
            log(lines, "  " + out.splitlines()[-1] if out else "  EAC: нет ответа")
            log(lines, "ОТКАТ ГОТОВ: общие файлы — из бэкапа; папки Ch2_* остаются, но не запускаются. Нужен старт стойки.")
            flush(lines)
            return 0
        rc, out = psf(PS_EDITS % {"v2": V2, "dry": "$false" if apply else "$true"}, timeout=300)
        for l in out.splitlines():
            log(lines, "  " + l)
        if rc != 0 or "FAILS=0" not in out:
            log(lines, "СТОП: правки не прошли (см. FAIL) — %s" % ("часть файлов могла измениться: --rollback" if apply else "сухой прогон"))
            flush(lines)
            return 5
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply")
            flush(lines)
            return 0
        rc, out = ps(PS_EAC, timeout=120)
        st = out.splitlines()[-1].strip() if out else ""
        log(lines, "  служба: %s" % st)
        if st != "EAC Running":
            log(lines, "СТОП: служба AsdaEacServer не поднялась после перезапуска (%s) — общие файлы уже изменены" % out[-300:])
            flush(lines)
            return 7
        log(lines, "ГОТОВО: канал 2 включён в общих файлах (CM ChannelCount 4, Indun → 3, LoginManager 2 канала, EAC + Ch2_GameServer, "
                   "start.bat + 3 процесса). Старт стойки — restart_stack.py; ждать 15 процессов.")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
