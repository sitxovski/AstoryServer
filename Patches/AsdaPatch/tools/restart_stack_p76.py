# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# ★ УСТАРЕЛО (22.10.2026): работает через сетевую папку \\@@ASTORY_SERVER_HOSTNAME@@, которая висит. Выкладка — только по SSH по образцу
#   deploy_p77.py (restart_stack.py --deploy ...). Без ASDA_USE_SMB=1 скрипт сразу отказывается (код 3), не висит.
# restart_stack_p76.py — перезапуск dev-стойки с выкладкой P76 (слово владельца 21.10.2026: «можешь сам перезапускать сервера,
# полной стойкой; перед перезапуском — сообщение ботом в канал testing-info всем @BetaTester на EN/AR/RU, что сервер будет
# перезапущен через 3 минуты; отсчитать 3 минуты и перезапустить»).
#
# Шаги (каждый — с проверкой; провал → стоп с кодом, дальше не идёт):
#   1. Объявление: AstoryAdminCenter/DiscordBot/announce_restart.py (канал test-info, роль Beta Tester, EN/AR/RU, 3 минуты).
#   2. Ожидание 180 с.
#   3. Остановка стойки: taskkill /f 9 видов процессов (как stop_servers.bat / start.bat) + node gp7-server; проверка, что их нет.
#   4. Выкладка P76: deploy_p76.py --apply (бэкапы, сверка md5; при чужой DLL — стоп).
#   5. Запуск: start.bat одноразовой задачей планировщика /RU Administrator /IT (интерактивная сессия администратора), задача удаляется.
#   6. Проверка: 12 процессов поднялись; в PatchLog GameServer и Indun — «[OK] P76_SowelSlotBounds».
# Запуск: python restart_stack_p76.py [--no-announce] [--wait 180]
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "Administrator@@@ASTORY_SERVER_LAN_IP@@"]
V2_LOCAL = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
from srv_paths import ROOT as SRV_ROOT, require_smb   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
require_smb(__file__)   # ★ 22.10.2026: устарело — только ASDA_USE_SMB=1
V2_SHARE = SRV_ROOT + "/v2"
BOT = r"@@ASTORY_DEV_ROOT@@\AstoryAdminCenter\DiscordBot"
TOOLS = os.path.dirname(os.path.abspath(__file__))
PROCS = ["ChannelManager", "DBManager", "OperationServer", "OverlapCheckServer", "RelayServer", "ItemRelayServer",
         "LoginManager", "NpcServer", "GameServer"]
EXPECT = {"ChannelManager": 1, "DBManager": 1, "OperationServer": 1, "OverlapCheckServer": 1, "RelayServer": 2,
          "ItemRelayServer": 1, "LoginManager": 1, "NpcServer": 2, "GameServer": 2}


def say(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def ssh_ps(cmd, timeout=180):
    """PowerShell-команда на сервере; возврат (код, вывод)."""
    p = subprocess.run(SSH + ["powershell -NoProfile -Command \"%s\"" % cmd.replace('"', '\\"')],
                       capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("cp866", "replace") + p.stderr.decode("cp866", "replace")


def counts():
    names = ",".join(PROCS)
    rc, out = ssh_ps("Get-Process %s -ErrorAction SilentlyContinue | Group-Object ProcessName | ForEach-Object { $_.Name + '=' + $_.Count }" % names)
    res = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.strip().split("=", 1)
            if v.isdigit():
                res[k] = int(v)
    return res


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    wait = 180
    if "--wait" in sys.argv:
        wait = int(sys.argv[sys.argv.index("--wait") + 1])

    if "--no-announce" not in sys.argv:
        say("1. объявление в Discord")
        p = subprocess.run([sys.executable, os.path.join(BOT, "announce_restart.py"), "--minutes", str(max(1, wait // 60))],
                           cwd=BOT, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        print(p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
        if p.returncode != 0 or "Отправлено" not in p.stdout.decode("utf-8", "replace"):
            say("СТОП: объявление не отправлено — стойку не трогаю")
            return 2
        say("2. ожидание %d с" % wait)
        time.sleep(wait)

    say("3. остановка стойки")
    rc, out = ssh_ps("foreach ($n in '%s'.Split(',')) { Stop-Process -Name $n -Force -ErrorAction SilentlyContinue }; "
                     "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' -and $_.CommandLine -like '*gp7-server*' } | "
                     "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" % ",".join(PROCS))
    print(out.strip())
    for _ in range(20):
        c = counts()
        if not c:
            break
        time.sleep(3)
    c = counts()
    if c:
        say("СТОП: процессы не остановились: %s" % c)
        return 3
    say("   все 12 процессов остановлены")

    say("4. выкладка P76")
    p = subprocess.run([sys.executable, os.path.join(TOOLS, "deploy_p76.py"), "--apply"], capture_output=True,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    out = p.stdout.decode("utf-8", "replace")
    print(out)
    if p.returncode != 0 or "ГОТОВО: DLL v48" not in out:
        say("СТОП: выкладка не прошла (код %d) — стойка ОСТАНОВЛЕНА, нужен ручной запуск start.bat (или откат)" % p.returncode)
        return 4

    say("5. запуск start.bat в интерактивной сессии администратора")
    task = "AsdaStackStart_p76"
    start_bat = V2_LOCAL + r"\start.bat"
    rc, out = ssh_ps("schtasks /Create /F /TN %s /SC ONCE /ST 23:59 /RU Administrator /IT /TR '%s'; schtasks /Run /TN %s" % (task, start_bat, task))
    print(out.strip())
    time.sleep(75)
    rc, out = ssh_ps("schtasks /Delete /F /TN %s" % task)
    print(out.strip())

    say("6. проверка")
    c = {}
    for _ in range(20):
        c = counts()
        if all(c.get(k, 0) >= v for k, v in EXPECT.items()):
            break
        time.sleep(5)
    ok_procs = all(c.get(k, 0) >= v for k, v in EXPECT.items())
    say("   процессы: %s %s" % (c, "OK" if ok_procs else "НЕ ВСЕ"))
    day = time.strftime("%Y%m%d")
    ok_patch = True
    for d in ("GameServer", "Indun_GameServer"):
        path = "%s/%s/Log/Log_Patch/PatchLog_%s.txt" % (V2_SHARE, d, day)
        try:
            text = open(path, "rb").read().decode("cp1251", "replace")
        except OSError as e:
            say("   %s: журнал патчей не прочитан (%s)" % (d, e))
            ok_patch = False
            continue
        last = text[text.rfind("AsdaPatch — старт"):]
        has = "[OK]       P76_SowelSlotBounds" in last or ("[OK]" in last and "P76_SowelSlotBounds" in last)
        mism = last.count("MISMATCH")
        say("   %s: P76 %s; строк MISMATCH в последнем старте: %d" % (d, "OK" if has else "НЕТ", mism))
        ok_patch = ok_patch and has
    say("ИТОГ: %s" % ("стойка поднята, P76 стоит" if ok_procs and ok_patch else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if ok_procs and ok_patch else 5


if __name__ == "__main__":
    sys.exit(main())
