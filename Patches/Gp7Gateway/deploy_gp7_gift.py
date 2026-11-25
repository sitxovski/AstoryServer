# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Выкладка шлюза gp7 с подарком P101_CashGift (01.11.2026): server.js (команда 0x52 → 0x53) и install_gp7_balance.sql
(dbo.GP7GiftLog, dbo.GP7_GiftHold, dbo.GP7_GiftSettle). Образец — deploy_gp7_cart.py.

Что меняет на сервере (@@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\gp7-server):
  - server.js               ← AstoryServer\\Patches\\Gp7Gateway\\server.js
  - install_gp7_balance.sql ← AstoryServer\\Patches\\Gp7Gateway\\install_gp7_balance.sql
Установщик SQL выполняет сам server.js при старте (installSqlSchema). Он идемпотентен: таблица создаётся один раз,
процедуры — CREATE OR ALTER. При ошибке SQL шлюз не стартует (SQL_MIGRATION_ERROR) — тогда откат.
Только SSH/scp (шару \\\\@@ASTORY_SERVER_HOSTNAME@@ не трогает). Перезапускается ТОЛЬКО node gp7-server: задача планировщика в
интерактивной сессии Administrator, как restart_stack.py; остальная стойка не трогается.
★ 02.11 (ревизия Б1): шлюз запускается ТОЙ ЖЕ командой, что в start.bat (cmd /c node "<полный путь>\\server.js"), поэтому его
видит фильтр restart_stack.py «*gp7-server*»; процесс ищется ещё и по слушающему порту 15022 (как гасит start.bat).
GameServer переподключается к шлюзу сам: таймер раз в 5 с (GameServer.c:9038–9052, журнал 18.10 22:55:53 → 22:55:57).

ПОРЯДОК (ревизия М5, М6):
  - выкладывать в тихое окно, объявление — за координатором (announce_restart.py). Скрипт ждёт до 30 с, пока у шлюза нет
    дочернего sqlcmd (покупка/подарок в полёте), но запрос, пришедший в эти секунды, получит обрыв;
  - ОТКАТ при включённой DLL P101: СНАЧАЛА patches.ini [P101_CashGift] Enabled=0 (без пересборки), потом --rollback.
    Прежний server.js (mode "echo") вернул бы GS кадр 0x52 как есть.

    python deploy_gp7_gift.py             — СУХОЙ ПРОГОН (по умолчанию): md5 живых и новых файлов, дифф server.js и SQL,
                                            node --check нового server.js; на сервере ничего не пишет
    python deploy_gp7_gift.py --apply     — бэкап живых файлов в v2\\_backup\\cashgift_gp7_<дата>, выкладка с проверкой md5,
                                            node --check на сервере, перезапуск gp7-server, проверка журнала
    python deploy_gp7_gift.py --rollback  — вернуть оба файла из бэкапа и перезапустить gp7-server
                                            (таблица GP7GiftLog и процедуры остаются — прежний server.js их не зовёт)
★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import difflib
import hashlib
import os
import subprocess
import sys
import tempfile
import time

SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"                         # ключ dev-сервера
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"                               # dev-сервер (Tailscale)
SRV_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server"                         # каталог шлюза на сервере
BAK_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\cashgift_gp7_20261101"      # бэкап живых файлов
TASK = "AsdaGp7Restart_cashgift"                                        # одноразовая задача планировщика для запуска шлюза
SRV_TMP = r"C:\Users\Administrator\AppData\Local\Temp"                # временный сценарий запуска на сервере
GP7_PORT = 15022                                                        # порт шлюза (живой config.json "port")
HERE = os.path.dirname(os.path.abspath(__file__))                       # Gp7Gateway\
FILES = ["server.js", "install_gp7_balance.sql"]                         # что выкладывается
# Живые файлы на момент подготовки (01.11.2026 23:20, сняты scp; server.js = после P85 r2 от 25.10, SQL — 24.07).
EXPECTED_LIVE_MD5 = {
    "server.js": "E96DA7F2286BCCD295DA716F37B4DFD2",
    "install_gp7_balance.sql": "7002E1FFB561D9CF7AFCFC97212F2718",
}


def _ssh(cmd, timeout=120):
    """Команда на сервере по SSH → (код, stdout+stderr)."""
    r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", SSH_HOST, cmd],
                       capture_output=True, text=True, timeout=timeout, encoding="cp866", errors="replace")
    return r.returncode, (r.stdout + r.stderr).strip()


def _ps(script, timeout=120):
    """PowerShell-однострочник на сервере."""
    return _ssh('powershell -NoProfile -Command "%s"' % script, timeout)


def _scp(src, dst, timeout=300):
    """scp в любую сторону (удалённый путь — host:путь с прямыми слэшами)."""
    r = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", src, dst],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise SystemExit("scp %s -> %s: %s" % (src, dst, r.stderr.strip()))


def _remote(path):
    """host:путь для scp."""
    return "%s:%s" % (SSH_HOST, path.replace("\\", "/"))


def _remote_md5(path):
    """MD5 файла на сервере (пусто, если файла нет)."""
    _, out = _ps("if(Test-Path '%s'){(Get-FileHash '%s' -Algorithm MD5).Hash}" % (path, path))
    return out.strip().upper()


def _md5(path):
    """MD5 локального файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest().upper()


def _diff(live_path, new_path, name):
    """Унифицированный дифф живой → новой версии (текст)."""
    a = open(live_path, encoding="utf-8", errors="replace").read().splitlines()
    b = open(new_path, encoding="utf-8", errors="replace").read().splitlines()
    return list(difflib.unified_diff(a, b, "live/" + name, "new/" + name, lineterm="", n=2))


def _gp7_procs():
    """Процессы шлюза на сервере → {PID: командная строка}. ★ 02.11 (ревизия Б1): ищем ДВУМЯ способами и объединяем:
    node.exe с «gp7-server» в командной строке (так ищут restart_stack.py / restart_stack_p76.py) и владелец слушающего
    порта GP7_PORT, если это node (так гасит шлюз start.bat). Запущенный из start_gp7_server.bat («node server.js» без пути)
    первый способ не видит — второй видит."""
    _, out = _ps("$p = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' -and $_.CommandLine -like '*gp7-server*' } | "
                 "ForEach-Object { $_.ProcessId }); "
                 "$p += @(Get-NetTCPConnection -LocalPort %d -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess }); "
                 "$p | Sort-Object -Unique | ForEach-Object { $i = $_; $c = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $i }; "
                 "if ($c -and $c.Name -eq 'node.exe') { [string]$i + '|' + $c.CommandLine } }" % GP7_PORT)
    procs = {}
    for ln in out.splitlines():
        pid, _, cmd = ln.partition("|")
        if pid.strip().isdigit():
            procs[pid.strip()] = cmd.strip()
    return procs


def _gp7_pids():
    """PID-ы шлюза (см. _gp7_procs)."""
    return list(_gp7_procs())


def _show_procs(title):
    """Печать процессов шлюза и видит ли их фильтр restart_stack.py («*gp7-server*» в командной строке)."""
    procs = _gp7_procs()
    if not procs:
        print("%s: шлюза нет" % title)
    for pid, cmd in procs.items():
        print("%s: PID %s  «%s»  фильтр restart_stack.py: %s" % (title, pid, cmd, "видит" if "gp7-server" in cmd.lower() else "НЕ видит"))
    return procs


def _wait_sql_children(pids, limit=30):
    """★ 02.11 (ревизия М6): перед остановкой дождаться, пока у шлюза нет дочерних SQLCMD (запрос покупки/подарка в полёте):
    иначе sqlcmd докоммитит списание, а ответ GS уже некому отдать. Возвращает True, если дождались."""
    for _ in range(limit):
        _, out = _ps("@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'SQLCMD.EXE' -and @(%s) -contains $_.ParentProcessId }).Count"
                     % ",".join(pids or ["0"]))
        if out.strip() in ("", "0"):
            return True
        time.sleep(1)
    print("ВНИМАНИЕ: дочерний sqlcmd шлюза не завершился за %d с — останавливаю всё равно" % limit)
    return False


def _start_script():
    """Текст сценария PowerShell запуска шлюза (как строка start.bat: cmd /c node "<полный путь>\\server.js")."""
    return ("$tr = 'cmd /c node \\\"%s\\server.js\\\"'\r\n"
            "schtasks /Create /F /TN %s /SC ONCE /ST 23:59 /RU Administrator /IT /TR $tr\r\n"
            "schtasks /Run /TN %s\r\n") % (SRV_DIR, TASK, TASK)


def _start_gp7():
    """Запуск шлюза ТАК ЖЕ, как start.bat: cmd /c node "<полный путь>\\server.js" — командная строка содержит gp7-server,
    restart_stack.py его увидит. Одноразовая задача планировщика /RU Administrator /IT (как restart_stack.py, шаг 5);
    сценарий PowerShell кладётся файлом (кавычки пути не проходят через ssh → cmd → powershell -Command)."""
    local = os.path.join(tempfile.mkdtemp(prefix="gp7gift_start_"), "gp7_start.ps1")
    with open(local, "w", encoding="utf-8-sig") as f:
        f.write(_start_script())
    remote = SRV_TMP + "\\gp7_start_cashgift.ps1"
    _scp(local, _remote(remote))
    _, out = _ssh('powershell -NoProfile -ExecutionPolicy Bypass -File "%s" & del "%s"' % (remote, remote))
    print(out)
    time.sleep(20)
    _ps("schtasks /Delete /F /TN %s" % TASK)


def _restart_gp7():
    """Перезапуск ТОЛЬКО шлюза: ожидание sqlcmd в полёте → стоп всех найденных процессов шлюза → запуск как в start.bat →
    проверка: процесс найден, его видит фильтр restart_stack.py, установщик SQL прошёл.
    GameServer переподключается сам (таймер раз в 5 с, «#### GP7 : ReConnect Success» — GP7_DONE.md, «В4»)."""
    mark = time.strftime("%Y-%m-%d %H:%M:%S")
    before = _show_procs("до остановки")
    _wait_sql_children(list(before))
    _ps("foreach ($i in @(%s)) { Stop-Process -Id $i -Force -ErrorAction SilentlyContinue }" % ",".join(list(before) or ["0"]))
    for _ in range(10):
        if not _gp7_pids():
            break
        time.sleep(2)
    if _gp7_pids():
        raise SystemExit("ОШИБКА: шлюз не остановился: %s" % _gp7_procs())
    print("gp7-server остановлен")
    _start_gp7()
    after = _show_procs("после запуска")
    day = time.strftime("%Y%m%d")
    _, tail = _ps("Get-Content -Tail 80 '%s\\logs\\gp7-%s.log' | Select-String 'SQL_MIGRATION|listening|ACCEPT'" % (SRV_DIR, day))
    print(tail)
    mig = [ln for ln in tail.splitlines() if "SQL_MIGRATION" in ln]   # строки установщика; последняя — этот запуск
    if not after or any("gp7-server" not in c.lower() for c in after.values()) or not mig or "SQL_MIGRATION_ERROR" in mig[-1]:
        raise SystemExit("ОШИБКА: шлюз не поднялся, его не видит restart_stack.py, или установщик SQL упал — выполнить --rollback")
    print("Проверить: строки ACCEPT от трёх GameServer после %s (GS переподключается сам за ~5 с)." % mark)


def main(argv):
    """Точка входа: сухой прогон / --apply / --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    mode = "check"
    if "--apply" in argv:
        mode = "apply"
    if "--rollback" in argv:
        mode = "rollback"

    tmp = tempfile.mkdtemp(prefix="gp7gift_deploy_")
    live_md5, new_md5 = {}, {}
    for name in FILES:
        new_md5[name] = _md5(os.path.join(HERE, name))
        live_md5[name] = _remote_md5(SRV_DIR + "\\" + name)
        print("%-24s живой %s (ожидался %s)  новый %s" % (name, live_md5[name] or "НЕТ", EXPECTED_LIVE_MD5[name], new_md5[name]))

    if mode == "rollback":
        print("ВНИМАНИЕ (ревизия М5): если DLL P101 включена — сначала patches.ini [P101_CashGift] Enabled=0, потом этот откат.")
        for name in FILES:
            bak = _remote_md5(BAK_DIR + "\\" + name)
            if not bak:
                raise SystemExit("бэкапа %s\\%s нет — откатывать нечего" % (BAK_DIR, name))
            _, out = _ps("Copy-Item -Force '%s\\%s' '%s\\%s'; (Get-FileHash '%s\\%s' -Algorithm MD5).Hash" % (BAK_DIR, name, SRV_DIR, name, SRV_DIR, name))
            if out.strip().upper() != bak:
                raise SystemExit("ОШИБКА: после отката %s хэш %s != бэкап %s" % (name, out, bak))
            print("откат %s: %s" % (name, bak))
        _restart_gp7()
        print("ГОТОВО: шлюз возвращён к прежним файлам (таблица GP7GiftLog и процедуры остались, они не мешают)")
        return 0

    # сухой прогон и --apply: живые копии во временный каталог, дифф
    r = subprocess.run(["node", "--check", os.path.join(HERE, "server.js")], capture_output=True, text=True)
    print("node --check нового server.js: %s" % ("OK" if r.returncode == 0 else r.stderr.strip()))
    if r.returncode != 0:
        raise SystemExit("ОСТАНОВ: новый server.js не проходит node --check")
    for name in FILES:
        if not live_md5[name]:
            print("[%s] на сервере нет — дифф не строится" % name)
            continue
        local_live = os.path.join(tmp, "live_" + name)
        _scp(_remote(SRV_DIR + "\\" + name), local_live)
        d = _diff(local_live, os.path.join(HERE, name), name)
        plus = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
        minus = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
        print("")
        print("===== дифф %s: +%d / -%d строк =====" % (name, plus, minus))
        print("\n".join(d))
    _, cfg = _ps("Get-Content '%s\\config.json' | Select-String 'testFixedBalance|balanceSource|giftSellItemTable'" % SRV_DIR)
    print("")
    print("живой config.json (ключи режима): %s" % (cfg.strip() or "(нет ключей)"))
    _, sell = _ps("if(Test-Path '%s\\..\\GameServer\\ItemTable_Info\\SellItemTable.txt'){'SellItemTable.txt есть: ' + "
                  "(Get-Content '%s\\..\\GameServer\\ItemTable_Info\\SellItemTable.txt' -TotalCount 1)}" % (SRV_DIR, SRV_DIR))
    print("белый список подарка: %s" % (sell.strip() or "SellItemTable.txt НЕТ — подарки будут отклоняться"))
    _, port_line = _ps("Get-Content '%s\\config.json' | Select-String '^\\s*.port.\\s*:'" % SRV_DIR)
    print("порт шлюза в живом config.json: %s (скрипт ищет слушателя порта %d)" % (port_line.strip(), GP7_PORT))
    print("")
    print("процессы шлюза сейчас (ревизия Б1, только чтение):")
    _show_procs("  найден")
    print("сценарий запуска при --apply/--rollback (как строка start.bat):")
    print("  " + _start_script().replace("\r\n", "\n  ").rstrip())

    if all(live_md5[n] == new_md5[n] for n in FILES):
        print("на сервере уже новая версия — делать нечего")
        return 0
    drift = [n for n in FILES if live_md5[n] not in (EXPECTED_LIVE_MD5[n], new_md5[n])]
    if drift:
        raise SystemExit("ОСТАНОВ: живые файлы изменились после подготовки (%s) — слить изменения вручную" % ", ".join(drift))
    if mode == "check":
        print("СУХОЙ ПРОГОН пройден: можно выкладывать (--apply; решение — за координатором). На сервере ничего не изменено.")
        return 0

    # --apply
    _ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % BAK_DIR)
    for name in FILES:
        if not _remote_md5(BAK_DIR + "\\" + name):
            _ps("Copy-Item '%s\\%s' '%s\\%s'" % (SRV_DIR, name, BAK_DIR, name))
        if _remote_md5(BAK_DIR + "\\" + name) != live_md5[name] and live_md5[name] != new_md5[name]:
            raise SystemExit("ОШИБКА бэкапа %s" % name)
        print("бэкап: %s\\%s" % (BAK_DIR, name))
    staged = {}
    for name in FILES:
        stage = SRV_DIR + "\\" + ("server.new_20261101_cashgift.js" if name == "server.js" else name + ".new_20261101_cashgift")   # .js — для node --check
        _scp(os.path.join(HERE, name), _remote(stage))
        if _remote_md5(stage) != new_md5[name]:
            raise SystemExit("ОШИБКА: залитый %s не совпал по хэшу" % stage)
        staged[name] = stage
    code, out = _ssh('cd /d %s && node --check "%s"' % (SRV_DIR, staged["server.js"]))
    if code != 0:
        raise SystemExit("ОШИБКА node --check на сервере: %s" % out)
    for name in FILES:
        _ps("Move-Item -Force '%s' '%s\\%s'" % (staged[name], SRV_DIR, name))
        if _remote_md5(SRV_DIR + "\\" + name) != new_md5[name]:
            raise SystemExit("ОШИБКА: после замены хэш %s не совпал" % name)
        print("заменён %s (%s)" % (name, new_md5[name]))
    _restart_gp7()
    print("ГОТОВО: шлюз с подарком P101 выложен и перезапущен.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
