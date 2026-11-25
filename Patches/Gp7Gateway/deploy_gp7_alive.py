# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Выкладка шлюза gp7 с ответом на пинг GameServer (05.11.2026, баг «гача: списали — не выдали»).

ЧТО И ПОЧЕМУ. GameServer раз в 5 с шлёт GP7 пинг команды 20 (0x14) и ждёт ответ команды 21 (0x15); без него через 180 с
рвёт связь и переподключается (GameServer.c:9010-9033, :9785-9788). Прежний server.js отвечал на пинг ЭХОМ (0x14) —
связь рвалась каждые 3 минуты (~475 раз в сутки на каждый канал, Log_AliveCheck\\Ping_*.txt), и ответ 0x51 на покупку,
попавший в обрыв, терялся: GP7 списал, а приз не лёг в элитный ящик (01.11 19:40:41, Rimy/LUFFY, заказ 15068, приз 70787).
Новый server.js отвечает 0x15 на пинг и 0x0B на приветствие 0x0A (buildAliveResponse); config.answerAlivePing = false —
прежнее эхо без отката файла.

Что меняет на сервере (@@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\gp7-server): только server.js ← AstoryServer\\Patches\\Gp7Gateway\\server.js.
SQL, config.json и стойка не трогаются. CLI перезапускает ТОЛЬКО node gp7-server (общие функции — deploy_gp7_gift.py:
ожидание sqlcmd в полёте, остановка, запуск как start.bat). GameServer переподключается к шлюзу сам (таймер 5 с).
Только SSH/scp (шару \\\\@@ASTORY_SERVER_HOSTNAME@@ не трогает). Папки GameServer — из AstoryServer\\Patches\\AsdaPatch\\tools\\stack_layout.py.

    python deploy_gp7_alive.py                  — СУХОЙ ПРОГОН (по умолчанию): md5, дифф, node --check, стенд alive_stand.js
    python deploy_gp7_alive.py --apply          — бэкап живого server.js в v2\\_backup\\gp7_alive_20261105, выкладка с
                                                  проверкой md5 и node --check на сервере, перезапуск шлюза
    python deploy_gp7_alive.py --rollback       — вернуть server.js из бэкапа и перезапустить шлюз
    python deploy_gp7_alive.py --check-started [минут=10]
                                                — проверка после выкладки (ничего не пишет): шлюз жив, в журнале шлюза есть
                                                  heartbeat-ack, у каждого GameServer за последние N минут есть
                                                  «Arab Recv AliveCheck Packet» и нет «Arab Ping Timeout»

★ API ДЛЯ ОБЩЕГО СКРИПТА ВЫКЛАДКИ (05.11.2026, deploy_p108.py: стойка ОСТАНОВЛЕНА, шлюз потом поднимает start.bat):
    stage(apply=False, log=print) -> int      сухой прогон или замена server.js БЕЗ перезапуска шлюза;
    rollback_file(log=print) -> int           вернуть server.js из бэкапа БЕЗ перезапуска;
    check_started(minutes=10, log=print) -> int   то же, что --check-started.
  `log` — функция одной строки. 0 (RC_OK) — готово / уже новая версия / проверка пройдена, иначе — код причины RC_*.
  Функции не бросают SystemExit: ошибки SSH/scp общих функций превращаются в RC_REMOTE.
Выкладка — решение координатора/владельца; объявление о перезапуске — announce_restart.py (за координатором).
★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))                                  # Gp7Gateway\
TOOLS = os.path.normpath(os.path.join(HERE, "..", "AsdaPatch", "tools"))            # stack_layout.py
NAME = "server.js"                                                                  # единственный выкладываемый файл
BAK_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\gp7_alive_20261105"                     # бэкап живого server.js
STAGE = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server\server.new_20261105_alive.js"           # временное имя на сервере (.js — для node --check)
TASK = "AsdaGp7Restart_alive"                                                       # одноразовая задача планировщика запуска
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                                                     # корень стойки
REMOTE = V2 + "\\gp7-server\\" + NAME                                               # живой server.js
# Живой server.js на момент подготовки (05.11.2026 ~13:00, md5 снят по SSH; = локальный до правки, выкладка 02.11 09:47).
EXPECTED_LIVE_MD5 = "0327AA69AD853E13DA958EDA39CC06B4"

# Коды возврата API (0 — успех).
RC_OK = 0               # готово / уже новая версия / проверка пройдена
RC_NODE_CHECK = 2       # новый server.js не проходит node --check локально
RC_STAND = 3            # стенд alive_stand.js провален
RC_DRIFT = 4            # живой server.js изменился после подготовки — сливать вручную
RC_BACKUP = 5           # бэкап не создан / не совпал
RC_UPLOAD = 6           # залитый файл не совпал по хэшу
RC_REMOTE_CHECK = 7     # node --check на сервере провален
RC_REPLACE = 8          # после замены хэш не совпал
RC_NO_BACKUP = 9        # откат: бэкапа нет
RC_ROLLBACK_HASH = 10   # откат: хэш после копирования != бэкап
RC_REMOTE = 11          # ошибка SSH/scp (SystemExit общих функций)
RC_CHECK_FAILED = 12    # проверка после запуска провалена


def _gift():
    """Общие функции SSH/scp/перезапуска шлюза — модуль deploy_gp7_gift.py (без побочных эффектов при импорте)."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import deploy_gp7_gift as g
    g.TASK = TASK            # своя одноразовая задача планировщика
    g.BAK_DIR = BAK_DIR      # на случай чтения общими функциями
    return g


def _gs_folders():
    """Папки GameServer стойки — ТОЛЬКО из stack_layout.py (два полевых канала + Indun)."""
    if TOOLS not in sys.path:
        sys.path.insert(0, TOOLS)
    from stack_layout import GS_FOLDERS
    return list(GS_FOLDERS)


def _stand(log):
    """Локальный стенд stand\\alive_stand.js (ответы 0x15/0x0B, склейка, путь баланса, ключ отключения). True — 0 провалов."""
    r = subprocess.run(["node", os.path.join(HERE, "stand", "alive_stand.js")], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    for ln in (r.stdout.strip() + "\n" + r.stderr.strip()).strip().splitlines():
        log(ln)
    return r.returncode == 0


def _ts_after(line, since):
    """Строка журнала GameServer «11 Mon 05 Day 14 hou 03 min 01 sec : …» позже момента `since` (сегодня, локальное время)?"""
    try:
        p = line.split()
        mon, day, hh, mm, ss = int(p[0]), int(p[2]), int(p[4]), int(p[6]), int(p[8])
        t = time.mktime((time.localtime().tm_year, mon, day, hh, mm, ss, 0, 0, -1))
        return t >= since
    except (ValueError, IndexError):
        return True   # не разобрали — считаем подозрительной, пусть смотрит человек


def _last_digits(out):
    """Последняя строка вывода SSH-PowerShell, состоящая из цифр (★ последняя строка бывает CLIXML); нет — 0."""
    nums = [x.strip() for x in out.splitlines() if x.strip().isdigit()]
    return int(nums[-1]) if nums else 0


def check_started(minutes=10, log=print):
    """Проверка после запуска шлюза (ничего не пишет): процесс шлюза жив, в журнале шлюза есть heartbeat-ack, у каждого
    GameServer (stack_layout.GS_FOLDERS) есть «Arab Recv AliveCheck» и нет «Arab Ping Timeout» за последние `minutes` минут.
    RC_OK / RC_CHECK_FAILED / RC_REMOTE."""
    try:
        g = _gift()
        bad = 0
        procs = g._gp7_procs()
        for pid, cmd in procs.items():
            log("шлюз: PID %s «%s»" % (pid, cmd))
        if not procs:
            log("FAIL: процесса шлюза нет")
            bad += 1
        day = time.strftime("%Y%m%d")
        _, ack = g._ps("@(Get-Content -Tail 4000 '%s\\gp7-server\\logs\\gp7-%s.log' | Select-String 'heartbeat-ack').Count" % (V2, day))
        n_ack = _last_digits(ack)
        log("журнал шлюза: строк heartbeat-ack в хвосте 4000: %d" % n_ack)
        if n_ack == 0:
            log("FAIL: шлюз не отвечает на пинг (нет heartbeat-ack) — новая версия не запущена?")
            bad += 1
        since = time.time() - minutes * 60
        for f in _gs_folders():
            ps = ("$p='%s\\%s\\Log\\Log_AliveCheck\\Ping_%s.txt'; if(Test-Path $p){ "
                  "$l=Get-Content $p | Select-Object -Last 2000; "
                  "$r=@($l | Select-String 'Arab Recv AliveCheck').Count; $o=@($l | Select-String 'Arab Ping Timeout').Count; "
                  "$last=($l | Select-String 'Arab Ping Timeout' | Select-Object -Last 1).Line; "
                  "'recv=' + $r + ' timeout=' + $o + ' lastTimeout=' + $last } else { 'nolog' }") % (V2, f, day)
            _, out = g._ps(ps)
            line = [x for x in out.splitlines() if x.startswith("recv=") or x.strip() == "nolog"]
            res = line[-1] if line else out.strip()
            log("%-18s %s" % (f, res))
            if res.strip() == "nolog":
                log("  (журнала пинга нет — этот GameServer к GP7 не подключается или ещё не писал сегодня)")
                continue
            if res.startswith("recv=0 "):
                log("  FAIL: GameServer %s не получил ни одного ответа 21 (AliveCheck)" % f)
                bad += 1
            last = res.partition("lastTimeout=")[2].strip()
            if last and _ts_after(last, since):
                log("  FAIL: обрыв по пингу за последние %d мин: %s" % (minutes, last))
                bad += 1
        log("ПРОВЕРКА: %s" % ("OK" if bad == 0 else "ПРОВАЛОВ %d" % bad))
        return RC_OK if bad == 0 else RC_CHECK_FAILED
    except SystemExit as e:
        log("ОШИБКА SSH/scp: %s" % e)
        return RC_REMOTE


def stage(apply=False, log=print):
    """Сухой прогон (apply=False): md5 живого/нового, node --check, стенд, дифф, ключи config.json; на сервере ничего не пишет.
    apply=True: то же + бэкап живого server.js в BAK_DIR, заливка во временное имя, node --check на сервере, замена.
    Шлюз НЕ перезапускается (его поднимает start.bat стойки или main() этого скрипта). Коды — RC_*."""
    try:
        g = _gift()
        new_md5 = g._md5(os.path.join(HERE, NAME))
        live_md5 = g._remote_md5(REMOTE)
        log("%s живой %s (ожидался %s)  новый %s" % (NAME, live_md5 or "НЕТ", EXPECTED_LIVE_MD5, new_md5))
        r = subprocess.run(["node", "--check", os.path.join(HERE, NAME)], capture_output=True, text=True)
        log("node --check нового server.js: %s" % ("OK" if r.returncode == 0 else r.stderr.strip()))
        if r.returncode != 0:
            return RC_NODE_CHECK
        if not _stand(log):
            log("ОСТАНОВ: стенд alive_stand.js провален")
            return RC_STAND
        if live_md5 == new_md5:
            log("на сервере уже новая версия — делать нечего")
            return RC_OK
        if live_md5:
            local_live = os.path.join(tempfile.mkdtemp(prefix="gp7alive_deploy_"), "live_" + NAME)
            g._scp(g._remote(REMOTE), local_live)
            d = g._diff(local_live, os.path.join(HERE, NAME), NAME)
            log("===== дифф %s: +%d / -%d строк =====" % (NAME, sum(1 for x in d if x.startswith("+") and not x.startswith("+++")),
                                                       sum(1 for x in d if x.startswith("-") and not x.startswith("---"))))
            for ln in d:
                log(ln)
        _, cfg = g._ps("Get-Content '%s\\gp7-server\\config.json' | Select-String 'mode|heartbeatHex|answerAlivePing'" % V2)
        log("живой config.json: %s" % (cfg.strip() or "(нет ключей)"))
        if live_md5 != EXPECTED_LIVE_MD5:
            log("ОСТАНОВ: живой server.js изменился после подготовки (%s) — слить изменения вручную" % live_md5)
            return RC_DRIFT
        if not apply:
            log("СУХОЙ ПРОГОН пройден: можно выкладывать. На сервере ничего не изменено.")
            return RC_OK
        g._ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % BAK_DIR)
        if not g._remote_md5(BAK_DIR + "\\" + NAME):
            g._ps("Copy-Item '%s' '%s\\%s'" % (REMOTE, BAK_DIR, NAME))
        if g._remote_md5(BAK_DIR + "\\" + NAME) != live_md5:
            log("ОШИБКА бэкапа %s" % NAME)
            return RC_BACKUP
        log("бэкап: %s\\%s" % (BAK_DIR, NAME))
        g._scp(os.path.join(HERE, NAME), g._remote(STAGE))
        if g._remote_md5(STAGE) != new_md5:
            log("ОШИБКА: залитый %s не совпал по хэшу" % STAGE)
            return RC_UPLOAD
        code, out = g._ssh('cd /d %s\\gp7-server && node --check "%s"' % (V2, STAGE))
        if code != 0:
            log("ОШИБКА node --check на сервере: %s" % out)
            return RC_REMOTE_CHECK
        g._ps("Move-Item -Force '%s' '%s'" % (STAGE, REMOTE))
        if g._remote_md5(REMOTE) != new_md5:
            log("ОШИБКА: после замены хэш server.js не совпал")
            return RC_REPLACE
        log("заменён %s (%s); шлюз НЕ перезапускался" % (NAME, new_md5))
        return RC_OK
    except SystemExit as e:
        log("ОШИБКА SSH/scp: %s" % e)
        return RC_REMOTE


def rollback_file(log=print):
    """Вернуть server.js из BAK_DIR БЕЗ перезапуска шлюза. Коды — RC_OK / RC_NO_BACKUP / RC_ROLLBACK_HASH / RC_REMOTE."""
    try:
        g = _gift()
        bak = g._remote_md5(BAK_DIR + "\\" + NAME)
        if not bak:
            log("бэкапа %s\\%s нет — откатывать нечего" % (BAK_DIR, NAME))
            return RC_NO_BACKUP
        g._ps("Copy-Item -Force '%s\\%s' '%s'" % (BAK_DIR, NAME, REMOTE))
        now = g._remote_md5(REMOTE)
        if now != bak:
            log("ОШИБКА: после отката хэш %s != бэкап %s" % (now, bak))
            return RC_ROLLBACK_HASH
        log("откат %s: %s; шлюз НЕ перезапускался (ответ эхом — обрывы по пингу вернутся)" % (NAME, bak))
        return RC_OK
    except SystemExit as e:
        log("ОШИБКА SSH/scp: %s" % e)
        return RC_REMOTE


def main(argv):
    """CLI: сухой прогон / --apply / --rollback (оба с перезапуском ТОЛЬКО шлюза) / --check-started [минут]."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if "--check-started" in argv:
        i = argv.index("--check-started")
        minutes = int(argv[i + 1]) if i + 1 < len(argv) and argv[i + 1].isdigit() else 10
        return check_started(minutes)
    if "--rollback" in argv:
        rc = rollback_file()
        if rc != RC_OK:
            return rc
        _gift()._restart_gp7()
        print("ГОТОВО: шлюз возвращён к прежнему server.js и перезапущен")
        return RC_OK
    apply = "--apply" in argv
    rc = stage(apply)
    if rc != RC_OK or not apply:
        return rc
    _gift()._restart_gp7()
    print("ГОТОВО: шлюз выложен и перезапущен. Через 4–5 минут: python deploy_gp7_alive.py --check-started 4")
    return RC_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
