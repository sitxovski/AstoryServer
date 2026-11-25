# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Выкладка шлюза gp7 «оплачено, но не выдано» (22.11.2026; разбор Reports/admin_center/research_gp7_orphan_orders_20261121.md,
отчёт Reports/admin_center/impl_a6_econ_20261121.md §«gp7: оплачено, не выдано»).

ЧТО МЕНЯЕТСЯ в server.js (только он; SQL, config.json и стойка не трогаются):
  (а) строка журнала SEND 0x0051 несёт order=<номер заказа> (= смещение 174 ответа, = GP7PurchaseLog.id);
  (б) PURCHASE_UNCONFIRMED order=… — сокет GameServer закрылся / дал ошибку ≤ purchaseUnconfirmedMs (2000 мс) после ответа status 1;
  (в) лаки-бокс: код награды проверяется ДО списания (isKnownRewardCode: item_table или функциональный предмет); отказ без
      списания — source unknown-reward-code. Ключи config.json: purchaseUnconfirmedMs = 0, rejectUnknownRewardCode = false —
      прежнее поведение без отката файла.

КАК: тот же штатный путь, что deploy_gp7_alive.py (его stage / rollback_file / check_started), со своими бэкапом, временным
именем и ожидаемым md5 живого файла; перезапуск — ТОЛЬКО node gp7-server (deploy_gp7_gift._restart_gp7: ожидание sqlcmd в
полёте, остановка процесса шлюза, запуск как start.bat). GameServer переподключается сам (таймер 5 с). Только SSH/scp.
Перед перезапуском (--apply) проверяется: нет заморозок подарка 'H' моложе HOLD_FRESH_MIN минут (подарок «в процессе») и в
журнале шлюза за последние QUIET_S секунд нет запросов покупки / подарка (0x0050 / 0x0052). Иначе — останов без перезапуска.

    python deploy_gp7_unconfirmed.py              — СУХОЙ ПРОГОН: md5, дифф, node --check, стенды alive_stand.js и
                                                    unconfirmed_stand.js (с копиями живых таблиц GameServer — scp, только
                                                    чтение; не скопировались — пометка «без LV»); на сервере ничего не пишет
    python deploy_gp7_unconfirmed.py --apply      — бэкап живого server.js в v2\\_backup\\gp7_unconfirmed_20261122, выкладка с
                                                    md5 и node --check на сервере, проверка тишины, перезапуск шлюза
    python deploy_gp7_unconfirmed.py --rollback   — проверка тишины, вернуть server.js из бэкапа и перезапустить шлюз
    python deploy_gp7_unconfirmed.py --quiet      — только проверка тишины (заморозки в процессе, покупки в журнале)
    python deploy_gp7_unconfirmed.py --check-started [минут=10] — как у deploy_gp7_alive.py

★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))                                 # Gp7Gateway\
# ★ ревизия 53: вторая выкладка. Первая (22.11 01:04) сохранила исходный 8EFA8A9F в v2\_backup\gp7_unconfirmed_20261122.
BAK_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\gp7_unconfirmed_r53_20261122"         # бэкап живого server.js этой выкладки
STAGE = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server\server.new_20261122_unconfirmed_r53.js"   # временное имя на сервере (.js — для node --check)
TASK = "AsdaGp7Restart_unconfirmed"                                                # одноразовая задача планировщика запуска
# Живой server.js на момент подготовки (md5 по SSH 22.11 — первая выкладка этой правки; до неё 8EFA8A9F, ping fix 05.11).
EXPECTED_LIVE_MD5 = "0EB1766A9B10AD0E17BECF5230EE4181"
HOLD_FRESH_MIN = 15      # заморозка подарка моложе этого — «в процессе» (HoldTimeoutSec GS 120 с с запасом)
QUIET_S = 60             # в журнале шлюза столько секунд без запросов 0x0050 / 0x0052 — можно перезапускать
RC_BUSY = 13             # перезапуск отложен: подарок в процессе или идут покупки


def _alive():
    """Штатные функции выкладки шлюза (deploy_gp7_alive.py) со своими путями этой выкладки."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import deploy_gp7_alive as a
    a.BAK_DIR, a.STAGE, a.TASK, a.EXPECTED_LIVE_MD5 = BAK_DIR, STAGE, TASK, EXPECTED_LIVE_MD5
    a._stand = _stands
    return a


V2_TABLES = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\GameServer\ItemTable_Info" + "\\"   # папка таблиц GameServer на сервере
LIVE_TABLES = ("PrimiumGaChaTable.txt", "Function_Table.txt", "item_table.txt")   # таблицы GameServer для LV-прогона стенда (только чтение)


def _live_tables(log):
    """★ ревизия 53 М-3: копии живых таблиц GameServer (scp с сервера, только чтение) во временный каталог → путь или None (без них)."""
    import tempfile
    g = _alive()._gift()
    d = tempfile.mkdtemp(prefix="gp7unconf_live_")
    try:
        for n in LIVE_TABLES:
            g._scp(g._remote(V2_TABLES + n), os.path.join(d, n))
    except SystemExit as e:
        log("ВНИМАНИЕ: живые таблицы не скопированы (%s) — стенд без проверки всех живых наград (LV)" % e)
        return None
    log("живые таблицы GameServer скопированы (только чтение): %s" % d)
    return d


def _stands(log):
    """Стенды шлюза перед выкладкой: alive_stand.js (пинг) и unconfirmed_stand.js (эта правка; с живыми таблицами — LV: каждая награда
    живой PrimiumGaChaTable проходит проверку). True — 0 провалов."""
    good = True
    live = _live_tables(log)
    for js in ("alive_stand.js", "unconfirmed_stand.js"):
        args = ["node", os.path.join(HERE, "stand", js)] + (["25071", live] if js == "unconfirmed_stand.js" and live else [])
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        for ln in (r.stdout.strip() + "\n" + r.stderr.strip()).strip().splitlines():
            if "FAIL" in ln or "ИТОГ" in ln or " LV " in ln:
                log(ln)
        good = good and r.returncode == 0
    return good


def quiet(log=print):
    """Проверка тишины перед перезапуском: 0 заморозок 'H' моложе HOLD_FRESH_MIN мин и нет 0x0050 / 0x0052 в журнале шлюза за QUIET_S с.
    → RC 0 / RC_BUSY / alive.RC_REMOTE."""
    a = _alive()
    g = a._gift()
    try:
        q = ("SET NOCOUNT ON; SELECT COUNT(*) FROM dbo.GP7GiftLog WHERE state = 'H' AND created_at > DATEADD(minute, -%d, SYSUTCDATETIME());"
             % HOLD_FRESH_MIN)
        _, out = g._ps("& sqlcmd -S . -E -C -d AsdaStoryLogin -h -1 -W -Q \"%s\"" % q)
        fresh = a._last_digits(out)
        day = time.strftime("%Y%m%d")
        ps = ("$p='%s\\gp7-server\\logs\\gp7-%s.log'; $c=(Get-Date).AddSeconds(-%d).ToString('yyyy-MM-dd HH:mm:ss'); "
              "if (Test-Path $p) { @(Get-Content -Tail 6000 $p | Where-Object { $_.Length -ge 19 -and $_.Substring(0,19) -ge $c -and "
              "$_ -match ' RECV .*command=0x005[02]' }).Count } else { 0 }") % (a.V2, day, QUIET_S)
        _, out2 = g._ps(ps)
        busy = a._last_digits(out2)
    except SystemExit as e:
        log("ОШИБКА SSH: %s" % e)
        return a.RC_REMOTE
    log("заморозок подарка 'H' моложе %d мин: %d; запросов покупки/подарка в журнале шлюза за %d с: %d" % (HOLD_FRESH_MIN, fresh, QUIET_S, busy))
    return 0 if fresh == 0 and busy == 0 else RC_BUSY


def main(argv):
    """CLI: сухой прогон / --apply / --rollback / --quiet / --check-started [минут]."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    a = _alive()
    if "--check-started" in argv:
        i = argv.index("--check-started")
        return a.check_started(int(argv[i + 1]) if i + 1 < len(argv) and re.fullmatch(r"\d+", argv[i + 1]) else 10)
    if "--quiet" in argv:
        return quiet()
    if "--rollback" in argv:
        rc = quiet()                                      # ★ ревизия 53 М-3: та же проверка тишины, что у --apply
        if rc != 0:
            print("ОСТАНОВ: подарок в процессе или идут покупки — откат повторить через минуту (на сервере ничего не изменено)")
            return rc
        rc = a.rollback_file()
        if rc != a.RC_OK:
            return rc
        a._gift()._restart_gp7()
        print("ГОТОВО: шлюз возвращён к прежнему server.js и перезапущен")
        return a.RC_OK
    apply = "--apply" in argv
    if apply:
        rc = quiet()
        if rc != 0:
            print("ОСТАНОВ: подарок в процессе или идут покупки — повторить через минуту (на сервере ничего не изменено)")
            return rc
    rc = a.stage(apply)
    if rc != a.RC_OK or not apply:
        return rc
    rc = quiet()
    if rc != 0:
        print("ВНИМАНИЕ: server.js заменён, но перезапуск отложен (подарок в процессе или идут покупки) — повторить --apply через минуту "
              "(файл уже новый, stage ответит «уже новая версия»)")
        return rc
    a._gift()._restart_gp7()
    print("ГОТОВО: шлюз выложен и перезапущен. Через 4–5 минут: python deploy_gp7_unconfirmed.py --check-started 4")
    return a.RC_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
