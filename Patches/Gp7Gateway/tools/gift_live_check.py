# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# gift_live_check.py — проверка подарка из кэш-магазина (P101) на живом dev, ТОЛЬКО ЧТЕНИЕ (02.11.2026).
#   Сводит в одну картину: AsdaStoryLogin.dbo.GP7GiftLog (заказы подарков по состояниям), joylog1.ac.other виды 158–163
#   (журнал P101 трёх GS), Joy1/JoyLog1 EventGainItem State='CashGift' (выдача процедурой UPGivenitem) и строки
#   GIFT_HOLD/COMMIT/REFUND журналов gp7-server. Печатает аномалии — их сразу сообщать координатору.
#   SQL уходит файлом через scp + sqlcmd -i (не в командной строке SSH); в БД ничего не пишется.
#   Запуск: python gift_live_check.py [--since "2026-11-02 10:04"] [--hold-min 3]
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile

KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"                       # ключ SSH к dev-серверу
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"                             # dev-сервер (Tailscale)
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]   # общая команда SSH
REMOTE = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/_backup/cashgift_live_check"    # папка для временного SQL-файла на сервере
GP7_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server"                   # папка шлюза (журналы gp7-*.log)
KINDS = {158: "оплачен, 5076 ушёл", 159: "получатель принял, DB 2134", 160: "отказ получателя → REFUND",
         161: "GP7 отказал в HOLD", 162: "hold без исхода / рассинхрон", 163: "P101 выкл./настройка исправлена"}  # реестр ac-journal-p53.md §9
KIND_CASE = ("CASE WHEN event_kind LIKE N'P101: подарок оплачен%' THEN 158 WHEN event_kind LIKE N'P101: подарок принят%' THEN 159 WHEN event_kind LIKE N'P101: отказ получателя%' THEN 160 WHEN event_kind LIKE N'P101: отказ в оплате%' THEN 161 WHEN event_kind LIKE N'P101: подарок без исхода%' THEN 162 WHEN event_kind LIKE N'P101: подарок выключен%' THEN 163 ELSE 0 END")  # подпись вида → номер (тексты AcJournal.cpp:354-359)


def ps(cmd, timeout=600):
    """PowerShell по SSH → (код, вывод)."""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def run_sql(text):
    """Текст SQL → временный файл → scp → sqlcmd -i → строки вывода (разделитель |)."""
    fd, path = tempfile.mkstemp(suffix=".sql")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % REMOTE.replace("/", "\\"), 120)
        name = "check.sql"
        r = subprocess.run(["scp", "-q", "-i", KEY, "-o", "BatchMode=yes", path, "%s:%s/%s" % (HOST, REMOTE, name)],
                           capture_output=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError("scp: " + (r.stdout + r.stderr).decode("utf-8", "replace"))
        rp = (REMOTE + "/" + name).replace("/", "\\")
        rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -b -f 65001 -h -1 -W -s '|' -i '%s' 2>&1; "
                     "Write-Output ($o -join \"`n\"); Write-Output (\"RC=\" + $LASTEXITCODE)" % rp)
    finally:
        os.remove(path)
    m = re.search(r"RC=(-?\d+)", out)
    if not m or m.group(1) != "0":
        raise RuntimeError("sqlcmd: " + out[-2000:])
    return [ln.strip() for ln in out.splitlines() if "|" in ln and not ln.startswith("RC=")]


def sql_text(since, hold_min):
    """Запросы сводки; все — SELECT."""
    s = since.replace("'", "")
    return "\n".join([
        "SET NOCOUNT ON;",
        # заказы подарков по состояниям и висящие 'H'
        "SELECT 'state|'+state COLLATE DATABASE_DEFAULT+'|'+CAST(test_mode AS VARCHAR)+'|'+CAST(COUNT(*) AS VARCHAR)+'|'+CAST(SUM(amount) AS VARCHAR) "
        "FROM AsdaStoryLogin.dbo.GP7GiftLog WHERE created_at>='%s' GROUP BY state,test_mode;" % s,
        "SELECT 'hold|'+CAST(order_id AS VARCHAR)+'|'+CONVERT(VARCHAR(19),created_at,120)+'|'+CAST(DATEDIFF(SECOND,created_at,GETDATE()) AS VARCHAR)"
        "+'|'+ISNULL(sender_account COLLATE DATABASE_DEFAULT,'')+'|'+ISNULL(recipient_name COLLATE DATABASE_DEFAULT,'')+'|'+CAST(amount AS VARCHAR) "
        "FROM AsdaStoryLogin.dbo.GP7GiftLog WHERE state='H' AND created_at<DATEADD(MINUTE,-%d,GETDATE());" % hold_min,
        "SELECT TOP 20 'order|'+CAST(order_id AS VARCHAR)+'|'+state COLLATE DATABASE_DEFAULT+'|'+CONVERT(VARCHAR(19),created_at,120)+'|'+ISNULL(CONVERT(VARCHAR(19),settled_at,120),'-')"
        "+'|'+ISNULL(sender_account COLLATE DATABASE_DEFAULT,'')+'|'+ISNULL(recipient_name COLLATE DATABASE_DEFAULT,'')+'|'+CAST(code1 AS VARCHAR)+','+CAST(code2 AS VARCHAR)+','+CAST(code3 AS VARCHAR)"
        "+'|'+CAST(amount AS VARCHAR)+'|'+ISNULL(CAST(settle_result AS VARCHAR),'-') "
        "FROM AsdaStoryLogin.dbo.GP7GiftLog WHERE created_at>='%s' ORDER BY order_id DESC;" % s,
        # журнал P101 трёх GS
        # event_kind в ac.other — ТЕКСТОВАЯ подпись вида (AcJournal.cpp:354-359), номер восстанавливаем по её началу
        "SELECT 'kind|'+CAST(k AS VARCHAR)+'|'+sn+'|'+CAST(COUNT(*) AS VARCHAR) FROM (SELECT %s AS k, server_name COLLATE DATABASE_DEFAULT AS sn "
        "FROM joylog1.ac.other WHERE event_kind LIKE N'P101:%%' AND ev_local>='%s') t GROUP BY k,sn;" % (KIND_CASE, s),
        "SELECT TOP 30 'ev|'+CONVERT(VARCHAR(19),ev_local,120)+'|'+server_name COLLATE DATABASE_DEFAULT+'|'+CAST(" + KIND_CASE + " AS VARCHAR)"
        "+'|'+ISNULL(CAST(user_index AS VARCHAR),'-')+'|'+ISNULL(char_name COLLATE DATABASE_DEFAULT,'')+'|'+ISNULL(CAST(item_code AS VARCHAR),'-')"
        "+'|'+ISNULL(CAST(value1 AS VARCHAR),'-')+'|'+ISNULL(CAST(value2 AS VARCHAR),'-')+'|'+ISNULL(detail COLLATE DATABASE_DEFAULT,'') "
        "FROM joylog1.ac.other WHERE event_kind LIKE N'P101:%%' AND ev_local>='%s' ORDER BY event_id DESC;" % s,
        # выдача процедурой UPGivenitem (журнал EventGainItem)
        "SELECT 'gain|'+CAST(COUNT(*) AS VARCHAR)+'|'+CAST(COUNT(DISTINCT Serial) AS VARCHAR) "
        "FROM JoyLog1.dbo.EventGainItem WHERE State='CashGift' AND Edate>='%s';" % s,
        "SELECT TOP 20 'gainrow|'+CONVERT(VARCHAR(19),Edate,120)+'|'+CAST(Userindex AS VARCHAR)+'|'+CAST(Charidx AS VARCHAR)+'|'+CAST(Code AS VARCHAR)"
        "+'|'+CAST(Amount AS VARCHAR) FROM JoyLog1.dbo.EventGainItem WHERE State='CashGift' AND Edate>='%s' ORDER BY Edate DESC;" % s,
        ""])


def gp7_lines(since):
    """Строки GIFT_* журналов gp7-server за сегодня (последние 40)."""
    rc, out = ps("Get-ChildItem '%s' -Recurse -File -Filter 'gp7-*.log' -ErrorAction SilentlyContinue | Sort LastWriteTime -Desc | "
                 "Select -First 3 | Select-String -Pattern 'GIFT_(HOLD|COMMIT|REFUND|LOOKUP)|gift-' | Select -Last 40 | "
                 "ForEach-Object { $_.Line.Substring(0,[Math]::Min(260,$_.Line.Length)) }" % GP7_DIR)
    return [ln for ln in out.splitlines() if "GIFT" in ln or "gift-" in ln]


def main():
    """Сводка + аномалии. Код 0 — аномалий нет, 2 — есть (сообщить координатору), 1 — ошибка чтения."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="P101: проверка подарка на живом (только чтение)")
    ap.add_argument("--since", default="2026-11-02 10:04", help="начало окна (время выкладки P101)")
    ap.add_argument("--hold-min", type=int, default=3, help="'H' старше стольких минут — аномалия (HoldTimeoutSec=120)")
    a = ap.parse_args()
    try:
        rows = run_sql(sql_text(a.since, a.hold_min))
    except Exception as e:  # noqa: BLE001 — отчёт об ошибке чтения, без записи
        print("ОШИБКА ЧТЕНИЯ:", e)
        return 1
    by = {}
    for r in rows:
        by.setdefault(r.split("|", 1)[0], []).append(r.split("|"))
    anomalies = []
    print("== P101 на живом с %s" % a.since)
    print("-- GP7GiftLog по состояниям (state | тест | заказов | сумма):")
    st = {}
    for f in by.get("state", []):
        print("   ", " | ".join(f[1:]))
        st[f[1]] = st.get(f[1], 0) + int(f[3])
    if not by.get("state"):
        print("    подарков ещё не было")
    for f in by.get("hold", []):
        anomalies.append("заказ %s висит в 'H' %s с (отправитель %s → %s, сумма %s) — сверка gift_reconcile.py" % (f[1], f[3], f[4], f[5], f[6]))
    print("-- последние заказы (id | сост. | создан | закрыт | отправитель | получатель | коды | сумма | итог):")
    for f in by.get("order", []):
        print("   ", " | ".join(f[1:]))
    print("-- ac.other 158–163 (вид | сервер | строк):")
    kc = {}
    for f in by.get("kind", []):
        k = int(f[1])
        kc[k] = kc.get(k, 0) + int(f[3])
        print("    %s %-34s | %s | %s" % (k, KINDS.get(k, "?"), f[2], f[3]))
    print("-- последние события P101 (время | сервер | вид | учётка | персонаж | item_code | v1 | v2 | detail):")
    for f in by.get("ev", []):
        print("   ", " | ".join(f[1:]))
    gain = by.get("gain", [["gain", "0", "0"]])[0]
    print("-- выдано UPGivenitem (EventGainItem 'CashGift'): строк %s, ячеек %s" % (gain[1], gain[2]))
    for f in by.get("gainrow", []):
        print("   ", " | ".join(f[1:]))
    gl = gp7_lines(a.since)
    print("-- gp7 GIFT_* (последние):")
    for ln in gl:
        print("   ", ln)
    # правила аномалий
    if kc.get(162):
        anomalies.append("ac.other 162 — %d шт.: hold без исхода / рассинхрон" % kc[162])
    if kc.get(163):
        anomalies.append("ac.other 163 — %d шт.: P101 выключен или настройка исправлена при старте" % kc[163])
    if kc.get(158, 0) != kc.get(159, 0) + kc.get(160, 0) and (kc.get(158) or kc.get(159)):
        anomalies.append("158 (оплачено %d) ≠ 159 принято %d + 160 отказ %d — часть подарков в пути или потеряна"
                         % (kc.get(158, 0), kc.get(159, 0), kc.get(160, 0)))
    if st.get("C", 0) and int(gain[1]) == 0:
        anomalies.append("есть закрытые оплаты 'C' (%d), а выдачи CashGift в EventGainItem нет" % st["C"])
    if any("gift-price-mismatch" in ln for ln in gl):
        anomalies.append("gp7: gift-price-mismatch — цена витрины GS ≠ карте gp7")
    print("== АНОМАЛИИ: %s" % ("нет" if not anomalies else ""))
    for x in anomalies:
        print("   ⚠", x)
    return 2 if anomalies else 0


if __name__ == "__main__":
    sys.exit(main())
