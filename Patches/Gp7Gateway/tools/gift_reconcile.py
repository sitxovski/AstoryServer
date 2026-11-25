# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""gift_reconcile.py — сверка зависших заморозок подарка P101_CashGift (01.11.2026). ТОЛЬКО ЧТЕНИЕ.

Решение владельца: если ответа нет, деньги автоматически не возвращаются. Заморозку 'H', у которой не было COMMIT/REFUND
(упал GS или реле, рестарт), разбирает человек. Инструмент печатает всё, что нужно для решения, и ничего не применяет.

Для каждой строки AsdaStoryLogin.dbo.GP7GiftLog со state='H' старше N минут (по умолчанию 10):
  - отправитель: учётка, ник, UserIndex/Charidx/UserNum;
  - получатель: имя → Joy1.dbo.Charinfo (Userindex, Charidx);
  - коды с названиями, сумма, возраст, test_mode;
  - есть ли у получателя в Joy1.dbo.Item эти коды, полученные после заморозки (GainDate или Fdate ≥ created_at);
  - есть ли строки JoyLog1.dbo.EventGainItem State='CashGift' по получателю и кодам в окне [−5 с; +окно] (их пишет UPGivenitem);
  - ★ 02.11 (ревизия В3): другие заморозки (любого состояния) тому же получателю с общим кодом в окне ±окно → «неясно»;
  - ★ (ревизия М8): имя у нескольких персонажей — берётся единственный байт-в-байт, иначе «неясно»;
  - подсказка: «вероятно выдано → commit» / «не выдано → refund» / «неясно».
Итог печатается и пишется в CSV Reports/cash_gift/reconcile/gift_reconcile_<дата>.csv.

Время: GP7GiftLog хранит UTC (SYSUTCDATETIME), а Joy1/JoyLog1 — местное (GETDATE). Пересчёт идёт на сервере:
  DATEDIFF(minute, SYSUTCDATETIME(), SYSDATETIME()).

Доступ: SSH к dev-серверу, SQL — файлом (scp + sqlcmd -i, только SELECT; файл удаляется). Ключ --local SERVER гоняет
тот же SQL на локальном sqlcmd (стенд stand/reconcile_stand.py).

    python gift_reconcile.py                       — список заморозок старше 10 минут
    python gift_reconcile.py --minutes 30          — старше 30 минут
    python gift_reconcile.py --window 300          — окно сопоставления ±300 с (по умолчанию 180 = HoldTimeoutSec 120 + 60)
    python gift_reconcile.py --emit-sql 15301:commit,15302:refund
                                                   — дополнительно НАПЕЧАТАТЬ (не выполнять) EXEC dbo.GP7_GiftSettle
    python gift_reconcile.py --local "(localdb)\\gp7gift" --out <каталог>   — стенд

★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import csv
import datetime
import os
import subprocess
import sys
import tempfile
import uuid

SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"                       # ключ dev-сервера
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"                             # dev-сервер (Tailscale)
SRV_SQL = r"localhost\SQLEXPRESS"                                     # экземпляр SQL на сервере (как config.json gp7)
SRV_TMP = r"C:\Users\Administrator\AppData\Local\Temp"                # куда кладётся временный .sql
HERE = os.path.dirname(os.path.abspath(__file__))                     # Gp7Gateway\tools
PORT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))   # @@ASTORY_DEV_ROOT@@\port
OUT_DIR = os.path.join(PORT, "Reports", "cash_gift", "reconcile")     # CSV по умолчанию
NAMES_DIR = os.path.join(PORT, "AstoryClient", "RawAssets", "Data", "ItemDB")   # клиентские таблицы названий (как AstoryAdminCenter/tools/Admin/asda_give.py)
ACTIONS = {"commit": 2, "refund": 3}                                  # действие → @action GP7_GiftSettle
DEFAULT_WINDOW_SEC = 180                                              # окно сопоставления: HoldTimeoutSec DLL (120) + запас 60 с


def build_sql(minutes, window):
    """SELECT-only запрос сверки; строки вывода с префиксами info|/hold|/item|/ev|/other|.
    ★ 02.11 (ревизия В3): окно сопоставления симметрично — EventGainItem берётся в [заморозка − 5 с; заморозка + window с],
    «другие подарки» — все заморозки (любого состояния) тому же получателю с общим кодом, созданные в [−window; +window].
    ★ (ревизия М8): получатель ищется по Arabic_CI_AS; при нескольких персонажах берётся единственный байт-в-байт, иначе —
    «неоднозначно» (r_count > 1, без выбора)."""
    return """SET NOCOUNT ON;
IF OBJECT_ID('AsdaStoryLogin.dbo.GP7GiftLog') IS NULL
BEGIN
    SELECT 'info|notable';
    RETURN;
END;
DECLARE @shift INT = DATEDIFF(minute, SYSUTCDATETIME(), SYSDATETIME());   -- местное − UTC, минут
DECLARE @win INT = %d;                                                     -- окно сопоставления, секунд
SELECT 'info|now|' + CONVERT(VARCHAR(19), SYSDATETIME(), 120) + '|' + CAST(@shift AS VARCHAR(10)) + '|' + CAST(@win AS VARCHAR(10));
SELECT 'info|counts|' + CAST(SUM(CASE WHEN state='H' THEN 1 ELSE 0 END) AS VARCHAR(10)) + '|' + CAST(COUNT(*) AS VARCHAR(10))
FROM AsdaStoryLogin.dbo.GP7GiftLog;
IF OBJECT_ID('tempdb..#h') IS NOT NULL DROP TABLE #h;
IF OBJECT_ID('tempdb..#c') IS NOT NULL DROP TABLE #c;
SELECT g.order_id, g.sender_account, g.sender_name, g.sender_userindex, g.sender_charidx, g.sender_usernum, g.recipient_name,
       g.code1, g.code2, g.code3, g.code4, g.code5, g.code6, g.code7, g.amount, g.test_mode,
       g.created_at, DATEADD(minute, @shift, g.created_at) AS created_local,
       DATEDIFF(minute, g.created_at, SYSUTCDATETIME()) AS age_min,
       CAST(NULL AS INT) AS r_userindex, CAST(NULL AS INT) AS r_charidx, CAST(NULL AS VARCHAR(61)) AS r_uid, 0 AS r_count
INTO #h
FROM AsdaStoryLogin.dbo.GP7GiftLog g
WHERE g.state = 'H' AND g.created_at < DATEADD(minute, -%d, SYSUTCDATETIME());
-- персонажи с этим именем (Arabic_CI_AS) и признак «байт в байт»
SELECT h.order_id, c.Userindex, c.Charidx, c.Uid,
       CASE WHEN CAST(c.Charname AS VARBINARY(20)) = CAST(h.recipient_name AS VARBINARY(20)) THEN 1 ELSE 0 END AS exact
INTO #c
FROM #h h
JOIN Joy1.dbo.Charinfo c WITH (READUNCOMMITTED) ON c.Charname = h.recipient_name COLLATE Arabic_CI_AS;
UPDATE h SET r_count = (SELECT COUNT(*) FROM #c c WHERE c.order_id = h.order_id) FROM #h h;
UPDATE h SET r_userindex = c.Userindex, r_charidx = c.Charidx, r_uid = c.Uid
FROM #h h
JOIN #c c ON c.order_id = h.order_id
WHERE (h.r_count = 1)
   OR (h.r_count > 1 AND c.exact = 1 AND (SELECT COUNT(*) FROM #c x WHERE x.order_id = h.order_id AND x.exact = 1) = 1);
SELECT 'hold|' + CAST(order_id AS VARCHAR(20)) + '|' + sender_account COLLATE DATABASE_DEFAULT + '|'
       + CONVERT(VARCHAR(40), CAST(sender_name AS VARBINARY(20)), 2) + '|' + CAST(sender_userindex AS VARCHAR(12)) + '|'
       + CAST(sender_charidx AS VARCHAR(12)) + '|' + CAST(sender_usernum AS VARCHAR(12)) + '|'
       + CONVERT(VARCHAR(40), CAST(recipient_name AS VARBINARY(20)), 2) + '|'
       + CAST(code1 AS VARCHAR(12)) + ',' + CAST(code2 AS VARCHAR(12)) + ',' + CAST(code3 AS VARCHAR(12)) + ',' + CAST(code4 AS VARCHAR(12)) + ','
       + CAST(code5 AS VARCHAR(12)) + ',' + CAST(code6 AS VARCHAR(12)) + ',' + CAST(code7 AS VARCHAR(12)) + '|'
       + CAST(amount AS VARCHAR(20)) + '|' + CAST(test_mode AS VARCHAR(1)) + '|' + CONVERT(VARCHAR(19), created_at, 120) + '|'
       + CONVERT(VARCHAR(19), created_local, 120) + '|' + CAST(age_min AS VARCHAR(12)) + '|'
       + ISNULL(CAST(r_userindex AS VARCHAR(12)), '') + '|' + ISNULL(CAST(r_charidx AS VARCHAR(4)), '') + '|'
       + ISNULL(r_uid COLLATE DATABASE_DEFAULT, '') + '|' + CAST(r_count AS VARCHAR(6))
FROM #h ORDER BY order_id;
-- предметы получателя с этими кодами, полученные после заморозки
SELECT 'item|' + CAST(h.order_id AS VARCHAR(20)) + '|' + CAST(i.Code AS VARCHAR(12)) + '|' + CAST(COUNT(*) AS VARCHAR(10)) + '|'
       + CAST(SUM(CAST(i.Amount AS BIGINT)) AS VARCHAR(20)) + '|'
       + CONVERT(VARCHAR(19), MAX(CASE WHEN i.GainDate > ISNULL(i.Fdate, '19000101') THEN i.GainDate ELSE i.Fdate END), 120)
FROM #h h
JOIN Joy1.dbo.Item i WITH (READUNCOMMITTED) ON i.Userindex = h.r_userindex AND i.Charidx = h.r_charidx
WHERE i.Code IN (h.code1, h.code2, h.code3, h.code4, h.code5, h.code6, h.code7) AND i.Code > 0
  AND (i.GainDate >= h.created_local OR i.Fdate >= h.created_local)
GROUP BY h.order_id, i.Code;
-- журнал выдачи подарка (UPGivenitem → EventGainItem State='CashGift'), строка на ячейку; окно [−5 с; +@win с]
SELECT 'ev|' + CAST(h.order_id AS VARCHAR(20)) + '|' + CAST(e.Code AS VARCHAR(12)) + '|' + CAST(COUNT(*) AS VARCHAR(10)) + '|'
       + CAST(SUM(CAST(e.Amount AS BIGINT)) AS VARCHAR(20)) + '|' + CONVERT(VARCHAR(19), MIN(e.Edate), 120) + '|'
       + CONVERT(VARCHAR(19), MAX(e.Edate), 120)
FROM #h h
JOIN JoyLog1.dbo.EventGainItem e WITH (READUNCOMMITTED) ON e.Userindex = h.r_userindex AND e.Charidx = h.r_charidx
WHERE e.State = 'CashGift' AND e.Code IN (h.code1, h.code2, h.code3, h.code4, h.code5, h.code6, h.code7) AND e.Code > 0
  AND e.Edate >= DATEADD(second, -5, h.created_local) AND e.Edate <= DATEADD(second, @win, h.created_local)
GROUP BY h.order_id, e.Code;
-- другие заморозки (любое состояние) тому же получателю с общим кодом в окне [−@win; +@win] — журнал может быть их
SELECT 'other|' + CAST(h.order_id AS VARCHAR(20)) + '|' + CAST(g2.order_id AS VARCHAR(20)) + '|' + g2.state + '|'
       + CONVERT(VARCHAR(19), g2.created_at, 120)
FROM #h h
JOIN AsdaStoryLogin.dbo.GP7GiftLog g2 ON g2.recipient_name = h.recipient_name AND g2.order_id <> h.order_id
     AND g2.created_at BETWEEN DATEADD(second, -@win, h.created_at) AND DATEADD(second, @win, h.created_at)
WHERE EXISTS (SELECT 1 FROM (VALUES (g2.code1), (g2.code2), (g2.code3), (g2.code4), (g2.code5), (g2.code6), (g2.code7)) a(c)
              WHERE a.c > 0 AND a.c IN (h.code1, h.code2, h.code3, h.code4, h.code5, h.code6, h.code7))
ORDER BY h.order_id, g2.order_id;
""" % (int(window), int(minutes))


def run_sql_remote(sql):
    """SQL файлом на сервер: scp → sqlcmd -i (UTF-8 вывод) → удалить файл. Возвращает строки вывода."""
    name = "p101_reconcile_%s.sql" % uuid.uuid4().hex[:8]
    local = os.path.join(tempfile.gettempdir(), name)
    with open(local, "w", encoding="utf-8-sig") as f:
        f.write(sql)
    try:
        r = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", local,
                            "%s:%s/%s" % (SSH_HOST, SRV_TMP.replace("\\", "/"), name)], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise SystemExit("scp: %s" % r.stderr.strip())
        remote = SRV_TMP + "\\" + name
        cmd = 'sqlcmd -S %s -E -C -b -h -1 -W -f i:65001,o:65001 -i "%s" & del "%s"' % (SRV_SQL, remote, remote)
        r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", SSH_HOST, cmd],
                           capture_output=True, timeout=300)
    finally:
        os.remove(local)
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode != 0:
        raise SystemExit("sqlcmd на сервере: %s %s" % (out, r.stderr.decode("cp866", "replace")))
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def run_sql_local(server, sql):
    """Тот же SQL на локальном sqlcmd (стенд)."""
    local = os.path.join(tempfile.gettempdir(), "p101_reconcile_local_%s.sql" % uuid.uuid4().hex[:8])
    with open(local, "w", encoding="utf-8-sig") as f:
        f.write(sql)
    try:
        r = subprocess.run(["sqlcmd", "-S", server, "-E", "-C", "-b", "-h", "-1", "-W", "-f", "i:65001,o:65001", "-i", local],
                           capture_output=True, timeout=300)
    finally:
        os.remove(local)
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode != 0:
        raise SystemExit("sqlcmd: %s %s" % (out, r.stderr.decode("cp866", "replace")))
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def item_names(codes):
    """Код → название из клиентских таблиц (первое осмысленное), только для нужных кодов."""
    want = set(codes)
    names = {}
    for fname, kcol, ncol in (("special_itemlist.csv", "Code", "Name"), ("sowell_list.csv", "Id", "Name"),
                              ("item_list.csv", "ItemCode", "ItemName")):
        if not want - set(names):
            break
        try:
            with open(os.path.join(NAMES_DIR, fname), encoding="utf-8-sig", newline="") as fh:
                for r in csv.DictReader(fh):
                    k, n = (r.get(kcol) or "").strip(), (r.get(ncol) or "").strip()
                    if k.isdigit() and int(k) in want and int(k) not in names and n and n not in ("-", "Нет"):
                        names[int(k)] = n
        except OSError:
            pass
    return names


def name_text(hexstr):
    """Байты имени (hex, кодовая страница игры cp1256) → текст."""
    try:
        return bytes.fromhex(hexstr).decode("cp1256", "replace")
    except ValueError:
        return hexstr


def hint(h, items, evs, others):
    """Подсказка по одной заморозке: (метка, пояснение). others — [(заказ, состояние, создан)] в окне (ревизия В3):
    любое пересечение по получателю и коду → «неясно» (журнал выдачи может принадлежать другому подарку)."""
    if h["r_count"] > 1 and not h["r_userindex"]:
        return "неясно", "имя «%s» у %d персонажей Joy1.dbo.Charinfo и ни один не совпал байт в байт" % (h["recipient"], h["r_count"])
    if not h["r_userindex"]:
        return "неясно", "получатель «%s» не найден в Joy1.dbo.Charinfo" % h["recipient"]
    if others:
        return "неясно", "в окне есть другие подарки тому же получателю с тем же кодом: %s — журнал выдачи может быть их" % (
            ", ".join("%d(%s, %s UTC)" % o for o in others))
    need = {}
    for c in h["codes"]:
        need[c] = need.get(c, 0) + 1
    ev_ok = all(evs.get(c, (0, 0))[0] >= n for c, n in need.items())
    ev_any = any(evs.get(c, (0, 0))[0] > 0 for c in need)
    it_any = any(items.get(c, (0, 0))[0] > 0 for c in need)
    if ev_ok:
        return "вероятно выдано → commit", "EventGainItem 'CashGift' есть по всем кодам в окне заморозки"
    if not ev_any and not it_any:
        return "не выдано → refund", "ни EventGainItem 'CashGift' в окне, ни ячеек Item с этими кодами после заморозки"
    return "неясно", "частичные следы (EventGainItem: %s; Item: %s)" % (
        ",".join("%d×%d" % (c, evs.get(c, (0, 0))[0]) for c in need),
        ",".join("%d×%d" % (c, items.get(c, (0, 0))[0]) for c in need))


def parse(lines):
    """Строки вывода SQL → (info, holds, items, evs, others)."""
    info, holds, items, evs, others = {}, [], {}, {}, {}
    for ln in lines:
        f = ln.split("|")
        if f[0] == "info":
            info[f[1]] = f[2:]
        elif f[0] == "hold" and len(f) >= 18:
            holds.append({
                "order": int(f[1]), "account": f[2], "sender": name_text(f[3]), "s_userindex": f[4], "s_charidx": f[5],
                "s_usernum": f[6], "recipient": name_text(f[7]), "recipient_hex": f[7],
                "codes": [int(x) for x in f[8].split(",") if x and int(x) > 0], "amount": int(f[9]), "test": f[10],
                "created_utc": f[11], "created_local": f[12], "age_min": int(f[13]), "r_userindex": f[14], "r_charidx": f[15],
                "r_uid": f[16], "r_count": int(f[17])})
        elif f[0] == "item":
            items.setdefault(int(f[1]), {})[int(f[2])] = (int(f[3]), f[5])
        elif f[0] == "ev":
            evs.setdefault(int(f[1]), {})[int(f[2])] = (int(f[3]), f[5] + ".." + f[6])
        elif f[0] == "other":
            others.setdefault(int(f[1]), []).append((int(f[2]), f[3], f[4]))
    return info, holds, items, evs, others


def parse_emit(arg):
    """«15301:commit,15302:refund» → [(15301, 2), (15302, 3)]."""
    out = []
    for part in arg.split(","):
        part = part.strip()
        if not part:
            continue
        order, _, act = part.partition(":")
        if not order.isdigit() or act not in ACTIONS:
            raise SystemExit("--emit-sql: ждали «заказ:commit|refund», получено «%s»" % part)
        out.append((int(order), ACTIONS[act]))
    return out


def main(argv):
    """Точка входа: печать сверки, CSV, по ключу — текст EXEC (не выполняется)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    minutes, emit, local, out_dir, window = 10, None, None, OUT_DIR, DEFAULT_WINDOW_SEC
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--minutes":
            minutes = int(argv[i + 1]); i += 1
        elif a == "--window":
            window = int(argv[i + 1]); i += 1
        elif a == "--emit-sql":
            emit = parse_emit(argv[i + 1]); i += 1
        elif a == "--local":
            local = argv[i + 1]; i += 1
        elif a == "--out":
            out_dir = argv[i + 1]; i += 1
        elif a in ("-h", "--help"):
            print(__doc__); return 0
        else:
            raise SystemExit("неизвестный ключ %s (см. --help)" % a)
        i += 1

    sql = build_sql(minutes, window)
    lines = run_sql_local(local, sql) if local else run_sql_remote(sql)
    info, holds, items, evs, others = parse(lines)
    where = local or ("%s %s (SSH)" % (SSH_HOST, SRV_SQL))
    print("Сверка заморозок подарка (только чтение) — %s, старше %d мин" % (where, minutes))
    if "notable" in info:
        print("Таблицы AsdaStoryLogin.dbo.GP7GiftLog нет: шлюз с P101 не выложен, сверять нечего.")
        return 0
    now = info.get("now", ["?", "?"])
    cnt = info.get("counts", ["?", "?"])
    print("Время сервера (местное) %s, сдвиг от UTC %s мин; в GP7GiftLog всего %s строк, из них 'H' %s; окно сопоставления ±%d с"
          % (now[0], now[1], cnt[1], cnt[0], window))
    names = item_names({c for h in holds for c in h["codes"]})
    rows = []
    for h in holds:
        it = items.get(h["order"], {})
        ev = evs.get(h["order"], {})
        label, why = hint(h, it, ev, others.get(h["order"], []))
        print("")
        print("заказ %d  [%s]  возраст %d мин  сумма %d%s" % (h["order"], label, h["age_min"], h["amount"],
                                                             "  (test_mode: возврат меняет только state)" if h["test"] == "1" else ""))
        print("  отправитель: учётка %s, ник «%s», UserIndex %s, Charidx %s, UserNum %s" % (
            h["account"], h["sender"], h["s_userindex"], h["s_charidx"], h["s_usernum"]))
        print("  получатель : «%s» (hex %s) → %s" % (h["recipient"], h["recipient_hex"],
              "UserIndex %s, Charidx %s, учётка %s%s" % (h["r_userindex"], h["r_charidx"], h["r_uid"],
              " (из %d с этим именем — байт в байт)" % h["r_count"] if h["r_count"] > 1 else "") if h["r_userindex"]
              else ("НЕОДНОЗНАЧНО: %d персонажей" % h["r_count"] if h["r_count"] > 1 else "НЕ НАЙДЕН")))
        print("  заморожено : %s UTC (%s местное)" % (h["created_utc"], h["created_local"]))
        for c in sorted(set(h["codes"])):
            n = h["codes"].count(c)
            print("  код %-6d ×%d %-40s Item после: %-3d EventGainItem 'CashGift': %d %s" % (
                c, n, names.get(c, "(без названия)"), it.get(c, (0, ""))[0], ev.get(c, (0, ""))[0], ev.get(c, (0, ""))[1]))
        for oo in others.get(h["order"], []):
            print("  другой подарок в окне: заказ %d, state %s, создан %s UTC" % oo)
        print("  подсказка  : %s — %s" % (label, why))
        rows.append([h["order"], label, why, h["age_min"], h["amount"], h["test"], h["account"], h["sender"], h["s_userindex"],
                     h["s_charidx"], h["s_usernum"], h["recipient"], h["recipient_hex"], h["r_userindex"], h["r_charidx"], h["r_uid"],
                     " ".join("%d:%s" % (c, names.get(c, "")) for c in h["codes"]),
                     " ".join("%d×%d" % (c, it[c][0]) for c in sorted(it)), " ".join("%d×%d" % (c, ev[c][0]) for c in sorted(ev)),
                     h["created_utc"], h["created_local"]])
    if not holds:
        print("Зависших заморозок старше %d мин нет." % minutes)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "gift_reconcile_%s.csv" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["order_id", "hint", "why", "age_min", "amount", "test_mode", "sender_account", "sender_name", "sender_userindex",
                    "sender_charidx", "sender_usernum", "recipient_name", "recipient_hex", "recipient_userindex", "recipient_charidx",
                    "recipient_uid", "codes", "item_after", "eventgain_cashgift", "created_utc", "created_local"])
        w.writerows(rows)
    print("")
    print("CSV: %s (%d строк)" % (path, len(rows)))

    if emit:
        known = {h["order"] for h in holds}
        print("")
        print("-- Текст для ручного применения (НЕ выполнен). Решение — через координатора; выполнять на сервере файлом sqlcmd -i.")
        print("USE [AsdaStoryLogin];")
        for order, act in emit:
            mark = "" if order in known else "   -- ВНИМАНИЕ: заказа нет в списке 'H' этой сверки"
            print("EXEC dbo.GP7_GiftSettle @order_id=%d, @action=%d;   -- %s%s" % (
                order, act, "commit" if act == 2 else "refund", mark))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
