# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""reconcile_stand.py — стенд инструмента tools/gift_reconcile.py (01.11.2026) на своём LocalDB «gp7gift».

Запускать ПОСЛЕ gift_stand.py: нужна AsdaStoryLogin с установщиком P101. Стенд:
  - пересоздаёт у себя Joy1 и JoyLog1 (Arabic_CI_AS) по снимку живых схем
    Reports/cash_gift/tools/live_schemas.txt (Item / Charinfo / EventGainItem);
  - заводит получателей и заморозки 'H' возрастом 30 минут:
    - (ревизия В3) журнал от РАНЕЕ созданного подарка тому же получателю тем же кодом → неясно; журнал вне окна → refund;
    - (ревизия М8) имя у двух персонажей по коллации — выбирается байт-в-байт; два байт-в-байт — неясно;
    - выдано полностью в окне → commit;
    - ничего → refund;
    - частично → неясно;
    - получателя нет → неясно;
  - добавляет свежую заморозку: в выборку старше 10 минут она попасть не должна;
  - гоняет gift_reconcile.py --local … --emit-sql и сверяет подсказки, CSV и текст EXEC;
  - проверяет, что инструмент ничего не изменил: состояние и балансы до и после совпадают.
Живые сервер и БД не трогает. ★ tools-no-import-side-effects: при импорте ничего не делает.
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                                        # stand\
TOOL = os.path.normpath(os.path.join(HERE, "..", "tools", "gift_reconcile.py"))           # проверяемый инструмент
SCHEMAS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "cash_gift", "tools", "live_schemas.txt"))   # снимок схем
SERVER = r"(localdb)\gp7gift"                                                            # свой экземпляр
DATA = os.path.join(os.environ.get("TEMP", HERE), "gp7gift_localdb")                     # файлы БД
OUT = os.path.join(os.environ.get("TEMP", HERE), "gp7gift_reconcile_out")                # CSV стенда

ok = 0     # пройдено
bad = 0    # провалено


def check(cond, msg):
    """Одна проверка."""
    global ok, bad
    print("  [%s] %s" % ("OK" if cond else "!!", msg))
    if cond:
        ok += 1
    else:
        bad += 1


def sq(db, query):
    """sqlcmd → вывод (останов при ошибке)."""
    p = subprocess.run(["sqlcmd", "-S", SERVER, "-E", "-C", "-b", "-h", "-1", "-W", "-s", "|", "-d", db, "-Q", "SET NOCOUNT ON; " + query],
                       capture_output=True)
    out = (p.stdout + p.stderr).decode("cp866", "replace")
    if p.returncode:
        raise SystemExit("ОШИБКА SQL [%s]: %s\n%s" % (db, query[:300], out))
    return [x.strip() for x in out.splitlines() if x.strip()]


def schema(db, tbl):
    """Столбцы и PK из снимка: ([(имя, тип, len, nullable, default)], pk)."""
    cols, pk = [], ""
    for ln in open(SCHEMAS, encoding="utf-8", errors="replace"):
        f = ln.rstrip("\r\n").split("|")
        if len(f) == 4 and f[0] == "PK" and f[1] == db and f[2].lower() == tbl.lower():
            pk = f[3]
        elif len(f) >= 9 and f[0] == db and f[1].lower() == tbl.lower():
            cols.append((f[2], f[3], f[4], f[7] == "1", f[8]))
    return cols, pk


def ddl(db, tbl):
    """CREATE TABLE по снимку."""
    cols, pk = schema(db, tbl)
    parts = []
    for n, t, ml, nl, df in cols:
        tt = t + ("(%s)" % ("MAX" if int(ml) < 0 else ml) if t in ("varchar", "char", "varbinary", "binary") else "")
        parts.append("[%s] %s %s%s" % (n, tt, "NULL" if nl else "NOT NULL", (" DEFAULT " + df) if df else ""))
    if pk:
        parts.append("PRIMARY KEY CLUSTERED (%s)" % pk)
    return "CREATE TABLE %s (%s);" % (tbl, ", ".join(parts))


def insert(db, tbl, values):
    """INSERT строки: заданные столбцы из values, остальные NOT NULL — нулём / '' / GETDATE() / NEWID()."""
    cols, _ = schema(db, tbl)
    names, vals = [], []
    for n, t, _ml, nl, _df in cols:
        if n in values:
            v = values[n]
        elif nl:
            continue
        elif t in ("varchar", "char"):
            v = "''"
        elif t == "datetime":
            v = "GETDATE()"
        elif t == "uniqueidentifier":
            v = "NEWID()"
        else:
            v = "0"
        names.append("[%s]" % n)
        vals.append(str(v))
    sq(db, "INSERT %s (%s) VALUES (%s);" % (tbl, ", ".join(names), ", ".join(vals)))


def hold(name_hex, codes, amount, key):
    """Заморозка от giftA прямо процедурой → order_id."""
    c = (codes + [0] * 7)[:7]
    r = sq("AsdaStoryLogin", "EXEC dbo.GP7_GiftHold @username='giftA', @gs_key=0x%s, @userindex=1001, @charidx=1, @usernum=11, "
           "@sender_name=0x416C696365, @recipient_name=0x%s, @code1=%d, @code2=%d, @code3=%d, @code4=%d, @code5=%d, @code6=%d, @code7=%d, "
           "@amount=%d;" % ((key, name_hex) + tuple(c) + (amount,)))[0].split("|")
    if r[4] != "ok":
        raise SystemExit("ОШИБКА заморозки: %s" % r)
    return int(r[3])


def main():
    """Стенд целиком."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    for db in ("Joy1", "JoyLog1"):
        fn = os.path.join(DATA, "g7_" + db)
        sq("master", "IF DB_ID('%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s]; END; "
           "CREATE DATABASE [%s] ON (NAME=%s_d, FILENAME='%s.mdf') LOG ON (NAME=%s_l, FILENAME='%s_log.ldf') COLLATE Arabic_CI_AS;"
           % (db, db, db, db, db, fn, db, fn))
    sq("Joy1", ddl("Joy1", "dbo.Item"))
    sq("Joy1", ddl("Joy1", "dbo.Charinfo"))
    sq("JoyLog1", ddl("JoyLog1", "dbo.EventGainItem"))
    sq("AsdaStoryLogin", "UPDATE b SET balance = 100000 FROM dbo.GP7Balance b JOIN dbo.[user] u ON u.id=b.user_id WHERE u.username='giftA';")
    sq("AsdaStoryLogin", "UPDATE dbo.GP7GiftLog SET state='C', settled_at=SYSUTCDATETIME() WHERE state='H';")   # хвосты gift_stand — закрыть

    # имя → (Userindex, Charidx); Dupe/DUPE — одно имя по Arabic_CI_AS, разные байты; Dupe2 — два персонажа с одинаковыми байтами
    recv = {"RecvYes": (2001, 0), "RecvNo": (2002, 1), "RecvPart": (2003, 0), "RecvOld": (2004, 0), "RecvTwin": (2005, 0),
            "RecvLate": (2006, 0), "Dupe": (2007, 0), "DUPE": (2008, 0)}
    for n, (ui, ci) in recv.items():
        insert("Joy1", "dbo.Charinfo", {"Userindex": ui, "Charidx": ci, "Uid": "'acc_%s'" % n.lower(), "Charname": "'%s'" % n})
    for ui in (2009, 2010):
        insert("Joy1", "dbo.Charinfo", {"Userindex": ui, "Charidx": 0, "Uid": "'acc_dupe2_%d'" % ui, "Charname": "'Dupe2'"})
    hexname = lambda s: s.encode("latin1").hex().upper()
    o_yes = hold(hexname("RecvYes"), [62728, 62728, 30], 1770, "AA00000000000001")
    o_no = hold(hexname("RecvNo"), [63103], 790, "AA00000000000002")
    o_part = hold(hexname("RecvPart"), [62728, 30], 1380, "AA00000000000003")
    o_ghost = hold(hexname("Ghost"), [62728], 390, "AA00000000000004")
    o_old = hold(hexname("RecvOld"), [62728], 390, "AA00000000000006")
    o_twin_x = hold(hexname("RecvTwin"), [62728], 390, "AA00000000000007")   # отправлен раньше и ВЫДАН (закроем 'C')
    o_twin_y = hold(hexname("RecvTwin"), [62728], 390, "AA00000000000008")   # тот же код тому же получателю через 1 с, завис
    o_late = hold(hexname("RecvLate"), [62728], 390, "AA00000000000009")     # журнал CashGift через 10 мин — вне окна
    o_dupe = hold(hexname("Dupe"), [62728], 390, "AA0000000000000A")         # два персонажа по коллации, один байт в байт
    o_dupe2 = hold(hexname("Dupe2"), [62728], 390, "AA0000000000000B")       # два персонажа байт в байт — неоднозначно
    o_fresh = hold(hexname("RecvNo"), [62728], 390, "AA00000000000005")
    aged = (o_yes, o_no, o_part, o_ghost, o_old, o_twin_x, o_twin_y, o_late, o_dupe, o_dupe2)
    sq("AsdaStoryLogin", "UPDATE dbo.GP7GiftLog SET created_at = DATEADD(minute, -30, SYSUTCDATETIME()) WHERE order_id IN (%s);"
       % ",".join(map(str, aged)))
    sq("AsdaStoryLogin", "UPDATE dbo.GP7GiftLog SET created_at = DATEADD(second, 1, created_at) WHERE order_id = %d;" % o_twin_y)
    sq("AsdaStoryLogin", "UPDATE dbo.GP7GiftLog SET state = 'C', settled_at = SYSUTCDATETIME() WHERE order_id = %d;" % o_twin_x)
    # местное время заморозки (как пишет UPGivenitem: GETDATE()) = UTC заказа + сдвиг сервера, плюс sec секунд
    loc = lambda order, sec: ("(SELECT DATEADD(second, %d, DATEADD(minute, DATEDIFF(minute, SYSUTCDATETIME(), SYSDATETIME()), created_at)) "
                              "FROM AsdaStoryLogin.dbo.GP7GiftLog WHERE order_id = %d)" % (sec, order))
    # RecvYes: подарок выдан (UPGivenitem) через 10 с после заморозки: ячейки + EventGainItem на каждую
    for posx, code in enumerate((62728, 62728, 30)):
        insert("Joy1", "dbo.Item", {"Userindex": 2001, "Charidx": 0, "Plate": 1, "Posx": posx, "Code": code, "Amount": 1,
                                    "Fdate": loc(o_yes, 10)})
        insert("JoyLog1", "dbo.EventGainItem", {"Edate": loc(o_yes, 10), "Userindex": 2001, "Charidx": 0, "Code": code, "Amount": 1,
                                                "Ramount": 1, "State": "'CashGift'"})
    # RecvPart: только ячейка 62728, журнала нет
    insert("Joy1", "dbo.Item", {"Userindex": 2003, "Charidx": 0, "Plate": 1, "Posx": 0, "Code": 62728, "Amount": 1, "Fdate": "GETDATE()"})
    # RecvOld: 62728 лежит давно (Fdate и GainDate за час ДО заморозки) — не должно считаться выдачей
    insert("Joy1", "dbo.Item", {"Userindex": 2004, "Charidx": 0, "Plate": 1, "Posx": 0, "Code": 62728, "Amount": 1,
                                "Fdate": "DATEADD(minute,-90,GETDATE())", "GainDate": "DATEADD(minute,-90,GETDATE())"})
    # RecvNo: ничего; плюс чужая запись EventGainItem другим State — не должна считаться
    insert("JoyLog1", "dbo.EventGainItem", {"Edate": "GETDATE()", "Userindex": 2002, "Charidx": 1, "Code": 63103, "Amount": 1,
                                            "Ramount": 1, "State": "'CreateCharEvent'"})
    # RecvTwin (ревизия В3): выдан подарок X (через 2 с после X) — журнал виден и для зависшего Y
    insert("JoyLog1", "dbo.EventGainItem", {"Edate": loc(o_twin_x, 2), "Userindex": 2005, "Charidx": 0, "Code": 62728, "Amount": 1,
                                            "Ramount": 1, "State": "'CashGift'"})
    # RecvLate (ревизия В3): журнал CashGift через 10 мин после заморозки — вне окна ±180 с, не выдача ЭТОГО подарка
    insert("JoyLog1", "dbo.EventGainItem", {"Edate": loc(o_late, 600), "Userindex": 2006, "Charidx": 0, "Code": 62728, "Amount": 1,
                                            "Ramount": 1, "State": "'CashGift'"})
    # Dupe (ревизия М8): журнал у персонажа с байтами «Dupe» (2007), у «DUPE» (2008) — ничего
    insert("JoyLog1", "dbo.EventGainItem", {"Edate": loc(o_dupe, 5), "Userindex": 2007, "Charidx": 0, "Code": 62728, "Amount": 1,
                                            "Ramount": 1, "State": "'CashGift'"})

    snap = lambda: sq("AsdaStoryLogin", "SELECT CAST(order_id AS VARCHAR)+state FROM dbo.GP7GiftLog ORDER BY order_id") + \
        sq("AsdaStoryLogin", "SELECT CAST(user_id AS VARCHAR)+':'+CAST(balance AS VARCHAR) FROM dbo.GP7Balance ORDER BY user_id") + \
        sq("AsdaStoryLogin", "SELECT COUNT(*) FROM dbo.GP7PurchaseLog")
    before = snap()
    os.makedirs(OUT, exist_ok=True)
    for f in glob.glob(os.path.join(OUT, "*.csv")):
        os.remove(f)
    p = subprocess.run([sys.executable, TOOL, "--local", SERVER, "--out", OUT, "--emit-sql", "%d:commit,%d:refund" % (o_yes, o_no)],
                       capture_output=True)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    print(out)
    check(p.returncode == 0, "инструмент завершился с кодом 0")

    def block(order):
        """Текст блока заказа в выводе."""
        i = out.find("заказ %d " % order)
        return out[i:out.find("\nзаказ ", i + 1) if out.find("\nзаказ ", i + 1) > 0 else len(out)] if i >= 0 else ""
    check("[вероятно выдано → commit]" in block(o_yes), "заказ %d (всё выдано в окне, журнал CashGift) → commit" % o_yes)
    check("[не выдано → refund]" in block(o_no), "заказ %d (ничего; чужой State не считается) → refund" % o_no)
    check("[неясно]" in block(o_part), "заказ %d (ячейка есть, журнала нет) → неясно" % o_part)
    check("[неясно]" in block(o_ghost) and "НЕ НАЙДЕН" in block(o_ghost), "заказ %d (получателя нет) → неясно" % o_ghost)
    check("[не выдано → refund]" in block(o_old), "заказ %d (предмет лежал ДО заморозки) → refund" % o_old)
    check(("заказ %d " % o_fresh) not in out, "свежая заморозка %d (моложе 10 мин) в выборку не попала" % o_fresh)
    check("другой подарок в окне" not in block(o_no), "у %d свежая заморозка с ДРУГИМ кодом тому же получателю не считается" % o_no)
    check(("заказ %d " % o_twin_x) not in out, "выданный (C) заказ %d в выборку не попал" % o_twin_x)
    check("[неясно]" in block(o_twin_y) and ("заказ %d, state C" % o_twin_x) in block(o_twin_y),
          "В3: заказ %d — журнал от РАНЕЕ созданного %d тому же получателю тем же кодом → неясно, X назван" % (o_twin_y, o_twin_x))
    check("[не выдано → refund]" in block(o_late), "В3: заказ %d — журнал CashGift через 10 мин вне окна → refund, не commit" % o_late)
    check("[вероятно выдано → commit]" in block(o_dupe) and "UserIndex 2007" in block(o_dupe) and "из 2 с этим именем" in block(o_dupe),
          "М8: заказ %d — «Dupe»/«DUPE» по коллации, выбран байт-в-байт 2007 → commit" % o_dupe)
    check("[неясно]" in block(o_dupe2) and "НЕОДНОЗНАЧНО: 2" in block(o_dupe2), "М8: заказ %d — два «Dupe2» байт в байт → неясно" % o_dupe2)
    check("EXEC dbo.GP7_GiftSettle @order_id=%d, @action=2;" % o_yes in out and
          "EXEC dbo.GP7_GiftSettle @order_id=%d, @action=3;" % o_no in out, "--emit-sql печатает EXEC commit/refund")
    csvs = glob.glob(os.path.join(OUT, "gift_reconcile_*.csv"))
    rows = open(csvs[0], encoding="utf-8-sig").read().splitlines() if csvs else []
    check(len(csvs) == 1 and len(rows) == 10, "CSV: 1 файл, шапка + 9 строк (%s)" % (len(rows) - 1 if rows else "нет"))
    check(snap() == before, "инструмент ничего не изменил (state, балансы, число строк журнала — как до запуска)")
    print("ИТОГ reconcile_stand ok=%d bad=%d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
