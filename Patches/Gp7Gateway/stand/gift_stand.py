# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""gift_stand.py — стенд подарка P101_CashGift для шлюза gp7 (01.11.2026) на СВОЁМ экземпляре LocalDB «gp7gift».

Что делает:
  1) создаёт экземпляр (localdb)\\gp7gift; файлы БД — явно в %TEMP%\\gp7gift_localdb;
  2) пересоздаёт AsdaStoryLogin (сортировка SQL_Latin1_General_CP1_CI_AS — как на живом dev, снято SELECT-ом 01.11)
     и AsdaStoryOP (Arabic_CI_AS). Схемы dbo.[user] и Us_member — по живой схеме, только нужные столбцы;
  3) дважды прогоняет ..\\install_gp7_balance.sql (идемпотентность; третий раз его выполняет сам server.js при старте);
  4) собирает две копии gp7-server в %TEMP%\\gp7gift_stand\\{normal,test}:
     - server.js, установщик, premium_item_map.json — снимок живой карты 01.11 (md5 ee54b527);
     - таблицы GameServer: SellItemTable/Function_Table/item_table — снимок живых 01.11;
     - в SellItemTable стенда дописан код 99999998 без цены (проверка gift-unknown-item-price);
  5) гоняет stand\\gift_cases.js: normal (без тестового режима), test (testFixedBalance 999999) и
     slow (02.11, ревизия В2: sqlcmd через slow_sqlcmd.exe, тайм-аут 4 с — убийство клиента ДО и ПОСЛЕ коммита);
  6) (ревизия М7) проверяет, что русские комментарии установщика легли в sys.sql_modules без кракозябр
     (установщик выполнен так же, как его выполняет server.js: sqlcmd -f 65001 -i).

Живой сервер и живые БД НЕ трогает. Запуск: python gift_stand.py <каталог снимка live> <каталог снимка таблиц GS>
  (снимки — scp живых файлов только чтением; без аргументов берутся из Reports/cash_gift/p101/stand_input).
★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                         # stand\
GW = os.path.dirname(HERE)                                                 # Gp7Gateway\
INSTANCE = "gp7gift"                                                       # свой экземпляр LocalDB
SERVER = r"(localdb)\gp7gift"                                              # имя для sqlcmd
DATA = os.path.join(os.environ.get("TEMP", HERE), "gp7gift_localdb")       # файлы БД
WORK = os.path.join(os.environ.get("TEMP", HERE), "gp7gift_stand")         # копии gp7-server
DEFAULT_INPUT = os.path.normpath(os.path.join(GW, "..", "..", "..", "Reports", "cash_gift", "p101", "stand_input"))   # снимки живых файлов
SQLCMD = r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE"   # тот же клиент, что на сервере
PORTS = {"normal": 25052, "test": 25053, "slow": 25054}                    # порты стендов
SLOW_EXE = os.path.join(HERE, "slow_sqlcmd.exe")                           # обёртка тайм-аутов (ревизия В2), исходник slow_sqlcmd.c
SLOW_FLAG = os.path.join(WORK, "slow_flag.txt")                            # файл-команда обёртки


def sq(db, query=None, path=None, utf8=False):
    """sqlcmd на стенде → (код, вывод). utf8 — файл читается как UTF-8 (-f 65001, как installSqlSchema в server.js)."""
    a = [SQLCMD, "-S", SERVER, "-E", "-C", "-b", "-h", "-1", "-W", "-s", "|", "-d", db] + (["-f", "65001"] if utf8 else [])
    a += ["-i", path] if path else ["-Q", query]
    p = subprocess.run(a, capture_output=True)
    return p.returncode, (p.stdout + p.stderr).decode("cp866", "replace")


def must(rc_out, what):
    """Останов при ошибке шага подготовки."""
    rc, out = rc_out
    if rc:
        raise SystemExit("ОШИБКА %s: %s" % (what, out))
    return out


def md5(path):
    """MD5 файла (hex, нижний регистр)."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def make_databases():
    """Экземпляр + две базы с явными файлами и сортировками как на живом dev."""
    os.makedirs(DATA, exist_ok=True)
    subprocess.run(["sqllocaldb", "create", INSTANCE, "-s"], capture_output=True)
    subprocess.run(["sqllocaldb", "start", INSTANCE], capture_output=True)
    for db, coll in (("AsdaStoryLogin", "SQL_Latin1_General_CP1_CI_AS"), ("AsdaStoryOP", "Arabic_CI_AS")):
        fn = os.path.join(DATA, "g7_" + db)
        must(sq("master", "IF DB_ID('%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s]; END; "
                "CREATE DATABASE [%s] ON (NAME=%s_d, FILENAME='%s.mdf') LOG ON (NAME=%s_l, FILENAME='%s_log.ldf') COLLATE %s;"
                % (db, db, db, db, db, fn, db, fn, coll)), "создание " + db)
    # dbo.[user] — столбцы живой схемы (id identity bigint, username/password/name/role varchar(50))
    must(sq("AsdaStoryLogin", "CREATE TABLE dbo.[user] (id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_user PRIMARY KEY, "
            "username VARCHAR(50) NOT NULL, password VARCHAR(50) NOT NULL, name VARCHAR(50) NULL, role VARCHAR(50) NOT NULL);"), "dbo.[user]")
    # Us_member — нужные столбцы живой схемы (Userindex, Us_id varchar(61) Arabic_CI_AS)
    must(sq("AsdaStoryOP", "CREATE TABLE dbo.Us_member (Userindex INT NOT NULL, Us_id VARCHAR(61) NOT NULL, us_block TINYINT NOT NULL DEFAULT 0);"
            "INSERT dbo.Us_member (Userindex, Us_id) VALUES (1001,'giftA'),(1002,'giftB'),(1003,'giftC'),(1004,'giftD');"), "Us_member")
    must(sq("AsdaStoryLogin", "INSERT dbo.[user] (username, password, name, role) VALUES "
            "('giftA', CONVERT(VARCHAR(50), NEWID()), NULL, 'GA'), ('giftB', CONVERT(VARCHAR(50), NEWID()), NULL, 'GA'), "
            "('giftD', CONVERT(VARCHAR(50), NEWID()), NULL, 'GA');"), "учётки стенда")


def install_twice():
    """Установщик два раза подряд + проверка объектов."""
    inst = os.path.join(GW, "install_gp7_balance.sql")
    for i in (1, 2):
        must(sq("AsdaStoryLogin", path=inst, utf8=True), "установщик, проход %d" % i)
        print("установщик install_gp7_balance.sql: проход %d — без ошибок" % i)
    out = must(sq("AsdaStoryLogin", "SET NOCOUNT ON; SELECT name FROM sys.objects WHERE name IN "
                  "('GP7GiftLog','GP7_GiftHold','GP7_GiftSettle','GP7_Purchase','GP7_GetBalance','GP7Balance','GP7PurchaseLog',"
                  "'UQ_GP7GiftLog_GsKey','FK_GP7GiftLog_Purchase') ORDER BY name;"), "объекты")
    names = [x.strip() for x in out.splitlines() if x.strip()]
    print("объекты после установщика: %s" % ", ".join(names))
    if len(names) != 9:
        raise SystemExit("ОШИБКА: ждали 9 объектов, есть %d" % len(names))
    must(sq("AsdaStoryLogin", "UPDATE b SET balance = CASE u.username WHEN 'giftA' THEN 20000 WHEN 'giftB' THEN 100 ELSE 0 END "
            "FROM dbo.GP7Balance b JOIN dbo.[user] u ON u.id = b.user_id; "
            "INSERT dbo.GP7Balance (user_id, balance, present) SELECT id, CASE username WHEN 'giftA' THEN 20000 WHEN 'giftB' THEN 100 ELSE 0 END, 0 "
            "FROM dbo.[user] WHERE id NOT IN (SELECT user_id FROM dbo.GP7Balance);"), "балансы")


def make_server_dir(kind, live, gs):
    """Копия gp7-server для режима kind (normal/test)."""
    d = os.path.join(WORK, kind)
    if os.path.isdir(d):
        shutil.rmtree(d)
    tables = os.path.join(WORK, "GameServer", "ItemTable_Info")
    os.makedirs(tables, exist_ok=True)
    os.makedirs(d)
    shutil.copy2(os.path.join(GW, "server.js"), d)
    shutil.copy2(os.path.join(GW, "install_gp7_balance.sql"), d)
    shutil.copy2(os.path.join(live, "premium_item_map.json"), d)
    for t in ("Function_Table.txt", "item_table.txt"):
        shutil.copy2(os.path.join(gs, t), tables)
    # SellItemTable стенда = живой + код 99999998 (без цены нигде) и шапка +1
    tok = open(os.path.join(gs, "SellItemTable.txt"), "rb").read().decode("latin1").split()
    n = int(tok[1])
    codes = tok[2:2 + n] + ["99999998"]
    with open(os.path.join(tables, "SellItemTable.txt"), "w", encoding="latin1", newline="\r\n") as f:
        f.write("%s\t%d\n" % (tok[0], n + 1) + "\n".join(codes) + "\n")
    slow = kind == "slow"
    cfg = ('{\n "host": "127.0.0.1",\n "port": %d,\n "logBytes": 256,\n "mode": "echo",\n "balanceSource": "sql",\n'
           ' "sql": { "command": %s, "server": %s, "database": "AsdaStoryLogin", "timeoutMs": %d, "migrationTimeoutMs": 60000 },\n'
           ' "balancesFile": "balances.json",\n "defaultPremiumBalance": 0,\n "defaultPremiumPresent": 0,\n "quietHeartbeat": true,\n'
           ' "heartbeatHex": "FB0A0000005D001400FE",\n "functionTable": "../GameServer/ItemTable_Info/Function_Table.txt",\n'
           ' "itemTable": "../GameServer/ItemTable_Info/item_table.txt",\n "giftSellItemTable": "../GameServer/ItemTable_Info/SellItemTable.txt"%s\n}\n'
           % (PORTS[kind], json_str(SLOW_EXE if slow else SQLCMD), json_str(SERVER), 4000 if slow else 15000,
              ',\n "testFixedBalance": 999999' if kind == "test" else ""))
    with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as f:
        f.write(cfg)
    return d


def json_str(s):
    """Строка JSON с экранированием обратных слэшей."""
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def main(argv):
    """Стенд целиком; код возврата 0 — все проверки зелёные."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    live = argv[0] if len(argv) > 0 else os.path.join(DEFAULT_INPUT, "gp7-server")
    gs = argv[1] if len(argv) > 1 else os.path.join(DEFAULT_INPUT, "ItemTable_Info")
    print("снимок карты: %s md5 %s" % (os.path.join(live, "premium_item_map.json"), md5(os.path.join(live, "premium_item_map.json"))))
    print("server.js стенда: md5 %s" % md5(os.path.join(GW, "server.js")))
    make_databases()
    install_twice()
    rc_all = 0
    out = must(sq("AsdaStoryLogin", "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.sql_modules WHERE object_id = OBJECT_ID('dbo.GP7_GiftHold') "
                  "AND definition LIKE N'%подарок себе%';"), "комментарии установщика")
    good = out.strip().splitlines()[-1].strip() == "1"
    print("(ревизия М7) комментарии P101 в sys.sql_modules читаются по-русски: %s" % ("да" if good else "НЕТ"))
    rc_all = 0 if good else 1
    env = dict(os.environ, REAL_SQLCMD=SQLCMD, SLOW_SQL_FLAG=SLOW_FLAG)
    for kind in ("normal", "test", "slow"):
        d = make_server_dir(kind, live, gs)
        if os.path.exists(SLOW_FLAG):
            os.remove(SLOW_FLAG)
        p = subprocess.run(["node", os.path.join(HERE, "gift_cases.js"), d, str(PORTS[kind]), SERVER, kind],
                           capture_output=True, timeout=900, env=env)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        print(out)
        logs = os.path.join(d, "logs")
        mig = [ln for f in sorted(os.listdir(logs)) for ln in open(os.path.join(logs, f), encoding="utf-8") if "SQL_MIGRATION" in ln]
        print("[%s] установщик при старте server.js: %s" % (kind, mig[0].strip() if mig else "НЕТ строки"))
        if p.returncode or not mig or "SQL_MIGRATION_OK" not in mig[0]:
            rc_all = 1
    print("СТЕНД OK" if rc_all == 0 else "СТЕНД: ЕСТЬ ПРОВАЛЫ")
    return rc_all


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
