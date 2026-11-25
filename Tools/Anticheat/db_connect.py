# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""db_connect.py - подключение к dev-БД (SQL Server @@ASTORY_SERVER_VPN_IP@@) ТОЛЬКО ДЛЯ ЧТЕНИЯ.

Основа - помощник dbq.py. Пароль (GAMEPASS) читается из PasswordSQL.txt на сервере ПО SSH (с 24.10.2026;
шара \\@@ASTORY_SERVER_HOSTNAME@@ висит без таймаута — правило владельца 22.10) и нигде не печатается и не сохраняется в
репозиторий; в процессе кэшируется на время жизни модуля. Любой запрос проходит через assert_select_only(): допускаются
только SELECT / WITH / DECLARE / SET NOCOUNT; слова INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/TRUNCATE/
EXEC/MERGE/GRANT вне строковых литералов и комментариев - отказ.

Побочных эффектов при импорте нет (pyodbc подключается лениво, внутри функций).
Использование из кода: cn = connect("JoyLog1"); cols, rows = query(cn, "SELECT ...", params)
Из консоли:  python -I db_connect.py -d JoyLog1 -Q "SELECT ..."   |   -i файл.sql
"""
import io
import os
import re
import subprocess
import sys

DEFAULT_PWFILE = "ssh:@@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\PasswordSQL.txt"   # «ssh:» — читать на сервере по SSH
DEFAULT_SERVER = "@@ASTORY_SERVER_VPN_IP@@,1433"
DEFAULT_UID = "devgsaccount"
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"                              # dev-сервер @@ASTORY_SERVER_HOSTNAME@@ (адрес с 24.10.2026)
SSH_KEY = os.path.join(os.environ.get("USERPROFILE", ""), ".ssh", "@@ASTORY_SSH_KEY_NAME@@")
SSH_TIMEOUT_S = 20                                                    # предел чтения пароля по SSH
_pw_cache = {}                                                        # путь → пароль (только в памяти процесса)

_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|MERGE|GRANT|REVOKE|DENY|BACKUP|RESTORE|SHUTDOWN)\b",
    re.I)


def _read_text(pwfile):
    """Текст файла пароля: «ssh:<путь на сервере>» — по SSH с пределом времени, иначе — локальный путь."""
    if not pwfile.startswith("ssh:"):
        with io.open(pwfile, encoding="utf-8", errors="replace") as f:
            return f.read()
    ssh = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "OpenSSH", "ssh.exe")
    if not os.path.exists(ssh):
        ssh = "ssh"
    r = subprocess.run([ssh, "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", SSH_HOST,
                        'type "%s"' % pwfile[4:]],
                       capture_output=True, timeout=SSH_TIMEOUT_S, creationflags=0x08000000)   # без окна (pythonw)
    if r.returncode != 0:
        raise RuntimeError("PasswordSQL.txt по SSH не прочитан (код %d)" % r.returncode)
    return r.stdout.decode("utf-8", "replace")


def read_password(pwfile=DEFAULT_PWFILE):
    """Читает GAMEPASS из PasswordSQL.txt (по умолчанию — с сервера по SSH), кэш на время жизни процесса."""
    if pwfile in _pw_cache:
        return _pw_cache[pwfile]
    v = _parse_password(_read_text(pwfile), pwfile)
    _pw_cache[pwfile] = v
    return v


def _parse_password(text, pwfile):
    """GAMEPASS = <значение> (кавычки по краям снимаются)."""
    for line in text.splitlines():
        m = re.match(r"^\s*GAMEPASS\s*=\s*(.*?)\s*$", line, re.I)
        if m:
            v = m.group(1)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            return v
    raise RuntimeError("GAMEPASS не найден в " + pwfile)


def assert_select_only(sql):
    """Защита от случайной записи: бросает ValueError, если в запросе есть не-SELECT."""
    s = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)       # блочные комментарии
    s = re.sub(r"--[^\n]*", " ", s)                       # строчные комментарии
    s = re.sub(r"N?'(?:[^']|'')*'", "''", s)              # строковые литералы
    m = _FORBIDDEN.search(s)
    if m:
        raise ValueError("запрещённое слово в запросе (режим только чтение): " + m.group(1))
    return True


def connect(db="Joy1", pwfile=DEFAULT_PWFILE, server=DEFAULT_SERVER, uid=DEFAULT_UID, timeout=15):
    """Открывает соединение (autocommit, ApplicationIntent=ReadOnly не гарантируется - защита выше)."""
    import pyodbc  # ленивый импорт: модуль безопасно импортировать без драйвера
    drv = [d for d in pyodbc.drivers() if "SQL Server" in d]
    if not drv:
        raise RuntimeError("нет ODBC-драйвера SQL Server")
    drv = sorted(drv, key=lambda d: ("ODBC Driver" not in d, d))[0]
    pw = read_password(pwfile).replace("}", "}}")
    cs = ("DRIVER={%s};SERVER=%s;DATABASE=%s;UID=%s;PWD={%s};TrustServerCertificate=yes"
          % (drv, server, db, uid, pw))
    return pyodbc.connect(cs, autocommit=True, timeout=timeout)


def query(cn, sql, params=()):
    """Выполняет ОДИН SELECT; возвращает (список имён столбцов, список кортежей)."""
    assert_select_only(sql)
    cur = cn.cursor()
    cur.execute(sql, params) if params else cur.execute(sql)
    if not cur.description:
        return [], []
    cols = [c[0] for c in cur.description]
    return cols, [tuple(r) for r in cur.fetchall()]


def _main(argv):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    a = list(argv)
    db = "Joy1"
    if a and a[0] == "-d":
        db = a[1]
        a = a[2:]
    if not a:
        sys.exit("use: [-d БД] -Q sql | -i файл.sql")
    if a[0] == "-i":
        sql = open(a[1], encoding="utf-8-sig").read()
    elif a[0] == "-Q":
        sql = a[1]
    else:
        sys.exit("use -i file | -Q sql")
    cn = connect(db)
    for batch in re.split(r"^\s*GO\s*$", sql, flags=re.M | re.I):
        if not batch.strip():
            continue
        cols, rows = query(cn, batch)
        if cols:
            print("|".join(cols))
            for r in rows:
                print("|".join("" if v is None else str(v) for v in r))
            print("(%d rows)" % len(rows))


if __name__ == "__main__":
    _main(sys.argv[1:])
