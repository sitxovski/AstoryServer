# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_cash_gift.py — выкладка процедур UPGivenitem / UpCreateCharEventitem на Joy1 (волна cash_gift, 01.11.2026).
#   Без ключей — СУХОЙ ПРОГОН: только 01_preview (чтение). --apply: 02_backup → 03_apply → 04_verify.
#   --rollback: 05_rollback (снимает только процедуры с меткой волны) → 01_preview.
#   SQL — файлом через scp + sqlcmd -i (не в командной строке SSH). Стойку останавливать не нужно: процедуры новые,
#   DBManager их ищет по имени при каждом вызове. Источник SQL: Reports/cash_gift/sql (gen_cashgift_sql.py).
# Печатает «ГОТОВО» только если 03 вернул OK|2, а в 04 обе процедуры с нужным числом параметров и без BAD|.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import base64
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SQL_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "cash_gift", "sql"))
KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]
REMOTE = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/_backup/cashgift_sql_20261101"


def ps(cmd, timeout=600):
    """PowerShell по SSH → (код, вывод)."""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def run_sql(name):
    """Файл SQL → scp → sqlcmd -i на Joy1 → (код sqlcmd, вывод)."""
    ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % REMOTE.replace("/", "\\"), 120)
    r = subprocess.run(["scp", "-i", KEY, "-o", "BatchMode=yes", os.path.join(SQL_DIR, name), "%s:%s/%s" % (HOST, REMOTE, name)],
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        return 1, "scp: " + (r.stdout + r.stderr).decode("utf-8", "replace")
    rp = (REMOTE + "/" + name).replace("/", "\\")
    rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -h -1 -W -s '|' -i '%s' 2>&1; $c = $LASTEXITCODE; "
                 "Write-Output ($o -join \"`n\"); Write-Output (\"RC=\" + $c)" % rp)
    m = re.search(r"RC=(-?\d+)", out)
    return (int(m.group(1)) if m else 1), out


def step(name):
    """Один файл с печатью; → (ok, вывод)."""
    rc, out = run_sql(name)
    print("== %s RC=%d\n%s" % (name, rc, out[-4000:]), flush=True)
    return rc == 0, out


def main():
    """Сухой прогон / --apply / --rollback."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if "--rollback" in sys.argv:
        ok, out = step("05_rollback.sql")
        if not ok or "rollback|0 left" not in out:
            print("ОТКАЗ: откат не снял обе процедуры (чужой текст без метки не трогается)")
            return 1
        step("01_preview.sql")
        print("ГОТОВО: откат cash_gift — процедуры сняты")
        return 0
    if "--apply" not in sys.argv:
        ok, out = step("01_preview.sql")
        if not ok:
            return 1
        if re.search(r"joy1_has\|\w+\|1", out):
            print("ВНИМАНИЕ: процедура уже есть в Joy1 — 03_apply откажет; сначала разбор её текста")
        print("сухой прогон: БД не тронута; выкладка — с --apply")
        return 0
    for name in ("02_backup.sql", "03_apply.sql", "04_verify.sql"):
        ok, out = step(name)
        if not ok:
            print("ОТКАЗ: %s завершился с ошибкой (откат — --rollback)" % name)
            return 1
        if name == "03_apply.sql" and "OK|2" not in out:
            print("ОТКАЗ: 03_apply не вернул OK|2")
            return 1
        if name == "04_verify.sql" and ("BAD|" in out or out.count("mark=1") != 2):
            print("ОТКАЗ: проверка числа параметров/метки не прошла (откат — --rollback)")
            return 1
    print("ГОТОВО: cash_gift — UPGivenitem (147) и UpCreateCharEventitem (107) созданы в Joy1 и проверены")
    return 0


if __name__ == "__main__":
    sys.exit(main())
