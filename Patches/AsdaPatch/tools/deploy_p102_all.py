# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p102_all.py — ЕДИНАЯ выкладка P102 для restart_stack.py (04.11.2026, слово владельца «proceed P102»; разбор
#   Reports/item_dedup/P102_REPORT.md). Порядок при ОСТАНОВЛЕННОЙ стойке (--apply, зовёт restart_stack.py):
#   1) deploy_p102.py --apply                  — AsdaPatch v59 (P01…P102) во все GS; секцию [P102_DefectFixes] (Enabled=1, Sites=31)
#                                                и Version 58 → 59 DLL допишет сама при старте;
#   2) deploy_p100_sites.py --apply --rollback — [P100_ChargeStack] Sites -32769 → -1 (бит 15 «аукцион» снова включён: ошибку
#                                                цепочки afterSlot исправляет P102 / P100 R_B5BUYEQ·R_B5DELEQ);
#   3) SQL Joy1 (Reports/item_dedup/p102_sql): 02_backup («BACKUP OK|4») → 03_apply («APPLY OK») → 04_verify («VERIFY OK|4»)
#      — 4 строки спецпредметов с Amount 0: камни 401/363 → 1, свиток 205 → 5.
#   «ГОТОВО» — только если чисты все шаги. Любой провал — стоп с перечнем сделанного и командами отката.
# Без --apply — СУХОЙ ПРОГОН (ничего не пишет): сухие прогоны шагов 1 и 2 (--rollback), md5 SQL-файлов, на Joy1 только SELECT:
#   копии Item_bak_p102_20261104 ещё нет, 4 строки на месте с Amount 0.
#   deploy_p102.py --rollback.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PORT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
SQL_DIR = os.path.join(PORT, "Reports", "item_dedup", "p102_sql")
SQL_FILES = ["02_backup.sql", "03_apply.sql", "04_verify.sql"]
REMOTE = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/_backup/p102_sql_20261104"
BAK_TABLE = "Item_bak_p102_20261104"
ROWS = [(75209, 10, 1, 17, 205), (75232, 10, 1, 14, 205), (75210, 10, 1, 19, 401), (75237, 10, 1, 1, 363)]


def sub(script, args):
    """Подскрипт этой папки с ключами → (успех, вывод). Успех: код 0 и «ГОТОВО» при --apply, без «ОТКАЗ»/«СТОП» в сухом прогоне."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + args, capture_output=True, env=env, timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    if "--apply" in args:
        return p.returncode == 0 and "ГОТОВО" in out, out
    return p.returncode == 0 and "ОТКАЗ" not in out and "СТОП" not in out, out


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def rows_where():
    """Условие WHERE на 4 строки ремонта (Amount 0)."""
    parts = []
    for ui, ch, pl, px, code in ROWS:
        parts.append("(Userindex=%d AND Charidx=%d AND Plate=%d%s AND Code=%d AND Amount=0)"
                     % (ui, ch, pl, "" if px is None else " AND Posx=%d" % px, code))
    return " OR ".join(parts)


def run_sql(name):
    """Файл SQL из SQL_DIR → scp в свою папку REMOTE (не в папку F1) → sqlcmd -i на Joy1 → (код, вывод)."""
    from deploy_f1_p100 import ps, sqlcmd, KEY, HOST
    ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % REMOTE.replace("/", "\\"), 120)
    r = subprocess.run(["scp", "-i", KEY, "-o", "BatchMode=yes", os.path.join(SQL_DIR, name), "%s:%s/%s" % (HOST, REMOTE, name)],
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        return 1, "scp: " + (r.stdout + r.stderr).decode("utf-8", "replace")
    return sqlcmd("-i '%s'" % (REMOTE + "/" + name).replace("/", "\\"))


def value(lines):
    """Значение однострочного SELECT из вывода sqlcmd по SSH: ПОСЛЕДНЯЯ строка — это CLIXML прогресса PowerShell, а не ответ;
    берётся последняя строка, не начинающаяся с «#<» / «<» (None — значения нет)."""
    vals = [l for l in lines if not l.startswith("#<") and not l.startswith("<")]
    return vals[-1] if vals else None


def dry_run():
    """Сухой прогон всех шагов (только чтение); True — всё готово к --apply."""
    from deploy_f1_p100 import query
    good = True
    for script, args in (("deploy_p102.py", []), ("deploy_p100_sites.py", ["--rollback"])):
        ok, out = sub(script, args)
        print("== %s %s — %s\n%s" % (script, " ".join(args), "OK" if ok else "ОТКАЗ", out[-4000:]), flush=True)
        good = good and ok
    for n in SQL_FILES + ["01_preview.sql", "05_rollback.sql"]:
        p = os.path.join(SQL_DIR, n)
        print("  SQL %s %s" % (n, md5(p) if os.path.exists(p) else "НЕТ ФАЙЛА"))
        good = good and os.path.exists(p)
    rc, lines = query("SELECT CASE WHEN OBJECT_ID('Joy1.dbo.%s') IS NULL THEN 'NOBAK' ELSE 'HASBAK' END" % BAK_TABLE)
    v = value(lines)
    print("  копия %s: %s" % (BAK_TABLE, v))
    good = good and rc == 0 and v == "NOBAK"
    rc, lines = query("SELECT COUNT(*) FROM Joy1.dbo.Item WHERE %s" % rows_where())
    v = value(lines)
    print("  строк ремонта на месте (Amount 0): %s (ждём 4)" % v)
    good = good and rc == 0 and v == "4"
    print("СУХОЙ ПРОГОН: %s" % ("всё готово к --apply (restart_stack.py --deploy deploy_p102_all.py)" if good else "ЕСТЬ ОТКАЗЫ — смотри выше"))
    return good


def apply():
    """Выкладка по шагам; True — всё чисто."""
    done = []

    def fail(msg):
        print("ОТКАЗ: %s" % msg)
        print("сделано до отказа: %s" % (", ".join(done) or "ничего"))
        print("откат (только выполненные шаги, в обратном порядке): p102_sql/05_rollback.sql; deploy_p100_sites.py --apply; "
              "deploy_p102.py --rollback")
        return False

    for script, args in (("deploy_p102.py", ["--apply"]), ("deploy_p100_sites.py", ["--apply", "--rollback"])):
        ok, out = sub(script, args)
        print(out[-6000:], flush=True)
        if not ok:
            return fail("%s %s не напечатал ГОТОВО" % (script, " ".join(args)))
        done.append(script)
    want = {"02_backup.sql": r"(^|\n)\s*BACKUP OK\|4\s*($|\n)", "03_apply.sql": r"(^|\n)\s*APPLY OK\s*($|\n)",
            "04_verify.sql": r"(^|\n)\s*VERIFY OK\|4\s*($|\n)"}
    for n in SQL_FILES:
        rc, out = run_sql(n)
        print("== %s RC=%d\n%s" % (n, rc, out[-4000:]), flush=True)
        if rc != 0 or not re.search(want[n], out):
            return fail("%s: RC=%d или нет строки-итога" % (n, rc))
        done.append(n)
    print("ГОТОВО: P102 — AsdaPatch v59 во всех GS, [P100_ChargeStack] Sites=-1 (бит 15 включён), SQL ремонта 4 строк применён и проверен")
    return True


def main():
    """Точка входа: сухой прогон или --apply."""
    sys.stdout.reconfigure(encoding="utf-8")
    if "--apply" in sys.argv:
        return 0 if apply() else 1
    return 0 if dry_run() else 1


if __name__ == "__main__":
    sys.exit(main())
