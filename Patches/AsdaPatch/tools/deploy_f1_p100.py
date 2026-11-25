# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_f1_p100.py — ЕДИНАЯ выкладка для restart_stack.py (решение владельца 01.11.2026: один рестарт):
#   дедупликация предметов, волна F1 (Reports/item_dedup/stage2/DEPLOY_F1.md) + P100_ChargeStack (заряды спецпредметов,
#   Reports/item_dedup/charges/P100_PROJECT.md): серверные таблицы + карта шлюза gp7, AsdaPatch.dll v57 + ConfigSet\charge_groups.txt,
# Порядок при ОСТАНОВЛЕННОЙ стойке (--apply, зовёт restart_stack.py):
#   0) PRE_DEPLOY — чужие выкладки того же рестарта, которые должны лечь ДО F1 (их файлы — база для манифеста F1); каждая --apply → «ГОТОВО»;
#   1) deploy_item_dedup.py --apply  — 19 таблиц 3 GS + premium_item_map.json (сверка «живой = снимок» по каждому файлу);
#   2) deploy_p100.py --apply        — DLL 985eac7d + charge_groups.txt + patches.ini на 3 GS;
#   3) SQL F1  (stage2/sql_f1):      02_backup → 03_apply («OK|») → 04_verify (ни одного dup_left > 0);
#      12_stack_apply («OK») → 13_stack_verify (V1/V3/V6 = 0, V2: копия − снято = сейчас, V4/V5: сейчас ≤ копии).
#   «ГОТОВО» — только если все шаги чистые. Любой провал — стоп с перечнем сделанного и командами отката.
# Без --apply — СУХОЙ ПРОГОН (ничего не пишет): gen_charge_groups --check (живая FT), сухие прогоны PRE/F1/P100, md5 SQL-файлов
#   со списком ниже, на Joy1 только SELECT: копий *_bak_dedup_20261101b / AsdaProcBak_p100_20261101 / Item_bak_charge_20261101 /
# Откат: deploy_item_dedup.py --rollback; deploy_p100.py --rollback; SQL — 19_stack_rollback → 09_rollback_procs → sql_f1/05_rollback.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import base64
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
SQL_F1 = os.path.join(PORT, "Reports", "item_dedup", "stage2", "sql_f1")
SQL_P100 = os.path.join(PORT, "AstoryServer", "SQL", "p100_charge_stack")
KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]
REMOTE = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/_backup/f1_p100_sql_20261102"
# чужие выкладки этого же рестарта, которые ложатся ДО F1 (имя скрипта в этой папке, манифест «база → новый»):
#   deploy_premium_boxes.py — коробка 79935 «Зелье повышения уровня» (сессия levelup_potion, 02.11): item_table, SowelCombine,
#   PackageItem_Table ×3 GS и premium_item_map.json (ключ 558 → 79935). F1 собран ПОВЕРХ её новых файлов.
PRE_DEPLOY = [("deploy_premium_boxes.py", os.path.join(HERE, "data_premium_boxes", "manifest.json"))]
F1_MANIFEST = os.path.join(PORT, "Reports", "item_dedup", "stage2", "srv_md5.tsv")
# SQL-файлы: (папка, имя, ключи sqlcmd). F1 — как выкладывали этап 2 (без -I); P100 — с -I (QUOTED_IDENTIFIER, README).
F1_FILES = ["02_backup.sql", "03_apply.sql", "04_verify.sql"]
P100_FILES = ["00_charge_groups.sql", "01_backup_procs.sql", "02_alter_procs.sql", "11_stack_backup.sql", "12_stack_apply.sql",
              "13_stack_verify.sql"]
NEW_TABLES = ["Item_bak_dedup_20261101b", "AsdaProcBak_p100_20261101", "Item_bak_charge_20261101", "CharSlot_bak_charge_20261101",
              "Item_chargeDel_20261101", "AsdaChargeGroup"]


def ps(cmd, timeout=1800):
    """PowerShell по SSH → (код, вывод)."""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def sqlcmd(args, timeout=3600):
    """sqlcmd на сервере с выводом UTF-8 → (код sqlcmd, вывод)."""
    rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -h -1 -W -s '|' %s 2>&1; $c = $LASTEXITCODE; "
                 "Write-Output ($o -join \"`n\"); Write-Output (\"RC=\" + $c)" % args, timeout)
    m = re.search(r"RC=(-?\d+)", out)
    return (int(m.group(1)) if m else 1), out


def run_sql(folder, name, quoted):
    """Файл SQL → scp → sqlcmd -i на Joy1 → (код, вывод)."""
    ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % REMOTE.replace("/", "\\"), 120)
    r = subprocess.run(["scp", "-i", KEY, "-o", "BatchMode=yes", os.path.join(folder, name), "%s:%s/%s" % (HOST, REMOTE, name)],
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        return 1, "scp: " + (r.stdout + r.stderr).decode("utf-8", "replace")
    return sqlcmd("%s-i '%s'" % ("-I " if quoted else "", (REMOTE + "/" + name).replace("/", "\\")))


def query(sql):
    """Однострочный SELECT на Joy1 (только чтение) → (код, строки вывода)."""
    rc, out = sqlcmd("-Q \"SET NOCOUNT ON; %s\"" % sql.replace('"', '""'), 300)
    return rc, [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("RC=")]


def sub(script, apply):
    """Подскрипт этой папки (--apply при выкладке) → (успех, вывод). Успех: код 0 и, при выкладке, «ГОТОВО» в выводе."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + (["--apply"] if apply else []), capture_output=True, env=env,
                       timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    ok = p.returncode == 0 and ("ГОТОВО" in out if apply else "ОТКАЗ" not in out)
    return ok, out


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def check_13(out):
    """Разбор 13_stack_verify: список нарушений (пустой — чисто)."""
    bad = []
    for ln in out.splitlines():
        p = [x.strip() for x in ln.split("|")]
        if not p or not p[0][:2] in ("V1", "V2", "V3", "V4", "V5", "V6"):
            continue
        nums = [int(x) for x in p[1:] if re.fullmatch(r"-?\d+", x)]
        tag = p[0][:2]
        if tag in ("V1", "V3", "V6") and (not nums or nums[0] != 0):
            bad.append(ln)
        elif tag == "V2" and (len(nums) != 3 or nums[0] - nums[1] != nums[2]):
            bad.append(ln)
        elif tag in ("V4", "V5") and (len(nums) != 2 or nums[1] > nums[0]):
            bad.append(ln)
    if not any(l.strip().startswith("V1") for l in out.splitlines()):
        bad.append("нет строк V1…V6 в выводе")
    return bad


def proc_md5_expected():
    """Ожидаемые md5 живых процедур P100 (снимок) — из 01_backup_procs.sql (пары (N'имя', 0x…))."""
    s = open(os.path.join(SQL_P100, "01_backup_procs.sql"), encoding="utf-8-sig").read()
    return {n: h.lower() for n, h in re.findall(r"\(N'(\w+)',\s*0x([0-9A-Fa-f]{32})\)", s)}


def f1_against_pre():
    """Сухая сверка манифеста F1 с учётом PRE: живой md5 = «живой» F1, либо файл в манифесте PRE с живым = база PRE и
    «живой» F1 = новый PRE (его запишет PRE до F1). Плюс локальные новые файлы F1 = манифест. → (успех, строки отчёта)."""
    import csv
    import json
    import srv_io
    pre = {}
    for _, mpath in PRE_DEPLOY:
        for rel, v in json.load(open(mpath, encoding="utf-8"))["files"].items():
            pre[rel.replace("/", "\\")] = (v["base"], v["new"])
    rows = list(csv.DictReader(open(F1_MANIFEST, encoding="utf-8", newline=""), delimiter="\t"))
    out_dir = os.path.join(os.path.dirname(F1_MANIFEST), "srv_out")
    bad, lines = 0, []
    for r in rows:
        rel = r["file"]
        local = md5(os.path.join(out_dir, rel))
        live = srv_io.live_md5(rel)
        if local != r["md5_new"]:
            state, bad = "ЛОКАЛЬНЫЙ НОВЫЙ ≠ МАНИФЕСТ", bad + 1
        elif live == r["md5_live"]:
            state = "живой = снимок"
        elif rel in pre and live == pre[rel][0] and r["md5_live"] == pre[rel][1]:
            state = "живой = база PRE, F1 ждёт новый PRE"
        else:
            state, bad = "ЖИВОЙ РАСХОДИТСЯ (%s)" % live[:8], bad + 1
        lines.append("    %-58s %s" % (rel, state))
    return bad == 0, ["F1: файлов %d" % len(rows)] + lines


def dry_run():
    """Сухой прогон всех шагов; True — всё готово к --apply."""
    ok_all = True
    ok, lines = f1_against_pre()
    ok_all &= ok
    print("[%s] F1 сервер (с учётом PRE)" % ("OK" if ok else "ОТКАЗ"))
    if not ok:
        print("\n".join(lines))
    for name, script in [("ключи P100 (живая FT)", "gen_charge_groups.py --check")] + \
            [("PRE " + s, s) for s, _ in PRE_DEPLOY] + [("P100 DLL", "deploy_p100.py")]:
        parts = script.split()
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        p = subprocess.run([sys.executable, os.path.join(HERE, parts[0])] + parts[1:], capture_output=True, env=env, timeout=3600)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        ok = p.returncode == 0 and "ОТКАЗ" not in out and "ИЗМЕНИЛСЯ" not in out
        ok_all &= ok
        print("[%s] %s" % ("OK" if ok else "ОТКАЗ", name))
        if not ok:
            print(out[-3000:])
    for folder, files in ((SQL_F1, F1_FILES), (SQL_P100, P100_FILES)):
        for n in files:
            p = os.path.join(folder, n)
            print("    %s %s" % (md5(p) if os.path.isfile(p) else "НЕТ ФАЙЛА", os.path.relpath(p, PORT)))
            ok_all &= os.path.isfile(p)
    rc, rows = query("SELECT CONCAT(t.n, '|', CASE WHEN OBJECT_ID('dbo.' + t.n) IS NULL THEN 0 ELSE 1 END) FROM (VALUES %s) t(n)"
                     % ",".join("('%s')" % t for t in NEW_TABLES))
    exist = [r for r in rows if r.endswith("|1")]
    ok = rc == 0 and len([r for r in rows if r.endswith(("|0", "|1"))]) == len(NEW_TABLES) and not exist
    ok_all &= ok
    print("[%s] Joy1: новых таблиц ещё нет (%d проверено)%s" % ("OK" if ok else "ОТКАЗ", len(NEW_TABLES), " — уже есть: %s" % exist if exist else ""))
    want = proc_md5_expected()
    rc, rows = query("SELECT CONCAT(o.name, '|', CONVERT(VARCHAR(34), HASHBYTES('MD5', OBJECT_DEFINITION(o.object_id)), 2)) FROM sys.objects o "
                     "WHERE o.type = 'P' AND o.name IN (%s)" % ",".join("N'%s'" % n for n in want))
    live = {}
    for r in rows:
        if "|" in r:
            n, h = r.split("|", 1)
            live[n] = h.lower()
    diff = sorted(n for n in want if live.get(n) != want[n])
    ok = rc == 0 and len(want) >= 16 and not diff        # число процедур — по списку 01_backup_procs.sql (16 + UPItemDisassemble)
    ok_all &= ok
    print("[%s] Joy1: живые процедуры = снимок (%d/%d)%s" % ("OK" if ok else "ОТКАЗ", len(want) - len(diff), len(want),
                                                          " — расходятся: %s" % diff if diff else ""))
    print("СУХОЙ ПРОГОН: %s" % ("всё готово к --apply (restart_stack.py --deploy deploy_f1_p100.py --expect P100_ChargeStack)"
                                if ok_all else "ОТКАЗ — выкладка невозможна"))
    return ok_all


def apply():
    """Выкладка по шагам; True — всё чисто."""
    done = []

    def fail(msg):
        print("ОТКАЗ: %s" % msg)
        print("сделано до отказа: %s" % (", ".join(done) or "ничего"))
        print("откат: deploy_item_dedup.py --rollback; deploy_p100.py --rollback; SQL 19_stack_rollback → 09_rollback_procs → sql_f1/05_rollback "
              "(только выполненные шаги, в обратном порядке)")
        return False

    for s in [p for p, _ in PRE_DEPLOY] + ["deploy_item_dedup.py", "deploy_p100.py"]:
        ok, out = sub(s, True)
        print(out[-6000:], flush=True)
        if not ok:
            return fail("%s не напечатал ГОТОВО" % s)
        done.append(s)
    for folder, files, quoted in ((SQL_F1, F1_FILES, False), (SQL_P100, P100_FILES, True)):
        for n in files:
            rc, out = run_sql(folder, n, quoted)
            print("== %s RC=%d\n%s" % (n, rc, out[-6000:]), flush=True)
            if rc != 0:
                return fail("%s завершился с ошибкой" % n)
            if n == "03_apply.sql" and not re.search(r"(^|\n)\s*OK\|", out):
                return fail("03_apply не вернул OK")
            if n == "04_verify.sql":
                bad = [l for l in out.splitlines() if re.match(r"^[A-Za-z_]+\.[A-Za-z0-9_]+\|[1-9]\d*$", l.strip())]
                if bad:
                    return fail("F1: остались коды-дубли %s" % bad[:20])
            if n == "12_stack_apply.sql" and not re.search(r"(^|\n)\s*OK\|", out):
                return fail("12_stack_apply не вернул OK")
            if n == "13_stack_verify.sql":
                bad = check_13(out)
                if bad:
                    return fail("13_stack_verify: %s" % bad)
            done.append(n)
    print("ГОТОВО: F1 + P100 — таблицы и карта gp7, AsdaPatch v57, SQL F1, процедуры P100 и укладка зарядов выложены и проверены")
    return True


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    if "--apply" in sys.argv:
        return 0 if apply() else 1
    return 0 if dry_run() else 1


if __name__ == "__main__":
    sys.exit(main())
