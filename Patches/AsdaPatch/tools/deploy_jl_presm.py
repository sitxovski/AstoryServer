# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_jl_presm.py — выкладка волны jl_presm (02.11.2026) на dev: исправление Joy1.dbo.UPPreSMConnect
#   (LoginManager: статус соулмейта на выборе персонажа 1025 и запрет одержимости при владельце в сети 1027/2) —
#   признак «в сети» из AsdaStoryOP.dbo.Us_member.Flag вместо несуществующей AsdaStoryOP.dbo.Startinfo (171 падение 17.10–01.11).
#   Без ключей — СУХОЙ ПРОГОН: только 01_preview (чтение). --apply: 01 → 02_backup (копия текста в Joy1.dbo.AsdaProcBak_jlpresm_20261102)
#   → 03_apply → 04_verify. --rollback: 05_rollback (текст из копии) → 01_preview.
#   SQL — файлом через scp + sqlcmd -i. Рестарт LoginManager не нужен (процедура ищется по имени при каждом вызове).
#   Источник SQL: Reports/joylog_missing/side/sql (стенд side/jlpresm_stand.py 20/20).
# Печатает «ГОТОВО» только если 03 вернул OK|1 (или SKIP|1), а 04 — VERIFY|OK без BAD|.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import base64
import datetime
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SQL_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "joylog_missing", "side", "sql"))
LOCAL_BAK = r"@@ASTORY_DEV_ROOT@@\_backup\2026-11-02_joylog_missing"
KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]
REMOTE = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/_backup/jl_presm_sql_20261102"


def ps(cmd, timeout=600):
    """PowerShell по SSH → (код, вывод)."""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def run_sql(name):
    """Файл SQL → scp → sqlcmd -i на Joy1 (вывод и в файл <name>.out рядом) → (код sqlcmd, вывод)."""
    ps("New-Item -ItemType Directory -Force '%s' | Out-Null" % REMOTE.replace("/", "\\"), 120)
    r = subprocess.run(["scp", "-i", KEY, "-o", "BatchMode=yes", os.path.join(SQL_DIR, name), "%s:%s/%s" % (HOST, REMOTE, name)],
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        return 1, "scp: " + (r.stdout + r.stderr).decode("utf-8", "replace")
    rp = (REMOTE + "/" + name).replace("/", "\\")
    rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -I -f 65001 -h -1 -W -s '|' -i '%s' 2>&1; $c = $LASTEXITCODE; "
                 "$t = ($o -join \"`n\"); Set-Content -Encoding UTF8 -Path '%s.out' -Value $t; Write-Output $t; Write-Output (\"RC=\" + $c)" % (rp, rp))
    m = re.search(r"RC=(-?\d+)", out)
    return (int(m.group(1)) if m else 1), out


def step(name, run_dir):
    """Один файл с печатью и сохранением вывода; → (ok, вывод)."""
    rc, out = run_sql(name)
    with open(os.path.join(run_dir, name + ".out.txt"), "w", encoding="utf-8") as f:
        f.write(out)
    print("== %s RC=%d\n%s" % (name, rc, out[-4000:]), flush=True)
    return rc == 0, out


def main():
    """Сухой прогон / --apply / --rollback."""
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    mode = "rollback" if "--rollback" in sys.argv else "apply" if "--apply" in sys.argv else "dry"
    run_dir = os.path.join(LOCAL_BAK, "presm_run_%s_%s" % (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), mode))
    os.makedirs(run_dir, exist_ok=True)
    if mode == "rollback":
        ok, out = step("05_rollback.sql", run_dir)
        if not ok or "rollback|0 left" not in out:
            print("ОТКАЗ: откат не вернул текст UPPreSMConnect")
            return 1
        step("01_preview.sql", run_dir)
        print("ГОТОВО: откат jl_presm — UPPreSMConnect возвращён к тексту из AsdaProcBak_jlpresm_20261102")
        return 0
    ok, out = step("01_preview.sql", run_dir)
    if not ok:
        return 1
    fixed = "def|marker jl_presm|1" in out
    if not fixed and ("def|reads Startinfo|1" not in out or "def|@UState=State once|1" not in out):
        print("ОТКАЗ: текст UPPreSMConnect не тот, что разобран (нет ожидаемых фрагментов) — нужен разбор")
        return 1
    if mode == "dry":
        print("сухой прогон: БД не тронута%s; выкладка — с --apply. Вывод: %s" % (" (уже исправлена)" if fixed else "", run_dir))
        return 0
    for name in ("02_backup.sql", "03_apply.sql", "04_verify.sql"):
        ok, out = step(name, run_dir)
        if not ok:
            print("ОТКАЗ: %s завершился с ошибкой (откат — --rollback)" % name)
            return 1
        if name == "03_apply.sql" and "OK|1" not in out and "SKIP|1" not in out:
            print("ОТКАЗ: 03_apply не вернул OK|1")
            return 1
        if name == "04_verify.sql" and ("BAD|" in out or "VERIFY|OK" not in out):
            print("ОТКАЗ: проверка не прошла (откат — --rollback)")
            return 1
    print("ГОТОВО: jl_presm — UPPreSMConnect читает Us_member.Flag, проверка и живой вызов OK. Вывод: %s" % run_dir)
    return 0

if __name__ == "__main__":
    sys.exit(main())
