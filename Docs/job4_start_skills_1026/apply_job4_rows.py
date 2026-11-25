# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# apply_job4_rows.py — ВЫКЛАДКА / ОТКАТ строк 6/17/28 ChangeJobAddSkillTable.txt (стартовые навыки 4-й профессии Рыцарь /
#   Капканщик / Жрец) на dev-стойку по SSH. 26.10.2026; обоснование — Reports/job4/START_SKILLS_6_17_28.md.
#   ★ Применяет ТОЛЬКО координатор после решения владельца (источник строк — «выведено признаком», а не «найдено в данных»).
#   Читают таблицу только GameServer и Indun_GameServer (загрузчик GameServer.c:71655 при старте; в NpcServer.exe строки
#   «ChangeJobAddSkillTable» нет — копии NpcServer\Skill и Indun_NpcServer\Skill мёртвые, не трогаются).
#   Таблица читается при старте (fopen/fclose) — файл не занят, класть можно при работающей стойке; действует после рестарта
#   GameServer/Indun: python ..\..\Patches\AsdaPatch\tools\restart_stack.py --no-deploy --expect P87_Job4StartSkills
#   (P87 уже на стойке — DLL 77307319; новые строки он берёт из загруженной таблицы без пересборки).
#
# Режимы:
#   (без ключей)  сухой прогон: md5 живых файлов, занятость, что будет сделано — только чтение.
#   --apply       живые файлы обеих папок = LIVE_MD5 (сток 12 строк) → бэкапы → заливка staging → сверка; печатает «ГОТОВО».
#                 Уже NEW_MD5 в обеих — «ГОТОВО» без действий. Иное md5 / папки различаются — СТОП, код 8, ничего не тронуто.
#   --rollback    только поверх NEW_MD5: вернуть <файл>.bak_20261026_job4rows (md5 = LIVE_MD5); печатает «ГОТОВО».
#   --check       md5 живых файлов.
# Бэкап (до записи, существующий не перезаписывается): рядом <файл>.bak_20261026_job4rows; на сервере
#   v2\_backup\2026-10-26_job4rows\<папка>\SkillTable_Info\; локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_job4rows\server\v2\<папка>\SkillTable_Info\
#   (скачан по scp, сверка md5 и размера). Уже выданные навыки откат не снимает (они в CharSkill персонажа).
import base64
import hashlib
import os
import subprocess
import sys
import time

KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]
SCP = ["scp", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "Patches", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2: Ch2_GameServer)
FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"]
REL = r"SkillTable_Info\ChangeJobAddSkillTable.txt"
LIVE_MD5 = "8e0cd3a44563ab0162505b6a924fc848"      # сток / живой: 12 строк (1 2 3 4 12 13 14 15 23 24 25 26)
NEW_MD5 = "8fa64c2394d3c684a3b684553f270fcc"       # staging: + 6 17 28 (build_job4_rows.py)
SUFFIX = ".bak_20261026_job4rows"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_job4rows"
LOCAL_BACKUP = r"@@ASTORY_DEV_ROOT@@\_backup\2026-10-26_job4rows\server\v2"
LOG = os.path.join(HERE, "apply.log")

PS_LIB = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Md5Of([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'NONE' }
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { $h = [Security.Cryptography.MD5]::Create().ComputeHash($fs) } finally { $fs.Close() }
  return ([BitConverter]::ToString($h) -replace '-', '').ToLower()
}
function IsBusy([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'NONE' }
  try { $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None'); $fs.Close(); return 'FREE' } catch { return 'BUSY' }
}
"""


def log(text):
    """Строка в консоль и в apply.log (дописывается)."""
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + text
    print(text)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def ps(script, timeout=120):
    """PowerShell на сервере через -EncodedCommand; (код, вывод)."""
    enc = base64.b64encode((PS_LIB + script).encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        out += " | " + p.stderr.decode("utf-8", "replace").strip()[-500:]
    return p.returncode, out


def q(path):
    """Строка PowerShell в одинарных кавычках."""
    return "'" + path.replace("'", "''") + "'"


def live_path(folder):
    """Полный путь таблицы на стойке."""
    return V2 + "\\" + folder + "\\" + REL


def rmd5(path):
    """md5 файла на сервере ('NONE' — нет)."""
    rc, out = ps("Md5Of %s" % q(path))
    return out.strip().splitlines()[-1] if rc == 0 and out else "ERR " + out


def state():
    """{папка: (md5, занятость)} живых таблиц."""
    res = {}
    for f in FOLDERS:
        rc, out = ps("(Md5Of %s) + ' ' + (IsBusy %s)" % (q(live_path(f)), q(live_path(f))))
        parts = out.split()
        res[f] = (parts[0], parts[1]) if rc == 0 and len(parts) >= 2 else ("ERR", out)
    return res


def local_md5(path):
    """md5 локального файла."""
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def apply():
    staging = os.path.join(HERE, "GameServer", REL)
    # staging есть у поля и Indun; копия канала 2 (Ch2_*) берёт staging своего поля (stack_layout.twin_of)
    if local_md5(staging) != NEW_MD5 or local_md5(os.path.join(HERE, "Indun_GameServer", REL)) != NEW_MD5:
        log("СТОП: staging md5 ≠ %s (пересобрать build_job4_rows.py и проверить verify_job4_rows.py)" % NEW_MD5)
        return 8
    st = state()
    for f, (m, busy) in st.items():
        log("  %s: md5 %s, %s" % (f, m, busy))
    if all(m == NEW_MD5 for m, _ in st.values()):
        log("строки 6/17/28 уже на стойке — ничего не делаю\nГОТОВО")
        return 0
    if not all(m in (LIVE_MD5, NEW_MD5) for m, _ in st.values()):
        log("СТОП: живые таблицы не сток %s и не staging (или ошибка чтения) — ничего не тронуто" % LIVE_MD5)
        return 8
    if any(b == "BUSY" for _, b in st.values()):
        log("СТОП: файл занят процессом — повторить позже")
        return 2
    for f in FOLDERS:
        lp = live_path(f)
        if st[f][0] == NEW_MD5:   # ★ 26.10: папка уже со строками 6/17/28 (например, копия Ch2_* снята после выкладки)
            log("  %s: уже staging — пропуск" % f)
            continue
        # 1) бэкап рядом и в v2\_backup (не перезаписывать существующий)
        sb = SRV_BACKUP + "\\" + f + "\\" + REL
        rc, out = ps("""
$src = %s; $b1 = $src + %s; $b2 = %s
if (-not (Test-Path -LiteralPath $b1)) { Copy-Item -LiteralPath $src -Destination $b1 }
New-Item -ItemType Directory -Force -Path (Split-Path $b2) | Out-Null
if (-not (Test-Path -LiteralPath $b2)) { Copy-Item -LiteralPath $src -Destination $b2 }
(Md5Of $b1) + ' ' + (Md5Of $b2)""" % (q(lp), q(SUFFIX), q(sb)))
        if rc != 0 or out.split()[-2:] != [LIVE_MD5, LIVE_MD5]:
            log("СТОП: бэкап на сервере %s не сошёлся: %s" % (f, out))
            return 8
        # 2) локальный бэкап (scp с сервера) со сверкой md5 и размера
        ld = os.path.join(LOCAL_BACKUP, f, "SkillTable_Info")
        os.makedirs(ld, exist_ok=True)
        lf = os.path.join(ld, "ChangeJobAddSkillTable.txt")
        if not os.path.exists(lf):
            p = subprocess.run(SCP + [HOST + ":" + lp.replace("\\", "/"), lf], capture_output=True, timeout=120)
            if p.returncode != 0:
                log("СТОП: локальный бэкап %s: %s" % (f, p.stderr.decode("utf-8", "replace")[-300:]))
                return 8
        if local_md5(lf) != LIVE_MD5 or os.path.getsize(lf) != 1178:
            log("СТОП: локальный бэкап %s md5 %s / %d б ≠ сток" % (f, local_md5(lf), os.path.getsize(lf)))
            return 8
        log("  %s: бэкапы — %s%s, %s, %s (md5 %s)" % (f, lp, SUFFIX, sb, lf, LIVE_MD5))
        # 3) заливка во временный файл, сверка, замена
        tmp = lp + ".job4rows_upload"
        p = subprocess.run(SCP + [os.path.join(HERE, stack_layout.twin_of(f), REL), HOST + ":" + tmp.replace("\\", "/")], capture_output=True, timeout=120)
        if p.returncode != 0 or rmd5(tmp) != NEW_MD5:
            log("СТОП: заливка %s не сошлась (%s)" % (f, p.stderr.decode("utf-8", "replace")[-300:]))
            return 8
        rc, out = ps("Copy-Item -LiteralPath %s -Destination %s -Force; Remove-Item -LiteralPath %s; Md5Of %s" % (q(tmp), q(lp), q(tmp), q(lp)))
        if rc != 0 or out.split()[-1] != NEW_MD5:
            log("СТОП: замена %s: %s — откатить: --rollback" % (f, out))
            return 8
        log("  %s: %s = %s (строки 6/17/28 добавлены)" % (f, lp, NEW_MD5))
    log("Таблица действует после рестарта GameServer/Indun_GameServer (restart_stack.py --no-deploy --expect P87_Job4StartSkills).")
    log("ГОТОВО")
    return 0


def rollback():
    for f in FOLDERS:
        lp = live_path(f)
        m = rmd5(lp)
        if m == LIVE_MD5:
            log("  %s: уже сток" % f)
            continue
        if m != NEW_MD5:
            log("СТОП: %s md5 %s — не наша staging, откат не делаю" % (f, m))
            return 8
        rc, out = ps("$b = %s; if ((Md5Of $b) -ne %s) { 'BADBAK ' + (Md5Of $b) } else { Copy-Item -LiteralPath $b -Destination %s -Force; Md5Of %s }"
                     % (q(lp + SUFFIX), q(LIVE_MD5), q(lp), q(lp)))
        if rc != 0 or out.split()[-1] != LIVE_MD5:
            log("СТОП: откат %s: %s" % (f, out))
            return 8
        log("  %s: возвращён сток %s" % (f, LIVE_MD5))
    log("Сток действует после рестарта GameServer/Indun_GameServer.\nГОТОВО")
    return 0


def main():
    if "--apply" in sys.argv:
        log("== apply_job4_rows --apply")
        return apply()
    if "--rollback" in sys.argv:
        log("== apply_job4_rows --rollback")
        return rollback()
    st = state()
    print("== apply_job4_rows: %s" % ("проверка" if "--check" in sys.argv else "сухой прогон (ничего не пишется)"))
    for f, (m, busy) in st.items():
        tag = "сток (12 строк) — будет заменён" if m == LIVE_MD5 else ("уже staging (15 строк)" if m == NEW_MD5 else "НЕИЗВЕСТНЫЙ — --apply откажет")
        print("  %s\\%s: md5 %s, %s — %s" % (f, REL, m, busy, tag))
    print("  staging: %s (ждём %s)" % (local_md5(os.path.join(HERE, "GameServer", REL)), NEW_MD5))
    return 0


if __name__ == "__main__":
    sys.exit(main())
