# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_board_quest.py — ВЫКЛАДКА / ОТКАТ серверной части «заданий доски объявлений» (LimitationQuest 20000…20056;
#   решения владельца 28.10.2026; спецификация Docs/Port/systems/BOARD_QUEST_FLOW.md; отчёт Reports/board_quest/SERVER.md):
#   1. ДАННЫЕ (board_quest_data.py build → tools/data_board_quest/): LimitationQuest.txt под клиентскую таблицу Interlude
#      (57 записей; 20055/20056 новые; 20026 режим 4 → 0; lvMax 99 клиента → 100) — во ВСЕ копии стойки: GameServer
#      NpcData_Info (читает GS) и ItemTable_Info (не читается), NpcServer Quest (читает NpcServer) и NpcInfo (не читается), по
#      папкам stack_layout.GS_FOLDERS / NPC_FOLDERS (поле, Indun, канал 2) — 12 файлов, все одинаковые.
#      Monster.ai (GameServer\MonsterData_Info, NpcServer\Monster; 6 копий): условие (20056, 79427, 40 %) мобам 817/818
#      (Dia Parrot) — без него 20056 не засчитывался никем. Базы: c4da0022 (5 копий) и 08c20c96 (Indun_GameServer).
#      board_quest_stand_20261028.py 12/0): суточный сброс dbo.CRT_AsdaLimitationDailyReset + журнал dbo.AsdaLimitationResetLog,
#      вызов-страховка в CRT_UPLimitationList, Quest_Type в CRT_UPLimitationEnter, сверка строк. Затем разовый сброс 'deploy'.
#   3. Задача планировщика Windows «ASDA_LimitationDailyReset»: ежедневно 06:02, Administrator S4U (без пароля, без окна),
#      StartWhenAvailable; sqlcmd … EXEC dbo.CRT_AsdaLimitationDailyReset @Source='task'. После создания — пробный запуск
#      (за сегодняшнюю границу сброс уже сделан → запись журнала Source 'task', Done 0 — путь задачи рабочий).
#   ★ Две фазы: А — python deploy_board_quest.py --apply-sql (на ЖИВОЙ стойке: SQL + сброс 'deploy' + задача; рестарт не нужен);
#     Б — python restart_stack.py --deploy deploy_board_quest.py (файлы; GS/NpcServer перечитывают таблицы только при старте;
#     SQL уже стоит → повторяется только сверка строк). После старта: python deploy_board_quest.py --check-started.
#     Без фазы А --apply делает и SQL. --retask — пересоздать задачу, если она уже есть.
# Выкладка (--apply; стойка ОСТАНОВЛЕНА): сверка md5 базы каждого файла (чужой — СТОП, код 8, ничего не тронуто) и стоковых
#   текстов процедур → бэкап (рядом <файл>.bak_20261028_board, v2\_backup\2026-10-28_board_quest\…,
#   @@ASTORY_DEV_ROOT@@\_backup\2026-10-28_board_server\server\v2\…; тексты процедур — …\sql\) → заливка (scp в stage, сверка md5,
#   копия поверх, сверка) → SQL → сброс 'deploy' → задача → «ГОТОВО». Уже новый файл / уже правленый SQL пропускаются.
# Откат (--rollback; стойка остановлена): файлы, которые сейчас = новый, — из <файл>.bak_20261028_board; SQL —
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_board_quest_20261028_deploy/deploy.log (дописывается).
import base64
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                         # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, md5                                           # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
DATA = os.path.join(HERE, "data_board_quest")                               # новые файлы (board_quest_data.py build)
SQL_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "..", "SQL"))     # AstoryServer/SQL
SQL_FIX = os.path.join(SQL_DIR, "board_quest_fix_20261028.sql")
SQL_ROLLBACK = os.path.join(SQL_DIR, "board_quest_rollback_20261028.sql")
SQL_BK = os.path.join(SQL_DIR, "board_quest_backup_20261028")               # стоковые тексты процедур
STOCK_MD5 = {"CRT_UPLimitationList": "762FB6180C1291CFB51AE5D8BF5FD4A5",   # HASHBYTES('MD5', OBJECT_DEFINITION) стока
             "CRT_UPLimitationEnter": "17D421496E5BEBF4EBAC38D32ABB9877"}
MARK = "board_20261028"                                                     # метка правки в текстах процедур
SUFFIX = ".bak_20261028_board"
SRV_BACKUP = V2 + r"\_backup\2026-10-28_board_quest"
STAGE = SRV_BACKUP + r"\stage"                                              # залитые новые файлы (сверка md5 перед копией)
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-28_board_server/server/v2"
LOG = os.path.join(HERE, "run_board_quest_20261028_deploy", "deploy.log")
TASK = "ASDA_LimitationDailyReset"                                          # имя задачи планировщика
TASK_TIME = "06:02"                                                         # граница 06:00 + запас (см. генератор SQL)
SQLCMD = r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE"

LQ_NEW = ("LimitationQuest.txt", "b19a88ed65959391e81bf539d71a4399")        # (локальный файл, md5) — одна таблица на все копии
AI_NEW = {"c4da0022f45ac5dec75e0309246fb0e6": ("Monster_c4da0022.ai", "2ea24c66ea64f24ce98d05ac9fd8f190"),
          "08c20c9605369dc97fb7145730cde863": ("Monster_08c20c96.ai", "e222372ede62a45188d700eca6a415d1")}
BASE_LOCAL = {   # md5 базы → локальная копия той же базы (для локального бэкапа без чтения по SSH; md5 сверяется)
    "da2846efc390e4727930fbbad2b67f25": os.path.join(DATA, "base", "LimitationQuest_GS_da2846ef.txt"),
    "a7aa81f7ed7ac075967de6e12825cea0": os.path.join(DATA, "base", "LimitationQuest_GSItemTable_a7aa81f7.txt"),
    "6d772859808d09409c2ef3510eb4b401": os.path.join(DATA, "base", "LimitationQuest_NPC_6d772859.txt"),
    "f924d562863350a4279d042dd01a63f5": os.path.join(DATA, "base", "LimitationQuest_NPCNpcInfo_f924d562.txt"),
    "c4da0022f45ac5dec75e0309246fb0e6": os.path.join(HERE, "data_p91b", "NpcServer", "Monster", "Monster.ai"),
    "08c20c9605369dc97fb7145730cde863": os.path.join(HERE, "data_p91b", "Indun_GameServer", "MonsterData_Info", "Monster.ai"),
}


def plan_files():
    """Путь от v2 → (локальный новый, допустимые md5 базы, md5 нового). Состав папок — только stack_layout."""
    out = {}
    lq_local, lq_md5 = LQ_NEW
    for d in stack_layout.GS_FOLDERS:
        out[d + r"\NpcData_Info\LimitationQuest.txt"] = (lq_local, {"da2846efc390e4727930fbbad2b67f25"}, lq_md5)
        out[d + r"\ItemTable_Info\LimitationQuest.txt"] = (lq_local, {"a7aa81f7ed7ac075967de6e12825cea0"}, lq_md5)
        base = "08c20c9605369dc97fb7145730cde863" if d == "Indun_GameServer" else "c4da0022f45ac5dec75e0309246fb0e6"
        out[d + r"\MonsterData_Info\Monster.ai"] = (AI_NEW[base][0], {base}, AI_NEW[base][1])
    for d in stack_layout.NPC_FOLDERS:
        out[d + r"\Quest\LimitationQuest.txt"] = (lq_local, {"6d772859808d09409c2ef3510eb4b401"}, lq_md5)
        out[d + r"\NpcInfo\LimitationQuest.txt"] = (lq_local, {"f924d562863350a4279d042dd01a63f5"}, lq_md5)
        base = "c4da0022f45ac5dec75e0309246fb0e6"
        out[d + r"\Monster\Monster.ai"] = (AI_NEW[base][0], {base}, AI_NEW[base][1])
    return out


BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS] + [d + r"\NpcServer.exe" for d in stack_layout.NPC_FOLDERS] + \
       [r"DBManager\DBManager.exe"]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def ps_list(paths):
    """Литерал массива PowerShell из путей."""
    return "@(" + ",".join(q(p) for p in paths) + ")"


def md5_many(rels):
    """md5 многих файлов стойки ОДНИМ вызовом SSH: {путь от v2: md5 | 'none'}."""
    rc, out = ps("foreach ($r in %s) { Write-Output ('M|' + $r + '|' + (Md5Of (Join-Path %s $r))) }" % (ps_list(rels), q(V2)), timeout=300)
    res = {l.split("|")[1]: l.split("|")[2].strip().lower() for l in out.splitlines() if l.startswith("M|") and l.count("|") == 2}
    if rc != 0 or len(res) != len(set(rels)):
        raise RuntimeError("md5 по SSH: код %d: %s" % (rc, out[-400:]))
    return res


def busy_many(rels):
    """Занятые процессами файлы (IsBusy = BUSY) — одним вызовом."""
    rc, out = ps("foreach ($r in %s) { Write-Output ('B|' + $r + '|' + (IsBusy (Join-Path %s $r))) }" % (ps_list(rels), q(V2)), timeout=180)
    if rc != 0:
        raise RuntimeError("занятость по SSH: код %d: %s" % (rc, out[-300:]))
    return [l.split("|")[1] for l in out.splitlines() if l.startswith("B|") and l.strip().endswith("BUSY")]


def sql(query, timeout=180):
    """sqlcmd -E по SSH (Joy1), запрос в UTF-8 через временный файл → (код, вывод)."""
    b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    return ps("$f = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String('%s')); "
              "$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -h -1 -W -i $f 2>&1; $c = $LASTEXITCODE; Remove-Item $f; "
              "Write-Output ($o -join \"`n\"); Write-Output (\"RC=\" + $c)" % b64, timeout=timeout)


def sql_state():
    """{List: md5, Enter: md5, listmark, entermark, proc, table} — состояние процедур Joy1."""
    rc, out = sql("SET NOCOUNT ON; SELECT CONCAT('S|', "
                  "CONVERT(varchar(32), HASHBYTES('MD5', OBJECT_DEFINITION(OBJECT_ID('dbo.CRT_UPLimitationList'))), 2), '|', "
                  "CONVERT(varchar(32), HASHBYTES('MD5', OBJECT_DEFINITION(OBJECT_ID('dbo.CRT_UPLimitationEnter'))), 2), '|', "
                  "CASE WHEN OBJECT_DEFINITION(OBJECT_ID('dbo.CRT_UPLimitationList')) LIKE '%" + MARK + "%' THEN 1 ELSE 0 END, '|', "
                  "CASE WHEN OBJECT_DEFINITION(OBJECT_ID('dbo.CRT_UPLimitationEnter')) LIKE '%" + MARK + "%' THEN 1 ELSE 0 END, '|', "
                  "CASE WHEN OBJECT_ID('dbo.CRT_AsdaLimitationDailyReset', 'P') IS NULL THEN 0 ELSE 1 END, '|', "
                  "CASE WHEN OBJECT_ID('dbo.AsdaLimitationResetLog', 'U') IS NULL THEN 0 ELSE 1 END, '|', "
                  "(SELECT COUNT(*) FROM dbo.CRT_LimitationQuest));")
    line = [l for l in out.splitlines() if l.startswith("S|")]
    if rc != 0 or not line or "RC=0" not in out:
        raise RuntimeError("состояние процедур Joy1: %s" % out[-400:])
    f = line[0].split("|")
    return {"list": f[1], "enter": f[2], "listmark": f[3] == "1", "entermark": f[4] == "1", "proc": f[5] == "1",
            "table": f[6] == "1", "rows": int(f[7])}


def sql_done(st):
    """SQL правки уже на месте."""
    return st["listmark"] and st["entermark"] and st["proc"] and st["table"]


def run_sql_file(path, lines):
    """Применить .sql (GO-пакеты) через sqlcmd -b: файл по scp в v2\\_backup\\2026-10-28_board_quest\\sql. → 0 успех."""
    remote = SRV_BACKUP + "\\sql\\" + os.path.basename(path)
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null" % q(SRV_BACKUP + "\\sql"))
    r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", path,
                        "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        log(lines, "  SQL %s: ОШИБКА scp: %s" % (os.path.basename(path), r.stderr.strip()))
        return 5
    rc, out = ps("$o = & sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -i %s 2>&1; Write-Output ($o -join \"`n\"); "
                 "Write-Output (\"RC=\" + $LASTEXITCODE)" % q(remote), timeout=300)
    good = rc == 0 and "RC=0" in out
    for l in out.splitlines():
        if l.startswith("BOARDSYNC|"):
            log(lines, "  сверка строк: " + l.strip())
    log(lines, "  SQL %s: %s" % (os.path.basename(path), "OK" if good else "ОШИБКА: " + out[-600:]))
    return 0 if good else 5


def backup_procs(lines):
    """Стоковые тексты процедур (локальная копия сверена с живыми md5 вызывающим) → v2\\_backup\\…\\sql и локальный бэкап."""
    os.makedirs(LOCAL_BACKUP.rsplit("/", 2)[0] + "/sql", exist_ok=True)
    for name in STOCK_MD5:
        src = os.path.join(SQL_BK, name + ".sql")
        text = open(src, encoding="utf-8", newline="").read()
        loc = LOCAL_BACKUP.rsplit("/", 2)[0] + "/sql/" + name + ".sql"
        if not os.path.exists(loc):
            open(loc, "w", encoding="utf-8", newline="").write(text)
        # по scp (текст в -EncodedCommand не влезает в предел длины командной строки — сбой 28.10 21:25)
        remote = SRV_BACKUP + "\\sql\\" + name + ".sql"
        rc, out = ps("New-Item -ItemType Directory -Force -Path %s | Out-Null; Write-Output (Md5Of %s)" % (q(SRV_BACKUP + "\\sql"), q(remote)))
        if out.splitlines()[-1].strip().lower() == "none":
            r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", src,
                                "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")], capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                raise RuntimeError("бэкап текста %s на сервере (scp): %s" % (name, r.stderr.strip()))
        got = md5_many_abs([remote])[remote]
        if got != md5(src):
            raise RuntimeError("бэкап текста %s на сервере: md5 %s ≠ %s" % (name, got, md5(src)))
        log(lines, "  бэкап процедуры %s: %d симв. → %s и %s\\sql" % (name, len(text), loc, SRV_BACKUP))


def backup_files(todo, cur, lines):
    """Бэкап файлов: рядом (SUFFIX) и в v2\\_backup (одним вызовом SSH, со сверкой md5), локально — из сверенной копии базы."""
    script = []
    for rel in todo:
        script.append("BackupOne %s %s" % (q(rel), q(cur[rel])))
    rc, out = ps(("function BackupOne([string]$rel, [string]$want) { $src = Join-Path %s $rel; "
                  "foreach ($dst in @(($src + '%s'), (Join-Path %s $rel))) { $h = Md5Of $dst; "
                  "if ($h -eq 'none') { $d = Split-Path -Parent $dst; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                  "Copy-Item -LiteralPath $src -Destination $dst; $h = Md5Of $dst; if ($h -ne $want) { Write-Output ('BAD|' + $dst + '|' + $h); return }; "
                  "Write-Output ('NEW|' + $dst + '|' + $h) } elseif ($h -ne $want) { Write-Output ('OTHER|' + $dst + '|' + $h) } else { Write-Output ('HAVE|' + $dst + '|' + $h) } } }\n"
                  % (q(V2), SUFFIX, q(SRV_BACKUP))) + "\n".join(script), timeout=600)
    bad = [l for l in out.splitlines() if l.startswith("BAD|") or l.startswith("OTHER|")]
    for l in out.splitlines():
        if l.startswith("NEW|"):
            log(lines, "  бэкап: %s" % l[4:])
    if rc != 0 or bad or out.count("|") < 2 * len(todo):
        raise RuntimeError("бэкап на сервере: %s" % ("; ".join(bad) or out[-400:]))
    for rel in todo:
        loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
        src = BASE_LOCAL[cur[rel]]
        if md5(src) != cur[rel]:
            raise RuntimeError("локальная копия базы %s ≠ %s" % (src, cur[rel]))
        if os.path.exists(loc):
            if md5(loc) != cur[rel]:
                raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл" % loc)
            continue
        os.makedirs(os.path.dirname(loc), exist_ok=True)
        with open(src, "rb") as f, open(loc, "wb") as g:
            g.write(f.read())
        if md5(loc) != cur[rel]:
            raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %d файлов → %s" % (len(todo), LOCAL_BACKUP))


def upload(todo, plan, lines):
    """Новые файлы (3 разных) → stage по scp → сверка md5 → копия на место каждого пути → сверка."""
    locs = sorted({plan[rel][0] for rel in todo})
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null; Write-Output OK" % q(STAGE))
    r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes"] + [os.path.join(DATA, l) for l in locs] +
                       ["Administrator@@@ASTORY_SERVER_VPN_IP@@:" + STAGE.replace("\\", "/") + "/"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("scp в stage: %s" % r.stderr.strip())
    st = md5_many_abs([STAGE + "\\" + l for l in locs])
    for l in locs:
        want = md5(os.path.join(DATA, l))
        if st[STAGE + "\\" + l] != want:
            raise RuntimeError("stage %s = %s, ожидался %s — ничего не скопировано" % (l, st[STAGE + "\\" + l], want))
    # ★ по 3 файла за вызов: SSH на сервере идёт через cmd.exe (предел строки 8191), а -EncodedCommand раздувает скрипт ×2,7 —
    #   18 копий одним вызовом молча не выполнились (28.10 21:31, стойка стояла)
    got = {}
    for i in range(0, len(todo), 3):
        cmds = "\n".join("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('C|' + %s + '|' + (Md5Of %s))" % (
            q(STAGE + "\\" + plan[rel][0]), q(V2 + "\\" + rel), q(rel), q(V2 + "\\" + rel)) for rel in todo[i:i + 3])
        rc, out = ps(cmds, timeout=300)
        got.update({l.split("|")[1]: l.split("|")[2].strip() for l in out.splitlines() if l.startswith("C|")})
    for rel in todo:
        ok = got.get(rel) == plan[rel][2]
        log(lines, "  %s выложено: %s %s" % (rel, got.get(rel), "OK" if ok else "НЕ СОШЛОСЬ"))
        if not ok:
            raise RuntimeError("после копии %s = %s, ожидался %s" % (rel, got.get(rel), plan[rel][2]))


def md5_many_abs(paths):
    """md5 файлов по абсолютным путям сервера (одним вызовом)."""
    rc, out = ps("foreach ($p in %s) { Write-Output ('M|' + $p + '|' + (Md5Of $p)) }" % ps_list(paths), timeout=180)
    res = {l.split("|")[1]: l.split("|")[2].strip().lower() for l in out.splitlines() if l.startswith("M|") and l.count("|") == 2}
    if rc != 0 or len(res) != len(paths):
        raise RuntimeError("md5 по SSH: %s" % out[-300:])
    return res


def task_state():
    """(есть ли задача, состояние, время следующего запуска, результат последнего, время последнего)."""
    rc, out = ps("$t = Get-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue; if (-not $t) { Write-Output 'T|0'; return }; "
                 "$i = $t | Get-ScheduledTaskInfo; Write-Output ('T|1|' + $t.State + '|' + $i.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') + '|' + "
                 "$i.LastTaskResult + '|' + $i.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $t.Principal.UserId + '|' + $t.Principal.LogonType)" % q(TASK))
    line = [l for l in out.splitlines() if l.startswith("T|")]
    if rc != 0 or not line:
        raise RuntimeError("состояние задачи %s: %s" % (TASK, out[-300:]))
    f = line[0].split("|")
    return (f[1] == "1",) + tuple(f[2:])


def make_task(lines):
    """Создать/обновить задачу планировщика (S4U, без пароля) и сделать пробный запуск; проверить запись 'task' в журнале.
    Возврат True/False; сбой НЕ останавливает выкладку (страховка — вызов сброса из CRT_UPLimitationList)."""
    try:
        return _make_task(lines)
    except Exception as e:
        log(lines, "  ПРЕДУПРЕЖДЕНИЕ: задача %s не готова: %s (сброс всё равно сработает при первом входе на карту после 06:01)" % (TASK, e))
        return False


def _make_task(lines):
    """Тело make_task (исключение — сбой)."""
    arg = "-S localhost\\SQLEXPRESS -E -d Joy1 -b -Q \"SET NOCOUNT ON; EXEC dbo.CRT_AsdaLimitationDailyReset @Source = 'task'\""
    rc, out = ps(("$act = New-ScheduledTaskAction -Execute %s -Argument %s\n"
                  "$trg = New-ScheduledTaskTrigger -Daily -At %s\n"
                  "$pr = New-ScheduledTaskPrincipal -UserId 'Administrator' -LogonType S4U -RunLevel Limited\n"
                  "$st = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew\n"
                  "Register-ScheduledTask -TaskName %s -Action $act -Trigger $trg -Principal $pr -Settings $st -Force "
                  "-Description %s | Out-Null\nWrite-Output OK")
                 % (q(SQLCMD), q(arg), q(TASK_TIME), q(TASK),
                    q("ASDA: суточный сброс дневных заданий доски объявлений (LimitationQuest Quest_Type=1) в Joy1; граница 06:00. "
                      "deploy_board_quest.py, Reports/board_quest/SERVER.md")), timeout=120)
    if rc != 0 or not out.endswith("OK"):
        raise RuntimeError("создание задачи %s: %s" % (TASK, out[-400:]))
    before = sql_log_count("task")
    ps("Start-ScheduledTask -TaskName %s; Write-Output OK" % q(TASK))
    for _ in range(20):
        time.sleep(3)
        if sql_log_count("task") > before:
            break
    ex, state, nxt, last, lastt, user, logon = task_state()
    after = sql_log_count("task")
    log(lines, "  задача %s: %s, следующий запуск %s, пробный запуск %s код %s (%s/%s); записей журнала 'task' %d → %d" % (
        TASK, state, nxt, lastt, last, user, logon, before, after))
    if after <= before or last != "0":
        raise RuntimeError("пробный запуск задачи не записал журнал (код %s)" % last)
    return True


def apply_sql(st, lines):
    """SQL-часть (можно на ЖИВОЙ стойке — ALTER процедур берёт краткий замок схемы): бэкап текстов, правка, разовый сброс 'deploy',
    задача. Возврат 0 — успех, 5 — SQL не применён."""
    if not sql_done(st):
        if not (st["listmark"] or st["entermark"]):
            backup_procs(lines)
        if run_sql_file(SQL_FIX, lines) != 0:
            return 5
        st = sql_state()
        if not sql_done(st):
            log(lines, "  после SQL правка не на месте: %s" % st)
            return 5
    else:
        sync_rows(lines)
    rc, out = sql("SET NOCOUNT ON; DECLARE @rc INT; EXEC @rc = dbo.CRT_AsdaLimitationDailyReset @Source = 'deploy'; SELECT CONCAT('R|', @rc);")
    m = re.search(r"R\|(-?\d+)", out)
    log(lines, "  сброс 'deploy': код %s (1 — сделан за текущую границу, 0 — уже был)" % (m.group(1) if m else out[-200:]))
    if task_state()[0] and "--retask" not in sys.argv:
        log(lines, "  задача %s уже есть (пересоздать — --retask)" % TASK)
    else:
        make_task(lines)
    log_tail(lines)
    return 0


def sync_rows(lines):
    """Повтор разовой сверки строк (блок «разовая сверка» из правки; идемпотентно) — когда процедуры уже правлены (SQL выложен
    заранее на живой стойке, а таблица GS меняется только сейчас)."""
    text = open(SQL_FIX, encoding="utf-8").read()
    i = text.index("-- ── разовая сверка")
    body = text[i:].rstrip()
    if body.endswith("GO"):
        body = body[:-2]
    rc, out = sql("SET NOCOUNT ON;\n" + body)
    line = [l for l in out.splitlines() if l.startswith("BOARDSYNC|")]
    log(lines, "  сверка строк: %s" % (line[0].strip() if line else "ОШИБКА " + out[-300:]))


def sql_log_count(source):
    """Число записей журнала сбросов с источником source."""
    rc, out = sql("SET NOCOUNT ON; SELECT CONCAT('N|', COUNT(*)) FROM dbo.AsdaLimitationResetLog WHERE Source = '%s';" % source)
    m = re.search(r"N\|(\d+)", out)
    return int(m.group(1)) if m else -1


def log_tail(lines, n=6):
    """Последние записи журнала сбросов."""
    rc, out = sql("SET NOCOUNT ON; SELECT TOP %d CONCAT('L|', Id, '|', CONVERT(varchar(19), Boundary, 120), '|', CONVERT(varchar(19), Edate, 120), "
                  "'|', Source, '|', Done, '|', FlagRows, '|', CountRows) FROM dbo.AsdaLimitationResetLog ORDER BY Id DESC;" % n)
    for l in out.splitlines():
        if l.startswith("L|"):
            log(lines, "  журнал сброса: " + l[2:].strip())


def check_started(lines):
    """После старта (только чтение): файлы = новые во всех папках, процессы GS/NpcServer работают, SQL на месте, задача готова."""
    plan = plan_files()
    cur = md5_many(list(plan))
    good = True
    for rel, (loc, bases, new) in plan.items():
        st = "новый" if cur[rel] == new else ("база" if cur[rel] in bases else "ЧУЖОЙ")
        if cur[rel] != new:
            good = False
            log(lines, "%s: %s %s" % (rel, cur[rel], st))
    log(lines, "файлы: %d из %d = новые (LimitationQuest %s ×%d, Monster.ai ×%d)" % (
        sum(1 for rel in plan if cur[rel] == plan[rel][2]), len(plan), LQ_NEW[1][:8],
        sum(1 for rel in plan if rel.endswith(".txt")), sum(1 for rel in plan if rel.endswith(".ai"))))
    busy = busy_many(BUSY)
    log(lines, "процессы GameServer/NpcServer/DBManager держат exe: %d из %d" % (len(busy), len(BUSY)))
    good = good and len(busy) == len(BUSY)
    st = sql_state()
    log(lines, "SQL: List метка %s, Enter метка %s, сброс %s, журнал %s, строк заданий %d" % (
        st["listmark"], st["entermark"], st["proc"], st["table"], st["rows"]))
    good = good and sql_done(st)
    ex, *rest = task_state()
    log(lines, "задача %s: %s" % (TASK, "нет!" if not ex else "состояние %s, следующий %s, последний код %s (%s), %s/%s" % tuple(rest)))
    good = good and ex
    log_tail(lines)
    # ошибки загрузки таблиц (MessageBox «Sync Error» / «LoadLimitationTable Read failed») — в свежих журналах процессов
    rc, out = ps("$since = (Get-Date).AddHours(-3); foreach ($d in %s) { Get-ChildItem -LiteralPath (Join-Path %s $d) -Recurse -File -Include *.txt,*.log "
                 "-ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since -and $_.Length -lt 20MB } | "
                 "Select-String -Pattern 'Limitation' -SimpleMatch | Select-Object -First 5 | ForEach-Object { Write-Output ('E|' + $_.Path + '|' + $_.Line) } }"
                 % (ps_list(stack_layout.GS_FOLDERS + stack_layout.NPC_FOLDERS), q(V2)), timeout=300)
    errs = [l for l in out.splitlines() if l.startswith("E|")]
    for l in errs[:10]:
        log(lines, "  журнал процесса: " + l[2:][:300])
    log(lines, "строк «Limitation» в журналах процессов за 3 ч: %d" % len(errs))
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply-sql (фаза А, живая стойка), --apply (фаза Б, стойка остановлена), --rollback,
    --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply_sql_only = "--apply-sql" in sys.argv
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    lines = []
    log(lines, "== deploy_board_quest %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                               "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ФАЗА А (SQL)" if apply_sql_only else
                                               "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:
            rc = check_started(lines)
            flush(lines)
            return rc
        busy = busy_many(BUSY)
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        plan = plan_files()
        cur = md5_many(list(plan))
        st = sql_state()
        log(lines, "SQL сейчас: List %s (%s), Enter %s (%s), сброс %s, журнал %s, строк заданий %d" % (
            st["list"], "правка" if st["listmark"] else ("сток" if st["list"] == STOCK_MD5["CRT_UPLimitationList"] else "ЧУЖОЙ"),
            st["enter"], "правка" if st["entermark"] else ("сток" if st["enter"] == STOCK_MD5["CRT_UPLimitationEnter"] else "ЧУЖОЙ"),
            "есть" if st["proc"] else "нет", "есть" if st["table"] else "нет", st["rows"]))

        if rollback:
            todo = [rel for rel, (l, b, new) in plan.items() if cur[rel] == new]
            baks = md5_many([rel + SUFFIX for rel in todo]) if todo else {}
            for rel in todo:
                if baks[rel + SUFFIX] not in plan[rel][1]:
                    log(lines, "СТОП: %s%s нет или это не база (%s)" % (rel, SUFFIX, baks[rel + SUFFIX]))
                    flush(lines)
                    return 6
            if st["listmark"] or st["entermark"] or st["proc"]:
                if run_sql_file(SQL_ROLLBACK, lines) != 0:
                    flush(lines)
                    return 5
                st = sql_state()
                ok = st["list"] == STOCK_MD5["CRT_UPLimitationList"] and st["enter"] == STOCK_MD5["CRT_UPLimitationEnter"] and not st["proc"]
                log(lines, "  SQL после отката: %s" % ("сток" if ok else "НЕ СТОК (%s / %s)" % (st["list"], st["enter"])))
                if not ok:
                    flush(lines)
                    return 5
            rc, out = ps("Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction SilentlyContinue; Write-Output OK" % q(TASK))
            log(lines, "  задача %s удалена" % TASK)
            got = {}
            for i in range(0, len(todo), 3):   # по 3 файла: предел строки cmd.exe на сервере (см. upload)
                cmds = "\n".join("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('C|' + %s + '|' + (Md5Of %s))" % (
                    q(V2 + "\\" + rel + SUFFIX), q(V2 + "\\" + rel), q(rel), q(V2 + "\\" + rel)) for rel in todo[i:i + 3])
                rc, out = ps(cmds, timeout=300)
                got.update({l.split("|")[1]: l.split("|")[2].strip() for l in out.splitlines() if l.startswith("C|")})
            if todo:
                for rel in todo:
                    ok = got.get(rel) in plan[rel][1]
                    log(lines, "%s: возвращён %s %s" % (rel, got.get(rel), "OK" if ok else "НЕ СОШЛОСЬ"))
                    if not ok:
                        flush(lines)
                        return 4
            log(lines, "ОТКАТ ГОТОВ (файлов %d, SQL — сток, задача удалена; журнал dbo.AsdaLimitationResetLog остался). Нужен старт стойки."
                % len(todo))
            flush(lines)
            return 0

        for loc, want in [LQ_NEW] + list(AI_NEW.values()):
            p = os.path.join(DATA, loc)
            if not os.path.exists(p) or md5(p) != want:
                log(lines, "СТОП: %s нет или md5 не %s (перегенерировать: board_quest_data.py build)" % (p, want))
                flush(lines)
                return 3
        todo = []
        for rel, (loc, bases, new) in plan.items():
            if cur[rel] == new:
                log(lines, "%s: уже новый" % rel)
                continue
            if cur[rel] not in bases:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю" % (rel, cur[rel], "/".join(sorted(bases))))
                flush(lines)
                return 8
            todo.append(rel)
        log(lines, "файлов к выкладке: %d из %d (LimitationQuest → %s, Monster.ai → %s)" % (
            len(todo), len(plan), LQ_NEW[1][:8], "/".join(v[1][:8] for v in AI_NEW.values())))
        if not sql_done(st):
            if (st["list"] != STOCK_MD5["CRT_UPLimitationList"] and not st["listmark"]) or \
               (st["enter"] != STOCK_MD5["CRT_UPLimitationEnter"] and not st["entermark"]):
                log(lines, "СТОП: процедуры не стоковые и не правленые — SQL не применяю, ничего не тронуто")
                flush(lines)
                return 8
        ex = task_state()[0]
        log(lines, "задача %s: %s" % (TASK, "есть" if ex else "нет (будет создана)"))
        if apply_sql_only:   # фаза А — на живой стойке: только SQL + задача; файлы — фазой Б (restart_stack --deploy)
            if apply_sql(st, lines) != 0:
                log(lines, "СТОП: SQL не применён")
                flush(lines)
                return 5
            log(lines, "ГОТОВО (фаза А, SQL и задача; стойка не трогалась). Файлы — restart_stack.py --deploy deploy_board_quest.py.")
            flush(lines)
            return 0
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (файлов %d, SQL — %s, задача — %s)" % (
                len(todo), "уже стоит (повторится сверка строк)" if sql_done(st) else "применить", "есть" if ex else "создать"))
            flush(lines)
            return 0

        if todo:
            backup_files(todo, cur, lines)
            upload(todo, plan, lines)
        if apply_sql(st, lines) != 0:
            log(lines, "СТОП: SQL не применён — файлы уже выложены (от SQL не зависят); откат: python deploy_board_quest.py --rollback")
            flush(lines)
            return 5
        log(lines, "ГОТОВО: данные доски (%d файлов), SQL суточного сброса и задача %s (%s) на месте. Старт стойки — restart_stack; "
                   "затем python deploy_board_quest.py --check-started." % (len(todo), TASK, TASK_TIME))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
