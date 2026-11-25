# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# patchlog.py — ЕДИНЫЙ разбор журнала патчей (PatchLog_ГГГГММДД.txt) для проверки «после старта» (31.10.2026, fix-check-started).
#
# Зачем: до 31.10 каждый deploy_p*.py искал «[OK] <патч>» в хвосте суточного журнала (120–400 строк). Журнал ДОПИСЫВАЕТСЯ
#   за день (Log.cpp: FILE_APPEND_DATA, имя файла — по дате старта процесса; 31.10 на dev — 4 старта за день): если в тот же
#   день был удачный старт, а следующий прошёл с [MISMATCH]/[ОШИБКА], «Version не поддерживается» или MasterEnable=0 —
#   прежний [OK] оставался в хвосте, и проверка говорила «установлен». Образец правильного разбора —
#   deploy_quest_turnin.py --check-started (bug-quest-follow, 31.10); здесь он вынесен для всех скриптов.
#
# Разбор (judge):
#   • берётся ТОЛЬКО блок последнего запуска: от последней строки паспорта «Хост   :» (dllmain LogHostPassport, пишется при
#     каждом старте до установки патчей) до конца файла; шапка старта «<продукт> — старт <дата время>, PID <n>»
#     (Log::Init) — выше паспорта (между ними строки Config «+ раздел … добавлен», сколько угодно), из неё время и PID;
#   • установка = от паспорта до «=== итог»; после итога — строки работы процесса;
#   • ПРОВАЛ: нет «=== итог» (в т.ч. «! Version=… не поддерживается» — dllmain выходит без итога); в итоге «ошибок N≠0»;
#     «MasterEnable=0»; «не поддерживается»; в установке любой [MISMATCH]/[ОШИБКА]/[ERR]/[FAIL]; нет «[OK] <патч>» или есть
#     «[ВЫКЛ] <патч>» у ожидаемого; нет обязательной строки (need); после итога [MISMATCH]/[ОШИБКА]/[ERR]/[FAIL] со
#     ссылкой на ожидаемый патч (раздел или «P98:»); PID шапки не среди работающих процессов этой папки (журнал — от
#     прежнего запуска, новый процесс не писал);
#   • только сведения: [ВЫКЛ] прочих патчей (диагностика, выключенная по умолчанию), ошибки прочих патчей после итога.
# Чтение (read_folder): ТОЛЬКО по SSH (правило 22.10: шару \\@@ASTORY_SERVER_HOSTNAME@@ не трогать), FileStream с FileShare.ReadWrite (файл держит
#   работающий процесс), один вызов PowerShell с пределом времени; читается не больше MAX_BYTES с конца файла.
# Без побочных эффектов при импорте (памятка tools-no-import-side-effects). Только чтение сервера.
import base64
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
MAX_BYTES = 16 * 1024 * 1024        # предел чтения с конца файла (суточный журнал GameServer 31.10 — ~0,2 МБ)
TIMEOUT = 120                       # предел времени одного чтения по SSH, с

PASSPORT = "Хост   :"                                                    # dllmain LogHostPassport
_HEAD = re.compile(r"(\S+) — старт (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d), PID (\d+)")   # Log::Init
_TOTAL = re.compile(r"=== итог: применено (\d+), пропущено (\d+), ошибок (\d+)")
_SEP = "=" * 20                                                         # разделитель запусков Log::Init (67 «=»)
_BAD = ("[MISMATCH]", "[ОШИБКА]", "[ERR]", "[FAIL")                    # метки провала в журнале патчей
_SHORT = re.compile(r"^([A-Z]+\d+[a-z]?)_")                              # «P98_PremiumStackAmount» → «P98»


def decode_log(raw):
    """Байты журнала → текст. Log.cpp пишет cp1251 (WideCharToMultiByte 1251); строгий UTF-8 — на случай другой сборки
    (★ 26.10: проверка «есть байт D0 → UTF-8» ошибалась на cp1251, D0 = «Р»)."""
    if raw[:3] == b"\xef\xbb\xbf":
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", "replace")


def last_run(text):
    """Последний запуск в журнале: словарь head (строка шапки), product, start, pid, install (строки от паспорта до итога
    включительно), runtime (после итога), total (строка итога или ''). Нет паспорта — None."""
    ls = [l.rstrip("\r") for l in text.splitlines()]
    starts = [i for i, l in enumerate(ls) if PASSPORT in l]
    if not starts:
        return None
    s = starts[-1]
    head, product, start, pid = "", "", "", None
    # Шапка Log::Init стоит выше паспорта, но между ними Config пишет по строке «+ раздел [Pxx] добавлен…» на каждый новый
    #   раздел ini (запуск 14:38 31.10 — 4 строки) — поэтому без предела: назад до разделителя «=====» этого запуска,
    #   прежнего паспорта или начала текста.
    prev = starts[-2] if len(starts) > 1 else -1
    for j in range(s - 1, prev, -1):
        m = _HEAD.search(ls[j])
        if m:
            head, product, start, pid = ls[j].strip(), m.group(1), m.group(2), int(m.group(3))
            break
        if _SEP in ls[j]:
            break
    block = ls[s:]
    end = next((i for i, l in enumerate(block) if "=== итог" in l), None)
    install = block if end is None else block[:end + 1]
    runtime = [] if end is None else block[end + 1:]
    return {"head": head, "product": product, "start": start, "pid": pid, "install": install, "runtime": runtime,
            "total": block[end].strip() if end is not None else ""}


def _refers(line, patch):
    """Строка ссылается на патч: имя раздела или короткий номер с двоеточием, пробелом или «]» («P98:», «N22 », «[P53]»)."""
    if patch in line:
        return True
    m = _SHORT.match(patch)
    return bool(m) and re.search(r"(?<![A-Za-z0-9])" + re.escape(m.group(1)) + r"[:\s\]]", line) is not None


def judge(text, patches=(), need=(), pids=None):
    """Вердикт по журналу: (ok, why, info). patches — разделы, которым нужен «[OK]» (напр. 'P98_PremiumStackAmount');
    need — подстроки, обязательные в блоке последнего запуска; pids — PID работающих процессов этой папки (None — не
    сверять). why — причины провала; info — словарь: run (last_run), ok_count, notes (сведения, не провал)."""
    run = last_run(text)
    info = {"run": run, "ok_count": 0, "notes": []}
    if run is None:
        return False, ["в журнале нет строки паспорта «%s» — запуск не найден" % PASSPORT.strip()], info
    why = []
    inst, rt = run["install"], run["runtime"]
    block = inst + rt
    if pids is not None:
        if not pids:
            why.append("процесс этой папки не работает")
        elif run["pid"] is None:
            why.append("нет шапки старта с PID перед паспортом — свежесть запуска не подтверждена")
        elif run["pid"] not in pids:
            why.append("последний запуск в журнале — PID %d, а работают %s (новый процесс в журнал не писал)"
                       % (run["pid"], ", ".join(map(str, sorted(pids)))))
    if not run["total"]:
        why.append("нет «=== итог» в блоке последнего запуска (установка не завершена, Version не поддерживается или журнал оборван)")
    else:
        m = _TOTAL.search(run["total"])
        if m and m.group(3) != "0":
            why.append(run["total"])
    for l in inst:
        t = l.strip()
        if any(b in t for b in _BAD) or "не поддерживается" in t or "MasterEnable=0" in t:
            why.append(t[:220])
    info["ok_count"] = sum(1 for l in inst if "[OK]" in l)
    for p in patches:
        if not any("[OK]" in l and p in l for l in inst):
            why.append("нет «[OK] %s»" % p)
        for l in inst:
            if "[ВЫКЛ]" in l and p in l:
                why.append(l.strip()[:220])
    for n in need:
        if not any(n in l for l in block):
            why.append("нет строки «%s»" % n)
    for l in rt:
        t = l.strip()
        if any(b in t for b in _BAD):
            if any(_refers(t, p) for p in patches):
                why.append("после итога: " + t[:200])
            else:
                info["notes"].append("после итога (не ожидаемый патч): " + t[:160])
    info["notes"] += ["прочий выключен: " + l.strip()[:120] for l in inst
                      if "[ВЫКЛ]" in l and not any(p in l for p in patches)]
    return not why, why, info


def _ssh_ps(script, timeout):
    """PowerShell на сервере по SSH (общая функция deploy_p90.ps); (код, вывод). Предел времени — TimeoutExpired → код -1."""
    from deploy_p90 import ps
    try:
        return ps(script, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, "SSH не ответил за %d с" % timeout


def read_folder(folder, timeout=TIMEOUT, max_bytes=MAX_BYTES, v2=V2, runner=None):
    """Журнал патчей папки стойки (v2\\<folder>\\Log\\Log_Patch, самый поздний по имени файл строго PatchLog_<8 цифр>.txt —
    «PatchLog_20261031 - копия.txt» не берётся) и PID процессов, чей exe лежит прямо в этой папке. Возврат (имя файла, текст,
    pids, ошибка) — при ошибке текст ''. runner(script, timeout) → (код, вывод) — по умолчанию SSH; test_patchlog подаёт
    локальный PowerShell и свою папку v2. Только чтение."""
    from deploy_p90 import q
    root = v2 + "\\" + folder
    script = (
        "$d = %s; $f = Get-ChildItem -LiteralPath $d -Filter 'PatchLog_*.txt' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -match '^PatchLog_\\d{8}\\.txt$' } | Sort-Object Name -Descending | Select-Object -First 1; "
        "$root = %s; foreach ($p in @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
        "((Split-Path -Parent $_.ExecutablePath) -eq $root) })) { Write-Output ('PID|' + $p.ProcessId) }; "
        "if (-not $f) { Write-Output 'NOLOG'; return }; "
        "$fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite'); "
        "try { $len = $fs.Length; $n = [Math]::Min($len, %d); [void]$fs.Seek($len - $n, 'Begin'); $buf = New-Object byte[] $n; "
        "$got = 0; while ($got -lt $n) { $r = $fs.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r } } "
        "finally { $fs.Close() }; "
        "Write-Output ('FILE|' + $f.Name + '|' + $len + '|' + $got); Write-Output ('B64|' + [Convert]::ToBase64String($buf, 0, $got))"
        % (q(root + "\\Log\\Log_Patch"), q(root), max_bytes))
    rc, out = (runner or _ssh_ps)(script, timeout)
    pids = [int(l[4:]) for l in out.splitlines() if l.startswith("PID|") and l[4:].strip().isdigit()]
    if rc != 0:
        return "", "", pids, "чтение журнала %s по SSH: код %d: %s" % (folder, rc, out[-200:])
    if any(l.strip() == "NOLOG" for l in out.splitlines()):
        return "", "", pids, "журнал патчей %s не найден" % folder
    fl = [l for l in out.splitlines() if l.startswith("FILE|")]
    bl = [l for l in out.splitlines() if l.startswith("B64|")]
    if not fl or not bl:
        return "", "", pids, "журнал %s: нет ответа (%s)" % (folder, out[-200:])
    _, name, size, got = fl[-1].split("|")
    raw = base64.b64decode(bl[-1][4:].strip())
    if int(got) < int(size):                  # прочитан хвост: первая строка может быть обрезана — отбросить её
        raw = raw[raw.find(b"\n") + 1:]
    return name, decode_log(raw), pids, ""


def check_folder(folder, patches=(), need=(), log=print, timeout=TIMEOUT, check_pid=True):
    """Проверка «после старта» одной папки стойки: чтение по SSH + judge; строки отчёта — в log. Возврат (ok, info)."""
    name, text, pids, err = read_folder(folder, timeout=timeout)
    if err:
        log("%s: %s — НЕ УСТАНОВЛЕН" % (folder, err))
        return False, {"run": None, "ok_count": 0, "notes": [], "error": err}
    ok, why, info = judge(text, patches, need, pids if check_pid else None)
    run = info["run"] or {}
    log("%s: %s, последний запуск «%s»; %s; [OK] %d — %s" % (
        folder, name, run.get("head") or "шапки нет", run.get("total") or "итога нет", info["ok_count"],
        ("%s УСТАНОВЛЕН" % ", ".join(patches) if patches else "запуск чистый") if ok else "НЕ УСТАНОВЛЕН"))
    for n in need:
        hit = [l.strip() for l in (run.get("install", []) + run.get("runtime", [])) if n in l]
        if hit:
            log("  %s" % hit[-1][:220])
    for w in why:
        log("  ПРОВАЛ: %s" % w)
    for n in info["notes"][:12]:
        log("  сведения: %s" % n)
    return ok, info
