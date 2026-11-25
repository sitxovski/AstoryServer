# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stack_parity.py — паритет копий канала 2 с полем (26.10.2026; PLAN Reports/channel2/PLAN.md §5).
#
# Ch2_GameServer / Ch2_NpcServer / Ch2_RelayServer — побайтные копии GameServer / NpcServer / RelayServer, кроме
# поканальных файлов (stack_layout.CHANNEL_FILES), журналов (LOG_DIRS) и бэкапов. Скрипт сверяет md5 всех файлов
# по SSH (только чтение) и печатает расхождения; исполняемые файлы копий сверяются с stack_layout.EXE_MD5.
#   python stack_parity.py            — сверка; код 0 = паритет, 6 = СУЩЕСТВЕННЫЕ расхождения (exe/dll/patches.ini, нет папки),
#                                        8 = расхождения только в данных, 7 = ошибка SSH. Файлы, которые серверы пишут во время
#                                        работы (stack_layout.RUNTIME_FILES: EventLog.txt, *.log, ErrTrace.txt, …), не сверяются.
#   python stack_parity.py --sync     — то же, затем каждый расходящийся/недостающий файл копии берётся с поля
#                                        (бэкап прежнего в v2\_backup\<дата>_parity\…), и повторная сверка
# restart_stack.py зовёт --sync после выкладки и не запускает стойку, если паритета нет (код 6).
# Без побочных эффектов при импорте.
import base64
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout as L   # noqa: E402

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
       "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
# Файлы, которые копия не берёт с поля (как при создании копии 26.10): дампы, бэкапы, старые копии exe.
SKIP_NAME = ["*.dmp", "*.bak*", "*.pre*", "*.running*", "*.new_*", "*.exe11122", "*.exe222", "*.exe_copy", "Copy*", "ErrTrace.txt",
             "*.p9*_upload", "*.p8*_upload"]


def run_ps(script, timeout=600):
    """PowerShell-скрипт на сервере ФАЙЛОМ (scp во временный .ps1 с BOM, затем -File): у -EncodedCommand предел длины
    командной строки (длинный список файлов не влезает). Возврат (код, stdout, stderr)."""
    body = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8\n" + script).encode("utf-8-sig")
    name = "asda_tool_%d_%d.ps1" % (os.getpid(), int(time.time() * 1000))
    local = os.path.join(os.environ.get("TEMP", HERE), name)
    remote = "C:/Users/Administrator/AppData/Local/Temp/" + name
    with open(local, "wb") as f:
        f.write(body)
    try:
        up = subprocess.run(["scp", "-q"] + SSH[1:-1] + [local, SSH[-1] + ":" + remote], capture_output=True, timeout=120)
        if up.returncode != 0:
            return up.returncode, "", up.stderr.decode("utf-8", "replace")
        p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + remote.replace("/", "\\") +
                                  " & del " + remote.replace("/", "\\")], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    finally:
        try:
            os.remove(local)
        except OSError:
            pass


def ps_list(arr):
    return "@(" + ",".join("'" + a.replace("'", "''") + "'" for a in arr) + ")" if arr else "@()"


def scan(folders):
    """{папка: {относительный путь (нижний регистр): (путь, md5)}} по SSH. Журналы и SKIP_NAME не входят."""
    script = (
        "$v2 = '%s'; $skip = %s; $logs = %s\n"
        "foreach ($d in %s) { $root = Join-Path $v2 $d; if (-not (Test-Path $root)) { Write-Output ('NODIR|' + $d); continue }\n"
        "  Get-ChildItem -LiteralPath $root -Recurse -File -Force | ForEach-Object {\n"
        "    $rel = $_.FullName.Substring($root.Length + 1); $parts = $rel.Split('\\');\n"
        "    $isLog = $false; foreach ($p in $parts[0..($parts.Length-2)]) { if ($logs -contains $p) { $isLog = $true } }\n"
        "    $sk = $false; foreach ($w in $skip) { if ($_.Name -like $w) { $sk = $true } }\n"
        "    if (-not $isLog -and -not $sk) {\n"
        "      try { $fs = New-Object IO.FileStream($_.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite);\n"
        "            $h = [BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($fs)).Replace('-','').ToLower(); $fs.Close() }\n"
        "      catch { $h = 'LOCKED' }\n"
        "      Write-Output ('F|' + $d + '|' + $rel + '|' + $h) } } }\n"
        % (V2, ps_list(SKIP_NAME), ps_list(L.LOG_DIRS), ps_list(folders)))
    rc, out, err = run_ps(script)
    if rc != 0 and not out:
        raise RuntimeError("SSH: %s" % err.strip()[:300])
    res = {f: {} for f in folders}
    for line in out.splitlines():
        if line.startswith("NODIR|"):
            res.pop(line.split("|", 1)[1].strip(), None)
        elif line.startswith("F|"):
            _, d, rel, h = line.rstrip("\r").split("|", 3)
            res.setdefault(d, {})[rel.lower()] = (rel, h)
    return res


def is_channel_file(twin, rel):
    for c in L.CHANNEL_FILES.get(twin, []):
        c = c.lower()
        if (c.endswith("\\") and rel.startswith(c)) or rel == c:
            return True
    return False


def compare(data):
    """Список расхождений [(вид, копия, путь, md5 поля, md5 копии)]."""
    diffs = []
    for twin, field in L.TWINS.items():
        if twin not in data:
            diffs.append(("нет папки", twin, "", "", ""))
            continue
        f, t = data.get(field, {}), data[twin]
        for key, (rel, h) in f.items():
            if is_channel_file(twin, key) or L.is_runtime_file(os.path.basename(rel)):   # ★ 26.10: пишутся во время работы
                continue
            if key not in t:
                diffs.append(("нет в копии", twin, rel, h, ""))
            elif t[key][1] != h:
                diffs.append(("другой md5", twin, rel, h, t[key][1]))
        for key, (rel, h) in t.items():
            if key not in f and not is_channel_file(twin, key) and not L.is_runtime_file(os.path.basename(rel)):
                diffs.append(("лишний в копии", twin, rel, "", h))
        # исполняемые файлы копии — по stack_layout.EXE_MD5
        for full, want in L.EXE_MD5.items():
            d, _, rel = full.partition("\\")
            if d == twin:
                got = t.get(rel.lower(), (rel, "нет"))[1]
                if got != want:
                    diffs.append(("exe не тот", twin, rel, want, got))
    return diffs


def sync(diffs, lines):
    r"""Расходящиеся и недостающие файлы копии — с поля (бэкап прежнего), лишние не трогаем (только отчёт).
    ★ 26.10.2026 (инцидент 18:55): прежняя версия передавала пары вложенным массивом @(@('a','b')) — при ОДНОЙ паре
    PowerShell разворачивал его в плоский @('a','b'), цикл шёл по СТРОКАМ, и $it[0]/$it[1] были буквами ('C'|'h', 'E'|'v'):
    создавались пустые каталоги v2\C, v2\E, Copy-Item из несуществующего источника давал «мягкую» ошибку мимо try,
    а строка «бэкап прежних» печаталась всегда. Теперь: пары — строками 'копия|путь' (без вложенных массивов), проверка
    копии/пути в Python, -ErrorAction Stop, md5 после копии, бэкап — с подтверждением, отчёт о нём — только если сделан."""
    todo = []
    for kind, twin, rel, fh, th in diffs:
        if kind not in ("нет в копии", "другой md5"):
            continue
        if twin not in L.TWINS or not rel or ".." in rel or ":" in rel or rel.startswith(("\\", "/")) \
                or "|" in rel or "'" in rel or L.is_runtime_file(os.path.basename(rel)):
            lines.append("  ОТКАЗ синхронизации (недопустимая пара): %s | %s" % (twin, rel))
            continue
        todo.append((twin, rel))
    if not todo:
        return 0
    stamp = time.strftime("%Y-%m-%d_%H%M")
    items = ",".join("'%s|%s'" % (twin, rel) for twin, rel in todo)
    fields = ";".join("'%s'='%s'" % (t, f) for t, f in L.TWINS.items())
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$v2 = '%s'; $bk = Join-Path $v2 '_backup\\%s_parity'; $fields = @{%s}\n"
        "function Get-Md5x([string]$p) { $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite'); try { "
        "([BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($fs))).Replace('-','') } finally { $fs.Close() } }\n"
        "[string[]]$items = @(%s)\n"
        "foreach ($it in $items) { $pp = $it.Split('|', 2); $twin = $pp[0]; $rel = $pp[1]; $field = $fields[$twin]\n"
        "  try { if (-not $field) { throw ('нет поля для ' + $twin) }\n"
        "        $src = Join-Path (Join-Path $v2 $field) $rel; $dst = Join-Path (Join-Path $v2 $twin) $rel\n"
        "        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw ('нет источника ' + $src) }\n"
        "        if (Test-Path -LiteralPath $dst -PathType Leaf) { $b = Join-Path (Join-Path $bk $twin) $rel\n"
        "          New-Item -ItemType Directory -Force -Path (Split-Path $b) | Out-Null; Copy-Item -LiteralPath $dst -Destination $b -Force\n"
        "          if ((Get-Md5x $b) -ne (Get-Md5x $dst)) { throw ('бэкап не сошёлся ' + $b) }; Write-Output ('BK|' + $b) }\n"
        "        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null; Copy-Item -LiteralPath $src -Destination $dst -Force\n"
        "        $h = Get-Md5x $dst; if ($h -ne (Get-Md5x $src)) { throw ('после копии md5 не сошёлся ' + $dst) }\n"
        "        Write-Output ('SYNC|' + $twin + '|' + $rel + '|' + $h) }\n"
        "  catch { Write-Output ('SYNCERR|' + $twin + '|' + $rel + '|' + $_.Exception.Message) } }\n"
        % (V2, stamp, fields, items))
    rc, out, err = run_ps(script)
    n = nb = 0
    for line in out.splitlines():
        if line.startswith("SYNC|"):
            n += 1
            lines.append("  взят с поля: " + line[5:].strip())
        elif line.startswith("BK|"):
            nb += 1
            lines.append("  бэкап прежней копии: " + line[3:].strip())
        elif line.startswith("SYNCERR|"):
            lines.append("  ОШИБКА копии: " + line[8:].strip())
    if rc != 0:
        lines.append("  ОШИБКА SSH при синхронизации: %s" % err.strip()[-300:])
    if not nb:
        lines.append("  бэкапов не понадобилось (в копии не было прежних версий файлов)")
    return n


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    folders = list(L.TWINS.values()) + list(L.TWINS.keys())
    lines = ["== stack_parity %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "--sync" if "--sync" in sys.argv else "сверка")]
    try:
        data = scan(folders)
        diffs = compare(data)
        if diffs and "--sync" in sys.argv:
            n = sync(diffs, lines)
            lines.append("  синхронизировано файлов: %d; повторная сверка" % n)
            data = scan(folders)
            diffs = compare(data)
    except Exception as e:
        print("\n".join(lines + ["ОШИБКА: %s" % e]))
        return 7
    for twin, field in L.TWINS.items():
        lines.append("  %s ↔ %s: файлов %d / %d" % (twin, field, len(data.get(twin, {})), len(data.get(field, {}))))
    for kind, twin, rel, fh, th in diffs:
        lines.append("  РАСХОЖДЕНИЕ %s: %s\\%s (поле %s, копия %s)" % (kind, twin, rel, fh or "-", th or "-"))
    lines.append("ПАРИТЕТ: %s" % ("ДА" if not diffs else "НЕТ (%d)" % len(diffs)))
    print("\n".join(lines))
    # ★ 26.10.2026: код 6 — СУЩЕСТВЕННЫЕ расхождения (exe/dll/patches.ini, нет папки, exe копии не тот); прочие данные — код 8
    essential = [d for d in diffs if d[0] in ("нет папки", "exe не тот") or L.is_essential(d[2])]
    if diffs:
        print("  из них существенных (exe/dll/patches.ini): %d" % len(essential))
    return 0 if not diffs else (6 if essential else 8)


if __name__ == "__main__":
    sys.exit(main())
