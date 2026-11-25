# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p105.py — ВЫКЛАДКА / ОТКАТ слота P105 = выключение AddonNPC N10 (волна exp-party, 05.11.2026) на dev-стойке во всех папках
#   NpcServer из stack_layout.NPC_FOLDERS (NpcServer, Indun_NpcServer, Ch2_NpcServer). Разбор: Reports/exprate/party_basic_2026-11-05/REPORT.md.
#   • [ИСПРАВЛЕНИЕ НАШЕЙ ПРАВКИ] N10_NormalAttackHateDamage (25.08) дописывала урон обычной атаки в список боя ПОВЕРХ стока: сток сам
#     записывает фактически снятое здоровье (sub_4423C0 → 0x4429A2 sub_43D2C0, урон = [ebp+14h]), а N10 на каждом 0x2009 добавляла
#     ВСЮ предсказанную очередь из 4 ударов. Урон бьющих обычной атакой завышался в 1,4–8 раз; зажим N20 давал каждому участнику
#     отряда долю как за целого моба — дележ отряда обходился.
#   • Меняется ОДНА строка: `Enabled=1` → `Enabled=0` в секции [N10_NormalAttackHateDamage] файла <папка>\ConfigSet\patches.ini
#     (UTF-16LE). DLL, NpcServer.exe, GameServer, протокол, клиент — не меняются. N20 остаётся.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: restart_stack.py --deploy deploy_p105.py; после старта NpcServer:
#     python deploy_p105.py --check-started.
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ NpcServer/Indun_NpcServer/Ch2_NpcServer):
#   1. Процессы не держат NpcServer.exe — иначе код 2.
#   2. AddonNPC.dll каждой папки — из DLLS (N10 и ключ Enabled в ней известны); иначе СТОП, код 8.
#   3. В каждом patches.ini ровно одна секция [N10_NormalAttackHateDamage] и в ней ровно одна строка Enabled=…; если уже 0 — папка
#      пропускается («уже выключено»), если не 0/1 — СТОП. Новый файл = старый с заменой ОДНОЙ строки (остальные строки сверяются
#      побайтно после обратного декодирования).
#   4. Бэкап patches.ini: рядом <файл>.bak_20261105_p105, на сервере v2\_backup\2026-11-05_p105\<папка>\ConfigSet\patches.ini,
#      локально @@ASTORY_DEV_ROOT@@\_backup\2026-11-05_exp\server\v2\<папка>\ConfigSet\patches.ini; сверка md5; существующий не перезаписывается.
#   5. Заливка по scp во временный patches.ini.p105_upload (md5), копия поверх, сверка md5.
# Откат (--rollback; при остановленных процессах): обратная правка той же строки Enabled=0 → Enabled=1 (с теми же проверками и
#   бэкапом <файл>.bak_20261105_p105r). ⚠ Откат ВОЗВРАЩАЕТ дефект (двойной учёт урона обычной атаки).
# Проверка после старта (--check-started; только чтение): последний PatchLog каждой папки — «[ВЫКЛ] N10_NormalAttackHateDamage»,
#   «[OK] N20_PartyShareClamp», итог без ошибок, PID работающего процесса (patchlog.check_folder).
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_p105_20261105_deploy/deploy.log (дописывается).
# Самопроверка правки без сервера: python deploy_p105.py --selftest <patches.ini>
import base64
import hashlib
import os
import re
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
SECTION = "N10_NormalAttackHateDamage"
DLLS = {"4b03ad7d36e3a0fcd51c0dfff19391c6": "P104 (N01…N23, Config 14) — живая с 05.11 01:50"}   # DLL, под которыми ключ проверен
SUFFIX = ".bak_20261105_p105"
SUFFIX_RB = ".bak_20261105_p105r"
SRV_BACKUP = V2 + r"\_backup\2026-11-05_p105"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-05_exp/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_p105_20261105_deploy/deploy.log"
FOLDERS = stack_layout.NPC_FOLDERS

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


def ps(script, timeout=120):
    """PowerShell-скрипт на сервере (-EncodedCommand); возврат (код, вывод utf-8)."""
    enc = base64.b64encode((PS_LIB + script).encode("utf-16-le")).decode("ascii")
    p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc], capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        out += " | " + p.stderr.decode("utf-8", "replace").strip()[-500:]
    return p.returncode, out


def q(path):
    """Строка PowerShell в одинарных кавычках."""
    return "'" + path.replace("'", "''") + "'"


def last_line(out, pred):
    """Последняя строка вывода, подходящая под pred (★ SSH PowerShell может дописать CLIXML последней строкой)."""
    for l in reversed(out.splitlines()):
        if pred(l.strip()):
            return l.strip()
    return ""


def rmd5(path):
    """md5 файла стойки ('none' — файла нет)."""
    rc, out = ps("Write-Output (Md5Of %s)" % q(path))
    h = last_line(out, lambda s: s == "NONE" or (len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s))).lower()
    if rc != 0 or not h:
        raise RuntimeError("md5 %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return h


def rbusy(path):
    """FREE / BUSY / NONE — держит ли файл процесс стойки."""
    rc, out = ps("Write-Output (IsBusy %s)" % q(path))
    st = last_line(out, lambda s: s in ("FREE", "BUSY", "NONE"))
    if rc != 0 or not st:
        raise RuntimeError("проверка занятости %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return st


def rread(path):
    """Содержимое файла стойки (чтение с совместным доступом)."""
    rc, out = ps("$fs = [IO.File]::Open(%s, 'Open', 'Read', 'ReadWrite'); try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms) } "
                 "finally { $fs.Close() }; Write-Output ('B64:' + [Convert]::ToBase64String($ms.ToArray()))" % q(path), timeout=300)
    b = last_line(out, lambda s: s.startswith("B64:"))
    if rc != 0 or not b:
        raise RuntimeError("чтение %s по SSH: код %d: %s" % (path, rc, out[-300:]))
    return base64.b64decode(b[4:])


def rcopy(src, dst):
    """Копия на сервере src → dst (папка создаётся)."""
    rc, out = ps("$d = Split-Path -Parent %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                 "Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output OK" % (q(dst), q(src), q(dst)))
    if rc != 0 or not last_line(out, lambda s: s == "OK"):
        raise RuntimeError("копия %s → %s по SSH: код %d: %s" % (src, dst, rc, out[-300:]))


def rupload(data, remote):
    """Залить байты на сервер по scp во временный файл remote (через локальный временный файл)."""
    tmp = os.path.join(os.path.dirname(LOG), "upload.tmp")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(data)
    dst = "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + remote.replace("\\", "/")
    try:
        p = subprocess.run(["scp", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", tmp, dst],
                           capture_output=True, timeout=300)
    finally:
        os.remove(tmp)   # ревизия 05.11: не оставлять временный файл при исключении scp
    if p.returncode != 0:
        raise RuntimeError("заливка → %s по scp: код %d: %s" % (remote, p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")[-300:]))


def rdel(path):
    """Удалить временный файл на сервере (ошибки игнорируются)."""
    ps("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; Write-Output OK" % q(path))


def md5b(data):
    """md5 байтов (hex)."""
    return hashlib.md5(data).hexdigest()


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def edit_ini(raw, want):
    """Правка patches.ini (байты UTF-16LE): в секции [N10_NormalAttackHateDamage] строка Enabled=<0|1> → Enabled=<want>.
    Возврат (новые байты | None если уже want, было, описание). Исключение — если структура не та (ничего не трогаем)."""
    bom = raw[:2] == b"\xff\xfe"
    body = raw[2:] if bom else raw
    if len(body) % 2:
        raise RuntimeError("patches.ini: нечётная длина — не UTF-16LE")
    text = body.decode("utf-16-le")
    # строки с сохранением разделителей (в файле встречаются и CRLF, и одиночные CR)
    parts = re.split(r"(\r\n|\r|\n)", text)
    lines, seps = parts[0::2], parts[1::2] + [""]
    heads = [i for i, l in enumerate(lines) if l.strip().lower() == "[%s]" % SECTION.lower()]
    if len(heads) != 1:
        raise RuntimeError("секций [%s] %d (нужна ровно одна)" % (SECTION, len(heads)))
    start = heads[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    keys = [i for i in range(start, end) if re.match(r"^\s*Enabled\s*=", lines[i], re.I)]
    if len(keys) != 1:
        raise RuntimeError("в секции [%s] строк Enabled= %d (нужна ровно одна)" % (SECTION, len(keys)))
    k = keys[0]
    m = re.match(r"^(\s*Enabled\s*=\s*)(\S*)(\s*)$", lines[k], re.I)
    if not m or m.group(2) not in ("0", "1"):
        raise RuntimeError("строка %d «%s»: значение не 0/1" % (k + 1, lines[k]))
    was = m.group(2)
    if was == want:
        return None, was, "строка %d «%s» — уже %s" % (k + 1, lines[k].strip(), want)
    new_lines = list(lines)
    new_lines[k] = m.group(1) + want + m.group(3)
    new_text = "".join(l + s for l, s in zip(new_lines, seps))
    new_raw = (b"\xff\xfe" if bom else b"") + new_text.encode("utf-16-le")
    # сверка: обратное декодирование, отличается ровно одна строка
    back = re.split(r"(\r\n|\r|\n)", (new_raw[2:] if bom else new_raw).decode("utf-16-le"))
    diff = [i for i, (a, b) in enumerate(zip(parts, back)) if a != b]
    if len(back) != len(parts) or diff != [2 * k] or len(new_raw) != len(raw):
        raise RuntimeError("самопроверка правки не сошлась (отличия в частях %s)" % diff[:5])
    return new_raw, was, "строка %d «%s» → «%s»" % (k + 1, lines[k].strip(), new_lines[k].strip())


def backup_one(src, data, suffix, lines):
    """Бэкап файла стойки: рядом (suffix), в v2\\_backup\\2026-11-05_p105 и локально; существующие не перезаписываются (сверка md5)."""
    want = md5b(data)
    rel = src[len(V2) + 1:]
    for dst in (src + suffix, SRV_BACKUP + ("" if suffix == SUFFIX else "_rollback") + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
        else:
            log(lines, "  бэкап уже есть: %s (%s)" % (dst, have))
    loc = LOCAL_BACKUP + ("" if suffix == SUFFIX else "_rollback") + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        with open(loc, "rb") as f:
            if md5b(f.read()) != want:
                raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл — разберись вручную" % loc)
        log(lines, "  локальный бэкап уже есть: %s" % loc)
        return
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    log(lines, "  локальный бэкап: %s %d б %s" % (loc, len(data), want))


def check_started(lines):
    """После старта: PatchLog каждой папки — N20 [OK], N10 [ВЫКЛ], запуск чистый. Только чтение."""
    import patchlog
    good = True
    for d in FOLDERS:
        ok, info = patchlog.check_folder(d, ["N20_PartyShareClamp"], [SECTION], log=lambda s: log(lines, s))
        run = info.get("run") or {}
        hit = [l for l in (run.get("install", []) + run.get("runtime", [])) if SECTION in l]
        off = any("[ВЫКЛ]" in l for l in hit) and not any("[OK]" in l for l in hit)
        log(lines, "  %s: N10 %s" % (d, "ВЫКЛЮЧЕН — как задумано" if off else "НЕ ВЫКЛЮЧЕН (%s)" % (hit[-1][:160] if hit else "строки нет")))
        good = good and ok and off
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def selftest(path):
    """Правка локальной копии patches.ini без сервера: 1→0 и обратно даёт исходные байты."""
    with open(path, "rb") as f:
        raw = f.read()
    new, was, what = edit_ini(raw, "0")
    print("1) %s; было %s; md5 %s → %s" % (what, was, md5b(raw), md5b(new) if new else "-"))
    if new is None:
        return 0
    back, was2, what2 = edit_ini(new, "1")
    print("2) откат: %s; совпадает с исходным: %s" % (what2, back == raw))
    again, _, what3 = edit_ini(new, "0")
    print("3) повтор: %s (правки нет: %s)" % (what3, again is None))
    return 0 if back == raw and again is None else 1


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started, --selftest."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--selftest" in sys.argv:
        return selftest(sys.argv[sys.argv.index("--selftest") + 1])
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p105 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    if "--check-started" in sys.argv:
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    want = "1" if rollback else "0"
    try:
        busy = [V2 + "\\" + d + "\\NpcServer.exe" for d in FOLDERS if rbusy(V2 + "\\" + d + "\\NpcServer.exe") == "BUSY"]
        if busy:
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if apply or rollback:
                log(lines, "СТОП: процессы NpcServer не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")
        plan = []
        for d in FOLDERS:   # сначала проверка ВСЕХ папок, потом запись
            dll = rmd5(V2 + "\\" + d + "\\AddonNPC.dll")
            if dll not in DLLS:
                log(lines, "СТОП: AddonNPC.dll в %s = %s — не из проверенных (%s); ничего не трогаю" % (d, dll, ", ".join(DLLS)))
                flush(lines)
                return 8
            ini = V2 + "\\" + d + "\\ConfigSet\\patches.ini"
            raw = rread(ini)
            new, was, what = edit_ini(raw, want)
            log(lines, "%s: AddonNPC %s (%s); patches.ini %s: %s" % (d, dll, DLLS[dll], md5b(raw), what))
            if new is not None:
                plan.append((d, ini, raw, new))
        if not plan:
            log(lines, "ГОТОВО: нечего делать — во всех папках уже Enabled=%s" % want)
            flush(lines)
            return 0
        if not (apply or rollback):
            log(lines, "сухой прогон: всё готово к --apply (%d файл(а))" % len(plan))
            flush(lines)
            return 0
        for d, ini, raw, new in plan:
            if rmd5(ini) != md5b(raw):
                log(lines, "СТОП: %s изменился после чтения — ничего не пишу" % ini)
                flush(lines)
                return 4
            backup_one(ini, raw, SUFFIX_RB if rollback else SUFFIX, lines)
            up = ini + ".p105_upload"
            rupload(new, up)
            if rmd5(up) != md5b(new):
                rdel(up)
                log(lines, "СТОП: залитый %s не сошёлся по md5 — patches.ini не тронут" % up)
                flush(lines)
                return 4
            rcopy(up, ini)
            rdel(up)
            got = rmd5(ini)
            log(lines, "%s: patches.ini %s → %s %s" % (d, md5b(raw), got, "OK" if got == md5b(new) else "НЕ СОШЛОСЬ"))
            if got != md5b(new):
                flush(lines)
                return 4
        log(lines, ("ОТКАТ ГОТОВ: N10 снова Enabled=1 (⚠ возвращает двойной учёт урона обычной атаки). " if rollback else
                    "ГОТОВО: N10 Enabled=0 во всех папках NpcServer. ") +
                   "Старт процессов — за координатором; затем python deploy_p105.py --check-started.")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
