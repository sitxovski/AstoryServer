# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p81_crouch132.py — ПРАВКА INI существующего P81 (без номера патча): коды 4024 приседа стоя 132/133 в
#   [P81_ActionCodeGuard] AllowedCodes (сессия crouch-stand, 05.11.2026) на dev-стойке во всех папках GameServer из
#   stack_layout.GS_FOLDERS (GameServer, Indun_GameServer, Ch2_GameServer). DLL не меняется.
#   Разбор: клиент `AstoryClient/Source/AsdaReborn/Public/World/AsdaCrouchStand.h` (ключ asda.Crouch.StandRelay).
#   • [ПОРТ] Стоя присед серверу через 4006 не передать (CharMove@0x544EB0 отвергает ход в ту же клетку: result 0, статус не
#     пишется, рассылки нет). Клиент шлёт 4024 132 «присел стоя» / 133 «встал»; сток (`CharEMotionSync` sub_546730) пишет код в
#     CUser+0x54E4 и рассылает 4025 сектору. P81 (Mode=1) коды вне AllowedCodes ОТКЛОНЯЕТ с журналом ac.other 88.
#   • Меняется ОДНА строка: AllowedCodes=100-110;112-117;122;124;127;128;131;400 → …;131-133;400 (UTF-16LE patches.ini).
#     Сток 132/133 особо не трактует (читатели CUser+0x54E4 сравнивают только с 2/4/8, 108, 200, 300/301). Разбор «a-b» —
#     `ParseAllowed` P81 (p81_action_code_guard.cpp:163), формат с v53 не менялся; слияние Config DLL дописывает только
#     недостающие ключи — значение AllowedCodes переживает подъём Version (v63…v65).
#   ★ Порядок выпуска: сервер РАНЬШЕ клиента с приседом стоя.
#   ★ Выкладка — ТОЛЬКО координатор, одним перезапуском вместе с общим скриптом (restart_stack.py принимает один --deploy):
#     общий deploy_*.py зовёт `run("apply"|"rollback"|"check"|"dry", lines)` этого модуля (импорт без побочных эффектов).
#     Отдельно: python deploy_p81_crouch132.py [--apply|--rollback|--check-started].
#
# --apply (GameServer остановлены): 1) GameServer.exe не занят — иначе 2; 2) AsdaPatch.dll каждой папки из DLLS — иначе 8;
#   3) ровно одна секция [P81_ActionCodeGuard] и одна строка AllowedCodes= со значением OLD (правим) или NEW (пропуск); иное — СТОП;
#   4) бэкап: рядом <файл>.bak_20261105_crouch132, v2\_backup\2026-11-05_crouch132\…, локально
#   @@ASTORY_DEV_ROOT@@\_backup\2026-11-05_crouch-stand\server\v2\…; 5) заливка scp во временный .crouch132_upload, сверка md5.
# --rollback: NEW → OLD (бэкап .bak_20261105_crouch132r). ⚠ при выпущенном клиенте соседи не видят присед стоя, журнал 88.
# --check-started (только чтение): PatchLog каждой папки — [OK] P81 и «131-133» в строке разрешённых кодов.
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_crouch132_20261105_deploy/deploy.log.
# Самопроверка правки без сервера: python deploy_p81_crouch132.py --selftest <patches.ini>
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
SECTION = "P81_ActionCodeGuard"
KEY = "AllowedCodes"
OLD = "100-110;112-117;122;124;127;128;131;400"   # живое значение на 05.11.2026 (3 GS)
NEW = "100-110;112-117;122;124;127;128;131-133;400"   # + 132 присел стоя, 133 встал (порт)
DLLS = {   # AsdaPatch, под которыми ключ проверен (разбор AllowedCodes P81 одинаков с v53)
    "9862a5deb2ddb25616ba2a7f6272c468": "v63 (P100 EchoAllCodes + P106) — живая с 05.11 12:21",
    "512e80c81bfdb70552cbeae2a8916d63": "v64 (v63 + P107 CantActGate; tools/p107_data)",
    "6f644a7671ff331ebc6c4c81dfc2f2a5": "v65 (P100 + P106 + P107 + P108) — общая выкладка",
}
SUFFIX = ".bak_20261105_crouch132"
SUFFIX_RB = ".bak_20261105_crouch132r"
SRV_BACKUP = V2 + r"\_backup\2026-11-05_crouch132"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-05_crouch-stand/server/v2"
LOG = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/run_crouch132_20261105_deploy/deploy.log"
FOLDERS = stack_layout.GS_FOLDERS

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


def _ini_encoding(raw):
    """Кодировка patches.ini: (префикс BOM, кодек). UTF-16LE с BOM (как пишет DLL) / UTF-16LE без BOM (нули в нечётных байтах) /
    ANSI — побайтно (latin-1: каждый байт ↔ символ, файл восстанавливается байт в байт)."""
    if raw[:2] == b"\xff\xfe":
        if (len(raw) - 2) % 2:
            raise RuntimeError("patches.ini: нечётная длина после BOM UTF-16LE")
        return b"\xff\xfe", "utf-16-le"
    # Без BOM — по тому, в каком виде в файле стоит заголовок секции (первые строки бывают псевдографикой — счёт нулей врёт).
    head = ("[%s]" % SECTION)
    if len(raw) % 2 == 0 and head.encode("utf-16-le") in raw:
        return b"", "utf-16-le"
    return b"", "latin-1"


def new_ini_bytes(old):
    """ЧИСТАЯ функция для общего скрипта выкладки: байты patches.ini → байты с AllowedCodes=NEW (только эта строка; кодировка,
    BOM и переводы строк сохраняются). Уже NEW — те же байты. Значение не OLD/NEW или структура не та — RuntimeError."""
    new, _, _ = edit_ini(old, NEW)
    return old if new is None else new


def old_ini_bytes(cur):
    """Обратная к `new_ini_bytes` (откат): AllowedCodes=NEW → OLD; уже OLD — те же байты."""
    new, _, _ = edit_ini(cur, OLD)
    return cur if new is None else new


def edit_ini(raw, want):
    """Правка patches.ini (UTF-16LE или ANSI, см. `_ini_encoding`): в секции [P81_ActionCodeGuard] строка AllowedCodes=<OLD|NEW> → AllowedCodes=<want>.
    Возврат (новые байты | None если уже want, было, описание). Исключение — если структура/значение не те (ничего не трогаем)."""
    if want not in (OLD, NEW):
        raise RuntimeError("целевое значение «%s» — не OLD/NEW" % want)
    pre, enc = _ini_encoding(raw)
    text = raw[len(pre):].decode(enc)
    parts = re.split(r"(\r\n|\r|\n)", text)   # строки с разделителями (в файле бывают CRLF и одиночные CR)
    lines, seps = parts[0::2], parts[1::2] + [""]
    heads = [i for i, l in enumerate(lines) if l.strip().lower() == "[%s]" % SECTION.lower()]
    if len(heads) != 1:
        raise RuntimeError("секций [%s] %d (нужна ровно одна)" % (SECTION, len(heads)))
    start = heads[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    keys = [i for i in range(start, end) if re.match(r"^\s*%s\s*=" % KEY, lines[i], re.I)]
    if len(keys) != 1:
        raise RuntimeError("в секции [%s] строк %s= %d (нужна ровно одна)" % (SECTION, KEY, len(keys)))
    k = keys[0]
    m = re.match(r"^(\s*%s\s*=\s*)(\S*)(\s*)$" % KEY, lines[k], re.I)
    if not m or m.group(2) not in (OLD, NEW):
        raise RuntimeError("строка %d «%s»: значение не OLD/NEW — список правили вручную, разберись" % (k + 1, lines[k]))
    was = m.group(2)
    if was == want:
        return None, was, "строка %d «%s» — уже так" % (k + 1, lines[k].strip())
    new_lines = list(lines)
    new_lines[k] = m.group(1) + want + m.group(3)
    new_text = "".join(l + sp for l, sp in zip(new_lines, seps))
    new_raw = pre + new_text.encode(enc)
    back = re.split(r"(\r\n|\r|\n)", new_raw[len(pre):].decode(enc))
    diff = [i for i, (a, b) in enumerate(zip(parts, back)) if a != b]
    if len(back) != len(parts) or diff != [2 * k]:
        raise RuntimeError("самопроверка правки не сошлась (отличия в частях %s)" % diff[:5])
    return new_raw, was, "строка %d «%s» → «%s»" % (k + 1, lines[k].strip(), new_lines[k].strip())


def backup_one(src, data, suffix, lines):
    """Бэкап файла стойки: рядом (suffix), в v2\\_backup\\2026-11-05_crouch132 и локально; существующие не перезаписываются (сверка md5)."""
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
    """После старта: PatchLog каждой папки GameServer — [OK] P81, в строке разрешённых кодов «131-133», запуск чистый. Только чтение."""
    import patchlog
    good = True
    for d in FOLDERS:
        ok, info = patchlog.check_folder(d, [SECTION], [], log=lambda s: log(lines, s))
        run = info.get("run") or {}
        hit = [l for l in (run.get("install", []) + run.get("runtime", [])) if "P81" in l and "4024" in l]
        codes = any("131-133" in l for l in hit)
        log(lines, "  %s: коды P81 %s" % (d, "с 132/133 — как задумано" if codes else "БЕЗ 132/133 (%s)" % (hit[-1][:160] if hit else "строки нет")))
        good = good and ok and codes
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def selftest(path):
    """Правка локальной копии patches.ini без сервера: OLD→NEW и обратно даёт исходные байты, повтор — без правки."""
    with open(path, "rb") as f:
        raw = f.read()
    new, was, what = edit_ini(raw, NEW)
    print("1) %s; было %s; md5 %s → %s" % (what, was, md5b(raw), md5b(new) if new else "-"))
    if new is None:
        return 0
    back, was2, what2 = edit_ini(new, OLD)
    print("2) откат: %s; совпадает с исходным: %s" % (what2, back == raw))
    again, _, what3 = edit_ini(new, NEW)
    print("3) повтор: %s (правки нет: %s)" % (what3, again is None))
    ok = back == raw and again is None
    # чистые функции и другие кодировки (та же правка на копии в ANSI и в UTF-16LE без BOM)
    n1 = new_ini_bytes(raw); ok = ok and n1 == new and new_ini_bytes(n1) == n1 and old_ini_bytes(n1) == raw
    txt = raw[2:].decode("utf-16-le")
    for name, data in (("ANSI", txt.encode("latin-1", "replace")), ("UTF-16LE без BOM", raw[2:])):
        if name == "ANSI" and any(ord(c) > 255 for c in txt):
            data = "".join(c if ord(c) < 256 else "?" for c in txt).encode("latin-1")
        n2 = new_ini_bytes(data); r2 = old_ini_bytes(n2)
        good = n2 != data and r2 == data and NEW.encode("utf-16-le" if "UTF" in name else "latin-1") in n2
        print("4) %s: правка %s, откат байт в байт %s" % (name, "есть" if n2 != data else "НЕТ", r2 == data))
        ok = ok and good
    print("5) new_ini_bytes/old_ini_bytes: %s" % ("сходятся" if n1 == new else "РАСХОДЯТСЯ"))
    return 0 if ok else 1


def _run(mode, lines):
    """Ядро для встраивания в общий скрипт выкладки (без побочных эффектов при импорте). mode: "dry" — сухой прогон (только
    чтение), "apply" — правка (GameServer остановлены), "rollback" — откат, "check" — проверка после старта. lines — накопитель
    строк журнала вызывающего (сюда же пишет и собственный журнал модуля). Возврат — код (0 — успех/готово)."""
    apply = mode == "apply"
    rollback = mode == "rollback"
    log(lines, "== deploy_p81_crouch132 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "сухой прогон"))
    if mode == "check":
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    want = OLD if rollback else NEW
    try:
        busy = [V2 + "\\" + d + "\\GameServer.exe" for d in FOLDERS if rbusy(V2 + "\\" + d + "\\GameServer.exe") == "BUSY"]
        if busy:
            for p in busy:
                log(lines, "  занят (процесс работает): " + p)
            if apply or rollback:
                log(lines, "СТОП: процессы GameServer не остановлены — ничего не тронуто")
                flush(lines)
                return 2
            log(lines, "  (сухой прогон: процессы работают — к выкладке их нужно остановить)")
        plan = []
        for d in FOLDERS:   # сначала проверка ВСЕХ папок, потом запись
            dll = rmd5(V2 + "\\" + d + "\\AsdaPatch.dll")
            if dll not in DLLS:
                log(lines, "СТОП: AsdaPatch.dll в %s = %s — не из проверенных (%s); ничего не трогаю" % (d, dll, ", ".join(DLLS)))
                flush(lines)
                return 8
            ini = V2 + "\\" + d + "\\ConfigSet\\patches.ini"
            raw = rread(ini)
            new, was, what = edit_ini(raw, want)
            tag = DLLS[dll]
            log(lines, "%s: AsdaPatch %s (%s); patches.ini %s: %s" % (d, dll, tag, md5b(raw), what))
            if new is not None:
                plan.append((d, ini, raw, new))
        if not plan:
            log(lines, "ГОТОВО: нечего делать — во всех папках уже AllowedCodes=%s" % want)
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
            up = ini + ".crouch132_upload"
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
        log(lines, ("ОТКАТ ГОТОВ: AllowedCodes без 132/133 (⚠ при выпущенном клиенте соседи не видят присед стоя, журнал 88). " if rollback else
                    "ГОТОВО: AllowedCodes += 132-133 во всех папках GameServer. ") +
                   "Старт процессов — за координатором; затем python deploy_p81_crouch132.py --check-started.")
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


def run(mode, out):
    """Вход для общего скрипта выкладки: mode "dry" | "apply" | "rollback" | "check"; строки журнала модуля дописываются в out
    (свой журнал модуля — tools/run_crouch132_20261105_deploy/deploy.log). Возврат — код (0 — успех/готово/нечего делать)."""
    lines = []
    try:
        return _run(mode, lines)
    finally:
        out.extend(lines)


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started, --selftest."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--selftest" in sys.argv:
        return selftest(sys.argv[sys.argv.index("--selftest") + 1])
    mode = ("check" if "--check-started" in sys.argv else "rollback" if "--rollback" in sys.argv
            else "apply" if "--apply" in sys.argv else "dry")
    return run(mode, [])


if __name__ == "__main__":
    sys.exit(main())
