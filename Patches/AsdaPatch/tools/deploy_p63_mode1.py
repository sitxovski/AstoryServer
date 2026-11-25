# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p63_mode1.py — ВКЛЮЧЕНИЕ / ОТКАТ режима 1 общего замка «запрос в БД в полёте» P63 (05.11.2026, сессия booster-loot;
#   решение владельца — вариант А: [P63_InFlightLock] Mode=1 для всех 25 семей). Только правка patches.ini, номера патча нет.
#   Повод: баг «несколько бустеров подряд» — повтор 5468 до ответа БД 2229 при Mode=0 пишется в журнал (вид 35) и ВСЁ РАВНО
#   уходит в БД (сервер меняет память только в ответе 0x8B5 sendGachaItemUse). Mode=1: повтор подавляется (вид 37), у 5048/6162 —
#   стоковая ветка «занят» (вид 36). Разбор и стенд: AstoryServer/Docs/GameServer/inflight-lock-p63.md,
#   Reports/booster_bundles/2026-11-05/p63_mode1/ (стенд v65 6f644a76 на образе e7b4ac38: Mode 1 both 65/0, rev 65/0, p63 43/0;
#   честный путь 25 семей — 0 срабатываний).
#   Цели — ВСЕ GameServer из stack_layout.GS_FOLDERS (GameServer, Indun_GameServer, Ch2_GameServer).
#
# Режимы (CLI):  py -3.13 deploy_p63_mode1.py                 — сухой прогон (только чтение по SSH): что поменяется в каждой папке;
#                py -3.13 deploy_p63_mode1.py --apply         — стойка ОСТАНОВЛЕНА: бэкап ini (рядом SUFFIX, v2\_backup\…, локально),
#                                                                Mode=0 → 1 ровно одной строкой, сверка md5 после заливки;
#                py -3.13 deploy_p63_mode1.py --rollback      — стойка ОСТАНОВЛЕНА: Mode=1 → 0 (та же точечная правка, бэкап);
#                py -3.13 deploy_p63_mode1.py --check-started — после старта: PatchLog каждого GS — «[OK] P63_InFlightLock» и строка
#                                                                «P63: режим ОТКАЗ/ПОДАВЛЕНИЕ»; Log_Item — нет всплеска строк P63 (виды 35–39)
#                                                                после старта процесса (порог --max-events, по умолчанию 10).
# Встраивание в общий скрипт выкладки (с P109/P110): `import deploy_p63_mode1; rc = deploy_p63_mode1.run("apply", lines)` —
#   без перезапуска, только код возврата; строки журнала дописываются в переданный список (и в свой deploy.log).
# Коды возврата: 0 готово; 2 стойка не остановлена; 4 после заливки не сошлось; 5 проверка старта — проблемы; 6 в ini нет секции P63;
#   7 исключение; 9 менять нечего (уже в нужном режиме).
# Модуль без побочных эффектов при импорте (памятка tools-no-import-side-effects).
import hashlib
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5, ps, q   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                          # корень стойки
GS_FOLDERS = stack_layout.GS_FOLDERS                     # все GameServer, включая Indun и канал 2
INI_REL = r"ConfigSet\patches.ini"                       # конфиг AsdaPatch
SECTION = "P63_InFlightLock"                             # секция P63 (Config.cpp)
KEY = "Mode"                                             # ключ режима (p63_inflight_lock.cpp: GetInt(kSec, L"Mode", 0))
MODE_LINE_NEEDLE = "P63: режим"                          # строка установки P63 в PatchLog
MODE1_TEXT = "ОТКАЗ/ПОДАВЛЕНИЕ"                          # её текст при Mode=1 (Log::Line P63, `g_mode ? …`)
P63_LOG_NEEDLE = "P63 InFlightLock:"                     # префикс строк P63 в Log_Item (sub_569DF0, LogChannel 1)
SUFFIX = ".bak_20261105_p63mode1"                        # бэкап рядом с файлом
SRV_BACKUP = V2 + r"\_backup\2026-11-05_p63mode1"        # бэкап на сервере
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-05_p63mode1/server/v2"   # локальный бэкап
RUN_DIR = os.path.join(HERE, "run_p63mode1_20261105")    # рабочая папка (файлы ini, журнал)
LOG = os.path.join(RUN_DIR, "deploy.log")                # журнал выкладки (дописывается)
DEFAULT_MAX_EVENTS = 10                                  # порог всплеска строк P63 после старта (честный путь даёт 0)


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def decode_ini(data):
    """Байты patches.ini → (текст, кодировка). DLL пишет UTF-16 LE с BOM (Config::MergeMissing); иначе — однобайтовый."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16"), "utf-16"
    return data.decode("latin-1"), "latin-1"


def encode_ini(text, enc):
    """Текст → байты в исходной кодировке (UTF-16 — с BOM, как у исходника)."""
    return text.encode("utf-16") if enc == "utf-16" else text.encode("latin-1")


def set_mode(text, want):
    """Поставить `Mode=<want>` в секции SECTION, меняя ровно одну строку (или вставив её сразу за заголовком секции, если ключа нет).
    Возврат (новый текст, прежнее значение или None, изменено ли). Исключение — секции нет."""
    nl = "\r\n" if "\r\n" in text else "\n"
    rows = text.split(nl)
    sec_at, key_at, cur = -1, -1, None
    for i, ln in enumerate(rows):
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            name = s[1:-1].strip()
            if sec_at >= 0 and name != SECTION:
                break                                    # секция кончилась
            if name == SECTION:
                sec_at = i
            continue
        if sec_at >= 0 and "=" in s and not s.startswith(";"):
            k, v = [x.strip() for x in s.split("=", 1)]
            if k == KEY:
                key_at, cur = i, v
                break
    if sec_at < 0:
        raise KeyError("в patches.ini нет секции [%s]" % SECTION)
    if cur == str(want):
        return text, cur, False
    if key_at >= 0:
        rows[key_at] = re.sub(r"=\s*\S*", "=%d" % want, rows[key_at], count=1)
    else:
        rows.insert(sec_at + 1, "%s=%d" % (KEY, want))
    return nl.join(rows), cur, True


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в SRV_BACKUP и локально; существующий бэкап не перезаписывается
    (если он другой — исключение, разбирать вручную)."""
    src = V2 + "\\" + rel
    want = rmd5(src)
    for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            log(lines, "  бэкап %s уже есть (%s, первый — сохранён; текущий %s)" % (dst, have, want))
    loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
    if not os.path.exists(loc):
        data = rread(src)
        if hashlib.md5(data).hexdigest() != want:
            raise RuntimeError("прочитанное по SSH %s не сошлось по md5" % src)
        os.makedirs(os.path.dirname(loc), exist_ok=True)
        with open(loc, "wb") as f:
            f.write(data)
        log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def plan_folder(folder, want, lines):
    """Прочитать живой ini папки и построить правку. Возврат (байты нового ini или None, если менять нечего, прежнее значение)."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    text, enc = decode_ini(data)
    new, cur, changed = set_mode(text, want)
    ver = re.search(r"(?mi)^\s*Version\s*=\s*(\S+)", text)
    log(lines, "  %s: patches.ini %s (%s, Version %s), [%s] %s=%s → %s" % (
        folder, hashlib.md5(data).hexdigest(), enc, ver.group(1) if ver else "?", SECTION, KEY,
        cur if cur is not None else "(нет ключа, по умолчанию 0)", "%d" % want if changed else "без изменений"))
    if not changed:
        return None, cur
    nb = encode_ini(new, enc)
    old_rows, new_rows = text.splitlines(), new.splitlines()
    diff = sum(1 for a, b in zip(old_rows, new_rows) if a != b) + abs(len(old_rows) - len(new_rows))
    if diff != 1:
        raise RuntimeError("%s: правка затрагивает %d строк вместо одной — стоп" % (folder, diff))
    return nb, cur


def put_ini(folder, nb, lines):
    """Залить новый ini через временный файл со сверкой md5."""
    rel = folder + "\\" + INI_REL
    os.makedirs(RUN_DIR, exist_ok=True)
    local = os.path.join(RUN_DIR, folder + "_patches.ini")
    with open(local, "wb") as f:
        f.write(nb)
    want = md5(local)
    dst = V2 + "\\" + rel
    up = dst + ".p63mode1_upload"
    rupload(local, up)
    if rmd5(up) != want:
        rdel(up)
        raise RuntimeError("залитый %s не сошёлся по md5 — %s не тронут" % (up, dst))
    rcopy(up, dst)
    rdel(up)
    got = rmd5(dst)
    log(lines, "  %s выложено: %s %s" % (rel, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
    return got == want


def p63_events_since_start(folder):
    """Строки P63 в Log_Item папки за сегодня, записанные после старта её GameServer.exe: (время старта, {вид: число}, примеры).
    Вид по тексту строки: 35 JOURNAL ONLY, 36 stock BUSY branch, 37 SUPPRESSED, 38 lock had expired, 39 lock kept."""
    day = time.strftime("%Y%m%d")
    script = (
        "$root = %s; $p = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ((Split-Path -Parent $_.ExecutablePath) -eq $root) "
        "-and $_.Name -eq 'GameServer.exe' } | Select-Object -First 1; "
        "if (-not $p) { Write-Output 'NOPROC'; return }; Write-Output ('START|' + $p.CreationDate.ToString('yyyyMMddHHmmss')); "
        "$f = Join-Path $root 'Log\\Log_Item\\ItemLog_%s.txt'; if (-not (Test-Path -LiteralPath $f)) { Write-Output 'NOFILE'; return }; "
        "Select-String -LiteralPath $f -SimpleMatch -Pattern %s | ForEach-Object { Write-Output ('L|' + $_.Line) }"
        % (q(V2 + "\\" + folder), day, q(P63_LOG_NEEDLE)))
    rc, out = ps(script, timeout=180)
    if rc != 0:
        raise RuntimeError("чтение Log_Item %s по SSH: код %d: %s" % (folder, rc, out[-200:]))
    start = next((l[6:].strip() for l in out.splitlines() if l.startswith("START|")), None)
    if start is None:
        return None, {}, []
    kinds, samples = {35: 0, 36: 0, 37: 0, 38: 0, 39: 0}, []
    for l in out.splitlines():
        if not l.startswith("L|"):
            continue
        m = re.match(r"L\|(\d+) Mon (\d+) Day (\d+) hou (\d+) min (\d+) sec", l)
        if not m:
            continue
        stamp = "%s%02d%02d%02d%02d%02d" % (start[:4], int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
        if stamp < start:
            continue
        k = (35 if "JOURNAL ONLY" in l else 36 if "BUSY branch" in l else 37 if "SUPPRESSED" in l
             else 38 if "had expired" in l else 39 if "lock kept" in l else None)
        if k:
            kinds[k] += 1
            if len(samples) < 3:
                samples.append(l[2:200])
    return start, kinds, samples


def check_started(lines, max_events=DEFAULT_MAX_EVENTS):
    """После старта: PatchLog — P63 установлен и стоит в режиме 1; Log_Item — строк P63 после старта не больше порога."""
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, info = patchlog.check_folder(d, [SECTION], [MODE_LINE_NEEDLE], log=lambda s: log(lines, s))
        run = info.get("run") or {}
        mode_lines = [l for l in (run.get("install", []) + run.get("runtime", [])) if MODE_LINE_NEEDLE in l]
        mode1 = bool(mode_lines) and MODE1_TEXT in mode_lines[-1]
        log(lines, "  %s: P63 в режиме 1 — %s" % (d, "ДА" if mode1 else "НЕТ (%s)" % (mode_lines[-1][:160] if mode_lines else "строки режима нет")))
        start, kinds, samples = p63_events_since_start(d)
        total = sum(kinds.values())
        log(lines, "  %s: строки P63 в Log_Item после старта %s — %d (виды 35/36/37/38/39 = %s)" % (
            d, start or "?", total, "/".join(str(kinds.get(k, 0)) for k in (35, 36, 37, 38, 39))))
        for s in samples:
            log(lines, "    пример: %s" % s)
        if start is None:
            log(lines, "  ПРОВАЛ: %s — процесс GameServer.exe не найден" % d)
        if total > max_events:
            log(lines, "  ПРОВАЛ: %s — всплеск строк P63 (%d > %d): проверить, не задеты ли честные действия" % (d, total, max_events))
        good = good and ok and mode1 and start is not None and total <= max_events
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("P63 Mode=1 стоит во всех GS, всплеска нет" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def run(action, lines=None, max_events=DEFAULT_MAX_EVENTS):
    """Встраиваемая точка: action — "dry", "apply", "rollback", "check-started". Без перезапуска стойки. Возврат — код (см. шапку)."""
    lines = [] if lines is None else lines
    log(lines, "== deploy_p63_mode1 %s %s (папки: %s)" % (time.strftime("%Y-%m-%d %H:%M:%S"), action, ", ".join(GS_FOLDERS)))
    try:
        if action == "check-started":
            return check_started(lines, max_events)
        want = 0 if action == "rollback" else 1
        busy = [d for d in GS_FOLDERS if rbusy(V2 + "\\" + d + r"\GameServer.exe") == "BUSY"]
        for d in busy:
            log(lines, "  работает: %s\\GameServer.exe" % d)
        if busy and action in ("apply", "rollback"):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            return 2
        plans = {}
        for d in GS_FOLDERS:
            try:
                nb, _ = plan_folder(d, want, lines)
            except KeyError as e:
                log(lines, "СТОП: %s — %s" % (d, e))
                return 6
            if nb is not None:
                plans[d] = nb
        if action == "dry":
            log(lines, "сухой прогон: %s" % ("к --apply готово, правка в %d папках: %s" % (len(plans), ", ".join(plans))
                                              if plans else "менять нечего — Mode=1 уже стоит"))
            return 0 if plans else 9
        if not plans:
            log(lines, "менять нечего: Mode=%d уже во всех папках" % want)
            return 9
        for d, nb in plans.items():
            backup_one(d + "\\" + INI_REL, lines)
            if not put_ini(d, nb, lines):
                return 4
            nb2, cur = plan_folder(d, want, lines)   # сверка: после заливки менять нечего
            if nb2 is not None:
                log(lines, "СТОП: %s — после заливки Mode=%s, ожидался %d" % (d, cur, want))
                return 4
        log(lines, "ГОТОВО: [%s] %s=%d в %d папках. Перезапуск — общим скриптом (restart_stack); после старта — --check-started."
                   % (SECTION, KEY, want, len(plans)))
        return 0
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        return 7
    finally:
        flush(lines)


def main():
    """CLI: без ключа — сухой прогон; --apply, --rollback, --check-started [--max-events N]."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    a = sys.argv[1:]
    action = "apply" if "--apply" in a else "rollback" if "--rollback" in a else "check-started" if "--check-started" in a else "dry"
    mx = DEFAULT_MAX_EVENTS
    if "--max-events" in a:
        i = a.index("--max-events")
        mx = int(a[i + 1]) if i + 1 < len(a) else DEFAULT_MAX_EVENTS
    return run(action, max_events=mx)


if __name__ == "__main__":
    sys.exit(main())
