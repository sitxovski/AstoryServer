# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p128.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v85 = v84 (P127 А5.4, живая с 21.11) + P128 «значок события Event.dat всем игрокам»
#   (6039 / 6041 на такте игрока, общая точка UserTick P73). 21.11.2026, шаг А5.10. Образец — deploy_p127e.py.
#   Документ: AstoryServer/Docs/GameServer/event-badge-all-p128.md; отчёт: Reports/admin_center/impl_a5_live_20261121.md (А5.10).
#   ВЫКЛАДКА — ТОЛЬКО по слову владельца (рестарт стойки). Меняется AsdaPatch.dll во всех 3 папках GameServer и в patches.ini
#   дописывается секция [P128_EventBadgeAll] Enabled=1 (если её нет; остальные ключи DLL допишет сама). Секция P127 и секреты моста —
#   без изменений. Допустимая прежняя DLL — v84 612db6fe (живая).
#   --help / -h — эта шапка без действий; неизвестный ключ — код 1 без действий.
#   Выкладка — с объявлением:
#     py -3.13 restart_stack.py --deploy deploy_p128.py --expect P128_EventBadgeAll --expect P127_AdminBridge --expect P73_EacBridge
#   После старта: py -3.13 deploy_p128.py --check-started (PatchLog, md5, пульс трёх узлов с ver 85).
#   ОТКАТ: --rollback (или ASDA_P128_ROLLBACK=1 + --apply) — DLL <- v84 из бэкапа рядом; секция P128 остаётся (v84 её не читает).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
# ★ ревизия 49: сборка после исправлений С-1 / Н-3 (явное состояние на первом такте входа, поколение слота); b8d52267 — НЕ выкладывать
BUILT_DLL = os.path.join(HERE, "p128_data", "AsdaPatch_v85p128r49_e0d08ba5.dll")   # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "e0d08ba5a4ee855451a9e8530d73710c"                       # AsdaPatch v85 = v84 + P128 (значок события всем), ред. р49
PREV_DLL = {"612db6fef6cb800a2e557783b32d4f77": "AsdaPatch v84 + P127 А5.4 (живая, tools/p127_data)"}
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P128_EventBadgeAll"
INI_KEYS = ["Enabled", "ExpWithLuckyHours"]
OTHER_SECTIONS = ["P127_AdminBridge", "P73_EacBridge", "P123_GmMapJump", "P75_LevelUpPotion", "P100_ChargeStack", "P24_FameRatingRevoke",
                  "P25_GmRatingRecalc"]
NEED_LINES = ["P128: значок события Event.dat всем игрокам", "P127: мост админ-центра", "P127: живьём (v84): события 6038/6040 да",
              "P73: мост EAC"]
KNOWN_KEYS = ("--apply", "--rollback", "--check-started")
INI_VERSION = 85                                                   # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки сверены по нему (stand_p128, stand_p127)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261121_p128"
SRV_BACKUP = V2 + r"\_backup\2026-11-21_p128"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-21_p128/server/v2"
RUN_DIR = os.path.join(HERE, "run_p128_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def ini_state(folder):
    """Живой patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции, UTF-16 ли)."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    if data[:2] == b"\xfe\xff":
        # ★ ревизия 49 М-3: UTF-16 BE — DLL такой ini не пишет; дописывание в LE испортило бы файл — отказ
        raise RuntimeError("%s\\%s в UTF-16 BE (BOM FE FF) — так его DLL не пишет, секцию не дописываю — разберись вручную" % (folder, INI_REL))
    wide = data[:2] == b"\xff\xfe"
    text = data.decode("utf-16") if wide else data.decode("latin-1")
    ver, cur, keys, has = None, None, {}, False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
            has = has or cur == SECTION
            continue
        if not s or s.startswith(";") or "=" not in s:
            continue
        k, v = [x.strip() for x in s.split("=", 1)]
        if cur == "General" and k == "Version":
            ver = v
        elif cur == SECTION:
            keys[k] = v
    return hashlib.md5(data).hexdigest(), ver, has, keys, wide


def seed_section(folder, has, keys, wide, lines):
    """Секция [P128_EventBadgeAll] Enabled=1 в конец patches.ini (в его кодировке), если её нет; остальные ключи DLL допишет сама."""
    if has:
        log(lines, "  секция [%s] уже есть: %s — не трогаю" % (SECTION, ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys) or "—"))
        return
    path = V2 + "\\" + folder + "\\" + INI_REL
    enc = "[Text.Encoding]::Unicode" if wide else "[Text.Encoding]::Default"
    rc, out = ps("$p=%s; $t=\"`r`n[%s]`r`nEnabled=1`r`n\"; [IO.File]::AppendAllText($p, $t, %s); 'OK'" % (q(path), SECTION, enc))
    if rc != 0 or "OK" not in out:
        raise RuntimeError("секция в %s не дописана: %s" % (path, out[-300:]))
    _, _, has2, k2, _ = ini_state(folder)
    if not has2 or k2.get("Enabled") != "1":
        raise RuntimeError("после дописывания секция [%s] в %s читается не так: %s" % (SECTION, path, k2))
    log(lines, "  [%s] Enabled=1 дописана в %s (ExpWithLuckyHours — DLL при старте)" % (SECTION, INI_REL))


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в SRV_BACKUP и локально; существующие не перезаписываются."""
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
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
    loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        if md5(loc) != want:
            raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл" % loc)
        return
    data = rread(src)
    if hashlib.md5(data).hexdigest() != want:
        raise RuntimeError("прочитанное по SSH %s не сошлось по md5" % src)
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p128_upload"
    rupload(local, up)
    if rmd5(up) != want:
        rdel(up)
        raise RuntimeError("залитый %s не сошёлся по md5 — %s не тронут" % (up, dst))
    rcopy(up, dst)
    rdel(up)
    got = rmd5(dst)
    log(lines, "  %s выложено: %s %s" % (rel, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
    if got != want:
        raise RuntimeError("после копии %s = %s, ожидался %s" % (dst, got, want))


def survey(lines):
    """Сверки по всем папкам (только чтение). → (план [(папка, есть секция, ключи, UTF-16, нужна DLL)], стоп-код или 0)."""
    plan = []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        if rmd5(base + INI_REL) == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        ini_md5, ver, has, keys, wide = ini_state(d)
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (v85)" % (
            d, exe, cur, PREV_DLL.get(cur, "уже v85" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
        log(lines, "  patches.ini %s (%s): Version %s → DLL поднимет до %d; секция [%s] %s" % (
            ini_md5, "UTF-16" if wide else "ANSI", ver, INI_VERSION, SECTION,
            ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has else "нет — будет дописана Enabled=1"))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки v85 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if cur != WANT_DLL and cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append((d, has, keys, wide, cur != WANT_DLL))
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer — «[OK]» P128 и соседей; DLL = WANT; пульс узлов в AsdaAdmin с ver 85 (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION] + OTHER_SECTIONS, NEED_LINES, log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    rc, out = ps("$o = & sqlcmd -S lpc:.\\SQLEXPRESS -E -d AsdaAdmin -h -1 -W -s '|' -Q \"SET NOCOUNT ON; SELECT node, mode, ver, "
                 "DATEDIFF(second, heartbeat, SYSUTCDATETIME()), present, errors FROM adm.bridge_node\" 2>&1; ($o | Out-String).Trim()")
    seen = {}
    for ln in out.splitlines():
        f = [x.strip() for x in ln.split("|")]
        if len(f) == 6 and f[3].lstrip("-").isdigit():
            seen[f[0]] = f
    for d in GS_FOLDERS:
        f = seen.get(d)
        fresh = bool(f) and int(f[3]) <= 15 and f[2] == str(INI_VERSION)
        log(lines, "%s: узел моста %s" % (d, ("пульс %s с, Mode=%s, v%s, в игре %s, ошибок SQL %s" % (f[3], f[1], f[2], f[4], f[5])) if f
                                          else "НЕТ строки в adm.bridge_node"))
        good = good and fresh
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def rollback(lines):
    """Вернуть v84 из бэкапов рядом (только поверх WANT); секция P128 остаётся (v84 её не читает). → код возврата."""
    todo = [d for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
    for d in todo:
        bak = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll" + SUFFIX)
        if bak not in PREV_DLL:
            log(lines, "СТОП: %s\\AsdaPatch.dll%s нет или это не прежняя DLL (%s)" % (d, SUFFIX, bak))
            return 6
    for d in todo:
        rel = d + r"\AsdaPatch.dll"
        rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
        got = rmd5(V2 + "\\" + rel)
        log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
        if got not in PREV_DLL:
            return 4
    log(lines, "ГОТОВО: ОТКАТ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована). Нужен старт стойки." % (len(todo), SECTION))
    return 0


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(open(os.path.abspath(__file__), encoding="utf-8").read().split("\nimport hashlib")[0])
        return 0
    bad = [a for a in args if a not in KNOWN_KEYS]
    if bad:
        print("неизвестный ключ: %s (есть: %s; --help — справка) — ничего не делаю" % (" ".join(bad), ", ".join(KNOWN_KEYS)))
        return 1
    apply = "--apply" in args
    rb = "--rollback" in args or (apply and os.environ.get("ASDA_P128_ROLLBACK") == "1")
    apply = apply and not rb
    lines = []
    mode = "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in args else "сухой прогон"
    log(lines, "== deploy_p128 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
    if "--check-started" in args:
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    try:
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rb):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        if rb:
            rc = rollback(lines)
            flush(lines)
            return rc
        built = md5(BUILT_DLL)
        if built != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, built, WANT_DLL))
            flush(lines)
            return 3
        log(lines, "  собранная DLL %s — OK" % built)
        plan, stop = survey(lines)
        if stop:
            flush(lines)
            return stop
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (DLL — %d папок из %d; секция [%s] — дописать в %d)"
                % (sum(1 for p in plan if p[4]), len(plan), SECTION, sum(1 for p in plan if not p[1])))
            flush(lines)
            return 0
        for d, has, keys, wide, need_dll in plan:
            log(lines, "%s:" % d)
            backup_one(d + "\\" + INI_REL, lines)
            seed_section(d, has, keys, wide, lines)
            if need_dll:
                backup_one(d + r"\AsdaPatch.dll", lines)
                put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: v85 (AsdaPatch %s) — %d папок. Дальше restart_stack: start.bat; затем py -3.13 deploy_p128.py --check-started."
            % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
