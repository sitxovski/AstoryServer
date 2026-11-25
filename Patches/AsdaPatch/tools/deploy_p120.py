# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p120.py — ВЫКЛАДКА / ОТКАТ P120 «переход в шахту (карта 23) и обратно» (09.11.2026, пачка 20; документ
#   AstoryServer/Docs/GameServer/mine-travel-p120.md, отчёт Reports/batch20/mine/REPORT.md). Образец — deploy_p117.py + deploy_water_swim.py.
#   Состав: (1) AsdaPatch v73 (= v72 b31adafd + P120) во ВСЕ GameServer из stack_layout; patches.ini скрипт не правит — DLL при старте
#   допишет [P120_MineTravel] и поднимет Version до 73. (2) Данные карты 23 — 54 файла из p120_data/manifest.json (собирает
#   build_p120_data.py): GameServer ×3, NpcServer ×3, ChannelManager. Файл, уже равный новому, пропускается; база не та — СТОП, код 8.
#   Имена с «^» (^MineWar^.*) scp не передаёт (удалённый cmd съедает «^») — заливка во временное имя без «^», копия PowerShell -LiteralPath.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца:
#     py -3.13 restart_stack.py --deploy deploy_p120.py --expect P120_MineTravel --expect P117_PlusPackOnce --expect P13_ChatWideChannels6560
#   После старта: py -3.13 deploy_p120.py --check-started. Режимы: без ключей — сухой прогон (только чтение); --apply — выкладка
#   (стойка остановлена); --rollback (или ASDA_P120_ROLLBACK=1 + --apply из restart_stack) — откат: DLL ← прежняя v72, изменённые файлы
#   данных ← бэкап рядом; НОВЫЕ файлы карты (^MineWar^.*) остаются на месте — без строки в ini их никто не читает (список — в журнале).
#   Быстрое выключение без замены DLL: [P120_MineTravel] Enabled=0 + рестарт (шахта снова без потока; 6746/6749 — в default).
#   ★ РЕЖИМ «ТОЛЬКО ДАННЫЕ» (09.11, координатор: кумулятивная v76 ставится deploy_p122.py): `--data-only` или ASDA_P120_DATA_ONLY=1
#   (restart_stack передаёт только --apply). DLL не кладётся и с f60f7713 не сверяется; перед записью на каждом GameServer проверяется,
#   что стоит одна из DATA_DLL (v76 5330a12a или живая v72 b31adafd). Сухой прогон, --apply, --rollback (только данные), --check-started
#   (данные + процессы + PatchLog «[OK] P120_MineTravel»). Общая обёртка v76 + шахта — deploy_v76_mine.py.
# Коды: 0 готово, 2 стойка не остановлена, 3 нет/не та сборка или данные, 4 копия не сошлась, 5 проверка старта не прошла,
#   6 нет бэкапа для отката, 7 ошибка, 8 чужой файл на стойке / всё уже выложено, 9 выкладывать/откатывать нечего.
# Журнал: tools/run_p120_20261109_deploy/deploy.log (дописывается).
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
DATA = os.path.join(HERE, "p120_data")
BUILT_DLL = os.path.join(DATA, "AsdaPatch_v73_f60f7713.dll")       # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "f60f771353903718be1546da41b3a3ad"                      # AsdaPatch v73 (v72 + P120)
PREV_DLL = {"b31adafd2665fea45df1c091ece5e61a": "AsdaPatch v72 = … + P117 (живая, tools/p117_data)"}   # допустимая замена
DATA_DLL = {"5330a12ac213f05c056528964676b7c5": "AsdaPatch v76 = P120 + P118 + P121 + P122 (deploy_p122, tools/p122_data)",
            "b31adafd2665fea45df1c091ece5e61a": "AsdaPatch v72 = … + P117 (живая до v76)"}   # режим «только данные»: допустимая DLL на стойке
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P120_MineTravel"
OTHER_SECTIONS = ["P117_PlusPackOnce", "P114_BoardExpBonus", "P13_ChatWideChannels6560", "P30_MapSlots", "P40_CrystalTeleportGate",
                  "P101_CashGift", "P103_InFlightFixes", "P112_PartyExpSpread"]   # соседи — контроль старта
NEED_LINES = ["P120: диспетчер ja @0x0042AE1B", "P120: раздача потоков @0x004A53DC", "P120: RecvCharRegen case 8 @0x0052A755", "P30: слотов карт 23 -> 24"]
INI_VERSION = 73
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки P120 сверены по нему (verify_p120, stand_p120)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261109_p120"
SRV_BACKUP = V2 + r"\_backup\2026-11-09_p120"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-09_p120/server/v2"
RUN_DIR = os.path.join(HERE, "run_p120_20261109_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = ([d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]
        + [d + r"\NpcServer.exe" for d in stack_layout.NPC_FOLDERS] + [r"ChannelManager\ChannelManager.exe"])


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def manifest():
    """{путь стойки: (локальный файл, md5 базы | 'none', md5 нового)} из p120_data/manifest.json; локальные файлы сверены."""
    with open(os.path.join(DATA, "manifest.json"), encoding="utf-8") as f:
        m = json.load(f)["files"]
    out = {}
    for rel, (b, n) in m.items():
        lp = os.path.join(DATA, "files", rel.replace("\\", os.sep))
        if not os.path.exists(lp) or md5(lp) != n:
            raise RuntimeError("локальный %s нет или md5 не %s (перегенерировать: build_p120_data.py)" % (lp, n))
        out[rel] = (lp, b, n)
    return out


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-09_p120 и локально; существующие не перезаписываются."""
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
    if md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл без «^» в имени (scp), копия на сервере -LiteralPath, сверка md5."""
    dst = V2 + "\\" + rel
    folder, name = dst.rsplit("\\", 1)
    up = folder + "\\" + name.replace("^", "_") + ".p120_upload"
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


def survey_dll(lines):
    """DLL: сверки по папкам GameServer (только чтение). → (план, стоп-код)."""
    plan = []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        ini = rmd5(base + INI_REL)
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P120); patches.ini %s" % (
            d, exe, cur, PREV_DLL.get(cur, "уже P120" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL, ini))
        if ini == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini" % d)
            return plan, 8
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P120 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


def survey_data(files, lines):
    """Данные: сверка базы каждого файла (только чтение). → (план, стоп-код)."""
    plan = []
    for rel, (lp, b, n) in sorted(files.items()):
        cur = rmd5(V2 + "\\" + rel)
        state = "уже новый" if cur == n else ("новый файл" if b == "none" and cur == "none" else "правка" if cur == b else "ЧУЖОЙ")
        log(lines, "  %-60s %s → %s  %s" % (rel, cur[:8], n[:8], state))
        if cur == n:
            continue
        if cur != b:
            log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю" % (rel, cur, b))
            return plan, 8
        plan.append(rel)
    return plan, 0


def survey_dll_data_only(lines):
    """Режим «только данные»: на каждом GameServer стоит одна из DATA_DLL (только чтение). → стоп-код или 0."""
    for d in GS_FOLDERS:
        cur = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        exe = rmd5(V2 + "\\" + d + r"\GameServer.exe")
        log(lines, "%s: AsdaPatch %s (%s); GameServer.exe %s" % (d, cur, DATA_DLL.get(cur, "НЕ из допустимых"), exe))
        if cur not in DATA_DLL:
            log(lines, "СТОП: в %s AsdaPatch.dll %s — данные P120 кладутся только поверх v76 5330a12a или v72 b31adafd" % (d, cur))
            return 8
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, ожидался %s" % (d, exe, GS_EXE))
            return 8
    return 0


def check_started(lines, files):
    """После старта: PatchLog каждого GameServer — «[OK]» P120 и соседи без провалов; DLL = WANT; данные = новые; NpcServer работают."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        if DATA_ONLY:
            ok, _ = patchlog.check_folder(d, [SECTION], NEED_LINES, log=lambda s: log(lines, s))
            got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
            log(lines, "%s: AsdaPatch %s (%s)" % (d, got, DATA_DLL.get(got, "НЕ из допустимых")))
            good = good and ok and got in DATA_DLL
            continue
        ok, _ = patchlog.check_folder(d, [SECTION] + OTHER_SECTIONS, NEED_LINES, log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    bad = [rel for rel, (lp, b, n) in files.items() if rmd5(V2 + "\\" + rel) != n]
    log(lines, "данные карты 23: %d из %d = новые%s" % (len(files) - len(bad), len(files), (" — НЕ новые: " + ", ".join(bad)) if bad else ""))
    good = good and not bad
    run = [rel for rel in BUSY if rel.endswith(".exe") and rbusy(V2 + "\\" + rel) == "BUSY"]
    want = [rel for rel in BUSY if rel.endswith(".exe")]
    log(lines, "процессов (GameServer ×3, NpcServer ×3, ChannelManager) работает: %d из %d" % (len(run), len(want)))
    good = good and len(run) == len(want)
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def rollback(lines, files):
    """Откат: DLL ← бэкап рядом (только поверх WANT); изменённые файлы данных ← бэкап рядом (только поверх нового). Новые файлы остаются."""
    todo_dll = [] if DATA_ONLY else [d + r"\AsdaPatch.dll" for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
    todo_dat = [rel for rel, (lp, b, n) in files.items() if b != "none" and rmd5(V2 + "\\" + rel) == n]
    if not todo_dll and not todo_dat:
        log(lines, "СТОП: на стойке нет ни DLL P120, ни изменённых файлов P120 — откатывать нечего")
        return 9
    for rel in todo_dll:
        bak = rmd5(V2 + "\\" + rel + SUFFIX)
        if bak not in PREV_DLL:
            log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
            return 6
    for rel in todo_dat:
        bak = rmd5(V2 + "\\" + rel + SUFFIX)
        if bak != files[rel][1]:
            log(lines, "СТОП: %s%s нет или это не база (%s)" % (rel, SUFFIX, bak))
            return 6
    for rel in todo_dll + todo_dat:
        rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
        got = rmd5(V2 + "\\" + rel)
        okv = got in PREV_DLL if rel.endswith("AsdaPatch.dll") else got == files[rel][1]
        log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if okv else "НЕ СОШЛОСЬ"))
        if not okv:
            return 4
    left = [rel for rel, (lp, b, n) in files.items() if b == "none"]
    log(lines, "новые файлы карты 23 оставлены (%d; без строк в MapInfo.ini/Total_PortalConfig/OpenMapInfo их никто не читает): %s"
        % (len(left), ", ".join(left)))
    log(lines, "ГОТОВО: ОТКАТ (DLL %d папок, данных %d файлов; секция [%s] в ini останется и будет проигнорирована). Нужен старт стойки."
        % (len(todo_dll), len(todo_dat), SECTION))
    return 0


DATA_ONLY = False   # режим «только данные» (ставит main)


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started; --data-only / ASDA_P120_DATA_ONLY=1 — только данные."""
    global DATA_ONLY
    DATA_ONLY = "--data-only" in sys.argv or os.environ.get("ASDA_P120_DATA_ONLY") == "1"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    # ★ restart_stack зовёт скрипт только с --apply: ASDA_P120_ROLLBACK=1 превращает этот вызов в откат (тот же один перезапуск).
    rb = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P120_ROLLBACK") == "1")
    apply = apply and not rb
    lines = []
    mode = "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p120 %s %s%s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode, " (ТОЛЬКО ДАННЫЕ)" if DATA_ONLY else ""))
    try:
        files = manifest()
        if "--check-started" in sys.argv:
            rc = check_started(lines, files)
            flush(lines)
            return rc
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
            rc = rollback(lines, files)
            flush(lines)
            return rc
        if DATA_ONLY:
            stop = survey_dll_data_only(lines)
            if stop:
                flush(lines)
                return stop
            log(lines, "данные карты 23 (%d в манифесте):" % len(files))
            plan_dat, stop = survey_data(files, lines)
            if stop:
                flush(lines)
                return stop
            if not apply:
                log(lines, "сухой прогон: %s (только данные — %d файлов)" % ("всё готово к --apply" if plan_dat else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan_dat)))
                flush(lines)
                return 0 if plan_dat else 9
            if not plan_dat:
                log(lines, "СТОП: данные уже выложены")
                flush(lines)
                return 8
            for rel in plan_dat:
                if files[rel][1] != "none":
                    backup_one(rel, lines)
                put(rel, files[rel][0], files[rel][2], lines)
            log(lines, "ГОТОВО: данные P120 (карта 23) — %d файлов, DLL не тронута. Дальше start.bat; затем "
                       "py -3.13 deploy_p120.py --data-only --check-started." % len(plan_dat))
            flush(lines)
            return 0
        built = md5(BUILT_DLL)
        if built != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, built, WANT_DLL))
            flush(lines)
            return 3
        log(lines, "  собранная DLL %s — OK; данных в манифесте %d" % (built, len(files)))
        plan_dll, stop = survey_dll(lines)
        if stop:
            flush(lines)
            return stop
        log(lines, "данные карты 23:")
        plan_dat, stop = survey_data(files, lines)
        if stop:
            flush(lines)
            return stop
        if not apply:
            log(lines, "сухой прогон: %s (DLL — %d папок: %s; данных — %d файлов)" % (
                "всё готово к --apply" if (plan_dll or plan_dat) else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan_dll), ", ".join(plan_dll) or "—", len(plan_dat)))
            flush(lines)
            return 0 if (plan_dll or plan_dat) else 9
        if not plan_dll and not plan_dat:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        for d in plan_dll:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        for rel in plan_dat:
            if files[rel][1] != "none":
                backup_one(rel, lines)
            put(rel, files[rel][0], files[rel][2], lines)
        log(lines, "ГОТОВО: P120 (AsdaPatch %s) — DLL %d папок, данные карты 23 — %d файлов; секция [%s] Enabled=1 допишется при старте. "
                   "Дальше restart_stack: start.bat; в PatchLog — «Version … -> %d»; затем py -3.13 deploy_p120.py --check-started."
                   % (WANT_DLL, len(plan_dll), len(plan_dat), SECTION, INI_VERSION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
