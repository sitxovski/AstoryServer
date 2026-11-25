# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# ★★★ 09.11.2026 РЕШЕНИЕ КООРДИНАТОРА: ОТДЕЛЬНО НЕ ИСПОЛЬЗУЕТСЯ. v74 (44e70ef7) промежуточная; P118 уходит на стойку в кумулятивной
#   DLL v76 (P120+P118+P121+P122) одним перезапуском вместе с данными P119/P120. Скрипт оставлен как образец и для сухой сверки.
# deploy_p118.py — ВЫКЛАДКА / ОТКАТ AsdaPatch = текущая живая + P118 (09.11.2026, пачка 20, баг 3, жалоба 10; обмен отменяется, пока игрок
#   работает с аукционом; документ AstoryServer/Docs/GameServer/auction-trade-block-p118.md). Образец — deploy_p118.py.
#   Во ВСЕ GameServer из stack_layout. patches.ini скрипт не правит: DLL при старте сама допишет [P118_AuctionTradeBlock] (Enabled=1,
#   WindowSec=120, StormGuard=0) и поднимет Version до INI_VERSION.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца:
#     py -3.13 restart_stack.py --deploy deploy_p118.py --expect P118_AuctionTradeBlock --expect P117_PlusPackOnce --expect P44_ExchangeIntegrity
#   После старта: py -3.13 deploy_p118.py --check-started. ASDA_P118_ROLLBACK=1 + --apply — откат.
#   Быстрое выключение без замены DLL: [P118_AuctionTradeBlock] Enabled=0 + рестарт. Шторм 9907 у alpha-7.0.0: StormGuard=1 + рестарт.
#   ★ WANT_DLL / BUILT_DLL / INI_VERSION / PREV_DLL заполняются при закреплении сборки (tools/p118_data) — порядок выкладки P118/P120/P121
#     решает координатор; скрипт сверяет md5 и не тронет чужую DLL.
# Журнал: tools/run_p118_20261109_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = os.path.join(HERE, "p118_data", "AsdaPatch_v74_44e70ef7.dll")   # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "44e70ef74302508da7d35ceb100e8b96"                      # AsdaPatch v74 (+ P118)
# ★ Сборка v74 СОДЕРЖИТ P120 (шахта, Enabled=1 по умолчанию): поверх v72 без данных шахты (deploy_p120) её класть нельзя — только после P120.
PREV_DLL = {"f60f771353903718be1546da41b3a3ad": "AsdaPatch v73 = v72 + P120 (deploy_p120, tools/p120_data)"}   # допустимая замена (+ сборки P120/P121, если выложат раньше)
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P118_AuctionTradeBlock"
INI_KEYS = ["Enabled", "WindowSec", "StormGuard", "StormStatus", "LogPerMinute"]   # kAuctionTradeBlock (Config.cpp)
OTHER_SECTIONS = ["P117_PlusPackOnce", "P44_ExchangeIntegrity", "P19_AuctionRecordBounds", "P114_BoardExpBonus", "P75_LevelUpPotion", "P103_InFlightFixes", "P112_PartyExpSpread", "P111_HatchSupplement", "P110_Job4PointPools", "P109_SelfHitNoDamage", "P108_DungeonRelogEntry", "P107_CantActGate",
                  "P106_FriendAcceptNotify", "P100_ChargeStack", "P63_InFlightLock"]                           # соседняя правка — проверка старта
NEED_LINES = ["P117: Char_FunctionItem_Use case 120 @0x004EE25B", "P118: метка аукциона в прологах 9901/9903/9905/9907/9909"]   # строка установки, обязательна
INI_VERSION = 74                                                   # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки P118 сверены по нему (verify_p118)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261109_p118"
SRV_BACKUP = V2 + r"\_backup\2026-11-09_p118"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-09_p118/server/v2"
RUN_DIR = os.path.join(HERE, "run_p118_20261109_deploy")
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
    """Сведения о живом patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции)."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("latin-1")
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
    return hashlib.md5(data).hexdigest(), ver, has, keys


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-09_p118 и локально; существующие не перезаписываются."""
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
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p118_upload"
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
    """Сверки по всем папкам (только чтение). → (план DLL, стоп-код или 0)."""
    plan = []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        ini_md5, ver, has, keys = ini_state(d) if rmd5(base + INI_REL) != "none" else ("none", None, False, {})
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P118)" % (
            d, exe, cur, PREV_DLL.get(cur, "уже P118" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
            ini_md5, ver, INI_VERSION, SECTION,
            ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has
            else "нет — DLL допишет при старте (Enabled=1)"))
        if has and keys.get("Enabled", "1").strip() != "1":
            log(lines, "  ВНИМАНИЕ: [%s] Enabled=%s — P118 не встанет, пока не 1" % (SECTION, keys.get("Enabled")))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P118 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK]» P117, P114, P75, P103 без провалов (patchlog); DLL = WANT
    (dll_builds.accept) (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION] + OTHER_SECTIONS, NEED_LINES, log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def rollback_dll(lines):
    """Вернуть прежнюю DLL из бэкапов рядом (только поверх WANT). → код возврата."""
    todo = [d + r"\AsdaPatch.dll" for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
    for rel in todo:
        bak = rmd5(V2 + "\\" + rel + SUFFIX)
        if bak not in PREV_DLL:
            log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
            return 6
    for rel in todo:
        rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
        got = rmd5(V2 + "\\" + rel)
        log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
        if got not in PREV_DLL:
            return 4
    log(lines, "ГОТОВО: ОТКАТ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована, General Version прежняя DLL при старте "
               "сама понизит). Нужен старт стойки." % (len(todo), SECTION))
    return 0


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    # ★ restart_stack зовёт скрипт только с --apply: ASDA_P117_ROLLBACK=1 превращает этот вызов в откат (тот же один перезапуск).
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P117_ROLLBACK") == "1")
    apply = apply and not rollback
    lines = []
    mode = "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p118 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
    if "--check-started" in sys.argv:
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
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        if rollback:
            rc = rollback_dll(lines)
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
            log(lines, "сухой прогон: %s (DLL — %d папок: %s)" % ("всё готово к --apply" if plan else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan), ", ".join(plan) or "—"))
            flush(lines)
            return 0 if plan else 9
        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "DLL: AsdaPatch (P118) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P118 (AsdaPatch %s) — DLL %d папок; секция [%s] Enabled=1 допишется при старте. Дальше restart_stack: "
                   "start.bat; в PatchLog — «Version … -> %d»; затем py -3.13 deploy_p118.py --check-started."
                   % (WANT_DLL, len(plan), SECTION, INI_VERSION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
