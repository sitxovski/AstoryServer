# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p123.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v77 = живая v76 (P01…P122) + P123 «GM-прыжок на другую карту по клетке» — 09.11.2026,
#   пачка 20, решение владельца «Да, P123»; документ AstoryServer/Docs/GameServer/gm-map-jump-p123.md. Образец — deploy_p122.py.
#   Состав: AsdaPatch v77 (кумулятивная, номер Config — координатор) во ВСЕ GameServer из stack_layout; секцию [P123_GmMapJump] DLL
#   допишет при старте (Enabled=1, LogPerMinute=30). Данных и SQL нет. Клиент alpha-7.1.0 не затронут (шлёт только 6010 в 38 б).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца:
#     py -3.13 restart_stack.py --deploy deploy_p123.py --expect P123_GmMapJump --expect P122_PetFuncFloor --expect P121_CharRenameGuard
#         --expect P118_AuctionTradeBlock --expect P120_MineTravel --expect P117_PlusPackOnce
#   После старта: py -3.13 deploy_p123.py --check-started.
#   ASDA_P123_ROLLBACK=1 + --apply (или --rollback) — откат: DLL ← прежняя v76 (из бэкапа рядом).
#   Быстрое выключение без замены DLL: [P123_GmMapJump] Enabled=0 + рестарт.
# Журнал: tools/run_p123_20261109_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (rread пустого файла → b"")

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = os.path.join(HERE, "p123_data", "AsdaPatch_v77_475e0c07.dll")   # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "475e0c071d433c2e54e47346ce1799b8"                      # AsdaPatch v77 (v76 + P123)
PREV_DLL = {"5330a12ac213f05c056528964676b7c5": "AsdaPatch v76 = … + P120 + P118 + P121 + P122 (живая на 09.11, tools/p122_data)"}
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P123_GmMapJump"
INI_KEYS = ["Enabled", "LogPerMinute"]   # kGmMapJump (Config.cpp)
OTHER_SECTIONS = ["P122_PetFuncFloor", "P121_CharRenameGuard", "P118_AuctionTradeBlock", "P120_MineTravel", "P117_PlusPackOnce", "P68_CharNameGuard",
                  "P47_IdentityOperatorGate", "P41_GmHide4056", "P44_ExchangeIntegrity", "P19_AuctionRecordBounds", "P114_BoardExpBonus", "P75_LevelUpPotion",
                  "P103_InFlightFixes", "P112_PartyExpSpread", "P111_HatchSupplement", "P110_Job4PointPools", "P109_SelfHitNoDamage",
                  "P108_DungeonRelogEntry", "P107_CantActGate", "P106_FriendAcceptNotify", "P100_ChargeStack", "P63_InFlightLock"]   # проверка старта
NEED_LINES = ["P123: CharJumpCommandPosition @0x0054EF50", "P122: sub_459AD0 @0x00459C0E", "P121: Char_FunctionItem_Use @0x004EDEB3",
              "P68: режим ОТКАЗ", "P118: метка аукциона в прологах 9901/9903/9905/9907/9909", "P120: диспетчер ja @0x0042AE1B",
              "P117: Char_FunctionItem_Use case 120 @0x004EE25B"]   # строки установки, обязательны
INI_VERSION = 77                                                   # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки P123 сверены по нему (verify_p123, stand_p123)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261109_p123"
SRV_BACKUP = V2 + r"\_backup\2026-11-09_p123"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-09_p123/server/v2"
RUN_DIR = os.path.join(HERE, "run_p123_20261109_deploy")
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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-09_p123 и локально; существующие не перезаписываются."""
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
    up = dst + ".p123_upload"
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
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (v77)" % (
            d, exe, cur, PREV_DLL.get(cur, "уже v77" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
            ini_md5, ver, INI_VERSION, SECTION,
            ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has
            else "нет — DLL допишет при старте (Enabled=1)"))
        if has and keys.get("Enabled", "1").strip() != "1":
            log(lines, "  ВНИМАНИЕ: [%s] Enabled=%s — P123 не встанет, пока не 1" % (SECTION, keys.get("Enabled")))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки v77 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK]» P123 и соседей без провалов (patchlog); DLL = WANT
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
    # ★ restart_stack зовёт скрипт только с --apply: ASDA_P123_ROLLBACK=1 превращает этот вызов в откат (тот же один перезапуск).
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P123_ROLLBACK") == "1")
    apply = apply and not rollback
    lines = []
    mode = "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p123 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
            log(lines, "сухой прогон: %s (DLL — %d папок: %s)" % ("всё готово к --apply" if plan else "ВЫКЛАДЫВАТЬ НЕЧЕГО",
                len(plan), ", ".join(plan) or "—"))
            flush(lines)
            return 0 if plan else 9
        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "DLL: AsdaPatch (v77) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: v77 = v76 + P123 (AsdaPatch %s) — DLL %d папок; секция [%s] Enabled=1 допишется при старте. Дальше restart_stack: "
                   "start.bat; в PatchLog — «Version … -> %d»; затем py -3.13 deploy_p123.py --check-started."
                   % (WANT_DLL, len(plan), SECTION, INI_VERSION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
