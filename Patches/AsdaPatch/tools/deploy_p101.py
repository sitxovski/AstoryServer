# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p101.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v58 с P101 «подарок из кэш-магазина» (02.11.2026, решение владельца;
#   проект Reports/cash_gift/PROJECT_P101.md, итог p101/DLL_DONE.md). Во ВСЕ GameServer из stack_layout.GS_FOLDERS:
#   1. AsdaPatch.dll v58 (P01…P101, P101_CashGift): живая 2013e099 (v57 P01…P100, deploy_p100) → WANT_DLL.
#   2. patches.ini — как у deploy_p98/p99/p100: файл НЕ правится скриптом, только бэкап. DLL при старте сама (Config::MergeMissing)
#      дописывает недостающую секцию [P101_CashGift] со значениями шаблона kCashGift (Enabled=0, Sites=1, HoldTimeoutSec=120,
#      SettleMaxSec=1800, MaxInFlight=1, RouteMaxAgeSec=300, LogChannel=22) и поднимает [General] Version 57 → 58. Enabled=0 — подарок ВЫКЛЮЧЕН:
#      выкладка DLL ничего не меняет для игроков. Включение — отдельным шагом координатора по PROJECT_P101.md §7 (SQL Joy1 + GP7,
#      реле/CM 237 б, gp7 server.js, затем Enabled=1 Sites=1 → Sites=15) — ini правится руками/своим скриптом, НЕ этим.
#   3. P101 опирается на P100 (слияние зарядов у получателя): если в папке нет ConfigSet\charge_groups.txt (P100 не встанет) —
#      сведения, не стоп (получатель без P100 раскладывает подарок как сток).
#   SQL нет. Протокол клиента не меняется (опкоды 5072–5078 стока; шлюз — новая пара 0x52/0x53, её знает только gp7 с веткой подарка).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     py -3.13 restart_stack.py --deploy deploy_p101.py --expect P101_CashGift
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем stack_parity --sync и start.bat).
#   После старта: py -3.13 deploy_p101.py --check-started  («[OK] P101_CashGift» при Enabled=1 / «[SKIP]» при Enabled=0 — оба допустимы).
#
# Режимы:
#   (без ключа) — сухой прогон (только чтение по SSH): md5 собранной DLL против WANT_DLL, образы GameServer.exe, живые DLL, patches.ini
#                 (Version, есть ли секция [P101_CashGift] и её ключи), charge_groups.txt P100, занятость; план по папкам. Ничего не пишет.
#   --apply     — стойка ОСТАНОВЛЕНА: повтор сверок; бэкапы (рядом SUFFIX, v2\_backup\2026-11-02_p101, локально) patches.ini и
#                 AsdaPatch.dll; заливка DLL через временный файл со сверкой md5. «ГОТОВО» — только если прошло всё.
#   --rollback  — стойка остановлена: DLL из <файл>.bak_20261102_p101 (только поверх WANT). ini не правится: прежняя DLL сама вернёт
#                 General Version 58 → 57, секцию P101 игнорирует. Быстро без замены: [P101_CashGift] Enabled=0 + рестарт.
#                 ⚠ Если подарок был включён: висящие hold в GP7 (GP7GiftLog state='H') — ручная сверка (gift_reconcile.py).
#   --check-started — после старта (только чтение): PatchLog каждого GS (patchlog.check_folder) — строка P101 в блоке последнего
#                 запуска; DLL = WANT (dll_builds.accept).
# Журнал: tools/run_p101_20261102_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/p101_data/AsdaPatch_v58_80b8d21b.dll"   # закреплённая v58: out\ перепишет следующая сборка
WANT_DLL = "80b8d21b3c48d716457f7425c0466f6c"                    # AsdaPatch v58 (P01…P101), ревизия 02.11; черновик e0d46e7a не выкладывался
PREV_DLL = {"2013e099d35dbed5f2ea755e53e03a52": "AsdaPatch v57 P01…P100 (deploy_p100)"}
NOT_YET = {"a6e7c425b33f8353b23e4ece69b26157": "AsdaPatch v56 P01…P99 — P100 ещё не выложен",
           "e41618f8d974501f683062c0cd627da3": "AsdaPatch v56 P01…P98 — P99/P100 ещё не выложены",
           "a8480800f903d4f5452df45d1a2b730b": "AsdaPatch v56 P01…P97 — P98…P100 ещё не выложены"}
INI_REL = r"ConfigSet\patches.ini"
CG_REL = r"ConfigSet\charge_groups.txt"
SECTION = "P101_CashGift"
INI_KEYS = ["Enabled", "Sites", "HoldTimeoutSec", "SettleMaxSec", "MaxInFlight", "RouteMaxAgeSec", "LogChannel"]   # kCashGift
INI_VERSION = 58                                                  # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261102_p101"
SRV_BACKUP = V2 + r"\_backup\2026-11-02_p101"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-02_p101/server/v2"
RUN_DIR = os.path.join(HERE, "run_p101_20261102_deploy")
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
    """Сведения о живом patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции P101)."""
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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-02_p101 и локально; существующие не перезаписываются."""
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
    up = dst + ".p101_upload"
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
    """Сверки по всем папкам (только чтение). → (план DLL, стоп-код или 0). 8 — не та площадка/файл, 10 — не выложен P100."""
    plan = []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        cg = rmd5(base + CG_REL)
        ini_md5, ver, has, keys = ini_state(d) if rmd5(base + INI_REL) != "none" else ("none", None, False, {})
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P101)" % (
            d, exe, cur, PREV_DLL.get(cur, NOT_YET.get(cur, "уже P101" if cur == WANT_DLL else "НЕ из допустимых")), WANT_DLL))
        log(lines, "  P100 ConfigSet\\charge_groups.txt: %s" % ("нет — P100 не встанет, получатель подарка без слияния зарядов (сведения)"
                                                           if cg == "none" else cg))
        if ini_md5 == "none":
            log(lines, "  patches.ini: НЕТ")
        else:
            miss = [k for k in INI_KEYS if k not in keys]
            log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
                ini_md5, ver, INI_VERSION, SECTION,
                "есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)
                + ("; недостающие допишет DLL: " + ", ".join(miss) if miss else "")
                if has else "нет — DLL допишет при старте со значениями шаблона (Enabled=0 — подарок выключен)"))
            if has and keys.get("Enabled", "0").strip() == "1":
                log(lines, "  ВНИМАНИЕ: [%s] Enabled=1 уже стоит — подарок включится сразу после старта (проверь PROJECT_P101.md §7)" % SECTION)
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P101 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur in NOT_YET:
            log(lines, "СТОП: в %s ещё нет P100 (%s) — сначала deploy_p100 через restart_stack.py, затем P101" % (d, NOT_YET[cur]))
            return plan, 10
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — строка секции P101 (OK при Enabled=1 / SKIP при 0) без
    провалов (patchlog); DLL = WANT (dll_builds.accept) (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [], [SECTION], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    mode = "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p101 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
            todo = [d + r"\AsdaPatch.dll" for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + SUFFIX)
                if bak not in PREV_DLL:
                    log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
                if got not in PREV_DLL:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована, General Version 58 DLL v57 при "
                       "старте сама вернёт на 57). Если подарок был включён — сверка висящих hold GP7GiftLog state='H'. Нужен старт стойки."
                       % (len(todo), SECTION))
            flush(lines)
            return 0

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
            log(lines, "сухой прогон: %s (DLL — %d папок: %s)" % ("всё готово к --apply" if plan else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan),
                                                              ", ".join(plan) or "—"))
            flush(lines)
            return 0 if plan else 9
        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "DLL: AsdaPatch v58 (P101) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P101 (AsdaPatch %s) — DLL %d папок; секция [%s] Enabled=0 допишется при старте. Дальше restart_stack: "
                   "start.bat; в PatchLog — «Version 57 -> 58»; затем py -3.13 deploy_p101.py --check-started." % (WANT_DLL, len(plan), SECTION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
