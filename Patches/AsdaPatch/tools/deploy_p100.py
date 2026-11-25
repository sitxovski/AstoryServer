# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p100.py — ВЫКЛАДКА / ОТКАТ P100 «заряды спецпредметов складываются при получении» (01.11.2026, решение владельца;
#   проект Reports/item_dedup/charges/P100_PROJECT.md). Во ВСЕ GameServer из stack_layout.GS_FOLDERS:
#   1. AsdaPatch.dll v57 (P01…P100, P100_ChargeStack): живая a6e7c425 (v56 P01…P99, deploy_p99) → WANT_DLL.
#   2. НОВЫЙ файл ConfigSet\charge_groups.txt (ключи складывания кодов 1…637; генератор tools/gen_charge_groups.py) из
#      tools/p100_data/charge_groups.txt. Первая строка файла — «# P100 ft_md5=<md5> …»: DLL сверяет его с md5 ЖИВОЙ
#      <папка>\ItemTable_Info\Function_Table.txt и при расхождении P100 НЕ ставит (сток, журнал ac.other 157). Поэтому скрипт
#      сверяет ft_md5 с Function_Table.txt каждой папки ДО выкладки и при расхождении отказывает (иначе P100 молча выключится).
#   3. patches.ini — как у deploy_p98/p99: файл НЕ правится скриптом, только бэкап. DLL при старте сама (Config::MergeMissing)
#      дописывает недостающую секцию [P100_ChargeStack] со значениями шаблона kChargeStack (Enabled=1, Cap=30000, Sites=-1,
#      TradeMerge=1, FixCharges=1, PendingTtlSec=60, JournalIntervalSec=10, LogChannel=1), существующие значения не трогает,
#      и поднимает [General] Version 56 → 57 (kVersion). Если секция уже есть — её значения сохранятся (сухой прогон их печатает).
#   SQL нет. Протокол не меняется.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     py -3.13 restart_stack.py --deploy deploy_p100.py --expect P100_ChargeStack
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем stack_parity --sync и start.bat).
#   После старта: py -3.13 deploy_p100.py --check-started
#
# Режимы:
#   (без ключа) — сухой прогон (только чтение по SSH): md5 собранной DLL и charge_groups.txt против констант, образы GameServer.exe,
#                 живые DLL, patches.ini (Version, есть ли секция [P100_ChargeStack] и её ключи), Function_Table.txt против ft_md5,
#                 наличие/md5 живого charge_groups.txt, занятость; план по папкам. Ничего не пишет.
#   --apply     — стойка ОСТАНОВЛЕНА: повтор всех сверок; бэкапы (рядом SUFFIX, v2\_backup\2026-11-01_p100, локально) patches.ini,
#                 AsdaPatch.dll и прежнего charge_groups.txt (если был); заливка charge_groups.txt, затем DLL — через временный
#                 файл со сверкой md5. «ГОТОВО» — только если прошло всё.
#   --rollback  — стойка остановлена: DLL из <файл>.bak_20261101_p100 (только поверх WANT). ini не правится: прежняя DLL сама
#                 вернёт General Version 57 → 56 (MergeMissing пишет свою kVersion), секцию P100 игнорирует. charge_groups.txt НЕ удаляется:
#                 DLL v56 его не читает (как секция в ini — остаётся и игнорируется); при повторной выкладке он уже на месте.
#                 Быстро без замены: [P100_ChargeStack] Enabled=0 + рестарт.
#   --check-started — после старта (только чтение): PatchLog каждого GS (patchlog.check_folder, блок последнего запуска) —
#                 «[OK] P100_ChargeStack» и строка «P100: заряды спецпредметов складываются»; DLL = WANT (dll_builds.accept —
#                 более поздняя сборка цепочки при подтверждённом журнале не провал); charge_groups.txt = CG_MD5.
# Журнал: tools/run_p100_20261101_deploy/deploy.log (дописывается).
import hashlib
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
# ★ 02.11: ЗАКРЕПЛЁННАЯ сборка v57 (копия из out\ до сборки P101 поверх неё): out\ теперь занимает v58 (P101), а этот шаг
#   выкладывает именно v57 — P101 ставит свой deploy_p101.py следом.
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/p100_data/AsdaPatch_v57_2013e099.dll"
WANT_DLL = "2013e099d35dbed5f2ea755e53e03a52"                    # AsdaPatch v57 (P01…P99) + P100 (ревизия 2, 02.11; черновики 985eac7d, e3cc5013 не выкладывались)
PREV_DLL = {"a6e7c425b33f8353b23e4ece69b26157": "AsdaPatch v56 P01…P99 (deploy_p99)"}
NOT_YET = {"e41618f8d974501f683062c0cd627da3": "AsdaPatch v56 P01…P98 — P99 ещё не выложен",
           "a8480800f903d4f5452df45d1a2b730b": "AsdaPatch v56 P01…P97 — P98/P99 ещё не выложены"}
CG_LOCAL = os.path.join(HERE, "p100_data", "charge_groups.txt")  # источник ключей складывания (gen_charge_groups.py)
CG_MD5 = "ada98fa2b3e0ca9aa16f7419270a65a2"                      # md5 charge_groups.txt (ft_md5=b8ff782e…, кодов 637, ключей 63)
CG_REL = r"ConfigSet\charge_groups.txt"
FT_REL = r"ItemTable_Info\Function_Table.txt"
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P100_ChargeStack"
INI_KEYS = ["Enabled", "Cap", "Sites", "TradeMerge", "FixCharges", "PendingTtlSec", "JournalIntervalSec", "LogChannel"]  # kChargeStack
INI_VERSION = 57                                                  # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261101_p100"
SRV_BACKUP = V2 + r"\_backup\2026-11-01_p100"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-01_p100/server/v2"
RUN_DIR = os.path.join(HERE, "run_p100_20261101_deploy")
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


def cg_header():
    """ft_md5 и шапка из первой строки локального charge_groups.txt («# P100 ft_md5=… codes=… merge=… keys=…»)."""
    with open(CG_LOCAL, "rb") as f:
        first = f.readline().decode("ascii", "replace").strip()
    m = re.search(r"ft_md5=([0-9a-f]{32}) codes=(\d+) merge=(\d+) keys=(\d+)", first)
    if not m:
        raise RuntimeError("в %s нет шапки «ft_md5=… codes=… merge=… keys=…» (первая строка: %r)" % (CG_LOCAL, first[:120]))
    return m.group(1), first


def ini_state(folder):
    """Сведения о живом patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции P100)."""
    path = V2 + "\\" + folder + "\\" + INI_REL
    data = rread(path)
    # Живой patches.ini — UTF-16 LE с BOM (Config.cpp создаёт файл юникодным, WritePrivateProfileStringW пишет в нём же).
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16")
    else:
        text = data.decode("latin-1")
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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-01_p100 и локально; существующие не перезаписываются."""
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
    up = dst + ".p100_upload"
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


def survey(lines, ft_want):
    """Сверки по всем папкам (только чтение). → (plan_dll, plan_cg, стоп-код или 0). plan_cg — папки, где charge_groups.txt
    нужно залить (нет или другой); stop — первый отказ (8 — не та площадка/файл, 10 — не выложен P99, 11 — ft_md5 ≠ FT)."""
    plan_dll, plan_cg = [], []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        ft = rmd5(base + FT_REL)
        cg = rmd5(base + CG_REL)
        ini_md5, ver, has, keys = ini_state(d) if rmd5(base + INI_REL) != "none" else ("none", None, False, {})
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P100)" % (
            d, exe, cur, PREV_DLL.get(cur, NOT_YET.get(cur, "уже P100" if cur == WANT_DLL else "НЕ из допустимых")), WANT_DLL))
        log(lines, "  Function_Table.txt %s (ft_md5 charge_groups %s) — %s" % (ft, ft_want, "совпал" if ft == ft_want else "НЕ СОВПАЛ"))
        log(lines, "  charge_groups.txt на стойке: %s" % (
            "нет (будет залит)" if cg == "none" else "%s (%s)" % (cg, "уже наш" if cg == CG_MD5 else "ДРУГОЙ — будет заменён с бэкапом")))
        if ini_md5 == "none":
            log(lines, "  patches.ini: НЕТ")
        else:
            miss = [k for k in INI_KEYS if k not in keys]
            log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
                ini_md5, ver, INI_VERSION, SECTION,
                "есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)
                + ("; недостающие допишет DLL: " + ", ".join(miss) if miss else "")
                if has else "нет — DLL допишет при старте со значениями шаблона (Enabled=1 … LogChannel=1)"))
            if has and keys.get("Enabled", "1").strip() == "0":
                log(lines, "  ВНИМАНИЕ: [%s] Enabled=0 — патч встанет выключенным (решение администратора сохраняется)" % SECTION)
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P100 сверены по %s" % (d, exe, GS_EXE))
            return plan_dll, plan_cg, 8
        if ft != ft_want:
            log(lines, "СТОП: в %s ItemTable_Info\\Function_Table.txt = %s, а charge_groups.txt собран по ft_md5 %s — с таким файлом "
                       "P100 на сервере выключится сам (сток, ac.other 157). Перегенерируй charge_groups (gen_charge_groups.py) по "
                       "живой Function_Table и обнови CG_MD5, либо выясни, кто поменял таблицу." % (d, ft, ft_want))
            return plan_dll, plan_cg, 11
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan_dll, plan_cg, 8
        if cg != CG_MD5:
            plan_cg.append(d)
        if cur == WANT_DLL:
            continue
        if cur in NOT_YET:
            log(lines, "СТОП: в %s ещё нет P99 (%s) — сначала deploy_p98/deploy_p99 через restart_stack.py, затем P100" % (d, NOT_YET[cur]))
            return plan_dll, plan_cg, 10
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan_dll, plan_cg, 8
        plan_dll.append(d)
    return plan_dll, plan_cg, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P100_ChargeStack», строка «P100: заряды
    спецпредметов складываются», без провалов (patchlog); DLL = WANT (dll_builds.accept); charge_groups.txt = CG_MD5 (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION], ["P100: заряды спецпредметов складываются"], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
        cg = rmd5(V2 + "\\" + d + "\\" + CG_REL)
        log(lines, "%s\\%s: %s %s" % (d, CG_REL, cg, "OK" if cg == CG_MD5 else "НЕ ТОТ (ожидался %s)" % CG_MD5))
        good = good and cg == CG_MD5
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
    log(lines, "== deploy_p100 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
            # Config::MergeMissing прежней DLL: fileVer != kVersion → пишет свою версию (57 → 56), затем dllmain сверяет 56 = 56.
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована, General Version 57 DLL v56 "
                       "при старте сама вернёт на 56; ConfigSet\\charge_groups.txt остаётся — DLL v56 его не читает). "
                       "Нужен старт стойки." % (len(todo), SECTION))
            flush(lines)
            return 0

        built = md5(BUILT_DLL)
        if built != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, built, WANT_DLL))
            flush(lines)
            return 3
        cg_local = md5(CG_LOCAL)
        if cg_local != CG_MD5:
            log(lines, "СТОП: %s = %s, ожидался %s" % (CG_LOCAL, cg_local, CG_MD5))
            flush(lines)
            return 3
        ft_want, head = cg_header()
        log(lines, "  собранная DLL %s — OK; charge_groups.txt %s — OK; шапка: %s" % (built, cg_local, head))

        plan_dll, plan_cg, stop = survey(lines, ft_want)
        if stop:
            flush(lines)
            return stop

        if not apply:
            todo = plan_dll or plan_cg
            log(lines, "сухой прогон: %s (DLL — %d папок: %s; charge_groups.txt — %d папок: %s)" % (
                "всё готово к --apply" if todo else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan_dll), ", ".join(plan_dll) or "—",
                len(plan_cg), ", ".join(plan_cg) or "—"))
            flush(lines)
            return 0 if todo else 9

        if not plan_dll and not plan_cg:
            log(lines, "СТОП: DLL и charge_groups.txt уже выложены во все папки")
            flush(lines)
            return 8
        log(lines, "1. charge_groups.txt в %d папках" % len(plan_cg))
        for d in plan_cg:
            if rmd5(V2 + "\\" + d + "\\" + CG_REL) != "none":
                backup_one(d + "\\" + CG_REL, lines)
            put(d + "\\" + CG_REL, CG_LOCAL, CG_MD5, lines)
        log(lines, "2. DLL: AsdaPatch v57 (P100) в %d папках" % len(plan_dll))
        for d in plan_dll:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P100 (AsdaPatch %s + charge_groups.txt %s) — DLL %d папок, таблица %d папок. Дальше restart_stack: "
                   "start.bat; в PatchLog — «[OK] P100_ChargeStack» и «Version 56 -> 57»; затем py -3.13 deploy_p100.py --check-started."
                   % (WANT_DLL, CG_MD5, len(plan_dll), len(plan_cg)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
