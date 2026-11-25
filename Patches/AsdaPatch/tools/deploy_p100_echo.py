# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p100_echo.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v62: P100 ответ премиум-почты 2604 — ячейка эха БД для всех кодов (05.11.2026,
#   сессия p100-postbox-echo-cell; разбор — отчёт сессии, стенд tools/stand_p100 сценарии «A1-эхо», режим echooff).
#   [ИСПРАВЛЕНИЕ НАШЕЙ ПРАВКИ] запрос 11006 (0x4F882E) пропускал ячейки с резервом P100 в полёте (коробка), а ответ 2604 (0x4F8BA3) для
#   кодов без ключа брал стоковую ячейку без пропуска: БД — ячейка Y, память и 11007 — X («призраки» в сумке, 11007 статус 0, коробки Flag 0).
#   Во ВСЕ GameServer из stack_layout.GS_FOLDERS (GameServer, Indun_GameServer, Ch2_GameServer):
#   1. AsdaPatch.dll v62: живая v60 7cb74110 (P01…P103, deploy_p103) → WANT_DLL (закреплённая копия p100echo_data\).
#   2. patches.ini — файл НЕ правится этим скриптом, только бэкап. DLL при старте сама (Config::MergeMissing) дописывает ключ
#      [P100_ChargeStack] EchoAllCodes=1 и поднимает [General] Version 60 → 62 (61 не используется; P106 другой сессии пойдёт
#      поверх как Version 63 своей выкладкой; в этой сборке код P106 был скомпилирован, но НЕ зарегистрирован — не ставится).
#   Данных в БД не меняет, протокол клиента не меняется. SQL разбиения строки почты 36426 — отдельно (AstoryServer/SQL/
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением): py -3.13 restart_stack.py --deploy deploy_p100_echo.py --expect P100_ChargeStack
#   После старта: py -3.13 deploy_p100_echo.py --check-started («[OK] P100_ChargeStack», строка P100 «2604 — ячейка эха для всех кодов 1»).
#
# Режимы: (без ключа) — сухой прогон (только чтение по SSH); --apply — стойка ОСТАНОВЛЕНА: бэкапы (рядом SUFFIX, v2\_backup\2026-11-05_p100echo,
#   локально) patches.ini и AsdaPatch.dll, заливка DLL со сверкой md5; --rollback — DLL из <файл>.bak_20261105_p100echo (только поверх WANT;
#   прежняя DLL сама вернёт Version 62 → 60, ключ EchoAllCodes игнорирует; быстро без замены: [P100_ChargeStack] EchoAllCodes=0 + рестарт).
#   --check-started — PatchLog каждого GS: строка P100 в блоке последнего запуска; DLL = WANT.
# Журнал: tools/run_p100echo_20261105_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/p100echo_data/AsdaPatch_v62_f2476bf0.dll"   # закреплённая v62: out\ перепишет следующая сборка
WANT_DLL = "f2476bf06b944e972052c9f044ceadbf"                    # AsdaPatch v62 (P01…P103 + P100 EchoAllCodes; P106 скомпилирован, НЕ зарегистрирован)
PREV_DLL = {"7cb74110c30cab90658bfd47319d0520": "AsdaPatch v60 P01…P103 (deploy_p103)"}
NOT_YET = {"8bbc83f5dfcb38ea8e3333440a4d04a7": "AsdaPatch v59 P01…P102 — P103 ещё не выложен"}
INI_REL = r"ConfigSet\patches.ini"
CG_REL = r"ConfigSet\charge_groups.txt"
SECTION = "P100_ChargeStack"
INI_KEYS = ["Enabled", "Sites", "EchoAllCodes"]                   # из kChargeStack: что важно для этой выкладки
INI_VERSION = 62                                                  # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261105_p100echo"
SRV_BACKUP = V2 + r"\_backup\2026-11-05_p100echo"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-05_p100-echo/server/v2"
RUN_DIR = os.path.join(HERE, "run_p100echo_20261105_deploy")
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
    """Сведения о живом patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции P100)."""
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
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-05_p100echo и локально; существующие не перезаписываются."""
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
    up = dst + ".p100echo_upload"
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
    """Сверки по всем папкам (только чтение). → (план DLL, стоп-код или 0). 8 — не та площадка/файл, 10 — не выложен P103."""
    plan = []
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        cg = rmd5(base + CG_REL)
        ini_md5, ver, has, keys = ini_state(d) if rmd5(base + INI_REL) != "none" else ("none", None, False, {})
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (v62, P100 EchoAllCodes)" % (
            d, exe, cur, PREV_DLL.get(cur, NOT_YET.get(cur, "уже v62" if cur == WANT_DLL else "НЕ из допустимых")), WANT_DLL))
        log(lines, "  P100 ConfigSet\\charge_groups.txt: %s" % ("нет — P100 не встанет, исправление не действует (сведения)"
                                                           if cg == "none" else cg))
        if ini_md5 == "none":
            log(lines, "  patches.ini: НЕТ")
        else:
            miss = [k for k in INI_KEYS if k not in keys]
            log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
                ini_md5, ver, INI_VERSION, SECTION,
                "есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)
                + ("; недостающие допишет DLL: " + ", ".join(miss) if miss else "")
                if has else "нет — DLL допишет при старте со значениями шаблона (Enabled=1, EchoAllCodes=1)"))
            if has and (keys.get("Enabled", "1").strip() != "1" or keys.get("EchoAllCodes", "1").strip() != "1"):
                log(lines, "  ВНИМАНИЕ: [%s] Enabled=%s EchoAllCodes=%s — исправление не включится, DLL возьмёт эти значения" % (
                    SECTION, keys.get("Enabled"), keys.get("EchoAllCodes")))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P100 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur in NOT_YET:
            log(lines, "СТОП: в %s ещё нет P103 (%s) — сначала deploy_p103 через restart_stack.py, затем этот" % (d, NOT_YET[cur]))
            return plan, 10
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — строка секции P100 (OK при Enabled=1) без
    провалов (patchlog); DLL = WANT (dll_builds.accept) (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION], [], log=lambda s: log(lines, s))
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
    log(lines, "== deploy_p100_echo %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; ключ EchoAllCodes секции [%s] останется и будет проигнорирован, General Version 62 DLL v60 "
                       "при старте сама вернёт на 60). Нужен старт стойки."
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
        log(lines, "DLL: AsdaPatch v62 (P100 EchoAllCodes) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: v62 (AsdaPatch %s) — DLL %d папок; ключ [%s] EchoAllCodes=1 допишется при старте. Дальше restart_stack: "
                   "start.bat; в PatchLog — «Version 60 -> 62»; затем py -3.13 deploy_p100_echo.py --check-started." % (WANT_DLL, len(plan), SECTION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
