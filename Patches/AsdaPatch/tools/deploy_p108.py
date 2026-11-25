# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p108.py — ВЫКЛАДКА / ОТКАТ общей AsdaPatch v65 = P100 EchoAllCodes (v62) + P106 (v63) + P107 (v64) + P108 (v65)
#   (05.11.2026, сессия dungeon-relog; P108 «выход из данжа сохраняется в точку входа», документ
#   AstoryServer/Docs/GameServer/dungeon-relog-entry-p108.md). Образец — deploy_p106.py.
#   Во ВСЕ GameServer из stack_layout.GS_FOLDERS (GameServer и Ch2_GameServer — оба полевых канала — и Indun_GameServer: одна DLL на
#   все GS, stack_parity требует у копии ту же AsdaPatch.dll, что у поля; Indun держим в паритете — слово владельца 05.11):
#   1. AsdaPatch.dll: живая из PREV_DLL (v63 9862a5de; v64 512e80c8 P107, если её выложат раньше) → WANT_DLL (закреплённая копия tools/p108_data/).
#   2. patches.ini — файл НЕ правится этим скриптом, только бэкап. DLL при старте сама (Config::MergeMissing) дописывает секции
#      [P107_CantActGate] и [P108_DungeonRelogEntry] (Enabled=1, EntryMaps=8,9,17, ReturnMaps=10,11) и поднимает [General] Version до 65.
#   этот скрипт его НЕ применяет (только со слова владельца). Протокол клиента не меняется.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор с разрешения владельца (с объявлением):
#     py -3.13 restart_stack.py --deploy deploy_p108.py --expect P108_DungeonRelogEntry --expect P107_CantActGate --expect P106_FriendAcceptNotify
#   После старта: py -3.13 deploy_p108.py --check-started («[OK]» P100/P106/P107/P108 во всех GS).
#
# Режимы: (без ключа) — сухой прогон (только чтение по SSH); --apply — стойка ОСТАНОВЛЕНА: бэкапы (рядом SUFFIX, v2\_backup\2026-11-05_p108,
#   локально) patches.ini и AsdaPatch.dll, заливка DLL со сверкой md5; --rollback — DLL из <файл>.bak_20261105_p108 (только поверх WANT;
#   это прежняя живая DLL — v63 9862a5de; она сама понизит Version, секции P107/P108 игнорирует; быстро без замены DLL:
#   [P108_DungeonRelogEntry] Enabled=0 + рестарт); --check-started — PatchLog каждого GS: P100/P106/P107/P108 в блоке последнего
#   запуска; DLL = WANT.
#   --from-v60 / ASDA_P108_FROM_V60=1 (вместе с любым режимом; restart_stack зовёт скрипт только с --apply) — допустить живую v60 7cb74110 или
#   v62 f2476bf0 как прежнюю: v65 приносит и P100 EchoAllCodes (v62), и P106 (v63).
# Коды возврата: 0 готово; 2 стойка не остановлена; 3 закреплённая DLL не та; 4 откат не сошёлся; 5 проверка старта — проблемы;
#   6 нет бэкапа для отката; 7 исключение; 8 не тот файл на стойке / уже выложено; 9 выкладывать нечего; 10 прежняя версия ещё не выложена.
#   ASDA_P108_ROLLBACK=1 + --apply (так зовёт restart_stack) — то же, что --rollback, одним перезапуском стойки.
# Встроено (EXTRAS, одним перезапуском): deploy_p81_crouch132 (P81 AllowedCodes += 132-133 в patches.ini всех GS) и GP7-шлюз
#   (Gp7Gateway/deploy_gp7_alive.py: server.js без перезапуска шлюза — его поднимает start.bat); у каждой — dry/apply/rollback/check.
#   --check-started звать через 4–5 мин после старта стойки (пинг GS к GP7 — 180 с).
# Журнал: tools/run_p108_20261105_deploy/deploy.log (дописывается).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = os.path.join(HERE, "p108_data", "AsdaPatch_v65_6f644a76.dll")   # закреплённая сборка v65: out\ перепишет следующая сборка
WANT_DLL = "6f644a7671ff331ebc6c4c81dfc2f2a5"                      # AsdaPatch v65 (P01…P103 + P100 EchoAllCodes + P106 + P107 + P108)
PREV_DLL = {"9862a5deb2ddb25616ba2a7f6272c468": "AsdaPatch v63 P01…P103 + P100 EchoAllCodes + P106 (живая; tools/p106_data)",
            "512e80c81bfdb70552cbeae2a8916d63": "AsdaPatch v64 = v63 + P107 (tools/p107_data/AsdaPatch_v64_512e80c8.dll)"}   # допустимые живые DLL под заменой
NOT_YET = {"7cb74110c30cab90658bfd47319d0520": "AsdaPatch v60 P01…P103 — v62/v63 ещё не выложены",
           "f2476bf06b944e972052c9f044ceadbf": "AsdaPatch v62 + P100 EchoAllCodes — v63 (P106) ещё не выложена"}
# --from-v60: выложить v65 прямо поверх живой v60/v62 ОДНИМ рестартом (v65 содержит P100 EchoAllCodes, P106, P107, P108) — только если
#   координатор выкладывает все правки вместе. Тогда они считаются допустимой прежней DLL (и для отката).
if "--from-v60" in sys.argv or os.environ.get("ASDA_P108_FROM_V60") == "1":   # restart_stack ключей не передаёт — переменная
    PREV_DLL.update(NOT_YET)
    NOT_YET = {}
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P108_DungeonRelogEntry"
INI_KEYS = ["Enabled", "EntryMaps", "ReturnMaps"]                  # kDungeonRelogEntry (Config.cpp)
OTHER_SECTIONS = ["P106_FriendAcceptNotify", "P107_CantActGate"]  # прочие правки v65 — проверка старта
# ★ v65 несёт и правку v62 (P100 EchoAllCodes): сухой прогон показывает [P100_ChargeStack] Enabled/EchoAllCodes, --check-started требует
#   «[OK] P100_ChargeStack» рядом с P106/P107/P108. deploy_p100_echo.py / deploy_p106.py в ту же выкладку НЕ запускать: их WANT — v62/v63,
#   поверх v65 они откажут (код 8) и ничего не тронут; после выкладки проверять только этим скриптом.
P100_SECTION = "P100_ChargeStack"                                  # секция правки v62
P100_KEYS = {}                                                     # папка → {ключ: значение} [P100_ChargeStack] (заполняет ini_state)
INI_VERSION = 65                                                 # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки P106/P107/P108 сверены по нему (verify_p106/107/108)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261105_p108"
SRV_BACKUP = V2 + r"\_backup\2026-11-05_p108"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-05_p108/server/v2"
RUN_DIR = os.path.join(HERE, "run_p108_20261105_deploy")
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
    """Сведения о живом patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции P108)."""
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
        elif cur == P100_SECTION:
            P100_KEYS.setdefault(folder, {})[k] = v
    return hashlib.md5(data).hexdigest(), ver, has, keys


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-05_p108 и локально; существующие не перезаписываются."""
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
    up = dst + ".p108_upload"
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
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P108)" % (
            d, exe, cur, PREV_DLL.get(cur, NOT_YET.get(cur, "уже P108" if cur == WANT_DLL else "НЕ из допустимых")), WANT_DLL))
        if ini_md5 == "none":
            log(lines, "  patches.ini: НЕТ")
        else:
            log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
                ini_md5, ver, INI_VERSION, SECTION,
                ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has
                else "нет — DLL допишет при старте (Enabled=1)"))
            if has and keys.get("Enabled", "1").strip() != "1":
                log(lines, "  ВНИМАНИЕ: [%s] Enabled=%s — P108 не встанет, пока не 1" % (SECTION, keys.get("Enabled")))
            pk = P100_KEYS.get(d, {})
            log(lines, "  [%s] Enabled=%s EchoAllCodes=%s (v63 несёт правку v62; ключа нет — DLL допишет EchoAllCodes=1)" % (
                P100_SECTION, pk.get("Enabled", "нет"), pk.get("EchoAllCodes", "нет")))
            if pk.get("Enabled", "1").strip() != "1" or pk.get("EchoAllCodes", "1").strip() != "1":
                log(lines, "  ВНИМАНИЕ: [%s] Enabled/EchoAllCodes не 1 — правка эха 2604 не включится" % P100_SECTION)
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P108 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        if cur == WANT_DLL:
            continue
        if cur in NOT_YET:
            log(lines, "СТОП: в %s %s — сначала выкладка предыдущей версии, затем P108" % (d, NOT_YET[cur]))
            return plan, 10
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append(d)
    return plan, 0


# ★ 05.11.2026 (координатор): restart_stack принимает один --deploy — в ту же выкладку встроены правки других сессий. Каждая — модуль
#   без побочных эффектов при импорте с входом run(mode, lines) -> int, mode = "dry" | "apply" | "rollback" | "check"; 0 — готово.
#   Порядок: dry/apply/check — по списку, rollback — в обратном. В --apply модули идут ПОСЛЕ замены DLL (бэкап ini уже снят).
GP7_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "Gp7Gateway"))   # deploy_gp7_alive.py (сессия гачи)
GP7_CHECK_MINUTES = 4                                                     # окно журнала GS для check_started (пинг GS — 180 с)


def gp7_run(mode, lines):
    """Переходник к API deploy_gp7_alive.py (сессия gacha-overlap): stage / rollback_file / check_started. Шлюз НЕ перезапускается —
    при --apply стойка остановлена, node gp7-server поднимет start.bat (строка «ASDA GP7 Server»). Код 9 отката («бэкапа нет» —
    файл не выкладывался) — нечего откатывать, 0. --check-started звать через 4–5 мин после старта стойки."""
    if GP7_DIR not in sys.path:
        sys.path.insert(0, GP7_DIR)
    import deploy_gp7_alive as gp7
    say = lambda s: log(lines, "  gp7: " + s)
    if mode == "dry":
        return gp7.stage(False, say)
    if mode == "apply":
        return gp7.stage(True, say)
    if mode == "rollback":
        rc = gp7.rollback_file(say)
        if rc == gp7.RC_NO_BACKUP:
            say("бэкапа нет — server.js не выкладывался, откатывать нечего")
            return 0
        return rc
    return gp7.check_started(GP7_CHECK_MINUTES, say)


EXTRAS = [
    ("deploy_p81_crouch132", "присед стоя: [P81_ActionCodeGuard] AllowedCodes += 132-133 во всех GS (только ini; сессия hide-stealth)"),
    (gp7_run, "GP7-шлюз: server.js отвечает 0x15 на пинг GS (без перезапуска шлюза — его поднимет start.bat; сессия gacha-overlap)"),
]


def extras(mode, lines):
    """Встроенные правки других сессий в режиме mode. → 0 или код первого провала (остальные после провала не идут)."""
    import importlib
    order = EXTRAS if mode != "rollback" else list(reversed(EXTRAS))
    for name, what in order:
        fn = name if callable(name) else importlib.import_module(name).run
        name = name.__name__ if callable(name) else name
        log(lines, "-- встроено: %s (%s), режим %s" % (name, what, mode))
        rc = fn(mode, lines)
        log(lines, "-- %s: код %d" % (name, rc))
        if rc != 0:
            return rc
    return 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK]» P108, P107, P106, P100 без провалов
    (patchlog); DLL = WANT (dll_builds.accept) (только чтение); затем проверки встроенных правок (EXTRAS)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION, P100_SECTION] + OTHER_SECTIONS, [], log=lambda s: log(lines, s))   # P108, P107, P106 и P100 (EchoAllCodes v62)
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    good = extras("check", lines) == 0 and good
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    # ★ restart_stack зовёт скрипт только с --apply: ASDA_P108_ROLLBACK=1 превращает этот вызов в откат (тот же один перезапуск стойки).
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P108_ROLLBACK") == "1")
    apply = apply and not rollback
    lines = []
    mode = "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p108 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
    if "@" in WANT_DLL or not PREV_DLL:
        log(lines, "СТОП: WANT_DLL / PREV_DLL не заполнены (сборка P108 ещё не закреплена)")
        flush(lines)
        return 3
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
            rc2 = extras("rollback", lines)
            if rc2:
                log(lines, "СТОП: откат встроенной правки не прошёл (код %d) — DLL уже возвращена, смотри выше" % rc2)
                flush(lines)
                return rc2
            log(lines, "ГОТОВО: ОТКАТ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована, General Version %d прежняя DLL "
                       "при старте сама понизит; встроенные правки возвращены). Нужен старт стойки." % (len(todo), SECTION, INI_VERSION))
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
            rc2 = extras("dry", lines)
            log(lines, "сухой прогон: %s (DLL — %d папок: %s; встроенные правки: %s)" % (
                "всё готово к --apply" if plan and not rc2 else "НЕ ГОТОВО" if rc2 else "ВЫКЛАДЫВАТЬ НЕЧЕГО", len(plan),
                ", ".join(plan) or "—", "готовы" if not rc2 else "код %d" % rc2))
            flush(lines)
            return rc2 if rc2 else (0 if plan else 9)
        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "DLL: AsdaPatch (P108) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + "\\" + INI_REL, lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        rc2 = extras("apply", lines)
        if rc2:
            log(lines, "СТОП: встроенная правка не прошла (код %d): DLL v65 уже во всех папках, бэкапы сняты — откат: --rollback" % rc2)
            flush(lines)
            return rc2
        log(lines, "ГОТОВО: P108 (AsdaPatch %s) — DLL %d папок; секция [%s] Enabled=1 допишется при старте. Дальше restart_stack: "
                   "start.bat; в PatchLog — «Version … -> %d»; затем py -3.13 deploy_p108.py --check-started."
                   % (WANT_DLL, len(plan), SECTION, INI_VERSION))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
