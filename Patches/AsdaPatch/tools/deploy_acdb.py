# Copyright (c) 2026 @sitxovski (Discord)
# ★ УСТАРЕЛО (22.10.2026): работает через сетевую папку \\@@ASTORY_SERVER_HOSTNAME@@, которая висит. Выкладка — только по SSH по образцу
#   deploy_p77.py (restart_stack.py --deploy ...). Без ASDA_USE_SMB=1 скрипт сразу отказывается (код 3), не висит.
# deploy_acdb.py — выкладка волны античита на dev-сервер. ★ Редакция sec2c (2026-10-15, ревизия SEC2 Н-3/Н-4/Н-5): AsdaPatch
#   20539079 (Version 43) — атрибуция кика P47/P48/P49/P55 без гонок нитей карт: значение Secret до сброса — по CUser (таблица CAS
#   P49), +1 отказа P47 объявляется «прочим» под замком учёта до инкремента (pendingOther), база счётчика на начале учёта
#   (база + прочее ≤ порога). DBPatch 2cdd080b, AddonNPC 0bcf9bf5, LoginPatch 55106cd6 — пересобраны без правок исходников
#   (единый пин; md5 плавает по метке). LoginManager — в TARGETS последним («DLL → LoginPatch копированием»). Нового SQL нет.
#   Отчёт Reports/anticheat/wave_SEC2c_20261015.md. (P71+P72+N18, deploy_p71p72n18.py: AsdaPatch d5243b5d, DBPatch 5726b52f,
#   AddonNPC 46336972, LoginPatch d1e59013 — заменены.)
#
# Прежняя редакция p57fix2: (2026-10-15, ревизия review_P57_fix.md): AsdaPatch
#   633b4667 (Version 41) — p57fix + СРЕДН-1: из опережения вычитается собственный простой сервера на перезапуске отрезка
#   после каждого 4006 в движении (честные частые клики 5–10/с и WASD+камера 4/с больше не дают строк вида 17); комментарии
#   НИЗК-1/2/3. Остальные DLL, бэкап и суффикс — как в p57fix ниже. (p57fix: AsdaPatch 1afc8ed4 — заменена.)
# Прежняя редакция p57fix (2026-10-15, ложные срабатывания P57 MoveGuard на
#   честной игре владельца, event_id 7255–7257): AsdaPatch 1afc8ed4 (Version 41) — sec2b + P57: бюджет хода по накопленному пути
#   (+0x550E + экстраполяция с такта шага +0x5502, пополняемый бюджет опережения BudgetReserveMs/BudgetRefillPermille), MaxStepLen
#   не ниже 72500 (диагональ карты 512×512: у оригинала длину отрезка ограничивает только карта), массивы ограничителя строк P57
#   на виды 14..20 (раньше 13 — запись в соседнюю сессию). DBPatch 39c38764, AddonNPC 1a633410 — БЕЗ изменений (AcJournal.cpp
#   не менялся); LoginPatch f2d25fb6 — без изменений. Нового SQL нет. Отчёт Reports/anticheat/wave_P57_fix.md.
#   (sec2b: AsdaPatch 0f16948c — заменена.)
# Прежняя редакция sec2b (2026-10-15, ревизия SEC2 С-1/Н-1/Н-2/Н-6): AsdaPatch
#   0f16948c (Version 40) — sec2 + мост шифрования: при AllowLegacy=1 молчащий сокет по сроку снимается со счёта незавершённых
#   рукопожатий (С-1), ключ MaxPendingPerIp=16 (Н-1, ac.other 64 «from IP»), вытеснение очереди только если под замком она всё ещё
#   наибольшая (Н-2), общий предел TxQueueTotalMB — по реальной памяти кадров (Н-6), первый приём ждёт решения сторожа допуска;
#   DBPatch 39c38764 — пересобран без правок исходников; AddonNPC 1a633410 — + N16 (допуск скорости атаки 15 %, Config 7);
#   (sec2: AsdaPatch 34963251, DBPatch 7fa2254d, AddonNPC 333645f3, LoginPatch a69fc114 — заменены.)
#   Отчёт Reports/anticheat/wave_SEC2b_20261015.md.
# Редакция sec2 (2026-10-15, блок В плана альфы): AsdaPatch
#   34963251 (Version 39) — autoban + шифрование P61: Е-1 (очередь сбойного слота освобождается сразу), Е-2 (справедливая доля
#   общего предела, вытеснение наибольшей очереди — ac.other 61 причина 6), кэш ключа подписи + пул ECDH, допуск подключений
#   до рукопожатия (ac.other 63–65); P48 не засчитывает кик за нарушения целостности пакетов P55 (код 6), P49 — значение
#   Secret до сброса; DBPatch 7fa2254d и AddonNPC 333645f3 — пересобраны (общий AcJournal.cpp: виды 63–65, код 6); LoginPatch
#   (autoban на стойку ещё не выложен). (autoban: AsdaPatch 6f77e7f2, DBPatch e32d1fb9, AddonNPC b575d5fb, LoginPatch d923811e —
#   заменены.) Отчёт Reports/anticheat/wave_SEC2_20261015.md.
# Редакция autoban (2026-10-14, решение владельца 14.10): AsdaPatch
#   6f77e7f2 (Version 39) — fix2e + P69 «ступенчатый автоблок за нарушения целостности пакетов» (Mode=0 — только журнал
#   ac.other 62), учётка/адрес в журнал P55/P61; DBPatch e32d1fb9 и AddonNPC b575d5fb — пересобраны (общий AcJournal.cpp:
#   вид 62, колонки ac.packet_validator); LoginPatch d923811e (L07: учётка сессии и адрес из кэша) — копированием.
#   Скрипт сам проверяет (только чтение, db_connect) колонки session_state/char_owner_user_index и без них не выкладывает.
#   (fix2e: AsdaPatch f1d76b80, DBPatch ddea83ca, AddonNPC 6102075a, LoginPatch 37df021c — заменены.)
# Редакция fix2e (2026-10-14, ревизия fix2d Ф-1): AsdaPatch
#   f1d76b80 (Version 38) — fix2d + общий предел очередей моста на процесс TxQueueTotalMB=64 (сверх — разрыв слота,
#   ac.other 61 причина 4) + перехват нехватки памяти в мосте (разрыв слота, причина 5; процесс не падает); DBPatch ddea83ca и
#   AddonNPC 6102075a — пересобраны (общий AcJournal.cpp: текст вида 61); LoginPatch 37df021c — копированием.
#   (fix2d: AsdaPatch d6120de9, DBPatch d423db89, AddonNPC f32f0180, LoginPatch 6f2e6e00 — заменены.)
# Редакция fix2d (2026-10-14, хвост ревизии FIX2 «переполнение
#   досылки стока»): AsdaPatch d6120de9 (Version 38) — fix2c + П-1 (шифрованный кадр, который стоковая досылка 0x9F9C не
#   вместит, ждёт в очереди слота моста TxQueueKB=1 МБ) + П-2 (отказ стокового Send / переполнение очереди — разрыв, ac.other 61);
#   DBPatch d423db89 и AddonNPC f32f0180 — пересобраны (общий AcJournal.cpp: текст вида 61); LoginPatch 6f2e6e00 — копированием.
#   (fix2c: AsdaPatch e38c0a56, DBPatch 9d5a6e86, AddonNPC c3528e06, LoginPatch b9fc03ae — заменены.)
# Редакция fix2c (2026-10-13, ревизия FIX2): AsdaPatch e38c0a56
#   (Version 38) — fix2b + предел буфера стока 0x1000 (Н-1: шифрованные кадры ≤ 4096 б на вызов Send, приём стоку кусками
#   ≤ 4087), пауза 150 мс перед разрывом отказанного (Н-2), поколение слота (Н-3), IoWorker (Н-4); DBPatch 9d5a6e86 и AddonNPC
#   c3528e06 — без изменений с fix2; LoginPatch b9fc03ae — копированием. (fix2b: AsdaPatch 17fc1054, LoginPatch 2610336f — заменены.)
# Редакция fix2b (2026-10-13): AsdaPatch 17fc1054 (Version 38) —
#   fix2 + кадры сервера до рукопожатия (отказ 6004 после accept не теряется: очередь слота + отложенный DisConnect);
#   DBPatch 9d5a6e86 и AddonNPC c3528e06 — без изменений с fix2; LoginPatch 2610336f — копированием (ниже).
#   (редакция fix2: AsdaPatch d7986b6e, LoginPatch bec23089 — заменены.)
# Редакция fix2 (2026-10-13, находки ревизии INTEG3):
#   AsdaPatch d7986b6e (Version 38), DBPatch 9d5a6e86, AddonNPC c3528e06; LoginPatch bec23089 — копированием (ниже).
#   Б-1/Б-2 шифрования P61/L07 (замок слота не берётся под замком Ciocp; шифрование + стоковый Send под замком слота),
#   журнал — обрезка строк до ширины колонок + пределы файла (FileRowsPerMinute/MaxFileMB), НИЗК-5…12.
#   SQL acj2 (ширина колонок joylog1.ac.*) на dev УЖЕ применён 13.10 20:36. Отчёт Reports/anticheat/wave_FIX2_20261013.md.
# Прежняя редакция integ3 (2026-10-13): AsdaPatch v38 8cb990af =
#   fix13 + B7d (P61 разрыв при нарушении, ac.other 56–59) + P68 CharNameGuard (с исключением операторов) + такт замков
#   P33/P35/P44; DBPatch 94658eac и AddonNPC 941a5bbb — пересобраны (общий AcJournal.cpp: тексты видов 53–59).
#   (прежняя редакция fix13: AsdaPatch 7ad42f0e, DBPatch c76a0b03, AddonNPC 821126c4.)
#   LoginPatch (v7 d263d48d, L07 с B7d) этим скриптом НЕ выкладывается — копированием по чек-листу
#   Reports/anticheat/wave_INTEG3_20261013.md §5. Ключ шифрования и правка ini — вручную, там же.
#
# Что делает (только при остановленной стойке):
#   1. Проверяет, что сервер остановлен: каждый exe и каждая заменяемая DLL открываются на запись.
#      Хоть один занят — ничего не трогает (код 2).
#   2. Бэкап каждой заменяемой DLL: рядом <dll>.bak_20261015_p57fix и в
#      @@ASTORY_DEV_ROOT@@\_backup\2026-10-15_p57fix\server\v2\<папка>\<dll>; сверка размера и md5 копий.
#      Уже существующий бэкап не перезаписывается (сверяется, что это та же DLL).
#   3. Копирует собранную DLL и сверяет md5 выложенной с собранной.
# По умолчанию — сухой прогон (только проверки и план). Выкладка — ключ --apply.
# Журнал: Reports/anticheat/wP57FIX_logs/deploy.log (дописывается).
# Документы: AstoryServer/Docs/GameServer/ac-journal-p53.md, blocked-login-message-p54.md,
#            NpcServer/ac-journal-n13.md; INDEX.md (запись 12.10 acdb).
import hashlib
import os
import shutil
import sys
import time

from srv_paths import ROOT as SRV_ROOT, require_smb   # ★ 22.10.2026: корень стойки — локальное зеркало по SSH (srv_mirror.py); шара \\@@ASTORY_SERVER_HOSTNAME@@ только ASDA_USE_SMB=1
require_smb(__file__)   # ★ 22.10.2026: устарело — только ASDA_USE_SMB=1
SRV = SRV_ROOT + "/v2"          # корень dev-сервера
TOOLS = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches"                               # собранные DLL
BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-15_sec2c/server/v2"    # бэкап-копии
SUFFIX = ".bak_20261015_sec2c"                                  # суффикс бэкапа рядом
LOG = "@@ASTORY_DEV_ROOT_FWD@@/Reports/anticheat/wSEC2c_logs/deploy.log"     # журнал выкладки

# (папка на сервере, exe процесса, имя DLL, собранная DLL, ожидаемый md5 собранной)
TARGETS = [
    ("GameServer",       "GameServer.exe",   "AsdaPatch.dll",  TOOLS + "/AsdaPatch/out/AsdaPatch.dll",   "20539079b6fe0ef84143610af382bc76"),
    ("Indun_GameServer", "GameServer.exe",   "AsdaPatch.dll",  TOOLS + "/AsdaPatch/out/AsdaPatch.dll",   "20539079b6fe0ef84143610af382bc76"),
    ("DBManager",        "DBManager.exe",    "DBPatch.dll",    TOOLS + "/DBPatch/out/DBPatch.dll",       "2cdd080bbd3c7130f4633f06e35823d1"),
    ("NpcServer",        "NpcServer.exe",    "AddonNPC.dll",   TOOLS + "/AddonNPC/out/AddonNPC.dll",     "0bcf9bf50a146b4a87437370c528a0a8"),
    ("Indun_NpcServer",  "NpcServer.exe",    "AddonNPC.dll",   TOOLS + "/AddonNPC/out/AddonNPC.dll",     "0bcf9bf50a146b4a87437370c528a0a8"),
    ("LoginManager",     "LoginManager.exe", "LoginPatch.dll", TOOLS + "/LoginPatch/out/LoginPatch.dll", "55106cd6b38678f97ce7f36389bdf8aa"),
]


def md5(path):
    """md5 файла (hex)."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def writable(path):
    """True — файл открывается на запись (процесс его не держит)."""
    try:
        with open(path, "r+b"):
            return True
    except OSError:
        return False


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def backup_one(src, dst, lines):
    """Бэкап src → dst со сверкой размера и md5; существующий dst не перезаписывается."""
    want = md5(src)
    if os.path.exists(dst):
        have = md5(dst)
        if have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГАЯ DLL (%s ≠ %s) — разберись вручную" % (dst, have, want))
        log(lines, "  бэкап уже есть: %s (%s)" % (dst, have))
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    if os.path.getsize(dst) != os.path.getsize(src) or md5(dst) != want:
        raise RuntimeError("бэкап %s не сошёлся с оригиналом" % dst)
    log(lines, "  бэкап: %s %d б %s" % (dst, os.path.getsize(dst), want))


def sql_ready(lines):
    """★ autoban: SQL раньше DLL — колонки ac.packet_validator из autoban_01_migrate.sql есть (только чтение, db_connect).
    Без них AsdaPatch v39 валила бы каждый пакет журнала в файл. Не удалось проверить — False (выкладки нет)."""
    try:
        sys.path.insert(0, r"@@ASTORY_DEV_ROOT@@\AstoryServer\Tools\Anticheat")
        import db_connect as dbc
        cn = dbc.connect("joylog1")
        _, rows = dbc.query(cn, "SELECT COL_LENGTH(N'ac.packet_validator', N'session_state'), "
                                "COL_LENGTH(N'ac.packet_validator', N'char_owner_user_index')")
        ok = bool(rows) and rows[0][0] is not None and rows[0][1] is not None
        log(lines, "SQL autoban: колонки session_state/char_owner_user_index %s" % ("есть" if ok else "НЕТ"))
        return ok
    except Exception as e:   # нет драйвера/сети — не выкладываем вслепую
        log(lines, "SQL autoban: проверить не удалось (%s)" % e.__class__.__name__)
        return False


def main():
    """Точка входа: сухой прогон или --apply."""
    apply = "--apply" in sys.argv
    lines = []
    log(lines, "== deploy_acdb %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ВЫКЛАДКА" if apply else "сухой прогон"))
    if not sql_ready(lines):
        log(lines, "СТОП: сначала SQL AstoryServer/Docs/SQL/autoban_01_migrate.sql (порядок выкладки: SQL раньше DLL)")
        _flush(lines)
        return 5
    # Собранные DLL — те, что прошли стенды.
    for _, _, _, built, want in TARGETS:
        have = md5(built)
        if have != want:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (built, have, want))
            return 3
    # Сервер остановлен?
    busy = []
    for d, exe, dll, _, _ in TARGETS:
        for p in (SRV + "/" + d + "/" + exe, SRV + "/" + d + "/" + dll):
            if os.path.exists(p) and not writable(p):
                busy.append(p)
    if busy:
        for p in busy:
            log(lines, "  занят (процесс работает): " + p)
        log(lines, "СТОП: сервер не остановлен — ничего не тронуто")
        _flush(lines)
        return 2
    for d, exe, dll, built, want in TARGETS:
        live = SRV + "/" + d + "/" + dll
        log(lines, "%s: сейчас %s → будет %s" % (d, md5(live), want))
        if not apply:
            continue
        backup_one(live, live + SUFFIX, lines)
        backup_one(live, BACKUP + "/" + d + "/" + dll, lines)
        shutil.copy2(built, live)
        got = md5(live)
        log(lines, "%s выложено: %s %d б %s" % (d, got, os.path.getsize(live), "OK" if got == want else "НЕ СОШЛОСЬ"))
        if got != want:
            _flush(lines)
            return 4
    log(lines, "ГОТОВО" if apply else "сухой прогон: всё готово к --apply")
    _flush(lines)
    return 0


def _flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
