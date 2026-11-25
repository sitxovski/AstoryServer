# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p98.py — ВЫКЛАДКА / ОТКАТ P98 «стопочный предмет из премиум-почты приходит 1 шт.» (волна bugs7, 30.10.2026; баги игроков
#   «знак охоты 75521: нумпад Все = 0, сдача кодом 6», свитки 20936/20946/20952/23229 с количеством 0).
#   1. SQL-ремонт уже испорченных записей Joy1.dbo.Item: строки стопочных кодов ветки «расходник» (item_table: контейнер 2 по
#      правилу sub_5340B0, +35 «стопка» != 0, тип +26 != 10) с Amount <= 0 → Amount = 1, Weight = вес одной штуки (+5 строки,
#      u16 побитно в smallint, как fn_W16). Перед UPDATE — снимок строк в журнал dbo.AsdaP98AmountFix (одна транзакция, метка
#      RunUtc); вес персонажа в Charinfo не трогаем — UPCharInfo пересчитывает его SUM(Item.Weight) при входе.
#   2. AsdaPatch.dll (P98_PremiumStackAmount) во ВСЕ GameServer из stack_layout.GS_FOLDERS: живая a8480800 (v56 P01…P97) → WANT_DLL
#      (+ P98). Секцию [P98_PremiumStackAmount] (Enabled=1, JournalIntervalSec=10, LogChannel=38) DLL дописывает сама при старте.
#   Протокол не меняется. Документ: AstoryServer/Docs/GameServer/premium-stack-amount-p98.md.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор (с объявлением):
#     py -3.13 restart_stack.py --deploy deploy_p98.py --expect P98_PremiumStackAmount
#   (restart_stack останавливает стойку, зовёт этот скрипт с --apply, затем start.bat). После старта: deploy_p98.py --check-started
#
# Режимы:
#   (без ключа) — сухой прогон: md5 DLL/образов, занятость, план по папкам, список кодов из живой item_table и SQL-СТЕНД:
#                 копия строк стопочных кодов во временную #stand (tempdb), тот же UPDATE в транзакции, сверка, ROLLBACK —
#                 Joy1 не меняется (только SELECT); печать строк-кандидатов; тексты ремонта и отката — компиляция SET NOEXEC ON.
#   --apply     — стойка ОСТАНОВЛЕНА: SQL-ремонт (снимок + UPDATE одной транзакцией, отказ при расхождении или > MAX_ROWS строк),
#                 затем DLL (бэкапы рядом / v2\_backup / локально, заливка через временный файл со сверкой md5). «ГОТОВО» — только
#                 если прошло всё.
#   --rollback  — стойка остановлена: DLL из <файл>.bak_20261030_p98 (только поверх WANT). Быстро без замены: Enabled=0 + рестарт.
#   --rollback-sql — стойка остановлена: строки последнего прогона из dbo.AsdaP98AmountFix, не менявшиеся с ремонта
#                 (Amount = 1, Weight = WeightAfter), возвращаются к AmountBefore / WeightBefore.
#   --check-started — после старта (только чтение): PatchLog «[OK] P98_PremiumStackAmount» и строка «P98: премиум-почта 11006»,
#                 DLL = WANT; в БД нет строк-кандидатов.
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)
from deploy_p91 import decode_log

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT_DLL = "e41618f8d974501f683062c0cd627da3"                    # AsdaPatch v56 (P01…P97) + P98
PREV_DLL = {"a8480800f903d4f5452df45d1a2b730b": "AsdaPatch v56 P01…P97 (живая с 30.10 03:19)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261030_p98"
SRV_BACKUP = V2 + r"\_backup\2026-10-30_p98"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-30_bugs7/server/v2"
RUN_DIR = os.path.join(HERE, "run_p98_20261030_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]
ITEM_TABLE = r"ItemTable_Info\item_table.txt"
MAX_ROWS = 50                     # потолок строк ремонта (30.10 их 9); больше — СТОП, разбор вручную
SQLCMD = "& sqlcmd -S localhost\\SQLEXPRESS -E -b -h -1 -W -s '|' 2>&1"
# Колонки item_table.txt (42 шт.) → смещение в записи 71 б (порядок загрузчика sub_4A96A0; как verify_p95/verify_p98).
OFF = [0, 4, 5, 7, 8, 9, 11, 10, 12, 14, 18, 20, 21, 22, 24, 25, 26, 27, 28, 30, 32, 33, 34, 35, 36, 37, 41, 45, 46, 47, 49, 50, 54, 56,
       57, 58, 59, 60, 62, 63, 65, 67]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def s16(v):
    """u16 → smallint тем же битовым образом (как dbo.fn_W16): 32768…65535 → −32768…−1."""
    v = max(0, min(65535, v))
    return v - 65536 if v > 32767 else v


def stack_codes(lines):
    """Коды правила P98 и вес штуки — из ЖИВОЙ item_table (одинаковой во всех GS_FOLDERS). → {код: вес smallint}."""
    sums = {d: rmd5(V2 + "\\" + d + "\\" + ITEM_TABLE) for d in GS_FOLDERS}
    if len(set(sums.values())) != 1:
        raise RuntimeError("item_table.txt в папках GameServer различается: %s" % sums)
    data = rread(V2 + "\\" + GS_FOLDERS[0] + "\\" + ITEM_TABLE)
    if hashlib.md5(data).hexdigest() != list(sums.values())[0]:
        raise RuntimeError("item_table.txt, прочитанная по SSH, не сошлась по md5")
    codes = {}
    for ln in data.decode("latin-1").split("\n")[1:]:
        p = ln.split()
        if len(p) < 42:
            continue
        r = dict(zip(OFF, [int(x) for x in p[:42]]))
        cont2 = not (r[36] == 3 or r[26] in (0, 1, 2, 3, 4, 8, 9, 12, 13, 14, 15))   # sub_5340B0: контейнер 2
        if cont2 and r[35] != 0 and r[26] != 10:
            codes[r[0]] = s16(r[5] & 0xFFFF)
    log(lines, "  item_table %s (одинакова в %d папках): кодов правила P98 %d (75521: %s, 20936: %s, 20952: %s)"
        % (list(sums.values())[0][:8], len(GS_FOLDERS), len(codes), codes.get(75521), codes.get(20936), codes.get(20952)))
    if not all(c in codes for c in (75521, 20936, 20946, 20952, 23229)):
        raise RuntimeError("в списке нет одного из кодов бага (75521/20936/20946/20952/23229) — таблица не та")
    return codes


def codes_sql(codes):
    """#c (Code, W) — кодами пачками по 900 строк (предел VALUES — 1000)."""
    out = ["IF OBJECT_ID('tempdb..#c') IS NOT NULL DROP TABLE #c;", "CREATE TABLE #c (Code INT PRIMARY KEY, W SMALLINT NOT NULL);"]
    items = sorted(codes.items())
    for i in range(0, len(items), 900):
        out.append("INSERT INTO #c (Code, W) VALUES " + ",".join("(%d,%d)" % kv for kv in items[i:i + 900]) + ";")
    return "\n".join(out)


def sql_stand(codes):
    """SQL-стенд: копия строк стопочных кодов в #stand (tempdb), UPDATE в транзакции, сверка, ROLLBACK. Joy1 — только SELECT."""
    return "\n".join([
        "SET NOCOUNT ON; SET XACT_ABORT ON;",
        codes_sql(codes),
        "SELECT i.Uuid, i.Userindex, i.Charidx, i.Code, i.Plate, i.Posx, i.Amount, i.Weight INTO #stand",
        "  FROM Joy1.dbo.Item i JOIN #c c ON c.Code = i.Code;",
        "CREATE TABLE #log (Uuid UNIQUEIDENTIFIER, AmountBefore INT, WeightBefore SMALLINT, AmountAfter INT, WeightAfter SMALLINT);",
        "SELECT CONCAT('P98ROW|', s.Userindex, '|', s.Charidx, '|', s.Uuid, '|', s.Code, '|', s.Plate, '|', s.Posx, '|', s.Amount, '|',",
        "  s.Weight, '|', c.W) FROM #stand s JOIN #c c ON c.Code = s.Code WHERE s.Amount <= 0 ORDER BY s.Userindex, s.Charidx, s.Code;",
        "DECLARE @all INT = (SELECT COUNT(*) FROM #stand), @snap INT, @upd INT, @left INT, @other INT, @bad INT;",
        "BEGIN TRAN;",
        "INSERT INTO #log SELECT s.Uuid, s.Amount, s.Weight, 1, c.W FROM #stand s JOIN #c c ON c.Code = s.Code WHERE s.Amount <= 0;",
        "SET @snap = @@ROWCOUNT;",
        "UPDATE s SET s.Amount = 1, s.Weight = c.W FROM #stand s JOIN #c c ON c.Code = s.Code WHERE s.Amount <= 0;",
        "SET @upd = @@ROWCOUNT;",
        "SET @left = (SELECT COUNT(*) FROM #stand WHERE Amount <= 0);",
        # строки вне журнала обязаны совпасть с Joy1; строки журнала — 1 / вес штуки
        "SET @other = (SELECT COUNT(*) FROM #stand s JOIN Joy1.dbo.Item i ON i.Uuid = s.Uuid",
        "  WHERE s.Uuid NOT IN (SELECT Uuid FROM #log) AND (s.Amount <> i.Amount OR s.Weight <> i.Weight));",
        "SET @bad = (SELECT COUNT(*) FROM #stand s JOIN #log l ON l.Uuid = s.Uuid WHERE s.Amount <> 1 OR s.Weight <> l.WeightAfter);",
        "SELECT CONCAT('P98STAND|all=', @all, '|snap=', @snap, '|upd=', @upd, '|left=', @left, '|other_changed=', @other, '|bad=', @bad);",
        "ROLLBACK;",
        "SELECT CONCAT('P98STAND|after_rollback_candidates=', (SELECT COUNT(*) FROM #stand WHERE Amount <= 0));",
        "GO",
    ]) + "\n"


def sql_apply(codes, max_rows):
    """Ремонт Joy1: журнал dbo.AsdaP98AmountFix, снимок + UPDATE одной транзакцией; отказ при snap ≠ upd или > max_rows."""
    return "\n".join([
        "SET NOCOUNT ON; SET XACT_ABORT ON;",
        "USE Joy1;",
        "IF OBJECT_ID('dbo.AsdaP98AmountFix', 'U') IS NULL",
        "  CREATE TABLE dbo.AsdaP98AmountFix (Id INT IDENTITY(1,1) PRIMARY KEY, RunUtc DATETIME2 NOT NULL, Userindex INT NOT NULL,",
        "    Charidx TINYINT NOT NULL, Uuid UNIQUEIDENTIFIER NOT NULL, Code INT NOT NULL, Plate TINYINT, Posx SMALLINT,",
        "    AmountBefore INT NOT NULL, WeightBefore SMALLINT NOT NULL, AmountAfter INT NOT NULL, WeightAfter SMALLINT NOT NULL, GainDate DATETIME);",
        "GO",
        codes_sql(codes),
        "DECLARE @now DATETIME2 = SYSUTCDATETIME(), @snap INT, @upd INT;",
        "BEGIN TRAN;",
        "INSERT INTO dbo.AsdaP98AmountFix (RunUtc, Userindex, Charidx, Uuid, Code, Plate, Posx, AmountBefore, WeightBefore, AmountAfter, WeightAfter, GainDate)",
        "  SELECT @now, i.Userindex, i.Charidx, i.Uuid, i.Code, i.Plate, i.Posx, i.Amount, i.Weight, 1, c.W, i.GainDate",
        "  FROM dbo.Item i WITH (UPDLOCK, HOLDLOCK) JOIN #c c ON c.Code = i.Code WHERE i.Amount <= 0;",
        "SET @snap = @@ROWCOUNT;",
        "UPDATE i SET i.Amount = 1, i.Weight = c.W FROM dbo.Item i JOIN #c c ON c.Code = i.Code WHERE i.Amount <= 0;",
        "SET @upd = @@ROWCOUNT;",
        "IF @snap <> @upd OR @upd > %d" % max_rows,
        "BEGIN",
        "  ROLLBACK;",
        "  SELECT CONCAT('P98SQL|FAIL|snap=', @snap, '|upd=', @upd, '|max=%d');" % max_rows,
        "  THROW 50098, 'P98 SQL: snap <> upd or too many rows - rolled back', 1;",
        "END",
        "COMMIT;",
        "SELECT CONCAT('P98SQL|OK|run=', CONVERT(VARCHAR(30), @now, 126), '|snap=', @snap, '|upd=', @upd, '|left=',",
        "  (SELECT COUNT(*) FROM dbo.Item i JOIN #c c ON c.Code = i.Code WHERE i.Amount <= 0));",
        "SELECT CONCAT('P98FIX|', Userindex, '|', Charidx, '|', Uuid, '|', Code, '|', Plate, '|', Posx, '|', AmountBefore, '|', WeightBefore,",
        "  '->', AmountAfter, '|', WeightAfter) FROM dbo.AsdaP98AmountFix WHERE RunUtc = @now ORDER BY Userindex, Charidx, Code;",
        "GO",
    ]) + "\n"


def sql_rollback():
    """Откат ремонта: строки последнего прогона, не менявшиеся с него, — к AmountBefore / WeightBefore."""
    return "\n".join([
        "SET NOCOUNT ON; SET XACT_ABORT ON;",
        "USE Joy1;",
        "IF OBJECT_ID('dbo.AsdaP98AmountFix', 'U') IS NULL BEGIN SELECT 'P98RB|NOLOG'; RETURN; END",
        "DECLARE @run DATETIME2 = (SELECT MAX(RunUtc) FROM dbo.AsdaP98AmountFix), @n INT, @all INT;",
        "SET @all = (SELECT COUNT(*) FROM dbo.AsdaP98AmountFix WHERE RunUtc = @run);",
        "BEGIN TRAN;",
        "UPDATE i SET i.Amount = f.AmountBefore, i.Weight = f.WeightBefore FROM dbo.Item i JOIN dbo.AsdaP98AmountFix f ON f.Uuid = i.Uuid",
        "  WHERE f.RunUtc = @run AND i.Amount = f.AmountAfter AND i.Weight = f.WeightAfter;",
        "SET @n = @@ROWCOUNT;",
        "COMMIT;",
        "SELECT CONCAT('P98RB|OK|run=', CONVERT(VARCHAR(30), @run, 126), '|restored=', @n, '|of=', @all);",
        "GO",
    ]) + "\n"


def run_sql(tag, text, lines, timeout=600):
    """SQL на сервере: текст в stdin sqlcmd (файлы на сервер не пишутся); копия текста — в RUN_DIR. → (успех, строки вывода)."""
    os.makedirs(RUN_DIR, exist_ok=True)
    path = os.path.join(RUN_DIR, "%s_%s.sql" % (time.strftime("%Y%m%d_%H%M%S"), tag))
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    rc, out = ps("$s = [Console]::In.ReadToEnd(); $o = $s | %s; Write-Output ($o -join \"`n\"); Write-Output ('RC=' + $LASTEXITCODE)" % SQLCMD,
                 stdin=text.encode("ascii"), timeout=timeout)
    res = [l.strip() for l in out.splitlines() if l.strip()]
    good = rc == 0 and "RC=0" in res
    for l in res:
        if l.startswith(("P98", "Msg", "Сообщение", "RC=")) or "rror" in l:
            log(lines, "    " + l[:300])
    log(lines, "  SQL %s (%s): %s" % (tag, os.path.basename(path), "OK" if good else "ОШИБКА"))
    return good, res


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-30_p98 и локально; существующие не перезаписываются."""
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
    up = dst + ".p98_upload"
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


def check_started(lines):
    """После старта: PatchLog каждого GameServer, блок последнего запуска — «[OK] P98_PremiumStackAmount» и строка «P98: премиум-почта
    11006», без провалов (patchlog); DLL = WANT; в БД нет строк-кандидатов (только чтение)."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P98_PremiumStackAmount"], ["P98: премиум-почта 11006"], log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        # ★ 31.10.2026: более поздняя сборка цепочки (dll_builds) при подтверждённом журнале — не провал
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    codes = stack_codes(lines)
    okq, res = run_sql("check", "SET NOCOUNT ON;\n" + codes_sql(codes) + "\nSELECT CONCAT('P98CHECK|left=', (SELECT COUNT(*) FROM Joy1.dbo.Item i "
                       "JOIN #c c ON c.Code = i.Code WHERE i.Amount <= 0), '|logged=', CASE WHEN OBJECT_ID('Joy1.dbo.AsdaP98AmountFix', 'U') IS NULL "
                       "THEN -1 ELSE (SELECT COUNT(*) FROM Joy1.dbo.AsdaP98AmountFix) END);\nGO\n", lines)
    good = good and okq and any(l.startswith("P98CHECK|left=0|") for l in res)
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --rollback-sql, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    rollback_sql = "--rollback-sql" in sys.argv
    lines = []
    mode = ("ОТКАТ SQL" if rollback_sql else "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply
            else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон")
    log(lines, "== deploy_p98 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
        if busy and (apply or rollback or rollback_sql):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")

        if rollback_sql:
            good, res = run_sql("rollback", sql_rollback(), lines)
            log(lines, "ОТКАТ SQL %s" % ("ГОТОВ" if good and any(l.startswith("P98RB|OK|") for l in res) else "НЕ ПРОШЁЛ"))
            flush(lines)
            return 0 if good else 4

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
            log(lines, "ОТКАТ ГОТОВ (DLL %d папок; секция [P98_PremiumStackAmount] в ini останется и будет проигнорирована; ремонт БД "
                       "не откатывается — для него --rollback-sql). Нужен старт стойки." % len(todo))
            flush(lines)
            return 0

        if md5(BUILT_DLL) != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, md5(BUILT_DLL), WANT_DLL))
            flush(lines)
            return 3
        plan = []
        for d in GS_FOLDERS:
            exe = rmd5(V2 + "\\" + d + r"\GameServer.exe")
            cur = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P98)" % (
                d, exe, cur, PREV_DLL.get(cur, "уже P98" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадка P98 сверена по %s" % (d, exe, GS_EXE))
                flush(lines)
                return 8
            if cur == WANT_DLL:
                continue
            if cur not in PREV_DLL:
                log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
                flush(lines)
                return 8
            plan.append(d)
        codes = stack_codes(lines)

        if not apply:
            good, res = run_sql("stand", sql_stand(codes), lines)
            st = [l for l in res if l.startswith("P98STAND|all=")]
            rows = [l for l in res if l.startswith("P98ROW|")]
            ok = good and st and "|left=0|other_changed=0|bad=0" in st[0]
            parts = dict(kv.split("=") for kv in st[0].split("|")[1:]) if st else {}
            ok = ok and parts.get("snap") == parts.get("upd") == str(len(rows)) and int(parts.get("upd", "0")) <= MAX_ROWS
            ok = ok and any(l == "P98STAND|after_rollback_candidates=%d" % len(rows) for l in res)
            log(lines, "  SQL-стенд (#stand в tempdb, ROLLBACK): кандидатов %d — %s" % (len(rows), "сошлось" if ok else "НЕ СОШЛОСЬ"))
            # тексты ремонта и отката — только компиляция (SET NOEXEC ON: ничего не выполняется)
            for tag, text in (("apply_noexec", sql_apply(codes, MAX_ROWS)), ("rollback_noexec", sql_rollback())):
                g2, r2 = run_sql(tag, "SET NOEXEC ON;\n" + text, lines)
                ok = ok and g2
                log(lines, "  компиляция %s (NOEXEC): %s" % (tag.split("_")[0], "без ошибок" if g2 else "ОШИБКА"))
            log(lines, "сухой прогон: %s (DLL — %d папок из stack_layout: %s; SQL — %d строк)" % (
                "всё готово к --apply" if ok and plan else "ЕСТЬ ЗАМЕЧАНИЯ", len(plan), ", ".join(plan) or "—", len(rows)))
            flush(lines)
            return 0 if ok and plan else 9

        if not plan:
            log(lines, "СТОП: DLL уже выложена во все папки")
            flush(lines)
            return 8
        log(lines, "1. SQL: ремонт Joy1.dbo.Item (снимок в dbo.AsdaP98AmountFix + UPDATE одной транзакцией)")
        good, res = run_sql("apply", sql_apply(codes, MAX_ROWS), lines)
        if not good or not any(l.startswith("P98SQL|OK|") and l.endswith("|left=0") for l in res):
            log(lines, "СТОП: SQL-ремонт не прошёл (транзакция откатилась) — DLL НЕ тронуты")
            flush(lines)
            return 5
        log(lines, "2. DLL: AsdaPatch (P98) в %d папках" % len(plan))
        for d in plan:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
            backup_one(d + r"\AsdaPatch.dll", lines)
            put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: P98 (AsdaPatch %s) в %d папках + SQL-ремонт. Дальше restart_stack: start.bat; в PatchLog — "
                   "«[OK] P98_PremiumStackAmount»; затем py -3.13 deploy_p98.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
