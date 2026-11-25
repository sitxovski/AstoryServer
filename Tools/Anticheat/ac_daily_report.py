# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""ac_daily_report.py - суточный отчёт античита (мера 4 плана, только чтение).

Читает журналы серверов с шары (GameServer, Indun_GameServer, NpcServer, LoginManager), считает метрики
M1 M5 M6 M6b M7 M7d M8 M9 M11 M12 M12o и делает SELECT-отчёты M3 / M4 / M8 (LogInfo) и сводку joylog1.ac.
Пишет Markdown ac_report_<дата>.md и CSV по событиям (ac_<дата>_<метрика>.csv) в --out.

Шару и БД не меняет: файлы открываются на чтение, SQL проходит через проверку «только SELECT».
Пароли/хеши в отчёт не попадают. Подробности и пороги - README.md.

Запуск:  python ac_daily_report.py --date 2026-10-11
         python ac_daily_report.py --date 2026-10-12 --days 400 --out D:\\tmp\\ac
         python -I ac_daily_report.py ...   (допустим; для БД-части нужен pyodbc из пользовательского site-packages,
                                             при -I он не виден - тогда БД-метрики честно пишут «нет данных»)
Побочных эффектов при импорте нет - всё в main() под `if __name__ == "__main__"`.
"""
import argparse
import collections
import csv
import datetime as dt
import os
import sys
import time

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Server", "Patches", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/REPORT.md §3.1

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = "//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/ASDA/Working_ASDA/v2"
DEFAULT_OTP_ARCHIVE = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-12_otp_report_archive"
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "..", "Reports", "anticheat", "daily"))


def _load_modules():
    """Подгрузка соседних модулей (при `python -I` каталог скрипта не в sys.path)."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import ac_common
    import ac_metrics_logs
    return ac_common, ac_metrics_logs


def md(s):
    """Экранирование ячейки таблицы Markdown."""
    return str(s).replace("|", "/").replace("\n", " ").replace("\r", " ")


def table(headers, rows):
    out = ["| " + " | ".join(md(h) for h in headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(md(c) for c in r) + " |")
    return "\n".join(out)


def failed(C, mid, title, e):
    """Метрика, которую не удалось посчитать из-за исключения e: «ошибка» (без модуля - «нет данных»)."""
    m = C.Metric(mid, title)
    if isinstance(e, ModuleNotFoundError):
        m.status = "нет данных"
        m.notes.append("нет модуля %s (при `python -I` пользовательский pyodbc не виден - запустить без -I)." % e.name)
    else:
        m.status = "ошибка"
        m.notes.append("%s: %s" % (type(e).__name__, str(e)[:200]))
    m.source = "см. README.md"
    return m


def safe(C, mid, title, fn, *a):
    """Запуск метрики с перехватом ошибок: падение одной метрики не рушит отчёт."""
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001 - отчёт должен жить при любой ошибке источника
        return failed(C, mid, title, e)


def needs(C, mid, title, err, fn, *a):
    """★ 22.11.2026 (ревизия 56 Н-1 админ-центра): метрика от общего источника (сессии Log_LevelUp, записи OTP_Report). Источник не
    прочитался (файл занят писателем, исчез между листингом и чтением) - «ошибка» у зависящих метрик, остальные считаются.
    Было: load_sessions / load_otp вне safe() - исключение роняло весь отчёт."""
    if err is not None:
        m = failed(C, mid, title, err)
        m.notes.insert(0, "общий источник метрики не прочитан:")
        return m
    return safe(C, mid, title, fn, *a)


def summary_row(C, ctx, m):
    per = collections.Counter(e.subject for e in m.events if e.subject)
    total = m.total_override if m.total_override is not None else len(m.events)
    if m.top_override is not None:
        top = m.top_override
    else:
        top = ", ".join("%s: %d" % (k, v) for k, v in per.most_common(5))
    avg = "%.1f / %d" % (sum(per.values()) / len(per), max(per.values())) if per else "-"
    if getattr(m, "no_owner", False):
        non = "-"
    else:
        real = [e.subject for e in m.events if e.subject and not e.subject.startswith(("(", "ui:", "ip:", "serial"))]
        unk = [e.subject for e in m.events if e.subject.startswith(("(", "ui:", "ip:"))]
        n_non = sum(1 for s in real if not ctx.is_owner(s))
        non = str(n_non) + (" (+%d без ника)" % len(unk) if unk else "")
    fa = sum(1 for s, _ in m.flags if not ctx.is_owner(s))
    fb = len(m.flags) - fa
    status = m.status if m.status != "ok" else ("данные есть" if (m.events or total) else "событий нет")
    return [m.mid, total, len(per), avg, top or "-", non, "%d / %d" % (fa, fb), status]


def render(C, ctx, metrics, meta):
    L = []
    rng = ctx.d1.isoformat() if ctx.d0 == ctx.d1 else "%s .. %s (%d дн.)" % (ctx.d0, ctx.d1, len(ctx.dates))
    L.append("# Суточный отчёт античита: %s" % rng)
    L.append("")
    L.append("Сформирован %s, прогон %.1f с. Режим: **только чтение** (шара и БД не менялись). Источник: `%s`."
             % (dt.datetime.now().strftime("%Y-%m-%d %H:%M"), meta["elapsed"], ctx.root))
    L.append("Серверы: %s; Npc: %s. Список владельца (regex): `%s`." % (", ".join(ctx.gs_servers), ", ".join(ctx.npc_servers), ctx.owner.pattern))
    L.append("")
    L.append("## Итог")
    L.append("")
    L.append(table(["Метрика", "Всего", "Субъектов", "На субъекта (ср. / макс.)", "Топ-5", "Вне владельца", "Флагов (вне / фон)", "Статус"],
                   [summary_row(C, ctx, m) for m in metrics]))
    L.append("")
    L.append("«Вне владельца» - события на никах вне списка владельца; «без ника» - источник ника не даёт (userindex/IP). "
             "Флаги «вне» = субъект не из списка владельца или не определён; «фон» = учётки владельца (справочно).")
    L.append("")
    # флаги
    fa_lines, fb_count = [], []
    for m in metrics:
        a = [(s, t) for s, t in m.flags if not ctx.is_owner(s)]
        b = [(s, t) for s, t in m.flags if ctx.is_owner(s)]
        if a:
            fa_lines.append((m, a))
        if b:
            fb_count.append((m, b))
    L.append("## Флаги вне списка владельца (кандидаты на разбор)")
    L.append("")
    if not fa_lines:
        L.append("Нет: на учётках вне списка владельца пороги не превышены.")
    for m, a in fa_lines:
        L.append("**%s** (%d):" % (m.mid, len(a)))
        for s, t in a[:30]:
            L.append("- `%s` - %s" % (s or "?", md(t)))
        if len(a) > 30:
            L.append("- ... и ещё %d (полный список в CSV)" % (len(a) - 30))
        L.append("")
    L.append("## Фон владельца (справочно)")
    L.append("")
    if not fb_count:
        L.append("Флагов на учётках владельца нет.")
    for m, b in fb_count:
        cnt = collections.Counter(s for s, _ in b)
        L.append("- **%s**: %d флагов; по нику: %s" % (m.mid, len(b), ", ".join("%s: %d" % kv for kv in cnt.most_common(6))))
    L.append("")
    L.append("## Метрики")
    for m in metrics:
        L.append("")
        L.append("### %s - %s" % (m.mid, m.title))
        L.append("")
        L.append("- Источник: %s" % m.source)
        L.append("- Формула/порог: %s" % m.formula)
        L.append("- Статус: **%s**" % m.status)
        for n in m.notes:
            L.append("- %s" % n)
        for name, hd, rows in m.tables:
            if rows:
                L.append("")
                L.append("**%s**" % name)
                L.append("")
                L.append(table(hd, rows))
        if m.events:
            L.append("")
            L.append("Последние события (из %d, полный список в CSV):" % len(m.events))
            L.append("")
            ev = sorted(m.events, key=lambda e: e.ts)[-8:]
            L.append(table(["Время", "Источник", "Субъект", "Вид", "Деталь"],
                           [[C.fmt_ts(e.ts), e.src, e.subject, e.kind, e.detail[:90]] for e in ev]))
    L.append("")
    return "\n".join(L)


def write_csv(C, ctx, metrics):
    os.makedirs(ctx.out, exist_ok=True)
    files = []
    for m in metrics:
        if m.events:
            p = os.path.join(ctx.out, "ac_%s_%s.csv" % (ctx.tag, m.mid))
            with open(p, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["time", "source", "subject", "kind", "detail", "file", "ip"])
                for e in sorted(m.events, key=lambda e: e.ts):
                    w.writerow([C.fmt_ts(e.ts), e.src, e.subject, e.kind, e.detail, e.file, e.ip])
            files.append(p)
        for i, (name, hd, rows) in enumerate(m.tables, 1):
            if rows and m.mid in ("M3", "M4", "ACJ", "M8"):
                p = os.path.join(ctx.out, "ac_%s_%s_t%d.csv" % (ctx.tag, m.mid, i))
                with open(p, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.writer(f)
                    w.writerow(hd)
                    w.writerows(rows)
                files.append(p)
    return files


def build(C, L, ctx):
    """Считает все метрики; возвращает список Metric в порядке отчёта."""
    ms = []
    t0 = time.time()
    sess = info = recs = otpcnt = None
    sess_err = otp_err = None
    try:
        sess, info = L.load_sessions(ctx)
    except Exception as e:  # noqa: BLE001 - ★ ревизия 56 Н-1: занятый Log_LevelUp - «ошибка» у M1 / M9, а не падение отчёта
        sess_err = e
    try:
        recs, otpcnt = L.load_otp(ctx)
    except Exception as e:  # noqa: BLE001 - ★ ревизия 56 Н-1: занятый OTP_Report - «ошибка» у M8 / M12 / M12o
        otp_err = e
    ms.append(needs(C, "M1", "Опыт в час", sess_err, L.metric_m1, ctx, sess))
    ms.append(safe(C, "M3", "Сделки между парой", _db, ctx, "M3", "Сделки между парой"))
    ms.append(safe(C, "M4", "Дубли предметов", _db, ctx, "M4", "Дубли предметов"))
    ms.append(safe(C, "M5", "Перемещение", L.metric_m5, ctx))
    ms.append(safe(C, "M6", "Скорость атаки", L.metric_m6, ctx))
    ms.append(safe(C, "M6b", "Спидхак по пингу", L.metric_m6b, ctx))
    ms.append(safe(C, "M7", "Подделка пакетов", L.metric_m7, ctx))
    ms.append(safe(C, "M7d", "Исключительные отключения", L.metric_m7d, ctx))
    m8 = needs(C, "M8", "Мультиаккаунт", otp_err, L.metric_m8, ctx, recs)
    _merge_m8_db(C, L, ctx, m8)
    ms.append(m8)
    ms.append(needs(C, "M9", "Длительность сессий", sess_err, L.metric_m9, ctx, sess, info))
    ms.append(safe(C, "M11", "Действия GM", L.metric_m11, ctx))
    ms.append(needs(C, "M12", "Перебор паролей", otp_err, L.metric_m12, ctx, recs, otpcnt))
    ms.append(needs(C, "M12o", "Повторный вход", otp_err, L.metric_m12o, ctx, recs))
    ms.append(safe(C, "ACJ", "Журнал joylog1.ac", _db, ctx, "ACJ", "Журнал joylog1.ac"))
    for m in ms:
        if m.mid in ("M3", "M4", "ACJ"):
            m.no_owner = True
    if ctx.with_db:      # ui:N -> логин(ui:N) по Us_member, чтобы отличить учётки владельца
        try:
            import ac_metrics_db as D
            D.resolve_userindexes(ctx, ms, L.operator_ui_map(ctx))
        except Exception as e:  # noqa: BLE001
            ms[0].notes.append("Замена ui:N на логины не выполнена: %s" % str(e)[:100])
    return ms


def _db(ctx, mid, title):
    """Запуск БД-метрики; без БД / без pyodbc - честное «нет данных»."""
    import ac_common as C
    m = C.Metric(mid, title)
    if not ctx.with_db:
        m.status = "нет данных"
        m.notes.append("БД отключена (--no-db).")
        return m
    try:
        import ac_metrics_db as D
    except ImportError as e:
        m.status = "нет данных"
        m.notes.append("БД недоступна: %s (при `python -I` пользовательский pyodbc не виден - запустить без -I)." % e)
        return m
    return {"M3": D.metric_m3, "M4": D.metric_m4, "ACJ": D.metric_acj}[mid](ctx)


def _merge_m8_db(C, L, ctx, m8):
    """Добавляет к M8 записи JoyLog1.LogInfo и пересчитывает граф (флаги/таблицы) по объединению источников."""
    if not ctx.with_db:
        m8.notes.append("LogInfo: БД отключена (--no-db).")
        _loginproc(L, ctx, m8)
        return
    try:
        import ac_metrics_db as D
        rows, total = D.loginfo_rows(ctx)
    except Exception as e:  # noqa: BLE001
        m8.notes.append("LogInfo недоступна: %s: %s" % (type(e).__name__, str(e)[:120]))
        _loginproc(L, ctx, m8)
        return
    trip = list(getattr(m8, "triples", []))
    empty_mac = 0
    for login, ip, mac, n, first, last in rows:
        m8.add(last, "JoyLog1.LogInfo", login, "login-ip-mac", "n=%d, %s .. %s, mac=%s" % (n, C.fmt_ts(first), C.fmt_ts(last), mac or "-"), "", ip)
        trip.append((login, ip, mac))
        if not mac:
            empty_mac += n
    m8.total_override = (m8.total_override or 0) + total
    m8.flags, m8.tables = [], []
    L.graph_flags(m8, trip)
    _loginproc(L, ctx, m8)
    m8.notes.append("LogInfo за окно: %d входов, из них с пустым MAC %d (LoginManager MAC в UPUserLogin не передаёт - 04 §1.6)." % (total, empty_mac))


def _loginproc(L, ctx, m8):
    """★ 22.11.2026 (ревизия 57 Н-1 админ-центра): таблица подключений LoginProc у M8 - третий общий источник (LoginManager держит
    LoginProc_<дата> так же, как OTP_Report). Не прочитался - «ошибка» у M8 с причиной, остальной отчёт считается. Было: вызов вне
    safe() / needs() - исключение роняло весь отчёт."""
    try:
        L.loginproc_ips(ctx, m8)
    except Exception as e:  # noqa: BLE001
        m8.status = "ошибка"
        m8.notes.append("LoginProc не прочитан: %s: %s" % (type(e).__name__, str(e)[:200]))


def parse_args(argv):
    ap = argparse.ArgumentParser(description="Суточный отчёт античита (только чтение).")
    ap.add_argument("--date", help="последний день окна YYYY-MM-DD (по умолчанию вчера)")
    ap.add_argument("--days", type=int, default=1, help="длина окна в днях, считая --date назад (по умолчанию 1)")
    ap.add_argument("--root", default=DEFAULT_ROOT, help="корень сервера v2 (по умолчанию шара)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="папка для отчёта и CSV")
    ap.add_argument("--otp-archive", default=DEFAULT_OTP_ARCHIVE, help="архив OTP_Report (пустая строка - не использовать)")
    ap.add_argument("--owner-regex", default=None, help="regex ников/логинов владельца (фон, не нарушение)")
    ap.add_argument("--servers", default=",".join(stack_layout.GS_FOLDERS))        # 26.10: + Ch2_GameServer
    ap.add_argument("--npc-servers", default=",".join(stack_layout.NPC_FOLDERS))   # 26.10: + Ch2_NpcServer
    ap.add_argument("--no-db", action="store_true", help="не выполнять SELECT-отчёты (M3/M4/M8-LogInfo/ACJ)")
    ap.add_argument("--thr", action="append", default=[], metavar="KEY=VAL", help="переопределить порог (см. README)")
    ap.add_argument("--selftest", action="store_true", help="самопроверка на синтетических данных (без шары и БД)")
    return ap.parse_args(argv)


def run(args):
    C, L = _load_modules()
    for kv in args.thr:
        k, _, v = kv.partition("=")
        if k not in C.THR:
            raise SystemExit("неизвестный порог %s; допустимые: %s" % (k, ", ".join(sorted(C.THR))))
        C.THR[k] = type(C.THR[k])(v)
    d1 = dt.datetime.strptime(args.date, "%Y-%m-%d").date() if args.date else dt.date.today() - dt.timedelta(days=1)
    d0 = d1 - dt.timedelta(days=max(1, args.days) - 1)
    ctx = C.Ctx(args.root, d0, d1, args.out, args.owner_regex or C.DEFAULT_OWNER_RE,
                [s for s in args.servers.split(",") if s], [s for s in args.npc_servers.split(",") if s],
                args.otp_archive, not args.no_db)
    t0 = time.time()
    metrics = build(C, L, ctx)
    meta = {"elapsed": time.time() - t0}
    text = render(C, ctx, metrics, meta)
    os.makedirs(ctx.out, exist_ok=True)
    p = os.path.join(ctx.out, "ac_report_%s.md" % ctx.tag)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    files = write_csv(C, ctx, metrics)
    return ctx, metrics, p, files, C


def selftest():
    """Синтетический прогон: проверяет разбор, флаги и защиту «только SELECT». Возвращает 0 при успехе."""
    import tempfile
    import shutil
    C, L = _load_modules()
    import db_connect
    tmp = tempfile.mkdtemp(prefix="ac_selftest_")
    try:
        def w(rel, lines):
            p = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(("\r\n".join(lines) + "\r\n").encode("cp1251"))
        pre = "01 Mon 05 Day %02d hou %02d min %02d sec : "
        w("GameServer/Log/Log_Game/GameLog_20260105.txt",
          [pre % (10, m, 0) + "CharMove Hack Position Cheater Error" for m in range(0, 6)] +
          [pre % (11, 0, 0) + "CharMove Hack Position GM_sitxovski Error",
           pre % (11, 1, 0) + "___ExceptionDisConnetUser___ CallFunc = CharMove(), UserNum = 3, CharN = Cheater, IP = 10.0.0.5"])
        w("GameServer/Log/Log_Secret/Secret_20260105.txt",
          [pre % (12, 0, 0) + "\t123\tCheater\tSecret Error\tUser 1, Server 2, CharMove()"])
        w("GameServer/Log/Log_LevelUp/LevelUp_20260105.txt",
          [pre % (1, 0, 0) + "CUserManager::CharLogonRes1\tCharName\tBotty\tLevel\t5\tExp\t100",
           pre % (10, 0, 0) + "CUserManager::DisConnectUser\tCharName\tBotty\tLevel\t6\tExp\t90100"])
        w("GameServer/Log/Log_Operator/OperatorLog_20260105.txt",
          [pre % (9, 0, 0) + "Recv_OperatorCommand_ItemGive() Give OK UserID = GM_sitxovski, 2 -> UserID = Stranger, 77, Code = 20551, iAmount = 3"])
        w("LoginManager/Log/LoginMngError/OTP_Report_20260105.txt",
          [pre % (8, 0, 0) + "Login User ID u1/u1, Pass " + "a" * 32 + "/" + "b" * 32 + "00-15-5d-a3-01-00, IP 10.0.0.9",
           pre % (8, 0, 1) + "u1 UPUserLogin result : iUserLoginStatus 3"] * 6)
        d = dt.date(2026, 1, 5)
        ctx = C.Ctx(tmp, d, d, os.path.join(tmp, "out"), C.DEFAULT_OWNER_RE, ["GameServer"], ["NpcServer"], "", False)
        ms = build(C, L, ctx)
        by = {m.mid: m for m in ms}
        ok = []
        ok.append(("M5 всего 7", len(by["M5"].events) == 7))
        ok.append(("M5 флаг серии на Cheater", any(s == "Cheater" and "серия" in t for s, t in by["M5"].flags)))
        ok.append(("M5 владелец не флагуется серией", not any(s == "GM_sitxovski" for s, _ in by["M5"].flags)))
        ok.append(("M7 секрет Cheater", any(e.subject == "Cheater" for e in by["M7"].events)))
        ok.append(("M7d кик Cheater c IP", any(e.subject == "Cheater" and e.ip == "10.0.0.5" for e in by["M7d"].events)))
        ok.append(("M9 сессия 9 ч -> флаг", any(s == "Botty" for s, _ in by["M9"].flags)))
        ok.append(("M1 опыт/ч Botty", any(e.subject == "Botty" for e in by["M1"].events)))
        ok.append(("M11 ItemGive Stranger флаг", any(s == "Stranger" for s, _ in by["M11"].flags)))
        ok.append(("M12 6 неудач -> флаг IP", any("с IP" in t for _, t in by["M12"].flags)))
        ok.append(("M8 MAC разобран", any("00-15-5d-a3-01-00" in e.detail for e in by["M8"].events)))
        ok.append(("M3/M4 без БД -> нет данных", by["M3"].status == "нет данных" and by["M4"].status == "нет данных"))
        text = render(C, ctx, ms, {"elapsed": 0.0})
        ok.append(("в отчёте нет хешей", ("a" * 32) not in text and ("b" * 32) not in text))
        files = write_csv(C, ctx, ms)
        ok.append(("CSV записаны", len(files) >= 5))
        # пары сделок
        import ac_metrics_db as D
        pairs = D.analyse_pairs([(1, 2, "gold", 6, 5000000), (2, 1, "item", 6, 6)])
        fl = D.pair_flags(pairs)
        ok.append(("M3 пара: >=5 и асимметрия", len(fl) == 2))
        # ★ 22.11.2026 (ревизия 54 админ-центра): направление и сумма M3 по реверсу процедур Joy1 — живые ложные флаги прежней M3
        #   лавка 75210 (продавец) / 75204 (покупатель): строка продавца PersonalStoreGoldFrom 66 753 743 -> 66 754 928 — платит 75204 1185
        lav = D.pair_rows("PersonalStoreGoldFrom", True, True, [(75210, 75204, 0, 6, 66753743, 66754928)])
        ok.append(("M3 лавка: золото покупатель -> продавец, сумма = Ramount - Amount (1185), флага «в одну сторону» нет",
                   lav == [(75204, 75210, "gold", 6, 1185)] and not [t for _, t in D.pair_flags(D.analyse_pairs(lav)) if "асимметрия" in t]))
        #   лавка 1 (продавец) / 75214 (покупатель): баланс продавца 974 151 034 -> 974 155 534 — платит 75214 4500
        own = D.pair_rows("PersonalStoreGoldFrom", True, True, [(1, 75214, 0, 1, 974151034, 974155534)])
        ok.append(("M3 лавка 1 / 75214: 75214 -> 1 золото 4500, ложного флага 974 155 534 нет",
                   own == [(75214, 1, "gold", 1, 4500)] and not D.pair_flags(D.analyse_pairs(own))))
        #   обмен: строка From отдавшего — переданное Amount - Ramount (а не баланс «было»); стопка золота целиком — TradeItemFrom Code 20551
        tr = D.pair_rows("TradeGoldFrom", True, True, [(75214, 75237, 0, 1, 35201072, 25201072)])
        st = D.pair_rows("TradeItemFrom", True, True, [(5, 6, 1, 1, 2000000, 0), (5, 6, 0, 1, 3, 0)])
        ok.append(("M3 обмен: переданное 10 000 000 (не баланс 35 201 072), стопка золота TradeItemFrom Code 20551 — золото 2 000 000",
                   tr == [(75214, 75237, "gold", 1, 10000000)] and st == [(5, 6, "gold", 1, 2000000), (5, 6, "item", 1, 3)]
                   and any("асимметрия" in t for _, t in D.pair_flags(D.analyse_pairs(st)))))
        ok.append(("M3 вещи без количества — штука на строку, Functional — Amount / Ramount",
                   D.pair_rows("TradeSowel", False, False, [(1, 2, 0, 4, 0, 0)]) == [(1, 2, "item", 4, 4)]
                   and D.pair_rows("TradeFunctional", True, False, [(1, 2, 0, 1, 7, 0)]) == [(1, 2, "item", 1, 7)]
                   and D.pair_rows("PersonalStoreFunctional", False, True, [(1, 2, 0, 1, 0, 9)]) == [(1, 2, "item", 1, 9)]))
        # ★ ревизия 56 Н-1: общий источник не открылся (на месте файла - папка: open падает, как у занятого писателем) - отчёт живёт
        tmp2 = os.path.join(tmp, "busy")
        for rel in ("GameServer/Log/Log_LevelUp/LevelUp_20260105.txt", "LoginManager/Log/LoginMngError/OTP_Report_20260105.txt"):
            os.makedirs(os.path.join(tmp2, rel))
        w2 = os.path.join(tmp2, "GameServer", "Log", "Log_Game", "GameLog_20260105.txt")
        os.makedirs(os.path.dirname(w2))
        with open(w2, "wb") as f:
            f.write((pre % (10, 0, 0) + "CharMove Hack Position Cheater Error\r\n").encode("cp1251"))
        ctx2 = C.Ctx(tmp2, d, d, os.path.join(tmp2, "out"), C.DEFAULT_OWNER_RE, ["GameServer"], ["NpcServer"], "", False)
        by2 = {m.mid: m for m in build(C, L, ctx2)}
        ok.append(("Log_LevelUp / OTP_Report не открылись - «ошибка» у M1 M9 M8 M12 M12o, отчёт не падает, M5 и M7 считаются",
                   all(by2[k].status == "ошибка" for k in ("M1", "M9", "M8", "M12", "M12o")) and len(by2["M5"].events) == 1
                   and by2["M7"].status == "ok"))
        # ★ ревизия 57 Н-1: LoginProc занят писателем без общего доступа (Windows: CreateFileW share 0) - «ошибка» у M8, остальное считается
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            tmp3 = os.path.join(tmp, "busy_lp")
            lp = os.path.join(tmp3, "LoginManager", "Log", "LoginMngError", "LoginProc_20260105.txt")
            os.makedirs(os.path.dirname(lp))
            with open(lp, "wb") as f:
                f.write((pre % (8, 0, 0) + "ProcConnect = 1, 10.0.0.7\r\n").encode("cp1251"))
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateFileW.restype = wintypes.HANDLE
            k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                        wintypes.HANDLE]
            hnd = k32.CreateFileW(lp, 0x40000000, 0, None, 3, 0x80, None)
            try:
                ctx3 = C.Ctx(tmp3, d, d, os.path.join(tmp3, "out"), C.DEFAULT_OWNER_RE, ["GameServer"], ["NpcServer"], "", False)
                by3 = {m.mid: m for m in build(C, L, ctx3)}
            finally:
                k32.CloseHandle(hnd)
            ok.append(("LoginProc занят писателем - «ошибка» у M8, отчёт не падает (M12 / M12o читают его сами в safe() - у них своя «ошибка»), M5 считается",
                       by3["M8"].status == "ошибка" and any(n.startswith("LoginProc не прочитан") for n in by3["M8"].notes)
                       and by3["M5"].status == "ok"))
        # защита «только чтение»
        bad = 0
        for q in ("UPDATE t SET a=1", "DELETE FROM t", "EXEC sp_x", "SELECT 1; DROP TABLE t"):
            try:
                db_connect.assert_select_only(q)
            except ValueError:
                bad += 1
        ok.append(("защита SELECT-only", bad == 4 and db_connect.assert_select_only("SELECT 'update' AS a")))
        fail = [n for n, v in ok if not v]
        for n, v in ok:
            print(("OK   " if v else "FAIL ") + n)
        return 1 if fail else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.selftest:
        return selftest()
    ctx, metrics, p, files, C = run(args)
    print("Отчёт: %s" % p)
    print("CSV: %d файлов в %s" % (len(files), ctx.out))
    for m in metrics:
        row = summary_row(C, ctx, m)
        print("%-5s всего=%s субъектов=%s вне_владельца=%s флагов=%s статус=%s" % (row[0], row[1], row[2], row[5], row[6], row[7]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
