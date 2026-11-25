# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""ac_metrics_db.py - SELECT-отчёты по БД dev (M3 сделки, M4 дубли серийников, M8 LogInfo, сводка joylog1.ac).

ТОЛЬКО SELECT (db_connect.query отказывает на любом другом слове). Названия таблиц/столбцов не зашиты
намертво: набор таблиц Trade*/PersonalStore* и наличие столбцов определяются по sys.tables / sys.columns;
если таблицы или столбца нет - метрика пишет «нет данных», а не падает. Побочных эффектов при импорте нет.
"""
import collections
import datetime as dt

import db_connect
from ac_common import THR, Metric, fmt_ts

AC_TABLES = ["operator_refusal", "identity_mismatch", "login_check_refusal", "kick_block",
             "sign_replay", "move_combat", "other"]


def open_db(name):
    return db_connect.connect(name)


def q(cn, sql, params=()):
    return db_connect.query(cn, sql, params)[1]


def logins_for(cn, uis):
    """{userindex: логин} из AsdaStoryOp.dbo.Us_member (если доступно)."""
    out = {}
    uis = sorted(set(int(u) for u in uis if u is not None))
    try:
        for i in range(0, len(uis), 200):
            chunk = uis[i:i + 200]
            rows = q(cn, "SELECT Userindex, Us_id FROM AsdaStoryOp.dbo.Us_member WHERE Userindex IN (%s)"
                     % ",".join(str(u) for u in chunk))
            for u, l in rows:
                out[int(u)] = l
    except Exception:
        pass
    return out


def name_of(logins, ui):
    return "%s(ui:%s)" % (logins[ui], ui) if ui in logins else "ui:%s" % ui


# ----------------------------------------------------------------------------------------------
# M3: пары сделок
# ----------------------------------------------------------------------------------------------
def trade_tables(cn):
    """Таблицы JoyLog1 Trade*/PersonalStore* с нужными столбцами: [(имя, есть_Amount, есть_Serial, есть_Ramount, есть_Code)].
    Зеркальные «...To» пропускаются: каждая сделка пишется в «From» и «To» - иначе всё считалось бы дважды."""
    rows = q(cn, """SELECT t.name,
                           MAX(CASE WHEN c.name='Amount' THEN 1 ELSE 0 END),
                           MAX(CASE WHEN c.name='Serial' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN c.name IN ('Edate','Userindex','Tuserindex','Fromname','Toname') THEN 1 ELSE 0 END),
                           MAX(CASE WHEN c.name='Ramount' THEN 1 ELSE 0 END),
                           MAX(CASE WHEN c.name='Code' THEN 1 ELSE 0 END)
                    FROM sys.tables t JOIN sys.columns c ON c.object_id=t.object_id
                    WHERE t.name LIKE 'Trade%' OR t.name LIKE 'PersonalStore%'
                    GROUP BY t.name ORDER BY t.name""")
    return [(n, bool(a), bool(s), bool(r), bool(c)) for n, a, s, k, r, c in rows if k == 5]


def is_mirror(name):
    return name.endswith("To")      # TradeGoldTo, TradeitemTo, PersonalStoreGoldTo, TradeShellGoldTo ...


def analyse_pairs(rows):
    """rows: (a, b, kind('gold'|'item'), n, amt) где a -> b. Возвращает {(min,max): статистика}."""
    pairs = {}
    for a, b, kind, n, amt in rows:
        k = (min(a, b), max(a, b))
        p = pairs.setdefault(k, {"deals": 0, "gold_ab": 0, "gold_ba": 0, "items_ab": 0, "items_ba": 0})
        d = "ab" if a < b else "ba"
        p["deals"] += n
        p["gold_" + d if kind == "gold" else "items_" + d] += amt or 0
    return pairs


def pair_flags(pairs):
    """Список (пара, текст): много сделок или золото в одну сторону при предметах в обратную."""
    out = []
    for k, p in sorted(pairs.items()):
        if p["deals"] >= THR["m3_pair_deals"]:
            out.append((k, "пара %s<->%s: %d записей сделок за окно" % (k[0], k[1], p["deals"])))
        for g_f, g_r, i_f, i_r, fw in (("gold_ab", "gold_ba", "items_ab", "items_ba", "%s->%s" % k),
                                       ("gold_ba", "gold_ab", "items_ba", "items_ab", "%s->%s" % (k[1], k[0]))):
            if p[g_f] >= THR["m3_gold_oneway"] and p[g_r] == 0:
                out.append((k, "пара %s: золото %d в одну сторону, обратно золота нет (предметов обратно: %d) - асимметрия"
                            % (fw, p[g_f], p[i_r])))
    return out


# ★ 22.11.2026 (ревизия 54 админ-центра, реверс процедур Joy1 UPItemChange / UPShellItemChange / UPSelfStoreBuy): во всех Trade*
#   Userindex = отдал, Tuserindex = получил; в PersonalStore* Userindex = продавец, Tuserindex = покупатель (вещь продавец -> покупатель,
#   золото покупатель -> продавец). Amount / Ramount - баланс владельца строки «было / стало», поэтому переданное = дельта у него: в строке
#   From отдавшего - Amount - Ramount, в PersonalStoreGoldFrom (строка продавца) - Ramount - Amount. Стопка золота целиком уходит строкой
#   TradeItemFrom с Code 20551 - это золото. Было: сумма Amount (баланс «было») и направление лавки продавец -> покупатель.
GOLD_CODE = 20551                          # код золота (Item.Code)
RECEIVER_ROW = ("PersonalStoreGoldFrom",)  # строка получателя (продавца): платит Tuserindex, получает Userindex


def pair_rows(name, has_amt, has_ram, raw):
    """Сырые суммы окна по таблице -> строки M3 (a, b, kind, n, amt), a -> b. raw: [(Userindex, Tuserindex, is_gold, n, SUM(Amount),
    SUM(Ramount))]. Чистая функция (самотест без БД)."""
    out = []
    for u, t, is_gold, n, sa, sr in raw:
        sa, sr = int(sa or 0), int(sr or 0)
        if name in RECEIVER_ROW:
            a, b, amt = t, u, sr - sa
        elif has_amt and has_ram:
            a, b, amt = u, t, sa - sr
        elif has_amt:
            a, b, amt = u, t, sa             # TradeFunctional: Amount = количество
        elif has_ram:
            a, b, amt = u, t, sr             # PersonalStoreFunctional: Ramount = количество
        else:
            a, b, amt = u, t, int(n)         # вещь без количества (Gear / Sowel / NoStack) - штука на строку
        kind = "gold" if ("Gold" in name or is_gold) else "item"
        out.append((a, b, kind, int(n), amt))
    return out


def window_pairs(cn, tabs, t0, t1):
    rows = []
    for name, has_amt, _, has_ram, has_code in tabs:
        if is_mirror(name):
            continue
        gold = "CASE WHEN Code = %d THEN 1 ELSE 0 END" % GOLD_CODE if has_code else "0"   # без Code — константа (в GROUP BY не идёт)
        sa = "SUM(CAST(Amount AS BIGINT))" if has_amt else "CAST(0 AS BIGINT)"
        sr = "SUM(CAST(Ramount AS BIGINT))" if has_ram else "CAST(0 AS BIGINT)"
        raw = q(cn, "SELECT Userindex, Tuserindex, %s, COUNT_BIG(*), %s, %s FROM dbo.[%s] WHERE Edate >= ? AND Edate < ? "
                    "GROUP BY Userindex, Tuserindex%s" % (gold, sa, sr, name, (", " + gold) if has_code else ""), (t0, t1))
        rows.extend(pair_rows(name, has_amt, has_ram, raw))
    return rows


def metric_m3(ctx):
    m = Metric("M3", "Сделки между одной парой (JoyLog1 `Trade*`, `PersonalStore*`)")
    m.source = "JoyLog1.dbo.Trade*/PersonalStore* (без зеркальных ...To)"
    m.formula = ("GROUP BY Userindex,Tuserindex за окно отчёта и за 7 дней; флаг: >= %d записей пары или золото >= %d в одну сторону"
                 % (THR["m3_pair_deals"], THR["m3_gold_oneway"]))
    cn = open_db("JoyLog1")
    tabs = trade_tables(cn)
    if not tabs:
        m.status = "нет данных"
        m.notes.append("таблиц Trade*/PersonalStore* с нужными столбцами (Edate, Userindex, Tuserindex, Fromname, Toname) нет")
        return m
    nonmirror = [t for t in tabs if not is_mirror(t[0])]
    total_rows = 0
    for name, *_rest in tabs:
        total_rows += int(q(cn, "SELECT COUNT_BIG(*) FROM dbo.[%s]" % name)[0][0])
    m.notes.append("Таблиц найдено: %d (учитывается %d без зеркальных ...To); строк во всех: %d." % (len(tabs), len(nonmirror), total_rows))
    m.notes.append("Направление и сумма - по реверсу процедур Joy1 (22.11.2026): Trade* - Userindex отдал, Tuserindex получил; лавка - "
                   "вещь продавец (Userindex) -> покупатель (Tuserindex), золото PersonalStoreGoldFrom - покупатель -> продавец; сумма - "
                   "переданное (дельта баланса владельца строки), а не баланс «было»; золото - таблицы с `Gold` в имени и строки Code 20551 "
                   "(стопка золота целиком в TradeItemFrom), остальное - предметы.")
    if total_rows == 0:
        m.status = "нет данных"
        m.notes.append("все таблицы сделок пусты (журнал обмена/лавки на dev ещё не заполнялся).")
        return m
    for label, t0 in (("окно отчёта", ctx.t0), ("7 дней до конца окна", min(ctx.t0, ctx.t1 - dt.timedelta(days=7)))):
        rows = window_pairs(cn, tabs, t0, ctx.t1)
        pairs = analyse_pairs(rows)
        lg = logins_for(cn, [x for k in pairs for x in k])
        tbl = []
        for k, p in sorted(pairs.items(), key=lambda kv: -kv[1]["deals"]):
            tbl.append([name_of(lg, k[0]) + " <-> " + name_of(lg, k[1]), p["deals"], p["items_ab"], p["items_ba"], p["gold_ab"], p["gold_ba"]])
            if label == "окно отчёта":
                m.add(ctx.t1, "JoyLog1", name_of(lg, k[0]) + "<->" + name_of(lg, k[1]), "пара",
                      "записей=%d, предметов %d/%d, золота %d/%d" % (p["deals"], p["items_ab"], p["items_ba"], p["gold_ab"], p["gold_ba"]))
        m.tables.append(("Пары, %s (предметов a->b / b->a, золота a->b / b->a)" % label,
                         ["Пара", "Записей", "Пред. a->b", "Пред. b->a", "Золото a->b", "Золото b->a"], tbl[:20]))
        for k, text in pair_flags(pairs):
            m.flag(name_of(lg, k[0]), "[%s] %s" % (label, text))
    return m


# ----------------------------------------------------------------------------------------------
# M4: дубли серийных номеров
# ----------------------------------------------------------------------------------------------
def metric_m4(ctx):
    m = Metric("M4", "Дубли предметов (`Joy1.Item.Uuid`, `Del_item`, цепочки `Serial` в JoyLog1)")
    m.source = "Joy1.dbo.Item (Uuid), Joy1.dbo.Del_item, JoyLog1 Trade*/PersonalStore* (Serial)"
    m.formula = "Uuid встречается > 1 раза в Item; Uuid одновременно в Item и Del_item; Serial передан >= %d раз за окно" % THR["m4_chain"]
    cn = open_db("Joy1")
    dups = q(cn, """SELECT CONVERT(varchar(36), Uuid), COUNT(*), MIN(Userindex), MAX(Userindex), MIN(Code), MIN(GainDate), MAX(GainDate)
                    FROM dbo.Item GROUP BY Uuid HAVING COUNT(*) > 1""")
    for u, n, u0, u1, code, g0, g1 in dups:
        legacy = (g0 is not None and g0.year < 2026)
        m.add(ctx.t1, "Joy1.Item", "ui:%s" % u0, "дубль Uuid",
              "Uuid=%s x%d, Code=%s, userindex %s..%s, GainDate %s..%s%s" % (u, n, code, u0, u1, fmt_ts(g0), fmt_ts(g1),
                                                                         " (унаследовано из исходной базы)" if legacy else ""))
        m.flag("ui:%s" % u0, "Uuid %s встречается %d раз (Code=%s)%s" % (u, n, code, ", GainDate до 2026 - унаследовано" if legacy else ""))
    total = q(cn, "SELECT COUNT_BIG(*) FROM dbo.Item")[0][0]
    m.notes.append("Предметов в Joy1.Item: %d; Uuid с повторами: %d." % (total, len(dups)))
    try:
        both = q(cn, "SELECT CONVERT(varchar(36), i.Uuid), i.Userindex, d.Edate FROM dbo.Item i JOIN dbo.Del_item d ON d.Uuid=i.Uuid")
        for u, ui, ed in both:
            m.add(ctx.t1, "Joy1.Item+Del_item", "ui:%s" % ui, "Uuid и в Item, и в Del_item", "Uuid=%s, удалён %s" % (u, fmt_ts(ed)))
            m.flag("ui:%s" % ui, "Uuid %s есть и в Item, и в Del_item" % u)
        m.notes.append("Пересечение Item и Del_item: %d." % len(both))
    except Exception as e:
        m.notes.append("Del_item недоступна: %s" % str(e)[:100])
    # цепочки Serial в JoyLog1
    cj = open_db("JoyLog1")
    chains, nser = [], 0
    for name, _, has_serial, *_rest in trade_tables(cj):
        if not has_serial or is_mirror(name):
            continue
        for s, n in q(cj, "SELECT Serial, COUNT_BIG(*) FROM dbo.[%s] WHERE Edate >= ? AND Edate < ? AND Serial IS NOT NULL "
                          "GROUP BY Serial HAVING COUNT_BIG(*) >= ?" % name, (ctx.t0, ctx.t1, THR["m4_chain"])):
            chains.append((name, s, int(n)))
        nser += 1
    for name, s, n in chains:
        m.add(ctx.t1, "JoyLog1." + name, "serial", "цепочка Serial", "Serial=%s передан %d раз" % (s, n))
        m.flag("serial:" + s, "Serial %s передан %d раз за окно (%s)" % (s, n, name))
    m.notes.append("Таблиц сделок со столбцом Serial проверено: %d; серийников с цепочкой >= %d: %d." % (nser, THR["m4_chain"], len(chains)))
    m.notes.append("Тип «Nostack» серийника не имеет - в проверку не входит.")
    return m


# ----------------------------------------------------------------------------------------------
# M8 (БД): JoyLog1.LogInfo
# ----------------------------------------------------------------------------------------------
def loginfo_rows(ctx):
    """[(login/ui, ip, mac, n, first, last)] из JoyLog1.dbo.LogInfo за окно (имя таблицы ищется без учёта регистра)."""
    cn = open_db("JoyLog1")
    tn = q(cn, "SELECT name FROM sys.tables WHERE name = 'LogInfo' OR name = 'Loginfo'")
    if not tn:
        return [], 0
    t = tn[0][0]
    rows = q(cn, "SELECT Userindex, IpAddress, Mac, COUNT_BIG(*), MIN(Login), MAX(Login) FROM dbo.[%s] "
                 "WHERE Login >= ? AND Login < ? GROUP BY Userindex, IpAddress, Mac" % t, (ctx.t0, ctx.t1))
    lg = logins_for(cn, [r[0] for r in rows])
    out = [(lg.get(r[0], "ui:%s" % r[0]), (r[1] or "").strip(), (r[2] or "").strip().lower(), int(r[3]), r[4], r[5]) for r in rows]
    return out, sum(r[3] for r in out)


# ----------------------------------------------------------------------------------------------
# Сводка журнала античита joylog1.ac (P53)
# ----------------------------------------------------------------------------------------------
def metric_acj(ctx):
    m = Metric("ACJ", "Журнал античита в БД (`joylog1.ac`, P53)")
    m.source = "joylog1.ac.* и представления v_events / v_top_offenders / v_account_daily"
    m.formula = "справочно: события серверных проверок (кик, автоблок, повтор подписи, откат позиции, отказы GM), без служебных строк «журнал:»"
    cn = open_db("JoyLog1")
    rows = []
    for t in AC_TABLES:
        n, a, b = q(cn, "SELECT COUNT_BIG(*), MIN(ev_local), MAX(ev_local) FROM ac.[%s]" % t)[0]
        rows.append([t, int(n), fmt_ts(a), fmt_ts(b)])
    m.tables.append(("Таблицы ac.* (всего строк за всё время)", ["Таблица", "Строк", "Первое", "Последнее"], rows))
    svc = q(cn, "SELECT COUNT_BIG(*), MAX(ev_local) FROM ac.other WHERE event_kind LIKE ?", ("журнал:%",))[0]
    m.notes.append("Служебных строк журнала («журнал: старт/проблемы»): %d, последняя %s - журнал %s."
                   % (svc[0], fmt_ts(svc[1]), "жив" if svc[0] else "ещё не писался (процессы с P53 не выложены)"))
    ev = q(cn, """SELECT TOP 20000 ev_local, violation_type, server_name, user_index, login, char_name, ip, opcode, summary
                  FROM ac.v_events WHERE ev_local >= ? AND ev_local < ? AND NOT (table_name = N'other' AND summary LIKE ?)
                  ORDER BY ev_local""", (ctx.t0, ctx.t1, "журнал:%"))
    for ts, vt, srv, ui, lg, ch, ip, op, summ in ev:
        subj = lg or ch or (("ui:%s" % ui) if ui is not None else "")
        m.add(ts, srv or "", subj, vt, "opcode=%s %s" % (op, summ or ""), "", ip or "")
    if not ev:
        m.status = "нет данных"
        m.notes.append("событий нарушений в окне нет (таблицы пусты или процессы с P53 ещё не выложены).")
    else:
        by = collections.Counter(e.kind for e in m.events)
        m.tables.append(("События в окне по видам", ["Вид", "Событий"], [[k, v] for k, v in by.most_common()]))
        top = q(cn, "SELECT TOP 10 user_index, login, total, kicks, autoblocks, sign_replay, move_combat FROM ac.v_top_offenders ORDER BY total DESC")
        m.tables.append(("Топ нарушителей за всё время (v_top_offenders)", ["ui", "Логин", "Всего", "Кики", "Автоблоки", "Повтор подписи", "Откат позиции"],
                         [list(r) for r in top]))
    return m


def resolve_userindexes(ctx, metrics, extra=None):
    """Заменяет «ui:N» в субъектах событий и флагов на «логин(ui:N)» по Us_member (чтобы отличить владельца).
    Нет БД/нет строки - остаётся «ui:N»."""
    import re
    rx = re.compile(r"(?<!\()ui:(\d+)")
    uis = set()
    for m in metrics:
        for e in m.events:
            uis.update(int(x) for x in rx.findall(e.subject))
        for s, _ in m.flags:
            uis.update(int(x) for x in rx.findall(s))
    if not uis:
        return 0
    lg = logins_for(open_db("Joy1"), uis)
    for ui in uis:           # нет в Us_member - ники из Log_Operator (если их не больше 3)
        if ui not in lg and extra and 0 < len(extra.get(ui, [])) <= 3:
            lg[ui] = ",".join(extra[ui])
    if not lg:
        return 0

    def sub(s):
        return rx.sub(lambda mo: "%s(ui:%s)" % (lg[int(mo.group(1))], mo.group(1)) if int(mo.group(1)) in lg else mo.group(0), s)
    for m in metrics:
        m.events = [e._replace(subject=sub(e.subject)) for e in m.events]
        m.flags = [(sub(s), t) for s, t in m.flags]
    return len(lg)
