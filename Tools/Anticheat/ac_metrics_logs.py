# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""ac_metrics_logs.py - метрики по файловым журналам (M1 M5 M6 M6b M7 M7d M8 M9 M11 M12 M12o).

Только чтение файлов шары. Хеши паролей из OTP_Report отбрасываются сразу после разбора строки.
Побочных эффектов при импорте нет.
"""
import collections
import datetime as dt
import os
import re
import statistics

from ac_common import (THR, Metric, burst_flags, fmt_ts, gs_lines, in_window, index_dir, kind_table,
                       nonowner_flag, read_lines, ts_lines)

MAC_TAIL = re.compile(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})$")


# ----------------------------------------------------------------------------------------------
# M5: перемещение (CharMove / CharReMove Hack Position)
# ----------------------------------------------------------------------------------------------
RX_HACKPOS = re.compile(r"^(CharMove|CharReMove) Hack Position (.*?) Error\s*$")


def metric_m5(ctx):
    m = Metric("M5", "Телепорт/ускорение перемещения (`CharMove|CharReMove Hack Position`)")
    m.source = "GameServer/Log/Log_Game"
    m.formula = "число строк на ник; флаг: >= %d за %d мин" % (THR["m5_burst_n"], THR["m5_burst_min"])
    per = collections.defaultdict(list)
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Game"):
        r = RX_HACKPOS.match(text)
        if not r:
            continue
        m.add(ts, srv, r.group(2), r.group(1), "", os.path.basename(p))
        per[r.group(2)].append(ts)
    burst_flags(m, per, THR["m5_burst_n"], THR["m5_burst_min"], "серия отката позиции")
    nonowner_flag(m, ctx, "позиция")
    kind_table(m)
    m.notes.append("Сервер сам откатывает позицию (4007 тип 5), санкции нет; координат в строке нет.")
    return m


# ----------------------------------------------------------------------------------------------
# M6: скорость (NpcServer SpeedHack_*) и M6b (GameServer Log_SpeedHack)
# ----------------------------------------------------------------------------------------------
def metric_m6(ctx):
    m = Metric("M6", "Скорость атаки (NpcServer `SpeedHack Check....!`)")
    m.source = "все NpcServer стойки (%s)/Error_Log/SpeedHack_YYYYMMDD.txt (только нужные дни, потоково)" % ", ".join(ctx.npc_servers)
    m.formula = ("Duration/PDuration < %.1f многократно (>= %d на ник); Count > %d = порог отключения 8905"
                 % (THR["m6_ratio"], THR["m6_ratio_n"], THR["m6_count"]))
    low = collections.Counter()
    maxcnt = collections.defaultdict(int)
    for srv in ctx.npc_servers:
        base = os.path.join(ctx.root, srv, "Error_Log")
        for d in ctx.dates:
            p = os.path.join(base, "SpeedHack_%s.txt" % d.strftime("%Y%m%d"))
            if not os.path.isfile(p):
                continue
            for s in read_lines(p):
                if "SpeedHack Check" not in s:
                    continue
                t = re.match(r"^\d+\t(\d\d):(\d\d):(\d\d):\d+->", s)
                tm = dt.time(int(t.group(1)), int(t.group(2)), int(t.group(3))) if t else dt.time()
                ts = dt.datetime.combine(d, tm)
                g = re.search(r"Nick\s*\t([^\t]*)", s)
                nick = g.group(1).strip() if g else ""
                g = re.search(r"\tCount (\d+)", s)
                cnt = int(g.group(1)) if g else 0
                g = re.search(r"PDuration (\d+)", s)
                pd = int(g.group(1)) if g else 0
                g = re.search(r"(?<![A-Za-z])Duration (\d+)", s)
                du = int(g.group(1)) if g else 0
                ratio = (du / pd) if pd else 0.0
                m.add(ts, srv, nick, "Count=%d" % cnt, "PDuration=%d Duration=%d ratio=%.2f" % (pd, du, ratio),
                      os.path.basename(p))
                if pd and ratio < THR["m6_ratio"]:
                    low[nick] += 1
                maxcnt[nick] = max(maxcnt[nick], cnt)
    for nick, c in low.items():
        if c >= THR["m6_ratio_n"]:
            m.flag(nick, "атака быстрее допуска (ratio<%.1f): %d раз" % (THR["m6_ratio"], c))
    for nick, c in maxcnt.items():
        if c > THR["m6_count"]:
            m.flag(nick, "Count %d > %d (порог отключения 8905)" % (c, THR["m6_count"]))
    nonowner_flag(m, ctx, "скорость атаки")
    m.notes.append("Строки отключения по 8905 (sendSpeedHackDisConnect) в просмотренных каналах GameServer не найдены.")
    return m


RX_SPEEDGS = re.compile(r"^\t?(Warning|HackCheck)\t(\d+)/(\d+)\t([^\t]*)")


def metric_m6b(ctx):
    m = Metric("M6b", "Спидхак по пингу (GameServer `Log_SpeedHack`: Warning / HackCheck)")
    m.source = "GameServer/Log/Log_SpeedHack"
    m.formula = "два пинга ближе 6 с = Warning; 4 подряд = HackCheck. По 04 §2.1 детектор шумный, реакции нет"
    hc = collections.Counter()
    for srv, d, p, ts, text in gs_lines(ctx, "Log_SpeedHack"):
        r = RX_SPEEDGS.match(text)
        if not r:
            continue
        a, b = int(r.group(2)), int(r.group(3))
        nick = r.group(4).strip()
        m.add(ts, srv, nick or "(без ника)", r.group(1), "tick %d->%d dt=%d мс" % (a, b, b - a), os.path.basename(p))
        if r.group(1) == "HackCheck":
            hc[nick or "(без ника)"] += 1
    for nick, c in hc.items():
        if not nick.startswith("(") and not ctx.is_owner(nick):
            m.flag(nick, "HackCheck: %d раз вне списка владельца" % c)
    kind_table(m)
    wnick = sum(1 for e in m.events if e.kind == "Warning" and not e.subject.startswith("("))
    m.notes.append("Warning с ником: %d (остальные Warning - без ника: ник проставляется только со 2-й строки серии)." % wnick)
    m.notes.append("HackCheck пишется, но в срезе кода никем не читается; шум от легитимного клиента владельца.")
    return m


# ----------------------------------------------------------------------------------------------
# M7: подделка пакетов; M7d: исключительные отключения
# ----------------------------------------------------------------------------------------------
RX_SECRET = re.compile(r"^\t?(\d+)\t([^\t]+)\t(Secret[^\t]*)\t(.*)$")
RX_MD5 = re.compile(r"memcmp\(szMD5.*Command = (\d+)")
RX_NOTKNOW = re.compile(r"(?i)notknow|hack\s*packet|unknown\s*(packet|command)")
RX_ITEMERR = re.compile(r"Error|Failed")
RX_UI = re.compile(r"(?:UserIndex|User)\s*=\s*(\d+)|Failed,\s*(\d+)")
RX_EXC = re.compile(r"___ExceptionDisConnetUser(?: \d+)?___ CallFunc = (.*?), UserNum = (-?\d+), CharN = (.*?), IP = (\S+)")


def metric_m7(ctx):
    m = Metric("M7", "Подделка пакетов (`Log_Secret`, MD5 в `Log_Exception_Asm`, ошибки `Log_Item`, кик LoginManager)")
    m.source = "Log_Secret, Log_Exception_Asm, Log_Item, LoginManager/LoginoutCheck"
    m.formula = "любое ненулевое значение вне списка владельца - сильный сигнал (порт должен быть «чистым»)"
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Secret"):
        r = RX_SECRET.match(text)
        if r:
            m.add(ts, srv, r.group(2), r.group(3), r.group(4), os.path.basename(p))
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Exception_Asm"):
        r = RX_MD5.search(text)
        if r:
            m.add(ts, srv, "(нет ника)", "MD5-несовпадение", "Command=%s" % r.group(1), os.path.basename(p))
        elif RX_NOTKNOW.search(text):
            m.add(ts, srv, "(нет ника)", "неизвестный/хак-пакет", text[:160], os.path.basename(p))
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Item"):
        if RX_ITEMERR.search(text) and "Refine" not in text and "ServerNotice" not in text:
            u = RX_UI.search(text)
            ui = (u.group(1) or u.group(2)) if u else ""
            m.add(ts, srv, ("ui:" + ui) if ui else "(нет ника)", "ошибка предмета", text[:160], os.path.basename(p))
    ping = 0
    for d in ctx.dates:
        p = os.path.join(ctx.root, "LoginManager", "Log", "LoginMngError", "LoginoutCheck_%s.txt" % d.strftime("%Y%m%d"))
        if not os.path.isfile(p):
            continue
        for ts, text in ts_lines(p, d):
            r = re.search(r"UserNum (-?\d+)\s+Disconnect_PingCount\(\) : pCallFunc = (\w+), Count (\d+)", text)
            if not r:
                continue
            if r.group(2) == "Ping":
                ping += 1
            else:
                m.add(ts, "LoginManager", "(LoginManager UserNum %s)" % r.group(1), "кик " + r.group(2),
                      "Count=%s" % r.group(3), os.path.basename(p))
    nonowner_flag(m, ctx, "подделка")
    agg, ex = collections.Counter(), {}
    for e in m.events:       # события без ника: по одному флагу на (субъект, вид); ui:N позже заменяется логином из БД
        if e.subject.startswith(("(", "ui:")):
            agg[(e.subject, e.kind)] += 1
            ex.setdefault((e.subject, e.kind), e.detail[:70])
    for (subj, kind), c in sorted(agg.items()):
        m.flag(subj, "%s x%d (в источнике нет ника; пример: %s)" % (kind, c, ex[(subj, kind)]))
    kind_table(m)
    m.notes.append("Ошибки Log_Item считаются по userindex (ui:N), ника в строке нет; штатные Refine/ServerNotice не считаются.")
    m.notes.append("LoginManager: плановых отключений по счётчику Ping за период - %d (в метрику не входят)." % ping)
    return m


def metric_m7d(ctx):
    m = Metric("M7d", "Исключительные отключения (`___ExceptionDisConnetUser___ CallFunc, CharN, IP`)")
    m.source = "Log_Game, Log_Exception_Asm, Log_Operator"
    m.formula = "справочно: функция-причина, ник, IP; Ping TimeOut - плановая очистка"
    seen = set()
    for sub in ("Log_Game", "Log_Exception_Asm", "Log_Operator"):
        for srv, d, p, ts, text in gs_lines(ctx, sub):
            r = RX_EXC.search(text)
            if not r:
                continue
            key = (srv, ts, text)
            if key in seen:
                continue
            seen.add(key)
            nick = r.group(3).strip()
            m.add(ts, srv, nick or ("ip:" + r.group(4)), r.group(1).strip(), "UserNum=%s" % r.group(2),
                  os.path.basename(p), r.group(4))
    kind_table(m, "По функциям-причинам")
    for e in m.events:
        if "Ping TimeOut" not in e.kind and e.subject and not e.subject.startswith("ip:") and not ctx.is_owner(e.subject):
            m.flag(e.subject, "отключение %s вне списка владельца" % e.kind)
    return m


# ----------------------------------------------------------------------------------------------
# Сессии (M1, M9) по Log_LevelUp
# ----------------------------------------------------------------------------------------------
RX_LVL = re.compile(r"^CUserManager::(\w+)\tCharName\t(.*?)\tLevel\t(\d+)\tExp\t(-?\d+)")


def load_sessions(ctx):
    """Сессии по Log_LevelUp: старт = CharLogonRes1 / CharPortalLogonRes1, конец = DisConnectUser.
    Читается ещё один день назад (для сессий через полночь). Дисконнект + портал-логон в пределах
    m9_merge_gap_s склеиваются в одну сессию. Возвращает (сессии, служебные счётчики)."""
    ds = set(ctx.dateset)
    ds.add(ctx.d0 - dt.timedelta(days=1))
    evs = []
    for srv, d, p, ts, text in gs_lines(ctx, "Log_LevelUp", ds):
        r = RX_LVL.match(text)
        if not r:
            continue
        k = r.group(1)
        kind = "start" if k in ("CharLogonRes1", "CharPortalLogonRes1") else "end" if k == "DisConnectUser" else None
        if kind:
            evs.append((ts, kind, r.group(2).strip(), int(r.group(3)), int(r.group(4)), srv))
    evs.sort(key=lambda x: (x[0], 0 if x[1] == "start" else 1))
    open_, raw, orphan_end, overwritten = {}, [], 0, 0
    for ts, kind, nick, lvl, exp, srv in evs:
        if kind == "start":
            if nick in open_:
                overwritten += 1
            open_[nick] = (ts, lvl, exp, srv)
        else:
            o = open_.pop(nick, None)
            if o is None:
                orphan_end += 1
            else:
                raw.append([nick, o[0], ts, o[1], o[2], lvl, exp, o[3]])
    unclosed = len(open_)
    raw.sort(key=lambda x: (x[1], x[0]))
    merged, last = [], {}
    gap = dt.timedelta(seconds=THR["m9_merge_gap_s"])
    for s in raw:
        pr = last.get(s[0])
        if pr is not None and s[1] - pr[2] <= gap:
            pr[2], pr[5], pr[6] = s[2], s[5], s[6]   # продолжаем прошлую сессию
            continue
        last[s[0]] = s
        merged.append(s)
    sess = [s for s in merged if in_window(ctx, s[2])]
    return sess, {"orphan_end": orphan_end, "unclosed": unclosed, "overwritten": overwritten, "raw": len(raw)}


def metric_m9(ctx, sess, info):
    m = Metric("M9", "Бот-поведение: длительность сессий (`Log_LevelUp` вход/выход)")
    m.source = "GameServer/Log/Log_LevelUp (+ Login_Check для сверки числа входов)"
    m.formula = ("сессия > %.0f ч или онлайн за сутки >= %.0f ч; сессии портала склеены (разрыв <= %d с)"
                 % (THR["m9_session_h"], THR["m9_day_h"], THR["m9_merge_gap_s"]))
    perday = collections.defaultdict(float)
    tot_h = collections.Counter()
    cnt_s = collections.Counter()
    mx = collections.defaultdict(float)
    for nick, st, en, l0, e0, l1, e1, srv in sess:
        dur = (en - st).total_seconds()
        m.add(en, srv, nick, "сессия", "%.2f ч, L%d->L%d" % (dur / 3600.0, l0, l1))
        tot_h[nick] += dur / 3600.0
        cnt_s[nick] += 1
        mx[nick] = max(mx[nick], dur / 3600.0)
        cur = st
        while cur < en:  # разбивка по суткам
            nxt = min(en, dt.datetime.combine(cur.date() + dt.timedelta(days=1), dt.time()))
            perday[(nick, cur.date())] += (nxt - cur).total_seconds() / 3600.0
            cur = nxt
        if dur / 3600.0 > THR["m9_session_h"]:
            m.flag(nick, "сессия %.1f ч (%s - %s)" % (dur / 3600.0, fmt_ts(st), fmt_ts(en)))
    for (nick, d), h in sorted(perday.items()):
        if h >= THR["m9_day_h"] and ctx.d0 <= d <= ctx.d1:
            m.flag(nick, "онлайн %.1f ч за %s" % (h, d.isoformat()))
    m.top_override = ", ".join("%s: %.1f ч" % (k, v) for k, v in tot_h.most_common(5))
    m.tables.append(("Сессии по нику (топ-15 по времени онлайн)", ["Ник", "Сессий", "Онлайн, ч", "Макс. сессия, ч"],
                     [[n, cnt_s[n], "%.2f" % h, "%.2f" % mx[n]] for n, h in tot_h.most_common(15)]))
    n_logon = 0
    for srv, d, p, ts, text in gs_lines(ctx, "Login"):
        if text.rstrip().endswith("-> GM_LOGON_REQ"):
            n_logon += 1
    m.notes.append("Сессий в окне (по времени выхода): %d; запросов входа GM_LOGON_REQ в Login_Check: %d (ника в этих строках нет)."
                   % (len(sess), n_logon))
    m.notes.append("Без выхода (нет DisConnectUser): %d; выходов без входа: %d; перезаписей входа: %d."
                   % (info["unclosed"], info["orphan_end"], info["overwritten"]))
    return m


def metric_m1(ctx, sess):
    m = Metric("M1", "Опыт в час (`Log_LevelUp` Exp на входе/выходе)")
    m.source = "GameServer/Log/Log_LevelUp"
    m.formula = ("(Exp_выхода - Exp_входа) / длительность, сессии >= %d с; флаг: > %.1f x медианы уровня (группа >= %d сессий)"
                 % (THR["m1_min_session_s"], THR["m1_z"], THR["m1_min_group"]))
    rows = []
    for nick, st, en, l0, e0, l1, e1, srv in sess:
        dur = (en - st).total_seconds()
        if dur < THR["m1_min_session_s"]:
            continue
        rate = (e1 - e0) / (dur / 3600.0)
        rows.append((rate, nick, st, en, l0, l1, e1 - e0, dur))
        m.add(en, srv, nick, "L%d->L%d" % (l0, l1), "dExp=%d за %.2f ч = %.0f/ч" % (e1 - e0, dur / 3600.0, rate))
    groups = collections.defaultdict(list)
    for r in rows:
        if r[0] > 0:
            groups[r[4]].append(r[0])
    med = {l: statistics.median(v) for l, v in groups.items() if len(v) >= THR["m1_min_group"]}
    for rate, nick, st, en, l0, l1, d, dur in rows:
        if l0 in med and med[l0] > 0 and rate > THR["m1_z"] * med[l0]:
            m.flag(nick, "опыт %.0f/ч на уровне %d (медиана %.0f, x%.1f), сессия до %s"
                   % (rate, l0, med[l0], rate / med[l0], fmt_ts(en)))
    best = collections.defaultdict(float)
    for rate, nick, *_ in rows:
        best[nick] = max(best[nick], rate)
    m.top_override = ", ".join("%s: %.0f/ч" % (k, v) for k, v in sorted(best.items(), key=lambda kv: -kv[1])[:5])
    m.tables.append(("Медиана опыта/ч по уровню входа (группы >= %d сессий)" % THR["m1_min_group"],
                     ["Уровень", "Сессий", "Медиана/ч"], [[l, len(groups[l]), "%.0f" % med[l]] for l in sorted(med)]))
    m.notes.append("Exp в журнале накопительный (не сбрасывается при повышении уровня), дельта корректна и через уровни.")
    m.notes.append("Порог по уровням работает при достаточной выборке; на малом окне видны лишь топ-5 по ставке. "
                   "GM-выдача опыта (ники GM_*) искажает ставку.")
    return m


# ----------------------------------------------------------------------------------------------
# M11: GM-команды
# ----------------------------------------------------------------------------------------------
RX_OPCMD = re.compile(r"^(\w+)\(\)\s+(.*)$")
RX_GIVE = re.compile(r"Give OK UserID = ([^,]+), (\d+) -> UserID = ([^,]+), (\d+), Code = (\d+), iAmount = (\d+)")


def metric_m11(ctx):
    m = Metric("M11", "Действия GM (`Log_Operator`: ItemGive, Kick, Kill, Move, Summon, чат)")
    m.source = "GameServer/Log/Log_Operator"
    m.formula = "ItemGive/любая команда не-владельческого ника - флаг; Hide - рутина, в итог не входит"
    cmds = collections.Counter()
    gives = []
    hide = 0
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Operator"):
        r = RX_OPCMD.match(text)
        if not r:
            continue
        cmd, rest = r.group(1), r.group(2)
        if cmd == "Send_HideCommand":
            hide += 1
            continue
        actor = ""
        a = re.search(r"UserID = ([^,]+)", rest)
        if a:
            actor = a.group(1).strip()
        fn = os.path.basename(p)
        if cmd == "Recv_OperatorCommand_ItemGive":
            g = RX_GIVE.search(rest)
            if g:
                frm, to = g.group(1).strip(), g.group(3).strip()
                m.add(ts, srv, frm, "ItemGive OK", "-> %s (ui %s) Code=%s x%s" % (to, g.group(4), g.group(5), g.group(6)), fn)
                gives.append((ts, frm, to, g.group(5), g.group(6)))
                if not ctx.is_owner(to):
                    m.flag(to, "ItemGive от %s: Code=%s x%s (%s)" % (frm, g.group(5), g.group(6), fmt_ts(ts)))
                if not ctx.is_owner(frm):
                    m.flag(frm, "ItemGive выдан не-владельческим ником")
            else:
                m.add(ts, srv, actor, "ItemGive отказ", rest[:140], fn)
            cmds["ItemGive"] += 1
        else:
            name = cmd.replace("Recv_OperatorCommand_", "R:").replace("Send_", "").replace("Command", "")
            m.add(ts, srv, actor, name, rest[:140], fn)
            cmds[name] += 1
            if actor and not ctx.is_owner(actor):
                m.flag(actor, "GM-команда %s вне списка владельца" % name)
    m.tables.append(("По командам", ["Команда", "Событий"], [[k, v] for k, v in cmds.most_common()]))
    if gives:
        m.tables.append(("ItemGive OK (последние 15)", ["Время", "От", "Кому", "Code", "Кол-во"],
                         [[fmt_ts(a), b, c, d, e] for a, b, c, d, e in gives[-15:]]))
    m.notes.append("Send_HideCommand за период: %d (рутина, в итог не входит). Строки `___ExceptionDisConnetUser___` - в M7d." % hide)
    return m


# ----------------------------------------------------------------------------------------------
# LoginManager: M12 / M12o / M8 (OTP_Report) + LoginProc
# ----------------------------------------------------------------------------------------------
RX_OTP_LOGIN = re.compile(r"^Login User ID (\S+?)/(\S*), Pass (\S*), IP (\S+)")
RX_OTP_RES = re.compile(r"^(\S+) UPUserLogin result : iUserLoginStatus (-?\d+)")


def load_otp(ctx):
    """OTP_Report из LoginMngError (если файлы там ещё есть) и из архива. Запись:
    (ts, login, ip, mac, status, имя файла). Хеши паролей отбрасываются сразу."""
    live = index_dir(os.path.join(ctx.root, "LoginManager", "Log", "LoginMngError"), ctx.dateset)
    arch = index_dir(ctx.otp_archive, ctx.dateset) if ctx.otp_archive else {}
    recs, nl, na = [], 0, 0
    for d in ctx.dates:
        paths = [p for p in live.get(d, []) if os.path.basename(p).startswith("OTP_Report")]
        if paths:
            nl += len(paths)
        else:
            paths = [p for p in arch.get(d, []) if os.path.basename(p).startswith("OTP_Report")]
            na += len(paths)
        for p in paths:
            pending = collections.defaultdict(list)
            for ts, text in ts_lines(p, d):
                r = RX_OTP_LOGIN.match(text)
                if r:
                    mac = MAC_TAIL.search(r.group(3))
                    pending[r.group(1)].append((ts, r.group(4), mac.group(1).lower() if mac else ""))
                    continue
                r = RX_OTP_RES.match(text)
                if r:
                    login, st = r.group(1), int(r.group(2))
                    pl = pending[login].pop(0) if pending[login] else (ts, "", "")
                    recs.append((pl[0], login, pl[1], pl[2], st, os.path.basename(p)))
    return recs, {"live": nl, "archive": na}


def metric_m12(ctx, recs, cnt):
    m = Metric("M12", "Перебор паролей / вход в заблокированную учётку (OTP_Report + `[LOGIN] Failed Count / Block User`)")
    m.source = "LoginManager/Log/LoginMngError (OTP_Report: live %d, архив %d файлов; LoginProc)" % (cnt["live"], cnt["archive"])
    m.formula = "неудачи (status 2/3/5, Failed Count, Block User) с одного IP/логина: > %d за %d мин" % (THR["m12_fail_n"], THR["m12_win_min"])
    by_ip, by_login = collections.defaultdict(list), collections.defaultdict(list)
    sc = collections.Counter(r[4] for r in recs)
    for ts, login, ip, mac, st, fn in recs:
        if st in (1, 4):
            continue
        m.add(ts, "LoginManager", login, "status %d" % st, "", fn, ip)
        by_ip[ip or "(нет IP)"].append(ts)
        by_login[login].append(ts)
    for d in ctx.dates:
        p = os.path.join(ctx.root, "LoginManager", "Log", "LoginMngError", "LoginProc_%s.txt" % d.strftime("%Y%m%d"))
        if not os.path.isfile(p):
            continue
        for ts, text in ts_lines(p, d):
            if "[LOGIN]" in text and re.search(r"Failed Count|Block User|UPUserLogin Error|Check Block IP", text):
                u = re.search(r"UserID = ([^,\s]+)", text)
                login = u.group(1) if u else "(нет логина)"
                kind = re.search(r"(Failed Count[^\s]*|Block User|UPUserLogin Error\d*|Check Block IP)", text).group(1)
                m.add(ts, "LoginManager", login, kind, text[:140], os.path.basename(p))
                by_login[login].append(ts)
    burst_flags(m, by_ip, THR["m12_fail_n"] + 1, THR["m12_win_min"], "неудачных входов с IP")
    burst_flags(m, by_login, THR["m12_fail_n"] + 1, THR["m12_win_min"], "неудачных входов на логин")
    m.tables.append(("Попытки по status (OTP_Report): 1=вход, 2/3=неверный ID/пароль, 4=уже в игре, 5=блок",
                     ["status", "Записей"], [[k, v] for k, v in sorted(sc.items())]))
    kind_table(m)
    if not recs:
        # ★ 22.11.2026 (ревизия 56 Н-2 админ-центра): прежний текст «старые перенесены в архив» читался так, будто архив просмотрен
        m.notes.append("OTP_Report за период нет ни в LoginMngError, ни в архиве (%s): M8 / M12 / M12o без записей входа LoginManager."
                       % (ctx.otp_archive or "архив не задан"))
    m.notes.append("В dev `UPUserLogin` не проверяет пароль (04 §0 п.5): статусы 2/3 недостижимы, Failed Count мёртв - ожидается 0.")
    return m


def metric_m12o(ctx, recs):
    m = Metric("M12o", "Вход при уже открытой сессии (OTP status 4 / `[LOGIN] Overlap User Error`)")
    m.source = "LoginManager OTP_Report, LoginProc"
    m.formula = "справочно: повторный вход той же учётки; много по разным логинам - признак передачи учётки/бота"
    have = set(r[0].date() for r in recs)
    for ts, login, ip, mac, st, fn in recs:
        if st == 4:
            m.add(ts, "LoginManager", login, "status 4", "", fn, ip)
    for d in ctx.dates:
        if d in have:
            continue
        p = os.path.join(ctx.root, "LoginManager", "Log", "LoginMngError", "LoginProc_%s.txt" % d.strftime("%Y%m%d"))
        if os.path.isfile(p):
            for ts, text in ts_lines(p, d):
                if "Overlap User Error" in text:
                    u = re.search(r"UserID = ([^,\s]+)", text)
                    m.add(ts, "LoginManager", u.group(1) if u else "(нет логина)", "Overlap", "", os.path.basename(p))
    nonowner_flag(m, ctx, "повторный вход")
    return m


def graph_flags(m, triples):
    """Флаги графа учётка-IP-MAC и таблицы топ-IP/MAC. triples: iterable (login, ip, mac)."""
    ip_l, mac_l, l_ip = collections.defaultdict(set), collections.defaultdict(set), collections.defaultdict(set)
    for login, ip, mac in triples:
        login = login.lower()        # логин в БД регистронезависим (Rimy = rimy)
        if ip:
            ip_l[ip].add(login)
            l_ip[login].add(ip)
        if mac:
            mac_l[mac].add(login)
    n = THR["m8_group_n"]
    for ip, ls in sorted(ip_l.items()):      # одна строка флага на группу (субъект = логины группы через запятую)
        if len(ls) >= n:
            m.flag(",".join(sorted(ls)), "IP %s делят %d логинов" % (ip, len(ls)))
    for mac, ls in sorted(mac_l.items()):
        if len(ls) >= n:
            m.flag(",".join(sorted(ls)), "MAC %s делят %d логинов" % (mac, len(ls)))
    for l, ips in sorted(l_ip.items()):
        if len(ips) >= n:
            m.flag(l, "логин входил с %d IP: %s" % (len(ips), ", ".join(sorted(ips))))
    rows = sorted(([ip, len(ls), ", ".join(sorted(ls))[:80]] for ip, ls in ip_l.items()), key=lambda r: -r[1])[:10]
    if rows:
        m.tables.append(("IP -> число логинов (топ-10)", ["IP", "Логинов", "Логины"], rows))
    macs = sorted(([mc, len(ls), ", ".join(sorted(ls))[:80]] for mc, ls in mac_l.items()), key=lambda r: -r[1])[:10]
    if macs:
        m.tables.append(("MAC -> число логинов (топ-10)", ["MAC", "Логинов", "Логины"], macs))


def metric_m8(ctx, recs):
    m = Metric("M8", "Мультиаккаунт: граф учётка - IP - MAC (OTP_Report; БД `JoyLog1.LogInfo` добавляется отдельно)")
    m.source = "OTP_Report (MAC попадает в строку случайно), JoyLog1.dbo.LogInfo"
    m.formula = ">= %d учётки на IP или MAC, >= %d IP на учётку. В dev-LAN все 192.168.10.x - IP слабый признак" % (THR["m8_group_n"], THR["m8_group_n"])
    trip, first, last = collections.Counter(), {}, {}
    for ts, login, ip, mac, st, fn in recs:
        k = (login, ip, mac)
        trip[k] += 1
        first.setdefault(k, ts)
        last[k] = ts
    for k, c in trip.items():
        m.add(last[k], "OTP_Report", k[0], "login-ip-mac", "n=%d, %s .. %s, mac=%s" % (c, fmt_ts(first[k]), fmt_ts(last[k]), k[2] or "-"), "", k[1])
    m.total_override = len(recs)
    m.triples = list(trip)       # для объединения с данными БД
    graph_flags(m, m.triples)
    return m


def loginproc_ips(ctx, m8):
    cnt = collections.Counter()
    for d in ctx.dates:
        p = os.path.join(ctx.root, "LoginManager", "Log", "LoginMngError", "LoginProc_%s.txt" % d.strftime("%Y%m%d"))
        if not os.path.isfile(p):
            continue
        for ts, text in ts_lines(p, d):
            r = re.match(r"ProcConnect = \d+, (\S+)", text)
            if r:
                cnt[r.group(1)] += 1
    if cnt:
        m8.tables.append(("Подключений к LoginManager по IP (LoginProc, топ-10)", ["IP", "Подключений"],
                          [[k, v] for k, v in cnt.most_common(10)]))


def operator_ui_map(ctx):
    """{userindex: [ники]} из Log_Operator (`UserID = <ник>, <userindex>`): запасной способ узнать владельца
    userindex, когда в Us_member строки нет (исторические индексы прошлых баз dev)."""
    out = collections.defaultdict(set)
    for srv, d, p, ts, text in gs_lines(ctx, "Log_Operator"):
        for nick, idx in re.findall(r"UserID = ([^,]+), (\d+)", text):
            out[int(idx)].add(nick.strip())
    return {k: sorted(v) for k, v in out.items()}
