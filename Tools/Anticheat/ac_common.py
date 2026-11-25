# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""ac_common.py - общие типы и разборщики журналов для ac_daily_report.py (мера 4 античита, только чтение).

Побочных эффектов при импорте нет. Формат строк GameServer/LoginManager:
    'MM Mon DD Day HH hou MM min SS sec : текст'  (без года - год берётся из имени файла, кодировка cp1251/UTF-8).
"""
import collections
import datetime as dt
import os
import re

# Учётки/ники владельца и служебные тестовые (GM_*, ADM_*, sitx*, Rimy, тестовые). Меняется --owner-regex.
DEFAULT_OWNER_RE = r"(?i)(sitx|rimy|kreemdfgre|ssssiiiiii|testbot|^GM_|^ADM_)"

# Пороги-кандидаты (04_detection_response.md §3). Переопределяются --thr KEY=VALUE.
THR = {
    "m5_burst_n": 5, "m5_burst_min": 10,            # M5: >= N срабатываний на ник за 10 мин
    "m6_ratio": 0.8, "m6_ratio_n": 10,              # M6: Duration/PDuration < 0.8 многократно (>= n на ник)
    "m6_count": 30,                                 # M6: Count > 30 = порог отключения 8905
    "m9_session_h": 8.0, "m9_day_h": 16.0,          # M9: одна сессия > 8 ч; онлайн за сутки >= 16 ч
    "m9_merge_gap_s": 120,                          # склейка сессий при портале (дисконнект -> портал-логон)
    "m1_min_session_s": 300, "m1_z": 5.0,           # M1: сессии от 5 мин; флаг > Z x медианы уровня
    "m1_min_group": 5,                              # M1: медиана уровня считается от >= 5 сессий
    "m8_group_n": 3,                                # M8: >= 3 учётки на IP/MAC, >= 3 IP на учётку
    "m12_fail_n": 5, "m12_win_min": 10,             # M12: > N неудач с IP/учётки за 10 мин
    "m3_pair_deals": 5, "m3_gold_oneway": 1000000,  # M3: пара >= 5 сделок; золото в одну сторону
    "m4_chain": 3,                                  # M4: серийник передан >= 3 раз за окно
}

HDR = re.compile(r"^(\d{2}) [A-Za-z]{3} (\d{2}) Day (\d{2}) hou (\d{2}) min (\d{2}) sec : ?(.*)$")
DATE_IN_NAME = re.compile(r"(\d{8})\.txt$")

Ev = collections.namedtuple("Ev", "ts src subject kind detail file ip")


class Ctx(object):
    """Параметры прогона."""

    def __init__(self, root, d0, d1, out, owner_re, gs_servers, npc_servers, otp_archive, with_db):
        self.root = root.rstrip("/\\")
        self.d0, self.d1 = d0, d1
        self.dates = [d0 + dt.timedelta(days=i) for i in range((d1 - d0).days + 1)]
        self.dateset = set(self.dates)
        self.t0 = dt.datetime.combine(d0, dt.time())
        self.t1 = dt.datetime.combine(d1 + dt.timedelta(days=1), dt.time())
        self.out = out
        self.owner = re.compile(owner_re)
        self.gs_servers = gs_servers
        self.npc_servers = npc_servers
        self.otp_archive = otp_archive
        self.with_db = with_db
        self.tag = d1.isoformat() if d0 == d1 else "%s_%s" % (d0.isoformat(), d1.isoformat())

    def is_owner(self, subject):
        """Субъект принадлежит владельцу; для группы «a,b,c» (флаги графа M8) - только если ВСЕ члены владельческие."""
        if not subject:
            return False
        parts = [x.strip() for x in subject.split(",") if x.strip()]
        return bool(parts) and all(self.owner.search(x) for x in parts)


class Metric(object):
    """Результат одной метрики: события + заметки + флаги + доп. таблицы."""

    def __init__(self, mid, title):
        self.mid, self.title = mid, title
        self.events = []
        self.status = "ok"       # ok | нет данных | ошибка
        self.notes = []
        self.flags = []          # (субъект, текст)
        self.tables = []         # (название, заголовки, строки)
        self.top_override = None   # строка вместо топ-5 по числу событий
        self.total_override = None
        self.source = ""
        self.formula = ""

    def add(self, ts, src, subject, kind, detail="", file="", ip=""):
        self.events.append(Ev(ts, src, subject or "", kind, detail, file, ip))

    def flag(self, subject, text):
        self.flags.append((subject or "", text))


def read_lines(path):
    """Потоково читает файл построчно; строка - UTF-8, а при ошибке cp1251 (в логах встречаются обе)."""
    with open(path, "rb") as f:
        for raw in f:
            raw = raw.rstrip(b"\r\n")
            if not raw:
                continue
            try:
                yield raw.decode("utf-8")
            except UnicodeDecodeError:
                yield raw.decode("cp1251", "replace")


def ts_lines(path, date):
    """Разбор 'MM Mon DD Day HH hou MM min SS sec : текст'; год из имени файла (date)."""
    for s in read_lines(path):
        m = HDR.match(s)
        if not m:
            continue
        mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 6))
        try:
            ts = dt.datetime(date.year, mo, d, h, mi, se)
        except ValueError:
            continue
        yield ts, m.group(6)


def index_dir(path, dateset):
    """{дата: [файлы]} для файлов вида *_YYYYMMDD.txt, попадающих в dateset."""
    out = collections.defaultdict(list)
    try:
        names = os.listdir(path)
    except OSError:
        return out
    for n in names:
        m = DATE_IN_NAME.search(n)
        if not m:
            continue
        try:
            d = dt.datetime.strptime(m.group(1), "%Y%m%d").date()
        except ValueError:
            continue
        if d in dateset:
            out[d].append(os.path.join(path, n))
    return out


def gs_lines(ctx, subdir, dateset=None):
    """Строки каналов всех GameServer из ctx.gs_servers (по умолчанию stack_layout.GS_FOLDERS): (сервер, дата, файл, ts, текст)."""
    ds = dateset or ctx.dateset
    for srv in ctx.gs_servers:
        idx = index_dir(os.path.join(ctx.root, srv, "Log", subdir), ds)
        for d in sorted(idx):
            for p in sorted(idx[d]):
                for ts, text in ts_lines(p, d):
                    yield srv, d, p, ts, text


def in_window(ctx, ts):
    return ctx.t0 <= ts < ctx.t1


def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def max_in_window(times, minutes):
    """Максимум событий в скользящем окне по отсортированному списку datetime -> (n, начало окна)."""
    best, best_t, j = 0, None, 0
    span = dt.timedelta(minutes=minutes)
    for i, t in enumerate(times):
        while times[j] < t - span:
            j += 1
        if i - j + 1 > best:
            best, best_t = i - j + 1, times[j]
    return best, best_t


def burst_flags(m, items, n_thr, minutes, label):
    """items: {субъект: [ts...]}; добавляет флаг, если за окно в minutes минут >= n_thr событий."""
    for subj, times in sorted(items.items()):
        n, t = max_in_window(sorted(times), minutes)
        if n >= n_thr:
            m.flag(subj, "%s: %d за %d мин (с %s)" % (label, n, minutes, fmt_ts(t)))


def nonowner_flag(m, ctx, label, kinds=None):
    """Флаг на каждый субъект-не-владелец (настоящий ник), у которого есть события метрики."""
    cnt = collections.Counter()
    for e in m.events:
        if kinds is not None and e.kind not in kinds:
            continue
        if e.subject and not e.subject.startswith(("(", "ui:", "ip:")) and not ctx.is_owner(e.subject):
            cnt[e.subject] += 1
    for s, c in cnt.most_common():
        m.flag(s, "%s: %d событий вне списка владельца" % (label, c))


def kind_table(m, name="По видам"):
    c = collections.Counter(e.kind for e in m.events)
    if c:
        m.tables.append((name, ["Вид", "Событий"], [[k, v] for k, v in c.most_common()]))
