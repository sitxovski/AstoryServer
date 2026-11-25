# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""ac_case.py - журнал дел античита (волна В6 «Санкции», блок Г плана альфы).

Дело AC-NNNN ведётся в joylog1.san.* (SQL-комплект AstoryServer/Docs/SQL/san_*.sql, док san_cases.md),
доказательства - файлы в хранилище (ключ evidence_root в ac_case_config.json / ASDA_CASES_DIR / --store), к каждому
файлу sha256 в БД. Принципы (00_PLAN.md §3, 04_detection_response.md §4-5): санкцию выносит ЧЕЛОВЕК по делу с
доказательствами из двух независимых источников; автоматика стойки - только кик и автоблок P48/P69.

Команды: open, attach, export, show, decide, execute, withdraw, lift, appeal, close, verify, list, ladder, rollback-report, selftest.
Блок и разблок - только ШТАТНЫЕ скрипты ac0_block_user.sql / ac0_unblock_user.sql (us_block = 5 + BlockList /
AsdaStoryOP.dbo.OPBlockDel) с подстановкой параметров; новых путей блокировки нет. В игровые таблицы (Joy1 Item,
Charinfo и т.п.) инструмент не пишет: rollback-report только готовит отчёт «что откатить по Serial».

Побочных эффектов при импорте нет (всё под main()). Пароль БД читается db_connect.read_password() и не печатается.
Запуск без -I (pyodbc в пользовательском site-packages); selftest без --db работает и с -I.
"""
import argparse
import csv
import datetime as dt
import decimal
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "ac_case_config.json")
MIGRATE_SQL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Docs/SQL/san_01_migrate.sql"

# Таблицы журнала античита, на которые может ссылаться дело (как CK_san_case_event_tbl).
AC_TABLES = ("operator_refusal", "identity_mismatch", "login_check_refusal", "kick_block",
             "sign_replay", "move_combat", "other", "packet_validator")

ALLOWED = {("open", "evidence"), ("open", "closed"), ("evidence", "decision"), ("evidence", "closed"),
           ("decision", "executed"), ("decision", "evidence"), ("decision", "closed"),
           ("executed", "appeal"), ("executed", "closed"),
           ("appeal", "decision"), ("appeal", "executed"), ("appeal", "closed"), ("closed", "appeal")}

OUTCOMES = ("sanctioned", "acquitted", "no_action", "overturned")
LOGIN_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,61}$")          # набор символов логина UPUserLogin (P51)
MD5_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
NON_INDEPENDENT_KINDS = ("export", "report")            # производные файлы - не независимые источники

DEFAULT_CONFIG = {
    "evidence_root": "D:/AsdaCases", "appeal_days": 14, "retention_days": 180, "two_sources_from_step": 3,
    "max_file_mb": 200, "share_root": "//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/ASDA/Working_ASDA/v2",
    "block_script": "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Docs/SQL/ac0_block_user.sql",
    "unblock_script": "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Docs/SQL/ac0_unblock_user.sql",
    "ladder": [],
}


class CaseError(Exception):
    """Отказ команды с понятным оператору текстом (код возврата 2)."""


# ════════════════════════════════════════════ конфиг и хранилище ════════════════════════════════════════════

def load_config(path=CONFIG_PATH):
    """Конфиг: умолчания + ac_case_config.json (если есть)."""
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.isfile(path):
        with io.open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def ladder_map(cfg):
    """Ступени лестницы {номер: описание}."""
    lad = {int(x["step"]): x for x in cfg.get("ladder", [])}
    if sorted(lad) != list(range(7)):
        raise CaseError("лестница в конфиге должна содержать ступени 0..6")
    return lad


def norm(p):
    """Путь с прямыми слэшами (для сравнения и сообщений)."""
    return os.path.abspath(p).replace("\\", "/") if not p.startswith(("//", "\\\\")) else p.replace("\\", "/")


def check_store_root(root):
    """Хранилище: не на шаре стойки (там журналы без контроля доступа, 04 §4). Возвращает список предупреждений."""
    r = root.replace("\\", "/")
    if r.startswith("//"):
        if "@@ASTORY_SERVER_HOSTNAME@@" in r.lower():
            raise CaseError("хранилище доказательств на шаре стойки запрещено: " + root)
        return ["хранилище на сетевом пути " + root + " - проверьте контроль доступа"]
    warn = []
    if norm(r).lower().startswith("d:/Astory/"):
        warn.append("хранилище внутри @@ASTORY_DEV_ROOT_FWD@@ (рабочая папка Perforce) - лучше вне её")
    return warn


def store_root(cfg, override=None):
    """Корень хранилища: --store > ASDA_CASES_DIR > evidence_root конфига."""
    return override or os.environ.get("ASDA_CASES_DIR") or cfg["evidence_root"]


def sha256_file(path, chunk=1 << 20):
    """sha256 и размер файла (потоково, только чтение)."""
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def sha256_bytes(b):
    """sha256 байтов."""
    return hashlib.sha256(b).hexdigest()


def jval(v):
    """Значение строки БД -> JSON (дата ISO, Decimal/bytes/uuid - строкой)."""
    if isinstance(v, (dt.datetime, dt.date, dt.time)):
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, uuid.UUID):
        return str(v).upper()
    return v


def canon_json(d):
    """Канонический JSON строки (ключи по алфавиту, без пробелов, UTF-8) - основа row_sha256."""
    return json.dumps({k: jval(v) for k, v in d.items()}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def decode_line(b):
    """Строка журнала сервера: UTF-8, при ошибке cp1251 (встречаются обе)."""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp1251", errors="replace")


def mask_secrets(s):
    """Маска 32-hex (MD5 паролей в OTP_Report и т.п., 04 §6.3)."""
    return MD5_RE.sub("<md5 скрыт>", s)


def make_excerpt(src, dst, regex, header):
    """Выдержка строк по регулярке (пароли замаскированы) -> UTF-8 файл. Возвращает число строк."""
    rx = re.compile(regex)
    n = 0
    with open(src, "rb") as f, io.open(dst, "w", encoding="utf-8", newline="\n") as o:
        for line in header:
            o.write("# " + line + "\n")
        for i, raw in enumerate(f, 1):
            s = decode_line(raw.rstrip(b"\r\n"))
            if rx.search(s):
                o.write("%d\t%s\n" % (i, mask_secrets(s)))
                n += 1
    return n


def safe_name(name):
    """Имя файла для хранилища (без каталогов и опасных символов)."""
    base = os.path.basename(name.replace("\\", "/"))
    return re.sub(r"[^\w.\-()]+", "_", base)[:120] or "file"


def write_json_atomic(path, obj):
    """Запись JSON через временный файл (manifest.json)."""
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def verify_files(case_dir, rows):
    """Проверка файлов дела против реестра БД. rows: [{rel_path, size_bytes, sha256}]. -> (ok, fail, extra)."""
    ok, fail = [], []
    known = set()
    for r in rows:
        rel = r["rel_path"].replace("\\", "/")
        known.add(rel.lower())
        p = os.path.join(case_dir, *rel.split("/"))
        if not os.path.isfile(p):
            fail.append((rel, "файла нет"))
            continue
        h, n = sha256_file(p)
        if n != r["size_bytes"]:
            fail.append((rel, "размер %d, в БД %d" % (n, r["size_bytes"])))
        elif h != r["sha256"]:
            fail.append((rel, "sha256 %s, в БД %s" % (h[:16], r["sha256"][:16])))
        else:
            ok.append(rel)
    extra = []
    if os.path.isdir(case_dir):
        for dp, _, fns in os.walk(case_dir):
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), case_dir).replace("\\", "/")
                if rel.lower() in known or rel in ("manifest.json", "case.md") or rel.endswith(".tmp"):
                    continue
                extra.append(rel)
    return ok, fail, extra


# ════════════════════════════════════════════ штатные скрипты блока ════════════════════════════════════════════

def _sub_once(text, pattern, repl, what):
    """Замена ровно одного вхождения (иначе шаблон скрипта изменился - отказ)."""
    new, n = re.subn(pattern, repl, text, flags=re.M)
    if n != 1:
        raise CaseError("шаблон штатного скрипта изменился: %s найдено %d раз" % (what, n))
    return new


def ascii_reason(s):
    """Причина для BlockList.Reason (varchar 300, кодировка базы): только печатная латиница без кавычек."""
    s = "".join(ch for ch in s if 32 <= ord(ch) < 127 and ch != "'")
    return re.sub(r"\s+", " ", s).strip()[:300]


def render_block_script(text, login, hours, reason):
    """ac0_block_user.sql с подставленными логином, часами, причиной."""
    if not LOGIN_RE.match(login or ""):
        raise CaseError("логин вне набора [A-Za-z0-9_.@-]: %r" % login)
    if not (hours == -1 or (isinstance(hours, int) and hours > 0)):
        raise CaseError("срок блока: целое > 0 или -1")
    if not reason or reason != ascii_reason(reason):
        raise CaseError("причина блока - только печатная латиница без апострофа, до 300 символов")
    t = _sub_once(text, r"^(DECLARE @Uid\s+VARCHAR\(61\)\s+=\s+)'[^']*'", r"\g<1>'%s'" % login, "@Uid")
    t = _sub_once(t, r"^(DECLARE @Hours\s+INT\s+=\s+)-?\d+", r"\g<1>%d" % hours, "@Hours")
    t = _sub_once(t, r"^(DECLARE @Reason\s+VARCHAR\(300\)\s+=\s+)'[^']*'", r"\g<1>'%s'" % reason, "@Reason")
    return t


def render_unblock_script(text, login):
    """ac0_unblock_user.sql с подставленным логином."""
    if not LOGIN_RE.match(login or ""):
        raise CaseError("логин вне набора [A-Za-z0-9_.@-]: %r" % login)
    return _sub_once(text, r"^(DECLARE @Uid\s+VARCHAR\(61\)\s+=\s+)'[^']*'", r"\g<1>'%s'" % login, "@Uid")


def split_batches(sql):
    """Пакеты по строкам GO."""
    return [b for b in re.split(r"^\s*GO\s*$", sql, flags=re.M | re.I) if b.strip()]


# ════════════════════════════════════════════ ini стойки (P48/P69) ════════════════════════════════════════════

def parse_ini_bytes(raw):
    """patches.ini (UTF-16 с BOM или UTF-8/cp1251) -> {секция: {ключ: значение}}."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1251", errors="replace")
    res, sec = {}, None
    for line in text.splitlines():
        s = line.split(";", 1)[0].strip()
        if not s:
            continue
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            sec = res.setdefault(m.group(1), {})
        elif sec is not None and "=" in s:
            k, v = s.split("=", 1)
            sec[k.strip()] = v.strip()
    return res


def ladder_check(cfg, ini_by_server):
    """Сверка сроков лестницы с ini стойки. -> [(сервер, ступень, секция.ключ, в ini, в лестнице, ok)]."""
    out = []
    lad = ladder_map(cfg)
    for srv, ini in ini_by_server.items():
        for st in sorted(lad):
            for sec, key in lad[st].get("ini", []):
                v = ini.get(sec, {}).get(key)
                try:
                    iv = int(v) if v is not None else None
                except ValueError:
                    iv = None
                out.append((srv, st, "%s.%s" % (sec, key), v, lad[st]["hours"], iv == lad[st]["hours"]))
    return out


# ════════════════════════════════════════════ БД ════════════════════════════════════════════

_WRITE_TARGET = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|EXEC(?:UTE)?)\s+([\w.\[\]]+)", re.I)
_DDL = re.compile(r"\b(DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|DENY|MERGE|BACKUP|RESTORE|SHUTDOWN)\b", re.I)


def assert_san_write(sql):
    """Запись инструмента - только в joylog1.san.* (штатные скрипты блока идут отдельным путём run_script)."""
    s = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    s = re.sub(r"--[^\n]*", " ", s)
    s = re.sub(r"N?'(?:[^']|'')*'", "''", s)
    m = _DDL.search(s)
    if m:
        raise ValueError("запрещённое слово в записи журнала дел: " + m.group(1))
    for m in _WRITE_TARGET.finditer(s):
        t = m.group(2).lower().replace("[", "").replace("]", "")
        if not (t.startswith("joylog1.san.") or t.startswith("san.")):
            raise ValueError("запись вне схемы san: " + m.group(2))
    return True


class Db(object):
    """Одно соединение на команду (autocommit выключен): все записи команды - одна транзакция."""

    def __init__(self, cn):
        self.cn = cn

    @staticmethod
    def open():
        import pyodbc  # ленивый импорт
        sys.path.insert(0, HERE)
        import db_connect as dbc
        drv = [d for d in pyodbc.drivers() if "SQL Server" in d]
        if not drv:
            raise RuntimeError("нет ODBC-драйвера SQL Server")
        drv = sorted(drv, key=lambda d: ("ODBC Driver" not in d, d))[0]
        pw = dbc.read_password().replace("}", "}}")
        cs = ("DRIVER={%s};SERVER=%s;DATABASE=joylog1;UID=%s;PWD={%s};TrustServerCertificate=yes"
              % (drv, dbc.DEFAULT_SERVER, dbc.DEFAULT_UID, pw))
        return Db(pyodbc.connect(cs, autocommit=False, timeout=15))

    def rows(self, sql, params=()):
        """SELECT -> список словарей."""
        cur = self.cn.cursor()
        cur.execute(sql, params) if params else cur.execute(sql)
        if not cur.description:
            return []
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def one(self, sql, params=()):
        r = self.rows(sql, params)
        return r[0] if r else None

    def w(self, sql, params=()):
        """Запись в san.* (проверка цели); возвращает первую строку результата, если есть."""
        assert_san_write(sql)
        cur = self.cn.cursor()
        cur.execute(sql, params) if params else cur.execute(sql)
        res = None
        while True:
            if cur.description and res is None:
                cols = [c[0] for c in cur.description]
                r = cur.fetchone()
                res = dict(zip(cols, r)) if r else None
            if not cur.nextset():
                break
        return res

    def run_script(self, text):
        """Пакеты штатного скрипта блока/разблока; ошибки (RAISERROR) всплывают исключением. -> строки последнего SELECT."""
        last = []
        cur = self.cn.cursor()
        for b in split_batches(text):
            cur.execute(b)
            while True:
                if cur.description:
                    cols = [c[0] for c in cur.description]
                    last = [dict(zip(cols, r)) for r in cur.fetchall()]
                if not cur.nextset():
                    break
        cur.execute("USE joylog1")
        return last

    def set_status(self, case_id, to, actor, action, detail, expect_from):
        self.w("EXEC joylog1.san.UP_SAN_SetStatus ?, ?, ?, ?, ?, ?", (case_id, to, actor, action, detail, expect_from))

    def log(self, case_id, actor, action, detail):
        st = self.one("SELECT status FROM joylog1.san.cases WHERE case_id = ?", (case_id,))["status"]
        self.w("INSERT INTO joylog1.san.case_log (case_id, actor, action, status_from, status_to, detail) VALUES (?, ?, ?, ?, ?, ?)",
               (case_id, actor, action, st, st, detail))

    def commit(self):
        self.cn.commit()

    def rollback(self):
        self.cn.rollback()


# ════════════════════════════════════════════ общие запросы ════════════════════════════════════════════

def parse_case_id(s):
    """'AC-0001' / '1' -> 1."""
    m = re.match(r"^(?:AC-)?0*(\d+)$", str(s).strip(), re.I)
    if not m:
        raise CaseError("номер дела: AC-NNNN или число, получено %r" % s)
    return int(m.group(1))


def get_case(db, cid, lock=False):
    c = db.one("SELECT * FROM joylog1.san.cases %s WHERE case_id = ?" % ("WITH (UPDLOCK)" if lock else ""), (cid,))
    if not c:
        raise CaseError("дела %s нет" % cid)
    return c


def resolve_user(db, login=None, ui=None):
    """Учётка по логину или номеру: (Userindex, us_id)."""
    if login:
        r = db.one("SELECT Userindex, us_id FROM AsdaStoryOp.dbo.Us_member WHERE us_id = ?", (login,))
    else:
        r = db.one("SELECT Userindex, us_id FROM AsdaStoryOp.dbo.Us_member WHERE Userindex = ?", (ui,))
    if not r:
        raise CaseError("учётка не найдена: %s" % (login or ui))
    return r["Userindex"], r["us_id"]


def char_names(db, ui):
    return [r["Charname"] for r in db.rows("SELECT Charname FROM Joy1.dbo.Charinfo WHERE Userindex = ? ORDER BY Charidx", (ui,))]


def case_dir(root, c):
    return os.path.join(root, c["evidence_dir"] or c["case_no"])


def source_key(r):
    """Кто источник файла по сути (ревизия 59 Н-4, 22.11.2026): путь источника (без регистра и вида слэшей), без пути — sha256 источника,
    без него — sha256 самого файла. Метка (source_label) — подпись оператора, источником не считается: две выдержки одного журнала
    с разными метками — ОДИН источник."""
    p = (r.get("source_path") or "").replace("\\", "/").strip().lower()
    return ("path", p) if p else (("sha", r["source_sha256"]) if r.get("source_sha256") else ("sha", r.get("sha256") or ""))


def case_sources(db, cid):
    """Независимые источники дела: ac.<таблица> событий + файлы (кроме export/report), разные по сути (source_key), а не по метке.
    Подпись — «файл: <метка>» (у второго файла с той же меткой — с именем источника в скобках)."""
    src = set("ac." + r["table_name"] for r in db.rows("SELECT DISTINCT table_name FROM joylog1.san.case_event WHERE case_id = ?", (cid,)))
    seen = {}
    for r in db.rows("SELECT source_label, kind, source_path, source_sha256, sha256 FROM joylog1.san.evidence WHERE case_id = ? "
                     "ORDER BY evidence_id", (cid,)):
        if r["kind"] in NON_INDEPENDENT_KINDS:
            continue
        k = source_key(r)
        if k in seen:
            continue
        name = "файл: " + r["source_label"]
        if name in seen.values():
            tail = (r.get("source_path") or "").replace("\\", "/").rsplit("/", 1)[-1] or (r.get("source_sha256") or r.get("sha256") or "")[:12]
            name = "%s (%s)" % (name, tail)
        seen[k] = name
    return sorted(src | set(seen.values()))


def write_manifest(db, root, c):
    """manifest.json папки дела (04 §4): реестр файлов и событий из БД. Генерируется после каждой записи."""
    d = case_dir(root, c)
    os.makedirs(d, exist_ok=True)
    ev = db.rows("SELECT kind, rel_path, size_bytes, sha256, source_label, source_path, source_size, source_mtime, source_sha256, "
                 "added_by, added_at, note FROM joylog1.san.evidence WHERE case_id = ? ORDER BY evidence_id", (c["case_id"],))
    evs = db.rows("SELECT table_name, event_id, ev_local, server_name, row_sha256 FROM joylog1.san.case_event WHERE case_id = ? "
                  "ORDER BY table_name, event_id", (c["case_id"],))
    write_json_atomic(os.path.join(d, "manifest.json"), {
        "case_no": c["case_no"], "generated_by": "ac_case.py", "note": "реестр - в joylog1.san; этот файл - его копия",
        "files": [{k: jval(v) for k, v in r.items()} for r in ev],
        "events": [{k: jval(v) for k, v in r.items()} for r in evs]})


def login_readiness(db, ui):
    """Можно ли войти по данным БД (условия UPUserLogin P51/P52 + блок): -> (bool, [строки])."""
    u = db.one("SELECT Userindex, us_id, us_block, Flag, us_pwfail, us_pwfail_at, "
               "CASE WHEN us_pwhash IS NULL THEN 0 ELSE 1 END AS has_hash, CASE WHEN us_pwsalt IS NULL THEN 0 ELSE 1 END AS has_salt, "
               "(SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList b WHERE b.Userindex = m.Userindex) AS bl_rows, "
               "(SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList b WHERE b.Userindex = m.Userindex AND b.CloseDate >= GETDATE()) AS bl_active, "
               "CASE WHEN us_pwfail >= 10 AND us_pwfail_at > DATEADD(MINUTE, -15, GETDATE()) THEN 1 ELSE 0 END AS pw_locked "
               "FROM AsdaStoryOp.dbo.Us_member m WHERE Userindex = ?", (ui,))
    if not u:
        return False, ["учётки нет"]
    lines, ok = [], True
    if not LOGIN_RE.match(u["us_id"].rstrip()):
        ok = False
        lines.append("логин вне набора символов UPUserLogin -> статус 2")
    if u["us_block"] != 0:
        ok = False
        lines.append("us_block = %s -> статус 5 (блок)%s" % (u["us_block"], "; строки BlockList истекли - снимет UPUserLogin при входе"
                                                           if u["us_block"] == 5 and u["bl_rows"] and not u["bl_active"] else ""))
    if u["bl_rows"]:
        lines.append("строк BlockList: %d (действующих %d)" % (u["bl_rows"], u["bl_active"]))
    if not (u["has_hash"] and u["has_salt"]):
        ok = False
        lines.append("пароль не задан (us_pwhash/us_pwsalt NULL) -> статус 3")
    if u["pw_locked"]:
        ok = False
        lines.append("замок неудач пароля (10 за 15 мин) -> статус 3 до истечения окна")
    if u["Flag"] == 1:
        lines.append("Flag = 1 (числится в игре) -> первый вход даст статус 4 (сброс), второй пройдёт")
    if ok:
        lines.insert(0, "вход по данным БД возможен: us_block 0, BlockList пуст, пароль задан, замка нет")
    return ok, lines


# ════════════════════════════════════════════ команды ════════════════════════════════════════════

class Ctx(object):
    """Контекст команды: конфиг, БД, хранилище, кто действует."""

    def __init__(self, cfg, db, root, actor, out=None):
        self.cfg, self.db, self.root, self.actor = cfg, db, root, actor
        self.out = out or sys.stdout
        self.created = []      # файлы/папки, созданные командой: при откате транзакции удаляются (ещё не доказательства)

    def cleanup(self):
        """Откат файловой части команды: удалить свои свежие файлы и пустые папки."""
        for p in reversed(self.created):
            try:
                if os.path.isfile(p):
                    os.remove(p)
                elif os.path.isdir(p):
                    for dp, dns, fns in os.walk(p, topdown=False):
                        if not fns and not os.listdir(dp):
                            os.rmdir(dp)
            except OSError:
                pass
        self.created = []

    def p(self, *a):
        print(*a, file=self.out)


def cmd_open(ctx, a):
    db = ctx.db
    ui, login = resolve_user(db, a.user, a.ui)
    char_idx = None
    if a.char:
        r = db.one("SELECT Charidx FROM Joy1.dbo.Charinfo WHERE Userindex = ? AND Charname = ?", (ui, a.char))
        if not r:
            raise CaseError("у учётки %s нет персонажа %s (есть: %s)" % (login, a.char, ", ".join(char_names(db, ui))))
        char_idx = r["Charidx"]
    for w in check_store_root(ctx.root):
        ctx.p("ВНИМАНИЕ:", w)
    r = db.w("EXEC joylog1.san.UP_SAN_CaseOpen ?, ?, ?, ?, ?, ?, ?, ?",
             (ui, login, char_idx, a.char, a.title, a.hypothesis, ctx.actor, 1 if a.training else 0))
    cid, no = r["case_id"], r["case_no"]
    db.w("UPDATE joylog1.san.cases SET evidence_dir = ? WHERE case_id = ?", (no, cid))
    c = get_case(db, cid)
    d = case_dir(ctx.root, c)
    if not os.path.exists(d):
        ctx.created.append(d)
    for sub in ("files", "exports", "reports"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    write_manifest(db, ctx.root, c)
    ctx.p("%s открыто: учётка %d (%s)%s; папка %s" % (no, ui, login, (", персонаж " + a.char) if a.char else "", norm(d)))
    return c


def _fetch_event(db, table, eid):
    if table not in AC_TABLES:
        raise CaseError("таблица журнала: одна из %s" % ", ".join(AC_TABLES))
    row = db.one("SELECT * FROM joylog1.ac.[%s] WHERE event_id = ?" % table, (eid,))
    if not row:
        raise CaseError("события ac.%s #%d нет (очищено журналом или неверный номер)" % (table, eid))
    v = db.one("SELECT violation_type, summary FROM joylog1.ac.v_events WHERE table_name = ? AND event_id = ?", (table, eid))
    return row, v or {}


def attach_events(ctx, c, pairs, note=None):
    """Привязка событий ac.* к делу: ссылка + полный снимок строки + sha256. -> число новых."""
    db, cid, added = ctx.db, c["case_id"], []
    for table, eid in pairs:
        if db.one("SELECT 1 AS x FROM joylog1.san.case_event WHERE case_id = ? AND table_name = ? AND event_id = ?", (cid, table, eid)):
            ctx.p("  уже в деле: ac.%s #%d" % (table, eid))
            continue
        row, v = _fetch_event(db, table, eid)
        js = canon_json(row)
        db.w("INSERT INTO joylog1.san.case_event (case_id, table_name, event_id, attached_by, ev_local, server_name, user_index, char_name, "
             "ip, violation_type, summary, row_json, row_sha256, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (cid, table, eid, ctx.actor, row.get("ev_local"), row.get("server_name"), row.get("user_index"), row.get("char_name"),
              row.get("ip"), v.get("violation_type"), v.get("summary"), js, sha256_bytes(js.encode("utf-8")), note))
        added.append("ac.%s #%d" % (table, eid))
        ctx.p("  + ac.%s #%d  %s  %s" % (table, eid, jval(row.get("ev_local")), (v.get("summary") or "")[:90]))
    if added:
        db.log(cid, ctx.actor, "attach_event", "событий %d: %s" % (len(added), ", ".join(added))[:4000])
    return len(added)


def auto_event_pairs(db, c, t0, t1):
    """События окна по учётке дела или её персонажам (служебные «журнал:» исключены)."""
    names = char_names(db, c["user_index"])
    q = ("SELECT table_name, event_id FROM joylog1.ac.v_events WHERE ev_local >= ? AND ev_local < ? AND summary NOT LIKE N'журнал:%' "
         "AND (user_index = ?" + (" OR char_name IN (%s)" % ",".join("?" * len(names)) if names else "") + ") ORDER BY ev_local")
    return [(r["table_name"], int(r["event_id"])) for r in db.rows(q, tuple([t0, t1, c["user_index"]] + names))]


def attach_file(ctx, c, src, label, excerpt=None, note=None, kind=None, sub="files"):
    """Файл в хранилище (копия или выдержка) + sha256 в БД. Источник открывается только на чтение."""
    db, cid = ctx.db, c["case_id"]
    if not os.path.isfile(src):
        raise CaseError("нет файла: " + src)
    s_sha, s_size = sha256_file(src)
    s_mtime = dt.datetime.fromtimestamp(os.path.getmtime(src)).replace(microsecond=0)
    if excerpt is None:
        if re.search(r"OTP_Report|LoginMngError", src, re.I):
            raise CaseError("журналы входа LoginManager содержат MD5 паролей - только выдержкой (--excerpt), там маска")
        if s_size > ctx.cfg["max_file_mb"] << 20:
            raise CaseError("файл больше %d МБ - приложите выдержку (--excerpt)" % ctx.cfg["max_file_mb"])
    d = os.path.join(case_dir(ctx.root, c), sub)
    os.makedirs(d, exist_ok=True)
    seq = 1 + len([f for f in os.listdir(d) if re.match(r"^\d{3}_", f)])
    name = "%03d_%s%s" % (seq, safe_name(src), ".excerpt.txt" if excerpt is not None else "")
    dst = os.path.join(d, name)
    if os.path.exists(dst):
        raise CaseError("файл уже есть в хранилище: " + dst)
    ctx.created.append(dst)
    if excerpt is not None:
        n = make_excerpt(src, dst, excerpt, [
            "выдержка для %s; источник %s" % (c["case_no"], norm(src)),
            "источник: %d б, изменён %s, sha256 %s" % (s_size, s_mtime.isoformat(), s_sha),
            "отбор: строки по регулярке %s; 32-hex замаскированы; формат «номер строки<TAB>текст»" % excerpt])
        kind = kind or "excerpt"
        ctx.p("  выдержка: %d строк" % n)
    else:
        shutil.copyfile(src, dst)
        kind = kind or "file"
    h, size = sha256_file(dst)
    if kind == "file" and h != s_sha:
        os.remove(dst)
        raise CaseError("копия не совпала с источником по sha256 (файл меняется во время копирования?)")
    rel = sub + "/" + name
    try:
        db.w("INSERT INTO joylog1.san.evidence (case_id, kind, rel_path, size_bytes, sha256, source_label, source_path, source_size, "
             "source_mtime, source_sha256, added_by, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
             (cid, kind, rel, size, h, label, norm(src), s_size, s_mtime, s_sha, ctx.actor, note))
        db.log(cid, ctx.actor, "attach_file", "%s: %s (%d б, sha256 %s); источник «%s» %s" % (kind, rel, size, h, label, norm(src)))
    except Exception:
        os.remove(dst)       # своя свежая копия, ещё не доказательство
        raise
    ctx.p("  + %s %s  sha256 %s" % (kind, rel, h))
    return rel, h


def register_generated(ctx, c, path, kind, label, note):
    """Файл, созданный инструментом в папке дела (export/report) -> реестр."""
    ctx.created.append(path)
    h, size = sha256_file(path)
    rel = os.path.relpath(path, case_dir(ctx.root, c)).replace("\\", "/")
    ctx.db.w("INSERT INTO joylog1.san.evidence (case_id, kind, rel_path, size_bytes, sha256, source_label, added_by, note) "
             "VALUES (?,?,?,?,?,?,?,?)", (c["case_id"], kind, rel, size, h, label, ctx.actor, note))
    ctx.p("  + %s %s  sha256 %s" % (kind, rel, h))
    return rel, h


def cmd_attach(ctx, a):
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    if c["status"] == "closed":
        raise CaseError("%s закрыто - сначала апелляция" % c["case_no"])
    pairs = []
    for e in a.event or []:
        m = re.match(r"^(?:ac\.)?(\w+)[:#](\d+)$", e)
        if not m:
            raise CaseError("событие: ТАБЛИЦА:event_id, например move_combat:7158")
        pairs.append((m.group(1), int(m.group(2))))
    if a.events_auto:
        t0, t1 = [dt.datetime.fromisoformat(x) for x in a.events_auto]
        auto = auto_event_pairs(db, c, t0, t1)
        ctx.p("событий в окне %s .. %s по учётке/персонажам: %d" % (t0, t1, len(auto)))
        pairs += auto
    n_ev = attach_events(ctx, c, pairs, a.note) if pairs else 0
    n_f = 0
    if a.file:
        if not a.source:
            raise CaseError("для файла нужна метка источника --source (например «NpcServer SpeedHack»)")
        attach_file(ctx, c, a.file, a.source, a.excerpt, a.note)
        n_f = 1
    if not (n_ev or n_f):
        raise CaseError("нечего прикладывать (нужны --event / --events-auto / --file)")
    if c["status"] == "open":
        db.set_status(c["case_id"], "evidence", ctx.actor, "attach", "собраны доказательства", "open")
    write_manifest(db, ctx.root, c)
    ctx.p("%s: событий +%d, файлов +%d; источники: %s" % (c["case_no"], n_ev, n_f, "; ".join(case_sources(db, c["case_id"]))))


def cmd_export(ctx, a):
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    if c["status"] == "closed":
        raise CaseError("%s закрыто - материалы не дополняются (сначала апелляция)" % c["case_no"])
    evs = db.rows("SELECT * FROM joylog1.san.case_event WHERE case_id = ? ORDER BY ev_local, table_name, event_id", (c["case_id"],))
    if not evs:
        raise CaseError("в деле нет событий журнала")
    items = []
    for e in evs:
        live = db.one("SELECT * FROM joylog1.ac.[%s] WHERE event_id = ?" % e["table_name"], (e["event_id"],))
        live_sha = sha256_bytes(canon_json(live).encode("utf-8")) if live else None
        items.append({"table": e["table_name"], "event_id": int(e["event_id"]), "violation_type": e["violation_type"],
                      "summary": e["summary"], "snapshot_sha256": e["row_sha256"],
                      "in_journal_now": bool(live), "journal_matches_snapshot": (live_sha == e["row_sha256"]) if live else None,
                      "row": json.loads(e["row_json"])})
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    d = os.path.join(case_dir(ctx.root, c), "exports")
    os.makedirs(d, exist_ok=True)
    fmts = [x.strip() for x in a.format.split(",")]
    out = []
    if "json" in fmts:
        p = os.path.join(d, "events_%s.json" % stamp)
        with io.open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"case_no": c["case_no"], "exported_at": dt.datetime.now().isoformat(timespec="seconds"),
                       "exported_by": ctx.actor, "events": items}, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
        out.append(p)
    if "csv" in fmts:
        p = os.path.join(d, "events_%s.csv" % stamp)
        cols = ["table", "event_id", "ev_local", "server_name", "user_index", "char_name", "ip", "violation_type", "summary",
                "snapshot_sha256", "in_journal_now", "journal_matches_snapshot"]
        with io.open(p, "w", encoding="utf-8-sig", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(cols)
            for it in items:
                r = it["row"]
                wr.writerow([it["table"], it["event_id"], r.get("ev_local"), r.get("server_name"), r.get("user_index"),
                             r.get("char_name"), r.get("ip"), it["violation_type"], it["summary"], it["snapshot_sha256"],
                             it["in_journal_now"], it["journal_matches_snapshot"]])
        out.append(p)
    if not out:
        raise CaseError("--format: json, csv или оба через запятую")
    for p in out:
        register_generated(ctx, c, p, "export", "export: события дела", "выгрузка %d событий" % len(items))
    db.log(c["case_id"], ctx.actor, "export", "выгрузка %d событий: %s" % (len(items), ", ".join(os.path.basename(p) for p in out)))
    write_manifest(db, ctx.root, c)
    ctx.p("%s: выгружено событий %d -> %s" % (c["case_no"], len(items), ", ".join(norm(p) for p in out)))


def history_hint(ctx, c):
    """Прошлые санкции и блоки учётки (для лестницы): -> рекомендуемая минимальная ступень."""
    db, ui = ctx.db, c["user_index"]
    prev = db.rows("SELECT case_no, ladder_step, outcome, decided_at FROM joylog1.san.cases WHERE user_index = ? AND case_id <> ? "
                   "AND ladder_step IS NOT NULL AND ISNULL(outcome, '') NOT IN ('acquitted', 'overturned') AND is_training = 0",
                   (ui, c["case_id"]))
    blocks = db.rows("SELECT 'BlockList' AS t, BlackDate, CloseDate, Reason FROM AsdaStoryOp.dbo.BlockList WHERE Userindex = ? "
                     "UNION ALL SELECT 'BlockHistory', BlackDate, CloseDate, Reason FROM AsdaStoryOp.dbo.BlockHistory WHERE Userindex = ? "
                     "ORDER BY BlackDate", (ui, ui))
    for r in prev:
        ctx.p("  прошлое дело %s: ступень %s, итог %s" % (r["case_no"], r["ladder_step"], r["outcome"]))
    for r in blocks:
        ctx.p("  %s: %s .. %s  %s" % (r["t"], r["BlackDate"], r["CloseDate"], r["Reason"]))
    auto = [r for r in blocks if (r["Reason"] or "").strip() == "Speed Hack"]
    if auto:
        ctx.p("  в т.ч. автоблоков/GM-6094 (UPHackBlock, причина «Speed Hack»): %d" % len(auto))
    top = max([r["ladder_step"] for r in prev if r["ladder_step"] is not None and 3 <= r["ladder_step"] <= 5] or [0])
    return min(top + 1, 5) if top else None


def cmd_decide(ctx, a):
    db, cfg = ctx.db, ctx.cfg
    lad = ladder_map(cfg)
    c = get_case(db, parse_case_id(a.case), lock=True)
    no, cid = c["case_no"], c["case_id"]
    if c["status"] not in ("evidence", "appeal"):
        raise CaseError("%s в статусе %s: решение выносится по собранным доказательствам (evidence) или при пересмотре (appeal)"
                        % (no, c["status"]))
    if c["status"] == "appeal":
        raise CaseError("пересмотр по апелляции - командой appeal %s --resolve upheld|overturned" % no)
    step = a.step
    if step not in lad:
        raise CaseError("ступень 0..6")
    st = lad[step]
    hours = st["hours"]
    if a.hours is not None:
        if st["exec"] != "block" or step == 5:
            raise CaseError("--hours только для блока на срок (ступени 3, 4)")
        if a.hours <= 0:
            raise CaseError("--hours > 0")
        hours = a.hours
    srcs = case_sources(db, cid)
    two = cfg["two_sources_from_step"]
    if step >= two and len(srcs) < 2:
        if not a.override_two_sources:
            raise CaseError("ступень %d требует доказательств из двух независимых источников, есть: %s"
                            % (step, "; ".join(srcs) or "нет"))
        ctx.p("ВНИМАНИЕ: правило двух источников снято вручную: " + a.override_two_sources)
    if st["exec"] == "report" and not db.one("SELECT 1 AS x FROM joylog1.san.evidence WHERE case_id = ? AND kind = 'report'", (cid,)):
        raise CaseError("откат по Serial: сначала rollback-report %s (отчёт «что откатить»)" % no)
    ctx.p("%s: учётка %d (%s); ступень %d «%s»%s; источники: %s" % (no, c["user_index"], c["login"], step, st["name"],
          (", срок %s ч" % hours) if hours else "", "; ".join(srcs)))
    hint = history_hint(ctx, c)
    if hint and step < hint:
        ctx.p("  ВНИМАНИЕ: по прошлым санкциям лестница предлагает ступень не ниже %d" % hint)
    if hours not in (None, st["hours"]):
        ctx.p("  срок %d ч вне лестницы (ступень %d = %s ч) - записывается в дело" % (hours, step, st["hours"]))
    if st["exec"] == "block" and not a.yes:
        if not sys.stdin.isatty() or input("Наложить блок? Введите номер дела (%s): " % no).strip().upper() != no:
            raise CaseError("блок не подтверждён (ключ --yes или ввод номера дела)")
    detail = "ступень %d %s%s; %s%s" % (step, st["code"], (", %s ч" % hours) if hours else "", a.text,
                                        ("; два источника сняты: " + a.override_two_sources) if a.override_two_sources else "")
    db.w("UPDATE joylog1.san.cases SET ladder_step = ?, decision_kind = ?, block_hours = ?, decision_text = ?, decided_by = ?, "
         "decided_at = SYSDATETIME(), updated_at = SYSDATETIME() WHERE case_id = ?", (step, st["code"], hours, a.text, ctx.actor, cid))
    db.set_status(cid, "decision", ctx.actor, "decide", detail[:4000], c["status"])
    if st["exec"] == "block":
        apply_block(ctx, c, step, hours, a.reason_en)
    elif st["exec"] == "none":
        mark_executed(ctx, c, "наблюдение: только журнал дел", "decision")
    else:
        ctx.p("решение записано; исполнение - вручную (%s), затем: ac_case.py execute %s --text \"...\"" % (st["mechanism"], no))
    write_manifest(db, ctx.root, get_case(db, cid))


def mark_executed(ctx, c, text, expect, action="execute"):
    ctx.db.w("UPDATE joylog1.san.cases SET executed_by = ?, executed_at = SYSDATETIME(), execution_text = ?, "
             "appeal_until = DATEADD(DAY, ?, SYSDATETIME()), updated_at = SYSDATETIME() WHERE case_id = ?",
             (ctx.actor, text, int(ctx.cfg["appeal_days"]), c["case_id"]))
    ctx.db.set_status(c["case_id"], "executed", ctx.actor, action, text[:4000], expect)


def apply_block(ctx, c, step, hours, reason_en=None):
    """Блок штатным ac0_block_user.sql + связь с BlockList в san.case_block + статус executed."""
    db, cfg = ctx.db, ctx.cfg
    path = cfg["block_script"]
    raw = open(path, "rb").read()
    md5 = hashlib.md5(raw).hexdigest()
    reason = ascii_reason("%s s%d %sh%s" % (c["case_no"], step, hours, (": " + reason_en) if reason_en else ""))
    if not reason.startswith(c["case_no"] + " "):
        raise CaseError("причина блока должна начинаться с номера дела")
    login = (c["login"] or "").rstrip()
    u = db.one("SELECT us_id, us_block, Flag FROM AsdaStoryOp.dbo.Us_member WHERE Userindex = ?", (c["user_index"],))
    if not u or u["us_id"].rstrip() != login:
        raise CaseError("логин учётки изменился с открытия дела (%s -> %s)" % (login, u and u["us_id"]))
    if u["Flag"] == 1:
        ctx.p("ВНИМАНИЕ: учётка числится в игре - блок не выкидывает (нужен GM Kick 6018 или выход игрока)")
    db.run_script(render_block_script(raw.decode("utf-8-sig"), login, hours, reason))
    row = db.one("SELECT TOP 1 Userindex, Uid, BlackDate, CloseDate, Reason FROM AsdaStoryOp.dbo.BlockList "
                 "WHERE Userindex = ? AND Reason = ? ORDER BY BlackDate DESC", (c["user_index"], reason))
    ub = db.one("SELECT us_block FROM AsdaStoryOp.dbo.Us_member WHERE Userindex = ?", (c["user_index"],))
    if not row or ub["us_block"] != 5:
        raise CaseError("после ac0_block_user.sql нет строки BlockList / us_block != 5 - откат транзакции")
    via = "ac0_block_user.sql md5 %s" % md5
    db.w("INSERT INTO joylog1.san.case_block (case_id, user_index, uid, hours, reason, black_date, close_date, applied_by, apply_via) "
         "VALUES (?,?,?,?,?,?,?,?,?)", (c["case_id"], c["user_index"], login, hours, reason, row["BlackDate"], row["CloseDate"],
                                        ctx.actor, via))
    text = "блок: us_block = 5, BlockList %s .. %s, причина «%s» (%s)" % (row["BlackDate"], row["CloseDate"], reason, via)
    mark_executed(ctx, c, text, "decision", "block")
    ctx.p("исполнено: " + text)


def cmd_execute(ctx, a):
    db, lad = ctx.db, ladder_map(ctx.cfg)
    c = get_case(db, parse_case_id(a.case), lock=True)
    if c["status"] != "decision":
        raise CaseError("%s в статусе %s; исполнить можно только вынесенное решение" % (c["case_no"], c["status"]))
    if lad[c["ladder_step"]]["exec"] == "block":
        raise CaseError("блок исполняется командой decide (штатным скриптом), не вручную")
    mark_executed(ctx, c, a.text, "decision")
    write_manifest(db, ctx.root, c)
    ctx.p("%s: исполнено (%s)" % (c["case_no"], a.text))


def cmd_withdraw(ctx, a):
    """Отозвать вынесенное, но НЕ исполненное решение (decision -> evidence); запись о нём остаётся в истории."""
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    if c["status"] != "decision":
        raise CaseError("%s в статусе %s; отозвать можно только неисполненное решение (decision)" % (c["case_no"], c["status"]))
    if db.one("SELECT 1 AS x FROM joylog1.san.case_block WHERE case_id = ? AND lifted_at IS NULL", (c["case_id"],)):
        raise CaseError("по делу действует блок - решение исполнено, отмена только через апелляцию")
    was = "ступень %s %s, срок %s, вынес %s %s: %s" % (c["ladder_step"], c["decision_kind"], c["block_hours"], c["decided_by"],
                                                       jval(c["decided_at"]), c["decision_text"])
    db.w("UPDATE joylog1.san.cases SET ladder_step = NULL, decision_kind = NULL, block_hours = NULL, decision_text = NULL, "
         "decided_by = NULL, decided_at = NULL, updated_at = SYSDATETIME() WHERE case_id = ?", (c["case_id"],))
    db.set_status(c["case_id"], "evidence", ctx.actor, "withdraw", ("решение отозвано (%s); было: %s" % (a.text, was))[:4000], "decision")
    write_manifest(db, ctx.root, c)
    ctx.p("%s: решение отозвано, дело снова на доказательствах" % c["case_no"])


def cmd_lift(ctx, a):
    """Снять блок дела штатным ac0_unblock_user.sql (OPBlockDel: BlockList -> BlockHistory, us_block = 0)."""
    db, cfg = ctx.db, ctx.cfg
    c = get_case(db, parse_case_id(a.case), lock=True)
    no = c["case_no"]
    act = db.rows("SELECT * FROM joylog1.san.case_block WHERE case_id = ? AND lifted_at IS NULL", (c["case_id"],))
    if not act:
        raise CaseError("%s: активных блоков по делу нет" % no)
    rows = db.rows("SELECT Reason, BlackDate, CloseDate FROM AsdaStoryOp.dbo.BlockList WHERE Userindex = ?", (c["user_index"],))
    foreign = [r for r in rows if not (r["Reason"] or "").startswith(no + " ")]
    if foreign and not a.all_blocks:
        for r in foreign:
            ctx.p("  чужой блок: %s .. %s «%s»" % (r["BlackDate"], r["CloseDate"], r["Reason"]))
        raise CaseError("у учётки есть блоки не этого дела; OPBlockDel снимет ВСЕ - подтвердите ключом --all-blocks")
    if not a.yes and (not sys.stdin.isatty() or input("Снять блок? Введите номер дела (%s): " % no).strip().upper() != no):
        raise CaseError("снятие не подтверждено (ключ --yes или ввод номера дела)")
    raw = open(cfg["unblock_script"], "rb").read()
    md5 = hashlib.md5(raw).hexdigest()
    db.run_script(render_unblock_script(raw.decode("utf-8-sig"), c["login"].rstrip()))
    u = db.one("SELECT us_block, (SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList b WHERE b.Userindex = m.Userindex) AS n "
               "FROM AsdaStoryOp.dbo.Us_member m WHERE Userindex = ?", (c["user_index"],))
    if u["us_block"] != 0 or u["n"] != 0:
        raise CaseError("после OPBlockDel us_block = %s, строк BlockList %s - откат транзакции" % (u["us_block"], u["n"]))
    via = "ac0_unblock_user.sql (OPBlockDel) md5 %s" % md5
    for b in act:
        h = db.one("SELECT COUNT(*) AS n FROM AsdaStoryOp.dbo.BlockHistory WHERE Userindex = ? AND Reason = ?", (c["user_index"], b["reason"]))
        db.w("UPDATE joylog1.san.case_block SET lifted_by = ?, lifted_at = SYSDATETIME(), lift_via = ?, lift_text = ?, in_history = ? "
             "WHERE block_id = ?", (ctx.actor, via, a.text, 1 if h["n"] else 0, b["block_id"]))
    ok, lines = login_readiness(db, c["user_index"])
    db.log(c["case_id"], ctx.actor, "lift", ("блок снят (%s); %s; %s; проверка входа по БД: %s" %
                                             (via, a.text or "", "сняты и чужие блоки: %d" % len(foreign) if foreign else "чужих блоков нет",
                                              " | ".join(lines)))[:4000])
    write_manifest(db, ctx.root, c)
    ctx.p("%s: блок снят; BlockList -> BlockHistory; us_block = 0" % no)
    for ln in lines:
        ctx.p("  " + ln)


def cmd_appeal(ctx, a):
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    no, cid = c["case_no"], c["case_id"]
    if a.resolve:
        if c["status"] != "appeal":
            raise CaseError("%s не на апелляции" % no)
        if (c["decided_by"] or "") == ctx.actor and not a.same_person:
            raise CaseError("апелляцию пересматривает другое лицо (решение выносил %s); иначе --same-person \"почему\"" % ctx.actor)
        prev = db.one("SELECT TOP 1 status_from FROM joylog1.san.case_log WHERE case_id = ? AND status_to = 'appeal' ORDER BY log_id DESC",
                      (cid,))["status_from"]
        note = a.text + (("; пересмотр тем же лицом: " + a.same_person) if a.same_person else "")
        db.w("UPDATE joylog1.san.cases SET appeal_result = ?, appeal_reviewed_by = ?, appeal_reviewed_at = SYSDATETIME(), "
             "updated_at = SYSDATETIME() WHERE case_id = ?", (a.resolve, ctx.actor, cid))
        if a.resolve == "upheld":
            db.set_status(cid, prev, ctx.actor, "appeal_resolve", ("апелляция отклонена, решение в силе: " + note)[:4000], "appeal")
        else:
            if db.one("SELECT 1 AS x FROM joylog1.san.case_block WHERE case_id = ? AND lifted_at IS NULL", (cid,)):
                raise CaseError("решение отменяется, но блок дела ещё действует - сначала lift %s" % no)
            db.w("UPDATE joylog1.san.cases SET outcome = 'overturned', closed_by = ?, closed_at = SYSDATETIME(), close_text = ? "
                 "WHERE case_id = ?", (ctx.actor, note, cid))
            db.set_status(cid, "closed", ctx.actor, "appeal_resolve",
                          ("решение отменено; возврат имущества (если был откат) - владельцем: " + note)[:4000], "appeal")
        ctx.p("%s: апелляция - %s" % (no, a.resolve))
    else:
        if c["status"] not in ("executed", "closed"):
            raise CaseError("%s в статусе %s; апелляция - на исполненное или закрытое решение" % (no, c["status"]))
        if c["outcome"] in ("acquitted", "no_action", "overturned"):
            raise CaseError("%s закрыто без санкции (%s) - обжаловать нечего" % (no, c["outcome"]))
        late = db.one("SELECT CASE WHEN appeal_until IS NOT NULL AND appeal_until < SYSDATETIME() THEN 1 ELSE 0 END AS late "
                      "FROM joylog1.san.cases WHERE case_id = ?", (cid,))["late"]
        if late and not a.late:
            raise CaseError("срок апелляции истёк %s; принять всё равно - --late \"почему\"" % c["appeal_until"])
        db.w("UPDATE joylog1.san.cases SET appeal_by = ?, appeal_at = SYSDATETIME(), appeal_text = ?, appeal_result = NULL, "
             "updated_at = SYSDATETIME() WHERE case_id = ?", (a.who or ctx.actor, a.text, cid))
        db.set_status(cid, "appeal", ctx.actor, "appeal", ("апелляция%s: %s%s" % (
            (" от " + a.who) if a.who else "", a.text, ("; принята после срока: " + a.late) if late else ""))[:4000], c["status"])
        ctx.p("%s: апелляция принята к рассмотрению; пересмотр - другим лицом: appeal %s --resolve upheld|overturned" % (no, no))
    write_manifest(db, ctx.root, c)


def verify_case(db, root, c, out):
    """Целостность одного дела: файлы (sha256/размер), лишние файлы, manifest, снимки событий, связь с BlockList."""
    fails, notes = [], []
    d = case_dir(root, c)
    ev = db.rows("SELECT rel_path, size_bytes, sha256 FROM joylog1.san.evidence WHERE case_id = ? ORDER BY evidence_id", (c["case_id"],))
    ok, ff, extra = verify_files(d, ev)
    fails += ["файл %s: %s" % x for x in ff]
    notes += ["лишний файл (нет в реестре): %s" % x for x in extra]
    mp = os.path.join(d, "manifest.json")
    if os.path.isfile(mp):
        with io.open(mp, encoding="utf-8") as f:
            man = json.load(f)
        mset = set((x["rel_path"], x["sha256"]) for x in man.get("files", []))
        if mset != set((r["rel_path"], r["sha256"]) for r in ev):
            notes.append("manifest.json расходится с реестром БД (перезапишется следующей записью)")
    elif ev:
        notes.append("нет manifest.json")
    n_live = n_gone = 0
    for e in db.rows("SELECT table_name, event_id, row_json, row_sha256 FROM joylog1.san.case_event WHERE case_id = ?", (c["case_id"],)):
        if sha256_bytes(e["row_json"].encode("utf-8")) != e["row_sha256"]:
            fails.append("снимок ac.%s #%d не совпал со своим sha256" % (e["table_name"], e["event_id"]))
            continue
        live = db.one("SELECT * FROM joylog1.ac.[%s] WHERE event_id = ?" % e["table_name"], (e["event_id"],))
        if not live:
            n_gone += 1
        elif sha256_bytes(canon_json(live).encode("utf-8")) != e["row_sha256"]:
            fails.append("строка журнала ac.%s #%d ИЗМЕНИЛАСЬ после привязки" % (e["table_name"], e["event_id"]))
        else:
            n_live += 1
    for b in db.rows("SELECT * FROM joylog1.san.case_block WHERE case_id = ?", (c["case_id"],)):
        if b["lifted_at"] is None:
            if not db.one("SELECT 1 AS x FROM AsdaStoryOp.dbo.BlockList WHERE Userindex = ? AND Reason = ?", (b["user_index"], b["reason"])):
                notes.append("блок «%s» не снят по делу, но строки BlockList нет (снят вне дела или истёк при входе)" % b["reason"])
        elif not db.one("SELECT 1 AS x FROM AsdaStoryOp.dbo.BlockHistory WHERE Userindex = ? AND Reason = ?", (b["user_index"], b["reason"])):
            fails.append("снятый блок «%s»: строки BlockHistory нет" % b["reason"])
    print("%s [%s]: файлов %d, проверено %d, ошибок %d; событий в журнале %d, очищено журналом %d (снимки целы)"
          % (c["case_no"], c["status"], len(ev), len(ok), len(fails), n_live, n_gone), file=out)
    for x in fails:
        print("  FAIL " + x, file=out)
    for x in notes:
        print("  ЗАМЕЧАНИЕ " + x, file=out)
    return not fails


def cmd_verify(ctx, a):
    db = ctx.db
    if a.case:
        cases = [get_case(db, parse_case_id(a.case))]
    else:
        cases = db.rows("SELECT * FROM joylog1.san.cases ORDER BY case_id")
    bad = [c["case_no"] for c in cases if not verify_case(db, ctx.root, c, ctx.out)]
    ctx.p("ИТОГ verify: дел %d, с ошибками %d%s" % (len(cases), len(bad), (": " + ", ".join(bad)) if bad else ""))
    return 1 if bad else 0


def cmd_close(ctx, a):
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    no, cid = c["case_no"], c["case_id"]
    if c["status"] == "closed":
        raise CaseError("%s уже закрыто" % no)
    if c["status"] == "appeal":
        raise CaseError("на апелляции - закрывается решением appeal --resolve")
    if a.outcome == "sanctioned" and c["status"] != "executed":
        raise CaseError("итог sanctioned - только после исполненного решения")
    if a.outcome in ("acquitted", "no_action") and c["status"] == "executed" and c["ladder_step"] and c["ladder_step"] > 0:
        raise CaseError("решение уже исполнено - его отмена только через апелляцию (overturned)")
    if a.outcome == "overturned":
        raise CaseError("overturned ставит только appeal --resolve")
    active = db.one("SELECT COUNT(*) AS n FROM joylog1.san.case_block WHERE case_id = ? AND lifted_at IS NULL", (cid,))["n"]
    if active and a.outcome != "sanctioned":
        raise CaseError("у дела действует блок - сначала lift")
    if not verify_case(db, ctx.root, c, ctx.out) and not a.force_unverified:
        raise CaseError("целостность доказательств нарушена - закрытие отклонено (--force-unverified \"почему\" - под запись)")
    text = a.text + (("; закрыто без проверки целостности: " + a.force_unverified) if a.force_unverified else "") + \
        ("; блок продолжает действовать до срока" if active else "")
    db.w("UPDATE joylog1.san.cases SET outcome = ?, closed_by = ?, closed_at = SYSDATETIME(), close_text = ?, updated_at = SYSDATETIME() "
         "WHERE case_id = ?", (a.outcome, ctx.actor, text, cid))
    db.set_status(cid, "closed", ctx.actor, "close", ("итог %s: %s" % (a.outcome, text))[:4000], c["status"])
    write_manifest(db, ctx.root, c)
    ctx.p("%s закрыто: %s. Хранить материалы не меньше %d дней." % (no, a.outcome, int(ctx.cfg["retention_days"])))


def render_case(db, root, c):
    """Текст дела (Markdown) - для show и case.md."""
    cid = c["case_id"]
    L = ["# %s — %s%s" % (c["case_no"], c["title"], " (УЧЕБНОЕ)" if c["is_training"] else ""), "",
         "| поле | значение |", "|---|---|"]
    for k in ("status", "user_index", "login", "char_name", "hypothesis", "opened_by", "opened_at", "ladder_step", "decision_kind",
              "block_hours", "decision_text", "decided_by", "decided_at", "executed_by", "executed_at", "execution_text",
              "appeal_until", "appeal_by", "appeal_at", "appeal_text", "appeal_result", "appeal_reviewed_by", "outcome",
              "closed_by", "closed_at", "close_text", "evidence_dir"):
        if c.get(k) is not None:
            L.append("| %s | %s |" % (k, str(jval(c[k])).replace("|", "/").replace("\n", " ")))
    L += ["", "Хранилище: `%s`" % norm(case_dir(root, c)), "", "## История", ""]
    for r in db.rows("SELECT at, actor, action, status_from, status_to, detail FROM joylog1.san.case_log WHERE case_id = ? ORDER BY log_id", (cid,)):
        L.append("- %s %s **%s** %s%s" % (str(r["at"])[:19], r["actor"], r["action"],
                                          ("%s→%s " % (r["status_from"] or "", r["status_to"])) if r["status_from"] != r["status_to"] else "",
                                          (r["detail"] or "").replace("\n", " ")))
    L += ["", "## События журнала", ""]
    for r in db.rows("SELECT table_name, event_id, ev_local, server_name, user_index, char_name, ip, summary, row_sha256 "
                     "FROM joylog1.san.case_event WHERE case_id = ? ORDER BY ev_local", (cid,)):
        L.append("- ac.%s #%d %s %s ui=%s %s %s — %s (sha256 %s…)" % (r["table_name"], r["event_id"], str(r["ev_local"])[:23],
                 r["server_name"] or "", r["user_index"], r["char_name"] or "", r["ip"] or "", r["summary"] or "", r["row_sha256"][:16]))
    L += ["", "## Доказательства", ""]
    for r in db.rows("SELECT kind, rel_path, size_bytes, sha256, source_label, source_path FROM joylog1.san.evidence WHERE case_id = ? "
                     "ORDER BY evidence_id", (cid,)):
        L.append("- %s `%s` %d б sha256 `%s` — источник «%s»%s" % (r["kind"], r["rel_path"], r["size_bytes"], r["sha256"], r["source_label"],
                                                                   (" (" + r["source_path"] + ")") if r["source_path"] else ""))
    L += ["", "## Блоки по делу", ""]
    for r in db.rows("SELECT * FROM joylog1.san.case_block WHERE case_id = ? ORDER BY block_id", (cid,)):
        L.append("- %s .. %s, %s ч, «%s»; наложил %s %s (%s); снят: %s %s (%s), в BlockHistory: %s" % (
            r["black_date"], r["close_date"], r["hours"], r["reason"], r["applied_by"], str(r["applied_at"])[:19], r["apply_via"],
            r["lifted_by"] or "—", str(r["lifted_at"] or "")[:19], r["lift_via"] or "—", r["in_history"]))
    now = db.rows("SELECT BlackDate, CloseDate, Reason FROM AsdaStoryOp.dbo.BlockList WHERE Userindex = ?", (c["user_index"],))
    L.append("")
    L.append("BlockList учётки сейчас: " + ("; ".join("%s..%s «%s»" % (r["BlackDate"], r["CloseDate"], r["Reason"]) for r in now) or "пусто"))
    return "\n".join(L) + "\n"


def cmd_show(ctx, a):
    c = get_case(ctx.db, parse_case_id(a.case))
    text = render_case(ctx.db, ctx.root, c)
    ctx.p(text)
    if a.md:
        p = os.path.join(case_dir(ctx.root, c), "case.md")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with io.open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        ctx.p("записано: " + norm(p))


def cmd_list(ctx, a):
    q, prm = "SELECT * FROM joylog1.san.v_cases WHERE 1 = 1", []
    if a.status:
        q += " AND status = ?"
        prm.append(a.status)
    if a.user:
        q += " AND login = ?"
        prm.append(a.user)
    rows = ctx.db.rows(q + " ORDER BY case_id", tuple(prm))
    ctx.p("дело     статус     учётка          ступень срок  событий файлов блоков(акт) BlockList итог        суть")
    for r in rows:
        ctx.p("%-8s %-10s %-15s %-7s %-5s %-7d %-6d %d(%d)%s %-9d %-11s %s%s" % (
            r["case_no"], r["status"], "%s(%s)" % (r["login"], r["user_index"]), "" if r["ladder_step"] is None else r["ladder_step"],
            "" if r["block_hours"] is None else r["block_hours"], r["n_events"], r["n_evidence"], r["n_blocks"], r["n_blocks_active"],
            "     ", r["blocklist_rows_now"], r["outcome"] or "", r["title"][:60], " [учебное]" if r["is_training"] else ""))
    ctx.p("дел: %d" % len(rows))


def read_stand_ini(cfg):
    """patches.ini всех GameServer стойки (stack_layout.GS_FOLDERS, 26.10: + Ch2_GameServer) с шары (только чтение)."""
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Server", "Patches", "AsdaPatch", "tools")))
    import stack_layout
    res = {}
    for srv in stack_layout.GS_FOLDERS:
        p = "%s/%s/ConfigSet/patches.ini" % (cfg["share_root"].rstrip("/"), srv)
        try:
            with open(p, "rb") as f:
                res[srv] = parse_ini_bytes(f.read())
        except OSError as e:
            res[srv] = {}
            print("  нет доступа к %s: %s" % (p, e))
    return res


def cmd_ladder(ctx, a):
    lad = ladder_map(ctx.cfg)
    ctx.p("Лестница санкций (ac_case_config.json):")
    for st in sorted(lad):
        x = lad[st]
        ctx.p("  %d %-12s %-26s срок %-5s исполнение %-7s %s" % (st, x["code"], x["name"], "" if x["hours"] is None else x["hours"],
                                                              x["exec"], x["mechanism"]))
    ctx.p("Апелляция: %s дн.; хранение материалов: >= %s дн.; два независимых источника - со ступени %s"
          % (ctx.cfg["appeal_days"], ctx.cfg["retention_days"], ctx.cfg["two_sources_from_step"]))
    if a.check:
        bad = 0
        for srv, st, key, v, h, ok in ladder_check(ctx.cfg, read_stand_ini(ctx.cfg)):
            bad += 0 if ok else 1
            ctx.p("  %-16s ступень %d  %-36s ini=%-5s лестница=%-5s %s" % (srv, st, key, v, h, "OK" if ok else "РАСХОЖДЕНИЕ"))
        ctx.p("ИТОГ ladder --check: расхождений %d" % bad)
        return 1 if bad else 0
    return 0


def serial_tables(db):
    """Таблицы JoyLog1 со столбцами Serial, Userindex, Edate (журнал движения предметов): [(имя, есть Charidx, есть Code)]."""
    return [(r["name"], r["ch"], r["cd"]) for r in db.rows(
        "SELECT t.name, CASE WHEN EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'Charidx') "
        "THEN 1 ELSE 0 END AS ch, CASE WHEN EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'Code') "
        "THEN 1 ELSE 0 END AS cd FROM joylog1.sys.tables t WHERE t.schema_id = SCHEMA_ID('dbo') "
        "AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'Serial') "
        "AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'Userindex') "
        "AND EXISTS (SELECT 1 FROM joylog1.sys.columns c WHERE c.object_id = t.object_id AND c.name = 'Edate') ORDER BY t.name")]


def cmd_rollback_report(ctx, a):
    """Отчёт «что откатить по Serial» - ТОЛЬКО ЧТЕНИЕ игровых таблиц; запись - владельцем, на копии базы, вне инструмента."""
    db = ctx.db
    c = get_case(db, parse_case_id(a.case), lock=True)
    if c["status"] == "closed":
        raise CaseError("%s закрыто - материалы не дополняются (сначала апелляция)" % c["case_no"])
    tabs = serial_tables(db)
    union = " UNION ALL ".join("SELECT '%s' AS tbl, Edate, Userindex, %s AS Charidx, %s AS Code, Serial FROM joylog1.dbo.[%s]"
                               % (t, "Charidx" if ch else "NULL", "Code" if cd else "NULL", t) for t, ch, cd in tabs)
    serials = [s.strip().upper() for s in (a.serial or [])]
    for s in serials:
        try:
            uuid.UUID(s)
        except ValueError:
            raise CaseError("Serial - GUID (как Joy1.Item.Uuid): %r" % s)
    if a.window:
        t0, t1 = [dt.datetime.fromisoformat(x) for x in a.window]
        got = db.rows("SELECT DISTINCT TOP (?) UPPER(Serial) AS s FROM (%s) x WHERE Userindex = ? AND Edate >= ? AND Edate < ? "
                      "AND Serial IS NOT NULL AND Serial <> ''" % union, (a.max, c["user_index"], t0, t1))
        serials += [r["s"] for r in got if r["s"] not in serials]
    if not serials:
        raise CaseError("нет серийников (--serial GUID ... или --window FROM TO)")
    report = {"case_no": c["case_no"], "generated_at": dt.datetime.now().isoformat(timespec="seconds"), "generated_by": ctx.actor,
              "warning": "ОТЧЁТ, НЕ ДЕЙСТВИЕ. Инструмент не пишет в игровые таблицы. Откат - владельцем, сначала на копии базы, "
                         "с бэкапом и проверкой; затем ac_case.py execute.", "case_user_index": c["user_index"], "serials": []}
    md = ["# Откат по Serial — %s (отчёт, без записи)" % c["case_no"], "", "> " + report["warning"], "",
          "Учётка дела: %s (%s). Таблиц журнала JoyLog1 с Serial: %d." % (c["user_index"], c["login"], len(tabs)), ""]
    for s in serials:
        trail = db.rows("SELECT tbl, Edate, Userindex, Charidx, Code FROM (%s) x WHERE Serial = ? ORDER BY Edate" % union, (s,))
        items = db.rows("SELECT Userindex, Charidx, Code, Plate, Posx, Amount, Durability, Upcount, Refine, GainDate "
                        "FROM Joy1.dbo.Item WHERE Uuid = ?", (s,))
        dels = db.rows("SELECT Edate, Userindex, Charidx, Code, Amount FROM Joy1.dbo.Del_item WHERE Uuid = ?", (s,))
        holders = sorted(set(r["Userindex"] for r in items))
        if not items:
            prop = "предмета нет в Joy1.Item (удалён/продан/израсходован): откатывать нечего; см. цепочку и Del_item"
        elif holders == [c["user_index"]] and len(items) == 1:
            prop = "у учётки дела: удалить строку Item Uuid=%s (или вернуть прежнему владельцу по цепочке)" % s
        elif len(items) > 1:
            prop = "ДУБЛЬ Uuid (%d строк, учётки %s): оставить одну исходную, остальные удалить" % (len(items), holders)
        else:
            prop = "предмет у другой учётки %s: решить по цепочке передач (не у нарушителя)" % holders
        report["serials"].append({"serial": s, "item_now": [{k: jval(v) for k, v in r.items()} for r in items],
                                  "del_item": [{k: jval(v) for k, v in r.items()} for r in dels],
                                  "trail": [{k: jval(v) for k, v in r.items()} for r in trail], "proposal": prop})
        md += ["## Serial %s" % s, "", "**Предложение:** " + prop, "", "Сейчас в Joy1.Item: " +
               ("; ".join("ui %s/ch %s код %s кол-во %s plate %s pos %s" % (r["Userindex"], r["Charidx"], r["Code"], r["Amount"],
                                                                          r["Plate"], r["Posx"]) for r in items) or "нет"),
               "", "Del_item: " + ("; ".join("%s ui %s код %s" % (r["Edate"], r["Userindex"], r["Code"]) for r in dels) or "нет"), "",
               "| время | журнал | учётка | перс. | код |", "|---|---|---|---|---|"]
        md += ["| %s | %s | %s | %s | %s |" % (str(r["Edate"])[:19], r["tbl"], r["Userindex"], r["Charidx"], r["Code"]) for r in trail]
        md += ["", "Шаблон для КОПИИ базы (не выполняется инструментом):", "", "```sql",
               "-- USE <копия Joy1>;  BEGIN TRAN;  -- бэкап строки: SELECT * INTO Item_bak_%s FROM dbo.Item WHERE Uuid = '%s'"
               % (c["case_no"].replace("-", "_"), s),
               "-- DELETE FROM dbo.Item WHERE Uuid = '%s' AND Userindex = <учётка>;  -- проверить @@ROWCOUNT, затем COMMIT" % s, "```", ""]
    d = os.path.join(case_dir(ctx.root, c), "reports")
    os.makedirs(d, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    pj, pm = os.path.join(d, "rollback_%s.json" % stamp), os.path.join(d, "rollback_%s.md" % stamp)
    with io.open(pj, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    with io.open(pm, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(md))
    for p in (pj, pm):
        register_generated(ctx, c, p, "report", "report: откат по Serial", "серийников %d" % len(serials))
    db.log(c["case_id"], ctx.actor, "report", "отчёт отката по Serial: %d серийников, %s" % (len(serials), os.path.basename(pm)))
    write_manifest(db, ctx.root, c)
    ctx.p("%s: отчёт отката (без записи) по %d серийникам -> %s" % (c["case_no"], len(serials), norm(pm)))


# ════════════════════════════════════════════ самопроверка ════════════════════════════════════════════

def selftest_offline(out):
    """Проверки без БД и шары. -> (ok, fail)."""
    res = []

    def chk(cond, what):
        res.append((bool(cond), what))

    tmp = tempfile.mkdtemp(prefix="ac_case_selftest_")
    try:
        # 1. канонический JSON и sha256
        a = canon_json({"b": 1, "a": dt.datetime(2026, 10, 12, 20, 45, 20, 442000), "c": "тест", "u": uuid.UUID(int=1)})
        chk(a == '{"a":"2026-10-12T20:45:20.442000","b":1,"c":"тест","u":"00000000-0000-0000-0000-000000000001"}', "канонический JSON")
        chk(sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 эталон")
        # 2. выдержка: отбор, маска MD5, cp1251
        src = os.path.join(tmp, "OTP_Report_20261012.txt")
        with open(src, "wb") as f:
            f.write("Login User ID sitx/x, Pass 0123456789abcdef0123456789ABCDEF/1, IP 1\r\n".encode("utf-8"))
            f.write("другое\r\n".encode("cp1251"))
            f.write("SpeedHack GM_sitxovski Count 1\r\n".encode("utf-8"))
        dst = os.path.join(tmp, "ex.txt")
        n = make_excerpt(src, dst, r"sitx", ["шапка"])
        body = io.open(dst, encoding="utf-8").read()
        chk(n == 2 and "<md5 скрыт>" in body and "0123456789abcdef" not in body, "выдержка: 2 строки, MD5 замаскирован")
        chk(make_excerpt(src, dst, r"другое", []) == 1, "выдержка: строка cp1251 читается")
        # 3. хранилище: шара стойки запрещена, папка Perforce - предупреждение
        try:
            check_store_root("//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/cases")
            chk(False, "хранилище на шаре стойки отклоняется")
        except CaseError:
            chk(True, "хранилище на шаре стойки отклоняется")
        chk(check_store_root("@@ASTORY_DEV_ROOT_FWD@@/x") and not check_store_root("D:/AsdaCases"), "хранилище в @@ASTORY_DEV_ROOT_FWD@@ - предупреждение")
        # 4. проверка файлов: совпадение, порча, лишний файл
        cd = os.path.join(tmp, "AC-0001")
        os.makedirs(os.path.join(cd, "files"))
        p = os.path.join(cd, "files", "001_a.txt")
        with open(p, "wb") as f:
            f.write(b"evidence")
        h, sz = sha256_file(p)
        rows = [{"rel_path": "files/001_a.txt", "size_bytes": sz, "sha256": h}]
        ok, fail, extra = verify_files(cd, rows)
        chk(ok == ["files/001_a.txt"] and not fail and not extra, "verify: файл цел")
        with open(p, "wb") as f:
            f.write(b"evidencE")
        ok, fail, extra = verify_files(cd, rows)
        chk(fail and "sha256" in fail[0][1], "verify: подмена байта найдена")
        with open(os.path.join(cd, "files", "002_x.txt"), "wb") as f:
            f.write(b"x")
        os.remove(p)
        ok, fail, extra = verify_files(cd, rows)
        chk(fail and fail[0][1] == "файла нет" and extra == ["files/002_x.txt"], "verify: пропажа и лишний файл найдены")
        # 5. штатные скрипты: подстановка ровно по одному разу, отказ на опасный ввод
        cfg = load_config()
        bt = open(cfg["block_script"], "rb").read().decode("utf-8-sig")
        r = render_block_script(bt, "sitxovski", 1, "AC-0001 s3 1h")
        chk("@Uid    VARCHAR(61)  = 'sitxovski'" in r and re.search(r"@Hours\s+INT\s+=\s+1\b", r) and "'AC-0001 s3 1h'" in r,
            "ac0_block_user.sql: логин, часы, причина подставлены")
        chk(len(split_batches(r)) == 2, "ac0_block_user.sql: 2 пакета (USE, работа)")
        for bad in (("sit'x", 1, "AC-0001 x"), ("sitx", 0, "AC-0001 x"), ("sitx", 1, "AC-0001 x'; DROP"), ("sitx", 1, "кириллица")):
            try:
                render_block_script(bt, *bad)
                chk(False, "отказ на %r" % (bad,))
            except CaseError:
                chk(True, "отказ на %r" % (bad,))
        ut = open(cfg["unblock_script"], "rb").read().decode("utf-8-sig")
        chk("@Uid VARCHAR(61) = 'Rimy'" in render_unblock_script(ut, "Rimy"), "ac0_unblock_user.sql: логин подставлен")
        chk(ascii_reason("AC-0001 s3 24h: тест 'x'") == "AC-0001 s3 24h: x", "причина блока: только латиница")
        # 6. защита записи: только san.*
        for sql, good in (("INSERT INTO joylog1.san.cases (a) VALUES (1)", True), ("EXEC joylog1.san.UP_SAN_CaseOpen 1", True),
                          ("UPDATE AsdaStoryOp.dbo.Us_member SET us_block = 0", False), ("DELETE FROM Joy1.dbo.Item", False),
                          ("INSERT INTO joylog1.san.x VALUES ('UPDATE Joy1.dbo.Item')", True), ("DROP TABLE san.cases", False)):
            try:
                assert_san_write(sql)
                chk(good, "запись: %s" % sql[:40])
            except ValueError:
                chk(not good, "запись: %s" % sql[:40])
        # 7. переходы статуса = процедуре SQL
        mig = io.open(MIGRATE_SQL, encoding="utf-8").read()
        body = mig[mig.index("ALTER PROCEDURE san.UP_SAN_SetStatus"):]
        body = body[:body.index("RAISERROR(N'UP_SAN_SetStatus: переход")]
        sql_set = set(tuple(x.split(">")) for x in re.findall(r"'(\w+>\w+)'", body))
        chk(sql_set == ALLOWED, "переходы статуса совпадают с san.UP_SAN_SetStatus (%d)" % len(sql_set))
        # 8. лестница и ini стойки
        lad = ladder_map(cfg)
        chk(lad[3]["hours"] == 24 and lad[4]["hours"] == 720 and lad[5]["hours"] == -1, "лестница: 24 / 720 / -1")
        ini = ("[P48_KickAutoBlock]\r\nBlockHours=24 ; c\r\n[P69_IntegrityAutoBlock]\r\nStage1Hours=24\r\nStage2Hours=720\r\n"
               "Stage3Hours=-1\r\n").encode("utf-16")
        chk(all(x[5] for x in ladder_check(cfg, {"GS": parse_ini_bytes(ini)})), "сверка с ini (UTF-16): совпадает")
        ini2 = ini.decode("utf-16").replace("Stage2Hours=720", "Stage2Hours=168").encode("utf-16")
        chk([x[2] for x in ladder_check(cfg, {"GS": parse_ini_bytes(ini2)}) if not x[5]] == ["P69_IntegrityAutoBlock.Stage2Hours"],
            "сверка с ini: расхождение найдено")
        chk(parse_case_id("AC-0001") == 1 and parse_case_id("17") == 17, "номер дела AC-NNNN")
        # 9. два независимых источника — по сути, не по метке (ревизия 59 Н-4)
        class _Fdb(object):
            def __init__(self, ev, files):
                self.ev, self.files = ev, files

            def rows(self, sql, params=()):
                return self.ev if "case_event" in sql else self.files
        f1 = {"source_label": "GS SpeedHack", "kind": "excerpt", "source_path": r"v2:GameServer\Log\Log_SpeedHack\SpeedHack_20261012.txt",
              "source_sha256": "a" * 64, "sha256": "b" * 64}
        f2 = dict(f1, source_label="NpcServer SpeedHack", sha256="c" * 64)
        f3 = dict(f1, source_path=r"v2:NpcServer\Error_Log\SpeedHack_20261012.txt", source_sha256="d" * 64, sha256="e" * 64)
        f4 = dict(f3, source_label="GS SpeedHack", source_path=r"v2:Ch2_GameServer\x.txt", source_sha256="f" * 64)
        ev = [{"table_name": "move_combat"}]
        chk(case_sources(_Fdb(ev, [f1, f2]), 1) == ["ac.move_combat", "файл: GS SpeedHack"], "два источника: одна выдержка с другой меткой — тот же источник")
        chk(len(case_sources(_Fdb([], [f1, f3]), 1)) == 2 and len(case_sources(_Fdb([], [f1, dict(f1, source_path="V2:gameserver/log/log_speedhack/speedhack_20261012.txt")]), 1)) == 1,
            "два источника: разные журналы — два, тот же путь (регистр, слэши) — один")
        chk(case_sources(_Fdb([], [f1, f4]), 1) == ["файл: GS SpeedHack", "файл: GS SpeedHack (x.txt)"]
            and len(case_sources(_Fdb([], [dict(f1, kind="export"), dict(f3, kind="report")]), 1)) == 0,
            "два источника: одинаковая метка у разных файлов — два (с именем), выгрузки и отчёты — не источники")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for okk, what in res:
        print("  %s %s" % ("OK  " if okk else "FAIL", what), file=out)
    return sum(1 for x in res if x[0]), sum(1 for x in res if not x[0])


def selftest_db(cfg, login, out):
    """Полный цикл дела на dev-БД в ОДНОЙ транзакции с откатом в конце (следов в БД не остаётся; хранилище - временная папка).
    Блок учётки накладывается и снимается штатными скриптами внутри этой транзакции - после отката us_block прежний."""
    res = []

    def chk(cond, what):
        res.append((bool(cond), what))
        print("  %s %s" % ("OK  " if cond else "FAIL", what), file=out)

    db = Db.open()
    tmp = tempfile.mkdtemp(prefix="ac_case_dbtest_")
    sink = io.StringIO()
    try:
        before = db.one("SELECT (SELECT COUNT(*) FROM joylog1.san.cases) c, (SELECT COUNT(*) FROM joylog1.san.case_log) l, "
                        "(SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList) bl, (SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockHistory) bh, "
                        "(SELECT us_block FROM AsdaStoryOp.dbo.Us_member WHERE us_id = ?) ub", (login,))
        if before["bl"] and db.one("SELECT 1 AS x FROM AsdaStoryOp.dbo.BlockList b JOIN AsdaStoryOp.dbo.Us_member m ON m.Userindex = b.Userindex "
                                   "WHERE m.us_id = ?", (login,)):
            raise CaseError("у %s есть строки BlockList - самопроверка с блоком не запускается" % login)
        A = lambda **kw: argparse.Namespace(**kw)  # noqa: E731
        k1 = Ctx(cfg, db, tmp, "selftest-1", sink)
        k2 = Ctx(cfg, db, tmp, "selftest-2", sink)
        c = cmd_open(k1, A(user=login, ui=None, char=None, title="selftest", hypothesis=None, training=True))
        chk(c["status"] == "open" and os.path.isdir(case_dir(tmp, c)), "open: дело и папка")
        try:
            cmd_decide(k1, A(case=c["case_no"], step=3, hours=1, text="t", yes=True, reason_en=None, override_two_sources=None))
            chk(False, "decide без доказательств отклонён")
        except CaseError:
            chk(True, "decide без доказательств отклонён")
        ev = db.rows("SELECT TOP 2 table_name, event_id FROM joylog1.ac.v_events WHERE summary NOT LIKE N'журнал:%' ORDER BY ev_local DESC")
        cmd_attach(k1, A(case=c["case_no"], event=["%s:%d" % (r["table_name"], r["event_id"]) for r in ev[:1]], events_auto=None,
                         file=None, source=None, excerpt=None, note=None))
        chk(get_case(db, c["case_id"])["status"] == "evidence", "attach события: статус evidence")
        try:
            cmd_decide(k1, A(case=c["case_no"], step=3, hours=1, text="t", yes=True, reason_en=None, override_two_sources=None))
            chk(len(case_sources(db, c["case_id"])) >= 2, "decide с одним источником отклонён")
        except CaseError:
            chk(True, "decide с одним источником отклонён")
        fsrc = os.path.join(tmp, "src_log.txt")
        with open(fsrc, "wb") as f:
            f.write(b"line sitx 1\nline other\n")
        cmd_attach(k1, A(case=c["case_no"], event=None, events_auto=None, file=fsrc, source="selftest file", excerpt="sitx", note=None))
        cmd_export(k1, A(case=c["case_no"], format="json,csv"))
        it0 = db.one("SELECT COUNT(*) AS n, CHECKSUM_AGG(BINARY_CHECKSUM(*)) AS h FROM Joy1.dbo.Item WHERE Userindex = ?", (c["user_index"],))
        cmd_rollback_report(k1, A(case=c["case_no"], serial=None, window=["2026-07-01T00:00:00", "2026-10-15T00:00:00"], max=5))
        it1 = db.one("SELECT COUNT(*) AS n, CHECKSUM_AGG(BINARY_CHECKSUM(*)) AS h FROM Joy1.dbo.Item WHERE Userindex = ?", (c["user_index"],))
        rep = db.rows("SELECT rel_path FROM joylog1.san.evidence WHERE case_id = ? AND kind = 'report'", (c["case_id"],))
        chk(len(rep) == 2 and dict(it0) == dict(it1), "rollback-report: отчёт .md/.json в реестре, Joy1.Item не изменён")
        try:
            cmd_rollback_report(k1, A(case=c["case_no"], serial=["not-a-guid"], window=None, max=5))
            chk(False, "rollback-report: негодный Serial отклонён")
        except CaseError:
            chk(True, "rollback-report: негодный Serial отклонён")
        chk(db.one("SELECT COUNT(*) AS n FROM joylog1.san.evidence WHERE case_id = ? AND kind IN ('excerpt', 'export')",
                   (c["case_id"],))["n"] == 3, "файл + выгрузка JSON/CSV в реестре")
        cmd_decide(k1, A(case=c["case_no"], step=1, hours=None, text="warn", yes=False, reason_en=None, override_two_sources=None))
        chk(get_case(db, c["case_id"])["status"] == "decision", "decide ступень 1 (ручное исполнение): статус decision")
        cmd_withdraw(k1, A(case=c["case_no"], text="selftest"))
        cw = get_case(db, c["case_id"])
        chk(cw["status"] == "evidence" and cw["ladder_step"] is None, "withdraw: решение отозвано, снова evidence")
        cmd_decide(k1, A(case=c["case_no"], step=3, hours=1, text="selftest", yes=True, reason_en="selftest", override_two_sources=None))
        c2 = get_case(db, c["case_id"])
        bl = db.one("SELECT us_block, (SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList b WHERE b.Userindex = m.Userindex AND b.Reason LIKE ?) n "
                    "FROM AsdaStoryOp.dbo.Us_member m WHERE Userindex = ?", (c["case_no"] + " %", c["user_index"]))
        chk(c2["status"] == "executed" and bl["us_block"] == 5 and bl["n"] == 1, "decide блок 1 ч: us_block 5, строка BlockList, executed")
        chk(not login_readiness(db, c["user_index"])[0], "вход по БД невозможен во время блока")
        cmd_appeal(k1, A(case=c["case_no"], text="не я", who="player", late=None, resolve=None, same_person=None))
        try:
            cmd_appeal(k1, A(case=c["case_no"], text="x", who=None, late=None, resolve="upheld", same_person=None))
            chk(False, "пересмотр тем же лицом отклонён")
        except CaseError:
            chk(True, "пересмотр тем же лицом отклонён")
        cmd_appeal(k2, A(case=c["case_no"], text="доказательства в силе", who=None, late=None, resolve="upheld", same_person=None))
        chk(get_case(db, c["case_id"])["status"] == "executed", "апелляция отклонена другим лицом: снова executed")
        try:
            cmd_close(k1, A(case=c["case_no"], outcome="acquitted", text="x", force_unverified=None))
            chk(False, "закрытие «оправдан» при исполненном блоке отклонено")
        except CaseError:
            chk(True, "закрытие «оправдан» при исполненном блоке отклонено")
        cmd_lift(k1, A(case=c["case_no"], text="selftest", all_blocks=False, yes=True))
        okr, _ = login_readiness(db, c["user_index"])
        h = db.one("SELECT in_history FROM joylog1.san.case_block WHERE case_id = ?", (c["case_id"],))
        chk(okr and h["in_history"] == 1, "lift: us_block 0, BlockList пуст, строка в BlockHistory, вход по БД возможен")
        cmd_close(k1, A(case=c["case_no"], outcome="sanctioned", text="selftest", force_unverified=None))
        chk(get_case(db, c["case_id"])["status"] == "closed", "close: closed")
        chk(verify_case(db, tmp, get_case(db, c["case_id"]), sink), "verify: целостность")
        p = os.path.join(case_dir(tmp, c), "files")
        f1 = [x for x in os.listdir(p)][0]
        with open(os.path.join(p, f1), "ab") as f:
            f.write(b"!")
        chk(not verify_case(db, tmp, get_case(db, c["case_id"]), sink), "verify: порча файла найдена")
        try:
            db.w("DELETE FROM joylog1.san.case_log WHERE case_id = ?", (c["case_id"],))
            chk(False, "удаление истории отклонено")
        except Exception:
            chk(True, "удаление истории отклонено")
    finally:
        db.rollback()
        after = db.one("SELECT (SELECT COUNT(*) FROM joylog1.san.cases) c, (SELECT COUNT(*) FROM joylog1.san.case_log) l, "
                       "(SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockList) bl, (SELECT COUNT(*) FROM AsdaStoryOp.dbo.BlockHistory) bh, "
                       "(SELECT us_block FROM AsdaStoryOp.dbo.Us_member WHERE us_id = ?) ub", (login,))
        db.rollback()
        shutil.rmtree(tmp, ignore_errors=True)
    chk(dict(before) == dict(after), "после ROLLBACK san.*, BlockList, BlockHistory, us_block прежние")
    return sum(1 for x in res if x[0]), sum(1 for x in res if not x[0])


def cmd_selftest(ctx_cfg, a, out):
    print("самопроверка без БД:", file=out)
    ok, fail = selftest_offline(out)
    if a.db:
        print("самопроверка на dev-БД (одна транзакция, ROLLBACK; учётка %s):" % a.login, file=out)
        o2, f2 = selftest_db(ctx_cfg, a.login, out)
        ok, fail = ok + o2, fail + f2
    print("ИТОГ selftest: OK %d / FAIL %d" % (ok, fail), file=out)
    return 1 if fail else 0


# ════════════════════════════════════════════ CLI ════════════════════════════════════════════

def build_parser():
    ap = argparse.ArgumentParser(prog="ac_case.py", description="Журнал дел античита (В6): дела AC-NNNN, доказательства, санкции.")
    ap.add_argument("--config", default=CONFIG_PATH, help="конфиг (по умолчанию ac_case_config.json рядом)")
    ap.add_argument("--store", help="корень хранилища доказательств (иначе ASDA_CASES_DIR или evidence_root)")
    ap.add_argument("--by", help="кто действует (по умолчанию USERNAME)")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("open", help="открыть дело")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--user", help="логин (us_id)")
    g.add_argument("--ui", type=int, help="Userindex")
    p.add_argument("--char", help="персонаж (Charname)")
    p.add_argument("--title", required=True, help="суть дела одной строкой")
    p.add_argument("--hypothesis", help="гипотеза / флаги отчёта")
    p.add_argument("--training", action="store_true", help="учебное дело")

    p = sp.add_parser("attach", help="приложить события журнала ac.* и/или файл")
    p.add_argument("case")
    p.add_argument("--event", action="append", help="ТАБЛИЦА:event_id (повторяемый), напр. move_combat:7158")
    p.add_argument("--events-auto", nargs=2, metavar=("FROM", "TO"), help="все события окна по учётке/персонажам дела (ISO-время)")
    p.add_argument("--file", help="файл-доказательство (источник открывается только на чтение)")
    p.add_argument("--source", help="метка независимого источника файла, напр. «NpcServer SpeedHack»")
    p.add_argument("--excerpt", help="регулярка: сохранить только совпавшие строки (32-hex маскируются)")
    p.add_argument("--note")

    p = sp.add_parser("export", help="выгрузить события дела в файл(ы) хранилища с sha256")
    p.add_argument("case")
    p.add_argument("--format", default="json,csv")

    p = sp.add_parser("show", help="показать дело")
    p.add_argument("case")
    p.add_argument("--md", action="store_true", help="записать case.md в папку дела")

    p = sp.add_parser("decide", help="вынести решение по лестнице (блок - штатным скриптом сразу)")
    p.add_argument("case")
    p.add_argument("--step", type=int, required=True, help="ступень 0..6 (ladder)")
    p.add_argument("--hours", type=int, help="срок блока для ступеней 3-4, если не по лестнице")
    p.add_argument("--text", required=True, help="на основании чего")
    p.add_argument("--reason-en", help="латиницей в BlockList.Reason (после номера дела)")
    p.add_argument("--override-two-sources", help="снять правило двух источников (под запись в дело)")
    p.add_argument("--yes", action="store_true", help="подтвердить блок без вопроса")

    p = sp.add_parser("execute", help="отметить ручное исполнение (предупреждение, кик, откат владельцем)")
    p.add_argument("case")
    p.add_argument("--text", required=True)

    p = sp.add_parser("withdraw", help="отозвать неисполненное решение (decision -> evidence)")
    p.add_argument("case")
    p.add_argument("--text", required=True, help="почему")

    p = sp.add_parser("lift", help="снять блок дела (ac0_unblock_user.sql / OPBlockDel)")
    p.add_argument("case")
    p.add_argument("--text", default="")
    p.add_argument("--all-blocks", action="store_true", help="разрешить снять и блоки не этого дела (OPBlockDel снимает все)")
    p.add_argument("--yes", action="store_true")

    p = sp.add_parser("appeal", help="подать апелляцию или вынести по ней решение (--resolve)")
    p.add_argument("case")
    p.add_argument("--text", required=True)
    p.add_argument("--who", help="кто подаёт (игрок)")
    p.add_argument("--late", help="принять после срока (почему)")
    p.add_argument("--resolve", choices=("upheld", "overturned"))
    p.add_argument("--same-person", help="пересмотр тем же лицом, что выносил решение (почему)")

    p = sp.add_parser("close", help="закрыть дело")
    p.add_argument("case")
    p.add_argument("--outcome", required=True, choices=OUTCOMES)
    p.add_argument("--text", required=True)
    p.add_argument("--force-unverified", help="закрыть при нарушенной целостности (почему)")

    p = sp.add_parser("verify", help="проверка целостности хранилища и связей (все дела или одно)")
    p.add_argument("case", nargs="?")

    p = sp.add_parser("list", help="список дел")
    p.add_argument("--status")
    p.add_argument("--user")

    p = sp.add_parser("ladder", help="лестница санкций; --check - сверка с ini стойки (P48/P69)")
    p.add_argument("--check", action="store_true")

    p = sp.add_parser("rollback-report", help="отчёт «что откатить по Serial» (без записи в игровые таблицы)")
    p.add_argument("case")
    p.add_argument("--serial", action="append", help="GUID серийника (повторяемый)")
    p.add_argument("--window", nargs=2, metavar=("FROM", "TO"), help="все серийники учётки дела за окно")
    p.add_argument("--max", type=int, default=200)

    p = sp.add_parser("selftest", help="самопроверка (без БД; --db - полный цикл на dev-БД с откатом)")
    p.add_argument("--db", action="store_true")
    p.add_argument("--login", default="sitxovski")
    return ap


READ_ONLY = ("show", "list", "verify", "ladder")
COMMANDS = {"open": cmd_open, "attach": cmd_attach, "export": cmd_export, "show": cmd_show, "decide": cmd_decide,
            "execute": cmd_execute, "withdraw": cmd_withdraw, "lift": cmd_lift, "appeal": cmd_appeal, "close": cmd_close, "verify": cmd_verify,
            "list": cmd_list, "ladder": cmd_ladder, "rollback-report": cmd_rollback_report}


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    a = build_parser().parse_args(argv)
    cfg = load_config(a.config)
    if a.cmd == "selftest":
        return cmd_selftest(cfg, a, sys.stdout)
    actor = (a.by or os.environ.get("USERNAME") or "unknown")[:64]
    root = store_root(cfg, a.store)
    if a.cmd == "ladder":
        return cmd_ladder(Ctx(cfg, None, root, actor), a) or 0
    db = Db.open()
    ctx = Ctx(cfg, db, root, actor)
    try:
        rc = COMMANDS[a.cmd](ctx, a)
        rc = rc if isinstance(rc, int) else 0       # open возвращает дело (для самопроверки), код - 0
        if a.cmd in READ_ONLY:
            db.rollback()
        else:
            db.commit()
        return rc
    except CaseError as e:
        db.rollback()
        ctx.cleanup()
        print("ОТКАЗ: %s (ничего не записано)" % e, file=sys.stderr)
        return 2
    except Exception:
        db.rollback()
        ctx.cleanup()
        print("ОШИБКА - транзакция откатана, в БД ничего не записано", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
