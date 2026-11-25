# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""
fake_sidecar.py — ФАЛЬШИВЫЙ САЙДКАР моста P73 (сторона AsdaEacServer, TCP 127.0.0.1:PORT) для стенда P73 (2026-10-16, Э1-В).

Протокол — контракт `Reports/anticheat/eac/CONTRACT.md` §4 (кадр: u16 len (type+payload) · u8 type · payload, little-endian):
    0x10 HELLO  P73→С  u8 ver=2 · u8 serverKind (2 Game, 3 Indun) · u32 pid · u16 gamePort        (ред. 3: ver 2)
    0x11 LOGIN  P73→С  u16 userNum · u32 userIndex · u32 ipv4 (сетевой порядок) · u32 seq · u8[32] bind   (ред. 3: + bind)
    0x12 LOGOUT P73→С  u16 userNum · u32 userIndex · u32 seq
    0x13 REBIND P73→С  u16 userNum · u32 oldUserIndex · u32 sessionUserIndex · u32 seq · u8[32] bind  (ред. 2; ред. 3: + bind)
    0x14 PING   P73→С  пусто
    0x21 KICK   С→P73  u16 userNum · u32 userIndex · u8 ourReason · u8 eosReason
    0x24 PONG   С→P73  пусто
Секретов нет: мост без шифрования, слушает ТОЛЬКО 127.0.0.1.

Режимы:
    python fake_sidecar.py --selftest
        юнит-проверка кодека кадров (сборка/разбор, кадры порциями по 1..N байт, границы len 0/4096/4097).
    python fake_sidecar.py --port 15799 --scenario std --status status.json
        сценарий для stand_p73.exe (режим tcp): принимает соединения P73, сверяет кадры, шлёт KICK / порченый кадр,
        закрывает соединение и ждёт переподключения. Ход пишется в status.json (stand читает фазу), итог — [OK]/[!!] и код выхода.
    python fake_sidecar.py --port 15702 --serve
        простой сайдкар для ручной проверки: печатает кадры, отвечает PONG на PING; команда в stdin
        «kick <userNum> <userIndex> <ourReason> <eosReason>» шлёт KICK последнему соединению.
"""
import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

HELLO, LOGIN, LOGOUT, REBIND, PING, KICK, PONG = 0x10, 0x11, 0x12, 0x13, 0x14, 0x21, 0x24
NAMES = {HELLO: "HELLO", LOGIN: "LOGIN", LOGOUT: "LOGOUT", REBIND: "REBIND", PING: "PING", KICK: "KICK", PONG: "PONG"}
FRAME_MAX = 4096          # предел поля len (type + payload)
BIND_LEN = 32             # ★ ред. 3: длина bind (ServerChannel::ChannelBinding)
ZERO_BIND = bytes(BIND_LEN)   # ★ ред. 3: bind Legacy-слота / без P61


def bind_of(slot, gen=0):
    """★ ред. 3: детерминированный bind слота стенда — тот же расчёт, что BindOf в stand_p73.cpp."""
    return bytes(((slot * 7 + gen * 31 + i) & 0xFF) for i in range(BIND_LEN))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ═════════════════════════════ кодек ═════════════════════════════
def encode(ftype, payload=b""):
    """Собрать кадр. ValueError — payload не помещается в len ≤ 4096."""
    if len(payload) + 1 > FRAME_MAX:
        raise ValueError("payload %d > %d" % (len(payload), FRAME_MAX - 1))
    return struct.pack("<HB", len(payload) + 1, ftype) + payload


class Decoder:
    """Накопитель приёма: feed(bytes) → список (type, payload); ProtocolError — len 0 или > 4096."""

    class ProtocolError(Exception):
        pass

    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        out = []
        while len(self.buf) >= 2:
            ln = struct.unpack_from("<H", self.buf, 0)[0]
            if ln < 1 or ln > FRAME_MAX:
                raise Decoder.ProtocolError("len %d" % ln)
            if len(self.buf) < 2 + ln:
                break
            out.append((self.buf[2], self.buf[3:2 + ln]))
            self.buf = self.buf[2 + ln:]
        return out


def parse(ftype, p):
    """Разобрать полезную нагрузку кадра P73 в словарь; ValueError — длина не по контракту."""
    if ftype == HELLO:
        if len(p) != 8:
            raise ValueError("HELLO len %d" % len(p))
        ver, kind, pid, port = struct.unpack("<BBIH", p)
        return {"t": "HELLO", "ver": ver, "kind": kind, "pid": pid, "gamePort": port}
    if ftype == LOGIN:
        if len(p) != 14 + BIND_LEN:
            raise ValueError("LOGIN len %d" % len(p))
        un, ui = struct.unpack_from("<HI", p, 0)
        ip = "%d.%d.%d.%d" % tuple(p[6:10])
        seq = struct.unpack_from("<I", p, 10)[0]
        return {"t": "LOGIN", "userNum": un, "userIndex": ui, "ip": ip, "seq": seq, "bind": bytes(p[14:14 + BIND_LEN])}
    if ftype == LOGOUT:
        if len(p) != 10:
            raise ValueError("LOGOUT len %d" % len(p))
        un, ui, seq = struct.unpack("<HII", p)
        return {"t": "LOGOUT", "userNum": un, "userIndex": ui, "seq": seq}
    if ftype == REBIND:
        if len(p) != 14 + BIND_LEN:
            raise ValueError("REBIND len %d" % len(p))
        un, old, sess, seq = struct.unpack_from("<HIII", p, 0)
        return {"t": "REBIND", "userNum": un, "oldUserIndex": old, "sessionUserIndex": sess, "seq": seq,
                "bind": bytes(p[14:14 + BIND_LEN])}
    if ftype == PING:
        if p:
            raise ValueError("PING len %d" % len(p))
        return {"t": "PING"}
    raise ValueError("тип 0x%02X не от P73" % ftype)


def bind_tag(b):
    """★ ред. 3: короткое имя bind для сверки и печати: «zero», «b<слот>.<поколение>» (bind_of) или hex."""
    if b is None:
        return None
    if b == ZERO_BIND:
        return "zero"
    for slot in range(0, 0x226):
        for gen in (0, 1):
            if b == bind_of(slot, gen):
                return "b%d.%d" % (slot, gen)
    return b.hex()


def short(f):
    """Кадр для печати: bind — коротким именем."""
    if not f:
        return f
    g = dict(f)
    if "bind" in g:
        g["bind"] = bind_tag(g["bind"])
    return g


def kick(user_num, user_index, our, eos):
    return encode(KICK, struct.pack("<HIBB", user_num, user_index, our, eos))


# ═════════════════════════════ selftest ═════════════════════════════
def selftest():
    bad = 0

    def ok(c, m):
        nonlocal bad
        print("  [%s] %s" % ("OK" if c else "!!", m))
        bad += 0 if c else 1

    print("-- кодек кадров (сторона сайдкара)")
    ok(encode(PING) == b"\x01\x00\x14", "PING = 01 00 14")
    ok(encode(PONG) == b"\x01\x00\x24", "PONG = 01 00 24")
    k = kick(7, 75001, 2, 1)
    ok(k == bytes.fromhex("0900" "21" "0700" "f9240100" "02" "01"), "KICK(7, 75001, 2, 1) = %s" % k.hex())
    hello = encode(HELLO, struct.pack("<BBIH", 2, 2, 4242, 15601))
    login = encode(LOGIN, struct.pack("<HI", 7, 75001) + bytes([192, 168, 10, 7]) + struct.pack("<I", 1) + bind_of(7))
    logout = encode(LOGOUT, struct.pack("<HII", 7, 75001, 2))
    rebind = encode(REBIND, struct.pack("<HIII", 15, 75005, 80015, 3) + bind_of(15))
    ok(rebind == bytes.fromhex("2f00" "13" "0f00" "fd240100" "8f380100" "03000000") + bind_of(15),
       "REBIND v2 (15, 75005, 80015, seq 3, bind) = %s… (49 б)" % rebind[:15].hex())
    ok(len(login) == 49 and login[:3] == bytes.fromhex("2f0011"), "ред. 3: LOGIN v2 = 2f 00 11 + 46 б (len 47)")
    ok(bind_of(7) != ZERO_BIND and bind_of(7, 1) != bind_of(7) and bind_of(7)[:3] == bytes([49, 50, 51]), "bind_of(7) = 31 32 33 …")
    stream = hello + login + encode(PING) + logout + rebind
    for chunk in (1, 2, 3, 5, 7, 13, len(stream)):
        d = Decoder()
        got = []
        for i in range(0, len(stream), chunk):
            got += d.feed(stream[i:i + chunk])
        types = [t for t, _ in got]
        ok(types == [HELLO, LOGIN, PING, LOGOUT, REBIND] and d.buf == b"", "поток порциями по %d б → %s" % (chunk, [NAMES[t] for t in types]))
    pl = [parse(t, p) for t, p in Decoder().feed(stream)]
    ok(pl[0] == {"t": "HELLO", "ver": 2, "kind": 2, "pid": 4242, "gamePort": 15601}, "HELLO разобран: %s" % pl[0])
    ok(pl[1] == {"t": "LOGIN", "userNum": 7, "userIndex": 75001, "ip": "192.168.10.7", "seq": 1, "bind": bind_of(7)},
       "LOGIN v2 разобран (bind %s…)" % pl[1]["bind"][:4].hex())
    ok(pl[3] == {"t": "LOGOUT", "userNum": 7, "userIndex": 75001, "seq": 2}, "LOGOUT разобран: %s" % pl[3])
    ok(pl[4] == {"t": "REBIND", "userNum": 15, "oldUserIndex": 75005, "sessionUserIndex": 80015, "seq": 3, "bind": bind_of(15)},
       "REBIND v2 разобран (bind %s…)" % pl[4]["bind"][:4].hex())
    d = Decoder()
    ok(d.feed(login[:5]) == [] and len(d.buf) == 5, "неполный кадр ждёт продолжения (5 б в накопителе)")
    big = encode(0x02, b"\xAB" * (FRAME_MAX - 1))
    ok(len(big) == FRAME_MAX + 2 and Decoder().feed(big)[0][1] == b"\xAB" * (FRAME_MAX - 1), "len = 4096 (предел) принимается")
    for raw, what in ((b"\x00\x00\x21", "len 0"), (struct.pack("<HB", FRAME_MAX + 1, 0x02), "len 4097")):
        try:
            Decoder().feed(raw)
            ok(False, "%s — нарушение протокола не поймано" % what)
        except Decoder.ProtocolError:
            ok(True, "%s — нарушение протокола" % what)
    try:
        encode(0x02, b"\0" * FRAME_MAX)
        ok(False, "сборка payload 4096 (len 4097) не отвергнута")
    except ValueError:
        ok(True, "сборка payload 4096 (len 4097) отвергнута")
    # ★ ред. 3: LOGIN/REBIND v1 (14 б, без bind) — тоже нарушение длины
    for t, p in ((LOGIN, b"\0" * 13), (LOGIN, b"\0" * 14), (LOGIN, b"\0" * 47), (LOGOUT, b"\0" * 11), (HELLO, b"\0" * 7),
                 (REBIND, b"\0" * 13), (REBIND, b"\0" * 14)):
        try:
            parse(t, p)
            ok(False, "%s длины %d не отвергнут" % (NAMES[t], len(p)))
        except ValueError:
            ok(True, "%s длины %d отвергнут" % (NAMES[t], len(p)))
    print("== ИТОГ fake_sidecar --selftest: ошибок %d ==" % bad)
    return 1 if bad else 0


# ═════════════════════════════ сценарий для stand_p73 ═════════════════════════════
class Conn:
    """Соединение с P73: приём кадров в фоне, ожидание кадра нужного типа."""

    def __init__(self, sock):
        self.s = sock
        self.d = Decoder()
        self.frames = []              # [(time, dict)] — ещё не взятые wait()
        self.order = []               # все кадры (кроме PING) в порядке прихода — для проверки «LOGIN и сразу REBIND»
        self.closed = False
        self.proto_error = None
        self.lock = threading.Condition()
        threading.Thread(target=self._rx, daemon=True).start()

    def _rx(self):
        try:
            while True:
                data = self.s.recv(65536)
                if not data:
                    break
                for t, p in self.d.feed(data):
                    try:
                        f = parse(t, p)
                    except ValueError as e:
                        f = {"t": "BAD", "why": str(e)}
                    if f["t"] == "PING":
                        try:
                            self.s.sendall(encode(PONG))
                        except OSError:
                            pass
                    with self.lock:
                        self.frames.append((time.time(), f))
                        if f["t"] != "PING":
                            self.order.append(f)
                        self.lock.notify_all()
        except Decoder.ProtocolError as e:
            self.proto_error = str(e)
        except OSError:
            pass
        with self.lock:
            self.closed = True
            self.lock.notify_all()

    def wait(self, pred, timeout):
        """Ждать кадр, удовлетворяющий pred (из ещё не взятых). Возврат — dict или None."""
        end = time.time() + timeout
        with self.lock:
            while True:
                for i, (_, f) in enumerate(self.frames):
                    if pred(f):
                        del self.frames[i]
                        return f
                left = end - time.time()
                if left <= 0 or self.closed:
                    return None
                self.lock.wait(left)

    def wait_closed(self, timeout):
        end = time.time() + timeout
        with self.lock:
            while not self.closed and time.time() < end:
                self.lock.wait(end - time.time())
            return self.closed

    def send(self, data):
        self.s.sendall(data)

    def close(self):
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close()


def scenario_std(port, status_path, expect_kind):
    bad = 0

    def ok(c, m):
        nonlocal bad
        print("  [%s] %s" % ("OK" if c else "!!", m), flush=True)
        bad += 0 if c else 1

    seen_phases = []

    def phase(name, **kw):
        # Фаза + список ВСЕХ пройденных фаз: стенд мог не успеть прочесть промежуточную (файл перезаписывается).
        seen_phases.append(name)
        kw["phase"] = name
        kw["seen"] = list(seen_phases)
        tmp = status_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(kw, f)
        os.replace(tmp, status_path)
        print("-- фаза: %s" % name, flush=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1) if hasattr(socket, "SO_EXCLUSIVEADDRUSE") else None
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    srv.settimeout(30)
    phase("listening")
    seqs = []

    def accept():
        try:
            s, a = srv.accept()
        except socket.timeout:
            return None
        ok(a[0] == "127.0.0.1", "соединение с 127.0.0.1 (порт клиента %d)" % a[1])
        return Conn(s)

    def take_seq(f):
        if f and "seq" in f:
            seqs.append(f["seq"])

    def snapshot(c, want, what):
        """После HELLO: ровно want кадров LOGIN/REBIND в порядке прихода (REBIND сразу за LOGIN своего слота)."""
        end = time.time() + 5
        while time.time() < end and len([f for f in c.order if f["t"] != "HELLO"]) < len(want):
            time.sleep(0.05)
        got = [f for f in c.order if f["t"] != "HELLO"][:len(want)]
        for f in got:
            take_seq(f)
        sig = [(f["t"], f["userNum"], f.get("userIndex", f.get("oldUserIndex")), f.get("sessionUserIndex"), bind_tag(f.get("bind")))
               for f in got]
        ok(sig == want, "%s: %s" % (what, sig))
        with c.lock:                                  # снятые снимком кадры — из очереди wait()
            c.frames = [(t, f) for t, f in c.frames if f not in got and f["t"] != "HELLO"]
        return got

    # ★ ред. 3: bind в снимке — ТОТ, что взят на LOGIN (поколение 0); стенд после conn1_ready меняет источник слота 7 на
    #   поколение 1, и снимки соединений 2/3 всё равно обязаны нести b7.0.
    SNAP1 = [("LOGIN", 7, 75001, None, "b7.0"), ("LOGIN", 15, 75005, None, "b15.0"), ("REBIND", 15, 75005, 80015, "b15.0")]
    SNAP2 = SNAP1 + [("LOGIN", 17, 75006, None, "b17.0"), ("REBIND", 17, 75006, 80017, "b17.0")]

    # ── соединение 1: HELLO + LOGIN всех, кто уже в игре (7 и соулмейт 15 вошли, пока сайдкара не было) ──
    c = accept()
    ok(c is not None, "P73 подключился (переподключение после старта сайдкара)")
    if c is None:
        return 1
    h = c.wait(lambda f: f["t"] == "HELLO", 5)
    ok(h is not None and h["ver"] == 2 and h["kind"] == expect_kind and h["pid"] > 0, "HELLO v2 (ред. 3): %s" % h)
    got = snapshot(c, SNAP1, "соединение 1: LOGIN всех в игре, у соулмейта сразу REBIND")
    ok(len(got) == 3 and got[0]["ip"] == "192.168.10.7" and got[1]["ip"] == "192.168.10.15", "IPv4 в LOGIN — сетевой порядок байт")
    phase("conn1_ready")
    f = c.wait(lambda f: f["t"] == "LOGIN" and f["userNum"] == 9, 10)
    take_seq(f)
    ok(f is not None and f["userIndex"] == 75002 and f["ip"] == "192.168.10.9", "живой LOGIN userNum 9: %s" % short(f))
    ok(f is not None and f["bind"] == ZERO_BIND, "ред. 3: Legacy-слот 9 — bind 32 нуля")
    f = c.wait(lambda f: f["t"] == "LOGIN" and f["userNum"] == 17, 10)
    take_seq(f)
    r = c.wait(lambda f: f["t"] == "REBIND" and f["userNum"] == 17, 10)
    take_seq(r)
    ok(f is not None and f["userIndex"] == 75006, "живой LOGIN соулмейта 17 (персонаж учётки 75006): %s" % short(f))
    ok(r is not None and r["oldUserIndex"] == 75006 and r["sessionUserIndex"] == 80017 and r["seq"] > f["seq"],
       "живой REBIND 17: 75006 → 80017 после ответа БД 2145: %s" % short(r))
    ok(f is not None and r is not None and bind_tag(f["bind"]) == "b17.0" and r["bind"] == f["bind"],
       "ред. 3: живые LOGIN/REBIND 17 несут один и тот же bind слота (b17.0)")
    c.send(kick(7, 75001, 2, 1))
    c.send(kick(9, 99999, 1, 0))               # чужой UserIndex — P73 обязан отбросить (вид 81)
    c.send(kick(15, 80015, 1, 0))              # KICK несёт userIndex из LOGIN (+0x174), не sessionUserIndex — отбросить
    phase("kick_sent")
    f = c.wait(lambda f: f["t"] == "LOGOUT", 15)
    take_seq(f)
    ok(f is not None and f["userNum"] == 9 and f["userIndex"] == 75002, "LOGOUT userNum 9 на разрыве: %s" % f)
    p = c.wait(lambda f: f["t"] == "PING", 8)
    ok(p is not None, "PING каждые 5 с (получен)")
    ok(c.proto_error is None and not any(fr["t"] == "BAD" for fr in c.order), "кадры P73 по контракту (нет порченых)")
    c.close()
    phase("conn1_closed")

    # ── соединение 2: после разрыва — снова HELLO + LOGIN всех (+ REBIND соулмейтов); порченый кадр → P73 рвёт соединение ──
    c = accept()
    ok(c is not None, "P73 переподключился после разрыва сайдкаром")
    if c is None:
        return 1
    h = c.wait(lambda f: f["t"] == "HELLO", 5)
    ok(h is not None and h["ver"] == 2, "HELLO v2 повторно: %s" % h)
    snapshot(c, SNAP2, "соединение 2: LOGIN всех + REBIND соулмейтов (9 вышел)")
    extra = c.wait(lambda f: f["t"] in ("LOGIN", "LOGOUT", "REBIND"), 1.0)
    ok(extra is None, "лишних LOGIN/LOGOUT/REBIND нет: %s" % extra)
    phase("conn2_ready")
    c.send(encode(0x99, b"\x00"))             # неизвестный тип — нарушение протокола
    ok(c.wait_closed(5), "на неизвестный тип кадра P73 закрыл соединение")
    phase("conn2_closed")

    # ── соединение 3: снова подключение; PONG от нас; всё спокойно ──
    c = accept()
    ok(c is not None, "P73 переподключился после нарушения протокола")
    if c is None:
        return 1
    h = c.wait(lambda f: f["t"] == "HELLO", 5)
    ok(h is not None, "HELLO в третьем соединении")
    snapshot(c, SNAP2, "соединение 3: LOGIN всех + REBIND соулмейтов")
    ok(seqs == sorted(seqs) and len(set(seqs)) == len(seqs) and len(seqs) == 17, "seq растёт монотонно через все соединения: %s" % seqs)
    phase("conn3_ready")
    time.sleep(1.0)
    srv.close()                                # сначала перестать принимать: иначе P73 успеет подключиться в очередь listen
    c.close()
    phase("done", bad=bad)
    print("== ИТОГ fake_sidecar (сценарий std): ошибок %d ==" % bad, flush=True)
    return 1 if bad else 0


def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    last = {"c": None}

    def repl():
        for line in sys.stdin:
            w = line.split()
            if len(w) == 5 and w[0] == "kick" and last["c"]:
                last["c"].send(kick(int(w[1]), int(w[2]), int(w[3]), int(w[4])))
                print("> KICK", w[1:])

    threading.Thread(target=repl, daemon=True).start()
    print("сайдкар слушает 127.0.0.1:%d" % port)
    while True:
        s, a = srv.accept()
        c = Conn(s)
        last["c"] = c
        print("соединение", a)

        def dump(c=c):
            while not c.closed:
                f = c.wait(lambda f: True, 1)
                if f:
                    print("<", f, flush=True)
            print("соединение закрыто", c.proto_error or "")
        threading.Thread(target=dump, daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--port", type=int, default=15702)
    ap.add_argument("--scenario")
    ap.add_argument("--status", default="status.json")
    ap.add_argument("--kind", type=int, default=2)
    ap.add_argument("--serve", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.scenario == "std":
        return scenario_std(a.port, a.status, a.kind)
    if a.serve:
        return serve(a.port)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
