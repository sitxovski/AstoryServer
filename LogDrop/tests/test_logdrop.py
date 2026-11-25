# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# test_logdrop.py — ★ 19.10.2026 проверка и фаззинг приёмника AsdaLogDrop (AstoryServer/LogDrop) на этой машине.
#   Запускает out\AsdaLogDrop.exe --console с временным конфигом (127.0.0.1, временный корень, --test-accounts вместо SQL),
#   шлёт корректные конверты (настоящий .alog игрока или синтетический сегмент Tools/asda_logseal.py), ломаные конверты,
#   превышения лимитов и случайные мутации; сверяет коды ответа, содержимое хранилища и живость службы.
#   Запуск: python tests/test_logdrop.py [--alog файл] [--keep]   (код возврата 0 — все проверки прошли)
import argparse
import glob
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SVC_DIR = os.path.dirname(HERE)
EXE = os.path.join(SVC_DIR, "out", "AsdaLogDrop.exe")
TOOLS = os.path.normpath(os.path.join(SVC_DIR, "..", "..", "AsdaReborn", "Tools"))
sys.path.insert(0, TOOLS)
import asda_logseal as ls   # noqa: E402  (без сайд-эффектов при импорте)

PORT = 18446
ACCOUNTS = "TestUser,con,service,_x,Mixed.Case@mail-1,RateLogin"


def envelope(files, ver=2, n=None, reserved=0):
    """files: [(вид, логин bytes, данные bytes)] → тело ASLU."""
    out = b"ASLU" + bytes([ver, len(files) if n is None else n]) + struct.pack("<H", reserved)
    for kind, login, data in files:
        out += bytes([kind, len(login)]) + login + struct.pack("<I", len(data)) + data
    return out


def request(body, path="/api/v1/ingest", method="POST", headers=None, ip=None, install=None, cl=True, raw=None, timeout=15):
    """Сырой HTTP/1.1 запрос → код ответа (0 — соединение закрыто без ответа)."""
    h = {"Host": "127.0.0.1", "Content-Type": "application/octet-stream"}
    if install is not False:
        h["X-Asda-Install"] = install or os.urandom(16).hex()
    if ip:
        h["X-Forwarded-For"] = ip
    if cl and body is not None:
        h["Content-Length"] = str(len(body))
    if headers:
        for k, v in headers.items():
            if v is None:
                h.pop(k, None)
            else:
                h[k] = v
    msg = raw if raw is not None else ("%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n").encode("latin-1") + (body or b"")
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    try:
        try:
            s.sendall(msg)
        except OSError:
            pass
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                c = s.recv(4096)
            except OSError:
                break
            if not c:
                break
            data += c
        if not data.startswith(b"HTTP/1.1 "):
            return 0
        return int(data[9:12])
    finally:
        s.close()


class Ctx:
    def __init__(self):
        self.ok = 0
        self.fail = 0
        self.n_ip = 0

    def ip(self):
        self.n_ip += 1
        return "10.%d.%d.%d" % ((self.n_ip >> 16) & 255, (self.n_ip >> 8) & 255, self.n_ip & 255)

    def check(self, cond, what):
        if cond:
            self.ok += 1
        else:
            self.fail += 1
            print("  ПРОВАЛ:", what)


def start(root, extra_cfg="", accounts=ACCOUNTS):
    cfg = os.path.join(root, "test.ini")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write("Port=%d\nRoot=%s\nLogDir=%s\nHeadTimeoutMs=2000\nBodyTimeoutMs=4000\nIoTimeoutMs=2000\n%s"
                % (PORT, os.path.join(root, "drop"), os.path.join(root, "drop", "service", "logs"), extra_cfg))
    out = open(os.path.join(root, "console.txt"), "wb")   # в файл: непрочитанный PIPE заблокировал бы службу
    p = subprocess.Popen([EXE, "--console", "--config", cfg, "--test-accounts", accounts], stdin=subprocess.PIPE,
                         stdout=out, stderr=subprocess.STDOUT)
    p.out_path = os.path.join(root, "console.txt")
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("служба не поднялась")


def stop(p):
    try:
        p.stdin.write(b"\n")
        p.stdin.flush()
        p.wait(10)
    except Exception:
        p.kill()
    return open(p.out_path, "rb").read().decode("utf-8", "replace")


def stored(root):
    """Сохранённые файлы (без .json и журналов службы)."""
    drop = os.path.join(root, "drop")
    out = []
    for dp, dn, fn in os.walk(drop):
        if os.path.relpath(dp, drop).split(os.sep)[0] == "service":
            continue
        out += [os.path.join(dp, f) for f in fn]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alog", help="настоящий .alog (по умолчанию — из %%LOCALAPPDATA%%\\AsdaReborn\\Saved\\Logs)")
    ap.add_argument("--keep", action="store_true", help="не удалять временную папку")
    ap.add_argument("--fuzz", type=int, default=400, help="число случайных мутаций")
    a = ap.parse_args()
    xy, kid = ls.current_public()
    real = a.alog
    if not real:
        cands = glob.glob(os.path.join(os.environ.get("LOCALAPPDATA", ""), "AsdaReborn", "Saved", "Logs", "AsdaEac*.alog"))
        real = cands[0] if cands else None
    eac = open(real, "rb").read() if real else ls._seal_segment_py(xy, 1, [bytes([2]) + b"eac line\n"])
    game = ls._seal_segment_py(xy, 3, [bytes([2]) + b"game line %d\n" % i for i in range(5)])
    game2 = game + ls._seal_segment_py(xy, 3, [bytes([2]) + b"second segment\n"])
    crash = ls._seal_segment_py(xy, 4, [bytes([0x10]) + struct.pack("<H", 4) + b"a.dm" + struct.pack("<Q", 3), bytes([0x11]) + b"abc", bytes([0x12])])
    print("ключ %s; настоящий файл: %s (%d б)" % (kid.hex(), real or "нет — синтетический", len(eac)))

    root = tempfile.mkdtemp(prefix="logdrop_test_")
    c = Ctx()
    p = start(root)
    try:
        # ── корректные ──
        r = request(envelope([(2, b"TestUser", eac)]), ip=c.ip())
        c.check(r == 204, "корректный EAC + существующий логин → 204 (%d)" % r)
        files = [f for f in stored(root) if f.endswith(".alog")]
        c.check(len(files) == 1 and os.sep + "testuser" + os.sep in files[0], "файл в drop\\testuser\\<дата>\\ (%s)" % files)
        if files:
            c.check(open(files[0], "rb").read() == eac, "байты файла = отправленным")
            meta = json.load(open(files[0][:-5] + ".json", encoding="utf-8"))
            c.check(meta["account_status"] == "ok" and meta["key_id"] == kid.hex() and meta["size"] == len(eac) and meta["kind"] == 2,
                    "метаданные .json (%s)" % meta)
            c.check(len(meta["sha256"]) == 64 and meta["file"] == os.path.basename(files[0]), "sha256 и имя в .json")
        codes = [request(envelope([f]), ip=c.ip()) for f in ((1, b"nobody", game2), (3, b"", crash), (2, b"../evil", eac), (1, b"Mixed.Case@mail-1", game))]
        c.check(codes == [204] * 4, "по файлу: несуществующий/пустой/неверный/существующий логин → 204 (%s)" % codes)
        unk = [f for f in stored(root) if os.sep + "_unknown" + os.sep in f and not f.endswith(".json")]
        c.check(len(unk) == 3, "три файла в _unknown (%d)" % len(unk))
        c.check(any(f.endswith(".acrash") for f in unk), "падение сохранено как .acrash")
        c.check(any(os.sep + "mixed.case@mail-1" + os.sep in f for f in stored(root)), "логин нижним регистром")
        c.check(not any(".." in os.path.relpath(f, root) or "evil" in f for f in stored(root)), "логин ../evil не попал в путь")
        for login, d in ((b"con", "_acct_636f6e"), (b"service", "_acct_73657276696365"), (b"_x", "_acct_5f78")):
            r = request(envelope([(1, login, game)]), ip=c.ip())
            c.check(r == 204 and any(os.sep + d + os.sep in f for f in stored(root)), "логин %s → папка %s (%d)" % (login, d, r))
        c.check(not any(f.endswith(".part") for f in stored(root)), "нет недописанных .part")
        n_good = len(stored(root))

        # ── ломаные: всё → 400, ничего не сохранено ──
        def bad(body, what, code=400, **kw):
            kw.setdefault("ip", c.ip())
            r = request(body, **kw)
            c.check(r == code, "%s → %d (получено %d)" % (what, code, r))

        g = envelope([(1, b"TestUser", game)])
        bad(b"", "пустое тело")
        bad(b"ASLU", "4 байта")
        bad(envelope([(1, b"TestUser", game)], ver=1), "версия 1")
        bad(envelope([(1, b"", game)], ver=3), "версия 3")
        bad(envelope([(1, b"", game)], n=0), "N=0")
        bad(envelope([(1, b"", game)] * 5), "N=5")
        bad(envelope([(1, b"", game)] * 2), "N=2 (★ В1: ровно один файл)")
        legacy = ls._seal_segment_py(xy, 5, [bytes([2]) + b"legacy\n"])
        bad(envelope([(1, b"", legacy)]), "журнал игры с сегментом 5 (★ М2)")
        r = request(envelope([(3, b"", legacy)]), ip=c.ip())
        c.check(r == 204, "падение с сегментом 5 (перенос старых) → 204 (%d)" % r)
        bad(envelope([(1, b"", game)], n=2), "N больше, чем файлов")
        bad(envelope([(1, b"", game)] * 2, n=1), "N меньше, чем файлов (хвост)")
        bad(envelope([(1, b"", game)], reserved=1), "резерв ≠ 0")
        bad(b"XSLU" + g[4:], "чужая магия конверта")
        bad(envelope([(4, b"", game)]), "вид 4")
        bad(envelope([(0, b"", game)]), "вид 0")
        bad(envelope([(1, b"A" * 33, game)]), "логин 33 байта")
        bad(envelope([(3, b"", game)]), "журнал игры под видом падения")
        bad(envelope([(2, b"", game)]), "журнал игры под видом EAC")
        bad(envelope([(1, b"", game[:-1])]), "контейнер обрезан на 1 байт")
        bad(envelope([(1, b"", game + b"\0")]), "лишний байт в контейнере")
        bad(envelope([(1, b"", game + b"ASLG")]), "хвост ASLG")
        bad(envelope([(1, b"", game[:128])]), "только заголовок сегмента")
        bad(envelope([(1, b"", game[:150])]), "обрезанный кадр")
        body = bytearray(g)
        struct.pack_into("<I", body, 8 + 2 + 8, len(game) + 10)
        bad(bytes(body), "длина файла завышена")
        body = bytearray(g)
        struct.pack_into("<I", body, 8 + 2 + 8, len(game) - 10)
        bad(bytes(body), "длина файла занижена")
        body = bytearray(g)
        struct.pack_into("<I", body, 8 + 2 + 8, 0xFFFFFFFF)
        bad(bytes(body), "длина файла 0xFFFFFFFF", code=413)

        def mut(off, val, what, base=game):
            b = bytearray(base)
            b[off] = val
            bad(envelope([(1, b"", bytes(b))]), what)
        mut(0, ord("X"), "магия сегмента")
        mut(8, 2, "версия сегмента")
        mut(9, 127, "вид сегмента 127 (самотест)")
        mut(10, 1, "резерв сегмента")
        mut(12, game[12] ^ 1, "чужой keyId")
        mut(20, 0x5A, "ClientHello магия")
        mut(22, 1, "ClientHello под-сервер")
        mut(24 + 63, game[24 + 63] ^ 1, "эфемерный ключ — не точка на кривой")
        mut(125, 1, "резерв 120..127")
        b = bytearray(game)
        b[24:56] = b"\xff" * 32
        bad(envelope([(1, b"", bytes(b))]), "x ≥ p")
        b = bytearray(game)
        b[24:88] = bytes(64)
        bad(envelope([(1, b"", bytes(b))]), "точка (0,0)")
        b = bytearray(game)
        struct.pack_into("<Q", b, 128 + 4, 2)
        bad(envelope([(1, b"", bytes(b))]), "seq первого кадра 2")
        b = bytearray(game)
        struct.pack_into("<I", b, 128, 0)
        bad(envelope([(1, b"", bytes(b))]), "clen 0")
        b = bytearray(game)
        struct.pack_into("<I", b, 128, 0x7FFFFFFF)
        bad(envelope([(1, b"", bytes(b))]), "clen огромный")
        b = bytearray(game)
        struct.pack_into("<I", b, 128, struct.unpack_from("<I", game, 128)[0] + 1)
        bad(envelope([(1, b"", bytes(b))]), "clen +1 (ложная длина кадра)")
        bad(envelope([(1, b"", game[:128] + game)]), "сегмент без кадров")
        bad(envelope([(1, b"", os.urandom(4000))]), "случайные байты вместо контейнера")
        big = ls._seal_segment_py(xy, 3, [bytes([2]) + os.urandom(60 * 1024) for _ in range(70)])   # > 4 МиБ
        bad(envelope([(1, b"", big)]), "файл > 4 МиБ", code=413)

        # ── HTTP ──
        bad(g, "другой путь", path="/api/v1/ingest2", code=404)
        bad(g, "путь с запросом", path="/api/v1/ingest?x=1", code=404)
        bad(g, "GET", method="GET", code=404)
        bad(g, "без X-Asda-Install", install=False)
        bad(g, "X-Asda-Install не hex", install="z" * 32)
        bad(g, "X-Asda-Install 31 символ", install="a" * 31)
        bad(g, "без Content-Length", cl=False)
        bad(g, "chunked", headers={"Transfer-Encoding": "chunked"})
        bad(g, "Content-Type text/plain", headers={"Content-Type": "text/plain"})
        bad(g, "без Content-Type", headers={"Content-Type": None})
        bad(g, "Content-Length с минусом", headers={"Content-Length": "-1"})
        bad(g, "дубль Content-Length", raw=("POST /api/v1/ingest HTTP/1.1\r\nContent-Length: %d\r\nContent-Length: %d\r\nX-Asda-Install: %s\r\n"
                                            "Content-Type: application/octet-stream\r\n\r\n" % (len(g), len(g), "a" * 32)).encode() + g)
        bad(g, "Content-Length 9 МиБ", headers={"Content-Length": str(9 * 1024 * 1024)}, code=413)
        bad(g, "заголовок > 16 КиБ", headers={"X-Pad": "a" * 17000})
        bad(g, "XFF мусор", ip="not-an-ip")
        bad(g, "Expect странный", headers={"Expect": "nonsense"})
        r = request(g, ip=c.ip(), headers={"Expect": "100-continue"})
        c.check(r in (100, 204), "Expect: 100-continue принимается (%d)" % r)
        n_good = len(stored(root))

        # медленный заголовок: соединение закрыто сроком, служба жива
        s = socket.create_connection(("127.0.0.1", PORT))
        s.sendall(b"POST /api/v1/ingest HTTP/1.1\r\n")
        t0 = time.time()
        s.settimeout(10)
        try:
            got = s.recv(100)
        except OSError:
            got = b""
        c.check(time.time() - t0 < 6, "медленный заголовок закрыт по сроку (%.1f с, %r)" % (time.time() - t0, got[:20]))
        s.close()
        # медленное тело: обрыв по сроку
        s = socket.create_connection(("127.0.0.1", PORT))
        s.sendall(("POST /api/v1/ingest HTTP/1.1\r\nContent-Length: %d\r\nX-Asda-Install: %s\r\nX-Forwarded-For: %s\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n" % (len(g), os.urandom(16).hex(), c.ip())).encode() + g[:100])
        t0 = time.time()
        s.settimeout(10)
        try:
            s.recv(100)
        except OSError:
            pass
        c.check(time.time() - t0 < 7, "медленное тело закрыто по сроку (%.1f с)" % (time.time() - t0))
        s.close()

        # ── лимиты ──
        ip = c.ip()
        g0 = envelope([(1, b"", game)])
        codes = [request(g0, ip=ip) for _ in range(7)]
        c.check(codes[:6] == [204] * 6 and codes[6] == 429, "IP: 6/час, седьмой 429 (%s)" % codes)
        inst = os.urandom(16).hex()
        codes = [request(envelope([(1, b"", game)]), ip=c.ip(), install=inst) for _ in range(7)]
        c.check(codes[:6] == [204] * 6 and codes[6] == 429, "install: 6/час, седьмой 429 (%s)" % codes)
        # ★ М1: мусор с логином лимит логина не ест; лимит — 12 принятых с СУЩЕСТВУЮЩЕЙ учёткой
        codes = [request(envelope([(1, b"RateLogin", game[:-1])]), ip=c.ip()) for _ in range(13)]
        c.check(codes == [400] * 13, "битый файл с логином → 400 x13 (%s)" % codes)
        codes = [request(envelope([(1, b"RateLogin", game)]), ip=c.ip()) for _ in range(13)]
        c.check(codes[:12] == [204] * 12 and codes[12] == 429, "логин: 12/час принятых, 13-й 429 (%s)" % codes)
        codes = [request(envelope([(1, b"freshlogin", game)]), ip=c.ip()) for _ in range(13)]
        c.check(codes == [204] * 13, "несуществующий логин лимитом логина не считается (→ _unknown) (%s)" % codes)
        codes = [request(b"garbage" * 30, ip=ip2) for ip2 in [c.ip()] * 7]
        c.check(codes[:6] == [400] * 6 and codes[6] == 429, "мусор тоже засчитывается в лимит IP (%s)" % codes)

        def slow_conn(ip_):
            s_ = socket.create_connection(("127.0.0.1", PORT))
            s_.sendall(("POST /api/v1/ingest HTTP/1.1\r\nContent-Length: %d\r\nX-Asda-Install: %s\r\nX-Forwarded-For: %s\r\n"
                        "Content-Type: application/octet-stream\r\n\r\n" % (len(g), os.urandom(16).hex(), ip_)).encode() + g[:50])
            return s_
        # ★ В3: один приём на IP одновременно
        ip1 = c.ip()
        s1 = slow_conn(ip1)
        time.sleep(0.3)
        r = request(g, ip=ip1)
        c.check(r == 429, "второй одновременный приём с того же IP → 429 (%d)" % r)
        s1.close()
        time.sleep(4.5)
        # одновременно ≤ 4: четыре медленных тела с разных IP держат слоты, пятый → 429
        held = [slow_conn(c.ip()) for _ in range(4)]
        time.sleep(0.5)
        r = request(g, ip=c.ip())
        c.check(r == 429, "пятый одновременный приём → 429 (%d)" % r)
        for s in held:
            s.close()
        time.sleep(4.5)
        r = request(g, ip=c.ip())
        c.check(r == 204, "после освобождения слотов → 204 (%d)" % r)

        # ── фаззинг: случайные мутации корректного конверта ──
        base = envelope([(1, b"", game2)])
        rnd = random.Random(20261019)
        hist = {}
        for i in range(a.fuzz):
            b = bytearray(base)
            op = rnd.randrange(6)
            if op == 0:
                for _ in range(rnd.randint(1, 4)):
                    b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            elif op == 1:
                b = b[:rnd.randrange(len(b))]
            elif op == 2:
                pos = rnd.randrange(len(b))
                b[pos:pos] = os.urandom(rnd.randint(1, 64))
            elif op == 3:
                pos = rnd.randrange(len(b) - 4)
                struct.pack_into("<I", b, pos, rnd.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF, len(b), rnd.getrandbits(32)]))
            elif op == 4:
                pos = rnd.randrange(len(b))
                del b[pos:pos + rnd.randint(1, 200)]
            else:
                b = bytearray(os.urandom(rnd.randint(0, 2000)))
            r = request(bytes(b), ip=c.ip())
            hist[r] = hist.get(r, 0) + 1
        c.check(set(hist) <= {204, 400, 413}, "фаззинг %d: только 204/400/413 (%s)" % (a.fuzz, hist))
        r = request(g, ip=c.ip())
        c.check(r == 204 and p.poll() is None, "служба жива после фаззинга (%d)" % r)
        c.check(not any(f.endswith(".part") for f in stored(root)), "после фаззинга нет .part")
        rej = glob.glob(os.path.join(root, "drop", "service", "logs", "rejects_*.log"))
        txt = open(rej[0], encoding="utf-8").read() if rej else ""
        c.check(rej and "reason=seg_point@1" in txt and "ASLGSEG1" not in txt, "журнал отказов: причины есть, тел нет")
    finally:
        out = stop(p)
    if "handler error" in out:
        c.check(False, "в журнале службы handler error:\n" + "\n".join(l for l in out.splitlines() if "handler error" in l))

    # ── квота: отдельный запуск с маленькой квотой ──
    root2 = tempfile.mkdtemp(prefix="logdrop_quota_")
    p = start(root2, "QuotaBytes=%d\nQuotaWarnPercent=30\n" % (len(game) * 6))
    try:
        codes = [request(envelope([(1, b"", game)]), ip=c.ip()) for _ in range(4)]
        c.check(codes[0] == 204 and 507 in codes, "квота: сверх объёма → 507 (%s)" % codes)
    finally:
        out = stop(p)
    c.check("QUOTA WARNING" in out, "предупреждение о квоте (80 %) в журнале службы")

    # ── ★ В1: бюджеты в байтах (маленькие, отдельный запуск) + восстановление после перезапуска ──
    root3 = tempfile.mkdtemp(prefix="logdrop_bytes_")
    L = len(envelope([(1, b"", game)]))
    budgets = ("IpBytesPerHour=%d\nInstallBytesPerHour=%d\nLoginBytesPerDay=%d\nUnknownBytesPerDay=%d\nGlobalBytesPerDay=%d\n"
               % (2 * L + 10, 2 * L + 10, 2 * L + 50, 4 * L + 10, 6 * L + 40))
    p = start(root3, budgets)
    try:
        junk = [request(os.urandom(L), ip=c.ip()) for _ in range(20)]
        c.check(junk == [400] * 20, "20 отказов размером с файл (бюджеты ниже не должны пострадать) (%s)" % set(junk))
        ipb = c.ip()
        codes = [request(envelope([(1, b"", game)]), ip=ipb) for _ in range(3)]
        c.check(codes == [204, 204, 429], "байты с IP: 2 файла, 3-й 429 (%s)" % codes)
        instb = os.urandom(16).hex()
        codes = [request(envelope([(1, b"", game)]), ip=c.ip(), install=instb) for _ in range(3)]
        c.check(codes[:2] == [204, 204] and codes[2] == 429, "байты с install: 3-й 429 (%s)" % codes)
        codes = [request(envelope([(1, b"TestUser", game)]), ip=c.ip()) for _ in range(3)]
        c.check(codes == [204, 204, 429], "байты на логин: 3-й 429 (%s)" % codes)
        r = request(envelope([(1, b"Mixed.Case@mail-1", game)]), ip=c.ip())
        c.check(r == 429, "общий суточный бюджет (6 файлов) → 429 (%d)" % r)
    finally:
        stop(p)
    p = start(root3, budgets.replace("GlobalBytesPerDay=%d" % (6 * L + 40), "GlobalBytesPerDay=%d" % (100 * L)))
    try:
        r = request(envelope([(1, b"", game)]), ip=c.ip())
        c.check(r == 429, "после перезапуска бюджет _unknown восстановлен из .json → 429 (%d)" % r)
        r = request(envelope([(1, b"TestUser", game)]), ip=c.ip())
        c.check(r == 429, "после перезапуска бюджет логина восстановлен → 429 (%d)" % r)
        r = request(envelope([(1, b"con", game)]), ip=c.ip())
        c.check(r == 204, "другой логин после перезапуска → 204 (%d)" % r)
    finally:
        out = stop(p)
    c.check("budgets restored from 6 file(s)" in out, "журнал: бюджеты восстановлены из 6 файлов")
    shutil.rmtree(root3, ignore_errors=True)

    print("проверок %d, провалов %d; папка %s" % (c.ok + c.fail, c.fail, root))
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(root2, ignore_errors=True)
    return 1 if c.fail else 0


if __name__ == "__main__":
    sys.exit(main())
