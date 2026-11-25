# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Прогон стенда P125_DbReconnect (сессия srv-db-reconnect, 15.11.2026).

Что делает: поднимает локальный TCP-прокси 127.0.0.1:<порт> -> SQL Server dev-стойки и запускает
stand_p125.exe для LoginManager и DBManager в режимах on / off / noretry / mismatch. Стенд командует прокси
(порт управления): KILL - оборвать все соединения (RST), DOWN - оборвать и не принимать, UP - принимать.
Так воспроизводится обрыв TCP (как при обновлении Tailscale 14.11.2026), сервер при этом не трогается.

База: только SELECT (@@SPID и константа). Пароль читается помощником db_connect (по SSH), в журналы не попадает.
Побочных эффектов при импорте нет; запуск - только через main().
Запуск: py -3.13 run_stand_p125.py [--only lm|db] [--modes on,off,noretry,mismatch]
"""
import argparse
import os
import socket
import struct
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.dirname(os.path.dirname(HERE))                 # AstoryServer\Patches
STAND = os.path.join(HERE, "stand_p125", "stand_p125.exe")
HOSTS = {
    "lm": (os.path.join(PATCHES, "LoginPatch", "out", "LoginManager.exe.loginpatch.exe"),
           os.path.join(PATCHES, "LoginPatch", "out", "LoginPatch.dll")),
    "db": (os.path.join(PATCHES, "DBPatch", "out", "DBManager.exe.dbpatch.exe"),
           os.path.join(PATCHES, "DBPatch", "out", "DBPatch.dll")),
}


class Proxy:
    """TCP-прокси с обрывом соединений по команде."""

    def __init__(self, upstream):
        self.upstream = upstream            # (адрес, порт) SQL Server
        self.lock = threading.Lock()
        self.pairs = []                     # открытые пары сокетов (клиент, сервер)
        self.down = False                   # True - новые соединения сразу рвутся
        self.accepted = 0                   # всего принято соединений
        self.data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data.bind(("127.0.0.1", 0))
        self.data.listen(64)
        self.ctl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ctl.bind(("127.0.0.1", 0))
        self.ctl.listen(8)
        self.port = self.data.getsockname()[1]
        self.ctl_port = self.ctl.getsockname()[1]

    @staticmethod
    def _rst(sock):
        """Закрыть сокет сбросом (RST), как при пропаже сетевого интерфейса."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _pump(self, a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        self._rst(a)
        self._rst(b)

    def _accept_loop(self):
        while True:
            try:
                c, _ = self.data.accept()
            except OSError:
                return
            with self.lock:
                down = self.down
            if down:
                self._rst(c)
                continue
            try:
                s = socket.create_connection(self.upstream, timeout=10)
                s.settimeout(None)
            except OSError:
                self._rst(c)
                continue
            for sk in (c, s):
                sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                self.pairs.append((c, s))
                self.accepted += 1
            threading.Thread(target=self._pump, args=(c, s), daemon=True).start()
            threading.Thread(target=self._pump, args=(s, c), daemon=True).start()

    def kill_all(self):
        with self.lock:
            pairs, self.pairs = self.pairs, []
        for c, s in pairs:
            self._rst(c)
            self._rst(s)
        return len(pairs)

    def _ctl_loop(self):
        while True:
            try:
                c, _ = self.ctl.accept()
            except OSError:
                return
            try:
                cmd = c.recv(64).decode("ascii", "replace").strip().upper()
                if cmd == "KILL":
                    self.kill_all()
                elif cmd == "DOWN":
                    with self.lock:
                        self.down = True
                    self.kill_all()
                elif cmd == "UP":
                    with self.lock:
                        self.down = False
                if cmd == "COUNT":
                    with self.lock:
                        n = self.accepted
                    c.sendall(b"OK %d\n" % n)
                else:
                    c.sendall(b"OK\n")
            except OSError:
                pass
            finally:
                c.close()

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._ctl_loop, daemon=True).start()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Стенд P125_DbReconnect")
    ap.add_argument("--only", choices=["lm", "db"], help="только один образ")
    ap.add_argument("--modes", default="on,off,noretry,nocom,mismatch")
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(PATCHES)), "AstoryServer", "Tools", "Anticheat"))
    import db_connect                                            # пароль dev-базы по SSH, только чтение

    host, port = db_connect.DEFAULT_SERVER.split(",")
    proxy = Proxy((host, int(port)))
    proxy.start()

    env = dict(os.environ)
    env.pop("STAND_P125_CHILD", None)
    env["P125_PORT"] = str(proxy.port)
    env["P125_CTL"] = str(proxy.ctl_port)
    env["P125_UID"] = db_connect.DEFAULT_UID
    env["P125_PWD"] = db_connect.read_password()
    env["P125_DB"] = "Joy1"

    failed = 0
    for key in ([args.only] if args.only else ["lm", "db"]):
        exe, dll = HOSTS[key]
        for mode in args.modes.split(","):
            with proxy.lock:
                proxy.down = False
            proxy.kill_all()
            log = os.path.join(HERE, "stand_p125", "run_%s_%s.log" % (key, mode))
            try:
                r = subprocess.run([STAND, exe, dll, key, mode], env=env, capture_output=True, timeout=600)
                out, code = r.stdout + r.stderr, r.returncode
            except subprocess.TimeoutExpired as e:
                out, code = (e.stdout or b"") + b"\n[TIMEOUT]\n", 99
            with open(log, "wb") as f:
                f.write(out)
            text = out.decode("utf-8", "replace")
            tail = [ln for ln in text.splitlines() if ln.startswith("== ИТОГ")]
            bad = [ln for ln in text.splitlines() if "[!!]" in ln]
            print("%-2s %-8s код %d  %s" % (key, mode, code, tail[-1] if tail else "(итога нет)"))
            for ln in bad:
                print("      " + ln.strip())
            if code != 0:
                failed += 1
    print("прокси: принято соединений %d" % proxy.accepted)
    print("=== СТЕНД P125: %s ===" % ("ВСЁ ЗЕЛЁНОЕ" if failed == 0 else "ЕСТЬ ОШИБКИ (%d)" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
