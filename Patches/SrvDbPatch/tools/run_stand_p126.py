# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Прогон стенда P126_DbReconnect (SrvDbPatch.dll, 15.11.2026).

Поднимает локальный TCP-прокси 127.0.0.1:<порт> -> SQL Server dev-стойки (класс Proxy — общий со стендом P125,
`DbReconnect/tools/run_stand_p125.py`) и запускает stand_p126.exe для RelayServer (живой a8cd94ba и Ch2 075c41a5),
ItemRelayServer и OperationServer в режимах on / off / noretry / nocom / mismatch. Стенд командует прокси: KILL — оборвать
все соединения (RST), DOWN — оборвать и не принимать, UP — принимать, COUNT — сколько принято.

База: только SELECT. Пароль читается помощником db_connect (по SSH, только чтение), в журналы не попадает.
Побочных эффектов при импорте нет; запуск — main().
Запуск: py -3.13 run_stand_p126.py [--only relay,relay_ch2,itemrelay,operation] [--modes on,off,noretry,nocom,mismatch]
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                                     # SrvDbPatch
PATCHES = os.path.dirname(ROOT)                                  # AstoryServer\Patches
STAND = os.path.join(HERE, "stand_p126", "stand_p126.exe")
DLL = os.path.join(ROOT, "out", "SrvDbPatch.dll")
HOSTS = {
    "relay":     (os.path.join(ROOT, "out", "RelayServer.exe.srvdbpatch.exe"), "relay"),
    "relay_ch2": (os.path.join(ROOT, "out", "RelayServer_ch2.exe.srvdbpatch.exe"), "relay"),
    "itemrelay": (os.path.join(ROOT, "out", "ItemRelayServer.exe.srvdbpatch.exe"), "itemrelay"),
    "operation": (os.path.join(ROOT, "out", "OperationServer.exe.srvdbpatch.exe"), "operation"),
}


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Стенд P126_DbReconnect")
    ap.add_argument("--only", default="relay,relay_ch2,itemrelay,operation")
    ap.add_argument("--modes", default="on,off,noretry,nocom,mismatch")
    ap.add_argument("--dll", default=DLL, help="проверяемая DLL (по умолчанию out\\SrvDbPatch.dll)")
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.join(PATCHES, "DbReconnect", "tools"))
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(PATCHES)), "AstoryServer", "Tools", "Anticheat"))
    from run_stand_p125 import Proxy                             # тот же прокси, что у стенда P125
    import db_connect                                            # пароль dev-базы по SSH, только чтение

    host, port = db_connect.DEFAULT_SERVER.split(",")
    proxy = Proxy((host, int(port)))
    proxy.start()

    env = dict(os.environ)
    env.pop("STAND_P126_CHILD", None)
    env["P126_PORT"] = str(proxy.port)
    env["P126_CTL"] = str(proxy.ctl_port)
    env["P126_UID"] = db_connect.DEFAULT_UID
    env["P126_PWD"] = db_connect.read_password()
    env["P126_DB"] = "Joy1"

    failed = 0
    for key in args.only.split(","):
        exe, kind = HOSTS[key]
        for mode in args.modes.split(","):
            with proxy.lock:
                proxy.down = False
            proxy.kill_all()
            log = os.path.join(HERE, "stand_p126", "run_%s_%s.log" % (key, mode))
            try:
                r = subprocess.run([STAND, exe, args.dll, kind, mode], env=env, capture_output=True, timeout=600)
                out, code = r.stdout + r.stderr, r.returncode
            except subprocess.TimeoutExpired as e:
                out, code = (e.stdout or b"") + b"\n[TIMEOUT]\n", 99
            with open(log, "wb") as f:
                f.write(out)
            text = out.decode("utf-8", "replace")
            tail = [ln for ln in text.splitlines() if ln.startswith("== ИТОГ")]
            bad = [ln for ln in text.splitlines() if "[!!]" in ln]
            print("%-9s %-8s код %d  %s" % (key, mode, code, tail[-1] if tail else "(итога нет)"))
            for ln in bad:
                print("      " + ln.strip())
            if code != 0:
                failed += 1
    print("прокси: принято соединений %d" % proxy.accepted)
    print("=== СТЕНД P126: %s ===" % ("ВСЁ ЗЕЛЁНОЕ" if failed == 0 else "ЕСТЬ ОШИБКИ (%d)" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
