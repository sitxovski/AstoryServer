# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Выкладка исправления шлюза премиум-покупок gp7 «корзина: списана сумма всех, выдана одна» (25.10.2026).

Что меняет: @@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\gp7-server\\server.js ← AstoryServer\\Patches\\Gp7Gateway\\server.js
(новая проверка isCartTotalPrice: для кода item_table присланная GameServer-ом цена должна быть ценой ОДНОЙ штуки,
иначе status 0 «cart-total-mismatch», без списания; ключ config.rejectCartTotal, false = как раньше).

Только SSH/scp (шару \\\\@@ASTORY_SERVER_HOSTNAME@@ не трогает). Сам НИЧЕГО не перезапускает: новый server.js подхватится при следующем
запуске node gp7-server (полная стойка — restart_stack_p76.py с объявлением; правило stack-restart-with-announce).

    python deploy_gp7_cart.py            — проверка (по умолчанию): хэши живого и нового файла, ничего не пишет
    python deploy_gp7_cart.py --apply    — бэкап живого server.js.bak_20261025_cart, выкладка, node --check на сервере
    python deploy_gp7_cart.py --rollback — вернуть server.js из server.js.bak_20261025_cart
"""
import hashlib
import os
import subprocess
import sys

SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SRV_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server"
SRV_FILE = SRV_DIR + r"\server.js"
SRV_BAK = SRV_DIR + r"\server.js.bak_20261025_cart"
SRV_NEW = SRV_DIR + r"\server.new_20261025_cart.js"   # расширение .js обязательно: пакет type=module, node --check иначе падает
LOCAL_NEW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.js")
# Живой server.js на момент подготовки (24.10.2026 17:20, после fableshop) — выкладываем только поверх него.
EXPECTED_LIVE_MD5 = "E40E1ADAC147113C5347F62DC8878243"


def _ssh(cmd, timeout=120):
    """Команда на сервере по SSH; возвращает (код, stdout+stderr)."""
    r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", SSH_HOST, cmd],
                       capture_output=True, text=True, timeout=timeout, encoding="cp866", errors="replace")
    return r.returncode, (r.stdout + r.stderr).strip()


def _ps(script, timeout=120):
    """PowerShell-однострочник на сервере."""
    return _ssh('powershell -NoProfile -Command "%s"' % script, timeout)


def _scp_to(local, remote, timeout=300):
    """Залить файл на сервер (путь сервера — с прямыми слэшами)."""
    r = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                        local, "%s:%s" % (SSH_HOST, remote.replace("\\", "/"))],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise SystemExit("scp %s -> %s: %s" % (local, remote, r.stderr.strip()))


def _remote_md5(path):
    """MD5 файла на сервере (пусто, если файла нет)."""
    _, out = _ps("if(Test-Path '%s'){(Get-FileHash '%s' -Algorithm MD5).Hash}" % (path, path))
    return out.strip().upper()


def _local_md5(path):
    """MD5 локального файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest().upper()


def main(argv):
    """Точка входа: проверка / --apply / --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")   # русский вывод в любой консоли
    except (AttributeError, ValueError):
        pass
    mode = "check"
    if "--apply" in argv:
        mode = "apply"
    if "--rollback" in argv:
        mode = "rollback"
    new_md5 = _local_md5(LOCAL_NEW)
    live_md5 = _remote_md5(SRV_FILE)
    print("живой server.js : %s (ожидался %s)" % (live_md5 or "НЕТ", EXPECTED_LIVE_MD5))
    print("новый server.js : %s (%s)" % (new_md5, LOCAL_NEW))

    if mode == "rollback":
        bak = _remote_md5(SRV_BAK)
        if not bak:
            raise SystemExit("бэкапа %s нет — откатывать нечего" % SRV_BAK)
        code, out = _ps("Copy-Item -Force '%s' '%s'; (Get-FileHash '%s' -Algorithm MD5).Hash" % (SRV_BAK, SRV_FILE, SRV_FILE))
        print("откат:", out)
        if out.strip().upper() != bak:
            raise SystemExit("ОШИБКА: после отката хэш %s != бэкап %s" % (out, bak))
        print("ГОТОВО: server.js возвращён из бэкапа; подхватится при следующем запуске gp7-server")
        return 0

    if live_md5 == new_md5:
        print("на сервере уже новая версия — делать нечего")
        return 0
    if live_md5 != EXPECTED_LIVE_MD5:
        raise SystemExit("ОСТАНОВ: живой server.js изменился после подготовки правки (%s) — слить изменения вручную" % live_md5)
    if mode == "check":
        print("ПРОВЕРКА пройдена: можно выкладывать (--apply)")
        return 0

    # --apply
    if not _remote_md5(SRV_BAK):
        code, out = _ps("Copy-Item '%s' '%s'" % (SRV_FILE, SRV_BAK))
        if _remote_md5(SRV_BAK) != live_md5:
            raise SystemExit("ОШИБКА бэкапа: %s" % out)
    print("бэкап:", SRV_BAK)
    _scp_to(LOCAL_NEW, SRV_NEW)
    if _remote_md5(SRV_NEW) != new_md5:
        raise SystemExit("ОШИБКА: залитый %s не совпал по хэшу" % SRV_NEW)
    code, out = _ssh('cd /d %s && node --check "%s"' % (SRV_DIR, SRV_NEW))
    if code != 0:
        raise SystemExit("ОШИБКА node --check на сервере: %s" % out)
    code, out = _ps("Move-Item -Force '%s' '%s'" % (SRV_NEW, SRV_FILE))
    if _remote_md5(SRV_FILE) != new_md5:
        raise SystemExit("ОШИБКА: после замены хэш server.js не совпал: %s" % out)
    print("ГОТОВО: server.js заменён (%s). Работающий node держит старую версию в памяти — новая включится при"
          " следующем запуске gp7-server (перезапуск стойки — за координатором, с объявлением)." % new_md5)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
