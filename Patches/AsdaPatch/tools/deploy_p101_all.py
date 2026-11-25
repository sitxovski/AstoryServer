# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p101_all.py — выкладка серверной части P101 «подарок из кэш-магазина» одним перезапуском (02.11.2026, слово владельца
#   «Выкладывай сейчас»). Для restart_stack.py, при ОСТАНОВЛЕННОЙ стойке:
#   1. deploy_relay_gift.py --apply  — RelayServer ×3 и ChannelManager пересылают 5076 целиком (237 б), EXE_MD5 в stack_layout.py;
#   2. deploy_p101.py --apply        — AsdaPatch v58 80b8d21b (P01…P101) во все GameServer;
#   3. ConfigSet\patches.ini каждого GS — дописать секцию [P101_CashGift] с Enabled=1, Sites=15 (полный подарок), остальные ключи —
#      шаблон kCashGift. Бэкап ini уже сделал шаг 2 (.bak_20261102_p101). Если секция уже есть — не трогаем, только печатаем.
#   SQL Joy1 (deploy_cash_gift.py) и gp7 (Gp7Gateway/deploy_gp7_gift.py) выкладываются ДО этого скрипта, без перезапуска стойки.
#   «ГОТОВО» — только если прошли все три шага. Откат: [P101_CashGift] Enabled=0 + рестарт; дальше deploy_p101.py --rollback,
#   deploy_relay_gift.py --rollback (порядок — p101/DEPLOY_P101.md §3).
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SECTION = "P101_CashGift"
# Шаблон kCashGift (deploy_p101.py, стр. 6–7), кроме Enabled/Sites — включаем полный подарок
SECTION_TEXT = ("[P101_CashGift]\r\nEnabled=1\r\nSites=15\r\nHoldTimeoutSec=120\r\nSettleMaxSec=1800\r\nMaxInFlight=1\r\n"
                "RouteMaxAgeSec=300\r\nLogChannel=22\r\n")


def run(script):
    """Шаг-скрипт с --apply → (успех, вывод); успех = код 0 и «ГОТОВО» в выводе."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, os.path.join(HERE, script), "--apply"], capture_output=True, env=env, timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    print(out, flush=True)
    return p.returncode == 0 and "ГОТОВО" in out, out


def enable_ini():
    """Дописать [P101_CashGift] Enabled=1 Sites=15 в patches.ini каждого GS (через временный файл, сверка md5) → успех."""
    sys.path.insert(0, HERE)
    from deploy_p90 import rread, rupload, rmd5, rdel   # общие функции SSH (без побочных эффектов)
    import stack_layout
    v2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
    for d in stack_layout.GS_FOLDERS:
        path = v2 + "\\" + d + r"\ConfigSet\patches.ini"
        raw = rread(path)
        # patches.ini пишет сама DLL (Config) в UTF-16LE с BOM — так же и дописываем; иначе ANSI как есть
        wide = raw[:2] == b"\xff\xfe"
        text = raw[2:].decode("utf-16-le") if wide else raw.decode("latin-1")
        if ("[" + SECTION + "]") in text:
            print("%s: секция [%s] уже есть — не трогаю" % (d, SECTION))
            continue
        if not text.endswith("\n"):
            text += "\r\n"
        new = (b"\xff\xfe" + (text + SECTION_TEXT).encode("utf-16-le")) if wide else (text + SECTION_TEXT).encode("latin-1")
        want = hashlib.md5(new).hexdigest()
        fd, tmp = tempfile.mkstemp(suffix=".ini")
        os.write(fd, new)
        os.close(fd)
        try:
            rupload(tmp, path + ".tmp_p101all")
        finally:
            os.remove(tmp)
        if rmd5(path + ".tmp_p101all") != want:
            rdel(path + ".tmp_p101all")
            print("ОТКАЗ: %s — md5 временного ini не совпал" % d)
            return False
        rupload_ok = rmd5(path)
        from deploy_p90 import ps
        rc, out = ps("Move-Item -LiteralPath '%s' -Destination '%s' -Force; Write-Output OK" % (path + ".tmp_p101all", path))
        if rc != 0 or rmd5(path) != want:
            print("ОТКАЗ: %s — ini не записан (было %s): %s" % (d, rupload_ok, out[-300:]))
            return False
        print("%s: [%s] Enabled=1 Sites=15 дописана, patches.ini %s" % (d, SECTION, want))
    return True


def main():
    """Реле/CM → DLL v58 → включение секции в ini; «ГОТОВО» при чистоте всех шагов."""
    if "--apply" not in sys.argv:
        print("сухой прогон: запускать с --apply (из restart_stack.py); по отдельности сухо — deploy_relay_gift.py и deploy_p101.py")
        return 0
    ok, _ = run("deploy_relay_gift.py")
    if not ok:
        print("ОТКАЗ: реле/ChannelManager не выложены; DLL не трогалась")
        return 1
    ok, _ = run("deploy_p101.py")
    if not ok:
        print("ОТКАЗ: DLL v58 не выложена (реле уже выложены; откат — deploy_relay_gift.py --rollback)")
        return 1
    if not enable_ini():
        print("ОТКАЗ: секция [P101_CashGift] не включена (DLL и реле выложены; подарок останется выключен шаблоном)")
        return 1
    print("ГОТОВО: P101 — реле ×3 и ChannelManager (5076 = 237 б), AsdaPatch v58 во всех GS, [P101_CashGift] Enabled=1 Sites=15")
    return 0


if __name__ == "__main__":
    sys.exit(main())
