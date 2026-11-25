# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_a5_final.py — ЕДИНАЯ выкладка конца волны А5 админ-центра для restart_stack.py (слово владельца 21.11.2026 «Сейчас»: один
#   общий рестарт): AsdaPatch v84 (deploy_p127e.py, 3 папки GameServer) + LoginPatch v11 L09 (LoginPatch/tools/deploy_l09.py).
# Порядок при ОСТАНОВЛЕННОЙ стойке (--apply, зовёт restart_stack.py): 1) deploy_p127e.py --apply → «ГОТОВО»; 2) deploy_l09.py --apply →
#   «ГОТОВО». «ГОТОВО» этого скрипта — только если оба шага чистые; провал — стоп с перечнем сделанного и командами отката
#   (стойка остаётся остановленной: починить или откатить, затем restart_stack.py --start-only).
# Без ключей — СУХОЙ ПРОГОН обоих (только чтение по SSH). --help / -h — эта шапка без действий; неизвестный ключ — код 1 без действий.
# Запуск: py -3.13 restart_stack.py --deploy deploy_a5_final.py --expect P127_AdminBridge --expect P100_ChargeStack
#   --expect P75_LevelUpPotion --expect P24_FameRatingRevoke --expect P25_GmRatingRecalc
# После старта: deploy_p127e.py --check-started; LoginPatch/tools/deploy_l09.py --check.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
L09 = os.path.normpath(os.path.join(HERE, "..", "..", "LoginPatch", "tools", "deploy_l09.py"))
STEPS = [("AsdaPatch v84", os.path.join(HERE, "deploy_p127e.py")), ("LoginPatch v11 L09", L09)]   # порядок выкладки
ROLLBACK = "deploy_p127e.py --rollback; LoginPatch/tools/deploy_l09.py --rollback (только выполненные шаги, при остановленной стойке)"
KNOWN_KEYS = ("--apply",)


def sub(path, apply):
    """Подскрипт (--apply при выкладке) → (успех, вывод). Успех: код 0 и, при выкладке, «ГОТОВО» в выводе."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, path] + (["--apply"] if apply else []), capture_output=True, env=env, timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    return p.returncode == 0 and ("ГОТОВО" in out if apply else True), out


def main():
    """Точка входа: сухой прогон или выкладка по шагам; код 0 — всё чисто."""
    sys.stdout.reconfigure(encoding="utf-8")
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(open(os.path.abspath(__file__), encoding="utf-8").read().split("import os")[0])
        return 0
    bad = [a for a in args if a not in KNOWN_KEYS]
    if bad:
        print("неизвестный ключ: %s — ничего не сделано" % " ".join(bad))
        return 1
    apply = "--apply" in args
    done = []
    for name, path in STEPS:
        ok, out = sub(path, apply)
        print("== %s (%s)\n%s" % (name, os.path.basename(path), out[-6000:]), flush=True)
        if not ok:
            print("ОТКАЗ: %s — %s" % (name, "не напечатал ГОТОВО" if apply else "сухой прогон не прошёл"))
            print("сделано до отказа: %s" % (", ".join(done) or "ничего"))
            if apply:
                print("откат: " + ROLLBACK)
            return 1
        done.append(name)
    if apply:
        print("ГОТОВО: AsdaPatch v84 + LoginPatch v11 (L09) выложены. Дальше: deploy_p127e.py --check-started, deploy_l09.py --check")
    else:
        print("СУХОЙ ПРОГОН: оба шага готовы к --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
