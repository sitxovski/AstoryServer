# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_v79_p119r.py — ОДНА выкладка для restart_stack (09.11.2026, координатор, слово владельца «Да, выкладывай»):
#   AsdaPatch v79 (deploy_p123r3.py: P123 ред. 3 — снят ложный гейт очереди CampWar, закрытые карты GM-у) в 3 GameServer
#   + P119r (deploy_p119r.py: Night_Valley.npc → сток, убраны 10 дублей NPC карты 5) в 6 папках.
#   Выкладка: p123r3, затем p119r; откат — обратный (ASDA_V79P119R_ROLLBACK=1 + --apply или --rollback).
#   Шаг с кодом ≠ 0 или без «ГОТОВО» останавливает цепочку (стойка остаётся остановленной).
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STEPS = ("deploy_p123r3.py", "deploy_p119r.py")          # порядок выкладки
RB_ENV = {"deploy_p123r2.py": "ASDA_P123R3_ROLLBACK"}       # переменная отката шага (если есть)


def run(script, args, env_add):
    """Запуск шага: (код, вывод); вывод печатается целиком."""
    env = dict(os.environ)
    env.pop("ASDA_P123R3_ROLLBACK", None)
    env.update(env_add)
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + args, capture_output=True, env=env, timeout=3600)
    out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    print("---- %s %s (код %d) ----" % (script, " ".join(args), p.returncode), flush=True)
    print(out, flush=True)
    return p.returncode, out


def main():
    """Точка входа: сухой прогон / --apply / --rollback / --check-started по обоим шагам."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rb = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_V79P119R_ROLLBACK") == "1")
    check = "--check-started" in sys.argv
    print("== deploy_v79_p119r %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
          "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"), flush=True)
    if check:
        codes = [run(s, ["--check-started"], {})[0] for s in STEPS]
        ok = all(c == 0 for c in codes)
        print("ПРОВЕРКА СТАРТА v79 + P119r: %s %s" % ("всё стоит" if ok else "ЕСТЬ ПРОБЛЕМЫ", codes), flush=True)
        return 0 if ok else 5
    if rb:
        for s in reversed(STEPS):
            c, o = run(s, ["--rollback"], {})
            if c != 0:
                print("СТОП: откат %s не прошёл (код %d)" % (s, c), flush=True)
                return c
        print("ГОТОВО: откат v79 + P119r", flush=True)
        return 0
    for s in STEPS:
        c, o = run(s, ["--apply"] if apply else [], {})
        if c != 0 or (apply and "ГОТОВО" not in o):
            print("СТОП: шаг %s (код %d) — дальше не иду" % (s, c), flush=True)
            return c or 7
    print("ГОТОВО: v79 + P119r выложены" if apply else "сухой прогон: оба шага готовы", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
