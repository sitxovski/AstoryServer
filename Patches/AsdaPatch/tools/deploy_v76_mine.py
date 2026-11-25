# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_v76_mine.py — ОДНА выкладка для restart_stack: AsdaPatch v76 (deploy_p122.py: DLL 5330a12a + [P68_CharNameGuard] Mode=1) и данные
#   карты «Шахта» P120 (deploy_p120.py в режиме «только данные», 54 файла из p120_data/manifest.json) — 09.11.2026, решение владельца
#   «Вместе с Шахтой сейчас». restart_stack принимает один --deploy и зовёт его с --apply; обёртка зовёт оба скрипта по очереди.
#   Порядок: выкладка — сначала deploy_p122 (DLL), потом данные P120 (они проверяют, что на стойке уже v76 или v72); откат — обратный:
#   сначала данные P120 (только изменённые 18 файлов ← бэкап; новые ^MineWar^.* остаются, без строк в ini их не читают), потом deploy_p122.
#   Шаг, вернувший код ≠ 0 или без «ГОТОВО», останавливает цепочку (стойка остаётся остановленной — решает координатор); откат
#   данных с кодом 9 («откатывать нечего») не считается ошибкой.
#   Режимы: без ключей — сухой прогон обоих (только чтение); --apply — выкладка; --rollback или ASDA_V76_MINE_ROLLBACK=1 + --apply — откат;
#   --check-started — проверка старта обоих.
#   Запуск (ТОЛЬКО координатор по слову владельца):
#     py -3.13 restart_stack.py --deploy deploy_v76_mine.py --expect P120_MineTravel --expect P122_PetFuncFloor --expect P121_CharRenameGuard
#         --expect P118_AuctionTradeBlock --expect P68_CharNameGuard --expect P117_PlusPackOnce
#   После старта: py -3.13 deploy_v76_mine.py --check-started
# Журнал шагов — у каждого скрипта свой (run_p122_…, run_p120_…); здесь — сводка в консоль.
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, args, env_add):
    """Запуск шага: (код, вывод). Вывод шага печатается целиком."""
    env = dict(os.environ)
    for k in ("ASDA_P122_ROLLBACK", "ASDA_P120_ROLLBACK", "ASDA_P120_DATA_ONLY"):
        env.pop(k, None)
    env.update(env_add)
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + args, capture_output=True, env=env, timeout=3600)
    out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    print("---- %s %s (код %d) ----" % (script, " ".join(args), p.returncode), flush=True)
    print(out, flush=True)
    return p.returncode, out


def main():
    """Точка входа."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rb = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_V76_MINE_ROLLBACK") == "1")
    check = "--check-started" in sys.argv
    mode = "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"
    print("== deploy_v76_mine %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode), flush=True)
    data = {"ASDA_P120_DATA_ONLY": "1"}
    if check:
        c1, _ = run("deploy_p122.py", ["--check-started"], {})
        c2, _ = run("deploy_p120.py", ["--data-only", "--check-started"], data)
        ok = c1 == 0 and c2 == 0
        print("ПРОВЕРКА СТАРТА v76 + шахта: %s (deploy_p122 %d, данные P120 %d)" % ("всё стоит" if ok else "ЕСТЬ ПРОБЛЕМЫ", c1, c2), flush=True)
        return 0 if ok else 5
    if rb:
        c1, o1 = run("deploy_p120.py", ["--apply"], dict(data, ASDA_P120_ROLLBACK="1"))
        if not (c1 == 9 or (c1 == 0 and "ГОТОВО" in o1)):
            print("СТОП: откат данных P120 не прошёл (код %d) — DLL не тронута, стойка остановлена" % c1, flush=True)
            return c1 or 7
        c2, o2 = run("deploy_p122.py", ["--apply"], {"ASDA_P122_ROLLBACK": "1"})
        if c2 != 0 or "ГОТОВО" not in o2:
            print("СТОП: откат v76 (deploy_p122) не прошёл (код %d) — данные P120 уже откатаны, стойка остановлена" % c2, flush=True)
            return c2 or 7
        print("ГОТОВО: ОТКАТ v76 + шахта (данные P120 %s, DLL ← прежняя). Нужен старт стойки." % ("откатаны" if c1 == 0 else "откатывать было нечего"), flush=True)
        return 0
    if not apply:
        c1, _ = run("deploy_p122.py", [], {})
        c2, o2 = run("deploy_p120.py", ["--data-only"], data)
        ok = c1 == 0 and c2 == 0
        print("сухой прогон v76 + шахта: %s (deploy_p122 %d, данные P120 %d). ⚠ Данные P120 в сухом прогоне сверяют DLL, которая стоит СЕЙЧАС "
              "(v72 допустима); при --apply их шаг идёт после установки v76." % ("всё готово к --apply" if ok else "ЕСТЬ СТОП — смотри выше", c1, c2), flush=True)
        return 0 if ok else (c1 or c2)
    c1, o1 = run("deploy_p122.py", ["--apply"], {})
    if c1 != 0 or "ГОТОВО" not in o1:
        print("СТОП: deploy_p122 не прошёл (код %d) — данные P120 не выкладывались, стойка остановлена" % c1, flush=True)
        return c1 or 7
    c2, o2 = run("deploy_p120.py", ["--apply"], data)
    if c2 != 0 or "ГОТОВО" not in o2:
        print("СТОП: данные P120 не выложены (код %d) — v76 уже стоит; стойка остановлена: старт без шахты допустим (её данных нет — "
              "шахта закрыта), либо откат ASDA_V76_MINE_ROLLBACK=1" % c2, flush=True)
        return c2 or 7
    print("ГОТОВО: v76 (deploy_p122) + данные шахты P120. Дальше restart_stack: start.bat; затем py -3.13 deploy_v76_mine.py --check-started.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
