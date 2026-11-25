# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_batch_20261107b.py — выкладка 07.11.2026 одним перезапуском (слово владельца: «Yes, release»).
#   Шаги при остановленной стойке: deploy_p114.py, deploy_gear_fix_20261107.py, deploy_veteran_delete_20261107.py.
#   Запуск: py -3.13 restart_stack.py --deploy deploy_batch_20261107b.py
# Режимы: без ключа — сухой прогон шагов; --apply — шаги по порядку, при сбое остановка с кодом 13; --rollback — обратный порядок.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))     # папка инструментов выкладки
STEPS = ["deploy_p114.py", "deploy_gear_fix_20261107.py", "deploy_veteran_delete_20261107.py"]   # шаги выкладки по порядку


def run(script, flag):
    """Запускает шаг с ключом и возвращает код и вывод."""
    args = [sys.executable, os.path.join(HERE, script)] + ([flag] if flag else [])
    p = subprocess.run(args, cwd=HERE, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    return p.returncode, p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")


def main():
    """Выполняет шаги в выбранном режиме; «ГОТОВО» печатается только после успеха всех шагов."""
    apply = "--apply" in sys.argv
    undo = "--rollback" in sys.argv
    flag = "--rollback" if undo else "--apply" if apply else ""
    for script in (list(reversed(STEPS)) if undo else STEPS):
        rc, out = run(script, flag)
        print("== %s %s: код %d\n%s" % (script, flag or "сухой прогон", rc, out), flush=True)
        if rc != 0 or (flag and "ГОТОВО" not in out):
            print("СТОП: шаг %s не прошёл, стойка остаётся остановленной" % script, flush=True)
            return 13
    if flag:
        print("ГОТОВО: пачка 07.11б %s" % ("откачена" if undo else "выложена"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
