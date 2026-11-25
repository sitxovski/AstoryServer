# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p89_job4rows.py — общая выкладка 26.10.2026 за один рестарт стойки: AsdaPatch P89 (deploy_p89.py) + строки
# стартовых навыков 4-й профессии для подклассов 6/17/28 (AstoryServer/Docs/job4_start_skills_1026/apply_job4_rows.py).
# Решение владельца 26.10: «применяй выведенные стартовые навыки для 6/17/28 (вместе с выкладкой P89)».
# Вызывается restart_stack.py с --apply; печатает «ГОТОВО» только если оба шага напечатали «ГОТОВО».
#   python restart_stack.py --deploy deploy_p89_job4rows.py --expect P87_Job4StartSkills --expect P88_TitleEvents --expect P89_Job4GateBranch
# Откат: deploy_p89.py --rollback и apply_job4_rows.py --rollback (при остановленных GameServer/Indun).
import os
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
STEPS = [os.path.join(TOOLS, "deploy_p89.py"),
         os.path.normpath(os.path.join(TOOLS, r"..\..\..\Docs\job4_start_skills_1026\apply_job4_rows.py"))]


def main():
    """Запускает оба шага с теми же ключами; итог «ГОТОВО» только при успехе обоих."""
    for step in STEPS:
        p = subprocess.run([sys.executable, step] + sys.argv[1:], capture_output=True,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        print("== %s (код %d)\n%s" % (os.path.basename(step), p.returncode, out.strip()))
        if p.returncode != 0 or ("--apply" in sys.argv and "ГОТОВО" not in out):
            print("СТОП: шаг %s не прошёл" % os.path.basename(step))
            return 1
    if "--apply" in sys.argv:
        print("ГОТОВО: P89 и строки 6/17/28 выложены")
    return 0


if __name__ == "__main__":
    sys.exit(main())
