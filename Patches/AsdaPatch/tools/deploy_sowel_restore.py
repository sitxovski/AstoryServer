# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_sowel_restore.py — выкладка восстановленного SowelCombine.txt (данные заточки хвостовой экипировки, баг 29.10
#   «Military Set cannot be upgraded … 0/0») для restart_stack.py: `--apply` пишет файл, собранный
#   AstoryClient/Tools/ItemDB/server_sowel_tail_restore.py (--build --classes A,B,C --verify), во все GameServer stack_layout.GS_FOLDERS
#   (бэкапы рядом, в v2\_backup и локально — srv_io) и сверяет md5; при успехе печатает «ГОТОВО».
#   Без `--apply` — только показывает, что будет записано.
# Без побочных эффектов при импорте.
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "AstoryClient", "Tools", "ItemDB", "server_sowel_tail_restore.py"))


def run(args):
    """Запуск инструмента восстановления; возврат кода выхода (вывод — сразу в консоль)."""
    return subprocess.run([sys.executable, TOOL] + args).returncode


def main():
    if not os.path.isfile(TOOL):
        print("нет инструмента %s" % TOOL)
        return 2
    if run(["--verify"]) != 0:
        print("ОТКАЗ: собранный SowelCombine.txt не прошёл проверки")
        return 1
    if "--apply" not in sys.argv:
        print("сухой прогон: запись — с --apply")
        return 0
    if run(["--write", "--check-live"]) != 0:
        print("ОТКАЗ: запись/сверка не удалась")
        return 1
    print("ГОТОВО: SowelCombine.txt выложен на все GameServer")
    return 0


if __name__ == "__main__" or globals().get("__spec__") is None:
    sys.exit(main())
