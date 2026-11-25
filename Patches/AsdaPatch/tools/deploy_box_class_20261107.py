# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_box_class_20261107.py — ВЫКЛАДКА / ОТКАТ: строки 4365–4376 PackageItem_Table и ток.39 item_table у 14 коробок (части 1 и 2) —
#   только оружие капитана своего класса (пачка 12, баг 4, часть 1; разбор Reports/booster_class_20261107). Данные, без патча.
#   Логика — `deploy_premium_boxes.py`: сверка базы по md5, бэкапы, заливка со сверкой, откат. Файлы — data_box_class_20261107.
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет. Выкладка только по слову координатора:
#     python restart_stack.py --deploy deploy_box_class_20261107.py
#   После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_box_class_20261107", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
