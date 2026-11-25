# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_item_names_20261106.py — ВЫКЛАДКА / ОТКАТ косметики ItemName_Table.txt: имена коробок 76444–76447, 76452, 76453 = содержимому (06.11.2026,
#   решение владельца; Reports/premium_circle_bike/REPORT_LABELS.md). Файл на всех GameServer стойки, база одна. DLL и шлюз не меняются.
#   Логика выкладки — `deploy_premium_boxes.py` (сверка базы, бэкапы .bak_<tag> / v2\_backup / локальный, заливка со сверкой md5, откат), свой манифест.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор, стойка остановлена:
#     python restart_stack.py --deploy deploy_item_names_20261106.py
#     или шагом общего перезапуска: python deploy_item_names_20261106.py --apply
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет. После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_item_names_20261106", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
