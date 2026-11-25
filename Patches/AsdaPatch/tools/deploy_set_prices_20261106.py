# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_set_prices_20261106.py — ВЫКЛАДКА / ОТКАТ следующей пачки: цены 40 наборов (item_table) и чистка белого списка от коробок 75843–75851 (SellItemTable). Файлы строит build_set_prices_20261106.py.
#   Логика — `deploy_premium_boxes.py`: сверка базы по md5, бэкапы, заливка со сверкой, откат. DLL, шлюз и карта gp7 не меняются.
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет. Выкладка только по слову владельца, стойка остановлена:
#     python restart_stack.py --deploy deploy_set_prices_20261106.py
#   После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_set_prices_20261106", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
