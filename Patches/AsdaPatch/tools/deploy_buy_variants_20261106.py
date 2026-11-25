# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_buy_variants_20261106.py — ВЫКЛАДКА / ОТКАТ SellItemTable.txt для выбора класса и уровня в окне 6000 (06.11.2026; Reports/premium_circle_bike/REPORT_VARIANTS.md).
#   Белый список и цены бустеров (item_table) на всех GameServer стойки; DLL, шлюз и карта gp7 не меняются. Файлы строит build_buy_variants_20261106.py.
#   Логика — `deploy_premium_boxes.py` (сверка базы по md5, бэкапы .bak_<tag> / v2\_backup / локальный, заливка со сверкой, откат), свой манифест.
#   ★ Порядок: сервер РАНЬШЕ клиента, иначе выбранный уровень отказывает. Выкладка ТОЛЬКО по слову владельца, стойка остановлена:
#     python restart_stack.py --deploy deploy_buy_variants_20261106.py
#     или шагом общего перезапуска: python deploy_buy_variants_20261106.py --apply
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет. После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_buy_variants_20261106", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
