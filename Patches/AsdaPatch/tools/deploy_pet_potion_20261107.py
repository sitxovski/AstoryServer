# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_pet_potion_20261107.py — ВЫКЛАДКА / ОТКАТ коробки 79940 «Зелье нового уровня питомца x2»: item_table, SowelCombine, PackageItem_Table, SellItemTable на всех GameServer. Файлы строит build_pet_potion_20261107.py.
#   ★ Порядок: только ПОСЛЕ deploy_box_class_20261107.py (база item_table 33b27fff, PackageItem_Table 77d9c0c5) и вместе с клиентом: старый клиент кода 79940 не знает.
#   Логика — `deploy_premium_boxes.py`: сверка базы по md5, бэкапы, заливка со сверкой, откат. DLL, шлюз и карта gp7 не меняются.
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет; до выкладки box_class он покажет расхождение базы. Выкладка только через координатора, стойка остановлена:
#     python restart_stack.py --deploy deploy_pet_potion_20261107.py
#   После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_pet_potion_20261107", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
