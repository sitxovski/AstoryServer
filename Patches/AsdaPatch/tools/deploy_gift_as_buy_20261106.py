# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_gift_as_buy_20261106.py — ВЫКЛАДКА / ОТКАТ таблиц «подарок = покупка себе» (06.11.2026, решение владельца; Reports/premium_circle_bike/REPORT_GIFT.md):
#   SellItemTable.txt и item_table.txt на всех GameServer стойки. DLL, шлюз и карта gp7 не меняются. Файлы строит build_gift_as_buy_20261106.py.
#   Логика — `deploy_premium_boxes.py` (сверка базы по md5, бэкапы .bak_<tag> / v2\_backup / локальный, заливка со сверкой, откат), свой манифест.
#   ★ Порядок: сервер РАНЬШЕ клиента. Клиент с `asda.PremiumMall.GiftAsBuy` 1 шлёт код коробки; без этих таблиц GS откажет (5075 код 0).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор, стойка остановлена:
#     python restart_stack.py --deploy deploy_gift_as_buy_20261106.py
#     или шагом общего перезапуска: python deploy_gift_as_buy_20261106.py --apply
#   Сухой прогон (по умолчанию): сверка базы, ничего не пишет. После старта (чтение): --check-started. Откат (стойка остановлена): --rollback.
#   Если базу сменила другая выкладка, скрипт остановится: пересобрать билдером по свежему снимку.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_premium_boxes as base   # noqa: E402  общие шаги выкладки; импорт без побочных эффектов


def main():
    """Запуск общей логики со своим манифестом."""
    base.MANIFEST = os.path.join(HERE, "data_gift_as_buy_20261106", "manifest.json")
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
