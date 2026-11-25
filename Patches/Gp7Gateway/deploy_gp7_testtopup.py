# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
"""Выкладка шлюза gp7 «тестовый режим: пополнение и покупка одной транзакцией» (22.11.2026; ревизия 63 М-5 / Н-3 шага А6.9 админ-центра,
Reports/admin_center/review63_a69_gp7adj_20261122.md; решение владельца «Да, чинить»; отчёт impl_a6_econ_20261121.md §А6.9 «М-5»).

ЧТО МЕНЯЕТСЯ в server.js (только он; SQL, config.json и стойка не трогаются), ТОЛЬКО при testFixedBalance > 0:
  пополнение перед покупкой берёт учётку сайта под UPDLOCK, HOLDLOCK (порядок [user] → GP7Balance, как у GP7_Purchase и adm.GP7Adjust),
  одиночная покупка идёт одной транзакцией с пополнением (корзина уже шла). При testFixedBalance = 0 текст SQL побайтно прежний.

КАК: тот же штатный путь, что deploy_gp7_unconfirmed.py (его stage / quiet / rollback / check-started и стенды alive_stand.js +
unconfirmed_stand.js с живыми таблицами), со своими бэкапом, временным именем и ожидаемым md5 живого файла. Перезапуск — ТОЛЬКО node
gp7-server, после проверки тишины (нет свежих заморозок подарка и покупок в журнале шлюза). Только SSH/scp.

    python deploy_gp7_testtopup.py              — сухой прогон (на сервере ничего не пишет)
    python deploy_gp7_testtopup.py --apply      — бэкап живого server.js в v2\\_backup\\gp7_testtopup_20261122, выкладка, перезапуск шлюза
    python deploy_gp7_testtopup.py --rollback   — проверка тишины, вернуть server.js из бэкапа и перезапустить шлюз
    python deploy_gp7_testtopup.py --quiet | --check-started [минут]

★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                                   # Gp7Gateway\
BAK_DIR = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\gp7_testtopup_20261122"                 # бэкап живого server.js этой выкладки
STAGE = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\gp7-server\server.new_20261122_testtopup.js"      # временное имя на сервере (.js — для node --check)
TASK = "AsdaGp7Restart_testtopup"                                                   # одноразовая задача планировщика запуска
EXPECTED_LIVE_MD5 = "57B4E40DCB8B7468DB248E101AD8F3EB"                              # живой server.js (ревизия 53, 22.11 02:02)


def main(argv):
    """Штатный выкладчик deploy_gp7_unconfirmed.py со своими путями и ожидаемым md5 этой выкладки."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import deploy_gp7_unconfirmed as u
    u.BAK_DIR, u.STAGE, u.TASK, u.EXPECTED_LIVE_MD5 = BAK_DIR, STAGE, TASK, EXPECTED_LIVE_MD5
    return u.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
