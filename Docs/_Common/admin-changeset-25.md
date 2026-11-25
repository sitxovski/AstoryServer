# Набор изменений админ-центра №25 «P69 боевой режим (Mode=1) — слово владельца 22.11»

* **Процесс / путь:** GameServer, Indun_GameServer, Ch2_GameServer — `ItemTable_Info\` (таблицы магазинов)
* **Тип:** данные, выкладчик `deploy_changeset.py` через restart_stack
* **Бэкап:** `.bak_<метка>` рядом, `v2\_backup\<метка>`, `@@ASTORY_DEV_ROOT@@\_backup\<дата>_cs25`
* **Откат:** `python asda_admin.py changeset server-rollback 25 --confirm-restart`
* **Рестарт:** да (GS читает таблицы при старте)

## Журнал
* 22.11.2026 — серверная половина применена (метка 20261122_cs25): AsdaPatch [P69_IntegrityAutoBlock] Mode: 0 → 1 (ConfigSet\patches.ini: GameServer, Indun_GameServer, Ch2_GameServer; действует после рестарта стойки)
