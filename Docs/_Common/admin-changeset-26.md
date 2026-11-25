# Набор изменений админ-центра №26 «P129 заглушки чата действуют (Mode=1) — слово владельца 22.11»

* **Процесс / путь:** GameServer, Indun_GameServer, Ch2_GameServer — `ItemTable_Info\` (таблицы магазинов)
* **Тип:** данные, выкладчик `deploy_changeset.py` через restart_stack
* **Бэкап:** `.bak_<метка>` рядом, `v2\_backup\<метка>`, `@@ASTORY_DEV_ROOT@@\_backup\<дата>_cs26`
* **Откат:** `python asda_admin.py changeset server-rollback 26 --confirm-restart`
* **Рестарт:** да (GS читает таблицы при старте)

## Журнал
* 22.11.2026 — серверная половина применена (метка 20261122_cs26): AsdaPatch [P129_ChatLog] Mode: 0 → 1 (ConfigSet\patches.ini: GameServer, Indun_GameServer, Ch2_GameServer; действует после рестарта стойки)
