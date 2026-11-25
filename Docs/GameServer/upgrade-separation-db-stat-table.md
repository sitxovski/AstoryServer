# Разделение улучшения: «DB Error» — нет таблицы joylog1.dbo.Stat_UpgradeSeparation (01.11.2026)

**Статус:** ВЫЛОЖЕНО 01.11.2026 по прямому указанию владельца («создай таблицу. выполни скрипт»): fix выполнен на живом dev, RC=0; verify — таблица есть, 14 колонок, процедура не тронута (modify_date 2026-06-18, md5 D8B51A45…). Стенд 17/17. **Ярлык:** [ИСПРАВЛЕНИЕ] — дефект стоковой БД.

## Симптом
Живой dev, клиент 5.1.0: «Flame Grimreaper's Ballista» (63033) +86 % в сумке 1/30, пустые оружейные камни 400 ×10 в 1/58,
«Разделение» → подтверждение → окно «DB Error» (6550 код 98, клиент `AsdaUpgradeSplitSubsystem.cpp` case 98 → kErrDb).

## Цепочка (доказано журналом и текстами)
1. GameServer `Recv_UserUpgradeExtraction@0x534640` все проверки проходит (иначе коды 2–6), шлёт DBManager 2527 (242 б).
2. DBManager `sub_438BD0@0x438BD0`: `EXEC UpItemupgradeSeparation …` (62 параметра). Запрос не выполнился ⇒ ответ 2528 с кодом **98**
   (99 — процедура выполнилась, но вернула Flag ≠ 1).
3. `OLEDB_LOG\LOG_FILE_20261101.Txt` 03:33:49: `HRESULT Error : DB_E_NOTABLE … EXEC UpItemupgradeSeparation 1,10,2,63033,1,30,0,7,7,0,400,1,58,10,10,-1,…,401,1,34,1,1,10,10,10,86,44,8,0 :: Execute Error`.
   `INSERT INTO JoyLog1.dbo.Stat_UpgradeSeparation(...)`; в joylog1 этой таблицы нет (таблиц `Stat_*` нет вообще). Отложенное разрешение
   имён ⇒ ошибка 208 при выполнении, XACT_ABORT ON ⇒ откат всей транзакции (вещь и камни у владельца целы: 400 ×10 в 1/58).
5. Параметры от клиента/сервера верны: вещь 1/30 (вторая половина сумки P96), камни 1/58, Dt=Da=10, готовый камень 401 (P99 действует), ячейка 1/34.

## Правка
процедуры, типы — её параметры). Процедура, протокол, GameServer, DBManager, клиент не меняются. Рестарт стойки не нужен. Повтор безопасен.
* Стенд: `upgrade_separation_stand_20261101.py` — tempdb, живые таблицы только читаются, ROLLBACK: T0 сток с дословными параметрами
  владельца = ошибка 208 по Stat_UpgradeSeparation; T1 провал (State 3, 10→5 камней); T2 успех с параметрами владельца (стопка удалена,
  вещь 0/7/7/0, камень 401 в 1/34 +86 % опция 44=8); K0 идемпотентность; K1 откат; K2–K4 следов нет. **17/17.**

## Попутно (не правилось)
Сплошной поиск по `sys.sql_expression_dependencies`: ещё 15 процедур Joy1 ссылаются на несуществующие таблицы JoyLog1 —
CRT_UPItemInsert, OpItemAdd, UP_FETCH_SHELL, UP_FETCH_SPEND, UpCampRewarditem (4 таблицы), UPChargeItemBuy, UPExchangeItemBuy,
UPGotChaCashItemBuy (2), UPGotChaTransItem, UPNewItemRefine, UPSkillItemBuy. Падают ли они — зависит от ветки, где стоит INSERT (не проверено).
