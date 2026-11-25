# P96 — сумка 60 ячеек: DBManager отдаёт до 60 строк сумки + SQL-волна «инвентарь ×2» (вес ×2)

| Поле | Значение |
|---|---|
| Дата | 2026-10-30 (задача владельца 29.10 «инвентарь ×2»: сумка 30 → 60, вес ×2) |
| Статус | **собрано, проверено, НЕ выложено** (DLL); SQL — **проверено стендом в транзакции с откатом, НЕ применено** |
| Процессы | `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\DBManager\DBManager.exe` (MD5 `3d05c835…`, с импортом `DBPatch.dll`); SQL Server `Joy1`, `AsdaStoryOp` |
| Тип | ① бинарный в памяти — `DBPatch.dll`, 4 imm8 по сигнатуре (без трамплина); ② SQL: 2 функции, 1 таблица-метка, 2 таблицы снимка, ALTER 7 процедур, UPDATE MaxWeight, служебная `Posx` |
| Секция ini | `ConfigSet\dbpatch.ini` → `[P96_DbShellRows]`, `Enabled` (по умолчанию `1`; `0` = сток, 30 строк); `Config::kVersion` 9 → **10** |
| Артефакт | `AstoryServer/Patches/DBPatch/out/DBPatch.dll` MD5 **`740562a4b82cb616751a320acf60450e`**, 255 488 б (живая v9+P85 `9376a6bf…`, 246 272 б — бэкап `@@ASTORY_DEV_ROOT@@\_backup\2026-10-29_inventory_x2\AstoryServer\Patches\DBPatch\out\`) |
| Протокол | не меняется: пачки 2040 (Userindex + ≤ 8 записей × 57 б), конец 2041; при 60 строках пачек 8 вместо 4 |
| Рестарт | да — DBManager (вся стойка одним окном, PLAN §5) |
| Пара | AsdaPatch `P96_InventoryX2` + `P96_WeightU16` (GameServer/Indun/Ch2), клиент (`asda.Inven.ShellX2`, `asda.Weight.Unsigned`) — **выкладывать вместе** |

План: `Reports/inventory_x2/PLAN.md` §3.2, §3.3, §5. Разборы: `_research/db_dbm_other.md` §2, `_research/weight.md` §4, §6.

## ЗАЧЕМ (DBManager)

Сумку (Plate 1) DBManager читает `EXEC UPPlateItem …,1` (ORDER BY Posx, без TOP; строка 57 б) и отдаёт GameServer пачками.
Перед отправкой — обрезка «строк > 30 → 30» (журнал `UPPlateItem SHELLINVEN_SLOTNUM …`), в двух функциях:

| Функция | Когда | Ячейка счётчика | Площадки (живой = сток) |
|---|---|---|---|
| `sub_422C20` Send_ShellInvenItem | DB `0x7F7` DBM_SHELLINVENINFO_REQ | `[ebp-0x3CE4]` | `0x422E61` `83 BD 1C C3 FF FF 1E` cmp; `0x422E96` `C7 85 1C C3 FF FF 1E 00 00 00` mov |
| `sub_423600` Send_AllInventoryItem | вход `0x7D1` (2001) и портал `0x829` (2089), Plate 1 | `[ebp-0x738C]` | `0x423785` `83 BD 74 8C FF FF 1E` cmp; `0x4237B4` `C7 85 74 8C FF FF 1E 00 00 00` mov |

Строки идут по Posx, поэтому при 31+ предмете молча отбрасывались бы ячейки 30..59: GameServer считает их пустыми, кладёт туда
новый предмет, `INSERT` в `Item` падает на PK `(Userindex, Charidx, Plate, Posx)`. Декомпил: `RE/ida/db_work/DBManager.exe.c:16145`, `:16369`.

## ЧТО (DBManager)

`1Eh → 3Ch` в четырёх местах (длина инструкций та же). **По сигнатуре, не по адресу**: 10-байтные сигнатуры
(`83bd1cc3ffff1e7e360f`, `c7851cc3ffff1e000000`, `83bd748cffff1e7e300f`, `c785748cffff1e000000`) ищутся во всём `.text`
образа; совпадение должно быть **ровно одно**, и сверяется связка «cmp → `jle` сразу за ним → ведёт за `mov` → та же ячейка
кадра». Иначе — `Mismatch`, ничего не пишется (всё или ничего). На 30.10 адреса в живом образе `3d05c835…` и стоке
`DBManager-Original.exe 4cec9b61…` совпадают; найденный другой адрес пишется в журнал как «сдвиг».

Буферы (перепроверено по декомпилу и дизасму): приёмник строк `14000/14004 б` (`sub_4073D0` и так отказывает при rows×57 ≥ 14000),
60 × 57 = 3420; пачка 472 б (memset `0x1D6`), отправка при заполнении `> 0x19D` → максимум 4 + 8·57 = 460 — от числа строк не
зависит. Расходники (Plate 2) уже `3Ch` той же схемой (`0x423315/0x42334A`, `0x423AEA/0x423B19`) — не трогаются.
Журнал DBManager «SHELLINVEN_SLOTNUM» остаётся, теперь — только при > 60 строк. Рантайм-кода нет.

## Проверки (DBManager)

* `AstoryServer/Patches/DBPatch/tools/verify_p96_db.py` — **45 OK / 0 ошибок**: оба образа (живой и сток из зеркала SSH), сигнатуры
  ×1 на своих адресах, связка cmp/jle/mov, журнал между ними, граница цикла пачек на той же ячейке, буферы, расходники 3Ch,
  нет переходов/abs32 внутрь, имитация патча меняет ровно 4 байта; пересечений с `DBPatch/src` и `SITES_DB` (verify_dll.py) нет;
  в DLL есть секция и все 4 сигнатуры.
* Стенд `DBPatch/tools/stand_p96_db` (НАСТОЯЩАЯ DLL ставит патч в разложенный образ; НАСТОЯЩИЙ код 0x7F7 и 2001/2089 с заглушками
  memcpy/memset/журнала/Sleep/отправки, N = 0…70 строк): режимы **on 29/0, off 29/0, mismatch 29/0, dup 30/0**, плюс on на стоке
  29/0. on: N=31 → 31 запись, N=60 → 60 в 8 пачках, N=61/70 → 60 + журнал; off/mismatch/dup: N=31 → 30 (дефект воспроизводится),
  площадки не тронуты. Пачки ≤ 460 б, заголовок = Userindex, порядок записей верный, 2041 в конце, стек сбалансирован.
* Сборка `build.bat` — без ошибок и предупреждений. ⚠ В DLL попали и изменения общего `AsdaPatch/src/AcJournal.cpp` от 29.10
  (только тексты видов ac.other 140–144 волны P95) — на DBManager не влияют.

## Выкладка / откат (DBManager)

* Выкладка — **только координатор**, одним окном с AsdaPatch P96 и SQL: `python @@ASTORY_DEV_ROOT@@\AstoryServer\Patches\DBPatch\tools\deploy_p96_db.py`
  (сухой прогон 30.10 00:14 — «готово»: живая `9376a6bf…`, DBManager.exe `3d05c835…`; DBManager работал — к `--apply` остановить),
  `--apply` (бэкапы `.bak_20261030_p96`, `v2\_backup\2026-10-30_inventory_x2\`, локально `_backup\2026-10-29_inventory_x2\server\v2\`),
  после старта `--check` («[OK] P96_DbShellRows», строка «P96db: 0x00422E61/…»). Можно звать из `restart_stack.py --deploy <полный путь>`.
* Откат: `deploy_p96_db.py --rollback` или `[P96_DbShellRows] Enabled=0` + рестарт DBManager. ⚠ **Перед откатом сумки** —

## БД — SQL-волна `inventory_x2_*_20261030` (вес ×2, служебная Posx)

Вариант А разбора weight.md §6: вес — **u16 побитно** в тех же smallint (схема, протокол, DBManager, LoginManager не меняются).

| Файл | Что |
|---|---|
| `10_verify` | только чтение: V1–V9 (предметы каждого персонажа = снимок, Del_item, итог Item, MaxWeight = 2× снимок, Del_Charinfo, метки/функции, Posx 0..59, типы результата UPCharInfo smallint и @CharWeight int) |
| `rollback_check` | «есть ли Plate 1 Posx ≥ 30» (Item и Del_item) — перед откатом сумки |

[ИСПРАВЛЕНИЕ] попутно: в стоке `@We = SUM(Weight)` у персонажа без предметов вне склада = NULL → `Charinfo.Weight NOT NULL` падал
(вход/выход ломался) — теперь 0.

**Стенд** `inventory_x2_stand_20261030.py` — настоящие файлы на настоящих данных dev Joy1 в одной транзакции с ROLLBACK (сторож
`@@TRANCOUNT` между частями — у UPCreateChar внутренний ROLLBACK): VERIFY **9/0** (35 персонажей, 0 расхождений предметов,
MaxWeight 15000→30000 ×18, 18750→37500 ×5, 22500→45000 ×1, 30000→60000 ×10, 32000→64000 ×1; Del_Charinfo 5/0), STAND **12/0**:
UPCreateChar → 30000; вес предметов 43 364 — UPCharInfo/UPLogOutGame/UPPortalLogOut не падают, Weight = u16; UPMaxWeight
56250+3750 = 60000, потолок, 30000+3750 = 33750, −3750 = 30000, 64000+3750 = 64000, 64000−3750 = 60250; повторный 01 не удваивает;
откат 99 — 7/7 процедур = сток по md5, MaxWeight = снимок 35/35, Del 5/5; после ROLLBACK TRAN БД **чистая** (проверено). Блок BACKUP
проверен разбором `SET NOEXEC ON` (место посчитано), сам бэкап НЕ делался.

Откат: `rollback_check` → `99_rollback`. Файлы заливать scp и `sqlcmd -S localhost\SQLEXPRESS -E -b -f 65001 -i …` (образец `deploy_p94.py`).

## Утилиты

`AstoryAdminCenter/tools/Admin/asda_give.py`: `PLATE_CELLS = {1: 60, 2: 60}`; фактическая ёмкость сумки 1 — `_plate_cells()`: 60 только при метке
`MaxWeight & 0xFFFF`. Прочие инструменты `Tools` и `AstoryAdminCenter/DiscordBot` вес/ячейки сумки не пишут (только чтение Plate/Posx).

## Риски

* DBManager и GameServer — только вместе (PLAN §4 п. 2); старый клиент со слотами ≥ 30 несовместим (п. 1).
* GM_sitxovski: 32000 → 64000 (> потолка 60000, прибавка его не уменьшает); при желании владельца — выставить 60000 вручную.
* После выкладки `Charinfo.MaxWeight/Weight` у части персонажей отрицательные в «сыром» smallint — это u16; любые внешние
  читатели должны брать `& 0xFFFF` / `dbo.fn_U16`.
