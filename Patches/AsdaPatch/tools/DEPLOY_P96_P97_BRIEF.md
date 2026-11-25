# Выкладка P96 (инвентарная сумка 30→60) + P97 (вес u16) — бриф для сессии

## Статус: ГОТОВО К ВЫКЛАДКЕ

Код написан, собран, верифицирован, регрессия пройдена (501 прогон, 0 провалов по P96/P97).
Выкладка на сервер **не выполнена** — владелец остановил процесс.

## Что выкладывать

### 1. AsdaPatch.dll → все GameServer (3 папки)

| | Значение |
|---|---|
| Собранная DLL | `AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll` |
| MD5 новой | `a8480800f903d4f5452df45d1a2b730b` |
| MD5 живой (PREV) | `cc26b99531705a7cbdac4170adbdb0e2` (v54, P01…P95) |
| Куда | `GameServer/`, `Indun_GameServer/`, `Ch2_GameServer/` (stack_layout.GS_FOLDERS) |
| Config version | 56 (v55 = P96, v56 = P97) |
| Новые патчи | P96_InventoryX2, P97_WeightU16 |

### 2. DBPatch.dll → DBManager (1 папка)

| | Значение |
|---|---|
| Собранная DLL | `AstoryServer/Patches/DBPatch/out/DBPatch.dll` |
| MD5 новой | `740562a4b82cb616751a320acf60450e` |
| MD5 живой (PREV) | `9376a6bf64f0ba26066c6bb4032b6c13` (v9) |
| Куда | `DBManager/` |
| Новый патч | P96_DbShellRows (обрезка строк сумки >30 → до 60) |

### 3. GameServer.exe — НЕ МЕНЯТЬ

MD5 всех трёх: `e7b4ac38e8328aaa847bbd9bf261bb01` (площадки сверены по нему).

## Скрипт выкладки

**Готов**: `AstoryServer/Patches/AsdaPatch/tools/deploy_p96_p97.py`

Режимы:
- `--apply` — выкладка (при остановленной стойке): сверка md5, бэкапы (рядом `.bak_20261030_p96p97` + `v2\_backup\2026-10-30_p96p97` + локально `_backup/2026-10-30_p96_p97/server/v2`), заливка scp, проверка.
- `--rollback` — откат из бэкапов.
- `--check-started` — проверка после старта: DLL md5, PatchLog `[OK] P96_InventoryX2` / `[OK] P97_WeightU16`, MISMATCH 0.

Быстрое отключение без замены DLL: `[P96_InventoryX2] Enabled=0` и/или `[P97_WeightU16] Enabled=0` в patches.ini + рестарт.

## Команда рестарта

```bash
python restart_stack.py --deploy deploy_p96_p97.py --expect P96_InventoryX2 --expect P97_WeightU16
```

restart_stack.py сам: объявление бота в Discord (#test-info, 3 мин) → ожидание → стоп стойки → deploy --apply → паритет Ch2_* → start.bat → проверка 15 процессов.

## Правила выкладки (из MEMANTO)

1. **Предупредить владельца в чате** заранее (что, зачем, когда) — перед ЛЮБЫМ перезапуском.
2. Объявление ботом в #test-info обязательно (restart_stack делает).
3. SSH: `Administrator@@@ASTORY_SERVER_VPN_IP@@`, ключ `@@ASTORY_SSH_KEY_NAME@@`, правка только в `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2`.
4. Шару `\\@@ASTORY_SERVER_HOSTNAME@@` **НЕ трогать**.
5. Два полевых канала — deploy/скрипты **только через stack_layout.py** (Ch2_* = копия поля).

## Регрессия (30.10.2026)

- **run_checks.py**: 501 прогон, 25 010 OK, 0 провалов по P96/P97.
- Все rc!=0 — предсуществующие: verify_p63 (1), verify_p87 (4), p82 ini-косметика (v53→v56), stand_map (P29/P30 Failed).
- **verify_dll.py**: площадки P96 0 расхождений, площадки P97 0 расхождений (все 3 образа + DBManager).
- **Сборка**: 0 ошибок, 0 предупреждений (production + stand).

## Строки для changelog (с причиной)

**P96:**
> Инвентарная сумка (контейнер 1) расширена с 30 до 60 ячеек. Боковое хранилище `g_bag` в DLL — старый массив `CUser[0x4BC]` не вмещал 60×57 байт на слот. 9 роутеров перехвачены подменой указателя, 19 границ контейнера обновлены, 4 сайта DBManager обновлены. P95 (гейт предметов) читает `P96_BagSize()` для динамической границы. Античит: виды 145–147.

**P97:**
> Поле веса предмета переведено с signed i16 (макс 32 767) на unsigned u16 (макс 65 535), потолок увеличения предметами поднят с 30 000 до 60 000. 129 точек movsx→movzx, 10 пересчётов регистра, 5 трамплинов аккумулятора CraftEnter. P35 использует `P97_WeightU16Active()` для корректной u16 арифметики. **Причина:** signed i16 переполнялся при весе > 32 767 — вес становился отрицательным и предмет «исчезал» из проверок.

## Файлы, затронутые этой волной

| Файл | Что |
|---|---|
| `src/patches/p96_inventory_x2.cpp` | Новый — патч P96 |
| `src/patches/p97_weight_u16.cpp` | Новый — патч P97 |
| `src/patches/Patches.h` | + объявления P96/P97 |
| `src/patches/Registry.cpp` | + записи P96/P97 |
| `src/Config.h` | version 54→56 |
| `src/Config.cpp` | + секции kInventoryX2/kWeightU16 |
| `src/patches/p95_item_use_guard.cpp` | P96_BagSize() вместо 30 |
| `src/patches/p35_craft_server_defects.cpp` | P97_WeightU16Active() u16 арифметика |
| `tools/verify_dll.py` | + площадки P96 |
| `tools/deploy_p96_p97.py` | Новый — скрипт выкладки |
| `AstoryServer/Docs/GameServer/ac-journal-p53.md` | Виды 145–147 для P96 |

### DBPatch (отдельный проект)

| Файл | Что |
|---|---|
| `AstoryServer/Patches/DBPatch/src/patches/p96_db_shell_rows.cpp` | Новый — P96_DbShellRows |
| `AstoryServer/Patches/DBPatch/src/patches/Patches.h` | + объявление |
| `AstoryServer/Patches/DBPatch/src/patches/Registry.cpp` | + запись |
| `AstoryServer/Patches/DBPatch/src/Config.h` | version 9→10 |

## Бэкапы

Локальный бэкап модифицированных файлов: `@@ASTORY_DEV_ROOT@@\_backup\2026-10-30_p96_p97\`.
Серверные бэкапы создаст deploy_p96_p97.py при `--apply`.
