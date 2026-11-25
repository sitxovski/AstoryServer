# Мировые данные — правки владельца 27.09.2026 (STAGING, применяет ВЛАДЕЛЕЦ)

Файлы серверные. На живой сервер НЕ писались. Применить на
`\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\GameServer\...`, затем перезапустить GameServer.
Бэкап оригиналов: `@@ASTORY_DEV_ROOT@@\_backup\2026-09-27_world_data\` (совпадают по размеру).

| Файл в staging | Куда положить (перезаписать) | Что изменено |
|---|---|---|
| `GameServerEvent.txt` | `GameServer\Event\GameServerEvent.txt` | #7 бонус-часы (двойной EXP) продлены: 28.09.2026 → 31.12.2026 (570 новых записей, ставка 1.0). Заголовок 360→930. Старые 360 записей не тронуты. |
| `SunnyCoast_PortalConfig.Ini` | `GameServer\PortalIP_Info\SunnyCoast_PortalConfig.Ini` | #8 точка прибытия на турнирную карту 11 (PORTAL_INFO_1, Index=11): STARTPOSX 63→48, STARTPOSZ 463→460 (= оригинал Castle_of_Chess). |
| `MapWarpCost.txt` | `GameServer\MapData_Info\MapWarpCost.txt` | #9 стоимость телепорта кристаллом Flammio(7)→FirewayForest(16): [7][16] 0→5000. |
| `OpenMapInfo.ini` | `GameServer\MapData_Info\OpenMapInfo.ini` | #10 открыть данжи: MAP_15 dragonlair, MAP_17 Castle_of_Chaos, MAP_18 Inferion — Use 0→1. ★ Дополнено 27.09 (агент lostvalley): **MAP_5 lost — Use 0→1** (вход в LostValley через телепорт у Эллы, см. ниже). Открыто 19 карт ≤ ThreadInfo `COUNT = 21`. |

## После применения на сервере
1. Перезапустить GameServer (владелец).
2. Обновить зеркало реестра карт: в `@@ASTORY_DEV_ROOT@@\AstoryClient\Tools\data\asda_map_registry.json`
   выставить `server.open_use = 1` у карт id 15, 17, 18; затем
   `python Tools/asda_map_registry.py` (перегенерация) и `--check` (0 ошибок).
   Перегенерация меняет C++-заголовок `AsdaMapRegistry.h` → нужна пересборка клиента (build-агент).
   Это чисто для автопути/квест-трекера; на саму возможность входа НЕ влияет.
   ★ После MAP_5: там же `server.open_use = 1` у карты id 5 (до применения `--check` покажет расхождение по 5 — ожидаемо).

## LostValley (MAP_5) — дополнение 27.09 (отчёт `Reports/owner_0927/lostvalley_entry.md`)
- Вход — как в оригинале: NPC-телепорт, опкод 5477 слово 5 (команда диалога 30037). Клиент порта: кнопка
  «Забытая Лощина» у Эллы (NPC 107, Alpen 81,431) — уже в данных порта, самотест пройден.
- Серверу нужно ТОЛЬКО `OpenMapInfo MAP_5 Use = 1` (этот файл). Остальное на живом уже есть и не меняется:
  `Total_PortalConfig [PORTAL_INFO_5] Use=1, 195,470`; `MapWarpCost[3][5] = 0` (бесплатно); `MapInfo.txt` тип 3 (поток создаётся);
  NpcServer: `ini/MapInfo.ini` #5, `Monster/lostvalley.svr` (353 записи) + `.Aif`, `NpcInfo/LostValley.npc`;
  выход `LostValley_PortalConfig` зона 193..198×477..479 → Alpen 80,425 (петли нет: прибытие 195,470 вне зоны; в Alpen у 80,425 зон нет).
- Без `Use = 1` сервер при нажатии кнопки пришлёт 5055, но вход сорвётся (`SearchThreadInfo`: потока карты нет).

## Не входит (описано в отчёте, владелец решает)
- #18 потолок цены личной лавки — правка КОДА сервера (DLL-патч), рецепт в отчёте.
- #10 LostValley (MAP_5) — РЕШЕНО 27.09: вход NPC-телепортом (Элла), Use=1 включён в этот staging (см. выше).
- #9 обратное направление Fireway→Flammio [16][7] осталось 0 — если нужно, добавить симметрично.
