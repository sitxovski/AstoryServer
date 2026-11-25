# P59 — журнал редкого дропа с монстров и подбора

- **Дата:** 2026-10-12 (античит, волна A6; план `Reports/anticheat/04_detection_response.md` §6.2 П4).
- **Статус:** собран в копии `AstoryServer/_archive_waves/AsdaPatch_w57` (DLL v36), статика и стенд пройдены; на живой сервер НЕ выложен (интегрирует координатор). **Интегрировано в основную сборку 2026-10-12** (`AstoryServer/Patches/AsdaPatch`, DLL v36 md5 `bfb4dc9f1fe2a8a0cbe0b9878aea64fa`, 540 672 б); стенд `stand_p57` 55/60/55, `verify_p57.py` пройден; **НЕ выложено** — отчёт `Reports/anticheat/wave_INTEG_20261012.md`. Виды `ac.other` 4/5 — без изменений.
- **Процесс:** GameServer.exe (основной и Indun — e7b4ac38, для площадки = сток 4e20f0ad).
- **Тип:** [ПОРТ/СЕРВЕР-ДОРАБОТКА], только журнал — выдача и подбор не меняются.
- **Файл:** `src/patches/p59_rare_drop_journal.cpp`; секция ini `[P59_RareDropJournal]`; общие точки в `p11_announce_sources.cpp` (`P11_IsRareCode`, `P11_EnsureGradeTable`, трамплин подбора).

## Что и зачем

Сток дроп с монстров **не журналирует**: NpcServer присылает список добычи (опкоды `0x206F` обычный / `0x1F4A` рейд; диспетчер `GameServer.c:20654/20714`) → `recvBattleServerFromItemDrop@0x4C9370` (`:79972`) → `Search_AddMonsterMapItem@0x420120` кладёт предметы на карту; строк лога нет (кроме отказа «iSellType Error»). Подбор 5012 `CharItemPicking` сток тоже не пишет (строки в Log_Item появляются только по P11 при анонсе). Для разбора «откуда у игрока редкая вещь» (дюп, подброс, чужой лут) в логах нет ни точки выдачи, ни точки подбора.

P59:
- **Дроп.** Вход `recvBattleServerFromItemDrop` (пролог 9 б, возврат `0x4C9379`): тело пакета (+9, 0x82 б) `{i16 userNum убийцы, i16 индекс монстра, i16 клетка X, i16 клетка Z, int код[20], i16 количество[20], i16 золото}` — ровно то, что читает сток (`:79979-80037`; список кончается первым кодом ≤ 0). Для каждого кода из таблицы «редкого» — строка в канал `LogChannel` (29 = `Log_UserEvent`, папка есть, в стоке туда пишут только `Recv_UserEventItemStack*`) и журнал P53 `ac.other` вид 4: `item_code` код, `value1` количество, `value2` индекс монстра, `detail` «имя монстра, клетка, рейд» (имя — из таблицы Monster.ai `0x5F5F80`, запись 44 б: +0 индекс, +4 имя; чтение под SEH с проверкой индекса записи), `user_index/char_name/ip` — убийца.
  ```
  P59 RareDrop\tItem 61785 x3\tMonster 5 (Wolf)\tTile 12,34\tKiller UserNum 7 UserIndex 75001 CharN Tester\tRaid 0
  ```
- **Подбор.** Общая точка P11: эпилог `CharItemPicking` `0x4D5E61` (успешный подбор, запись предмета 60 б в кадре) — `AsdaOnPickup` теперь первым делом зовёт `P59_OnPickup`; P11 ставит трамплин, если он нужен ему **или** нам (`P59_PickupWanted()`), то есть и при `PickupEnabled=0`. Строка `P59 RarePickup\tItem %d\tUserNum %d\tUserIndex %d\tCharN %s\tMap %d` + `ac.other` вид 5.
- **Порог «редкого»** — та же таблица, что у P01/P11 (`[P11_ServerAnnounceSources] GradeTableFile`, по умолчанию `ConfigSet\announce_codes.txt`: `item_list` грейд ≥ 3 и тип ≤ 9 или 11/200; `sowell_list` грейд ≥ 3; 644 диапазона, 9886 кодов; генератор `tools/gen_announce_codes.py`). Таблица грузится один раз на DLL (`P11_EnsureGradeTable`); пустая таблица → патч не ставится (`Failed`, строка в PatchLog).
- **Ограничитель** `MaxPerMinute` на процесс (писатель `sub_569DF0` — одна глобальная секция записи; план §6: только редкие события): сверх — считается, число подавленных уходит в `repeat_suppressed` следующей строки.

## Площадка «было → стало»

| VA | Было (сток) | Стало |
|---|---|---|
| `0x4C9370` (9 б) | `55` `push ebp`; `8B EC` `mov ebp,esp`; `81 EC 9C 00 00 00` `sub esp,9Ch` | `E9` → `DropStub`: `pushad`; `P59_OnMonsterDrop(mgr=ecx, pkt=[esp+4], raid=[esp+8])`; `popad`; вытесненный пролог; `jmp 0x4C9379` |

Сосед `0x4C9379` = `A1 F0 63 5A 00` (`mov eax,[security_cookie]`). Переходов внутрь пролога нет (функция зовётся из диспетчера `call`-ами на начало). С P01…P58 не пересекается; трамплин подбора — площадка P11 (`0x4D5E61`), новых площадок для подбора нет.

## Конфиг

```ini
[P59_RareDropJournal]
Enabled=1
Pickup=1          ; журналировать и подбор (через трамплин P11)
LogChannel=29     ; 29 Log_UserEvent, 1 Log_Item, 0 Log_Game
MaxPerMinute=120
```
Порог редкости — `[P11_ServerAnnounceSources] GradeTableFile` (общий с анонсом 6616/6131).

## Проверка

- `tools/verify_p57.py`: байты пролога и соседа в трёх образах, переходов внутрь нет, граница инструкций; стаб найден, `jmp [..]` → `0x4C9379`; unicorn: `P59_OnMonsterDrop(mgr, pkt, raid)` получает `(ecx, [esp+4], [esp+8])`, пролог воспроизведён (`ebp = esp−4`, прежний ebp сохранён, `esp −= 0x9C`), `ecx/ebx/esi/edi` целы.
- `tools/stand_p57/`: обычный код — ничего; редкий ×3 — строка в канал 29 с монстром/клеткой/убийцей; редкий во 2-м слоте + рейд; подбор редкого через трамплин P11 при `PickupEnabled=0`; `MaxPerMinute=3` — 4-я строка подавлена; подбор обычного — ничего; в файловом журнале P53 — 2 строки вида 4 и 1 вида 5.
- На живом: `PatchLog` строка `P59: дроп с монстров → канал 29 + ac.other вид 4; подбор=1 …; таблица редких: 644 диапазонов`; в `Log\Log_UserEvent\UserEvent_<дата>.txt` строки `P59 RareDrop`/`P59 RarePickup`; в `joylog1.ac.other` виды «P59: редкий дроп с монстра» / «P59: подбор редкого предмета».

## Откат / рестарт

`Enabled=0` + рестарт GameServer/Indun. При `Enabled=0` трамплин подбора P11 ставится только по его собственному `PickupEnabled`. DLL v35 сама опустит `Version` и проигнорирует секцию.
