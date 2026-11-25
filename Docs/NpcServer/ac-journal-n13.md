# NpcServer — журнал нарушений скорости атаки в базе (N13 = P53, сторона NpcServer)

| поле | значение |
|---|---|
| **Дата** | 2026-10-12 (волна acdb) |
| **Статус** | ✅ собран (`AddonNPC.dll` v4, N01…N13); стенда на живом коде NpcServer нет — запись проверена общим модулем журнала на стендах GameServer/DBManager; площадки сверяются самой DLL при установке. Выкладка — см. INDEX.md (запись 12.10 acdb) |
| **Процессы** | `NpcServer`, `Indun_NpcServer` (импорт `AddonNPC.dll`) |
| **Флаги** | `ConfigSet\patches.ini` → `[P53_AcJournal]`: `Enabled=1`, `StockSites=1`, `QueueCapacity=8192`, `PurgeDays=0`, остальные — как у GameServer (`../GameServer/ac-journal-p53.md` §5); `Version 3 → 4` |
| **Исходник** | `AstoryServer/Patches/AddonNPC/src/patches/n13_ac_journal_npc.cpp`; общий модуль `AstoryServer/Patches/AsdaPatch/src/AcJournal.cpp` |
| **Пара** | N01 (античит скорости атаки считает время 32-битным) — те же функции, другие площадки |

## 1. Что пишется
Штатный античит скорости атаки NpcServer (`CAi::Process_AttackedToMonster` и функция-двойник, см. N01) на каждое
нарушение («удар раньше интервала») пишет в `Error_Log` строку `SpeedHack Check....!`, а при > 30 нарушениях шлёт
GameServer 8905 (кик тип 6) и пишет `SpeedHack Banish....!`. N13 дублирует ровно эти четыре строки в
`joylog1.ac.move_combat`:

| вид (`event_kind`) | откуда | колонки |
|---|---|---|
| 4 «NpcServer: удар раньше интервала (SpeedHack Check)» | Check | `map_index`, `user_num` (слот игрока на GameServer), `char_name`, `tick_prev`, `tick_now`, `interval_ms`, `violation_count`, `p_duration` (требуемый интервал, мс), `duration` (фактический + 100 мс допуска) |
| 5 «NpcServer: больше 30 нарушений — отключение (SpeedHack Banish)» | Banish | `map_index`, `user_num`, `char_name`, `tick_now`, `violation_count`, `opcode = 8905` |

`user_index` и `ip` NpcServer не знает (NULL); учётку по тому же кику видно в `ac.kick_block` от GameServer
(тип 6 «скорость атаки (сигнал NpcServer 8905)», то же время и `user_num`). Ограничитель — 60 строк в минуту на
`user_num`, подавленные — в `repeat_suppressed`.

## 2. Площадки
Подмена цели `call rel32` → стаб → тот же писатель `sub_408DC0` с тем же `ecx` и аргументами; `Error_Log` пишется
как раньше. Байты одинаковы в живых `NpcServer.exe` `c02486d6…` и `Indun_NpcServer.exe` `0de2c559…`.

| VA | байты | строка формата (`push` за 10 байт до `call`) | вид |
|---|---|---|---|
| `0x0045F600` | `E8 BB 97 FA FF` | `0x004776A8` SpeedHack Check | 4 |
| `0x0045F674` | `E8 47 97 FA FF` | `0x00477720` SpeedHack Banish | 5 |
| `0x004601B4` | `E8 07 8C FA FF` | `0x00478488` SpeedHack Check (двойник) | 4 |
| `0x00460228` | `E8 93 8B FA FF` | `0x00478500` SpeedHack Banish (двойник) | 5 |

При установке сверяются байты всех четырёх `call` и `push` строки формата; не сошлось — `[MISMATCH]`, ни одна
площадка не ставится. С площадками N01 (`0x45F5A4` / `0x460151`) и N02…N12 не пересекаются. Разбор аргументов — под SEH.

## 3. Проверка после старта
- `NpcServer\Log\Log_Patch\PatchLog_<дата>.txt` (и Indun): `[OK] P53_AcJournal`, «P53: площадок скорости атаки
  поставлено 4», затем `[P53] журнал: подключено к базе`.
- `SELECT TOP 20 * FROM joylog1.ac.move_combat WHERE server_name LIKE N'%NpcServer' ORDER BY ev_utc DESC;` — строка
  «журнал: старт» от NpcServer будет в `ac.other`; строки вида 4/5 — только при реальных нарушениях.

## 4. Откат
`[P53_AcJournal] Enabled=0` (или `StockSites=0` — поток есть, площадок нет) в `NpcServer\ConfigSet\patches.ini` + рестарт;
полный — `AddonNPC.dll.bak_20261012_acdb` (N12 `4c38d932…`) на место DLL + рестарт.

## 5. Не сделано / за владельцем
Статическая сверка площадок (переходы внутрь 5-байтовых площадок из других мест образа) в этой волне не выполнена —
за владельцем.
