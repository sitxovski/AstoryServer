# P120 — переход в «Шахту» (карта 23 `^MineWar^`) и обратно (`P120_MineTravel`)

| Поле | Значение |
|---|---|
| Дата | 2026-11-09 |
| Статус | собран и проверен на стенде, **НЕ ВЫЛОЖЕН** (ревизия и выкладка — координатор) |
| Задача | владелец: «make possible to travel to "Mine" map, it should be enabled in game server (remember there is a map limit, we should patch it) and in client. There is NPC in alpen, that have option to teleport to "Mine"» |
| Процессы | `GameServer`, `Ch2_GameServer`, `Indun_GameServer` (DLL); данные — ещё `NpcServer` ×3 и `ChannelManager` |
| Тип | DLL (7 площадок, протокол не меняется) + данные карты (54 файла) |
| Секция ini | `[P120_MineTravel]` (DLL допишет сама при старте) |
| Версия конфига | `Config::kVersion` 72 → **73** (⚠ если раньше выйдет P118/P119 с тем же номером — поднять) |
| Исходник | `AstoryServer/Patches/AsdaPatch/src/patches/p120_mine_travel.cpp` |
| Сборка | AsdaPatch v73 = v72 `b31adafd` + P120: `tools/p120_data/AsdaPatch_v73_f60f7713.dll`, MD5 `f60f771353903718be1546da41b3a3ad` |
| Данные | `tools/build_p120_data.py` → `tools/p120_data/files/…` + `manifest.json` |
| Выкладка | `py -3.13 restart_stack.py --deploy deploy_p120.py --expect P120_MineTravel --expect P117_PlusPackOnce --expect P13_ChatWideChannels6560`, затем `py -3.13 deploy_p120.py --check-started` |
| Проверки | `tools/verify_p120.py` (102/0), стенд `tools/stand_p120` (on 69/0, refuse0 70/0, off 3/0, mismatch 3/0) |
| Отчёт | `Reports/batch20/mine/REPORT.md` |

## Почему шахта была мертва

1. **Лимит карт** снят ещё P30 (`MaxMaps=30`, слот 23 есть — живой PatchLog «слотов карт 23 -> 24»). Сам по себе он карту не оживлял.
2. **Тип карты 6.** Поток карты создаёт только `SetUserInfo_ThreadID_Mapping @0x4A5360`, и только типам 0/1/3 (`test edx,edx / cmp edx,1 /
   cmp edx,3` @0x4A53AB…0x4A53E6). Полный перебор `.text` по шаблону `movzx r,[r+r+3Fh] / cmp [ebp-x],5 / ja` нашёл ровно пять switch по
   типу карты; ни один не знает тип 6:
   `EndSelectThread` 0x4A72BE, `SearchThreadInfo` 0x4A84BC (вход на карту — default = код 0, войти нельзя), `GetDisplayInfo` 0x4C0BE5,
   напольный портал 0x52C741 (default = путь типа 0 — не трогаем), `CharPortalLogonRes` 0x52D38E (default — строка в журнал).
   Остальная логика типа 6 в стоке есть и рабочая (её сохраняем, тип НЕ меняем — июньский разбор `RE/docs/_june2026/04_SERVER_AND_MAPS.md`):
   PvP-смерть (`sub_4CB180`), запрет лавки (`CharSelfStoreReady` 6301 код 7), призыв (5461 код 9), выход/обрыв → прежняя карта
   (`DisConnectUser` / `PortalDisConnectUser`, CUser+49149).
3. **Кнопки NPC сервер не обрабатывает.** NPC 181 «Шахта» в Альпии (тайл 118,310; кнопка 30077) шлёт **6746**, стражи шахты 202/203/204
   «В Альпию» (30078) — **6749** (эталон `game_main.c:10304-10309`; клиент 7.0.0 шлёт оба: `AsdaNpcDialogSubsystem_Script.cpp:1254`).
   В `sub_42A9D0` их нет: таблица `0x19AF…0x1A58` кончается на 6744, `ja` @0x42AE1B уводит 6745…8005 в default 0x42F020 (там P13);
   `push 1A5Ah/1A5Dh` в образе нет. В этой сборке сервера системы войны за шахту нет вовсе (ответы 6747/6750 клиента не нужны).
4. **Данных карты нет** ни на одном сервере: `.sim/.svr/.npc/_PortalConfig/_ConnectIP`, NpcServer (`MapCount = 23`, `SectorInfo`,
   `Map/Monster/NpcInfo`, `MiningItemTable\<имя>00/01.mng` — без них NpcServer не стартует), `Total_PortalConfig count = 23`,
   `OpenMapInfo` без `MAP_23`, `MapWarpCost` 23×23, `ChannelManager Indun_Info MapCount = 23`.
5. **★ Смерть в шахте.** На карте 23 клиент (и оригинал `Recv_CharDeath_Apply`, и порт `AsdaAfterDeathSubsystem`) даёт ТОЛЬКО опцию 8
   «база» (4054 режим 8), а `RecvCharRegen @0x52A570` принимает режим 8 лишь на карте типа 4 (и при армии `sub_5328B0` ≥ 0) — на типе 6
   пакет молча пропадал, игрок оставался мёртвым.

## Площадки DLL (живой `e7b4ac38` = Ch2 = Indun; сток `4e20f0ad` — те же байты)

| | VA | байты стока | что делает P120 |
|---|---|---|---|
| A | 0x004A53DC | `0F B6 54 01 3F 83 FA 03 74 02 EB 8E` | jmp на стаб: тип 3 **или 6** → создать поток (0x4A53E8), иначе пропуск (0x4A5376). Только при Use=1 в OpenMapInfo (проверка стока выше) |
| B | 0x004A84BC | `0F 87 57 09 00 00` (ja 0x4A8E19) | rel32 → стаб: `[ebp-4Ch]==6` → ветка 0/1/3 0x4A84CC (таблица 0x4A8E24[0]), иначе прежний default |
| C | 0x004A72BE | `0F 87 01 01 00 00` (ja 0x4A73C5) | `[ebp-28h]==6` → 0x4A72CE (0x4A73E8[0]) |
| D | 0x004C0BE5 | `0F 87 5D 02 00 00` (ja 0x4C0E48) | `[ebp-1Ch]==6` → 0x4C0D77 (0x4C0E84[0]) — строка состояния окна сервера |
| E | 0x0052D38E | `0F 87 90 01 00 00` (ja 0x52D524) | `[ebp-598h]==6` → 0x52D3A1 (ветка 1/2/4/5: точку привязки города не трогать) |
| F | 0x0042AE1B | `0F 87 FF 41 00 00` (ja 0x42F020) | `[ebp-10C8h]` (= опкод − 0x19AF) 0xAB (6746) / 0xAE (6749) → `P120_OnClient`, хвост 0x42F036; иначе прежний default (P13 не тронут) |
| G | 0x0052A755 | `83 F9 04 75 1C` | `[ИСПРАВЛЕНИЕ]` case 8 `RecvCharRegen`: тип 4 → сток (0x52A75A), **тип 6 → ветка режима 0** 0x52A646 (`CharRegenVillage(this, idx, 0)` — город привязки, 4055), иначе выход (0x52A776). Ключ `ReviveTownOnMine` |

Длина и кодировка команд в B…F не меняются (только rel32). Переходов внутрь A (0x4A53DD…0x4A53E7) и G (0x52A756…0x52A759) по всему `.text`
нет (`verify_p120.py`). Сверяется также начало `sub_530C20` (`55 8B EC 83 EC 30`) и ветка режима 0 `6A 00 66 8B 4D 08 51 8B 4D E4 E8`.

### Обработчик 6746 / 6749 (`P120_OnClient`)

* Конверт — как у всех стоковых обработчиков: анти-повтор `sub_524390` (8 б с +9), MD5 тела `sub_523F00` (4 б у 6746, 6 б у 6749);
  короткий кадр — отброшен до конверта.
* `charId` тела = UserIndex сессии (`sub_5324F0`), текущая карта: 6746 — `EnterFrom` (3), 6749 — `MineMap` (23).
* NPC рядом — мера `CNpcManager::TemporaryRequestProcess` (как P40): NPC типа `EnterNpc` (181) / `ExitNpc` (202,203,204) не дальше `Range` (3) клеток.
* Цель: строка в `MapInfo.txt`, открыта в OpenMapInfo (массив `0x52C610` — следует за P30, как у P40 и напольного портала),
  запись `Total_PortalConfig` (`CUserManager+0xA60+31·n`, USE ≠ 0).
* Дальше **ровно как вход стока на спецкарту** `chatGameRoseWarGameJoin @0x463550`: с карты типа 0 — точка возврата `sub_530C20(idx, x, z)`
  (DB 2235); затем 5055 код 1 (53 б, буфер как `sub_40DE70`): IP 16 б, порт, номер карты, тайл. У 6746 тайл — STARTPOS
  `Total_PortalConfig[23]`, у 6749 — первая пара точек MapInfo цели (`+98/+108`; у Альпии 115,320 — рядом с NPC 181), если есть.
* Отказ — молча, строка `P120: … refused …` в Log_Game (не чаще `LogPerMinute`); `RefuseCode ≥ 0` — 5055 с этим кодом (0 → нотис 1096).
* Сбой чтения — `__try`, пакет проигнорирован, счётчик `faults`. Счётчики — экспорт `P120_GetStats`.

## Ключи `[P120_MineTravel]`

`Enabled` (1), `EnterNpc` (181), `EnterFrom` (3), `MineMap` (23), `ExitNpc` (202,203,204), `ExitTo` (3), `ExitPointFromMapInfo` (1),
`ReviveTownOnMine` (1), `Range` (3), `RefuseCode` (-1), `LogPerMinute` (30).

## Данные (54 файла, `manifest.json`; сухой прогон 09.11 — все базы сошлись)

Имя карты — **оригинальное `^MineWar^`** (строка 23 MapInfo.txt, тип 6 не меняется). Геометрия — клиент-эталон
`Donors/AsdaChroniclesInterlude/map/mine` (`mine.SIM` = стоковый `MapData_Info/MineWar.SIM`, `7095c685`; `mine.BIN` = `MineWar.BIN`, `90d8b553`).

| Папки | Файл | Что |
|---|---|---|
| GameServer ×3 | `MapData_Info\MapInfo.txt` | строка 23: 5 пар точек = прибытие (261,41) вместо нулей (запасной спавн `CharMake`) |
| | `MapData_Info\MapWarpCost.txt` | N 23→24; строка и столбец 23 = −1 (кристаллом 5477 в шахту и из неё нельзя; матрицу читает только 5477) |
| поле, Ch2 | `MapData_Info\OpenMapInfo.ini` | `[MAP_23] Name = mine, Use = 1` (у Indun файла нет — потоков там нет вовсе) |
| GameServer ×3 | `PortalIP_Info\Total_PortalConfig.Ini` | `count = 24` + `PORTAL_INFO_23` (IP/PORT как у записи 22 этой папки: поле 15601, Ch2 15621), STARTPOS (261,41) |
| | `^MineWar^.SIM`, `^MineWar^.svr` (0 мобов), `^MineWar^.npc`, `^MineWar^_PortalConfig.Ini` (count 0), `^MineWar^_ConnectIP.ini` (= `Inferion_ConnectIP.ini` этой папки) | новые |
| NpcServer ×3 | `ini\MapInfo.ini` | `MapCount = 24` + блок `023` |
| | `ini\SectorInfo.ini` | `[^MineWar^]` 512×512, сектор 256 |
| | `Map\^MineWar^.SIM/.BIN`, `Monster\^MineWar^.svr/.Aif` (клиентский `mine.Aif`), `NpcInfo\^MineWar^.npc`, `MiningItemTable\^MineWar^00/01.mng` (пустой шаблон `14d5b967` = quizstage/battlefield) | новые |
| ChannelManager | `ini\Indun_Info.ini` | `MapCount = 24` + `MapStartX_23=261`, `MapStartZ_23=41` |

Стражи (`^MineWar^.npc`, записи 221 б, хвост +0x10…+0xDC — самый частый по стойке): **точки оригинала** — клиент-эталон
`Data/NPC/npc_list.BIN` (запись 0x88 с +0x14: +0x6C карта, +0x70/+0x74 X/Z float, +0x78 поворот), тайл = X//100, Z//100 (то же правило,
что у P119 и запечённых в уровень mine стражей клиента): 202 «Страж Света» (261,38) поворот 0, 203 «Страж Тьмы» (44,466) 135,
204 «Страж Хаоса» (457,471) 225. Типы есть в `NPC.nif` (빛의_경비병 / 어둠의_경비병 / 혼돈의_경비병). Прибытие (261,41) — в 3 клетках
от стража 202 (с точки прибытия можно сразу вернуться). Все точки проходимы по `mine.SIM`.

`ThreadInfo.ini [MAX_INIT_THREAD] COUNT = 21` ≥ 20 открытых карт — не меняется.

## Что P120 НЕ делает

* Войны за шахту (регистрация, команды, добыча руды, ответы 6747/6750) нет и не появляется: в этой сборке сервера её нет.
  Таблица добычи шахты — пустая (своих данных у шахты нет), мобов нет (`mine.svr` клиента — одна запись «босса» 186 с нулевым откликом —
  не берём, это решение владельца).
* Тип карты остаётся 6: в шахте PvP, лавки запрещены, выход из игры возвращает на прежнюю карту.

## Откат

* Быстрый: `[P120_MineTravel] Enabled=0` + рестарт (данные можно оставить: без потока шахту никто не обслуживает, 6746/6749 — в default).
* Полный: `restart_stack.py --deploy deploy_p120.py` с `ASDA_P120_ROLLBACK=1` — DLL ← v72 `b31adafd`, 18 изменённых файлов ← бэкап рядом
  (`.bak_20261109_p120`); 36 новых файлов `^MineWar^.*` остаются (без строк в ini их не читают). Перед откатом вывести игроков из шахты.
