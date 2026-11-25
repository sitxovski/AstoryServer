# P58 — причина отключения (4101) в общий лог всегда

- **Дата:** 2026-10-12 (античит, волна A6; план `Reports/anticheat/04_detection_response.md` §6.2 П1).
- **Статус:** собран в копии `AstoryServer/_archive_waves/AsdaPatch_w57` (DLL v36), статика и стенд пройдены; на живой сервер НЕ выложен (интегрирует координатор). **Интегрировано в основную сборку 2026-10-12** (`AstoryServer/Patches/AsdaPatch`, DLL v36 md5 `bfb4dc9f1fe2a8a0cbe0b9878aea64fa`, 540 672 б); стенд `stand_p57` 55/60/55, `verify_p57.py` пройден; **НЕ выложено** — отчёт `Reports/anticheat/wave_INTEG_20261012.md`.
- **Процесс:** GameServer.exe (основной и Indun — бинарь e7b4ac38, для этой площадки = сток 4e20f0ad).
- **Тип:** [ПОРТ/СЕРВЕР-ДОРАБОТКА], только журнал — протокол и поведение сервера не меняются.
- **Файл:** `src/patches/p58_disconnect_reason_log.cpp`; секция ini `[P58_DisconnectReasonLog]`.

## Что и зачем

Все кики с кодом сервер шлёт одной функцией `Send_DisConnectType` (`sub_52EDB0@0x52EDB0`, `GameServer.c:115141`): 4101 + код типа клиенту. Сток пишет строку `[CALL] Send_DisConnectType() UserNum:%d DisConnectType:%s(%d)` **только когда тип сервера == 4** (таблица `0x5F5E18`, запись 0xEC, +0x3F) и **только в канал 31 = Log_RoseWar** (`GameServer.c:115149-115150`). На обычном сервере в файл-логах остаётся лишь `___ExceptionDisConnetUser___ CallFunc = …` без кода, по которому нельзя сопоставить, что увидел игрок (loc 1098/1100/1106/1107…) и за что его выкинули. В архиве логов владельца (`Log_Game`, 54 файла) строк `[CALL] Send_DisConnectType` нет вовсе — ни одной.

P58 пишет ту же строку **всегда** и **в общий лог** (канал 0 = Log_Game, ключ `LogChannel`), дополнив её именем персонажа, UserIndex, IP пира и адресом возврата (откуда кик):

```
[CALL] Send_DisConnectType() \tUserNum:7 \tDisConnectType:SpeedHack(6) \tCharN:Tester \tUserIndex:75001 \tIP:192.168.10.154 \tFrom:0x005271D6
```

Адрес возврата → смысл: `0x526D10/0x526D4F/0x526D8E/0x526DCD` — `CheckDisConnectUser()` Secret/MD5/NotKnow/Hack Packet, `0x526E02` — Ping TimeOut, `0x5271D6` — `Send_SpeedHackDisConnect()` (NpcServer 8905), `0x527678/0x52CD24` — отказ логона/портала (в т. ч. P47), `0x527919/0x52D08C` — отказ DB-логона (в т. ч. P50/P54) — полная таблица в `AcJournal.cpp` (`kKickSites`). Кик P57 (MoveGuard) приходит с адресом внутри AsdaPatch.dll (выше 0x10000000).

## Площадка «было → стало»

| VA | Было (сток) | Стало |
|---|---|---|
| `0x52EDE4` (5 б) | `83 FA 04` `cmp edx,4` ; `75 25` `jne 0x52EE0E` | `E9 rel32` → `DiscLogStub`: `pushad`; `P58_OnDisconnect(mgr=[ebp-8], userNum=[ebp+8] i16, type=[ebp+0xC] u8, retVa=[ebp+4])`; `popad`; `cmp edx,4`; `je 0x52EDE9` / `jmp 0x52EE0E` |

Стоковая ветка типа 4 сохранена (на сервере типа 4 будет и строка стока в Log_RoseWar, и наша в Log_Game). Кадр к моменту площадки уже построен прологом (его держит P48 с возвратом на `0x52EDB6`): `[ebp-8]` = CUserManager, `[ebp+4]` = адрес возврата. `edx` (тип сервера) сохраняется `pushad/popad`.

Имя типа — из стоковой таблицы `off_5A62AC` (15 указателей 0..14: Default, Network, Duplication, Security, Notting, Wrong Info, SpeedHack, Block Account, Seceder, 14 Age, NProtect Update, NProtect Authentication, HackShield, APR, User Full); тип вне 0..14 → `Unknown`. ⚠ Сток индексирует таблицу любым байтом типа (у типа 15 указатель уже мусорный, `0x59FCAC`) — поэтому «просто включить стоковую ветку всегда» нельзя было: код 15 (`переполнение / занятый слот`, см. P48) печатал бы мусор.

Проверки при установке: байты площадки, соседи `0x52EDE9` (`0F B6 45 0C`), `0x52EE0E` (`6A 01 6A 00`), `0x52EDFF` (`push fmt; push 31`), все 15 указателей таблицы лежат в `.rdata` (0x583000..0x5A6000). С P01…P57 не пересекается (P48 — вход `0x52EDB0..0x52EDB6`, P57 зовёт `0x52EDB0` как функцию).

## Конфиг

```ini
[P58_DisconnectReasonLog]
Enabled=1      ; 0 = как в стоке
LogChannel=0   ; 0 Log_Game, 6 Log_Operator, 31 Log_RoseWar
```

## Проверка

- `tools/verify_p57.py` (сток 4e20f0ad, живой GameServer и Indun e7b4ac38): байты площадки и соседей во всех образах, переходов/abs32 внутрь нет, границы инструкций, стаб найден, `jmp [..]` → `0x52EE0E`/`0x52EDE9`; unicorn: тип сервера 4 → `0x52EDE9`, 1/0 → `0x52EE0E`, аргументы `(mgr, 7, 6, 0x5271D6)`, регистры (edx/ecx/eax/ebx/esi/edi) сохранены, стек сбалансирован.
- `tools/stand_p57/`: строка для сессии с IP, тип 99 → `Unknown(99)`, несуществующий userNum → `CharN:? UserIndex:-1`, `mgr=NULL` — без падения.
- На живом: после рестарта в `PatchLog` строка `P58: причина отключения (4101) пишется в канал 0 (Log_Game) всегда`; при любом кике в `Log_Game\GameLog_<дата>.txt` появляется `[CALL] Send_DisConnectType() …`.

## Откат / рестарт

`Enabled=0` в `patches.ini` + рестарт GameServer (патч живёт в памяти; exe на диске не меняется). Понижение DLL до v35 само опустит `Version` и проигнорирует секцию.
