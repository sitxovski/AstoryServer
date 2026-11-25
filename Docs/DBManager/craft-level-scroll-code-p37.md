# P37 — настоящий код результата в ответе 2668 (ремесло: уровень свитком)

| Поле | Значение |
|---|---|
| Дата | 2026-09-27 |
| Статус | 🟡 **СОБРАН, НЕ УСТАНОВЛЕН.** `verify_dll.py`: «ВСЁ СОШЛОСЬ» (живой DBManager, сток DBManager-Original, живые GameServer/Indun — по 200 площадок, расхождений 0) |
| Процесс | `DBManager.exe` — `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\DBManager\DBManager.exe` (MD5 `3D05C835…`, уже с инъекцией импорта `DBPatch.dll`) |
| Тип | бинарный, **в памяти** (наша `DBPatch.dll`, 3 площадки по 7 б, чистая замена байт, без трамплина) |
| Секция ini | `ConfigSet\dbpatch.ini` → `[P37_CraftLevelScrollCode]`, ключ `Enabled` (по умолчанию `1`) |
| Версия конфига | `Config::kVersion` 5 → **6** (шаблон берёт число из той же константы) |
| Исходник | `AstoryServer/Patches/DBPatch/src/p37_craft_level_scroll_code.cpp` |
| Артефакт | `AstoryServer/Patches/DBPatch/out/DBPatch.dll` MD5 `C4154D580B275EC73716085EDED9BAC0`, 182 272 б. Прежняя (= живая `064CE0E5…`, 179 200 б, P22+P23+P26+P28) — `out/DBPatch.dll.pre_p37_20260927` |
| Пара | GameServer **P35** `LevelScrollSync` — с этим патчем по умолчанию `1` (AsdaPatch.dll `Version` 19) |
| Рестарт | да, `DBManager.exe` (вместе с GameServer/Indun — см. §5) |
| Протокол | не меняется: 2668, 70 б, раскладка прежняя; меняется только значение байта 0 (кода), и только на коды, которые GameServer уже разбирает |
| Разбор | `Reports/craft/p37_dbm.md`; ранее `wave6_server_REVIEW.md` (Н-1), `p36_r248_dbm.md` §3, `p36_r248_REVIEW.md` §3 |

## ЗАЧЕМ

`sub_445B60@0x00445B60` — приём DB-опкода 2667 (GameServer `RecvUser_CraftScrollLevelUP@0x53F480`,
клиентский 6604 «повысить уровень ремесла свитком»), `EXEC UP_CRT_CraftLevelScroll`, ответ 2668.

```
0x445C0D  mov ecx,0x11 / lea esi,[ebp-0x3B48] / lea edi,[ebp-0x50] / rep movsd / movsw   ; копия 70 б ДО процедуры
0x445CC6  call 0x447720                                   ; EXEC UP_CRT_CraftLevelScroll …
0x445CE7  mov byte [ebp-0x3B48], 1      → lea eax,[ebp-0x50] / push 0x46 / push 0xA6C / call 0x44E2F0
0x445D6D  mov byte [ebp-0x3B48], 0x63   → lea ecx,[ebp-0x50] / … / call 0x44E2F0   ; процедура вернула ≠1
0x445DB3  mov byte [ebp-0x3B48], 0x62   → lea eax,[ebp-0x50] / … / call 0x44E2F0   ; ошибка выполнения SQL
```

Код пишется в исходный буфер, а уходит копия, снятая до процедуры. Байт 0 копии — тот, что прислал
GameServer, а он всегда 1 (`0x53F84A mov byte [ebp-0x90],1`). GameServer (`recvDBCraftScrollLevelUP@0x53F960`,
`0x53FA0D cmp byte [ebp-0x90],1`) всегда видел «успех». Соседние обработчики ремесла (2662 `sub_445070`,
2664, 2666, 2670 `sub_445E50`) пишут код в отправляемую копию — дефект только у 2668.

## ЧТО ДЕЛАЕТ ПАТЧ

| VA | было | стало |
|---|---|---|
| `0x00445CE7` | `C6 85 B8 C4 FF FF 01` `mov byte [ebp-0x3B48],1` | `C6 85 B0 FF FF FF 01` `mov byte [ebp-0x50],1` |
| `0x00445D6D` | `C6 85 B8 C4 FF FF 63` | `C6 85 B0 FF FF FF 63` |
| `0x00445DB3` | `C6 85 B8 C4 FF FF 62` | `C6 85 B0 FF FF FF 62` |

Сначала сверяются все три площадки, потом пишутся все три (либо целиком, либо никак). Рантайм-кода нет —
журнал в работе не пишется; отказы штатно журналирует сам DBManager (`Recv_CraftScrollLevelUP(1)/(2)`).

## ЧЕМ ДОКАЗАНО

* Дизассемблер capstone по живому `DBManager.exe` (0x445B60…0x445DEB) — единственные обращения к `[ebp-0x50]`:
  `lea ecx` для конструктора (0x445B8A), `lea edi` копии (0x445C18) и три `lea` перед отправкой. Регион 0x445B60…0x445DF0
  побайтно равен стоку `DBManager-Original.exe` и копии декомпила `RE/ida/db_work/DBManager.exe`.
* Декомпил `db_work/DBManager.exe.c:32751`: `qmemcpy(v22, v19, 68)` до SQL, `LOBYTE(v19[0]) = 1/99/98`, отправляется `v22`.
* `sub_44E2F0` (`:…Ciocp::MakeHeaderSend`) кладёт тело с 9-го байта пакета — GameServer читает `memcpy(v7, pkt+9, 0x46)`, `v7[0]` = код.
* Полный перебор `.text` живого образа (rel8/rel32/jcc32) и абсолютных DWORD — ни одного входа внутрь и на начало трёх площадок.
* Пересечений нет: P22 `0x4054B4`, P23 `0x4054BE`, P26 `0x42E262`, P28 `0x447720` (вход сборщика), бинарный P17 `0x4478B9`.
* `verify_dll.py`: площадки P37 ok в живом и стоке, соседи отправки (3× `lea [ebp-0x50]…push 0xA6C`) и снимок `0x445C0D` ok,
  байты замены лежат в `DBPatch.dll` по одному разу; «ВСЁ СОШЛОСЬ».

## ЧТО УВИДИТ GameServer / игрок

| Ответ | Что делает GameServer (сток, P35 поверх) | Игрок |
|---|---|---|
| 1 (успех) | как раньше: свиток −1/удалён в памяти, уровень → память, 6605 код 1 | без изменений |
| 99 (процедура отказала) / 98 (ошибка SQL) | ветка `RecvDB_CraftScrollLevelUP DB Error` (0x53FA19): 6605 код 99, **память не трогается** (свиток цел, уровень прежний). Замок P35 InFlightLock снимается (WrapRecv, эхо charId по +2 не тронуто) | сообщение 5563 (оригинал и порт — `AsdaCraftSubsystem::On6605` case 99); окно не виснет |

Раньше в этих случаях GameServer считал уровень поднятым (ветка успеха) при том, что база его не записала.

## КАК ОТКАТИТЬ

1. Быстро: `ConfigSet\dbpatch.ini` → `[P37_CraftLevelScrollCode] Enabled=0`, рестарт DBManager.
   ⚠ Тогда же поставить `LevelScrollSync=0` в `patches.ini` GameServer и Indun_GameServer (без P37 он опирается на ложный код 1).
2. Полностью: вернуть `DBPatch.dll` из `v2\DBManager\DBPatch.dll.bak_pre_p37_20260927` (= `out/DBPatch.dll.pre_p37_20260927`, `064CE0E5…`).
   Прежняя DLL сама понизит `Version` 6 → 5 (MergeMissing пишет версию в обе стороны); секция P37 останется в ini и будет проигнорирована.

## РИСКИ И СВЯЗАННОЕ

* Тело `UP_CRT_CraftLevelScroll` не снято (вход в БД отклонён у прежнего агента) — транзакционность процедуры при коде ≠1 не проверена.
  Для игрока это не хуже стока: при 99/98 память не меняется, а при частичной записи в БД следующая запись уровня из памяти (6602) вернёт
  старый уровень.
* Остаток С-1 (п.2 ревизии P35) — в `p37_dbm.md` §3: в ветках «свиток не найден после записи БД» свиток в памяти не расходуется
  (гонка модклиента; честный клиент туда не попадает).
