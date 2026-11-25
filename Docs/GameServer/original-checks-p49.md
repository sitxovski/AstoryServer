# GameServer — возврат штатных проверок оригинала: кик за повторы и подпись 5450 (P49)

| поле | значение |
|---|---|
| **Дата** | 2026-10-12 (мера 11 плана `Reports/anticheat/00_PLAN.md`) |
| **Статус** | ✅ собран, проверен (`verify_ac0.py`, стенд `stand_ac0`); **выложен на dev 12.10 (AsdaPatch v33 `2c8ab8b6…`), действует со старта** |
| **Процесс** | `GameServer` + `Indun_GameServer` |
| **Флаги** | `[P49_OriginalChecksRestore]`: `Enabled=1`, `SecretRepeatKick=1`, `FunctionItemMd5Full=1` |
| **Исходник** | `AstoryServer/Patches/AsdaPatch/src/patches/p49_original_checks_restore.cpp` (+ правка `p08_functionitem_check_off.cpp`) |

## 1. Кик за повторы (`SecretRepeatKick`)
`sub_524440@0x524440` при счётчике ошибок анти-повтора `CUser+4` > 20 пишет «Secret Error Disconnect» и обнуляет счётчик, но
всегда возвращает 0 — ветка кика `CheckDisConnectUser() Secret Broken Count` мертва. Площадка `0x524496` (7 б `C7 40 04 00000000`,
только ветка «> 20»): стаб — тот же сброс + `eax = 1` + переход на эпилог `0x52449F`. Ветка «≤ 20» (`0x52449D`) не тронута, порог стоковый.
Клиент порта: генератор токена монотонен; `Log_Secret` на dev — последняя ошибка 07.08.2026, после — 0 при регулярной игре.

## 2. Подпись 5450 (`FunctionItemMd5Full`)
`Char_FunctionItem_Use@0x4ED780` сверяет MD5 по `0x89` байтам тела, а клиент (эталон `netSendItemUsePacket@0xA0D470`:
`Net_Md5Digest16(…, 0x101)`; порт `SendFunctionItemUse5450` — так же) подписывает `0x101`. Несходимость — в оригинале; поэтому на
живом стоял чужой обход P08. Правка: `0x4ED8CF` `68 89000000` → `68 01010000` — проверка снова работает и сходится с клиентом.
При `FunctionItemMd5Full=1` **P08 не ставится** (`P49_FunctionItemMd5FullWanted`, строка в PatchLog). Протокол прежний.

## 3. Откат
`SecretRepeatKick=0` и/или `FunctionItemMd5Full=0` (тогда P08 снова ставится по своему `Enabled`), рестарт; или прежняя DLL.

## ★ sec2c (15.10.2026) — значение Secret до сброса по CUser (ревизия SEC2 Н-3)
Стаб `0x524496` теперь: `pushad; pushfd; push [eax+4]; push eax; call P49_NoteSecretPre; add esp,8; popfd; popad`, затем прежнее
(`[eax+4]=0; eax=1; jmp 0x52449F`). `P49_NoteSecretPre` пишет значение в таблицу по указателю CUser (1024 слота, хеш
`(ptr>>4)&1023`, линейный пробинг, CAS захвата пустого слота); `P49_TakeSecretPre` (P48) берёт его один раз (значение → −1).
Ключи из таблицы не удаляются: CUser — элементы фиксированного массива 550 записей, таблица не переполняется, а удаление рвало
бы цепочку пробинга. Площадки и байты не менялись. `verify_ac0.py`: сигнатура `609cff700450e8`, цель call по MAP, эмуляция
(аргументы `(CUser, 21)`, регистры и флаги сохранены).
