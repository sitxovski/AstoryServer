# DBManager — сверка личности при DB-логоне персонажа (P50)

| поле | значение |
|---|---|
| **Дата** | 2026-10-12 |
| **Статус** | ✅ собран, проверен (`verify_ac0.py` — площадки в живом и стоковом DBManager; стенд `stand_ac0 db` — 16/16); **выложен на dev 12.10 (`DBPatch.dll` MD5 `ac8db3fee602991beac8586a1ad1f192`, 187 904 б), действует со старта** |
| **Процесс** | `DBManager` (`v2\DBManager\DBManager.exe`, импорт `DBPatch.dll`) |
| **Флаги** | `ConfigSet\dbpatch.ini` → `[P50_IdentityCheck]`: `Enabled=1`, `CheckIp=1`, `RefuseBlocked=1`, `RequireSession=1`, `RequireIp=0`, `FailOpen=1`, `LogPass=0`; `Version 6 → 7` |
| **Исходник** | `AstoryServer/Patches/DBPatch/src/p50_identity_check.cpp` |
| **Пара** | GameServer P47 (IP пира в хвосте запроса), SQL P51 (`dbo.UP_AC_IdentityCheck`) |

## 1. Что проверяется
Цели двух `call` в диспетчере `sub_402420` заменены обёртками (то же соглашение, `ret 0x10`):
`0x004026D1` (case 2001 → `sub_407480`), `0x00402FE3` (case 2089 → `sub_417410`). До стокового обработчика —
`EXEC dbo.UP_AC_IdentityCheck UserIndex, CharIdx, 'IP'`, одна строка 5 × TINYINT.
Отказ (штатный ответ-неудача, как у стока при ошибке UPCharInfo: 2002 тело 265 б / 2090 тело 262 б, `[0] = 0` → GameServer
кикает 4101 код 5): нет учётки; `us_block <> 0` (`RefuseBlocked`); слот не принадлежит учётке; нет открытой записи входа
`JoyLog1.dbo.Loginfo` (`RequireSession`); IP передан и не совпал (`CheckIp`); IP не передан — только при `RequireIp=1`.
Соулмейт (запись входа State 2 с IP `'0'` — дефект оригинала `UPCharSoulState`) — IP сверяется с записью партнёра.
Ошибка самого запроса → `FailOpen=1`: пропуск со строкой в журнале. Группа/UserIndex/слот вне стоковых границ — сразу сток.
Журнал: `DBManager\Log\Log_Patch\PatchLog_*.txt` (`[P50] ОТКАЗ …`, антифлуд).

## 2. Откат
`[P50_IdentityCheck] Enabled=0` + рестарт DBManager, либо `DBManager\DBPatch.dll.bak_20261012_ac0` (v6 `c4154d58…`).

## 3. ★ ac0r (2026-10-12) — блок по учётке сессии входа
DBPatch **не менялся** (v7 `ac8db3fe…`, читает те же 5 × TINYINT). Изменилась SQL-процедура `dbo.UP_AC_IdentityCheck`
партнёр `SoulMate.Ouserindex`, у которого истёкший блок снимается тем же правилом, что в `UPUserLogin`); блок
хозяина персонажа только читается и мешает, лишь пока действует (истёкший, но не снятый — больше не мешает). Так
закрыт СРЕД-1 ревизии: вход соулмейтом не зависит от того, заходил ли хозяин персонажа сам после истечения его блока.

## 4. ★ acdb (2026-10-12) — код 7 при отказе по блоку + журнал в базе (DBPatch v8)
- **`BlockedClientCode7=1`** (новый ключ `[P50_IdentityCheck]`): отказ ИМЕННО по причине «учётка заблокирована»
  (в т. ч. вход соулмейтом в персонажа заблокированного хозяина) помечается в штатном ответе-неудаче 2002/2090:
  `[0] = 0` как раньше, `[1..4] = 'P54B'`, `[5] = 1`. GameServer P54 по метке шлёт игроку 4101 **код 7** — loc 1107
  «учетная запись заблокирована» вместо кода 5 «недостаточно данных». Прочие отказы (IP, сессия, слот, нет учётки) —
  без метки, код 5. Без P54 на GameServer метка ни на что не влияет (сток читает только `[0]`). Подробно —
  `../GameServer/blocked-login-message-p54.md`.
- **Журнал P53**: каждый отказ и каждая ошибка запроса `UP_AC_IdentityCheck` пишутся в `joylog1.ac.login_check_refusal`
  (вердикт 5 полей, причина, IP, код и текст для игрока); соулмейт расшифровывает `ac.v_login_check_readable`.
  Запись — фоновым потоком со своим соединением, поток запросов DBManager не ждёт. Подробно — `../GameServer/ac-journal-p53.md`.
- Проверка: стенд `stand_ac0 db` 35/35 (`Reports/anticheat/wA3_logs/stand_db.log`).
- Откат: `BlockedClientCode7=0` (только код) / `[P53_AcJournal] Enabled=0` (только журнал) + рестарт DBManager; полный —
  `DBManager\DBPatch.dll.bak_20261012_acdb` (v7 `ac8db3fe…`).
