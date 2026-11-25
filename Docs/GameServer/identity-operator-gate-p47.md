# GameServer — привязка личности на входе и обязательный GM-флаг (P47)

| поле | значение |
|---|---|
| **Дата** | 2026-10-12 |
| **Статус** | ✅ собран, проверен статически (`verify_ac0.py`, `verify_dll.py` — «ВСЁ СОШЛОСЬ») и стендом логики (`stand_ac0` — 41/41 на живых GameServer и Indun); **DLL выложена на dev 12.10 при остановленной стойке, действует с ближайшего старта** |
| **Процесс** | `GameServer` + `Indun_GameServer` (`\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2`), бинарь один (`e7b4ac38…`) |
| **Тип** | патч в нашей DLL (`AsdaPatch.dll` v33, MD5 `2c8ab8b62d4415018528517fa500b939`, 416 768 б); `GameServer.exe` не меняется |
| **Флаги** | `ConfigSet\patches.ini` → `[P47_IdentityOperatorGate]`: `Enabled`, `OperatorGmFlag`, `CountAsHackPacket` (★ ac0r: умолч. **0**), `RefusalLogIntervalSec` (★ ac0r, 60), `TargetJumpRetailOnly`, `TargetJumpCountdownWindow`, `CountdownSlackSec`, `Match20000`, `SendPeerIp`, `RuntimeLog` (секция допишется сама при старте) |
| **★ ac0r (12.10)** | AsdaPatch **v34** MD5 `d8cc87fd3ad53e0e4650092eaec2aaf4` (419 328 б): отказ гейта A — тихий сброс без Hack Packet, строка журнала не чаще раза в минуту на сессию — §5 |
| **Исходник** | `AstoryServer/Patches/AsdaPatch/src/patches/p47_identity_operator_gate.cpp` |
| **Отчёт** | `Reports/anticheat/wave_A0.md` (мера 3 плана `Reports/anticheat/00_PLAN.md`, §8 A1) |
| **Рестарт** | да — вся стойка |

## 1. Что проверяется
**A. GM-флаг обязателен для операторских опкодов** (площадка `0x42AB4F`, диспетчер `sub_42A9D0`, до дерева сравнений и до стаба P01).
Флаг = байт `CUser+0x40B9F`: приходит из БД (`UPCharGMInfo` → DB-ответ 2801 → `sub_560160`, сверка UserIndex), до DB-логона равен 0
(обнуляет `ClearUserMemory → sub_4A2DC0`). Без флага обработчик не вызывается, строка в `Log_Operator`, отказ по чистой команде =
+1 к штатному счётчику Hack Packet (`sub_524540`, кик при > 5 — код 3). ★ ac0r: счётчик по умолчанию НЕ трогается (§5).
Опкоды (скан диспетчера — все обработчики с входным гейтом `sub_52ECF0`): 4209, 6005, 6007, 6010, 6012, 6014, 6018, 6020, 6022,
6024, 6026, 6028, 6029, 6030, 6032, 6033, 6035, 6036, 6038, 6040, 6042, 6045, 6046, 6058, 6075, 6094, 6145, 6147.
Условные — розничный клиент шлёт их и обычным игрокам:
- **6146** без флага пропускается только в формах эталона: режим 0 + свой userNum + шестёрка NPC 30071/30072
  (`game_main.c:10287-10296`); режим 1 + цель −1 + шестёрка конца отсчёта (`ui_core.c:86991`) — только в окне после принятого
  от оператора 6145 типа 2 (длительность + `CountdownSlackSec`).
- **6147** — розничная форма конца отсчёта (1, 0, 0) у не-оператора отбрасывается молча (как в стоке при UserIndex > 5000).
- **6184** — ветка сброса обучения (номер −1) требует флаг; обычные обновления не трогаются.
Розничные формы без флага — без счётчика Hack Packet.

**B. UserIndex логона == UserIndex из 20000** (площадки `0x527692` CharLogonReq / `0x52CD3E` CharPortalLogonReq — вход ветки «успех»).
Несовпадение → стоковая ветка отказа (`0x52764D` / `0x52CCF9`: лог «Exception…», 4101 код 5, отключение).

**C. IP пира в DB-логон** (площадки `0x52773F` / `0x52CF05` — `push len; push op` перед отправкой 2001/2089). К телу дописывается
8 б: `'P47I'` + IPv4 (`getpeername` по сокету userNum — путь `sub_565150`, с проверкой результата). DBManager без P50 хвост игнорирует.

## 2. Площадки (байты стока = живой GameServer = живой Indun; переходов внутрь — 0, перебор кодировок + abs32)
| VA | было | стало |
|---|---|---|
| `0x0042AB4F` | `8B45FC 0FB74807 898D38EFFFFF` | `jmp GateStub` + nop |
| `0x00527692` | `8B95D8FBFFFF` | `jmp LogonMatchStub` + nop |
| `0x0052CD3E` | `8B85CCFBFFFF` | `jmp PortalMatchStub` + nop |
| `0x0052773F` | `6A08 68D1070000` | `jmp LogonIpStub` + 2 nop |
| `0x0052CF05` | `6A0C 6829080000` | `jmp PortalIpStub` + 2 nop |

## 3. Откат
- Любая часть: соответствующий ключ = 0 в `[P47_IdentityOperatorGate]` (или `Enabled=0` целиком), рестарт.
- Вся DLL: `GameServer\AsdaPatch.dll.bak_20261012_ac0` и `Indun_GameServer\AsdaPatch.dll.bak_20261012_ac0` (v32 `b74bd693…`) на место
  `AsdaPatch.dll`; прежняя DLL сама понизит `Version` до 32, секции P47–P49 останутся и будут проигнорированы.
- Копии: `@@ASTORY_DEV_ROOT@@\_backup\2026-10-12_ac0\server\v2\…`.

## 4. Проверка
`python AstoryServer/Patches/AsdaPatch/tools/verify_ac0.py` (площадки, соседи, стабы, unicorn), стенд `AstoryServer/Patches/AsdaPatch/tools/stand_ac0`
(`build_stand.bat`, затем `stand_ac0.exe gs <GameServer.exe> <AsdaPatch.dll>`). Живая проверка — чек-лист в `wave_A0.md` §6.

## 5. ★ ac0r (2026-10-12) — ревизия А0/А2, СРЕД-2: тихий сброс отказа
**Зачем.** Обычный игрок с операторским префиксом имени (GM_/ADM_ — клиентский фильтр меню) при пробе прав получал
под P47 +1 Hack Packet на каждое нажатие: шесть нажатий за сессию — кик код 3 и +1 к автоблоку P48 (СРЕД-2 ревизии
`Reports/anticheat/wave_A0_A2_REVIEW.md`). Решение координатора: отказ по операторским опкодам — тихий сброс.
- Обработчик по-прежнему не вызывается (гейт A без изменений, список опкодов тот же — 6036 в нём есть).
- `CountAsHackPacket` = **0** по умолчанию: `sub_524540` не зовётся → нет кика код 3 → нет засчёта в P48. `1` — поведение А0.
- Строка `P47 OperatorGate: op N refused (GMFlag != 1) … [silent drop], suppressed K` в `Log_Operator` — **не чаще одной
  за `RefusalLogIntervalSec` (60 с) на сессию**. Сессия = слот userNum + UserIndex (CUser+0x174); логон 4001/5058 в
  процессе (вход ветки B, зовётся при любом Match20000) начинает отсчёт заново; подавленные отказы считаются (`suppressed K`
  в следующей строке). PatchLog-строка `[P47] отказ …` подчиняется тому же ограничителю.
- Клиент порта шлёт пробу прав не больше одного раза за сессию, без повторов по таймауту (`wave_A0r.md` §3).
- Проверка: стенд `stand_ac0 gs` — 55/55 (10 проб 6005/6036 без флага → 10 отказов, Hack Packet **0**, одна строка
  журнала; новый логон → новая строка; оператору 6036 проходит), `verify_ac0.py` / `verify_dll.py` — «ВСЁ СОШЛОСЬ».
- Откат: `CountAsHackPacket=1` (+ `RefusalLogIntervalSec=0`) и рестарт, либо DLL `AsdaPatch.dll.bak_20261012_ac0r` (v33).

## 6. ★ integ3 (2026-10-13) — общая точка «отправитель — оператор» для P68

- `bool P47_IsGmUser(void* mgr, int userNum)` (`Patches.h`, определена в `p47_identity_operator_gate.cpp`): `sub_52ED50(mgr, userNum) == 1`
  под SEH — ровно тот признак, по которому гейт A решает «операторская команда без GM-флага»; `P47_OperatorGate` переведён на неё
  (поведение то же). Работает и при `OperatorGmFlag=0` / выключенном P47 (не зависит от установки стаба).
- Байт `CUser+0x40B9F`: `sub_52ED50` → `sub_5324A0(mgr, userNum)` (слот < 0x226) → `v3[1].gap_B6E[2971]`. Пишет только
  `sub_560160` (GameServer) по DB-ответу **2801** {UserIndex 4 б, флаг 1 б}, если UserIndex ответа = `CUser+0x174`. 2801 шлёт DBManager
  в загрузке персонажа (`DBM_CHARINFO_RES`, после `UPCharFameProgress`; второй вызов — `DBManager.exe.c:11705`): `EXEC UPCharGMInfo <UserIndex>` →
  процедура `SELECT @GMFlag = GMFlag FROM Joy1.dbo.CharGmInfo WHERE Userindex = @Userindex` → **1, если строка учётки есть и `GMFlag` не NULL**
  До DB-логона 0 (`ClearUserMemory → sub_4A2DC0`).
- Пользователь: P68 `OperatorExempt=1` (оператор без правила имени 6138/6140) — `char-name-check-p68.md`; тот же источник у SQL A13b

## ★ autoban (2026-10-14) — кэш CUserManager слота для P69
В C-гейте `P47_OperatorGate` ТРЕТЬИМ вызовом (после P55 и P64; их порядок сверяют verify_p55/verify_p64) стоит
`P69_OnClientPacket(mgr, userNum)` — одна запись указателя CUserManager слота. По нему P61 (поток приёма IOCP, своего CUserManager
не имеет) находит CUser сессии для учётки в журнале и счёта автоблока P69. Ничего не решает и не отклоняет; пакет, отклонённый P55/P64
в Mode=1, кэш не обновляет. См. [integrity-autoblock-p69.md](integrity-autoblock-p69.md). AsdaPatch Version 39 — не выложено.

## ★ sec2c (15.10.2026) — +1 отказа к Hack объявляется до инкремента (ревизия SEC2 Н-4)
Перед `pHackCount` (`sub_524540`) — `P55_PendOtherHack(userNum)` (под замком учёта P55), при SEH — `P55_CancelOtherHack`.
Прежде `P55_NoteOtherHack` вызывался после инкремента: кик другой нити между ними отдавал +1 классу предыдущего кадра.
