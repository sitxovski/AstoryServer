# LoginPatch.dll — загрузчик патчей LoginManager

- **Дата:** 12.10.2026
- **Статус:** ✅ **ВЫЛОЖЕНО** 12.10.2026 12:45 (exe `51db86b2…`), первый старт 12:53 — 4 патча Applied, Mismatch 0; 13:10 DLL `a5ac8328…` (L01–L05), 13:31 старт — 5 Applied; 13:45 DLL **`96bc93a7…`** (исправлен слот UserIndex в L04b), рестарт за владельцем
- **Процесс:** LoginManager — `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\LoginManager\LoginManager.exe`
- **Тип:** инъекция импорта (заголовок PE + блок в нулевом хвосте `.rdata`); код `.text` не тронут
- **Назначение:** четвёртая DLL семейства (AsdaPatch — GameServer, AddonNPC — NpcServer, DBPatch — DBManager).
  Реестр: L01 (маска пароля/MAC в OTP_Report), L03 (апостроф → отказ), L02 (маска EXEC в OLEDB_LOG),
  L04 (личность сессии: 1005, 1016 режимы 0/1 и соулмейт), L05 (длина MD5 1010/1028). Доки — рядом, `L0x-*.md`.
  (Упоминания «стаб/пустой реестр» ниже — история первой сборки 12.10 утра.)

## Где что лежит

| Что | Путь |
|---|---|
| Исходники | `AstoryServer/Patches/LoginPatch/src/` (`dllmain.cpp`, `Config.*`, `LoginApi.h`, `patches/Patches.h`, `patches/Registry.cpp`); `Log.cpp`/`Hook.cpp` — общие из `AstoryServer/Patches/AsdaPatch/src` |
| Сборка | `AstoryServer/Patches/LoginPatch/build.bat` (VS2022 x86, `/MT`) → `out/LoginPatch.dll` |
| Инъектор | `AstoryServer/Patches/LoginPatch/tools/inject_import_login.py` → `out/LoginManager.exe.loginpatch.exe` |
| База инъекции | `AstoryServer/Patches/LoginPatch/work/lm_live_12dcd9f1.exe` = копия ЖИВОГО образа (md5 `12dcd9f14359610dcc045b7317102e81`, 245 760 б; сток + 4 байтовые правки `auth-ip-secret-bypass.md` — они сохраняются) |

## Артефакты

| Файл | Размер | MD5 | статус |
|---|---|---|---|
| `out/LoginPatch.dll` | 142 336 | **`96bc93a7c9f2e85783ddeea218e8fc6d`** | текущая (L01–L05, L04b читает верный слот), на шаре с 13:45 |
| `out/LoginManager.exe.loginpatch.exe` | 245 760 | **`51db86b2a1c44b91b11bebfc343e88be`** | на шаре с 12:45 (сток на 5 площадках обхода + P17 + инъекция) |
| прежние DLL | 126 464 / 130 048 / 134 656 / 138 240 | `5b1c3916…` (стаб) / `03499467…` (L01) / `194bf5d3…` (L01–L03) / `b97b99be…` (L01–L04a/b) / `a5ac8328…` (L01–L05, L04b со слотом группы) | история, см. L0x-доки |
| прежние exe | 245 760 | `6c4c6691…` (инъекция поверх живого с обходом) / `a57f878b…` (де-байпас 4 площадки) | заменены, см. debypass |

DLL импортирует только `KERNEL32.dll` и `USER32.dll` (оба LoginManager уже грузит), экспортирует `LoginPatchInit`.

## Что изменено в exe (119 байт)

| Где | Было | Стало |
|---|---|---|
| `DataDirectory[IMPORT]` (файл `0x170`, 8 б) | `rva 0x36EA0, size 0xB4` | `rva 0x37C40, size 0xC8` |
| `DataDirectory[IAT].Size` (файл `0x1CC`, 4 б) | `0x29C` | `0x9D38` (начало `0x2E000` то же) |
| Блок `0x37C40..0x37D38` (хвост `.rdata`) | нули | 8 исходных дескрипторов 1:1 + `LoginPatch.dll` + терминатор, INT, имя функции, имя DLL, FirstThunk `0x37D30` |

### ★ Отличие от схемы GameServer/NpcServer

У тех FirstThunk лежит в нулевом хвосте файловой части `.data`. **У LoginManager так нельзя:**
`VirtualSize` `.data` = `0x635248C` (~100 МБ) при файловой части `0x2000` — сразу за инициализированными
данными начинаются неинициализированные глобальные переменные, нули хвоста — живые переменные программы.
Поэтому FirstThunk лежит в хвосте `.rdata`, а `DataDirectory[IAT]` расширен до него: загрузчик снимает
защиту ровно с этого региона на время связывания импорта и возвращает её после.

## Проверка

Сервер локально не запускается (запрет). Механизм проверен на **собственном тестовом хосте** той же
конфигурации (x86 `/MT`, фиксированная база, IAT в `.rdata`, блок за `VirtualSize` `.rdata`), обработанном
тем же инъектором:
- без инъекции `GetModuleHandle("LoginPatch.dll") = 0`, с инъекцией — DLL загружена до точки входа;
- `loginpatch_boot.log`: все шаги до `10 dllmain-end`;
- `ConfigSet\patches.ini` создан (UTF-16), повторный старт — «все ключи на месте»;
- (история стаба 12.10 утра) `MasterEnable=0` → «НИ ОДИН патч не ставится»; `MasterEnable=1` → «реестр патчей ПУСТ», итог 0/0/0. ★ Сейчас реестр = L01–L05; на шаре `MasterEnable=1`, первый старт 12:53 — 4 Applied.

Статически на живом образе: якорь точки входа `0x41F83B` = `e8 d2 65 00 00 e9 16 fe ff ff`; инъектор
сверяет, что изменены только 5 байт заголовка и 114 байт блока, все импорты читаются, FirstThunk внутри IAT.

## Выкладка (делает владелец, при остановленном LoginManager)

1. Бэкап живого `LoginManager.exe` (md5 должен быть `12dcd9f1…`; иначе инъектор пересобрать по новому образу).
2. Положить `LoginPatch.dll` рядом с `LoginManager.exe`.
3. Заменить `LoginManager.exe` на `LoginManager.exe.loginpatch.exe` (переименовать).
4. Старт. Проверить `LoginManager\loginpatch_boot.log` (последняя строка `10 dllmain-end`) и
   `LoginManager\Log\Log_Patch\PatchLog_<дата>.txt` (якорь точки входа — байты выше).

⚠ Не путать `ConfigSet\patches.ini` (наш) с `Patch.ini` в папке сервера — это автообновление оригинала.

## Откат

Вернуть исходный `LoginManager.exe` из бэкапа. Либо в файле: по смещению `0x170` записать
`a0 6e 03 00 b4 00 00 00`, по `0x1CC` — `9c 02 00 00`. `LoginPatch.dll` без инъекции не грузится.
Рестарт LoginManager нужен в обоих направлениях.

## Как добавить патч

`src/patches/lNN_<имя>.cpp` с `PatchResult LNN_<Имя>()` → объявление в `Patches.h` → строка в `kPatches`
(`Registry.cpp`, перед терминатором) → секция в `Config.cpp` и `Config::kVersion + 1` → адреса в `LoginApi.h`
→ `build.bat`. Exe повторно инъектировать НЕ нужно — меняется только DLL.
