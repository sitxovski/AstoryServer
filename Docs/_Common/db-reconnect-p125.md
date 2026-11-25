# P125_DbReconnect — повторное подключение к SQL Server после обрыва связи

- **Дата:** 15.11.2026 (сессия srv-db-reconnect).
- **Процессы:** LoginManager (`LoginPatch.dll`, Version 9 → 10), DBManager (`DBPatch.dll`, Version 10 → 11).
- **Вид:** ★ ИСПРАВЛЕНИЕ дефекта оригинала (наша правка, в стоке этого нет).
- **Статус:** **ВЫЛОЖЕН 15.11.2026 15:27:53** по слову владельца, стойка перезапущена (старт 15:29). PatchLog: LoginManager
  «применено 9, ошибок 0», DBManager «применено 11, ошибок 0», `[OK] P125_DbReconnect` в обоих; журналов ошибок базы после
  старта нет. Настоящий обрыв на живой стойке ещё не случался — работа переподключения в поле не наблюдалась.
- **Отчёт:** `Reports/login_db_reconnect/REPORT.md`.

## Симптом и диагноз

15.11.2026 игроки получали «Login failed. Error 0»; в `LoginManager\Log\LoginMngError\LoginProc_20261115.txt` —
`[LOGIN] UPUserLogin Error`, в `OLEDB_LOG` обоих процессов — `HRESULT Error : DEFAULT, No such interface supported, 80004005 … :: Execute Error`
на каждой из 10 сессий.

Причина обрыва: **14.11.2026 21:08:15** служба Tailscale на сервере сама обновилась до 1.104.7 (журнал Windows: MsiInstaller
21:07:59–21:08:19, служба остановлена 21:08:15, запущена 21:08:17). Соединения стойки с SQL Server шли по TCP на адрес Tailscale
`@@ASTORY_SERVER_VPN_IP@@`: DSN `joy1` (пользовательский, драйвер `SQLSRV32.dll`) указывает на `@@ASTORY_SERVER_HOSTNAME@@\SQLEXPRESS`, а имя `@@ASTORY_SERVER_HOSTNAME@@` разрешается
в адрес Tailscale. Интерфейс пропал на 2 секунды — все соединения оборваны.

Дефект кода: класс работы с базой (один и тот же в LoginManager и DBManager; OLE DB, поставщик MSDASQL поверх DSN)
открывает источник и 10 сессий **один раз при старте** и не открывает заново никогда.

| | LoginManager (`51db86b2…`) | DBManager (`3d05c835…`) |
|---|---|---|
| объект класса | `0x0043ACD8` | `0x0534E7F0` |
| конструктор | `sub_40E8E0` | `sub_446BA0` |
| открытие источника (один раз при старте) | `sub_40EC40` (вызов — `LoginManager.c` строка 853) | `sub_446F00` (вызов — `DBManager.exe.c` строка 1921) |
| создание 10 сессий | `sub_40F230` | `sub_447510` |
| запрос (38 / 310 вызовов) | `sub_40F440` | `sub_447720` |
| вызов `ICommand::Execute` | `0x0040F7A9` | `0x00447B49` |
| ветка ошибки `Execute` | `0x0040F7C1`: `*status = 0`, строка «Execute Error», `return 0` | `0x00447B61`: то же |
| описание ошибки | `sub_410C00` → `sub_410CD0` | `sub_4492E0` |

Раскладка объекта: 20 источников по `0x14410` б; в источнике `+0` `IDBInitialize*`, `+8` четыре свойства (окно входа, пользователь,
пароль, DSN), `+0xD8` `DBPROPSET`; сессии с `+0xF0` по `0x2050` б: `+0` `IDBCreateSession*`, `+4` объект сессии, `+8` `IRowset*`,
`+0xC` `ICommandText*`, `+0x50` текст запроса; счётчик открытых источников `+0x195140`. Номер сессии = номер рабочего потока.

Попутно: `sub_410CD0` перед чтением сведений об ошибке зовёт `SetErrorInfo(0, NULL)` и тем стирает их — отсюда вечное
«DEFAULT, No such interface supported» в `OLEDB_LOG` вместо настоящего текста драйвера. Не исправлялось (настоящий текст теперь
пишет P125 в PatchLog при обрыве).

## Что изменено

Один перехват на образ, 5 байт, `.text` файла не меняется (ставит DLL в памяти после сверки):

| образ | адрес | было | стало |
|---|---|---|---|
| LoginManager | `0x0040F7A9` | `8b 42 10 ff d0` (`mov eax,[edx+10h]` / `call eax`) | `e8 rel32` → `DbReconnect::ExecuteHook` |
| DBManager | `0x00447B49` | `8b 51 10 ff d2` (`mov edx,[ecx+10h]` / `call edx`) | `e8 rel32` → `DbReconnect::ExecuteHook` |

Перед установкой сверяются ещё: соседние команды (`0x40F7A6` / `0x447B46` — `push cmd`; `0x40F7AE` / `0x447B4E` —
`mov [ebp-1024h],eax`), `lea` адреса поля результата (`0x40F740` / `0x447AE0`, `+0xF8`) и CLSID поставщика в образе
(`0x4309C0` / `0x478DA0` = MSDASQL). Несовпадение — `MISMATCH`, патч не ставится.

`ExecuteHook` (общий модуль `AstoryServer/Patches/DbReconnect/src/DbReconnectCore.cpp`) зовёт `Execute` сам. Успех — как сток. Ошибка:

1. Оборвана ли связь: SQLSTATE `08xxx` или сетевой код (10054, 10053, 10060, 10061, …) в сведениях об ошибке → оборвана;
   классы обычных ошибок SQL (21, 22, 23, 37, 40, 42, S0) → поведение стока; иначе — проверка `SELECT 1` на той же сессии.
2. Оборвана — для ЭТОЙ сессии создаются свой источник MSDASQL с теми же свойствами (DSN, пользователь, пароль берутся из
   объекта стока), сессия и команда; три указателя записи сессии подменяются; старые объекты освобождаются.
3. Запрос повторяется один раз на новой команде; стоку возвращается результат повтора.

Не удалось открыть заново или повтор не прошёл — стоку возвращается ошибка, он ведёт себя как прежде. После неудачной попытки
сессия не пробует снова `RetryIntervalMs`.

## Ключи

`LoginManager\ConfigSet\patches.ini` и `DBManager\ConfigSet\dbpatch.ini`, секция `[P125_DbReconnect]` (дописывается DLL при старте):

| ключ | умолчание | смысл |
|---|---|---|
| `Enabled` | 1 | 0 — сток |
| `Retry` | 1 | повторить запрос один раз после переподключения; 0 — только открыть сессию заново |
| `Probe` | 1 | при неясных сведениях об ошибке проверять связь `SELECT 1` |
| `ReleaseOld` | 1 | освобождать объекты оборванной сессии |
| `ComInit` | 1 | включить COM на рабочем потоке перед его первым запросом (без этого поставщик не оставляет сведений об ошибке, обрыв определяется только `SELECT 1`) |
| `RetryIntervalMs` | 10000 | пауза после неудачной попытки (в это время запросы сессии сразу отдают ошибку стоку) |
| `ConnectTimeoutSec` | 5 | предел ожидания нового подключения |
| `LogPerMinute` | 30 | строк PatchLog о переподключениях в минуту |

## Границы

- Повтор после обрыва на отправке запроса безопасен (до сервера запрос не дошёл — так было 14.11: соединения простаивали).
  При обрыве на приёме ответа сервер мог успеть выполнить запрос — повтор выполнит его второй раз. Выключается `Retry=0`.
- Не покрыты: `RelayServer` ×3, `ItemRelayServer`, `OperationServer` — у них тот же поставщик и та же строка «Execute Error»
  (другая сборка того же класса: журнал без номеров источника и сессии), но нет ни загрузчика наших DLL, ни декомпила. После обрыва им по-прежнему нужен перезапуск.
- Журнал античита (`AsdaAcJournal`, наш ODBC) переподключается сам (`ReconnectSec`), `AsdaEacServer` ходит через `127.0.0.1`.

## Файлы

- Модуль: `AstoryServer/Patches/DbReconnect/src/DbReconnectCore.{h,cpp}`.
- Патч: `AstoryServer/Patches/LoginPatch/src/patches/p125_db_reconnect.cpp`, `AstoryServer/Patches/DBPatch/src/p125_db_reconnect.cpp`.
- Конфиг/реестр/сборка: `Config.cpp`, `Config.h`, `Registry.cpp`, `Patches.h`, `build.bat` обеих DLL.
- Проверка: `AstoryServer/Patches/DbReconnect/tools/run_stand_p125.py` (стенд), `verify_p125.py` (сверка байтов).
- Выкладка: `AstoryServer/Patches/DbReconnect/tools/deploy_p125.py`.
- Сборки: `LoginPatch/out/LoginPatch.dll` md5 `2dcf9be9008975242692421fe376799d`, `DBPatch/out/DBPatch.dll` md5 `f90f0faa50be7584dc0af855acc06cc5`.
- Бэкап до правки: `@@ASTORY_DEV_ROOT@@\_backup\2026-11-15_db_reconnect\` (исходники и прежние DLL `1bff1b63…`, `740562a4…`).

## Выкладка и откат

Нужен перезапуск LoginManager и DBManager (DLL занята процессом), то есть всей стойки.

```
py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DbReconnect/tools/deploy_p125.py            # сухой прогон, только чтение
py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/tools/restart_stack.py --deploy @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DbReconnect/tools/deploy_p125.py
py -3.13 @@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/DbReconnect/tools/deploy_p125.py --check    # после старта
```

Откат: `deploy_p125.py --rollback` при остановленных процессах (DLL из `*.bak_20261115_p125`), либо без замены DLL —
`[P125_DbReconnect] Enabled=0` в обоих ini и перезапуск.
