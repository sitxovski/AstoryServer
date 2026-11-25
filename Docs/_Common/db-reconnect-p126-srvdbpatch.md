# P126_DbReconnect — переподключение к SQL Server в RelayServer ×3, ItemRelayServer, OperationServer (SrvDbPatch.dll)

- **Дата:** 15.11.2026.
- **Процессы:** RelayServer.exe (папки `RelayServer`, `Indun_RelayServer`, `Ch2_RelayServer`), ItemRelayServer.exe, OperationServer.exe.
- **Вид:** ★ ИСПРАВЛЕНИЕ дефекта оригинала (наша правка). То же, что [P125](db-reconnect-p125.md) у LoginManager/DBManager.
- **Статус:** собран, проверен на стенде, **НЕ выложен** (нужно слово владельца и перезапуск стойки).
- **Отчёт:** `Reports/relay_db_reconnect/REPORT.md`.

## Дефект

Класс работы с базой тот же, что у LoginManager (OLE DB, MSDASQL, DSN `joy1`), но другая сборка: 10 источников по `0xA410` б,
10 сессий по `0x1050` б, счётчик `+0x668A0`. Источник и сессии открываются один раз при старте; функция запроса при ошибке
`Execute` пишет «`%s :: Execute Error`» в `OLEDB_LOG` и возвращает 0, повторного открытия нет. После обрыва 14.11 21:08:15 все
пять процессов работали без базы до перезапуска.

| | RelayServer | ItemRelayServer | OperationServer |
|---|---|---|---|
| объект | `0x00427A30` (глобальный) | не на постоянном месте: по одному в каждом CNpcSession (`+0x68`, куча, 1 сессия на поток NPC) + временный на стеке `sub_408110` | `0x00414660` (глобальный) |
| конструктор | `sub_411830` | `sub_40B710` | `sub_406790` |
| открытие источника | `sub_411340` | `sub_40B220` | `sub_4062A0` |
| функция запроса | `sub_411920` (48 вызовов) | `sub_40B800` (5) | `sub_406880` (11, все — сессия 0) |
| площадка | `0x00411ADB` | `0x0040B9BB` | `0x00406A3B` |
| CLSID MSDASQL | `0x00420CC8` | `0x004288BC` | `0x0040C29C` |

Отличия от P125: (1) размеры массивов; (2) на площадке между `mov eax,[edx+10h]` и `call eax` стоит `mov [esp+44h],ecx` —
заменяются 9 байт: `8b4210 894c2444 ffd0` → `89 4c 24 44` + `e8 rel32`; (3) у ItemRelayServer нет постоянного адреса объекта —
источник сессии ищется по самой записи (DBPROPSET источника указывает на свои же свойства `+8`, набор DBPROPSET_DBINIT);
(4) в журнале стока нет номеров источника и сессии. Запись сессии (`+0/+4/+8/+0xC/+0x50`) и источник (`+0/+8/+0xD8`) совпадают.

## Что сделано

- Общий модуль `AstoryServer/Patches/DbReconnect/src/DbReconnectCore.{h,cpp}` параметризован: `Host::layout` (умолчания = P125),
  `objBase = 0` — режим поиска. LoginPatch/DBPatch не менялись, их регресс прошёл.
- Новая DLL `AstoryServer/Patches/SrvDbPatch/` (загрузчик через инъекцию импорта, как LoginPatch; блок и FirstThunk в хвосте
  `.rdata` — у всех трёх `.data` ≈70 МБ BSS). Образ выбирается по имени exe; перед установкой сверяются площадка, соседние команды,
  `lea ebp,[esi+0F8h]`, `push IID_IRowset` и сам IID, CLSID, начало функции запроса. Несовпадение — MISMATCH, не ставится.
- OperationServer: если в `ini\ServerInfo.ini` `QueueThreadCount > 1` (потоки делят сессию 0), `ReleaseOld` принудительно 0.

## Ключи

`<папка>\ConfigSet\srvdbpatch.ini` (создаёт сама DLL): `[General] Version=1 MasterEnable=1 LogEnabled=1`,
`[P126_DbReconnect]` — `Enabled=1 Retry=1 Probe=1 ReleaseOld=1 ComInit=1 RetryIntervalMs=10000 ConnectTimeoutSec=5 LogPerMinute=30`
(смысл — как у P125). Журнал: `<папка>\Log\Log_Patch\PatchLog_<дата>.txt`, ранний — `srvdbpatch_boot.log`.

## Файлы

- `SrvDbPatch/src/{dllmain,Config,Registry,p126_db_reconnect}.cpp`, `Config.h`, `Patches.h`, `build.bat`.
- `SrvDbPatch/tools/inject_import_srvdb.py` (инъекция и `--check`), `run_stand_p126.py` + `stand_p126/`, `host_inject/` (проверка загрузчика).
- Сборки: `out/SrvDbPatch.dll` md5 `51a77c74cec3c72a8338634bb8fe6f1b`; exe — `RelayServer.exe.srvdbpatch.exe` `6851e000…`
  (RelayServer и Indun), `RelayServer_ch2.exe.srvdbpatch.exe` `418b24a2…` (Ch2), `ItemRelayServer.exe.srvdbpatch.exe` `35d01e2d…`,
  `OperationServer.exe.srvdbpatch.exe` `0f54ea70…`.
- Декомпил: `RE/ida/relay_work/idb/*/*.c`, живые копии `RE/ida/relay_work/live/`.

## Выкладка и откат

Только по слову владельца, при остановленных процессах, перезапуск стойки (`restart_stack.py`). В каждую из 5 папок: бэкап exe
(`*.bak_20261115_p126`), положить `SrvDbPatch.dll`, заменить exe на соответствующий `*.srvdbpatch.exe` (md5 живого перед заменой
обязан совпасть: a8cd94ba / 075c41a5 / b8c740b3 / a8209ce5). После старта — `[OK] P126_DbReconnect` в PatchLog каждой папки.
Откат: вернуть exe из `*.bak_20261115_p126` (DLL без инъекции не грузится) либо `[P126_DbReconnect] Enabled=0` и перезапуск.
Скрипт — `SrvDbPatch/tools/deploy_p126.py` (сухой прогон / `--apply` / `--rollback` / `--check`); `--apply` и `--rollback` сами
правят `AsdaPatch/tools/stack_layout.py` → `EXE_MD5` трёх RelayServer («после» 6851e000…/418b24a2…, «до» a8cd94ba…/075c41a5…),
иначе `stack_parity` останавливает стойку (так было при выкладке 15.11 18:00, правлено вручную).
