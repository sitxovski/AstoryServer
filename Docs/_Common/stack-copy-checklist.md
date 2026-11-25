# Чек-лист: новая копия папок стойки (канал, второй экземпляр процесса)

- **Дата:** 2026-10-26 (по итогам включения второго полевого канала, `Reports/channel2/REPORT.md`)
- **Где применимо:** любая новая папка-копия GameServer / NpcServer / RelayServer на @@ASTORY_SERVER_HOSTNAME@@ (`@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2`).
- **Единый состав стойки:** `AstoryServer/Patches/AsdaPatch/tools/stack_layout.py` — новую папку добавлять ТОЛЬКО туда
  (GS_FOLDERS / NPC_FOLDERS / RELAY_FOLDERS, TWINS, EXE_MD5, CHANNEL_FILES, FIREWALL_EXES); все инструменты берут его.

Шаги идут по порядку. У каждого — что сделать и чем проверить. Всё, что привязано к ПУТИ или ИМЕНИ, копия сама не
наследует.

| № | Что | Почему | Проверка |
|---|---|---|---|
| 1 | Копия с ПОЛЯ (не с Indun) без `*.dmp`, журналов, `*.bak*`; дерево журналов — пустое | у поля свои PortalConfig/DBInfo; дампы по 1 ГБ | `stack_parity.py` → ПАРИТЕТ ДА |
| 2 | Поканальные файлы: `ServerIPPORT.txt` (свой порт), `GroupInfo.ini` / `AIInfo.ini` / `ChannelInfo.ini` (индекс канала), `ConnectIPPORT.ini` + `ConnectIP_Info\*` (свои Npc/Relay), `PortalIP_Info\*` и `VillageServerConfig.Ini` (свой порт GS) | GS отдаёт клиенту адрес из своего ServerIPPORT (6017/5055); порталы и деревня ведут на порт из ini | поиск портов поля в копии — 0 совпадений; занести в `CHANNEL_FILES` |
| 3 | Имена именованных таймеров в exe копии NpcServer (`AI_ProcessThread` @0x75A70, `WaitableTimer` @0x72794/@0x727D8) и RelayServer (`WaitableTimer` @0x19038) — длина та же | объекты ядра в одной сессии общие: копии делят таймер, AI идёт вдвое реже | md5 exe копии → `EXE_MD5`; байты прочих = поле (`cmp`) |
| 4 | **Брандмауэр Windows: входящие Allow, профиль Private, TCP и UDP, по ПРОГРАММЕ — для каждого exe копии** (`New-NetFirewallRule -DisplayName "<папка> TCP" -Direction Inbound -Action Allow -Profile Private -Protocol TCP -Program "<путь exe>"`, то же UDP) | правила привязаны к пути exe; без них порт копии закрыт и снаружи, и из LAN (26.10: 15621 был закрыт) | `restart_stack.py` шаг 0 (`firewall_missing`): «у всех N exe стойки правило есть»; hairpin с сервера на внешний IP — порт OPEN |
| 5 | Проброс на роутере (только внешний порт GameServer копии) — делает владелец | — | hairpin с сервера: порт OPEN, контрольный закрытый порт — closed |
| 6 | EAC: `EacServer\EacServer.ini` `AllowedImageDirs` + папка копии GS, перезапуск службы `AsdaEacServer` | мост P73 пускает GameServer.exe только из перечисленных каталогов | `eac_*.log`: «HELLO v2 … порт <порт копии>» |
| 7 | Defender | исключения — по всей `v2` и по ИМЕНАМ процессов (`os-boost-power-priority-av.md` А3) — копия уже покрыта | `Get-MpPreference` |
| 8 | ChannelManager `ChannelCount`, LoginManager `GameServerIP.ini` / `<гр>_<канал>_ServerIP.ini` / `CreateGameServerIP.ini` (для полевого канала) | вход и маршрут смены канала (PLAN §1.2, §1.4) | на входе канал активен; Operation `ConnectionLog`: «Connect … Channel N» у трёх процессов |
| 9 | `start.bat` — строки запуска копии; `stack_layout` — папки, EXPECT, CRITICAL_FILES | запуск и проверка стойки | `restart_stack.py`: «процессы: … OK», [OK] копии = [OK] поля |
| 10 | Паритет данных: выкладки/скрипты данных только через `stack_layout` | иначе следующая выкладка разведёт копию и поле | `stack_parity.py` (restart_stack зовёт до остановки и `--sync` после выкладки) |

Файлы, которые серверы пишут во время работы (EventLog.txt, *.log, ErrTrace.txt, *.dmp, счётчики), в паритет не входят —
`stack_layout.RUNTIME_FILES`.
