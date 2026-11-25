# AsdaEacServer — сервер EAC для AsdaReborn (Э1, 16.10.2026; ред. 3 контракта — по ревизии REVIEW_E1)

Один 64-битный процесс (служба Windows `AsdaEacServer`) с тремя слушателями по контракту
`Reports/anticheat/eac/CONTRACT.md` (§8 «Редакция 3» перекрывает §3–§6):

| Слушатель | Адрес | Что делает |
|---|---|---|
| AsdaId | `127.0.0.1:8444` (наружу — `https://@@ASTORY_AUTH_HOST@@` через Caddy) | `/token`, `/refresh`, `GET /status` (лаунчер, с 17.10.2026), JWKS, openid-configuration; JWT RS256 (CNG), пароль — `UPEacAuth`, статус учётки — `UPEacAuthStatus`, неудачи — `UPEacAuthFail` (ODBC 17) |
| Сайдкар | `0.0.0.0:15901` | AsdaSecure (`SubServer::Eac = 4`, ключ `secure_server.key`), кадры REG/ACMSG/KICK/PING и **BIND 0x05 / BIND_RESULT 0x85** (ред. 3); EOS AntiCheatServer (SDK 1.19.2.1) |
| ★ Точка статуса (А6.8) | `127.0.0.1:8447` (только локально, `[AdminStatus] Enabled=1`) | только чтение состояния EAC по учётке для админ-центра, ключ `X-Asda-Key` (раздел ниже) |
| Мост | `127.0.0.1:15702` (только локально) | P73 GameServer/Indun, **протокол v2** (HELLO ver=2, LOGIN/REBIND с bind); только процесс `GameServer.exe` из каталогов стойки |

Модель потоков: ядро (сайдкар + мост + EOS + политика) — одна нить на `WSAPoll` с тиком EOS каждые 30 мс
(EOS SDK однопоточен; таблица привязок без блокировок). Живучесть под шквалом соединений — порядком и пределами прохода,
а не нитями (мост и зарегистрированные — первыми, слушатели — последними, ≤ `AcceptPerPass` accept за проход, token bucket
на IP и общий, отказы — сводкой). AsdaId — нить ввода-вывода (все соединения в `WSAPoll`, общий срок запроса 5 с от accept),
пул нитей БД (получают только прочитанный целиком запрос) и фоновая нить. Обоснование — `src/Core.h`, `src/AsdaId.h`.

## Политика (ред. 3)

Игровая сессия защищена, только если одновременно: EAC-сессия учётки (`sessionUserIndex` после REBIND) **Authenticated**
(пришёл `RemoteAuthComplete`; `RegisterClient` и `LocalAuthComplete` недостаточно), она прислала **BIND, равный bind из
LOGIN/REBIND** (сверяется только значение; serverKind клиент шлёт всегда 2 — для журнала), bind ненулевой, и при
`RequireSameIp=1` IP канала 15901 = IP игры. BIND принимается и до Authenticated (до 4 на сессию, несопоставленные
живут 300 с); `BIND_RESULT 2` — только если REG этой сессии не принят. Иначе:

| Ситуация | Срок | Причина |
|---|---|---|
| у учётки нет EAC-сессии | `BindTimeoutSec` от LOGIN/REBIND | 1 |
| была защищена, канал EAC потерян | `GraceSec` от потери | 3 |
| EAC-сессия есть, но не Authenticated / регистрация отклонена (помнится `RejectMemorySec`) | BindTimeout или Grace | 4 |
| Authenticated, но BIND не пришёл / не совпал / bind нулевой / IP (RequireSameIp) | BindTimeout или Grace | 6 |

§8.6 (R3-04): если за 120 с после HELLO процесса P73 пришло ≥ 5 LOGIN и все с нулевым bind, в журнале — «P61 у процесса не
активен»; причина 6 к сессиям этого процесса не применяется (их защищает аутентифицированная EAC-сессия учётки, как до ред. 3),
причины 1/3/4 работают. Первый LOGIN процесса с ненулевым bind снимает вывод. Окно без вывода (< 5 нулевых LOGIN) открывается
заново при следующем HELLO того же процесса.

`AuthTimeoutSec=90` от `RegisterClient` без RemoteAuthComplete — канал закрывается (KICK 4 клиенту в Mode 2). REG одной
учётки — не больше 6 за 10 мин (§8.6 R3-01; REG, вытесняющая Authenticated-сессию той же учётки с того же IP, в лимит не
считается), с одного IP — 10 в минуту (лишние — `REG_RESULT 3`). Вытеснение не сбрасывает и не
продлевает отсчёт игровой сессии; в Mode 1 вытесненному — без KICK, канал просто закрывается.
FailOpen: до первой BeginSession, окно после старта, «Epic недоступен» (доля временных отказов VerifyIdToken ≥ 50 % от
≥ 5 разных IP за 60 с, или ≥ `EosCallErrorsMax` временных ошибок вызовов EOS за окно), «AsdaId деградировал» (доля 503
≥ 50 % при ≥ 5 запросах за 60 с). §8.6 (R3-03): временный отказ VerifyIdToken отдельную учётку от кика НЕ освобождает —
только глобальный FailOpen по этим порогам.

## Сборка

```
build.bat          — всё (Visual Studio 2022, vcvars64, /MT)
build.bat test     — всё + все стенды (stand\run_stands.bat)
```

Выход: `out\AsdaEacServer.exe` (+ `.pdb`), `out\EOSSDK-Win64-Shipping.dll` (грузится отложенно — с `--no-eos`
не нужна), `out\EacServer.ini.sample`; стенды — `out\stand\` (`AsdaEacServer_stand.exe` собран с `ASDA_EAC_STAND`).

## Ключи командной строки

| Ключ | Смысл |
|---|---|
| `--console` | работа в консоли, Ctrl+C / Ctrl+Break — штатный останов |
| `--service` | запуск под SCM (так прописывает `--install-service`) |
| `--install-service` | создать службу: автозапуск (отложенный), LocalSystem, перезапуск при сбое 5 с / 5 с / 30 с, и при выходе с ненулевым кодом |
| `--uninstall-service` | остановить и удалить службу |
| `--config <ini>` | другой ini (по умолчанию `EacServer.ini` рядом с exe) |
| `--no-eos` | не инициализировать EOS: REG → `REG_RESULT 3`, при `FailOpen=1` никого не кикаем |
| `--eos-smoke` | `EOS_Initialize` + `Platform_Create` + `BeginSession` + 3 с тиков + `EndSession`, код 0 — успех (нужен `secrets\eos.json`) |
| только `AsdaEacServer_stand.exe`: `--fake-auth`, `--fake-eos`, `--sql-probe <логин> <md5>`, `--sql-probe-status <UserIndex>` | таблица учёток стенда / имитация EOS (сценарии — `src/EosLayer.h`) / один вызов `UPEacAuth` или `UPEacAuthStatus` настоящим ODBC (пароль SQL — из stdin). В рабочем exe этих ключей нет |

## `GET /status` — пинг и состояние для лаунчера (17.10.2026)

Ответ `200 {"online":<login&&game>,"login":<bool>,"game":<bool>}`, `Cache-Control: no-store`; не GET — 405.
`login`/`game` — слушает ли кто-то `StatusLoginPort`/`StatusGamePort` (таблица слушающих сокетов Windows,
`GetExtendedTcpTable`). **К LoginManager и GameServer никто не подключается** — их лимиты (LoginPatch: 120 соединений
с IP за 60 с, 16 ожидающих) не расходуются. Ответ кэшируется на `StatusCacheMs`, поэтому любое число лаунчеров — одна
проверка за 2 с; на самом сервере запрос занимает ~1 мс (AsdaId) / ~1 мс (Caddy, тёплое соединение).
Лаунчер (`AstoryClient\Launcher\src\Ping.cpp`) опрашивает раз в 2 с по одному keep-alive HTTPS-соединению, на свёрнутом окне —
пауза. Проверка: `curl https://@@ASTORY_AUTH_HOST@@/status`. Стенд: `stand_asdaid` (4 проверки `/status`).

## ★ Точка статуса для админ-центра (А6.8, 22.11.2026) — `127.0.0.1:8447`, только чтение

`src/AdminStatus.{h,cpp}`: своя нить, слушает ТОЛЬКО 127.0.0.1 (соединение не с 127.0.0.1 закрывается), GET `/eac/v1/summary`,
`/eac/v1/account/<UserIndex>`, `/eac/v1/accounts[?limit=N]` (JSON, схема `a68.1`): канал EAC учётки (состояние, Authenticated,
регистрация, PING, BIND), игровые сессии P73 (защита, bind, срок, решение и «почему без KICK», KICK), последние события учётки
(история в ядре `Core.cpp` `Ev` — только при `Enabled=1`). IP — только в полях `net`. Доступ — заголовок `X-Asda-Key` = первая строка
`[AdminStatus] SecretFile` (≥ 32 знаков; на стойке создан выкладчиком, копия — `@@ASTORY_SERVER_ROOT@@\AdminCenter\secrets\eac_status.key`); 401 / 429
(частота и отказы по ключу), запрос и ответ — каждый за `DeadlineMs`. Ядро по запросу точки строит снимок ТОЛЬКО спрошенного
(★ ревизия 61: сводка — счётчики, учётка — только её записи, список — лёгкие строки без истории; схема `a68.2`) и отдаёт его под
коротким замком (`AdminStatus::Board`) — нить ядра не ждёт HTTP; замер такта — `server.core` в ответе, стенд S7 (5 000 учёток:
снимок 2,6 мс, проход ядра 4,7 мс; до ревизии 61 — 33,3 / 44,2 мс). Точка не запустилась (нет секрета, порт занят, ошибка секции
`[AdminStatus]`) — EAC работает без неё (строка `[adm]`).
Ключи `[AdminStatus]`: `Enabled` (0 — как до А6.8), `Port` 8447, `SecretFile`, `ReqPerSec` 20, `ReqBurst` 40, `FailPerMin` 5,
`DeadlineMs` 2000, `SnapshotMaxAgeMs` 1000, `EventsPerAccount` 20, `EventKeepSec` 86400, `MaxAccounts` 5000.
Стенд (ж) `stand_status` (61 проверка); `ASDA_STAND_STATUS=1` — все стенды с включённой точкой (итоги те же).
Выкладка — `tools/deploy_eac_a68.py` (сухой прогон по умолчанию, `--apply` только при 0 игроков, `--check`, `--rollback`);
документ — `AstoryServer/Docs/_Common/eac-admin-status-a68.md`. Наружу (Caddy, брандмауэр) точку НЕ открывать.

## Конфиг `EacServer.ini`

Образец с комментариями — `config\EacServer.ini`. Относительные пути считаются от папки exe (служба стартует
в System32). Главное:

- `[General] Mode` 0/1/2, `FailOpen`, `FailOpenStartupSec=120`, `EpicDownHoldSec=60`; пороги ред. 3: `EpicDownWindowSec=60`,
  `EpicDownMinIps=5`, `EpicDownRatioPct=50`, `EosCallErrorsMax=5`, `IdDegradedWindowSec=60`, `IdDegradedMinRequests=5`, `IdDegradedRatioPct=50`.
- `[Secrets]` `EosJson`, `JwtKey` (создаётся при первом запуске), `SqlPasswordFile`, `SecureKeyFile=..\GameServer\secure_server.key`.
- `[Sidecar]` тайминги §3; ред. 3: `AuthTimeoutSec=90`, `RegPerAccountMax=6`/`RegPerAccountWindowSec=600` (§8.6), `RegPerIpPerMin=10`,
  `BindKeepSec=300`, `MaxBindsPerSession=4`, `MaxUnregPerIp=16` (с проверкой токена), `AcceptPerPass=32`,
  `ConnectRatePerIp=5`/`ConnectBurstPerIp=20`, `ConnectRateGlobal=300`/`ConnectBurstGlobal=600`, `RejectSummarySec=10`.
- `[Bridge]` порт (адрес всегда 127.0.0.1); ред. 3: `CheckPeerProcess=1`, `AllowedImageNames=GameServer.exe`,
  `AllowedImageDirs=..\GameServer;..\Indun_GameServer` (копии `GameServer.exe` в `NpcServer`, `Indun_NpcServer` НЕ пускаются).
- `[Policy] BindTimeoutSec=60 GraceSec=30 KickRepeatSec=30 RequireSameIp=0 RejectMemorySec=300 VerifyWaitSec=15 OperatorUserIndex=`.
- `[AsdaId]` лимиты §2; ред. 3: `LoginFailMax=5` (на пару логин+IP), `LoginGlobalFailMax=10`, `LoginPauseStagesSec=60,300,3600`,
  `LoginKnownIpDays=30`, `FailWrite=1`, `FailWriteDelayMs=3000`, `RefreshTtlSec=43200` (с последнего использования),
  `RefreshAbsoluteSec=604800`, `RefreshFile=secrets\refresh.dat`, `StatusRecheckSec=900`, `RequestDeadlineSec=5`,
  `MaxPendingConns=1024`, `Workers=8`, `WwwDir=www`; ★ 17.10.2026 `StatusLoginPort=15001`, `StatusGamePort=15601`, `StatusCacheMs=2000`.
- `[Sql] ConnectionString` (без пароля!); `[Eos] RegisterTimeoutSec=60 TickMs=30 LogLevel=500`.

Пароль в `ConnectionString` запрещён (процесс не стартует) — только файл секрета. Секреты и токены в журнал не
пишутся (журнал EOS дополнительно вымарывается: ClientSecret, `Basic …`, `Bearer …`, `eyJ…`); bind — только отпечаток 4 байт.

## SQL (`sql\`)

  подпись `EacAuthSign`, логин `eac_auth` — только `EXECUTE`. ⚠ `ALTER PROCEDURE` снимает подпись — запускать весь скрипт.
  отпечаток пароля) и `UPEacAuthFail(@login)` (запись только `us_pwfail`/`us_pwfail_at` по логике замка `UPUserLogin`;
  повтор < 5 с не засчитывается — тот же ввод игрока уже засчитал LoginManager). Подписи `EacAuthStatusSign`/`EacAuthFailSign`,
  права пользователей-из-сертификата — по столбцам, закрытые ключи удаляются после подписи.
  Проверки на сервере: `eac_auth_smoke.ps1 [-PermProbe]`, `eac_auth_r3_smoke.ps1` (в том числе сверка замка с копией живой `UPUserLogin`).
- **Применено на dev-БД 16.10.2026** (см. `Reports/anticheat/eac/SERVER_REPORT.md`, раздел «Ред. 3»).

```
```

## Стенды (`stand\`)

`stand\run_stands.bat` (или `build.bat test`): (а) `stand_asdaid` — AsdaId (в т.ч. медленные клиенты, пары логин+IP,
refresh на диске, перепроверка учётки); (б) `stand_bridge` — фальшивый P73 v2 и политика ред. 3 (Authenticated, BIND,
FailOpen по порогам, проверка процесса моста); (в) `stand_sidecar` — 15901 через AsdaSecure (BIND, лимиты, AuthTimeout,
шквал 12 и 300 нитей с одного IP); (д) `e2e_r3` — сквозной стенд ревизора, адаптированный под ред. 3 (S0 — настоящая
DLL P73 w73: HELLO ver=1 должен быть отвергнут); (г) `--eos-smoke` без секретов (отказ с кодом 2).
`stand\review_regress\asdaid_probe_r3.py` — независимая проверка AsdaId ревизора (Python + cryptography), адаптированная:
`python -X utf8 -I asdaid_probe_r3.py`. Секреты не нужны. Порты стендов: 18444–18446, 18544, 18644, 25701–25803.

## Развёртывание (этап Э2-0 — НЕ выполнено, только описание)

1. Скопировать в `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\EacServer\`: `AsdaEacServer.exe`, `EOSSDK-Win64-Shipping.dll`,
   `EacServer.ini` (из `config\EacServer.ini`; на старте альфы `Mode=1`). Папка `secrets\` уже есть
   (`eos.json`, `sql_eac_auth.txt`); `jwt_rs256.key` и `refresh.dat` создадутся при первом запуске.
   Сервер сам пишет статику для Caddy: `www\.well-known\jwks.json` и `www\.well-known\openid-configuration`.
2. Проверка EOS: `AsdaEacServer.exe --eos-smoke` → «итог OK» в `logs\eac_*.log`.
3. Служба: `AsdaEacServer.exe --install-service`, затем `sc start AsdaEacServer`.
   Откат: `AsdaEacServer.exe --uninstall-service` (или `sc stop AsdaEacServer & sc delete AsdaEacServer`).
4. Брандмауэр (входящие):
   ```
   netsh advfirewall firewall add rule name="AsdaEac 15901" dir=in action=allow protocol=TCP localport=15901
   netsh advfirewall firewall add rule name="AsdaEac 443 (Caddy)" dir=in action=allow protocol=TCP localport=443
   ```
   Откат: `netsh advfirewall firewall delete rule name="AsdaEac 15901"` и `... name="AsdaEac 443 (Caddy)"`.
   Порты 8444 и 15702 наружу НЕ открывать (слушают только 127.0.0.1).
5. Caddy v2 (TLS Let's Encrypt через TLS-ALPN на 443, порт 80 занят IIS). Ред. 3 (E1-05): тело буферизуется и
   ограничено 4 КиБ, сроки чтения заголовков/тела 5 с, JWKS и openid-configuration отдаются статикой (AsdaId
   их не обслуживает снаружи), прочие пути — 404. **Проверить на Э2** (синтаксис — по документации Caddy v2):
   ```
   {
       auto_https disable_redirects
       servers {
           timeouts {
               read_header 5s
               read_body   5s
               write       10s
               idle        30s
           }
           max_header_size 8KB
       }
   }
   @@ASTORY_AUTH_HOST@@:443 {
       tls {
           issuer acme {
               disable_http_challenge
           }
       }
       @wk path /.well-known/jwks.json /.well-known/openid-configuration
       handle @wk {
           root * @@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2/EacServer/www
           header Content-Type application/json
           header Cache-Control "public, max-age=300"
           file_server
       }
       @auth {
           method POST
           path /token /refresh
       }
       handle @auth {
           request_body {
               max_size 4KB
           }
           reverse_proxy 127.0.0.1:8444 {
               request_buffers 4KB
               header_up X-Forwarded-For {remote_host}
               transport http {
                   dial_timeout 2s
                   response_header_timeout 15s
               }
           }
       }
       # ★ 17.10.2026 GET /status для лаунчера
       @status {
           method GET
           path /status
       }
       handle @status {
           request_body {
               max_size 1KB
           }
           reverse_proxy 127.0.0.1:8444 {
               transport http {
                   dial_timeout 2s
                   response_header_timeout 5s
               }
           }
       }
       handle {
           respond 404
       }
   }
   ```
   `header_up X-Forwarded-For {remote_host}` — заголовок ЗАМЕНЯЕТСЯ адресом клиента (пришедший от клиента не
   передаётся); AsdaId берёт последний элемент только от 127.0.0.1 (`TrustForwardedFor=1`). Служба Caddy — по его
   инструкции (`sc create caddy ...` или WinSW); откат — `sc stop caddy & sc delete caddy`.
6. P73 v2 (`patches.ini [P73_EacBridge] Enabled=1, Mode=0, ExemptOperators=1`) подключится к 127.0.0.1:15702 сам.
   P73 v1 (HELLO ver=1) сайдкар ред. 3 отвергает (журнал: «HELLO ver=1 … ОТКАЗ»). Порт 15901 пробросить на роутере.
7. §8.6 (R3-04): **P61 `Enabled=1` (и обновлённые клиенты) — раньше `Mode=2`.** Без P61 у всех нулевой bind; сайдкар
   тогда пишет «P61 у процесса не активен» и причину 6 не применяет, но защита держится только на EAC-сессии учётки
   (обход «второй ПК» E1-02 открыт). Перед `Mode=2` проверить в журнале отсутствие этой строки и в PatchLog P73
   «из них с нулевым bind: 0».
8. Смена режимов: `Mode 0 → 1 → 2` — по контракту §8.4 клиент после `REG_RESULT 4` повторяет REG раз в 300 с, поэтому
   перед `Mode=2` выдержать ≥ 5 мин в `Mode=1` (иначе часть игроков без EAC-сессии получит KICK 1).
9. Проверки после старта: `curl https://@@ASTORY_AUTH_HOST@@/.well-known/jwks.json` (снаружи / через hosts), строка
   «статистика» в журнале раз в минуту (там же «аутентифицировано» и «защищено»), `REG ок` растёт при входе клиента.

`Remove-Item @@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\EacServer -Recurse` (папка secrets тоже — сначала сохранить `eos.json`).
