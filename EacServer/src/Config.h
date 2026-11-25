// Copyright (c) 2026 @sitxovski (Discord)
// Config.h — настройки AsdaEacServer из EacServer.ini (рядом с exe) и секреты EOS из secrets\eos.json.
// Значения по умолчанию — из контракта (eac/CONTRACT.md §2–§7); ini может их менять (стенды ставят малые тайминги).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace Eac
{
    // Все настройки процесса. Пути — уже абсолютные (ResolvePath от папки exe).
    struct Config
    {
        // [General]
        int  mode = 1;                        // 0 выкл (REG_RESULT 4, кик никогда), 1 журнал, 2 кик (§6)
        bool failOpen = true;                 // FailOpen=1: Epic недоступен / до первой BeginSession / окно после старта — не кикать
        int  failOpenStartupSec = 120;        // окно «не кикать» после старта процесса (§6: 120 с)
        int  epicDownHoldSec = 60;            // сколько держать FailOpen после признания «Epic недоступен» / «AsdaId деградировал»
        // ред. 3 §8.3 (E1-03): «Epic недоступен» — по отказу BeginSession, по ошибкам вызовов EOS в нити ядра или по доле
        // временных отказов VerifyIdToken ≥ EpicDownRatioPct % от ≥ EpicDownMinIps разных IP за EpicDownWindowSec.
        int  epicDownWindowSec = 60;          // окно счёта временных отказов VerifyIdToken и ошибок вызовов EOS
        int  epicDownMinIps = 5;              // минимум разных IP среди временных отказов
        int  epicDownRatioPct = 50;           // доля временных отказов среди всех ответов VerifyIdToken за окно, %
        int  eosCallErrorsMax = 5;            // столько временных ошибок RegisterClient/ReceiveMessageFromClient за окно — Epic недоступен
        // ред. 3 §8.3 (E1-09): «AsdaId деградировал» — доля 503 ≥ DegradedRatioPct % за DegradedWindowSec при ≥ DegradedMinRequests.
        int  idDegradedWindowSec = 60;        // окно счёта ответов /token и /refresh
        int  idDegradedMinRequests = 5;       // минимум запросов в окне
        int  idDegradedRatioPct = 50;         // доля 503, %
        std::wstring logDir;                  // папка журнала (logs)
        int  logLevel = 2;                    // 0 ошибки … 3 отладка
        int  statsSec = 60;                   // период строки статистики в журнале

        // [Secrets]
        std::wstring eosJson;                 // secrets\eos.json (ClientId/Secret AlphaServer)
        std::wstring jwtKey;                  // secrets\jwt_rs256.key (создаётся при первом запуске)
        std::wstring sqlPasswordFile;         // secrets\sql_eac_auth.txt (пароль SQL-логина eac_auth)
        std::wstring secureKeyFile;           // ..\GameServer\secure_server.key (AsdaSecure, только чтение)

        // [Sidecar] — TCP 15901 (§3, ред. 2: 15701 занят NpcServer)
        std::string sidecarBind = "0.0.0.0"; // адрес слушателя
        int  sidecarPort = 15901;
        int  handshakeTimeoutSec = 10;        // рукопожатие AsdaSecure должно завершиться за это время
        int  regTimeoutSec = 30;              // REG в течение 30 с после рукопожатия (§3)
        int  pingTimeoutSec = 30;             // без PING 30 с — разрыв (§3)
        int  verifyTimeoutSec = 45;           // страховка: ответ VerifyIdToken/регистрации не пришёл
        int  maxConnections = 2000;           // предел одновременных соединений 15901
        int  maxUnregPerIp = 16;              // предел незарегистрированных (рукопожатие / ждём REG / проверка токена) с одного IP
        int  maxQueuedAcMsg = 64;             // ACMSG, пришедшие во время проверки токена (буфер до RegisterClient)
        // ред. 3 §8.2 (E1-01)
        int  authTimeoutSec = 90;             // от RegisterClient до RemoteAuthComplete; иначе причина 4 и закрытие канала
        // ред. 3 §8.6 (R3-01): 6 за 10 мин; REG, вытесняющая Authenticated-сессию той же учётки с того же IP 15901, в лимит не считается
        int  regPerAccountMax = 6;            // REG одной учётки (подтверждённых Epic) не больше стольких …
        int  regPerAccountWindowSec = 600;    // … за это окно; лишние — REG_RESULT 3 и закрытие канала
        // ред. 3 §8.3 (E1-03): лимит REG на IP
        int  regPerIpPerMin = 10;             // кадров REG с одного IP в минуту; лишние — REG_RESULT 3 и закрытие
        // ред. 3 §8.1 (E1-02): BIND
        int  bindKeepSec = 300;               // сколько хранить BIND, ещё не сопоставленный с игровой сессией
        int  maxBindsPerSession = 4;          // до стольких последних BIND на EAC-сессию
        // E1-04: защита цикла приёма
        int  acceptPerPass = 32;              // не больше стольких accept за проход цикла ядра
        int  connectRatePerIp = 5;            // token bucket на IP: соединений в секунду …
        int  connectBurstPerIp = 20;          // … и запас (всплеск)
        int  connectRateGlobal = 300;         // общий token bucket: соединений в секунду …
        int  connectBurstGlobal = 600;        // … и запас
        int  rejectSummarySec = 10;           // отказы приёма пишутся в журнал сводкой раз в столько секунд

        // [Bridge] — TCP 127.0.0.1:15702 (§4)
        int  bridgePort = 15702;
        int  bridgeHelloTimeoutSec = 10;      // HELLO должен прийти первым за это время
        int  bridgePingTimeoutSec = 20;       // P73 шлёт PING каждые 5 с; 20 с тишины — разрыв
        int  bridgeOrphanSec = 120;           // сессии отключившегося P73 без переподключения снимаются
        // ред. 3 §8.4 (E1-13): пускать на мост только процесс GameServer.exe из каталогов стойки, pid HELLO = pid владельца соединения
        bool bridgeCheckPeer = true;          // проверять процесс-владельца соединения (GetExtendedTcpTable + путь образа)
        std::vector<std::wstring> bridgeImageNames;   // допустимые имена образа (без пути, без учёта регистра); по умолчанию GameServer.exe
        std::vector<std::wstring> bridgeImageDirs;    // допустимые каталоги образа (абсолютные, без '' в конце)

        // [Policy] (§5–§6)
        int  bindTimeoutSec = 60;             // игра без EAC-сессии учётки дольше — причина 1
        int  graceSec = 30;                   // потеря 15901 при живой игре дольше — причина 3
        int  kickRepeatSec = 30;              // повтор KICK, если P73 не снял сессию
        bool requireSameIp = false;           // ред. 3 §8.1: дополнительно требовать IP канала 15901 == IP игры
        int  rejectMemorySec = 300;           // отказ регистрации учётки (причина 4) помнится столько секунд — для причины решения
        int  verifyWaitSec = 15;              // сколько один раз подождать идущую проверку токена той же учётки (по известному PUID)
        // ★ Д2 (22.11.2026): REG учётки в предел RegPerAccountMax не считается, если за RegFreeAfterAuthSec до неё у учётки была
        //   аутентифицированная EAC-сессия с того же IP (честный перезапуск после падения клиента); 0 — как раньше.
        int  regFreeAfterAuthSec = 600;
        // ★ Д3 ред. 2 (ревизия 64, 22.11.2026): общий признак «≥ 3 учёток с токеном без REG» УБРАН (не ловил сбой 16–17.11 — учётки шли
        //   по одной; включался умышленно). Вместо него — поблажка ОДНОЙ учётке «Epic Connect у клиента не проходит» (Core.cpp ConnectGrace):
        //   только учётке, у которой уже была аутентифицированная EAC-сессия за AuthHistoryDays (история — на диске, AuthHistoryFile),
        //   пока её клиенту AsdaId выдаёт токены (последний не старше ConnectGraceTokenSec), а EAC-сессии нет; не больше
        //   пределы Р66-1 (эпизод, скользящие 24 ч, суток за 30); поблажкой кик за ClientActionRequired не глушится (FailOpen — глушит, как и прежде); 0 сек — поблажки нет.
        std::wstring authHistoryFile;         // state\auth_history.dat — формат v4 (Core.cpp HistLoad): «uid lastAuth lastViolation epStart epDur epLast
                                              //   nW окна… nU минута:мс…» (не секрет; папка — DACL SYSTEM + Administrators)
        int  authHistoryDays = 30;            // история аутентификации действует столько суток (как LoginKnownIpDays)
        int  connectGraceTokenSec = 180;      // токен AsdaId не старше стольких секунд — клиент ещё пытается войти в EOS Connect
        int  connectGraceSecPerDay = 3600;    // ★ Р66-1: поблажка на учётку за СКОЛЬЗЯЩИЕ 24 ч, с (учётка 1 16.11 — 54 мин за сутки)
        int  connectGraceEpisodeSec = 2400;   // ★ Р66-1: предел одного эпизода, с (самый длинный честный эпизод игрока 16.11 — 75220, 35 мин)
        int  connectGraceEpisodeGapSec = 600; // ★ Р66-1: перерыв короче — тот же эпизод
        int  connectGraceDaysPer30 = 2;       // ★ Р66-1: суток с поблажкой за 30 суток (сбой 16–17.11 — одно событие на двое суток)
        int  connectGraceAfterViolationDays = 30;   // ★ Р66-2: после нарушения EAC поблажки нет столько суток и до новой аутентификации
        std::string graceConfigError;         // ★ Р68-3: ключи поблажки несогласованы (AuthHistoryDays < 30 или < ConnectGraceAfterViolationDays) —
                                              //   поблажка выключена (журнал при старте), EAC работает; пусто — нет
        std::vector<uint32_t> operators;      // OperatorUserIndex= — запасной список операторов (только журнал); по умолчанию пуст:
                                              //   операторов исключает сам P73 (ExemptOperators=1, контракт ред. 2 §6)

        // [AsdaId] — HTTP 127.0.0.1:8444 (§2)
        int  idPort = 8444;
        std::string issuer = "https://@@ASTORY_AUTH_HOST@@";
        std::string audience = "astory-eac";
        int  accessTtlSec = 3600;             // exp = iat + 3600
        int  refreshTtlSec = 12 * 3600;       // E1-10: refresh живёт 12 ч с ПОСЛЕДНЕГО использования (продлевается на /refresh) …
        int  refreshAbsoluteSec = 7 * 86400;  // … но не дольше 7 суток от /token (потом — вход паролем)
        std::wstring refreshFile;             // E1-10: secrets\refresh.dat — хеши refresh под DPAPI LocalMachine
        int  statusRecheckSec = 900;          // E1-19: на /refresh не реже раза в 15 мин перепроверять учётку (UPEacAuthStatus)
        int  tokenPerIpPerMin = 10;           // 10 запросов /token в минуту с IP
        int  loginFailMax = 5;                // E1-06: 5 неудач подряд на пару (логин, IP) …
        int  loginFailPauseSec = 60;          // … пауза пары (растёт по ступеням loginPauseStagesSec, начиная с этой)
        int  loginGlobalFailMax = 10;         // E1-06: 10 неудач подряд на логин со всех IP → пауза логина по ступеням
        std::vector<int> loginPauseStagesSec; // ступени паузы: 60 → 300 → 3600 (сброс успехом)
        int  loginKnownIpDays = 30;           // IP успешного входа на логин помнится столько дней: общая пауза логина его не касается
        bool failWrite = true;                // E1-06: писать неудачи пароля в us_pwfail (UPEacAuthFail)
        int  failWriteDelayMs = 3000;         // запись — через столько мс (успеет записаться неудача того же ввода от LoginManager)
        int  requestDeadlineSec = 5;          // E1-05: весь HTTP-запрос (заголовки + тело) должен прийти за столько секунд от accept
        int  maxPendingConns = 1024;          // E1-05: соединений, ждущих запрос (сверх — закрываются сразу)
        std::wstring wwwDir;                  // E1-05: папка статики Caddy; сервер пишет www\.well-known\{jwks.json,openid-configuration}
        bool trustForwardedFor = true;        // IP клиента — из X-Forwarded-For (только от 127.0.0.1, т.е. Caddy)
        int  idWorkers = 8;                   // нити проверки по БД (запрос к ним попадает уже прочитанным целиком)
        int  idIoTimeoutSec = 10;             // не используется с ред. 3 (общий срок RequestDeadlineSec); ключ оставлен для совместимости ini
        int  maxRefreshPerUser = 10;          // активных refresh на учётку (старейший гасится)
        // ★ 17.10.2026 GET /status для лаунчера (пинг и «онлайн/офлайн»): состояние берётся из таблицы слушающих сокетов
        //   Windows (GetExtendedTcpTable) — к игровым процессам НЕ подключаемся, ответ кэшируется на StatusCacheMs.
        int  statusLoginPort = 15001;         // порт LoginManager для клиентов (слушает → вход доступен)
        int  statusGamePort = 15601;          // порт GameServer для клиентов (слушает → игровой сервер доступен)
        int  statusCacheMs = 2000;            // срок кэша ответа /status (любое число лаунчеров = одна проверка за срок)

        // ★ А6.8 (22.11.2026) [AdminStatus] — локальная точка статуса EAC по учётке для админ-центра (AdminStatus.h), только чтение.
        bool statusEnabled = false;           // Enabled=0 — точки нет и история событий не ведётся (поведение до А6.8)
        int  statusPort = 8447;               // порт на 127.0.0.1 (адрес не настраивается)
        std::wstring statusSecretFile;        // secrets\admin_status.key — общий секрет (≥ 32 знаков, одна строка), копия у службы панели
        int  statusReqPerSec = 20;            // запросов в секунду (token bucket) …
        int  statusReqBurst = 40;             // … и запас
        int  statusFailPerMin = 5;            // отказов по ключу в минуту; сверх — 429 всем до пополнения
        int  statusDeadlineMs = 2000;         // весь запрос должен прийти за столько мс
        int  statusSnapshotMaxAgeMs = 1000;   // снимок старше — ядро строит новый (по запросу)
        int  statusEventsPerAccount = 20;     // событий в истории учётки
        int  statusEventKeepSec = 86400;      // история учётки без новых событий забывается через столько секунд
        int  statusMaxAccounts = 5000;        // учёток с историей (сверх — забывается давнее всех обновлённая)
        std::string statusConfigError;        // ★ р61 М-2: ошибка секции [AdminStatus] (точка выключена, EAC стартует); пусто — нет

        // [Sql]
        std::string sqlConnString;           // строка ODBC без пароля (пароль — из sqlPasswordFile)
        int  sqlTimeoutSec = 5;               // таймаут запроса/входа

        // [Eos]
        int  eosRegisterTimeoutSec = 60;      // BeginSession.RegisterTimeoutSeconds (10..120)
        int  eosTickMs = 30;                  // период EOS_Platform_Tick
        std::string eosServerName = "AsdaReborn";
        std::wstring eosCacheDir;             // CacheDirectory платформы (создаётся)
        int  eosLogLevel = 500;               // EOS_ELogLevel: 400 Info, 500 Verbose, 600 VeryVerbose

        // Загрузить ini. false — файл не найден/негодные значения (err — причина).
        bool Load(const std::wstring& path, std::string* err);
        // Оператор ли учётка.
        bool IsOperator(uint32_t userIndex) const;
    };

    // Учётные данные EOS из secrets\eos.json (секреты не логируются).
    struct EosSecrets
    {
        std::string productId, sandboxId, deploymentId;   // идентификаторы продукта
        std::string clientId, clientSecret;               // serverClient (AlphaServer, TrustedServer)
        // Прочитать eos.json. false — нет файла/полей (err без секретов).
        bool Load(const std::wstring& path, std::string* err);
    };

    // Прочитать первую строку текстового файла секрета (без CR/LF/пробелов по краям).
    bool ReadSecretLine(const std::wstring& path, std::string& out, std::string* err);
}
