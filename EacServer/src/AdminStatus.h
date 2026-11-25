// Copyright (c) 2026 @sitxovski (Discord)
// AdminStatus.h — ★ А6.8 (22.11.2026, разбор Reports/admin_center/impl_a6_econ_20261121.md §«А6.8 — точка статуса EAC»):
// локальная точка ТОЛЬКО ДЛЯ ЧТЕНИЯ состояния EAC по учётке для админ-центра (служба панели на той же машине).
//
//   * Слушает только 127.0.0.1:[AdminStatus] Port (по умолчанию 8447), соединение не с 127.0.0.1 закрывается сразу;
//     наружу не пробрасывается (в Caddy её нет), брандмауэр не нужен.
//   * Доступ — общий секрет: заголовок «X-Asda-Key: <строка из [AdminStatus] SecretFile>» (файл в secrets\, создаёт выкладчик,
//     копия — в secrets\ службы панели); сравнение за постоянное время; секрет в журнал не пишется.
//   * Частота: общий token bucket (ReqPerSec / ReqBurst) и отдельный на отказы по ключу (FailPerMin) — сверх — 429.
//   * Игровой поток EAC (нить ядра Core) не ждёт нить точки: точка кладёт запрос (атомарный флаг), ядро на ближайшем проходе
//     (≤ TickMs) строит неизменяемый Snapshot ТОЛЬКО спрошенного (★ ревизия 61 Н-1: сводка — счётчики; учётка — только её записи;
//     список — лёгкие строки без истории и текстов, ≤ limit) и отдаёт его под коротким замком (обмен shared_ptr); JSON строит нить
//     точки. Частота: учётка — не чаще запросов (ReqPerSec), сводка и список — из кэша точки не чаще раза в SnapshotMaxAgeMs.
//     Время построения снимка и наибольший проход ядра — в ответе (server.core.*_us). Нет запросов — ядро снимков не строит.
//   * IP (канала 15901 и игры) отдаются ТОЛЬКО в полях "net" — панель показывает их лишь по праву players.view_net.
//   * Ключ [AdminStatus] Enabled=0 (умолчание) — точки нет, ядро не ведёт историю событий (поведение до А6.8).
//
// Ответы (GET, Connection: close, application/json, Cache-Control: no-store):
//   /eac/v1/summary              {"ok":true,"server":{…}}
//   /eac/v1/account/<UserIndex>  {"ok":true,"server":{…},"found":bool,"account":{…}|null}
//   /eac/v1/accounts[?limit=N]   {"ok":true,"server":{…},"accounts":[лёгкие строки],"total":N,"capped":bool}  (★ р61: схема a68.2)
//   отказ: 400 / 401 / 404 / 405 / 429 / 503 {"ok":false,"error":"<код>"}
#pragma once
#include "Config.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace Eac { namespace AdminStatus
{
    // Событие учётки (история в памяти ядра, только при Enabled=1). Без IP и без секретов.
    struct Event
    {
        int64_t     unix = 0;                 // время события (Unix, с)
        std::string kind;                     // код вида: reg_ok, reg_reject, reg_limit, reg_error, auth, auth_timeout, eac_lost, evicted,
                                              //   violation, decision, kick, kick_wait, protected, unprotected, login, logout, rebind, orphan_drop
        int         reason = 0;               // причина §5 (1…6) или 0
        std::string eos;                      // текст причины EOS (ClientActionRequired) или пусто
        std::string text;                     // пояснение (русский, как в журнале, но без IP)
    };

    // Живая EAC-сессия учётки (соединение 15901 в состоянии Registered).
    struct EacConn
    {
        uint64_t    id = 0;                   // номер соединения (он же EOS ClientHandle)
        std::string state;                    // состояние соединения текстом
        bool        authenticated = false;    // пришёл RemoteAuthComplete
        int         authStatus = 0;           // последний ClientAuthStatus (1 Local, 2 Remote)
        int         platform = 0;             // платформа из REG (1 — Windows)
        int64_t     registeredUnix = 0;       // когда RegisterClient
        int64_t     lastPingAgoMs = 0;        // сколько мс назад был PING клиента
        int         binds = 0;                // BIND в памяти сессии
        std::string ip;                       // IP канала 15901 (только поле net)
    };

    // Игровая сессия от P73.
    struct Game
    {
        int         kind = 0;                 // 2 GameServer, 3 Indun
        uint32_t    pid = 0;                  // процесс сервера
        int         userNum = 0;              // слот CUser
        uint32_t    userIndex = 0;            // учётка персонажа (LOGIN)
        uint32_t    bindUi = 0;               // EAC-учётка привязки (после REBIND — учётка сессии)
        int64_t     loginUnix = 0;            // когда LOGIN
        bool        prot = false;             // защищена сейчас
        bool        everProtected = false;    // была защищена с последнего отсчёта
        bool        bindZero = true;          // bind игрового канала нулевой (Legacy / P61 выключен)
        bool        bound = false;            // bind сопоставлен с BIND EAC-сессии
        bool        orphan = false;           // P73 этого процесса отключён
        bool        p61Inactive = false;      // §8.6 R3-04: у процесса P61 не активен
        int64_t     unprotSinceUnix = 0;      // когда защита потеряна (0 — нет)
        int64_t     deadlineUnix = 0;         // когда истекает срок BindTimeout/Grace (только для незащищённой; 0 — нет)
        int64_t     lastKickUnix = 0;         // последний KICK / попытка (0 — нет)
        int         decided = 0;              // последняя принятая причина (0 — нет)
        std::string decidedWhy;               // почему KICK не отправлен (пусто — отправлен или решения нет)
        std::string ip;                       // IP игры по данным сервера (только поле net)
    };

    // Учётка в снимке.
    struct Account
    {
        uint32_t           ui = 0;            // UserIndex
        bool               hasEac = false;    // есть живая EAC-сессия
        EacConn            eac;               // она (при hasEac)
        int64_t            rejectUnix = 0;    // последний отказ регистрации/аутентификации (в пределах RejectMemorySec; 0 — нет)
        int                regInWindow = 0;   // REG за окно RegPerAccountWindowSec
        std::vector<Game>  games;             // игровые сессии (по учётке персонажа или по EAC-учётке привязки)
        std::vector<Event> events;            // последние события (старые — первыми)
    };

    // ★ р61: лёгкая строка списка учёток (без истории и без текстов событий).
    struct ListRow
    {
        uint32_t    ui = 0;                   // UserIndex
        bool        connected = false;        // есть живая EAC-сессия
        bool        authenticated = false;    // она аутентифицирована
        int         games = 0;                // игровых сессий (по учётке персонажа или EAC-учётке)
        int         protectedGames = 0;       // из них защищено
        int         decided = 0;              // последняя причина решения по одной из сессий (0 — нет)
        int         events = 0;               // событий в истории
        int64_t     lastEventUnix = 0;        // время последнего события (0 — нет)
        const char* lastEventKind = "";       // вид последнего события (литерал Core.cpp Ev)
    };

    // ★ р61: что спрашивает точка (ядро строит снимок только этого).
    enum AskKind : int { kAskSummary = 0, kAskAccount = 1, kAskList = 2 };

    // Запрос снимка от нити точки к ядру.
    struct Request
    {
        int      kind = kAskSummary;          // AskKind
        uint32_t uid = 0;                     // учётка (kAskAccount)
        int      limit = 0;                   // строк (kAskList)
        uint64_t id = 0;                      // номер запроса (ответ сверяется по нему)
    };

    // Неизменяемый снимок состояния ядра (только то, что спросили).
    struct Snapshot
    {
        int         kind = kAskSummary;       // ★ р61: на какой запрос построен
        int64_t     builtUnix = 0;            // когда построен (Unix, с)
        int64_t     builtMs = 0;              // когда построен (NowMs)
        int64_t     uptimeSec = 0;            // сколько работает ядро
        int         mode = 0;                 // [General] Mode
        std::string failOpen;                 // почему FailOpen (пусто — нет)
        bool        eosSession = false;       // сессия AntiCheatServer есть
        int         eacRegistered = 0, eacAuthenticated = 0, eacPending = 0;   // соединения 15901
        int         bridges = 0;              // подключённые P73 (после HELLO)
        int         p61Inactive = 0;          // процессов с выводом «P61 не активен»
        int         gameSessions = 0, gameProtected = 0;                        // игровые сессии
        long long   regOk = 0, regFail = 0, evictions = 0, decisions = 0, kicks = 0;   // счётчики с запуска
        bool        eventsOn = false;         // история событий ведётся
        int64_t     passMaxUs = 0;            // ★ р61: наибольшая работа прохода ядра за последние 10–20 с, мкс
        int64_t     snapLastUs = 0, snapMaxUs = 0;   // ★ р61: построение снимка (на нити ядра): последнее и наибольшее, мкс
        long long   snapBuilds = 0;           // ★ р61: снимков построено с запуска
        int         accountsKnown = 0;        // ★ р61: учёток в таблице привязок ядра
        int         historyAccounts = 0;      // ★ р61: учёток с историей событий
        std::vector<Account> accounts;        // kAskAccount: 0 или 1 запись (только спрошенная учётка)
        std::vector<ListRow> rows;            // kAskList: ≤ limit строк по возрастанию UserIndex
        int         total = 0;                // kAskList: всего учёток в списке
    };

    // Доска снимков между нитью ядра (строит) и нитью точки (спрашивает). Нить точки последовательная — запрос в полёте один.
    class Board
    {
    public:
        // Ядро: есть ли запрос (флаг сбрасывается); r — его копия.
        bool Take(Request& r);
        // Ядро: ответ на запрос id (короткий замок — только обмен указателя). Ответ на отменённый запрос отбрасывается.
        void Publish(uint64_t id, std::shared_ptr<const Snapshot> s);
        // Точка: спросить ядро и ждать ответ до waitMs. nullptr — ядро не ответило в срок.
        std::shared_ptr<const Snapshot> Ask(int kind, uint32_t uid, int limit, int waitMs);

    private:
        std::mutex mu;                                  // охраняет pend, hasPend, done, result
        std::condition_variable cv;                     // будит ждущую точку после Publish
        Request pend;                                   // запрос в полёте
        bool hasPend = false;                           // он есть (сбрасывается по ответу или по сроку)
        uint64_t nextId = 0, done = 0;                  // номера: последнего запроса и последнего ответа
        std::shared_ptr<const Snapshot> result;         // ответ на запрос done
        std::atomic<bool> want{ false };                // есть запрос — ядро проверяет одним атомарным обменом за проход
    };

    // HTTP-точка 127.0.0.1:Port (своя нить).
    class Server
    {
    public:
        Server();
        ~Server();
        // Запустить (при Enabled=1). Сбой (нет секрета, порт занят) — запись в журнал, точка не работает, процесс продолжает:
        // EAC важнее панели. Возврат — работает ли точка.
        bool Start(const Config& cfg, Board* board);
        // Остановить и дождаться нити.
        void Stop();

    private:
        struct Impl;
        Impl* m;
    };
}}
