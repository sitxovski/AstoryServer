// Copyright (c) 2026 @sitxovski (Discord)
// AdminStatus.cpp — ★ А6.8 (22.11.2026): точка статуса EAC для админ-центра, только чтение (см. AdminStatus.h).
// Нить точки: accept по одному (select 250 мс — проверка останова), запрос целиком за DeadlineMs, ответ, закрытие.
// Последовательная обработка достаточна: клиент один (служба панели), каждый запрос ограничен по времени и размеру.
#include "EacCommon.h"
#include "AdminStatus.h"
#include "Json.h"
#include "Log.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>

namespace Eac { namespace AdminStatus
{
    // ── Доска снимков ──────────────────────────────────────────────────────────────────────
    bool Board::Take(Request& r)
    {
        if (!want.exchange(false)) return false;
        std::lock_guard<std::mutex> lk(mu);
        if (!hasPend) return false;                // точка уже не ждёт (срок вышел)
        r = pend;
        return true;
    }

    void Board::Publish(uint64_t id, std::shared_ptr<const Snapshot> s)
    {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!hasPend || pend.id != id) return;   // ответ на отменённый запрос не нужен
            result = std::move(s);
            done = id;
            hasPend = false;
        }
        cv.notify_all();
    }

    std::shared_ptr<const Snapshot> Board::Ask(int kind, uint32_t uid, int limit, int waitMs)
    {
        std::unique_lock<std::mutex> lk(mu);
        pend.kind = kind; pend.uid = uid; pend.limit = limit; pend.id = ++nextId;
        hasPend = true;
        const uint64_t id = pend.id;
        want = true;                               // ядро возьмёт запрос на ближайшем проходе (≤ TickMs)
        cv.wait_for(lk, std::chrono::milliseconds(waitMs), [&] { return done == id; });
        if (done != id) { hasPend = false; return nullptr; }
        std::shared_ptr<const Snapshot> r = std::move(result);
        result.reset();
        return r;
    }

    namespace
    {
        constexpr size_t kMaxRequest = 8192;       // предел запроса (строка + заголовки); тело не читается
        constexpr int    kSummarySec = 60;         // сводка отказов в журнал не чаще раза в столько секунд
        constexpr int    kLimitDefault = 500;      // учёток в списке по умолчанию
        constexpr int    kLimitMax = 5000;         // предел списка
        const char*      kVersion = "a68.2";       // версия схемы ответа (панель сверяет «a68.*»); ★ р61: a68.2 — лёгкий список, core.*

        // Token bucket: rate в секунду (или в минуту при perMin), ёмкость burst.
        struct Bucket
        {
            double  tokens = -1;                   // запас (−1 — не начат)
            int64_t last = 0;                      // последнее пополнение
            bool Take(int64_t now, double perMs, int burst)
            {
                if (tokens < 0) { tokens = burst; last = now; }
                tokens = (std::min)((double)burst, tokens + (double)(now - last) * perMs);
                last = now;
                if (tokens < 1.0) return false;
                tokens -= 1.0;
                return true;
            }
            bool Empty(int64_t now, double perMs, int burst)
            {
                if (tokens < 0) return false;
                return (std::min)((double)burst, tokens + (double)(now - last) * perMs) < 1.0;
            }
        };

        std::string Q(const std::string& s) { return Json::Quote(s); }
        std::string B(bool b) { return b ? "true" : "false"; }
        std::string N(long long v) { return std::to_string(v); }
        // Время Unix или null.
        std::string T(int64_t u) { return u ? std::to_string(u) : std::string("null"); }

        const char* ReasonCode(int r)
        {
            switch (r)
            {
            case 1: return "no_session"; case 2: return "eac_action"; case 3: return "channel_lost";
            case 4: return "reg_rejected"; case 5: return "evicted"; case 6: return "not_bound";
            default: return "";
            }
        }

        std::string ServerJson(const Snapshot& s)
        {
            std::string o = "{";
            o += "\"version\":" + Q(kVersion);
            o += ",\"built_unix\":" + N(s.builtUnix) + ",\"age_ms\":" + N((std::max)((int64_t)0, NowMs() - s.builtMs));
            o += ",\"uptime_sec\":" + N(s.uptimeSec) + ",\"mode\":" + N(s.mode);
            o += ",\"fail_open\":" + (s.failOpen.empty() ? std::string("null") : Q(s.failOpen));
            o += ",\"eos_session\":" + B(s.eosSession);
            o += ",\"eac\":{\"registered\":" + N(s.eacRegistered) + ",\"authenticated\":" + N(s.eacAuthenticated) + ",\"pending\":" + N(s.eacPending) + "}";
            o += ",\"bridges\":" + N(s.bridges) + ",\"p61_inactive\":" + N(s.p61Inactive);
            o += ",\"games\":{\"sessions\":" + N(s.gameSessions) + ",\"protected\":" + N(s.gameProtected) + "}";
            o += ",\"stats\":{\"reg_ok\":" + N(s.regOk) + ",\"reg_fail\":" + N(s.regFail) + ",\"evictions\":" + N(s.evictions) +
                 ",\"decisions\":" + N(s.decisions) + ",\"kicks\":" + N(s.kicks) + "}";
            o += ",\"events_on\":" + B(s.eventsOn) + ",\"accounts\":" + N(s.accountsKnown) + ",\"history_accounts\":" + N(s.historyAccounts);
            o += ",\"core\":{\"pass_max_us\":" + N(s.passMaxUs) + ",\"snap_last_us\":" + N(s.snapLastUs) + ",\"snap_max_us\":" + N(s.snapMaxUs) +
                 ",\"snap_builds\":" + N(s.snapBuilds) + "}";
            o += "}";
            return o;
        }

        std::string AccountJson(const Account& a)
        {
            std::string o = "{\"uid\":" + N(a.ui);
            o += ",\"connected\":" + B(a.hasEac);
            if (a.hasEac)
            {
                const EacConn& e = a.eac;
                o += ",\"eac\":{\"conn\":" + N((long long)e.id) + ",\"state\":" + Q(e.state) + ",\"authenticated\":" + B(e.authenticated) +
                     ",\"auth_status\":" + N(e.authStatus) + ",\"platform\":" + N(e.platform) + ",\"registered_unix\":" + T(e.registeredUnix) +
                     ",\"last_ping_ago_ms\":" + N(e.lastPingAgoMs) + ",\"binds\":" + N(e.binds) + ",\"net\":{\"ip\":" + Q(e.ip) + "}}";
            }
            else o += ",\"eac\":null";
            o += ",\"reject_unix\":" + T(a.rejectUnix) + ",\"reg_in_window\":" + N(a.regInWindow);
            o += ",\"games\":[";
            for (size_t i = 0; i < a.games.size(); ++i)
            {
                const Game& g = a.games[i];
                if (i) o += ",";
                o += "{\"server\":" + Q(g.kind == 2 ? "GameServer" : g.kind == 3 ? "Indun" : "?") + ",\"pid\":" + N(g.pid) + ",\"user_num\":" + N(g.userNum) +
                     ",\"uid\":" + N(g.userIndex) + ",\"eac_uid\":" + N(g.bindUi) + ",\"login_unix\":" + T(g.loginUnix) +
                     ",\"protected\":" + B(g.prot) + ",\"ever_protected\":" + B(g.everProtected) + ",\"bind_zero\":" + B(g.bindZero) +
                     ",\"bound\":" + B(g.bound) + ",\"orphan\":" + B(g.orphan) + ",\"p61_inactive\":" + B(g.p61Inactive) +
                     ",\"unprot_since_unix\":" + T(g.unprotSinceUnix) + ",\"deadline_unix\":" + T(g.deadlineUnix) +
                     ",\"last_kick_unix\":" + T(g.lastKickUnix) + ",\"decided\":" + N(g.decided) + ",\"decided_code\":" + Q(ReasonCode(g.decided)) +
                     ",\"decided_why\":" + Q(g.decidedWhy) + ",\"net\":{\"ip\":" + Q(g.ip) + "}}";
            }
            o += "],\"events\":[";
            for (size_t i = 0; i < a.events.size(); ++i)
            {
                const Event& e = a.events[i];
                if (i) o += ",";
                o += "{\"unix\":" + N(e.unix) + ",\"kind\":" + Q(e.kind) + ",\"reason\":" + N(e.reason) + ",\"reason_code\":" + Q(ReasonCode(e.reason)) +
                     ",\"eos\":" + Q(e.eos) + ",\"text\":" + Q(e.text) + "}";
            }
            o += "]}";
            return o;
        }

        const char* StatusText(int code)
        {
            switch (code)
            {
            case 200: return "OK"; case 400: return "Bad Request"; case 401: return "Unauthorized"; case 404: return "Not Found";
            case 405: return "Method Not Allowed"; case 429: return "Too Many Requests"; case 503: return "Service Unavailable";
            default: return "Error";
            }
        }

        // ★ р61: лёгкая строка списка (без истории и без текстов).
        std::string RowJson(const ListRow& r)
        {
            return "{\"uid\":" + N(r.ui) + ",\"connected\":" + B(r.connected) + ",\"authenticated\":" + B(r.authenticated) + ",\"games\":" + N(r.games) +
                   ",\"protected\":" + N(r.protectedGames) + ",\"decided\":" + N(r.decided) + ",\"decided_code\":" + Q(ReasonCode(r.decided)) +
                   ",\"events\":" + N(r.events) + ",\"last_event_unix\":" + T(r.lastEventUnix) + ",\"last_event_kind\":" + Q(r.lastEventKind) + "}";
        }

        std::string ErrBody(const char* code) { return std::string("{\"ok\":false,\"error\":\"") + code + "\"}"; }
    }

    struct Server::Impl
    {
        Config cfg;                                // копия настроек
        Board* board = nullptr;                    // доска снимков ядра
        SOCKET ls = INVALID_SOCKET;                // слушатель 127.0.0.1:Port
        std::thread th;                            // нить точки
        std::atomic<bool> stop{ false };           // запрос останова
        std::string key;                           // общий секрет (в журнал не пишется)
        Bucket all, fails;                         // частота всех запросов / отказов по ключу
        std::shared_ptr<const Snapshot> cacheSum, cacheList;   // ★ р61: кэш сводки и списка (не чаще раза в SnapshotMaxAgeMs)
        int cacheListLimit = 0;                    // ★ р61: limit, на который построен cacheList
        // Сводка отказов (журнал раз в kSummarySec).
        long long nOk = 0, nAuth = 0, nRate = 0, nNonLocal = 0, nBad = 0, nNoSnap = 0, nSlowSend = 0;   // nSlowSend — ★ р61 М-3
        int64_t lastSummary = 0;

        void Summary(int64_t now, bool force)
        {
            if (!force && now - lastSummary < (int64_t)kSummarySec * 1000) return;
            lastSummary = now;
            if (nAuth || nRate || nNonLocal || nBad || nNoSnap || nSlowSend)
                LOGW("adm", "точка статуса за %d с: ответов %lld; отказов по ключу %lld, по частоте %lld, не с 127.0.0.1 %lld, негодных запросов %lld, без снимка %lld, "
                     "ответ не отдан за срок %lld", kSummarySec, nOk, nAuth, nRate, nNonLocal, nBad, nNoSnap, nSlowSend);
            else if (nOk) LOGD("adm", "точка статуса за %d с: ответов %lld", kSummarySec, nOk);
            nOk = nAuth = nRate = nNonLocal = nBad = nNoSnap = nSlowSend = 0;
        }

        // ★ ревизия 61 М-3: весь ответ — за DeadlineMs (общий срок, а не на каждый кусок): перед каждым куском срок send — остаток.
        void SendAll(SOCKET s, const std::string& d)
        {
            const int64_t end = NowMs() + cfg.statusDeadlineMs;
            const char* p = d.data(); size_t n = d.size();
            while (n)
            {
                const int64_t left = end - NowMs();
                if (left <= 0) { ++nSlowSend; return; }
                DWORD to = (DWORD)left;
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
                int k = send(s, p, (int)(std::min)(n, (size_t)65536), 0);
                if (k <= 0) { ++nSlowSend; return; }
                p += k; n -= (size_t)k;
            }
        }

        void Reply(SOCKET s, int code, const std::string& body)
        {
            std::string h = "HTTP/1.1 " + std::to_string(code) + " " + StatusText(code) + "\r\nContent-Type: application/json; charset=utf-8\r\n"
                            "Cache-Control: no-store\r\nConnection: close\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
            if (code == 405) h += "Allow: GET\r\n";
            h += "\r\n";
            SendAll(s, h + body);
        }

        // Прочитать заголовки запроса за срок. false — срок вышел / закрыто / слишком длинно (tooLong).
        bool ReadHead(SOCKET s, std::string& head, bool& tooLong)
        {
            tooLong = false;
            int64_t end = NowMs() + cfg.statusDeadlineMs;
            char buf[2048];
            while (head.find("\r\n\r\n") == std::string::npos)
            {
                if (head.size() > kMaxRequest) { tooLong = true; return false; }
                int64_t left = end - NowMs();
                if (left <= 0 || stop) return false;
                fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
                timeval tv{ (long)(left / 1000), (long)((left % 1000) * 1000) };
                int r = select(0, &rs, nullptr, nullptr, &tv);
                if (r <= 0) return false;
                int n = recv(s, buf, sizeof(buf), 0);
                if (n <= 0) return false;
                head.append(buf, (size_t)n);
            }
            return true;
        }

        void Handle(SOCKET s)
        {
            std::string head; bool tooLong = false;
            if (!ReadHead(s, head, tooLong))
            {
                ++nBad;
                if (tooLong) Reply(s, 400, ErrBody("too_long"));
                return;
            }
            head.resize(head.find("\r\n\r\n"));
            // Строка запроса: METHOD SP target SP HTTP/1.x
            size_t le = head.find("\r\n");
            std::string line = head.substr(0, le), hdrs = le == std::string::npos ? "" : head.substr(le + 2);
            size_t a = line.find(' '), b = a == std::string::npos ? a : line.find(' ', a + 1);
            if (a == std::string::npos || b == std::string::npos || line.compare(b + 1, 7, "HTTP/1.") != 0) { ++nBad; Reply(s, 400, ErrBody("bad_request")); return; }
            std::string method = line.substr(0, a), target = line.substr(a + 1, b - a - 1);
            // Заголовки: нужен только X-Asda-Key (ровно один).
            std::string got; int keys = 0;
            size_t p = 0;
            while (p < hdrs.size())
            {
                size_t e = hdrs.find("\r\n", p); if (e == std::string::npos) e = hdrs.size();
                std::string h = hdrs.substr(p, e - p); p = e + 2;
                size_t c = h.find(':');
                if (c == std::string::npos) continue;
                if (Lower(h.substr(0, c)) != "x-asda-key") continue;
                ++keys;
                size_t vb = h.find_first_not_of(" \t", c + 1), ve = h.find_last_not_of(" \t");
                got = vb == std::string::npos ? "" : h.substr(vb, ve - vb + 1);
            }
            int64_t now = NowMs();
            if (!all.Take(now, cfg.statusReqPerSec / 1000.0, cfg.statusReqBurst)) { ++nRate; Reply(s, 429, ErrBody("rate")); return; }
            const double failPerMs = cfg.statusFailPerMin / 60000.0;
            if (fails.Empty(now, failPerMs, cfg.statusFailPerMin)) { ++nRate; Reply(s, 429, ErrBody("auth_rate")); return; }
            if (keys != 1 || !ConstEq(got, key))
            {
                SecureZeroMemory(&got[0], got.size());
                fails.Take(now, failPerMs, cfg.statusFailPerMin);
                ++nAuth; Reply(s, 401, ErrBody("key")); return;
            }
            SecureZeroMemory(&got[0], got.size());
            if (method != "GET") { ++nBad; Reply(s, 405, ErrBody("method")); return; }
            std::string path = target, query;
            size_t qm = target.find('?');
            if (qm != std::string::npos) { path = target.substr(0, qm); query = target.substr(qm + 1); }
            const std::string kAcc = "/eac/v1/account/";
            enum { kNone, kSummary, kOne, kList } route = kNone;
            uint32_t uid = 0; int limit = kLimitDefault;
            if (path == "/eac/v1/summary") route = kSummary;
            else if (path == "/eac/v1/accounts")
            {
                route = kList;
                // limit=N (1…kLimitMax); прочие параметры не принимаются
                if (!query.empty())
                {
                    uint32_t v = 0;
                    if (query.compare(0, 6, "limit=") != 0 || !ParseUserIndex(query.substr(6), v) || v > (uint32_t)kLimitMax) { ++nBad; Reply(s, 400, ErrBody("limit")); return; }
                    limit = (int)v;
                }
            }
            else if (path.compare(0, kAcc.size(), kAcc) == 0)
            {
                route = kOne;
                if (!query.empty() || !ParseUserIndex(path.substr(kAcc.size()), uid) || uid > 0x7FFFFFFFu) { ++nBad; Reply(s, 400, ErrBody("uid")); return; }
            }
            if (route == kNone) { ++nBad; Reply(s, 404, ErrBody("path")); return; }
            // ★ р61 Н-1: ядро строит только спрошенное; сводка и список — из кэша не чаще раза в SnapshotMaxAgeMs
            std::shared_ptr<const Snapshot> sn;
            auto fresh = [&](const std::shared_ptr<const Snapshot>& c) { return c && NowMs() - c->builtMs <= cfg.statusSnapshotMaxAgeMs; };
            if (route == kSummary && fresh(cacheSum)) sn = cacheSum;
            else if (route == kList && fresh(cacheList) && cacheListLimit >= limit) sn = cacheList;
            else
            {
                sn = board->Ask(route == kOne ? kAskAccount : route == kList ? kAskList : kAskSummary, uid, limit, 1500);
                if (sn && route == kSummary) cacheSum = sn;
                if (sn && route == kList) { cacheList = sn; cacheListLimit = limit; }
            }
            if (!sn) { ++nNoSnap; Reply(s, 503, ErrBody("snapshot")); return; }
            std::string body = "{\"ok\":true,\"server\":" + ServerJson(*sn);
            if (route == kOne)
            {
                bool found = !sn->accounts.empty() && sn->accounts[0].ui == uid;
                body += ",\"found\":" + B(found) + ",\"account\":" + (found ? AccountJson(sn->accounts[0]) : std::string("null"));
            }
            else if (route == kList)
            {
                const size_t n = (std::min)(sn->rows.size(), (size_t)limit);
                body += ",\"total\":" + N(sn->total) + ",\"capped\":" + B(sn->total > (int)n) + ",\"accounts\":[";
                body.reserve(body.size() + n * 200);
                for (size_t i = 0; i < n; ++i) { if (i) body += ","; body += RowJson(sn->rows[i]); }
                body += "]";
            }
            body += "}";
            ++nOk;
            Reply(s, 200, body);
        }

        void Loop()
        {
            lastSummary = NowMs();
            while (!stop)
            {
                fd_set rs; FD_ZERO(&rs); FD_SET(ls, &rs);
                timeval tv{ 0, 250000 };
                int r = select(0, &rs, nullptr, nullptr, &tv);
                Summary(NowMs(), false);
                if (r <= 0) continue;
                sockaddr_in sa{}; int sl = sizeof(sa);
                SOCKET s = accept(ls, (sockaddr*)&sa, &sl);
                if (s == INVALID_SOCKET) continue;
                if (sa.sin_addr.s_addr != htonl(INADDR_LOOPBACK))   // слушаем 127.0.0.1, но проверяем и адрес
                {
                    ++nNonLocal; closesocket(s); continue;
                }
                u_long nb = 0; ioctlsocket(s, FIONBIO, &nb);
                DWORD to = (DWORD)cfg.statusDeadlineMs;
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
                Handle(s);
                shutdown(s, SD_SEND);
                closesocket(s);
            }
            Summary(NowMs(), true);
        }
    };

    Server::Server() : m(new Impl()) {}
    Server::~Server() { Stop(); delete m; }

    bool Server::Start(const Config& cfg, Board* board)
    {
        if (!cfg.statusConfigError.empty())
        {
            LOGE("adm", "точка статуса НЕ запущена: ошибка секции [AdminStatus] (%s) — EAC работает без неё", cfg.statusConfigError.c_str());
            return false;
        }
        if (!cfg.statusEnabled) { LOGI("adm", "точка статуса для панели выключена ([AdminStatus] Enabled=0)"); return false; }
        m->cfg = cfg; m->board = board;
        std::string err;
        if (!ReadSecretLine(cfg.statusSecretFile, m->key, &err))
        {
            LOGE("adm", "точка статуса НЕ запущена: секрет не прочитан (%s) — EAC работает без неё", err.c_str());
            return false;
        }
        if (m->key.size() < 32)
        {
            SecureZeroMemory(&m->key[0], m->key.size()); m->key.clear();
            LOGE("adm", "точка статуса НЕ запущена: секрет короче 32 знаков (%s) — EAC работает без неё", Utf8(cfg.statusSecretFile).c_str());
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL excl = TRUE; setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof(excl));
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)cfg.statusPort); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (s == INVALID_SOCKET || bind(s, (sockaddr*)&sa, sizeof(sa)) != 0 || listen(s, 16) != 0)
        {
            LOGE("adm", "точка статуса НЕ запущена: bind/listen 127.0.0.1:%d (%d) — EAC работает без неё", cfg.statusPort, WSAGetLastError());
            if (s != INVALID_SOCKET) closesocket(s);
            SecureZeroMemory(&m->key[0], m->key.size()); m->key.clear();
            return false;
        }
        m->ls = s;
        m->th = std::thread([this] { m->Loop(); });
        LOGI("adm", "точка статуса для панели: 127.0.0.1:%d (только чтение, ключ из %s; %d запросов/с, запас %d; отказов по ключу %d/мин)", cfg.statusPort,
             Utf8(cfg.statusSecretFile).c_str(), cfg.statusReqPerSec, cfg.statusReqBurst, cfg.statusFailPerMin);
        return true;
    }

    void Server::Stop()
    {
        if (!m) return;
        m->stop = true;
        if (m->th.joinable()) m->th.join();
        if (m->ls != INVALID_SOCKET) { closesocket(m->ls); m->ls = INVALID_SOCKET; }
        if (!m->key.empty()) { SecureZeroMemory(&m->key[0], m->key.size()); m->key.clear(); }
    }
}}
