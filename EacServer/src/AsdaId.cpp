// Copyright (c) 2026 @sitxovski (Discord)
// AsdaId.cpp — реализация HTTP-сервера AsdaId (см. AsdaId.h).
// Ред. 3 (16.10.2026, ревизия REVIEW_E1):
//   * E1-05 — нить ввода-вывода читает запросы всех соединений сразу (WSAPoll) с общим сроком RequestDeadlineSec от accept;
//     в рабочие нити (БД) попадает только полностью прочитанный запрос; JWKS/openid-configuration отвечает сама нить ввода-вывода;
//     при старте те же ответы пишутся статикой в WwwDir\.well-known\ (их отдаёт Caddy).
//   * E1-06 — неудачи считаются на пару (логин, IP) и на логин с растущей паузой (ступени LoginPauseStagesSec), успех сбрасывает;
//     IP прежних успешных входов не попадает под общую паузу логина; неудача пароля пишется в us_pwfail (UPEacAuthFail) отложенно.
//   * E1-09 — доля 503 за окно → признак «AsdaId деградировал» для ядра (Health.h).
//   * E1-10 — refresh-токены (только SHA-256) на диске под DPAPI LocalMachine, продление при использовании, абсолютный предел.
//   * E1-19 — на /refresh не реже StatusRecheckSec перепроверка учётки (UPEacAuthStatus: блок, состояние, смена пароля).
//   * §8.6 (R3-07, 16.10) — журнал считает КАЖДУЮ неудачу пароля: сквозной номер неудачи логина и пары (логин, IP) с последнего
//     успеха (остывает через час без неудач), независимо от окна 5 с процедуры UPEacAuthFail (её «тот же ввод уже засчитан»).
#include "EacCommon.h"
#include "AsdaId.h"
#include "Health.h"
#include "Json.h"
#include "Jwt.h"
#include "Log.h"
#include <wincrypt.h>
#include <iphlpapi.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <map>
#include <unordered_map>
#include <atomic>
#include <algorithm>

namespace Eac
{
    namespace
    {
        constexpr size_t kMaxHeader = 8192;    // предел заголовков запроса
        constexpr size_t kMaxBody   = 4096;    // предел тела запроса
        constexpr size_t kQueueMax  = 256;     // прочитанных запросов, ждущих рабочую нить (сверх — 503)
        constexpr size_t kFailQueueMax = 10000;   // отложенных записей UPEacAuthFail
        constexpr int    kAcceptPerPass = 64;  // accept за проход нити ввода-вывода
        constexpr int64_t kKnownIpMax = 8;     // IP успешного входа на логин (старейший вытесняется)
        const char kRefreshMagic[8] = { 'A', 'S', 'D', 'A', 'R', 'F', '0', '1' };   // формат secrets\refresh.dat (до DPAPI)
        const wchar_t* kRefreshEntropy = L"AsdaEacServer/refresh/v1";               // дополнительная энтропия DPAPI

        // Входящий HTTP-запрос (только нужное).
        struct Request
        {
            std::string method, path;          // метод и путь
            std::string contentType;           // Content-Type (нижний регистр)
            std::string xff;                   // X-Forwarded-For
            std::string body;                  // тело
        };

        // Прочитанный запрос для рабочей нити.
        struct Job
        {
            SOCKET      s = INVALID_SOCKET;
            std::string ip;                    // IP клиента (с учётом X-Forwarded-For от Caddy)
            Request     rq;
        };

        // Соединение, ждущее запрос целиком (нить ввода-вывода).
        struct PendingConn
        {
            SOCKET      s = INVALID_SOCKET;
            std::string sockIp;                // адрес сокета
            std::string buf;                   // принятые байты
            int64_t     deadline = 0;          // NowMs() — к этому сроку запрос должен прийти целиком
        };

        // Запись refresh-токена (ключ — SHA-256 токена: сам токен не хранится ни в памяти, ни на диске).
        struct RefreshEntry
        {
            uint32_t    userIndex = 0;         // учётка (sub)
            std::string login;                 // логин (журнал)
            int64_t     idleExp = 0;           // Unix-время: истекает без использования (продлевается на /refresh)
            int64_t     absExp = 0;            // Unix-время: абсолютный предел (от /token, не продлевается)
            int64_t     issued = 0;            // Unix-время выдачи (вытеснение старейшего)
            int64_t     checkedAt = 0;         // Unix-время последней проверки UPEacAuthStatus (0 — не было)
            std::string pwTag;                 // отпечаток пароля на момент проверки (смена пароля → refresh недействителен)
        };

        // Счётчик неудач с растущей паузой.
        struct FailCounter
        {
            int     fails = 0;                 // неудач подряд с последней паузы/успеха
            int     stage = 0;                 // ступень следующей паузы
            int64_t pauseUntil = 0;            // NowMs() конца паузы
            int64_t lastAt = 0;                // последняя неудача (ступени остывают через час без неудач)
            long long total = 0;               // §8.6 (R3-07): все неудачи с последнего успеха / остывания — для журнала (паузой не сбрасывается)
        };

        // Отложенная запись неудачи пароля.
        struct FailWrite { int64_t due = 0; std::string login; };

        std::string Trim(const std::string& s)
        {
            size_t b = 0, e = s.size();
            while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
            while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
            return s.substr(b, e - b);
        }

        // Логин по правилам P51/UPUserLogin: хвостовые пробелы снимаются, 1..61 символов [A-Za-z0-9_.@-].
        bool NormalizeLogin(std::string& login)
        {
            while (!login.empty() && login.back() == ' ') login.pop_back();
            if (login.empty() || login.size() > 61) return false;
            for (char c : login)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '@' || c == '-';
                if (!ok) return false;
            }
            return true;
        }

        // MD5-hex: ровно 32 hex → строчными.
        bool NormalizeMd5(std::string& s)
        {
            if (s.size() != 32) return false;
            for (char& c : s)
            {
                if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
                else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        // base64url-строка разумной длины (refresh-токен).
        bool IsB64Url(const std::string& s, size_t lo, size_t hi)
        {
            if (s.size() < lo || s.size() > hi) return false;
            for (char c : s) if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
            return true;
        }

        // Похоже ли на IP-адрес (v4/v6).
        bool IsIpText(const std::string& s)
        {
            in_addr a4; in6_addr a6;
            return inet_pton(AF_INET, s.c_str(), &a4) == 1 || inet_pton(AF_INET6, s.c_str(), &a6) == 1;
        }

        const char* Reason(int code)
        {
            switch (code)
            {
            case 200: return "OK"; case 400: return "Bad Request"; case 401: return "Unauthorized";
            case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 429: return "Too Many Requests";
            case 503: return "Service Unavailable"; default: return "Internal Server Error";
            }
        }

        // Разбор накопленного буфера. Возврат: 0 — нужно ещё байт; 1 — запрос целиком (rq заполнен); 400 — кривой запрос.
        int ParseRequest(const std::string& buf, Request& rq)
        {
            size_t hdrEnd = buf.find("\r\n\r\n");
            if (hdrEnd == std::string::npos) return buf.size() > kMaxHeader ? 400 : 0;
            if (hdrEnd > kMaxHeader) return 400;
            size_t le = buf.find("\r\n");
            std::string line = buf.substr(0, le);
            size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
            if (sp1 == std::string::npos || sp2 == sp1) return 400;
            rq.method = line.substr(0, sp1);
            rq.path = line.substr(sp1 + 1, sp2 - sp1 - 1);
            std::string ver = line.substr(sp2 + 1);
            if (ver != "HTTP/1.1" && ver != "HTTP/1.0") return 400;
            long long contentLength = -1;
            bool bad = false;
            rq.contentType.clear(); rq.xff.clear();
            size_t pos = le + 2;
            while (pos < hdrEnd)
            {
                size_t e = buf.find("\r\n", pos);
                if (e == std::string::npos || e > hdrEnd) e = hdrEnd;
                std::string h = buf.substr(pos, e - pos);
                pos = e + 2;
                size_t c = h.find(':');
                if (c == std::string::npos || c == 0) return 400;
                std::string name = Lower(h.substr(0, c));
                std::string val = Trim(h.substr(c + 1));
                if (name == "content-length")
                {
                    if (contentLength >= 0 || val.empty() || val.size() > 9) { bad = true; continue; }
                    long long v = 0; for (char ch : val) { if (ch < '0' || ch > '9') { bad = true; break; } v = v * 10 + (ch - '0'); }
                    contentLength = v;
                }
                else if (name == "transfer-encoding") bad = true;   // chunked не поддерживаем
                else if (name == "content-type") rq.contentType = Lower(val);
                else if (name == "x-forwarded-for") rq.xff = rq.xff.empty() ? val : rq.xff + "," + val;
            }
            if (bad) return 400;
            if (contentLength < 0) contentLength = 0;
            if ((size_t)contentLength > kMaxBody) return 400;
            size_t have = buf.size() - (hdrEnd + 4);
            if (have < (size_t)contentLength) return 0;
            if (have > (size_t)contentLength) return 400;   // лишние байты (конвейер запрещён)
            rq.body = buf.substr(hdrEnd + 4);
            return 1;
        }

        // Ответ целиком и закрытие отправки. waitMs — сколько ждать готовности сокета на запись (0 — не ждать).
        void SendResponse(SOCKET s, int code, const std::string& body, bool cacheable, int waitMs)
        {
            std::string r = "HTTP/1.1 " + std::to_string(code) + " " + Reason(code) + "\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: " + std::to_string(body.size()) + "\r\n" +
                            (cacheable ? "Cache-Control: public, max-age=300\r\n" : "Cache-Control: no-store\r\nPragma: no-cache\r\n") +
                            "Connection: close\r\n\r\n" + body;
            size_t off = 0;
            int64_t end = NowMs() + waitMs;
            while (off < r.size())
            {
                int n = send(s, r.data() + off, (int)(r.size() - off), 0);
                if (n > 0) { off += (size_t)n; continue; }
                if (WSAGetLastError() != WSAEWOULDBLOCK) break;
                int left = (int)(end - NowMs());
                if (left <= 0) break;
                WSAPOLLFD f{}; f.fd = s; f.events = POLLWRNORM;
                if (WSAPoll(&f, 1, left) <= 0) break;
            }
            shutdown(s, SD_SEND);
        }

        // Записать файл атомарно (временный + замена). false — ошибка (err).
        bool WriteFileAtomic(const std::wstring& path, const void* data, size_t len, std::string* err)
        {
            std::wstring tmp = path + L".tmp";
            HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) { if (err) *err = "создание " + Utf8(tmp) + " (" + std::to_string(GetLastError()) + ")"; return false; }
            DWORD wr = 0; BOOL ok = len ? WriteFile(h, data, (DWORD)len, &wr, nullptr) : TRUE;
            if (ok) ok = FlushFileBuffers(h);
            CloseHandle(h);
            if (!ok || wr != len) { DeleteFileW(tmp.c_str()); if (err) *err = "запись " + Utf8(tmp); return false; }
            if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                if (err) *err = "замена " + Utf8(path) + " (" + std::to_string(GetLastError()) + ")";
                DeleteFileW(tmp.c_str()); return false;
            }
            return true;
        }

        // Прочитать файл целиком (≤ 16 МиБ). false — нет файла/ошибка.
        bool ReadWholeFile(const std::wstring& path, std::vector<uint8_t>& out)
        {
            HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
            if (sz.QuadPart > 16 * 1024 * 1024) { CloseHandle(h); return false; }
            out.resize((size_t)sz.QuadPart);
            DWORD rd = 0; BOOL ok = out.empty() ? TRUE : ReadFile(h, out.data(), (DWORD)out.size(), &rd, nullptr);
            CloseHandle(h);
            return ok && rd == out.size();
        }

        // Создать каталоги по пути (как mkdir -p).
        void MakeDirs(const std::wstring& dir)
        {
            for (size_t i = 3; i <= dir.size(); ++i)
                if (i == dir.size() || dir[i] == L'\\' || dir[i] == L'/') CreateDirectoryW(dir.substr(0, i).c_str(), nullptr);
        }

        void PutU32(std::string& v, uint32_t x) { for (int i = 0; i < 4; ++i) v += (char)(uint8_t)(x >> (8 * i)); }
        void PutI64(std::string& v, int64_t x) { for (int i = 0; i < 8; ++i) v += (char)(uint8_t)((uint64_t)x >> (8 * i)); }
        bool GetU32(const std::vector<uint8_t>& b, size_t& o, uint32_t& x) { if (o + 4 > b.size()) return false; x = 0; for (int i = 0; i < 4; ++i) x |= (uint32_t)b[o + i] << (8 * i); o += 4; return true; }
        bool GetI64(const std::vector<uint8_t>& b, size_t& o, int64_t& x) { if (o + 8 > b.size()) return false; uint64_t u = 0; for (int i = 0; i < 8; ++i) u |= (uint64_t)b[o + i] << (8 * i); x = (int64_t)u; o += 8; return true; }
        bool GetStr(const std::vector<uint8_t>& b, size_t& o, std::string& s) { if (o + 1 > b.size()) return false; size_t n = b[o++]; if (o + n > b.size()) return false; s.assign((const char*)b.data() + o, n); o += n; return true; }
    }

    struct AsdaIdServer::Impl
    {
        Config cfg;                                 // копия настроек
        Crypto::RsaKey* key = nullptr;              // ключ подписи JWT
        std::string kid, jwks, oidc;                // заранее собранные ответы
        std::string statusCached;                   // ★ 17.10.2026: последний ответ /status (JSON)
        int64_t statusUntilMs = 0;                  // до какого момента statusCached действителен

        // ★ 17.10.2026: слушает ли кто-нибудь TCP-порт port (любой адрес) — по таблице сокетов Windows, без подключения.
        static bool PortListening(int port)
        {
            ULONG size = 0;
            if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != ERROR_INSUFFICIENT_BUFFER)
                return false;
            std::vector<uint8_t> buf(size + 4096);
            size = (ULONG)buf.size();
            if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) return false;
            const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i)
                if (ntohs((u_short)t->table[i].dwLocalPort) == port) return true;
            return false;
        }

        // ★ 17.10.2026: ответ GET /status — {"online":вход&&игра,"login":…,"game":…}; кэш statusCacheMs (нагрузка не растёт
        //   с числом лаунчеров). Только признаки доступности: ни числа игроков, ни адресов, ни версий наружу не уходит.
        const std::string& StatusJson()
        {
            const int64_t now = NowMs();
            if (statusCached.empty() || now >= statusUntilMs)
            {
                const bool login = PortListening(cfg.statusLoginPort), game = PortListening(cfg.statusGamePort);
                statusCached = std::string("{\"online\":") + (login && game ? "true" : "false") +
                               ",\"login\":" + (login ? "true" : "false") + ",\"game\":" + (game ? "true" : "false") + "}";
                statusUntilMs = now + cfg.statusCacheMs;
            }
            return statusCached;
        }
        AuthFactory factory;
        SOCKET listenSock = INVALID_SOCKET;
        std::atomic<bool> stop{ false };
        std::thread ioThread, bgThread;
        std::vector<std::thread> workers;
        std::mutex qmu; std::condition_variable qcv;
        std::deque<Job> queue;                                // прочитанные запросы /token, /refresh

        std::mutex lmu;                                       // лимиты, refresh, окно деградации
        std::unordered_map<std::string, std::deque<int64_t>> ipHits;   // IP → времена /token за минуту
        std::unordered_map<std::string, FailCounter> pairFails;       // "логин|IP" → неудачи пары (E1-06)
        std::unordered_map<std::string, FailCounter> loginFails;      // логин (нижний регистр) → неудачи со всех IP (E1-06)
        std::unordered_map<std::string, std::map<std::string, int64_t>> knownIps;   // логин → IP успешного входа → Unix-время
        std::unordered_map<std::string, RefreshEntry> refresh;        // sha256(refresh) hex → запись
        bool refreshDirty = false;                                     // нужно сбросить refresh на диск
        int64_t refreshDirtyAt = 0;                                    // когда стало «грязным»
        std::deque<std::pair<int64_t, bool>> outcomes;                // (время, 503?) ответов /token и /refresh (E1-09)
        int64_t lastSweep = 0;

        std::mutex fmu; std::condition_variable fcv;          // отложенные записи UPEacAuthFail
        std::deque<FailWrite> failQueue;

        // Сводка отказов нити ввода-вывода (не строка на каждый — E1-05).
        std::atomic<long long> rejDeadline{ 0 }, rejOverflow{ 0 }, rejQueue{ 0 };

        // ── нить ввода-вывода ─────────────────────────────────────────────────────────
        std::string ClientIp(const std::string& sockIp, const Request& rq) const
        {
            if (cfg.trustForwardedFor && sockIp == "127.0.0.1" && !rq.xff.empty())
            {
                size_t c = rq.xff.rfind(',');
                std::string last = Trim(c == std::string::npos ? rq.xff : rq.xff.substr(c + 1));
                if (IsIpText(last)) return last;
            }
            return sockIp;
        }

        void IoLoop()
        {
            std::vector<PendingConn> pend;
            std::vector<WSAPOLLFD> fds;
            int64_t lastSummary = NowMs();
            while (!stop)
            {
                fds.clear();
                WSAPOLLFD f{}; f.fd = listenSock; f.events = POLLRDNORM; fds.push_back(f);
                for (auto& p : pend) { f.fd = p.s; f.events = POLLRDNORM; fds.push_back(f); }
                int r = WSAPoll(fds.data(), (ULONG)fds.size(), 100);
                if (stop) break;
                int64_t now = NowMs();
                if (r > 0)
                {
                    // Сначала уже принятые (их запросы), затем новые соединения.
                    for (size_t i = 1; i < fds.size(); ++i)
                    {
                        if (!fds[i].revents) continue;
                        PendingConn& p = pend[i - 1];
                        if (p.s == INVALID_SOCKET) continue;
                        char tmp[4096];
                        int n = recv(p.s, tmp, sizeof(tmp), 0);
                        if (n <= 0)
                        {
                            if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
                            closesocket(p.s); p.s = INVALID_SOCKET; continue;
                        }
                        p.buf.append(tmp, (size_t)n);
                        Request rq;
                        int pr = ParseRequest(p.buf, rq);
                        if (pr == 0) continue;
                        SOCKET s = p.s; p.s = INVALID_SOCKET;
                        std::string ip = pr == 1 ? ClientIp(p.sockIp, rq) : p.sockIp;
                        if (pr == 400) { LOGI("id", "%s запрос отклонён (400: заголовки/длина)", ip.c_str()); SendResponse(s, 400, "{\"error\":\"invalid_request\"}", false, 0); closesocket(s); continue; }
                        Dispatch(s, ip, std::move(rq));
                    }
                    if (fds[0].revents)
                    {
                        for (int k = 0; k < kAcceptPerPass; ++k)
                        {
                            sockaddr_in sa{}; int sl = sizeof(sa);
                            SOCKET s = accept(listenSock, (sockaddr*)&sa, &sl);
                            if (s == INVALID_SOCKET) break;
                            size_t live = 0; for (auto& p : pend) live += p.s != INVALID_SOCKET;
                            if ((int)live >= cfg.maxPendingConns) { ++rejOverflow; closesocket(s); continue; }
                            u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
                            PendingConn p; p.s = s; p.sockIp = Ipv4Text(sa.sin_addr.s_addr); p.deadline = now + (int64_t)cfg.requestDeadlineSec * 1000;
                            pend.push_back(std::move(p));
                        }
                    }
                }
                // Общий срок запроса от accept (E1-05): медленный клиент не держит нити.
                for (auto& p : pend)
                    if (p.s != INVALID_SOCKET && now >= p.deadline) { ++rejDeadline; closesocket(p.s); p.s = INVALID_SOCKET; }
                pend.erase(std::remove_if(pend.begin(), pend.end(), [](const PendingConn& p) { return p.s == INVALID_SOCKET; }), pend.end());
                if (now - lastSummary >= 10000)
                {
                    lastSummary = now;
                    long long d = rejDeadline.exchange(0), o = rejOverflow.exchange(0), q = rejQueue.exchange(0);
                    if (d || o || q) LOGW("id", "за 10 с: закрыто по сроку запроса (%d с) %lld, сверх MaxPendingConns %lld, очередь рабочих полна (503) %lld; ждут запрос %zu",
                                          cfg.requestDeadlineSec, d, o, q, pend.size());
                }
            }
            for (auto& p : pend) if (p.s != INVALID_SOCKET) closesocket(p.s);
        }

        // Запрос прочитан целиком: статику — сразу, /token и /refresh — рабочим нитям.
        void Dispatch(SOCKET s, const std::string& ip, Request&& rq)
        {
            if (rq.path == "/.well-known/jwks.json" || rq.path == "/.well-known/openid-configuration")
            {
                if (rq.method != "GET") SendResponse(s, 405, "{\"error\":\"method_not_allowed\"}", false, 0);
                else { LOGD("id", "%s GET %s", ip.c_str(), rq.path.c_str()); SendResponse(s, 200, rq.path == "/.well-known/jwks.json" ? jwks : oidc, true, 0); }
                closesocket(s);
                return;
            }
            if (rq.path == "/status")   // ★ 17.10.2026: пинг и статус для лаунчера (ответ из кэша, нить ввода-вывода не ждёт)
            {
                if (rq.method != "GET") SendResponse(s, 405, "{\"error\":\"method_not_allowed\"}", false, 0);
                else SendResponse(s, 200, StatusJson(), false, 0);
                closesocket(s);
                return;
            }
            if (rq.path != "/token" && rq.path != "/refresh") { SendResponse(s, 404, "{\"error\":\"not_found\"}", false, 0); closesocket(s); return; }
            if (rq.method != "POST") { SendResponse(s, 405, "{\"error\":\"method_not_allowed\"}", false, 0); closesocket(s); return; }
            std::unique_lock<std::mutex> lk(qmu);
            if (queue.size() >= kQueueMax)
            {
                lk.unlock(); ++rejQueue;
                SendResponse(s, 503, "{\"error\":\"temporarily_unavailable\"}", false, 0); closesocket(s);
                return;
            }
            Job j; j.s = s; j.ip = ip; j.rq = std::move(rq);
            queue.push_back(std::move(j));
            lk.unlock(); qcv.notify_one();
        }

        // ── рабочие нити ──────────────────────────────────────────────────────────────
        void WorkerLoop()
        {
            std::unique_ptr<IAuthBackend> auth = factory();
            while (true)
            {
                Job job;
                {
                    std::unique_lock<std::mutex> lk(qmu);
                    qcv.wait(lk, [&] { return stop || !queue.empty(); });
                    if (stop && queue.empty()) break;
                    job = std::move(queue.front()); queue.pop_front();
                }
                if (job.rq.path == "/token") HandleToken(job.s, job.ip, job.rq, auth.get());
                else HandleRefresh(job.s, job.ip, job.rq, auth.get());
                closesocket(job.s);
                if (!job.rq.body.empty()) SecureZeroMemory(&job.rq.body[0], job.rq.body.size());
            }
        }

        void Reply(SOCKET s, int code, const std::string& body) { SendResponse(s, code, body, false, cfg.requestDeadlineSec * 1000); }

        bool JsonContentType(const Request& rq)
        {
            return rq.contentType == "application/json" || rq.contentType.rfind("application/json;", 0) == 0;
        }

        // Строгая схема: объект ровно с перечисленными строковыми полями.
        bool StrictObject(const std::string& body, std::initializer_list<const char*> keys, Json::Value& v)
        {
            if (!Json::Parse(body, v) || v.type != Json::Type::Object || v.obj.size() != keys.size()) return false;
            for (const char* k : keys) { const Json::Value* f = v.Get(k); if (!f || f->type != Json::Type::String) return false; }
            return true;
        }

        // E1-09: учесть исход запроса к БД и обновить признак деградации (под lmu).
        void NoteOutcome(bool is503, int64_t now)
        {
            outcomes.emplace_back(now, is503);
            int64_t win = (int64_t)cfg.idDegradedWindowSec * 1000;
            while (!outcomes.empty() && now - outcomes.front().first > win) outcomes.pop_front();
            while (outcomes.size() > 100000) outcomes.pop_front();
            size_t total = outcomes.size(), bad = 0;
            for (auto& o : outcomes) bad += o.second;
            int pct = total ? (int)(bad * 100 / total) : 0;
            GetHealth().idDegradedPct = pct;
            if ((int)total >= cfg.idDegradedMinRequests && pct >= cfg.idDegradedRatioPct)
            {
                int64_t until = now + (int64_t)cfg.epicDownHoldSec * 1000;
                if (GetHealth().idDegradedUntil.load() <= now)
                    LOGW("id", "AsdaId деградировал: 503 в %d %% из %zu запросов за %d с — ядру FailOpen на %d с", pct, total, cfg.idDegradedWindowSec, cfg.epicDownHoldSec);
                GetHealth().idDegradedUntil = until;
            }
        }

        // Пауза ступени st (st за пределами — последняя ступень).
        int64_t StageMs(const std::vector<int>& stages, int st) const
        {
            if (stages.empty()) return 60000;
            return (int64_t)stages[(size_t)(std::min)(st, (int)stages.size() - 1)] * 1000;
        }

        // Неудача на счётчике: при достижении предела — пауза текущей ступени, ступень растёт. true — пауза включена.
        bool CountFail(FailCounter& f, int max, const std::vector<int>& stages, int64_t now, int64_t& pauseMs)
        {
            if (f.lastAt && now - f.lastAt > 3600000) { f.stage = 0; f.fails = 0; f.total = 0; }   // час без неудач — ступени и счёт остыли
            f.lastAt = now;
            ++f.total;
            if (++f.fails < max) return false;
            pauseMs = StageMs(stages, f.stage);
            f.pauseUntil = now + pauseMs;
            f.fails = 0;
            if (f.stage < (int)stages.size() - 1) ++f.stage;
            return true;
        }

        void Sweep(int64_t now)
        {
            // под lmu: чистка раз в минуту
            if (now - lastSweep < 60000) return;
            lastSweep = now;
            for (auto it = ipHits.begin(); it != ipHits.end();)
            {
                while (!it->second.empty() && now - it->second.front() >= 60000) it->second.pop_front();
                it = it->second.empty() ? ipHits.erase(it) : std::next(it);
            }
            auto stale = [&](const FailCounter& f) { return now - f.lastAt > 3600000 && f.pauseUntil < now; };
            for (auto it = pairFails.begin(); it != pairFails.end();) it = stale(it->second) ? pairFails.erase(it) : std::next(it);
            for (auto it = loginFails.begin(); it != loginFails.end();) it = stale(it->second) ? loginFails.erase(it) : std::next(it);
            int64_t unow = UnixNow(), keep = (int64_t)cfg.loginKnownIpDays * 86400;
            for (auto it = knownIps.begin(); it != knownIps.end();)
            {
                for (auto j = it->second.begin(); j != it->second.end();) j = unow - j->second > keep ? it->second.erase(j) : std::next(j);
                it = it->second.empty() ? knownIps.erase(it) : std::next(it);
            }
            size_t before = refresh.size();
            for (auto it = refresh.begin(); it != refresh.end();)
                it = (it->second.idleExp <= unow || it->second.absExp <= unow) ? refresh.erase(it) : std::next(it);
            if (refresh.size() != before) MarkDirty(now);
        }

        void MarkDirty(int64_t now) { if (!refreshDirty) refreshDirtyAt = now; refreshDirty = true; }

        // Выпустить пару токенов; refresh регистрируется в хранилище (lmu вызывающий НЕ держит).
        bool IssuePair(const RefreshEntry& base, std::string& body, std::string& jti, std::string& rtPrefix)
        {
            std::string access;
            if (!Jwt::Issue(*key, kid, cfg.issuer, cfg.audience, std::to_string(base.userIndex), UnixNow(), cfg.accessTtlSec, access, &jti)) return false;
            uint8_t rnd[32];
            if (!Crypto::Random(rnd, sizeof(rnd))) return false;
            std::string rt = Crypto::B64Url(rnd, sizeof(rnd));   // 43 символа
            SecureZeroMemory(rnd, sizeof(rnd));
            uint8_t h[32]; Crypto::Sha256(rt.data(), rt.size(), h);
            std::string hk = Crypto::Hex(h, 32);
            rtPrefix = hk.substr(0, 12);
            {
                std::lock_guard<std::mutex> lk(lmu);
                // Предел активных refresh на учётку: старейший гасится.
                std::vector<std::unordered_map<std::string, RefreshEntry>::iterator> mine;
                for (auto it = refresh.begin(); it != refresh.end(); ++it) if (it->second.userIndex == base.userIndex) mine.push_back(it);
                while ((int)mine.size() >= cfg.maxRefreshPerUser)
                {
                    auto oldest = std::min_element(mine.begin(), mine.end(), [](auto a, auto b) { return a->second.issued < b->second.issued; });
                    refresh.erase(*oldest); mine.erase(oldest);
                }
                RefreshEntry e = base;
                e.idleExp = (std::min)(UnixNow() + (int64_t)cfg.refreshTtlSec, e.absExp);   // E1-10: продление при использовании
                refresh[hk] = e;
                MarkDirty(NowMs());
            }
            body = "{\"access_token\":" + Json::Quote(access) + ",\"token_type\":\"Bearer\",\"expires_in\":" +
                   std::to_string(cfg.accessTtlSec) + ",\"refresh_token\":" + Json::Quote(rt) + "}";
            SecureZeroMemory(&rt[0], rt.size());
            GetHealth().NoteToken(NowMs(), base.userIndex);   // ★ Д3: выдача токена — для признака «токены есть, REG нет»
            return true;
        }

        void HandleToken(SOCKET s, const std::string& ip, const Request& rq, IAuthBackend* auth)
        {
            int64_t now = NowMs();
            {
                std::lock_guard<std::mutex> lk(lmu);
                Sweep(now);
                auto& dq = ipHits[ip];
                while (!dq.empty() && now - dq.front() >= 60000) dq.pop_front();
                if ((int)dq.size() >= cfg.tokenPerIpPerMin)
                {
                    LOGW("id", "/token %s → 429 (предел %d/мин с IP)", ip.c_str(), cfg.tokenPerIpPerMin);
                    Reply(s, 429, "{\"error\":\"rate_limited\"}");
                    return;
                }
                dq.push_back(now);
            }
            Json::Value v;
            std::string login, md5;
            if (!JsonContentType(rq) || !StrictObject(rq.body, { "login", "password_md5" }, v) ||
                !v.GetString("login", login) || !v.GetString("password_md5", md5) ||
                !NormalizeLogin(login) || !NormalizeMd5(md5))
            {
                LOGI("id", "/token %s → 400 (схема)", ip.c_str());
                Reply(s, 400, "{\"error\":\"invalid_request\"}");
                if (!md5.empty()) SecureZeroMemory(&md5[0], md5.size());
                return;
            }
            std::string lkey = Lower(login), pkey = lkey + "|" + ip;
            {
                // E1-06: пауза пары (логин, IP) — всегда; общая пауза логина — кроме IP, с которых на этот логин уже входили.
                std::lock_guard<std::mutex> lk(lmu);
                auto pit = pairFails.find(pkey);
                auto lit = loginFails.find(lkey);
                bool known = false;
                auto kit = knownIps.find(lkey);
                if (kit != knownIps.end() && kit->second.count(ip)) known = true;
                const char* why = nullptr; int64_t left = 0;
                if (pit != pairFails.end() && pit->second.pauseUntil > now) { why = "пауза пары логин+IP"; left = pit->second.pauseUntil - now; }
                else if (!known && lit != loginFails.end() && lit->second.pauseUntil > now) { why = "общая пауза логина (IP без прежних входов)"; left = lit->second.pauseUntil - now; }
                if (why)
                {
                    LOGW("id", "/token %s login=%s → 429 (%s, ещё %lld с)", ip.c_str(), login.c_str(), why, (long long)((left + 999) / 1000));
                    SecureZeroMemory(&md5[0], md5.size());
                    Reply(s, 429, "{\"error\":\"rate_limited\"}");
                    return;
                }
            }
            AuthResult ar = auth->Check(login, md5);
            SecureZeroMemory(&md5[0], md5.size());
            if (ar.verdict == AuthVerdict::Error)
            {
                { std::lock_guard<std::mutex> lk(lmu); NoteOutcome(true, now); }
                LOGE("id", "/token %s login=%s → 503 (БД недоступна)", ip.c_str(), login.c_str());
                Reply(s, 503, "{\"error\":\"temporarily_unavailable\"}");
                return;
            }
            if (ar.verdict == AuthVerdict::Denied)
            {
                int64_t pp = 0, lp = 0; bool pPaused, lPaused; int pf, lf; long long pt, lt;
                {
                    std::lock_guard<std::mutex> lk(lmu);
                    NoteOutcome(false, now);
                    std::vector<int> pairStages = cfg.loginPauseStagesSec;
                    if (!pairStages.empty()) pairStages[0] = cfg.loginFailPauseSec;
                    FailCounter& pfc = pairFails[pkey];
                    FailCounter& lfc = loginFails[lkey];
                    pPaused = CountFail(pfc, cfg.loginFailMax, pairStages, now, pp);
                    lPaused = CountFail(lfc, cfg.loginGlobalFailMax, cfg.loginPauseStagesSec, now, lp);
                    pf = pfc.fails; lf = lfc.fails; pt = pfc.total; lt = lfc.total;
                }
                // §8.6 (R3-07): строка на КАЖДУЮ неудачу со сквозным номером (логина и пары) — окно 5 с UPEacAuthFail на журнал не влияет.
                LOGI("id", "/token %s login=%s → 401 (UPEacAuth статус %d; неудача №%lld логина, №%lld пары с последнего успеха; неудач пары %d/%d%s; логина %d/%d%s)",
                     ip.c_str(), login.c_str(), ar.status, lt, pt,
                     pPaused ? cfg.loginFailMax : pf, cfg.loginFailMax, pPaused ? (", пауза пары " + std::to_string(pp / 1000) + " с").c_str() : "",
                     lPaused ? cfg.loginGlobalFailMax : lf, cfg.loginGlobalFailMax, lPaused ? (", общая пауза логина " + std::to_string(lp / 1000) + " с").c_str() : "");
                // E1-06: неудача ПАРОЛЯ — в us_pwfail (по логике замка UPUserLogin), отложенно: тот же ввод игрока параллельно
                // проверяет LoginManager (UPUserLogin пишет сам) — процедура не засчитает повтор, если неудача записана < 5 с назад.
                if (ar.status == 3 && cfg.failWrite)
                {
                    std::lock_guard<std::mutex> lk(fmu);
                    if (failQueue.size() < kFailQueueMax) { failQueue.push_back({ NowMs() + cfg.failWriteDelayMs, login }); fcv.notify_one(); }
                    else LOGE("id", "очередь записи неудач переполнена (%zu) — неудача login=%s не записана в БД", failQueue.size(), login.c_str());
                }
                Reply(s, 401, "{\"error\":\"invalid_grant\"}");
                return;
            }
            // Успех: сброс счётчиков (E1-06), IP запоминается как «свой» для логина.
            {
                std::lock_guard<std::mutex> lk(lmu);
                NoteOutcome(false, now);
                pairFails.erase(pkey);
                loginFails.erase(lkey);
                auto& ips = knownIps[lkey];
                ips[ip] = UnixNow();
                while ((int64_t)ips.size() > kKnownIpMax)
                    ips.erase(std::min_element(ips.begin(), ips.end(), [](auto& a, auto& b) { return a.second < b.second; }));
            }
            // E1-19: отпечаток пароля для последующих /refresh (сбой БД — проверим на первом /refresh).
            RefreshEntry base; base.userIndex = ar.userIndex; base.login = login; base.issued = UnixNow();
            base.absExp = base.issued + cfg.refreshAbsoluteSec;
            StatusResult sr = auth->CheckStatus(ar.userIndex);
            if (sr.verdict == AuthVerdict::Ok) { base.pwTag = sr.pwTag; base.checkedAt = base.issued; }
            else if (sr.verdict == AuthVerdict::Denied)
            {
                LOGW("id", "/token %s login=%s → 401 (пароль верен, но UPEacAuthStatus статус %d)", ip.c_str(), login.c_str(), sr.status);
                Reply(s, 401, "{\"error\":\"invalid_grant\"}");
                return;
            }
            std::string body, jti, rtp;
            if (!IssuePair(base, body, jti, rtp))
            {
                LOGE("id", "/token %s login=%s → 503 (сбой подписи CNG)", ip.c_str(), login.c_str());
                { std::lock_guard<std::mutex> lk(lmu); NoteOutcome(true, now); }
                Reply(s, 503, "{\"error\":\"temporarily_unavailable\"}");
                return;
            }
            LOGI("id", "/token %s login=%s → 200 sub=%u jti=%s refresh=%s…", ip.c_str(), login.c_str(), ar.userIndex, jti.c_str(), rtp.c_str());
            Reply(s, 200, body);
        }

        void HandleRefresh(SOCKET s, const std::string& ip, const Request& rq, IAuthBackend* auth)
        {
            Json::Value v; std::string rt;
            if (!JsonContentType(rq) || !StrictObject(rq.body, { "refresh_token" }, v) || !v.GetString("refresh_token", rt) || !IsB64Url(rt, 43, 128))
            {
                LOGI("id", "/refresh %s → 400 (схема)", ip.c_str());
                Reply(s, 400, "{\"error\":\"invalid_request\"}");
                return;
            }
            uint8_t h[32]; Crypto::Sha256(rt.data(), rt.size(), h);
            SecureZeroMemory(&rt[0], rt.size());
            std::string hk = Crypto::Hex(h, 32);
            RefreshEntry e; bool found = false;
            int64_t unow = UnixNow(), now = NowMs();
            {
                std::lock_guard<std::mutex> lk(lmu);
                Sweep(now);
                auto it = refresh.find(hk);
                if (it != refresh.end())
                {
                    e = it->second;
                    refresh.erase(it);   // старый гасится в любом случае (одноразовый)
                    MarkDirty(now);
                    found = e.idleExp > unow && e.absExp > unow;
                }
            }
            if (!found)
            {
                LOGI("id", "/refresh %s refresh=%s… → 401", ip.c_str(), hk.substr(0, 12).c_str());
                Reply(s, 401, "{\"error\":\"invalid_grant\"}");
                return;
            }
            // E1-19: не реже StatusRecheckSec — состояние учётки (блок/состояние) и смена пароля.
            if (unow - e.checkedAt >= cfg.statusRecheckSec)
            {
                StatusResult sr = auth->CheckStatus(e.userIndex);
                if (sr.verdict == AuthVerdict::Denied || (sr.verdict == AuthVerdict::Ok && !e.pwTag.empty() && sr.pwTag != e.pwTag))
                {
                    LOGW("id", "/refresh %s login=%s sub=%u → 401 (%s)", ip.c_str(), e.login.c_str(), e.userIndex,
                         sr.verdict == AuthVerdict::Denied ? ("UPEacAuthStatus статус " + std::to_string(sr.status)).c_str() : "пароль сменён после входа");
                    Reply(s, 401, "{\"error\":\"invalid_grant\"}");
                    return;
                }
                if (sr.verdict == AuthVerdict::Ok) { e.checkedAt = unow; e.pwTag = sr.pwTag; }
                else LOGW("id", "/refresh %s login=%s: UPEacAuthStatus недоступна — проверка отложена до следующего /refresh", ip.c_str(), e.login.c_str());
            }
            std::string body, jti, rtp;
            if (!IssuePair(e, body, jti, rtp))
            {
                LOGE("id", "/refresh %s → 503 (сбой подписи CNG)", ip.c_str());
                Reply(s, 503, "{\"error\":\"temporarily_unavailable\"}");
                return;
            }
            LOGI("id", "/refresh %s login=%s → 200 sub=%u jti=%s refresh=%s…→%s…", ip.c_str(), e.login.c_str(), e.userIndex, jti.c_str(),
                 hk.substr(0, 12).c_str(), rtp.c_str());
            Reply(s, 200, body);
        }

        // ── фоновая нить: отложенные UPEacAuthFail и сброс refresh на диск ─────────────
        void BgLoop()
        {
            std::unique_ptr<IAuthBackend> auth = factory();
            while (true)
            {
                FailWrite job; bool have = false;
                {
                    std::unique_lock<std::mutex> lk(fmu);
                    fcv.wait_for(lk, std::chrono::milliseconds(250), [&] { return stop.load() || (!failQueue.empty() && failQueue.front().due <= NowMs()); });
                    if (!failQueue.empty() && (failQueue.front().due <= NowMs() || stop)) { job = failQueue.front(); failQueue.pop_front(); have = true; }
                    else if (stop) break;
                }
                if (have)
                {
                    int st = -1;
                    bool ok = auth->RecordFail(job.login, st);
                    if (!ok) LOGE("id", "UPEacAuthFail login=%s: ошибка БД — неудача не записана", job.login.c_str());
                    else LOGI("id", "UPEacAuthFail login=%s → статус %d (%s)", job.login.c_str(), st,
                              st == 0 ? "засчитана в us_pwfail" : st == 1 ? "тот же ввод уже засчитан в us_pwfail < 5 с назад; в счёте AsdaId неудача учтена" :
                              st == 4 ? "учётка заперта — не растёт" : "учётки нет");
                }
                FlushRefresh(false);
            }
            FlushRefresh(true);
        }

        // ── хранилище refresh (E1-10) ─────────────────────────────────────────────────
        std::string SerializeRefresh()
        {
            std::string b(kRefreshMagic, sizeof(kRefreshMagic));
            PutU32(b, (uint32_t)refresh.size());
            for (auto& kv : refresh)
            {
                std::vector<uint8_t> hb;
                for (size_t i = 0; i + 1 < kv.first.size(); i += 2) hb.push_back((uint8_t)strtoul(kv.first.substr(i, 2).c_str(), nullptr, 16));
                b.append((const char*)hb.data(), hb.size());
                const RefreshEntry& e = kv.second;
                PutU32(b, e.userIndex);
                b += (char)(uint8_t)(std::min)(e.login.size(), (size_t)255); b.append(e.login, 0, (std::min)(e.login.size(), (size_t)255));
                PutI64(b, e.idleExp); PutI64(b, e.absExp); PutI64(b, e.issued); PutI64(b, e.checkedAt);
                b += (char)(uint8_t)(std::min)(e.pwTag.size(), (size_t)255); b.append(e.pwTag, 0, (std::min)(e.pwTag.size(), (size_t)255));
            }
            return b;
        }

        void FlushRefresh(bool force)
        {
            std::string plain;
            {
                std::lock_guard<std::mutex> lk(lmu);
                if (!refreshDirty || (!force && NowMs() - refreshDirtyAt < 1000)) return;
                plain = SerializeRefresh();
                refreshDirty = false;
            }
            DATA_BLOB in{ (DWORD)plain.size(), (BYTE*)plain.data() }, out{};
            DATA_BLOB ent{ (DWORD)(wcslen(kRefreshEntropy) * sizeof(wchar_t)), (BYTE*)kRefreshEntropy };
            BOOL ok = CryptProtectData(&in, L"AsdaEacServer refresh", &ent, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out);
            SecureZeroMemory(&plain[0], plain.size());
            if (!ok) { LOGE("id", "refresh: CryptProtectData %lu — на диск не записано", GetLastError()); std::lock_guard<std::mutex> lk(lmu); MarkDirty(NowMs()); return; }
            std::string err;
            if (!WriteFileAtomic(cfg.refreshFile, out.pbData, out.cbData, &err))
            {
                LOGE("id", "refresh: %s", err.c_str());
                std::lock_guard<std::mutex> lk(lmu); MarkDirty(NowMs());
            }
            LocalFree(out.pbData);
        }

        void LoadRefresh()
        {
            std::vector<uint8_t> raw;
            if (!ReadWholeFile(cfg.refreshFile, raw)) { LOGI("id", "refresh: файла %s нет — хранилище пустое", Utf8(cfg.refreshFile).c_str()); return; }
            DATA_BLOB in{ (DWORD)raw.size(), raw.data() }, out{};
            DATA_BLOB ent{ (DWORD)(wcslen(kRefreshEntropy) * sizeof(wchar_t)), (BYTE*)kRefreshEntropy };
            if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
            {
                std::wstring bad = cfg.refreshFile + L".bad";
                MoveFileExW(cfg.refreshFile.c_str(), bad.c_str(), MOVEFILE_REPLACE_EXISTING);
                LOGE("id", "refresh: CryptUnprotectData %lu — файл не читается (другая машина?), отложен в %s; хранилище пустое", GetLastError(), Utf8(bad).c_str());
                return;
            }
            std::vector<uint8_t> b(out.pbData, out.pbData + out.cbData);
            SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
            size_t o = sizeof(kRefreshMagic); uint32_t n = 0;
            if (b.size() < o || memcmp(b.data(), kRefreshMagic, o) != 0 || !GetU32(b, o, n)) { LOGE("id", "refresh: неизвестный формат файла — хранилище пустое"); return; }
            int64_t unow = UnixNow(); size_t loaded = 0, expired = 0;
            for (uint32_t i = 0; i < n; ++i)
            {
                if (o + 32 > b.size()) { LOGE("id", "refresh: файл обрезан на записи %u", i); break; }
                std::string hk = Crypto::Hex(b.data() + o, 32); o += 32;
                RefreshEntry e;
                if (!GetU32(b, o, e.userIndex) || !GetStr(b, o, e.login) || !GetI64(b, o, e.idleExp) || !GetI64(b, o, e.absExp) ||
                    !GetI64(b, o, e.issued) || !GetI64(b, o, e.checkedAt) || !GetStr(b, o, e.pwTag)) { LOGE("id", "refresh: файл обрезан на записи %u", i); break; }
                if (e.idleExp <= unow || e.absExp <= unow) { ++expired; continue; }
                refresh[hk] = e; ++loaded;
            }
            SecureZeroMemory(b.data(), b.size());
            LOGI("id", "refresh: загружено %zu действующих (истёкших пропущено %zu) из %s", loaded, expired, Utf8(cfg.refreshFile).c_str());
        }

        // E1-05: статика для Caddy — WwwDir\.well-known\{jwks.json, openid-configuration} (пишется, если содержимое изменилось).
        void WriteWellKnown()
        {
            std::wstring dir = cfg.wwwDir + L"\\.well-known";
            MakeDirs(dir);
            const std::pair<const wchar_t*, const std::string*> files[] = { { L"jwks.json", &jwks }, { L"openid-configuration", &oidc } };
            for (auto& f : files)
            {
                std::wstring path = dir + L"\\" + f.first;
                std::vector<uint8_t> cur;
                if (ReadWholeFile(path, cur) && cur.size() == f.second->size() && memcmp(cur.data(), f.second->data(), cur.size()) == 0) continue;
                std::string err;
                if (WriteFileAtomic(path, f.second->data(), f.second->size(), &err)) LOGI("id", "статика Caddy записана: %s (kid=%s)", Utf8(path).c_str(), kid.c_str());
                else LOGE("id", "статика Caddy не записана: %s", err.c_str());
            }
        }
    };

    AsdaIdServer::AsdaIdServer() : m(new Impl()) {}
    AsdaIdServer::~AsdaIdServer() { Stop(); delete m; }

    bool AsdaIdServer::Start(const Config& cfg, Crypto::RsaKey* key, AuthFactory factory, std::string* err)
    {
        m->cfg = cfg; m->key = key; m->factory = factory;
        m->kid = Jwt::Kid(*key);
        m->jwks = Jwt::Jwks(*key, m->kid);
        m->oidc = "{\"issuer\":" + Json::Quote(cfg.issuer) + ",\"jwks_uri\":" + Json::Quote(cfg.issuer + "/.well-known/jwks.json") +
                  ",\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
        m->listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m->listenSock == INVALID_SOCKET) { if (err) *err = "socket"; return false; }
        BOOL excl = TRUE; setsockopt(m->listenSock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof(excl));
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)cfg.idPort);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);   // контракт: только 127.0.0.1 (наружу — через Caddy)
        if (bind(m->listenSock, (sockaddr*)&sa, sizeof(sa)) != 0 || listen(m->listenSock, SOMAXCONN) != 0)
        {
            if (err) *err = "bind/listen 127.0.0.1:" + std::to_string(cfg.idPort) + " (" + std::to_string(WSAGetLastError()) + ")";
            closesocket(m->listenSock); m->listenSock = INVALID_SOCKET;
            return false;
        }
        u_long nb = 1; ioctlsocket(m->listenSock, FIONBIO, &nb);
        m->LoadRefresh();
        m->WriteWellKnown();
        m->stop = false;
        for (int i = 0; i < cfg.idWorkers; ++i) m->workers.emplace_back([this] { m->WorkerLoop(); });
        m->bgThread = std::thread([this] { m->BgLoop(); });
        m->ioThread = std::thread([this] { m->IoLoop(); });
        LOGI("id", "AsdaId слушает 127.0.0.1:%d, kid=%s, нитей БД %d; срок запроса %d с; refresh: %zu в %s", cfg.idPort, m->kid.c_str(), cfg.idWorkers,
             cfg.requestDeadlineSec, m->refresh.size(), Utf8(cfg.refreshFile).c_str());
        return true;
    }

    void AsdaIdServer::Stop()
    {
        if (!m || (m->listenSock == INVALID_SOCKET && m->workers.empty())) return;
        m->stop = true;
        if (m->ioThread.joinable()) m->ioThread.join();
        if (m->listenSock != INVALID_SOCKET) { closesocket(m->listenSock); m->listenSock = INVALID_SOCKET; }
        m->qcv.notify_all();
        for (auto& t : m->workers) if (t.joinable()) t.join();
        m->workers.clear();
        m->fcv.notify_all();
        if (m->bgThread.joinable()) m->bgThread.join();   // дописывает отложенные UPEacAuthFail и сбрасывает refresh на диск
        for (auto& j : m->queue) closesocket(j.s);
        m->queue.clear();
    }
}
