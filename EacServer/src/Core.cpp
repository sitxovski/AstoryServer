// Copyright (c) 2026 @sitxovski (Discord)
// Core.cpp — сайдкар, мост, привязки и политика (см. Core.h). Всё — в одной нити.
// Ред. 3 (16.10.2026, по ревизии REVIEW_E1, контракт §8): защищённая игровая сессия = EAC-сессия учётки в состоянии
// Authenticated (RemoteAuthComplete) + совпавший ненулевой BIND игрового канала (+ IP при RequireSameIp); FailOpen по
// порогам; лимиты REG на учётку и на IP; вытеснение не продлевает отсчёт; мост v2 с bind и проверкой процесса-владельца;
// приём соединений с пределами за проход и token bucket без журнала на каждый отказ.
// §8.6 (REVIEW_R3, 16.10): лимит REG 6/10 мин без учёта REG, вытесняющей Authenticated-сессию той же учётки с того же IP (R3-01);
// освобождения отдельной учётки при временном отказе VerifyIdToken нет — только глобальный FailOpen по порогам (R3-03); процесс,
// у которого за 120 с после HELLO пришло ≥ 5 LOGIN и все с нулевым bind, — «P61 у процесса не активен»: причина 6 к нему не
// применяется, причина 1 работает (R3-04).
#include "EacCommon.h"
#include "Core.h"
#include "Health.h"
#include "AdminStatus.h"
#include "Jwt.h"
#include "Log.h"
#include <iphlpapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <io.h>
#include <map>
#include <set>
#include <unordered_map>
#include <deque>
#include <algorithm>
#include <sstream>
#include <cstring>

namespace Eac
{
    namespace
    {
        constexpr size_t  kMaxOut        = 256 * 1024;   // предел неотправленного на соединение (медленный читатель — разрыв)
        constexpr int64_t kCloseFlushMs  = 2000;         // сколько ждать отправки перед закрытием
        constexpr int64_t kHousekeepMs   = 250;          // период проверки таймаутов и политики
        constexpr size_t  kMaxPuid       = 32;           // EOS_PRODUCTUSERID_MAX_LENGTH
        constexpr size_t  kMaxToken      = 4000;         // предел длины ID-токена в REG
        constexpr int     kBindPerMinMax = 60;           // BIND-кадров на соединение в минуту (сверх — разрыв: защита от ротации списка)
        constexpr size_t  kVerifyWinMax  = 20000;        // предел записей окна ответов VerifyIdToken
        constexpr int64_t kP61ProbeMs    = 120000;       // §8.6 (R3-04): окно наблюдения bind LOGIN процесса после HELLO
        constexpr int     kP61ProbeMin   = 5;            // §8.6 (R3-04): столько LOGIN за окно, все нулевые, — «P61 у процесса не активен»

        const char* ReasonText(int r)
        {
            switch (r)
            {
            case kReasonNoSession: return "нет EAC-сессии за BindTimeout";
            case kReasonEacAction: return "EAC потребовал удалить (ClientActionRequired)";
            case kReasonChannelLost: return "канал 15901 потерян дольше Grace";
            case kReasonRegRejected: return "регистрация EAC отклонена / не аутентифицирована";
            case kReasonEvicted: return "вытеснен новой EAC-сессией";
            case kReasonNotBound: return "игровое соединение не привязано к EAC-сессии";
            default: return "?";
            }
        }

        const char* EosReasonText(int r)
        {
            static const char* t[] = { "Invalid", "InternalError", "InvalidMessage", "AuthenticationFailed", "NullClient", "HeartbeatTimeout",
                                       "ClientViolation", "BackendViolation", "TemporaryCooldown", "TemporaryBanned", "PermanentBanned" };
            return (r >= 0 && r <= 10) ? t[r] : "?";
        }

        void PutU16(std::vector<uint8_t>& v, uint16_t x) { v.push_back((uint8_t)x); v.push_back((uint8_t)(x >> 8)); }
        void PutU32(std::vector<uint8_t>& v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> (8 * i))); }
        uint16_t GetU16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
        uint32_t GetU32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

        // Кадр «u16 len · u8 type · payload».
        std::vector<uint8_t> MakeFrame(uint8_t type, const std::vector<uint8_t>& payload)
        {
            std::vector<uint8_t> f; f.reserve(3 + payload.size());
            PutU16(f, (uint16_t)(1 + payload.size()));
            f.push_back(type);
            f.insert(f.end(), payload.begin(), payload.end());
            return f;
        }

        bool IsPuid(const std::string& s)
        {
            if (s.size() != 32) return false;
            for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            return true;
        }

        // Все 32 байта привязки нулевые (слот Legacy / P61 выключен).
        bool BindIsZero(const uint8_t* b) { uint8_t acc = 0; for (size_t i = 0; i < kBindLen; ++i) acc |= b[i]; return acc == 0; }

        // Краткий отпечаток привязки для журнала (первые 4 байта hex — по ним значение не восстановить).
        std::string BindTag(const uint8_t* b) { return Crypto::Hex(b, 4); }

        // Состояние соединения сайдкара.
        enum class SideState { Handshake, WaitReg, Verifying, Registered, Closing };

        const char* SideStateText(SideState s)
        {
            switch (s)
            {
            case SideState::Handshake: return "рукопожатие"; case SideState::WaitReg: return "ждём REG";
            case SideState::Verifying: return "проверка токена"; case SideState::Registered: return "зарегистрирован";
            default: return "закрывается";
            }
        }

        // Один BIND от клиента (ред. 3 §8.1).
        struct BindEntry
        {
            uint8_t kind = 0;                      // serverKind из BIND — только журнал (клиент шлёт всегда 2; сверяется лишь bind)
            uint8_t b[kBindLen] = {};              // привязка игрового канала
            int64_t at = 0;                        // когда пришёл
            bool    matched = false;               // уже сопоставлен с игровой сессией (тогда не истекает по BindKeepSec)
        };

        // Соединение 15901.
        struct SideConn
        {
            uint64_t id = 0;                       // он же EOS ClientHandle (монотонный, не переиспользуется)
            SOCKET   s = INVALID_SOCKET;
            uint32_t ipv4 = 0;                     // адрес клиента (сетевой порядок)
            std::string ip;                        // он же текстом
            AsdaSecure::ServerChannel ch;          // AsdaSecure, SubServer::Eac
            std::vector<uint8_t> in;               // расшифрованный поток (кадры)
            std::vector<uint8_t> out;              // шифротекст к отправке
            SideState st = SideState::Handshake;
            int64_t acceptedAt = 0, readyAt = 0, lastPing = 0, verifyAt = 0, closeAt = 0;
            uint32_t userIndex = 0;                // после успешной проверки токена
            std::string puid;                      // PUID из REG
            uint8_t  platform = 0;                 // EOS_EAntiCheatCommonClientPlatform из REG
            uint64_t verifyReq = 0;                // идентификатор запроса VerifyIdToken
            bool     eosRegistered = false;        // RegisterClient выполнен
            int64_t  registeredAt = 0;             // когда RegisterClient (отсчёт AuthTimeoutSec)
            int      authStatus = 0;               // последний ClientAuthStatus (1 Local, 2 Remote)
            bool     authenticated = false;        // ред. 3 §8.2: пришёл RemoteAuthComplete
            std::deque<BindEntry> binds;           // ред. 3 §8.1: до MaxBindsPerSession последних BIND
            std::deque<int64_t> bindTimes;         // времена BIND-кадров за минуту (предел kBindPerMinMax)
            std::deque<std::vector<uint8_t>> pendingAc;   // ACMSG, пришедшие во время проверки токена
            bool     pendingCounted = false;       // учтено в pendingPerIp (рукопожатие / ждём REG / проверка)
            bool     dead = false;                 // закрыть в конце итерации
            std::string closeWhy;                  // причина закрытия (журнал)
        };

        // Соединение моста 15702.
        struct BridgeConn
        {
            uint64_t id = 0;
            SOCKET   s = INVALID_SOCKET;
            std::vector<uint8_t> in, out;
            bool     hello = false;                // HELLO получен
            uint8_t  kind = 0;                     // 2 Game, 3 Indun
            uint32_t pid = 0;                      // pid процесса сервера (из HELLO)
            uint32_t peerPid = 0;                  // ред. 3 §8.4: pid владельца соединения (GetExtendedTcpTable), 0 — проверка выключена
            std::string peerImage;                 // путь образа владельца (журнал)
            uint16_t gamePort = 0;
            int64_t  acceptedAt = 0, lastRecv = 0;
            bool     dead = false;
            std::string closeWhy;
        };

        // Учётка в таблице привязок.
        struct Account
        {
            uint64_t eacConn = 0;                  // соединение 15901 с зарегистрированной EAC-сессией (Registered); 0 — нет
            std::string puid;                      // последний PUID, подтверждённый Epic (для ожидания идущей проверки — E1-12)
            int64_t  rejectAt = 0;                 // последний отказ регистрации/аутентификации (причина 4 в решении)
            std::deque<int64_t> regTimes;          // ред. 3 §8.2/§8.6: подтверждённые REG за окно (кроме вытесняющих Authenticated с того же IP)
            int64_t  lastAuthAt = 0;               // ★ Д2: когда последний раз у учётки была аутентифицированная EAC-сессия (RemoteAuth / её закрытие)
            uint32_t lastAuthIp = 0;               // ★ Д2: IP 15901 той сессии
            int64_t  regLimitedAt = 0;             // ★ Д2: последний REG, отбитый пределом RegPerAccountMax
            int64_t  lastRegAt = 0;                // ★ Р66-3: последний REG учётки, дошедший до проверки токена (Connect у клиента работает)
            uint32_t regLimitedIp = 0;             // ★ Д2: IP 15901 того REG
        };

        // Игровая сессия от P73.
        struct GameSess
        {
            uint8_t  kind = 0; uint32_t pid = 0; uint16_t userNum = 0;   // ключ (сервер, процесс, слот CUser)
            uint32_t userIndex = 0;                // учётка из LOGIN (CUser+0x174) — она уходит в KICK (контракт §4)
            uint32_t bindUi = 0;                   // учётка привязки к EAC: = userIndex, после REBIND — sessionUserIndex (вход соулмейтом)
            uint32_t ipv4 = 0;                     // IP игрока по данным сервера
            uint32_t seq = 0;                      // seq последнего LOGIN/REBIND
            uint8_t  bind[kBindLen] = {};          // ред. 3: bind слота (ServerChannel::ChannelBinding P61), нули — Legacy/P61 выкл.
            bool     bindZero = true;              // bind нулевой
            uint64_t boundConn = 0;                // EAC-соединение, BIND которого совпал с bind (0 — не сопоставлен)
            int64_t  loginAt = 0;                  // когда пришёл LOGIN
            int64_t  bindBase = 0;                 // отсчёт BindTimeout (LOGIN, REBIND, выход из FailOpen)
            bool     prot = false;                 // защищена сейчас
            bool     everProtected = false;        // была защищена с bindBase (тогда после потери — Grace, иначе BindTimeout)
            int64_t  unprotSince = 0;              // когда защита потеряна (при everProtected)
            int64_t  waitUntil = 0;                // E1-12: разовое ожидание идущей проверки токена учётки (0 — не начиналось)
            int64_t  limitWaitUntil = 0;           // ★ Д2: разовое ожидание, пока REG учётки отбивается пределом (0 — не начиналось)
            int64_t  orphanSince = 0;              // P73 этого процесса отключён (0 — подключён)
            int      decided = 0;                  // последняя принятая причина (0 — нет)
            std::string decidedWhy;                // почему KICK не отправлен при последнем решении (пусто — отправлен / пытались)
            int64_t  lastKickAt = 0;               // когда последний раз слали KICK
        };

        uint64_t GameKey(uint8_t kind, uint32_t pid, uint16_t userNum) { return ((uint64_t)kind << 56) | ((uint64_t)pid << 16) | userNum; }

        // Ключ процесса сервера (вид, pid) — для наблюдения bind (§8.6 R3-04).
        uint64_t ProcKey(uint8_t kind, uint32_t pid) { return ((uint64_t)kind << 32) | pid; }

        // §8.6 (R3-04): наблюдение bind в LOGIN одного процесса P73 (живёт, пока жив процесс: P61 ставится на старте процесса).
        struct ProcBind
        {
            int64_t windowFrom = 0;                // начало текущего окна наблюдения (HELLO, пока вывода нет); 0 — окна нет
            int     zero = 0;                      // LOGIN с нулевым bind в текущем окне (ненулевой сразу даёт вывод active)
            bool    active = false;                // пришёл LOGIN с ненулевым bind — P61 у процесса работает (вывод окончательный)
            bool    inactive = false;              // «P61 у процесса не активен»: причина 6 к сессиям процесса не применяется
            bool    windowLogged = false;          // итог окна без вывода уже записан в журнал
        };

        // Token bucket (E1-04): rate токенов в секунду, ёмкость burst.
        struct Bucket
        {
            double  tokens = 0;                    // текущий запас
            int64_t last = 0;                      // время последнего пополнения
            // Взять токен. false — запас исчерпан.
            bool Take(int64_t now, int rate, int burst)
            {
                if (last == 0) { tokens = burst; last = now; }
                tokens = (std::min)((double)burst, tokens + (double)(now - last) * rate / 1000.0);
                last = now;
                if (tokens < 1.0) return false;
                tokens -= 1.0;
                return true;
            }
        };

        // Ответ VerifyIdToken в окне «Epic недоступен» (ред. 3 §8.3).
        struct VerifyEv { int64_t t = 0; uint32_t ip = 0; bool transient = false; };

        SOCKET MakeListener(const char* addr, int port, std::string* err)
        {
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) { if (err) *err = "socket"; return s; }
            BOOL excl = TRUE; setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof(excl));
            sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port);
            if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) { closesocket(s); if (err) *err = std::string("адрес ") + addr; return INVALID_SOCKET; }
            if (bind(s, (sockaddr*)&sa, sizeof(sa)) != 0 || listen(s, SOMAXCONN) != 0)
            {
                if (err) *err = std::string("bind/listen ") + addr + ":" + std::to_string(port) + " (" + std::to_string(WSAGetLastError()) + ")";
                closesocket(s); return INVALID_SOCKET;
            }
            u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
            return s;
        }

        // ред. 3 §8.4 (E1-13): pid процесса, владеющего клиентским концом принятого loopback-соединения.
        bool PeerOwnerPid(SOCKET s, uint32_t& pid)
        {
            sockaddr_in peer{}, local{}; int pl = sizeof(peer), ll = sizeof(local);
            if (getpeername(s, (sockaddr*)&peer, &pl) != 0 || getsockname(s, (sockaddr*)&local, &ll) != 0) return false;
            std::vector<uint8_t> buf;
            ULONG size = 0;
            DWORD r = ERROR_INSUFFICIENT_BUFFER;
            for (int attempt = 0; attempt < 4 && r == ERROR_INSUFFICIENT_BUFFER; ++attempt)
            {
                buf.resize(size ? size + 4096 : 16384);
                size = (ULONG)buf.size();
                r = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            }
            if (r != NO_ERROR) return false;
            const MIB_TCPTABLE_OWNER_PID* t = (const MIB_TCPTABLE_OWNER_PID*)buf.data();
            for (DWORD i = 0; i < t->dwNumEntries; ++i)
            {
                const MIB_TCPROW_OWNER_PID& row = t->table[i];
                // Строка клиентского конца: локальный адрес/порт = адрес пира, удалённый = наш слушающий конец.
                if (row.dwLocalAddr == peer.sin_addr.s_addr && (u_short)row.dwLocalPort == peer.sin_port &&
                    row.dwRemoteAddr == local.sin_addr.s_addr && (u_short)row.dwRemotePort == local.sin_port)
                {
                    pid = row.dwOwningPid;
                    return pid != 0;
                }
            }
            return false;
        }

        // Полный путь образа процесса.
        bool ProcessImage(uint32_t pid, std::wstring& path)
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) return false;
            wchar_t b[MAX_PATH * 4]; DWORD n = (DWORD)(sizeof(b) / sizeof(b[0]));
            BOOL ok = QueryFullProcessImageNameW(h, 0, b, &n);
            CloseHandle(h);
            if (!ok) return false;
            path.assign(b, n);
            return true;
        }

        // Строки равны без учёта регистра (пути Windows).
        bool PathEq(const std::wstring& a, const std::wstring& b)
        {
            return CompareStringOrdinal(a.c_str(), (int)a.size(), b.c_str(), (int)b.size(), TRUE) == CSTR_EQUAL;
        }
    }

    struct Core::Impl : public IEosSink
    {
        Config cfg;
        IEos* eos = nullptr;
        const AsdaSecure::PrivateKey* key = nullptr;
        SOCKET sideListen = INVALID_SOCKET, brListen = INVALID_SOCKET;
        uint64_t nextId = 1;                                   // общий счётчик id соединений и запросов
        std::map<uint64_t, std::unique_ptr<SideConn>> sides;
        std::map<uint64_t, std::unique_ptr<BridgeConn>> bridges;
        std::unordered_map<uint64_t, uint64_t> verifyReqs;     // reqId → id соединения
        std::unordered_map<uint32_t, Account> accounts;        // UserIndex → учётка
        std::map<uint64_t, GameSess> games;                    // GameKey → игровая сессия
        std::map<uint64_t, ProcBind> procBind;                 // §8.6 (R3-04): ProcKey → наблюдение bind LOGIN процесса
        int64_t startMs = 0, epicDownUntil = 0, lastHouse = 0, lastStats = 0, lastTick = 0;
        bool failOpenWas = true;                               // предыдущее состояние FailOpen (для сдвига отсчётов)
        long long statKicks = 0, statDecisions = 0, statRegOk = 0, statRegFail = 0, statEvict = 0;

        // E1-04: приём под нагрузкой.
        Bucket globalBucket;                                   // общий token bucket соединений 15901
        std::unordered_map<uint32_t, Bucket> ipBuckets;        // token bucket на IP
        std::unordered_map<uint32_t, int> pendingPerIp;        // незарегистрированные (рукопожатие/ждём REG/проверка) по IP
        std::unordered_map<uint32_t, std::deque<int64_t>> regPerIp;   // ред. 3 §8.3: REG-кадры по IP за минуту
        // Сводка отказов за период RejectSummarySec (вместо строки на каждый отказ).
        struct RejectStats { long long rate = 0, global = 0, unreg = 0, full = 0, regIp = 0; std::unordered_map<uint32_t, long long> byIp; } rej;
        int64_t lastRejectSummary = 0;

        // ред. 3 §8.3: окна признаков «Epic недоступен».
        std::deque<VerifyEv> verifyWin;                        // ответы VerifyIdToken
        std::deque<int64_t> eosErrWin;                         // временные ошибки вызовов EOS
        // ★ Д3 ред. 4 (ревизии 64, 66, 68): поблажка одной учётке «Epic Connect у клиента не проходит» (ConnectGrace) и её история.
        //   ★ Р68-1: пределы считаются по агрегатам, которые НЕ вытесняются эпизодами: окна поблажки (начала, ≤ 31 за AuthHistoryDays —
        //   окна не перекрываются) и расход по минутам за 24 ч (≤ 1440 записей). От эпизода хранится только текущий.
        struct AuthHist
        {
            int64_t lastAuthUnix = 0;          // последняя аутентифицированная EAC-сессия (RemoteAuthComplete), Unix — переживает рестарт
            int64_t lastViolationUnix = 0;     // ★ Р66-2: последнее нарушение (ClientActionRequired / решение причины 2), Unix
            int64_t epStartUnix = 0;           // текущий (последний) эпизод: начало, Unix
            int64_t epDurMs = 0;               //   его длительность
            int64_t epLastUnix = 0;            //   последний такт эпизода, Unix (перерыв > ConnectGraceEpisodeGapSec — новый эпизод)
            std::deque<int64_t> windows;       // ★ Р68-2: начала окон поблажки по 24 ч (окно открывает эпизод вне прошлых окон), Unix
            std::deque<std::pair<int64_t, int64_t>> usage;   // ★ Р68-1: расход по минутам: (Unix/60, мс) за последние 24 ч
            int64_t graceSeenMs = 0;           // последний такт поблажки (расход — один раз за такт)
            bool    graceOn = false;           // поблажка сейчас идёт (журнал / история)
            bool    graceDeniedLogged = false; // отказ по пределу записан (до следующего эпизода)
        };
        std::unordered_map<uint32_t, AuthHist> hist;           // UserIndex → история (AuthHistoryFile)
        bool histDirty = false; int64_t histSavedAt = 0;       // нужно сохранить / когда сохраняли
        bool histTrusted = true;                               // ★ Р66-4: папке state\ можно доверять (иначе история пустая и не пишется)
        std::unordered_map<uint32_t, int64_t> lastTokenMs;     // UserIndex → когда AsdaId последний раз выдал токен (NowMs)

        // ★ Р66-4: SID пользователя процесса (служба — SYSTEM; стенд — учётка, от которой запущен) в виде строки.
        static std::wstring ProcessUserSid()
        {
            HANDLE tok = nullptr; std::wstring out;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return out;
            uint8_t buf[256]; DWORD n = 0;
            if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n))
            {
                LPWSTR s = nullptr;
                if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &s)) { out = s; LocalFree(s); }
            }
            CloseHandle(tok);
            return out;
        }

        // ★ Р66-4: допустимые SID папки истории — SYSTEM, Administrators и пользователь самой службы (на стойке он и есть SYSTEM).
        static bool TrustedSid(PSID sid, const std::wstring& me)
        {
            LPWSTR s = nullptr;
            if (!ConvertSidToStringSidW(sid, &s)) return false;
            std::wstring v = s; LocalFree(s);
            return v == L"S-1-5-18" || v == L"S-1-5-32-544" || (!me.empty() && v == me);
        }

        // ★ Р66-4: папка state\ — создать с явным DACL без наследования (SYSTEM + Administrators + служба) или проверить существующую:
        //   владелец и все записи DACL — только из допустимых, DACL защищён от наследования. false — не доверять (журнал, пустая история).
        bool HistDirTrusted(std::string& why)
        {
            const std::wstring dir = cfg.authHistoryFile.substr(0, cfg.authHistoryFile.find_last_of(L"\\/"));
            const std::wstring me = ProcessUserSid();
            if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
                if (!me.empty() && me != L"S-1-5-18") sddl += L"(A;OICI;FA;;;" + me + L")";
                PSECURITY_DESCRIPTOR sd = nullptr;
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) { why = "SDDL"; return false; }
                SECURITY_ATTRIBUTES sa{ sizeof(sa), sd, FALSE };
                BOOL ok = CreateDirectoryW(dir.c_str(), &sa);
                LocalFree(sd);
                if (!ok) { why = "папка не создана (" + std::to_string(GetLastError()) + ")"; return false; }
                LOGI("pol", "история аутентификации: создана папка %s (DACL без наследования: SYSTEM, Administrators%s)", Utf8(dir).c_str(),
                     me == L"S-1-5-18" ? "" : ", пользователь службы");
            }
            PSID owner = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
            if (GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
            { why = "права папки не прочитаны"; return false; }
            SECURITY_DESCRIPTOR_CONTROL ctl = 0; DWORD rev = 0;
            GetSecurityDescriptorControl(sd, &ctl, &rev);
            bool good = owner && TrustedSid(owner, me);
            if (!good) why = "владелец папки — не SYSTEM / Administrators / служба";
            if (good && (!dacl || !(ctl & SE_DACL_PROTECTED))) { good = false; why = "DACL папки наследуется или пуст"; }
            for (DWORD i = 0; good && dacl && i < dacl->AceCount; ++i)
            {
                ACE_HEADER* h = nullptr;
                if (!GetAce(dacl, i, (LPVOID*)&h)) { good = false; why = "запись DACL не прочитана"; break; }
                // ★ Р68-5: допустимы только ACCESS_ALLOWED с разрешёнными SID; любой другой тип записи (объектный, callback, условный,
                //   запрещающий и пр.) — недоверие
                if (h->AceType != ACCESS_ALLOWED_ACE_TYPE) { good = false; why = "в DACL папки запись другого типа (" + std::to_string(h->AceType) + ")"; }
                else if (!TrustedSid(&((ACCESS_ALLOWED_ACE*)h)->SidStart, me)) { good = false; why = "в DACL папки есть чужая учётка"; }
            }
            LocalFree(sd);
            return good;
        }

        // ★ Д3: файл истории v4 — «#asda-auth-history v4», затем по строке:
        //   «uid lastAuth lastViolation epStart epDurSec epLast nW w… nU m:ms …» (окна — начала, Unix; расход — минута Unix/60 и мс).
        void HistLoad()
        {
            std::string why;
            // ★ Р70-3: «выключена ключом» (ConnectGraceSecPerDay=0) — не ошибка; несогласованные ключи — ошибка
            if (cfg.connectGraceSecPerDay <= 0) LOGI("pol", "поблажка Connect выключена ключом ConnectGraceSecPerDay=0");
            else if (!cfg.graceConfigError.empty())
                LOGE("pol", "поблажка Connect ВЫКЛЮЧЕНА: ошибка ключей [Policy] (%s) — EAC работает без неё", cfg.graceConfigError.c_str());
            histTrusted = HistDirTrusted(why);
            if (!histTrusted)
            {
                LOGE("pol", "история аутентификации: папке %s НЕ доверяю (%s) — история пустая и не пишется, поблажки Connect нет",
                     Utf8(cfg.authHistoryFile.substr(0, cfg.authHistoryFile.find_last_of(L"\\/"))).c_str(), why.c_str());
                return;
            }
            FILE* f = _wfopen(cfg.authHistoryFile.c_str(), L"rb");
            if (!f) { LOGI("pol", "история аутентификации учёток: файла %s нет — начинается пустой", Utf8(cfg.authHistoryFile).c_str()); return; }
            char head[64] = {};
            if (!fgets(head, sizeof(head), f) || strncmp(head, "#asda-auth-history v4", 21) != 0)
            {
                fclose(f); LOGW("pol", "история аутентификации: %s не версии v4 — не читается", Utf8(cfg.authHistoryFile).c_str()); return;
            }
            const int64_t now = UnixNow(), cut = now - (int64_t)cfg.authHistoryDays * 86400, fut = now + 86400;
            int n = 0, bad = 0, fixed = 0;
            char line[65536];
            while (fgets(line, sizeof(line), f))
            {
                // ★ Р70-1 / Р70-2: строка выбрасывается только при негодных uid / lastAuth / lastViolation. Негодные поля эпизода
                //   сбрасывают только эпизод, негодное окно / запись расхода пропускаются по одному; минута расхода > 60000 мс и
                //   длительность эпизода > предела прижимаются (не в пользу игрока: расход сохраняется полностью в пределах минуты).
                std::istringstream is(line);
                unsigned long long ui = 0, la = 0, lv = 0, es = 0, ed = 0, el = 0; long long nw = -1, nu = -1;
                if (!(is >> ui >> la >> lv) || ui == 0 || ui > 0x7FFFFFFFull || la > (unsigned long long)fut || lv > (unsigned long long)fut) { ++bad; continue; }
                AuthHist h; h.lastAuthUnix = (int64_t)la; h.lastViolationUnix = (int64_t)lv;
                bool fix = false;
                if (is >> es >> ed >> el)
                {
                    if (es <= (unsigned long long)fut && el <= (unsigned long long)fut && el >= es)
                    {
                        const unsigned long long cap = (unsigned long long)cfg.connectGraceEpisodeSec;
                        if (ed > cap) { ed = cap; fix = true; }
                        h.epStartUnix = (int64_t)es; h.epDurMs = (int64_t)ed * 1000; h.epLastUnix = (int64_t)el;
                    }
                    else fix = true;                              // эпизод сброшен, остальное — дальше
                }
                else { fix = true; is.clear(); }
                if (is >> nw && nw >= 0)
                {
                    for (long long i = 0; i < nw && i < 4096; ++i)
                    {
                        unsigned long long w = 0;
                        if (!(is >> w)) { fix = true; break; }
                        if (w <= (unsigned long long)fut && h.windows.size() < 64 && (h.windows.empty() || (int64_t)w >= h.windows.back())) h.windows.push_back((int64_t)w);
                        else fix = true;
                    }
                    if (is >> nu && nu >= 0)
                    {
                        for (long long i = 0; i < nu && i < 4096; ++i)
                        {
                            unsigned long long mi = 0, ms = 0; char c = 0;
                            if (!(is >> mi >> c >> ms) || c != ':') { fix = true; break; }
                            if (mi > (unsigned long long)(fut / 60)) { fix = true; continue; }
                            if (ms > 60000) { ms = 60000; fix = true; }
                            if (!h.usage.empty() && h.usage.back().first == (int64_t)mi) h.usage.back().second = (std::min)((int64_t)60000, h.usage.back().second + (int64_t)ms);
                            else if (h.usage.size() < 1440) h.usage.push_back({ (int64_t)mi, (int64_t)ms });
                        }
                    }
                    else fix = true;
                }
                else fix = true;
                fixed += fix;
                if (h.lastAuthUnix < cut && h.lastViolationUnix < cut) continue;
                hist[(uint32_t)ui] = std::move(h); ++n;
                if (hist.size() >= 200000) break;
            }
            if (fixed) LOGW("pol", "история аутентификации: у %d записей поправлены / пропущены отдельные поля (эпизод, окна, расход) — записи сохранены", fixed);
            fclose(f);
            LOGI("pol", "история аутентификации учёток: %d записей из %s%s", n, Utf8(cfg.authHistoryFile).c_str(),
                 bad ? (" (негодных строк пропущено: " + std::to_string(bad) + ")").c_str() : "");
        }

        // Забыть старое в агрегатах учётки: окна старше AuthHistoryDays, расход старше 24 ч.
        void HistTrim(AuthHist& h, int64_t un)
        {
            const int64_t cut = un - (int64_t)cfg.authHistoryDays * 86400;
            while (!h.windows.empty() && h.windows.front() < cut) h.windows.pop_front();
            while (!h.usage.empty() && h.usage.front().first < (un - 86400) / 60) h.usage.pop_front();
        }

        void HistSave(bool force)
        {
            const int64_t now = NowMs();
            if (!histTrusted || !histDirty || (!force && now - histSavedAt < 60000)) return;
            histSavedAt = now;
            const int64_t un = UnixNow(), cut = un - (int64_t)cfg.authHistoryDays * 86400;
            std::wstring tmp = cfg.authHistoryFile + L".tmp";
            FILE* f = _wfopen(tmp.c_str(), L"wb");
            if (!f) { LOGE("pol", "история аутентификации учёток: не записан %s", Utf8(tmp).c_str()); return; }
            fputs("#asda-auth-history v4\n", f);
            for (auto it = hist.begin(); it != hist.end();)
            {
                AuthHist& h = it->second;
                HistTrim(h, un);
                if (h.lastAuthUnix < cut && h.lastViolationUnix < cut) { it = hist.erase(it); continue; }
                fprintf(f, "%u %llu %llu %llu %llu %llu %d", it->first, (unsigned long long)h.lastAuthUnix, (unsigned long long)h.lastViolationUnix,
                        (unsigned long long)h.epStartUnix, (unsigned long long)(h.epDurMs / 1000), (unsigned long long)h.epLastUnix, (int)h.windows.size());
                for (int64_t w : h.windows) fprintf(f, " %llu", (unsigned long long)w);
                fprintf(f, " %d", (int)h.usage.size());
                for (auto& u : h.usage) fprintf(f, " %llu:%llu", (unsigned long long)u.first, (unsigned long long)u.second);
                fputc('\n', f);
                ++it;
            }
            // ★ Р66-5: ошибки записи, сброс на диск до переименования
            bool ok = fflush(f) == 0 && !ferror(f) && FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(f)));
            ok = (fclose(f) == 0) && ok;
            if (ok && MoveFileExW(tmp.c_str(), cfg.authHistoryFile.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) histDirty = false;
            else LOGE("pol", "история аутентификации учёток: не записан / не заменён %s (%lu)", Utf8(cfg.authHistoryFile).c_str(), GetLastError());
        }

        // Учётка прошла аутентификацию EAC — запомнить (на диск — с ближайшим сохранением).
        void HistAuth(uint32_t ui)
        {
            if (!ui) return;
            hist[ui].lastAuthUnix = UnixNow(); histDirty = true;
        }

        // ★ Р66-2: нарушение (ClientActionRequired / решение причины 2) — поблажки нет до новой чистой аутентификации и
        //   ConnectGraceAfterViolationDays суток после нарушения.
        void HistViolation(uint32_t ui)
        {
            if (!ui) return;
            AuthHist& h = hist[ui]; h.lastViolationUnix = UnixNow(); h.graceOn = false; histDirty = true;
        }

        // ★ Д3 ред. 3: поблажка «Epic Connect у клиента не проходит» для игровой сессии без EAC-сессии. true — решение отложить.
        //   Все условия: (1) аутентифицированная сессия учётки за AuthHistoryDays; (2) нарушений нет: последнее — раньше последней
        //   аутентификации и дальше ConnectGraceAfterViolationDays (Р66-2); (3) с LOGIN этой игровой сессии от учётки не было ни одной
        //   REG (отбитый REG / AuthTimeout = Connect работает, Р66-3); (4) клиенту AsdaId выдан токен не позже ConnectGraceTokenSec;
        //   (5) пределы Р66-1: эпизод ≤ ConnectGraceEpisodeSec, за скользящие 24 ч ≤ ConnectGraceSecPerDay, суток с поблажкой ≤
        //   ConnectGraceDaysPer30 за 30 суток. Кончилась — решение сразу (нового срока нет); ClientActionRequired идёт мимо (DecideAccount).
        bool ConnectGrace(const GameSess& gs, const Account* a, int64_t now)
        {
            if (cfg.connectGraceSecPerDay <= 0 || !histTrusted || !cfg.graceConfigError.empty()) return false;
            const uint32_t ui = gs.bindUi;
            auto hit = hist.find(ui);
            const int64_t un = UnixNow();
            if (hit == hist.end() || un - hit->second.lastAuthUnix > (int64_t)cfg.authHistoryDays * 86400) return false;
            AuthHist& h = hit->second;
            auto stop = [&](const char* why) {
                if (h.graceOn) { h.graceOn = false; LOGI("pol", "учётка %u: поблажка Connect снята — %s", ui, why);
                                 Ev(ui, "connect_grace_end", 0, "", std::string("поблажка «Epic Connect не проходит» снята: ") + why); }
                return false;
            };
            if (h.lastViolationUnix && (h.lastViolationUnix >= h.lastAuthUnix || un - h.lastViolationUnix < (int64_t)cfg.connectGraceAfterViolationDays * 86400))
                return stop("было нарушение EAC");
            if (a && ((a->lastRegAt && a->lastRegAt >= gs.loginAt) || (a->rejectAt && a->rejectAt >= gs.loginAt)))
                return stop("REG от учётки в этой игровой сессии был — Connect работает");
            auto tit = lastTokenMs.find(ui);
            if (tit == lastTokenMs.end() || now - tit->second > (int64_t)cfg.connectGraceTokenSec * 1000) return stop("клиент перестал получать токены");
            // ★ Р68-1 / Р68-2: эпизод — продолжение, если прошлый такт был не дольше ConnectGraceEpisodeGapSec назад; окна по 24 ч от начала
            //   эпизода, открывшего окно (окно ≠ календарные сутки: сбой 16–18.11 ~36 ч укладывается в 2 окна); расход — по минутам за 24 ч.
            HistTrim(h, un);
            const bool cont = h.epLastUnix && un - h.epLastUnix <= (int64_t)cfg.connectGraceEpisodeGapSec;
            int64_t used24 = 0; for (auto& u : h.usage) used24 += u.second;
            const bool inWindow = !h.windows.empty() && un < h.windows.back() + 86400;
            const char* deny = nullptr;
            if (cont && h.epDurMs >= (int64_t)cfg.connectGraceEpisodeSec * 1000) deny = "эпизод исчерпан";
            else if (used24 >= (int64_t)cfg.connectGraceSecPerDay * 1000) deny = "исчерпана за 24 ч";
            else if (!inWindow && (int)h.windows.size() >= cfg.connectGraceDaysPer30) deny = "окон поблажки по 24 ч за период уже предел";
            if (deny)
            {
                if (!h.graceDeniedLogged)
                {
                    h.graceDeniedLogged = true;
                    LOGW("pol", "учётка %u: поблажка Connect — %s (эпизод ≤ %d с, 24 ч ≤ %d с, окон по 24 ч ≤ %d за %d сут) — решения по сроку выносятся", ui, deny,
                         cfg.connectGraceEpisodeSec, cfg.connectGraceSecPerDay, cfg.connectGraceDaysPer30, cfg.authHistoryDays);
                    Ev(ui, "connect_grace_end", 0, "", std::string("поблажка «Epic Connect не проходит»: ") + deny);
                }
                h.graceOn = false;
                return false;
            }
            if (!cont) { h.epStartUnix = un; h.epDurMs = 0; h.graceSeenMs = 0; h.graceDeniedLogged = false; histDirty = true; }
            if (!inWindow) { h.windows.push_back(un); histDirty = true; }
            h.epLastUnix = un;
            if (h.graceSeenMs && now - h.graceSeenMs < 2000 && h.graceSeenMs != now)
            {
                const int64_t d = now - h.graceSeenMs, mi = un / 60;
                // ★ Р70-1 / Р70-2: минута расхода ≤ 60000 мс, эпизод ≤ ConnectGraceEpisodeSec (дрожание такта не выводит за предел)
                h.epDurMs = (std::min)(h.epDurMs + d, (int64_t)cfg.connectGraceEpisodeSec * 1000);
                if (!h.usage.empty() && h.usage.back().first == mi) h.usage.back().second = (std::min)((int64_t)60000, h.usage.back().second + d);
                else h.usage.push_back({ mi, (std::min)((int64_t)60000, d) });
                while (h.usage.size() > 1440) h.usage.pop_front();
                histDirty = true;
            }
            if (h.graceSeenMs != now) h.graceSeenMs = now;
            if (!h.graceOn)
            {
                h.graceOn = true;
                LOGW("pol", "учётка %u userNum %u: Epic Connect у клиента не проходит (токены AsdaId есть, REG в этой игровой сессии не было; "
                     "аутентифицирована %lld ч назад) — решение отложено; эпизод %lld с, за 24 ч %lld с, окон по 24 ч — %zu", gs.userIndex, gs.userNum,
                     (long long)((un - h.lastAuthUnix) / 3600), (long long)(h.epDurMs / 1000), (long long)(used24 / 1000), h.windows.size());
                Ev(ui, "connect_grace", 0, "", "Epic Connect у клиента не проходит: токены AsdaId есть, REG нет — решение отложено (поблажка учётки)");
            }
            return true;
        }
        bool idDegradedWas = false;                            // для журнала смены состояния AsdaId

        // ★ А6.8 (ревизия 61 Н-1): замер такта ядра — работа одного прохода цикла (без ожидания в WSAPoll) и построения снимка, мкс.
        int64_t passMaxCurUs = 0, passMaxPrevUs = 0, passWinFrom = 0;   // максимум прохода за текущее и прошлое окно 10 с
        int64_t snapLastUs = 0, snapMaxUs = 0;                 // последний и наибольший снимок для точки статуса
        long long snapBuilds = 0;                              // сколько снимков построено
        static int64_t NowUs()
        {
            static LARGE_INTEGER f = [] { LARGE_INTEGER x; QueryPerformanceFrequency(&x); return x; }();
            LARGE_INTEGER c; QueryPerformanceCounter(&c);
            return (int64_t)(c.QuadPart * 1000000 / f.QuadPart);
        }

        // ★ А6.8 (22.11.2026): точка статуса для панели (AdminStatus.h). board == nullptr — ничего из этого не ведётся.
        AdminStatus::Board* board = nullptr;                   // доска снимков (нить точки просит, ядро публикует)
        struct EvRec { int64_t ms = 0; const char* kind = ""; int reason = 0; const char* eos = ""; std::string text; };   // событие учётки (без IP)
        struct EvList { std::deque<EvRec> q; int64_t lastMs = 0; };   // история учётки и время последнего события
        std::unordered_map<uint32_t, EvList> evs;              // UserIndex → история (≤ EventsPerAccount, ≤ MaxAccounts учёток)

        // ★ А6.8: записать событие учётки в историю точки статуса (только при board; текст — без IP и секретов).
        void Ev(uint32_t ui, const char* kind, int reason, const char* eosText, const std::string& text)
        {
            if (!board || !ui) return;
            const int64_t now = NowMs();
            auto it = evs.find(ui);
            if (it == evs.end())
            {
                if ((int)evs.size() >= cfg.statusMaxAccounts)
                {
                    auto old = evs.begin();
                    for (auto j = evs.begin(); j != evs.end(); ++j) if (j->second.lastMs < old->second.lastMs) old = j;
                    evs.erase(old);
                }
                it = evs.emplace(ui, EvList()).first;
            }
            EvRec r; r.ms = now; r.kind = kind; r.reason = reason; r.eos = eosText ? eosText : "";
            size_t n = (std::min)(text.size(), (size_t)300);
            while (n < text.size() && n > 0 && ((unsigned char)text[n] & 0xC0) == 0x80) --n;   // не резать знак UTF-8 посередине
            r.text.assign(text, 0, n);
            it->second.q.push_back(std::move(r)); it->second.lastMs = now;
            while ((int)it->second.q.size() > cfg.statusEventsPerAccount) it->second.q.pop_front();
        }

        // ── общие ─────────────────────────────────────────────────────────────────────────
        // Почему сейчас FailOpen (nullptr — не FailOpen).
        const char* FailOpenWhy(int64_t now) const
        {
            if (!cfg.failOpen) return nullptr;
            if (!eos->SessionStarted()) return "нет сессии AntiCheatServer (BeginSession не было или не удалась)";
            if (now - startMs < (int64_t)cfg.failOpenStartupSec * 1000) return "окно после старта";
            if (epicDownUntil > now) return "Epic недоступен";
            if (GetHealth().idDegradedUntil.load() > now) return "AsdaId деградировал (доля 503)";
            return nullptr;
        }
        bool FailOpenNow(int64_t now) const { return FailOpenWhy(now) != nullptr; }

        // Можно ли применять наказание (кик) к учётке сейчас. why — почему нельзя.
        bool Punish(uint32_t userIndex, int64_t now, std::string& why) const
        {
            if (cfg.mode == 0) { why = "Mode=0"; return false; }
            if (cfg.mode == 1) { why = "Mode=1 (журнал)"; return false; }
            if (cfg.IsOperator(userIndex)) { why = "оператор (только журнал)"; return false; }
            if (const char* fo = FailOpenWhy(now)) { why = std::string("FailOpen: ") + fo; return false; }
            why.clear(); return true;
        }

        void MarkEpicDown(const std::string& what)
        {
            int64_t until = NowMs() + (int64_t)cfg.epicDownHoldSec * 1000;
            if (until > epicDownUntil)
            {
                if (epicDownUntil <= NowMs()) LOGW("pol", "Epic недоступен (%s) — FailOpen на %d с", what.c_str(), cfg.epicDownHoldSec);
                epicDownUntil = until;
            }
        }

        // ред. 3 §8.3: учесть ответ VerifyIdToken (или его отсутствие) и проверить порог «Epic недоступен».
        void NoteVerify(uint32_t ip, bool transient, int64_t now)
        {
            verifyWin.push_back({ now, ip, transient });
            while (verifyWin.size() > kVerifyWinMax) verifyWin.pop_front();
            int64_t win = (int64_t)cfg.epicDownWindowSec * 1000;
            while (!verifyWin.empty() && now - verifyWin.front().t > win) verifyWin.pop_front();
            if (!transient) return;
            size_t total = verifyWin.size(), tr = 0;
            std::set<uint32_t> ips;
            for (const VerifyEv& e : verifyWin) if (e.transient) { ++tr; ips.insert(e.ip); }
            if ((int)ips.size() >= cfg.epicDownMinIps && tr * 100 >= (size_t)cfg.epicDownRatioPct * total)
                MarkEpicDown("временных отказов VerifyIdToken " + std::to_string(tr) + " из " + std::to_string(total) + " от " +
                             std::to_string(ips.size()) + " IP за " + std::to_string(cfg.epicDownWindowSec) + " с");
        }

        // Учётка по PUID, подтверждённому Epic раньше (0 — неизвестен).
        uint32_t AccountByPuid(const std::string& puid) const
        {
            if (puid.empty()) return 0;
            for (auto& kv : accounts) if (kv.second.puid == puid) return kv.first;
            return 0;
        }

        // §8.6 (R3-04): у процесса игровой сессии P61 не активен (≥ 5 LOGIN за 120 с после HELLO, все с нулевым bind).
        bool P61Inactive(const GameSess& gs) const
        {
            auto it = procBind.find(ProcKey(gs.kind, gs.pid));
            return it != procBind.end() && it->second.inactive;
        }

        // §8.6 (R3-04): начать окно наблюдения bind процесса на HELLO (если вывода о P61 ещё нет).
        void ProbeOnHello(uint8_t kind, uint32_t pid, int64_t now)
        {
            ProcBind& pb = procBind[ProcKey(kind, pid)];
            if (pb.active || pb.inactive) return;
            pb.windowFrom = now; pb.zero = 0; pb.windowLogged = false;
        }

        // §8.6 (R3-04): учесть bind очередного LOGIN процесса.
        void ProbeOnLogin(uint8_t kind, uint32_t pid, bool zero, int64_t now)
        {
            ProcBind& pb = procBind[ProcKey(kind, pid)];
            const char* kn = kind == 2 ? "GameServer" : "Indun";
            if (!zero)
            {
                if (pb.inactive)
                    LOGW("pol", "%s pid %u: LOGIN с ненулевым bind — P61 у процесса активен, причина 6 к его сессиям снова применяется", kn, pid);
                pb.inactive = false; pb.active = true; pb.windowFrom = 0;
                return;
            }
            if (pb.active || pb.inactive || pb.windowFrom == 0 || now - pb.windowFrom > kP61ProbeMs) return;
            if (++pb.zero < kP61ProbeMin) return;
            pb.inactive = true;
            LOGW("pol", "P61 у процесса не активен: %s pid %u — за %lld с после HELLO пришло %d LOGIN, все с нулевым bind; причина 6 к сессиям "
                 "этого процесса не применяется (причина 1 работает). Порядок развёртывания: P61 Enabled=1 раньше Mode 2", kn, pid,
                 (long long)((now - pb.windowFrom) / 1000), pb.zero);
        }

        // ── сайдкар: счёт незарегистрированных по IP ──────────────────────────────────────
        void Pending(SideConn& c, bool on)
        {
            if (c.pendingCounted == on) return;
            c.pendingCounted = on;
            int& n = pendingPerIp[c.ipv4];
            n += on ? 1 : -1;
            if (n <= 0) pendingPerIp.erase(c.ipv4);
        }

        // ── сайдкар: отправка ─────────────────────────────────────────────────────────────
        void SideSend(SideConn& c, uint8_t type, const std::vector<uint8_t>& payload)
        {
            if (c.dead) return;
            std::vector<uint8_t> f = MakeFrame(type, payload), toSock;
            AsdaSecure::Err e = c.ch.OnSend(f.data(), f.size(), toSock);
            if (e != AsdaSecure::Err::Ok) { SideKill(c, std::string("шифрование: ") + AsdaSecure::ErrName(e)); return; }
            c.out.insert(c.out.end(), toSock.begin(), toSock.end());
            if (c.out.size() > kMaxOut) SideKill(c, "переполнение исходящего (клиент не читает)");
        }

        void SideRegResult(SideConn& c, uint8_t status) { SideSend(c, kSideRegResult, { status }); }

        void SideKick(SideConn& c, uint8_t ours, uint8_t eosReason, const std::string& details)
        {
            std::vector<uint8_t> p; p.push_back(ours); p.push_back(eosReason);
            std::string d = details.size() > 256 ? details.substr(0, 256) : details;
            PutU16(p, (uint16_t)d.size()); p.insert(p.end(), d.begin(), d.end());
            SideSend(c, kSideKick, p);
        }

        // Отправить остаток и закрыть (ограничено kCloseFlushMs).
        void SideCloseAfterFlush(SideConn& c, const std::string& why)
        {
            if (c.dead || c.st == SideState::Closing) return;
            SideDetach(c, why);
            Pending(c, false);
            c.st = SideState::Closing; c.closeAt = NowMs() + kCloseFlushMs; c.closeWhy = why;
            // приём не закрываем (shutdown SD_RECEIVE дал бы RST на входящий PING и потерю KICK/REG_RESULT)
        }

        // Немедленный разрыв.
        void SideKill(SideConn& c, const std::string& why)
        {
            if (c.dead) return;
            SideDetach(c, why);
            Pending(c, false);
            c.dead = true; if (c.closeWhy.empty()) c.closeWhy = why;
        }

        // Снять соединение с EOS и с учётки (идемпотентно). why — причина закрытия (★ А6.8: в историю учётки).
        void SideDetach(SideConn& c, const std::string& why = std::string())
        {
            if (c.verifyReq) { verifyReqs.erase(c.verifyReq); c.verifyReq = 0; }
            if (c.eosRegistered) { eos->UnregisterClient(c.id); c.eosRegistered = false; }
            if (c.userIndex)
            {
                auto it = accounts.find(c.userIndex);
                if (it != accounts.end() && it->second.eacConn == c.id)
                {
                    it->second.eacConn = 0;
                    if (c.authenticated) { it->second.lastAuthAt = NowMs(); it->second.lastAuthIp = c.ipv4; }   // ★ Д2
                    LOGI("pol", "учётка %u: EAC-сессия потеряна (соединение %llu %s%s)", c.userIndex, (unsigned long long)c.id, c.ip.c_str(),
                         c.authenticated ? "" : ", не была аутентифицирована");
                    Ev(c.userIndex, "eac_lost", 0, "", "EAC-сессия потеряна (соединение " + std::to_string(c.id) + (c.authenticated ? "" : ", не была аутентифицирована") +
                       (why.empty() ? std::string() : "): " + why) + (why.empty() ? ")" : ""));
                }
            }
        }

        // ── сайдкар: приём (E1-04) ────────────────────────────────────────────────────────
        void NoteReject(long long RejectStats::* field, uint32_t ip)
        {
            ++(rej.*field);
            if (rej.byIp.size() < 4096 || rej.byIp.count(ip)) ++rej.byIp[ip];
        }

        void SideAccept(int64_t now)
        {
            for (int i = 0; i < cfg.acceptPerPass; ++i)
            {
                sockaddr_in sa{}; int sl = sizeof(sa);
                SOCKET s = accept(sideListen, (sockaddr*)&sa, &sl);
                if (s == INVALID_SOCKET) break;
                uint32_t ip = sa.sin_addr.s_addr;
                // Отказы — без строки журнала на каждый (сводка раз в RejectSummarySec).
                if (!globalBucket.Take(now, cfg.connectRateGlobal, cfg.connectBurstGlobal)) { NoteReject(&RejectStats::global, ip); closesocket(s); continue; }
                if (!ipBuckets[ip].Take(now, cfg.connectRatePerIp, cfg.connectBurstPerIp)) { NoteReject(&RejectStats::rate, ip); closesocket(s); continue; }
                auto pit = pendingPerIp.find(ip);
                if (pit != pendingPerIp.end() && pit->second >= cfg.maxUnregPerIp) { NoteReject(&RejectStats::unreg, ip); closesocket(s); continue; }
                if ((int)LiveSides() >= cfg.maxConnections)
                {
                    SideConn* oldest = nullptr;
                    for (auto& kv : sides)
                    {
                        SideConn& c = *kv.second;
                        if (c.dead || !c.pendingCounted) continue;
                        if (!oldest || c.acceptedAt < oldest->acceptedAt) oldest = &c;
                    }
                    if (!oldest) { NoteReject(&RejectStats::full, ip); closesocket(s); continue; }
                    LOGD("side", "предел соединений %d: вытеснено старейшее незарегистрированное %llu %s", cfg.maxConnections,
                         (unsigned long long)oldest->id, oldest->ip.c_str());
                    ++rej.full;
                    SideKill(*oldest, "вытеснено при переполнении");
                }
                u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
                BOOL nd = TRUE; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
                std::unique_ptr<SideConn> c(new SideConn());
                c->id = nextId++; c->s = s; c->ipv4 = ip; c->ip = Ipv4Text(ip);
                c->acceptedAt = now;
                c->ch.SetAllowLegacy(false);                         // только AsdaSecure
                c->ch.SetIdentity(AsdaSecure::SubServer::Eac, key);  // SubServer::Eac = 4
                c->ch.Reset();
                Pending(*c, true);
                LOGD("side", "соединение %llu от %s", (unsigned long long)c->id, c->ip.c_str());
                sides[c->id] = std::move(c);
            }
        }

        // Сводка отказов приёма (раз в RejectSummarySec, только если были).
        void RejectSummary(int64_t now, bool force)
        {
            if (!force && now - lastRejectSummary < (int64_t)cfg.rejectSummarySec * 1000) return;
            lastRejectSummary = now;
            long long total = rej.rate + rej.global + rej.unreg + rej.full + rej.regIp;
            if (total == 0) return;
            std::vector<std::pair<long long, uint32_t>> top;
            for (auto& kv : rej.byIp) top.emplace_back(kv.second, kv.first);
            std::sort(top.begin(), top.end(), [](auto& a, auto& b) { return a.first > b.first; });
            std::string t;
            for (size_t i = 0; i < top.size() && i < 3; ++i) t += (i ? ", " : "") + Ipv4Text(top[i].second) + " ×" + std::to_string(top[i].first);
            LOGW("side", "отказы приёма за %d с: всего %lld (частота с IP %lld, общая частота %lld, незарегистрированных с IP %lld, "
                 "переполнение %lld, REG с IP %lld); IP: %zu, чаще всех: %s", cfg.rejectSummarySec, total, rej.rate, rej.global, rej.unreg,
                 rej.full, rej.regIp, rej.byIp.size(), t.c_str());
            rej = RejectStats();
        }

        size_t LiveSides() const
        {
            size_t n = 0;
            for (auto& kv : sides) if (!kv.second->dead) ++n;
            return n;
        }

        void SideRead(SideConn& c)
        {
            uint8_t buf[16384];
            for (int round = 0; round < 8 && !c.dead; ++round)
            {
                int n = recv(c.s, (char*)buf, sizeof(buf), 0);
                if (n == 0) { SideKill(c, "клиент закрыл соединение"); return; }
                if (n < 0)
                {
                    int e = WSAGetLastError();
                    if (e == WSAEWOULDBLOCK) return;
                    SideKill(c, "ошибка приёма " + std::to_string(e)); return;
                }
                if (c.st == SideState::Closing) continue;   // после решения закрыть входящее не обрабатываем
                std::vector<uint8_t> toParser, toSock;
                AsdaSecure::Err e = c.ch.OnRecv(buf, (size_t)n, toParser, toSock);
                if (!toSock.empty()) c.out.insert(c.out.end(), toSock.begin(), toSock.end());
                if (e != AsdaSecure::Err::Ok) { SideKill(c, std::string("AsdaSecure: ") + AsdaSecure::ErrName(e)); return; }
                if (c.st == SideState::Handshake && c.ch.IsReady())
                {
                    c.st = SideState::WaitReg; c.readyAt = c.lastPing = NowMs();
                    LOGD("side", "%llu %s: рукопожатие AsdaSecure завершено", (unsigned long long)c.id, c.ip.c_str());
                }
                if (!toParser.empty())
                {
                    c.in.insert(c.in.end(), toParser.begin(), toParser.end());
                    SideParse(c);
                }
            }
        }

        void SideParse(SideConn& c)
        {
            size_t off = 0;
            while (!c.dead && c.st != SideState::Closing && c.in.size() - off >= 2)
            {
                uint16_t len = GetU16(c.in.data() + off);
                if (len == 0 || len > kMaxFrameLen) { SideKill(c, "кадр: длина " + std::to_string(len)); break; }
                if (c.in.size() - off < 2u + len) break;
                uint8_t type = c.in[off + 2];
                const uint8_t* p = c.in.data() + off + 3;
                size_t pl = (size_t)len - 1;
                off += 2u + len;
                SideFrame(c, type, p, pl);
            }
            if (off) c.in.erase(c.in.begin(), c.in.begin() + (ptrdiff_t)(std::min)(off, c.in.size()));
        }

        void SideFrame(SideConn& c, uint8_t type, const uint8_t* p, size_t n)
        {
            int64_t now = NowMs();
            switch (type)
            {
            case kSidePing:
                if (n != 0) { SideKill(c, "PING с данными"); return; }
                c.lastPing = now;
                SideSend(c, kSidePong, {});
                return;
            case kSideReg:
                SideReg(c, p, n);
                return;
            case kSideBind:
                SideBind(c, p, n, now);
                return;
            case kSideAcMsg:
                if (n < 1 || n > kMaxAcMsg) { SideKill(c, "ACMSG: длина " + std::to_string(n)); return; }
                if (c.st == SideState::Registered)
                {
                    eos->ReceiveFromClient(c.id, p, (uint32_t)n);
                    return;
                }
                if (c.st == SideState::Verifying)
                {
                    if ((int)c.pendingAc.size() >= cfg.maxQueuedAcMsg) { SideKill(c, "ACMSG: очередь до регистрации переполнена"); return; }
                    c.pendingAc.emplace_back(p, p + n);
                    return;
                }
                SideKill(c, "ACMSG до REG");
                return;
            default:
                SideKill(c, "неизвестный тип кадра 0x" + Crypto::Hex(&type, 1));
                return;
            }
        }

        // ред. 3 §8.1: BIND — u8 serverKind · u8[32] bind игрового соединения.
        void SideBind(SideConn& c, const uint8_t* p, size_t n, int64_t now)
        {
            if (n != 1 + kBindLen || (p[0] != 2 && p[0] != 3)) { SideKill(c, "BIND негоден (длина " + std::to_string(n) + ")"); return; }
            while (!c.bindTimes.empty() && now - c.bindTimes.front() > 60000) c.bindTimes.pop_front();
            if ((int)c.bindTimes.size() >= kBindPerMinMax) { SideKill(c, "BIND: больше " + std::to_string(kBindPerMinMax) + " в минуту"); return; }
            c.bindTimes.push_back(now);
            if (c.st != SideState::Registered)
            {
                // Контракт: 2 — нет аутентифицированной сессии. До REG_RESULT 0 BIND не принимается (клиент шлёт его после REG_RESULT 0).
                LOGI("side", "%llu %s: BIND в состоянии «%s» → BIND_RESULT 2", (unsigned long long)c.id, c.ip.c_str(), SideStateText(c.st));
                SideSend(c, kSideBindResult, { kBindRejected });
                return;
            }
            BindEntry e; e.kind = p[0]; memcpy(e.b, p + 1, kBindLen); e.at = now;
            bool zero = BindIsZero(e.b);
            // Повтор того же значения — обновить время, не плодить записи.
            bool dup = false;
            for (BindEntry& x : c.binds) if (memcmp(x.b, e.b, kBindLen) == 0) { x.at = now; dup = true; }
            if (!dup && !zero)
            {
                c.binds.push_back(e);
                while ((int)c.binds.size() > cfg.maxBindsPerSession) c.binds.pop_front();
            }
            LOGI("side", "%llu %s: учётка %u BIND %s bind=%s…%s%s → BIND_RESULT 0", (unsigned long long)c.id, c.ip.c_str(), c.userIndex,
                 e.kind == 2 ? "Game" : "Indun", BindTag(e.b).c_str(), zero ? " (НУЛЕВОЙ — не сопоставляется)" : "", dup ? " (повтор)" : "");
            SideSend(c, kSideBindResult, { kBindOk });
        }

        void SideReg(SideConn& c, const uint8_t* p, size_t n)
        {
            if (c.st != SideState::WaitReg) { SideKill(c, std::string("REG в состоянии «") + SideStateText(c.st) + "»"); return; }
            // u8 ver · u8 platform · u16 n + PUID · u16 n + IdToken
            if (n < 6) { SideKill(c, "REG: короткий"); return; }
            uint8_t ver = p[0], platform = p[1];
            size_t o = 2;
            uint16_t pn = GetU16(p + o); o += 2;
            if (o + pn + 2 > n) { SideKill(c, "REG: PUID за пределами кадра"); return; }
            std::string puid((const char*)p + o, pn); o += pn;
            uint16_t tn = GetU16(p + o); o += 2;
            if (o + tn != n) { SideKill(c, "REG: длина токена не сходится с кадром"); return; }
            std::string token((const char*)p + o, tn);
            c.platform = platform;
            if (cfg.mode == 0)
            {
                LOGI("side", "%llu %s: REG при Mode=0 → REG_RESULT 4", (unsigned long long)c.id, c.ip.c_str());
                SideRegResult(c, kRegDisabled); SideCloseAfterFlush(c, "Mode=0"); return;
            }
            // ред. 3 §8.3: не больше RegPerIpPerMin REG с одного IP в минуту (до EOS — не тратить лимиты Epic).
            int64_t now = NowMs();
            auto& dq = regPerIp[c.ipv4];
            while (!dq.empty() && now - dq.front() > 60000) dq.pop_front();
            if ((int)dq.size() >= cfg.regPerIpPerMin)
            {
                ++statRegFail; NoteReject(&RejectStats::regIp, c.ipv4);
                LOGD("side", "%llu %s: REG сверх %d/мин с IP → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str(), cfg.regPerIpPerMin);
                SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "REG: предел с IP"); return;
            }
            dq.push_back(now);
            if (ver != 1 || pn == 0 || pn > kMaxPuid || !IsPuid(puid) || !Jwt::LooksLikeJwt(token, kMaxToken))
            {
                ++statRegFail;
                LOGI("side", "%llu %s: REG отклонён до EOS (ver=%u, PUID/токен негодны) → REG_RESULT 1", (unsigned long long)c.id, c.ip.c_str(), ver);
                SideRegResult(c, kRegBadToken); SideCloseAfterFlush(c, "REG: формат"); return;
            }
            c.puid = puid;
            if (!eos->SessionStarted())
            {
                ++statRegFail;
                LOGW("side", "%llu %s: REG, но сессии AntiCheatServer нет (%s) → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str(), eos->Name());
                SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "EOS не готов"); return;
            }
            uint64_t req = nextId++;
            if (!eos->VerifyIdToken(req, puid, token))
            {
                ++statRegFail;
                LOGW("side", "%llu %s: VerifyIdToken не принят → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str());
                SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "VerifyIdToken не принят"); return;
            }
            c.verifyReq = req; verifyReqs[req] = c.id;
            c.st = SideState::Verifying; c.verifyAt = now;   // Verifying остаётся в счёте незарегистрированных на IP (ред. 3 §8.3)
            LOGI("side", "%llu %s: REG puid=%s platform=%u → VerifyIdToken", (unsigned long long)c.id, c.ip.c_str(), puid.c_str(), platform);
        }

        // ── EOS → ядро ────────────────────────────────────────────────────────────────────
        SideConn* SideById(uint64_t id)
        {
            auto it = sides.find(id);
            return (it == sides.end() || it->second->dead) ? nullptr : it->second.get();
        }

        void OnEosVerifyDone(uint64_t reqId, const VerifyResult& r) override
        {
            auto it = verifyReqs.find(reqId);
            if (it == verifyReqs.end()) { LOGD("side", "VerifyIdToken req=%llu: соединение уже закрыто", (unsigned long long)reqId); return; }
            uint64_t cid = it->second; verifyReqs.erase(it);
            SideConn* cp = SideById(cid);
            if (!cp || cp->st != SideState::Verifying) return;
            SideConn& c = *cp;
            c.verifyReq = 0;
            int64_t now = NowMs();
            NoteVerify(c.ipv4, r.eosResult != 0 && r.transient, now);
            if (r.eosResult != 0)
            {
                ++statRegFail;
                if (r.transient)
                {
                    // ред. 3 §8.3: одиночный временный отказ НЕ включает глобальный FailOpen — только порог по доле и IP (NoteVerify).
                    // §8.6 (R3-03): освобождения отдельной учётки нет — PUID неподтверждённой REG ничего не даёт.
                    LOGW("side", "%llu %s: VerifyIdToken %s (временный сбой) → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str(), r.eosResultText.c_str());
                    SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "VerifyIdToken: " + r.eosResultText);
                }
                else
                {
                    LOGI("side", "%llu %s: VerifyIdToken %s → REG_RESULT 1", (unsigned long long)c.id, c.ip.c_str(), r.eosResultText.c_str());
                    SideRegResult(c, kRegBadToken); SideCloseAfterFlush(c, "VerifyIdToken: " + r.eosResultText);
                }
                return;
            }
            uint32_t ui = 0;
            if (!r.accountInfo || r.accountType != 8 /*EOS_EAT_OPENID*/ || !ParseUserIndex(r.accountId, ui))
            {
                ++statRegFail;
                LOGW("side", "%llu %s: токен без учётки OpenID (info=%d type=%d accountId='%s') → REG_RESULT 2", (unsigned long long)c.id, c.ip.c_str(),
                     (int)r.accountInfo, r.accountType, r.accountId.c_str());
                SideRegResult(c, kRegAccount); SideCloseAfterFlush(c, "учётка не найдена"); return;
            }
            Account& a = accounts[ui];
            a.lastRegAt = now;   // ★ Р66-3: REG учётки дошёл до проверки токена — Connect у клиента работает
            if (r.puid != c.puid || c.platform != 1 /*EOS_ACCCP_Windows*/)
            {
                ++statRegFail;
                a.rejectAt = now;   // решение по игровым сессиям — политикой в свой срок (причина 4), без немедленного кика
                LOGW("side", "%llu %s: учётка %u: %s → REG_RESULT 1", (unsigned long long)c.id, c.ip.c_str(), ui,
                     r.puid != c.puid ? "PUID ответа не совпал с REG" : "платформа не Windows");
                Ev(ui, "reg_reject", kReasonRegRejected, "", std::string("регистрация EAC отклонена: ") + (r.puid != c.puid ? "PUID ответа не совпал с REG" : "платформа не Windows"));
                SideRegResult(c, kRegBadToken);
                SideCloseAfterFlush(c, "регистрация отклонена");
                return;
            }
            // ред. 3 §8.2 / §8.6 (R3-01): REG одной учётки — не чаще RegPerAccountMax за RegPerAccountWindowSec; лишние — REG_RESULT 3,
            // прежняя сессия остаётся. REG, вытесняющая Authenticated-сессию той же учётки с того же IP 15901 (переподключение честного
            // клиента), в лимит не считается: карусель E1-01 так не построить — каждая вытесняемая сессия обязана пройти RemoteAuthComplete.
            int64_t win = (int64_t)cfg.regPerAccountWindowSec * 1000;
            while (!a.regTimes.empty() && now - a.regTimes.front() > win) a.regTimes.pop_front();
            const SideConn* prev = (a.eacConn && a.eacConn != c.id) ? SideById(a.eacConn) : nullptr;
            const bool freeReg = prev && prev->st == SideState::Registered && prev->authenticated && prev->ipv4 == c.ipv4;
            // ★ Д2: честный перезапуск после падения — прежней сессии уже нет, но недавно была аутентифицированная с того же IP.
            //   Карусель E1-01 так не построить: lastAuthAt обновляет только сессия, дошедшая до RemoteAuthComplete.
            const bool recentAuth = !freeReg && cfg.regFreeAfterAuthSec > 0 && a.lastAuthAt && a.lastAuthIp == c.ipv4 &&
                                    now - a.lastAuthAt <= (int64_t)cfg.regFreeAfterAuthSec * 1000;
            if (freeReg)
                LOGI("side", "%llu %s: учётка %u: REG вытесняет аутентифицированную EAC-сессию %llu с того же IP — в лимит REG не считается",
                     (unsigned long long)c.id, c.ip.c_str(), ui, (unsigned long long)prev->id);
            else if (recentAuth)
                LOGI("side", "%llu %s: учётка %u: REG после аутентифицированной EAC-сессии с того же IP %lld с назад — в лимит REG не считается (Д2)",
                     (unsigned long long)c.id, c.ip.c_str(), ui, (long long)((now - a.lastAuthAt) / 1000));
            else
            {
                if (!recentAuth && (int)a.regTimes.size() >= cfg.regPerAccountMax)
                {
                    ++statRegFail;
                    a.regLimitedAt = now; a.regLimitedIp = c.ipv4;   // ★ Д2: решение по игровой сессии подождёт (Policy)
                    LOGW("side", "%llu %s: учётка %u: REG сверх %d за %d с → REG_RESULT 3 (прежняя EAC-сессия не тронута)", (unsigned long long)c.id,
                         c.ip.c_str(), ui, cfg.regPerAccountMax, cfg.regPerAccountWindowSec);
                    Ev(ui, "reg_limit", 0, "", "REG сверх " + std::to_string(cfg.regPerAccountMax) + " за " + std::to_string(cfg.regPerAccountWindowSec) +
                       " с — отказ (прежняя EAC-сессия не тронута)");
                    SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "REG: предел на учётку");
                    return;
                }
                if (!recentAuth) a.regTimes.push_back(now);
            }
            c.userIndex = ui;
            // Вытеснение прежней EAC-сессии той же учётки (§3; ред. 3 §8.4: в Mode 1 — без KICK, только закрыть канал).
            // Отсчёт игровых сессий НЕ сбрасывается и не продлевается: они защищены только Authenticated + BIND новой сессии.
            if (a.eacConn && a.eacConn != c.id)
            {
                SideConn* old = SideById(a.eacConn);
                a.eacConn = 0;
                if (old)
                {
                    ++statEvict;
                    Ev(ui, "evicted", kReasonEvicted, "", "новая EAC-сессия " + std::to_string(c.id) + " вытесняет " + std::to_string(old->id) +
                       (cfg.mode == 2 ? " (KICK 5)" : " (Mode=" + std::to_string(cfg.mode) + " — без KICK, канал закрыт)"));
                    // ★ Р64-3: вытесняемая аутентифицированная сессия — тоже «недавняя аутентификация» (SideDetach её уже не увидит)
                    if (old->authenticated) { a.lastAuthAt = now; a.lastAuthIp = old->ipv4; }
                    old->userIndex = 0;
                    if (cfg.mode == 2)
                    {
                        LOGI("side", "учётка %u: новая EAC-сессия %llu %s вытесняет %llu %s (KICK 5)", ui, (unsigned long long)c.id, c.ip.c_str(),
                             (unsigned long long)old->id, old->ip.c_str());
                        SideKick(*old, kReasonEvicted, 0, "вытеснен новой EAC-сессией учётки");
                    }
                    else
                        LOGI("side", "учётка %u: новая EAC-сессия %llu %s вытесняет %llu %s (Mode=%d — без KICK, канал закрыт)", ui, (unsigned long long)c.id,
                             c.ip.c_str(), (unsigned long long)old->id, old->ip.c_str(), cfg.mode);
                    SideCloseAfterFlush(*old, "вытеснен");
                }
            }
            std::string err;
            if (!eos->RegisterClient(c.id, c.puid, c.platform, c.ip, &err))
            {
                ++statRegFail;
                LOGE("side", "%llu %s: учётка %u: RegisterClient: %s → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str(), ui, err.c_str());
                Ev(ui, "reg_error", 0, "", "RegisterClient: " + err);
                c.userIndex = 0;
                SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "RegisterClient: " + err);
                return;
            }
            ++statRegOk;
            c.eosRegistered = true;
            c.st = SideState::Registered;
            c.registeredAt = now;
            Pending(c, false);
            a.eacConn = c.id; a.puid = c.puid;
            Ev(ui, "reg_ok", 0, "", "EAC-сессия зарегистрирована (соединение " + std::to_string(c.id) + "); ждём RemoteAuthComplete и BIND");
            LOGI("side", "%llu %s: учётка %u зарегистрирована в EAC (puid=%s, %s); ждём RemoteAuthComplete ≤ %d с и BIND", (unsigned long long)c.id,
                 c.ip.c_str(), ui, c.puid.c_str(), r.platform.c_str(), cfg.authTimeoutSec);
            SideRegResult(c, kRegOk);
            while (!c.pendingAc.empty() && !c.dead)
            {
                eos->ReceiveFromClient(c.id, c.pendingAc.front().data(), (uint32_t)c.pendingAc.front().size());
                c.pendingAc.pop_front();
            }
        }

        void OnEosMessageToClient(uint64_t handle, const uint8_t* data, uint32_t len) override
        {
            SideConn* c = SideById(handle);
            if (!c || c->st != SideState::Registered) return;
            if (len < 1 || len > kMaxAcMsg) { LOGW("side", "%llu: EOS сообщение длиной %u — пропущено", (unsigned long long)handle, len); return; }
            SideSend(*c, kSideAcMsg, std::vector<uint8_t>(data, data + len));
        }

        void OnEosActionRequired(uint64_t handle, int action, int reason, const std::string& details) override
        {
            SideConn* c = SideById(handle);
            if (!c) { LOGW("pol", "ClientActionRequired для закрытого соединения %llu: %s (%s)", (unsigned long long)handle, EosReasonText(reason), details.c_str()); return; }
            uint32_t ui = c->userIndex;
            int64_t now = NowMs();
            LOGW("pol", "учётка %u (%llu %s): ClientActionRequired action=%d reason=%s «%s»", ui, (unsigned long long)handle, c->ip.c_str(), action,
                 EosReasonText(reason), details.c_str());
            Ev(ui, "violation", kReasonEacAction, EosReasonText(reason), "ClientActionRequired action=" + std::to_string(action) + (details.empty() ? "" : ": " + details));
            HistViolation(ui);   // ★ Р66-2: после нарушения поблажки Connect нет
            std::string why;
            if (Punish(ui, now, why))
            {
                SideKick(*c, kReasonEacAction, (uint8_t)reason, details);
                SideCloseAfterFlush(*c, std::string("ClientActionRequired: ") + EosReasonText(reason));
            }
            else LOGI("pol", "учётка %u: отключение клиента EAC не выполнено — %s", ui, why.c_str());
            if (ui) DecideAccount(ui, kReasonEacAction, (uint8_t)reason, now, "ClientActionRequired");
        }

        void OnEosAuthStatus(uint64_t handle, int status) override
        {
            SideConn* c = SideById(handle);
            const char* name = status == 1 ? "LocalAuthComplete" : status == 2 ? "RemoteAuthComplete" : "Invalid";
            if (!c) { LOGD("side", "%llu: ClientAuthStatus=%s для закрытого соединения", (unsigned long long)handle, name); return; }
            c->authStatus = status;
            // ред. 3 §8.2: Authenticated — только RemoteAuthComplete (RegisterClient и LocalAuthComplete недостаточно).
            if (status == 2 && !c->authenticated)
            {
                c->authenticated = true;
                if (c->userIndex) { Account& aa = accounts[c->userIndex]; aa.lastAuthAt = NowMs(); aa.lastAuthIp = c->ipv4; HistAuth(c->userIndex); }   // ★ Д2, Д3 ред. 2
                LOGI("side", "%llu %s: учётка %u — RemoteAuthComplete через %lld мс после RegisterClient: EAC-сессия аутентифицирована",
                     (unsigned long long)handle, c->ip.c_str(), c->userIndex, (long long)(NowMs() - c->registeredAt));
                Ev(c->userIndex, "auth", 0, "", "RemoteAuthComplete через " + std::to_string(NowMs() - c->registeredAt) + " мс: EAC-сессия аутентифицирована");
            }
            else LOGI("side", "%llu: ClientAuthStatus=%s (учётка %u)", (unsigned long long)handle, name, c->userIndex);
        }

        // ── политика ──────────────────────────────────────────────────────────────────────
        BridgeConn* BridgeFor(uint8_t kind, uint32_t pid)
        {
            for (auto& kv : bridges)
            {
                BridgeConn& b = *kv.second;
                if (!b.dead && b.hello && b.kind == kind && b.pid == pid) return &b;
            }
            return nullptr;
        }

        // ★ А6.8: где игровая сессия (для текста события; без IP).
        static std::string DecideWhere(const GameSess& gs)
        {
            std::string w = std::string("; ") + (gs.kind == 2 ? "GameServer" : gs.kind == 3 ? "Indun" : "?") + " pid " + std::to_string(gs.pid) + " userNum " + std::to_string(gs.userNum);
            if (gs.bindUi != gs.userIndex) w += ", EAC-учётка " + std::to_string(gs.bindUi);
            return w;
        }

        // Решение по одной игровой сессии. detail — пояснение для журнала.
        void Decide(GameSess& gs, int reason, uint8_t eosReason, int64_t now, const std::string& detail)
        {
            std::string why;
            bool punish = Punish(gs.bindUi, now, why);
            if (punish && gs.bindUi != gs.userIndex && cfg.IsOperator(gs.userIndex)) { punish = false; why = "оператор (только журнал)"; }
            // §8.6 (R3-04): у процесса P61 не активен — причина 6 не применяется (решение пишется в журнал).
            if (reason == kReasonNotBound && P61Inactive(gs))
            {
                punish = false; why = "P61 у процесса не активен — причина 6 не применяется (§8.6 R3-04)";
            }
            if (reason == kReasonEacAction) HistViolation(gs.bindUi);   // ★ Р66-2: решение за нарушение EAC — поблажки нет
            bool same = gs.decided == reason;
            // Повтор: без кика — только если изменилась причина «почему нельзя» (иначе журнал не засоряется); с киком — раз в KickRepeatSec.
            // Решение, не исполненное из-за освобождения (FailOpen, временный сбой учётки), исполняется, как только освобождение снято.
            if (!punish && same && gs.decidedWhy == why) return;
            if (punish && same && gs.decidedWhy.empty() && gs.lastKickAt != 0 && now - gs.lastKickAt < (int64_t)cfg.kickRepeatSec * 1000) return;
            bool repeat = punish && same && gs.decidedWhy.empty() && gs.lastKickAt != 0;
            gs.decided = reason;
            gs.decidedWhy = why;
            ++statDecisions;
            if (!punish)
            {
                Ev(gs.userIndex, "decision", reason, reason == kReasonEacAction ? EosReasonText(eosReason) : "",
                   std::string(ReasonText(reason)) + " [" + detail + "] — KICK не отправлен: " + why + DecideWhere(gs));
                LOGW("pol", "РЕШЕНИЕ учётка %u (EAC-учётка %u, сервер %u pid %u userNum %u, IP %s): причина %d «%s»%s%s [%s] → KICK НЕ отправлен: %s",
                     gs.userIndex, gs.bindUi, gs.kind, gs.pid, gs.userNum, Ipv4Text(gs.ipv4).c_str(), reason, ReasonText(reason),
                     reason == kReasonEacAction ? ", EOS " : "", reason == kReasonEacAction ? EosReasonText(eosReason) : "", detail.c_str(), why.c_str());
                return;
            }
            BridgeConn* b = BridgeFor(gs.kind, gs.pid);
            if (!b)
            {
                LOGW("pol", "РЕШЕНИЕ учётка %u userNum %u: причина %d [%s] — P73 (сервер %u pid %u) не подключён, повтор позже", gs.userIndex, gs.userNum,
                     reason, detail.c_str(), gs.kind, gs.pid);
                gs.lastKickAt = now;
                Ev(gs.userIndex, "kick_wait", reason, "", std::string(ReasonText(reason)) + " [" + detail + "] — P73 не подключён, повтор позже" + DecideWhere(gs));
                return;
            }
            std::vector<uint8_t> p;
            PutU16(p, gs.userNum); PutU32(p, gs.userIndex); p.push_back((uint8_t)reason); p.push_back(eosReason);
            BridgeSend(*b, kBrKick, p);
            gs.lastKickAt = now; ++statKicks;
            Ev(gs.userIndex, "kick", reason, reason == kReasonEacAction ? EosReasonText(eosReason) : "",
               std::string(repeat ? "KICK (повтор) → P73: " : "KICK → P73: ") + ReasonText(reason) + " [" + detail + "]" + DecideWhere(gs));
            LOGW("pol", "KICK%s → P73 (сервер %u pid %u): учётка %u userNum %u, причина %d «%s» [%s], EOS %s", repeat ? " (повтор)" : "", gs.kind, gs.pid,
                 gs.userIndex, gs.userNum, reason, ReasonText(reason), detail.c_str(), EosReasonText(eosReason));
        }

        void DecideAccount(uint32_t ui, int reason, uint8_t eosReason, int64_t now, const std::string& detail)
        {
            bool any = false;
            for (auto& g : games) if (g.second.bindUi == ui && !g.second.orphanSince) { Decide(g.second, reason, eosReason, now, detail); any = true; }
            if (!any) LOGI("pol", "учётка %u: причина %d «%s» — игровых сессий нет, кикать некого", ui, reason, ReasonText(reason));
        }

        // Живая EAC-сессия учётки (зарегистрирована в EOS) или nullptr.
        SideConn* LiveEac(const Account* a)
        {
            if (!a || !a->eacConn) return nullptr;
            SideConn* c = SideById(a->eacConn);
            return (c && c->st == SideState::Registered) ? c : nullptr;
        }

        // Попробовать сопоставить bind игровой сессии с BIND EAC-сессии e.
        void TryMatch(GameSess& gs, SideConn& e)
        {
            if (gs.boundConn == e.id || gs.bindZero) return;
            for (BindEntry& x : e.binds)
            {
                // Координатор (уточнение §8.1): сверяется только значение bind; serverKind клиент шлёт всегда 2 — только для журнала.
                if (memcmp(x.b, gs.bind, kBindLen) != 0) continue;
                gs.boundConn = e.id; x.matched = true;
                LOGI("pol", "учётка %u userNum %u (сервер %u pid %u): игровое соединение привязано к EAC-сессии %llu (bind=%s…)", gs.userIndex, gs.userNum,
                     gs.kind, gs.pid, (unsigned long long)e.id, BindTag(gs.bind).c_str());
                return;
            }
        }

        // Почему игровая сессия не защищена; reason — причина §5/§8 для решения.
        std::string WhyUnprotected(const GameSess& gs, const Account* a, const SideConn* e, int& reason, int64_t now) const
        {
            if (!e)
            {
                if (a && a->rejectAt && now - a->rejectAt < (int64_t)cfg.rejectMemorySec * 1000) { reason = kReasonRegRejected; return "регистрация/аутентификация учётки отклонена"; }
                reason = gs.everProtected ? kReasonChannelLost : kReasonNoSession;
                return gs.everProtected ? "EAC-сессия учётки потеряна" : "EAC-сессии учётки нет";
            }
            if (!e->authenticated) { reason = kReasonRegRejected; return "EAC-сессия не аутентифицирована (нет RemoteAuthComplete)"; }
            reason = kReasonNotBound;
            if (gs.bindZero) return "нулевой bind игрового соединения (Legacy или P61 выключен)";
            if (gs.boundConn != e->id) return e->binds.empty() ? "BIND от EAC-сессии не пришёл" : "BIND EAC-сессии не совпал с bind игрового соединения";
            return "IP канала EAC " + e->ip + " ≠ IP игры " + Ipv4Text(gs.ipv4) + " (RequireSameIp=1)";
        }

        void Policy(int64_t now)
        {
            const char* foWhy = FailOpenWhy(now);
            bool fo = foWhy != nullptr;
            if (failOpenWas && !fo)
            {
                // Выход из FailOpen: всем — новый отсчёт BindTimeout/Grace от «сейчас».
                LOGI("pol", "FailOpen снят — отсчёты BindTimeout/Grace начинаются заново");
                for (auto& g : games)
                {
                    GameSess& gs = g.second;
                    gs.bindBase = now; gs.decided = 0; gs.decidedWhy.clear(); gs.lastKickAt = 0; gs.waitUntil = 0;
                    if (gs.everProtected && !gs.prot) gs.unprotSince = now;
                }
                for (auto& kv : sides) { SideConn& c = *kv.second; if (!c.dead && c.st == SideState::Registered && !c.authenticated) c.registeredAt = now; }
            }
            else if (!failOpenWas && fo) LOGW("pol", "FailOpen включён (%s) — кики приостановлены", foWhy);
            failOpenWas = fo;
            bool deg = GetHealth().idDegradedUntil.load() > now;
            if (deg != idDegradedWas) { LOGW("pol", "AsdaId: %s", deg ? "деградировал (доля 503 выше порога) — FailOpen" : "снова исправен"); idDegradedWas = deg; }
            if (cfg.mode == 0) return;
            for (auto& g : games)
            {
                GameSess& gs = g.second;
                if (gs.orphanSince) continue;   // P73 отключён — кикнуть всё равно нельзя
                auto ait = accounts.find(gs.bindUi);
                Account* a = ait == accounts.end() ? nullptr : &ait->second;
                SideConn* e = LiveEac(a);
                if (e) TryMatch(gs, *e);
                bool ipOk = !cfg.requireSameIp || (e && e->ipv4 == gs.ipv4);
                // §8.6 (R3-04): у процесса P61 не активен — bind невозможен, защищает аутентифицированная EAC-сессия учётки (как до ред. 3).
                const bool noBindProc = gs.bindZero && P61Inactive(gs);
                bool prot = e && e->authenticated && ((gs.boundConn == e->id && !gs.bindZero) || noBindProc) && ipOk;
                if (prot)
                {
                    if (!gs.prot)
                    {
                        LOGI("pol", "учётка %u userNum %u (сервер %u pid %u): игровая сессия ЗАЩИЩЕНА (EAC %llu аутентифицирована, %s%s)", gs.userIndex,
                             gs.userNum, gs.kind, gs.pid, (unsigned long long)e->id,
                             noBindProc ? "без bind: P61 у процесса не активен" : "bind совпал", cfg.requireSameIp ? ", IP совпал" : "");
                        if (gs.decided) LOGI("pol", "учётка %u userNum %u: прежнее решение (причина %d) снято", gs.userIndex, gs.userNum, gs.decided);
                        Ev(gs.userIndex, "protected", 0, "", std::string("игровая сессия защищена (EAC ") + std::to_string(e->id) + " аутентифицирована, " +
                           (noBindProc ? "без bind: P61 у процесса не активен" : "bind совпал") + ")" + DecideWhere(gs));
                    }
                    gs.prot = true; gs.everProtected = true; gs.unprotSince = 0; gs.decided = 0; gs.decidedWhy.clear(); gs.lastKickAt = 0; gs.waitUntil = 0;
                    continue;
                }
                if (gs.prot)
                {
                    int r = 0; std::string why = WhyUnprotected(gs, a, e, r, now);
                    LOGW("pol", "учётка %u userNum %u (сервер %u pid %u): защита потеряна — %s; Grace %d с", gs.userIndex, gs.userNum, gs.kind, gs.pid,
                         why.c_str(), cfg.graceSec);
                    gs.prot = false; gs.unprotSince = now;
                    Ev(gs.userIndex, "unprotected", r, "", "защита потеряна — " + why + "; Grace " + std::to_string(cfg.graceSec) + " с" + DecideWhere(gs));
                }
                int64_t deadline = gs.everProtected ? gs.unprotSince + (int64_t)cfg.graceSec * 1000 : gs.bindBase + (int64_t)cfg.bindTimeoutSec * 1000;
                if (now < deadline) continue;
                // ★ Д1 / Р64-4: все ожидания ниже (VerifyWait, Д1, Д2) ограничены одной границей от СРОКА игровой сессии:
                //   не позже deadline + AuthTimeoutSec + GraceSec (на стойке 60 + 90 + 30 = 180 с от входа).
                const bool holdOk = now < deadline + ((int64_t)cfg.authTimeoutSec + cfg.graceSec) * 1000;
                // E1-12: идёт проверка токена той же учётки (PUID уже подтверждался) — подождать один раз, не дольше VerifyWaitSec.
                if (!e && a && !a->puid.empty() && cfg.verifyWaitSec > 0 && gs.waitUntil == 0)
                {
                    bool verifying = false;
                    for (auto& kv : sides) { SideConn& c = *kv.second; if (!c.dead && c.st == SideState::Verifying && c.puid == a->puid) { verifying = true; break; } }
                    if (verifying)
                    {
                        gs.waitUntil = now + (int64_t)cfg.verifyWaitSec * 1000;
                        LOGI("pol", "учётка %u userNum %u: срок вышел, но идёт проверка токена учётки — ждём до %d с (один раз)", gs.userIndex, gs.userNum, cfg.verifyWaitSec);
                    }
                }
                if (holdOk && gs.waitUntil && now < gs.waitUntil) continue;
                // ★ Д1: EAC-сессия есть, но RemoteAuthComplete ещё в пути — решения нет, пока с регистрации не прошло AuthTimeoutSec
                //   (провал аутентификации наказывает ветка AuthTimeout в Housekeep: причина 4 через rejectAt).
                // ★ Д1: ожидание ограничено от СРОКА игровой сессии (не от REG): не позже deadline + AuthTimeoutSec + GraceSec — карусель REG
                //   без аутентификации (E1-01) и вытеснение чужой REG срок не продлевают сверх этого предела.
                if (holdOk && e && !e->authenticated && now - e->registeredAt < (int64_t)cfg.authTimeoutSec * 1000) continue;
                // ★ Д1: сессия только что отклонена (AuthTimeout / отказ регистрации) — клиент переподключается сам за 2–4 с (AsdaEacFlow
                //   LoseChannel): решение — не раньше GraceSec от отказа (25.10 23:05: повторная REG через 3 с аутентифицирована за 11 с).
                if (holdOk && !e && a && a->rejectAt && now - a->rejectAt < (int64_t)cfg.graceSec * 1000) continue;
                // ★ Д2: REG учётки с IP игры только что отбит пределом — подождать один раз окно предела, а не «нет EAC-сессии».
                //   Только если эта игровая сессия уже была защищена (честный клиент, падающий после входа): карусель REG без
                //   аутентификации (E1-01) защищённой не бывает и отсрочки не получает.
                // ★ Р64-3: и только если последняя аутентифицированная сессия учётки шла с IP игры; ожидание — в общей границе holdOk.
                if (holdOk && !e && a && gs.everProtected && a->regLimitedAt && a->regLimitedIp == gs.ipv4 && a->lastAuthIp == gs.ipv4 &&
                    now - a->regLimitedAt <= 60000 && gs.limitWaitUntil == 0)
                {
                    gs.limitWaitUntil = now + (int64_t)cfg.regPerAccountWindowSec * 1000;
                    LOGI("pol", "учётка %u userNum %u: срок вышел, но REG учётки с IP игры отбит пределом — ждём до %d с (один раз, Д2)", gs.userIndex,
                         gs.userNum, cfg.regPerAccountWindowSec);
                }
                if (holdOk && gs.limitWaitUntil && now < gs.limitWaitUntil && !e) continue;
                // ★ Д3 ред. 2: Epic Connect у клиента этой учётки не проходит (история + свежие токены + бюджет) — отложить (границы — свои).
                if (!e && ConnectGrace(gs, a, now)) continue;
                int reason = 0;
                std::string why = WhyUnprotected(gs, a, e, reason, now);
                Decide(gs, reason, 0, now, why);
            }
        }

        // ── мост ──────────────────────────────────────────────────────────────────────────
        void BridgeSend(BridgeConn& b, uint8_t type, const std::vector<uint8_t>& payload)
        {
            if (b.dead) return;
            std::vector<uint8_t> f = MakeFrame(type, payload);
            b.out.insert(b.out.end(), f.begin(), f.end());
            if (b.out.size() > kMaxOut) BridgeKill(b, "переполнение исходящего");
        }

        void BridgeKill(BridgeConn& b, const std::string& why)
        {
            if (b.dead) return;
            b.dead = true; b.closeWhy = why;
        }

        // ред. 3 §8.4 (E1-13): владелец соединения — GameServer.exe из каталогов стойки. why — причина отказа.
        bool BridgePeerAllowed(SOCKET s, uint32_t& pid, std::string& image, std::string& why)
        {
            pid = 0;
            if (!PeerOwnerPid(s, pid)) { why = "владелец соединения не найден (GetExtendedTcpTable)"; return false; }
            std::wstring path;
            if (!ProcessImage(pid, path)) { why = "образ процесса pid " + std::to_string(pid) + " не прочитан (" + std::to_string(GetLastError()) + ")"; return false; }
            image = Utf8(path);
            size_t k = path.find_last_of(L"\\/");
            std::wstring dir = k == std::wstring::npos ? L"" : path.substr(0, k), name = k == std::wstring::npos ? path : path.substr(k + 1);
            bool nameOk = false, dirOk = false;
            for (const std::wstring& n : cfg.bridgeImageNames) if (PathEq(n, name)) nameOk = true;
            for (const std::wstring& d : cfg.bridgeImageDirs) if (PathEq(d, dir)) dirOk = true;
            if (!nameOk || !dirOk) { why = "образ " + image + " не из списка AllowedImageNames/AllowedImageDirs"; return false; }
            return true;
        }

        void BridgeAccept()
        {
            for (int i = 0; i < cfg.acceptPerPass; ++i)
            {
                sockaddr_in sa{}; int sl = sizeof(sa);
                SOCKET s = accept(brListen, (sockaddr*)&sa, &sl);
                if (s == INVALID_SOCKET) break;
                if (sa.sin_addr.s_addr != htonl(INADDR_LOOPBACK))   // слушаем 127.0.0.1, но проверяем и адрес
                {
                    LOGE("bridge", "соединение не с 127.0.0.1 (%s) — закрыто", Ipv4Text(sa.sin_addr.s_addr).c_str());
                    closesocket(s); continue;
                }
                uint32_t peerPid = 0; std::string image, why;
                if (cfg.bridgeCheckPeer && !BridgePeerAllowed(s, peerPid, image, why))
                {
                    LOGE("bridge", "соединение отклонено: %s", why.c_str());
                    closesocket(s); continue;
                }
                u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
                BOOL nd = TRUE; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
                std::unique_ptr<BridgeConn> b(new BridgeConn());
                b->id = nextId++; b->s = s; b->acceptedAt = b->lastRecv = NowMs(); b->peerPid = peerPid; b->peerImage = image;
                if (cfg.bridgeCheckPeer) LOGI("bridge", "соединение P73 %llu: процесс pid %u %s", (unsigned long long)b->id, peerPid, image.c_str());
                else LOGI("bridge", "соединение P73 %llu (проверка процесса выключена: CheckPeerProcess=0)", (unsigned long long)b->id);
                bridges[b->id] = std::move(b);
            }
        }

        void BridgeRead(BridgeConn& b)
        {
            uint8_t buf[16384];
            for (int round = 0; round < 8 && !b.dead; ++round)
            {
                int n = recv(b.s, (char*)buf, sizeof(buf), 0);
                if (n == 0) { BridgeKill(b, "P73 закрыл соединение"); return; }
                if (n < 0)
                {
                    int e = WSAGetLastError();
                    if (e == WSAEWOULDBLOCK) return;
                    BridgeKill(b, "ошибка приёма " + std::to_string(e)); return;
                }
                b.lastRecv = NowMs();
                b.in.insert(b.in.end(), buf, buf + n);
                size_t off = 0;
                while (!b.dead && b.in.size() - off >= 2)
                {
                    uint16_t len = GetU16(b.in.data() + off);
                    if (len == 0 || len > kMaxFrameLen) { BridgeKill(b, "кадр: длина " + std::to_string(len)); break; }
                    if (b.in.size() - off < 2u + len) break;
                    uint8_t type = b.in[off + 2];
                    const uint8_t* p = b.in.data() + off + 3;
                    size_t pl = (size_t)len - 1;
                    off += 2u + len;
                    BridgeFrame(b, type, p, pl);
                }
                if (off) b.in.erase(b.in.begin(), b.in.begin() + (ptrdiff_t)(std::min)(off, b.in.size()));
            }
        }

        // Записать bind слота в игровую сессию (LOGIN/REBIND v2).
        static void SetBind(GameSess& gs, const uint8_t* b)
        {
            memcpy(gs.bind, b, kBindLen); gs.bindZero = BindIsZero(b); gs.boundConn = 0;
        }

        void BridgeFrame(BridgeConn& b, uint8_t type, const uint8_t* p, size_t n)
        {
            int64_t now = NowMs();
            if (!b.hello && type != kBrHello) { BridgeKill(b, "кадр до HELLO"); return; }
            switch (type)
            {
            case kBrHello:
            {
                if (b.hello) { BridgeKill(b, "повторный HELLO"); return; }
                if (n == 8 && p[0] == 1)
                {
                    // ред. 3 §8.1: мост v1 (LOGIN без bind) не поддерживается — нужен P73 с HELLO ver=2.
                    LOGE("bridge", "HELLO ver=1 от pid %u — ОТКАЗ: мост v1 (LOGIN без bind) не поддерживается с ред. 3 контракта, нужен P73 с HELLO ver=2",
                         GetU32(p + 2));
                    BridgeKill(b, "HELLO ver=1 (нужен v2)"); return;
                }
                if (n != 8 || p[0] != kBridgeVer || (p[1] != 2 && p[1] != 3)) { BridgeKill(b, "HELLO негоден"); return; }
                uint8_t kind = p[1]; uint32_t pid = GetU32(p + 2); uint16_t port = GetU16(p + 6);
                if (cfg.bridgeCheckPeer && pid != b.peerPid)
                {
                    LOGE("bridge", "HELLO pid %u ≠ pid владельца соединения %u (%s) — ОТКАЗ", pid, b.peerPid, b.peerImage.c_str());
                    BridgeKill(b, "HELLO: pid не совпал с владельцем соединения"); return;
                }
                // Прежнее соединение того же процесса — заменить.
                if (BridgeConn* old = BridgeFor(kind, pid)) BridgeKill(*old, "заменено новым HELLO того же процесса");
                b.hello = true; b.kind = kind; b.pid = pid; b.gamePort = port;
                ProbeOnHello(kind, pid, now);   // §8.6 (R3-04): окно наблюдения bind LOGIN (снимок P73 следом)
                // ред. 2 контракта: HELLO с тем же pid = сброс прежней таблицы этого процесса (P73 следом пришлёт LOGIN всех, кто в игре);
                // HELLO нового pid того же вида сервера при отключённом старом процессе — сессии старого недействительны.
                int reset = 0, dropped = 0;
                for (auto it = games.begin(); it != games.end();)
                {
                    GameSess& gs = it->second;
                    if (gs.kind == kind && gs.pid == pid) { ++reset; it = games.erase(it); }
                    else if (gs.kind == kind && !BridgeFor(kind, gs.pid)) { ++dropped; it = games.erase(it); }
                    else ++it;
                }
                LOGI("bridge", "HELLO v2 %llu: сервер %s pid %u порт %u (сброс таблицы этого pid: %d сессий, снято сессий прежнего процесса %d)",
                     (unsigned long long)b.id, kind == 2 ? "GameServer" : "Indun", pid, port, reset, dropped);
                return;
            }
            case kBrLogin:
            {
                // ред. 3: u16 userNum · u32 userIndex · u32 ipv4 · u32 seq · u8[32] bind
                if (n != 14 + kBindLen) { BridgeKill(b, "LOGIN: длина " + std::to_string(n) + " (v2 — 46)"); return; }
                uint16_t un = GetU16(p); uint32_t ui = GetU32(p + 2); uint32_t ip; memcpy(&ip, p + 6, 4); uint32_t seq = GetU32(p + 10);
                if (ui == 0 || ui > 0x7FFFFFFFu) { LOGW("bridge", "LOGIN userNum %u с негодной учёткой %u — пропущен", un, ui); return; }
                uint64_t k = GameKey(b.kind, b.pid, un);
                auto it = games.find(k);
                if (it != games.end())
                {
                    GameSess& gs = it->second;
                    if (gs.userIndex == ui && seq < gs.seq)
                    {
                        LOGW("bridge", "LOGIN учётка %u userNum %u seq %u < %u — устаревший, пропущен", ui, un, seq, gs.seq);
                        return;
                    }
                    if (gs.userIndex != ui)
                        LOGW("bridge", "LOGIN userNum %u: слот занят учёткой %u без LOGOUT — заменён учёткой %u", un, gs.userIndex, ui);
                }
                GameSess gs;
                gs.kind = b.kind; gs.pid = b.pid; gs.userNum = un; gs.userIndex = ui; gs.bindUi = ui; gs.ipv4 = ip; gs.seq = seq;
                SetBind(gs, p + 14);
                gs.loginAt = gs.bindBase = now;
                games[k] = gs;
                ProbeOnLogin(b.kind, b.pid, gs.bindZero, now);   // §8.6 (R3-04)
                Ev(ui, "login", 0, "", std::string("вход в игру (LOGIN ") + (b.kind == 2 ? "GameServer" : "Indun") + " pid " + std::to_string(b.pid) + " userNum " +
                   std::to_string(un) + (gs.bindZero ? ", bind нулевой" : "") + ")");
                LOGI("bridge", "LOGIN %s pid %u: учётка %u userNum %u IP %s seq %u bind=%s…%s", b.kind == 2 ? "Game" : "Indun", b.pid, ui, un,
                     Ipv4Text(ip).c_str(), seq, BindTag(gs.bind).c_str(), gs.bindZero ? " (НУЛЕВОЙ: Legacy/P61 выкл. — защита невозможна)" : "");
                return;
            }
            case kBrRebind:
            {
                // ред. 2/3: вход соулмейтом — u16 userNum · u32 oldUserIndex · u32 sessionUserIndex · u32 seq · u8[32] bind.
                if (n != 14 + kBindLen) { BridgeKill(b, "REBIND: длина " + std::to_string(n) + " (v2 — 46)"); return; }
                uint16_t un = GetU16(p); uint32_t oldUi = GetU32(p + 2); uint32_t sessUi = GetU32(p + 6); uint32_t seq = GetU32(p + 10);
                auto it = games.find(GameKey(b.kind, b.pid, un));
                if (it == games.end() || it->second.userIndex != oldUi)
                {
                    LOGW("bridge", "REBIND userNum %u: сессии учётки %u нет — пропущен", un, oldUi);
                    return;
                }
                if (sessUi == 0 || sessUi > 0x7FFFFFFFu) { LOGW("bridge", "REBIND userNum %u: негодная учётка сессии %u — пропущен", un, sessUi); return; }
                GameSess& gs = it->second;
                if (seq < gs.seq) { LOGW("bridge", "REBIND учётка %u userNum %u seq %u < %u — устаревший, пропущен", oldUi, un, seq, gs.seq); return; }
                gs.seq = seq;
                gs.bindUi = sessUi;
                SetBind(gs, p + 14);
                gs.bindBase = now;                 // BindTimeout отсчитывается заново
                gs.prot = false; gs.everProtected = false; gs.unprotSince = 0; gs.waitUntil = 0;
                gs.decided = 0; gs.decidedWhy.clear(); gs.lastKickAt = 0;
                Ev(oldUi, "rebind", 0, "", "вход соулмейтом: EAC-учётка сессии " + std::to_string(sessUi) + " (userNum " + std::to_string(un) + ")");
                if (sessUi != oldUi) Ev(sessUi, "rebind", 0, "", "сессия соулмейтом: персонаж учётки " + std::to_string(oldUi) + " (userNum " + std::to_string(un) + ")");
                LOGI("bridge", "REBIND %s pid %u userNum %u: учётка персонажа %u → EAC-учётка сессии %u (seq %u, bind=%s…)", b.kind == 2 ? "Game" : "Indun",
                     b.pid, un, oldUi, sessUi, seq, BindTag(gs.bind).c_str());
                return;
            }
            case kBrLogout:
            {
                if (n != 10) { BridgeKill(b, "LOGOUT: длина " + std::to_string(n)); return; }
                uint16_t un = GetU16(p); uint32_t ui = GetU32(p + 2); uint32_t seq = GetU32(p + 6);
                auto it = games.find(GameKey(b.kind, b.pid, un));
                if (it == games.end() || it->second.userIndex != ui)
                {
                    LOGD("bridge", "LOGOUT учётка %u userNum %u — сессии нет", ui, un);
                    return;
                }
                if (seq < it->second.seq) { LOGW("bridge", "LOGOUT учётка %u userNum %u seq %u < LOGIN %u — устаревший", ui, un, seq, it->second.seq); return; }
                LOGI("bridge", "LOGOUT %s pid %u: учётка %u userNum %u (в игре %lld с)", b.kind == 2 ? "Game" : "Indun", b.pid, ui, un,
                     (long long)((now - it->second.loginAt) / 1000));
                Ev(ui, "logout", 0, "", "выход из игры (LOGOUT userNum " + std::to_string(un) + ", в игре " + std::to_string((now - it->second.loginAt) / 1000) + " с)");
                games.erase(it);
                return;
            }
            case kBrPing:
                if (n != 0) { BridgeKill(b, "PING с данными"); return; }
                BridgeSend(b, kBrPong, {});
                return;
            default:
                BridgeKill(b, "неизвестный тип кадра 0x" + Crypto::Hex(&type, 1));
                return;
            }
        }

        void BridgeClosed(BridgeConn& b)
        {
            LOGW("bridge", "P73 %llu (%s pid %u) отключён: %s", (unsigned long long)b.id, b.kind == 2 ? "Game" : b.kind == 3 ? "Indun" : "?", b.pid, b.closeWhy.c_str());
            if (!b.hello) return;
            if (BridgeFor(b.kind, b.pid)) return;   // есть другое соединение того же процесса
            int64_t now = NowMs();
            for (auto& g : games) if (g.second.kind == b.kind && g.second.pid == b.pid && !g.second.orphanSince) g.second.orphanSince = now;
        }

        // ── обслуживание ──────────────────────────────────────────────────────────────────
        void Housekeep(int64_t now)
        {
            for (auto& kv : sides)
            {
                SideConn& c = *kv.second;
                if (c.dead) continue;
                switch (c.st)
                {
                case SideState::Handshake:
                    if (now - c.acceptedAt > (int64_t)cfg.handshakeTimeoutSec * 1000) SideKill(c, "таймаут рукопожатия");
                    break;
                case SideState::WaitReg:
                    if (now - c.readyAt > (int64_t)cfg.regTimeoutSec * 1000) SideKill(c, "REG не пришёл за RegTimeout");
                    else if (now - c.lastPing > (int64_t)cfg.pingTimeoutSec * 1000) SideKill(c, "нет PING");
                    break;
                case SideState::Verifying:
                    if (now - c.verifyAt > (int64_t)cfg.verifyTimeoutSec * 1000)
                    {
                        ++statRegFail;
                        NoteVerify(c.ipv4, true, now);   // нет ответа — временный отказ (в порог «Epic недоступен»); §8.6 R3-03: без освобождения учётки
                        LOGW("side", "%llu %s: VerifyIdToken без ответа %d с → REG_RESULT 3", (unsigned long long)c.id, c.ip.c_str(), cfg.verifyTimeoutSec);
                        SideRegResult(c, kRegInternal); SideCloseAfterFlush(c, "таймаут VerifyIdToken");
                    }
                    else if (now - c.lastPing > (int64_t)cfg.pingTimeoutSec * 1000) SideKill(c, "нет PING");
                    break;
                case SideState::Registered:
                    if (now - c.lastPing > (int64_t)cfg.pingTimeoutSec * 1000) { SideKill(c, "нет PING"); break; }
                    // ред. 3 §8.2: без RemoteAuthComplete за AuthTimeoutSec — причина 4, канал закрывается (KICK клиенту — только в Mode 2).
                    // Во время FailOpen срок не применяется (Epic недоступен — аутентификация и не может завершиться); при выходе из
                    // FailOpen отсчёт начинается заново (Policy).
                    if (!c.authenticated && !FailOpenNow(now) && now - c.registeredAt > (int64_t)cfg.authTimeoutSec * 1000)
                    {
                        uint32_t ui = c.userIndex;
                        if (ui) accounts[ui].rejectAt = now;
                        Ev(ui, "auth_timeout", kReasonRegRejected, "", "нет RemoteAuthComplete за " + std::to_string(cfg.authTimeoutSec) + " с — EAC-сессия отклонена");
                        LOGW("pol", "учётка %u (%llu %s): нет RemoteAuthComplete за %d с (статус %d) — EAC-сессия отклонена (причина 4)", ui,
                             (unsigned long long)c.id, c.ip.c_str(), cfg.authTimeoutSec, c.authStatus);
                        std::string why;
                        if (Punish(ui, now, why)) SideKick(c, kReasonRegRejected, 0, "EAC-сессия не аутентифицирована");
                        SideCloseAfterFlush(c, "AuthTimeout");
                        break;
                    }
                    // Несопоставленные BIND старше BindKeepSec — забыть (сопоставленные живут с соединением).
                    while (!c.binds.empty() && !c.binds.front().matched && now - c.binds.front().at > (int64_t)cfg.bindKeepSec * 1000) c.binds.pop_front();
                    break;
                case SideState::Closing:
                    if (now >= c.closeAt) SideKill(c, c.closeWhy);
                    break;
                }
            }
            for (auto& kv : bridges)
            {
                BridgeConn& b = *kv.second;
                if (b.dead) continue;
                if (!b.hello && now - b.acceptedAt > (int64_t)cfg.bridgeHelloTimeoutSec * 1000) BridgeKill(b, "HELLO не пришёл");
                else if (now - b.lastRecv > (int64_t)cfg.bridgePingTimeoutSec * 1000) BridgeKill(b, "нет PING от P73");
            }
            for (auto it = games.begin(); it != games.end();)
            {
                GameSess& gs = it->second;
                if (gs.orphanSince && now - gs.orphanSince > (int64_t)cfg.bridgeOrphanSec * 1000)
                {
                    LOGI("bridge", "учётка %u userNum %u: P73 не вернулся за %d с — сессия снята", gs.userIndex, gs.userNum, cfg.bridgeOrphanSec);
                    Ev(gs.userIndex, "orphan_drop", 0, "", "P73 не вернулся за " + std::to_string(cfg.bridgeOrphanSec) + " с — игровая сессия снята");
                    it = games.erase(it); continue;
                }
                ++it;
            }
            // ред. 3 §8.3: временные ошибки вызовов EOS в нити ядра.
            int errs = eos->TakeCallErrors();
            int64_t win = (int64_t)cfg.epicDownWindowSec * 1000;
            for (int i = 0; i < errs && eosErrWin.size() < 100000; ++i) eosErrWin.push_back(now);
            while (!eosErrWin.empty() && now - eosErrWin.front() > win) eosErrWin.pop_front();
            if (errs && (int)eosErrWin.size() >= cfg.eosCallErrorsMax)
                MarkEpicDown("временных ошибок вызовов EOS " + std::to_string(eosErrWin.size()) + " за " + std::to_string(cfg.epicDownWindowSec) + " с");
            // ★ Д3 ред. 2: выдачи токенов AsdaId по учёткам (для поблажки ConnectGrace); общего признака FailOpen по ним больше нет.
            {
                auto got = GetHealth().TakeTokens();
                for (auto& t : got) lastTokenMs[t.second] = t.first;
                const int64_t keep = (int64_t)cfg.connectGraceTokenSec * 1000;
                for (auto it = lastTokenMs.begin(); it != lastTokenMs.end();) it = (now - it->second > keep) ? lastTokenMs.erase(it) : std::next(it);
                HistSave(false);
            }
            // §8.6 (R3-04): окно наблюдения bind истекло без вывода — запись в журнал; процессы без моста и без сессий — забыть.
            for (auto it = procBind.begin(); it != procBind.end();)
            {
                ProcBind& pb = it->second;
                const uint8_t kind = (uint8_t)(it->first >> 32); const uint32_t pid = (uint32_t)it->first;
                if (!pb.active && !pb.inactive && pb.windowFrom && !pb.windowLogged && now - pb.windowFrom > kP61ProbeMs)
                {
                    pb.windowLogged = true;
                    if (pb.zero > 0)
                        LOGI("pol", "%s pid %u: за %lld с после HELLO LOGIN с нулевым bind %d (< %d), ненулевых нет — вывода о P61 нет, причина 6 применяется",
                             kind == 2 ? "GameServer" : "Indun", pid, (long long)(kP61ProbeMs / 1000), pb.zero, kP61ProbeMin);
                }
                bool used = BridgeFor(kind, pid) != nullptr;
                if (!used) for (auto& g : games) if (g.second.kind == kind && g.second.pid == pid) { used = true; break; }
                it = used ? std::next(it) : procBind.erase(it);
            }
            // Учётки без EAC, без игр и без памяти о лимитах/отказах — забыть.
            int64_t regWin = (int64_t)cfg.regPerAccountWindowSec * 1000, rejMem = (int64_t)cfg.rejectMemorySec * 1000;
            for (auto it = accounts.begin(); it != accounts.end();)
            {
                Account& a = it->second;
                while (!a.regTimes.empty() && now - a.regTimes.front() > regWin) a.regTimes.pop_front();
                bool used = a.eacConn != 0 || !a.regTimes.empty() || (a.rejectAt && now - a.rejectAt < rejMem);
                if (!used) for (auto& g : games) if (g.second.bindUi == it->first) { used = true; break; }
                it = used ? std::next(it) : accounts.erase(it);
            }
            // Счётчики приёма: пустые/полные корзины и старые окна REG — забыть.
            for (auto it = ipBuckets.begin(); it != ipBuckets.end();)
                it = (now - it->second.last > 60000) ? ipBuckets.erase(it) : std::next(it);
            for (auto it = regPerIp.begin(); it != regPerIp.end();)
            {
                while (!it->second.empty() && now - it->second.front() > 60000) it->second.pop_front();
                it = it->second.empty() ? regPerIp.erase(it) : std::next(it);
            }
            // ★ А6.8: история учёток без новых событий дольше EventKeepSec — забыть.
            if (board)
                for (auto it = evs.begin(); it != evs.end();)
                    it = (now - it->second.lastMs > (int64_t)cfg.statusEventKeepSec * 1000) ? evs.erase(it) : std::next(it);
            RejectSummary(now, false);
            Policy(now);
        }

        // ★ А6.8 (ревизия 61 Н-1): снимок для точки статуса — ТОЛЬКО то, что спросили, и без лишних копий на нити ядра:
        //   сводка — счётчики (целые, без строк); учётка — только её записи (канал EAC, её игровые сессии, ≤ EventsPerAccount событий);
        //   список — лёгкие строки по учёткам без истории и без текстов (≤ limit строк). Время построения — в замере (core.snap_*_us).
        void FillServer(AdminStatus::Snapshot& s, int64_t now)
        {
            s.builtMs = now; s.builtUnix = UnixNow(); s.uptimeSec = (now - startMs) / 1000; s.mode = cfg.mode;
            const char* fo = FailOpenWhy(now); s.failOpen = fo ? fo : "";
            s.eosSession = eos->SessionStarted();
            for (auto& kv : sides)
            {
                if (kv.second->dead) continue;
                if (kv.second->st == SideState::Registered) { ++s.eacRegistered; s.eacAuthenticated += kv.second->authenticated; } else ++s.eacPending;
            }
            for (auto& kv : bridges) if (!kv.second->dead && kv.second->hello) ++s.bridges;
            for (auto& kv : procBind) s.p61Inactive += kv.second.inactive;
            s.gameSessions = (int)games.size();
            for (auto& g : games) s.gameProtected += g.second.prot;
            s.regOk = statRegOk; s.regFail = statRegFail; s.evictions = statEvict; s.decisions = statDecisions; s.kicks = statKicks;
            s.eventsOn = true; s.accountsKnown = (int)accounts.size(); s.historyAccounts = (int)evs.size();
        }

        void ServeSnapshot(const AdminStatus::Request& rq, int64_t now)
        {
            const int64_t snapT0 = NowUs();
            auto sp = std::make_shared<AdminStatus::Snapshot>();
            AdminStatus::Snapshot& s = *sp;
            s.kind = rq.kind;
            FillServer(s, now);
            auto toUnix = [&](int64_t ms) -> int64_t { return ms ? s.builtUnix - (now - ms) / 1000 : 0; };
            if (rq.kind == AdminStatus::kAskAccount)
            {
                const uint32_t ui = rq.uid;
                AdminStatus::Account a; a.ui = ui;
                bool found = false;
                const int64_t regWin = (int64_t)cfg.regPerAccountWindowSec * 1000, rejMem = (int64_t)cfg.rejectMemorySec * 1000;
                auto ait = accounts.find(ui);
                if (ait != accounts.end())
                {
                    found = true;
                    const Account& src = ait->second;
                    if (src.rejectAt && now - src.rejectAt < rejMem) a.rejectUnix = toUnix(src.rejectAt);
                    for (int64_t t : src.regTimes) if (now - t <= regWin) ++a.regInWindow;
                    if (const SideConn* e = LiveEac(&src))
                    {
                        a.hasEac = true;
                        a.eac.id = e->id; a.eac.state = SideStateText(e->st); a.eac.authenticated = e->authenticated; a.eac.authStatus = e->authStatus;
                        a.eac.platform = e->platform; a.eac.registeredUnix = toUnix(e->registeredAt); a.eac.lastPingAgoMs = now - e->lastPing;
                        a.eac.binds = (int)e->binds.size(); a.eac.ip = e->ip;
                    }
                }
                for (auto& kv : games)
                {
                    const GameSess& gs = kv.second;
                    if (gs.userIndex != ui && gs.bindUi != ui) continue;
                    found = true;
                    AdminStatus::Game g;
                    g.kind = gs.kind; g.pid = gs.pid; g.userNum = gs.userNum; g.userIndex = gs.userIndex; g.bindUi = gs.bindUi;
                    g.loginUnix = toUnix(gs.loginAt); g.prot = gs.prot; g.everProtected = gs.everProtected; g.bindZero = gs.bindZero;
                    g.bound = gs.boundConn != 0; g.orphan = gs.orphanSince != 0; g.p61Inactive = P61Inactive(gs);
                    g.unprotSinceUnix = toUnix(gs.unprotSince); g.lastKickUnix = toUnix(gs.lastKickAt);
                    if (!gs.prot && !gs.orphanSince && cfg.mode != 0)
                    {
                        int64_t dl = gs.everProtected ? gs.unprotSince + (int64_t)cfg.graceSec * 1000 : gs.bindBase + (int64_t)cfg.bindTimeoutSec * 1000;
                        g.deadlineUnix = s.builtUnix + (dl - now) / 1000;
                    }
                    g.decided = gs.decided; g.decidedWhy = gs.decidedWhy; g.ip = Ipv4Text(gs.ipv4);
                    a.games.push_back(std::move(g));
                }
                auto eit = evs.find(ui);
                if (eit != evs.end())
                {
                    found = true;
                    a.events.reserve(eit->second.q.size());
                    for (const EvRec& r : eit->second.q)
                    {
                        AdminStatus::Event e; e.unix = toUnix(r.ms); e.kind = r.kind; e.reason = r.reason; e.eos = r.eos; e.text = r.text;
                        a.events.push_back(std::move(e));
                    }
                }
                if (found) s.accounts.push_back(std::move(a));
            }
            else if (rq.kind == AdminStatus::kAskList)
            {
                std::map<uint32_t, AdminStatus::ListRow> rows;   // по возрастанию UserIndex; строки — без истории и без текстов
                auto row = [&](uint32_t ui) -> AdminStatus::ListRow& { AdminStatus::ListRow& r = rows[ui]; r.ui = ui; return r; };
                for (auto& kv : accounts)
                {
                    AdminStatus::ListRow& r = row(kv.first);
                    if (const SideConn* e = LiveEac(&kv.second)) { r.connected = true; r.authenticated = e->authenticated; }
                }
                for (auto& kv : games)
                {
                    const GameSess& gs = kv.second;
                    for (uint32_t ui : { gs.userIndex, gs.bindUi })
                    {
                        AdminStatus::ListRow& r = row(ui);
                        ++r.games; r.protectedGames += gs.prot; if (gs.decided) r.decided = gs.decided;
                        if (gs.bindUi == gs.userIndex) break;
                    }
                }
                for (auto& kv : evs)
                {
                    if (kv.second.q.empty()) continue;
                    AdminStatus::ListRow& r = row(kv.first);
                    r.events = (int)kv.second.q.size(); r.lastEventUnix = toUnix(kv.second.q.back().ms); r.lastEventKind = kv.second.q.back().kind;
                }
                s.total = (int)rows.size();
                const size_t lim = (size_t)(std::max)(1, rq.limit);
                s.rows.reserve((std::min)(lim, rows.size()));
                for (auto& kv : rows) { if (s.rows.size() >= lim) break; s.rows.push_back(kv.second); }
            }
            snapLastUs = NowUs() - snapT0; if (snapLastUs > snapMaxUs) snapMaxUs = snapLastUs; ++snapBuilds;
            s.passMaxUs = (std::max)(passMaxCurUs, passMaxPrevUs); s.snapLastUs = snapLastUs; s.snapMaxUs = snapMaxUs; s.snapBuilds = snapBuilds;
            board->Publish(rq.id, std::move(sp));
        }

        void Stats(int64_t now)
        {
            int reg = 0, auth = 0, pend = 0;
            for (auto& kv : sides)
            {
                if (kv.second->dead) continue;
                if (kv.second->st == SideState::Registered) { ++reg; auth += kv.second->authenticated; } else ++pend;
            }
            int br = 0; for (auto& kv : bridges) if (!kv.second->dead && kv.second->hello) ++br;
            int prot = 0; for (auto& g : games) prot += g.second.prot;
            int noP61 = 0; for (auto& kv : procBind) noP61 += kv.second.inactive;
            const char* fo = FailOpenWhy(now);
            LOGI("main", "статистика: 15901 EAC %d (аутентифицировано %d) / прочих %d; P73 %d (P61 не активен у %d); игровых сессий %zu (защищено %d); учёток %zu; "
                 "Mode=%d FailOpen=%s; EOS сессия %s; REG ок %lld / отказ %lld, вытеснений %lld, решений %lld, KICK %lld",
                 reg, auth, pend, br, noP61, games.size(), prot, accounts.size(), cfg.mode, fo ? fo : "нет", eos->SessionStarted() ? "есть" : "нет",
                 statRegOk, statRegFail, statEvict, statDecisions, statKicks);
        }

        // Закрыть и удалить мёртвые соединения.
        void Reap()
        {
            for (auto it = sides.begin(); it != sides.end();)
            {
                SideConn& c = *it->second;
                if (!c.dead) { ++it; continue; }
                SideDetach(c);
                Pending(c, false);
                shutdown(c.s, SD_SEND);   // FIN после уже отданных ядру данных
                closesocket(c.s);
                // Закрытия незарегистрированных под шквалом — только отладка (E1-04: журнал не растёт лавиной).
                if (c.userIndex || c.st == SideState::Registered || c.st == SideState::Verifying || Log::GetLevel() >= Log::Debug)
                    LOGI("side", "%llu %s закрыто (%s): %s", (unsigned long long)c.id, c.ip.c_str(), SideStateText(c.st), c.closeWhy.c_str());
                it = sides.erase(it);
            }
            for (auto it = bridges.begin(); it != bridges.end();)
            {
                BridgeConn& b = *it->second;
                if (!b.dead) { ++it; continue; }
                closesocket(b.s);
                std::unique_ptr<BridgeConn> hold = std::move(it->second);
                it = bridges.erase(it);
                BridgeClosed(*hold);
            }
        }

        // Отправить накопленное.
        template <class C> void Flush(C& c)
        {
            while (!c.out.empty() && !c.dead)
            {
                int n = send(c.s, (const char*)c.out.data(), (int)(std::min)(c.out.size(), (size_t)65536), 0);
                if (n > 0) { c.out.erase(c.out.begin(), c.out.begin() + n); continue; }
                int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) return;
                c.dead = true; if (c.closeWhy.empty()) c.closeWhy = "ошибка отправки " + std::to_string(e);
                return;
            }
        }

        void ServeSide(uint64_t id, short re)
        {
            auto it = sides.find(id); if (it == sides.end()) return;
            SideConn& c = *it->second;
            if (c.dead) return;
            if (re & (POLLRDNORM | POLLHUP | POLLERR)) SideRead(c);
            if (!c.dead && (re & POLLNVAL)) SideKill(c, "POLLNVAL");
            if (!c.dead && !c.out.empty()) Flush(c);
        }

        void ServeBridge(uint64_t id, short re)
        {
            auto it = bridges.find(id); if (it == bridges.end()) return;
            BridgeConn& b = *it->second;
            if (b.dead) return;
            if (re & (POLLRDNORM | POLLHUP | POLLERR)) BridgeRead(b);
            if (!b.dead && (re & POLLNVAL)) BridgeKill(b, "POLLNVAL");
            if (!b.dead && !b.out.empty()) Flush(b);
        }

        void Loop(std::atomic<bool>& stop)
        {
            startMs = lastHouse = lastStats = lastTick = lastRejectSummary = NowMs();
            failOpenWas = FailOpenNow(startMs);
            std::vector<WSAPOLLFD> fds;
            // (вид, id): 1 мост, 0 сайдкар, -1 слушатель 15901, -2 слушатель 15702.
            std::vector<std::pair<int, uint64_t>> who;
            while (!stop)
            {
                fds.clear(); who.clear();
                WSAPOLLFD f{};
                // E1-04: порядок обслуживания — мост, зарегистрированные 15901, прочие 15901, слушатель моста, слушатель 15901 последним.
                for (auto& kv : bridges)
                {
                    BridgeConn& b = *kv.second; if (b.dead) continue;
                    f.fd = b.s; f.events = (short)(POLLRDNORM | (b.out.empty() ? 0 : POLLWRNORM)); fds.push_back(f); who.emplace_back(1, b.id);
                }
                for (int pass = 0; pass < 2; ++pass)
                    for (auto& kv : sides)
                    {
                        SideConn& c = *kv.second; if (c.dead) continue;
                        if ((c.st == SideState::Registered) != (pass == 0)) continue;
                        f.fd = c.s; f.events = (short)(POLLRDNORM | (c.out.empty() ? 0 : POLLWRNORM)); fds.push_back(f); who.emplace_back(0, c.id);
                    }
                f.fd = brListen;   f.events = POLLRDNORM; fds.push_back(f); who.emplace_back(-2, 0);
                f.fd = sideListen; f.events = POLLRDNORM; fds.push_back(f); who.emplace_back(-1, 0);
                int64_t now = NowMs();
                int wait = (int)(std::max)((int64_t)0, (int64_t)cfg.eosTickMs - (now - lastTick));
                int r = WSAPoll(fds.data(), (ULONG)fds.size(), wait);
                const int64_t workT0 = NowUs();   // ★ А6.8 (р61): работа прохода — от возврата WSAPoll до конца прохода
                if (r == SOCKET_ERROR) { LOGE("main", "WSAPoll: %d", WSAGetLastError()); Sleep(10); }
                else if (r > 0)
                {
                    for (size_t i = 0; i < fds.size(); ++i)
                    {
                        short re = fds[i].revents;
                        if (!re) continue;
                        switch (who[i].first)
                        {
                        case 1: ServeBridge(who[i].second, re); break;
                        case 0: ServeSide(who[i].second, re); break;
                        case -2: BridgeAccept(); break;
                        case -1: SideAccept(NowMs()); break;
                        }
                    }
                }
                now = NowMs();
                if (now - lastTick >= cfg.eosTickMs) { lastTick = now; eos->Tick(); }
                if (now - lastHouse >= kHousekeepMs) { lastHouse = now; Housekeep(now); }
                // ★ А6.8 (р61): снимок — только когда его просит точка статуса, и только то, что спросили (один запрос за проход)
                { AdminStatus::Request rq; if (board && board->Take(rq)) ServeSnapshot(rq, NowMs()); }
                if (now - lastStats >= (int64_t)cfg.statsSec * 1000) { lastStats = now; Stats(now); }
                // Ответы, сформированные колбэками EOS и политикой, — отправить сразу.
                for (auto& kv : bridges) { BridgeConn& b = *kv.second; if (!b.dead && !b.out.empty()) Flush(b); }
                for (auto& kv : sides)
                {
                    SideConn& c = *kv.second;
                    if (!c.dead && !c.out.empty()) Flush(c);
                    if (!c.dead && c.st == SideState::Closing && c.out.empty()) SideKill(c, c.closeWhy);
                }
                Reap();
                // ★ А6.8 (р61): наибольший проход за окно 10 с (текущее и прошлое — точка статуса отдаёт максимум двух)
                const int64_t passUs = NowUs() - workT0;
                if (now - passWinFrom >= 10000) { passMaxPrevUs = passMaxCurUs; passMaxCurUs = 0; passWinFrom = now; }
                if (passUs > passMaxCurUs) passMaxCurUs = passUs;
            }
            // Останов: закрыть всё.
            RejectSummary(NowMs(), true);
            for (auto& kv : sides) SideKill(*kv.second, "останов сервера");
            for (auto& kv : bridges) BridgeKill(*kv.second, "останов сервера");
            Reap();
        }
    };

    Core::Core(const Config& cfg, IEos* eos, const AsdaSecure::PrivateKey* secureKey) : m(new Impl())
    {
        m->cfg = cfg; m->eos = eos; m->key = secureKey;
    }

    Core::~Core()
    {
        if (m->sideListen != INVALID_SOCKET) closesocket(m->sideListen);
        if (m->brListen != INVALID_SOCKET) closesocket(m->brListen);
        delete m;
    }

    bool Core::Start(std::string* err)
    {
        m->sideListen = MakeListener(m->cfg.sidecarBind.c_str(), m->cfg.sidecarPort, err);
        if (m->sideListen == INVALID_SOCKET) return false;
        m->brListen = MakeListener("127.0.0.1", m->cfg.bridgePort, err);   // контракт §4: ТОЛЬКО 127.0.0.1
        if (m->brListen == INVALID_SOCKET) return false;
        LOGI("main", "сайдкар слушает %s:%d (AsdaSecure, SubServer::Eac=4), мост v2 — 127.0.0.1:%d (проверка процесса P73: %s)", m->cfg.sidecarBind.c_str(),
             m->cfg.sidecarPort, m->cfg.bridgePort, m->cfg.bridgeCheckPeer ? "да" : "НЕТ");
        LOGI("main", "политика ред. 3: AuthTimeout=%d с, REG на учётку %d/%d с, REG с IP %d/мин, RequireSameIp=%d, accept за проход %d, "
             "соединений с IP %d/с (запас %d), общий %d/с (запас %d)", m->cfg.authTimeoutSec, m->cfg.regPerAccountMax, m->cfg.regPerAccountWindowSec,
             m->cfg.regPerIpPerMin, (int)m->cfg.requireSameIp, m->cfg.acceptPerPass, m->cfg.connectRatePerIp, m->cfg.connectBurstPerIp,
             m->cfg.connectRateGlobal, m->cfg.connectBurstGlobal);
        return true;
    }

    void Core::SetStatusBoard(AdminStatus::Board* board) { m->board = board; }

    void Core::Run(std::atomic<bool>& stop)
    {
        // EOS стартует в нити ядра: все вызовы SDK — только отсюда.
        m->HistLoad();   // ★ Д3 ред. 2: история аутентификации учёток с диска
        bool ok = m->eos->Start(m);
        LOGI("main", "EOS: %s — %s", m->eos->Name(), ok ? "сессия AntiCheatServer начата" : "сессии нет (REG → REG_RESULT 3; FailOpen по ini)");
        m->Loop(stop);
        m->HistSave(true);
        m->eos->Stop();
    }
}
