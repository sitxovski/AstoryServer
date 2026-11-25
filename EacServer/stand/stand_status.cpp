// Copyright (c) 2026 @sitxovski (Discord)
// stand_status.cpp — стенд (ж) ★ А6.8 (22.11.2026): точка статуса EAC для админ-центра (src/AdminStatus.h) против AsdaEacServer_stand.exe.
// Подставные сессии — настоящим путём: фальшивый P73 на мосту (LOGIN/LOGOUT), клиент 15901 поверх AsdaSecure (REG, BIND, ACMSG «ACTION:n»)
// с фальшивым EOS. Проверки: Enabled=0 / нет секрета / короткий секрет — точки нет, EAC работает; отказ без ключа и с чужим ключом;
// маршруты и негодные запросы; состояние учётки (подключён, Authenticated, защищена, bind, KICK, история событий, IP только в net);
// конкуренция (8 нитей опрашивают точку, а мост и политика работают в срок — PONG и KICK по BindTimeout); частота (429 rate и auth_rate);
// медленный клиент сброшен по сроку; не-локальный адрес машины не отвечает; слушатель только 127.0.0.1; секрета нет в журнале.
#include "StandCommon.h"
#include "Json.h"
#include <iphlpapi.h>
#include <atomic>
#include <thread>

using namespace Stand;

namespace
{
    const int kId = 18447, kSide = 25731, kBr = 25732, kSt = 25733;   // порты стенда
    AsdaSecure::PublicKey g_pub;
    const std::string kKey = "a68stand0123456789abcdef0123456789abcdef01234567";   // секрет стенда (48 знаков; не боевой)

    // Ответ HTTP: код (0 — нет ответа) и тело.
    struct Resp { int code = 0; std::string body; Eac::Json::Value js; bool json = false; };

    // GET (или иной метод) к точке статуса. key == nullptr — без заголовка ключа.
    Resp Req(const std::string& path, const char* key, const std::string& method = "GET", int port = kSt)
    {
        Resp r;
        SOCKET s = Connect(port, 5000);
        if (s == INVALID_SOCKET) return r;
        std::string q = method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        if (key) q += std::string("X-Asda-Key: ") + key + "\r\n";
        q += "Connection: close\r\n\r\n";
        SendAll(s, q.data(), q.size());
        std::string raw; uint8_t b[16384];
        while (true) { int n = RecvSome(s, b, sizeof(b), 5000); if (n <= 0) break; raw.append((char*)b, (size_t)n); }
        closesocket(s);
        if (raw.size() > 12 && raw.compare(0, 9, "HTTP/1.1 ") == 0) r.code = atoi(raw.c_str() + 9);
        size_t p = raw.find("\r\n\r\n");
        if (p != std::string::npos) r.body = raw.substr(p + 4);
        r.json = Eac::Json::Parse(r.body, r.js);
        return r;
    }

    // Поле-строка ответа.
    std::string Str(const Eac::Json::Value* v, const char* k) { std::string s; if (v) v->GetString(k, s); return s; }
    // Поле-булево.
    bool Bool(const Eac::Json::Value* v, const char* k) { const Eac::Json::Value* x = v ? v->Get(k) : nullptr; return x && x->type == Eac::Json::Type::Bool && x->b; }
    // Поле-число.
    double Num(const Eac::Json::Value* v, const char* k) { const Eac::Json::Value* x = v ? v->Get(k) : nullptr; return x && x->type == Eac::Json::Type::Number ? x->num : -1; }
    // Есть ли событие вида kind в истории учётки.
    bool HasEvent(const Eac::Json::Value* acc, const char* kind)
    {
        const Eac::Json::Value* ev = acc ? acc->Get("events") : nullptr;
        if (!ev || ev->type != Eac::Json::Type::Array) return false;
        for (auto& e : ev->arr) if (Str(&e, "kind") == kind) return true;
        return false;
    }
    // Ждать, пока учётка ui в ответе точки удовлетворит pred (опрос раз в 200 мс).
    template <class P> bool WaitAcc(uint32_t ui, int ms, P pred, Resp* out = nullptr)
    {
        int64_t end = NowMs() + ms;
        while (true)
        {
            Resp r = Req("/eac/v1/account/" + std::to_string(ui), kKey.c_str());
            const Eac::Json::Value* a = r.json ? r.js.Get("account") : nullptr;
            if (r.code == 200 && a && a->type == Eac::Json::Type::Object && pred(a)) { if (out) *out = r; return true; }
            if (NowMs() > end) { if (out) *out = r; return false; }
            Sleep(200);
        }
    }

    bool OpenP73(PlainClient& c) { return c.Open(kBr) && c.Send(0x10, HelloV(2, 2, 0, 15601)); }
    std::vector<uint8_t> Logout(uint16_t un, uint32_t ui, uint32_t seq) { std::vector<uint8_t> p; PutU16(p, un); PutU32(p, ui); PutU32(p, seq); return p; }

    bool Run(Server& srv, const std::wstring& dir, const std::map<std::string, std::string>& ov)
    {
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, ov);
        return srv.Start(dir, ini, L"--fake-eos --fake-auth", kBr) && WaitPort(kSide, 5000);
    }

    void WriteFile(const std::wstring& path, const std::string& text)
    {
        FILE* f = _wfopen(path.c_str(), L"wb"); if (f) { fwrite(text.data(), 1, text.size(), f); fclose(f); }
    }

    // Первый не-loopback IPv4 этой машины ("" — нет).
    std::string NonLoopbackIp()
    {
        char host[256] = {}; gethostname(host, sizeof(host));
        addrinfo hints{}; hints.ai_family = AF_INET; addrinfo* res = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &res) != 0) return "";
        std::string out;
        for (addrinfo* p = res; p; p = p->ai_next)
        {
            uint32_t a = ((sockaddr_in*)p->ai_addr)->sin_addr.s_addr;
            if ((ntohl(a) >> 24) == 127) continue;
            char t[32]; inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, t, sizeof(t)); out = t; break;
        }
        freeaddrinfo(res);
        return out;
    }

    // Подключение к адресу ip:port (true — соединение принято).
    bool ConnectTo(const std::string& ip, int port)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port); inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        bool ok = connect(s, (sockaddr*)&sa, sizeof(sa)) == 0;
        closesocket(s);
        return ok;
    }

    // Адреса, на которых слушается порт (таблица Windows).
    std::vector<std::string> ListenAddrs(int port)
    {
        std::vector<std::string> out;
        std::vector<uint8_t> buf(1 << 20); ULONG size = (ULONG)buf.size();
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) return out;
        auto* t = (MIB_TCPTABLE_OWNER_PID*)buf.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i)
            if (ntohs((u_short)t->table[i].dwLocalPort) == port)
            {
                in_addr a; a.s_addr = t->table[i].dwLocalAddr; char s[32]; inet_ntop(AF_INET, &a, s, sizeof(s)); out.push_back(s);
            }
        return out;
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    WsaInit();
    printf("=== stand_status: ★ А6.8 точка статуса EAC для панели (127.0.0.1, только чтение) ===\n");
    std::wstring dir = RunDir("status");
    if (!Check(MakeSecureKey(dir, g_pub), "ключ AsdaSecure стенда создан")) return Summary("stand_status");
    const std::string port = std::to_string(kSt), keyFile = U8(dir) + "secrets\\admin_status.key";

    // ── S1: Enabled=0 (умолчание) — точки нет ───────────────────────────────────────────────
    {
        printf("-- S1: [AdminStatus] нет в ini (Enabled=0 по умолчанию)\n");
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Port", port} }), "сервер запущен"))
        {
            Check(!WaitPort(kSt, 1500), "порт точки не слушается");
            Check(srv.WaitLog("точка статуса для панели выключена", 2000), "журнал: «точка статуса для панели выключена»");
            Check(srv.Stop(), "штатный останов");
        }
    }
    // ── S2: Enabled=1, файла секрета нет — точки нет, EAC работает ──────────────────────────
    {
        printf("-- S2: Enabled=1, секрета нет\n");
        DeleteFileW((dir + L"secrets\\admin_status.key").c_str());
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile} }), "сервер запущен (сайдкар и мост слушают)"))
        {
            Check(!WaitPort(kSt, 1500), "порт точки не слушается");
            Check(srv.WaitLog("точка статуса НЕ запущена: секрет не прочитан", 2000), "журнал: точка не запущена — секрет не прочитан, EAC работает");
            PlainClient p73; OpenP73(p73); p73.Send(0x14, {}); std::vector<uint8_t> pl;
            Check(p73.RecvType(0x24, pl, 2000) == 1, "мост отвечает PONG");
            srv.Stop();
        }
    }
    // ── S3: короткий секрет ─────────────────────────────────────────────────────────────────
    {
        printf("-- S3: секрет короче 32 знаков\n");
        WriteFile(dir + L"secrets\\admin_status.key", "short_secret_123\r\n");
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile} }), "сервер запущен"))
        {
            Check(!WaitPort(kSt, 1500), "порт точки не слушается");
            Check(srv.WaitLog("секрет короче 32 знаков", 2000), "журнал: секрет короче 32 знаков");
            Check(!srv.LogHas("short_secret_123"), "секрета нет в журнале");
            srv.Stop();
        }
    }
    // ── S4: рабочая точка — доступ, маршруты, состояние учётки, конкуренция ─────────────────
    {
        printf("-- S4: Enabled=1, секрет 48 знаков, Mode=2 FailOpen=0 BindTimeout=3\n");
        WriteFile(dir + L"secrets\\admin_status.key", kKey + "\r\n");
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile}, {"AdminStatus.ReqPerSec", "1000"}, {"AdminStatus.ReqBurst", "1000"},
                                  {"AdminStatus.DeadlineMs", "600"}, {"Policy.BindTimeoutSec", "3"}, {"Policy.KickRepeatSec", "30"} }), "сервер запущен"))
        {
            Check(WaitPort(kSt, 3000), "порт точки слушается");
            Check(srv.WaitLog("точка статуса для панели: 127.0.0.1:" + port, 2000), "журнал: точка запущена на 127.0.0.1");
            std::vector<std::string> la = ListenAddrs(kSt);
            Check(la.size() == 1 && la[0] == "127.0.0.1", "слушатель точки — только 127.0.0.1 (" + std::to_string(la.size()) + " строк)");
            std::string nl = NonLoopbackIp();
            if (nl.empty()) printf("  [нет не-loopback IPv4 — проверка внешнего адреса пропущена]\n");
            else Check(!ConnectTo(nl, kSt), "с адреса машины " + nl + " точка не отвечает (соединение не принято)");
            // доступ
            Resp r = Req("/eac/v1/summary", nullptr);
            Check(r.code == 401 && Str(&r.js, "error") == "key", "без ключа → 401 key");
            r = Req("/eac/v1/summary", "wrong-key-wrong-key-wrong-key-wrong-key-00");
            Check(r.code == 401, "чужой ключ → 401");
            r = Req("/eac/v1/summary", (kKey + "x").c_str());
            Check(r.code == 401, "ключ с лишним знаком → 401");
            r = Req("/eac/v1/summary", kKey.c_str());
            const Eac::Json::Value* sv = r.json ? r.js.Get("server") : nullptr;
            Check(r.code == 200 && Bool(&r.js, "ok") && sv && Str(sv, "version") == "a68.2" && Num(sv, "mode") == 2 && Bool(sv, "events_on"),
                  "summary → 200, версия a68.2, Mode 2, история событий ведётся");
            // маршруты и негодные запросы
            Check(Req("/eac/v1/account/0", kKey.c_str()).code == 400, "учётка 0 → 400");
            Check(Req("/eac/v1/account/abc", kKey.c_str()).code == 400, "учётка abc → 400");
            Check(Req("/eac/v1/account/012", kKey.c_str()).code == 400, "учётка с ведущим нулём → 400");
            Check(Req("/eac/v1/account/3000000000", kKey.c_str()).code == 400, "учётка > 2^31-1 → 400");
            Check(Req("/eac/v1/accounts?limit=0", kKey.c_str()).code == 400, "limit=0 → 400");
            Check(Req("/eac/v1/accounts?foo=1", kKey.c_str()).code == 400, "чужой параметр → 400");
            Check(Req("/eac/v1/other", kKey.c_str()).code == 404, "чужой путь → 404");
            Check(Req("/eac/v1/summary", kKey.c_str(), "POST").code == 405, "POST → 405");
            r = Req("/eac/v1/account/1001", kKey.c_str());
            Check(r.code == 200 && r.json && r.js.Get("found") && !Bool(&r.js, "found") && r.js.Get("account")->type == Eac::Json::Type::Null,
                  "неизвестная учётка → found=false, account=null");
            // подставная сессия: P73 LOGIN 1001 + EAC REG 1001 + BIND
            PlainClient p73;
            Check(OpenP73(p73), "фальшивый P73 подключён");
            Bind32 b1 = RandBind();
            SecureClient e1;
            Check(EacRegister(e1, kSide, g_pub, 1001, 1001) == 0, "EAC 1001: REG_RESULT 0");
            Check(EacBind(e1, 2, b1) == 0, "EAC 1001: BIND_RESULT 0");
            p73.Send(0x11, LoginV2(11, 1001, 0x0A010203, 1, b1));
            Resp ra;
            bool ok = WaitAcc(1001, 4000, [](const Eac::Json::Value* a) {
                const Eac::Json::Value* g = a->Get("games");
                return Bool(a, "connected") && g && g->arr.size() == 1 && Bool(&g->arr[0], "protected"); }, &ra);
            const Eac::Json::Value* a = ra.json ? ra.js.Get("account") : nullptr;
            Check(ok, "учётка 1001: подключена, игровая сессия защищена");
            const Eac::Json::Value* eac = a ? a->Get("eac") : nullptr;
            Check(eac && Bool(eac, "authenticated") && Num(eac, "auth_status") == 2 && Num(eac, "platform") == 1 && Num(eac, "binds") == 1,
                  "eac: authenticated, auth_status 2, platform 1, binds 1");
            Check(eac && eac->Get("net") && Str(eac->Get("net"), "ip") == "127.0.0.1", "IP канала EAC — только в eac.net.ip (127.0.0.1)");
            const Eac::Json::Value* g0 = (a && a->Get("games") && !a->Get("games")->arr.empty()) ? &a->Get("games")->arr[0] : nullptr;
            Check(g0 && Num(g0, "user_num") == 11 && Num(g0, "uid") == 1001 && Bool(g0, "bound") && !Bool(g0, "bind_zero") && Str(g0, "server") == "GameServer" &&
                  Num(g0, "login_unix") > 1.7e9 && g0->Get("deadline_unix")->type == Eac::Json::Type::Null,
                  "игровая сессия: userNum 11, bind сопоставлен, срока нет (защищена), время входа — Unix");
            Check(g0 && Str(g0->Get("net"), "ip") == "10.1.2.3", "IP игры — только в games[].net.ip (10.1.2.3)");
            Check(HasEvent(a, "reg_ok") && HasEvent(a, "auth") && HasEvent(a, "login") && HasEvent(a, "protected"),
                  "история: reg_ok, auth, login, protected");
            bool ipInText = false;
            if (a && a->Get("events")) for (auto& e : a->Get("events")->arr) if (Str(&e, "text").find("127.0.0.1") != std::string::npos || Str(&e, "text").find("10.1.2.3") != std::string::npos) ipInText = true;
            Check(!ipInText, "в текстах событий нет IP");
            // нарушение EAC → KICK (Mode=2)
            e1.Send(0x02, std::vector<uint8_t>({ 'A', 'C', 'T', 'I', 'O', 'N', ':', '6' }));
            std::vector<uint8_t> kp;
            Check(p73.RecvType(0x21, kp, 3000) == 1 && kp.size() == 8 && kp[6] == 2, "ClientActionRequired → KICK причина 2 на мост");
            ok = WaitAcc(1001, 3000, [](const Eac::Json::Value* x) { return HasEvent(x, "violation") && HasEvent(x, "kick") && HasEvent(x, "eac_lost"); }, &ra);
            a = ra.json ? ra.js.Get("account") : nullptr;
            Check(ok, "история: violation, kick, eac_lost");
            bool eosOk = false;
            if (a && a->Get("events")) for (auto& e : a->Get("events")->arr) if (Str(&e, "kind") == "violation" && Str(&e, "eos") == "ClientViolation" && Num(&e, "reason") == 2) eosOk = true;
            Check(eosOk, "violation: eos ClientViolation, причина 2");
            const Eac::Json::Value* g1 = (a && a->Get("games") && !a->Get("games")->arr.empty()) ? &a->Get("games")->arr[0] : nullptr;
            Check(a && !Bool(a, "connected") && g1 && Num(g1, "decided") == 2 && Str(g1, "decided_code") == "eac_action" && Num(g1, "last_kick_unix") > 1.7e9,
                  "после KICK: EAC не подключён, решение 2 eac_action, время KICK есть");
            // список
            r = Req("/eac/v1/accounts", kKey.c_str());
            Check(r.code == 200 && r.json && r.js.Get("accounts") && r.js.Get("accounts")->arr.size() >= 1 && Num(r.js.Get("accounts") ? &r.js.Get("accounts")->arr[0] : nullptr, "uid") == 1001,
                  "accounts → 200, учётка 1001 в списке");
            // конкуренция: 8 нитей опрашивают точку; мост — PONG в срок, политика — KICK 1002 по BindTimeout
            std::atomic<int> n200{ 0 }, nOther{ 0 }; std::atomic<bool> hammer{ true };
            std::vector<std::thread> th;
            for (int i = 0; i < 8; ++i)
                th.emplace_back([&, i] {
                    // 8 нитей по запросу раз в 10 мс (~800/с — на порядки чаще панели); код 0 (соединение не принято) — тоже «прочий»
                    while (hammer) { Resp x = Req(i % 2 ? "/eac/v1/accounts" : "/eac/v1/account/1001", kKey.c_str()); (x.code == 200 ? n200 : nOther)++; Sleep(10); }
                });
            int64_t t0 = NowMs();
            p73.Send(0x11, LoginV2(12, 1002, 0x0A010204, 2, RandBind()));
            int64_t worstPong = 0; bool kick1002 = false;
            while (NowMs() - t0 < 6000)
            {
                int64_t p0 = NowMs(); p73.Send(0x14, {});
                uint8_t t; std::vector<uint8_t> pl; int64_t deadline = p0 + 2000; bool pong = false;
                while (NowMs() < deadline)
                {
                    if (p73.Recv(t, pl, (int)(deadline - NowMs())) != 1) break;
                    if (t == 0x24) { pong = true; break; }
                    if (t == 0x21 && pl.size() == 8 && GetU32(pl.data() + 2) == 1002 && pl[6] == 1) kick1002 = true;
                }
                worstPong = (std::max)(worstPong, pong ? NowMs() - p0 : 9999);
                Sleep(200);
            }
            hammer = false;
            for (auto& x : th) x.join();
            Check(n200 > 50 && nOther == 0, "конкуренция: " + std::to_string(n200.load()) + " ответов 200, прочих " + std::to_string(nOther.load()));
            Check(worstPong < 500, "мост под нагрузкой точки: худший PONG " + std::to_string(worstPong) + " мс (< 500)");
            Check(kick1002, "политика под нагрузкой: KICK 1002 причина 1 по BindTimeout");
            // медленный клиент: заголовки не дописаны — сброс по сроку (DeadlineMs=600), точка снова отвечает
            SOCKET slow = Connect(kSt, 3000);
            SendAll(slow, "GET /eac/v1/summary HTTP/1.1\r\n", 31);
            int64_t s0 = NowMs(); uint8_t sb[64]; int sr = RecvSome(slow, sb, sizeof(sb), 3000); int64_t sdt = NowMs() - s0;
            closesocket(slow);
            Check(sr <= 0 && sr != -1 && sdt < 1500, "медленный клиент сброшен за " + std::to_string(sdt) + " мс");
            Check(Req("/eac/v1/summary", kKey.c_str()).code == 200, "после медленного клиента точка отвечает");
            // LOGOUT
            p73.Send(0x12, Logout(11, 1001, 3));
            ok = WaitAcc(1001, 3000, [](const Eac::Json::Value* x) { return HasEvent(x, "logout") && x->Get("games") && x->Get("games")->arr.empty(); });
            Check(ok, "LOGOUT: игровой сессии нет, в истории logout");
            Check(!srv.LogHas(kKey), "секрета нет в журнале");
            Check(srv.Stop(), "штатный останов с работающей точкой");
        }
    }
    // ── S5: частота — rate и отказы по ключу ────────────────────────────────────────────────
    {
        printf("-- S5: ReqPerSec=2 ReqBurst=3, FailPerMin=3\n");
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile}, {"AdminStatus.ReqPerSec", "2"}, {"AdminStatus.ReqBurst", "3"},
                                  {"AdminStatus.FailPerMin", "3"} }), "сервер запущен") && Check(WaitPort(kSt, 3000), "порт точки слушается"))
        {
            Sleep(1600);   // WaitPort израсходовал запас частоты (соединения без запроса не тратят токен — пауза на всякий случай)
            int c200 = 0, c429 = 0;
            for (int i = 0; i < 8; ++i) { Resp x = Req("/eac/v1/summary", kKey.c_str()); if (x.code == 200) ++c200; else if (x.code == 429 && Str(&x.js, "error") == "rate") ++c429; }
            Check(c200 >= 3 && c200 <= 5 && c429 >= 3, "частота: 200 — " + std::to_string(c200) + ", 429 rate — " + std::to_string(c429));
            Sleep(2500);
            int a401 = 0;
            for (int i = 0; i < 3; ++i) if (Req("/eac/v1/summary", "bad-key-bad-key-bad-key-bad-key-bad-key").code == 401) ++a401;
            Sleep(1100);
            Resp x = Req("/eac/v1/summary", "bad-key-bad-key-bad-key-bad-key-bad-key");
            Check(a401 == 3 && x.code == 429 && Str(&x.js, "error") == "auth_rate", "3 отказа по ключу → 401, 4-й → 429 auth_rate");
            Sleep(1100);
            x = Req("/eac/v1/summary", kKey.c_str());
            Check(x.code == 429, "пока запас отказов пуст — 429 и с верным ключом (перебор не идёт)");
            printf("  ждём пополнения запаса отказов (20 с)…\n");
            Sleep(21000);
            x = Req("/eac/v1/summary", kKey.c_str());
            Check(x.code == 200, "после пополнения — 200");
            srv.Stop();
            Check(srv.LogHas("отказов по ключу 4") || srv.LogHas("отказов по ключу 3"), "журнал: сводка отказов по ключу при останове");
        }
    }
    // ── S6 (ревизия 61 М-1): порт точки занят — точка не запущена, EAC работает ─────────────────
    {
        printf("-- S6: порт точки занят другим процессом\n");
        SOCKET busy = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)kSt); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOL excl = TRUE; setsockopt(busy, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof(excl));
        bool held = bind(busy, (sockaddr*)&sa, sizeof(sa)) == 0 && listen(busy, 4) == 0;
        Check(held, "стенд занял 127.0.0.1:" + port);
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile} }), "сервер запущен (сайдкар и мост слушают)"))
        {
            Check(srv.WaitLog("точка статуса НЕ запущена: bind/listen 127.0.0.1:" + port, 3000), "журнал: точка не запущена — bind/listen, EAC работает без неё");
            PlainClient p73; OpenP73(p73); p73.Send(0x14, {}); std::vector<uint8_t> pl;
            Check(p73.RecvType(0x24, pl, 2000) == 1, "мост отвечает PONG");
            SecureClient e; Check(EacRegister(e, kSide, g_pub, 1101, 1101) == 0, "сайдкар принимает REG (REG_RESULT 0)");
            Check(srv.Stop(), "штатный останов");
        }
        closesocket(busy);
    }
    // ── S8 (ревизия 61 М-2): ошибка в [AdminStatus] не ломает конфиг — точка выключена, EAC стартует ─────
    {
        printf("-- S8: негодный [AdminStatus] Port=0 и Port = порту моста\n");
        for (int v = 0; v < 2; ++v)
        {
            Server srv;
            std::map<std::string, std::string> ov = { {"AdminStatus.Enabled", "1"}, {"AdminStatus.SecretFile", keyFile},
                                                      {"AdminStatus.Port", v == 0 ? std::string("0") : std::to_string(kBr)} };
            const std::string what = v == 0 ? "Port=0" : "Port = порту моста";
            if (Check(Run(srv, dir, ov), "сервер запущен при " + what + " (конфиг загружен, сайдкар и мост слушают)"))
            {
                Check(srv.WaitLog("точка статуса НЕ запущена: ошибка секции [AdminStatus]", 3000), what + ": журнал — ошибка секции, EAC работает без точки");
                PlainClient p73; OpenP73(p73); p73.Send(0x14, {}); std::vector<uint8_t> pl;
                Check(p73.RecvType(0x24, pl, 2000) == 1, what + ": мост отвечает PONG");
                Check(srv.Stop(), what + ": штатный останов");
            }
        }
    }
    // ── S7 (ревизия 61 Н-1): 5 000 учёток с полной историей — такт ядра под опросом точки ─────────────
    {
        printf("-- S7: 5000 игровых сессий, по 20 событий на учётку, опрос точки 10 с (замер такта ядра)\n");
        Server srv;
        if (Check(Run(srv, dir, { {"AdminStatus.Enabled", "1"}, {"AdminStatus.Port", port}, {"AdminStatus.SecretFile", keyFile},
                                  {"AdminStatus.ReqPerSec", "1000"}, {"AdminStatus.ReqBurst", "1000"}, {"General.Mode", "1"},
                                  {"Policy.BindTimeoutSec", "3600"}, {"General.LogLevel", "1"} }), "сервер запущен") && Check(WaitPort(kSt, 3000), "порт точки слушается"))
        {
            const int kN = 5000;
            PlainClient p73; OpenP73(p73);
            uint32_t seq = 1;
            std::vector<uint8_t> batch;
            for (int i = 0; i < kN; ++i)
            {
                const uint32_t ui = 100000 + i; const uint16_t un = (uint16_t)(i + 1);
                for (int k = 0; k < 10; ++k)
                {
                    auto f1 = Frame(0x11, LoginV2(un, ui, 0x0A000000 + i, seq++, RandBind())); batch.insert(batch.end(), f1.begin(), f1.end());
                    auto f2 = Frame(0x12, Logout(un, ui, seq++)); batch.insert(batch.end(), f2.begin(), f2.end());
                }
                auto f3 = Frame(0x11, LoginV2(un, ui, 0x0A000000 + i, seq++, RandBind())); batch.insert(batch.end(), f3.begin(), f3.end());
                if (batch.size() > 200000) { p73.SendRaw(batch); batch.clear(); }
            }
            if (!batch.empty()) p73.SendRaw(batch);
            bool loaded = false;
            for (int t = 0; t < 100 && !loaded; ++t)
            {
                Resp r = Req("/eac/v1/summary", kKey.c_str());
                const Eac::Json::Value* g = r.json && r.js.Get("server") ? r.js.Get("server")->Get("games") : nullptr;
                loaded = g && Num(g, "sessions") == kN;
                if (!loaded) { p73.Send(0x14, {}); Sleep(300); }
            }
            Check(loaded, "5000 игровых сессий в таблице ядра");
            Resp r1 = Req("/eac/v1/account/" + std::to_string(100000 + 777), kKey.c_str());
            const Eac::Json::Value* a1 = r1.json ? r1.js.Get("account") : nullptr;
            Check(a1 && a1->Get("events") && a1->Get("events")->arr.size() == 20, "история учётки — 20 последних событий (предел EventsPerAccount)");
            std::atomic<bool> go{ true }; std::atomic<int> nAcc{ 0 }, nList{ 0 }, nBad{ 0 };
            std::vector<std::thread> th;
            for (int i = 0; i < 4; ++i)
                th.emplace_back([&, i] { uint32_t x = 1234567u * (i + 1); while (go) { x = x * 1103515245u + 12345u; Resp q = Req("/eac/v1/account/" + std::to_string(100000 + (x >> 8) % kN), kKey.c_str());
                    (q.code == 200 ? nAcc : nBad)++; Sleep(5); } });
            th.emplace_back([&] { while (go) { Resp q = Req("/eac/v1/accounts?limit=5000", kKey.c_str()); (q.code == 200 ? nList : nBad)++; Sleep(200); } });
            int64_t t0 = NowMs(), worstPong = 0;
            while (NowMs() - t0 < 10000)
            {
                int64_t p0 = NowMs(); p73.Send(0x14, {});
                std::vector<uint8_t> pl; bool pong = p73.RecvType(0x24, pl, 2000) == 1;
                worstPong = (std::max)(worstPong, pong ? NowMs() - p0 : 9999);
                Sleep(100);
            }
            go = false;
            for (auto& x : th) x.join();
            Resp rs = Req("/eac/v1/summary", kKey.c_str());
            const Eac::Json::Value* core = rs.json && rs.js.Get("server") ? rs.js.Get("server")->Get("core") : nullptr;
            const double pass = Num(core, "pass_max_us"), snapMax = Num(core, "snap_max_us"), builds = Num(core, "snap_builds");
            printf("  ЗАМЕР: запросов учётки %d, списка %d, прочих %d; снимков %.0f; наибольший снимок %.0f мкс; наибольший проход ядра %.0f мкс; худший PONG моста %lld мс\n",
                   nAcc.load(), nList.load(), nBad.load(), builds, snapMax, pass, (long long)worstPong);
            Check(core != nullptr && nAcc > 100 && nList > 5 && nBad == 0, "опрос точки: ответы 200 (учётка и список), прочих нет");
            Check(snapMax >= 0 && snapMax < 15000, "снимок на нити ядра — меньше половины такта TickMs 30 мс (" + std::to_string((long long)snapMax) + " мкс)");
            Check(pass >= 0 && pass < 30000, "наибольший проход ядра под опросом — меньше TickMs 30 мс (" + std::to_string((long long)pass) + " мкс)");
            Check(worstPong < 500, "мост под опросом: худший PONG " + std::to_string((long long)worstPong) + " мс (< 500)");
            srv.Stop();
        }
    }
    return Summary("stand_status");
}
