// Copyright (c) 2026 @sitxovski (Discord)
// e2e_r3rev.cpp — сквозной стенд ревизии R3 (agent-eac-review-r3, 16.10.2026). Всё настоящее, кроме EOS и стоковой сети:
//   • сайдкар — AsdaEacServer_stand.exe --fake-eos --fake-auth (ядро, мост v2, политика ред. 3, AsdaSecure рабочие);
//   • GameServer — stand_r3host.exe (x86): стоковый образ GameServer + ОСНОВНАЯ AsdaPatch.dll (P61 + P73 ред. 3);
//     рукопожатие игрового соединения проходит через настоящий AsdaWire в DLL, bind в LOGIN P73 берёт своим путём из P61;
//   • игровой клиент — КЛИЕНТСКАЯ копия AsdaSecure (AstoryClient/.../AsdaNet/Private/Secure, собрана вне UE, cli_wrap.cpp);
//   • клиент 15901 — роль 4 (SubServer::Eac), REG + BIND (StandCommon.h сайдкара).
// Сценарии: A — bind P73 == bind клиента (ретранслятор моста видит кадры LOGIN целиком), «ПК2 честный + ПК1 бот» → 6,
//   нулевой bind (Legacy) → 6, переиспользование слота; B — прямое соединение с проверкой процесса моста, подмена HELLO pid;
//   C — карусель REG (E1-01) → 4; D — чужая REG с временным отказом не включает FailOpen; E — шквал 15901 при живом P73.
// ★ Копия в стендах AsdaEacServer (agent-eac-r3-server, 16.10.2026, контракт §8.6): прежний F (дефект R3-01) заменён на
//   F — 6 смен персонажа без закрытия канала 15901 (новый BIND на том же канале) и F2 — 7 переподключений канала с того же IP
//   (вытеснение Authenticated в лимит не считается), оба при умолчаниях RegPerAccountMax/Window — без кика;
//   G — R3-03: временные отказы VerifyIdToken повторных REG не освобождают учётку, KICK 3 через Grace;
//   H — R3-04: 5 Legacy-слотов (нулевой bind) у настоящего P73 → «P61 у процесса не активен», причина 6 не применяется,
//   причина 1 работает. Сценарии A–E — без изменений (C задаёт лимит 3/300 явно).
// Запуск: e2e_r3rev.exe <GameServer.exe> <AsdaPatch.dll> <AsdaPatch.map> <stand_r3host.exe>
#include "StandCommon.h"
#include <thread>
#include <atomic>
#include <mutex>

using namespace Stand;

namespace CliGame
{
    struct Chan;
    bool Init();
    Chan* Start(const unsigned char pub64[64], std::vector<unsigned char>& hello);
    int Recv(Chan* c, const unsigned char* d, size_t n, std::vector<unsigned char>& plain);
    bool Ready(Chan* c);
    bool Bind(Chan* c, unsigned char out[32]);
    void Reset(Chan* c);
    void Free(Chan* c);
}

namespace
{
    const int kSide = 26901, kBr = 26902, kCtl = 26903, kRelay = 26904, kId = 18644;
    AsdaSecure::PublicKey g_sidePub;     // ключ сайдкара (канал 15901)
    AsdaSecure::PublicKey g_gamePub;     // ключ GameServer (P61 в хосте)
    std::wstring g_gs, g_dll, g_map, g_hostExe, g_hostDir;

    std::string Hex(const uint8_t* p, size_t n) { static const char* d = "0123456789abcdef"; std::string s; for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; } return s; }
    std::vector<uint8_t> Unhex(const std::string& h) { std::vector<uint8_t> v; for (size_t i = 0; i + 1 < h.size(); i += 2) v.push_back((uint8_t)strtoul(h.substr(i, 2).c_str(), nullptr, 16)); return v; }
    template <class F> bool WaitUntilTrue(F f, int ms) { int64_t e = NowMs() + ms; while (NowMs() < e) { if (f()) return true; Sleep(50); } return f(); }
    std::string Tag(const Bind32& b) { if (b.size() != 32) return "(нет)"; return Hex(b.data(), 4) + "…" + Hex(b.data() + 28, 4); }

    // ── управляющее соединение хоста P73 ──
    struct Host
    {
        PROCESS_INFORMATION pi{}; SOCKET c = INVALID_SOCKET; bool up = false;
        bool Start(int brPort)
        {
            std::wstring cmd = L"\"" + g_hostExe + L"\" \"" + g_gs + L"\" \"" + g_dll + L"\" \"" + g_map + L"\" 1 " + std::to_wstring(brPort) + L" " + std::to_wstring(kCtl);
            SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
            HANDLE out = CreateFileW((g_hostDir + L"host_stdout.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, OPEN_ALWAYS, 0, nullptr);
            SetFilePointer(out, 0, nullptr, FILE_END);
            STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = out; si.hStdError = out;
            std::vector<wchar_t> b(cmd.begin(), cmd.end()); b.push_back(0);
            BOOL ok = CreateProcessW(nullptr, b.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, g_hostDir.c_str(), &si, &pi);
            CloseHandle(out);
            if (!ok) return false;
            int64_t end = NowMs() + 15000;
            while (NowMs() < end) { c = Connect(kCtl, 20000); if (c != INVALID_SOCKET) break; Sleep(100); }
            up = c != INVALID_SOCKET;
            return up;
        }
        std::string Cmd(const std::string& line)
        {
            std::string l = line + "\n"; SendAll(c, l.data(), l.size());
            std::string r; char ch;
            while (recv(c, &ch, 1, 0) == 1) { if (ch == '\n') break; r += ch; }
            return r;
        }
        void Stop()
        {
            if (up) { Cmd("quit"); closesocket(c); c = INVALID_SOCKET; up = false; }
            if (pi.hProcess) { if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); pi = {}; }
            Sleep(300);
        }
        ~Host() { Stop(); }
        // Число из ответа stats по ключу.
        int Stat(const std::string& key) { std::string r = Cmd("stats"); size_t p = r.find(" " + key + " "); return p == std::string::npos ? -1 : atoi(r.c_str() + p + key.size() + 2); }
        // check n → disc, type
        void Check(int slot, int& disc, int& type) { std::string r = Cmd("check " + std::to_string(slot)); disc = -1; type = -1; sscanf_s(r.c_str(), "ok %*d disc %d type %d", &disc, &type); }
    };

    // Игровое соединение клиента через НАСТОЯЩИЙ P61 хоста: accept слота → ClientHello → ServerHello → bind клиента.
    struct GameConn { CliGame::Chan* ch = nullptr; Bind32 bind = Bind32(32, 0); ~GameConn() { if (ch) CliGame::Free(ch); } };
    bool GameHandshake(Host& h, int slot, GameConn& g)
    {
        h.Cmd("conn " + std::to_string(slot) + " 1");
        std::vector<unsigned char> hello;
        if (g.ch) CliGame::Free(g.ch);
        g.ch = CliGame::Start(g_gamePub.xy, hello);
        if (!g.ch) return false;
        std::string r = h.Cmd("rx " + std::to_string(slot) + " " + Hex(hello.data(), hello.size()));
        size_t sp = r.find(' ', 3);
        if (r.compare(0, 3, "ok ") != 0 || sp == std::string::npos) { printf("     rx: %s\n", r.c_str()); return false; }
        std::vector<uint8_t> sh = Unhex(r.substr(sp + 1));
        std::vector<unsigned char> plain;
        int rr = sh.empty() ? -99 : CliGame::Recv(g.ch, sh.data(), sh.size(), plain);
        if (rr != 0 || !CliGame::Ready(g.ch)) { printf("     rx: %.120s… recv=%d ready=%d\n", r.c_str(), rr, (int)CliGame::Ready(g.ch)); return false; }
        return CliGame::Bind(g.ch, g.bind.data());
    }

    // ── ретранслятор моста P73 ↔ сайдкар: видит кадры P73→С целиком ──
    struct Relay
    {
        std::mutex mu; std::map<int, Bind32> loginBind; std::map<int, int> loginCount; std::vector<std::vector<uint8_t>> kicks; int helloVer = -1;
        std::atomic<bool> stop{ false }; std::thread t; SOCKET ls = INVALID_SOCKET;
        void Run()
        {
            WsaInit();
            ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)kRelay); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            BOOL ra = TRUE; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&ra, sizeof(ra));
            bind(ls, (sockaddr*)&a, sizeof(a)); listen(ls, 4);
            t = std::thread([this] {
                while (!stop)
                {
                    SOCKET p = accept(ls, nullptr, nullptr);
                    if (p == INVALID_SOCKET) break;
                    SOCKET s = Connect(kBr, 3000);
                    if (s == INVALID_SOCKET) { closesocket(p); continue; }
                    DWORD inf = 0; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&inf, sizeof(inf));   // без срока приёма (Connect ставит 3 с)
                    std::thread back([this, p, s] {   // С→P73: KICK
                        FrameReader rd; uint8_t b[4096];
                        while (true) { int n = recv(s, (char*)b, sizeof(b), 0); if (n <= 0) break; SendAll(p, b, n); rd.buf.insert(rd.buf.end(), b, b + n);
                            uint8_t ty; std::vector<uint8_t> pl; while (rd.Next(ty, pl)) if (ty == 0x21) { std::lock_guard<std::mutex> g(mu); kicks.push_back(pl); } }
                        shutdown(p, SD_BOTH);
                    });
                    FrameReader rd; uint8_t b[4096];
                    while (true)
                    {
                        int n = recv(p, (char*)b, sizeof(b), 0); if (n <= 0) break;
                        SendAll(s, b, n); rd.buf.insert(rd.buf.end(), b, b + n);
                        uint8_t ty; std::vector<uint8_t> pl;
                        while (rd.Next(ty, pl))
                        {
                            std::lock_guard<std::mutex> g(mu);
                            if (ty == 0x10 && !pl.empty()) helloVer = pl[0];
                            if (ty == 0x11 && pl.size() == 46) { int un = GetU16(pl.data()); loginBind[un] = Bind32(pl.begin() + 14, pl.end()); loginCount[un]++; }
                        }
                    }
                    shutdown(s, SD_BOTH); back.join(); closesocket(s); closesocket(p);
                }
            });
        }
        bool Login(int un, Bind32& b, int count, int ms)
        {
            int64_t e = NowMs() + ms;
            while (NowMs() < e) { { std::lock_guard<std::mutex> g(mu); if (loginCount[un] >= count) { b = loginBind[un]; return true; } } Sleep(50); }
            return false;
        }
        bool Kick(int un, int& reason, int ms)
        {
            int64_t e = NowMs() + ms;
            while (NowMs() < e) { { std::lock_guard<std::mutex> g(mu); for (auto& k : kicks) if (GetU16(k.data()) == un) { reason = k[6]; return true; } } Sleep(50); }
            return false;
        }
        ~Relay() { stop = true; closesocket(ls); if (t.joinable()) t.join(); }
    };

    bool StartSide(Server& srv, const std::string& name, const std::map<std::string, std::string>& ov)
    {
        std::wstring dir = RunDir(name, true);
        if (!MakeSecureKey(dir, g_sidePub)) return false;
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, ov);
        return srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide);
    }
    struct Pinger
    {
        std::atomic<bool> stop{ false }; std::thread t;
        explicit Pinger(SecureClient& c) : t([this, &c] { while (!stop && !c.closed) { c.Send(0x04, {}); for (int i = 0; i < 5 && !stop; ++i) Sleep(100); } }) {}
        ~Pinger() { stop = true; if (t.joinable()) t.join(); }
    };
    // Ждать, пока P73 получит KICK (kickRecv вырос).
    bool WaitKickRecv(Host& h, int from, int ms) { int64_t e = NowMs() + ms; while (NowMs() < e) { if (h.Stat("kickRecv") > from) return true; Sleep(100); } return false; }
    std::map<std::string, std::string> Base(const std::string& checkPeer)
    {
        std::map<std::string, std::string> ov = { {"General.Mode", "2"}, {"General.FailOpen", "0"}, {"Policy.BindTimeoutSec", "3"}, {"Policy.GraceSec", "2"},
                                                  {"Policy.KickRepeatSec", "30"}, {"Bridge.CheckPeerProcess", checkPeer} };
        if (checkPeer == "1")
        {
            std::wstring d = g_hostDir; d.pop_back();
            ov["Bridge.AllowedImageNames"] = "stand_r3host.exe"; ov["Bridge.AllowedImageDirs"] = U8(d);
        }
        return ov;
    }
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 5) { printf("usage: e2e_r3rev <GameServer.exe> <AsdaPatch.dll> <AsdaPatch.map> <stand_r3host.exe>\n"); return 2; }
    g_gs = argv[1]; g_dll = argv[2]; g_map = argv[3]; g_hostExe = argv[4];
    g_hostDir = g_hostExe.substr(0, g_hostExe.find_last_of(L"\\/") + 1);
    AsdaSecure::Init(); CliGame::Init(); WsaInit();
    Check(MakeSecureKey(g_hostDir, g_gamePub), "ключ AsdaSecure GameServer (secure_server.key рядом с хостом P73)");
    const char* only = getenv("R3_ONLY");
    auto want = [&](char s) { return !only || strchr(only, s); };

    if (want('A'))
    {
        printf("\n== A: bind — настоящий P61/P73 (DLL основной AsdaPatch) против клиентской копии AsdaSecure; мост через ретранслятор ==\n");
        Server srv; Check(StartSide(srv, "r3a", Base("0")), "A: сайдкар (Mode 2, BindTimeout 3, Grace 2; CheckPeerProcess=0 — между P73 и сайдкаром ретранслятор)");
        Relay rl; rl.Run();
        Host h; Check(h.Start(kRelay), "A: хост P73 запущен (P61+P73 установлены, ctl)");
        Check(WaitUntilTrue([&] { std::lock_guard<std::mutex> g(rl.mu); return rl.helloVer == 2; }, 8000), "A: P73 прислал HELLO ver=2");
        GameConn g7, g9, g11;
        bool k7 = GameHandshake(h, 7, g7); Check(k7, "A: игровое соединение слота 7 — рукопожатие клиентской копии ↔ P61 DLL, bind клиента " + Tag(g7.bind));
        bool k9 = GameHandshake(h, 9, g9); Check(k9, "A: слот 9 (бот ПК1, учётка 75002), bind " + Tag(g9.bind));
        bool k11 = GameHandshake(h, 11, g11); Check(k11, "A: слот 11 (честный ПК2 той же учётки, в мир не вошёл), bind " + Tag(g11.bind));
        Check(g7.bind != g9.bind && g9.bind != g11.bind && g7.bind != g11.bind && g7.bind != ZeroBind(), "A: bind трёх соединений попарно различны и ненулевые");
        h.Cmd("user 7 75001"); h.Cmd("user 9 75002"); h.Cmd("user 11 75002");
        h.Cmd("l4001 7 75001"); h.Cmd("l4001 9 75002");
        Bind32 lb7, lb9;
        bool l7 = rl.Login(7, lb7, 1, 3000); Check(l7 && lb7 == g7.bind, "A: LOGIN.bind слота 7 из P73 == bind клиента (32 б): " + Hex(lb7.data(), lb7.size()) + " == " + Hex(g7.bind.data(), 32));
        Check(rl.Login(9, lb9, 1, 3000) && lb9 == g9.bind, "A: LOGIN.bind слота 9 == bind клиента слота 9");
        Check(lb7 != g9.bind && lb7 != g11.bind, "A: LOGIN.bind слота 7 ≠ bind других соединений");
        Check(h.Stat("loginBindZero") == 0, "A: P73 — нулевых bind в LOGIN нет");
        // честный клиент учётки 75001: REG + BIND своего соединения
        SecureClient e1; Check(EacRegister(e1, kSide, g_sidePub, 75001, 1) == 0 && EacBind(e1, 2, g7.bind) == 0, "A: EAC 75001 — REG_RESULT 0, BIND (bind игрового слота 7) → 0");
        Pinger p1(e1);
        // ПК2 честный (учётка 75002, своё соединение слота 11), ПК1 бот играет слотом 9
        SecureClient e2; Check(EacRegister(e2, kSide, g_sidePub, 75002, 2) == 0 && EacBind(e2, 2, g11.bind) == 0, "A: ПК2 — EAC 75002 Authenticated, BIND своего (не игрового) соединения");
        Pinger p2(e2);
        int reason = -1;
        Check(rl.Kick(9, reason, 6000) && reason == 6, "A: «ПК2 честный + ПК1 бот» — сайдкар → P73 KICK причина 6 (" + std::to_string(reason) + ")");
        Check(WaitKickRecv(h, 0, 2000), "A: P73 принял KICK");
        int disc, type; h.Check(9, disc, type);
        Check(disc == 1 && type == 6, "A: P73 выполнил кик слота 9 штатной парой стока в нити карты: 4101 тип " + std::to_string(type) + " (ожидается 6, E1-07)");
        h.Check(7, disc, type);
        Check(disc == 0 && srv.LogHas("userNum 7 (сервер 2 pid") && srv.LogHas("игровая сессия ЗАЩИЩЕНА"), "A: слот 7 (bind совпал) — защищён, кика нет");
        // нулевой bind: слот 13 старым клиентом (Legacy)
        h.Cmd("conn 13 1"); h.Cmd("rx 13 0b00a00f0102030405060708");
        h.Cmd("user 13 75003"); h.Cmd("l4001 13 75003");
        Bind32 lb13; Check(rl.Login(13, lb13, 1, 3000) && lb13 == ZeroBind() && h.Stat("loginBindZero") == 1, "A: слот Legacy — LOGIN с нулевым bind (счётчик P73 loginBindZero 1)");
        SecureClient e3; Check(EacRegister(e3, kSide, g_sidePub, 75003, 3) == 0 && EacBind(e3, 2, g7.bind) == 0, "A: EAC 75003 Authenticated (BIND чужого bind слота 7)");
        Pinger p3(e3);
        Check(rl.Kick(13, reason, 6000) && reason == 6 && srv.LogHas("нулевой bind"), "A: нулевой bind → KICK 6 «нулевой bind игрового соединения»");
        // переиспользование слота 7: разрыв → bind затирается; новое соединение — новый bind
        h.Cmd("conn 7 0");
        h.Cmd("l4001 7 75001");   // логон без нового рукопожатия (в стоке невозможен) — проверка затирания bind слота
        Bind32 lz; Check(rl.Login(7, lz, 2, 3000) && lz == ZeroBind(), "A: после разрыва слота 7 bind затёрт (LOGIN несёт нули)");
        GameConn g7b; bool k7b = GameHandshake(h, 7, g7b); Check(k7b && g7b.bind != g7.bind, "A: новое соединение на слоте 7 — новый bind " + Tag(g7b.bind));
        h.Cmd("l4001 7 75001");
        Bind32 lb7b; Check(rl.Login(7, lb7b, 3, 3000) && lb7b == g7b.bind, "A: LOGIN нового соединения слота 7 несёт новый bind == bind клиента");
        Check(EacBind(e1, 2, g7b.bind) == 0, "A: клиент шлёт BIND после нового рукопожатия");
        Sleep(4000);
        { int r7 = -1; bool k7 = false; { std::lock_guard<std::mutex> g(rl.mu); for (auto& k : rl.kicks) if (GetU16(k.data()) == 7) { k7 = true; r7 = k[6]; } } Check(!k7, "A: слот 7 после перепривязки — без KICK" + (k7 ? " (пришёл " + std::to_string(r7) + ")" : std::string())); }
        CliGame::Reset(g7b.ch); unsigned char tmp[32]; Check(!CliGame::Bind(g7b.ch, tmp), "A: клиентская копия — после Reset ChannelBinding = false (затирание)");
        p1.stop = p2.stop = p3.stop = true;
        h.Stop(); srv.Stop();
    }
    if (want('B'))
    {
        printf("\n== B: прямое соединение P73 → сайдкар, проверка процесса моста (CheckPeerProcess=1) ==\n");
        Server srv; Check(StartSide(srv, "r3b", Base("1")), "B: сайдкар (AllowedImageNames=stand_r3host.exe из папки хоста)");
        Host h; Check(h.Start(kBr), "B: хост P73");
        Check(srv.WaitLog("HELLO v2", 8000) && srv.LogHas("stand_r3host.exe"), "B: соединение P73 принято: владелец stand_r3host.exe, HELLO v2");
        GameConn g5, g6; Check(GameHandshake(h, 5, g5) && GameHandshake(h, 6, g6), "B: два игровых соединения");
        h.Cmd("user 5 76001"); h.Cmd("user 6 76002"); h.Cmd("l4001 5 76001"); h.Cmd("l4001 6 76002");
        SecureClient c5; Check(EacRegister(c5, kSide, g_sidePub, 76001, 5) == 0 && EacBind(c5, 2, g5.bind) == 0, "B: EAC 76001 + BIND своего");
        Pinger q5(c5);
        SecureClient c6; Check(EacRegister(c6, kSide, g_sidePub, 76002, 6) == 0 && EacBind(c6, 2, g5.bind) == 0, "B: EAC 76002 шлёт BIND ЧУЖОГО соединения (76001)");
        Pinger q6(c6);
        Check(WaitKickRecv(h, 0, 6000), "B: P73 получил KICK");
        int disc, type; h.Check(6, disc, type); Check(disc == 1 && type == 6, "B: слот 6 (чужой bind) кикнут, тип 6");
        h.Check(5, disc, type); Check(disc == 0, "B: слот 5 не кикнут");
        Check(srv.LogHas("userNum 6") && srv.LogHas("причина 6"), "B: причина 6 в журнале сайдкара");
        // подмена: свой процесс подключается к мосту и называется pid хоста
        DWORD hostPid = 0; { std::string r = srv.Log(); size_t p = r.find("HELLO v2"); if (p != std::string::npos) { size_t q = r.find("pid ", p); if (q != std::string::npos) hostPid = (DWORD)atoi(r.c_str() + q + 4); } }
        PlainClient fake; bool op = fake.Open(kBr);
        if (op) fake.Send(0x10, HelloV(2, 2, hostPid, 15601));
        uint8_t ty; std::vector<uint8_t> pl; int fr = op ? fake.Recv(ty, pl, 3000) : -1;
        Check(op && fr == -1 && srv.WaitLog("соединение отклонено: образ", 2000), "B: чужой процесс (e2e_r3rev.exe) с HELLO pid хоста " + std::to_string(hostPid) + " — отклонён по образу владельца");
        Sleep(500);
        h.Check(5, disc, type); Check(disc == 0 && h.Stat("disconnects") == 0, "B: таблица P73 не сброшена подменой, мост не рвался");
        q5.stop = q6.stop = true;
        h.Stop(); srv.Stop();
    }
    if (want('C'))
    {
        printf("\n== C: карусель REG (E1-01) — бот знает bind своего соединения, но без клиента EAC ==\n");
        auto ov = Base("1"); ov["Sidecar.RegPerAccountMax"] = "3"; ov["Sidecar.RegPerAccountWindowSec"] = "300";
        // ★ Д1 (22.11.2026): решение по неаутентифицированной сессии — не раньше AuthTimeout от REG и не позже BindTimeout + AuthTimeout + Grace
        //   от LOGIN; стенду AuthTimeout 3 с (на стойке 90), иначе ждать 95 с
        ov["Sidecar.AuthTimeoutSec"] = "3";
        Server srv; Check(StartSide(srv, "r3c", ov), "C: сайдкар, RegPerAccountMax=3/300 с");
        Host h; Check(h.Start(kBr), "C: хост P73");
        GameConn g15; Check(GameHandshake(h, 15, g15), "C: игровое соединение бота (слот 15) — бот сам вывел bind");
        h.Cmd("user 15 77001"); h.Cmd("l4001 15 77001");
        int st[4] = { -1, -1, -1, -1 };
        std::vector<std::unique_ptr<SecureClient>> cs;
        for (int i = 0; i < 4; ++i)
        {
            cs.emplace_back(new SecureClient());
            st[i] = EacRegister(*cs.back(), kSide, g_sidePub, 77001, 100 + i, { {"auth", i % 2 ? "local" : "none"} });
            if (st[i] == 0) EacBind(*cs.back(), 2, g15.bind);
            Sleep(300);
        }
        Check(st[0] == 0 && st[1] == 0 && st[2] == 0 && st[3] == 3, "C: REG 1–3 приняты, 4-я → REG_RESULT 3 (" + std::to_string(st[0]) + std::to_string(st[1]) + std::to_string(st[2]) + std::to_string(st[3]) + ")");
        Check(WaitKickRecv(h, 0, 9000), "C: P73 получил KICK для бота (не позже BindTimeout + AuthTimeout + Grace — карусель срок не продлевает)");
        int disc, type; h.Check(15, disc, type);
        Check(disc == 1 && type == 6 && srv.LogHas("причина 4"), "C: бот с BIND своего соединения, но без RemoteAuthComplete — кикнут (причина 4), тип 6");
        h.Stop(); srv.Stop();
    }
    if (want('D'))
    {
        printf("\n== D: FailOpen=1 — чужая REG с временным отказом Epic не освобождает всех ==\n");
        auto ov = Base("1"); ov["General.FailOpen"] = "1"; ov["General.FailOpenStartupSec"] = "0";
        Server srv; Check(StartSide(srv, "r3d", ov), "D: сайдкар FailOpen=1, без стартового окна");
        Host h; Check(h.Start(kBr), "D: хост P73");
        SecureClient atk; Check(EacRegister(atk, kSide, g_sidePub, 1, 99, { {"eosres", "TooManyRequests"} }) == 3, "D: мусорная REG с временным отказом → 3");
        GameConn g17; Check(GameHandshake(h, 17, g17), "D: игровое соединение игрока без EAC");
        h.Cmd("user 17 78001"); h.Cmd("l4001 17 78001");
        Check(WaitKickRecv(h, 0, 6000), "D: P73 получил KICK");
        int disc, type; h.Check(17, disc, type);
        Check(disc == 1 && !srv.LogHas("Epic недоступен"), "D: игрок без EAC кикнут, «Epic недоступен» не объявлен");
        h.Stop(); srv.Stop();
    }
    if (want('E'))
    {
        printf("\n== E: шквал 15901 (300 нитей, один IP) при живом мосте P73 ==\n");
        auto ov = Base("1");
        ov["Sidecar.MaxUnregPerIp"] = "16"; ov["Sidecar.ConnectRatePerIp"] = "5"; ov["Sidecar.ConnectBurstPerIp"] = "20";
        ov["Sidecar.ConnectRateGlobal"] = "300"; ov["Sidecar.ConnectBurstGlobal"] = "600"; ov["Sidecar.RegPerIpPerMin"] = "10"; ov["General.LogLevel"] = "2";
        Server srv; Check(StartSide(srv, "r3e", ov), "E: сайдкар, приём по умолчанию");
        Host h; Check(h.Start(kBr), "E: хост P73");
        GameConn g3; Check(GameHandshake(h, 3, g3), "E: защищённый игрок (слот 3)");
        h.Cmd("user 3 79001"); h.Cmd("l4001 3 79001");
        SecureClient c3; Check(EacRegister(c3, kSide, g_sidePub, 79001, 3, {}, "127.0.0.30") == 0 && EacBind(c3, 2, g3.bind) == 0, "E: EAC 79001 + BIND (свой IP)");
        int pong0 = h.Stat("pong");
        std::atomic<bool> stop{ false }; std::atomic<long> hs{ 0 }; std::vector<std::thread> th;
        for (int i = 0; i < 300; ++i) th.emplace_back([&] { while (!stop) { SecureClient c; if (c.Open(kSide, g_sidePub) && c.Handshake(2000)) ++hs; } });
        Sleep(1000);
        GameConn g4; GameHandshake(h, 4, g4); h.Cmd("user 4 79002"); h.Cmd("l4001 4 79002");   // бот входит посреди шквала
        int64_t worst = 0, t1 = NowMs();
        while (NowMs() - t1 < 6000)
        {
            int64_t s0 = NowMs(); c3.Send(0x04, {}); std::vector<uint8_t> p;
            if (c3.RecvType(0x84, p, 3000) != 1) { worst = 99999; break; }
            worst = (std::max)(worst, NowMs() - s0); Sleep(100);
        }
        int kickDuring = h.Stat("kickRecv");
        stop = true; for (auto& t : th) t.join();
        printf("     рукопожатий за 7 с: %ld, худший PONG: %lld мс, PONG моста P73 за шквал: %d\n", hs.load(), (long long)worst, h.Stat("pong") - pong0);
        Check(worst < 200, "E: PONG клиенту 15901 во время шквала < 200 мс (" + std::to_string(worst) + ")");
        Check(h.Stat("pong") - pong0 >= 1 && h.Stat("disconnects") == 0, "E: мост P73 обслуживался (PONG пришли, разрывов нет)");
        int disc, type; h.Check(4, disc, type);
        Check(kickDuring >= 1 && disc == 1, "E: бот, вошедший во время шквала, кикнут вовремя (KICK во время шквала)");
        h.Check(3, disc, type); Check(disc == 0, "E: защищённый игрок не кикнут");
        h.Stop(); srv.Stop();
    }
    if (want('F'))
    {
        printf("\n== F: §8.6 R3-01 — честный клиент, 6 смен персонажа БЕЗ закрытия канала 15901 (новый BIND на том же канале), умолчания лимита REG ==\n");
        auto ov = Base("1"); ov["Sidecar.RegPerAccountMax"] = kIniDefault; ov["Sidecar.RegPerAccountWindowSec"] = kIniDefault;
        Server srv; Check(StartSide(srv, "r3f", ov), "F: сайдкар (RegPerAccountMax/Window — умолчания сервера)");
        Check(srv.WaitLog("REG на учётку 6/600 с", 3000), "F: журнал старта: REG на учётку 6/600 с");
        Host h; Check(h.Start(kBr), "F: хост P73");
        int kick0 = h.Stat("kickRecv");
        GameConn g; Check(GameHandshake(h, 20, g), "F: игровое соединение слота 20");
        h.Cmd("user 20 80101"); h.Cmd("l4001 20 80101");
        SecureClient c; Check(EacRegister(c, kSide, g_sidePub, 80101, 20) == 0 && EacBind(c, 2, g.bind) == 0, "F: одна REG канала 15901 + BIND игрового соединения");
        Pinger pc(c);
        int binds = 0, changes = 0;
        for (int i = 0; i < 6; ++i)
        {
            Sleep(700);
            h.Cmd("conn 20 0");                          // смена персонажа: игровое соединение к выбору персонажа закрыто
            Sleep(300);
            GameConn gn; bool hs = GameHandshake(h, 20, gn);
            h.Cmd("user 20 80101"); h.Cmd("l4001 20 80101");
            binds += hs && EacBind(c, 2, gn.bind) == 0;   // канал 15901 тот же — только новый BIND
            changes += hs;
        }
        Check(changes == 6 && binds == 6, "F: 6 смен персонажа: 6 новых рукопожатий и 6 BIND на том же канале (" + std::to_string(binds) + ")");
        Sleep(6000);                                     // > BindTimeout 3 + Grace 2
        int disc, type; h.Check(20, disc, type);
        Check(h.Stat("kickRecv") == kick0 && disc == 0, "F: за 6 смен персонажа и BindTimeout+Grace — KICK нет");
        Check(srv.LogCount("учётка 80101 зарегистрирована в EAC") == 1 && !srv.LogHas("учётка 80101: REG сверх"), "F: REG одна, предела нет");
        Check(srv.LogCount("userNum 20 (сервер 2 pid") >= 7 && srv.LogCount("игровая сессия ЗАЩИЩЕНА") >= 7, "F: каждая новая игровая сессия ЗАЩИЩЕНА");
        pc.stop = true;
        // F2: 7 переподключений канала 15901 с того же IP (обрыв сети) — каждая REG вытесняет аутентифицированную сессию → в лимит не идёт.
        printf("-- F2: 7 переподключений канала 15901 с того же IP — вытеснение Authenticated в лимит REG не считается\n");
        GameConn g2; Check(GameHandshake(h, 21, g2), "F2: игровое соединение слота 21");
        h.Cmd("user 21 80102"); h.Cmd("l4001 21 80102");
        int ok7 = 0; std::vector<std::unique_ptr<SecureClient>> cs;
        for (int i = 0; i < 7; ++i)
        {
            cs.emplace_back(new SecureClient());
            ok7 += EacRegister(*cs.back(), kSide, g_sidePub, 80102, 21) == 0 && EacBind(*cs.back(), 2, g2.bind) == 0;
            Sleep(500);
        }
        Pinger pl(*cs.back());
        Check(ok7 == 7, "F2: 7 REG подряд с одного IP — все REG_RESULT 0 (" + std::to_string(ok7) + ")");
        Check(srv.LogCount("учётка 80102: REG вытесняет аутентифицированную EAC-сессию") == 6, "F2: журнал: 6 вытеснений «в лимит REG не считается»");
        Sleep(4000);
        h.Check(21, disc, type);
        Check(h.Stat("kickRecv") == kick0 && disc == 0, "F2: KICK нет");
        pl.stop = true;
        h.Stop(); srv.Stop();
    }
    if (want('G'))
    {
        printf("\n== G: §8.6 R3-03 — временные отказы VerifyIdToken повторных REG учётку от кика не освобождают ==\n");
        auto ov = Base("1"); ov["General.FailOpen"] = "1"; ov["General.FailOpenStartupSec"] = "0"; ov["General.EpicDownHoldSec"] = "30"; ov["Policy.VerifyWaitSec"] = "0";
        Server srv; Check(StartSide(srv, "r3g", ov), "G: сайдкар FailOpen=1 (пороги по умолчанию), Grace 2");
        Host h; Check(h.Start(kBr), "G: хост P73");
        GameConn g; Check(GameHandshake(h, 22, g), "G: игровое соединение слота 22");
        h.Cmd("user 22 80201"); h.Cmd("l4001 22 80201");
        int kick0 = h.Stat("kickRecv");
        { SecureClient e; Check(EacRegister(e, kSide, g_sidePub, 80201, 22) == 0 && EacBind(e, 2, g.bind) == 0, "G: учётка 80201 защищена (PUID подтверждён Epic)");
          Pinger pe(e); Check(srv.WaitLog("userNum 22 (сервер 2 pid", 4000) && srv.WaitLog("игровая сессия ЗАЩИЩЕНА", 2000), "G: игровая сессия ЗАЩИЩЕНА"); pe.stop = true; e.Close(); }
        int64_t t0 = NowMs();
        int tr = 0, n = 0; bool kicked = false;
        while (NowMs() - t0 < 9000 && !kicked)
        {
            SecureClient b; tr += EacRegister(b, kSide, g_sidePub, 80201, 22, { {"eosres", "ServiceFailure"} }) == 3; ++n;   // бот: тот же PUID, временный отказ
            kicked = WaitKickRecv(h, kick0, 700);
        }
        int64_t dt = NowMs() - t0;
        int disc, type; h.Check(22, disc, type);
        Check(n > 0 && tr == n, "G: REG бота с PUID учётки — временный отказ Epic → REG_RESULT 3 (" + std::to_string(tr) + " из " + std::to_string(n) + ")");
        Check(kicked && disc == 1 && type == 6 && dt >= 1800 && dt <= 6500, "G: KICK (кик P73 тип 6) через Grace (" + std::to_string(dt) + " мс) — временные отказы не продлевают");
        Check(srv.LogHas("учётка 80201 userNum 22, причина 3"), "G: журнал: причина 3 «канал 15901 потерян дольше Grace»");
        Check(!srv.LogHas("не кикать до повторной REG") && !srv.LogHas("Epic недоступен"), "G: журнал: освобождения учётки нет, глобального «Epic недоступен» нет (один IP)");
        h.Stop(); srv.Stop();
    }
    if (want('H'))
    {
        printf("\n== H: §8.6 R3-04 — настоящий P73: 5 LOGIN с нулевым bind (Legacy) → «P61 у процесса не активен» ==\n");
        Server srv; Check(StartSide(srv, "r3h", Base("1")), "H: сайдкар Mode 2");
        Host h; Check(h.Start(kBr), "H: хост P73 (P61 поставлен, клиенты — старые: Legacy)");
        SecureClient e30; Check(EacRegister(e30, kSide, g_sidePub, 80430, 30) == 0, "H: учётка 80430 — EAC аутентифицирована (bind у старого клиента нет — BIND не шлёт)");
        Pinger p30(e30);
        for (int sl = 30; sl <= 34; ++sl)
        {
            h.Cmd("conn " + std::to_string(sl) + " 1"); h.Cmd("rx " + std::to_string(sl) + " 0b00a00f0102030405060708");   // Legacy-клиент
            h.Cmd("user " + std::to_string(sl) + " " + std::to_string(80400 + sl)); h.Cmd("l4001 " + std::to_string(sl) + " " + std::to_string(80400 + sl));
        }
        Check(h.Stat("loginBindZero") == 5, "H: P73 — 5 LOGIN с нулевым bind (loginBindZero " + std::to_string(h.Stat("loginBindZero")) + ")");
        Check(srv.WaitLog("P61 у процесса не активен: GameServer pid", 3000), "H: журнал сайдкара: «P61 у процесса не активен» (5 LOGIN за 120 с после HELLO, все нулевые)");
        Check(WaitKickRecv(h, 0, 7000), "H: P73 получил KICK");
        Sleep(1500);
        int disc, type;
        h.Check(31, disc, type);
        Check(disc == 1 && type == 6 && srv.LogHas("учётка 80431 userNum 31, причина 1"), "H: учётка без EAC (слот 31) — KICK причина 1 по-прежнему, кик P73 тип 6");
        h.Check(30, disc, type);
        Check(disc == 0 && srv.LogHas("без bind: P61 у процесса не активен") && !srv.LogHas("учётка 80430 userNum 30, причина 6"),
              "H: учётка 80430 (EAC аутентифицирована, нулевой bind) — защищена без bind, причина 6 не применена");
        p30.stop = true;
        h.Stop(); srv.Stop();
    }
    printf("\n");
    return Summary("e2e_r3rev (ревизия R3, настоящие P61/P73 + клиентская копия AsdaSecure)");
}
