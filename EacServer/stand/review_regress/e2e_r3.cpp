// Copyright (c) 2026 @sitxovski (Discord)
// e2e_r3.cpp — сквозной стенд ревизора (eac/review_e1/e2e/e2e_eac.cpp, agent-eac-review), адаптированный под ред. 3 контракта
// (agent-eac-server-fix, 16.10.2026). Исходник ревизора не меняется; это копия со сценариями под bind и Authenticated.
//   Сайдкар — настоящий AsdaEacServer_stand.exe (--fake-eos: EOS имитируется, ядро/мост/AsdaSecure рабочие).
//   S0 — НАСТОЯЩИЙ P73 (review_e1/e2e/bin/stand_e2e.exe, x86, DLL AsdaPatch_w73 — протокол моста v1): по ред. 3 сайдкар обязан
//        отвергнуть HELLO ver=1 с записью в журнал; P73 v2 (bind из P61) делает исполнитель P73 — когда он появится, S0 должен
//        показать HELLO v2 (стенд это различает и пишет).
//   S1–S4 — P73 v2 имитируется в этом процессе (кадры §4 + bind §8.1), клиенты 15901 — по AsdaSecure с ролью 4, REG + BIND.
//   S4.2 — сценарий дефекта E1-03: одна чужая REG с временным отказом Epic больше НЕ отключает кики.
//   S5 — сценарий дефекта E1-04: шквал рукопожатий с одного IP (12 и 300 нитей), настройки приёма по умолчанию: PONG
//        зарегистрированному < 200 мс, журнал растёт сводками.
// Запуск: e2e_r3.exe [<GameServer.exe> <AsdaPatch.dll> <stand_e2e.exe>] (без аргументов S0 пропускается).
#include "StandCommon.h"
#include <string>
#include <thread>
#include <atomic>
#include <algorithm>

using namespace Stand;

namespace
{
    const int kSide = 25801, kBr = 25802, kCtl = 25803, kId = 18544;   // порты стенда (как у ревизора)
    AsdaSecure::PublicKey g_pub;

    // Фальшивый P73 v2 (один процесс сервера: kind, pid).
    struct FakeP73
    {
        PlainClient c; uint8_t kind = 2; uint32_t pid = 0; uint32_t seq = 0;
        bool Open(uint8_t k, uint32_t p) { kind = k; pid = p; if (!c.Open(kBr)) return false; return c.Send(0x10, HelloV(2, k, p, k == 2 ? 15601 : 15651)); }
        void Login(uint16_t un, uint32_t ui, const Bind32& b) { c.Send(0x11, LoginV2(un, ui, 0x7F000001, ++seq, b)); }
        void Logout(uint16_t un, uint32_t ui) { std::vector<uint8_t> p; PutU16(p, un); PutU32(p, ui); PutU32(p, ++seq); c.Send(0x12, p); }
        void Rebind(uint16_t un, uint32_t oldUi, uint32_t sessUi, const Bind32& b) { c.Send(0x13, RebindV2(un, oldUi, sessUi, ++seq, b)); }
        void Ping() { c.Send(0x14, {}); }
        // Ждать KICK (1/0/-1); kick — userNum, учётка, причина.
        int Kick(uint16_t& un, uint32_t& ui, uint8_t& reason, int ms)
        {
            std::vector<uint8_t> p; int r = c.RecvType(0x21, p, ms);
            if (r == 1 && p.size() == 8) { un = GetU16(p.data()); ui = GetU32(p.data() + 2); reason = p[6]; }
            return r;
        }
    };

    // Клиент EAC: REG + BIND игрового канала. true — REG_RESULT 0 и BIND_RESULT 0.
    bool EacUp(SecureClient& cl, uint32_t ui, uint32_t puidN, const Bind32& b, const std::map<std::string, std::string>& extra = {})
    {
        return EacRegister(cl, kSide, g_pub, ui, puidN, extra) == 0 && EacBind(cl, 2, b) == 0;
    }

    bool StartServer(Server& srv, const std::string& name, const std::map<std::string, std::string>& ov, bool clean = true)
    {
        std::wstring dir = RunDir(name, clean);
        if (clean && !MakeSecureKey(dir, g_pub)) return false;
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, ov);
        return srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide);
    }

    template <class F> bool WaitUntil(F f, int ms) { int64_t e = NowMs() + ms; while (NowMs() < e) { if (f()) return true; Sleep(100); } return f(); }

    // Пингер канала EAC в отдельной нити (PING каждые 0,5 с, пока не stop).
    struct Pinger
    {
        std::atomic<bool> stop{ false }; std::thread t;
        explicit Pinger(SecureClient& c) : t([this, &c] { while (!stop && !c.closed) { c.Send(0x04, {}); for (int i = 0; i < 5 && !stop; ++i) Sleep(100); } }) {}
        ~Pinger() { stop = true; if (t.joinable()) t.join(); }
    };
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    AsdaSecure::Init();
    WsaInit();
    const std::map<std::string, std::string> base = { {"General.Mode", "2"}, {"General.FailOpen", "0"}, {"Policy.BindTimeoutSec", "3"},
                                                      {"Policy.GraceSec", "2"}, {"Policy.KickRepeatSec", "30"}, {"Bridge.OrphanSec", "120"},
                                                      {"Bridge.CheckPeerProcess", "0"} };
    const bool only5 = _wgetenv(L"E2E_ONLY5") != nullptr;
    if (!only5 && argc >= 4)
    {
        // ═══ S0: настоящий P73 (DLL w73, мост v1) против сайдкара ред. 3 ═══
        printf("\n== S0: настоящий P73 (stand_e2e.exe + AsdaPatch_w73) — HELLO ver=1 должен быть отвергнут ==\n");
        std::wstring stand = argv[3];
        std::wstring standDir = stand.substr(0, stand.find_last_of(L"\\/"));
        auto ov = base; ov["Bridge.CheckPeerProcess"] = "1"; ov["Bridge.AllowedImageNames"] = "stand_e2e.exe"; ov["Bridge.AllowedImageDirs"] = U8(standDir);
        Server srv; Check(StartServer(srv, "s0", ov), "S0: сайдкар (проверка процесса моста: stand_e2e.exe из папки стенда ревизора)");
        std::wstring cmd = L"\"" + stand + L"\" \"" + argv[1] + L"\" \"" + argv[2] + L"\" 1 " + std::to_wstring(kBr) + L" " + std::to_wstring(kCtl);
        STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        std::vector<wchar_t> b(cmd.begin(), cmd.end()); b.push_back(0);
        bool started = CreateProcessW(nullptr, b.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, standDir.c_str(), &si, &pi) != 0;
        Check(started, "S0: stand_e2e.exe (x86, настоящая DLL P73) запущен");
        bool v1 = srv.WaitLog("HELLO ver=1 от pid", 15000), v2 = srv.LogHas("HELLO v2");
        if (v2) Check(true, "S0: настоящий P73 прислал HELLO v2 (P73 ред. 3 уже на месте)");
        else Check(v1 && srv.LogHas("ОТКАЗ: мост v1 (LOGIN без bind) не поддерживается"), "S0: настоящий P73 v1 → HELLO ver=1 отвергнут с записью в журнал (контракт §8.1)");
        Check(srv.LogHas("соединение P73") && srv.LogHas("stand_e2e.exe"), "S0: мост проверил процесс-владельца соединения (образ stand_e2e.exe)");
        if (started)
        {
            SOCKET c = Connect(kCtl, 3000);
            if (c != INVALID_SOCKET) { SendAll(c, "quit\n", 5); Sleep(300); closesocket(c); }
            if (WaitForSingleObject(pi.hProcess, 3000) != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            // stand_e2e перезапускает себя дочерним процессом — дочерний тоже закрыть (он держит соединение моста)
            srv.Stop();
            Sleep(500);
        }
    }
    if (!only5)
    {
        // ═══ S1: Mode 2 — BindTimeout, гонка LOGIN→REG, две сессии одной учётки, Grace, REBIND, вытеснение, рестарт сайдкара ═══
        printf("\n== S1: Mode=2, FailOpen=0, BindTimeout=3, Grace=2; P73 v2 (имитация) ==\n");
        Server srv;
        Check(StartServer(srv, "s1", base), "S1: сайдкар запущен");
        FakeP73 gs; Check(gs.Open(2, 424200), "S1: P73 GameServer (HELLO v2)");
        uint16_t un; uint32_t ui; uint8_t rs;
        // S1.1 нет EAC → KICK 1
        int64_t t0 = NowMs();
        gs.Login(7, 75001, RandBind());
        gs.Ping();
        int kr = gs.Kick(un, ui, rs, 6000); int64_t dt = NowMs() - t0;
        Check(kr == 1 && un == 7 && ui == 75001 && rs == 1 && dt >= 2700, "S1.1: нет EAC → KICK 1 через BindTimeout (" + std::to_string(dt) + " мс)");
        gs.Logout(7, 75001);
        // S1.2 гонка: LOGIN раньше REG на 1,5 с (REG + BIND) — кика нет
        Bind32 b9 = RandBind();
        gs.Login(9, 75002, b9);
        Sleep(1500);
        SecureClient a;
        Check(EacUp(a, 75002, 2, b9), "S1.2: REG + BIND учётки 75002 через 1,5 с после LOGIN");
        Pinger pa(a);
        // S1.6 вторая игровая сессия той же учётки (Indun, другое соединение): клиент шлёт BIND и для него
        FakeP73 ind; Check(ind.Open(3, 424242), "S1.6: второй процесс сервера (Indun) подключился к мосту");
        Bind32 b30 = RandBind();
        ind.Login(30, 75002, b30);
        Check(EacBind(a, 2, b30) == 0, "S1.6: BIND Indun-канала (serverKind клиент шлёт 2 — сверяется только bind)");
        gs.Ping(); ind.Ping();
        Check(gs.Kick(un, ui, rs, 4500) == 0, "S1.2: кика по BindTimeout нет (Authenticated + BIND)");
        Check(ind.Kick(un, ui, rs, 300) == 0 && !srv.LogHas("вытесняет"), "S1.6: Indun-сессия той же учётки без KICK, самовытеснения нет");
        // S1.3 потеря канала → KICK 3 и GameServer, и Indun
        pa.stop = true; pa.t.join();
        a.Close(); t0 = NowMs();
        gs.Ping(); ind.Ping();
        kr = gs.Kick(un, ui, rs, 6000); dt = NowMs() - t0;
        Check(kr == 1 && un == 9 && rs == 3 && dt >= 1700, "S1.3: канал 15901 закрыт → KICK 3 через Grace (" + std::to_string(dt) + " мс)");
        Check(ind.Kick(un, ui, rs, 4000) == 1 && un == 30 && ui == 75002 && rs == 3, "S1.3: и Indun-сессии — KICK 3 на свой мост");
        gs.Logout(9, 75002); ind.Logout(30, 75002);
        // S1.4 REBIND (соулмейт): персонаж 75005 → сессия 80015 (EAC + BIND) — кика нет; 75006 → 80017 без EAC — KICK 1 с учёткой персонажа
        SecureClient m; Bind32 b15 = RandBind();
        Check(EacUp(m, 80015, 15, b15), "S1.4: EAC-сессия учётки сессии 80015 + BIND");
        Pinger pm(m);
        gs.Login(15, 75005, b15); gs.Rebind(15, 75005, 80015, b15);
        gs.Login(17, 75006, RandBind()); gs.Rebind(17, 75006, 80017, RandBind());
        Check(srv.WaitLog("REBIND Game pid 424200 userNum 15", 3000), "S1.4: сайдкар получил REBIND 75005 → 80015");
        gs.Ping();
        Check(gs.Kick(un, ui, rs, 5000) == 1 && un == 17 && ui == 75006 && rs == 1, "S1.4: соулмейт 17 без EAC у 80017 → KICK 1 с учёткой персонажа (75006)");
        Check(gs.Kick(un, ui, rs, 1500) == 0, "S1.4: соулмейт 15 (EAC у учётки сессии) не кикнут");
        // S1.5 вытеснение: вторая REG той же учётки → первой KICK 5
        SecureClient b1, b2; std::vector<uint8_t> p5;
        Check(EacRegister(b1, kSide, g_pub, 75003, 31) == 0 && EacRegister(b2, kSide, g_pub, 75003, 32) == 0, "S1.5: две EAC-сессии 75003 (разные PUID)");
        Check(b1.RecvType(0x03, p5, 3000) == 1 && p5.size() >= 4 && p5[0] == 5, "S1.5: первой — KICK ourReason 5");
        Check(b1.WaitClosed(4000), "S1.5: первое соединение закрыто сайдкаром");
        // S1.7 REBIND до LOGIN — пропущен
        FakeP73 raw; raw.Open(2, 515151); raw.Rebind(40, 90001, 90002, RandBind());
        Check(srv.WaitLog("REBIND userNum 40: сессии учётки 90001 нет — пропущен", 3000), "S1.7: REBIND до LOGIN — пропущен, соединение живо");
        // S1.8 рестарт GameServer: новый pid того же вида при отключённом старом → сессии старого снимаются
        raw.Login(41, 90003, RandBind()); Sleep(300); raw.c.Close(); Sleep(500);
        FakeP73 raw2; raw2.Open(2, 616161);
        Check(srv.WaitLog("снято сессий прежнего процесса 1", 3000), "S1.8: HELLO нового pid — сессии отключённого процесса сняты");
        raw2.c.Close();
        // S1.9 рестарт сайдкара: P73 переподключается (HELLO + LOGIN всех + REBIND с bind), клиент — REG + BIND заново → защищена
        pm.stop = true; pm.t.join();
        srv.Stop();
        Server srv2; Check(StartServer(srv2, "s1", base, false), "S1.9: сайдкар перезапущен (тот же ключ/папка/порты)");
        FakeP73 gs2; gs2.seq = gs.seq; Check(gs2.Open(2, 424200), "S1.9: P73 переподключился: HELLO v2 того же pid");
        gs2.Login(15, 75005, b15); gs2.Rebind(15, 75005, 80015, b15);
        SecureClient m2; Check(EacUp(m2, 80015, 15, b15), "S1.9: клиент переподключил канал EAC: REG + BIND текущего игрового соединения");
        gs2.Ping();
        Check(gs2.Kick(un, ui, rs, 4500) == 0 && srv2.WaitLog("игровая сессия ЗАЩИЩЕНА", 1000), "S1.9: после рестарта сайдкара — снова защищена, кика нет");
        srv2.Stop();
    }
    if (!only5)
    {
        // ═══ S2: Mode=1 — KICK в P73 не идёт ═══
        printf("\n== S2: сайдкар Mode=1 ==\n");
        auto ov = base; ov["General.Mode"] = "1";
        Server srv; Check(StartServer(srv, "s2", ov), "S2: сайдкар Mode=1");
        FakeP73 gs; gs.Open(2, 424300); gs.Login(7, 75001, RandBind()); gs.Ping();
        uint16_t un; uint32_t ui; uint8_t rs;
        Check(gs.Kick(un, ui, rs, 4500) == 0 && srv.WaitLog("KICK НЕ отправлен: Mode=1", 1000), "S2: решение записано, KICK не отправлен");
        srv.Stop();
        printf("\n== S3: P73 Mode=0 — проверяется на стороне P73 (стенд ревизора с настоящей DLL); у сайдкара не меняется ==\n");
    }
    if (!only5)
    {
        // ═══ S4: FailOpen=1 — окно после старта; дефект E1-03 (чужая REG отключала кики для всех) — ИСПРАВЛЕН ═══
        printf("\n== S4: FailOpen=1, FailOpenStartupSec=4, EpicDownHoldSec=60 ==\n");
        auto ov = base; ov["General.FailOpen"] = "1"; ov["General.FailOpenStartupSec"] = "4"; ov["General.EpicDownHoldSec"] = "60";
        Server srv; Check(StartServer(srv, "s4", ov), "S4: сайдкар FailOpen=1");
        FakeP73 gs; gs.Open(2, 424400); gs.Login(7, 75001, RandBind());
        uint16_t un; uint32_t ui; uint8_t rs;
        gs.Ping();
        Check(gs.Kick(un, ui, rs, 3000) == 0, "S4.1: в окне FailOpen (4 с после старта) кика нет");
        Check(gs.Kick(un, ui, rs, 8000) == 1, "S4.1: после окна — отсчёт заново и KICK 1");
        gs.Logout(7, 75001);
        SecureClient atk;
        Check(EacRegister(atk, kSide, g_pub, 1, 99, { {"eosres", "TooManyRequests"} }) == 3, "S4.2: REG неаутентифицированного клиента с временным отказом Epic → REG_RESULT 3");
        gs.Login(9, 75002, RandBind()); gs.Ping();
        Check(gs.Kick(un, ui, rs, 5000) == 1 && ui == 75002 && rs == 1, "S4.2 (дефект E1-03 ИСПРАВЛЕН): игрок без EAC кикнут — одна чужая REG кики не отключает");
        Check(!srv.LogHas("Epic недоступен"), "S4.2: «Epic недоступен» не объявлен");
        gs.Logout(9, 75002);
        const char* ips[] = { "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6" };
        for (const char* ip : ips) { SecureClient c; EacRegister(c, kSide, g_pub, 1, 100, { {"eosres", "TimedOut"} }, ip); }
        Check(srv.WaitLog("Epic недоступен (временных отказов VerifyIdToken", 2000), "S4.3: 5 IP с временными отказами — «Epic недоступен» (порог §8.3)");
        gs.Login(11, 75003, RandBind()); gs.Ping();
        Check(gs.Kick(un, ui, rs, 4500) == 0, "S4.3: при настоящей недоступности Epic — кика нет (FailOpen)");
        srv.Stop();
    }
    // ═══ S5: шквал рукопожатий с одного IP — дефект E1-04 ИСПРАВЛЕН ═══
    for (int floodN : { 12, 300 })
    {
        printf("\n== S5: шквал рукопожатий 15901 с одного IP, %d нитей, настройки приёма по умолчанию ==\n", floodN);
        auto ov = base;
        ov["Sidecar.MaxUnregPerIp"] = "16"; ov["Sidecar.ConnectRatePerIp"] = "5"; ov["Sidecar.ConnectBurstPerIp"] = "20";
        ov["Sidecar.ConnectRateGlobal"] = "300"; ov["Sidecar.ConnectBurstGlobal"] = "600"; ov["Sidecar.RegPerIpPerMin"] = "10"; ov["General.LogLevel"] = "2";
        Server srv; Check(StartServer(srv, "s5", ov), "S5: сайдкар");
        SecureClient a;
        Check(EacRegister(a, kSide, g_pub, 75010, 10, {}, "127.0.0.30") == 0, "S5: зарегистрированный клиент (свой IP)");
        size_t lines0 = srv.LogLines();
        std::atomic<bool> stop{ false }; std::atomic<long> hs{ 0 };
        std::vector<std::thread> th;
        for (int i = 0; i < floodN; ++i)
            th.emplace_back([&] { while (!stop) { SecureClient c; if (c.Open(kSide, g_pub) && c.Handshake(2000)) ++hs; } });
        int64_t worst = 0, t1 = NowMs();
        while (NowMs() - t1 < 6000)
        {
            int64_t s0 = NowMs(); a.Send(0x04, {}); std::vector<uint8_t> p;
            if (a.RecvType(0x84, p, 3000) != 1) { worst = 99999; break; }
            worst = (std::max)(worst, NowMs() - s0); Sleep(100);
        }
        stop = true; for (auto& t : th) t.join();
        size_t lines = srv.LogLines() - lines0;
        printf("     рукопожатий за 6 с: %ld (%.0f/с), худшая задержка PONG: %lld мс, строк журнала: %zu\n", hs.load(), hs.load() / 6.0, (long long)worst, lines);
        Check(worst < 200, "S5 (дефект E1-04 ИСПРАВЛЕН): PONG зарегистрированному < 200 мс (" + std::to_string(worst) + " мс; было > 3 с)");
        Check(lines < 200, "S5: журнал не растёт лавиной (" + std::to_string(lines) + " строк за 6 с; было ~10 тыс./с)");
        srv.Stop();
    }
    printf("\n");
    return Summary("e2e_r3 (ред. 3, по стенду ревизора E1)");
}
