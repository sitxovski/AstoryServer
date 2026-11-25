// Copyright (c) 2026 @sitxovski (Discord)
// stand_sidecar.cpp — стенд (в): клиент 15901 через AsdaSecure (SubServer::Eac = 4) против AsdaEacServer_stand.exe.
// Проверяет: рукопожатие и закрепление ключа, отказ старому (0xFB) и чужому под-серверу, REG с мусорным токеном → 1,
// REG без EOS → 3, Mode=0 → 4, разбор кадров (нарезка, склейка, негодные длины/типы), PING/PONG и таймауты PING/REG/
// рукопожатия, пределы соединений (вытеснение старейшего незарегистрированного, предел на IP), 300 одновременных
// соединений; с фальшивым EOS — REG 0, ACMSG-эхо через «EOS», вытеснение той же учётки (KICK 5), повторный REG.
// Ред. 3: кадр BIND (0x05/0x85), лимит REG на IP, проверка токена в счёте незарегистрированных на IP, AuthTimeout (KICK 4 /
// в Mode 1 — без KICK), одиночный временный отказ Epic не включает FailOpen; E1-04 — шквал соединений с одного IP (12 и 300
// нитей) при настройках по умолчанию: PONG зарегистрированному < 200 мс, журнал растёт сводками, а не строкой на отказ.
#include "StandCommon.h"
#include <thread>
#include <atomic>

using namespace Stand;

namespace
{
    const int kId = 18446, kSide = 25721, kBr = 25722;   // порты стенда
    AsdaSecure::PublicKey g_pub;                          // открытый ключ сервера стенда

    std::string GoodShapeJwt()
    {
        return Eac::Crypto::B64Url(std::string("{\"alg\":\"RS256\",\"typ\":\"JWT\"}")) + "." +
               Eac::Crypto::B64Url(std::string("{\"sub\":\"1\"}")) + ".c2ln";
    }

    // Открыть и пройти рукопожатие.
    bool OpenReady(SecureClient& c)
    {
        return c.Open(kSide, g_pub) && c.Handshake(5000);
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== stand_sidecar: 15901 / AsdaSecure / кадры §3 ===\n");
    std::wstring dir = RunDir("sidecar");
    if (!Check(MakeSecureKey(dir, g_pub), "ключ AsdaSecure стенда создан")) return Summary("stand_sidecar");

    // ── 1. --no-eos: протокол, таймауты, пределы ───────────────────────────────────────────
    {
        printf("-- [no-eos] рукопожатие, REG, кадры\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.PingTimeoutSec", "3"}, {"Sidecar.RegTimeoutSec", "30"}, {"Sidecar.HandshakeTimeoutSec", "2"} });
        Server srv;
        if (!Check(srv.Start(dir, ini, L"--no-eos --fake-auth", kSide), "сервер (--no-eos) запущен")) return Summary("stand_sidecar");

        {
            SecureClient c;
            Check(OpenReady(c), "рукопожатие AsdaSecure с SubServer::Eac=4: подпись ServerHello сошлась с ключом сервера");
            Check(c.Send(0x04, {}), "PING отправлен");
            std::vector<uint8_t> p;
            Check(c.RecvType(0x84, p, 3000) == 1 && p.empty(), "PONG пришёл (пустой)");
            Check(c.Send(0x01, RegPayload(1, 1, Puid(1), "not-a-jwt")), "REG с мусорным токеном");
            Check(c.RecvType(0x81, p, 3000) == 1 && p.size() == 1 && p[0] == 1, "REG_RESULT 1");
            Check(c.WaitClosed(3000), "соединение закрыто после REG_RESULT 1");
        }
        {
            SecureClient c; std::vector<uint8_t> p;
            OpenReady(c);
            c.Send(0x01, RegPayload(1, 1, Puid(2), GoodShapeJwt()));
            Check(c.RecvType(0x81, p, 3000) == 1 && p.size() == 1 && p[0] == 3, "REG с формой JWT при --no-eos → REG_RESULT 3 (EOS недоступен)");
            Check(c.WaitClosed(3000), "закрыто после REG_RESULT 3");
        }
        {
            SecureClient c; std::vector<uint8_t> p;
            OpenReady(c);
            c.Send(0x01, RegPayload(2, 1, Puid(3), GoodShapeJwt()));
            Check(c.RecvType(0x81, p, 3000) == 1 && p[0] == 1, "REG ver=2 → REG_RESULT 1");
        }
        {
            SecureClient c; std::vector<uint8_t> p;
            OpenReady(c);
            c.Send(0x01, RegPayload(1, 1, "ABCDEF", GoodShapeJwt()));
            Check(c.RecvType(0x81, p, 3000) == 1 && p[0] == 1, "REG с негодным PUID → REG_RESULT 1");
        }
        {
            // Старый клиент (0xFB) — шифрование обязательно.
            SOCKET s = Connect(kSide); uint8_t legacy[] = { 0xFB, 0x10, 0x00 }; SendAll(s, legacy, sizeof(legacy));
            uint8_t b[64]; int n = RecvSome(s, b, sizeof(b), 3000);
            Check(n == 0 || n == -2, "первый байт 0xFB (старый кадр) → разрыв");
            closesocket(s);
        }
        {
            SecureClient c; c.Open(kSide, g_pub, AsdaSecure::SubServer::Game);
            Check(!c.Handshake(3000) && c.closed, "ClientHello с SubServer::Game на 15901 → разрыв (BadSubServer)");
        }
        {
            AsdaSecure::PrivateKey other; AsdaSecure::GenerateLongTermKey(other);
            AsdaSecure::PublicKey otherPub; memcpy(otherPub.xy, other.xy, sizeof(otherPub.xy));
            SecureClient c; c.Open(kSide, otherPub);
            Check(!c.Handshake(3000) && c.lastErr == AsdaSecure::Err::BadSignature, "клиент с чужим закреплённым ключом отвергает сервер (BadSignature)");
        }
        printf("-- [no-eos] негодные кадры\n");
        {
            struct Case { std::vector<uint8_t> raw; const char* what; };
            std::vector<Case> cases = {
                { {0x00, 0x00}, "len=0" },
                { {0x89, 0x13, 0x04}, "len=5001 > 4096" },
                { Frame(0x77, {}), "неизвестный тип 0x77" },
                { Frame(0x02, {1, 2, 3}), "ACMSG до REG" },
                { Frame(0x04, {1}), "PING с данными" },
                { Frame(0x81, {0}), "кадр сервера (REG_RESULT) от клиента" },
                { Frame(0x01, {1, 1, 0xFF, 0x00}), "REG: PUID за пределами кадра" },
            };
            for (auto& cs : cases)
            {
                SecureClient c; OpenReady(c);
                c.SendPlain(cs.raw);
                Check(c.WaitClosed(3000), std::string("разрыв: ") + cs.what);
            }
            {
                SecureClient c; OpenReady(c); std::vector<uint8_t> p;
                c.Send(0x01, RegPayload(1, 1, Puid(4), GoodShapeJwt()));
                c.RecvType(0x81, p, 3000);
                Check(c.WaitClosed(3000), "после REG_RESULT ≠ 0 соединение закрыто");
            }
            {
                SecureClient c; OpenReady(c);
                std::vector<uint8_t> big(513, 0x41);
                c.SendPlain(Frame(0x02, big));
                Check(c.WaitClosed(3000), "разрыв: ACMSG 513 байт");
            }
        }
        printf("-- [no-eos] нарезка и склейка кадров\n");
        {
            SecureClient c; OpenReady(c);
            std::vector<uint8_t> two = Frame(0x04, {}); auto f2 = Frame(0x04, {}); two.insert(two.end(), f2.begin(), f2.end());
            c.SendPlain(two);
            std::vector<uint8_t> p; int pongs = 0;
            while (c.RecvType(0x84, p, 1500) == 1) { if (++pongs == 2) break; }
            Check(pongs == 2, "два PING в одном куске → два PONG");
            // Кадр PING по одному байту: каждый байт — отдельный зашифрованный кадр AsdaSecure.
            auto f = Frame(0x04, {});
            for (uint8_t b : f) { c.SendPlain({ b }); Sleep(30); }
            Check(c.RecvType(0x84, p, 2000) == 1, "PING, нарезанный по 1 байту → PONG");
        }
        printf("-- [no-eos] таймауты (стенд: PING 3 с, рукопожатие 2 с)\n");
        {
            SecureClient c; OpenReady(c);
            int64_t t0 = NowMs();
            bool closed = c.WaitClosed(6000);
            int64_t dt = NowMs() - t0;
            Check(closed && dt >= 2500 && dt <= 4500, "без PING → разрыв через ~3 с (" + std::to_string(dt) + " мс)");
        }
        {
            SecureClient c; OpenReady(c);
            bool alive = true;
            for (int i = 0; i < 6 && alive; ++i) { c.Send(0x04, {}); std::vector<uint8_t> p; alive = c.RecvType(0x84, p, 2000) == 1; Sleep(1000); }
            Check(alive && !c.closed, "PING каждую секунду — соединение живёт 6+ с (дольше таймаута PING)");
        }
        {
            SOCKET s = Connect(kSide);
            int64_t t0 = NowMs(); uint8_t b[64]; int n;
            do { n = RecvSome(s, b, sizeof(b), 5000); } while (n > 0);
            int64_t dt = NowMs() - t0;
            Check((n == 0 || n == -2) && dt >= 1500 && dt <= 3500, "молчание без ClientHello → разрыв через ~2 с (" + std::to_string(dt) + " мс)");
            closesocket(s);
        }
        printf("-- [no-eos] 300 одновременных соединений\n");
        {
            std::vector<std::unique_ptr<SecureClient>> v;
            int opened = 0, ready = 0, pong = 0;
            int64_t t0 = NowMs();
            for (int i = 0; i < 300; ++i) { v.emplace_back(new SecureClient()); opened += v.back()->Open(kSide, g_pub); }
            for (auto& c : v) ready += c->Handshake(10000);
            for (auto& c : v) c->Send(0x04, {});
            for (auto& c : v) { std::vector<uint8_t> p; pong += c->RecvType(0x84, p, 5000) == 1; }
            int64_t dt = NowMs() - t0;
            Check(opened == 300 && ready == 300 && pong == 300, "300 соединений: рукопожатие и PONG у всех (" + std::to_string(dt) + " мс)");
            printf("    открыто %d, рукопожатий %d, PONG %d\n", opened, ready, pong);
        }
        Check(srv.WaitLog("AsdaSecure: BadSubServer", 2000), "журнал: BadSubServer");
        Check(srv.LogHas("AsdaSecure: BadMagic"), "журнал: BadMagic (0xFB)");
        srv.Stop();
    }

    // ── 2. Пределы соединений ──────────────────────────────────────────────────────────────
    {
        printf("-- [no-eos] MaxConnections=5: вытеснение старейшего незарегистрированного\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.MaxConnections", "5"}, {"Sidecar.MaxUnregPerIp", "100"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--no-eos --fake-auth", kSide), "сервер (MaxConnections=5)"))
        {
            std::vector<std::unique_ptr<SecureClient>> v;
            for (int i = 0; i < 5; ++i) { v.emplace_back(new SecureClient()); OpenReady(*v.back()); Sleep(20); }
            SecureClient extra; bool ok6 = OpenReady(extra);
            Check(ok6, "6-е соединение принято");
            Check(v[0]->WaitClosed(3000), "старейшее незарегистрированное вытеснено");
            std::vector<uint8_t> p; v[1]->Send(0x04, {});
            Check(v[1]->RecvType(0x84, p, 2000) == 1, "остальные живы");
            Check(srv.WaitLog("вытеснено старейшее незарегистрированное", 2000), "журнал: вытеснение");
            srv.Stop();
        }
    }
    {
        printf("-- [no-eos] MaxUnregPerIp=3\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.MaxUnregPerIp", "3"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--no-eos --fake-auth", kSide), "сервер (MaxUnregPerIp=3)"))
        {
            SecureClient a, b, c, d;
            OpenReady(a); OpenReady(b); OpenReady(c);
            d.Open(kSide, g_pub);
            Check(!d.Handshake(2000) && d.closed, "4-е незарегистрированное с того же IP → отказ");
            std::vector<uint8_t> p; a.Send(0x04, {});
            Check(a.RecvType(0x84, p, 2000) == 1, "первые три живы");
            srv.Stop();
        }
    }
    {
        printf("-- Mode=0 → REG_RESULT 4\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"General.Mode", "0"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер (Mode=0, fake-eos)"))
        {
            SecureClient c; OpenReady(c); std::vector<uint8_t> p;
            c.Send(0x01, RegPayload(1, 1, Puid(777), FakeToken("777", Puid(777))));
            Check(c.RecvType(0x81, p, 3000) == 1 && p[0] == 4, "REG при Mode=0 → REG_RESULT 4");
            srv.Stop();
        }
    }

    // ── 3. --fake-eos: регистрация, ACMSG через «EOS», вытеснение ─────────────────────────
    {
        printf("-- [fake-eos] REG 0, ACMSG-эхо, повторный REG, вытеснение\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"General.Mode", "1"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер (--fake-eos)"))
        {
            SecureClient c; OpenReady(c); std::vector<uint8_t> p;
            // ACMSG во время проверки токена должен дойти после регистрации (буфер до RegisterClient).
            c.Send(0x01, RegPayload(1, 1, Puid(777), FakeToken("777", Puid(777))));
            c.Send(0x02, { 'e', 'a', 'r', 'l', 'y' });
            Check(c.RecvType(0x81, p, 3000) == 1 && p[0] == 0, "REG (учётка 777) → REG_RESULT 0");
            Check(c.RecvType(0x02, p, 3000) == 1 && std::string(p.begin(), p.end()) == "early", "ACMSG, отправленный во время проверки, дошёл до EOS после регистрации (эхо)");
            c.Send(0x02, { 'h', 'e', 'l', 'l', 'o' });
            Check(c.RecvType(0x02, p, 3000) == 1 && std::string(p.begin(), p.end()) == "hello", "ACMSG → ReceiveMessageFromClient → MessageToClient → ACMSG (эхо)");
            std::vector<uint8_t> m512(512, 0x5A); c.Send(0x02, m512);
            Check(c.RecvType(0x02, p, 3000) == 1 && p.size() == 512, "ACMSG 512 байт — предел проходит");
            {
                SecureClient bad; OpenReady(bad); std::vector<uint8_t> q;
                bad.Send(0x01, RegPayload(1, 1, Puid(779), FakeToken("779", Puid(780))));
                Check(bad.RecvType(0x81, q, 3000) == 1 && q[0] == 1, "токен другого PUID → VerifyIdToken отказ → REG_RESULT 1");
            }
            {
                SecureClient tr; OpenReady(tr); std::vector<uint8_t> q;
                tr.Send(0x01, RegPayload(1, 1, Puid(781), FakeToken("transient", Puid(781))));
                Check(tr.RecvType(0x81, q, 3000) == 1 && q[0] == 3, "временный сбой Epic (NoConnection) → REG_RESULT 3");
                Check(srv.WaitLog("VerifyIdToken EOS_NoConnection (временный сбой)", 2000) && !srv.LogHas("Epic недоступен"),
                      "ред. 3: одиночный временный отказ — без глобального «Epic недоступен»");
            }
            {
                SecureClient na; OpenReady(na); std::vector<uint8_t> q;
                na.Send(0x01, RegPayload(1, 1, Puid(782), FakeToken("0777", Puid(782))));
                Check(na.RecvType(0x81, q, 3000) == 1 && q[0] == 2, "AccountId «0777» (не UserIndex) → REG_RESULT 2");
            }
            // Второй клиент той же учётки вытесняет первый.
            SecureClient c2; OpenReady(c2);
            c2.Send(0x01, RegPayload(1, 1, Puid(777), FakeToken("777", Puid(777))));
            Check(c2.RecvType(0x81, p, 3000) == 1 && p[0] == 0, "второй REG учётки 777 → REG_RESULT 0");
            Check(c.RecvType(0x03, p, 3000) == -1, "первому (Mode=1, E1-18) — KICK не шлётся, канал закрыт");
            Check(srv.WaitLog("(Mode=1 — без KICK, канал закрыт)", 1000), "журнал: вытеснение без KICK в Mode=1");
            Check(c.WaitClosed(3000), "первое соединение закрыто");
            c2.Send(0x01, RegPayload(1, 1, Puid(777), FakeToken("777", Puid(777))));
            Check(c2.WaitClosed(3000), "повторный REG в том же соединении → разрыв");
            srv.Stop();
        }
    }
    // ── 4. ред. 3: BIND, лимит REG на IP, проверка токена в счёте IP, AuthTimeout ─────────────
    {
        printf("-- [fake-eos] ред. 3: BIND, RegPerIpPerMin=3\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.RegPerIpPerMin", "3"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер (RegPerIpPerMin=3)"))
        {
            {
                SecureClient c; OpenReady(c); std::vector<uint8_t> p;
                Check(c.Send(0x05, BindPayload(2, RandBind())) && c.RecvType(0x85, p, 3000) == 1 && p.size() == 1 && p[0] == 2,
                      "BIND до REG → BIND_RESULT 2 (нет сессии), соединение живо");
                c.Send(0x04, {});
                Check(c.RecvType(0x84, p, 2000) == 1, "после BIND_RESULT 2 PING → PONG");
            }
            { SecureClient c; OpenReady(c); std::vector<uint8_t> b(32, 1); c.SendPlain(Frame(0x05, b)); Check(c.WaitClosed(3000), "BIND 32 байта (без serverKind) → разрыв"); }
            { SecureClient c; OpenReady(c); c.Send(0x05, BindPayload(7, RandBind())); Check(c.WaitClosed(3000), "BIND serverKind=7 → разрыв"); }
            int ok3 = 0;
            for (uint32_t ui = 777; ui < 780; ++ui)
            {
                SecureClient c; Bind32 b = RandBind();
                ok3 += EacRegister(c, kSide, g_pub, ui, ui) == 0 && EacBind(c, 2, b) == 0 && EacBind(c, 3, RandBind()) == 0;
            }
            Check(ok3 == 3, "3 REG с IP за минуту → REG_RESULT 0; BIND Game и BIND Indun → BIND_RESULT 0");
            Check(srv.WaitLog("учётка 777 BIND Game bind=", 1000), "журнал: BIND (только отпечаток 4 байт)");
            {
                SecureClient c; int st = EacRegister(c, kSide, g_pub, 781, 781);
                Check(st == 3, "4-я REG с одного IP за минуту → REG_RESULT 3 (" + std::to_string(st) + ")");
                SecureClient o; Check(EacRegister(o, kSide, g_pub, 782, 782, {}, "127.0.0.9") == 0, "с другого IP (127.0.0.9) REG проходит");
            }
            srv.Stop();
        }
    }
    {
        printf("-- [fake-eos] AuthTimeout: Mode 2 — KICK 4 клиенту; Mode 1 — только закрыть\n");
        for (int mode = 2; mode >= 1; --mode)
        {
            std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"General.Mode", std::to_string(mode)}, {"Sidecar.AuthTimeoutSec", "2"} });
            Server srv;
            if (!Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер Mode=" + std::to_string(mode))) continue;
            SecureClient c; std::vector<uint8_t> p;
            int64_t t0 = NowMs();
            Check(EacRegister(c, kSide, g_pub, 790, 790, { {"auth", "none"} }) == 0, "REG без RemoteAuthComplete → REG_RESULT 0");
            int r = c.RecvType(0x03, p, 4000);
            int64_t dt = NowMs() - t0;
            if (mode == 2) Check(r == 1 && p.size() >= 4 && p[0] == 4 && dt >= 1800, "Mode 2: KICK 4 через ~AuthTimeout (" + std::to_string(dt) + " мс)");
            else Check(r == -1 && c.closed && dt >= 1800, "Mode 1: KICK не шлётся, канал закрыт через ~AuthTimeout (" + std::to_string(dt) + " мс)");
            srv.Stop();
        }
    }
    {
        printf("-- [fake-eos] MaxUnregPerIp=2: соединения в «проверке токена» входят в предел IP (ред. 3 §8.3)\n");
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.MaxUnregPerIp", "2"} });
        Server srv;
        if (Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер (MaxUnregPerIp=2)"))
        {
            SecureClient a, b, c;
            OpenReady(a); OpenReady(b);
            a.Send(0x01, RegPayload(1, 1, Puid(1), FakeToken("1", Puid(1), { {"noanswer", "1"} })));
            b.Send(0x01, RegPayload(1, 1, Puid(2), FakeToken("2", Puid(2), { {"noanswer", "1"} })));
            Check(srv.WaitLog("REG puid=" + Puid(2), 2000), "два соединения в состоянии «проверка токена»");
            c.Open(kSide, g_pub);
            Check(!c.Handshake(2000) && c.closed, "третье с того же IP → отказ (Verifying считается незарегистрированным)");
            SecureClient d; Check(d.Open(kSide, g_pub, AsdaSecure::SubServer::Eac, "127.0.0.7") && d.Handshake(3000), "с другого IP — принято");
            srv.Stop();
        }
    }
    // ── 5. E1-04: шквал соединений с одного IP при настройках приёма по умолчанию ─────────────
    for (int floodN : { 12, 300 })
    {
        printf("-- E1-04: шквал рукопожатий с одного IP, %d нитей, лимиты приёма по умолчанию (5/с на IP, запас 20, незарегистрированных 16)\n", floodN);
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, { {"Sidecar.ConnectRatePerIp", "5"}, {"Sidecar.ConnectBurstPerIp", "20"}, {"Sidecar.ConnectRateGlobal", "300"},
                                                            {"Sidecar.ConnectBurstGlobal", "600"}, {"Sidecar.MaxUnregPerIp", "16"}, {"Sidecar.RegPerIpPerMin", "10"},
                                                            {"General.LogLevel", "2"} });
        Server srv;
        if (!Check(srv.Start(dir, ini, L"--fake-eos --fake-auth", kSide), "сервер (лимиты по умолчанию)")) continue;
        SecureClient reg;
        Check(EacRegister(reg, kSide, g_pub, 777, 777, {}, "127.0.0.20") == 0, "зарегистрированный клиент (другой IP)");
        size_t lines0 = srv.LogLines();
        std::atomic<bool> stop{ false }; std::atomic<long> hs{ 0 }, tries{ 0 };
        std::vector<std::thread> th;
        for (int i = 0; i < floodN; ++i)
            th.emplace_back([&] { while (!stop) { SecureClient c; ++tries; if (c.Open(kSide, g_pub) && c.Handshake(2000)) ++hs; } });
        int64_t worst = 0, t1 = NowMs(); int pongs = 0;
        while (NowMs() - t1 < 6000)
        {
            int64_t s0 = NowMs(); reg.Send(0x04, {}); std::vector<uint8_t> p;
            if (reg.RecvType(0x84, p, 3000) != 1) { worst = 99999; break; }
            worst = (std::max)(worst, NowMs() - s0); ++pongs; Sleep(100);
        }
        stop = true; for (auto& t : th) t.join();
        size_t lines = srv.LogLines() - lines0;
        printf("    попыток соединения %ld, рукопожатий %ld за 6 с; PONG %d, худшая задержка %lld мс; строк журнала за шквал: %zu\n", tries.load(), hs.load(), pongs,
               (long long)worst, lines);
        Check(worst < 200, "PONG зарегистрированному < 200 мс под шквалом (" + std::to_string(worst) + " мс)");
        Check(lines < 200, "журнал не растёт лавиной: " + std::to_string(lines) + " строк за 6 с (было ~10 тыс./с)");
        Check(srv.WaitLog("отказы приёма за 10 с", 6000), "отказы — сводкой раз в 10 с");
        std::vector<uint8_t> p; reg.Send(0x04, {});
        Check(reg.RecvType(0x84, p, 2000) == 1 && !reg.closed, "зарегистрированный клиент жив после шквала");
        srv.Stop();
    }
    return Summary("stand_sidecar");
}
