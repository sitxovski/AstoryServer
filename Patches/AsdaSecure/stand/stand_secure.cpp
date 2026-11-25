// Copyright (c) 2026 @sitxovski (Discord)
// stand_secure.cpp — стенд криптопрослойки (волна В7). Сервер/клиент НЕ запускаются: оба конца
// живут в одном процессе, байты «гоняются» через std::vector вместо сокета.
//
// Проверяет:
//   1) рукопожатие ClientHello→ServerHello→ключи; подпись сервера проверяется клиентом;
//   2) 10 000 кадров разной длины в ОБЕ стороны — расшифрованное совпадает с исходным байт-в-байт;
//   3) повтор кадра → отказ (Replay); переупорядочивание двух кадров → отказ; порча тега → отказ (BadTag);
//   4) подмена открытого ключа сервера в клиенте → отказ рукопожатия (BadSignature);
//   5) старый клиент (первый байт 0xFB) → канал Legacy, байты проходят как есть;
//   6) замер: мкс на кадр 64/512/1500 байт; накладные байты на кадр.
// Итог печатает «ВСЁ СОШЛОСЬ» только при нуле расхождений и всех ожидаемых отказах.
#include "AsdaSecure.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>

using namespace AsdaSecure;

static int g_fail = 0;
static void CHECK(bool cond, const char* what)
{
    if (!cond) { printf("  [ПРОВАЛ] %s\n", what); ++g_fail; }
}

static uint32_t g_rng = 0x1234abcd;
static uint32_t xr() { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }
static void fillRand(std::vector<uint8_t>& v, size_t n) { v.resize(n); for (size_t i = 0; i < n; ++i) v[i] = (uint8_t)xr(); }

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    if (!Init()) { printf("CNG недоступен (0x%08lX)\n", LastStatus()); return 1; }
    printf("=== Стенд AsdaSecure (волна В7) ===\n");

    // Долговременная пара сервера (в стенде — в памяти).
    PrivateKey srvPriv; CHECK(GenerateLongTermKey(srvPriv), "генерация долговременной пары");
    PublicKey  srvPub;  memcpy(srvPub.xy, srvPriv.xy, kPubLen);

    // ── 1. Рукопожатие через каналы высокого уровня ───────────────────────────────────────
    ServerChannel srv; srv.SetIdentity(SubServer::Game, &srvPriv); srv.SetAllowLegacy(true); srv.Reset();
    ClientChannel cli; cli.Reset();

    std::vector<uint8_t> c2s, s2c, parse;
    CHECK(cli.Start(SubServer::Game, srvPub, c2s), "ClientHello сформирован");
    CHECK(c2s.size() == kClientHelloLen, "размер ClientHello");
    // клиент → сервер
    Err e = srv.OnRecv(c2s.data(), c2s.size(), parse, s2c);
    CHECK(e == Err::Ok, "сервер принял ClientHello");
    CHECK(s2c.size() == kServerHelloLen, "размер ServerHello");
    // сервер → клиент
    e = cli.OnRecv(s2c.data(), s2c.size(), parse);
    CHECK(e == Err::Ok, "клиент принял ServerHello (подпись верна)");
    CHECK(cli.IsReady() && srv.IsReady(), "обе стороны готовы");

    // ── 2. 10 000 кадров разной длины в обе стороны ───────────────────────────────────────
    int mismatch = 0, nFrames = 10000;
    for (int i = 0; i < nFrames; ++i)
    {
        size_t len = 1 + (xr() % 1600);             // 1..1600 байт
        std::vector<uint8_t> plain; fillRand(plain, len);
        std::vector<uint8_t> wire, got;
        if (i & 1)
        {   // клиент → сервер
            e = cli.OnSend(plain.data(), plain.size(), wire);
            if (e != Err::Ok) { ++mismatch; continue; }
            e = srv.OnRecv(wire.data(), wire.size(), got, s2c);
            if (e != Err::Ok || got.size() != len || memcmp(got.data(), plain.data(), len) != 0) ++mismatch;
        }
        else
        {   // сервер → клиент
            e = srv.OnSend(plain.data(), plain.size(), wire);
            if (e != Err::Ok) { ++mismatch; continue; }
            e = cli.OnRecv(wire.data(), wire.size(), got);
            if (e != Err::Ok || got.size() != len || memcmp(got.data(), plain.data(), len) != 0) ++mismatch;
        }
    }
    printf("  кадров прогнано: %d, расхождений: %d\n", nFrames, mismatch);
    CHECK(mismatch == 0, "10000 кадров байт-в-байт");

    // ── 3. Фрагментация приёма: кадр приходит по 1 байту ──────────────────────────────────
    {
        std::vector<uint8_t> plain; fillRand(plain, 777);
        std::vector<uint8_t> wire; CHECK(cli.OnSend(plain.data(), plain.size(), wire) == Err::Ok, "seal для фрагментации");
        std::vector<uint8_t> acc, got; bool gotOne = false;
        for (size_t i = 0; i < wire.size(); ++i)
        {
            std::vector<uint8_t> piece;
            Err fe = srv.OnRecv(wire.data() + i, 1, piece, s2c);
            CHECK(fe == Err::Ok, "побайтовый приём не ошибается");
            if (!piece.empty()) { got = piece; gotOne = true; }
        }
        CHECK(gotOne && got.size() == 777 && memcmp(got.data(), plain.data(), 777) == 0, "склейка из побайтовых кусков");
    }

    // ── 4. Атаки на низком уровне (Session напрямую, чтобы управлять порядком/порчей) ──────
    {
        Session S, C;
        uint8_t ch[kClientHelloLen], sh[kServerHelloLen];
        CHECK(C.ClientHello(SubServer::Game, srvPub, ch), "session: ClientHello");
        CHECK(S.ServerAccept(ch, kClientHelloLen, SubServer::Game, srvPriv, sh) == Err::Ok, "session: ServerAccept");
        CHECK(C.ClientFinish(sh, kServerHelloLen) == Err::Ok, "session: ClientFinish");

        std::vector<uint8_t> f1, f2, out;
        std::vector<uint8_t> p1, p2; fillRand(p1, 100); fillRand(p2, 200);
        CHECK(C.Seal(p1.data(), p1.size(), f1) == Err::Ok, "seal f1");
        CHECK(C.Seal(p2.data(), p2.size(), f2) == Err::Ok, "seal f2");

        // повтор f1 (сначала принять f1 нормально)
        S.Feed(f1.data(), f1.size()); CHECK(S.Next(out), "принят f1");
        S.Feed(f1.data(), f1.size());                      // тот же seq снова
        CHECK(!S.Next(out) && S.LastError() == Err::Replay, "повтор кадра отвергнут (Replay)");

        // переупорядочивание: новая сессия, подать f2 раньше f1
        Session S2;
        uint8_t ch2[kClientHelloLen], sh2[kServerHelloLen]; Session C2;
        C2.ClientHello(SubServer::Game, srvPub, ch2);
        S2.ServerAccept(ch2, kClientHelloLen, SubServer::Game, srvPriv, sh2);
        C2.ClientFinish(sh2, kServerHelloLen);
        std::vector<uint8_t> g1, g2;
        CHECK(C2.Seal(p1.data(), p1.size(), g1) == Err::Ok, "seal g1");
        CHECK(C2.Seal(p2.data(), p2.size(), g2) == Err::Ok, "seal g2");
        S2.Feed(g2.data(), g2.size());                     // второй кадр первым — seq=2, ожидался 1
        CHECK(!S2.Next(out) && S2.LastError() == Err::Replay, "переупорядочивание отвергнуто");

        // порча тега: испортить последний байт свежего кадра
        Session S3, C3;
        uint8_t ch3[kClientHelloLen], sh3[kServerHelloLen];
        C3.ClientHello(SubServer::Game, srvPub, ch3);
        S3.ServerAccept(ch3, kClientHelloLen, SubServer::Game, srvPriv, sh3);
        C3.ClientFinish(sh3, kServerHelloLen);
        std::vector<uint8_t> bad; CHECK(C3.Seal(p1.data(), p1.size(), bad) == Err::Ok, "seal bad");
        bad[bad.size() - 1] ^= 0x80;                       // бит в теге
        S3.Feed(bad.data(), bad.size());
        CHECK(!S3.Next(out) && S3.LastError() == Err::BadTag, "порча тега отвергнута (BadTag)");
    }

    // ── 5. Подмена открытого ключа сервера → отказ рукопожатия ────────────────────────────
    {
        PrivateKey other; GenerateLongTermKey(other);
        PublicKey  otherPub; memcpy(otherPub.xy, other.xy, kPubLen);
        ServerChannel s2; s2.SetIdentity(SubServer::Game, &srvPriv); s2.Reset();   // сервер подписывает НАСТОЯЩИМ
        ClientChannel c2; c2.Reset();
        std::vector<uint8_t> hc, hs, pp;
        c2.Start(SubServer::Game, otherPub, hc);           // клиенту вшит ЧУЖОЙ открытый ключ
        s2.OnRecv(hc.data(), hc.size(), pp, hs);
        Err re = c2.OnRecv(hs.data(), hs.size(), pp);
        CHECK(re == Err::BadSignature, "подмена ключа сервера → BadSignature");
        AsdaSecure::Wipe(&other, sizeof(other));
    }

    // ── 6. Старый клиент (Legacy): первый байт 0xFB ───────────────────────────────────────
    {
        ServerChannel sl; sl.SetIdentity(SubServer::Login, &srvPriv); sl.SetAllowLegacy(true); sl.Reset();
        uint8_t legacy[] = { 0xFB, 0x10, 0x00, 0x01, 0x00, 0x02, 0x00, 0xEB, 0x03, 0xFE };
        std::vector<uint8_t> toP, toS;
        Err le = sl.OnRecv(legacy, sizeof(legacy), toP, toS);
        CHECK(le == Err::Ok && sl.GetMode() == Mode::Legacy, "старый клиент → режим Legacy");
        CHECK(toP.size() == sizeof(legacy) && memcmp(toP.data(), legacy, sizeof(legacy)) == 0, "Legacy: байты прошли как есть");
        // а при запрете legacy — отказ
        ServerChannel sl2; sl2.SetIdentity(SubServer::Login, &srvPriv); sl2.SetAllowLegacy(false); sl2.Reset();
        Err le2 = sl2.OnRecv(legacy, sizeof(legacy), toP, toS);
        CHECK(le2 == Err::BadMagic, "запрет legacy → старый кадр отвергнут");
    }

    // ── 7. Замеры производительности ──────────────────────────────────────────────────────
    auto bench = [&](size_t len)
    {
        Session S, C; uint8_t ch[kClientHelloLen], sh[kServerHelloLen];
        C.ClientHello(SubServer::Game, srvPub, ch);
        S.ServerAccept(ch, kClientHelloLen, SubServer::Game, srvPriv, sh);
        C.ClientFinish(sh, kServerHelloLen);
        std::vector<uint8_t> plain; fillRand(plain, len);
        const int N = 20000;
        LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f);
        std::vector<uint8_t> wire, out;
        QueryPerformanceCounter(&a);
        for (int i = 0; i < N; ++i)
        {
            wire.clear(); C.Seal(plain.data(), len, wire);
            S.Feed(wire.data(), wire.size()); S.Next(out);
        }
        QueryPerformanceCounter(&b);
        double us = (double)(b.QuadPart - a.QuadPart) * 1e6 / (double)f.QuadPart / N;
        printf("  кадр %4zu б: seal+open = %.3f мкс/кадр, накладных байт = %zu\n", len, us, kFrameOverhead);
    };
    bench(64); bench(512); bench(1500);

    AsdaSecure::Wipe(&srvPriv, sizeof(srvPriv));
    printf("\n%s (провалов: %d)\n", g_fail == 0 ? "ВСЁ СОШЛОСЬ" : "ЕСТЬ РАСХОЖДЕНИЯ", g_fail);
    return g_fail == 0 ? 0 : 1;
}
