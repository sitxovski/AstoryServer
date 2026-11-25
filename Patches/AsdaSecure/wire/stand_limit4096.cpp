// Copyright (c) 2026 @sitxovski (Discord)
// stand_limit4096.cpp — ★ fix2c (ревизия FIX2, Н-1/Н-5): ПРЕДЕЛЫ БУФЕРОВ СТОКА на пути моста AsdaWire.
//
// Имитация стока (дизасм GameServer 4e20f0ad / LoginManager 51db86b2 — одна библиотека Ciocp):
//   • Ciocp::Send (GS 0x561F20, LM 0x413AB0) копирует данные в буфер перекрытой записи 0x1000 б: `0x5653B0(tag, ov+0x1C,
//     0x1000, src, n)` при n > 0x1000 только пишет строку лога, копии НЕТ, а WriteFile уходит с n байтами обнулённого буфера
//     (memset 0x1000 при выдаче из пула 0x5681D1) и чтением за буфером. Здесь: в «сокет» — n нулей.
//   • Приём: сток читает сокет по 0x1000 (ReadFile) и разбирает порцию CopyToWriteBuffer 0x5656D0 — обрывок заголовка (< 10 б)
//     в буфере сборки слота 0x1000 + вся следующая порция: порция больше 0x1000 − 9 не помещается. Здесь: такая порция — провал.
// Случаи: пакет стока 4095 б (GS копит пакет до 0xFFF — 0x4C2A9D), 4096 б, 8200 б, очередь до рукопожатия > 4 КБ (Н-5),
//   кадр клиента 12 КБ на приём.
// Собирается ДВАЖДЫ (AsdaSecure\build.bat): с мостом fix2c (out\stand_limit4096.exe — ждём «ВСЁ СОШЛОСЬ») и с мостом fix2b из
//   бэкапа (/DSTAND_OLD_BRIDGE, out\stand_limit4096_old.exe — Н-1 воспроизводится: провалы, код ≠ 0).
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <windows.h>
#include <cstdio>
#include <vector>
#include <cstring>

using namespace AsdaSecure;

static int g_fail = 0, g_overSend = 0, g_overSink = 0;
static void CHECK(bool ok, const char* what) { printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what); if (!ok) { ++g_fail; } }

static std::vector<uint8_t> g_s2c[AsdaWire::kMaxSlots], g_sink[AsdaWire::kMaxSlots];
static int MockSend(void*, int slot, const void* d, int n)
{
    if (n > 0x1000) { ++g_overSend; g_s2c[slot].insert(g_s2c[slot].end(), (size_t)n, (uint8_t)0); return 1; }
    g_s2c[slot].insert(g_s2c[slot].end(), (const uint8_t*)d, (const uint8_t*)d + n);
    return 1;
}
static int MockSink(void*, const void* d, int n, int slot)
{
    if (n > 0x1000 - 9) { ++g_overSink; return 0; }
    g_sink[slot].insert(g_sink[slot].end(), (const uint8_t*)d, (const uint8_t*)d + n);
    return 1;
}
static std::vector<uint8_t> Frame(uint16_t op, size_t total, uint8_t fill)
{
    std::vector<uint8_t> f(total, fill);
    f[0] = 0xFB; f[1] = (uint8_t)(total & 0xFF); f[2] = (uint8_t)(total >> 8); f[7] = (uint8_t)op; f[8] = (uint8_t)(op >> 8); f.back() = 0xFE;
    return f;
}
static PublicKey g_pub{};
static bool Open(int slot, ClientChannel& c)
{
    AsdaWire::ResetSlot(slot); g_s2c[slot].clear();
    c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr; AsdaWire::RecvRoute(nullptr, slot, h.data(), (int)h.size(), &o);
    std::vector<uint8_t> d; const bool ok = c.OnRecv(g_s2c[slot].data(), g_s2c[slot].size(), d) == Err::Ok && c.IsReady();
    g_s2c[slot].clear();
    return ok;
}

int main()
{
#ifdef STAND_OLD_BRIDGE
    printf("== stand_limit4096: предел 0x1000 стока — мост fix2b (ДО правки Н-1) ==\n");
#else
    printf("== stand_limit4096: предел 0x1000 стока — мост fix2c ==\n");
#endif
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }
    PrivateKey priv{}; GenerateLongTermKey(priv);
    wchar_t kp[MAX_PATH]; { wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t); _snwprintf(kp, MAX_PATH, L"%sstand_limit_%lu.key", t, GetCurrentProcessId()); }
    SavePrivateKeyFile(kp, priv); memcpy(g_pub.xy, priv.xy, kPubLen);
    AsdaWire::Init(SubServer::Game, kp, true, &MockSend);

    // пакеты стока на готовый Secure-канал
    int slot = 1;
    for (size_t len : { (size_t)4095, (size_t)4096, (size_t)8200 })
    {
        ClientChannel c; Open(slot, c);
        const std::vector<uint8_t> f = Frame(0x1771, len, 0x5A);
        const int ov0 = g_overSend;
        AsdaWire::SendRoute(nullptr, slot, f.data(), (int)f.size());
        std::vector<uint8_t> d; const Err e = c.OnRecv(g_s2c[slot].data(), g_s2c[slot].size(), d);
        char msg[160]; sprintf(msg, "пакет %zu б → Send длиннее 0x1000: %d раз, клиент OnRecv = %s, поток %s", len, g_overSend - ov0, ErrName(e),
                               (e == Err::Ok && d == f) ? "цел" : "ИСПОРЧЕН");
        CHECK(g_overSend == ov0 && e == Err::Ok && d == f, msg);
        ++slot;
    }
    // очередь до рукопожатия > 4 КБ (Н-5)
    {
        AsdaWire::ResetSlot(slot, 0); AsdaWire::ResetSlot(slot, 1); g_s2c[slot].clear();
        std::vector<uint8_t> want;
        for (int i = 0; i < 3; ++i) { const auto f = Frame((uint16_t)(0x500 + i), 2000, (uint8_t)(0x30 + i)); AsdaWire::SendRoute(nullptr, slot, f.data(), (int)f.size()); want.insert(want.end(), f.begin(), f.end()); }
        ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
        const int ov0 = g_overSend;
        const uint8_t* o = nullptr; AsdaWire::RecvRoute(nullptr, slot, h.data(), (int)h.size(), &o);
        std::vector<uint8_t> d; const Err e = c.OnRecv(g_s2c[slot].data(), g_s2c[slot].size(), d);
        char msg[160]; sprintf(msg, "очередь до рукопожатия 6000 б → Send длиннее 0x1000: %d, клиент OnRecv = %s, поток %s", g_overSend - ov0, ErrName(e),
                               (e == Err::Ok && d == want) ? "цел" : "ИСПОРЧЕН");
        CHECK(g_overSend == ov0 && e == Err::Ok && d == want, msg);
        ++slot;
    }
    // приём: кадр клиента 12 КБ (очередь Flush клиента) → разборщику стока
    {
        ClientChannel c; Open(slot, c); g_sink[slot].clear();
        std::vector<uint8_t> big; for (int i = 0; i < 20; ++i) { const auto f = Frame(0x3EB, 600, (uint8_t)i); big.insert(big.end(), f.begin(), f.end()); }
        std::vector<uint8_t> ct; c.OnSend(big.data(), big.size(), ct);
        const int os0 = g_overSink;
        const uint8_t* o = nullptr;
#ifdef STAND_OLD_BRIDGE
        const int n = AsdaWire::RecvRoute(nullptr, slot, ct.data(), (int)ct.size(), &o);   // трамплин: одна порция стоку
        if (n > 0) { MockSink(nullptr, o, n, slot); }
#else
        AsdaWire::SetRecvSink(&MockSink);
        AsdaWire::RecvRoute(nullptr, slot, ct.data(), (int)ct.size(), &o);                  // мост сам отдаёт кусками
        AsdaWire::SetRecvSink(nullptr);
#endif
        char msg[160]; sprintf(msg, "приём кадра клиента %zu б → порций стоку длиннее 4087: %d, поток стока %s", big.size(), g_overSink - os0,
                               g_sink[slot] == big ? "цел" : "ИСПОРЧЕН");
        CHECK(g_overSink == os0 && g_sink[slot] == big, msg);
    }
    DeleteFileW(kp);
    printf(g_fail == 0 ? "\n== ВСЁ СОШЛОСЬ, провалов 0 ==\n" : "\n== ПРОВАЛОВ: %d (Н-1 воспроизведён) ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
