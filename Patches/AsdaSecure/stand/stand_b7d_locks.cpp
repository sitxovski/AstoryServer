// Copyright (c) 2026 @sitxovski (Discord)
// stand_b7d_locks.cpp — РЕГРЕСС блокировок и гонок моста AsdaWire (Б-1/Б-2 ревизии INTEG3) на НАСТОЯЩЕМ коде
// AsdaServerBridge.cpp / AsdaChannel.cpp / AsdaSecure.cpp.
//
// Происхождение: стенд ревизора AstoryServer/_archive_waves/AsdaPatch_rev3/stand_b7d_locks (13.10.2026) — там S1/S1b/S2 воспроизводили
// дефекты на коде integ3 (run_s1.txt «ВЗАИМНАЯ БЛОКИРОВКА», run_s2.txt «Replay, 80 из 4 000 000 байт»). fix2 перенёс его
// сюда и перевёл на новый путь моста (трамплин отправки = AsdaWire::SendRoute), добавив S2m/S3/S4/S5.
//
// Модель стока (дизасм GameServer 4e20f0ad; LoginManager 51db86b2 — та же библиотека Ciocp):
//   L = Ciocp+0x60D1830 — ОДНА критическая секция на весь Ciocp (EnterCriticalSection через 0x568D50 / LM 0x41A620).
//   Ciocp::Send 0x561F20       : Enter(L) … копия в буфер сокета (WriteFile либо досылочный буфер) … Leave(L)
//   Ciocp::DisConnect 0x561C30 : Enter(L) … 0x563B60 → SetConnectFlag(slot,0) 0x562910 … Leave(L)
//   SetConnectFlag 0x562910    : [детур P61 → AsdaWire::ResetSlot(slot)] → Enter(L) … (L рекурсивная)
//   Ошибка WriteFile 64 в Send : под L → 0x561D70 → 0x563B60 → SetConnectFlag (S3: режим «ошибка сокета»)
//   Трамплин приёма            : AsdaWire::RecvRoute → под cs_X: ServerHello → Ciocp::Send (Enter(L))
//   Трамплин отправки (fix2)   : AsdaWire::SendRoute → под cs_X: шифрование + Ciocp::Send (Enter(L))
//
// Сценарии (все должны пройти — ИТОГ «дефектов не найдено», код 0):
//   S1  принудительное чередование приёма: «DisConnect» держит L и зовёт SetConnectFlag→ResetSlot, пока «IOCP» внутри
//       RecvRoute (рукопожатие) держит cs_X и ждёт L в Send → блокировки быть не должно (ResetSlot без cs_X).
//   S1b естественное чередование без задержек 10 с: accept+рукопожатие на слоте против DisConnect того же слота.
//   S2  две нити шлют на ОДИН слот по 50 000 кадров — клиент расшифровал всё, порядок номеров верный.
//   S2m 21 нить карт + 1 нить 6004 (как ThreadInfo.ini COUNT=21 и MessageListeSocketIocpProcess) по 5 000 кадров.
//   S3  отправка нескольких нитей против DisConnect/accept того же слота (и «ошибка WriteFile» под L) 5 с — без блокировки.
//   S4  после S3: новый клиент на том же слоте — рукопожатие и кадры проходят (старые ключи/номера не видны).
//   S5  принудительное чередование отправки: «DisConnect» держит L, отправитель внутри SendRoute держит cs_X и ждёт L.
//   S6  ★ fix2b: отказ до рукопожатия — «логика» (accept → SendRoute(2253) → DisConnect через ворота) против «IOCP»
//       (ClientHello) в случайном порядке, 3000 итераций: клиент КАЖДЫЙ раз получил ServerHello + 2253, настоящий DisConnect
//       ровно один на итерацию, блокировок нет.
//   S2big ★ fix2c (Н-1): 2 нити по 1500 пакетов 4095 б (GS копит пакет до 0xFFF) — мок стокового Send держит ПРЕДЕЛ 0x1000
//       (длиннее — нули, как сток: копии нет, WriteFile уходит); поток цел, порядок верный, вызовов длиннее 0x1000 — 0.
//   S6L ★ fix2c (Н-2): S6 с паузой PreHandshakeLingerMs=150 (200 итераций) — отказ доставлен, разрыв ровно один, не раньше паузы.
#include <windows.h>
#include <process.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"

using namespace AsdaSecure;

static CRITICAL_SECTION g_L;                 // Ciocp-лок (Ciocp+0x60D1830)
static CRITICAL_SECTION g_wireCs;            // защита «провода» s2c (часть модели сокета)
static std::vector<uint8_t> g_s2c[AsdaWire::kMaxSlots];   // байты, ушедшие в сокет слота (в порядке захвата L)
static HANDLE g_evInSend = nullptr;          // S1/S5: нить внутри Send (держит cs_X), до захвата L
static volatile LONG g_signalInSend = 0;
static volatile LONG g_sockErrEvery = 0;     // S3: каждая N-я отправка имитирует WriteFile 64 → DisConnect под L

static void MockSetConnectFlag(int slot, int flag);
static void MockDisConnectLocked(int slot) { MockSetConnectFlag(slot, 0); }

// Стоковый Ciocp::Send: Enter(L) → копия → Leave(L). Возврат 1/0, как у стока.
static volatile LONG g_sendCount = 0;
static volatile LONG g_overSend = 0;           // ★ fix2c (Н-1): вызовов длиннее 0x1000 (сток: копии нет, уходят нули)
static int MockCiocpSend(void*, int slot, const void* data, int len)
{
    if (g_signalInSend) { SetEvent(g_evInSend); }
    EnterCriticalSection(&g_L);
    EnterCriticalSection(&g_wireCs);
    if (len > 0x1000) { InterlockedIncrement(&g_overSend); g_s2c[slot].insert(g_s2c[slot].end(), (size_t)len, (uint8_t)0); }
    else { g_s2c[slot].insert(g_s2c[slot].end(), (const uint8_t*)data, (const uint8_t*)data + len); }
    LeaveCriticalSection(&g_wireCs);
    const LONG n = InterlockedIncrement(&g_sendCount);
    const LONG every = g_sockErrEvery;
    if (every > 0 && n % every == 0) { MockDisConnectLocked(slot); }   // 0x561D70 → 0x563B60 → SetConnectFlag под L
    LeaveCriticalSection(&g_L);
    return 1;
}
// Стоковый SetConnectFlag с детуром P61 на входе.
static void MockSetConnectFlag(int slot, int flag)
{
    AsdaWire::ResetSlot(slot, flag);         // детур P61_SetConnTramp → P61_ResetSlotC(slot, flag) (fix2: без cs_X)
    EnterCriticalSection(&g_L);              // тело стока
    LeaveCriticalSection(&g_L);
}
// Стоковый DisConnect: [★ fix2b: детур входа → ворота DisconnectGate] → Enter(L) → … → SetConnectFlag(slot,0) → Leave(L).
static volatile LONG g_realDisc[AsdaWire::kMaxSlots] = {};   // настоящих (не отложенных) DisConnect по слоту
static void MockDisConnect(int slot)
{
    if (AsdaWire::DisconnectGate(nullptr, slot, 0)) { return; }   // отложен: сток не выполняется (вернул бы 1)
    EnterCriticalSection(&g_L);
    MockSetConnectFlag(slot, 0);
    LeaveCriticalSection(&g_L);
    InterlockedIncrement(&g_realDisc[slot]);
}

static PublicKey g_pub{};
static std::vector<uint8_t> MakeClientHello(ClientChannel& c)
{
    c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h); return h;
}
// Открыть Secure-сессию на слоте: accept + ClientHello → ServerHello → клиент готов.
static bool OpenSecure(int slot, ClientChannel& c)
{
    MockSetConnectFlag(slot, 1);
    std::vector<uint8_t> h = MakeClientHello(c);
    EnterCriticalSection(&g_wireCs); g_s2c[slot].clear(); LeaveCriticalSection(&g_wireCs);
    const uint8_t* o = nullptr;
    AsdaWire::RecvRoute(nullptr, slot, h.data(), (int)h.size(), &o);
    std::vector<uint8_t> d;
    EnterCriticalSection(&g_wireCs);
    std::vector<uint8_t> sh = g_s2c[slot]; g_s2c[slot].clear();
    LeaveCriticalSection(&g_wireCs);
    return c.OnRecv(sh.data(), sh.size(), d) == Err::Ok && c.IsReady();
}

static int g_rc = 0;
static volatile LONG g_errCount[32] = {};   // отчёты моста по коду ошибки (AsdaSecure::Err) — причина разрывов в S3
static void Bad(const char* m) { printf("   [!!] %s\n", m); g_rc = 1; }

// ── S1 ──
struct S1Ctx { int slot; std::vector<uint8_t> hello; };
static unsigned __stdcall S1_Iocp(void* p)
{
    S1Ctx* c = (S1Ctx*)p; const uint8_t* out = nullptr;
    AsdaWire::RecvRoute(nullptr, c->slot, c->hello.data(), (int)c->hello.size(), &out);
    return 0;
}
static unsigned __stdcall S1_Disc(void* p)
{
    S1Ctx* c = (S1Ctx*)p;
    EnterCriticalSection(&g_L);                       // DisConnect вошёл в L (0x561C6B)
    HANDLE h = (HANDLE)_beginthreadex(nullptr, 0, S1_Iocp, c, 0, nullptr);   // в это время пришёл ClientHello
    WaitForSingleObject(g_evInSend, 5000);            // IOCP внутри RecvRoute под cs_X, идёт в Ciocp::Send
    Sleep(20);                                        // дать ему дойти до Enter(L)
    MockSetConnectFlag(c->slot, 0);                   // 0x563C03 → детур → ResetSlot (fix2: без cs_X)
    LeaveCriticalSection(&g_L);
    WaitForSingleObject(h, INFINITE); CloseHandle(h);
    return 0;
}

// ── S5 (отправка) ──
struct S5Ctx { int slot; std::vector<uint8_t> frame; };
static unsigned __stdcall S5_Sender(void* p)
{
    S5Ctx* c = (S5Ctx*)p;
    AsdaWire::SendRoute(nullptr, c->slot, c->frame.data(), (int)c->frame.size());
    return 0;
}
static unsigned __stdcall S5_Disc(void* p)
{
    S5Ctx* c = (S5Ctx*)p;
    EnterCriticalSection(&g_L);
    HANDLE h = (HANDLE)_beginthreadex(nullptr, 0, S5_Sender, c, 0, nullptr);
    WaitForSingleObject(g_evInSend, 5000);            // отправитель внутри SendRoute под cs_X, идёт в Ciocp::Send
    Sleep(20);
    MockSetConnectFlag(c->slot, 0);
    LeaveCriticalSection(&g_L);
    WaitForSingleObject(h, INFINITE); CloseHandle(h);
    return 0;
}

// ── S1b ──
static volatile LONG g_stop = 0, g_hs = 0, g_disc = 0;
static const int kS1bSlot = 7;
static unsigned __stdcall S1b_Iocp(void*)
{
    ClientChannel c;
    while (!g_stop)
    {
        MockSetConnectFlag(kS1bSlot, 1);              // accept (563C50 → SetConnectFlag(slot,1))
        std::vector<uint8_t> h = MakeClientHello(c);
        const uint8_t* out = nullptr;
        AsdaWire::RecvRoute(nullptr, kS1bSlot, h.data(), (int)h.size(), &out);
        InterlockedIncrement(&g_hs);
    }
    return 0;
}
static unsigned __stdcall S1b_Disc(void*)
{
    while (!g_stop) { MockDisConnect(kS1bSlot); InterlockedIncrement(&g_disc); SwitchToThread(); }
    return 0;
}

// ── S2/S2m: несколько нитей шлют на ОДИН слот ──
struct SendCtx { int slot; int tid; int frames; int flen; };
static unsigned __stdcall Sender(void* p)
{
    SendCtx* c = (SendCtx*)p;
    std::vector<uint8_t> frame((size_t)c->flen);
    for (int i = 0; i < c->frames; ++i)
    {
        memset(frame.data(), (uint8_t)c->tid, frame.size());
        frame[0] = 0xFB; frame[1] = (uint8_t)c->tid; memcpy(frame.data() + 2, &i, 4); frame[c->flen - 1] = 0xFE;
        AsdaWire::SendRoute(nullptr, c->slot, frame.data(), (int)frame.size());   // трамплин отправки (fix2): шифрование + Send под cs_X
    }
    return 0;
}
// Прогнать nThreads отправителей; клиент расшифровывает поток; проверить полноту и порядок кадров каждой нити.
static void RunSenders(const char* name, int slot, int nThreads, int frames, int flen = 40)
{
    ClientChannel cli;
    if (!OpenSecure(slot, cli)) { Bad("рукопожатие не прошло"); return; }
    std::vector<SendCtx> ctx(nThreads);
    std::vector<HANDLE> th(nThreads);
    DWORD t0 = GetTickCount();
    for (int t = 0; t < nThreads; ++t) { ctx[t] = { slot, t + 1, frames, flen }; th[t] = (HANDLE)_beginthreadex(nullptr, 0, Sender, &ctx[t], 0, nullptr); }
    for (int t = 0; t < nThreads; ++t) { WaitForSingleObject(th[t], INFINITE); CloseHandle(th[t]); }
    DWORD ms = GetTickCount() - t0;
    std::vector<uint8_t> plain;
    Err e = cli.OnRecv(g_s2c[slot].data(), g_s2c[slot].size(), plain);
    const size_t want = (size_t)nThreads * frames * flen;
    const LONG ov = g_overSend;
    // порядок: у каждой нити номера кадров строго 0,1,2,… в принятом потоке
    std::vector<int> next(nThreads + 1, 0);
    bool orderOk = (plain.size() % flen) == 0;
    for (size_t off = 0; orderOk && off + flen <= plain.size(); off += flen)
    {
        const uint8_t* f = plain.data() + off;
        int tid = f[1], i; memcpy(&i, f + 2, 4);
        if (f[0] != 0xFB || f[flen - 1] != 0xFE || tid < 1 || tid > nThreads || i != next[tid]) { orderOk = false; break; }
        ++next[tid];
    }
    printf("%s %d нит. × %d кадров на один слот: клиент OnRecv = %s, получено %zu из %zu байт, порядок кадров нитей %s (%lu мс)\n",
           name, nThreads, frames, ErrName(e), plain.size(), want, orderOk ? "верный" : "НАРУШЕН", (unsigned long)ms);
    if (ov) { printf("   вызовов стокового Send длиннее 0x1000: %ld\n", ov); }
    if (e != Err::Ok || plain.size() != want || !orderOk || ov) { Bad("клиент получил порченый/переставленный поток (Replay/BadTag на живом) / Send длиннее 0x1000"); }
    else { printf("   [OK] %s: поток цел, номера кадров по порядку\n", name); }
    g_s2c[slot].clear();
}

// ── S3: отправители против DisConnect/accept того же слота ──
static const int kS3Slot = 12;
static volatile LONG g_s3sends = 0, g_s3disc = 0;
static unsigned __stdcall S3_Sender(void* p)
{
    uint8_t frame[40] = { 0xFB }; frame[1] = (uint8_t)(UINT_PTR)p; frame[39] = 0xFE;
    while (!g_stop) { AsdaWire::SendRoute(nullptr, kS3Slot, frame, sizeof(frame)); InterlockedIncrement(&g_s3sends); }
    return 0;
}
static unsigned __stdcall S3_Disc(void*)
{
    ClientChannel c;
    while (!g_stop)
    {
        MockDisConnect(kS3Slot);
        EnterCriticalSection(&g_wireCs); g_s2c[kS3Slot].clear(); LeaveCriticalSection(&g_wireCs);   // «сокет» закрыт — провод пуст
        MockSetConnectFlag(kS3Slot, 1);
        std::vector<uint8_t> h = MakeClientHello(c); const uint8_t* o = nullptr;
        AsdaWire::RecvRoute(nullptr, kS3Slot, h.data(), (int)h.size(), &o);
        InterlockedIncrement(&g_s3disc);
    }
    return 0;
}

// ── S6 (★ fix2b): отказ до рукопожатия в случайном порядке с ClientHello ──
static const int kS6Slot = 14;
static volatile LONG g_s6Go = 0;
static const uint8_t kRefuse[12] = { 0xFB, 12, 0, 0, 0, 0, 0, 0xCD, 0x08, 7, 0, 0xFE };   // 2253 «сервер переполнен»
static unsigned __stdcall S6_Logic(void* p)
{
    while (!g_s6Go) { YieldProcessor(); }
    if ((UINT_PTR)p & 1) { SwitchToThread(); }
    AsdaWire::SendRoute(nullptr, kS6Slot, kRefuse, sizeof(kRefuse));    // ProcConnect: 2253
    MockDisConnect(kS6Slot);                                             // и сразу DisConnect (0x4138D0)
    return 0;
}
struct S6Ctx { std::vector<uint8_t> hello; int jitter; };
static unsigned __stdcall S6_Iocp(void* p)
{
    S6Ctx* c = (S6Ctx*)p;
    while (!g_s6Go) { YieldProcessor(); }
    for (int i = 0; i < c->jitter; ++i) { YieldProcessor(); }
    const uint8_t* o = nullptr;
    AsdaWire::RecvRoute(nullptr, kS6Slot, c->hello.data(), (int)c->hello.size(), &o);
    return 0;
}

// Сторож: ждать нить не дольше ms; false — висит (взаимная блокировка).
static bool Join(HANDLE h, DWORD ms) { const DWORD w = WaitForSingleObject(h, ms); return w == WAIT_OBJECT_0; }

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "all";
    auto on = [&](const char* m) { return !strcmp(mode, "all") || !strcmp(mode, m); };
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("== stand_b7d_locks (регресс Б-1/Б-2 integ3, fix2): блокировки/гонки AsdaWire на настоящем коде ==\n");
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }
    InitializeCriticalSection(&g_L); InitializeCriticalSection(&g_wireCs);
    g_evInSend = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    PrivateKey priv{}; GenerateLongTermKey(priv);
    wchar_t keyPath[MAX_PATH]; { wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t); _snwprintf(keyPath, MAX_PATH, L"%sstand_b7d_locks_%lu.key", t, GetCurrentProcessId()); }
    SavePrivateKeyFile(keyPath, priv); memcpy(g_pub.xy, priv.xy, kPubLen);
    if (!AsdaWire::Init(SubServer::Game, keyPath, true, &MockCiocpSend)) { printf("ключ не загрузился\n"); return 2; }
    AsdaWire::SetFailureHooks([](void*, int s) { MockDisConnect(s); },
                              [](void*, int, const AsdaWire::FailInfo& fi) { InterlockedIncrement(&g_errCount[(int)fi.err & 31]); },
                              nullptr, true);

    if (on("s2"))  { RunSenders("S2", 9, 2, 50000); }
    if (on("s2m")) { RunSenders("S2m (21 нить карт + нить 6004)", 10, 22, 5000); }
    if (on("s2big")) { RunSenders("S2big (пакеты 4095 б, предел Send 0x1000)", 15, 2, 1500, 4095); }

    if (on("s1b"))
    {
        { ClientChannel w; OpenSecure(kS1bSlot, w); }   // прогрев (как после первого входа)
        g_stop = 0; g_hs = 0; g_disc = 0;
        HANDLE a = (HANDLE)_beginthreadex(nullptr, 0, S1b_Iocp, nullptr, 0, nullptr);
        HANDLE b = (HANDLE)_beginthreadex(nullptr, 0, S1b_Disc, nullptr, 0, nullptr);
        LONG lastHs = -1; int still = 0; bool dead = false;
        for (int i = 0; i < 100; ++i)
        {
            Sleep(100);
            LONG hs = g_hs;
            if (hs == lastHs) { if (++still >= 10) { dead = true; break; } } else { still = 0; }
            lastHs = hs;
        }
        g_stop = 1;
        const bool joined = !dead && Join(a, 3000) && Join(b, 3000);
        printf("S1b естественное чередование 10 с: рукопожатий %ld, DisConnect %ld — %s\n", g_hs, g_disc,
               dead ? "ВЗАИМНАЯ БЛОКИРОВКА (1 с без продвижения)" : (joined ? "блокировки нет, нити завершились" : "нити НЕ завершились"));
        if (dead || !joined) { Bad("S1b: cs_X → L (RecvRoute → Send) против L → cs_X (DisConnect → SetConnectFlag → ResetSlot)"); }
        else { printf("   [OK] S1b: блокировки нет\n"); }
    }

    if (on("s3"))
    {
        g_stop = 0; g_s3sends = 0; g_s3disc = 0; g_sockErrEvery = 97;   // каждая 97-я отправка — «WriteFile 64» → DisConnect под L
        { ClientChannel w; OpenSecure(kS3Slot, w); }
        HANDLE s[4]; for (int i = 0; i < 4; ++i) { s[i] = (HANDLE)_beginthreadex(nullptr, 0, S3_Sender, (void*)(UINT_PTR)(i + 1), 0, nullptr); }
        HANDLE d = (HANDLE)_beginthreadex(nullptr, 0, S3_Disc, nullptr, 0, nullptr);
        LONG lastS = -1, lastD = -1; int still = 0; bool dead = false;
        for (int i = 0; i < 50; ++i)
        {
            Sleep(100);
            const LONG cs = g_s3sends, cd = g_s3disc;
            if (cs == lastS && cd == lastD) { if (++still >= 10) { dead = true; break; } } else { still = 0; }
            lastS = cs; lastD = cd;
        }
        g_stop = 1;
        bool joined = !dead && Join(d, 3000);
        for (int i = 0; i < 4 && joined; ++i) { joined = Join(s[i], 3000); }
        g_sockErrEvery = 0;
        printf("S3 4 отправителя против DisConnect/accept/рукопожатия того же слота 5 с (+ «ошибка WriteFile» под L): отправок %ld, переподключений %ld — %s\n",
               g_s3sends, g_s3disc, dead ? "ВЗАИМНАЯ БЛОКИРОВКА" : (joined ? "блокировки нет" : "нити НЕ завершились"));
        if (dead || !joined) { Bad("S3: блокировка отправки против разрыва"); } else { printf("   [OK] S3: блокировки нет\n"); }

        // S4: новый клиент на том же слоте после всей этой гонки — старые ключи/номера не видны
        if (!dead && joined)
        {
            ClientChannel n;
            const bool hs = OpenSecure(kS3Slot, n);
            uint8_t f[40] = { 0xFB, 0x77 }; f[39] = 0xFE;
            AsdaWire::SendRoute(nullptr, kS3Slot, f, sizeof(f));
            std::vector<uint8_t> p; const Err e = n.OnRecv(g_s2c[kS3Slot].data(), g_s2c[kS3Slot].size(), p);
            printf("S4 новый клиент на слоте после S3: рукопожатие %s, кадр сервера %s\n", hs ? "прошло" : "НЕ прошло", ErrName(e));
            if (!hs || e != Err::Ok || p.size() != sizeof(f) || memcmp(p.data(), f, sizeof(f)) != 0) { Bad("S4: новый клиент увидел чужую сессию"); }
            else { printf("   [OK] S4: новый клиент получил чистую сессию\n"); }
        }
    }

    if (on("s5"))
    {
        static S5Ctx c5; c5.slot = 13; c5.frame.assign(40, 0x33); c5.frame[0] = 0xFB; c5.frame[39] = 0xFE;
        { ClientChannel w; OpenSecure(c5.slot, w); }
        g_signalInSend = 1; ResetEvent(g_evInSend);
        HANDLE d = (HANDLE)_beginthreadex(nullptr, 0, S5_Disc, &c5, 0, nullptr);
        const bool ok = Join(d, 5000);
        g_signalInSend = 0;
        printf("S5 принудительное чередование отправки (DisConnect держит L, SendRoute держит cs_X и ждёт L): %s\n",
               ok ? "блокировки нет" : "ВЗАИМНАЯ БЛОКИРОВКА (5 с)");
        if (!ok) { Bad("S5: cs_X → L против L → cs_X на отправке"); } else { printf("   [OK] S5: блокировки нет\n"); }
    }

    if (on("s6"))
    {
        AsdaWire::SetLingerMs(0);                     // 3000 итераций — разрыв сразу после выдачи (пауза Н-2 — в S6L)
        int okCnt = 0, badDeliver = 0, badDisc = 0; bool hung = false;
        for (int it = 0; it < 3000 && !hung; ++it)
        {
            MockSetConnectFlag(kS6Slot, 1);                                // accept (сток: до первого ReadFile)
            EnterCriticalSection(&g_wireCs); g_s2c[kS6Slot].clear(); LeaveCriticalSection(&g_wireCs);
            const LONG disc0 = g_realDisc[kS6Slot];
            ClientChannel cli; S6Ctx ctx; ctx.hello = MakeClientHello(cli); ctx.jitter = (it * 7919) % 4000;
            g_s6Go = 0;
            HANDLE a = (HANDLE)_beginthreadex(nullptr, 0, S6_Logic, (void*)(UINT_PTR)it, 0, nullptr);
            HANDLE b = (HANDLE)_beginthreadex(nullptr, 0, S6_Iocp, &ctx, 0, nullptr);
            g_s6Go = 1;
            hung = !Join(a, 5000) || !Join(b, 5000);
            CloseHandle(a); CloseHandle(b);
            if (hung) { break; }
            std::vector<uint8_t> plain;
            EnterCriticalSection(&g_wireCs); std::vector<uint8_t> wire = g_s2c[kS6Slot]; LeaveCriticalSection(&g_wireCs);
            const Err e = cli.OnRecv(wire.data(), wire.size(), plain);
            const bool delivered = e == Err::Ok && cli.IsReady() && plain.size() == sizeof(kRefuse) && memcmp(plain.data(), kRefuse, sizeof(kRefuse)) == 0;
            const LONG discs = g_realDisc[kS6Slot] - disc0;
            if (!delivered) { ++badDeliver; }
            if (discs != 1) { ++badDisc; }
            if (delivered && discs == 1) { ++okCnt; }
        }
        AsdaWire::Counters c6{}; AsdaWire::GetCounters(&c6);
        printf("S6 отказ 2253 до рукопожатия против ClientHello, случайный порядок: итераций с доставкой и одним DisConnect %d из 3000, "
               "не доставлено %d, DisConnect не ровно один %d%s; отложенных разрывов всего %ld, выдач очереди %ld\n",
               okCnt, badDeliver, badDisc, hung ? " — ВЗАИМНАЯ БЛОКИРОВКА" : "", c6.deferredCloses, c6.preFlushed);
        if (hung || badDeliver || badDisc) { Bad("S6: отказ до рукопожатия потерян / разрыв не один / блокировка"); }
        else { printf("   [OK] S6: отказ доходит до Secure-клиента в любом порядке, разрыв ровно один, блокировки нет\n"); }
    }

    if (on("s6l"))
    {
        AsdaWire::SetLingerMs(150);
        int okCnt = 0, bad = 0, early = 0; bool hung = false;
        for (int it = 0; it < 200 && !hung; ++it)
        {
            MockSetConnectFlag(kS6Slot, 1);
            EnterCriticalSection(&g_wireCs); g_s2c[kS6Slot].clear(); LeaveCriticalSection(&g_wireCs);
            const LONG disc0 = g_realDisc[kS6Slot];
            ClientChannel cli; S6Ctx ctx; ctx.hello = MakeClientHello(cli); ctx.jitter = (it * 7919) % 4000;
            g_s6Go = 0;
            HANDLE a = (HANDLE)_beginthreadex(nullptr, 0, S6_Logic, (void*)(UINT_PTR)it, 0, nullptr);
            HANDLE b = (HANDLE)_beginthreadex(nullptr, 0, S6_Iocp, &ctx, 0, nullptr);
            g_s6Go = 1;
            hung = !Join(a, 5000) || !Join(b, 5000);
            const DWORD t0 = GetTickCount();
            CloseHandle(a); CloseHandle(b);
            if (hung) { break; }
            for (int w = 0; w < 100 && g_realDisc[kS6Slot] == disc0; ++w) { Sleep(10); }
            const DWORD dt = GetTickCount() - t0;
            std::vector<uint8_t> plain;
            EnterCriticalSection(&g_wireCs); std::vector<uint8_t> wire = g_s2c[kS6Slot]; LeaveCriticalSection(&g_wireCs);
            const bool delivered = cli.OnRecv(wire.data(), wire.size(), plain) == Err::Ok && plain.size() == sizeof(kRefuse) && memcmp(plain.data(), kRefuse, sizeof(kRefuse)) == 0;
            const LONG discs = g_realDisc[kS6Slot] - disc0;
            if (delivered && discs == 1) { ++okCnt; } else { ++bad; }
            (void)dt; (void)early;
        }
        printf("S6L отказ до рукопожатия с паузой 150 мс: доставлен и один DisConnect %d из 200, иначе %d%s\n", okCnt, bad, hung ? " — ВЗАИМНАЯ БЛОКИРОВКА" : "");
        if (hung || bad) { Bad("S6L: отказ не доставлен / разрыв не один / блокировка"); } else { printf("   [OK] S6L: отказ доставлен, разрыв ровно один, блокировок нет\n"); }
        AsdaWire::SetLingerMs(0);
    }

    // S1 — принудительное чередование приёма (последним: при блокировке нити остаются висеть).
    if (on("s1"))
    {
        static S1Ctx c; c.slot = 11; ClientChannel cli; c.hello = MakeClientHello(cli);
        MockSetConnectFlag(c.slot, 1);
        if (TryEnterCriticalSection(&g_L))
        {
            LeaveCriticalSection(&g_L);
            g_signalInSend = 1; ResetEvent(g_evInSend);
            HANDLE d = (HANDLE)_beginthreadex(nullptr, 0, S1_Disc, &c, 0, nullptr);
            const bool ok = Join(d, 5000);
            g_signalInSend = 0;
            printf("S1 принудительное чередование приёма (DisConnect держит L, RecvRoute держит cs_X и ждёт L): %s\n",
                   ok ? "блокировки нет" : "ВЗАИМНАЯ БЛОКИРОВКА (5 с)");
            if (!ok) { Bad("S1: на живом сервере L — общий лок Ciocp: встанут ВСЕ приёмы/отправки/accept процесса"); }
            else { printf("   [OK] S1: блокировки нет\n"); }
        }
        else { printf("S1 пропущен: L уже навсегда захвачен блокировкой из прежнего сценария\n"); g_rc = 1; }
    }

    AsdaWire::Counters cn{}; AsdaWire::GetCounters(&cn);
    printf("счётчики моста: применённых сбросов %ld, разрывов %ld, сбоев отправки %ld, отправок стоком %ld\n",
           cn.resetsApplied, cn.kills, cn.sendFails, g_sendCount);
    printf("вызовов стокового Send длиннее 0x1000 (Н-1): %ld\n", g_overSend);
    if (g_overSend) { Bad("стоковый Send получил больше 0x1000 б — у живого стока ушли бы нули"); }
    for (int i = 0; i < 32; ++i) { if (g_errCount[i]) { printf("  отчётов с ошибкой %s: %ld\n", ErrName((Err)i), g_errCount[i]); } }
    DeleteFileW(keyPath);
    printf("ИТОГ: %s\n", g_rc ? "НАЙДЕНЫ ДЕФЕКТЫ" : "дефектов не найдено");
    fflush(stdout);
    ExitProcess(g_rc);   // висящие нити (если блокировка всё же случилась) не ждём
}
