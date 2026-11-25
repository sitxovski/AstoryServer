// Copyright (c) 2026 @sitxovski (Discord)
// stand_perf.cpp — замер производительности моста шифрования (P61/L07) на моке стока по дизасму (раскладка Ciocp, замок L).
//
// Вопрос владельца (14.10.2026): не роняет ли шифрование трафика производительность сервера и комфорт игроков.
// Что меряется (x86 /O2 /MT, как серверные DLL; «сток» = мок Ciocp::Send под замком L — копия кадра в досылку, БЕЗ WriteFile):
//   Т0  справка: стоимость настоящего send() на loopback-TCP (порядок цены стокового WriteFile/WSASend);
//   Т1  рукопожатие: сервер (RecvRoute(ClientHello) → ECDH + подпись ECDSA + HKDF), клиент (Start, проверка подписи + вывод ключей);
//       «шторм входов» — рукопожатия на 1/2/4/8/16 нитях (массовый реконнект после рестарта);
//   Т2  отправка одного кадра (SendRoute: шифрование + проверка досылки под L + сток) против голого стока, по размерам кадра;
//   Т3  приём одного кадра (RecvRoute: расшифровка + отдача стоковому разборщику) против голого разборщика; пачкой по 10;
//   Т4  конкуренция: 4/22 нити шлют на 500 слотов вперемешку, 22 нити в ОДИН слот, 22 нити в темпе 200 000 кадров/с;
//       задержка вызова (p50/p99/p99.9/макс) и ОЖИДАНИЕ замка L пробником (как IoWorkerThread/accept ждут L) — «замирание сервера»;
//   Т4б 8 нитей (без переподписки ЦП) и сток с ценой WriteFile под L (5 мкс — пессимистично, Т0 даёт ~7 мкс на блокирующий send).
// Время — по TSC (калибровка по QPC). Сборка (Dev x86):
//   cl /nologo /utf-8 /std:c++17 /W3 /O2 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS /I src /Fo:obj\perf\ wire\stand_perf.cpp
//      src\AsdaSecure.cpp src\AsdaChannel.cpp src\AsdaServerBridge.cpp /link /MACHINE:X86 /OUT:out\stand_perf.exe bcrypt.lib ws2_32.lib
// ★ sec2: аргумент noaccel — прежний путь рукопожатия (сравнение в той же сборке). Мост и AsdaSecure не правятся; ключ — временный (генерируется, удаляется), рабочий secure_server.key не читается.
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <memory>
#include <algorithm>
#include <cstddef>

#pragma comment(lib, "ws2_32.lib")

using namespace AsdaSecure;

static int g_fail = 0;                                   // число провалов проверок целостности
static void CHECK(bool ok, const char* what) { printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what); if (!ok) { ++g_fail; } }

// ── время: TSC, калиброванный по QPC ──────────────────────────────────────────────────────────────────────────────
static double g_tscPerUs = 0;                            // тиков TSC в микросекунде
static void CalibrateTsc()
{
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    const uint64_t t0 = __rdtsc();
    do { QueryPerformanceCounter(&b); } while ((b.QuadPart - a.QuadPart) * 1000 / f.QuadPart < 200);
    const uint64_t t1 = __rdtsc();
    g_tscPerUs = (double)(t1 - t0) / ((double)(b.QuadPart - a.QuadPart) * 1e6 / (double)f.QuadPart);
}
static inline double Us(uint64_t ticks) { return (double)ticks / g_tscPerUs; }   // тики → мкс

// ── гистограмма задержек (50 нс до 50 мкс, дальше шаг 5 %) ─────────────────────────────────────────────────────────
struct Hist
{
    static constexpr int kLin = 1000, kN = 1600;         // линейных корзин и всего корзин
    std::vector<uint64_t> b;                              // счётчики корзин
    uint64_t n = 0;                                       // всего замеров
    double sum = 0, mx = 0;                               // сумма и максимум, мкс
    Hist() : b(kN, 0) {}
    static int Idx(double us)
    {
        if (us < 50.0) { return (int)(us * 20.0); }
        const int i = kLin + (int)(std::log(us / 50.0) / std::log(1.05));
        return i >= kN ? kN - 1 : i;
    }
    static double Val(int i) { return i < kLin ? (i + 0.5) / 20.0 : 50.0 * std::pow(1.05, (double)(i - kLin) + 0.5); }
    void Add(double us) { ++b[Idx(us)]; ++n; sum += us; if (us > mx) { mx = us; } }
    void Merge(const Hist& o) { for (int i = 0; i < kN; ++i) { b[i] += o.b[i]; } n += o.n; sum += o.sum; if (o.mx > mx) { mx = o.mx; } }
    double Q(double p) const
    {
        if (!n) { return 0; }
        const uint64_t want = (uint64_t)std::ceil(p * (double)n);
        uint64_t acc = 0;
        for (int i = 0; i < kN; ++i) { acc += b[i]; if (acc >= want) { return Val(i); } }
        return mx;
    }
    double Mean() const { return n ? sum / (double)n : 0; }
};

// ── мок стокового Ciocp (раскладка по дизасму GS 0x561F20 / LM 0x413AB0 — как в stand_backlog) ───────────────────────
constexpr uint32_t kStride = 0xA0BE, kConn = 4, kFly = 8, kPBuf = 0xB2, kPend = 0xA0B2;
constexpr int      kLimit = 0x9F9C, kDirect = 0x1000;
struct MockCiocp
{
    char             pad[40];                            // чтобы смещения были ненулевыми
    CRITICAL_SECTION L;                                  // замок L (Ciocp+0x60D1830 в GS)
    uint8_t*         sess;                               // [Ciocp+0x60D1898] — массив сессий слотов
};
static MockCiocp g_ci;
static uint8_t* SS(int slot) { return g_ci.sess + (size_t)slot * kStride; }
static volatile LONG& CONN(int slot) { return *(volatile LONG*)(SS(slot) + kConn); }
static volatile uint8_t& FLY(int slot) { return *(volatile uint8_t*)(SS(slot) + kFly); }
static volatile LONG& PEND(int slot) { return *(volatile LONG*)(SS(slot) + kPend); }
static uint8_t* PBUF(int slot) { return SS(slot) + kPBuf; }

static volatile LONG g_capture[AsdaWire::kMaxSlots] = {};    // 1 — копить байты слота для клиента (рукопожатие/проверка)
static std::vector<uint8_t> g_cap[AsdaWire::kMaxSlots];      // накопленные байты «в сокет» слота

// Мок стокового Send: под L — флаг соединения, «запись в полёте» (1), дописать кадр в досылку; досылка > 16 КБ — считаем, что
//   SendTemp её выдал (длина 0). Это НИЖНЯЯ оценка цены стока: настоящий делает ещё WriteFile (см. Т0).
static volatile LONG g_writeSpinNs = 0;                  // Т4б: имитация WriteFile под L (нс; 0 — без неё)
static int MockStockSend(void* self, int slot, const void* src, int n)
{
    MockCiocp* c = (MockCiocp*)self;
    if (!c || n < 0) { return 0; }
    EnterCriticalSection(&c->L);
    int rc = 0;
    if (slot >= 0 && slot < 0x226 && CONN(slot))
    {
        if (g_capture[slot]) { g_cap[slot].insert(g_cap[slot].end(), (const uint8_t*)src, (const uint8_t*)src + n); }
        FLY(slot) = 1;
        if (PEND(slot) + n > 16384) { PEND(slot) = 0; }
        memcpy(PBUF(slot) + PEND(slot), src, (size_t)n);
        PEND(slot) += n;
        rc = 1;
        if (g_writeSpinNs)
        {
            const uint64_t until = __rdtsc() + (uint64_t)(g_tscPerUs * g_writeSpinNs / 1000.0);
            while (__rdtsc() < until) { YieldProcessor(); }
        }
    }
    LeaveCriticalSection(&c->L);
    return rc;
}

// Мок стокового разборщика приёма (sub_563C20): копия порции в буфер сборки слота (0x1000), счёт байт.
static volatile LONG g_sinkBytes = 0;                    // всего байт, отданных разборщику
static uint8_t g_sinkBuf[AsdaWire::kMaxSlots][0x1000];   // буферы сборки слотов
static int MockSink(void* /*self*/, const void* data, int len, int slot)
{
    if (len > 0x1000 - 9 || slot < 0 || slot >= AsdaWire::kMaxSlots) { return 0; }
    memcpy(g_sinkBuf[slot], data, (size_t)len);
    InterlockedExchangeAdd(&g_sinkBytes, len);
    return 1;
}

static std::vector<uint8_t> Frame(uint16_t op, size_t total, uint8_t fill)   // старый кадр FB|size|A|B|op|body|FE
{
    if (total < 10) { total = 10; }
    std::vector<uint8_t> f(total, fill);
    f[0] = 0xFB; f[1] = (uint8_t)(total & 0xFF); f[2] = (uint8_t)(total >> 8); f[7] = (uint8_t)op; f[8] = (uint8_t)(op >> 8); f.back() = 0xFE;
    return f;
}

static PublicKey g_pub{};                                // открытый ключ временной пары (вшивается клиенту)

// Рукопожатие слота через мост (как в DLL: accept → ResetSlot(X,1), ClientHello → RecvRoute, ServerHello → сток).
static bool OpenSlot(int slot, ClientChannel& c)
{
    CONN(slot) = 1; FLY(slot) = 0; PEND(slot) = 0;
    AsdaWire::ResetSlot(slot, 1);
    g_cap[slot].clear(); InterlockedExchange(&g_capture[slot], 1);
    c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
    std::vector<uint8_t> d;
    const bool ok = c.OnRecv(g_cap[slot].data(), g_cap[slot].size(), d) == Err::Ok && c.IsReady();
    InterlockedExchange(&g_capture[slot], 0); g_cap[slot].clear();
    return ok;
}

// ── Т0: настоящий send() на loopback-TCP ─────────────────────────────────────────────────────────────────────────────
static SOCKET g_rx = INVALID_SOCKET;
static volatile bool g_rxStop = false;
static DWORD WINAPI Drain(LPVOID) { char b[65536]; while (!g_rxStop) { if (recv(g_rx, b, sizeof(b), 0) <= 0) { break; } } return 0; }
static void T0_RealSend()
{
    printf("\n── Т0. Справка: настоящий send() на loopback-TCP (порядок цены стокового WriteFile/WSASend) ──\n");
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    bind(ls, (sockaddr*)&a, sizeof(a)); int al = sizeof(a); getsockname(ls, (sockaddr*)&a, &al); listen(ls, 1);
    SOCKET tx = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    connect(tx, (sockaddr*)&a, sizeof(a)); g_rx = accept(ls, nullptr, nullptr);
    BOOL nd = TRUE; setsockopt(tx, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    HANDLE th = CreateThread(nullptr, 0, Drain, nullptr, 0, nullptr);
    for (size_t len : { (size_t)60, (size_t)700 })
    {
        std::vector<uint8_t> f = Frame(0x1771, len, 0x11);
        const int N = 100000;
        const uint64_t t0 = __rdtsc();
        for (int i = 0; i < N; ++i) { send(tx, (const char*)f.data(), (int)f.size(), 0); }
        const uint64_t t1 = __rdtsc();
        printf("  send() %4zu б: %.2f мкс/вызов\n", len, Us(t1 - t0) / N);
    }
    g_rxStop = true; closesocket(tx); WaitForSingleObject(th, 2000); closesocket(g_rx); closesocket(ls); CloseHandle(th);
}

// ── Т1: рукопожатие ──────────────────────────────────────────────────────────────────────────────────────────────────
struct StormArg { int first, count, iters; std::vector<std::vector<uint8_t>>* hellos; Hist h; };
static DWORD WINAPI StormThread(LPVOID p)
{
    StormArg& a = *(StormArg*)p;
    for (int it = 0; it < a.iters; ++it)
    {
        const int slot = a.first + (it % a.count);
        const std::vector<uint8_t>& hello = (*a.hellos)[(size_t)(it % a.hellos->size())];
        CONN(slot) = 1; AsdaWire::ResetSlot(slot, 1);
        const uint8_t* o = nullptr;
        const uint64_t t0 = __rdtsc();
        AsdaWire::RecvRoute(&g_ci, slot, hello.data(), (int)hello.size(), &o);
        a.h.Add(Us(__rdtsc() - t0));
    }
    return 0;
}
static void T1_Handshake()
{
    printf("\n── Т1. Рукопожатие (раз на соединение: вход на логин, вход в мир) ──\n");
    Hist hs, hcStart, hcFin;
    for (int i = 0; i < 400; ++i)
    {
        const int slot = 100 + (i % 50);
        ClientChannel c; c.Reset();
        CONN(slot) = 1; FLY(slot) = 0; PEND(slot) = 0; AsdaWire::ResetSlot(slot, 1);
        g_cap[slot].clear(); InterlockedExchange(&g_capture[slot], 1);
        std::vector<uint8_t> h;
        uint64_t t0 = __rdtsc(); c.Start(SubServer::Game, g_pub, h); hcStart.Add(Us(__rdtsc() - t0));
        const uint8_t* o = nullptr;
        t0 = __rdtsc(); AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o); hs.Add(Us(__rdtsc() - t0));
        std::vector<uint8_t> d;
        t0 = __rdtsc(); const Err e = c.OnRecv(g_cap[slot].data(), g_cap[slot].size(), d); hcFin.Add(Us(__rdtsc() - t0));
        InterlockedExchange(&g_capture[slot], 0);
        if (e != Err::Ok || !c.IsReady()) { CHECK(false, "рукопожатие не сошлось"); break; }
    }
    printf("  сервер (ECDH-пара + подпись ECDSA + ECDH + HKDF + ServerHello в сток): ср %.0f мкс, p50 %.0f, p99 %.0f, макс %.0f\n",
           hs.Mean(), hs.Q(.5), hs.Q(.99), hs.mx);
    printf("  клиент Start (ECDH-пара, ClientHello):                                   ср %.0f мкс, p99 %.0f\n", hcStart.Mean(), hcStart.Q(.99));
    printf("  клиент ServerHello (проверка подписи + ECDH + HKDF):                     ср %.0f мкс, p99 %.0f\n", hcFin.Mean(), hcFin.Q(.99));
    { AccelStats as{}; GetAccelStats(&as);
      printf("  ★ sec2: подписей кэшем %ld / с импортом %ld; пар ECDH из пула %ld / на месте %ld (размер пула %ld)\n",
             as.signCached, as.signImport, as.ephPool, as.ephInline, as.poolTarget); }

    // Шторм входов: заранее заготовленные ClientHello, сервер принимает их на N нитях (как N рабочих нитей IOCP).
    std::vector<std::vector<uint8_t>> hellos;
    std::vector<std::unique_ptr<ClientChannel>> keep;
    for (int i = 0; i < 64; ++i)
    {
        keep.emplace_back(new ClientChannel()); keep.back()->Reset();
        std::vector<uint8_t> h; keep.back()->Start(SubServer::Game, g_pub, h); hellos.push_back(h);
    }
    printf("  шторм входов (сервер, N нитей одновременно принимают рукопожатия):\n");
    for (int nt : { 1, 2, 4, 8, 16 })
    {
        const int per = 600 / nt < 100 ? 100 : 600 / nt;
        std::vector<StormArg> args((size_t)nt);
        std::vector<HANDLE> th;
        for (int t = 0; t < nt; ++t) { args[t].first = 200 + t * 20; args[t].count = 20; args[t].iters = per; args[t].hellos = &hellos; }
        const uint64_t t0 = __rdtsc();
        for (int t = 0; t < nt; ++t) { th.push_back(CreateThread(nullptr, 0, StormThread, &args[t], 0, nullptr)); }
        WaitForMultipleObjects((DWORD)th.size(), th.data(), TRUE, INFINITE);
        const double wall = Us(__rdtsc() - t0);
        for (HANDLE h : th) { CloseHandle(h); }
        Hist all; for (auto& a : args) { all.Merge(a.h); }
        printf("    %2d нит.: %6.0f рукопожатий/с, одно — ср %.0f мкс, p99 %.0f, макс %.0f\n",
               nt, (double)all.n / (wall / 1e6), all.Mean(), all.Q(.99), all.mx);
    }
    for (int s = 200; s < 200 + 16 * 20; ++s) { AsdaWire::ResetSlot(s, 0); CONN(s) = 0; }
}

// ── Т2: отправка одного кадра ────────────────────────────────────────────────────────────────────────────────────────
static void T2_Send(int slotSecure, int slotStock)
{
    printf("\n── Т2. Отправка кадра сервером (одна нить): голый сток vs мост (шифрование + проверка досылки под L + сток) ──\n");
    printf("  размер | сток, мкс | мост, мкс | добавка, мкс | +байт на проводе\n");
    CONN(slotStock) = 1;
    for (size_t len : { (size_t)20, (size_t)43, (size_t)60, (size_t)129, (size_t)400, (size_t)700, (size_t)1500, (size_t)4000, (size_t)8000 })
    {
        const std::vector<uint8_t> f = Frame(0x1771, len, 0x5A);
        const int N = len >= 4000 ? 50000 : 200000;
        for (int i = 0; i < 2000; ++i) { MockStockSend(&g_ci, slotStock, f.data(), (int)f.size()); AsdaWire::SendRoute(&g_ci, slotSecure, f.data(), (int)f.size()); }
        uint64_t t0 = __rdtsc();
        for (int i = 0; i < N; ++i) { MockStockSend(&g_ci, slotStock, f.data(), (int)f.size()); }
        const double stock = Us(__rdtsc() - t0) / N;
        t0 = __rdtsc();
        for (int i = 0; i < N; ++i) { AsdaWire::SendRoute(&g_ci, slotSecure, f.data(), (int)f.size()); }
        const double bridge = Us(__rdtsc() - t0) / N;
        const size_t chunks = (len + 4067) / 4068;
        printf("  %6zu | %9.3f | %9.3f | %12.3f | +%zu (%.0f %%)\n", len, stock, bridge, bridge - stock, chunks * 28, 100.0 * chunks * 28 / len);
    }
}

// ── Т3: приём ────────────────────────────────────────────────────────────────────────────────────────────────────────
static void T3_Recv(int slotBase)
{
    printf("\n── Т3. Приём кадра клиента сервером: голый разборщик vs мост (расшифровка + отдача разборщику) ──\n");
    printf("  размер | порция | разборщик, мкс/кадр | мост, мкс/кадр | добавка, мкс/кадр\n");
    AsdaWire::SetRecvSink(&MockSink);
    int slot = slotBase;
    for (size_t len : { (size_t)43, (size_t)65, (size_t)277, (size_t)1500 })
    {
        for (int batch : { 1, 10 })
        {
            ClientChannel c;
            if (!OpenSlot(slot, c)) { CHECK(false, "рукопожатие слота приёма"); return; }
            const std::vector<uint8_t> f = Frame(0x3EB, len, 0x33);
            const int N = len >= 1500 ? 20000 : 100000;
            const int portions = N / batch;
            std::vector<std::vector<uint8_t>> ct((size_t)portions);
            for (int p = 0; p < portions; ++p)
            {
                for (int k = 0; k < batch; ++k) { std::vector<uint8_t> one; c.OnSend(f.data(), f.size(), one); ct[p].insert(ct[p].end(), one.begin(), one.end()); }
            }
            std::vector<uint8_t> plainBatch; for (int k = 0; k < batch; ++k) { plainBatch.insert(plainBatch.end(), f.begin(), f.end()); }
            uint64_t t0 = __rdtsc();
            for (int p = 0; p < portions; ++p) { MockSink(&g_ci, plainBatch.data(), (int)plainBatch.size(), slot); }
            const double stock = Us(__rdtsc() - t0) / N;
            const LONG before = g_sinkBytes;
            t0 = __rdtsc();
            for (int p = 0; p < portions; ++p) { const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, slot, ct[p].data(), (int)ct[p].size(), &o); }
            const double bridge = Us(__rdtsc() - t0) / N;
            const bool whole = (size_t)(g_sinkBytes - before) == (size_t)N * len && !AsdaWire::SlotFailed(slot);
            if (!whole) { CHECK(false, "приём: поток разборщику не цел"); }
            printf("  %6zu | %6d | %19.3f | %13.3f | %17.3f\n", len, batch, stock, bridge, bridge - stock);
            AsdaWire::ResetSlot(slot, 0); CONN(slot) = 0;
            ++slot;
        }
    }
    AsdaWire::SetRecvSink(nullptr);
}

// ── Т4: конкуренция ──────────────────────────────────────────────────────────────────────────────────────────────────
static volatile LONG g_go = 0, g_stop = 0;
struct SendArg { bool bridge; int slotLo, slotHi; double ratePerThread; uint32_t rnd; Hist h; uint64_t calls = 0; std::vector<uint8_t>* frame; };
static DWORD WINAPI SendThread(LPVOID p)
{
    SendArg& a = *(SendArg*)p;
    while (!g_go) { YieldProcessor(); }
    const uint64_t step = a.ratePerThread > 0 ? (uint64_t)(g_tscPerUs * 1e6 / a.ratePerThread) : 0;
    uint64_t next = __rdtsc();
    const std::vector<uint8_t>& f = *a.frame;
    while (!g_stop)
    {
        if (step) { while (__rdtsc() < next && !g_stop) { YieldProcessor(); } next += step; }
        a.rnd = a.rnd * 1103515245u + 12345u;
        const int slot = a.slotLo + (int)((a.rnd >> 8) % (uint32_t)(a.slotHi - a.slotLo));
        const uint64_t t0 = __rdtsc();
        if (a.bridge) { AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); }
        else          { MockStockSend(&g_ci, slot, f.data(), (int)f.size()); }
        a.h.Add(Us(__rdtsc() - t0));
        ++a.calls;
    }
    return 0;
}
static Hist g_probe;                                     // ожидание замка L пробником
static DWORD WINAPI ProbeThread(LPVOID)
{
    while (!g_go) { YieldProcessor(); }
    const uint64_t gap = (uint64_t)(g_tscPerUs * 100);    // каждые 100 мкс
    while (!g_stop)
    {
        const uint64_t until = __rdtsc() + gap;
        while (__rdtsc() < until) { YieldProcessor(); }
        const uint64_t t0 = __rdtsc();
        EnterCriticalSection(&g_ci.L);
        const uint64_t t1 = __rdtsc();
        LeaveCriticalSection(&g_ci.L);
        g_probe.Add(Us(t1 - t0));
    }
    return 0;
}
static void RunLoad(const char* name, bool bridge, int threads, int slotLo, int slotHi, double totalRate, size_t frameLen)
{
    std::vector<uint8_t> f = Frame(0x1771, frameLen, 0x5A);
    std::vector<SendArg> args((size_t)threads);
    for (int t = 0; t < threads; ++t)
    {
        args[t].bridge = bridge; args[t].slotLo = slotLo; args[t].slotHi = slotHi; args[t].rnd = 0x9E3779B9u * (t + 1);
        args[t].ratePerThread = totalRate > 0 ? totalRate / threads : 0; args[t].frame = &f;
    }
    g_probe = Hist(); g_go = 0; g_stop = 0;
    std::vector<HANDLE> th;
    for (int t = 0; t < threads; ++t) { th.push_back(CreateThread(nullptr, 0, SendThread, &args[t], 0, nullptr)); }
    HANDLE pr = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
    Sleep(50);
    const uint64_t t0 = __rdtsc();
    InterlockedExchange(&g_go, 1);
    Sleep(1500);
    InterlockedExchange(&g_stop, 1);
    const double wall = Us(__rdtsc() - t0);
    WaitForMultipleObjects((DWORD)th.size(), th.data(), TRUE, INFINITE); WaitForSingleObject(pr, INFINITE);
    for (HANDLE h : th) { CloseHandle(h); } CloseHandle(pr);
    Hist all; uint64_t calls = 0; for (auto& a : args) { all.Merge(a.h); calls += a.calls; }
    printf("  %-34s %-4s | %9.0f кадр/с | вызов p50 %6.2f p99 %6.2f p99.9 %7.2f макс %8.1f мкс | ожидание L: p99 %6.2f p99.9 %7.2f макс %8.1f мкс\n",
           name, bridge ? "мост" : "сток", (double)calls / (wall / 1e6), all.Q(.5), all.Q(.99), all.Q(.999), all.mx,
           g_probe.Q(.99), g_probe.Q(.999), g_probe.mx);
}
static void T4_Contention(int slotLo, int slotHi)
{
    printf("\n── Т4. Конкуренция (кадр 60 б; пробник раз в 100 мкс берёт замок L, как IoWorkerThread/accept) ──\n");
    for (bool br : { false, true }) { RunLoad("4 нити, 500 слотов, без пауз", br, 4, slotLo, slotHi, 0, 60); }
    for (bool br : { false, true }) { RunLoad("22 нити, 500 слотов, без пауз", br, 22, slotLo, slotHi, 0, 60); }
    for (bool br : { false, true }) { RunLoad("22 нити, ОДИН слот, без пауз", br, 22, slotLo, slotLo + 1, 0, 60); }
    for (bool br : { false, true }) { RunLoad("22 нити, 500 слотов, 200 000 кадр/с", br, 22, slotLo, slotHi, 200000, 60); }
    for (bool br : { false, true }) { RunLoad("22 нити, 500 слотов, 50 000 кадр/с", br, 22, slotLo, slotHi, 50000, 60); }
    printf("\n── Т4б. Без переподписки ЦП (8 нитей) и с ценой WriteFile под L (5 мкс на вызов стока — пессимистично, см. Т0) ──\n");
    for (bool br : { false, true }) { RunLoad("8 нитей, 100 000 кадр/с, без WriteFile", br, 8, slotLo, slotHi, 100000, 60); }
    InterlockedExchange(&g_writeSpinNs, 5000);
    for (bool br : { false, true }) { RunLoad("8 нитей, без пауз, WriteFile 5 мкс", br, 8, slotLo, slotHi, 0, 60); }
    for (bool br : { false, true }) { RunLoad("8 нитей, 100 000 кадр/с, WriteFile 5 мкс", br, 8, slotLo, slotHi, 100000, 60); }
    for (bool br : { false, true }) { RunLoad("8 нитей, 100 000 кадр/с, WriteFile, 700 б", br, 8, slotLo, slotHi, 100000, 700); }
    InterlockedExchange(&g_writeSpinNs, 0);
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    // ★ sec2: «noaccel» — прежний путь рукопожатия (импорт ключа подписи на каждое рукопожатие, пара ECDH на месте) для сравнения
    //   в той же сборке; по умолчанию — кэш ключа + пул ECDH (как в DLL).
    const bool noAccel = argc > 1 && strcmp(argv[1], "noaccel") == 0;
    if (noAccel) { AsdaWire::SetHandshakeAccel(false, 0); }
    printf("== stand_perf: производительность моста шифрования (x86, мок стока по дизасму)%s ==\n",
           noAccel ? " — БЕЗ ускорения рукопожатия (noaccel)" : " — кэш ключа подписи + пул ECDH");
    CalibrateTsc();
    SYSTEM_INFO si; GetSystemInfo(&si);
    printf("  TSC %.0f МГц, логических ЦП %lu\n", g_tscPerUs, si.dwNumberOfProcessors);
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }
    PrivateKey priv{}; GenerateLongTermKey(priv);
    wchar_t kp[MAX_PATH]; { wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t); _snwprintf(kp, MAX_PATH, L"%sstand_perf_%lu.key", t, GetCurrentProcessId()); }
    SavePrivateKeyFile(kp, priv); memcpy(g_pub.xy, priv.xy, kPubLen);

    InitializeCriticalSection(&g_ci.L);
    g_ci.sess = (uint8_t*)calloc((size_t)0x226 * kStride, 1);
    AsdaWire::StockSendLayout lay{};
    lay.lockOff = (uint32_t)offsetof(MockCiocp, L); lay.sessPtrOff = (uint32_t)offsetof(MockCiocp, sess); lay.sessStride = kStride;
    lay.connOff = kConn; lay.inFlightOff = kFly; lay.pendingOff = kPend; lay.pendingLimit = kLimit; lay.directMax = kDirect;
    if (!AsdaWire::Init(SubServer::Game, kp, /*allowLegacy=*/false, &MockStockSend)) { printf("ключ не загружен\n"); return 2; }
    AsdaWire::SetStockSendLayout(&lay);

    // Проверка целостности пути (прежде замеров): кадр через мост расшифровывается клиентом байт-в-байт.
    {
        ClientChannel c; const bool ok = OpenSlot(1, c);
        CHECK(ok, "рукопожатие через мост и мок стока");
        const std::vector<uint8_t> f = Frame(0x1771, 700, 0x42);
        InterlockedExchange(&g_capture[1], 1);
        AsdaWire::SendRoute(&g_ci, 1, f.data(), (int)f.size());
        InterlockedExchange(&g_capture[1], 0);
        std::vector<uint8_t> d; const Err e = c.OnRecv(g_cap[1].data(), g_cap[1].size(), d);
        CHECK(e == Err::Ok && d == f, "кадр сервера 700 б: клиент расшифровал байт-в-байт");
        g_cap[1].clear();
    }

    T0_RealSend();
    T1_Handshake();
    {
        ClientChannel c; OpenSlot(2, c);
        T2_Send(2, 3);
    }
    T3_Recv(10);

    // 500 готовых Secure-слотов для конкуренции.
    {
        std::vector<std::unique_ptr<ClientChannel>> cl;
        int okN = 0;
        for (int s = 40; s < 540; ++s) { cl.emplace_back(new ClientChannel()); if (OpenSlot(s, *cl.back())) { ++okN; } }
        char m[96]; sprintf(m, "500 слотов прошли рукопожатие: %d", okN); CHECK(okN == 500, m);
        T4_Contention(40, 540);
    }

    AsdaWire::Counters cn{}; AsdaWire::GetCounters(&cn);
    char m[200];
    sprintf(m, "счётчики моста: отказов %ld, очередь моста %ld, потерь %ld, разрывов %ld, Send > 0x1000: %ld", cn.txRefused, cn.txQueued, cn.txLost, cn.kills, cn.overSend);
    CHECK(cn.txRefused == 0 && cn.txLost == 0 && cn.kills == 0 && cn.overSend == 0, m);
    DeleteFileW(kp);
    printf(g_fail == 0 ? "\n== ЗАМЕР ЗАВЕРШЁН, провалов 0 ==\n" : "\n== ПРОВАЛОВ: %d ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
