// Copyright (c) 2026 @sitxovski (Discord)
// stand_backlog.cpp — ★ fix2d (ревизия FIX2, хвост «переполнение досылки стока», правки П-1/П-2).
//
// Мок стока — по дизасму Ciocp::Send GS 0x561F20 / LM 0x413AB0 и Ciocp::SendTemp GS 0x562640 (одна библиотека Ciocp):
//   • замок L (CRITICAL_SECTION Ciocp+0x60D1830) — Send и SendTemp берут его первым делом;
//   • сессия слота = [Ciocp+0x60D1898] + slot·0xA0BE: +4 флаг соединения, +8 байт «запись в полёте», +0xB2 досылка 0xA000 б,
//     +0xA0B2 длина досылки;
//   • Send: флаг 0 → 0; запись в полёте → досылка + n ≥ 0x9F9C ? memset досылки, длина 0, флаг полёта 0, возврат 0 (СТИРАНИЕ)
//     : дописать, 1; записи нет → пул перекрытых (пуст → возврат 1 без записи), досылка > 0 → дописать и отправить всю досылку
//     через буфер 0x1000 (больше 0x1000 — мусор), иначе кадр через буфер 0x1000; ошибка WriteFile → DisConnect_NoLock, 0;
//   • SendTemp (IoWorker, завершение записи): флаг полёта 0; досылка > 0 → WriteFile прямо из досылки, затем memset, длина 0.
// «Сокет»: одна перекрытая запись на слот в полёте; ядро принимает запись целиком, если в буфере ядра (окно клиента + буфер
//   отправки, kKernelCap) есть место; завершение → нить IoWorker → SendTemp. Клиент читает только когда «не грузит карту».
// Собирается ДВАЖДЫ (build.bat): с мостом fix2d (out\stand_backlog.exe — всё сходится) и с мостом fix2c из stand\old_fix2c
//   (/DSTAND_OLD_BRIDGE, out\stand_backlog_old.exe — Replay у клиента воспроизводится, код ≠ 0).
// ★ fix2e (ревизия fix2d, Ф-1): Т9 — 150 слотов одновременно не читают при общем пределе очередей 2 МБ (TxQueueTotalMB): сумма
//   принятых очередей не больше предела, разрывы только с причиной 4, выжившие получают поток целым, после — общий счётчик 0;
//   Т10 — подставной operator new (отказ на нити по флагу): отказ выделения в очереди до рукопожатия, буфере шифрования, очереди
//   моста и на приёме — исключение наружу не выходит, процесс жив, разрыв с причиной 5, счётчики 0.
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <windows.h>
#include <cstdio>
#include <vector>
#include <deque>
#include <cstring>
#include <atomic>

#include <new>
#include <cstdlib>

using namespace AsdaSecure;

#ifndef STAND_OLD_BRIDGE
// ── ★ fix2e: подставной аллокатор — пока у нити взведён t_failNew, любой operator new этой нити бросает std::bad_alloc ────────
//   (мост и AsdaSecure собраны в этот же exe — /MT, замена глобальная). Мок стока выделяет память ПОД замком L — на время мока
//   флаг снимается (NoFailScope), иначе исключение ушло бы из-под L (у настоящего стока C++-выделений нет).
static thread_local int t_failNew = 0;
static volatile LONG g_newFailed = 0;
void* operator new(size_t n)
{
    if (t_failNew) { InterlockedIncrement(&g_newFailed); throw std::bad_alloc(); }
    void* p = malloc(n ? n : 1);
    if (!p) { throw std::bad_alloc(); }
    return p;
}
void operator delete(void* p) noexcept { free(p); }
void operator delete(void* p, size_t) noexcept { free(p); }
struct NoFailScope { int saved; NoFailScope() : saved(t_failNew) { t_failNew = 0; } ~NoFailScope() { t_failNew = saved; } };
#endif

static int g_fail = 0;
static void CHECK(bool ok, const char* what) { printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what); if (!ok) { ++g_fail; } }

// ── мок стокового Ciocp ──────────────────────────────────────────────────────────────────────────────────────────
constexpr uint32_t kStride = 0xA0BE, kConn = 4, kFly = 8, kPBuf = 0xB2, kPend = 0xA0B2;
constexpr int      kLimit = 0x9F9C, kDirect = 0x1000;
constexpr size_t   kKernelCap = 80 * 1024;      // окно приёма клиента ~64 КБ + буфер отправки сервера ~16 КБ

struct MockCiocp
{
    char             pad[40];
    CRITICAL_SECTION L;
    uint8_t*         sess;
};
static MockCiocp g_ci;
static uint8_t* SS(int slot) { return g_ci.sess + (size_t)slot * kStride; }
static volatile LONG& CONN(int slot) { return *(volatile LONG*)(SS(slot) + kConn); }
static volatile uint8_t& FLY(int slot) { return *(volatile uint8_t*)(SS(slot) + kFly); }
static volatile LONG& PEND(int slot) { return *(volatile LONG*)(SS(slot) + kPend); }
static uint8_t* PBUF(int slot) { return SS(slot) + kPBuf; }

struct Sock
{
    std::vector<uint8_t> kernel;        // принято ядром, клиент ещё не прочёл
    std::deque<std::vector<uint8_t>> ops;   // перекрытые записи в полёте (ядро не приняло — нет места); после СТИРАНИЯ сток
                                            //   ставит [sess+8]=0 при живой записи и выдаёт вторую — у Legacy так бывает
    bool                 opPending = false; // ops непуст
    volatile bool        reading = true;
    ClientChannel        client;
    std::vector<uint8_t> got;           // расшифрованный клиентом поток
    Err                  err = Err::Ok;
    bool                 legacy = false;
};
static Sock* g_sock = nullptr;
static CRITICAL_SECTION g_kmx;          // «ядро» (после L: L → ядро)
static std::deque<int> g_compl;         // завершения записей → IoWorker
static HANDLE g_complEv;
static volatile LONG g_wipes = 0, g_poolLost = 0, g_garbage = 0, g_doubleOp = 0, g_killCalls = 0, g_killEff = 0, g_noLockDisc = 0;
static volatile LONG g_rep61 = 0, g_repOther = 0, g_lastReason = 0;
static volatile LONG g_repByReason[8] = {};    // ★ fix2e: отчётов вида 61 по причинам 1…5
static bool g_poolEmpty[AsdaWire::kMaxSlots] = {};
static bool g_failWrite[AsdaWire::kMaxSlots] = {};
static volatile bool g_stop = false;

static void PostCompletion(int slot) { EnterCriticalSection(&g_kmx); g_compl.push_back(slot); LeaveCriticalSection(&g_kmx); SetEvent(g_complEv); }

// Ядро принимает запись целиком при наличии места (под g_kmx).
static bool KernelTryTakeLocked(int slot)
{
    Sock& k = g_sock[slot];
    if (k.ops.empty() || k.kernel.size() + k.ops.front().size() > kKernelCap) { return false; }
    k.kernel.insert(k.kernel.end(), k.ops.front().begin(), k.ops.front().end());
    k.ops.pop_front(); k.opPending = !k.ops.empty();
    return true;
}

// WriteFile (под L): данные копируются (AFD буферизует — проверено на Windows 11: memset после ERROR_IO_PENDING поток не портит).
static int MockWrite(int slot, const uint8_t* p, int n)
{
    if (g_failWrite[slot])
    {
        g_failWrite[slot] = false;
        FLY(slot) = 0;                                  // 0x5623D5
        CONN(slot) = 0; AsdaWire::ResetSlot(slot, 0);   // DisConnect_NoLock 0x561D70 → SetConnectFlag(X,0)
        InterlockedIncrement(&g_noLockDisc);
        return 0;
    }
    int done = 0;
    EnterCriticalSection(&g_kmx);
    Sock& k = g_sock[slot];
    if (k.opPending && !k.legacy) { InterlockedIncrement(&g_doubleOp); }   // Secure: мост не даёт стоку потерять запись в полёте
    k.ops.emplace_back(p, p + n); k.opPending = true;
    while (KernelTryTakeLocked(slot)) { ++done; }
    LeaveCriticalSection(&g_kmx);
    for (; done > 0; --done) { PostCompletion(slot); }
    return 1;
}

static void Wipe(int slot) { memset(PBUF(slot), 0, 0xA000); PEND(slot) = 0; FLY(slot) = 0; InterlockedIncrement(&g_wipes); }

static int MockStockSend(void* self, int slot, const void* src, int n)
{
#ifndef STAND_OLD_BRIDGE
    NoFailScope nf;                                     // ★ fix2e: у настоящего стока C++-выделений нет
#endif
    MockCiocp* c = (MockCiocp*)self;
    if (!c) { return 0; }
    EnterCriticalSection(&c->L);
    int rc = 0;
    if (n < 0 || slot < 0 || slot >= 0x226 || !CONN(slot)) { rc = 0; }
    else if (FLY(slot) == 1)
    {
        if (PEND(slot) + n >= kLimit) { Wipe(slot); rc = 0; }
        else { memcpy(PBUF(slot) + PEND(slot), src, n); PEND(slot) += n; rc = 1; }
    }
    else if (g_poolEmpty[slot]) { InterlockedIncrement(&g_poolLost); rc = 1; }          // 0x5625DF: лог, возврат 1
    else if (PEND(slot) > 0)
    {
        FLY(slot) = 1;
        if (PEND(slot) + n >= kLimit) { Wipe(slot); rc = 0; }
        else
        {
            memcpy(PBUF(slot) + PEND(slot), src, n); PEND(slot) += n;
            const int total = PEND(slot);
            std::vector<uint8_t> ov(total, 0);
            if (total <= kDirect) { memcpy(ov.data(), PBUF(slot), total); } else { InterlockedIncrement(&g_garbage); }
            rc = MockWrite(slot, ov.data(), total);
            if (rc) { memset(PBUF(slot), 0, 0xA000); PEND(slot) = 0; }
        }
    }
    else
    {
        FLY(slot) = 1;
        std::vector<uint8_t> ov(n, 0);
        if (n <= kDirect) { memcpy(ov.data(), src, n); } else { InterlockedIncrement(&g_garbage); }
        rc = MockWrite(slot, ov.data(), n);
    }
    LeaveCriticalSection(&c->L);
    return rc;
}

static void MockSendTemp(int slot)
{
    EnterCriticalSection(&g_ci.L);
    FLY(slot) = 0;
    if (CONN(slot) && PEND(slot) > 0 && !g_poolEmpty[slot])
    {
        FLY(slot) = 1;
        if (MockWrite(slot, PBUF(slot), PEND(slot))) { memset(PBUF(slot), 0, 0xA000); PEND(slot) = 0; }
    }
    LeaveCriticalSection(&g_ci.L);
}

static DWORD WINAPI IoWorker(LPVOID)
{
    while (!g_stop)
    {
        WaitForSingleObject(g_complEv, 20);
        for (;;)
        {
            EnterCriticalSection(&g_kmx);
            if (g_compl.empty()) { LeaveCriticalSection(&g_kmx); break; }
            const int slot = g_compl.front(); g_compl.pop_front();
            LeaveCriticalSection(&g_kmx);
            MockSendTemp(slot);
        }
    }
    return 0;
}

// Клиент: читает «сокет», когда не грузит карту; освобождённое место принимает запись в полёте → завершение.
static DWORD WINAPI Reader(LPVOID)
{
    std::vector<uint8_t> buf, d;
    while (!g_stop)
    {
        bool any = false;
        for (int slot = 0; slot < AsdaWire::kMaxSlots; ++slot)
        {
            Sock& k = g_sock[slot];
            if (!k.reading) { continue; }
            int posted = 0;
            EnterCriticalSection(&g_kmx);
            buf.swap(k.kernel); k.kernel.clear();
            while (KernelTryTakeLocked(slot)) { ++posted; }
            LeaveCriticalSection(&g_kmx);
            for (; posted > 0; --posted) { PostCompletion(slot); }
            if (buf.empty()) { continue; }
            any = true;
            if (k.err == Err::Ok)
            {
                if (k.legacy) { k.got.insert(k.got.end(), buf.begin(), buf.end()); }
                else
                {
                    d.clear();
                    const Err e = k.client.OnRecv(buf.data(), buf.size(), d);
                    if (e != Err::Ok) { k.err = e; }
                    k.got.insert(k.got.end(), d.begin(), d.end());
                }
            }
            buf.clear();
        }
        if (!any) { Sleep(1); }
    }
    return 0;
}

// ── хуки моста ───────────────────────────────────────────────────────────────────────────────────────────────────
static void MockKill(void* self, int slot)     // GetConnectFlag + DisConnect (под L, как сток)
{
    InterlockedIncrement(&g_killCalls);
    MockCiocp* c = (MockCiocp*)self;
    if (!c) { return; }
    EnterCriticalSection(&c->L);
    if (CONN(slot)) { CONN(slot) = 0; FLY(slot) = 0; PEND(slot) = 0; AsdaWire::ResetSlot(slot, 0); InterlockedIncrement(&g_killEff); }
    LeaveCriticalSection(&c->L);
}
static void MockReport(void*, int slot, const AsdaWire::FailInfo& fi)
{
#ifndef STAND_OLD_BRIDGE
    if (fi.kind == AsdaWire::kKindSendFail)
    {
        InterlockedIncrement(&g_rep61); InterlockedExchange(&g_lastReason, fi.reason);
        if (fi.reason > 0 && fi.reason < 8) { InterlockedIncrement(&g_repByReason[fi.reason]); }
        if (fi.reason == AsdaWire::kSendFailTotalMax || fi.reason == 6) { return; }   // Т9: десятки однотипных строк не печатаем (считаются; 6 — sec2 вытеснение)
        printf("    (отчёт вид 61: слот %d причина %d, в очереди %d б, досылка %d б, во всех очередях %d б, режим %d, фаза %d)\n", slot, fi.reason, fi.queued, fi.pending, fi.total, fi.mode, fi.phase);
        return;
    }
#endif
    InterlockedIncrement(&g_repOther);
    printf("    (отчёт: слот %d %s вид %d режим %d фаза %d)\n", slot, ErrName(fi.err), fi.kind, fi.mode, fi.phase);
}

static PublicKey g_pub{};

static void Accept(int slot)
{
    EnterCriticalSection(&g_ci.L);
    memset(SS(slot), 0, kStride);
    CONN(slot) = 1;
    AsdaWire::ResetSlot(slot, 1);
    LeaveCriticalSection(&g_ci.L);
    EnterCriticalSection(&g_kmx);
    Sock& k = g_sock[slot];
    k.kernel.clear(); k.ops.clear(); k.opPending = false; k.got.clear(); k.err = Err::Ok; k.legacy = false;
    LeaveCriticalSection(&g_kmx);
}

static bool WaitFor(DWORD ms, bool (*pred)(int), int slot)
{
    const DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < ms) { if (pred(slot)) { return true; } Sleep(5); }
    return pred(slot);
}

static bool Open(int slot)
{
    Accept(slot);
    Sock& k = g_sock[slot];
    k.reading = false;
    k.client.Reset();
    std::vector<uint8_t> h; k.client.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr;
    AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
    k.reading = true;
    return WaitFor(3000, [](int s) { return g_sock[s].client.IsReady() || g_sock[s].err != Err::Ok; }, slot) && k.client.IsReady();
}

static std::vector<uint8_t> Pkt(uint16_t op, size_t total, uint8_t tid, uint32_t seq)
{
    std::vector<uint8_t> f(total, (uint8_t)(0x40 + (seq & 0x3F)));
    f[0] = 0xFB; f[1] = (uint8_t)(total & 0xFF); f[2] = (uint8_t)(total >> 8); f[7] = (uint8_t)op; f[8] = (uint8_t)(op >> 8);
    if (total >= 15) { f[9] = tid; memcpy(&f[10], &seq, 4); }
    f.back() = 0xFE;
    return f;
}
static uint32_t g_rng = 12345;
static uint32_t Rnd() { g_rng = g_rng * 1103515245u + 12345u; return g_rng >> 8; }
static size_t RndLen() { const uint32_t r = Rnd() % 100; return r < 60 ? 15 + Rnd() % 300 : (r < 90 ? 300 + Rnd() % 1500 : 1800 + Rnd() % 2296); }   // до 4095

#ifndef STAND_OLD_BRIDGE
static long TxNow() { AsdaWire::Counters c{}; AsdaWire::GetCounters(&c); return c.txNow; }
#endif

// ── Т1: загрузка карты — клиент не читает, сервер шлёт поток streamKB ─────────────────────────────────────────────────
static bool LoadMap(int slot, size_t streamKB, DWORD pauseMs, bool expectOk)
{
    if (!Open(slot)) { CHECK(false, "рукопожатие"); return false; }
    Sock& k = g_sock[slot];
    k.reading = false;                                   // OpenLevel: игровой поток клиента занят, сокет не читается
    std::vector<uint8_t> want;
    const LONG w0 = g_wipes, r0 = g_rep61, kc0 = g_killEff;
    uint32_t seq = 0;
    while (want.size() < streamKB * 1024)
    {
        const auto f = Pkt(0x1000 + (seq % 7), RndLen(), 1, seq); ++seq;
        AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size());
        want.insert(want.end(), f.begin(), f.end());
    }
    Sleep(pauseMs);
    k.reading = true;
    WaitFor(8000, [](int s) { return g_sock[s].err != Err::Ok || (g_sock[s].kernel.empty() && !g_sock[s].opPending && PEND(s) == 0
#ifndef STAND_OLD_BRIDGE
                                    && TxNow() == 0
#endif
                                    ); }, slot);
    Sleep(100);
    const bool ok = k.err == Err::Ok && k.got == want;
    char msg[300];
    sprintf(msg, "загрузка карты %zu КБ (пауза чтения %lu мс): клиент %s, поток %s (%zu из %zu б), стираний досылки стоком %ld, вид 61 %ld, разрывов %ld",
            streamKB, pauseMs, ErrName(k.err), k.got == want ? "цел, порядок верный" : "ИСПОРЧЕН", k.got.size(), want.size(),
            g_wipes - w0, g_rep61 - r0, g_killEff - kc0);
    if (expectOk) { CHECK(ok, msg); } else { printf("  [%s] %s\n", ok ? "цел" : "ИСПОРЧЕН — ожидаемо для fix2c", msg); }
    return ok;
}

#ifndef STAND_OLD_BRIDGE
// ── Т3: 21 нить карт + нить 6004 на один слот при «не читающем» клиенте ──────────────────────────────────────────────
struct MtArg { int slot; uint8_t tid; int count; };
static DWORD WINAPI MtSender(LPVOID p)
{
    MtArg* a = (MtArg*)p;
    uint32_t r = 777u * (a->tid + 1);
    for (int i = 0; i < a->count; ++i)
    {
        r = r * 1103515245u + 12345u;
        const size_t len = a->tid == 21 ? 26 : 15 + (r >> 8) % 1400;      // 21 — «нить 6004» (короткие кадры)
        const auto f = Pkt(a->tid == 21 ? 6004 : (uint16_t)(0x2000 + a->tid), len, a->tid, (uint32_t)i);
        AsdaWire::SendRoute(&g_ci, a->slot, f.data(), (int)f.size());
        if ((i & 15) == 0) { Sleep(0); }
    }
    return 0;
}
static void MultiThread(int slot)
{
    if (!Open(slot)) { CHECK(false, "рукопожатие Т3"); return; }
    Sock& k = g_sock[slot];
    k.reading = false;
    const int kThreads = 22, kCount = 40;
    MtArg args[kThreads]; HANDLE th[kThreads];
    const DWORD t0 = GetTickCount();
    for (int i = 0; i < kThreads; ++i) { args[i] = { slot, (uint8_t)i, kCount }; th[i] = CreateThread(nullptr, 0, &MtSender, &args[i], 0, nullptr); }
    Sleep(1500);                                          // клиент грузит карту
    k.reading = true;
    const DWORD wr = WaitForMultipleObjects(kThreads, th, TRUE, 20000);
    for (int i = 0; i < kThreads; ++i) { CloseHandle(th[i]); }
    WaitFor(8000, [](int s) { return g_sock[s].err != Err::Ok || (g_sock[s].kernel.empty() && !g_sock[s].opPending && PEND(s) == 0 && TxNow() == 0); }, slot);
    Sleep(100);
    // разбор потока на пакеты, порядок по нитям
    int next[kThreads] = {}; int bad = 0, frames = 0;
    for (size_t off = 0; off + 10 <= k.got.size(); )
    {
        const size_t len = k.got[off + 1] | (k.got[off + 2] << 8);
        if (k.got[off] != 0xFB || len < 15 || off + len > k.got.size() || k.got[off + len - 1] != 0xFE) { ++bad; break; }
        const uint8_t tid = k.got[off + 9]; uint32_t sq; memcpy(&sq, &k.got[off + 10], 4);
        if (tid >= kThreads || (int)sq != next[tid]) { ++bad; } else { ++next[tid]; }
        ++frames; off += len;
    }
    int complete = 0; for (int i = 0; i < kThreads; ++i) { if (next[i] == kCount) { ++complete; } }
    char msg[300];
    sprintf(msg, "22 нити (21 карт + 6004) × %d пакетов, пауза чтения 1500 мс: нити завершились %s (%lu мс), клиент %s, пакетов %d, нитей с полным порядком %d/%d, нарушений %d",
            kCount, wr == WAIT_TIMEOUT ? "НЕТ (блокировка)" : "да", GetTickCount() - t0, ErrName(k.err), frames, complete, kThreads, bad);
    CHECK(wr != WAIT_TIMEOUT && k.err == Err::Ok && bad == 0 && complete == kThreads, msg);
}

// ── Т8: стресс поколения слота: отправители (SendRoute → L) против DisConnect/accept (L → ResetSlot), IoWorker (SendTemp под L),
//   сторожа (очередь под cs_X → L). Клиент — своя нить «IOCP» (Reader слот пропускает). Ни одного кадра прошлой сессии новому
//   клиенту: ошибок клиента 0; блокировок нет.
static volatile bool g_stressStop = false;
struct StArg { int slot; uint8_t tid; LONG sent; };
static DWORD WINAPI StressSender(LPVOID p)
{
    StArg* a = (StArg*)p; uint32_t r = 99u + a->tid; uint32_t seq = 0;
    while (!g_stressStop)
    {
        r = r * 1103515245u + 12345u;
        const size_t len = 15 + (r >> 8) % 4081;
        const auto f = Pkt(0x4000, len, a->tid, seq++);
        AsdaWire::SendRoute(&g_ci, a->slot, f.data(), (int)f.size());
        InterlockedIncrement(&a->sent);
        if ((seq & 7) == 0) { Sleep(0); }
    }
    return 0;
}
static void StressCycles(int slot)
{
    g_sock[slot].reading = false;                         // клиента ведёт эта нить
    g_stressStop = false;
    StArg args[4]; HANDLE th[4];
    for (int i = 0; i < 4; ++i) { args[i] = { slot, (uint8_t)(10 + i), 0 }; th[i] = CreateThread(nullptr, 0, &StressSender, &args[i], 0, nullptr); }
    int cycles = 0, handshakes = 0, clientErr = 0; size_t bytes = 0;
    const DWORD t0 = GetTickCount();
    std::vector<uint8_t> buf, d;
    while (GetTickCount() - t0 < 3000)
    {
        Accept(slot);
        ClientChannel c; c.Reset();
        std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
        const uint8_t* o = nullptr;
        AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
        const bool lazy = (cycles % 2) == 1;              // каждый второй цикл — «загрузка карты»: 40 мс не читаем
        if (lazy) { Sleep(40); }
        const DWORD t1 = GetTickCount();
        while (GetTickCount() - t1 < 25)
        {
            int posted = 0;
            EnterCriticalSection(&g_kmx);
            buf.swap(g_sock[slot].kernel); g_sock[slot].kernel.clear();
            while (KernelTryTakeLocked(slot)) { ++posted; }
            LeaveCriticalSection(&g_kmx);
            for (; posted > 0; --posted) { PostCompletion(slot); }
            if (!buf.empty())
            {
                d.clear();
                const Err e = c.OnRecv(buf.data(), buf.size(), d);
                if (e != Err::Ok) { ++clientErr; printf("    (цикл %d: клиент %s)\n", cycles, ErrName(e)); break; }
                bytes += d.size(); buf.clear();
            }
            else { Sleep(1); }
        }
        if (c.IsReady()) { ++handshakes; }
        MockKill(&g_ci, slot);                            // DisConnect под L → SetConnectFlag(X,0) → ResetSlot
        ++cycles;
    }
    g_stressStop = true;
    const DWORD wr = WaitForMultipleObjects(4, th, TRUE, 10000);
    for (int i = 0; i < 4; ++i) { CloseHandle(th[i]); }
    Sleep(200);                                           // сторож применяет последний сброс
    AsdaWire::SlotFailed(slot);                           // вход в слот — применить сброс, если сторож не успел
    LONG sent = 0; for (int i = 0; i < 4; ++i) { sent += args[i].sent; }
    AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
    char msg[320];
    sprintf(msg, "циклов разрыв→accept→рукопожатие %d (рукопожатий %d), отправок %ld, клиенту расшифровано %zu б, ошибок клиента %d, нити %s, очередь сейчас %ld б",
            cycles, handshakes, sent, bytes, clientErr, wr == WAIT_TIMEOUT ? "ЗАВИСЛИ" : "завершились", c.txNow);
    CHECK(wr != WAIT_TIMEOUT && clientErr == 0 && handshakes > 10 && c.txNow == 0 && g_doubleOp == 0, msg);
    g_sock[slot].reading = true;
}

// ── ★ fix2e Т9: МНОГО СЛОТОВ ОДНОВРЕМЕННО НЕ ЧИТАЮТ при малом общем пределе очередей (ревизия fix2d, Ф-1) ─────────────────────
//   150 слотов (рукопожатие, затем клиенты «грузят карту»), 6 нитей шлют по кругу каждому своему слоту по 200 КБ. У каждого слота
//   ядро 80 КБ + досылка 0x9F9C — остальное в очереди моста (≈ 76 КБ на слот, всего ≈ 11 МБ при пределе 2 МБ).
static const int kT9First = 100, kT9Slots = 150, kT9Threads = 6;
static const LONG kT9Total = 2 * 1024 * 1024;
static std::vector<uint8_t> g_t9want[kT9Slots];
static volatile bool g_t9stop = false;
static volatile LONG g_t9maxNow = 0, g_t9maxTotal = 0;
static DWORD WINAPI T9Sender(LPVOID p)
{
    const int t = (int)(intptr_t)p;
    uint32_t r = 4242u + (uint32_t)t;
    bool alive[kT9Slots]; size_t sent[kT9Slots] = {}; uint32_t seq[kT9Slots] = {};
    for (int i = 0; i < kT9Slots; ++i) { alive[i] = (i % kT9Threads) == t; }
    for (bool any = true; any; )
    {
        any = false;
        for (int i = 0; i < kT9Slots; ++i)
        {
            if (!alive[i]) { continue; }
            if (sent[i] >= 200 * 1024) { alive[i] = false; continue; }
            any = true;
            r = r * 1103515245u + 12345u;
            const size_t len = 15 + (r >> 8) % 4081;
            const auto f = Pkt(0x5000, len, (uint8_t)t, seq[i]++);
            if (AsdaWire::SendRoute(&g_ci, kT9First + i, f.data(), (int)f.size()))
            {
                g_t9want[i].insert(g_t9want[i].end(), f.begin(), f.end()); sent[i] += len;
            }
            else { alive[i] = false; }                     // слот в сбое П-2 / закрыт — дальше не шлём
        }
    }
    return 0;
}
static DWORD WINAPI T9Monitor(LPVOID)
{
    while (!g_t9stop)
    {
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        if (c.txNow > g_t9maxNow) { g_t9maxNow = c.txNow; }
        if (c.txTotal > g_t9maxTotal) { g_t9maxTotal = c.txTotal; }
        Sleep(1);
    }
    return 0;
}
static bool T9Drained(int)
{
    if (TxNow() != 0) { return false; }
    for (int i = 0; i < kT9Slots; ++i)
    {
        const int s = kT9First + i;
        if (CONN(s) && (!g_sock[s].kernel.empty() || g_sock[s].opPending || PEND(s) != 0)) { return false; }
    }
    return true;
}
static void ManySlotsTotalCap()
{
    AsdaWire::SetTxQueueTotalMax(kT9Total);
    int hsOk = 0;
    for (int i = 0; i < kT9Slots; ++i) { if (Open(kT9First + i)) { ++hsOk; } g_t9want[i].clear(); }
    for (int i = 0; i < kT9Slots; ++i) { g_sock[kT9First + i].reading = false; }
    AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
    LONG rr0[8]; for (int i = 0; i < 8; ++i) { rr0[i] = g_repByReason[i]; }
    const LONG k0 = g_killEff, w0 = g_wipes;
    g_t9stop = false; g_t9maxNow = 0; g_t9maxTotal = 0;
    HANDLE mon = CreateThread(nullptr, 0, &T9Monitor, nullptr, 0, nullptr);
    HANDLE th[kT9Threads];
    const DWORD t0 = GetTickCount();
    for (int t = 0; t < kT9Threads; ++t) { th[t] = CreateThread(nullptr, 0, &T9Sender, (LPVOID)(intptr_t)t, 0, nullptr); }
    const DWORD wr = WaitForMultipleObjects(kT9Threads, th, TRUE, 60000);
    for (int t = 0; t < kT9Threads; ++t) { CloseHandle(th[t]); }
    Sleep(400);                                            // сторож: разрывы П-2
    AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
    LONG rr[8]; for (int i = 0; i < 8; ++i) { rr[i] = g_repByReason[i] - rr0[i]; }
    int closed = 0, survivors = 0;
    for (int i = 0; i < kT9Slots; ++i) { if (CONN(kT9First + i)) { ++survivors; } else { ++closed; } }
    char msg[700];
#ifdef ASDAWIRE_HAS_SEC2
    // ★ sec2 (Е-2): разрывы — причины 4 (тяжёлый слот рвётся сам / сверх жёсткого потолка) и 6 (сторож вытеснил наибольшую очередь);
    //   принятый общий объём не больше жёсткого потолка предел + предел/8 (лёгкому кадр принимается сверх мягкого предела).
    const LONG cap9 = kT9Total + kT9Total / 8, r6 = rr[6], ev = c1.txEvicted - c0.txEvicted;
#else
    const LONG cap9 = kT9Total, r6 = 0, ev = 0;
#endif
    sprintf(msg, "150 слотов не читают, общий предел %ld б: рукопожатий %d, нити %s (%lu мс); вид 61 по причинам 1/2/3/4/5/6 = %ld/%ld/%ld/%ld/%ld/%ld, "
                 "общих превышений %ld, вытеснено наибольших %ld, разрывов %ld, закрыто слотов %d, живы %d; наибольший общий объём: принятый (txTotalPeak) %ld б "
                 "(потолок %ld), Σ очередей слотов (замер) %ld б, счётчик с резервами (замер) %ld б; стираний досылки %ld",
            kT9Total, hsOk, wr == WAIT_TIMEOUT ? "ЗАВИСЛИ" : "завершились", GetTickCount() - t0, rr[1], rr[2], rr[3], rr[4], rr[5], r6,
            c1.txTotalOver - c0.txTotalOver, ev, g_killEff - k0, closed, survivors, c1.txTotalPeak, cap9, (long)g_t9maxNow, (long)g_t9maxTotal, g_wipes - w0);
    CHECK(wr != WAIT_TIMEOUT && hsOk == kT9Slots && rr[4] + r6 > 0 && rr[1] == 0 && rr[2] == 0 && rr[3] == 0 && rr[5] == 0
          && c1.txTotalOver - c0.txTotalOver == rr[4] && ev == r6 && g_killEff - k0 == rr[4] + r6 && closed == rr[4] + r6 && survivors > 0
          && c1.txTotalPeak <= cap9 && g_t9maxNow <= cap9 && g_wipes == w0, msg);
    // выжившие дочитывают: поток каждого цел и по порядку
    for (int i = 0; i < kT9Slots; ++i) { g_sock[kT9First + i].reading = true; }
    WaitFor(20000, &T9Drained, 0);
    Sleep(200);
    int intact = 0, broken = 0;
    for (int i = 0; i < kT9Slots; ++i)
    {
        const int s = kT9First + i;
        if (!CONN(s)) { continue; }
        if (g_sock[s].err == Err::Ok && g_sock[s].got == g_t9want[i]) { ++intact; } else { ++broken; }
    }
    sprintf(msg, "выжившие %d слотов дочитали: поток цел и по порядку у %d, испорчен у %d; очередь сейчас %ld б", survivors, intact, broken, TxNow());
    CHECK(broken == 0 && intact == survivors && TxNow() == 0, msg);
    // все слоты закрыть (сток) — сброс по поколению; общий счётчик должен вернуться в 0
    for (int i = 0; i < kT9Slots; ++i) { MockKill(&g_ci, kT9First + i); }
    Sleep(200);
    for (int i = 0; i < kT9Slots; ++i) { AsdaWire::SlotFailed(kT9First + i); }     // применить сброс, если сторож не дошёл
    g_t9stop = true; WaitForSingleObject(mon, 2000); CloseHandle(mon);
    AsdaWire::Counters c2{}; AsdaWire::GetCounters(&c2);
#ifdef ASDAWIRE_HAS_SEC2B
    sprintf(msg, "после закрытия всех 150 слотов: общий счётчик txTotal %ld, Σ очередей слотов txNow %ld б, учтённая память слотов txCostNow %ld", c2.txTotal, c2.txNow, c2.txCostNow);
    CHECK(c2.txTotal == 0 && c2.txNow == 0 && c2.txCostNow == 0, msg);
#else
    sprintf(msg, "после закрытия всех 150 слотов: общий счётчик txTotal %ld б, Σ очередей слотов txNow %ld б", c2.txTotal, c2.txNow);
    CHECK(c2.txTotal == 0 && c2.txNow == 0, msg);
#endif
    for (int i = 0; i < kT9Slots; ++i) { std::vector<uint8_t>().swap(g_t9want[i]); g_sock[kT9First + i].got.clear(); }
    AsdaWire::SetTxQueueTotalMax(64 * 1024 * 1024);
}

// ── ★ fix2e Т10: ОТКАЗ ВЫДЕЛЕНИЯ ПАМЯТИ (подставной operator new) — процесс жив, разрыв с причиной 5 ──────────────────────────
static int g_escaped = 0;
static int SendArmed(int slot, const std::vector<uint8_t>& f)
{
    int rc = -7;
    t_failNew = 1;
    try { rc = AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); } catch (...) { ++g_escaped; }
    t_failNew = 0;
    return rc;
}
static void NoMemCase(const char* what, int slot, int rc, int wantRc, LONG r5before, LONG k0, LONG nm0)
{
    Sleep(250);                                            // сторож: разрыв
    AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
    char msg[500];
    sprintf(msg, "%s: возврат %d, исключений наружу %d, вид 61 причина 5 +%ld (последняя причина %ld), разрывов %ld, txNoMem +%ld, соединение %s, очередь %ld б, общий счётчик %ld б",
            what, rc, g_escaped, g_repByReason[5] - r5before, g_lastReason, g_killEff - k0, c.txNoMem - nm0, CONN(slot) ? "открыто" : "закрыто", c.txNow, c.txTotal);
    CHECK(rc == wantRc && g_escaped == 0 && g_repByReason[5] - r5before == 1 && g_lastReason == AsdaWire::kSendFailNoMem && g_killEff - k0 == 1
          && c.txNoMem - nm0 == 1 && !CONN(slot) && c.txNow == 0 && c.txTotal == 0, msg);
}
static bool T10Got(int s) { return g_sock[s].got.size() >= 30000 || g_sock[s].err != Err::Ok; }
static void AllocFailures()
{
    int slot = 300;
    {   // а) очередь до рукопожатия (preQ): accept, рукопожатия нет, сервер шлёт кадр
        Accept(slot); g_sock[slot].reading = true;
        const LONG r5 = g_repByReason[5], k0 = g_killEff; AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        const auto f = Pkt(0x6001, 100, 1, 0);
        const int rc = SendArmed(slot, f);
        NoMemCase("отказ выделения в очереди до рукопожатия", slot, rc, 0, r5, k0, c0.txNoMem);
        ++slot;
    }
    {   // б) буфер шифрования (s.sealed, первая отправка слота — ёмкость 0)
        if (!Open(slot)) { CHECK(false, "рукопожатие Т10б"); }
        const LONG r5 = g_repByReason[5], k0 = g_killEff; AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        const auto f = Pkt(0x6002, 1000, 1, 0);
        const int rc = SendArmed(slot, f);
        NoMemCase("отказ выделения в буфере шифрования", slot, rc, 0, r5, k0, c0.txNoMem);
        ++slot;
    }
    {   // в) очередь моста: досылка стока полна, в очереди уже кадр, следующий — отказ выделения при постановке
        if (!Open(slot)) { CHECK(false, "рукопожатие Т10в"); }
        Sleep(50);
        g_sock[slot].reading = false;
        EnterCriticalSection(&g_ci.L); FLY(slot) = 1; PEND(slot) = 0x9F00; LeaveCriticalSection(&g_ci.L);   // запись в полёте, досылка почти полна
        const auto f1 = Pkt(0x6003, 2000, 1, 0);
        const int rc1 = AsdaWire::SendRoute(&g_ci, slot, f1.data(), (int)f1.size());
        const long q1 = TxNow();
        AsdaWire::Counters cq{}; AsdaWire::GetCounters(&cq);
#ifdef ASDAWIRE_HAS_SEC2B
        // ★ sec2b (ревизия SEC2 Н-6): общий счётчик — учтённая память кадра (TxFrameCost: блок данных + блок элемента deque + указатель
        //   карты), а не 2028 б кадра; очередь слота (txNow) — по-прежнему байты кадра.
        const long cost1 = AsdaWire::TxFrameCost(2028);
        char m[260]; sprintf(m, "подготовка: кадр встал в очередь моста (возврат %d, очередь %ld б, общий счётчик %ld б = TxFrameCost(2028) %ld, учтённая память слотов %ld)",
                             rc1, q1, cq.txTotal, cost1, cq.txCostNow);
        CHECK(rc1 == 1 && q1 == 2028 && cost1 > 2028 && cq.txTotal == cost1 && cq.txCostNow == cost1, m);
#else
        char m[200]; sprintf(m, "подготовка: кадр встал в очередь моста (возврат %d, очередь %ld б, общий счётчик %ld б)", rc1, q1, cq.txTotal);
        CHECK(rc1 == 1 && q1 == 2028 && cq.txTotal == 2028, m);
#endif
        const LONG r5 = g_repByReason[5], k0 = g_killEff; AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        const auto f2 = Pkt(0x6003, 2000, 1, 1);
        const int rc = SendArmed(slot, f2);
        NoMemCase("отказ выделения при постановке в очередь моста", slot, rc, 0, r5, k0, c0.txNoMem);
        g_sock[slot].reading = true; ++slot;
    }
    {   // г) приём: ClientHello при отказе выделения (накопитель приветствия канала)
        Accept(slot);
        ClientChannel cl; cl.Reset();
        std::vector<uint8_t> h; cl.Start(SubServer::Game, g_pub, h);
        const LONG r5 = g_repByReason[5], k0 = g_killEff; AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        const uint8_t* o = nullptr;
        int rc = -7;
        t_failNew = 1;
        try { rc = AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o); } catch (...) { ++g_escaped; }
        t_failNew = 0;
        NoMemCase("отказ выделения на приёме (ClientHello)", slot, rc, -1, r5, k0, c0.txNoMem);
        ++slot;
    }
    {   // д) после отказов — тот же слот принимает нового клиента, поток идёт (мост и процесс в порядке)
        const int s2 = 300 + 2;
        const bool ok = Open(s2);
        std::vector<uint8_t> want;
        for (uint32_t i = 0; i < 20; ++i) { const auto f = Pkt(0x6004, 1500, 2, i); AsdaWire::SendRoute(&g_ci, s2, f.data(), (int)f.size()); want.insert(want.end(), f.begin(), f.end()); }
        WaitFor(3000, &T10Got, s2);
        Sleep(50);
        char m[300]; sprintf(m, "после отказов: новый клиент на слоте %d — рукопожатие %s, поток %s; отказов operator new всего %ld", s2, ok ? "да" : "НЕТ",
                             g_sock[s2].got == want ? "цел" : "ИСПОРЧЕН", (long)g_newFailed);
        CHECK(ok && g_sock[s2].err == Err::Ok && g_sock[s2].got == want && g_newFailed >= 4, m);
        MockKill(&g_ci, s2);
    }
}
#endif

int main()
{
#ifdef STAND_OLD_BRIDGE
    printf("== stand_backlog: переполнение досылки стока — мост fix2c (ДО правки П-1) ==\n");
#else
    printf("== stand_backlog: переполнение досылки стока — мост fix2d (П-1/П-2) ==\n");
#endif
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }
    InitializeCriticalSection(&g_ci.L); InitializeCriticalSection(&g_kmx);
    g_ci.sess = (uint8_t*)calloc(AsdaWire::kMaxSlots, kStride);
    g_sock = new Sock[AsdaWire::kMaxSlots];
    g_complEv = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    PrivateKey priv{}; GenerateLongTermKey(priv);
    wchar_t kp[MAX_PATH]; { wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t); _snwprintf(kp, MAX_PATH, L"%sstand_backlog_%lu.key", t, GetCurrentProcessId()); }
    SavePrivateKeyFile(kp, priv); memcpy(g_pub.xy, priv.xy, kPubLen);
    AsdaWire::Init(SubServer::Game, kp, true, &MockStockSend);
    AsdaWire::SetFailureHooks(&MockKill, &MockReport, nullptr, true);
#ifndef STAND_OLD_BRIDGE
    // раскладка мока: те же смещения сессии, что у стока; замок и указатель сессий — поля мока
    AsdaWire::StockSendLayout lay{ (uint32_t)offsetof(MockCiocp, L), (uint32_t)offsetof(MockCiocp, sess), kStride, kConn, kFly, kPend, kLimit, kDirect };
    AsdaWire::SetStockSendLayout(&lay);
    AsdaWire::SetTxQueueMax(1024 * 1024);
#endif
    HANDLE io = CreateThread(nullptr, 0, &IoWorker, nullptr, 0, nullptr);
    HANDLE rd = CreateThread(nullptr, 0, &Reader, nullptr, 0, nullptr);

    printf("-- Т1: загрузка карты (ядро принимает %zu КБ, досылка стока 0x9F9C) --\n", kKernelCap / 1024);
    int slot = 1;
#ifdef STAND_OLD_BRIDGE
    int lost = 0;
    for (size_t kb : { (size_t)120, (size_t)160, (size_t)200 }) { if (!LoadMap(slot++, kb, 1500, false)) { ++lost; } }
    printf(lost ? "\n== мост fix2c: потоков испорчено %d из 3 — переполнение досылки ВОСПРОИЗВЕДЕНО ==\n" : "\n== мост fix2c: не воспроизведено ==\n", lost);
    g_stop = true; WaitForSingleObject(io, 2000); WaitForSingleObject(rd, 2000); DeleteFileW(kp);
    return lost ? 1 : 0;
#else
    for (size_t kb : { (size_t)120, (size_t)160, (size_t)200 }) { LoadMap(slot++, kb, 1500, true); }
    {
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        char msg[200]; sprintf(msg, "очередь моста работала: в очередь %ld кадров, выдано %ld, пик %ld б, сейчас %ld б, стираний стоком %ld", c.txQueued, c.txFlushed, c.txPeak, c.txNow, g_wipes);
        CHECK(c.txQueued > 0 && c.txQueued == c.txFlushed && c.txNow == 0 && g_wipes == 0 && g_garbage == 0 && g_doubleOp == 0, msg);
    }

    printf("-- Т2: переполнение очереди моста (TxQueueKB=64, клиент не читает) --\n");
    {
        AsdaWire::SetTxQueueMax(64 * 1024);
        if (!Open(slot)) { CHECK(false, "рукопожатие Т2"); }
        g_sock[slot].reading = false;
        const LONG r0 = g_rep61, k0 = g_killEff, kc0 = g_killCalls;
        AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        int accepted = 0, refused = 0;
        for (uint32_t i = 0; i < 200; ++i) { const auto f = Pkt(0x3000, 2000, 2, i); if (AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size())) { ++accepted; } else { ++refused; } }
        Sleep(300);                                       // сторож: разрыв
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        char msg[300]; sprintf(msg, "400 КБ при очереди 64 КБ: принято %d, отвергнуто %d, вид 61 %ld (причина %ld), разрывов %ld (вызовов %ld), переполнений %ld, очередь сейчас %ld б, соединение %s",
                               accepted, refused, g_rep61 - r0, g_lastReason, g_killEff - k0, g_killCalls - kc0, c.txOverflow - c0.txOverflow, c.txNow, CONN(slot) ? "открыто" : "закрыто");
        CHECK(g_rep61 - r0 == 1 && g_lastReason == AsdaWire::kSendFailQueueMax && g_killEff - k0 == 1 && g_killCalls - kc0 == 1 && c.txOverflow - c0.txOverflow == 1 && c.txNow == 0 && !CONN(slot), msg);
        AsdaWire::SetTxQueueMax(1024 * 1024);
        g_sock[slot].reading = true; ++slot;
    }

    printf("-- Т3: многопоточная отправка --\n");
    MultiThread(slot++);

    printf("-- Т4: отказ стокового Send (ошибка WriteFile) --\n");
    {
        if (!Open(slot)) { CHECK(false, "рукопожатие Т4"); }
        const LONG r0 = g_rep61, k0 = g_killEff, kc0 = g_killCalls, nl0 = g_noLockDisc;
        AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        g_failWrite[slot] = true;
        const auto f = Pkt(0x3001, 500, 3, 0);
        const int rc = AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size());
        const auto f2 = Pkt(0x3001, 500, 3, 1);
        const int rc2 = AsdaWire::SendRoute(&g_ci, slot, f2.data(), (int)f2.size());
        Sleep(200);
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        char msg[300]; sprintf(msg, "отказ Send: возврат %d/%d, вид 61 %ld (причина %ld), DisConnect стока %ld, разрыв моста %ld (вызовов %ld), снято сбросом %ld",
                               rc, rc2, g_rep61 - r0, g_lastReason, g_noLockDisc - nl0, g_killEff - k0, g_killCalls - kc0, c.txKillStale - c0.txKillStale);
        CHECK(rc == 0 && rc2 == 0 && g_rep61 - r0 == 1 && g_lastReason == AsdaWire::kSendFailRefused && g_noLockDisc - nl0 == 1 && g_killEff - k0 == 0
              && g_killCalls - kc0 == 0 && c.txKillStale - c0.txKillStale == 1, msg);
        ++slot;
    }

    printf("-- Т5: сток потерял кадр (пул перекрытых пуст) и досылка без записи в полёте --\n");
    {
        if (!Open(slot)) { CHECK(false, "рукопожатие Т5"); }
        const LONG r0 = g_rep61, k0 = g_killEff;
        g_poolEmpty[slot] = true;
        const auto f = Pkt(0x3002, 700, 4, 0);
        const int rc = AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size());
        Sleep(200);
        g_poolEmpty[slot] = false;
        char msg[300]; sprintf(msg, "пул пуст: возврат %d, вид 61 %ld (причина %ld), разрывов %ld", rc, g_rep61 - r0, g_lastReason, g_killEff - k0);
        CHECK(rc == 0 && g_rep61 - r0 == 1 && g_lastReason == AsdaWire::kSendFailLost && g_killEff - k0 == 1, msg);
        ++slot;

        if (!Open(slot)) { CHECK(false, "рукопожатие Т5b"); }
        Sleep(50);                                            // завершение записи ServerHello обработано IoWorker
        const LONG r1 = g_rep61, k1 = g_killEff, gb = g_garbage;
        EnterCriticalSection(&g_ci.L); FLY(slot) = 0; PEND(slot) = 3000; LeaveCriticalSection(&g_ci.L);   // состояние после пустого пула в SendTemp
        const auto f2 = Pkt(0x3003, 2000, 4, 1);
        const int rc2 = AsdaWire::SendRoute(&g_ci, slot, f2.data(), (int)f2.size());
        Sleep(200);
        sprintf(msg, "досылка 3000 б без записи + кадр 2028 б (> 0x1000): возврат %d, вид 61 %ld (причина %ld), разрывов %ld, мусора стоку %ld",
                rc2, g_rep61 - r1, g_lastReason, g_killEff - k1, g_garbage - gb);
        CHECK(rc2 == 0 && g_rep61 - r1 == 1 && g_lastReason == AsdaWire::kSendFailLost && g_killEff - k1 == 1 && g_garbage == gb, msg);
        ++slot;
    }

    printf("-- Т6: Legacy-клиент — поведение стока не меняется --\n");
    {
        Accept(slot);
        Sock& k = g_sock[slot]; k.legacy = true; k.reading = true;
        const auto hello = Pkt(1001, 40, 9, 0);              // первый байт 0xFB — старый клиент
        const uint8_t* o = nullptr;
        AsdaWire::RecvRoute(&g_ci, slot, hello.data(), (int)hello.size(), &o);
        k.reading = false;
        AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        const LONG w0 = g_wipes, r0 = g_rep61;
        for (uint32_t i = 0; i < 100; ++i) { const auto f = Pkt(0x3004, 2000, 5, i); AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); }
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        char msg[300]; sprintf(msg, "Legacy 200 КБ без чтения: стираний досылки стоком %ld (как сток), в очередь моста %ld, вид 61 %ld, режим %d",
                               g_wipes - w0, c.txQueued - c0.txQueued, g_rep61 - r0, AsdaWire::SlotMode(slot));
        CHECK(g_wipes - w0 > 0 && c.txQueued == c0.txQueued && g_rep61 == r0 && AsdaWire::SlotMode(slot) == 2, msg);
        k.reading = true; ++slot;
    }

    printf("-- Т7: разрыв при непустой очереди → новый клиент на том же слоте --\n");
    {
        if (!Open(slot)) { CHECK(false, "рукопожатие Т7"); }
        g_sock[slot].reading = false;
        for (uint32_t i = 0; i < 100; ++i) { const auto f = Pkt(0x3005, 2000, 6, i); AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); }
        const long q = TxNow();
        AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        MockKill(&g_ci, slot);                                // сток закрыл соединение (DisConnect → SetConnectFlag(X,0))
        Sleep(200);                                           // сторож применяет сброс: очередь прошлой сессии выброшена
        AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
        const long q1 = c1.txNow;
        const bool ok1 = Open(slot);                          // новый accept + рукопожатие
        std::vector<uint8_t> want;
        for (uint32_t i = 0; i < 5; ++i) { const auto f = Pkt(0x3006, 1000, 7, i); AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); want.insert(want.end(), f.begin(), f.end()); }
        WaitFor(3000, [](int s) { return g_sock[s].got.size() >= 5000 || g_sock[s].err != Err::Ok; }, slot);
        Sleep(100);
        char msg[300]; sprintf(msg, "очередь до разрыва %ld б, после сброса %ld б (выброшено очередей %ld), новый клиент: рукопожатие %s, %s, поток %s",
                               q, q1, c1.txDropped - c0.txDropped, ok1 ? "да" : "НЕТ", ErrName(g_sock[slot].err), g_sock[slot].got == want ? "только свой" : "ЧУЖОЙ/ИСПОРЧЕН");
        CHECK(q > 0 && q1 == 0 && c1.txDropped - c0.txDropped == 1 && ok1 && g_sock[slot].err == Err::Ok && g_sock[slot].got == want, msg);
        ++slot;
    }

    printf("-- Т8: стресс — 4 нити отправки против разрывов/accept/рукопожатий того же слота, клиент то читает, то нет --\n");
    StressCycles(slot++);

    printf("-- Т9 (fix2e): 150 слотов одновременно не читают, общий предел очередей моста 2 МБ --\n");
    ManySlotsTotalCap();

    printf("-- Т10 (fix2e): отказ выделения памяти (подставной operator new) — процесс жив, разрыв с причиной 5 --\n");
    AllocFailures();

    {
        AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
        printf("\nсчётчики моста: txQueued %ld txFlushed %ld txPeak %ld txRefused %ld txOverflow %ld txLost %ld txKills %ld txKillStale %ld txDropped %ld txNow %ld overSend %ld\n",
               c.txQueued, c.txFlushed, c.txPeak, c.txRefused, c.txOverflow, c.txLost, c.txKills, c.txKillStale, c.txDropped, c.txNow, c.overSend);
        printf("fix2e: txTotal %ld txTotalPeak %ld txTotalOver %ld txNoMem %ld\n", c.txTotal, c.txTotalPeak, c.txTotalOver, c.txNoMem);
        CHECK(c.txTotal == 0 && c.txNow == 0, "в конце: общий счётчик очередей 0, очереди слотов 0");
        printf("мок стока: стираний %ld, мусора %ld, двойных записей %ld, потерь пула %ld\n", g_wipes, g_garbage, g_doubleOp, g_poolLost);
        CHECK(c.overSend == 0 && g_doubleOp == 0, "Send длиннее 0x1000 — 0, двойных записей в полёте — 0");
    }
    g_stop = true; WaitForSingleObject(io, 2000); WaitForSingleObject(rd, 2000);
    DeleteFileW(kp);
    printf(g_fail == 0 ? "\n== ВСЁ СОШЛОСЬ, провалов 0 ==\n" : "\n== ПРОВАЛОВ: %d ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
#endif
}
