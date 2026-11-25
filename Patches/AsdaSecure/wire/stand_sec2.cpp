// Copyright (c) 2026 @sitxovski (Discord)
// stand_sec2.cpp — ★ sec2 (15.10.2026, блок В плана альфы): стенд правок моста шифрования P61/L07.
//
//   Е1  (ревизия fix2e Е-1) очередь моста слота, упавшего НЕ по виду 61 (нарушение приёма при KillOnViolation=0), освобождается
//       сразу: общий счётчик 0 без сброса слота; соединение живо, разрыва нет.
//   Е2  (ревизия fix2e Е-2) справедливая доля общего предела: «тяжёлые» не читающие слоты занимают почти весь предел, честные
//       клиенты начинают грузить карту — честных НЕ рвёт (их кадры приняты до жёсткого потолка предел·9/8), сторож вытесняет
//       наибольшие очереди (причина 6); тяжёлый слот сверх предела рвётся сам (причина 4); Σ принятого ≤ потолка; после — 0.
//   Х   ускорение рукопожатия: кэш ключа подписи + пул ECDH против прежнего пути (то же сборка, тот же процесс), время на нити
//       сервера (ср/p50/p99); пары пула одноразовые (ни один эфемерный ключ ServerHello не повторился), пул пуст — генерация на
//       месте; 8 нитей одновременно — подписи верны, дескрипторов ≤ 16.
//   Д   допуск подключений до рукопожатия: предел с адреса за окно (вид 63, отказ ДО ServerAccept — ServerHello не уходит, пара
//       ECDH не тратится; отчёт один на адрес за окно; окно истекло — снова пускает), молчащие соединения — сторожем, предел
//       незавершённых рукопожатий (64, ограничитель отчётов), срок рукопожатия (65: молчит при AllowLegacy=0 / начал и бросил;
//       при AllowLegacy=1 молчащий не трогается), старый клиент (0xFB) завершает рукопожатие первым байтом, отложенный разрыв
//       fix2b не задерживает отказ, стресс accept/разрыв/рукопожатие — счётчик незавершённых возвращается в 0, блокировок нет.
//   ★ sec2b (ревизия SEC2): С-1 (AllowLegacy=1: молчащие по сроку сняты со счёта незавершённых, не разорваны; честный проходит; снятые потом
//       говорят — второго вычета нет; контроль AllowLegacy=0), Н-1 (MaxPendingPerIp: один адрес не больше предела, другие адреса не задеты,
//       завершённое рукопожатие освобождает место; предел процесса отличим в отчёте — режим 0/1), Н-6 (общий счёт = Σ TxFrameCost; сверка с
//       кучей процесса HeapWalk; предел по учтённой памяти; после закрытия 0), Н-2 (детерминированная гонка «выбор жертвы ↔ выталкивание»
//       на «воротах» стокового Send второго мока Ciocp: опустошённая под замком жертва не вытесняется, вытесняется настоящая наибольшая).
//       Гонки допуска (найдены при сборке sec2b): ClientHello соединению, уже отвергнутому сторожем, и ClientHello, ждавший cs слота,
//       пока слот разрывали, — байты не разбираются (ServerAccept нет, пара ECDH не тратится, −1).
//
// Мок стока — как stand_backlog (дизасм Ciocp::Send/SendTemp GS 0x561F20/0x562640): замок L, досылка 0x9F9C, буфер записи 0x1000,
//   ядро (здесь 16 КБ — чтобы очереди моста считались просто). Собирается ДВАЖДЫ (build.bat): с мостом sec2 (out\stand_sec2.exe)
//   и с мостом fix2e из stand\old_fix2e (/DSTAND_OLD_BRIDGE, out\stand_sec2_old.exe — только Е1/Е2: дефекты воспроизводятся, код ≠ 0).
// Серверные exe и оригинальный клиент не запускаются; ключ — временный (создаётся и удаляется).
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <windows.h>
#include <cstdio>
#include <vector>
#include <deque>
#include <set>
#include <string>
#include <cstring>
#include <cstddef>
#include <algorithm>

using namespace AsdaSecure;

static int g_fail = 0;
static void CHECK(bool ok, const char* what) { printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what); if (!ok) { ++g_fail; } }

// ── мок стокового Ciocp (как stand_backlog) ─────────────────────────────────────────────────────────────────────────
constexpr uint32_t kStride = 0xA0BE, kConn = 4, kFly = 8, kPBuf = 0xB2, kPend = 0xA0B2;
constexpr int      kLimit = 0x9F9C, kDirect = 0x1000;
constexpr size_t   kKernelCap = 16 * 1024;

struct MockCiocp { char pad[40]; CRITICAL_SECTION L; uint8_t* sess; };
static MockCiocp g_ci;
static uint8_t* SS(int slot) { return g_ci.sess + (size_t)slot * kStride; }
static volatile LONG& CONN(int slot) { return *(volatile LONG*)(SS(slot) + kConn); }
static volatile uint8_t& FLY(int slot) { return *(volatile uint8_t*)(SS(slot) + kFly); }
static volatile LONG& PEND(int slot) { return *(volatile LONG*)(SS(slot) + kPend); }
static uint8_t* PBUF(int slot) { return SS(slot) + kPBuf; }

struct Sock
{
    std::vector<uint8_t> kernel;
    std::deque<std::vector<uint8_t>> ops;
    bool                 opPending = false;
    volatile bool        reading = true;
    ClientChannel        client;
    std::vector<uint8_t> got;
    Err                  err = Err::Ok;
    volatile LONG        sends = 0;        // вызовов стокового Send слоту (ServerHello — первый)
};
static Sock* g_sock = nullptr;
static CRITICAL_SECTION g_kmx;
static std::deque<int> g_compl;
static HANDLE g_complEv;
static volatile LONG g_wipes = 0, g_killCalls = 0, g_killEff = 0;
static volatile bool g_stop = false;

// ServerHello (148 б, первый байт 0x5A): эфемерный открытый ключ сервера — для проверки «пара одноразовая».
static CRITICAL_SECTION g_hsLk;
static std::set<std::string> g_ephSeen;
static volatile LONG g_ephDup = 0, g_hello = 0;

static void PostCompletion(int slot) { EnterCriticalSection(&g_kmx); g_compl.push_back(slot); LeaveCriticalSection(&g_kmx); SetEvent(g_complEv); }
static bool KernelTryTakeLocked(int slot)
{
    Sock& k = g_sock[slot];
    // запись больше ядра (досылка до 40 КБ одной записью) принимается в ПУСТОЕ ядро — как настоящий сокет, принимающий её частями
    if (k.ops.empty() || (!k.kernel.empty() && k.kernel.size() + k.ops.front().size() > kKernelCap)) { return false; }
    k.kernel.insert(k.kernel.end(), k.ops.front().begin(), k.ops.front().end());
    k.ops.pop_front(); k.opPending = !k.ops.empty();
    return true;
}
static int MockWrite(int slot, const uint8_t* p, int n)
{
    int done = 0;
    EnterCriticalSection(&g_kmx);
    Sock& k = g_sock[slot];
    k.ops.emplace_back(p, p + n); k.opPending = true;
    while (KernelTryTakeLocked(slot)) { ++done; }
    LeaveCriticalSection(&g_kmx);
    for (; done > 0; --done) { PostCompletion(slot); }
    return 1;
}
static void Wipe(int slot) { memset(PBUF(slot), 0, 0xA000); PEND(slot) = 0; FLY(slot) = 0; InterlockedIncrement(&g_wipes); }
#ifdef ASDAWIRE_HAS_SEC2B
// ★ sec2b (Н-2): «ворота» стокового Send — первый вызов для слота g_gateSlot через Ciocp g_gateCi останавливается (мост в этот
//   момент держит cs слота и замок L этого Ciocp) до g_gateGo; g_gateHit — «нить дошла до ворот». Одноразово (CAS).
static volatile LONG g_gateSlot = -1;
static void* volatile g_gateCi = nullptr;
static HANDLE g_gateHit = nullptr, g_gateGo = nullptr;
#endif
static int MockStockSend(void* self, int slot, const void* src, int n)
{
    MockCiocp* c = (MockCiocp*)self;
    if (!c) { return 0; }
#ifdef ASDAWIRE_HAS_SEC2B
    if ((void*)c == g_gateCi && slot == (int)g_gateSlot && InterlockedCompareExchange(&g_gateSlot, -1, slot) == slot)
    {
        SetEvent(g_gateHit);
        WaitForSingleObject(g_gateGo, INFINITE);
    }
    // ★ sec2b: состояние сессии — того Ciocp, через который шлют (у g_ci — как раньше; у второго мока Н-2 — своя досылка).
    if (c != &g_ci)
    {
        EnterCriticalSection(&c->L);
        int rc2 = 0;
        if (n >= 0 && slot >= 0 && slot < 0x226)
        {
            uint8_t* ss = c->sess + (size_t)slot * kStride;
            volatile LONG& conn = *(volatile LONG*)(ss + kConn);
            volatile uint8_t& fly = *(volatile uint8_t*)(ss + kFly);
            volatile LONG& pend = *(volatile LONG*)(ss + kPend);
            if (conn && fly == 1)
            {
                if (pend + n >= kLimit) { memset(ss + kPBuf, 0, 0xA000); pend = 0; fly = 0; InterlockedIncrement(&g_wipes); }
                else { memcpy(ss + kPBuf + pend, src, n); pend += n; rc2 = 1; }
            }
            // (второй мок используется только с досылкой «в полёте» — запись в сокет ему не нужна)
        }
        LeaveCriticalSection(&c->L);
        return rc2;
    }
#endif
    if (n == (int)kServerHelloLen && ((const uint8_t*)src)[0] == kServerMagic)
    {
        std::string k((const char*)src + 4, kPubLen);
        EnterCriticalSection(&g_hsLk);
        if (!g_ephSeen.insert(k).second) { InterlockedIncrement(&g_ephDup); }
        LeaveCriticalSection(&g_hsLk);
        InterlockedIncrement(&g_hello);
    }
    if (slot >= 0 && slot < AsdaWire::kMaxSlots) { InterlockedIncrement(&g_sock[slot].sends); }
    EnterCriticalSection(&c->L);
    int rc = 0;
    if (n < 0 || slot < 0 || slot >= 0x226 || !CONN(slot)) { rc = 0; }
    else if (FLY(slot) == 1)
    {
        if (PEND(slot) + n >= kLimit) { Wipe(slot); rc = 0; }
        else { memcpy(PBUF(slot) + PEND(slot), src, n); PEND(slot) += n; rc = 1; }
    }
    else if (PEND(slot) > 0)
    {
        FLY(slot) = 1;
        memcpy(PBUF(slot) + PEND(slot), src, n); PEND(slot) += n;
        rc = MockWrite(slot, PBUF(slot), PEND(slot));
        memset(PBUF(slot), 0, 0xA000); PEND(slot) = 0;
    }
    else { FLY(slot) = 1; rc = MockWrite(slot, (const uint8_t*)src, n); }
    LeaveCriticalSection(&c->L);
    return rc;
}
static void MockSendTemp(int slot)
{
    EnterCriticalSection(&g_ci.L);
    FLY(slot) = 0;
    if (CONN(slot) && PEND(slot) > 0)
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
                d.clear();
                const Err e = k.client.OnRecv(buf.data(), buf.size(), d);
                if (e != Err::Ok) { k.err = e; }
                k.got.insert(k.got.end(), d.begin(), d.end());
            }
            buf.clear();
        }
        if (!any) { Sleep(1); }
    }
    return 0;
}

// ── хуки моста ────────────────────────────────────────────────────────────────────────────────────────────────────
static volatile LONG g_slotKilled[AsdaWire::kMaxSlots] = {};
static void MockKill(void* self, int slot)          // GetConnectFlag + DisConnect (под L, как сток) → SetConnectFlag(X,0)
{
    InterlockedIncrement(&g_killCalls);
    MockCiocp* c = (MockCiocp*)self;
    if (!c) { return; }
    EnterCriticalSection(&c->L);
    if (CONN(slot))
    {
        CONN(slot) = 0; FLY(slot) = 0; PEND(slot) = 0;
#ifdef ASDAWIRE_HAS_SEC2
        AsdaWire::ResetSlotEx(self, slot, 0);
#else
        AsdaWire::ResetSlot(slot, 0);
#endif
        InterlockedIncrement(&g_killEff); InterlockedIncrement(&g_slotKilled[slot]);
    }
    LeaveCriticalSection(&c->L);
}
static volatile LONG g_repKind[80] = {}, g_rep61Reason[8] = {};
static volatile LONG g_repSlotReason[AsdaWire::kMaxSlots] = {};
static AsdaWire::FailInfo g_lastAdm[80];
static CRITICAL_SECTION g_repLk;
static void MockReport(void*, int slot, const AsdaWire::FailInfo& fi)
{
    if (fi.kind >= 0 && fi.kind < 80) { InterlockedIncrement(&g_repKind[fi.kind]); }
    if (fi.kind == AsdaWire::kKindSendFail)
    {
        if (fi.reason > 0 && fi.reason < 8) { InterlockedIncrement(&g_rep61Reason[fi.reason]); }
        if (slot >= 0 && slot < AsdaWire::kMaxSlots) { InterlockedExchange(&g_repSlotReason[slot], fi.reason); }
        return;
    }
#ifdef ASDAWIRE_HAS_SEC2
    if (fi.kind >= AsdaWire::kKindConnRate && fi.kind <= AsdaWire::kKindHsDeadline)
    {
        EnterCriticalSection(&g_repLk); g_lastAdm[fi.kind] = fi; LeaveCriticalSection(&g_repLk);
        return;
    }
#endif
}

#ifdef ASDAWIRE_HAS_SEC2
static volatile LONG g_ip[AsdaWire::kMaxSlots] = {};
static uint32_t MockPeerIp(void*, int slot) { return (slot >= 0 && slot < AsdaWire::kMaxSlots) ? (uint32_t)g_ip[slot] : 0; }
static uint32_t Ip(int a, int b, int c, int d) { return (uint32_t)a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24); }
#endif

static PublicKey g_pub{};
static PrivateKey g_priv{};

static void AcceptSlot(int slot)
{
    EnterCriticalSection(&g_kmx);
    Sock& k = g_sock[slot];
    k.kernel.clear(); k.ops.clear(); k.opPending = false; k.got.clear(); k.err = Err::Ok; k.sends = 0;
    LeaveCriticalSection(&g_kmx);
    InterlockedExchange(&g_slotKilled[slot], 0);
    EnterCriticalSection(&g_ci.L);
    memset(SS(slot), 0, kStride);
    CONN(slot) = 1;
#ifdef ASDAWIRE_HAS_SEC2
    AsdaWire::ResetSlotEx(&g_ci, slot, 1);
#else
    AsdaWire::ResetSlot(slot, 1);
#endif
    LeaveCriticalSection(&g_ci.L);
}
static void CloseSlot(int slot) { MockKill(&g_ci, slot); }

static bool WaitFor(DWORD ms, bool (*pred)(int), int arg)
{
    const DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < ms) { if (pred(arg)) { return true; } Sleep(5); }
    return pred(arg);
}

// Клиент: ClientHello в RecvRoute; ответ читает нить Reader. Возврат RecvRoute (−1 — отказ/разрыв).
static int SendHello(int slot)
{
    Sock& k = g_sock[slot];
    k.client.Reset();
    std::vector<uint8_t> h; k.client.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr;
    return AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
}
static bool Open(int slot)
{
    AcceptSlot(slot);
    Sock& k = g_sock[slot];
    k.reading = false;
    const int rc = SendHello(slot);
    k.reading = true;
    if (rc < 0) { return false; }
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
static AsdaWire::Counters Cnt() { AsdaWire::Counters c{}; AsdaWire::GetCounters(&c); return c; }

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Е1: очередь слота, упавшего НЕ по виду 61, освобождается сразу.
static void E1()
{
    printf("-- Е1: нарушение приёма при KillOnViolation=0 у слота с очередью моста — очередь и общий счёт освобождаются сразу --\n");
    AsdaWire::SetFailureHooks(&MockKill, &MockReport, nullptr, /*killOnViolation=*/false);
    const int slot = 10;
    if (!Open(slot)) { CHECK(false, "Е1: рукопожатие"); return; }
    Sock& k = g_sock[slot];
    k.reading = false;                                         // клиент «грузит карту»
    uint32_t seq = 0;
    for (int i = 0; i < 120; ++i) { const auto f = Pkt(0x1100, 2000, 1, seq++); AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size()); }
    const AsdaWire::Counters c0 = Cnt();
    // Клиент шлёт кадр с порчей тега (вид 56): KillOnViolation=0 — слот в сбое, соединение не рвётся.
    std::vector<uint8_t> enc; const auto p = Pkt(0x2000, 60, 2, 1);
    k.client.OnSend(p.data(), p.size(), enc);
    enc[enc.size() - 3] ^= 0x5A;
    const LONG r56 = g_repKind[56], kc0 = g_killEff;
    const uint8_t* o = nullptr;
    const int rc = AsdaWire::RecvRoute(&g_ci, slot, enc.data(), (int)enc.size(), &o);
    const AsdaWire::Counters c1 = Cnt();                      // СРАЗУ, без ожидания сторожа и сброса слота
    char m[400];
    sprintf(m, "до нарушения: очередь моста %ld б (общий %ld); после RecvRoute (возврат %d, отчёт вида 56 +%ld, разрывов %ld, соединение %s): "
               "очередь %ld б, общий счётчик %ld б"
#ifdef ASDAWIRE_HAS_SEC2
               ", освобождено очередей сбойных слотов +%ld, слотов с очередью %ld"
#endif
            , c0.txNow, c0.txTotal, rc, g_repKind[56] - r56, g_killEff - kc0, CONN(slot) ? "открыто" : "закрыто", c1.txNow, c1.txTotal
#ifdef ASDAWIRE_HAS_SEC2
            , c1.txFailFreed - c0.txFailFreed, c1.txActive
#endif
            );
#ifdef STAND_OLD_BRIDGE
    const bool kept = c1.txNow > 0;
    printf("  [%s] (мост fix2e) %s\n", kept ? "ВОСПРОИЗВЕДЕНО" : "не воспроизведено", m);
    if (kept) { ++g_fail; }
#else
    CHECK(c0.txNow > 0 && rc == 0 && g_repKind[56] - r56 == 1 && g_killEff == kc0 && CONN(slot) && c1.txNow == 0 && c1.txTotal == 0
          && c1.txFailFreed - c0.txFailFreed == 1 && c1.txActive == 0, m);
#endif
    k.reading = true;
    CloseSlot(slot);
    AsdaWire::SlotFailed(slot);
    AsdaWire::SetFailureHooks(&MockKill, &MockReport, nullptr, true);
    const AsdaWire::Counters c2 = Cnt();
    sprintf(m, "после закрытия слота: общий счётчик %ld б, очередь %ld б", c2.txTotal, c2.txNow);
    CHECK(c2.txTotal == 0 && c2.txNow == 0, m);
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Е2: справедливая доля общего предела.
static const int kAtt = 4, kHon = 8, kAttFirst = 200, kHonFirst = 220;
static const LONG kE2Cap = 1024 * 1024;
static std::vector<uint8_t> g_honWant[kHon];
static volatile LONG g_e2maxTotal = 0;
static volatile bool g_e2mon = false;
static DWORD WINAPI E2Monitor(LPVOID)
{
    while (g_e2mon) { const AsdaWire::Counters c = Cnt(); if (c.txNow > g_e2maxTotal) { g_e2maxTotal = c.txNow; } Sleep(1); }
    return 0;
}
// Честный клиент грузит карту: ~150 КБ сервер шлёт порциями (2 КБ / 10 мс ≈ 200 КБ/с на слот), клиент не читает.
static DWORD WINAPI HonestSender(LPVOID p)
{
    const int i = (int)(intptr_t)p, slot = kHonFirst + i;
    uint32_t seq = 0;
    for (size_t sent = 0; sent < 150 * 1024; )
    {
        const auto f = Pkt(0x6000, 2048, (uint8_t)i, seq++);
        if (!AsdaWire::SendRoute(&g_ci, slot, f.data(), (int)f.size())) { break; }
        g_honWant[i].insert(g_honWant[i].end(), f.begin(), f.end()); sent += f.size();
        Sleep(10);
    }
    return 0;
}
static bool HonDrained(int)
{
    if (Cnt().txNow != 0) { return false; }
    for (int i = 0; i < kHon; ++i) { const int s = kHonFirst + i; if (CONN(s) && (!g_sock[s].kernel.empty() || g_sock[s].opPending || PEND(s) != 0)) { return false; } }
    return true;
}
static void E2()
{
    printf("-- Е2: общий предел %ld б: 4 «тяжёлых» не читают (≈240 КБ очереди каждый), 8 честных грузят карту (≈95 КБ очереди) --\n", kE2Cap);
    AsdaWire::SetTxQueueTotalMax(kE2Cap);
    AsdaWire::SetTxQueueMax(2 * 1024 * 1024);                  // предел слота выше общего — рвёт только общий предел
    for (int i = 0; i < kAtt; ++i) { if (!Open(kAttFirst + i)) { CHECK(false, "Е2: рукопожатие тяжёлого"); return; } g_sock[kAttFirst + i].reading = false; }
    for (int i = 0; i < kHon; ++i) { if (!Open(kHonFirst + i)) { CHECK(false, "Е2: рукопожатие честного"); return; } g_sock[kHonFirst + i].reading = false; g_honWant[i].clear(); }
    // тяжёлые: очередь ≈ 240 КБ каждому (досылка ~40 КБ + ядро 16 КБ сверху) — вместе ≈ 960 КБ, под пределом
    uint32_t seq = 0;
    for (int i = 0; i < kAtt; ++i)
    {
        const int s = kAttFirst + i;
        for (int j = 0; j < 140; ++j) { const auto f = Pkt(0x7000, 2048, (uint8_t)(50 + i), seq++); AsdaWire::SendRoute(&g_ci, s, f.data(), (int)f.size()); }
    }
    Sleep(100);
    const AsdaWire::Counters c0 = Cnt();
    LONG r0[8]; for (int i = 0; i < 8; ++i) { r0[i] = g_rep61Reason[i]; }
    const LONG k0 = g_killEff;
    g_e2maxTotal = 0; g_e2mon = true;
    HANDLE mon = CreateThread(nullptr, 0, &E2Monitor, nullptr, 0, nullptr);
    HANDLE th[kHon];
    for (int i = 0; i < kHon; ++i) { th[i] = CreateThread(nullptr, 0, &HonestSender, (LPVOID)(intptr_t)i, 0, nullptr); }
    const DWORD wr = WaitForMultipleObjects(kHon, th, TRUE, 30000);
    for (int i = 0; i < kHon; ++i) { CloseHandle(th[i]); }
    Sleep(300);
    g_e2mon = false; WaitForSingleObject(mon, 2000); CloseHandle(mon);
    const AsdaWire::Counters c1 = Cnt();
    LONG rr[8]; for (int i = 0; i < 8; ++i) { rr[i] = g_rep61Reason[i] - r0[i]; }
    int honKilled = 0, attKilled = 0;
    for (int i = 0; i < kHon; ++i) { if (!CONN(kHonFirst + i)) { ++honKilled; } }
    for (int i = 0; i < kAtt; ++i) { if (!CONN(kAttFirst + i)) { ++attKilled; } }
    char m[700];
#ifdef ASDAWIRE_HAS_SEC2
    const LONG hard = kE2Cap + kE2Cap / 8, ev = c1.txEvicted - c0.txEvicted, os = c1.txOverSoft - c0.txOverSoft;
#else
    const LONG hard = kE2Cap, ev = 0, os = 0;
#endif
    sprintf(m, "до честных: очереди %ld б (тяжёлых %d); после: разорвано честных %d из %d, тяжёлых %d из %d; вид 61 по причинам 4/6 = %ld/%ld "
               "(вытеснено %ld, «лёгких» постановок сверх предела %ld); наибольшая Σ очередей (замер) %ld б, txTotalPeak %ld б, потолок %ld б; "
               "нити %s; стираний досылки %ld",
            c0.txNow, kAtt, honKilled, kHon, attKilled, kAtt, rr[4], rr[6], ev, os, (long)g_e2maxTotal, c1.txTotalPeak, hard,
            wr == WAIT_TIMEOUT ? "ЗАВИСЛИ" : "завершились", g_wipes);
#ifdef STAND_OLD_BRIDGE
    printf("  [%s] (мост fix2e) %s\n", honKilled > 0 ? "ВОСПРОИЗВЕДЕНО: честные разорваны при живых тяжёлых" : "не воспроизведено", m);
    if (honKilled > 0) { ++g_fail; }
#else
    CHECK(wr != WAIT_TIMEOUT && honKilled == 0 && attKilled >= 1 && rr[6] == attKilled && rr[6] == ev && rr[4] == 0 && os > 0
          && g_killEff - k0 == attKilled && g_e2maxTotal <= hard && c1.txTotalPeak <= hard && g_wipes == 0, m);
#endif
    // честные дочитывают — поток цел и по порядку
    for (int i = 0; i < kHon; ++i) { g_sock[kHonFirst + i].reading = true; }
    WaitFor(20000, &HonDrained, 0);
    Sleep(200);
    int intact = 0, alive = 0;
    for (int i = 0; i < kHon; ++i)
    {
        const int s = kHonFirst + i;
        if (!CONN(s)) { continue; }
        ++alive;
        if (g_sock[s].err == Err::Ok && g_sock[s].got == g_honWant[i]) { ++intact; }
        else
        {
            size_t d = 0; const size_t mn = g_sock[s].got.size() < g_honWant[i].size() ? g_sock[s].got.size() : g_honWant[i].size();
            while (d < mn && g_sock[s].got[d] == g_honWant[i][d]) { ++d; }
            printf("    честный %d: клиент %s, получено %zu б, отправлено %zu б, первое расхождение на %zu\n", i, ErrName(g_sock[s].err),
                   g_sock[s].got.size(), g_honWant[i].size(), d);
        }
    }
    sprintf(m, "честные дочитали: живых %d, поток цел и по порядку у %d", alive, intact);
    CHECK(alive == intact, m);
#ifndef STAND_OLD_BRIDGE
    // тяжёлый слот один превышает предел — рвётся сам (причина 4), честные (уже дочитали) не задеты
    {
        const int s = 240;
        if (!Open(s)) { CHECK(false, "Е2: рукопожатие тяжёлого 2"); }
        g_sock[s].reading = false;
        const LONG r4 = g_rep61Reason[4], r6 = g_rep61Reason[6];
        int acc = 0;
        for (int j = 0; j < 800; ++j) { const auto f = Pkt(0x7100, 2048, 90, seq++); if (AsdaWire::SendRoute(&g_ci, s, f.data(), (int)f.size())) { ++acc; } else { break; } }
        Sleep(300);
        const AsdaWire::Counters c2 = Cnt();
        int honOpen = 0; for (int i = 0; i < kHon; ++i) { if (CONN(kHonFirst + i)) { ++honOpen; } }
        sprintf(m, "один тяжёлый шлёт 1,6 МБ не читая: принято %d кадров, причина 4 +%ld, причина 6 +%ld, соединение %s, честных открыто %d, "
                   "txTotalPeak %ld б", acc, g_rep61Reason[4] - r4, g_rep61Reason[6] - r6, CONN(s) ? "открыто" : "закрыто", honOpen, c2.txTotalPeak);
        CHECK(!CONN(s) && g_rep61Reason[4] - r4 + g_rep61Reason[6] - r6 == 1 && honOpen == alive && c2.txTotalPeak <= hard, m);
        g_sock[s].reading = true;
    }
#endif
    for (int i = 0; i < kAtt; ++i) { g_sock[kAttFirst + i].reading = true; CloseSlot(kAttFirst + i); AsdaWire::SlotFailed(kAttFirst + i); }
    for (int i = 0; i < kHon; ++i) { CloseSlot(kHonFirst + i); AsdaWire::SlotFailed(kHonFirst + i); }
    CloseSlot(240); AsdaWire::SlotFailed(240);
    Sleep(150);
    const AsdaWire::Counters c3 = Cnt();
#ifdef ASDAWIRE_HAS_SEC2
    sprintf(m, "после закрытия всех: общий счётчик %ld б, Σ очередей %ld б, слотов с очередью %ld", c3.txTotal, c3.txNow, c3.txActive);
    CHECK(c3.txTotal == 0 && c3.txNow == 0 && c3.txActive == 0, m);
#else
    sprintf(m, "после закрытия всех: общий счётчик %ld б, Σ очередей %ld б", c3.txTotal, c3.txNow);
    CHECK(c3.txTotal == 0 && c3.txNow == 0, m);
#endif
    AsdaWire::SetTxQueueTotalMax(64 * 1024 * 1024);
    AsdaWire::SetTxQueueMax(1024 * 1024);
}

#ifdef ASDAWIRE_HAS_SEC2
// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Х: ускорение рукопожатия.
// Время на нити сервера — по ЦИКЛАМ ЦП этой нити (QueryThreadCycleTime): не зависит от вытеснения другими процессами; работа
//   фоновой нити пула сюда не входит (она и снята с нити IOCP). Циклы → мкс — калибровка на этой нити (занятой цикл против QPC).
static double g_cycPerUs = 0;
static double NowUs() { ULONG64 c = 0; QueryThreadCycleTime(GetCurrentThread(), &c); return (double)c / g_cycPerUs; }
static void CalibrateCycles()
{
    LARGE_INTEGER f, q0, q1; QueryPerformanceFrequency(&f);
    ULONG64 c0 = 0, c1 = 0;
    QueryPerformanceCounter(&q0); QueryThreadCycleTime(GetCurrentThread(), &c0);
    volatile uint32_t x = 1; do { for (int i = 0; i < 100000; ++i) { x = x * 1664525u + 1013904223u; } QueryPerformanceCounter(&q1); }
    while ((double)(q1.QuadPart - q0.QuadPart) / (double)f.QuadPart < 0.3);
    QueryThreadCycleTime(GetCurrentThread(), &c1);
    g_cycPerUs = (double)(c1 - c0) / ((double)(q1.QuadPart - q0.QuadPart) * 1e6 / (double)f.QuadPart);
}
struct Stat { std::vector<double> v; void Add(double x) { v.push_back(x); }
    double Mean() const { double s = 0; for (double x : v) { s += x; } return v.empty() ? 0 : s / v.size(); }
    double Q(double q) { if (v.empty()) { return 0; } std::sort(v.begin(), v.end()); return v[(size_t)(q * (v.size() - 1))]; } };

// Рукопожатие слота (сервер — RecvRoute(ClientHello), время только на нити сервера), клиент проверяет подпись и выводит ключи.
static bool TimedHandshake(int slot, double* us)
{
    AcceptSlot(slot);
    Sock& k = g_sock[slot];
    k.reading = false;
    k.client.Reset();
    std::vector<uint8_t> h; k.client.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr;
    const double t0 = NowUs();
    const int rc = AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
    *us = NowUs() - t0;
    k.reading = true;
    if (rc < 0) { return false; }
    return WaitFor(3000, [](int s) { return g_sock[s].client.IsReady() || g_sock[s].err != Err::Ok; }, slot) && k.client.IsReady();
}
static void HsSeries(const char* name, int n, Stat& st, int* okOut)
{
    int ok = 0;
    for (int i = 0; i < n; ++i)
    {
        const int slot = 300 + (i % 100);
        double us = 0;
        if (TimedHandshake(slot, &us)) { ++ok; st.Add(us); }
        CloseSlot(slot); AsdaWire::SlotFailed(slot);
        if ((i % 16) == 15) { Sleep(30); }                     // темп «входов»: пул успевает пополняться (≈1400 пар/с на одной нити)
    }
    *okOut = ok;
    printf("    %-48s ср %.0f мкс, p50 %.0f, p99 %.0f (рукопожатий %d из %d)\n", name, st.Mean(), st.Q(.5), st.Q(.99), ok, n);
}
struct ConcArg { int first; int n; int ok; };
static DWORD WINAPI ConcThread(LPVOID p)
{
    ConcArg& a = *(ConcArg*)p;
    for (int i = 0; i < a.n; ++i)
    {
        const int slot = a.first + (i % 10);
        double us = 0;
        if (TimedHandshake(slot, &us)) { ++a.ok; }
        CloseSlot(slot); AsdaWire::SlotFailed(slot);
    }
    return 0;
}
static void HX()
{
    printf("-- Х: ускорение рукопожатия (кэш ключа подписи + пул ECDH) — время сервера на нити приёма --\n");
    CalibrateCycles();
    printf("    (время — циклы ЦП нити сервера, %.0f циклов/мкс)\n", g_cycPerUs);
    AccelStats a0{}; GetAccelStats(&a0);
    char m[400];
    sprintf(m, "после первого соединения мост загрузил ключ подписи в кэш (дескрипторов %ld) и запустил пул (размер %ld, сейчас %ld)", a0.signHandles, a0.poolTarget, a0.poolNow);
    CHECK(a0.signHandles >= 1 && a0.poolTarget == 16, m);
    // прежний путь: ключ импортируется на каждую подпись, пара — на месте
    ServerSignerClear(); EphemeralPoolStop();
    Stat sOld; int okOld = 0;
    AccelStats b0{}; GetAccelStats(&b0);
    HsSeries("прежний путь (импорт ключа + пара на месте):", 400, sOld, &okOld);
    AccelStats b1{}; GetAccelStats(&b1);
    sprintf(m, "прежний путь: подписей с импортом %ld, пар на месте %ld, из пула %ld", b1.signImport - b0.signImport, b1.ephInline - b0.ephInline, b1.ephPool - b0.ephPool);
    CHECK(okOld == 400 && b1.signImport - b0.signImport == 400 && b1.ephInline - b0.ephInline == 400 && b1.ephPool == b0.ephPool, m);
    // ускоренный путь
    CHECK(ServerSignerLoad(g_priv) && EphemeralPoolStart(16), "кэш ключа и пул снова включены");
    Sleep(200);
    Stat sNew; int okNew = 0;
    GetAccelStats(&b0);
    HsSeries("кэш ключа + пул ECDH:", 400, sNew, &okNew);
    GetAccelStats(&b1);
    sprintf(m, "ускоренный путь: подписей кэшем %ld, с импортом %ld; пар из пула %ld, на месте %ld; время ср %.0f → %.0f мкс (−%.0f %%), p99 %.0f → %.0f",
            b1.signCached - b0.signCached, b1.signImport - b0.signImport, b1.ephPool - b0.ephPool, b1.ephInline - b0.ephInline,
            sOld.Mean(), sNew.Mean(), 100.0 * (1.0 - sNew.Mean() / sOld.Mean()), sOld.Q(.99), sNew.Q(.99));
    CHECK(okNew == 400 && b1.signCached - b0.signCached == 400 && b1.signImport == b0.signImport && b1.ephPool - b0.ephPool >= 380
          && sNew.Mean() < sOld.Mean() * 0.65, m);
    // одноразовость: ни один эфемерный ключ ServerHello не повторился
    sprintf(m, "ServerHello выдано %ld, разных эфемерных ключей %zu, повторов %ld", g_hello, g_ephSeen.size(), g_ephDup);
    CHECK(g_ephDup == 0 && (long)g_ephSeen.size() == g_hello, m);
    // пул пуст / выключен — генерация на месте, рукопожатия идут
    EphemeralPoolStop();
    GetAccelStats(&b0);
    Stat sEmpty; int okE = 0;
    HsSeries("кэш ключа, пул выключен (пары на месте):", 100, sEmpty, &okE);
    GetAccelStats(&b1);
    sprintf(m, "пул выключен: рукопожатий %d из 100, пар на месте %ld, из пула %ld", okE, b1.ephInline - b0.ephInline, b1.ephPool - b0.ephPool);
    CHECK(okE == 100 && b1.ephInline - b0.ephInline == 100 && b1.ephPool == b0.ephPool, m);
    // 8 нитей одновременно (пул 16, дескрипторов подписи ≤ 16)
    EphemeralPoolStart(16); Sleep(100);
    GetAccelStats(&b0);
    const long dup0 = g_ephDup;
    ConcArg args[8]; HANDLE th[8];
    for (int t = 0; t < 8; ++t) { args[t] = { 400 + t * 10, 60, 0 }; th[t] = CreateThread(nullptr, 0, &ConcThread, &args[t], 0, nullptr); }
    const DWORD wr = WaitForMultipleObjects(8, th, TRUE, 120000);
    int okC = 0; for (int t = 0; t < 8; ++t) { CloseHandle(th[t]); okC += args[t].ok; }
    GetAccelStats(&b1);
    sprintf(m, "8 нитей × 60 рукопожатий: прошло %d из 480 (подпись проверена клиентом), нити %s; дескрипторов подписи %ld (≤ %d), подписей кэшем %ld + импортом %ld; "
               "пар из пула %ld + на месте %ld; повторов эфемерного ключа %ld",
            okC, wr == WAIT_TIMEOUT ? "ЗАВИСЛИ" : "завершились", b1.signHandles, kSignerHandles, b1.signCached - b0.signCached, b1.signImport - b0.signImport,
            b1.ephPool - b0.ephPool, b1.ephInline - b0.ephInline, g_ephDup - dup0);
    CHECK(wr != WAIT_TIMEOUT && okC == 480 && b1.signHandles <= kSignerHandles && (b1.signCached - b0.signCached) + (b1.signImport - b0.signImport) == 480
          && (b1.ephPool - b0.ephPool) + (b1.ephInline - b0.ephInline) == 480 && g_ephDup == dup0, m);
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Д: допуск подключений до рукопожатия.
static void SetAdm(int perIp, int winMs, int maxPend, int deadline, int gap)
{
    AsdaWire::AdmissionCfg c{ perIp, winMs, maxPend, deadline, gap };
    AsdaWire::SetAdmission(&c, &MockPeerIp);
}
static void AdmissionTests()
{
    char m[600];
    printf("-- Д1: предел с адреса (5 за окно 2 с): шестое подключение с того же адреса — отказ ДО рукопожатия (вид 63) --\n");
    SetAdm(5, 2000, 0, 0, 1000);
    const uint32_t X = Ip(203, 0, 113, 7), Y = Ip(198, 51, 100, 9);
    {
        AccelStats a0{}; GetAccelStats(&a0);
        const LONG h0 = g_hello, r63 = g_repKind[63], k0 = g_killEff;
        const AsdaWire::Counters c0 = Cnt();
        int ok = 0;
        for (int i = 0; i < 5; ++i) { g_ip[20 + i] = X; if (Open(20 + i)) { ++ok; } }
        g_ip[25] = X; AcceptSlot(25);
        const int rc6 = SendHello(25);
        g_ip[26] = X; AcceptSlot(26);
        const int rc7 = SendHello(26);
        g_ip[27] = Y; const bool okY = Open(27);
        AccelStats a1{}; GetAccelStats(&a1);
        const AsdaWire::Counters c1 = Cnt();
        AsdaWire::FailInfo fi = g_lastAdm[63];
        sprintf(m, "5 с адреса X прошли: %d; шестое: RecvRoute %d, соединение %s, стоковых Send слоту %ld; седьмое: %d, %s; с адреса Y: %s; "
                   "отчётов вида 63 %ld (адрес %u.%u.%u.%u, счёт %d, предел %d, окно %d с); отказов по адресу %ld; ServerAccept выполнен %ld раз (пары %ld) на 6 допущенных",
                ok, rc6, CONN(25) ? "открыто" : "закрыто", g_sock[25].sends, rc7, CONN(26) ? "открыто" : "закрыто", okY ? "прошло" : "НЕ прошло",
                g_repKind[63] - r63, fi.ip & 0xFF, (fi.ip >> 8) & 0xFF, (fi.ip >> 16) & 0xFF, fi.ip >> 24, fi.count, fi.limit, fi.extra,
                c1.admRate - c0.admRate, g_hello - h0, (a1.ephPool + a1.ephInline) - (a0.ephPool + a0.ephInline));
        CHECK(ok == 5 && rc6 == -1 && !CONN(25) && g_sock[25].sends == 0 && rc7 == -1 && !CONN(26) && okY && g_repKind[63] - r63 == 1
              && fi.ip == X && fi.count == 6 && fi.limit == 5 && fi.extra == 2 && c1.admRate - c0.admRate == 2 && g_hello - h0 == 6
              && (a1.ephPool + a1.ephInline) - (a0.ephPool + a0.ephInline) == 6 && g_killEff - k0 == 2, m);
        Sleep(2100);
        g_ip[28] = X; const bool okAfter = Open(28);
        sprintf(m, "окно истекло (2,1 с) — с адреса X снова пускает: %s", okAfter ? "да" : "НЕТ");
        CHECK(okAfter, m);
        for (int s = 20; s <= 28; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
    }
    printf("-- Д2: молчащие соединения с одного адреса (8 при пределе 5) — отказ сторожем без единого байта клиента --\n");
    {
        const uint32_t Z = Ip(192, 0, 2, 33);
        const LONG k0 = g_killEff, r63 = g_repKind[63];
        for (int i = 0; i < 8; ++i) { g_ip[40 + i] = Z; AcceptSlot(40 + i); }
        Sleep(200);
        int closed = 0; for (int i = 0; i < 8; ++i) { if (!CONN(40 + i)) { ++closed; } }
        sprintf(m, "закрыто сторожем %d из 8 (ожидается 3), разрывов %ld, отчётов 63 %ld", closed, g_killEff - k0, g_repKind[63] - r63);
        CHECK(closed == 3 && g_killEff - k0 == 3 && g_repKind[63] - r63 == 1, m);
        for (int i = 0; i < 8; ++i) { CloseSlot(40 + i); AsdaWire::SlotFailed(40 + i); }
    }
    printf("-- Д3: предел незавершённых рукопожатий (10): одиннадцатое молчащее соединение — отказ (вид 64), завершённые освобождают место --\n");
    {
        SetAdm(0, 2000, 10, 0, 1000);
        const AsdaWire::Counters c0 = Cnt();
        const LONG r64 = g_repKind[64], k0 = g_killEff;
        for (int i = 0; i < 10; ++i) { g_ip[60 + i] = Ip(10, 0, 0, 1 + i); AcceptSlot(60 + i); }
        Sleep(150);
        const LONG pend10 = Cnt().hsPending;
        g_ip[70] = Ip(10, 0, 0, 99); AcceptSlot(70);
        Sleep(150);
        const AsdaWire::Counters c1 = Cnt();
        AsdaWire::FailInfo fi = g_lastAdm[64];
        sprintf(m, "10 молчащих: незавершённых %ld; 11-е: соединение %s, отказов 64 +%ld, отчётов 64 +%ld (счёт %d, предел %d), незавершённых после %ld, разрывов %ld",
                pend10 - c0.hsPending, CONN(70) ? "открыто" : "закрыто", c1.admPending - c0.admPending, g_repKind[64] - r64, fi.count, fi.limit,
                c1.hsPending - c0.hsPending, g_killEff - k0);
        CHECK(pend10 - c0.hsPending == 10 && !CONN(70) && c1.admPending - c0.admPending == 1 && g_repKind[64] - r64 == 1 && fi.count == 11 && fi.limit == 10
              && c1.hsPending - c0.hsPending == 10 && g_killEff - k0 == 1, m);
        // пять завершают рукопожатие — место освобождается
        int done = 0;
        for (int i = 0; i < 5; ++i) { Sock& k = g_sock[60 + i]; k.reading = false; SendHello(60 + i); k.reading = true;
                                      if (WaitFor(3000, [](int s) { return g_sock[s].client.IsReady(); }, 60 + i)) { ++done; } }
        const LONG pend5 = Cnt().hsPending - c0.hsPending;
        g_ip[71] = Ip(10, 0, 0, 100); const bool ok71 = Open(71);
        sprintf(m, "5 завершили рукопожатие (%d): незавершённых %ld; новое соединение прошло: %s", done, pend5, ok71 ? "да" : "НЕТ");
        CHECK(done == 5 && pend5 == 5 && ok71, m);
        // ограничитель отчётов: 20 отказов подряд — отчёт один, подавленные — в следующем
        for (int i = 0; i < 5; ++i) { g_ip[72 + i] = Ip(10, 0, 0, 120 + i); AcceptSlot(72 + i); }   // добить до 10 незавершённых (5 + 5)
        Sleep(120);
        const LONG rr = g_repKind[64], ar = Cnt().admPending;
        for (int i = 0; i < 20; ++i) { g_ip[80 + i] = Ip(10, 0, 1, i); AcceptSlot(80 + i); }
        Sleep(200);
        sprintf(m, "20 отказов (64) за 0,2 с: отказов %ld, отчётов %ld (ограничитель 1 с)", Cnt().admPending - ar, g_repKind[64] - rr);
        CHECK(Cnt().admPending - ar == 20 && g_repKind[64] - rr <= 1, m);
        Sleep(1100);
        g_ip[100] = Ip(10, 0, 2, 1); AcceptSlot(100); Sleep(150);
        fi = g_lastAdm[64];
        sprintf(m, "следующий отказ через 1,1 с — отчёт с подавленными: extra %d", fi.extra);
        CHECK(fi.extra >= 19, m);
        for (int s = 60; s <= 100; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
        Sleep(60);
        sprintf(m, "все закрыты: незавершённых %ld (до Д3 %ld)", Cnt().hsPending, c0.hsPending);
        CHECK(Cnt().hsPending == c0.hsPending, m);
    }
    printf("-- Д4: срок рукопожатия 300 мс --\n");
    {
        SetAdm(0, 2000, 0, 300, 0);
        AsdaWire::SetAllowLegacy(false);
        const LONG r65 = g_repKind[65], k0 = g_killEff;
        g_ip[110] = Ip(10, 1, 0, 1); AcceptSlot(110);                         // молчит
        g_ip[111] = Ip(10, 1, 0, 2); AcceptSlot(111);                         // начал ClientHello и бросил
        { Sock& k = g_sock[111]; k.client.Reset(); std::vector<uint8_t> h; k.client.Start(SubServer::Game, g_pub, h);
          const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, 111, h.data(), 20, &o); }
        g_ip[112] = Ip(10, 1, 0, 3); const bool ok112 = Open(112);           // завершил
        Sleep(120);
        const bool early = CONN(110) && CONN(111);
        Sleep(400);
        AsdaWire::FailInfo fi = g_lastAdm[65];
        sprintf(m, "AllowLegacy=0: через 120 мс оба ещё открыты: %s; через 520 мс — молчащий %s, начавший %s, завершивший %s; отчётов 65 +%ld, разрывов %ld; "
                   "последний отчёт: возраст %d мс, срок %d, режим %d",
                early ? "да" : "НЕТ", CONN(110) ? "открыт" : "закрыт", CONN(111) ? "открыт" : "закрыт", CONN(112) ? "открыт" : "закрыт",
                g_repKind[65] - r65, g_killEff - k0, fi.count, fi.limit, fi.mode);
        CHECK(early && !CONN(110) && !CONN(111) && ok112 && CONN(112) && g_repKind[65] - r65 == 2 && g_killEff - k0 == 2 && fi.count >= 300 && fi.limit == 300, m);
        for (int s = 110; s <= 112; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
        AsdaWire::SetAllowLegacy(true);
        const LONG k1 = g_killEff;
        g_ip[113] = Ip(10, 1, 0, 4); AcceptSlot(113);                         // молчит при AllowLegacy=1 — старый клиент мог открыть заранее
        g_ip[114] = Ip(10, 1, 0, 5); AcceptSlot(114);
        { Sock& k = g_sock[114]; k.client.Reset(); std::vector<uint8_t> h; k.client.Start(SubServer::Game, g_pub, h);
          const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, 114, h.data(), 20, &o); }
        g_ip[115] = Ip(10, 1, 0, 6); AcceptSlot(115);                         // старый клиент: первый байт 0xFB — рукопожатие завершено
        const LONG pBefore = Cnt().hsPending;
        { const auto f = Pkt(20000, 40, 1, 1); const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, 115, f.data(), (int)f.size(), &o); }
        const LONG pAfter = Cnt().hsPending;
        Sleep(550);
        sprintf(m, "AllowLegacy=1: молчащий %s, начавший и бросивший %s, старый клиент %s (незавершённых до первого байта %ld, после %ld); разрывов %ld",
                CONN(113) ? "открыт" : "закрыт", CONN(114) ? "открыт" : "закрыт", CONN(115) ? "открыт" : "закрыт", pBefore, pAfter, g_killEff - k1);
        CHECK(CONN(113) && !CONN(114) && CONN(115) && pAfter == pBefore - 1 && g_killEff - k1 == 1, m);
        for (int s = 113; s <= 115; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
    }
    printf("-- Д5: отложенный разрыв fix2b (отказ сервера до рукопожатия) не задерживает разрыв по сроку --\n");
    {
        SetAdm(0, 2000, 0, 300, 0);
        AsdaWire::SetAllowLegacy(false);
        const int s = 120;
        g_ip[s] = Ip(10, 2, 0, 1); AcceptSlot(s);
        const auto f = Pkt(6004, 26, 1, 1);
        const int q = AsdaWire::SendRoute(&g_ci, s, f.data(), (int)f.size());   // кадр до рукопожатия — в очередь слота
        const bool deferred = AsdaWire::DisconnectGate(&g_ci, s, 0);            // логика зовёт DisConnect — отложен (ждёт клиента до 5 с)
        const DWORD t0 = GetTickCount();
        WaitFor(3000, [](int x) { return !CONN(x); }, s);
        const DWORD dt = GetTickCount() - t0;
        sprintf(m, "кадр в очередь %d, DisConnect отложен %s; молчащий клиент разорван через %lu мс (срок 300, отложенный ждал бы 5000)", q, deferred ? "да" : "нет", dt);
        CHECK(q == 1 && deferred && !CONN(s) && dt < 1000, m);
        AsdaWire::SlotFailed(s);
        AsdaWire::SetAllowLegacy(true);
    }
    printf("-- Д6: стресс 3 с — 4 нити accept/ClientHello/разрыв на 64 слотах против сторожа (все пределы включены) --\n");
    {
        SetAdm(1000000, 60000, 48, 200, 1000);
        AsdaWire::SetAllowLegacy(false);
        const LONG pend0 = Cnt().hsPending;
        struct SA { int first; volatile LONG* stop; LONG cycles; };
        static volatile LONG stop = 0; stop = 0;
        auto fn = [](LPVOID p) -> DWORD {
            SA& a = *(SA*)p; uint32_t r = 7u * (a.first + 1);
            while (!*a.stop)
            {
                r = r * 1103515245u + 12345u;
                const int slot = a.first + (int)((r >> 8) % 16);
                g_ip[slot] = Ip(172, 16, 0, (int)(r >> 20) & 0xFF);
                EnterCriticalSection(&g_ci.L); const bool open = CONN(slot) != 0; LeaveCriticalSection(&g_ci.L);
                if (!open)
                {
                    EnterCriticalSection(&g_ci.L); memset(SS(slot), 0, kStride); CONN(slot) = 1; AsdaWire::ResetSlotEx(&g_ci, slot, 1); LeaveCriticalSection(&g_ci.L);
                    if ((r >> 4) & 1)
                    {
                        ClientChannel c; std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
                        const uint8_t* o = nullptr; AsdaWire::RecvRoute(&g_ci, slot, h.data(), (int)h.size(), &o);
                    }
                }
                else if (((r >> 12) & 3) == 0) { MockKill(&g_ci, slot); }
                ++a.cycles;
            }
            return 0;
        };
        for (int s = 140; s < 204; ++s) { g_sock[s].reading = false; }
        SA args[4]; HANDLE th[4];
        for (int t = 0; t < 4; ++t) { args[t] = { 140 + t * 16, &stop, 0 }; th[t] = CreateThread(nullptr, 0, fn, &args[t], 0, nullptr); }
        Sleep(3000);
        stop = 1;
        const DWORD wr = WaitForMultipleObjects(4, th, TRUE, 20000);
        LONG cyc = 0; for (int t = 0; t < 4; ++t) { CloseHandle(th[t]); cyc += args[t].cycles; }
        const AsdaWire::Counters cmid = Cnt();
        for (int s = 140; s < 204; ++s) { MockKill(&g_ci, s); AsdaWire::SlotFailed(s); g_sock[s].reading = true; }
        Sleep(120);
        const AsdaWire::Counters c = Cnt();
        sprintf(m, "циклов %ld, нити %s; незавершённых наибольшее %ld (предел 48 + принятые до проверки), отказов 64 %ld, по сроку 65 %ld; "
                   "после закрытия всех — незавершённых %ld (до стресса %ld)", cyc, wr == WAIT_TIMEOUT ? "ЗАВИСЛИ" : "завершились", cmid.hsPendingPeak,
                c.admPending, c.admDeadline, c.hsPending, pend0);
        CHECK(wr != WAIT_TIMEOUT && c.hsPending == pend0 && c.hsPending >= 0, m);
        AsdaWire::SetAllowLegacy(true);
    }
    AsdaWire::SetAdmission(nullptr, nullptr);
}
#endif

#ifdef ASDAWIRE_HAS_SEC2B
// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ★ sec2b (ревизия SEC2, review_SEC2_20261015.md): С-1, Н-1, Н-2, Н-6.
static void SetAdmB(int perIp, int winMs, int maxPend, int deadline, int gap, int pendPerIp)
{
    AsdaWire::AdmissionCfg c{ perIp, winMs, maxPend, deadline, gap, pendPerIp };
    AsdaWire::SetAdmission(&c, &MockPeerIp);
}

// С-1: AllowLegacy=1 — молчащие сокеты по сроку рукопожатия снимаются со счёта незавершённых (не рвутся); честный клиент проходит.
static void SecC1()
{
    char m[900];
    printf("-- С-1: AllowLegacy=1, MaxPendingHandshakes=10, срок 300 мс: 10 молчащих с одного адреса — по сроку сняты со счёта, не разорваны --\n");
    SetAdmB(0, 2000, 10, 300, 0, 0);
    AsdaWire::SetAllowLegacy(true);
    const AsdaWire::Counters c0 = Cnt();
    const LONG r64 = g_repKind[64], r65 = g_repKind[65], k0 = g_killEff;
    const uint32_t Q = Ip(203, 0, 113, 50);
    for (int i = 0; i < 10; ++i) { g_ip[130 + i] = Q; AcceptSlot(130 + i); }
    Sleep(120);
    g_ip[140] = Ip(198, 51, 100, 50); AcceptSlot(140);           // до срока предел действует: 11-е — отказ 64
    Sleep(120);
    const bool rej11 = !CONN(140);
    const LONG k1 = g_killEff, r64a = g_repKind[64];
    Sleep(500);                                                    // > 300 мс от accept + шаг сторожа
    const AsdaWire::Counters c1 = Cnt();
    int open = 0; for (int i = 0; i < 10; ++i) { if (CONN(130 + i)) { ++open; } }
    g_ip[141] = Ip(198, 51, 100, 51);
    const bool ok = Open(141);                                     // честный клиент с другого адреса
    const AsdaWire::Counters c2 = Cnt();
    sprintf(m, "до срока 11-е соединение %s (отчётов 64 +%ld, разрывов %ld); после срока: молчащих открыто %d из 10, незавершённых %ld (до %ld), "
               "снято со счёта по сроку +%ld, отчётов 65 +%ld, разрывов после 11-го %ld; честный с другого адреса: %s, отказов 64 после срока +%ld",
            rej11 ? "отвергнуто" : "ПРОПУЩЕНО", r64a - r64, k1 - k0, open, c1.hsPending, c0.hsPending, c1.hsSilentReleased - c0.hsSilentReleased,
            g_repKind[65] - r65, g_killEff - k1, ok ? "прошёл" : "ОТВЕРГНУТ", c2.admPending - c1.admPending);
    CHECK(rej11 && r64a - r64 == 1 && k1 - k0 == 1 && open == 10 && c1.hsPending == c0.hsPending && c1.hsSilentReleased - c0.hsSilentReleased == 10
          && g_repKind[65] == r65 && g_killEff == k1 && ok && c2.admPending == c1.admPending, m);
    // снятые со счёта потом заговорили: вычета второй раз нет (счёт не уходит ниже)
    {
        Sock& k = g_sock[130]; k.reading = false; const int rc = SendHello(130); k.reading = true;
        const bool hs = rc >= 0 && WaitFor(3000, [](int s) { return g_sock[s].client.IsReady(); }, 130);
        const auto f = Pkt(20000, 40, 1, 1); const uint8_t* o = nullptr;
        const int rl = AsdaWire::RecvRoute(&g_ci, 131, f.data(), (int)f.size(), &o);
        const AsdaWire::Counters c3 = Cnt();
        sprintf(m, "снятые со счёта заговорили: ClientHello — рукопожатие %s; старый клиент (0xFB) — приём %d, режим %d; незавершённых %ld (до %ld) — "
                   "второго вычета нет; разрывов +%ld", hs ? "завершено" : "НЕТ", rl, AsdaWire::SlotMode(131), c3.hsPending, c0.hsPending, g_killEff - k1);
        CHECK(hs && rl == (int)f.size() && AsdaWire::SlotMode(131) == 2 && c3.hsPending == c0.hsPending && g_killEff == k1, m);
    }
    for (int s = 130; s <= 141; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
    Sleep(60);
    sprintf(m, "все закрыты: незавершённых %ld (до С-1 %ld)", Cnt().hsPending, c0.hsPending);
    CHECK(Cnt().hsPending == c0.hsPending, m);
    // контроль: AllowLegacy=0 — молчащие по сроку разорваны (65), «снятия без разрыва» нет
    AsdaWire::SetAllowLegacy(false);
    const AsdaWire::Counters d0 = Cnt();
    const LONG kd = g_killEff;
    for (int i = 0; i < 3; ++i) { g_ip[150 + i] = Ip(10, 77, 0, 1 + i); AcceptSlot(150 + i); }
    Sleep(600);
    const AsdaWire::Counters d1 = Cnt();
    int closed = 0; for (int i = 0; i < 3; ++i) { if (!CONN(150 + i)) { ++closed; } }
    sprintf(m, "контроль AllowLegacy=0: молчащих закрыто по сроку %d из 3 (65 +%ld, разрывов %ld), снято без разрыва +%ld, незавершённых %ld (до %ld)",
            closed, d1.admDeadline - d0.admDeadline, g_killEff - kd, d1.hsSilentReleased - d0.hsSilentReleased, d1.hsPending, d0.hsPending);
    CHECK(closed == 3 && d1.admDeadline - d0.admDeadline == 3 && g_killEff - kd == 3 && d1.hsSilentReleased == d0.hsSilentReleased && d1.hsPending == d0.hsPending, m);
    for (int s = 150; s <= 152; ++s) { AsdaWire::SlotFailed(s); }
    AsdaWire::SetAllowLegacy(true);
    AsdaWire::SetAdmission(nullptr, nullptr);
}

// Н-1: один адрес не занимает больше MaxPendingPerIp незавершённых рукопожатий (схема R2 ревизора + предел с адреса).
static void SecN1()
{
    char m[900];
    printf("-- Н-1: MaxPendingPerIp=16 (как R2 ревизора: ConnPerIpMax 120/60 с, MaxPendingHandshakes 64, AllowLegacy=0): один адрес открывает 64 молчащих --\n");
    SetAdmB(120, 60000, 64, 5000, 0, 16);
    AsdaWire::SetAllowLegacy(false);
    const AsdaWire::Counters c0 = Cnt();
    const LONG r64 = g_repKind[64], k0 = g_killEff;
    const uint32_t A = Ip(203, 0, 113, 66), B = Ip(198, 51, 100, 20), C = Ip(198, 51, 100, 77);
    for (int i = 0; i < 64; ++i) { g_ip[340 + i] = A; AcceptSlot(340 + i); }
    Sleep(150);
    int openA = 0, firstA = -1;
    for (int i = 0; i < 64; ++i) { if (CONN(340 + i)) { ++openA; if (firstA < 0) { firstA = 340 + i; } } }
    const AsdaWire::Counters c1 = Cnt();
    const AsdaWire::FailInfo fi = g_lastAdm[64];
    const LONG k1 = g_killEff, rep1 = g_repKind[64];
    g_ip[420] = B; const bool okB = Open(420);                    // в срок рукопожатия — честный с другого адреса
    for (int i = 0; i < 16; ++i) { g_ip[430 + i] = C; AcceptSlot(430 + i); }   // другой адрес — свои 16, предел A его не касается
    Sleep(150);
    int openC = 0; for (int i = 0; i < 16; ++i) { if (CONN(430 + i)) { ++openC; } }
    const AsdaWire::Counters c2 = Cnt();
    sprintf(m, "адрес A: открыто %d из 64, отказов 64 «с адреса» +%ld (всего 64 +%ld, отчётов +%ld, разрывов %ld), последний отчёт: режим %d, счёт %d, предел %d; "
               "незавершённых %ld; честный с адреса B в срок: %s; адрес C: 16 молчащих — открыто %d; отказов после A +%ld",
            openA, c1.admPendingIp - c0.admPendingIp, c1.admPending - c0.admPending, rep1 - r64, k1 - k0, fi.mode, fi.count, fi.limit,
            c1.hsPending - c0.hsPending, okB ? "прошёл" : "ОТВЕРГНУТ", openC, c2.admPending - c1.admPending);
    CHECK(openA == 16 && c1.admPendingIp - c0.admPendingIp == 48 && c1.admPending - c0.admPending == 48 && rep1 - r64 == 48 && k1 - k0 == 48
          && fi.mode == 1 && fi.count == 17 && fi.limit == 16 && fi.ip == A && c1.hsPending - c0.hsPending == 16 && okB && openC == 16
          && c2.admPending == c1.admPending, m);
    // одно соединение A завершило рукопожатие — место адреса освободилось: новое с A проходит, следующее — снова отказ
    {
        Sock& k = g_sock[firstA]; k.reading = false; SendHello(firstA); k.reading = true;
        const bool hs = WaitFor(3000, [](int s) { return g_sock[s].client.IsReady(); }, firstA);
        const AsdaWire::Counters d0 = Cnt();
        g_ip[410] = A; AcceptSlot(410); Sleep(120);
        g_ip[411] = A; AcceptSlot(411); Sleep(120);
        const AsdaWire::Counters d1 = Cnt();
        sprintf(m, "A завершил одно рукопожатие (%s): новое с A %s, следующее %s (отказов «с адреса» +%ld)", hs ? "да" : "НЕТ",
                CONN(410) ? "допущено" : "ОТВЕРГНУТО", CONN(411) ? "ДОПУЩЕНО" : "отвергнуто", d1.admPendingIp - d0.admPendingIp);
        CHECK(hs && CONN(410) && !CONN(411) && d1.admPendingIp - d0.admPendingIp == 1, m);
        // гонка «сторож отверг ↔ первый приём» (найдена при сборке sec2b, стенд Д1): ClientHello, пришедший соединению, которое сторож уже
        //   отверг и разорвал (порция была в пути), не разбирается — ServerAccept не выполняется, пара ECDH не тратится, −1
        AccelStats a0{}; GetAccelStats(&a0);
        const LONG h0 = g_hello;
        const int rcDead = SendHello(411);
        AccelStats a1{}; GetAccelStats(&a1);
        const AsdaWire::Counters d2 = Cnt();
        sprintf(m, "ClientHello соединению, уже отвергнутому сторожем: RecvRoute %d, ServerHello +%ld, пар ECDH +%ld, приёмов на разорванном +%ld",
                rcDead, g_hello - h0, (a1.ephPool + a1.ephInline) - (a0.ephPool + a0.ephInline), d2.admDeadRecv - d1.admDeadRecv);
        CHECK(rcDead == -1 && g_hello == h0 && (a1.ephPool + a1.ephInline) == (a0.ephPool + a0.ephInline) && d2.admDeadRecv - d1.admDeadRecv == 1, m);
    }
    for (int s = 340; s < 450; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
    Sleep(60);
    // общий предел процесса по-прежнему действует и отличим в отчёте (режим 0): процесс 20, адрес 16
    {
        SetAdmB(0, 60000, 20, 5000, 0, 16);
        const AsdaWire::Counters e0 = Cnt();
        const uint32_t D = Ip(192, 0, 2, 101), E = Ip(192, 0, 2, 102), G = Ip(192, 0, 2, 103);
        for (int i = 0; i < 17; ++i) { g_ip[460 + i] = D; AcceptSlot(460 + i); }   // 16 + 1 сверх предела адреса
        Sleep(120);
        const AsdaWire::FailInfo fa = g_lastAdm[64];
        for (int i = 0; i < 4; ++i) { g_ip[480 + i] = E; AcceptSlot(480 + i); }    // процесс: 16 + 4 = 20
        Sleep(120);
        g_ip[490] = G; AcceptSlot(490);                                              // 21-е на процесс
        Sleep(120);
        const AsdaWire::Counters e1 = Cnt();
        const AsdaWire::FailInfo fp = g_lastAdm[64];
        int openD = 0; for (int i = 0; i < 17; ++i) { if (CONN(460 + i)) { ++openD; } }
        int openE = 0; for (int i = 0; i < 4; ++i) { if (CONN(480 + i)) { ++openE; } }
        sprintf(m, "процесс 20 / адрес 16: с D открыто %d из 17 (отказ: режим %d, счёт %d, предел %d), с E %d из 4, 21-е с G %s (режим %d, счёт %d, предел %d); "
                   "отказов 64 +%ld, из них «с адреса» +%ld; незавершённых %ld",
                openD, fa.mode, fa.count, fa.limit, openE, CONN(490) ? "ДОПУЩЕНО" : "отвергнуто", fp.mode, fp.count, fp.limit,
                e1.admPending - e0.admPending, e1.admPendingIp - e0.admPendingIp, e1.hsPending - e0.hsPending);
        CHECK(openD == 16 && fa.mode == 1 && fa.count == 17 && fa.limit == 16 && openE == 4 && !CONN(490) && fp.mode == 0 && fp.count == 21 && fp.limit == 20
              && e1.admPending - e0.admPending == 2 && e1.admPendingIp - e0.admPendingIp == 1 && e1.hsPending - e0.hsPending == 20, m);
        for (int s = 460; s <= 490; ++s) { CloseSlot(s); AsdaWire::SlotFailed(s); }
        Sleep(60);
    }
    sprintf(m, "все закрыты: незавершённых %ld (до Н-1 %ld)", Cnt().hsPending, c0.hsPending);
    CHECK(Cnt().hsPending == c0.hsPending, m);
    AsdaWire::SetAllowLegacy(true);
    AsdaWire::SetAdmission(nullptr, nullptr);
}

// Н-6: общий счёт очередей = учтённая память кадров (TxFrameCost), сверка с реальной кучей процесса; после закрытия всех — 0.
static long long HeapBusy()
{
    HANDLE h = GetProcessHeap();
    long long b = 0;
    if (!HeapLock(h)) { return -1; }
    PROCESS_HEAP_ENTRY e{};
    while (HeapWalk(h, &e)) { if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY) { b += (long long)e.cbData + e.cbOverhead; } }
    HeapUnlock(h);
    return b;
}
static void FillStock(int slot)          // досылка стока «в полёте» и почти полна — каждый кадр ≥ 12 б встаёт в очередь моста
{
    EnterCriticalSection(&g_ci.L); FLY(slot) = 1; PEND(slot) = 0x9F90; LeaveCriticalSection(&g_ci.L);
}
static void SecN6()
{
    char m[900];
    printf("-- Н-6: общий счёт очередей моста — реальная память кадров (TxFrameCost), а не байты кадров --\n");
    AsdaWire::SetTxQueueTotalMax(64 * 1024 * 1024);
    AsdaWire::SetTxQueueMax(16 * 1024 * 1024);              // 3000 наибольших кадров (12 МБ) — в пределе слота
    const AsdaWire::Counters c0 = Cnt();
    // а) кадры разных длин (открытый текст 9…4068 → кадр +28): общий счётчик = Σ TxFrameCost, очередь слота — Σ байт
    const int s = 250;
    if (!Open(s)) { CHECK(false, "Н-6: рукопожатие"); return; }
    g_sock[s].reading = false;
    Sleep(100);
    FillStock(s);
    static const int kLens[] = { 9, 15, 40, 100, 220, 228, 229, 484, 485, 996, 997, 2000, 2020, 2021, 4000, 4067, 4068 };
    long long sumBytes = 0, sumCost = 0; int acc = 0, sent = 0;
    uint32_t seq = 0;
    for (int rep = 0; rep < 20; ++rep)
        for (int L : kLens)
        {
            const auto f = Pkt(0x1200, (size_t)L, 1, seq++);
            const int sealed = (int)f.size() + (int)kFrameOverhead;
            ++sent;
            if (AsdaWire::SendRoute(&g_ci, s, f.data(), (int)f.size()) == 1) { ++acc; sumBytes += sealed; sumCost += AsdaWire::TxFrameCost(sealed); }
        }
    const AsdaWire::Counters c1 = Cnt();
    sprintf(m, "кадров %d (принято %d), Σ байт кадров %lld, Σ TxFrameCost %lld (×%.2f); общий счётчик %ld (+%ld), учтённая память слотов %ld, очередь слота txNow %ld б",
            sent, acc, sumBytes, sumCost, sumBytes ? (double)sumCost / sumBytes : 0.0, c1.txTotal, c1.txTotal - c0.txTotal, c1.txCostNow, c1.txNow);
    CHECK(acc == sent && c1.txTotal - c0.txTotal == sumCost && c1.txCostNow == c1.txTotal && c1.txNow - c0.txNow == sumBytes && sumCost > sumBytes, m);
    CloseSlot(s); AsdaWire::SlotFailed(s); g_sock[s].reading = true;
    // б) сверка с кучей процесса (HeapWalk): 3000 кадров одной длины в очередь — прирост занятой памяти кучи > Σ байт (учёт по байтам
    //    занижал память очереди) и ≤ Σ TxFrameCost. Длины: мелкий частый кадр, середины корзин, наибольший кадр (4096 б — выделение
    //    MSVC «большого блока»).
    static const int kHeapLens[] = { 15, 100, 485, 1000, 2000, 4040, 4068 };
    bool allOk = true;
    for (int L : kHeapLens)
    {
        const int hs = 251;
        if (!Open(hs)) { CHECK(false, "Н-6б: рукопожатие"); return; }
        g_sock[hs].reading = false;
        Sleep(100);
        FillStock(hs);
        std::vector<std::vector<uint8_t>> frames; frames.reserve(3000);
        for (int i = 0; i < 3000; ++i) { frames.push_back(Pkt(0x1300, (size_t)L, 2, (uint32_t)i)); }
        const int sealed = L + (int)kFrameOverhead;
        const long long h0 = HeapBusy();
        const AsdaWire::Counters b0 = Cnt();
        int okN = 0;
        for (int i = 0; i < 3000; ++i) { if (AsdaWire::SendRoute(&g_ci, hs, frames[i].data(), (int)frames[i].size()) == 1) { ++okN; } }
        const long long h1 = HeapBusy();
        const AsdaWire::Counters b1 = Cnt();
        const long long dHeap = h1 - h0, cost = (long long)okN * AsdaWire::TxFrameCost(sealed), bytes = (long long)okN * sealed;
        const bool ok = okN == 3000 && b1.txTotal - b0.txTotal == cost && dHeap > bytes && dHeap <= cost;
        if (!ok) { allOk = false; }
        printf("    кадр %4d б: принято %d, прирост кучи %lld б (%.1f на кадр), учтено %lld (%ld на кадр), байт кадров %lld — %s\n",
               sealed, okN, dHeap, dHeap / 3000.0, cost, AsdaWire::TxFrameCost(sealed), bytes, ok ? "учёт ≥ реальной памяти" : "НЕ СХОДИТСЯ");
        CloseSlot(hs); AsdaWire::SlotFailed(hs); g_sock[hs].reading = true;
    }
    CHECK(allOk, "реальная память очереди (куча процесса) по 7 длинам кадра: больше байт кадров и не больше учтённой (TxFrameCost)");
    // в) общий предел — по учтённой памяти: один слот шлёт мелкие кадры (43 б) при пределе 64 КБ — принято ⌊предел / TxFrameCost(43)⌋, далее причина 4
    {
        const LONG cap = 64 * 1024, cost43 = AsdaWire::TxFrameCost(43);
        AsdaWire::SetTxQueueTotalMax(cap);
        const int cs = 252;
        if (!Open(cs)) { CHECK(false, "Н-6в: рукопожатие"); return; }
        g_sock[cs].reading = false;
        Sleep(100);
        FillStock(cs);
        const LONG r4 = g_rep61Reason[4];
        int accN = 0;
        for (int i = 0; i < 4000; ++i) { const auto f = Pkt(0x1400, 15, 3, (uint32_t)i); if (AsdaWire::SendRoute(&g_ci, cs, f.data(), (int)f.size()) == 1) { ++accN; } else { break; } }
        Sleep(200);
        const AsdaWire::Counters g1 = Cnt();
        sprintf(m, "предел %ld, кадр 43 б (учтено %ld): принято %d (ожидается %ld; по байтам было бы %ld), причина 4 +%ld, соединение %s, txTotalPeak %ld",
                cap, cost43, accN, cap / cost43, cap / 43, g_rep61Reason[4] - r4, CONN(cs) ? "открыто" : "закрыто", g1.txTotalPeak);
        CHECK(accN == cap / cost43 && g_rep61Reason[4] - r4 == 1 && !CONN(cs), m);
        AsdaWire::SlotFailed(cs); g_sock[cs].reading = true;
        AsdaWire::SetTxQueueTotalMax(64 * 1024 * 1024);
    }
    Sleep(100);
    const AsdaWire::Counters c9 = Cnt();
    sprintf(m, "после закрытия всех: общий счётчик %ld, учтённая память слотов %ld, Σ очередей %ld б, слотов с очередью %ld", c9.txTotal, c9.txCostNow, c9.txNow, c9.txActive);
    CHECK(c9.txTotal == 0 && c9.txCostNow == 0 && c9.txNow == 0 && c9.txActive == 0, m);
    AsdaWire::SetTxQueueMax(1024 * 1024);
}

// Н-2: жертва вытеснения — только если под её замком она всё ещё наибольшая/тяжёлая.
//   Детерминированная схема: жертва V — наибольшая очередь; нить A выталкивает её очередь (SendRoute через второй мок Ciocp g_ciR, где у V
//   есть место в досылке на 8 кадров) и останавливается на «воротах» стокового Send, держа cs V. Пока A стоит, честные лёгкие слоты S
//   переводят сумму через предел — сторож выбирает V (наибольшая) и ждёт cs V. Ворота открываются: A выталкивает 8 кадров V (остаётся 2),
//   отпускает cs; сторож под замком V видит, что она уже не наибольшая и ниже средней, — не рвёт (txEvictRetry), а вытесняет наибольшую
//   (один из W). Прежний код (без перепроверки) вытеснил бы V. Если сторож в момент ворот был не в EvictLargest (стоял в обходе слотов),
//   гонка не воспроизведена — попытка повторяется (до 5).
static MockCiocp g_ciR;
static const int kN2V = 260, kN2W0 = 261, kN2nW = 8, kN2S0 = 270, kN2nS = 8;
static DWORD WINAPI N2Drainer(LPVOID)
{
    const auto f = Pkt(0x7700, 2000, 77, 9999);
    return (DWORD)AsdaWire::SendRoute(&g_ciR, kN2V, f.data(), (int)f.size());
}
static int N2Attempt(int attempt, bool* exercised, char* m)
{
    const LONG F = AsdaWire::TxFrameCost(2028);                   // Pkt(…, 2000) → кадр шифрования 2028 б
    const LONG C = 96 * F;                                        // предел: 74F до ворот ≤ C; 106F на воротах ≤ 9/8·C; 98F после выталкивания > C
    AsdaWire::SetTxQueueTotalMax(C);
    AsdaWire::SetTxFairShare(0);                                  // «тяжёлый» — только по средней
    *exercised = false;
    const int all[] = { kN2V, kN2W0, kN2W0 + 1, kN2W0 + 2, kN2W0 + 3, kN2W0 + 4, kN2W0 + 5, kN2W0 + 6, kN2W0 + 7,
                        kN2S0, kN2S0 + 1, kN2S0 + 2, kN2S0 + 3, kN2S0 + 4, kN2S0 + 5, kN2S0 + 6, kN2S0 + 7 };
    for (int sl : all) { if (!Open(sl)) { sprintf(m, "Н-2 попытка %d: рукопожатие слота %d", attempt, sl); return -1; } g_sock[sl].reading = false; }
    Sleep(120);
    for (int sl : all) { FillStock(sl); }
    const AsdaWire::Counters c0 = Cnt();
    const LONG ev0 = c0.txEvicted, rt0 = c0.txEvictRetry, r4 = g_rep61Reason[4], r6 = g_rep61Reason[6];
    LONG killed0[17]; for (int i = 0; i < 17; ++i) { killed0[i] = g_slotKilled[all[i]]; }
    uint32_t seq = 0;
    for (int j = 0; j < 9; ++j) { const auto f = Pkt(0x7000, 2000, 1, seq++); AsdaWire::SendRoute(&g_ci, kN2V, f.data(), (int)f.size()); }
    for (int w = 0; w < kN2nW; ++w)
        for (int j = 0; j < 8; ++j) { const auto f = Pkt(0x7100, 2000, 2, seq++); AsdaWire::SendRoute(&g_ci, kN2W0 + w, f.data(), (int)f.size()); }
    const AsdaWire::Counters c1 = Cnt();
    // второй мок: у V досылка «в полёте», места на 8 кадров по 2028 б (23000 + 8·2028 < 0x9F9C ≤ 23000 + 9·2028)
    uint8_t* vs = g_ciR.sess + (size_t)kN2V * kStride;
    EnterCriticalSection(&g_ciR.L);
    memset(vs, 0, kStride);
    *(volatile LONG*)(vs + kConn) = 1;
    *(volatile uint8_t*)(vs + kFly) = 1;
    *(volatile LONG*)(vs + kPend) = 23000;
    LeaveCriticalSection(&g_ciR.L);
    ResetEvent(g_gateHit); ResetEvent(g_gateGo);
    g_gateCi = &g_ciR; InterlockedExchange(&g_gateSlot, kN2V);
    HANDLE ta = CreateThread(nullptr, 0, &N2Drainer, nullptr, 0, nullptr);
    const bool hit = WaitForSingleObject(g_gateHit, 3000) == WAIT_OBJECT_0;
    int sAcc = 0;
    if (hit)
    {
        for (int r = 0; r < 4; ++r)                               // честные лёгкие: по кадру каждому S за круг — сумма через предел
            for (int i = 0; i < kN2nS; ++i) { const auto f = Pkt(0x7200, 2000, 3, seq++); if (AsdaWire::SendRoute(&g_ci, kN2S0 + i, f.data(), (int)f.size()) == 1) { ++sAcc; } }
    }
    const AsdaWire::Counters c2 = Cnt();
    Sleep(300);                                                   // сторож: EvictLargest выбрал V и ждёт её cs
    InterlockedExchange(&g_gateSlot, -1);
    SetEvent(g_gateGo);
    const bool aDone = WaitForSingleObject(ta, 5000) == WAIT_OBJECT_0;
    DWORD aRc = 0; GetExitCodeThread(ta, &aRc); CloseHandle(ta);
    Sleep(300);
    const AsdaWire::Counters c3 = Cnt();
    int wKilled = 0, wReason6 = 0;
    for (int w = 0; w < kN2nW; ++w)
    {
        const int sl = kN2W0 + w;
        if (g_slotKilled[sl] != killed0[1 + w]) { ++wKilled; if (g_repSlotReason[sl] == AsdaWire::kSendFailTotalEvict) { ++wReason6; } }
    }
    int sKilled = 0; for (int i = 0; i < kN2nS; ++i) { if (g_slotKilled[kN2S0 + i] != killed0[9 + i]) { ++sKilled; } }
    const bool vKilled = g_slotKilled[kN2V] != killed0[0];
    *exercised = c3.txEvictRetry - rt0 >= 1;
    sprintf(m, "попытка %d: кадр учтён %ld, предел %ld; до ворот общий %ld (V 9 + W 8×8 кадров), ворота %s, лёгких принято %d из 32, общий на воротах %ld "
               "(потолок %ld); нить A %s (возврат %lu); после: повторных выборов жертвы +%ld, вытеснено +%ld (причина 6 +%ld, причина 4 +%ld); V %s, "
               "W разорвано %d (причина 6 у %d), S разорвано %d; общий %ld (предел %ld)",
            attempt, F, C, c1.txTotal, hit ? "достигнуты" : "НЕ ДОСТИГНУТЫ", sAcc, c2.txTotal, C + C / 8, aDone ? "завершилась" : "ЗАВИСЛА", aRc,
            c3.txEvictRetry - rt0, c3.txEvicted - ev0, g_rep61Reason[6] - r6, g_rep61Reason[4] - r4, vKilled ? "РАЗОРВАНА" : "жива",
            wKilled, wReason6, sKilled, c3.txTotal, C);
    const bool pass = hit && aDone && aRc == 1 && sAcc == 32 && c1.txTotal == 73 * F && c2.txTotal == 106 * F && !vKilled && wKilled == 1 && wReason6 == 1
                      && sKilled == 0 && c3.txEvicted - ev0 == 1 && g_rep61Reason[4] == r4 && c3.txTotal <= C && c3.txEvictRetry - rt0 == 1;
    for (int sl : all) { g_sock[sl].reading = true; CloseSlot(sl); AsdaWire::SlotFailed(sl); }
    EnterCriticalSection(&g_ciR.L); memset(vs, 0, kStride); LeaveCriticalSection(&g_ciR.L);
    Sleep(100);
    AsdaWire::SetTxQueueTotalMax(64 * 1024 * 1024);
    AsdaWire::SetTxFairShare(256 * 1024);
    return pass ? 1 : 0;
}
static void SecN2()
{
    char m[1400];
    printf("-- Н-2: вытеснение — жертва перепроверяется под её замком (выталкивание успело опустошить очередь — рвётся настоящая наибольшая) --\n");
    InitializeCriticalSection(&g_ciR.L);
    g_ciR.sess = (uint8_t*)calloc(AsdaWire::kMaxSlots, kStride);
    g_gateHit = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_gateGo  = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    int res = 0; bool ex = false; int tries = 0;
    for (int a = 1; a <= 5; ++a)
    {
        ++tries;
        res = N2Attempt(a, &ex, m);
        printf("    %s\n", m);
        if (res < 0 || ex) { break; }
    }
    sprintf(m, "гонка «выбор жертвы ↔ выталкивание» воспроизведена (попыток %d): жертва, опустошённая под замком, не вытеснена, вытеснена одна настоящая "
               "наибольшая (причина 6), честные лёгкие не задеты, сумма ≤ предела", tries);
    CHECK(res == 1 && ex, m);
    const AsdaWire::Counters c9 = Cnt();
    sprintf(m, "после закрытия всех: общий счётчик %ld, учтённая память слотов %ld, Σ очередей %ld б, слотов с очередью %ld", c9.txTotal, c9.txCostNow, c9.txNow, c9.txActive);
    CHECK(c9.txTotal == 0 && c9.txCostNow == 0 && c9.txNow == 0 && c9.txActive == 0, m);
}

// Гонка «разрыв ↔ приём под замком слота» (найдена при сборке sec2b): порция приёма прошла проверку флага соединения, ждёт cs слота;
//   в это время соединение разорвано (DisConnect → флаг 0, запрос сброса). Войдя в cs, приём применяет сброс — слот «чистый», и без
//   проверки под замком ClientHello разобрался бы на мёртвом слоте (ServerAccept, пара ECDH). Детерминированно: cs слота держит нить A
//   на «воротах» стокового Send (второй мок Ciocp, как в Н-2), нить B зовёт RecvRoute(ClientHello) и ждёт cs, главный разрывает слот,
//   ворота открываются.
static const int kDrSlot = 290;
static DWORD WINAPI DrHolder(LPVOID)
{
    const auto f = Pkt(0x7800, 2000, 88, 1);
    return (DWORD)AsdaWire::SendRoute(&g_ciR, kDrSlot, f.data(), (int)f.size());
}
static volatile LONG g_drRc = 7;
static DWORD WINAPI DrReceiver(LPVOID)
{
    ClientChannel c; std::vector<uint8_t> h; c.Start(SubServer::Game, g_pub, h);
    const uint8_t* o = nullptr;
    InterlockedExchange(&g_drRc, AsdaWire::RecvRoute(&g_ci, kDrSlot, h.data(), (int)h.size(), &o));
    return 0;
}
static void SecDeadRecvInCs()
{
    char m[700];
    printf("-- Гонка «разрыв ↔ приём под замком слота»: ClientHello ждал cs, слот разорван — байты не разбираются --\n");
    SetAdmB(0, 60000, 0, 600000, 0, 0);                       // допуск включён (срок 10 мин — не мешает)
    AsdaWire::SetAllowLegacy(true);
    if (!Open(kDrSlot)) { CHECK(false, "гонка в cs: рукопожатие"); return; }
    g_sock[kDrSlot].reading = false;
    Sleep(100);
    FillStock(kDrSlot);
    { const auto f = Pkt(0x7801, 2000, 88, 0); AsdaWire::SendRoute(&g_ci, kDrSlot, f.data(), (int)f.size()); }   // кадр в очередь моста
    uint8_t* vs = g_ciR.sess + (size_t)kDrSlot * kStride;
    EnterCriticalSection(&g_ciR.L); memset(vs, 0, kStride); *(volatile LONG*)(vs + kConn) = 1; *(volatile uint8_t*)(vs + kFly) = 1;
    *(volatile LONG*)(vs + kPend) = 1000; LeaveCriticalSection(&g_ciR.L);
    ResetEvent(g_gateHit); ResetEvent(g_gateGo);
    g_gateCi = &g_ciR; InterlockedExchange(&g_gateSlot, kDrSlot);
    HANDLE ta = CreateThread(nullptr, 0, &DrHolder, nullptr, 0, nullptr);
    const bool hit = WaitForSingleObject(g_gateHit, 3000) == WAIT_OBJECT_0;   // A держит cs слота
    AccelStats a0{}; GetAccelStats(&a0);
    const AsdaWire::Counters c0 = Cnt();
    const LONG h0 = g_hello, r56 = g_repKind[56], r57 = g_repKind[57];
    InterlockedExchange(&g_drRc, 7);
    HANDLE tb = CreateThread(nullptr, 0, &DrReceiver, nullptr, 0, nullptr);
    Sleep(150);                                                // B прошёл проверку флага (соединение ещё открыто) и ждёт cs
    const bool bWaiting = WaitForSingleObject(tb, 0) == WAIT_TIMEOUT;
    MockKill(&g_ci, kDrSlot);                                  // разрыв: флаг 0, запрос сброса
    InterlockedExchange(&g_gateSlot, -1);
    SetEvent(g_gateGo);
    const bool aDone = WaitForSingleObject(ta, 5000) == WAIT_OBJECT_0;
    const bool bDone = WaitForSingleObject(tb, 5000) == WAIT_OBJECT_0;
    CloseHandle(ta); CloseHandle(tb);
    AccelStats a1{}; GetAccelStats(&a1);
    const AsdaWire::Counters c1 = Cnt();
    sprintf(m, "ворота %s, приём ждал cs: %s; после разрыва и открытия ворот: RecvRoute %ld, пар ECDH +%ld, ServerHello +%ld, нарушений канала 56/57 +%ld/+%ld, "
               "приёмов на разорванном +%ld; нити %s",
            hit ? "достигнуты" : "НЕ ДОСТИГНУТЫ", bWaiting ? "да" : "НЕТ", (long)g_drRc, (a1.ephPool + a1.ephInline) - (a0.ephPool + a0.ephInline),
            g_hello - h0, g_repKind[56] - r56, g_repKind[57] - r57, c1.admDeadRecv - c0.admDeadRecv, aDone && bDone ? "завершились" : "ЗАВИСЛИ");
    CHECK(hit && bWaiting && aDone && bDone && g_drRc == -1 && (a1.ephPool + a1.ephInline) == (a0.ephPool + a0.ephInline) && g_hello == h0
          && g_repKind[56] == r56 && g_repKind[57] == r57 && c1.admDeadRecv - c0.admDeadRecv == 1, m);
    g_sock[kDrSlot].reading = true;
    AsdaWire::SlotFailed(kDrSlot);
    EnterCriticalSection(&g_ciR.L); memset(vs, 0, kStride); LeaveCriticalSection(&g_ciR.L);
    AsdaWire::SetAdmission(nullptr, nullptr);
    Sleep(100);
    const AsdaWire::Counters c9 = Cnt();
    sprintf(m, "после: общий счётчик очередей %ld, учтённая память %ld, незавершённых %ld", c9.txTotal, c9.txCostNow, c9.hsPending);
    CHECK(c9.txTotal == 0 && c9.txCostNow == 0 && c9.hsPending == 0, m);
}
#endif

int main()
{
    SetConsoleOutputCP(CP_UTF8);
#ifdef STAND_OLD_BRIDGE
    printf("== stand_sec2: мост fix2e (ДО правок Е-1/Е-2) — дефекты должны воспроизвестись ==\n");
#else
    printf("== stand_sec2: мост sec2 — Е-1, Е-2, ускорение рукопожатия, допуск подключений (виды 63–65) ==\n");
#endif
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }
    InitializeCriticalSection(&g_ci.L); InitializeCriticalSection(&g_kmx); InitializeCriticalSection(&g_hsLk); InitializeCriticalSection(&g_repLk);
    g_ci.sess = (uint8_t*)calloc(AsdaWire::kMaxSlots, kStride);
    g_sock = new Sock[AsdaWire::kMaxSlots];
    g_complEv = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    GenerateLongTermKey(g_priv);
    wchar_t kp[MAX_PATH]; { wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t); _snwprintf(kp, MAX_PATH, L"%sstand_sec2_%lu.key", t, GetCurrentProcessId()); }
    SavePrivateKeyFile(kp, g_priv); memcpy(g_pub.xy, g_priv.xy, kPubLen);
    AsdaWire::SetFailureHooks(&MockKill, &MockReport, nullptr, true);
    AsdaWire::StockSendLayout lay{ (uint32_t)offsetof(MockCiocp, L), (uint32_t)offsetof(MockCiocp, sess), kStride, kConn, kFly, kPend, kLimit, kDirect };
    AsdaWire::SetStockSendLayout(&lay);
    AsdaWire::SetTxQueueMax(1024 * 1024);
#ifdef ASDAWIRE_HAS_SEC2
    // Д0: молчащие соединения, принятые ДО первого обращения к мосту (таблицы слотов ещё нет), — тоже в допуск и под срок.
    AsdaWire::AdmissionCfg c0{ 0, 2000, 0, 300, 0 };
    AsdaWire::SetAdmission(&c0, &MockPeerIp);
    g_ip[500] = Ip(10, 9, 0, 1); AcceptSlot(500);
    g_ip[501] = Ip(10, 9, 0, 2); AcceptSlot(501);
    AsdaWire::Init(SubServer::Game, kp, /*allowLegacy=*/false, &MockStockSend);
#else
    AsdaWire::Init(SubServer::Game, kp, true, &MockStockSend);
#endif
    DeleteFileW(kp);                                           // ключ уже в памяти моста
    HANDLE io = CreateThread(nullptr, 0, &IoWorker, nullptr, 0, nullptr);
    HANDLE rd = CreateThread(nullptr, 0, &Reader, nullptr, 0, nullptr);
#ifdef ASDAWIRE_HAS_SEC2
    {
        printf("-- Д0: 2 молчащих соединения приняты до построения таблицы слотов (первое обращение к мосту) — срок 300 мс, AllowLegacy=0 --\n");
        const AsdaWire::Counters a = Cnt();
        Sleep(600);
        const AsdaWire::Counters b = Cnt();
        char m[300];
        sprintf(m, "сразу после Init: незавершённых %ld; через 600 мс — соединения %s/%s, по сроку %ld, незавершённых %ld",
                a.hsPending, CONN(500) ? "открыто" : "закрыто", CONN(501) ? "открыто" : "закрыто", b.admDeadline, b.hsPending);
        CHECK(a.hsPending == 2 && !CONN(500) && !CONN(501) && b.admDeadline == 2 && b.hsPending == 0, m);
        AsdaWire::SlotFailed(500); AsdaWire::SlotFailed(501);
        AsdaWire::SetAdmission(nullptr, nullptr);
        AsdaWire::SetAllowLegacy(true);
    }
#endif

    E1();
    E2();
#ifdef ASDAWIRE_HAS_SEC2
    HX();
    AdmissionTests();
#endif
#ifdef ASDAWIRE_HAS_SEC2B
    SecC1();
    SecN1();
    SecN6();
    SecN2();
    SecDeadRecvInCs();
#endif

    g_stop = true; WaitForSingleObject(io, 2000); WaitForSingleObject(rd, 2000);
#ifdef STAND_OLD_BRIDGE
    printf(g_fail ? "\n== мост fix2e: дефектов воспроизведено %d (Е-1/Е-2) ==\n" : "\n== мост fix2e: не воспроизведено ==\n", g_fail);
#else
    printf(g_fail == 0 ? "\n== ВСЁ СОШЛОСЬ (провалов: 0) ==\n" : "\n== ПРОВАЛОВ: %d ==\n", g_fail);
#endif
    return g_fail == 0 ? 0 : 1;
}
