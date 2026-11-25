// Copyright (c) 2026 @sitxovski (Discord)
// AsdaServerBridge.cpp — реализация моста (см. AsdaServerBridge.h).
//
// ★ fix2 (2026-10-13, ревизия INTEG3 Б-1/Б-2) — ПОРЯДОК ЗАМКОВ ВЕЗДЕ «замок слота cs_X → замок Ciocp L»:
//   • Б-1: ResetSlot (детур SetConnectFlag, зовётся ПОД L из DisConnect/accept/ошибки WriteFile) замок слота НЕ берёт —
//     только InterlockedIncrement(resetReq). Сброс применяется под cs_X на входе в каждую функцию, работающую со слотом
//     (RecvRoute/OnRecv, SendRoute, SlotFailed, SlotMode) — ApplyResetLocked. Обратного ребра L → cs_X больше нет.
//   • Б-2: SendRoute шифрует И вызывает стоковый Ciocp::Send одним куском под cs_X: порядок номеров кадров на проводе =
//     порядок шифрования; скретч s.sealed за пределы замка не выходит.
// ★ fix2d (2026-10-14, хвост ревизии FIX2 «переполнение досылки стока», П-1/П-2): Secure-кадр отдаётся стоковому Send только
//   под замком Ciocp L после проверки досылки слота (StockSendSecure); не вмещается — в очередь слота моста txQ (порядок номеров
//   сохраняется, выталкивает сторож / следующий кадр). Отказ стокового Send, переполнение очереди (TxQueueKB) или потеря кадра
//   стоком — слот в сбой вида 61, отчёт, разрыв сторожем (RunTxKill, поколение слота). Legacy — как сток.
// ★ fix2e (2026-10-14, ревизия fix2d Ф-1): ОБЩИЙ предел очередей моста на процесс (TxQueueTotalMB, умолчание 64 МБ) — счётчик
//   g_txTotal (Interlocked): место резервируется ДО выделения памяти под кадр, отдаётся при выталкивании (TxDrainLocked), сбросе и
//   разрыве (TxFreeLocked — единственная точка обнуления txBytes слота). Превышение — П-2 этому слоту, причина 4. Выделение памяти
//   на путях моста (очередь слота, буферы шифрования, очередь до рукопожатия, буферы приёма канала) — под try/catch ВНУТРИ замка
//   слота: std::bad_alloc / std::exception → П-2 причина 5, исключение наружу (naked-трамплин, сток) не выходит. Ловятся только
//   C++-исключения (catch по типу): DLL собраны с /EHa, но SEH (например, сбой внутри стокового Send под L) не перехватывается —
//   как и раньше. Под замком Ciocp L мост память не выделяет (StockSendSecure/KillIfSameGen).
#include "AsdaServerBridge.h"
#include <windows.h>
#include <vector>
#include <deque>
#include <cstring>
#include <cwchar>
#include <new>

using namespace AsdaSecure;

namespace
{
    struct Slot
    {
        ServerChannel        chan;
        std::vector<uint8_t> toParser;    // расшифрованный старый поток (возврат RecvRoute; читает только поток приёма слота)
        std::vector<uint8_t> toSocket;    // ServerHello / очередь исходящего (уходит сразу, под cs)
        std::vector<uint8_t> sealed;      // шифротекст (только под cs, внутри SendRoute)
        CRITICAL_SECTION     cs;
        volatile LONG        resetReq;    // ★ fix2: запросы сброса (ResetSlot под замком Ciocp — без cs, Interlocked)
        LONG                 resetSeen;   // ★ fix2: последний применённый запрос (только под cs)
        bool                 failed;
        bool                 identitySet;
        bool                 reported;    // ★ В7d: отчёт о нарушении уже сделан (одна строка на соединение)
        AsdaWire::FailInfo   fail;        // ★ В7d: сведения о первой фатальной ошибке слота
        // ★ fix2b (кадры сервера ДО рукопожатия: отказы LM 4101/2253, GS 6004 «сервер переполнен» сразу после accept)
        std::vector<uint8_t> preQ;        // старые кадры, отправленные сервером, пока режим канала не известен (только под cs)
        volatile LONG        preBytes;    // = preQ.size(); читается БЕЗ замка воротами DisConnect (под замком Ciocp)
        volatile LONG        closing;     // DisConnect отложен: новые кадры не принимаются (сток при флаге 0 их роняет)
        volatile LONG        deferKill;   // 1 — DisConnect отложен до выдачи очереди (владелец разрыва — кто снимет 1→0)
        volatile LONG        deferTick;   // когда отложен (GetTickCount, 0 → 1)
        void* volatile       deferThis;   // this Ciocp отложенного DisConnect
        volatile LONG        deferGen;    // ★ fix2c (Н-3): resetReq на момент откладывания — разрыв не трогает следующее соединение
        volatile LONG        flushTick;   // ★ fix2c (Н-2): когда очередь выдана (0 — ещё нет); разрыв не раньше LingerMs после
        // ★ fix2d (П-1): очередь УЖЕ ЗАШИФРОВАННЫХ кадров Secure-слота (каждый ≤ 0x1000 — один вызов стокового Send), которые
        //   стоковая досылка не вмещала. Порядок = порядок номеров кадров; пока непуста — каждый новый кадр в её хвост. Только под cs.
        std::deque<std::vector<uint8_t>> txQ;
        volatile LONG        txBytes;     // сумма длин txQ (читается сторожем без замка — только как признак «есть работа»)
        // ★ fix2d (П-2): разрыв по сбою доставки выполняет сторож (из пути отправки DisConnect не зовём: чужие замки вызывающего).
        volatile LONG        txKill;      // 1 — разрыв назначен (владелец — кто снимет 1→0)
        void* volatile       txThis;      // this Ciocp для разрыва
        volatile LONG        txGen;       // resetReq на момент сбоя: слот с тех пор сброшен — сток уже закрыл, разрыв не нужен
    };

    Slot* volatile g_slots = nullptr;      // массив kMaxSlots; публикуется ПОСЛЕ построения всех слотов (живёт весь процесс)
    PrivateKey   g_key{};
    bool         g_hasKey   = false;
    bool         g_cngOk    = false;
    SubServer    g_sub      = SubServer::Game;
    bool         g_allow    = true;
    AsdaWire::SendRawFn    g_sendRaw    = nullptr;
    AsdaWire::KillFn       g_kill       = nullptr;   // ★ В7d
    AsdaWire::ReportFn     g_report     = nullptr;   // ★ В7d
    AsdaWire::InitNotifyFn g_initNotify = nullptr;   // ★ В7d
    bool         g_killOnViolation = true;            // ★ В7d
    wchar_t      g_keyPath[260] = {};
    volatile LONG g_inited  = 0;           // 0 — не инициализирован, 1 — идёт, 2 — готов

    // ★ В7d: счётчики и ограничитель строк PatchLog. ★ fix2: + применённые сбросы, обход при сбое CNG.
    volatile LONG g_kills = 0, g_reports = 0, g_logSuppr = 0, g_sendFails = 0, g_resets = 0, g_bypass = 0;
    // ★ fix2b: кадры до рукопожатия и отложенный разрыв.
    volatile LONG g_connFlag[AsdaWire::kMaxSlots] = {};   // флаг соединения слота (= стоковый [slot+4], пишет детур SetConnectFlag)
    volatile LONG g_preMax      = 64 * 1024;   // PreHandshakeQueueKB: предел очереди слота до рукопожатия, байт (0 — не копить)
    volatile LONG g_deferMs     = 5000;        // PreHandshakeCloseMs: сколько ждать первых байт клиента при отложенном DisConnect (0 — не откладывать)
    uintptr_t     g_ioLo = 0, g_ioHi = 0;      // IoWorkerThread [lo, hi): DisConnect оттуда (сокет уже мёртв) не откладывается
    volatile LONG g_preQueued = 0, g_preFlushed = 0, g_preDropped = 0, g_deferred = 0, g_deferTimeouts = 0;
    volatile LONG g_watchdog = 0;              // 0 — нить сторожа не создана, 1 — создана
    // ★ fix2c (Н-2): пауза между выдачей отказа и разрывом. Сокеты стока закрываются аварийно (SO_LINGER {1,0} при accept:
    //   GS 0x567FC1…0x567FF1, LM 0x4188C1…0x4188F1) — RST догоняет данные; сток GS сам держит Sleep(100) между 6004 и киком.
    volatile LONG g_lingerMs    = 150;         // PreHandshakeLingerMs (0 — разрыв сразу после выдачи)
    volatile LONG g_deferStale = 0, g_overSend = 0;
    AsdaWire::SinkFn g_sink = nullptr;         // ★ fix2c: стоковый разборщик приёма (sub_563C20 / sub_415600)
    // ★ fix2d (П-1/П-2): раскладка стокового Send (nullptr — нет: стенды старого типа), предел очереди моста слота, счётчики.
    AsdaWire::StockSendLayout g_layout{};
    volatile LONG g_layoutSet  = 0;
    volatile LONG g_txMax      = 1024 * 1024;  // TxQueueKB
    volatile LONG g_txQueued = 0, g_txFlushed = 0, g_txPeak = 0, g_txRefused = 0, g_txOverflow = 0, g_txLost = 0;
    volatile LONG g_txKills = 0, g_txKillStale = 0, g_txDropped = 0;
    // ★ fix2e (Ф-1): общий объём очередей моста (Σ txBytes + резервы в процессе постановки), предел, наибольший принятый объём,
    //   сбоев причин 4/5.
    volatile LONG g_txTotal = 0;
    volatile LONG g_txTotalMax = 64 * 1024 * 1024;   // TxQueueTotalMB
    volatile LONG g_txTotalPeak = 0, g_txTotalOver = 0, g_txNoMem = 0;

    volatile LONG g_perMinute   = 30;      // строк PatchLog в минуту (0 — без ограничения)
    volatile LONG g_winStart    = 0;       // начало окна (GetTickCount; 0 — окна ещё не было)
    volatile LONG g_winCount    = 0;       // строк в окне
    volatile LONG g_pendingSup  = 0;       // подавлено с последней разрешённой строки

    void EnsureIdentity(Slot& s)
    {
        if (!s.identitySet)
        {
            s.chan.SetIdentity(g_sub, g_hasKey ? &g_key : nullptr);
            s.chan.SetAllowLegacy(g_allow);
            s.identitySet = true;
        }
    }

    // ★ fix2: применить отложенный запрос сброса (ТОЛЬКО под s.cs). Новый клиент на переиспользованном слоте не видит
    //   старых ключей/номеров: accept (SetConnectFlag(X,1)) ставит запрос ДО первого чтения сокета (0x563D1D раньше
    //   ReadFile 0x564ABA/0x564EB3; LM аналогично), а любое обращение к каналу начинается с этой функции.
    //   Буферы toParser/sealed не трогаем: toParser читает стоковый разборщик потока приёма после выхода из замка.
    // ── ★ fix2c (Н-1, ревизия FIX2): ПРЕДЕЛЫ БУФЕРОВ СТОКА ──
    //   Отправка: Ciocp::Send копирует данные в буфер перекрытой записи 0x1000 б (`0x5653B0(tag, ov+0x1C, 0x1000, src, n)`;
    //   при n > 0x1000 копии НЕТ — только строка лога, а WriteFile уходит с нулями и чтением за буфером). Поэтому один вызов
    //   стокового Send — не больше kStockSendMax байт: кадр шифрования [len4][seq8][ct][tag16] = открытый текст + 28 →
    //   открытого текста в кадре не больше kSealPlainMax = 0x1000 − 28 = 4068.
    //   Приём: сток читает сокет по 0x1000 (ReadFile 0x1000 — GS GameServer.c:138021, LM LoginManager.c:8180…8250) и разбирает
    //   порцию CopyToWriteBuffer (`0x5656D0`): обрывок заголовка (< 10 б) в начале буфера сборки слота 0x1000 б, к нему
    //   дописывается ВСЯ следующая порция (DesSize 0x1000) — порция ≤ 0x1000 − 9 = 4087 б всегда помещается. Расшифрованный
    //   поток моста отдаётся разборщику кусками не больше kStockSinkMax (кадр клиента может быть больше 4 КБ: очередь Flush).
    constexpr size_t kStockSendMax = 0x1000;
    constexpr size_t kSealPlainMax = kStockSendMax - kFrameOverhead;   // 4068
    constexpr size_t kStockSinkMax = 0x1000 - 9;                       // 4087
    static_assert(kSealPlainMax == 4068, "кадр шифрования: 4 + 8 + текст + 16 ≤ 0x1000");

    // Стоковый Send кусками ≤ kStockSendMax (сырые байты: ServerHello, Legacy). Под cs. Возврат: 1 — все приняты, 0 — нет.
    int SendRawChunked(void* self, int slot, const uint8_t* p, size_t n)
    {
        int rc = 1;
        for (size_t off = 0; off < n; )
        {
            const size_t k = (n - off) > kStockSendMax ? kStockSendMax : (n - off);
            if (!g_sendRaw || !g_sendRaw(self, slot, p + off, (int)k)) { rc = 0; }
            off += k;
        }
        return rc;
    }

    void EnsureWatchdog();   // ★ fix2d: нить сторожа (ниже, рядом с DeferWatch)

    // ── ★ fix2d (П-1/П-2): ДОСЫЛКА СТОКА ──────────────────────────────────────────────────────────────────────────────
    //   Стоковый Ciocp::Send (GS 0x561F20, LM 0x413AB0), пока предыдущая запись в полёте ([sess+8]==1), дописывает кадр в досылку
    //   (+0xB2, длина [sess+0xA0B2]); если досылка + кадр ≥ 0x9F9C — memset досылки, длина 0, [sess+8]=0, возврат 0
    //   (GS 0x56202B…0x5620A9, LM 0x413BBB…0x413C39). Стираются УЖЕ зашифрованные кадры — у Secure-клиента разрыв по Replay,
    //   сервер этого не видит. Бывает, когда клиент не читает сокет (загрузка карты OpenLevel на игровом потоке клиента), а сервер
    //   шлёт вход в мир и окружение (120–170 КБ). Мост такой кадр стоку НЕ отдаёт, а держит в своей очереди слота (txQ).
    enum StockRc { kStOk = 1, kStRefused, kStNoRoom, kStClosed, kStLost, kStStale };

    // Один вызов стокового Send для Secure-кадра (n ≤ 0x1000) с проверкой места ПОД замком Ciocp L. Под cs слота (порядок «слот → L»).
    //   L — тот же CRITICAL_SECTION, который Send/SendTemp берут первыми (GS RAII 0x568D50 → EnterCriticalSection(this+0x60D1830);
    //   SendTemp 0x562640 → тот же замок; LM 0x41A620), поэтому чтение полей и вызов Send — один захват L: IoWorker (SendTemp —
    //   единственный, кто уменьшает досылку, ResetSlot/DisConnect — флаг) между проверкой и Send вклиниться не может.
    int StockSendSecure(Slot& s, void* self, int slot, const uint8_t* p, int n, int* pendOut)
    {
        if (pendOut) { *pendOut = -1; }
        if (!g_sendRaw) { return kStRefused; }
        if (n > (int)kStockSendMax) { InterlockedIncrement(&g_overSend); }       // не должно случаться (кадр ≤ 4068 + 28)
        if (!g_layoutSet || !self)
        {
            // Раскладки нет (стенды старого типа): места не проверить; отказ при флаге соединения 0 — слот закрыт (сток роняет).
            if (g_sendRaw(self, slot, p, n)) { return kStOk; }
            return g_connFlag[slot] ? kStRefused : kStClosed;
        }
        const AsdaWire::StockSendLayout& L = g_layout;
        CRITICAL_SECTION* lk = (CRITICAL_SECTION*)((uint8_t*)self + L.lockOff);
        int rc;
        EnterCriticalSection(lk);
        if (InterlockedCompareExchange(&s.resetReq, 0, 0) != s.resetSeen)
        {
            rc = kStStale;      // слот сброшен после входа в cs (разрыв/accept под L) — кадр прошлой сессии не шлём
        }
        else
        {
            uint8_t* sess = *(uint8_t* const*)((uint8_t*)self + L.sessPtrOff) + (size_t)slot * L.sessStride;
            const LONG    conn = *(volatile LONG*)(sess + L.connOff);
            const uint8_t fl   = *(volatile uint8_t*)(sess + L.inFlightOff);
            const LONG    pend = *(volatile LONG*)(sess + L.pendingOff);
            if (pendOut) { *pendOut = (int)pend; }
            if (!conn)                                        { rc = kStClosed; }    // сток вернул бы 0 (0x561FCA / 0x413B5A)
            else if (pend + n >= L.pendingLimit)              { rc = kStNoRoom; }    // сток стёр бы досылку (0x56202B / 0x413BBB)
            else if (fl != 1 && pend > 0 && pend + n > L.directMax) { rc = kStLost; } // ветка 0x5621A3: досылка в буфер 0x1000 не влезет
            else
            {
                const int r = g_sendRaw(self, slot, p, n);    // стоковый Send: L повторно (рекурсивно), WriteFile перекрытый
                const uint8_t fl2 = *(volatile uint8_t*)(sess + L.inFlightOff);
                if (!r)                       { rc = kStRefused; }                   // ошибка WriteFile: сток уже DisConnect_NoLock
                else if (fl != 1 && fl2 != 1) { rc = kStLost; }                      // пул 0x5680A0/0x4199A0 пуст: возврат 1 без записи
                else                          { rc = kStOk; }
            }
        }
        LeaveCriticalSection(lk);
        return rc;
    }

    // Очередь слота выброшена: память — сразу, её объём — из общего счётчика (★ fix2e: единственная точка обнуления txBytes;
    //   txBytes и g_txTotal меняются только под cs слота — сумма не «утекает»). Исключений не бросает.
    void TxFreeLocked(Slot& s)
    {
        if (!s.txQ.empty())
        {
            try { std::deque<std::vector<uint8_t>>().swap(s.txQ); }          // память очереди — сразу (пустой deque не выделяет)
            catch (const std::exception&) { s.txQ.clear(); }                  // на всякий случай: clear() не выделяет
        }
        const LONG had = InterlockedExchange(&s.txBytes, 0);
        if (had) { InterlockedExchangeAdd(&g_txTotal, -had); }
    }

    // П-2: доставка Secure-кадра невозможна — слот в сбой (вид 61), очередь освобождена, разрыв назначен сторожу. Под cs.
    //   ★ fix2e: total — общий объём очередей ДО освобождения очереди слота; очередь до рукопожатия тоже отдаётся (иначе ворота
    //   DisConnect отложили бы разрыв до PreHandshakeCloseMs); phase — 0 приём / 1 отправка (сбой памяти бывает на обоих).
    void TxFailLocked(Slot& s, void* self, int reason, int pend, int phase = 1)
    {
        const int queued = (int)s.txBytes;
        const int total  = (int)InterlockedCompareExchange(&g_txTotal, 0, 0);
        TxFreeLocked(s);
        if (!s.preQ.empty() || s.preQ.capacity()) { std::vector<uint8_t>().swap(s.preQ); }   // не выделяет
        InterlockedExchange(&s.preBytes, 0);
        if (s.failed) { return; }
        s.failed = true;
        s.fail.err = Err::Ok; s.fail.mode = (int)s.chan.GetMode(); s.fail.phase = phase; s.fail.firstByte = -1;
        s.fail.bytes = queued; s.fail.kind = AsdaWire::kKindSendFail; s.fail.reason = reason; s.fail.queued = queued; s.fail.pending = pend;
        s.fail.total = total;
        InterlockedIncrement(reason == AsdaWire::kSendFailRefused   ? &g_txRefused
                           : reason == AsdaWire::kSendFailQueueMax  ? &g_txOverflow
                           : reason == AsdaWire::kSendFailTotalMax  ? &g_txTotalOver
                           : reason == AsdaWire::kSendFailNoMem     ? &g_txNoMem : &g_txLost);
        s.txThis = self;
        InterlockedExchange(&s.txGen, s.resetSeen);
        InterlockedExchange(&s.txKill, 1);
        EnsureWatchdog();
    }

    // Слот закрыт стоком / сброшен — очередь этой сессии не нужна. Под cs.
    void TxDropLocked(Slot& s)
    {
        if (s.txBytes > 0) { InterlockedIncrement(&g_txDropped); }
        TxFreeLocked(s);
    }

    // ★ fix2e: сбой выделения памяти в мосте (перехвачено под cs слота) — П-2 причина 5.
    void NoMemLocked(Slot& s, void* self, int phase) { TxFailLocked(s, self, AsdaWire::kSendFailNoMem, -1, phase); }

    bool TxPushLocked(Slot& s, void* self, const uint8_t* p, size_t n, int pend)
    {
        if ((LONGLONG)s.txBytes + (LONGLONG)n > (LONGLONG)g_txMax) { TxFailLocked(s, self, AsdaWire::kSendFailQueueMax, pend); return false; }
        // ★ fix2e (Ф-1): общий предел — резерв ДО выделения. Каждая принятая постановка проверяет сумму принятого и всех резервов
        //   в процессе, поэтому сумма ПРИНЯТЫХ кадров никогда не больше предела (одновременные резервы могут лишь отказать оба).
        const LONG totMax = g_txTotalMax;
        const LONG tot = InterlockedExchangeAdd(&g_txTotal, (LONG)n) + (LONG)n;
        if (totMax > 0 && tot > totMax)
        {
            InterlockedExchangeAdd(&g_txTotal, -(LONG)n);
            TxFailLocked(s, self, AsdaWire::kSendFailTotalMax, pend);
            return false;
        }
        try { s.txQ.emplace_back(p, p + n); }                              // deque::emplace_back — строгая гарантия: при отказе очередь цела
        catch (const std::exception&)
        {
            InterlockedExchangeAdd(&g_txTotal, -(LONG)n);
            TxFailLocked(s, self, AsdaWire::kSendFailNoMem, pend);
            return false;
        }
        s.txThis = self;                                                   // сторож выталкивает этим же this Ciocp
        const LONG b = InterlockedExchangeAdd(&s.txBytes, (LONG)n) + (LONG)n;
        InterlockedIncrement(&g_txQueued);
        for (LONG pk = g_txPeak; b > pk && InterlockedCompareExchange(&g_txPeak, b, pk) != pk; pk = g_txPeak) {}
        for (LONG pk = g_txTotalPeak; tot > pk && InterlockedCompareExchange(&g_txTotalPeak, tot, pk) != pk; pk = g_txTotalPeak) {}
        EnsureWatchdog();
        return true;
    }

    // Вытолкнуть очередь в стоковый Send, пока досылка принимает. Под cs. Возврат false — слот в сбое/закрыт.
    bool TxDrainLocked(Slot& s, void* self, int slot)
    {
        while (!s.txQ.empty())
        {
            std::vector<uint8_t>& f = s.txQ.front();
            int pend = -1;
            const int rc = StockSendSecure(s, self, slot, f.data(), (int)f.size(), &pend);
            if (rc == kStOk)
            {
                InterlockedExchangeAdd(&s.txBytes, -(LONG)f.size());
                InterlockedExchangeAdd(&g_txTotal, -(LONG)f.size());     // ★ fix2e
                s.txQ.pop_front();
                InterlockedIncrement(&g_txFlushed);
                continue;
            }
            if (rc == kStNoRoom) { return true; }
            if (rc == kStClosed || rc == kStStale) { TxDropLocked(s); return false; }
            TxFailLocked(s, self, rc == kStRefused ? AsdaWire::kSendFailRefused : AsdaWire::kSendFailLost, pend);
            return false;
        }
        TxFreeLocked(s);   // пуста — отдать память
        return true;
    }

    // Шифрованный кадр Secure-слота в провод ПО ПОРЯДКУ (под cs): очередь непуста — в хвост и выталкивание; иначе стоку; досылка
    //   не вмещает — в очередь (сторож вытолкнет). Возврат 1 — ушёл или в очереди; 0 — слот закрыт / сбой П-2.
    int SecureEmitLocked(Slot& s, void* self, int slot, const uint8_t* p, size_t n)
    {
        if (s.failed) { return 0; }
        if (!s.txQ.empty())
        {
            if (!TxPushLocked(s, self, p, n, -1)) { return 0; }
            return TxDrainLocked(s, self, slot) ? 1 : 0;
        }
        int pend = -1;
        const int rc = StockSendSecure(s, self, slot, p, (int)n, &pend);
        switch (rc)
        {
        case kStOk:      return 1;
        case kStNoRoom:  return TxPushLocked(s, self, p, n, pend) ? 1 : 0;
        case kStClosed:
        case kStStale:   TxDropLocked(s); return 0;
        case kStRefused: TxFailLocked(s, self, AsdaWire::kSendFailRefused, pend); return 0;
        default:         TxFailLocked(s, self, AsdaWire::kSendFailLost, pend); return 0;
        }
    }

    // Отправить открытый текст в ГОТОВЫЙ канал (под cs): Legacy — как есть кусками ≤ 4096 (поведение стока, без очереди);
    //   Secure — кусками ≤ 4068, каждый отдельным кадром шифрования и отдельным вызовом стокового Send (номера кадров по порядку;
    //   клиент собирает поток). ★ fix2d: Secure-кадр — через SecureEmitLocked (очередь моста при полной досылке, П-2 при отказе;
    //   после сбоя/закрытия остальные куски не шифруются и не шлются). *err — ошибка шифрования. Возврат — 1/0.
    int SendReadyChunked(Slot& s, void* self, int slot, const uint8_t* p, size_t n, Err* err)
    {
        *err = Err::Ok;
        if (s.chan.GetMode() == Mode::Legacy) { return SendRawChunked(self, slot, p, n); }
        for (size_t off = 0; off < n; )
        {
            const size_t k = (n - off) > kSealPlainMax ? kSealPlainMax : (n - off);
            const Err e = s.chan.OnSend(p + off, k, s.sealed);
            if (e != Err::Ok) { *err = e; return 0; }
            if (!SecureEmitLocked(s, self, slot, s.sealed.data(), s.sealed.size())) { return 0; }
            off += k;
        }
        return 1;
    }

    void ApplyResetLocked(Slot& s)
    {
        const LONG req = InterlockedCompareExchange(&s.resetReq, 0, 0);   // чтение с барьером
        if (req == s.resetSeen) { return; }
        s.chan.Reset();
        s.identitySet = false;
        EnsureIdentity(s);
        s.failed = false;
        s.reported = false;
        memset(&s.fail, 0, sizeof(s.fail));
        // ★ fix2b: очередь до рукопожатия и отложенный разрыв относятся к ПРОШЛОЙ сессии. Кадры новой сессии в очередь
        //   встают только при флаге соединения 1 (SendRoute), а ResetSlot(X,1) сперва ставит запрос сброса, затем флаг —
        //   значит, сброс accept применяется ДО постановки первого кадра нового соединения и его очередь не стирает.
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        InterlockedExchange(&s.closing, 0);
        InterlockedExchange(&s.deferKill, 0);
        InterlockedExchange(&s.flushTick, 0);
        // ★ fix2d: очередь шифрованных кадров и назначенный разрыв П-2 — тоже прошлой сессии (поколение слота, как Н-3): сток
        //   соединение уже закрыл (или слот занят новым клиентом) — кадры выбрасываются, память освобождается, разрыв снимается.
        TxDropLocked(s);
        if (InterlockedExchange(&s.txKill, 0) == 1) { InterlockedIncrement(&g_txKillStale); }
        s.resetSeen = req;
        InterlockedIncrement(&g_resets);
    }

    // ★ fix2b: выдать очередь до рукопожатия (под cs, сразу после ServerHello / первого байта Legacy-клиента).
    //   ★ fix2c (Н-1/Н-5): кусками в пределе стокового Send (Secure ≤ 4068 открытого текста на кадр, Legacy ≤ 4096).
    //   Ошибка шифрования — сбой сервера (фаза 1).
    Err FlushPreQueueLocked(Slot& s, void* self, int slot)
    {
        Err e = Err::Ok;
        SendReadyChunked(s, self, slot, s.preQ.data(), s.preQ.size(), &e);
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        if (e == Err::Ok)
        {
            InterlockedIncrement(&g_preFlushed);
            DWORD t = GetTickCount(); if (t == 0) { t = 1; }
            InterlockedExchange(&s.flushTick, (LONG)t);              // ★ fix2c (Н-2): от этого момента — пауза до разрыва
        }
        return e;
    }

    // Запомнить первую фатальную ошибку слота (под слотовым локом).
    void MarkFail(Slot& s, Err e, int phase, const void* data, int len)
    {
        if (s.failed) { return; }          // первая причина — главная; следующие не перетирают
        s.failed = true;
        s.fail.err       = e;
        s.fail.mode      = (int)s.chan.GetMode();
        s.fail.phase     = phase;
        s.fail.firstByte = (data && len > 0) ? ((const uint8_t*)data)[0] : -1;
        s.fail.bytes     = len;
        // Приём: любая ошибка вызвана присланными байтами (Cng на приёме = негодная точка ECDH в ClientHello) — вид 56..59;
        // отправка: сбой на стороне сервера — вид 0 (только PatchLog, не нарушение клиента).
        const int k = AsdaWire::KindForErr(e);
        s.fail.kind      = (phase == 0) ? (k ? k : AsdaWire::kKindHandshake) : 0;
    }

    // Разбор порции приёма под cs (общая часть OnRecv/RecvRoute). Возврат — длина расшифрованного (>0, *out) или 0.
    //   ServerHello/очередь исходящего уходят стоковым Send ЗДЕСЬ, под cs_X (порядок «cs_X → L»).
    int RecvLocked(Slot& s, void* ciocpThis, int slot, const void* in, int len, const uint8_t** out)
    {
        if (s.failed) { return 0; }        // ★ В7d: слот уже в ошибке (например, сбой шифрования на отправке)
        EnsureIdentity(s);
        Err e = s.chan.OnRecv((const uint8_t*)in, (size_t)len, s.toParser, s.toSocket);
        Err fe = Err::Ok;
        if (!s.toSocket.empty())
        {
            // ServerHello 148 б (★ fix2c: в пределе Send). ★ fix2d: Secure — тем же упорядоченным путём, что и шифрованные кадры
            //   (очередь моста при полной досылке; кадры до рукопожатия идут сразу за ним).
            if (s.chan.GetMode() == Mode::Secure)
            {
                for (size_t off = 0; off < s.toSocket.size(); )
                {
                    const size_t k = (s.toSocket.size() - off) > kStockSendMax ? kStockSendMax : (s.toSocket.size() - off);
                    if (!SecureEmitLocked(s, ciocpThis, slot, s.toSocket.data() + off, k)) { break; }
                    off += k;
                }
            }
            else
            {
                SendRawChunked(ciocpThis, slot, s.toSocket.data(), s.toSocket.size());
            }
        }
        if (e == Err::Ok && !s.preQ.empty() && s.chan.IsReady())
        {
            fe = FlushPreQueueLocked(s, ciocpThis, slot);   // ★ fix2b: кадры до рукопожатия — сразу за ServerHello / как есть (Legacy)
        }
        if (e != Err::Ok || fe != Err::Ok)
        {
            // BadTag/Replay/BadMagic/Format/… — вызывающий закроет слот; очередь до рукопожатия этой сессии больше не нужна
            if (e != Err::Ok) { MarkFail(s, e, /*phase=*/0, in, len); } else { MarkFail(s, fe, /*phase=*/1, in, len); }
            s.preQ.clear();
            InterlockedExchange(&s.preBytes, 0);
            return 0;
        }
        if (s.toParser.empty()) { return 0; }
        *out = s.toParser.data();
        return (int)s.toParser.size();
    }
}

namespace AsdaWire
{
    void Configure(SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw)
    {
        g_sub     = sub;
        g_allow   = allowLegacy;
        g_sendRaw = sendRaw;
        g_keyPath[0] = 0;
        if (keyPath)
        {
            int i = 0;
            for (; keyPath[i] && i < (int)(sizeof(g_keyPath) / sizeof(wchar_t)) - 1; ++i) { g_keyPath[i] = keyPath[i]; }
            g_keyPath[i] = 0;
        }
    }

    void SetFailureHooks(KillFn kill, ReportFn report, InitNotifyFn initNotify, bool killOnViolation)
    {
        g_kill            = kill;
        g_report          = report;
        g_initNotify      = initNotify;
        g_killOnViolation = killOnViolation;
    }

    bool EnsureInit()
    {
        // Фаза перехода 0→1 делает ровно один поток; остальные ждут завершения (busy-wait коротко).
        // ★ fix2: под замком Ciocp не зовётся (ResetSlot его больше не вызывает) — ожидание здесь не держит L.
        LONG prev = InterlockedCompareExchange(&g_inited, 1, 0);
        if (prev == 2) { return g_hasKey; }
        if (prev == 1)
        {
            while (g_inited == 1) { Sleep(0); }
            return g_hasKey;
        }
        // prev == 0 — инициализируем здесь (уже вне DllMain: первый вызов с рабочего потока IOCP).
#ifdef ASDAWIRE_STAND_NO_CNG
        const bool cngOk = false;          // только стенд stand_nocng: имитация «CNG не открылся» (в DLL не определено)
#else
        const bool cngOk = AsdaSecure::Init();
#endif
        if (cngOk)
        {
            g_cngOk = true;
            // ★ fix2e: нехватка памяти при построении таблицы слотов (первое соединение) — исключение не выходит в трамплин:
            //   таблица не публикуется, мост работает как при сбое CNG (байты как есть при AllowLegacy=1; строка InitNotify «CNG
            //   не открылся»). Частично построенные слоты не освобождаются (процесс без памяти; повторной инициализации нет).
            Slot* t = nullptr;
            try
            {
                t = (Slot*)::operator new(sizeof(Slot) * kMaxSlots);
                for (int i = 0; i < kMaxSlots; ++i)
                {
                    new (&t[i]) Slot();
                    InitializeCriticalSection(&t[i].cs);
                    t[i].resetReq = 0;
                    t[i].resetSeen = 0;
                    t[i].failed = false;
                    t[i].identitySet = false;
                    t[i].reported = false;
                    memset(&t[i].fail, 0, sizeof(t[i].fail));
                }
                g_hasKey = (g_keyPath[0] && AsdaSecure::LoadPrivateKeyFile(g_keyPath, g_key));
            }
            catch (const std::exception&)
            {
                t = nullptr; g_cngOk = false; g_hasKey = false;
            }
            if (t) { InterlockedExchangePointer((PVOID volatile*)&g_slots, t); }   // публикация ПОСЛЕ построения (барьер)
        }
        InterlockedExchange(&g_inited, 2);
        if (g_initNotify) { g_initNotify(g_cngOk, g_hasKey); }
        return g_hasKey;
    }

    bool Init(SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw)
    {
        Configure(sub, keyPath, allowLegacy, sendRaw);
        return EnsureInit();
    }

    bool IsReady() { return g_inited == 2 && g_hasKey; }

    bool IsBypass() { return g_inited == 2 && !g_slots; }

    void SetAllowLegacy(bool allow)
    {
        g_allow = allow;
        Slot* sl = g_slots;
        if (!sl) { return; }
        for (int i = 0; i < kMaxSlots; ++i)
        {
            EnterCriticalSection(&sl[i].cs);
            sl[i].chan.SetAllowLegacy(allow);
            LeaveCriticalSection(&sl[i].cs);
        }
    }

    bool CheckKeyFile(const wchar_t* path, wchar_t* why, int whyLen)
    {
        auto say = [&](const wchar_t* t) { if (why && whyLen > 0) { wcsncpy_s(why, (size_t)whyLen, t, _TRUNCATE); } };
        if (!path || !path[0]) { say(L"путь к ключу пуст (KeyFile)"); return false; }
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE)
        {
            const DWORD le = GetLastError();
            say(le == ERROR_FILE_NOT_FOUND || le == ERROR_PATH_NOT_FOUND ? L"файл ключа не найден"
              : le == ERROR_ACCESS_DENIED ? L"нет доступа к файлу ключа (права)" : L"файл ключа не открывается");
            return false;
        }
        LARGE_INTEGER sz{};
        const bool szOk = GetFileSizeEx(f, &sz) != FALSE;
        uint8_t buf[8] = {};
        DWORD rd = 0;
        const bool rdOk = ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd == sizeof(buf);
        CloseHandle(f);
        if (!szOk || sz.QuadPart != (LONGLONG)(8 + kPrivLen + kPubLen)) { say(L"размер файла ключа не 104 байта (повреждён/не тот файл)"); return false; }
        if (!rdOk || memcmp(buf, "ASDAKEY1", 8) != 0) { SecureZeroMemory(buf, sizeof(buf)); say(L"нет метки ASDAKEY1 (не файл ключа keygen)"); return false; }
        SecureZeroMemory(buf, sizeof(buf));
        say(L"ок");
        return true;
    }

    int KindForErr(Err e)
    {
        switch (e)
        {
        case Err::BadTag:       return kKindBadTag;
        case Err::Replay:       return kKindReplay;
        case Err::Format:       return kKindFormat;
        case Err::BadMagic:
        case Err::BadVersion:
        case Err::BadSubServer:
        case Err::BadSignature:
        case Err::State:
        case Err::Arg:
        case Err::Legacy:       return kKindHandshake;
        default:                return 0;      // Cng/Ok — сбой сервера, не нарушение клиента
        }
    }

    void SetLogPerMinute(int perMinute) { InterlockedExchange(&g_perMinute, perMinute < 0 ? 0 : perMinute); }

    bool LogAllow(int* suppressed)
    {
        if (suppressed) { *suppressed = 0; }
        const LONG lim = g_perMinute;
        if (lim <= 0)
        {
            if (suppressed) { *suppressed = InterlockedExchange(&g_pendingSup, 0); }
            return true;
        }
        // ★ fix2 (НИЗК-6 integ3, урок N01b): окно — в БЕЗЗНАКОВОЙ разности тиков. Знаковое (LONG)(now-start) после
        //   24,8 суток без строк становилось отрицательным, окно не сбрасывалось до следующих 24,8 суток.
        DWORD now = GetTickCount();
        if (now == 0) { now = 1; }                 // 0 — признак «окна ещё не было»
        const LONG start = g_winStart;
        if (start == 0 || (DWORD)(now - (DWORD)start) >= 60000u)
        {
            // Новое окно: кто первым сменил начало — обнуляет счётчик.
            if (InterlockedCompareExchange(&g_winStart, (LONG)now, start) == start)
            {
                InterlockedExchange(&g_winCount, 0);
            }
        }
        if (InterlockedIncrement(&g_winCount) > lim)
        {
            InterlockedIncrement(&g_pendingSup);
            InterlockedIncrement(&g_logSuppr);
            return false;
        }
        if (suppressed) { *suppressed = InterlockedExchange(&g_pendingSup, 0); }
        return true;
    }

    // ★ fix2 (Б-1): БЕЗ замка слота и без EnsureInit — зовётся из детура SetConnectFlag ПОД замком Ciocp L.
    //   До инициализации слотов сбрасывать нечего (сессий ещё нет). Сброс применит ApplyResetLocked под cs_X.
    //   ★ fix2b: connectFlag — значение стокового флага соединения (SetConnectFlag(X,1) accept / (X,0) разрыв). Порядок:
    //   accept — сперва запрос сброса, потом флаг 1 (кадр новой сессии встанет в очередь только после применения сброса);
    //   разрыв — сперва флаг 0 (новые кадры не копятся, как сток их роняет), потом запрос сброса.
    void ResetSlot(int slot, int connectFlag)
    {
        if (slot < 0 || slot >= kMaxSlots) { return; }
        Slot* sl = g_slots;
        if (connectFlag)
        {
            if (sl) { InterlockedIncrement(&sl[slot].resetReq); }
            InterlockedExchange(&g_connFlag[slot], 1);
        }
        else
        {
            InterlockedExchange(&g_connFlag[slot], 0);
            if (sl) { InterlockedIncrement(&sl[slot].resetReq); }
        }
    }

    void SetPreHandshake(int maxBytes, int closeDelayMs, uintptr_t ioWorkerLo, uintptr_t ioWorkerHi)
    {
        InterlockedExchange(&g_preMax, maxBytes < 0 ? 0 : maxBytes);
        InterlockedExchange(&g_deferMs, closeDelayMs < 0 ? 0 : closeDelayMs);
        g_ioLo = ioWorkerLo; g_ioHi = ioWorkerHi;
    }

    void SetLingerMs(int ms) { InterlockedExchange(&g_lingerMs, ms < 0 ? 0 : (ms > 5000 ? 5000 : ms)); }

    void SetRecvSink(SinkFn sink) { g_sink = sink; }

    void SetStockSendLayout(const StockSendLayout* layout)
    {
        if (!layout) { InterlockedExchange(&g_layoutSet, 0); return; }
        g_layout = *layout;
        InterlockedExchange(&g_layoutSet, 1);
    }

    void SetTxQueueMax(int maxBytes) { InterlockedExchange(&g_txMax, maxBytes < 0 ? 0 : maxBytes); }

    void SetTxQueueTotalMax(int maxBytes) { InterlockedExchange(&g_txTotalMax, maxBytes < 0 ? 0 : maxBytes); }   // ★ fix2e
}

namespace
{
    // ★ fix2d: разрыв слота, если с момента gen слот не сбрасывался. При известной раскладке — ПОД замком Ciocp L: флаг
    //   соединения стока меняет только SetConnectFlag 0x562910 / LM 0x4144A0, и меняет ПОД L (сам берёт L), а наш детур на его
    //   входе ставит запрос сброса ДО этого (accept 0x563C50 → (X,1); DisConnect/DisConnect_NoLock/кик через 0x563B60 → (X,0)).
    //   Значит, под L «поколение не сменилось» ⇒ в слоте тот же клиент, и GetConnectFlag + DisConnect (берут L повторно — замок
    //   рекурсивный) не заденут нового, принятого между проверкой и разрывом. Зовётся без замка слота (сторож / поток приёма) —
    //   порядок «слот → L» не нарушается.
    //   true — разрыв выполнен (или g_kill нет), false — слот уже сброшен.
    bool KillIfSameGen(Slot& s, void* self, int slot, LONG gen)
    {
        CRITICAL_SECTION* lk = (g_layoutSet && self) ? (CRITICAL_SECTION*)((uint8_t*)self + g_layout.lockOff) : nullptr;
        if (lk) { EnterCriticalSection(lk); }
        const bool same = InterlockedCompareExchange(&s.resetReq, 0, 0) == gen;
        if (same && g_kill) { g_kill(self, slot); }
        if (lk) { LeaveCriticalSection(lk); }
        return same;
    }

    // ★ fix2b: выполнить отложенный DisConnect слота (владелец — кто снял deferKill 1→0). Очередь до рукопожатия к этому
    //   моменту выдана (RecvRoute) или выброшена (сторож: клиент молчит); ворота DisConnect видят preBytes==0 и пропускают сток.
    //   ★ fix2c (Н-3): если с момента откладывания у слота был сброс (resetReq ≠ deferGen) — соединение уже закрыто
    //   (DisConnect_NoLock GS 0x561D70 / LM 0x413A10 из Send/SendTemp при ошибке WriteFile обходит ворота) и, возможно, слот
    //   занят НОВЫМ клиентом: GetConnectFlag вернул бы 1 и разрыв задел бы его. Тогда g_kill не зовём.
    void RunDeferredKill(int slot)
    {
        Slot& s = g_slots[slot];
        void* self = s.deferThis;
        EnterCriticalSection(&s.cs);
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        LeaveCriticalSection(&s.cs);
        // ВНЕ замка слота: GetConnectFlag + DisConnect (замок Ciocp). ★ fix2d: поколение проверяется под L (KillIfSameGen).
        if (!KillIfSameGen(s, self, slot, s.deferGen)) { InterlockedIncrement(&g_deferStale); }
    }

    // ★ fix2b: сторож отложенных разрывов — клиент не прислал ни байта за PreHandshakeCloseMs → разрыв, очередь выбрасывается.
    //   ★ fix2c (Н-2): очередь выдана — разрыв не раньше PreHandshakeLingerMs после выдачи (сокет закрывается с RST — без паузы
    //   отказ догоняется сбросом; сток GS делал Sleep(100)). Сторож шагает по 50 мс, потоков сервера не держит.
    // ★ fix2d (П-2): назначенный разрыв по сбою доставки — вне замка слота (GetConnectFlag + DisConnect берут L). Слот с момента
    //   сбоя сброшен (сток сам закрыл: DisConnect_NoLock при ошибке WriteFile, или новый accept) — не трогаем (txKillStale).
    void RunTxKill(int slot)
    {
        Slot& s = g_slots[slot];
        if (InterlockedCompareExchange(&s.txKill, 0, 1) != 1) { return; }
        if (KillIfSameGen(s, s.txThis, slot, s.txGen)) { InterlockedIncrement(&g_txKills); } else { InterlockedIncrement(&g_txKillStale); }
    }

    void ReportFn_(void* self, int slot, const AsdaWire::FailInfo& fi)
    {
        if (g_report) { InterlockedIncrement(&g_reports); g_report(self, slot, fi); }
    }

    // ★ fix2d (П-1): вытолкнуть очередь шифрованных кадров слота (сторож). Замок слота держится только на время стоковых Send
    //   (перекрытый WriteFile не блокирует); Sleep сторожа — вне замков. Отчёт П-2 — после выхода из замка.
    void TxWatchSlot(int slot)
    {
        Slot& s = g_slots[slot];
        bool doReport = false;
        AsdaWire::FailInfo fi{};
        void* self = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        if (!s.txQ.empty() && !s.failed)
        {
            // this Ciocp — тот же, что у кадров очереди (у сервера один Ciocp на клиентские слоты); берём из последнего вызова слота
            self = s.txThis;
            // ★ fix2e: выталкивание память не выделяет; барьер — чтобы нить сторожа не завершилась исключением (падение процесса)
            try { TxDrainLocked(s, self, slot); } catch (const std::exception&) { NoMemLocked(s, self, 1); }
        }
        if (s.failed && !s.reported && s.fail.kind == AsdaWire::kKindSendFail) { s.reported = true; doReport = true; fi = s.fail; self = s.txThis; }
        LeaveCriticalSection(&s.cs);
        if (doReport) { ReportFn_(self, slot, fi); }
        if (s.txKill) { RunTxKill(slot); }
    }

    DWORD WINAPI DeferWatch(LPVOID)
    {
        for (;;)
        {
            Sleep(50);
            Slot* sl = g_slots;
            const DWORD lim = (DWORD)g_deferMs, linger = (DWORD)g_lingerMs;
            if (!sl) { continue; }
            const DWORD now = GetTickCount();
            for (int i = 0; i < AsdaWire::kMaxSlots; ++i)
            {
                Slot& s = sl[i];
                if (s.txBytes > 0 || s.txKill) { TxWatchSlot(i); }   // ★ fix2d (П-1/П-2)
                if (!s.deferKill) { continue; }
                const LONG ft = s.flushTick;
                const bool due = ft ? (DWORD)(now - (DWORD)ft) >= linger : (DWORD)(now - (DWORD)s.deferTick) >= lim;
                if (!due) { continue; }
                if (InterlockedCompareExchange(&s.deferKill, 0, 1) != 1) { continue; }   // разрыв уже взял другой
                if (!ft) { InterlockedIncrement(&g_deferTimeouts); }
                RunDeferredKill(i);
            }
        }
    }

    // ★ fix2d: нить сторожа — одна на процесс (отложенные разрывы fix2b/fix2c + очередь и разрывы П-1/П-2). Создаётся при первой
    //   надобности, не в DllMain. false — нить не создана (CreateThread отказал).
    bool EnsureWatchdogOk()
    {
        if (g_watchdog) { return true; }
        if (InterlockedCompareExchange(&g_watchdog, 1, 0) == 0)
        {
            HANDLE h = CreateThread(nullptr, 0, &DeferWatch, nullptr, 0, nullptr);
            if (h) { CloseHandle(h); return true; }
            InterlockedExchange(&g_watchdog, 0);
            return false;
        }
        return true;
    }
    void EnsureWatchdog() { EnsureWatchdogOk(); }

    // ★ fix2c (Н-1, приём): отдать расшифрованный поток стоковому разборщику кусками ≤ kStockSinkMax (как порции ReadFile
    //   0x1000) — БЕЗ замков моста. Нет зарегистрированного разборщика (стенды) — вернуть указатель и длину вызывающему.
    int Deliver(void* self, int slot, const uint8_t* p, int n, const uint8_t** out)
    {
        if (n <= 0) { return 0; }
        if (!g_sink) { if (out) { *out = p; } return n; }
        for (int off = 0; off < n; )
        {
            const int k = (n - off) > (int)kStockSinkMax ? (int)kStockSinkMax : (n - off);
            g_sink(self, p + off, k, slot);
            off += k;
        }
        return 0;
    }
}

namespace AsdaWire
{
    // ★ fix2b: ворота входа Ciocp::DisConnect. Зовутся БЕЗ замка слота (вход DisConnect бывает под замком Ciocp — только
    //   Interlocked-поля). true — отложить (сток не выполнять, вернуть 1): у слота есть невыданные кадры до рукопожатия
    //   (отказ сервера 4101/2253/6004 сразу после accept), и разрыв идёт не из IoWorkerThread (там сокет уже мёртв).
    //   Разрыв выполнит приём (после выдачи очереди за ServerHello / как есть Legacy-клиенту) или сторож по сроку.
    bool DisconnectGate(void* ciocpThis, int slot, uintptr_t retAddr)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots || g_deferMs <= 0) { return false; }
        Slot& s = sl[slot];
        // ★ fix2c (Н-4): из IoWorkerThread (клиент сам закрыл / ошибка сокета) — сток сразу, даже если разрыв уже отложен:
        //   снять отложенный (CAS) — сокет освобождается сейчас, а не через PreHandshakeCloseMs.
        if (retAddr >= g_ioLo && retAddr < g_ioHi)
        {
            if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { InterlockedExchange(&s.closing, 0); }
            return false;
        }
        if (s.deferKill) { return true; }                                   // уже отложен — повторный DisConnect тоже ждёт
        if (s.preBytes <= 0) { return false; }                              // нечего выдавать — сток как есть
        s.deferThis = ciocpThis;
        InterlockedExchange(&s.deferGen, InterlockedCompareExchange(&s.resetReq, 0, 0));   // ★ fix2c (Н-3)
        InterlockedExchange(&s.flushTick, 0);
        DWORD t = GetTickCount(); if (t == 0) { t = 1; }
        InterlockedExchange(&s.deferTick, (LONG)t);
        InterlockedExchange(&s.closing, 1);
        if (InterlockedCompareExchange(&s.deferKill, 1, 0) != 0) { return true; }
        const bool watchOk = EnsureWatchdogOk();                            // вне DllMain: первый отложенный разрыв
        // Повторная проверка: приём мог выдать очередь между чтением preBytes и установкой deferKill (тогда он разрыв уже не
        //   возьмёт). Нет сторожа — тоже не откладываем. Кто снял deferKill 1→0 — тот и выполняет разрыв: здесь — сток сейчас.
        if ((s.preBytes <= 0 || !watchOk) && InterlockedCompareExchange(&s.deferKill, 0, 1) == 1)
        {
            InterlockedExchange(&s.closing, 0);
            return false;
        }
        InterlockedIncrement(&g_deferred);
        return true;
    }

    const uint8_t* OnRecv(void* ciocpThis, int slot, const void* in, int len, int* outLen)
    {
        if (outLen) { *outLen = 0; }
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return nullptr; }
        Slot& s = sl[slot];
        const uint8_t* p = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        int n = 0;
        try { n = RecvLocked(s, ciocpThis, slot, in, len, &p); }                 // ★ fix2e: исключение — внутри моста
        catch (const std::exception&) { n = 0; p = nullptr; NoMemLocked(s, ciocpThis, 0); }
        LeaveCriticalSection(&s.cs);
        if (n > 0 && outLen) { *outLen = n; }
        return n > 0 ? p : nullptr;
    }

    int RecvRoute(void* ciocpThis, int slot, const void* in, int len, const uint8_t** out)
    {
        if (out) { *out = nullptr; }
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl)
        {
            // ★ fix2 (НИЗК-5 integ3): CNG не открылся — таблицы слотов нет. AllowLegacy=1: байты как есть (сток, Legacy) —
            //   старые клиенты работают; зашифрованный ClientHello уходит стоковому разборщику и ответа не получает.
            //   AllowLegacy=0: шифрование обязательно, а его нет — соединение закрывается (строка PatchLog, вид 0).
            if (g_allow)
            {
                InterlockedIncrement(&g_bypass);
                return Deliver(ciocpThis, slot, (const uint8_t*)in, len, out);
            }
            FailInfo fi{}; fi.err = Err::Cng; fi.mode = 0; fi.phase = 0; fi.firstByte = (in && len > 0) ? ((const uint8_t*)in)[0] : -1;
            fi.bytes = len; fi.kind = 0;
            if (g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
            if (!g_killOnViolation || !g_kill) { return 0; }
            InterlockedIncrement(&g_kills);
            g_kill(ciocpThis, slot);
            return -1;
        }
        if (slot < 0 || slot >= kMaxSlots)
        {
            return Deliver(ciocpThis, slot, (const uint8_t*)in, len, out);   // вне таблицы (у Ciocp не бывает) — сток
        }

        Slot& s = sl[slot];
        FailInfo fi{};
        bool failedNow = false, doReport = false;
        const uint8_t* p = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        int n = 0;
        // ★ fix2e: сбой выделения памяти на приёме (буферы канала, ServerHello, выдача очереди до рукопожатия) — П-2 причина 5 под
        //   тем же захватом cs; ниже — обычная ветка вида 61 (отчёт, разрыв сторожем, −1).
        try { n = RecvLocked(s, ciocpThis, slot, in, len, &p); }
        catch (const std::exception&) { n = 0; p = nullptr; NoMemLocked(s, ciocpThis, 0); }
        if (s.failed)
        {
            failedNow = true;
            fi = s.fail;                                       // снимок под тем же захватом: сброс не вклинится
            if (!s.reported) { s.reported = true; doReport = true; }
        }
        LeaveCriticalSection(&s.cs);
        if (!failedNow)
        {
            // ★ fix2b: сервер отказал соединению до рукопожатия (DisConnect отложен воротами), очередь уже выдана клиенту —
            //   выполнить отложенный разрыв; присланное клиентом стоку не отдаём (в стоке сокет был бы уже закрыт).
            //   ★ fix2c (Н-2): при PreHandshakeLingerMs > 0 разрыв выполнит сторож через паузу после выдачи (−1: ReadFile не
            //   перевыставляется, присланное клиентом стоку не отдаётся); 0 — сразу, как в fix2b.
            if (s.deferKill && s.preBytes <= 0)
            {
                if (g_lingerMs > 0 && s.flushTick) { return -1; }
                if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { RunDeferredKill(slot); return -1; }
            }
            return Deliver(ciocpThis, slot, p, n, out);
        }

        // ── нарушение: отчёт (один раз на соединение) → разрыв штатным путём ──
        if (doReport && g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
        // ★ fix2d (П-2): сбой доставки (вид 61) — разрыв назначен сторожу (RunTxKill, ровно один); приём слоту больше не нужен
        //   (−1: ReadFile не перевыставляется). Отложенный разрыв до рукопожатия, если есть, покрывает и этот.
        if (fi.kind == kKindSendFail)
        {
            if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { InterlockedExchange(&s.txKill, 0); RunDeferredKill(slot); return -1; }
            if (s.txKill && g_watchdog) { return -1; }
            RunTxKill(slot);                               // сторожа нет (CreateThread отказал) — разрыв здесь, вне замка слота
            return -1;
        }
        // ★ fix2b: сервер уже отказал соединению (DisConnect отложен) — разрыв нужен в любом режиме; очередь выброшена (RecvLocked).
        if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { RunDeferredKill(slot); return -1; }
        if (!g_killOnViolation || !g_kill) { return 0; }   // режим «только отбросить» (откат поведения В7b)
        InterlockedIncrement(&g_kills);
        g_kill(ciocpThis, slot);                           // ВНЕ слотового лока: DisConnect → SetConnectFlag → ResetSlot
        return -1;
    }

    int SendRoute(void* ciocpThis, int slot, const void* frame, int len)
    {
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots)
        {
            // ★ fix2 (НИЗК-5): CNG не открылся / вне таблицы — сток как есть. При AllowLegacy=0 без CNG открытым не шлём
            //   (соединение и так будет закрыто на первом приёме).
            if (!sl && !g_allow) { return 0; }
            if (!sl) { InterlockedIncrement(&g_bypass); }
            return g_sendRaw ? g_sendRaw(ciocpThis, slot, frame, len) : 0;
        }
        Slot& s = sl[slot];
        int rc = 0;
        bool doReport = false;
        FailInfo fi{};
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        // ★ fix2e: всё, что выделяет память (очередь до рукопожатия, буфер шифрования, очередь моста), — в try под cs слота;
        //   std::bad_alloc/std::exception → П-2 причина 5 (вид 61; отчёт ниже, разрыв сторожем), возврат 0. Исключение наружу
        //   (naked-трамплин отправки → сток) не выходит. Под L в этот момент мост не стоит (StockSendSecure память не выделяет).
        try {
        if (s.closing)
        {
            rc = 0;                                       // ★ fix2b: DisConnect отложен — сток после разрыва кадры роняет
        }
        else if (!s.failed && !s.chan.IsReady())
        {
            // ★ fix2b: канал ещё не готов (режим не известен / рукопожатие не завершено) — кадр в очередь слота; уйдёт сразу за
            //   ServerHello (Secure) или как есть (Legacy) в том порядке, в каком отправлялся. Флаг соединения 0 — сток такой
            //   Send отвергает (возврат 0), мост тоже. Предел PreHandshakeQueueKB: лишнее отбрасывается и считается (preDropped).
            if (!g_connFlag[slot] || len <= 0) { rc = 0; }
            else if ((LONG)s.preQ.size() + len > g_preMax) { rc = 0; InterlockedIncrement(&g_preDropped); }
            else
            {
                s.preQ.insert(s.preQ.end(), (const uint8_t*)frame, (const uint8_t*)frame + len);
                InterlockedExchange(&s.preBytes, (LONG)s.preQ.size());
                InterlockedIncrement(&g_preQueued);
                rc = 1;                                   // для вызывающего «принят» (как стоковый Send)
            }
        }
        else if (!s.failed)                               // ★ В7d: слот к закрытию — не слать
        {
            EnsureIdentity(s);
            // ★ fix2 (Б-2): стоковый Send ПОД cs_X — номер кадра, присвоенный шифрованием, уходит в буфер сокета (Ciocp
            //   копирует под L: WriteFile либо досылочный буфер +178, который SendTemp шлёт по порядку) в том же порядке, в каком
            //   кадры шифровались. ★ fix2c (Н-1): пакет GS до 0xFFF б + 28 б шифрования не помещается в буфер записи Send
            //   (0x1000) — режем открытый текст на куски ≤ 4068, каждый — свой кадр и свой Send под тем же замком.
            Err e = Err::Ok;
            if (len > 0) { rc = SendReadyChunked(s, ciocpThis, slot, (const uint8_t*)frame, (size_t)len, &e); } else { rc = 1; }
            if (e != Err::Ok)
            {
                MarkFail(s, e, /*phase=*/1, frame, len);
                InterlockedIncrement(&g_sendFails);
                if (!s.reported) { s.reported = true; doReport = true; fi = s.fail; }
            }
        }
        } catch (const std::exception&) { rc = 0; NoMemLocked(s, ciocpThis, 1); }
        // ★ fix2d (П-2): сбой доставки Secure-кадра (отказ стокового Send / переполнение очереди / потеря стоком) — отчёт здесь,
        //   вне замка (IP слота ещё читается); разрыв выполнит сторож (из пути отправки DisConnect не зовём).
        if (!doReport && s.failed && !s.reported && s.fail.kind == kKindSendFail) { s.reported = true; doReport = true; fi = s.fail; }
        LeaveCriticalSection(&s.cs);
        if (doReport && g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
        return rc;
    }

    bool SlotFailed(int slot)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return false; }
        Slot& s = sl[slot];
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const bool f = s.failed;
        LeaveCriticalSection(&s.cs);
        return f;
    }

    int SlotMode(int slot)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return 0; }
        Slot& s = sl[slot];
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const int m = (int)s.chan.GetMode();
        LeaveCriticalSection(&s.cs);
        return m;
    }

    void GetCounters(Counters* c)
    {
        if (!c) { return; }
        c->kills = g_kills; c->reports = g_reports; c->logSuppressed = g_logSuppr; c->sendFails = g_sendFails;
        c->resetsApplied = g_resets; c->bypass = g_bypass;
        c->preQueued = g_preQueued; c->preFlushed = g_preFlushed; c->preDropped = g_preDropped;
        c->deferredCloses = g_deferred; c->deferTimeouts = g_deferTimeouts;
        c->deferStale = g_deferStale; c->overSend = g_overSend;
        c->txQueued = g_txQueued; c->txFlushed = g_txFlushed; c->txPeak = g_txPeak; c->txRefused = g_txRefused;
        c->txOverflow = g_txOverflow; c->txLost = g_txLost; c->txKills = g_txKills; c->txKillStale = g_txKillStale;
        c->txDropped = g_txDropped;
        c->txTotal = g_txTotal; c->txTotalPeak = g_txTotalPeak; c->txTotalOver = g_txTotalOver; c->txNoMem = g_txNoMem;   // ★ fix2e
        long now = 0;
        if (Slot* sl = g_slots) { for (int i = 0; i < kMaxSlots; ++i) { now += sl[i].txBytes; } }
        c->txNow = now;
    }
}
