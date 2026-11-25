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
// ★ sec2 (2026-10-15, блок В плана альфы; ревизия fix2e Е-1/Е-2):
//   • Е-1: MarkFail (сбой шифрования отправки / нарушение приёма при KillOnViolation=0) и сторож (любой сбойный слот) освобождают
//     очередь моста СРАЗУ через TxFreeLocked — место в общем пределе не держится до сброса слота.
//   • Е-2: справедливая доля общего предела (TxPushLocked): «тяжёлый» слот (≥ средней очереди или ≥ TxQueueFairKB) рвётся сам
//     (причина 4); «лёгкому» кадр принимается до жёсткого потолка предел·9/8, сторож вытесняет НАИБОЛЬШУЮ очередь (причина 6).
//   • Допуск подключений до рукопожатия: ResetSlotEx учитывает незавершённые рукопожатия (g_hsPending) по поколению accept;
//     проверка (предел с адреса за окно — вид 63, предел незавершённых — 64) один раз на соединение — первый приём или сторож;
//     срок рукопожатия — 65. Отказ — разрыв штатным путём под L только своего поколения (KillIfSameGen).
//   • Ускорение рукопожатия: EnsureInit загружает ключ подписи в кэш AsdaSecure и запускает пул ECDH (SetHandshakeAccel).
// ★ sec2b (2026-10-15, ревизия SEC2 `review_SEC2_20261015.md`):
//   • С-1: AllowLegacy=1 — молчащий сокет по сроку рукопожатия не рвётся, но снимается из незавершённых (AdmissionWatch: dlDone +
//     CAS hsPend своего поколения → g_hsPending −1 ровно один раз; счётчик g_hsSilentReleased). Правка ревизора (out/fix_C1.diff).
//   • Н-1: предел незавершённых рукопожатий НА АДРЕС (AdmissionCfg.maxPendingPerIp): адрес соединения пишется в слот при проверке
//     допуска вместе с поколением accept (hsIp/hsIpGen); счёт — по живому состоянию слотов под листовым замком таблицы адресов
//     (слот считается, пока hsPend == hsIpGen), отдельного счётчика, который мог бы «утечь», нет.
//   • Н-2: EvictLargest под замком жертвы пересканирует учтённую память всех слотов: жертва уже не наибольшая — не рвём, следующий
//     раунд выбирает заново (g_txEvictRetry).
//   • Н-6: общий предел очередей — в байтах реальной памяти кадра (TxCost: блок данных + блок элемента deque + указатель карты,
//     округление блоков кучи x86/LFH — по замеру HeapWalk); память слота — s.txCost (единственная точка обнуления — TxFreeLocked).
//   • Гонка «сторож допуска ↔ первый приём» (стенд stand_sec2 Д1, найдено при сборке sec2b): ClientHello соединения, которое сторож в этот
//     момент отвергал, разбирался (ServerAccept, пара ECDH) уже на разорванном слоте. Теперь приём ждёт решения сторожа (admBusy) и при
//     флаге соединения 0 байты не разбирает (−1, счётчик admDeadRecv).
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
        bool                 txAct;       // ★ sec2 (Е-2): очередь слота учтена в g_txActive (только под cs)
        // ★ sec2: допуск подключений до рукопожатия (поля пишет ResetSlotEx под замком Ciocp — только Interlocked).
        volatile LONG        hsPend;      // поколение accept, пока рукопожатие не завершено (0 — нет); в g_hsPending
        volatile LONG        admitGen;    // поколение accept, ждущее проверки допуска (0 — проверено / нет); забирает CAS
        volatile LONG        acceptTick;  // GetTickCount accept (≠ 0)
        volatile LONG        gotByte;     // 1 — клиент прислал хоть байт в этой сессии
        volatile LONG        dlDone;      // поколение, для которого срок рукопожатия уже обработан
        // ★ sec2b: сторож принимает решение допуска по этому слоту (≠ 0 — идёт: AdmitDecide + AdmissionReject с разрывом). Первый
        //   приём того же соединения, пришедший в это время, ждёт решения (μs), а не разбирает байты (иначе ServerAccept на
        //   отвергнутом соединении — стенд stand_sec2 Д1).
        volatile LONG        admBusy;
        void* volatile       admThis;     // this Ciocp из детура SetConnectFlag (разрыв сторожем)
        // ★ sec2b (Н-1): адрес соединения и поколение accept, к которому он относится (пишет проверка допуска под g_admLk).
        //   Слот входит в счёт незавершённых адреса, пока hsPend == hsIpGen (рукопожатие этого же соединения не завершено).
        volatile LONG        hsIp;
        volatile LONG        hsIpGen;
        // ★ sec2b (Н-6): учтённая память очереди слота (Σ TxCost кадров txQ) — её доля в g_txTotal. Меняется только под cs.
        volatile LONG        txCost;
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
    // ★ sec2 (Е-1/Е-2): освобождено очередей сбойных слотов; слотов с непустой очередью; «лёгких» постановок сверх предела;
    //   вытеснено наибольших очередей; порог «тяжёлого» слота (TxQueueFairKB); запрос вытеснения сторожу.
    volatile LONG g_txFailFreed = 0, g_txActive = 0, g_txOverSoft = 0, g_txEvicted = 0;
    volatile LONG g_txFair = 256 * 1024;
    volatile LONG g_evictReq = 0;
    // ★ sec2: ускорение рукопожатия (применяется в EnsureInit).
    volatile LONG g_accelSigner = 1, g_accelPool = 16;
    // ★ sec2: допуск подключений до рукопожатия.
    AsdaWire::AdmissionCfg g_adm{};
    AsdaWire::PeerIpFn     g_peerIp = nullptr;
    volatile LONG g_admOn = 0;                     // SetAdmission с хоть одним пределом
    volatile LONG g_hsPending = 0, g_hsPendingPeak = 0;
    volatile LONG g_admChecked = 0, g_admRate = 0, g_admPending = 0, g_admDeadline = 0, g_admNoIp = 0, g_admTableFull = 0;
    volatile LONG g_repTick[3] = {}, g_repSup[3] = {};   // ограничитель отчётов: 0 — вид 64 (процесс), 1 — 65, 2 — 64 (адрес, ★ sec2b)
    volatile LONG g_admPendingIp = 0, g_hsSilentReleased = 0, g_txEvictRetry = 0;   // ★ sec2b (Н-1, С-1, Н-2)
    volatile LONG g_admDeadRecv = 0;               // ★ sec2b: порций приёма соединения, уже разорванного допуском/сроком (не разбирались)
    void* volatile g_lastThis = nullptr;            // последний this Ciocp (сторожу — если детур SetConnectFlag его не дал)
    struct AdmEntry { uint32_t ip; DWORD winStart; LONG count; LONG reported; };
    AdmEntry      g_admTab[AsdaWire::kAdmTable] = {};
    SRWLOCK       g_admLk = SRWLOCK_INIT;           // листовой: под ним других замков нет

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

    // ★ sec2b (ревизия SEC2 Н-6): блок кучи процесса x86 под запрос sz байт. ПО ЗАМЕРУ (HeapWalk, cbData + cbOverhead; стенд
    //   stand_sec2 Н-6б и проверочная программа 15.10): LFH округляет ЗАПРОС до гранулы корзины (8 б до 256, 16 до 512, 32 до 1 КБ,
    //   64 до 2 КБ, 128 до 4 КБ, 256 до 8 КБ, 512 до 16 КБ) и добавляет заголовок 8 б (500 → 520, 2028 → 2056, 4000 → 4104); блоки
    //   до включения LFH (запрос + 8, гранула 8) не больше. Первая версия sec2b клала заголовок ДО округления (2028 → 2048) и
    //   занижала память кадра на 8 б (стенд Н-6б: прирост кучи 2085,8 б на кадр 2028 б при учёте 2080). Крупнее 16 КБ кадров нет
    //   (кадр шифрования ≤ 4096 б) — для полноты гранула страницы.
    LONG HeapBlock32(LONG sz)
    {
        const LONG g = sz <= 256 ? 8 : sz <= 512 ? 16 : sz <= 1024 ? 32 : sz <= 2048 ? 64 : sz <= 4096 ? 128 : sz <= 8192 ? 256
                     : sz <= 16384 ? 512 : 4096;
        return ((sz + g - 1) & ~(g - 1)) + 8;
    }
    // Память кадра очереди: данные (vector) + блок элемента deque (_DEQUESIZ = 1 при элементе > 8 б) + до 2 указателей карты.
    //   ★ sec2b: запрос vector к куче — n байт, а при n ≥ 4096 (MSVC _Big_allocation_threshold) — n + sizeof(void*) + 31 (выровненный
    //   «большой блок»: 4096 → 4131, замер). Кадр шифрования наибольшей длины — ровно 4096 б (4068 + 28).
    LONG TxCost(LONG n)
    {
        static_assert(sizeof(std::vector<uint8_t>) > 8, "deque<vector>: один элемент на блок (_DEQUESIZ = 1)");
        const LONG req = n >= 4096 ? n + (LONG)sizeof(void*) + 31 : n;
        return HeapBlock32(req) + HeapBlock32((LONG)sizeof(std::vector<uint8_t>)) + 2 * (LONG)sizeof(void*);
    }

    // Очередь слота выброшена: память — сразу, её объём — из общего счётчика (★ fix2e: единственная точка обнуления txBytes;
    //   txBytes и g_txTotal меняются только под cs слота — сумма не «утекает»). Исключений не бросает.
    //   ★ sec2b (Н-6): в общий счётчик возвращается учтённая память слота (txCost), обнуляется здесь же.
    void TxFreeLocked(Slot& s)
    {
        if (!s.txQ.empty())
        {
            try { std::deque<std::vector<uint8_t>>().swap(s.txQ); }          // память очереди — сразу (пустой deque не выделяет)
            catch (const std::exception&) { s.txQ.clear(); }                  // на всякий случай: clear() не выделяет
        }
        InterlockedExchange(&s.txBytes, 0);
        const LONG had = InterlockedExchange(&s.txCost, 0);
        if (had) { InterlockedExchangeAdd(&g_txTotal, -had); }
        if (s.txAct) { s.txAct = false; InterlockedDecrement(&g_txActive); }   // ★ sec2 (Е-2): слот без очереди
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
                           : reason == AsdaWire::kSendFailTotalEvict ? &g_txEvicted     // ★ sec2 (Е-2)
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
        //   ★ sec2b (Н-6): резерв, сумма, доля слота и вытеснение — в учтённой памяти кадра (TxCost), а не в байтах кадра.
        const LONG cost = TxCost((LONG)n);
        const LONG totMax = g_txTotalMax;
        const LONG tot = InterlockedExchangeAdd(&g_txTotal, cost) + cost;
        bool overSoft = false;
        if (totMax > 0 && tot > totMax)
        {
            // ★ sec2 (ревизия fix2e Е-2): СПРАВЕДЛИВАЯ ДОЛЯ. «Тяжёлый» слот (его очередь с этим кадром ≥ средней по слотам с
            //   непустой очередью или ≥ TxQueueFairKB) рвётся сам — как fix2e. «Лёгкий» (честный клиент, начавший грузить карту)
            //   получает кадр, пока сумма ≤ предел + предел/8 (жёсткий потолок: каждая принятая постановка видит сумму принятого и
            //   всех резервов — сумма принятых не больше потолка), а сторож вытесняет НАИБОЛЬШУЮ очередь процесса (причина 6),
            //   пока сумма > предела. Решение — по Interlocked-снимкам (txActive, txBytes чужих слотов замков не требуют): чужих
            //   замков слотов отсюда не берём, порядок «слот → Ciocp» не меняется.
            const LONG mine = s.txCost + cost;
            LONG act = g_txActive + (s.txAct ? 0 : 1);
            if (act < 1) { act = 1; }
            const LONG avg  = tot / act;
            const LONG fair = g_txFair;
            const bool heavy = mine >= avg || (fair > 0 && mine >= fair);
            const LONG hard = totMax + totMax / 8;
            if (heavy || tot > hard)
            {
                InterlockedExchangeAdd(&g_txTotal, -cost);
                TxFailLocked(s, self, AsdaWire::kSendFailTotalMax, pend);
                return false;
            }
            overSoft = true;
        }
        try { s.txQ.emplace_back(p, p + n); }                              // deque::emplace_back — строгая гарантия: при отказе очередь цела
        catch (const std::exception&)
        {
            InterlockedExchangeAdd(&g_txTotal, -cost);
            TxFailLocked(s, self, AsdaWire::kSendFailNoMem, pend);
            return false;
        }
        s.txThis = self;                                                   // сторож выталкивает этим же this Ciocp
        InterlockedExchangeAdd(&s.txCost, cost);                           // ★ sec2b (Н-6): доля слота в общем счётчике
        const LONG b = InterlockedExchangeAdd(&s.txBytes, (LONG)n) + (LONG)n;
        if (!s.txAct) { s.txAct = true; InterlockedIncrement(&g_txActive); }   // ★ sec2 (Е-2)
        if (overSoft) { InterlockedIncrement(&g_txOverSoft); InterlockedExchange(&g_evictReq, 1); }   // ★ sec2: сторож вытеснит наибольшую
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
                const LONG c = TxCost((LONG)f.size());                     // ★ sec2b (Н-6): ровно то, что учтено при постановке
                InterlockedExchangeAdd(&s.txBytes, -(LONG)f.size());
                InterlockedExchangeAdd(&s.txCost, -c);
                InterlockedExchangeAdd(&g_txTotal, -c);                    // ★ fix2e
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
        // ★ sec2 (ревизия fix2e Е-1): слот в сбое НЕ по виду 61 (сбой шифрования отправки — разрыв на ближайшем приёме; нарушение
        //   приёма при KillOnViolation=0 — соединение живёт без доставки) кадров больше не отдаёт: очередь моста не нужна —
        //   освободить СРАЗУ (память и место в общем пределе TxQueueTotalMB), не дожидаясь сброса слота. Счёт — через
        //   TxFreeLocked (единственная точка обнуления txBytes, под cs): без утечки и без двойного вычитания.
        if (s.txBytes > 0 || !s.txQ.empty()) { InterlockedIncrement(&g_txFailFreed); }
        TxFreeLocked(s);
    }

    // Разбор порции приёма под cs (общая часть OnRecv/RecvRoute). Возврат — длина расшифрованного (>0, *out) или 0.
    //   ServerHello/очередь исходящего уходят стоковым Send ЗДЕСЬ, под cs_X (порядок «cs_X → L»).
    int RecvLocked(Slot& s, void* ciocpThis, int slot, const void* in, int len, const uint8_t** out)
    {
        if (s.failed) { return 0; }        // ★ В7d: слот уже в ошибке (например, сбой шифрования на отправке)
        EnsureIdentity(s);
        Err e = s.chan.OnRecv((const uint8_t*)in, (size_t)len, s.toParser, s.toSocket);
        // ★ sec2: рукопожатие завершено (Secure — ключи выведены, Legacy — первый байт) — соединение больше не «незавершённое»
        //   (g_hsPending). CAS по поколению ЭТОЙ сессии: отметку нового accept на том же слоте не снимем.
        if (s.hsPend && s.chan.IsReady())
        {
            const LONG g = s.resetSeen;
            if (g && InterlockedCompareExchange(&s.hsPend, 0, g) == g) { InterlockedDecrement(&g_hsPending); }
        }
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
            // ★ sec2: ускорение рукопожатия — ключ подписи импортируется ОДИН раз (дескрипторы в памяти процесса), пары ECDH
            //   готовит фоновая нить. Сбой — прежний путь (импорт / генерация на месте), рукопожатие не страдает.
            if (t && g_hasKey)
            {
                if (g_accelSigner) { AsdaSecure::ServerSignerLoad(g_key); }
                if (g_accelPool > 0) { AsdaSecure::EphemeralPoolStart((int)g_accelPool); }
            }
            if (t && g_admOn)
            {
                // ★ sec2: соединения, принятые ДО построения таблицы слотов (accept идёт раньше первого обращения к мосту), — тоже в
                //   допуск и в незавершённые: иначе молчащие сокеты, открытые сразу после старта сервера, не проверялись бы и не
                //   рвались по сроку. Флаг соединения стока ведёт детур SetConnectFlag и без таблицы (g_connFlag). Только Interlocked;
                //   параллельный разрыв (ResetSlotEx) снимает отметку сам — повторная проверка флага ниже.
                DWORD now = GetTickCount(); if (now == 0) { now = 1; }
                for (int i = 0; i < kMaxSlots; ++i)
                {
                    if (!g_connFlag[i]) { continue; }
                    Slot& s = t[i];
                    LONG gen = InterlockedIncrement(&s.resetReq);
                    if (!gen) { gen = InterlockedIncrement(&s.resetReq); }
                    s.admThis = g_lastThis;
                    InterlockedExchange(&s.acceptTick, (LONG)now);
                    if (InterlockedCompareExchange(&s.hsPend, gen, 0) == 0)
                    {
                        const LONG p = InterlockedIncrement(&g_hsPending);
                        for (LONG pk = g_hsPendingPeak; p > pk && InterlockedCompareExchange(&g_hsPendingPeak, p, pk) != pk; pk = g_hsPendingPeak) {}
                    }
                    InterlockedCompareExchange(&s.admitGen, gen, 0);
                    if (!g_connFlag[i])                       // разорван за это время — снять, как ResetSlotEx(X,0)
                    {
                        InterlockedCompareExchange(&s.admitGen, 0, gen);
                        if (InterlockedCompareExchange(&s.hsPend, 0, gen) == gen) { InterlockedDecrement(&g_hsPending); }
                    }
                }
                EnsureWatchdog();                             // ★ sec2: сторож допуска (молчащие соединения, срок рукопожатия)
            }
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
    void ResetSlot(int slot, int connectFlag) { ResetSlotEx(nullptr, slot, connectFlag); }

    // ★ sec2: + this Ciocp и учёт допуска. Только Interlocked (под замком Ciocp L). Accept: поколение = новый resetReq; соединение
    //   встаёт в «незавершённые рукопожатия» (hsPend = поколение, g_hsPending +1, если слот там ещё не числился) и в очередь
    //   проверки допуска (admitGen). Разрыв: снять обе отметки (g_hsPending −1 ровно один раз — Exchange), затем запрос сброса.
    void ResetSlotEx(void* ciocpThis, int slot, int connectFlag)
    {
        if (slot < 0 || slot >= kMaxSlots) { return; }
        if (ciocpThis) { g_lastThis = ciocpThis; }
        Slot* sl = g_slots;
        if (connectFlag)
        {
            if (sl)
            {
                Slot& s = sl[slot];
                LONG gen = InterlockedIncrement(&s.resetReq);
                if (g_admOn)
                {
                    if (!gen) { gen = InterlockedIncrement(&s.resetReq); }        // поколение 0 — признак «нет»; после 2^32 сбросов
                    if (ciocpThis) { s.admThis = ciocpThis; }
                    DWORD t = GetTickCount(); if (t == 0) { t = 1; }
                    InterlockedExchange(&s.acceptTick, (LONG)t);
                    InterlockedExchange(&s.gotByte, 0);
                    if (InterlockedExchange(&s.hsPend, gen) == 0)
                    {
                        const LONG p = InterlockedIncrement(&g_hsPending);
                        for (LONG pk = g_hsPendingPeak; p > pk && InterlockedCompareExchange(&g_hsPendingPeak, p, pk) != pk; pk = g_hsPendingPeak) {}
                    }
                    InterlockedExchange(&s.admitGen, gen);
                }
            }
            InterlockedExchange(&g_connFlag[slot], 1);
        }
        else
        {
            InterlockedExchange(&g_connFlag[slot], 0);
            if (sl)
            {
                Slot& s = sl[slot];
                InterlockedExchange(&s.admitGen, 0);
                if (InterlockedExchange(&s.hsPend, 0) != 0) { InterlockedDecrement(&g_hsPending); }
                InterlockedIncrement(&s.resetReq);
            }
        }
    }

    void SetAdmission(const AdmissionCfg* cfg, PeerIpFn ip)
    {
        g_peerIp = ip;
        if (!cfg) { InterlockedExchange(&g_admOn, 0); return; }
        g_adm = *cfg;
        if (g_adm.perIpMax < 0) { g_adm.perIpMax = 0; }
        if (g_adm.perIpWindowMs < 1000) { g_adm.perIpWindowMs = 1000; }
        if (g_adm.maxPending < 0) { g_adm.maxPending = 0; }
        if (g_adm.deadlineMs < 0) { g_adm.deadlineMs = 0; }
        if (g_adm.reportGapMs < 0) { g_adm.reportGapMs = 0; }
        if (g_adm.maxPendingPerIp < 0) { g_adm.maxPendingPerIp = 0; }                 // ★ sec2b (Н-1)
        InterlockedExchange(&g_admOn, (g_adm.perIpMax > 0 || g_adm.maxPending > 0 || g_adm.deadlineMs > 0 || g_adm.maxPendingPerIp > 0) ? 1 : 0);
    }

    void SetTxFairShare(int fairBytes) { InterlockedExchange(&g_txFair, fairBytes < 0 ? 0 : fairBytes); }

    void SetHandshakeAccel(bool signerCache, int poolSize)
    {
        InterlockedExchange(&g_accelSigner, signerCache ? 1 : 0);
        InterlockedExchange(&g_accelPool, poolSize < 0 ? 0 : (poolSize > AsdaSecure::kEphPoolMax ? AsdaSecure::kEphPoolMax : poolSize));
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
        if (s.failed && (s.txBytes > 0 || !s.txQ.empty()))
        {
            // ★ sec2 (Е-1): слот в сбое (любого вида) с непустой очередью — кадры больше не уйдут; освободить сразу.
            InterlockedIncrement(&g_txFailFreed);
            TxFreeLocked(s);
        }
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

    // ── ★ sec2 (ревизия fix2e Е-2): вытеснение НАИБОЛЬШЕЙ очереди при превышении общего предела ──────────────────────────
    //   Сторож (без чужих замков): ищет слот с наибольшей очередью (txBytes читаются без замка — только выбор кандидата), берёт ЕГО
    //   замок, перепроверяет (не в сбое, очередь непуста, сумма всё ещё > предела) и переводит в сбой вида 61 причина 6 (очередь
    //   освобождена TxFailLocked); отчёт и разрыв — TxWatchSlot (вне замка слота, разрыв под L по поколению). Повтор, пока сумма >
    //   предела (не больше 32 за проход). Порядок замков: слот → L, как везде.
    //   ★ sec2b (ревизия SEC2 Н-2): кандидат выбран чтением без замков — пока сторож шёл по 550 слотам, его очередь могла
    //   вытолкнуться почти до нуля, и вытеснен был бы маленький (честный) слот. Под замком жертвы её очередь заморожена (выталкивание и
    //   постановка идут под тем же cs): пересканировать учтённую память остальных слотов и рвать, только если жертва всё ещё
    //   наибольшая или выше справедливой доли («тяжёлая» по Е-2: ≥ средней по слотам с очередью или ≥ TxQueueFairKB). Иначе не
    //   рвать: следующий раунд выбирает заново (g_txEvictRetry). Размер — учтённая память (txCost, Н-6).
    void EvictLargest()
    {
        Slot* sl = g_slots;
        const LONG totMax = g_txTotalMax;
        InterlockedExchange(&g_evictReq, 0);
        if (!sl || totMax <= 0) { return; }
        for (int round = 0; round < 32 && g_txTotal > totMax; ++round)
        {
            int best = -1; LONG bestB = 0;
            for (int i = 0; i < AsdaWire::kMaxSlots; ++i)
            {
                const LONG b = sl[i].txCost;
                if (b > bestB && !sl[i].txKill) { best = i; bestB = b; }
            }
            if (best < 0) { break; }
            Slot& s = sl[best];
            bool did = false;
            EnterCriticalSection(&s.cs);
            ApplyResetLocked(s);
            if (!s.failed && s.txCost > 0 && g_txTotal > totMax)
            {
                const LONG cur = s.txCost;                // под cs жертвы не меняется
                LONG sum = 0, cnt = 0, maxOther = 0;
                for (int j = 0; j < AsdaWire::kMaxSlots; ++j)
                {
                    const LONG c = sl[j].txCost;
                    if (c > 0) { sum += c; ++cnt; }
                    if (j != best && !sl[j].txKill && c > maxOther) { maxOther = c; }
                }
                const LONG avg  = cnt ? sum / cnt : 0;
                const LONG fair = g_txFair;
                // «тяжёлый» — как в TxPushLocked (Е-2): не ниже средней по слотам с очередью или не ниже TxQueueFairKB; наибольшая —
                //   всегда не ниже средней. Очередь, вытолкнутая почти до нуля, ни тем, ни другим не является.
                const bool still = cur >= maxOther || cur >= avg || (fair > 0 && cur >= fair);
                if (still)
                {
                    TxFailLocked(s, s.txThis, AsdaWire::kSendFailTotalEvict, -1);
                    did = true;
                }
                else
                {
                    InterlockedIncrement(&g_txEvictRetry);  // жертва уже не наибольшая — не рвём, выбор заново
                }
            }
            LeaveCriticalSection(&s.cs);
            if (did) { TxWatchSlot(best); }               // отчёт вида 61 причина 6 + разрыв (RunTxKill)
        }
    }

    // ── ★ sec2: ДОПУСК ПОДКЛЮЧЕНИЙ ДО РУКОПОЖАТИЯ ────────────────────────────────────────────────────────────────────────
    // Ограничитель отчётов видов 64 (idx 0) / 65 (idx 1): не чаще раза в reportGapMs; *sup — подавлено с прошлого отчёта.
    bool RepAllow(int idx, int* sup)
    {
        *sup = 0;
        const LONG gap = g_adm.reportGapMs;
        DWORD now = GetTickCount(); if (now == 0) { now = 1; }
        const LONG last = g_repTick[idx];
        if (gap <= 0 || last == 0 || (DWORD)(now - (DWORD)last) >= (DWORD)gap)
        {
            if (InterlockedCompareExchange(&g_repTick[idx], (LONG)now, last) == last) { *sup = InterlockedExchange(&g_repSup[idx], 0); return true; }
        }
        InterlockedIncrement(&g_repSup[idx]);
        return false;
    }

    // Счёт подключений адреса в его окне (фиксированное окно с первого подключения). Возврат — счёт с этим подключением
    //   (0 — таблица полна, адрес не учтён: пропуск). *firstOver — первое превышение в этом окне (отчёт вида 63 — один на адрес за
    //   окно). Таблица — открытая адресация, 32 пробы; запись с истёкшим окном переиспользуется. Замок листовой.
    int AdmCountIp(uint32_t ip, bool* firstOver)
    {
        *firstOver = false;
        const DWORD win = (DWORD)g_adm.perIpWindowMs;
        const uint32_t h = (ip * 2654435761u) >> 20;      // 12 бит (kAdmTable = 4096)
        static_assert(AsdaWire::kAdmTable == 4096, "хэш адреса — 12 бит");
        int cnt = 0;
        AcquireSRWLockExclusive(&g_admLk);
        const DWORD now = GetTickCount();
        AdmEntry* e = nullptr; AdmEntry* freeE = nullptr;
        for (int i = 0; i < 32; ++i)
        {
            AdmEntry& x = g_admTab[(h + (uint32_t)i) & (AsdaWire::kAdmTable - 1)];
            if (x.ip == ip) { e = &x; break; }
            if (!freeE && (x.ip == 0 || (DWORD)(now - x.winStart) >= win)) { freeE = &x; }
        }
        if (e && (DWORD)(now - e->winStart) >= win) { e->winStart = now; e->count = 0; e->reported = 0; }
        if (!e && freeE) { e = freeE; e->ip = ip; e->winStart = now; e->count = 0; e->reported = 0; }
        if (e)
        {
            cnt = (int)++e->count;
            if (cnt > g_adm.perIpMax && !e->reported) { e->reported = 1; *firstOver = true; }
        }
        ReleaseSRWLockExclusive(&g_admLk);
        return cnt;
    }

    // ★ sec2b (Н-1): записать адрес соединения поколения gen в слот и посчитать незавершённые рукопожатия с этого адреса (с этим
    //   соединением, если оно ещё не завершено). Под листовым g_admLk: одновременные проверки с одного адреса видят друг друга
    //   (запись и подсчёт — одним захватом). Счёт — по живому состоянию слотов (hsPend == hsIpGen && hsIp == ip): соединение,
    //   завершившее рукопожатие, разорванное или снятое по сроку (С-1), из счёта выпадает само — счётчика, который мог бы утечь, нет.
    int AdmPendingFromIp(int slot, LONG gen, uint32_t ip)
    {
        Slot* sl = g_slots;
        if (!sl || !ip || slot < 0 || slot >= AsdaWire::kMaxSlots) { return 0; }
        int n = 0;
        AcquireSRWLockExclusive(&g_admLk);
        InterlockedExchange(&sl[slot].hsIp, (LONG)ip);
        InterlockedExchange(&sl[slot].hsIpGen, gen);
        for (int j = 0; j < AsdaWire::kMaxSlots; ++j)
        {
            const LONG g = sl[j].hsPend;
            if (g && sl[j].hsIpGen == g && (uint32_t)sl[j].hsIp == ip) { ++n; }
        }
        ReleaseSRWLockExclusive(&g_admLk);
        return n;
    }

    // Решение допуска (без замков моста; листовой замок таблицы адресов). 0 — допущен; иначе вид 63/64 и fi для отчёта.
    //   ★ sec2b: gen — поколение accept проверяемого соединения (для предела незавершённых с адреса, Н-1).
    int AdmitDecide(void* self, int slot, LONG gen, AsdaWire::FailInfo& fi, bool& report)
    {
        report = false;
        memset(&fi, 0, sizeof(fi)); fi.err = Err::Ok; fi.firstByte = -1;
        InterlockedIncrement(&g_admChecked);
        const uint32_t ip = g_peerIp ? g_peerIp(self, slot) : 0;
        fi.ip = ip;
        if (g_adm.perIpMax > 0)
        {
            if (!ip) { if (g_peerIp) { InterlockedIncrement(&g_admNoIp); } }
            else
            {
                bool first = false;
                const int cnt = AdmCountIp(ip, &first);
                if (cnt == 0) { InterlockedIncrement(&g_admTableFull); }
                else if (cnt > g_adm.perIpMax)
                {
                    fi.kind = AsdaWire::kKindConnRate; fi.count = cnt; fi.limit = g_adm.perIpMax; fi.extra = g_adm.perIpWindowMs / 1000;
                    report = first;
                    InterlockedIncrement(&g_admRate);
                    return AsdaWire::kKindConnRate;
                }
            }
        }
        // ★ sec2b (ревизия SEC2 Н-1): незавершённых рукопожатий С ОДНОГО АДРЕСА — до общего предела: один адрес (64 молчащих
        //   сокета) больше не отсекает всех остальных на срок рукопожатия; отказ — вид 64 с fi.mode = 1 (адрес), свой ограничитель.
        if (g_adm.maxPendingPerIp > 0 && ip)
        {
            const int pip = AdmPendingFromIp(slot, gen, ip);
            if (pip > g_adm.maxPendingPerIp)
            {
                fi.kind = AsdaWire::kKindPendingCap; fi.mode = 1; fi.count = pip; fi.limit = g_adm.maxPendingPerIp;
                int sup = 0; report = RepAllow(2, &sup); fi.extra = sup;
                InterlockedIncrement(&g_admPending);
                InterlockedIncrement(&g_admPendingIp);
                return AsdaWire::kKindPendingCap;
            }
        }
        if (g_adm.maxPending > 0)
        {
            const LONG p = g_hsPending;                   // с этим соединением (учтено на accept)
            if (p > g_adm.maxPending)
            {
                fi.kind = AsdaWire::kKindPendingCap; fi.mode = 0; fi.count = (int)p; fi.limit = g_adm.maxPending;
                int sup = 0; report = RepAllow(0, &sup); fi.extra = sup;
                InterlockedIncrement(&g_admPending);
                return AsdaWire::kKindPendingCap;
            }
        }
        return 0;
    }

    // Отказ допуска соединению поколения gen: слот в сбой (кадры не принимаются, очереди выброшены — ворота DisConnect не
    //   отложат), отчёт (вне замка слота), разрыв штатным путём стока под L только своего поколения (KillIfSameGen). Отложенный
    //   разрыв fix2b, если был, выполняется им же. false — соединение уже сменилось (ничего не сделано).
    bool AdmissionReject(Slot& s, void* self, int slot, LONG gen, const AsdaWire::FailInfo& fi, bool report)
    {
        if (!self) { self = s.admThis ? s.admThis : g_lastThis; }
        bool same = false;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        if (s.resetSeen == gen && InterlockedCompareExchange(&s.resetReq, 0, 0) == gen)
        {
            same = true;
            if (!s.preQ.empty() || s.preQ.capacity()) { std::vector<uint8_t>().swap(s.preQ); }   // не выделяет
            InterlockedExchange(&s.preBytes, 0);
            if (s.txBytes > 0 || !s.txQ.empty()) { InterlockedIncrement(&g_txFailFreed); }
            TxFreeLocked(s);
            if (!s.failed) { s.failed = true; s.fail = fi; }
            s.reported = true;
        }
        LeaveCriticalSection(&s.cs);
        if (!same) { return false; }
        if (report) { ReportFn_(self, slot, fi); }
        if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { RunDeferredKill(slot); }
        else { KillIfSameGen(s, self, slot, gen); }
        return true;
    }

    // Сторож: проверка допуска молчащего соединения (клиент не прислал байт за ≤ 50 мс) и срок рукопожатия.
    void AdmissionWatch(int i, DWORD now)
    {
        Slot& s = g_slots[i];
        const LONG g = s.admitGen;
        if (g)
        {
            // ★ sec2b: «решение идёт» ставится ДО снятия admitGen — первый приём, увидевший admitGen = 0, видит и admBusy
            //   (порядок записей Interlocked) и ждёт исхода; разрыв (KillIfSameGen) выполняется до снятия отметки.
            InterlockedExchange(&s.admBusy, g);
            if (InterlockedCompareExchange(&s.admitGen, 0, g) == g)
            {
                AsdaWire::FailInfo fi; bool rep = false;
                void* self = s.admThis ? s.admThis : g_lastThis;
                const bool rej = AdmitDecide(self, i, g, fi, rep) != 0;
                if (rej) { AdmissionReject(s, self, i, g, fi, rep); }
                InterlockedExchange(&s.admBusy, 0);
                if (rej) { return; }
            }
            else { InterlockedExchange(&s.admBusy, 0); }
        }
        const LONG hp = s.hsPend;
        // Отложенный разрыв fix2b (отказ сервера до рукопожатия, ждёт первых байт клиента до PreHandshakeCloseMs) срок не отменяет:
        //   AdmissionReject выполнит его сразу (CAS deferKill).
        if (!hp || g_adm.deadlineMs <= 0 || s.dlDone == hp) { return; }
        const DWORD age = now - (DWORD)s.acceptTick;
        if ((LONG)age < 0 || age < (DWORD)g_adm.deadlineMs) { return; }
        const bool silent = s.gotByte == 0;
        // AllowLegacy=1: старый клиент мог открыть сокет заранее — не рвём. ★ sec2b (ревизия SEC2 С-1, правка ревизора fix_C1.diff):
        //   но из «незавершённых» снимаем — иначе молчащие сокеты держали MaxPendingHandshakes (и предел адреса) бессрочно и каждое
        //   новое соединение получало вид 64. dlDone — срок этого поколения обработан; CAS своего поколения: разрыв/готовность,
        //   снявшие отметку раньше, вычитают сами (−1 ровно один раз). Канал, начавший рукопожатие позже, готовность не учтёт
        //   повторно (RecvLocked снимает только hsPend ≠ 0).
        if (silent && g_allow)
        {
            InterlockedExchange(&s.dlDone, hp);
            if (InterlockedCompareExchange(&s.hsPend, 0, hp) == hp) { InterlockedDecrement(&g_hsPending); InterlockedIncrement(&g_hsSilentReleased); }
            return;
        }
        InterlockedExchange(&s.dlDone, hp);               // dlDone пишет только сторож
        void* self = s.admThis ? s.admThis : g_lastThis;
        AsdaWire::FailInfo fi; memset(&fi, 0, sizeof(fi)); fi.err = Err::Ok; fi.firstByte = -1;
        fi.kind = AsdaWire::kKindHsDeadline; fi.mode = silent ? 0 : 1;
        fi.ip = g_peerIp ? g_peerIp(self, i) : 0; fi.count = (int)age; fi.limit = g_adm.deadlineMs;
        int sup = 0; const bool rep = RepAllow(1, &sup); fi.extra = sup;
        if (AdmissionReject(s, self, i, hp, fi, rep)) { InterlockedIncrement(&g_admDeadline); }
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
            if (g_txTotalMax > 0 && (g_evictReq || g_txTotal > g_txTotalMax)) { EvictLargest(); }   // ★ sec2 (Е-2)
            const bool adm = g_admOn != 0;
            for (int i = 0; i < AsdaWire::kMaxSlots; ++i)
            {
                Slot& s = sl[i];
                if (adm && (s.admitGen || s.hsPend)) { AdmissionWatch(i, now); }   // ★ sec2: допуск / срок рукопожатия
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
        if (ciocpThis) { g_lastThis = ciocpThis; }
        // ★ sec2: ДОПУСК — первая порция нового соединения (если сторож ещё не проверил молчащее): до разбора байт (ServerAccept не
        //   выполняется). Отказ — отчёт вида 63/64, разрыв штатным путём (под L, своё поколение), −1: ReadFile не перевыставляется.
        if (s.admitGen)
        {
            const LONG g = s.admitGen;
            if (g && InterlockedCompareExchange(&s.admitGen, 0, g) == g)
            {
                FailInfo afi; bool rep = false;
                if (AdmitDecide(ciocpThis, slot, g, afi, rep) && AdmissionReject(s, ciocpThis, slot, g, afi, rep)) { return -1; }
            }
        }
        // ★ sec2b: сторож мог взять проверку этого соединения раньше (молчало ≤ 50 мс, потом прислало ClientHello) — дождаться его
        //   решения (AdmitDecide + разрыв — микросекунды; замок Ciocp L эта нить не держит, взаимной блокировки нет). Затем: при
        //   включённом допуске флаг соединения 0 — соединение уже разорвано штатным DisConnect (отказ допуска / срок; порция приёма
        //   была в пути) — байты НЕ разбирать: ServerAccept не выполняется, пара ECDH не тратится; −1 — ReadFile не перевыставлять
        //   (хвост стоковой ветки разрыва). Флаг ведёт детур SetConnectFlag — при допуске он стоит всегда (от него поколение accept).
        if (g_admOn)
        {
            for (int spin = 0; s.admBusy && spin < 5000; ++spin) { Sleep(spin < 50 ? 0 : 1); }
            if (!g_connFlag[slot]) { InterlockedIncrement(&g_admDeadRecv); return -1; }
        }
        if (len > 0 && !s.gotByte) { InterlockedExchange(&s.gotByte, 1); }   // ★ sec2: для срока рукопожатия (молчит / начал)
        FailInfo fi{};
        bool failedNow = false, doReport = false;
        const uint8_t* p = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        // ★ sec2b: то же под замком слота — разрыв сторожем по сроку рукопожатия (AdmissionReject: сбой под cs, затем DisConnect вне cs)
        //   мог пройти между проверкой выше и входом в cs; после ApplyResetLocked слот «чистый», и ClientHello разобрался бы на мёртвом
        //   слоте. DisConnect снимает флаг соединения ДО запроса сброса (ResetSlotEx), поэтому сброс, применённый здесь, флаг 0 уже видит.
        if (g_admOn && !g_connFlag[slot])
        {
            LeaveCriticalSection(&s.cs);
            InterlockedIncrement(&g_admDeadRecv);
            return -1;
        }
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

        // ★ sec2: соединение уже отвергнуто допуском (63–65) и разорвано сторожем/первым приёмом — повторно не рвём (−1: ReadFile не
        //   перевыставляется; сокет закрыт или закрывается штатным DisConnect).
        if (fi.kind >= kKindConnRate && fi.kind <= kKindHsDeadline) { return -1; }
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

    // ★ EAC ред. 3: привязка канала слота (см. AsdaServerBridge.h). Под замком слота: OnRecv/Reset того же слота сериализованы им.
    bool SlotChannelBinding(int slot, uint8_t out[AsdaSecure::kBindLen])
    {
        Slot* sl = g_slots;
        if (!sl || !out || slot < 0 || slot >= kMaxSlots) { return false; }
        Slot& s = sl[slot];
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const bool ok = !s.failed && s.chan.ChannelBinding(out);
        LeaveCriticalSection(&s.cs);
        return ok;
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
        c->txFailFreed = g_txFailFreed; c->txActive = g_txActive; c->txOverSoft = g_txOverSoft; c->txEvicted = g_txEvicted;   // ★ sec2
        c->admChecked = g_admChecked; c->admRate = g_admRate; c->admPending = g_admPending; c->admDeadline = g_admDeadline;
        c->admNoIp = g_admNoIp; c->admTableFull = g_admTableFull; c->hsPending = g_hsPending; c->hsPendingPeak = g_hsPendingPeak;
        c->admPendingIp = g_admPendingIp; c->hsSilentReleased = g_hsSilentReleased; c->txEvictRetry = g_txEvictRetry;   // ★ sec2b
        c->admDeadRecv = g_admDeadRecv;
        long now = 0, cost = 0;
        if (Slot* sl = g_slots) { for (int i = 0; i < kMaxSlots; ++i) { now += sl[i].txBytes; cost += sl[i].txCost; } }
        c->txNow = now;
        c->txCostNow = cost;
    }

    long TxFrameCost(int bytes) { return bytes > 0 ? (long)TxCost((LONG)bytes) : 0; }   // ★ sec2b (Н-6)
}
