// Copyright (c) 2026 @sitxovski (Discord)
// AsdaServerBridge.h — мост между нативными трамплинами серверной DLL и AsdaSecure::ServerChannel.
//
// Назначение: дать naked-трамплинам патча (L07 в LoginPatch.dll, P61 в AsdaPatch.dll) простые
// C-функции без имён C++ и без исключений, наружу торчащих. Вся криптология — в ServerChannel;
// здесь только таблица каналов по слоту сокета (0..kMaxSlots-1), per-slot блокировка и два
// скретч-буфера (вход/выход) на слот, живущие до синхронного потребления стоковой функцией.
//
// Поток вызовов в DLL (идентично для LM и GS, разные адреса):
//   accept/disc  → трамплин SetConnectFlag  → AsdaWire::ResetSlot(slot)
//   приём с сокета (IoWorkerThread, клиентский слот <10000)
//                → трамплин recv-callsite   → AsdaWire::RecvRoute(this,slot,buf,n,&out)
//                  • расшифровка в скретч, возврат старого потока для стоковой recv-функции;
//                  • ServerHello/очередь исходящего — через зарегистрированный SendRaw (стоковый Ciocp::Send);
//                  • ★ В7d: нарушение целостности → отчёт (журнал/PatchLog) + РАЗРЫВ штатным путём стока
//                    (зарегистрированный KillFn = Ciocp::GetConnectFlag + Ciocp::DisConnect), возврат −1 —
//                    трамплин уходит на хвост стоковой ветки разрыва (без ReadFile на закрытом сокете).
//   отправка прикладного кадра (Ciocp::Send call-site, слот<550)
//                → трамплин send-callsite   → AsdaWire::SendRoute(this,slot,frame,n)
//                  • ★ fix2 (Б-2): шифрование И стоковый Ciocp::Send одним куском под замком слота — порядок номеров
//                    кадров на проводе = порядок шифрования (в GS одному слоту шлют до 21 нити карт + нить 6004);
//                  • при незавершённом рукопожатии кадр в очереди канала (уйдёт за ServerHello);
//                  • ошибка шифрования (сбой CNG/кадр > 64 КБ) → кадр не уходит, слот помечен; разрыв —
//                    на ближайшем приёме этого слота (из send-пути DisConnect не зовём: чужие локи вызывающего).
//                  • ★ fix2d: Secure-кадр, который досылка стока не вместит (проверка под замком Ciocp), — в очередь слота
//                    моста (выталкивает сторож); отказ стока / переполнение очереди → вид 61, разрыв сторожем.
//                  • ★ fix2e: общий предел очередей моста на процесс (TxQueueTotalMB, Interlocked-счётчик) и перехват
//                    std::bad_alloc/std::exception на всех путях с выделением памяти ВНУТРИ моста (под замком слота) —
//                    превышение / нехватка памяти → вид 61 (причины 4/5), разрыв этого слота; исключение наружу (в naked-
//                    трамплин и сток) не выходит, процесс не падает.
//
// Межсерверные слоты (10000..10099) НЕ шифруются (связь наших под-серверов в доверенной сети).
//
// Потоки: IOCP крутит НЕСКОЛЬКО рабочих потоков; Ciocp::Send берёт свой лок уже ПОСЛЕ нашего call-site,
// поэтому per-slot состояние (Session.txSeq/rxSeq, накопитель) мы защищаем СВОЕЙ критической секцией.
// ★ fix2 (Б-1) ПОРЯДОК ЗАМКОВ: только «замок слота cs_X → замок Ciocp L» (L = Ciocp+0x60D1830, его берут ровно 9
//   функций Ciocp GS / 8 LM; verify_traffic.py проверяет, что из-под L нет пути к площадкам отправки/приёма).
//   ResetSlot зовётся ПОД L (DisConnect → 0x563B60 → SetConnectFlag; accept 0x563C50; ошибка WriteFile в Send) и
//   замок слота НЕ берёт — только ставит запрос сброса; сброс применяется под cs_X на входе в RecvRoute/OnRecv/
//   SendRoute/SlotFailed/SlotMode. KillFn и ReportFn зовутся ВНЕ слотового лока.
#pragma once
#include <cstdint>
#include "AsdaSecure.h"

namespace AsdaWire
{
    constexpr int kMaxSlots = 550;        // как у Ciocp (a2 >= 0x226 — отказ)

    // ★ В7d: виды журнала античита ac.other для нарушений канала (выданы волне В7d: 56–59).
    constexpr int kKindBadTag    = 56;    // тег GCM не сошёлся — порча/подмена кадра
    constexpr int kKindReplay    = 57;    // номер кадра не «следующий» — повтор/переупорядочивание
    constexpr int kKindHandshake = 58;    // мусор до рукопожатия / сбой рукопожатия / старый клиент при AllowLegacy=0
    constexpr int kKindFormat    = 59;    // длина кадра вне допустимого (превышение предела 64 КБ / меньше тега)
    // ★ fix2d (П-2): шифрованный кадр Secure-слота не может быть доставлен стоком (отказ стокового Send / переполнение очереди
    //   моста / сток потерял кадр) — поток номеров у клиента был бы разорван (Replay). Разрыв с причиной (сбой сервера, не клиента).
    constexpr int kKindSendFail  = 61;    // ac.other 61 (60 занят SQL A11c)

    // ★ fix2d: причина П-2 (FailInfo.reason, журнал v[0]).
    constexpr int kSendFailRefused  = 1;  // стоковый Send вернул 0 при открытом соединении (ошибка WriteFile — сток закрыл сокет)
    constexpr int kSendFailQueueMax = 2;  // очередь моста слота больше TxQueueKB (клиент долго не читает сокет)
    constexpr int kSendFailLost     = 3;  // сток потерял кадр: пул перекрытых структур исчерпан (Send вернул 1 без записи) или
                                          //   досылка без записи в полёте не помещается в буфер 0x1000 (сток отправил бы мусор)
    // ★ fix2e (ревизия fix2d, Ф-1): общий предел и нехватка памяти.
    constexpr int kSendFailTotalMax = 4;  // сумма очередей моста всех слотов процесса больше TxQueueTotalMB (массовое «не читают»)
    constexpr int kSendFailNoMem    = 5;  // нехватка памяти: std::bad_alloc (или иное исключение выделения) на пути отправки/приёма
                                          //   моста (очередь слота, буферы шифрования, очередь до рукопожатия) — перехвачено в мосте
#define ASDAWIRE_HAS_TX_TOTAL 1           // ★ fix2e: признак API общего предела (стенды, собираемые и на старых копиях моста)

    // Сведения о фатальной ошибке слота (для журнала).
    struct FailInfo
    {
        AsdaSecure::Err err;      // код ошибки прослойки
        int             mode;     // режим канала на момент ошибки: 0 Unknown, 1 Secure, 2 Legacy
        int             phase;    // 0 — приём (клиент прислал), 1 — отправка (сбой шифрования на сервере)
        int             firstByte;// первый байт порции приёма (-1 — нет); для 58 — признак «0xFB старый клиент»
        int             bytes;    // длина порции приёма/кадра отправки
        int             kind;     // вид журнала 56..59, ★ fix2d 61 (0 — не нарушение клиента, только PatchLog)
        int             reason;   // ★ fix2d: для вида 61 — kSendFail* (иначе 0)
        int             queued;   // ★ fix2d: для вида 61 — байт в очереди моста слота в момент сбоя
        int             pending;  // ★ fix2d: для вида 61 — длина стоковой досылки (−1 — не читалась)
        int             total;    // ★ fix2e: для вида 61 — байт во ВСЕХ очередях моста процесса в момент сбоя (до освобождения
                                  //   очереди этого слота; без отвергнутого кадра)
    };

    // Отправить СЫРЫЕ (уже готовые к проводу) байты в сокет слота — стоковый Ciocp::Send.
    // ciocpThis — значение this (ecx) с площадки, slot — номер сокета.
    //   ★ fix2: возвращает итог стокового Send (1 — принят, 0 — отказ/слот закрыт) — его отдаёт SendRoute.
    typedef int (*SendRawFn)(void* ciocpThis, int slot, const void* data, int len);
    // ★ В7d: закрыть соединение слота штатным путём стока (GetConnectFlag → DisConnect).
    typedef void (*KillFn)(void* ciocpThis, int slot);
    // ★ В7d: отчёт о нарушении (PatchLog с ограничителем + журнал ac.other). Зовётся ДО KillFn (IP ещё читается).
    typedef void (*ReportFn)(void* ciocpThis, int slot, const FailInfo& fi);
    // ★ В7d: однократное уведомление о ленивой инициализации (CNG открыт? ключ загружен?) — строка в PatchLog.
    typedef void (*InitNotifyFn)(bool cngOk, bool keyOk);

    // Запомнить параметры. БЕЗОПАСНО звать из DllMain: НЕ открывает CNG и НЕ грузит bcrypt
    //   (это сделает ленивый EnsureInit на первом вызове трамплина, уже на рабочем потоке IOCP).
    // keyPath — файл закрытого ключа рядом с DLL; allowLegacy — принимать старый клиент (0xFB).
    void Configure(AsdaSecure::SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw);

    // ★ В7d: обработчики нарушений. kill=nullptr или killOnViolation=false — только отчёт и отброс кадра.
    void SetFailureHooks(KillFn kill, ReportFn report, InitNotifyFn initNotify, bool killOnViolation);

    // Полная инициализация (Configure + немедленный EnsureInit). Для стенда/теста ВНЕ DllMain.
    //   Возвращает false, если ключ не загружен (тогда шифрование не включается).
    bool Init(AsdaSecure::SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw);

    // Ленивая инициализация: открыть CNG, выделить таблицу слотов, загрузить ключ. Один раз.
    //   Зовётся автоматически из ResetSlot/OnRecv/OnSend. true — ключ загружен, шифрование возможно.
    bool EnsureInit();

    bool IsReady();                       // EnsureInit выполнен и ключ загружен
    // ★ fix2 (НИЗК-5): EnsureInit выполнен, но CNG не открылся (таблицы слотов нет) — байты идут как есть
    //   (AllowLegacy=1: старые клиенты работают; AllowLegacy=0: соединения закрываются на первом приёме).
    bool IsBypass();
    void SetAllowLegacy(bool allow);

    // ★ В7d: проверка файла закрытого ключа БЕЗ CNG (можно из DllMain): есть, ровно 104 байта, метка ASDAKEY1.
    //   false — в why причина по-русски (для PatchLog). Содержимое ключа не выводится и в память не копируется
    //   дальше стекового буфера, который затирается.
    bool CheckKeyFile(const wchar_t* path, wchar_t* why, int whyLen);

    // Вид журнала для ошибки (56..59; 0 — не нарушение клиента).
    int KindForErr(AsdaSecure::Err e);

    // ★ В7d: ограничитель частоты строк PatchLog (общий на процесс): не больше perMinute строк в минуту.
    //   true — строку писать; *suppressed — сколько строк подавлено с прошлой разрешённой (сбрасывается).
    void SetLogPerMinute(int perMinute);
    bool LogAllow(int* suppressed);

    // Сброс канала слота (новое соединение / разрыв). Безопасно вне диапазона.
    // ★ fix2 (Б-1): НЕ блокируется и замок слота НЕ берёт (зовётся под замком Ciocp) — InterlockedIncrement запроса;
    //   сброс применяется под замком слота при следующем обращении к слоту (до первого чтения нового клиента).
    //   ★ fix2b: connectFlag — второй аргумент стокового SetConnectFlag (1 accept / 0 разрыв); стенды зовут ResetSlot(X) как accept.
    void ResetSlot(int slot, int connectFlag = 1);

    // ★ fix2b: КАДРЫ СЕРВЕРА ДО РУКОПОЖАТИЯ (отказы сразу после accept: LM 4101 код 22 / 2253 + DisConnect, GS 6004 тип 14/15
    //   + DisConnect). Пока режим канала не известен, SendRoute кладёт кадры в очередь слота (не больше maxBytes; сверх —
    //   отбрасываются и считаются); очередь уходит сразу за ServerHello (Secure, шифрованная) или как есть (Legacy) на первом
    //   приёме. DisConnect, вызванный при невыданной очереди, откладывается (DisconnectGate) до её выдачи либо до closeDelayMs
    //   без единого байта клиента (сторож-нить). DisConnect из IoWorkerThread [ioWorkerLo, ioWorkerHi) не откладывается.
    void SetPreHandshake(int maxBytes, int closeDelayMs, uintptr_t ioWorkerLo, uintptr_t ioWorkerHi);
    // ★ fix2c (Н-2): пауза между выдачей очереди до рукопожатия и отложенным разрывом, мс (PreHandshakeLingerMs, 150; 0 — сразу).
    //   Сокеты стока закрываются с SO_LINGER {1,0} (RST) — без паузы отказ догоняется сбросом; сток GS сам ждал Sleep(100).
    void SetLingerMs(int ms);

    // ★ fix2c (Н-1, приём): стоковый разборщик приёма (GS sub_563C20, LM sub_415600: thiscall(this, buf, size, slot), ret 0xC).
    //   Зарегистрирован — RecvRoute сам отдаёт ему расшифрованный поток кусками ≤ 0x1000 − 9 (буфер сборки слота стока 0x1000,
    //   обрывок заголовка < 10 б) и возвращает 0/−1; не зарегистрирован (стенды) — возвращает указатель и длину, как раньше.
    typedef int (*SinkFn)(void* ciocpThis, const void* data, int len, int slot);
    void SetRecvSink(SinkFn sink);

    // ★ fix2d (П-1): РАСКЛАДКА СТОКОВОГО Ciocp::Send — чтобы мост НЕ отдавал стоку кадр, который сток сотрёт вместе с досылкой.
    //   Дизасм GS 0x561F20 / LM 0x413AB0 (одна библиотека Ciocp, смещения совпадают): замок L = CRITICAL_SECTION this+lockOff
    //   (0x60D1830; Send/SendTemp берут его первым делом — RAII 0x568D50/0x41A620 → EnterCriticalSection); сессия слота =
    //   [this+sessPtrOff (0x60D1898)] + slot·sessStride (0xA0BE); +connOff (4) dword флаг соединения; +inFlightOff (8) byte
    //   «запись в полёте»; +pendingOff (0xA0B2) dword длина досылки (буфер +0xB2, 0xA000 б). Send при pending + n ≥ pendingLimit
    //   (0x9F9C) memset досылки, pending=0, возврат 0 — стираются уже зашифрованные кадры. Ветка «досылка без записи в полёте»
    //   копирует досылку в буфер записи directMax (0x1000) — больше не помещается.
    //   Мост читает поля ПОД L (сам входит в L под замком слота: порядок «слот → L»; стоковый Send входит в L повторно — замок
    //   рекурсивный), там же решает и там же зовёт стоковый Send — атомарно относительно SendTemp из IoWorkerThread.
    //   nullptr — раскладки нет (стенды старого типа): проверки места нет, поведение fix2c + П-2 по итогу Send.
    struct StockSendLayout
    {
        uint32_t lockOff, sessPtrOff, sessStride, connOff, inFlightOff, pendingOff;
        int32_t  pendingLimit, directMax;
    };
    void SetStockSendLayout(const StockSendLayout* layout);
    // ★ fix2d (П-1): предел очереди шифрованных кадров слота в мосте, байт (TxQueueKB, умолчание 1 МБ). 0 — без очереди
    //   (досылка стока полна → сразу П-2). Превышение — П-2 (вид 61, причина kSendFailQueueMax).
    void SetTxQueueMax(int maxBytes);
    // ★ fix2e (ревизия fix2d, Ф-1): ОБЩИЙ предел очередей моста на процесс, байт (TxQueueTotalMB, умолчание 64 МБ; 0 — без общего
    //   предела, только для стендов). Учёт — Interlocked-счётчик: место резервируется ДО выделения памяти под кадр (сумма
    //   принятых в очереди кадров никогда не больше предела), освобождается при выталкивании / сбросе / разрыве слота.
    //   Превышение — П-2 этому слоту (вид 61, причина kSendFailTotalMax).
    void SetTxQueueTotalMax(int maxBytes);

    // Ворота входа Ciocp::DisConnect (детур, без замка слота: вход бывает под замком Ciocp). true — сток не выполнять, вернуть 1.
    bool DisconnectGate(void* ciocpThis, int slot, uintptr_t retAddr);

    // ★ В7d: приём с маршрутизацией. >0 — *out/длина расшифрованного СТАРОГО потока для стоковой recv-функции
    //   (per-slot скретч, жив до возврата из неё); 0 — отдавать нечего (рукопожатие/неполный кадр/кадр отброшен);
    //   −1 — нарушение целостности: отчёт сделан, соединение закрыто KillFn — вызывающий НЕ зовёт стоковую
    //   recv-функцию и уходит на хвост стоковой ветки разрыва.
    int RecvRoute(void* ciocpThis, int slot, const void* in, int len, const uint8_t** out);

    // Приём (низкий уровень, без отчёта/разрыва): расшифровать in[0..len) для слота. Возврат — указатель на
    //   расшифрованный СТАРЫЙ поток и его длина в *outLen (0 — целого кадра пока нет / рукопожатие).
    //   nullptr + *outLen==0 + SlotFailed — ошибка целостности.
    const uint8_t* OnRecv(void* ciocpThis, int slot, const void* in, int len, int* outLen);

    // ★ fix2 (Б-2): отправка прикладного кадра frame[0..len) АТОМАРНО под замком слота: применить запрос сброса,
    //   зашифровать и тут же отдать шифротекст стоковому Ciocp::Send (SendRawFn, берёт L). Возврат — итог стокового
    //   Send; 1 — кадр отложен до рукопожатия (в очереди канала); 0 — слот в ошибке / сбой шифрования (кадр не ушёл,
    //   слот помечен, отчёт сделан; разрыв на ближайшем приёме). Прежний OnSend (указатель на скретч слота, Send
    //   вызывался трамплином ПОСЛЕ выхода из замка) удалён: он и был гонкой Б-2.
    //   ★ fix2e: исключений не бросает (как и RecvRoute/OnRecv): сбой выделения памяти внутри → 0, слот в сбое вида 61 причина 5.
    int SendRoute(void* ciocpThis, int slot, const void* frame, int len);

    // Был ли последний OnRecv/SendRoute слота фатальной ошибкой (для журналов/кика). true — закрыть слот.
    //   ★ fix2: SlotFailed/SlotMode берут замок слота (и применяют отложенный сброс) — НЕ звать под замком Ciocp.
    bool SlotFailed(int slot);

    // Режим слота (для журнала): 0 Unknown, 1 Secure, 2 Legacy.
    int SlotMode(int slot);

    // ★ В7d: счётчики (стенд/PatchLog): разрывов по нарушению, отчётов, подавленных строк журнала.
    //   ★ fix2: resetsApplied — применённые отложенные сбросы; bypass — порций, прошедших как есть при сбое CNG.
    //   ★ fix2b: preQueued/preFlushed/preDropped — кадры сервера до рукопожатия (в очередь / выдач очереди / отброшено сверх
    //   PreHandshakeQueueKB); deferredCloses — отложенных DisConnect; deferTimeouts — из них закрыто сторожем по сроку.
    struct Counters { long kills; long reports; long logSuppressed; long sendFails; long resetsApplied; long bypass;
                      long preQueued; long preFlushed; long preDropped; long deferredCloses; long deferTimeouts;
                      long deferStale;   // ★ fix2c (Н-3): отложенных разрывов, снятых из-за сброса слота (соединение уже закрыто)
                      long overSend;     // ★ fix2c (Н-1): вызовов стокового Send длиннее 0x1000 (должно быть 0)
                      // ★ fix2d (П-1/П-2): кадров в очередь моста (досылка стока не вмещала / очередь непуста), выдано из очереди
                      //   стоку, наибольшая очередь слота (байт), сбоев П-2 по причинам 1/2/3, разрывов П-2 сторожем, разрывов
                      //   П-2, снятых сбросом слота (сток уже закрыл), очередей, выброшенных сбросом/закрытием слота.
                      long txQueued; long txFlushed; long txPeak; long txRefused; long txOverflow; long txLost;
                      long txKills; long txKillStale; long txDropped;
                      long txNow;        // ★ fix2d: байт в очередях моста сейчас (сумма по слотам; стенд — память освобождена)
                      // ★ fix2e: общий счётчик объёма очередей (Interlocked; = txNow вне операций), наибольший принятый общий
                      //   объём, сбоев П-2 по причинам 4 (общий предел) и 5 (нехватка памяти).
                      long txTotal; long txTotalPeak; long txTotalOver; long txNoMem; };
    void GetCounters(Counters* c);
}
