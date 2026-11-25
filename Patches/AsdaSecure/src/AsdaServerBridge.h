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
//   ★ sec2 (15.10.2026, блок В плана альфы): Е-1 — очередь моста слота, упавшего НЕ по виду 61 (сбой шифрования отправки,
//     нарушение приёма при KillOnViolation=0, отказ допуска), освобождается сразу (MarkFail/сторож), общий счёт — без утечки;
//     Е-2 — справедливая доля общего предела (SetTxFairShare: тяжёлый слот рвётся сам, при лёгком сторож вытесняет наибольшую
//     очередь, причина 6); допуск подключений до рукопожатия (SetAdmission: предел с адреса за окно — вид 63, предел
//     незавершённых рукопожатий — 64, срок рукопожатия — 65); ускорение рукопожатия (кэш ключа подписи и пул ECDH — AsdaSecure.h,
//     SetHandshakeAccel). Порядок замков прежний: «слот → Ciocp»; таблица адресов допуска — свой SRW-замок, листовой (под ним
//     других замков не берём, под замком слота его не берём).
//   ★ sec2b (15.10.2026, ревизия SEC2 С-1, Н-1, Н-2, Н-6): С-1 — при AllowLegacy=1 молчащий сокет по сроку рукопожатия не рвётся,
//     но снимается со счёта незавершённых (иначе молчащие держали MaxPendingHandshakes вечно); Н-1 — предел незавершённых
//     рукопожатий ещё и на адрес (AdmissionCfg.maxPendingPerIp, вид 64 с FailInfo.mode = 1); Н-2 — сторож вытесняет очередь,
//     только если под замком жертвы она всё ещё наибольшая (иначе выбирает заново); Н-6 — общий предел очередей считается по
//     РЕАЛЬНОЙ памяти кадра в куче 32-битного процесса (TxFrameCost: блок данных + блок элемента deque + указатель карты).
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
    // ★ sec2 (ревизия fix2e Е-2): при общем пределе рвётся не «тот, чей кадр не влез», а слот с наибольшей очередью (сторож).
    constexpr int kSendFailTotalEvict = 6;// общий предел превышен лёгким слотом — вытеснена НАИБОЛЬШАЯ очередь процесса (этот слот)
#define ASDAWIRE_HAS_TX_TOTAL 1           // ★ fix2e: признак API общего предела (стенды, собираемые и на старых копиях моста)
#define ASDAWIRE_HAS_SEC2 1               // ★ sec2: справедливая доля общего предела, допуск подключений до рукопожатия (виды 63–65)
#define ASDAWIRE_HAS_SEC2B 1              // ★ sec2b: предел незавершённых на адрес, учёт памяти очередей по TxFrameCost, С-1, Н-2

    // ★ sec2 (блок В плана альфы, стойка в интернете): ДОПУСК ПОДКЛЮЧЕНИЙ ДО РУКОПОЖАТИЯ — виды ac.other 63–65 (выданы волне sec2).
    constexpr int kKindConnRate   = 63;   // с одного адреса больше PerIpMax новых подключений за окно PerIpWindowSec — разрыв до рукопожатия
    constexpr int kKindPendingCap = 64;   // незавершённых рукопожатий в процессе больше MaxPendingHandshakes — новое соединение разорвано
    constexpr int kKindHsDeadline = 65;   // рукопожатие не завершено за HandshakeDeadlineMs после accept — разрыв (молчащий/медленный сокет)

    // Сведения о фатальной ошибке слота (для журнала).
    struct FailInfo
    {
        AsdaSecure::Err err;      // код ошибки прослойки
        int             mode;     // режим канала на момент ошибки: 0 Unknown, 1 Secure, 2 Legacy
                                  //   (★ sec2: для 65 — 0 молчит / 1 начал и бросил; ★ sec2b: для 64 — 0 предел процесса / 1 предел адреса)
        int             phase;    // 0 — приём (клиент прислал), 1 — отправка (сбой шифрования на сервере)
        int             firstByte;// первый байт порции приёма (-1 — нет); для 58 — признак «0xFB старый клиент»
        int             bytes;    // длина порции приёма/кадра отправки
        int             kind;     // вид журнала 56..59, ★ fix2d 61 (0 — не нарушение клиента, только PatchLog)
        int             reason;   // ★ fix2d: для вида 61 — kSendFail* (иначе 0)
        int             queued;   // ★ fix2d: для вида 61 — байт в очереди моста слота в момент сбоя
        int             pending;  // ★ fix2d: для вида 61 — длина стоковой досылки (−1 — не читалась)
        int             total;    // ★ fix2e: для вида 61 — байт во ВСЕХ очередях моста процесса в момент сбоя (до освобождения
                                  //   очереди этого слота; без отвергнутого кадра); ★ sec2b (Н-6): учтённая память (TxFrameCost)
        // ★ sec2: для видов 63–65 (допуск подключений).
        uint32_t        ip;       // IPv4 пира (сетевой порядок), 0 — не определён
        int             count;    // 63: подключений с адреса в текущем окне (с этим); 64: незавершённых рукопожатий; 65: возраст, мс
        int             limit;    // 63: PerIpMax; 64: MaxPendingHandshakes; 65: HandshakeDeadlineMs
        int             extra;    // 63: окно, с; 64/65: отчётов этого вида подавлено с прошлого (ограничитель моста)
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

    // ★ sec2: ускорение рукопожатия (AsdaSecure::ServerSignerLoad / EphemeralPoolStart) — применяется в EnsureInit (лениво, на
    //   рабочей нити, не в DllMain). signerCache — держать импортированный ключ подписи; poolSize — пар ECDH в пуле заготовок
    //   (0 — без пула, генерация на месте как раньше). Умолчание: кэш вкл, пул 16. Вызывать ДО первого соединения.
    void SetHandshakeAccel(bool signerCache, int poolSize);

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
    // ★ sec2: то же с this Ciocp (ecx детура SetConnectFlag) — нужен сторожу допуска, чтобы разорвать молчащее соединение
    //   (KillIfSameGen берёт замок L этого Ciocp). Без замков, только Interlocked (зовётся под L).
    void ResetSlotEx(void* ciocpThis, int slot, int connectFlag);

    // ★ sec2: ДОПУСК ПОДКЛЮЧЕНИЙ ДО РУКОПОЖАТИЯ (стойка доступна из интернета). Проверка — ОДИН раз на соединение, до разбора
    //   первых байт (ServerAccept не выполняется): на первом приёме слота (RecvRoute) либо сторожем ≤ 50 мс после accept, если
    //   клиент молчит, — кто раньше (CAS поколения). Отказ — отчёт (вид 63/64, FailInfo.ip/count/limit) и разрыв штатным
    //   путём стока (GetConnectFlag + DisConnect под L, только своё поколение), очередь до рукопожатия выбрасывается.
    //   • perIpMax/perIpWindowMs — не больше perIpMax новых подключений с одного IPv4 за окно (фиксированное окно на адрес;
    //     таблица адресов kAdmTable записей, переполнена — пропуск, счётчик admTableFull); 0 — без предела по адресу.
    //   • maxPending — не больше maxPending соединений «accept есть, рукопожатие не завершено» на процесс (новое сверх — разрыв,
    //     вид 64); 0 — без предела. Рукопожатие завершено = канал готов (Secure после ServerHello, Legacy на первом байте).
    //   • deadlineMs — соединение, не завершившее рукопожатие за deadlineMs после accept, разрывается сторожем (вид 65); молчащий
    //     сокет (ни байта) — только при AllowLegacy=0 (старый клиент мог открыть сокет заранее). 0 — без срока.
    //     ★ sec2b (С-1): при AllowLegacy=1 молчащий сокет по сроку НЕ рвётся, но снимается со счёта незавершённых (maxPending и
    //     maxPendingPerIp его больше не видят; счётчик hsSilentReleased) — иначе молчащие держали предел бессрочно.
    //   • reportGapMs — виды 64/65 в отчёт не чаще раза в reportGapMs (подавленные — FailInfo.extra); 63 — раз на адрес за окно.
    //   • ★ sec2b (Н-1) maxPendingPerIp — не больше maxPendingPerIp незавершённых рукопожатий с ОДНОГО адреса (новое сверх — разрыв,
    //     вид 64, FailInfo.mode = 1; по процессу — mode = 0). Счёт — по живому состоянию слотов (адрес записывается при проверке
    //     допуска вместе с поколением accept; считаются слоты, чьё поколение ещё в незавершённых), утечки счёта нет. 0 — без предела.
    //   ip — IPv4 пира слота (getpeername); nullptr — без проверки по адресу. Без вызова SetAdmission допуск выключен.
    constexpr int kAdmTable = 4096;
    typedef uint32_t (*PeerIpFn)(void* ciocpThis, int slot);
    struct AdmissionCfg { int perIpMax; int perIpWindowMs; int maxPending; int deadlineMs; int reportGapMs;
                          int maxPendingPerIp;   // ★ sec2b (Н-1); агрегатная инициализация из 5 полей оставляет 0 — без предела
                        };
    void SetAdmission(const AdmissionCfg* cfg, PeerIpFn ip);

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
    //   ★ sec2b (ревизия SEC2 Н-6): общий счётчик (Counters.txTotal, FailInfo.total, справедливая доля, вытеснение) — в байтах
    //   РЕАЛЬНОЙ памяти очереди: кадр n байт стоит TxFrameCost(n). Предел очереди слота TxQueueKB — по-прежнему в байтах кадров.
    void SetTxQueueTotalMax(int maxBytes);
    // ★ sec2b (Н-6): память кадра очереди моста в куче 32-битного процесса (MSVC /MT: operator new → HeapAlloc кучи процесса).
    //   Элемент очереди — std::vector<uint8_t> (12 б) в std::deque, у которой при элементе > 8 б _DEQUESIZ = 1: на каждый кадр
    //   приходятся блок данных n б, блок элемента deque 12 б и указатель карты блоков (карта растёт удвоением — не больше 2
    //   указателей на блок). Блок кучи x86 (замер HeapWalk) = запрос, округлённый до гранулы корзины LFH (8 б до 256, 16 до 512,
    //   32 до 1 КБ, 64 до 2 КБ, 128 до 4 КБ, 256 до 8 КБ, 512 до 16 КБ), + заголовок 8 б; без LFH — не больше. Запрос vector при
    //   n ≥ 4096 — n + 35 (MSVC «большой блок»). Итог — верхняя оценка реальной памяти: TxFrameCost(n) = Блок(запрос) + Блок(12) + 8.
    long TxFrameCost(int bytes);
    // ★ sec2 (ревизия fix2e Е-2): СПРАВЕДЛИВАЯ ДОЛЯ общего предела. Постановка, после которой сумма > TxQueueTotalMax:
    //   • очередь этого слота (с кадром) ≥ средней по слотам с непустой очередью ИЛИ ≥ fairBytes («тяжёлый») — рвётся он сам
    //     (причина 4, как fix2e);
    //   • иначе («лёгкий»: честный клиент, начавший грузить карту) кадр принимается, пока сумма ≤ предел + предел/8 (жёсткий
    //     потолок), а сторож вытесняет НАИБОЛЬШУЮ очередь процесса (причина 6), пока сумма > предела. Сверх жёсткого — причина 4.
    //   fairBytes 0 — только средняя. Умолчание 256 КБ (TxQueueFairKB).
    void SetTxFairShare(int fairBytes);

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

    // ★ EAC ред. 3 (16.10.2026, контракт eac/CONTRACT.md §8.1): привязка канала слота — ServerChannel::ChannelBinding текущего
    //   соединения слота (32 б, одинакова у клиента и сервера этого соединения). Берёт замок слота и применяет отложенный сброс,
    //   как SlotMode, — НЕ звать под замком Ciocp. false — моста нет / слот вне диапазона / режим Unknown или Legacy /
    //   рукопожатие не завершено / слот сброшен (разрыв); out при false не трогается.
    bool SlotChannelBinding(int slot, uint8_t out[AsdaSecure::kBindLen]);

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
                      long txTotal; long txTotalPeak; long txTotalOver; long txNoMem;
                      // ★ sec2 (Е-1/Е-2): очередей сбойных слотов (не вид 61), освобождённых сразу; слотов с непустой очередью
                      //   сейчас; постановок «лёгкого» слота сверх предела (принято, назначено вытеснение); вытеснено наибольших
                      //   очередей (причина 6).
                      long txFailFreed; long txActive; long txOverSoft; long txEvicted;
                      // ★ sec2 (допуск): проверено соединений, отказов по адресу (63), по пределу незавершённых (64), по сроку (65),
                      //   адрес не определён, таблица адресов полна (пропуск); незавершённых рукопожатий сейчас / наибольшее.
                      long admChecked; long admRate; long admPending; long admDeadline; long admNoIp; long admTableFull;
                      long hsPending; long hsPendingPeak;
                      // ★ sec2b: отказов 64 по пределу С АДРЕСА (Н-1; входят и в admPending); молчащих сокетов, снятых со счёта
                      //   незавершённых по сроку при AllowLegacy=1 (С-1); повторных выборов жертвы вытеснения (Н-2: под её замком
                      //   очередь уже не наибольшая); Σ учтённой памяти очередей по слотам (Н-6; = txTotal вне операций).
                      long admPendingIp; long hsSilentReleased; long txEvictRetry; long txCostNow;
                      // ★ sec2b: порций приёма соединения, уже разорванного допуском/сроком (сторож решил раньше) — байты не разбирались.
                      long admDeadRecv; };
    void GetCounters(Counters* c);
}
