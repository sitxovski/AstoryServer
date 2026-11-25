// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P101 — ПОДАРОК ИЗ КЭШ-МАГАЗИНА РАБОЧЕЙ СИСТЕМОЙ (02.11.2026, решение владельца; AsdaPatch v58 поверх v57 P100).
//  Проект: Reports/cash_gift/PROJECT_P101.md §1–§2, §7, §8. Контракты: re/billing.md, re/client.md §2, re/relay.md,
//  REPORT.md §1–2, p101/PROTOCOL_GP7_GIFT.md (§5 — окончательный), p101/CLIENT_DONE.md. Итог волны: p101/DLL_DONE.md.
//
//  ── ЧТО В СТОКЕ ──
//  [ОРИГИНАЛ] В GameServer есть только ПРИНИМАЮЩАЯ половина подарка: ответ БД 2133 → 5073 (sub_513240), получатель 5076
//  (recvChatResponseUserCharChargeShopGift@0x513330) → DB 2134 → 2135 (sub_513910) → 5078 получателю и 5077 отправителю,
//  отправитель 5077 (sub_513DF0) → локальное списание sub_43FC70(…,0,0) мимо GP7 + DB 2136 + 5075. ОТПРАВЛЯЮЩЕЙ половины нет ни в
//  одной сборке: обработчиков 5072/5074 нет (push 13D0h/13D2h = 0; диспетчер sub_42A9D0 отдаёт их в default), отправки DB 2132
//  нет (push 854h = 0), отправки 5076 нет (push 13D4h = 0). Она [ВОССТАНОВЛЕНА ПО КОНТРАКТУ] соседних половин: что шлёт клиент
//  (re/client.md §2: 5072 тело 20 б, 5074 тело 187 б), что ждёт DBM (2132 35 б: [1] группа, [15..34] имя — re/billing.md §2),
//  что читает получатель (5076 237 б — раскладка по recvChatResponse…Gift, REPORT.md §2 / re/relay.md §3.1, конструктор пакета
//  стока sub_517110), что приходит назад (5077 61 б). Деньги — через шлюз GP7 новой парой 0x52/0x53 (PROTOCOL_GP7_GIFT.md).
//
//  ── ТОЧКИ (бит Sites) ──
//   A (1) 5072 0x13D0 — диспетчер клиента sub_42A9D0, `jmp [ecx*4+42F2C0h]` @0x42AD02 (7 б): индекс таблицы 0x42F370 для
//         5072/5074 = 43 = default 0x42F020 (там P13). Конверт как у 5070 (sub_524390 анти-повтор, sub_523F00 подпись 20 б),
//         «душа» sub_52EEA0 (как case 5070), sub_52BFF0, имя: правила P68 (кавычка/управляющие не уходят в '%s' DBM), ≠ своё
//         (5073 код 5) → DB 2132. Ответ 2133 → 5073 — СТОК (sub_513240); call @0x4303DE перенацелен: маршрут получателя
//         запоминается для отправителя (слот + учётка), затем сток.
//   B (2) 5074 0x13D2 — тот же стаб. Конверт/анти-повтор (подпись 187 б), sub_52BFF0, «одержим» sub_52EE40 при режиме 1 (как
//         5070 → у подарка 5075 код 0), блок «в полёте» по учётке (MaxInFlight), маршрут из тела [176..186] = последний 2133 этого
//         отправителя (не старше RouteMaxAgeSec), UserIndex получателя ≠ свой; коды — проверки CharChargeShopBuy@0x511DA0
//         (sub_532A90 / sub_532B10 + витрина dword_5F5E9C[код] == код, у item_list байт +36 ∈ {0,3}, режим ≠ 0), позиции подряд
//         с первой; сумма — ТОЛЬКО по таблицам GS (item_table +41 / Function_Table +33), клиентских цен нет; потолок 100 000 000
//         (5070 сравнивал с адресом &unk_5F5E100 = то же число); CUser+0x1A4 (sub_43FC20) ≥ сумма, иначе 5075 код 2 (loc 6892
//         «мало кэша»); опции item_list — сервером, как в 5070 (sub_4A7EE0/sub_4A7FC0 по item_table +18/+22), клиентские
//         опции не берутся. → 0x52 HOLD (157 б) в GP7 через sub_5646C0(…, 82, 157, 93, …, sub_4C0250(поток)), как 0x50.
//   C (2) ответ 0x53 — цепочка сравнений ConnectSocketMsgProcess (0x0B/0x51/0x5B), хвост `jmp 0x43462B` @0x42FC62 (5 б) →
//         стаб: 0x53 → разбор, иначе хвост. HOLD 1 → кэш абсолютно (sub_43FC70(…,бал,0,1), как 2601) и 5076 237 б в реле
//         (sub_5646C0(…, 5076, 237, sub_4C0A90(поток), тело, UserNum получателя)); 5 → повтор HOLD тем же ключом ≤ 3 раз через
//         1,5 с, затем 5075 код 0 + журнал 162; 2 → 5075 код 2; 0/3/4 → 5075 код 0 (161). Settle 1 → кэш абсолютно + 5075 по коду
//         5077; 5 → повтор ≤ 3; 3/4/0 → журнал 162 (рассинхрон, ручная сверка) + 5075.
//   D (8) получатель — call sub_4D6A70 @0x5134B3 (проверка места: план раскладки), call sub_4D6740 @0x513558 (ячейка позиции из
//         плана), чтение FT+13 @0x5136DA ([ИСПРАВЛЕНИЕ 300]: заряды i32 P100_Charges вместо u8 стока), call sub_4D63F0 @0x513D31
//         в sub_513910 (запись со слиянием P100_WriteMerged + итог ячейки в прежние записи 5078), call sub_513910 @0x43047A
//         (ошибка БД 2135 → P100_CancelBatch), call recvChatResponse…Gift @0x430412 ([ИСПРАВЛЕНИЕ] получателя нет в слоте или
//         слот занят другой учёткой — сток молча выбрасывал 5076, деньги висели; теперь 5077 код 0 → возврат). Слияние зарядов —
//         только при P100_Active() и бите 8 (P100_SiteOn(7) по контракту P100 всегда 0 — бит подарка читает P101). Журнал 159
//         (принято, Orderidx из [78..81]) / 160 (отказ получателя).
//   E (4) 5077 — call sub_513DF0 @0x430446 перенацелен на замену тела: запись «в полёте» по UserNum [25] + сумме [29] + кодам
//         [33..]; [0]=1 → 0x52 COMMIT, 0/2 → REFUND. [ИСПРАВЛЕНИЕ] локального sub_43FC70(…,0,0) нет (деньги ведёт GP7); кэш и 5075 —
//         по ответу 0x53, 5075 — только если в слоте та же учётка (сток сверял один UserNum). DB 2136 UPGiftUser — как сток (42 б).
//   F таблица «в полёте» — глобальная в DLL (не в CUser): {ключ 8 б, Orderidx, учётка/uid/Charidx/UserNum/имя отправителя,
//         2133 получателя, коды, таблицы, опции, сумма, тики}. Тайм-аут HoldTimeoutSec — БЕЗ автовозврата (журнал 162, блок
//         отправителя снимается, запись живёт ещё час для позднего 5077/0x53). Выход отправителя запись не трогает.
//   Повторы 0x52 (status 5 / сбой отправки) — фоновая нить DLL (только sub_5646C0 в сокет шлюза, CUser не трогает); всё, что
//   касается CUser и клиента, — в нитях карт (диспетчеры стока).
//
//  Ключи [P101_CashGift]: Enabled (0), Sites (маска 1/2/4/8; шаблон 1 — первый шаг PROJECT §7), HoldTimeoutSec (120), SettleMaxSec
//  (1800), MaxInFlight (1), RouteMaxAgeSec (300), LogChannel (22). Бит 2 без бита 4 недопустим (сток списал бы ещё и локально) —
//  бит 4 включается сам; бит 2 без бита 1 бесполезен (нет маршрута 2133) — бит 1 включается сам; оба — журнал 163.
//  ── РЕВИЗИЯ 02.11 (REVIEW_DLL.md) ──
//  Б1 таблицы при установке не проверяются (их ещё нет — DllMain раньше загрузчика GS); В1 settle повторяется до ответа GP7 с паузой
//  1,5 → 5 → 30 с не дольше SettleMaxSec (затем 162); В2 2135 при пустом/чужом слоте получателя — 5077 по исходу БД без записи в чужой
//  CUser; М1 2133 берётся только на последний 5072; М2 5077 — учётка слота, затем старшая; М3 второй 5074 «в полёте» — молча (161);
//  М6 бит 2 → бит 1; М7 шаблон Sites=1; М8 ключ: система в [1], время UNIX в [4..7]; М9 8 пакетов P100 на получателя, эхо закрытой
//  записи в 0x53 — не 162.
//  Журнал ac.other 158–163 (158 отправлено, 159 получено, 160 отказ получателя → возврат, 161 отказ GP7, 162 hold без исхода /
//  рассинхрон, 163 выключение/коррекция настройки). Без ограничителя: каждая строка — событие с деньгами.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

namespace
{
    const wchar_t* kSec = L"P101_CashGift";   // секция patches.ini

    // ── виды журнала ac.other (ac-journal-p53.md §9: следующий свободный после P100 — 158) ──
    constexpr BYTE kKindSent     = 158;   // HOLD принят GP7, 5076 ушёл в реле
    constexpr BYTE kKindRecv     = 159;   // получатель принял 5076 (раскладка готова, DB 2134 ушёл)
    constexpr BYTE kKindRefuse   = 160;   // отказ получателя (5077 0/2) → возврат
    constexpr BYTE kKindGp7      = 161;   // отказ GP7 на HOLD
    constexpr BYTE kKindStuck    = 162;   // hold без исхода / рассинхрон — ручная сверка
    constexpr BYTE kKindOff      = 163;   // выключение / коррекция настройки

    // ── биты Sites ──
    constexpr DWORD kBit5072 = 1, kBit5074 = 2, kBitSettle = 4, kBitRecv = 8;

    // ── опкоды ──
    constexpr int kOp5072 = 5072, kOp5073 = 5073, kOp5074 = 5074, kOp5075 = 5075, kOp5076 = 5076, kOp5077 = 5077;
    constexpr int kOpDb2132 = 2132, kOpDb2136 = 2136;
    constexpr int kOpGiftReq = 0x52, kOpGiftRes = 0x53;   // шлюз GP7
    constexpr int kGp7Conn = 93;                          // индекс исходящего соединения GP7 (sub_4F60E0 case 137/153: литерал 93)

    // ── длины ──
    constexpr int kBody5072 = 20, kBody5074 = 187;        // тела клиента (re/client.md §2)
    constexpr int kEnvHead = 33;                          // 9 заголовок + 8 секрет + 16 MD5 (CharChargeShopBuy: тело с a3+33)
    constexpr int kLen2132 = 35, kLen5073 = 34, kLen5075 = 6, kLen5076 = 237, kLen5077 = 61, kLen2136 = 42;
    constexpr int kLenGiftReq = 157, kLenGiftRes = 28;
    constexpr int kSumCap = 100000000;                    // потолок суммы (5070: BuyCash >= &unk_5F5E100 = 0x5F5E100)

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kMaxUsers   = 0x226;                  // 550 слотов (sub_5328F0)
    constexpr int   kOffUserIndex = 0x174, kOffName = 0x178, kOffSlot = 0x18C;   // учётка, имя, слот персонажа
    constexpr DWORD kItemTablePtr = 0x005F5E98;           // dword_5F5E98 → item_table, запись 71 б, индекс (код − 20551)
    constexpr DWORD kFuncTablePtr = 0x005F5E70;           // dword_5F5E70 → Function_Table, запись 48 б, индекс (код − 1)
    constexpr DWORD kSellTablePtr = 0x005F5E9C;           // dword_5F5E9C → витрина SellItemTable: [код] == код
    constexpr DWORD kSellCountPtr = 0x005F5EC4;           // dword_5F5EC4 → число ячеек витрины
    constexpr int   kItemBase = 20551;

    // ── стоковые функции (thiscall через __fastcall: edx — пустышка) ─────────
    typedef BYTE*       (__fastcall *PFN_GetUser)(void* mgr, void* edx, int userNum);                              // sub_5324A0 ret 4
    typedef int         (__fastcall *PFN_UserIndex)(void* mgr, void* edx, int userNum);                            // sub_5324F0 ret 4
    typedef char        (__fastcall *PFN_CharIdx)(void* mgr, void* edx, int userNum);                              // sub_532530 ret 4
    typedef const char* (__fastcall *PFN_Name)(void* mgr, void* edx, int userNum);                                 // sub_532570 ret 4
    typedef int         (__fastcall *PFN_Uid)(void* mgr, void* edx, BYTE* out, int userNum);                       // sub_539180 ret 8
    typedef int         (__fastcall *PFN_Replay)(void* mgr, void* edx, DWORD lo, DWORD hi, int userNum, const char* fn);   // sub_524390 ret 10h
    typedef int         (__fastcall *PFN_Sign)(void* mgr, void* edx, BYTE* frame, int len, int userNum, int mode); // sub_523F00 ret 10h
    typedef char        (__fastcall *PFN_Busy)(void* mgr, void* edx, int userNum, int opcode);                     // sub_52BFF0 ret 8 (шлёт 6001)
    typedef BOOL        (__fastcall *PFN_UserPred)(void* mgr, void* edx, int userNum);                             // sub_52EEA0 / sub_52EE40 ret 4
    typedef int         (__fastcall *PFN_GetCash)(void* param, void* edx, int userNum);                            // sub_43FC20 ret 4
    typedef void        (__fastcall *PFN_SetCash)(void* param, void* edx, int userNum, int v, int add, int set);   // sub_43FC70 ret 10h
    typedef int         (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, void* buf, int a6, int a7);   // sub_4C28F0 ret 18h
    typedef int         (__fastcall *PFN_ConnSend)(void* net, void* edx, int op, int len, int conn, void* body, int a6);           // sub_5646C0 ret 14h
    typedef int         (__fastcall *PFN_TrInt)(void* tr, void* edx);                                              // sub_4C0A90 / sub_4C0A30 / sub_4C0250
    typedef char        (__fastcall *PFN_MgrByte)(void* mgr, void* edx);                                           // sub_40C960 / sub_40E110 / sub_40E0F0
    typedef char        (__cdecl    *PFN_Byte)();                                                                  // sub_4A7EA0 / sub_4A7EB0
    typedef BOOL        (__cdecl    *PFN_IsCode)(int code);                                                        // sub_532A90 / sub_532B10
    typedef short       (__stdcall  *PFN_Opt1)(int userNum, int tabWord);                                          // sub_4A7EE0 ret 8
    typedef short       (__stdcall  *PFN_Opt2)(int userNum, int tabWord, int opIdx, int zero);                     // sub_4A7FC0 ret 10h
    typedef void*       (__fastcall *PFN_Ctor)(void* buf, void* edx);                                              // sub_517110 / sub_517800 / sub_517940 / sub_517070
    typedef int         (__fastcall *PFN_Router)(void* mgr, void* edx, int userNum, int plate, int after);         // sub_4D6740 ret 0Ch
    typedef int         (__fastcall *PFN_Count)(void* mgr, void* edx, int userNum, int plate);                     // sub_4D6A70 ret 8
    typedef int         (__fastcall *PFN_Write)(void* mgr, void* edx, int userNum, BYTE* rec, BYTE* src);          // sub_4D63F0 ret 0Ch
    typedef int         (__fastcall *PFN_Handler)(void* mgr, void* edx, int userNum, BYTE* frame);                 // sub_513240 / sub_513330 / sub_513DF0 / sub_513910 ret 8
    typedef void        (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                                   // sub_569DF0
    PFN_GetUser   const pGetUser   = (PFN_GetUser)0x005324A0;
    PFN_UserIndex const pUserIndex = (PFN_UserIndex)0x005324F0;
    PFN_CharIdx   const pCharIdx   = (PFN_CharIdx)0x00532530;
    PFN_Name      const pName      = (PFN_Name)0x00532570;
    PFN_Uid       const pUid       = (PFN_Uid)0x00539180;
    PFN_Replay    const pReplay    = (PFN_Replay)0x00524390;
    PFN_Sign      const pSign      = (PFN_Sign)0x00523F00;
    PFN_Busy      const pBusy      = (PFN_Busy)0x0052BFF0;
    PFN_UserPred  const pSoul      = (PFN_UserPred)0x0052EEA0;
    PFN_UserPred  const pPossess   = (PFN_UserPred)0x0052EE40;
    PFN_GetCash   const pGetCash   = (PFN_GetCash)0x0043FC20;
    PFN_SetCash   const pSetCash   = (PFN_SetCash)0x0043FC70;
    PFN_ToClient  const pToClient  = (PFN_ToClient)0x004C28F0;
    PFN_ConnSend  const pConnSend  = (PFN_ConnSend)0x005646C0;
    PFN_TrInt     const pRelaySock = (PFN_TrInt)0x004C0A90;
    PFN_TrInt     const pDbSock    = (PFN_TrInt)0x004C0A30;
    PFN_TrInt     const pRoute     = (PFN_TrInt)0x004C0250;
    PFN_MgrByte   const pPortal    = (PFN_MgrByte)0x0040C960;
    PFN_MgrByte   const pSystem    = (PFN_MgrByte)0x0040E110;
    PFN_MgrByte   const pThread    = (PFN_MgrByte)0x0040E0F0;
    PFN_Byte      const pGroup     = (PFN_Byte)0x004A7EA0;
    PFN_Byte      const pChannel   = (PFN_Byte)0x004A7EB0;
    PFN_IsCode    const pIsItem    = (PFN_IsCode)0x00532A90;
    PFN_IsCode    const pIsFunc    = (PFN_IsCode)0x00532B10;
    PFN_Opt1      const pOpt1      = (PFN_Opt1)0x004A7EE0;
    PFN_Opt2      const pOpt2      = (PFN_Opt2)0x004A7FC0;
    PFN_Ctor      const pCtor5076  = (PFN_Ctor)0x00517110;
    PFN_Ctor      const pCtor2132  = (PFN_Ctor)0x00517800;
    PFN_Ctor      const pCtor2136  = (PFN_Ctor)0x00517940;
    PFN_Ctor      const pCtor5073  = (PFN_Ctor)0x00517070;
    PFN_Router    const pRouter    = (PFN_Router)0x004D6740;
    PFN_Count     const pCount     = (PFN_Count)0x004D6A70;
    PFN_Write     const pWrite     = (PFN_Write)0x004D63F0;
    PFN_Handler   const pOn2133    = (PFN_Handler)0x00513240;
    PFN_Handler   const pOn5076    = (PFN_Handler)0x00513330;
    PFN_Handler   const pOn5077    = (PFN_Handler)0x00513DF0;
    PFN_Handler   const pOn2135    = (PFN_Handler)0x00513910;
    PFN_SrvLog    const pSrvLog    = (PFN_SrvLog)Srv::kLog;
    void* const kNet = (void*)Srv::kNetMoveMgr;   // CUserMoveManager (this sub_5646C0) — stru_600C98.gap_1D6028[39028]

    // ── настройки ────────────────────────────────────────────────────────────
    bool  g_enabled     = false;   // площадки стоят
    DWORD g_sites       = 0;       // маска точек (после коррекции)
    int   g_holdTimeout = 120;     // с, hold без исхода → журнал 162 (без автовозврата)
    int   g_maxInFlight = 1;       // подарков «в полёте» на учётку отправителя
    int   g_routeMaxAge = 300;     // с, годность маршрута 2133 для 5074
    int   g_logChannel  = 22;      // канал стокового лога sub_569DF0 (22 — канал «CharChargeShopBuy() Start»)
    int   g_settleMax   = 1800;    // с, settle (COMMIT/REFUND) повторяется до ответа GP7 не дольше этого; затем журнал 162
    constexpr DWORD kRetryMs   = 1500;           // пауза повтора 0x52 (контракт §5: 1–2 с)
    constexpr int   kMaxRetry  = 3;              // повторов HOLD (status 5 / сбой отправки): 3 повтора, 4-й ответ 5 — отказ
    // Пауза повтора settle по номеру попытки: 1,5 с, 5 с, затем 30 с (переподключение GS к шлюзу 5 с, рестарт gp7 — десятки с).
    DWORD SettleDelay(int n) { return n <= 0 ? 1500 : n == 1 ? 5000 : 30000; }
    constexpr DWORD kKeepMs    = 3600000;        // запись после тайм-аута ждёт поздний 5077/0x53 ещё час
    constexpr DWORD kPlanMs    = 2000;           // годность плана раскладки получателя (один вызов обработчика)

    P101_Stats g_stats = {};       // счётчики (экспорт P101_GetStats)
    CRITICAL_SECTION g_lock; bool g_lockReady = false;   // замок таблиц
    struct Guard { Guard() { if (g_lockReady) { EnterCriticalSection(&g_lock); } } ~Guard() { if (g_lockReady) { LeaveCriticalSection(&g_lock); } } };

    bool On(DWORD bit) { return g_enabled && (g_sites & bit) != 0; }   // точка включена

    // ── последний 2133 отправителя (маршрут получателя) ──────────────────────
    struct Check { int userIndex; DWORD tick; BYTE pendingName[20]; BYTE r[kLen2132]; bool pending; bool valid; };
    Check g_check[kMaxUsers] = {};

    // ── таблица «в полёте» (F) ────────────────────────────────────────────────
    enum : int { S_FREE = 0, S_HOLD = 1, S_SENT = 2, S_SETTLE = 3 };
    struct Gift
    {
        int   state;               // S_*
        BYTE  key[8];              // ключ запроса GS (PROTOCOL §4)
        int   orderIdx;            // Orderidx GP7 (0 до HOLD)
        int   userIndex;           // учётка отправителя
        int   charIdx;             // Charidx отправителя
        int   userNum;             // слот отправителя (UserNum)
        char  name[20];            // ник отправителя
        BYTE  uid[61];             // учётка (Us_id) отправителя
        BYTE  r2133[kLen2132];     // ответ 2133 получателя (маршрут, UserIndex, Charidx, UserNum, имя)
        int   n;                   // позиций
        int   code[7];             // коды
        BYTE  table[7];            // 1 item_list, 0 спецпредмет
        BYTE  opt[140];            // опции 7 × 5 × {i16, i16} (сервером)
        int   sum;                 // сумма по таблицам GS
        BYTE  route[4];            // маршрут отправителя для 5076 [0..3] (канал, система, карта, поток)
        int   gpRoute;             // a6 запроса шлюза (sub_4C0250 потока отправителя)
        int   settleAction;        // 2 COMMIT / 3 REFUND
        int   result5077;          // [0] 5077 (1 / 0 / 2)
        int   code5075;            // код 5075 клиенту после settle (1 / 0 / 4)
        int   cashType;            // 5077 [28] → 5075 [1]
        int   retries;             // повторов в текущей фазе
        DWORD retryAt;             // тик повтора (0 — нет)
        DWORD created, stateTick;  // тики
        bool  expired;             // тайм-аут отмечен (журнал 162), блок отправителя снят
    };
    constexpr int kMaxGifts = 256;
    Gift g_gift[kMaxGifts] = {};

    // ── план раскладки получателя (D) ────────────────────────────────────────
    struct Plan { DWORD tid; DWORD tick; DWORD batch; int userIndex; int slot[7]; bool valid; };
    Plan g_plan[kMaxUsers] = {};
    struct RecvBatch { int senderUserIndex; int userIndex; DWORD batch; DWORD tick; };   // пакет P100 на (получатель, отправитель)
    constexpr int kRecvBatchMax = 8;
    RecvBatch g_rb[kMaxUsers][kRecvBatchMax] = {};

    HANDLE g_pump = nullptr; DWORD g_pumpTid = 0;   // фоновая нить повторов и тайм-аутов

    // ── мелкие ───────────────────────────────────────────────────────────────
    DWORD Now() { const DWORD t = GetTickCount(); return t ? t : 1; }     // тик (0 — «нет»)
    void* ThreadOf(void* mgr) { return mgr ? *(void**)((BYTE*)mgr + 4) : nullptr; }   // поток карты (CUserManager+4)
    void* ParamOf(void* mgr) { void* tr = ThreadOf(mgr); return tr ? *(void**)((BYTE*)tr + 0x18) : nullptr; }   // CParamManager
    BYTE* UserOf(void* mgr, int userNum)
    {
        if (!mgr || userNum < 0 || userNum >= kMaxUsers) { return nullptr; }
        __try { return pGetUser(mgr, nullptr, userNum); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }
    int UiOf(const BYTE* user) { __try { return user ? *(const int*)(user + kOffUserIndex) : -1; } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; } }
    // Имена равны: байты до NUL, латиница без учёта регистра (как fn_AsdaNameEq для ASCII; не-ASCII — байт в байт).
    bool NameEq(const BYTE* a, const BYTE* b)
    {
        for (int i = 0; i < 20; ++i)
        {
            BYTE x = a[i], y = b[i];
            if (x >= 'a' && x <= 'z') { x = (BYTE)(x - 32); }
            if (y >= 'a' && y <= 'z') { y = (BYTE)(y - 32); }
            if (x != y) { return false; }
            if (!x) { return true; }
        }
        return true;
    }
    void Hex8(const BYTE* k, char* out) { for (int i = 0; i < 8; ++i) { sprintf_s(out + 2 * i, 3, "%02X", k[i]); } }   // ключ текстом
    // Строка стокового лога (канал LogChannel), безопасно к сбою форматтера стока.
    void SrvLogF(const char* fmt, ...)
    {
        char buf[512];
        va_list ap; va_start(ap, fmt); _vsnprintf_s(buf, _TRUNCATE, fmt, ap); va_end(ap);
        __try { pSrvLog(g_logChannel, "%s", buf); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    // Отправка в исходящее соединение (sub_5646C0). false — сокет закрыт / сбой.
    bool ConnSend(int op, int len, int conn, void* body, int a6)
    {
        BOOL ok = FALSE;
        __try { ok = pConnSend(kNet, nullptr, op, len, conn, body, a6); } __except (EXCEPTION_EXECUTE_HANDLER) { ok = FALSE; }
        return ok != FALSE;
    }
    int RelayConn(void* mgr) { void* tr = ThreadOf(mgr); if (!tr) { return -1; } __try { return pRelaySock(tr, nullptr); } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; } }   // сокет реле
    int DbConn(void* mgr) { void* tr = ThreadOf(mgr); if (!tr) { return -1; } __try { return pDbSock(tr, nullptr); } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; } }      // сокет DBManager

    // ── журнал ───────────────────────────────────────────────────────────────
    // Строка стокового лога + ac.other. user может быть nullptr (фоновая нить / нет игрока).
    void Report(BYTE kind, int opcode, const BYTE* user, int userNum, int userIndex, int v0, int v1, int v2, const char* detail, const char* logText)
    {
        __try { pSrvLog(g_logChannel, "P101 CashGift: %d UserNum %d UserIndex %d: %s", opcode, userNum, userIndex, logText); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = (user && userNum >= 0 && userNum < kMaxUsers) ? P47_PeerIpv4(userNum) : 0;
        e.userIndex = userIndex;
        if (user)
        {
            __try { e.charSlot = user[kOffSlot]; AcJournal::CopyName(e, user + kOffName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }
    // Строка журнала по записи «в полёте» (v0 Orderidx, v1/v2 — по виду).
    void ReportGift(BYTE kind, int opcode, const Gift& g, const BYTE* user, int v1, int v2, const char* what)
    {
        char k[20], d[64], t[256];
        Hex8(g.key, k);
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 %d order %d key %s %s", opcode, g.orderIdx, k, what);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "%s; order %d key %s sender %d/%d to \"%.20s\" (UserIndex %d) codes %d,%d,%d,%d,%d,%d,%d sum %d",
                    what, g.orderIdx, k, g.userIndex, g.charIdx, (const char*)(g.r2133 + 15), *(const int*)(g.r2133 + 8),
                    g.code[0], g.code[1], g.code[2], g.code[3], g.code[4], g.code[5], g.code[6], g.sum);
        Report(kind, opcode, user, g.userNum, g.userIndex, g.orderIdx, v1, v2, d, t);
    }

    // ── отправки ─────────────────────────────────────────────────────────────
    // Клиенту (sub_4C28F0 потока этого CUserManager).
    void ToClient(void* mgr, int op, int len, int userNum, void* buf)
    {
        void* tr = ThreadOf(mgr);
        if (!tr) { return; }
        __try { pToClient(tr, nullptr, op, len, userNum, buf, 0, 1); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    // 5073 отказ (код, остальное — умолчания конструктора sub_517070).
    void Send5073(void* mgr, int userNum, int code)
    {
        BYTE b[40] = {};
        pCtor5073(b, nullptr);
        b[0] = (BYTE)code;
        ToClient(mgr, kOp5073, kLen5073, userNum, b);
        InterlockedIncrement(&g_stats.refused5072);
    }
    // Кэш персонажа (sub_43FC20).
    int CashOf(void* mgr, int userNum) { void* p = ParamOf(mgr); if (!p) { return 0; } __try { return pGetCash(p, nullptr, userNum); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; } }
    // Кэш = баланс GP7 абсолютно (sub_43FC70(…, бал, 0, 1) — как ответ 2601 sub_4F7D10).
    void SetCashAbs(void* mgr, int userNum, int bal) { void* p = ParamOf(mgr); if (!p) { return; } __try { pSetCash(p, nullptr, userNum, bal, 0, 1); } __except (EXCEPTION_EXECUTE_HANDLER) {} }
    // 5075 клиенту: [0] код, [1] CashType, [2] i32 кэш (sub_513DF0: v7).
    void Send5075(void* mgr, int userNum, int code, int cashType)
    {
        BYTE b[8] = {};
        b[0] = (BYTE)code; b[1] = (BYTE)cashType; *(int*)(b + 2) = CashOf(mgr, userNum);
        ToClient(mgr, kOp5075, kLen5075, userNum, b);
        InterlockedIncrement(&g_stats.sent5075);
    }
    // Игрок слота — та же учётка (иначе клиенту и кэшу ничего: слот мог занять другой).
    BYTE* SameAccount(void* mgr, int userNum, int userIndex) { BYTE* u = UserOf(mgr, userNum); return (u && UiOf(u) == userIndex) ? u : nullptr; }

    // Запрос 0x52 по записи (PROTOCOL §2). action 1 HOLD / 2 COMMIT / 3 REFUND.
    void BuildGiftReq(const Gift& g, int action, BYTE* q)
    {
        memset(q, 0, kLenGiftReq);
        q[0] = (BYTE)action;
        *(int*)(q + 1) = g.userIndex;
        memcpy(q + 5, g.uid, 60);
        *(int*)(q + 66) = g.charIdx & 0xFF;
        *(WORD*)(q + 70) = (WORD)g.userNum;
        memcpy(q + 72, g.name, 19);
        memcpy(q + 92, g.r2133 + 15, 19);
        for (int k = 0; k < 7; ++k) { *(int*)(q + 112 + 4 * k) = k < g.n ? g.code[k] : 0; }
        *(int*)(q + 140) = g.sum;
        *(int*)(q + 144) = action == 1 ? 0 : g.orderIdx;
        memcpy(q + 148, g.key, 8);
        q[156] = action == 1 ? 0 : (BYTE)g.result5077;
    }
    // Отправка 0x52 в шлюз (sub_5646C0(…, 82, 157, 93, …, маршрут потока), как 0x50 в sub_4F60E0). false — сокет шлюза закрыт.
    bool SendGiftReq(const BYTE* q, int gpRoute)
    {
        const bool ok = ConnSend(kOpGiftReq, kLenGiftReq, kGp7Conn, (void*)q, gpRoute);
        InterlockedIncrement(ok ? &g_stats.gp7Sent : &g_stats.gp7SendFail);
        return ok;
    }

    // Запись по ключу (nullptr — нет). Под замком.
    Gift* FindKey(const BYTE* key) { for (Gift& g : g_gift) { if (g.state != S_FREE && !memcmp(g.key, key, 8)) { return &g; } } return nullptr; }
    // Активных (не просроченных) записей учётки. Под замком.
    int InFlightOf(int userIndex) { int n = 0; for (const Gift& g : g_gift) { if (g.state != S_FREE && !g.expired && g.userIndex == userIndex) { ++n; } } return n; }
    // Недавно закрытые ключи (ревизия М9 б): поздний/повторный 0x53 по уже закрытой записи — эхо, а не рассинхрон.
    constexpr int kClosedMax = 64;
    BYTE g_closed[kClosedMax][8] = {}; int g_closedPos = 0;
    // Снять запись (ключ — в кольцо закрытых). Под замком.
    DWORD g_lastKeyTime = 0;   // последнее время UNIX в ключе (ключи процесса не повторяются)
    void Free(Gift& g) { memcpy(g_closed[g_closedPos], g.key, 8); g_closedPos = (g_closedPos + 1) % kClosedMax; memset(&g, 0, sizeof(g)); }
    // Ключ недавно закрыт. Под замком.
    bool WasClosed(const BYTE* key) { for (int i = 0; i < kClosedMax; ++i) { if (!memcmp(g_closed[i], key, 8) && *(const DWORD*)(key + 4)) { return true; } } return false; }
    // Повтор settle записи по растущей паузе (ревизия В1: до ответа GP7, не дольше SettleMaxSec). Под замком.
    void ArmSettle(Gift& x) { x.retryAt = Now() + SettleDelay(x.retries); }
    // Повтор 0x52 записи (сбой отправки HOLD — kRetryMs; settle — растущая пауза).
    void ScheduleRetry(const BYTE* key) { Guard lk; Gift* x = FindKey(key); if (x) { if (x->state == S_SETTLE) { ArmSettle(*x); } else { x->retryAt = Now() + kRetryMs; } } }
    // Снять запись по ключу.
    void DropKey(const BYTE* key) { Guard lk; Gift* x = FindKey(key); if (x) { Free(*x); } }
}

// ─────────────────────────────────────────────────────────────────────────────
//  A — 5072 (проверка имени)
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    void CheckBegin(int userNum, int ui, const BYTE* name);   // ниже
    void Record2133(int userNum, int ui, const BYTE* r);       // ниже

    // Конверт «с секретом» как у 5070 (CharChargeShopBuy@0x511DA0): анти-повтор sub_524390 по 8 б с +9, подпись sub_523F00 тела.
    bool Envelope(void* mgr, int userNum, BYTE* frame, int body, const char* fn)
    {
        const DWORD lo = *(const DWORD*)(frame + 9), hi = *(const DWORD*)(frame + 13);
        if (!pReplay(mgr, nullptr, lo, hi, userNum, fn)) { InterlockedIncrement(&g_stats.envelopeRefused); return false; }
        if (!pSign(mgr, nullptr, frame, body, userNum, 1)) { InterlockedIncrement(&g_stats.envelopeRefused); return false; }
        return true;
    }

    // ★ 5072: проверки → DB 2132 (35 б). Ответ 2133 → 5073 — сток sub_513240.
    void Do5072(void* mgr, int userNum, BYTE* frame)
    {
        InterlockedIncrement(&g_stats.req5072);
        if (!Envelope(mgr, userNum, frame, kBody5072, "P101 CashGift 5072()")) { return; }
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return; }
        if (pBusy(mgr, nullptr, userNum, kOp5072)) { Send5073(mgr, userNum, 0); return; }   // как 5070: «занят» → код 0
        BYTE name[20] = {};
        memcpy(name, frame + kEnvHead, 20);
        // Имя уходит в DBM `EXEC UPUserState %d,'%s'` как есть: правила P68 (набор 1 — объединение локалей) отсекают кавычку,
        //   управляющие байты и поле без нуля. Такого персонажа существовать не может — 5073 код 3 «игрок не найден».
        int len = 0, pos = 0, bad = 0;
        if (P68_NameVerdict(name, 1, &len, &pos, &bad) != 0) { Send5073(mgr, userNum, 3); InterlockedIncrement(&g_stats.badName); return; }
        if (NameEq(name, user + kOffName)) { Send5073(mgr, userNum, 5); return; }   // себе — код 5 (loc 12946)
        BYTE q[kLen2132 + 5] = {};
        pCtor2132(q, nullptr);   // sub_517800: [3]=[4]=−1, [8..11]=−1, [13]=−1
        q[1] = (BYTE)pGroup();
        memcpy(q + 15, name, 19); q[34] = 0;
        CheckBegin(userNum, UiOf(user), name);
        if (ConnSend(kOpDb2132, kLen2132, DbConn(mgr), q, userNum)) { InterlockedIncrement(&g_stats.sent2132); } else { Send5073(mgr, userNum, 0); }
    }

    // Отметка «ждём 2133» слота (учётка, имя запроса).
    void CheckBegin(int userNum, int ui, const BYTE* name)
    {
        Guard g;
        Check& c = g_check[userNum];
        c.userIndex = ui; c.tick = Now(); memcpy(c.pendingName, name, 20); c.pending = true; c.valid = false;
    }
    // Ответ 2133 в запись слота (только на свой ожидаемый запрос той же учётки).
    void Record2133(int userNum, int ui, const BYTE* r)
    {
        Guard g;
        Check& c = g_check[userNum];
        if (!c.pending || c.userIndex != ui) { return; }
        // ревизия М1: ответ не на последний запрос (два быстрых 5072: A, затем B) — не берётся, ждём ответ на B
        if (!NameEq(r + 15, c.pendingName)) { InterlockedIncrement(&g_stats.routesStale); return; }
        memcpy(c.r, r, kLen2132);
        c.tick = Now();
        c.pending = false;
        // как sub_513240: [3] Gsidx и [4] Thread ≥ 0; годен только «в сети» (1) — иначе 5073 не даёт маршрута
        c.valid = r[0] == 1 && (char)r[3] >= 0 && (char)r[4] >= 0;
        InterlockedIncrement(&g_stats.routes2133);
    }
}

// Ответ 2133 (call sub_513240 @0x4303DE): маршрут получателя — для 5074 этого отправителя; затем сток (5073).
extern "C" int __fastcall P101_On2133(void* mgr, void* edx, int a2, BYTE* frame)
{
    const int userNum = (short)a2;
    if (On(kBit5072) && userNum >= 0 && userNum < kMaxUsers && frame)
    {
        BYTE* user = UserOf(mgr, userNum);
        BYTE r[kLen2132] = {};
        bool ok = false;
        __try { memcpy(r, frame + 9, kLen2132); ok = true; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (ok && user) { Record2133(userNum, UiOf(user), r); }
    }
    return pOn2133(mgr, nullptr, a2, frame);
}

// ─────────────────────────────────────────────────────────────────────────────
//  B — 5074 (подарок): проверки, сумма по таблицам GS, HOLD
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    // Отказ 5074 кодом 5075 (+ журнал 162 при подмене данных клиентом).
    void Refuse5074(void* mgr, int userNum, int code, const char* why, bool tamper, const BYTE* user)
    {
        InterlockedIncrement(&g_stats.refused5074);
        Send5075(mgr, userNum, code, 1);
        char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 5074 refused: %s", why);
        if (tamper) { Report(kKindStuck, kOp5074, user, userNum, UiOf(user), 0, code, 0, d, why); }
        else { SrvLogF("P101 CashGift: 5074 UserNum %d UserIndex %d refused (5075 %d): %s", userNum, UiOf(user), code, why); }
    }

    // Маршрут получателя для 5074: 1 — годен (r заполнен), 0 — нет проверки / устарел, −1 — подарок учётки уже «в полёте».
    int TakeRoute(int userNum, int ui, BYTE* r)
    {
        Guard g;
        if (InFlightOf(ui) >= g_maxInFlight) { return -1; }
        const Check& c = g_check[userNum];
        if (!c.valid || c.userIndex != ui || (g_routeMaxAge > 0 && Now() - c.tick > (DWORD)g_routeMaxAge * 1000)) { return 0; }
        memcpy(r, c.r, kLen2132);
        return 1;
    }
    // Новая запись «в полёте»: уникальный ключ, занять ячейку таблицы, израсходовать маршрут; q — запрос HOLD. false — таблица полна.
    bool AddGift(Gift& ng, BYTE* q)
    {
        Guard g;
        DWORD t = (DWORD)_time32(nullptr);
        if (t <= g_lastKeyTime) { t = g_lastKeyTime + 1; }   // время в ключе не повторяется в процессе (несколько 5074 в секунду)
        for (;;) { *(DWORD*)(ng.key + 4) = t; if (!FindKey(ng.key) && !WasClosed(ng.key)) { break; } ++t; }
        g_lastKeyTime = t;
        Gift* slot = nullptr;
        for (Gift& x : g_gift) { if (x.state == S_FREE) { slot = &x; break; } }
        if (!slot) { return false; }
        *slot = ng;
        g_check[ng.userNum].valid = false;   // маршрут израсходован: следующий подарок — новая проверка имени (как клиент после 5075)
        BuildGiftReq(*slot, 1, q);
        return true;
    }

    // ★ 5074.
    void Do5074(void* mgr, int userNum, BYTE* frame)
    {
        InterlockedIncrement(&g_stats.req5074);
        if (!Envelope(mgr, userNum, frame, kBody5074, "P101 CashGift 5074()")) { return; }
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return; }
        const BYTE* b = frame + kEnvHead;
        const int ui = UiOf(user);
        if (pBusy(mgr, nullptr, userNum, kOp5074)) { Refuse5074(mgr, userNum, 0, "busy (sub_52BFF0)", false, user); return; }
        if (pPossess(mgr, nullptr, userNum) && b[0] == 1) { Refuse5074(mgr, userNum, 0, "possessed (sub_52EE40), mode 1", false, user); return; }
        if (!b[0]) { Refuse5074(mgr, userNum, 0, "showcase mode 0 (CharChargeShopBuy: code 7)", true, user); return; }

        // маршрут получателя: последний 2133 этого отправителя (без проверки имени честный клиент сюда не попадает — гейт 12939)
        BYTE r[kLen2132] = {};
        const int rt = TakeRoute(userNum, ui, r);
        if (rt < 0)
        {
            // ревизия М3: второй 5074 при подарке «в полёте» — молча (честный клиент держит [2079] и ждёт 5075 первого; 5075 0 здесь
            //   показал бы «не удалось» до успеха первого). Строка журнала 161 — повтор не оплачивается.
            InterlockedIncrement(&g_stats.refused5074);
            Report(kKindGp7, kOp5074, user, userNum, ui, 0, g_maxInFlight, 0, "P101 5074 dropped: gift already in flight (no 5075)",
                   "second 5074 while a gift of this account is in flight (MaxInFlight): dropped silently, first gift continues");
            return;
        }
        if (rt == 0 || r[0] != 1) { Refuse5074(mgr, userNum, 0, "no confirmed recipient (5072/2133) or route expired", false, user); return; }
        // тело +176 Channel, +177 Portal, +178 Gsidx, +179 Thread, +180 i32 UserIndex, +184 Charidx, +185 i16 UserNum (re/client.md §2.2)
        if (b[176] != r[2] || b[177] != r[5] || b[178] != r[3] || b[179] != r[4] || *(const int*)(b + 180) != *(const int*)(r + 8) ||
            b[184] != r[12] || *(const short*)(b + 185) != *(const short*)(r + 13))
        {
            Refuse5074(mgr, userNum, 0, "recipient route in body != last 2133 of this sender", true, user); return;
        }
        if (*(const int*)(r + 8) == ui) { Refuse5074(mgr, userNum, 0, "recipient UserIndex == own", true, user); return; }

        // коды и цены — как CharChargeShopBuy, только витрина; позиции подряд с первой
        Gift ng = {};
        int n = 0; bool gap = false, bad = false; const char* why = "";
        const BYTE* items = *(const BYTE**)kItemTablePtr;
        const BYTE* ft = *(const BYTE**)kFuncTablePtr;
        const int* sell = *(const int**)kSellTablePtr;
        const int sellN = *(const int*)kSellCountPtr;
        long long sum = 0;
        if (!sell || sellN <= 0 || !items || !ft) { Refuse5074(mgr, userNum, 0, "GS tables not loaded yet (SellItemTable / item_table / FT)", false, user); return; }
        for (int k = 0; k < 7 && !bad; ++k)
        {
            const int code = *(const int*)(b + 8 + 4 * k);
            const BYTE tab = b[1 + k];
            if (code <= 0) { gap = true; continue; }
            if (gap) { bad = true; why = "positions not contiguous"; break; }
            // [ИСПРАВЛЕНИЕ] сток читает dword_5F5E9C[код] и вне [0, dword_5F5EC4) (чтение за таблицей) — здесь код вне витрины = отказ
            if (!sell || code >= sellN || sell[code] != code) { bad = true; why = "code not on showcase (SellItemTable)"; break; }
            int price = 0;
            if (tab)
            {
                if (!pIsItem(code) || !items) { bad = true; why = "table 1 but not item_list code"; break; }
                const BYTE* row = items + 71 * (code - kItemBase);
                if (row[36] != 0 && row[36] != 3) { bad = true; why = "item_list +36 not 0/3 (CharChargeShopBuy code 0)"; break; }
                price = *(const int*)(row + 41);
                // опции — сервером, как 5070 (GS.c:104675–104683): j = 0, 1 по словам item_table +18 / +22; прочие {−1, −1} (sub_40C8B0)
                for (int j = 0; j < 5; ++j) { *(short*)(ng.opt + 20 * k + 4 * j) = -1; *(short*)(ng.opt + 20 * k + 4 * j + 2) = -1; }
                for (int j = 0; j < 2; ++j)
                {
                    const int w = *(const short*)(row + 18 + 4 * j);
                    const short oi = pOpt1(userNum, w);
                    const short ov = pOpt2(userNum, w, oi, 0);
                    *(short*)(ng.opt + 20 * k + 4 * j) = oi; *(short*)(ng.opt + 20 * k + 4 * j + 2) = ov;
                }
            }
            else
            {
                if (!pIsFunc(code) || !ft) { bad = true; why = "table 0 but not Function_Table code"; break; }
                price = *(const int*)(ft + 48 * (code - 1) + 33);
                for (int j = 0; j < 5; ++j) { *(short*)(ng.opt + 20 * k + 4 * j) = -1; *(short*)(ng.opt + 20 * k + 4 * j + 2) = -1; }
            }
            if (price <= 0) { bad = true; why = "price <= 0 in GS table"; break; }
            ng.code[n] = code; ng.table[n] = tab ? 1 : 0; ++n;
            sum += price;
        }
        if (!bad && n == 0) { bad = true; why = "no positions"; }
        if (bad) { Refuse5074(mgr, userNum, 0, why, true, user); return; }
        if (sum >= kSumCap) { Refuse5074(mgr, userNum, 0, "sum >= 100000000", false, user); return; }
        if (CashOf(mgr, userNum) < (int)sum) { Refuse5074(mgr, userNum, 2, "cash < sum (CUser+0x1A4)", false, user); return; }

        // запись «в полёте»
        ng.state = S_HOLD;
        ng.userIndex = ui;
        ng.charIdx = (BYTE)pCharIdx(mgr, nullptr, userNum);
        ng.userNum = userNum;
        const char* nm = pName(mgr, nullptr, userNum);
        if (nm) { memcpy(ng.name, nm, 19); }
        BYTE uid[96] = {};
        pUid(mgr, nullptr, uid, userNum);
        memcpy(ng.uid, uid, 60);
        memcpy(ng.r2133, r, kLen2132);
        ng.n = n; ng.sum = (int)sum; ng.cashType = 1;
        ng.route[0] = (BYTE)pChannel(); ng.route[1] = (BYTE)pSystem(mgr, nullptr); ng.route[2] = (BYTE)pPortal(mgr, nullptr); ng.route[3] = (BYTE)pThread(mgr, nullptr);
        void* tr = ThreadOf(mgr);
        ng.gpRoute = tr ? pRoute(tr, nullptr) : 0;
        ng.created = ng.stateTick = Now();
        // ключ (PROTOCOL §4, ред. 02.11 ревизия М8): [0] группа, [1] канал ^ (система << 4) (GameServer / Indun / Ch2 различаются
        //   системой sub_40E110), [2..3] UserNum, [4..7] время UNIX в секундах (растёт и между рестартами — UNIQUE gs_key в GP7GiftLog
        //   не встретит прежний ключ этого слота); совпадение в процессе — +1 (AddGift)
        ng.key[0] = (BYTE)pGroup(); ng.key[1] = (BYTE)(ng.route[0] ^ (ng.route[1] << 4)); *(WORD*)(ng.key + 2) = (WORD)userNum;
        ng.created = Now();
        BYTE q[kLenGiftReq];
        if (!AddGift(ng, q)) { Refuse5074(mgr, userNum, 0, "in-flight table full", false, user); return; }
        if (!SendGiftReq(q, ng.gpRoute))
        {
            // шлюз недоступен: HOLD не ушёл — денег не трогали, запись снимается
            DropKey(q + 148);
            Refuse5074(mgr, userNum, 0, "GP7 socket closed (HOLD not sent)", false, user);
            return;
        }
        InterlockedIncrement(&g_stats.holdSent);
        char k[20]; Hex8(q + 148, k);
        SrvLogF("P101 CashGift: 5074 UserNum %d UserIndex %d %.20s -> \"%.20s\" HOLD key %s sum %d positions %d",
                userNum, ui, ng.name, (const char*)(r + 15), k, ng.sum, n);
    }
}

// Общий вход стаба диспетчера клиента (0x42AD02). Возврат 1 — обработано (стаб уходит в хвост 0x42F036), 0 — сток (default).
extern "C" int __stdcall P101_OnClient(int opcode, BYTE* ebp, void* mgr, int userNum, BYTE* frame, int packetLen)
{
    const DWORD bit = opcode == kOp5072 ? kBit5072 : kBit5074;
    if (!On(bit)) { return 0; }
    const int body = opcode == kOp5072 ? kBody5072 : kBody5074;
    // длина кадра: 9 + 8 + 16 + тело + 1, паддинг клиента до +19 (как OpcodeLengths P55; 5072/5074 в таблице P55 нет)
    if (packetLen < kEnvHead + body + 1 || packetLen > kEnvHead + body + 1 + 19) { InterlockedIncrement(&g_stats.badLen); return 0; }
    int* marker = *(int**)(ebp + 8);
    __try { *marker = opcode; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    __try
    {
        if (!pSoul(mgr, nullptr, userNum))   // как case 5070: «душа» — обработчик не вызывается
        {
            if (opcode == kOp5072) { Do5072(mgr, userNum, frame); } else { Do5074(mgr, userNum, frame); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    __try { *marker = opcode + 1; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  C — ответ шлюза 0x53
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    // 5076 237 б по записи (раскладка — по читателю recvChatResponse…Gift, конструктор пакета стока sub_517110).
    bool Send5076(void* mgr, const Gift& g)
    {
        BYTE b[240] = {};
        pCtor5076(b, nullptr);
        memcpy(b, g.route, 4);                          // [0..3] маршрут отправителя: канал, система, карта, поток (→ 5077 [21..24])
        *(int*)(b + 4) = g.userIndex;                   // [4] UserIndex отправителя
        b[8] = (BYTE)g.charIdx;                         // [8] Charidx
        *(short*)(b + 9) = (short)g.userNum;            // [9] UserNum отправителя (→ hdr+3 и [25] 5077)
        memcpy(b + 11, g.name, 19); b[30] = 0;          // [11..30] имя отправителя
        const BYTE* r = g.r2133;
        b[31] = r[2]; b[32] = r[3]; b[33] = r[5]; b[34] = r[4];   // маршрут получателя: канал (CM), система, карта, поток (реле)
        *(int*)(b + 35) = *(const int*)(r + 8);         // [35] UserIndex получателя
        b[39] = r[12];                                   // [39] Charidx получателя
        *(short*)(b + 40) = *(const short*)(r + 13);    // [40] UserNum получателя
        b[42] = (BYTE)g.cashType;                        // [42] CashType = 1 (кэш)
        for (int k = 0; k < g.n; ++k) { b[43 + k] = g.table[k]; *(int*)(b + 50 + 4 * k) = g.code[k]; }
        *(int*)(b + 78) = g.orderIdx;                    // [78..81] Orderidx (получатель не читает; журнал 159)
        memcpy(b + 92, g.opt, 20 * g.n);                 // [92..231] опции позиций (прочие — {−1, −1} конструктора sub_517110)
        *(int*)(b + 232) = g.sum;                        // [232] сумма
        b[236] = (BYTE)g.n;                              // [236] число позиций
        return ConnSend(kOp5076, kLen5076, RelayConn(mgr), b, *(const short*)(r + 13));
    }

    // Переход записи в settle и отправка 0x52 COMMIT/REFUND (сбой отправки — повтор фоновой нитью).
    void StartSettle(Gift& g, int result5077, int code5075, int cashType, BYTE* q)
    {
        g.state = S_SETTLE;
        g.result5077 = result5077;
        g.code5075 = code5075;
        g.cashType = cashType;
        g.settleAction = result5077 == 1 ? 2 : 3;
        g.retries = 0; g.stateTick = Now(); g.expired = false;
        ArmSettle(g);   // ревизия В1: settle повторяется до ответа (идемпотентен по ключу и Orderidx, PROTOCOL §5)
        BuildGiftReq(g, g.settleAction, q);
    }

    // Разбор 0x53 под замком: переход записи; g — копия. Возврат: −1 нет записи/не то состояние; 1 HOLD ок → 5076; 2 HOLD повтор;
    //   3 HOLD отказ; 4 settle ок; 5 settle повтор; 6 settle рассинхрон / повторы исчерпаны; 7 HOLD исход неизвестен после повторов.
    int Resolve53(const BYTE* p, Gift* g)
    {
        const int status = p[0], action = p[1], ui = *(const int*)(p + 2), un = *(const short*)(p + 6), order = *(const int*)(p + 8);
        Guard lk;
        Gift* x = FindKey(p + 20);
        if (!x || x->userIndex != ui || x->userNum != un ||
            (x->state == S_HOLD && action != 1) || (x->state == S_SETTLE && action != x->settleAction) || (x->state != S_HOLD && x->state != S_SETTLE))
        {
            if (x) { *g = *x; return -1; }
            return WasClosed(p + 20) ? -2 : -1;   // −2: эхо уже закрытой записи (повтор ушёл одновременно с ответом)
        }
        int what;
        if (x->state == S_HOLD)
        {
            if (status == 1) { x->orderIdx = order; x->state = S_SENT; x->stateTick = Now(); x->retries = 0; x->retryAt = 0; x->expired = false; what = 1; }
            else if (status == 5 && x->retries < kMaxRetry) { ++x->retries; x->retryAt = Now() + kRetryMs; what = 2; }
            else if (status == 5) { what = 7; }
            else { what = 3; }
        }
        else
        {
            if (status == 1) { what = 4; }
            else if (status == 5) { ++x->retries; ArmSettle(*x); what = 5; }   // до ответа, предел — SettleMaxSec (P101_Pump)
            else { what = 6; }
        }
        *g = *x;
        if (what == 3 || what == 7 || what == 4 || what == 6) { Free(*x); }
        return what;
    }
    // Реле недоступно после HOLD: запись → REFUND (результат 0). q — запрос, *route — маршрут. false — записи нет.
    bool BeginRefund(const BYTE* key, BYTE* q, int* route, Gift* g)
    {
        Guard lk;
        Gift* x = FindKey(key);
        if (!x) { return false; }
        StartSettle(*x, 0, 0, 1, q);
        *route = x->gpRoute; *g = *x;
        return true;
    }

    void OnGatewayImpl(void* mgr, BYTE* frame)
    {
        if (*(const WORD*)(frame + 1) < 10 + kLenGiftRes) { InterlockedIncrement(&g_stats.unknown53); return; }
        const BYTE* p = frame + 9;
        const int status = p[0], action = p[1], ui = *(const int*)(p + 2), un = *(const short*)(p + 6);
        const int order = *(const int*)(p + 8), bal = *(const int*)(p + 12);
        InterlockedIncrement(&g_stats.recv53);
        Gift g = {};
        const int what = Resolve53(p, &g);
        BYTE* user = SameAccount(mgr, g.userNum, g.userIndex);
        switch (what)
        {
        case -2:   // эхо уже закрытой записи — повтор разминулся с ответом (ревизия М9 б)
            InterlockedIncrement(&g_stats.echo53);
            SrvLogF("P101 CashGift: 0x53 status %d action %d order %d — echo of already closed gift (repeat crossed the answer)", status, action, order);
            break;
        case -1:
        {
            InterlockedIncrement(&g_stats.unknown53);
            char k[20], d[64], t[200]; Hex8(p + 20, k);
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 0x53 no matching gift key %s", k);
            _snprintf_s(t, sizeof(t), _TRUNCATE, "GP7 0x53 status %d action %d order %d for key %s: no gift in flight in this state (late answer / sync)", status, action, order, k);
            Report(kKindStuck, kOpGiftRes, nullptr, un, ui, order, status, action, d, t);
            break;
        }
        case 1:   // HOLD принят: кэш = баланс, 5076 в реле
        {
            InterlockedIncrement(&g_stats.holdOk);
            if (user) { SetCashAbs(mgr, g.userNum, bal); }
            if (Send5076(mgr, g))
            {
                InterlockedIncrement(&g_stats.sent5076);
                ReportGift(kKindSent, kOp5076, g, user, g.sum, *(const int*)(g.r2133 + 8), "HOLD ok, 5076 sent to relay");
            }
            else
            {
                // реле недоступно: подарок не ушёл — деньги вернуть (REFUND), клиенту 5075 код 0 по ответу
                BYTE q[kLenGiftReq]; int route = 0;
                if (BeginRefund(g.key, q, &route, &g))
                {
                    ReportGift(kKindRefuse, kOp5076, g, user, 0, 0, "relay socket closed: 5076 not sent -> REFUND");
                    if (!SendGiftReq(q, route)) { ScheduleRetry(g.key); }
                }
            }
            break;
        }
        case 2: case 5:
            InterlockedIncrement(&g_stats.retries53);
            SrvLogF("P101 CashGift: 0x53 status 5 (unknown outcome) order %d — repeat %d of %d in %u ms", order, g.retries, kMaxRetry, kRetryMs);
            break;
        case 3:   // HOLD отказ: 2 мало денег → 5075 код 2 (loc 6892); 0/3/4 → код 0
            InterlockedIncrement(&g_stats.holdRefused);
            if (user) { Send5075(mgr, g.userNum, status == 2 ? 2 : 0, 1); }
            ReportGift(kKindGp7, kOpGiftRes, g, user, status, bal, status == 2 ? "GP7 HOLD refused: insufficient balance" :
                       status == 3 ? "GP7 HOLD: order already closed (C/R), 5076 not sent" : status == 4 ? "GP7 HOLD: order not found" : "GP7 HOLD refused");
            break;
        case 7:   // третий status 5: заморозка могла пройти — ручная сверка
            InterlockedIncrement(&g_stats.stuck);
            if (user) { Send5075(mgr, g.userNum, 0, 1); }
            ReportGift(kKindStuck, kOpGiftRes, g, user, status, g.retries, "GP7 HOLD outcome unknown after retries: manual reconcile (gift_reconcile.py)");
            break;
        case 4:   // settle ок: кэш = баланс, 5075 по коду 5077
            InterlockedIncrement(&g_stats.settleOk);
            if (user) { SetCashAbs(mgr, g.userNum, bal); Send5075(mgr, g.userNum, g.code5075, g.cashType); }
            SrvLogF("P101 CashGift: settle %s order %d ok, balance %d", g.settleAction == 2 ? "COMMIT" : "REFUND", g.orderIdx, bal);
            break;
        case 6:   // settle 3/4/0 или повторы исчерпаны — рассинхрон
            InterlockedIncrement(&g_stats.stuck);
            if (user) { Send5075(mgr, g.userNum, g.code5075, g.cashType); }
            ReportGift(kKindStuck, kOpGiftRes, g, user, status, g.settleAction, g.settleAction == 2 ? "GP7 COMMIT failed (state/order mismatch or unknown): manual reconcile" :
                       "GP7 REFUND failed (state/order mismatch or unknown): manual reconcile");
            break;
        default: break;
        }
    }
}

// Стаб ответа шлюза (0x42FC62): 0x53. ebp — кадр ConnectSocketMsgProcess (маркер прогресса [ebp+8]).
extern "C" void __stdcall P101_OnGateway(BYTE* ebp, void* mgr, BYTE* frame)
{
    int* marker = *(int**)(ebp + 8);
    __try { *marker = 2118; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (g_enabled && (g_sites & (kBit5074 | kBitSettle)))
    {
        __try { OnGatewayImpl(mgr, frame); } __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    }
    __try { *marker = 2119; } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ─────────────────────────────────────────────────────────────────────────────
//  E — 5077 (исход от получателя): замена тела sub_513DF0
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    // DB 2136 UPGiftUser — как сток sub_513DF0 (42 б, конструктор sub_517940); учётка/Charidx — из записи «в полёте».
    void Send2136(void* mgr, int userNum, const Gift& g, const BYTE* v)
    {
        BYTE b[48] = {};
        pCtor2136(b, nullptr);
        b[0] = 0;
        b[1] = (BYTE)pGroup();
        b[2] = (BYTE)pChannel();
        b[3] = (BYTE)pPortal(mgr, nullptr);
        *(int*)(b + 4) = g.userIndex;
        b[8] = (BYTE)g.charIdx;
        b[9] = v[28];
        *(int*)(b + 10) = *(const int*)(v + 29);
        memcpy(b + 14, v + 33, 28);
        ConnSend(kOpDb2136, kLen2136, DbConn(mgr), b, userNum);
    }

    // Запись S_SENT по 5077 (UserNum + сумма + коды) → settle. false — нет. 5077 учётки не несёт, поэтому при нескольких
    //   подходящих: учётка игрока слота (ui) первой, затем старшая (реле FIFO).
    bool Match5077(int userNum, int ui, const BYTE* v, BYTE* q, int* route, Gift* g)
    {
        const int result = v[0], sum = *(const int*)(v + 29);
        Guard lk;
        Gift* best = nullptr;
        for (Gift& x : g_gift)
        {
            if (x.state != S_SENT || x.userNum != userNum || x.sum != sum) { continue; }
            bool same = true;
            for (int k = 0; k < 7 && same; ++k) { const int c = *(const int*)(v + 33 + 4 * k); same = k < x.n ? x.code[k] == c : c <= 0; }
            if (!same) { continue; }
            const int sc = x.userIndex == ui ? 1 : 0;   // ревизия М2: учётка слота первой, затем старшая (реле FIFO); тайм-аут порядок не меняет
            const int sb = best ? (best->userIndex == ui ? 1 : 0) : -1;
            if (!best || sc > sb || (sc == sb && (int)(x.created - best->created) < 0)) { best = &x; }
        }
        if (!best) { return false; }
        StartSettle(*best, result, result == 1 ? 1 : result == 2 ? 4 : 0, v[28], q);
        *g = *best; *route = best->gpRoute;
        return true;
    }

    int On5077Impl(void* mgr, int userNum, BYTE* frame)
    {
        const BYTE* v = frame + 9;
        if (*(const short*)(v + 25) != (short)userNum) { return 0; }   // как сток: a2 == [25]
        InterlockedIncrement(&g_stats.recv5077);
        const int result = v[0], sum = *(const int*)(v + 29);
        BYTE q[kLenGiftReq]; Gift g = {}; int route = 0;
        const bool found = Match5077(userNum, UiOf(UserOf(mgr, userNum)), v, q, &route, &g);
        BYTE* user = found ? SameAccount(mgr, userNum, g.userIndex) : nullptr;
        if (!found)
        {
            // Записи нет: подарок не этого процесса / уже снят. Сток списал бы локально — не списываем, клиенту ничего (слот мог смениться).
            char d[64], t[200];
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 5077 result %d sum %d: no gift in flight", result, sum);
            _snprintf_s(t, sizeof(t), _TRUNCATE, "5077 result %d sum %d codes %d,%d: no matching gift in flight (UserNum %d) — not settled", result, sum,
                        *(const int*)(v + 33), *(const int*)(v + 37), userNum);
            Report(kKindStuck, kOp5077, UserOf(mgr, userNum), userNum, UiOf(UserOf(mgr, userNum)), 0, result, sum, d, t);
            return 1;
        }
        if (result == 1) { Send2136(mgr, userNum, g, v); }   // сток: 2136 только при [0] == 1
        else { ReportGift(kKindRefuse, kOp5077, g, user, result, 0, result == 2 ? "recipient: no room -> REFUND" : "recipient: DB error / sum <= 0 / absent -> REFUND"); }
        InterlockedIncrement(&g_stats.settleSent);
        if (!SendGiftReq(q, route)) { ScheduleRetry(g.key); }
        return 1;
    }
}

// 5077 (call sub_513DF0 @0x430446).
extern "C" int __fastcall P101_On5077(void* mgr, void* edx, int a2, BYTE* frame)
{
    if (!On(kBitSettle)) { return pOn5077(mgr, nullptr, a2, frame); }
    __try { return On5077Impl(mgr, (short)a2, frame); }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  D — получатель
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    // Owner (+50), который сток ставит позиции подарка: sub_513910 GS.c:105172 — спецпредмет с FT+12 == 3 и FT+43 == 2 → 2.
    int GiftOwner(int code)
    {
        __try
        {
            const BYTE* ft = *(const BYTE**)kFuncTablePtr;
            if (!pIsFunc(code) || !ft) { return 0; }
            const BYTE* r = ft + 48 * (code - 1);
            return (r[12] == 3 && r[43] == 2) ? 2 : 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    // Заряды выдачи спецпредмета на пути подарка: P100_Charges (i32, [ИСПРАВЛЕНИЕ 300]) или u8 FT+13 стока.
    int GiftCharges(int code)
    {
        const int c = P100_Charges(code);
        if (c >= 0) { return c; }
        const BYTE* ft = *(const BYTE**)kFuncTablePtr;
        return ft ? ft[48 * (code - 1) + 13] : 0;
    }
    // 5077 код 0 от имени получателя (получателя нет / не та учётка): маршрут отправителя из 5076 (раскладка sub_513330 LABEL_7).
    void Send5077Back(void* mgr, const BYTE* v)
    {
        BYTE b[64] = {};
        b[0] = 0;
        b[21] = v[0]; b[22] = v[1]; b[23] = v[2]; b[24] = v[3];
        *(short*)(b + 25) = *(const short*)(v + 9);
        b[27] = v[8];
        b[28] = v[42];
        *(int*)(b + 29) = *(const int*)(v + 232);
        for (int i = 0; i < 7; ++i) { *(int*)(b + 33 + 4 * i) = *(const int*)(v + 50 + 4 * i); }
        ConnSend(kOp5077, kLen5077, RelayConn(mgr), b, *(const short*)(v + 9));
    }
    // План раскладки получателя: снять (новый 5076 / путь без плана).
    void InvalidatePlan(int userNum) { Guard g; g_plan[userNum].valid = false; }
    // План раскладки получателя: записать (нить, тик, пакет P100, ячейки позиций) и пакет на (получатель, отправитель) для 2135.
    void SavePlan(int userNum, int ui, int senderUi, DWORD batch, const int* slot)
    {
        Guard g;
        Plan& p = g_plan[userNum];
        p.tid = GetCurrentThreadId(); p.tick = Now(); p.batch = batch; p.userIndex = ui; p.valid = true;
        memcpy(p.slot, slot, sizeof(p.slot));
        RecvBatch* rb = g_rb[userNum]; int pick = 0; DWORD oldest = 0;
        for (int i = 0; i < kRecvBatchMax; ++i) { if (!rb[i].batch) { pick = i; break; } if (Now() - rb[i].tick >= oldest) { oldest = Now() - rb[i].tick; pick = i; } }
        rb[pick].senderUserIndex = senderUi; rb[pick].userIndex = ui; rb[pick].batch = batch; rb[pick].tick = Now();
    }
    // Ячейка позиции j из плана (−1 — плана нет / не та нить / устарел).
    int PlanSlot(int userNum, int j)
    {
        Guard g;
        const Plan& p = g_plan[userNum];
        if (p.valid && p.tid == GetCurrentThreadId() && Now() - p.tick < kPlanMs && j >= 0 && j < 7) { return p.slot[j]; }
        return -1;
    }
    // Пакет P100 подарка этого отправителя у получателя (снимается из списка); 0 — нет.
    DWORD TakeBatch(int userNum, int senderUi, int ui)
    {
        Guard g;
        RecvBatch* rb = g_rb[userNum];
        for (int i = 0; i < kRecvBatchMax; ++i)
        {
            if (rb[i].batch && rb[i].senderUserIndex == senderUi && rb[i].userIndex == ui) { const DWORD b = rb[i].batch; memset(&rb[i], 0, sizeof(rb[i])); return b; }
        }
        return 0;
    }
    // Журнал получателя (v0 Orderidx [78], v1 сумма, v2 — по виду).
    void ReportRecv(BYTE kind, const BYTE* user, int userNum, const BYTE* v, int v2, const char* what)
    {
        char d[64], t[220];
        const int order = *(const int*)(v + 78);
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 5076 order %d %s", order, what);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "%s; order %d from UserIndex %d \"%.20s\" codes %d,%d,%d,%d,%d,%d,%d sum %d n %d", what, order,
                    *(const int*)(v + 4), (const char*)(v + 11), *(const int*)(v + 50), *(const int*)(v + 54), *(const int*)(v + 58),
                    *(const int*)(v + 62), *(const int*)(v + 66), *(const int*)(v + 70), *(const int*)(v + 74), *(const int*)(v + 232), v[236]);
        Report(kind, kOp5076, user, userNum, UiOf(user), order, *(const int*)(v + 232), v2, d, t);
    }
}

// 5076 (call recvChatResponse…Gift @0x430412): [ИСПРАВЛЕНИЕ] получателя нет в слоте / слот занят другой учёткой — 5077 код 0.
extern "C" int __fastcall P101_On5076(void* mgr, void* edx, int a2, BYTE* frame)
{
    if (On(kBitRecv) && frame)
    {
        __try
        {
            const BYTE* v = frame + 9;
            InterlockedIncrement(&g_stats.recv5076);
            BYTE* user = UserOf(mgr, (short)a2);
            if ((short)a2 == *(const short*)(v + 40) && (!user || UiOf(user) != *(const int*)(v + 35)))
            {
                // сток: при пустом слоте — молчит (деньги висят без исхода); при чужой учётке в слоте — отдаёт подарок ей
                Send5077Back(mgr, v);
                InterlockedIncrement(&g_stats.recvAbsent);
                ReportRecv(kKindRefuse, user, (short)a2, v, user ? UiOf(user) : -1, user ? "recipient slot taken by another account -> 5077 0" : "recipient not in slot -> 5077 0");
                return 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    }
    return pOn5076(mgr, nullptr, a2, frame);
}

// Проверка места получателя (call sub_4D6A70 @0x5134B3). ebp — кадр recvChatResponse…Gift: [ebp-2F8h] тело 237 б, [ebp-308h] число.
extern "C" int __stdcall P101_RecvRoom(BYTE* ebp, void* mgr, int a1, int a2)
{
    const int userNum = (short)a1;
    const int freeCells = pCount(mgr, nullptr, userNum, a2);
    if (!On(kBitRecv) || userNum < 0 || userNum >= kMaxUsers) { return freeCells; }
    __try
    {
        const BYTE* v = ebp - 0x2F8;
        const int need = *(const int*)(ebp - 0x308);
        BYTE* user = UserOf(mgr, userNum);
        InvalidatePlan(userNum);
        if (*(const int*)(v + 232) <= 0)
        {
            ReportRecv(kKindRefuse, user, userNum, v, 0, "sum <= 0 -> 5077 0 (stock)");
            return freeCells;
        }
        const bool merge = P100_Active() != 0;
        if (!merge)
        {
            if (freeCells >= need) { InterlockedIncrement(&g_stats.recvPlaced); ReportRecv(kKindRecv, user, userNum, v, freeCells, "accepted (stock cells) -> DB 2134"); }
            else { InterlockedIncrement(&g_stats.recvNoRoom); ReportRecv(kKindRefuse, user, userNum, v, freeCells, "no room -> 5077 2"); }
            return freeCells;
        }
        // план: спецпредмет с ключом P100 — стопка того же ключа и Owner (накопитель P100, пакет batch); иначе новая ячейка
        //   стоковым роутером после предыдущей новой, с обходом резервов P100 «в полёте» (как P100 StockNew).
        const DWORD batch = P100_BeginBatch();
        int slot[7]; for (int& s : slot) { s = -1; }
        int after = -1, merged = 0; bool fail = false;
        bool used[64] = {};
        for (int j = 0; j < 7 && !fail; ++j)
        {
            const int code = *(const int*)(v + 50 + 4 * j);
            if (code <= 0) { continue; }
            const bool special = v[43 + j] == 0;
            const int owner = special ? GiftOwner(code) : 0;
            const int key = special ? P100_KeyOf(code) : 0;
            const int add = special ? GiftCharges(code) : 0;
            if (special && key > 0)
            {
                int isNew = 0;
                const int s = P100_FindChargeStack(mgr, userNum, code, add, 7, owner, batch, &isNew);
                if (s >= 0) { slot[j] = s; ++merged; if (s < 64) { used[s] = true; } continue; }
            }
            int a = after, soft = -1, pick = -1;
            for (int t = 0; t < 70; ++t)
            {
                const int s = (short)pRouter(mgr, nullptr, userNum, 1, a);
                if (s < 0) { break; }
                const bool mine = s < 64 && used[s];
                if (!mine && !P100_IsReserved(mgr, userNum, s, key, code)) { pick = s; break; }
                if (!mine && soft < 0) { soft = s; }
                a = s;
            }
            if (pick < 0) { pick = soft; }
            if (pick < 0) { fail = true; break; }
            slot[j] = pick; after = pick; if (pick < 64) { used[pick] = true; }
            if (key > 0) { P100_ReserveNew(mgr, userNum, code, add, owner, pick, batch); }
        }
        if (fail)
        {
            P100_CancelBatch(userNum, batch);
            InterlockedIncrement(&g_stats.recvNoRoom);
            ReportRecv(kKindRefuse, user, userNum, v, freeCells, "no room (with P100 stacks) -> 5077 2");
            return -1;   // < числа позиций → сток шлёт 5077 код 2
        }
        SavePlan(userNum, UiOf(user), *(const int*)(v + 4), batch, slot);
        InterlockedIncrement(&g_stats.recvPlaced);
        if (merged) { InterlockedExchangeAdd(&g_stats.recvMerged, merged); }
        ReportRecv(kKindRecv, user, userNum, v, merged, merged ? "accepted (P100 stacks) -> DB 2134" : "accepted -> DB 2134");
        return freeCells > need ? freeCells : need;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    return freeCells;
}

// Ячейка позиции (call sub_4D6740 @0x513558): из плана P101_RecvRoom; j = [ebp-48h]. Нет плана — сток.
extern "C" int __stdcall P101_RecvPick(BYTE* ebp, void* mgr, int a1, int a2, int a3)
{
    const int userNum = (short)a1;
    if (On(kBitRecv) && userNum >= 0 && userNum < kMaxUsers)
    {
        int j = -1;
        __try { j = *(const int*)(ebp - 0x48); } __except (EXCEPTION_EXECUTE_HANDLER) { j = -1; }
        const int s = PlanSlot(userNum, j);
        if (s >= 0) { InterlockedIncrement(&g_stats.recvPlanPicks); return s; }
    }
    return (short)pRouter(mgr, nullptr, userNum, a2, a3);
}

// [ИСПРАВЛЕНИЕ 300] чтение FT+13 @0x5136DA: p = FT + 48·(код − 1) + 13.
extern "C" int __stdcall P101_ChargesAt(const BYTE* p)
{
    const int stock = *p;
    if (!On(kBitRecv)) { return stock; }
    __try
    {
        const DWORD off = (DWORD)(p - 13 - *(const BYTE**)kFuncTablePtr);
        if (off % 48) { return stock; }
        const int c = P100_Charges((int)(off / 48) + 1);
        return c >= 0 ? c : stock;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return stock; }
}

// Запись позиции в память (call sub_4D63F0 @0x513D31 в sub_513910): слияние P100 + итог ячейки в прежние записи 5078
//   ([ebp-19Ch] + 57·j, j = [ebp-3BCh]). Вес: P100_WriteMerged(…, wresp = 1) снимает вес слитой копии — сток прибавит его сам.
extern "C" int __stdcall P101_RecvWrite(BYTE* ebp, void* mgr, int a1, BYTE* rec, BYTE* src)
{
    const int userNum = (short)a1;
    if (!On(kBitRecv) || !P100_Active() || src || !rec) { return pWrite(mgr, nullptr, userNum, rec, src); }
    const int r = P100_WriteMerged(mgr, userNum, rec, 1);
    __try
    {
        if (r)
        {
            InterlockedIncrement(&g_stats.recvWritesMerged);
            const int j = *(const int*)(ebp - 0x3BC);
            const short posx = *(const short*)(rec + 5);
            for (int i = 0; i < j && i < 7; ++i)
            {
                BYTE* e = ebp - 0x19C + 57 * i;
                if (*(const int*)e > 0 && e[4] == 1 && *(const short*)(e + 5) == posx) { memcpy(e, rec, 57); }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 1;
}

// Ответ 2135 (call sub_513910 @0x43047A): ошибка БД — снять пакет P100 этого подарка; затем сток (5078 + 5077 1 / 5077 0).
//   [ИСПРАВЛЕНИЕ] ревизия В2: сток (GS.c:105123–105140) при пустом слоте получателя молчит (5077 не уходит — запись отправителя висит
//   до тайм-аута), а при чужой учётке в слоте пишет вещи в память ЧУЖОГО CUser и шлёт ему 5078. Теперь: слот пуст или учётка ≠ 2134
//   [38] (UserIndex получателя; 2134 = v16 @ebp-208h, v21 @ebp-1E2h) — сток не зовётся, в память ничего не пишется, отправителю 5077
//   с исходом БД: [0] ≠ 0 → 1 (вещи выданы в БД, придут при входе — COMMIT), [0] = 0 → 0 (REFUND).
namespace
{
    // 5077 отправителю по кадру 2135 (раскладка v12 sub_513910: [21..24] = 2135 [3..6], [25] = [12], [28] = [56], [29] = [45], коды [57+55i]).
    void Send5077From2135(void* mgr, const BYTE* v, int result)
    {
        BYTE b[64] = {};
        b[0] = (BYTE)result;
        b[21] = v[3]; b[22] = v[4]; b[23] = v[5]; b[24] = v[6];
        *(short*)(b + 25) = *(const short*)(v + 12);
        b[28] = v[56];
        *(int*)(b + 29) = *(const int*)(v + 45);
        for (int i = 0; i < 7; ++i) { *(int*)(b + 33 + 4 * i) = *(const int*)(v + 57 + 55 * i); }
        ConnSend(kOp5077, kLen5077, RelayConn(mgr), b, *(const short*)(v + 12));
    }
}
extern "C" int __fastcall P101_On2135(void* mgr, void* edx, int a2, BYTE* frame)
{
    const int userNum = (short)a2;
    if (On(kBitRecv) && frame && userNum >= 0 && userNum < kMaxUsers)
    {
        bool handled = false;
        __try
        {
            const BYTE* v = frame + 9;
            const int sender = *(const int*)(v + 7), recvUi = *(const int*)(v + 38);
            BYTE* user = UserOf(mgr, userNum);
            const bool absent = *(const short*)(v + 43) == (short)userNum && (!user || UiOf(user) != recvUi);
            const DWORD batch = TakeBatch(userNum, sender, absent ? recvUi : UiOf(user));
            if (absent)
            {
                if (batch) { P100_CancelBatch(userNum, batch); }   // резерв ячеек этого подарка у прежнего владельца слота не нужен
                Send5077From2135(mgr, v, v[0] ? 1 : 0);
                InterlockedIncrement(&g_stats.recvGone2135);
                char d[64], t[200];
                _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 2135 recipient %d gone, DB %d -> 5077 %d", recvUi, v[0], v[0] ? 1 : 0);
                _snprintf_s(t, sizeof(t), _TRUNCATE, "recipient UserIndex %d not in slot %d (left / slot taken by %d) at DB answer: %s", recvUi, userNum, UiOf(user),
                            v[0] ? "items are in DB (arrive on login) -> 5077 1 -> COMMIT" : "DB error -> 5077 0 -> REFUND");
                Report(v[0] ? kKindRecv : kKindRefuse, 2135, nullptr, userNum, recvUi, 0, sender, v[0], d, t);
                handled = true;
            }
            else if (!v[0])
            {
                if (batch) { P100_CancelBatch(userNum, batch); }
                InterlockedIncrement(&g_stats.recvDbError);
                char d[64], t[160];
                _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 2135 DB error from %d", sender);
                _snprintf_s(t, sizeof(t), _TRUNCATE, "UPGivenitem failed for gift from UserIndex %d (whole gift rolled back) -> 5077 0 -> REFUND", sender);
                Report(kKindRefuse, 2135, user, userNum, UiOf(user), 0, sender, 0, d, t);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
        if (handled) { return 0; }
    }
    return pOn2135(mgr, nullptr, a2, frame);
}

// ─────────────────────────────────────────────────────────────────────────────
//  F — повторы и тайм-ауты (фоновая нить; CUser/клиент не трогает)
// ─────────────────────────────────────────────────────────────────────────────
// Один проход: повторы 0x52 по сроку, тайм-ауты HoldTimeoutSec (журнал 162 без возврата), снятие записей старше часа после тайм-аута.
extern "C" __declspec(dllexport) void __stdcall P101_Pump()
{
    if (!g_enabled) { return; }
    for (int i = 0; i < kMaxGifts; ++i)
    {
        // ev: 1 повтор, 2 тайм-аут HOLD/5077, 3 снятие, 4 повторы HOLD исчерпаны, 5 settle не подтверждён за SettleMaxSec
        BYTE q[kLenGiftReq]; int route = 0; int act = 0; Gift g = {}; int ev = 0;
        {
            Guard lk;
            Gift& x = g_gift[i];
            if (x.state == S_FREE) { continue; }
            const DWORD now = Now();
            const DWORD life = x.state == S_SETTLE ? (DWORD)g_settleMax * 1000 : (DWORD)g_holdTimeout * 1000;   // срок фазы
            if (x.state == S_SETTLE && !x.expired && now - x.stateTick > life) { x.expired = true; x.retryAt = 0; ev = 5; }
            else if (x.retryAt && (int)(now - x.retryAt) >= 0)
            {
                x.retryAt = 0;
                act = x.state == S_HOLD ? 1 : x.state == S_SETTLE ? x.settleAction : 0;
                if (act) { BuildGiftReq(x, act, q); route = x.gpRoute; ev = 1; }
                if (x.state == S_SETTLE) { ++x.retries; ArmSettle(x); }   // settle: следующий повтор, если ответа так и не будет
            }
            else if (x.state != S_SETTLE && !x.expired && now - x.stateTick > life) { x.expired = true; ev = 2; }
            else if (x.expired && now - x.stateTick > life + kKeepMs) { ev = 3; }
            g = x;
            if (ev == 3) { Free(x); }
        }
        if (ev == 1)
        {
            InterlockedIncrement(&g_stats.resent);
            if (!SendGiftReq(q, route) && g.state == S_HOLD)
            {
                Guard lk;
                Gift* x = FindKey(g.key);
                if (x && x->retries < kMaxRetry) { ++x->retries; x->retryAt = Now() + kRetryMs; }
                else if (x) { x->expired = true; ev = 4; g = *x; }
            }
        }
        if (ev == 2)
        {
            InterlockedIncrement(&g_stats.timeouts);
            ReportGift(kKindStuck, kOpGiftReq, g, nullptr, g.state, g_holdTimeout,
                       g.state == S_HOLD ? "HOLD without GP7 answer (timeout, no auto refund)" : "no 5077 from recipient (timeout, no auto refund)");
        }
        if (ev == 5)
        {
            InterlockedIncrement(&g_stats.timeouts);
            ReportGift(kKindStuck, kOpGiftReq, g, nullptr, g.settleAction, g.retries, g.settleAction == 2 ? "COMMIT not confirmed by GP7 within SettleMaxSec: manual reconcile" :
                       "REFUND not confirmed by GP7 within SettleMaxSec: manual reconcile");
        }
        if (ev == 3) { ReportGift(kKindStuck, kOpGiftReq, g, nullptr, g.state, 0, "dropped from in-flight table 1 h after timeout: manual reconcile"); }
        if (ev == 4) { ReportGift(kKindStuck, kOpGiftReq, g, nullptr, g.state, g.retries, "GP7 socket closed, HOLD retries exhausted: manual reconcile"); }
    }
}

namespace
{
    volatile LONG g_pumpStop = 0;   // выход фоновой нити (выгрузка DLL / стенд)
    // Фоновая нить: проход P101_Pump раз в 250 мс.
    DWORD WINAPI PumpThread(LPVOID)
    {
        while (!g_pumpStop) { Sleep(250); __try { P101_Pump(); } __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); } }
        return 0;
    }

    // ── трамплины ─────────────────────────────────────────────────────────────
    // 0x42AD02 `jmp dword ptr [ecx*4+42F2C0h]`: [ebp-10C8h] = опкод − 0x138A (0x46 → 5072, 0x48 → 5074).
    DWORD g_dispTail = 0x0042F036;   // общий хвост switch (как все case)
    __declspec(naked) void St_Disp()
    {
        __asm
        {
            cmp   dword ptr [ebp-10C8h], 46h
            je    g72
            cmp   dword ptr [ebp-10C8h], 48h
            je    g74
            jmp   dword ptr [ecx*4+42F2C0h]       // сток
        g72:
            push  5072
            jmp   gcom
        g74:
            push  5074
        gcom:
            pop   eax
            movsx edx, word ptr [ebp-34h]         // packetLen (полная длина кадра)
            push  edx
            lea   edx, [ebp-1048h]                // кадр пакета
            push  edx
            movsx edx, word ptr [ebp-44h]         // userNum
            push  edx
            mov   edx, dword ptr [ebp-10C4h]      // this диспетчера → [[+4]+34h] CUserManager
            mov   edx, dword ptr [edx+4]
            mov   edx, dword ptr [edx+34h]
            push  edx
            push  ebp
            push  eax
            call  P101_OnClient
            test  eax, eax
            jz    gdef
            jmp   dword ptr [g_dispTail]
        gdef:
            mov   eax, dword ptr [ebp-10C8h]      // сток: индекс по таблице 0x42F370 → default
            movzx ecx, byte ptr [eax+42F370h]
            jmp   dword ptr [ecx*4+42F2C0h]
        }
    }
    // 0x42FC62 `jmp 0x43462B` (конец цепочки 0x0B/0x51/0x5B): [ebp-102Ch] опкод, [ebp-1018h] кадр, [ebp-1028h] this.
    DWORD g_gwTail = 0x0043462B;
    __declspec(naked) void St_Gateway()
    {
        __asm
        {
            cmp   dword ptr [ebp-102Ch], 53h
            jne   gtail
            lea   eax, [ebp-1018h]
            push  eax
            mov   eax, dword ptr [ebp-1028h]
            mov   eax, dword ptr [eax+4]
            mov   eax, dword ptr [eax+34h]
            push  eax
            push  ebp
            call  P101_OnGateway
        gtail:
            jmp   dword ptr [g_gwTail]
        }
    }
    // call sub_4D6A70 (thiscall(mgr, userNum, plate) ret 8) с кадром вызывающей.
    __declspec(naked) void St_Room()
    {
        __asm
        {
            push  dword ptr [esp+8]
            push  dword ptr [esp+8]
            push  ecx
            push  ebp
            call  P101_RecvRoom
            ret   8
        }
    }
    // call sub_4D6740 (thiscall(mgr, userNum, plate, after) ret 0Ch) с кадром вызывающей.
    __declspec(naked) void St_Pick()
    {
        __asm
        {
            push  dword ptr [esp+0Ch]
            push  dword ptr [esp+0Ch]
            push  dword ptr [esp+0Ch]
            push  ecx
            push  ebp
            call  P101_RecvPick
            ret   0Ch
        }
    }
    // call sub_4D63F0 (thiscall(mgr, userNum, rec, src) ret 0Ch) с кадром вызывающей.
    __declspec(naked) void St_Write()
    {
        __asm
        {
            push  dword ptr [esp+0Ch]
            push  dword ptr [esp+0Ch]
            push  dword ptr [esp+0Ch]
            push  ecx
            push  ebp
            call  P101_RecvWrite
            ret   0Ch
        }
    }
    // 0x5136DA `movzx dx, byte ptr [ecx+eax+0Dh]` (6 б) → dx = заряды; продолжение 0x5136E0 (`mov eax,[ebp-48h]`).
    DWORD g_ftBack = 0x005136E0;
    __declspec(naked) void St_Ft()
    {
        __asm
        {
            pushfd
            push  ecx
            push  eax
            lea   edx, [ecx+eax+0Dh]
            push  edx
            call  P101_ChargesAt
            mov   edx, eax
            pop   eax
            pop   ecx
            popfd
            jmp   dword ptr [g_ftBack]
        }
    }

    // ── площадки ──
    const BYTE kDisp[]  = { 0xFF, 0x24, 0x8D, 0xC0, 0xF2, 0x42, 0x00 };   // 0x42AD02 jmp [ecx*4+42F2C0h]
    const BYTE kGw[]    = { 0xE9, 0xC4, 0x49, 0x00, 0x00 };               // 0x42FC62 jmp 0x43462B
    const BYTE kFt[]    = { 0x66, 0x0F, 0xB6, 0x54, 0x01, 0x0D };         // 0x5136DA movzx dx, byte [ecx+eax+0Dh]
    // соседи (кадры, на которые опираются стабы)
    const BYTE kNbDispA[] = { 0x81, 0xEA, 0x8A, 0x13, 0x00, 0x00, 0x89, 0x95, 0x38, 0xEF, 0xFF, 0xFF };   // 0x42ACD9 sub edx,138Ah; mov [ebp-10C8h],edx
    const BYTE kNbDispB[] = { 0x0F, 0xB6, 0x88, 0x70, 0xF3, 0x42, 0x00 };                                // 0x42ACFB movzx ecx,byte [eax+42F370h]
    const BYTE kNbCase[]  = { 0x8D, 0x95, 0xB8, 0xEF, 0xFF, 0xFF, 0x52, 0x66, 0x8B, 0x45, 0xBC };        // 0x42BA64 lea edx,[ebp-1048h]; push edx; mov ax,[ebp-44h] (case 5070)
    const BYTE kNbGw[]    = { 0x83, 0xBD, 0xD4, 0xEF, 0xFF, 0xFF, 0x5B };                                // 0x42FC55 cmp dword [ebp-102Ch],5Bh
    const BYTE kNbGwS[]   = { 0x8D, 0x85, 0xE8, 0xEF, 0xFF, 0xFF, 0x50, 0x6A, 0x00, 0x8B, 0x8D, 0xD8, 0xEF, 0xFF, 0xFF };   // 0x4345A9 lea eax,[ebp-1018h]; push eax; push 0; mov ecx,[ebp-1028h]
    const BYTE kNbRoom[]  = { 0x3B, 0x85, 0xF8, 0xFC, 0xFF, 0xFF };                                      // 0x5134B8 cmp eax,[ebp-308h]
    const BYTE kNbBody[]  = { 0x66, 0x8B, 0x85, 0x30, 0xFD, 0xFF, 0xFF };                                // 0x5134A5 mov ax,[ebp-2D0h] (тело [40])
    const BYTE kNbJ[]     = { 0x8B, 0x55, 0xB8, 0x8B, 0x84, 0x95, 0x3A, 0xFD, 0xFF, 0xFF };              // 0x513511 mov edx,[ebp-48h]; mov eax,[ebp+edx*4-2C6h]
    const BYTE kNbFt[]    = { 0x8B, 0x0D, 0x70, 0x5E, 0x5F, 0x00 };                                      // 0x5136D4 mov ecx,[5F5E70h]
    const BYTE kNbFtB[]   = { 0x8B, 0x45, 0xB8 };                                                        // 0x5136E0 mov eax,[ebp-48h]
    const BYTE kNbWrite[] = { 0x8D, 0x84, 0x15, 0x64, 0xFE, 0xFF, 0xFF };                                // 0x513D1E lea eax,[ebp+edx-19Ch]
    const BYTE kNbWriteJ[] = { 0x8B, 0x95, 0x44, 0xFC, 0xFF, 0xFF };                                     // 0x513D15 mov edx,[ebp-3BCh]

    struct CallSite { DWORD va; DWORD target; void* to; DWORD bit; const char* what; };   // call-площадка (E8 rel32)
    const CallSite kCalls[] =
    {
        { 0x004303DE, 0x00513240, (void*)&P101_On2133,  kBit5072,   "2133 → sub_513240 (маршрут получателя)" },
        { 0x00430446, 0x00513DF0, (void*)&P101_On5077,  kBitSettle, "5077 → sub_513DF0 (settle)" },
        { 0x00430412, 0x00513330, (void*)&P101_On5076,  kBitRecv,   "5076 → recvChatResponse…Gift (получатель в слоте)" },
        { 0x0043047A, 0x00513910, (void*)&P101_On2135,  kBitRecv,   "2135 → sub_513910 (ошибка БД — снять пакет P100)" },
        { 0x005134B3, 0x004D6A70, (void*)&St_Room,      kBitRecv,   "получатель: проверка места (план раскладки)" },
        { 0x00513558, 0x004D6740, (void*)&St_Pick,      kBitRecv,   "получатель: ячейка позиции (план)" },
        { 0x00513D31, 0x004D63F0, (void*)&St_Write,     kBitRecv,   "2135: запись позиции (слияние P100)" },
    };

    // Журнал «выключение / коррекция настройки» (вид 163).
    void NoteOff(const char* why)
    {
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P101 %s", why);
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kKindOff);
        e.opcode = 0; e.userNum = -1;
        AcJournal::CopyText(e, d);
        AcJournal::Push(e);
        __try { pSrvLog(g_logChannel, "P101 CashGift: %s", why); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

extern "C" __declspec(dllexport) void __stdcall P101_GetStats(P101_Stats* out)
{
    if (!out) { return; }
    g_stats.pumpThreadId = (LONG)g_pumpTid;
    LONG n = 0; { Guard g; for (const Gift& x : g_gift) { if (x.state != S_FREE) { ++n; } } }
    g_stats.inFlight = n;
    g_stats.sites = (LONG)g_sites;
    *out = g_stats;
}

PatchResult P101_CashGift()
{
    g_enabled = false;
    if (!Config::GetBool(kSec, L"Enabled", false)) { return PatchResult::Disabled; }
    DWORD sites = (DWORD)Config::GetInt(kSec, L"Sites", 1) & 15u;
    g_holdTimeout = Config::GetInt(kSec, L"HoldTimeoutSec", 120);
    if (g_holdTimeout < 10 || g_holdTimeout > 3600) { g_holdTimeout = 120; }
    g_maxInFlight = Config::GetInt(kSec, L"MaxInFlight", 1);
    if (g_maxInFlight < 1 || g_maxInFlight > 8) { g_maxInFlight = 1; }
    g_routeMaxAge = Config::GetInt(kSec, L"RouteMaxAgeSec", 300);
    if (g_routeMaxAge < 0 || g_routeMaxAge > 3600) { g_routeMaxAge = 300; }
    g_settleMax = Config::GetInt(kSec, L"SettleMaxSec", 1800);
    if (g_settleMax < 60 || g_settleMax > 86400) { g_settleMax = 1800; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 22);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 22; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }

    // бит 2 (HOLD до отправки) без бита 4: сток sub_513DF0 списал бы локально ещё раз и не закрыл бы hold — бит 4 включается сам
    if ((sites & kBit5074) && !(sites & kBitSettle))
    {
        sites |= kBitSettle;
        Log::Line(L"    P101: Sites — бит 2 без бита 4 недопустим (двойное списание стоком), бит 4 включён");
        NoteOff("Sites: bit 2 without bit 4 -> bit 4 forced on (stock sub_513DF0 would charge locally)");
    }
    // ревизия М6: бит 2 без бита 1 — маршрут получателя (2133) некому запомнить, все 5074 отказали бы — бит 1 включается сам
    if ((sites & kBit5074) && !(sites & kBit5072))
    {
        sites |= kBit5072;
        Log::Line(L"    P101: Sites — бит 2 без бита 1 бесполезен (нет проверки имени 5072/2133), бит 1 включён");
        NoteOff("Sites: bit 2 without bit 1 -> bit 1 forced on (no recipient route otherwise)");
    }
    // ревизия Б1: таблиц (витрина dword_5F5E9C, item_table, Function_Table) при установке ещё НЕТ — DLL ставится в DllMain до точки
    //   входа exe, загрузчик GS заполняет их позже (GS.c:68191, 68447, 70427). Проверяет их каждый 5074 (Do5074: нет таблицы — отказ).

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    BYTE callOrig[ARRAYSIZE(kCalls)][5];
    Site check[ARRAYSIZE(kCalls) + 20];
    int nc = 0;
    for (int i = 0; i < (int)ARRAYSIZE(kCalls); ++i)
    {
        callOrig[i][0] = 0xE8;
        *(int*)(callOrig[i] + 1) = (int)(kCalls[i].target - (kCalls[i].va + 5));
        check[nc++] = { kCalls[i].va, callOrig[i], 5 };
    }
    const Site extra[] =
    {
        { 0x0042AD02, kDisp, sizeof(kDisp) }, { 0x0042FC62, kGw, sizeof(kGw) }, { 0x005136DA, kFt, sizeof(kFt) },
        { 0x0042ACD9, kNbDispA, sizeof(kNbDispA) }, { 0x0042ACFB, kNbDispB, sizeof(kNbDispB) }, { 0x0042BA64, kNbCase, sizeof(kNbCase) },
        { 0x0042FC55, kNbGw, sizeof(kNbGw) }, { 0x004345A9, kNbGwS, sizeof(kNbGwS) }, { 0x005134B8, kNbRoom, sizeof(kNbRoom) },
        { 0x005134A5, kNbBody, sizeof(kNbBody) }, { 0x00513511, kNbJ, sizeof(kNbJ) }, { 0x005136D4, kNbFt, sizeof(kNbFt) },
        { 0x005136E0, kNbFtB, sizeof(kNbFtB) }, { 0x00513D1E, kNbWrite, sizeof(kNbWrite) }, { 0x00513D15, kNbWriteJ, sizeof(kNbWriteJ) },
    };
    for (const Site& s : extra) { check[nc++] = s; }
    if (!VerifyAllSites(L"P101", check, nc)) { NoteOff("site bytes mismatch -> P101 not installed (stock)"); return PatchResult::Mismatch; }

    memset(g_check, 0, sizeof(g_check)); memset(g_gift, 0, sizeof(g_gift)); memset(g_plan, 0, sizeof(g_plan)); memset(g_rb, 0, sizeof(g_rb));
    g_sites = sites;
    g_enabled = true;

    bool ok = true;
    int placed = 0;
    if (sites & (kBit5072 | kBit5074)) { ok &= Hook::WriteJmp(0x0042AD02, (void*)&St_Disp, sizeof(kDisp)); ++placed; }
    if (sites & (kBit5074 | kBitSettle)) { ok &= Hook::WriteJmp(0x0042FC62, (void*)&St_Gateway, sizeof(kGw)); ++placed; }
    if (sites & kBitRecv) { ok &= Hook::WriteJmp(0x005136DA, (void*)&St_Ft, sizeof(kFt)); ++placed; }
    for (const CallSite& c : kCalls) { if (sites & c.bit) { ok &= Hook::WriteCall(c.va, c.to, 5); ++placed; } }
    if (!ok) { g_enabled = false; Log::Line(L"    P101: ошибка записи площадок"); return PatchResult::Failed; }

    if (sites & (kBit5074 | kBitSettle))
    {
        g_pump = CreateThread(nullptr, 0, &PumpThread, nullptr, 0, &g_pumpTid);
        if (!g_pump) { Log::Line(L"    P101: фоновая нить повторов не создана (%u) — повторы 0x52 и тайм-ауты не работают", GetLastError()); }
    }
    Log::Line(L"    P101: подарок из кэш-магазина — Sites 0x%X (1 5072, 2 5074/HOLD, 4 5077-settle, 8 получатель), площадок %d; "
              L"HoldTimeoutSec %d (без автовозврата), settle до ответа GP7 не дольше %d с, MaxInFlight %d, RouteMaxAgeSec %d; P100 %s; журнал ac.other 158–163, канал лога %d",
              sites, placed, g_holdTimeout, g_settleMax, g_maxInFlight, g_routeMaxAge, P100_Active() ? L"активен — заряды подарка складываются" : L"не активен — ячейки как сток",
              g_logChannel);
    return PatchResult::Applied;
}
