// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P44 — ★ КОРРЕКТНОСТЬ ПРЯМОГО ОБМЕНА (528x) И ЛИЧНОЙ ЛАВКИ (630x)
//  Оборонительные правки сервера. НАША правка (дефекты оригинала), не перенос чужой.
//
//  Разбор: Reports/trade/trade_re_report.md §3; C1_exchange_server.md §3/§7;
//  C2_selfstore_server.md (D6). Ревизия: Reports/trade/server_p44_REVIEW.md
//  (КРИТ-1…5, СРЕДН-1…3). Документ: AstoryServer/Docs/GameServer/trade-p44.md.
//
//  ★★★ ЭТАЛОН. Все площадки сверены дизассемблером по ЖИВОМУ GameServer.exe и
//  Indun_GameServer.exe (md5 e7b4ac38…, равны базе IDA). Отказ — ТЕМ ЖЕ штатным
//  путём сервера (нотисы из существующих таблиц клиента). [ПРОТОКОЛ] размеры и
//  раскладки пакетов НЕ меняются. С P01…P43 не пересекается.
//
//  Все дефекты достижимы лишь модифицированным клиентом / дублем пакета.
//
//  ── СО-1 CompleteLock [ключ CompleteLock, ВКЛ] ──
//     Завершение обмена (CharExchangeCompleteReq@0x4E4720): (а) нет замка «в полёте»
//     между запросом в БД и ответом БД; (б) сверяются только подтверждения +659/+660,
//     но не фиксации +657/+658.
//     Правки (учтена ревизия КРИТ-2/КРИТ-3):
//       • Замок хранится ОТДЕЛЬНО для каждого CUserManager (поток карты), не глобально:
//         таблица «указатель менеджера → BYTE[550]», P44_LockRow (КРИТ-2). Индекс окна
//         повторяется в разных менеджерах — общий массив давал ложные отказы/снятия.
//       • Замок СТАВИТСЯ в точке фактической отправки запроса в БД (оба sub_5646C0 в
//         …Complete: shell 0x4E70EF, normal 0x4E89B7), ПОСЛЕ всех проверок; отказы
//         1…4 (нет места/вес/золото/Same User, без запроса в БД) замок НЕ оставляют, и
//         повторный ОК проходит (КРИТ-3).
//       • На 0x4E48B3 замок только ПРОВЕРЯЕТСЯ (+ обе фиксации): дубль по помеченному
//         окну идёт в штатный эпилог без БД-запроса.
//       • Снятие — в единственной точке освобождения окна sub_4DF6D0@0x4DF6D0.
//
//  ── СО-3 WindowBounds [ключ WindowBounds, ВКЛ] ──
//     Верхняя граница windowIndex (<550) в 5288/5290/5291/5293 (проверялось только «<0»)
//     + ячейка лотка (<5) в 5288. Заодно (КРИТ-5) 5288/5290/5291 при «в полёте»
//     отказывают штатным путём — лоток нельзя менять, пока ждём ответ БД.
//     Заодно 5286 (КРИТ-4): верхняя граница индекса окна.
//
//  ── СЛ-1 StoreSlotBounds [ключ StoreSlotBounds, ВКЛ] ──
//     Граница индекса лота витрины (0..9) в покупке 6309 (CharSelfStoreBuyItem), оба
//     цикла. Во втором цикле (0x505C6D) пустые записи корзины (itemId ≤ 0, индекс −1)
//     ПРОПУСКАЮТСЯ как в стоке (jmp 0x505C40), а не отвергаются (КРИТ-1) — иначе почти
//     каждая покупка с корзиной < 6 позиций отклонялась бы.
//
//  ── DeathCancelExchange [ключ DeathCancelExchange, ВКЛ] ──
//     Сброс обмена в момент смерти (SendCharDead@0x4CB5D8) — как реген/разрыв. НО при
//     «в полёте» (ждём ответ БД) отмену НЕ делаем (СРЕДН-2): окно освободит recvDB,
//     иначе БД проведёт обмен, а память — нет.
//
//  ── СО-2 (retarget двух jne в recvDB) [часть CompleteLock] ──
//     При несовпадении charId в ответе БД recvDB НЕ освобождает окно (иначе опоздавший
//     ответ рушит переиспользованное окно новой пары; при уже освобождённом окне —
//     двойной возврат в стек). Ветка несовпадения теперь идёт прямо в эпилог, минуя
//     sub_4DF6D0. Shell: jne 0x4E994B 0x4EA723→0x4EA735. Normal: jne 0x4EB628
//     0x4EC33D→0x4EC34F. Успешные (charId совпал) ветки не тронуты.
//
//  ── СО-4 AcceptNeedsRequest [ключ AcceptNeedsRequest, ВЫКЛ по умолчанию] ──
//     Принятие требует висящей заявки. Оставлено ВЫКЛ (решение владельца). Перед
//     включением закрыть два случая (см. doc): (1) userNum уникален лишь внутри
//     менеджера — таблицу заявок сделать «менеджер+цель»; (2) на цель хранится ОДНА
//     заявка — при двух одновременных заявителях более ранний будет отклонён.
//     AcceptTtlMs зажат снизу (≥1000), чтобы 0 не означало «отклонять всё».
//
//  ── Д4 (БД, только описание) ── UPShellItemChange без SET XACT_ABORT ON / единого
//     ROLLBACK. Вне P-патчей DLL. Рекомендация владельцу.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>   // memset (МЕЛК-B: очистка строк таблицы замков)

// ⚠ Смещения в __asm — ТОЛЬКО через #define (закон msvc-inline-asm-offsets); численные
//   пределы — тоже литералами через #define, иначе MSVC берёт constexpr за память.
#define WIN_REC_SIZE     0x231       // 561 — запись окна обмена
#define OFF_FIX_A        0xE1D       // запись+657 — фиксация A (5291 lock)
#define OFF_FIX_B        0xE1E       // запись+658 — фиксация B
#define OFF_EXCH_FLAG    0x145       // CUser+0x145 — «я в обмене»
#define OFF_EXCH_WINDOW  0x149       // CUser+0x149 — индекс моего окна обмена
#define ASM_MAX_WINDOWS  550         // ёмкость массива окон (sub_4DF660: >=550 -> -1)
#define ASM_MAX_SLOT     5           // ячеек лотка на сторону
#define ASM_MAX_STORESLT 10          // строк витрины

// CompleteReq (кадр)
#define CR_MGR           0x20        // [ebp-0x20] CUserManager
#define CR_IDX           0x18        // [ebp-0x18] windowIndex
#define CR_BOTHCONF      0x08        // [ebp-8]   v10 (обе стороны подтвердили)
// SendCharDead (кадр)
#define DEAD_PUSER       0x438       // [ebp-0x438] CUser*
#define DEAD_MGR         0x464       // [ebp-0x464] CUserManager
// CharExchangeReq (успех)
#define REQ_TARGET       0x2C        // [ebp-0x2c] userNum цели (v10[0])
#define REQ_SRC_CODE     0x2E        // [ebp-0x2e] код результата
#define REQ_DST_BUF      0x1C        // [ebp-0x1c] тело 5283
// CharExchangeAcceptReq
#define ACC_MGR          0x58        // [ebp-0x58] CUserManager
#define ACC_INITIATOR    0x47        // [ebp-0x47] userNum заявителя (v9[1])
// …Complete DB-send (кадры)
#define SHELL_MGR        0x514       // [ebp-0x514] CUserManager (CharShell…Complete)
#define NORMAL_MGR       0x1C8       // [ebp-0x1c8] CUserManager (CharNormal…Complete)
#define DBSEND_WINDOW    0x0C        // [ebp+0xC] windowIndex (arg a3 обоих …Complete)
// 5288/5290/5291 (кадры)
#define D88_MGR          0xAC        // [ebp-0xac]  CharExchangeDragDropItem this
#define D88_IDX          0x6C        // [ebp-0x6c]  windowIndex
#define D88_SLOT         0x24        // [ebp-0x24]  dragReq[4] activeSlot
#define D90_MGR          0x60        // [ebp-0x60]  CharExchangeDragDropDeleteItem this
#define D90_IDX          0x54        // [ebp-0x54]  windowIndex
#define D91_MGR          0x218       // [ebp-0x218] CharExchangeFixReq this
#define D91_IDX          0x188       // [ebp-0x188] windowIndex
// 5286 / CharExchanageCancelReq (кадр)
#define C86_IDX          0x34        // [ebp-0x34]  windowIndex
#define C86_MGR          0x44        // [ebp-0x44]  CUserManager (this) в точке освобождения
// buy loop2 (кадр)
#define BUY_K            0x510       // [ebp-0x510] индекс позиции корзины k
#define BUY_V42          0x4EC       // [ebp-0x4ec] v42 (индекс лота витрины)
#define BUY_REC_ITEMID   0x47D       // [ebp + k*0x2d - 0x47D] itemId записи корзины

// ── Пункт 2 (PartnerFlagGuard): флаги обмена CUser ────────────────────────────
//   OFF_EXCH_FLAG(=+0x145) «я в обмене», OFF_EXCH_WINDOW(=+0x149) индекс окна (-1=нет).
//   2A — CharExchanageCancelReq ветка таймаута v10[0]==-2 (0x4E01E2):
//     v8(=user arg0)=[ebp-0x40], v4(=партнёр)=[ebp-0x3C]. Сток чистит оба +0x145.
#define C2A_V8           0x40        // [ebp-0x40]  user(arg0)
#define C2A_V4           0x3C        // [ebp-0x3c]  партнёр (user v10[1])
//   2B — CharExchangeAcceptReq ветка отказа v9[0]!=1 (0x4DFFE2 и 0x4E001C, две копии):
//     v7(=accepter)=[ebp-0x50], v10(=инициатор)=[ebp-0x44]. Сток чистит оба +0x145 и +0x149.
#define C2B_V7           0x50        // [ebp-0x50]  accepter (user arg0)
#define C2B_V10          0x44        // [ebp-0x44]  инициатор (user v9[1])

// ── Пункт 3b (StoreGuestLock): CharSelfStoreInfo @ 0x5044B0, кадр ──────────────
#define SI_MGR           0x2D4       // [ebp-0x2d4] CUserManager (this)
#define SI_HOST          0x284       // [ebp-0x284] v24 — хозяин лавки
#define SI_V16           0x2B4       // [ebp-0x2b4] v16 (репродукция: v16=0 перед поиском)
//   поля записи хозяина (абсолютные смещения CUser, сверены дизассемблером):
#define ST_SLOT_UNUM     0x5B51      // +0x5B51 + 2*i (i16) userNum гостя в слоте
#define ST_SLOT_CID      0x5B3D      // +0x5B3D + 4*i (i32) userIndex (charId) гостя
#define ST_GUEST_COUNT   0x5AE8      // +0x5AE8 (byte) счётчик гостей (+1432)

// ── Пункт 4 (RefusalBySide): коды отказа итога по стороне с нехваткой ─────────
#define P4_ARG8          0x10        // [ebp+0x10] arg8: триггер=сторона +3609 (A) если !=0
//   CharNormalItemExchangeComplete @ 0x4E7110 (5295), блок 0x4E75F7..0x4E7658:
#define P4N_V42          0xC4        // [ebp-0xc4]  свободные слоты A(3609)
#define P4N_V25          0x19C       // [ebp-0x19c] входящих к A
#define P4N_V51          0x5C        // [ebp-0x5c]  свободные слоты B(3611)
#define P4N_V52          0x58        // [ebp-0x58]  входящих к B
#define P4N_V44          0xBC        // [ebp-0xbc]  макс.вес A
#define P4N_V37          0xD8        // [ebp-0xd8]  занятый вес A (вычитается)
#define P4N_V53          0x54        // [ebp-0x54]  вес входящих к A
#define P4N_V40          0xCC        // [ebp-0xcc]  макс.вес B
#define P4N_V49          0x64        // [ebp-0x64]  занятый вес B
#define P4N_V43          0xC0        // [ebp-0xc0]  вес входящих к B
#define P4N_V54          0x50        // [ebp-0x50]  буфер v54 (при arg8 -> A, иначе -> B)
#define P4N_V47          0xB0        // [ebp-0xb0]  буфер v47 (при arg8 -> B, иначе -> A)
#define P4N_V24          0x1A0       // [ebp-0x1a0] v24 (1=нет отказа)
//   CharShellItemExchangeComplete @ 0x4E4910 (5294), блок 0x4E4E7E..0x4E4EF1:
#define P4S_V47          0x268       // [ebp-0x268] свободные слоты A(3609)
#define P4S_V33          0x4CC       // [ebp-0x4cc] входящих к A
#define P4S_V46          0x26C       // [ebp-0x26c] свободные слоты B(3611)
#define P4S_V56          0x12C       // [ebp-0x12c] входящих к B
#define P4S_V49          0x260       // [ebp-0x260] макс.вес A
#define P4S_V44          0x274       // [ebp-0x274] занятый вес A
#define P4S_V57          0x128       // [ebp-0x128] вес входящих к A
#define P4S_V45          0x270       // [ebp-0x270] макс.вес B
#define P4S_V53          0x250       // [ebp-0x250] занятый вес B
#define P4S_V48          0x264       // [ebp-0x264] вес входящих к B
#define P4S_V59          0x120       // [ebp-0x120] буфер v59 (при arg8 -> A, иначе -> B)
#define P4S_V55          0x248       // [ebp-0x248] буфер v55 (при arg8 -> B, иначе -> A)
#define P4S_V32          0x4D0       // [ebp-0x4d0] v32 (1=нет отказа)

namespace
{
    const wchar_t* const S = L"P44_ExchangeIntegrity";

    constexpr int   kMaxWindows   = 550;
    constexpr int   kMaxUserNum   = 560;   // userNum < 0x226; запас
    constexpr int   kMaxManagers  = 64;    // потоков карт/инстансов заведомо меньше

    // ── СО-1 (КРИТ-2): замок «в полёте» ПО КАЖДОМУ CUserManager ──────────────
    //   Каждый менеджер работает в своём потоке, доступ к его строке гонок не даёт;
    //   гонка возможна лишь при первичном захвате слота — она снята Interlocked-CAS.
    //   v31: к байту замка добавлены метка времени (E2) и флаг «освобождение отложено» (E1).
    void*        g_mgrKey[kMaxManagers]                 = { nullptr };
    BYTE         g_mgrRow[kMaxManagers][kMaxWindows]    = { { 0 } };   // 1 = ждём ответ БД
    DWORD        g_mgrTick[kMaxManagers][kMaxWindows]   = { { 0 } };   // GetTickCount() отправки в БД
    BYTE         g_mgrDefer[kMaxManagers][kMaxWindows]  = { { 0 } };   // 1 = отмена отложена до ответа БД
    DWORD        g_deferMaxMs = 30000;                                  // E2: предел отложенной отмены

    // функции GameServer для терпимого освобождения окна (E1)
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short num);        // 0x5324A0
    typedef void* (__thiscall *FnWinInit)(void* rec);                   // 0x4EC420 (пустая запись окна)
    typedef char  (__thiscall *FnStackPush)(void* stack, int idx);      // 0x49F2D0 (вернуть окно в стек)
    const FnGetUser   SrvGetUser   = (FnGetUser)0x005324A0;
    const FnWinInit   SrvWinInit   = (FnWinInit)0x004EC420;
    const FnStackPush SrvStackPush = (FnStackPush)0x0049F2D0;

    // Пункт 3b: sub_5324F0 — userIndex по userNum (null-безопасна, -1 если слота нет).
    typedef int (__thiscall *FnGetUserNum)(void* mgr, short num);     // 0x5324F0
    const FnGetUserNum SrvGetUserNum = (FnGetUserNum)0x005324F0;

    // лог сервера (variadic): void __cdecl Log(int cat, const char* fmt, ...)
    typedef void (__cdecl *FnSrvLog)(int, const char*, ...);
    LONG g_overflowLogged = 0;   // МЕЛК-B: однократная запись при переполнении таблицы

    // Номер слота менеджера (создаётся лениво); -1 — таблица переполнена (fail-open).
    int P44_Slot(void* mgr)
    {
        for (int i = 0; i < kMaxManagers; ++i)
            if (g_mgrKey[i] == mgr) { return i; }
        for (int i = 0; i < kMaxManagers; ++i)
            if (InterlockedCompareExchangePointer(&g_mgrKey[i], mgr, nullptr) == nullptr)
            {
                memset((void*)g_mgrRow[i], 0, sizeof(g_mgrRow[i]));     // МЕЛК-B: чистый слот
                memset((void*)g_mgrTick[i], 0, sizeof(g_mgrTick[i]));
                memset((void*)g_mgrDefer[i], 0, sizeof(g_mgrDefer[i]));
                return i;
            }
        if (InterlockedCompareExchange(&g_overflowLogged, 1, 0) == 0)   // МЕЛК-B: один раз
            ((FnSrvLog)Srv::kLog)(1, "P44: lock table overflow (>%d managers), exchange in-flight lock disabled", kMaxManagers);
        return -1;
    }

    // Строка байтов замка менеджера (для inline-проверок в стабах); nullptr — переполнение.
    BYTE* __cdecl P44_LockRow(void* mgr)
    {
        const int s = P44_Slot(mgr);
        return (s < 0) ? nullptr : g_mgrRow[s];
    }

    // МЕЛК-B (E3): забыть слот менеджера — зовётся из очистки потока карты sub_4BFBE0
    // ПОСЛЕ Send_AllDisConnectUser и ДО удаления менеджера.
    void __cdecl P44_MgrForget(void* mgr)
    {
        for (int i = 0; i < kMaxManagers; ++i)
            if (g_mgrKey[i] == mgr)
            {
                memset((void*)g_mgrRow[i], 0, sizeof(g_mgrRow[i]));
                memset((void*)g_mgrTick[i], 0, sizeof(g_mgrTick[i]));
                memset((void*)g_mgrDefer[i], 0, sizeof(g_mgrDefer[i]));
                InterlockedExchangePointer(&g_mgrKey[i], nullptr);
                return;
            }
    }

    // КРИТ-3: пометить окно «в полёте» в точке отправки в БД (+ метка времени, E2).
    void __cdecl P44_MarkFlight(void* mgr, int idx)
    {
        if (idx < 0 || idx >= kMaxWindows) { return; }
        const int s = P44_Slot(mgr);
        if (s < 0) { return; }
        g_mgrRow[s][idx]   = 1;
        // ★ fix w33b 13.10.2026: было `GetTickCount() | 1` — при чётном now такт = now+1 и в том же кванте таймера now-tick = 0xFFFFFFFF (грабли P63/P33 N-2)
        const DWORD now    = GetTickCount();
        g_mgrTick[s][idx]  = now ? now : 1;
        g_mgrDefer[s][idx] = 0;
    }

    // E2: замок взведён И моложе предела DeferMaxMs.
    int __cdecl P44_YoungLock(void* mgr, int idx)
    {
        if (idx < 0 || idx >= kMaxWindows) { return 0; }
        const int s = P44_Slot(mgr);
        if (s < 0 || !g_mgrRow[s][idx]) { return 0; }
        return ((DWORD)(GetTickCount() - g_mgrTick[s][idx]) < g_deferMaxMs) ? 1 : 0;
    }

    // СРЕДН-A + E2: отложить освобождение, пока замок молод. 1 — отложено (не освобождать).
    int __cdecl P44_DeferCancel(void* mgr, int idx)
    {
        if (!P44_YoungLock(mgr, idx)) { return 0; }       // нет замка или старше предела -> как v29
        g_mgrDefer[P44_Slot(mgr)][idx] = 1;
        return 1;
    }

    // E1: точка освобождения окна sub_4DF6D0. Снимает замок. Если освобождение было отложено —
    // выполняет его ТЕРПИМО к отсутствию участника (ушёл/реген/другой поток): сбросить
    // +0x145/+0x149 у найденных участников (сверка charId), обнулить запись окна по образцу
    // sub_4EC420 и вернуть окно в стек sub_49F2D0. Возврат 1 — освобождено здесь (сток пропустить).
    int __cdecl P44_ReleaseHook(BYTE* mgr, int idx)
    {
        if (idx < 0 || idx >= kMaxWindows) { return 0; }
        const int s = P44_Slot(mgr);
        if (s < 0) { return 0; }
        const BYTE deferred = g_mgrDefer[s][idx];
        g_mgrRow[s][idx] = 0; g_mgrTick[s][idx] = 0; g_mgrDefer[s][idx] = 0;
        if (!deferred) { return 0; }                      // обычное освобождение — стоком
        __try
        {
            BYTE* rec = mgr + idx * 0x231;                // поля записи — со смещениями абсолюта +0xE0C…
            const int   chA = *(int*)(rec + 0xE11),  chB = *(int*)(rec + 0xE15);
            const short nA  = *(short*)(rec + 0xE19), nB  = *(short*)(rec + 0xE1B);
            BYTE* u;
            if ((u = SrvGetUser(mgr, nA)) != nullptr && *(int*)(u + 0x174) == chA)
                { *(int*)(u + 0x145) = 0; *(int*)(u + 0x149) = -1; }
            if ((u = SrvGetUser(mgr, nB)) != nullptr && *(int*)(u + 0x174) == chB)
                { *(int*)(u + 0x145) = 0; *(int*)(u + 0x149) = -1; }
            BYTE tmpl[0x240];
            SrvWinInit(tmpl);
            memcpy(rec + 0xE0C, tmpl, 0x231);
            SrvStackPush(*(void**)(mgr + 0x4CBF0), idx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
        return 1;
    }

    // ── Пункт 3b (StoreGuestLock): чистка застрявших гостевых слотов лавки ───────
    //   Зовётся из CharSelfStoreInfo ДО поиска свободного слота. Для каждого слота
    //   guest[]: если живой userIndex (sub_5324F0 по userNum слота) ≠ сохранённому
    //   charId (+0x5B3D), слот мёртв (гость ушёл аварийно/userNum переиспользован) —
    //   освободить (userNum=-1, charId=-1) и скорректировать счётчик гостей (+0x5AE8).
    //   Чинит «потолок 5 достигнут» и завышенный счётчик при авар. выходах DisConnectUser.
    void __cdecl P44_StoreInfoCleanGuests(void* mgr, BYTE* host)
    {
        if (!mgr || !host) { return; }
        __try
        {
            for (int i = 0; i < 5; ++i)
            {
                short* pUn  = (short*)(host + ST_SLOT_UNUM + 2 * i);
                int*   pCid = (int*)  (host + ST_SLOT_CID  + 4 * i);
                const short un = *pUn;
                if (un < 0) { continue; }                    // слот пуст
                const int live = SrvGetUserNum(mgr, un);     // -1, если слота нет
                if (live != *pCid)                           // мёртв/переиспользован
                {
                    *pUn  = -1;
                    *pCid = -1;
                    BYTE* cnt = host + ST_GUEST_COUNT;
                    if (*cnt > 0) { --(*cnt); }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    // ── СО-4: пометка «заявка initiator→target» (только при AcceptNeedsRequest=1) ──
    struct ReqPending { LONG initiator; DWORD tick; };
    ReqPending g_pending[kMaxUserNum] = { { -1, 0 } };
    DWORD      g_acceptTtlMs = 60000;

    // ── адреса продолжения/отказа (host VA; косвенные jmp/call) ───────────────
    DWORD g_cl_exit      = 0x004E48FD;   // эпилог CompleteReq (без БД)
    DWORD g_cl_dispatch  = 0x004E48B9;   // стоковый диспетчер …Complete
    DWORD g_rel_cont     = 0x004DF6D9;   // sub_4DF6D0 за прологом
    DWORD g_dbsend       = 0x005646C0;   // ConnectSend (запрос в БД)
    DWORD g_shell_dbret  = 0x004E70F4;   // shell …Complete за call sub_5646C0
    DWORD g_normal_dbret = 0x004E89BC;   // normal …Complete за call sub_5646C0
    DWORD g_b88_err  = 0x004E0466, g_b88_cont = 0x004E04A0;   // 5288
    DWORD g_b90_err  = 0x004E3469, g_b90_cont = 0x004E347D;   // 5290
    DWORD g_b91_err  = 0x004E3723, g_b91_cont = 0x004E3766;   // 5291
    DWORD g_b93_err  = 0x004E47E5, g_b93_cont = 0x004E47F9;   // 5293
    DWORD g_b86_err  = 0x004E020C, g_b86_cont = 0x004E0220;   // 5286
    DWORD g_ss1_rej  = 0x00505405, g_ss1_cont = 0x005053C7;   // buy loop1
    DWORD g_ss2_rej  = 0x00505DD3, g_ss2_cont = 0x00505C74, g_ss2_skip = 0x00505C40;  // buy loop2
    DWORD g_death_cont = 0x004CB5E5;
    DWORD g_req_cont   = 0x004DFBF4;
    DWORD g_acc_alloc  = 0x004DF660;
    DWORD g_acc_cont   = 0x004DFE63;
    DWORD g_acc_reject = 0x004DFD7B;
    DWORD g_cancel     = 0x004E00A0;
    // СРЕДН-A / МЕЛК-B
    DWORD g_sub4df6d0     = 0x004DF6D0;   // освобождение окна (thiscall, ret 4)
    DWORD g_cancel_ret    = 0x004E0338;   // CharExchanageCancelReq за call sub_4DF6D0
    DWORD g_mgrforget_cont = 0x004BFC1C;  // sub_4BFBE0 за обнулением [mgr+0xE04] (E3)
    // Пункт 2 (PartnerFlagGuard)
    DWORD g_c2a_cont      = 0x004E0338;   // CancelReq -2: эпилог (как стоковый jmp 0x4E0338)
    DWORD g_c2b_cont      = 0x004E004D;   // AcceptReq отказ: отправка 5285 (общая для обеих копий)
    // Пункт 3b (StoreGuestLock): продолжение после v16=0 (поиск слота)
    DWORD g_si_cont       = 0x005047BE;   // CharSelfStoreInfo: i=0 (инициализация цикла поиска)
    // Пункт 4 (RefusalBySide): продолжения `if(!v24)` / `if(!v32)`
    DWORD g_p4n_cont      = 0x004E7659;   // normal: cmp [ebp-0x1A0],0
    DWORD g_p4s_cont      = 0x004E4EF2;   // shell:  cmp [ebp-0x4D0],0

    // ── СО-4 helpers ──────────────────────────────────────────────────────────
    void __cdecl P44_RecordRequest(int target, int initiator)
    {
        if (target < 0 || target >= kMaxUserNum) { return; }
        g_pending[target].initiator = initiator;
        // ★ fix w33b 13.10.2026: было `GetTickCount() | 1` — при чётном now такт = now+1 и в том же кванте таймера now-tick = 0xFFFFFFFF (грабли P63/P33 N-2)
        const DWORD now             = GetTickCount();
        g_pending[target].tick      = now ? now : 1;
    }
    int __cdecl P44_AcceptAllowed(int accepter, int initiator)
    {
        if (accepter < 0 || accepter >= kMaxUserNum) { return 0; }
        const ReqPending p = g_pending[accepter];
        if (p.tick == 0 || p.initiator != initiator) { return 0; }
        if ((DWORD)(GetTickCount() - p.tick) >= g_acceptTtlMs) { return 0; }
        g_pending[accepter].tick = 0;
        return 1;
    }

    // ═══════════════════ трамплины ═══════════════════════════════════════════

    // ── СО-1: только ПРОВЕРКА (обе фиксации + окно не «в полёте»); замок НЕ ставим ──
    __declspec(naked) void StubCompleteLock()
    {
        __asm
        {
            cmp   dword ptr [ebp - CR_BOTHCONF], 0     // обе стороны подтвердили?
            je    exit_
            mov   eax, [ebp - CR_IDX]
            cmp   eax, 0
            jl    exit_
            cmp   eax, ASM_MAX_WINDOWS
            jae   exit_
            mov   ecx, [ebp - CR_MGR]
            imul  edx, eax, WIN_REC_SIZE
            cmp   byte ptr [ecx + edx + OFF_FIX_A], 0  // фиксация A
            je    exit_
            cmp   byte ptr [ecx + edx + OFF_FIX_B], 0  // фиксация B
            je    exit_
            mov   eax, [ebp - CR_MGR]                  // строка замка этого менеджера
            push  eax
            call  P44_LockRow
            add   esp, 4
            test  eax, eax
            jz    dispatch_                            // строки нет -> пропустить
            mov   edx, [ebp - CR_IDX]
            cmp   byte ptr [eax + edx], 0
            jne   exit_                                // уже «в полёте» -> дубль, отбросить
        dispatch_:
            jmp   dword ptr [g_cl_dispatch]
        exit_:
            jmp   dword ptr [g_cl_exit]
        }
    }

    // ── СО-1: пометить окно «в полёте» в точке отправки в БД (shell) ──
    __declspec(naked) void StubDbSendShell()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp + DBSEND_WINDOW]      // windowIndex
            push  dword ptr [ebp - SHELL_MGR]          // mgr
            call  P44_MarkFlight
            add   esp, 8
            popad                                      // ecx=0x7E0538 восстановлен
            call  dword ptr [g_dbsend]
            jmp   dword ptr [g_shell_dbret]
        }
    }

    // ── СО-1: пометить окно «в полёте» в точке отправки в БД (normal) ──
    __declspec(naked) void StubDbSendNormal()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp + DBSEND_WINDOW]
            push  dword ptr [ebp - NORMAL_MGR]
            call  P44_MarkFlight
            add   esp, 8
            popad
            call  dword ptr [g_dbsend]
            jmp   dword ptr [g_normal_dbret]
        }
    }

    // ── СО-1: снять пометку «в полёте» (единственная точка освобождения окна) ──
    //   Пролог sub_4DF6D0 репродуцирован; this=ecx на входе. pushad/popad сохраняют
    //   ecx для стокового `mov [ebp-0x250],ecx` после нашего jmp.
    __declspec(naked) void StubReleaseWindow()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            sub   esp, 0x250
            pushad
            push  dword ptr [ebp + 8]                  // windowIndex
            push  dword ptr [esp + 0x1C]               // saved ecx (this) — после одного push
            call  P44_ReleaseHook
            add   esp, 8
            test  eax, eax
            popad                                      // флаги не меняет
            jnz   released                             // E1: освобождено терпимо — сток пропустить
            jmp   dword ptr [g_rel_cont]               // обычное освобождение стоком
        released:
            mov   al, 1
            mov   esp, ebp
            pop   ebp
            ret   4
        }
    }

    // ── СО-3 + КРИТ-5: 5288 — границы windowIndex/ячейки + запрет при «в полёте» ──
    __declspec(naked) void StubBound5288()
    {
        __asm
        {
            mov   eax, [ebp - D88_IDX]
            cmp   eax, 0
            jl    err
            cmp   eax, ASM_MAX_WINDOWS
            jae   err
            movzx ecx, byte ptr [ebp - D88_SLOT]
            cmp   ecx, ASM_MAX_SLOT
            jae   err
            mov   eax, [ebp - D88_MGR]
            push  eax
            call  P44_LockRow
            add   esp, 4
            test  eax, eax
            jz    cont_
            mov   edx, [ebp - D88_IDX]
            cmp   byte ptr [eax + edx], 0
            jne   err                                  // «в полёте» -> нельзя менять лоток
        cont_:
            jmp   dword ptr [g_b88_cont]
        err:
            jmp   dword ptr [g_b88_err]
        }
    }

    // ── СО-3 + КРИТ-5: 5290 ──
    __declspec(naked) void StubBound5290()
    {
        __asm
        {
            mov   eax, [ebp - D90_IDX]
            cmp   eax, 0
            jl    err
            cmp   eax, ASM_MAX_WINDOWS
            jae   err
            mov   eax, [ebp - D90_MGR]
            push  eax
            call  P44_LockRow
            add   esp, 4
            test  eax, eax
            jz    cont_
            mov   edx, [ebp - D90_IDX]
            cmp   byte ptr [eax + edx], 0
            jne   err
        cont_:
            jmp   dword ptr [g_b90_cont]
        err:
            jmp   dword ptr [g_b90_err]
        }
    }

    // ── СО-3 + КРИТ-5: 5291 ──
    __declspec(naked) void StubBound5291()
    {
        __asm
        {
            mov   eax, [ebp - D91_IDX]
            cmp   eax, 0
            jl    err
            cmp   eax, ASM_MAX_WINDOWS
            jae   err
            mov   eax, [ebp - D91_MGR]
            push  eax
            call  P44_LockRow
            add   esp, 4
            test  eax, eax
            jz    cont_
            mov   edx, [ebp - D91_IDX]
            cmp   byte ptr [eax + edx], 0
            jne   err
        cont_:
            jmp   dword ptr [g_b91_cont]
        err:
            jmp   dword ptr [g_b91_err]
        }
    }

    // ── СО-3: 5293 — только граница windowIndex (замок — в CompleteLock) ──
    __declspec(naked) void StubBound5293()
    {
        __asm
        {
            mov   eax, [ebp - CR_IDX]
            cmp   eax, 0
            jl    err
            cmp   eax, ASM_MAX_WINDOWS
            jae   err
            jmp   dword ptr [g_b93_cont]
        err:
            jmp   dword ptr [g_b93_err]
        }
    }

    // ── КРИТ-4: 5286 — верхняя граница windowIndex ──
    __declspec(naked) void StubBound5286()
    {
        __asm
        {
            mov   eax, [ebp - C86_IDX]
            cmp   eax, 0
            jl    err
            cmp   eax, ASM_MAX_WINDOWS
            jae   err
            cmp   dword ptr [ebp + 0x10], 0             // a4 >= 0 — внутренняя отмена (разрыв/реген)
            jge   cont_
            push  eax                                  // МЕЛК-E4: пакет 5286 при молодом замке —
            push  dword ptr [ebp - C86_MGR]            //   штатный выход без 5287 и без освобождения
            call  P44_YoungLock
            add   esp, 8
            test  eax, eax
            jnz   quiet
        cont_:
            jmp   dword ptr [g_b86_cont]
        err:
            jmp   dword ptr [g_b86_err]
        quiet:
            jmp   dword ptr [g_cancel_ret]
        }
    }

    // ── СЛ-1: цикл проверки покупки — v42 в 0..9 ──
    __declspec(naked) void StubStoreSlot1()
    {
        __asm
        {
            mov   word ptr [ebp - BUY_V42], dx         // v42 = dx (репродукция)
            movsx eax, dx
            cmp   eax, 0
            jl    rej
            cmp   eax, ASM_MAX_STORESLT
            jge   rej
            jmp   dword ptr [g_ss1_cont]
        rej:
            jmp   dword ptr [g_ss1_rej]
        }
    }

    // ── СЛ-1 + КРИТ-1: цикл применения — пустая запись корзины пропускается ──
    __declspec(naked) void StubStoreSlot2()
    {
        __asm
        {
            mov   word ptr [ebp - BUY_V42], dx         // v42 = dx (репродукция)
            mov   eax, [ebp - BUY_K]                   // k
            imul  eax, eax, 0x2D
            cmp   dword ptr [ebp + eax - BUY_REC_ITEMID], 0   // itemId записи корзины
            jle   skip_                                // пусто/не задано -> стоковый пропуск
            movsx eax, dx
            cmp   eax, 0
            jl    rej
            cmp   eax, ASM_MAX_STORESLT
            jge   rej
            jmp   dword ptr [g_ss2_cont]
        skip_:
            jmp   dword ptr [g_ss2_skip]
        rej:
            jmp   dword ptr [g_ss2_rej]
        }
    }

    // ── death: сброс обмена при смерти; при «в полёте» отмену НЕ делаем (СРЕДН-2) ──
    __declspec(naked) void StubDeathCancel()
    {
        __asm
        {
            mov   ecx, [ebp - DEAD_PUSER]
            mov   dword ptr [ecx + 0x4F], 1            // «мёртв» (репродукция)
            mov   ecx, [ebp - DEAD_PUSER]
            cmp   dword ptr [ecx + OFF_EXCH_FLAG], 0
            je    done
            mov   ecx, [ebp - DEAD_PUSER]
            mov   eax, [ecx + OFF_EXCH_WINDOW]         // windowIndex
            cmp   eax, 0
            jl    done
            push  eax                                  // сохранить window ([esp])
            push  eax                                  // idx
            push  dword ptr [ebp - DEAD_MGR]           // mgr
            call  P44_YoungLock
            add   esp, 8
            test  eax, eax
            jnz   skip_cancel                          // молодой замок -> окно освободит recvDB
            mov   eax, [esp]
            push  eax                                  // a4
            push  0                                    // a3
            xor   edx, edx
            mov   dx, word ptr [ebp + 8]
            push  edx
            mov   ecx, [ebp - DEAD_MGR]
            call  dword ptr [g_cancel]                 // ret 0Ch
        skip_cancel:
            add   esp, 4
        done:
            jmp   dword ptr [g_death_cont]
        }
    }

    // ── СРЕДН-A: отмена/разрыв/реген участника при «в полёте» НЕ освобождает окно ──
    //   Точка освобождения в CharExchanageCancelReq (0x4E032C, до call sub_4DF6D0). Если окно
    //   «в полёте» (ждём ответ БД) — освобождение откладываем: окно освободит recvDB (иначе
    //   обмен в БД проведён, а в память не применён). Иначе — стоковое освобождение.
    __declspec(naked) void StubCancelRelease()
    {
        __asm
        {
            push  dword ptr [ebp - C86_IDX]            // windowIndex
            push  dword ptr [ebp - C86_MGR]            // mgr
            call  P44_DeferCancel                      // 1 = отложено (замок молод)
            add   esp, 8
            test  eax, eax
            jnz   skip_
            mov   edx, [ebp - C86_IDX]                 // репродукция: sub_4DF6D0(this, windowIndex)
            push  edx
            mov   ecx, [ebp - C86_MGR]
            call  dword ptr [g_sub4df6d0]              // ret 4
        skip_:
            jmp   dword ptr [g_cancel_ret]
        }
    }

    // ── МЕЛК-B: забыть слот таблицы замков при удалении менеджера (sub_4BFBE0) ──
    //   Пролог sub_4BFBE0 репродуцирован; this=ecx на входе = удаляемый CUserManager.
    __declspec(naked) void StubMgrForget()
    {
        __asm
        {
            mov   edx, [ebp - 0x84]                    // this = поток карты (репродукция)
            mov   eax, [edx + 0x34]                    // менеджер потока
            mov   dword ptr [eax + 0xE04], 0           // (репродукция стока)
            pushad
            push  eax
            call  P44_MgrForget                        // после Send_AllDisConnectUser, до удаления
            add   esp, 4
            popad
            jmp   dword ptr [g_mgrforget_cont]
        }
    }

    // ── СО-4: запись заявки (только при AcceptNeedsRequest=1) ──
    __declspec(naked) void StubReqRecord()
    {
        __asm
        {
            mov   al, byte ptr [ebp - REQ_SRC_CODE]
            mov   byte ptr [ebp - REQ_DST_BUF], al
            movzx eax, word ptr [ebp + 8]              // initiator = arg0
            push  eax
            movzx eax, word ptr [ebp - REQ_TARGET]     // target = v10[0]
            push  eax
            call  P44_RecordRequest
            add   esp, 8
            jmp   dword ptr [g_req_cont]
        }
    }

    // ── СО-4: гейт принятия (только при AcceptNeedsRequest=1) ──
    __declspec(naked) void StubAcceptGate()
    {
        __asm
        {
            movzx eax, word ptr [ebp - ACC_INITIATOR]
            push  eax
            movzx eax, word ptr [ebp + 8]
            push  eax
            call  P44_AcceptAllowed
            add   esp, 8
            test  eax, eax
            jz    reject
            mov   ecx, [ebp - ACC_MGR]
            call  dword ptr [g_acc_alloc]
            jmp   dword ptr [g_acc_cont]
        reject:
            jmp   dword ptr [g_acc_reject]
        }
    }

    // ═══════════ Пункт 2 (PartnerFlagGuard): сторожа флага партнёра ═══════════
    //  Снимать +0x145 (и, где сток снимал, +0x149) у стороны ТОЛЬКО если она НЕ в
    //  реальном окне-обмене (+0x149 == -1). Сторона с +0x149 != -1 занята обменом с
    //  третьим — её трогать нельзя. [ОРИГИНАЛ] дефект (O1 МЕЛК-6).

    // ── 2A: CharExchanageCancelReq ветка таймаута (-2), площадка 0x4E01E2 ──
    //  Сток чистил оба +0x145 безусловно. Защищаем каждую сторону по её +0x149.
    __declspec(naked) void StubCancelTimeoutGuard()
    {
        __asm
        {
            mov   eax, [ebp - C2A_V8]                  // v8 = user(arg0)
            test  eax, eax
            jz    do_v4                                // null -> пропустить (как сток: сток тоже писал бы в null — но здесь ветка -2 уже проверила v8!=0)
            cmp   dword ptr [eax + OFF_EXCH_WINDOW], -1 // в реальном окне?
            jne   do_v4                                // да -> флаг не трогать
            mov   dword ptr [eax + OFF_EXCH_FLAG], 0    // нет -> снять «я в обмене»
        do_v4:
            mov   eax, [ebp - C2A_V4]                  // v4 = партнёр
            test  eax, eax
            jz    done
            cmp   dword ptr [eax + OFF_EXCH_WINDOW], -1
            jne   done
            mov   dword ptr [eax + OFF_EXCH_FLAG], 0
        done:
            jmp   dword ptr [g_c2a_cont]               // 0x4E0338 (как стоковый jmp)
        }
    }

    // ── 2B: CharExchangeAcceptReq ветка отказа (v9[0]!=1), площадки 0x4DFFE2 и 0x4E001C ──
    //  Обе копии (v12[0]=3 и v12[0]=2) чистят +0x145/+0x149 обеих сторон безусловно.
    //  Один трамплин на обе: защищаем v7 и v10 по их +0x149; продолжение — отправка 5285.
    __declspec(naked) void StubAcceptRefuseGuard()
    {
        __asm
        {
            mov   eax, [ebp - C2B_V7]                  // v7 = accepter
            cmp   dword ptr [eax + OFF_EXCH_WINDOW], -1 // в реальном окне с третьим?
            jne   acc_v10                              // да -> не трогать
            mov   dword ptr [eax + OFF_EXCH_FLAG], 0    // нет -> снять флаг (+0x149 уже -1)
        acc_v10:
            mov   eax, [ebp - C2B_V10]                 // v10 = инициатор
            cmp   dword ptr [eax + OFF_EXCH_WINDOW], -1
            jne   acc_done
            mov   dword ptr [eax + OFF_EXCH_FLAG], 0
        acc_done:
            jmp   dword ptr [g_c2b_cont]               // 0x4E004D (отправка 5285)
        }
    }

    // ═══════════ Пункт 3b (StoreGuestLock): чистка застрявших гостей ═══════════
    //  Площадка 0x5047B4 — перед поиском свободного слота в CharSelfStoreInfo.
    //  Репродуцирует v16=0, вызывает чистку, уходит на инициализацию цикла (i=0).
    __declspec(naked) void StubStoreInfoClean()
    {
        __asm
        {
            mov   dword ptr [ebp - SI_V16], 0          // репродукция: v16 = 0
            pushad
            push  dword ptr [ebp - SI_HOST]            // host (v24)
            push  dword ptr [ebp - SI_MGR]             // mgr (this)
            call  P44_StoreInfoCleanGuests
            add   esp, 8
            popad
            jmp   dword ptr [g_si_cont]                // 0x5047BE (i = 0)
        }
    }

    // ═══════════ Пункт 4 (RefusalBySide): код отказа итога по стороне ═══════════
    //  Считаем код для стороны A(+3609)=cA и B(+3611)=cB по НЕХВАТКЕ (1/2=«ты»,
    //  3/4=«партнёр»), затем раскладываем в буферы по arg8 (буфер «триггера»→его стороне).
    //  cl=cA, ch=cB, dl=hit. Регистры eax/ecx/edx — скретч (продолжение перезагружает).

    // ── 4n: CharNormalItemExchangeComplete (5295), площадка 0x4E75F7 ──
    __declspec(naked) void StubRefusalNormal()
    {
        __asm
        {
            xor   ecx, ecx                             // cl=cA=0, ch=cB=0
            xor   edx, edx                             // dl=hit=0
            // A(3609) нет места: v42 < v25
            mov   eax, [ebp - P4N_V42]
            cmp   eax, [ebp - P4N_V25]
            jge   n_bp
            mov   cl, 1
            mov   ch, 3
            mov   dl, 1
        n_bp:
            // B(3611) нет места: v51 < v52
            mov   eax, [ebp - P4N_V51]
            cmp   eax, [ebp - P4N_V52]
            jge   n_aw
            mov   ch, 1
            mov   cl, 3
            mov   dl, 1
        n_aw:
            // A перевес: v44 - v37 < v53
            mov   eax, [ebp - P4N_V44]
            sub   eax, [ebp - P4N_V37]
            cmp   eax, [ebp - P4N_V53]
            jge   n_bw
            mov   cl, 2
            mov   ch, 4
            mov   dl, 1
        n_bw:
            // B перевес: v40 - v49 < v43
            mov   eax, [ebp - P4N_V40]
            sub   eax, [ebp - P4N_V49]
            cmp   eax, [ebp - P4N_V43]
            jge   n_fin
            mov   ch, 2
            mov   cl, 4
            mov   dl, 1
        n_fin:
            test  dl, dl
            jz    n_cont                               // нет отказа -> буферы/v24 не трогаем
            mov   dword ptr [ebp - P4N_V24], 0         // v24 = 0 (есть отказ)
            cmp   dword ptr [ebp + P4_ARG8], 0         // arg8: v54->A если !=0
            jne   n_arg8
            // !arg8: v54->B(3611), v47->A(3609)  =>  v54=cB(ch), v47=cA(cl)
            mov   byte ptr [ebp - P4N_V54], ch
            mov   byte ptr [ebp - P4N_V47], cl
            jmp   n_cont
        n_arg8:
            // arg8: v54->A(3609), v47->B(3611)  =>  v54=cA(cl), v47=cB(ch)
            mov   byte ptr [ebp - P4N_V54], cl
            mov   byte ptr [ebp - P4N_V47], ch
        n_cont:
            jmp   dword ptr [g_p4n_cont]               // 0x4E7659 (cmp v24,0)
        }
    }

    // ── 4s: CharShellItemExchangeComplete (5294), площадка 0x4E4E7E ──
    __declspec(naked) void StubRefusalShell()
    {
        __asm
        {
            xor   ecx, ecx                             // cl=cA, ch=cB
            xor   edx, edx                             // dl=hit
            // A(3609) нет места: v47 < v33
            mov   eax, [ebp - P4S_V47]
            cmp   eax, [ebp - P4S_V33]
            jge   s_bp
            mov   cl, 1
            mov   ch, 3
            mov   dl, 1
        s_bp:
            // B(3611) нет места: v46 < v56
            mov   eax, [ebp - P4S_V46]
            cmp   eax, [ebp - P4S_V56]
            jge   s_aw
            mov   ch, 1
            mov   cl, 3
            mov   dl, 1
        s_aw:
            // A перевес: v49 - v44 < v57
            mov   eax, [ebp - P4S_V49]
            sub   eax, [ebp - P4S_V44]
            cmp   eax, [ebp - P4S_V57]
            jge   s_bw
            mov   cl, 2
            mov   ch, 4
            mov   dl, 1
        s_bw:
            // B перевес: v45 - v53 < v48
            mov   eax, [ebp - P4S_V45]
            sub   eax, [ebp - P4S_V53]
            cmp   eax, [ebp - P4S_V48]
            jge   s_fin
            mov   ch, 2
            mov   cl, 4
            mov   dl, 1
        s_fin:
            test  dl, dl
            jz    s_cont
            mov   dword ptr [ebp - P4S_V32], 0         // v32 = 0 (есть отказ)
            cmp   dword ptr [ebp + P4_ARG8], 0
            jne   s_arg8
            // !arg8 (LABEL_27): v59->B(3611), v55->A(3609) => v59=cB(ch), v55=cA(cl)
            mov   byte ptr [ebp - P4S_V59], ch
            mov   byte ptr [ebp - P4S_V55], cl
            jmp   s_cont
        s_arg8:
            // arg8 (LABEL_4): v59->A(3609), v55->B(3611) => v59=cA(cl), v55=cB(ch)
            mov   byte ptr [ebp - P4S_V59], cl
            mov   byte ptr [ebp - P4S_V55], ch
        s_cont:
            jmp   dword ptr [g_p4s_cont]               // 0x4E4EF2 (cmp v32,0)
        }
    }

    // ── оригинальные байты площадок (сверка до записи) ──
    const BYTE kCL[]   = { 0x83, 0x7D, 0xF8, 0x00, 0x74, 0x44 };                         // 0x4E48B3 (6)
    const BYTE kRel[]  = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x50, 0x02, 0x00, 0x00 };       // 0x4DF6D0 (9)
    const BYTE kDbS[]  = { 0xE8, 0xCC, 0xD5, 0x07, 0x00 };                               // 0x4E70EF (5)
    const BYTE kDbN[]  = { 0xE8, 0x04, 0xBD, 0x07, 0x00 };                               // 0x4E89B7 (5)
    const BYTE kB88[]  = { 0x83, 0x7D, 0x94, 0x00, 0x7D, 0x3A };                         // 0x4E0460 (6)
    const BYTE kB90[]  = { 0x83, 0x7D, 0xAC, 0x00, 0x7D, 0x14 };                         // 0x4E3463 (6)
    const BYTE kB91[]  = { 0x83, 0xBD, 0x78, 0xFE, 0xFF, 0xFF, 0x00, 0x7D, 0x43 };       // 0x4E371A (9)
    const BYTE kB93[]  = { 0x83, 0x7D, 0xE8, 0x00, 0x7D, 0x14 };                         // 0x4E47DF (6)
    const BYTE kB86[]  = { 0x83, 0x7D, 0xCC, 0x00, 0x7D, 0x14 };                         // 0x4E0206 (6)
    const BYTE kSS1[]  = { 0x66, 0x89, 0x95, 0x14, 0xFB, 0xFF, 0xFF };                   // 0x5053C0 (7)
    const BYTE kSS2[]  = { 0x66, 0x89, 0x95, 0x14, 0xFB, 0xFF, 0xFF };                   // 0x505C6D (7)
    const BYTE kDeath[]= { 0x8B, 0x8D, 0xC8, 0xFB, 0xFF, 0xFF, 0xC7, 0x41, 0x4F, 0x01, 0x00, 0x00, 0x00 }; // 0x4CB5D8 (13)
    const BYTE kCancRel[]= { 0x8B, 0x55, 0xCC, 0x52, 0x8B, 0x4D, 0xBC, 0xE8, 0x98, 0xF3, 0xFF, 0xFF };     // 0x4E032C (12)
    const BYTE kMgrFgt[]= { 0x8B, 0x95, 0x7C, 0xFF, 0xFF, 0xFF, 0x8B, 0x42, 0x34, 0xC7, 0x80, 0x04, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x4BFC09 (19)
    const BYTE kReq[]  = { 0x8A, 0x45, 0xD2, 0x88, 0x45, 0xE4 };                         // 0x4DFBEE (6)
    const BYTE kAcc[]  = { 0x8B, 0x4D, 0xA8, 0xE8, 0xFD, 0xF7, 0xFF, 0xFF };             // 0x4DFE5B (8)

    // ── Пункт 2 (PartnerFlagGuard) ──
    const BYTE k2A[]   = { 0xC7, 0x81, 0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x4E01E2 (10) mov [ecx+0x145],0
    const BYTE k2Ba[]  = { 0xC7, 0x81, 0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x4DFFE2 (10) v9[0]==3 копия
    const BYTE k2Bb[]  = { 0xC7, 0x82, 0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x4E001C (10) v9[0]!=3 копия
    // ── Пункт 3 (StoreGuestLock) ──
    const BYTE k3aNop[]= { 0xC7, 0x81, 0xEF, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x50448C (10) mov [ecx+0x5AEF],0 (guest-close)
    // СРЕДН-1: та же мера на error-path «HostUserIndex Different» (стр.100513). База edx (c7 82),
    //   не ecx как 3a. За инструкцией — jmp 0x504496 (эпилог). NOP безопасен: замок снимет реальная
    //   покупка (set 0x505278, снятие в точках разрешения 6309), а не чужой close по неверному charId.
    const BYTE k3aErr[]= { 0xC7, 0x82, 0xEF, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0x503DB9 (10) mov [edx+0x5AEF],0 (error-path)
    const BYTE kNop10[]= { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // 3a/СРЕДН-1: замена NOP'ами
    const BYTE k3b[]   = { 0xC7, 0x85, 0x4C, 0xFD, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 }; // 0x5047B4 (10) mov [ebp-0x2B4],0 (v16=0)
    // ── Пункт 4 (RefusalBySide) ──
    const BYTE k4n[]   = { 0x8B, 0x85, 0x3C, 0xFF, 0xFF, 0xFF };                         // 0x4E75F7 (6) mov eax,[ebp-0xC4]
    const BYTE k4s[]   = { 0x8B, 0x95, 0x98, 0xFD, 0xFF, 0xFF };                         // 0x4E4E7E (6) mov edx,[ebp-0x268]

    // ── СО-2: две ветки несовпадения charId в recvDB (retarget rel32) ──
    //   Shell jne 0x4E994B: 0x4EA723 -> 0x4EA735 (эпилог, минуя sub_4DF6D0).
    const BYTE kJneShell[]  = { 0x0F, 0x85, 0xD2, 0x0D, 0x00, 0x00 };                    // 0x4E994B (6)
    const BYTE kJneShellNew[]= { 0x0F, 0x85, 0xE4, 0x0D, 0x00, 0x00 };                   //   -> 0x4EA735
    //   Normal jne 0x4EB628: 0x4EC33D -> 0x4EC34F.
    const BYTE kJneNormal[] = { 0x0F, 0x85, 0x0F, 0x0D, 0x00, 0x00 };                    // 0x4EB628 (6)
    const BYTE kJneNormalNew[]={ 0x0F, 0x85, 0x21, 0x0D, 0x00, 0x00 };                   //   -> 0x4EC34F

    // ── КРИТ-4: 5286 гейт участия — je 0x4E032C (release) -> je 0x4E0338 (skip) ──
    const BYTE kJeCancel[]   = { 0x74, 0x3E };                                           // 0x4E02EC (je 0x4E032C)
    const BYTE kJeCancelNew[]= { 0x74, 0x4A };                                           //   -> je 0x4E0338
}

PatchResult P44_ExchangeIntegrity()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }

    const bool doLock   = Config::GetBool(S, L"CompleteLock",        true);
    const bool doBounds = Config::GetBool(S, L"WindowBounds",        true);
    const bool doStore  = Config::GetBool(S, L"StoreSlotBounds",     true);
    const bool doDeath  = Config::GetBool(S, L"DeathCancelExchange", true);
    const bool doAccept = Config::GetBool(S, L"AcceptNeedsRequest",  false);
    const bool doPartner = Config::GetBool(S, L"PartnerFlagGuard",   true);   // Пункт 2
    const bool doGuest   = Config::GetBool(S, L"StoreGuestLock",     true);   // Пункт 3
    const bool doRefusal = Config::GetBool(S, L"RefusalBySide",      true);   // Пункт 4
    int ttl = Config::GetInt(S, L"AcceptTtlMs", 60000);
    if (ttl < 1000) { ttl = 1000; }                 // МЕЛК-1: 0 не должно значить «отклонять всё»
    g_acceptTtlMs = (DWORD)ttl;
    int dmax = Config::GetInt(S, L"DeferMaxMs", 30000);   // E2: предел отложенной отмены
    if (dmax < 1000) { dmax = 1000; }
    g_deferMaxMs = (DWORD)dmax;

    // Сверка ВСЕХ площадок по включённым группам до первой записи.
    Site sites[32];
    int n = 0;
    if (doLock)   { sites[n++] = { 0x004E48B3, kCL,  sizeof(kCL)  };
                    sites[n++] = { 0x004DF6D0, kRel, sizeof(kRel) };
                    sites[n++] = { 0x004E70EF, kDbS, sizeof(kDbS) };
                    sites[n++] = { 0x004E89B7, kDbN, sizeof(kDbN) };
                    sites[n++] = { 0x004E994B, kJneShell,  sizeof(kJneShell)  };
                    sites[n++] = { 0x004EB628, kJneNormal, sizeof(kJneNormal) };
                    sites[n++] = { 0x004E032C, kCancRel, sizeof(kCancRel) };   // СРЕДН-A
                    sites[n++] = { 0x004BFC09, kMgrFgt,  sizeof(kMgrFgt)  }; }  // МЕЛК-B
    if (doBounds) { sites[n++] = { 0x004E0460, kB88, sizeof(kB88) };
                    sites[n++] = { 0x004E3463, kB90, sizeof(kB90) };
                    sites[n++] = { 0x004E371A, kB91, sizeof(kB91) };
                    sites[n++] = { 0x004E47DF, kB93, sizeof(kB93) };
                    sites[n++] = { 0x004E0206, kB86, sizeof(kB86) };
                    sites[n++] = { 0x004E02EC, kJeCancel, sizeof(kJeCancel) }; }
    if (doStore)  { sites[n++] = { 0x005053C0, kSS1, sizeof(kSS1) };
                    sites[n++] = { 0x00505C6D, kSS2, sizeof(kSS2) }; }
    if (doDeath)  { sites[n++] = { 0x004CB5D8, kDeath, sizeof(kDeath) }; }
    if (doAccept) { sites[n++] = { 0x004DFBEE, kReq, sizeof(kReq) };
                    sites[n++] = { 0x004DFE5B, kAcc, sizeof(kAcc) }; }
    if (doPartner){ sites[n++] = { 0x004E01E2, k2A,  sizeof(k2A)  };   // Пункт 2A
                    sites[n++] = { 0x004DFFE2, k2Ba, sizeof(k2Ba) };  // Пункт 2B (v9==3)
                    sites[n++] = { 0x004E001C, k2Bb, sizeof(k2Bb) }; } // Пункт 2B (v9!=3)
    if (doGuest)  { sites[n++] = { 0x0050448C, k3aNop, sizeof(k3aNop) };  // Пункт 3a (NOP)
                    sites[n++] = { 0x00503DB9, k3aErr, sizeof(k3aErr) }; // СРЕДН-1 (NOP, error-path)
                    sites[n++] = { 0x005047B4, k3b, sizeof(k3b) }; }     // Пункт 3b
    if (doRefusal){ sites[n++] = { 0x004E75F7, k4n, sizeof(k4n) };   // Пункт 4 normal
                    sites[n++] = { 0x004E4E7E, k4s, sizeof(k4s) }; } // Пункт 4 shell
    if (n && !VerifyAllSites(L"P44", sites, n)) { return PatchResult::Mismatch; }

    if (doLock)
    {
        if (!Hook::WriteJmp(0x004E48B3, (const void*)&StubCompleteLock,  sizeof(kCL)))  { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E70EF, (const void*)&StubDbSendShell,   sizeof(kDbS))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E89B7, (const void*)&StubDbSendNormal,  sizeof(kDbN))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004DF6D0, (const void*)&StubReleaseWindow, sizeof(kRel))) { return PatchResult::Failed; }
        // СО-2: retarget веток несовпадения charId (не освобождать окно)
        if (!Hook::WriteBytes(0x004E994B, kJneShellNew,  sizeof(kJneShellNew)))  { return PatchResult::Failed; }
        if (!Hook::WriteBytes(0x004EB628, kJneNormalNew, sizeof(kJneNormalNew))) { return PatchResult::Failed; }
        // СРЕДН-A: отмена/разрыв/реген при «в полёте» не освобождает окно (recvDB освободит)
        if (!Hook::WriteJmp(0x004E032C, (const void*)&StubCancelRelease, sizeof(kCancRel))) { return PatchResult::Failed; }
        // МЕЛК-B: освобождение слота таблицы замков при удалении менеджера
        if (!Hook::WriteJmp(0x004BFC09, (const void*)&StubMgrForget, sizeof(kMgrFgt))) { return PatchResult::Failed; }
    }
    if (doBounds)
    {
        if (!Hook::WriteJmp(0x004E0460, (const void*)&StubBound5288, sizeof(kB88))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E3463, (const void*)&StubBound5290, sizeof(kB90))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E371A, (const void*)&StubBound5291, sizeof(kB91))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E47DF, (const void*)&StubBound5293, sizeof(kB93))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E0206, (const void*)&StubBound5286, sizeof(kB86))) { return PatchResult::Failed; }
        // КРИТ-4: 5286 гейт участия (не освобождать чужое окно)
        if (!Hook::WriteBytes(0x004E02EC, kJeCancelNew, sizeof(kJeCancelNew))) { return PatchResult::Failed; }
    }
    if (doStore)
    {
        if (!Hook::WriteJmp(0x005053C0, (const void*)&StubStoreSlot1, sizeof(kSS1))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x00505C6D, (const void*)&StubStoreSlot2, sizeof(kSS2))) { return PatchResult::Failed; }
    }
    if (doDeath)
    {
        if (!Hook::WriteJmp(0x004CB5D8, (const void*)&StubDeathCancel, sizeof(kDeath))) { return PatchResult::Failed; }
    }
    if (doAccept)
    {
        if (!Hook::WriteJmp(0x004DFBEE, (const void*)&StubReqRecord,  sizeof(kReq))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004DFE5B, (const void*)&StubAcceptGate, sizeof(kAcc))) { return PatchResult::Failed; }
    }
    if (doPartner)   // Пункт 2: сторож флага партнёра (обе точки отмены/отказа)
    {
        if (!Hook::WriteJmp(0x004E01E2, (const void*)&StubCancelTimeoutGuard, sizeof(k2A)))  { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004DFFE2, (const void*)&StubAcceptRefuseGuard,  sizeof(k2Ba))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E001C, (const void*)&StubAcceptRefuseGuard,  sizeof(k2Bb))) { return PatchResult::Failed; }
    }
    if (doGuest)     // Пункт 3: лавка
    {
        // 3a: выход гостя НЕ снимает замок покупки хозяина (+0x5AEF) — NOP на 0x50448C
        if (!Hook::WriteBytes(0x0050448C, kNop10, sizeof(kNop10))) { return PatchResult::Failed; }
        // СРЕДН-1: та же мера на error-path «HostUserIndex Different» (0x503DB9) — NOP
        if (!Hook::WriteBytes(0x00503DB9, kNop10, sizeof(kNop10))) { return PatchResult::Failed; }
        // 3b: чистка застрявших гостей перед поиском слота
        if (!Hook::WriteJmp(0x005047B4, (const void*)&StubStoreInfoClean, sizeof(k3b))) { return PatchResult::Failed; }
    }
    if (doRefusal)   // Пункт 4: коды отказа итога по стороне с нехваткой
    {
        if (!Hook::WriteJmp(0x004E75F7, (const void*)&StubRefusalNormal, sizeof(k4n))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x004E4E7E, (const void*)&StubRefusalShell,  sizeof(k4s))) { return PatchResult::Failed; }
    }

    Log::Line(L"    P44: обмен/лавка — CompleteLock(per-mgr,+СРЕДН-A,+МЕЛК-B)=%d WindowBounds=%d StoreSlotBounds=%d "
              L"DeathCancel=%d AcceptNeedsRequest=%d PartnerFlagGuard=%d StoreGuestLock=%d RefusalBySide=%d "
              L"(площадок сверено %d)",
              doLock, doBounds, doStore, doDeath, doAccept, doPartner, doGuest, doRefusal, n);
    return PatchResult::Applied;
}
