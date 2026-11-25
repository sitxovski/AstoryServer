// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P35 — ★ ОБОРОНИТЕЛЬНЫЕ ПРАВКИ СЕРВЕРНОЙ ЧАСТИ РЕМЕСЛА (окна 76000/77000/77500,
//  C→S 6598/6600/6602/6604 → S→C 6599/6601/6603/6605, GameServer ↔ DBManager
//  2661…2668).
//
//  ЭТО НАША ПРАВКА, а не перенос чужой. Разбор: Reports/craft/craft_server.md
//  (§2…§8), craft_re_report.md (§5, §9-С, В6), ревизия craft_re_REVIEW.md (С-1…С-22,
//  Р-6, Р-7). Итог волны: Reports/craft/wave6_server.md, документ патча:
//  AstoryServer/Docs/GameServer/craft-server-defects-p35.md
//
//  ★★★ ЭТАЛОН. Все 39 площадок сверены побайтно в ТРЁХ образах: ЖИВОЙ
//  `v2\GameServer\GameServer.exe`, ЖИВОЙ `v2\Indun_GameServer\GameServer.exe`
//  (оба MD5 E7B4AC38…) и сток `GameServer.exe_before_mine_patch.exe` — расхождений 0.
//  Полный перебор rel8/rel32/jcc по .text живого образа + скан абсолютных DWORD —
//  входов ВНУТРЬ площадок нет. С площадками P01…P34 не пересекается ни одна.
//
//  ★ ПРОТОКОЛ НЕ МЕНЯЕТСЯ (закон old-server-protocol-compat): размеры и раскладки
//  пакетов прежние. Меняются только КОДЫ результата в уже существующих телах — и
//  только на те, которые клиентский приёмник обрабатывает (craft_re_report.md §5.5):
//    6599 {1,10,11,12,13,99}, 6601 {1,10,11,99}, 6603 {0,1,3,4,5,6,99}, 6605 {1,2,99}.
//
//  Ключи (секция [P35_CraftServerDefects]):
//    TsSecretCheck   — С-5: результат штатной анти-повторной проверки sub_524390
//                      (TS-секрет) теперь соблюдается, как во всех прочих обработчиках
//    StateGate       — С-13: причины штатной преамбулы sub_52BFF0 (1 мёртв +0x4F,
//                      2 обмен +0x145, 3 аукцион +0x15F, 4 лавка +0x14D, 5 рыбалка
//                      +0x3F6B4) закрывают все 4 опкода; 6001 НЕ шлётся (у стока он
//                      уходит и при причине 0 — клиенту ремесла он не нужен).
//                      ★ Лавка — только ПРОДАВЕЦ (ревизия, М-4): +0x14D ставится и
//                      посетителю чужой лавки; продавец — у кого +0x151 == свой индекс
//    InFlightLock    — С-3/С-18 (Р-6/Р-7): одна операция ремесла на персонажа, пока БД
//                      не ответила (+ LockTimeoutMs). Снимается: ответ БД, разрыв,
//                      уход порталом, тайм-аут
//    ContainerGuard  — С-1/С-2/С-14: материалы/катализаторы/свитки берутся только из
//                      контейнеров сумки 1 и 2 (не 3 надетое, не 5 склад, не 4 —
//                      способности: 44-б записи, pAbilityOut == nullptr ⇒ падение)
//    RecipeBounds    — Д-Д2/Д-8/С-9: граница ИЗУЧЕНИЯ 6598 — min(576, строк
//                      CraftRecipeInfo @0x7E0394); ИЗГОТОВЛЕНИЯ 6602 — строк Info и
//                      iMakeIndex в [0, CraftRecipeMake). Забывание 6600 — по ёмкости
//                      маски 576 (ревизия, М-5): рецепт вне таблицы, изученный до патча
//                      (свиток 79360 → 248), забывается; таблиц 6600 не читает вовсе
//    ClientCodes     — С-7/Д-12: коды, которых клиент не знает (6603=10, 6605=0),
//                      заменены известными
//    CatalystStack   — С-4: катализатор стопкой >1 расходуется САМ (count−1, вес),
//                      а не отнимает единицу у материала №j
//    CatalystGhost   — С-21: израсходованный катализатор уходит в 6603 с count 0
//    CraftListMask   — С-19: recvDBCraftList не читает 10-й qword маски за пакетом
//    LevelScrollCode — С-20: отказ после фиксации в БД — код 99 вместо немого 0
//    LevelScrollSync — С-20: уровень из ответа БД ставится и в память. ★ ВКЛ по умолчанию
//                      с 27.09.2026 (решение владельца), ПАРА к DBManager P37: до P37
//                      DBManager 0x445B60 всегда отвечал 2668 кодом 1 (Н-1, ревизия С-1),
//                      с P37 код 1 = процедура действительно записала уровень. Остаток
//                      С-1 п.2: свиток в памяти в этой ветке НЕ расходуется (только гонка
//                      модклиента) — см. Reports/craft/p37_dbm.md §3
//    LogPerMinute    — предел строк P35 в журнале Log_Craft (категория 26) в минуту
//
//  С-6 кодом НЕ лечится (решение волны): при рассинхроне charId ответ НЕ шлётся — слот
//  занят другим персонажем. С-10 опровергнут. Опция 24 и данные рецепта 248 — не здесь.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

// P97: при активном P97 вес unsigned short (0..65535)
extern "C" bool __stdcall P97_WeightU16Active();

// ⚠ Смещения в __asm — ТОЛЬКО через #define (закон `msvc-inline-asm-offsets`).
#define CR_DISC_MAIN_FRAME    0xAD4     // DisConnectUser: sub esp, 0xAD4
#define CR_DISC_PORTAL_FRAME  0x6C4     // PortalDisConnectUser: sub esp, 0x6C4
#define CR_INFO_COUNT_VA      0x007E0394// i16 — число строк CraftRecipeInfo.txt
#define CR_RECIPE_MAX         0x244     // 580 — ёмкость флагов CUser+0x40913
#define CR_MASK_BITS          0x240     // 576 — ёмкость маски CUser+0x40B57 (9 qword)
#define CR_6598_PARAM         0xD0      // [ebp-0xD0] int — id рецепта из свитка (item_table +14)

namespace
{
    const wchar_t* const S = L"P35_CraftServerDefects";

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);                     // 0x5324A0
    typedef int   (__thiscall *FnSendPacket)(void* net, short op, short len, short idx,
                                             void* body, short a6, int a7);          // 0x4C28F0
    typedef int   (__thiscall *FnFetch)(void* self, short idx, short cont, short slot,
                                        void* out, void* abilityOut);               // 0x4D61E0
    typedef int   (__thiscall *FnRecvDb)(void* mgr, short idx, void* pkt);           // recvDB*
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);             // 0x569DF0

    const FnGetUser    SrvGetUser    = (FnGetUser)Srv::kGetUser;
    const FnSendPacket SrvSendPacket = (FnSendPacket)Srv::kSendPacket;
    const FnFetch      SrvFetch      = (FnFetch)0x004D61E0;
    const FnRecvDb     SrvRecvReg    = (FnRecvDb)0x0053D4A0;   // recvDBCraftRecipeRegist  (2662)
    const FnRecvDb     SrvRecvDel    = (FnRecvDb)0x0053DA70;   // recvDBCraftRecipeDelete  (2664)
    const FnRecvDb     SrvRecvEnter  = (FnRecvDb)0x0053EE30;   // recvDBCraftEnter         (2666)
    const FnRecvDb     SrvRecvLvl    = (FnRecvDb)0x0053F960;   // recvDBCraftScrollLevelUP (2668)
    const FnSrvLog     SrvLog        = (FnSrvLog)Srv::kLog;

    constexpr int   kLogCat         = 26;          // категория штатных строк ремесла (push 1Ah)
    constexpr int   kOffCharId      = 0x174;       // CUser+0x174 — charId (сверка в recvDB*)
    constexpr int   kOffCraftLevel  = 0x4090E;     // CUser — u8 уровень ремесла
    constexpr DWORD kInfoCountVa    = CR_INFO_COUNT_VA;
    constexpr DWORD kInfoPtrVa      = 0x007E0398;  // CraftRecipeInfo, записи по 128 б
    constexpr DWORD kMakeCountVa    = 0x007E039C;  // i16 — число строк CraftRecipeMake.txt
    constexpr int   kInfoRec        = 128;
    constexpr int   kInfoMakeIdx    = 124;         // Info +124 i32 iMakeIndex
    constexpr DWORD kFuncTablePtr   = 0x005F5E70;  // Function_Table, записи по 48 б
    constexpr int   kFuncRec        = 48;
    constexpr int   kFuncWeight     = 4;           // +4 i16 — вес единицы (как у стока :36671)
    constexpr int   kMaxUserIdx     = 10000;       // запас; живые индексы < 0x226
    constexpr int   kRec            = 57;          // ItemRecord

    // ── ключи ───────────────────────────────────────────────────────────────
    bool  g_stateGate   = true;
    bool  g_lockOn      = true;
    bool  g_contGuard   = true;
    bool  g_lvlSync     = true;         // 27.09: вкл (Н-1 вылечен DBManager P37)
    BYTE  g_lvlCode     = 99;           // код 6605 в ветках С-20 (0 — как в стоке)
    DWORD g_lockTimeout = 15000;
    int   g_logMax      = 30;

    // ═════════════════════════════════════════════════════════════════════════
    //  Журнал с пределом: не больше LogPerMinute строк P35 в минуту. Модифицированный
    //  клиент может слать отказные пакеты сотнями — журнал ремесла не должен тонуть.
    // ═════════════════════════════════════════════════════════════════════════
    CRITICAL_SECTION g_logCs;
    bool             g_logCsInit = false;
    DWORD            g_logWin    = 0;
    int              g_logCnt    = 0;
    int              g_logDrop   = 0;

    bool LogAllowed()
    {
        if (!g_logCsInit) { return true; }
        int  dropped = 0;
        bool ok;
        EnterCriticalSection(&g_logCs);
        const DWORD now = GetTickCount();
        if (g_logWin == 0 || (DWORD)(now - g_logWin) >= 60000)
        {
            dropped   = g_logDrop;
            g_logWin  = now ? now : 1;   // [fix2, НИЗК-12 integ3] было now | 1: в кванте старта now-win=0xFFFFFFFF, окно сбрасывалось каждой строкой
            g_logCnt  = 0;
            g_logDrop = 0;
        }
        ok = g_logCnt < g_logMax;
        if (ok) { ++g_logCnt; } else { ++g_logDrop; }
        LeaveCriticalSection(&g_logCs);
        if (dropped > 0)
        {
            SrvLog(kLogCat, "P35: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)",
                   dropped, g_logMax);
        }
        return ok;
    }
#define P35LOG(...) do { if (LogAllowed()) { SrvLog(kLogCat, __VA_ARGS__); } } while (0)

    // ═════════════════════════════════════════════════════════════════════════
    //  С-3/С-18: замок «одна операция ремесла в полёте». Ключ — (индекс сессии,
    //  charId): charId отсекает чужую запись, если слот занял другой персонаж.
    //  Общий на 4 опкода: все четыре пишут в БД АБСОЛЮТНЫЕ значения (уровень, опыт,
    //  вес, счётчик рецептов), а память CUser меняет только приём ответа БД.
    // ═════════════════════════════════════════════════════════════════════════
    struct LockEntry { int charId; DWORD tick; short op; };
    LockEntry        g_lock[kMaxUserIdx] = {};
    CRITICAL_SECTION g_lockCs;
    bool             g_lockCsInit = false;

    bool LockActiveNoCs(short idx, int charId)
    {
        if (idx < 0 || idx >= kMaxUserIdx) { return false; }
        const LockEntry& e = g_lock[idx];
        if (e.tick == 0 || e.charId != charId) { return false; }
        return (DWORD)(GetTickCount() - e.tick) < g_lockTimeout;
    }

    // Описание обработчиков: кадр `this` (сохранённый ecx), ответ и код отказа.
    struct HandlerInfo
    {
        short       op;          // C→S
        short       replyOp;     // S→C
        short       replyLen;    // длина тела ответа (как у стока)
        BYTE        refuseCode;  // код отказа гейта состояния — из известных клиенту
        int         thisOff;     // [ebp - thisOff] — this обработчика
        const char* name;
    };
    const HandlerInfo kH[4] =
    {
        { 6598, 6599,  64, 10, 0x124, "RecvUser_CraftRecipeRegist(6598)" },   // 10 → 5560 «Ошибка данных»
        { 6600, 6601,   3, 10, 0x04C, "RecvUser_CraftRecipeDelete(6600)" },   // 10 → 5560
        { 6602, 6603, 525,  0, 0x820, "RecvUser_CraftEnter(6602)"        },   // 0  → 5563 + сброс окна
        { 6604, 6605,  61, 99, 0x0E8, "RecvUser_CraftScrollLevelUP(6604)"},   // 99 → 5563
    };

    void SendRefuse(BYTE* self, short idx, const HandlerInfo& h)
    {
        BYTE body[525] = {};
        body[0] = h.refuseCode;
        void* net = *(void**)(self + 4);
        SrvSendPacket(net, h.replyOp, h.replyLen, idx, body, idx, 1);   // a6 = idx, a7 = 1 — как у стока
    }

    // Причина штатной преамбулы sub_52BFF0 (0 — можно). Поля CUser сняты с её asm:
    // 0x4CB030 [+0x4F], 0x52C070 [+0x145], 0x52C0A6 [+0x15F], 0x52C0DC [+0x14D],
    // 0x52C10F byte [+0x3F6B4].
    //
    // ★ Ревизия, М-4: +0x14D ставится ОБОИМ — продавцу (CharSelfStoreReady 0x502D8C,
    //   рядом 0x502D9D `mov [+0x151], [ebp+8]` = СВОЙ индекс и 0x502DA7 байт +0x5AE7 = 1
    //   «лавка открыта») и посетителю чужой лавки (CharSelfStoreInfo 0x504837/0x5048DD,
    //   рядом `mov [+0x151], [ebp-0x2A4]` = индекс ВЛАДЕЛЬЦА; «Same User Error» стока не
    //   даёт зайти в свою лавку посетителем, поэтому у посетителя +0x151 != свой индекс).
    //   Блокируем только продавца: его вещи выставлены, посетитель ничего не держит.
    int StateReason(const BYTE* u, short idx)
    {
        if (*(const int*)(u + 0x4F))     { return 1; }   // мёртв
        if (*(const int*)(u + 0x145))    { return 2; }   // обмен
        if (*(const int*)(u + 0x15F))    { return 3; }   // аукцион
        if (*(const int*)(u + 0x14D) && *(const short*)(u + 0x151) == idx) { return 4; }   // своя лавка
        if (*(const BYTE*)(u + 0x3F6B4)) { return 5; }   // рыбалка
        return 0;
    }
    const char* const kReasonName[6] = { "-", "DEAD", "TRADE", "AUCTION", "OWN PRIVATE SHOP (seller)", "FISHING" };

    // Общий снятчик замка после приёма ответа БД. charId — из тела ответа.
    int WrapRecv(FnRecvDb fn, int charOff, void* mgr, int a2, int pkt)
    {
        const short idx  = (short)a2;
        bool        have = false;
        int         cid  = 0;
        if (g_lockOn && g_lockCsInit && idx >= 0 && idx < kMaxUserIdx)
        {
            __try { cid = *(int*)(pkt + 9 + charOff); have = true; }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        const int r = fn(mgr, idx, (void*)pkt);
        // Снимаем ПОСЛЕ обработки: пока приём не записал результат в память CUser,
        // новый пакет того же персонажа обязан видеть замок (урок P33, М-2).
        if (have)
        {
            EnterCriticalSection(&g_lockCs);
            if (g_lock[idx].charId == cid) { g_lock[idx].tick = 0; }
            LeaveCriticalSection(&g_lockCs);
        }
        return r;
    }
}

// ═══════════════════════════ C-обработчики ═════════════════════════════════
extern "C"
{
// Гейт состояния + ранняя проверка замка. Площадка — сразу ПОСЛЕ штатных
// анти-повтора sub_524390 и подписи sub_523F00 (поддельный пакет идёт штатной
// веткой), ДО копирования тела. 0 — дальше по стоку, 1 — обработчик уходит в эпилог.
int __cdecl P35_Early(BYTE* ebp, int k)
{
    if (k < 0 || k > 3) { return 0; }
    const HandlerInfo& h = kH[k];
    __try
    {
        const short idx  = *(short*)(ebp + 8);
        BYTE*       self = *(BYTE**)(ebp - h.thisOff);
        void*       mgr  = *(void**)(*(BYTE**)(self + 4) + 0x34);
        BYTE*       u    = SrvGetUser(mgr, idx);
        if (!u) { return 0; }                               // сток сам выйдет по «нет пользователя»
        const int cid = *(int*)(u + kOffCharId);

        if (g_lockOn && g_lockCsInit)
        {
            EnterCriticalSection(&g_lockCs);
            const bool  busy = LockActiveNoCs(idx, cid);
            const short prev = g_lock[(idx >= 0 && idx < kMaxUserIdx) ? idx : 0].op;
            LeaveCriticalSection(&g_lockCs);
            if (busy)
            {
                // Ответа НЕТ намеренно: итог придёт ответом на ПЕРВЫЙ запрос, а отказной
                // код сбросил бы окно клиента посреди операции (К-1 — вылет клиента).
                P35LOG("P35 C-3: %s from user %d (charId %d) dropped - craft opcode %d is still waiting for DB reply",
                       h.name, (int)idx, cid, (int)prev);
                return 1;
            }
        }
        // Гейт состояния — ПОСЛЕ замка (ревизия, М-1): пока первый запрос ждёт БД,
        // отказной код (6603 код 0 = сброс окна) уйти не должен — схема вылета К-1.
        if (g_stateGate)
        {
            const int why = StateReason(u, idx);
            if (why)
            {
                P35LOG("P35 C-13: %s from user %d (charId %d) refused - %s (reason %d of sub_52BFF0); reply %d code %d",
                       h.name, (int)idx, cid, kReasonName[why], why, (int)h.replyOp, (int)h.refuseCode);
                SendRefuse(self, idx, h);
                return 1;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 0;
}

// Атомарная постановка замка: стаб на `call ConnectSend` (2661/2663/2665/2667).
// a → [op][len][conn][body][userIdx] (аргументы thiscall ConnectSend на стеке).
// 1 — отправлять, 0 — дубль (пакет в БД не уходит, память CUser не тронута).
int __stdcall P35_GateSend(int* a)
{
    if (!g_lockOn || !g_lockCsInit) { return 1; }
    const short op   = (short)a[0];
    BYTE*       body = (BYTE*)a[3];
    const short idx  = (short)a[4];
    if (idx < 0 || idx >= kMaxUserIdx || !body) { return 1; }
    // charId в теле GS→DB: 2665 — +4, прочие три — +2 (сверено с приёмниками ответа:
    // 0x53D526 [ebp-0x9E], 0x53DACF [ebp-0x16], 0x53EEBC [ebp-0x454], 0x53F9F1 [ebp-0x8E]).
    const int cid = *(int*)(body + (op == 2665 ? 4 : 2));

    EnterCriticalSection(&g_lockCs);
    const bool busy = LockActiveNoCs(idx, cid);
    if (!busy)
    {
        g_lock[idx].charId = cid;
        // ★ fix w33b 13.10.2026: было `GetTickCount() | 1` — при чётном now такт = now+1 и в том же кванте таймера now-tick = 0xFFFFFFFF (грабли P63/P33 N-2)
        const DWORD now    = GetTickCount();
        g_lock[idx].tick   = now ? now : 1;        // 0 зарезервирован под «свободно»
        g_lock[idx].op     = op;
    }
    LeaveCriticalSection(&g_lockCs);

    if (busy)
    {
        P35LOG("P35 C-3: DB packet %d for user %d (charId %d) suppressed - craft operation already in flight",
               (int)op, (int)idx, cid);
        return 0;
    }
    return 1;
}

// Снятие замка при разрыве / уходе порталом (вход DisConnectUser / PortalDisConnectUser).
void __cdecl P35_OnDisconnect(int userNum)
{
    const short idx = (short)userNum;
    if (!g_lockCsInit || idx < 0 || idx >= kMaxUserIdx) { return; }
    EnterCriticalSection(&g_lockCs);
    g_lock[idx].tick = 0;
    LeaveCriticalSection(&g_lockCs);
}

// Подмены `call recvDB*` в диспетчере ответов БД (thiscall → fastcall + пустой edx).
int __fastcall P35_RecvReg  (void* mgr, void*, int a2, int pkt) { return WrapRecv(SrvRecvReg,   2, mgr, a2, pkt); }
int __fastcall P35_RecvDel  (void* mgr, void*, int a2, int pkt) { return WrapRecv(SrvRecvDel,   2, mgr, a2, pkt); }
int __fastcall P35_RecvEnter(void* mgr, void*, int a2, int pkt) { return WrapRecv(SrvRecvEnter, 4, mgr, a2, pkt); }
int __fastcall P35_RecvLvl  (void* mgr, void*, int a2, int pkt) { return WrapRecv(SrvRecvLvl,   2, mgr, a2, pkt); }

// С-1/С-2/С-14: подмена `call sub_4D61E0` в 6598/6602(материалы, катализаторы)/6604.
// Контейнер не 1/2 ⇒ «слот пуст» (запись 0) ⇒ штатная ветка отказа обработчика
// (6599 код 10, 6603 код 10→3 / 3, 6605 код 0→99). Контейнер 4 в стоке писал
// 44 байта в pAbilityOut == nullptr — падение всего GameServer одним пакетом.
int __fastcall P35_Fetch(void* self, void*, int userIdx, int cont, int slot, void* out, void* abilityOut)
{
    const short c = (short)cont;
    if (g_contGuard && c != 1 && c != 2)
    {
        if (out) { *(int*)out = 0; }
        P35LOG("P35 C-1: user %d asked craft item from container %d slot %d - only bag containers 1/2 "
               "are allowed (3 worn, 4 abilities -> crash, 5 warehouse); treated as empty slot",
               (int)(short)userIdx, (int)c, (int)(short)slot);
        return 0;
    }
    return SrvFetch(self, (short)userIdx, c, (short)slot, out, abilityOut);
}

// Д-Д2/Д-8/С-9: 6602 — рецепт в [0, InfoCount) и < 580, а его iMakeIndex в [0, MakeCount).
// 1 — годится (дальше копия Info/Make), 0 — штатный отказ кодом 0.
int __cdecl P35_RecipeOk6602(BYTE* ebp)
{
    __try
    {
        const int r     = *(short*)(ebp - 0x548);
        const int cnt   = *(short*)kInfoCountVa;
        const int mcnt  = *(short*)kMakeCountVa;
        if (r < 0 || r >= cnt || r >= CR_RECIPE_MAX) { return 0; }
        BYTE* info = *(BYTE**)kInfoPtrVa;
        if (!info) { return 0; }
        const int mk = *(int*)(info + r * kInfoRec + kInfoMakeIdx);
        if (mk < 0 || mk >= mcnt)
        {
            P35LOG("P35 D-8: 6602 from user %d: recipe %d has iMakeIndex %d outside CraftRecipeMake (%d rows) - refused, code 0",
                   (int)*(short*)(ebp + 8), r, mk, mcnt);
            return 0;
        }
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// С-4: ветка «катализатор j, count > 1». Сток ставил статус 1, но уменьшал count
// МАТЕРИАЛА j ([ebp-0x7B7+57j]), а вес не трогал. Здесь — count и вес самого
// катализатора ([ebp-0x5C8+57j]), вес единицы — Function_Table +4.
void __cdecl P35_CatStack(BYTE* ebp)
{
    __try
    {
        const int j   = *(int*)(ebp - 0x7CC);
        if (j < 0 || j > 1) { return; }
        BYTE* rec     = ebp - 0x5C8 + kRec * j;
        const int code = *(int*)rec;
        *(BYTE*)(ebp - 0x4C4 + j) = 1;                                  // статус «обновить»
        *(int*)(rec + 9) -= 1;                                          // count
        short unitW = 0;
        BYTE* ft = *(BYTE**)kFuncTablePtr;
        if (ft && code >= 1) { unitW = *(short*)(ft + kFuncRec * (code - 1) + kFuncWeight); }
        *(short*)(rec + 14)       -= unitW;                             // вес стопки
        if (P97_WeightU16Active())
        {
            int w = (int)*(unsigned short*)(ebp - 0x238) - (int)unitW;
            if (w < 0) { w = 0; }
            if (w > 65535) { w = 65535; }
            *(unsigned short*)(ebp - 0x238) = (unsigned short)w;        // P97: u16
        }
        else
        {
            *(short*)(ebp - 0x238) -= unitW;                            // сток: i16
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// С-20: БД уже записала новый уровень ремесла и израсходовала свиток, а GameServer
// не нашёл свиток в слоте (переложен, пока ждали ответ). Уровень — в память, как у
// успешной ветки (0x53FBB0 `mov [edx+0x4090E], al`), иначе следующий 6602 запишет
// в БД старый уровень абсолютным значением и свиток пропадёт без эффекта.
void __cdecl P35_LvlMiss(BYTE* ebp)
{
    __try
    {
        BYTE* u = *(BYTE**)(ebp - 0xD0);
        const char lvl = *(char*)(ebp - 0x89);
        if (u && g_lvlSync)
        {
            const char old = *(char*)(u + kOffCraftLevel);
            *(char*)(u + kOffCraftLevel) = lvl;
            P35LOG("P35 C-20: 6604 DB committed craft level %d for charId %d, scroll not found in slot - "
                   "level %d -> %d set in memory, reply code %d", (int)lvl, *(int*)(u + kOffCharId),
                   (int)old, (int)lvl, (int)g_lvlCode);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
}   // extern "C"

// ═══════════════════════════ трамплины ══════════════════════════════════════
namespace
{
    DWORD g_pConnectSend = Srv::kConnectSend;   // 0x5646C0 — штатная цель 4 вызовов

    // выходы (эпилоги) обработчиков
    DWORD g_pExit6598 = 0x0053D444;
    DWORD g_pExit6600 = 0x0053DA5D;
    DWORD g_pExit6602 = 0x0053ED2C;
    DWORD g_pExit6604 = 0x0053F91B;
    // TS: возврат за вытесненные `push 1; movsx edx,[ebp+8]`
    DWORD g_pTs6598   = 0x0053CD43;
    DWORD g_pTs6600   = 0x0053D853;
    DWORD g_pTs6602   = 0x0053DC46;
    DWORD g_pTs6604   = 0x0053F523;
    // EARLY: штатная цель `jne` «подпись верна»
    DWORD g_pGo6598   = 0x0053CD64;
    DWORD g_pGo6600   = 0x0053D871;
    DWORD g_pGo6602   = 0x0053DC67;
    DWORD g_pGo6604   = 0x0053F544;
    // границы
    DWORD g_pB6598Ok  = 0x0053CFB3;   // штатная цель `jl` (рецепт в пределах)
    DWORD g_pB6598No  = 0x0053CF62;   // лог (3) + 6599 код 10
    DWORD g_pB6602Ok  = 0x0053DDBE;   // копия Info/Make
    DWORD g_pB6602No  = 0x0053DD63;   // лог (1) + 6603 код 0
    // катализатор / уровень / разрыв
    DWORD g_pCatNext  = 0x0053E6A8;   // `jmp 0x53E3B1` — следующий катализатор
    DWORD g_pLvl1Ret  = 0x0053FA9E;
    DWORD g_pLvl2Ret  = 0x0053FB06;
    DWORD g_pDiscMain = 0x005245D9;   // DisConnectUser за прологом
    DWORD g_pDiscPort = 0x00525EB9;   // PortalDisConnectUser за прологом

    // ── С-5: сразу за `call sub_524390`, eax = 1 (годен) / 0 (повтор/подделка).
    //    Как во всех прочих обработчиках: 0 ⇒ эпилог. Вытеснено `push 1; movsx edx,[ebp+8]`.
    __declspec(naked) void Ts6598()
    {
        __asm { test eax, eax
                jz   X
                push 1
                movsx edx, word ptr [ebp + 8]
                jmp  dword ptr [g_pTs6598]
            X:  jmp  dword ptr [g_pExit6598] }
    }
    __declspec(naked) void Ts6600()
    {
        __asm { test eax, eax
                jz   X
                push 1
                movsx edx, word ptr [ebp + 8]
                jmp  dword ptr [g_pTs6600]
            X:  jmp  dword ptr [g_pExit6600] }
    }
    __declspec(naked) void Ts6602()
    {
        __asm { test eax, eax
                jz   X
                push 1
                movsx edx, word ptr [ebp + 8]
                jmp  dword ptr [g_pTs6602]
            X:  jmp  dword ptr [g_pExit6602] }
    }
    __declspec(naked) void Ts6604()
    {
        __asm { test eax, eax
                jz   X
                push 1
                movsx edx, word ptr [ebp + 8]
                jmp  dword ptr [g_pTs6604]
            X:  jmp  dword ptr [g_pExit6604] }
    }

    // ── С-13 + С-3 (ранняя проверка): вместо `test eax,eax; jne ok; jmp exit` за
    //    `call sub_523F00`. eax/ecx/edx на цели «ok» пишутся до чтения, флаги тоже.
    __declspec(naked) void Early6598()
    {
        __asm { test eax, eax
                jz   X
                push 0
                push ebp
                call P35_Early
                add  esp, 8
                test eax, eax
                jnz  X
                jmp  dword ptr [g_pGo6598]
            X:  jmp  dword ptr [g_pExit6598] }
    }
    __declspec(naked) void Early6600()
    {
        __asm { test eax, eax
                jz   X
                push 1
                push ebp
                call P35_Early
                add  esp, 8
                test eax, eax
                jnz  X
                jmp  dword ptr [g_pGo6600]
            X:  jmp  dword ptr [g_pExit6600] }
    }
    __declspec(naked) void Early6602()
    {
        __asm { test eax, eax
                jz   X
                push 2
                push ebp
                call P35_Early
                add  esp, 8
                test eax, eax
                jnz  X
                jmp  dword ptr [g_pGo6602]
            X:  jmp  dword ptr [g_pExit6602] }
    }
    __declspec(naked) void Early6604()
    {
        __asm { test eax, eax
                jz   X
                push 3
                push ebp
                call P35_Early
                add  esp, 8
                test eax, eax
                jnz  X
                jmp  dword ptr [g_pGo6604]
            X:  jmp  dword ptr [g_pExit6604] }
    }

    // ── С-3: вместо `call ConnectSend` (ecx = CUserMoveManager 0x7E0538; на стеке
    //    [ret][op][len][conn][body][userIdx]). Годен — хвостовой переход со ВСЕМ стеком
    //    как был; дубль — сами снимаем 5 аргументов (thiscall).
    __declspec(naked) void StubSend()
    {
        __asm { push ecx
                lea  eax, [esp + 8]
                push eax
                call P35_GateSend
                pop  ecx
                test eax, eax
                jz   Drop
                jmp  dword ptr [g_pConnectSend]
            Drop:
                xor  eax, eax
                ret  0x14 }
    }

    // ── разрыв: вход функций, [esp+4] = UserNum; ecx (this) сохраняем.
    __declspec(naked) void DiscMain()
    {
        __asm { push ecx
                push dword ptr [esp + 8]
                call P35_OnDisconnect
                add  esp, 4
                pop  ecx
                push ebp
                mov  ebp, esp
                sub  esp, CR_DISC_MAIN_FRAME
                jmp  dword ptr [g_pDiscMain] }
    }
    __declspec(naked) void DiscPortal()
    {
        __asm { push ecx
                push dword ptr [esp + 8]
                call P35_OnDisconnect
                add  esp, 4
                pop  ecx
                push ebp
                mov  ebp, esp
                sub  esp, CR_DISC_PORTAL_FRAME
                jmp  dword ptr [g_pDiscPort] }
    }

    // ── Д-Д2: 6598, `cmp [ebp-0xD0],580; jl ok` → граница min(576, InfoCount).
    //    576 — ёмкость маски: id 576…579 recvDBCraftRecipeRegist писал бы 10-м qword
    //    за маской 9×64. Выше по коду уже проверено `[ebp-0xD0] > 0`. eax/ecx мёртвы.
    __declspec(naked) void Bound6598()
    {
        __asm { mov   eax, dword ptr [ebp - CR_6598_PARAM]
                mov   ecx, CR_INFO_COUNT_VA
                movsx ecx, word ptr [ecx]
                cmp   ecx, CR_MASK_BITS
                jle   L
                mov   ecx, CR_MASK_BITS
            L:  cmp   eax, ecx
                jge   No
                jmp   dword ptr [g_pB6598Ok]
            No: jmp   dword ptr [g_pB6598No] }
    }

    // ── Д-8/С-9: 6602, вместо `movsx ecx,[ebp-0x548]; … cmp с MakeCount`.
    __declspec(naked) void Bound6602()
    {
        __asm { push ebp
                call P35_RecipeOk6602
                add  esp, 4
                test eax, eax
                jz   No
                jmp  dword ptr [g_pB6602Ok]
            No: jmp  dword ptr [g_pB6602No] }
    }

    // ── С-4: ветка «count катализатора > 1» (вытеснено `mov eax,[ebp-0x7CC]`;
    //    ветка целиком заменена — её хвост уходит на 0x53E6A8).
    __declspec(naked) void CatStack()
    {
        __asm { push ebp
                call P35_CatStack
                add  esp, 4
                jmp  dword ptr [g_pCatNext] }
    }

    // ── С-20: `add esp,N; mov byte [ebp-0x44],0` → уровень в память + код g_lvlCode.
    __declspec(naked) void LvlMiss1()
    {
        __asm { add  esp, 0x0C
                push ebp
                call P35_LvlMiss
                add  esp, 4
                mov  al, byte ptr [g_lvlCode]
                mov  byte ptr [ebp - 0x44], al
                jmp  dword ptr [g_pLvl1Ret] }
    }
    __declspec(naked) void LvlMiss2()
    {
        __asm { add  esp, 0x14
                push ebp
                call P35_LvlMiss
                add  esp, 4
                mov  al, byte ptr [g_lvlCode]
                mov  byte ptr [ebp - 0x44], al
                jmp  dword ptr [g_pLvl2Ret] }
    }

    // ── площадки ────────────────────────────────────────────────────────────
    const BYTE kTs[6]       = { 0x6A, 0x01, 0x0F, 0xBF, 0x55, 0x08 };      // push 1; movsx edx,[ebp+8]
    const BYTE kEarly6598[9]= { 0x85, 0xC0, 0x75, 0x05, 0xE9, 0xE0, 0x06, 0x00, 0x00 };
    const BYTE kEarly6600[9]= { 0x85, 0xC0, 0x75, 0x05, 0xE9, 0xEC, 0x01, 0x00, 0x00 };
    const BYTE kEarly6602[9]= { 0x85, 0xC0, 0x75, 0x05, 0xE9, 0xC5, 0x10, 0x00, 0x00 };
    const BYTE kEarly6604[9]= { 0x85, 0xC0, 0x75, 0x05, 0xE9, 0xD7, 0x03, 0x00, 0x00 };
    const BYTE kSend2661[5] = { 0xE8, 0x7C, 0x72, 0x02, 0x00 };           // call ConnectSend
    const BYTE kSend2663[5] = { 0xE8, 0x63, 0x6C, 0x02, 0x00 };
    const BYTE kSend2665[5] = { 0xE8, 0x94, 0x59, 0x02, 0x00 };
    const BYTE kSend2667[5] = { 0xE8, 0xA5, 0x4D, 0x02, 0x00 };
    const BYTE kDb2662[5]   = { 0xE8, 0x77, 0x90, 0x10, 0x00 };           // call recvDBCraftRecipeRegist
    const BYTE kDb2664[5]   = { 0xE8, 0x13, 0x96, 0x10, 0x00 };           // call recvDBCraftRecipeDelete
    const BYTE kDb2666[5]   = { 0xE8, 0x9F, 0xA9, 0x10, 0x00 };           // call recvDBCraftEnter
    const BYTE kDb2668[5]   = { 0xE8, 0x9B, 0xB4, 0x10, 0x00 };           // call recvDBCraftScrollLevelUP
    const BYTE kDiscMain[9] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xD4, 0x0A, 0x00, 0x00 };
    const BYTE kDiscPort[9] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xC4, 0x06, 0x00, 0x00 };
    const BYTE kFetch6598[5]= { 0xE8, 0xAA, 0x93, 0xF9, 0xFF };           // call sub_4D61E0
    const BYTE kFetchMat[5] = { 0xE8, 0x65, 0x82, 0xF9, 0xFF };
    const BYTE kFetchCat[5] = { 0xE8, 0xBD, 0x7D, 0xF9, 0xFF };
    const BYTE kFetch6604[5]= { 0xE8, 0xF5, 0x6B, 0xF9, 0xFF };
    const BYTE kBound6598[12] = { 0x81, 0xBD, 0x30, 0xFF, 0xFF, 0xFF, 0x44, 0x02, 0x00, 0x00, 0x7C, 0x51 };
    const BYTE kBound6602[29] = { 0x0F, 0xBF, 0x8D, 0xB8, 0xFA, 0xFF, 0xFF, 0x85, 0xC9, 0x7C, 0x12,
                                  0x0F, 0xBF, 0x95, 0xB8, 0xFA, 0xFF, 0xFF, 0x0F, 0xBF, 0x05, 0x9C,
                                  0x03, 0x7E, 0x00, 0x3B, 0xD0, 0x7C, 0x5B };
    const BYTE kBound6600[5]  = { 0x3D, 0x44, 0x02, 0x00, 0x00 };           // cmp eax, 0x244 → imm 0x240 (576)
    const BYTE kList576[10]   = { 0x81, 0xBD, 0xE4, 0xFA, 0xFF, 0xFF, 0x44, 0x02, 0x00, 0x00 };
    const BYTE kCatStack[6]   = { 0x8B, 0x85, 0x34, 0xF8, 0xFF, 0xFF };     // mov eax,[ebp-0x7CC]
    const BYTE kCatGhost[16]  = { 0x8B, 0x95, 0x50, 0xFB, 0xFF, 0xFF, 0x6B, 0xD2, 0x39,
                                  0x8D, 0xB4, 0x15, 0x6C, 0xFD, 0xFF, 0xFF };
    // `lea esi,[ebp-0x4EC]` (обнулённая запись v6: код/контейнер/слот, count 0) + 10 nop
    const BYTE kCatGhostNew[16] = { 0x8D, 0xB5, 0x14, 0xFB, 0xFF, 0xFF, 0x90, 0x90, 0x90,
                                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    const BYTE kLvl1[7] = { 0x83, 0xC4, 0x0C, 0xC6, 0x45, 0xBC, 0x00 };
    const BYTE kLvl2[7] = { 0x83, 0xC4, 0x14, 0xC6, 0x45, 0xBC, 0x00 };

    // С-7/Д-12: отказы кодом, которого клиент не знает.
    struct CodeSite { DWORD va; int immOff; BYTE was; BYTE now; const char* why; };
    const CodeSite kCodes[] =
    {
        // RecvUser_CraftEnter — `mov byte [ebp-0x230], 0Ah`, 6603 код 10 у клиента — default без сброса
        { 0x0053DFC8, 6, 0x0A, 3, "(4) slot of material is empty -> 3 (5566 Nedostatochno materialov)" },
        { 0x0053E06B, 6, 0x0A, 3, "(5) material is not an item_table code -> 3" },
        { 0x0053E0FC, 6, 0x0A, 3, "(6) material code differs from recipe -> 3" },
        { 0x0053E1A9, 6, 0x0A, 3, "(7) not enough in THIS stack -> 3" },
        { 0x0053E5FC, 6, 0x0A, 3, "(10) catalyst kind is not 1/2 -> 3 (like catalyst gates 8/9)" },
        { 0x0053E772, 6, 0x0A, 0, "(11) craft level below stage 0 -> 0 (5563 + window reset)" },
        // RecvUser_CraftScrollLevelUP — `mov byte [ebp-0x44], 0`, 6605 код 0 клиент молча пропускает
        { 0x0053F620, 3, 0x00, 99, "(1) scroll slot empty -> 99 (5563)" },
        { 0x0053F692, 3, 0x00, 99, "(2) scroll is not item_table code -> 99" },
        { 0x0053F732, 3, 0x00, 99, "(3) item is not a level scroll (type 102) -> 99" },
    };
    const BYTE kCodeE[7] = { 0xC6, 0x85, 0xD0, 0xFD, 0xFF, 0xFF, 0x0A };
    const BYTE kCodeL[4] = { 0xC6, 0x45, 0xBC, 0x00 };
}

PatchResult P35_CraftServerDefects()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }

    const bool doTs     = Config::GetBool(S, L"TsSecretCheck",   true);
    g_stateGate         = Config::GetBool(S, L"StateGate",       true);
    g_lockOn            = Config::GetBool(S, L"InFlightLock",    true);
    g_contGuard         = Config::GetBool(S, L"ContainerGuard",  true);
    const bool doBounds = Config::GetBool(S, L"RecipeBounds",    true);
    const bool doCodes  = Config::GetBool(S, L"ClientCodes",     true);
    const bool doCatStk = Config::GetBool(S, L"CatalystStack",   true);
    const bool doGhost  = Config::GetBool(S, L"CatalystGhost",   true);
    const bool doList   = Config::GetBool(S, L"CraftListMask",   true);
    const bool lvlCode  = Config::GetBool(S, L"LevelScrollCode", true);
    g_lvlSync           = Config::GetBool(S, L"LevelScrollSync", true);    // 27.09: пара к DBManager P37
    g_lvlCode           = lvlCode ? 99 : 0;
    int timeout = Config::GetInt(S, L"LockTimeoutMs", 15000);
    if (timeout < 1000)   { timeout = 1000; }
    if (timeout > 120000) { timeout = 120000; }
    g_lockTimeout = (DWORD)timeout;
    int perMin = Config::GetInt(S, L"LogPerMinute", 30);
    if (perMin < 1)    { perMin = 1; }
    if (perMin > 1000) { perMin = 1000; }
    g_logMax = perMin;

    const bool doEarly = g_stateGate || g_lockOn;
    const bool doLvl   = lvlCode || g_lvlSync;
    if (!doTs && !doEarly && !g_contGuard && !doBounds && !doCodes && !doCatStk && !doGhost && !doList && !doLvl)
    {
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ 39 площадок до первой записи: патч ставится целиком или никак ──
    Site sites[40];
    int  n = 0;
    sites[n++] = { 0x0053CD3D, kTs,        sizeof(kTs)        };
    sites[n++] = { 0x0053D84D, kTs,        sizeof(kTs)        };
    sites[n++] = { 0x0053DC40, kTs,        sizeof(kTs)        };
    sites[n++] = { 0x0053F51D, kTs,        sizeof(kTs)        };
    sites[n++] = { 0x0053CD5B, kEarly6598, sizeof(kEarly6598) };
    sites[n++] = { 0x0053D868, kEarly6600, sizeof(kEarly6600) };
    sites[n++] = { 0x0053DC5E, kEarly6602, sizeof(kEarly6602) };
    sites[n++] = { 0x0053F53B, kEarly6604, sizeof(kEarly6604) };
    sites[n++] = { 0x0053D43F, kSend2661,  sizeof(kSend2661)  };
    sites[n++] = { 0x0053DA58, kSend2663,  sizeof(kSend2663)  };
    sites[n++] = { 0x0053ED27, kSend2665,  sizeof(kSend2665)  };
    sites[n++] = { 0x0053F916, kSend2667,  sizeof(kSend2667)  };
    sites[n++] = { 0x00434424, kDb2662,    sizeof(kDb2662)    };
    sites[n++] = { 0x00434458, kDb2664,    sizeof(kDb2664)    };
    sites[n++] = { 0x0043448C, kDb2666,    sizeof(kDb2666)    };
    sites[n++] = { 0x004344C0, kDb2668,    sizeof(kDb2668)    };
    sites[n++] = { 0x005245D0, kDiscMain,  sizeof(kDiscMain)  };
    sites[n++] = { 0x00525EB0, kDiscPort,  sizeof(kDiscPort)  };
    sites[n++] = { 0x0053CE31, kFetch6598, sizeof(kFetch6598) };
    sites[n++] = { 0x0053DF76, kFetchMat,  sizeof(kFetchMat)  };
    sites[n++] = { 0x0053E41E, kFetchCat,  sizeof(kFetchCat)  };
    sites[n++] = { 0x0053F5E6, kFetch6604, sizeof(kFetch6604) };
    for (int i = 0; i < ARRAYSIZE(kCodes); ++i)
    {
        if (kCodes[i].immOff == 6) { sites[n++] = { kCodes[i].va, kCodeE, sizeof(kCodeE) }; }
        else                       { sites[n++] = { kCodes[i].va, kCodeL, sizeof(kCodeL) }; }
    }
    sites[n++] = { 0x0053CF56, kBound6598, sizeof(kBound6598) };
    sites[n++] = { 0x0053DD46, kBound6602, sizeof(kBound6602) };
    sites[n++] = { 0x0053D8CA, kBound6600, sizeof(kBound6600) };
    sites[n++] = { 0x0053C89F, kList576,   sizeof(kList576)   };
    sites[n++] = { 0x0053E646, kCatStack,  sizeof(kCatStack)  };
    sites[n++] = { 0x0053F40F, kCatGhost,  sizeof(kCatGhost)  };
    sites[n++] = { 0x0053FA97, kLvl1,      sizeof(kLvl1)      };
    sites[n++] = { 0x0053FAFF, kLvl2,      sizeof(kLvl2)      };
    if (!VerifyAllSites(L"P35", sites, n)) { return PatchResult::Mismatch; }

    InitializeCriticalSection(&g_logCs);
    g_logCsInit = true;

    bool ok = true;

    // С-5
    if (doTs)
    {
        ok &= Hook::WriteJmp(0x0053CD3D, (const void*)&Ts6598, sizeof(kTs));
        ok &= Hook::WriteJmp(0x0053D84D, (const void*)&Ts6600, sizeof(kTs));
        ok &= Hook::WriteJmp(0x0053DC40, (const void*)&Ts6602, sizeof(kTs));
        ok &= Hook::WriteJmp(0x0053F51D, (const void*)&Ts6604, sizeof(kTs));
        Log::Line(L"    P35/С-5: результат анти-повтора sub_524390 соблюдается в 6598/6600/6602/6604 "
                  L"(0 ⇒ эпилог, как у всех прочих обработчиков)");
    }

    // С-3 (замок): до ранней проверки — чтобы она уже видела таблицу
    if (g_lockOn)
    {
        InitializeCriticalSection(&g_lockCs);
        g_lockCsInit = true;
        ok &= Hook::WriteCall(0x0053D43F, (const void*)&StubSend, 5);
        ok &= Hook::WriteCall(0x0053DA58, (const void*)&StubSend, 5);
        ok &= Hook::WriteCall(0x0053ED27, (const void*)&StubSend, 5);
        ok &= Hook::WriteCall(0x0053F916, (const void*)&StubSend, 5);
        ok &= Hook::WriteCall(0x00434424, (const void*)&P35_RecvReg,   5);
        ok &= Hook::WriteCall(0x00434458, (const void*)&P35_RecvDel,   5);
        ok &= Hook::WriteCall(0x0043448C, (const void*)&P35_RecvEnter, 5);
        ok &= Hook::WriteCall(0x004344C0, (const void*)&P35_RecvLvl,   5);
        ok &= Hook::WriteJmp (0x005245D0, (const void*)&DiscMain,   sizeof(kDiscMain));
        ok &= Hook::WriteJmp (0x00525EB0, (const void*)&DiscPortal, sizeof(kDiscPort));
        Log::Line(L"    P35/С-3: замок «одна операция ремесла в полёте» (тайм-аут %u мс): постановка на 4 "
                  L"отправках 2661/2663/2665/2667, снятие — приём 2662/2664/2666/2668, разрыв, портал", g_lockTimeout);
    }

    // С-13 + ранняя проверка замка
    if (doEarly)
    {
        ok &= Hook::WriteJmp(0x0053CD5B, (const void*)&Early6598, sizeof(kEarly6598));
        ok &= Hook::WriteJmp(0x0053D868, (const void*)&Early6600, sizeof(kEarly6600));
        ok &= Hook::WriteJmp(0x0053DC5E, (const void*)&Early6602, sizeof(kEarly6602));
        ok &= Hook::WriteJmp(0x0053F53B, (const void*)&Early6604, sizeof(kEarly6604));
        Log::Line(L"    P35/С-13: гейт состояния (мёртв/обмен/аукцион/лавка/рыбалка): %s; ранний отказ дублю: %s — "
                  L"4 площадки сразу за подписью", g_stateGate ? L"вкл" : L"выкл", g_lockOn ? L"вкл" : L"выкл");
    }

    // С-1/С-2/С-14
    if (g_contGuard)
    {
        ok &= Hook::WriteCall(0x0053CE31, (const void*)&P35_Fetch, 5);
        ok &= Hook::WriteCall(0x0053DF76, (const void*)&P35_Fetch, 5);
        ok &= Hook::WriteCall(0x0053E41E, (const void*)&P35_Fetch, 5);
        ok &= Hook::WriteCall(0x0053F5E6, (const void*)&P35_Fetch, 5);
        Log::Line(L"    P35/С-1: предметы ремесла только из контейнеров сумки 1/2 (4 вызова sub_4D61E0)");
    }

    // Д-Д2/Д-8/С-9
    if (doBounds)
    {
        ok &= Hook::WriteJmp(0x0053CF56, (const void*)&Bound6598, sizeof(kBound6598));
        ok &= Hook::WriteByteChecked(0x0053D8CA + 1, 0x44, 0x40);   // 6600: 580 → 576 (маска), таблиц не читает
        ok &= Hook::WriteJmp(0x0053DD46, (const void*)&Bound6602, 7);
        Log::Line(L"    P35/Д-Д2: граница изучения 6598 = min(576, строк CraftRecipeInfo); изготовления 6602 — "
                  L"строк Info и iMakeIndex в [0, строк Make); забывания 6600 — 576 (маска)");
    }

    // С-7/Д-12
    if (doCodes)
    {
        int c = 0;
        for (int i = 0; i < ARRAYSIZE(kCodes); ++i)
        {
            if (Hook::WriteByteChecked(kCodes[i].va + kCodes[i].immOff, kCodes[i].was, kCodes[i].now)) { ++c; }
            else { ok = false; }
        }
        Log::Line(L"    P35/С-7: неизвестных клиенту кодов заменено %d из %d (6603: 10→3 ×5, 10→0 ×1; 6605: 0→99 ×3)",
                  c, (int)ARRAYSIZE(kCodes));
    }

    // С-4
    if (doCatStk)
    {
        ok &= Hook::WriteJmp(0x0053E646, (const void*)&CatStack, sizeof(kCatStack));
        Log::Line(L"    P35/С-4: катализатор стопкой >1 расходует сам себя (count−1, вес Function_Table +4)");
    }

    // С-21
    if (doGhost)
    {
        if (Hook::WriteBytes(0x0053F40F, kCatGhostNew, sizeof(kCatGhostNew)))
        {
            Log::Line(L"    P35/С-21: израсходованный катализатор уходит в 6603 обнулённой записью (count 0)");
        }
        else { ok = false; }
    }

    // С-19
    if (doList)
    {
        ok &= Hook::WriteByteChecked(0x0053C89F + 6, 0x44, 0x40);
        Log::Line(L"    P35/С-19: recvDBCraftList разбирает 576 бит маски (9 qword пакета), а не 580");
    }

    // С-20
    if (doLvl)
    {
        ok &= Hook::WriteJmp(0x0053FA97, (const void*)&LvlMiss1, sizeof(kLvl1));
        ok &= Hook::WriteJmp(0x0053FAFF, (const void*)&LvlMiss2, sizeof(kLvl2));
        Log::Line(L"    P35/С-20: свиток уровня не найден после записи БД — код %d, уровень в память: %s",
                  (int)g_lvlCode, g_lvlSync ? L"да" : L"нет");
    }

    return ok ? PatchResult::Applied : PatchResult::Failed;
}
