// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P100 — [ИСПРАВЛЕНИЕ] ЗАРЯДЫ СПЕЦПРЕДМЕТОВ СКЛАДЫВАЮТСЯ ПРИ ПОЛУЧЕНИИ (решение владельца 01.11.2026, AsdaPatch v57).
//  Проект: Reports/item_dedup/charges/P100_PROJECT.md; разбор путей с адресами: CHARGES_RE.md §2.1, paths_A.md, paths_B.md.
//
//  ── ДЕФЕКТ / РЕШЕНИЕ ВЛАДЕЛЬЦА ──
//  [ОРИГИНАЛ] Спецпредмет F (код 1…637, Function_Table dword_5F5E70, запись 48 б) при любом получении в сумку (Plate 1) занимает
//  НОВУЮ ячейку (sub_5340B0 GS:117743–117756 и 20 собственных выборов ячейки путей). Сумка забивается копиями «Свиток (30)».
//  [ИСПРАВЛЕНИЕ] Входящий F с кодом c, ключом k = key[c] > 0 и добавкой n складывается в ПЕРВУЮ по Posx ячейку сумки с тем же
//  ключом, если старое + в_полёте + n ≤ Cap (30000); иначе следующая ячейка ключа; иначе новая ячейка, как сток. Код ячейки НЕ
//  меняется (UPSkillItemSpend сверяет Code), вес не меняется (у F вес — на штуку). Ключ = группа v2 + привязка FT+43 (файл
//  ConfigSet\charge_groups.txt, генератор tools/gen_charge_groups.py; режим 1, срочные, 401/363 — ключ 0, не трогаются).
//  [ИСПРАВЛЕНИЕ 300] FT ток.9 хранится стоком в u8 (FT+13): у 505/506/515 вместо 300 выдаётся 44. Пять чтений FT+13 на путях
//  выдачи (0x4F4EA2 гача, 0x515DC6 магазин осады, 0x5345EB sub_5340B0, 0x5525F9 GM, 0x55BD4B sub_55B7F0) берут заряды из
//  charge_groups (i32). Чтения 0x5127ED (CharChargeShopBuy → GP7, не сумка) и 0x5136DA (подарок A8 — забирает P101) не трогаются.
//
//  ── КОНТРАКТ С SQL (процедуры Joy1 — отдельная волна; формат DB-пакетов не меняется) ──
//  При слиянии GS шлёт в DB-пакете пути Posx = Posx стопки, Amount = ДОБАВКА (не итог); несколько копий одного запроса —
//  Posx может повторяться. Процедура на занятом Posx того же ключа: UPDATE Amount = Amount + @Amount (UPDLOCK, HOLDLOCK), на
//  свободном — INSERT как сток. Переносы (обмен, лавка, аукцион, склад): Posx получателя = стопка, процедура прибавляет и удаляет
//  строку у отдающего. Крафт / лимит-задания / рулетка (флаг 1/2 + абсолютный Amount) — GS сам ставит флаг 1 и итог (точка 1, ABS).
//
//  ── МЕХАНИЗМЫ ──
//  • ВЫБОР ЯЧЕЙКИ: `call sub_4D6740` площадки перенацелен (E8 rel32, 5 б) на преобразователь сайта: стопка ключа (FindChargeStack)
//    или новая ячейка стоковым роутером с пропуском ячеек, зарезервированных другими ключами «в полёте». Сумка читается ТОЛЬКО через
//    экспорт P96_BagRec (g_bag P96 или CUser+0x4BC без P96). Накопитель «ждёт ответа БД» — g_pend на персонажа: добавки в полёте
//    учитываются в Cap, новая ячейка первой копии ключа резервируется — следующие копии того же ключа сливаются в неё.
//  • ЗАПИСЬ В ПАМЯТЬ (ответ): `call sub_4D63F0` площадки перенацелен: запись F в занятую ячейку того же ключа превращается в
//    запись ячейки с Amount = старое + добавка (код и прочие поля ячейки); пакет клиенту: в КАЖДОЙ записи пакета этой ячейки — итог
//    (клиент кладёт перезаписью по rec+5). Вес: прибавку веса слитой копии обработчик стока делает сам — P100 её снимает
//    (CUser+0x1A2 / переменная кадра) там, где обработчик прибавляет; где вес «устанавливается» из запроса — правка на запросе.
//  • ПРЕДПРОВЕРКИ: sub_4D7CD0 (квест) / sub_4D6A70(1) (обмен, лавка, аукцион) — к числу пустых ячеек прибавляется число входящих F,
//    которые сольются (полная сумка со стопкой — не отказ).
//  • ОТКАТ АУКЦИОНА (ошибка БД 2205/2207): вместо стирания ячейки — вычитание добавки (журнал добавок по Uidx лота).
//  • A6 коробки — внутри P95 (P95_OnPackage → P100_BoxPlace); A1′ премиум-гача P16 — P100_PremiumSlot; P62 — P100_IsBoxMergeSlot.
//
//  ── ПУТИ (бит Sites) ──
//   0 A1 премиум-почта 11006/2604 (+P16)   1 A2 гача 5468/2229        2 A3 сундук 6540/2521     3 A4 GM 6042/2231
//   4 A5 магазин осады 6162/2469          5 A6 коробки 6096 (P95)     6 A7 события 6098/2270     7 A8 подарок — ЗАРЕЗЕРВИРОВАН (P101)
//   8 B1 квест 7104/7105 → 2076            9 B2/B7/B8 лимит/крафт/рулетка (ABS)                 10 B6 рыбалка 6171/6182
//  11 B9 разборка 6502 (только тот же код) 12 B10 война роз 2462        13 B3 обмен shell (перенос) 14 B4 личная лавка (перенос)
//  15 B5 аукцион покупка/снятие (перенос) 16 B11 склад → сумка (перенос, только тот же код)
//  Биты 13–16 работают только при TradeMerge=1. Ответная сторона (преобразование записи) работает всегда, пока P100 стоит.
//
//  Ключи [P100_ChargeStack]: Enabled, Cap, Sites, TradeMerge, FixCharges, PendingTtlSec, JournalIntervalSec, LogChannel,
//  EchoAllCodes (05.11.2026, v61: ответ 2604 премиум-почты берёт ячейку эха БД для ЛЮБОГО кода сумки; 0 — только коды с ключом).
//  Журнал ac.other 153–157 (153 слияние, 154 потолок → следующая/новая ячейка, 155 откат аукциона вычитанием, 156 расхождение
//  памяти и БД / исключение, 157 P100 выключен сверкой FT / ошибкой таблицы). Не чаще JournalIntervalSec на (слот, вид).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

// P96_BagSize / P96_BagRec (p96_inventory_x2.cpp) объявлены в Patches.h.

namespace
{
    const wchar_t* kSec = L"P100_ChargeStack";   // секция patches.ini

    // ── виды журнала ac.other (свободны по ac-journal-p53.md §9; P98 занял 150–152) ──
    constexpr BYTE kKindMerge    = 153;   // слияние заряда в стопку
    constexpr BYTE kKindCap      = 154;   // потолок Cap — следующая ячейка ключа / новая
    constexpr BYTE kKindRollback = 155;   // откат аукциона: вычитание добавки вместо стирания ячейки
    constexpr BYTE kKindMismatch = 156;   // расхождение памяти и БД / исключение — решение стока
    constexpr BYTE kKindOff      = 157;   // P100 выключен (FT ≠ ft_md5 / ошибка таблицы)
    constexpr int  kKindBase = 153, kKindCount = 5;   // диапазон видов для ограничителя

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kOffUserIndex = 0x174;       // учётка (sub_5324F0)
    constexpr int   kOffName      = 0x178;       // имя персонажа cp1251
    constexpr int   kOffSlot      = 0x18C;       // слот персонажа
    constexpr int   kOffWeight    = 0x1A2;       // текущий вес u16 (sub_43F880 +418)
    constexpr int   kMaxUsers     = 0x226;       // 550 слотов (sub_5328F0)
    constexpr DWORD kFuncTablePtr = 0x005F5E70;  // dword_5F5E70 → Function_Table, запись 48 б, индекс (код − 1)
    constexpr DWORD kFuncMaxPtr   = 0x005F5EA4;  // dword_5F5EA4 → число кодов Function_Table
    constexpr int   kFuncRec = 48;               // шаг записи FT
    constexpr int   kMaxCode = 637;              // кодов F в charge_groups
    constexpr int   kRec = 57;                   // запись предмета
    constexpr int   kRecPlate = 4, kRecPosx = 5, kRecAmount = 9, kRecWeight = 14;   // поля записи 57 б

    // ── стоковые функции (thiscall через __fastcall: edx — пустышка) ──────────
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);                         // sub_5324A0 ret 4
    typedef int   (__fastcall *PFN_Router)(void* self, void* edx, int userNum, int plate, int after);    // sub_4D6740 ret 0Ch
    typedef int   (__fastcall *PFN_Write)(void* self, void* edx, int userNum, BYTE* rec, BYTE* src);     // sub_4D63F0 ret 0Ch
    typedef int   (__fastcall *PFN_Erase)(void* self, void* edx, int userNum, int plate, int posx);     // sub_4D6540 ret 0Ch
    typedef int   (__fastcall *PFN_Room)(void* self, void* edx, int userNum, int plate, int weight);    // sub_4D7CD0 ret 0Ch
    typedef int   (__fastcall *PFN_Count)(void* self, void* edx, int userNum, int plate);              // sub_4D6A70 ret 8
    typedef char  (__fastcall *PFN_Busy)(void* self, void* edx, int userNum, int opcode);              // sub_52BFF0 ret 8 («занят»)
    typedef int   (__fastcall *PFN_GetCell)(void* self, void* edx, int userNum, int plate, int slot, BYTE* out, BYTE* src);   // sub_4D61E0 ret 14h
    typedef int   (__fastcall *PFN_DbSend)(void* self, void* edx, int op, int len, int conn, void* body, int userNum);   // sub_5646C0 ret 14h
    typedef BOOL  (__cdecl    *PFN_IsF)(int code);                                                         // sub_532B10
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                               // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)0x005324A0;
    PFN_Router  const pRouter  = (PFN_Router)0x004D6740;
    PFN_Write   const pWrite   = (PFN_Write)0x004D63F0;
    PFN_Erase   const pErase   = (PFN_Erase)0x004D6540;
    PFN_Room    const pRoom    = (PFN_Room)0x004D7CD0;
    PFN_Count   const pCount   = (PFN_Count)0x004D6A70;
    PFN_Busy    const pBusy    = (PFN_Busy)0x0052BFF0;
    PFN_GetCell const pGetCell = (PFN_GetCell)0x004D61E0;
    PFN_DbSend  const pDbSend  = (PFN_DbSend)0x005646C0;
    PFN_IsF     const pIsF     = (PFN_IsF)0x00532B10;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog)Srv::kLog;

    // ── настройки ────────────────────────────────────────────────────────────
    bool  g_enabled    = false;    // площадки стоят, таблица сошлась с FT
    int   g_cap        = 30000;    // потолок зарядов в ячейке (CRT_UPCheckItem SMALLINT)
    DWORD g_sites      = 0xFFFFFFFFu;   // маска путей запроса (бит 7 — подарок, зарезервирован за P101)
    bool  g_tradeMerge = true;     // переносы (биты 13–16)
    bool  g_fixCharges = true;     // [ИСПРАВЛЕНИЕ 300]: заряды выдачи — i32 из charge_groups
    int   g_ttlSec     = 60;       // жизнь записи накопителя без ответа БД, с
    int   g_journalIntervalSec = 10;   // ограничитель журнала, с
    int   g_logChannel = 1;        // 1 = Log_Item
    bool  g_echoAll    = true;     // ★ 05.11: ответ 2604 берёт ячейку эха БД и для кодов без ключа (ключ EchoAllCodes; 0 — прежнее)

    P100_Stats g_stats = {};       // счётчики (экспорт P100_GetStats)

    // ── таблица ключей (charge_groups.txt) ────────────────────────────────────
    struct ChargeRow { int key; int charges; int mode; int days; int bind; };   // строка на код F
    ChargeRow g_row[kMaxCode + 1] = {};   // индекс = код (0 не используется)
    bool g_tableOk = false;               // файл прочитан и ft_md5 совпал
    char g_ftMd5[40] = {};                // md5 живой FT (для лога)

    // ── накопитель «ждёт ответа БД» ───────────────────────────────────────────
    constexpr int kPendMax = 32;   // записей на персонажа
    constexpr int kKeyMove = -1;   // ключ записи «перемещение 5000 в полёте» (ячейку не сливать)
    constexpr int kKeyAbs  = -2;   // ключ записи «абсолютный Amount (крафт/лимит/рулетка) в полёте» (ячейку не трогать другим)
    constexpr DWORD kShortTtlMs = 5000;   // жизнь записей, которые не снимает запись в память (ABS/перемещение), и записей путей
                                          // с отказом стока ПОСЛЕ выбора (A2 вес, A5 вес): дольше они ячейку не держат
    // Добавка в полёте: ячейка, резерв новой (isNew), ключ, код, добавка, Owner (+50 входящей записи), время, жизнь, пакет.
    struct Pend { short slot; short isNew; int key; int code; int add; int owner; DWORD tick; DWORD ttl; DWORD batch; };
    struct UserPend { int userIndex; int n; Pend e[kPendMax]; };                                       // накопитель персонажа
    UserPend g_pend[kMaxUsers] = {};

    // ── журнал добавок аукциона (для отката вычитанием) ──────────────────────
    constexpr int kLedgerMax = 16;   // записей на персонажа (лотов в одной сделке ≤ 10)
    struct Ledger { int userIndex; int posx; int uidx; int code; int add; DWORD tick; };   // слитый лот
    Ledger g_ledger[kMaxUsers][kLedgerMax] = {};

    // ── цепочка afterSlot (стоковые вызывающие пишут результат роутера в «после») ──
    struct Chain { DWORD tid; int user; int site; int lastMerge; int chainAfter; DWORD tick; DWORD batch; };   // состояние на поток
    Chain g_chain[16] = {};

    // ── ящики P95: ячейки, куда в последнем 6096 персонажа легли ≥ 2 позиции (для P62) ──
    DWORD g_boxShared[kMaxUsers][2] = {};   // битовая маска ячеек 0…63
    DWORD g_batchSeq = 0;                   // номер пакета размещения (P95 / P101)

    CRITICAL_SECTION g_lock; bool g_lockReady = false;   // замок накопителя/цепочек/журнала

    // Ограничитель журнала: одна строка на (слот, вид) за JournalIntervalSec.
    struct Sess { int userIndex; DWORD last[kKindCount]; int sup[kKindCount]; };
    Sess g_sess[kMaxUsers] = {};

    // Замок (рекурсивный CRITICAL_SECTION).
    struct Guard { Guard() { if (g_lockReady) { EnterCriticalSection(&g_lock); } } ~Guard() { if (g_lockReady) { LeaveCriticalSection(&g_lock); } } };

    int UserIndexOf(const BYTE* user);   // учётка персонажа (ниже)

    // Пропуск по ограничителю; *supOut — сколько строк этого вида подавлено с прошлой.
    bool Allow(int userNum, const BYTE* user, BYTE kind, int* supOut)
    {
        *supOut = 0;
        const int k = kind - kKindBase;
        if (userNum < 0 || userNum >= kMaxUsers || k < 0 || k >= kKindCount) { return true; }
        const int ui = UserIndexOf(user);
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool allow = true;
        Guard g;
        Sess& s = g_sess[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        if (g_journalIntervalSec > 0 && s.last[k] && now - s.last[k] < (DWORD)g_journalIntervalSec * 1000) { ++s.sup[k]; allow = false; }
        else { s.last[k] = now; *supOut = s.sup[k]; s.sup[k] = 0; }
        return allow;
    }

    // Строка стокового лога + ac.other (под ограничителем). v0 → item_code, v1 → value1, v2 → value2.
    void Report(BYTE kind, int opcode, const BYTE* user, int userNum, int v0, int v1, int v2, const char* detail, const char* logText)
    {
        int sup = 0;
        if (!Allow(userNum, user, kind, &sup)) { InterlockedIncrement(&g_stats.suppressed); return; }
        int ui = -1;
        const char* name = "?";
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); name = (const char*)(user + kOffName); } }
        __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; name = "?"; }
        __try
        {
            pSrvLog(g_logChannel, "P100 ChargeStack: %d UserNum %d UserIndex %d %s: %s%s", opcode, userNum, ui, name, logText,
                    sup ? " (+suppressed)" : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = (userNum >= 0 && userNum < kMaxUsers) ? P47_PeerIpv4(userNum) : 0;
        e.suppressed = sup;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIndex);
                e.charSlot  = user[kOffSlot];
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    // ── доступ к кадру ───────────────────────────────────────────────────────
    int   I32(const BYTE* ebp, int off) { return *(const int*)(ebp + off); }          // i32 кадра
    int   I16(const BYTE* ebp, int off) { return *(const short*)(ebp + off); }        // i16 кадра со знаком
    BYTE* Ptr(const BYTE* ebp, int off) { return *(BYTE* const*)(ebp + off); }        // указатель кадра

    // Ключ кода (0 — не складывать / не F / таблица не готова).
    int KeyOf(int code) { return (g_tableOk && code >= 1 && code <= kMaxCode) ? g_row[code].key : 0; }
    // Заряды выдачи кода (ток.9 целиком; −1 — нет в таблице).
    int ChargesOf(int code) { return (g_tableOk && code >= 1 && code <= kMaxCode) ? g_row[code].charges : -1; }
    // Вес одного F (FT+4).
    int FtWeight(int code)
    {
        __try { return (code >= 1 && code <= *(const int*)kFuncMaxPtr) ? *(const short*)(*(const BYTE**)kFuncTablePtr + kFuncRec * (code - 1) + 4) : 0; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    // Бит пути включён (переносы — ещё и TradeMerge).
    bool SiteOn(int bit) { if (bit < 0 || bit > 31 || bit == 7) { return false; } if (bit >= 13 && bit <= 16 && !g_tradeMerge) { return false; } return (g_sites >> bit) & 1; }
    // Учётка персонажа (сброс накопителя при смене персонажа в слоте).
    int UserIndexOf(const BYTE* user) { __try { return user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; } }
    // CUser слота.
    BYTE* UserOf(void* mgr, int userNum)
    {
        if (!mgr || userNum < 0 || userNum >= kMaxUsers) { return nullptr; }
        __try { return pGetUser(mgr, nullptr, userNum); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }
    // Вес персонажа −= w (кламп 0; как sub_43F880 a4 = a5 = 0).
    void SubWeight(BYTE* user, int w)
    {
        if (!user || w <= 0) { return; }
        WORD* p = (WORD*)(user + kOffWeight);
        *p = (WORD)((int)*p > w ? (int)*p - w : 0);
        InterlockedIncrement(&g_stats.weightFixed);
    }

    // ── накопитель ─────────────────────────────────────────────────────────────
    // Накопитель персонажа (сброс при смене учётки и снятие просроченных).
    UserPend* PendOf(int userNum, const BYTE* user)
    {
        if (userNum < 0 || userNum >= kMaxUsers) { return nullptr; }
        UserPend* up = &g_pend[userNum];
        const int ui = UserIndexOf(user);
        if (up->userIndex != ui) { memset(up, 0, sizeof(*up)); up->userIndex = ui; }
        const DWORD now = GetTickCount();
        int w = 0;
        for (int i = 0; i < up->n; ++i)
        {
            if (now - up->e[i].tick > up->e[i].ttl) { InterlockedIncrement(&g_stats.pendExpired); continue; }
            up->e[w++] = up->e[i];
        }
        up->n = w;
        return up;
    }
    // Сумма добавок в полёте по ячейке (только слияния, ключ > 0).
    int PendSum(const UserPend* up, int slot) { int s = 0; for (int i = 0; i < up->n; ++i) { if (up->e[i].slot == slot && up->e[i].key > 0) { s += up->e[i].add; } } return s; }
    // Записей накопителя по ячейке (любых).
    int PendCount(const UserPend* up, int slot) { int n = 0; for (int i = 0; i < up->n; ++i) { if (up->e[i].slot == slot) { ++n; } } return n; }
    // Ячейка заблокирована: перемещение 5000 или абсолютный Amount в полёте.
    bool Blocked(const UserPend* up, int slot) { for (int i = 0; i < up->n; ++i) { if (up->e[i].slot == slot && up->e[i].key < 0) { return true; } } return false; }
    // Ключ резерва пустой ячейки (0 — резерва нет, −1 — резервы разных ключей / Owner / блокировка); код и Owner резерва.
    int PendNewKey(const UserPend* up, int slot, int* codeOut, int* ownerOut)
    {
        int k = 0, o = 0;
        for (int i = 0; i < up->n; ++i)
        {
            if (up->e[i].slot != slot) { continue; }
            if (up->e[i].key < 0) { return -1; }
            if (k == 0) { k = up->e[i].key; o = up->e[i].owner; if (codeOut) { *codeOut = up->e[i].code; } }
            else if (k != up->e[i].key || o != up->e[i].owner) { return -1; }
        }
        if (ownerOut) { *ownerOut = o; }
        return k;
    }
    // Ячейка зарезервирована в полёте не этим ключом / Owner (key ≤ 0 — любым резервом).
    bool ReservedOther(const UserPend* up, int slot, int key, int owner)
    {
        for (int i = 0; i < up->n; ++i)
        {
            const Pend& e = up->e[i];
            if (e.slot == slot && (key <= 0 || e.key != key || e.owner != owner)) { return true; }
        }
        return false;
    }
    // Новая запись накопителя (ttl 0 — PendingTtlSec).
    void PendAdd(UserPend* up, int slot, int key, int code, int add, int owner, bool isNew, DWORD batch, DWORD ttl = 0)
    {
        if (!up) { return; }
        if (up->n >= kPendMax) { memmove(&up->e[0], &up->e[1], sizeof(Pend) * (kPendMax - 1)); up->n = kPendMax - 1; InterlockedIncrement(&g_stats.pendDropped); }
        Pend& p = up->e[up->n++];
        p.slot = (short)slot; p.isNew = isNew ? 1 : 0; p.key = key; p.code = code; p.add = add; p.owner = owner; p.tick = GetTickCount();
        p.ttl = ttl ? ttl : (DWORD)g_ttlSec * 1000; p.batch = batch;
        InterlockedIncrement(&g_stats.pendAdded);
    }
    // Снятие одной записи-добавки по ячейке (предпочтительно с той же добавкой). Возврат: 1 — снято слияние (isNew = 0),
    //   2 — снят резерв новой ячейки, 0 — записи не было.
    int PendRelease(UserPend* up, int slot, int add)
    {
        if (!up) { return 0; }
        int pick = -1;
        for (int i = 0; i < up->n; ++i)
        {
            if (up->e[i].slot != slot || up->e[i].key <= 0) { continue; }
            if (up->e[i].add == add) { pick = i; break; }
            if (pick < 0) { pick = i; }
        }
        if (pick < 0) { return 0; }
        const int r = up->e[pick].isNew ? 2 : 1;
        memmove(&up->e[pick], &up->e[pick + 1], sizeof(Pend) * (up->n - pick - 1));
        --up->n;
        InterlockedIncrement(&g_stats.pendReleased);
        return r;
    }
    // Снятие записей пакета (сток отказал выдаче после выбора ячейки).
    void PendCancel(UserPend* up, DWORD batch)
    {
        if (!up || !batch) { return; }
        int w = 0;
        for (int i = 0; i < up->n; ++i) { if (up->e[i].batch != batch) { up->e[w++] = up->e[i]; } else { InterlockedIncrement(&g_stats.pendCancelled); } }
        up->n = w;
    }

    // Исключённые ячейки (отдаются получателем в этой же сделке обмена).
    struct Excl { int n; int slot[8]; bool Has(int s) const { for (int i = 0; i < n; ++i) { if (slot[i] == s) { return true; } } return false; } };

    // Режимы выбора стопки.
    enum : int { M_ADD = 0, M_ABS = 1, M_SAME = 2 };

    // ★ FindChargeStack: первая по Posx ячейка ключа k, в которую влезает n (старое + в полёте + n ≤ Cap).
    //   M_ABS — ячейки с добавками в полёте пропускаются (абсолютный Amount сверяется со старым в процедуре);
    //   M_SAME — только тот же код (склад 5011 копирует код записи склада; разборка — процедура сливает по коду).
    //   Возврат: слот (≥ 0) и *isNew (резерв пустой ячейки той же партии ключа); −1 — стопки нет; *overflow — была, но полна.
    //   owner — Owner (+50), который получит входящая запись: слияние только в ячейку с тем же Owner (привязка не «снимается»).
    int FindStack(BYTE* user, UserPend* up, int code, int key, int add, int owner, int mode, const Excl* ex, bool* isNew, bool* overflow)
    {
        *isNew = false; *overflow = false;
        const int size = P96_BagSize();
        for (int s = 0; s < size; ++s)
        {
            if (ex && ex->Has(s)) { continue; }
            const BYTE* r = P96_BagRec(user, s);
            if (!r || Blocked(up, s)) { continue; }
            const int c = *(const int*)r;
            const int pend = PendSum(up, s);
            if (c > 0)
            {
                if (c > kMaxCode || KeyOf(c) != key || r[kRecPlate] != 1 || (int)r[50] != owner) { continue; }
                if (mode == M_SAME && c != code) { continue; }
                if (mode == M_ABS && PendCount(up, s) != 0) { continue; }
                const long long total = (long long)*(const int*)(r + kRecAmount) + pend + add;
                if (total <= g_cap) { return s; }
                *overflow = true;
            }
            else if (mode != M_ABS)
            {
                int rc = 0, ro = 0;
                if (PendNewKey(up, s, &rc, &ro) != key || ro != owner) { continue; }
                if (mode == M_SAME && rc != code) { continue; }
                if ((long long)pend + add <= g_cap) { *isNew = true; return s; }
                *overflow = true;
            }
        }
        return -1;
    }

    // Новая ячейка: стоковый роутер с пропуском исключённых ячеек и (по возможности) зарезервированных в полёте другим
    //   ключом/Owner. Резерв — предпочтение, а не запрет: если свободны только зарезервированные, берётся первая из них, как
    //   сток (резерв отказанного запроса не может дать ложное «сумка полна»).
    int StockNew(void* mgr, int userNum, UserPend* up, int plate, int after, int key, int owner, const Excl* ex)
    {
        int a = after, soft = -1;
        for (int t = 0; t < 70; ++t)
        {
            const int s = (short)pRouter(mgr, nullptr, userNum, plate, a);
            if (s < 0) { break; }
            const bool excl = ex && ex->Has(s);
            if (plate != 1 || !up || (!excl && !ReservedOther(up, s, key, owner))) { return s; }
            if (!excl && soft < 0) { soft = s; }
            InterlockedIncrement(&g_stats.skippedReserved);
            a = s;
        }
        if (soft >= 0) { InterlockedIncrement(&g_stats.softReserved); }
        return soft;
    }

    // Цепочка afterSlot потока: вызывающий записал наш слот стопки в «после» — для стокового роутера подставляется прежнее звено.
    Chain* ChainOf(int user, int site)
    {
        const DWORD tid = GetCurrentThreadId();
        Chain* free = nullptr;
        const DWORD now = GetTickCount();
        for (Chain& c : g_chain)
        {
            if (c.tid == tid)
            {
                // другой персонаж / путь или пауза > 50 мс — это другой вызов обработчика: цепочка с нуля
                if (c.user != user || c.site != site || now - c.tick > 50)
                {
                    c.user = user; c.site = site; c.lastMerge = -2; c.chainAfter = -1;
                    c.batch = (DWORD)InterlockedIncrement((LONG*)&g_batchSeq);   // номер вызова обработчика (снятие при отказе)
                }
                c.tick = now;
                return &c;
            }
            if (!c.tid && !free) { free = &c; }
        }
        if (!free) { free = &g_chain[now % 16]; }
        free->tid = tid; free->user = user; free->site = site; free->lastMerge = -2; free->chainAfter = -1; free->tick = now;
        free->batch = (DWORD)InterlockedIncrement((LONG*)&g_batchSeq);
        return free;
    }

    // Строка «слито» в журнал (вид 153) + счётчик.
    void NoteMerge(int opcode, const BYTE* user, int userNum, int code, int slot, int add, int site)
    {
        InterlockedIncrement(&g_stats.merged);
        char d[64], t[160];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P100 %d code %d +%d -> slot %d (site %d)", opcode, code, add, slot, site);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d: +%d charges merged into bag cell %d (path bit %d)", code, add, slot, site);
        Report(kKindMerge, opcode, user, userNum, code, slot, add, d, t);
    }
    // Строка «потолок» (вид 154).
    void NoteCap(int opcode, const BYTE* user, int userNum, int code, int add, int slot)
    {
        InterlockedIncrement(&g_stats.capHit);
        char d[64], t[160];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P100 %d code %d +%d cap %d -> %d", opcode, code, add, g_cap, slot);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d: +%d would exceed cap %d in every cell of its key -> cell %d", code, add, g_cap, slot);
        Report(kKindCap, opcode, user, userNum, code, add, slot, d, t);
    }
    // Строка «расхождение / исключение» (вид 156).
    void NoteMismatch(int opcode, const BYTE* user, int userNum, int v0, int v1, int v2, const char* what)
    {
        InterlockedIncrement(&g_stats.mismatch);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P100 %d %s", opcode, what);
        Report(kKindMismatch, opcode, user, userNum, v0, v1, v2, d, what);
    }

    // ★ Выбор ячейки входящего F (общий для всех путей запроса). Возврат: слот (стопка/новая) или < 0 (места нет, как сток).
    //   site — бит пути; opcode — для журнала; plate/after — аргументы стокового роутера; ex — исключённые ячейки; owner — Owner
    //   входящей записи; ttl — жизнь записи накопителя (0 — PendingTtlSec). Отказ «нет места» (< 0) снимает все записи
    //   накопителя этого вызова обработчика (цепочка потока / batch) — сток отказывает всей выдаче.
    int PickCell(void* mgr, int userNum, int plate, int after, int code, int add, int site, int opcode, int mode, const Excl* ex,
                 bool* mergedOut, DWORD batch, int owner, DWORD ttl = 0)
    {
        if (mergedOut) { *mergedOut = false; }
        BYTE* user = UserOf(mgr, userNum);
        const int key = KeyOf(code);
        Guard g;
        Chain* ch = ChainOf(userNum, site);
        int a = after;
        if (ch->lastMerge >= 0 && (short)after == ch->lastMerge) { a = ch->chainAfter; InterlockedIncrement(&g_stats.chainFixed); }
        else { ch->chainAfter = (short)after; }
        UserPend* up = user ? PendOf(userNum, user) : nullptr;
        const DWORD b = batch ? batch : ch->batch;
        if (plate == 1 && user && up && key > 0 && add >= 0 && SiteOn(site))
        {
            bool isNew = false, overflow = false;
            const int s = FindStack(user, up, code, key, add, owner, mode, ex, &isNew, &overflow);
            if (s >= 0)
            {
                // ABS: ячейка помечается «абсолютный Amount в полёте» — другие пути в неё не сливают до ответа
                PendAdd(up, s, mode == M_ABS ? kKeyAbs : key, code, mode == M_ABS ? 0 : add, owner, false, b, mode == M_ABS ? kShortTtlMs : ttl);
                ch->lastMerge = s;
                if (mergedOut) { *mergedOut = true; }
                NoteMerge(opcode, user, userNum, code, s, add, site);
                return s;
            }
            // ABS: новая ячейка (флаг 2 = INSERT) не совпадает ни с каким резервом и сама резервируется (kKeyAbs)
            const int n = StockNew(mgr, userNum, up, plate, a, mode == M_ABS ? 0 : key, owner, ex);
            if (overflow) { NoteCap(opcode, user, userNum, code, add, n); }
            if (n >= 0)
            {
                PendAdd(up, n, mode == M_ABS ? kKeyAbs : key, code, mode == M_ABS ? 0 : add, owner, true, b, mode == M_ABS ? kShortTtlMs : ttl);
                InterlockedIncrement(&g_stats.newCells);
            }
            else { PendCancel(up, b); }   // «нет места» — сток отказывает выдаче целиком: записи этого вызова снимаются
            ch->chainAfter = n; ch->lastMerge = -2;
            return n;
        }
        const int n = (plate == 1 && up) ? StockNew(mgr, userNum, up, plate, a, 0, 0, ex) : (short)pRouter(mgr, nullptr, userNum, plate, a);
        if (n < 0 && up) { PendCancel(up, b); }
        ch->chainAfter = n; ch->lastMerge = -2;
        return n;
    }

    // ── подсчёт «сольётся» для предпроверок вместимости ──────────────────────
    struct In { int code; int add; int owner; };   // входящий предмет (owner — Owner, который получит запись)
    // Сколько входящих F НЕ потребуют новой ячейки (слияние в стопку или в новую ячейку более ранней копии того же ключа).
    int CountMerges(BYTE* user, int userNum, const In* in, int n, int site, const Excl* ex, int mode)
    {
        if (!user || !SiteOn(site)) { return 0; }
        Guard g;
        UserPend* up = PendOf(userNum, user);
        if (!up) { return 0; }
        UserPend sim = *up;   // копия: добавки этого запроса — во временный накопитель
        int merges = 0;
        int virtKey[8] = {}, virtOwner[8] = {}, virtSum[8] = {}, nv = 0;   // новые ячейки ранних копий этого запроса
        for (int i = 0; i < n; ++i)
        {
            const int key = KeyOf(in[i].code);
            if (key <= 0) { continue; }
            bool isNew = false, overflow = false;
            const int s = FindStack(user, &sim, in[i].code, key, in[i].add, in[i].owner, mode, ex, &isNew, &overflow);
            if (s >= 0)
            {
                ++merges;
                if (sim.n < kPendMax) { Pend& p = sim.e[sim.n++]; memset(&p, 0, sizeof(p)); p.slot = (short)s; p.key = key; p.code = in[i].code; p.add = in[i].add; p.owner = in[i].owner; p.ttl = 0xFFFFFFFFu; }
                continue;
            }
            int v = -1;
            for (int k = 0; k < nv; ++k) { if (virtKey[k] == key && virtOwner[k] == in[i].owner && virtSum[k] + in[i].add <= g_cap) { v = k; break; } }
            if (v >= 0) { ++merges; virtSum[v] += in[i].add; continue; }
            if (nv < 8) { virtKey[nv] = key; virtOwner[nv] = in[i].owner; virtSum[nv] = in[i].add; ++nv; }
        }
        return merges;
    }

    // ── преобразование записи при записи в память ────────────────────────────
    enum : int { L_FULL = 0, L_COMPACT54 = 1, L_LOT = 2 };   // формат записей пакета
    // Массив записей пакета клиенту (обновить все записи этой ячейки).
    struct Arr { int baseOff; int ptrOff; int ptrAdd; int stride; int layout; int idxOff; bool includeCur; int max; };
    // Описание площадки записи.
    struct WSpec
    {
        int  id; int opcode; int site;
        bool wresp;          // снять вес слитой копии с CUser (обработчик прибавит/прибавил +=)
        int  wAdjOff;        // ≠ 0: снять вес с i16 переменной кадра (вес «устанавливается» из неё после цикла)
        int  okOff;          // ≠ 0: байт результата БД (0 — ошибка; сток всё равно пишет)
        bool sameCode;       // только тот же код (склад)
        int  weightPtrOff;   // ≠ 0: [ebp+off] + weightPtrAdd — u16 вес в пакете, обновить после снятия
        int  weightPtrAdd;
        bool ledger; int lotOff; int lotStride; int lotIdxOff;   // аукцион: журнал добавок по Uidx лота
        Arr  arr[2];
    };

    // Записи массива, относящиеся к ячейке posx, получают итог ячейки.
    void Propagate(const BYTE* ebp, const Arr& a, int posx, const BYTE* cell)
    {
        if (!a.stride) { return; }
        BYTE* base = a.ptrOff ? Ptr(ebp, a.ptrOff) + a.ptrAdd : (BYTE*)ebp + a.baseOff;
        if (!base) { return; }
        int cur = I32(ebp, a.idxOff);
        if (cur < 0) { return; }
        if (cur > a.max - 1) { cur = a.max - 1; }
        const int last = a.includeCur ? cur : cur - 1;
        for (int j = 0; j <= last; ++j)
        {
            BYTE* e = base + a.stride * j;
            if (a.layout == L_FULL)
            {
                if (*(const int*)e > 0 && e[kRecPlate] == 1 && *(const short*)(e + kRecPosx) == posx) { memcpy(e, cell, kRec); }
            }
            else if (a.layout == L_COMPACT54)
            {
                if (*(const int*)e > 0 && e[4] == 1 && *(const short*)(e + 5) == posx) { *(int*)(e + 42) = *(const int*)(cell + kRecAmount); }
            }
            else if (*(const int*)(e + 7) > 0 && e[15] == 1 && *(const short*)(e + 16) == posx)
            {
                *(int*)(e + 11) = *(const int*)(cell + kRecAmount);
            }
        }
    }

    constexpr DWORD kLedgerTtlMs = 600000;   // добавка аукциона живёт до ответа БД (10 мин — с большим запасом)
    // Журнал добавки аукциона (на персонажа; при переполнении вытесняется самая старая).
    void LedgerPut(int userNum, const BYTE* user, int posx, int uidx, int code, int add)
    {
        if (userNum < 0 || userNum >= kMaxUsers) { return; }
        Guard g;
        Ledger* L = g_ledger[userNum];
        const int ui = UserIndexOf(user);
        int pick = 0; DWORD oldest = 0xFFFFFFFFu;
        const DWORD now = GetTickCount();
        for (int i = 0; i < kLedgerMax; ++i)
        {
            if (!L[i].tick || L[i].userIndex != ui || now - L[i].tick > kLedgerTtlMs) { pick = i; break; }
            if (now - L[i].tick < oldest) { continue; }
            oldest = now - L[i].tick; pick = i;
        }
        if (L[pick].tick && L[pick].userIndex == ui && now - L[pick].tick <= kLedgerTtlMs) { InterlockedIncrement(&g_stats.ledgerEvicted); }
        Ledger& l = L[pick];
        l.userIndex = ui; l.posx = posx; l.uidx = uidx; l.code = code; l.add = add; l.tick = now ? now : 1;
    }
    // Добавка аукциона по (персонаж, ячейка, Uidx лота) — снимается из журнала. 0 — слияния не было (или запись устарела).
    int LedgerTake(int userNum, const BYTE* user, int posx, int uidx, int* codeOut)
    {
        if (userNum < 0 || userNum >= kMaxUsers) { return 0; }
        Guard g;
        const int ui = UserIndexOf(user);
        const DWORD now = GetTickCount();
        for (int i = 0; i < kLedgerMax; ++i)
        {
            Ledger& l = g_ledger[userNum][i];
            if (l.tick && l.userIndex == ui && l.posx == posx && l.uidx == uidx)
            {
                const bool fresh = now - l.tick <= kLedgerTtlMs;
                const int a = l.add; if (codeOut) { *codeOut = l.code; } memset(&l, 0, sizeof(l));
                return fresh ? a : 0;
            }
        }
        return 0;
    }
    // Owner (+50), который сток ставит спецпредмету из выдачи с привязкой FT+43 == 2 (гача GS:94383, коробки/события
    //   sub_55B7F0 GS:133959, квест GS:38677, премиум-ящик @BelongType GS:95948); без привязки — 0.
    int BindOwner(int code) { return (g_tableOk && code >= 1 && code <= kMaxCode && g_row[code].bind == 2) ? 2 : 0; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ОБЩИЕ ТОЧКИ (Patches.h): P95 (коробки), P16 (премиум-гача), P62 (уникальность ячеек 6096), P101 (подарок кэш-магазина).
// ─────────────────────────────────────────────────────────────────────────────

// Активен ли P100 (площадки стоят, таблица сошлась с живой FT).
extern "C" __declspec(dllexport) int __stdcall P100_Active() { return g_enabled ? 1 : 0; }
// Включён ли путь (бит Sites; 7 — подарок, зарезервирован за P101 и здесь всегда 0 — P101 читает свою настройку).
extern "C" __declspec(dllexport) int __stdcall P100_SiteOn(int bit) { return (g_enabled && SiteOn(bit)) ? 1 : 0; }
// Ключ слияния кода (0 — не складывается / P100 не активен).
extern "C" __declspec(dllexport) int __stdcall P100_KeyOf(int code) { return g_enabled ? KeyOf(code) : 0; }
// Заряды выдачи кода: ток.9 целиком при FixCharges=1 ([ИСПРАВЛЕНИЕ 300]); иначе / вне таблицы — −1 (решает сток).
extern "C" __declspec(dllexport) int __stdcall P100_Charges(int code) { return (g_enabled && g_fixCharges) ? ChargesOf(code) : -1; }
// ★ P102 (02.11): сколько лотов (код/количество, Owner 0) НЕ потребуют новой ячейки сумки — слияние в стопку или в ячейку более
//   ранней копии того же ключа этого же запроса (как предпроверка 9906 P100). Нужна предпроверке вместимости 9910 (P102).
extern "C" __declspec(dllexport) int __stdcall P100_CountLotMerges(void* mgr, int userNum, const int* codes, const int* adds, int n, int site)
{
    if (!g_enabled || !codes || !adds || n <= 0) { return 0; }
    In in[16] = {};
    int k = 0;
    for (int i = 0; i < n && k < 16; ++i) { in[k].code = codes[i]; in[k].add = adds[i]; in[k].owner = 0; ++k; }
    __try { return CountMerges(UserOf(mgr, userNum), userNum, in, k, site, nullptr, M_ADD); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
// Новый номер пакета размещения (одна выдача из нескольких копий: коробка, P101).
extern "C" __declspec(dllexport) DWORD __stdcall P100_BeginBatch() { return (DWORD)InterlockedIncrement((LONG*)&g_batchSeq); }

namespace
{
    // Тело P100_FindChargeStack (без __try: замок — объект с деструктором).
    int FindChargeStackImpl(BYTE* user, int userNum, int code, int key, int add, int site, int owner, DWORD batch, int* isNewOut)
    {
        Guard g;
        UserPend* up = PendOf(userNum, user);
        bool isNew = false, overflow = false;
        const int s = FindStack(user, up, code, key, add, owner, M_ADD, nullptr, &isNew, &overflow);
        if (s >= 0)
        {
            PendAdd(up, s, key, code, add, owner, false, batch);
            if (isNewOut) { *isNewOut = isNew ? 1 : 0; }
            NoteMerge(0, user, userNum, code, s, add, site);
            return s;
        }
        if (overflow) { NoteCap(0, user, userNum, code, add, -1); }
        return -1;
    }
}

// ★ FindChargeStack + накопитель (для P101 и P95): стопка ключа кода, куда влезает add. Возврат: слот (добавка записана в
//   накопитель, *isNewOut = 1 — это новая ячейка ранней копии того же ключа) или −1 (стопки нет: вызывающий выбирает новую
//   ячейку сам и сообщает её P100_ReserveNew). site — бит Sites пути (для P101 — 7). owner — Owner (+50) входящей записи
//   (−1 — по привязке кода: FT+43 == 2 → 2, иначе 0); сливается только в ячейку с тем же Owner. Сумка — через P96_BagRec.
extern "C" __declspec(dllexport) int __stdcall P100_FindChargeStack(void* mgr, int userNum, int code, int add, int site, int owner, DWORD batch, int* isNewOut)
{
    if (isNewOut) { *isNewOut = 0; }
    if (!g_enabled || (site != 7 && !SiteOn(site))) { return -1; }
    const int key = KeyOf(code);
    BYTE* user = UserOf(mgr, userNum);
    if (key <= 0 || !user || add < 0) { return -1; }
    __try { return FindChargeStackImpl(user, userNum, code, key, add, site, owner < 0 ? BindOwner(code) : owner, batch, isNewOut); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(0, user, userNum, code, (int)GetExceptionCode(), 0, "exception in FindChargeStack -> stock"); }
    return -1;
}

// Резерв новой ячейки первой копии ключа (следующие копии того же ключа сольются в неё до ответа БД).
extern "C" __declspec(dllexport) void __stdcall P100_ReserveNew(void* mgr, int userNum, int code, int add, int owner, int slot, DWORD batch)
{
    const int key = g_enabled ? KeyOf(code) : 0;
    BYTE* user = UserOf(mgr, userNum);
    if (key <= 0 || !user || slot < 0) { return; }
    Guard g;
    PendAdd(PendOf(userNum, user), slot, key, code, add, owner < 0 ? BindOwner(code) : owner, true, batch);
    InterlockedIncrement(&g_stats.newCells);
}

// Ячейка зарезервирована в полёте (ключ ≠ key или Owner ≠ owner; key = 0 — любым; owner −1 — по привязке кода) — для выбора
//   свободной ячейки снаружи (P95, P101). code — код входящего (для Owner −1).
extern "C" __declspec(dllexport) int __stdcall P100_IsReserved(void* mgr, int userNum, int slot, int key, int code)
{
    if (!g_enabled) { return 0; }
    BYTE* user = UserOf(mgr, userNum);
    if (!user) { return 0; }
    Guard g;
    UserPend* up = PendOf(userNum, user);
    return (up && ReservedOther(up, slot, key, BindOwner(code))) ? 1 : 0;
}

// Снятие резервов/добавок пакета (выдача отказана до отправки в БД).
extern "C" __declspec(dllexport) void __stdcall P100_CancelBatch(int userNum, DWORD batch)
{
    if (userNum < 0 || userNum >= kMaxUsers || !batch) { return; }
    Guard g;
    UserPend* up = &g_pend[userNum];
    int w = 0;
    for (int i = 0; i < up->n; ++i) { if (up->e[i].batch != batch) { up->e[w++] = up->e[i]; } }
    up->n = w;
}

namespace
{
    // Тело P100_ReleaseRecs (без __try: замок — объект с деструктором).
    int ReleaseRecsImpl(BYTE* user, int userNum, const BYTE* recs, int n, int stride, int* slotsOut)
    {
        Guard g;
        UserPend* up = PendOf(userNum, user);
        if (!up) { return 0; }
        int rel = 0;
        for (int i = 0; i < n; ++i)
        {
            const BYTE* r = recs + stride * i;
            const int code = *(const int*)r;
            if (code <= 0 || r[kRecPlate] != 1 || KeyOf(code) <= 0) { continue; }
            const int posx = *(const short*)(r + kRecPosx);
            if (PendRelease(up, posx, *(const int*)(r + kRecAmount)))
            {
                if (slotsOut && rel < 5) { slotsOut[rel] = posx; }
                ++rel;
            }
        }
        return rel;
    }
}

// ★ P103 (04.11.2026): записи накопителя по записям ОТКАЗАННОГО ответа БД (запрос ушёл, процедура вернула Flag 0 — сток в память
//   не пишет, ConvertRec не зовётся). По каждой записи 57 б (код > 0, сумка, ключ > 0) снимается одна запись накопителя её ячейки
//   (Posx, Amount), как это сделал бы успешный ответ. Возврат — снято записей; slotsOut (до 5) — их ячейки. Без P100 — 0.
extern "C" __declspec(dllexport) int __stdcall P100_ReleaseRecs(void* mgr, int userNum, const BYTE* recs, int n, int stride, int* slotsOut)
{
    if (!g_enabled || !recs || n <= 0 || stride < kRec || userNum < 0 || userNum >= kMaxUsers) { return 0; }
    BYTE* user = UserOf(mgr, userNum);
    if (!user) { return 0; }
    __try { return ReleaseRecsImpl(user, userNum, recs, n, stride, slotsOut); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(0, user, userNum, n, (int)GetExceptionCode(), 0, "exception in ReleaseRecs -> entries kept until TTL"); }
    return 0;
}

// ★ Запись F в память с преобразованием (для P101 и площадок записи): rec в занятую ячейку того же ключа → запись ячейки
//   с Amount = старое + rec.Amount (код ячейки не меняется), затем стоковый sub_4D63F0. wresp = 1 — снять вес слитой копии с
//   CUser (обработчик прибавит его сам). Возврат: 1 — слито, 0 — обычная запись (пусто / не F / P100 не активен).
extern "C" __declspec(dllexport) int __stdcall P100_WriteMerged(void* mgr, int userNum, BYTE* rec, int wresp);

// Ячейки 6096, куда в последнем запросе персонажа сложены ≥ 2 позиции коробки (P62: повтор пары — не нарушение).
extern "C" __declspec(dllexport) int __stdcall P100_IsBoxMergeSlot(int userNum, int slot)
{
    if (!g_enabled || userNum < 0 || userNum >= kMaxUsers || slot < 0 || slot >= 64) { return 0; }
    return (g_boxShared[userNum][slot >> 5] >> (slot & 31)) & 1;
}

// ★ P95 S1 (коробки 6096): раскладка позиции-спецпредмета. Возврат: слот стопки (слияние) или −1 (P95 выбирает новую ячейку
//   и сообщает её P100_ReserveNew с тем же batch). pos — номер позиции; pos < 0 — начало запроса (сброс маски общих ячеек).
extern "C" __declspec(dllexport) int __stdcall P100_BoxPlace(void* mgr, int userNum, int code, int pos, DWORD batch)
{
    if (!g_enabled || userNum < 0 || userNum >= kMaxUsers) { return -1; }
    if (pos < 0) { g_boxShared[userNum][0] = g_boxShared[userNum][1] = 0; return -1; }   // начало запроса 6096
    const int add = g_fixCharges ? ChargesOf(code) : (ChargesOf(code) & 0xFF);   // sub_55B7F0: заряды выдачи (количество позиции для F игнорируется)
    int isNew = 0;
    const int s = P100_FindChargeStack(mgr, userNum, code, add, 5, BindOwner(code), batch, &isNew);   // sub_55B7F0: +50 = 2 при FT+43 == 2
    if (s >= 0)
    {
        InterlockedIncrement(&g_stats.viaBox);
        if (isNew && s < 64) { g_boxShared[userNum][s >> 5] |= 1u << (s & 31); }
        else if (s < 64)
        {
            // стопка уже лежит: несколько позиций этого запроса в ней — отметка для P62
            Guard g;
            UserPend* up = &g_pend[userNum];
            int cnt = 0;
            for (int i = 0; i < up->n; ++i) { if (up->e[i].batch == batch && up->e[i].slot == s) { ++cnt; } }
            if (cnt >= 2) { g_boxShared[userNum][s >> 5] |= 1u << (s & 31); }
        }
    }
    return s;
}

// ★ P16 (премиум-гача → сумка, путь A1′): ячейка копии i шаблона вместо SrvFindFreeSlot. Возврат как у sub_4D6740.
extern "C" __declspec(dllexport) int __stdcall P100_PremiumSlot(void* mgr, int userNum, int code, int container, int after, int add)
{
    if (!g_enabled) { return (short)pRouter(mgr, nullptr, userNum, container, after); }
    __try { return PickCell(mgr, userNum, container, after, code, add, 0, 2601, M_ADD, nullptr, nullptr, 0, BindOwner(code)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(2601, nullptr, userNum, code, (int)GetExceptionCode(), 0, "exception in P16 slot -> stock"); }
    return (short)pRouter(mgr, nullptr, userNum, container, after);
}

extern "C" __declspec(dllexport) void __stdcall P100_GetStats(P100_Stats* out) { if (out) { *out = g_stats; } }

// ─────────────────────────────────────────────────────────────────────────────
//  ПЛОЩАДКИ
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    // Номера площадок (общие преобразователи по id).
    enum : int
    {
        // выбор ячейки (вместо call sub_4D6740)
        R_P1 = 1, R_A1REQ, R_A1RES, R_A4, R_A5, R_A7, R_B1, R_B3A, R_B3B, R_B3C, R_B3D, R_B4, R_B5BUY, R_B5DEL, R_B9, R_B10, R_B11,
        // ★ P102 (02.11): экипировка лота аукциона — стоковые вызовы того же afterSlot, что у F-лотов (0x51CC90 9906, 0x52001E 9910)
        R_B5BUYEQ = 18, R_B5DELEQ = 19,
        // запись в память (вместо call sub_4D63F0)
        W_A1 = 30, W_A2, W_A3, W_A4, W_A5, W_A6, W_A7, W_B1, W_B6F, W_B6B, W_B10, W_B11, W_B4, W_B5BUY, W_B5DEL, W_B3_1, W_B3_2, W_B3_3, W_B3_4,
        W_B9 = 55,                                                   // ответ разборки, ветка «тот же код уже лежит» 0x4FEBBC
        // стирание ячейки (вместо call sub_4D6540) — откат аукциона
        E_B5BUY = 60, E_B5DEL,
        // предпроверки
        Q_B1 = 70,                                                   // sub_4D7CD0
        C_B3A = 80, C_B3B, C_B4, C_B5RES, C_B5REQ, C_B5DELREQ,       // sub_4D6A70
        M_MOVE = 86,                                                 // sub_52BFF0 в CharItemMove 5000
        // ★ ревизия 02.11 (б): операции, убирающие/перемещающие ячейку сумки — отказ стоком, пока по ячейке слияние в полёте
        G_DUMP = 100, G_KEEP, G_SELL, G_VANISH, G_STORE1, G_STORE2, G_MEET, G_MEET2, G_SUMMON, G_FISHBOOK,   // sub_52BFF0 «занят»
        G_XDRAG = 120, G_AUCREG, G_USE5450, G_SUMMON2, G_UPG6504, G_RESET6506, G_PETLV1, G_PETLV2, G_PETCNT, G_INCUB, G_PETCOND,
        G_PGACHA, G_RENAME, G_PSUM, G_EXTRACT, G_BLESS, G_OPTTR, G_OPTEXT, G_CASHKEY, G_FLAG, G_SQUAD, G_TRADE,                // sub_4D61E0
        G_CRAFT = 150,                                               // sub_532B10 в RecvUser_CraftEnter (материал-спецпредмет)
        G_AUTOUSE = 160,                                             // sub_5646C0 автоприменения sub_4F1550
    };

    // Площадки записи: опкод, бит, вес, массивы пакета.
    const WSpec kW[] =
    {
        // id      op    bit wresp wAdj  ok     same  wPtr  wAdd  ledger lot   lotSt idx    arrays {base, ptr, ptrAdd, stride, layout, idx, cur, max}
        { W_A1,   2604,  0, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x1AF, 0, 0, 57, L_FULL, -0x21C, true, 7 } } },
        { W_A2,   2229,  1, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     {} },
        { W_A3,   2521,  2, false, -0x118, 0,    false, 0,    0,    false, 0,    0,    0,     {} },
        { W_A4,   6042,  3, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     {} },
        { W_A5,   2469,  4, false, 0,     0,     false, 0,    0,    false, 0,    0,    0,     {} },
        { W_A6,   2272,  5, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x12D, 0, 0, 57, L_FULL, -0x280, true, 5 } } },
        { W_A7,   2270,  6, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x27E, 0, 0, 57, L_FULL, -0x294, true, 5 } } },
        { W_B1,   2076,  8, true,  0,     0,     false, 0x1C, 0x1DF, false, 0,   0,    0,     { { 0, 0x1C, 0x89, 57, L_FULL, -0x80, true, 6 } } },
        { W_B6F,  2577, 10, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     {} },
        { W_B6B,  2587, 10, true,  0,     -0x52, false, 0,    0,    false, 0,    0,    0,     {} },
        { W_B10,  2462, 12, false, 0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x271, 0, 0, 57, L_FULL, -0x280, true, 4 } } },
        { W_B11,  2031, 16, true,  0,     0,     true,  0,    0,    false, 0,    0,    0,     {} },
        { W_B4,   2400, 14, false, -0x1F1, 0,    false, 0,    0,    false, 0,    0,    0,     { { -0x5F0, 0, 0, 57, L_FULL, -0x5FC, true, 6 } } },
        { W_B5BUY, 9906, 15, true, 0,     0,     false, 0,    0,    true, -0x2FC, 85, -0xD10, { { -0x2FC, 0, 0, 85, L_LOT, -0xD10, true, 8 }, { -0x87B, 0, 0, 85, L_LOT, -0xD10, false, 8 } } },
        { W_B5DEL, 9910, 15, true, 0,     0,     false, 0,    0,    true, -0x2C4, 61, -0x8E0, { { -0x2C4, 0, 0, 61, L_LOT, -0x8E0, true, 10 }, { -0x52B, 0, 0, 61, L_LOT, -0x8E0, false, 10 } } },
        { W_B3_1, 2120, 13, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x3BB, 0, 0, 54, L_COMPACT54, -0x44, true, 5 } } },
        { W_B3_2, 2120, 13, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x513, 0, 0, 54, L_COMPACT54, -0x44, true, 5 } } },
        { W_B3_3, 2120, 13, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x3BB, 0, 0, 54, L_COMPACT54, -0x44, true, 5 } } },
        { W_B3_4, 2120, 13, true,  0,     0,     false, 0,    0,    false, 0,    0,    0,     { { -0x513, 0, 0, 54, L_COMPACT54, -0x44, true, 5 } } },
    };
    const WSpec* WSpecOf(int id) { for (const WSpec& w : kW) { if (w.id == id) { return &w; } } return nullptr; }

    // ★ Преобразование записи rec перед стоковой записью. *wOut — вес слитой копии. Возврат: 1 слито, 0 обычная, −1 — не писать.
    int ConvertRec(void* mgr, int userNum, BYTE* rec, const WSpec* sp, const BYTE* ebp, int* wOut, BYTE** userOut)
    {
        *wOut = 0;
        BYTE* user = UserOf(mgr, userNum);
        if (userOut) { *userOut = user; }
        if (!user || rec[kRecPlate] != 1) { return 0; }
        const int code = *(const int*)rec;
        const int key = KeyOf(code);
        if (key <= 0) { return 0; }
        const int posx = *(const short*)(rec + kRecPosx);
        BYTE* cell = P96_BagRec(user, posx);
        if (!cell) { return 0; }
        const int add = *(const int*)(rec + kRecAmount);
        Guard g;
        UserPend* up = PendOf(userNum, user);
        const int cc = *(const int*)cell;
        if (cc <= 0)
        {
            // первая копия в новую ячейку — обычная запись. Если же снята запись-СЛИЯНИЕ (стопка опустела/ушла в полёте), память
            //   и БД могут разойтись по порядку исполнения в DBManager — запись как стока (БД: UPDATE без строки → INSERT), журнал 156.
            if (PendRelease(up, posx, add) == 1)
            {
                NoteMismatch(sp ? sp->opcode : 0, user, userNum, code, posx, add, "merge target cell emptied while DB request in flight -> written as new cell");
            }
            return 0;
        }
        if (KeyOf(cc) != key || cell[kRecPlate] != 1 || (sp && sp->sameCode && cc != code))
        {
            NoteMismatch(sp ? sp->opcode : 0, user, userNum, code, posx, cc, "write of charge item into cell of another item -> stock write");
            return 0;
        }
        if (sp && sp->okOff && !*(ebp + sp->okOff))
        {
            // [ИСПРАВЛЕНИЕ] сток пишет запись и при ошибке БД (книга рыбака): слитую ячейку не трогаем — заряды в БД не прибавлены
            PendRelease(up, posx, add);
            NoteMismatch(sp->opcode, user, userNum, code, posx, add, "DB error: merge into stack skipped (stock would overwrite the stack)");
            *wOut = *(const short*)(rec + kRecWeight);
            memcpy(rec, cell, kRec);   // пакет клиенту (6183 копирует rec после записи) получает запись ячейки, а не «добавку в стопку»
            return -1;
        }
        const long long total = (long long)*(const int*)(cell + kRecAmount) + add;
        if (total > g_cap) { NoteCap(sp ? sp->opcode : 0, user, userNum, code, add, posx); }
        *wOut = *(const short*)(rec + kRecWeight);
        BYTE tmp[kRec];
        memcpy(tmp, cell, kRec);
        *(int*)(tmp + kRecAmount) = (int)(total > 0x7FFFFFFF ? 0x7FFFFFFF : total);
        memcpy(rec, tmp, kRec);
        PendRelease(up, posx, add);
        InterlockedIncrement(&g_stats.writesMerged);
        return 1;
    }

    // Разборка 0x4FEBBC: сток уже сложил запись (Amount += тело +71, вес ячейки += тело +73 [ebp-8Fh]) и прибавил вес персонажу
    //   (sub_43F880 0x4FEBA3). У складываемого спецпредмета вес — на штуку: вес ячейки и персонажа возвращаются назад.
    int DoWriteB9(BYTE* ebp, void* mgr, int userNum, BYTE* rec, BYTE* src)
    {
        if (g_enabled && rec && !src)
        {
            __try
            {
                const int w = I16(ebp, -0x8F);
                if (rec[kRecPlate] == 1 && KeyOf(*(const int*)rec) > 0 && w > 0)
                {
                    *(short*)(rec + kRecWeight) = (short)(*(const short*)(rec + kRecWeight) - w);
                    SubWeight(UserOf(mgr, userNum), w);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return pWrite(mgr, nullptr, userNum, rec, src);
    }

    // Площадка записи: преобразование, стоковая запись, итог в пакет, вес.
    int DoWrite(int id, BYTE* ebp, void* mgr, int userNum, BYTE* rec, BYTE* src)
    {
        if (id == W_B9) { return DoWriteB9(ebp, mgr, userNum, rec, src); }
        const WSpec* sp = WSpecOf(id);
        int merged = 0, w = 0, add = 0, uidx = 0;
        BYTE* user = nullptr;
        if (g_enabled && sp && rec && !src)
        {
            add = *(const int*)(rec + kRecAmount);
            if (sp->ledger) { uidx = I32(ebp, sp->lotOff + sp->lotStride * I32(ebp, sp->lotIdxOff)); }
            __try { merged = ConvertRec(mgr, userNum, rec, sp, ebp, &w, &user); }
            __except (EXCEPTION_EXECUTE_HANDLER) { merged = 0; NoteMismatch(sp->opcode, nullptr, userNum, id, (int)GetExceptionCode(), 0, "exception in merge write -> stock"); }
        }
        if (merged < 0)
        {
            if (sp->wresp) { SubWeight(user, w); }   // сток прибавит вес копии после записи — снимаем
            return 0;
        }
        const int r = pWrite(mgr, nullptr, userNum, rec, src);
        if (merged > 0)
        {
            __try
            {
                const int posx = *(const short*)(rec + kRecPosx);
                const BYTE* cell = P96_BagRec(user, posx);
                if (cell)
                {
                    for (const Arr& a : sp->arr) { Propagate(ebp, a, posx, cell); }
                }
                if (sp->wresp) { SubWeight(user, w); }
                if (sp->wAdjOff) { short* v = (short*)(ebp + sp->wAdjOff); *v = (short)(*v > w ? *v - w : 0); InterlockedIncrement(&g_stats.weightFixed); }
                if (sp->weightPtrOff) { BYTE* p = Ptr(ebp, sp->weightPtrOff); if (p) { *(WORD*)(p + sp->weightPtrAdd) = *(const WORD*)(user + kOffWeight); } }
                if (sp->ledger) { LedgerPut(userNum, user, posx, uidx, *(const int*)rec, add); }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(sp->opcode, user, userNum, id, (int)GetExceptionCode(), 1, "exception after merge write"); }
        }
        return r;
    }

    // Откат аукциона (ошибка БД): слитая добавка вычитается, ячейка не стирается; вес не снимается (его не прибавляли).
    int DoErase(int id, BYTE* ebp, void* mgr, int userNum, int plate, int posx)
    {
        if (g_enabled && (short)plate == 1)
        {
            __try
            {
                BYTE* user = UserOf(mgr, userNum);
                const bool buy = id == E_B5BUY;
                const int j = I32(ebp, buy ? -0xD18 : -0x9BC);
                const BYTE* lot = ebp + (buy ? -0x58B + 85 * j : -0x53B + 61 * j);
                int code = 0;
                const int add = user ? LedgerTake(userNum, user, (short)posx, *(const int*)lot, &code) : 0;
                BYTE* cell = user ? P96_BagRec(user, (short)posx) : nullptr;
                if (add > 0 && cell && *(const int*)cell > 0 && KeyOf(*(const int*)cell) == KeyOf(code))
                {
                    const int left = *(const int*)(cell + kRecAmount) - add;
                    if (left > 0)
                    {
                        int* acc = (int*)(ebp + (buy ? -0xC64 : -0x954));
                        *acc -= FtWeight(I32(ebp, buy ? -0xC68 : -0x958));   // ячейка остаётся — вес копии не прибавлялся, сток снял бы его
                    }
                    InterlockedIncrement(&g_stats.rollbacks);
                    char d[64], t[160];
                    _snprintf_s(d, sizeof(d), _TRUNCATE, "P100 %d rollback slot %d -%d -> %d", buy ? 2205 : 2207, (short)posx, add, left);
                    _snprintf_s(t, sizeof(t), _TRUNCATE, "auction DB error: merged lot %d (+%d) subtracted from cell %d instead of erasing it, left %d",
                                *(const int*)lot, add, (short)posx, left);
                    Report(kKindRollback, buy ? 2205 : 2207, user, userNum, code, (short)posx, add, d, t);
                    if (left > 0)
                    {
                        BYTE tmp[kRec];
                        memcpy(tmp, cell, kRec);
                        *(int*)(tmp + kRecAmount) = left;
                        return pWrite(mgr, nullptr, userNum, tmp, nullptr);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(id == E_B5BUY ? 2205 : 2207, nullptr, userNum, posx, (int)GetExceptionCode(), 0, "exception in auction rollback -> stock"); }
        }
        return pErase(mgr, nullptr, userNum, plate, posx);
    }

    // Список отдаваемых ячеек стороны сделки shell (их нельзя брать стопкой).
    void ShellExcl(const BYTE* D, bool sideA, Excl* ex)
    {
        ex->n = 0;
        const int base = sideA ? 0xE21 : 0xF2F;
        for (int k = 0; k < 5; ++k)
        {
            const BYTE* r = D + base + 54 * k;
            const int c = *(const int*)r;
            if (c > 0 && c != 20551 && r[4] == 1 && ex->n < 8) { ex->slot[ex->n++] = *(const short*)(r + 5); }
        }
    }
    // Сделка shell: D = this + a3 * 0x231 (CharShellItemExchangeComplete).
    const BYTE* ShellDeal(const BYTE* ebp) { return Ptr(ebp, -0x514) + I32(ebp, 0xC) * 0x231; }
    // Owner отдаваемой ячейки сделки shell (у отдающего; компактная запись Owner не несёт). toA — получает A (отдаёт B).
    int ShellGiverOwner(void* mgr, const BYTE* D, bool toA, int i)
    {
        const int giver = *(const short*)(D + (toA ? 0xE1B : 0xE19));
        const BYTE* r = D + (toA ? 0xF2F : 0xE21) + 54 * i;
        BYTE* gu = UserOf(mgr, giver);
        const BYTE* cell = (gu && r[4] == 1) ? P96_BagRec(gu, *(const short*)(r + 5)) : nullptr;
        return (cell && *(const int*)cell == *(const int*)r) ? cell[50] : 0;
    }
    // Owner шаблона путей «шаблон» точки 1: 11006 — @BelongType (по привязке), война роз — Owner шаблона.
    int kind3Owner(DWORD ret, int code, int owner) { return ret == 0x004F8596 ? BindOwner(code) : owner; }

    // ★ Выбор ячейки (площадки R_*). ebp — кадр вызывающей функции.
    int DoPick(int id, BYTE* ebp, void* mgr, int userNum, int plate, int after)
    {
        int code = 0, add = 0, site = -1, opcode = 0, mode = M_ADD, owner = 0;
        DWORD ttl = 0;
        Excl ex = {}; const Excl* pex = nullptr;
        bool merged = false;
        switch (id)
        {
        case R_P1:   // sub_5340B0 ветка F: код [ebp+0Ch], запись [ebp+14h], вызывающий [ebp+4]
        {
            code = I32(ebp, 0xC);
            BYTE* rec = Ptr(ebp, 0x14);
            const DWORD ret = *(const DWORD*)(ebp + 4);
            add = *(const int*)(rec + kRecAmount);
            int kind = 0;   // 0 сток, 1 ADD, 2 ABS, 3 шаблон
            switch (ret)
            {
            case 0x00533932: kind = 1; site = 2;  opcode = 6540; break;   // Recv_User_CashKey (A3)
            case 0x0040FC57: kind = 1; site = 10; opcode = 6171; break;   // Recv_EndFishing (B6)
            case 0x004131C8: kind = 1; site = 10; opcode = 6182; break;   // Recv_FishingBookReward (B6)
            case 0x0053B891: case 0x0053BAA9: kind = 2; site = 9; opcode = 6593; break;   // RecvUser_LimitationQuestResult (B2)
            case 0x0053E898: case 0x0053E8D1: kind = 2; site = 9; opcode = 6602; break;   // RecvUser_CraftEnter (B7)
            case 0x0049AD4C: kind = 2; site = 9; opcode = 6579; break;   // Recv_UserSoulResult (B8)
            case 0x004F8596: kind = 3; site = 0;  opcode = 11006; break;  // Recv_PremiumItemToInven_Req (A1) — ячейки выбирает 0x4F882E
            case 0x00469300: kind = 3; site = 12; opcode = 2462; break;   // sub_469010 (B10) — перевыбор 0x469362
            default: kind = 0; break;
            }
            const int owner = rec[50];   // sub_5340B0 для F +50 не ставит — Owner записи вызывающего (обычно 0)
            if (kind == 0) { return PickCell(mgr, userNum, plate, after, code, -1, -1, 0, M_ADD, nullptr, nullptr, 0, owner); }
            if (kind == 3)
            {
                // шаблон: ячейка будет перевыбрана площадкой пути; стопка лишь не даёт «нет места» (код 6) при полной сумке
                BYTE* user = UserOf(mgr, userNum);
                const int key = KeyOf(code);
                if (user && key > 0 && SiteOn(site))
                {
                    Guard g;
                    UserPend* up = PendOf(userNum, user);
                    bool isNew = false, overflow = false;
                    const int s = FindStack(user, up, code, key, add, kind3Owner(ret, code, owner), M_ADD, nullptr, &isNew, &overflow);
                    if (s >= 0 && !isNew) { return s; }
                }
                return (short)pRouter(mgr, nullptr, userNum, plate, after);
            }
            mode = kind == 2 ? M_ABS : M_ADD;
            const int s = PickCell(mgr, userNum, plate, after, code, add, site, opcode, mode, nullptr, &merged, 0, owner);
            if (merged && s >= 0)
            {
                BYTE* user = UserOf(mgr, userNum);
                const BYTE* cell = user ? P96_BagRec(user, s) : nullptr;
                if (kind == 2 && cell)
                {
                    // ABS: запись = ячейка (её код), Amount = старое + добавка; флаг «изменить» и сверку старого ставит сам путь
                    memcpy(rec, cell, kRec);
                    *(int*)(rec + kRecAmount) = *(const int*)(cell + kRecAmount) + add;
                }
                // A3: вес записи награды не обнуляется (при INSERT в БД — свой вес); вес персонажа снимается на ответе
                //   (W_A3: тело +8 [ebp-118h] «установить», 0x534045).
            }
            return s;
        }
        case R_A1REQ:   // 11006: код [ebp-220h], шаблон [ebp-5Fh] (Amount +9 = [ebp-56h]); Owner в БД = @BelongType (FT+43 == 2 → 2)
            code = I32(ebp, -0x220); add = I32(ebp, -0x56); site = 0; opcode = 11006; owner = BindOwner(code); break;
        case R_A1RES:   // ответ 2604: ячейка — из эха тела (Posx1..7 @+71), а не пересчётом (БД положила туда)
        {
            code = I32(ebp, -0x1FF);
            const int i = I32(ebp, -0x21C);
            if (g_enabled && KeyOf(code) > 0 && i >= 0 && i < 7 && (short)plate == 1)
            {
                const int s = I16(ebp, -0x1C5 + 2 * i);
                if (s >= 0) { InterlockedIncrement(&g_stats.echoSlots); return s; }
            }
            // ★ [ИСПРАВЛЕНИЕ НАШЕЙ ПРАВКИ, 05.11.2026, ключ EchoAllCodes] запрос 0x4F882E (StockNew, ключ 0) пропускает ячейки с ЛЮБОЙ
            //   записью накопителя (резерв коробки в полёте), а ответ для кодов без ключа звал стоковый роутер без пропуска: БД
            //   вставляла в Y, память и 11007 — в X; ответ коробки потом затирал X, следующий 11006 снова брал Y → PK_Item_1 (11007
            //   статус 0), открытие коробки в X — Flag 0. Теперь сумке и для кодов без ключа — ячейка эха (туда положила БД).
            if (g_enabled && g_echoAll && i >= 0 && i < 7 && (short)plate == 1)
            {
                const int s = I16(ebp, -0x1C5 + 2 * i);
                if (s >= 0 && s < P96_BagSize())
                {
                    BYTE* user = UserOf(mgr, userNum);
                    const BYTE* cell = user ? P96_BagRec(user, s) : nullptr;
                    if (cell && *(const int*)cell <= 0) { InterlockedIncrement(&g_stats.echoNonKey); return s; }
                    // ячейка эха в памяти уже занята (или недоступна) — не затираем: стоковый выбор + вид 156 (память ≠ БД)
                    InterlockedIncrement(&g_stats.echoBusy);
                    const int n = (short)pRouter(mgr, nullptr, userNum, plate, after);
                    char t[160];
                    _snprintf_s(t, sizeof(t), _TRUNCATE, "2604 item %d copy %d: DB echo cell %d is occupied in memory (code %d) -> stock cell %d, memory != DB",
                                code, i, s, cell ? *(const int*)cell : -1, n);
                    NoteMismatch(2604, user, userNum, code, s, n, t);
                    return n;
                }
            }
            return (short)pRouter(mgr, nullptr, userNum, plate, after);
        }
        case R_A4:      // GM 6042: код [ebp-4], заряды из таблицы (запись ещё не построена)
            code = I32(ebp, -4); add = ChargesOf(code); if (!g_fixCharges && add > 0) { add &= 0xFF; } site = 3; opcode = 6042; owner = 0; break;
        case R_A5:      // магазин осады 6162: код [ebp-15Ch]
            code = I32(ebp, -0x15C); add = ChargesOf(code); if (!g_fixCharges && add > 0) { add &= 0xFF; } site = 4; opcode = 6162; owner = 0;
            ttl = kShortTtlMs; break;   // после выбора сток ещё сверяет вес (отказ без записи) — запись накопителя короткая
        case R_A7:      // sub_55B7F0 (вызывающий EventItemRequestReq 0x5548AD): код [ebp+0Ch], запись [ebp+18h]
            if (*(const DWORD*)(ebp + 4) != 0x005548AD) { return PickCell(mgr, userNum, plate, after, I32(ebp, 0xC), -1, -1, 0, M_ADD, nullptr, nullptr, 0, 0); }
            code = I32(ebp, 0xC); add = *(const int*)(Ptr(ebp, 0x18) + kRecAmount); site = 6; opcode = 6098; owner = BindOwner(code); break;
        case R_B1:      // квест sub_45DEE0: код [ebp-4D8h], кол-во RepayTable [ebp-410h] (сток: Amount = кол-во)
            code = I32(ebp, -0x4D8); add = I32(ebp, -0x410); site = 8; opcode = 7104; owner = BindOwner(code); break;   // v180 GS:38677
        case R_B3A: case R_B3D: case R_B3B: case R_B3C:   // обмен shell: получатель — userNum вызова
        {
            const BYTE* D = ShellDeal(ebp);
            const int i = I32(ebp, -0x254);
            const bool toA = id == R_B3A || id == R_B3D;   // получает A (предмет B)
            code = *(const int*)(D + (toA ? 0xF2F : 0xE21) + 54 * i);
            add  = *(const int*)(D + (toA ? 0xF59 : 0xE4B) + 54 * i);
            ShellExcl(D, toA, &ex); pex = &ex;
            site = 13; opcode = 5291;
            owner = ShellGiverOwner(mgr, D, toA, i);   // UPShellItemChange берёт Owner из строки отдающего
            break;
        }
        case R_B4:      // лавка 6309: код [ebp-494h], копия предмета продавца [ebp-4E0h] (Amount [ebp-4D7h])
            code = I32(ebp, -0x494); add = I32(ebp, -0x4D7); site = 14; opcode = 6309; owner = *(ebp - 0x4AE); break;   // Owner копии продавца
        case R_B5BUY:   // аукцион, покупка 9906: код [ebp-0C60h], лот m [ebp-0D10h], Amount лота [ebp-2F1h+85m]
            code = I32(ebp, -0xC60); add = I32(ebp, -0x2F1 + 85 * I32(ebp, -0xD10)); site = 15; opcode = 9906; owner = 0; break;   // лот только с Owner 0 (GS:106983)
        case R_B5DEL:   // аукцион, снятие 9910: код [ebp-87Ch], лот j [ebp-8E0h], Amount [ebp-2B9h+61j]
            code = I32(ebp, -0x87C); add = I32(ebp, -0x2B9 + 61 * I32(ebp, -0x8E0)); site = 15; opcode = 9910; owner = 0; break;
        case R_B9:      // разборка 6502: код [ebp-12Ch]; сток даёт Amount 0 (дефект оригинала); процедура сливает только тот же код
        {
            code = I32(ebp, -0x12C); add = P102_DisasmAdd(code); site = 11; opcode = 6502; mode = M_SAME;   // ★ P102: заряды кода (0 — сток)
            // ревизия 02.11 (в): @Weight (2302 +73 = [ebp-98h]) остаётся весом штуки, как в стоке — при INSERT (стопку израсходовали
            //   в полёте) строка получит правильный вес; рост веса в ПАМЯТИ при слиянии снимает площадка ответа 0x4FEBBC (W_B9).
            //   В БД `UPItemDisassemble` на UPDATE прибавляет Weight + @Weight — для складываемых спецпредметов это правка процедуры.
            return PickCell(mgr, userNum, plate, after, code, add, site, opcode, mode, nullptr, &merged, 0, *(ebp - 0x12C + 50));   // +50 = FT+43 (GS:98397)
        }
        case R_B10:     // война роз sub_469010: код [ebp-4], шаблон [ebp-1F4h] (Amount +9 = [ebp-1EBh])
        {
            code = I32(ebp, -4); add = I32(ebp, -0x1EB); site = 12; opcode = 2462;
            const int s = PickCell(mgr, userNum, plate, after, code, add, site, opcode, M_ADD, nullptr, &merged, 0, *(ebp - 0x1F4 + 50));
            if (merged) { short* v = (short*)(ebp - 0x188); *v = (short)(*v - FtWeight(code)); }   // v41 += вес после — копия слита
            return s;
        }
        // ★ [ИСПРАВЛЕНИЕ P102, 02.11] ошибка P100 v57: в цикле 9906/9910 F-лот и лот экипировки ищут ячейку сумки ОДНОЙ цепочкой
        //   afterSlot ([ebp-4Ch] / [ebp-58h]). F-лот через P100 мог вернуть слот СТОПКИ; вызывающий записал его в «после», и
        //   стоковый поиск экипировки (0x51CC90 / 0x52001E) пропускал свободные ячейки ниже стопки → отказ посреди цикла (память
        //   с лишними зарядами, 2204/2206 не ушёл). Теперь эти вызовы идут через PickCell с ключом 0: слияния нет, «после» —
        //   прежнее звено цепочки (как у собственных площадок P100); «нет места» снимает записи накопителя этого вызова.
        case R_B5BUYEQ:
        case R_B5DELEQ:
            return PickCell(mgr, userNum, plate, after, 0, 0, 15, id == R_B5BUYEQ ? 9906 : 9910, M_ADD, nullptr, &merged, 0, 0);
        case R_B11:     // склад → сумка 5010: код [ebp-1C0h], запись склада [ebp-1B8h] (Amount [ebp-1AFh]); только тот же код
            code = I32(ebp, -0x1C0); add = I32(ebp, -0x1AF); site = 16; opcode = 5010; mode = M_SAME; owner = *(ebp - 0x1B8 + 50); break;   // Owner записи склада
        default:
            return (short)pRouter(mgr, nullptr, userNum, plate, after);
        }
        const int s = PickCell(mgr, userNum, plate, after, code, add, site, opcode, mode, pex, &merged, 0, owner, ttl);
        if (merged && id == R_A5) { short* v = (short*)(ebp - 0xA4); *v = (short)(*v - FtWeight(code)); }   // v111 += вес F после выбора
        return s;
    }

    // ★ Предпроверки вместимости.
    int DoRoom2(int id, BYTE* ebp, void* mgr, int userNum, int plate)
    {
        const int freeCells = pCount(mgr, nullptr, userNum, plate);
        if (!g_enabled || (short)plate != 1) { return freeCells; }
        int extra = 0;
        __try
        {
            BYTE* user = UserOf(mgr, userNum);
            In in[10] = {}; int n = 0; Excl ex = {}; const Excl* pex = nullptr; int site = 15;
            switch (id)
            {
            case C_B3A: case C_B3B:   // обмен shell: A получает предметы B, B — предметы A
            {
                const BYTE* D = ShellDeal(ebp);
                const bool toA = id == C_B3A;
                for (int k = 0; k < 5; ++k)
                {
                    const BYTE* r = D + (toA ? 0xF2F : 0xE21) + 54 * k;
                    if (*(const int*)r > 0) { in[n].code = *(const int*)r; in[n].add = *(const int*)(r + 42); in[n].owner = ShellGiverOwner(mgr, D, toA, k); ++n; }
                }
                ShellExcl(D, toA, &ex); pex = &ex; site = 13;
                break;
            }
            case C_B4:   // лавка: список запроса 6 × 45 б с [ebp-488h]: код +0Bh, Amount +12h
                for (int k = 0; k < 6; ++k)
                {
                    const BYTE* r = ebp - 0x488 + 45 * k;
                    const int c = *(const int*)(r + 0xB);
                    if (c >= 1 && c <= kMaxCode) { in[n].code = c; in[n].add = *(const int*)(r + 0x12); ++n; }
                }
                site = 14;
                break;
            case C_B5RES:   // аукцион, ответ ItemRelay: лоты 85 б с [ebp-2FCh], число [ebp-0CFCh]
            {
                int cnt = I32(ebp, -0xCFC); if (cnt > 8) { cnt = 8; }
                for (int k = 0; k < cnt; ++k)
                {
                    const BYTE* r = ebp - 0x2FC + 85 * k;
                    const int c = *(const int*)(r + 7);
                    if (c >= 1 && c <= kMaxCode) { in[n].code = c; in[n].add = *(const int*)(r + 11); ++n; }
                }
                break;
            }
            case C_B5REQ: case C_B5DELREQ:   // аукцион, запросы: записи 45 б (код +4, Amount +8), 8 / 10 шт.
            {
                const int base = id == C_B5REQ ? -0x58C : -0x5EC, cnt = id == C_B5REQ ? 8 : 10;
                for (int k = 0; k < cnt; ++k)
                {
                    const BYTE* r = ebp + base + 45 * k;
                    const int c = *(const int*)(r + 4);
                    if (c >= 1 && c <= kMaxCode) { in[n].code = c; in[n].add = *(const int*)(r + 8); ++n; }
                }
                break;
            }
            default: break;
            }
            extra = CountMerges(user, userNum, in, n, site, pex, M_ADD);
            if (extra) { InterlockedExchangeAdd(&g_stats.roomGranted, extra); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { extra = 0; }
        return freeCells + extra;
    }

    // Квест: sub_4D7CD0(user, 1, вес) — для слияния не нужна свободная ячейка и вес не растёт.
    int DoRoom3(int id, BYTE* ebp, void* mgr, int userNum, int plate, int weight)
    {
        if (g_enabled && id == Q_B1 && (short)plate == 1)
        {
            __try
            {
                BYTE* user = UserOf(mgr, userNum);
                In in = { I32(ebp, -0x4D8), I32(ebp, -0x410), BindOwner(I32(ebp, -0x4D8)) };
                if (CountMerges(user, userNum, &in, 1, 8, nullptr, M_ADD) == 1) { InterlockedIncrement(&g_stats.roomGranted); return 1; }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return pRoom(mgr, nullptr, userNum, plate, weight);
    }
}

// Общий вход трёхаргументных площадок (sub_4D6740 / sub_4D63F0 / sub_4D6540 / sub_4D7CD0). Аргументы — как пушит сток.
extern "C" int __stdcall P100_Call3(int id, BYTE* ebp, void* mgr, int a1, int a2, int a3)
{
    const int userNum = (short)a1;
    if (id >= 30 && id < 60) { return DoWrite(id, ebp, mgr, userNum, (BYTE*)a2, (BYTE*)a3); }
    if (id >= 60 && id < 70) { return DoErase(id, ebp, mgr, userNum, a2, a3); }
    if (id >= 70 && id < 80) { return DoRoom3(id, ebp, mgr, userNum, a2, a3); }
    if (!g_enabled) { return (short)pRouter(mgr, nullptr, userNum, a2, a3); }
    __try { return DoPick(id, ebp, mgr, userNum, a2, a3); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(0, nullptr, userNum, id, (int)GetExceptionCode(), 0, "exception in cell pick -> stock"); }
    return (short)pRouter(mgr, nullptr, userNum, a2, a3);
}

// ★ P127 А2.3 (19.11.2026): выбор ячейки сумки для спецпредмета (Function) в переносе хвоста Recv_OperatorCommand_ItemGive (мост
//   админ-центра) — ТОТ ЖЕ путь, что площадка A4 0x5525B0 (`call sub_4D6740(mgr, num, 1, 0xFFFF)` ветки Function): преобразователь
//   R_A4 читает код из [ebp-4] — здесь кадр-заготовка с кодом на том же смещении. P100 не активен — стоковый роутер (как и у площадки).
extern "C" __declspec(dllexport) int __stdcall P100_GmGivePick(void* mgr, int userNum, int code)
{
    BYTE frame[8] = {};
    *(int*)frame = code;                                            // [ebp-4] = код (кадр: ebp = frame + 4)
    return P100_Call3(R_A4, frame + 4, mgr, userNum, 1, -1);        // сумка 1, «после» −1 (сток пушит 0xFFFF)
}

namespace
{
    // ★ Перемещение 5000 (CharItemMove, «занят» sub_52BFF0 @0x4CE562; сток применяет перемещение к памяти только в ответе БД
    //   sub_4D12F0). Ячейка сумки с добавкой/абсолютом в полёте не перемещается: отказ стоковым кодом 18 (тело 0x4CE56E) — иначе
    //   ответ слияния увидел бы пустую ячейку и записал её заново (память: t = старое, s = добавка; БД: t = старое + добавка).
    //   Пропущенное перемещение помечает свои ячейки (kKeyMove, 5 с): в них не сливают, пока перемещение в полёте.
    //   moveReq [ebp-88h]: +0 слот-источник i16, +4 контейнер-источник u8, +0Bh слот-цель i16, +0Fh контейнер-цель u8.
    int DoMove(BYTE* ebp, void* mgr, int userNum, int opcode)
    {
        const char busy = pBusy(mgr, nullptr, userNum, opcode);
        if (busy || !g_enabled) { return (BYTE)busy; }
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return 0; }
        const int sp = *(ebp - 0x84), ss = I16(ebp, -0x88), dp = *(ebp - 0x79), ds = I16(ebp, -0x7D);
        Guard g;
        UserPend* up = PendOf(userNum, user);
        if (!up) { return 0; }
        auto inflight = [&](int plate, int slot) { if (plate != 1) { return false; } for (int i = 0; i < up->n; ++i) { if (up->e[i].slot == slot && up->e[i].key != kKeyMove) { return true; } } return false; };
        if (inflight(sp, ss) || inflight(dp, ds))
        {
            InterlockedIncrement(&g_stats.movesRefused);
            NoteMismatch(5000, user, userNum, sp * 1000 + ss, dp * 1000 + ds, 18, "item move of bag cell with charges in flight (DB) -> refused 5001 code 18");
            return 1;
        }
        if (sp == 1 && ss >= 0) { PendAdd(up, ss, kKeyMove, 0, 0, 0, false, 0, kShortTtlMs); InterlockedIncrement(&g_stats.moveMarks); }
        if (dp == 1 && ds >= 0) { PendAdd(up, ds, kKeyMove, 0, 0, 0, false, 0, kShortTtlMs); InterlockedIncrement(&g_stats.moveMarks); }
        return 0;
    }
}

namespace
{
    // Ячейка запроса операции (контейнер, слот).
    struct Cell2 { int plate; int slot; };
    // Ячейки запроса гейта из кадра вызывающей (ebp). Смещения сняты с дизасма живого образа (разбор 02.11, агент «removal»).
    int GateCells(int id, const BYTE* ebp, Cell2* c)
    {
        int n = 0;
        auto one = [&](int plate, int slot) { if (n < 12) { c[n].plate = plate; c[n].slot = slot; ++n; } };
        switch (id)
        {
        case G_DUMP:     one(ebp[-0x494], I16(ebp, -0x498)); break;                                          // 5006 [ebp-498h]
        case G_KEEP:     for (int i = 0; i < 5; ++i) { one(ebp[-0x5A8 + 11 * i + 4], I16(ebp, -0x5A8 + 11 * i)); } break;   // 5008 5×11
        case G_SELL:     for (int i = 0; i < 5; ++i) { one(ebp[-0x14C + 11 * i + 4], I16(ebp, -0x14C + 11 * i)); } break;   // 5018 5×11
        case G_VANISH:   one(ebp[-0x13C], I16(ebp, -0x13B)); break;                                          // 5026 [ebp-13Ch]
        case G_STORE1: case G_STORE2:                                                                         // 6302 10×45
        {
            int cnt = ebp[-0x454]; if (cnt > 10) { cnt = 10; }
            for (int i = 0; i < cnt; ++i) { if (I32(ebp, -0x453 + 45 * i) > 0) { one(ebp[-0x44F + 45 * i], I16(ebp, -0x44E + 45 * i)); } }
            break;
        }
        case G_MEET: case G_SUMMON: one(1, I16(ebp, -0x108)); break;                                          // 5458 / 6134
        case G_MEET2:    one(1, I16(ebp, -0x4F)); break;                                                     // sub_4F39D0 (5461)
        case G_FISHBOOK: one(ebp[-0x308], I16(ebp, -0x30C)); break;                                          // 6176
        case G_UPG6504:  for (int i = 1; i < 4; ++i) { one(ebp[-0x22C + 3 * i], I16(ebp, -0x22C + 3 * i + 1)); } break;   // свиток + 2 F
        case G_RESET6506: for (int i = 0; i < 10; ++i) { one(ebp[-0x1D6 + i], I16(ebp, -0x1CC + 2 * i)); } break;
        case G_INCUB:    one(ebp[-0xD4], I16(ebp, -0xD3)); one(ebp[-0xD1], I16(ebp, -0xD0)); one(ebp[-0xCE], I16(ebp, -0xCD)); break;
        case G_PSUM:     for (int i = 0; i < 5; ++i) { one(ebp[-0x24A + 2 * i], I16(ebp, -0x254 + 2 * i)); } break;
        case G_EXTRACT:  for (int i = 0; i < 8; ++i) { one(ebp[-0x590 + 2 * i], I16(ebp, -0x5A0 + 2 * i)); } break;
        case G_CRAFT:    { const int j = I32(ebp, -0x7CC); if (j >= 0 && j < 8) { one(ebp[-0x530 + j], I16(ebp, -0x534 + 2 * j)); } break; }
        default: break;
        }
        return n;
    }
    // Ячейка сумки занята слиянием/абсолютом в полёте (перемещение — не помеха).
    bool CellInFlight(const UserPend* up, int plate, int slot)
    {
        if (plate != 1 || slot < 0) { return false; }
        for (int i = 0; i < up->n; ++i) { if (up->e[i].slot == slot && up->e[i].key != kKeyMove) { return true; } }
        return false;
    }
    // Опкод гейта (журнал).
    int GateOpcode(int id)
    {
        static const struct { int id, op; } k[] = {
            { G_DUMP, 5006 }, { G_KEEP, 5008 }, { G_SELL, 5018 }, { G_VANISH, 5026 }, { G_STORE1, 6302 }, { G_STORE2, 6302 }, { G_MEET, 5458 },
            { G_MEET2, 5461 }, { G_SUMMON, 6134 }, { G_FISHBOOK, 6176 }, { G_XDRAG, 5288 }, { G_AUCREG, 9901 }, { G_USE5450, 5450 },
            { G_SUMMON2, 3540 }, { G_UPG6504, 6504 }, { G_RESET6506, 6506 }, { G_PETLV1, 6148 }, { G_PETLV2, 6148 }, { G_PETCNT, 6121 },
            { G_INCUB, 6102 }, { G_PETCOND, 6108 }, { G_PGACHA, 6581 }, { G_RENAME, 6140 }, { G_PSUM, 6555 }, { G_EXTRACT, 6549 },
            { G_BLESS, 6551 }, { G_OPTTR, 6553 }, { G_OPTEXT, 5433 }, { G_CASHKEY, 6540 }, { G_FLAG, 6524 }, { G_SQUAD, 6704 },
            { G_TRADE, 5475 }, { G_CRAFT, 6602 }, { G_AUTOUSE, 2223 } };
        for (const auto& e : k) { if (e.id == id) { return e.op; } }
        return 0;
    }
    constexpr DWORD kExchangeTtlMs = 600000;   // ячейка в окне обмена: количество снято снимком при перетаскивании — 10 мин без слияний

    // ★ Общий гейт: ячейки (из кадра и/или аргументов) — есть слияние в полёте → true (отказ стоком); иначе метка
    //   «операция в полёте» (kKeyMove; обмен — 10 мин, прочие — 5 с): в эти ячейки P100 не сливает, пока операция не дошла до БД.
    bool GateBlocked(int id, BYTE* ebp, void* mgr, int userNum, const Cell2* extra, int nExtra)
    {
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return false; }
        Cell2 c[16]; int n = GateCells(id, ebp, c);
        for (int i = 0; i < nExtra && n < 16; ++i) { c[n++] = extra[i]; }
        // применение спецпредмета (5450, встреча, призыв) уменьшает Amount на 1 — это перестановочно со слиянием (обе правки
        //   относительные); гонка только когда применение удаляет ячейку (Amount ≤ 1: UPSkillItemSpend @Tamount < 2 → DELETE)
        const bool useOp = id == G_USE5450 || id == G_MEET || id == G_MEET2 || id == G_SUMMON || id == G_SUMMON2;
        for (int i = 0; i < n; ++i)
        {
            if (!useOp || c[i].plate != 1) { continue; }
            const BYTE* r = P96_BagRec(user, c[i].slot);
            if (r && *(const int*)(r + kRecAmount) > 1) { c[i].plate = 0; }   // не удалит ячейку — не мешает слиянию
        }
        Guard g;
        UserPend* up = PendOf(userNum, user);
        if (!up) { return false; }
        for (int i = 0; i < n; ++i)
        {
            if (CellInFlight(up, c[i].plate, c[i].slot))
            {
                InterlockedIncrement(&g_stats.opsRefused);
                char d[64];
                _snprintf_s(d, sizeof(d), _TRUNCATE, "op %d: bag cell %d has charges merge in flight -> stock refusal", GateOpcode(id), c[i].slot);
                NoteMismatch(GateOpcode(id), user, userNum, c[i].plate * 1000 + c[i].slot, id, 0, d);
                return true;
            }
        }
        for (int i = 0; i < n; ++i)
        {
            if (c[i].plate == 1 && c[i].slot >= 0 && c[i].slot < 64)
            {
                PendAdd(up, c[i].slot, kKeyMove, 0, 0, 0, false, 0, id == G_XDRAG ? kExchangeTtlMs : kShortTtlMs);
                InterlockedIncrement(&g_stats.moveMarks);
            }
        }
        return false;
    }
    // Есть ли у персонажа слияние/абсолют в полёте (любая ячейка сумки) — для автоприменения без ячейки в кадре.
    bool AnyInFlight(void* mgr, int userNum)
    {
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return false; }
        Guard g;
        UserPend* up = PendOf(userNum, user);
        if (!up) { return false; }
        for (int i = 0; i < up->n; ++i) { if (up->e[i].key != kKeyMove) { return true; } }
        return false;
    }
}

// Общий вход двухаргументных площадок (sub_4D6A70, sub_52BFF0).
extern "C" int __stdcall P100_Call2(int id, BYTE* ebp, void* mgr, int a1, int a2)
{
    if (id == M_MOVE)
    {
        __try { return DoMove(ebp, mgr, (short)a1, a2); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return (BYTE)pBusy(mgr, nullptr, (short)a1, a2); }
    }
    if (id >= G_DUMP && id < G_XDRAG)
    {
        // «занят»: сток вернул отказ — его код; иначе — отказ P100 (al = 1), если ячейка запроса со слиянием в полёте
        const char busy = pBusy(mgr, nullptr, (short)a1, a2);
        if (busy || !g_enabled) { return (BYTE)busy; }
        __try { return GateBlocked(id, ebp, mgr, (short)a1, nullptr, 0) ? 1 : 0; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    return DoRoom2(id, ebp, mgr, (short)a1, a2);
}

// Общий вход пятиаргументных площадок: sub_4D61E0 (ячейка запроса; 0 — «пусто» → стоковый отказ операции) и sub_5646C0
//   автоприменения (персонаж со слиянием в полёте — запрос не уходит, повтор на следующем такте).
extern "C" int __stdcall P100_Call5(int id, BYTE* ebp, void* mgr, int a1, int a2, int a3, int a4, int a5)
{
    if (id == G_AUTOUSE)
    {
        bool skip = false;
        if (g_enabled) { __try { skip = AnyInFlight(mgr, (short)a5); } __except (EXCEPTION_EXECUTE_HANDLER) { skip = false; } }
        if (skip) { InterlockedIncrement(&g_stats.opsRefused); return 1; }
        const int r = pDbSend(mgr, nullptr, a1, a2, a3, (void*)a4, a5);
        if (r) { P103_OnDbSent(a1, (const BYTE*)a4, a5); }   // ★ P103 S3: автоприменение 2223 ушло — замок группы до ответа 2224 (не ушло — ответа не будет)
        return r;
    }
    if (g_enabled)
    {
        bool blocked = false;
        __try { const Cell2 arg = { (BYTE)a2, (short)a3 }; blocked = GateBlocked(id, ebp, mgr, (short)a1, &arg, 1); }
        __except (EXCEPTION_EXECUTE_HANDLER) { blocked = false; }
        if (blocked) { return 0; }
    }
    return pGetCell(mgr, nullptr, a1, a2, a3, (BYTE*)a4, (BYTE*)a5);
}

// Крафт 6602: `call sub_532B10` по коду материала-спецпредмета (0x53E4B8). Ячейка материала со слиянием в полёте → «не
//   спецпредмет» (сток отказывает 6603 кодом 3).
extern "C" BOOL __stdcall P100_IsF(int id, BYTE* ebp, int code)
{
    const BOOL r = pIsF(code);
    if (!r || !g_enabled) { return r; }
    bool blocked = false;
    __try { blocked = GateBlocked(id, ebp, Ptr(ebp, -0x820), I16(ebp, 8), nullptr, 0); }   // this [ebp-820h] (0x53DBB5), userNum [ebp+8]
    __except (EXCEPTION_EXECUTE_HANDLER) { blocked = false; }
    return blocked ? FALSE : r;
}

extern "C" __declspec(dllexport) int __stdcall P100_WriteMerged(void* mgr, int userNum, BYTE* rec, int wresp)
{
    int merged = 0, w = 0;
    BYTE* user = nullptr;
    if (g_enabled && rec)
    {
        __try { merged = ConvertRec(mgr, userNum, rec, nullptr, nullptr, &w, &user); }
        __except (EXCEPTION_EXECUTE_HANDLER) { merged = 0; }
    }
    pWrite(mgr, nullptr, userNum, rec, nullptr);
    if (merged > 0 && wresp) { SubWeight(user, w); }
    return merged > 0 ? 1 : 0;
}

// [ИСПРАВЛЕНИЕ 300] Чтение FT+13 на пути выдачи: p = адрес байта (FT + 48·(код−1) + 13). Заряды i32 из charge_groups.
extern "C" int __stdcall P100_ChargesAt(const BYTE* p)
{
    const int stock = *p;
    if (!g_enabled || !g_fixCharges) { return stock; }
    __try
    {
        const DWORD off = (DWORD)(p - 13 - *(const BYTE**)kFuncTablePtr);
        if (off % kFuncRec) { return stock; }
        const int code = (int)(off / kFuncRec) + 1;
        const int ch = ChargesOf(code);
        if (ch < 0) { return stock; }
        if (ch != stock) { InterlockedIncrement(&g_stats.chargesFixed); }
        return ch;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return stock; }
}

namespace
{
    // Тело P100_OnGacha (без __try: замок — объект с деструктором).
    void OnGachaImpl(BYTE* ebp, int userNum)
    {
        void* mgr = Ptr(ebp, -0x194);
        const int code = I32(ebp, -0xD4);
        BYTE* src = ebp - 0x48;
        if (*(const int*)src != code || src[kRecPlate] != 1 || KeyOf(code) <= 0 || !SiteOn(1)) { return; }
        BYTE* user = UserOf(mgr, userNum);
        if (!user) { return; }
        const int key = KeyOf(code), add = *(const int*)(src + kRecAmount), owner = BindOwner(code);   // GS:94383: +50 = 2 при FT+43 == 2
        Guard g;
        UserPend* up = PendOf(userNum, user);
        bool isNew = false, overflow = false;
        const int s = FindStack(user, up, code, key, add, owner, M_ADD, nullptr, &isNew, &overflow);
        if (s >= 0)
        {
            *(short*)(src + kRecPosx) = (short)s;
            *(short*)(ebp - 0x16C) = 0;   // приращение веса: копия слита — вес не растёт
            PendAdd(up, s, key, code, add, owner, false, 0, kShortTtlMs);   // после выбора сток ещё сверяет вес (код 7 без записи)
            NoteMerge(5468, user, userNum, code, s, add, 1);
            return;
        }
        if (overflow) { NoteCap(5468, user, userNum, code, add, *(const short*)(src + kRecPosx)); }
        int pos = *(const short*)(src + kRecPosx);
        if (ebp[-0x80] != 1 && ReservedOther(up, pos, key, owner))
        {
            pos = StockNew(mgr, userNum, up, 1, pos, key, owner, nullptr);   // стоковая ячейка зарезервирована другим ключом в полёте
            if (pos >= 0) { *(short*)(src + kRecPosx) = (short)pos; }
        }
        if (pos >= 0) { PendAdd(up, pos, key, code, add, owner, true, 0, kShortTtlMs); InterlockedIncrement(&g_stats.newCells); }
    }
}

// A2 гача 5468 (точка схождения веток после выбора ячейки, 0x4F4F7B): запись Src [ebp-48h], код [ebp-0D4h], вес Δ [ebp-16Ch].
extern "C" void __stdcall P100_OnGacha(BYTE* ebp)
{
    if (!g_enabled) { return; }
    int userNum = -1;
    __try { userNum = *(const short*)(ebp + 8); OnGachaImpl(ebp, userNum); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NoteMismatch(5468, nullptr, userNum, 0, (int)GetExceptionCode(), 0, "exception in gacha pick -> stock"); }
}

namespace
{
    // ── трамплины ─────────────────────────────────────────────────────────────
    //   call-площадка: [esp] = адрес возврата, далее аргументы стока; ecx = this; ebp — кадр вызывающей (не тронут).
    __declspec(naked) void C3Common()
    {
        __asm
        {
            pop   eax                       // id площадки
            push  dword ptr [esp+0Ch]       // a3
            push  dword ptr [esp+0Ch]       // a2
            push  dword ptr [esp+0Ch]       // a1
            push  ecx                       // this
            push  ebp                       // кадр вызывающей
            push  eax                       // id
            call  P100_Call3
            ret   0Ch
        }
    }
    __declspec(naked) void C2Common()
    {
        __asm
        {
            pop   eax                       // id площадки
            push  dword ptr [esp+8]         // a2
            push  dword ptr [esp+8]         // a1
            push  ecx
            push  ebp
            push  eax
            call  P100_Call2
            ret   8
        }
    }
#define P100_C3(name, ID) __declspec(naked) void name() { __asm { push ID } __asm { jmp C3Common } }
#define P100_C2(name, ID) __declspec(naked) void name() { __asm { push ID } __asm { jmp C2Common } }
    P100_C3(T_P1, 1)  P100_C3(T_A1REQ, 2) P100_C3(T_A1RES, 3) P100_C3(T_A4, 4) P100_C3(T_A5, 5) P100_C3(T_A7, 6) P100_C3(T_B1, 7)
    P100_C3(T_B3A, 8) P100_C3(T_B3B, 9) P100_C3(T_B3C, 10) P100_C3(T_B3D, 11) P100_C3(T_B4, 12) P100_C3(T_B5BUY, 13) P100_C3(T_B5DEL, 14)
    P100_C3(T_B9, 15) P100_C3(T_B10, 16) P100_C3(T_B11, 17)
    P100_C3(T_B5BUYEQ, 18) P100_C3(T_B5DELEQ, 19)   // ★ P102: экипировка лота аукциона (та же цепочка afterSlot)
    P100_C3(TW_A1, 30) P100_C3(TW_A2, 31) P100_C3(TW_A3, 32) P100_C3(TW_A4, 33) P100_C3(TW_A5, 34) P100_C3(TW_A6, 35) P100_C3(TW_A7, 36)
    P100_C3(TW_B1, 37) P100_C3(TW_B6F, 38) P100_C3(TW_B6B, 39) P100_C3(TW_B10, 40) P100_C3(TW_B11, 41) P100_C3(TW_B4, 42)
    P100_C3(TW_B5BUY, 43) P100_C3(TW_B5DEL, 44) P100_C3(TW_B3_1, 45) P100_C3(TW_B3_2, 46) P100_C3(TW_B3_3, 47) P100_C3(TW_B3_4, 48)
    P100_C3(TE_B5BUY, 60) P100_C3(TE_B5DEL, 61) P100_C3(TQ_B1, 70)
    P100_C2(TC_B3A, 80) P100_C2(TC_B3B, 81) P100_C2(TC_B4, 82) P100_C2(TC_B5RES, 83) P100_C2(TC_B5REQ, 84) P100_C2(TC_B5DELREQ, 85)
    P100_C2(TM_MOVE, 86)
    P100_C3(TW_B9, 55)
    P100_C2(TG_DUMP, 100) P100_C2(TG_KEEP, 101) P100_C2(TG_SELL, 102) P100_C2(TG_VANISH, 103) P100_C2(TG_STORE1, 104) P100_C2(TG_STORE2, 105)
    P100_C2(TG_MEET, 106) P100_C2(TG_MEET2, 107) P100_C2(TG_SUMMON, 108) P100_C2(TG_FISHBOOK, 109)
    __declspec(naked) void C5Common()
    {
        __asm
        {
            pop   eax                       // id площадки
            push  dword ptr [esp+14h]       // a5
            push  dword ptr [esp+14h]       // a4
            push  dword ptr [esp+14h]       // a3
            push  dword ptr [esp+14h]       // a2
            push  dword ptr [esp+14h]       // a1
            push  ecx                       // this
            push  ebp                       // кадр вызывающей
            push  eax                       // id
            call  P100_Call5
            ret   14h
        }
    }
#define P100_C5(name, ID) __declspec(naked) void name() { __asm { push ID } __asm { jmp C5Common } }
    P100_C5(TG_XDRAG, 120) P100_C5(TG_AUCREG, 121) P100_C5(TG_USE5450, 122) P100_C5(TG_SUMMON2, 123) P100_C5(TG_UPG6504, 124)
    P100_C5(TG_RESET6506, 125) P100_C5(TG_PETLV1, 126) P100_C5(TG_PETLV2, 127) P100_C5(TG_PETCNT, 128) P100_C5(TG_INCUB, 129)
    P100_C5(TG_PETCOND, 130) P100_C5(TG_PGACHA, 131) P100_C5(TG_RENAME, 132) P100_C5(TG_PSUM, 133) P100_C5(TG_EXTRACT, 134)
    P100_C5(TG_BLESS, 135) P100_C5(TG_OPTTR, 136) P100_C5(TG_OPTEXT, 137) P100_C5(TG_CASHKEY, 138) P100_C5(TG_FLAG, 139)
    P100_C5(TG_SQUAD, 140) P100_C5(TG_TRADE, 141) P100_C5(TG_AUTOUSE, 160)
    // крафт 0x53E4B8: cdecl sub_532B10(код) — вызывающий снимает аргумент сам
    __declspec(naked) void TG_CRAFT()
    {
        __asm
        {
            mov   eax, dword ptr [esp+4]    // код материала
            push  eax
            push  ebp
            push  150
            call  P100_IsF
            ret
        }
    }

    // [ИСПРАВЛЕНИЕ 300] замена `movzx r32, byte [rA + rB + 0Dh]` (5 б) — результат из P100_ChargesAt, флаги/прочие регистры целы.
    DWORD g_ftBack[5] = { 0x004F4EA7, 0x00515DCB, 0x005345F0, 0x005525FE, 0x0055BD50 };   // продолжения
    __declspec(naked) void Ft_4F4EA2()   // movzx edx, byte [ecx+eax+0Dh]
    {
        __asm { pushfd } __asm { push eax } __asm { push ecx } __asm { lea edx, [ecx+eax+0Dh] } __asm { push edx }
        __asm { call P100_ChargesAt } __asm { mov edx, eax } __asm { pop ecx } __asm { pop eax } __asm { popfd } __asm { jmp dword ptr [g_ftBack+0] }
    }
    __declspec(naked) void Ft_515DC6()   // movzx eax, byte [edx+ecx+0Dh]
    {
        __asm { pushfd } __asm { push ecx } __asm { push edx } __asm { lea eax, [edx+ecx+0Dh] } __asm { push eax }
        __asm { call P100_ChargesAt } __asm { pop edx } __asm { pop ecx } __asm { popfd } __asm { jmp dword ptr [g_ftBack+4] }
    }
    __declspec(naked) void Ft_5345EB()   // movzx eax, byte [edx+ecx+0Dh]
    {
        __asm { pushfd } __asm { push ecx } __asm { push edx } __asm { lea eax, [edx+ecx+0Dh] } __asm { push eax }
        __asm { call P100_ChargesAt } __asm { pop edx } __asm { pop ecx } __asm { popfd } __asm { jmp dword ptr [g_ftBack+8] }
    }
    __declspec(naked) void Ft_5525F9()   // movzx edx, byte [ecx+eax+0Dh]
    {
        __asm { pushfd } __asm { push eax } __asm { push ecx } __asm { lea edx, [ecx+eax+0Dh] } __asm { push edx }
        __asm { call P100_ChargesAt } __asm { mov edx, eax } __asm { pop ecx } __asm { pop eax } __asm { popfd } __asm { jmp dword ptr [g_ftBack+12] }
    }
    __declspec(naked) void Ft_55BD4B()   // movzx eax, byte [edx+ecx+0Dh]
    {
        __asm { pushfd } __asm { push ecx } __asm { push edx } __asm { lea eax, [edx+ecx+0Dh] } __asm { push eax }
        __asm { call P100_ChargesAt } __asm { pop edx } __asm { pop ecx } __asm { popfd } __asm { jmp dword ptr [g_ftBack+16] }
    }

    // A2: jmp с 0x4F4F7B; замещённое `mov ecx,[ebp-0D4h]`, продолжение 0x4F4F81.
    DWORD g_gachaBack = 0x004F4F81;
    __declspec(naked) void St_Gacha()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P100_OnGacha
            popad
            popfd
            mov   ecx, dword ptr [ebp-0D4h]
            jmp   dword ptr [g_gachaBack]
        }
    }

    // ── таблица call-площадок: адрес, стоковая цель, трамплин, бит (−1 — всегда) ──
    struct CallSite { DWORD va; DWORD target; void* stub; const char* what; };
    const CallSite kCalls[] =
    {
        { 0x0053460C, 0x004D6740, (void*)&T_P1,     "sub_5340B0 F (точка 1)" },
        { 0x004F882E, 0x004D6740, (void*)&T_A1REQ,  "A1 11006 ячейки копий" },
        { 0x004F8BA3, 0x004D6740, (void*)&T_A1RES,  "A1 2604 ячейки из эха" },
        { 0x005525B0, 0x004D6740, (void*)&T_A4,     "A4 GM 6042" },
        { 0x00515D16, 0x004D6740, (void*)&T_A5,     "A5 магазин осады 6162" },
        { 0x0055BD73, 0x004D6740, (void*)&T_A7,     "A7 sub_55B7F0 (события)" },
        { 0x0045F0B2, 0x004D6740, (void*)&T_B1,     "B1 квест" },
        { 0x004E531C, 0x004D6740, (void*)&T_B3A,    "B3 shell → A (arg8≠0)" },
        { 0x004E5B40, 0x004D6740, (void*)&T_B3B,    "B3 shell → B (arg8≠0)" },
        { 0x004E6348, 0x004D6740, (void*)&T_B3C,    "B3 shell → B (arg8=0)" },
        { 0x004E6B5D, 0x004D6740, (void*)&T_B3D,    "B3 shell → A (arg8=0)" },
        { 0x00505DBC, 0x004D6740, (void*)&T_B4,     "B4 лавка 6309" },
        { 0x0051BB2D, 0x004D6740, (void*)&T_B5BUY,  "B5 аукцион покупка" },
        { 0x0051EEFA, 0x004D6740, (void*)&T_B5DEL,  "B5 аукцион снятие" },
        { 0x0051CC90, 0x004D6740, (void*)&T_B5BUYEQ, "B5 аукцион покупка — экипировка (цепочка, P102)" },
        { 0x0052001E, 0x004D6740, (void*)&T_B5DELEQ, "B5 аукцион снятие — экипировка (цепочка, P102)" },
        { 0x004FE715, 0x004D6740, (void*)&T_B9,     "B9 разборка" },
        { 0x00469362, 0x004D6740, (void*)&T_B10,    "B10 война роз" },
        { 0x0050B9C6, 0x004D6740, (void*)&T_B11,    "B11 склад → сумка" },
        { 0x004F8CCE, 0x004D63F0, (void*)&TW_A1,    "A1 запись 2604" },
        { 0x004F5813, 0x004D63F0, (void*)&TW_A2,    "A2 запись 2229" },
        { 0x0053402B, 0x004D63F0, (void*)&TW_A3,    "A3 запись 2521" },
        { 0x005533A6, 0x004D63F0, (void*)&TW_A4,    "A4 запись GM" },
        { 0x00516A5A, 0x004D63F0, (void*)&TW_A5,    "A5 запись 2469" },
        { 0x0055B483, 0x004D63F0, (void*)&TW_A6,    "A6 запись 2272" },
        { 0x00559E57, 0x004D63F0, (void*)&TW_A7,    "A7 запись 2270" },
        { 0x0045F1DF, 0x004D63F0, (void*)&TW_B1,    "B1 запись квест" },
        { 0x00410988, 0x004D63F0, (void*)&TW_B6F,   "B6 запись рыба 2577" },
        { 0x004135AE, 0x004D63F0, (void*)&TW_B6B,   "B6 запись книга 2587" },
        { 0x00469DDF, 0x004D63F0, (void*)&TW_B10,   "B10 запись 2462" },
        { 0x0050CE93, 0x004D63F0, (void*)&TW_B11,   "B11 запись 2031" },
        { 0x00507055, 0x004D63F0, (void*)&TW_B4,    "B4 запись 2400" },
        { 0x0051BE0C, 0x004D63F0, (void*)&TW_B5BUY, "B5 запись покупка" },
        { 0x0051F1DC, 0x004D63F0, (void*)&TW_B5DEL, "B5 запись снятие" },
        { 0x004E91D2, 0x004D63F0, (void*)&TW_B3_1,  "B3 запись (ветка 1, блок 1)" },
        { 0x004E977D, 0x004D63F0, (void*)&TW_B3_2,  "B3 запись (ветка 1, блок 2)" },
        { 0x004E9FCE, 0x004D63F0, (void*)&TW_B3_3,  "B3 запись (ветка 2, блок 1)" },
        { 0x004EA579, 0x004D63F0, (void*)&TW_B3_4,  "B3 запись (ветка 2, блок 2)" },
        { 0x0051DBAC, 0x004D6540, (void*)&TE_B5BUY, "B5 откат покупки" },
        { 0x00520A74, 0x004D6540, (void*)&TE_B5DEL, "B5 откат снятия" },
        { 0x0045F066, 0x004D7CD0, (void*)&TQ_B1,    "B1 предпроверка" },
        { 0x004E4DFE, 0x004D6A70, (void*)&TC_B3A,   "B3 пустые A" },
        { 0x004E4E29, 0x004D6A70, (void*)&TC_B3B,   "B3 пустые B" },
        { 0x00505ACE, 0x004D6A70, (void*)&TC_B4,    "B4 пустые" },
        { 0x0051BA5A, 0x004D6A70, (void*)&TC_B5RES, "B5 пустые (ответ)" },
        { 0x0051B10F, 0x004D6A70, (void*)&TC_B5REQ, "B5 пустые (запрос покупки)" },
        { 0x0051EA3E, 0x004D6A70, (void*)&TC_B5DELREQ, "B5 пустые (запрос снятия)" },
        { 0x004CE562, 0x0052BFF0, (void*)&TM_MOVE,  "перемещение 5000 — «занят» (ячейка с зарядами в полёте)" },
        { 0x004FEBBC, 0x004D63F0, (void*)&TW_B9,    "B9 ответ разборки — вес штуки при слиянии" },
        { 0x004D353C, 0x0052BFF0, (void*)&TG_DUMP,  "5006 уничтожение" },
        { 0x0050961E, 0x0052BFF0, (void*)&TG_KEEP,  "5008 склад" },
        { 0x0050D463, 0x0052BFF0, (void*)&TG_SELL,  "5018 продажа NPC" },
        { 0x004DD76A, 0x0052BFF0, (void*)&TG_VANISH, "5026 исчезновение" },
        { 0x0050300E, 0x0052BFF0, (void*)&TG_STORE1, "6302 лавка (1)" },
        { 0x0050302A, 0x0052BFF0, (void*)&TG_STORE2, "6302 лавка (2)" },
        { 0x004F34E7, 0x0052BFF0, (void*)&TG_MEET,  "5458 встреча" },
        { 0x004F3B03, 0x0052BFF0, (void*)&TG_MEET2, "5461 встреча (ответ ретранслятора)" },
        { 0x004F2A32, 0x0052BFF0, (void*)&TG_SUMMON, "6134 призыв" },
        { 0x0041191E, 0x0052BFF0, (void*)&TG_FISHBOOK, "6176 книга рыбака" },
        { 0x004E1CB9, 0x004D61E0, (void*)&TG_XDRAG, "5288 предмет в окно обмена" },
        { 0x00517EC6, 0x004D61E0, (void*)&TG_AUCREG, "9901 выставление на аукцион" },
        { 0x004EDD35, 0x004D61E0, (void*)&TG_USE5450, "5450 применение" },
        { 0x004F32C0, 0x004D61E0, (void*)&TG_SUMMON2, "3540 призыв (ответ ретранслятора)" },
        { 0x004FF180, 0x004D61E0, (void*)&TG_UPG6504, "6504 улучшение" },
        { 0x0050115F, 0x004D61E0, (void*)&TG_RESET6506, "6506 сброс улучшения" },
        { 0x0045A49E, 0x004D61E0, (void*)&TG_PETLV1, "6148 питомец (1)" },
        { 0x0045A6D0, 0x004D61E0, (void*)&TG_PETLV2, "6148 питомец (2)" },
        { 0x00459DC8, 0x004D61E0, (void*)&TG_PETCNT, "6121 питомец" },
        { 0x0045524C, 0x004D61E0, (void*)&TG_INCUB, "6102 инкубатор" },
        { 0x004578BA, 0x004D61E0, (void*)&TG_PETCOND, "6108 питомец" },
        { 0x004F741D, 0x004D61E0, (void*)&TG_PGACHA, "6581 премиум-гача" },
        { 0x0055DA95, 0x004D61E0, (void*)&TG_RENAME, "6140 смена имени" },
        { 0x005370D0, 0x004D61E0, (void*)&TG_PSUM, "6555 премиум-сумма" },
        { 0x005347EE, 0x004D61E0, (void*)&TG_EXTRACT, "6549 извлечение" },
        { 0x00535A49, 0x004D61E0, (void*)&TG_BLESS, "6551 благословение" },
        { 0x005365DD, 0x004D61E0, (void*)&TG_OPTTR, "6553 перенос опции" },
        { 0x005141B9, 0x004D61E0, (void*)&TG_OPTEXT, "5433 извлечение опции" },
        { 0x00533378, 0x004D61E0, (void*)&TG_CASHKEY, "6540 сундук (ключ)" },
        { 0x0040A82C, 0x004D61E0, (void*)&TG_FLAG, "6524 герб" },
        { 0x00462B2C, 0x004D61E0, (void*)&TG_SQUAD, "6704 отряд" },
        { 0x004EC73C, 0x004D61E0, (void*)&TG_TRADE, "5475 обмен NPC" },
        { 0x0053E4B8, 0x00532B10, (void*)&TG_CRAFT, "6602 крафт: материал" },
        { 0x004F1771, 0x005646C0, (void*)&TG_AUTOUSE, "автоприменение sub_4F1550" },
    };

    // ── соседи (байты стока, на которые опираются смещения кадров) ──────────
    const BYTE kNbP1[]    = { 0x8B, 0x4D, 0xE4 };                                     // 0x534609 mov ecx,[ebp-1Ch]
    const BYTE kNbP1Rec[] = { 0x8B, 0x4D, 0x14, 0x89, 0x41, 0x09 };                   // 0x5345F0 mov ecx,[ebp+14h]; mov [ecx+9],eax
    const BYTE kNbA1a[]   = { 0x0F, 0xB6, 0x95, 0xE4, 0xFD, 0xFF, 0xFF };             // 0x4F8802 movzx edx,byte [ebp-21Ch]
    const BYTE kNbA1b[]   = { 0x0F, 0xB6, 0x95, 0x3A, 0xFE, 0xFF, 0xFF };             // 0x4F8B74 movzx edx,byte [ebp-1C6h] (count эха)
    const BYTE kNbA1c[]   = { 0x8D, 0x94, 0x0D, 0x51, 0xFE, 0xFF, 0xFF };             // 0x4F8CBB lea edx,[ebp+ecx-1AFh]
    const BYTE kNbA4[]    = { 0x8B, 0x55, 0x8A, 0x89, 0x55, 0xFC };                   // 0x55257B mov edx,[ebp-76h]; mov [ebp-4],edx (код)
    const BYTE kNbA5[]    = { 0x8B, 0x8D, 0xA4, 0xFE, 0xFF, 0xFF };                   // 0x515CEA mov ecx,[ebp-15Ch]
    const BYTE kNbA5w[]   = { 0x0F, 0xBF, 0x95, 0x5C, 0xFF, 0xFF, 0xFF };             // 0x515E82 movsx edx,word [ebp-0A4h]
    const BYTE kNbB1[]    = { 0x66, 0x89, 0x85, 0x2C, 0xFB, 0xFF, 0xFF };             // 0x45F0B7 mov [ebp-4D4h],ax
    const BYTE kNbB1rec[] = { 0x8D, 0x8D, 0x80, 0xFB, 0xFF, 0xFF };                   // 0x45F1C7 lea ecx,[ebp-480h]
    const BYTE kNbB4[]    = { 0x66, 0x89, 0x85, 0xEC, 0xFA, 0xFF, 0xFF };             // 0x505DC1 mov [ebp-514h],ax
    const BYTE kNbB4w[]   = { 0x66, 0x89, 0x85, 0xC7, 0xFC, 0xFF, 0xFF };             // 0x50683C mov [ebp-339h],ax (вес +23 после цикла)
    const BYTE kNbB5[]    = { 0x66, 0x89, 0x45, 0xB4 };                               // 0x51BB32 mov [ebp-4Ch],ax
    const BYTE kNbB5r[]   = { 0x03, 0x85, 0x9C, 0xF3, 0xFF, 0xFF };                   // 0x51DB81 add eax,[ebp-0C64h]
    const BYTE kNbB5d[]   = { 0x03, 0x85, 0xAC, 0xF6, 0xFF, 0xFF };                   // 0x520A49 add eax,[ebp-954h]
    const BYTE kNbB9[]    = { 0x8B, 0x8D, 0xD4, 0xFE, 0xFF, 0xFF };                   // 0x4FE6E8 mov ecx,[ebp-12Ch]
    const BYTE kNbB10[]   = { 0x66, 0x8B, 0x95, 0x70, 0xFE, 0xFF, 0xFF };             // 0x469348 mov dx,[ebp-190h]
    const BYTE kNbB10w[]  = { 0x66, 0x89, 0x95, 0x78, 0xFE, 0xFF, 0xFF };             // 0x46956F mov [ebp-188h],dx
    const BYTE kNbB11[]   = { 0x66, 0x8B, 0x8D, 0x38, 0xFE, 0xFF, 0xFF };             // 0x50B9B1 mov cx,[ebp-1C8h]
    const BYTE kNbB3[]    = { 0x8B, 0x8D, 0xEC, 0xFA, 0xFF, 0xFF };                   // 0x4E4DF8 mov ecx,[ebp-514h]
    const BYTE kNbGacha[] = { 0x8B, 0x8D, 0x2C, 0xFF, 0xFF, 0xFF };                   // 0x4F4F7B mov ecx,[ebp-0D4h] (площадка A2)
    const BYTE kNbGachaB[] = { 0x83, 0xE9, 0x01, 0x6B, 0xC9, 0x30 };                  // 0x4F4F81 sub ecx,1; imul ecx,ecx,30h
    const BYTE kNbGachaW[] = { 0x66, 0x89, 0x85, 0x94, 0xFE, 0xFF, 0xFF };            // 0x4F4F74 mov [ebp-16Ch],ax
    const BYTE kNbB6b[]   = { 0x0F, 0xB6, 0x4D, 0xAE };                               // 0x41354A movzx ecx,byte [ebp-52h] (результат БД)
    const BYTE kNbMove[]  = { 0x8D, 0x85, 0x78, 0xFF, 0xFF, 0xFF };                   // 0x4CE543 lea eax,[ebp-88h] (moveReq)
    const BYTE kNbMoveR[] = { 0xC6, 0x85, 0x70, 0xFE, 0xFF, 0xFF, 0x12 };             // 0x4CE56E mov byte [ebp-190h],12h (отказ 18)
    const BYTE kNbA3w[]   = { 0x66, 0x8B, 0x85, 0xE8, 0xFE, 0xFF, 0xFF };             // 0x534045 mov ax,[ebp-118h] (вес «установить»)
    const BYTE kNbCraft[] = { 0x89, 0x8D, 0xE0, 0xF7, 0xFF, 0xFF };                   // 0x53DBB5 mov [ebp-820h],ecx (this крафта)
    const BYTE kNbCraftR[] = { 0xC6, 0x85, 0xD0, 0xFD, 0xFF, 0xFF, 0x03 };            // 0x53E513 mov byte [ebp-230h],3 (отказ «не спецпредмет»)
    // FT+13 (5 чтений)
    const BYTE kFt4F4EA2[] = { 0x0F, 0xB6, 0x54, 0x01, 0x0D };
    const BYTE kFt515DC6[] = { 0x0F, 0xB6, 0x44, 0x0A, 0x0D };
    const BYTE kFt5345EB[] = { 0x0F, 0xB6, 0x44, 0x0A, 0x0D };
    const BYTE kFt5525F9[] = { 0x0F, 0xB6, 0x54, 0x01, 0x0D };
    const BYTE kFt55BD4B[] = { 0x0F, 0xB6, 0x44, 0x0A, 0x0D };

    // MD5 файла (hex, нижний регистр). false — файла нет / ошибка.
    bool FileMd5(const wchar_t* path, char out[33])
    {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return false; }
        BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hh = nullptr;
        bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, 0) == 0 && BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0) == 0;
        BYTE buf[65536]; DWORD rd = 0;
        while (ok && ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd) { ok = BCryptHashData(hh, buf, rd, 0) == 0; }
        BYTE dg[16] = {};
        if (ok) { ok = BCryptFinishHash(hh, dg, 16, 0) == 0; }
        if (hh) { BCryptDestroyHash(hh); }
        if (alg) { BCryptCloseAlgorithmProvider(alg, 0); }
        CloseHandle(h);
        for (int i = 0; ok && i < 16; ++i) { sprintf_s(out + 2 * i, 3, "%02x", dg[i]); }
        return ok;
    }

    // Чтение ConfigSet\charge_groups.txt и сверка ft_md5 с живой ItemTable_Info\Function_Table.txt. Пустая строка — успех.
    bool LoadTable(char* err, int cch)
    {
        wchar_t path[MAX_PATH], ftPath[MAX_PATH];
        wsprintfW(path, L"%sConfigSet\\charge_groups.txt", Config::BaseDir());
        wsprintfW(ftPath, L"%sItemTable_Info\\Function_Table.txt", Config::BaseDir());
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { _snprintf_s(err, cch, _TRUNCATE, "no ConfigSet\\charge_groups.txt"); return false; }
        const DWORD sz = GetFileSize(h, nullptr);
        char* t = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz + 1);
        DWORD rd = 0;
        if (!t || !ReadFile(h, t, sz, &rd, nullptr)) { CloseHandle(h); if (t) { HeapFree(GetProcessHeap(), 0, t); } _snprintf_s(err, cch, _TRUNCATE, "read error"); return false; }
        CloseHandle(h);
        t[rd] = 0;
        char want[40] = {}; int codes = 0, merge = 0, keys = 0;
        const char* hdr = strstr(t, "ft_md5=");
        if (!hdr || sscanf_s(hdr, "ft_md5=%32s codes=%d merge=%d keys=%d", want, (unsigned)sizeof(want), &codes, &merge, &keys) != 4)
        {
            HeapFree(GetProcessHeap(), 0, t); _snprintf_s(err, cch, _TRUNCATE, "bad header"); return false;
        }
        if (!FileMd5(ftPath, g_ftMd5)) { HeapFree(GetProcessHeap(), 0, t); _snprintf_s(err, cch, _TRUNCATE, "no ItemTable_Info\\Function_Table.txt"); return false; }
        if (_stricmp(want, g_ftMd5) != 0)
        {
            HeapFree(GetProcessHeap(), 0, t); _snprintf_s(err, cch, _TRUNCATE, "FT md5 %s != charge_groups ft_md5 %s", g_ftMd5, want); return false;
        }
        memset(g_row, 0, sizeof(g_row));
        int n = 0, nm = 0, nk = 0; int seenKey[256] = {};
        for (char* line = strchr(t, '\n'); line; line = strchr(line + 1, '\n'))
        {
            int c = 0, k = 0, ch = 0, m = 0, d = 0, b = 0;
            if (sscanf_s(line + 1, "%d\t%d\t%d\t%d\t%d\t%d", &c, &k, &ch, &m, &d, &b) != 6) { continue; }
            if (c < 1 || c > kMaxCode || ch < 0 || k < 0) { continue; }
            g_row[c].key = k; g_row[c].charges = ch; g_row[c].mode = m; g_row[c].days = d; g_row[c].bind = b;
            ++n;
            if (k > 0)
            {
                ++nm;
                bool seen = false; for (int i = 0; i < nk; ++i) { if (seenKey[i] == k) { seen = true; break; } }
                if (!seen && nk < 256) { seenKey[nk++] = k; }
            }
        }
        HeapFree(GetProcessHeap(), 0, t);
        if (n != codes || nm != merge || nk != keys || codes != kMaxCode)
        {
            _snprintf_s(err, cch, _TRUNCATE, "counts codes %d/%d merge %d/%d keys %d/%d", n, codes, nm, merge, nk, keys); return false;
        }
        g_stats.codes = n; g_stats.mergeCodes = nm; g_stats.keys = nk;
        return true;
    }

    // Запись в журнал «P100 выключен» (вид 157) — при старте.
    void NoteOff(const char* why)
    {
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P100 off: %s", why);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "P100 ChargeStack disabled (stock behavior): %s", why);
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kKindOff);
        e.opcode = 0; e.userNum = -1;
        AcJournal::CopyText(e, d);
        AcJournal::Push(e);
        __try { pSrvLog(g_logChannel, "%s", t); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

PatchResult P100_ChargeStack()
{
    g_enabled = false;
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_cap = Config::GetInt(kSec, L"Cap", 30000);
    if (g_cap < 1 || g_cap > 30000) { g_cap = 30000; }        // CRT_UPCheckItem / CRT_UPCraftEnter @iOldAmount — SMALLINT
    g_sites = (DWORD)Config::GetInt(kSec, L"Sites", -1);
    g_tradeMerge = Config::GetBool(kSec, L"TradeMerge", true);
    g_fixCharges = Config::GetBool(kSec, L"FixCharges", true);
    g_ttlSec = Config::GetInt(kSec, L"PendingTtlSec", 60);
    if (g_ttlSec < 5 || g_ttlSec > 3600) { g_ttlSec = 60; }
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 1);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 1; }
    g_echoAll = Config::GetBool(kSec, L"EchoAllCodes", true);
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }

    // ── таблица ключей и сверка FT ───────────────────────────────────────────
    char err[160] = {};
    g_tableOk = LoadTable(err, sizeof(err));
    if (!g_tableOk)
    {
        wchar_t w[200]; MultiByteToWideChar(CP_ACP, 0, err, -1, w, 200);
        Log::Line(L"    P100: ВЫКЛЮЧЕН (сток) — charge_groups: %s", w);
        NoteOff(err);
        return PatchResult::Mismatch;
    }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    BYTE callOrig[ARRAYSIZE(kCalls)][5];
    Site check[ARRAYSIZE(kCalls) + 40];
    int nc = 0;
    for (int i = 0; i < (int)ARRAYSIZE(kCalls); ++i)
    {
        callOrig[i][0] = 0xE8;
        *(int*)(callOrig[i] + 1) = (int)(kCalls[i].target - (kCalls[i].va + 5));
        check[nc++] = { kCalls[i].va, callOrig[i], 5 };
    }
    const Site extra[] =
    {
        { 0x00534609, kNbP1, sizeof(kNbP1) }, { 0x005345F0, kNbP1Rec, sizeof(kNbP1Rec) }, { 0x004F8802, kNbA1a, sizeof(kNbA1a) },
        { 0x004F8B74, kNbA1b, sizeof(kNbA1b) }, { 0x004F8CBB, kNbA1c, sizeof(kNbA1c) }, { 0x0055257B, kNbA4, sizeof(kNbA4) },
        { 0x00515CEA, kNbA5, sizeof(kNbA5) }, { 0x00515E82, kNbA5w, sizeof(kNbA5w) }, { 0x0045F0B7, kNbB1, sizeof(kNbB1) },
        { 0x0045F1C7, kNbB1rec, sizeof(kNbB1rec) }, { 0x00505DC1, kNbB4, sizeof(kNbB4) }, { 0x0050683C, kNbB4w, sizeof(kNbB4w) },
        { 0x0051BB32, kNbB5, sizeof(kNbB5) }, { 0x0051DB81, kNbB5r, sizeof(kNbB5r) }, { 0x00520A49, kNbB5d, sizeof(kNbB5d) },
        { 0x004FE6E8, kNbB9, sizeof(kNbB9) }, { 0x00469348, kNbB10, sizeof(kNbB10) }, { 0x0046956F, kNbB10w, sizeof(kNbB10w) },
        { 0x0050B9B1, kNbB11, sizeof(kNbB11) }, { 0x004E4DF8, kNbB3, sizeof(kNbB3) },
        { 0x004F4F7B, kNbGacha, sizeof(kNbGacha) }, { 0x004F4F81, kNbGachaB, sizeof(kNbGachaB) }, { 0x004F4F74, kNbGachaW, sizeof(kNbGachaW) },
        { 0x0041354A, kNbB6b, sizeof(kNbB6b) }, { 0x004CE543, kNbMove, sizeof(kNbMove) }, { 0x004CE56E, kNbMoveR, sizeof(kNbMoveR) },
        { 0x00534045, kNbA3w, sizeof(kNbA3w) }, { 0x0053DBB5, kNbCraft, sizeof(kNbCraft) }, { 0x0053E513, kNbCraftR, sizeof(kNbCraftR) },
        { 0x004F4EA2, kFt4F4EA2, sizeof(kFt4F4EA2) }, { 0x00515DC6, kFt515DC6, sizeof(kFt515DC6) }, { 0x005345EB, kFt5345EB, sizeof(kFt5345EB) },
        { 0x005525F9, kFt5525F9, sizeof(kFt5525F9) }, { 0x0055BD4B, kFt55BD4B, sizeof(kFt55BD4B) },
    };
    for (const Site& s : extra) { check[nc++] = s; }
    if (!VerifyAllSites(L"P100", check, nc)) { NoteOff("site bytes mismatch"); return PatchResult::Mismatch; }

    memset(g_pend, 0, sizeof(g_pend)); memset(g_ledger, 0, sizeof(g_ledger)); memset(g_chain, 0, sizeof(g_chain)); memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    bool ok = true;
    for (const CallSite& c : kCalls) { ok &= Hook::WriteCall(c.va, c.stub, 5); }
    ok &= Hook::WriteJmp(0x004F4EA2, (void*)&Ft_4F4EA2, 5);
    ok &= Hook::WriteJmp(0x00515DC6, (void*)&Ft_515DC6, 5);
    ok &= Hook::WriteJmp(0x005345EB, (void*)&Ft_5345EB, 5);
    ok &= Hook::WriteJmp(0x005525F9, (void*)&Ft_5525F9, 5);
    ok &= Hook::WriteJmp(0x0055BD4B, (void*)&Ft_55BD4B, 5);
    ok &= Hook::WriteJmp(0x004F4F7B, (void*)&St_Gacha, 6);
    if (!ok) { g_enabled = false; Log::Line(L"    P100: ошибка записи площадок"); return PatchResult::Failed; }

    wchar_t md[40]; MultiByteToWideChar(CP_ACP, 0, g_ftMd5, -1, md, 40);
    Log::Line(L"    P100: заряды спецпредметов складываются при получении — call-площадок %d, FT+13 5, гача 1; таблица %d кодов, "
              L"складываемых %d, ключей %d (FT %s); Cap %d, Sites 0x%08X, TradeMerge %d, FixCharges %d, накопитель %d с; "
              L"журнал ac.other 153–157 не чаще 1 раза в %d с, канал лога %d; 2604 — ячейка эха для всех кодов %d",
              (int)ARRAYSIZE(kCalls), g_stats.codes, g_stats.mergeCodes, g_stats.keys, md, g_cap, g_sites, g_tradeMerge ? 1 : 0,
              g_fixCharges ? 1 : 0, g_ttlSec, g_journalIntervalSec, g_logChannel, g_echoAll ? 1 : 0);
    return PatchResult::Applied;
}
