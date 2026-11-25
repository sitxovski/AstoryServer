// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P102 — [ИСПРАВЛЕНИЕ] ДЕФЕКТЫ ОРИГИНАЛА ВЫДАЧИ ПРЕДМЕТОВ (02.11.2026, решение владельца «дефекты оригинала исправляем»).
//  Разбор (фаза 1, стенды tools/stand_p102, MEMANTO p102-dll): Reports/item_dedup/charges; отчёт — DEPLOY_F1_P100.md §«после».
//
//  S1 (бит Sites 1) РАЗБОРКА 6502 Recv_User_Disassemble@0x4FD9B0, ветка размещения спецпредмета (sub_532B10), площадка 0x4FE76F:
//     сток `mov [ebp-123h],0` (запись +9) / `mov [ebp-17Ch],0` (количество в DB 2302 +71) — спецпредмет (камни 401/363 из ветки
//     «Updamage ≥ 88», GS:98329–98363, и любой F таблицы разборки) выдавался с Amount 0; вес шёл записью (+14), а @Weight (+73,
//     [ebp-98h]) оставался 0 — вес персонажа не рос, строка БД получала Weight 0. Ответ sub_4FE900 кладёт в память
//     Amount = запись +9 + тело +71, вес = запись +14 + тело +73 (GS:98575–98590), процедура UPItemDisassemble — INSERT
//     @Amount/@Weight или UPDATE +@Amount. Теперь: запись +9 = 0 (как сток), количество = заряды кода (P100_Charges — таблица
//     charge_groups, [ИСПРАВЛЕНИЕ 300]; без P100 — FT+13), @Weight = вес штуки (FT+4), запись +14 = 0. Память = БД.
//  S2 (бит 2) КНИГА РЫБАКА 6182 Recv_FishingBookReward@0x412D60, площадка 0x41344C `mov edx,[ebp-54h]; mov [ebp-0AAh],edx`:
//     в тело DB 2587 +14 (@Amount) сток кладёт количество позиции книги (+199 таблицы), а в память (запись sub_5340B0 [ebp-0A4h])
//     — заряды FT. Для спецпредмета теперь @Amount = заряды записи (+9). Прочие коды — как сток.
//  S3 (бит 4) ОТВЕТ КНИГИ sub_4134A0, площадка 0x413598 (общая точка ветки ошибки и успеха): при ошибке БД ([ebp-52h] == 0)
//     сток после отказа 6183 продолжал: sub_4D63F0 записывал пустую запись, книга из пустого эха (индекс −1) копировалась поверх
//     CUser+0x3F592…0x3F6C2 (очки рыбалки → 0, флаг «рыбачит»), уходил второй 6183 «успех». Теперь — выход на эпилог 0x413683.
//  S4 (бит 8) СНЯТИЕ ЛОТОВ 9910 recvTransActionDeleteItemRes@0x51EC90, площадка 0x51EE6B (до цикла лотов): в стоке предпроверки
//     вместимости нет — лот посреди цикла без ячейки → LABEL_67 (0x520571): предыдущие лоты уже в памяти, 2206 не ушёл.
//     Теперь до цикла считаются ячейки по правилам самого цикла (= предпроверка 9906): спецпредмет и «прочее» — сумка (за вычетом
//     слияний P100, P100_CountLotMerges), самоцвет / тип 4+36 (без стопки / колчан / нет стопки того же кода) — контейнер 2;
//     нехватка → [ebp-51h] = 3 (сумка) / 4 (контейнер 2), переход на 0x520571 — стоковый отказ ДО записи в память. Лот с кодом
//     ≤ 0 → код 1 (как цикл). Отказ оставляет лоты в ItemRelay так же, как любой стоковый отказ 9910.
//  S5 (бит 16) ВОСКРЕШЕНИЕ 5450 Char_FunctionItem_Use@0x4ED780, категория FT+8 = 48 (свитки 8/36/187/188/205–207/301/346/353/
//     394–396/508/553), площадка 0x4EDDE1 (после проверки отката, до уровней и 2140): сток шлёт 2140 в БД без проверки «мёртв»
//     (у 48 даже CharFlag пропущен), UPSkillItemSpend списывает заряд, а ответ sub_4EF270 (case 0x30, GS:92651) отказывает
//     «Not Dead» / «TargetNum Sync» ПОСЛЕ списания — память не уменьшается (память 5, БД 4…1). На последнем заряде БД (Tamount
//     памяти ≥ 2, Amount БД 1) процедура идёт веткой UPDATE: Amount = 0, @Ra < 1 → Flag 0 без отката — строка Amount 0
//     (живые 75209/10 и 75232/10, 205; FuncLog 20.10 20:41–20:44, 26.10 09:50). Теперь отказ ДО БД тем же кодом 0, если
//     персонаж жив (sub_4CB030), в целях есть чужой живой слот (0 ≠ себя или любой в 1…19 — ответ обошёл бы весь список и
//     отказал на нём) или прошлый запрос воскрешения этого слота моложе ReviveLatchMs (второй запрос до ответа на первый:
//     ответ отказал бы «Not Dead» после первого воскрешения — тоже после списания).
//  Ошибка P100 v57 на аукционе (общая цепочка afterSlot F-лота и лота экипировки) исправлена в P100: R_B5BUYEQ/R_B5DELEQ.
//  Журнал ac.other 164 (книга: ошибка БД — запись пропущена), 165 (9910: места нет — отказ до цикла), 166 (исключение — сток),
//  167 (воскрешение: жив / лишние цели — отказ до БД).
//  Ключи [P102_DefectFixes]: Enabled, Sites (маска 1|2|4|8|16, по умолчанию 31), ReviveLatchMs (3000), JournalIntervalSec, LogChannel.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P102_DefectFixes";   // секция patches.ini

    constexpr BYTE kKindBookDb  = 164;   // ac.other 164 — книга рыбака: ошибка БД, запись в CUser пропущена
    constexpr BYTE kKindLotRoom = 165;   // ac.other 165 — 9910: места нет, отказ до цикла лотов
    constexpr BYTE kKindFault   = 166;   // ac.other 166 — исключение, решение стока
    constexpr BYTE kKindRevive  = 167;   // ac.other 167 — воскрешение: жив / лишние цели, отказ до БД
    constexpr int  kKindBase = 164, kKindCount = 4;   // диапазон видов P102 для ограничителя

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kOffUserIndex = 0x174;       // учётка
    constexpr int   kOffName      = 0x178;       // имя персонажа cp1251
    constexpr int   kOffSlot      = 0x18C;       // слот персонажа
    constexpr int   kMaxUsers     = 0x226;       // 550 слотов
    constexpr DWORD kFuncTablePtr = 0x005F5E70;  // dword_5F5E70 → Function_Table, запись 48 б, индекс (код − 1)
    constexpr DWORD kFuncMaxPtr   = 0x005F5EA4;  // число кодов Function_Table
    constexpr int   kFuncRec = 48;               // шаг записи FT
    constexpr DWORD kItemTablePtr = 0x005F5E98;  // dword_5F5E98 → Item_Table, запись 71 б, индекс (код − 20551)
    constexpr int   kItemRec = 71, kItemBase = 20551;   // шаг и база Item_Table
    constexpr int   kRecAmount = 9, kRecWeight = 14;    // запись 57 б: +9 Amount i32, +14 вес i16
    constexpr int   kMaxLots = 10;               // лотов 9910 (Src[10] по 61 б)
    constexpr int   kCatRevive = 48;             // FT+8: воскрешение (ответ sub_4EF270 case 0x30)
    constexpr int   kMaxTargets = 20;            // целей 5450 (i16 с [ebp-1F1h])

    typedef BOOL (__cdecl *PFN_CodeIs)(int code);                                                          // sub_532B10 / AE0 / A90
    typedef int  (__fastcall *PFN_Count)(void* self, void* edx, int userNum, int plate);                   // sub_4D6A70 ret 8
    typedef int* (__fastcall *PFN_Same)(void* self, void* edx, int* out, int userNum, int plate, int code); // sub_4D6CE0 ret 10h
    typedef int  (__fastcall *PFN_Dead)(void* self, void* edx, int userNum);                               // sub_4CB030 ret 4
    typedef void (__cdecl *PFN_SrvLog)(int cat, const char* fmt, ...);                                     // sub_569DF0
    PFN_CodeIs const pIsF     = (PFN_CodeIs)0x00532B10;   // спецпредмет
    PFN_CodeIs const pIsSowel = (PFN_CodeIs)0x00532AE0;   // самоцвет
    PFN_CodeIs const pIsItem  = (PFN_CodeIs)0x00532A90;   // item_list
    PFN_Count  const pCount   = (PFN_Count)0x004D6A70;    // пустых ячеек контейнера
    PFN_Same   const pSame    = (PFN_Same)0x004D6CE0;     // ячейка того же кода в контейнере ([1] — слот, < 0 — нет)
    PFN_Dead   const pDead    = (PFN_Dead)0x004CB030;     // ≠ 0 — персонаж мёртв (CUser+0x4F; та же проверка, что в ответе)
    PFN_SrvLog const pSrvLog  = (PFN_SrvLog)Srv::kLog;    // стоковый лог

    // ── настройки ────────────────────────────────────────────────────────────
    bool  g_enabled = false;             // P102 стоит
    DWORD g_sites = 31;                  // маска площадок (1 разборка, 2 книга-количество, 4 книга-ошибка БД, 8 9910, 16 воскрешение)
    bool  g_disasmOn = false;            // площадка S1 стоит (P100 R_B9 берёт добавку отсюда)
    int   g_journalIntervalSec = 10;     // ограничитель журнала, с
    int   g_logChannel = 1;              // канал стокового лога

    P102_Stats g_stats = {};             // счётчики (экспорт P102_GetStats)

    int   g_reviveLatchMs = 3000;        // S5: окно «воскрешение в полёте» на слот, мс (0 — без замка)

    struct Sess { int userIndex; DWORD last[kKindCount]; int sup[kKindCount]; DWORD reviveTick; };
    Sess g_sess[kMaxUsers] = {};         // ограничитель по слотам
    CRITICAL_SECTION g_lock; bool g_lockReady = false;   // замок ограничителя

    // Строка FT кода (код проверен sub_532B10).
    const BYTE* FtRow(int code) { return *(const BYTE**)kFuncTablePtr + kFuncRec * (code - 1); }
    // Строка Item_Table кода (код проверен sub_532A90).
    const BYTE* ItemRow(int code) { return *(const BYTE**)kItemTablePtr + kItemRec * (code - kItemBase); }
    // Заряды выдачи кода: таблица P100 (i32, [ИСПРАВЛЕНИЕ 300]) или FT+13 (u8, сток).
    int ChargesOf(int code)
    {
        const int c = P100_Charges(code);
        if (c >= 0) { return c; }
        return (code >= 1 && code <= *(const int*)kFuncMaxPtr) ? (int)FtRow(code)[13] : 0;
    }

    // Пропуск по ограничителю; *supOut — подавлено с прошлой строки.
    bool Allow(int userNum, const BYTE* user, BYTE kind, int* supOut)
    {
        *supOut = 0;
        const int k = kind - kKindBase;
        if (userNum < 0 || userNum >= kMaxUsers || k < 0 || k >= kKindCount) { return true; }
        int ui = 0;
        __try { ui = user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { ui = 0; }
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool allow = true;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        if (g_journalIntervalSec > 0 && s.last[k] && now - s.last[k] < (DWORD)g_journalIntervalSec * 1000) { ++s.sup[k]; allow = false; }
        else { s.last[k] = now; *supOut = s.sup[k]; s.sup[k] = 0; }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        return allow;
    }

    // CUser слота (sub_5324A0: mgr+0x40+4·n).
    BYTE* UserOf(void* mgr, int userNum)
    {
        __try { return (mgr && userNum >= 0 && userNum < kMaxUsers) ? *(BYTE**)((BYTE*)mgr + 0x40 + 4 * userNum) : nullptr; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    // Строка стокового лога + ac.other (под ограничителем).
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
            pSrvLog(g_logChannel, "\tP102 DefectFixes\t%d\tUserNum %d\tUserIndex %d\tNick %s\t%s%s", opcode, userNum, ui, name, logText,
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

    // Исключение — вид 166, решение стока.
    void Fault(int opcode, int userNum, DWORD exc)
    {
        InterlockedIncrement(&g_stats.faults);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P102 %d exception 0x%08X -> stock", opcode, exc);
        Report(kKindFault, opcode, nullptr, userNum, opcode, (int)exc, AcJournal::kNone, d, "exception -> stock");
    }
}

// ── S1 разборка (стаб St_Disasm, вместо двух mov стока). Кадр Recv_User_Disassemble: запись v25 [ebp-12Ch], количество v13
//    [ebp-17Ch], @Weight v36 [ebp-98h] (i16). Площадку достигает только ветка «спецпредмет, ячейка выбрана». ──
extern "C" void __stdcall P102_OnDisasm(BYTE* ebp)
{
    BYTE* rec = ebp - 0x12C;
    *(int*)(rec + kRecAmount) = 0;   // замещённое стока: запись +9 = 0 (количество приходит телом +71)
    *(int*)(ebp - 0x17C) = 0;        // замещённое стока: количество (на исключении остаётся 0 — сток)
    DWORD exc = 0;
    __try
    {
        const int code = *(const int*)rec;
        if (!pIsF(code)) { return; }
        *(int*)(ebp - 0x17C) = ChargesOf(code);                                 // количество в БД = заряды кода
        *(short*)(ebp - 0x98) = *(const short*)(FtRow(code) + 4);               // @Weight = вес штуки (FT+4)
        *(short*)(rec + kRecWeight) = 0;                                        // вес записи — через @Weight (память += тело +73)
        InterlockedIncrement(&g_stats.disasmFixed);
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        *(int*)(ebp - 0x17C) = 0;
        Fault(6502, *(const short*)(ebp + 8), exc);
    }
}

// P100 R_B9: добавка разборки = заряды кода, когда стоит S1 (иначе 0 — сток).
extern "C" int __stdcall P102_DisasmAdd(int code)
{
    if (!g_enabled || !g_disasmOn) { return 0; }
    __try { return pIsF(code) ? ChargesOf(code) : 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// ── S2 книга рыбака, запрос (стаб St_BookReq вместо `mov edx,[ebp-54h]; mov [ebp-0AAh],edx`). Возврат — значение для edx. ──
extern "C" int __stdcall P102_OnBookReq(BYTE* ebp)
{
    int v = *(const int*)(ebp - 0x54);   // сток: количество позиции книги
    __try
    {
        const BYTE* rec = ebp - 0xA4;    // запись sub_5340B0 (a5)
        if (pIsF(*(const int*)rec))
        {
            v = *(const int*)(rec + kRecAmount);   // @Amount спецпредмета = заряды записи (добавка P100 / заряды выдачи)
            InterlockedIncrement(&g_stats.bookAmount);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = *(const int*)(ebp - 0x54); }
    *(int*)(ebp - 0xAA) = v;             // тело 2587 +14
    return v;
}

// ── S3 ответ книги: ошибка БД — строка журнала (выход на эпилог делает стаб). ──
extern "C" void __stdcall P102_OnBookDbError(BYTE* ebp, BYTE* self)
{
    InterlockedIncrement(&g_stats.bookDbError);
    __try
    {
        const int userNum = *(const short*)(ebp + 8);
        void* mgr = self ? *(void**)(*(BYTE**)self + 0x34) : nullptr;   // *(this->gap_0) + 52 → менеджер пользователей
        const BYTE* user = UserOf(mgr, userNum);
        const int book = *(const int*)(ebp - 0x4F);   // v11[9] — индекс книги
        Report(kKindBookDb, 6182, user, userNum, book, 0, AcJournal::kNone, "P102 6182 DB error -> no CUser write",
               "fishing book reward: DB error -> stock would write empty book over CUser (fishing points) and send 2nd 6183; skipped");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ── S4 9910 предпроверка (стаб St_Lots до цикла). 0 — продолжить сток; иначе код отказа (уже записан в [ebp-51h]). ──
extern "C" int __stdcall P102_OnLots(BYTE* ebp)
{
    InterlockedIncrement(&g_stats.lotChecks);
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        userNum = *(const short*)(ebp + 8);
        void* mgr = *(void**)(ebp - 0x918);   // this
        const int n = *(const int*)(ebp - 0x8D8);   // v33 — лотов
        if (n <= 0 || n > kMaxLots) { return 0; }
        int need1 = 0, need2 = 0;
        int fc[kMaxLots] = {}, fa[kMaxLots] = {}, nf = 0;
        int newStack[kMaxLots] = {}, nNew = 0;      // коды контейнера 2, под которые эта же выдача уже заводит стопку
        for (int j = 0; j < n; ++j)
        {
            const int code = *(const int*)(ebp - 0x2BD + 61 * j);
            const int amt  = *(const int*)(ebp - 0x2B9 + 61 * j);
            if (code <= 0) { *(ebp - 0x51) = 1; return 1; }   // как цикл: v49 = 1
            if (pIsF(code)) { ++need1; if (nf < kMaxLots) { fc[nf] = code; fa[nf] = amt; ++nf; } continue; }
            if (pIsSowel(code)) { ++need2; continue; }
            if (!pIsItem(code)) { continue; }
            const BYTE* row = ItemRow(code);
            if (row[7] == 4 && row[36] == 1)
            {
                if (!row[35] || row[26] == 10) { ++need2; continue; }   // нестопочный / колчан — новая ячейка контейнера 2
                bool counted = false;
                for (int k = 0; k < nNew; ++k) { if (newStack[k] == code) { counted = true; break; } }
                if (counted) { continue; }                              // стопку завела ранняя копия этой выдачи
                int out[2] = { 0, -1 };
                const int* r = pSame(mgr, nullptr, out, userNum, 2, code);
                if (!r || r[1] < 0) { ++need2; if (nNew < kMaxLots) { newStack[nNew++] = code; } }
                continue;
            }
            ++need1;   // «прочее» (экипировка) — сумка
        }
        const int merges = nf ? P100_CountLotMerges(mgr, userNum, fc, fa, nf, 15) : 0;
        const int free1 = pCount(mgr, nullptr, userNum, 1);
        const int free2 = pCount(mgr, nullptr, userNum, 2);
        int code = 0;
        if (free1 < need1 - merges) { code = 3; }
        else if (free2 < need2) { code = 4; }
        if (!code) { return 0; }
        InterlockedIncrement(&g_stats.lotRefused);
        *(ebp - 0x51) = (BYTE)code;
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P102 9910 lots %d need %d/%d free %d/%d merge %d -> %d", n, need1, need2, free1, free2, merges, code);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "auction withdraw 9910: %d lots need bag %d (-%d merge) / spend %d, free %d / %d -> refuse %d before loop",
                    n, need1, merges, need2, free1, free2, code);
        Report(kKindLotRoom, 9910, UserOf(mgr, userNum), userNum, n, need1 - merges, free1, d, t);
        return code;
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(9910, userNum, exc);
    }
    return 0;
}

// ── S5 5450 воскрешение (стаб St_Revive вместо `mov edx,[ebp-204h]`). Кадр Char_FunctionItem_Use: код ячейки v87 [ebp-204h],
//    this [ebp-2F8h], цели v88+15 [ebp-1F1h] (i16 ×20), код отказа v91 [ebp-121h]. 0 — продолжить сток; 1 — отказ (код 0 записан). ──
extern "C" int __stdcall P102_OnUseReq(BYTE* ebp)
{
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        const int code = *(const int*)(ebp - 0x204);
        if (code < 1 || code > *(const int*)kFuncMaxPtr || FtRow(code)[8] != kCatRevive) { return 0; }
        InterlockedIncrement(&g_stats.reviveChecks);
        userNum = *(const short*)(ebp + 8);
        void* mgr = *(void**)(ebp - 0x2F8);
        const BYTE* user = UserOf(mgr, userNum);
        if (!user) { return 0; }                                   // сток откажет сам (sub_5324A0 уже проверен выше)
        const bool dead = pDead(mgr, nullptr, userNum) != 0;
        int extra = -1;                                            // первая живая чужая цель: слот 0 ≠ себя или любой живой в 1…19
        const int t0 = *(const short*)(ebp - 0x1F1);              //   (ответ обходит все 20 и отказывает на ней ПОСЛЕ списания)
        if (t0 != userNum && UserOf(mgr, t0)) { extra = t0; }
        for (int j = 1; j < kMaxTargets && extra < 0; ++j)
        {
            const int t = *(const short*)(ebp - 0x1F1 + 2 * j);
            if (UserOf(mgr, t)) { extra = t; }
        }
        // замок «в полёте»: второй запрос до ответа на первый прошёл бы проверку (ещё мёртв), а ответ отказал бы после списания
        //   («Not Dead» после первого воскрешения). Окно g_reviveLatchMs от последнего пропущенного запроса этого слота.
        bool inflight = false;
        if (dead && extra < 0 && g_reviveLatchMs > 0)
        {
            int ui = 0;
            __try { ui = *(const int*)(user + kOffUserIndex); } __except (EXCEPTION_EXECUTE_HANDLER) { ui = 0; }
            DWORD now = GetTickCount();
            if (!now) { now = 1; }
            if (g_lockReady) { EnterCriticalSection(&g_lock); }
            Sess& s = g_sess[userNum];
            if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
            if (s.reviveTick && now - s.reviveTick < (DWORD)g_reviveLatchMs) { inflight = true; }
            else { s.reviveTick = now; }
            if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        }
        if (dead && extra < 0 && !inflight) { return 0; }
        InterlockedIncrement(&g_stats.reviveRefused);
        *(ebp - 0x121) = 0;                                        // тот же код, что USE_FAIL ответа (Error:0)
        const char* why = !dead ? "alive" : inflight ? "in flight" : "extra target";
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P102 5450 revive %d %s extra %d -> refuse", code, why, extra);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "revive item %d: %s, extra target %d -> refused before DB 2140 (stock spent a charge in DB, memory kept it)",
                    code, why, extra);
        Report(kKindRevive, 5450, user, userNum, code, dead ? (inflight ? 2 : 1) : 0, extra, d, t);
        return 1;
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(5450, userNum, exc);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P102_GetStats(P102_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // ── площадки: адрес, байты стока, продолжение; соседи кадра и смысла ──────
    //   S1 0x4FE76F: mov [ebp-123h],0 / mov [ebp-17Ch],0 → 0x4FE783
    const DWORD kS1 = 0x004FE76F; DWORD g_s1Back = 0x004FE783;
    const BYTE kS1Orig[20] = { 0xC7, 0x85, 0xDD, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x85, 0x84, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    const BYTE kS1Back[4]  = { 0x66, 0x8B, 0x55, 0x08 };                                             // 0x4FE783 mov dx,[ebp+8]
    const BYTE kS1Jne[6]   = { 0x83, 0xF8, 0xFF, 0x75, 0x42, 0x0F };                                 // 0x4FE728 cmp eax,-1; jne 0x4FE76F
    const BYTE kS1IsF[5]   = { 0xE8, 0x1C, 0x44, 0x03, 0x00 };                                       // 0x4FE6EF call sub_532B10
    const BYTE kS1Code[6]  = { 0x8B, 0x8D, 0xD4, 0xFE, 0xFF, 0xFF };                                 // 0x4FE6E8 mov ecx,[ebp-12Ch] (код)
    const BYTE kS1W[7]     = { 0x0F, 0xBF, 0x8D, 0x68, 0xFF, 0xFF, 0xFF };                           // 0x4FE7BE movsx ecx,word [ebp-98h] (v36)
    //   S2 0x41344C: mov edx,[ebp-54h]; mov [ebp-0AAh],edx → 0x413455
    const DWORD kS2 = 0x0041344C; DWORD g_s2Back = 0x00413455;
    const BYTE kS2Orig[9]  = { 0x8B, 0x55, 0xAC, 0x89, 0x95, 0x56, 0xFF, 0xFF, 0xFF };
    const BYTE kS2Back[7]  = { 0x66, 0x8B, 0x45, 0xA8, 0x66, 0x89, 0x85 };                           // 0x413455 mov ax,[ebp-58h]; mov [ebp-0A6h],ax
    const BYTE kS2Body[6]  = { 0x8D, 0x95, 0x48, 0xFF, 0xFF, 0xFF };                                 // 0x413465 lea edx,[ebp-0B8h] (тело 2587)
    const BYTE kS2Send[2]  = { 0x6A, 0x4D };                                                         // 0x41347A push 4Dh
    //   S3 0x413598: push 0; lea edx,[ebp-44h] → 0x41359D; ошибка [ebp-52h] == 0 → 0x413683
    const DWORD kS3 = 0x00413598; DWORD g_s3Back = 0x0041359D; DWORD g_s3Exit = 0x00413683;
    const BYTE kS3Orig[5]  = { 0x6A, 0x00, 0x8D, 0x55, 0xBC };
    const BYTE kS3Flag[9]  = { 0x0F, 0xB6, 0x4D, 0xAE, 0x85, 0xC9, 0x75, 0x46, 0x8B };               // 0x41354A movzx ecx,byte [ebp-52h]; test; jne 0x413598
    const BYTE kS3Fail[5]  = { 0xE8, 0x58, 0xF3, 0x0A, 0x00 };                                       // 0x413593 call sub_4C28F0 (отказ 6183)
    const BYTE kS3Exit[6]  = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD, 0xE8 };                                 // 0x413683 эпилог (cookie)
    const BYTE kS3Write[5] = { 0xE8, 0x3D, 0x2E, 0x0C, 0x00 };                                       // 0x4135AE call sub_4D63F0 (сток; P100 W_B6B ставит свою)
    //   S4 0x51EE6B: mov dword [ebp-8E0h],0 → 0x51EE75; отказ → 0x520571 (LABEL_67)
    const DWORD kS4 = 0x0051EE6B; DWORD g_s4Back = 0x0051EE75; DWORD g_s4Refuse = 0x00520571;
    const BYTE kS4Orig[10] = { 0xC7, 0x85, 0x20, 0xF7, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    const BYTE kS4Back[2]  = { 0xEB, 0x0F };                                                         // 0x51EE75 jmp 0x51EE86
    const BYTE kS4Err[7]   = { 0x0F, 0xB6, 0x8D, 0x42, 0xFD, 0xFF, 0xFF };                           // 0x51EE52 movzx ecx,byte [ebp-2BEh] (v47[0])
    const BYTE kS4Cnt[6]   = { 0x3B, 0x8D, 0x28, 0xF7, 0xFF, 0xFF };                                 // 0x51EE8C cmp ecx,[ebp-8D8h] (v33)
    const BYTE kS4Code[7]  = { 0x8B, 0x84, 0x15, 0x43, 0xFD, 0xFF, 0xFF };                           // 0x51EEA1 mov eax,[ebp+edx-2BDh] (код лота)
    const BYTE kS4Res[3]   = { 0x8A, 0x45, 0xAF };                                                   // 0x520571 mov al,[ebp-51h] (v49)
    //   S5 0x4EDDE1: mov edx,[ebp-204h] → 0x4EDDE7; отказ → 0x4EF0C3 (общий выход Char_FunctionItem_Use, 5451 с [ebp-121h])
    const DWORD kS5 = 0x004EDDE1; DWORD g_s5Back = 0x004EDDE7; DWORD g_s5Refuse = 0x004EF0C3;
    const BYTE kS5Orig[6]  = { 0x8B, 0x95, 0xFC, 0xFD, 0xFF, 0xFF };
    const BYTE kS5Back[6]  = { 0x83, 0xEA, 0x01, 0x6B, 0xD2, 0x30 };                                 // 0x4EDDE7 sub edx,1; imul edx,edx,30h
    const BYTE kS5Jne[2]   = { 0x75, 0x11 };                                                         // 0x4EDDCE jne 0x4EDDE1 (после отката 0x4F27F0)
    const BYTE kS5Res[7]   = { 0x0F, 0xB6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF };                           // 0x4EF0C3 movzx eax,byte [ebp-121h]
    const BYTE kS5Tgt[7]   = { 0x0F, 0xBF, 0x85, 0x0F, 0xFE, 0xFF, 0xFF };                           // 0x4EE6DF movsx eax,word [ebp-1F1h] (цель 0)
    const BYTE kS5This[6]  = { 0x8B, 0x8D, 0x08, 0xFD, 0xFF, 0xFF };                                 // 0x4EDDFC mov ecx,[ebp-2F8h] (this)
    const BYTE kS5Dead[3]  = { 0x8B, 0x51, 0x4F };                                                   // 0x4CB05D mov edx,[ecx+4Fh] (флаг «мёртв»)

    // S1: регистры и флаги целиком; две инструкции стока выполняет обработчик.
    __declspec(naked) void St_Disasm()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P102_OnDisasm
            popad
            popfd
            jmp   dword ptr [g_s1Back]              // 0x4FE783
        }
    }
    // S2: обработчик пишет тело +14 и возвращает значение edx (замещённое: edx = [ebp-54h] стока).
    __declspec(naked) void St_BookReq()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P102_OnBookReq
            mov   dword ptr [esp + 20], eax          // EDX в кадре pushad
            popad
            popfd
            jmp   dword ptr [g_s2Back]              // 0x413455
        }
    }
    // S3: ошибка БД ([ebp-52h] == 0) — журнал и эпилог; иначе замещённое `push 0; lea edx,[ebp-44h]`.
    __declspec(naked) void St_BookRes()
    {
        __asm
        {
            cmp   byte ptr [ebp - 52h], 0
            jne   ok
            pushfd
            pushad
            push  dword ptr [ebp - 1D8h]             // this (sub_4134A0)
            push  ebp
            call  P102_OnBookDbError
            popad
            popfd
            jmp   dword ptr [g_s3Exit]              // 0x413683
        ok:
            push  0
            lea   edx, [ebp - 44h]
            jmp   dword ptr [g_s3Back]              // 0x41359D
        }
    }
    // S4: 0 — замещённое `mov [ebp-8E0h],0` и цикл; иначе LABEL_67 (код в [ebp-51h] записал обработчик).
    __declspec(naked) void St_Lots()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P102_OnLots
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   dword ptr [ebp - 8E0h], 0
            jmp   dword ptr [g_s4Back]              // 0x51EE75
        refuse:
            popad
            popfd
            jmp   dword ptr [g_s4Refuse]            // 0x520571
        }
    }
    // S5: 0 — замещённое `mov edx,[ebp-204h]` и сток; иначе общий выход отказа (код 0 в [ebp-121h] записал обработчик).
    __declspec(naked) void St_Revive()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P102_OnUseReq
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   edx, dword ptr [ebp - 204h]
            jmp   dword ptr [g_s5Back]              // 0x4EDDE7
        refuse:
            popad
            popfd
            jmp   dword ptr [g_s5Refuse]            // 0x4EF0C3
        }
    }
}

PatchResult P102_DefectFixes()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_sites = (DWORD)Config::GetInt(kSec, L"Sites", 31) & 31u;
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 1);
    g_reviveLatchMs = Config::GetInt(kSec, L"ReviveLatchMs", 3000);
    if (g_reviveLatchMs < 0 || g_reviveLatchMs > 60000) { g_reviveLatchMs = 3000; }
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 1; }

    // ── сверка площадок и соседей ДО записи ─────────────────────────────────
    const Site check[] =
    {
        { kS1, kS1Orig, sizeof(kS1Orig) }, { g_s1Back, kS1Back, sizeof(kS1Back) }, { 0x004FE728, kS1Jne, sizeof(kS1Jne) },
        { 0x004FE6EF, kS1IsF, sizeof(kS1IsF) }, { 0x004FE6E8, kS1Code, sizeof(kS1Code) }, { 0x004FE7BE, kS1W, sizeof(kS1W) },
        { kS2, kS2Orig, sizeof(kS2Orig) }, { g_s2Back, kS2Back, sizeof(kS2Back) }, { 0x00413465, kS2Body, sizeof(kS2Body) },
        { 0x0041347A, kS2Send, sizeof(kS2Send) },
        { kS3, kS3Orig, sizeof(kS3Orig) }, { 0x0041354A, kS3Flag, sizeof(kS3Flag) }, { 0x00413593, kS3Fail, sizeof(kS3Fail) },
        { g_s3Exit, kS3Exit, sizeof(kS3Exit) },
        { kS4, kS4Orig, sizeof(kS4Orig) }, { g_s4Back, kS4Back, sizeof(kS4Back) }, { 0x0051EE52, kS4Err, sizeof(kS4Err) },
        { 0x0051EE8C, kS4Cnt, sizeof(kS4Cnt) }, { 0x0051EEA1, kS4Code, sizeof(kS4Code) }, { g_s4Refuse, kS4Res, sizeof(kS4Res) },
        { kS5, kS5Orig, sizeof(kS5Orig) }, { g_s5Back, kS5Back, sizeof(kS5Back) }, { 0x004EDDCE, kS5Jne, sizeof(kS5Jne) },
        { g_s5Refuse, kS5Res, sizeof(kS5Res) }, { 0x004EE6DF, kS5Tgt, sizeof(kS5Tgt) }, { 0x004EDDFC, kS5This, sizeof(kS5This) },
        { 0x004CB05D, kS5Dead, sizeof(kS5Dead) },
    };
    if (!VerifyAllSites(L"P102", check, ARRAYSIZE(check))) { g_enabled = false; return PatchResult::Mismatch; }
    (void)kS3Write;   // сосед 0x4135AE — площадка P100 (W_B6B); сверяет и ставит её P100

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    bool ok = true;
    if (g_sites & 1) { ok &= Hook::WriteJmp(kS1, (void*)&St_Disasm, sizeof(kS1Orig)); g_disasmOn = ok; }
    if (g_sites & 2) { ok &= Hook::WriteJmp(kS2, (void*)&St_BookReq, sizeof(kS2Orig)); }
    if (g_sites & 4) { ok &= Hook::WriteJmp(kS3, (void*)&St_BookRes, sizeof(kS3Orig)); }
    if (g_sites & 8) { ok &= Hook::WriteJmp(kS4, (void*)&St_Lots, sizeof(kS4Orig)); }
    if (g_sites & 16) { ok &= Hook::WriteJmp(kS5, (void*)&St_Revive, sizeof(kS5Orig)); }
    // частичный провал записи: уже стоящие площадки остаются, флаги отражают их (S1 — g_disasmOn, P100 R_B9 берёт добавку)
    if (!ok) { return PatchResult::Failed; }
    Log::Line(L"    P102: Sites 0x%X — разборка 0x4FE76F (заряды и @Weight спецпредмета), книга 0x41344C (@Amount = заряды) и 0x413598 "
              L"(ошибка БД — без записи в CUser), 9910 0x51EE6B (вместимость до цикла), воскрешение 5450 0x4EDDE1 (жив — отказ до БД); "
              L"журнал ac.other 164–167 не чаще 1 раза в %d с",
              g_sites, g_journalIntervalSec);
    return PatchResult::Applied;
}
