// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P98 — [ИСПРАВЛЕНИЕ] СТОПОЧНЫЙ ПРЕДМЕТ ИЗ ПРЕМИУМ-ПОЧТЫ ПРИХОДИТ С КОЛИЧЕСТВОМ 1 (волна bugs7, 30.10.2026).
//  Документ: AstoryServer/Docs/GameServer/premium-stack-amount-p98.md.
//
//  ── ДЕФЕКТ (11006 Recv_PremiumItemToInven_Req@0x4F8340, GameServer.c:95835) ──
//  Шаблон записи предмета (57 б, a5 = [ebp-5Fh], он же тело DB 2604 +13) строит sub_5340B0(this, userNum, код, a4 = 0, a5, 0, 0)
//  (GameServer.c:117645; дизасм 0x5343C2…0x53449A). Для стопочного предмета item_list (контейнер 2: +36 != 3 и тип +26 вне
//  {0,1,2,3,4,8,9,12,13,14,15}; +35 «стопка» != 0) sub_5340B0 ищет стопку того же кода в контейнере 2 (sub_4D6CE0):
//    найдена → шаблон +9 (Amount) = её количество N, +14 (вес) = её вес, +5 = её слот;
//    нет     → +9 = 0, +14 = 0, +5 = свободный слот;
//  затем +9 += a4, +14 += a4 · вес штуки (+5 строки Item_Table). Функция рассчитана на ДОБАВЛЕНИЕ a4 штук к стопке (так её зовут
//  рыбалка/ремесло с a4 = 1), а премиум-почта зовёт её с a4 = 0 и кладёт шаблон как НОВУЮ запись в каждую из Count свободных
//  ячеек (sub_4D6740) → DB 2604 → UPCashitemToinvenFunctional (@Amount = шаблон +9, @Weight = +14, INSERT на каждую ячейку) →
//  ответ sub_4F89D0@0x4F89D0 копирует тот же шаблон в память персонажа. Итог:
//    (1) новая стопка — Amount 0: предмет нерабочий (знак охоты 75521: нумпад «Все» = 0, сдача 6150 → код 6; свитки 20936/
//        20946/20952/23229 у 8 игроков; joylog1.dbo.CashBuyFunctional: 46 из 48 стопочных доставок с Ramount 0);
//    (2) ДЮП — при наличии стопки N новая запись получает Amount N (и вес стопки).
//
//  ── ЧТО ДЕЛАЕТ P98 (одна площадка, трамплин; протокол не меняется) ──
//  S1 11006 @0x4F8636 `mov ecx,[ebp-220h]` — цель `je` после `cmp [ebp-228h],1` (sub_5340B0 вернула 1, шаблон готов; ни одна
//     ячейка ещё не выбрана, ничего не отправлено). P98_OnPremium(ebp): если код — item_list, шаблон в контейнере 2, строка
//     Item_Table +35 != 0 и тип +26 != 10 (колчаны/наживка — своя логика количества, не трогаем), то шаблон +9 := 1,
//     +14 := вес одной штуки (+5). Каждая ячейка доставки — отдельная стопка из 1 шт. (Count ячеек = Count штук, как задумано
//     стоком: по ячейке на штуку). Это же закрывает дюп. Журнал ac.other 150 (было 0 → 1) / 151 (шаблон скопировал стопку N →
//     1, дюп) / 152 (исключение — решение стока). Нестопочные (Amount 0 у них штатный), контейнер 1, самоцветы, особые — как сток.
//  Второй путь того же шаблона — наш P16 (GachaPrizeToInven, DB 2601, сейчас Enabled=0): зовёт P98_FixPremiumRecord сразу
//  после своего sub_5340B0. Другие вызовы sub_5340B0 с a4 = 0 (Recv_UserPrimiumGaChaReward — только +36 == 3, контейнер 1;
//  Recv_UserPrimiumSum — награды PrimiumSumTable нестопочные) дефекта не дают — разбор в документе.
//  Кадр 11006: this = [ebp-238h], pUser = [ebp-218h], v36 = [ebp-224h] (+0 Order, +4 код, +8 Count u8, +9 BuyType u8),
//  шаблон a5 = [ebp-5Fh] (тело 2604 v41 = [ebp-6Ch], +13), userNum = [ebp+8].
//  Ключи [P98_PremiumStackAmount]: Enabled (0 — площадка не ставится, сток), JournalIntervalSec, LogChannel.
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
    const wchar_t* kSec = L"P98_PremiumStackAmount";   // секция patches.ini

    constexpr BYTE kKindNew    = 150;   // ac.other 150 — стопка из премиум-почты: Amount 0 → 1
    constexpr BYTE kKindCopied = 151;   // ac.other 151 — шаблон скопировал существующую стопку N → 1 (дюп)
    constexpr BYTE kKindFault  = 152;   // ac.other 152 — исключение при сверке, решение стока
    constexpr int  kKindBase = 150, kKindCount = 3;   // диапазон видов P98 для ограничителя

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kOffUserIndex = 0x174;       // учётка (sub_5324F0)
    constexpr int   kOffName      = 0x178;       // имя персонажа cp1251
    constexpr int   kOffSlot      = 0x18C;       // слот персонажа
    constexpr int   kMaxUsers     = 0x226;       // 550 слотов (sub_5328F0)
    constexpr DWORD kItemTablePtr = 0x005F5E98;  // dword_5F5E98 → Item_Table, запись 71 б, индекс (код − 20551)
    constexpr int   kItemRec = 71, kItemBase = 20551;   // шаг записи и база кода Item_Table
    constexpr int   kRowWeight = 5, kRowType = 26, kRowStack = 35;   // +5 вес штуки (i16), +26 тип, +35 «стопка»
    constexpr int   kRecCont = 4, kRecAmount = 9, kRecWeight = 14;    // шаблон 57 б: +4 контейнер, +9 Amount i32, +14 вес u16
    constexpr int   kTypeQuiver = 10;            // тип 10 — колчаны/наживка (своя логика количества)
    constexpr int   kOpPremium = 11006, kOpP16 = 2601;   // опкоды путей: 11006 (сток), 2601 (ответ БД, путь P16)

    typedef BOOL (__cdecl *PFN_CodeIs)(int code);                         // sub_532A90 — предмет item_list 20551…dword_5F5EAC
    typedef void (__cdecl *PFN_SrvLog)(int cat, const char* fmt, ...);    // sub_569DF0
    PFN_CodeIs const pIsItem = (PFN_CodeIs)0x00532A90;                    // проверка кода item_list
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)Srv::kLog;                     // стоковый лог

    // ── настройки ────────────────────────────────────────────────────────────
    bool g_enabled = false;              // площадка стоит и решения принимаются
    int  g_journalIntervalSec = 10;      // ограничитель журнала, с
    int  g_logChannel = 38;              // 38 = Log_MGamePremium (MoveToInven_<дата>.txt, рядом со строками стока)

    P98_Stats g_stats = {};              // счётчики (экспорт P98_GetStats)

    // Ограничитель: одна строка на (слот, вид) за JournalIntervalSec; смена учётки в слоте — заново.
    struct Sess { int userIndex; DWORD last[kKindCount]; int sup[kKindCount]; };
    Sess g_sess[kMaxUsers] = {};         // состояние ограничителя по слотам
    CRITICAL_SECTION g_lock; bool g_lockReady = false;   // замок ограничителя

    // Строка Item_Table по коду (код уже проверен sub_532A90).
    const BYTE* ItemRow(int code) { return *(const BYTE**)kItemTablePtr + kItemRec * (code - kItemBase); }

    // Пропуск по ограничителю; *supOut — сколько строк этого вида подавлено с прошлой.
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
            pSrvLog(g_logChannel, "\tP98 PremiumStackAmount\t%d\tUserNum %d\tUserIndex %d\tNick %s\t%s%s", opcode, userNum, ui, name, logText,
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

    // CUser слота (sub_5324A0: mgr+0x40+4·n).
    BYTE* UserOf(void* mgr, int userNum)
    {
        __try { return (mgr && userNum >= 0 && userNum < kMaxUsers) ? *(BYTE**)((BYTE*)mgr + 0x40 + 4 * userNum) : nullptr; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    // Приведение шаблона. 0 — не стопка ветки «расходник» (или уже 1 шт. с весом штуки), 1 — было 0 → 1, 2 — копия стопки N → 1.
    int FixRecord(int opcode, const BYTE* user, int userNum, int code, BYTE* rec, int count)
    {
        if (!pIsItem(code) || *(const int*)rec != code) { InterlockedIncrement(&g_stats.notStack); return 0; }
        const BYTE* row = ItemRow(code);
        if (rec[kRecCont] != 2 || row[kRowStack] == 0 || row[kRowType] == kTypeQuiver) { InterlockedIncrement(&g_stats.notStack); return 0; }
        const int  oldAmt = *(const int*)(rec + kRecAmount);
        const WORD oldW   = *(const WORD*)(rec + kRecWeight);
        const WORD unit   = *(const WORD*)(row + kRowWeight);
        if (oldAmt == 1 && oldW == unit) { InterlockedIncrement(&g_stats.alreadyOne); return 0; }
        *(int*)(rec + kRecAmount)  = 1;
        *(WORD*)(rec + kRecWeight) = unit;
        const bool copied = oldAmt > 0;
        InterlockedIncrement(copied ? &g_stats.fixedCopied : &g_stats.fixedNew);
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P98 %d code %d amt %d w %u -> 1/%u x%d", opcode, code, oldAmt, (unsigned)oldW, (unsigned)unit, count);
        if (copied)
        {
            _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d: template copied existing stack Amount %d Weight %u -> Amount 1 Weight %u, cells %d (dupe closed)",
                        code, oldAmt, (unsigned)oldW, (unsigned)unit, count);
        }
        else
        {
            _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d: new stack Amount %d Weight %u -> Amount 1 Weight %u, cells %d",
                        code, oldAmt, (unsigned)oldW, (unsigned)unit, count);
        }
        Report(copied ? kKindCopied : kKindNew, opcode, user, userNum, code, oldAmt, count, d, t);
        return copied ? 2 : 1;
    }

    // Исключение при сверке — вид 152, шаблон остаётся как у стока.
    void Fault(int opcode, int userNum, DWORD exc)
    {
        InterlockedIncrement(&g_stats.faults);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P98 %d exception 0x%08X -> stock", opcode, exc);
        Report(kKindFault, opcode, nullptr, userNum, opcode, (int)exc, AcJournal::kNone, d, "exception in check -> stock template");
    }
}

// ── S1 11006 (вызывается стабом St_Premium). Шаблон [ebp-5Fh] приводится на месте; возврат в сток всегда. ──
extern "C" void __stdcall P98_OnPremium(BYTE* ebp)
{
    if (!g_enabled) { return; }
    InterlockedIncrement(&g_stats.checks);
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        userNum = *(const short*)(ebp + 8);
        const BYTE* user = *(BYTE**)(ebp - 0x218);               // v37 = sub_5324A0(…) (сток проверил: не null)
        const int code = *(const int*)(ebp - 0x220);             // v36[1] — код предмета запроса
        const int count = *(const BYTE*)(ebp - 0x21C);           // LOBYTE(v36[2]) — число ячеек
        FixRecord(kOpPremium, user, userNum, code, ebp - 0x5F, count);
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(kOpPremium, userNum, exc);
    }
}

// ── путь P16 (GachaPrizeToInven, ответ БД 2601): тот же шаблон сразу после sub_5340B0 == 1. 1/2 — приведён, 0 — нет. ──
extern "C" __declspec(dllexport) int __stdcall P98_FixPremiumRecord(void* mgr, int userNum, int code, BYTE* rec, int count)
{
    if (!g_enabled || !rec) { return 0; }
    InterlockedIncrement(&g_stats.checks);
    InterlockedIncrement(&g_stats.viaP16);
    DWORD exc = 0;
    __try
    {
        return FixRecord(kOpP16, UserOf(mgr, userNum), userNum, code, rec, count);
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(kOpP16, userNum, exc);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P98_GetStats(P98_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // ── площадка: адрес, байты стока, продолжение; соседи кадра и смысла ──────
    //   S1 Recv_PremiumItemToInven_Req: mov ecx, dword ptr [ebp-220h] (цель je «sub_5340B0 == 1») → 0x4F863C
    const DWORD kSite = 0x004F8636; const BYTE kSiteOrig[6] = { 0x8B, 0x8D, 0xE0, 0xFD, 0xFF, 0xFF };
    DWORD g_back = 0x004F863C;                                                                        // продолжение стока
    const BYTE kBackOrig[6]  = { 0x51, 0xE8, 0x4E, 0xA4, 0x03, 0x00 };                               // push ecx; call sub_532A90
    const BYTE kJeOrig[13]   = { 0x83, 0xBD, 0xD8, 0xFD, 0xFF, 0xFF, 0x01, 0x0F, 0x84, 0x8D, 0x00, 0x00, 0x00 }; // 0x4F859C cmp [ebp-228h],1; je 0x4F8636
    const BYTE kCallBuild[5] = { 0xE8, 0x1A, 0xBB, 0x03, 0x00 };                                     // 0x4F8591 call sub_5340B0
    const BYTE kArgs[17]     = { 0x6A, 0x00, 0x6A, 0x00, 0x8D, 0x4D, 0xA1, 0x51, 0x6A, 0x00,          // 0x4F8575 push 0; push 0; lea ecx,[ebp-5Fh]; push ecx;
                                 0x8B, 0x95, 0xE0, 0xFD, 0xFF, 0xFF, 0x52 };                         //          push 0 (a4); mov edx,[ebp-220h]; push edx
    const BYTE kThisRd[6]    = { 0x8B, 0x8D, 0xC8, 0xFD, 0xFF, 0xFF };                               // 0x4F858B mov ecx,[ebp-238h] (this)
    const BYTE kThisWr[6]    = { 0x89, 0x8D, 0xC8, 0xFD, 0xFF, 0xFF };                               // 0x4F836B mov [ebp-238h],ecx
    const BYTE kV36[6]       = { 0x8D, 0x8D, 0xDC, 0xFD, 0xFF, 0xFF };                               // 0x4F846A lea ecx,[ebp-224h] (v36 ← тело +33)
    const BYTE kUserWr[6]    = { 0x89, 0x85, 0xE8, 0xFD, 0xFF, 0xFF };                               // 0x4F8499 mov [ebp-218h],eax (pUser)
    const BYTE kCountRd[7]   = { 0x0F, 0xB6, 0x95, 0xE4, 0xFD, 0xFF, 0xFF };                         // 0x4F8802 movzx edx,byte [ebp-21Ch] (Count)
    const BYTE kContRd[5]    = { 0x66, 0x0F, 0xB6, 0x4D, 0xA5 };                                     // 0x4F881D movzx cx,byte [ebp-5Bh] (шаблон +4)
    const BYTE kBody[3]      = { 0x8D, 0x4D, 0x94 };                                                 // 0x4F8957 lea ecx,[ebp-6Ch] (тело 2604)
    const BYTE kSend2604[7]  = { 0x6A, 0x57, 0x68, 0x2C, 0x0A, 0x00, 0x00 };                         // 0x4F896A push 57h; push 0A2Ch
    //   sub_5340B0 (смысл ветки «стопка»): +35, запись +9, прибавка a4
    const BYTE kFnBuild[6]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C };                               // 0x5340B0 пролог
    const BYTE kBuildStk[5]  = { 0x0F, 0xB6, 0x4C, 0x10, 0x23 };                                     // 0x5343DA movzx ecx,byte [eax+edx+23h] (+35)
    const BYTE kBuildAmt[3]  = { 0x89, 0x51, 0x09 };                                                 // 0x534453 mov [ecx+9],edx (Amount стопки/0)
    const BYTE kBuildAdd[3]  = { 0x03, 0x45, 0x10 };                                                 // 0x534467 add eax,[ebp+10h] (+= a4)
    const BYTE kFnItem[10]   = { 0x55, 0x8B, 0xEC, 0x81, 0x7D, 0x08, 0x47, 0x50, 0x00, 0x00 };       // sub_532A90 cmp [ebp+8],5047h

    // Стаб. Вход jmp с площадки; регистры и флаги сохраняются целиком; на продолжении — замещённая инструкция стока.
    __declspec(naked) void St_Premium()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P98_OnPremium
            popad
            popfd
            mov   ecx, dword ptr [ebp-220h]         // замещённое: код предмета
            jmp   dword ptr [g_back]                // 0x4F863C
        }
    }
}

PatchResult P98_PremiumStackAmount()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 38);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 38; }

    // ── сверка площадки и соседей ДО записи ─────────────────────────────────
    const Site check[] =
    {
        { kSite, kSiteOrig, sizeof(kSiteOrig) }, { g_back, kBackOrig, sizeof(kBackOrig) }, { 0x004F859C, kJeOrig, sizeof(kJeOrig) },
        { 0x004F8591, kCallBuild, sizeof(kCallBuild) }, { 0x004F8575, kArgs, sizeof(kArgs) }, { 0x004F858B, kThisRd, sizeof(kThisRd) },
        { 0x004F836B, kThisWr, sizeof(kThisWr) }, { 0x004F846A, kV36, sizeof(kV36) }, { 0x004F8499, kUserWr, sizeof(kUserWr) },
        { 0x004F8802, kCountRd, sizeof(kCountRd) }, { 0x004F881D, kContRd, sizeof(kContRd) }, { 0x004F8957, kBody, sizeof(kBody) },
        { 0x004F896A, kSend2604, sizeof(kSend2604) },
        { 0x005340B0, kFnBuild, sizeof(kFnBuild) }, { 0x005343DA, kBuildStk, sizeof(kBuildStk) }, { 0x00534453, kBuildAmt, sizeof(kBuildAmt) },
        { 0x00534467, kBuildAdd, sizeof(kBuildAdd) }, { 0x00532A90, kFnItem, sizeof(kFnItem) },
    };
    if (!VerifyAllSites(L"P98", check, ARRAYSIZE(check))) { g_enabled = false; return PatchResult::Mismatch; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    if (!Hook::WriteJmp(kSite, (void*)&St_Premium, sizeof(kSiteOrig))) { g_enabled = false; return PatchResult::Failed; }
    Log::Line(L"    P98: премиум-почта 11006 @0x%08X — стопочный предмет (контейнер 2, Item_Table +35, тип != 10): Amount := 1, вес := вес "
              L"штуки (сток: 0 или копия стопки — дюп); путь P16 — P98_FixPremiumRecord; журнал ac.other 150–152 не чаще 1 раза в %d с, "
              L"канал лога %d", kSite, g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
