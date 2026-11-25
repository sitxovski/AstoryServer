// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P111 — [ИСПРАВЛЕНИЕ] ДОБАВКА ВЫЛУПЛЕНИЯ ДАЁТ ОБЕЩАННЫЕ +30%; В ЯЧЕЙКУ ДОБАВКИ — ТОЛЬКО ДОБАВКА (05.11.2026, сессия pet-hatch-summon;
//  жалоба игрока «Pet Hatching Supplement не работает: 3 яйца, 3 провала»). Документ: AstoryServer/Docs/GameServer/hatch-supplement-p111.md.
//
//  ── ПОТОК (GameServer e7b4ac38 = Indun = Ch2 = сток, функция побайтно равна; декомпил GameServer.c:34503, дизасм 0x454F70) ──
//  6102 → Recv_IncubatorReq: слот 1 — катализатор (подтип 107, значение v8 — проценты к базе), слот 2 — яйцо (подтип 109), слот 3 —
//  необязательная добавка (значение v13, ПОДТИП НЕ ПРОВЕРЯЕТСЯ). Шанс в единицах 1/100000:
//      v15 = база + база·v8/100 + v13;  успех, если v15 > rand(0…100000)  → 2275 в БД (UPPetHatch), ответ 6103 код 1 / 9.
//  База: обычное яйцо (Function_Table) 100000; яйцо из item_table — PetIncubateRate_Table[грейд] (20000/15000/10000/5000, грейд 8 — 100000).
//
//  ── ДЕФЕКТ (оригинала: код и данные стока те же) ──
//  Добавка 298/322/323/324 — значение 30, подсказка оригинала «[Pet hatching probability + 30% additional probability]». Таблица шансов —
//  в стотысячных (20000 = 20%), а значение прибавляется как есть: 30 = +0,03 п.п. Масштаб доказан самими данными оригинала: запись 429
//  того же подтипа 108 (сток и живой сервер, без имени и подсказки) имеет значение 30000 = +30 п.п. — то есть «30» у продаваемых
//  предметов — ошибка данных. Журнал dev 19.10–03.11: с добавкой 0 успехов из 12 (ожидание 3,2), без неё 5 из 19 (ожидание 4,9).
//  Подтип слота 3 не сверяется: подделанный клиент кладёт туда любой предмет, и его поле значения идёт в шанс (у спец-предмета — dword).
//
//  ── ЧТО ДЕЛАЕТ P111 (6 байт, протокол не меняется: тот же 6103, код 5 — штатный отказ стока «ошибка вспомогательного средства») ──
//  Площадка 0x4556C3 (fild [ebp-84h] — начало формулы, сюда сходятся все ветки разбора слота 3) → трамплин:
//  P111_Apply(CUser [ebp-0E8h], код слота 3 [ebp-0E0h], &значение [ebp-8Ch], база [ebp-84h], катализатор [ebp-0E4h], userNum [ebp+8]).
//    • слота 3 нет (код ≤ 0) — сток;
//    • подтип ≠ SupplementSubType (108) и RequireSubType=1 — отказ: переход на стоковый блок кода 5 (0x455699: 6103 и выход);
//    • подтип 108, значение меньше PercentBelow (1000: записано в процентах) — × SupplementScale (1000: 30 → 30000 = +30 п.п.), не больше
//      100000; значение от порога (запись 429) — уже в стотысячных, как есть.
//  Пропуск — вытесненный fild и 0x4556C9. Mode=1 — решение; Mode=0 — только журнал (сток). Журнал ac.other 174 (чужой подтип), 175
//  (исключение — сток), 176 (добавка применена: итоговый шанс); ограничитель JournalIntervalSec на (слот, вид).
//  Откат: patches.ini [P111_HatchSupplement] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"P111_HatchSupplement";             // секция patches.ini

    // ── площадка: начало формулы шанса Recv_IncubatorReq ──────────────────────
    constexpr DWORD kSite    = 0x004556C3;                     // fild dword ptr [ebp-84h]
    constexpr DWORD kSiteLen = 6;                              // jmp rel32 + 1 nop
    const BYTE kSiteOrig[kSiteLen] = { 0xDB, 0x85, 0x7C, 0xFF, 0xFF, 0xFF };
    constexpr DWORD kBack = 0x004556C9;                        // mov edx,[ebp-84h] — продолжение формулы стока
    const BYTE kBackOrig[6] = { 0x8B, 0x95, 0x7C, 0xFF, 0xFF, 0xFF };

    // ── стоковый блок отказа кода 5 (0x455699): mov [ebp-70h],5 ; 6103 ; jmp выход ──
    constexpr DWORD kRefuse = 0x00455699;
    const BYTE kRefuseOrig[42] =
    {
        0xC6, 0x45, 0x90, 0x05, 0x6A, 0x01, 0x6A, 0xFF, 0x8D, 0x55, 0x8C, 0x52, 0x66, 0x8B, 0x45, 0x08,
        0x50, 0x6A, 0x12, 0x68, 0xD7, 0x17, 0x00, 0x00, 0x8B, 0x8D, 0x08, 0xFF, 0xFF, 0xFF, 0x8B, 0x09,
        0xE8, 0x32, 0xD2, 0x06, 0x00, 0xE9, 0x86, 0x01, 0x00, 0x00
    };

    // ── сосед: чтение значения слота 3 (0x455638…0x455697) — сверка кадра [ebp-0E0h]/[ebp-8Ch] и полей таблиц ──
    constexpr DWORD kReadSlot3 = 0x00455638;
    const BYTE kReadSlot3Orig[97] =
    {
        0x89, 0x95, 0x20, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF0, 0x50, 0xE8, 0x49, 0xD4, 0x0D, 0x00, 0x83,
        0xC4, 0x04, 0x83, 0xF8, 0x01, 0x75, 0x1E, 0x8B, 0x4D, 0xF0, 0x81, 0xE9, 0x47, 0x50, 0x00, 0x00,
        0x6B, 0xC9, 0x47, 0x8B, 0x15, 0x98, 0x5E, 0x5F, 0x00, 0x8B, 0x44, 0x0A, 0x0E, 0x89, 0x85, 0x74,
        0xFF, 0xFF, 0xFF, 0xEB, 0x56, 0x8B, 0x4D, 0xF0, 0x51, 0xE8, 0x9A, 0xD4, 0x0D, 0x00, 0x83, 0xC4,
        0x04, 0x83, 0xF8, 0x01, 0x75, 0x1B, 0x8B, 0x55, 0xF0, 0x83, 0xEA, 0x01, 0x6B, 0xD2, 0x30, 0xA1,
        0x70, 0x5E, 0x5F, 0x00, 0x0F, 0xBF, 0x4C, 0x10, 0x09, 0x89, 0x8D, 0x74, 0xFF, 0xFF, 0xFF, 0xEB,
        0x2A
    };

    // ── данные GameServer ──────────────────────────────────────────────────────
    constexpr DWORD kSpecialTbl  = 0x005F5E98;                 // dword_5F5E98 — item_table, записи 71 б, коды от 20551
    constexpr DWORD kSpecialMax  = 0x005F5EAC;                 // dword_5F5EAC — наибольший код item_table
    constexpr int   kSpecialFrom = 20551;                      // первый код item_table
    constexpr int   kSpecialRec  = 71;                         // шаг записи item_table
    constexpr int   kSpecialSub  = 27;                         // запись item_table: подтип
    constexpr DWORD kFuncTbl     = 0x005F5E70;                 // dword_5F5E70 — Function_Table, записи 48 б, коды от 1
    constexpr DWORD kFuncMax     = 0x005F5EA4;                 // dword_5F5EA4 — наибольший код Function_Table
    constexpr int   kFuncRec     = 48;                         // шаг записи Function_Table
    constexpr int   kFuncSub     = 8;                          // запись Function_Table: подтип
    constexpr int   kOffUserIdx  = 0x174;                      // CUser: UserIndex (учётка)
    constexpr int   kOffCharSlot = 0x18C;                      // CUser: слот персонажа
    constexpr int   kOpHatch     = 6102;                       // опкод запроса (для журнала)
    constexpr int   kChanceFull  = 100000;                     // шанс 100% в единицах формулы
    constexpr int   kRefuseCode  = 5;                          // код 6103 блока отказа

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1; P111 — 174–176).
    constexpr BYTE kKindSubType = 174;                         // в слоте 3 предмет чужого подтипа
    constexpr BYTE kKindFault   = 175;                         // исключение — решение стока
    constexpr BYTE kKindApplied = 176;                         // добавка применена

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);                                         // sub_569DF0
    FnSrvLog const pSrvLog = (FnSrvLog)Srv::kLog;

    int  g_mode        = 1;                                    // 1 — решение; 0 — только журнал (сток)
    int  g_subType     = 108;                                  // подтип добавки
    int  g_scale       = 1000;                                 // множитель значения добавки (1 — как сток)
    int  g_percentBelow = 1000;                                // значения меньше порога записаны в процентах (от порога — уже в стотысячных)
    bool g_requireSub  = true;                                 // отказ, если в слоте 3 чужой подтип
    int  g_intervalSec = 10;                                   // ограничитель журнала (слот, вид), с
    P111_Stats g_stats = {};                                   // счётчики (экспорт P111_GetStats)
    DWORD g_lastJournal[4096][2] = {};                         // ограничитель: GetTickCount последней строки (слот & 4095, вид 0/1)

    // Подтип предмета по коду теми же границами, что у стока (sub_532A90 / sub_532B10); −1 — кода нет в таблицах.
    int SubTypeOf(int code)
    {
        if (code >= kSpecialFrom && code <= *(const int*)kSpecialMax)
        {
            return (*(const BYTE* const*)kSpecialTbl)[kSpecialRec * (code - kSpecialFrom) + kSpecialSub];
        }
        if (code >= 1 && code <= *(const int*)kFuncMax)
        {
            return (*(const BYTE* const*)kFuncTbl)[kFuncRec * (code - 1) + kFuncSub];
        }
        return -1;
    }

    // Строка журнала ac.other (с ограничителем) + строка Log_Operator.
    void Report(BYTE kind, const BYTE* user, int userNum, int code, int subType, int value, int newValue, int base, int catalyst)
    {
        int account = AcJournal::kNone, slot = AcJournal::kNone;
        char name[24] = "?";
        __try
        {
            account = *(const int*)(user + kOffUserIdx);
            slot    = user[kOffCharSlot];
            lstrcpynA(name, (const char*)(user + Srv::kOffCharName), 20);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { lstrcpyA(name, "?"); }

        const __int64 chance = (__int64)base + (__int64)base * catalyst / 100 + newValue;   // итог формулы стока
        const int k = kind == kKindSubType ? 0 : 1;
        const DWORD now = GetTickCount();
        DWORD* last = &g_lastJournal[userNum & 4095][k];
        const bool journal = kind == kKindFault || *last == 0 || (now - *last) >= (DWORD)g_intervalSec * 1000u;
        if (journal)
        {
            *last = now ? now : 1;
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kind);
            e.userNum   = (short)userNum;
            e.userIndex = account;
            e.charSlot  = slot;
            e.opcode    = kOpHatch;
            __try { e.ip = P47_PeerIpv4(userNum); }            // IP слота (сбой — без IP, решение не меняется)
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            __try { AcJournal::CopyName(e, user + Srv::kOffCharName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            e.v[0] = code;                                     // item_code: код предмета слота 3
            e.v[1] = kind == kKindSubType ? subType : value;   // value1:    подтип (174) / значение стока (175, 176)
            e.v[2] = (int)chance;                              // value2:    итоговый шанс, 1/100000
            char t[120];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P111 code %d sub %d val %d -> %d base %d cat %d chance %d mode %d",
                        code, subType, value, newValue, base, catalyst, (int)chance, g_mode);
            AcJournal::CopyText(e, t);
            if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
        }
        else { InterlockedIncrement(&g_stats.suppressed); }

        __try
        {
            const char* what = kind == kKindSubType ? (g_mode ? "wrong item in supplement slot - refused" : "JOURNAL ONLY: wrong item in supplement slot")
                             : kind == kKindApplied ? (g_mode ? "supplement applied" : "JOURNAL ONLY: supplement seen")
                             : "FAULT - stock decision";
            pSrvLog(Srv::kLogCatOperator, "P111 HatchSupplement: UserNum %d (UserIndex %d, CharN %s) Item %d sub %d val %d -> %d base %d cat %d "
                    "chance %d: %s", userNum, account == AcJournal::kNone ? -1 : account, name, code, subType, value, newValue, base,
                    catalyst, (int)chance, what);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ── C-часть трамплина площадки 0x4556C3 ──────────────────────────────────────────────────────────────────────────
//   user — CUser ([ebp-0E8h]); code — код предмета слота 3 ([ebp-0E0h], −1 — нет); value — значение слота 3 ([ebp-8Ch], пишется);
//   base — база шанса ([ebp-84h]); catalyst — проценты катализатора ([ebp-0E4h]); userNum — a2 ([ebp+8]).
//   Возврат: 0 — формула стока (с новым значением), иначе отказ (блок кода 5).
extern "C" int __stdcall P111_Apply(BYTE* user, int code, int* value, int base, int catalyst, int userNum)
{
    InterlockedIncrement(&g_stats.seen);
    if (code <= 0) { return 0; }                               // слота 3 нет — сток
    InterlockedIncrement(&g_stats.withItem);
    const int old = *value;
    int sub = -1;
    __try
    {
        sub = SubTypeOf(code);
        if (sub < 0) { return 0; }                             // сток уже отказал бы кодом 5; сюда не доходит
        if (sub != g_subType)
        {
            if (!g_requireSub) { return 0; }                   // сверка выключена — сток
            InterlockedIncrement(&g_stats.refusedSubType);
            Report(kKindSubType, user, userNum, code, sub, old, old, base, catalyst);
            return g_mode ? kRefuseCode : 0;
        }
        if (old < g_percentBelow && g_mode)                    // от порога значение уже в стотысячных (запись 429) — сток
        {
            __int64 scaled = (__int64)old * g_scale;
            if (scaled < 0) { scaled = 0; }
            if (scaled > kChanceFull) { scaled = kChanceFull; }
            *value = (int)scaled;
            InterlockedIncrement(&g_stats.scaled);
        }
        Report(kKindApplied, user, userNum, code, sub, old, *value, base, catalyst);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try { Report(kKindFault, user, userNum, code, sub, old, old, base, catalyst); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return 0;
    }
}

extern "C" __declspec(dllexport) void __stdcall P111_GetStats(P111_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_backAddr   = kBack;                                // продолжение формулы стока
    DWORD g_refuseAddr = kRefuse;                              // блок отказа кода 5 стока

    // Трамплин площадки 0x4556C3. Вход по jmp из Recv_IncubatorReq: ebp — его кадр, стек — как на 0x4556C3 и на 0x455699 (сюда стоковые
    //   ветки приходят после add esp; глубина одна). Регистры и флаги на площадке не живые (сток дальше грузит всё из кадра), стек x87
    //   пуст — вызов C-части его не трогает, вытесненный fild выполняется последним.
    __declspec(naked) void ApplyTrampoline()
    {
        __asm
        {
            pushad
            movsx eax, word ptr [ebp+0x08]           // a2 — userNum
            push  eax
            push  dword ptr [ebp-0xE4]               // проценты катализатора
            push  dword ptr [ebp-0x84]               // база шанса
            lea   eax, [ebp-0x8C]
            push  eax                                // &значение слота 3
            push  dword ptr [ebp-0xE0]               // код предмета слота 3
            push  dword ptr [ebp-0xE8]               // CUser*
            call  P111_Apply
            test  eax, eax
            jnz   refuse
            popad
            fild  dword ptr [ebp-0x84]               // вытесненная команда стока
            jmp   dword ptr [g_backAddr]             // 0x4556C9
        refuse:
            popad
            jmp   dword ptr [g_refuseAddr]           // 0x455699 — стоковый 6103 код 5 и выход
        }
    }
}

PatchResult P111_HatchSupplement()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_subType     = Config::GetInt(kSec, L"SupplementSubType", 108);
    g_scale       = Config::GetInt(kSec, L"SupplementScale", 1000);
    g_percentBelow = Config::GetInt(kSec, L"PercentBelow", 1000);
    g_requireSub  = Config::GetBool(kSec, L"RequireSubType", true);
    g_intervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_subType < 0 || g_subType > 255) { g_subType = 108; }
    if (g_scale < 1 || g_scale > kChanceFull) { g_scale = 1000; }
    if (g_percentBelow < 0) { g_percentBelow = 1000; }
    if (g_intervalSec < 0) { g_intervalSec = 0; }

    const Site sites[] =
    {
        { kSite,      kSiteOrig,      sizeof(kSiteOrig)      },
        { kBack,      kBackOrig,      sizeof(kBackOrig)      },
        { kRefuse,    kRefuseOrig,    sizeof(kRefuseOrig)    },
        { kReadSlot3, kReadSlot3Orig, sizeof(kReadSlot3Orig) },
    };
    if (!VerifyAllSites(L"P111", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(kSite, &ApplyTrampoline, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P111: Recv_IncubatorReq @0x%08X (6 б) -> трамплин 0x%08X: значение добавки подтипа %d меньше %d × %d (не больше %d); чужой "
              L"подтип в слоте 3 — %s; Mode=%d (%s); журнал ac.other 174/175/176 (раз в %d с на слот)", kSite, (DWORD)&ApplyTrampoline, g_subType,
              g_percentBelow, g_scale, kChanceFull, g_requireSub ? L"6103 код 5" : L"сток", g_mode, g_mode ? L"решение" : L"только журнал", g_intervalSec);
    return PatchResult::Applied;
}
