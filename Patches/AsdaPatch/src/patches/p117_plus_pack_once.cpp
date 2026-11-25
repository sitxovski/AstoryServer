// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P117 — [ИСПРАВЛЕНИЕ] ЗЕЛЬЕ УРОВНЯ (PLUS PACKAGE) НЕ ПРИМЕНЯЕТСЯ, ПОКА ДЕЙСТВУЕТ ПРЕЖНЕЕ (09.11.2026, пачка 19, баг 9;
//  решение владельца «запретить применение нового зелья уровня, пока действует прежнее», номер — «Да, P117»).
//  Разбор: Reports/batch19/levelup_potion/REPORT.md; документ AstoryServer/Docs/GameServer/plus-pack-once-p117.md.
//
//  ── СТОК (GameServer e7b4ac38 = Indun = Ch2; сток 4e20f0ad — те же байты) ──
//  Предметы Function_Table категории 120 (+8): 14, 475, 476, 489, 490, 536, 537, 538, 544 — наборы уровня на 1/7/30 дней.
//  5450 → Char_FunctionItem_Use@0x4ED780, switch(+8) case 120 @0x4EE25B: проверка только номера строки PrimiumLevelTable (+9),
//  затем 2565 в DBManager → UPPlusPackageitemUse: предмет списан, CharPlusPackage ПЕРЕЗАПИСАН (срок с нуля, iType новый) →
//  recvDBPlusPakege@0x4F90F0 пишет в CUser +0xBFC5 номер строки (i16) и +0xBFC7 остаток в секундах (i32, минуты × 60) → 6585.
//  Таймер sub_4F9210 (из sub_5433D0) раз в секунду уменьшает CUser +0xBFC7; на нуле — 6585 «выкл» и пересчёт параметров.
//  Действующий набор ничем не проверяется: повтор тратит предмет и сбрасывает остаток (30 дней можно затереть 7-дневным).
//
//  ── ЧТО ДЕЛАЕТ P117 (6 б, протокол не меняется) ──
//  Площадка 0x4EE25B — `mov eax,[ebp-204h]` в начале case 120 → заглушка. CUser — [ebp-20Ch] (sub_5324A0, проверен стоком на 0
//  @0x4ED9D5). Если остаток CUser +0xBFC7 > 0 — [ebp-121h] = 0x10 и общий выход отказа 0x4EF0C3: 5451 код 0x10, в DBManager
//  ничего не уходит, предмет не тратится. Клиент (и alpha-6.9.9, и оригинал) переводит код 0x10 в нотис 12849
//  «В настоящее время действует эффект навыка того же типа». Иначе — штатная инструкция и продолжение 0x4EE261.
//  Журнал: FuncLog сервера (канал 8) — строка на каждый отказ. Нарушения античита нет (обычное действие игрока).
//  Соседи в Char_FunctionItem_Use: P75 0x4EDDC7 (до switch, только код 558 — категория 6), P102 S5 0x4EDDE1, P103 S2 0x4EE5A1
//  (вход LABEL_69 — ветка default, case 120 туда не идёт), P15 0x4ED9EF, P65 0x4EDD82, P08/P49 0x4ED8CF/0x4ED8DE — не пересекаются.
//  Откат: patches.ini [P117_PlusPackOnce] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P117_PlusPackOnce";               // секция patches.ini

    constexpr DWORD kSite   = 0x004EE25B;                     // case 120: mov eax,[ebp-204h]
    constexpr DWORD kBack   = 0x004EE261;                     // продолжение стока: sub eax,1
    constexpr DWORD kRefuse = 0x004EF0C3;                     // общий выход отказа: 5451 с кодом [ebp-121h]
    const BYTE kSiteOrig[6] = { 0x8B, 0x85, 0xFC, 0xFD, 0xFF, 0xFF };
    const BYTE kBackOrig[6] = { 0x83, 0xE8, 0x01, 0x6B, 0xC0, 0x30 };                   // sub eax,1; imul eax,eax,30h
    const BYTE kRefuseOrig[7] = { 0x0F, 0xB6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF };           // movzx eax, byte [ebp-121h]
    // 0x4ED9CF: mov [ebp-20Ch],eax (CUser из sub_5324A0); cmp dword [ebp-20Ch],0 — сток не пускает дальше пустого
    const BYTE kUserStore[13] = { 0x89, 0x85, 0xF4, 0xFD, 0xFF, 0xFF, 0x83, 0xBD, 0xF4, 0xFD, 0xFF, 0xFF, 0x00 };
    // 0x4F9248: таймер sub_4F9210 — cmp dword [eax+0BFC7h],0 (дальше sub edx,1 и запись по тому же +0xBFC7)
    const BYTE kTimerRead[7] = { 0x83, 0xB8, 0xC7, 0xBF, 0x00, 0x00, 0x00 };
    constexpr DWORD kTimerSite = 0x004F9248;
    // 0x4F91A1: recvDBPlusPakege — add ecx,0BFC5h; затем [ecx] = номер строки (i16) + младшие 16 бит остатка, [ecx+4] = старшие 16
    const BYTE kDbWrite[6] = { 0x81, 0xC1, 0xC5, 0xBF, 0x00, 0x00 };
    constexpr DWORD kDbWriteSite = 0x004F91A1;
    constexpr int kOffRemain = 0xBFC7;                        // CUser: остаток набора уровня, секунды
    constexpr int kOffIndex  = 0xBFC5;                        // CUser: номер строки PrimiumLevelTable (i16)
    constexpr int kOffUserIdx = 0x174;                        // CUser: Userindex (учётка)
    constexpr int kOffName = 0x178;                           // CUser: имя персонажа
    constexpr BYTE kCode = 0x10;                              // 5451: «действует эффект того же типа» (клиент → 12849)

    typedef void (__cdecl* FnSrvLog)(int cat, const char* fmt, ...);
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;
    constexpr int kLogCatFunc = 8;                            // Log\Log_Func\FuncLog_<дата>.txt

    bool g_funcLog = true;
    DWORD g_back = kBack;
    DWORD g_refuse = kRefuse;
    P117_Stats g_stats = {};
}

// C-часть заглушки: 1 — отказ (код 0x10), 0 — сток. ebp — кадр Char_FunctionItem_Use.
extern "C" int __stdcall P117_Gate(BYTE* ebp)
{
    __try
    {
        InterlockedIncrement(&g_stats.seen);
        const BYTE* user = *(BYTE* const*)(ebp - 0x20C);
        if (!user) { return 0; }
        const int remain = *(const int*)(user + kOffRemain);
        if (remain <= 0) { return 0; }
        InterlockedIncrement(&g_stats.refused);
        if (g_funcLog)
        {
            const int code = *(const int*)(ebp - 0x204);
            SrvLog(kLogCatFunc, "\t[P117] PlusPackage still active..! %s, UserIndex:%d, Code:%d, Index:%d, Remain:%d s -> 5451 %d",
                   (const char*)(user + kOffName), *(const int*)(user + kOffUserIdx), code, (int)*(const short*)(user + kOffIndex), remain, (int)kCode);
        }
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P117_GetStats(P117_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Вместо `mov eax,[ebp-204h]` в начале case 120.
    __declspec(naked) void St_PlusGate()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P117_Gate
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   eax, dword ptr [ebp - 204h]
            jmp   dword ptr [g_back]                  // 0x4EE261
        refuse:
            popad
            popfd
            mov   byte ptr [ebp - 121h], 10h          // 5451 код 0x10
            jmp   dword ptr [g_refuse]                // 0x4EF0C3 — общий выход: 5451 клиенту, в БД ничего
        }
    }
}

PatchResult P117_PlusPackOnce()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_funcLog = Config::GetBool(kSec, L"FuncLog", true);
    const Site sites[] =
    {
        { kSite,      kSiteOrig,   sizeof(kSiteOrig)   },
        { kBack,      kBackOrig,   sizeof(kBackOrig)   },
        { kRefuse,    kRefuseOrig, sizeof(kRefuseOrig) },
        { 0x004ED9CF, kUserStore,  sizeof(kUserStore)  },
        { kTimerSite, kTimerRead,  sizeof(kTimerRead)  },
        { kDbWriteSite, kDbWrite,  sizeof(kDbWrite)    },
    };
    if (!VerifyAllSites(L"P117", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &St_PlusGate, 6)) { return PatchResult::Failed; }
    Log::Line(L"    P117: Char_FunctionItem_Use case 120 @0x%08X (6 б) -> заглушка 0x%08X: набор уровня действует (CUser+0x%X > 0) -> 5451 код 0x10",
              kSite, (DWORD)&St_PlusGate, kOffRemain);
    return PatchResult::Applied;
}
