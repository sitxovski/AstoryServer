// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P114 — [ИСПРАВЛЕНИЕ] ОПЫТ ЗАДАНИЙ ДОСКИ УСИЛИВАЕТСЯ, КАК ОПЫТ ОБЫЧНОГО ЗАДАНИЯ (07.11.2026, пачка 11, баг 8; слово владельца
//  «EXP rewards from Silaris Quest Board missions are not boosted by EXP potions… Same for the flammio quest board»).
//  Документ: AstoryServer/Docs/GameServer/board-exp-bonus-p114.md.
//
//  ── ПОТОК (GameServer e7b4ac38 = Indun = Ch2 = сток) ──
//  Обычное задание: sub_45DEE0 → sub_4C6F80(a5 = 1, fEvent = 1.0) → GetExpUpDownValue@0x4CC3A0 → Recv_BattleServerFromCharParamExp_1@0x4CBA90.
//  GetExpUpDownValue складывает события (GameServerEvent), бафы/зелья (param 53−54, опция 53), усилители CUser+0xBEDD/0xBF07 и опцию 103.
//  Задание доски (20000…20056, обе доски, все типы — один обработчик): recvDBLimitationResult@0x53C180 зовёт
//  Recv_BattleServerFromCharParamExp_1(this, num, 0, опыт таблицы +208, 1, 1.0f) напрямую, мимо GetExpUpDownValue. Так в оригинале.
//
//  ── ЧТО ДЕЛАЕТ P114 (5 байт, протокол не меняется) ──
//  Площадка 0x53C4F9 — этот call → трамплин: опыт > 0 проходит через GetExpUpDownValue(this, num, опыт, 1.0f), затем jmp в штатное начисление.
//  Те же аргументы, что у обычного задания. Задвоения нет: Recv_BattleServerFromCharParamExp_1 множителей не применяет (a6 не читает,
//  единственное умножение в нём — 0.3 для шкалы кувшина, verify_p114), вызов один. a5 = 1 как и был: доли Друга у наград нет ни у обычных заданий, ни у доски.
//  Опыт ≤ 0 не трогаем: GetExpUpDownValue превратил бы 0 в 1. Исключение — опыт стока, журнал ac.other 184.
//  Откат: patches.ini [P114_BoardExpBonus] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"

namespace
{
    const wchar_t* kSec = L"P114_BoardExpBonus";               // секция patches.ini

    constexpr DWORD kSite = 0x0053C4F9;                        // recvDBLimitationResult: call Recv_BattleServerFromCharParamExp_1
    const BYTE kSiteOrig[5] = { 0xE8, 0x92, 0xF5, 0xF8, 0xFF };
    constexpr DWORD kExpAdd = 0x004CBA90;                      // Recv_BattleServerFromCharParamExp_1 — ret 18h
    constexpr DWORD kExpUpDown = 0x004CC3A0;                   // GetExpUpDownValue — ret 10h
    const BYTE kExpUpDownProlog[3] = { 0x55, 0x8B, 0xEC };     // push ebp; mov ebp,esp (сверка цели)
    constexpr int kKindFault = 184;                            // ac.other: исключение, опыт стока
    constexpr int kOp6593 = 6593;                              // опкод сдачи задания для журнала

    typedef __int64 (__thiscall* FnExpUpDown)(void* mgr, short num, __int64 exp, float fEvent);   // GetExpUpDownValue

    P114_Stats g_stats = {};                                   // счётчики стенда
}

// C-часть трамплина. args — аргументы начисления на стеке: [0] номер игрока, [1] a3, [2..3] опыт (i64), [4] a5, [5] a6.
extern "C" void __stdcall P114_Adjust(void* mgr, DWORD* args)
{
    InterlockedIncrement(&g_stats.seen);
    __try
    {
        __int64* exp = (__int64*)(args + 2);
        if (*exp <= 0) { return; }
        const __int64 boosted = ((FnExpUpDown)kExpUpDown)(mgr, (short)args[0], *exp, 1.0f);
        if (boosted <= 0) { return; }
        if (boosted != *exp) { InterlockedIncrement(&g_stats.boosted); }
        *exp = boosted;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kKindFault);
            e.opcode = kOp6593;
            e.userNum = (short)args[0];                        // игрок
            e.v[0] = (int)args[2];                             // item_code: опыт таблицы
            AcJournal::Push(e);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

extern "C" __declspec(dllexport) void __stdcall P114_GetStats(P114_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_expAdd = kExpAdd;                                  // штатное начисление

    // Вход по call площадки: [esp] — возврат, [esp+4] — аргументы начисления, ecx — this. ecx восстанавливаем, остальное сохраняет C-часть.
    __declspec(naked) void ExpTrampoline()
    {
        __asm
        {
            push  ecx
            lea   eax, [esp+8]                       // аргументы начисления
            push  eax
            push  ecx                                // CUserManager
            call  P114_Adjust
            pop   ecx
            jmp   dword ptr [g_expAdd]               // ret 18h вернётся на 0x53C4FE
        }
    }
}

PatchResult P114_BoardExpBonus()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    const Site sites[] =
    {
        { kSite,      kSiteOrig,        sizeof(kSiteOrig)        },
        { kExpUpDown, kExpUpDownProlog, sizeof(kExpUpDownProlog) },
    };
    if (!VerifyAllSites(L"P114", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteCall(kSite, &ExpTrampoline, 5)) { return PatchResult::Failed; }
    Log::Line(L"    P114: recvDBLimitationResult @0x%08X (5 б) -> трамплин 0x%08X: опыт доски через GetExpUpDownValue, ac.other 184", kSite, (DWORD)&ExpTrampoline);
    return PatchResult::Applied;
}
