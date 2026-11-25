// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P36 — ★ ОПЦИЯ 24 «УСПЕШНОЕ ИЗГОТОВЛЕНИЕ +N %», КОТОРУЮ СЕРВЕР НЕ ПРИМЕНЯЛ
//  (решение владельца 26.09.2026; формула — вариант (б) координатора).
//
//  ЭТО НАША ПРАВКА. Разбор: Reports/gear_upgrade/p34_necklace.md §4,
//  AstoryServer/Docs/GameServer/craft-server-defects-p35.md §8; итог волны —
//  Reports/craft/p36_r248_dbm.md §1; документ патча —
//  AstoryServer/Docs/GameServer/craft-success-option-p36.md
//
//  У 13 амулетов (23324, 29827…29838) фиксированная опция item_table +12 = 24,
//  +14 = N (2…7). Строка в подсказке есть, эффекта не было: sub_445DD0 (сумма
//  опции по типу) 83 раза зовётся с литералами, 24 среди них нет, а в
//  RecvUser_CraftEnter @0x53DBA0 нет ни одного бонуса игрока.
//
//  Формула (вариант (б)): порог КАЖДОЙ ступени лестницы ремесла умножается на
//  (1 + N/100) — по аналогии с единственным бонусом шанса сервера (бонус дропа,
//  NpcServer sub_42E3A0: rate·(1 + x/100); P34 тип 61). Итог — не выше 100000
//  (потолок броска sub_5329A0(0, 100000)) и не ниже 0. Порог ≤ 0 и ≥ 100000
//  не меняется. Великий успех (+1 шт., 0x53E84F) НЕ трогается.
//
//  N = sub_445DD0(CParamManager, userNum, 24) — штатная сумма GameServer по
//  ВСЕМ надетым вещам: пары доп-опций 11 слотов (0…10) + фиксированная опция
//  трёх аксессуаров (слоты 5/6/7) — ровно тот же источник, что у P34 (тип 61).
//  Сейчас в данных тип 24 есть только как фикс. опция 13 амулетов (слот 7):
//  в Item_OptionTable.txt строк типа 24 — 0 (38 899 строк, тип = токен 1),
//  Item_Option.txt сервер не читает (fopen нет), премиум-опции — 300…329.
//
//  ★ Площадка (1), сверена побайтно: наш RE/ida/server_work/GameServer.exe,
//  ЖИВОЙ v2\GameServer\GameServer.exe и v2\Indun_GameServer\GameServer.exe
//  (все MD5 E7B4AC38…) и сток GameServer.exe_before_mine_patch.exe.
//    0x0053E7DF  8B 95 30 F8 FF FF  mov edx,[ebp-0x7D0]      ; k
//                8B 85 44 FB FF FF  mov eax,[ebp-0x4BC]      ; бросок
//                3B 84 95 12 FB FF FF cmp eax,[ebp+edx*4-0x4EE] ; порог ступени (копия Make+58+4k)
//                7F 10              jg  0x53E804             ; провал -> выход из лестницы
//  Все 21 байт заменяются (jmp + 16 nop): трамплин сам сравнивает бросок с
//  эффективным порогом и уходит на 0x53E7F4 (ступень пройдена) или 0x53E804
//  (провал). Стековая копия порога НЕ меняется (она больше нигде не читается,
//  но так надёжнее). eax/ecx/edx на обеих целях пишутся до чтения (стоковая
//  площадка сама их портит; 0x53E9C8 — `mov ecx,[ebp-0x820]` до чтения),
//  флаги перезаписываются. Переходов внутрь площадки нет (полный скан rel8/
//  rel32/jcc по .text живого образа + скан абсолютных DWORD — 0). С P01…P35
//  не пересекается (ближайшие — P35 CODE.e11 0x53E772 и CAT.stack 0x53E646).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P36_CraftSuccessOption";

    typedef int  (__thiscall *FnOptSum)(void* paramMgr, short idx, short type);     // 0x445DD0, ret 8
    typedef void (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);             // 0x569DF0

    const FnOptSum SrvOptSum = (FnOptSum)0x00445DD0;
    const FnSrvLog SrvLog    = (FnSrvLog)Srv::kLog;

    constexpr short kOptCraft    = 24;       // «Успешное изготовление %»
    constexpr int   kRollMax     = 100000;   // sub_5329A0(0, 100000)
    constexpr int   kLogCatCraft = 26;       // Log\Log_Craft (категория стоковых строк RecvUser_CraftEnter)

    // Кадр RecvUser_CraftEnter (asm 0x53E6F5…0x53E7F2, декомпил GameServer.c:121536-121559)
    constexpr int   kFrmK        = -0x7D0;   // int  k — номер ступени 0…6
    constexpr int   kFrmRoll     = -0x4BC;   // int  бросок (0 при помощнике вида 2 на k == 0)
    constexpr int   kFrmThr      = -0x4EE;   // int[7] пороги ступеней: [ebp + k*4 - 0x4EE]
    constexpr int   kFrmThis     = -0x820;   // this (менеджер игроков): [[this+4]+0x18] = CParamManager
    constexpr int   kFrmUserNum  = 8;        // [ebp+8] i16 индекс игрока (arg0)

    bool g_on = true;
    int  g_maxBonus = 1000;                   // предел суммы N, % (защита от кривых данных)

    constexpr LONG kLogMax  = 20;             // первые N применений за жизнь процесса — в Log_Craft
    volatile LONG  g_logged = 0;

    DWORD g_pPass = 0x0053E7F4;               // ступень пройдена: mov cx,[ebp-0x7D0]; v18 = k
    DWORD g_pFail = 0x0053E804;               // провал: jmp 0x53E80B (выход из лестницы)
}

extern "C"
{
// 1 — бросок больше эффективного порога (провал ступени), 0 — ступень пройдена.
// Сравнение знаковое, как у стокового `jg`.
int __cdecl P36_StageFail(BYTE* ebp)
{
    const int k    = *(const int*)(ebp + kFrmK);
    const int roll = *(const int*)(ebp + kFrmRoll);
    const int thr  = *(const int*)(ebp + kFrmThr + 4 * k);
    int eff = thr;
    if (g_on && thr > 0 && thr < kRollMax)
    {
        __try
        {
            BYTE* self  = *(BYTE**)(ebp + kFrmThis);
            BYTE* world = self ? *(BYTE**)(self + 4) : nullptr;
            void* pm    = world ? *(void**)(world + 0x18) : nullptr;
            if (pm)
            {
                const short idx = *(const short*)(ebp + kFrmUserNum);
                int n = SrvOptSum(pm, idx, kOptCraft);
                if (n >  g_maxBonus) { n =  g_maxBonus; }
                if (n < -100)        { n = -100; }
                if (n != 0)
                {
                    __int64 e = (__int64)thr * (100 + n) / 100;
                    if (e > kRollMax) { e = kRollMax; }
                    if (e < 0)        { e = 0; }
                    eff = (int)e;
                    const LONG c = InterlockedIncrement(&g_logged);
                    if (c <= kLogMax)
                    {
                        SrvLog(kLogCatCraft, "P36: craft option 24 user %d stage %d bonus %d%% threshold %d -> %d roll %d %s%s",
                               (int)idx, k, n, thr, eff, roll, roll > eff ? "FAIL" : "PASS",
                               c == kLogMax ? " (further messages suppressed)" : "");
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { eff = thr; }
    }
    return roll > eff ? 1 : 0;
}
}

namespace
{
    // Площадка 0x53E7DF (21 б) целиком: вместо `cmp eax,[порог]; jg` — сравнение
    // с эффективным порогом. eax/ecx/edx свободны (см. шапку), флаги не нужны.
    __declspec(naked) void TrampStage()
    {
        __asm
        {
            push  ebp
            call  P36_StageFail
            add   esp, 4
            test  eax, eax
            jnz   Fail
            jmp   dword ptr [g_pPass]
        Fail:
            jmp   dword ptr [g_pFail]
        }
    }

    const BYTE kStage[21] =
    {
        0x8B, 0x95, 0x30, 0xF8, 0xFF, 0xFF,             // mov edx,[ebp-0x7D0]
        0x8B, 0x85, 0x44, 0xFB, 0xFF, 0xFF,             // mov eax,[ebp-0x4BC]
        0x3B, 0x84, 0x95, 0x12, 0xFB, 0xFF, 0xFF,       // cmp eax,[ebp+edx*4-0x4EE]
        0x7F, 0x10                                      // jg 0x53E804
    };
    const BYTE kPassNext[7] = { 0x66, 0x8B, 0x8D, 0x30, 0xF8, 0xFF, 0xFF };  // 0x53E7F4 mov cx,[ebp-0x7D0]
    const BYTE kFailNext[2] = { 0xEB, 0x05 };                                // 0x53E804 jmp 0x53E80B
}

PatchResult P36_CraftSuccessOption()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    g_on = Config::GetBool(S, L"CraftSuccessOption", true);
    if (!g_on) { return PatchResult::Disabled; }
    int mx = Config::GetInt(S, L"MaxBonusPercent", 1000);
    if (mx < 0)     { mx = 0; }
    if (mx > 10000) { mx = 10000; }
    g_maxBonus = mx;

    // сверка площадки и обеих целей возврата до записи
    const Site sites[] =
    {
        { 0x0053E7DF, kStage,    sizeof(kStage)    },
        { 0x0053E7F4, kPassNext, sizeof(kPassNext) },
        { 0x0053E804, kFailNext, sizeof(kFailNext) },
    };
    if (!VerifyAllSites(L"P36", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    const bool ok = Hook::WriteJmp(0x0053E7DF, (const void*)&TrampStage, sizeof(kStage));
    Log::Line(L"    P36/тип 24: порог каждой ступени ремесла × (1 + N/100), N = sub_445DD0(24) по надетому, "
              L"не выше 100000; великий успех не меняется. @0x0053E7DF -> 0x%08X, MaxBonusPercent=%d",
              (DWORD)&TrampStage, g_maxBonus);
    return ok ? PatchResult::Applied : PatchResult::Failed;
}
