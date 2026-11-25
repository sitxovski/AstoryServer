// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P122 — ФУНКЦИЯ ПИТОМЦА НЕ НИЖЕ ТАБЛИЦЫ (09.11.2026, пачка 20, баг 4; решение владельца «Не ниже таблицы», номер — координатор).
//  Разбор: Reports/batch20/pets/pet_option_zero.md; документ AstoryServer/Docs/GameServer/pet-func-floor-p122.md.
//
//  ── СТОК (GameServer = Indun = Ch2, функция побайтно одна — verify_p122) ──
//  sub_459AD0@0x459AD0 (GameServer.c:36358) считает три функции записи питомца (CUser-слот 45 б: +0 порода i16, +0x12 сытость,
//  +0x13 уровень, +0x17+6i тип функции i16, +0x19+6i значение i32):
//      v = (int)(PetExp[уровень].множитель × PetInfo[порода].значение_i / 100)           (множитель 30/60/100/…/155)
//      сытость ≤ 39 → 0; 40–59 → (int)(0.8·v); 60–79 → (int)(0.9·v); ≥ 80 → v.
//  Значение уходит клиенту в записи питомца (6106 и др.) и применяется к статам как процент (sub_455F60 → sub_43B750: стат × v / 100).
//  На 1-м уровне функции с малым значением таблицы дают +1 % и +0 % (NewbieWolf 4 → 1, при сытости < 80 → 0).
//
//  ── ЧТО ДЕЛАЕТ P122 (7 б, протокол не меняется) ──
//  Площадка 0x459C0E — `mov edx,[ebp-4]; mov [ecx+eax+19h],edx` (запись значения i-й функции) → заглушка: edx = max(v, табличное
//  значение PetInfo[порода].значение_i), табличное — `[0x7E0004] + 60·порода + 6·i + 0x24` (те же адреса, что читает сток @0x459B49).
//  Режим `FloorWhenHungry=0` (по умолчанию, слово владельца про голодного: «0, как сейчас»): у голодного (сытость ≤ 39) остаётся 0,
//  как у стока, пол действует при сытости от 40; 1 — пол и у голодного. Затем штатная запись и возврат на 0x459C15 (jmp на следующую функцию).
//  Соседей в sub_459AD0 нет (ни одна площадка AsdaPatch не лежит в 0x459AD0…0x459C20 — verify_p122).
//  Откат: patches.ini [P122_PetFuncFloor] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P122_PetFuncFloor";               // секция patches.ini

    constexpr DWORD kFunc  = 0x00459AD0;                      // sub_459AD0 — расчёт трёх функций питомца
    constexpr DWORD kSite  = 0x00459C0E;                      // mov edx,[ebp-4]; mov [ecx+eax+19h],edx
    constexpr DWORD kBack  = 0x00459C15;                      // jmp 0x459B0F — следующая функция
    const BYTE kSiteOrig[7] = { 0x8B, 0x55, 0xFC, 0x89, 0x54, 0x01, 0x19 };
    const BYTE kBackOrig[5] = { 0xE9, 0xF5, 0xFE, 0xFF, 0xFF };
    // 0x459B49: add edx,[7E0004h] — база PetInfo (запись 60 б); 0x459B55: mov ecx,[edx+eax+24h] — значение i-й функции
    const BYTE kTableBase[6] = { 0x03, 0x15, 0x04, 0x00, 0x7E, 0x00 };
    const BYTE kTableRead[4] = { 0x8B, 0x4C, 0x02, 0x24 };
    // 0x459B8B: movzx ecx, byte [eax+12h] — сытость; 0x459B5F: movzx eax, byte [edx+13h] — уровень
    const BYTE kFullRead[4] = { 0x0F, 0xB6, 0x48, 0x12 };
    constexpr DWORD kPetInfoPtr = 0x007E0004;                 // DWORD: база таблицы PetInfo (60 б на породу)
    constexpr DWORD kPetInfoCnt = 0x007E0008;                 // i16: число пород (сток сверяет породу с ним @0x459AF0)
    constexpr int kRec = 60;                                  // размер записи PetInfo
    constexpr int kOffValue = 0x24;                           // значение функции 0 в записи PetInfo (+6 на следующую)
    constexpr int kHungry = 39;                               // сытость ≤ 39 — сток даёт 0

    bool  g_floorHungry = false;
    DWORD g_back = kBack;
    P122_Stats g_stats = {};
}

// C-часть заглушки: возвращает значение функции для записи. ebp — кадр sub_459AD0 ([ebp+8] слот питомца, [ebp-0Ch] номер функции).
extern "C" int __stdcall P122_Floor(BYTE* ebp, int value)
{
    __try
    {
        InterlockedIncrement(&g_stats.seen);
        const BYTE* pet = *(const BYTE* const*)(ebp + 8);
        const int i = *(const int*)(ebp - 0x0C);
        if (!pet || i < 0 || i > 2) { return value; }
        const int breed = *(const short*)pet;
        const int count = *(const short*)kPetInfoCnt;
        const BYTE* table = *(const BYTE* const*)kPetInfoPtr;
        if (!table || breed < 0 || breed >= count) { return value; }
        const int floor = *(const int*)(table + kRec * breed + 6 * i + kOffValue);
        if (floor <= value) { return value; }
        if (!g_floorHungry && pet[0x12] <= kHungry) { return value; }
        InterlockedIncrement(&g_stats.raised);
        return floor;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
    return value;
}

extern "C" __declspec(dllexport) void __stdcall P122_GetStats(P122_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Вместо `mov edx,[ebp-4]; mov [ecx+eax+19h],edx`.
    __declspec(naked) void St_FuncFloor()
    {
        __asm
        {
            pushfd
            push  eax
            push  ecx
            push  dword ptr [ebp - 4]             // значение стока
            push  ebp
            call  P122_Floor                      // eax = max(значение, таблица)
            mov   edx, eax
            pop   ecx
            pop   eax
            popfd
            mov   dword ptr [ecx + eax + 19h], edx
            jmp   dword ptr [g_back]              // 0x459C15
        }
    }
}

PatchResult P122_PetFuncFloor()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_floorHungry = Config::GetBool(kSec, L"FloorWhenHungry", false);
    const Site sites[] =
    {
        { kSite,      kSiteOrig,  sizeof(kSiteOrig)  },
        { kBack,      kBackOrig,  sizeof(kBackOrig)  },
        { 0x00459B49, kTableBase, sizeof(kTableBase) },
        { 0x00459B55, kTableRead, sizeof(kTableRead) },
        { 0x00459B8B, kFullRead,  sizeof(kFullRead)  },
    };
    if (!VerifyAllSites(L"P122", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &St_FuncFloor, 7)) { return PatchResult::Failed; }
    Log::Line(L"    P122: sub_459AD0 @0x%08X (7 б) -> заглушка 0x%08X: функция питомца = max(расчёт, PetInfo), у голодного %s",
              kSite, (DWORD)&St_FuncFloor, g_floorHungry ? L"тоже" : L"0 как сток");
    (void)kFunc;
    return PatchResult::Applied;
}
