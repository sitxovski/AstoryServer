// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P07 — ранний выход в sub_43C690 по полю CUser+0x3BC3D.
//  Перенос 1:1 бинарного кейва живого сервера (0x58294D).
//
//  Сток @0x43C6DD:
//      0x43C6DD  mov eax, dword ptr [ebp-0x20]        <-- ЗАМЕНЯЕМ (9 байт)
//      0x43C6E0  mov ecx, dword ptr [eax+0x453]       <-- вместе с этим
//      0x43C6E6  mov dword ptr [ebp-0x18], ecx        <-- ВОЗВРАТ сюда
//
//  Патч: если CUser+0x3BC3D != 0 (то же поле, что у «неуязвимости» в P04, т.е.
//  оператор/неуязвимый игрок) — вернуть 1 сразу, перепрыгнув на 0x43C895
//  (место, где функция отдаёт результат в al). Иначе — оригинальный путь.
//
//  ⚠ Назначение — ГИПОТЕЗА: «GM/неуязвимый игрок проходит проверку автоматически».
//    Байты перенесены 1:1 с живого сервера.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pRet  = 0x0043C6E6;     // штатное продолжение
    DWORD g_pExit = 0x0043C895;     // «вернуть 1» — хвост функции

    // mov eax,[ebp-0x20] ; mov ecx,[eax+0x453]
    const BYTE kOrig[9] = { 0x8B, 0x45, 0xE0, 0x8B, 0x88, 0x53, 0x04, 0x00, 0x00 };

    __declspec(naked) void Sub43C690Trampoline()
    {
        __asm
        {
            mov eax, dword ptr [ebp-0x20]
            cmp dword ptr [eax+0x3BC3D], 0
            je  normal
            mov al, 1
            jmp dword ptr [g_pExit]
        normal:
            mov ecx, dword ptr [eax+0x453]      // оригинальная вторая инструкция
            jmp dword ptr [g_pRet]
        }
    }
}

PatchResult P07_Sub43C690EarlyExit()
{
    if (!Config::GetBool(L"P07_Sub43C690EarlyExit", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kSub43C690, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P07", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kSub43C690, &Sub43C690Trampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P07: перехват @0x%08X (9 б) -> трамплин 0x%08X, возврат 0x%08X, ранний выход 0x%08X",
              Srv::Hooks::kSub43C690, (DWORD)&Sub43C690Trampoline, g_pRet, g_pExit);
    return PatchResult::Applied;
}
