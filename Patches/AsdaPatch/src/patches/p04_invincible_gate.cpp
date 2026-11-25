// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P04 — GM-гейт на «неуязвимость», Recv_OperatorCommand_Invincible@0x551870.
//
//  Стоковый код (проверено дизассемблером):
//      0x5518F0  push ecx
//      0x5518F1  mov  ecx, [ebp-0x14]          ; CUserManager
//      0x5518F4  call 0x524390                 ; анти-реплей
//      0x5518F9  test eax, eax
//      0x5518FB  jne  0x5518FF
//      0x5518FD  jmp  0x551960                 ; -> эпилог (mov esp,ebp; pop ebp; ret 8)
//      0x5518FF  mov  edx, [ebp-0x0C]          <-- ЗАМЕНЯЕМ (10 байт)
//      0x551902  cmp  dword ptr [edx+0x3BC3D], 1   <-- вместе с этим
//      0x551909  jne  0x551921                 <-- ВОЗВРАТ сюда (читает флаги от cmp)
//
//  В стоке режим неуязвимости мог включить ЛЮБОЙ игрок. Патч добавляет проверку
//  флага оператора: не оператор -> сразу на эпилог 0x551960.
//
//  ★ Флаги: последняя инструкция трамплина перед возвратом — тот самый `cmp`,
//    а `jmp dword ptr [...]` флаги НЕ меняет, поэтому `jne` на 0x551909 получает
//    ровно те же флаги, что и в стоке.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pIsOperator = Srv::kIsOperator;                     // char __thiscall (mgr, idx)
    DWORD g_pRet        = Srv::Hooks::kInvincibleGate + 10;     // 0x551909
    DWORD g_pExit       = 0x00551960;                           // штатный эпилог функции

    // mov edx,[ebp-0x0C] ; cmp dword ptr [edx+0x3BC3D], 1
    const BYTE kOrig[10] =
    {
        0x8B, 0x55, 0xF4, 0x83, 0xBA, 0x3D, 0xBC, 0x03, 0x00, 0x01
    };

    __declspec(naked) void InvincibleGateTrampoline()
    {
        __asm
        {
            movsx eax, word ptr [ebp+8]         // userNum
            push eax
            mov  ecx, dword ptr [ebp-0x14]      // CUserManager
            call dword ptr [g_pIsOperator]      // callee чистит 4 байта
            test al, al
            jne  allowed
            jmp  dword ptr [g_pExit]            // не оператор -> выход из обработчика
        allowed:
            mov  edx, dword ptr [ebp-0x0C]      // оригинальные инструкции
            cmp  dword ptr [edx+0x3BC3D], 1
            jmp  dword ptr [g_pRet]             // jmp флаги не портит
        }
    }
}

PatchResult P04_InvincibleGmGate()
{
    if (!Config::GetBool(L"P04_InvincibleGmGate", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kInvincibleGate, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P04", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kInvincibleGate, &InvincibleGateTrampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P04: перехват @0x%08X (10 б) -> трамплин 0x%08X, возврат 0x%08X, отказ 0x%08X",
              Srv::Hooks::kInvincibleGate, (DWORD)&InvincibleGateTrampoline, g_pRet, g_pExit);
    return PatchResult::Applied;
}
