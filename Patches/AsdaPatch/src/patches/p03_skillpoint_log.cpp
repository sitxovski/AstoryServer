// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P03 — лог выдачи скиллпоинтов в Recv_OperatorCommand_Add@0x5510F0.
//
//  Стоковый код (проверено дизассемблером):
//      0x55152B  mov  cx, word ptr [ebp+8]     ; userNum
//      0x55152F  push ecx                      ; аргумент для 0x52EA20
//      0x551530  mov  ecx, [ebp-0x40C]         <-- ЗАМЕНЯЕМ (11 байт)
//      0x551536  call 0x52EA20                 <-- вместе с этим
//      0x55153B  mov  word ptr [ebp-0x3FF], ax <-- ВОЗВРАТ сюда
//
//  Трамплин воспроизводит оригинальный вызов и добавляет строку в Log_Operator.
//  Логика игры не меняется: результат sub_52EA20 сохраняется через push/pop eax.
//
//  Двойная разыменовка `mov ecx,[ecx+4]; mov ecx,[ecx+0x34]` перенесена 1:1 с
//  живого сервера. Она эквивалентна оригиналу: у менеджера поле +4 указывает на
//  родителя, а у родителя +0x34 — обратно на менеджер ([[M+4]+52] == M).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pGetSkillPoint = 0x0052EA20;                    // __thiscall (mgr, __int16 idx) -> ax
    DWORD g_pLog           = Srv::kLog;                     // __cdecl (cat, fmt, ...)
    DWORD g_pRet           = Srv::Hooks::kSkillPointLog + 11;   // 0x55153B

    const char kFmt[] = "SKILLPOINT: user=%d now=%d";

    // mov ecx,[ebp-0x40C] ; call 0x52EA20
    const BYTE kOrig[11] =
    {
        0x8B, 0x8D, 0xF4, 0xFB, 0xFF, 0xFF, 0xE8, 0xE5, 0xD4, 0xFD, 0xFF
    };

    __declspec(naked) void SkillPointTrampoline()
    {
        __asm
        {
            mov  ecx, dword ptr [ebp-0x40C]
            mov  ecx, dword ptr [ecx+4]
            mov  ecx, dword ptr [ecx+0x34]      // == тот же менеджер (см. комментарий выше)
            call dword ptr [g_pGetSkillPoint]   // callee чистит аргумент, положенный хостом

            push eax                            // сохранить исходный результат
            movzx eax, ax
            push eax                            // now
            movsx eax, word ptr [ebp+8]
            push eax                            // user
            push offset kFmt
            push 6                              // 6 = Log_Operator
            call dword ptr [g_pLog]
            add  esp, 0x10
            pop  eax                            // вернуть результат нетронутым

            jmp  dword ptr [g_pRet]
        }
    }
}

PatchResult P03_OperatorSkillPointLog()
{
    if (!Config::GetBool(L"P03_OperatorSkillPointLog", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kSkillPointLog, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P03", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kSkillPointLog, &SkillPointTrampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P03: перехват @0x%08X (11 б) -> трамплин 0x%08X, возврат 0x%08X",
              Srv::Hooks::kSkillPointLog, (DWORD)&SkillPointTrampoline, g_pRet);
    return PatchResult::Applied;
}
