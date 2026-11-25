// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P06 — отправка DB-пакета 2601 (0xA29, 120 б) в sub_4F6650.
//  Перенос 1:1 бинарного кейва живого сервера (0x582900).
//
//  Сток @0x4F6CA5:
//      0x4F6CA5  mov dword ptr [ebp-0x2BD], edx      <-- ЗАМЕНЯЕМ (6 байт)
//      0x4F6CAB  jmp 0x4F6E42
//
//  ★ ВНИМАНИЕ, это не «добавление сбоку»: в ветке, где условие НЕ выполнено,
//    патч уходит на 0x4F6E42 БЕЗ выполнения оригинального `mov [ebp-0x2BD], edx`.
//    То есть исходное сохранение стало условным. Так на живом сервере — переносим
//    как есть, ничего молча не «исправляем».
//
//  ⚠ Назначение — ГИПОТЕЗА: добавлена запись в БД (опкод 2601, длина 120) при
//    условии [ebp-0xD8] == 1.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pGetSeq  = 0x004C0A30;      // __thiscall(...) — порядковый номер для DB-пакета
    DWORD g_pDbSend  = 0x005646C0;      // __thiscall(mgr, __int16 op, __int16 len, ...)
    DWORD g_pRet     = 0x004F6E42;      // общий выход ветки

    // mov dword ptr [ebp-0x2BD], edx
    const BYTE kOrig[6] = { 0x89, 0x95, 0x43, 0xFD, 0xFF, 0xFF };

    __declspec(naked) void Db2601Trampoline()
    {
        __asm
        {
            cmp  byte ptr [ebp-0x0D8], 1
            jne  finish                          // условие не выполнено -> сразу на выход

            mov  dword ptr [ebp-0x2BD], edx     // оригинальная инструкция
            mov  eax, dword ptr [ebp-0x2A]
            mov  dword ptr [ebp-0x2B9], eax

            mov  ax, word ptr [ebp-8]
            push eax
            lea  eax, [ebp-0x328]
            push eax
            mov  eax, dword ptr [ebp-0x344]
            mov  ecx, dword ptr [eax+4]
            call dword ptr [g_pGetSeq]
            push eax
            push 0x78                           // длина 120
            push 0x0A29                         // опкод 2601
            mov  ecx, 0x007E0538
            call dword ptr [g_pDbSend]
        finish:
            jmp  dword ptr [g_pRet]
        }
    }
}

PatchResult P06_Db2601Send()
{
    if (!Config::GetBool(L"P06_Db2601Send", L"Enabled", true)) { return PatchResult::Disabled; }

    const Site sites[] = { { Srv::Hooks::kDb2601, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P06", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kDb2601, &Db2601Trampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P06: перехват @0x%08X (6 б) -> трамплин 0x%08X, выход 0x%08X",
              Srv::Hooks::kDb2601, (DWORD)&Db2601Trampoline, g_pRet);
    return PatchResult::Applied;
}
