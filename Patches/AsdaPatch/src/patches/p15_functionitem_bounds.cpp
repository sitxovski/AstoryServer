// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P15 — ★ ЗАЩИТА ОТ УДАЛЁННОГО ПАДЕНИЯ СЕРВЕРА. Char_FunctionItem_Use@0x4ED780
//  (опкод 5450): проверка диапазона кода предмета перед обращением к Function_Table.
//
//  ЭТО НАША ПРАВКА, а не перенос чужой. Дефект найден аудитом 2026-08-17
//  (Reports/server_bypass_audit_p08_p09.md §4.1 п.4) и существует в СТОКЕ.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  `iCode` приходит из тела пакета (payload+2) и кладётся в `[ebp-0x1FE]`. Дальше он
//  используется как индекс БЕЗ ЕДИНОЙ ПРОВЕРКИ — шесть обращений подряд, первое:
//      004ED9EF  8B 85 02 FE FF FF   mov   eax, [ebp-0x1FE]      ; iCode
//      004ED9F5  83 E8 01            sub   eax, 1
//      004ED9F8  6B C0 30            imul  eax, eax, 0x30        ; stride 48
//      004ED9FB  8B 0D 70 5E 5F 00   mov   ecx, [0x5F5E70]       ; Function_Table
//      004EDA01  0F B6 54 01 08      movzx edx, byte [ecx+eax+8] ; ← чтение по (iCode-1)*48
//  При произвольном i32 в `iCode` адрес улетает куда угодно ⇒ access violation ⇒
//  ПАДЕНИЕ GameServer ОДНИМ ПАКЕТОМ. Для сравнения: в 5070 такой bounds-check есть.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Штатной функцией самого сервера `sub_532B10` (__cdecl(int code) → 1/0):
//      cmp [ebp+8], 1 ; jl → 0 ; cmp eax, [0x5F5EA4] ; jg → 0 ; иначе 1
//  где `0x5F5EA4` — число записей `Function_Table.txt`. Что это именно её счётчик,
//  проверено по загрузчику: @0x004AFA11 `mov [0x5F5EA4], eax` стоит в функции, которая
//  открывает ".\ItemTable_Info\Function_Table.txt" и выделяет count × 0x30 байт —
//  тот же stride 48, что и у обращения выше.
//
//  ── КУДА УХОДИМ ПРИ ОТКАЗЕ ──
//  Ровно туда же, куда уходит соседняя штатная проверка этой же функции:
//      004ED9DE  C6 85 DF FE FF FF 00   mov byte [ebp-0x121], 0   ; код результата
//      004ED9E5  E9 D9 16 00 00         jmp 0x4EF0C3              ; общий выход
//  То есть клиент получает штатный отказ, а не разрыв соединения.
//
//  ⚠ Патч НЕ является заменой P08: тот про подпись (и про неё аудит показал, что
//    проверка бесполезна — MD5 без соли), а этот закрывает реальную дыру.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pIsValidFuncCode = 0x00532B10;   // __cdecl(int code) → 1, если 1 <= code <= [0x5F5EA4]
    DWORD g_pRet             = 0x004ED9F5;   // возврат: сразу за перехваченными 6 байтами
    DWORD g_pReject          = 0x004EF0C3;   // общий выход функции (тот же, что у штатного отказа)

    const BYTE kOrig[6] =
    {
        0x8B, 0x85, 0x02, 0xFE, 0xFF, 0xFF     // mov eax, dword ptr [ebp-0x1FE]
    };

    __declspec(naked) void FunctionItemBoundsTrampoline()
    {
        __asm
        {
            // ── проверка диапазона кода ──
            mov   eax, dword ptr [ebp-0x1FE]     // iCode из тела пакета
            push  eax
            call  dword ptr [g_pIsValidFuncCode] // __cdecl: аргумент снимаем сами
            add   esp, 4
            test  eax, eax
            jz    Reject

            // ── код в диапазоне: воспроизводим оригинальную инструкцию и возвращаемся ──
            mov   eax, dword ptr [ebp-0x1FE]
            jmp   dword ptr [g_pRet]

        Reject:
            // Тот же отказ, что у штатной соседней проверки (@0x4ED9DE): код результата 0
            // и общий выход. Соединение не рвём, пакет просто отклоняется.
            mov   byte ptr [ebp-0x121], 0
            jmp   dword ptr [g_pReject]
        }
    }
}

PatchResult P15_FunctionItemCodeBounds()
{
    if (!Config::GetBool(L"P15_FunctionItemCodeBounds", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kFunctionItemBounds, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P15", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kFunctionItemBounds, &FunctionItemBoundsTrampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P15: перехват @0x%08X (6 б) -> трамплин 0x%08X, возврат 0x%08X, отказ 0x%08X",
              Srv::Hooks::kFunctionItemBounds, (DWORD)&FunctionItemBoundsTrampoline, g_pRet, g_pReject);
    Log::Line(L"    P15: код предмета 5450 проверяется через sub_532B10 (1..[0x5F5EA4]) — закрыт "
              L"выход за границу Function_Table (падение сервера одним пакетом)");
    return PatchResult::Applied;
}
