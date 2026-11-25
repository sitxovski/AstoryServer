// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P08 — ⚠⚠ ОБХОД, НЕ ФИКС. Char_FunctionItem_Use@0x4ED780: снятие проверки
//  подписи пакета. Перенос 1:1 с живого сервера (правка ЧУЖОГО происхождения).
//
//  Сток @0x4ED8CA:
//      movsx ecx, word ptr [ebp+8]        ; userNum
//      push  ecx
//      push  0x89                         ; длина тела
//      mov   edx, dword ptr [ebp+0x0C]    ; пакет
//      push  edx
//      mov   ecx, dword ptr [ebp-0x2F8]   ; CUserManager
//    0x4ED8DE:
//      call  0x523F00                     ; ПРОВЕРКА MD5-ПОДПИСИ ТЕЛА ПАКЕТА
//      test  eax, eax
//      jne   0x4ED929
//
//  Живой сервер (9 байт с 0x4ED8DE):
//      add   esp, 0x10                    ; вручную снять 4 аргумента — вызова нет
//      push  1
//      pop   eax                          ; результат = 1, «как будто проверка прошла»
//      jmp   0x4ED929
//      nop
//
//  ★★ ЧЕМ ЭТО ЯВЛЯЕТСЯ: проверка криптоподписи пакета «использование функционального
//     предмета» ПОЛНОСТЬЮ ОТКЛЮЧЕНА — сервер принимает такие пакеты без проверки
//     целостности. Модифицированный клиент может слать их произвольно.
//  ★★ ЧЕМ ГРОЗИТ ОТКЛЮЧЕНИЕ ПАТЧА (Enabled=0): вернётся штатная проверка. Если
//     обход ставили потому, что подпись у этого опкода в текущей связке
//     клиент/сервер не сходится, использование функциональных предметов начнёт
//     отваливаться у ВСЕХ игроков. Менять только осознанно и с проверкой.
//  По решению юзера значение по умолчанию = 1 (как сейчас на живом сервере).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    // call 0x523F00 ; test eax,eax ; jne 0x4ED929
    const BYTE kOrig[9]  = { 0xE8, 0x1D, 0x66, 0x03, 0x00, 0x85, 0xC0, 0x75, 0x42 };
    // add esp,0x10 ; push 1 ; pop eax ; jmp 0x4ED929 ; nop
    const BYTE kPatch[9] = { 0x83, 0xC4, 0x10, 0x6A, 0x01, 0x58, 0xEB, 0x43, 0x90 };
}

PatchResult P08_FunctionItemUseCheckOff()
{
    if (!Config::GetBool(L"P08_FunctionItemUseCheckOff", L"Enabled", true))
    {
        Log::Line(L"    P08: выключен — штатная проверка подписи в Char_FunctionItem_Use РАБОТАЕТ");
        return PatchResult::Disabled;
    }
    // ★ 2026-10-12 (волна А0, мера 11): P49 FunctionItemMd5Full возвращает проверку подписи,
    //   исправив длину сверки 0x89 → 0x101 (столько подписывает клиент). Тогда обход не нужен
    //   и НЕ ставится — иначе он снова отключил бы проверку. Откат: [P49] FunctionItemMd5Full=0.
    if (P49_FunctionItemMd5FullWanted())
    {
        Log::Line(L"    P08: не ставится — проверку подписи 5450 возвращает P49 (MD5 по 0x101 байт)");
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kFunctionItemUse, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P08", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteBytes(Srv::Hooks::kFunctionItemUse, kPatch, sizeof(kPatch)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P08: @0x%08X снята проверка подписи (результат всегда 1) "
              L"— ! ОБХОД чужого происхождения", Srv::Hooks::kFunctionItemUse);
    return PatchResult::Applied;
}
