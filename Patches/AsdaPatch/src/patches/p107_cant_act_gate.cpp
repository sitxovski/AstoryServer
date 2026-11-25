// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P107 — [ИСПРАВЛЕНИЕ] ОГЛУШЁННЫЙ / ИСПУГАННЫЙ / ПОД «МОЩНЫМ ОГЛУШЕНИЕМ» НЕ АТАКУЕТ И НЕ ПРИМЕНЯЕТ НАВЫКИ (05.11.2026, сессия
//  stun-attack; решение владельца «дефекты оригинала исправляем»). Отчёт: AstoryServer/Docs/GameServer/cant-act-gate-p107.md.
//
//  sub_484E40@0x484E40 (CSkillManager, a2 = userNum, a3 = навык или −1 для удара) — общий гейт «не может действовать»:
//  обычная атака 4026 (Send_CharNormalMonsterAttack, GameServer.c:78392) и 4028 (Send_CharNormalMonsterAttackNext, :78547) —
//  отказ 4027 код 4; навыки RecvChar_SkillUse (:46055, :57135); PvP 4201/4203 (:131001, :131158); :63286.
//  Состояние игрока — запись 24 б на id: байт «активно» [CUser + 0x8F1E + 24·id] (0 лёд 0x8F1E, 1 окаменение 0x8F36,
//  3 «Слабость»-оглушение 0x8F66, 4 страх 0x8F7E, 8 сон 0x8FDE, 11 0x9026, 12 0x903E, 14 «Мощное оглушение» 0x906E).
//  Сток: 0/1 → 1 (нельзя); 3 → ВСЕГДА 0; иначе 4 → ВСЕГДА 0; иначе 8/11/12 → 1; иначе 0.
//
//  ── ДЕФЕКТ ──
//  Ветки 3 и 4 сравнивают a3 с 736 «Сосредоточение» и 984 «Ледяной щит» (навыки, снимающие оглушение и страх) и в обоих исходах
//  возвращают 0 (`je …; xor eax,eax` / `je …; xor eax,eax` → оба пути на 0x484F56). Задумка — «под оглушением/страхом только эти
//  два навыка», итог — оглушённый и испуганный атакуют и применяют ЛЮБЫЕ навыки, а проверки 8/11/12 при 3/4 вообще не идут.
//  Состояние 14 «Мощное оглушение» («не может действовать, не снимается») не проверяется вовсе. Клиент оригинала гейтит те же
//  состояния 0/1/3/4/8/14 (`charHasAnyEquippedItemType@0xA38E40`), а сервер — нет: урон от оглушённого проходит.
//
//  ── ЧТО ДЕЛАЕТ P107 (76 байт в трёх местах, протокол 4027/4029/5257 не меняется) ──
//  R1 0x484EBB (38 б, ветка 3): `movsx eax,a3; cmp 736; je CHK14; cmp 984; je CHK14; mov eax,1; jmp эпилог` + int3.
//  R2 0x484EEF (36 б, ветка 4): `jmp R1` (то же правило) и CHK14 (0x484EF1): `mov ecx,[ebp-4]; movzx edx,[ecx+906Eh]; test;
//     jle 0x484F56 (0); mov eax,1; jmp эпилог` + int3.
//  J12 0x484F4D (2 б): `jle 0x484F56` после проверки 12 → `jle CHK14`.
//  Итог: 0/1 → 1 (сток); 3/4 → 1, кроме 736/984 (→ CHK14); 8/11/12 → 1 (сток, теперь и при 3/4); 14 → 1; иначе 0.
//  Переходов внутрь R1/R2 извне нет, внутренние цели старых ветвей (0x484ECF/EDF/F01/F11) больше не нужны (verify_p107).
//  Ключ [P107_CantActGate] Enabled (0 — сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P107_CantActGate";   // секция patches.ini

    // ── площадки (байты живого GameServer.exe e7b4ac38 = gs_stock) ─────────────
    // R1 0x484EBB: ветка «состояние 3»: movsx eax,a3 · cmp 2E0h · je 0x484ECF · xor eax,eax · jmp 0x484F58 · jmp 0x484EDF ·
    //   movsx ecx,a3 · cmp 3D8h · je 0x484EDF · xor eax,eax · jmp 0x484F58 · jmp 0x484F56.
    const BYTE kR1Orig[] = { 0x0F, 0xBF, 0x45, 0x0C, 0x3D, 0xE0, 0x02, 0x00, 0x00, 0x74, 0x09, 0x33, 0xC0, 0xE9, 0x8B, 0x00, 0x00, 0x00,
                             0xEB, 0x10, 0x0F, 0xBF, 0x4D, 0x0C, 0x81, 0xF9, 0xD8, 0x03, 0x00, 0x00, 0x74, 0x04, 0x33, 0xC0, 0xEB, 0x79,
                             0xEB, 0x75 };
    const BYTE kR1New[]  = { 0x0F, 0xBF, 0x45, 0x0C, 0x3D, 0xE0, 0x02, 0x00, 0x00, 0x74, 0x2B, 0x3D, 0xD8, 0x03, 0x00, 0x00, 0x74, 0x24,
                             0xB8, 0x01, 0x00, 0x00, 0x00, 0xE9, 0x81, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                             0xCC, 0xCC };
    // R2 0x484EEF: ветка «состояние 4» — та же пара сравнений (0x484F01 / 0x484F11).
    const BYTE kR2Orig[] = { 0x0F, 0xBF, 0x4D, 0x0C, 0x81, 0xF9, 0xE0, 0x02, 0x00, 0x00, 0x74, 0x06, 0x33, 0xC0, 0xEB, 0x59, 0xEB, 0x10,
                             0x0F, 0xBF, 0x55, 0x0C, 0x81, 0xFA, 0xD8, 0x03, 0x00, 0x00, 0x74, 0x04, 0x33, 0xC0, 0xEB, 0x47, 0xEB, 0x43 };
    const BYTE kR2New[]  = { 0xEB, 0xCA, 0x8B, 0x4D, 0xFC, 0x0F, 0xB6, 0x91, 0x6E, 0x90, 0x00, 0x00, 0x85, 0xD2, 0x7E, 0x57, 0xB8, 0x01,
                             0x00, 0x00, 0x00, 0xEB, 0x52, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    // J12 0x484F4D: jle 0x484F56 после проверки состояния 12.
    const BYTE kJ12Orig[] = { 0x7E, 0x07 };
    const BYTE kJ12New[]  = { 0x7E, 0xA2 };
    static_assert(sizeof(kR1Orig) == sizeof(kR1New) && sizeof(kR2Orig) == sizeof(kR2New) && sizeof(kJ12Orig) == sizeof(kJ12New), "P107: длины участков");

    // соседи (только сверка): вход ветки 3 (0x484EAD) — mov ecx,[ebp-4] · movzx edx,[ecx+8F66h] · test · jle 0x484EE1;
    //   вход ветки 4 (0x484EE1) — mov edx,[ebp-4] · movzx eax,[edx+8F7Eh] · test · jle 0x484F13; хвост 0x484F44…0x484F5E — проверка 12,
    //   xor eax,eax, эпилог.
    const BYTE kIn3[] = { 0x8B, 0x4D, 0xFC, 0x0F, 0xB6, 0x91, 0x66, 0x8F, 0x00, 0x00, 0x85, 0xD2, 0x7E, 0x26 };
    const BYTE kIn4[] = { 0x8B, 0x55, 0xFC, 0x0F, 0xB6, 0x82, 0x7E, 0x8F, 0x00, 0x00, 0x85, 0xC0, 0x7E, 0x24 };
    const BYTE kTail[] = { 0x0F, 0xB6, 0x91, 0x3E, 0x90, 0x00, 0x00, 0x85, 0xD2, 0x7E, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02,
                           0x33, 0xC0, 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };

    constexpr DWORD kR1 = 0x00484EBB, kR2 = 0x00484EEF, kJ12 = 0x00484F4D;
}

PatchResult P107_CantActGate()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    const Site check[] =
    {
        { kR1, kR1Orig, sizeof(kR1Orig) }, { kR2, kR2Orig, sizeof(kR2Orig) }, { kJ12, kJ12Orig, sizeof(kJ12Orig) },
        { 0x00484EAD, kIn3, sizeof(kIn3) }, { 0x00484EE1, kIn4, sizeof(kIn4) }, { 0x00484F44, kTail, sizeof(kTail) },
    };
    if (!VerifyAllSites(L"P107", check, ARRAYSIZE(check))) { return PatchResult::Mismatch; }

    // Порядок: сперва ветки (R1, R2 — код CHK14), последним — переход J12 на CHK14.
    if (!Hook::WriteBytes(kR1, kR1New, sizeof(kR1New))) { return PatchResult::Failed; }
    if (!Hook::WriteBytes(kR2, kR2New, sizeof(kR2New))) { return PatchResult::Failed; }
    if (!Hook::WriteBytes(kJ12, kJ12New, sizeof(kJ12New))) { return PatchResult::Failed; }
    if (memcmp((const void*)kR1, kR1New, sizeof(kR1New)) != 0 || memcmp((const void*)kR2, kR2New, sizeof(kR2New)) != 0
        || memcmp((const void*)kJ12, kJ12New, sizeof(kJ12New)) != 0)
    {
        return PatchResult::Failed;
    }
    Log::Line(L"    P107: гейт «не может действовать» sub_484E40 — оглушение 3 / страх 4: только навыки 736/984 (сток пускал всё); "
              L"состояние 14 «Мощное оглушение» — нельзя; участки @0x%08X 38 б, @0x%08X 36 б, @0x%08X 2 б", kR1, kR2, kJ12);
    return PatchResult::Applied;
}
