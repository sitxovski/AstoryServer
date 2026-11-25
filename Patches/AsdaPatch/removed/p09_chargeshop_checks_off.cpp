// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P09 — ⚠⚠ ОБХОД, НЕ ФИКС. CharChargeShopBuy@0x511DA0: четыре снятые проверки.
//  Перенос 1:1 с живого сервера (правка ЧУЖОГО происхождения).
//
//  Все четыре площадки в стоке выглядят одинаково:
//      mov ecx, dword ptr [0x5F5E9C]      ; таблица кэш-магазина
//      mov edx, dword ptr [ebp-0x410]     ; значение, пришедшее от клиента
//      cmp edx, dword ptr [ecx+eax*4]     ; сверка с таблицей
//      je  <дальше>                       <-- 74 34   ЗАМЕНЯЕТСЯ на EB 34 (jmp)
//      mov byte ptr [ebp-0x1A8], 0x0E     ; иначе — код ошибки 14 и отказ
//
//  ★★ ЧЕМ ЭТО ЯВЛЯЕТСЯ: сверка значения из пакета покупки со справочной таблицей
//     `dword_5F5E9C` больше не выполняется — переход стал безусловным, ветка
//     «ошибка 14» недостижима. Сервер принимает значение клиента как есть.
//  ★★ ЧЕМ ГРОЗИТ ОТКЛЮЧЕНИЕ ПАТЧА (Enabled=0): вернутся штатные проверки. Если
//     таблица кэш-магазина на сервере не совпадает с тем, что шлёт текущий клиент,
//     часть покупок начнёт отклоняться с ошибкой 14. Менять только осознанно.
//  По решению юзера значение по умолчанию = 1 (как сейчас на живом сервере).
//
//  ★ Замечание из дифа стоков: в стоке (и в Indun_GameServer, который стоковый)
//    здесь `74` — проверки ВКЛЮЧЕНЫ. Снимает их именно этот патч.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const DWORD kSites[4] =
    {
        Srv::Hooks::kChargeShop1,   // 0x5120B2
        Srv::Hooks::kChargeShop2,   // 0x5120FF
        Srv::Hooks::kChargeShop3,   // 0x512725
        Srv::Hooks::kChargeShop4,   // 0x512772
    };
    const BYTE kOrigByte  = 0x74;   // je  rel8
    const BYTE kPatchByte = 0xEB;   // jmp rel8
}

PatchResult P09_ChargeShopBuyChecksOff()
{
    if (!Config::GetBool(L"P09_ChargeShopBuyChecksOff", L"Enabled", true))
    {
        Log::Line(L"    P09: выключен — штатные проверки CharChargeShopBuy РАБОТАЮТ");
        return PatchResult::Disabled;
    }

    Site sites[4];
    for (int i = 0; i < 4; ++i) { sites[i].va = kSites[i]; sites[i].orig = &kOrigByte; sites[i].len = 1; }
    if (!VerifyAllSites(L"P09", sites, 4)) { return PatchResult::Mismatch; }

    for (int i = 0; i < 4; ++i)
    {
        if (!Hook::WriteBytes(kSites[i], &kPatchByte, 1)) { return PatchResult::Failed; }
    }

    Log::Line(L"    P09: 4 перехода je -> jmp (0x%08X, 0x%08X, 0x%08X, 0x%08X) "
              L"— ! ОБХОД чужого происхождения",
              kSites[0], kSites[1], kSites[2], kSites[3]);
    return PatchResult::Applied;
}
