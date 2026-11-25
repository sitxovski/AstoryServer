// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P43 — ★ ПОТОЛОК ЦЕНЫ ЛИЧНОЙ ЛАВКИ 100 млн → 1 млрд + защита от переполнения int32
//  [ОРИГИНАЛ/НАСТРОЙКА] решение владельца 27.09.2026.
//  Разбор: Reports/owner_0927/world_data_0927.md #18 + независимый реверс тракта покупки;
//  документ — AstoryServer/Docs/GameServer/store-price-cap-p43.md
//
//  ── ЧТО ──
//  Личная лавка (StreetStall, опкоды 6300..6306) держит цену как int32 и в ДВУХ местах сверяет
//  её с потолком 100 000 000 (0x05F5E100):
//    • ОТКРЫТИЕ  CharSelfStoreOpen@0x502E50: цена ЗА ЕДИНИЦУ (v26) — cmp @0x503386, imm @0x50338C.
//    • ПОКУПКА   CharSelfStoreBuyItem@0x504E70: СУММА лота (v80 = кол-во × цена) — cmp @0x5056CF,
//      imm @0x5056D5. ★ Поднять НАДО ОБА: иначе лот дороже 100 млн открыть можно, а купить —
//      нет (молча «Wrong Price», нотис 6310).
//  Поднимаем оба потолка до 1 000 000 000 (0x3B9ACA00). Для amount=1 покупка идёт при цене до
//  1 млрд; для стопок ограничение — сумма лота ≤ 1 млрд.
//
//  ── ЗАЩИТА ОТ ПЕРЕПОЛНЕНИЯ int32 (кол-во × цена) ──
//  При 1 млрд произведение кол-во×цена может превысить 2^31. Штатные проверки ловят только
//  переход в ОТРИЦАТЕЛЬНОЕ (v<=0); переход в МАЛОЕ ПОЛОЖИТЕЛЬНОЕ (обёртка ≤ потолка) проходил
//  бы с ТИХО заниженной суммой (дюпа денег нет — золото i32 сохраняется, страдает продавец).
//  Три умножения/суммы (все — signed `imul`/`add`, ставят OF при переполнении):
//    G1 Open  @0x503338  imul ecx,[ebp+eax-0x44c]   (v27 = кол-во×цена, валидация открытия)
//    G2 Buy   @0x505689  imul edx,[ebp-0x364]        (v80 = кол-во×цена, сумма лота)
//    G3 Buy   @0x5056AA  imul edx,[ebp-0x364]; add edx,[ebp-0x4e4]  (v44 += сумма лота, итог)
//  На переполнение (OF) трамплин обнуляет результат (v27/v80/v44 = 0) — и штатная проверка
//  «<= 0» отклоняет лот/покупку ТЕМ ЖЕ путём, что и любую недопустимую цену (6303 при открытии,
//  6310 при покупке). Новых пакетов нет, протокол не меняется.
//
//  ── ЧЕГО НЕ ДЕЛАЕМ (описано в документе) ──
//  Накопление золота ПРОДАВЦА (CalcGameMoneyItemAmount@0x4D7540, add без верхнего предела) может
//  переполнить i32 за много продаж — но этот риск СУЩЕСТВОВАЛ и при 100 млн (нужно ~21 продажа
//  ≈2.1 млрд) и поднятием потолка НЕ создаётся заново; покупатель физически не может заплатить
//  сумму > 2^31 (его золото i32, гейт «денег < суммы» отклоняет). Отдельная правка не делается.
//  Кэш-шоп CharChargeShopBuy@0x512xxx (cmp 100M @0x5124FB) — ВНЕ лавки, НЕ трогаем.
//
//  ── ПЛОЩАДКИ (сверены с живым GameServer, Indun и базой IDA, md5 e7b4ac38; с P01…P42 не пересекается) ──
//    caps:  0x50338C (4 б imm) 00 E1 F5 05 → 00 CA 9A 3B; 0x5056D5 (4 б imm) 00 E1 F5 05 → 00 CA 9A 3B
//    guards: 0x503338 (8 б → StubOpenMul), 0x505689 (7 б → StubBuyMul1), 0x5056AA (13 б → StubBuyMul2)
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P43_StorePriceCap";

    constexpr int kNewCap = 1000000000;      // 0x3B9ACA00 (было 0x05F5E100 = 100 млн)

    // деньги игрока (золото i32): thiscall(mgr, num) -> gold, -1 если игрок не найден. 0x4D7690.
    typedef int (__thiscall *FnGetMoney)(void* mgr, short num);
    const FnGetMoney GetMoney = (FnGetMoney)0x004D7690;

    // ── потолки (imm32 инструкций cmp) ──
    struct CapSite { DWORD ctxVA; BYTE ctx[10]; DWORD immVA; };
    const CapSite kOpenCap = { 0x00503386, { 0x81, 0xBD, 0x9C, 0xFB, 0xFF, 0xFF, 0x00, 0xE1, 0xF5, 0x05 }, 0x0050338C };
    const CapSite kBuyCap  = { 0x005056CF, { 0x81, 0xBD, 0x90, 0xFE, 0xFF, 0xFF, 0x00, 0xE1, 0xF5, 0x05 }, 0x005056D5 };

    // ── адреса продолжения после трамплинов (host VA, косвенный jmp) ──
    DWORD g_open_resume = 0x00503340;        // за imul (mov [ebp-0x460],ecx)
    DWORD g_buy1_resume = 0x00505690;        // за imul (mov [ebp-0x170],edx)
    DWORD g_buy2_resume = 0x005056B7;        // за imul+add (mov [ebp-0x4e4],edx)

    // G1 Open: v27 = кол-во × цена. Переполнение -> ecx=0 -> штатная проверка v27<=0 отклонит.
    __declspec(naked) void StubOpenMul()
    {
        __asm
        {
            imul ecx, dword ptr [ebp+eax-0x44c]
            jno  ok
            xor  ecx, ecx
        ok:
            jmp  dword ptr [g_open_resume]
        }
    }

    // G2 Buy: v80 = кол-во × цена (сумма лота). Переполнение -> edx=0 -> штатная проверка v80<=0.
    __declspec(naked) void StubBuyMul1()
    {
        __asm
        {
            imul edx, dword ptr [ebp-0x364]
            jno  ok
            xor  edx, edx
        ok:
            jmp  dword ptr [g_buy1_resume]
        }
    }

    // G3 Buy: v44 += кол-во × цена (итог по лотам). Переполнение imul ИЛИ add -> edx=0 -> v44<=0.
    __declspec(naked) void StubBuyMul2()
    {
        __asm
        {
            imul edx, dword ptr [ebp-0x364]
            jo   bad
            add  edx, dword ptr [ebp-0x4e4]
            jno  ok
        bad:
            xor  edx, edx
        ok:
            jmp  dword ptr [g_buy2_resume]
        }
    }

    // ── СРЕДН-3: зачисление продавцу не переполняет i32 (иначе штатный отказ 6310 код 6) ──
    DWORD g_sell_ok  = 0x00505C19;    // v39==0 -> покупка идёт
    DWORD g_sell_rej = 0x00505BDC;    // v39!=0 -> стоковый отказ 6310 (сброс + отправка)

    // 1 — зачисление v44 продавцу переполнило бы int32.
    int __cdecl P43_SellerOverflow(void* mgr, int sellerNum, int v44)
    {
        if (!mgr || v44 <= 0) { return 0; }
        __try
        {
            const int gold = GetMoney(mgr, (short)sellerNum);
            if (gold <= 0) { return 0; }
            return ((long long)gold + (long long)v44 > 0x7FFFFFFFLL) ? 1 : 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // Площадка 0x505BD3 (после стоковых проверок покупки, перед `if(v39)`). Стоковые байты:
    //   cmp [ebp-0x4f8],0 ; je 0x505C19  (v39==0 -> покупка). Добавляем: если зачисление продавцу
    //   переполнит i32 — ставим код 6 (v82[0]) и v39=1, дальше штатный путь отказа (6310).
    //   Раскладка кадра CharSelfStoreBuyItem: mgr [ebp-0x53c], продавец [ebp-0x490] (word),
    //   v44 [ebp-0x4e4], код v82[0] [ebp-0x168], v39 [ebp-0x4f8].
    __declspec(naked) void StubSellerCap()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0x4e4]           // v44
            push  eax
            movzx eax, word ptr [ebp-0x490]  // номер продавца
            push  eax
            mov   eax, [ebp-0x53c]           // mgr
            push  eax
            call  P43_SellerOverflow
            add   esp, 12
            test  eax, eax
            jz    nover
            mov   byte  ptr [ebp-0x168], 6   // код отказа «не хватает денег» (штатный 6310 код 6)
            mov   dword ptr [ebp-0x4f8], 1   // v39 = 1 (отказ)
        nover:
            popad
            cmp   dword ptr [ebp-0x4f8], 0   // доиграть стоковую развязку
            je    ok
            jmp   dword ptr [g_sell_rej]
        ok:
            jmp   dword ptr [g_sell_ok]
        }
    }
    const BYTE kSeller[] = { 0x83, 0xBD, 0x08, 0xFB, 0xFF, 0xFF, 0x00, 0x74, 0x3D }; // 0x505BD3 (9)

    // байты умножений (сверка до записи)
    const BYTE kOpenMul[] = { 0x0F, 0xAF, 0x8C, 0x05, 0xB4, 0xFB, 0xFF, 0xFF };                       // 0x503338 (8)
    const BYTE kBuyMul1[] = { 0x0F, 0xAF, 0x95, 0x9C, 0xFC, 0xFF, 0xFF };                             // 0x505689 (7)
    const BYTE kBuyMul2[] = { 0x0F, 0xAF, 0x95, 0x9C, 0xFC, 0xFF, 0xFF, 0x03, 0x95, 0x1C, 0xFB, 0xFF, 0xFF }; // 0x5056AA (13)
}

PatchResult P43_StorePriceCap()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    const bool doGuard = Config::GetBool(S, L"GuardOverflow", true);

    // Сверка ВСЕХ площадок до первой записи.
    Site sites[6];
    int n = 0;
    sites[n++] = { kOpenCap.ctxVA, kOpenCap.ctx, sizeof(kOpenCap.ctx) };
    sites[n++] = { kBuyCap.ctxVA,  kBuyCap.ctx,  sizeof(kBuyCap.ctx)  };
    sites[n++] = { 0x00503338, kOpenMul, sizeof(kOpenMul) };
    sites[n++] = { 0x00505689, kBuyMul1, sizeof(kBuyMul1) };
    sites[n++] = { 0x005056AA, kBuyMul2, sizeof(kBuyMul2) };
    sites[n++] = { 0x00505BD3, kSeller,  sizeof(kSeller)  };
    if (!VerifyAllSites(L"P43", sites, n)) { return PatchResult::Mismatch; }

    // Потолки (оба обязательны).
    const BYTE cap[4] = { (BYTE)(kNewCap & 0xFF), (BYTE)((kNewCap >> 8) & 0xFF),
                          (BYTE)((kNewCap >> 16) & 0xFF), (BYTE)((kNewCap >> 24) & 0xFF) };
    if (!Hook::WriteBytes(kOpenCap.immVA, cap, 4)) { return PatchResult::Failed; }
    if (!Hook::WriteBytes(kBuyCap.immVA,  cap, 4)) { return PatchResult::Failed; }

    // Защита от переполнения (3 трамплина).
    int guards = 0;
    if (doGuard)
    {
        if (!Hook::WriteJmp(0x00503338, (const void*)&StubOpenMul, sizeof(kOpenMul))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x00505689, (const void*)&StubBuyMul1, sizeof(kBuyMul1))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x005056AA, (const void*)&StubBuyMul2, sizeof(kBuyMul2))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x00505BD3, (const void*)&StubSellerCap, sizeof(kSeller))) { return PatchResult::Failed; }
        guards = 4;
    }

    Log::Line(L"    P43: потолок цены личной лавки 100млн -> 1млрд (0x50338C и 0x5056D5); "
              L"защита от переполнения int32 (кол-во×цена + зачисление продавцу) — трамплинов %d", guards);
    return PatchResult::Applied;
}
