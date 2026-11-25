// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P85 — [ИСПРАВЛЕНИЕ] 25.10.2026 ПРЕМИУМ-КОРЗИНА ЦЕЛИКОМ: ВСЕ КОДЫ ПАКЕТА 5070 УХОДЯТ ШЛЮЗУ GP7.
//  Слово владельца: «Корзина из нескольких позиций должна проходить! … в премиум ящике каждый ряд имеет несколько
//  ячеек, а клался всегда 1 предмет». Дефект оригинала. Пара: DBPatch P85 (список ящика до 49 записей),
//
//  ── ЧТО В СТОКЕ (GameServer.c, сверено по дизасму живого образа MD5 e7b4ac38…) ─────────────────────────────
//  CharChargeShopBuy@0x511DA0 разбирает до 7 кодов 5070, кладёт по записи 55 б на каждый годный код в
//  структуру корзины (+23 + 55·i: код @0) и суммирует цены в BuyCash (+17). Затем sub_4F60E0, ветка 137
//  («Premium Item Buy Request», 0x4F61B0…0x4F62D5): копия корзины на стеке [ebp-0x2A8] (rep movsd 0x66),
//  запрос шлюзу 173 б на [ebp-0x110], в нём ТОЛЬКО код записи 0 (@66 ← [ebp-0x291]) и вся сумма (@104).
//  Ответ шлюза несёт один код → SendNewPremiumPacket(Count 1) → DB 2601 → одна строка ItemPostbox.
//
//  ── ПРАВКА ──────────────────────────────────────────────────────────────────────────────────────────────
//  Площадка 0x4F62AC (9 б, перед вызовом отправки 0x5646C0):  mov eax,[ebp-0x608] / mov ecx,[eax+4]
//  → трамплин: дописать в хвост запроса (поле «channel%d» @112, 61 б, обнулено конструктором sub_4F9D00, строка
//  занимает ≤ 10 б) РАСШИРЕНИЕ КОРЗИНЫ, затем те же две инструкции и возврат на 0x4F62B5.
//      @128  4 б  метка 'C','R','T','7'
//      @132  7×4  коды записей 0…6 корзины (0 = пустая/негодная позиция — сток её не записал и не посчитал)
//      @160  1 б  число непустых позиций
//  Размер и разметка запроса не меняются (173 б), стоковые поля не тронуты; шлюз без поддержки метки её не читает.
//  Шлюз (server.js, 25.10) по метке сверяет сумму с ценами ВСЕХ позиций, списывает один раз и пишет позиции в
//  Joy1.dbo.ItemPostBoxCart под номером заказа; UPCashitemBuy раскладывает их строками одного заказа.
//
//  ★ r2 (25.10.2026): в расширение идут коды САМОГО пакета 5070 (метка 'CRT8') — смешанная корзина одним пакетом; разбор
//    у P85_OnCartRequest ниже.
//  Журнал ac.other: 100 — передана корзина из ≥ 2 позиций (value1 = позиций, value2 = BuyCash, item_code = код 0);
//  101 — в корзине ни одного кода (расширение не пишется). Откат: patches.ini [P85_PremiumCartRows] Enabled=0 —
//  тогда шлюз видит стоковый запрос и (ключ rejectCartTotal) отказывает корзине без списания.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"

namespace
{
    constexpr DWORD kSite    = 0x004F62AC;   // mov eax,[ebp-0x608] ; mov ecx,[eax+4]
    constexpr DWORD kSiteLen = 9;
    DWORD g_pRet = 0x004F62B5;               // call 0x4C0250 (дальше — отправка 0x5646C0)

    const BYTE kOrig[kSiteLen] =
    {
        0x8B, 0x85, 0xF8, 0xF9, 0xFF, 0xFF,   // mov eax, dword ptr [ebp-0x608]
        0x8B, 0x48, 0x04                      // mov ecx, dword ptr [eax+4]
    };

    constexpr int kExtMagicOff = 128;        // метка расширения в запросе шлюзу
    constexpr int kExtCodesOff = 132;        // 7 кодов
    constexpr int kExtCountOff = 160;        // число позиций
    constexpr int kCartRecOff  = 23;         // запись i корзины: +23 + 55·i
    constexpr int kCartRecSize = 55;
    constexpr int kCartSumOff  = 17;         // BuyCash
    constexpr int kSlots       = 7;

    volatile LONG g_carts = 0;               // корзин ≥ 2 позиций передано (для лога остановки/стенда)

    void Journal(BYTE kind, int num, int v0, int v1, int code)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = 5070;
        e.userNum = (short)num;
        e.ip = P47_PeerIpv4(num);
        e.v[0] = v0;
        e.v[1] = v1;
        e.v[2] = code;
        AcJournal::CopyText(e, "CharChargeShopBuy → GP7 (ветка 137)");
        AcJournal::Push(e);
    }
}

// ★ r2 (25.10.2026, баг владельца «купил 7 — в строке 6»): смешанная корзина (item_list + special_itemlist). Байт +1 «таблица»
//   у пакета 5070 один; CharChargeShopBuy@0x511DA0 в ветке своей таблицы молча ПРОПУСКАЕТ коды другой — их нет ни в записях
//   корзины, ни в BuyCash. Клиент alpha-2.0.3 поэтому слал смешанную корзину ДВУМЯ пакетами → два заказа → две строки ящика
//   (6 спец-позиций одной строкой, 1 позиция item_list — второй; заказы 12812 и 12811 владельца 25.10 10:36:53).
//   Теперь в расширение уходят коды САМОГО ПАКЕТА клиента: CharChargeShopBuy держит его тело на стеке [ebp-0x408]
//   (memcpy 0xAB с пакета+33 @0x511EF4), а в sub_4F60E0 передаёт &[ebp-0x350] (@0x512B93) — то есть тело пакета = a4 − 0xB8.
//   Шлюз сверяет BuyCash с суммой позиций ТОЙ таблицы, что посчитал сервер, и списывает за ВСЕ — один заказ, одна строка.
//      @128  4 б  метка 'C','R','T','8' (r1: 'CRT7' — коды записей корзины)
//      @132  7×4  коды пакета 5070 по слотам (≤ 0 → 0)
//      @160  1 б  число непустых кодов пакета
//      @161  1 б  байт +1 пакета «таблица» (1 = item_list, 0 = special_itemlist)
//      @162  1 б  сколько позиций сервер принял в запись корзины (их цены и есть BuyCash)
//   Тело пакета не читается — пишется r1 'CRT7' (коды записей), шлюз обработает как раньше.
constexpr int kPktFromCart = 0xB8;           // тело пакета 5070 = a4 − 0xB8 (кадр CharChargeShopBuy)

// Записать расширение корзины в запрос шлюзу. req — 173 б запроса, cart — копия структуры корзины (408 б),
//   cartOrig — указатель a4 на структуру в кадре CharChargeShopBuy (рядом с ней — тело пакета клиента).
extern "C" void __stdcall P85_OnCartRequest(int num, BYTE* req, const BYTE* cart, const BYTE* cartOrig)
{
    __try
    {
        int rec[kSlots] = {};
        int nRec = 0;
        for (int i = 0; i < kSlots; ++i)
        {
            const int c = *(const int*)(cart + kCartRecOff + kCartRecSize * i);
            rec[i] = (c > 0) ? c : 0;
            if (c > 0) { ++nRec; }
        }
        int raw[kSlots] = {};
        int nRaw = 0;
        BYTE table = 0;
        bool rawOk = false;
        __try
        {
            const BYTE* pkt = cartOrig - kPktFromCart;
            table = pkt[1];
            for (int i = 0; i < kSlots; ++i)
            {
                const int c = *(const int*)(pkt + 3 + 4 * i);
                raw[i] = (c > 0) ? c : 0;
                if (c > 0) { ++nRaw; }
            }
            rawOk = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { rawOk = false; }
        if (rawOk && nRaw > 0)
        {
            req[kExtMagicOff + 0] = 'C';
            req[kExtMagicOff + 1] = 'R';
            req[kExtMagicOff + 2] = 'T';
            req[kExtMagicOff + 3] = '8';
            for (int i = 0; i < kSlots; ++i) { *(int*)(req + kExtCodesOff + 4 * i) = raw[i]; }
            req[kExtCountOff] = (BYTE)nRaw;
            req[kExtCountOff + 1] = table;
            req[kExtCountOff + 2] = (BYTE)nRec;
            if (nRaw >= 2)
            {
                InterlockedIncrement(&g_carts);
                Journal(100, num, nRaw, *(const int*)(cart + kCartSumOff), raw[0]);
            }
            return;
        }
        if (nRec == 0)
        {
            Journal(101, num, 0, *(const int*)(cart + kCartSumOff), 0);
            return;
        }
        req[kExtMagicOff + 0] = 'C';
        req[kExtMagicOff + 1] = 'R';
        req[kExtMagicOff + 2] = 'T';
        req[kExtMagicOff + 3] = '7';
        for (int i = 0; i < kSlots; ++i) { *(int*)(req + kExtCodesOff + 4 * i) = rec[i]; }
        req[kExtCountOff] = (BYTE)nRec;
        if (nRec >= 2)
        {
            InterlockedIncrement(&g_carts);
            Journal(100, num, nRec, *(const int*)(cart + kCartSumOff), rec[0]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Запрос уходит стоковым (без расширения) — шлюз отработает его по-старому.
    }
}

namespace
{
    __declspec(naked) void CartRequestTrampoline()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp+0x10]           // a4 — структура корзины в кадре CharChargeShopBuy (тело пакета = a4 − 0xB8)
            lea   eax, [ebp-0x2A8]               // копия корзины (v50)
            push  eax
            lea   eax, [ebp-0x110]               // запрос шлюзу (v51, 173 б)
            push  eax
            movsx eax, word ptr [ebp+0x0C]       // userNum (a3)
            push  eax
            call  P85_OnCartRequest              // __stdcall, чистит 4 аргумента
            popad
            // ── оригинальные инструкции ──
            mov   eax, dword ptr [ebp-0x608]
            mov   ecx, dword ptr [eax+4]
            jmp   dword ptr [g_pRet]
        }
    }
}

PatchResult P85_PremiumCartRows()
{
    if (!Config::GetBool(L"P85_PremiumCartRows", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    const Site sites[] = { { kSite, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P85", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &CartRequestTrampoline, kSiteLen))
    {
        return PatchResult::Failed;
    }
    Log::Line(L"    P85: 0x%08X (9 б, ветка 137 sub_4F60E0) -> трамплин 0x%08X, возврат 0x%08X: "
              L"коды корзины 5070 в хвост запроса шлюзу (r2: @128 'CRT8', @132 7×код пакета, @160 число, @161 таблица, @162 принято)",
              kSite, (DWORD)&CartRequestTrampoline, g_pRet);
    return PatchResult::Applied;
}
