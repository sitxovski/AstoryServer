// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P85 (DBManager) — [ИСПРАВЛЕНИЕ] 25.10.2026 ПРЕМИУМ-ПОЧТА: СПИСОК ДО 49 ЗАПИСЕЙ (7 строк окна × 7 ячеек).
//
//  ── ЧТО В СТОКЕ ──────────────────────────────────────────────────────────────
//  Обработчик DB 2602 (список ящика) — sub_43EF50@0x43EF50 (DBManager.exe.c:29369):
//      EXEC UPCashitemList → Size = строк × 10;  if (Size > 0x46) → «UPCashitemList return data is SizeOver…!»
//      и в 2603 уходит ПУСТОЙ список (признак 0). 0x46 = 70 байт = ровно 7 записей 11005 (Order, Code, Count, Type).
//  Окно 69000 оригинала — 7 строк × 7 ячеек (69011…69017 … 69071…69077, JUI gamemain_jui.ini), а строка ящика
//  несла одну запись (один код × Count). Корзина из нескольких позиций — это НЕСКОЛЬКО записей с одним Orderidx
//  (строка на штуку, см. шапку SQL), поэтому 7 заказов = до 49 записей.
//
//  ── ПРАВКА ────────────────────────────────────────────────────────────────────
//  Площадка 0x43F0DC (9 б):  cmp dword ptr [ebp-0x3D88], 0x46  /  jbe 0x43F142
//  → jmp на трамплин: cmp dword ptr [ebp-0x3D88], 490 (= 49 × 10) / jbe 0x43F142 / jmp 0x43F0E5 (ветка SizeOver).
//  Буферы хватают с запасом: приёмник процедуры v24 = 14 000 б, тело 2603 v22 = 650 б (5 + 490), у GameServer
//  RecvDB_PremiumItemList_Res@0x4F8050 — 649 б (4 + 490), число записей он не ограничивает (len % 10 == 0).
//  Протокол 2603/11005 не меняется: та же запись 10 б, просто их больше 7. Клиент порта собирает строки по Orderidx.
//  ⚠ Старый (стоковый) клиент рассчитан на 7 записей (переполнение стека) — им никто не играет; клиент порта
//    клампит приём (исправление дефекта C) и с 25.10 принимает до 49.
//
//  Журнал: ac.other вид 102 — список упёрся в потолок (> 490 байт, ветка SizeOver): процедура вернула больше
//  Откат: ConfigSet\patches.ini [P85_DbPostRows] Enabled=0 (тогда ставить и откат SQL — иначе список корзины пуст).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "AcJournal.h"

namespace
{
    const wchar_t* const S = L"P85_DbPostRows";

    constexpr DWORD kSite     = 0x0043F0DC;   // cmp dword ptr [ebp-0x3D88], 0x46 ; jbe 0x43F142
    constexpr DWORD kSiteLen  = 9;
    DWORD g_pOk      = 0x0043F142;            // ветка «размер в норме» (разбор записей)
    DWORD g_pOver    = 0x0043F0E5;            // ветка SizeOver (лог + пустой список)
    DWORD g_maxBytes = 490;                   // 49 записей × 10 б

    const BYTE kOrig[kSiteLen] =
    {
        0x83, 0xBD, 0x78, 0xC2, 0xFF, 0xFF, 0x46,   // cmp dword ptr [ebp-0x3D88], 0x46
        0x76, 0x5D                                  // jbe 0x43F142
    };

    // Журнал вида 102: размер ответа процедуры сверх нового потолка.
    extern "C" void __stdcall P85Db_OnOver(int size)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, 102);
        e.opcode = 2602;
        e.v[0] = size;
        e.v[1] = (int)g_maxBytes;
        AcJournal::CopyText(e, "UPCashitemList > 49 записей: список ящика пуст (SizeOver)");
        AcJournal::Push(e);
    }

    __declspec(naked) void ListCapTrampoline()
    {
        __asm
        {
            push  eax
            mov   eax, dword ptr [g_maxBytes]
            cmp   dword ptr [ebp-0x3D88], eax
            pop   eax
            jbe   ok_size
            pushad
            push  dword ptr [ebp-0x3D88]
            call  P85Db_OnOver
            popad
            jmp   dword ptr [g_pOver]
        ok_size:
            jmp   dword ptr [g_pOk]
        }
    }
}

PatchResult P85_DbPostRows()
{
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    const Site sites[] = { { kSite, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P85db", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &ListCapTrampoline, kSiteLen))
    {
        return PatchResult::Failed;
    }
    Log::Line(L"    P85db: 0x%08X cmp Size,0x46 -> трамплин 0x%08X: потолок списка ящика %u б (49 записей 11005)",
              kSite, (DWORD)&ListCapTrampoline, g_maxBytes);
    return PatchResult::Applied;
}
