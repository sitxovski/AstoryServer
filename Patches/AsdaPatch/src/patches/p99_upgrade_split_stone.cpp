// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P99 — [ИСПРАВЛЕНИЕ] РАЗДЕЛЕНИЕ УЛУЧШЕНИЯ ВЫДАЁТ КАМЕНЬ СВОЕГО ТИПА (31.10.2026, окно 50500, решение владельца «Да, патчить»).
//  Документ: AstoryServer/Docs/GameServer/upgrade-split-stone-p99.md.
//
//  ── ДЕФЕКТ (6549 Recv_UserUpgradeExtraction@0x534640, GameServer.c:117761) ──
//  Тип вещи: `v30 = (Item_Table[код].+0x1A == 9) ? 2 : 1` (0x534929…0x53493B; 9 — оружие). Пустые камни сверяются верно:
//  v30 == 2 требует 205 (пустой камень ОРУЖИЯ, 0x534AD5), v30 == 1 — 203 (доспеха, 0x534B6C). Но готовый камень (исходы 0/1)
//  выбирается наоборот:
//    v30 == 1 (НЕ оружие) → запись special_itemlist 400 (+0x4B00 = 400·48): код 401 «Оружие — камень улучшения», подтип 204
//                            (сверка `cmp [+0x4B08], 0CCh` @0x534DE6) — камень, который клиент кладёт ТОЛЬКО на оружие;
//    v30 == 2 (оружие)    → запись 362 (+0x43E0): код 363 «Доспех — камень улучшения», подтип 206 (`cmp [+0x43E8], 0CEh`
//                            @0x534E9B) — камень только для доспехов.
//  Клиент (`itemIsValidColorMixPair@0xB65590`): 204 ↔ itemType 9, 206 ↔ itemType ≤ 8. Итог стока: разделил оружие — получил
//  камень, который на оружие не ложится (и наоборот).
//
//  ── ЧТО ДЕЛАЕТ P99 (2 байта, протокол 6549/6550 не меняется) ──
//  Меняет местами условия веток выбора: `cmp ecx, 1` @0x534DD0 (imm @0x534DD2: 01 → 02) и `cmp edx, 2` @0x534E86
//  (imm @0x534E88: 02 → 01). Оружие (v30 = 2) идёт в ветку записи 400 (камень 401, 204), прочее (v30 = 1) — в ветку 362
//  (камень 363, 206). Тела веток, сверки подтипа, записи камня (+0 код, +12 вес, +50 байт) и журнальные строки стока не
//  трогаются; v30 после ветки читают только строки лога (11)/(12)/(13). Ключ [P99_UpgradeSplitStone] Enabled (0 — сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P99_UpgradeSplitStone";   // секция patches.ini

    // ── площадки и соседи (байты живого GameServer.exe e7b4ac38) ─────────────
    // 0x534DCC: movsx ecx,[ebp-4] · cmp ecx,1 · jne 0x534E82 — ветка «v30 == 1».
    const BYTE kBranch1[] = { 0x0F, 0xBF, 0x4D, 0xFC, 0x83, 0xF9, 0x01, 0x0F, 0x85, 0xA9, 0x00, 0x00, 0x00 };
    // 0x534DD9: mov edx,[5F5E70h] · movzx eax,byte [edx+4B08h] · cmp eax,0CCh — сверка «запись 400 = подтип 204».
    const BYTE kCheck204[] = { 0x8B, 0x15, 0x70, 0x5E, 0x5F, 0x00, 0x0F, 0xB6, 0x82, 0x08, 0x4B, 0x00, 0x00, 0x3D, 0xCC, 0x00, 0x00, 0x00 };
    // 0x534E46: mov edx,[5F5E70h] · mov eax,[edx+4B00h] — код камня из записи 400.
    const BYTE kTake401[] = { 0x8B, 0x15, 0x70, 0x5E, 0x5F, 0x00, 0x8B, 0x82, 0x00, 0x4B, 0x00, 0x00 };
    // 0x534E82: movsx edx,[ebp-4] · cmp edx,2 · jne 0x534F34 — ветка «v30 == 2».
    const BYTE kBranch2[] = { 0x0F, 0xBF, 0x55, 0xFC, 0x83, 0xFA, 0x02, 0x0F, 0x85, 0xA5, 0x00, 0x00, 0x00 };
    // 0x534E8F: mov eax,[5F5E70h] · movzx ecx,byte [eax+43E8h] · cmp ecx,0CEh — сверка «запись 362 = подтип 206».
    const BYTE kCheck206[] = { 0xA1, 0x70, 0x5E, 0x5F, 0x00, 0x0F, 0xB6, 0x88, 0xE8, 0x43, 0x00, 0x00, 0x81, 0xF9, 0xCE, 0x00, 0x00, 0x00 };
    // 0x534EFB: mov eax,[5F5E70h] · mov ecx,[eax+43E0h] — код камня из записи 362.
    const BYTE kTake363[] = { 0xA1, 0x70, 0x5E, 0x5F, 0x00, 0x8B, 0x88, 0xE0, 0x43, 0x00, 0x00 };
    // 0x534929: movzx edx,byte [ecx+eax+1Ah] · cmp edx,9 · jne · mov word [ebp-4],2 · jmp · mov word [ebp-4],1 — источник v30.
    const BYTE kTypeSel[] = { 0x0F, 0xB6, 0x54, 0x01, 0x1A, 0x83, 0xFA, 0x09, 0x75, 0x08, 0x66, 0xC7, 0x45, 0xFC, 0x02, 0x00, 0xEB, 0x06,
                              0x66, 0xC7, 0x45, 0xFC, 0x01, 0x00 };

    constexpr DWORD kImm1 = 0x00534DD2;   // imm8 `cmp ecx, 1` ветки записи 400
    constexpr DWORD kImm2 = 0x00534E88;   // imm8 `cmp edx, 2` ветки записи 362
}

PatchResult P99_UpgradeSplitStone()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    const Site check[] =
    {
        { 0x00534DCC, kBranch1, sizeof(kBranch1) }, { 0x00534DD9, kCheck204, sizeof(kCheck204) }, { 0x00534E46, kTake401, sizeof(kTake401) },
        { 0x00534E82, kBranch2, sizeof(kBranch2) }, { 0x00534E8F, kCheck206, sizeof(kCheck206) }, { 0x00534EFB, kTake363, sizeof(kTake363) },
        { 0x00534929, kTypeSel, sizeof(kTypeSel) },
    };
    if (!VerifyAllSites(L"P99", check, ARRAYSIZE(check))) { return PatchResult::Mismatch; }

    bool ok = Hook::WriteByteChecked(kImm1, 0x01, 0x02);   // ветка записи 400 (камень 401, 204) — для оружия
    ok &= Hook::WriteByteChecked(kImm2, 0x02, 0x01);        // ветка записи 362 (камень 363, 206) — для прочего
    if (!ok) { return PatchResult::Failed; }
    Log::Line(L"    P99: разделение улучшения 6549 — оружие получает камень 401 (подтип 204), прочее — 363 (206); "
              L"imm @0x%08X 01→02, @0x%08X 02→01 (сток выдавал наоборот)", kImm1, kImm2);
    return PatchResult::Applied;
}
