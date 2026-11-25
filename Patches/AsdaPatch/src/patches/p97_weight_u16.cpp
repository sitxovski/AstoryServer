// Copyright (c) 2026 @sitxovski (Discord)
// p97_weight_u16.cpp — P97: вес u16 (до 65535, потолок 60000)
//
// movsx→movzx у 129 чтений, 10 пересчётов регистром, потолок 30000→60000,
// CraftEnter-аккумулятор [ebp-0x238] зажим 0..65535.
// Образ: GameServer.exe md5 e7b4ac38 (одинаков у GS/Indun/Ch2).
// Ключ: [P97_WeightU16] Enabled=1.

#include "Hook.h"
#include "Patches.h"
#include "../Config.h"
#include "../Log.h"
#include <windows.h>

namespace {

const wchar_t* kSec = L"P97_WeightU16";
static bool g_active = false;

// =====================================================================
// 1. Простые movsx→movzx: замена байта addr+1 из 0xBF в 0xB7.
//    12 в писателях (sub_43F880/sub_43FA50) + 117 в вызывающих = 129.
// =====================================================================
static const DWORD kSimpleSites[] = {
    0x0040FEB9, 0x0040FED7, 0x00413216, 0x00413231, 0x004294F0, 0x0043F88F,
    0x0043F8E8, 0x0043F8EF, 0x0043F94A, 0x0043F94E, 0x0043F973, 0x0043F9C5,
    0x0043F9C9, 0x0043FA9B, 0x0043FA9F, 0x0043FAE5, 0x0043FAE9, 0x00455964,
    0x0045851D, 0x0045A2A2, 0x0045A463, 0x0045B66E, 0x0046958B, 0x004695A9,
    0x004D5178, 0x004D5194, 0x004D7CFA, 0x004D7D13, 0x004DA6E1, 0x004DEE58,
    0x004DF0E4, 0x004E4D3F, 0x004E4D71, 0x004E4DA3, 0x004E4DD5, 0x004E74CD,
    0x004E74FF, 0x004E752E, 0x004E7560, 0x004ECD00, 0x004ECD07, 0x004EE218,
    0x004F0CB8, 0x004F0D69, 0x004F12A2, 0x004F454F, 0x004F551E, 0x004F5522,
    0x004F5536, 0x004F5547, 0x004F5892, 0x004F8D10, 0x004F9CB8, 0x004FE799,
    0x004FE7B8, 0x00505A99, 0x00505AB8, 0x00506866, 0x0050C93E, 0x0050C95D,
    0x00510A92, 0x00510AAE, 0x005125AF, 0x005125CB, 0x00512A58, 0x00512A74,
    0x005131E2, 0x005166EC, 0x00516712, 0x00516751, 0x00516756, 0x00518FBA,
    0x00519E21, 0x0051B0C2, 0x0051B0E8, 0x0051B9FE, 0x0051BA30, 0x0051D18E,
    0x0051DF06, 0x0051E9EE, 0x0051EA17, 0x0052045F, 0x00520DA4, 0x0052103D,
    0x005339B4, 0x005339D0, 0x00535603, 0x005362E4, 0x00536DAA, 0x00537A6D,
    0x00539137, 0x0053BCE8, 0x0053BD04, 0x0053C527, 0x0053D308, 0x0053D3E9,
    0x0053E228, 0x0053E308, 0x0053E698, 0x0053E986, 0x0053E9AF, 0x0053E9C8,
    0x0053E9E5, 0x0053EA02, 0x0053EA06, 0x0053EB6C, 0x0054836F, 0x00548388,
    0x0055261F, 0x00552623, 0x005526DE, 0x005526E2, 0x005528E3, 0x005528E7,
    0x00552A6B, 0x00552A6F, 0x00552B29, 0x00552B2D, 0x00552D0E, 0x00552D12,
    0x00552FC3, 0x00552FC7, 0x0055400B, 0x00554026, 0x0055A090, 0x0055B67D,
    0x0055C88E, 0x0055DF0B, 0x0055F8A5,
};
static constexpr int kSimpleCount = sizeof(kSimpleSites) / sizeof(kSimpleSites[0]);

// =====================================================================
// 2. Пересчёт регистром (10 адресов): movsx → mov reg,reg + nop.
//    Повторное чтение 16-битного значения заменяется на копию из
//    регистра, уже хранящего полное 32-битное значение.
// =====================================================================
struct RegRecalc {
    DWORD va;
    BYTE  orig[7];
    BYTE  fix[7];
    int   len;
};

static const RegRecalc kRecalc[] = {
    // sub_43F880 (SetCurrentWeightValue)
    // 0x43F969: movsx ecx,[eax+1A2h] → mov ecx,edx (edx — полная сумма)
    { 0x0043F969,
      {0x0F,0xBF,0x88,0xA2,0x01,0x00,0x00},
      {0x8B,0xCA,0x90,0x90,0x90,0x90,0x90}, 7 },
    // 0x43F9D3: movsx edx,[ebp-4] → mov edx,eax (eax — полная разность)
    { 0x0043F9D3,
      {0x0F,0xBF,0x55,0xFC,0x00,0x00,0x00},
      {0x8B,0xD0,0x90,0x90,0x00,0x00,0x00}, 4 },

    // sub_43FA50 (AddMaxWeight)
    // 0x43FABA: movsx ecx,[eax+1A0h] → mov ecx,edx (полная сумма)
    { 0x0043FABA,
      {0x0F,0xBF,0x88,0xA0,0x01,0x00,0x00},
      {0x8B,0xCA,0x90,0x90,0x90,0x90,0x90}, 7 },
    // 0x43FAF3: movsx ecx,[ebp-4] → mov ecx,edx
    { 0x0043FAF3,
      {0x0F,0xBF,0x4D,0xFC,0x00,0x00,0x00},
      {0x8B,0xCA,0x90,0x90,0x00,0x00,0x00}, 4 },

    // CharSpendHolyItemUse
    // 0x4DEE66: movsx edx,[ebp-47h] → mov edx,eax (eax — результат GetCur)
    { 0x004DEE66,
      {0x0F,0xBF,0x55,0xB9,0x00,0x00,0x00},
      {0x8B,0xD0,0x90,0x90,0x00,0x00,0x00}, 4 },
    // 0x4DF0F2: то же
    { 0x004DF0F2,
      {0x0F,0xBF,0x55,0xB9,0x00,0x00,0x00},
      {0x8B,0xD0,0x90,0x90,0x00,0x00,0x00}, 4 },

    // CharRoseWarStoreBuy
    // 0x5166FD: movsx eax,[ebp-4] → mov eax,ecx
    { 0x005166FD,
      {0x0F,0xBF,0x45,0xFC,0x00,0x00,0x00},
      {0x8B,0xC1,0x90,0x90,0x00,0x00,0x00}, 4 },
    // 0x51670E: movsx edx,[ebp-4] → mov edx,eax
    { 0x0051670E,
      {0x0F,0xBF,0x55,0xFC,0x00,0x00,0x00},
      {0x8B,0xD0,0x90,0x90,0x00,0x00,0x00}, 4 },

    // eventNpcProcessRes
    // 0x55401F: movsx eax,[ebp-128h] → mov eax,ecx + 5 nop (7 байт)
    { 0x0055401F,
      {0x0F,0xBF,0x85,0xD8,0xFE,0xFF,0xFF},
      {0x8B,0xC1,0x90,0x90,0x90,0x90,0x90}, 7 },

    // RecvUser_CraftRecipeRegist
    // 0x53D312: movsx edx,[ebp-54h] → mov edx,ecx
    { 0x0053D312,
      {0x0F,0xBF,0x55,0xAC,0x00,0x00,0x00},
      {0x8B,0xD1,0x90,0x90,0x00,0x00,0x00}, 4 },
};
static constexpr int kRecalcCount = sizeof(kRecalc) / sizeof(kRecalc[0]);

// =====================================================================
// 3. Потолок 30000→60000 (4 адреса)
// =====================================================================

// 0x43FAC1: cmp ecx, 7530h → cmp ecx, EA60h
//   байты: 81 F9 [30 75] 00 00 → 81 F9 [60 EA] 00 00
static const BYTE kCeil_43FAC1_orig[] = { 0x30, 0x75 };
static const BYTE kCeil_43FAC1_fix[]  = { 0x60, 0xEA };

// 0x43FACC: mov word [edx+1A0h], 7530h → EA60h
//   байты: 66 C7 82 A0 01 00 00 [30 75] → [60 EA]
static const BYTE kCeil_43FACC_orig[] = { 0x30, 0x75 };
static const BYTE kCeil_43FACC_fix[]  = { 0x60, 0xEA };

// 0x4EE21F: cmp edx, 7530h → EA60h (гейт Char_FunctionItem_Use)
//   байты: 81 FA [30 75] 00 00
static const BYTE kCeil_4EE21F_orig[] = { 0x30, 0x75 };
static const BYTE kCeil_4EE21F_fix[]  = { 0x60, 0xEA };

// 0x4F0CBF: cmp ecx, 7530h → EA60h (гейт sub_4EF270)
//   байты: 81 F9 [30 75] 00 00
static const BYTE kCeil_4F0CBF_orig[] = { 0x30, 0x75 };
static const BYTE kCeil_4F0CBF_fix[]  = { 0x60, 0xEA };

// =====================================================================
// 4. CraftEnter аккумулятор [ebp-0x238] — зажим 0..65535
//    5 мест записи: каждое 7 байт `66 89 XX C8 FD FF FF`
// =====================================================================

// Оригинальные байты для сверки
static const BYTE kCraft0_orig[] = { 0x66,0x89,0x85,0xC8,0xFD,0xFF,0xFF }; // mov word [ebp-238h], ax
static const BYTE kCraft1_orig[] = { 0x66,0x89,0x95,0xC8,0xFD,0xFF,0xFF }; // mov word [ebp-238h], dx
static const BYTE kCraft2_orig[] = { 0x66,0x89,0x8D,0xC8,0xFD,0xFF,0xFF }; // mov word [ebp-238h], cx
static const BYTE kCraft3_orig[] = { 0x66,0x89,0x8D,0xC8,0xFD,0xFF,0xFF }; // mov word [ebp-238h], cx
static const BYTE kCraft4_orig[] = { 0x66,0x89,0x8D,0xC8,0xFD,0xFF,0xFF }; // mov word [ebp-238h], cx

static const DWORD kCraftBack0 = 0x0053E238;   // 0x53E231 + 7
static const DWORD kCraftBack1 = 0x0053E318;   // 0x53E311 + 7
static const DWORD kCraftBack2 = 0x0053E6A8;   // 0x53E6A1 + 7
static const DWORD kCraftBack3 = 0x0053E996;   // 0x53E98F + 7
static const DWORD kCraftBack4 = 0x0053E9BF;   // 0x53E9B8 + 7

// трамплин: зажим ax, запись в [ebp-0x238], возврат
__declspec(naked) void CraftClamp_AX()
{
    __asm {
        test eax, eax
        jns  L_pos
        xor  eax, eax
        jmp  L_wr
    L_pos:
        cmp  eax, 0FFFFh
        jbe  L_wr
        mov  eax, 0FFFFh
    L_wr:
        mov  word ptr [ebp - 0x238], ax
        jmp  dword ptr [kCraftBack0]
    }
}

// трамплин: зажим dx, запись, возврат
__declspec(naked) void CraftClamp_DX()
{
    __asm {
        test edx, edx
        jns  L_pos
        xor  edx, edx
        jmp  L_wr
    L_pos:
        cmp  edx, 0FFFFh
        jbe  L_wr
        mov  edx, 0FFFFh
    L_wr:
        mov  word ptr [ebp - 0x238], dx
        jmp  dword ptr [kCraftBack1]
    }
}

// зажим cx — три сайта, три обратных адреса, три трамплина
__declspec(naked) void CraftClamp_CX_2()
{
    __asm {
        test ecx, ecx
        jns  L_pos
        xor  ecx, ecx
        jmp  L_wr
    L_pos:
        cmp  ecx, 0FFFFh
        jbe  L_wr
        mov  ecx, 0FFFFh
    L_wr:
        mov  word ptr [ebp - 0x238], cx
        jmp  dword ptr [kCraftBack2]
    }
}
__declspec(naked) void CraftClamp_CX_3()
{
    __asm {
        test ecx, ecx
        jns  L_pos
        xor  ecx, ecx
        jmp  L_wr
    L_pos:
        cmp  ecx, 0FFFFh
        jbe  L_wr
        mov  ecx, 0FFFFh
    L_wr:
        mov  word ptr [ebp - 0x238], cx
        jmp  dword ptr [kCraftBack3]
    }
}
__declspec(naked) void CraftClamp_CX_4()
{
    __asm {
        test ecx, ecx
        jns  L_pos
        xor  ecx, ecx
        jmp  L_wr
    L_pos:
        cmp  ecx, 0FFFFh
        jbe  L_wr
        mov  ecx, 0FFFFh
    L_wr:
        mov  word ptr [ebp - 0x238], cx
        jmp  dword ptr [kCraftBack4]
    }
}

} // namespace

// =====================================================================
// 5. Экспорт для P35 (CatStack)
// =====================================================================
extern "C" __declspec(dllexport) bool __stdcall P97_WeightU16Active()
{
    return g_active;
}

// =====================================================================
// Apply
// =====================================================================
PatchResult P97_WeightU16()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
        return PatchResult::Disabled;

    // ----------- verify -----------

    // 1. Простые movsx (129): проверить 0F BF
    for (int i = 0; i < kSimpleCount; ++i)
    {
        const BYTE expect[] = { 0x0F, 0xBF };
        if (!Hook::Verify(kSimpleSites[i], expect, 2))
        {
            Log::Line(L"    %s: verify movsx #%d @0x%08X", kSec, i, kSimpleSites[i]);
            return PatchResult::Mismatch;
        }
    }

    // 2. Пересчёт регистром (10)
    for (int i = 0; i < kRecalcCount; ++i)
    {
        if (!Hook::Verify(kRecalc[i].va, kRecalc[i].orig, kRecalc[i].len))
        {
            Log::Line(L"    %s: verify recalc #%d @0x%08X", kSec, i, kRecalc[i].va);
            return PatchResult::Mismatch;
        }
    }

    // 3. Потолок: проверить операнды 30 75
    if (!Hook::Verify(0x0043FAC3, kCeil_43FAC1_orig, 2) ||
        !Hook::Verify(0x0043FAD3, kCeil_43FACC_orig, 2) ||
        !Hook::Verify(0x004EE221, kCeil_4EE21F_orig, 2) ||
        !Hook::Verify(0x004F0CC1, kCeil_4F0CBF_orig, 2))
    {
        Log::Line(L"    %s: verify ceiling", kSec);
        return PatchResult::Mismatch;
    }

    // 4. CraftEnter записи (5 × 7 байт)
    if (!Hook::Verify(0x0053E231, kCraft0_orig, 7) ||
        !Hook::Verify(0x0053E311, kCraft1_orig, 7) ||
        !Hook::Verify(0x0053E6A1, kCraft2_orig, 7) ||
        !Hook::Verify(0x0053E98F, kCraft3_orig, 7) ||
        !Hook::Verify(0x0053E9B8, kCraft4_orig, 7))
    {
        Log::Line(L"    %s: verify CraftEnter accum", kSec);
        return PatchResult::Mismatch;
    }

    // ----------- apply -----------
    bool ok = true;

    // 1. Простые movsx→movzx: 0xBF → 0xB7 по addr+1
    for (int i = 0; i < kSimpleCount; ++i)
        ok &= Hook::WriteByteChecked(kSimpleSites[i] + 1, 0xBF, 0xB7);

    // 2. Пересчёт регистром
    for (int i = 0; i < kRecalcCount; ++i)
        ok &= Hook::WriteBytes(kRecalc[i].va, kRecalc[i].fix, kRecalc[i].len);

    // 3. Потолок 30000→60000
    ok &= Hook::WriteBytes(0x0043FAC3, kCeil_43FAC1_fix, 2);   // cmp ecx, EA60h
    ok &= Hook::WriteBytes(0x0043FAD3, kCeil_43FACC_fix, 2);   // mov word ..., EA60h
    ok &= Hook::WriteBytes(0x004EE221, kCeil_4EE21F_fix, 2);   // cmp edx, EA60h
    ok &= Hook::WriteBytes(0x004F0CC1, kCeil_4F0CBF_fix, 2);   // cmp ecx, EA60h

    // 4. CraftEnter трамплины (jmp, 7 байт = 5+2nop)
    ok &= Hook::WriteJmp(0x0053E231, (const void*)&CraftClamp_AX,   7);
    ok &= Hook::WriteJmp(0x0053E311, (const void*)&CraftClamp_DX,   7);
    ok &= Hook::WriteJmp(0x0053E6A1, (const void*)&CraftClamp_CX_2, 7);
    ok &= Hook::WriteJmp(0x0053E98F, (const void*)&CraftClamp_CX_3, 7);
    ok &= Hook::WriteJmp(0x0053E9B8, (const void*)&CraftClamp_CX_4, 7);

    if (!ok)
    {
        Log::Line(L"    %s: write failed", kSec);
        return PatchResult::Failed;
    }

    g_active = true;
    Log::Line(L"    %s: OK  simple=%d recalc=%d ceil=4 craft=5",
             kSec, kSimpleCount, kRecalcCount);
    return PatchResult::Applied;
}
