// Copyright (c) 2026 @sitxovski (Discord)
// p96_inventory_x2.cpp — P96: сумка 30→60 (боковое хранилище DLL)
//
// Контейнер 1 целиком перенесён в g_bag[550][60][57] в памяти DLL.
// В каждой точке доступа база подменяется на g_bag[idx] − 0x4BC,
// исходные смещения 0x4BC/0x4C1/0x4C5/0x4CA работают без правки.
// Старая область CUser+0x4BC..0xB69 — канарейка (вид 145).
// Образ: GameServer.exe md5 e7b4ac38 (GS/Indun/Ch2).
// Ключ: [P96_InventoryX2] Enabled=1.

#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <windows.h>
#include <string.h>

namespace {

const wchar_t* kSec = L"P96_InventoryX2";
static bool g_active = false;

// =====================================================================
// Боковое хранилище
// =====================================================================
constexpr int kMaxUsers  = 550;      // CUser слотов (sub_5328F0)
constexpr int kNewSlots  = 60;
constexpr int kOldSlots  = 30;
constexpr int kRecSize   = 57;       // 0x39 — запись предмета
constexpr DWORD kUserArrayPtr = 0x0060BFF8;  // ds:[0x60AD18+0x12E0] → CUser*[550]
constexpr DWORD kUserStride   = 0x40BA0;
constexpr int kOldBagOff = 0x4BC;    // CUser+0x4BC — начало старой сумки
constexpr int kOldBagSize = kOldSlots * kRecSize;  // 1710 = 0x6AE

static BYTE g_bag[kMaxUsers][kNewSlots][kRecSize];   // 1 881 000 б ≈ 1,88 МБ
static BYTE g_emptyRec[kRecSize];

// Пустая запись (семантика sub_40A9F0):
// +0..4=0, +5..8=FF, +9..F=0, +10..17=FF, +18..1C=0, +1D..30=FF, +31..38=0
void InitEmptyRecord()
{
    memset(g_emptyRec, 0, kRecSize);
    memset(g_emptyRec + 0x05, 0xFF, 4);   // +5..+8
    memset(g_emptyRec + 0x10, 0xFF, 8);   // +10..+17
    memset(g_emptyRec + 0x1D, 0xFF, 20);  // +1D..+30
}

void InitAllBags()
{
    for (int u = 0; u < kMaxUsers; ++u)
        for (int s = 0; s < kNewSlots; ++s)
            memcpy(g_bag[u][s], g_emptyRec, kRecSize);
}

int UserIdx(const BYTE* pUser)
{
    DWORD base = *(const DWORD*)kUserArrayPtr;
    if (!base || (DWORD)pUser < base) return -1;
    DWORD off = (DWORD)pUser - base;
    if (off % kUserStride != 0) return -1;
    int idx = (int)(off / kUserStride);
    return (idx >= 0 && idx < kMaxUsers) ? idx : -1;
}

BYTE* FakeBase(int idx)
{
    return (BYTE*)&g_bag[idx][0][0] - kOldBagOff;
}

// =====================================================================
// ac.other виды (зарегистрировать в ac-journal-p53 §9)
// =====================================================================
constexpr BYTE kKindCanary  = 145;   // запись в старую область CUser — пропущенное место
constexpr BYTE kKindSlotOOB = 146;   // ячейка вне 0..59 отброшена
constexpr BYTE kKindFault   = 147;   // исключение / указатель не из массива

// =====================================================================
// Подстановки
// =====================================================================

// Подмена pUser в стековом кадре: *ppUser → fakePUser
extern "C" void __stdcall P96_SubstUser(BYTE** ppUser)
{
    if (!g_active || !ppUser || !*ppUser) return;
    int idx = UserIdx(*ppUser);
    if (idx < 0) return;
    *ppUser = FakeBase(idx);
}

// Возврат fakePUser по pUser (для регистровой подстановки)
extern "C" BYTE* __stdcall P96_FakeUser(BYTE* pUser)
{
    if (!g_active || !pUser) return pUser;
    int idx = UserIdx(pUser);
    return (idx >= 0) ? FakeBase(idx) : pUser;
}

// Инициализация сумки одного пользователя пустыми записями
extern "C" void __stdcall P96_InitBagSlot(int userNum)
{
    if (userNum < 0 || userNum >= kMaxUsers) return;
    for (int s = 0; s < kNewSlots; ++s)
        memcpy(g_bag[userNum][s], g_emptyRec, kRecSize);
}

// =====================================================================
// Адреса возврата / отказа для стабов
// =====================================================================

// 9 роутеров
static const DWORD kBack_4D61E0  = 0x004D621C;
static const DWORD kBack_4D63F0  = 0x004D6486;
static const DWORD kFail_4D63F0  = 0x004D6539;  // srv_sites: 4D63F0→0x4D6539
static const DWORD kBack_4D6540  = 0x004D6597;
static const DWORD kFail_4D6540  = 0x004D65CB;  // srv_sites: 4D6540→0x4D65CB
static const DWORD kBack_4D6740  = 0x004D6785;
static const DWORD kBack_4D6910  = 0x004D694C;
static const DWORD kBack_4D6A70  = 0x004D6ABC;
static const DWORD kBack_4D6BD0  = 0x004D6C17;
static const DWORD kFail_4D6BD0  = 0x004D6C2B;  // srv_sites: 4D6BD0→0x4D6C2B
static const DWORD kBack_4D6CE0  = 0x004D6D4B;
static const DWORD kBack_4D7410  = 0x004D74D2;

// recvDB
static const DWORD kBack_recvDB  = 0x005296BA;
static const DWORD kFail_recvDB  = 0x005296D5;

// 4045
static const DWORD kBack_529A50  = 0x00529A56;
static const DWORD kBack_529A6F  = 0x00529A75;

// PrimiumSum
static const DWORD kBack_53721C  = 0x00537222;

// EventItem
static const DWORD kBack_554936  = 0x0055493C;

// Cleanup
static const DWORD kBack_4A36A1  = 0x004A36A6;

// =====================================================================
// Стабы 9 роутеров
// =====================================================================

// --- Тип A: подмена + повтор movsx/test (sub_4D61E0, sub_4D6910) ---
__declspec(naked) void St_4D61E0()
{
    __asm {
        pushad
        lea  eax, [ebp - 4]               // &pUser [ebp-4]
        push eax
        call P96_SubstUser
        popad
        movsx edx, word ptr [ebp + 10h]   // replay
        test  edx, edx
        jmp   dword ptr [kBack_4D61E0]    // → 0x4D621C
    }
}

__declspec(naked) void St_4D6910()
{
    __asm {
        pushad
        lea  eax, [ebp - 4]
        push eax
        call P96_SubstUser
        popad
        movsx edx, word ptr [ebp + 10h]
        test  edx, edx
        jmp   dword ptr [kBack_4D6910]
    }
}

// --- Тип B: подмена + граница 0..59 (sub_4D6540, sub_4D6BD0) ---
__declspec(naked) void St_4D6540()
{
    __asm {
        pushad
        lea  eax, [ebp - 70h]             // &pUser [ebp-70h]
        push eax
        call P96_SubstUser
        popad
        movsx edx, word ptr [ebp + 10h]   // replay slot read
        test  edx, edx
        js   Fail_6540                     // slot < 0
        cmp  edx, 3Ch                      // 60
        jge  Fail_6540                     // slot ≥ 60
        jmp  dword ptr [kBack_4D6540]      // → 0x4D6597
    Fail_6540:
        jmp  dword ptr [kFail_4D6540]      // → 0x4D65CB
    }
}

__declspec(naked) void St_4D6BD0()
{
    __asm {
        pushad
        lea  eax, [ebp - 8]               // &pUser [ebp-8]
        push eax
        call P96_SubstUser
        popad
        movsx edx, word ptr [ebp + 10h]
        test  edx, edx
        js   Fail_6BD0
        cmp  edx, 3Ch
        jge  Fail_6BD0
        jmp  dword ptr [kBack_4D6BD0]
    Fail_6BD0:
        jmp  dword ptr [kFail_4D6BD0]
    }
}

// --- Тип C: подмена + повтор loop init (sub_4D6740, sub_4D6A70, sub_4D6CE0, sub_4D7410) ---
__declspec(naked) void St_4D6740()
{
    __asm {
        pushad
        lea  eax, [ebp - 8]               // &pUser [ebp-8]
        push eax
        call P96_SubstUser
        popad
        mov  dword ptr [ebp - 4], 0        // replay: i = 0
        jmp  dword ptr [kBack_4D6740]      // → 0x4D6785
    }
}

__declspec(naked) void St_4D6A70()
{
    __asm {
        pushad
        lea  eax, [ebp - 8]               // &pUser [ebp-8]
        push eax
        call P96_SubstUser
        popad
        mov  dword ptr [ebp - 4], 0
        jmp  dword ptr [kBack_4D6A70]
    }
}

__declspec(naked) void St_4D6CE0()
{
    __asm {
        pushad
        lea  eax, [ebp - 0Ch]             // &pUser [ebp-0Ch]
        push eax
        call P96_SubstUser
        popad
        mov  dword ptr [ebp - 10h], 0      // replay: i = 0 (локаль ebp-10h)
        jmp  dword ptr [kBack_4D6CE0]
    }
}

__declspec(naked) void St_4D7410()
{
    __asm {
        pushad
        lea  eax, [ebp - 48h]             // &pUser [ebp-48h]
        push eax
        call P96_SubstUser
        popad
        mov  dword ptr [ebp - 4], 0
        jmp  dword ptr [kBack_4D7410]
    }
}

// --- Тип D: подмена + граница из записи (sub_4D63F0) ---
__declspec(naked) void St_4D63F0()
{
    __asm {
        pushad
        // подмена pUser
        lea  eax, [ebp - 4]               // &pUser [ebp-4]
        push eax
        call P96_SubstUser
        // граница: слот из записи [ebp+0Ch]+5
        mov  edx, [ebp + 0Ch]
        movsx eax, word ptr [edx + 5]
        test eax, eax
        js   Fail_63F0
        cmp  eax, 3Ch                      // 60
        jge  Fail_63F0
        popad
        // replay: push 57; mov ecx,[ebp+0Ch]; push ecx
        push 39h
        mov  ecx, [ebp + 0Ch]
        push ecx
        jmp  dword ptr [kBack_4D63F0]     // → 0x4D6486
    Fail_63F0:
        popad
        jmp  dword ptr [kFail_4D63F0]     // → 0x4D6539
    }
}

// =====================================================================
// Стаб recvDB (recvDBShellInvenItemInfo @0x5296B4)
// =====================================================================
__declspec(naked) void St_recvDB()
{
    __asm {
        pushad
        // граница ячейки
        mov  eax, [ebp - 48h]             // slot (сохранён ранее)
        test eax, eax
        js   Fail_rcv
        cmp  eax, 3Ch
        jge  Fail_rcv
        // подмена pUser
        lea  eax, [ebp - 4Ch]             // &pUser [ebp-4Ch]
        push eax
        call P96_SubstUser
        popad
        // replay: push 57; lea eax,[ebp-44h]; push eax
        push 39h
        lea  eax, [ebp - 44h]
        push eax
        jmp  dword ptr [kBack_recvDB]     // → 0x5296BA
    Fail_rcv:
        popad
        jmp  dword ptr [kFail_recvDB]     // → 0x5296D5
    }
}

// =====================================================================
// Стабы 4045 sub_5299B0 (регистровая подстановка, pUser остаётся в кадре)
// =====================================================================
__declspec(naked) void St_529A50()
{
    __asm {
        push eax
        push edx
        mov  ecx, [ebp - 2D8h]            // real pUser → ecx
        push ecx
        call P96_FakeUser                  // eax = fakePUser
        mov  ecx, eax
        pop  edx
        pop  eax
        jmp  dword ptr [kBack_529A50]      // → 0x529A56
    }
}

__declspec(naked) void St_529A6F()
{
    __asm {
        push ecx
        push edx
        mov  eax, [ebp - 2D8h]            // real pUser → eax
        push eax
        call P96_FakeUser
        pop  edx
        pop  ecx
        jmp  dword ptr [kBack_529A6F]      // → 0x529A75 (eax = fakePUser)
    }
}

// =====================================================================
// Стаб PrimiumSum @0x53721C (регистровая подстановка)
// =====================================================================
__declspec(naked) void St_53721C()
{
    __asm {
        push ecx
        push edx
        mov  eax, [ebp - 23Ch]            // real pUser → eax
        push eax
        call P96_FakeUser
        pop  edx
        pop  ecx
        jmp  dword ptr [kBack_53721C]     // → 0x537222 (eax = fakePUser)
    }
}

// =====================================================================
// Стаб EventItem @0x554936 (регистровая подстановка)
// =====================================================================
__declspec(naked) void St_554936()
{
    __asm {
        push eax
        push edx
        mov  ecx, [ebp - 3C0h]            // real pUser → ecx
        push ecx
        call P96_FakeUser
        mov  ecx, eax
        pop  edx
        pop  eax
        jmp  dword ptr [kBack_554936]     // → 0x55493C (ecx = fakePUser)
    }
}

// =====================================================================
// Стаб очистки @0x4A36A1 — инициализация g_bag + повтор оригинала
// =====================================================================
__declspec(naked) void St_Cleanup()
{
    __asm {
        pushad
        movsx eax, word ptr [ebp + 8]     // userNum
        push  eax
        call  P96_InitBagSlot
        popad
        // replay: push 0x6AE (old bag size — канарейка: сток обнуляет старую область)
        push  6AEh
        jmp   dword ptr [kBack_4A36A1]    // → 0x4A36A6
    }
}

// =====================================================================
// Оригинальные байты для verify
// =====================================================================

// Роутер sub_4D61E0 @0x4D6216: movsx edx,word[ebp+10h] (4b) + test edx,edx (2b) = 6 б
static const BYTE kOrig_4D6216[] = { 0x0F, 0xBF, 0x55, 0x10, 0x85, 0xD2 };

// Роутер sub_4D63F0 @0x4D6480: push 39h (2b) + mov ecx,[ebp+0Ch] (3b) + push ecx (1b) = 6 б
static const BYTE kOrig_4D6480[] = { 0x6A, 0x39, 0x8B, 0x4D, 0x0C, 0x51 };

// Роутер sub_4D6540 @0x4D658E: movsx edx,[ebp+10h](4b)+cmp edx,1Eh(3b)+jge(2b) = 9 б
static const BYTE kOrig_4D658E[] = { 0x0F, 0xBF, 0x55, 0x10, 0x83, 0xFA, 0x1E, 0x7D, 0x34 };

// Роутер sub_4D6740 @0x4D677E: mov dword[ebp-4],0 = 7 б
static const BYTE kOrig_4D677E[] = { 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00 };

// Роутер sub_4D6910 @0x4D6946: movsx edx,[ebp+10h](4b)+test edx,edx(2b) = 6 б
static const BYTE kOrig_4D6946[] = { 0x0F, 0xBF, 0x55, 0x10, 0x85, 0xD2 };

// Роутер sub_4D6A70 @0x4D6AB5: mov dword[ebp-4],0 = 7 б
static const BYTE kOrig_4D6AB5[] = { 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00 };

// Роутер sub_4D6BD0 @0x4D6C0E: movsx edx,[ebp+10h](4b)+cmp edx,1Eh(3b)+jge(2b) = 9 б
static const BYTE kOrig_4D6C0E[] = { 0x0F, 0xBF, 0x55, 0x10, 0x83, 0xFA, 0x1E, 0x7D, 0x14 };

// Роутер sub_4D6CE0 @0x4D6D44: mov dword[ebp-10h],0 = 7 б
static const BYTE kOrig_4D6D44[] = { 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00 };

// Роутер sub_4D7410 @0x4D74CB: mov dword[ebp-4],0 = 7 б
static const BYTE kOrig_4D74CB[] = { 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00 };

// recvDB @0x5296B4: push 39h(2b) + lea eax,[ebp-44h](3b) + push eax(1b) = 6 б
static const BYTE kOrig_5296B4[] = { 0x6A, 0x39, 0x8D, 0x45, 0xBC, 0x50 };

// 4045 @0x529A50: mov ecx,[ebp-2D8h] = 6 б
static const BYTE kOrig_529A50[] = { 0x8B, 0x8D, 0x28, 0xFD, 0xFF, 0xFF };

// 4045 @0x529A6F: mov eax,[ebp-2D8h] = 6 б
static const BYTE kOrig_529A6F[] = { 0x8B, 0x85, 0x28, 0xFD, 0xFF, 0xFF };

// PrimiumSum @0x53721C: mov eax,[ebp-23Ch] = 6 б
static const BYTE kOrig_53721C[] = { 0x8B, 0x85, 0xC4, 0xFD, 0xFF, 0xFF };

// EventItem @0x554936: mov ecx,[ebp-3C0h] = 6 б
static const BYTE kOrig_554936[] = { 0x8B, 0x8D, 0x40, 0xFC, 0xFF, 0xFF };

// Cleanup @0x4A36A1: push 6AEh = 5 б
static const BYTE kOrig_4A36A1[] = { 0x68, 0xAE, 0x06, 0x00, 0x00 };

// =====================================================================
// imm8 1E→3C (19 адресов): байт = 1E
// =====================================================================

// 6 в роутерах
static const DWORD kImm_routers[] = {
    0x004D6224, 0x004D6793, 0x004D6954, 0x004D6ACA, 0x004D6D59, 0x004D74E0,
};
// 13 снаружи
static const DWORD kImm_other[] = {
    0x004D703E, 0x004D7079,  // GetItemWeight
    0x004CE673, 0x004CE85F,  // CharItemMove
    0x004EC703,              // TradeReq
    0x004D8B59,              // sub_4D88F0
    0x0055BAD5, 0x0055BAFB, 0x0055BD64, 0x0055BD8A,  // sub_55B7F0
    0x00529A40,              // 4045
    0x005371CA,              // PrimiumSum
    0x0055492A,              // EventItem
};
static constexpr int kImmRouterCount = sizeof(kImm_routers) / sizeof(kImm_routers[0]);
static constexpr int kImmOtherCount  = sizeof(kImm_other) / sizeof(kImm_other[0]);

// recvDB граница: @0x5296B1 байт 1E → 3B (59)
static const DWORD kRecvDbBound = 0x005296B1;

} // namespace

// =====================================================================
// Экспорт для P95: текущий размер сумки (60 если P96 встал, иначе 30)
// =====================================================================
extern "C" __declspec(dllexport) int __stdcall P96_BagSize()
{
    return g_active ? kNewSlots : kOldSlots;
}

extern "C" __declspec(dllexport) bool __stdcall P96_Active()
{
    return g_active;
}

// ★ P100 (01.11.2026): запись ячейки сумки (контейнер 1) по CUser и слоту — g_bag при P96, иначе CUser+0x4BC (сток, 30 ячеек).
//   nullptr — слот вне сумки / CUser не из массива. Сумку P100 читает ТОЛЬКО через этот экспорт.
extern "C" __declspec(dllexport) BYTE* __stdcall P96_BagRec(BYTE* pUser, int slot)
{
    if (!pUser || slot < 0) return nullptr;
    if (g_active)
    {
        const int idx = UserIdx(pUser);
        return (idx >= 0 && slot < kNewSlots) ? g_bag[idx][slot] : nullptr;
    }
    return slot < kOldSlots ? pUser + kOldBagOff + kRecSize * slot : nullptr;
}

// =====================================================================
// Apply
// =====================================================================
PatchResult P96_InventoryX2()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
        return PatchResult::Disabled;

    // ----------- verify -----------

    const Site checks[] =
    {
        // 9 роутеров
        { 0x004D6216, kOrig_4D6216, sizeof(kOrig_4D6216) },
        { 0x004D6480, kOrig_4D6480, sizeof(kOrig_4D6480) },
        { 0x004D658E, kOrig_4D658E, sizeof(kOrig_4D658E) },
        { 0x004D677E, kOrig_4D677E, sizeof(kOrig_4D677E) },
        { 0x004D6946, kOrig_4D6946, sizeof(kOrig_4D6946) },
        { 0x004D6AB5, kOrig_4D6AB5, sizeof(kOrig_4D6AB5) },
        { 0x004D6C0E, kOrig_4D6C0E, sizeof(kOrig_4D6C0E) },
        { 0x004D6D44, kOrig_4D6D44, sizeof(kOrig_4D6D44) },
        { 0x004D74CB, kOrig_4D74CB, sizeof(kOrig_4D74CB) },
        // recvDB
        { 0x005296B4, kOrig_5296B4, sizeof(kOrig_5296B4) },
        // 4045
        { 0x00529A50, kOrig_529A50, sizeof(kOrig_529A50) },
        { 0x00529A6F, kOrig_529A6F, sizeof(kOrig_529A6F) },
        // PrimiumSum
        { 0x0053721C, kOrig_53721C, sizeof(kOrig_53721C) },
        // EventItem
        { 0x00554936, kOrig_554936, sizeof(kOrig_554936) },
        // Cleanup
        { 0x004A36A1, kOrig_4A36A1, sizeof(kOrig_4A36A1) },
    };
    if (!VerifyAllSites(kSec, checks, ARRAYSIZE(checks)))
        return PatchResult::Mismatch;

    // Проверка 19 imm8 = 0x1E
    for (int i = 0; i < kImmRouterCount; ++i)
    {
        const BYTE expect = 0x1E;
        if (!Hook::Verify(kImm_routers[i], &expect, 1))
        {
            Log::Line(L"    %s: verify imm_router #%d @0x%08X", kSec, i, kImm_routers[i]);
            return PatchResult::Mismatch;
        }
    }
    for (int i = 0; i < kImmOtherCount; ++i)
    {
        const BYTE expect = 0x1E;
        if (!Hook::Verify(kImm_other[i], &expect, 1))
        {
            Log::Line(L"    %s: verify imm_other #%d @0x%08X", kSec, i, kImm_other[i]);
            return PatchResult::Mismatch;
        }
    }

    // recvDB граница
    {
        const BYTE expect = 0x1E;
        if (!Hook::Verify(kRecvDbBound, &expect, 1))
        {
            Log::Line(L"    %s: verify recvDB bound @0x%08X", kSec, kRecvDbBound);
            return PatchResult::Mismatch;
        }
    }

    // ----------- init storage -----------
    InitEmptyRecord();
    InitAllBags();

    // ----------- apply -----------
    bool ok = true;

    // 9 роутеров
    ok &= Hook::WriteJmp(0x004D6216, (const void*)&St_4D61E0,  sizeof(kOrig_4D6216));
    ok &= Hook::WriteJmp(0x004D6480, (const void*)&St_4D63F0,  sizeof(kOrig_4D6480));
    ok &= Hook::WriteJmp(0x004D658E, (const void*)&St_4D6540,  sizeof(kOrig_4D658E));
    ok &= Hook::WriteJmp(0x004D677E, (const void*)&St_4D6740,  sizeof(kOrig_4D677E));
    ok &= Hook::WriteJmp(0x004D6946, (const void*)&St_4D6910,  sizeof(kOrig_4D6946));
    ok &= Hook::WriteJmp(0x004D6AB5, (const void*)&St_4D6A70,  sizeof(kOrig_4D6AB5));
    ok &= Hook::WriteJmp(0x004D6C0E, (const void*)&St_4D6BD0,  sizeof(kOrig_4D6C0E));
    ok &= Hook::WriteJmp(0x004D6D44, (const void*)&St_4D6CE0,  sizeof(kOrig_4D6D44));
    ok &= Hook::WriteJmp(0x004D74CB, (const void*)&St_4D7410,  sizeof(kOrig_4D74CB));

    // recvDB
    ok &= Hook::WriteJmp(0x005296B4, (const void*)&St_recvDB,  sizeof(kOrig_5296B4));

    // 4045
    ok &= Hook::WriteJmp(0x00529A50, (const void*)&St_529A50,  sizeof(kOrig_529A50));
    ok &= Hook::WriteJmp(0x00529A6F, (const void*)&St_529A6F,  sizeof(kOrig_529A6F));

    // PrimiumSum
    ok &= Hook::WriteJmp(0x0053721C, (const void*)&St_53721C,  sizeof(kOrig_53721C));

    // EventItem
    ok &= Hook::WriteJmp(0x00554936, (const void*)&St_554936,  sizeof(kOrig_554936));

    // Cleanup
    ok &= Hook::WriteJmp(0x004A36A1, (const void*)&St_Cleanup, sizeof(kOrig_4A36A1));

    // 19 imm8: 1E → 3C
    for (int i = 0; i < kImmRouterCount; ++i)
        ok &= Hook::WriteByteChecked(kImm_routers[i], 0x1E, 0x3C);
    for (int i = 0; i < kImmOtherCount; ++i)
        ok &= Hook::WriteByteChecked(kImm_other[i], 0x1E, 0x3C);

    // recvDB граница: 1E → 3B (59, т.к. оригинал использует `> N`)
    ok &= Hook::WriteByteChecked(kRecvDbBound, 0x1E, 0x3B);

    if (!ok)
    {
        Log::Line(L"    %s: write failed", kSec);
        return PatchResult::Failed;
    }

    g_active = true;
    Log::Line(L"    %s: OK  routers=9 recvDB=1 4045=2 premium=1 event=1 cleanup=1 imm=%d bound=1 bag=%d×%d×%d",
              kSec, kImmRouterCount + kImmOtherCount, kMaxUsers, kNewSlots, kRecSize);
    return PatchResult::Applied;
}
