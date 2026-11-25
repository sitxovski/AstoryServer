// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P112 — [ИСПРАВЛЕНИЕ] РАЗБРОС УРОВНЕЙ ОТРЯДА В ОПЫТЕ: ПО ВСЕМУ ОТРЯДУ И С НАСТОЯЩИМ МИНИМУМОМ (06.11.2026, сессия pet-hatch-summon;
//  слово владельца «IF THERE IS A PARTY WITH PLAYERS WHERE lower IS 5 and max is 60. NO EXP AND NO LOOT FOR EVERYONE»).
//  Документ: AstoryServer/Docs/GameServer/party-exp-spread-p112.md. Пара для лута — N24 (AddonNPC), определение разброса одно.
//
//  ── ПОТОК (GameServer e7b4ac38 = Indun = Ch2 = сток; GameServer.c:79341 sub_4C7650, приём 8306) ──
//  NpcServer кладёт в 8306 только нанёсших урон с разницей уровней ≤ 6. sub_4C7650 считает по записям пакета максимум v22 и минимум v18;
//  `if (v22 - v18 < 10)` — сумма долей делится поровну, иначе опыта нет никому. Проверка 20 клеток идёт в том же цикле, на разброс не влияет.
//
//  ── ДЕФЕКТЫ ──
//  1. Сильный, отсеянный NpcServer (разница ≥ 7), в пакет не попадает: лв5 + лв60 на низком мобе дают разброс 0 — лв5 опыт получает.
//  2. Член отряда, не бивший моба, в разброс не входит.
//  3. Минимум стартует с константы 59 (0x4C77E7; сток держал потолок уровня 59, P29 поднял его до 100): при максимуме 69 и выше разброс ≥ 10
//     у любого отряда, даже лв70 + лв70 — опыта нет никому. Отряд лв60 + лв69 — тоже.
//
//  ── ЧТО ДЕЛАЕТ P112 (12 байт, протокол не меняется) ──
//  Площадка 0x4C7A8E (mov ecx,[ebp-150h] / sub ecx,[ebp-1B4h] — расчёт разброса перед `cmp ecx,0Ah`) → трамплин → P112_Decide:
//  максимум и минимум уровней — при SpreadWholeParty=1 по ОБЩЕМУ ПУЛУ игроков процесса (все карты: у каждого потока-карты свой CUserManager, sub_5324A0
//  видит только свою; пул — [0x60AD18+0x12E0], шаг 0x40BA0, 550 записей, занятая — +372 ≠ −1), с тем же номером отряда (CUser+436; номер
//  выдаёт единый CPartyManager RelayServer, на канале он уникален); иначе по записям пакета (проверка стока: учётка и отряд).
//  Разброс ≥ SpreadLimit — ecx = 10 (ветка стока «никому»), иначе ecx = 0.
//  FixMin59=0 — минимум как у стока (не выше 59). Индивидуальная проверка sub_4C7C70 (уровень − уровень моба < 7) не меняется.
//  Mode=0 — решение стока, расхождения только в журнал. Журнал ac.other 181 (сток дал бы опыт, разброс отряда запретил), 182 (сток запретил
//  из-за константы 59, опыт разрешён), 183 (исключение — сток); ограничитель JournalIntervalSec на (отряд, вид).
//  Откат: patches.ini [P112_PartyExpSpread] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"P112_PartyExpSpread";              // секция patches.ini

    // ── площадка: расчёт разброса sub_4C7650 ──────────────────────────────────
    constexpr DWORD kSite    = 0x004C7A8E;                     // mov ecx,[ebp-150h] ; sub ecx,[ebp-1B4h]
    constexpr DWORD kSiteLen = 12;                             // jmp rel32 + 7 nop
    const BYTE kSiteOrig[kSiteLen] = { 0x8B, 0x8D, 0xB0, 0xFE, 0xFF, 0xFF, 0x2B, 0x8D, 0x4C, 0xFE, 0xFF, 0xFF };
    constexpr DWORD kBack = 0x004C7A9A;                        // cmp ecx,0Ah ; jl — решение стока
    const BYTE kBackOrig[5] = { 0x83, 0xF9, 0x0A, 0x7C, 0x05 };
    constexpr DWORD kMinInit = 0x004C77E7;                     // mov [ebp-1B4h],3Bh — стартовый минимум (сверка, не правится)
    const BYTE kMinInitOrig[10] = { 0xC7, 0x85, 0x4C, 0xFE, 0xFF, 0xFF, 0x3B, 0x00, 0x00, 0x00 };

    constexpr int kStockCut    = 10;                           // порог стока в `cmp ecx,0Ah`
    constexpr int kStockMin    = 59;                           // стартовый минимум стока
    constexpr int kMaxSlots    = 0x226;                        // записей пула (CThreadManager, цикл инициализации 550)
    constexpr DWORD kUserPool  = 0x0060BFF8;                   // [0x60AD18+0x12E0] — общий пул CUser всех карт процесса (как P96)
    constexpr DWORD kUserStep  = 0x40BA0;                      // шаг записи пула
    constexpr int kOffLevel    = 402;                          // CUser: уровень (байт; как читает sub_4C7650)
    constexpr int kOffParty    = 436;                          // CUser: номер отряда (i16; −1 — нет)
    constexpr int kOffUserIdx  = 372;                          // CUser: UserIndex (учётка)
    constexpr int kPktParty    = 0;                            // тело 8306 (слова): номер отряда
    constexpr int kPktUsers    = 2;                            // тело 8306 (слова): 6 слотов
    constexpr int kPktIndex    = 8;                            // тело 8306 (слова): 6 учёток (dword)
    constexpr int kOp8306      = 8306;                         // опкод для журнала

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1; P112 — 181–183).
    constexpr BYTE kKindBlocked  = 181;                        // сток дал бы опыт, разброс отряда запретил
    constexpr BYTE kKindUnlocked = 182;                        // сток запретил из-за константы 59, опыт разрешён
    constexpr BYTE kKindFault    = 183;                        // исключение — решение стока

    typedef BYTE* (__fastcall *FnGetUser)(void* self, void* edx, int userNum);   // sub_5324A0 (thiscall i16)
    FnGetUser const pGetUser = (FnGetUser)Srv::kGetUser;

    int  g_mode        = 1;                                    // 1 — решение; 0 — только журнал (сток)
    int  g_spreadLimit = 10;                                   // разброс, с которого опыта нет никому
    bool g_wholeParty  = true;                                 // весь отряд; иначе записи пакета
    bool g_fixMin      = true;                                 // настоящий минимум; иначе не выше 59, как сток
    int  g_intervalSec = 60;                                   // ограничитель журнала, с
    P112_Stats g_stats = {};                                   // счётчики (экспорт P112_GetStats)
    DWORD g_lastJournal[4096][2] = {};                         // ограничитель: GetTickCount последней строки (отряд & 4095, вид 0/1)

    // Строка журнала ac.other с ограничителем (отряд, вид).
    void Report(BYTE kind, int party, int lo, int hi, int members)
    {
        const DWORD now = GetTickCount();
        DWORD* last = &g_lastJournal[party & 4095][kind == kKindBlocked ? 0 : 1];
        if (*last != 0 && (now - *last) < (DWORD)g_intervalSec * 1000u) { InterlockedIncrement(&g_stats.suppressed); return; }
        *last = now ? now : 1;
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = kOp8306;
        e.v[0] = party;                                        // item_code: номер отряда
        e.v[1] = lo;                                           // value1:    меньший уровень
        e.v[2] = hi;                                           // value2:    больший уровень
        char t[96];
        _snprintf_s(t, sizeof(t), _TRUNCATE, "P112 party %d lv %d..%d members %d limit %d mode %d", party, lo, hi, members, g_spreadLimit, g_mode);
        AcJournal::CopyText(e, t);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }
}

// ── C-часть трамплина площадки 0x4C7A8E ──────────────────────────────────────────────────────────────────────────
//   mgr — CUserManager ([ebp-200h]); pkt — тело 8306 ([ebp-1B0h]); hiStock/loStock — максимум и минимум стока. Возврат — ecx для `cmp ecx,0Ah`.
extern "C" int __stdcall P112_Decide(void* mgr, const short* pkt, int hiStock, int loStock)
{
    InterlockedIncrement(&g_stats.seen);
    const int stock = hiStock - loStock;
    __try
    {
        const short party = pkt[kPktParty];
        int lo = 256, hi = -1, members = 0;
        auto take = [&](const BYTE* u)
        {
            const int lv = u[kOffLevel];
            if (lv < lo) { lo = lv; }
            if (lv > hi) { hi = lv; }
            ++members;
        };
        if (g_wholeParty)
        {
            const BYTE* pool = *(const BYTE* const*)kUserPool;
            for (int s = 0; pool && s < kMaxSlots; ++s)
            {
                const BYTE* u = pool + (size_t)kUserStep * s;
                if (*(const int*)(u + kOffUserIdx) != -1 && *(const short*)(u + kOffParty) == party && u[kOffLevel] > 0) { take(u); }
            }
        }
        else
        {
            for (int i = 0; i < 6; ++i)                        // записи пакета — с проверкой стока (учётка и отряд)
            {
                const BYTE* u = pGetUser(mgr, nullptr, pkt[kPktUsers + i]);
                if (u && *(const int*)(u + kOffUserIdx) == *(const int*)&pkt[kPktIndex + 2 * i] && *(const short*)(u + kOffParty) == party) { take(u); }
            }
        }
        if (hi < 0) { return stock; }                          // никого — решение стока
        if (!g_fixMin && lo > kStockMin) { lo = kStockMin; }
        const bool block = hi - lo >= g_spreadLimit;
        const bool stockBlock = stock >= kStockCut;
        if (block && !stockBlock)
        {
            InterlockedIncrement(&g_stats.blocked);
            Report(kKindBlocked, party, lo, hi, members);
        }
        else if (!block && stockBlock)
        {
            InterlockedIncrement(&g_stats.unlocked);
            Report(kKindUnlocked, party, lo, hi, members);
        }
        if (!g_mode) { return stock; }
        return block ? kStockCut : 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kKindFault);
            e.opcode = kOp8306;
            AcJournal::Push(e);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return stock;
    }
}

extern "C" __declspec(dllexport) void __stdcall P112_GetStats(P112_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_backAddr = kBack;                                  // продолжение стока

    // Трамплин площадки 0x4C7A8E. Вход по jmp из sub_4C7650: ebp — его кадр. Регистры на площадке не живые (сток грузит ecx из кадра, edx/eax —
    //   после ветки), флаги тоже. Ответ — в сохранённый ecx (pushad: +18h).
    __declspec(naked) void DecideTrampoline()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x1B4]              // минимум стока
            push  dword ptr [ebp-0x150]              // максимум стока
            lea   eax, [ebp-0x1B0]
            push  eax                                // тело 8306
            push  dword ptr [ebp-0x200]              // CUserManager
            call  P112_Decide
            mov   dword ptr [esp+0x18], eax          // ecx для `cmp ecx,0Ah`
            popad
            jmp   dword ptr [g_backAddr]             // 0x4C7A9A
        }
    }
}

PatchResult P112_PartyExpSpread()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_spreadLimit = Config::GetInt(kSec, L"SpreadLimit", 10);
    g_wholeParty  = Config::GetBool(kSec, L"SpreadWholeParty", true);
    g_fixMin      = Config::GetBool(kSec, L"FixMin59", true);
    g_intervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 60);
    if (g_spreadLimit < 1 || g_spreadLimit > 255) { g_spreadLimit = 10; }
    if (g_intervalSec < 0) { g_intervalSec = 0; }

    const Site sites[] =
    {
        { kSite,    kSiteOrig,    sizeof(kSiteOrig)    },
        { kBack,    kBackOrig,    sizeof(kBackOrig)    },
        { kMinInit, kMinInitOrig, sizeof(kMinInitOrig) },
    };
    if (!VerifyAllSites(L"P112", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &DecideTrampoline, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P112: sub_4C7650 @0x%08X (12 б) -> трамплин 0x%08X: разброс отряда ≥ %d — опыта нет никому (%s, минимум %s); Mode=%d; журнал "
              L"ac.other 181/182/183", kSite, (DWORD)&DecideTrampoline, g_spreadLimit, g_wholeParty ? L"весь отряд" : L"записи 8306",
              g_fixMin ? L"настоящий" : L"как сток, не выше 59", g_mode);
    return PatchResult::Applied;
}
