// Copyright (c) 2026 @sitxovski (Discord)
// p91_exp_cap_rate.cpp — ПОТОЛОК ОПЫТА ЗА МОБА МАСШТАБИРУЕТСЯ РЕЙТОМ СОБЫТИЯ (P91, волна exprate, 26.10.2026).
//
// [ИСПРАВЛЕНИЕ] по решению владельца 26.10 («сделай правильно»; жалоба игроков «Exp x3 даёт только 10 %»).
//
// СТОК (GameServer e7b4ac38 = IDB = живой = Indun)
//   Опыт за моба (a5 = 0) режется потолком «1/9 уровня»: (ExpTable[ур+1] − ExpTable[ур]) / 9 —
//     одиночка  Recv_BattleServerFromCharParamExp_1@0x4CBA90: площадка 0x4CBC09…0x4CBC2C (`push 0 / push 9 / … / call
//               __alldiv / mov [ebp-100h], eax / mov [ebp-0FCh], edx`), диапазон уровня в [ebp-100h] (i64);
//     отряд     sub_4C7C70@0x4C7C70: площадка 0x4C8012…0x4C8035, диапазон в [ebp-118h] (i64).
//   Рейт (fEvent из NpcServer + Lucky Hours GameServerEvent.txt + личные %) применяется РАНЬШЕ, в GetExpUpDownValue@0x4CC3A0,
//   и потолком «съедается»: на ур. 1 x2 = x3 = x5 = 10 % за моба (MOB_EXP_AUDIT.md §3).
//
// ЧТО ДЕЛАЕМ
//   потолок = диапазон_уровня × max(1, fEvent + LuckyHours) / CapDivisor, не больше целого уровня.
//   • fEvent — аргумент функции (a6, float, тот же, что получил GetExpUpDownValue); LuckyHours — тот же цикл, что у стока
//     (0x4CC3FE…0x4CC492: первая строка «год/мес/день = сегодня, час_от ≤ час < час_до», массивы 0x5E23AC/0x5E2414/
//     0x5E247C/0x5E24E4/0x5E26DC/0x5E2744, счётчик WORD 0x5A7964 со знаком), сумма во float, как у стока.
//   • ЛИЧНЫЕ проценты (бафы/зелья param 53−54, опция 53 вещей, поля-усилители CUser+0xBEBB/0xBEE5, опция 103) в потолок
//     НЕ входят — решение волны: потолок ограничивает прыжок за одного моба относительно ТЕМПА СЕРВЕРА; событие меняет темп
//     для всех — потолок растёт с ним; личный бонус ускоряет игрока относительно других внутри того же предела (как в
//     стоке, где он тоже упирается в потолок). С личными % (на живом до +162 %) потолок на ур. 1–3 вырос бы до ~51 % за моба —
//     цель «не больше доли уровня за моба» потеряла бы смысл.
//   • max(1, …): ниже стока потолок не опускается никогда (событие с Value < 1 не делает потолок строже стока).
//   • CapScalesWithRate=0 и CapDivisor=9 — ровно сток (тот же __alldiv со знаком). Задания/GM/зелье P75 (a5 = 1) — не
//     трогаются (стоковая ветка обходит площадку). Доля соулмейта-партнёра (sub_4CC290 → _1 с a5 = 0) получает тот же потолок.
//   • Рейт вне [0, 20] или не число — потолок стока, журнал ac.other 118; исключение — потолок стока, журнал 119. 120 свободен.
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЧЕРЕЗ #define/литералы (C++-константа в `[reg + имя]` даёт АДРЕС).
// Документ: AstoryServer/Docs/GameServer/exp-cap-rate-p91.md; разбор Reports/exprate/MOB_EXP_AUDIT.md.
// Проверки: tools/verify_p91.py (образы, переходы, кадр), tools/stand_p91 (настоящий код площадок, матрица рейтов × уровни).
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P91_ExpCapRate";                    // секция patches.ini

    const DWORD kSiteSolo  = 0x004CBC09;                         // Recv_BattleServerFromCharParamExp_1: деление /9
    const DWORD kBackSolo  = 0x004CBC2C;                         // продолжение стока (проверка «≤ 0 → 1»)
    const DWORD kSiteParty = 0x004C8012;                         // sub_4C7C70 (отряд): деление /9
    const DWORD kBackParty = 0x004C8035;
    const SIZE_T kSiteLen  = 0x23;                               // 35 б у обеих площадок
    // 0x4CBC09: push 0 / push 9 / mov edx,[ebp-0FCh] / push edx / mov eax,[ebp-100h] / push eax / call __alldiv /
    //           mov [ebp-100h],eax / mov [ebp-0FCh],edx
    const BYTE kSoloOrig[kSiteLen] = {
        0x6A,0x00, 0x6A,0x09, 0x8B,0x95,0x04,0xFF,0xFF,0xFF, 0x52, 0x8B,0x85,0x00,0xFF,0xFF,0xFF, 0x50,
        0xE8,0x30,0x22,0x0A,0x00, 0x89,0x85,0x00,0xFF,0xFF,0xFF, 0x89,0x95,0x04,0xFF,0xFF,0xFF };
    // 0x4C8012: push 0 / push 9 / mov eax,[ebp-114h] / push eax / mov ecx,[ebp-118h] / push ecx / call __alldiv /
    //           mov [ebp-118h],eax / mov [ebp-114h],edx
    const BYTE kPartyOrig[kSiteLen] = {
        0x6A,0x00, 0x6A,0x09, 0x8B,0x85,0xEC,0xFE,0xFF,0xFF, 0x50, 0x8B,0x8D,0xE8,0xFE,0xFF,0xFF, 0x51,
        0xE8,0x27,0x5E,0x0A,0x00, 0x89,0x85,0xE8,0xFE,0xFF,0xFF, 0x89,0x95,0xEC,0xFE,0xFF,0xFF };

    // Массивы GameServerEvent.txt (загрузчик sub_4190E0) — глобалы с УКАЗАТЕЛЯМИ на массивы.
    const DWORD kEvCount = 0x005A7964;   // WORD (со знаком, как movsx у стока)
    const DWORD kEvYear  = 0x005E23AC;   // -> WORD[]
    const DWORD kEvMonth = 0x005E2414;   // -> char[]
    const DWORD kEvDay   = 0x005E247C;   // -> char[]
    const DWORD kEvHFrom = 0x005E24E4;   // -> char[]
    const DWORD kEvHTo   = 0x005E26DC;   // -> char[]
    const DWORD kEvValue = 0x005E2744;   // -> float[]

    int  g_divisor = 9;                  // CapDivisor (≥ 1; иначе 9)
    bool g_scale   = true;               // CapScalesWithRate
    DWORD g_backSolo = kBackSolo, g_backParty = kBackParty;   // адреса продолжения (для jmp [mem])
    volatile LONG g_calls[2] = {}, g_raised[2] = {}, g_bad = 0, g_exc = 0, g_journaled = 0;

    // Lucky Hours ровно как сток (0x4CC3FE…0x4CC492): первая подходящая строка, сумма во float.
    float LuckyNow()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        const int n = *(const short*)kEvCount;
        const short* year = *(const short* const*)kEvYear;
        const char* mon = *(const char* const*)kEvMonth;
        const char* day = *(const char* const*)kEvDay;
        const char* hf  = *(const char* const*)kEvHFrom;
        const char* ht  = *(const char* const*)kEvHTo;
        const float* val = *(const float* const*)kEvValue;
        for (int i = 0; i < n; ++i)
        {
            if (year[i] == (int)st.wYear && mon[i] == (int)st.wMonth && day[i] == (int)st.wDay
                && hf[i] <= (int)st.wHour && ht[i] > (int)st.wHour)
            {
                return val[i];
            }
        }
        return 0.0f;
    }

    void Journal(BYTE kind, int site, int userNum, float rate, __int64 range)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.userNum = (short)userNum;
        e.opcode = site ? 8306 : 8301;                            // откуда пришёл опыт моба: отряд / одиночка
        e.v[0] = site;                                            // item_code ← площадка (0 одиночка, 1 отряд)
        e.v[1] = (int)(range > 0x7FFFFFFF ? 0x7FFFFFFF : range);  // value1 ← диапазон уровня
        e.v[2] = (int)(rate * 1000.0f);                           // value2 ← рейт × 1000 (как прочитан)
        char t[64];
        sprintf_s(t, "P91 rate %.3f div %d scale %d", (double)rate, g_divisor, g_scale ? 1 : 0);
        AcJournal::CopyText(e, t);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_journaled); }
    }
}

// Новый потолок: *range (i64, диапазон уровня, > 0 — стоковая ветка уже проверила) → потолок за моба.
//   site — 0 одиночка / 1 отряд; fevBits — float fEvent из аргумента функции.
extern "C" void __stdcall P91_Cap(int site, int userNum, DWORD fevBits, __int64* range)
{
    const __int64 r = *range;
    __int64 cap = r / g_divisor;                                  // как сток при CapDivisor=9 (знаковое __alldiv)
    InterlockedIncrement(&g_calls[site & 1]);
    if (g_scale)
    {
        __try
        {
            float fev;
            memcpy(&fev, &fevBits, 4);
            const float rate = fev + LuckyNow();                  // во float — как стоковая сумма expRateBonus
            if (!(rate >= 0.0f && rate <= 20.0f))                 // NaN / вне разумного — потолок стока
            {
                InterlockedIncrement(&g_bad);
                Journal(118, site, userNum, rate, r);
            }
            else if (rate > 1.0f)
            {
                double c = floor((double)r * (double)rate / (double)g_divisor);
                if (c > (double)r) { c = (double)r; }            // не больше целого уровня
                const __int64 ci = (__int64)c;
                if (ci > cap) { cap = ci; InterlockedIncrement(&g_raised[site & 1]); }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedIncrement(&g_exc);
            __try { Journal(119, site, userNum, 0.0f, r); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    *range = cap;
}

// Статистика (стенд tools/stand_p91): вызовы и подъёмы по площадкам, плохой рейт, исключения, записи журнала.
extern "C" __declspec(dllexport) void __stdcall P91_GetStats(LONG* out7)
{
    if (!out7) { return; }
    out7[0] = g_calls[0]; out7[1] = g_calls[1]; out7[2] = g_raised[0]; out7[3] = g_raised[1];
    out7[4] = g_bad; out7[5] = g_exc; out7[6] = g_journaled;
}

namespace
{
    // Одиночка: кадр Recv_BattleServerFromCharParamExp_1 — [ebp+8] userNum (WORD), [ebp+1Ch] fEvent (a6), [ebp-100h] диапазон.
    __declspec(naked) void St_Solo()
    {
        __asm
        {
            pushfd
            pushad
            lea     eax, [ebp - 100h]
            push    eax                         // диапазон уровня (i64) — читается и пишется
            push    dword ptr [ebp + 1Ch]       // fEvent (биты float)
            movzx   eax, word ptr [ebp + 8]
            push    eax                         // userNum
            push    0                           // площадка: одиночка
            call    P91_Cap                     // __stdcall, 16 б
            popad
            popfd
            jmp     dword ptr [g_backSolo]      // 0x4CBC2C — сток: «≤ 0 → 1», сравнение с прибавкой
        }
    }
    // Отряд: кадр sub_4C7C70 — [ebp+8] userNum, [ebp+1Ch] fEvent (a6), [ebp-118h] диапазон.
    __declspec(naked) void St_Party()
    {
        __asm
        {
            pushfd
            pushad
            lea     eax, [ebp - 118h]
            push    eax
            push    dword ptr [ebp + 1Ch]
            movzx   eax, word ptr [ebp + 8]
            push    eax
            push    1                           // площадка: отряд
            call    P91_Cap
            popad
            popfd
            jmp     dword ptr [g_backParty]     // 0x4C8035
        }
    }
}

PatchResult P91_ExpCapRate()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_divisor = Config::GetInt(kSec, L"CapDivisor", 9);
    if (g_divisor < 1 || g_divisor > 1000) { g_divisor = 9; }
    g_scale = Config::GetBool(kSec, L"CapScalesWithRate", true);
    const bool solo  = Config::GetBool(kSec, L"SoloSite", true);
    const bool party = Config::GetBool(kSec, L"PartySite", true);

    const Site sites[] = { { kSiteSolo, kSoloOrig, kSiteLen }, { kSiteParty, kPartyOrig, kSiteLen } };
    if (!VerifyAllSites(L"P91", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!solo && !party) { return PatchResult::Disabled; }
    if (solo && !Hook::WriteJmp(kSiteSolo, (void*)&St_Solo, kSiteLen)) { return PatchResult::Failed; }
    if (party && !Hook::WriteJmp(kSiteParty, (void*)&St_Party, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P91: потолок опыта за моба = уровень × max(1, fEvent + LuckyHours) / %d%s — одиночка %s, отряд %s; "
              L"личные %% в потолок не входят; журнал ac.other 118/119", g_divisor,
              g_scale ? L"" : L" (CapScalesWithRate=0 — без рейта)", solo ? L"да" : L"нет", party ? L"да" : L"нет");
    return PatchResult::Applied;
}
