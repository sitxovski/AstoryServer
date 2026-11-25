// Copyright (c) 2026 @sitxovski (Discord)
// n20_party_share_clamp.cpp — ДОЛЯ УРОНА В ОПЫТЕ ОТРЯДА ЗАЖИМАЕТСЯ ТАК ЖЕ, КАК У ОДИНОЧКИ (слот P90, 26.10.2026).
//
// [ИСПРАВЛЕНИЕ] дефекта стока, который стал заметен из-за N10.
//
// СИМПТОМ (жалоба владельца 26.10: «игрок получил с обычного моба в Rain River неадекватно много опыта»)
//   Живой случай: Player14 (учётка Player15, ур. 18–19) в отряде с Player17, Rein, 19.10 23:27–23:29 — за StampBlade
//   (ур. 16, база 29) и GapeCrab (ур. 17, база 31) по 1380/1756 опыта = ровно 1/9 уровня (потолок GameServer), а по
//   формуле ~60. GameServer Log_Exp: «iExp 7010019 … fUpDown 4.52» — NpcServer прислал по 7 млн за моба.
//
// МЕХАНИЗМ (NpcServer CMonster::Process_MonsterDead = sub_437A30, NpcServer.exe.c:41287-41390)
//   Доля игрока = урон в списке угрозы (+12 записи) / МАКСИМУМ здоровья (+31288 = +7A38h) × база (+30861) + 0.9.
//   Две ветки по записи списка:
//     • одиночка (0x437DA6): сток ЗАЖИМАЕТ урон сверху максимумом здоровья (`cmp [ecx],eax / jle / mov [ecx],eax`);
//     • отряд   (0x437ECD): зажима НЕТ — доля > 1 даёт опыт больше базы, отрицательный урон — отрицательный опыт.
//   В стоке урон в список приходил только из sub_4423C0 (навыки), уже зажатым остатком здоровья, и ветка отряда без
//   зажима почти не срабатывала. N10 (наша правка) пишет урон обычной атаки; её первая редакция складывала ещё и
//   указатель (~2·10^8 на пакет) — ветка отряда отдавала миллионы, GameServer упирался в 1/9 уровня за моба.
//   Сама N10 исправлена (см. n10), а эта правка закрывает ветку отряда от ЛЮБОГО источника завышенного/отрицательного
//   урона: перебой последнего удара, будущие площадки, мусор в записи.
//
// ЧТО ДЕЛАЕМ
//   На площадке 0x437ECD (первая инструкция расчёта доли отряда) — тот же зажим, что у одиночки, с записью обратно
//   в поле (как делает сток в 0x437DB4): урон > максимума → максимум; ключ ClampNegative=1 — урон < 0 → 0 (у одиночки
//   сток отрицательный не трогает; при нуле доля 0 и опыт округляется так же, как у не бившего).
//   Аномалии (урон < 0 или > 2 × максимума) — в журнал ac.other 115 (item_code = тип монстра +30808, value1 = урон,
//   value2 = максимум здоровья, detail «N20 base B lvl L map M mob I»). 116 — исключение в разборе (поведение стока).
//
// ПЛОЩАДКА (сток d292e4ec / живой c02486d6 / Indun 0de2c559 — байты одинаковы, сверяет verify_n20.py)
//     00437ECD  8B 54 24 18     mov  edx, [esp+18h]      ; edx -> поле «урон» записи списка угрозы (+12)
//     00437ED1  6B F6 53        imul esi, esi, 53h       ; индекс записи отряда × 83
//     00437ED4  DB 02           fild dword ptr [edx]     ; ← сюда возвращаемся
//   В стабе: pushfd/pushad, указатель поля = [esp + 18h + 24h + 4] (кадр + pushad/pushfd + адрес возврата), монстр = ebp
//   (0x437ED6 `fidiv [ebp+7A38h]`). После popad/popfd — исходные инструкции: `mov edx,[esp+1Ch]` (+4 на адрес возврата)
//   и `imul esi,esi,53h` (флаги после него — как в стоке). Переходов внутрь 0x437ECE…0x437ED3 нет (verify_n20.py).
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЧЕРЕЗ #define (см. n03): C++-константа в `[reg + имя]` даёт АДРЕС.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"
#include "AcJournal.h"

namespace
{
    const DWORD kVa     = 0x00437ECD;                                              // mov edx,[esp+18h] / imul esi,esi,53h
    const BYTE  kOrig[] = { 0x8B, 0x54, 0x24, 0x18, 0x6B, 0xF6, 0x53 };
    const Site  kSites[] = { { kVa, kOrig, sizeof(kOrig) } };

    constexpr int kOffMaxHp  = 0x7A38;   // монстр +31288: максимум здоровья (Monster.ai +0x2D)
    constexpr int kOffType   = 0x7858;   // монстр +30808: тип (id Monster.ai, начало копии записи 479 б)
    constexpr int kOffLevel  = 0x785C;   // монстр +30812: уровень (байт)
    constexpr int kOffBase   = 0x788D;   // монстр +30861: базовый опыт (Monster.ai +0x35)
    constexpr int kOffMap    = 0x7732;   // монстр +30514: номер карты (i16)
    constexpr int kOffMobIdx = 0x7694;   // монстр +30356: номер монстра на карте

    #define DMG_PTR  40h                 // [esp+18h] кадра в стабе: 18h + 24h (pushad/pushfd) + 4 (адрес возврата)
    #define DMG_ORIG 1Ch                 // исходная `mov edx,[esp+18h]` после popad/popfd: +4 на адрес возврата

    bool g_clampNegative = true;         // ClampNegative=1 — отрицательный урон в ветке отряда → 0
    volatile LONG g_hits = 0, g_high = 0, g_low = 0, g_journaled = 0;   // площадка / зажато сверху / снизу / записей 115
}

// mob — монстр (ebp на площадке), dmg — поле «урон» записи списка угрозы. Зажим как у одиночки (сток 0x437DA6).
extern "C" void __stdcall N20_Clamp(BYTE* mob, int* dmg)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        if (!mob || !dmg) { return; }
        const int maxHp = *(const int*)(mob + kOffMaxHp);
        const int d = *dmg;
        int fixed = d;
        if (d > maxHp) { fixed = maxHp; InterlockedIncrement(&g_high); }   // ровно как сток одиночки (знаковое jle), и при максимуме ≤ 0
        else if (d < 0 && g_clampNegative) { fixed = 0; InterlockedIncrement(&g_low); }
        if (fixed == d) { return; }
        *dmg = fixed;
        if (d < 0 || (maxHp > 0 && d / 2 > maxHp))   // аномалия, а не перебой последнего удара
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, 115);
            e.opcode = 8306;                                         // запись отряда уходит GameServer пакетом 8306
            e.v[0] = *(const int*)(mob + kOffType);                  // item_code ← тип монстра
            e.v[1] = d;                                              // value1 ← урон в записи до зажима
            e.v[2] = maxHp;                                          // value2 ← максимум здоровья
            char t[64];
            wsprintfA(t, "N20 base %d lvl %d map %d mob %d", *(const int*)(mob + kOffBase), (int)mob[kOffLevel],
                      (int)*(const short*)(mob + kOffMap), *(const int*)(mob + kOffMobIdx));
            AcJournal::CopyText(e, t);
            if (AcJournal::Push(e)) { InterlockedIncrement(&g_journaled); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        __try
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, 116);
            e.opcode = 8306;
            AcJournal::Push(e);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// Счётчики (стенд): вызовы площадки, зажато сверху, зажато снизу, записей журнала 115.
extern "C" __declspec(dllexport) void __stdcall N20_Counters(LONG* hits, LONG* high, LONG* low, LONG* journaled)
{
    if (hits) { *hits = g_hits; }
    if (high) { *high = g_high; }
    if (low) { *low = g_low; }
    if (journaled) { *journaled = g_journaled; }
}

namespace
{
    __declspec(naked) void St_PartyShare()
    {
        __asm
        {
            pushfd
            pushad
            push    dword ptr [esp + DMG_PTR]   // поле «урон» записи списка угрозы
            push    ebp                         // монстр
            call    N20_Clamp                   // __stdcall, 8 б
            popad
            popfd
            mov     edx, dword ptr [esp + DMG_ORIG]   // исходная `mov edx,[esp+18h]` (+4 адрес возврата)
            imul    esi, esi, 53h                     // исходная `imul esi,esi,53h`
            ret
        }
    }
}

PatchResult N20_PartyShareClamp()
{
    if (!Config::GetBool(L"N20_PartyShareClamp", L"Enabled", true)) { return PatchResult::Disabled; }
    g_clampNegative = Config::GetBool(L"N20_PartyShareClamp", L"ClampNegative", true);
    if (!VerifyAllSites(L"N20_PartyShareClamp", kSites, ARRAYSIZE(kSites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteCall(kVa, (void*)&St_PartyShare, sizeof(kOrig))) { return PatchResult::Failed; }
    Log::Line(L"    N20: доля урона отряда в Process_MonsterDead зажата максимумом здоровья, как у одиночки%s; "
              L"аномалии — журнал ac.other 115", g_clampNegative ? L" (и снизу нулём)" : L"");
    return PatchResult::Applied;
}
