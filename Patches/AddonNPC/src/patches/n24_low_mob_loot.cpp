// Copyright (c) 2026 @sitxovski (Discord)
// n24_low_mob_loot.cpp — НЕТ ЛУТА С МОБОВ НАМНОГО НИЖЕ ИГРОКА И В ОТРЯДЕ С БОЛЬШИМ РАЗБРОСОМ УРОВНЕЙ (06.11.2026, сессия pet-hatch-summon).
//
// [ИСПРАВЛЕНИЕ] отклонение от оригинала по решению владельца (06.11.2026): «лута с таких мобов быть не должно»;
//   «IF THERE IS A PARTY WITH PLAYERS WHERE lower IS 5 and max is 60. NO EXP AND NO LOOT FOR EVERYONE».
//   Документ: AstoryServer/Docs/NpcServer/low-mob-loot-n24.md.
//
// ПОТОК (NpcServer CMonster::Process_MonsterDead = sub_437A30, NpcServer.exe.c:41052; функция одна в живом c02486d6, Ch2 7f79b5da, Indun
//   0de2c559). Лут разыгрывается ОДИН раз на владельца (первый по угрозе; при флаге монстра +30958&2 — убийца): предметы +30982 / +31182,
//   деньги +30981, мировой дроп +31202; проверки уровней в нём нет. Итог уходит GameServer одним пакетом 8303 (130 б). Опыт — иное:
//   у каждой записи угрозы своя проверка «уровень игрока − уровень моба ≤ 6», отряд — дополнительно разброс < 10 (GameServer sub_4C7650).
//
// ЧТО ДЕЛАЕМ (площадка — `call sub_455120` отправки 8303, 0x4387D7; розыгрыш и ход ГСЧ не меняются; блок заданий +31210 идёт ПОСЛЕ
//   площадки и не трогается; опыт разобран раньше и не меняется):
//   участник годен, если уровень игрока − уровень моба < LevelGap (7) и у его отряда разброс уровней < SpreadLimit (10);
//   • владелец годен — пакет как есть;
//   • иначе владелец — первый по угрозе годный из списка (порядок стока: больше урона, при равенстве — меньше поле +4);
//   • годных нет — пакета нет: ни предметов, ни денег, ни мирового дропа.
//   Боссы — без исключений. Бонус шанса посчитан стоком по исходному владельцу (решение координатора 06.11).
//   Разброс: максимум − минимум уровней отряда. SpreadWholeParty=1 — все члены отряда, известные этому NpcServer (номер отряда +30470
//   в слоте игрока, слот сбрасывается при выходе: sub_421BD0 → sub_426AB0); 0 — только записи угрозы. Определение опыта уже: оно видит лишь
//   прошедших проверку уровня (лв60 + лв5 на низком мобе дают разброс 0) — слова владельца про такой отряд оно не выполняет.
//   ★ 09.11.2026 (слово владельца: «If party members are at least 80 coordinate units apart on the map, enable loot drops. Then, for each
//   party member individually, apply the rule that checks the level difference»): в разброс входят только члены отряда, стоящие БЛИЖЕ
//   SpreadRangeTiles (80) клеток к проверяемому участнику на той же карте (+30514; ★ ревизия 09.11: +30356 — UserIndex, +30508 — поток, не сервер и не карта); дальний и на другой карте
//   разброса не дают. Позиция — текущая мировая (+30416 x, +30420 z, float; пишет Process_UserMove → sub_428530), клетка — размер из
//   сектор-менеджера карты (+30532 → +44 / +48, как sub_4349A0: мир = клетка·размер + 25), то есть те же клетки, что видит игрок («46, 240»).
//   Затем у каждого участника отдельно — LevelGap. SpreadRangeTiles=0 — дальность не учитывается (как до 09.11).
//   Mode=0 — только журнал. Журнал ac.other 177 (снято: разница уровней), 178 (снято: разброс), 179 (сменён владелец), 180 (исключение —
//   сток); ограничитель JournalIntervalSec на (слот, вид).
//
// ПЛОЩАДКА: 004387D7 E8 44 C9 01 00 call sub_455120 (usercall: cx размер, edi тело, 4 аргумента стека, ret 10h). В стабе: pushad, ebp —
//   монстр, edi — тело; ответ в сохранённый eax; годен — jmp sub_455120 (стек как при вызове), нет — ret 10h. eax после вызова сток не читает.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"
#include "AcJournal.h"

namespace
{
    const wchar_t* kSec = L"N24_LowMobLoot";                  // секция patches.ini

    const DWORD kVa     = 0x004387D7;                         // call sub_455120 — отправка 8303
    const BYTE  kOrig[] = { 0xE8, 0x44, 0xC9, 0x01, 0x00 };
    const DWORD kSendVa = 0x00455120;                         // sub_455120 — отправка пакета GameServer
    const BYTE  kSendOrig[] = { 0x81, 0xEC, 0xCC, 0x02, 0x00, 0x00 };   // sub esp, 2CCh — пролог, сверка цели
    const Site  kSites[] = { { kVa, kOrig, sizeof(kOrig) }, { kSendVa, kSendOrig, sizeof(kSendOrig) } };

    constexpr int kOffMobType   = 30808;                      // монстр: тип (id Monster.ai)
    constexpr int kOffMobLevel  = 30812;                      // монстр: уровень (байт)
    constexpr int kOffPlayers   = 30536;                      // монстр: массив игроков этого GameServer
    constexpr int kOffThreat    = 31352;                      // монстр: список угрозы, 20 записей по 16 б
    constexpr int kThreatCount  = 20;                         // записей угрозы
    constexpr int kThreatStep   = 16;                         // шаг записи угрозы
    constexpr int kThreatOrder  = 4;                          // запись угрозы: поле порядка при равном уроне
    constexpr int kThreatDamage = 12;                         // запись угрозы: урон
    constexpr int kPlayerStep   = 68264;                      // шаг записи игрока
    constexpr int kPlayerCount  = 1000;                       // слотов игроков
    constexpr int kOffPlayerLv  = 30858;                      // игрок: уровень (байт; 0 — слот свободен)
    constexpr int kOffPlayerPty = 30470;                      // игрок: номер отряда (i16; −1 — нет)
    constexpr int kOffMap       = 30514;                      // игрок: карта (i16; блок +30504…+30531 из описания потока, Process_PlayerLogin)
    // ★ Ревизия 09.11: +30356 у игрока — UserIndex (Process_PlayerLogin, NpcServer.exe.c:60927), +30508 — номер потока: не сравнивать.
    constexpr int kOffPosX      = 30416;                      // игрок: мировой x (float; sub_428530)
    constexpr int kOffPosZ      = 30420;                      // игрок: мировой z (float)
    constexpr int kOffMapInfo   = 30532;                      // игрок: сектор-менеджер карты (+44 ширина клетки, +48 высота клетки)
    constexpr int kBodyItems    = 8;                          // тело 8303: 20 кодов предметов
    constexpr int kBodyGold     = 128;                        // тело 8303: деньги (i16)
    constexpr int kOp8303       = 8303;                       // опкод для журнала

    constexpr BYTE kKindLevel  = 177;                         // снято: разница уровней
    constexpr BYTE kKindSpread = 178;                         // снято: разброс уровней отряда
    constexpr BYTE kKindOwner  = 179;                         // сменён владелец
    constexpr BYTE kKindFault  = 180;                         // исключение — сток

    enum Why { kFit = 0, kLevel = 1, kSpread = 2 };           // годность участника

    int  g_mode        = 1;                                   // 1 — решение; 0 — только журнал
    int  g_levelGap    = 7;                                   // разница уровней, с которой лута нет
    int  g_spreadLimit = 10;                                  // разброс отряда, с которого лута нет
    bool g_wholeParty  = true;                                // разброс по всему отряду; иначе по записям угрозы
    int  g_rangeTiles  = 80;                                  // в разброс — только члены ближе этого числа клеток (0 — все)
    int  g_intervalSec = 60;                                  // ограничитель журнала, с
    DWORD g_sendAddr   = kSendVa;                             // адрес продолжения стока
    N24_Stats g_stats  = {};                                  // счётчики (экспорт N24_GetStats)
    DWORD g_lastJournal[kPlayerCount][4] = {};                // ограничитель: GetTickCount последней строки (слот, вид)

    // Запись игрока по слоту.
    const BYTE* PlayerAt(const BYTE* players, int slot) { return players + (size_t)kPlayerStep * slot; }

    // Размер клетки по оси (мировых единиц): сектор-менеджер карты +44 / +48; нет указателя или 0 — 100 (мир клиента = клетка × 100).
    float CellOf(const BYTE* p, int off)
    {
        const BYTE* info = *(const BYTE* const*)(p + kOffMapInfo);
        const int v = info ? *(const int*)(info + off) : 0;
        return v > 0 ? (float)v : 100.0f;
    }

    // Стоит ли член отряда p рядом с участником who: та же карта (+30514), ближе g_rangeTiles клеток.
    bool Near(const BYTE* who, const BYTE* p)
    {
        if (g_rangeTiles <= 0 || who == p) { return true; }
        // массив игроков монстра (+30536) — один блок сервера, отдельная сверка сервера не нужна
        if (*(const short*)(p + kOffMap) != *(const short*)(who + kOffMap)) { return false; }
        const float dx = (*(const float*)(p + kOffPosX) - *(const float*)(who + kOffPosX)) / CellOf(who, 44);
        const float dz = (*(const float*)(p + kOffPosZ) - *(const float*)(who + kOffPosZ)) / CellOf(who, 48);
        const float r = (float)g_rangeTiles;
        return dx * dx + dz * dz < r * r;
    }

    // Разброс уровней отряда party среди тех, кто рядом с участником who.
    int SpreadOf(const BYTE* mob, const BYTE* players, short party, const BYTE* who)
    {
        int lo = 256, hi = -1;
        auto take = [&](const BYTE* p)
        {
            if (*(const short*)(p + kOffPlayerPty) != party) { return; }
            if (!Near(who, p)) { return; }
            const int lv = p[kOffPlayerLv];
            if (lv == 0) { return; }
            if (lv < lo) { lo = lv; }
            if (lv > hi) { hi = lv; }
        };
        if (g_wholeParty)
        {
            for (int s = 0; s < kPlayerCount; ++s) { take(PlayerAt(players, s)); }
        }
        else
        {
            for (int i = 0; i < kThreatCount; ++i)
            {
                const WORD slot = *(const WORD*)(mob + kOffThreat + kThreatStep * i);
                if (slot < kPlayerCount) { take(PlayerAt(players, slot)); }
            }
        }
        return hi < 0 ? 0 : hi - lo;
    }

    // Годность участника по слоту; spreadOut — разброс его отряда (0 — без отряда).
    Why Judge(const BYTE* mob, const BYTE* players, int slot, int* spreadOut)
    {
        const BYTE* p = PlayerAt(players, slot);
        *spreadOut = 0;
        if (p[kOffPlayerLv] == 0) { return kLevel; }           // пустой слот (игрок вышел) — не участник: лут без владельца не уходит
        const short party = *(const short*)(p + kOffPlayerPty);
        *spreadOut = party >= 0 ? SpreadOf(mob, players, party, p) : 0;
        if (*spreadOut >= g_spreadLimit) { return kSpread; }
        if ((int)p[kOffPlayerLv] - (int)mob[kOffMobLevel] >= g_levelGap) { return kLevel; }
        return kFit;
    }

    // Первый по угрозе годный (порядок стока); −1 — нет.
    int BestFit(const BYTE* mob, const BYTE* players)
    {
        int best = -1, bestDmg = 0, bestOrder = 0;
        for (int i = 0; i < kThreatCount; ++i)
        {
            const BYTE* e = mob + kOffThreat + kThreatStep * i;
            const WORD slot = *(const WORD*)e;
            if (slot >= kPlayerCount) { continue; }
            int spread = 0;
            if (Judge(mob, players, slot, &spread) != kFit) { continue; }
            const int dmg = *(const int*)(e + kThreatDamage), order = *(const int*)(e + kThreatOrder);
            if (best < 0 || dmg > bestDmg || (dmg == bestDmg && bestOrder > order)) { best = slot; bestDmg = dmg; bestOrder = order; }
        }
        return best;
    }

    // Строка журнала ac.other с ограничителем (слот, вид).
    void Report(BYTE kind, const BYTE* mob, const BYTE* players, const BYTE* body, int owner, int spread, int newOwner)
    {
        const int k = kind - kKindLevel;
        const DWORD now = GetTickCount();
        DWORD* last = &g_lastJournal[owner][k];
        if (*last != 0 && (now - *last) < (DWORD)g_intervalSec * 1000u) { InterlockedIncrement(&g_stats.suppressed); return; }
        *last = now ? now : 1;
        int items = 0;
        while (items < 20 && *(const int*)(body + kBodyItems + 4 * items) > 0) { ++items; }
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.userNum = (short)owner;
        e.opcode  = kOp8303;
        e.v[0] = *(const int*)(mob + kOffMobType);                      // item_code ← тип монстра
        e.v[1] = PlayerAt(players, owner)[kOffPlayerLv];                // value1 ← уровень владельца
        e.v[2] = mob[kOffMobLevel];                                     // value2 ← уровень моба
        char t[96];
        wsprintfA(t, "N24 owner %d spread %d new %d items %d gold %d mode %d", owner, spread, newOwner, items,
                  (int)*(const short*)(body + kBodyGold), g_mode);
        AcJournal::CopyText(e, t);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }
}

// Решение о пакете 8303. mob — монстр (ebp), body — тело (edi). Возврат: 1 — отправить, 0 — лута нет.
extern "C" int __stdcall N24_Filter(BYTE* mob, BYTE* body)
{
    InterlockedIncrement(&g_stats.seen);
    __try
    {
        const BYTE* players = *(BYTE* const*)(mob + kOffPlayers);
        const WORD owner = *(const WORD*)body;
        if (!players || owner >= kPlayerCount) { return 1; }            // сток сам разбирает такой случай
        int spread = 0;
        const Why why = Judge(mob, players, owner, &spread);
        if (why == kFit) { return 1; }
        const int next = BestFit(mob, players);
        if (next >= 0)
        {
            InterlockedIncrement(&g_stats.ownerChanged);
            Report(kKindOwner, mob, players, body, owner, spread, next);
            if (g_mode) { *(WORD*)body = (WORD)next; }
            return 1;
        }
        InterlockedIncrement(why == kLevel ? &g_stats.cutLevel : &g_stats.cutSpread);
        Report(why == kLevel ? kKindLevel : kKindSpread, mob, players, body, owner, spread, -1);
        return g_mode ? 0 : 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kKindFault);
            e.opcode = kOp8303;
            AcJournal::Push(e);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return 1;
    }
}

// Счётчики (стенд).
extern "C" __declspec(dllexport) void __stdcall N24_GetStats(N24_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Стаб площадки 0x4387D7. Вход по call: [esp] — 0x4387DC, выше 4 аргумента sub_455120; ecx (размер) и edi (тело) живые, ebp — монстр.
    __declspec(naked) void St_Send8303()
    {
        __asm
        {
            pushad
            push    edi                             // тело 8303
            push    ebp                             // монстр
            call    N24_Filter                      // __stdcall, 8 б
            mov     dword ptr [esp + 1Ch], eax      // ответ — в сохранённый eax
            popad
            test    eax, eax
            jz      skip
            jmp     dword ptr [g_sendAddr]          // sub_455120 — стек как при вызове
        skip:
            ret     10h                             // аргументы снимает вызываемая
        }
    }
}

PatchResult N24_LowMobLoot()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_levelGap    = Config::GetInt(kSec, L"LevelGap", 7);
    g_spreadLimit = Config::GetInt(kSec, L"SpreadLimit", 10);
    g_wholeParty  = Config::GetBool(kSec, L"SpreadWholeParty", true);
    g_rangeTiles  = Config::GetInt(kSec, L"SpreadRangeTiles", 80);
    g_intervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 60);
    if (g_levelGap < 1 || g_levelGap > 255) { g_levelGap = 7; }
    if (g_spreadLimit < 1 || g_spreadLimit > 255) { g_spreadLimit = 10; }
    if (g_intervalSec < 0) { g_intervalSec = 0; }
    if (g_rangeTiles < 0 || g_rangeTiles > 4096) { g_rangeTiles = 80; }
    if (!VerifyAllSites(L"N24_LowMobLoot", kSites, ARRAYSIZE(kSites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteCall(kVa, (void*)&St_Send8303, sizeof(kOrig))) { return PatchResult::Failed; }
    Log::Line(L"    N24: 8303 @0x%08X — лута нет при разнице уровней ≥ %d и разбросе отряда ≥ %d (%s); владелец — первый годный по угрозе; "
              L"в разброс — члены отряда ближе %d клеток (0 — все); Mode=%d; журнал ac.other 177–180", kVa, g_levelGap, g_spreadLimit,
              g_wholeParty ? L"весь отряд" : L"нанёсшие урон", g_rangeTiles, g_mode);
    return PatchResult::Applied;
}
