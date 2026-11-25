// Copyright (c) 2026 @sitxovski (Discord)
// n14_combat_limits_npc.cpp — ★ СЕРВЕРНЫЕ ЛИМИТЫ БОЯ, сторона NpcServer (P56/N14, мера 9 плана античита,
// волна В5, 2026-10-12). Пара к AsdaPatch P56 (GameServer).
//
// ЧТО УЖЕ ЕСТЬ В СТОКЕ (ничего не меняем)
//   • Частота ударов по серверному GetTickCount: `Process_AttackedToMonster` (sub_45F3A0, NS:63108) и
//     двойник PvP (sub_45FF80, NS:63545) — интервал WORD игрок+65172 из sub_401900 (тип оружия/темп) с
//     баффами, допуск +100 мс; нарушение → счётчик +65120, >30 → 8905 (кик тип 6). 16-битное сравнение
//     чинит N01, строки «SpeedHack Check/Banish» зеркалит в журнал N13 (виды 4/5).
//   • Дальность по серверным позициям: `sub_42C4F0` — PvE: игрок в коробке моба ± (3 + байт дальности
//     моба +30956) клеток; PvP: ± 4 клетки. Нарушение → строка в Error_Log через sub_408D40 и ШТАТНЫЙ
//     отказ: PvE → 8204 код 1 (GameServer → 4027 код 1), PvP → 8223/8225 код 1.
//
// ЧТО ДЕЛАЕТ N14
//   Зеркалит эти два штатных отказа по дальности в журнал античита (ac.move_combat, виды 12/13) — ровно
//   так же, как N13 зеркалит скорость атаки: подмена цели `call sub_408D40` → стаб → тот же sub_408D40 с
//   теми же аргументами (ecx сохраняется). Файл-лог NpcServer пишется как раньше. Пороги, допуски и
//   отказы стока не трогаются — это «только журнал» по построению.
//
// ПЛОЩАДКИ (байты одинаковы в стоке 16c7a0af, живом c02486d6 и Indun 0de2c559 — verify_p56.py)
//     0x0045F581  E8 BA97FAFF  call sub_408D40  ← push 0x477638 за 5 б (формат PvE «%s … px %d, pz %d, mx %d, mz %d (%d)»)
//     0x00460131  E8 0A8CFAFF  call sub_408D40  ← push 0x478428 за 5 б (формат PvP «… tx %d, tz %d (%d)»)
//   Аргументы (стек при вызове): [1] формат, [2] имя игрока (запись игрока + 0x7714), [3] PvE: индекс
//   моба / PvP: имя цели (запись цели + 0x7714), [4] px, [5] pz, [6] mx|tx, [7] mz|tz, [8] такт удара.
//   userNum игрока = WORD запись+0x7864 (как у N13; его же несёт 8905). Площадки N01/N13 — другие VA.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"
#include "AcJournal.h"
#include <string.h>

namespace
{
    struct SiteDef { DWORD va; DWORD fmt; int kind; };
    const SiteDef kSites[] =
    {
        { 0x0045F581, 0x00477638, 12 },   // PvE: удар по монстру вне дальности
        { 0x00460131, 0x00478428, 13 },   // PvP: удар по игроку вне дальности
    };
    const DWORD kWriter = 0x00408D40;     // писатель Error_Log NpcServer (как sub_408DC0 у N13, cdecl-аргументы)
    DWORD g_pWriter = kWriter;
    constexpr int kOffName    = 0x7714;   // запись игрока: имя
    constexpr int kOffUserNum = 0x7864;   // запись игрока: WORD userNum (слот GameServer)
    volatile LONG g_hits = 0;

    int Abs(int v) { return v < 0 ? -v : v; }
}

// st: [0] адрес возврата, [1] формат, [2…] аргументы строки.
extern "C" void __stdcall N14_OnSite(int kind, const DWORD* st)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, (BYTE)kind);
        const BYTE* rec = st[2] ? (const BYTE*)st[2] - kOffName : nullptr;
        if (rec) { e.userNum = *(const short*)(rec + kOffUserNum); }
        AcJournal::CopyName(e, (const void*)st[2]);
        const int px = (int)st[4], pz = (int)st[5], mx = (int)st[6], mz = (int)st[7];
        const int dx = Abs(px - mx), dz = Abs(pz - mz);
        e.w[1]   = (DWORD)st[8];                      // такт удара (NpcServer)
        e.v[1]   = dx > dz ? dx : dz;                 // interval_ms ← расстояние по клеткам (max |dx|,|dz|)
        e.v[4]   = px; e.v[2] = pz;                   // duration ← px, violation_count ← pz (позиция игрока)
        if (kind == 12)
        {
            e.opcode = 8201;
            e.v[3]   = (int)st[3];                    // p_duration ← индекс моба (PvE)
        }
        else
        {
            e.opcode = 8222;
            const BYTE* trec = st[3] ? (const BYTE*)st[3] - kOffName : nullptr;   // [3] — имя цели → её запись
            e.v[3]   = trec ? *(const short*)(trec + kOffUserNum) : AcJournal::kNone;   // p_duration ← userNum цели
        }
        AcJournal::Push(e);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

namespace
{
    // На входе: [esp] вид, [esp+4] адрес возврата, [esp+8…] аргументы; ecx — объект писателя (сохраняется).
    __declspec(naked) void WriterTail()
    {
        __asm
        {
            pushad
            lea   eax, [esp+36]
            push  eax
            push  dword ptr [esp+36]               // вид (после push: +32+4)
            call  N14_OnSite                       // __stdcall, 8 б
            popad
            add   esp, 4                           // снять вид
            jmp   dword ptr [g_pWriter]            // дальше — стоковый писатель с теми же аргументами
        }
    }
    __declspec(naked) void St_Pve() { __asm { push 12 } __asm { jmp WriterTail } }
    __declspec(naked) void St_Pvp() { __asm { push 13 } __asm { jmp WriterTail } }
}

PatchResult N14_CombatLimits()
{
    if (!Config::GetBool(L"N14_CombatLimits", L"Enabled", true)) { return PatchResult::Disabled; }
    if (!Config::GetBool(L"P53_AcJournal", L"Enabled", true))
    {
        Log::Line(L"    N14: журнал P53 выключен — площадок дальности не ставим (писать некуда)");
        return PatchResult::Disabled;
    }
    BYTE orig[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        orig[i][0] = 0xE8;
        const int rel = (int)(kWriter - (kSites[i].va + 5));
        memcpy(orig[i] + 1, &rel, 4);
        sites[i].va = kSites[i].va; sites[i].orig = orig[i]; sites[i].len = 5;
        // Страховка кадра: за 5 б до call — push строки формата именно этой площадки.
        const BYTE* p = (const BYTE*)(kSites[i].va - 5);
        if (!(p[0] == 0x68 && *(const DWORD*)(p + 1) == kSites[i].fmt))
        {
            Log::Line(L"    N14: ! у площадки 0x%08X нет push строки формата 0x%08X — площадки не ставятся", kSites[i].va, kSites[i].fmt);
            return PatchResult::Mismatch;
        }
    }
    if (!VerifyAllSites(L"N14", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!Hook::WriteCall(kSites[i].va, kSites[i].kind == 12 ? (void*)&St_Pve : (void*)&St_Pvp, 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    N14: площадок дальности поставлено %d (PvE 8204 код 1, PvP) — только журнал, пороги стока не тронуты", (int)ARRAYSIZE(kSites));
    return PatchResult::Applied;
}
