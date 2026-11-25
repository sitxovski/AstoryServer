// Copyright (c) 2026 @sitxovski (Discord)
// n13_ac_journal_npc.cpp — ★ ЖУРНАЛ АНТИЧИТА В БАЗЕ, сторона NpcServer (P53, волна acdb, 2026-10-12).
//
// ЧТО ПИШЕМ
//   Античит скорости атаки NpcServer (CAi::Process_AttackedToMonster и функция-двойник, см. N01): каждое
//   нарушение («удар раньше интервала») сервер пишет строкой «SpeedHack Check....!» в Error_Log, а при
//   > 30 нарушениях шлёт GameServer 8905 (кик тип 6) и пишет «SpeedHack Banish....!». Перехватываем ровно
//   эти четыре вызова писателя sub_408DC0 (подмена цели `call rel32` → стаб → тот же sub_408DC0 с тем же
//   ecx), файл-лог NpcServer пишется как раньше. Строки — в ac.move_combat (виды 4 и 5).
//
// ПЛОЩАДКИ (живые NpcServer c02486d6… и Indun_NpcServer 0de2c559…, байты одинаковы; сверено дизасмом):
//     0x0045F600  E8 BB97FAFF  call sub_408DC0  ← push 0x4776A8 «SpeedHack Check» (основная функция)
//     0x0045F674  E8 4797FAFF  call sub_408DC0  ← push 0x477720 «SpeedHack Banish»
//     0x004601B4  E8 078CFAFF  call sub_408DC0  ← push 0x478488 «SpeedHack Check» (двойник)
//     0x00460228  E8 938BFAFF  call sub_408DC0  ← push 0x478500 «SpeedHack Banish» (двойник)
//   Аргументы (стек при вызове): [1] формат, [2] карта, [3] userNum (WORD игрока +0x7864 — номер слота
//   GameServer, его же несёт 8905), [4] имя (+0x7714), [5] текущий такт, [6] счётчик нарушений (+0xFE60);
//   у Check ещё [7] такт прошлого удара (+0xFE90), [8] требуемый интервал (+0xFE94), [9] фактический
//   интервал + допуск (сток 100 мс; ★ N16 15.10.2026 — действующий допуск max(100, Rate % dur), см. N01).
//   Площадки N01 (0x45F5A4 / 0x460151) — другие байты, не пересекаются.
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
        { 0x0045F600, 0x004776A8, 4 },   // Check
        { 0x0045F674, 0x00477720, 5 },   // Banish
        { 0x004601B4, 0x00478488, 4 },   // Check (двойник)
        { 0x00460228, 0x00478500, 5 },   // Banish (двойник)
    };
    const DWORD kWriter = 0x00408DC0;    // писатель Error_Log NpcServer (thiscall-подобный, cdecl-аргументы)
    DWORD g_pWriter = kWriter;
}

// st: [0] адрес возврата, [1] формат, [2…] аргументы строки.
extern "C" void __stdcall N13_OnSite(int kind, const DWORD* st)
{
    __try
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, (BYTE)kind);
        e.v[0]    = (short)st[2];                 // карта
        e.userNum = (short)st[3];                 // слот игрока на GameServer
        AcJournal::CopyName(e, (const void*)st[4]);
        e.w[1]    = (DWORD)st[5];                 // такт удара
        e.v[2]    = (signed char)st[6];           // счётчик нарушений после ++
        if (kind == 4)
        {
            e.w[0] = (DWORD)st[7];                // такт прошлого удара
            e.v[1] = (int)((DWORD)st[5] - (DWORD)st[7]);
            e.v[3] = (int)st[8];                  // требуемый интервал, мс
            e.v[4] = (int)st[9];                  // фактический интервал + допуск (100 мс или N16: max(100, Rate % dur))
        }
        else
        {
            e.opcode = 8905;                      // NpcServer → GameServer: отключить за скорость атаки
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
            call  N13_OnSite                       // __stdcall, 8 б
            popad
            add   esp, 4
            jmp   dword ptr [g_pWriter]
        }
    }
    __declspec(naked) void St_Check()  { __asm { push 4 } __asm { jmp WriterTail } }
    __declspec(naked) void St_Banish() { __asm { push 5 } __asm { jmp WriterTail } }
}

PatchResult N13_AcJournal()
{
    const int r = AcJournal::Start(L"AddonNPC");
    if (r == 1) { return PatchResult::Disabled; }
    if (r != 0) { Log::Line(L"    P53: не удалось создать очередь/поток журнала"); return PatchResult::Failed; }
    if (!Config::GetBool(L"P53_AcJournal", L"StockSites", true))
    {
        Log::Line(L"    P53: StockSites=0 — проверки скорости атаки в журнал не зеркалируются");
        return PatchResult::Applied;
    }
    BYTE orig[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        orig[i][0] = 0xE8;
        const int rel = (int)(kWriter - (kSites[i].va + 5));
        memcpy(&orig[i][1], &rel, 4);
        sites[i].va = kSites[i].va; sites[i].orig = orig[i]; sites[i].len = 5;
        // push строки формата: 68 imm32 за 10 б до call (`push fmt` / `mov ecx, imm32`)
        const BYTE* p = (const BYTE*)(kSites[i].va - 10);
        if (!(p[0] == 0x68 && *(const DWORD*)(p + 1) == kSites[i].fmt))
        {
            Log::Line(L"    P53: ! у площадки 0x%08X нет push строки формата 0x%08X — площадки не ставятся", kSites[i].va, kSites[i].fmt);
            return PatchResult::Mismatch;
        }
    }
    if (!VerifyAllSites(L"P53", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!Hook::WriteCall(kSites[i].va, kSites[i].kind == 4 ? (void*)&St_Check : (void*)&St_Banish, 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    P53: площадок скорости атаки поставлено %d (Check/Banish, основная функция и двойник)", (int)ARRAYSIZE(kSites));
    return PatchResult::Applied;
}
