// Copyright (c) 2026 @sitxovski (Discord)
// NpcApi.h — адреса и константы ОБРАЗА NpcServer.exe.
//
// Полный аналог `AsdaPatch/src/SrvApi.h`, но для боевого сервера. Держим отдельно: адреса
// двух образов не имеют между собой ничего общего, и перепутать их — верный способ записать
// байты не туда.
//
// ⚠ Все значения выверены на образе NpcServer.exe md5 d292e4ec4edfd5040d8fb39382664eab —
//   он побайтово совпадает с живым сервером (сверено 24.08.2026).
#pragma once
#include <windows.h>

namespace Npc
{
    constexpr DWORD kImageBase = 0x00400000;
    constexpr DWORD kFileSize  = 516096;      // размер СТОКА (без инъекции импорта)
    // ★ Размер после инъекции AddonNPC.dll НЕ меняется — она укладывается в нулевые хвосты
    //   .rdata и .data, не добавляя ни байта. Поэтому одно число годится для обоих случаев.

    namespace Hooks
    {
        // N01 — античит скорости атаки (см. n01_attack_timer32.cpp)
        constexpr DWORD kAtkTimerMain  = 0x0045F5A4;   // Process_AttackedToMonster
        constexpr DWORD kAtkTimerTwin  = 0x00460151;   // функция-двойник
        constexpr DWORD kAtkTimerTrunc = 0x00460169;   // повторное усечение у двойника

        // N02 — очистка списка угрозы при возрождении (см. n02_hate_clear_damage.cpp)
        constexpr DWORD kHateClearLoop = 0x0043E42F;   // тело цикла в sub_43E300

        // N03 — поиск владельца добычи (см. n03_hate_winner_entry0.cpp)
        constexpr DWORD kHateWinnerInit = 0x00437A6C;  // mov esi, [ebp+7A84h] в sub_437A30

        // N04 — мёртвый монстр не крутит боевой ИИ (см. n04_dead_mob_no_battle.cpp)
        constexpr DWORD kOnBattleCall = 0x004486E3;    // call sub_447B30 внутри ProcessState
        constexpr DWORD kOnBattle     = 0x00447B30;    // сам боевой ИИ (цель хвостового перехода)

        // N05 — здоровье монстра в пакете 8202 (см. n05_hp8202_subtract_accum.cpp)
        constexpr DWORD kHp8202Load   = 0x0045FEF2;    // mov ecx, [ebx+7885h]

        // N06 — поиск по списку угрозы читает за границей (см. n06_hate_search_oob.cpp).
        //   Одна и та же 15-байтовая последовательность в sub_43D2C0 встречается трижды.
        constexpr DWORD kHateSearchOob1 = 0x0043D539;  // поиск наименьшего (вытеснение)
        constexpr DWORD kHateSearchOob2 = 0x0043D5ED;  // поиск наибольшего
        constexpr DWORD kHateSearchOob3 = 0x0043D6CC;  // поиск наибольшего

        // N07 — накопитель урона больше здоровья (см. n07_accum_overkill.cpp)
        constexpr DWORD kAccumOverkill = 0x004427E7;   // add ecx, eax в DamageAndHateCheck

        // N08 — здоровье монстра в пакете 8005 (см. n08_hp8005_subtract_accum.cpp)
        constexpr DWORD kHp8005Load = 0x00440F93;      // mov eax, [esi+7885h] в sub_440D20

        // N11 (P39) — скрытый оператор невидим для монстров (см. n11_gm_hide_npc.cpp)
        constexpr DWORD kGmHideOnBattle     = 0x00447BA7;  // cmp [esi+7654h],0 в OnBattle (цель)
        constexpr DWORD kGmHideUserSearch   = 0x0041AA44;  // cmp [edi+7654h],0 в OnUserSearch
        constexpr DWORD kGmHideSkillVictims = 0x0040C38C;  // cmp [edi+7654h],0 в sub_40C200 (жертвы навыка)
        constexpr DWORD kGmHideSkillTarget  = 0x0040F41E;  // cmp [edi+7654h],0 в sub_40EE50 (цель навыка)
        constexpr DWORD kGmHideAddState     = 0x0045A11F;  // call sub_42CC20 в Process_PlayerAddState (8115)
        constexpr DWORD kGmHideSubState     = 0x0045A08E;  // call sub_42CB70 в Process_PlayerSubState (8116)
        constexpr DWORD kGmHideRespawn      = 0x00458D18;  // mov [esi+7654h],1 в Process_PlayerRespawn (4031)
        constexpr DWORD kPlayerAddStateFn   = 0x0042CC20;  // AddState (edi = биты, esi = запись)
        constexpr DWORD kPlayerSubStateFn   = 0x0042CB70;  // SubState (eax = биты, esi = запись)

        // N12 (P39-доводка) — угроза к скрытому не возникает вновь (см. n12_gm_hide_hate.cpp)
        constexpr DWORD kGmHideHateAdd          = 0x0043D2C0;  // начало sub_43D2C0 (OnHated), 9 б
        constexpr DWORD kGmHideSingleVictim     = 0x0040C649;  // movsx edx,[esi+8F7Ch] в sub_40C200 (одна цель)
        constexpr DWORD kGmHideSingleVictimSkip = 0x0040C687;  // за добавлением жертвы

        // N22 (31.10.2026) — ячейки NPC сверх 10, таблица расширения (см. n22_quest_cells_ext.cpp)
        constexpr DWORD kQuestTakeLimit = 0x00420CB9;  // cmp word [esp+2Ah], 9 в Process_Quest (sub_420C10)
        constexpr DWORD kQuestTakeCell  = 0x00420D3A;  // movsx/imul/lea адреса ячейки «ПРИНИМАЕТ», 15 б
        constexpr DWORD kQuestGiveLimit = 0x004210AD;  // cmp word [esp+26h], 9 в Start_Quest (sub_421020)
        constexpr DWORD kQuestGiveCell  = 0x0042112E;  // movsx/imul/lea адреса ячейки «ВЫДАЁТ», 15 б

        // N23 (слот P104, 04.11.2026) — скрытый навыком 112/186 не цель для необнаружившего монстра (см. n23_skill_hide_aggro.cpp)
        constexpr DWORD kHideBattleGate     = 0x00447B92;  // cmp byte [esi+7858h],1 в OnBattle (sub_447B30) — проверка цели
        constexpr DWORD kHideAcquireMove2   = 0x0043F117;  // mov [ebx+7A58h],dx в sub_43E580 после Hide Check
        constexpr DWORD kHideAcquireMove1   = 0x0043F4AB;  // mov [edi+7A58h],bx в sub_43F330 после Hide Check
        constexpr DWORD kHideSkillTarget    = 0x0040FFE4;  // mov [esi+91C5h],ax в sub_40EE50 — запись цели навыка монстра
        constexpr DWORD kHideQuickHater     = 0x0042895C;  // push 0 ×3 перед строкой «Exception» в sub_4287F0 (QuickHide)
        constexpr DWORD kHideQuickHaterCont = 0x00428895;  // продолжение цикла секторов sub_4287F0
        constexpr DWORD kHideSkillCondTarget = 0x0043668B; // mov [ebx+7A58h],di в sub_4364E0 (цикл условий навыков)
        constexpr DWORD kHideSkillCondSkip   = 0x004366B4; // выход стока «кандидата нет» (mov edi,[esp+18h])

        // Ориентиры (не патчатся, нужны для сверки образа)
        constexpr DWORD kProcessState = 0x00448350;    // ProcessState
    }
}
