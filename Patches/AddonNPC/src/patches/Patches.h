// Copyright (c) 2026 @sitxovski (Discord)
// Patches.h — реестр патчей AddonNPC. Каждый патч живёт в своём .cpp и регистрируется здесь.
//
// Полный близнец `AsdaPatch/src/patches/Patches.h`: та же форма записи, тот же результат.
// Отличие одно — здесь патчи для NpcServer.exe, а не для GameServer.exe.
#pragma once
#include <windows.h>

// Результат установки одного патча.
enum class PatchResult
{
    Applied,        // поставлен
    Disabled,       // выключен в ini
    Mismatch,       // оригинальные байты не совпали — НЕ поставлен
    Failed          // ошибка записи/доступа — НЕ поставлен
};

struct PatchEntry
{
    const wchar_t* section;     // секция в patches.ini
    const wchar_t* title;       // краткое описание для лога
    PatchResult  (*apply)();    // сам патч: читает ini, сверяет байты, пишет
    // Для каких образов патч предназначен: имена exe через ';', в нижнем регистре.
    // nullptr = только NpcServer.exe.
    const wchar_t* hosts;
};

extern const PatchEntry* g_patches;
extern const int         g_patchCount;

// ── реализации патчей ───────────────────────────────────────────────────────
PatchResult N01_AttackTimer32();
PatchResult N02_HateClearDamage();
PatchResult N03_HateWinnerEntry0();
PatchResult N04_DeadMobNoBattle();
PatchResult N05_Hp8202SubtractAccum();
PatchResult N06_HateSearchOob();
PatchResult N07_AccumOverkill();
PatchResult N08_Hp8005SubtractAccum();
PatchResult N09_ExpProbe();          // ДИАГНОСТИКА опыта (по умолчанию выключена)
PatchResult N10_NormalAttackHateDamage();
PatchResult N11_GmHideNpc();          // P39: скрытый оператор невидим для монстров
PatchResult N13_AcJournal();          // ★ acdb (P53): журнал античита в БД — скорость атаки (SpeedHack Check/Banish)
PatchResult N12_GmHideHate();         // P39-доводка: угроза к скрытому не возникает вновь, одиночный навык мимо
PatchResult N14_CombatLimits();       // ★ В5/P56 (мера 9): штатные отказы по дальности (PvE 8204 код 1, PvP) → журнал ac.move_combat 12/13
PatchResult N15_SkillArea();          // ★ В5b (остаток меры 9): центр площадного навыка против кастера и цель против центра (8205/8940) → журнал 21/22; свой допуск + Mode=1 штатный отказ
PatchResult N17_MobActionTimer();     // ★ N17 [ОРИГИНАЛ]: ворота «доиграла ли атака» монстра — беззнаково (аптайм хоста > 24,8 сут: монстры не ходят/не дерутся)
PatchResult N18_TickSigned();         // ★ N18 [ОРИГИНАЛ]: знаковые сравнения такта — соулмейт 2 с, событие «1000 предметов», ATTACK_WAIT (аптайм > 24,8 сут / переход 2^32)
PatchResult N19_RestartAttackClock(); // ★ N19 (слот P86, 25.10.2026) [ОРИГИНАЛ]: начало серии 4026/4201 не обнуляет часы атаки — «атака → ход → клик» не бьёт быстрее скорости атаки
PatchResult N20_PartyShareClamp();    // ★ N20 (слот P90, 26.10.2026) [ИСПРАВЛЕНИЕ]: доля урона в опыте ОТРЯДА зажата максимумом здоровья, как у одиночки (журнал ac.other 115)
PatchResult N21_RespawnFreeTile();    // ★ N21 (слот P93, 26.10.2026) [ИСПРАВЛЕНИЕ]: появившийся монстр не встаёт в клетку живого монстра (свободная проходимая в радиусе)
PatchResult N22_QuestCellsExt();      // ★ N22 (31.10.2026, bug-quest-follow) [ИСПРАВЛЕНИЕ]: ячейки «ВЫДАЁТ»/«ПРИНИМАЕТ» сверх 10 у любого NPC — Quest\QuestNpcTableExt.Bin
PatchResult N24_LowMobLoot();         // ★ N24 (06.11.2026) [ИСПРАВЛЕНИЕ]: нет лута с мобов намного ниже игрока и в отряде с разбросом уровней
// Счётчики N24 (экспорт N24_GetStats).
struct N24_Stats
{
    LONG seen;          // вызовов площадки (пакетов 8303)
    LONG cutLevel;      // лут снят: разница уровней
    LONG cutSpread;     // лут снят: разброс отряда
    LONG ownerChanged;  // сменён владелец
    LONG faults;        // исключения (решение стока)
    LONG journaled;     // строк журнала
    LONG suppressed;    // подавлено ограничителем
};
extern "C" int __stdcall N24_Filter(BYTE* mob, BYTE* body);                       // C-часть стаба
extern "C" __declspec(dllexport) void __stdcall N24_GetStats(N24_Stats* out);     // счётчики
PatchResult N23_SkillHideAggro();     // ★ N23 (слот P104, 04.11.2026, bug-hide-skill) [ИСПРАВЛЕНИЕ]: скрытый навыком 112/186 не цель монстра, не обнаружившего его Hide Check
