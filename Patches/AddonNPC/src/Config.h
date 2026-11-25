// Copyright (c) 2026 @sitxovski (Discord)
// Config.h — <GameServer>\ConfigSet\patches.ini (штатные Win-ini API).
//
// ★ БЕРЕЖНОЕ СЛИЯНИЕ. Файл НИКОГДА не перезаписывается целиком, если он уже есть:
//   • существующие значения сохраняются как есть — правки администратора не теряются;
//   • отсутствующая СЕКЦИЯ дописывается в конец файла вместе с комментариями;
//   • отсутствующий КЛЮЧ вставляется в свою секцию через WritePrivateProfileString;
//     пользовательские значения остаются нетронутыми.
//   Всё добавленное перечисляется в PatchLog.
//
// Indun_GameServer отложен по решению юзера (2026-08-04) — работаем только с
// основным GameServer. Раскладка ini от процесса не зависит: у каждого процесса
// свой каталог, значит и свой patches.ini появится автоматически.
#pragma once
#include <windows.h>

namespace Config
{
    // Текущая версия формата. Повышать при добавлении ключей.
    //   1 — исходный набор (P01..P13)
    //   2 — добавлена секция [P14_ChatMessageLength]
    //   3 — добавлена секция [P17_SqlCodePage] (кодовая страница SQL-запросов);
    //       с этой версии DLL живёт не только в GameServer
    //   4 — добавлена секция [P53_AcJournal] (журнал античита в БД, волна acdb, 12.10.2026).
    //   5 — добавлена секция [N14_CombatLimits] (штатные отказы по дальности → журнал; пара к P56,
    //       волна В5 «серверные лимиты боя», 12.10.2026). Поднято и в шаблоне Config.cpp (kGeneral).
    //       ⚠ Откат: прежняя DLL (Version 4) сама понизит Version до 4; секция N14 будет проигнорирована.
    //   6 — добавлена секция [N15_SkillArea] (центр/радиус площадного навыка 8205/8940 → журнал виды 21/22;
    //       свой допуск CenterSlackCells/TargetSlackCells, Mode; остаток меры 9, волна В5b, 12.10.2026).
    //       ⚠ Откат: прежняя DLL (Version 5) сама понизит Version до 5; секция N15 будет проигнорирована.
    //   7 — ★ N16 (15.10.2026): ключ [N01_AttackTimer32] AttackToleranceRate (допуск проверки скорости атаки, %
    //       серверной длительности удара; 15 по решению владельца; 0 = сток 100 мс). Секция не новая — ключ
    //       дописывается в существующую [N01_AttackTimer32] при слиянии.
    //       ⚠ Откат: прежняя DLL (Version 6) сама понизит Version до 6; ключ будет проигнорирован (допуск 100 мс).
    //   8 — ★ N17 (15.10.2026): секция [N17_MobActionTimer] (ворота ИИ монстра «ждать конца атаки» — беззнаковое
    //       сравнение такта; [ОРИГИНАЛ] дефект стока при аптайме хоста > 24,8 сут).
    //       ⚠ Откат: прежняя DLL (Version 7) сама понизит Version до 7; секция N17 будет проигнорирована.
    //   9 — ★ N18 (15.10.2026): секция [N18_TickSigned] (Enabled + FixSoulmateSkill/FixItemEvent/FixAttackWait) — знаковые
    //       сравнения такта: навыки соулмейта, событие «1000 предметов», ATTACK_WAIT; [ОРИГИНАЛ] дефект стока.
    //       ⚠ Откат: прежняя DLL (Version 8) сама понизит Version до 8; секция N18 будет проигнорирована.
    //  10 — ★ N19 (25.10.2026, слот P86): секция [N19_RestartAttackClock].
    //  11 — ★ N10 ред. 2 + N20 (26.10.2026, слот P90, волна exprate): ключ [N10_NormalAttackHateDamage] CritHits и секция
    //       [N20_PartyShareClamp] (Enabled, ClampNegative).
    //       ⚠ Откат: прежняя DLL (Version 10) сама понизит Version до 10; ключ CritHits и секция N20 будут проигнорированы.
    //  12 — ★ N21 (26.10.2026, слот P93, волна invismobs): секция [N21_RespawnFreeTile] (Enabled, Radius).
    //       ⚠ Откат: прежняя DLL (Version 11) сама понизит Version до 11; секция N21 будет проигнорирована.
    //  13 — ★ N22 (31.10.2026): секция [N22_QuestCellsExt].
    //  14 — ★ N23 (04.11.2026, слот P104, bug-hide-skill): секция [N23_SkillHideAggro] (Enabled, DropUndetected, SkillTarget,
    //       QuickHideHate, LogEvents).
    //       ⚠ Откат: прежняя DLL (Version 13) сама понизит Version до 13; секция N23 будет проигнорирована.
    //  15 — ★ N24 (06.11.2026, сессия pet-hatch-summon): секция [N24_LowMobLoot] (Enabled, Mode, LevelGap, SpreadLimit, SpreadWholeParty,
    //       JournalIntervalSec). ⚠ Откат: прежняя DLL (Version 14) сама понизит Version до 14; секция N24 будет проигнорирована.
    //  16 — ★ N24 (09.11.2026): ключ [N24_LowMobLoot] SpreadRangeTiles=80 — разброс отряда только по членам ближе 80 клеток.
    //       ⚠ Откат: прежняя DLL (Version 15) сама понизит Version до 15; ключ SpreadRangeTiles будет проигнорирован.
    constexpr int kVersion = 16;   // ★ 09.11.2026: + N24 SpreadRangeTiles (06.11.2026, 15: + [N24_LowMobLoot])

    // baseDir — папка NpcServer.exe (с завершающим '\'). Возвращает false, если ini
    // не удалось ни прочитать, ни создать (тогда работаем на умолчаниях).
    bool Init(const wchar_t* baseDir);

    const wchar_t* Path();
    const wchar_t* BaseDir();   // папка NpcServer.exe (с завершающим '\')
    const wchar_t* BaseDir();   // папка NpcServer.exe (с завершающим '\')
    bool WasCreated();          // файл создан этим запуском

    int  GetInt (const wchar_t* section, const wchar_t* key, int def);
    bool GetBool(const wchar_t* section, const wchar_t* key, bool def);
    void GetStr (const wchar_t* section, const wchar_t* key, const wchar_t* def,
                 wchar_t* out, int cch);

    // Досоздание недостающих секций/ключей. Вызывается ПОСЛЕ Log::Init,
    // чтобы всё добавленное попало в лог.
    void MergeMissing();
}
