// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P29 — ★ ПОТОЛОК УРОВНЯ ИГРОКА 59 → MaxLevel (по умолчанию 100).
//
//  ЭТО НАША ПРАВКА (решение владельца 2026-09-11: «поднимаемся до 60-го и выше»),
//  а не перенос чужой. Отчёт: Reports/level_cap_100.md,
//  документ: AstoryServer/Docs/GameServer/level-cap-100-p29.md.
//
//  ── ЧТО В ОРИГИНАЛЕ ──
//  Потолок нигде не хранится в данных: в семи функциях GameServer зашита одна и та
//  же константа 0x3B (59) в команде `cmp r32, 0x3B` сразу за чтением уровня
//  (байт CUser+0x192, u8, читается movzx). Таблицы при этом длиннее потолка:
//  ExpTable.txt — 151 строка, ClassStat.txt / Standard.txt — по 100 уровней.
//  Площадки (все 5 байт — cmp + условный переход — сверены с настоящим стоком,
//  ЖИВЫМ GameServer, ЖИВЫМ Indun_GameServer и декомпильным образом: совпали все 4):
//
//   гр. VA          байты            функция                               смысл
//   exp 0x004C7F63  83 FA 3B 7C 05   sub_4C7C70 PartyExpProcess             опыт (отряд/соулмейт): только при ур.<59
//   exp 0x004C8D91  83 FA 3B 7C 05   sub_4C8CB0 SetForwardSoulJarExp        опыт из кувшина души: только при ур.<59
//   exp 0x004CBB61  83 FA 3B 7C 05   Recv_BattleServerFromCharParamExp_1    опыт от NpcServer (моб) + UserLevelUp
//   exp 0x004CC592  83 FA 3B 7C 0E   GetExpUpDownValue                      при ур.>=59 множитель опыта обнуляется
//   sm  0x00495426  83 F8 3B 7C 42   SoulJar_RequestUser_Req                кувшин: партнёр должен быть ур.<59 (иначе код 6)
//   sm  0x0049D077  83 F8 3B 7C 11   RecvChar_SoulMateSkillUse              навык соулмейта 31: при ур.>=59 отказ 29
//   st  0x0052E8DA  83 F8 3B 7F 17   sub_52E8A0 (из UserLevelUp)            +2 очка НАВЫКОВ, пока новый ур.<=59
//
//  ★ ред. 2 (2026-10-21): площадка `st` — это очки НАВЫКОВ (CUser+0x19B, word; тот же счётчик пишут
//    sub_52E900 «2·ур.−8» при сбросе навыков, sub_52E9E0 при изучении — Recv_SkillPoint_SkillActive,
//    уходит в 4036 +11 и в БД UPLevelUp @SkillPoint → Charinfo.SkillPoint). В ред. 1 ошибочно названа
//    «очками характеристик»; ключ ini `StatPoints` оставлен прежним (совместимость живых patches.ini).
//    Проверено на живой БД: JoyLog1.SkillEvent «Skill Point Gain-Level UP» +2 на каждом уровне 60→90.
//
//  Все семь — это одна мысль «игрок на потолке»: опыт не идёт, кувшин и навык 31
//  (оба дают опыт) на потолке бесполезны, очки навыков за уровни выше
//  потолка не положены. Поэтому все они получают ОДНО число — MaxLevel.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Меняем ТОЛЬКО байт imm8 (VA+2) в каждой площадке: 0x3B → MaxLevel. Кодировка
//  команды не меняется (imm8 знаковый, поэтому MaxLevel ≤ 127). Уровень читается
//  movzx, сравнение со знаковым imm8 ≤ 127 даёт тот же результат, что беззнаковое.
//
//  ── ПОЧЕМУ 100 И НЕ БОЛЬШЕ: ГРАНИЦЫ ТАБЛИЦ (проверено по загрузчикам) ──
//   • ExpTable (sub_4AC640): массив [0..N] по 9 б. GetExpUpDownValue и потеря опыта
//     при смерти (sub_4CAC10) читают ExpTable[ур.+1] даже НА потолке ⇒ MaxLevel ≤ N−1.
//   • ClassStat (sub_4ACAD0): 4 класса × (N/4+1) записей по 14 б, индекс = уровень
//     (sub_43C170, вызывается на каждом повышении) ⇒ MaxLevel ≤ N/4.
//     ⚠ Дефект оригинала на будущее: гейт в sub_43C170 — `count < lvl`, т.е. уровень
//     ровно count (=101) проходит и читает запись ЗА концом массива. При MaxLevel ≤ N/4
//     недостижимо.
//   • Standard (sub_4ACD50): массив [0..N] по 6 б ⇒ MaxLevel ≤ N.
//   • ★ ред. 2 — AppleExpLimit (sub_4AF270 → dword_5F5E80) и SoulStoneExpLimit (sub_4AF480 →
//     dword_5F5E7C): массивы [0..N] по 9 б, и ОБА читаются по уровню ИГРОКА (call GetLevel
//     0x5325F0, imul 9): AppleExpLimit[ур.] — Soulmate_GetAppleExp sub_498C60 (+0x2B4/+0x2D9,
//     Hex-Rays тело схлопывает — ред. 1 из-за этого записала «обращений нет»), SoulStoneExpLimit[ур.]
//     — Send_SoulJarProcessBarExp@0x495790 (+0xA4) ⇒ MaxLevel ≤ N (на данных 151 — не связывает).
//     ред. 1 перепутала адреса: dword_5F5E84 — это SoulMateExpTable.txt (sub_4AF060), читается по
//     уровню КУВШИНА (Recv_BattleServerFromCharParamExp, [jar+1]) — в предел не входит.
//  Всё это DLL читает сама из ConfigSet при установке и зажимает MaxLevel сверху;
//  при нечитаемом файле патч НЕ ставится (лучше потолок 59, чем чтение за массивом).
//  На текущих данных: ExpTable 151, ClassStat 400/4 = 100, Standard 100, AppleExpLimit 151,
//  SoulStoneExpLimit 151 ⇒ предел 100.
//
//  ── ★ ред. 2: ВТОРОЙ МЕТОД (2026-10-21) — других зашитых потолков игрока нет ──
//  Межпроцедурный taint-анализ уровня по .text ТРЁХ образов (сток 4e20f0ad, живой GameServer и
//  Indun e7b4ac38; capstone): источники — каждое чтение [reg+0x192] (70 мест) и каждый вызов
//  GetLevel 0x5325F0 (38), протяжка через регистры/слоты [ebp±x]/аргументы; стоки — cmp/test,
//  индексация, imul. 208 стоков, у трёх образов одинаковы; сравнений уровня с константой < 100,
//  кроме семи площадок ниже, НЕТ (остальное: 5/10/20 — нижние границы, ±1/±5/±6/7/10 — разница
//  уровней, табличные мин/макс). Отчёт: Reports/level_caps_2026-10-21/REPORT.md.
//
//  ── ЧТО ОСТАЁТСЯ НЕТРОНУТЫМ (проверено, это НЕ потолок игрока) ──
//   • 0x456989 / 0x459BA3 — уровень ПИТОМЦА (пороги 39/59/79);
//   • 0x478917, 0x479A28, 0x47A4F2, 0x48C35B, 0x48D451 — номер состояния навыка (59/60/61…);
//   • 0x4CFF26 / 0x4CFFAE — номер ячейки инвентаря (59/58) в CharItemMove.
//  NpcServer / Indun_NpcServer / DBManager своего потолка не имеют (квесты — 1..150).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstdio>

namespace
{
    const wchar_t* const kSec = L"P29_LevelCap";   // секция в patches.ini

    constexpr BYTE kStockCap = 0x3B;               // потолок стока (59)
    constexpr int  kImm8Max  = 127;                // предел знакового imm8 в `cmp r32, imm8`

    // Группа площадки — у каждой свой ключ ini (кроме exp: она и есть патч).
    enum class Grp { Exp, Soul, Stat };

    struct CapSite
    {
        DWORD          va;        // адрес команды cmp (imm8 лежит в va+2)
        BYTE           orig[5];   // cmp r32, 0x3B ; jcc rel8 — сверяются целиком
        Grp            grp;       // группа (ключ ini)
        const wchar_t* what;      // что за место — для лога
    };

    const CapSite kSites[] =
    {
        { Srv::Hooks::kLvlCapPartyExp,   { 0x83, 0xFA, 0x3B, 0x7C, 0x05 }, Grp::Exp,
          L"sub_4C7C70 PartyExpProcess — опыт отряда/соулмейта" },
        { Srv::Hooks::kLvlCapSoulJarExp, { 0x83, 0xFA, 0x3B, 0x7C, 0x05 }, Grp::Exp,
          L"sub_4C8CB0 SetForwardSoulJarExp — опыт из кувшина души" },
        { Srv::Hooks::kLvlCapMobExp,     { 0x83, 0xFA, 0x3B, 0x7C, 0x05 }, Grp::Exp,
          L"Recv_BattleServerFromCharParamExp_1 — опыт от NpcServer + UserLevelUp" },
        { Srv::Hooks::kLvlCapExpUpDown,  { 0x83, 0xFA, 0x3B, 0x7C, 0x0E }, Grp::Exp,
          L"GetExpUpDownValue — обнуление опыта на потолке" },
        { Srv::Hooks::kLvlCapSoulJarReq, { 0x83, 0xF8, 0x3B, 0x7C, 0x42 }, Grp::Soul,
          L"SoulJar_RequestUser_Req — уровень партнёра для кувшина (отказ 6)" },
        { Srv::Hooks::kLvlCapSmSkill31,  { 0x83, 0xF8, 0x3B, 0x7C, 0x11 }, Grp::Soul,
          L"RecvChar_SoulMateSkillUse — навык соулмейта 31 (отказ 29)" },
        { Srv::Hooks::kLvlCapStatPoints, { 0x83, 0xF8, 0x3B, 0x7F, 0x17 }, Grp::Stat,
          L"sub_52E8A0 — +2 очка навыков за уровень (CUser+0x19B)" },
    };

    // Первое число файла ConfigSet\<name> — объявленное число строк (формат всех
    // пяти таблиц: "N" в первой строке). -1 — файл не открылся или не число.
    int ReadDeclaredCount(const wchar_t* name)
    {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"%sConfigSet\\%s", Config::BaseDir(), name);
        FILE* f = nullptr;
        if (_wfopen_s(&f, path, L"r") != 0 || !f) { return -1; }
        int n = -1;
        if (fscanf_s(f, "%d", &n) != 1) { n = -1; }
        fclose(f);
        return n;
    }

    // Предел MaxLevel по таблицам (см. шапку). 0 — хотя бы одна таблица нечитаема.
    int TableLimit()
    {
        const int nExp = ReadDeclaredCount(L"ExpTable.txt");
        const int nCls = ReadDeclaredCount(L"ClassStat.txt");
        const int nStd = ReadDeclaredCount(L"Standard.txt");
        // ★ ред. 2: обе таблицы кувшина/яблока читаются по уровню ИГРОКА (см. шапку).
        const int nApl = ReadDeclaredCount(L"AppleExpLimit.txt");
        const int nSst = ReadDeclaredCount(L"SoulStoneExpLimit.txt");
        Log::Line(L"    P29: таблицы ConfigSet: ExpTable=%d ClassStat=%d (на класс %d) Standard=%d "
                  L"AppleExpLimit=%d SoulStoneExpLimit=%d",
                  nExp, nCls, nCls > 0 ? nCls / 4 : -1, nStd, nApl, nSst);
        if (nExp <= 1 || nCls < 4 || nStd <= 0 || nApl <= 0 || nSst <= 0) { return 0; }

        int lim = kImm8Max;
        lim = min(lim, nExp - 1);     // ExpTable[ур.+1] читается и на потолке
        lim = min(lim, nCls / 4);     // ClassStat[класс][ур.]
        lim = min(lim, nStd);         // Standard[ур.]
        lim = min(lim, nApl);         // AppleExpLimit[ур.]  — sub_498C60 (Soulmate_GetAppleExp)
        lim = min(lim, nSst);         // SoulStoneExpLimit[ур.] — Send_SoulJarProcessBarExp
        return lim;
    }

    bool GroupOn(Grp g, bool soul, bool stat)
    {
        switch (g)
        {
            case Grp::Exp:  return true;
            case Grp::Soul: return soul;
            case Grp::Stat: return stat;
        }
        return false;
    }
}

PatchResult P29_LevelCap()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        Log::Line(L"    P29: выключен — потолок уровня 59, как в стоке");
        return PatchResult::Disabled;
    }

    const int  wanted = Config::GetInt (kSec, L"MaxLevel", 100);
    const bool soul   = Config::GetBool(kSec, L"SoulmateGates", true);
    const bool stat   = Config::GetBool(kSec, L"StatPoints", true);

    // ── предел по таблицам: без него поднимать потолок нельзя ──
    const int lim = TableLimit();
    if (lim <= 0)
    {
        Log::Line(L"    P29: ! таблица в ConfigSet не прочитана — патч НЕ ставится "
                  L"(поднять потолок, не зная длины таблиц, значит рискнуть чтением за массивом)");
        return PatchResult::Failed;
    }

    int cap = wanted;
    if (cap < 2)   { Log::Line(L"    P29: MaxLevel=%d меньше 2 — взято 2", cap); cap = 2; }
    if (cap > lim) { Log::Line(L"    P29: ! MaxLevel=%d больше предела таблиц %d — взято %d", cap, lim, lim); cap = lim; }

    // ── сверка ВСЕХ выбранных площадок до первой записи (всё или ничего) ──
    Site sites[ARRAYSIZE(kSites)];
    const CapSite* chosen[ARRAYSIZE(kSites)];
    int n = 0;
    for (const CapSite& s : kSites)
    {
        if (!GroupOn(s.grp, soul, stat)) { continue; }
        sites[n]  = { s.va, s.orig, sizeof(s.orig) };
        chosen[n] = &s;
        ++n;
    }
    if (!VerifyAllSites(L"P29", sites, n)) { return PatchResult::Mismatch; }

    // ── запись imm8; при сбое — откат уже записанных, чтобы не остаться «наполовину» ──
    for (int i = 0; i < n; ++i)
    {
        const DWORD immVa = chosen[i]->va + 2;
        if (!Hook::WriteByteChecked(immVa, kStockCap, (BYTE)cap))
        {
            for (int j = 0; j < i; ++j)
            {
                Hook::WriteByteChecked(chosen[j]->va + 2, (BYTE)cap, kStockCap);
            }
            Log::Line(L"    P29: ! запись @0x%08X не удалась — откат %d площадок, потолок 59", immVa, i);
            return PatchResult::Failed;
        }
        Log::Line(L"    P29: @0x%08X cmp imm 0x3B -> 0x%02X  (%s)", chosen[i]->va, cap, chosen[i]->what);
    }

    Log::Line(L"    P29: потолок уровня %d (сток 59); площадок %d; соулмейт-гейты=%d, очки навыков (StatPoints)=%d",
              cap, n, soul ? 1 : 0, stat ? 1 : 0);
    return PatchResult::Applied;
}
