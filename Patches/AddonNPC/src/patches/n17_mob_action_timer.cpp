// Copyright (c) 2026 @sitxovski (Discord)
// n17_mob_action_timer.cpp — МОНСТРЫ «ЗАМЕРЗАЮТ» ПОСРЕДИ ХОДА ПРИ АПТАЙМЕ ХОСТА > 24,8 СУТ. [ОРИГИНАЛ — дефект стока]
//
// СИМПТОМ (сессия владельца 15.10.2026, карта rein, отчёт Reports/anticheat/wave_N17_mob_stale_move.md)
//   При входе на карту 207 монстров из 214 приходят в 4013 «идёт из клетки A в клетку B», и за 3,5 минуты по ним
//   нет ни одного 4015 (в сентябрьских сессиях — ~30 пакетов 4015 в секунду). Клиент (как и оригинал) доводит
//   монстра до B, а NpcServer держит его в A: удары по «призраку» получают отказ «вне дальности» (N14, 7249–7254),
//   монстр в бою не отвечает и не преследует. После сброса боя — «стоп» (4015 вид 1) и через ~5 с новый ход
//   (4015 вид 2) — и снова тишина.
//
// МЕХАНИЗМ
//   Поле монстра +0x7A70 (31344) — такт начала его последней атаки, +0x7A74 (31348, i16) — длительность атаки.
//   Конструктор монстра (`sub_44BF30`, 0x44BF80/0x44C122) обнуляет такт; ставит его только рассылка атаки
//   (`AlarmMonsterActionToGameServer` sub_460990, ветка ATTACK) и пути навыков (0x42E4CC, 0x43700D, 0x43CD94).
//   Восемь «ворот» ИИ ждут, пока доиграет атака:
//
//       movsx R1, word [M+7A74h]        ; длительность
//       mov   R2, <такт кадра>          ; GetTickCount из кадра ИИ (sub_462D90 → Frame_Monster)
//       sub   R2, [M+7A70h]             ; прошло с начала атаки
//       cmp   R2, R1
//       jl    <выход из функции>        ; ★ ЗНАКОВОЕ сравнение
//
//   GetTickCount — аптайм ХОСТА. При аптайме ≥ 2^31 мс (24,86 сут) такт как знаковое число отрицателен, и у
//   монстра, который ещё ни разу не атаковал (такт атаки 0), «прошло» = такт − 0 < 0 ≤ длительности → ворота
//   закрыты НАВСЕГДА (до перехода такта через 2^32, ещё ~24,8 сут). Под воротами — ход (MOVE), погоня (CHASE/
//   AROUNDMOVE), боевой ход, ход-и-действие, страх, ход навыка, боевой ИИ (OnBattle) и особые монстры в покое.
//   ProcessAction_Idle этих ворот (у обычных монстров) не имеет — монстр делает ОДИН Move_Tile (8005 вид 2 →
//   4015/кэш GameServer «A→B»), переходит в MOVE и больше не шагает: ни 8004 (клетка), ни 8005 (действие).
//   GameServer честно отдаёт новым игрокам последнее, что сказал NpcServer, — «идёт A→B».
//   Живьём: такт NpcServer 15.10 09:28:17 UTC = 3 083 955 078 (журнал ac.move_combat, tick_now) ≥ 2^31;
//   хост загружен ~09.09 16:49 UTC; ворота закрылись ~04.10 13:20 UTC, откроются сами ~29.10 09:51 UTC.
//   Тот же класс дефекта, что N01 площадки 4/5 (12.10.2026, `jge` → `jae`).
//
// ЧТО ДЕЛАЕМ
//   В каждой из 8 площадок `sub R2,[M+7A70h]` + `cmp R2,R1` (8 байт) → `call` стаба + nop×3, а `jl` → `jb`
//   (байт 8Ch → 82h). Стаб делает то же вычитание (R2 = такт − такт атаки, как в стоке) и ставит CF:
//       ждать  ⇔  длительность > 0  И  (беззн.)(такт − такт атаки) < длительность
//   Разность по модулю 2^32 верна при любом переходе такта через 2^31 и 2^32. Длительность ≤ 0 — «ждать нечего»,
//   как в стоке при неотрицательной разности. Пока такт < 2^31 и разность ≥ 0, поведение совпадает со стоком
//   бит в бит (единственное отличие — исход при «отрицательной» разности, которая и есть дефект).
//   Флаги после ворот никто не читает: ветка «ждать» — эпилог функции (pop/ret), прямой путь начинается с
//   `movsx`/`mov`/`push` (сверено в verify_n17.py). Регистры, кроме R2 и флагов, стаб не трогает; R2 — как в стоке.
//
// Образы: сток 16c7a0af, живой NpcServer c02486d6, Indun 0de2c559 — площадки побайтно одинаковы.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"

// ⚠ Смещения в __asm — ТОЛЬКО #define (см. n03/n04: MSVC подставлял адрес константы вместо значения).
#define MOB_ATK_TICK 7A70h      // +31344: такт начала последней атаки монстра (0 — ни разу не атаковал)

namespace
{
    // Стабы по раскладке регистров площадки: R1 — длительность (movsx), R2 — «прошло», M — монстр.
    // Вход: R2 = такт кадра. Выход: R2 = такт − [M+7A70h] (как в стоке); CF = 1 ⇔ ждать (для `jb`).
#define N17_STUB(NAME, R1, R2, M)                                   \
    __declspec(naked) void NAME()                                   \
    {                                                               \
        __asm sub  R2, dword ptr [M + MOB_ATK_TICK]                 \
        __asm test R1, R1           /* CF = 0 */                    \
        __asm jle  done             /* длительность ≤ 0 — не ждать */ \
        __asm cmp  R2, R1           /* CF = (беззн.) R2 < R1 */      \
        __asm done:                                                 \
        __asm ret                                                   \
    }

    N17_STUB(St17_EdxEcxEbx, edx, ecx, ebx)     // 0x43949C, 0x439ACA
    N17_STUB(St17_EcxEdxEbx, ecx, edx, ebx)     // 0x43E693
    N17_STUB(St17_EdxEcxEdi, edx, ecx, edi)     // 0x43F39B, 0x44B409
    N17_STUB(St17_EdiEdxEbx, edi, edx, ebx)     // 0x44060F
    N17_STUB(St17_EdxEcxEsi, edx, ecx, esi)     // 0x4415F9
    N17_STUB(St17_EaxEdxEbx, eax, edx, ebx)     // 0x447EB1
#undef N17_STUB

    struct Gate
    {
        DWORD       movsxVa;    // ориентир (movsx R1, word [M+7A74h]) — для лога и сверки
        DWORD       subVa;      // площадка: sub R2,[M+7A70h] (6) + cmp R2,R1 (2) → call + nop×3
        BYTE        orig[8];
        DWORD       jlVa;       // jl rel32 (0F 8C) — второй байт 8C → 82 (jb)
        void      (*stub)();
        const wchar_t* where;
    };

    const Gate kGates[] =
    {
        { 0x43949C, 0x4394A5, { 0x2B,0x8B,0x70,0x7A,0x00,0x00, 0x3B,0xCA }, 0x4394AD, &St17_EdxEcxEbx,
          L"sub_439450 BATTLEMOVE (действие 7)" },
        { 0x439ACA, 0x439AD3, { 0x2B,0x8B,0x70,0x7A,0x00,0x00, 0x3B,0xCA }, 0x439ADB, &St17_EdxEcxEbx,
          L"sub_439A70 MOVE_AND_ACTION (действие 16)" },
        { 0x43E693, 0x43E69C, { 0x2B,0x93,0x70,0x7A,0x00,0x00, 0x3B,0xD1 }, 0x43E6A4, &St17_EcxEdxEbx,
          L"sub_43E580 ProcessAction_Move (действие 2) ★ причина «призраков»" },
        { 0x43F39B, 0x43F3A4, { 0x2B,0x8F,0x70,0x7A,0x00,0x00, 0x3B,0xCA }, 0x43F3AC, &St17_EdxEcxEdi,
          L"sub_43F330 ProcessAction_Idle (особые монстры, флаг 0x2000000)" },
        { 0x44060F, 0x440618, { 0x2B,0x93,0x70,0x7A,0x00,0x00, 0x3B,0xD7 }, 0x440620, &St17_EdiEdxEbx,
          L"sub_4405B0 CHASE/AROUNDMOVE (действия 5, 13)" },
        { 0x4415F9, 0x441602, { 0x2B,0x8E,0x70,0x7A,0x00,0x00, 0x3B,0xCA }, 0x44160A, &St17_EdxEcxEsi,
          L"sub_4415D0 FEAR (действие 14)" },
        { 0x447EB1, 0x447EBA, { 0x2B,0x93,0x70,0x7A,0x00,0x00, 0x3B,0xD0 }, 0x447EC2, &St17_EaxEdxEbx,
          L"sub_447B30 OnBattle (боевой ИИ: погоня/атака)" },
        { 0x44B409, 0x44B412, { 0x2B,0x8F,0x70,0x7A,0x00,0x00, 0x3B,0xCA }, 0x44B41A, &St17_EdxEcxEdi,
          L"sub_44B3D0 действие 19 (ход навыка)" },
    };

    // Сверка: обе части каждой площадки (8 байт sub+cmp и 2 байта jl), плюс ориентир movsx.
    const BYTE kJl[] = { 0x0F, 0x8C };
    const BYTE kJb[] = { 0x82 };
}

PatchResult N17_MobActionTimer()
{
    if (!Config::GetBool(L"N17_MobActionTimer", L"Enabled", true))
        return PatchResult::Disabled;

    // Правило проекта: ни один патч не пишет байты, не сверив ВСЕ свои площадки.
    Site sites[ARRAYSIZE(kGates) * 2];
    for (int i = 0; i < (int)ARRAYSIZE(kGates); ++i)
    {
        sites[2 * i]     = { kGates[i].subVa, kGates[i].orig, sizeof(kGates[i].orig) };
        sites[2 * i + 1] = { kGates[i].jlVa,  kJl,            sizeof(kJl) };
    }
    if (!VerifyAllSites(L"N17_MobActionTimer", sites, ARRAYSIZE(sites)))
        return PatchResult::Mismatch;

    for (const Gate& g : kGates)
    {
        if (!Hook::WriteCall(g.subVa, (void*)g.stub, sizeof(g.orig))) return PatchResult::Failed;   // call + nop×3
        if (!Hook::WriteBytes(g.jlVa + 1, kJb, sizeof(kJb)))         return PatchResult::Failed;   // jl → jb
    }
    for (const Gate& g : kGates)
        Log::Line(L"    0x%06X %ls", g.movsxVa, g.where);
    Log::Line(L"    ожидание атаки монстра считается беззнаково (8 площадок): при аптайме хоста > 24,8 сут монстры, "
              L"ещё не атаковавшие, снова ходят, преследуют и дерутся; длительность ≤ 0 — не ждать");
    return PatchResult::Applied;
}
