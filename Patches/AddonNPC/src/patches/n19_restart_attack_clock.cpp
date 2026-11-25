// Copyright (c) 2026 @sitxovski (Discord)
// n19_restart_attack_clock.cpp — ★ N19 (слот P86 координатора, 25.10.2026) [ОРИГИНАЛ — дефект стока, эксплойт скорости атаки].
//   Отчёт: Reports/phantom_damage/REPORT.md. Баг игроков: «Performing a normal attack followed by micro-movement queues
//   phantom damage instances, causing 1 attack to hit 4 times».
//
// СИМПТОМ
//   «Атака → микроход → снова клик по монстру» бьёт быстрее скорости атаки: каждый перезапуск серии засчитывает удар сразу.
//   Живой журнал игрока 20.10 17:53:30–32: 4 перезапуска 4026 за 2,4 с, HP монстра 1400 → 902 → 452 → 269 → 0 — по 2 удара
//   ближнего боя (`+65117`) на каждый 4026, тогда как серия 4028 дала бы их не чаще раза в 900 мс (Combo.lst, одноручный меч).
//
// МЕХАНИЗМ
//   Начало серии — `Process_AttackToMonster` (sub_45FCD0, пакет 8201 ← 4026) и PvP-двойник (sub_460710, 8222 ← 4201):
//     0x45FE08  mov  byte  [ebp+0Eh], 0          ; шаг комбо := 0
//     0x45FE0C  mov  dword [ebp+0FE90h], 0       ; ★ момент прошлого удара := 0   ← площадка 1
//     … дальность (sub_42C4F0) → sub_45F3A0(…, a4 = 1) — тот же приём, что у 4028, с проверкой скорости:
//       (такт − [ebp+0FE90h]) + допуск ≥ [ebp+0FE94h] (длительность прошлого удара), иначе «SpeedHack Check»: удар молча
//       отброшен, счётчик +0FE60h (> 30 → 8905).
//   Обнуление делает проверку пустой: 4026 принимается ВСЕГДА, сколько бы раньше ни был прошлый удар. PvP — то же @0x46085F
//   (проверка — sub_45FF80). Клиент оригинала шлёт 4026 на каждый вход в бой (клик → подход 4006 → 4008 → 4026), поэтому
//   ход + клик по цели давал «бесплатный» удар; порт делал то же.
//
// ЧТО ДЕЛАЕМ
//   Площадку `mov dword [ebp+0FE90h], 0` (10 б) заменяем на call стаба + nop×5. Стаб (все регистры и флаги сохранены) зовёт
//   N19_Restart(запись игрока, такт удара, площадка): если прошлый удар есть и его длительность с допуском N01 ЕЩЁ НЕ ИСТЕКЛА
//   (та же формула, что проверит sub_45F3A0/sub_45FF80, — `N01_TolSum`), момент прошлого удара НЕ обнуляется (Mode=1): ранний
//   перезапуск судит штатная проверка скорости — как ранний 4028. Иначе — обнуление, как в стоке (честный вход в бой после
//   паузы ничем не отличается от стока). Шаг комбо, пересчёт очереди уронов, дальность и отказы не трогаются.
//   Журнал: ac.move_combat 103 (Mode=1, часы сохранены) / 104 (Mode=0 — только журнал, обнуление как в стоке).
//   ★ Ревизия 25.10 (М-5): запись уходит только в ветке «цель в дальности» — там сток зовёт проверку скорости
//   (0x45FE67 `call sub_45F3A0`, 0x4608CC `call sub_45FF80` подменены стабом «отдать запись → та же функция»); вне
//   дальности проверки нет, раннего отброса нет — и записи нет. Счётчики — `N19_Counters` (стенд).
//   Клиент порта ждёт эти часы сам (`asda.Combat.RestartSeriesGate`), честному игроку отброс не грозит.
//
// ПЛОЩАДКИ (байты одинаковы в стоке 16c7a0af, живом c02486d6 и Indun 0de2c559 — verify_n19.py)
//     0x0045FE0C  C7 85 90 FE 00 00 00 00 00 00   mov dword ptr [ebp+0FE90h], 0   (sub_45FCD0, такт — [esp+94h])
//     0x0046085F  C7 85 90 FE 00 00 00 00 00 00   mov dword ptr [ebp+0FE90h], 0   (sub_460710, такт — [esp+7Ch])
//   ebp — запись игрока (база 68264·индекс), такт удара — третий аргумент обработчика (`a3`, по нему же меряет sub_45F3A0).
//     0x0045FE67  E8 34 F5 FF FF                  call sub_45F3A0   (ветка «в дальности», монстр) — ревизия М-5
//     0x004608CC  E8 AF F6 FF FF                  call sub_45FF80   (ветка «в дальности», PvP) — ревизия М-5
//   С N05 (0x45FEF2), N10 (0x45FE41, 0x45FED5) и N01/N13/N14 площадки не пересекаются.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"
#include "AcJournal.h"
#include <string.h>

extern "C" DWORD __stdcall N01_TolSum(DWORD dt, int dur);   // n01: (интервал + действующий допуск) с насыщением; dur ≤ 0 → 0xFFFFFFFF

namespace
{
    const DWORD kVaMob = 0x0045FE0C;   // sub_45FCD0: начало серии по монстру (8201 ← 4026)
    const DWORD kVaPvp = 0x0046085F;   // sub_460710: начало серии по игроку (8222 ← 4201)
    const BYTE  kOrig[] = { 0xC7, 0x85, 0x90, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };   // mov dword ptr [ebp+0FE90h], 0
    constexpr int kOffLast    = 0xFE90;   // запись игрока: такт прошлого принятого удара/навыка
    constexpr int kOffDur     = 0xFE94;   // запись игрока: WORD длительность прошлого удара (Combo.lst/Skill.lst с баффами)
    constexpr int kOffViol    = 0xFE60;   // запись игрока: BYTE счётчик нарушений скорости
    constexpr int kOffName    = 0x7714;   // запись игрока: имя
    constexpr int kOffUserNum = 0x7864;   // запись игрока: WORD userNum (слот GameServer)

    int  g_mode = 1;                      // 1 — часы не обнуляются (ранний перезапуск судит проверка скорости); 0 — только журнал
    volatile LONG g_hits = 0, g_early = 0, g_journaled = 0;   // площадки / ранние перезапуски / записи 103-104 (ветка «в дальности»)

    // ★ Ревизия 25.10 (М-5): запись журнала откладывается до ветки «цель в дальности» — там же сток зовёт проверку скорости
    //   (вне дальности 4026/4201 проверки нет и раннего отброса тоже нет, запись была бы неточной). Решение и вызов проверки
    //   идут подряд в одном обработчике одного потока NpcServer — отложенная запись хранится в слоте своего потока.
    struct FPending
    {
        DWORD tid;        // поток (0 — слот свободен)
        int   site;       // 0 монстр / 1 игрок
        AcJournal::Event e;   // готовая запись
    };
    FPending g_pending[16] = {};
    CRITICAL_SECTION g_pendLock;
    bool g_pendLockInit = false;

    FPending* SlotOf(DWORD tid, bool create)
    {
        FPending* freeSlot = nullptr;
        for (FPending& p : g_pending)
        {
            if (p.tid == tid) { return &p; }
            if (!freeSlot && p.tid == 0) { freeSlot = &p; }
        }
        if (create && freeSlot) { freeSlot->tid = tid; return freeSlot; }
        return nullptr;
    }
}

// rec — запись игрока (ebp на площадке), tick — такт удара, site — 0 монстр / 1 игрок.
// Возврат: 1 — обнулить момент прошлого удара (как сток), 0 — оставить.
extern "C" int __stdcall N19_Restart(BYTE* rec, DWORD tick, int site)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        const DWORD tid = GetCurrentThreadId();
        if (g_pendLockInit)
        {
            EnterCriticalSection(&g_pendLock);
            if (FPending* p = SlotOf(tid, false)) { p->tid = 0; }   // прошлая отложенная запись потока (цель была вне дальности) — снята
            LeaveCriticalSection(&g_pendLock);
        }
        if (!rec) { return 1; }
        const DWORD last = *(const DWORD*)(rec + kOffLast);
        const int   dur  = *(const short*)(rec + kOffDur);
        if (last == 0 || dur <= 0) { return 1; }                  // прошлого удара нет / проверки нет — как сток
        const DWORD dt  = tick - last;                            // по модулю 2^32 (N01: тик хранится 32-битным)
        const DWORD sum = N01_TolSum(dt, dur);
        if (sum >= (DWORD)dur) { return 1; }                      // прошлый удар доиграл — честный вход в бой
        InterlockedIncrement(&g_early);
        if (g_pendLockInit)
        {
            EnterCriticalSection(&g_pendLock);
            if (FPending* p = SlotOf(tid, true))
            {
                p->site = site;
                AcJournal::Event& e = p->e;
                AcJournal::Clear(e, AcJournal::kMoveCombat, (BYTE)(g_mode == 1 ? 103 : 104));
                e.opcode  = site ? 8222 : 8201;
                e.userNum = *(const short*)(rec + kOffUserNum);
                AcJournal::CopyName(e, rec + kOffName);
                e.w[0] = last;                                    // такт прошлого удара
                e.w[1] = tick;                                    // такт перезапуска
                e.v[1] = (int)dt;                                 // interval_ms
                e.v[2] = *(const signed char*)(rec + kOffViol);   // violation_count (счётчик скорости до проверки)
                e.v[3] = (int)(sum - dt);                         // p_duration ← действующий допуск N01, мс
                e.v[4] = dur;                                     // duration ← длительность прошлого удара, мс
            }
            LeaveCriticalSection(&g_pendLock);
        }
        return g_mode == 1 ? 0 : 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 1;   // любая ошибка разбора — поведение стока
    }
}

// Ветка «цель в дальности» (сток сейчас позовёт проверку скорости): отложенная запись этого потока уходит в журнал.
extern "C" void __stdcall N19_InRange(int site)
{
    __try
    {
        if (!g_pendLockInit) { return; }
        AcJournal::Event e;
        bool have = false;
        EnterCriticalSection(&g_pendLock);
        if (FPending* p = SlotOf(GetCurrentThreadId(), false))
        {
            if (p->site == site) { e = p->e; have = true; }
            p->tid = 0;
        }
        LeaveCriticalSection(&g_pendLock);
        if (have) { InterlockedIncrement(&g_journaled); AcJournal::Push(e); }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Счётчики (стенд; в PatchLog — строка установки): площадки, ранние перезапуски, записи журнала.
extern "C" __declspec(dllexport) void __stdcall N19_Counters(LONG* hits, LONG* early, LONG* journaled)
{
    if (hits) { *hits = g_hits; }
    if (early) { *early = g_early; }
    if (journaled) { *journaled = g_journaled; }
}

namespace
{
    // Площадка монстра: на входе [esp] — адрес возврата; кадр обработчика ниже на 0x10 (аргументы sub_42C4F0 уже на стеке):
    //   такт у площадки — [esp+94h], в стабе после pushad/pushfd и адреса возврата — [esp+0x24+4+0x94].
    __declspec(naked) void St_Mob()
    {
        __asm
        {
            pushfd
            pushad
            push  0                             // площадка: монстр
            push  dword ptr [esp+0x24+4+0x94+4] // такт (после push 0 — ещё +4)
            push  ebp                           // запись игрока
            call  N19_Restart                   // __stdcall, 12 б
            test  eax, eax
            jz    keep
            mov   dword ptr [ebp+0FE90h], 0     // как сток
        keep:
            popad
            popfd
            ret
        }
    }
    // Площадка PvP: такт у площадки — [esp+7Ch].
    __declspec(naked) void St_Pvp()
    {
        __asm
        {
            pushfd
            pushad
            push  1                             // площадка: игрок
            push  dword ptr [esp+0x24+4+0x7C+4] // такт
            push  ebp
            call  N19_Restart
            test  eax, eax
            jz    keep
            mov   dword ptr [ebp+0FE90h], 0
        keep:
            popad
            popfd
            ret
        }
    }
}

namespace
{
    // ★ Ревизия 25.10 (М-5): вызовы проверки скорости в ветке «цель в дальности» — `call rel32` подменяется стабом, который
    //   отдаёт отложенную запись журнала и уходит в ту же функцию стока с теми же аргументами (адрес возврата не тронут).
    const DWORD kVaChkMob = 0x0045FE67;   // sub_45FCD0: call sub_45F3A0 (Process_AttackedToMonster, a4 = 1)
    const DWORD kVaChkPvp = 0x004608CC;   // sub_460710: call sub_45FF80 (Process_AttackedToPlayer, a4 = 1)
    const DWORD kFnChkMob = 0x0045F3A0;
    const DWORD kFnChkPvp = 0x0045FF80;
    DWORD g_pChkMob = kFnChkMob;
    DWORD g_pChkPvp = kFnChkPvp;

    __declspec(naked) void St_InRangeMob()
    {
        __asm
        {
            pushfd
            pushad
            push  0                             // площадка: монстр
            call  N19_InRange                   // __stdcall, 4 б
            popad
            popfd
            jmp   dword ptr [g_pChkMob]         // сток: sub_45F3A0 с теми же регистрами и стеком
        }
    }
    __declspec(naked) void St_InRangePvp()
    {
        __asm
        {
            pushfd
            pushad
            push  1                             // площадка: игрок
            call  N19_InRange
            popad
            popfd
            jmp   dword ptr [g_pChkPvp]         // сток: sub_45FF80
        }
    }

    void CallBytes(BYTE out[5], DWORD va, DWORD target)
    {
        out[0] = 0xE8;
        const int rel = (int)(target - (va + 5));
        memcpy(out + 1, &rel, 4);
    }
}

PatchResult N19_RestartAttackClock()
{
    if (!Config::GetBool(L"N19_RestartAttackClock", L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode = Config::GetInt(L"N19_RestartAttackClock", L"Mode", 1) == 0 ? 0 : 1;
    const bool bMob = Config::GetBool(L"N19_RestartAttackClock", L"MobSite", true);
    const bool bPvp = Config::GetBool(L"N19_RestartAttackClock", L"PvpSite", true);
    BYTE chkMob[5], chkPvp[5];
    CallBytes(chkMob, kVaChkMob, kFnChkMob);
    CallBytes(chkPvp, kVaChkPvp, kFnChkPvp);
    const Site sites[] = { { kVaMob, kOrig, sizeof(kOrig) }, { kVaPvp, kOrig, sizeof(kOrig) },
                           { kVaChkMob, chkMob, 5 }, { kVaChkPvp, chkPvp, 5 } };
    if (!VerifyAllSites(L"N19", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!g_pendLockInit) { InitializeCriticalSection(&g_pendLock); g_pendLockInit = true; }
    if (bMob && !Hook::WriteCall(kVaMob, (void*)&St_Mob, sizeof(kOrig))) { return PatchResult::Failed; }
    if (bMob && !Hook::WriteCall(kVaChkMob, (void*)&St_InRangeMob, 5)) { return PatchResult::Failed; }
    if (bPvp && !Hook::WriteCall(kVaPvp, (void*)&St_Pvp, sizeof(kOrig))) { return PatchResult::Failed; }
    if (bPvp && !Hook::WriteCall(kVaChkPvp, (void*)&St_InRangePvp, 5)) { return PatchResult::Failed; }
    Log::Line(L"    N19: начало серии без обнуления часов атаки — монстр %s, PvP %s, Mode=%d (%s)",
        bMob ? L"да" : L"нет", bPvp ? L"да" : L"нет", g_mode,
        g_mode == 1 ? L"ранний перезапуск судит проверка скорости" : L"только журнал 104");
    return (bMob || bPvp) ? PatchResult::Applied : PatchResult::Disabled;
}
