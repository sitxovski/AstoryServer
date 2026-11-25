// Copyright (c) 2026 @sitxovski (Discord)
// n23_skill_hide_aggro.cpp — N23 (слот P104, 04.11.2026, bug-hide-skill) [ИСПРАВЛЕНИЕ] дефектов оригинала:
//   монстр не держит целью игрока под навыком «Убежище» (состояние 112 / «Быстрая маскировка» 186), которого он
//   НЕ обнаружил штатной проверкой скрытности. Разбор: Reports/hide_skill/p104/P104_N23_REPORT.md.
//
// КАК В ОРИГИНАЛЕ (реверс 04.11.2026: декомпиль npc_work/NpcServer.exe.c + дизассемблер живого образа c02486d6)
//   Скрытность навыка — байт записи игрока +0x173F (5951 = слот 112 · 53 + 15) == 1. Монстр с байтом +0x1FF1 (8177) ≠ 0
//   видит скрытых. Проверку скрытности `sub_434C30` («Hide Check», edi = монстр, [esp+4] = запись игрока) вызывают
//   ТОЛЬКО два места — поиск первого агрессора в простое (`sub_43E580` «ProcessAction_Move()2», `sub_43F330`
//   «ProcessAction_Move()1»): скрытого видно в ближнем прямоугольнике (Check1), в половине дальности обзора минус
//   бонус +52302 % (Check2) или по броску 15 − (+52274) из 100 (Check3); иначе монстр его не выбирает.
//   Всех остальных писателей цели монстра (+0x7A58) — 25 мест `mov word [r+7A58h], r16` в .text — проверка не касается.
//
// ДЕФЕКТЫ (все сводятся к «цель-скрытый появляется мимо Hide Check»)
//   D1  `sub_4287F0` (CPlayer::ProcessSkill_QuickHide, состояние 186), 0x42895C: монстр, у которого игрок в списке
//       угрозы, но цель другая, — ветка находит запись и только пишет «SetAttackToMonsterPlayerInfo() Exception…
//       iArrayIndex -1»; запись угрозы остаётся (у целящихся монстров её снимает штатная потеря цели `sub_43FFC0`).
//   D2  смена цели по списку угрозы без проверки скрытности: OnBattle `sub_447B30` (0x447E05; цель в состоянии
//       0/1/8/11) и ИИ «берсерк» `sub_4364E0` (0x43668B).
//   D3  передача цели без проверки: следующая цель `sub_43D0D0` (0x43D17F свой список, 0x43D2AA списки отряда
//       монстров), копия цели отряда `sub_43A4F0` / `sub_43A6E0` (0x43A55C / 0x43A74B), «вой» `sub_439EA0` (0x43A04F).
//   D4  «Убежище» 112 не снимает погоню: обработчик начала 112 — пустой `sub_4249C0`; монстр, уже целившийся в
//       игрока, продолжает гнаться и бить скрытого.
//   Навык монстра с выбором цели «по угрозе» (типы 3/4/5 `sub_40EE50`) и «случайный игрок рядом» (тип 6) тоже
//   выбирает скрытого без проверки (запись выбора 0x40FFE4).
//
// ПРАВКА — одна точка выбора вместо 25 писателей
//   S1 0x447B92  OnBattle, начало (`cmp byte [esi+7858h],1` → je потеря цели 0x4482FD): цель скрыта навыком, монстр не
//                видит скрытых и НЕ обнаружил её проверкой Hide Check в этой погоне → ZF=1 → штатная потеря цели
//                `sub_43FFC0(монстр, тик, 1)` (та же ветка, что у мёртвой цели; запись угрозы цели снимается в
//                `sub_43D0D0`, берётся следующий в списке). Закрывает D2, D3, D4 и всех прочих писателей разом:
//                обычная атака монстра — только из OnBattle (`sub_442A40` / `sub_436880` вызываются только оттуда), а цель
//                проверяется в начале каждого прохода. Навык — см. S4 и S6.
//   S2 0x43F117  поиск агрессора «Move()2» после пройденной Hide Check: запись цели + отметка «обнаружил» (монстр →
//   S3 0x43F4AB  номер игрока + UserIndex), если цель скрыта. То же в «Move()1». Отметка живёт, пока цель монстра —
//                этот игрок и он скрыт: S1 с видимой целью отметку снимает (новое скрытие = новая проверка); отметка,
//                которую S1 не подтверждал дольше kMarkTtlMs (монстр сменил цель, ушёл в простой, умер), не действует и
//                вычищается. Детекция стока (дальность, бросок, частота 500 мс) не меняется.
//   S4 0x40FFE4  выбор цели навыка монстра (`mov word [esi+91C5h], ax`, вид цели +91C4 == 1 — игрок): выбран скрытый игрок,
//                который НЕ текущая цель монстра (типы 3/4/5 «по угрозе», 6 «случайный рядом»; детектор — без подмены) →
//                цель навыка = текущая цель монстра (запасной вариант стока при пустом выборе, LABEL_5). Текущую цель
//                судит S1 (обнаружена — можно, нет — снимается).
//   S5 0x42895C  D1: найденная у монстра запись угрозы к игроку, ушедшему в «Быструю маскировку», вычищается (номер −1,
//                +4/+8/+12 = 0) вместе с обратной записью игрока +68168 «этот монстр» — ровно как штатная `sub_434A60`
//                (InitializeBattleInfo) при потере цели; строка «Exception» стока не пишется.
//   S6 0x43668B  ★ ревизия 04.11 (F1): цикл условий навыков монстра `sub_4364E0` (цель в состоянии 0/1/8/11) пишет цель
//                «наибольшая угроза» и В ТОМ ЖЕ проходе зовёт обработчик условия (0x43669E → `sub_419C80`, мгновенный
//                навык бьёт сразу) — мимо S1. Выбор повторяется по правилу стока (наибольшая угроза строго больше, без
//                текущей цели и пустых), но без скрытых необнаруживших; никого — выход стока «кандидата нет» 0x4366B4.
//
// ЧЕГО НЕ ТРОГАЕМ
//   * Сама проверка Hide Check и её частота — детекция оригинала (обнаружение рядом, бросок) остаётся как есть.
//   * Площадной навык монстра, задевший скрытого рядом с целью (сбор жертв `sub_40C200`): это не выбор цели; урон снимает
//     скрытность на GameServer (штатно).
//   * Скрытый оператор (GM, бит 2 +0x7654) — N11/N12; площадки не пересекаются (N11-A 0x447BA7 идёт следом за S1).
//   * Навык, каст которого начат ДО скрытия (`sub_44B2A0` доводит его по сохранённой цели +91C5): один удар возможен, урон
//     снимает скрытность на GameServer (штатно).
//   * Монстр, взявший игрока ВИДИМЫМ, теряет его в момент скрытия даже вплотную; заново — только поиском агрессора с Hide
//     Check (D4: в стоке «Убежище» погоню не снимало вовсе; «Быстрая маскировка» снимает и стоком).
//
// ПОТОКИ: S1–S6 исполняются в AI-потоках карт; таблица отметок общая — под критической секцией; без отметок (обычный
//   случай) S1 не берёт замок.
//
// ⚠ Смещения во встроенном ассемблере — только #define (урок 24.08, см. n03 и verify_trampolines.py).
#include "Patches.h"
#include "../Config.h"
#include "../NpcApi.h"
#include "Hook.h"
#include "Log.h"
#include <unordered_map>

namespace
{
    const wchar_t* const kSec = L"N23_SkillHideAggro";

    // ── площадки (байты стока; одинаковы в живом, Indun, Ch2 и IDB-образах) ──
    // S1: cmp byte ptr [esi+7858h], 1
    const BYTE kOrigS1[] = { 0x80, 0xBE, 0x58, 0x78, 0x00, 0x00, 0x01 };
    // S2: mov word ptr [ebx+7A58h], dx
    const BYTE kOrigS2[] = { 0x66, 0x89, 0x93, 0x58, 0x7A, 0x00, 0x00 };
    // S3: mov word ptr [edi+7A58h], bx
    const BYTE kOrigS3[] = { 0x66, 0x89, 0x9F, 0x58, 0x7A, 0x00, 0x00 };
    // S4: mov word ptr [esi+91C5h], ax
    const BYTE kOrigS4[] = { 0x66, 0x89, 0x86, 0xC5, 0x91, 0x00, 0x00 };
    // S5: push 0 / push 0 / push 0 (аргументы строки «Exception»)
    const BYTE kOrigS5[] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00 };
    // S6: mov word ptr [ebx+7A58h], di
    const BYTE kOrigS6[] = { 0x66, 0x89, 0xBB, 0x58, 0x7A, 0x00, 0x00 };

    const Site kSiteS1 = { Npc::Hooks::kHideBattleGate,   kOrigS1, sizeof(kOrigS1) };
    const Site kSiteS2 = { Npc::Hooks::kHideAcquireMove2, kOrigS2, sizeof(kOrigS2) };
    const Site kSiteS3 = { Npc::Hooks::kHideAcquireMove1, kOrigS3, sizeof(kOrigS3) };
    const Site kSiteS4 = { Npc::Hooks::kHideSkillTarget,  kOrigS4, sizeof(kOrigS4) };
    const Site kSiteS5 = { Npc::Hooks::kHideQuickHater,   kOrigS5, sizeof(kOrigS5) };
    const Site kSiteS6 = { Npc::Hooks::kHideSkillCondTarget, kOrigS6, sizeof(kOrigS6) };

    // Смещения для встроенного ассемблера.
    #define DEAD_FLAG    7858h    // +30808: байт записи игрока, сток сравнивает с 1 (потеря цели)
    #define HIDE_BYTE    173Fh    // +5951: слот 112, байт 15 — скрыт навыком (== 1)
    #define TGT_KIND     91C4h    // +37316: вид цели навыка монстра (1 — игрок)
    #define TGT_NUM      91C5h    // +37317: номер цели навыка
    #define MOB_TARGET   7A58h    // +31320: цель монстра (номер игрока)

    // Те же смещения для C-кода.
    constexpr DWORD kHideByte   = 5951;     // байт скрытности навыка
    constexpr DWORD kMobSeeHide = 8177;     // монстр видит скрытых (Hide Check: ≠ 0 — проверка пропускается)
    constexpr DWORD kUserIndex  = 30356;    // UserIndex учётки (у монстра — его номер)
    constexpr DWORD kMobUsers   = 30536;    // монстр → массив записей игроков (+0x7748)
    constexpr DWORD kMobTarget  = 31320;    // цель монстра
    constexpr DWORD kMobHate    = 31352;    // 20 × 16 б: i16 игрок, +4, +8 угроза, +12 урон
    constexpr DWORD kUserSize   = 68264;    // шаг массива игроков
    constexpr int   kMaxUsers   = 1000;     // предел номера игрока (OnBattle 0x447B6D)

    DWORD g_quickCont = Npc::Hooks::kHideQuickHaterCont;   // 0x428895 — продолжение цикла QuickHide
    DWORD g_condSkip  = Npc::Hooks::kHideSkillCondSkip;    // 0x4366B4 — выход стока «кандидата нет» в sub_4364E0
    constexpr DWORD kUserBackRef = 68168;   // 8 × {i16 номер монстра, i32} — кто его бьёт (sub_434A60 чистит)
    constexpr DWORD kMarkTtlMs   = 3000;    // отметка без подтверждения S1 дольше — не действует (OnBattle идёт ≤ 500 мс)

    bool g_trace = true;

    // ── отметки «монстр обнаружил скрытого» ────────────────────────────────
    struct Mark { short num; LONG ui; DWORD tick; };
    std::unordered_map<const BYTE*, Mark> g_marks;
    CRITICAL_SECTION g_cs;
    bool             g_csReady   = false;
    volatile LONG    g_markCount = 0;      // > 0 — в таблице есть отметки (S1 без замка, если 0)

    volatile LONG g_dropped = 0, g_marked = 0, g_skillRedirect = 0, g_quickCleared = 0, g_condRedirect = 0;
    DWORD         g_lastPurge = 0;      // под g_cs

    // Журнал без лавины: первые 20 событий каждого вида, дальше — каждое 1000-е.
    bool ShouldLog(LONG n) { return n <= 20 || (n % 1000) == 0; }

    bool IsSkillHidden(const BYTE* rec) { return rec[kHideByte] == 1; }
    bool MobSeesHidden(const BYTE* mob) { return mob[kMobSeeHide] != 0; }
    LONG UserIndexOf(const BYTE* rec)   { return *(volatile const LONG*)(rec + kUserIndex); }
    LONG MobId(const BYTE* mob)         { return *(volatile const LONG*)(mob + kUserIndex); }

    // Отметка монстра совпадает с игроком (номер и UserIndex — запись могла перейти к другому игроку).
    bool HasMark(const BYTE* mob, short num, LONG ui)
    {
        if (g_markCount <= 0) return false;
        bool hit = false;
        EnterCriticalSection(&g_cs);
        auto it = g_marks.find(mob);
        const DWORD now = GetTickCount();
        if (it != g_marks.end() && it->second.num == num && it->second.ui == ui && now - it->second.tick <= kMarkTtlMs)
        {
            it->second.tick = now;                    // подтверждено: погоня идёт
            hit = true;
        }
        LeaveCriticalSection(&g_cs);
        return hit;
    }

    void SetMark(const BYTE* mob, short num, LONG ui)
    {
        EnterCriticalSection(&g_cs);
        g_marks[mob] = Mark{ num, ui, GetTickCount() };
        g_markCount = (LONG)g_marks.size();
        LeaveCriticalSection(&g_cs);
    }

    // Снять отметку монстра; раз в 5 с — вычистить просроченные (монстр сменил цель / в простое / умер: S1 их не видит).
    void EraseMark(const BYTE* mob)
    {
        EnterCriticalSection(&g_cs);
        g_marks.erase(mob);
        const DWORD now = GetTickCount();
        if (now - g_lastPurge >= 5000)
        {
            g_lastPurge = now;
            for (auto it = g_marks.begin(); it != g_marks.end(); )
                it = (now - it->second.tick > kMarkTtlMs) ? g_marks.erase(it) : std::next(it);
        }
        g_markCount = (LONG)g_marks.size();
        LeaveCriticalSection(&g_cs);
    }

    // ── C-часть врезок ──────────────────────────────────────────────────────
    // S1: цель скрыта навыком. 1 — снять цель (штатная потеря цели), 0 — оставить.
    int __cdecl OnHiddenTarget(const BYTE* mob, const BYTE* rec)
    {
        if (MobSeesHidden(mob)) return 0;
        const short num = *(const short*)(mob + kMobTarget);
        const LONG  ui  = UserIndexOf(rec);
        if (HasMark(mob, num, ui)) return 0;          // обнаружил Hide Check в этой погоне
        const LONG n = InterlockedIncrement(&g_dropped);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N23] монстр %ld снял цель: игрок #%d (UserIndex %ld) скрыт навыком и не обнаружен (всего %ld)",
                      MobId(mob), (int)num, ui, (long)n);
        return 1;
    }

    // S1: цель видима — отметка монстра (если была) больше не нужна: следующее скрытие проверяется заново.
    void __cdecl OnVisibleTarget(const BYTE* mob)
    {
        EraseMark(mob);
    }

    // S2/S3: монстр выбрал цель после пройденной Hide Check; цель скрыта (проверено в врезке).
    void __cdecl OnAcquireHidden(const BYTE* mob, const BYTE* rec, int num)
    {
        if (MobSeesHidden(mob)) return;               // детектор: отметка не нужна (S1 его не трогает)
        const LONG ui = UserIndexOf(rec);
        SetMark(mob, (short)num, ui);
        const LONG n = InterlockedIncrement(&g_marked);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N23] монстр %ld обнаружил скрытого игрока #%d (UserIndex %ld) проверкой Hide Check (всего %ld)",
                      MobId(mob), num, ui, (long)n);
    }

    // S4: номер цели навыка (вид — игрок). Возвращает номер, который запишется.
    int __cdecl OnSkillTarget(const BYTE* mob, int num)
    {
        if (num < 0 || num >= kMaxUsers) return num;
        const BYTE* users = *(const BYTE* const*)(mob + kMobUsers);
        if (!users) return num;
        const BYTE* rec = users + (DWORD)num * kUserSize;
        if (!IsSkillHidden(rec) || MobSeesHidden(mob)) return num;
        const short tgt = *(const short*)(mob + kMobTarget);
        if (tgt == (short)num) return num;            // текущая цель: её судит S1 (обнаружен / снимается)
        const LONG ui = UserIndexOf(rec);
        const LONG n = InterlockedIncrement(&g_skillRedirect);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N23] навык монстра %ld: скрытый игрок #%d (UserIndex %ld) не выбран — цель навыка текущая #%d (всего %ld)",
                      MobId(mob), num, ui, (int)tgt, (long)n);
        return (int)(unsigned short)tgt;
    }

    // S5: запись угрозы (eax) монстра к игроку, ушедшему в «Быструю маскировку»; idx — номер записи 0..19.
    void __cdecl OnQuickHideHater(BYTE* entry, int idx)
    {
        const short num = *(short*)entry;
        *(short*)entry        = -1;                   // как sub_43D0D0 чистит запись цели
        *(DWORD*)(entry + 4)  = 0;
        *(DWORD*)(entry + 8)  = 0;
        *(DWORD*)(entry + 12) = 0;
        const BYTE* mob = entry - kMobHate - (DWORD)idx * 16;
        // Обратная запись игрока «этот монстр» — как sub_434A60 (иначе sub_428770 по ней добавит угрозу лекарю).
        const BYTE* users = *(const BYTE* const*)(mob + kMobUsers);
        if (users && num >= 0 && num < kMaxUsers)
        {
            BYTE* back = (BYTE*)users + (DWORD)num * kUserSize + kUserBackRef;
            const short mobNum = *(const short*)(mob + kUserIndex);
            for (int k = 0; k < 8; ++k, back += 8)
                if (*(short*)back == mobNum) { *(short*)back = -1; *(DWORD*)(back + 4) = 0; }
        }
        const LONG n = InterlockedIncrement(&g_quickCleared);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N23] «Быстрая маскировка»: у монстра %ld снята угроза к игроку #%d (запись %d; всего %ld)",
                      MobId(mob), (int)num, idx, (long)n);
    }

    // S6: выбор цели «наибольшая угроза» в цикле условий навыков (sub_4364E0). cur — исключаемый номер (bp, текущая цель),
    //     pick — выбор стока. Возвращает номер (−1 — кандидата нет). Правило стока: max с нуля, строго больше, без cur и −1.
    int __cdecl OnSkillCondTarget(const BYTE* mob, int pick, int cur)
    {
        const BYTE* users = *(const BYTE* const*)(mob + kMobUsers);
        if (!users || MobSeesHidden(mob) || pick < 0 || pick >= kMaxUsers) return pick;
        const BYTE* prec = users + (DWORD)pick * kUserSize;
        if (!IsSkillHidden(prec) || HasMark(mob, (short)pick, UserIndexOf(prec))) return pick;   // как сток
        int best = -1; LONG maxHate = 0;
        const BYTE* e = mob + kMobHate;
        for (int j = 0; j < 20; ++j, e += 16)
        {
            const short num = *(const short*)e;
            if (num == (short)cur || num == -1) continue;
            const LONG hate = *(const LONG*)(e + 8);
            if (!(maxHate < hate)) continue;
            if (num >= 0 && num < kMaxUsers)
            {
                const BYTE* rec = users + (DWORD)num * kUserSize;
                if (IsSkillHidden(rec) && !HasMark(mob, num, UserIndexOf(rec))) continue;   // скрытый необнаруживший
            }
            maxHate = hate; best = (unsigned short)num;
        }
        const LONG n = InterlockedIncrement(&g_condRedirect);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N23] навык-условие монстра %ld: скрытый игрок #%d не взят целью — %s %d (всего %ld)",
                      MobId(mob), pick, best >= 0 ? L"цель" : L"кандидата нет,", best, (long)n);
        return best;
    }

    // ── врезки ──────────────────────────────────────────────────────────────
    // S1: вместо `cmp byte ptr [esi+7858h],1` (ebx = монстр, esi = запись цели). ZF=1 ⇔ потерять цель.
    __declspec(naked) void BattleGate()
    {
        __asm
        {
            cmp     byte ptr [esi + DEAD_FLAG], 1
            je      done                             // сток: потеря цели
            cmp     byte ptr [esi + HIDE_BYTE], 1
            je      hidden
            cmp     dword ptr [g_markCount], 0
            je      keep
            pushad
            push    ebx
            call    OnVisibleTarget
            add     esp, 4
            popad
        keep:
            test    esp, esp                         // ZF=0: цель остаётся
        done:
            ret
        hidden:
            pushad
            push    esi
            push    ebx
            call    OnHiddenTarget
            add     esp, 8
            cmp     eax, 1                           // ZF=1 ⇔ снять цель
            popad                                    // popad флаги не меняет
            ret
        }
    }

    // S2: вместо `mov word ptr [ebx+7A58h], dx` (ebx = монстр, esi = запись, dx = номер). Флаги test — для jne следом.
    __declspec(naked) void AcquireGateMove2()
    {
        __asm
        {
            mov     word ptr [ebx + MOB_TARGET], dx
            pushfd
            cmp     byte ptr [esi + HIDE_BYTE], 1
            jne     out2
            pushad
            movsx   eax, dx
            push    eax
            push    esi
            push    ebx
            call    OnAcquireHidden
            add     esp, 12
            popad
        out2:
            popfd
            ret
        }
    }

    // S3: вместо `mov word ptr [edi+7A58h], bx` (edi = монстр, esi = запись, bx = номер).
    __declspec(naked) void AcquireGateMove1()
    {
        __asm
        {
            mov     word ptr [edi + MOB_TARGET], bx
            pushfd
            cmp     byte ptr [esi + HIDE_BYTE], 1
            jne     out1
            pushad
            movsx   eax, bx
            push    eax
            push    esi
            push    edi
            call    OnAcquireHidden
            add     esp, 12
            popad
        out1:
            popfd
            ret
        }
    }

    // S4: вместо `mov word ptr [esi+91C5h], ax` (esi = монстр, ax = номер цели навыка).
    __declspec(naked) void SkillTargetGate()
    {
        __asm
        {
            pushfd
            cmp     byte ptr [esi + TGT_KIND], 1
            jne     write
            pushad
            movsx   eax, ax
            push    eax
            push    esi
            call    OnSkillTarget
            add     esp, 8
            mov     dword ptr [esp + 28], eax        // сохранённый eax кадра pushad
            popad
        write:
            mov     word ptr [esi + TGT_NUM], ax
            popfd
            ret
        }
    }

    // S6: вместо `mov word ptr [ebx+7A58h], di` (ebx = монстр, di = выбор, bp = текущая цель). −1 — на выход стока 0x4366B4.
    //     За площадкой флаги не читаются (0x436692 mov / movsx / mov … call); edi перечитывается там же.
    __declspec(naked) void SkillCondGate()
    {
        __asm
        {
            pushad
            movsx   eax, bp
            push    eax
            movsx   eax, di
            push    eax
            push    ebx
            call    OnSkillCondTarget
            add     esp, 12
            cmp     eax, -1
            je      skip
            mov     word ptr [ebx + MOB_TARGET], ax
            popad
            ret
        skip:
            popad
            push    eax
            mov     eax, dword ptr [g_condSkip]
            mov     dword ptr [esp + 4], eax         // адрес возврата → 0x4366B4
            pop     eax
            ret
        }
    }

    // S5: jmp из 0x42895C (eax = запись угрозы, ecx = её номер). Продолжение — цикл секторов 0x428895.
    __declspec(naked) void QuickHideHaterGate()
    {
        __asm
        {
            pushad
            pushfd
            push    ecx
            push    eax
            call    OnQuickHideHater
            add     esp, 8
            popfd
            popad
            jmp     dword ptr [g_quickCont]
        }
    }
}

PatchResult N23_SkillHideAggro()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
        return PatchResult::Disabled;

    const bool drop  = Config::GetBool(kSec, L"DropUndetected", true);   // S1 (+ S2/S3)
    const bool skill = Config::GetBool(kSec, L"SkillTarget",    true);   // S4 (+ S2/S3)
    const bool quick = Config::GetBool(kSec, L"QuickHideHate",  true);   // S5
    g_trace          = Config::GetBool(kSec, L"LogEvents",      true);

    // Сверяем ВСЕ площадки до первой записи: частичная установка хуже никакой.
    const Site all[] = { kSiteS1, kSiteS2, kSiteS3, kSiteS4, kSiteS5, kSiteS6 };
    if (!VerifyAllSites(kSec, all, ARRAYSIZE(all)))
        return PatchResult::Mismatch;

    if (!g_csReady) { InitializeCriticalSection(&g_cs); g_csReady = true; }

    // Отметки «обнаружил» читают S1 и S6: без них обнаруженный Hide Check скрытый тоже снимался бы — детекция оригинала
    // пропала бы. S4 отметок не читает (текущую цель не подменяет, прочих скрытых — всегда).
    if (drop)
    {
        if (!Hook::WriteCall(kSiteS2.va, &AcquireGateMove2, kSiteS2.len)) return PatchResult::Failed;
        if (!Hook::WriteCall(kSiteS3.va, &AcquireGateMove1, kSiteS3.len)) return PatchResult::Failed;
    }
    if (drop  && !Hook::WriteCall(kSiteS1.va, &BattleGate,         kSiteS1.len)) return PatchResult::Failed;
    if (drop  && !Hook::WriteCall(kSiteS6.va, &SkillCondGate,      kSiteS6.len)) return PatchResult::Failed;
    if (skill && !Hook::WriteCall(kSiteS4.va, &SkillTargetGate,    kSiteS4.len)) return PatchResult::Failed;
    if (quick && !Hook::WriteJmp (kSiteS5.va, &QuickHideHaterGate, kSiteS5.len)) return PatchResult::Failed;

    Log::Line(L"    скрытый навыком (112/186): необнаруженный снимается с цели %s, цель навыка монстра %s, "
              L"угроза при «Быстрой маскировке» %s",
              drop ? L"ВКЛ" : L"выкл", skill ? L"ВКЛ" : L"выкл", quick ? L"ВКЛ" : L"выкл");
    return PatchResult::Applied;
}
