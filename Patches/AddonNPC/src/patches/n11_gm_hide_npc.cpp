// Copyright (c) 2026 @sitxovski (Discord)
// n11_gm_hide_npc.cpp — P39: СКРЫТЫЙ ОПЕРАТОР (GM hide) НЕВИДИМ ДЛЯ МОНСТРОВ.
//                     [ПОРТ/СЕРВЕР-ДОРАБОТКА] поверх замысла оригинала.
//
// КАК ЭТО УСТРОЕНО В ОРИГИНАЛЕ (реверс 27.09.2026, разбор: Reports/owner_0927/gm_hide_npc.md)
//   GameServer `Send_HideCommand@0x54E970` → `sub_4C6C50@0x4C6C50` шлёт на NpcServer
//   8115 (скрыть) / 8116 (показать), тело 7 б: [0]=1, [1..4]=UserIndex, [5..6]=номер игрока.
//   NpcServer: case 0x1FB3 → `CAi::Process_PlayerAddState@0x45A0C0`, case 0x1FB4 →
//   `Process_PlayerSubState@0x45A030`: `запись_игрока.состояние (+30292) |= / &= ~(1 << тело[0])`,
//   то есть бит 2 (значение 2). ★ Прежний вывод «обработчика 8115/8116 у NpcServer нет» —
//   ЛОЖНОЕ «нет»: case в декомпиле записан в шестнадцатеричном виде (0x1FB3/0x1FB4), поиск
//   шёл по десятичному.
//   ★ Бит 2 у ИГРОКА ставит ТОЛЬКО 8115: пакет входа 8101 кладёт в состояние 0/1 (байт +105,
//     «жив»), возрождение 4031 пишет 1, смерть 4030 — 0.
//   Боевой ИИ оригинала читает этот бит в двух местах — в обеих ветках поиска первого агрессора
//   (`sub_43E580` «ProcessAction_Move()2» и `sub_43F330` «ProcessAction_Move()1»): скрытого
//   монстр сам не выбирает. Третье чтение — отладочная трассировка `Process_UpdatePlayerPosition
//   sub_45B230` (ветка `UserIndex == word_47C068`, по умолчанию −1; на игру не влияет).
//   Всё остальное бит игнорирует. (Поправка по ревизии 27.09: было «ровно в двух местах».)
//
// ЧТО НЕ ДОДЕЛАНО В ОРИГИНАЛЕ (и что чинит каждая площадка)
//   A  0x447BA7  `OnBattle@0x447B30` проверяет цель только на «состояние == 0» — монстр, уже
//                бившийся со скрытым, продолжает гнаться и бить. Бит 2 → «цели нет»: штатная
//                ветка потери цели `sub_43FFC0(монстр, тик, 1)` (та же, что после смерти).
//   B  0x41AA44  `OnUserSearch@0x41A930` отдаёт ПЕРВОГО игрока с ненулевым состоянием, а бит
//                проверяет уже вызывающий — скрытый, стоящий первым, «заслонял» соседей: монстр
//                не агрился на видимого игрока рядом. Скрытый пропускается, поиск идёт дальше.
//   C  0x40C38C  `sub_40C200` — сбор жертв навыка монстра (площадь): скрытый не попадает.
//   D  0x40F41E  `sub_40EE50` — выбор цели навыка монстра по площади: скрытый не выбирается.
//   E  0x45A11F  8115: скрытый вычищается из списков угрозы ВСЕХ монстров своего AI-потока и
//                из своего обратного списка (+68168). Порядок: врезка стоит на `call AddState`,
//                C-часть исполняется ДО штатной AddState (хвостовой jmp), бит ставит уже она —
//                в пределах одного пакета очереди, на итог не влияет. (Поправка по ревизии.)
//                Новые записи угрозы к скрытому после чистки не появятся — это закрывает N12
//                (гейт в самом добавлении угрозы `sub_43D2C0`). Иначе навык монстра
//                с выбором «по угрозе» (типы 3/4/5 в `sub_40EE50`) и перебор угрозы при смене
//                цели (`sub_43D0D0`, `sub_4364E0`) снова находили бы его. Запоминаем
//                «запись игрока → UserIndex» для площадки G.
//   F  0x45A08E  8116: забыть отметку.
//   G  0x458D18  4031 (возрождение) писал состояние = 1 и стирал бит 2, хотя GameServer держит
//                оператора скрытым (`CUser+244795` остаётся 300 — его пишут только вход и сама
//                команда). Теперь скрытому пишется 1|2.
//
// ПОТОКИ
//   Все обработчики (8115/8116/4031) исполняются в AI-потоке карты игрока; там же крутятся
//   его монстры — чистка списков угрозы идёт без гонок (так же работает штатный
//   `Process_PlayerDead`). Массив записей игроков — общий на GameServer-system (не «свой у
//   потока»); запись игрока правит только поток его карты. Таблица отметок общая — под CS.
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЧЕРЕЗ #define (см. n03): C++-константа в
//   операнде `[reg + имя]` подставляет АДРЕС переменной. На этом 24.08.2026 упал живой NpcServer.
#include "Patches.h"
#include "../Config.h"
#include "../NpcApi.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* const kSec = L"N11_GmHideNpc";

    // ── площадки ────────────────────────────────────────────────────────────
    // cmp dword ptr [esi+7654h], 0
    const BYTE kOrigA[] = { 0x83, 0xBE, 0x54, 0x76, 0x00, 0x00, 0x00 };
    // cmp dword ptr [edi+7654h], 0
    const BYTE kOrigEdi[] = { 0x83, 0xBF, 0x54, 0x76, 0x00, 0x00, 0x00 };
    // call sub_42CC20 (AddState) из 0x45A11F
    const BYTE kOrigE[] = { 0xE8, 0xFC, 0x2A, 0xFD, 0xFF };
    // call sub_42CB70 (SubState) из 0x45A08E
    const BYTE kOrigF[] = { 0xE8, 0xDD, 0x2A, 0xFD, 0xFF };
    // mov dword ptr [esi+7654h], 1
    const BYTE kOrigG[] = { 0xC7, 0x86, 0x54, 0x76, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

    const Site kSiteA = { Npc::Hooks::kGmHideOnBattle,     kOrigA,   sizeof(kOrigA)   };
    const Site kSiteB = { Npc::Hooks::kGmHideUserSearch,   kOrigEdi, sizeof(kOrigEdi) };
    const Site kSiteC = { Npc::Hooks::kGmHideSkillVictims, kOrigEdi, sizeof(kOrigEdi) };
    const Site kSiteD = { Npc::Hooks::kGmHideSkillTarget,  kOrigEdi, sizeof(kOrigEdi) };
    const Site kSiteE = { Npc::Hooks::kGmHideAddState,     kOrigE,   sizeof(kOrigE)   };
    const Site kSiteF = { Npc::Hooks::kGmHideSubState,     kOrigF,   sizeof(kOrigF)   };
    const Site kSiteG = { Npc::Hooks::kGmHideRespawn,      kOrigG,   sizeof(kOrigG)   };

    // Смещения для встроенного ассемблера.
    #define USER_STATE 7654h     // +30292: биты состояния записи (у игрока: 1 = жив, 2 = скрыт)
    #define HIDE_BIT   2         // бит «скрытый оператор» (8115 с телом [0]=1 → 1 << 1)

    // Те же смещения для C-кода.
    constexpr DWORD kUserState   = 30292;      // биты состояния
    constexpr DWORD kUserIndex   = 30356;      // UserIndex учётки (у монстра — его номер)
    constexpr DWORD kUserBackRef = 68168;      // 8 × {i16 номер монстра, i32} — кто его бьёт
    constexpr DWORD kUserSize    = 68264;      // шаг массива игроков
    constexpr DWORD kMaxUsers    = 1000;       // 0x3E7 — предел номера у обработчиков
    constexpr DWORD kCtxUsers    = 0x0115475C; // поток: указатель на массив игроков
    constexpr DWORD kCtxMobCount = 0x02954858; // поток: число монстров
    constexpr DWORD kCtxMobs     = 8;          // поток: массив монстров начинается с +8
    constexpr DWORD kMobSize     = 37624;      // шаг массива монстров
    constexpr DWORD kMobHate     = 31352;      // 20 × 16 б: i16 игрок, +4, +8 угроза, +12 урон
    constexpr int   kHateSlots   = 20;
    constexpr int   kMobCountMax = 400;        // ёмкость массива монстров потока: конструктор
                                               // `sub_462E60` — 400 × 0x92F8 (ревизия МЕЛК-6)

    // Адреса настоящих AddState/SubState — в переменных, чтобы переход был косвенным.
    DWORD g_addState = Npc::Hooks::kPlayerAddStateFn;   // 0x42CC20
    DWORD g_subState = Npc::Hooks::kPlayerSubStateFn;   // 0x42CB70

    bool g_purge = true;    // площадка E: чистить списки угрозы (ключ PurgeHateOnHide)
    bool g_keep  = true;    // площадка G: беречь бит при возрождении (ключ KeepOnRespawn)
    bool g_trace = true;    // строка в PatchLog на каждое скрытие/показ (ключ LogEvents)

    // ── таблица «запись игрока → UserIndex» скрытых операторов ─────────────
    // Ключ — адрес записи, значение — UserIndex. Адрес стабилен: массив игроков выделяется
    // один раз на GameServer-system (`sub_421A50` → m_pPlayerInfoArray[system]) и ОБЩИЙ для
    // потоков этого system, а не «свой у потока» (поправка по ревизии 27.09).
    // Сверка UserIndex при чтении отсекает чужого игрока, занявшего ту же запись после выхода
    // скрытого оператора: у него другой UserIndex, отметка к нему не применится.
    // Переполнение (МЕЛК-7 ревизии): при нехватке места вытесняется сначала «протухшая»
    // (в записи уже другой UserIndex), затем самая СТАРАЯ отметка — новое скрытие
    // запоминается всегда; вытеснение пишется в журнал.
    struct HiddenRec { BYTE* rec; LONG ui; DWORD tick; };
    constexpr int kHiddenMax = 128;
    HiddenRec        g_hidden[kHiddenMax] = {};
    CRITICAL_SECTION g_cs;
    bool             g_csReady = false;

    LONG UserIndexOf(BYTE* rec) { return *(volatile LONG*)(rec + kUserIndex); }

    void Remember(BYTE* rec, LONG ui)
    {
        EnterCriticalSection(&g_cs);
        int freeSlot = -1, stale = -1, oldest = 0, slot = -1;
        const DWORD now = GetTickCount();
        for (int i = 0; i < kHiddenMax; ++i)
        {
            if (g_hidden[i].rec == rec) { slot = i; break; }
            if (!g_hidden[i].rec) { if (freeSlot < 0) freeSlot = i; continue; }
            if (stale < 0 && UserIndexOf(g_hidden[i].rec) != g_hidden[i].ui) stale = i;
            if (now - g_hidden[i].tick > now - g_hidden[oldest].tick) oldest = i;
        }
        bool evicted = false;
        LONG evictedUi = 0;
        if (slot < 0) slot = (freeSlot >= 0) ? freeSlot : stale;
        if (slot < 0) { slot = oldest; evicted = true; evictedUi = g_hidden[slot].ui; }
        g_hidden[slot].rec = rec; g_hidden[slot].ui = ui; g_hidden[slot].tick = now;
        LeaveCriticalSection(&g_cs);
        if (evicted)
            Log::Line(L"    [N11] таблица скрытых заполнена (%d) — вытеснена самая старая отметка "
                      L"(UserIndex %ld); если тот оператор ещё скрыт, после возрождения бит не "
                      L"восстановится до повторного скрытия", kHiddenMax, (long)evictedUi);
    }

    void Forget(BYTE* rec)
    {
        EnterCriticalSection(&g_cs);
        for (int i = 0; i < kHiddenMax; ++i)
            if (g_hidden[i].rec == rec) { g_hidden[i].rec = nullptr; g_hidden[i].ui = 0; g_hidden[i].tick = 0; }
        LeaveCriticalSection(&g_cs);
    }

    bool IsHidden(BYTE* rec)
    {
        bool hit = false;
        const LONG ui = UserIndexOf(rec);
        EnterCriticalSection(&g_cs);
        for (int i = 0; i < kHiddenMax; ++i)
            if (g_hidden[i].rec == rec && g_hidden[i].ui == ui) { hit = true; break; }
        LeaveCriticalSection(&g_cs);
        return hit;
    }

    // Номер игрока по адресу записи; -1 — адрес не из массива игроков (массив общий на
    // GameServer-system, указатель на него поток держит в +0x0115475C).
    int UserNumOf(BYTE* ctx, BYTE* rec)
    {
        BYTE* base = *(BYTE**)(ctx + kCtxUsers);
        if (!base || rec < base) return -1;
        const DWORD off = (DWORD)(rec - base);
        if (off % kUserSize) return -1;
        const DWORD n = off / kUserSize;
        return (n < kMaxUsers) ? (int)n : -1;
    }

    // Вычистить игрока из списков угрозы всех монстров потока и обнулить его обратный список.
    // Поля чистятся ровно как в штатном `sub_434A10` (InitializeBattleByPlayer):
    // номер = -1, +4/+8/+12 = 0. Текущую цель монстра (+31320) не трогаем — её снимает
    // площадка A штатной веткой потери цели на ближайшем тике боя.
    int PurgeHate(BYTE* ctx, BYTE* rec, int userNum)
    {
        int cleared = 0;
        const int count = *(int*)(ctx + kCtxMobCount);
        if (count > 0 && count <= kMobCountMax)
        {
            for (int m = 0; m < count; ++m)
            {
                BYTE* hate = ctx + kCtxMobs + (DWORD)m * kMobSize + kMobHate;
                for (int j = 0; j < kHateSlots; ++j, hate += 16)
                {
                    if (*(short*)hate != (short)userNum) continue;
                    *(short*)hate       = -1;
                    *(DWORD*)(hate + 4)  = 0;
                    *(DWORD*)(hate + 8)  = 0;
                    *(DWORD*)(hate + 12) = 0;
                    ++cleared;
                }
            }
        }
        BYTE* back = rec + kUserBackRef;
        for (int k = 0; k < 8; ++k, back += 8)
        {
            *(short*)back       = -1;
            *(DWORD*)(back + 4) = 0;
        }
        return cleared;
    }

    // ── C-часть врезок ──────────────────────────────────────────────────────
    void __cdecl OnAddState(DWORD bits, BYTE* rec, BYTE* ctx)
    {
        if (!(bits & HIDE_BIT) || !rec || !ctx) return;
        const LONG ui = UserIndexOf(rec);
        Remember(rec, ui);
        int n = -1, cleared = 0;
        if (g_purge)
        {
            n = UserNumOf(ctx, rec);
            if (n >= 0) cleared = PurgeHate(ctx, rec, n);
        }
        if (g_trace)
            Log::Line(L"    [N11] 8115 скрыт: игрок #%d, UserIndex %ld — вычищено записей угрозы: %d%s",
                      n, (long)ui, cleared, (g_purge && n < 0) ? L" (номер не определён, чистка пропущена)" : L"");
    }

    void __cdecl OnSubState(DWORD bits, BYTE* rec)
    {
        if (!(bits & HIDE_BIT) || !rec) return;
        Forget(rec);
        if (g_trace)
            Log::Line(L"    [N11] 8116 показан: UserIndex %ld", (long)UserIndexOf(rec));
    }

    void __cdecl OnRespawn(BYTE* rec)
    {
        DWORD v = 1;                                   // как в оригинале
        if (g_keep && IsHidden(rec)) v |= HIDE_BIT;    // скрытый остаётся скрытым
        *(DWORD*)(rec + kUserState) = v;
        if (g_trace && (v & HIDE_BIT))
            Log::Line(L"    [N11] 4031 возрождение скрытого: UserIndex %ld — бит сохранён",
                      (long)UserIndexOf(rec));
    }

    // ── врезки ──────────────────────────────────────────────────────────────
    // A: вместо `cmp [esi+7654h],0` перед `je потеря_цели`. ZF=1 ⇔ состояние 0 ИЛИ скрыт.
    __declspec(naked) void GateEsi()
    {
        __asm
        {
            push    eax
            mov     eax, dword ptr [esi + USER_STATE]
            test    eax, eax
            jz      done                 // 0 — как в оригинале
            test    al, HIDE_BIT
            jz      visible
            xor     eax, eax             // скрыт — ZF=1, «цели нет»
            jmp     done
        visible:
            test    eax, eax             // ненулевое — ZF=0
        done:
            pop     eax                  // pop флаги не меняет
            ret
        }
    }

    // B/C/D: то же для записи в edi (перебор игроков сектора; ZF=1 ⇔ пропустить).
    __declspec(naked) void GateEdi()
    {
        __asm
        {
            push    eax
            mov     eax, dword ptr [edi + USER_STATE]
            test    eax, eax
            jz      done
            test    al, HIDE_BIT
            jz      visible
            xor     eax, eax
            jmp     done
        visible:
            test    eax, eax
        done:
            pop     eax
            ret
        }
    }

    // E: вместо `call sub_42CC20` (edi = биты, esi = запись игрока, ecx = поток).
    __declspec(naked) void AddStateGate()
    {
        __asm
        {
            pushad
            pushfd
            push    ecx
            push    esi
            push    edi
            call    OnAddState
            add     esp, 12
            popfd
            popad
            jmp     dword ptr [g_addState]   // хвостовой переход: вернётся по адресу из call
        }
    }

    // F: вместо `call sub_42CB70` (eax = биты, esi = запись игрока).
    __declspec(naked) void SubStateGate()
    {
        __asm
        {
            pushad
            pushfd
            push    esi
            push    eax
            call    OnSubState
            add     esp, 8
            popfd
            popad
            jmp     dword ptr [g_subState]
        }
    }

    // G: вместо `mov dword ptr [esi+7654h], 1` (esi = запись игрока).
    __declspec(naked) void RespawnGate()
    {
        __asm
        {
            pushad
            pushfd
            push    esi
            call    OnRespawn
            add     esp, 4
            popfd
            popad
            ret
        }
    }
}

PatchResult N11_GmHideNpc()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
        return PatchResult::Disabled;

    const bool dropTarget = Config::GetBool(kSec, L"DropTarget",     true);  // A
    const bool searchSkip = Config::GetBool(kSec, L"SearchSkip",     true);  // B
    const bool skillSkip  = Config::GetBool(kSec, L"SkillSkip",      true);  // C, D
    g_purge               = Config::GetBool(kSec, L"PurgeHateOnHide", true); // E (чистка)
    g_keep                = Config::GetBool(kSec, L"KeepOnRespawn",  true);  // G
    g_trace               = Config::GetBool(kSec, L"LogEvents",      true);

    // Сверяем ВСЕ площадки до первой записи: частичная установка хуже никакой.
    const Site all[] = { kSiteA, kSiteB, kSiteC, kSiteD, kSiteE, kSiteF, kSiteG };
    if (!VerifyAllSites(kSec, all, ARRAYSIZE(all)))
        return PatchResult::Mismatch;

    if (!g_csReady) { InitializeCriticalSection(&g_cs); g_csReady = true; }

    // E/F ставятся всегда: без отметок G бессилен, а сама отметка ничего не меняет в поведении.
    if (!Hook::WriteCall(kSiteE.va, &AddStateGate, kSiteE.len)) return PatchResult::Failed;
    if (!Hook::WriteCall(kSiteF.va, &SubStateGate, kSiteF.len)) return PatchResult::Failed;
    if (dropTarget && !Hook::WriteCall(kSiteA.va, &GateEsi, kSiteA.len)) return PatchResult::Failed;
    if (searchSkip && !Hook::WriteCall(kSiteB.va, &GateEdi, kSiteB.len)) return PatchResult::Failed;
    if (skillSkip)
    {
        if (!Hook::WriteCall(kSiteC.va, &GateEdi, kSiteC.len)) return PatchResult::Failed;
        if (!Hook::WriteCall(kSiteD.va, &GateEdi, kSiteD.len)) return PatchResult::Failed;
    }
    if (g_keep && !Hook::WriteCall(kSiteG.va, &RespawnGate, kSiteG.len)) return PatchResult::Failed;

    Log::Line(L"    скрытый оператор (8115) невидим для монстров: снятие цели %s, поиск агрессора %s, "
              L"навыки монстров %s, чистка угрозы при скрытии %s, бит при возрождении %s",
              dropTarget ? L"ВКЛ" : L"выкл", searchSkip ? L"ВКЛ" : L"выкл",
              skillSkip ? L"ВКЛ" : L"выкл", g_purge ? L"ВКЛ" : L"выкл", g_keep ? L"ВКЛ" : L"выкл");
    return PatchResult::Applied;
}
