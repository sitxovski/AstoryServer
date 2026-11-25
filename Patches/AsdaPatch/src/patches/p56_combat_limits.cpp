// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P56 — ★ СЕРВЕРНЫЕ ЛИМИТЫ БОЯ, сторона GameServer (мера 9 плана античита, волна В5, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Задача владельца дословно: «частота атак и навыков по серверному времени
//  (4026/4028/5256), дальность по серверным позициям, откат и мана навыков».
//  Отчёт: `Reports/anticheat/wave_A5_combat.md`; документ: `AstoryServer/Docs/GameServer/combat-limits-p56.md`.
//
//  ── ЧТО СЕРВЕР УЖЕ ДЕЛАЕТ (сток, не дублируем) ──
//  • Частота ударов 4026/4028/4201/4203 и дальность до монстра/игрока считает NpcServer по СВОЕМУ
//    GetTickCount и СВОИМ позициям (`Process_AttackedToMonster` NS:63102-63108, PvP NS:63537-63545):
//    интервал = WORD игрок+65172 из таблицы оружия/темпа (sub_401900) с учётом баффов, допуск +100 мс,
//    нарушение → счётчик, >30 → 8905 (кик тип 6). 16-битное сравнение чинит N01, журнал — N13.
//    Дальность: `sub_42C4F0` (PvE: 3 + байт дальности моба; PvP: 4 клетки) → лог + отказ 8204 код 1.
//    Эти отказы зеркалит в журнал N14 (AddonNPC). Здесь — ВТОРАЯ линия на GameServer.
//  • Откат навыка: `sub_47BE60` (WORD CUser gap_552E[10·skill+2745] ≤ 0), MP/класс/оружие `sub_46F600`,
//    замок каста `sub_47B7E0` — всё проверяется на заявке 5256, но ЗАПИСЫВАЕТСЯ только по ответу
//    NpcServer 8206 (`sub_470DB0`). Между заявкой и ответом второй 5256 проходит все проверки (Б-02).
//
//  ── ЧТО ДЕЛАЕТ P56 (все площадки — замена цели `call rel32`, как у P53; ни одного трамплина) ──
//  A. Б-01 ПОВТОРЫ ЦЕЛЕЙ (5256 @0x46FDCF, 6158 @0x48E8DF — вызов `sub_52BFF0` сразу ПОСЛЕ цикла
//     копирования записей целей): пара (тип, индекс) встречается дважды → журнал (вид 6) и, при
//     DedupeRefuse=1, отказ ШТАТНЫМ путём этого же вызова (eax=1 → 5257/6159 код 0). Честный клиент
//     дублей не шлёт (порт: `PickEntityRenderIdsInGameBox` исключает первичную цель; эталон — список
//     из одного прохода по сетке).
//  B. Б-02 ЗАЯВКА «В ПУТИ» (5256): при отправке 8205 (@0x470CCC) ставим у userNum отметку
//     {skill, тик}; снимаем при ответе 8206 (диспетчер @0x43164E → `sub_470DB0`) или по таймауту
//     InFlightTimeoutMs. Повторная 5256, пока отметка жива, — вызов `sub_47BE60` (@0x470097) возвращает
//     0 → ШТАТНЫЙ код 7 «откат» (Mode=1) либо только журнал (вид 7, Mode=0). Этим же закрыта «мана»:
//     вторая заявка не списывает MP дважды до ответа. Порт после каждой заявки ставит состояние 25 и
//     вторую не шлёт до 5257/5270 — честному клиенту отказ не грозит.
//  C. ЧАСТОТА по серверному времени (GetTickCount GameServer): 4026 @0x4C4B48, 4028 @0x4C5278 —
//     интервал между ударами одного userNum меньше AttackFloorMs → журнал (вид 8); 4201 @0x554DCC,
//     4203 @0x555473 — PvpFloorMs → журнал (вид 9). Mode=1 → отказ штатным путём `sub_52BFF0`
//     (4027/4202 код 0). Порог — грубый «пол» (порт: клип удара ≥ ~0,6 с при максимальном темпе;
//     точный интервал по оружию знает только NpcServer).
//  D. ДАЛЬНОСТЬ по серверным клеткам CUser (WORD +0x54E6 x, +0x54E8 y — те же поля, что сток даёт
//     `sub_41A010`): 4201/4203 — до цели дальше PvpMaxCells → журнал (вид 10), Mode=1 → отказ код 0;
//     5256/6158 — цель-игрок (тип 1, не сам) дальше SkillMaxCells → журнал (вид 11), без отказа
//     (сток NpcServer режет по цели кодом 10 поштучно, общего отказа заявки у него нет).
//  Монстров GameServer по индексу не адресует (их позиции — у NpcServer), дальность 4026/4028 — N14.
//
//  ── КАДРЫ (все смещения сверены дизасмом живого e7b4ac38 = сток для этих мест, verify_p56.py) ──
//  5256 RecvChar_SkillUse@0x46F900: userNum [ebp+8] WORD; записи целей ebp-0x25C по 29 б ([0] тип,
//    [1..2] индекс), iRecvCount [ebp-0x10], CUser [ebp-0x5B4], skill [ebp-0x59C] WORD.
//  6158 RecvChar_SoulGuarderSkillUse@0x48E4F0: записи ebp-0x250, iRecvCount [ebp-4], CUser [ebp-0x570],
//    skill [ebp-0x560] WORD.
//  4201 Recv_User_AttackToPlayer@0x554CA0: цель WORD [ebp-0x2C], CUser [ebp-0x6C].
//  4203 Recv_User_AttackedToPlayer@0x555340: цель WORD [ebp-0x24], CUser [ebp-0x60].
//  4026 @0x4C49F0 / 4028 @0x4C5120: userNum [ebp+8]; ecx у вызова = CUserManager.
//  Вызовы: `sub_52BFF0` thiscall(mgr, userNum, opcode) ret 8, al≠0 = отказ; `sub_47BE60`
//    thiscall(skillMgr, userNum, skill) ret 8, eax=0 = «на откате»; `sub_5646C0` ret 0x14;
//    `sub_470DB0` thiscall(skillMgr, userNum, pkt) ret 8.
//  С P01…P54 не пересекается (P42 C1 стоит на входе 0x556DB0, не на наших вызовах; P53 — другие VA).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P56_CombatLimits";

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;

    constexpr int kOffName      = 0x178;    // CUser: имя персонажа (cp1251)
    constexpr int kOffUserNumW  = 0x0C;     // CUser: WORD userNum
    constexpr int kOffUserIndex = 0x174;    // CUser: UserIndex
    constexpr int kOffSlot      = 0x18C;    // CUser: BYTE слот персонажа
    constexpr int kOffCellX     = 0x54E6;   // CUser: WORD клетка X (сток: аргумент sub_41A010)
    constexpr int kOffCellY     = 0x54E8;   // CUser: WORD клетка Y
    constexpr int kUsers        = 0x226;    // слотов userNum (sub_5328F0: < 0x226)
    constexpr int kRecLen       = 29;       // запись цели навыка
    constexpr int kMaxRecs      = 20;

    // Виды площадок (константа в стабе → смысл).
    enum SiteKind : int { kSkill5256 = 1, kSkill6158, kAttack4026, kAttack4028, kPvp4201, kPvp4203 };

    // ── настройки ───────────────────────────────────────────────────────────
    int  g_mode          = 0;       // 0 журнал / 1 отказ
    bool g_dedupeRefuse  = true;    // повтор цели → отказ (штатный код) даже при Mode=0
    int  g_inflightMs    = 2000;    // таймаут отметки «в пути»
    int  g_attackFloorMs = 200;     // пол интервала 4026/4028 (0 = выкл)
    int  g_pvpFloorMs    = 200;     // пол интервала 4201/4203 (0 = выкл)
    int  g_pvpMaxCells   = 6;       // дальность PvP по клеткам (0 = выкл); сток NpcServer — 4
    int  g_skillMaxCells = 20;      // дальность цели-игрока у навыка (0 = выкл); только журнал

    // ── состояние на userNum ────────────────────────────────────────────────
    struct UserState
    {
        DWORD lastAttack;     // тик последнего принятого 4026/4028
        DWORD lastPvp;        // тик последнего принятого 4201/4203
        DWORD inflightTick;   // тик отправки 8205
        WORD  inflightSkill;  // 0 — отметки нет
        WORD  pad;
        DWORD guardTick;      // ★ В5b: тик отправки 8940 (страж, 6158)
        WORD  guardSkill;     // ★ В5b: код навыка стража «в пути» (0 — отметки нет)
        WORD  pad2;
        LONG  violations;     // счётчик нарушений (в журнал v[2])
    };
    UserState g_st[kUsers] = {};

    // Счётчики для PatchLog/стенда.
    volatile LONG g_hits = 0, g_journal = 0, g_refused = 0;

    bool ValidUser(int n) { return n >= 0 && n < kUsers; }

    // Заполнить общие поля из CUser (под SEH — указатель приходит из кадра сервера).
    void FromUser(AcJournal::Event& e, const BYTE* user, int userNum)
    {
        e.userNum = (short)userNum;
        if (!user) { return; }
        __try
        {
            e.userIndex = *(const int*)(user + kOffUserIndex);
            e.charSlot  = user[kOffSlot];
            AcJournal::CopyName(e, user + kOffName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (e.userNum >= 0) { e.ip = P47_PeerIpv4(e.userNum); }
    }

    void Journal(BYTE kind, int opcode, const BYTE* user, int userNum, DWORD tickPrev, DWORD tickNow,
                 int v1, int v3, int v4, const char* text = nullptr)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, kind);
        e.opcode = opcode;
        if (tickPrev) { e.w[0] = tickPrev; }
        if (tickNow)  { e.w[1] = tickNow; }
        e.v[1] = v1; e.v[3] = v3; e.v[4] = v4;
        if (ValidUser(userNum)) { e.v[2] = g_st[userNum].violations; }
        if (text) { AcJournal::CopyText(e, text); }
        FromUser(e, user, userNum);
        InterlockedIncrement(&g_journal);
        AcJournal::Push(e);
    }

    // Клетка CUser; false — указатель пуст/недоступен.
    bool Cell(const BYTE* user, int* x, int* y)
    {
        if (!user) { return false; }
        __try
        {
            *x = *(const short*)(user + kOffCellX);
            *y = *(const short*)(user + kOffCellY);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    int CellDist(int ax, int ay, int bx, int by)
    {
        const int dx = ax > bx ? ax - bx : bx - ax;
        const int dy = ay > by ? ay - by : by - ay;
        return dx > dy ? dx : dy;
    }

    // Пол интервала: true — нарушение (интервал от последнего ПРИНЯТОГО меньше порога).
    bool FloorCheck(DWORD* last, int floorMs, DWORD now, int* intervalOut)
    {
        if (floorMs <= 0) { *last = now; return false; }
        const DWORD prev = *last;
        if (prev != 0)
        {
            const DWORD d = now - prev;
            *intervalOut = (int)d;
            if (d < (DWORD)floorMs) { return true; }
        }
        *last = now;
        return false;
    }
}

// ── C-обработчики стабов (все __stdcall; вызываются из naked-стабов) ─────────
// Площадки sub_52BFF0: kind — вид, mgr — ecx вызывающего (CUserManager), ebp — кадр обработчика,
// st — [0] адрес возврата, [1] userNum, [2] опкод. Возврат: 0 — пропуск (дальше сток), 1 — отказ.
extern "C" int __stdcall P56_Gate(int kind, void* mgr, BYTE* ebp, const DWORD* st)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        const int userNum = (short)st[1];
        if (!ValidUser(userNum)) { return 0; }
        UserState& S = g_st[userNum];
        const DWORD now = GetTickCount();
        bool refuse = false;
        switch (kind)
        {
        case kSkill5256:
        case kSkill6158:
        {
            const bool g = kind == kSkill5256;
            const BYTE* recs  = ebp - (g ? 0x25C : 0x250);
            int         count = *(const int*)(ebp - (g ? 0x10 : 0x4));
            const BYTE* user  = *(BYTE* const*)(ebp - (g ? 0x5B4 : 0x570));
            const int   skill = *(const short*)(ebp - (g ? 0x59C : 0x560));
            const int   op    = g ? 5256 : 6158;
            if (count < 0) { count = 0; }
            if (count > kMaxRecs) { count = kMaxRecs; }
            // A. повторы пары (тип, индекс)
            int dups = 0, firstDup = -1;
            for (int i = 1; i < count; ++i)
            {
                const BYTE  ti = recs[i * kRecLen];
                const short xi = *(const short*)(recs + i * kRecLen + 1);
                for (int j = 0; j < i; ++j)
                {
                    if (recs[j * kRecLen] == ti && *(const short*)(recs + j * kRecLen + 1) == xi)
                    {
                        ++dups;
                        if (firstDup < 0) { firstDup = i; }
                        break;
                    }
                }
            }
            if (dups)
            {
                InterlockedIncrement(&S.violations);
                Journal(6, op, user, userNum, 0, now, firstDup, count, skill, "повтор (тип, индекс) в списке целей");
                if (g_dedupeRefuse) { refuse = true; }
            }
            // D. дальность до целей-игроков по серверным клеткам (только журнал)
            if (g_skillMaxCells > 0 && user && mgr)
            {
                int ax, ay;
                if (Cell(user, &ax, &ay))
                {
                    for (int i = 0; i < count; ++i)
                    {
                        if (recs[i * kRecLen] != 1) { continue; }
                        const int tgt = *(const short*)(recs + i * kRecLen + 1);
                        if (tgt == userNum || !ValidUser(tgt)) { continue; }
                        const BYTE* tu = pGetUser(mgr, nullptr, (short)tgt);
                        int bx, by;
                        if (!Cell(tu, &bx, &by)) { continue; }
                        const int d = CellDist(ax, ay, bx, by);
                        if (d > g_skillMaxCells)
                        {
                            InterlockedIncrement(&S.violations);
                            Journal(11, op, user, userNum, 0, now, d, g_skillMaxCells, skill, nullptr);
                            break;   // одной строки на заявку достаточно
                        }
                    }
                }
            }
            break;
        }
        case kAttack4026:
        case kAttack4028:
        {
            int interval = 0;
            const DWORD prev = S.lastAttack;
            if (FloorCheck(&S.lastAttack, g_attackFloorMs, now, &interval))
            {
                InterlockedIncrement(&S.violations);
                const BYTE* user = mgr ? pGetUser(mgr, nullptr, (short)userNum) : nullptr;
                Journal(8, kind == kAttack4026 ? 4026 : 4028, user, userNum, prev, now, interval, g_attackFloorMs, 0, nullptr);
                if (g_mode == 1) { refuse = true; }
                else { S.lastAttack = now; }     // режим журнала: удар принят стоком — считаем его последним
            }
            break;
        }
        case kPvp4201:
        case kPvp4203:
        {
            const bool a = kind == kPvp4201;
            const int   op   = a ? 4201 : 4203;
            const int   tgt  = *(const short*)(ebp - (a ? 0x2C : 0x24));
            const BYTE* user = *(BYTE* const*)(ebp - (a ? 0x6C : 0x60));
            int interval = 0;
            const DWORD prev = S.lastPvp;
            if (FloorCheck(&S.lastPvp, g_pvpFloorMs, now, &interval))
            {
                InterlockedIncrement(&S.violations);
                Journal(9, op, user, userNum, prev, now, interval, g_pvpFloorMs, tgt, nullptr);
                if (g_mode == 1) { refuse = true; }
                else { S.lastPvp = now; }
            }
            if (g_pvpMaxCells > 0 && mgr && ValidUser(tgt) && tgt != userNum)
            {
                int ax, ay, bx, by;
                const BYTE* tu = pGetUser(mgr, nullptr, (short)tgt);
                if (Cell(user, &ax, &ay) && Cell(tu, &bx, &by))
                {
                    const int d = CellDist(ax, ay, bx, by);
                    if (d > g_pvpMaxCells)
                    {
                        InterlockedIncrement(&S.violations);
                        Journal(10, op, user, userNum, 0, now, d, g_pvpMaxCells, tgt, nullptr);
                        if (g_mode == 1) { refuse = true; }
                    }
                }
            }
            break;
        }
        default:
            return 0;
        }
        if (refuse) { InterlockedIncrement(&g_refused); return 1; }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;   // любая ошибка разбора — пропуск в сток, лимит не должен мешать серверу
    }
}

// Площадка sub_47BE60 (откат) в 5256: [1] userNum, [2] skill. Возврат 1 — «считать на откате» (код 7).
extern "C" int __stdcall P56_Cool(const DWORD* st)
{
    __try
    {
        const int userNum = (short)st[1];
        const int skill   = (short)st[2];
        if (!ValidUser(userNum)) { return 0; }
        UserState& S = g_st[userNum];
        if (S.inflightSkill == 0) { return 0; }
        const DWORD now = GetTickCount();
        const DWORD age = now - S.inflightTick;
        if (age >= (DWORD)g_inflightMs) { S.inflightSkill = 0; return 0; }   // ответа не было — отметка истекла
        InterlockedIncrement(&S.violations);
        Journal(7, 5256, nullptr, userNum, S.inflightTick, now, (int)age, S.inflightSkill, skill, "заявка до ответа 8206");
        if (g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Площадка отправки 8205 (5256): кадр обработчика → отметка «в пути».
extern "C" void __stdcall P56_Mark8205(BYTE* ebp)
{
    __try
    {
        const int userNum = *(const short*)(ebp + 8);
        const int skill   = *(const short*)(ebp - 0x59C);
        if (!ValidUser(userNum)) { return; }
        g_st[userNum].inflightSkill = (WORD)(skill ? skill : 1);
        g_st[userNum].inflightTick  = GetTickCount();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Площадка диспетчера 8206 → sub_470DB0: снять отметку.
extern "C" void __stdcall P56_Clear8206(int userNum)
{
    userNum = (short)userNum;
    if (ValidUser(userNum)) { g_st[userNum].inflightSkill = 0; }
}

// ★ В5b (остаток меры 9, 2026-10-12) — Б-02 ДЛЯ СТРАЖА (6158). Разбор (отчёт wave_A5b_combat_rest.md): GameServer
//   `RecvChar_SkillUse_0` @0x48E4F0 проверяет на заявке «страж не в касте» (`sub_48B850`: WORD CUser gap_3E95C+2790 ≤ 0,
//   иначе код 5) и ресурс стража (`sub_48B780`: gap_3E95C[2785+слот] ≥ 5, иначе код 0), шлёт 8940 (@0x48F1E9);
//   NpcServer (`SoulGuarderSkillStart` sub_414E10) отвечает 8941 (0x22ED) → диспетчер `ConnectSocketMsgProcess`
//   @0x433BAC → `sub_48F2B0`, и ТОЛЬКО там ресурс списывается (`sub_48B570(…, 5)`), каст ставится (`sub_48B9A0`:
//   +2790 = длительность). Между 8940 и 8941 вторая 6158 проходит все проверки — та же дыра, что у 5256.
//   Закрытие: отметка {skill, тик} при отправке 8940, снятие при 8941 (или по InFlightTimeoutMs); повторная 6158
//   при живой отметке → обёртка `sub_48B850` возвращает 0 → сток ставит ШТАТНЫЙ код 5 («страж занят»).
//   Отметка стража отдельная от отметки 5256: заявки независимы и на сервере.
// Площадка sub_48B850 (6158): [1] userNum; ecx — CSoulGuarderManager. Возврат 1 — «занят» (код 5).
extern "C" int __stdcall P56_GuardBusy(const DWORD* st)
{
    __try
    {
        const int userNum = (short)st[1];
        if (!ValidUser(userNum)) { return 0; }
        UserState& S = g_st[userNum];
        if (S.guardSkill == 0) { return 0; }
        const DWORD now = GetTickCount();
        const DWORD age = now - S.guardTick;
        if (age >= (DWORD)g_inflightMs) { S.guardSkill = 0; return 0; }   // ответа 8941 не было — отметка истекла
        InterlockedIncrement(&S.violations);
        Journal(23, 6158, nullptr, userNum, S.guardTick, now, (int)age, S.guardSkill, 0, "заявка до ответа 8941");
        if (g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Площадка отправки 8940 (6158): кадр обработчика → отметка «в пути» стража ([ebp+8] userNum, [ebp-0x560] навык).
extern "C" void __stdcall P56_Mark8940(BYTE* ebp)
{
    __try
    {
        const int userNum = *(const short*)(ebp + 8);
        const int skill   = *(const short*)(ebp - 0x560);
        if (!ValidUser(userNum)) { return; }
        g_st[userNum].guardSkill = (WORD)(skill ? skill : 1);
        g_st[userNum].guardTick  = GetTickCount();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Площадка диспетчера 8941 → sub_48F2B0: снять отметку стража.
extern "C" void __stdcall P56_Clear8941(int userNum)
{
    userNum = (short)userNum;
    if (ValidUser(userNum)) { g_st[userNum].guardSkill = 0; }
}

// Для стенда/соседей: прочитать состояние.
extern "C" int __stdcall P56_InflightSkill(int userNum) { return ValidUser(userNum) ? g_st[userNum].inflightSkill : -1; }
extern "C" int __stdcall P56_InflightGuard(int userNum) { return ValidUser(userNum) ? g_st[userNum].guardSkill : -1; }

namespace
{
    DWORD g_pGate  = 0x0052BFF0;   // стоковая цель площадок sub_52BFF0
    DWORD g_pCool  = 0x0047BE60;   // sub_47BE60
    DWORD g_pSend  = 0x005646C0;   // sub_5646C0 (8205)
    DWORD g_pResp  = 0x00470DB0;   // sub_470DB0 (8206)
    DWORD g_pBusy  = 0x0048B850;   // ★ В5b: sub_48B850 (страж не в касте; thiscall, ret 4)
    DWORD g_pResp2 = 0x0048F2B0;   // ★ В5b: sub_48F2B0 (8941)

    // Общий хвост площадок sub_52BFF0. На входе: [esp] вид, [esp+4] адрес возврата, [esp+8] userNum,
    // [esp+12] опкод; ecx — CUserManager; ebp — кадр обработчика. Стоковый вызов: thiscall, ret 8.
    __declspec(naked) void GateTail()
    {
        __asm
        {
            pushad                                 // +32
            lea   eax, [esp+36]                    // st: адрес возврата и аргументы
            push  eax
            push  ebp
            push  ecx
            push  dword ptr [esp+44]               // вид
            call  P56_Gate                         // __stdcall, 16 б
            test  eax, eax
            jnz   refuse
            popad
            add   esp, 4                           // снять вид
            jmp   dword ptr [g_pGate]              // дальше — сток с теми же аргументами
        refuse:
            popad
            add   esp, 4
            mov   eax, 1                           // al ≠ 0 — отказ штатным путём вызывающего
            ret   8
        }
    }
    __declspec(naked) void St_Skill5256() { __asm { push kSkill5256 } __asm { jmp GateTail } }
    __declspec(naked) void St_Skill6158() { __asm { push kSkill6158 } __asm { jmp GateTail } }
    __declspec(naked) void St_Attack4026() { __asm { push kAttack4026 } __asm { jmp GateTail } }
    __declspec(naked) void St_Attack4028() { __asm { push kAttack4028 } __asm { jmp GateTail } }
    __declspec(naked) void St_Pvp4201() { __asm { push kPvp4201 } __asm { jmp GateTail } }
    __declspec(naked) void St_Pvp4203() { __asm { push kPvp4203 } __asm { jmp GateTail } }

    // Площадка sub_47BE60: [esp] адрес возврата, [esp+4] userNum, [esp+8] skill; ecx — CSkillManager.
    __declspec(naked) void St_Cool()
    {
        __asm
        {
            pushad
            lea   eax, [esp+32]
            push  eax
            call  P56_Cool                         // __stdcall, 4 б
            test  eax, eax
            jnz   refuse
            popad
            jmp   dword ptr [g_pCool]
        refuse:
            popad
            xor   eax, eax                         // 0 — «на откате» → сток ставит код 7
            ret   8
        }
    }

    // Площадка отправки 8205: только отметка, дальше сток.
    __declspec(naked) void St_Send8205()
    {
        __asm
        {
            pushad
            push  ebp
            call  P56_Mark8205                     // __stdcall, 4 б
            popad
            jmp   dword ptr [g_pSend]
        }
    }

    // Площадка 8206 (диспетчер → sub_470DB0): [esp+4] userNum.
    __declspec(naked) void St_Resp8206()
    {
        __asm
        {
            pushad
            push  dword ptr [esp+36]
            call  P56_Clear8206                    // __stdcall, 4 б
            popad
            jmp   dword ptr [g_pResp]
        }
    }

    // ★ В5b. Площадка sub_48B850 (6158): [esp] адрес возврата, [esp+4] userNum; ecx — CSoulGuarderManager; ret 4.
    __declspec(naked) void St_GuardBusy()
    {
        __asm
        {
            pushad
            lea   eax, [esp+32]
            push  eax
            call  P56_GuardBusy                    // __stdcall, 4 б
            test  eax, eax
            jnz   refuse
            popad
            jmp   dword ptr [g_pBusy]
        refuse:
            popad
            xor   eax, eax                         // 0 — «страж занят» → сток ставит код 5
            ret   4
        }
    }
    // Площадка отправки 8940 (6158): только отметка стража, дальше сток sub_5646C0.
    __declspec(naked) void St_Send8940()
    {
        __asm
        {
            pushad
            push  ebp
            call  P56_Mark8940                     // __stdcall, 4 б
            popad
            jmp   dword ptr [g_pSend]
        }
    }
    // Площадка 8941 (диспетчер → sub_48F2B0): [esp+4] userNum.
    __declspec(naked) void St_Resp8941()
    {
        __asm
        {
            pushad
            push  dword ptr [esp+36]
            call  P56_Clear8941                    // __stdcall, 4 б
            popad
            jmp   dword ptr [g_pResp2]
        }
    }

    struct SiteDef { DWORD va; DWORD target; void* stub; const wchar_t* what; };
    const SiteDef kSites[] =
    {
        { 0x0046FDCF, 0x0052BFF0, (void*)&St_Skill5256,  L"5256 после цикла целей (повторы/дальность)" },
        { 0x00470097, 0x0047BE60, (void*)&St_Cool,       L"5256 проверка отката (заявка в пути)" },
        { 0x00470CCC, 0x005646C0, (void*)&St_Send8205,   L"5256 отправка 8205 (отметка в пути)" },
        { 0x0043164E, 0x00470DB0, (void*)&St_Resp8206,   L"диспетчер 8206 (снятие отметки)" },
        { 0x0048E8DF, 0x0052BFF0, (void*)&St_Skill6158,  L"6158 после цикла целей (повторы/дальность)" },
        { 0x004C4B48, 0x0052BFF0, (void*)&St_Attack4026, L"4026 пол интервала" },
        { 0x004C5278, 0x0052BFF0, (void*)&St_Attack4028, L"4028 пол интервала" },
        { 0x00554DCC, 0x0052BFF0, (void*)&St_Pvp4201,    L"4201 пол интервала + дальность" },
        { 0x00555473, 0x0052BFF0, (void*)&St_Pvp4203,    L"4203 пол интервала + дальность" },
        // ★ В5b (остаток меры 9): страж 6158 — заявка «в пути» 8940→8941.
        { 0x0048EA99, 0x0048B850, (void*)&St_GuardBusy,  L"6158 проверка «страж не в касте» (заявка в пути → код 5)" },
        { 0x0048F1E9, 0x005646C0, (void*)&St_Send8940,   L"6158 отправка 8940 (отметка в пути стража)" },
        { 0x00433BAC, 0x0048F2B0, (void*)&St_Resp8941,   L"диспетчер 8941 (снятие отметки стража)" },
    };

    // Соседи: байты, на которые опираются смещения кадров (сверяются, но не меняются).
    struct Neighbour { DWORD va; const BYTE* bytes; SIZE_T len; const wchar_t* what; };
    const BYTE kN5256Cnt[]  = { 0x83,0x7D,0xF0,0x14 };                                   // cmp [ebp-0x10],0x14
    const BYTE kN5256Rec[]  = { 0x66,0x8B,0x8C,0x05,0xA5,0xFD,0xFF,0xFF };               // mov cx,[ebp+eax-0x25B]
    const BYTE kN5256User[] = { 0x8B,0x85,0x4C,0xFA,0xFF,0xFF,0x66,0x8B,0x88,0xE8,0x54,0x00,0x00 }; // [ebp-0x5B4]→+0x54E8
    const BYTE kN5256Cool[] = { 0x85,0xC0,0x75,0x0C,0xC6,0x85,0x78,0xFD,0xFF,0xFF,0x07 }; // test eax; jne; mov byte [ebp-0x288],7
    const BYTE kN6158Cnt[]  = { 0x3B,0x55,0xFC,0x0F,0x8D };                              // cmp edx,[ebp-4]; jge
    const BYTE kN6158Rec[]  = { 0x0F,0xB6,0x84,0x15,0xB0,0xFD,0xFF,0xFF };               // movzx eax,[ebp+edx-0x250]
    const BYTE kN6158User[] = { 0x8B,0x85,0x90,0xFA,0xFF,0xFF,0x66,0x8B,0x88,0xE6,0x54,0x00,0x00 }; // [ebp-0x570]→+0x54E6
    const BYTE kN4201Tgt[]  = { 0x66,0x8B,0x4D,0xD4,0x51 };                              // mov cx,[ebp-0x2C]; push ecx
    const BYTE kN4201User[] = { 0x8B,0x55,0x94,0x66,0x8B,0x82,0xE6,0x54,0x00,0x00 };     // [ebp-0x6C]→+0x54E6
    const BYTE kN4203Tgt[]  = { 0x66,0x8B,0x55,0xDC,0x52 };                              // mov dx,[ebp-0x24]; push edx
    const BYTE kN4203User[] = { 0x8B,0x55,0xA0,0x66,0x8B,0x82,0xE6,0x54,0x00,0x00 };     // [ebp-0x60]→+0x54E6
    const BYTE kN8206Arg[]  = { 0x66,0x8B,0x4D,0xF8,0x51 };                              // mov cx,[ebp-8]; push ecx
    const BYTE kN6158Busy[] = { 0x66,0x8B,0x4D,0x08,0x51,0x8B,0x8D,0x6C,0xFA,0xFF,0xFF };  // ★ В5b: mov cx,[ebp+8]; push ecx; mov ecx,[ebp-0x594]
    const BYTE kN6158Code5[]= { 0x85,0xC0,0x75,0x11,0xC6,0x85,0x88,0xFD,0xFF,0xFF,0x05 };  // test eax; jne; mov byte [ebp-0x288],5
    const BYTE kN6158Op[]   = { 0x68,0xEC,0x22,0x00,0x00,0xB9,0x38,0x05,0x7E,0x00 };      // push 8940; mov ecx,0x7E0538
    const BYTE kN6158Skill[]= { 0x0F,0xBF,0x95,0xA0,0xFA,0xFF,0xFF,0x81,0xEA,0xB1,0x04,0x00,0x00 }; // movsx edx,[ebp-0x560]; sub edx,1201
    const BYTE kN8941Arg[]  = { 0x66,0x8B,0x55,0xF8,0x52 };                              // mov dx,[ebp-8]; push edx
    const Neighbour kNeighbours[] =
    {
        { 0x0046FBB3, kN5256Cnt,  sizeof(kN5256Cnt),  L"5256 iRecvCount [ebp-0x10]" },
        { 0x0046FCB2, kN5256Rec,  sizeof(kN5256Rec),  L"5256 записи целей ebp-0x25C" },
        { 0x0046FE71, kN5256User, sizeof(kN5256User), L"5256 CUser [ebp-0x5B4], клетка +0x54E8" },
        { 0x0047009C, kN5256Cool, sizeof(kN5256Cool), L"5256 откат → код 7" },
        { 0x0048E797, kN6158Cnt,  sizeof(kN6158Cnt),  L"6158 iRecvCount [ebp-4]" },
        { 0x0048E7DC, kN6158Rec,  sizeof(kN6158Rec),  L"6158 записи целей ebp-0x250" },
        { 0x0048E937, kN6158User, sizeof(kN6158User), L"6158 CUser [ebp-0x570], клетка +0x54E6" },
        { 0x00554E0D, kN4201Tgt,  sizeof(kN4201Tgt),  L"4201 цель [ebp-0x2C]" },
        { 0x00554EAA, kN4201User, sizeof(kN4201User), L"4201 CUser [ebp-0x6C], клетка +0x54E6" },
        { 0x00555486, kN4203Tgt,  sizeof(kN4203Tgt),  L"4203 цель [ebp-0x24]" },
        { 0x005555ED, kN4203User, sizeof(kN4203User), L"4203 CUser [ebp-0x60], клетка +0x54E6" },
        { 0x0043163D, kN8206Arg,  sizeof(kN8206Arg),  L"8206 userNum [ebp-8]" },
        { 0x0048EA8E, kN6158Busy, sizeof(kN6158Busy), L"6158 sub_48B850: userNum [ebp+8], this [ebp-0x594]" },
        { 0x0048EA9E, kN6158Code5,sizeof(kN6158Code5),L"6158 «страж занят» → код 5" },
        { 0x0048F1DF, kN6158Op,   sizeof(kN6158Op),   L"6158 push 8940 перед отправкой" },
        { 0x0048E878, kN6158Skill,sizeof(kN6158Skill),L"6158 код навыка [ebp-0x560]" },
        { 0x00433B98, kN8941Arg,  sizeof(kN8941Arg),  L"8941 userNum [ebp-8]" },
    };
}

PatchResult P56_CombatLimits()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode          = Config::GetInt(kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_dedupeRefuse  = Config::GetBool(kSec, L"DedupeRefuse", true);
    g_inflightMs    = Config::GetInt(kSec, L"InFlightTimeoutMs", 2000);
    g_attackFloorMs = Config::GetInt(kSec, L"AttackFloorMs", 200);
    g_pvpFloorMs    = Config::GetInt(kSec, L"PvpFloorMs", 200);
    g_pvpMaxCells   = Config::GetInt(kSec, L"PvpMaxCells", 6);
    g_skillMaxCells = Config::GetInt(kSec, L"SkillMaxCells", 20);
    if (g_inflightMs < 100) { g_inflightMs = 100; }
    if (g_inflightMs > 10000) { g_inflightMs = 10000; }

    // Площадки: ровно `E8 rel32` на стоковую цель + соседи (кадры).
    BYTE orig[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites) + ARRAYSIZE(kNeighbours)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        orig[i][0] = 0xE8;
        const int rel = (int)(kSites[i].target - (kSites[i].va + 5));
        memcpy(orig[i] + 1, &rel, 4);
        sites[i].va = kSites[i].va; sites[i].orig = orig[i]; sites[i].len = 5;
    }
    for (int i = 0; i < ARRAYSIZE(kNeighbours); ++i)
    {
        Site& s = sites[ARRAYSIZE(kSites) + i];
        s.va = kNeighbours[i].va; s.orig = kNeighbours[i].bytes; s.len = kNeighbours[i].len;
    }
    if (!VerifyAllSites(L"P56", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    memset(g_st, 0, sizeof(g_st));
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!Hook::WriteCall(kSites[i].va, kSites[i].stub, 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    P56: площадок %d (5256 ×3, 8206, 6158 ×3 + 8941, 4026, 4028, 4201, 4203); Mode=%d (%s); "
              L"DedupeRefuse=%d; InFlightTimeoutMs=%d; AttackFloorMs=%d; PvpFloorMs=%d; PvpMaxCells=%d; SkillMaxCells=%d",
              (int)ARRAYSIZE(kSites), g_mode, g_mode ? L"отказ штатными кодами" : L"только журнал",
              g_dedupeRefuse ? 1 : 0, g_inflightMs, g_attackFloorMs, g_pvpFloorMs, g_pvpMaxCells, g_skillMaxCells);
    return PatchResult::Applied;
}
