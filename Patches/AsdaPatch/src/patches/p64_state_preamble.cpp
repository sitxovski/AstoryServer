// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P64 — ★ ОБЩАЯ ПРЕАМБУЛА СОСТОЯНИЯ ПЕРСОНАЖА (античит, волна A7, механизм L4, приоритет A8, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] План `Reports/anticheat/00_PLAN.md` §8.2 A8 / L4; находки
//  `02_parts/economy2_handlers.md` (строка «одна общая преамбула в DLL по образцу P33_PreambleGate»),
//  `02_parts/combat_skills.md` Б-03, `02_parts/fishing_loot_quests.md`.
//  Документ: `AstoryServer/Docs/GameServer/state-preamble-p64.md`.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  У диспетчера sub_42A9D0 гейт состояния стоит ВЫБОРОЧНО: «душа» sub_52EEA0 — у 71 опкода (`if (!sub_52EEA0) handler`,
//  молча), «занят» sub_52BFF0 (мёртв / обмен / биржа / лавка / рыбалка) — внутри 49 обработчиков, «одержим» sub_52EE40 —
//  внутри 22. Десятки обработчиков экономики/прогресса/питомцев/рыбалки/заданий не спрашивают НИЧЕГО: мёртвый или стоящий
//  в обмене персонаж может открыть набор 6096, вытянуть/благословить/перенести опцию (6549/6551/6553/5433), сложить премиум
//  6555, выбрать знак 6586, сменить имя 6140, вызвать/объединить питомцев (6100…6121/6148), ловить (6167…6182), входить в
//  ограниченные задания (6591/6593). PvP-удары 4201/4203 и навык стража 6158 не гейтятся по «душе» (Б-03).
//
//  ── ЧЕМ ЛЕЧИМ (без новых площадок в .text) ──
//  Гейт зовётся ВТОРЫМ (сразу после P55) из C-функции гейта P47 (P47_OperatorGate; стаб 0x42AB4F — запись опкода в
//  кадр диспетчера, ветка userNum < 10000) с теми же аргументами (CUserManager, опкод, userNum, кадр).
//  Для опкодов из настраиваемого списка (шесть семей: экономика, питомцы, бой, рыбалка, задания, прочее — каждая со своей
//  маской запретов) читаются ТЕ ЖЕ поля CUser, что читают стоковые предикаты (смещения сняты дизасмом, образ 4e20f0ad =
//  живые e7b4ac38 — тела предикатов побайтно одинаковы, verify_p64.py):
//    «не в игре»  sub_532670@0x532670: BYTE  CUser+0x190   (0x53269D  mov al,[ecx+190h])            == 0
//    «мёртв»      sub_4CB030@0x4CB030: DWORD CUser+0x4F    (0x4CB05D  mov edx,[ecx+4Fh])            != 0
//                 пишут sub_4CB070 (0x4CB0E7; CharMake тип 3 → 1, CharRegen* → 0) и ClearUserMemory sub_4A2DC0 (0x4A33EC → 0);
//                 порт зеркалит его как `bSelfDead` («CUser+79»).
//    «занят»      sub_52BFF0@0x52BFF0 — коды как у стока: 1 = мёртв (см. выше), 2 = обмен DWORD CUser+0x145 (0x52C070;
//                 пишет CharExchangeAcceptReq 0x4DFF27 = 1), 3 = биржа «запрос в полёте» DWORD CUser+0x15F (0x52C0A6; пишет
//                 sub_521980 0x5219AE), 4 = личная лавка DWORD CUser+0x14D (0x52C0DC; CharSelfStoreReady 0x502D8C = 1),
//                 5 = рыбалка BYTE CUser+0x3F6B4 (0x52C10F; Recv_StartFishing 0x40F292 = 1).
//                 ⚠ sub_52BFF0 НЕ предикат: он ШЛЁТ 6001 {опкод, код} на КАЖДОМ вызове (и при коде 0 — 0x52C154), поэтому из
//                 гейта он не зовётся — иначе у опкодов без стокового 6001 появился бы новый пакет (протокол менять нельзя).
//    «душа»       sub_52EEA0@0x52EEA0: BYTE  CUser+0x182D3 (0x52EECD) == 1
//    «одержим»    sub_52EE40@0x52EE40: DWORD CUser+0x182B9 (0x52EE6D) > 0 && BYTE CUser+0x182D3 (0x52EE79) == 2
//  Отказ (Mode=1) — ТИХИЙ ПРОПУСК обработчика: ровно так сток молча пропускает обработчик под гейтом «душа» в диспетчере.
//  Никаких новых пакетов/кодов. Mode=0 (умолчание) — только журнал.
//  Опкоды, у которых «занят/мёртв» уже спрашивает сам обработчик (sub_52BFF0 внутри: 6162, 6502, 6506, 4201, 4203, 6158,
//  6165, 6176 — xref дизасма), при RespectStockGates=1 по этим двум запретам НЕ проверяются: иначе в Mode=1 тихий отказ
//  подменил бы штатный ответ стока (4202 код 0 / 6001 код N / 6166 код 117).
//  «Душа»/«одержим» по умолчанию ВЫКЛЮЧЕНЫ во всех семьях: сток эти опкоды не гейтит, и честный порт шлёт их в обоих
//  состояниях (таблица AsdaSoul/AsdaPossess порта повторяет диспетчер: «ГЕЙТА НЕТ (и ставить нельзя) на … блоке 0x1777…0x182D»,
//  `AsdaPossessGate.cpp`) — иначе честный путь давал бы срабатывания. Включаются ключами Mask<Семья>=…;soul;possess.
//
//  ── ЖУРНАЛ ──
//  ac.other (P53), виды 40 «не в игре», 41 «мёртв», 42 «занят», 43 «душа», 44 «одержим» (номера выданы координатором);
//  v[0] = значение поля (для «занят» — код 2…5 как у sub_52BFF0), v[1] = семья, v[2] = действие (0 журнал / 1 отказ),
//  text = имя обработчика (таблица OpcodeLengths.h P55). Только нарушения, ограничитель на (сессия, вид) JournalIntervalSec;
//  плюс строка штатного лога сервера sub_569DF0(LogChannel, "P64 …") под тем же ограничителем.
//
//  ── ЗАВИСИМОСТИ ──
//  Стаб гейта ставит P47 (и при OperatorGmFlag=0, если P64 включён — общая точка P64_GateWanted, как P55_GateWanted).
//  P53 — журнал. Площадок своих нет; байты площадки 0x42AB4F сверяет P47. Перед установкой сверяются 9 «опорных» инструкций
//  предикатов (список выше) — несовпадение любой = Mismatch (смещения не доказаны для этого образа).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include "../OpcodeLengths.h"
#include <string.h>
#include <stdlib.h>

namespace
{
    const wchar_t* kSec = L"P64_StatePreamble";

    // ── запреты (биты маски) ─────────────────────────────────────────────────
    enum Flag : BYTE
    {
        fDead     = 0x01,   // CUser+0x4F  != 0
        fExchange = 0x02,   // CUser+0x145 != 0  (код 2 sub_52BFF0)
        fAuction  = 0x04,   // CUser+0x15F != 0  (код 3)
        fStore    = 0x08,   // CUser+0x14D != 0  (код 4)
        fFishing  = 0x10,   // CUser+0x3F6B4 != 0 (код 5)
        fSoul     = 0x20,   // CUser+0x182D3 == 1
        fPossess  = 0x40,   // CUser+0x182B9 > 0 && CUser+0x182D3 == 2
        fInGame   = 0x80,   // CUser+0x190 == 0 → нарушение
    };
    constexpr BYTE fBusyAll = fExchange | fAuction | fStore | fFishing;

    // ── семьи опкодов ────────────────────────────────────────────────────────
    enum Family : BYTE { kFamNone = 0, kFamEconomy = 1, kFamPets = 2, kFamCombat = 3, kFamFishing = 4, kFamQuest = 5, kFamMisc = 6, kFamCount = 7 };
    struct FamDef { const wchar_t* opKey; const wchar_t* maskKey; const wchar_t* defOps; const wchar_t* defMask; const wchar_t* name; const char* nameA; };
    const FamDef kFam[kFamCount] =
    {
        { nullptr, nullptr, L"", L"", L"-", "-" },
        { L"OpcodesEconomy", L"MaskEconomy", L"6096;6098;6549;6551;6553;5433;6555;6586;6140;6162;6502;6506", L"dead;busy;ingame", L"экономика", "economy" },
        { L"OpcodesPets",    L"MaskPets",    L"6100;6102;6108;6110;6112;6114;6116;6118;6121;6148",           L"dead;busy;ingame", L"питомцы",   "pets"    },
        { L"OpcodesCombat",  L"MaskCombat",  L"4201;4203;6158",                                              L"dead;busy;ingame", L"бой",       "combat"  },
        { L"OpcodesFishing", L"MaskFishing", L"6165;6167;6169;6171;6176;6178;6180;6182",                     L"dead;exchange;auction;store;ingame", L"рыбалка", "fishing" },
        { L"OpcodesQuest",   L"MaskQuest",   L"6591;6593",                                                   L"dead;busy;ingame", L"задания",   "quest"   },
        { L"OpcodesMisc",    L"MaskMisc",    L"6150;6067;5428;6127",                                         L"dead;busy;ingame", L"прочее",    "misc"    },
    };

    // Опкоды, у которых «занят» (и «мёртв» как его код 1) уже спрашивает сам обработчик — sub_52BFF0 внутри
    // (xref дизасма: CharRoseWarStoreBuy, Recv_User_Disassemble, Recv_User_ShellItemUpgradeReset, Recv_User_AttackToPlayer,
    // Recv_User_AttackedToPlayer, RecvChar_SkillUse_0, Recv_FishingToolUse, Recv_FishingBookRegist).
    const WORD kStockBusy[] = { 6162, 6502, 6506, 4201, 4203, 6158, 6165, 6176 };

    // ── настройки (patches.ini) ─────────────────────────────────────────────
    volatile LONG g_enabled = 0;
    int  g_mode        = 0;      // 0 — только журнал, 1 — тихий отказ
    bool g_respectStock= true;   // не дублировать стоковый sub_52BFF0
    bool g_logHits     = true;   // строки в PatchLog
    int  g_logChannel  = 1;      // канал sub_569DF0 (1 = Log_Item)
    int  g_journalSec  = 60;     // ограничитель журнала
    BYTE g_famMask[kFamCount] = {};

    // ── таблицы по опкоду (строятся при установке) ───────────────────────────
    BYTE g_family[OpLen::kOpcodeMax];    // семья (0 — не в списке)
    BYTE g_mask  [OpLen::kOpcodeMax];    // действующая маска запретов

    // ── функции GameServer ───────────────────────────────────────────────────
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);        // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    constexpr int   kSlots    = 0x226;
    constexpr DWORD kGateSite = 0x0042AB4F;

    // ── ограничитель журнала на (userNum, вид 40..44) ────────────────────────
    struct JLimit { DWORD lastTick; LONG suppressed; BYTE used; };
    JLimit g_jlimit[kSlots][5] = {};

    P64_Stats g_stats = {};
    CRITICAL_SECTION g_logLock;
    bool g_logLockReady = false;

    bool JournalAllow(int userNum, int kind, LONG* suppressedOut)
    {
        *suppressedOut = 0;
        if (kind < 40 || kind > 44) { return true; }
        JLimit& j = g_jlimit[userNum][kind - 40];
        const DWORD now = GetTickCount();
        if (j.used && g_journalSec > 0 && (DWORD)(now - j.lastTick) < (DWORD)g_journalSec * 1000u)
        {
            InterlockedIncrement(&j.suppressed);
            InterlockedIncrement(&g_stats.suppressed);
            return false;
        }
        *suppressedOut = j.used ? InterlockedExchange(&j.suppressed, 0) : 0;
        j.used = 1; j.lastTick = now;
        return true;
    }

    // Состояние персонажа — чтения тех же полей, что у стоковых предикатов (см. шапку).
    struct State { int inGame; int dead; int exchange; int auction; int store; int fishing; int soul; int partner; int userIndex; int charSlot; const BYTE* user; };

    bool ReadState(void* mgr, int userNum, State& s)
    {
        memset(&s, 0, sizeof(s));
        __try
        {
            const BYTE* u = pGetUser(mgr, nullptr, (short)userNum);
            if (!u) { return false; }
            s.user      = u;
            s.inGame    = u[Srv::kOffInGameFlag];
            s.dead      = *(const int*)(u + Srv::kOffDeadFlag);
            s.exchange  = *(const int*)(u + Srv::kOffExchangeFlag);
            s.auction   = *(const int*)(u + Srv::kOffAuctionFlag);
            s.store     = *(const int*)(u + Srv::kOffStoreFlag);
            s.fishing   = u[Srv::kOffFishingFlag];
            s.soul      = u[Srv::kOffSoulState];
            s.partner   = *(const int*)(u + Srv::kOffSoulPartner);
            s.userIndex = *(const int*)(u + Srv::kOffUserNum);
            s.charSlot  = u[Srv::kOffUserSubFlag];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    const wchar_t* KindTextW(int kind)
    {
        switch (kind)
        {
        case 40: return L"не в игре";
        case 41: return L"мёртв";
        case 42: return L"занят";
        case 43: return L"душа";
        case 44: return L"одержим";
        }
        return L"?";
    }
    const char* KindTextA(int kind, int detail)
    {
        switch (kind)
        {
        case 40: return "not-in-game";
        case 41: return "dead";
        case 42: return detail == 2 ? "busy(exchange)" : detail == 3 ? "busy(auction)" : detail == 4 ? "busy(store)" : "busy(fishing)";
        case 43: return "soul";
        case 44: return "possessed";
        }
        return "?";
    }

    void Report(const State& st, int userNum, int opcode, int kind, int detail, int fam, int action)
    {
        LONG suppressed = 0;
        if (!JournalAllow(userNum, kind, &suppressed)) { return; }
        InterlockedIncrement(&g_stats.journaled);

        const OpLen::Info* info = &OpLen::kInfo[0];
        if (opcode >= 0 && opcode < OpLen::kOpcodeMax) { info = &OpLen::kInfo[OpLen::kIndex[opcode]]; }
        const char* handler = info->opcode ? info->handler : "?";

        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, (BYTE)kind);
        e.userNum   = (short)userNum;
        e.opcode    = opcode;
        e.ip        = P47_PeerIpv4(userNum);
        e.userIndex = st.userIndex;
        e.charSlot  = st.charSlot;
        __try { if (st.user) { AcJournal::CopyName(e, st.user + Srv::kOffCharName); } } __except (EXCEPTION_EXECUTE_HANDLER) {}
        e.v[0] = detail;
        e.v[1] = fam;
        e.v[2] = action;
        AcJournal::CopyText(e, handler);
        e.suppressed = (int)suppressed;
        AcJournal::Push(e);

        // Штатный лог сервера (как P57/P33) — под тем же ограничителем.
        pSrvLog(g_logChannel, "P64 StatePreamble: op %d (%s) %s=%d family %s UserNum %d UserIndex %d -> %s, suppressed %d",
                opcode, handler, KindTextA(kind, detail), detail, kFam[fam].nameA, userNum, st.userIndex,
                action ? "REFUSED (silent)" : "JOURNAL ONLY (Mode=0)", (int)suppressed);

        if (!g_logHits) { return; }
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        Log::Line(L"[P64] %s: опкод %d (%S) значение %d, семья %s, userNum %d UserIndex %d → %s, подавлено %d",
                  KindTextW(kind), opcode, handler, detail, kFam[fam].name, userNum, st.userIndex,
                  action ? L"отказ (тихо)" : L"журнал", (int)suppressed);
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
    }

    // ── разбор ini ───────────────────────────────────────────────────────────
    BYTE ParseMask(const wchar_t* s)
    {
        BYTE m = 0;
        wchar_t buf[256]; lstrcpynW(buf, s, 256);
        wchar_t* ctx = nullptr;
        for (wchar_t* t = wcstok_s(buf, L";, \t", &ctx); t; t = wcstok_s(nullptr, L";, \t", &ctx))
        {
            if      (!_wcsicmp(t, L"dead"))     { m |= fDead; }
            else if (!_wcsicmp(t, L"busy"))     { m |= fBusyAll; }
            else if (!_wcsicmp(t, L"exchange")) { m |= fExchange; }
            else if (!_wcsicmp(t, L"auction"))  { m |= fAuction; }
            else if (!_wcsicmp(t, L"store"))    { m |= fStore; }
            else if (!_wcsicmp(t, L"fishing"))  { m |= fFishing; }
            else if (!_wcsicmp(t, L"soul"))     { m |= fSoul; }
            else if (!_wcsicmp(t, L"possess"))  { m |= fPossess; }
            else if (!_wcsicmp(t, L"ingame"))   { m |= fInGame; }
            else if (!_wcsicmp(t, L"none"))     { }
            else { Log::Line(L"    P64: неизвестный запрет «%s» в маске — пропущен", t); }
        }
        return m;
    }

    // Вызывает fn(op) для каждого числа списка «a;b;c». Возвращает число принятых.
    template <class F> int ForEachOp(const wchar_t* s, F fn)
    {
        int n = 0;
        wchar_t buf[1024]; lstrcpynW(buf, s, 1024);
        wchar_t* ctx = nullptr;
        for (wchar_t* t = wcstok_s(buf, L";, \t", &ctx); t; t = wcstok_s(nullptr, L";, \t", &ctx))
        {
            const long op = wcstol(t, nullptr, 10);
            if (op <= 0 || op >= OpLen::kOpcodeMax) { Log::Line(L"    P64: опкод «%s» вне 1..%d — пропущен", t, OpLen::kOpcodeMax - 1); continue; }
            fn((int)op); ++n;
        }
        return n;
    }

    bool IsStockBusy(int op)
    {
        for (int i = 0; i < ARRAYSIZE(kStockBusy); ++i) { if (kStockBusy[i] == op) { return true; } }
        return false;
    }

    // Опорные инструкции предикатов стока: совпадение = смещения полей доказаны для этого образа.
    const BYTE kRefDead[3]     = { 0x8B,0x51,0x4F };                       // 0x4CB05D  mov edx,[ecx+4Fh]        sub_4CB030
    const BYTE kRefSoul[7]     = { 0x0F,0xB6,0x91,0xD3,0x82,0x01,0x00 };   // 0x52EECD  movzx edx,byte [ecx+182D3h] sub_52EEA0
    const BYTE kRefPartner[7]  = { 0x83,0xB9,0xB9,0x82,0x01,0x00,0x00 };   // 0x52EE6D  cmp [ecx+182B9h],0        sub_52EE40
    const BYTE kRefSoul2[7]    = { 0x0F,0xB6,0x82,0xD3,0x82,0x01,0x00 };   // 0x52EE79  movzx eax,byte [edx+182D3h]
    const BYTE kRefInGame[6]   = { 0x8A,0x81,0x90,0x01,0x00,0x00 };        // 0x53269D  mov al,[ecx+190h]         sub_532670
    const BYTE kRefExchange[7] = { 0x83,0xB8,0x45,0x01,0x00,0x00,0x00 };   // 0x52C070  cmp [eax+145h],0          sub_52BFF0 код 2
    const BYTE kRefAuction[7]  = { 0x83,0xB9,0x5F,0x01,0x00,0x00,0x00 };   // 0x52C0A6  cmp [ecx+15Fh],0          код 3
    const BYTE kRefStore[7]    = { 0x83,0xBA,0x4D,0x01,0x00,0x00,0x00 };   // 0x52C0DC  cmp [edx+14Dh],0          код 4
    const BYTE kRefFishing[7]  = { 0x0F,0xB6,0x88,0xB4,0xF6,0x03,0x00 };   // 0x52C10F  movzx ecx,byte [eax+3F6B4h] код 5
}

// ── общая точка для P47: нужен ли стаб гейта 0x42AB4F ради P64 ──────────────
bool P64_GateWanted()
{
    return Config::GetBool(kSec, L"Enabled", true);
}

// ── гейт: 1 — пропустить в switch, 0 — обработчик не вызывать (только Mode=1) ─
//   Зовёт P47_OperatorGate ВТОРЫМ (сразу после P55). Аргументы те же, что у стаба P47.
int P64_StateGate(void* mgr, int opcode, int userNum, const BYTE* pkt)
{
    (void)pkt;
    if (!g_enabled || !mgr) { return 1; }
    if (userNum < 0 || userNum >= kSlots) { return 1; }
    if (opcode < 0 || opcode >= OpLen::kOpcodeMax) { return 1; }
    const BYTE fam  = g_family[opcode];
    if (!fam) { return 1; }
    InterlockedIncrement(&g_stats.checked);
    const BYTE mask = g_mask[opcode];
    if (!mask) { return 1; }

    State st;
    if (!ReadState(mgr, userNum, st)) { return 1; }

    int kind = 0, detail = 0;
    if      ((mask & fInGame)   && st.inGame == 0)                  { kind = 40; detail = st.inGame;   InterlockedIncrement(&g_stats.notInGame); }
    else if ((mask & fDead)     && st.dead != 0)                    { kind = 41; detail = st.dead;     InterlockedIncrement(&g_stats.dead); }
    else if ((mask & fExchange) && st.exchange != 0)                { kind = 42; detail = 2;           InterlockedIncrement(&g_stats.busy); }
    else if ((mask & fAuction)  && st.auction != 0)                 { kind = 42; detail = 3;           InterlockedIncrement(&g_stats.busy); }
    else if ((mask & fStore)    && st.store != 0)                   { kind = 42; detail = 4;           InterlockedIncrement(&g_stats.busy); }
    else if ((mask & fFishing)  && st.fishing != 0)                 { kind = 42; detail = 5;           InterlockedIncrement(&g_stats.busy); }
    else if ((mask & fSoul)     && st.soul == 1)                    { kind = 43; detail = st.soul;     InterlockedIncrement(&g_stats.soul); }
    else if ((mask & fPossess)  && st.partner > 0 && st.soul == 2)  { kind = 44; detail = st.partner;  InterlockedIncrement(&g_stats.possess); }
    if (!kind) { return 1; }

    const int action = g_mode == 1 ? 1 : 0;
    Report(st, userNum, opcode, kind, detail, fam, action);
    if (!action) { return 1; }
    InterlockedIncrement(&g_stats.refused);
    return 0;
}

// ── для стенда и строки PatchLog ────────────────────────────────────────────
extern "C" __declspec(dllexport) void __stdcall P64_GetStats(P64_Stats* s)
{
    if (s) { memcpy(s, &g_stats, sizeof(g_stats)); }
}

extern "C" __declspec(dllexport) void __stdcall P64_ResetState()
{
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_jlimit, 0, sizeof(g_jlimit));
}

extern "C" __declspec(dllexport) int __stdcall P64_QueryOpcode(int opcode, int* family)
{
    if (opcode < 0 || opcode >= OpLen::kOpcodeMax) { if (family) { *family = 0; } return 0; }
    if (family) { *family = g_family[opcode]; }
    return g_mask[opcode];
}

PatchResult P64_StatePreamble()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode         = Config::GetInt (kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_respectStock = Config::GetBool(kSec, L"RespectStockGates", true);
    g_logHits      = Config::GetBool(kSec, L"LogHits", true);
    g_logChannel   = Config::GetInt (kSec, L"LogChannel", 1);
    if (g_logChannel < 0 || g_logChannel > 63) { g_logChannel = 1; }
    g_journalSec   = Config::GetInt (kSec, L"JournalIntervalSec", 60);
    if (g_journalSec < 0)     { g_journalSec = 0; }
    if (g_journalSec > 86400) { g_journalSec = 86400; }
    if (!g_logLockReady) { InitializeCriticalSection(&g_logLock); g_logLockReady = true; }

    // Таблицы по опкоду: семьи → маски; затем общий список Opcodes= (если задан) сужает набор.
    memset(g_family, 0, sizeof(g_family));
    memset(g_mask, 0, sizeof(g_mask));
    int listed = 0;
    wchar_t buf[1024];
    for (int f = 1; f < kFamCount; ++f)
    {
        Config::GetStr(kSec, kFam[f].maskKey, kFam[f].defMask, buf, 1024);
        g_famMask[f] = ParseMask(buf);
        Config::GetStr(kSec, kFam[f].opKey, kFam[f].defOps, buf, 1024);
        listed += ForEachOp(buf, [f](int op) { g_family[op] = (BYTE)f; });
    }
    Config::GetStr(kSec, L"Opcodes", L"", buf, 1024);
    if (buf[0])
    {
        static BYTE keep[OpLen::kOpcodeMax];
        memset(keep, 0, sizeof(keep));
        ForEachOp(buf, [](int op) { keep[op] = 1; });
        listed = 0;
        for (int op = 0; op < OpLen::kOpcodeMax; ++op)
        {
            if (!keep[op]) { g_family[op] = 0; continue; }
            if (!g_family[op]) { g_family[op] = kFamMisc; }   // не из семей — считается «прочее»
            ++listed;
        }
    }
    int stripped = 0;
    for (int op = 0; op < OpLen::kOpcodeMax; ++op)
    {
        if (!g_family[op]) { continue; }
        BYTE m = g_famMask[g_family[op]];
        if (g_respectStock && IsStockBusy(op) && (m & (fDead | fBusyAll))) { m &= (BYTE)~(fDead | fBusyAll); ++stripped; }
        g_mask[op] = m;
    }

    // Зависимость: стаб гейта ставит P47 (площадка 0x42AB4F). Без него гейт никто не зовёт.
    if (!Config::GetBool(L"P47_IdentityOperatorGate", L"Enabled", true))
    {
        Log::Line(L"    P64: [P47_IdentityOperatorGate] Enabled=0 — стаб гейта 0x42AB4F не стоит, преамбула НЕ работает");
        return PatchResult::Failed;
    }
    BYTE first = 0;
    __try { first = *(const BYTE*)kGateSite; } __except (EXCEPTION_EXECUTE_HANDLER) { first = 0; }
    if (first != 0xE9)
    {
        Log::Line(L"    P64: на 0x%08X нет jmp стаба P47 (байт 0x%02X) — преамбула НЕ работает", kGateSite, first);
        return PatchResult::Failed;
    }

    // Опорные инструкции стоковых предикатов — смещения полей доказаны для этого образа (ничего не пишем).
    const Site refs[] =
    {
        { 0x004CB05D, kRefDead,     sizeof(kRefDead)     },
        { 0x0052EECD, kRefSoul,     sizeof(kRefSoul)     },
        { 0x0052EE6D, kRefPartner,  sizeof(kRefPartner)  },
        { 0x0052EE79, kRefSoul2,    sizeof(kRefSoul2)    },
        { 0x0053269D, kRefInGame,   sizeof(kRefInGame)   },
        { 0x0052C070, kRefExchange, sizeof(kRefExchange) },
        { 0x0052C0A6, kRefAuction,  sizeof(kRefAuction)  },
        { 0x0052C0DC, kRefStore,    sizeof(kRefStore)    },
        { 0x0052C10F, kRefFishing,  sizeof(kRefFishing)  },
    };
    if (!VerifyAllSites(L"P64 (опорные инструкции предикатов)", refs, ARRAYSIZE(refs))) { return PatchResult::Mismatch; }

    P64_ResetState();
    InterlockedExchange(&g_enabled, 1);
    Log::Line(L"    P64: Mode=%d (%s) опкодов в списке %d (у %d «занят/мёртв» оставлен стоку), RespectStockGates=%d LogHits=%d LogChannel=%d "
              L"JournalIntervalSec=%d; маски: экономика 0x%02X питомцы 0x%02X бой 0x%02X рыбалка 0x%02X задания 0x%02X прочее 0x%02X",
              g_mode, g_mode == 1 ? L"ТИХИЙ ОТКАЗ" : L"только журнал", listed, stripped, g_respectStock ? 1 : 0, g_logHits ? 1 : 0,
              g_logChannel, g_journalSec, g_famMask[1], g_famMask[2], g_famMask[3], g_famMask[4], g_famMask[5], g_famMask[6]);
    return PatchResult::Applied;
}
