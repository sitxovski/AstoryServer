// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P69 — ★ СТУПЕНЧАТЫЙ АВТОБЛОК ЗА НАРУШЕНИЯ ЦЕЛОСТНОСТИ ПАКЕТОВ (античит, волна autoban, 2026-10-14).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Решение владельца 14.10: «нарушения целостности пакетов от учётки наказываются ступенчато:
//  20 нарушений → блок на сутки, всего 50 → блок на месяц, больше → бессрочно».
//  Отчёт: `Reports/anticheat/wave_AUTOBAN_20261014.md`; документ: `AstoryServer/Docs/GameServer/integrity-autoblock-p69.md`.
//
//  ── ЧТО СЧИТАЕМ (CountP55Kinds / CountChannelKinds) ──
//  «Поддельный/битый пакет» — кадр, которого честный клиент прислать не может:
//    • P55 (валидатор пакетов, гейт диспетчера 0x42AB4F): 1 кадр короче минимума опкода, 2 длиннее максимума (паддинг клиента
//      +0..19 уже учтён в таблице), 4 кадр короче заголовка. НЕ считается 3 «частота класса» — это не порча кадра, а темп
//      (бывает от лагов/повторной отправки), и пороги частоты ещё калибруются.
//    • P61 (защищённый канал, приём IOCP): 56 тег AES-GCM не сошёлся (подмена/порча), 57 номер кадра не следующий (повтор),
//      58 мусор до рукопожатия / сбой рукопожатия / старый клиент при AllowLegacy=0, 59 длина кадра вне предела.
//      Только приём (phase 0). НЕ считается: вид 0 (сбой CNG/шифрования на сервере) и 61 (кадр сервера не доставлен: отказ
//      стокового Send, очередь моста, сток потерял кадр, общий предел, нехватка памяти — сбой сервера/сети, не игрока).
//  Счёт P55 — по строкам журнала (ограничитель P55 на (сессия, вид), JournalIntervalSec): подавленные повторы счёт не
//  прибавляют, иначе один битый клиент в режиме журнала набрал бы 51 за секунду. Нарушение канала — одно на соединение (мост
//  рвёт соединение на первом).
//
//  ── ЧЬЯ УЧЁТКА ──
//  Только подтверждённая учётка СЕССИИ: сессия в мире (CUser+0x2E == 1 — CharMake/CharPortalMake после DB-логона, сверенного
//  P50), вход соулмейтом (SoulState 2) — iMateUserIndex CUser+0x182C6 (общая точка P48_IdentityOf, те же правила, что у счёта
//  киков P48). До входа в мир CUser+0x174 — номер, ЗАЯВЛЕННЫЙ клиентом в 20000: нарушение пишется в журнал, но НЕ считается
//  (иначе подставной клиент заблокировал бы чужую учётку). Операторы (GM-флаг, общая точка P47_IsGmUser) не считаются.
//  P61 работает в потоке IOCP и CUserManager не имеет: его запоминает гейт P47 на каждом пакете слота (P69_OnClientPacket),
//  сброс — на accept/разрыве слота (P61_ResetSlotC → P69_SlotReset). Нет CUserManager — учётка неизвестна (только журнал).
//
//  ── СТУПЕНИ (ключи ini, умолчания владельца) ──
//  Stage1Count=20 → Stage1Hours=24; Stage2Count=50 → Stage2Hours=720; Stage3Count=51 → Stage3Hours=-1 (бессрочно = 30 лет
//  UPHackBlock). Счёт накопительный (без окна), по учётке, переживает рестарт: файл ini CounterFile (общий GameServer/Indun),
//  межпроцессный мьютекс. Каждая ступень срабатывает ОДИН раз (stageDone в файле; ступень забирается под замком до отправки,
//  сбой отправки 2271 возвращает её — повтор на следующем нарушении). Счёт перепрыгнул ступень (сбой) — сработает старшая.
//  Mode=0 (умолчание до альфы): ТОЛЬКО ЖУРНАЛ — строка ac.other 62 «был бы блок», PatchLog, Log_Operator; 2271 не уходит.
//  Mode=1: штатный DB-запрос 2271 (как GM-блок 6094 / Recv_CharBlock, общая точка P48_SendHackBlock) → DBManager sub_432950 →
//  `EXEC UPHackBlock UserIndex, часы` (новая строка BlockList; блок держится, пока не истекли ВСЕ строки — короткий блок
//  бессрочный не отменяет). KickOnBlock=1: сессия, ещё играющая после блока (источник P55 — валидатор не рвёт соединение),
//  выводится штатным счётчиком Hack Packet (CUser+0x22 > 5 → CheckDisConnectUser 0x526C20, кик тип 3); этот кик P48 не
//  считает (метка P69_TakeKickMark). P61 соединение рвёт сам мост.
//  Счётчики Mode=0 и Mode=1 — разные секции файла ([Mode0] / [Mode1]): наблюдение до альфы не переносится в боевой счёт.
//
//  ── ПЛОЩАДОК НЕТ ──
//  Зовётся из P47_OperatorGate (кэш), P55 Report и P61 Report/трамплинов. Своих байт в .text не пишет.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P69_IntegrityAutoBlock";
    constexpr int  kSlots      = 0x226;      // userNum / слот Ciocp 0…549 (sub_5328F0)
    constexpr int  kStages     = 3;
    constexpr int  kOffOwner   = 0x174;      // CUser: UserIndex (хозяин персонажа / заявлен в 20000 до входа)
    constexpr int  kOffSlot    = 0x18C;      // CUser: слот персонажа
    constexpr int  kOffHackCnt = 0x22;       // CUser: DWORD счётчик Hack Packet (sub_524540 ++; sub_524580 «> 5» → кик тип 3)
    constexpr int  kHackKick   = 6;          // > 5 — штатный кик CheckDisConnectUser
    constexpr int  kKindLimit  = 64;         // номера видов, допустимые в списках

    // ── настройки (patches.ini) ─────────────────────────────────────────────
    volatile LONG g_enabled  = 0;
    int  g_mode        = 0;                  // 0 — только журнал «был бы блок», 1 — блок 2271
    struct Stage { int count; int hours; };
    Stage g_stage[kStages] = { { 20, 24 }, { 50, 720 }, { 51, -1 } };
    bool g_countP55[kKindLimit] = {};
    bool g_countCh [kKindLimit] = {};
    bool g_exemptGm     = true;
    bool g_soulSession  = true;
    bool g_kickOnBlock  = true;
    bool g_logCounted   = true;
    wchar_t g_counterFile[MAX_PATH] = L"";

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);         // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    // ── состояние слотов (без замков: одна запись указателя/числа) ───────────
    void* volatile g_slotMgr[kSlots] = {};   // CUserManager, с которым гейт P47 видел слот последним
    volatile LONG  g_slotIp[kSlots]  = {};   // IP пира соединения (сетевой порядок), 0 — нет
    volatile LONG  g_kickMark[kSlots] = {};  // учётка, которой P69 назначил кик (KickOnBlock); 0 — нет

    P69_Stats g_stats = {};

    CRITICAL_SECTION g_lock;
    bool             g_lockReady = false;
    HANDLE           g_mutex     = nullptr;   // межпроцессный (GameServer + Indun)

    __int64 NowUnix()
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        return (__int64)(u.QuadPart / 10000000ULL) - 11644473600LL;
    }

    void Lock()   { if (g_lockReady) { EnterCriticalSection(&g_lock); } if (g_mutex) { WaitForSingleObject(g_mutex, 2000); } }
    void Unlock() { if (g_mutex) { ReleaseMutex(g_mutex); } if (g_lockReady) { LeaveCriticalSection(&g_lock); } }

    const wchar_t* Section() { return g_mode == 1 ? L"Mode1" : L"Mode0"; }

    // Запись файла: «счёт,ступень,первое_unix,последнее_unix».
    struct Rec { int count; int stage; unsigned first; unsigned last; };

    unsigned ParseU(const wchar_t*& p) { unsigned v = 0; while (*p >= L'0' && *p <= L'9') { v = v * 10 + (unsigned)(*p - L'0'); ++p; } return v; }

    Rec RecRead(int account)
    {
        wchar_t key[16]; wsprintfW(key, L"%d", account);
        wchar_t val[96] = L"";
        GetPrivateProfileStringW(Section(), key, L"", val, ARRAYSIZE(val), g_counterFile);
        Rec r = {};
        const wchar_t* p = val;
        r.count = (int)ParseU(p); if (*p == L',') { ++p; }
        r.stage = (int)ParseU(p); if (*p == L',') { ++p; }
        r.first = ParseU(p);      if (*p == L',') { ++p; }
        r.last  = ParseU(p);
        if (r.count < 0) { r.count = 0; }
        if (r.stage < 0 || r.stage > kStages) { r.stage = 0; }
        return r;
    }

    void RecWrite(int account, const Rec& r)
    {
        wchar_t key[16]; wsprintfW(key, L"%d", account);
        wchar_t out[96]; wsprintfW(out, L"%d,%d,%u,%u", r.count, r.stage, r.first, r.last);
        WritePrivateProfileStringW(Section(), key, out, g_counterFile);
    }

    // Старшая ступень, порог которой достигнут (0 — ни одной).
    int StageFor(int count)
    {
        int st = 0;
        for (int i = 0; i < kStages; ++i) { if (count >= g_stage[i].count) { st = i + 1; } }
        return st;
    }

    const wchar_t* SrcName(int source) { return source == kP69SrcP55 ? L"P55" : (source == kP69SrcP61 ? L"P61" : L"?"); }

    // Строка ac.other 62 — ступень достигнута.
    void JournalStage(const P69_Session& s, int userNum, int account, int stage, int count, int hours, DWORD ip,
                      int source, int kind, int result)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, 62);
        e.userNum   = (short)userNum;
        e.ip        = ip;
        e.userIndex = account;
        e.charSlot  = s.charSlot >= 0 ? s.charSlot : AcJournal::kNone;
        e.opcode    = (g_mode == 1 && result == 1) ? 2271 : AcJournal::kNone;
        if (s.user)
        {
            __try { AcJournal::CopyName(e, s.user + Srv::kOffCharName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = stage;
        e.v[1] = count;
        e.v[2] = hours;
        char t[64];
        const char* src = source == kP69SrcP55 ? "P55" : (source == kP69SrcP61 ? "P61" : "?");
        if (g_mode == 1)
        {
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P69 Mode=1: 2271 %s, %dh; last %s kind %d%s", result == 1 ? "sent" : "FAILED", hours, src,
                        kind, (result == 1 && source == kP69SrcP55 && g_kickOnBlock) ? ", kick" : "");
        }
        else
        {
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P69 Mode=0: would block %dh; last %s kind %d", hours, src, kind);
        }
        AcJournal::CopyText(e, t);
        AcJournal::Push(e);
    }

    // Разбор списка видов «1,2,4».
    void ParseKinds(const wchar_t* s, bool* out)
    {
        for (int i = 0; i < kKindLimit; ++i) { out[i] = false; }
        int v = -1;
        for (const wchar_t* p = s; ; ++p)
        {
            if (*p >= L'0' && *p <= L'9') { v = (v < 0 ? 0 : v * 10) + (*p - L'0'); if (v > 100000) { v = 100000; } continue; }
            if (v >= 0 && v < kKindLimit) { out[v] = true; }
            v = -1;
            if (!*p) { break; }
        }
    }
}

// ── общие точки: сессия слота ───────────────────────────────────────────────

void P69_OnClientPacket(void* mgr, int userNum)
{
    if (!mgr || userNum < 0 || userNum >= kSlots) { return; }
    if (g_slotMgr[userNum] != mgr) { InterlockedExchangePointer((void* volatile*)&g_slotMgr[userNum], mgr); }
}

void P69_SlotReset(int slot)
{
    if (slot < 0 || slot >= kSlots) { return; }
    InterlockedExchangePointer((void* volatile*)&g_slotMgr[slot], nullptr);
    InterlockedExchange(&g_slotIp[slot], 0);
    InterlockedExchange(&g_kickMark[slot], 0);
}

void P69_NoteSlotIp(int slot)
{
    if (slot < 0 || slot >= kSlots || g_slotIp[slot] != 0) { return; }
    const DWORD ip = P47_PeerIpv4(slot);
    if (ip) { InterlockedCompareExchange(&g_slotIp[slot], (LONG)ip, 0); }
}

DWORD P69_SlotIp(int slot)
{
    const DWORD live = P47_PeerIpv4(slot);
    if (live || slot < 0 || slot >= kSlots) { return live; }
    const DWORD cached = (DWORD)g_slotIp[slot];
    if (cached) { InterlockedIncrement(&g_stats.ipFromCache); }
    return cached;
}

bool P69_ResolveSession(void* mgr, int userNum, P69_Session* s)
{
    s->mgr = nullptr; s->user = nullptr; s->account = 0; s->owner = -1; s->soul = -1; s->state = -1; s->charSlot = -1; s->gm = false;
    if (userNum < 0 || userNum >= kSlots) { return false; }
    if (!mgr) { mgr = g_slotMgr[userNum]; }
    if (!mgr) { return false; }
    s->mgr = mgr;
    __try
    {
        BYTE* u = pGetUser(mgr, nullptr, (short)userNum);
        if (!u) { return false; }
        s->user     = u;
        s->owner    = *(const int*)(u + kOffOwner);
        s->charSlot = u[kOffSlot];
        P48_Identity id;
        P48_IdentityOf(u, s->owner, g_soulSession, &id);
        s->soul  = id.soul;
        if (!id.inWorld)          { s->state = 0; s->account = 0; }
        else if (!id.soulMate)    { s->state = 1; s->account = id.account; }
        else if (id.account > 0)  { s->state = 2; s->account = id.account; }
        else                      { s->state = 3; s->account = 0; }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        s->user = nullptr; s->account = 0; s->state = -1;
        return false;
    }
    s->gm = P47_IsGmUser(mgr, userNum);
    return true;
}

bool P69_TakeKickMark(int userNum, int account)
{
    if (userNum < 0 || userNum >= kSlots || account <= 0) { return false; }
    return InterlockedCompareExchange(&g_kickMark[userNum], 0, account) == account;
}

// ── нарушение → счёт → ступень ───────────────────────────────────────────────
void P69_OnViolation(const P69_Session& s, int userNum, int source, int kind, DWORD ip, int opcode)
{
    if (!g_enabled) { return; }
    InterlockedIncrement(&g_stats.seen);
    const bool kindOk = kind >= 0 && kind < kKindLimit &&
                        ((source == kP69SrcP55 && g_countP55[kind]) || (source == kP69SrcP61 && g_countCh[kind]));
    if (!kindOk) { InterlockedIncrement(&g_stats.notKind); return; }
    const BYTE* q = (const BYTE*)&ip;
    if (s.account <= 0)
    {
        // До входа в мир (или соулмейт без iMateUserIndex): учётка не подтверждена — только журнал источника.
        InterlockedIncrement(&g_stats.preWorld);
        return;
    }
    if (g_exemptGm && s.gm)
    {
        InterlockedIncrement(&g_stats.operators);
        Log::Line(L"[P69] %s вид %d: UserIndex %d (userNum %d, IP %u.%u.%u.%u) — оператор (GM-флаг), НЕ засчитано",
                  SrcName(source), kind, s.account, userNum, q[0], q[1], q[2], q[3]);
        return;
    }

    // Счёт и решение о ступени — под замком (CS + межпроцессный мьютекс); ступень забирается ДО отправки.
    int count = 0, claim = 0, prevStage = 0;
    Lock();
    __try
    {
        Rec r = RecRead(s.account);
        const unsigned now = (unsigned)NowUnix();
        ++r.count;
        if (!r.first) { r.first = now; }
        r.last = now;
        const int target = StageFor(r.count);
        prevStage = r.stage;
        if (target > r.stage) { claim = target; r.stage = target; }
        RecWrite(s.account, r);
        count = r.count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { count = 0; claim = 0; }
    Unlock();
    if (count <= 0) { return; }
    InterlockedIncrement(&g_stats.counted);

    int next = 0;
    for (int i = 0; i < kStages; ++i) { if (count < g_stage[i].count) { next = g_stage[i].count; break; } }
    if (g_logCounted)
    {
        if (next)
        {
            Log::Line(L"[P69] %s вид %d (опкод %d): UserIndex %d (userNum %d, IP %u.%u.%u.%u) — нарушений %d, следующая ступень на %d",
                      SrcName(source), kind, opcode == AcJournal::kNone ? -1 : opcode, s.account, userNum, q[0], q[1], q[2], q[3], count, next);
        }
        else
        {
            Log::Line(L"[P69] %s вид %d (опкод %d): UserIndex %d (userNum %d, IP %u.%u.%u.%u) — нарушений %d, все ступени пройдены",
                      SrcName(source), kind, opcode == AcJournal::kNone ? -1 : opcode, s.account, userNum, q[0], q[1], q[2], q[3], count);
        }
    }
    if (!claim) { return; }

    const int hours = g_stage[claim - 1].hours;
    int result = 0;   // Mode=1: 1 отправлен / 0 сбой; Mode=0: 2 «был бы блок»
    if (g_mode == 1)
    {
        result = P48_SendHackBlock(s.mgr, userNum, s.account, hours) ? 1 : 0;
        if (result == 1)
        {
            InterlockedIncrement(&g_stats.sent);
            if (source == kP69SrcP55 && g_kickOnBlock && s.user)
            {
                // Сессия продолжает игру (валидатор соединение не рвёт) — штатный вывод: счётчик Hack Packet > 5 → кик тип 3 на
                // ближайшем проходе CheckDisConnectUser 0x526C20. Метка — чтобы P48 этот кик не считал.
                InterlockedExchange(&g_kickMark[userNum], s.account);
                __try { DWORD* hc = (DWORD*)(s.user + kOffHackCnt); if ((int)*hc < kHackKick) { *hc = kHackKick; } }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                InterlockedIncrement(&g_stats.kickMarks);
            }
        }
        else
        {
            InterlockedIncrement(&g_stats.sendFailed);
            // Вернуть ступень: следующее нарушение повторит попытку (если её ещё не забрал другой поток).
            Lock();
            __try
            {
                Rec r = RecRead(s.account);
                if (r.stage == claim) { r.stage = prevStage; RecWrite(s.account, r); }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Unlock();
        }
    }
    else
    {
        result = 2;
        InterlockedIncrement(&g_stats.wouldBlock);
    }
    InterlockedIncrement(&g_stats.stages);

    __try
    {
        pSrvLog(Srv::kLogCatOperator, "P69 IntegrityAutoBlock: UserIndex %d, UserNum %d, violations %d, stage %d, hours %d, mode %d -> %s (last %s kind %d)",
                s.account, userNum, count, claim, hours, g_mode,
                result == 1 ? "DB 2271 sent" : (result == 0 ? "DB 2271 FAILED (retry on next violation)" : "journal only, would block"),
                source == kP69SrcP55 ? "P55" : "P61", kind);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    Log::Line(L"[P69] ★ СТУПЕНЬ %d: UserIndex %d — %d нарушений → %s %d ч%s", claim, s.account, count,
              g_mode == 1 ? (result == 1 ? L"блок 2271 (UPHackBlock) отправлен," : L"блок 2271 НЕ ОТПРАВЛЕН (повтор на следующем нарушении),")
                          : L"Mode=0: был бы блок", hours,
              hours == -1 ? L" (бессрочно)" : L"");
    JournalStage(s, userNum, s.account, claim, count, hours, ip, source, kind, result);
}

// ── для стенда ──────────────────────────────────────────────────────────────
extern "C" __declspec(dllexport) void __stdcall P69_GetStats(P69_Stats* s)
{
    if (s) { memcpy(s, &g_stats, sizeof(g_stats)); }
}
// Только для стенда tools/stand_p69: имитированное событие журнала (источник + код вида) для сессии userNum — тот же путь, что
//   у P55 Report / P61 Report: P69_ResolveSession (mgr nullptr → CUserManager из кэша слота) → P69_OnViolation. Возврат — учётка
//   сессии (0 — неизвестна). На сервере не зовётся.
extern "C" __declspec(dllexport) int __stdcall P69_TestViolation(void* mgr, int userNum, int source, int kind, DWORD ip)
{
    P69_Session s;
    P69_ResolveSession(mgr, userNum, &s);
    P69_OnViolation(s, userNum, source, kind, ip, AcJournal::kNone);
    return s.account;
}
// Только для стенда: общие точки слота. op 1 — P69_OnClientPacket(mgr, slot), 2 — P69_SlotReset, 3 — P69_NoteSlotIp,
//   4 — вернуть P69_SlotIp, 5 — вернуть метку кика слота (учётку).
extern "C" __declspec(dllexport) DWORD __stdcall P69_TestSlot(int op, void* mgr, int slot)
{
    switch (op)
    {
    case 1: P69_OnClientPacket(mgr, slot); return 0;
    case 2: P69_SlotReset(slot); return 0;
    case 3: P69_NoteSlotIp(slot); return 0;
    case 4: return P69_SlotIp(slot);
    case 5: return (slot >= 0 && slot < kSlots) ? (DWORD)g_kickMark[slot] : 0;
    }
    return 0;
}

PatchResult P69_IntegrityAutoBlock()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode        = Config::GetInt (kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_exemptGm    = Config::GetBool(kSec, L"ExemptOperators", true);
    g_soulSession = Config::GetBool(kSec, L"SoulMateSessionAccount", true);
    g_kickOnBlock = Config::GetBool(kSec, L"KickOnBlock", true);
    g_logCounted  = Config::GetBool(kSec, L"LogCounted", true);
    const Stage def[kStages] = { { 20, 24 }, { 50, 720 }, { 51, -1 } };
    static const wchar_t* kCnt[kStages] = { L"Stage1Count", L"Stage2Count", L"Stage3Count" };
    static const wchar_t* kHrs[kStages] = { L"Stage1Hours", L"Stage2Hours", L"Stage3Hours" };
    bool stagesOk = true;
    for (int i = 0; i < kStages; ++i)
    {
        g_stage[i].count = Config::GetInt(kSec, kCnt[i], def[i].count);
        g_stage[i].hours = Config::GetInt(kSec, kHrs[i], def[i].hours);
        if (g_stage[i].count < 1)                                  { stagesOk = false; }
        if (i > 0 && g_stage[i].count <= g_stage[i - 1].count)     { stagesOk = false; }
        if (g_stage[i].hours == 0 || g_stage[i].hours < -1)        { stagesOk = false; }   // 0 истёк бы сразу
    }
    if (!stagesOk)
    {
        Log::Line(L"    P69: ступени в ini негодны (порог < 1, не по возрастанию или срок 0 / < -1) — взяты умолчания владельца 20/24, 50/720, 51/-1");
        for (int i = 0; i < kStages; ++i) { g_stage[i] = def[i]; }
    }

    wchar_t kinds[96];
    Config::GetStr(kSec, L"CountP55Kinds", L"1,2,4", kinds, ARRAYSIZE(kinds));
    ParseKinds(kinds, g_countP55);
    wchar_t chKinds[96];
    Config::GetStr(kSec, L"CountChannelKinds", L"56,57,58,59", chKinds, ARRAYSIZE(chKinds));
    ParseKinds(chKinds, g_countCh);
    g_countCh[0] = false; g_countCh[61] = false;   // сбой сервера / доставки — никогда (не вина игрока)

    wchar_t rel[MAX_PATH];
    Config::GetStr(kSec, L"CounterFile", L"..\\GameServer\\ConfigSet\\ac_integrity_counter.ini", rel, ARRAYSIZE(rel));
    wchar_t joined[MAX_PATH];
    if (rel[0] && rel[1] == L':') { lstrcpynW(joined, rel, MAX_PATH); }
    else { _snwprintf_s(joined, MAX_PATH, _TRUNCATE, L"%s%s", Config::BaseDir(), rel); }
    if (!GetFullPathNameW(joined, MAX_PATH, g_counterFile, nullptr)) { lstrcpynW(g_counterFile, joined, MAX_PATH); }
    wchar_t dir[MAX_PATH]; lstrcpynW(dir, g_counterFile, MAX_PATH);
    for (int i = lstrlenW(dir) - 1; i >= 0; --i) { if (dir[i] == L'\\' || dir[i] == L'/') { dir[i] = 0; break; } }
    if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES)
    {
        _snwprintf_s(g_counterFile, MAX_PATH, _TRUNCATE, L"%sConfigSet\\ac_integrity_counter.ini", Config::BaseDir());
    }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    if (!g_mutex) { g_mutex = CreateMutexW(nullptr, FALSE, L"Local\\AsdaPatch_P69_IntegrityCounter"); }

    // Источники: без гейта P47 (кэш CUserManager) P61 учётку не узнает; без P55/P61 считать нечего — строка в PatchLog.
    const bool p47 = Config::GetBool(L"P47_IdentityOperatorGate", L"Enabled", true);
    const bool p55 = Config::GetBool(L"P55_PacketValidator", L"Enabled", true);
    const bool p61 = Config::GetBool(L"P61_TrafficEncryption", L"Enabled", false);
    InterlockedExchange(&g_enabled, 1);
    Log::Line(L"    P69: Mode=%d (%s); ступени %d→%d ч, %d→%d ч, %d→%d ч; виды P55 [%s], канала [%s]; операторы %s; соулмейт → учётка сессии=%d; "
              L"KickOnBlock=%d; счётчик %s (секция [%s]); мьютекс %s",
              g_mode, g_mode == 1 ? L"БЛОК 2271" : L"только журнал «был бы блок»",
              g_stage[0].count, g_stage[0].hours, g_stage[1].count, g_stage[1].hours, g_stage[2].count, g_stage[2].hours,
              kinds, chKinds, g_exemptGm ? L"не считаются" : L"СЧИТАЮТСЯ", g_soulSession ? 1 : 0, g_kickOnBlock ? 1 : 0,
              g_counterFile, Section(), g_mutex ? L"есть" : L"НЕТ (только внутри процесса)");
    Log::Line(L"    P69: источники — P55 %s, P61 %s, гейт P47 (CUserManager слота для P61) %s",
              p55 ? L"включён" : L"ВЫКЛ", p61 ? L"включён" : L"выкл", p47 ? L"включён" : L"ВЫКЛ (нарушения канала — без учётки, не считаются)");
    return PatchResult::Applied;
}
