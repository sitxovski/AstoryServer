// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P59 — ★ ЖУРНАЛ РЕДКОГО ДРОПА С МОНСТРОВ И ПОДБОРА (П4 плана 04_detection_response.md §6.2; волна A6, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Документ: `AstoryServer/Docs/GameServer/rare-drop-journal-p59.md`.
//
//  Сток дроп с монстров НЕ журналирует: NpcServer присылает список добычи (опкоды 0x206F обычный / 0x1F4A рейд,
//  диспетчер GameServer.c:20654/20714) → recvBattleServerFromItemDrop@0x4C9370 (GS:79972) → Search_AddMonsterMapItem
//  @0x420120 кладёт предметы на карту; строк лога нет (только отказ «iSellType Error»). Подбор 5012 CharItemPicking
//  пишет в Log_Item лишь по P11 (анонс 6131), сток — нет.
//  Площадка A — ВХОД recvBattleServerFromItemDrop (пролог 9 б `55 8BEC 81EC9C000000`, возврат 0x4C9379): тело
//  пакета (+9, 0x82 б): {i16 userNum убийцы, i16 индекс монстра, i16 клетка X, i16 клетка Z, int код[20],
//  i16 количество[20], i16 золото} — ровно то, что сток читает (GS:79979-80037). Для каждого кода из таблицы
//  «редкого» (та же, что у P01/P11: announce_codes.txt, грейд ≥ 3 — общая точка P11_IsRareCode) — строка в канал
//  LogChannel (29 = Log_UserEvent, папка существует, в стоке пишут только два обработчика 61xx) и журнал P53
//  ac.other вид 4 (item_code, value1 = количество, value2 = индекс монстра, detail = имя монстра из таблицы
//  Monster.ai 0x5F5F80 (запись 44 б: +0 индекс, +4 имя), клетка, рейд).
//  Площадка B — подбор: общая точка P11 (AsdaOnPickup, эпилог CharItemPicking 0x4D5E61): P11 ставит трамплин,
//  если нужен ему ИЛИ нам (P59_PickupWanted), и зовёт P59_OnPickup — ac.other вид 5.
//  Ограничитель: не больше MaxPerMinute строк в минуту на процесс (sub_569DF0 — одна глобальная секция записи,
//  план §6: только редкие события); сверх — считается и уходит в repeat_suppressed следующей строки.
//  Переходов внутрь площадки A нет (verify_p57.py), с P01…P58 не пересекается.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>   // [fix13] _snprintf_s / _snwprintf_s — ограниченные форматтеры
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P59_RareDropJournal";

    bool g_enabled = true;
    bool g_pickup  = true;
    int  g_channel = 29;
    int  g_maxPerMinute = 120;

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);         // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    constexpr DWORD kMonsterTable = 0x005F5F80;   // Monster.ai: запись 44 б (+0 WORD индекс, +4 имя 40 б)
    constexpr int   kMonsterRec   = 44;
    constexpr int   kMonsterMax   = 4096;
    constexpr int   kOffUserIndex = 0x174;
    constexpr int   kOffName      = 0x178;
    constexpr int   kOffSlot      = 0x18C;
    constexpr int   kOffMap       = 0x1C;

    volatile LONG g_drops = 0, g_pickups = 0, g_suppressed = 0;
    DWORD g_minuteStart = 0; int g_minuteCount = 0; int g_pendingSuppressed = 0;
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    // Ограничитель на процесс. Возвращает число подавленных перед этой строкой (−1 = подавить эту).
    int Allow()
    {
        const DWORD now = GetTickCount();
        int sup = 0;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        if (g_minuteStart == 0 || now - g_minuteStart >= 60000) { g_minuteStart = now; g_minuteCount = 0; }
        if (g_maxPerMinute > 0 && g_minuteCount >= g_maxPerMinute) { ++g_pendingSuppressed; InterlockedIncrement(&g_suppressed); sup = -1; }
        else { ++g_minuteCount; sup = g_pendingSuppressed; g_pendingSuppressed = 0; }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        return sup;
    }

    void MonsterName(int idx, char* out, int cch)
    {
        out[0] = 0;
        if (idx < 0 || idx >= kMonsterMax) { return; }
        __try
        {
            const BYTE* rec = (const BYTE*)(kMonsterTable + kMonsterRec * idx);
            if (*(const WORD*)rec != (WORD)idx) { return; }
            int n = 0;
            while (n < 39 && n < cch - 1 && rec[4 + n]) { out[n] = (char)rec[4 + n]; ++n; }
            out[n] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
    }

    void Fill(AcJournal::Event& e, BYTE kind, void* mgr, int userNum, int opcode)
    {
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = P47_PeerIpv4(userNum);
        if (mgr && userNum >= 0 && userNum < 0x226)
        {
            const BYTE* user = pGetUser(mgr, nullptr, (short)userNum);
            if (user)
            {
                __try
                {
                    e.userIndex = *(const int*)(user + kOffUserIndex);
                    e.charSlot  = user[kOffSlot];
                    AcJournal::CopyName(e, user + kOffName);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    const BYTE* UserOf(void* mgr, int userNum)
    {
        return (mgr && userNum >= 0 && userNum < 0x226) ? pGetUser(mgr, nullptr, (short)userNum) : nullptr;
    }
}

// Нужен ли трамплин подбора P11 ради нас (зовёт P11 при установке).
bool P59_PickupWanted()
{
    return Config::GetBool(kSec, L"Enabled", true) && Config::GetBool(kSec, L"Pickup", true);
}

// Подбор (из P11 AsdaOnPickup, эпилог CharItemPicking при успехе).
void P59_OnPickup(void* mgr, int userNum, int itemCode)
{
    if (!g_enabled || !g_pickup || itemCode <= 0) { return; }
    __try
    {
        if (!P11_IsRareCode(itemCode)) { return; }
        InterlockedIncrement(&g_pickups);
        const int sup = Allow();
        if (sup < 0) { return; }
        const BYTE* user = UserOf(mgr, userNum);
        pSrvLog(g_channel, "P59 RarePickup\tItem %d\tUserNum %d\tUserIndex %d\tCharN %s\tMap %d%s",
                itemCode, userNum, user ? *(const int*)(user + kOffUserIndex) : -1, user ? (const char*)(user + kOffName) : "?",
                user ? (int)*(const short*)(user + kOffMap) : -1, sup ? "\t(suppressed before)" : "");
        AcJournal::Event e;
        Fill(e, 5, mgr, userNum, 5012);
        e.v[0] = itemCode; e.v[1] = 1; e.v[2] = user ? (int)*(const short*)(user + kOffMap) : AcJournal::kNone;
        e.suppressed = sup;
        AcJournal::CopyText(e, "pickup");
        AcJournal::Push(e);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Дроп с монстра (вход recvBattleServerFromItemDrop). raid = третий аргумент стока (0 обычный 0x206F, 1 рейд 0x1F4A).
extern "C" void __stdcall P59_OnMonsterDrop(void* mgr, const BYTE* pkt, int raid)
{
    if (!g_enabled || !pkt) { return; }
    __try
    {
        const BYTE* b = pkt + 9;
        const int userNum   = *(const short*)(b + 0);
        const int monster   = *(const short*)(b + 2);
        const int tileX     = *(const short*)(b + 4);
        const int tileZ     = *(const short*)(b + 6);
        const int*   codes  = (const int*)(b + 8);
        const short* counts = (const short*)(b + 88);
        const BYTE* user = UserOf(mgr, userNum);
        char mname[48] = "";
        bool named = false;
        for (int i = 0; i < 20; ++i)
        {
            const int code = codes[i];
            if (code <= 0) { break; }                    // как сток: первый ≤ 0 завершает список
            if (!P11_IsRareCode(code)) { continue; }
            InterlockedIncrement(&g_drops);
            const int sup = Allow();
            if (sup < 0) { continue; }
            if (!named) { MonsterName(monster, mname, sizeof(mname)); named = true; }
            const int count = counts[i] > 0 ? counts[i] : 1;
            pSrvLog(g_channel, "P59 RareDrop\tItem %d x%d\tMonster %d (%s)\tTile %d,%d\tKiller UserNum %d UserIndex %d CharN %s\tRaid %d%s",
                    code, count, monster, mname[0] ? mname : "?", tileX, tileZ, userNum,
                    user ? *(const int*)(user + kOffUserIndex) : -1, user ? (const char*)(user + kOffName) : "?", raid,
                    sup ? "\t(suppressed before)" : "");
            AcJournal::Event e;
            Fill(e, 4, mgr, userNum, raid ? 0x1F4A : 0x206F);
            e.v[0] = code; e.v[1] = count; e.v[2] = monster;
            e.suppressed = sup;
            // [fix13, 2026-10-13] было detail[64] + wsprintfA: имя монстра до 39 б + « tile x,z raid n» до 36 б — переполнение
            // на крайних значениях. Теперь 128 б и _snprintf_s с усечением (ноль гарантирован).
            char detail[128];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s tile %d,%d raid %d", mname[0] ? mname : "monster ?", tileX, tileZ, raid);
            AcJournal::CopyText(e, detail);
            AcJournal::Push(e);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

extern "C" void __stdcall P59_GetStats(int* drops, int* pickups, int* suppressed)
{
    if (drops) { *drops = g_drops; } if (pickups) { *pickups = g_pickups; } if (suppressed) { *suppressed = g_suppressed; }
}

namespace
{
    DWORD g_ret = 0x004C9379;   // после вытесненного пролога

    // Вход recvBattleServerFromItemDrop (thiscall: ecx = CUserManager, [esp+4] = пакет, [esp+8] = рейд).
    __declspec(naked) void DropStub()
    {
        __asm
        {
            pushad                              // +32
            push  dword ptr [esp+40]            // рейд
            push  dword ptr [esp+40]            // пакет (после push сместился на 4)
            push  ecx                           // CUserManager
            call  P59_OnMonsterDrop             // __stdcall, 12 б
            popad
            push  ebp                           // вытеснено
            mov   ebp, esp                      // вытеснено
            sub   esp, 0x9C                     // вытеснено
            jmp   dword ptr [g_ret]
        }
    }

    const BYTE kOrig[9]   = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x9C, 0x00, 0x00, 0x00 };   // 0x4C9370
    const BYTE kNbRet[5]  = { 0xA1, 0xF0, 0x63, 0x5A, 0x00 };                           // 0x4C9379 mov eax,[security_cookie]
}

PatchResult P59_RareDropJournal()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_pickup       = Config::GetBool(kSec, L"Pickup", true);
    g_channel      = Config::GetInt(kSec, L"LogChannel", 29);
    g_maxPerMinute = Config::GetInt(kSec, L"MaxPerMinute", 120);
    if (g_channel < 0 || g_channel > 60) { g_channel = 29; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }

    const int ranges = P11_EnsureGradeTable();
    if (ranges <= 0)
    {
        Log::Line(L"    P59: ! таблица редких кодов пуста (announce_codes.txt) — журнал писать нечего, патч не ставится");
        return PatchResult::Failed;
    }
    const Site sites[] =
    {
        { 0x004C9370, kOrig,  sizeof(kOrig)  },
        { 0x004C9379, kNbRet, sizeof(kNbRet) },
    };
    if (!VerifyAllSites(L"P59", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(0x004C9370, &DropStub, 9)) { return PatchResult::Failed; }
    Log::Line(L"    P59: дроп с монстров → канал %d + ac.other вид 4; подбор=%d (через трамплин P11); таблица редких: %d диапазонов; ≤%d строк/мин",
              g_channel, g_pickup ? 1 : 0, ranges, g_maxPerMinute);
    return PatchResult::Applied;
}
