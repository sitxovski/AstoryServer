// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P110 — [ИСПРАВЛЕНИЕ] ДВА ПУЛА ОЧКОВ НАВЫКОВ: ОСНОВНЫЕ ДЕРЕВЬЯ (110) И ДЕРЕВО 4-Й ПРОФЕССИИ (05.11.2026, сессия job4-points;
//  жалоба игроков «4-я профессия: можно изучать навыки сверх лимита очков, уже −8; тратятся очки основного дерева»).
//  Документ: AstoryServer/Docs/GameServer/job4-point-pools-p110.md.
//
//  Очки навыков у сервера — ОДИН счёт: word CUser+0x19B (Charinfo.SkillPoint; 2·ур.−8: +2 за уровень sub_52E8A0, полный сброс
//  sub_52E900, изучение sub_52E9E0). Вложенное по деревьям — dword CUser+0xC024+4·дерево (сумма уровней навыков дерева: загрузка
//  sub_475290 «+= уровень», изучение sub_47E9B0 «++», сброс дерева sub_480F20 «−= уровень»). Дерево навыка — SkillInfo.sif +0xBD
//  (запись 209 б, dword_5F5E4C): 1–3 боец, 4–6 лучник, 7–9 маг — основные; 10/11/12 — дерево 4-й профессии бойца/лучника/мага.
//  5253 → Recv_SkillPoint_SkillActive@0x4774C0: отказы 5254 — 3 (очков < числа), 0 (навыка нет), 6 (вложено в дерево меньше
//  требования +0xBE), 2 (уровень на максимуме); дальше 0x4778B3 списывает очки и учит навык. ЛИМИТА ПО ДЕРЕВЬЯМ НЕТ.
//
//  ── ДЕФЕКТ ──
//  Клиент оригинала делит счёт на два пула (Skill_BuildTreeUI@0xE532E0, skillUiUpdatePointText@0xE56720): основные деревья —
//  110 очков (все очки до 59-го уровня: 2·59−8), дерево 4-й профессии — всё сверх 110 с 60-го уровня («(вложено всего + свободные)
//  − 110 − вложено в 4-ю»), и знает отказ 5254 код 8 — нотис 111701 «недостаточно очков навыка после 4-й профессии» (код 7 —
//  111700 «не для твоей профессии»). Стоковый сервер держал потолок уровня 59 (P29 поднял до 100), пула сверх 110 у него не было,
//  проверки — тоже. Итог на живом dev: навык 4-й профессии берёт очки основного пула (Player58: 4-я 30 при пуле 22 → «−8»),
//  основной навык — очки 4-й профессии (Player17: основные 132 при лимите 110).
//
//  ── ЧТО ДЕЛАЕТ P110 (14 байт, протокол не меняется: тот же 5254, коды из таблицы клиента оригинала) ──
//  Площадка 0x4778B3 (movsx ecx,[ebp-0DCh] / movzx edx,[ebp-0D1h] — начало списания, ПОСЛЕ всех отказов стока) → трамплин:
//  P110_Check(CUser [ebp-0D0h], навык [ebp-10h], число [ebp-0D1h], свободные [ebp-0DCh], userNum [ebp+8]).
//    • дерево навыка ∈ Job4Trees (10,11,12): остаток = (уровень ≥ MinLevel(60) ? основные + свободные − MainCap(110) − вложено в 4-ю : 0);
//      остаток < числа → отказ Job4RefuseCode (8 → 111701);
//    • дерево ∈ 1…9: остаток = MainCap − основные; меньше числа → отказ MainRefuseCode (3 → 2202);
//    • дерево 0 / вне таблицы / учётка ≤ ExemptMaxUserIndex — сток.
//  Отказ: [ebp-0CCh] = код, переход в стоковый блок отказа кода 2 после его `mov` (0x47787A: 5254 код, деструктор, выход) — ровно
//  то, что сток делает для своих отказов. Пропуск — две вытесненные команды и 0x4778C1.
//  Mode=1 — решение; Mode=0 — только журнал (сток). Журнал ac.other 171 (отказ 4-й профессии), 172 (отказ основного пула),
//  173 (исключение — сток); ограничитель JournalIntervalSec на (слот, вид). Log_Operator — строка на каждый отказ.
//  Откат: patches.ini [P110_Job4PointPools] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"P110_Job4PointPools";              // секция patches.ini

    // ── площадка: начало списания очков Recv_SkillPoint_SkillActive ───────────
    constexpr DWORD kSite    = 0x004778B3;                     // movsx ecx,[ebp-0DCh] ; movzx edx,[ebp-0D1h]
    constexpr DWORD kSiteLen = 14;                             // jmp rel32 + 9 nop
    const BYTE kSiteOrig[kSiteLen] =
    {
        0x0F, 0xBF, 0x8D, 0x24, 0xFF, 0xFF, 0xFF,              // movsx ecx, word ptr [ebp-0DCh]   (свободные очки)
        0x0F, 0xB6, 0x95, 0x2F, 0xFF, 0xFF, 0xFF               // movzx edx, byte ptr [ebp-0D1h]   (число очков запроса)
    };
    constexpr DWORD kBack = 0x004778C1;                        // sub ecx,edx ; mov [ebp-0DCh],cx — продолжение стока
    const BYTE kBackOrig[9] = { 0x2B, 0xCA, 0x66, 0x89, 0x8D, 0x24, 0xFF, 0xFF, 0xFF };

    // ── стоковый блок отказа кода 2 (0x477873): mov [ebp-0CCh],2 ; 5254 ; деструктор ; jmp выход ──
    //   P110 входит на 0x47787A (после mov кода): push 1 / push 0 / lea ecx,[ebp-0CCh] / … / call sub_4C28F0 / … / jmp 0x477B21.
    constexpr DWORD kRefuseBlock = 0x00477873;
    const BYTE kRefuseOrig[64] =
    {
        0xC6, 0x85, 0x34, 0xFF, 0xFF, 0xFF, 0x02, 0x6A, 0x01, 0x6A, 0x00, 0x8D, 0x8D, 0x34, 0xFF, 0xFF,
        0xFF, 0x51, 0x66, 0x8B, 0x55, 0x08, 0x52, 0x6A, 0x6F, 0x68, 0x86, 0x14, 0x00, 0x00, 0x8B, 0x85,
        0x20, 0xFF, 0xFF, 0xFF, 0x8B, 0x48, 0x04, 0xE8, 0x51, 0xB0, 0x04, 0x00, 0xC7, 0x45, 0xFC, 0xFF,
        0xFF, 0xFF, 0xFF, 0x8D, 0x4D, 0xA8, 0xE8, 0xC2, 0x1E, 0xFB, 0xFF, 0xE9, 0x6E, 0x02, 0x00, 0x00
    };
    constexpr DWORD kRefuseEntry = 0x0047787A;                 // push 1 — вход в блок отказа после записи кода

    // ── сосед: проверка требования дерева (код 6) 0x4777BA…0x47780F — сверка смещений CUser+0xC024 и SkillInfo +0xBD/+0xBE ──
    constexpr DWORD kTreeCheck = 0x004777BA;
    const BYTE kTreeCheckOrig[85] =
    {
        0x8A, 0x4D, 0xAC, 0x88, 0x4D, 0xD3, 0x0F, 0xB6, 0x55, 0xD3, 0x0F, 0xB6, 0x85, 0x2F, 0xFF, 0xFF,
        0xFF, 0x03, 0xD0, 0x88, 0x55, 0xD2, 0x0F, 0xBF, 0x4D, 0xF0, 0x69, 0xC9, 0xD1, 0x00, 0x00, 0x00,
        0x8B, 0x15, 0x4C, 0x5E, 0x5F, 0x00, 0x0F, 0xB6, 0x84, 0x0A, 0xBD, 0x00, 0x00, 0x00, 0x0F, 0xBF,
        0x4D, 0xF0, 0x69, 0xC9, 0xD1, 0x00, 0x00, 0x00, 0x8B, 0x15, 0x4C, 0x5E, 0x5F, 0x00, 0x0F, 0xB6,
        0x8C, 0x0A, 0xBE, 0x00, 0x00, 0x00, 0x8B, 0x95, 0x30, 0xFF, 0xFF, 0xFF, 0x39, 0x8C, 0x82, 0x24,
        0xC0, 0x00, 0x00, 0x7D, 0x40
    };

    // ── данные GameServer ──────────────────────────────────────────────────────
    constexpr DWORD kSkillInfo   = 0x005F5E4C;                 // dword_5F5E4C — записи SkillInfo.sif по 209 б
    constexpr DWORD kSkillCount  = 0x005F5ECC;                 // dword_5F5ECC — число записей
    constexpr int   kSkillRec    = 209;                        // шаг записи SkillInfo
    constexpr int   kOffRecTree  = 0xBD;                       // запись SkillInfo: дерево навыка
    constexpr int   kOffTreePts  = 0xC024;                     // CUser: вложено в дерево t — +0xC024 + 4·t
    constexpr int   kTreeSlots   = 16;                         // читаем деревья 0…15 (P89: 13–15 в данных пусты)
    constexpr int   kOffLevel    = 0x192;                      // CUser: уровень (u8; P29: потолок — тот же байт)
    constexpr int   kOffUserIdx  = 0x174;                      // CUser: UserIndex (учётка)
    constexpr int   kOffCharSlot = 0x18C;                      // CUser: слот персонажа
    constexpr int   kOpLearn     = 5253;                       // опкод запроса (для журнала)

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1; P110 — 171–173).
    constexpr BYTE kKindJob4   = 171;                          // отказ: пул 4-й профессии
    constexpr BYTE kKindMain   = 172;                          // отказ: основной пул (лимит MainCap)
    constexpr BYTE kKindFault  = 173;                          // исключение — решение стока

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);                                         // sub_569DF0
    FnSrvLog const pSrvLog = (FnSrvLog)Srv::kLog;

    int  g_mode        = 1;                                    // 1 — решение; 0 — только журнал (сток)
    int  g_mainCap     = 110;                                  // лимит основных деревьев
    int  g_minLevel    = 60;                                   // уровень, с которого есть пул 4-й профессии
    int  g_job4Code    = 8;                                    // код отказа 5254 для дерева 4-й профессии
    int  g_mainCode    = 3;                                    // код отказа 5254 для основного пула
    int  g_exemptMax   = 0;                                    // учётки ≤ этого номера — без проверки (0 — проверяются все)
    int  g_intervalSec = 60;                                   // ограничитель журнала (слот, вид), с
    bool g_job4Tree[kTreeSlots] = {};                          // деревья 4-й профессии
    bool g_mainTree[kTreeSlots] = {};                          // основные деревья
    P110_Stats g_stats = {};                                   // счётчики (экспорт P110_GetStats)
    DWORD g_lastJournal[4096][2] = {};                         // ограничитель: GetTickCount последней строки (слот & 4095, вид 0/1)

    // Разбор списка деревьев «a,b,c» в маску (вне 1…15 — пропуск).
    void ParseTrees(const wchar_t* s, bool* out)
    {
        for (int i = 0; i < kTreeSlots; ++i) { out[i] = false; }
        int v = -1;
        for (const wchar_t* p = s; ; ++p)
        {
            if (*p >= L'0' && *p <= L'9') { v = (v < 0 ? 0 : v * 10) + (*p - L'0'); continue; }
            if (v >= 1 && v < kTreeSlots) { out[v] = true; }
            v = -1;
            if (!*p) { break; }
        }
    }

    // Строка журнала ac.other (с ограничителем) + строка Log_Operator.
    void Report(BYTE kind, const BYTE* user, int userNum, int skill, int tree, int count, int points, int level,
                int mainPts, int job4Pts, int left, int code)
    {
        int account = AcJournal::kNone, slot = AcJournal::kNone;
        char name[24] = "?";
        __try
        {
            account = *(const int*)(user + kOffUserIdx);
            slot    = user[kOffCharSlot];
            lstrcpynA(name, (const char*)(user + Srv::kOffCharName), 20);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { lstrcpyA(name, "?"); }

        const int k = kind == kKindJob4 ? 0 : 1;
        const DWORD now = GetTickCount();
        DWORD* last = &g_lastJournal[userNum & 4095][k];
        const bool journal = kind == kKindFault || *last == 0 || (now - *last) >= (DWORD)g_intervalSec * 1000u;
        if (journal)
        {
            *last = now ? now : 1;
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kind);
            e.userNum   = (short)userNum;
            e.userIndex = account;
            e.charSlot  = slot;
            e.opcode    = kOpLearn;
            __try { e.ip = P47_PeerIpv4(userNum); }            // IP слота (сбой — без IP, решение не меняется)
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            __try { AcJournal::CopyName(e, user + Srv::kOffCharName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            e.v[0] = skill;                                    // item_code: навык запроса
            e.v[1] = kind == kKindJob4 ? job4Pts : mainPts;    // value1:    вложено в пул навыка
            e.v[2] = left;                                     // value2:    остаток пула (до запроса)
            char t[120];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P110 skill %d tree %d n %d free %d lv %d main %d job4 %d left %d code %d mode %d",
                        skill, tree, count, points, level, mainPts, job4Pts, left, code, g_mode);
            AcJournal::CopyText(e, t);
            if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
        }
        else { InterlockedIncrement(&g_stats.suppressed); }

        __try
        {
            const char* what = kind == kKindJob4 ? (g_mode ? "4th-job pool exceeded - refused" : "JOURNAL ONLY: 4th-job pool exceeded")
                             : kind == kKindMain ? (g_mode ? "main trees cap exceeded - refused" : "JOURNAL ONLY: main trees cap exceeded")
                             : "FAULT - stock decision";
            pSrvLog(Srv::kLogCatOperator, "P110 Job4PointPools: UserNum %d (UserIndex %d, CharN %s) Skill %d tree %d n %d free %d lv %d "
                    "main %d/%d job4 %d left %d code %d: %s", userNum, account == AcJournal::kNone ? -1 : account, name, skill, tree,
                    count, points, level, mainPts, g_mainCap, job4Pts, left, code, what);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ── C-часть трамплина площадки 0x4778B3 ──────────────────────────────────────────────────────────────────────────
//   user — CUser ([ebp-0D0h]); skill — навык (i16 [ebp-10h]); count — число очков запроса (u8 [ebp-0D1h]); points — свободные
//   (i16 [ebp-0DCh], сток уже проверил points ≥ count); userNum — a2 ([ebp+8]). Возврат: 0 — сток (списать и учить), иначе код 5254.
extern "C" int __stdcall P110_Check(BYTE* user, int skill, int count, int points, int userNum)
{
    InterlockedIncrement(&g_stats.seen);
    int tree = -1, level = -1, mainPts = 0, job4Pts = 0;
    __try
    {
        const BYTE* tbl = *(BYTE* const*)kSkillInfo;
        const int   n   = *(const int*)kSkillCount;
        if (!tbl || skill < 500 || skill >= n || !user) { return 0; }   // те же границы, что у стока (sub_4769C0: 500…n)
        tree = tbl[kSkillRec * skill + kOffRecTree];
        if (tree <= 0 || tree >= kTreeSlots || (!g_job4Tree[tree] && !g_mainTree[tree])) { return 0; }
        if (g_exemptMax > 0 && *(const int*)(user + kOffUserIdx) <= g_exemptMax) { InterlockedIncrement(&g_stats.exempt); return 0; }

        const int* pts = (const int*)(user + kOffTreePts);
        for (int t = 1; t < kTreeSlots; ++t)
        {
            if (g_mainTree[t]) { mainPts += pts[t]; }
            if (g_job4Tree[t]) { job4Pts += pts[t]; }
        }
        level = user[kOffLevel];
        int left = 0, code = 0;
        BYTE kind = 0;
        if (g_job4Tree[tree])
        {
            InterlockedIncrement(&g_stats.job4Seen);
            left = level >= g_minLevel ? mainPts + points - g_mainCap : 0;
            if (left > points) { left = points; }
            if (left < count) { code = g_job4Code; kind = kKindJob4; }
        }
        else
        {
            InterlockedIncrement(&g_stats.mainSeen);
            left = g_mainCap - mainPts;
            if (left > points) { left = points; }
            if (left < count) { code = g_mainCode; kind = kKindMain; }
        }
        if (!code) { return 0; }
        InterlockedIncrement(kind == kKindJob4 ? &g_stats.refusedJob4 : &g_stats.refusedMain);
        Report(kind, user, userNum, skill, tree, count, points, level, mainPts, job4Pts, left, code);
        return g_mode ? code : 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try { Report(kKindFault, user, userNum, skill, tree, count, points, level, mainPts, job4Pts, -1, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return 0;
    }
}

extern "C" __declspec(dllexport) void __stdcall P110_GetStats(P110_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_backAddr   = kBack;                                // продолжение стока (пропуск)
    DWORD g_refuseAddr = kRefuseEntry;                         // блок отказа стока (после записи кода)

    // Трамплин площадки 0x4778B3. Вход по jmp из Recv_SkillPoint_SkillActive: ebp — его кадр, стек — как на 0x4778B3 (те же
    //   глубина и содержимое, что на 0x47787A). Регистры на площадке не живые (сток сам грузит ecx/edx из кадра, eax — позже),
    //   pushad/popad сохраняют все; флаги не живые (sub на 0x4778C1 / push на 0x47787A).
    __declspec(naked) void CheckTrampoline()
    {
        __asm
        {
            pushad
            movsx eax, word ptr [ebp+0x08]           // a2 — userNum
            push  eax
            movsx eax, word ptr [ebp-0xDC]           // свободные очки
            push  eax
            movzx eax, byte ptr [ebp-0xD1]           // число очков запроса
            push  eax
            movsx eax, word ptr [ebp-0x10]           // навык
            push  eax
            push  dword ptr [ebp-0xD0]               // CUser*
            call  P110_Check
            test  eax, eax
            jnz   refuse
            popad
            movsx ecx, word ptr [ebp-0xDC]           // вытесненные команды стока
            movzx edx, byte ptr [ebp-0xD1]
            jmp   dword ptr [g_backAddr]             // 0x4778C1
        refuse:
            mov   byte ptr [ebp-0xCC], al            // код отказа 5254
            popad
            jmp   dword ptr [g_refuseAddr]           // 0x47787A — стоковый уход 5254 и выход
        }
    }
}

PatchResult P110_Job4PointPools()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_mainCap     = Config::GetInt(kSec, L"MainCap", 110);
    g_minLevel    = Config::GetInt(kSec, L"MinLevel", 60);
    g_job4Code    = Config::GetInt(kSec, L"Job4RefuseCode", 8);
    g_mainCode    = Config::GetInt(kSec, L"MainRefuseCode", 3);
    g_exemptMax   = Config::GetInt(kSec, L"ExemptMaxUserIndex", 0);
    g_intervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 60);
    wchar_t buf[128];
    Config::GetStr(kSec, L"Job4Trees", L"10,11,12", buf, ARRAYSIZE(buf));
    ParseTrees(buf, g_job4Tree);
    Config::GetStr(kSec, L"MainTrees", L"1,2,3,4,5,6,7,8,9", buf, ARRAYSIZE(buf));
    ParseTrees(buf, g_mainTree);
    for (int t = 0; t < kTreeSlots; ++t) { if (g_job4Tree[t]) { g_mainTree[t] = false; } }   // дерево — в одном пуле
    if (g_mainCap < 0 || g_mainCap > 32767) { g_mainCap = 110; }
    if (g_job4Code < 1 || g_job4Code > 255) { g_job4Code = 8; }
    if (g_mainCode < 1 || g_mainCode > 255) { g_mainCode = 3; }
    if (g_intervalSec < 0) { g_intervalSec = 0; }

    const Site sites[] =
    {
        { kSite,        kSiteOrig,      sizeof(kSiteOrig)      },
        { kBack,        kBackOrig,      sizeof(kBackOrig)      },
        { kRefuseBlock, kRefuseOrig,    sizeof(kRefuseOrig)    },
        { kTreeCheck,   kTreeCheckOrig, sizeof(kTreeCheckOrig) },
    };
    if (!VerifyAllSites(L"P110", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(kSite, &CheckTrampoline, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P110: Recv_SkillPoint_SkillActive @0x%08X (14 б) -> трамплин 0x%08X: пулы очков — основные деревья ≤ %d, "
              L"4-я профессия (с ур. %d) = основные + свободные − %d − вложено; отказ 5254 код %d (4-я) / %d (основные); Mode=%d (%s); "
              L"исключение учёток ≤ %d; журнал ac.other 171/172/173 (раз в %d с на слот)", kSite, (DWORD)&CheckTrampoline,
              g_mainCap, g_minLevel, g_mainCap, g_job4Code, g_mainCode, g_mode, g_mode ? L"решение" : L"только журнал",
              g_exemptMax, g_intervalSec);
    return PatchResult::Applied;
}
