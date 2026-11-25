// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P95 — [ИСПРАВЛЕНИЕ] ВСКРЫТИЕ КОРОБОК И ПРЕДМЕТЫ С МИНИМАЛЬНЫМ УРОВНЕМ (баги игроков 29.10, волна bugs6).
//  Документ: AstoryServer/Docs/GameServer/item-use-guard-p95.md.
//
//  ── ДЕФЕКТ 1 (6096 Recv_OpenPackageItem@0x55A820, GameServer.c:133373–133520) ──
//  Клиент сам выбирает ячейки-приёмники для позиций состава коробки (контейнер u8 @тело+10+3i, слот i16 @+11+3i) по СВОЕЙ
//  таблице предметов, а сервер сверяет их по СВОЕЙ: контейнер сервера (sub_55B7F0@0x55B7F0) — предмет item_list:
//  (+7 == 4 && +36 == 1) ? 2 (расходники, 60) : 1 (сумка, 30); самоцвет (sub_532AE0) → 2; особый (sub_532B10) → 1.
//  Таблицы клиента и сервера — разные версии, поэтому часть коробок отказывает кодом 11 («контейнер не тот») даже на пустом
//  инвентаре, а при стопках/рассинхроне — кодом 7 («Information error in empty inventory»). Дыра стока: у самоцветов и
//  особых предметов пустота ячейки не проверяется вовсе (блок проверки — внутри `if (sub_532A90(код))`), sub_55B7F0 кладёт
//  в запрошенный слот — при рассинхроне затирание вещи.
//  ── ДЕФЕКТ 2 (уровень) [дефект оригинала: эталон клиента уровень тоже не проверяет] ──
//  Мин. уровень (+8 записи 71 б) не проверяется ни у коробки (6096), ни у бустера-гачи (5468 Recv_GachaItemUse@0x4F48C0,
//  GameServer.c:94248), ни у расходника (5028 CharSpendItemUse@0x4D8C40, GameServer.c:85763). Пример: «Booster-Pig Pang
//  (3 days)» 28229 (тип 13/66, мин. уровень 10) открывается на 4-м. Экипировка и функциональные 5450 — со стоковой
//  проверкой, не трогаются.
//
//  ── ЧТО ДЕЛАЕТ P95 (3 площадки, трамплины; протокол не меняется) ──
//  S1+S2 6096 @0x55AB2A `mov dword [ebp-3FCh],0` (i = 0 — вход цикла позиций; сюда приходят только после всех стоковых проверок
//     коробки, коды 2…9): P95_OnPackage(ebp):
//     S2 (LevelGate) — мин. уровень коробки > уровня персонажа (sub_5325F0 = CUser+0x192) → [ebp-3C1h] := PackageLevelCode,
//        стоковое тело отказа LABEL_43 0x55AE56 (6097 тем же путём, что коды 2…11). Вид 141.
//     S1 (Placement) — запрос клиента приводится к правилу сервера ПРЯМО в теле [ebp-3ECh], позиция за позицией (код из
//        PackageItem_Table dword_5F5E68 + 34·v18 + 4 + 6i, как сток): контейнер C — правило сервера (выше); стопочный по правилу
//        стока (+7 == 4 && +36 == 1 && +35 == 1 && +26 != 10) и стопка этого кода есть в расходниках (sub_4D6CE0, как сток) →
//        (2, слот стопки); иначе запрошенная ячейка, если контейнер == C, слот в границах, пуста (sub_4D6910) и не занята
//        другими позициями этого же запроса; иначе первая такая свободная в C (два прохода: сначала остаются все годные запросы,
//        потом раздаются свободные ячейки — переносится минимум позиций). Свободной нет → [ebp-3C1h] := 7 и LABEL_43
//        (честное «нет места»; у самоцветов/особых сток бы затёр вещь). Код вне всех таблиц — позиция не трогается (сток: код 10).
//        Цикл стока после этого проходит проверки 7/11 и sub_55B7F0 кладёт в выбранную ячейку; ответ 6097 несёт каждую запись
//        со своими +4/+5 — клиент порта раскладывает по ним (AsdaInventorySubsystem::ApplyPackageResult). Вид 140.
//  S3 5468 @0x4F4BC5 `mov eax,[ebp-84h]` (после стоковых отказов 1/5, до чтения индекса гачи и броска): мин. уровень бустера >
//     уровня → [ebp-0D0h] := GachaLevelCode, общий хвост отказа 0x4F563E (5469, 68 б). Вид 142.
//  S4 5028 @0x4D8F30 `mov eax,[ebp-9Ch]` (сразу после стоковой проверки «item_list, тип 11», до отката +59 и действий):
//     мин. уровень > уровня → стоковое тело LABEL_196 0x4DA8DD (5029 код 0 «You cannot use this item»). Вид 143.
//  Исключение при сверке — вид 144, решение стока. Журнал ac.other и строка лога канала LogChannel — не чаще JournalIntervalSec
//  на (слот, вид). Placement=0 / LevelGate=0 — поведение стока по своей части; Enabled=0 — площадки не ставятся.
//  Кадры: 6096 this=[ebp-418h], pUser=[ebp-3F4h], тело v19=[ebp-3ECh], v18=[ebp-3F0h] (i16), запись коробки a5=[ebp-164h],
//  код v23=[ebp-3C1h]; 5468 this=[ebp-194h], запись бустера a5=[ebp-84h], ответ v36=[ebp-0D0h]; 5028 this=[ebp-4E8h], запись
//  Src=[ebp-9Ch]; userNum = [ebp+8] у всех.
//  С P62 (0x55AE4F call sub_5646C0, сосед 0x55ACC6), P63 (0x55A835/0x55AE4F, 0x4F48D3/0x4F55FC), P11 (0x4F5666), P66 (0x4D9BEB)
//  байтами не пересекается (verify_p95). Отказы P95 уходят до отправки в БД — замок P63 не ставится.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <string.h>

// P96: размер сумки (60 если P96 встал, иначе 30) — из p96_inventory_x2.cpp
extern "C" int __stdcall P96_BagSize();

namespace
{
    const wchar_t* kSec = L"P95_ItemUseGuard";

    constexpr BYTE kKindPlaced  = 140;   // ac.other 140 — позиция коробки переразмещена по правилу сервера / нет места
    constexpr BYTE kKindPkgLv   = 141;   // ac.other 141 — коробка ниже мин. уровня
    constexpr BYTE kKindGachaLv = 142;   // ac.other 142 — бустер-гача ниже мин. уровня
    constexpr BYTE kKindSpendLv = 143;   // ac.other 143 — расходник ниже мин. уровня
    constexpr BYTE kKindFault   = 144;   // ac.other 144 — исключение при сверке, решение стока
    constexpr int  kKindBase = 140, kKindCount = 5;

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kOffUserIndex = 0x174;       // учётка (sub_5324F0)
    constexpr int   kOffName      = 0x178;       // имя персонажа cp1251
    constexpr int   kOffSlot      = 0x18C;       // слот персонажа
    constexpr int   kMaxUsers     = 0x226;       // 550 слотов (sub_5328F0)
    constexpr DWORD kItemTablePtr = 0x005F5E98;  // dword_5F5E98 → Item_Table, запись 71 б, индекс (код − 20551)
    constexpr DWORD kPkgTablePtr  = 0x005F5E68;  // dword_5F5E68 → PackageItem_Table, запись 34 б: +0 idx, 5 × (+4+6i код i32, +8+6i кол-во i16)
    constexpr int   kItemRec = 71, kItemBase = 20551, kPkgRec = 34;

    typedef int  (__fastcall *PFN_Empty)(void* self, void* edx, int userNum, int type, int slot);              // sub_4D6910 thiscall(i16,i16,i16) ret 0Ch
    typedef int* (__fastcall *PFN_FindCode)(void* self, void* edx, int* out, int userNum, int type, int code); // sub_4D6CE0 thiscall(int*,i16,i16,int) ret 10h
    typedef char (__fastcall *PFN_Level)(void* self, void* edx, int userNum);                                  // sub_5325F0 thiscall(i16) ret 4 — CUser+0x192
    typedef BOOL (__cdecl    *PFN_CodeIs)(int code);                                                           // sub_532A90 / sub_532AE0 / sub_532B10
    typedef void (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                                      // sub_569DF0
    PFN_Empty    const pEmpty   = (PFN_Empty)0x004D6910;
    PFN_FindCode const pFind    = (PFN_FindCode)0x004D6CE0;
    PFN_Level    const pLevel   = (PFN_Level)0x005325F0;
    PFN_CodeIs   const pIsItem  = (PFN_CodeIs)0x00532A90;   // предмет item_list 20551…dword_5F5EAC
    PFN_CodeIs   const pIsGem   = (PFN_CodeIs)0x00532AE0;   // самоцвет 7001…dword_5F5EA0
    PFN_CodeIs   const pIsFunc  = (PFN_CodeIs)0x00532B10;   // особый (Function_Table) 1…dword_5F5EA4
    PFN_SrvLog   const pSrvLog  = (PFN_SrvLog)Srv::kLog;

    // ── настройки ────────────────────────────────────────────────────────────
    bool g_enabled   = false;
    bool g_placement = true;          // S1
    bool g_levelGate = true;          // S2–S4
    int  g_pkgCode   = 3;             // S2: код 6097 (сток: 3 — «коробка не найдена»; клиент 99313)
    int  g_gachaCode = 3;             // S3: код 5469 (клиент 13109 «Fail to use booster item»)
    int  g_journalIntervalSec = 10;
    int  g_logChannel = 1;            // 1 = Log_Item (как P62)

    P95_Stats g_stats = {};

    // Ограничитель: одна строка на (слот, вид) за JournalIntervalSec; смена учётки в слоте — заново.
    struct Sess { int userIndex; DWORD last[kKindCount]; int sup[kKindCount]; };
    Sess g_sess[kMaxUsers] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    const BYTE* ItemRec(int code) { return *(const BYTE**)kItemTablePtr + kItemRec * (code - kItemBase); }

    bool Allow(int userNum, const BYTE* user, BYTE kind, int* supOut)
    {
        *supOut = 0;
        const int k = kind - kKindBase;
        if (userNum < 0 || userNum >= kMaxUsers || k < 0 || k >= kKindCount) { return true; }
        int ui = 0;
        __try { ui = user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { ui = 0; }
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool allow = true;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        if (g_journalIntervalSec > 0 && s.last[k] && now - s.last[k] < (DWORD)g_journalIntervalSec * 1000) { ++s.sup[k]; allow = false; }
        else { s.last[k] = now; *supOut = s.sup[k]; s.sup[k] = 0; }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        return allow;
    }

    // Строка стокового лога + ac.other (под ограничителем). v0 → item_code, v1 → value1, v2 → value2.
    void Report(BYTE kind, int opcode, const BYTE* user, int userNum, int v0, int v1, int v2, const char* detail, const char* logText)
    {
        int sup = 0;
        if (!Allow(userNum, user, kind, &sup)) { InterlockedIncrement(&g_stats.suppressed); return; }
        int ui = -1;
        const char* name = "?";
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); name = (const char*)(user + kOffName); } }
        __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; name = "?"; }
        __try
        {
            pSrvLog(g_logChannel, "P95 ItemUseGuard: %d UserNum %d UserIndex %d %s: %s%s", opcode, userNum, ui, name, logText,
                    sup ? " (+suppressed)" : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = (userNum >= 0 && userNum < kMaxUsers) ? P47_PeerIpv4(userNum) : 0;
        e.suppressed = sup;
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
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    BYTE* UserOf(void* mgr, int userNum)
    {
        __try { return (userNum >= 0 && userNum < kMaxUsers) ? *(BYTE**)((BYTE*)mgr + 0x40 + 4 * userNum) : nullptr; }   // sub_5324A0
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    // Мин. уровень (+8) записи item_list против уровня персонажа (sub_5325F0). 1 — ниже минимума.
    bool BelowMin(void* mgr, int userNum, int code, int* minOut, int* lvOut)
    {
        *minOut = ItemRec(code)[8];
        *lvOut = (BYTE)pLevel(mgr, nullptr, userNum);
        return *minOut > *lvOut;
    }

    // ── S1: раскладка позиций коробки по правилу сервера. Возврат: 0 — продолжать сток, 7 — «нет места» (отказ). ──
    int Place(BYTE* ebp, void* mgr, const BYTE* user, int userNum, int boxCode)
    {
        BYTE* body = ebp - 0x3EC;
        const int n = body[6];                                   // 1…5 (сток проверил, код 6)
        const short pkIdx = *(const short*)(ebp - 0x3F0);        // v18 (сток проверил, коды 8/9)
        const BYTE* pk = *(const BYTE**)kPkgTablePtr + kPkgRec * pkIdx;
        int usedC[5], usedS[5], nUsed = 0;                       // ячейки, уже отданные позициям этого запроса
        int cont[5] = {}, newC[5], newS[5];                      // контейнер сервера и итог по позиции (−1 — ещё нет)
        int moved = 0, firstI = -1, firstCode = 0, firstReq = 0, firstNew = 0;
        char list[160]; list[0] = 0; int lo = 0;
        auto taken = [&](int c, int s) { for (int k = 0; k < nUsed; ++k) { if (usedC[k] == c && usedS[k] == s) { return true; } } return false; };
        // ★ P100 (01.11.2026): складываемый спецпредмет (ключ charge_groups > 0) раскладывается ЗДЕСЬ, по правилу сервера и
        //   независимо от присланной ячейки: стопка ключа (первая по Posx, старое + в полёте + заряды ≤ Cap) — туда, ячейка не
        //   занимается; стопки нет — новая ячейка (присланная, если пуста, не занята позициями запроса и не в резерве другого
        //   ключа; иначе первая такая свободная), следующие позиции того же ключа сливаются в неё. Добавка позиции = заряды кода
        //   (sub_55B7F0: количество позиции для спецпредмета сток игнорирует). P100 не активен — как раньше.
        const bool p100 = P100_Active() != 0;
        const DWORD batch = p100 ? P100_BeginBatch() : 0;
        if (p100) { P100_BoxPlace(mgr, userNum, 0, -1, batch); }   // сброс отметок общих ячеек (для P62) этого персонажа
        // Проход 1: стопка → слот стопки; годная запрошенная ячейка (контейнер сервера, в границах, пуста, не занята) — остаётся.
        for (int i = 0; i < n && i < 5; ++i)
        {
            newC[i] = newS[i] = -1;
            const int code = *(const int*)(pk + 4 + 6 * i);
            const int rc = body[10 + 3 * i];
            const int rs = *(const short*)(body + 11 + 3 * i);
            bool stack = false;
            if (pIsItem(code))
            {
                const BYTE* r = ItemRec(code);
                cont[i] = (r[7] == 4 && r[36] == 1) ? 2 : 1;
                stack = cont[i] == 2 && r[35] == 1 && r[26] != 10;
            }
            else if (pIsGem(code)) { cont[i] = 2; }
            else if (pIsFunc(code))
            {
                cont[i] = 1;
                if (p100 && P100_KeyOf(code) > 0 && P100_SiteOn(5))
                {
                    const int ms = P100_BoxPlace(mgr, userNum, code, i, batch);
                    if (ms >= 0) { newC[i] = 1; newS[i] = ms; continue; }   // слияние в стопку ключа
                    const int key = P100_KeyOf(code), size = P96_BagSize();
                    // резерв в полёте другого ключа — предпочтение, не запрет: нет других свободных — берётся и такая (как сток)
                    auto fits = [&](int s, bool soft) { return s >= 0 && s < size && !taken(1, s) && pEmpty(mgr, nullptr, userNum, 1, s) && (soft || !P100_IsReserved(mgr, userNum, s, key, code)); };
                    int pick = (rc == 1 && fits(rs, false)) ? rs : -1;
                    for (int s = 0; pick < 0 && s < size; ++s) { if (fits(s, false)) { pick = s; } }
                    for (int s = 0; pick < 0 && s < size; ++s) { if (fits(s, true)) { pick = s; } }
                    if (pick < 0)
                    {
                        InterlockedIncrement(&g_stats.noRoom);
                        P100_CancelBatch(userNum, batch);
                        char d[64], t[160];
                        _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 6096 box %d pos %d code %d no room in 1 -> 7", boxCode, i, code);
                        _snprintf_s(t, sizeof(t), _TRUNCATE, "box %d position %d charge item %d: no stack of its key and no free bag cell -> REFUSE 6097 code 7",
                                    boxCode, i, code);
                        Report(kKindPlaced, 6096, user, userNum, code, rc * 1000 + rs, -1, d, t);
                        return 7;
                    }
                    P100_ReserveNew(mgr, userNum, code, P100_Charges(code), -1, pick, batch);   // Owner — по привязке (sub_55B7F0)
                    newC[i] = 1; newS[i] = pick;
                    usedC[nUsed] = 1; usedS[nUsed] = pick; ++nUsed;
                    continue;
                }
            }
            else { cont[i] = 0; InterlockedIncrement(&g_stats.unknownCode); continue; }   // сток: код 10
            if (stack)
            {
                int out[2] = { -1, -65536 };
                pFind(mgr, nullptr, out, userNum, 2, code);
                if (out[1] >= 0) { newC[i] = 2; newS[i] = (short)(out[1] >> 16); continue; }   // как сток: v12 >= 0 → слот = HIWORD
            }
            const int size = cont[i] == 1 ? P96_BagSize() : 60;
            if (rc == cont[i] && rs >= 0 && rs < size && !taken(rc, rs) && pEmpty(mgr, nullptr, userNum, rc, rs))
            {
                newC[i] = rc; newS[i] = rs;
                usedC[nUsed] = rc; usedS[nUsed] = rs; ++nUsed;
            }
        }
        // Проход 2: остальным — первая свободная ячейка контейнера сервера, не отданная другим позициям запроса.
        for (int i = 0; i < n && i < 5; ++i)
        {
            if (!cont[i] || newC[i] >= 0) { continue; }
            const int C = cont[i], size = C == 1 ? P96_BagSize() : 60;
            for (int s = 0; s < size; ++s) { if (!taken(C, s) && pEmpty(mgr, nullptr, userNum, C, s)) { newC[i] = C; newS[i] = s; break; } }
            if (newC[i] < 0)
            {
                const int code = *(const int*)(pk + 4 + 6 * i);
                const int rc = body[10 + 3 * i], rs = *(const short*)(body + 11 + 3 * i);
                InterlockedIncrement(&g_stats.noRoom);
                char d[64], t[160];
                _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 6096 box %d pos %d code %d no room in %d -> 7", boxCode, i, code, C);
                _snprintf_s(t, sizeof(t), _TRUNCATE, "box %d position %d code %d: no free cell in container %d (requested %d,%d) -> REFUSE 6097 code 7",
                            boxCode, i, code, C, rc, rs);
                Report(kKindPlaced, 6096, user, userNum, code, rc * 1000 + rs, -1, d, t);
                if (p100) { P100_CancelBatch(userNum, batch); }   // ★ P100: отказ до БД — снять резервы/добавки запроса
                return 7;
            }
            usedC[nUsed] = newC[i]; usedS[nUsed] = newS[i]; ++nUsed;
        }
        // Запись в тело запроса (только после того, как место нашлось всем — при отказе тело не меняется).
        for (int i = 0; i < n && i < 5; ++i)
        {
            if (!cont[i]) { continue; }
            const int code = *(const int*)(pk + 4 + 6 * i);
            BYTE& rc = body[10 + 3 * i];
            short& rs = *(short*)(body + 11 + 3 * i);
            if (newC[i] != rc || newS[i] != rs)
            {
                ++moved;
                if (firstI < 0) { firstI = i; firstCode = code; firstReq = rc * 1000 + rs; firstNew = newC[i] * 1000 + newS[i]; }
                if (lo < (int)sizeof(list) - 1)
                {
                    const int w = _snprintf_s(list + lo, sizeof(list) - lo, _TRUNCATE, "%s#%d %d (%d,%d)->(%d,%d)", lo ? "; " : "", i, code, rc, rs, newC[i], newS[i]);
                    lo = w < 0 ? (int)sizeof(list) - 1 : lo + w;
                }
                rc = (BYTE)newC[i]; rs = (short)newS[i];
            }
        }
        if (moved)
        {
            InterlockedExchangeAdd(&g_stats.positionsMoved, moved);
            InterlockedIncrement(&g_stats.requestsMoved);
            char d[64], t[224];
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 6096 box %d moved %d/%d #%d %d.%d->%d.%d", boxCode, moved, n, firstI,
                        firstReq / 1000, firstReq % 1000, firstNew / 1000, firstNew % 1000);
            _snprintf_s(t, sizeof(t), _TRUNCATE, "box %d: %d of %d positions placed by server rule: %s", boxCode, moved, n, list);
            Report(kKindPlaced, 6096, user, userNum, firstCode, firstReq, firstNew, d, t);
        }
        return 0;
    }

    void Fault(int opcode, int userNum, DWORD code)
    {
        InterlockedIncrement(&g_stats.faults);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 %d exception 0x%08X -> stock", opcode, code);
        Report(kKindFault, opcode, nullptr, userNum, opcode, (int)code, AcJournal::kNone, d, "exception in check -> stock decision");
    }
}

// ── S1+S2 6096. 0 — продолжить сток (тело приведено), 1 — отказ: код уже в [ebp-3C1h], стаб уходит в LABEL_43. ──
extern "C" int __stdcall P95_OnPackage(BYTE* ebp)
{
    if (!g_enabled) { return 0; }
    InterlockedIncrement(&g_stats.checks[1]);
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x418);
        userNum = *(const short*)(ebp + 8);
        const BYTE* user = *(BYTE**)(ebp - 0x3F4);
        const int boxCode = *(const int*)(ebp - 0x164);
        if (g_levelGate)
        {
            int minLv = 0, lv = 0;
            if (BelowMin(mgr, userNum, boxCode, &minLv, &lv))
            {
                *(ebp - 0x3C1) = (BYTE)g_pkgCode;
                InterlockedIncrement(&g_stats.refusedLevel[1]);
                char d[64], t[128];
                _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 6096 box %d min lv %d > lv %d -> %d", boxCode, minLv, lv, g_pkgCode);
                _snprintf_s(t, sizeof(t), _TRUNCATE, "box %d requires level %d, character level %d -> REFUSE 6097 code %d", boxCode, minLv, lv, g_pkgCode);
                Report(kKindPkgLv, 6096, user, userNum, boxCode, minLv, lv, d, t);
                return 1;
            }
        }
        if (g_placement)
        {
            const int r = Place(ebp, mgr, user, userNum, boxCode);
            if (r)
            {
                *(ebp - 0x3C1) = (BYTE)r;
                InterlockedIncrement(&g_stats.refusedNoRoom);
                return 1;
            }
        }
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(6096, userNum, exc);
        return 0;
    }
    InterlockedIncrement(&g_stats.passed[1]);
    return 0;
}

// ── S3 5468. 0 — сток, 1 — отказ: код в [ebp-0D0h], стаб уходит в общий хвост 0x4F563E (5469). ──
extern "C" int __stdcall P95_OnGacha(BYTE* ebp)
{
    if (!g_enabled || !g_levelGate) { return 0; }
    InterlockedIncrement(&g_stats.checks[2]);
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x194);
        userNum = *(const short*)(ebp + 8);
        const int code = *(const int*)(ebp - 0x84);              // запись бустера a5 (сток: sub_532A90, +27 ∉ {200,201})
        int minLv = 0, lv = 0;
        if (BelowMin(mgr, userNum, code, &minLv, &lv))
        {
            *(ebp - 0xD0) = (BYTE)g_gachaCode;
            InterlockedIncrement(&g_stats.refusedLevel[2]);
            char d[64], t[128];
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 5468 booster %d min lv %d > lv %d -> %d", code, minLv, lv, g_gachaCode);
            _snprintf_s(t, sizeof(t), _TRUNCATE, "booster %d requires level %d, character level %d -> REFUSE 5469 code %d", code, minLv, lv, g_gachaCode);
            Report(kKindGachaLv, 5468, UserOf(mgr, userNum), userNum, code, minLv, lv, d, t);
            return 1;
        }
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(5468, userNum, exc);
        return 0;
    }
    InterlockedIncrement(&g_stats.passed[2]);
    return 0;
}

// ── S4 5028. 0 — сток, 1 — отказ: стаб уходит в стоковое тело LABEL_196 0x4DA8DD (5029 код 0). ──
extern "C" int __stdcall P95_OnSpend(BYTE* ebp)
{
    if (!g_enabled || !g_levelGate) { return 0; }
    InterlockedIncrement(&g_stats.checks[3]);
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x4E8);
        userNum = *(const short*)(ebp + 8);
        const int code = *(const int*)(ebp - 0x9C);              // запись Src (сток: sub_532A90, тип +26 == 11)
        int minLv = 0, lv = 0;
        if (BelowMin(mgr, userNum, code, &minLv, &lv))
        {
            InterlockedIncrement(&g_stats.refusedLevel[3]);
            char d[64], t[128];
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P95 5028 item %d min lv %d > lv %d -> 0", code, minLv, lv);
            _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d requires level %d, character level %d -> REFUSE 5029 code 0", code, minLv, lv);
            Report(kKindSpendLv, 5028, UserOf(mgr, userNum), userNum, code, minLv, lv, d, t);
            return 1;
        }
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
        Fault(5028, userNum, exc);
        return 0;
    }
    InterlockedIncrement(&g_stats.passed[3]);
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P95_GetStats(P95_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // ── площадки: адрес, байты стока, продолжение, отказ ─────────────────────
    //   S1/S2 Recv_OpenPackageItem: mov dword ptr [ebp-3FCh], 0           → 0x55AB34 / LABEL_43 0x55AE56
    const DWORD kPkg = 0x0055AB2A; const BYTE kPkgOrig[10] = { 0xC7, 0x85, 0x04, 0xFC, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    DWORD g_pkgBack = 0x0055AB34, g_pkgRefuse = 0x0055AE56;
    const BYTE kPkgBackOrig[2]   = { 0xEB, 0x0F };                                                   // jmp 0x55AB45 (условие цикла)
    const BYTE kPkgRefuseOrig[11] = { 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x8D, 0xE8, 0xFB, 0xFF, 0xFF }; // mov cx,[ebp+8]; push ecx; mov ecx,[ebp-418h]
    const BYTE kPkgCode9[7]   = { 0xC6, 0x85, 0x3F, 0xFC, 0xFF, 0xFF, 0x09 };                        // 0x55AB19 mov byte [ebp-3C1h],9 (код в кадре)
    const BYTE kPkgV18[7]     = { 0x66, 0x89, 0x95, 0x10, 0xFC, 0xFF, 0xFF };                        // 0x55AACB mov [ebp-3F0h],dx (v18)
    const BYTE kPkgBody[6]    = { 0x8D, 0x85, 0x14, 0xFC, 0xFF, 0xFF };                              // 0x55A96A lea eax,[ebp-3ECh] (тело v19)
    const BYTE kPkgUser[6]    = { 0x89, 0x85, 0x0C, 0xFC, 0xFF, 0xFF };                              // 0x55A925 mov [ebp-3F4h],eax (pUser)
    const BYTE kPkgThis[6]    = { 0x89, 0x8D, 0xE8, 0xFB, 0xFF, 0xFF };                              // 0x55A835 mov [ebp-418h],ecx (this)
    const BYTE kPkgBox[6]     = { 0x8B, 0x85, 0x9C, 0xFE, 0xFF, 0xFF };                              // 0x55A9E1 mov eax,[ebp-164h] (код коробки)
    const BYTE kPkgCount[7]   = { 0x0F, 0xB6, 0x85, 0x1A, 0xFC, 0xFF, 0xFF };                        // 0x55AB45 movzx eax,byte [ebp-3E6h] (кол-во позиций)
    const BYTE kPkgCode[4]    = { 0x8B, 0x44, 0x11, 0x04 };                                          // 0x55AB84 mov eax,[ecx+edx+4] (код позиции)
    const BYTE kPkgSlotRd[8]  = { 0x66, 0x8B, 0x84, 0x15, 0x1F, 0xFC, 0xFF, 0xFF };                  // 0x55AC96 mov ax,[ebp+edx-3E1h] (слот позиции)
    const BYTE kPkgContRd[9]  = { 0x66, 0x0F, 0xB6, 0x94, 0x0D, 0x1E, 0xFC, 0xFF, 0xFF };            // 0x55ACA8 movzx dx,byte [ebp+ecx-3E2h] (контейнер)
    //   S3 Recv_GachaItemUse: mov eax, dword ptr [ebp-84h]                → 0x4F4BCB / хвост 0x4F563E
    const DWORD kGacha = 0x004F4BC5; const BYTE kGachaOrig[6] = { 0x8B, 0x85, 0x7C, 0xFF, 0xFF, 0xFF };
    DWORD g_gachaBack = 0x004F4BCB, g_gachaRefuse = 0x004F563E;
    const BYTE kGachaBackOrig[5]   = { 0x2D, 0x47, 0x50, 0x00, 0x00 };                                // sub eax,5047h
    const BYTE kGachaRefuseOrig[13] = { 0x6A, 0x01, 0x66, 0x8B, 0x55, 0x08, 0x52, 0x8D, 0x85, 0x30, 0xFF, 0xFF, 0xFF }; // push 1; …; lea eax,[ebp-0D0h]
    const BYTE kGachaCode5[7] = { 0xC6, 0x85, 0x30, 0xFF, 0xFF, 0xFF, 0x05 };                        // 0x4F4BB4 mov byte [ebp-0D0h],5 (код в кадре)
    const BYTE kGachaThis[6]  = { 0x89, 0x8D, 0x6C, 0xFE, 0xFF, 0xFF };                              // 0x4F48D3 mov [ebp-194h],ecx (this)
    const BYTE kGachaRec[6]   = { 0x8D, 0x85, 0x7C, 0xFF, 0xFF, 0xFF };                              // 0x4F4AAC lea eax,[ebp-84h] (запись a5)
    //   S4 CharSpendItemUse: mov eax, dword ptr [ebp-9Ch]                 → 0x4D8F36 / LABEL_196 0x4DA8DD
    const DWORD kSpend = 0x004D8F30; const BYTE kSpendOrig[6] = { 0x8B, 0x85, 0x64, 0xFF, 0xFF, 0xFF };
    DWORD g_spendBack = 0x004D8F36, g_spendRefuse = 0x004DA8DD;
    const BYTE kSpendBackOrig[5]   = { 0x2D, 0x47, 0x50, 0x00, 0x00 };                                // sub eax,5047h
    const BYTE kSpendRefuseOrig[8] = { 0xC6, 0x45, 0xDC, 0x00, 0x6A, 0x01, 0x6A, 0x00 };              // mov byte [ebp-24h],0; push 1; push 0
    const BYTE kSpendType[9]  = { 0x83, 0xFA, 0x0B, 0x0F, 0x85, 0x8E, 0x17, 0x00, 0x00 };            // 0x4D8F27 cmp edx,0Bh; jne LABEL_181
    const BYTE kSpendThis[6]  = { 0x89, 0x8D, 0x18, 0xFB, 0xFF, 0xFF };                              // 0x4D8C53 mov [ebp-4E8h],ecx (this)
    const BYTE kSpendRec[6]   = { 0x8D, 0x8D, 0x64, 0xFF, 0xFF, 0xFF };                              // 0x4D8EC2 lea ecx,[ebp-9Ch] (запись Src)
    //   стоковые функции, которые зовёт P95 (прологи)
    const BYTE kFnEmpty[6]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 };                                // sub_4D6910
    const BYTE kFnFind[6]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C };                                // sub_4D6CE0
    const BYTE kFnLevel[6]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 };                                // sub_5325F0
    const BYTE kFnLevelRd[6] = { 0x8A, 0x81, 0x92, 0x01, 0x00, 0x00 };                               // 0x53261D mov al,[ecx+192h]
    const BYTE kFnItem[10]  = { 0x55, 0x8B, 0xEC, 0x81, 0x7D, 0x08, 0x47, 0x50, 0x00, 0x00 };        // sub_532A90 cmp [ebp+8],5047h
    const BYTE kFnGem[10]   = { 0x55, 0x8B, 0xEC, 0x81, 0x7D, 0x08, 0x59, 0x1B, 0x00, 0x00 };        // sub_532AE0 cmp [ebp+8],1B59h
    const BYTE kFnFunc[7]   = { 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x01 };                          // sub_532B10 cmp [ebp+8],1

    // Стабы. Вход jmp с площадки; регистры и флаги сохраняются целиком (pushfd/pushad), маршрут — ZF между test и jnz
    // (popad флагов не трогает). На продолжении — замещённая инструкция стока.
    __declspec(naked) void St_Package()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P95_OnPackage
            test  eax, eax
            popad
            jnz   Refuse
            popfd
            mov   dword ptr [ebp-3FCh], 0           // замещённое: i = 0
            jmp   dword ptr [g_pkgBack]             // 0x55AB34
        Refuse:
            popfd
            jmp   dword ptr [g_pkgRefuse]           // 0x55AE56 — LABEL_43 (6097, код уже в [ebp-3C1h])
        }
    }
    __declspec(naked) void St_Gacha()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P95_OnGacha
            test  eax, eax
            popad
            jnz   Refuse
            popfd
            mov   eax, dword ptr [ebp-84h]          // замещённое
            jmp   dword ptr [g_gachaBack]           // 0x4F4BCB
        Refuse:
            popfd
            jmp   dword ptr [g_gachaRefuse]         // 0x4F563E — 5469 (код уже в [ebp-0D0h])
        }
    }
    __declspec(naked) void St_Spend()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P95_OnSpend
            test  eax, eax
            popad
            jnz   Refuse
            popfd
            mov   eax, dword ptr [ebp-9Ch]          // замещённое
            jmp   dword ptr [g_spendBack]           // 0x4D8F36
        Refuse:
            popfd
            jmp   dword ptr [g_spendRefuse]         // 0x4DA8DD — LABEL_196 (5029 код 0)
        }
    }
}

PatchResult P95_ItemUseGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_placement = Config::GetBool(kSec, L"Placement", true);
    g_levelGate = Config::GetBool(kSec, L"LevelGate", true);
    g_pkgCode   = Config::GetInt(kSec, L"PackageLevelCode", 3);
    if (g_pkgCode < 2 || g_pkgCode > 11) { g_pkgCode = 3; }        // клиент показывает 6097 только для 2…11 (99312…99321)
    g_gachaCode = Config::GetInt(kSec, L"GachaLevelCode", 3);
    if (g_gachaCode < 1 || g_gachaCode > 8) { g_gachaCode = 3; }   // клиент: 1…8 → нотисы 13107…13113 / 12165
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 1);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 1; }
    if (!g_placement && !g_levelGate) { g_enabled = false; return PatchResult::Disabled; }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    const Site check[] =
    {
        { kPkg, kPkgOrig, sizeof(kPkgOrig) }, { g_pkgBack, kPkgBackOrig, sizeof(kPkgBackOrig) }, { g_pkgRefuse, kPkgRefuseOrig, sizeof(kPkgRefuseOrig) },
        { 0x0055AB19, kPkgCode9, sizeof(kPkgCode9) }, { 0x0055AACB, kPkgV18, sizeof(kPkgV18) }, { 0x0055A96A, kPkgBody, sizeof(kPkgBody) },
        { 0x0055A925, kPkgUser, sizeof(kPkgUser) }, { 0x0055A835, kPkgThis, sizeof(kPkgThis) }, { 0x0055A9E1, kPkgBox, sizeof(kPkgBox) },
        { 0x0055AB45, kPkgCount, sizeof(kPkgCount) }, { 0x0055AB84, kPkgCode, sizeof(kPkgCode) }, { 0x0055AC96, kPkgSlotRd, sizeof(kPkgSlotRd) },
        { 0x0055ACA8, kPkgContRd, sizeof(kPkgContRd) },
        { kGacha, kGachaOrig, sizeof(kGachaOrig) }, { g_gachaBack, kGachaBackOrig, sizeof(kGachaBackOrig) }, { g_gachaRefuse, kGachaRefuseOrig, sizeof(kGachaRefuseOrig) },
        { 0x004F4BB4, kGachaCode5, sizeof(kGachaCode5) }, { 0x004F48D3, kGachaThis, sizeof(kGachaThis) }, { 0x004F4AAC, kGachaRec, sizeof(kGachaRec) },
        { kSpend, kSpendOrig, sizeof(kSpendOrig) }, { g_spendBack, kSpendBackOrig, sizeof(kSpendBackOrig) }, { g_spendRefuse, kSpendRefuseOrig, sizeof(kSpendRefuseOrig) },
        { 0x004D8F27, kSpendType, sizeof(kSpendType) }, { 0x004D8C53, kSpendThis, sizeof(kSpendThis) }, { 0x004D8EC2, kSpendRec, sizeof(kSpendRec) },
        { 0x004D6910, kFnEmpty, sizeof(kFnEmpty) }, { 0x004D6CE0, kFnFind, sizeof(kFnFind) }, { 0x005325F0, kFnLevel, sizeof(kFnLevel) },
        { 0x0053261D, kFnLevelRd, sizeof(kFnLevelRd) }, { 0x00532A90, kFnItem, sizeof(kFnItem) }, { 0x00532AE0, kFnGem, sizeof(kFnGem) },
        { 0x00532B10, kFnFunc, sizeof(kFnFunc) },
    };
    if (!VerifyAllSites(L"P95", check, ARRAYSIZE(check))) { g_enabled = false; return PatchResult::Mismatch; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    // ── запись: 6096 — при Placement или LevelGate; 5468/5028 — только LevelGate ──
    if (!Hook::WriteJmp(kPkg, (void*)&St_Package, sizeof(kPkgOrig))) { return PatchResult::Failed; }
    if (g_levelGate)
    {
        if (!Hook::WriteJmp(kGacha, (void*)&St_Gacha, sizeof(kGachaOrig))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(kSpend, (void*)&St_Spend, sizeof(kSpendOrig))) { return PatchResult::Failed; }
    }
    Log::Line(L"    P95: коробки 6096 @0x%08X — раскладка позиций по правилу сервера %s, мин. уровень коробки %s (код 6097 %d); "
              L"бустер 5468 @0x%08X и расходник 5028 @0x%08X — мин. уровень %s (5469 код %d / 5029 код 0); "
              L"журнал ac.other 140–144 не чаще 1 раза в %d с, канал лога %d",
              kPkg, g_placement ? L"ВКЛ" : L"выкл (сток)", g_levelGate ? L"ВКЛ" : L"выкл (сток)", g_pkgCode,
              kGacha, kSpend, g_levelGate ? L"ВКЛ" : L"выкл (сток)", g_gachaCode, g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
