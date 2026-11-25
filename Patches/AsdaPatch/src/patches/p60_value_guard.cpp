// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P60 — ★ ЗНАЧЕНИЯ ПО СЕРВЕРНЫМ ТАБЛИЦАМ (механизм L5 плана античита; приоритеты A3/A4; волна A7
//  «экономика / предметы / рыбалка-лут-квесты», 2026-10-12). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Находки: `02_parts/economy2_handlers.md` (5020 крит. 5, 5048, 6586, 6140), `02_parts/fishing_loot_quests.md`
//  (FISH-3, TITLE-1, QUEST-1, QUEST-2, CLAN-1). Документ: `AstoryServer/Docs/GameServer/value-guard-p60.md`.
//
//  ── ЧТО ДЕЛАЕТ (всё под Mode: 0 = только журнал, 1 = штатный отказ того же обработчика) ──
//  1. 5020 CharItemBuy@0x50F170 (GS:103826). Тело 42 б = 7×{i32 код, i16 количество} лежит в кадре [ebp-3D4h]
//     (memcpy 0x50F2D7). Сток: количество ≤ 0 у стопочного товара ТОЛЬКО логирует (GS:104041), верхней границы
//     нет, `цена(int32) × количество(int16)` копится в int32 `totalPrice`/`totalWeight` без контроля переполнения
//     (GS:104067/104087) → отрицательная сумма проходит проверку денег/веса. Площадка — `call sub_52BFF0` (гейт
//     «занят», 0x50F3F0): стаб зовёт сток, при его «не занят» (al=0) наш обход всех 7 позиций ТОЙ ЖЕ классификацией,
//     что у стока (sub_532B10/532B30 → сток сам откажет; sub_532AE0 самоцвет — цена из dword_5F5E8C+19; обычный —
//     sub_532A90, запись dword_5F5E98 71 б: +7 тип, +26, +35 стопочный, +36 покупной, +41 цена, +5 вес, +62 ShopBuy;
//     стопочная ветка = (+7==4 && +36==1 && +26!=10 && +35!=0) — только там сток читает количество):
//       а) количество ≤ 0 → вид 20; б) количество > MaxBuyCount → вид 21; в) Σ цена×количество (int64) > INT_MAX
//       → вид 22 (скидка войны в сумме не учитывается — она ≤ ±rate%, на вердикт у честного игрока не влияет:
//       деньги < INT_MAX); г) Σ вес×количество (int64) > INT_MAX → вид 22 (текст «weight»).
//     Mode=1: а/б → стоковое тело «5021 код 0» (0x50F3FC — то же, что и у гейта «занят»); в → тело «код 4, денег
//     нет» (0x510A09); г → тело «код 3, вес» (0x510AC8). Тела читают только кадр, протокол не меняется.
//     ★ Макс. стека в Item_Table.txt НЕТ: +35 во всех 50+ местах GameServer.c — булев флаг; клиент считает максимум
//       покупки как деньги/цена (shopWnd_calcMaxBuyableQty@0xE2AEC0). Поэтому граница — ключ MaxBuyCount
//       (по умолчанию 32767 = предел int16 поля: честный порт шлёт количество из нумпада по деньгам).
//     Порт: магазин NPC шлёт количество ≥ 1 (нумпад ОК с max по деньгам), магазин снаряжения шлёт −1 у ЭКИПИРОВКИ
//     (не стопочная ветка — сток количество не читает, мы тоже). Ассортимент NPC НЕ проверяется: таблиц магазинов
//     в GameServer нет (ни одного loader'а «Shop*»), а в теле 5020 нет ни кода NPC, ни дистанции — отложено.
//  2. 6180 Recv_FishingBookUpdate@0x4124C0 (GS:7958): тело [ebp-228h] (+13 i32 количество); сток проверяет
//     «количество ≤ стопка» (GS:8041), отрицательное проходит и уходит в UPCharFishCountUP знаковым. Площадка —
//     `call sub_5324A0` 0x4125CC (GetUser после memcpy): количество ≤ 0 → вид 23; Mode=1 → стоковое тело «6181
//     код 8» (0x412906 — тот же код, что сток шлёт при «количество > стопки»). Порт: Qty из нумпада ≥ 1.
//  3. 6150 RecvClient_TitleItemCheck@0x55F090 (GS:135404): тело [ebp-F0h] (+7 i32 количество); сток «стопка ≥
//     количество» (GS:135412). Площадка `call sub_5324A0` 0x55F1AD: ≤ 0 → вид 24; Mode=1 → тело «6151 код 6»
//     (0x55F2CF — код стока на той же проверке). Порт: OnNumPadAccepted только при Qty > 0.
//  4. 5048 CharQuestItemBuy@0x5117F0 (GS:104443): `sub_532B30` (0x511978, cdecl) пропускает 20000+N (GS:117053),
//     а цена читается из dword_5F5E78 по (код−2001) за пределами таблицы (GS:104499). Стаб зовёт сток; при его
//     «1» и коде вне 2001…dword_5F5EA8 → вид 25; Mode=1 → возврат 0 → сток сам шлёт «5049 код 4». Порт 5048 не
//     шлёт (книги заданий не портированы) — риска нет.
//  5. 5041 → sub_45DEE0 (GS:38415): номер награды a3=[ebp+0Ch] на входе только `> 0` (GS:37901), читается
//     RewardTable dword_5F5E74 (запись 126 б) по (a3−1) без верхней границы. Число записей — заголовок блока
//     `new`: *(int*)(dword_5F5E74 − 4) (загрузчик GS:68880: Block[0]=count, данные с +4). Площадка `call sub_5324A0`
//     0x45E0F1 (после sub_4D61E0): a3 вне 1…N → вид 26; Mode=1 → eax=0 → штатный `return 0` функции (0x45E105:
//     xor al,al; jmp 0x460C78), вызывающий пишет «iReturnType == 0» и выходит (как при отсутствии предмета).
//  6. 6586 Recv_UserStarPointUpdate@0x539210 (GS:119532): результат анти-повтора sub_524390 (0x539278) сток НЕ
//     использует (единственный такой обработчик); знак v6[4] (тело [ebp-24h], +4 u8) уходит в БД 2568 без
//     диапазона. Две площадки: (а) `call sub_524390` — при его 0 → вид 27, Mode=1 → eax=0, `jmp 0x53939D`
//     (эпилог: тот же «return result» без ответа, что у соседей 6180/6150 при неудаче анти-повтора);
//     (б) `call sub_5324A0` 0x5392DB — знак вне 1…StarPointMax → вид 28, Mode=1 → тот же тихий выход.
//     Граница 12 — из клиента (Constellation.BIN: 12 знаков; порт шлёт 1…12).
//  7. 6521 Recv_User_ClanGrade@0x4099A0 (GS:4057): тело [ebp-118h] (+4 u16 ступень, +6 i32 цель UserIndex); сток
//     проверяет «цель ≠ глава» (код 4) и бит 8 полномочий (код 3). Площадка `call sub_5324A0` 0x409AD0: ступень вне
//     2…5, цель = отправитель (CUser+0x174) или ступень не ниже собственной (CUser+0x1832B, 1 = глава) → вид 29;
//     Mode=1 → стоковое тело «6522 код 3» (0x409C76, «нет полномочий» — штатный код этого обработчика).
//     По умолчанию ClanGrade6521=1 но вердикт только журнал, пока Mode=0 (находка «не подтв.»). Порт 6521 не шлёт.
//  8. 6140 CharNameChange — НЕ реализовано: в GameServer фильтра имени нет вовсе (6138 RecvClient_CharNameCheck
//     @0x55D7C0 — чистый проброс в БД 2450; 6140 → 2452 → DBManager sub_439E80 `EXEC UPCharRename … '%s'`).
//     Ключ NameChange6140 зарезервирован (0), ставить нечего — см. отчёт.
//  Кадры/смещения сняты с дизасма стока (gs_stock 4e20f0ad = живой e7b4ac38 на этих местах): адреса инструкций
//  указаны у каждой площадки ниже. Площадки — 5-байтовые `E8 rel32` целиком; переходов внутрь нет
//  (tools/verify_p60.py). С P01…P59 не пересекаются (P43 — лавка 6300…, P44 — обмен, P15 — 5450).
//  Журнал: ac.other виды 20…29 (выданы координатором), ограничитель на (сессия, вид) JournalIntervalSec;
//  строка в Log_Item `sub_569DF0(1, "P60 …")` на каждое нарушение (после ограничителя).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>   // [fix13] _snprintf_s / _snwprintf_s — ограниченные форматтеры
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>
#include <limits.h>

namespace
{
    const wchar_t* kSec = L"P60_ValueGuard";

    bool g_enabled = true;
    int  g_mode    = 0;           // 0 журнал, 1 штатный отказ
    bool g_buy5020 = true, g_fish6180 = true, g_title6150 = true, g_book5048 = true, g_reward5041 = true;
    bool g_star6586 = true, g_clan6521 = true, g_name6140 = false;
    int  g_maxBuyCount = 32767;   // верхняя граница количества в позиции 5020 (предел int16 поля)
    int  g_starMax     = 12;      // знаков зодиака (Constellation.BIN клиента)
    int  g_journalIntervalSec = 10;

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0 (thiscall i16)
    typedef int   (__cdecl    *PFN_CodeIs)(int code);                              // sub_532A90/532AE0/532B10/532B30
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);         // sub_569DF0
    PFN_GetUser const pGetUser     = (PFN_GetUser)Srv::kGetUser;
    PFN_CodeIs  const pIsItem      = (PFN_CodeIs)0x00532A90;   // обычный предмет 20551…dword_5F5EAC
    PFN_CodeIs  const pIsGem       = (PFN_CodeIs)0x00532AE0;   // самоцвет 7001…dword_5F5EA0
    PFN_CodeIs  const pIsFunc      = (PFN_CodeIs)0x00532B10;   // функциональный 1…dword_5F5EA4
    PFN_CodeIs  const pIsQuestBook = (PFN_CodeIs)0x00532B30;   // книга заданий 2001…dword_5F5EA8 (+ дыра 20000+N)
    PFN_SrvLog  const pSrvLog      = (PFN_SrvLog)Srv::kLog;

    // Глобальные таблицы стока (указатели в .data; значения читаются при каждом вызове — таблицы перегружаются).
    constexpr DWORD kpItemTable     = 0x005F5E98;   // Item_Table.txt, запись 71 б, индекс (код−20551)
    constexpr DWORD kpGemTable      = 0x005F5E8C;   // самоцветы, запись 43 б, индекс (код−7001)
    constexpr DWORD kpQuestBookMax  = 0x005F5EA8;   // int: 2000 + число книг (sub_532B30, GS:68803)
    constexpr DWORD kpRewardTable   = 0x005F5E74;   // RepayTable.txt, запись 126 б; число записей = *(int*)(ptr−4)
    constexpr int   kItemRec = 71, kGemRec = 43;

    constexpr int kOffUserNumW  = 0x0C;
    constexpr int kOffMap       = 0x1C;
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;
    constexpr int kOffClanIndex = 0x18318;   // i16 (GS:4100 pUser+99096)
    constexpr int kOffClanGrade = 0x1832B;   // u8  (GS:4116 pUser+99115; 1 = глава)

    // Виды журнала ac.other (выданы координатором: 20…29).
    enum Kind : BYTE
    {
        kBuyCountZero = 20, kBuyCountMax = 21, kBuyOverflow = 22, kFishCount = 23, kTitleCount = 24,
        kQuestBookCode = 25, kRewardIndex = 26, kStarReplay = 27, kStarRange = 28, kClanGrade = 29,
    };
    constexpr int kKindBase = 20, kKindCount = 10;

    struct Sess
    {
        int   userIndex;
        DWORD lastJournal[kKindCount];
        int   suppressed[kKindCount];
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_checked = 0, g_viol = 0, g_refused = 0, g_journaled = 0, g_suppressed = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    // Ограничитель: true — писать строку/журнал; иначе копим suppressed. Под замком.
    bool Allow(int userNum, const BYTE* user, int kind, int* suppressedOut)
    {
        *suppressedOut = 0;
        if (!SessOk(userNum)) { return true; }
        const int k = kind - kKindBase;
        if (k < 0 || k >= kKindCount) { return true; }
        bool w = true;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[userNum];
        int userIndex = 0;
        __try { userIndex = user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { userIndex = 0; }
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        const DWORD now = GetTickCount();
        if (g_journalIntervalSec > 0 && s.lastJournal[k] && now - s.lastJournal[k] < (DWORD)g_journalIntervalSec * 1000)
        {
            ++s.suppressed[k]; w = false; InterlockedIncrement(&g_suppressed);
        }
        else
        {
            s.lastJournal[k] = now; *suppressedOut = s.suppressed[k]; s.suppressed[k] = 0;
        }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        return w;
    }

    const char* NameOf(const BYTE* user)
    {
        __try { return user ? (const char*)(user + kOffName) : "?"; } __except (EXCEPTION_EXECUTE_HANDLER) { return "?"; }
    }

    // Нарушение: строка в Log_Item + ac.other (после ограничителя). Возврат — вердикт для стаба (1 при Mode=1).
    int Violation(BYTE kind, const BYTE* user, int userNum, int opcode, int v0, int v1, int v2, const char* text)
    {
        InterlockedIncrement(&g_viol);
        int sup = 0;
        if (Allow(userNum, user, kind, &sup))
        {
            InterlockedIncrement(&g_journaled);
            int userIndex = -1;
            __try { if (user) { userIndex = *(const int*)(user + kOffUserIndex); } } __except (EXCEPTION_EXECUTE_HANDLER) {}
            pSrvLog(1, "P60 ValueGuard: %d %s  v=%d/%d/%d  UserNum %d UserIndex %d %s%s%s",
                    opcode, text, v0, v1, v2, userNum, userIndex, NameOf(user),
                    g_mode ? " -> REFUSE (stock body)" : " (journal only, Mode=0)", sup ? " [suppressed before]" : "");
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, kind);
            e.opcode = opcode;
            e.userNum = (short)userNum;
            e.ip = P47_PeerIpv4(userNum);
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
            AcJournal::CopyText(e, text);
            AcJournal::Push(e);
        }
        if (g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        return 0;
    }
}

// ── 1. 5020 после стокового гейта «занят» (al=0). Возврат: 0 пропуск; 1 → тело «код 0»; 2 → «код 4»; 3 → «код 3» ──
extern "C" int __stdcall P60_OnBuy5020(BYTE* ebp)
{
    if (!g_enabled || !g_buy5020) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const BYTE* user = *(BYTE**)(ebp - 0x3DC);          // pUser (0x50F2F4 → mov [ebp-3DCh],eax)
        const int userNum = *(const short*)(ebp + 8);
        const BYTE* body = ebp - 0x3D4;                      // 7×6 б (memcpy 0x50F2D7)
        const BYTE* tblItem = *(const BYTE**)kpItemTable;
        const BYTE* tblGem  = *(const BYTE**)kpGemTable;
        __int64 sumPrice = 0, sumWeight = 0;
        int countViol = 0, priceViol = 0, weightViol = 0;
        int positions = 0;
        for (int i = 0; i < 7; ++i)
        {
            const int code = *(const int*)(body + 6 * i);
            if (code <= 0) { continue; }
            ++positions;
            if (pIsFunc(code) || pIsQuestBook(code)) { continue; }          // сток: LABEL_91 → код 0 сам
            if (pIsGem(code))
            {
                if (!tblGem) { continue; }
                const BYTE* gem = tblGem + kGemRec * (code - 7001);
                if (!gem[42] || gem[5] > 2) { continue; }                   // сток: код 5 / код 0 сам
                sumPrice += *(const int*)(gem + 19);
                sumWeight += gem[6];
                continue;
            }
            if (!pIsItem(code) || !tblItem) { continue; }                   // сток: код 5 сам
            const BYTE* rec = tblItem + kItemRec * (code - 20551);
            if (!rec[62]) { continue; }                                     // ShopBuyFlag → код 5 сам
            const int price = *(const int*)(rec + 41);
            const int weight = *(const short*)(rec + 5);
            if (rec[7] == 4 && rec[36] == 1)
            {
                if (rec[26] == 10) { sumPrice += price; sumWeight += weight; }
                else if (rec[35])
                {
                    const int count = *(const short*)(body + 6 * i + 4);     // (__int16)buyReq[3*i+2] — GS:104041
                    if (count <= 0)
                    {
                        ++countViol;
                        if (Violation(kBuyCountZero, user, userNum, 5020, count, code, i, "5020 count <= 0")) { verdict = 1; }
                        continue;
                    }
                    if (count > g_maxBuyCount)
                    {
                        ++countViol;
                        if (Violation(kBuyCountMax, user, userNum, 5020, count, g_maxBuyCount, code, "5020 count > MaxBuyCount")) { verdict = 1; }
                    }
                    sumPrice += (__int64)price * count;
                    sumWeight += (__int64)weight * count;
                }
                else { sumPrice += price; sumWeight += weight; }
            }
            else
            {
                if (rec[36] != 1) { continue; }                             // сток: LABEL_91
                sumPrice += price; sumWeight += weight;                     // экипировка — количество сток не читает
            }
        }
        if (sumPrice > (__int64)INT_MAX)
        {
            ++priceViol;
            char t[64]; _snprintf_s(t, sizeof(t), _TRUNCATE, "5020 price sum %I64d > INT_MAX", sumPrice);   // [fix13] ограниченный форматтер
            if (Violation(kBuyOverflow, user, userNum, 5020, (int)(sumPrice / 1000000), positions, 0, t) && !verdict) { verdict = 2; }
        }
        if (sumWeight > (__int64)INT_MAX)
        {
            ++weightViol;
            char t[64]; _snprintf_s(t, sizeof(t), _TRUNCATE, "5020 weight sum %I64d > INT_MAX", sumWeight);   // [fix13] ограниченный форматтер
            if (Violation(kBuyOverflow, user, userNum, 5020, (int)(sumWeight / 1000000), positions, 1, t) && !verdict) { verdict = 3; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return g_mode == 1 ? verdict : 0;
}

// ── 2. 6180 после GetUser: количество ≤ 0 → 1 (тело «код 8») ──
extern "C" int __stdcall P60_OnFish6180(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_fish6180) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const BYTE* body = ebp - 0x228;                      // memcpy 0x4125A3
        const int amount = *(const int*)(body + 13);
        if (amount <= 0)
        {
            verdict = Violation(kFishCount, user, *(const short*)(ebp + 8), 6180, amount, *(const int*)(body + 4), *(const short*)(body + 8), "6180 fish count <= 0");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── 3. 6150 после GetUser: количество ≤ 0 → 1 (тело «код 6») ──
extern "C" int __stdcall P60_OnTitle6150(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_title6150) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const BYTE* body = ebp - 0xF0;                       // memcpy 0x55F189
        const int amount = *(const int*)(body + 7);
        if (amount <= 0)
        {
            verdict = Violation(kTitleCount, user, *(const short*)(ebp + 8), 6150, amount, *(const short*)(body + 4), body[6], "6150 title item count <= 0");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── 4. 5048 после стокового sub_532B30 (вернул 1): возврат 1 = оставить «книга», 0 = «не книга» → сток код 4 ──
extern "C" int __stdcall P60_OnQuestBook5048(BYTE* ebp, int code)
{
    if (!g_enabled || !g_book5048) { return 1; }
    int pass = 1;
    __try
    {
        InterlockedIncrement(&g_checked);
        const int maxCode = *(const int*)kpQuestBookMax;
        if (code < 2001 || code > maxCode)
        {
            void* mgr = *(void**)(ebp - 0x170);              // this (0x511994 mov ecx,[ebp-170h])
            const int userNum = *(const short*)(ebp + 8);
            BYTE* user = (mgr && SessOk(userNum)) ? pGetUser(mgr, nullptr, (short)userNum) : nullptr;
            if (Violation(kQuestBookCode, user, userNum, 5048, code, maxCode, 0, "5048 quest book code outside 2001..max")) { pass = 0; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { pass = 1; }
    return pass;
}

// ── 5. sub_45DEE0 после GetUser: номер награды вне 1…N → 1 (eax=0 → штатный return 0) ──
extern "C" int __stdcall P60_OnReward5041(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_reward5041) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const int a3 = *(const int*)(ebp + 0xC);
        const BYTE* tbl = *(const BYTE**)kpRewardTable;
        const int n = tbl ? *(const int*)(tbl - 4) : 0;
        if (tbl && n > 0 && (a3 < 1 || a3 > n))
        {
            verdict = Violation(kRewardIndex, user, *(const short*)(ebp + 8), 5041, a3, n, 0, "5041 reward index outside 1..N");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── 6а. 6586: анти-повтор вернул 0 → 1 (тихий выход, как у соседей) ──
extern "C" int __stdcall P60_OnStar6586Replay(BYTE* ebp)
{
    if (!g_enabled || !g_star6586) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const int userNum = *(const short*)(ebp + 8);
        BYTE* user = nullptr;
        __try
        {
            void* self = *(void**)(ebp - 0x2C);              // 0x53926F mov eax,[ebp-2Ch]; mov ecx,[eax+4]; mov ecx,[ecx+34h]
            void* mgr = self ? *(void**)(*(BYTE**)((BYTE*)self + 4) + 0x34) : nullptr;
            if (mgr && SessOk(userNum)) { user = pGetUser(mgr, nullptr, (short)userNum); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { user = nullptr; }
        verdict = Violation(kStarReplay, user, userNum, 6586, 0, 0, 0, "6586 anti-replay failed (stock ignored)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── 6б. 6586 после GetUser: знак вне 1…StarPointMax → 1 (тихий выход) ──
extern "C" int __stdcall P60_OnStar6586(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_star6586) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const int star = *(const BYTE*)(ebp - 0x24 + 4);     // v6[4] (memcpy 0x5392BA → [ebp-24h], 5 б)
        if (star < 1 || star > g_starMax)
        {
            verdict = Violation(kStarRange, user, *(const short*)(ebp + 8), 6586, star, g_starMax, 0, "6586 constellation outside 1..max");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── 7. 6521 после GetUser: ступень/цель → 1 (тело «код 3») ──
extern "C" int __stdcall P60_OnClan6521(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_clan6521) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const BYTE* body = ebp - 0x118;                      // memcpy 0x409AA6, 0x1F б
        const int grade = *(const WORD*)(body + 4);
        const int target = *(const int*)(body + 6);
        const int own = user ? user[kOffClanGrade] : 0;
        const int self = user ? *(const int*)(user + kOffUserIndex) : 0;
        const char* why = nullptr;
        if (grade < 2 || grade > 5) { why = "6521 clan grade outside 2..5"; }
        else if (target == self)    { why = "6521 clan grade target == sender"; }
        else if (own >= 1 && grade <= own) { why = "6521 clan grade not below own"; }
        if (why)
        {
            verdict = Violation(kClanGrade, user, *(const short*)(ebp + 8), 6521, grade, own, target, why);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

extern "C" void __stdcall P60_GetStats(int* checked, int* viol, int* refused, int* journaled, int* suppressed)
{
    if (checked) { *checked = g_checked; } if (viol) { *viol = g_viol; } if (refused) { *refused = g_refused; }
    if (journaled) { *journaled = g_journaled; } if (suppressed) { *suppressed = g_suppressed; }
}
extern "C" void __stdcall P60_ResetState()
{
    if (g_lockReady) { EnterCriticalSection(&g_lock); }
    memset(g_sess, 0, sizeof(g_sess));
    if (g_lockReady) { LeaveCriticalSection(&g_lock); }
    g_checked = g_viol = g_refused = g_journaled = g_suppressed = 0;
}

namespace
{
    DWORD g_pStateGate  = 0x0052BFF0;   // сток 5020: гейт «занят» (thiscall userNum, opcode; ret 8)
    DWORD g_pGetUserFn  = 0x005324A0;   // сток: GetUser (thiscall userNum; ret 4)
    DWORD g_pQuestBook  = 0x00532B30;   // сток: sub_532B30 (cdecl code)
    DWORD g_pAntiReplay = 0x00524390;   // сток: анти-повтор (thiscall i64, userNum, name; ret 10h)
    DWORD g_buyBody0    = 0x0050F3FC;   // 5020: mov byte ptr [ebp-3A8h],0 … 5021 406 … jmp эпилог
    DWORD g_buyBody4    = 0x00510A09;   // 5020: код 4 (денег нет)
    DWORD g_buyBody3    = 0x00510AC8;   // 5020: код 3 (вес)
    DWORD g_fishBody8   = 0x00412906;   // 6180: mov byte ptr [ebp-178h],8 … 6181 365
    DWORD g_titleBody6  = 0x0055F2CF;   // 6150: mov byte ptr [ebp-5Bh],6 … 6151 66
    DWORD g_starEpi     = 0x0053939D;   // 6586: mov esp,ebp; pop ebp; ret 8
    DWORD g_clanBody3   = 0x00409C76;   // 6521: mov byte ptr [ebp-0C9h],3 … 6522 1

    // pushad: [esp+28]=eax, [esp+24]=ecx. Вердикт кладём в сохранённый ecx (caller-saved, стоком после вызова не читается).

    // 1. вместо `call sub_52BFF0` 0x50F3F0 (thiscall: ecx=this, [esp+4] userNum, [esp+8] opcode; ret 8).
    __declspec(naked) void St_Buy5020()
    {
        __asm
        {
            push  dword ptr [esp+8]            // opcode
            push  dword ptr [esp+8]            // userNum
            call  dword ptr [g_pStateGate]     // сток (снимает 8 б)
            test  al, al
            jnz   done                         // занят — сток отказывает сам
            pushad
            push  ebp
            call  P60_OnBuy5020                // __stdcall(ebp) → 0/1/2/3
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done                         // al=0 — как сток
            add   esp, 12                      // адрес возврата + 2 аргумента стока
            cmp   ecx, 2
            je    body4
            cmp   ecx, 3
            je    body3
            jmp   dword ptr [g_buyBody0]
        body4:
            jmp   dword ptr [g_buyBody4]
        body3:
            jmp   dword ptr [g_buyBody3]
        done:
            ret   8
        }
    }

    // 2/3/7. вместо `call sub_5324A0` (thiscall: ecx=mgr, [esp+4] userNum; ret 4) с переходом в стоковое тело отказа.
    __declspec(naked) void St_Fish6180()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUserFn]
            test  eax, eax
            jz    done
            pushad
            push  eax                          // user
            push  ebp
            call  P60_OnFish6180               // __stdcall(ebp, user)
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done
            add   esp, 8                       // адрес возврата + аргумент стока
            jmp   dword ptr [g_fishBody8]
        done:
            ret   4
        }
    }
    __declspec(naked) void St_Title6150()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUserFn]
            test  eax, eax
            jz    done
            pushad
            push  eax
            push  ebp
            call  P60_OnTitle6150
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done
            add   esp, 8
            jmp   dword ptr [g_titleBody6]
        done:
            ret   4
        }
    }
    __declspec(naked) void St_Clan6521()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUserFn]
            test  eax, eax
            jz    done
            pushad
            push  eax
            push  ebp
            call  P60_OnClan6521
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done
            add   esp, 8
            jmp   dword ptr [g_clanBody3]
        done:
            ret   4
        }
    }

    // 4. вместо `call sub_532B30` 0x511978 (cdecl: [esp+4] code; вызывающий снимает 4 б).
    __declspec(naked) void St_QuestBook5048()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pQuestBook]
            add   esp, 4
            test  eax, eax
            jz    done                         // сток: не книга → код 4
            pushad
            push  dword ptr [esp+36]           // code (аргумент стока)
            push  ebp
            call  P60_OnQuestBook5048          // → 1 книга / 0 не книга
            mov   dword ptr [esp+28], eax      // в eax
            popad
        done:
            ret
        }
    }

    // 5. вместо `call sub_5324A0` 0x45E0F1: вердикт → eax=0 → штатный return 0.
    __declspec(naked) void St_Reward5041()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUserFn]
            test  eax, eax
            jz    done
            pushad
            push  eax
            push  ebp
            call  P60_OnReward5041
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done
            xor   eax, eax                     // как «пользователя нет» → return 0
        done:
            ret   4
        }
    }

    // 6а. вместо `call sub_524390` 0x539278 (thiscall: 4 аргумента; ret 10h): при 0 — тихий выход (Mode=1).
    __declspec(naked) void St_Star6586Replay()
    {
        __asm
        {
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            call  dword ptr [g_pAntiReplay]
            test  eax, eax
            jnz   done                         // анти-повтор прошёл
            pushad
            push  ebp
            call  P60_OnStar6586Replay
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done                         // Mode=0: как сток (результат игнорируется)
            add   esp, 20                      // адрес возврата + 4 аргумента
            xor   eax, eax
            jmp   dword ptr [g_starEpi]
        done:
            ret   16
        }
    }
    // 6б. вместо `call sub_5324A0` 0x5392DB: знак вне диапазона → тихий выход.
    __declspec(naked) void St_Star6586()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUserFn]
            test  eax, eax
            jz    done
            pushad
            push  eax
            push  ebp
            call  P60_OnStar6586
            mov   dword ptr [esp+24], eax
            popad
            test  ecx, ecx
            jz    done
            add   esp, 8
            xor   eax, eax
            jmp   dword ptr [g_starEpi]
        done:
            ret   4
        }
    }

    // Площадки (сток 4e20f0ad = живой/Indun e7b4ac38) — `E8 rel32` целиком.
    const BYTE kOrigBuy5020[5]   = { 0xE8, 0xFB, 0xCB, 0x01, 0x00 };   // 0x50F3F0 call sub_52BFF0
    const BYTE kOrigFish6180[5]  = { 0xE8, 0xCF, 0xFE, 0x11, 0x00 };   // 0x4125CC call sub_5324A0
    const BYTE kOrigTitle6150[5] = { 0xE8, 0xEE, 0x32, 0xFD, 0xFF };   // 0x55F1AD call sub_5324A0
    const BYTE kOrigBook5048[5]  = { 0xE8, 0xB3, 0x11, 0x02, 0x00 };   // 0x511978 call sub_532B30
    const BYTE kOrigReward[5]    = { 0xE8, 0xAA, 0x43, 0x0D, 0x00 };   // 0x45E0F1 call sub_5324A0
    const BYTE kOrigStarReplay[5]= { 0xE8, 0x13, 0xB1, 0xFE, 0xFF };   // 0x539278 call sub_524390
    const BYTE kOrigStar[5]      = { 0xE8, 0xC0, 0x91, 0xFF, 0xFF };   // 0x5392DB call sub_5324A0
    const BYTE kOrigClan6521[5]  = { 0xE8, 0xCB, 0x89, 0x12, 0x00 };   // 0x409AD0 call sub_5324A0
    // Соседи: тела отказов/эпилоги, на которые прыгают стабы, и инструкции после площадок.
    const BYTE kNbBuyBody0[7]  = { 0xC6, 0x85, 0x58, 0xFC, 0xFF, 0xFF, 0x00 };   // 0x50F3FC mov byte ptr [ebp-3A8h],0
    const BYTE kNbBuyBody4[7]  = { 0xC6, 0x85, 0x58, 0xFC, 0xFF, 0xFF, 0x04 };   // 0x510A09
    const BYTE kNbBuyBody3[7]  = { 0xC6, 0x85, 0x58, 0xFC, 0xFF, 0xFF, 0x03 };   // 0x510AC8
    const BYTE kNbBuyRet[5]    = { 0x0F, 0xB6, 0xD0, 0x85, 0xD2 };               // 0x50F3F5 movzx edx,al; test edx,edx
    const BYTE kNbFishBody8[7] = { 0xC6, 0x85, 0x88, 0xFE, 0xFF, 0xFF, 0x08 };   // 0x412906
    const BYTE kNbFishRet[6]   = { 0x89, 0x85, 0xD0, 0xFD, 0xFF, 0xFF };         // 0x4125D1 mov [ebp-230h],eax
    const BYTE kNbTitleBody6[4]= { 0xC6, 0x45, 0xA5, 0x06 };                     // 0x55F2CF
    const BYTE kNbTitleRet[6]  = { 0x89, 0x85, 0x08, 0xFF, 0xFF, 0xFF };         // 0x55F1B2 mov [ebp-0F8h],eax
    const BYTE kNbBookRet[5]   = { 0x83, 0xC4, 0x04, 0x85, 0xC0 };               // 0x51197D add esp,4; test eax,eax
    const BYTE kNbRewardRet[6] = { 0x89, 0x85, 0xC4, 0xFA, 0xFF, 0xFF };         // 0x45E0F6 mov [ebp-53Ch],eax
    const BYTE kNbRewardZero[7]= { 0x32, 0xC0, 0xE9, 0x6C, 0x2B, 0x00, 0x00 };   // 0x45E105 xor al,al; jmp 0x460C78
    const BYTE kNbStarRet[2]   = { 0x6A, 0x01 };                                 // 0x53927D push 1
    const BYTE kNbStarRet2[3]  = { 0x89, 0x45, 0xE4 };                           // 0x5392E0 mov [ebp-1Ch],eax
    const BYTE kNbStarEpi[6]   = { 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };         // 0x53939D mov esp,ebp; pop ebp; ret 8
    const BYTE kNbClanBody3[7] = { 0xC6, 0x85, 0x37, 0xFF, 0xFF, 0xFF, 0x03 };   // 0x409C76
    const BYTE kNbClanRet[6]   = { 0x89, 0x85, 0xE4, 0xFE, 0xFF, 0xFF };         // 0x409AD5 mov [ebp-11Ch],eax
}

PatchResult P60_ValueGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode       = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_buy5020    = Config::GetBool(kSec, L"Buy5020", true);
    g_fish6180   = Config::GetBool(kSec, L"Fish6180", true);
    g_title6150  = Config::GetBool(kSec, L"Title6150", true);
    g_book5048   = Config::GetBool(kSec, L"QuestBook5048", true);
    g_reward5041 = Config::GetBool(kSec, L"QuestReward5041", true);
    g_star6586   = Config::GetBool(kSec, L"StarPoint6586", true);
    g_clan6521   = Config::GetBool(kSec, L"ClanGrade6521", true);
    g_name6140   = Config::GetBool(kSec, L"NameChange6140", false);
    g_maxBuyCount = Config::GetInt(kSec, L"MaxBuyCount", 32767);
    g_starMax     = Config::GetInt(kSec, L"StarPointMax", 12);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_maxBuyCount < 1 || g_maxBuyCount > 32767) { g_maxBuyCount = 32767; }
    if (g_starMax < 1 || g_starMax > 255) { g_starMax = 12; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    if (g_name6140)
    {
        Log::Line(L"    P60: NameChange6140=1 — ключ зарезервирован, площадки не ставятся: проверка имени 6138/6140 — "
                  L"отдельный патч [P68_CharNameGuard] + SQL A13 (2026-10-13)");
    }

    const Site sites[] =
    {
        { 0x0050F3F0, kOrigBuy5020,    sizeof(kOrigBuy5020)    },
        { 0x004125CC, kOrigFish6180,   sizeof(kOrigFish6180)   },
        { 0x0055F1AD, kOrigTitle6150,  sizeof(kOrigTitle6150)  },
        { 0x00511978, kOrigBook5048,   sizeof(kOrigBook5048)   },
        { 0x0045E0F1, kOrigReward,     sizeof(kOrigReward)     },
        { 0x00539278, kOrigStarReplay, sizeof(kOrigStarReplay) },
        { 0x005392DB, kOrigStar,       sizeof(kOrigStar)       },
        { 0x00409AD0, kOrigClan6521,   sizeof(kOrigClan6521)   },
        { 0x0050F3FC, kNbBuyBody0,     sizeof(kNbBuyBody0)     },
        { 0x00510A09, kNbBuyBody4,     sizeof(kNbBuyBody4)     },
        { 0x00510AC8, kNbBuyBody3,     sizeof(kNbBuyBody3)     },
        { 0x0050F3F5, kNbBuyRet,       sizeof(kNbBuyRet)       },
        { 0x00412906, kNbFishBody8,    sizeof(kNbFishBody8)    },
        { 0x004125D1, kNbFishRet,      sizeof(kNbFishRet)      },
        { 0x0055F2CF, kNbTitleBody6,   sizeof(kNbTitleBody6)   },
        { 0x0055F1B2, kNbTitleRet,     sizeof(kNbTitleRet)     },
        { 0x0051197D, kNbBookRet,      sizeof(kNbBookRet)      },
        { 0x0045E0F6, kNbRewardRet,    sizeof(kNbRewardRet)    },
        { 0x0045E105, kNbRewardZero,   sizeof(kNbRewardZero)   },
        { 0x0053927D, kNbStarRet,      sizeof(kNbStarRet)      },
        { 0x005392E0, kNbStarRet2,     sizeof(kNbStarRet2)     },
        { 0x0053939D, kNbStarEpi,      sizeof(kNbStarEpi)      },
        { 0x00409C76, kNbClanBody3,    sizeof(kNbClanBody3)    },
        { 0x00409AD5, kNbClanRet,      sizeof(kNbClanRet)      },
    };
    if (!VerifyAllSites(L"P60", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    int placed = 0;
    if (g_buy5020)    { if (!Hook::WriteCall(0x0050F3F0, &St_Buy5020, 5))         { return PatchResult::Failed; } ++placed; }
    if (g_fish6180)   { if (!Hook::WriteCall(0x004125CC, &St_Fish6180, 5))        { return PatchResult::Failed; } ++placed; }
    if (g_title6150)  { if (!Hook::WriteCall(0x0055F1AD, &St_Title6150, 5))       { return PatchResult::Failed; } ++placed; }
    if (g_book5048)   { if (!Hook::WriteCall(0x00511978, &St_QuestBook5048, 5))   { return PatchResult::Failed; } ++placed; }
    if (g_reward5041) { if (!Hook::WriteCall(0x0045E0F1, &St_Reward5041, 5))      { return PatchResult::Failed; } ++placed; }
    if (g_star6586)
    {
        if (!Hook::WriteCall(0x00539278, &St_Star6586Replay, 5)) { return PatchResult::Failed; }
        if (!Hook::WriteCall(0x005392DB, &St_Star6586, 5))       { return PatchResult::Failed; }
        placed += 2;
    }
    if (g_clan6521)   { if (!Hook::WriteCall(0x00409AD0, &St_Clan6521, 5))        { return PatchResult::Failed; } ++placed; }
    Log::Line(L"    P60: режим %s; площадок %d/8: 5020=%d 6180=%d 6150=%d 5048=%d 5041=%d 6586=%d 6521=%d (6140 — не реализовано); "
              L"MaxBuyCount %d, StarPointMax %d; ac.other виды 20..29, строки не чаще 1/%d с",
              g_mode ? L"ОТКАЗ (штатные тела)" : L"ЖУРНАЛ", placed, g_buy5020 ? 1 : 0, g_fish6180 ? 1 : 0, g_title6150 ? 1 : 0,
              g_book5048 ? 1 : 0, g_reward5041 ? 1 : 0, g_star6586 ? 1 : 0, g_clan6521 ? 1 : 0, g_maxBuyCount, g_starMax, g_journalIntervalSec);
    return placed ? PatchResult::Applied : PatchResult::Disabled;
}
