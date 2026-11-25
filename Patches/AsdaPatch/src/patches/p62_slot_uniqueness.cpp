// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P62 — ★ УНИКАЛЬНОСТЬ СЛОТОВ В МНОГОСЛОТОВЫХ ОПЕРАЦИЯХ (механизм L3, приоритет A5 плана античита;
//  волна A7 «экономика / предметы / рыбалка-лут-квесты», 2026-10-12; `02_parts/economy2_handlers.md` «Топ-5» п.3,
//  `02_parts/fishing_loot_quests.md` FAME-1). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Документ: `AstoryServer/Docs/GameServer/slot-uniqueness-p62.md`.
//
//  ── ДЫРА ──
//  Шесть обработчиков принимают СПИСОК ссылок (контейнер, слот) и, проверив каждую по отдельности (sub_4D61E0),
//  отправляют их в DBManager одним пакетом, не проверяя, что ссылки РАЗНЫЕ. Одна и та же вещь, указанная дважды,
//  считается дважды (сумма материалов, цена продажи, два зачисления в один слот). Седьмой (6067) принимает два
//  слота званий и применяет бонусы по каждому, не проверяя «слот 0 ≠ слот 1».
//    5018 CharItemSell@0x50D240             — 5 записей по 11 б (слот i16 @0, контейнер u8 @4, кол-во i32 @5)  → БД 2023
//    6549 UpgradeExtraction@0x534640        — 8 материалов (коды @0, слоты i16 @32, контейнеры i16 @48) + источник (@70,@68) → БД 2527
//    6506 ShellItemUpgradeReset@0x500F10    — 10 материалов (контейнеры u8 @6, слоты i16 @16) + цель (@3,@4), только при виде 1 → БД 2306
//    6555 PrimiumSum@0x536EE0               — 5 материалов (коды @0, слоты i16 @20, контейнеры i16 @30)       → БД 2531
//    6096 Recv_OpenPackageItem@0x55A820     — до 5 целевых слотов (контейнер u8 @10+3i, слот i16 @11+3i) + коробка (@7,@8) → БД 2272
//    6112 Recv_PetUnion_Req@0x458A60        — 3 uid питомцев-материалов i32 @6/@10/@14 (−1 = конец списка)  → БД 2282
//    6067 ChangeActiveFame@0x54C820         — слоты званий i16 @6/@8 тела (10 б)
//
//  ── ЧТО ДЕЛАЕТ ──
//  Одна общая функция CheckRefs(): среди «активных» ссылок (контейнер 1…5; слот ≥ 0, либо любой — по флагу)
//  ищет (а) повтор пары (контейнер, слот) — вид 30; (б) совпадение цели/источника с материалом — вид 34;
//  (в) при CheckBounds=1 — ссылку, по которой sub_4D61E0 (той же thiscall-сверкой, что и сток) вещи не находит:
//  слот вне границ контейнера или пуст — вид 31 (★ у 5018 сток при этом берёт КОД ПРЕДЫДУЩЕЙ записи — буфер a5
//  между итерациями не обнуляется, GS:103440+). 6112: повтор uid — вид 32. 6067: слот 0 == слот 1 — вид 33.
//  Площадки — подмена `call sub_5646C0` (E8 rel32, отправка в DBManager) в конце шести обработчиков: стаб зовёт
//  C-проверку по кадру (ebp); «чисто» → стоковая отправка с теми же 5 аргументами (ecx = CUserMoveManager);
//  нарушение в Mode=1 → esp возвращается к состоянию до push'ей и переход в СТОКОВОЕ тело отказа того же
//  обработчика (тот же код, что сток шлёт на соседней ветке ошибки, см. таблицу g_ref*). У 6067 площадка —
//  `call sub_5324A0` (GetUser) после memcpy тела: стаб зовёт сток, при user≠0 — проверка; Mode=1 → слот 1 := −1
//  в кадре (так сток сам помечает слот вне диапазона, GS:127447).
//  Mode=0 (умолчание) — ТОЛЬКО ЖУРНАЛ: строка `P62 SlotUniqueness: …` в лог сервера (канал LogChannel) + ac.other
//  вид 30…34 (v[0] контейнер/uid/звание, v[1] слот/индекс, v[2] 0 журнал / 1 отказ, text = обработчик и записи),
//  не чаще одной строки на (сессия, вид) за JournalIntervalSec; подавленные → repeat_suppressed.
//
//  ── КАДРЫ (смещения сняты с дизасма стока, адрес инструкции в скобках) ──
//    5018: this=[ebp-19Ch] (0x50D258), pUser=[ebp-154h] (0x50D36C), тело=[ebp-14Ch] (0x50D343), замок «в полёте»
//          pUser+157h (0x50E678 cmp / 0x50E6B2 = 1) — при отказе снимается, иначе продажа заперта до ответа БД;
//          тело отказа 0x50E681 (`mov byte [ebp-48h],0` → 5019 код 0, LABEL_83).
//    6549: this=[ebp-618h] (0x5347E8), pUser=[ebp-56Ch] (0x5347B6), тело=[ebp-5C0h] (0x534787); отказ 0x5349DB (6550 код 2, ветка (4)).
//    6506: this=[ebp-4BCh] (0x501159), pUser=[ebp-428h] (0x5010C7), тело=[ebp-1DCh] (0x501092), вид=[ebp-1DDh] (0x5010A7);
//          отказ 0x5017AB (6507 код 5 «материалов не хватает», без строки лога).
//    6555: this=[ebp-298h] (0x5370CA), pUser=[ebp-23Ch] (0x537034), тело=[ebp-268h] (0x537005); отказ 0x5370F8 (6556 код 10, ветка (3)).
//    6096: this=[ebp-418h] (0x55A9C1), pUser=[ebp-3F4h] (0x55A925), тело=[ebp-3ECh] (0x55A96A); отказ 0x55ACC6 (6097 код 7, LABEL_43).
//    6112: this=CPartyManager [ebp-F0h] (0x458A73), pUser=[ebp-D8h] (0x458B8F), тело=[ebp-D4h] (0x458B61); отказ 0x458DF7 (6113 код 3, LABEL_25).
//    6067: this=[ebp-6Ch] (0x54C831), тело=[ebp-38h] (0x54C8CA), pUser=eax стока; возврат 0x54C8EA (`mov [ebp-40h],eax`).
//    userNum = [ebp+8] (i16) у всех. Эпилоги не трогаются: `add esp,18h` = адрес возврата + 5 аргументов стока.
//
//  ── ЦЕПОЧКА С P63 (integ2, 2026-10-12) ──
//  Площадки 6549/6506/6555/6096/6112 — тот же `call sub_5646C0`, что перехватывает P63 (постановка замка). Порядок в
//  рантайме: P62 → P63 → sub_5646C0. Стаб на проходе уходит ХВОСТОВЫМ jmp в слот «следующий вызов» площадки
//  (g_next*, по умолчанию sub_5646C0; P63 кладёт туда St_Send) — вход в St_Send побайтно стоковый (стек, ecx, ebp,
//  адрес возврата). Отказ P62 (Mode=1) уходит в стоковое тело отказа — до P63 не доходит, замок не ставится.
//  Если P63 поставлен раньше (rel32 → St_Send P63, исходные байты таблиц совпали) — P62 забирает площадку, слот :=
//  St_Send. Общая точка — Patches.h (P62_SendStubAt/P62_SendOrigAt/P62_ChainSend, P63_SendStubAt/P63_SendOrigAt).
//
//  ── БЕЗОПАСНОСТЬ ──
//  Площадки `E8 rel32` целиком, байты сверены в стоке 4e20f0ad и живых GameServer/Indun e7b4ac38 (verify_p62.py:
//  переходов/abs32 внутрь нет, границы инструкций, цели стабов). Соседи (тела отказов, возврат 6067) сверяются при
//  установке. С P33 (0x5010EB в 6506), P31 (0x459264 — другая функция), P21 (0x54CB1A), P11, P43/P44, P56/P57
//  не пересекается. Все чтения памяти сервера — под __try/__except; стабы naked с pushad/popad, стек сбалансирован.
//  Честный порт: 5018 — корзина окна магазина (разные ячейки), 6506 — слоты свитков из CollectScrollSlots
//  (неиспользуемые = −1, контейнер 1), 6096 — ReservePackageSlots (TSet занятых), 6112 — три разных питомца,
//  6067 — приставка и окончание из разных списков; 6549/6555 порт не шлёт вовсе. Отказов у честного порта нет.
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
    const wchar_t* kSec = L"P62_SlotUniqueness";

    bool  g_enabled      = true;
    int   g_mode         = 0;        // 0 журнал, 1 отказ
    bool  g_checkBounds  = true;     // вид 31: ссылка на пустой слот / вне границ (sub_4D61E0 == 0)
    int   g_logChannel   = 1;        // канал sub_569DF0 (1 = Log_Item)
    int   g_journalIntervalSec = 10;
    bool  g_h5018 = true, g_h6549 = true, g_h6506 = true, g_h6555 = true, g_h6096 = true, g_h6112 = true, g_h6067 = true;

    typedef int  (__fastcall *PFN_GetItem)(void* self, void* edx, int userNum, int type, int slot, void* item, void* abil); // sub_4D61E0 thiscall(i16,i16,i16,void*,void*)
    typedef void (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                                               // sub_569DF0
    PFN_GetItem const pGetItem = (PFN_GetItem)0x004D61E0;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog)Srv::kLog;

    constexpr int kOffMap       = 0x1C;
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;
    constexpr int kOffSellLock  = 0x157;   // 5018: замок «в полёте» (cmp 0x50E678 / set 0x50E6B2)

    // Виды журнала ac.other (выданы координатором: 30…34).
    enum Kind : BYTE { kDupPair = 30, kBadRef = 31, kDupUid = 32, kSameTitle = 33, kTargetInMats = 34 };
    constexpr int kKindBase = 30, kKindCount = 5;

    struct Sess
    {
        int   userIndex;
        DWORD lastJournal[kKindCount];
        int   suppressed[kKindCount];
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;
    volatile LONG g_checked = 0, g_viol = 0, g_refused = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    // Ограничитель: одна строка на (сессия, вид) за JournalIntervalSec; смена учётки в слоте — заново.
    bool Allow(int userNum, const BYTE* user, int kind, int* suppressedOut)
    {
        *suppressedOut = 0;
        if (!SessOk(userNum)) { return true; }
        const int k = kind - kKindBase;
        if (k < 0 || k >= kKindCount) { return true; }
        int userIndex = 0;
        __try { userIndex = user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { userIndex = 0; }
        bool allow = true;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[userNum];
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        const DWORD now = GetTickCount();
        if (g_journalIntervalSec > 0 && s.lastJournal[k] && now - s.lastJournal[k] < (DWORD)g_journalIntervalSec * 1000)
        {
            ++s.suppressed[k]; allow = false;
        }
        else
        {
            s.lastJournal[k] = now; *suppressedOut = s.suppressed[k]; s.suppressed[k] = 0;
        }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        return allow;
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }

    void Journal(BYTE kind, const BYTE* user, int userNum, int opcode, int v0, int v1, int action, const char* text, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = P47_PeerIpv4(userNum);
        e.suppressed = suppressed;
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
        e.v[0] = v0; e.v[1] = v1; e.v[2] = action;
        AcJournal::CopyText(e, text);
        AcJournal::Push(e);
    }

    // Нарушение: строка в лог сервера + журнал (под ограничителем). Возврат: 1 — отказ (Mode=1), 0 — журнал.
    int Violation(BYTE kind, const BYTE* user, int userNum, int opcode, const char* handler, int v0, int v1, const char* detail, const char* refuseText)
    {
        InterlockedIncrement(&g_viol);
        const int action = g_mode ? 1 : 0;
        int sup = 0;
        if (Allow(userNum, user, kind, &sup))
        {
            char text[64];
            _snprintf_s(text, sizeof(text), _TRUNCATE, "%s: %s", handler, detail);   // [fix13] ограниченный форматтер (был wsprintfA + text[63]=0 ПОСЛЕ записи)
            static const char* const kKindName[kKindCount] = { "duplicate (container,slot)", "empty/out-of-bounds slot", "duplicate pet uid", "same title in both slots", "target/source among materials" };
            int userIndex = -1;
            __try { userIndex = user ? *(const int*)(user + kOffUserIndex) : -1; } __except (EXCEPTION_EXECUTE_HANDLER) { userIndex = -1; }
            if (g_mode)
            {
                pSrvLog(g_logChannel, "P62 SlotUniqueness: %d %s %s %s, UserNum %d, UserIndex %d, %s -> REFUSE (%s)%s",
                        opcode, handler, kKindName[kind - kKindBase], detail, userNum, userIndex, NameOf(user), refuseText,
                        sup ? " (+suppressed)" : "");
            }
            else
            {
                pSrvLog(g_logChannel, "P62 SlotUniqueness: %d %s %s %s, UserNum %d, UserIndex %d, %s -> JOURNAL ONLY (Mode=0)%s",
                        opcode, handler, kKindName[kind - kKindBase], detail, userNum, userIndex, NameOf(user),
                        sup ? " (+suppressed)" : "");
            }
            Journal(kind, user, userNum, opcode, v0, v1, action, text, sup);
        }
        if (action) { InterlockedIncrement(&g_refused); }
        return action;
    }

    struct Ref { int type; int slot; };

    // ★ ОБЩАЯ ПРОВЕРКА списка ссылок (контейнер, слот). refs[0..n) — материалы/записи, extra — цель/источник
    //   (nullptr = нет). negIsUnused: слот < 0 = «запись не используется» (6506/6549/6555), иначе (5018) это
    //   ссылка, которую сток считает (вид 31). bounds — проверять вид 31 (у 6096 цели могут быть пустыми — нет).
    //   Возврат: 0 чисто, иначе результат Violation (0/1).
    int CheckRefs(void* mgr, const BYTE* user, int userNum, int opcode, const char* handler, const Ref* refs, int n,
                  const Ref* extra, bool negIsUnused, bool bounds, const char* refuseText)
    {
        InterlockedIncrement(&g_checked);
        char d[48];
        for (int i = 0; i < n; ++i)
        {
            const bool active = refs[i].type >= 1 && refs[i].type <= 5 && (refs[i].slot >= 0 || !negIsUnused);
            if (!active) { continue; }
            for (int j = i + 1; j < n; ++j)
            {
                if (refs[j].type == refs[i].type && refs[j].slot == refs[i].slot)
                {
                    _snprintf_s(d, sizeof(d), _TRUNCATE, "rec %d & %d = (%d,%d)", i, j, refs[i].type, refs[i].slot);
                    return Violation(kDupPair, user, userNum, opcode, handler, refs[i].type, refs[i].slot, d, refuseText);
                }
            }
            if (extra && extra->type == refs[i].type && extra->slot == refs[i].slot)
            {
                _snprintf_s(d, sizeof(d), _TRUNCATE, "rec %d = target (%d,%d)", i, refs[i].type, refs[i].slot);
                return Violation(kTargetInMats, user, userNum, opcode, handler, refs[i].type, refs[i].slot, d, refuseText);
            }
        }
        if (bounds && g_checkBounds && mgr)
        {
            for (int i = 0; i < n; ++i)
            {
                const bool active = refs[i].type >= 1 && refs[i].type <= 5 && (refs[i].slot >= 0 || !negIsUnused);
                if (!active) { continue; }
                BYTE item[57], abil[44];
                int found = 0;
                __try { found = pGetItem(mgr, nullptr, (short)userNum, (short)refs[i].type, (short)refs[i].slot, item, abil); }
                __except (EXCEPTION_EXECUTE_HANDLER) { found = 1; }   // не смогли проверить — не наказываем
                if (!found)
                {
                    _snprintf_s(d, sizeof(d), _TRUNCATE, "rec %d = (%d,%d) not found", i, refs[i].type, refs[i].slot);
                    return Violation(kBadRef, user, userNum, opcode, handler, refs[i].type, refs[i].slot, d, refuseText);
                }
            }
        }
        return 0;
    }

    BYTE* UserAt(BYTE* ebp, int off) { return *(BYTE**)(ebp - off); }
    void* MgrAt(BYTE* ebp, int off)  { return *(void**)(ebp - off); }
    int   UserNumAt(BYTE* ebp)       { return *(const short*)(ebp + 8); }
}

// ── C-проверки по кадру. Возврат 1 = отказ (только Mode=1), 0 = стоковая отправка в БД ──
extern "C" int __stdcall P62_OnSell5018(BYTE* ebp)
{
    if (!g_enabled || !g_h5018) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserAt(ebp, 0x154); void* mgr = MgrAt(ebp, 0x19C); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0x14C;
        Ref refs[5];
        for (int i = 0; i < 5; ++i) { refs[i].type = body[11 * i + 4]; refs[i].slot = *(const short*)(body + 11 * i); if (refs[i].type != 1 && refs[i].type != 2) { refs[i].type = 0; } }
        r = CheckRefs(mgr, user, userNum, 5018, "CharItemSell", refs, 5, nullptr, false, true, "5019 code 0");
        if (r && user) { *(int*)(user + kOffSellLock) = 0; }   // замок «в полёте» уже взведён (0x50E6B2) — снимаем, иначе продажа заперта
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

extern "C" int __stdcall P62_OnExtraction6549(BYTE* ebp)
{
    if (!g_enabled || !g_h6549) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserAt(ebp, 0x56C); void* mgr = MgrAt(ebp, 0x618); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0x5C0;
        Ref refs[8];
        for (int i = 0; i < 8; ++i) { refs[i].type = *(const short*)(body + 48 + 2 * i); refs[i].slot = *(const short*)(body + 32 + 2 * i); }
        const Ref src = { *(const short*)(body + 70), *(const short*)(body + 68) };
        r = CheckRefs(mgr, user, userNum, 6549, "UpgradeExtraction", refs, 8, &src, true, true, "6550 code 2");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

extern "C" int __stdcall P62_OnReset6506(BYTE* ebp)
{
    if (!g_enabled || !g_h6506) { return 0; }
    int r = 0;
    __try
    {
        if (*(const BYTE*)(ebp - 0x1DD) != 1) { return 0; }   // материалы читаются только при виде 1 (GS:99456)
        BYTE* user = UserAt(ebp, 0x428); void* mgr = MgrAt(ebp, 0x4BC); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0x1DC;
        Ref refs[10];
        for (int i = 0; i < 10; ++i) { refs[i].type = body[6 + i]; refs[i].slot = *(const short*)(body + 16 + 2 * i); }
        const Ref target = { body[3], *(const short*)(body + 4) };
        r = CheckRefs(mgr, user, userNum, 6506, "ShellItemUpgradeReset", refs, 10, &target, true, true, "6507 code 5");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

extern "C" int __stdcall P62_OnPrimiumSum6555(BYTE* ebp)
{
    if (!g_enabled || !g_h6555) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserAt(ebp, 0x23C); void* mgr = MgrAt(ebp, 0x298); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0x268;
        Ref refs[5];
        for (int i = 0; i < 5; ++i)
        {
            refs[i].type = *(const short*)(body + 30 + 2 * i); refs[i].slot = *(const short*)(body + 20 + 2 * i);
            if (*(const int*)(body + 4 * i) < 0) { refs[i].type = 0; }   // сток такие записи пропускает (GS:118757)
        }
        r = CheckRefs(mgr, user, userNum, 6555, "PrimiumSum", refs, 5, nullptr, true, true, "6556 code 10");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

extern "C" int __stdcall P62_OnOpenPackage6096(BYTE* ebp)
{
    if (!g_enabled || !g_h6096) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserAt(ebp, 0x3F4); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0x3EC;
        int n = body[6]; if (n > 5) { n = 5; }
        Ref refs[5];
        for (int i = 0; i < n; ++i) { refs[i].type = body[10 + 3 * i]; refs[i].slot = *(const short*)(body + 11 + 3 * i); }
        // ★ P100 (01.11.2026): позиции-спецпредметы одного ключа P95 кладёт в ОДНУ ячейку сумки (стопка зарядов) — повтор
        //   пары (1, слот) для такой ячейки не нарушение: второй и следующие повторы снимаются из проверки.
        for (int i = 1; i < n; ++i)
        {
            if (refs[i].type != 1 || !P100_IsBoxMergeSlot(userNum, refs[i].slot)) { continue; }
            for (int j = 0; j < i; ++j) { if (refs[j].type == 1 && refs[j].slot == refs[i].slot) { refs[i].type = 0; break; } }
        }
        const Ref box = { body[7], *(const short*)(body + 8) };
        // Целевые слоты могут быть ПУСТЫМИ (сток проверяет их sub_4D6910) — только уникальность, без вида 31.
        r = CheckRefs(nullptr, user, userNum, 6096, "OpenPackageItem", refs, n, &box, false, false, "6097 code 7");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

extern "C" int __stdcall P62_OnPetUnion6112(BYTE* ebp)
{
    if (!g_enabled || !g_h6112) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserAt(ebp, 0xD8); const int userNum = UserNumAt(ebp);
        const BYTE* body = ebp - 0xD4;
        InterlockedIncrement(&g_checked);
        int uid[3], n = 0;
        for (int i = 0; i < 3; ++i) { uid[i] = *(const int*)(body + 6 + 4 * i); if (uid[i] == -1) { break; } ++n; }   // сток идёт до первого −1 (GS:35991)
        for (int i = 0; i < n && !r; ++i)
        {
            for (int j = i + 1; j < n; ++j)
            {
                if (uid[i] == uid[j])
                {
                    char d[48]; _snprintf_s(d, sizeof(d), _TRUNCATE, "mat %d & %d = uid %d", i, j, uid[i]);
                    r = Violation(kDupUid, user, userNum, 6112, "PetUnion", uid[i], i, d, "6113 code 3");
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

// 6067: после стокового GetUser (user ≠ 0). Mode=1 — слот 1 := −1 в кадре (как сток помечает слот вне диапазона).
extern "C" void __stdcall P62_OnFame6067(BYTE* ebp, BYTE* user)
{
    if (!g_enabled || !g_h6067) { return; }
    __try
    {
        short* body = (short*)(ebp - 0x38);
        const int userNum = UserNumAt(ebp);
        InterlockedIncrement(&g_checked);
        const short s0 = body[3], s1 = body[4];
        if (s0 >= 0 && s0 == s1)
        {
            char d[48]; _snprintf_s(d, sizeof(d), _TRUNCATE, "slot0 = slot1 = title %d", s0);
            if (Violation(kSameTitle, user, userNum, 6067, "ChangeActiveFame", s0, 1, d, "slot1 := -1")) { body[4] = -1; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

extern "C" __declspec(dllexport) void __stdcall P62_GetStats(int* checked, int* viol, int* refused)   // экспорт — для стенда tools/stand_p62
{
    if (checked) { *checked = g_checked; } if (viol) { *viol = g_viol; } if (refused) { *refused = g_refused; }
}

namespace
{
    DWORD g_pGetUser     = Srv::kGetUser;       // 0x5324A0 — стоковая цель площадки 6067
    DWORD g_ref5018 = 0x0050E681;   // 5019 код 0 (LABEL_83)
    DWORD g_ref6549 = 0x005349DB;   // 6550 код 2 (ветка (4))
    DWORD g_ref6506 = 0x005017AB;   // 6507 код 5
    DWORD g_ref6555 = 0x005370F8;   // 6556 код 10 (ветка (3))
    DWORD g_ref6096 = 0x0055ACC6;   // 6097 код 7 (LABEL_43)
    DWORD g_ref6112 = 0x00458DF7;   // 6113 код 3 (LABEL_25)
    // ★ integ2: «следующий вызов» на проходе — по площадке (общая точка P62 ↔ P63, Patches.h). По умолчанию сток
    //   sub_5646C0; P63 подставляет сюда свой St_Send на пяти общих площадках (5018 у P63 нет — свой замок у стока).
    volatile DWORD g_next5018 = Srv::kConnectSend;
    volatile DWORD g_next6549 = Srv::kConnectSend;
    volatile DWORD g_next6506 = Srv::kConnectSend;
    volatile DWORD g_next6555 = Srv::kConnectSend;
    volatile DWORD g_next6096 = Srv::kConnectSend;
    volatile DWORD g_next6112 = Srv::kConnectSend;

    // Проход — ХВОСТОВОЙ jmp в «следующий вызов»: [esp] = адрес возврата в обработчик, [esp+4..+20] = 5 аргументов,
    // ecx = CUserMoveManager, ebp = кадр обработчика — ровно как у стоковой `call sub_5646C0`. Отказ — esp к состоянию
    // до push'ей (возврат + 5 аргументов) и стоковое тело отказа обработчика.
#define P62_STUB(NAME, FN, REF, NEXT)                                      \
    __declspec(naked) void NAME()                                          \
    {                                                                      \
        __asm { pushad }                                                   \
        __asm { push ebp }                                                 \
        __asm { call FN }                        /* __stdcall(ebp) → eax */ \
        __asm { mov dword ptr [esp+28], eax }    /* в сохранённый eax */    \
        __asm { popad }                                                    \
        __asm { test eax, eax }                                            \
        __asm { jnz refuse }                                               \
        __asm { jmp dword ptr [NEXT] }           /* P63 St_Send или сток */ \
        __asm { refuse: }                                                  \
        __asm { add esp, 0x18 }                  /* возврат + 5 аргументов */ \
        __asm { jmp dword ptr [REF] }            /* стоковое тело отказа */  \
    }

    P62_STUB(St_Sell5018,        P62_OnSell5018,        g_ref5018, g_next5018)
    P62_STUB(St_Extraction6549,  P62_OnExtraction6549,  g_ref6549, g_next6549)
    P62_STUB(St_Reset6506,       P62_OnReset6506,       g_ref6506, g_next6506)
    P62_STUB(St_PrimiumSum6555,  P62_OnPrimiumSum6555,  g_ref6555, g_next6555)
    P62_STUB(St_OpenPackage6096, P62_OnOpenPackage6096, g_ref6096, g_next6096)
    P62_STUB(St_PetUnion6112,    P62_OnPetUnion6112,    g_ref6112, g_next6112)
#undef P62_STUB

    // 6067: вместо `call sub_5324A0` (thiscall: ecx = CUserManager, [esp+4] userNum, ret 4). eax стока сохраняется.
    __declspec(naked) void St_Fame6067()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pGetUser]
            test  eax, eax
            jz    done
            pushad
            push  eax                          // user
            push  ebp
            call  P62_OnFame6067               // __stdcall(ebp, user)
            popad
        done:
            ret   4
        }
    }

    const BYTE kOrig5018[5] = { 0xE8, 0x2A, 0x5D, 0x05, 0x00 };   // 0x50E991 call 0x5646C0
    const BYTE kOrig6549[5] = { 0xE8, 0xB9, 0xF4, 0x02, 0x00 };   // 0x535202
    const BYTE kOrig6506[5] = { 0xE8, 0x5F, 0x2C, 0x06, 0x00 };   // 0x501A5C
    const BYTE kOrig6555[5] = { 0xE8, 0xC8, 0xCF, 0x02, 0x00 };   // 0x5376F3
    const BYTE kOrig6096[5] = { 0xE8, 0x6C, 0x98, 0x00, 0x00 };   // 0x55AE4F
    const BYTE kOrig6112[5] = { 0xE8, 0xF4, 0xB5, 0x10, 0x00 };   // 0x4590C7
    const BYTE kOrig6067[5] = { 0xE8, 0xB6, 0x5B, 0xFE, 0xFF };   // 0x54C8E5 call 0x5324A0
    // Соседи: стоковые тела отказов и возврат 6067.
    const BYTE kNb5018[4]  = { 0xC6, 0x45, 0xB8, 0x00 };                     // 0x50E681 mov byte [ebp-48h],0
    const BYTE kNbLock[13] = { 0x8B, 0x85, 0xAC, 0xFE, 0xFF, 0xFF, 0x83, 0xB8, 0x57, 0x01, 0x00, 0x00, 0x00 };   // 0x50E672 cmp [pUser+157h],0
    const BYTE kNb6549[7]  = { 0xC6, 0x85, 0xA8, 0xFD, 0xFF, 0xFF, 0x02 };   // 0x5349DB mov byte [ebp-258h],2
    const BYTE kNb6506[7]  = { 0xC6, 0x85, 0x58, 0xFF, 0xFF, 0xFF, 0x05 };   // 0x5017AB mov byte [ebp-A8h],5
    const BYTE kNb6555[4]  = { 0xC6, 0x45, 0xA0, 0x0A };                     // 0x5370F8 mov byte [ebp-60h],0Ah
    const BYTE kNb6096[7]  = { 0xC6, 0x85, 0x3F, 0xFC, 0xFF, 0xFF, 0x07 };   // 0x55ACC6 mov byte [ebp-3C1h],7
    const BYTE kNb6112[7]  = { 0xC6, 0x85, 0x4C, 0xFF, 0xFF, 0xFF, 0x03 };   // 0x458DF7 mov byte [ebp-B4h],3
    const BYTE kNb6067[3]  = { 0x89, 0x45, 0xC0 };                           // 0x54C8EA mov [ebp-40h],eax
    const BYTE kNbGetItem[5] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC };             // 0x4D61E0 пролог sub_4D61E0

    // Площадки `call sub_5646C0` — таблица для общей точки P62 ↔ P63 (Patches.h).
    struct SendSite { DWORD va; const BYTE* orig; void (*stub)(); volatile DWORD* next; bool* on; bool put; };
    SendSite g_send[] =
    {
        { 0x0050E991, kOrig5018, St_Sell5018,        &g_next5018, &g_h5018, false },
        { 0x00535202, kOrig6549, St_Extraction6549,  &g_next6549, &g_h6549, false },
        { 0x00501A5C, kOrig6506, St_Reset6506,       &g_next6506, &g_h6506, false },
        { 0x005376F3, kOrig6555, St_PrimiumSum6555,  &g_next6555, &g_h6555, false },
        { 0x0055AE4F, kOrig6096, St_OpenPackage6096, &g_next6096, &g_h6096, false },
        { 0x004590C7, kOrig6112, St_PetUnion6112,    &g_next6112, &g_h6112, false },
    };
    SendSite* SendAt(DWORD va) { for (auto& s : g_send) { if (s.va == va) { return &s; } } return nullptr; }

    // Цель call rel32 на площадке (0 — не E8 / нет доступа).
    DWORD CallTarget(DWORD va)
    {
        __try { const BYTE* p = (const BYTE*)va; if (p[0] != 0xE8) { return 0; } return va + 5 + *(const DWORD*)(p + 1); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    void LogMismatch(DWORD va, const BYTE* want)
    {
        wchar_t got[32], exp[32]; static const wchar_t* kHex = L"0123456789abcdef"; int o = 0;
        Hook::Dump(va, 5, got, 32);
        for (int k = 0; k < 5; ++k) { if (k) { exp[o++] = L' '; } exp[o++] = kHex[want[k] >> 4]; exp[o++] = kHex[want[k] & 0x0F]; }
        exp[o] = 0;
        Log::Line(L"    MISMATCH P62 @0x%08X: ожидалось [%s], в памяти [%s]", va, exp, got);
    }
}

// ── общая точка P62 ↔ P63 (Patches.h) ──
const void* P62_SendStubAt(DWORD va) { const SendSite* s = SendAt(va); return (s && s->put) ? (const void*)s->stub : nullptr; }
const BYTE* P62_SendOrigAt(DWORD va) { const SendSite* s = SendAt(va); return s ? s->orig : nullptr; }
bool P62_ChainSend(DWORD va, const void* next)
{
    SendSite* s = SendAt(va);
    if (!s || !s->put || !next) { return false; }
    InterlockedExchange((volatile LONG*)s->next, (LONG)(DWORD)next);
    return true;
}
extern "C" __declspec(dllexport) DWORD __stdcall P62_GetSendNext(DWORD va)
{
    const SendSite* s = SendAt(va);
    return (s && s->put) ? *s->next : 0;
}

PatchResult P62_SlotUniqueness()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_checkBounds = Config::GetBool(kSec, L"CheckBounds", true);
    g_logChannel  = Config::GetInt(kSec, L"LogChannel", 1);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    g_h5018 = Config::GetBool(kSec, L"Sell5018", true);
    g_h6549 = Config::GetBool(kSec, L"Extraction6549", true);
    g_h6506 = Config::GetBool(kSec, L"Reset6506", true);
    g_h6555 = Config::GetBool(kSec, L"PrimiumSum6555", true);
    g_h6096 = Config::GetBool(kSec, L"OpenPackage6096", true);
    g_h6112 = Config::GetBool(kSec, L"PetUnion6112", true);
    g_h6067 = Config::GetBool(kSec, L"Fame6067", true);
    if (g_logChannel < 0 || g_logChannel > 40) { g_logChannel = 1; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    // Соседи и площадка 6067 — сверка стоковых байт. Площадки `call sub_5646C0` — отдельно (общая точка с P63).
    const Site sites[] =
    {
        { 0x0054C8E5, kOrig6067, sizeof(kOrig6067) },
        { 0x0050E681, kNb5018, sizeof(kNb5018) },     { 0x0050E672, kNbLock, sizeof(kNbLock) },
        { 0x005349DB, kNb6549, sizeof(kNb6549) },     { 0x005017AB, kNb6506, sizeof(kNb6506) },
        { 0x005370F8, kNb6555, sizeof(kNb6555) },     { 0x0055ACC6, kNb6096, sizeof(kNb6096) },
        { 0x00458DF7, kNb6112, sizeof(kNb6112) },     { 0x0054C8EA, kNb6067, sizeof(kNb6067) },
        { 0x004D61E0, kNbGetItem, sizeof(kNbGetItem) },
    };
    bool ok = VerifyAllSites(L"P62", sites, ARRAYSIZE(sites));
    // Площадки отправки (только включённые): сток → «следующий» = sub_5646C0; уже стоит St_Send P63 (P63 поставлен
    // раньше) и его исходные байты те же → забираем площадку, «следующий» = St_Send P63 (порядок P62 → P63 сохраняется).
    DWORD nextOf[ARRAYSIZE(g_send)] = {};
    int chained = 0;
    for (int i = 0; i < (int)ARRAYSIZE(g_send); ++i)
    {
        const SendSite& s = g_send[i];
        if (!*s.on) { continue; }
        if (Hook::Verify(s.va, s.orig, 5)) { nextOf[i] = Srv::kConnectSend; continue; }
        const void* p63 = P63_SendStubAt(s.va);
        const BYTE* p63orig = P63_SendOrigAt(s.va);
        if (p63 && p63orig && memcmp(p63orig, s.orig, 5) == 0 && CallTarget(s.va) == (DWORD)p63)
        {
            nextOf[i] = (DWORD)p63; ++chained;
            Log::Line(L"    P62: площадка 0x%08X уже у P63 (St_Send) — цепочка P62 → P63 → sub_5646C0", s.va);
            continue;
        }
        LogMismatch(s.va, s.orig); ok = false;
    }
    if (!ok) { return PatchResult::Mismatch; }

    int put = 0;
    for (int i = 0; i < (int)ARRAYSIZE(g_send); ++i)
    {
        SendSite& s = g_send[i];
        if (!*s.on) { continue; }
        InterlockedExchange((volatile LONG*)s.next, (LONG)nextOf[i]);   // слот ДО записи площадки
        if (!Hook::WriteCall(s.va, (const void*)s.stub, 5)) { return PatchResult::Failed; }
        s.put = true; ++put;
    }
    if (g_h6067)
    {
        if (!Hook::WriteCall(0x0054C8E5, (const void*)&St_Fame6067, 5)) { return PatchResult::Failed; }
        ++put;
    }
    Log::Line(L"    P62: режим %s; площадок %d/7 (5018=%d 6549=%d 6506=%d 6555=%d 6096=%d 6112=%d 6067=%d); границы (вид 31)=%d; "
              L"канал лога %d; строки не чаще 1/%d с на (сессия, вид); цепочек с P63 при установке %d",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ", put, g_h5018, g_h6549, g_h6506, g_h6555, g_h6096, g_h6112, g_h6067,
              g_checkBounds ? 1 : 0, g_logChannel, g_journalIntervalSec, chained);
    return put ? PatchResult::Applied : PatchResult::Disabled;
}
