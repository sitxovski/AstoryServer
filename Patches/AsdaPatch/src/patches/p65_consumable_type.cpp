// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P65 — ★ ТИП РАСХОДНИКА ПО СЕРВЕРНОЙ ТАБЛИЦЕ (античит, волна A7 «экономика / предметы», 2026-10-12;
//  план 00_PLAN.md §8 механизм L5, приоритет A9; находки 02_parts/economy2_handlers.md «Топ-5» п.4).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Документ: `AstoryServer/Docs/GameServer/consumable-type-p65.md`.
//
//  ── ДЫРА ──
//  Четыре обработчика принимают «любой функциональный предмет» — код 1…N таблицы Function_Table.txt
//  (загрузчик sub_4AF980@0x4AF980, GS:70386: dword_5F5E70 — массив записей по 48 б, индекс code−1,
//  колонка 5 → байт +8 = ТИП, колонка 6 → i16 +9 = значение), проверяя лишь диапазон кода
//  (sub_532B10@0x532B10: 1 <= code <= [0x5F5EA4]):
//   1. 6551 Recv_UserUpgradeBless@0x5358C0 (GS:118179): свиток благословения — любой функциональный предмет;
//      ступень берётся из байта +24 записи свитка (LOBYTE(a5[6])). Сток 6549 (извлечение, GS:117911/117929)
//      ПОРОЖДАЕТ такие свитки только из записей таблицы с типом 204 (код 401: `movzx eax,[edx+4B08h]; cmp eax,0CCh`
//      @0x534DDF) и 206 (код 363: `movzx ecx,[eax+43E8h]; cmp ecx,0CEh` @0x534E94). В Function_Table.txt (12.10)
//      тип 204 = коды 401/402/414, тип 206 = 363/413.
//   2. 6553 Recv_UserItemOptionTrans@0x536460 (GS:118490): свиток обмена опций — любой функциональный предмет.
//      Клиент (эталон sumInventoryItemsType67@0xB63500, порт AsdaItemOptionSubsystem kScrollSubType=67) кладёт в окно
//      только special_itemlist.SubType==67; серверная Function_Table тип 67 — коды 364/365/366/458/546 (529 из 558
//      кодов имеют тип == клиентскому SubType; у 367 и 393 таблицы разошлись — сервер 17/15, авторитет сервер).
//   3. 5433 Recv_ShellItemOption_Extraction@0x513F80 (GS:105447–105454): «помощник» — бонус к шансу из +9
//      ЛЮБОГО функционального предмета (`movsx edx,[ecx+eax+9]` @0x514A97). Клиент (порт AsdaExtractShopSubsystem
//      kScrollSubType=96) — SubType 96; Function_Table тип 96 — коды 289/290/291/459 (у всех +9 = 0, бонус нулевой).
//   4. 5450 Char_FunctionItem_Use@0x4ED780: гейты (состояние тип≠48, пол 35/36, уровень 54/55; GS:91702–91745)
//      решаются по коду ИЗ ПАКЕТА ([ebp-0x1FE]), действие — по коду ИЗ СЛОТА ([ebp-0x16C]; GS:91779); равенство
//      не сверяется. Порт шлёт код слота (AsdaInventorySubsystem.cpp: `Code = Src->ItemCode` → SendFunctionItemUse5450).
//
//  ── МЕХАНИЗМ ──
//  Площадки — четыре `E8 rel32` `call sub_532B10` ЦЕЛИКОМ (cdecl(int code) → eax 0/1; аргумент снимает сток `add esp,4`):
//  стаб зовёт сток (диапазон), при «1» читает тип из таблицы (индекс уже проверен стоком) и сверяет со списком ini;
//  5450 — сверяет код пакета с кодом слота. Нарушение: Mode=0 — строка Log_Item (sub_569DF0(1,…)) + журнал ac.other
//  (виды 45…48) с ограничителем на (сессия, вид) — и ПРОПУСК как в стоке; Mode=1 — стаб возвращает 0, и сток уходит
//  в СВОЮ соседнюю ветку отказа (`jne/je` сразу после площадки):
//   6551 → 6552 код 2 (119 б, GS:118267 «Recv_UserUpgradeBless(3)»; тело @0x535B0D),
//   6553 → 6554 код 2 (119 б, GS:118543 «Recv_UserItemOptionTrans(5)»; тело @0x536656),
//   5433 → 5434 код 0 (184 б, GS:105449 «Recv_ShellItemOption_Extraction(13)»; тело @0x514AAA),
//   5450 → 5451 код 9 (68 б, GS:91781 «Not FunctionItem»; тело @0x4EDDA4 → LABEL_165).
//  Новых пакетов/кодов нет; протокол не меняется. Честный порт: 6551 не шлёт вовсе; 6553/5433 — только SubType 67/96;
//  5450 — код слота. Единственный риск — коды 367/393 (клиент 67, сервер 17/15): порт предложит их в окно 6553,
//  сервер (Mode=1) откажет кодом 2; в Mode=0 это видно в журнале (вид 46).
//  Кадры (по дизасму стока; живой/Indun e7b4ac38 = сток для этих мест): userNum = word [ebp+8] у всех
//  (0x535B13 / 0x53665F / 0x514AD9 / 0x4EDDBC);
//   6551: код свитка [ebp-0x19C] (push @0x535AFA), код вещи [ebp-0x194] (@0x535C26), pUser [ebp-0x18C] (@0x535A11);
//   6553: код свитка [ebp-0xFC] (@0x536643), код вещи [ebp-0xF4] (@0x536685), pUser [ebp-0xEC] (@0x5365A8);
//   5433: код помощника [ebp-0x134] (@0x514A72), Src[0] [ebp-0x48], CUserManager this [ebp-0x260] (@0x513F93);
//   5450: код слота [ebp-0x16C] (@0x4EDD7B), код пакета [ebp-0x1FE] (@0x4ED97D), pUser [ebp-0x20C] (@0x4ED9CF).
//  Соседние площадки других патчей: P15 0x4ED9EF, P08 0x4ED8DE, P49 0x4ED8CF, P33 0x535E01 — не пересекаются.
//  Переходов/abs32 внутрь площадок нет (tools/verify_p65.py по трём образам).
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
    const wchar_t* kSec = L"P65_ConsumableType";

    bool g_enabled      = true;
    int  g_mode         = 0;       // 0 журнал, 1 отказ
    bool g_chkBless     = true;    // 6551
    bool g_chkOptTrans  = true;    // 6553
    bool g_chkHelper    = true;    // 5433
    bool g_chkUseCode   = true;    // 5450
    int  g_journalIntervalSec = 10;
    int  g_logChannel   = 1;       // 1 = Log_Item

    // Список типов из ini (через запятую). n == 0 — не проверять (так задано владельцем для недоказанных типов).
    struct TypeList { int n; BYTE t[16]; };
    TypeList g_bless = {}, g_optTrans = {}, g_helper = {};

    typedef int   (__cdecl    *PFN_IsFunc)(int code);                                   // sub_532B10
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);        // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);              // sub_569DF0
    PFN_IsFunc  const pIsFunc  = (PFN_IsFunc) 0x00532B10;
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    constexpr DWORD kFuncTablePtr = 0x005F5E70;   // dword_5F5E70 — указатель на записи Function_Table (48 б)
    constexpr DWORD kFuncCountVa  = 0x005F5EA4;   // dword_5F5EA4 — число записей
    constexpr int   kFuncRec      = 48;
    constexpr int   kOffType      = 8;            // колонка 5 загрузчика (GS:70464) — тип
    constexpr int   kOffUserIndex = 0x174;
    constexpr int   kOffName      = 0x178;
    constexpr int   kOffSlot      = 0x18C;

    enum Place : int { kBless = 1, kOptTrans = 2, kHelper = 3, kUse = 4 };
    // Виды журнала ac.other — выданы координатором: 45…49 (49 — резерв, не используется).
    enum Kind : BYTE { kKindBless = 45, kKindOptTrans = 46, kKindHelper = 47, kKindUse = 48 };

    struct Sess
    {
        int   userIndex;      // чья сессия (смена учётки в слоте — сброс)
        DWORD last[5];        // такт последней строки по площадке 1..4 (ограничитель)
        int   suppressed[5];  // подавлено ограничителем
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_checked = 0, g_viol = 0, g_refused = 0, g_journaled = 0, g_suppressed = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    bool InList(const TypeList& l, int type)
    {
        for (int i = 0; i < l.n; ++i) { if (l.t[i] == type) { return true; } }
        return false;
    }

    void ParseList(const wchar_t* s, TypeList& out)
    {
        out.n = 0;
        int v = -1;
        for (const wchar_t* p = s; ; ++p)
        {
            if (*p >= L'0' && *p <= L'9') { v = (v < 0 ? 0 : v * 10) + (*p - L'0'); if (v > 255) { v = 255; } }
            else
            {
                if (v >= 0 && out.n < 16) { out.t[out.n++] = (BYTE)v; }
                v = -1;
                if (!*p) { break; }
            }
        }
    }

    // [fix13, 2026-10-13] Ограниченный форматтер вместо wsprintfA: прежняя проверка `len < cch - 5` держалась только на том,
    // что тип — BYTE (",255" + NUL = 5 б); теперь каждый кусок — _snprintf_s в остаток буфера с усечением, ноль гарантирован.
    void ListText(const TypeList& l, char* out, int cch)
    {
        if (!out || cch <= 0) { return; }
        out[0] = 0;
        int len = 0;
        for (int i = 0; i < l.n && len < cch - 1; ++i)
        {
            const int w = _snprintf_s(out + len, (size_t)(cch - len), _TRUNCATE, i ? ",%d" : "%d", l.t[i]);
            if (w < 0) { break; }   // усечено — дальше не пишем
            len += w;
        }
        out[cch - 1] = 0;
    }

    // Ограничитель: true — писать; иначе копим suppressed. Под g_lock.
    bool Allow(Sess& s, int site, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.last[site] && now - s.last[site] < (DWORD)g_journalIntervalSec * 1000) { ++s.suppressed[site]; return false; }
        s.last[site] = now;
        return true;
    }

    // Тип записи таблицы по коду (−1 — таблицы нет / код вне). Индекс уже проверен стоком, но сверяем ещё раз.
    int TypeOf(int code)
    {
        __try
        {
            const BYTE* table = *(const BYTE**)kFuncTablePtr;
            const int count = *(const int*)kFuncCountVa;
            if (!table || code < 1 || code > count) { return -1; }
            return table[kFuncRec * (code - 1) + kOffType];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    void Journal(BYTE kind, int opcode, const BYTE* user, int userNum, int v0, int v1, int v2, const char* text, int suppressed)
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
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, text);
        AcJournal::Push(e);
        InterlockedIncrement(&g_journaled);
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }
    int IndexOf(const BYTE* user) { return user ? *(const int*)(user + kOffUserIndex) : -1; }
}

// Общая C-точка четырёх стабов. site — площадка, code — аргумент стока (код предмета), ebp — кадр обработчика.
// Возврат — как у sub_532B10 (eax): 0 → сток уходит в свою ветку отказа; 1 → пропуск.
extern "C" int __stdcall P65_Check(int site, int code, BYTE* ebp)
{
    int r = 0;
    __try { r = pIsFunc(code); } __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    if (!r || !g_enabled || !ebp) { return r; }
    __try
    {
        if ((site == kBless    && (!g_chkBless    || g_bless.n == 0))    ||
            (site == kOptTrans && (!g_chkOptTrans || g_optTrans.n == 0)) ||
            (site == kHelper   && (!g_chkHelper   || g_helper.n == 0))   ||
            (site == kUse      && !g_chkUseCode)) { return r; }
        InterlockedIncrement(&g_checked);
        const int userNum = *(const short*)(ebp + 8);
        const int type = TypeOf(code);
        const BYTE* user = nullptr;
        int opcode = 0, other = 0, v1 = type;
        BYTE kind = 0;
        const TypeList* list = nullptr;
        const char* name = "";
        bool bad = false;
        switch (site)
        {
        case kBless:
            opcode = 6551; kind = kKindBless; list = &g_bless; name = "6551 UpgradeBless scroll";
            user  = *(BYTE**)(ebp - 0x18C);
            other = *(const int*)(ebp - 0x194);                   // код вещи (второй предмет пакета)
            bad   = !InList(*list, type);
            break;
        case kOptTrans:
            opcode = 6553; kind = kKindOptTrans; list = &g_optTrans; name = "6553 ItemOptionTrans scroll";
            user  = *(BYTE**)(ebp - 0xEC);
            other = *(const int*)(ebp - 0xF4);
            bad   = !InList(*list, type);
            break;
        case kHelper:
            opcode = 5433; kind = kKindHelper; list = &g_helper; name = "5433 Extraction helper";
            if (SessOk(userNum)) { void* mgr = *(void**)(ebp - 0x260); if (mgr) { user = pGetUser(mgr, nullptr, (short)userNum); } }
            other = *(const int*)(ebp - 0x48);                    // Src[0] — код источника опций
            bad   = !InList(*list, type);
            break;
        case kUse:
            opcode = 5450; kind = kKindUse; name = "5450 FunctionItem_Use packet code != slot code";
            user  = *(BYTE**)(ebp - 0x20C);
            other = *(const int*)(ebp - 0x1FE);                   // код из пакета (по нему решались гейты)
            v1    = other;
            bad   = other != code;
            break;
        default:
            return r;
        }
        if (!bad) { return r; }
        InterlockedIncrement(&g_viol);
        if (SessOk(userNum))
        {
            const DWORD now = GetTickCount();
            int sup = 0; bool write = true;
            if (g_lockReady) { EnterCriticalSection(&g_lock); }
            Sess& s = g_sess[userNum];
            const int ui = IndexOf(user);
            if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
            write = Allow(s, site, now);
            if (write) { sup = s.suppressed[site]; s.suppressed[site] = 0; }
            if (g_lockReady) { LeaveCriticalSection(&g_lock); }
            if (write)
            {
                char lst[80] = ""; if (list) { ListText(*list, lst, sizeof(lst)); }
                // [fix13, 2026-10-13] было `char detail[64]` + wsprintfA: имя + " type %d not in {" + список до 79 б —
                // переполнение при длинном OptionTransTypes. Теперь 160 б и ограниченный форматтер (ноль гарантирован).
                char detail[160];
                if (site == kUse) { _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s", name); }
                else { _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s type %d not in {%s}", name, type, lst); }
                if (site == kUse)
                {
                    pSrvLog(g_logChannel, "P65 ConsumableType: 5450 packet code %d != slot code %d (slot type %d), %s UserNum %d UserIndex %d%s%s",
                            other, code, type, NameOf(user), userNum, IndexOf(user),
                            g_mode ? " -> REFUSE (code 9)" : " (journal)", sup ? " (suppressed before)" : "");
                }
                else
                {
                    pSrvLog(g_logChannel, "P65 ConsumableType: %s code %d type %d not in {%s} (other item %d), %s UserNum %d UserIndex %d%s%s",
                            name, code, type, lst, other, NameOf(user), userNum, IndexOf(user),
                            g_mode ? " -> REFUSE (stock branch)" : " (journal)", sup ? " (suppressed before)" : "");
                }
                Journal(kind, opcode, user, userNum, code, v1, other, detail, sup);
            }
            else { InterlockedIncrement(&g_suppressed); }
        }
        if (g_mode == 1) { InterlockedIncrement(&g_refused); return 0; }
        return r;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return r; }
}

extern "C" void __stdcall P65_GetStats(int* checked, int* viol, int* refused, int* journaled, int* suppressed)
{
    if (checked) { *checked = g_checked; } if (viol) { *viol = g_viol; } if (refused) { *refused = g_refused; }
    if (journaled) { *journaled = g_journaled; } if (suppressed) { *suppressed = g_suppressed; }
}

namespace
{
    // Стабы вместо `call sub_532B10` (cdecl: [esp+4] = code; аргумент снимает вызывающий). ecx/edx сохраняем
    // (сток sub_532B10 их не трогает). После push ecx/edx/ebp аргумент стока лежит в [esp+16].
    __declspec(naked) void St_Bless6551()
    {
        __asm { push ecx } __asm { push edx } __asm { push ebp } __asm { push dword ptr [esp+16] } __asm { push 1 }
        __asm { call P65_Check } __asm { pop edx } __asm { pop ecx } __asm { ret }
    }
    __declspec(naked) void St_OptTrans6553()
    {
        __asm { push ecx } __asm { push edx } __asm { push ebp } __asm { push dword ptr [esp+16] } __asm { push 2 }
        __asm { call P65_Check } __asm { pop edx } __asm { pop ecx } __asm { ret }
    }
    __declspec(naked) void St_Helper5433()
    {
        __asm { push ecx } __asm { push edx } __asm { push ebp } __asm { push dword ptr [esp+16] } __asm { push 3 }
        __asm { call P65_Check } __asm { pop edx } __asm { pop ecx } __asm { ret }
    }
    __declspec(naked) void St_Use5450()
    {
        __asm { push ecx } __asm { push edx } __asm { push ebp } __asm { push dword ptr [esp+16] } __asm { push 4 }
        __asm { call P65_Check } __asm { pop edx } __asm { pop ecx } __asm { ret }
    }

    // Площадки: `E8 rel32` → sub_532B10 (0x532B10).
    const BYTE kOrigBless[5]    = { 0xE8, 0x0A, 0xD0, 0xFF, 0xFF };   // 0x535B01  6551
    const BYTE kOrigOptTrans[5] = { 0xE8, 0xC1, 0xC4, 0xFF, 0xFF };   // 0x53664A  6553
    const BYTE kOrigHelper[5]   = { 0xE8, 0x92, 0xE0, 0x01, 0x00 };   // 0x514A79  5433
    const BYTE kOrigUse[5]      = { 0xE8, 0x89, 0x4D, 0x04, 0x00 };   // 0x4EDD82  5450
    // Соседи: аргумент (push кода из кадра), хвост `add esp,4; test eax,eax; jcc`, тело стокового отказа.
    const BYTE kNbBlessPush[7]    = { 0x8B, 0x95, 0x64, 0xFE, 0xFF, 0xFF, 0x52 };   // 0x535AFA mov edx,[ebp-19Ch]; push edx
    const BYTE kNbBlessAfter[7]   = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x75, 0x44 };   // 0x535B06 add esp,4; test eax,eax; jne 0x535B51
    const BYTE kNbBlessRefuse[4]  = { 0xC6, 0x45, 0x80, 0x02 };                     // 0x535B0D mov byte [ebp-80h],2 (6552 код 2)
    const BYTE kNbOptPush[7]      = { 0x8B, 0x95, 0x04, 0xFF, 0xFF, 0xFF, 0x52 };   // 0x536643 mov edx,[ebp-FCh]; push edx
    const BYTE kNbOptAfter[7]     = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x75, 0x4A };   // 0x53664F … jne 0x5366A0
    const BYTE kNbOptRefuse[7]    = { 0xC6, 0x85, 0x48, 0xFF, 0xFF, 0xFF, 0x02 };   // 0x536656 mov byte [ebp-B8h],2 (6554 код 2)
    const BYTE kNbHelperPush[7]   = { 0x8B, 0x95, 0xCC, 0xFE, 0xFF, 0xFF, 0x52 };   // 0x514A72 mov edx,[ebp-134h]; push edx
    const BYTE kNbHelperAfter[7]  = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x74, 0x25 };   // 0x514A7E … je 0x514AAA
    const BYTE kNbHelperRefuse[7] = { 0xC6, 0x85, 0x17, 0xFF, 0xFF, 0xFF, 0x00 };   // 0x514AAA mov byte [ebp-E9h],0 (v20=0 → 5434 код 0)
    const BYTE kNbHelperBonus[5]  = { 0x0F, 0xBF, 0x54, 0x01, 0x09 };               // 0x514A97 movsx edx,[ecx+eax+9] — бонус помощника
    const BYTE kNbHelperThis[6]   = { 0x89, 0x8D, 0xA0, 0xFD, 0xFF, 0xFF };         // 0x513F93 mov [ebp-260h],ecx — CUserManager
    const BYTE kNbUsePush[7]      = { 0x8B, 0x8D, 0x94, 0xFE, 0xFF, 0xFF, 0x51 };   // 0x4EDD7B mov ecx,[ebp-16Ch]; push ecx (код слота)
    const BYTE kNbUseAfter[7]     = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x75, 0x27 };   // 0x4EDD87 … jne 0x4EDDB5
    const BYTE kNbUseRefuse[7]    = { 0xC6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF, 0x09 };   // 0x4EDDA4 mov byte [ebp-121h],9 (5451 код 9)
    const BYTE kNbUsePkt[6]       = { 0x8B, 0x95, 0x02, 0xFE, 0xFF, 0xFF };         // 0x4ED97D mov edx,[ebp-1FEh] — код пакета (гейт 48)
    const BYTE kNbIsFunc[18]      = { 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x01, 0x7C, 0x12, 0x8B, 0x45, 0x08, 0x3B, 0x05, 0xA4, 0x5E, 0x5F, 0x00 };   // 0x532B10 sub_532B10: push ebp; mov ebp,esp; cmp [ebp+8],1; jl; mov eax,[ebp+8]; cmp eax,[5F5EA4h]
}

PatchResult P65_ConsumableType()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode        = Config::GetInt (kSec, L"Mode", 0) ? 1 : 0;
    g_chkBless    = Config::GetBool(kSec, L"CheckBless", true);
    g_chkOptTrans = Config::GetBool(kSec, L"CheckOptionTrans", true);
    g_chkHelper   = Config::GetBool(kSec, L"CheckHelper", true);
    g_chkUseCode  = Config::GetBool(kSec, L"CheckUseCode", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    g_logChannel  = Config::GetInt (kSec, L"LogChannel", 1);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 1; }
    wchar_t buf[128];
    Config::GetStr(kSec, L"BlessTypes",       L"204,206", buf, ARRAYSIZE(buf)); ParseList(buf, g_bless);
    Config::GetStr(kSec, L"OptionTransTypes", L"67",      buf, ARRAYSIZE(buf)); ParseList(buf, g_optTrans);
    Config::GetStr(kSec, L"HelperTypes",      L"96",      buf, ARRAYSIZE(buf)); ParseList(buf, g_helper);
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    const Site sites[] =
    {
        { 0x00535B01, kOrigBless,      sizeof(kOrigBless)      },
        { 0x0053664A, kOrigOptTrans,   sizeof(kOrigOptTrans)   },
        { 0x00514A79, kOrigHelper,     sizeof(kOrigHelper)     },
        { 0x004EDD82, kOrigUse,        sizeof(kOrigUse)        },
        { 0x00535AFA, kNbBlessPush,    sizeof(kNbBlessPush)    },
        { 0x00535B06, kNbBlessAfter,   sizeof(kNbBlessAfter)   },
        { 0x00535B0D, kNbBlessRefuse,  sizeof(kNbBlessRefuse)  },
        { 0x00536643, kNbOptPush,      sizeof(kNbOptPush)      },
        { 0x0053664F, kNbOptAfter,     sizeof(kNbOptAfter)     },
        { 0x00536656, kNbOptRefuse,    sizeof(kNbOptRefuse)    },
        { 0x00514A72, kNbHelperPush,   sizeof(kNbHelperPush)   },
        { 0x00514A7E, kNbHelperAfter,  sizeof(kNbHelperAfter)  },
        { 0x00514AAA, kNbHelperRefuse, sizeof(kNbHelperRefuse) },
        { 0x00514A97, kNbHelperBonus,  sizeof(kNbHelperBonus)  },
        { 0x00513F93, kNbHelperThis,   sizeof(kNbHelperThis)   },
        { 0x004EDD7B, kNbUsePush,      sizeof(kNbUsePush)      },
        { 0x004EDD87, kNbUseAfter,     sizeof(kNbUseAfter)     },
        { 0x004EDDA4, kNbUseRefuse,    sizeof(kNbUseRefuse)    },
        { 0x004ED97D, kNbUsePkt,       sizeof(kNbUsePkt)       },
        { 0x00532B10, kNbIsFunc,       sizeof(kNbIsFunc)       },
    };
    if (!VerifyAllSites(L"P65", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteCall(0x00535B01, &St_Bless6551,    5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x0053664A, &St_OptTrans6553, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x00514A79, &St_Helper5433,   5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x004EDD82, &St_Use5450,      5)) { return PatchResult::Failed; }

    char b1[80], b2[80], b3[80];
    ListText(g_bless, b1, sizeof(b1)); ListText(g_optTrans, b2, sizeof(b2)); ListText(g_helper, b3, sizeof(b3));
    Log::Line(L"    P65: режим %s; 6551 свиток типы {%S}%s; 6553 свиток типы {%S}%s; 5433 помощник типы {%S}%s; "
              L"5450 код пакета == код слота%s; журнал ac.other 45..48, не чаще 1/%d с на (сессия, вид); канал лога %d",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ",
              b1, (g_chkBless    && g_bless.n)    ? L"" : L" (ВЫКЛ)",
              b2, (g_chkOptTrans && g_optTrans.n) ? L"" : L" (ВЫКЛ)",
              b3, (g_chkHelper   && g_helper.n)   ? L"" : L" (ВЫКЛ)",
              g_chkUseCode ? L"" : L" (ВЫКЛ)", g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
