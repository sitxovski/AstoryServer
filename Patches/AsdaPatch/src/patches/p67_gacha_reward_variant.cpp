// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P67 — ★ ПРЕМИУМ-ГАЧА 6581: связь «приз в ячейке ↔ запрошенный вариант» + 6579 «результат рулетки»
//  без активной рулетки (античит, волна A7 «экономика/предметы», 2026-10-12; план 00_PLAN.md §8.2 A2,
//  02_parts/economy2_handlers.md «Топ-5» п.1 и строка 6575/6579). [СЕРВЕР-ДОРАБОТКА]
//  Документ: `AstoryServer/Docs/GameServer/gacha-reward-variant-p67.md`.
//
//  ── ДЫРА A (6581, крит 5) ──
//  Recv_UserPrimiumGaChaReward@0x4F72B0 (GameServer.c:95393–95443) читает из тела 11 б: +0 код приза, +4 слот,
//  +6 контейнер, +7 код ВАРИАНТА. Сток проверяет: запись в ячейке есть (sub_4D61E0), +0 == код в ячейке,
//  sub_532A90(вариант) и `item_table[вариант].+36 == 3` («кэш-предмет»). Связь «вариант ∈ семейству приза»
//  НЕ проверяется ⇒ любой кэш-предмет класса 3 вместо приза (DB 2555 снимает приз, кладёт вариант).
//
//  ── ПРАВИЛО КЛИЕНТА (эталон itemFindVariantBySlotOption@0xB71840, item_inventory.c:5480; порт
//     AsdaPremiumGachaSubsystem::CollectVariantCandidates/ResolveVariant) ──
//     база = запись приза; кандидат подходит, если
//       base.ItemSubType ∈ {200,201} (коробка): cand.LinkWordCode(+220, u16) == base.LinkWordCode;
//       иначе:                                   cand.SetCode(+232)           == base.SetCode;
//     и далее выбирается по SS1/SS2 (UsageCategory +92 / RequiredLevel +80) при равном ItemGrade (+236).
//     ★ Порт отсекает нулевой ключ (LinkWordCode==0 / SetCode==0 ⇒ кандидатов нет, пакета нет).
//
//  ── ЧТО ИЗ ЭТОГО ДОКАЗУЕМО НА СЕРВЕРЕ (Item_Table.txt → dword_5F5E98, 71 б, 42 колонки, sub_4A96A0) ──
//     Соответствие колонок клиентской записи снято эмпирически (tools/verify_p67.py --tables, 58 878 кодов):
//       +26 ItemType (c16), +27 ItemSubType (c17, 96,4 %), +65 u16 = LinkWordCode (c40, 81 % ненулевых),
//       +8 RequiredLevel (c4), +10 UsageCategory (c7). SetCode (+232) и ItemGrade (+236) на сервере НЕТ.
//     ⇒ Проверяем ровно то, что есть:
//       1) база (код в ячейке) — код таблицы предметов (sub_532A90) и приз из PrimiumGaChaTable
//          (массив 9 б: +0 i16 idx, +2 u8 автомат, +3 i32 код, +7 i16 кол-во; count ds:[0x7E0374] i16,
//          ptr ds:[0x7E0378] — объект 0x60AD18 + 0x1D565C/0x1D5660; загрузчик sub_4BCAD0@0x4BCAD0, читатели
//          sub_4BC200 @0x4BC617/0x4BC633 и 6577 @0x4F7042 (счётчик цен ds:[0x7E037C])).
//          Честный 6581 всегда про приз из 6578 (gp7 крутит ту же таблицу) — вид 50;
//       2) коробка (+27 ∈ {200,201}): вариант == база, либо LinkWord(+65) равны и не нулевые — вид 51;
//          нулевой ключ у базы/варианта = «семейства нет» (как отсечка порта) → вид 51 (ZeroKeyIsViolation=1);
//       3) не-коробка: SetCode серверу недоступен → вариант обязан совпадать с базой (NonPackageSameCodeOnly=1);
//          по живой PrimiumGaChaTable (9a441c03) все 89 призов-предметов — коробки или SetCode==0, честных
//          6581 с вариантом ≠ призу для не-коробок НЕТ.
//     ⚠ Расхождение таблиц: порт (item_list.csv) и живая Item_Table.txt (e5dc50cf) расходятся по LinkWord у
//       867 из 1 962 коробок-баз; на призах живой таблицы это 35 честных пар из 452 (призы 69244/69298/69352/
//       70679/71120/75647 — список в verify_p67.py --tables). Авторитет = сервер (закон client-server-table-desync):
//       Mode=0 (журнал) по умолчанию; Mode=1 ставить ПОСЛЕ сверки таблиц.
//
//  ── ДЫРА B (6579, крит 2) ──
//  Recv_UserSoulResult@0x49A8C0 (GameServer.c:61948) выдаёт результат рулетки по CUser+99382 (строка, i16) /
//  +99384 (столбец, u8) таблицы dword_5F5F60 (40 б/строка; word_5F5F5C строк) и обнуляет состояние
//  (62106–62115), включая флаг сессии CUser+99252 (его ставит 6575 @61841). Флаг перед выдачей НЕ проверяется:
//  повторный 6579 читает строку 0/столбец 0. Клиент (эталон и порт) шлёт 6579 только после 6576 с «−1»
//  (финальная клетка: `table[row][36+col] < 0`, 6575 @61868). Проверяем: флаг +99252 != 0 (SoulResultGuard) и,
//  при RequireTerminalCell=1, финальность клетки с границами стока (row <= word_5F5F5C, col <= 4) — вид 52.
//
//  ── ПЛОЩАДКИ (E8 rel32 целиком; байты одинаковы в стоке 4e20f0ad и живых GameServer/Indun e7b4ac38) ──
//   A. 0x4F75F5 `E8 A6 08 FB FF` call sub_4A7EA0 (GetServerGroup) — первая инструкция после стоковых проверок
//      6581 (`cmp eax,3 / je 0x4F75E9` @0x4F7586), перед сборкой тела DB-2555. Стаб: наша проверка → пропуск =
//      хвостовой jmp в сток sub_4A7EA0 (al вернётся как в стоке); отказ (Mode=1) = снять адрес возврата и перейти
//      в СТОКОВОЕ тело отказа (3) @0x4F758B: `mov byte [ebp-44h],0Ah` → sub_4C28F0(6582, 61 б, код 10, флаг 0)
//      → sub_569DF0(26, "...(3) %d=%d") → jmp эпилог 0x4F7678. Стек/регистры там только из кадра.
//      Кадр 6581 (дизасм 0x4F742C…0x4F7606): this=[ebp-0x160], userNum=[ebp+8] (word), CUser*=[ebp-0xD4],
//      тело=[ebp-0xE0] (приз +0, слот [ebp-0xDC] i16, контейнер [ebp-0xDA] u8, вариант [ebp-0xD9] i32),
//      запись ячейки=[ebp-0x158] (код базы +0).
//      Соседи P05 0x4F7084 / P16 0x4F7E40 / P11 0x4F766E — не пересекаются.
//   B. 0x49A963 `E8 28 9A 08 00` call sub_524390 (SecretCheck, thiscall, 4 аргумента, ret 10h) в 6579.
//      Стаб: сток → если тот вернул 0, выходим его результатом (сток молчит: `jmp 0x49B15F`); иначе наша проверка:
//      нарушение в Mode=1 → eax=0 ⇒ сток уходит на тот же тихий выход. Новых пакетов нет.
//      Кадр 6579 (дизасм 0x49A8D5, 0x49A944, 0x49A957–0x49A960): this=[ebp-0x164], userNum=[ebp+8] (word),
//      CUserManager = *(*(this+4)+0x34).
//  Журнал: ac.other виды 50/51/52 (выданы координатором), v[0]=код базы/строка, v[1]=вариант/столбец,
//  v[2]=ключи (base<<16|var) или причина; текст — детали. Ограничитель: 1 строка на (сессия, вид) за
//  JournalIntervalSec; подавленные → suppressed. Плюс строка sub_569DF0(1, "P67 …") на нарушение.
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
    const wchar_t* kSec = L"P67_GachaRewardVariant";

    bool g_enabled               = true;
    int  g_mode                  = 0;     // 0 журнал, 1 отказ
    bool g_requirePrizeInTable   = true;  // база обязана быть кодом PrimiumGaChaTable
    bool g_zeroKeyIsViolation    = true;  // LinkWord==0 у базы/варианта (вариант≠база) = нарушение
    bool g_nonPackageSameCode    = true;  // не-коробка: вариант обязан совпадать с базой
    bool g_soulGuard             = true;  // ставить площадку B (6579)
    bool g_requireTerminal       = true;  // 6579: клетка должна быть финальной
    int  g_journalIntervalSec    = 10;

    typedef int   (__cdecl    *PFN_IsItemCode)(int code);                                   // sub_532A90
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);            // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                  // sub_569DF0

    PFN_IsItemCode const pIsItemCode = (PFN_IsItemCode)Srv::kIsItemCode;
    PFN_GetUser    const pGetUser    = (PFN_GetUser)   Srv::kGetUser;
    PFN_SrvLog     const pSrvLog     = (PFN_SrvLog)    Srv::kLog;

    // Таблицы сервера (адреса из дизасма стока; см. шапку).
    constexpr DWORD kItemTablePtr  = 0x005F5E98;   // dword_5F5E98 → записи 71 б, индекс (code−20551)
    constexpr int   kItemCodeBase  = 20551;
    constexpr int   kItemStride    = 71;
    constexpr int   kItemOffType   = 26;           // u8  ItemType
    constexpr int   kItemOffSub    = 27;           // u8  ItemSubType (200/201 = коробка)
    constexpr int   kItemOffClass  = 36;           // u8  «класс 3» — проверяет сток
    constexpr int   kItemOffLink   = 65;           // u16 LinkWordCode
    // ★ Объект-владелец таблицы гачи = 0x60AD18 (тот же `this`, что у sub_4A7EA0; дизасм sub_4BC200 0x4BC617
    //   `movsx edx, word ptr [ecx+1D565Ch]` = счётчик this+1922652, 0x4BC633 `mov ecx,[7E0378h]` = массив this+1922656;
    //   6577 @0x4F7042 читает `word ptr [7E037Ch]` = счётчик PrimiumGaChaPriceTable this+1922660).
    constexpr DWORD kGachaCountVa  = 0x007E0374;   // i16 число записей PrimiumGaChaTable (0x60AD18 + 0x1D565C)
    constexpr DWORD kGachaArrVa    = 0x007E0378;   // ptr → записи 9 б (+3 i32 код предмета) (0x60AD18 + 0x1D5660)
    constexpr int   kGachaStride   = 9;
    constexpr DWORD kRouRowsVa     = 0x005F5F5C;   // word_5F5F5C — строк таблицы рулетки
    constexpr DWORD kRouTablePtr   = 0x005F5F60;   // dword_5F5F60 → строки 40 б; +36+col (char) < 0 = финал
    constexpr int   kRouStride     = 40;

    // CUser (дизасм стока; CUser+0x174/0x178/0x18C — как у P57; рулетка — GameServer.c:61841, 62005–62110).
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;
    constexpr int kOffMap       = 0x1C;
    constexpr int kOffRouFlag   = 99252;   // u8  сессия рулетки активна (6575 ставит 1, 6579 снимает)
    constexpr int kOffRouRow    = 99382;   // i16 строка таблицы
    constexpr int kOffRouCol    = 99384;   // u8  столбец (0..4)

    // Виды журнала ac.other (выданы координатором волны A7).
    enum Kind : BYTE { kPrizeNotInTable = 50, kVariantNotFamily = 51, kSoulNoSession = 52 };

    struct Sess
    {
        int   userIndex;
        DWORD lastJournal[3];
        int   suppressed[3];
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_checked = 0, g_viol = 0, g_refused = 0, g_soulChecked = 0, g_soulViol = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    Sess& SessOf(int userNum, const BYTE* user)
    {
        Sess& s = g_sess[userNum];
        const int userIndex = user ? *(const int*)(user + kOffUserIndex) : 0;
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        return s;
    }

    bool Allow(Sess& s, int kindIdx, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.lastJournal[kindIdx] && now - s.lastJournal[kindIdx] < (DWORD)g_journalIntervalSec * 1000) { ++s.suppressed[kindIdx]; return false; }
        s.lastJournal[kindIdx] = now;
        return true;
    }

    void Journal(BYTE kind, const BYTE* user, int userNum, int opcode, int v0, int v1, int v2, const char* text, int suppressed)
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
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }

    const BYTE* ItemRec(int code)
    {
        const BYTE* table = *(const BYTE* const*)kItemTablePtr;
        if (!table || !pIsItemCode(code)) { return nullptr; }
        return table + (size_t)kItemStride * (size_t)(code - kItemCodeBase);
    }

    // Приз есть в PrimiumGaChaTable? −1 = таблица не загружена (проверить нельзя), 0 = нет, 1 = есть.
    int PrizeInGachaTable(int code)
    {
        const int count = *(const short*)kGachaCountVa;
        const BYTE* arr = *(const BYTE* const*)kGachaArrVa;
        if (!arr || count <= 0) { return -1; }
        for (int i = 0; i < count; ++i)
        {
            if (*(const int*)(arr + (size_t)kGachaStride * i + 3) == code) { return 1; }
        }
        return 0;
    }
}

// ── A. 6581 после стоковых проверок, перед DB-2555. Возврат: 0 пропуск, 1 → стоковое тело отказа (3) ──
extern "C" int __stdcall P67_OnReward6581(BYTE* ebp)
{
    if (!g_enabled) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_checked);
        const int   userNum = *(const short*)(ebp + 8);
        const BYTE* user    = *(const BYTE* const*)(ebp - 0xD4);
        const BYTE* body    = ebp - 0xE0;
        const int   variant = *(const int*)(body + 7);
        const int   slot    = *(const short*)(body + 4);
        const int   cont    = body[6];
        const int   base    = *(const int*)(ebp - 0x158);        // код приза в ячейке (сток сверил с телом +0)
        if (!SessOk(userNum)) { return 0; }
        const DWORD now = GetTickCount();
        Sess& s = SessOf(userNum, user);

        // [fix13, 2026-10-13] было text[64] + wsprintfA: строка «6581 package … lw … -> variant … lw …: not family» до 77 б + NUL
        // (коды/ключи из пакета клиента) — переполнение. Теперь 128 б и _snprintf_s с усечением (ноль гарантирован).
        BYTE kind = 0; int v2 = 0; char text[128] = "";
        const BYTE* bRec = ItemRec(base);
        const BYTE* vRec = ItemRec(variant);   // сток уже проверил sub_532A90(вариант) и класс 3
        if (!bRec)
        {
            kind = kPrizeNotInTable; v2 = 1;
            _snprintf_s(text, sizeof(text), _TRUNCATE, "6581 base %d not an item code", base);
        }
        else if (g_requirePrizeInTable && PrizeInGachaTable(base) == 0)
        {
            kind = kPrizeNotInTable; v2 = 2;
            _snprintf_s(text, sizeof(text), _TRUNCATE, "6581 base %d not in PrimiumGaChaTable", base);
        }
        else if (variant != base && vRec)
        {
            const int bSub = bRec[kItemOffSub];
            const int bLw  = *(const WORD*)(bRec + kItemOffLink);
            const int vLw  = *(const WORD*)(vRec + kItemOffLink);
            if (bSub == 200 || bSub == 201)
            {
                if (bLw == 0 || vLw == 0)
                {
                    if (g_zeroKeyIsViolation)
                    {
                        kind = kVariantNotFamily; v2 = (bLw << 16) | vLw;
                        _snprintf_s(text, sizeof(text), _TRUNCATE, "6581 package %d lw %d -> variant %d lw %d: zero key", base, bLw, variant, vLw);
                    }
                }
                else if (bLw != vLw)
                {
                    kind = kVariantNotFamily; v2 = (bLw << 16) | vLw;
                    _snprintf_s(text, sizeof(text), _TRUNCATE, "6581 package %d lw %d -> variant %d lw %d: not family", base, bLw, variant, vLw);
                }
            }
            else if (g_nonPackageSameCode)
            {
                kind = kVariantNotFamily; v2 = (int)0x80000000 | bSub;
                _snprintf_s(text, sizeof(text), _TRUNCATE, "6581 item %d sub %d -> variant %d: SetCode unknown to server", base, bSub, variant);
            }
        }
        if (kind)
        {
            InterlockedIncrement(&g_viol);
            const int ki = kind - kPrizeNotInTable;
            if (Allow(s, ki, now))
            {
                pSrvLog(1, "P67 GachaRewardVariant: %s, %s UserNum %d, cell %d/%d%s", text, NameOf(user), userNum, cont, slot,
                        g_mode ? " -> REFUSE 6582 code 10" : " (journal, Mode=0)");
                Journal(kind, user, userNum, 6581, base, variant, v2, text, s.suppressed[ki]);
                s.suppressed[ki] = 0;
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_refused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── B. 6579 после стокового SecretCheck. Возврат: 0 пропуск, 1 → тихий выход стока (eax=0) ──
extern "C" int __stdcall P67_OnSoul6579(BYTE* ebp)
{
    if (!g_enabled || !g_soulGuard) { return 0; }
    int verdict = 0;
    __try
    {
        InterlockedIncrement(&g_soulChecked);
        const int   userNum = *(const short*)(ebp + 8);
        const BYTE* self    = *(const BYTE* const*)(ebp - 0x164);
        if (!self || !SessOk(userNum)) { return 0; }
        void* userMng = *(void**)(*(const BYTE* const*)(self + 4) + 0x34);
        if (!userMng) { return 0; }
        const BYTE* user = pGetUser(userMng, nullptr, (short)userNum);
        if (!user) { return 0; }
        const int flag = user[kOffRouFlag];
        const int row  = *(const short*)(user + kOffRouRow);
        const int col  = user[kOffRouCol];
        int reason = 0; char text[128] = "";   // [fix13] 64 → 128 + ограниченный форматтер, как в 6581
        if (!flag)
        {
            reason = 1; _snprintf_s(text, sizeof(text), _TRUNCATE, "6579 without active roulette (row %d col %d)", row, col);
        }
        else if (g_requireTerminal)
        {
            const int rows = *(const WORD*)kRouRowsVa;
            const BYTE* table = *(const BYTE* const*)kRouTablePtr;
            if (!table || row < 0 || row > rows || col > 4)
            {
                reason = 2; _snprintf_s(text, sizeof(text), _TRUNCATE, "6579 roulette state out of table (row %d/%d col %d)", row, rows, col);
            }
            else if (*(const char*)(table + (size_t)kRouStride * row + 36 + col) >= 0)
            {
                reason = 3; _snprintf_s(text, sizeof(text), _TRUNCATE, "6579 before terminal cell (row %d col %d next %d)", row, col,
                                      *(const char*)(table + (size_t)kRouStride * row + 36 + col));
            }
        }
        if (reason)
        {
            InterlockedIncrement(&g_soulViol);
            const DWORD now = GetTickCount();
            Sess& s = SessOf(userNum, user);
            const int ki = kSoulNoSession - kPrizeNotInTable;
            if (Allow(s, ki, now))
            {
                pSrvLog(1, "P67 GachaRewardVariant: %s, %s UserNum %d%s", text, NameOf(user), userNum,
                        g_mode ? " -> SILENT DROP" : " (journal, Mode=0)");
                Journal(kSoulNoSession, user, userNum, 6579, row, col, reason, text, s.suppressed[ki]);
                s.suppressed[ki] = 0;
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_refused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

extern "C" void __stdcall P67_GetStats(int* checked, int* viol, int* refused, int* soulChecked, int* soulViol)
{
    if (checked) { *checked = g_checked; } if (viol) { *viol = g_viol; } if (refused) { *refused = g_refused; }
    if (soulChecked) { *soulChecked = g_soulChecked; } if (soulViol) { *soulViol = g_soulViol; }
}

namespace
{
    DWORD g_pGetServerGroup = 0x004A7EA0;   // стоковая цель площадки A (sub_4A7EA0)
    DWORD g_pRefuseBody     = 0x004F758B;   // стоковое тело отказа (3) 6581: 6582 код 10 + лог + эпилог
    DWORD g_pSecretCheck    = 0x00524390;   // стоковая цель площадки B (sub_524390, thiscall, ret 10h)

    // A. вместо `call sub_4A7EA0` @0x4F75F5 (ecx = 0x60AD18, без аргументов). Адрес возврата 0x4F75FA.
    __declspec(naked) void St_Reward6581()
    {
        __asm
        {
            pushad
            push  ebp
            call  P67_OnReward6581             // __stdcall(ebp) → eax
            mov   dword ptr [esp+28], eax      // в сохранённый eax
            popad
            test  eax, eax
            jnz   refuse
            jmp   dword ptr [g_pGetServerGroup] // пропуск: сток вернёт al и ret на 0x4F75FA
        refuse:
            add   esp, 4                        // снять адрес возврата
            jmp   dword ptr [g_pRefuseBody]     // стоковое тело отказа (3): код 10, лог, эпилог
        }
    }

    // B. вместо `call sub_524390` @0x49A963 (thiscall: ecx = CUserManager, 4 аргумента, ret 10h).
    __declspec(naked) void St_Soul6579()
    {
        __asm
        {
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            call  dword ptr [g_pSecretCheck]   // сток (снимает 16 б)
            test  eax, eax
            jz    done                         // сток отказал — его результат (тихий выход стока)
            push  eax                          // результат стока
            pushad
            push  ebp
            call  P67_OnSoul6579               // __stdcall(ebp) → eax: 1 = тихий отказ
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            pop   eax                          // pop флагов не меняет
            jz    done
            xor   eax, eax                     // → сток уходит на 0x49B15F без ответа
        done:
            ret   0x10
        }
    }

    const BYTE kOrigReward[5] = { 0xE8, 0xA6, 0x08, 0xFB, 0xFF };   // 0x4F75F5 call 0x4A7EA0
    const BYTE kOrigSoul[5]   = { 0xE8, 0x28, 0x9A, 0x08, 0x00 };   // 0x49A963 call 0x524390
    // Соседи, на которые опираются стабы.
    const BYTE kNbRefuse[6]   = { 0xC6, 0x45, 0xBC, 0x0A, 0x6A, 0x00 };             // 0x4F758B mov byte [ebp-44h],0Ah; push 0
    const BYTE kNbRewardRet[6]= { 0x88, 0x85, 0x39, 0xFF, 0xFF, 0xFF };             // 0x4F75FA mov [ebp-0C7h],al
    const BYTE kNbGetGroup[7] = { 0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC };       // 0x4A7EA0 пролог
    const BYTE kNbSoulRet[9]  = { 0x85, 0xC0, 0x75, 0x05, 0xE9, 0xEE, 0x07, 0x00, 0x00 }; // 0x49A968 test/jne/jmp 0x49B15F
    const BYTE kNbSecret[3]   = { 0x55, 0x8B, 0xEC };                               // 0x524390 пролог
}

PatchResult P67_GachaRewardVariant()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode                = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_requirePrizeInTable = Config::GetBool(kSec, L"RequirePrizeInTable", true);
    g_zeroKeyIsViolation  = Config::GetBool(kSec, L"ZeroKeyIsViolation", true);
    g_nonPackageSameCode  = Config::GetBool(kSec, L"NonPackageSameCodeOnly", true);
    g_soulGuard           = Config::GetBool(kSec, L"SoulResultGuard", true);
    g_requireTerminal     = Config::GetBool(kSec, L"RequireTerminalCell", true);
    g_journalIntervalSec  = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    const Site sitesA[] =
    {
        { 0x004F75F5, kOrigReward,   sizeof(kOrigReward)   },
        { 0x004F758B, kNbRefuse,     sizeof(kNbRefuse)     },
        { 0x004F75FA, kNbRewardRet,  sizeof(kNbRewardRet)  },
        { 0x004A7EA0, kNbGetGroup,   sizeof(kNbGetGroup)   },
    };
    const Site sitesB[] =
    {
        { 0x0049A963, kOrigSoul,     sizeof(kOrigSoul)     },
        { 0x0049A968, kNbSoulRet,    sizeof(kNbSoulRet)    },
        { 0x00524390, kNbSecret,     sizeof(kNbSecret)     },
    };
    if (!VerifyAllSites(L"P67", sitesA, ARRAYSIZE(sitesA))) { return PatchResult::Mismatch; }
    if (g_soulGuard && !VerifyAllSites(L"P67", sitesB, ARRAYSIZE(sitesB))) { return PatchResult::Mismatch; }

    if (!Hook::WriteCall(0x004F75F5, &St_Reward6581, 5)) { return PatchResult::Failed; }
    if (g_soulGuard && !Hook::WriteCall(0x0049A963, &St_Soul6579, 5)) { return PatchResult::Failed; }
    Log::Line(L"    P67: режим %s; 6581: приз из PrimiumGaChaTable=%d, нулевой ключ=нарушение %d, не-коробка только тот же код %d; "
              L"6579: гейт %s, финальная клетка %d; строки не чаще 1/%d с",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ", g_requirePrizeInTable ? 1 : 0, g_zeroKeyIsViolation ? 1 : 0, g_nonPackageSameCode ? 1 : 0,
              g_soulGuard ? L"стоит" : L"выключен", g_requireTerminal ? 1 : 0, g_journalIntervalSec);
    return PatchResult::Applied;
}
