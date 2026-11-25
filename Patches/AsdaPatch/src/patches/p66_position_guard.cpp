// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P66 — ★ СВЕРКА С СЕРВЕРНОЙ ПОЗИЦИЕЙ/СОСТОЯНИЕМ: подбор 5012, зов друга 5427, воскрешение 6093, конец копания 5428
//  (античит, волна A7 «экономика / предметы / рыбалка-лут-квесты», 2026-10-12; план 00_PLAN.md механизм L6,
//  приоритет A10 — остаток после P57: 02_parts/fishing_loot_quests.md LOOT-1/LOOT-2/MINE-1,
//  02_parts/movement_teleports.md SM-1/RES-1). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Документ: `AstoryServer/Docs/GameServer/position-guard-p66.md`.
//
//  ── ЧТО ДЕЛАЕТ (A, C, D, E — под Mode: 0 — ТОЛЬКО ЖУРНАЛ, 1 — штатный отказ; B — исправление дефекта оригинала,
//     работает при ЛЮБОМ Mode, ключ ReturnItemOnRefuse) ──
//  A. LOOT-1, 5012 CharItemPicking@0x4D43A0 (GameServer.c:83909). Сток сравнивает ДВЕ пары клеток ИЗ ПАКЕТА:
//     «клетка персонажа» [ebp-0x518]/[ebp-0x568] и «клетка предмета» [ebp-0x5AC]/[ebp-0xC4]: `abs(dx) >= 7 || abs(dz) >= 7`
//     → отказ (0x4D468A/0x4D4696 `cmp eax,7`), серверная клетка CUser+0x54E6/+0x54E8 не участвует — клиент может
//     подбирать с другого конца карты, «подрисовав» свою клетку. Площадка — первый `call abs` 0x4D465A (E8 → CRT abs
//     0x56BD0A): стаб считает abs стоком, затем P66_OnPick5012(ebp): max(|srvX−itemX|,|srvZ−itemZ|) >= PickupTileTolerance
//     → нарушение. Умолчание 9 = стоковые 7 + 2 клетки запаса: серверную клетку пишет MoveSyncProcess на каждой смене клетки
//     и CharStop 4008 (0x546427: tile = pos/100), а честный клиент (эталон itemPickupGroundItem@0xC54ED0 и клик по луту
//     game state 103, порт AsdaPlayerController.cpp:1531/1558/3249) шлёт 5012 только стоя НА клетке предмета или в
//     d² < 90000 (3 клетки) — т. е. честное |srv−item| ≤ 3 (+1…2 клетки запаздывания тика хода). Отказ (Mode=1) —
//     переход в СТОКОВОЕ тело отказа LABEL_103 0x4D5999 (v71=0 → 5013 len 62 result=0, return): тот же путь, что
//     у стокового `>= 7`. Стек: у `call abs` на стеке адрес возврата + 1 аргумент (сток после вызова `add esp,4`) →
//     `add esp,8; jmp 0x4D5999`.
//  B. LOOT-2 — ★ ИСПРАВЛЕНИЕ ДЕФЕКТА ОРИГИНАЛА (не античит; работает при ЛЮБОМ Mode, ключ ReturnItemOnRefuse=1;
//     решение координатора 13.10: предмет пропадал — возвращаем всегда). GetSearchPickingItemInfo@0x4215A0 ОБНУЛЯЕТ запись
//     предмета на карте (sub_41EF00: memcpy нулей + sub_41F110), а ветки отказа через LABEL_103 (0x4D5999) предмет
//     НЕ возвращают (sub_41EFD0 зовётся только в LABEL_104 при v77=1): `sub_532B10||sub_532B30` (GS:84122),
//     `!sub_532A90` (84210), `+36 != 1` (84215), «iAmount <= 0» (84269) — предмет исчезает с карты, не попав в сумку.
//     Площадка — сама LABEL_103 (7 б `mov byte [ebp-0xB4],0` → jmp-стаб): если в записи [ebp-0x504] код > 0 и это
//     НЕ деньги (20551 — ветки «Money Not Find» 84409/84457 идут ПОСЛЕ частичной раздачи по отряду, возврат дал бы
//     дюп), вернуть запись на карту тем же sub_41EFD0(mapMgr, x=[rec+5], z=[rec+7], rec, "CharItemPicking()"), что
//     и сток в LABEL_104. Строка Log_Item — через ограничитель Allow() (слот kLimReturn, в журнал ac.* не пишется).
//     [fix13, 2026-10-13] Ветка «iAmount <= 0» (GS:84265-84269, 0x4D54F3 sub_4211F0 → 0x4D54F8 сверка суммы → 0x4D5510
//     лог → jmp 0x4D5999) — ЕДИНСТВЕННАЯ из веток LABEL_103, где сектору уже ушёл 5015 (снятие, SendPacket_ClippingSector-
//     InAllUser). Разослать появление можно стоковым sub_421150@0x421150 (5005 len 15, так делают UserDrop_AddMapItem
//     GS:14005 и Search_AddMonsterMapItem GS:14171), но это НЕ безопасно: в ветку попадает только накопительный предмет
//     (+7==4, +36==1, +35!=0, +26!=10) с количеством <= 0 при найденной в сумке такой же стопке — возвращённый и показанный,
//     он снова уходит в ту же ветку у каждого, у кого есть стопка (5015 → отказ → 5005 — мигание), а у кого нет — ложится
//     в сумку пустой стопкой (sub_4D6740). Поэтому такая запись НЕ возвращается (предмет без количества ценности не имеет,
//     вид клиентов уже согласован стоковым 5015) — строка «NOT returned». Ветка определяется по данным, а не по адресу:
//     код != деньги, sub_532A90 — да, sub_532B10/sub_532B30 — нет (иначе отказ раньше, 84122), поля таблицы предметов
//     dword_5F5E98 (+7, +0x24, +0x23, +0x1A; опоры 0x4D531C/0x4D533E/0x4D5360/0x4D5381) и количество записи <= 0 —
//     прочие ветки LABEL_103 с такими данными недостижимы (84211 требует !sub_532A90, 84215 — +36!=1, 84409/84457 — деньги).
//  C. SM-1, 5427 CharSoulMateRecallPosition@0x52BAE0 (GS:113825): клетка переноса берётся из пакета (113866) и
//     применяется сразу (113902-113928); связи с зовом 5236/5237, сверки с партнёром, гейта sub_52BFF0 нет —
//     любой клиент телепортируется в любую клетку своей карты. Точка знания «кого и куда зовут»: доставка 5236
//     партнёру B в sub_49EB60 (`call sub_4C28F0` 0x49ED38: userNum B = [ebp-0x40], тело 42 б [ebp-0x3C]: +0 UserIndex A,
//     +4 userNum A, +28/+30 клетка A = CUser+0x54E6/8 на момент зова; sub_49E960 GS:64216). Стаб после стокового
//     вызова пишет ожидание в таблицу g_recall[B] (кто/карта/клетка/такт). В 5427 площадка — `call sub_4221D0`
//     0x52BBF5 (границы клетки пакета [ebp-0x5C]/[ebp-0x5A]): сток → при его 1 наши проверки: (1) RecallGate —
//     код состояния != 0 по ТЕМ ЖЕ полям и в ТОМ ЖЕ порядке, что стоковый sub_52BFF0@0x52BFF0 (GS:113973): нет CUser → 0;
//     1 мёртв DWORD +0x4F (через sub_4CB030 0x4CB05D), 2 обмен DWORD +0x145 (0x52C070), 3 биржа DWORD +0x15F (0x52C0A6),
//     4 личная лавка DWORD +0x14D (0x52C0DC), 5 рыбалка BYTE +0x3F6B4 (0x52C10F); сами функции НЕ зовутся:
//     [fix13, 2026-10-13] стоковый sub_52BFF0 на КАЖДОМ вызове, включая код 0, шлёт клиенту 6001 {опкод, код}
//     (push 0x1771 @0x52C051/08C/0C2/0F8/12D/154 → sub_4C28F0), а сток 5427 его не зовёт — лишний пакет на каждый честный
//     зов и «отклонено» при кодах 2..5 при Mode=0. Опорные байты всех 5 чтений сверяются при установке; (2) ожидание есть, не старше
//     RecallWindowSec, партнёр A в своём слоте (UserIndex совпал), карты A и B равны; (3) клетка пакета = клетке зова
//     ИЛИ в пределах RecallTileTolerance от ТЕКУЩЕЙ клетки A. Отказ (Mode=1) — стаб возвращает al=0, и сток идёт
//     своей веткой «клетка вне карты» (0x52BBFE: лог канала 2 «if( !…IsCheckPosInMaxPos(sJump…) )», return 0 —
//     молча, как при нарушении границ). Ожидание снимается при успешном переносе.
//  D. RES-1, 6093 Recv_CharResurrectionConfirm@0x52B0E0 (GS:113589): цель/тип/процент берутся из подтверждения
//     (113607): CharRegenSelfPosition(mgr, a2 = +6 «кто воскресил», Type = +8, a4 = +0 «кого», pct = +9) — отправитель
//     может воскресить ЛЮБОГО userNum любым типом (HP max/2 — 113679/113783), предложения sub_52B070@0x52B070
//     (вызовы GS:46897, 57823, 63994, 86257) сервер не помнит. Площадки: `call sub_4C28F0` 0x52B0CC внутри sub_52B070
//     (отправка предложения; кадр: [ebp+8] кто, [ebp+0xC] тип, [ebp+0x10] кому, [ebp+0x14] процент) — стаб после
//     стокового вызова пишет предложение в g_res[кому] (кольцо на 4); `call CharRegenSelfPosition` 0x52B1AC в 6093 —
//     стаб ДО вызова: +0 цель == отправитель [ebp+8], в g_res[отправитель] есть предложение с тем же (кто, тип, процент)
//     не старше ResOfferWindowSec (умолчание 330 с = таймер меню смерти 300 с «5 минут», loc 2370, + запас).
//     Отказ (Mode=1) — вызов пропускается, eax=0 → стоковый эпилог 0x52B1B1 возвращает 0 (молча, как при «отправитель
//     не мёртв» 0x52B18E). Предложение снимается при использовании.
//  E. MINE-1, 5428 CharEMotion_MiningEnd@0x5469C0 (GS:124865): на каждый пакет сток обнуляет состояние CUser+0x54E4,
//     рассылает 5428 сектору, пересылает NpcServer и ++ счётчики званий 11/12/38 (124887-124889) — без проверки, что
//     копание было. Состояние копания на сервере складывается из 5028 CharSpendItemUse (лопата, тип 11/подтип 33..42:
//     5029 код 11 + 5429 на NpcServer, GS:85979-85991) и 4024 (sub_546730: CUser+0x54E4 := код действия 100..400;
//     эталон Item_UseShovelingTool шлёт 4024 110 лопата / 114 авто-лопата, порт AsdaPlayerCharacter.cpp:3003-3007).
//     Площадки: `call sub_5646C0` 0x4D9BEB (пересылка 5429 — старт принят; кадр [ebp+8] userNum) — стаб после
//     стокового вызова пишет g_dig[userNum] = {UserIndex, такт}; `call sub_5324A0` 0x546B21 в 5428 — стаб: сток →
//     при найденном CUser наши проверки: (1) старт есть и не старше DigWindowSec; (2) с него прошло ≥ MinDigMs
//     (умолчание 5000 = min CollectionTypeAniTime живого NpcServer\ini\Collection.ini 6000/9000 − 1 с запаса на
//     джиттер; итог награды NpcServer проверяет сам, здесь — счётчики званий); (3) RequireDigState — CUser+0x54E4 ∈
//     DigStates (110,114). Отказ (Mode=1) — переход в СТОКОВУЮ ветку 0x546ADD («MOVE :: CharEMotion_MiningEnd()
//     Exception Error» в лог канала 2, return) — та же, что при чужом userNum в пакете. Старт снимается при успехе.
//  Все площадки — `E8 rel32` целиком (подмена цели вызова) кроме LABEL_103 (7 б, две инструкции → jmp); байты
//  совпадают в стоке 4e20f0ad и живых GameServer/Indun e7b4ac38 (tools/verify_p66.py: байты, переходы внутрь, границы
//  инструкций, цели стабов, unicorn). С P11 (эпилог 0x4D5E61 + P59), P41 (0x52BE8B), P53/P55/P56/P57 не пересекаются.
//  Кадры/смещения — из дизасма стока (адрес инструкции указан у каждого). Отказы — только стоковыми ветками.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>
#include <stdlib.h>

namespace
{
    const wchar_t* kSec = L"P66_PositionGuard";

    bool g_enabled = true;
    int  g_mode    = 0;             // 0 журнал, 1 отказ
    int  g_journalIntervalSec = 10; // не чаще одной строки на (сессия, вид)
    // A/B — подбор
    bool g_pickCheck    = true;
    int  g_pickTol      = 9;        // клеток: max(|srv−item|) >= tol → нарушение (сток: |cli−item| >= 7)
    bool g_returnItem   = true;     // LOOT-2
    // C — зов друга
    bool g_recallCheck  = true;
    int  g_recallWindowSec = 120;
    int  g_recallTol    = 3;        // клеток от ТЕКУЩЕЙ клетки партнёра (клетка зова сверяется точно)
    bool g_recallGate   = true;     // sub_52BFF0
    // D — воскрешение
    bool g_resCheck     = true;
    int  g_resWindowSec = 330;
    // E — копание
    bool g_mineCheck    = true;
    int  g_minDigMs     = 5000;
    int  g_digWindowSec = 60;
    bool g_requireDigState = true;
    int  g_digStates[8] = { 110, 114, 0 };
    int  g_digStateN    = 2;

    // ── серверные функции (адреса — дизасм стока; живой образ = сток для них) ──
    typedef BYTE* (__fastcall *PFN_GetUser)(void* mgr, void* edx, int userNum);                              // sub_5324A0 thiscall(i16), ret 4
    typedef int   (__fastcall *PFN_ReturnItem)(void* mapMgr, void* edx, int x, int z, void* rec, int fn);  // sub_41EFD0 thiscall(i16,i16,void*,int a5=имя), ret 10h
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                                  // sub_569DF0
    typedef int   (__cdecl    *PFN_CodePred)(int code);                                                     // sub_532A90/B10/B30: чистые проверки диапазона кода

    PFN_GetUser    const pGetUser    = (PFN_GetUser)   Srv::kGetUser;        // 0x5324A0
    PFN_ReturnItem const pReturnItem = (PFN_ReturnItem)0x0041EFD0;
    PFN_SrvLog     const pSrvLog     = (PFN_SrvLog)    Srv::kLog;            // 0x569DF0
    PFN_CodePred   const pIsItem     = (PFN_CodePred)  0x00532A90;           // code в [20551, dword_5F5EAC]
    PFN_CodePred   const pIsB10      = (PFN_CodePred)  0x00532B10;           // code в [1, dword_5F5EA4]
    PFN_CodePred   const pIsB30      = (PFN_CodePred)  0x00532B30;           // code в [2001, dword_5F5EA8] или code-20000 в [0, N)

    // Таблица предметов (запись 0x47 б, индекс code-20551): указатель dword_5F5E98 (0x4D5317 `mov eax,[5F5E98h]`).
    constexpr DWORD kItemTablePtr = 0x005F5E98;
    constexpr int   kItemStride   = 0x47;

    // CUser (дизасм: CharMove 0x544EB0 / CharStop 0x546427 / 5427 0x52BF40 / 5428 0x546B40)
    constexpr int kOffUserNumW  = 0x0C;
    constexpr int kOffMap       = 0x1C;
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;
    constexpr int kOffAction    = 0x54E4;   // состояние действия (4024 → 100..400; 200 = мёртв; 5428 пишет 0)
    constexpr int kOffTileX     = 0x54E6;
    constexpr int kOffTileZ     = 0x54E8;

    constexpr int kMoney = 20551;

    // Виды журнала ac.move_combat 24..30 (при интеграции 12.10 сдвинуты с 21..27: 1..20 заняты P53/N13/P56/N14/P57, 21..23 — N15/P56b).
    enum Kind : BYTE { kPickRange = 24, kRecallNoCall = 25, kRecallTile = 26, kRecallGate = 27, kResNoOffer = 28, kDigNoStart = 29, kDigEarly = 30 };
    // Слот ограничителя для строк LOOT-2 (возврат предмета) — НЕ вид журнала, в ac.* не пишется (индекс 31-24 = 7 < 8).
    constexpr int kLimReturn = 31;

    // ── таблицы ожиданий (слот userNum 0..0x225, привязка к UserIndex — смена учётки = сброс) ──
    struct Recall { int bIndex; int aIndex; short aNum; short map; short tileX; short tileZ; DWORD tick; BYTE pending; };
    struct ResOffer { int tick; short caster; short pct; BYTE type; BYTE used; };
    struct ResSlot { int userIndex; ResOffer o[4]; int next; };
    struct Dig { int userIndex; DWORD tick; BYTE pending; };
    struct Limiter { int userIndex; DWORD last[8]; int suppressed[8]; };   // индекс = вид − 24

    Recall  g_recall[0x226] = {};
    ResSlot g_res[0x226]    = {};
    Dig     g_dig[0x226]    = {};
    Limiter g_lim[0x226]    = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    struct Stats { LONG pickChecked, pickViol, pickRefused, itemReturned, recallOffers, recallChecked, recallViol, recallRefused,
                        resOffers, resChecked, resViol, resRefused, digStarts, digChecked, digViol, digRefused; };
    Stats g_st = {};

    bool SessOk(int n) { return n >= 0 && n < 0x226; }

    // ⚠ Без RAII: внутри __try объекты с деструкторами запрещены (C2712) — замок берётся/отдаётся явно, без ранних return между.
    void LockEnter() { if (g_lockReady) { EnterCriticalSection(&g_lock); } }
    void LockLeave() { if (g_lockReady) { LeaveCriticalSection(&g_lock); } }

    // Ограничитель строк: true — писать; подавленные копятся по виду.
    bool Allow(int userNum, const BYTE* user, int kind, DWORD now, int* suppressedOut)
    {
        Limiter& l = g_lim[userNum];
        const int ui = user ? *(const int*)(user + kOffUserIndex) : 0;
        if (l.userIndex != ui) { memset(&l, 0, sizeof(l)); l.userIndex = ui; }
        const int k = kind - kPickRange;
        if (g_journalIntervalSec <= 0) { *suppressedOut = 0; return true; }
        if (l.last[k] && now - l.last[k] < (DWORD)g_journalIntervalSec * 1000) { ++l.suppressed[k]; return false; }
        l.last[k] = now; *suppressedOut = l.suppressed[k]; l.suppressed[k] = 0;
        return true;
    }

    // Колонки ac.move_combat: v[0] карта, w[0]/w[1] (64-бит), v[1..4]; текстовой колонки у таблицы НЕТ — клетки пакуются x*1000+z.
    void Journal(BYTE kind, const BYTE* user, int userNum, int opcode, __int64 w0, __int64 w1, int v1, int v2, int v3, int v4, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, kind);
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
                e.v[0]      = *(const short*)(user + kOffMap);
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.w[0] = w0; e.w[1] = w1; e.v[1] = v1; e.v[2] = v2; e.v[3] = v3; e.v[4] = v4;
        AcJournal::Push(e);
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }
    int IndexOf(const BYTE* user) { return user ? *(const int*)(user + kOffUserIndex) : -1; }
    int Cheb(int ax, int az, int bx, int bz) { const int dx = abs(ax - bx), dz = abs(az - bz); return dx > dz ? dx : dz; }
    const char* Verdict() { return g_mode ? " -> REFUSE (stock path)" : " (journal)"; }

    // Код состояния как у стокового sub_52BFF0@0x52BFF0 (GS:113973) — те же поля, тот же порядок веток, БЕЗ отправки 6001.
    // Сток: GetUser(userNum) → нет → 0; sub_4CB030 (снова GetUser, DWORD +0x4F) → 1; +0x145 → 2; +0x15F → 3; +0x14D → 4;
    // BYTE +0x3F6B4 → 5; иначе 0. Смещения — Srv::kOff* (общие с P64 ReadState); опоры сверяются при установке.
    int StateCode(void* mgr, int userNum)
    {
        const BYTE* u = pGetUser(mgr, nullptr, (short)userNum);
        if (!u) { return 0; }
        if (*(const int*)(u + Srv::kOffDeadFlag))     { return 1; }
        if (*(const int*)(u + Srv::kOffExchangeFlag)) { return 2; }
        if (*(const int*)(u + Srv::kOffAuctionFlag))  { return 3; }
        if (*(const int*)(u + Srv::kOffStoreFlag))    { return 4; }
        if (u[Srv::kOffFishingFlag])                  { return 5; }
        return 0;
    }

    // LOOT-2: запись из ветки «iAmount <= 0» (GS:84269) — после стокового 5015, см. шапку B. true — не возвращать.
    bool IsZeroStackBranch(int code, int amount)
    {
        if (amount > 0 || code == kMoney) { return false; }
        if (!pIsItem(code) || pIsB10(code) || pIsB30(code)) { return false; }
        const BYTE* table = *(const BYTE* const*)kItemTablePtr;
        if (!table) { return false; }
        const BYTE* r = table + (size_t)kItemStride * (code - kMoney);
        return r[7] == 4 && r[0x24] == 1 && r[0x23] != 0 && r[0x1A] != 10;
    }
}

// ── A. 5012: после стокового abs(dx) (площадка 0x4D465A). 0 — пропуск, 1 — в стоковое тело отказа LABEL_103 ──
extern "C" int __stdcall P66_OnPick5012(BYTE* ebp)
{
    if (!g_enabled || !g_pickCheck) { return 0; }
    int verdict = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x5F0);            // 0x4D43B3 mov [ebp-5F0h],ecx
        BYTE* user = *(BYTE**)(ebp - 0x5B0);           // 0x4D4579 mov [ebp-5B0h],eax (sub_5324A0)
        const int userNum = *(const short*)(ebp + 8);
        const int cliX = *(const short*)(ebp - 0x518), cliZ = *(const short*)(ebp - 0x568);   // 0x4D45BA / 0x4D45C8
        const int itX  = *(const short*)(ebp - 0x5AC), itZ  = *(const short*)(ebp - 0xC4);    // 0x4D45D6 / 0x4D45E4
        if (!mgr || !user || !SessOk(userNum)) { return 0; }
        InterlockedIncrement(&g_st.pickChecked);
        const int srvX = *(const short*)(user + kOffTileX), srvZ = *(const short*)(user + kOffTileZ);
        const int dSrvItem = Cheb(srvX, srvZ, itX, itZ);
        const int dCliSrv  = Cheb(cliX, cliZ, srvX, srvZ);
        if (dSrvItem >= g_pickTol)
        {
            InterlockedIncrement(&g_st.pickViol);
            const DWORD now = GetTickCount();
            int sup = 0;
            LockEnter(); const bool w = Allow(userNum, user, kPickRange, now, &sup); LockLeave();
            if (w)
            {
                pSrvLog(1, "P66 PositionGuard: 5012 server tile %d,%d is %d cells from item %d,%d (tol %d; client tile %d,%d, cli-srv %d), %s UserNum %d UserIndex %d%s",
                        srvX, srvZ, dSrvItem, itX, itZ, g_pickTol, cliX, cliZ, dCliSrv, NameOf(user), userNum, IndexOf(user), Verdict());
                Journal(kPickRange, user, userNum, 5012, (__int64)srvX * 1000 + srvZ, (__int64)cliX * 1000 + cliZ, dSrvItem, dCliSrv, itX, itZ, sup);
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_st.pickRefused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── B. LABEL_103 (0x4D5999): вернуть на карту снятую запись (LOOT-2) ──
extern "C" void __stdcall P66_OnPickRefuse5012(BYTE* ebp)
{
    if (!g_enabled || !g_returnItem) { return; }
    __try
    {
        void* mgr = *(void**)(ebp - 0x5F0);
        BYTE* rec = ebp - 0x504;                       // 0x4D46B7 lea ecx,[ebp-504h] — запись предмета (sub_422780)
        const int code = *(const int*)rec;
        if (!mgr || code <= 0 || code == kMoney) { return; }
        const int userNum = *(const short*)(ebp + 8);
        BYTE* user = *(BYTE**)(ebp - 0x5B0);
        void* mapMgr = *(void**)(*(BYTE**)((BYTE*)mgr + 4) + 0xC);   // 0x4D59F5 mov ecx,[edx+0Ch]
        const int x = *(const short*)(rec + 5), z = *(const short*)(rec + 7);   // 0x4D59DC / 0x4D59E4
        if (!mapMgr) { return; }
        const int amount = *(const int*)(rec + 9);     // 0x4D4C.. sPickItem.iAmount = rec+9 (как у стока)
        const bool zeroStack = IsZeroStackBranch(code, amount);
        if (!zeroStack)
        {
            pReturnItem(mapMgr, nullptr, x, z, rec, (int)"CharItemPicking()");
            InterlockedIncrement(&g_st.itemReturned);
        }
        *(int*)rec = 0;                                // повторный проход через LABEL_103 запись не вернёт дважды
        int sup = 0; bool w = true;
        if (SessOk(userNum)) { LockEnter(); w = Allow(userNum, user, kLimReturn, GetTickCount(), &sup); LockLeave(); }
        if (w)
        {
            if (zeroStack)
                pSrvLog(1, "P66 PositionGuard: 5012 refused after item was taken from map: Item %d x%d at %d,%d NOT returned (zero-amount stack, 5015 already sent by stock), UserNum %d UserIndex %d %s%s",
                        code, amount, x, z, userNum, IndexOf(user), NameOf(user), sup ? " (suppressed before)" : "");
            else
                pSrvLog(1, "P66 PositionGuard: 5012 refused after item was taken from map -> returned Item %d x%d at %d,%d (LOOT-2), UserNum %d UserIndex %d %s%s",
                        code, amount, x, z, userNum, IndexOf(user), NameOf(user), sup ? " (suppressed before)" : "");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ── C1. Доставка 5236 партнёру (площадка 0x49ED38 в sub_49EB60): запомнить ожидание ──
extern "C" void __stdcall P66_OnRecallOffer5236(BYTE* ebp)
{
    if (!g_enabled || !g_recallCheck) { return; }
    __try
    {
        void* self = *(void**)(ebp - 0x44);            // 0x49EB70 mov [ebp-44h],ecx (CSoulMateManager)
        const int bNum = *(const short*)(ebp - 0x40);  // 0x49EBA2 — userNum партнёра B (кому уходит 5236)
        const BYTE* body = ebp - 0x3C;                 // 0x49EB92 lea ecx,[ebp-3Ch] — тело 42 б
        if (!self || !SessOk(bNum)) { return; }
        void* mgr = *(void**)(*(BYTE**)((BYTE*)self + 4) + 0x34);   // 0x49EBAE/B1 — m_pcThread->m_cUserMng
        if (!mgr) { return; }
        const int   aIndex = *(const int*)(body + 0);
        const int   aNum   = *(const short*)(body + 4);
        const short tileX  = *(const short*)(body + 28), tileZ = *(const short*)(body + 30);
        BYTE* a = SessOk(aNum) ? pGetUser(mgr, nullptr, (short)aNum) : nullptr;
        BYTE* b = pGetUser(mgr, nullptr, (short)bNum);
        LockEnter();
        Recall& r = g_recall[bNum];
        r.bIndex = IndexOf(b); r.aIndex = aIndex; r.aNum = (short)aNum;
        r.map = a ? *(const short*)(a + kOffMap) : (short)-1;
        r.tileX = tileX; r.tileZ = tileZ; r.tick = GetTickCount(); r.pending = 1;
        LockLeave();
        InterlockedIncrement(&g_st.recallOffers);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ── C2. 5427 после стоковой проверки границ клетки (площадка 0x52BBF5). 0 — пропуск, 1 — al=0 (стоковая ветка отказа) ──
extern "C" int __stdcall P66_OnRecall5427(BYTE* ebp)
{
    if (!g_enabled || !g_recallCheck) { return 0; }
    int verdict = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x78);             // 0x52BAE9 mov [ebp-78h],ecx
        BYTE* user = *(BYTE**)(ebp - 0x58);            // 0x52BBD2 mov [ebp-58h],eax
        const int userNum = *(const short*)(ebp + 8);
        const int px = *(const short*)(ebp - 0x5C), pz = *(const short*)(ebp - 0x5A);   // 0x52BBE7 / 0x52BBE2 — клетка из пакета
        if (!mgr || !user || !SessOk(userNum)) { return 0; }
        InterlockedIncrement(&g_st.recallChecked);
        const DWORD now = GetTickCount();
        int kind = 0, v1 = 0, v2 = 0; __int64 w0 = AcJournal::kNone;
        // (1) гейт состояния — поля стокового sub_52BFF0, без его отправки 6001 (см. шапку C)
        if (g_recallGate)
        {
            const int gate = StateCode(mgr, userNum);
            if (gate) { kind = kRecallGate; v1 = gate; }
        }
        if (!kind)
        {
            LockEnter();
            Recall& r = g_recall[userNum];
            const int myIndex = IndexOf(user);
            if (!r.pending || r.bIndex != myIndex) { kind = kRecallNoCall; v1 = 1; }
            else if (now - r.tick > (DWORD)g_recallWindowSec * 1000) { kind = kRecallNoCall; v1 = 2; v2 = (int)(now - r.tick); }
            else
            {
                BYTE* a = SessOk(r.aNum) ? pGetUser(mgr, nullptr, r.aNum) : nullptr;
                if (!a || IndexOf(a) != r.aIndex) { kind = kRecallNoCall; v1 = 3; }
                else if (*(const short*)(a + kOffMap) != *(const short*)(user + kOffMap)) { kind = kRecallNoCall; v1 = 4; v2 = *(const short*)(a + kOffMap); }
                else
                {
                    const int ax = *(const short*)(a + kOffTileX), az = *(const short*)(a + kOffTileZ);
                    const int dCall = Cheb(px, pz, r.tileX, r.tileZ), dNow = Cheb(px, pz, ax, az);
                    if (dCall != 0 && dNow > g_recallTol)
                    {
                        kind = kRecallTile; v1 = dCall; v2 = dNow; w0 = (__int64)r.tileX * 1000 + r.tileZ;
                    }
                    else { r.pending = 0; }   // ожидание использовано: один зов — один перенос
                }
            }
            LockLeave();
        }
        if (kind)
        {
            InterlockedIncrement(&g_st.recallViol);
            int sup = 0;
            LockEnter(); const bool w = Allow(userNum, user, kind, now, &sup); LockLeave();
            if (w)
            {
                if (kind == kRecallGate)
                    pSrvLog(0, "P66 PositionGuard: 5427 under state gate (state code %d as sub_52BFF0: 1 dead, 2 exchange, 3 auction, 4 store, 5 fishing; no 6001), %s UserNum %d UserIndex %d%s", v1, NameOf(user), userNum, IndexOf(user), Verdict());
                else if (kind == kRecallNoCall)
                    pSrvLog(0, "P66 PositionGuard: 5427 without matching call (reason %d: 1 none, 2 expired %d ms, 3 partner slot changed, 4 partner on map %d), tile %d,%d, %s UserNum %d UserIndex %d%s",
                            v1, v2, v2, px, pz, NameOf(user), userNum, IndexOf(user), Verdict());
                else
                    pSrvLog(0, "P66 PositionGuard: 5427 tile %d,%d is %d cells from call tile and %d from partner (tol %d), %s UserNum %d UserIndex %d%s",
                            px, pz, v1, v2, g_recallTol, NameOf(user), userNum, IndexOf(user), Verdict());
                Journal((BYTE)kind, user, userNum, 5427, w0, now, v1, v2, px, pz, sup);
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_st.recallRefused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── D1. Предложение воскрешения (площадка 0x52B0CC в sub_52B070): запомнить ──
extern "C" void __stdcall P66_OnResOffer6093(BYTE* ebp)
{
    if (!g_enabled || !g_resCheck) { return; }
    __try
    {
        void* mgr = *(void**)(ebp - 0x10);             // 0x52B076 mov [ebp-10h],ecx (CUserManager)
        const int caster = *(const short*)(ebp + 8);   // 0x52B081
        const int type   = *(const BYTE*)(ebp + 0xC);  // 0x52B091
        const int target = *(const short*)(ebp + 0x10);// 0x52B097
        const int pct    = *(const short*)(ebp + 0x14);// 0x52B089
        if (!mgr || !SessOk(target)) { return; }
        BYTE* t = pGetUser(mgr, nullptr, (short)target);
        LockEnter();
        ResSlot& s = g_res[target];
        const int ti = IndexOf(t);
        if (s.userIndex != ti) { memset(&s, 0, sizeof(s)); s.userIndex = ti; }
        ResOffer& o = s.o[s.next & 3]; s.next = (s.next + 1) & 3;
        o.tick = (int)GetTickCount(); o.caster = (short)caster; o.pct = (short)pct; o.type = (BYTE)type; o.used = 0;
        LockLeave();
        InterlockedIncrement(&g_st.resOffers);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ── D2. 6093 перед CharRegenSelfPosition (площадка 0x52B1AC). 0 — пропуск, 1 — вызов пропустить, вернуть 0 ──
extern "C" int __stdcall P66_OnResConfirm6093(BYTE* ebp)
{
    if (!g_enabled || !g_resCheck) { return 0; }
    int verdict = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x1C);             // 0x52B0E6 mov [ebp-1Ch],ecx
        const int sender = *(const short*)(ebp + 8);
        const BYTE* body = ebp - 0x14;                 // 0x52B171 lea eax,[ebp-14h] — 11 б
        const int target = *(const short*)(body + 0);  // 0x52B195 → a4
        const int caster = *(const short*)(body + 6);  // 0x52B19E → a2
        const int type   = body[8];                    // 0x52B19A → Type
        const int pct    = *(const short*)(body + 9);  // 0x52B190 → a5
        if (!mgr || !SessOk(sender)) { return 0; }
        BYTE* user = pGetUser(mgr, nullptr, (short)sender);
        InterlockedIncrement(&g_st.resChecked);
        const DWORD now = GetTickCount();
        int reason = 0, age = 0;
        if (target != sender) { reason = 1; }
        else
        {
            LockEnter();
            ResSlot& s = g_res[sender];
            reason = 2;
            if (s.userIndex == IndexOf(user))
            {
                for (int i = 0; i < 4; ++i)
                {
                    ResOffer& o = s.o[i];
                    if (o.used || o.tick == 0 || o.caster != caster || o.type != type || o.pct != pct) { continue; }
                    age = (int)(now - (DWORD)o.tick);
                    if ((DWORD)age > (DWORD)g_resWindowSec * 1000) { reason = 3; continue; }
                    reason = 0; o.used = 1; break;
                }
            }
            LockLeave();
        }
        if (reason)
        {
            InterlockedIncrement(&g_st.resViol);
            int sup = 0;
            LockEnter(); const bool w = Allow(sender, user, kResNoOffer, now, &sup); LockLeave();
            if (w)
            {
                pSrvLog(0, "P66 PositionGuard: 6093 confirm without matching offer (reason %d: 1 target %d != sender, 2 no offer, 3 expired %d ms), caster %d type %d pct %d, %s UserNum %d UserIndex %d%s",
                        reason, target, age, caster, type, pct, NameOf(user), sender, IndexOf(user), Verdict());
                Journal(kResNoOffer, user, sender, 6093, AcJournal::kNone, now, reason, type, pct, caster, sup);
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_st.resRefused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── E1. 5028: лопата принята, 5429 ушёл на NpcServer (площадка 0x4D9BEB): запомнить старт ──
extern "C" void __stdcall P66_OnDigStart5028(BYTE* ebp)
{
    if (!g_enabled || !g_mineCheck) { return; }
    __try
    {
        void* mgr = *(void**)(ebp - 0x4E8);            // 0x4D9B2C mov edx,[ebp-4E8h] (this)
        const int userNum = *(const short*)(ebp + 8);  // 0x4D9BC4
        if (!mgr || !SessOk(userNum)) { return; }
        BYTE* user = pGetUser(mgr, nullptr, (short)userNum);
        LockEnter();
        Dig& d = g_dig[userNum];
        d.userIndex = IndexOf(user); d.tick = GetTickCount(); d.pending = 1;
        LockLeave();
        InterlockedIncrement(&g_st.digStarts);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ── E2. 5428 после стокового sub_5324A0 (площадка 0x546B21). 0 — пропуск, 1 — стоковая ветка «Exception Error» ──
extern "C" int __stdcall P66_OnDigEnd5428(BYTE* user, BYTE* ebp)
{
    if (!g_enabled || !g_mineCheck) { return 0; }
    int verdict = 0;
    __try
    {
        const int userNum = *(const short*)(ebp + 8);
        if (!user || !SessOk(userNum)) { return 0; }
        InterlockedIncrement(&g_st.digChecked);
        const DWORD now = GetTickCount();
        const int state = *(const short*)(user + kOffAction);
        int kind = 0, v1 = 0, v2 = 0;
        {
            LockEnter();
            Dig& d = g_dig[userNum];
            const int elapsed = (int)(now - d.tick);
            if (!d.pending || d.userIndex != IndexOf(user)) { kind = kDigNoStart; v1 = 1; }
            else if ((DWORD)elapsed > (DWORD)g_digWindowSec * 1000) { kind = kDigNoStart; v1 = 2; v2 = elapsed; d.pending = 0; }
            else if (g_requireDigState)
            {
                bool okState = false;
                for (int i = 0; i < g_digStateN; ++i) { if (g_digStates[i] == state) { okState = true; } }
                if (!okState) { kind = kDigNoStart; v1 = 3; v2 = elapsed; }
            }
            if (!kind && elapsed < g_minDigMs) { kind = kDigEarly; v1 = elapsed; v2 = g_minDigMs; }
            if (!kind) { d.pending = 0; }   // один старт — один итог (ранний конец старт не снимает: честный ещё может прийти)
            LockLeave();
        }
        if (kind)
        {
            InterlockedIncrement(&g_st.digViol);
            int sup = 0;
            LockEnter(); const bool w = Allow(userNum, user, kind, now, &sup); LockLeave();
            if (w)
            {
                if (kind == kDigNoStart)
                    pSrvLog(0, "P66 PositionGuard: 5428 mining end without start (reason %d: 1 no 5028/5429, 2 start expired %d ms, 3 action state %d not digging), %s UserNum %d UserIndex %d%s",
                            v1, v2, state, NameOf(user), userNum, IndexOf(user), Verdict());
                else
                    pSrvLog(0, "P66 PositionGuard: 5428 mining end after %d ms < MinDigMs %d (state %d), %s UserNum %d UserIndex %d%s",
                            v1, v2, state, NameOf(user), userNum, IndexOf(user), Verdict());
                Journal((BYTE)kind, user, userNum, 5428, AcJournal::kNone, now, v1, v2, state, g_minDigMs, sup);
            }
            if (g_mode == 1) { verdict = 1; InterlockedIncrement(&g_st.digRefused); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

extern "C" __declspec(dllexport) void __stdcall P66_GetStats(LONG* out16)
{
    if (out16) { memcpy(out16, &g_st, sizeof(g_st)); }
}
extern "C" __declspec(dllexport) void __stdcall P66_ResetState()
{
    LockEnter();
    memset(g_recall, 0, sizeof(g_recall)); memset(g_res, 0, sizeof(g_res)); memset(g_dig, 0, sizeof(g_dig)); memset(g_lim, 0, sizeof(g_lim));
    memset(&g_st, 0, sizeof(g_st));
    LockLeave();
}

namespace
{
    DWORD g_pAbs      = 0x0056BD0A;   // CRT abs (цель стоковой площадки 0x4D465A)
    DWORD g_pLabel103 = 0x004D5999;   // стоковое тело отказа 5013 result=0
    DWORD g_pRet103   = 0x004D59A0;   // после вытесненного `mov byte [ebp-0B4h],0`
    DWORD g_p4221D0   = 0x004221D0;   // границы клетки (площадка 5427)
    DWORD g_p4C28F0   = 0x004C28F0;   // SendPacket (площадки 5236 / предложение 6093), ret 18h
    DWORD g_p52B1C0   = 0x0052B1C0;   // CharRegenSelfPosition (площадка 6093), ret 10h
    DWORD g_p5646C0   = 0x005646C0;   // ConnectSend (площадка 5429), ret 14h
    DWORD g_p5324A0   = 0x005324A0;   // GetUser (площадка 5428), ret 4
    DWORD g_pDigExc   = 0x00546ADD;   // стоковая ветка «MOVE :: CharEMotion_MiningEnd() Exception Error»

    // A. вместо `call abs` 0x4D465A (cdecl, 1 аргумент, сток после вызова делает add esp,4).
    __declspec(naked) void St_Pick5012()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_pAbs]
            add   esp, 4
            pushad
            push  ebp
            call  P66_OnPick5012
            test  eax, eax
            jnz   refuse
            popad
            ret
        refuse:
            popad
            add   esp, 8                       // адрес возврата + аргумент abs
            jmp   dword ptr [g_pLabel103]
        }
    }

    // B. LABEL_103 0x4D5999: вытеснен `mov byte ptr [ebp-0B4h], 0` (7 б).
    __declspec(naked) void St_Refuse5012()
    {
        __asm
        {
            pushad
            push  ebp
            call  P66_OnPickRefuse5012
            popad
            mov   byte ptr [ebp-0xB4], 0
            jmp   dword ptr [g_pRet103]
        }
    }

    // C2. вместо `call sub_4221D0` 0x52BBF5 (thiscall ecx=CMapManager, 2 аргумента, ret 8).
    __declspec(naked) void St_Recall5427()
    {
        __asm
        {
            push  dword ptr [esp+8]
            push  dword ptr [esp+8]
            call  dword ptr [g_p4221D0]
            test  eax, eax
            jz    done
            pushad
            push  ebp
            call  P66_OnRecall5427
            test  eax, eax
            jnz   refuse
            popad
            jmp   done
        refuse:
            popad
            xor   eax, eax
        done:
            ret   8
        }
    }

    // C1/D1. вместо `call sub_4C28F0` (thiscall, 6 аргументов, ret 18h): сток, затем запись ожидания.
    __declspec(naked) void St_Recall5236()
    {
        __asm
        {
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            call  dword ptr [g_p4C28F0]
            pushad
            push  ebp
            call  P66_OnRecallOffer5236
            popad
            ret   0x18
        }
    }
    __declspec(naked) void St_ResOffer6093()
    {
        __asm
        {
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            push  dword ptr [esp+24]
            call  dword ptr [g_p4C28F0]
            pushad
            push  ebp
            call  P66_OnResOffer6093
            popad
            ret   0x18
        }
    }

    // D2. вместо `call CharRegenSelfPosition` 0x52B1AC (thiscall, 4 аргумента, ret 10h): проверка ДО вызова.
    __declspec(naked) void St_ResConfirm6093()
    {
        __asm
        {
            pushad
            push  ebp
            call  P66_OnResConfirm6093
            test  eax, eax
            jnz   refuse
            popad
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            call  dword ptr [g_p52B1C0]
            ret   0x10
        refuse:
            popad
            xor   eax, eax
            ret   0x10
        }
    }

    // E1. вместо `call sub_5646C0` 0x4D9BEB (thiscall ecx=CUserMoveManager, 5 аргументов, ret 14h).
    __declspec(naked) void St_DigStart5028()
    {
        __asm
        {
            push  dword ptr [esp+20]
            push  dword ptr [esp+20]
            push  dword ptr [esp+20]
            push  dword ptr [esp+20]
            push  dword ptr [esp+20]
            call  dword ptr [g_p5646C0]
            pushad
            push  ebp
            call  P66_OnDigStart5028
            popad
            ret   0x14
        }
    }

    // E2. вместо `call sub_5324A0` 0x546B21 (thiscall ecx=CUserManager, 1 аргумент, ret 4).
    __declspec(naked) void St_DigEnd5428()
    {
        __asm
        {
            push  dword ptr [esp+4]
            call  dword ptr [g_p5324A0]
            test  eax, eax
            jz    done
            pushad
            push  ebp
            push  eax                          // P66_OnDigEnd5428(user, ebp)
            call  P66_OnDigEnd5428
            test  eax, eax
            jnz   refuse
            popad
        done:
            ret   4
        refuse:
            popad
            add   esp, 8                       // адрес возврата + аргумент
            jmp   dword ptr [g_pDigExc]
        }
    }

    const BYTE kOrigPick[5]      = { 0xE8, 0xAB, 0x76, 0x09, 0x00 };                     // 0x4D465A call 0x56BD0A (abs)
    const BYTE kOrigLabel103[7]  = { 0xC6, 0x85, 0x4C, 0xFF, 0xFF, 0xFF, 0x00 };         // 0x4D5999 mov byte [ebp-0B4h],0
    const BYTE kOrigRecall[5]    = { 0xE8, 0xD6, 0x65, 0xEF, 0xFF };                     // 0x52BBF5 call 0x4221D0
    const BYTE kOrigOffer5236[5] = { 0xE8, 0xB3, 0x3B, 0x02, 0x00 };                     // 0x49ED38 call 0x4C28F0
    const BYTE kOrigResOffer[5]  = { 0xE8, 0x1F, 0x78, 0xF9, 0xFF };                     // 0x52B0CC call 0x4C28F0
    const BYTE kOrigResConfirm[5]= { 0xE8, 0x0F, 0x00, 0x00, 0x00 };                     // 0x52B1AC call 0x52B1C0
    const BYTE kOrigDigStart[5]  = { 0xE8, 0xD0, 0xAA, 0x08, 0x00 };                     // 0x4D9BEB call 0x5646C0
    const BYTE kOrigDigEnd[5]    = { 0xE8, 0x7A, 0xB9, 0xFE, 0xFF };                     // 0x546B21 call 0x5324A0
    // Соседи (адреса возврата / цели переходов стабов).
    const BYTE kNbPickRet[3]     = { 0x83, 0xC4, 0x04 };                                 // 0x4D465F add esp,4
    const BYTE kNbRet103[4]      = { 0x6A, 0x01, 0x6A, 0x00 };                           // 0x4D59A0 push 1; push 0
    const BYTE kNbRecallRet[4]   = { 0x85, 0xC0, 0x75, 0x16 };                           // 0x52BBFA test eax,eax; jne
    const BYTE kNbOfferRet[3]    = { 0x8B, 0x4D, 0xF0 };                                 // 0x49ED3D mov ecx,[ebp-10h]
    const BYTE kNbResOfferRet[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x10, 0x00 };               // 0x52B0D1 эпилог sub_52B070
    const BYTE kNbResConfRet[6]  = { 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };               // 0x52B1B1 эпилог 6093
    const BYTE kNbDigStartRet[5] = { 0xE9, 0x0E, 0x0D, 0x00, 0x00 };                     // 0x4D9BF0 jmp эпилог 5028
    const BYTE kNbDigEndRet[6]   = { 0x89, 0x85, 0xDC, 0xFB, 0xFF, 0xFF };               // 0x546B26 mov [ebp-424h],eax
    const BYTE kNbDigExc[5]      = { 0x68, 0xB4, 0xCC, 0x59, 0x00 };                     // 0x546ADD push "MOVE :: CharEMotion_MiningEnd() Exception Error"
    // [fix13] Опоры кода состояния (поля стокового sub_52BFF0 / sub_4CB030) — гейт 5427 читает их сам.
    const BYTE kRefDead[3]       = { 0x8B, 0x51, 0x4F };                                 // 0x4CB05D mov edx,[ecx+4Fh]
    const BYTE kRefExchange[7]   = { 0x83, 0xB8, 0x45, 0x01, 0x00, 0x00, 0x00 };         // 0x52C070 cmp [eax+145h],0  код 2
    const BYTE kRefAuction[7]    = { 0x83, 0xB9, 0x5F, 0x01, 0x00, 0x00, 0x00 };         // 0x52C0A6 cmp [ecx+15Fh],0  код 3
    const BYTE kRefStore[7]      = { 0x83, 0xBA, 0x4D, 0x01, 0x00, 0x00, 0x00 };         // 0x52C0DC cmp [edx+14Dh],0  код 4
    const BYTE kRefFishing[7]    = { 0x0F, 0xB6, 0x88, 0xB4, 0xF6, 0x03, 0x00 };         // 0x52C10F movzx ecx,byte [eax+3F6B4h] код 5
    // [fix13] Опоры ветки «iAmount <= 0» (LOOT-2): предикаты кода, таблица предметов, поля записи таблицы.
    const BYTE kRefIsItem[7]     = { 0x81, 0x7D, 0x08, 0x47, 0x50, 0x00, 0x00 };         // 0x532A93 cmp [ebp+8],5047h (sub_532A90)
    const BYTE kRefIsB10[4]      = { 0x83, 0x7D, 0x08, 0x01 };                           // 0x532B13 cmp [ebp+8],1     (sub_532B10)
    const BYTE kRefIsB30[7]      = { 0x81, 0x7D, 0x08, 0xD1, 0x07, 0x00, 0x00 };         // 0x532B34 cmp [ebp+8],7D1h  (sub_532B30)
    const BYTE kRefTable[5]      = { 0xA1, 0x98, 0x5E, 0x5F, 0x00 };                     // 0x4D5317 mov eax,[5F5E98h]
    const BYTE kRefT7[5]         = { 0x0F, 0xB6, 0x4C, 0x10, 0x07 };                     // 0x4D531C movzx ecx,byte [eax+edx+7]
    const BYTE kRefT24[5]        = { 0x0F, 0xB6, 0x4C, 0x10, 0x24 };                     // 0x4D533E movzx ecx,byte [eax+edx+24h]
    const BYTE kRefT23[5]        = { 0x0F, 0xB6, 0x4C, 0x10, 0x23 };                     // 0x4D5360 movzx ecx,byte [eax+edx+23h]
    const BYTE kRefT1A[5]        = { 0x0F, 0xB6, 0x4C, 0x10, 0x1A };                     // 0x4D5381 movzx ecx,byte [eax+edx+1Ah]
    const BYTE kRefStride[6]     = { 0x81, 0xEA, 0x47, 0x50, 0x00, 0x00 };               // 0x4D530E sub edx,5047h (затем imul edx,edx,47h)

    void ParseStates(const wchar_t* s)
    {
        g_digStateN = 0;
        while (*s && g_digStateN < 8)
        {
            while (*s == L' ' || *s == L',' || *s == L';') { ++s; }
            if (!*s) { break; }
            int v = 0; bool any = false;
            while (*s >= L'0' && *s <= L'9') { v = v * 10 + (*s - L'0'); ++s; any = true; }
            if (any) { g_digStates[g_digStateN++] = v; }
            while (*s && *s != L',' && *s != L';') { ++s; }
        }
        if (g_digStateN == 0) { g_digStates[0] = 110; g_digStates[1] = 114; g_digStateN = 2; }
    }
}

PatchResult P66_PositionGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode        = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    g_pickCheck   = Config::GetBool(kSec, L"PickupCheck", true);
    g_pickTol     = Config::GetInt(kSec, L"PickupTileTolerance", 9);
    g_returnItem  = Config::GetBool(kSec, L"ReturnItemOnRefuse", true);
    g_recallCheck = Config::GetBool(kSec, L"RecallCheck", true);
    g_recallWindowSec = Config::GetInt(kSec, L"RecallWindowSec", 120);
    g_recallTol   = Config::GetInt(kSec, L"RecallTileTolerance", 3);
    g_recallGate  = Config::GetBool(kSec, L"RecallGate", true);
    g_resCheck    = Config::GetBool(kSec, L"ResCheck", true);
    g_resWindowSec = Config::GetInt(kSec, L"ResOfferWindowSec", 330);
    g_mineCheck   = Config::GetBool(kSec, L"MiningCheck", true);
    g_minDigMs    = Config::GetInt(kSec, L"MinDigMs", 5000);
    g_digWindowSec = Config::GetInt(kSec, L"DigWindowSec", 60);
    g_requireDigState = Config::GetBool(kSec, L"RequireDigState", true);
    wchar_t states[64]; Config::GetStr(kSec, L"DigStates", L"110,114", states, 64); ParseStates(states);
    if (g_pickTol < 1) { g_pickTol = 1; }
    if (g_recallWindowSec < 1) { g_recallWindowSec = 1; }
    if (g_recallTol < 0) { g_recallTol = 0; }
    if (g_resWindowSec < 1) { g_resWindowSec = 1; }
    if (g_minDigMs < 0) { g_minDigMs = 0; }
    if (g_digWindowSec < 1) { g_digWindowSec = 1; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    P66_ResetState();

    const bool wantPick   = g_pickCheck || g_returnItem;
    const bool wantRecall = g_recallCheck;
    const bool wantRes    = g_resCheck;
    const bool wantMine   = g_mineCheck;
    if (!wantPick && !wantRecall && !wantRes && !wantMine) { Log::Line(L"    P66: все проверки выключены — площадки не ставятся"); return PatchResult::Disabled; }

    Site sites[48]; int n = 0;
    if (wantPick)
    {
        sites[n++] = { 0x004D465A, kOrigPick,       sizeof(kOrigPick)       };
        sites[n++] = { 0x004D5999, kOrigLabel103,   sizeof(kOrigLabel103)   };
        sites[n++] = { 0x004D465F, kNbPickRet,      sizeof(kNbPickRet)      };
        sites[n++] = { 0x004D59A0, kNbRet103,       sizeof(kNbRet103)       };
        if (g_returnItem)
        {
            sites[n++] = { 0x00532A93, kRefIsItem,  sizeof(kRefIsItem)  };
            sites[n++] = { 0x00532B13, kRefIsB10,   sizeof(kRefIsB10)   };
            sites[n++] = { 0x00532B34, kRefIsB30,   sizeof(kRefIsB30)   };
            sites[n++] = { 0x004D530E, kRefStride,  sizeof(kRefStride)  };
            sites[n++] = { 0x004D5317, kRefTable,   sizeof(kRefTable)   };
            sites[n++] = { 0x004D531C, kRefT7,      sizeof(kRefT7)      };
            sites[n++] = { 0x004D533E, kRefT24,     sizeof(kRefT24)     };
            sites[n++] = { 0x004D5360, kRefT23,     sizeof(kRefT23)     };
            sites[n++] = { 0x004D5381, kRefT1A,     sizeof(kRefT1A)     };
        }
    }
    if (wantRecall)
    {
        sites[n++] = { 0x0052BBF5, kOrigRecall,     sizeof(kOrigRecall)     };
        sites[n++] = { 0x0049ED38, kOrigOffer5236,  sizeof(kOrigOffer5236)  };
        sites[n++] = { 0x0052BBFA, kNbRecallRet,    sizeof(kNbRecallRet)    };
        sites[n++] = { 0x0049ED3D, kNbOfferRet,     sizeof(kNbOfferRet)     };
        if (g_recallGate)
        {
            sites[n++] = { 0x004CB05D, kRefDead,     sizeof(kRefDead)     };
            sites[n++] = { 0x0052C070, kRefExchange, sizeof(kRefExchange) };
            sites[n++] = { 0x0052C0A6, kRefAuction,  sizeof(kRefAuction)  };
            sites[n++] = { 0x0052C0DC, kRefStore,    sizeof(kRefStore)    };
            sites[n++] = { 0x0052C10F, kRefFishing,  sizeof(kRefFishing)  };
        }
    }
    if (wantRes)
    {
        sites[n++] = { 0x0052B0CC, kOrigResOffer,   sizeof(kOrigResOffer)   };
        sites[n++] = { 0x0052B1AC, kOrigResConfirm, sizeof(kOrigResConfirm) };
        sites[n++] = { 0x0052B0D1, kNbResOfferRet,  sizeof(kNbResOfferRet)  };
        sites[n++] = { 0x0052B1B1, kNbResConfRet,   sizeof(kNbResConfRet)   };
    }
    if (wantMine)
    {
        sites[n++] = { 0x004D9BEB, kOrigDigStart,   sizeof(kOrigDigStart)   };
        sites[n++] = { 0x00546B21, kOrigDigEnd,     sizeof(kOrigDigEnd)     };
        sites[n++] = { 0x004D9BF0, kNbDigStartRet,  sizeof(kNbDigStartRet)  };
        sites[n++] = { 0x00546B26, kNbDigEndRet,    sizeof(kNbDigEndRet)    };
        sites[n++] = { 0x00546ADD, kNbDigExc,       sizeof(kNbDigExc)       };
    }
    if (!VerifyAllSites(L"P66", sites, n)) { return PatchResult::Mismatch; }

    if (wantPick)
    {
        if (!Hook::WriteCall(0x004D465A, &St_Pick5012, 5))   { return PatchResult::Failed; }
        if (!Hook::WriteJmp (0x004D5999, &St_Refuse5012, 7)) { return PatchResult::Failed; }
    }
    if (wantRecall)
    {
        if (!Hook::WriteCall(0x0052BBF5, &St_Recall5427, 5)) { return PatchResult::Failed; }
        if (!Hook::WriteCall(0x0049ED38, &St_Recall5236, 5)) { return PatchResult::Failed; }
    }
    if (wantRes)
    {
        if (!Hook::WriteCall(0x0052B0CC, &St_ResOffer6093, 5))   { return PatchResult::Failed; }
        if (!Hook::WriteCall(0x0052B1AC, &St_ResConfirm6093, 5)) { return PatchResult::Failed; }
    }
    if (wantMine)
    {
        if (!Hook::WriteCall(0x004D9BEB, &St_DigStart5028, 5)) { return PatchResult::Failed; }
        if (!Hook::WriteCall(0x00546B21, &St_DigEnd5428, 5))   { return PatchResult::Failed; }
    }
    Log::Line(L"    P66: режим %s; 5012: сверка=%d допуск %d клеток, возврат предмета=%d; 5427: сверка=%d окно %d с, допуск %d, гейт=%d; "
              L"6093: сверка=%d окно %d с; 5428: сверка=%d MinDigMs %d, окно %d с, состояние=%d (%d кодов); строки не чаще 1/%d с",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ", g_pickCheck ? 1 : 0, g_pickTol, g_returnItem ? 1 : 0,
              g_recallCheck ? 1 : 0, g_recallWindowSec, g_recallTol, g_recallGate ? 1 : 0,
              g_resCheck ? 1 : 0, g_resWindowSec, g_mineCheck ? 1 : 0, g_minDigMs, g_digWindowSec, g_requireDigState ? 1 : 0, g_digStateN,
              g_journalIntervalSec);
    return PatchResult::Applied;
}
