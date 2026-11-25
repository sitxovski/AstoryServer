// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P33 — ★ ДЕФЕКТЫ СЕРВЕРНОЙ ЧАСТИ ЗАТОЧКИ (окно «Улучшение снаряжения» 20000,
//  C→S 6504 → S→C 6505, GameServer ↔ DBManager 2304/2305).
//
//  ЭТО НАША ПРАВКА, а не перенос чужой. Разбор: Reports/gear_upgrade_re_report.md
//  (§5, §7-бис, §9, §9-бис, §11-бис «Волна 6»), итоговый отчёт волны:
//  Reports/gear_upgrade/wave6_server.md, документ патча:
//  AstoryServer/Docs/GameServer/gear-upgrade-server-defects-p33.md
//
//  ★★★ ЭТАЛОН. Все 33 площадки сверены побайтно в ЧЕТЫРЁХ образах: наш
//  `RE/ida/server_work/GameServer.exe`, ЖИВОЙ `v2\GameServer\GameServer.exe`,
//  ЖИВОЙ `v2\Indun_GameServer\GameServer.exe` (оба MD5 E7B4AC38…) и сток
//  `GameServer.exe_before_mine_patch.exe` — расхождений 0.
//  С площадками P11 (0x004FFFC5, 0x00500602) не пересекается ни одна.
//
//  ★ ПРОТОКОЛ НЕ МЕНЯЕТСЯ (закон old-server-protocol-compat): ни размеров, ни
//  раскладки пакетов. Меняются только КОДЫ результата внутри уже существующего
//  тела 6505 — и только на те, которые клиент обрабатывает
//  (Recv_ItemUpgradeBatch@0xD2B1E0, эталон network.c:19609-19800: 2…7 → нотисы
//  50006…50011, 1/8 → успех/провал, 0 → `default: break`, т.е. тишина).
//
//  Ключи (секция [P33_GearUpgradeServerDefects]):
//    SoulPossessGate   — Д-1: гейт «душа» (sub_52EEA0, SoulState==1 — как у 5033)
//                        и «одержим» (sub_52EE40, SoulState==2) у 6500/6502/6504/6506
//    SilentCodes       — Д-2/Д-3: 14 отказов кодом 0 в обработчике и 5 в приёмнике
//                        ответа БД → осмысленные коды 5 и 2
//    GradeCode6        — N-7: «грейд свитка не тот» шлёт 6 (50010), а не 3 («нет купонов»)
//    ZeroLimitGuard    — N-14: предел SowelCombine[+0x92] <= 0 → отказ 7 ДО броска
//    ScrollCountFirst  — Д-7: «свитков меньше нужного» проверяется ДО броска ГСЧ
//    HelperWeight      — N-1: вес израсходованных помощников 97/98 списывается с персонажа
//    SyncErrorLog      — Д-4: осмысленная строка лога при расхождении UserIndex в 2305
//    InFlightLock      — N-2: «одна попытка в полёте» на персонажа (+ LockTimeoutMs);
//                        ранний отказ стоит ПОСЛЕ подписи/анти-повтора, снятие — ПОСЛЕ приёма 2305
//    SowelColumn57     — Д-5: колонка 57 SowelCombine.txt пишется в +0xA8, а не
//                        поверх колонки 56 в +0xA6
//    OptionIndexBounds — Н-15 (найдено этой волной): индекс OptionUpgrade на ступенях
//                        7…20 без проверки границ (номер опции −1 и 94…329 при 93 записях) —
//                        в заточке 6504 и в благословении 6551 (Recv_UserUpgradeBless)
//
//  Д-9, Д-10, Д-6, N-12, N-13 кодом НЕ лечатся — обоснование в отчёте волны.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

// ⚠ Смещения в __asm — ТОЛЬКО через #define (закон `msvc-inline-asm-offsets`).
#define UPG_FRAME_SLOT_TYPE   0x2C8     // [ebp-0x2C8] ScrollType (вытесненная инструкция)

namespace
{
    const wchar_t* const S = L"P33_GearUpgradeServerDefects";

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);                     // 0x5324A0
    typedef int   (__thiscall *FnUserPred)(void* mgr, short idx);                    // 0x52EEA0 / 0x52EE40
    typedef char  (__thiscall *FnPreamble)(void* mgr, short idx, short op);          // 0x52BFF0
    typedef int   (__thiscall *FnSendPacket)(void* net, short op, short len, short idx,
                                             void* body, short a6, int a7);          // 0x4C28F0
    typedef int   (__thiscall *FnHandler)(void* mgr, short idx, void* pkt);          // 0x4FEE50 / 0x500800
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);             // 0x569DF0

    const FnGetUser    SrvGetUser     = (FnGetUser)Srv::kGetUser;
    const FnUserPred   SrvIsSoul      = (FnUserPred)0x0052EEA0;   // CUser+0x182D3 == 1 («душа»)
    const FnUserPred   SrvIsPossessed = (FnUserPred)0x0052EE40;   // соулмейт > 0 && +0x182D3 == 2
    const FnPreamble   SrvPreamble    = (FnPreamble)0x0052BFF0;   // преамбула 6001 + причины 1…5
    const FnSendPacket SrvSendPacket  = (FnSendPacket)Srv::kSendPacket;
    const FnHandler    SrvRecvDb2305  = (FnHandler)0x00500800;    // recvDBShellItemUpgrade
    const FnSrvLog     SrvLog         = (FnSrvLog)Srv::kLog;

    constexpr int   kLogCat          = 26;          // категория штатных строк CRTJIN заточки
    constexpr WORD  kOp6505          = 6505;
    constexpr short kLen6505         = 231;         // 0xE7 — тело ответа заточки
    constexpr int   kOffUserIndex    = 0x174;       // CUser+0x174 — «UserIndex» (в отчёте: charId)
    constexpr DWORD kSowelTablePtr   = 0x007DFFC4;  // [0x7DFFC4] — база SowelCombine (asm 0x4FFBED)
    constexpr int   kSowelRec        = 0xAC;        // 172 б
    constexpr int   kSowelLimitOff   = 0x92;        // +146 — предел попыток (колонка 45)
    // ★ Поправка к отчёту §7б.5: база CThreadManager 0x60AD18 ⇒ SowelCombine —
    //   указатель 0x7DFFC4 (+0x1D52AC) и счётчик 0x7DFFC8 (+0x1D52B0); OptionUpgrade —
    //   указатель 0x7DFFCC (+0x1D52B4) и счётчик 0x7DFFD0 (+0x1D52B8). Сняты с asm
    //   загрузчиков sub_4A0DB0 / sub_4A1680 (0x4A17BD, 0x4A17DE) и потребителей
    //   (0x4FFBED, 0x500273). В отчёте все четыре сдвинуты на 4 байта.
    constexpr DWORD kSowelCountPtr   = 0x007DFFC8;
    constexpr int   kMaxUserIdx      = 10000;       // запас; живые индексы < 0x226

    // ── ключи ───────────────────────────────────────────────────────────────
    bool  g_soulPossess = true;
    bool  g_zeroLimit   = true;
    bool  g_countFirst  = true;
    bool  g_lockOn      = true;
    DWORD g_lockTimeout = 15000;

    // ═════════════════════════════════════════════════════════════════════════
    //  N-2: замок «одна попытка в полёте». Ключ — (индекс сессии, UserIndex):
    //  UserIndex отсекает чужую запись, если слот занял другой персонаж.
    //  Своя таблица, а НЕ стоковый флаг CUser+gap_145[15] (образец 5033,
    //  GameServer.c:97472): тот общий на 5033/6500/6502 и снимается приёмом
    //  ответа РАЗБОРКИ (GameServer.c:98619-98661), хотя 6502 его не ставит, —
    //  на нём замок заточки разваливался бы от постороннего пакета. И у стока нет
    //  тайм-аута: потерянный ответ БД запер бы заточку навсегда.
    // ═════════════════════════════════════════════════════════════════════════
    struct LockEntry { int userIndex; DWORD tick; };
    LockEntry        g_lock[kMaxUserIdx] = {};
    CRITICAL_SECTION g_lockCs;
    bool             g_lockCsInit = false;

    bool LockActiveNoCs(short idx, int userIndex)
    {
        if (idx < 0 || idx >= kMaxUserIdx) { return false; }
        const LockEntry& e = g_lock[idx];
        if (e.tick == 0 || e.userIndex != userIndex) { return false; }
        return (DWORD)(GetTickCount() - e.tick) < g_lockTimeout;
    }

    // Отказ дублю: код 0, как у легаси-ветки 5033 при занятом флаге
    // (GameServer.c:97495-97498). Клиент на коде 0 не показывает ничего и только
    // снимает ожидание; итог по предмету придёт ответом на ПЕРВЫЙ запрос.
    void SendResult(void* mgr, short idx, BYTE code)
    {
        BYTE body[kLen6505] = {};
        body[0] = code;
        void* net = *(void**)((BYTE*)mgr + 4);
        SrvSendPacket(net, (short)kOp6505, kLen6505, idx, body, 0, 1);
    }
}

// ═══════════════════════════ C-обработчики ═════════════════════════════════
extern "C"
{
// Д-1: подмена `call sub_52BFF0` в 6500/6502/6504/6506. Сначала штатная преамбула
// (она шлёт 6001 и возвращает причины 1…5), затем наши два гейта. Любое ненулевое
// значение ведёт обработчик по ЕГО СОБСТВЕННОЙ ветке «действие заблокировано»
// (6501/6503/6505/6507 код 0; у 6505 он дальше переводится ключом SilentCodes в 5).
int __fastcall P33_PreambleGate(void* mgr, void* /*edx*/, int a2, int op)
{
    const short idx = (short)a2;
    const char  r   = SrvPreamble(mgr, idx, (short)op);
    if (r) { return (unsigned char)r; }
    if (!g_soulPossess) { return 0; }
    __try
    {
        if (SrvIsSoul(mgr, idx))
        {
            SrvLog(kLogCat, "P33 D-1: opcode %d refused, user %d is SOUL (SoulState==1)", op, (int)idx);
            return 1;
        }
        if (SrvIsPossessed(mgr, idx))
        {
            SrvLog(kLogCat, "P33 D-1: opcode %d refused, user %d is POSSESSED (SoulState==2)", op, (int)idx);
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

// N-2 (ранняя проверка): площадка 0x004FF062 — СРАЗУ ПОСЛЕ преамбулы 6504, то есть
// после штатных анти-повтора sub_524390 и подписи sub_523F00 (ревизия, М-1: поддельный
// или повторённый пакет обязан идти штатной веткой «Secret Error» и счётчиком отключения,
// а не получать наш ответ). И всё ещё ДО броска и до анонса P11 (0x00500602).
// Кадр: [ebp+8] индекс, [ebp-0x2EC] CUserManager, [ebp-0x2C4] CUser (0x4FF039).
// 1 — дубль (ответ кодом 0 уже отправлен, обработчик уходит в эпилог), 0 — дальше по стоку.
int __cdecl P33_DupCheck6504(BYTE* ebp)
{
    if (!g_lockOn || !g_lockCsInit) { return 0; }
    __try
    {
        const short idx = *(short*)(ebp + 8);
        void*       mgr = *(void**)(ebp - 0x2EC);
        BYTE*       u   = *(BYTE**)(ebp - 0x2C4);
        if (!u) { return 0; }
        const int ui = *(int*)(u + kOffUserIndex);
        EnterCriticalSection(&g_lockCs);
        const bool busy = LockActiveNoCs(idx, ui);
        LeaveCriticalSection(&g_lockCs);
        if (busy)
        {
            SrvLog(kLogCat, "P33 N-2: 6504 from user %d (UserIndex %d) dropped - previous upgrade "
                            "is still waiting for DB reply 2305; reply code 0", (int)idx, ui);
            SendResult(mgr, idx, 0);
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

// N-2 (атомарная постановка): вызывается из стаба на `call ConnectSend` (2304).
// Кадр обработчика: [ebp+8] индекс, [ebp-0x2EC] CUserManager, [ebp-0x1C6] UserIndex
// в теле 2304 (+2). 1 — отправлять, 0 — дубль (уже ответили кодом 0).
int __stdcall P33_Gate2304(BYTE* ebp)
{
    if (!g_lockOn || !g_lockCsInit) { return 1; }
    const short idx = *(short*)(ebp + 8);
    const int   ui  = *(int*)(ebp - 0x1C6);
    void*       mgr = *(void**)(ebp - 0x2EC);
    if (idx < 0 || idx >= kMaxUserIdx) { return 1; }

    EnterCriticalSection(&g_lockCs);
    const bool busy = LockActiveNoCs(idx, ui);
    if (!busy)
    {
        g_lock[idx].userIndex = ui;
        // ★ fix w33b (13.10.2026, замечание P63): было `GetTickCount() | 1` — при чётном now такт замка
        //   = now+1, и в ТОМ ЖЕ кванте таймера (~15,6 мс) `now - tick` = 0xFFFFFFFF ≥ тайм-аута ⇒ замок
        //   «просрочен», дубль 6504/2304 проходил. 0 зарезервирован под «свободно» — подменяем только его
        //   (как P63 `L.tick = now ? now : 1`).
        const DWORD now       = GetTickCount();
        g_lock[idx].tick      = now ? now : 1;
    }
    LeaveCriticalSection(&g_lockCs);

    if (busy)
    {
        SrvLog(kLogCat, "P33 N-2: 2304 for user %d (UserIndex %d) suppressed - upgrade already in flight",
               (int)idx, ui);
        SendResult(mgr, idx, 0);
        return 0;
    }
    return 1;
}

// N-2 (снятие): подмена `call recvDBShellItemUpgrade` в диспетчере ответов БД.
// Снимаем ПОСЛЕ обработки (ревизия, М-2): пока приём не записал результат в память,
// новый 6504 того же персонажа обязан видеть замок. UserIndex читаем заранее.
int __fastcall P33_WrapRecvDb(void* mgr, void* /*edx*/, int a2, int pkt)
{
    const short idx  = (short)a2;
    bool        have = false;
    int         ui   = 0;
    if (g_lockOn && g_lockCsInit && idx >= 0 && idx < kMaxUserIdx)
    {
        __try { ui = *(int*)(pkt + 9 + 2); have = true; }     // тело 2305, +2 — UserIndex
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    const int r = SrvRecvDb2305(mgr, idx, (void*)pkt);
    if (have)
    {
        EnterCriticalSection(&g_lockCs);
        if (g_lock[idx].userIndex == ui) { g_lock[idx].tick = 0; }
        LeaveCriticalSection(&g_lockCs);
    }
    return r;
}

// N-14 + Д-7: проверки ДО броска ГСЧ (площадка 0x004FFD44 — общий вход обеих
// веток v17 перед `sub_5329A0(0, 100000)`). 0 — дальше по стоку; 7 / 3 — уйти
// в штатный блок отправки 6505 с этим кодом.
int __cdecl P33_PreRoll(BYTE* ebp)
{
    __try
    {
        const int code = *(int*)(ebp - 0x220);                 // запись предмета +0 — код
        const int row  = code - Srv::kItemCodeBase;
        if (g_zeroLimit && row >= 0 && row < *(int*)kSowelCountPtr)
        {
            BYTE* tbl = *(BYTE**)kSowelTablePtr;
            const short lim = *(short*)(tbl + row * kSowelRec + kSowelLimitOff);
            if (lim <= 0)
            {
                SrvLog(kLogCat, "P33 N-14: user %d item %d has upgrade limit %d (SowelCombine col 45) - "
                                "not upgradable, refused with code 7 BEFORE the roll",
                       (int)*(short*)(ebp + 8), code, (int)lim);
                return 7;
            }
        }
        if (g_countFirst)
        {
            const int amount = *(int*)(ebp - 0x147);            // CouponAmount (+9 записи свитка)
            const int use    = *(int*)(ebp - 0x234);            // UseCoupon (= 1)
            if (amount < use)
            {
                SrvLog(kLogCat, "P33 D-7: user %d scroll amount %d < %d - refused with code 3 BEFORE the roll",
                       (int)*(short*)(ebp + 8), amount, use);
                return 3;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 0;
}

// Д-4: вместо безликой строки — индекс сессии и оба UserIndex. Ответа клиенту
// НЕТ намеренно: слот уже занят ДРУГИМ персонажем, пакет ушёл бы чужому игроку.
void __cdecl P33_OnSyncError(BYTE* ebp)
{
    __try
    {
        const short idx  = *(short*)(ebp + 8);
        const int   pkt  = *(int*)(ebp - 0x166);                // тело 2305 +2
        BYTE*       u    = *(BYTE**)(ebp - 0x264);
        const int   cur  = u ? *(int*)(u + kOffUserIndex) : -1;
        SrvLog(kLogCat, "Recv_DB_ShellItemUpgrade UserIndex Sync Error: slot %d, UserIndex in DB reply %d, "
                        "UserIndex now in slot %d - reply NOT sent (slot belongs to another character)",
               (int)idx, pkt, cur);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
}   // extern "C"

// ═══════════════════════════ трамплины ══════════════════════════════════════
namespace
{
    DWORD g_pConnectSend  = Srv::kConnectSend;  // 0x5646C0 — штатная цель call @0x5007BB
    DWORD g_pPreRollRet   = 0x004FFD4A;         // после вытесненного `mov edx,[ebp-0x2C8]`
    DWORD g_pCode7Block   = 0x004FFC5D;         // `mov byte [ebp-0x100],7` + отправка 6505
    DWORD g_pCode3Block   = 0x005000E9;         // `mov byte [ebp-0x100],3` + отправка 6505
    DWORD g_pRecvExit     = 0x00500EFB;         // общий выход recvDBShellItemUpgrade
    DWORD g_pOptCount     = 0x007DFFD0;         // счётчик записей OptionUpgrade.txt (93 на живом)
    DWORD g_pOptRet       = 0x00500269;         // после вытесненного `movsx edx,[ebp-0x2E4]`
    DWORD g_pOptSkip      = 0x00500342;         // штатная цель `jne` «опция не найдена» — значение не меняется
    DWORD g_pBlessRet     = 0x00535E08;         // 6551: после вытесненного `movsx edx,[ebp-0x1B0]`
    DWORD g_pBlessSkip    = 0x00535EE1;         // 6551: штатная цель трёх `jne` — следующий шаг цикла
    DWORD g_pDupNext      = 0x004FF09D;         // 6504: штатная цель `je` «преамбула пропустила»
    DWORD g_pDupBlocked   = 0x004FF069;         // 6504: штатный блок «заблокировано» (код 0 → 5)
    DWORD g_pUpgExit      = 0x005007C0;         // 6504: общий эпилог обработчика

    // @0x005007BB вместо `call ConnectSend(2304)`: ecx = CUserMoveManager, на стеке
    // [ret][op][len][conn][body][userIdx]. Проверяем/ставим замок по кадру вызывающего
    // (ebp не тронут) и либо уходим в ConnectSend хвостовым переходом со ВСЕМ стеком
    // как был, либо сами снимаем 5 аргументов (thiscall).
    __declspec(naked) void Stub2304()
    {
        __asm
        {
            push ecx
            push ebp
            call P33_Gate2304               // stdcall: снимет свой аргумент
            pop  ecx
            test eax, eax
            jz   Blocked
            jmp  dword ptr [g_pConnectSend]
        Blocked:
            xor  eax, eax
            ret  0x14
        }
    }

    // @0x004FFD44 (6 б `mov edx,[ebp-0x2C8]`). eax/ecx/edx здесь МЁРТВЫ: следующие
    // инструкции пишут их до чтения (0x4FFD44 edx, 0x4FFD50 eax, 0x4FFD55 ecx), флаги
    // тоже не читаются — поэтому cdecl-вызов их портить вправе.
    __declspec(naked) void PreRollTrampoline()
    {
        __asm
        {
            push ebp
            call P33_PreRoll
            add  esp, 4
            cmp  eax, 7
            je   ToCode7
            cmp  eax, 3
            je   ToCode3
            mov  edx, dword ptr [ebp - UPG_FRAME_SLOT_TYPE]   // вытесненная инструкция
            jmp  dword ptr [g_pPreRollRet]
        ToCode7:
            jmp  dword ptr [g_pCode7Block]
        ToCode3:
            jmp  dword ptr [g_pCode3Block]
        }
    }

    // @0x005008CF (5 б `push offset "…UserIndex Sync Error"`). Штатные push/call/add
    // пропускаются целиком, стек на уровне тела функции — как у стока перед jmp.
    __declspec(naked) void SyncErrorTrampoline()
    {
        __asm
        {
            push ebp
            call P33_OnSyncError
            add  esp, 4
            jmp  dword ptr [g_pRecvExit]
        }
    }

    // Н-15 (найдено этой волной): @0x00500262 (7 б `movsx edx, word [ebp-0x2E4]`).
    // Ветка усиления доп-опции на ступенях 7…20 индексирует OptionUpgrade (93 записи)
    // номером опции предмета БЕЗ проверки границ — ни снизу (у предмета без опции там
    // −1), ни сверху (в Item_OptionTable.txt есть номера 94, 95, 105, 300…329).
    // Вне таблицы — уходим на штатный путь «опция не найдена» (значение не меняется).
    // eax здесь мёртв (0x500269 пишет его до чтения), флаги перезаписывает cmp @0x50027D.
    // Н-15б (ревизия, С-1): та же конструкция в Recv_UserUpgradeBless@0x5358C0 (6551 →
    // 6552), цикл по ступеням 7…N, площадка 0x00535E01 (7 б `movsx edx,[ebp-0x1B0]`).
    // Номер опции — v10 = sub_4A7EE0(...), т.е. может быть −1. Вне таблицы → 0x535EE1
    // (туда же ведут все три стоковых `jne` «не совпало»: значение без изменений).
    // eax на 0x535E08 пишется до чтения; флаги перезаписывает cmp @0x535E1C.
    __declspec(naked) void BlessOptionIndexTrampoline()
    {
        __asm
        {
            movsx edx, word ptr [ebp - 0x1B0]                 // вытесненная инструкция
            test  edx, edx
            js    BlessSkip
            mov   eax, dword ptr [g_pOptCount]
            cmp   edx, dword ptr [eax]
            jge   BlessSkip
            jmp   dword ptr [g_pBlessRet]
        BlessSkip:
            jmp   dword ptr [g_pBlessSkip]
        }
    }

    // N-2 ранний отказ @0x004FF062 (7 б `movzx eax,al / test eax,eax / je 0x4FF09D`) —
    // сразу за вызовом преамбулы. Стек на уровне тела, eax/ecx/edx дальше пишутся до
    // чтения (0x4FF09D movzx ecx, 0x4FF0DD movsx edx, 0x4FF11C movsx eax), флаги
    // перезаписывает cmp @0x4FF0A4 — cdecl-вызов их портить вправе.
    __declspec(naked) void DupCheckTrampoline()
    {
        __asm
        {
            movzx eax, al                                     // вытесненные инструкции
            test  eax, eax
            jnz   DupBlocked                                  // преамбула/душа/одержим — сток
            push  ebp
            call  P33_DupCheck6504
            add   esp, 4
            test  eax, eax
            jnz   DupExit
            jmp   dword ptr [g_pDupNext]
        DupBlocked:
            jmp   dword ptr [g_pDupBlocked]
        DupExit:
            jmp   dword ptr [g_pUpgExit]
        }
    }

    __declspec(naked) void OptionIndexTrampoline()
    {
        __asm
        {
            movsx edx, word ptr [ebp - 0x2E4]                 // вытесненная инструкция
            test  edx, edx
            js    OptSkip
            mov   eax, dword ptr [g_pOptCount]
            cmp   edx, dword ptr [eax]
            jge   OptSkip
            jmp   dword ptr [g_pOptRet]
        OptSkip:
            jmp   dword ptr [g_pOptSkip]
        }
    }

    // ── площадки ────────────────────────────────────────────────────────────
    // Д-1: `call sub_52BFF0` (E8 rel32) в четырёх обработчиках
    const BYTE kPre6500[5] = { 0xE8, 0x70, 0xF6, 0x02, 0x00 };   // 0x4FC97B Recv_User_UpperRefine
    const BYTE kPre6502[5] = { 0xE8, 0xB6, 0xE4, 0x02, 0x00 };   // 0x4FDB35 Recv_User_Disassemble
    const BYTE kPre6504[5] = { 0xE8, 0x8E, 0xCF, 0x02, 0x00 };   // 0x4FF05D CharShellItemUpgrade_0
    const BYTE kPre6506[5] = { 0xE8, 0x00, 0xAF, 0x02, 0x00 };   // 0x5010EB Recv_User_ShellItemUpgradeReset
    // N-2
    const BYTE kDup6504[7]  = { 0x0F, 0xB6, 0xC0, 0x85, 0xC0, 0x74, 0x34 };  // 0x4FF062 movzx eax,al; test; je
    const BYTE kDispDb[5]   = { 0xE8, 0x16, 0xDB, 0x0C, 0x00 };  // 0x432CE5 call recvDBShellItemUpgrade
    const BYTE kSend2304[5] = { 0xE8, 0x00, 0x3F, 0x06, 0x00 };  // 0x5007BB call ConnectSend
    // N-14 + Д-7
    const BYTE kPreRoll[6]  = { 0x8B, 0x95, 0x38, 0xFD, 0xFF, 0xFF };  // 0x4FFD44 mov edx,[ebp-0x2C8]
    // Д-4
    const BYTE kSyncErr[5]  = { 0x68, 0x7C, 0x54, 0x59, 0x00 };  // 0x5008CF push 0x59547C
    // N-1: `mov dx, word [ebp-0x120]` (вес свитка v21[72]) → `mov dx, word [ebp-0xF4]` (сумма v22)
    const BYTE kWeight[7]   = { 0x66, 0x8B, 0x95, 0xE0, 0xFE, 0xFF, 0xFF };  // 0x500DF2
    const BYTE kWeightNew[7]= { 0x66, 0x8B, 0x95, 0x0C, 0xFF, 0xFF, 0xFF };
    // Д-5: вторая запись загрузчика SowelCombine `mov [edx+ecx+0xA6], ax` → +0xA8
    const BYTE kCol57[8]    = { 0x66, 0x89, 0x84, 0x0A, 0xA6, 0x00, 0x00, 0x00 };  // 0x4A1635
    // N-7: код 3 → 6 в ветке «грейд свитка ≠ грейду предмета» (лог "(2)")
    const BYTE kGrade[7]    = { 0xC6, 0x85, 0x00, 0xFF, 0xFF, 0xFF, 0x03 };  // 0x4FFB98
    // Н-15: `movsx edx, word ptr [ebp-0x2E4]` — номер доп-опции перед индексом OptionUpgrade
    const BYTE kOptIdx[7]   = { 0x0F, 0xBF, 0x95, 0x1C, 0xFD, 0xFF, 0xFF };  // 0x500262
    const BYTE kBlessIdx[7] = { 0x0F, 0xBF, 0x95, 0x50, 0xFE, 0xFF, 0xFF };  // 0x535E01 (6551)

    // Д-2/Д-3: отказы кодом 0. imm8 — последний байт `mov byte [ebp-0x100|-0xF0], 0`.
    struct CodeSite { DWORD va; BYTE disp; BYTE newCode; const char* why; };
    const CodeSite kCodes[] =
    {
        // CharShellItemUpgrade_0 — тело ответа [ebp-0x100]
        { 0x004FF069, 0x00, 5, "преамбула 6001 заблокировала (причины 1..5) / душа / одержим" },
        // ревизия М-4: код 4 у клиента = 50008 «Это не личный предмет.» — к «слот < 0»
        // не подходит по смыслу, поэтому общий 5.
        { 0x004FF0E8, 0x00, 5, "слот предмета < 0" },
        { 0x004FF127, 0x00, 5, "слот свитка < 0" },
        { 0x004FF31D, 0x00, 5, "в слоте помощника-98 купон другого типа" },
        { 0x004FF41B, 0x00, 5, "в слоте помощника-97 купон другого типа" },
        { 0x004FF569, 0x00, 5, "(524) категория свитка != 70" },
        { 0x004FF60E, 0x00, 5, "(21) свиток не предмет и не купон" },
        { 0x004FF67D, 0x00, 5, "(28) ScrollType вне ItemUpgrade.txt" },
        { 0x004FF6FF, 0x00, 5, "(1) ScrollType != записи таблицы" },
        { 0x004FFD10, 0x00, 5, "(8) вид улучшения не 1 и не 2 — Д-10, ветка сохранена" },
        { 0x004FFE6C, 0x00, 2, "(7) ступень за пределами OverUpgrade — «превышено максимальное количество»" },
        { 0x005003FC, 0x00, 5, "(11) свиток перестал быть купоном" },
        { 0x005004E3, 0x00, 5, "(12) помощник-97 перестал быть купоном" },
        { 0x005005CE, 0x00, 5, "(13) помощник-98 перестал быть купоном" },
        // recvDBShellItemUpgrade — тело ответа [ebp-0xF0]
        { 0x005008EE, 0x10, 5, "БД вернула код 0 (запись не сохранена)" },
        { 0x00500950, 0x10, 5, "свиток пропал из слота, пока ждали БД" },
        { 0x005009B2, 0x10, 5, "предмет пропал из слота, пока ждали БД" },
        { 0x00500A27, 0x10, 5, "помощник-98 пропал из слота, пока ждали БД" },
        { 0x00500A9C, 0x10, 5, "помощник-97 пропал из слота, пока ждали БД" },
    };

    bool WriteOneByte(DWORD va, BYTE expect, BYTE value)
    {
        return Hook::WriteByteChecked(va, expect, value);
    }
}

PatchResult P33_GearUpgradeServerDefects()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }

    g_soulPossess = Config::GetBool(S, L"SoulPossessGate",  true);
    const bool doCodes  = Config::GetBool(S, L"SilentCodes",      true);
    const bool doGrade  = Config::GetBool(S, L"GradeCode6",       true);
    g_zeroLimit   = Config::GetBool(S, L"ZeroLimitGuard",   true);
    g_countFirst  = Config::GetBool(S, L"ScrollCountFirst", true);
    const bool doWeight = Config::GetBool(S, L"HelperWeight",     true);
    const bool doSync   = Config::GetBool(S, L"SyncErrorLog",     true);
    g_lockOn      = Config::GetBool(S, L"InFlightLock",     true);
    const bool doCol57  = Config::GetBool(S, L"SowelColumn57",    true);
    const bool doOptIdx = Config::GetBool(S, L"OptionIndexBounds", true);
    int timeout = Config::GetInt(S, L"LockTimeoutMs", 15000);
    if (timeout < 1000)   { timeout = 1000; }
    if (timeout > 120000) { timeout = 120000; }
    g_lockTimeout = (DWORD)timeout;

    const bool doPreRoll = g_zeroLimit || g_countFirst;
    if (!g_soulPossess && !doCodes && !doGrade && !doPreRoll && !doWeight && !doSync && !g_lockOn && !doCol57 && !doOptIdx)
    {
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ площадок до первой записи: патч ставится целиком или никак ──
    BYTE codeOrig[ARRAYSIZE(kCodes)][7];
    Site sites[18 + ARRAYSIZE(kCodes)];
    int  n = 0;
    sites[n++] = { 0x004FC97B, kPre6500,  sizeof(kPre6500)  };
    sites[n++] = { 0x004FDB35, kPre6502,  sizeof(kPre6502)  };
    sites[n++] = { 0x004FF05D, kPre6504,  sizeof(kPre6504)  };
    sites[n++] = { 0x005010EB, kPre6506,  sizeof(kPre6506)  };
    sites[n++] = { 0x004FF062, kDup6504,  sizeof(kDup6504)  };
    sites[n++] = { 0x00432CE5, kDispDb,   sizeof(kDispDb)   };
    sites[n++] = { 0x005007BB, kSend2304, sizeof(kSend2304) };
    sites[n++] = { 0x004FFD44, kPreRoll,  sizeof(kPreRoll)  };
    sites[n++] = { 0x005008CF, kSyncErr,  sizeof(kSyncErr)  };
    sites[n++] = { 0x00500DF2, kWeight,   sizeof(kWeight)   };
    sites[n++] = { 0x004A1635, kCol57,    sizeof(kCol57)    };
    sites[n++] = { 0x004FFB98, kGrade,    sizeof(kGrade)    };
    sites[n++] = { 0x00500262, kOptIdx,   sizeof(kOptIdx)   };
    sites[n++] = { 0x00535E01, kBlessIdx, sizeof(kBlessIdx) };
    for (int i = 0; i < ARRAYSIZE(kCodes); ++i)
    {
        const BYTE o[7] = { 0xC6, 0x85, kCodes[i].disp, 0xFF, 0xFF, 0xFF, 0x00 };
        memcpy(codeOrig[i], o, 7);
        sites[n++] = { kCodes[i].va, codeOrig[i], 7 };
    }
    if (!VerifyAllSites(L"P33", sites, n)) { return PatchResult::Mismatch; }

    bool ok = true;

    // Д-1
    if (g_soulPossess)
    {
        ok &= Hook::WriteCall(0x004FC97B, (const void*)&P33_PreambleGate, 5);
        ok &= Hook::WriteCall(0x004FDB35, (const void*)&P33_PreambleGate, 5);
        ok &= Hook::WriteCall(0x004FF05D, (const void*)&P33_PreambleGate, 5);
        ok &= Hook::WriteCall(0x005010EB, (const void*)&P33_PreambleGate, 5);
        Log::Line(L"    P33/Д-1: гейт «душа» (0x52EEA0) + «одержим» (0x52EE40) у 6500/6502/6504/6506 — "
                  L"4 площадки `call sub_52BFF0` -> 0x%08X", (DWORD)&P33_PreambleGate);
    }

    // Д-2/Д-3
    if (doCodes)
    {
        int c = 0;
        for (int i = 0; i < ARRAYSIZE(kCodes); ++i)
        {
            if (WriteOneByte(kCodes[i].va + 6, 0x00, kCodes[i].newCode)) { ++c; } else { ok = false; }
        }
        Log::Line(L"    P33/Д-2: отказов кодом 0 переведено %d из %d (обработчик 14, приём ответа БД 5): "
                  L"код 5 «Улучшение не удалось», 2 «превышено максимальное количество»", c, (int)ARRAYSIZE(kCodes));
    }

    // N-7
    if (doGrade)
    {
        ok &= WriteOneByte(0x004FFB98 + 6, 0x03, 0x06);
        Log::Line(L"    P33/N-7: «грейд свитка не тот» (лог (2)) — код 3 -> 6 (loc 50010 «Неподходящий уровень»)");
    }

    // N-14 + Д-7
    if (doPreRoll)
    {
        ok &= Hook::WriteJmp(0x004FFD44, (const void*)&PreRollTrampoline, sizeof(kPreRoll));
        Log::Line(L"    P33/N-14+Д-7: проверки ДО броска @0x004FFD44 -> 0x%08X (предел<=0: %s; свитков мало: %s)",
                  (DWORD)&PreRollTrampoline, g_zeroLimit ? L"отказ 7" : L"выкл", g_countFirst ? L"отказ 3" : L"выкл");
    }

    // N-1
    if (doWeight)
    {
        if (Hook::WriteBytes(0x00500DF2, kWeightNew, sizeof(kWeightNew)))
        {
            Log::Line(L"    P33/N-1: в SetCurrentWeightValue уходит сумма весов свитка и помощников 97/98 "
                      L"([ebp-0xF4]), а не только вес свитка");
        }
        else { ok = false; }
    }

    // Д-4
    if (doSync)
    {
        ok &= Hook::WriteJmp(0x005008CF, (const void*)&SyncErrorTrampoline, sizeof(kSyncErr));
        Log::Line(L"    P33/Д-4: строка «UserIndex Sync Error» дополнена слотом и обоими UserIndex; "
                  L"ответ клиенту в этой ветке НЕ шлётся (слот чужой)");
    }

    // N-2
    if (g_lockOn)
    {
        InitializeCriticalSection(&g_lockCs);
        g_lockCsInit = true;
        ok &= Hook::WriteJmp (0x004FF062, (const void*)&DupCheckTrampoline, sizeof(kDup6504));
        ok &= Hook::WriteCall(0x005007BB, (const void*)&Stub2304,       5);
        ok &= Hook::WriteCall(0x00432CE5, (const void*)&P33_WrapRecvDb, 5);
        Log::Line(L"    P33/N-2: замок «одна попытка в полёте» (тайм-аут %u мс): ранний отказ @0x004FF062 (после подписи), "
                  L"отправка 2304 @0x005007BB, приём 2305 @0x00432CE5", g_lockTimeout);
    }

    // Д-5
    if (doCol57)
    {
        ok &= WriteOneByte(0x004A1635 + 4, 0xA6, 0xA8);
        Log::Line(L"    P33/Д-5: колонка 57 SowelCombine.txt -> поле +0xA8 (было поверх колонки 56 в +0xA6)");
    }

    // Н-15
    if (doOptIdx)
    {
        ok &= Hook::WriteJmp(0x00500262, (const void*)&OptionIndexTrampoline,      sizeof(kOptIdx));
        ok &= Hook::WriteJmp(0x00535E01, (const void*)&BlessOptionIndexTrampoline, sizeof(kBlessIdx));
        Log::Line(L"    P33/Н-15: индекс OptionUpgrade проверяется по границам [0, *0x7DFFD0): "
                  L"заточка 6504 @0x00500262 -> 0x%08X, благословение 6551 @0x00535E01 -> 0x%08X",
                  (DWORD)&OptionIndexTrampoline, (DWORD)&BlessOptionIndexTrampoline);
    }

    return ok ? PatchResult::Applied : PatchResult::Failed;
}
