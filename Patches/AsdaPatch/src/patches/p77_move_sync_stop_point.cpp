// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P77 — ★ ТОЧКА МОЛЧАЛИВОЙ ОСТАНОВКИ ХОДА → КЛИЕНТУ (4009 со своей точкой)
//  (решение владельца 22.10.2026; разбор `Reports/wasd_2026-10-22/REPORT.md` §4 и `REVIEW.md` §5, отчёт волны
//  `Reports/p77_move_sync_point/REPORT.md`). [ПОРТ/СЕРВЕР-ДОРАБОТКА] Документ: `AstoryServer/Docs/GameServer/move-sync-stop-point-p77.md`.
//
//  ── ДЕФЕКТ СТОКА ──
//  MoveSyncProcess@0x5427D0 (нить карты, раз в ≥100 мс, RunProcess sub_4C0EA0) интегрирует позицию идущего игрока:
//  new = cur + dt·скорость·направление. Если следующая точка вне карты или на непроходимой клетке, сток зовёт
//  Return_UserMoveStack (sub_542520: снимает игрока со стека хода, DWORD CUser+0x33 := 0) — и ВСЁ: позиция
//  CUser+0x54EE/+0x54F2 остаётся последней пройденной, клиенту НИЧЕГО не уходит. Клиент (свой грант 4007, либо
//  серверный ход «Паники» ProcessState_SKILL_STATE_FEAR@0x488040 на 2000 ед.) идёт дальше. Следующий 4006 попадает
//  в ветку «стоит» CharMove@0x544EB0 (0x5453F1: ТОЧНОЕ равенство cur клиента и сервера) → «CharMove Hack Position»,
//  4007 result=5 и снап (за 21.10 — 82 строки у пяти игроков).
//  Молчаливых остановок «игрок ещё идёт у клиента» в MoveSyncProcess четыре (все — `call 0x542520`, затем jmp 0x542F4F):
//     S1 0x00542968  «MoveSyncProcess() iMotionStartTime = 0»  (CUser+0x5502 == 0 при состоянии хода 2/4/6/8)
//     S2 0x00542ACB  «MoveSyncProcess() iMovePos - Value2»      (клетка новой точки ≤ 0)
//     S3 0x00542B11  «iMovePos Max Over»                        (клетка за краем карты: > map+8 / map+0xA)
//     S4 0x00542B49  «don't move tile»                          (sub_41A010: бит 1 атрибута клетки — непроходима)
//  НЕ закрываются (обоснование — документ §2): 0x542D6E «Portal Move» (портал ведёт свой поток пакетов),
//  0x542F16 «Move End» (отрезок нулевой длины — клиент уже в точке), 0x542F77 «UserIndex == -1» (сессия не в игре),
//  0x5429C7 «iDistanceTime …» (переходов на 0x5429BA в .text нет — ссылок в срезе нет; verify_p77).
//
//  ── ЧТО ДЕЛАЕТ ──
//  Каждая из S1…S4 `call 0x542520` заменена на свой вход P77 (соглашение то же: thiscall ecx = CUserMoveManager,
//  [esp+4] = userNum (слово), [esp+8] = строка причины; снимает 8 б). Вход зовёт сток 0x542520 и, если игрок
//  ДЕЙСТВИТЕЛЬНО снят со стека (CUser+0x33: было ≠ 0, стало 0 — иначе ничего не шлём: повтор на каждом шаге исключён),
//  шлёт ШТАТНЫЙ 4009 в серверную точку той же формой, что CharStop «Revision Pos» (0x546030…0x546172):
//     тело 27 б: [0] 0, [1] userNum, [3] 0 (MOVE_STATUSIDLE), [5]/[9] cur X/Z, [13]/[17] = cur X/Z,
//                [21] скорость сервера CUser+0x54FE, [25] −1 (нет цели);
//     себе    — SendPacket@0x4C28F0(нить, 4009, 27, userNum, тело, userNum, 1);
//     сектору — sub_52E6D0(CUserManager, userNum, 4009, 27, тело, 1) (кроме себя; скрытому оператору — нет, как P74).
//  Клиент оригинала на свой 4009 снапит позицию и цель в точку (`Recv_EntityStop@0xF3AB50`, network.c:39457),
//  порт — `UAsdaWorldSubsystem::OnNetEntityMove` → `NetSnap(cur)`; чужой — стоп + снап при другой клетке. Новых
//  опкодов, полей, кодов нет. Следующий 4006 клиента идёт из точки сервера → ветка «стоит» проходит точным равенством.
//  Частота: не больше одного 4009 на каждое снятие со стека; на стек игрока возвращает только CharMove (4006 / ход
//  «Паники»), т.е. 4009 не чаще принятых 4006. MinIntervalMs (умолч. 0) — дополнительный пол на сессию.
//  Нить: MoveSyncProcess и CharMove/CharStop идут в ОДНОЙ нити карты (RunProcess: ConnectSocketMsgProcess → … →
//  MoveSyncProcess) — отправка из той же нити, что у стока (SendPack_CharPositionToBattleServer тоже шлёт отсюда).
//  Журнал: PatchLog — не чаще 1 строки за LogIntervalSec на сессию (с числом пропущенных); счётчики P77_GetStats.
//  Смещения CUser (дизасм стока, живой e7b4ac38 = сток по MoveSyncProcess): 0x2E «в игре» (=1), 0x33 флаг стека хода,
//  0x174 UserIndex, 0x178 имя, 0x54E4 состояние хода, 0x54E6/0x54E8 клетка, 0x54EE/0x54F2 текущая X/Z, 0x54FE скорость.
//  Нить: CUserMoveManager+4; нить+0x34 — CUserManager (sub_542520 0x542572: [edx+4] → [eax+0x34]).
//  Площадки и соседи сверяются на трёх образах (tools/verify_p77.py); других патчей в 0x5427D0…0x542F90 нет
//  (P57 лишь СВЕРЯЕТ байты 0x542F34/0x542F49 — не пересекаются).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>
#include <float.h>
#include <string.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P77_MoveSyncStopPoint";

    constexpr short kOp4009      = 4009;
    constexpr short kBodyLen     = 27;
    constexpr int   kMaxUser     = 0x226;     // 550 слотов
    constexpr int   kOffThread   = 0x04;      // CUserMoveManager+4 → нить карты
    constexpr int   kOffUserMgr  = 0x34;      // нить+0x34 → CUserManager
    constexpr int   kOffInGame   = 0x2E;      // DWORD 1 = в игре (MoveSyncProcess 0x542905)
    constexpr int   kOffMoveFlag = 0x33;      // DWORD флаг стека хода (sub_542520 0x542597, SetEmpty 0x542300)
    constexpr int   kOffUserIdx  = 0x174;     // UserIndex (MoveSyncProcess 0x5428F5)
    constexpr int   kOffName     = 0x178;     // имя персонажа
    constexpr int   kOffTileX    = 0x54E6;
    constexpr int   kOffTileZ    = 0x54E8;
    constexpr int   kOffCurX     = 0x54EE;
    constexpr int   kOffCurZ     = 0x54F2;
    constexpr int   kOffSpeed    = 0x54FE;
    constexpr int   kOffHide     = 0x3BC3B;   // word 300 = скрытый оператор (как P41/P74)
    constexpr short kHidden      = 300;

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef char  (__thiscall *FnStackRemove)(void* moveMgr, short userNum, const char* reason);                // 0x542520 (ret 8)
    typedef BYTE* (__thiscall *FnGetUser)(void* userMgr, short idx);                                            // 0x5324A0
    typedef BOOL  (__thiscall *FnIsOpIdx)(void* userMgr, short idx, int a3);                                    // 0x52ECF0
    typedef int   (__thiscall *FnSendPacket)(void* net, short op, short len, short to, void* body, short from, int a7);   // 0x4C28F0 (ret 18h)
    typedef int   (__thiscall *FnSendOther)(void* userMgr, short num, short op, short len, void* body, int pad);         // 0x52E6D0 (ret 14h)
    const FnStackRemove StackRemove = (FnStackRemove)0x00542520;
    const FnGetUser     GetUser     = (FnGetUser)Srv::kGetUser;
    const FnIsOpIdx     IsOpIdx     = (FnIsOpIdx)Srv::kIsOperatorIndex;
    const FnSendPacket  SendPacket  = (FnSendPacket)Srv::kSendPacket;
    const FnSendOther   SendOther   = (FnSendOther)0x0052E6D0;

    // ── настройки ───────────────────────────────────────────────────────────
    bool  g_site[5]       = { false, true, true, true, true };   // [1..4] = S1..S4
    bool  g_toSector      = true;
    bool  g_skipHidden    = true;
    DWORD g_minIntervalMs = 0;
    bool  g_logEvents     = true;
    DWORD g_logIntervalMs = 10000;

    // ── сессии (номер слота; UserIndex различает смену владельца слота) ──────
    struct Sess { int userIndex; DWORD lastSend; DWORD lastLog; LONG suppressedLog; };
    Sess g_sess[kMaxUser] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    P77_Stats g_stats = {};

    const wchar_t* SiteName(int site)
    {
        switch (site)
        {
        case 1: return L"iMotionStartTime = 0";
        case 2: return L"iMovePos - Value2";
        case 3: return L"iMovePos Max Over";
        case 4: return L"don't move tile";
        default: return L"?";
        }
    }

    bool IsHiddenOperator(void* userMgr, const BYTE* user, short num)
    {
        __try
        {
            if (*(const short*)(user + kOffHide) != kHidden) { return false; }
            return IsOpIdx(userMgr, num, -1) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // Точка годится в пакет: конечная, положительная (сток так проверяет 4008: [5]/[9] > 0, 0x545E26…).
    bool PointOk(float x, float z) { return _finite(x) && _finite(z) && x > 0.f && z > 0.f; }

    // Общая часть: сток уже снял игрока со стека (или нет). moveFlagBefore — CUser+0x33 до вызова стока.
    void AfterStop(int site, void* moveMgr, short num, BYTE* user, DWORD moveFlagBefore)
    {
        InterlockedIncrement(&g_stats.seen[site]);
        if (!user) { InterlockedIncrement(&g_stats.skipNoUser); return; }
        void* net = nullptr; void* userMgr = nullptr;
        float x = 0.f, z = 0.f, speed = 0.f;
        int userIndex = -1, tileX = 0, tileZ = 0;
        char name[24] = "";
        DWORD moveFlagAfter = 1, inGame = 0;
        __try
        {
            net     = *(void**)((BYTE*)moveMgr + kOffThread);
            userMgr = net ? *(void**)((BYTE*)net + kOffUserMgr) : nullptr;
            moveFlagAfter = *(const DWORD*)(user + kOffMoveFlag);
            inGame    = *(const DWORD*)(user + kOffInGame);
            userIndex = *(const int*)(user + kOffUserIdx);
            x = *(const float*)(user + kOffCurX);
            z = *(const float*)(user + kOffCurZ);
            speed = *(const float*)(user + kOffSpeed);
            tileX = *(const short*)(user + kOffTileX);
            tileZ = *(const short*)(user + kOffTileZ);
            memcpy(name, user + kOffName, sizeof(name) - 1);
            name[sizeof(name) - 1] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return; }
        // Повтора нет: шлём только при ПЕРЕХОДЕ «в стеке хода → снят» (сток мог не снять: исключения Error 1…4).
        if (moveFlagBefore == 0 || moveFlagAfter != 0) { InterlockedIncrement(&g_stats.skipNotRemoved); return; }
        if (inGame != 1 || userIndex < 0 || !net || !userMgr) { InterlockedIncrement(&g_stats.skipNotInGame); return; }
        if (!PointOk(x, z)) { InterlockedIncrement(&g_stats.skipBadPoint); return; }
        if (!(speed > 0.f && speed < 5.f) || !_finite(speed)) { speed = 0.f; }   // клиент порта кэширует [21] только в (0; 5)

        const DWORD now = GetTickCount();
        bool send = true, doLog = false;
        LONG sup = 0;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[num];
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        if (g_minIntervalMs && s.lastSend && now - s.lastSend < g_minIntervalMs) { send = false; }
        else { s.lastSend = now ? now : 1; }
        if (send && g_logEvents)
        {
            if (!s.lastLog || now - s.lastLog >= g_logIntervalMs) { doLog = true; s.lastLog = now ? now : 1; sup = s.suppressedLog; s.suppressedLog = 0; }
            else { ++s.suppressedLog; }
        }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        if (!send) { InterlockedIncrement(&g_stats.skipInterval); return; }

        // Тело — как CharStop «Revision Pos» (0x546030…0x546076): cur = dst = точка сервера, подтип 0, номер.
        BYTE body[kBodyLen];
        memset(body, 0, sizeof(body));
        body[0] = 0;
        *(short*)(body + 1)  = num;
        *(short*)(body + 3)  = 0;
        *(float*)(body + 5)  = x;
        *(float*)(body + 9)  = z;
        *(float*)(body + 13) = x;
        *(float*)(body + 17) = z;
        *(float*)(body + 21) = speed;
        *(short*)(body + 25) = -1;

        __try { SendPacket(net, kOp4009, kBodyLen, num, body, num, 1); }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return; }
        InterlockedIncrement(&g_stats.sentSelf[site]);
        bool sector = false;
        if (g_toSector)
        {
            if (g_skipHidden && IsHiddenOperator(userMgr, user, num)) { InterlockedIncrement(&g_stats.skipHidden); }
            else
            {
                __try { SendOther(userMgr, num, kOp4009, kBodyLen, body, 1); sector = true; }
                __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
                if (sector) { InterlockedIncrement(&g_stats.sentSector); }
            }
        }
        if (doLog)
        {
            wchar_t wname[24] = L"";
            MultiByteToWideChar(1251, 0, name, -1, wname, ARRAYSIZE(wname));
            Log::Line(L"[P77] «%s»: %s (UserNum %d, UserIndex %d) остановлен сервером в (%.1f, %.1f), клетка %d,%d — 4009 себе%s; "
                      L"по этой сессии с прошлой строки без журнала: %ld",
                      SiteName(site), wname, (int)num, userIndex, (double)x, (double)z, tileX, tileZ,
                      sector ? L" и сектору" : L"", sup);
        }
    }

    // Вход вместо `call 0x542520` на площадке site. __fastcall + 2 аргумента в стеке = thiscall стока (ret 8).
    void Enter(int site, void* moveMgr, int userNumArg, const char* reason)
    {
        const short num = (short)userNumArg;
        BYTE* user = nullptr;
        DWORD before = 0;
        if (num >= 0 && num < kMaxUser)
        {
            __try
            {
                void* net = *(void**)((BYTE*)moveMgr + kOffThread);
                void* userMgr = net ? *(void**)((BYTE*)net + kOffUserMgr) : nullptr;
                user = userMgr ? GetUser(userMgr, num) : nullptr;
                before = user ? *(const DWORD*)(user + kOffMoveFlag) : 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { user = nullptr; before = 0; }
        }
        StackRemove(moveMgr, num, reason);                   // сток: снятие со стека хода + его же журнал ошибок
        if (!g_site[site]) { return; }
        if (num < 0 || num >= kMaxUser) { InterlockedIncrement(&g_stats.skipNoUser); return; }
        AfterStop(site, moveMgr, num, user, before);
    }

    void __fastcall St_S1(void* self, void*, int num, const char* reason) { Enter(1, self, num, reason); }
    void __fastcall St_S2(void* self, void*, int num, const char* reason) { Enter(2, self, num, reason); }
    void __fastcall St_S3(void* self, void*, int num, const char* reason) { Enter(3, self, num, reason); }
    void __fastcall St_S4(void* self, void*, int num, const char* reason) { Enter(4, self, num, reason); }

    // ── площадки (`E8 rel32` → 0x542520) и соседи ────────────────────────────
    const BYTE kOrigS1[5] = { 0xE8, 0xB3, 0xFB, 0xFF, 0xFF };   // 0x542968
    const BYTE kOrigS2[5] = { 0xE8, 0x50, 0xFA, 0xFF, 0xFF };   // 0x542ACB
    const BYTE kOrigS3[5] = { 0xE8, 0x0A, 0xFA, 0xFF, 0xFF };   // 0x542B11
    const BYTE kOrigS4[5] = { 0xE8, 0xD2, 0xF9, 0xFF, 0xFF };   // 0x542B49
    // перед вызовом: push строки; mov r16,[ebp-40h]; push r32; mov ecx,[ebp-5Ch]
    const BYTE kPreS1[13] = { 0x68, 0x14, 0xC8, 0x59, 0x00, 0x66, 0x8B, 0x4D, 0xC0, 0x51, 0x8B, 0x4D, 0xA4 };
    const BYTE kPreS2[13] = { 0x68, 0x9C, 0xC7, 0x59, 0x00, 0x66, 0x8B, 0x45, 0xC0, 0x50, 0x8B, 0x4D, 0xA4 };
    const BYTE kPreS3[13] = { 0x68, 0x88, 0xC7, 0x59, 0x00, 0x66, 0x8B, 0x4D, 0xC0, 0x51, 0x8B, 0x4D, 0xA4 };
    const BYTE kPreS4[13] = { 0x68, 0x78, 0xC7, 0x59, 0x00, 0x66, 0x8B, 0x45, 0xC0, 0x50, 0x8B, 0x4D, 0xA4 };
    // после вызова: jmp 0x542F4F (rel32)
    const BYTE kPostS1[5] = { 0xE9, 0xDD, 0x05, 0x00, 0x00 };   // 0x54296D
    const BYTE kPostS2[5] = { 0xE9, 0x7A, 0x04, 0x00, 0x00 };   // 0x542AD0
    const BYTE kPostS3[5] = { 0xE9, 0x34, 0x04, 0x00, 0x00 };   // 0x542B16
    const BYTE kPostS4[5] = { 0xE9, 0xFC, 0x03, 0x00, 0x00 };   // 0x542B4E
    // sub_542520: пролог и чтение флага стека хода CUser+0x33; выход ret 8
    const BYTE kRemoveHead[6] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x1C };                   // 0x542520 push ebp; mov ebp,esp; sub esp,41Ch
    const BYTE kRemoveFlag[4] = { 0x83, 0x79, 0x33, 0x00 };                               // 0x542597 cmp dword [ecx+33h],0
    const BYTE kRemoveMgr[9]  = { 0x8B, 0x42, 0x04, 0x8B, 0x48, 0x34, 0xE8, 0x23, 0xFF }; // 0x542572 mov eax,[edx+4]; mov ecx,[eax+34h]; call 0x5324A0
    // MoveSyncProcess: «в игре» и UserIndex до ветки хода
    const BYTE kMspGate[20]   = { 0x83, 0xBA, 0x74, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x8C, 0x68, 0x06, 0x00, 0x00,   // 0x5428F5 cmp [edx+174h],0; jl
                                  0x8B, 0x45, 0xE8, 0x83, 0x78, 0x2E, 0x01 };                                   //          mov eax,[ebp-18h]; cmp [eax+2Eh],1
}

extern "C" __declspec(dllexport) void __stdcall P77_GetStats(P77_Stats* out)
{
    if (out) { *out = g_stats; }
}

PatchResult P77_MoveSyncStopPoint()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_site[1]   = Config::GetBool(kSec, L"MotionStartZero", true);
    g_site[2]   = Config::GetBool(kSec, L"PosBelowMap", true);
    g_site[3]   = Config::GetBool(kSec, L"PosOverMap", true);
    g_site[4]   = Config::GetBool(kSec, L"BlockedTile", true);
    g_toSector  = Config::GetBool(kSec, L"SendToSector", true);
    g_skipHidden = Config::GetBool(kSec, L"SkipHiddenOperators", true);
    int minMs   = Config::GetInt (kSec, L"MinIntervalMs", 0);
    g_logEvents = Config::GetBool(kSec, L"LogEvents", true);
    int logSec  = Config::GetInt (kSec, L"LogIntervalSec", 10);
    if (minMs < 0 || minMs > 60000) { Log::Line(L"    P77: MinIntervalMs=%d вне 0..60000 — взято 0", minMs); minMs = 0; }
    if (logSec < 0 || logSec > 3600) { Log::Line(L"    P77: LogIntervalSec=%d вне 0..3600 — взято 10", logSec); logSec = 10; }
    g_minIntervalMs = (DWORD)minMs;
    g_logIntervalMs = (DWORD)logSec * 1000;
    if (!g_site[1] && !g_site[2] && !g_site[3] && !g_site[4])
    {
        Log::Line(L"    P77: все четыре ветки выключены ключами — ставить нечего");
        return PatchResult::Disabled;
    }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    memset(&g_stats, 0, sizeof(g_stats));

    const Site sites[] =
    {
        { 0x00542968, kOrigS1, sizeof(kOrigS1) },
        { 0x00542ACB, kOrigS2, sizeof(kOrigS2) },
        { 0x00542B11, kOrigS3, sizeof(kOrigS3) },
        { 0x00542B49, kOrigS4, sizeof(kOrigS4) },
        { 0x0054295B, kPreS1,  sizeof(kPreS1) },
        { 0x00542ABE, kPreS2,  sizeof(kPreS2) },
        { 0x00542B04, kPreS3,  sizeof(kPreS3) },
        { 0x00542B3C, kPreS4,  sizeof(kPreS4) },
        { 0x0054296D, kPostS1, sizeof(kPostS1) },
        { 0x00542AD0, kPostS2, sizeof(kPostS2) },
        { 0x00542B16, kPostS3, sizeof(kPostS3) },
        { 0x00542B4E, kPostS4, sizeof(kPostS4) },
        { 0x00542520, kRemoveHead, sizeof(kRemoveHead) },
        { 0x00542597, kRemoveFlag, sizeof(kRemoveFlag) },
        { 0x00542572, kRemoveMgr,  sizeof(kRemoveMgr)  },
        { 0x005428F5, kMspGate,    sizeof(kMspGate)    },
    };
    if (!VerifyAllSites(L"P77", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    struct W { int site; DWORD va; void* fn; };
    const W w[] =
    {
        { 1, 0x00542968, (void*)&St_S1 },
        { 2, 0x00542ACB, (void*)&St_S2 },
        { 3, 0x00542B11, (void*)&St_S3 },
        { 4, 0x00542B49, (void*)&St_S4 },
    };
    int written = 0;
    for (const W& e : w)
    {
        if (!g_site[e.site]) { continue; }
        if (!Hook::WriteCall(e.va, e.fn, 5)) { return PatchResult::Failed; }
        ++written;
        Log::Line(L"    P77 S%d «%s» @0x%08X `call 0x542520` -> 0x%08X: сток + 4009 в точку сервера",
                  e.site, SiteName(e.site), e.va, (DWORD)e.fn);
    }
    Log::Line(L"    P77: площадок %d; 4009 себе (SendPacket 0x4C28F0) %s; скрытому оператору сектору %s; пол на сессию %u мс (0 — нет); "
              L"журнал %s, не чаще 1 строки за %d с на сессию",
              written, g_toSector ? L"и сектору кроме себя (sub_52E6D0)" : L"без сектора",
              g_skipHidden ? L"НЕ шлётся" : L"шлётся", g_minIntervalMs, g_logEvents ? L"вкл" : L"выкл", logSec);
    return PatchResult::Applied;
}
