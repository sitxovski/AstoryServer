// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P94 — [ИСПРАВЛЕНИЕ] СООБЩЕНИЯ ДРУГА (СОУЛМЕЙТА) НЕ УХОДЯТ САМОМУ СЕБЕ И ЧУЖОЙ ПАРЕ (2026-10-26, волна charpos).
//  Документ: AstoryServer/Docs/GameServer/soulmate-self-echo-p94.md. Отчёт: Reports/soulmate_self_echo/SERVER_FIX.md.
//
//  ── ДЕФЕКТ ──
//  Номер слота Друга (CUser+0x182CA) и «Друг в игре» (+0x182CC) сервер берёт при входе из DB UPCharSoulMate — из строки
//  dbo.CharPos Друга с Usernum <> −1. Строка устаревает (портальный выход UPPortalLogOut без входа на новую карту, рестарт
//  стойки без выхода игроков — RelayServer зовёт UpGameServerStart только при разрыве GS), и сервер считает Друга «в игре»
//  на чужом слоте. Сообщения пары 3309/3311/3313/3319 уходят через RelayServer на этот слот, получатель (обработчики ниже)
//  НЕ сверяет, кто ему пишет: слот совпал с самим отправителем — игрок получает «Друг вошёл» о СЕБЕ и записывает себя Другом;
//  слот занят посторонним — посторонний получает чужого Друга. Живой случай 26.10 22:19–22:34: Player17 в одержимости
//  персонажем Player52 (userNum 0) — строка своего персонажа 75214/10 висит с Usernum 0 State 1 → 5110/5220 о себе.
//
//  ── ЧТО ДЕЛАЕТ P94 (4 площадки, трамплины; протокол не меняется) ──
//  Каждая площадка стоит ПОСЛЕ стоковых проверок обработчика и ДО отправки клиенту. Решение P94_Decide(площадка, ebp):
//    «себе» (вид 130): отправитель = получатель — тот же слот (userNum отправителя @+4 = слот получателя), та же карта
//        (байт @+6 = CUserManager+0x8E9 получателя, sub_40C960) и тот же канал (@+7, у 3313 @+9 = 0x5F5EB4, sub_4A7EB0);
//        у 3313 ещё и по учётке персонажа: @+12 (sub_5324F0 отправителя) = CUser+0x174 получателя;
//    «чужая пара» (вид 131, ключ ForeignCheck): у получателя есть пара (CUser+0x182B9 Smidx > 0) и она не та, что в пакете
//        (@+0, Smidx отправителя; у пары Smidx общий — Joy1.dbo.SoulMate). Smidx ≤ 0 у получателя (пара ещё создаётся) —
//        пропускается, как в стоке. 3311→5227 сверяет Smidx сам (сток 0x494A21) — там только «себе».
//  Mode=1 — пакет не уходит (переход на эпилог обработчика, как стоковый отказ); Mode=0 — только журнал (поведение стока).
//    S1 recv_1 (Recv_SoulMateLoginStateInfo, relay 3314 ← 3313) @0x494631 → клиенту 5110, запись Друга +0x182C6…+0x182D2,
//       5220 и ответ 3313 — всё пропускается;
//    S2 recvSoulMateStateInfo (relay 3310 ← 3309) @0x493D2B → 5112;
//    S3 sub_4949C0 (relay 3312 ← 3311) @0x494A2F → запись места Друга +0x182CA/+0x182CD…+0x182D0 и 5227;
//    S4 sub_494010 (relay 3320 ← 3319) @0x49407C → 5111.
//  Журнал ac.other 130/131 (132 — исключение, решение стока) и строка в стоковый лог канала LogChannel; не чаще
//  JournalIntervalSec на (слот получателя, площадка).
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
    const wchar_t* kSec = L"P94_SoulmateSelfEcho";

    constexpr BYTE kKindSelf    = 130;   // ac.other 130 — сообщение пары самому себе (реестр ac-journal-p53.md §9)
    constexpr BYTE kKindForeign = 131;   // ac.other 131 — сообщение чужой пары
    constexpr BYTE kKindFault   = 132;   // ac.other 132 — исключение, решение стока

    // ── CUser / CUserManager / глобалы (сток) ───────────────────────────────
    constexpr int   kOffUserIndex  = 0x174;     // учётка персонажа (sub_5324F0)
    constexpr int   kOffName       = 0x178;     // имя персонажа cp1251
    constexpr int   kOffSlot       = 0x18C;     // слот персонажа
    constexpr int   kOffSmidx      = 0x182B9;   // +99001 — Smidx пары (int)
    constexpr int   kMgrUsers      = 0x40;      // CUserManager + 0x40 + 4·n = CUser* (sub_5324A0)
    constexpr int   kMgrMap        = 0x8E9;     // CUserManager + 0x8E9 — карта потока (sub_40C960)
    constexpr DWORD kChannelByte   = 0x005F5EB4; // канал процесса (sub_4A7EB0)
    constexpr int   kMaxUsers      = 0x226;     // 550 слотов (sub_5328F0)

    // ── площадки: адрес, байты стока, продолжение, пропуск (эпилог) ─────────
    //   S1 recv_1 0x4945B0: mov edx,[ebp-214h]                        → 0x494637 / 0x494855
    const DWORD kS1 = 0x00494631; const BYTE kS1Orig[6] = { 0x8B, 0x95, 0xEC, 0xFD, 0xFF, 0xFF };
    DWORD g_s1Back = 0x00494637, g_s1Skip = 0x00494855;
    const BYTE kS1BackOrig[7] = { 0x0F, 0xB6, 0x82, 0xC5, 0x82, 0x01, 0x00 };   // movzx eax, byte [edx+182C5h]
    const BYTE kS1SkipOrig[6] = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD, 0xE8 };         // mov ecx,[ebp-4] ; xor ecx,ebp ; call cookie
    const DWORD kS1Copy = 0x004945DF; const BYTE kS1CopyOrig[5] = { 0x68, 0x06, 0x01, 0x00, 0x00 };   // push 106h (memcpy пакета)
    //   S2 recvSoulMateStateInfo 0x493CB0: push 0A8h                    → 0x493D30 / 0x493D71
    const DWORD kS2 = 0x00493D2B; const BYTE kS2Orig[5] = { 0x68, 0xA8, 0x00, 0x00, 0x00 };
    DWORD g_s2Back = 0x00493D30, g_s2Skip = 0x00493D71;
    const BYTE kS2BackOrig[6] = { 0x8D, 0x95, 0x58, 0xFF, 0xFF, 0xFF };         // lea edx,[ebp-0A8h]
    const BYTE kS2SkipOrig[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00 };         // mov esp,ebp ; pop ebp ; ret 4
    const DWORD kS2Copy = 0x00493CD5; const BYTE kS2CopyOrig[5] = { 0x68, 0xB8, 0x00, 0x00, 0x00 };   // push 0B8h
    //   S3 sub_4949C0: mov edx,[ebp-1Ch] ; mov ax,[ebp-10h]           → 0x494A36 / 0x494A98
    const DWORD kS3 = 0x00494A2F; const BYTE kS3Orig[7] = { 0x8B, 0x55, 0xE4, 0x66, 0x8B, 0x45, 0xF0 };
    DWORD g_s3Back = 0x00494A36, g_s3Skip = 0x00494A98;
    const BYTE kS3BackOrig[7] = { 0x66, 0x89, 0x82, 0xCA, 0x82, 0x01, 0x00 };   // mov [edx+182CAh], ax
    const BYTE kS3SkipOrig[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00 };
    const DWORD kS3Smidx = 0x00494A21; const BYTE kS3SmidxOrig[12] = { 0x8B, 0x45, 0xE4, 0x8B, 0x88, 0xB9, 0x82, 0x01, 0x00, 0x3B, 0x4D, 0xEC };
    //   S4 sub_494010: push 32h ; lea ecx,[ebp-37h]                    → 0x494081 / 0x4940B0
    const DWORD kS4 = 0x0049407C; const BYTE kS4Orig[5] = { 0x6A, 0x32, 0x8D, 0x4D, 0xC9 };
    DWORD g_s4Back = 0x00494081, g_s4Skip = 0x004940B0;
    const BYTE kS4BackOrig[4] = { 0x51, 0x8D, 0x55, 0x84 };                     // push ecx ; lea edx,[ebp-7Ch]
    const BYTE kS4SkipOrig[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00 };
    const DWORD kS4Copy = 0x0049402F; const BYTE kS4CopyOrig[2] = { 0x6A, 0x43 };   // push 43h

    // Разметка кадра каждой площадки: менеджер пары (this), пакет relay, CUser получателя (0 — искать по слоту).
    struct Frame { int offMgr; int offPkt; int offUser; int offTarget; int offChannel; int relayOp; int clientOp; const char* name; };
    const Frame kFrames[5] =
    {
        { 0, 0, 0, 0, 0, 0, 0, "?" },
        { -0x218, -0x110, -0x214, 16, 9, 3314, 5110, "login-state" },   // S1: цель @16, канал @9, учётка @12, флаг входа @23
        { -0x164, -0x0B8, 0,      10, 7, 3310, 5112, "state-info"  },   // S2: CUser ищется по цели
        { -0x024, -0x014, -0x01C, 10, 7, 3312, 5227, "move"        },   // S3: Smidx сверил сток
        { -0x084, -0x048, -0x080, 10, 7, 3320, 5111, "info"        },   // S4
    };

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;

    // ── настройки ────────────────────────────────────────────────────────────
    bool g_enabled = false;
    int  g_mode = 1;                 // 1 — не отправлять; 0 — только журнал (сток)
    bool g_foreign = true;           // сверка Smidx получателя (S1/S2/S4)
    int  g_journalIntervalSec = 10;
    int  g_logChannel = 0;

    P94_Stats g_stats = {};

    // Ограничитель журнала: не чаще g_journalIntervalSec на (слот получателя, площадка); сброс при смене учётки в слоте.
    struct Sess { int userIndex; DWORD jLast[5]; int jSup[5]; };
    Sess g_sess[kMaxUsers] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    // Строка журнала P53 и стокового лога. kind 130/131/132.
    void Report(BYTE kind, int site, const BYTE* user, int target, int senderNum, int senderUi, int pktSm, int userSm,
                int map, int ch, int flag)
    {
        int ui = -1;
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); } } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool write = true; int sup = 0;
        if (target >= 0 && target < kMaxUsers)
        {
            if (g_lockReady) { EnterCriticalSection(&g_lock); }
            Sess& s = g_sess[target];
            if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
            if (g_journalIntervalSec > 0 && s.jLast[site] && now - s.jLast[site] < (DWORD)g_journalIntervalSec * 1000)
            {
                ++s.jSup[site];
                write = false;
            }
            else { s.jLast[site] = now; sup = s.jSup[site]; s.jSup[site] = 0; }
            if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        }
        if (!write) { InterlockedIncrement(&g_stats.suppressed); return; }

        const Frame& f = kFrames[site];
        const char* what = kind == kKindSelf ? "self" : kind == kKindForeign ? "foreign" : "fault";
        const char* act  = kind == kKindFault ? "-> stock" : (g_mode ? "-> drop" : "(journal)");
        char detail[64];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE, "P94 %d %s from %d sm %d/%d m%d c%d %s", f.clientOp, what, senderNum, pktSm, userSm, map, ch, act);
        __try
        {
            SrvLog(g_logChannel, "P94 SoulmateSelfEcho: relay %d -> %d (%s) to UserNum %d %s UserIndex %d: %s (sender UserNum %d UserIndex %d, "
                   "Smidx pkt %d / own %d, map %d ch %d, flag %d) %s%s",
                   f.relayOp, f.clientOp, f.name, target, user ? (const char*)(user + kOffName) : "?", ui,
                   kind == kKindSelf ? "message to SELF" : kind == kKindForeign ? "message of ANOTHER pair" : "exception",
                   senderNum, senderUi, pktSm, userSm, map, ch, flag, act, sup ? " (suppressed before)" : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = f.clientOp;
        e.userNum = (short)target;
        e.ip = (target >= 0 && target < kMaxUsers) ? P47_PeerIpv4(target) : 0;
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
        e.v[0] = f.relayOp;                                   // item_code ← опкод relay (3314/3310/3312/3320)
        e.v[1] = senderNum;                                   // value1    ← слот отправителя из пакета
        e.v[2] = site == 1 ? senderUi : pktSm;                // value2    ← учётка отправителя (3313) / Smidx пакета
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }
}

// Решение площадки. ebp — кадр обработчика хоста. 1 — отправлять (сток), 0 — пропустить пакет.
extern "C" int __stdcall P94_Decide(int site, BYTE* ebp)
{
    if (!g_enabled || site < 1 || site > 4) { return 1; }
    InterlockedIncrement(&g_stats.checks[site]);
    const Frame& f = kFrames[site];
    BYTE* user = nullptr;
    int target = -1, senderNum = -1, senderUi = AcJournal::kNone, pktSm = 0, userSm = 0, map = -1, ch = -1, flag = -1;
    int kind = 0;
    __try
    {
        const BYTE* pkt = ebp + f.offPkt;
        BYTE* mgr = *(BYTE**)(ebp + f.offMgr);                      // CSoulMateManager (this обработчика)
        BYTE* userMng = *(BYTE**)(*(BYTE**)(mgr + 4) + 0x34);        // [[this+4]+34h] — CUserManager потока
        target    = *(const short*)(pkt + f.offTarget);
        senderNum = *(const short*)(pkt + 4);
        pktSm     = *(const int*)(pkt + 0);
        map       = pkt[6];
        ch        = pkt[f.offChannel];
        if (site == 1) { senderUi = *(const int*)(pkt + 12); flag = pkt[23]; }
        if (f.offUser) { user = *(BYTE**)(ebp + f.offUser); }
        else if (target >= 0 && target < kMaxUsers) { user = *(BYTE**)(userMng + kMgrUsers + 4 * target); }
        if (!user) { InterlockedIncrement(&g_stats.noUser); return 1; }
        userSm = *(const int*)(user + kOffSmidx);
        const int ownMap = userMng[kMgrMap];
        const int ownCh  = *(const BYTE*)kChannelByte;
        const bool sameSlot = senderNum == target && map == ownMap && ch == ownCh;
        const bool sameChar = site == 1 && senderUi == *(const int*)(user + kOffUserIndex);
        if (sameSlot || sameChar) { kind = kKindSelf; }
        else if (g_foreign && site != 3 && userSm > 0 && userSm != pktSm) { kind = kKindForeign; }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        Report(kKindFault, site, nullptr, target, senderNum, senderUi, pktSm, userSm, map, ch, flag);
        return 1;
    }
    if (!kind) { InterlockedIncrement(&g_stats.passed[site]); return 1; }
    InterlockedIncrement(kind == kKindSelf ? &g_stats.self[site] : &g_stats.foreign[site]);
    Report((BYTE)kind, site, user, target, senderNum, senderUi, pktSm, userSm, map, ch, flag);
    if (!g_mode) { InterlockedIncrement(&g_stats.wouldDrop); return 1; }
    InterlockedIncrement(&g_stats.dropped);
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P94_GetStats(P94_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Стабы. Вход jmp с площадки; регистры и флаги сохраняются целиком (pushfd/pushad), маршрут — в ZF между test и jz
    // (popad флагов не трогает). На продолжении выполняются замещённые инструкции стока.
    __declspec(naked) void St_S1()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  1
            call  P94_Decide
            test  eax, eax
            popad
            jz    Skip1
            popfd
            mov   edx, dword ptr [ebp-214h]         // замещённое
            jmp   dword ptr [g_s1Back]              // 0x494637
        Skip1:
            popfd
            xor   eax, eax                          // результат обработчика (как стоковый отказ «нет пользователя»)
            jmp   dword ptr [g_s1Skip]              // 0x494855 — эпилог recv_1
        }
    }
    __declspec(naked) void St_S2()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  2
            call  P94_Decide
            test  eax, eax
            popad
            jz    Skip2
            popfd
            push  0A8h                              // замещённое: размер memcpy 5112
            jmp   dword ptr [g_s2Back]              // 0x493D30
        Skip2:
            popfd
            xor   eax, eax
            jmp   dword ptr [g_s2Skip]              // 0x493D71 — эпилог
        }
    }
    __declspec(naked) void St_S3()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  3
            call  P94_Decide
            test  eax, eax
            popad
            jz    Skip3
            popfd
            mov   edx, dword ptr [ebp-1Ch]          // замещённое
            mov   ax, word ptr [ebp-10h]            // замещённое
            jmp   dword ptr [g_s3Back]              // 0x494A36
        Skip3:
            popfd
            xor   eax, eax
            jmp   dword ptr [g_s3Skip]              // 0x494A98 — эпилог
        }
    }
    __declspec(naked) void St_S4()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  4
            call  P94_Decide
            test  eax, eax
            popad
            jz    Skip4
            popfd
            push  32h                               // замещённое: размер memcpy 5111
            lea   ecx, [ebp-37h]                    // замещённое
            jmp   dword ptr [g_s4Back]              // 0x494081
        Skip4:
            popfd
            xor   eax, eax
            jmp   dword ptr [g_s4Skip]              // 0x4940B0 — эпилог
        }
    }
}

PatchResult P94_SoulmateSelfEcho()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_foreign = Config::GetBool(kSec, L"ForeignCheck", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 0);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 0; }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    const Site check[] =
    {
        { kS1, kS1Orig, sizeof(kS1Orig) }, { g_s1Back, kS1BackOrig, sizeof(kS1BackOrig) }, { g_s1Skip, kS1SkipOrig, sizeof(kS1SkipOrig) },
        { kS1Copy, kS1CopyOrig, sizeof(kS1CopyOrig) },
        { kS2, kS2Orig, sizeof(kS2Orig) }, { g_s2Back, kS2BackOrig, sizeof(kS2BackOrig) }, { g_s2Skip, kS2SkipOrig, sizeof(kS2SkipOrig) },
        { kS2Copy, kS2CopyOrig, sizeof(kS2CopyOrig) },
        { kS3, kS3Orig, sizeof(kS3Orig) }, { g_s3Back, kS3BackOrig, sizeof(kS3BackOrig) }, { g_s3Skip, kS3SkipOrig, sizeof(kS3SkipOrig) },
        { kS3Smidx, kS3SmidxOrig, sizeof(kS3SmidxOrig) },
        { kS4, kS4Orig, sizeof(kS4Orig) }, { g_s4Back, kS4BackOrig, sizeof(kS4BackOrig) }, { g_s4Skip, kS4SkipOrig, sizeof(kS4SkipOrig) },
        { kS4Copy, kS4CopyOrig, sizeof(kS4CopyOrig) },
    };
    if (!VerifyAllSites(L"P94", check, ARRAYSIZE(check))) { g_enabled = false; return PatchResult::Mismatch; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    // ── запись ──────────────────────────────────────────────────────────────
    if (!Hook::WriteJmp(kS1, (void*)&St_S1, sizeof(kS1Orig))) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kS2, (void*)&St_S2, sizeof(kS2Orig))) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kS3, (void*)&St_S3, sizeof(kS3Orig))) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kS4, (void*)&St_S4, sizeof(kS4Orig))) { return PatchResult::Failed; }
    Log::Line(L"    P94: сообщения пары через RelayServer сверяются с получателем: S1 3314→5110 @0x%08X, S2 3310→5112 @0x%08X, "
              L"S3 3312→5227 @0x%08X, S4 3320→5111 @0x%08X; «себе» (слот+карта+канал, у 5110 и учётка) — %s; чужая пара (Smidx) — %s; "
              L"журнал ac.other 130/131/132 не чаще 1 раза в %d с",
              kS1, kS2, kS3, kS4, g_mode ? L"не отправляется" : L"только журнал",
              g_foreign ? (g_mode ? L"не отправляется" : L"только журнал") : L"не сверяется", g_journalIntervalSec);
    return PatchResult::Applied;
}
