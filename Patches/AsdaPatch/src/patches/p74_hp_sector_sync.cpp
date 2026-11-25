// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P74 — HP ИГРОКА СОСЕДЯМ ПО СЕКТОРУ (синхронизация боя, фаза Ф3, 2026-10-17).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Проект: Reports/combat_sync_2026-10-17/03_DESIGN.md §6, ревизия 04_REVIEW.md п.8.
//  Документ: AstoryServer/Docs/GameServer/hp-sector-sync-p74.md
//
//  ── ДЕФЕКТ (сток) ──
//  Снимок HP игрока 4058 (17 б, раскладка ниже) сток шлёт ВСЕМУ сектору только для типов 2/4 (SetCurrentHpTimeValue
//  @0x43CE34: `a6 == 2 || a6 == 4` → sub_52E630). Остальное уходит ТОЛЬКО самому игроку (SendPacket 0x4C28F0):
//    • sub_43C690 при a5=1 — 22 вызова: навыки, урон по времени, отражение (НЕ обычные удары мобов и НЕ обычная атака PvP:
//      sub_426B00 @GameServer.c:17238 и sub_555800 @:131556 зовут его с a5=0 — 4058 не уходит даже себе, HP цели
//      клиент берёт из пакета удара; P74 их не касается);
//    • SetCurrentHpTimeValue, типы 0/1/3/5/6: естественный реген TimeSyncProcess раз в 5 тиков, лечение/урон по времени,
//      остаток зелья по времени, вампиризм; тип 1 — мгновенное лечение предметом (CharSpendItemUse 7 вызовов,
//      sub_4F3D90), тип 6 — восстановление 50 % в зоне (sub_46AB50).
//  Соседи HP чужого игрока не видят, пока не придёт тип 2/4 (лечение навыком/предметом через сектор, навык-эффект).
//  (SetCurrentRegenHpValue@0x43C8A0 из проекта пакетов не шлёт — это запись HP воскрешения; реген — ветка 0x43CE68.)
//
//  ── ТЕЛО 4058 (sub_448850 инициализирует: номер −1, нули, тип 0, навык −1) ──
//    +0  i16 userNum   +2 i32 maxHp   +6 i32 curHp   +10 u8 тип   +11 i16 навык   +13 i32 «второе» HP (cur + остаток зелья)
//  sub_43C690 пишет +0/+2/+6/+13, тип остаётся 0, навык −1. SetCurrentHpTimeValue пишет тип = a6, навык = a7.
//
//  ── ЧТО ДЕЛАЕТ P74 (ред. 2 от 17.10, Version 46) ──
//  Себе пакет уходит КАК В СТОКЕ (тот же вызов SendPacket с теми же аргументами); ПОСЛЕ него — пакет соседям
//  по 3×3 секторам, КРОМЕ себя: sub_52E6D0 → SendPacket_ClippingSectorInOtherUser@0x41EA80 (тот же фильтр получателей,
//  что у стоковой рассылки типов 2/4, заголовок «от» = 0, как у пакета себе; паддинг a7 = 1, как в стоке).
//  Площадки (обе — `call rel32` на SendPacket, 5 б, подмена цели на свою заглушку; переходов внутрь нет):
//    S1 0x0043C854  sub_43C690 (урон при a5=1)  — ключ DamageToSector
//    S2 0x0043CE82  SetCurrentHpTimeValue, ветка «не 2/4» (реген/лечение/яд, мгновенное лечение 1/6) — ключ RegenToSector
//  Гейты рассылки соседям:
//    • только опкод 4058 и тело того же игрока (+0 == кому);
//    • типы: клиент порта (AsdaNetSubsystem.cpp, case 4058) рисует цифру дельты над игроком для типов 1/4/6, для прочих —
//      тихая запись. Тихие типы S2 (маска TimeTypeMask, умолч. 0/3/5) и тип 0 S1 — соседям тот же пакет. ★ ред. 2: типы 1/6
//      (мгновенное лечение) — соседям КОПИЯ тела в локальном буфере 17 б с +10 = 0 и +11 = −1 (тихая запись без цифры;
//      себе — оригинал, как сток), ключ InstantToSector. Тип 4 (и 2) на S2 не приходит — сток шлёт сектору сам;
//    • скрытый оператор (CUser+0x3BC3B == 300 и IsOperatorIndex, как P41) — соседям не шлём ничего (ключ SkipHiddenOperators).
//      Утечка его HP через СТОКОВУЮ рассылку типов 2/4 (sub_52E630) — вне охвата P74;
//    • прореживание тихих типов на игрока: RegenMinIntervalMs (S2) / DamageMinIntervalMs (S1), ★ ред. 2: оба по умолчанию 0
//      (каждое событие). При >0 конечные значения (HP ≤ 0 и HP ≥ максимума) проходят всегда, но промежуточное значение,
//      выброшенное прореживанием, «хвостом» НЕ дошлётся (до следующего события). Типы 1/6 не прореживаются (разовые события).
//  Регистры: заглушка — обычная функция с соглашением SendPacket (thiscall, ret 18h), ebx/esi/edi/ebp сохраняются;
//  после вызова на обеих площадках eax/ecx/edx не читаются до перезаписи (0x43C859 / 0x43CE87: mov dx,[ebp+8]).
//  Соседей среди P01…P73 нет (P07 — 0x43C6DD, ранний выход до площадки S1; grep адресов по src/patches).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P74_HpSectorSync";

    constexpr short kOp4058     = 4058;
    constexpr short kBodyLen    = 17;
    constexpr int   kOffMgr     = 0x34;      // net(CThread)+0x34 → CUserManager (как 0x43CE5E: mov ecx,[ecx+34h])
    constexpr int   kOffHide    = 0x3BC3B;   // CUser: word 300 = скрытый оператор (Send_HideCommand 0x54EAAA, как P41)
    constexpr short kHidden     = 300;
    constexpr int   kMaxUser    = 0x226;     // 550 слотов (sub_5643E0: userNum < 0x226)
    constexpr DWORD kDigitTypes = (1u << 1) | (1u << 4) | (1u << 6);   // клиент рисует цифру дельты
    constexpr DWORD kInstantTypes = (1u << 1) | (1u << 6);             // ★ ред. 2: мгновенное лечение — соседям тихая копия
    constexpr DWORD kSectorTypes = (1u << 2) | (1u << 4);              // сток сам шлёт сектору (на S2 не приходят)

    // ── площадки ────────────────────────────────────────────────────────────
    const DWORD kSiteDmg       = 0x0043C854;
    const BYTE  kSiteDmgOrig[5] = { 0xE8, 0x97, 0x60, 0x08, 0x00 };    // call 0x4C28F0
    const DWORD kSiteTime      = 0x0043CE82;
    const BYTE  kSiteTimeOrig[5] = { 0xE8, 0x69, 0x5A, 0x08, 0x00 };   // call 0x4C28F0
    // соседи (только сверка)
    const BYTE  kDmgArgs[]  = { 0x6A, 0x01, 0x6A, 0x00, 0x8D, 0x55, 0xEC, 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50,  // push 1; push 0; lea edx,[ebp-14h]; push edx; mov ax,[ebp+8]; push eax
                                0x6A, 0x11, 0x68, 0xDA, 0x0F, 0x00, 0x00,                                      // push 11h; push 0FDAh
                                0x8B, 0x4D, 0xD8, 0x8B, 0x49, 0x04 };                                          // mov ecx,[ebp-28h]; mov ecx,[ecx+4]
    const BYTE  kDmgAfter[] = { 0x66, 0x8B, 0x55, 0x08 };                                                      // 0x43C859 mov dx,[ebp+8]
    const BYTE  kTimeArgs[] = { 0x6A, 0x01, 0x6A, 0x00, 0x8D, 0x55, 0xEC, 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50,
                                0x6A, 0x11, 0x68, 0xDA, 0x0F, 0x00, 0x00,
                                0x8B, 0x4D, 0xC0, 0x8B, 0x49, 0x04 };                                          // mov ecx,[ebp-40h]; mov ecx,[ecx+4]
    const BYTE  kTimeAfter[] = { 0x66, 0x8B, 0x55, 0x08 };                                                     // 0x43CE87 mov dx,[ebp+8]
    const BYTE  kTimeGate[] = { 0x0F, 0xB6, 0x55, 0x18, 0x83, 0xFA, 0x02, 0x74, 0x09,                          // 0x43CE34 movzx edx,[ebp+18h]; cmp edx,2; je
                                0x0F, 0xB6, 0x45, 0x18, 0x83, 0xF8, 0x04, 0x75, 0x22 };                        //          movzx eax,[ebp+18h]; cmp eax,4; jne 0x43CE68
    const BYTE  kDmgType[]  = { 0xC6, 0x40, 0x0A, 0x00 };                                                      // 0x448876 sub_448850: тип = 0

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef void* (__thiscall *FnGetUser)(void* mgr, short idx);                                   // 0x5324A0
    typedef BOOL  (__thiscall *FnIsOpIdx)(void* mgr, short idx, int a3);                           // 0x52ECF0
    typedef int   (__thiscall *FnSendOther)(void* mgr, short num, short op, short len, void* body, int pad);   // 0x52E6D0 (ret 14h)
    const FnGetUser   GetUser   = (FnGetUser)Srv::kGetUser;
    const FnIsOpIdx   IsOpIdx   = (FnIsOpIdx)Srv::kIsOperatorIndex;
    const FnSendOther SendOther = (FnSendOther)0x0052E6D0;
    DWORD g_pSendPacket         = Srv::kSendPacket;     // 0x4C28F0 — стоковая отправка себе (из заглушек)

    // ── настройки ───────────────────────────────────────────────────────────
    bool  g_on[3]        = { false, false, false };     // [1] S1 урон, [2] S2 время
    bool  g_instant      = true;                        // ★ ред. 2: S2 типы 1/6 — соседям тихая копия (+10 = 0, +11 = −1)
    DWORD g_minMs[3]     = { 0, 0, 0 };                 // прореживание тихих типов на игрока, мс (ред. 2: умолч. 0 — каждое)
    DWORD g_typeMask     = 0x29;                        // S2: типы 0/3/5
    bool  g_skipHidden   = true;
    bool  g_trace        = true;

    volatile LONG g_last[3][kMaxUser] = {};             // такт последней рассылки соседям (0 — не было)
    P74_Stats     g_stats = {};

    bool ShouldLog(LONG n) { return g_trace && (n <= 3 || (n % 100000) == 0); }

    bool IsHiddenOperator(void* mgr, short idx)
    {
        __try
        {
            BYTE* user = (BYTE*)GetUser(mgr, idx);
            if (!user) { return false; }
            if (*(const short*)(user + kOffHide) != kHidden) { return false; }
            return IsOpIdx(mgr, idx, -1) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
}

// ── C-часть заглушек: зовётся ПОСЛЕ стоковой отправки себе ──
//   net — объект потока карты (ecx SendPacket), op/to/body — аргументы SendPacket, site — 1 (урон) / 2 (время).
extern "C" void __stdcall P74_AfterSelfSend(void* net, int op, int to, const BYTE* body, int site)
{
    if (site != 1 && site != 2) { return; }
    InterlockedIncrement(&g_stats.seen[site]);
    if (!g_on[site] || (short)op != kOp4058 || !net || !body) { return; }
    const short num = (short)to;
    if (num < 0 || num >= kMaxUser) { InterlockedIncrement(&g_stats.skipBad); return; }

    short bodyNum = -1; int maxHp = 0, curHp = 0; BYTE type = 0xFF; void* mgr = nullptr;
    __try
    {
        bodyNum = *(const short*)body;
        maxHp   = *(const int*)(body + 2);
        curHp   = *(const int*)(body + 6);
        type    = body[10];
        mgr     = *(void**)((BYTE*)net + kOffMgr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return; }
    if (bodyNum != num || !mgr) { InterlockedIncrement(&g_stats.skipBad); return; }

    // ★ типы: S1 — только 0; S2 — тихие из маски (0/3/5) как есть, 1/6 (мгновенное лечение, клиент рисует цифру) —
    //   ред. 2: тихой КОПИЕЙ (+10 = 0, +11 = −1), если InstantToSector; 2/4 сюда не приходят (сток шлёт сектору сам)
    bool instant = false;
    if (site == 2 && type < 32 && (kInstantTypes & (1u << type)))
    {
        if (!g_instant) { InterlockedIncrement(&g_stats.skipType); return; }
        instant = true;
    }
    else
    {
        const DWORD allowed = (site == 1) ? 1u : g_typeMask;
        if (type >= 32 || !(allowed & (1u << type)) || (kDigitTypes & (1u << type)) || (kSectorTypes & (1u << type)))
        {
            InterlockedIncrement(&g_stats.skipType);
            return;
        }
    }
    if (g_skipHidden && IsHiddenOperator(mgr, num)) { InterlockedIncrement(&g_stats.skipHidden); return; }

    // прореживание тихих типов (умолч. 0 — выкл.): конечные значения (0 и максимум) — всегда; типы 1/6 — разовые, не прореживаются.
    //   ⚠ При >0 выброшенное промежуточное значение «хвостом» не дошлётся (до следующего события игрока) — потому умолч. 0.
    const DWORD now = GetTickCount() | 1;
    const bool terminal = curHp <= 0 || (maxHp > 0 && curHp >= maxHp);
    if (g_minMs[site] && !terminal && !instant)
    {
        const DWORD last = (DWORD)g_last[site][num];
        if (last && (DWORD)(now - last) < g_minMs[site]) { InterlockedIncrement(&g_stats.skipThrottle[site]); return; }
    }
    InterlockedExchange(&g_last[site][num], (LONG)now);

    // тихая копия для 1/6 — в локальном буфере (тело себе не трогаем: оно в кадре вызывающего и уже ушло как сток)
    BYTE copy[kBodyLen];
    const BYTE* out = body;
    if (instant)
    {
        __try { memcpy(copy, body, kBodyLen); }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return; }
        copy[10] = 0;                                   // тип 0 — тихая запись у клиента (без цифры)
        *(short*)(copy + 11) = -1;                      // навык −1 — как у sub_448850
        out = copy;
    }

    int rc = 0;
    __try { rc = SendOther(mgr, num, kOp4058, kBodyLen, (void*)out, 1); }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return; }
    (void)rc;
    const LONG n = InterlockedIncrement(&g_stats.sent[site]);
    if (instant) { InterlockedIncrement(&g_stats.sentInstant); }
    if (ShouldLog(n))
    {
        Log::Line(L"[P74] %s: 4058 соседям по сектору №%ld — userNum %d, HP %d/%d, тип %u%s",
                  site == 1 ? L"урон" : L"время (реген/лечение/яд)", n, num, curHp, maxHp, (unsigned)type,
                  instant ? L" → тихая копия тип 0" : L"");
    }
}

extern "C" __declspec(dllexport) void __stdcall P74_GetStats(P74_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Заглушки площадок. Вход по `call` вместо SendPacket: ecx = net, в стеке ret + 6 аргументов SendPacket
    //   (op, len, кому, тело, от, a7). Делают стоковую отправку себе с теми же аргументами и ecx, затем — P74_AfterSelfSend.
    //   Выход — как у SendPacket: ret 18h, eax = её результат; ebx/esi/edi/ebp сохранены.
    __declspec(naked) void StubDamage()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  ecx                               // [ebp-4] = net
            push  dword ptr [ebp+28]                // a7
            push  dword ptr [ebp+24]                // от
            push  dword ptr [ebp+20]                // тело
            push  dword ptr [ebp+16]                // кому
            push  dword ptr [ebp+12]                // длина
            push  dword ptr [ebp+8]                 // опкод
            call  dword ptr [g_pSendPacket]         // thiscall, ret 18h; ecx = net
            push  eax                               // [ebp-8] = результат
            push  1                                 // площадка S1 (урон)
            push  dword ptr [ebp+20]
            push  dword ptr [ebp+16]
            push  dword ptr [ebp+8]
            push  dword ptr [ebp-4]
            call  P74_AfterSelfSend                 // stdcall, 20 б
            pop   eax
            mov   esp, ebp
            pop   ebp
            ret   0x18
        }
    }

    __declspec(naked) void StubTime()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  ecx
            push  dword ptr [ebp+28]
            push  dword ptr [ebp+24]
            push  dword ptr [ebp+20]
            push  dword ptr [ebp+16]
            push  dword ptr [ebp+12]
            push  dword ptr [ebp+8]
            call  dword ptr [g_pSendPacket]
            push  eax
            push  2                                 // площадка S2 (время)
            push  dword ptr [ebp+20]
            push  dword ptr [ebp+16]
            push  dword ptr [ebp+8]
            push  dword ptr [ebp-4]
            call  P74_AfterSelfSend
            pop   eax
            mov   esp, ebp
            pop   ebp
            ret   0x18
        }
    }
}

PatchResult P74_HpSectorSync()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_on[1]      = Config::GetBool(kSec, L"DamageToSector", true);
    g_on[2]      = Config::GetBool(kSec, L"RegenToSector", true);
    int dmgMs    = Config::GetInt (kSec, L"DamageMinIntervalMs", 0);
    int regenMs  = Config::GetInt (kSec, L"RegenMinIntervalMs", 0);
    g_instant    = Config::GetBool(kSec, L"InstantToSector", true);
    int mask     = Config::GetInt (kSec, L"TimeTypeMask", 0x29);
    g_skipHidden = Config::GetBool(kSec, L"SkipHiddenOperators", true);
    g_trace      = Config::GetBool(kSec, L"LogEvents", true);
    if (dmgMs < 0 || dmgMs > 60000)     { Log::Line(L"    P74: DamageMinIntervalMs=%d вне 0..60000 — взято 0", dmgMs); dmgMs = 0; }
    if (regenMs < 0 || regenMs > 60000) { Log::Line(L"    P74: RegenMinIntervalMs=%d вне 0..60000 — взято 0", regenMs); regenMs = 0; }
    if (mask & (int)(kDigitTypes | kSectorTypes))
    {
        Log::Line(L"    P74: TimeTypeMask=0x%X содержит типы 1/2/4/6 — сброшены (1/4/6 клиент рисует цифрой — 1/6 идут ключом "
                  L"InstantToSector тихой копией; 2/4 сток шлёт сектору сам)", mask);
    }
    g_minMs[1]  = (DWORD)dmgMs;
    g_minMs[2]  = (DWORD)regenMs;
    g_typeMask  = (DWORD)mask & 0xFF & ~(kDigitTypes | kSectorTypes);
    if (!g_on[1] && !g_on[2])
    {
        Log::Line(L"    P74: DamageToSector=0 и RegenToSector=0 — ставить нечего");
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ площадок и соседей включённых мер ДО первой записи ──────
    Site check[11];
    int  n = 0;
    check[n++] = { 0x00448876, kDmgType, sizeof(kDmgType) };          // общая: тип в инициализации тела = 0
    if (g_on[1])
    {
        check[n++] = { kSiteDmg,   kSiteDmgOrig, sizeof(kSiteDmgOrig) };
        check[n++] = { 0x0043C83A, kDmgArgs,     sizeof(kDmgArgs)     };
        check[n++] = { 0x0043C859, kDmgAfter,    sizeof(kDmgAfter)    };
    }
    if (g_on[2])
    {
        check[n++] = { kSiteTime,  kSiteTimeOrig, sizeof(kSiteTimeOrig) };
        check[n++] = { 0x0043CE68, kTimeArgs,     sizeof(kTimeArgs)     };
        check[n++] = { 0x0043CE87, kTimeAfter,    sizeof(kTimeAfter)    };
        check[n++] = { 0x0043CE34, kTimeGate,     sizeof(kTimeGate)     };
    }
    if (!VerifyAllSites(L"P74", check, n)) { return PatchResult::Mismatch; }

    // ── запись ──────────────────────────────────────────────────────────────
    if (g_on[1])
    {
        if (!Hook::WriteCall(kSiteDmg, &StubDamage, sizeof(kSiteDmgOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P74 DamageToSector: sub_43C690 (a5=1: навыки, урон по времени, отражение) @0x%08X `call 0x4C28F0` -> "
                  L"заглушка 0x%08X: себе как сток + соседям sub_52E6D0 (сектор 3x3 кроме себя); прореживание %u мс (0 — каждый)",
                  kSiteDmg, (DWORD)&StubDamage, g_minMs[1]);
    }
    if (g_on[2])
    {
        if (!Hook::WriteCall(kSiteTime, &StubTime, sizeof(kSiteTimeOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P74 RegenToSector: SetCurrentHpTimeValue @0x%08X `call 0x4C28F0` -> заглушка 0x%08X: себе как сток + соседям "
                  L"типы маски 0x%02X как есть; типы 1/6 (мгновенное лечение) — %s; прореживание %u мс (0 — каждое)",
                  kSiteTime, (DWORD)&StubTime, g_typeMask,
                  g_instant ? L"тихой копией (тип 0, навык -1)" : L"НЕ шлются (InstantToSector=0)", g_minMs[2]);
    }
    Log::Line(L"    P74: скрытый оператор соседям %s; журнал первых рассылок %s",
              g_skipHidden ? L"НЕ шлётся" : L"шлётся", g_trace ? L"вкл" : L"выкл");
    return PatchResult::Applied;
}
