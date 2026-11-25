// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P118 — [ИСПРАВЛЕНИЕ] ОБМЕН ОТМЕНЯЕТСЯ, ПОКА ИГРОК РАБОТАЕТ С АУКЦИОНОМ (09.11.2026, пачка 20, баг 3, жалоба 10;
//  слово владельца «any trade request should be canceled by server while communicating with auction»).
//  Разбор: Reports/npc_exchange_win_13000.md §18; документ AstoryServer/Docs/GameServer/auction-trade-block-p118.md.
//
//  ── СТОК (GameServer e7b4ac38 = Indun = Ch2) ──
//  Сервер не знает, что у игрока открыт аукцион: пакетов открытия/закрытия окна нет (9915 — один раз при входе в мир),
//  разговор с NPC на сервер не уходит. Признак CUser+0x15F «запрос в ItemRelay в полёте» живёт десятки миллисекунд (ставит
//  диспетчер перед 9901/9905/9909, снимает ответ ItemRelay). Запрос обмена 5282 (CharExchangeReq@0x4DF830) отказывает по
//  нему кодами 8/9 (клиент: «убит/обездвижен»), согласие 5284 (CharExchangeAcceptReq@0x4DFC80) его не проверяет вовсе.
//
//  ── ЧТО ДЕЛАЕТ P118 (протокол не меняется) ──
//  A. Метка «работает с аукционом»: пролог пяти обработчиков 9901/9903/9905/9907/9909 (по 10 б: push ebp; mov ebp,esp;
//     push -1; push SEH) → заглушка пишет GetTickCount() в таблицу «CUser* → (метка, учётка +0x174)». 9915 не метит (вход
//     в мир). Учётка сверяется при чтении — переиспользованный слот CUser чужую метку не наследует.
//  B. 5282: площадка 0x4DFA09 (10 б, перед проверкой «свой обмен открыт» +0x145) — свежая метка у заявителя → штатный блок
//     кода 5 (0x4DFA15, клиент: 5011 «Ты уже ведёшь обмен»), у цели → блок кода 4 (0x4DFA52, клиент: 5010 «Игрок уже занят
//     обменом»). Иначе — штатные инструкции и продолжение 0x4DFA13.
//  C. 5284 (согласие, v9[0] == 1): площадка 0x4DFE27 (10 б, перед проверкой +0x145 заявителя) — свежая метка у любой стороны
//     → [ebp-38h] = 0 и общий хвост отказа 0x4E004D: 5285 код 0 ОБЕИМ (клиент: 5007 «Обмен прошёл неудачно»), окно обмена
//     не создаётся. Флаги +0x145/+0x149 на этой ветке ещё не взведены — сбрасывать нечего.
//  «Свежая» = моложе WindowSec (умолчание 120 с — разбор журналов ItemRelay в документе).
//  D. [ВЫКЛ по умолчанию] StormGuard — гашение шторма 9907 у клиентов alpha-7.0.0: пересылка 9908 (sub_51A980, площадка
//     0x51A9D6, 7 б) при ПУСТОМ ответе ItemRelay шлёт одну запись 62 б со статусом StormStatus (3): старый порт тогда не
//     уходит в ветку 9910 и не шлёт 9907 снова; оригинал и новый порт запись с таким статусом пропускают.
//  Соседи: P44 (0x4DFE5B заглушка выделения окна, 0x4DFFE2/0x4E001C ветка отказа, 0x4E004D — её продолжение), P19 (тела
//  9905/9909 0x51ACC5/0x51E630) — не пересекаются.
//  Откат: patches.ini [P118_AuctionTradeBlock] Enabled=0 — ни одна площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P118_AuctionTradeBlock";         // секция patches.ini

    // ── A. Прологи обработчиков аукциона (одинаковые 6 б + push imm32 SEH-таблицы) ──
    constexpr DWORD kReg  = 0x00517AB0;   // 9901 Recv_TransAction_RegistItemReq
    constexpr DWORD kInq  = 0x00519FB0;   // 9903 Recv_TransAction_InqueryItemReq
    constexpr DWORD kMy   = 0x0051A4E0;   // 9907 Recv_TransAction_InqueryItemReq_0 («мои лоты»)
    constexpr DWORD kBuy  = 0x0051AA10;   // 9905 Recv_TransAction_BuyItemReq
    constexpr DWORD kDel  = 0x0051E380;   // 9909 Recv_TransAction_DeleteItemReq
    const BYTE kRegOrig[10] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x3D, 0x19, 0x58, 0x00 };
    const BYTE kInqOrig[10] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x6C, 0x1A, 0x58, 0x00 };
    const BYTE kMyOrig[10]  = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x07, 0x1B, 0x58, 0x00 };
    const BYTE kBuyOrig[10] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x67, 0x1B, 0x58, 0x00 };
    const BYTE kDelOrig[10] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xA7, 0x1C, 0x58, 0x00 };

    // ── B. CharExchangeReq: mov eax,[ebp-34h]; cmp dword [eax+145h],0 | jz 0x4DFA46 | блок кода 5 | … блок кода 4 ──
    constexpr DWORD kReqSite   = 0x004DFA09;
    constexpr DWORD kReqBack   = 0x004DFA13;   // jz short loc_4DFA46
    constexpr DWORD kReqSelf   = 0x004DFA15;   // mov byte [ebp-2Eh],5 — 5283 код 5 заявителю
    constexpr DWORD kReqTarget = 0x004DFA52;   // mov byte [ebp-2Eh],4 — 5283 код 4 заявителю
    const BYTE kReqOrig[10]   = { 0x8B, 0x45, 0xCC, 0x83, 0xB8, 0x45, 0x01, 0x00, 0x00, 0x00 };
    const BYTE kReqTail[6]    = { 0x74, 0x31, 0xC6, 0x45, 0xD2, 0x05 };   // 0x4DFA13: jz +31h; mov byte [ebp-2Eh],5
    const BYTE kReqTgtOrig[4] = { 0xC6, 0x45, 0xD2, 0x04 };               // 0x4DFA52: mov byte [ebp-2Eh],4

    // ── C. CharExchangeAcceptReq: mov ecx,[ebp-44h]; cmp dword [ecx+145h],0 | jz 0x4DFE5B ──
    constexpr DWORD kAccSite = 0x004DFE27;
    constexpr DWORD kAccBack = 0x004DFE31;     // jz short loc_4DFE5B
    constexpr DWORD kAccSend = 0x004E004D;     // хвост: 5285 [ebp-38h] заявителю ([ebp-47h]) и согласившемуся (arg0)
    const BYTE kAccOrig[10] = { 0x8B, 0x4D, 0xBC, 0x83, 0xB9, 0x45, 0x01, 0x00, 0x00, 0x00 };
    const BYTE kAccTail[2]  = { 0x74, 0x28 };
    const BYTE kAccSendOrig[8] = { 0x6A, 0x01, 0x6A, 0x00, 0x8D, 0x45, 0xC8, 0x50 };   // push 1; push 0; lea eax,[ebp-38h]; push eax

    // ── D. sub_51A980 (пересылка 9908 от ItemRelay): movsx eax,[ebp-4]; sub eax,0Ah | push eax ──
    constexpr DWORD kStormSite = 0x0051A9D6;
    constexpr DWORD kStormBack = 0x0051A9DD;
    const BYTE kStormOrig[7]  = { 0x0F, 0xBF, 0x45, 0xFC, 0x83, 0xE8, 0x0A };
    const BYTE kStormTail[6]  = { 0x50, 0x68, 0xB4, 0x26, 0x00, 0x00 };   // push eax; push 26B4h (9908)

    constexpr int kOffAcct = 0x174;            // CUser: Userindex (учётка)
    constexpr int kOffName = 0x178;            // CUser: имя персонажа
    constexpr int kSlots   = 16384;            // таблица меток: CUser* → метка (линейные пробы)

    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);
    const FnGetUser pGetUser = (FnGetUser)0x005324A0;
    typedef void (__cdecl* FnSrvLog)(int cat, const char* fmt, ...);
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;
    constexpr int kLogCat = 0;                 // Log_Game

    struct Mark { BYTE* user; DWORD tick; int acct; };
    Mark g_marks[kSlots] = {};
    SRWLOCK g_lock = SRWLOCK_INIT;
    DWORD g_windowMs = 120000;
    int g_logMax = 30;
    volatile LONG g_logCount = 0;
    volatile LONG g_logMinute = 0;
    P118_Stats g_stats = {};
    volatile LONG g_stormCount = 0;           // D: сколько пустых 9908 заменено записью

    DWORD g_backReg = kReg + 10, g_backInq = kInq + 10, g_backMy = kMy + 10, g_backBuy = kBuy + 10, g_backDel = kDel + 10;
    DWORD g_reqBack = kReqBack, g_reqSelf = kReqSelf, g_reqTarget = kReqTarget;
    DWORD g_accBack = kAccBack, g_accSend = kAccSend;
    DWORD g_stormBack = kStormBack;
    BYTE g_emptyRec[62] = {};                  // запись 9908 «пусто»: серийник 0, статус StormStatus на +4

    DWORD Slot(const BYTE* user) { return ((DWORD)(UINT_PTR)user >> 4) * 2654435761u % kSlots; }

    bool LogAllowed()
    {
        const LONG minute = (LONG)(GetTickCount() / 60000);
        if (InterlockedExchange(&g_logMinute, minute) != minute) { InterlockedExchange(&g_logCount, 0); }
        return InterlockedIncrement(&g_logCount) <= g_logMax;
    }

    // Метка свежая: та же учётка и моложе окна.
    bool Busy(const BYTE* user, DWORD* ageMs)
    {
        if (!user) { return false; }
        const int acct = *(const int*)(user + kOffAcct);
        bool busy = false;
        AcquireSRWLockShared(&g_lock);
        DWORD s = Slot(user);
        for (int n = 0; n < 64; ++n, s = (s + 1) % kSlots)
        {
            const Mark& m = g_marks[s];
            if (!m.user) { break; }
            if (m.user == user)
            {
                const DWORD age = GetTickCount() - m.tick;
                busy = (m.acct == acct) && age < g_windowMs;
                if (ageMs) { *ageMs = age; }
                break;
            }
        }
        ReleaseSRWLockShared(&g_lock);
        return busy;
    }
}

// A: C-часть пролога. op — опкод для журнала, mgr — CUserManager (ecx обработчика), num — userNum (a2).
extern "C" void __stdcall P118_Touch(int op, void* mgr, int num)
{
    __try
    {
        BYTE* user = pGetUser(mgr, (short)num);
        if (!user) { return; }
        const int acct = *(const int*)(user + kOffAcct);
        const DWORD now = GetTickCount();
        AcquireSRWLockExclusive(&g_lock);
        DWORD s = Slot(user), freeSlot = MAXDWORD, oldSlot = MAXDWORD, oldAge = 0;
        for (int n = 0; n < 64; ++n, s = (s + 1) % kSlots)
        {
            Mark& m = g_marks[s];
            if (m.user == user || !m.user) { freeSlot = s; break; }
            const DWORD age = now - m.tick;
            if (age >= g_windowMs && age >= oldAge) { oldSlot = s; oldAge = age; }   // просроченная — можно занять
        }
        if (freeSlot == MAXDWORD) { freeSlot = oldSlot; }
        if (freeSlot != MAXDWORD)
        {
            g_marks[freeSlot].user = user; g_marks[freeSlot].tick = now; g_marks[freeSlot].acct = acct;
            InterlockedIncrement(&g_stats.marked);
        }
        else { InterlockedIncrement(&g_stats.tableFull); }
        ReleaseSRWLockExclusive(&g_lock);
        (void)op;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
}

// B: 0 — сток, 5 — заявитель работает с аукционом, 4 — цель. ebp — кадр CharExchangeReq.
extern "C" int __stdcall P118_ReqGate(BYTE* ebp)
{
    __try
    {
        InterlockedIncrement(&g_stats.reqSeen);
        BYTE* self = *(BYTE* const*)(ebp - 0x34);
        BYTE* tgt  = *(BYTE* const*)(ebp - 0x20);
        DWORD age = 0;
        int code = 0;
        BYTE* who = nullptr;
        if (Busy(self, &age)) { code = 5; who = self; }
        else if (Busy(tgt, &age)) { code = 4; who = tgt; }
        if (!code) { return 0; }
        InterlockedIncrement(code == 5 ? &g_stats.reqSelf : &g_stats.reqTarget);
        if (LogAllowed())
        {
            SrvLog(kLogCat, "P118: 5282 %.20s -> %.20s refused, %.20s on auction %u ms ago -> 5283 code %d",
                   (const char*)(self + kOffName), (const char*)(tgt + kOffName), (const char*)(who + kOffName), age, code);
        }
        return code;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
    return 0;
}

// C: 1 — отказ (5285 код 0 обеим), 0 — сток. ebp — кадр CharExchangeAcceptReq.
extern "C" int __stdcall P118_AccGate(BYTE* ebp)
{
    __try
    {
        InterlockedIncrement(&g_stats.accSeen);
        BYTE* acc = *(BYTE* const*)(ebp - 0x50);
        BYTE* ini = *(BYTE* const*)(ebp - 0x44);
        DWORD age = 0;
        BYTE* who = Busy(acc, &age) ? acc : (Busy(ini, &age) ? ini : nullptr);
        if (!who) { return 0; }
        InterlockedIncrement(&g_stats.accRefused);
        if (LogAllowed())
        {
            SrvLog(kLogCat, "P118: 5284 accept %.20s <- %.20s refused, %.20s on auction %u ms ago -> 5285 code 0 to both",
                   (const char*)(acc + kOffName), (const char*)(ini + kOffName), (const char*)(who + kOffName), age);
        }
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P118_GetStats(P118_Stats* out)
{
    if (out) { *out = g_stats; out->storm = g_stormCount; }
}

namespace
{
#define P118_TOUCH_STUB(NAME, OP, SEH, BACK)                                             \
    __declspec(naked) void NAME()                                                     \
    {                                                                                 \
        __asm pushfd                                                                  \
        __asm pushad                                                                  \
        __asm movsx eax, word ptr [esp + 40]                                          \
        __asm push  eax                                                               \
        __asm push  ecx                                                               \
        __asm push  OP                                                                \
        __asm call  P118_Touch                                                        \
        __asm popad                                                                   \
        __asm popfd                                                                   \
        __asm push  ebp                                                               \
        __asm mov   ebp, esp                                                          \
        __asm push  -1                                                                \
        __asm push  SEH                                                               \
        __asm jmp   dword ptr [BACK]                                                  \
    }

    P118_TOUCH_STUB(St_Reg, 9901, 0x0058193D, g_backReg)
    P118_TOUCH_STUB(St_Inq, 9903, 0x00581A6C, g_backInq)
    P118_TOUCH_STUB(St_My,  9907, 0x00581B07, g_backMy)
    P118_TOUCH_STUB(St_Buy, 9905, 0x00581B67, g_backBuy)
    P118_TOUCH_STUB(St_Del, 9909, 0x00581CA7, g_backDel)

    // B: вместо `mov eax,[ebp-34h]; cmp dword [eax+145h],0` в CharExchangeReq.
    __declspec(naked) void St_ReqGate()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P118_ReqGate
            mov   dword ptr [esp + 28], eax       // в ячейку eax pushad
            popad
            popfd
            cmp   eax, 5
            je    self
            cmp   eax, 4
            je    target
            mov   eax, dword ptr [ebp - 34h]
            cmp   dword ptr [eax + 145h], 0
            jmp   dword ptr [g_reqBack]           // 0x4DFA13: jz loc_4DFA46
        self:
            jmp   dword ptr [g_reqSelf]           // 0x4DFA15: 5283 код 5
        target:
            jmp   dword ptr [g_reqTarget]         // 0x4DFA52: 5283 код 4
        }
    }

    // C: вместо `mov ecx,[ebp-44h]; cmp dword [ecx+145h],0` в CharExchangeAcceptReq.
    __declspec(naked) void St_AccGate()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P118_AccGate
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   ecx, dword ptr [ebp - 44h]
            cmp   dword ptr [ecx + 145h], 0
            jmp   dword ptr [g_accBack]           // 0x4DFE31: jz loc_4DFE5B
        refuse:
            popad
            popfd
            mov   byte ptr [ebp - 38h], 0         // 5285 код 0
            jmp   dword ptr [g_accSend]           // 0x4E004D: заявителю и согласившемуся
        }
    }

    // D: вместо `movsx eax,[ebp-4]; sub eax,0Ah` в sub_51A980. [esp+4] — указатель тела (push ecx перед push edx).
    __declspec(naked) void St_Storm()
    {
        __asm
        {
            movsx eax, word ptr [ebp - 4]
            sub   eax, 0Ah
            test  eax, eax
            jnz   done
            mov   dword ptr [esp + 4], offset g_emptyRec
            mov   eax, 62
            lock inc dword ptr [g_stormCount]
        done:
            jmp   dword ptr [g_stormBack]         // 0x51A9DD: push eax; push 26B4h
        }
    }
}

PatchResult P118_AuctionTradeBlock()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    const int sec = Config::GetInt(kSec, L"WindowSec", 120);
    g_windowMs = (DWORD)((sec < 5 ? 5 : (sec > 3600 ? 3600 : sec)) * 1000);
    g_logMax = Config::GetInt(kSec, L"LogPerMinute", 30);
    const bool storm = Config::GetBool(kSec, L"StormGuard", false);
    const int status = Config::GetInt(kSec, L"StormStatus", 3);
    g_emptyRec[4] = (BYTE)((status == 0 || status == 1 || status == 100) ? 3 : status);   // 0/1/100 эталон обрабатывает — нельзя

    const Site sites[] =
    {
        { kReg, kRegOrig, sizeof(kRegOrig) }, { kInq, kInqOrig, sizeof(kInqOrig) }, { kMy, kMyOrig, sizeof(kMyOrig) },
        { kBuy, kBuyOrig, sizeof(kBuyOrig) }, { kDel, kDelOrig, sizeof(kDelOrig) },
        { kReqSite, kReqOrig, sizeof(kReqOrig) }, { kReqBack, kReqTail, sizeof(kReqTail) }, { kReqTarget, kReqTgtOrig, sizeof(kReqTgtOrig) },
        { kAccSite, kAccOrig, sizeof(kAccOrig) }, { kAccBack, kAccTail, sizeof(kAccTail) }, { kAccSend, kAccSendOrig, sizeof(kAccSendOrig) },
        { kStormSite, kStormOrig, sizeof(kStormOrig) }, { kStormBack, kStormTail, sizeof(kStormTail) },
    };
    if (!VerifyAllSites(L"P118", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kReg, &St_Reg, 10) || !Hook::WriteJmp(kInq, &St_Inq, 10) || !Hook::WriteJmp(kMy, &St_My, 10)
        || !Hook::WriteJmp(kBuy, &St_Buy, 10) || !Hook::WriteJmp(kDel, &St_Del, 10)) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kReqSite, &St_ReqGate, 10)) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kAccSite, &St_AccGate, 10)) { return PatchResult::Failed; }
    if (storm && !Hook::WriteJmp(kStormSite, &St_Storm, 7)) { return PatchResult::Failed; }
    Log::Line(L"    P118: метка аукциона в прологах 9901/9903/9905/9907/9909; 5282 @0x%08X (коды 5/4), 5284 @0x%08X (5285 код 0 обеим); окно %u с;"
              L" StormGuard %s (статус %d)", kReqSite, kAccSite, g_windowMs / 1000, storm ? L"ВКЛ" : L"выкл", (int)g_emptyRec[4]);
    return PatchResult::Applied;
}
