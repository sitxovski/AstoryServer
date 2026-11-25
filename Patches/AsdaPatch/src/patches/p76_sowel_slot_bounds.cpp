// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P76 — ★ ПРОВЕРКА ПОЛЕЙ ПАКЕТОВ ЖИВЫХ КАМНЕЙ (5022 / 5024 / 5031) ПО ПРАВИЛАМ ЧЕСТНОГО КЛИЕНТА
//  (решение владельца 21.10.2026, ревизия `Reports/sowel_bugfix_2026-10-21/REVIEW.md`).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Документ: `AstoryServer/Docs/GameServer/sowel-slot-bounds-p76.md`.
//
//  ── ЧТО ПРОВЕРЯЕТСЯ ──
//  Честный клиент (эталон `invItemDropSendPacket@0xD06BA0`, порт `AsdaSowelSubsystem`) шлёт:
//   5022 извлечение (`CharCellobItemDetach@0x4DBC30`, тело 4 б в кадре [ebp-0x524]):
//        +0 контейнер предмета ∈ {1, 3}; +3 номер гнезда ∈ [0, 3] (гнездо 0 законно).
//   5024 вставка/замена (`CharCellobItemMove@0x4DC390`, тело 11 б в [ebp-0x534]):
//        +0 контейнер предмета ∈ {1, 3}; +3 номер гнезда ∈ [0, 3]; +8 контейнер камня = 2.
//   5031 «святость» (`CharSpendHolyItemUse@0x4DE590`, тело 6 б в [ebp-0xC8]):
//        +0 и +3 (контейнеры) = 2.
//  Поле вне диапазона → отказ ДО любой записи штатной веткой обработчика (та же, что при «занят»):
//   5022 → 5023 код 0 (ветка 0x4DBDFB), 5024 → 5025 код 0 (0x4DC52A), 5031 → 5032 код 0 (0x4DEC9D; код обнулён на 0x4DE628).
//  Новых пакетов, кодов и строк клиенту нет.
//
//  ── МЕХАНИЗМ ──
//  В каждом обработчике `call sub_52BFF0` (thiscall: ecx = CUserManager, [esp+4] = userNum, [esp+8] = опкод; `ret 8`;
//  al ≠ 0 → обработчик уходит в ветку отказа) заменён на стаб: стаб зовёт сток (пролог sub_52BFF0 может держать P63 —
//  вызов — прямо в сток), при al = 0 сверяет поля тела по кадру обработчика (ebp стаб не трогает) и при нарушении
//  возвращает al = 1. Mode=1 (умолчание) — отказ; Mode=0 — только журнал. P63 пролог sub_52BFF0 только сверяет (не перехватывает),
//  поэтому вызов из стаба идёт прямо в сток.
//  Журнал: PatchLog-канал сервера + ac.other виды 85 (5022) / 86 (5024) / 87 (5031), не чаще 1 строки за JournalIntervalSec
//  на (сессия, вид). Площадки (живой/Indun e7b4ac38 = сток): 0x4DBDEF, 0x4DC51E, 0x4DE70E — других патчей на них нет.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P76_SowelSlotBounds";

    bool g_enabled = true;
    int  g_mode    = 1;          // 1 отказ, 0 журнал
    int  g_journalIntervalSec = 10;
    int  g_logChannel = 1;       // 1 = Log_Item

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);         // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;

    enum SiteId : int { kDetach = 1, kMove = 2, kHoly = 3 };
    // Виды журнала ac.other — выданы по реестру ac-journal-p53.md §9: 85…87.
    enum Kind : BYTE { kKindDetach = 85, kKindMove = 86, kKindHoly = 87 };

    struct Sess { int userIndex; DWORD last[4]; int suppressed[4]; };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_checked = 0, g_viol = 0, g_refused = 0, g_journaled = 0, g_suppressed = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    bool Allow(Sess& s, int site, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.last[site] && now - s.last[site] < (DWORD)g_journalIntervalSec * 1000) { ++s.suppressed[site]; return false; }
        s.last[site] = now;
        return true;
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

// Проверка полей тела. site — площадка, self — CUserManager (ecx стокового вызова), ebp — кадр обработчика.
// Возврат: 0 — поля в пределах честного клиента; 1 — отказ (при Mode=1).
extern "C" int __stdcall P76_Check(int site, void* self, BYTE* ebp)
{
    if (!g_enabled || !ebp) { return 0; }
    __try
    {
        InterlockedIncrement(&g_checked);
        const int userNum = *(const short*)(ebp + 8);
        int opcode = 0, f0 = 0, f1 = 0, f2 = 0;
        BYTE kind = 0;
        const char* what = "";
        bool bad = false;
        switch (site)
        {
        case kDetach:
        {
            const BYTE* b = ebp - 0x524;
            opcode = 5022; kind = kKindDetach; what = "5022 detach";
            f0 = b[0]; f1 = b[3];
            bad = !(f0 == 1 || f0 == 3) || f1 > 3;
            break;
        }
        case kMove:
        {
            const BYTE* b = ebp - 0x534;
            opcode = 5024; kind = kKindMove; what = "5024 insert";
            f0 = b[0]; f1 = b[3]; f2 = b[8];
            bad = !(f0 == 1 || f0 == 3) || f1 > 3 || f2 != 2;
            break;
        }
        case kHoly:
        {
            const BYTE* b = ebp - 0xC8;
            opcode = 5031; kind = kKindHoly; what = "5031 holy";
            f0 = b[0]; f1 = b[3];
            bad = f0 != 2 || f1 != 2;
            break;
        }
        default:
            return 0;
        }
        if (!bad) { return 0; }
        InterlockedIncrement(&g_viol);
        if (SessOk(userNum))
        {
            const BYTE* user = nullptr;
            __try { if (self) { user = pGetUser(self, nullptr, (short)userNum); } } __except (EXCEPTION_EXECUTE_HANDLER) { user = nullptr; }
            const DWORD now = GetTickCount();
            int sup = 0; bool write = true;
            // ★ ревизия 21.10 (М4): UserIndex читается ДО входа в критическую секцию — исключение при чтении не оставит её занятой.
            int ui = -1;
            __try { ui = IndexOf(user); } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }
            if (g_lockReady) { EnterCriticalSection(&g_lock); }
            Sess& s = g_sess[userNum];
            if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
            write = Allow(s, site, now);
            if (write) { sup = s.suppressed[site]; s.suppressed[site] = 0; }
            if (g_lockReady) { LeaveCriticalSection(&g_lock); }
            if (write)
            {
                char detail[96];
                _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s fields %d/%d/%d out of range", what, f0, f1, f2);
                pSrvLog(g_logChannel, "P76 SowelSlotBounds: %s fields %d/%d/%d out of range, %s UserNum %d UserIndex %d%s%s",
                        what, f0, f1, f2, NameOf(user), userNum, IndexOf(user),
                        g_mode ? " -> REFUSE (code 0)" : " (journal)", sup ? " (suppressed before)" : "");
                Journal(kind, opcode, user, userNum, f0, f1, f2, detail, sup);
            }
            else { InterlockedIncrement(&g_suppressed); }
        }
        if (g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

extern "C" void __stdcall P76_GetStats(int* checked, int* viol, int* refused, int* journaled, int* suppressed)
{
    if (checked) { *checked = g_checked; } if (viol) { *viol = g_viol; } if (refused) { *refused = g_refused; }
    if (journaled) { *journaled = g_journaled; } if (suppressed) { *suppressed = g_suppressed; }
}

namespace
{
    // Стабы вместо `call sub_52BFF0` (thiscall, ret 8). На входе: ecx = self, [esp] = адрес возврата, [esp+4] = userNum,
    // [esp+8] = опкод. Стаб сохраняет self, повторяет аргументы и зовёт сток; при al ≠ 0 возвращает его как есть,
    // иначе — результат P76_Check в al. ebp не меняется (кадр обработчика). Снимает 8 б аргументов, как сток.
    __declspec(naked) void St_Detach5022()
    {
        __asm { push ecx }                              // [esp]=self, [esp+4]=ret, [esp+8]=userNum, [esp+12]=opcode
        __asm { push dword ptr [esp+12] }               // opcode
        __asm { push dword ptr [esp+12] }               // userNum
        __asm { mov ecx, dword ptr [esp+8] }            // self
        __asm { mov eax, 0x0052BFF0 }
        __asm { call eax }                              // сток (ret 8) → al
        __asm { pop ecx }                               // self
        __asm { test al, al }
        __asm { jnz done_d }
        __asm { push ebp }
        __asm { push ecx }
        __asm { push 1 }
        __asm { call P76_Check }                        // stdcall → eax 0/1
    done_d:
        __asm { ret 8 }
    }
    __declspec(naked) void St_Move5024()
    {
        __asm { push ecx }
        __asm { push dword ptr [esp+12] }
        __asm { push dword ptr [esp+12] }
        __asm { mov ecx, dword ptr [esp+8] }
        __asm { mov eax, 0x0052BFF0 }
        __asm { call eax }
        __asm { pop ecx }
        __asm { test al, al }
        __asm { jnz done_m }
        __asm { push ebp }
        __asm { push ecx }
        __asm { push 2 }
        __asm { call P76_Check }
    done_m:
        __asm { ret 8 }
    }
    __declspec(naked) void St_Holy5031()
    {
        __asm { push ecx }
        __asm { push dword ptr [esp+12] }
        __asm { push dword ptr [esp+12] }
        __asm { mov ecx, dword ptr [esp+8] }
        __asm { mov eax, 0x0052BFF0 }
        __asm { call eax }
        __asm { pop ecx }
        __asm { test al, al }
        __asm { jnz done_h }
        __asm { push ebp }
        __asm { push ecx }
        __asm { push 3 }
        __asm { call P76_Check }
    done_h:
        __asm { ret 8 }
    }

    // Площадки: `E8 rel32` → sub_52BFF0.
    const BYTE kOrigDetach[5] = { 0xE8, 0xFC, 0x01, 0x05, 0x00 };   // 0x4DBDEF
    const BYTE kOrigMove[5]   = { 0xE8, 0xCD, 0xFA, 0x04, 0x00 };   // 0x4DC51E
    const BYTE kOrigHoly[5]   = { 0xE8, 0xDD, 0xD8, 0x04, 0x00 };   // 0x4DE70E
    // Соседи: аргументы, this и хвост проверки al.
    const BYTE kNbDetachPre[16]  = { 0x68, 0x9E, 0x13, 0x00, 0x00, 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x8D, 0x90, 0xFA, 0xFF, 0xFF };  // 0x4DBDDF push 5022; mov cx,[ebp+8]; push ecx; mov ecx,[ebp-570h]
    const BYTE kNbDetachPost[14] = { 0x0F, 0xB6, 0xD0, 0x85, 0xD2, 0x74, 0x31, 0xC6, 0x85, 0x40, 0xFF, 0xFF, 0xFF, 0x00 };              // 0x4DBDF4 movzx edx,al; test; je; mov byte [ebp-C0h],0
    const BYTE kNbDetachBody[6]  = { 0x8D, 0x8D, 0xDC, 0xFA, 0xFF, 0xFF };                                                            // 0x4DBD66 lea ecx,[ebp-524h] — тело
    const BYTE kNbMovePre[16]    = { 0x68, 0xA0, 0x13, 0x00, 0x00, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x80, 0xFA, 0xFF, 0xFF };  // 0x4DC50E push 5024; mov ax,[ebp+8]; push eax; mov ecx,[ebp-580h]
    const BYTE kNbMovePost[14]   = { 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x31, 0xC6, 0x85, 0x40, 0xFF, 0xFF, 0xFF, 0x00 };              // 0x4DC523 movzx ecx,al; test; je; mov byte [ebp-C0h],0
    const BYTE kNbMoveBody[6]    = { 0x8D, 0x8D, 0xCC, 0xFA, 0xFF, 0xFF };                                                            // 0x4DC4D1 lea ecx,[ebp-534h] — тело
    const BYTE kNbHolyPre[16]    = { 0x68, 0xA7, 0x13, 0x00, 0x00, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0xE0, 0xFE, 0xFF, 0xFF };  // 0x4DE6FE push 5031; mov ax,[ebp+8]; push eax; mov ecx,[ebp-120h]
    const BYTE kNbHolyPost[12]   = { 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x0A, 0xE9, 0x7E, 0x05, 0x00, 0x00 };                          // 0x4DE713 movzx ecx,al; test; je; jmp 0x4DEC9D
    const BYTE kNbHolyBody[6]    = { 0x8D, 0x85, 0x38, 0xFF, 0xFF, 0xFF };                                                            // 0x4DE6D4 lea eax,[ebp-C8h] — тело
    const BYTE kNbHolyCode[7]    = { 0xC6, 0x85, 0x37, 0xFF, 0xFF, 0xFF, 0x00 };                                                      // 0x4DE628 mov byte [ebp-C9h],0 — код ответа
    const BYTE kNbRet8[3]        = { 0xC2, 0x08, 0x00 };                                                                              // 0x52C169 ret 8 — sub_52BFF0 thiscall
}

PatchResult P76_SowelSlotBounds()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 1);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 1; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    const Site sites[] =
    {
        { 0x004DBDEF, kOrigDetach,   sizeof(kOrigDetach)   },
        { 0x004DC51E, kOrigMove,     sizeof(kOrigMove)     },
        { 0x004DE70E, kOrigHoly,     sizeof(kOrigHoly)     },
        { 0x004DBDDF, kNbDetachPre,  sizeof(kNbDetachPre)  },
        { 0x004DBDF4, kNbDetachPost, sizeof(kNbDetachPost) },
        { 0x004DBD66, kNbDetachBody, sizeof(kNbDetachBody) },
        { 0x004DC50E, kNbMovePre,    sizeof(kNbMovePre)    },
        { 0x004DC523, kNbMovePost,   sizeof(kNbMovePost)   },
        { 0x004DC4D1, kNbMoveBody,   sizeof(kNbMoveBody)   },
        { 0x004DE6FE, kNbHolyPre,    sizeof(kNbHolyPre)    },
        { 0x004DE713, kNbHolyPost,   sizeof(kNbHolyPost)   },
        { 0x004DE6D4, kNbHolyBody,   sizeof(kNbHolyBody)   },
        { 0x004DE628, kNbHolyCode,   sizeof(kNbHolyCode)   },
        { 0x0052C169, kNbRet8,       sizeof(kNbRet8)       },
    };
    if (!VerifyAllSites(L"P76", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteCall(0x004DBDEF, &St_Detach5022, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x004DC51E, &St_Move5024,   5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x004DE70E, &St_Holy5031,   5)) { return PatchResult::Failed; }

    Log::Line(L"    P76: режим %s; 5022 @0x004DBDEF (контейнер предмета 1/3, гнездо 0..3) → 5023 код 0; "
              L"5024 @0x004DC51E (+ контейнер камня 2) → 5025 код 0; 5031 @0x004DE70E (контейнеры 2/2) → 5032 код 0; "
              L"журнал ac.other 85..87, не чаще 1/%d с на (сессия, вид); канал лога %d",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ", g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
