// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P81 — ★ СТРАЖ КОДА ДЕЙСТВИЯ 4024 (CharEMotionSync) И ЧАСТОТЫ ЗВАНИЯ «Dancer» (решение владельца 24.10.2026).
//  [ИСПРАВЛЕНИЕ] — защитная входная валидация на нашем сервере; протокол НЕ меняется (поля и опкоды стоковые).
//  Документ: `AstoryServer/Docs/GameServer/action-code-guard-p81.md`. Сток (4e20f0ad), живой GameServer и Indun (e7b4ac38)
//  совпадают побайтно во всей функции sub_546730 (проверка tools/verify_p81.py, стенд tools/stand_p81).
//
//  ── ДЫРА СТОКА (Б-07) ──
//  CharEMotionSync@0x546730 (4024 → 4025) принимает ЛЮБОЙ код 100…400 тела (word [ebp-416h]) от любого игрока: пишет его в
//  статус действия word CUser+0x54E4 (0x5468EE; его читают NpcServer и соседи) и рассылает 4025 сектору. Честный клиент шлёт
//  только 100–110, 112–117, 122, 124, 127, 128, 131 (прыжок, порт), 400 (оригинал 35 мест + порт); 0 сток отбрасывает сам
//  (0x5468D0). Подделка: 300/301 — у соседей игрок выглядит СКРЫТЫМ ОПЕРАТОРОМ / раскрытым (настоящее скрытие оператора идёт
//  ТОЛЬКО пакетом 6005 @0x54E970, не через 4024), 200 — помечает себя «мёртвым» для мобов (NpcServer видит статус 200).
//  Танец 112/113 после рассылки зовёт sub_54A050(userNum, 13, 0, 0) — накопитель звания «Dancer» (индекс 13) без ограничения
//  частоты: флуд 4024 112 набивает звание. Клип танца 13,3 с — честный клиент не шлёт его чаще. ★ 24.10 (ревизия): по умолчанию
//  DanceCountMinSec = 12 — запас 1,3 с на сетевую задержку (при 13 запас 0,33 с терял честный засчёт).
//
//  ── ПЛОЩАДКИ (не пересекаются с P80: S2 0x5468C1 и его соседями 0x5468B8/0x5468C6/0x546946/0x5469AF — verify_p80/p81) ──
//  A 0x5468E1 (13 б) `mov edx,[ebp-42Ch] ; mov ax,[ebp-416h]` — ветка «стоя», ПЕРЕД записью статуса 0x5468EE и курса.
//      Код вне AllowedCodes, отправитель не оператор → выход 0x5469AF (без записи статуса и курса, без рассылки 4025).
//  B 0x546952 (8 б) `mov byte[ebp-414h],cl ; push 1` — перед рассылкой 4025, общая для «стоя» и пути P80 S2 (131 в ходу →
//      0x546946). Сверяет ТОЛЬКО путь «в ходу» (dword CUser+0x33 ≠ 0 — тот же флаг, что читает sub_523ED0/sub_542250 на
//      0x5468B8; между ними вызовов нет); «стоя» уже сверено на A — двойного журнала нет. Нужна, если RelayWhileMoving P80
//      не входит в AllowedCodes.
//  C 0x546978 (13 б) `movsx ecx,[ebp-416h] ; mov [ebp-438h],ecx` — после рассылки, перед вызовом sub_54A050 для 112/113:
//      засчёт «Dancer» не чаще одного раза за DanceCountMinSec на сессию; анимация соседям (4025) уже ушла как сток.
//  Оператор (GM-флаг CUser+0x40B9F, общая точка P47_IsGmUser = sub_52ED50 == 1) на A/B — как сток. Скрытый оператор (300) сток
//  отбивает ещё до площадок (0x5467DE). Счётчик танца — для всех (честный клиент чаще клипа не шлёт).
//  Mode=1 — отклонять (A/B) и не засчитывать (C); Mode=0 — только журнал, поведение стока.
//  Журнал P53 ac.other: 88 (A, стоя), 89 (B, в ходу), 90 (C, танец чаще клипа) — не чаще JournalIntervalSec на (сессия, вид);
//  91 — свободен. Строка в стоковый лог sub_569DF0 канала LogChannel — тем же интервалом.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>
#include <string.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"

namespace
{
    const wchar_t* kSec = L"P81_ActionCodeGuard";
    const wchar_t* kDefAllowed = L"100-110;112-117;122;124;127;128;131;400";   // законные коды честного клиента (оригинал + порт)

    // ── площадки (sub_546730) ───────────────────────────────────────────────
    const DWORD kSiteA       = 0x005468E1;
    const BYTE  kOrigA[13]   = { 0x8B, 0x95, 0xD4, 0xFB, 0xFF, 0xFF,             // mov edx,[ebp-42Ch]   (CUser)
                                 0x66, 0x8B, 0x85, 0xEA, 0xFB, 0xFF, 0xFF };     // mov ax,[ebp-416h]    (код действия)
    const DWORD kSiteB       = 0x00546952;
    const BYTE  kOrigB[8]    = { 0x88, 0x8D, 0xEC, 0xFB, 0xFF, 0xFF,             // mov byte[ebp-414h],cl (байт шлема в тело 4025)
                                 0x6A, 0x01 };                                   // push 1
    const DWORD kSiteC       = 0x00546978;
    const BYTE  kOrigC[13]   = { 0x0F, 0xBF, 0x8D, 0xEA, 0xFB, 0xFF, 0xFF,       // movsx ecx,word[ebp-416h]
                                 0x89, 0x8D, 0xC8, 0xFB, 0xFF, 0xFF };           // mov [ebp-438h],ecx
    // соседи (только сверка)
    const DWORD kRangeSite   = 0x005468C6;                                       // movsx eax,[ebp-416h] ; cmp eax,64h ; jl 0x5468F7
    const BYTE  kRangeOrig[12] = { 0x0F, 0xBF, 0x85, 0xEA, 0xFB, 0xFF, 0xFF, 0x83, 0xF8, 0x64, 0x7C, 0x25 };
    const DWORD kRangeHiSite = 0x005468D2;                                       // movsx ecx,[ebp-416h] ; cmp ecx,190h ; jg 0x5468F7
    const BYTE  kRangeHiOrig[15] = { 0x0F, 0xBF, 0x8D, 0xEA, 0xFB, 0xFF, 0xFF, 0x81, 0xF9, 0x90, 0x01, 0x00, 0x00, 0x7F, 0x16 };
    DWORD g_pBackA           = 0x005468EE;                                       // mov [edx+54E4h],ax ; jmp 0x5468FC
    const BYTE  kBackAOrig[9] = { 0x66, 0x89, 0x82, 0xE4, 0x54, 0x00, 0x00, 0xEB, 0x05 };
    const DWORD kRelaySite   = 0x00546946;                                       // mov eax,[ebp-42Ch] ; mov cl,[eax+4A6h] (вход P80 S2)
    const BYTE  kRelayOrig[12] = { 0x8B, 0x85, 0xD4, 0xFB, 0xFF, 0xFF, 0x8A, 0x88, 0xA6, 0x04, 0x00, 0x00 };
    DWORD g_pBackB           = 0x0054695A;                                       // lea edx,[ebp-418h] ; push edx ; push 0Dh ; push 0FB9h
    const BYTE  kBackBOrig[14] = { 0x8D, 0x95, 0xE8, 0xFB, 0xFF, 0xFF, 0x52, 0x6A, 0x0D, 0x68, 0xB9, 0x0F, 0x00, 0x00 };
    const DWORD kCallSite    = 0x00546973;                                       // call sub_52E6D0 (рассылка 4025 сектору)
    const BYTE  kCallOrig[5] = { 0xE8, 0x58, 0x7D, 0xFE, 0xFF };
    DWORD g_pBackC           = 0x00546985;                                       // cmp [ebp-438h],70h ; jl ; cmp 71h ; jle ; jmp
    const BYTE  kBackCOrig[20] = { 0x83, 0xBD, 0xC8, 0xFB, 0xFF, 0xFF, 0x70, 0x7C, 0x21,
                                   0x83, 0xBD, 0xC8, 0xFB, 0xFF, 0xFF, 0x71, 0x7E, 0x02, 0xEB, 0x16 };
    const DWORD kDanceSite   = 0x00546999;                                       // push 0 ; push 0 ; push 0Dh ; mov dx,[ebp+8] ; push edx
    const BYTE  kDanceOrig[11] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x0D, 0x66, 0x8B, 0x55, 0x08, 0x52 };
    const DWORD kDanceCall   = 0x005469AA;                                       // call sub_54A050 (накопитель звания)
    const BYTE  kDanceCallOrig[5] = { 0xE8, 0xA1, 0x36, 0x00, 0x00 };
    DWORD g_pExit            = 0x005469AF;                                       // эпилог: mov ecx,[ebp-4] ; xor ecx,ebp
    const BYTE  kExitOrig[5] = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD };
    const DWORD kHiddenSite  = 0x005467C9;                                       // mov eax,[ebp-42Ch] ; movsx ecx,[eax+3BC3Bh] ; cmp ecx,12Ch
    const BYTE  kHiddenOrig[19] = { 0x8B, 0x85, 0xD4, 0xFB, 0xFF, 0xFF, 0x0F, 0xBF, 0x88, 0x3B, 0xBC, 0x03, 0x00,
                                    0x81, 0xF9, 0x2C, 0x01, 0x00, 0x00 };

    constexpr int kOffMoving    = 0x33;     // dword CUser+0x33 — «в стеке хода» (sub_542250)
    constexpr int kOffStatus    = 0x54E4;   // word CUser+0x54E4 — статус действия/хода
    constexpr int kOffUserIndex = 0x174;    // учётка
    constexpr int kOffSlot      = 0x18C;    // слот персонажа
    constexpr int kOffName      = 0x178;    // имя персонажа cp1251

    // ── настройки (читают трамплины) ────────────────────────────────────────
    BYTE  g_allowed[512] = {};   // 1 — код 4024 разрешён (индекс = код; читается трамплинами A/B без вызова)
    int   g_mode         = 1;    // 1 отклонять / не засчитывать, 0 только журнал
    DWORD g_danceMs      = 12000;// DanceCountMinSec × 1000; 0 — площадка C не ставится
    int   g_journalIntervalSec = 10;
    int   g_logChannel   = 0;    // 0 = Log_Game
    bool  g_enabled      = false;

    typedef void (__cdecl *PFN_SrvLog)(int cat, const char* fmt, ...);   // sub_569DF0
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)Srv::kLog;

    // Виды журнала ac.other — выданы по реестру ac-journal-p53.md §9: 88…90 (91 свободен).
    enum Kind : BYTE { kKindStanding = 88, kKindMoving = 89, kKindDance = 90 };
    enum JIdx : int { kJStanding = 0, kJMoving = 1, kJDance = 2 };

    // Сессия по userNum (0..0x225); сброс при смене учётки в слоте.
    struct Sess { int userIndex; DWORD danceLast; DWORD jLast[3]; int jSup[3]; };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    P81_Stats g_stats = {};

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    // Разрешить строку журнала (сессия, вид) не чаще g_journalIntervalSec. Вызывается под g_lock.
    bool AllowJournal(Sess& s, int j, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.jLast[j] && now - s.jLast[j] < (DWORD)g_journalIntervalSec * 1000) { ++s.jSup[j]; return false; }
        s.jLast[j] = now ? now : 1;
        return true;
    }

    // Событие в журнал P53 (ac.other) — поля по документу: item_code = код, value1/value2 — по виду.
    void Journal(BYTE kind, const BYTE* user, int userNum, int v0, int v1, int v2, const char* text, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = 4024;
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
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    // Учётка сессии из CUser (безопасно к мусорной памяти); −1 — нет.
    int IndexOf(const BYTE* user)
    {
        int ui = -1;
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); } } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }
        return ui;
    }

    // Найти сессию слота под g_lock (сброс при другой учётке). Вызывающий держит g_lock.
    Sess& SessOf(int userNum, int ui)
    {
        Sess& s = g_sess[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        return s;
    }

    // Разбор AllowedCodes: «a-b;c;d» (разделители ; , пробел). Коды вне 100…400 сток отбрасывает сам — игнорируются.
    // Возврат: число разрешённых кодов; -1 — синтаксическая ошибка.
    int ParseAllowed(const wchar_t* s, BYTE* out)
    {
        memset(out, 0, 512);
        int count = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L';' || *p == L',' || *p == L' ' || *p == L'\t') { ++p; }
            if (!*p) { break; }
            if (*p < L'0' || *p > L'9') { return -1; }
            int a = 0;
            while (*p >= L'0' && *p <= L'9') { a = a * 10 + (*p - L'0'); if (a > 100000) { return -1; } ++p; }
            int b = a;
            if (*p == L'-')
            {
                ++p;
                if (*p < L'0' || *p > L'9') { return -1; }
                b = 0;
                while (*p >= L'0' && *p <= L'9') { b = b * 10 + (*p - L'0'); if (b > 100000) { return -1; } ++p; }
            }
            if (*p && *p != L';' && *p != L',' && *p != L' ' && *p != L'\t') { return -1; }
            if (b < a) { return -1; }
            for (int c = a; c <= b; ++c)
            {
                if (c < 100 || c > 400) { continue; }
                if (!out[c]) { out[c] = 1; ++count; }
            }
        }
        return count;
    }
}

// Проверка кода вне разрешённых (медленный путь трамплинов A/B). site — 1 (A, стоя) / 2 (B, в ходу), ebp — кадр sub_546730,
// code — код действия тела 4024. Возврат: 0 — пропустить как сток; 1 — отклонить (выход без записи и рассылки).
extern "C" int __stdcall P81_Check(int site, BYTE* ebp, int code)
{
    if (!g_enabled || !ebp) { return 0; }
    __try
    {
        if (code >= 0 && code < 512 && g_allowed[code]) { return 0; }
        void* self = *(void**)(ebp - 0x434);                 // this обработчика (CUserManager)
        const int userNum = *(const short*)(ebp + 8);
        const BYTE* user = *(BYTE**)(ebp - 0x42C);          // CUser (обработчик проверил на NULL)
        if (P47_IsGmUser(self, userNum)) { InterlockedIncrement(&g_stats.operatorPassed); return 0; }
        InterlockedIncrement(site == 2 ? &g_stats.violMoving : &g_stats.violStanding);
        if (SessOk(userNum))
        {
            int status = -1;
            __try { if (user) { status = *(const short*)(user + kOffStatus); } } __except (EXCEPTION_EXECUTE_HANDLER) { status = -1; }
            const int ui = IndexOf(user);
            const DWORD now = GetTickCount();
            const int j = site == 2 ? kJMoving : kJStanding;
            bool write = true; int sup = 0;
            if (g_lockReady) { EnterCriticalSection(&g_lock); }
            Sess& s = SessOf(userNum, ui);
            write = AllowJournal(s, j, now);
            if (write) { sup = s.jSup[j]; s.jSup[j] = 0; }
            if (g_lockReady) { LeaveCriticalSection(&g_lock); }
            if (write)
            {
                char detail[64];
                _snprintf_s(detail, sizeof(detail), _TRUNCATE, "4024 code %d not allowed (%s)%s", code,
                            site == 2 ? "moving" : "standing", g_mode ? " -> drop" : "");
                pSrvLog(g_logChannel, "P81 ActionCodeGuard: 4024 code %d not allowed (%s), %s UserNum %d UserIndex %d status %d%s%s",
                        code, site == 2 ? "moving" : "standing", user ? (const char*)(user + kOffName) : "?", userNum, ui, status,
                        g_mode ? " -> DROP" : " (journal)", sup ? " (suppressed before)" : "");
                Journal(site == 2 ? kKindMoving : kKindStanding, user, userNum, code, g_mode, status, detail, sup);
            }
            else { InterlockedIncrement(&g_stats.suppressed); }
        }
        if (g_mode == 1) { InterlockedIncrement(&g_stats.refused); return 1; }
        InterlockedIncrement(&g_stats.journalOnly);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return 0; }
}

// Засчёт «Dancer» (площадка C, код 112/113 после рассылки 4025). ebp — кадр sub_546730.
// Возврат: 1 — звать sub_54A050 (как сток); 0 — не засчитывать (чаще DanceCountMinSec, Mode=1).
extern "C" int __stdcall P81_Dance(BYTE* ebp)
{
    if (!g_enabled || !ebp || g_danceMs == 0) { return 1; }
    __try
    {
        const int userNum = *(const short*)(ebp + 8);
        const int code = *(const short*)(ebp - 0x416);
        const BYTE* user = *(BYTE**)(ebp - 0x42C);
        if (!SessOk(userNum)) { return 1; }
        const int ui = IndexOf(user);
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool throttled = false, write = false; int sup = 0; DWORD since = 0;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = SessOf(userNum, ui);
        if (s.danceLast && now - s.danceLast < g_danceMs)
        {
            throttled = true;
            since = now - s.danceLast;
            write = AllowJournal(s, kJDance, now);
            if (write) { sup = s.jSup[kJDance]; s.jSup[kJDance] = 0; }
            if (g_mode == 0) { s.danceLast = now; }       // журнал: сток засчитывает — интервал от последнего засчёта
        }
        else { s.danceLast = now; }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        if (!throttled) { InterlockedIncrement(&g_stats.danceCounted); return 1; }
        InterlockedIncrement(&g_stats.danceFast);
        if (write)
        {
            char detail[64];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE, "4024 dance %d after %u ms (min %u)%s", code, since, g_danceMs,
                        g_mode ? " -> no count" : "");
            pSrvLog(g_logChannel, "P81 ActionCodeGuard: 4024 dance %d after %u ms (min %u ms), %s UserNum %d UserIndex %d%s%s",
                    code, since, g_danceMs, user ? (const char*)(user + kOffName) : "?", userNum, ui,
                    g_mode ? " -> Dancer NOT counted" : " (journal)", sup ? " (suppressed before)" : "");
            Journal(kKindDance, user, userNum, code, (int)since, (int)g_danceMs, detail, sup);
        }
        else { InterlockedIncrement(&g_stats.suppressed); }
        if (g_mode == 1) { InterlockedIncrement(&g_stats.danceSkipped); return 0; }
        InterlockedIncrement(&g_stats.danceCounted);
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return 1; }
}

extern "C" __declspec(dllexport) void __stdcall P81_GetStats(P81_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Трамплин A. Вход по jmp из 0x5468E1 (ветка «стоя», код уже в 100…400): ebp — кадр sub_546730. eax/ecx/edx и флаги
    //   свободны (0x5468EE ждёт edx = CUser, ax = код — повторяем замещённые инструкции). Стек сбалансирован (stdcall).
    __declspec(naked) void TrampA()
    {
        __asm
        {
            movsx eax, word ptr [ebp-416h]
            cmp   eax, 511
            ja    SlowA
            movzx ecx, byte ptr [g_allowed + eax]
            test  ecx, ecx
            jnz   PassA
        SlowA:
            push  eax                               // code
            push  ebp                               // кадр
            push  1                                 // площадка A
            call  P81_Check
            test  eax, eax
            jnz   RefuseA
        PassA:
            mov   edx, dword ptr [ebp-42Ch]         // замещённое: CUser
            mov   ax, word ptr [ebp-416h]           // замещённое: код
            jmp   dword ptr [g_pBackA]              // 0x5468EE — запись статуса, курс, рассылка (сток)
        RefuseA:
            jmp   dword ptr [g_pExit]               // 0x5469AF — выход без записи и рассылки
        }
    }

    // Трамплин B. Вход по jmp из 0x546952 (обе ветки перед рассылкой; cl = байт шлема). «Стоя» (dword CUser+0x33 == 0) —
    //   уже сверено площадкой A: сразу дальше. «В ходу» (путь P80 S2) — та же проверка кода. eax/ecx/edx и флаги после
    //   замещённых инструкций свободны (0x54695A их перезаписывает).
    __declspec(naked) void TrampB()
    {
        __asm
        {
            mov   byte ptr [ebp-414h], cl           // замещённое: байт шлема в тело 4025
            mov   eax, dword ptr [ebp-42Ch]
            cmp   dword ptr [eax+33h], 0            // в стеке хода?
            je    PassB
            movsx eax, word ptr [ebp-416h]
            cmp   eax, 511
            ja    SlowB
            movzx edx, byte ptr [g_allowed + eax]
            test  edx, edx
            jnz   PassB
        SlowB:
            push  eax
            push  ebp
            push  2                                 // площадка B
            call  P81_Check
            test  eax, eax
            jnz   RefuseB
        PassB:
            push  1                                 // замещённое: аргумент sub_52E6D0
            jmp   dword ptr [g_pBackB]              // 0x54695A — рассылка 4025 (сток)
        RefuseB:
            jmp   dword ptr [g_pExit]
        }
    }

    // Трамплин C. Вход по jmp из 0x546978 (после рассылки). Повторяет замещённое (код → [ebp-438h]); для 112/113 спрашивает
    //   P81_Dance: 0 — выход без sub_54A050, иначе — стоковое сравнение 0x546985 (оно само позовёт sub_54A050 для 112/113).
    __declspec(naked) void TrampC()
    {
        __asm
        {
            movsx ecx, word ptr [ebp-416h]          // замещённое
            mov   dword ptr [ebp-438h], ecx         // замещённое
            cmp   ecx, 70h
            jl    BackC
            cmp   ecx, 71h
            jg    BackC
            push  ebp
            call  P81_Dance
            test  eax, eax
            jz    ExitC
        BackC:
            jmp   dword ptr [g_pBackC]              // 0x546985
        ExitC:
            jmp   dword ptr [g_pExit]
        }
    }
}

PatchResult P81_ActionCodeGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    int danceSec = Config::GetInt(kSec, L"DanceCountMinSec", 12);
    if (danceSec < 0 || danceSec > 3600)
    {
        Log::Line(L"    P81: DanceCountMinSec=%d вне 0..3600 — взято 12", danceSec);
        danceSec = 12;
    }
    g_danceMs = (DWORD)danceSec * 1000;
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 0);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 0; }

    wchar_t list[512] = L"";
    Config::GetStr(kSec, L"AllowedCodes", kDefAllowed, list, ARRAYSIZE(list));
    int n = ParseAllowed(list, g_allowed);
    if (n <= 0)
    {
        Log::Line(L"    P81: AllowedCodes=\"%s\" не разобран или пуст — взят список по умолчанию \"%s\"", list, kDefAllowed);
        lstrcpynW(list, kDefAllowed, ARRAYSIZE(list));
        n = ParseAllowed(list, g_allowed);
    }
    if (g_allowed[200] || g_allowed[300] || g_allowed[301])
    {
        Log::Line(L"    P81: ВНИМАНИЕ — AllowedCodes разрешает %s%s%s: подделка «мёртв»/«скрытый оператор» через 4024 снова открыта",
                  g_allowed[200] ? L"200 " : L"", g_allowed[300] ? L"300 " : L"", g_allowed[301] ? L"301" : L"");
    }
    {
        const int relay = Config::GetInt(L"P80_CrouchSpeedJumpRelay", L"RelayWhileMoving", 131);
        if (relay >= 100 && relay <= 400 && !g_allowed[relay])
        {
            Log::Line(L"    P81: код прыжка в ходу P80 RelayWhileMoving=%d не входит в AllowedCodes — 4024 %d будет отклоняться "
                      L"и стоя, и в ходу (площадка B)", relay, relay);
        }
    }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    Site check[16];
    int  k = 0;
    check[k++] = { kSiteA,       kOrigA,       sizeof(kOrigA)       };
    check[k++] = { kSiteB,       kOrigB,       sizeof(kOrigB)       };
    check[k++] = { kRangeSite,   kRangeOrig,   sizeof(kRangeOrig)   };
    check[k++] = { kRangeHiSite, kRangeHiOrig, sizeof(kRangeHiOrig) };
    check[k++] = { g_pBackA,     kBackAOrig,   sizeof(kBackAOrig)   };
    check[k++] = { kRelaySite,   kRelayOrig,   sizeof(kRelayOrig)   };
    check[k++] = { g_pBackB,     kBackBOrig,   sizeof(kBackBOrig)   };
    check[k++] = { kCallSite,    kCallOrig,    sizeof(kCallOrig)    };
    check[k++] = { g_pExit,      kExitOrig,    sizeof(kExitOrig)    };
    check[k++] = { kHiddenSite,  kHiddenOrig,  sizeof(kHiddenOrig)  };
    if (g_danceMs)
    {
        check[k++] = { kSiteC,     kOrigC,         sizeof(kOrigC)         };
        check[k++] = { g_pBackC,   kBackCOrig,     sizeof(kBackCOrig)     };
        check[k++] = { kDanceSite, kDanceOrig,     sizeof(kDanceOrig)     };
        check[k++] = { kDanceCall, kDanceCallOrig, sizeof(kDanceCallOrig) };
    }
    if (!VerifyAllSites(L"P81", check, k)) { g_enabled = false; return PatchResult::Mismatch; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    // ── запись ──────────────────────────────────────────────────────────────
    if (!Hook::WriteJmp(kSiteA, &TrampA, sizeof(kOrigA))) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(kSiteB, &TrampB, sizeof(kOrigB))) { return PatchResult::Failed; }
    if (g_danceMs && !Hook::WriteJmp(kSiteC, &TrampC, sizeof(kOrigC))) { return PatchResult::Failed; }

    Log::Line(L"    P81: режим %s; разрешено кодов 4024: %d (\"%s\"); A @0x%08X (стоя, до записи CUser+0x54E4) -> 0x%08X, "
              L"B @0x%08X (в ходу, путь P80 S2) -> 0x%08X; оператор (GM-флаг) — как сток",
              g_mode ? L"ОТКЛОНЯТЬ" : L"ЖУРНАЛ", n, list, kSiteA, (DWORD)&TrampA, kSiteB, (DWORD)&TrampB);
    if (g_danceMs)
    {
        Log::Line(L"    P81: C @0x%08X -> 0x%08X: звание «Dancer» (sub_54A050, 112/113) — не чаще 1 раза за %d с на сессию%s",
                  kSiteC, (DWORD)&TrampC, danceSec, g_mode ? L"" : L" (режим журнала: засчитывается как сток)");
    }
    else { Log::Line(L"    P81: DanceCountMinSec=0 — площадка C не ставится (звание «Dancer» — сток)"); }
    Log::Line(L"    P81: журнал ac.other 88 (стоя) / 89 (в ходу) / 90 (танец) — не чаще 1/%d с на (сессия, вид); канал лога %d",
              g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
