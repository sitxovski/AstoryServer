// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L04 — ★ ИСПРАВЛЕНИЕ (безопасность): привязка номера учётки (UserIndex) к сессии.
//
//  ЭТО НАША ПРАВКА. Сессия хранит подтверждённый на входе UserIndex; обработчики
//  списка персонажей (1005) и выбора персонажа (1016) брали UserIndex из ПАКЕТА
//  и в части веток не сверяли с сессией — чужой список персонажей и подмена личности.
//
//  Реализованы две части (третья — соулмейт, режим 2 — вынесена, см. отчёт):
//
//  L04a (1016, `sub_40AD30`): сверка UserIndex с сессией (`sub_4038B0`) выполнялась
//    ТОЛЬКО для режима 0. Правим условие гейта так, чтобы сверка шла для режимов 0 И 1,
//    пропускался только режим 2. Правка — 2 значимых байта (см. LoginApi.h):
//      85 c0 0f 85 a6 00 00 00  ->  3c 02 0f 84 a6 00 00 00   (test;jne -> cmp al,2;je)
//
//  L04b (1005, `sub_407CE0`): перехват `call sub_40F440` (UPCharExist) @0x407FD2.
//    Трамплин сверяет UserIndex из пакета ([esp+0x1C]; [esp+0x20] — группа) с UserIndex сессии
//    (`sub_4038B0(&dword_66B4DA0, [ebp+8])`): при несовпадении запрос не выполняется,
//    `*out = 0` (штатная ветка «нет персонажа» — обработчик ничего не отдаёт), затем
//    хвостовой вызов стокового сборщика при совпадении.
//
//  ── ГРАНИЦЫ ──
//  • L04a — чистая правка условия, поведение режима 0 не меняется, режим 1 получает ту же
//    проверку, режим 2 по-прежнему идёт своей веткой.
//  • L04b при отказе использует СУЩЕСТВУЮЩИЙ путь (`*out=0`) — не новый, проверенный кодом.
//  • Enabled=0 (или под-ключ) — соответствующая часть не ставится.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

namespace
{
    bool g_logHits = true;
    long g_logLeft = 20;

    // sub_4038B0(__thiscall): this=&dword_66B4DA0 (ecx), a2=session -> UserIndex сессии.
    using GetSessUserFn = int(__thiscall*)(int /*self*/, int /*session*/);
    GetSessUserFn g_getSessUser    = (GetSessUserFn)Login::Hooks::kGetSessUser;
    void*         g_realBuilder    = (void*)Login::Hooks::kSqlBuilder40F440;
}

// Отметка в журнал о заблокированном чужом списке персонажей (без деталей сессии).
extern "C" void __cdecl L04_LogCharListReject()
{
    if (g_logHits && InterlockedDecrement(&g_logLeft) >= 0)
    {
        Log::Line(L"    L04b: запрос списка персонажей отклонён — UserIndex не совпал с сессией");
    }
}

// Точка подмены указателей для юнит-теста (стаб sub_4038B0 и стаб сборщика).
extern "C" void __cdecl L04_TestSetup(void* getSess, void* builder)
{
    g_getSessUser = (GetSessUserFn)getSess;
    g_realBuilder = builder;
}

namespace
{
    // Трамплин замены `call sub_40F440` (UPCharExist) в обработчике 1005.
    // Стек на входе: [esp]=ret, [esp+8]=out(v43), [esp+0x1C]=UserIndex(из пакета, 7-й аргумент),
    // [esp+0x20]=group (8-й аргумент). cdecl кладёт аргументы справа налево: дизасм стока 0x407F9F
    // `movsx eax,[ebp-0x24]; push eax` (группа) → `mov ecx,[ebp-0x28]; push ecx` (UserIndex) → … → call.
    // ★ ОШИБКА первой сборки (12.10, до 13:07): читался [esp+0x20] = группа ⇒ сравнение «группа == учётка
    //   сессии» проваливалось у ВСЕХ честных клиентов — список персонажей был бы пуст. Поймано ревизией
    //   другой сессии 12.10; живьём не проявилось только потому, что CheckCharList стоял в 0.
    // Кадр обработчика цел ⇒ session a2 = [ebp+8].
    __declspec(naked) void L04_CharListTrampoline()
    {
        __asm
        {
            movzx eax, word ptr [ebp + 8]        // session
            push eax
            mov  ecx, 0x066B4DA0                 // this = &dword_66B4DA0 (ЛИТЕРАЛ: constexpr в __asm дал бы адрес)
            call dword ptr [g_getSessUser]       // __thiscall: вернёт UserIndex сессии, снимет свой арг (ret 4)
            mov  edx, [esp + 0x1C]               // UserIndex из пакета (7-й аргумент; [esp+0x20] — группа!)
            cmp  eax, edx
            je   _ok
            // отказ: *out = 0 (штатная ветка «нет персонажа»)
            mov  eax, [esp + 0x08]
            mov  dword ptr [eax], 0
            pushad
            call L04_LogCharListReject
            popad
            xor  eax, eax
            ret
        _ok:
            jmp  dword ptr [g_realBuilder]        // хвостовой вызов стокового UPCharExist
        }
    }

    const BYTE kGateOrig[8] = { 0x85, 0xC0, 0x0F, 0x85, 0xA6, 0x00, 0x00, 0x00 };
    const BYTE kGateNew [8] = { 0x3C, 0x02, 0x0F, 0x84, 0xA6, 0x00, 0x00, 0x00 };
    const BYTE kCallOrig[5] = { 0xE8, 0x69, 0x74, 0x00, 0x00 };   // call 0x40F440

    // ── L04c (1016, режим 2 — вход персонажем соулмейта) ─────────────────────
    //  Сток после UPPreSMConnect зовёт sub_4037B0(session, UserIndex_из_пакета): личность сессии
    //  становится ЧУЖОЙ учёткой без проверки, что это соулмейт. Трамплин на этом call:
    //  realUser = sub_4038B0(session); EXEC UPCharExist realUser, group → result[4..7] = MateUserindex;
    //  совпало с UserIndex из пакета → хвостовой вызов стокового sub_4037B0; иначе — штатный отказ
    //  1016 (1027/651 б, код 3) и выход через эпилог обработчика, как делает сам сток при «занят».
    bool g_soulOn       = true;
    bool g_soulFailOpen = false;   // ошибка запроса к БД: 0 — отказ (по умолчанию), 1 — пропустить как сток
    long g_soulLogLeft  = 20;

    using DbSrcFn    = int (__stdcall*)(short);                                          // sub_4060A0
    using SqlFn      = int (__cdecl*)(int, int*, int, int, void*, const char*, ...);     // sub_40F440
    using SendFn     = BOOL(__thiscall*)(void*, short, short, short, void*, short, int); // sub_415A40
    DbSrcFn g_dbSrc        = (DbSrcFn)Login::Hooks::kDbSrcOfGroup;
    SqlFn   g_sql          = (SqlFn)Login::Hooks::kSqlBuilder40F440;
    SendFn  g_send         = (SendFn)Login::Hooks::kSendPacket;
    void*   g_realSetIdent = (void*)Login::Hooks::kSetSessUser;
    void*   g_leaveCs      = (void*)Login::Hooks::kLeaveCs;
    void*   g_selEpilogue  = (void*)Login::Hooks::kSelEpilogue;
    const BYTE kMateCallOrig[5] = { 0xE8, 0xFC, 0x83, 0xFF, 0xFF };   // call 0x4037B0 @0x40B3AF

    // ★ ревизия 43б Н-2 (L09, режим обслуживания): проверка режима для входа соулмейтом — ставит L09 при своей установке (L04 в реестре
    //   раньше, от L09 не зависит). Зовётся ПОСЛЕ сверки пары и ДО sub_4037B0 — личность сессии ещё своя. 1 — пропустить, 0 — отказ
    //   режима (4101/28 уже отправлен L09): трамплин шлёт 1027 код 0 (как стоковая ветка «UPCharSoulState Error») и выходит.
    using MaintGateFn = int (__cdecl*)(BYTE* fr, int realUser, int mate);
    MaintGateFn g_maintGate   = nullptr;
    bool        g_mateInstalled = false;
}

extern "C" void __cdecl L04c_SetMaintGate(void* fn) { g_maintGate = (MaintGateFn)fn; }
extern "C" int  __cdecl L04c_IsInstalled() { return g_mateInstalled ? 1 : 0; }

// Сверка для режима 2. fr — ebp обработчика 1016 (кадр sub_40AD30). 1 — пропустить, 0 — отказать (1027 код 3),
// ★ р43б Н-2: 2 — отказ режима обслуживания L09 (4101/28 уже ушёл; 1027 код 0). Экспонируется для юнит-теста (кадр подделывается буфером).
extern "C" int __cdecl L04c_Check(BYTE* fr)
{
    int result = g_soulFailOpen ? 1 : 0;
    __try
    {
        const short session = *(const short*)(fr + 8);
        const short group   = *(const short*)(fr - Login::Hooks::kSelFrameGrp);
        const int   db      = *(const int*)(fr + 0x10);
        int clientUi = 0;
        memcpy(&clientUi, fr - Login::Hooks::kSelFrameUi, 4);          // невыровненный dword

        const int realUser = g_getSessUser((int)Login::Hooks::kSessionObj, (int)session);

        int  out[5] = { 0, 0, 0, 0, 0 };
        BYTE dst[8000];
        memset(dst, 0, sizeof(dst));
        const int dbsrc = g_dbSrc(group);
        g_sql((int)Login::Hooks::kSqlCtx, out, dbsrc, db, dst, "EXEC UPCharExist %d,%d", realUser, (int)group);
        if (!out[0])
        {
            if (InterlockedDecrement(&g_soulLogLeft) >= 0)
            {
                Log::Line(L"    L04c: UPCharExist не выполнился (учётка сессии %d) — %s",
                          realUser, g_soulFailOpen ? L"пропуск (SoulMateFailOpen=1)" : L"отказ");
            }
            return g_soulFailOpen ? 1 : 0;
        }
        int mate = 0;
        memcpy(&mate, dst + 4, 4);                                       // MateUserindex (как 1005: &v44[4])
        if (dst[0] == 0 || mate == 0 || mate != clientUi)
        {
            if (InterlockedDecrement(&g_soulLogLeft) >= 0)
            {
                Log::Line(L"    L04c: вход соулмейтом отклонён — учётка сессии %d, в пакете %d, пара %d",
                          realUser, clientUi, mate);
            }
            return 0;
        }
        // ★ р43б Н-2: пара подтверждена — режим обслуживания L09 по обеим учёткам, пока личность сессии не сменена
        if (g_maintGate && !g_maintGate(fr, realUser, clientUi))
        {
            return 2;
        }
        result = 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // негодный кадр/указатель — по умолчанию отказ (fail-closed), FailOpen=1 — как сток
    }
    return result;
}

// Штатный отказ 1016: 1027 (651 б) с кодом 3 в стоковый буфер кадра ([ebp-0x618]), как сток шлёт код 2 при «занят».
// ★ р43б Н-2: kind = 2 (отказ режима обслуживания L09) — код 0, как стоковая ветка «UPCharSoulState Error», куда уходит гейт L09 у режимов 0/1.
extern "C" void __cdecl L04c_SendRefuse(BYTE* fr, int kind)
{
    __try
    {
        BYTE* body = fr - Login::Hooks::kSelFrameBody;
        memset(body, 0, Login::Hooks::kSelBodyLen);
        body[0] = kind == 2 ? 0 : 3;                                     // код 3 — «нет активной пары»; 0 — режим обслуживания
        g_send((void*)Login::Hooks::kNetObj, (short)0x403, (short)Login::Hooks::kSelBodyLen,
               *(const short*)(fr + 8), body, *(const short*)(fr + 0xC), 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

// Точка подмены для юнит-теста L04c.
extern "C" void __cdecl L04c_TestSetup(void* getSess, void* dbSrc, void* sql, void* send, int failOpen)
{
    g_getSessUser = (GetSessUserFn)getSess;
    g_dbSrc       = (DbSrcFn)dbSrc;
    g_sql         = (SqlFn)sql;
    g_send        = (SendFn)send;
    g_soulFailOpen = (failOpen != 0);
}

namespace
{
    // Трамплин замены `call sub_4037B0` @0x40B3AF. На входе: [esp]=ret, [esp+4]=session, [esp+8]=UserIndex
    // из пакета, ecx=&dword_66B4DA0, ebp = кадр обработчика (цел). esp = база кадра − 12.
    __declspec(naked) void L04c_SelectTrampoline()
    {
        __asm
        {
            push ebp
            call L04c_Check
            add  esp, 4
            cmp  eax, 1
            jne  _refuse                         // 0 — не пара (код 3), 2 — режим обслуживания L09 (код 0; р43б Н-2)
            mov  ecx, 0x066B4DA0                 // this для sub_4037B0 (ЛИТЕРАЛ, как в L04b)
            jmp  dword ptr [g_realSetIdent]      // хвостовой вызов стокового sub_4037B0 (ret 8 снимет аргументы)
        _refuse:
            add  esp, 12                         // снять ret + 2 аргумента несостоявшегося вызова → esp = база кадра
            push eax                             // kind
            push ebp
            call L04c_SendRefuse                 // 1027 код 3 / 0 (стоковый буфер и стоковый отправитель)
            add  esp, 8
            mov  dword ptr [ebp - 4], -1         // SEH-индекс, как в стоке перед выходом
            lea  ecx, [ebp - 0x1C]
            call dword ptr [g_leaveCs]           // sub_401040 (__thiscall, без аргументов)
            jmp  dword ptr [g_selEpilogue]       // 0x40C8CF: fs:[0], pop ecx/edi/esi/ebx, cookie, mov esp,ebp, ret 0x10
        }
    }
}

// Адрес трамплина 1005 — для юнит-теста (вызывается через фейковый кадр).
extern "C" void* __cdecl L04_TestGetCharListTrampoline()
{
    return (void*)&L04_CharListTrampoline;
}

PatchResult L04_LoginIdentity()
{
    if (!Config::GetBool(L"L04_LoginIdentity", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_logHits = Config::GetBool(L"L04_LoginIdentity", L"LogHits", true);
    const bool doSel  = Config::GetBool(L"L04_LoginIdentity", L"CheckSelectChar", true);  // L04a 1016
    const bool doList = Config::GetBool(L"L04_LoginIdentity", L"CheckCharList",  true);    // L04b 1005

    int ok = 0, mis = 0;

    // ── L04a: гейт режимов 0/1 в 1016 ───────────────────────────────────────
    if (doSel)
    {
        if (!Hook::Verify(Login::Hooks::kSelModeGate, kGateOrig, sizeof(kGateOrig)))
        {
            wchar_t hex[48];
            Hook::Dump(Login::Hooks::kSelModeGate, sizeof(kGateOrig), hex, 48);
            Log::Line(L"    L04a: оригинал не совпал на 0x%08X (%s) — пропуск", Login::Hooks::kSelModeGate, hex);
            ++mis;
        }
        else if (Hook::WriteBytes(Login::Hooks::kSelModeGate, kGateNew, sizeof(kGateNew)))
        {
            Log::Line(L"    L04a: 1016 — сверка UserIndex с сессией теперь и для режима 1 (вход «душой»)");
            ++ok;
        }
        else { Log::Line(L"    L04a: запись не удалась на 0x%08X", Login::Hooks::kSelModeGate); ++mis; }
    }

    // ── L04b: сверка UserIndex в 1005 ───────────────────────────────────────
    if (doList)
    {
        if (!Hook::Verify(Login::Hooks::kCharListCall, kCallOrig, sizeof(kCallOrig)))
        {
            wchar_t hex[32];
            Hook::Dump(Login::Hooks::kCharListCall, sizeof(kCallOrig), hex, 32);
            Log::Line(L"    L04b: оригинал не совпал на 0x%08X (%s) — пропуск", Login::Hooks::kCharListCall, hex);
            ++mis;
        }
        else
        {
            g_getSessUser = (GetSessUserFn)Login::Hooks::kGetSessUser;
            g_realBuilder = (void*)Login::Hooks::kSqlBuilder40F440;
            if (Hook::WriteCall(Login::Hooks::kCharListCall, (void*)&L04_CharListTrampoline, sizeof(kCallOrig)))
            {
                Log::Line(L"    L04b: 1005 — список персонажей только для своей учётки");
                ++ok;
            }
            else { Log::Line(L"    L04b: запись не удалась на 0x%08X", Login::Hooks::kCharListCall); ++mis; }
        }
    }

    // ── L04c: режим 2 (соулмейт) — сверка UserIndex пакета с MateUserindex учётки сессии ──
    g_soulOn       = Config::GetBool(L"L04_LoginIdentity", L"CheckSoulMate",    true);
    g_soulFailOpen = Config::GetBool(L"L04_LoginIdentity", L"SoulMateFailOpen", false);
    if (g_soulOn)
    {
        if (!Hook::Verify(Login::Hooks::kSelMateCall, kMateCallOrig, sizeof(kMateCallOrig)))
        {
            wchar_t hex[32];
            Hook::Dump(Login::Hooks::kSelMateCall, sizeof(kMateCallOrig), hex, 32);
            Log::Line(L"    L04c: оригинал не совпал на 0x%08X (%s) — пропуск", Login::Hooks::kSelMateCall, hex);
            ++mis;
        }
        else
        {
            g_getSessUser  = (GetSessUserFn)Login::Hooks::kGetSessUser;
            g_dbSrc        = (DbSrcFn)Login::Hooks::kDbSrcOfGroup;
            g_sql          = (SqlFn)Login::Hooks::kSqlBuilder40F440;
            g_send         = (SendFn)Login::Hooks::kSendPacket;
            g_realSetIdent = (void*)Login::Hooks::kSetSessUser;
            g_leaveCs      = (void*)Login::Hooks::kLeaveCs;
            g_selEpilogue  = (void*)Login::Hooks::kSelEpilogue;
            if (Hook::WriteCall(Login::Hooks::kSelMateCall, (void*)&L04c_SelectTrampoline, sizeof(kMateCallOrig)))
            {
                g_mateInstalled = true;              // ★ р43б Н-2: L09 спросит при своей установке
                g_maintGate     = nullptr;           // проверку режима ставит L09 (если сам поставлен)
                Log::Line(L"    L04c: 1016 режим 2 — вход соулмейтом только в учётку своей пары (UPCharExist.MateUserindex)%s",
                          g_soulFailOpen ? L"; при ошибке БД — пропуск" : L"");
                ++ok;
            }
            else { Log::Line(L"    L04c: запись не удалась на 0x%08X", Login::Hooks::kSelMateCall); ++mis; }
        }
    }

    if (mis > 0 && ok == 0) { return PatchResult::Mismatch; }
    if (ok == 0)            { return PatchResult::Disabled; }
    return PatchResult::Applied;
}
