// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L09 — режим обслуживания: отказ стоковым кодом 4101/28 (нотис клиента 7017 «Идут профилактические работы на сервере»)
//        на ВХОДЕ (1003) и ★ ревизия 43 С-1 — на ВХОДЕ В МИР с выбора персонажа (1016).
//        НАША ПРАВКА (21.11.2026, админ-центр Astory шаг А5.3). Описание: AstoryServer/Docs/LoginManager/L09-login-maintenance.md.
//
//  ── КАК УСТРОЕН ВХОД (реверс, LoginManager.c:2405-2733, sub_406C20 = CUserProc::Send_LoginUser) ──
//  1003 → секрет (sub_406360), MD5 cred-блока (sub_4060E0), IP слота (sub_403420, нет → 4101/5), версия «Arab_Closed» (→ 4101/10),
//  `EXEC UPUserLogin …` (0x407263, L03/L06), switch по статусу процедуры:
//     1 → личность сессии (sub_4037B0) и 1004/1;   2 / 3 → счётчик, 4-й подряд → 4101/3 + разрыв, иначе 1004/2 или 1004/3;
//     4 → дубль-вход (кик прежней сессии) и 1004/4;  5 → 4101/7 (1107 «заблокирована»);  6 → 4101/8;  7 → 4101/9;
//     ПРОЧИЕ статусы → ничего, сразу общий хвост `sub_415A40(1004, 8, slot, &v69, a3, 1)` @0x407B2F (клиент: default — нотис 119 + число).
//  Решение о допуске — только в процедуре (таблица Joy1 adm.LoginMaintenance, врезка [L09-GATE]): в режиме обслуживания учётке вне
//  1…5000 она отвечает статусом 28 (номер = код 4101 ниже, чтобы в журналах читалось одно число).
//  Свой «режим обслуживания» у стока — только AcceptIp.ini (ProcConnect 0x405A90: флаг this+0x3C, список префиксов IP, читается один
//  раз при старте в sub_405450) → `sub_415A40(4101, 1, slot, &28, 0, 1)` — клиент (network.c:2210-2290) для кодов 0x0D…0x20 показывает
//  нотис и НЕ рвёт соединение (0x1C → 7017). Учётки он не различает, поэтому для «вход только операторам» не годится.
//
//  ── ВХОД В МИР (★ ревизия 43 С-1; реверс LoginManager.c:3959-4230, sub_40AD30 = CUserProc::Send_SelectChar) ──
//  Кто прошёл UPUserLogin ДО включения режима, стоит на выборе персонажа: 1016 больше UPUserLogin не зовёт (секрет, MD5, группа, канал,
//  UserIndex ≥ 0, L04a — сверка с сессией у режимов 0/1, режим 2 — UPPreSMConnect + sub_4037B0 / L04c), первый запрос с записью —
//  `EXEC UPCharSoulState` (call sub_40F440 @0x40B41A), затем UPCharPos / UPChannelCount / UPCharInfo… и 1021 (адрес GameServer). Без адреса
//  из 1021 в мир не войти (обход — только свой клиент прямо на GameServer; гейт GS не ставится — там же портал и смена канала тех, кто
//  уже в игре). Патч перехватывает ЭТОТ call: для учётки вне 1…5000 спрашивает `EXEC adm.LoginMaintenanceGate <UserIndex>` (тот же
//  сборщик, та же сессия базы) — ответ 1: сессии уходит 4101/28 (нотис 7017, соединение живо), `*out = 0`, возврат 0 → стоковая ветка
//  «UPCharSoulState Error» (1027 код 0, выход из секции) — ни одной записи. Процедуры нет / ошибка запроса — вход как без режима
//  (на WorldMissingSec секунд проверка не повторяется, чтобы не сыпать ошибки в OLEDB_LOG). UserIndex — из пакета (после L04a / L04c это
//  учётка сессии; у входа соулмейтом — учётка партнёра, чей персонаж входит).
//  ★ ревизия 43б:
//   Н-1 — запрос гейта идёт на соединение 0 (как EXEC UPUserLogin, LoginManager.c:2582, и UPChannelCount в том же 1016, :4249), а не на
//         dbsrc = sub_4060A0(group) (DSN персонажей группы [DB_DNS<g>_0]): adm.LoginMaintenance и врезка живут в базе входа, и при выносе
//         персонажей группы в другую базу гейт не должен молча открываться. Слот (0, a4) в этом потоке есть — его же берёт UPChannelCount.
//   Н-2 — режим 2 (соулмейт) решается в трамплине L04c ДО sub_4037B0 (личность сессии ещё своя): L04c зовёт L09_MateGate(кадр, учётка
//         сессии, учётка партнёра) — отказ, если режим включён и хоть одна из двух вне 1…5000 (4101/28, затем 1027 код 0 стоковым буфером,
//         выход). На площадке 0x40B41A режим 2 тогда пропускается (решение уже принято). Без L04c (CheckSoulMate=0) учётка сессии после
//         sub_4037B0 неизвестна — режим 2 спрашивает гейт номером 0 (вне 1…5000): в режиме обслуживания вход соулмейтом закрыт всем.
//   Н-3 — сбой запроса (out = 0: процедуры нет, deadlock, обрыв, который P125 не поднял) открывает гейт не на 60 с сразу, а с нарастанием:
//         WorldErrorSec (2 с) → ×2 за каждый сбой подряд → не больше WorldMissingSec (60 с); успешный ответ сбрасывает счёт. По HRESULT
//         (out[4]) «нет процедуры» от прочих ошибок не отличить: сборщик отдаёт DB_E_ERRORSINCOMMAND на любую ошибку SQL. Каждый сбой и
//         восстановление — строка PatchLog БЕЗ предела LogPerMinute (их число ограничено самим окном): «СБОЙ ГЕЙТА ВХОДА В МИР …» и «гейт
//         входа в мир снова работает … без проверки пропущено N»; панель (domains/maint.py) читает их и показывает «гейт не работает».
//         Fail-open сохранён осознанно: сбой режима не должен закрывать вход в мир всем, включая операторов.
//   мелочь 3 — 4101 уходит с тем же заголовком, что стоковый ответ обработчика (эхо a3: [ebp+0xC] у 1016, аргумент hdr у 1003).
//
//  ── ГРАНИЦЫ ──
//  • Площадки — две, ни с чьей не пересекаются (Registry.cpp); байты сверяются ОБЕ до записи — не сошлось хоть одно — Mismatch, ничего.
//  • Status 1…7 запрещены (у них своя стоковая логика выше площадки) — патч не ставится (Failed с объяснением).
//  • Code — только коды, у которых клиент показывает текст без разрыва (13, 15, 20, 21, 22, 24…32; ★ ревизия 43, мелочь 5: 14, 16 «-»,
//    17–19, 23 — без текста).
//  • WorldGate=0 — только первая площадка (вход 1003), как до ревизии 43.
//  • Журнал — строка на отказ (слот), не больше LogPerMinute в минуту.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

namespace
{
    // sub_415A40: __thiscall (this, opcode, size, slot, body, hdr, pad), вызываемый снимает 0x18. Свободная функция — через
    // __fastcall (ecx = this, edx — мусор, остальное на стеке): тот же порядок аргументов и та же очистка стека.
    using SendFn = BOOL(__fastcall*)(void* self, void* edx, int opcode, int size, int slot, const BYTE* body, int hdr, int pad);
    using SqlFn  = int (__cdecl*)(int, int*, int, int, void*, const char*, ...);           // sub_40F440

    const wchar_t* const S = L"L09_LoginMaintenance";
    const BYTE kOrig[5]      = { 0xE8, 0x0C, 0xDF, 0x00, 0x00 };   // call 0x415A40 @0x407B2F
    const BYTE kWorldOrig[5] = { 0xE8, 0x21, 0x40, 0x00, 0x00 };   // call 0x40F440 @0x40B41A (EXEC UPCharSoulState)

    SendFn g_send    = (SendFn)Login::Hooks::kSendPacket;
    SqlFn  g_sql     = (SqlFn)Login::Hooks::kSqlBuilder;
    void*  g_worldReal = (void*)Login::Hooks::kSqlBuilder;
    int    g_status  = 28;
    BYTE   g_code    = 28;
    bool   g_worldOn = true;
    int    g_missingSec = 60;                 // ★ р43б Н-3: потолок окна «без проверки» после сбоев подряд
    int    g_errSec = 2;                      // ★ р43б Н-3: окно после первого сбоя (дальше ×2 за сбой подряд)
    volatile LONG64 g_missingUntil = 0;
    volatile LONG g_errStreak = 0, g_errTotal = 0, g_openPassed = 0;
    bool   g_mateByL04c = false;              // ★ р43б Н-2: режим 2 решает трамплин L04c (до sub_4037B0)
    int    g_logPerMin = 30;
    volatile LONG g_logMinute = 0, g_logInMinute = 0, g_logDropped = 0;
    volatile LONG g_hits = 0, g_worldHits = 0;
    bool   g_applied = false;
    bool   g_logOn   = true;          // юнит-тест журнал выключает (Log не инициализирован вне LoginManager)

    bool LogAllowed()
    {
        if (!g_logOn) { return false; }
        const LONG minute = (LONG)(GetTickCount64() / 60000ULL);
        if (InterlockedExchange(&g_logMinute, minute) != minute) { InterlockedExchange(&g_logInMinute, 0); }
        if (g_logPerMin > 0 && InterlockedIncrement(&g_logInMinute) > g_logPerMin)
        {
            InterlockedIncrement(&g_logDropped);
            return false;
        }
        return true;
    }

    bool CodeHasText(int code)     // network.c:2219-2283 — коды «нотис без разрыва» с текстом
    {
        switch (code)
        {
        case 0x0D: case 0x0F: case 0x14: case 0x15: case 0x16: case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D:
        case 0x1E: case 0x1F: case 0x20:
            return true;
        default:
            return false;
        }
    }
}

// Трамплин площадки 0x407B2F: подмена 1004/<Status> на 4101/<Code>. Экспортирован для юнит-теста (tools/test_l09.cpp).
extern "C" BOOL __fastcall L09_Send(void* self, void* edx, int opcode, int size, int slot, const BYTE* body, int hdr, int pad)
{
    bool refuse = false;
    __try
    {
        refuse = (WORD)opcode == Login::Hooks::kOpLoginReply && body && body[0] == (BYTE)g_status;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        refuse = false;                       // негодный указатель тела — пусть уйдёт как было
    }
    if (!refuse)
    {
        return g_send(self, edx, opcode, size, slot, body, hdr, pad);
    }
    InterlockedIncrement(&g_hits);
    if (LogAllowed())
    {
        const LONG dropped = InterlockedExchange(&g_logDropped, 0);
        Log::Line(L"    L09: слот %d — вход отклонён в режиме обслуживания (статус %d процедуры) → 4101 код %d (нотис 7017), "
                  L"соединение не рвётся; всего с запуска %ld%s", (short)slot, g_status, (int)g_code, g_hits,
                  dropped ? L" (строки выше подавлены пределом LogPerMinute)" : L"");
    }
    BYTE code = g_code;                       // тело 4101 — один байт кода (как `v11 = 28` у AcceptIp, LoginManager.c:2017)
    // ★ р43б мелочь 3: заголовок — эхо a3 стокового ответа (как у 1004 этого же вызова), а не 0 AcceptIp: клиент 4101 разбирает по опкоду
    return g_send(self, edx, Login::Hooks::kOpLoginRefuse, 1, slot, &code, hdr, 1);
}

// ★ р43б: общий запрос гейта входа в мир (площадка 0x40B41A и режим 2 из L04c). fr — кадр обработчика 1016 ([ebp+8] сессия, [ebp+0xC]
// заголовок a3, [ebp+0x10] a4 — номер сессии базы потока). 1 — пропустить, 0 — отказать (4101/Code уже отправлен).
static int L09_GateAsk(BYTE* fr, int uid, int db, const wchar_t* what)
{
    short slot = 0, hdr = 0;
    __try
    {
        slot = *(const short*)(fr + 8);
        hdr  = *(const short*)(fr + 0xC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 1;                            // негодный кадр — как без режима
    }
    const LONG64 now = (LONG64)GetTickCount64();
    if (now < InterlockedCompareExchange64(&g_missingUntil, 0, 0))
    {
        InterlockedIncrement(&g_openPassed); // окно после сбоя: вход без проверки — считаем, строка о восстановлении скажет сколько
        return 1;
    }
    int out[5] = { 0, 0, 0, 0, 0 };
    BYTE dst[8000];
    memset(dst, 0, sizeof(dst));
    __try
    {
        // ★ р43б Н-1: соединение 0 — база входа (там adm.LoginMaintenance и врезка UPUserLogin), а не DSN персонажей группы
        g_sql((int)Login::Hooks::kSqlCtx, out, 0, db, dst, "EXEC adm.LoginMaintenanceGate %d", uid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out[0] = 0;
    }
    if (!out[0])
    {
        // ★ р43б Н-3: окно растёт с числом сбоев подряд — разовый сбой открывает вход в мир на WorldErrorSec, а не на минуту
        const LONG streak = InterlockedIncrement(&g_errStreak);
        const LONG total  = InterlockedIncrement(&g_errTotal);
        int wait = g_errSec;
        for (LONG i = 1; i < streak && wait < g_missingSec; ++i) { wait *= 2; }
        if (wait > g_missingSec) { wait = g_missingSec; }
        InterlockedExchange64(&g_missingUntil, now + (LONG64)wait * 1000);
        if (g_logOn)                         // без предела LogPerMinute: строк не больше одной на окно
        {
            // метка [L09-GATE-FAIL] — для панели (domains/maint.py, _PS_DLL ищет её ASCII-шаблоном); текст метки не менять без панели
            Log::Line(L"    L09: [L09-GATE-FAIL] СБОЙ ГЕЙТА ВХОДА В МИР (%s), учётка %d — EXEC adm.LoginMaintenanceGate не выполнилась (HRESULT 0x%08X; нет "
                      L"процедуры — SQL L09 не применён, или ошибка базы) — вход пропущен как без режима, следующие %d с вход в мир без "
                      L"проверки; сбоев подряд %ld, всего с запуска %ld", what, uid, (unsigned)out[4], wait, streak, total);
        }
        return 1;
    }
    const LONG was = InterlockedExchange(&g_errStreak, 0);
    if (was > 0 && g_logOn)
    {
        Log::Line(L"    L09: [L09-GATE-OK] гейт входа в мир снова работает (сбоев подряд было %ld; входов в мир без проверки за это время: %ld)",
                  was, InterlockedExchange(&g_openPassed, 0));
    }
    if (dst[0] != 1) { return 1; }
    InterlockedIncrement(&g_worldHits);
    if (LogAllowed())
    {
        Log::Line(L"    L09: слот %d, учётка %d (%s) — вход в мир отклонён в режиме обслуживания → 4101 код %d (нотис 7017), дальше стоковая "
                  L"ветка ошибки (1027 код 0), записей нет; всего с запуска %ld", (int)slot, uid, what, (int)g_code, g_worldHits);
    }
    BYTE code = g_code;
    g_send((void*)Login::Hooks::kNetObj, nullptr, Login::Hooks::kOpLoginRefuse, 1, slot, &code, hdr, 1);
    return 0;
}

// ★ р43б Н-2: режим 2 (соулмейт) — зовёт трамплин L04c ПОСЛЕ сверки пары и ДО sub_4037B0 (личность сессии ещё своя). realUser — учётка
// сессии (sub_4038B0), mate — учётка партнёра из пакета (её персонаж входит). 1 — пропустить, 0 — отказать (4101/Code отправлен; L04c
// шлёт 1027 код 0 и выходит, sub_4037B0 не зовётся). Экспонируется для теста.
extern "C" int __cdecl L09_MateGate(BYTE* fr, int realUser, int mate)
{
    if (!g_worldOn) { return 1; }
    const bool outR = !(realUser >= 1 && realUser <= 5000), outM = !(mate >= 1 && mate <= 5000);
    if (!outR && !outM) { return 1; }         // обе служебные — без запроса
    int db = 0;
    __try { db = *(const int*)(fr + 0x10); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 1; }
    // одна учётка вне 1…5000 достаточна: процедура отвечает 1 при Mode = 1 для любого номера вне 1…5000 (в счётчик — учётка сессии)
    return L09_GateAsk(fr, outR ? realUser : mate, db, outR ? L"соулмейт, учётка сессии" : L"соулмейт, учётка партнёра");
}

// ★ р43б Н-2: связь с L04 (l04_login_identity.cpp; L04 в реестре раньше L09). L04 от L09 не зависит: L09 при установке спрашивает, стоит ли
// трамплин L04c, и отдаёт ему свою проверку режима 2.
extern "C" int  __cdecl L04c_IsInstalled();
extern "C" void __cdecl L04c_SetMaintGate(void* fn);

// ★ ревизия 43 С-1: решение площадки 0x40B41A. fr — ebp обработчика 1016, argp — esp на входе в трамплин ([0] ret, [2] out, [3] dbsrc
// (★ р43б Н-1: гейтом не берётся), [4] db, [8] UserIndex, [10] режим). 1 — пропустить (стоковый UPCharSoulState), 0 — отказать
// (4101/Code уже отправлен). Экспонируется для теста.
extern "C" int __cdecl L09_WorldCheck(BYTE* fr, DWORD* argp)
{
    if (!g_worldOn) { return 1; }
    int uid = 0, db = 0;
    BYTE mode = 0;
    __try
    {
        uid  = (int)argp[8];
        db   = (int)argp[4];
        mode = *(fr - Login::Hooks::kSelFrameMode);  // [ebp-0x28] — байт режима (первый push площадки: movzx eax, byte [ebp-0x28])
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 1;                            // негодный кадр — как без режима
    }
    const wchar_t* what = L"выбор персонажа";
    if (mode == 2)
    {
        // ★ р43б Н-2: режим 2 решён в L04c до смены личности сессии (обе учётки). Без L04c личность уже партнёрская — настоящая учётка
        //   сессии неизвестна: спрашиваем номером 0 (вне 1…5000) — в режиме обслуживания вход соулмейтом закрыт всем.
        if (g_mateByL04c) { return 1; }
        if (uid >= 1 && uid <= 5000) { uid = 0; }
        what = L"соулмейт без L04c";
    }
    else if (uid >= 1 && uid <= 5000)
    {
        return 1;                            // служебные — без запроса
    }
    return L09_GateAsk(fr, uid, db, what);
}

namespace
{
    // Трамплин замены `call sub_40F440` @0x40B41A (EXEC UPCharSoulState). cdecl: стек снимает вызывающий (add esp,0x28).
    __declspec(naked) void L09_WorldTrampoline()
    {
        __asm
        {
            mov  eax, esp
            push eax                         // argp — esp на входе ([esp] = адрес возврата)
            push ebp                         // кадр обработчика 1016
            call L09_WorldCheck
            add  esp, 8
            test eax, eax
            jnz  _go
            mov  eax, [esp + 8]              // out
            mov  dword ptr [eax], 0          // *out = 0 — стоковая ветка «UPCharSoulState Error»
            xor  eax, eax
            ret
        _go:
            jmp  dword ptr [g_worldReal]     // хвостовой вызов стокового сборщика (UPCharSoulState)
        }
    }
}

// Для юнит-теста: подмена отправки, сборщика и параметров без установки на площадки.
extern "C" void __cdecl L09_TestSetup(void* send, int status, int code) { g_send = (SendFn)send; g_status = status; g_code = (BYTE)code; g_logOn = false; }
extern "C" void __cdecl L09_TestSetupWorld(void* sql, int on, int missingSec) { g_sql = (SqlFn)sql; g_worldOn = on != 0; g_missingSec = missingSec;
                                                                                 InterlockedExchange64(&g_missingUntil, 0); InterlockedExchange(&g_errStreak, 0); }
extern "C" void __cdecl L09_TestSetupErr(int errSec, int mateByL04c) { g_errSec = errSec; g_mateByL04c = mateByL04c != 0; }
extern "C" long long __cdecl L09_TestWindowLeftMs() { return InterlockedCompareExchange64(&g_missingUntil, 0, 0) - (LONG64)GetTickCount64(); }
extern "C" void __cdecl L09_TestClearWindow() { InterlockedExchange64(&g_missingUntil, 0); }
extern "C" long __cdecl L09_TestHits() { return g_hits; }
extern "C" long __cdecl L09_TestWorldHits() { return g_worldHits; }
extern "C" void* __cdecl L09_TestWorldTrampoline() { return (void*)&L09_WorldTrampoline; }

PatchResult L09_LoginMaintenance()
{
    g_applied = false;
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    const int status = Config::GetInt(S, L"Status", 28);
    const int code   = Config::GetInt(S, L"Code", 28);
    g_logPerMin      = Config::GetInt(S, L"LogPerMinute", 30);
    g_worldOn        = Config::GetBool(S, L"WorldGate", true);
    g_missingSec     = Config::GetInt(S, L"WorldMissingSec", 60);
    if (g_missingSec < 5)    { g_missingSec = 5; }
    if (g_missingSec > 3600) { g_missingSec = 3600; }
    g_errSec         = Config::GetInt(S, L"WorldErrorSec", 2);       // ★ р43б Н-3
    if (g_errSec < 1)            { g_errSec = 1; }
    if (g_errSec > g_missingSec) { g_errSec = g_missingSec; }
    if (status < 8 || status > 255)
    {
        Log::Line(L"    L09: Status=%d недопустим (1…7 — стоковые ветки обработчика, нужен 8…255) — не ставлю", status);
        return PatchResult::Failed;
    }
    if (!CodeHasText(code))
    {
        Log::Line(L"    L09: Code=%d недопустим (нужен код, у которого клиент показывает текст без разрыва: 13, 15, 20–22, 24–32) — не ставлю", code);
        return PatchResult::Failed;
    }
    g_status = status;
    g_code   = (BYTE)code;
    g_send   = (SendFn)Login::Hooks::kSendPacket;
    g_sql    = (SqlFn)Login::Hooks::kSqlBuilder;
    g_worldReal = (void*)Login::Hooks::kSqlBuilder;
    const bool okReply = Hook::Verify(Login::Hooks::kLoginReplyCall, kOrig, sizeof(kOrig));
    const bool okWorld = !g_worldOn || Hook::Verify(Login::Hooks::kSelSoulStateCall, kWorldOrig, sizeof(kWorldOrig));
    if (!okReply || !okWorld)
    {
        wchar_t a[32], b[32];
        Hook::Dump(Login::Hooks::kLoginReplyCall, sizeof(kOrig), a, 32);
        Hook::Dump(Login::Hooks::kSelSoulStateCall, sizeof(kWorldOrig), b, 32);
        Log::Line(L"    L09: оригинал не совпал (0x%08X: %s, ждём e8 0c df 00 00; 0x%08X: %s, ждём e8 21 40 00 00) — пропуск, ничего не записано",
                  Login::Hooks::kLoginReplyCall, a, Login::Hooks::kSelSoulStateCall, b);
        return PatchResult::Mismatch;
    }
    if (!Hook::WriteCall(Login::Hooks::kLoginReplyCall, (void*)&L09_Send, sizeof(kOrig)))
    {
        Log::Line(L"    L09: не удалось записать трамплин на 0x%08X", Login::Hooks::kLoginReplyCall);
        return PatchResult::Failed;
    }
    if (g_worldOn && !Hook::WriteCall(Login::Hooks::kSelSoulStateCall, (void*)&L09_WorldTrampoline, sizeof(kWorldOrig)))
    {
        Hook::WriteBytes(Login::Hooks::kLoginReplyCall, kOrig, sizeof(kOrig));      // откат первой площадки — всё или ничего
        Log::Line(L"    L09: не удалось записать трамплин на 0x%08X — первая площадка возвращена", Login::Hooks::kSelSoulStateCall);
        return PatchResult::Failed;
    }
    g_applied = true;
    // ★ р43б Н-2: режим 2 — в трамплине L04c (до sub_4037B0), если он стоит; иначе — на площадке 0x40B41A номером 0
    g_mateByL04c = g_worldOn && L04c_IsInstalled() != 0;
    L04c_SetMaintGate(g_mateByL04c ? (void*)&L09_MateGate : nullptr);
    // Эту строку читает панель (domains/maint.py, _PS_DLL): «-> L09_Send» + «WorldGate=1» = гейт входа в мир стоит. Не менять без панели.
    Log::Line(L"    L09: отправка 1004 @0x%08X -> L09_Send; статус %d процедуры => 4101 код %d (нотис 7017, без разрыва); "
              L"вход в мир (1016, UPCharSoulState @0x%08X) — %s; соулмейт (режим 2) — %s; сбой гейта — окно %d…%d с; LogPerMinute=%d",
              Login::Hooks::kLoginReplyCall, g_status, (int)g_code, Login::Hooks::kSelSoulStateCall,
              g_worldOn ? L"гейт adm.LoginMaintenanceGate (WorldGate=1, соединение 0)" : L"без гейта (WorldGate=0)",
              !g_worldOn ? L"без гейта" : g_mateByL04c ? L"в L04c до смены личности, обе учётки" : L"без L04c: в режиме закрыт всем",
              g_errSec, g_missingSec, g_logPerMin);
    return PatchResult::Applied;
}
