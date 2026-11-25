// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L03 — ★ ИСПРАВЛЕНИЕ (безопасность): отказ по апострофу в логине/пароле
//        ещё до сборки SQL-строки. Второй рубеж к проверке в хранимой процедуре.
//
//  ЭТО НАША ПРАВКА. Образец подхода — P28 (`DBPatch/src/p28_sql_arg_escape.cpp`),
//  но стратегия иная: P28 ЭКРАНИРУЕТ апостроф в любых запросах DBManager, а здесь
//  мы ОТКАЗЫВАЕМ во входе — логин и пароль апострофов не содержат никогда,
//  поэтому апостроф = попытка инъекции, и вход отклоняется целиком.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Обработчик входа 1003 строит SQL так (sub_406C20, LM:2582):
//      sub_40F440(ctx, out, 0, a4, dst,
//                 "EXEC UPUserLogin '%s','%s','%s', %d, '%s','%s','%s','%s'",
//                 login, pass, ip, …);
//  а внутри `sub_40F440` — `vsprintf`. Логин/пароль из пакета подставляются в
//  одинарные кавычки БЕЗ экранирования: апостроф закрывает литерал, остаток уходит
//  в SQL Server как КОД. Клиентского фильтра на эти поля в срезе нет.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Перехватываем ровно ЭТОТ `call sub_40F440` @0x407263 (5 байт). Трамплин смотрит
//  логин и пароль (1-й и 2-й `%s`): если хоть в одном есть апостроф — НЕ зовёт
//  сборщик вообще, ставит `*out = 0` и возвращает 0. Обработчик входа при `out==0`
//  уходит в штатную ветку «UPUserLogin Error» (отказ клиенту) — ровно как при любой
//  другой неуспешной сборке запроса. Иначе — хвостовой переход в настоящий сборщик,
//  стек не тронут (`add esp,0x38` вызывающего снимает 14 аргументов, как и прежде).
//
//  ── ГРАНИЦЫ ──
//  • Хук стоит ТОЛЬКО на логин-запросе — остальные запросы (где апостроф легитимен:
//    имена, заметки) не затрагиваются. В этом отличие от хука на входе сборщика.
//  • Сканирование логина/пароля — до нуля и не дальше kMaxScan; записи никуда нет.
//  • Enabled=0 — хук не ставится, поведение стоковое.
//  • [fix13, 2026-10-13] Площадку делит L06 (MAC → @Mac). Порядок установки не важен: L06 после L03 — цепочка
//    site → L06 → L03 → sub_40F440 (L06 кладёт L03_Trampoline в свой слот); L03 после L06 — L03 распознаёт на площадке
//    `call L06_Trampoline` ПО АДРЕСУ, экспортированному L06 (L06_TrampolineAddr; любой другой чужой call — MISMATCH,
//    как раньше), и встаёт в слот L06 через L06_ChainNext(sub_40F440 → L03_Trampoline). Итог тот же: L06 → L03 → сборщик.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

extern "C" void* __cdecl L06_TrampolineAddr();                        // l06_login_mac.cpp: трамплин L06, если он стоит
extern "C" int   __cdecl L06_ChainNext(void* expectOld, void* newNext); // l06_login_mac.cpp: встать в слот «следующее звено» L06

namespace
{
    bool g_on       = true;
    int  g_maxScan  = 256;    // логин ≤61, пароль =32 — с запасом
    bool g_logHits  = true;
    long g_logLeft  = 20;

    void* g_realBuilder = (void*)Login::Hooks::kSqlBuilder;   // 0x40F440

    const char kQuote = 0x27;   // '

    bool HasQuote(const char* s, int maxScan)
    {
        if (!s) { return false; }
        for (int i = 0; i < maxScan; ++i)
        {
            const char c = s[i];
            if (c == 0)      { return false; }
            if (c == kQuote) { return true; }
        }
        return false;
    }
}

// Возвращает 1 — отказать во входе (апостроф в логине или пароле), иначе 0.
// Экспонируется для юнит-теста.
extern "C" int __cdecl L03_ShouldRefuse(const char* login, const char* pass)
{
    int refuse = 0;
    __try
    {
        refuse = (HasQuote(login, g_maxScan) || HasQuote(pass, g_maxScan)) ? 1 : 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        refuse = 0;   // негодный указатель — пусть сток решает (не ужесточаем вслепую)
    }
    if (refuse && g_logHits && InterlockedDecrement(&g_logLeft) >= 0)
    {
        // Сам текст логина НЕ печатаем — только факт отказа.
        Log::Line(L"    L03: вход отклонён — апостроф в логине или пароле (возможная инъекция)");
    }
    return refuse;
}

namespace
{
    // Трамплин замены `call sub_40F440` на логин-площадке.
    // На входе (после нашего call): [esp]=ret, [esp+8]=out, [esp+0x1C]=login, [esp+0x20]=pass.
    __declspec(naked) void L03_Trampoline()
    {
        __asm
        {
            mov  eax, [esp + 0x20]       // pass
            push eax
            mov  eax, [esp + 0x20]       // login (esp уже -4 ⇒ бывший +0x1C)
            push eax
            call L03_ShouldRefuse        // (login, pass) cdecl
            add  esp, 8
            test eax, eax
            jnz  _refuse
            jmp  dword ptr [g_realBuilder]   // хвостовой вызов стокового сборщика
        _refuse:
            mov  eax, [esp + 0x08]       // out (a2)
            mov  dword ptr [eax], 0      // *out = 0 — штатный отказ входа
            xor  eax, eax
            ret
        }
    }

    const BYTE kOrig[5] = { 0xE8, 0xD8, 0x81, 0x00, 0x00 };   // call 0x40F440
    bool g_applied = false;
}

// Адрес трамплина, если L03 поставлен (иначе nullptr). Нужен L06: он делит эту же площадку
// и встаёт ПОСЛЕ L03 цепочкой (site → L06 → L03 → sub_40F440), сверяя, что на площадке
// стоит именно `call L03_Trampoline`.
extern "C" void* __cdecl L03_TrampolineAddr() { return g_applied ? (void*)&L03_Trampoline : nullptr; }
// Для юнит-теста цепочки L06→L03: адрес трамплина без установки и подмена сборщика стабом.
extern "C" void* __cdecl L03_TestGetTrampoline() { return (void*)&L03_Trampoline; }
extern "C" void  __cdecl L03_TestSetup(void* builder) { g_realBuilder = builder; g_logHits = false; }

PatchResult L03_LoginSqlRefuse()
{
    g_applied = false;
    if (!Config::GetBool(L"L03_LoginSqlRefuse", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_maxScan = Config::GetInt(L"L03_LoginSqlRefuse", L"MaxScan", 256);
    if (g_maxScan < 32)   { g_maxScan = 32; }
    if (g_maxScan > 4096) { g_maxScan = 4096; }
    g_logHits = Config::GetBool(L"L03_LoginSqlRefuse", L"LogHits", true);

    g_realBuilder = (void*)Login::Hooks::kSqlBuilder;
    if (!Hook::Verify(Login::Hooks::kLoginSqlCall, kOrig, sizeof(kOrig)))
    {
        // [fix13] Площадку уже занял L06 (поставлен раньше)? Узнаём ЕГО трамплин по экспортированному адресу.
        const DWORD site = Login::Hooks::kLoginSqlCall;
        void* l06 = L06_TrampolineAddr();
        BYTE expect[5] = { 0xE8, 0, 0, 0, 0 };
        if (l06) { *(DWORD*)(expect + 1) = (DWORD)l06 - (site + 5); }
        if (l06 && Hook::Verify(site, expect, sizeof(expect)))
        {
            if (L06_ChainNext((void*)Login::Hooks::kSqlBuilder, (void*)&L03_Trampoline))
            {
                g_applied = true;
                Log::Line(L"    L03: апостроф в логине/пароле — отказ входа (до сборки SQL); площадка 0x%08X занята L06 — "
                          L"цепочка L06_Trampoline → L03_Trampoline → sub_40F440", site);
                return PatchResult::Applied;
            }
            Log::Line(L"    L03: на площадке 0x%08X L06, но его следующее звено не sub_40F440 — пропуск", site);
            return PatchResult::Mismatch;
        }
        wchar_t hex[32];
        Hook::Dump(Login::Hooks::kLoginSqlCall, sizeof(kOrig), hex, 32);
        Log::Line(L"    L03: оригинал не совпал на 0x%08X (в образе %s) — пропуск",
                  Login::Hooks::kLoginSqlCall, hex);
        return PatchResult::Mismatch;
    }
    if (!Hook::WriteCall(Login::Hooks::kLoginSqlCall, (void*)&L03_Trampoline, sizeof(kOrig)))
    {
        Log::Line(L"    L03: не удалось записать трамплин на 0x%08X", Login::Hooks::kLoginSqlCall);
        return PatchResult::Failed;
    }
    g_applied = true;
    Log::Line(L"    L03: апостроф в логине/пароле — отказ входа (до сборки SQL)");
    return PatchResult::Applied;
}
