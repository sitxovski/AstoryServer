// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L06 — ★ ИСПРАВЛЕНИЕ (античит, П5): MAC клиента попадает в `EXEC UPUserLogin`
//        (5-й '%s' = `@Mac VARCHAR(20)`), откуда процедура прокидывает его в
//        `JoyLog1.dbo.UPLoginGame … @Mac` → `LogInfo.Mac`.
//
//  ЭТО НАША ПРАВКА (план `Reports/anticheat/00_PLAN.md`, П5 «MAC в UPUserLogin»).
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Обработчик входа 1003 (`sub_406C20`, LoginManager.c:2582) собирает запрос
//      sub_40F440(ctx, out, 0, a4, dst, "EXEC UPUserLogin '%s','%s','%s', %d, '%s','%s','%s','%s'",
//                 Str, v46, v60, v45, &v33, &v29, &v25, &v16);
//  5-й '%s' — `&v33` (`[ebp-0x2530]`): переменная обнуляется при входе и НИКОГДА не
//  заполняется — в процедуру всегда уходит пустая строка, `LogInfo.Mac` пуст во всех
//  строках (wave_B1: 92 из 92), суточный отчёт «мультиаккаунт» (M8) слеп. При этом сам
//  MAC клиент присылает: cred-блок `Buf1` (243 б, `memcpy(Buf1, a5+33, 0xF3)` @0x406E50),
//  поле `Buf1[113]`, 17 б строкой `xx-xx-xx-xx-xx-xx` (порт `BuildLoginBody` cred+113).
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Та же площадка, что у L03 — `call sub_40F440` @0x407263 — цепочкой (порядок в рантайме всегда L06 → L03):
//      сток:      site → sub_40F440
//      L03:       site → L03_Trampoline → sub_40F440
//      L03+L06:   site → L06_Trampoline → L03_Trampoline → sub_40F440
//      только L06 site → L06_Trampoline → sub_40F440
//  [fix13, 2026-10-13] Результат не зависит от порядка установки: L06 после L03 — забирает площадку и кладёт
//  L03_Trampoline в свой слот g_next (как раньше); L03 после L06 — распознаёт на площадке `call L06_Trampoline` ПО АДРЕСУ,
//  экспортированному L06 (L06_TrampolineAddr, не «любой чужой call»), и встаёт в слот g_next через L06_ChainNext
//  (сравнение с обменом: слот обязан быть sub_40F440). Раньше при L06 раньше L03 у L03 был MISMATCH и отказ по
//  апострофу молча пропадал.
//  Трамплин L06 берёт MAC из кадра вызывающего (`ebp-0x9F` = `Buf1[113]`), санитизирует его
//  в СВОЙ буфер на стеке (17+NUL), перекладывает все 14 аргументов, подменяя 11-й (`&v33`,
//  `[esp+0x2C]`) указателем на этот буфер, и ВЫЗЫВАЕТ (не jmp) следующее звено. Подмена
//  указателя, а не запись в `v33`: в кадре под `v33` ровно 12 б (`char v33; int v34; int v35;
//  __int16 v36;` → `v37` @ebp-0x2524) — 18 б не влезают. Буфер в кадре трамплина живёт до
//  возврата сборщика (`vsprintf` внутри `sub_40F440` — синхронно) и свой у каждого потока
//  (рабочих потоков несколько: `sub_4041B0` → `CreateThread(StartAddress)` в цикле).
//
//  ★ Источник MAC — НЕ «pass+32», как в L01: здесь 2-й аргумент `[esp+0x20]` = `v46`
//    (ebp-0x2508) — КОПИЯ пароля в кадре (36 б, `v46[32]=0`), а не сырой пакет. В L01 второй
//    аргумент пароля в журнале — `&Buf1[81]` (ebp-0xBF), поэтому там `+32` = `Buf1[113]`.
//    Сверено дизасмом: `push 0x20; lea eax,[ebp-0xbf]; lea ecx,[ebp-0x2508]` @0x406FA0.
//
//  ── САНИТИЗАЦИЯ (апостроф L03 для MAC НЕ проверяет — делаем сами) ──
//  Читаем не более 17 байт поля (дальше — соседнее поле, NUL там может не быть). Допустимы
//  только `[0-9a-fA-F-]`; Strict=1 — ровно 17 символов вида `hh-hh-hh-hh-hh-hh`; Lowercase=1 —
//  `A-F` → `a-f` (порт шлёт нижний регистр; единый регистр нужен для группировки в M8).
//  Любое отклонение → пустая строка (ровно то, что уходило в стоке).
//
//  ── ГРАНИЦЫ ──
//  • Процедура не правится: `@Mac VARCHAR(20)` принимает 17 символов как есть
//  • L02 маскирует и этот '%s' в OLEDB_LOG (содержимое всех кавычек) — MAC в лог ошибок не утечёт.
//  • Enabled=0 — цепочка не меняется, в процедуру по-прежнему уходит пустая строка.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

extern "C" void* __cdecl L03_TrampolineAddr();   // l03_login_sql_refuse.cpp: адрес трамплина L03, если он стоит

namespace
{
    bool g_on        = true;
    bool g_strict    = true;    // ровно 17 символов hh-hh-hh-hh-hh-hh
    bool g_lower     = true;    // A-F → a-f
    bool g_logBad    = true;
    long g_logLeft   = 20;

    void* volatile g_next = (void*)Login::Hooks::kSqlBuilder;   // следующее звено: L03_Trampoline или sub_40F440
    bool g_applied = false;                                      // [fix13] L06 стоит на площадке (для L03_* при обратном порядке)

    bool IsHex(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}

// Санитизация поля MAC. src — поле cred-блока (до kMacLen байт, NUL не обязателен),
// dst — буфер ≥ kMacLen+1. Возвращает длину результата (0 — пусто/отброшено).
// Чистая функция, экспонируется для юнит-теста.
extern "C" int __cdecl L06_SanitizeMac(const char* src, char* dst, int strict, int lower)
{
    if (!dst) { return 0; }
    dst[0] = 0;
    if (!src) { return 0; }

    char tmp[Login::Hooks::kMacLen + 1];
    int  n = 0;
    __try
    {
        for (; n < Login::Hooks::kMacLen; ++n)
        {
            const char c = src[n];
            if (c == 0) { break; }
            if (c != '-' && !IsHex(c)) { return 0; }      // мусор/апостроф → пусто
            tmp[n] = (lower && c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;    // негодный указатель — пусто, как в стоке
    }
    tmp[n] = 0;
    if (n == 0) { return 0; }

    if (strict)
    {
        if (n != Login::Hooks::kMacLen) { return 0; }
        for (int i = 0; i < n; ++i)
        {
            const bool dash = (i % 3 == 2);               // позиции 2,5,8,11,14
            if (dash ? (tmp[i] != '-') : !IsHex(tmp[i])) { return 0; }
        }
    }
    for (int i = 0; i <= n; ++i) { dst[i] = tmp[i]; }
    return n;
}

// Заполнение буфера трамплина из кадра обработчика 1003. framebp — ebp вызывающего
// (`sub_406C20`), MAC = ebp - kLoginFrameMac (= Buf1[113]).
extern "C" void __cdecl L06_FillMac(char* dst, const BYTE* framebp)
{
    const char* src = (const char*)(framebp - Login::Hooks::kLoginFrameMac);
    const int n = L06_SanitizeMac(src, dst, g_strict ? 1 : 0, g_lower ? 1 : 0);
    if (n == 0 && g_logBad && InterlockedDecrement(&g_logLeft) >= 0)
    {
        // Проверяем, было ли поле непустым (т.е. отброшено, а не просто пусто у старого клиента).
        bool nonEmpty = false;
        __try { nonEmpty = src[0] != 0; } __except (EXCEPTION_EXECUTE_HANDLER) { nonEmpty = false; }
        if (nonEmpty)
        {
            Log::Line(L"    L06: поле MAC отброшено (недопустимые символы или формат) — в UPUserLogin уходит пусто");
        }
    }
}

namespace
{
    // Трамплин замены `call sub_40F440` на логин-площадке (после L03 — цепочкой).
    // На входе: [esp]=ret, [esp+4..0x38]=14 аргументов сборщика (cdecl, вызывающий снимает 0x38).
    // ebp = кадр sub_406C20 (не трогаем).
    //
    // Выкладка после `sub esp,20`: [esp+0..19] буфер MAC; [esp+20] ret; арг j (1..14) = [esp+20+4j].
    // Перекладка справа налево: после k сделанных push очередной арг j=14-k лежит по
    // [esp+20+4j+4k] = [esp+76] — смещение ПОСТОЯННОЕ. 11-й арг (k=3) → наш буфер = [esp+12].
    __declspec(naked) void L06_Trampoline()
    {
        __asm
        {
            sub  esp, 20                     // локальный буфер MAC (17+NUL, с запасом)
            push ebp                         // framebp
            lea  eax, [esp + 4]              // dst = буфер
            push eax
            call L06_FillMac                 // (dst, framebp) cdecl
            add  esp, 8
            push dword ptr [esp + 76]        // 14: &v16
            push dword ptr [esp + 76]        // 13: &v25
            push dword ptr [esp + 76]        // 12: &v29
            lea  eax, [esp + 12]             // 11: &v33 → НАШ буфер с MAC
            push eax
            push dword ptr [esp + 76]        // 10: v45
            push dword ptr [esp + 76]        //  9: v60 (ip)
            push dword ptr [esp + 76]        //  8: v46 (pass)
            push dword ptr [esp + 76]        //  7: Str (login)
            push dword ptr [esp + 76]        //  6: fmt
            push dword ptr [esp + 76]        //  5: dst (v58)
            push dword ptr [esp + 76]        //  4: a4 (db)
            push dword ptr [esp + 76]        //  3: 0
            push dword ptr [esp + 76]        //  2: out (v57)
            push dword ptr [esp + 76]        //  1: ctx (&unk_43ACD8)
            call dword ptr [g_next]          // L03_Trampoline (→ sub_40F440) или sub_40F440
            add  esp, 0x38                   // снять 14 переложенных аргументов
            add  esp, 20                     // снять буфер
            ret                              // eax — результат сборщика (или 0 от отказа L03)
        }
    }

    const BYTE kOrig[5] = { 0xE8, 0xD8, 0x81, 0x00, 0x00 };   // call 0x40F440 (сток)

    // Ожидаемые байты `call <target>` на площадке.
    void CallBytes(DWORD site, const void* target, BYTE out[5])
    {
        const DWORD rel = (DWORD)target - (site + 5);
        out[0] = 0xE8;
        out[1] = (BYTE)(rel);
        out[2] = (BYTE)(rel >> 8);
        out[3] = (BYTE)(rel >> 16);
        out[4] = (BYTE)(rel >> 24);
    }
}

// Для юнит-теста: подмена следующего звена и адрес трамплина.
extern "C" void  __cdecl L06_TestSetup(void* next, int strict, int lower)
{
    g_next = next; g_strict = strict != 0; g_lower = lower != 0; g_logBad = false;
}
extern "C" void* __cdecl L06_TestGetTrampoline() { return (void*)&L06_Trampoline; }

// [fix13] Для L03 при установке ПОСЛЕ L06: адрес трамплина L06, если он стоит (иначе nullptr) …
extern "C" void* __cdecl L06_TrampolineAddr() { return g_applied ? (void*)&L06_Trampoline : nullptr; }
// … и постановка следующего звена: слот g_next меняется, только если в нём ровно expectOld (сравнение с обменом).
// Возврат 1 — встал. Площадка при этом не переписывается: на ней остаётся `call L06_Trampoline`.
extern "C" int __cdecl L06_ChainNext(void* expectOld, void* newNext)
{
    if (!g_applied || !newNext) { return 0; }
    return InterlockedCompareExchangePointer((PVOID volatile*)&g_next, newNext, expectOld) == expectOld ? 1 : 0;
}

PatchResult L06_LoginMac()
{
    g_applied = false;
    if (!Config::GetBool(L"L06_LoginMac", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_strict = Config::GetBool(L"L06_LoginMac", L"Strict",    true);
    g_lower  = Config::GetBool(L"L06_LoginMac", L"Lowercase", true);
    g_logBad = Config::GetBool(L"L06_LoginMac", L"LogBad",    true);

    const DWORD site = Login::Hooks::kLoginSqlCall;
    const wchar_t* chain = nullptr;
    if (Hook::Verify(site, kOrig, sizeof(kOrig)))
    {
        g_next = (void*)Login::Hooks::kSqlBuilder;              // L03 выключен/не встал — звено сразу сборщик
        chain  = L"sub_40F440 (L03 не стоит)";
    }
    else
    {
        void* l03 = L03_TrampolineAddr();
        BYTE expect[5];
        if (l03) { CallBytes(site, l03, expect); }
        if (l03 && Hook::Verify(site, expect, sizeof(expect)))
        {
            g_next = l03;                                       // цепочка: L06 → L03 → сборщик
            chain  = L"L03_Trampoline → sub_40F440";
        }
        else
        {
            wchar_t hex[32];
            Hook::Dump(site, sizeof(kOrig), hex, 32);
            Log::Line(L"    L06: площадка 0x%08X не сток и не L03 (в образе %s) — пропуск", site, hex);
            return PatchResult::Mismatch;
        }
    }
    if (!Hook::WriteCall(site, (void*)&L06_Trampoline, sizeof(kOrig)))
    {
        Log::Line(L"    L06: не удалось записать трамплин на 0x%08X", site);
        return PatchResult::Failed;
    }
    g_applied = true;
    Log::Line(L"    L06: MAC (Buf1[113] = ebp-0x%X) → 5-й '%%s' EXEC UPUserLogin (@Mac); цепочка: %s; Strict=%d Lowercase=%d",
              Login::Hooks::kLoginFrameMac, chain, g_strict ? 1 : 0, g_lower ? 1 : 0);
    return PatchResult::Applied;
}
