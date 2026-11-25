// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L02 — ★ ИСПРАВЛЕНИЕ (безопасность): маскировка текста `EXEC UPUserLogin …`
//        в журнале ошибок базы (OLEDB_LOG).
//
//  ЭТО НАША ПРАВКА.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Сборщик SQL `sub_40F440@0x40F440` при ошибке исполнения пишет ПОЛНЫЙ текст
//  запроса в журнал:
//      sub_410C00(…, "%s :: Execute Error", MultiByteStr);
//      sub_4128E0("DBSourceNum = %d, SessionNum = %d, %s", a3, a4, MultiByteStr);
//  Для запроса входа `MultiByteStr` = «EXEC UPUserLogin 'логин','<MD5>','<ip>', …,
//  '<MAC>' …» ⇒ логин, MD5 пароля (без соли), IP и MAC попадают в OLEDB_LOG
//  открытым текстом при любой ошибке базы на входе.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Врезка СРАЗУ ПОСЛЕ `MultiByteToWideChar` (@0x40F5BC — трамплин P17): к этому
//  моменту ШИРОКИЙ буфер уже построен и именно он исполняется, а узкий `MultiByteStr`
//  (ebp-0x1020) дальше нужен ТОЛЬКО для логов. Маскируем узкий буфер на месте:
//  если это запрос `UPUserLogin`, заменяем содержимое всех `'…'` на звёздочки
//  (форма запроса и длина сохраняются). Исполнение (из широкого буфера) не затронуто.
//
//  ── ГРАНИЦЫ ──
//  • Маска включается ТОЛЬКО если текст содержит «UPUserLogin» — остальные запросы
//    в логах не меняются.
//  • Правится локальный стековый буфер этой сессии; общей памяти нет (потокобезопасно).
//  • Таблицы и широкий буфер не трогаются; уже исполнённый запрос прежний.
//  • Enabled=0 — врезка не ставится, журнал стоковый.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

namespace
{
    bool g_on      = true;
    long g_logLeft = 20;
    bool g_logHits = true;

    void* g_ret = (void*)Login::Hooks::kSqlMaskRet;   // 0x40F5C8

    const char kQuote = 0x27;   // '

    // Есть ли подстрока needle в первых maxScan байтах s (до нуля).
    const char* FindIn(const char* s, const char* needle, int maxScan)
    {
        if (!s || !needle) { return nullptr; }
        const int nl = (int)lstrlenA(needle);
        for (int i = 0; i < maxScan; ++i)
        {
            if (s[i] == 0) { return nullptr; }
            int k = 0;
            for (; k < nl && s[i + k]; ++k) { if (s[i + k] != needle[k]) { break; } }
            if (k == nl) { return s + i; }
        }
        return nullptr;
    }
}

// Маскирует содержимое всех `'…'` в SQL-тексте, если это запрос UPUserLogin.
// Длина строки сохраняется (замена символ-в-символ). Экспонируется для юнит-теста.
extern "C" void __cdecl L02_MaskIfLogin(char* sql)
{
    __try
    {
        if (!FindIn(sql, "UPUserLogin", 4096)) { return; }
        bool inQuote = false;
        int  masked  = 0;
        for (int i = 0; i < 4096; ++i)
        {
            const char c = sql[i];
            if (c == 0) { break; }
            if (c == kQuote) { inQuote = !inQuote; continue; }   // кавычки оставляем
            if (inQuote) { sql[i] = '*'; ++masked; }
        }
        if (masked > 0 && g_logHits && InterlockedDecrement(&g_logLeft) >= 0)
        {
            Log::Line(L"    L02: в журнале базы замаскирован запрос входа (символов: %d)", masked);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Негодный буфер — молча выходим, пусть сток логирует как есть.
    }
}

namespace
{
    // Врезка после MultiByteToWideChar. Воспроизводит затёртую инструкцию,
    // затем маскирует MultiByteStr (ebp-0x1020) и возвращается.
    __declspec(naked) void L02_Trampoline()
    {
        __asm
        {
            mov  dword ptr [ebp - 0x1028], eax   // затёртая: mov [ebp-0x1028],eax (хранит длину MBTWC)
            pushad
            pushfd
            lea  eax, [ebp - 0x1020]             // MultiByteStr
            push eax
            call L02_MaskIfLogin
            add  esp, 4
            popfd
            popad
            jmp  dword ptr [g_ret]               // 0x40F5C8
        }
    }

    const BYTE kOrig[6] = { 0x89, 0x85, 0xD8, 0xEF, 0xFF, 0xFF };   // mov [ebp-0x1028],eax
}

PatchResult L02_LoginSqlLogMask()
{
    if (!Config::GetBool(L"L02_LoginSqlLogMask", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_logHits = Config::GetBool(L"L02_LoginSqlLogMask", L"LogHits", true);

    if (!Hook::Verify(Login::Hooks::kSqlAfterMbtwc, kOrig, sizeof(kOrig)))
    {
        wchar_t hex[32];
        Hook::Dump(Login::Hooks::kSqlAfterMbtwc, sizeof(kOrig), hex, 32);
        Log::Line(L"    L02: оригинал не совпал на 0x%08X (в образе %s) — пропуск",
                  Login::Hooks::kSqlAfterMbtwc, hex);
        return PatchResult::Mismatch;
    }
    g_ret = (void*)Login::Hooks::kSqlMaskRet;
    // jmp rel32 (5 б) + nop (1 б) — ровно длина затёртой инструкции (6 б).
    if (!Hook::WriteJmp(Login::Hooks::kSqlAfterMbtwc, (void*)&L02_Trampoline, sizeof(kOrig)))
    {
        Log::Line(L"    L02: не удалось записать врезку на 0x%08X", Login::Hooks::kSqlAfterMbtwc);
        return PatchResult::Failed;
    }
    Log::Line(L"    L02: текст запроса входа в журнале базы маскируется");
    return PatchResult::Applied;
}
