// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P125 — ★ ИСПРАВЛЕНИЕ (дефект оригинала): LoginManager после обрыва связи с SQL Server
//  открывает сессию заново и повторяет запрос один раз.
//
//  ЭТО НАША ПРАВКА (15.11.2026). Причина, разбор и границы — в общем модуле
//  `..\DbReconnect\src\DbReconnectCore.cpp` и в `AstoryServer\Docs\_Common\db-reconnect-p125.md`.
//
//  ── ПЛОЩАДКА ──
//  Функция запроса sub_40F440 (0x40F440), вызов ICommand::Execute (единственный в образе):
//      0x0040F7A6   ; vtbl = *cmd ; push cmd
//      0x0040F7A9  8b 42 10 ff d0   ; ← 5 байт: call DbReconnect::ExecuteHook
//      0x0040F7AE   mov [ebp-0x1024], eax
//  ExecuteHook имеет соглашение Execute (6 аргументов, стек чистит вызываемый) и сам зовёт
//  Execute той же команды, поэтому стек, eax и ebp после площадки — ровно как в стоке.
//  Запись сессии находится по адресу поля результата (6-й аргумент = запись + 8): объект класса
//  лежит по 0x0043ACD8, источник 0x14410 б, сессия 0x2050 б со смещения 0xF0.
//
//  ── СВЕРКА ПЕРЕД УСТАНОВКОЙ ──
//  Кроме пяти байт площадки сверяются: соседние команды, `lea` адреса поля результата (+0xF8),
//  CLSID поставщика в образе (MSDASQL). Не совпало хоть что-то — MISMATCH, патч не ставится.
//
//  ── СОСЕДИ ──
//  L02 — детур @0x40F5C2 в той же функции (раньше по коду, не пересекается); бинарный P17 @0x40F5BC;
//  L03/L06 — вызов sub_40F440 @0x407263 (снаружи функции).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "DbReconnectCore.h"

namespace
{
    const wchar_t* const kSection = L"P125_DbReconnect";

    const DWORD kSiteVa   = 0x0040F7A9;   // mov r32,[vtbl+0x10] ; call r32
    const DWORD kCtxAVa   = 0x0040F7A6;   // mov r32,[cmd] ; push cmd
    const DWORD kCtxBVa   = 0x0040F7AE;   // mov [ebp-0x1024], eax
    const DWORD kLeaVa    = 0x0040F740;   // lea r32,[источник + сессия + 0xF8] — адрес поля результата
    const DWORD kClsidVa  = 0x004309C0;   // CLSID поставщика, который сток отдаёт CoCreateInstance
    const DWORD kObjBase  = 0x0043ACD8;   // объект класса работы с базой

    const BYTE kOrig[5]   = { 0x8B, 0x42, 0x10, 0xFF, 0xD0 };
    const BYTE kCtxA[3]   = { 0x8B, 0x10, 0x51 };
    const BYTE kCtxB[6]   = { 0x89, 0x85, 0xDC, 0xEF, 0xFF, 0xFF };
    const BYTE kLea[7]    = { 0x8D, 0x84, 0x11, 0xF8, 0x00, 0x00, 0x00 };
    const BYTE kClsid[16] = { 0xCB, 0x22, 0xB5, 0xC8, 0xF3, 0x5C, 0xCE, 0x11,
                              0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D };   // {C8B522CB-5CF3-11CE-ADE5-00AA0044773D} MSDASQL

    void LogSink(const wchar_t* line)
    {
        Log::Line(L"%s", line);
    }
}

// Счётчики для стенда и разбора на живом процессе.
extern "C" __declspec(dllexport) void __stdcall P125_GetStats(DbReconnect::Stats* out)
{
    DbReconnect::GetStats(out);
}

PatchResult P125_DbReconnect()
{
    if (!Config::GetBool(kSection, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    DbReconnect::Settings st;
    st.retry             = Config::GetBool(kSection, L"Retry", true);
    st.probe             = Config::GetBool(kSection, L"Probe", true);
    st.releaseOld        = Config::GetBool(kSection, L"ReleaseOld", true);
    st.comInit           = Config::GetBool(kSection, L"ComInit", true);
    st.retryIntervalMs   = Config::GetInt (kSection, L"RetryIntervalMs", 10000);
    st.connectTimeoutSec = Config::GetInt (kSection, L"ConnectTimeoutSec", 5);
    st.logPerMinute      = Config::GetInt (kSection, L"LogPerMinute", 30);

    const Site sites[] =
    {
        { kSiteVa,  kOrig,  sizeof(kOrig)  },
        { kCtxAVa,  kCtxA,  sizeof(kCtxA)  },
        { kCtxBVa,  kCtxB,  sizeof(kCtxB)  },
        { kLeaVa,   kLea,   sizeof(kLea)   },
        { kClsidVa, kClsid, sizeof(kClsid) },
    };
    if (!VerifyAllSites(L"P125", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    const DbReconnect::Host host = { kObjBase, L"P125" };
    DbReconnect::Configure(host, st, &LogSink);

    if (!Hook::WriteCall(kSiteVa, &DbReconnect::ExecuteHook, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P125: вызов Execute @0x%08X (5 б) -> DbReconnect::ExecuteHook 0x%08X; объект 0x%08X",
              kSiteVa, (DWORD)&DbReconnect::ExecuteHook, kObjBase);
    Log::Line(L"    P125: обрыв связи с базой -> сессия открывается заново%s; Probe=%d ReleaseOld=%d ComInit=%d "
              L"RetryIntervalMs=%d ConnectTimeoutSec=%d LogPerMinute=%d",
              st.retry ? L", запрос повторяется один раз" : L", запрос не повторяется (Retry=0)",
              st.probe ? 1 : 0, st.releaseOld ? 1 : 0, st.comInit ? 1 : 0, st.retryIntervalMs, st.connectTimeoutSec, st.logPerMinute);
    return PatchResult::Applied;
}
