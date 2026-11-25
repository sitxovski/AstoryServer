// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P12 — строка IP по умолчанию в .rdata @0x585610.
//
//  В стоке лежит литерал издателя "61.106.140.206" (14 символов + 2 нулевых
//  байта до следующей строки "GameServer_AR"), то есть слот ровно 16 байт:
//      0x585610: 36 31 2e 31 30 36 2e 31 34 30 2e 32 30 36 00 00
//                 6  1  .  1  0  6  .  1  4  0  .  2  0  6 \0 \0
//  На живом сервере он был заменён на "127.0.0.1".
//
//  Патч пишет значение из ini, дополняя нулями до 16 байт. Максимум 15 символов
//  (16-й байт — обязательный терминатор). Пустое значение = не трогать.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    // "61.106.140.206" + два нулевых байта — полный слот
    const BYTE kOrig[16] =
    {
        '6','1','.','1','0','6','.','1','4','0','.','2','0','6', 0, 0
    };
    constexpr int kSlot = 16;
    constexpr int kMaxChars = kSlot - 1;
}

PatchResult P12_DefaultServerIp()
{
    wchar_t val[64];
    Config::GetStr(L"P12_DefaultServerIp", L"Value", L"", val, ARRAYSIZE(val));
    if (!val[0])
    {
        Log::Line(L"    P12: Value пусто — строка IP оставлена стоковой");
        return PatchResult::Disabled;
    }

    char ansi[64] = {};
    const int n = WideCharToMultiByte(1251, 0, val, -1, ansi, ARRAYSIZE(ansi), "?", nullptr);
    const int len = (n > 0) ? (n - 1) : 0;
    if (len <= 0 || len > kMaxChars)
    {
        Log::Line(L"    P12: значение '%s' не годится (длина %d, максимум %d)",
                  val, len, kMaxChars);
        return PatchResult::Failed;
    }

    const Site sites[] = { { Srv::Hooks::kDefaultIpString, kOrig, kSlot } };
    if (!VerifyAllSites(L"P12", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    BYTE buf[kSlot] = {};
    for (int i = 0; i < len; ++i) { buf[i] = (BYTE)ansi[i]; }
    if (!Hook::WriteBytes(Srv::Hooks::kDefaultIpString, buf, kSlot)) { return PatchResult::Failed; }

    Log::Line(L"    P12: строка IP @0x%08X: \"61.106.140.206\" -> \"%s\"",
              Srv::Hooks::kDefaultIpString, val);
    return PatchResult::Applied;
}
