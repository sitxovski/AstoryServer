// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L05 — ★ ИСПРАВЛЕНИЕ (дефект оригинала): длина MD5-проверки тел 1010 и 1028.
//
//  ЭТО НАША ПРАВКА. Обработчики 1010 (Recv_ClientLogOut, `sub_40D0A0`) и 1028
//  (UPBackUser, `sub_40D310`) проверяют подпись тела так:
//      sub_4060E0(this, pkt, 0x3D, session, 1)   // MD5 по 61 байту с pkt+33 против хеша pkt+17
//  а клиент подписывает ровно 32 байта блока: эталон
//  `Net_Md5Digest16(&g_NetMd5Salt, authPasswordBuf1, 0x20, md5)` (login_charselect.c:1771,
//  пакет 56 б = секрет 8 + MD5 16 + блок 32) и порт `SendSecured(…, LoginCredBlob32, 32)`.
//  61 ≠ 32 ⇒ проверка не сходится НИКОГДА; прежний живой образ обходил её переворотом
//  `jne`→`jmp` @0x40D1F0/@0x40D41E (auth-ip-secret-bypass.md «патчи 3/4»). После отката
//  обхода (12.10.2026) оба опкода отклонялись бы всегда («UPLogoutUser MD5»/«UPBackUser MD5 Error»).
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Причину, а не симптом: байт операнда `push 0x3d` → `push 0x20` на обеих площадках
//  (0x40D1E1 и 0x40D40F). Проверка остаётся включённой и теперь сходится с тем, что
//  шлёт клиент. Аналог — P49 для 5450 (подпись по 0x101). Логин-строка для журналов
//  (`memcpy(v12, pkt+33, 0x3D)`) не трогается.
//
//  ── ГРАНИЦЫ ──
//  • Две однобайтовые замены со сверкой `6a 3d`; Enabled=0 — сток (проверка по 61 байту,
//    т.е. вечный отказ этих опкодов — как в чистом стоке).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

namespace
{
    const BYTE kPushOrig[2] = { 0x6A, 0x3D };   // push 0x3d
}

PatchResult L05_LogoutMd5Len()
{
    if (!Config::GetBool(L"L05_LogoutMd5Len", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const DWORD sites[2] = { Login::Hooks::kLogoutMd5LenPush, Login::Hooks::kBackMd5LenPush };
    const wchar_t* names[2] = { L"1010 Recv_ClientLogOut", L"1028 UPBackUser" };
    int ok = 0, mis = 0;
    for (int i = 0; i < 2; ++i)
    {
        if (!Hook::Verify(sites[i], kPushOrig, sizeof(kPushOrig)))
        {
            wchar_t hex[32];
            Hook::Dump(sites[i], sizeof(kPushOrig), hex, 32);
            Log::Line(L"    L05: оригинал не совпал на 0x%08X (%s) — пропуск (%s)", sites[i], hex, names[i]);
            ++mis;
            continue;
        }
        if (Hook::WriteByteChecked(sites[i] + 1, 0x3D, 0x20))
        {
            Log::Line(L"    L05: %s — MD5 тела считается по 32 байтам (было 61, не сходилось никогда)", names[i]);
            ++ok;
        }
        else { Log::Line(L"    L05: запись не удалась на 0x%08X", sites[i] + 1); ++mis; }
    }
    if (mis > 0 && ok == 0) { return PatchResult::Mismatch; }
    if (ok == 0)            { return PatchResult::Failed; }
    return PatchResult::Applied;
}
