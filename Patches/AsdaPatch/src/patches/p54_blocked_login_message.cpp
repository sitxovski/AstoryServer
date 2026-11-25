// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P54 — ★ СООБЩЕНИЕ ИГРОКУ О БЛОКЕ ПРИ ОТКАЗЕ ВХОДА НА ИГРОВОЙ СЕРВЕР (волна acdb, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Решение владельца 12.10: вход соулмейтом в персонажа заблокированного хозяина —
//  запрет С ВЫВОДОМ СООБЩЕНИЯ игроку. Пара — DBPatch P50 (ключ BlockedClientCode7, метка в ответе 2002/2090).
//  Документ: `AstoryServer/Docs/GameServer/blocked-login-message-p54.md`.
//
//  ── КАК БЫЛО ──
//  P50 (DBManager) при блоке учётки (своей учётки сессии или действующем блоке хозяина персонажа при входе
//  соулмейтом — SQL P51 `UP_AC_IdentityCheck`) отвечает штатной неудачей 2002/2090 `[0] = 0`. GameServer
//  (charLogOnRes@0x5277D0 / CharPortalLogonRes@0x52CF90, ветка «CharInfo DB Receive Error») шлёт клиенту
//  4101 с кодом 5. Эталон клиента (game_main.c:5915-5960, `g_nDisconnectReason`) на код 5 показывает
//  loc 8509 «Подключение прервано: недостаточно данных» — игрок не понимает, что случилось.
//
//  ── ШТАТНЫЙ КОД ОРИГИНАЛА ──
//  Блок учётки у оригинала — 4101 с кодом 7 (LoginManager: UPUserLogin Flag 5 → 4101/7, LoginManager.c:2694).
//  Эталон на код 7 показывает loc 1107 «Ты не можешь подключиться: учетная запись заблокирована.» (тот же путь
//  g_nDisconnectReason 3..12 → GameUI_UpdateByGameState + Show_DisconnectPopup). Порт: AsdaLoginGameMode.cpp
//  BuildKickText и AsdaDisconnectPopupSubsystem.cpp — код 7 → 1107 в обоих путях. Протокол клиента НЕ меняется,
//  правка клиента порта не нужна.
//
//  ── ЧТО ДЕЛАЕМ ──
//  P50 при отказе ИМЕННО по блоку кладёт в тело 2002/2090 метку: [1..4] = 'P54B', [5] = 1 (байт [0] = 0, как
//  было; сток GameServer в ветке неудачи читает только [0]). Здесь вместо `push 5` в двух ветках неудачи —
//  стаб: метка есть → `push 7`, иначе `push 5` (как сток). Прочие отказы P50 (IP, сессия, слот) — код 5 как было.
//  Площадки (байты стока = живой GameServer = живой Indun e7b4ac38; входов внутрь нет — verify_acdb.py):
//     0x00527907  6A05 668B4508   (6 б: push 5 / mov ax,[ebp+8]) — charLogOnRes, тело ответа в [ebp-0x120]
//     0x0052D07A  6A05 668B4D08   (6 б: push 5 / mov cx,[ebp+8]) — CharPortalLogonRes, тело в [ebp-0x118]
//  Возврат: 0x0052790D / 0x0052D080 (`push eax` / `push ecx` перед вызовом Send_DisConnectType).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P54_BlockedLoginMessage";
    constexpr DWORD kMagic = 0x42343550;   // 'P54B' (байты 50 35 34 42) — метка P50 в теле 2002/2090
    volatile LONG g_code7 = 0;              // сколько раз отдан код 7
}

// Код 4101 для ветки «CharInfo DB Receive Error»: 7 — отказ P50 по блоку (метка), иначе 5 (сток).
extern "C" int __stdcall P54_KickCode(const BYTE* body)
{
    __try
    {
        DWORD m; memcpy(&m, body + 1, 4);
        if (body[0] == 0 && m == kMagic && body[5] == 1)
        {
            InterlockedIncrement(&g_code7);
            return 7;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 5;
}

namespace
{
    DWORD g_ret4001 = 0x0052790D;   // после вытесненных `push 5 / mov ax,[ebp+8]`
    DWORD g_ret2089 = 0x0052D080;   // после вытесненных `push 5 / mov cx,[ebp+8]`

    __declspec(naked) void Code4001Stub()
    {
        __asm
        {
            pushad
            lea   eax, [ebp-0x120]                 // тело DB-ответа 2002 (memcpy 0x109 б)
            push  eax
            call  P54_KickCode                     // __stdcall, 4 б
            mov   dword ptr [esp+28], eax          // результат → сохранённый eax
            popad
            push  eax                              // код кика (вместо `push 5`)
            mov   ax, word ptr [ebp+8]             // вытеснено
            jmp   dword ptr [g_ret4001]
        }
    }

    __declspec(naked) void Code2089Stub()
    {
        __asm
        {
            pushad
            lea   eax, [ebp-0x118]                 // тело DB-ответа 2090 (memcpy 0x106 б)
            push  eax
            call  P54_KickCode
            mov   dword ptr [esp+28], eax
            popad
            push  eax
            mov   cx, word ptr [ebp+8]             // вытеснено
            jmp   dword ptr [g_ret2089]
        }
    }

    const BYTE kOrig4001[6] = { 0x6A, 0x05, 0x66, 0x8B, 0x45, 0x08 };
    const BYTE kOrig2089[6] = { 0x6A, 0x05, 0x66, 0x8B, 0x4D, 0x08 };
}

PatchResult P54_BlockedLoginMessage()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    const Site sites[] =
    {
        { 0x00527907, kOrig4001, sizeof(kOrig4001) },
        { 0x0052D07A, kOrig2089, sizeof(kOrig2089) },
    };
    if (!VerifyAllSites(L"P54", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(0x00527907, &Code4001Stub, sizeof(kOrig4001))) { return PatchResult::Failed; }
    if (!Hook::WriteJmp(0x0052D07A, &Code2089Stub, sizeof(kOrig2089))) { return PatchResult::Failed; }
    Log::Line(L"    P54: отказ P50 по блоку учётки -> 4101 код 7 (loc 1107 «учетная запись заблокирована»), "
              L"прочие отказы — код 5 как в стоке; площадок 2 из 2");
    return PatchResult::Applied;
}
