// Copyright (c) 2026 @sitxovski (Discord)
// Patches.h — реестр патчей SrvDbPatch (RelayServer / ItemRelayServer / OperationServer).
// Форма записи и результат — 1:1 с LoginPatch/src/patches/Patches.h.
#pragma once
#include <windows.h>

// Результат установки одного патча.
enum class PatchResult
{
    Applied,        // поставлен
    Disabled,       // выключен в ini
    Mismatch,       // оригинальные байты не совпали — НЕ поставлен
    Failed          // ошибка записи/доступа — НЕ поставлен
};

struct PatchEntry
{
    const wchar_t* section;     // секция в srvdbpatch.ini
    const wchar_t* title;       // краткое описание для лога
    PatchResult  (*apply)();    // сам патч: читает ini, сверяет байты, пишет
    // Для каких образов патч предназначен: имена exe через ';', в нижнем регистре.
    const wchar_t* hosts;
};

extern const PatchEntry* g_patches;
extern const int         g_patchCount;

// ── реализации патчей ───────────────────────────────────────────────────────
PatchResult P126_DbReconnect();      // ★ [ОРИГИНАЛ] после обрыва связи с SQL Server сессия открывается заново, запрос повторяется один раз
