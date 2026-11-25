// Copyright (c) 2026 @sitxovski (Discord)
// Patches.h — реестр патчей LoginPatch. Каждый патч живёт в своём .cpp и регистрируется
// в Registry.cpp.
//
// Полный близнец `AddonNPC/src/patches/Patches.h`: та же форма записи, тот же результат.
// Отличие одно — здесь патчи для LoginManager.exe.
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
    const wchar_t* section;     // секция в patches.ini
    const wchar_t* title;       // краткое описание для лога
    PatchResult  (*apply)();    // сам патч: читает ini, сверяет байты, пишет
    // Для каких образов патч предназначен: имена exe через ';', в нижнем регистре.
    // nullptr = только LoginManager.exe.
    const wchar_t* hosts;
};

extern const PatchEntry* g_patches;
extern const int         g_patchCount;

// ── реализации патчей ───────────────────────────────────────────────────────
PatchResult L01_LoginLogMask();      // маскировка хеша пароля в журнале входа + MAC отдельным полем
PatchResult L02_LoginSqlLogMask();   // маскировка текста EXEC UPUserLogin в журнале ошибок базы
PatchResult L03_LoginSqlRefuse();    // отказ входа при апострофе в логине/пароле (до сборки SQL)
PatchResult L04_LoginIdentity();     // привязка UserIndex к сессии: 1005 + 1016 режимы 0/1 («душа») + режим 2 (соулмейт, MateUserindex)
PatchResult L05_LogoutMd5Len();      // 1010/1028: длина MD5-проверки тела 61 → 32 (как подписывает клиент)
PatchResult L06_LoginMac();          // MAC клиента (Buf1[113]) → 5-й '%s' EXEC UPUserLogin (@Mac → LogInfo.Mac); цепочкой после L03
PatchResult L07_TrafficEncryption(); // прослойка шифрования трафика (ECDH+ECDSA+AES-256-GCM), Enabled=0 по умолчанию
PatchResult P125_DbReconnect();      // ★ [ОРИГИНАЛ] после обрыва связи с SQL Server сессия открывается заново, запрос повторяется один раз
PatchResult L08_ListenArrayLeak();   // ★ [ОРИГИНАЛ] утечка массива подключений: дубли слота, ранний разрыв, самоочистка перед пинг-сторожем
PatchResult L09_LoginMaintenance();  // режим обслуживания: статус 28 UPUserLogin → стоковый отказ 4101/28 (нотис 7017) вместо 1004/28
