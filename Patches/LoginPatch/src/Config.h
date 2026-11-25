// Copyright (c) 2026 @sitxovski (Discord)
// Config.h — <LoginManager>\ConfigSet\patches.ini (штатные Win-ini API).
//
// Полный близнец `AddonNPC/src/Config.h`.
// ★ БЕРЕЖНОЕ СЛИЯНИЕ. Файл НИКОГДА не перезаписывается целиком, если он уже есть:
//   • существующие значения сохраняются как есть — правки администратора не теряются;
//   • отсутствующая СЕКЦИЯ дописывается в конец файла вместе с комментариями;
//   • отсутствующий КЛЮЧ вставляется в свою секцию через WritePrivateProfileString;
//     пользовательские значения остаются нетронутыми.
//   Всё добавленное перечисляется в PatchLog.
//
// ⚠ Не путать с `<LoginManager>\Patch.ini` — это настройки штатного автообновления
//   оригинала (адрес FTP, папка выкладки); наш файл лежит в ConfigSet и называется иначе.
#pragma once
#include <windows.h>

namespace Config
{
    // Текущая версия формата. Повышать при добавлении ключей.
    //   1 — заготовка: только [General] (12.10.2026)
    //   2 — добавлена секция [L01_LoginLogMask] (12.10.2026)
    //   3 — добавлена секция [L03_LoginSqlRefuse] (12.10.2026)
    //   4 — добавлена секция [L02_LoginSqlLogMask] (12.10.2026)
    //   5 — добавлена секция [L04_LoginIdentity] (12.10.2026)
    //   6 — ключи CheckSoulMate/SoulMateFailOpen в [L04_LoginIdentity] + секция [L05_LogoutMd5Len] (12.10.2026)
    //   7 — L06 + L07: секции [L06_LoginMac] и [L07_TrafficEncryption] (12.10.2026)
    //   8 — sec2b: ключ MaxPendingPerIp в [L07_TrafficEncryption] (15.10.2026; откат — DLL v7 понизит Version, ключ проигнорирует)
    //   9 — L08: секция [L08_ListenArrayLeak] (27.10.2026; откат — DLL v8 понизит Version, секцию проигнорирует)
    //   10 — P125: секция [P125_DbReconnect] (15.11.2026; откат — DLL v9 понизит Version, секцию проигнорирует)
    //   11 — L09: секция [L09_LoginMaintenance] (21.11.2026; откат — DLL v10 понизит Version, секцию проигнорирует)
    constexpr int kVersion = 11;

    // baseDir — папка LoginManager.exe (с завершающим '\'). Возвращает false, если ini
    // не удалось ни прочитать, ни создать (тогда работаем на умолчаниях).
    bool Init(const wchar_t* baseDir);

    const wchar_t* Path();      // полный путь patches.ini
    const wchar_t* BaseDir();   // папка LoginManager.exe (с завершающим '\')
    bool WasCreated();          // файл создан этим запуском

    int  GetInt (const wchar_t* section, const wchar_t* key, int def);
    bool GetBool(const wchar_t* section, const wchar_t* key, bool def);
    void GetStr (const wchar_t* section, const wchar_t* key, const wchar_t* def,
                 wchar_t* out, int cch);

    // Досоздание недостающих секций/ключей. Вызывается ПОСЛЕ Log::Init,
    // чтобы всё добавленное попало в лог.
    void MergeMissing();
}
