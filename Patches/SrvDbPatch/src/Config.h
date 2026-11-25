// Copyright (c) 2026 @sitxovski (Discord)
// Config.h — <папка сервера>\ConfigSet\srvdbpatch.ini (штатные Win-ini API).
//
// Близнец `LoginPatch/src/Config.h` (та же механика бережного слияния; файл никогда не перезаписывается целиком,
// недостающие секции/ключи дописываются, правки администратора сохраняются, всё добавленное — в PatchLog).
// Свой ini у КАЖДОЙ папки сервера: RelayServer, Indun_RelayServer, Ch2_RelayServer, ItemRelayServer, OperationServer.
//
// ⚠ Не путать с `<папка сервера>\Patch.ini` — это настройки штатного автообновления оригинала
//   (RelayServer_Loader.exe и т.п.); наш файл лежит в ConfigSet и называется иначе.
#pragma once
#include <windows.h>

namespace Config
{
    // Текущая версия формата. Повышать при добавлении ключей.
    //   1 — первая сборка: [General] + [P126_DbReconnect] (15.11.2026)
    constexpr int kVersion = 1;

    // baseDir — папка exe (с завершающим '\'). false — ini не удалось ни прочитать, ни создать (работаем на умолчаниях).
    bool Init(const wchar_t* baseDir);

    const wchar_t* Path();      // полный путь srvdbpatch.ini
    const wchar_t* BaseDir();   // папка exe (с завершающим '\')
    bool WasCreated();          // файл создан этим запуском

    int  GetInt (const wchar_t* section, const wchar_t* key, int def);
    bool GetBool(const wchar_t* section, const wchar_t* key, bool def);

    // Досоздание недостающих секций/ключей. Вызывается ПОСЛЕ Log::Init, чтобы всё добавленное попало в лог.
    void MergeMissing();
}
