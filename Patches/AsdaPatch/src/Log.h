// Copyright (c) 2026 @sitxovski (Discord)
// Log.h — лог установки патчей: <GameServer>\Log\Log_Patch\PatchLog_<ГГГГММДД>.txt
// Кодировка файла — cp1251 (как у остальных логов сервера).
#pragma once
#include <windows.h>

namespace Log
{
    // Инициализация. baseDir — папка GameServer.exe (с завершающим '\').
    // ★ product — имя в шапке журнала. По умолчанию "AsdaPatch" (GameServer);
    //   AddonNPC передаёт своё. Параметр добавлен 24.08.2026, когда файл стал общим
    //   для двух DLL: иначе журнал боевого сервера представлялся чужим именем.
    void Init(const wchar_t* baseDir, bool enabled, const wchar_t* product = L"AsdaPatch");
    void Line(const wchar_t* fmt, ...);
    void Close();

    // Счётчики итога
    void CountOk();
    void CountSkip();
    void CountFail();
    int  Ok();
    int  Skip();
    int  Fail();
}
