// Copyright (c) 2026 @sitxovski (Discord)
// Log.h — журнал AsdaEacServer: logs\eac_YYYYMMDD.log (UTF-8), смена файла в полночь, копия в консоль.
// Потокобезопасен (нить ядра, нити AsdaId и колбэк журнала EOS пишут одновременно).
// ⚠ Секреты (ClientSecret, пароли, MD5 паролей, токены целиком) в журнал НЕ пишутся — вызывающие стороны
//   пишут только jti / префикс SHA-256 refresh-токена.
#pragma once
#include <string>

namespace Eac { namespace Log
{
    // Уровни журнала (чем больше — тем подробнее).
    enum Level : int { Error = 0, Warn = 1, Info = 2, Debug = 3 };

    // Открыть журнал: dir — папка (создаётся), console — дублировать в stdout, level — порог записи.
    bool Init(const std::wstring& dir, bool console, int level);
    // Сменить порог (после чтения ini).
    void SetLevel(int level);
    // Текущий порог.
    int  GetLevel();
    // Записать строку (printf-формат, UTF-8). tag — подсистема: "id", "side", "bridge", "pol", "eos", "sql", "main".
    void Write(int level, const char* tag, const char* fmt, ...);
    // Закрыть файл.
    void Close();
}}

#define LOGE(tag, ...) ::Eac::Log::Write(::Eac::Log::Error, tag, __VA_ARGS__)
#define LOGW(tag, ...) ::Eac::Log::Write(::Eac::Log::Warn,  tag, __VA_ARGS__)
#define LOGI(tag, ...) ::Eac::Log::Write(::Eac::Log::Info,  tag, __VA_ARGS__)
#define LOGD(tag, ...) ::Eac::Log::Write(::Eac::Log::Debug, tag, __VA_ARGS__)
