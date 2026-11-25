// Copyright (c) 2026 @sitxovski (Discord)
// EacCommon.h — общие включения и мелкие помощники AsdaEacServer (EAC Э1, 16.10.2026).
//
// AsdaEacServer.exe — один 64-битный процесс (служба Windows) с тремя слушателями
// (контракт Reports/anticheat/eac/CONTRACT.md):
//   * AsdaId   — HTTP 127.0.0.1:8444 (/token, /refresh, JWKS, openid-configuration), §2;
//   * сайдкар  — TCP 15901 поверх AsdaSecure (SubServer::Eac = 4), ретрансляция EAC, §3;
//   * мост     — TCP 127.0.0.1:15702 к P73 (GameServer/Indun), LOGIN/LOGOUT/KICK, §4.
// Политика кика — §5/§6. Всё, что трогает EOS SDK, живёт в одной нити ядра (Core.cpp).
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Eac
{
    // Монотонное время процесса в миллисекундах (GetTickCount64 — не зависит от перевода часов).
    inline int64_t NowMs() { return (int64_t)GetTickCount64(); }

    // Время Unix в секундах (для iat/exp JWT).
    inline int64_t UnixNow()
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        return (int64_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
    }

    // UTF-16 → UTF-8.
    std::string  Utf8(const std::wstring& w);
    // UTF-8 → UTF-16.
    std::wstring Wide(const std::string& s);

    // Папка, где лежит exe (с завершающим '\'). Служба стартует в System32 — все относительные пути
    // конфигурации считаются от этой папки.
    std::wstring ExeDir();
    // Относительный путь → абсолютный от ExeDir(); абсолютный — как есть.
    std::wstring ResolvePath(const std::wstring& p);

    // IPv4 из sockaddr в текст "a.b.c.d" (для журнала и EOS RegisterClient.IpAddress).
    std::string Ipv4Text(uint32_t netOrder);

    // Константное по времени сравнение строк (секреты/хеши).
    bool ConstEq(const std::string& a, const std::string& b);

    // Перевод строки ASCII в нижний регистр.
    std::string Lower(std::string s);

    // Строгий разбор десятичного u32 без ведущих нулей, без знака, без пробелов (JWT sub / EOS AccountId).
    bool ParseUserIndex(const std::string& s, uint32_t& out);
}
