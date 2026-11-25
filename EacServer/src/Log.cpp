// Copyright (c) 2026 @sitxovski (Discord)
// Log.cpp — реализация журнала и общих помощников EacCommon.h.
#include "EacCommon.h"
#include "Log.h"
#include <cstdarg>
#include <cstdio>
#include <share.h>
#include <mutex>

namespace Eac
{
    std::string Utf8(const std::wstring& w)
    {
        if (w.empty()) return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s((size_t)(n > 0 ? n : 0), '\0');
        if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
        return s;
    }

    std::wstring Wide(const std::string& s)
    {
        if (s.empty()) return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
        return w;
    }

    std::wstring ExeDir()
    {
        wchar_t buf[MAX_PATH * 2];
        DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
        std::wstring p(buf, n);
        size_t k = p.find_last_of(L"\\/");
        return k == std::wstring::npos ? std::wstring(L".\\") : p.substr(0, k + 1);
    }

    std::wstring ResolvePath(const std::wstring& p)
    {
        if (p.empty()) return p;
        bool abs = (p.size() > 1 && p[1] == L':') || (p.size() > 1 && p[0] == L'\\' && p[1] == L'\\');
        std::wstring full = abs ? p : ExeDir() + p;
        wchar_t out[MAX_PATH * 2];
        DWORD n = GetFullPathNameW(full.c_str(), (DWORD)(sizeof(out) / sizeof(out[0])), out, nullptr);
        return (n > 0 && n < sizeof(out) / sizeof(out[0])) ? std::wstring(out, n) : full;
    }

    std::string Ipv4Text(uint32_t netOrder)
    {
        const uint8_t* b = (const uint8_t*)&netOrder;
        char t[20]; snprintf(t, sizeof(t), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return t;
    }

    bool ConstEq(const std::string& a, const std::string& b)
    {
        if (a.size() != b.size()) return false;
        unsigned char d = 0;
        for (size_t i = 0; i < a.size(); ++i) d |= (unsigned char)(a[i] ^ b[i]);
        return d == 0;
    }

    std::string Lower(std::string s)
    {
        for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        return s;
    }

    bool ParseUserIndex(const std::string& s, uint32_t& out)
    {
        if (s.empty() || s.size() > 10) return false;
        if (s[0] == '0') return false;                 // без ведущих нулей; 0 — не учётка
        uint64_t v = 0;
        for (char c : s) { if (c < '0' || c > '9') return false; v = v * 10 + (uint64_t)(c - '0'); }
        if (v == 0 || v > 0x7FFFFFFFULL) return false; // Userindex в БД — INT (положительный)
        out = (uint32_t)v;
        return true;
    }

    namespace Log
    {
        static std::mutex   g_mu;            // сериализация записи
        static FILE*        g_file = nullptr; // текущий файл журнала
        static std::wstring g_dir;           // папка журнала
        static int          g_day = -1;      // день открытого файла (YYYYMMDD)
        static bool         g_console = false;
        static volatile LONG g_level = Info;

        // Открыть файл на текущий день (под g_mu).
        static void OpenForDay(const SYSTEMTIME& st)
        {
            int day = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
            if (g_file && day == g_day) return;
            if (g_file) { fclose(g_file); g_file = nullptr; }
            wchar_t name[64];
            swprintf(name, 64, L"eac_%04u%02u%02u.log", st.wYear, st.wMonth, st.wDay);
            std::wstring path = g_dir + name;
            g_file = _wfsopen(path.c_str(), L"ab", _SH_DENYWR);
            g_day = day;
        }

        bool Init(const std::wstring& dir, bool console, int level)
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_dir = dir;
            if (!g_dir.empty() && g_dir.back() != L'\\' && g_dir.back() != L'/') g_dir += L'\\';
            CreateDirectoryW(g_dir.c_str(), nullptr);
            g_console = console;
            InterlockedExchange(&g_level, level);
            if (console) SetConsoleOutputCP(CP_UTF8);
            SYSTEMTIME st; GetLocalTime(&st);
            OpenForDay(st);
            return g_file != nullptr;
        }

        void SetLevel(int level) { InterlockedExchange(&g_level, level); }
        int  GetLevel() { return (int)g_level; }

        void Write(int level, const char* tag, const char* fmt, ...)
        {
            if (level > (int)g_level) return;
            char msg[4096];
            va_list ap; va_start(ap, fmt);
            int n = vsnprintf(msg, sizeof(msg), fmt, ap);
            va_end(ap);
            if (n < 0) return;
            static const char* kLv[] = { "ERR", "WRN", "INF", "DBG" };
            SYSTEMTIME st; GetLocalTime(&st);
            char line[4400];
            int m = snprintf(line, sizeof(line), "%04u-%02u-%02u %02u:%02u:%02u.%03u [%s] [%s] %s\r\n",
                             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                             kLv[level < 0 ? 0 : (level > 3 ? 3 : level)], tag ? tag : "-", msg);
            if (m < 0) return;
            if (m >= (int)sizeof(line)) m = (int)sizeof(line) - 1;
            std::lock_guard<std::mutex> lk(g_mu);
            if (!g_dir.empty()) OpenForDay(st);
            if (g_file) { fwrite(line, 1, (size_t)m, g_file); fflush(g_file); }
            if (g_console) { fwrite(line, 1, (size_t)m, stdout); fflush(stdout); }
        }

        void Close()
        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (g_file) { fclose(g_file); g_file = nullptr; }
        }
    }
}
