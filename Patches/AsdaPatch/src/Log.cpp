// Copyright (c) 2026 @sitxovski (Discord)
#include "Log.h"
#include <stdio.h>
#include <stdarg.h>

namespace
{
    HANDLE  g_h        = INVALID_HANDLE_VALUE;
    bool    g_enabled  = false;
    int     g_ok = 0, g_skip = 0, g_fail = 0;

    // Рекурсивное создание каталога (путь без завершающего '\').
    void EnsureDir(const wchar_t* path)
    {
        wchar_t buf[MAX_PATH];
        lstrcpynW(buf, path, MAX_PATH);
        for (wchar_t* p = buf; *p; ++p)
        {
            if (*p == L'\\' && p != buf && *(p - 1) != L':')
            {
                *p = 0;
                CreateDirectoryW(buf, nullptr);
                *p = L'\\';
            }
        }
        CreateDirectoryW(buf, nullptr);
    }

    void WriteCp1251(const wchar_t* text)
    {
        if (g_h == INVALID_HANDLE_VALUE) { return; }
        char  stackBuf[2048];                       // NB: имя small занято макросом Windows
        int   need = WideCharToMultiByte(1251, 0, text, -1, nullptr, 0, "?", nullptr);
        char* out  = (need <= (int)sizeof(stackBuf)) ? stackBuf : (char*)HeapAlloc(GetProcessHeap(), 0, need);
        if (!out) { return; }
        WideCharToMultiByte(1251, 0, text, -1, out, need, "?", nullptr);
        DWORD written = 0;
        WriteFile(g_h, out, (DWORD)(need - 1), &written, nullptr);   // без завершающего 0
        if (out != stackBuf) { HeapFree(GetProcessHeap(), 0, out); }
    }
}

namespace Log
{
    // Имя продукта в шапке журнала (см. Log.h).
    static const wchar_t* g_product = L"AsdaPatch";
    void Init(const wchar_t* baseDir, bool enabled, const wchar_t* product)
    {
        g_product = (product && *product) ? product : L"AsdaPatch";
        g_enabled = enabled;
        if (!enabled) { return; }

        wchar_t dir[MAX_PATH];
        wsprintfW(dir, L"%sLog\\Log_Patch", baseDir);
        EnsureDir(dir);

        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t path[MAX_PATH];
        wsprintfW(path, L"%s\\PatchLog_%04d%02d%02d.txt", dir, st.wYear, st.wMonth, st.wDay);

        g_h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (g_h == INVALID_HANDLE_VALUE) { return; }
        SetFilePointer(g_h, 0, nullptr, FILE_END);

        Line(L"");
        Line(L"===================================================================");
        Line(L"%s — старт %04d-%02d-%02d %02d:%02d:%02d, PID %u",
             g_product, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             (unsigned)GetCurrentProcessId());
    }

    void Line(const wchar_t* fmt, ...)
    {
        if (!g_enabled || g_h == INVALID_HANDLE_VALUE) { return; }
        wchar_t buf[2048];
        va_list ap;
        va_start(ap, fmt);
        _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
        va_end(ap);

        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t line[2100];
        wsprintfW(line, L"[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, buf);
        WriteCp1251(line);
        FlushFileBuffers(g_h);
    }

    void Close()
    {
        if (g_h != INVALID_HANDLE_VALUE) { CloseHandle(g_h); g_h = INVALID_HANDLE_VALUE; }
    }

    void CountOk()   { ++g_ok;   }
    void CountSkip() { ++g_skip; }
    void CountFail() { ++g_fail; }
    int  Ok()        { return g_ok;   }
    int  Skip()      { return g_skip; }
    int  Fail()      { return g_fail; }
}
