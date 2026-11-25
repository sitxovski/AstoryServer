// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  SrvDbPatch.dll — загрузчик патчей RelayServer.exe (RelayServer, Indun_RelayServer, Ch2_RelayServer),
//  ItemRelayServer.exe и OperationServer.exe (15.11.2026, P126).
//
//  Пятая DLL семейства (AsdaPatch — GameServer, AddonNPC — NpcServer, DBPatch — DBManager, LoginPatch — LoginManager).
//  Каркас 1:1 с LoginPatch/src/dllmain.cpp: журнал, бережный конфиг, паспорт образа, реестр с фильтром по имени exe.
//
//  Как попадает в процесс: в таблицу импорта каждого из трёх exe добавлен дескриптор «SrvDbPatch.dll / SrvDbPatchInit»
//  (tools\inject_import_srvdb.py; блок и FirstThunk — в нулевом хвосте .rdata, как у LoginManager: у всех трёх .data —
//  ~70 МБ BSS при файловой части 0x1000–0x2000, хвост .data занят живыми переменными). Загрузчик Windows подгружает
//  DLL ДО точки входа exe — потоков ещё нет. Все патчи ставятся В ПАМЯТИ; .text на диске не меняется.
//
//  ⚠ В DllMain нельзя грузить другие модули. Используются kernel32 и статический CRT (/MT); ole32/oleaut32 нужны
//    модулю DbReconnect, но exe всех трёх серверов уже импортируют ole32.dll и OLEAUT32.dll — новых загрузок нет.
// ─────────────────────────────────────────────────────────────────────────────
#include <windows.h>
#include "Log.h"
#include "Config.h"
#include "Hook.h"
#include "Patches.h"

namespace
{
    // ── Ранняя трассировка (только kernel32): <папка exe>\srvdbpatch_boot.log, перезаписывается каждый старт ──
    HANDLE g_boot = INVALID_HANDLE_VALUE;

    void BootOpen(const wchar_t* baseDir)
    {
        wchar_t path[MAX_PATH];
        int i = 0;
        while (baseDir[i] && i < MAX_PATH - 32) { path[i] = baseDir[i]; ++i; }
        const wchar_t* nm = L"srvdbpatch_boot.log";
        int k = 0;
        while (nm[k] && i < MAX_PATH - 1) { path[i++] = nm[k++]; }
        path[i] = 0;
        g_boot = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    void Boot(const char* step)
    {
        if (g_boot == INVALID_HANDLE_VALUE) { return; }
        DWORD w = 0;
        int n = 0;
        while (step[n]) { ++n; }
        WriteFile(g_boot, step, (DWORD)n, &w, nullptr);
        WriteFile(g_boot, "\r\n", 2, &w, nullptr);
        FlushFileBuffers(g_boot);
    }

    void BootClose()
    {
        if (g_boot != INVALID_HANDLE_VALUE) { CloseHandle(g_boot); g_boot = INVALID_HANDLE_VALUE; }
    }

    // Имя exe процесса в нижнем регистре.
    void HostExeName(wchar_t* out, int cch)
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p) { if (*p == L'\\' || *p == L'/') { name = p + 1; } }
        int i = 0;
        for (; name[i] && i < cch - 1; ++i)
        {
            const wchar_t c = name[i];
            out[i] = (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
        }
        out[i] = 0;
    }

    // Список имён через ';' содержит self.
    bool HostAllowed(const wchar_t* self, const wchar_t* hosts)
    {
        if (!hosts) { return false; }
        wchar_t item[64];
        int k = 0;
        for (const wchar_t* p = hosts; ; ++p)
        {
            if (*p && *p != L';' && k < (int)ARRAYSIZE(item) - 1) { item[k++] = *p; continue; }
            item[k] = 0;
            if (k && lstrcmpiW(self, item) == 0) { return true; }
            k = 0;
            if (!*p) { return false; }
        }
    }

    // ── CRC32 (для паспорта образа в журнале) ───────────────────────────────
    DWORD Crc32(const BYTE* data, SIZE_T len, DWORD crc = 0xFFFFFFFF)
    {
        static DWORD tbl[256];
        static bool  init = false;
        if (!init)
        {
            for (DWORD i = 0; i < 256; ++i)
            {
                DWORD c = i;
                for (int k = 0; k < 8; ++k) { c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); }
                tbl[i] = c;
            }
            init = true;
        }
        for (SIZE_T i = 0; i < len; ++i) { crc = tbl[(crc ^ data[i]) & 0xFF] ^ (crc >> 8); }
        return crc;
    }

    void LogHostPassport(const wchar_t* exePath)
    {
        HMODULE hExe = GetModuleHandleW(nullptr);
        Log::Line(L"Хост   : %s", exePath);
        Log::Line(L"База   : 0x%08X (ожидается 0x00400000)", (DWORD)hExe);
        HANDLE h = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            const DWORD size = GetFileSize(h, nullptr);
            DWORD crc = 0xFFFFFFFF, got = 0;
            BYTE  buf[32768];
            while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) { crc = Crc32(buf, got, crc); }
            CloseHandle(h);
            Log::Line(L"Файл   : %u б, CRC32 %08X", size, crc ^ 0xFFFFFFFF);
        }
        auto* dos = (IMAGE_DOS_HEADER*)hExe;
        auto* nt  = (IMAGE_NT_HEADERS32*)((BYTE*)hExe + dos->e_lfanew);
        Log::Line(L"PE     : секций %u, SizeOfImage 0x%X, EntryPoint 0x%08X", nt->FileHeader.NumberOfSections,
                  nt->OptionalHeader.SizeOfImage, (DWORD)hExe + nt->OptionalHeader.AddressOfEntryPoint);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            wchar_t wnm[9] = {};
            for (int k = 0; k < 8; ++k) { wnm[k] = (wchar_t)sec[i].Name[k]; }
            Log::Line(L"  сек %-9s VA 0x%08X  vsz 0x%06X  raw 0x%06X", wnm, (DWORD)hExe + sec[i].VirtualAddress,
                      sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        }
    }

    void Init()
    {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t baseDir[MAX_PATH] = {};
        lstrcpynW(baseDir, exePath, MAX_PATH);
        for (int i = lstrlenW(baseDir) - 1; i >= 0; --i)
        {
            if (baseDir[i] == L'\\') { baseDir[i + 1] = 0; break; }
        }

        BootOpen(baseDir);
        Boot("1 baseDir");
        const bool cfgOk = Config::Init(baseDir);
        Boot("2 config");
        const bool logOn = Config::GetBool(L"General", L"LogEnabled", true);
        Log::Init(baseDir, logOn, L"SrvDbPatch");
        Boot("3 log-open");

        Log::Line(L"Конфиг : %s%s", Config::Path(),
                  Config::WasCreated() ? L"   * СОЗДАН с настройками по умолчанию"
                                       : (cfgOk ? L"" : L"   ! НЕДОСТУПЕН — работаем на умолчаниях"));
        Config::MergeMissing();
        Boot("4 config-merge");
        LogHostPassport(exePath);
        Boot("5 host-passport");

        const int version = Config::GetInt(L"General", L"Version", Config::kVersion);
        if (version != Config::kVersion)
        {
            Log::Line(L"! Version=%d не поддерживается этой сборкой (ожидается %d) — патчи не ставятся.", version, Config::kVersion);
            return;
        }
        if (!Config::GetBool(L"General", L"MasterEnable", true))
        {
            Log::Line(L"MasterEnable=0 — НИ ОДИН патч не ставится, сервер работает как сток.");
            Log::Line(L"=== итог: применено 0, пропущено 0, ошибок 0 ===");
            return;
        }

        wchar_t self[MAX_PATH] = {};
        HostExeName(self, ARRAYSIZE(self));
        Log::Line(L"MasterEnable=1 — установка патчей (%d в реестре), образ-хозяин: %s", g_patchCount, self);
        for (int i = 0; i < g_patchCount; ++i)
        {
            const PatchEntry& p = g_patches[i];
            if (!HostAllowed(self, p.hosts))
            {
                Log::Line(L"  [не для этого образа] %s", p.section);
                continue;
            }
            const PatchResult r = p.apply();
            switch (r)
            {
            case PatchResult::Applied:  Log::CountOk();   Log::Line(L"  [OK]       %s — %s", p.section, p.title); break;
            case PatchResult::Disabled: Log::CountSkip(); Log::Line(L"  [ВЫКЛ]     %s — %s", p.section, p.title); break;
            case PatchResult::Mismatch: Log::CountFail(); Log::Line(L"  [MISMATCH] %s — %s   * НЕ ПОСТАВЛЕН (см. строки выше)", p.section, p.title); break;
            default:                    Log::CountFail(); Log::Line(L"  [ОШИБКА]   %s — %s   * НЕ ПОСТАВЛЕН", p.section, p.title); break;
            }
        }
        Log::Line(L"=== итог: применено %d, пропущено %d, ошибок %d ===", Log::Ok(), Log::Skip(), Log::Fail());
        Boot("9 patches-done");
    }
}

// Символ, который импортируют exe (нужен только для того, чтобы загрузчик подтянул DLL). Никогда не вызывается.
extern "C" __declspec(dllexport) int __cdecl SrvDbPatchInit()
{
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Init();
        Boot("10 dllmain-end");
        BootClose();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        Log::Close();
    }
    return TRUE;
}
