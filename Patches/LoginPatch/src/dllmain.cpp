// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  LoginPatch.dll — загрузчик патчей LoginManager.
//
//  Четвёртая DLL семейства (AsdaPatch — GameServer, AddonNPC — NpcServer,
//  DBPatch — DBManager). Каркас 1:1 с AddonNPC; сборка 12.10.2026 — ЗАГОТОВКА
//  (стаб): реестр патчей пуст, DLL только грузится, создаёт конфиг и журнал.
//
//  Как попадает в процесс: в таблицу импорта LoginManager.exe добавлен дескриптор
//  «LoginPatch.dll / LoginPatchInit» (tools\inject_import_login.py). Загрузчик
//  Windows подгружает DLL ДО точки входа exe — потоков ещё нет, образ .text уже
//  отображён. Все патчи ставятся В ПАМЯТИ; .text на диске не меняется.
//
//  Порядок работы DllMain(PROCESS_ATTACH):
//    1. определить папку LoginManager.exe;
//    2. ConfigSet\patches.ini — прочитать, при отсутствии создать с умолчаниями;
//    3. Log\Log_Patch\PatchLog_<дата>.txt — открыть;
//    4. записать паспорт хост-образа (путь, размер, CRC32, секции, якорные байты);
//    5. при MasterEnable=1 пройти реестр патчей; каждый сверяет оригинал сам.
//
//  ⚠ В DllMain нельзя грузить другие модули. Используются только kernel32
//    (уже загружен) и статический CRT (/MT) — ничего, что тянет LoadLibrary.
// ─────────────────────────────────────────────────────────────────────────────
#include <windows.h>
#include "Log.h"
#include "Config.h"
#include "Hook.h"
#include "LoginApi.h"
#include "patches/Patches.h"
#include "AcJournal.h"   // ★ В7d: журнал античита (ac.other 56–59) — запускает L07 при Enabled=1

namespace
{
    // ── Ранняя трассировка ──────────────────────────────────────────────────
    // Пишется ТОЛЬКО через kernel32 (никакого CRT, user32 и наших модулей),
    // поэтому работает даже если всё остальное ещё не готово. Нужна на случай
    // падения в DllMain: последняя строка в файле = шаг, на котором упали.
    // Файл: <LoginManager>\loginpatch_boot.log (перезаписывается каждый старт).
    HANDLE g_boot = INVALID_HANDLE_VALUE;

    void BootOpen(const wchar_t* baseDir)
    {
        wchar_t path[MAX_PATH];
        int i = 0;
        while (baseDir[i] && i < MAX_PATH - 32) { path[i] = baseDir[i]; ++i; }
        const wchar_t* nm = L"loginpatch_boot.log";
        int k = 0;
        while (nm[k] && i < MAX_PATH - 1) { path[i++] = nm[k++]; }
        path[i] = 0;
        g_boot = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
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

    // ── Имя образа-хозяина и отбор патчей по нему ───────────────────────────
    void HostExeName(wchar_t* out, int cch)
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p)
        {
            if (*p == L'\\' || *p == L'/') { name = p + 1; }
        }
        int i = 0;
        for (; name[i] && i < cch - 1; ++i)
        {
            const wchar_t c = name[i];
            out[i] = (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
        }
        out[i] = 0;
    }

    // hosts == nullptr — патч только для LoginManager.exe. Иначе — список имён через ';'.
    bool HostAllowed(const wchar_t* self, const wchar_t* hosts)
    {
        if (!hosts) { return lstrcmpiW(self, L"loginmanager.exe") == 0; }
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

    // ── CRC32 (для паспорта билда в логе) ───────────────────────────────────
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

    bool HostFileInfo(const wchar_t* path, DWORD* sizeOut, DWORD* crcOut)
    {
        *sizeOut = 0; *crcOut = 0;
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return false; }
        DWORD size = GetFileSize(h, nullptr);
        DWORD crc  = 0xFFFFFFFF;
        BYTE  buf[32768];
        DWORD got = 0;
        while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) { crc = Crc32(buf, got, crc); }
        CloseHandle(h);
        *sizeOut = size;
        *crcOut  = crc ^ 0xFFFFFFFF;
        return true;
    }

    // ── паспорт хост-образа в лог ───────────────────────────────────────────
    void LogHostPassport(const wchar_t* exePath)
    {
        HMODULE hExe = GetModuleHandleW(nullptr);
        Log::Line(L"Хост   : %s", exePath);
        Log::Line(L"База   : 0x%08X (ожидается 0x%08X)", (DWORD)hExe, Login::kImageBase);

        DWORD size = 0, crc = 0;
        if (HostFileInfo(exePath, &size, &crc))
        {
            Log::Line(L"Файл   : %u б, CRC32 %08X%s", size, crc,
                      (size == Login::kFileSize) ? L"" : L"   ! размер НЕ совпадает с ожидаемым образом");
        }

        auto* dos = (IMAGE_DOS_HEADER*)hExe;
        auto* nt  = (IMAGE_NT_HEADERS32*)((BYTE*)hExe + dos->e_lfanew);
        Log::Line(L"PE     : секций %u, SizeOfImage 0x%X, EntryPoint 0x%08X",
                  nt->FileHeader.NumberOfSections,
                  nt->OptionalHeader.SizeOfImage,
                  (DWORD)hExe + nt->OptionalHeader.AddressOfEntryPoint);

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char  nm[9] = {};
            for (int k = 0; k < 8; ++k) { nm[k] = (char)sec[i].Name[k]; }
            wchar_t wnm[9] = {};
            MultiByteToWideChar(CP_ACP, 0, nm, -1, wnm, 9);
            Log::Line(L"  сек %-9s VA 0x%08X  vsz 0x%06X  raw 0x%06X",
                      wnm, (DWORD)hExe + sec[i].VirtualAddress,
                      sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        }
    }

    // ── якорные байты: подтверждение, что адреса из LoginApi.h попадают куда надо ──
    struct Anchor { DWORD va; SIZE_T len; const wchar_t* what; };

    void LogAnchors()
    {
        static const Anchor kAnchors[] =
        {
            { Login::Hooks::kEntryPoint, 10, L"(ориентир) точка входа" },   // ожидается e8 d2 65 00 00 e9 16 fe ff ff
        };
        Log::Line(L"Якорные байты (сверка адресов из LoginApi.h с образом):");
        for (const auto& a : kAnchors)
        {
            wchar_t hex[128];
            Hook::Dump(a.va, a.len, hex, 128);
            Log::Line(L"  0x%08X  %-24s %s", a.va, a.what, hex);
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
        Boot("3 cfg-read");
        Log::Init(baseDir, logOn, L"LoginPatch");
        Boot("4 log-open");

        Log::Line(L"Конфиг : %s%s", Config::Path(),
                  Config::WasCreated() ? L"   * СОЗДАН с настройками по умолчанию"
                                       : (cfgOk ? L"" : L"   ! НЕДОСТУПЕН — работаем на умолчаниях"));
        Config::MergeMissing();     // бережное слияние: правки администратора не трогаем
        Boot("4b config-merge");
        LogHostPassport(exePath);
        Boot("6 host-passport");
        LogAnchors();
        Boot("7 anchors");

        // Версию сверяем с Config::kVersion, а не с зашитым числом (урок AsdaPatch: при
        const int version = Config::GetInt(L"General", L"Version", Config::kVersion);
        if (version != Config::kVersion)
        {
            Log::Line(L"! Version=%d не поддерживается этой сборкой (ожидается %d) — патчи не ставятся.",
                      version, Config::kVersion);
            return;
        }

        if (!Config::GetBool(L"General", L"MasterEnable", false))
        {
            Log::Line(L"MasterEnable=0 — НИ ОДИН патч не ставится, сервер работает как сток.");
            Log::Line(L"   (это штатный режим проверки каркаса; после успешного старта поставить 1)");
            Log::Line(L"=== итог: применено 0, пропущено 0, ошибок 0 ===");
            return;
        }

        if (g_patchCount == 0)
        {
            Log::Line(L"MasterEnable=1, но реестр патчей ПУСТ (сборка-заготовка — только каркас).");
            Log::Line(L"=== итог: применено 0, пропущено 0, ошибок 0 ===");
            return;
        }

        Log::Line(L"MasterEnable=1 — установка патчей (%d в реестре):", g_patchCount);
        wchar_t self[MAX_PATH] = {};
        HostExeName(self, ARRAYSIZE(self));
        Log::Line(L"  образ-хозяин: %s", self);
        for (int i = 0; i < g_patchCount; ++i)
        {
            const PatchEntry& p = g_patches[i];
            // Патч ставится только в предназначенный ему образ.
            if (!HostAllowed(self, p.hosts))
            {
                Log::Line(L"  [не для этого образа] %s", p.section);
                continue;
            }
            const PatchResult r = p.apply();
            switch (r)
            {
            case PatchResult::Applied:
                Log::CountOk();
                Log::Line(L"  [OK]       %s — %s", p.section, p.title);
                break;
            case PatchResult::Disabled:
                Log::CountSkip();
                Log::Line(L"  [ВЫКЛ]     %s — %s", p.section, p.title);
                break;
            case PatchResult::Mismatch:
                Log::CountFail();
                Log::Line(L"  [MISMATCH] %s — %s   * НЕ ПОСТАВЛЕН (см. строки выше)", p.section, p.title);
                break;
            default:
                Log::CountFail();
                Log::Line(L"  [ОШИБКА]   %s — %s   * НЕ ПОСТАВЛЕН", p.section, p.title);
                break;
            }
        }
        Log::Line(L"=== итог: применено %d, пропущено %d, ошибок %d ===",
                  Log::Ok(), Log::Skip(), Log::Fail());
        Boot("9 patches-done");
    }
}

// Символ, который импортирует LoginManager.exe (нужен только для того, чтобы
// загрузчик подтянул DLL). Никогда не вызывается — вся работа в DllMain.
extern "C" __declspec(dllexport) int __cdecl LoginPatchInit()
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
        AcJournal::FlushToFileOnExit();   // ★ В7d: остаток очереди журнала (если L07 его запустил) — в файл
        Log::Close();
    }
    return TRUE;
}
