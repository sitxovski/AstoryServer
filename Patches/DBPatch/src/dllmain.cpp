// Copyright (c) 2026 @sitxovski (Discord)
//  DBPatch.dll — загрузчик патчей DBManager.
//
//  Как попадает в процесс: в таблицу импорта DBManager.exe добавлен дескриптор
//  на DBPatch.dll, поэтому системный загрузчик подтягивает её ДО точки входа,
//  когда образ .text уже отображён. Все патчи ставятся В ПАМЯТИ; файл
//  DBManager.exe на диске после инъекции импорта больше не меняется.
//
//  ★ ПОЧЕМУ ОТДЕЛЬНАЯ DLL, А НЕ ОБЩАЯ С GameServer (30.08.2026)
//    Сначала патч P22 положили в AsdaPatch.dll (патчи GameServer). Эта DLL
//    грузится в любой хост, куда её подложат, и в DBManager она:
//      • создавала там свой patches.ini от GameServer;
//      • печатала сверку ЧУЖИХ якорей GameServer по чужому образу (сплошные нули).
//    Спасла только проверка версии конфига. Разделено по образцу AddonNPC.dll
//    (NpcServer): одна DLL — один хост, свой файл настроек, свой реестр патчей.
//
//  Порядок работы:
//    1. определить папку DBManager.exe;
//    2. создать/дочитать ConfigSet\dbpatch.ini;
//    3. открыть журнал Log\Log_Patch\PatchLog_<ГГГГММДД>.txt;
//    4. записать паспорт хост-образа (путь, размер, CRC32, секции);
//    5. проверить версию конфига и MasterEnable;
//    6. обойти реестр патчей, ставя только предназначенные этому образу.
#include <windows.h>
#include "Config.h"
#include "Log.h"
#include "Hook.h"
#include "Patches.h"
#include "AcJournal.h"

namespace
{
    // ── ранняя диагностика ──────────────────────────────────────────────────
    // Файл: <DBManager>\dbpatch_boot.log (перезаписывается каждый старт).
    // Нужен на случай, если падение произойдёт ДО открытия обычного журнала.
    HANDLE g_boot = INVALID_HANDLE_VALUE;

    void BootOpen(const wchar_t* baseDir)
    {
        wchar_t p[MAX_PATH];
        wsprintfW(p, L"%sdbpatch_boot.log", baseDir);
        g_boot = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    void Boot(const char* stage)
    {
        if (g_boot == INVALID_HANDLE_VALUE) { return; }
        DWORD w = 0;
        WriteFile(g_boot, stage, (DWORD)lstrlenA(stage), &w, nullptr);
        WriteFile(g_boot, "\r\n", 2, &w, nullptr);
        FlushFileBuffers(g_boot);
    }

    void BootClose()
    {
        if (g_boot != INVALID_HANDLE_VALUE) { CloseHandle(g_boot); g_boot = INVALID_HANDLE_VALUE; }
    }

    // ── имя образа-хозяина в нижнем регистре ────────────────────────────────
    void HostExeName(wchar_t* out, int cch)
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p)
        {
            if (*p == L'\\' || *p == L'/') { name = p + 1; }
        }
        lstrcpynW(out, name, cch);
        CharLowerW(out);
    }

    // hosts == nullptr — в ЭТОЙ сборке считаем, что патч для dbmanager.exe.
    // (В AsdaPatch то же поле по умолчанию означает gameserver.exe.)
    bool HostAllowed(const wchar_t* self, const wchar_t* hosts)
    {
        if (!hosts) { return lstrcmpiW(self, L"dbmanager.exe") == 0; }

        wchar_t item[MAX_PATH];
        int n = 0;
        for (const wchar_t* p = hosts; ; ++p)
        {
            if (*p == L';' || *p == 0)
            {
                item[n] = 0;
                if (n > 0 && lstrcmpiW(self, item) == 0) { return true; }
                n = 0;
                if (*p == 0) { break; }
            }
            else if (n < MAX_PATH - 1)
            {
                item[n++] = *p;
            }
        }
        return false;
    }

    // ── CRC32 (для паспорта билда в логе) ───────────────────────────────────
    DWORD Crc32(const BYTE* data, DWORD len)
    {
        static DWORD table[256];
        static bool  ready = false;
        if (!ready)
        {
            for (DWORD i = 0; i < 256; ++i)
            {
                DWORD c = i;
                for (int k = 0; k < 8; ++k) { c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); }
                table[i] = c;
            }
            ready = true;
        }
        DWORD c = 0xFFFFFFFFu;
        for (DWORD i = 0; i < len; ++i) { c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8); }
        return c ^ 0xFFFFFFFFu;
    }

    bool HostFileInfo(const wchar_t* path, DWORD* sizeOut, DWORD* crcOut)
    {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return false; }
        const DWORD size = GetFileSize(h, nullptr);
        bool ok = false;
        if (size != INVALID_FILE_SIZE && size > 0)
        {
            BYTE* buf = (BYTE*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
            if (buf)
            {
                DWORD read = 0;
                if (ReadFile(h, buf, size, &read, nullptr) && read == size)
                {
                    *sizeOut = size;
                    *crcOut  = Crc32(buf, size);
                    ok = true;
                }
                VirtualFree(buf, 0, MEM_RELEASE);
            }
        }
        CloseHandle(h);
        return ok;
    }

    // Паспорт образа: путь, размер, CRC32, база, карта секций.
    // ⚠ Ожидаемые размер/CRC ЖИВОГО DBManager.exe с уже вшитым импортом
    //   DBPatch.dll. Несовпадение — не ошибка, а повод посмотреть, что подложено.
    constexpr DWORD kExpectSize = 536576;

    void LogHostPassport(const wchar_t* exePath)
    {
        Log::Line(L"Хост   : %s", exePath);

        DWORD size = 0, crc = 0;
        if (HostFileInfo(exePath, &size, &crc))
        {
            Log::Line(L"Файл   : %u б, CRC32 %08X%s", size, crc,
                      size == kExpectSize ? L"" : L"   ! размер отличается от ожидаемого");
        }

        const BYTE* base = (const BYTE*)GetModuleHandleW(nullptr);
        Log::Line(L"База   : 0x%08X (ожидается 0x00400000)", (DWORD)(DWORD_PTR)base);

        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { return; }
        const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { return; }

        Log::Line(L"PE     : секций %u, SizeOfImage 0x%X, EntryPoint 0x%08X",
                  nt->FileHeader.NumberOfSections,
                  nt->OptionalHeader.SizeOfImage,
                  (DWORD)(DWORD_PTR)base + nt->OptionalHeader.AddressOfEntryPoint);

        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char name[9] = {};
            memcpy(name, sec[i].Name, 8);
            wchar_t wname[9] = {};
            MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 9);
            Log::Line(L"  сек %-8s VA 0x%08X  vsz 0x%06X  raw 0x%06X",
                      wname,
                      (DWORD)(DWORD_PTR)base + sec[i].VirtualAddress,
                      sec[i].Misc.VirtualSize,
                      sec[i].SizeOfRawData);
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
        Log::Init(baseDir, logOn, L"DBPatch");
        Boot("4 log-open");

        Log::Line(L"Конфиг : %s%s", Config::Path(),
                  Config::WasCreated() ? L"   * СОЗДАН с настройками по умолчанию"
                                       : (cfgOk ? L"" : L"   ! НЕДОСТУПЕН — работаем на умолчаниях"));
        Config::MergeMissing();     // бережное слияние: правки администратора не трогаем
        Boot("4b config-merge");
        LogHostPassport(exePath);
        Boot("5 host-passport");

        // ★ Хост проверяется ДО всего остального: если DLL подложили не в тот
        //   процесс, она не должна ни сверять байты, ни что-либо ставить.
        wchar_t self[MAX_PATH] = {};
        HostExeName(self, ARRAYSIZE(self));
        Log::Line(L"  образ-хозяин: %s", self);
        if (lstrcmpiW(self, L"dbmanager.exe") != 0)
        {
            Log::Line(L"! Эта DLL предназначена ТОЛЬКО для DBManager.exe — ничего не ставится.");
            Log::Line(L"   (патчи GameServer живут в AsdaPatch.dll, патчи NpcServer — в AddonNPC.dll)");
            Log::Line(L"=== итог: применено 0, пропущено 0, ошибок 0 ===");
            return;
        }

        const int version = Config::GetInt(L"General", L"Version", Config::kVersion);
        if (version != Config::kVersion)
        {
            Log::Line(L"! Version=%d не поддерживается этой сборкой (ожидается %d) — патчи не ставятся.",
                      version, Config::kVersion);
            return;
        }

        if (!Config::GetBool(L"General", L"MasterEnable", false))
        {
            Log::Line(L"MasterEnable=0 — НИ ОДИН патч не ставится, DBManager работает как сток.");
            Log::Line(L"   (это штатный режим проверки каркаса; после успешного старта поставить 1)");
            Log::Line(L"=== итог: применено 0, пропущено 0, ошибок 0 ===");
            return;
        }

        Log::Line(L"MasterEnable=1 — установка патчей (%d в реестре):", g_patchCount);
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
        Boot("6 patches-done");
    }
}

// Символ, который импортирует DBManager.exe (нужен только для того, чтобы
// загрузчик подтянул DLL). Никогда не вызывается — вся работа в DllMain.
extern "C" __declspec(dllexport) int __cdecl DBPatchInit()
{
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Init();
        Boot("7 dllmain-end");
        BootClose();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        AcJournal::FlushToFileOnExit();   // ★ acdb: остаток очереди журнала — в файл (база в DllMain недоступна)
        Log::Close();
    }
    return TRUE;
}
