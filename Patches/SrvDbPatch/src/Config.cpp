// Copyright (c) 2026 @sitxovski (Discord)
#include "Config.h"
#include "Log.h"

// ─────────────────────────────────────────────────────────────────────────────
//  Декларативное описание srvdbpatch.ini. Один источник правды и для создания файла с нуля, и для досоздания
//  LoginPatch/src/Config.cpp.
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    struct IniKey
    {
        const wchar_t* key;
        const wchar_t* def;
        const wchar_t* comment;     // комментарий перед ключом (может быть многострочным)
    };

    struct IniSection
    {
        const wchar_t* name;
        const wchar_t* comment;     // блок комментария перед [секцией]
        const IniKey*  keys;
        int            nkeys;
    };

    const IniKey kGeneral[] =
    {
        // ⚠ Значение ОБЯЗАНО совпадать с Config::kVersion (иначе DllMain отвергнет файл и не поставит ни одного патча).
        { L"Version", L"1",
          L"; Версия формата файла. Меняет только сама DLL при миграции.\r\n" },
        // В отличие от LoginPatch/DBPatch здесь 1: в DLL один патч, у него свой выключатель Enabled, а смысл выкладки —
        // чтобы исправление работало с первого старта (файл создаётся самой DLL на стойке).
        { L"MasterEnable", L"1",
          L"; * ГЛАВНЫЙ ВЫКЛЮЧАТЕЛЬ. 0 = не ставить НИ ОДИН патч (сервер работает как сток).\r\n" },
        { L"LogEnabled", L"1",
          L"; Вести лог установки патчей.\r\n" },
    };

    // ── [P126_DbReconnect] (15.11.2026): ключи и смысл — как [P125_DbReconnect] LoginPatch/DBPatch ──
    const IniKey kDbReconnect[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: после обрыва связи с базой каждая сессия отвечает\r\n"
          L";   ошибкой до перезапуска процесса.\r\n" },
        { L"Retry", L"1",
          L"; * 1 = после удачного переподключения запрос повторяется ОДИН раз. 0 = сессия открывается заново,\r\n"
          L";   но запрос, на котором обнаружен обрыв, отдаёт ошибку стоку (следующие запросы уже работают).\r\n"
          L";   Обрыв на отправке запроса повторять безопасно; при обрыве на приёме ответа сервер мог успеть\r\n"
          L";   выполнить запрос — повтор выполнит его второй раз.\r\n" },
        { L"Probe", L"1",
          L"; * 1 = если по сведениям об ошибке неясно, жива ли связь, сессия проверяется запросом SELECT 1.\r\n"
          L";   0 = переподключение только при SQLSTATE 08xxx или сетевом коде ошибки.\r\n" },
        { L"ReleaseOld", L"1",
          L"; * 1 = объекты оборванной сессии освобождаются. 0 = остаются висеть.\r\n" },
        { L"ComInit", L"1",
          L"; * 1 = COM на рабочем потоке включается один раз перед его первым запросом (без этого поставщик не\r\n"
          L";   оставляет сведений об ошибке, обрыв определяется только SELECT 1). 0 = потоки как в стоке.\r\n" },
        { L"RetryIntervalMs", L"10000",
          L"; * После НЕудачной попытки открыть сессию заново следующая попытка на этой сессии — не раньше чем\r\n"
          L";   через столько миллисекунд.\r\n" },
        { L"ConnectTimeoutSec", L"5",
          L"; * Предел ожидания нового подключения, секунд (0 — как у драйвера).\r\n" },
        { L"LogPerMinute", L"30",
          L"; * Строк PatchLog о переподключениях в минуту, не больше.\r\n" },
    };

    const IniSection kSections[] =
    {
        { L"General",
          L"; ===========================================================================\r\n"
          L"; AsdaReborn — патчи RelayServer / ItemRelayServer / OperationServer. Ставит SrvDbPatch.dll\r\n"
          L"; (грузится через таблицу импорта exe, ДО точки входа). Патчи применяются В ПАМЯТИ; в файле exe\r\n"
          L"; изменена только таблица импорта, код (.text) не тронут.\r\n"
          L";\r\n"
          L"; Правится при ОСТАНОВЛЕННОМ сервере, читается один раз при старте процесса.\r\n"
          L"; * Ваши правки НЕ ТЕРЯЮТСЯ: при обновлении DLL дописывает только НЕДОСТАЮЩИЕ ключи и секции.\r\n"
          L"; Лог установки: Log\\Log_Patch\\PatchLog_<ГГГГММДД>.txt\r\n"
          L"; Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p126-srvdbpatch.md\r\n"
          L"; ! Не путать с Patch.ini в папке сервера — это автообновление оригинала.\r\n"
          L"; ===========================================================================\r\n",
          kGeneral, ARRAYSIZE(kGeneral) },
        { L"P126_DbReconnect",
          L"; === P126 (дефект оригинала, НАША ПРАВКА, 15.11.2026) =====================\r\n"
          L"\r\n"
          L"; После обрыва связи с SQL Server сервер отвечал ошибкой («… :: Execute Error» в OLEDB_LOG) на каждый\r\n"
          L"; запрос до перезапуска: сток открывает источник и сессии один раз при старте и никогда не открывает заново.\r\n"
          L"; Патч: вызов Execute в функции запроса идёт через SrvDbPatch — при обрыве сессия открывается заново\r\n"
          L"; и запрос повторяется один раз. То же, что P125 у LoginManager и DBManager.\r\n"
          L"; Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p126-srvdbpatch.md\r\n",
          kDbReconnect, ARRAYSIZE(kDbReconnect) },
    };

    // ── состояние ───────────────────────────────────────────────────────────
    wchar_t g_path[MAX_PATH] = L"";
    wchar_t g_base[MAX_PATH] = L"";
    bool    g_created        = false;

    // Кодировка существующего файла: UTF-16LE (BOM) или ANSI.
    bool FileIsUtf16()
    {
        HANDLE h = CreateFileW(g_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return true; }
        BYTE  bom[2] = {};
        DWORD got = 0;
        ReadFile(h, bom, 2, &got, nullptr);
        CloseHandle(h);
        return got == 2 && bom[0] == 0xFF && bom[1] == 0xFE;
    }

    // Дописать текст в КОНЕЦ файла в его собственной кодировке.
    void AppendText(const wchar_t* text)
    {
        const bool utf16 = FileIsUtf16();
        HANDLE h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        SetFilePointer(h, 0, nullptr, FILE_END);
        DWORD w = 0;
        if (utf16)
        {
            WriteFile(h, text, (DWORD)(lstrlenW(text) * sizeof(wchar_t)), &w, nullptr);
        }
        else
        {
            int need = WideCharToMultiByte(1251, 0, text, -1, nullptr, 0, "?", nullptr);
            char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, need);
            if (buf)
            {
                WideCharToMultiByte(1251, 0, text, -1, buf, need, "?", nullptr);
                WriteFile(h, buf, (DWORD)(need - 1), &w, nullptr);
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }
        CloseHandle(h);
    }

    // Полный текст одной секции: комментарии + [имя] + ключи со значениями по умолчанию.
    void BuildSectionText(const IniSection& s, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (s.comment) { lstrcpynW(out, s.comment, cch); }
        wchar_t tmp[768];
        wsprintfW(tmp, L"[%s]\r\n", s.name);
        lstrcatW(out, tmp);
        for (int i = 0; i < s.nkeys; ++i)
        {
            if (s.keys[i].comment) { lstrcatW(out, s.keys[i].comment); }
            wsprintfW(tmp, L"%s=%s\r\n", s.keys[i].key, s.keys[i].def);
            lstrcatW(out, tmp);
        }
        lstrcatW(out, L"\r\n");
    }

    bool SectionExists(const wchar_t* name)
    {
        wchar_t buf[4];
        SetLastError(0);
        DWORD n = GetPrivateProfileSectionW(name, buf, ARRAYSIZE(buf), g_path);
        return n > 0 || GetLastError() == ERROR_MORE_DATA;
    }

    bool KeyExists(const wchar_t* section, const wchar_t* key)
    {
        wchar_t buf[8];
        GetPrivateProfileStringW(section, key, L"\x01", buf, ARRAYSIZE(buf), g_path);
        return buf[0] != L'\x01';
    }

    void CreateFull()
    {
        HANDLE h = CreateFileW(g_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        const WORD bom = 0xFEFF;                    // UTF-16LE — родной формат Win-ini API
        DWORD w = 0;
        WriteFile(h, &bom, sizeof(bom), &w, nullptr);
        CloseHandle(h);

        wchar_t buf[8192];
        for (const auto& s : kSections)
        {
            BuildSectionText(s, buf, ARRAYSIZE(buf));
            AppendText(buf);
        }
        g_created = true;
    }
}

namespace Config
{
    bool Init(const wchar_t* baseDir)
    {
        lstrcpynW(g_base, baseDir, MAX_PATH);
        wchar_t dir[MAX_PATH];
        wsprintfW(dir, L"%sConfigSet", baseDir);
        CreateDirectoryW(dir, nullptr);
        wsprintfW(g_path, L"%s\\srvdbpatch.ini", dir);

        if (GetFileAttributesW(g_path) == INVALID_FILE_ATTRIBUTES) { CreateFull(); }
        return GetFileAttributesW(g_path) != INVALID_FILE_ATTRIBUTES;
    }

    void MergeMissing()
    {
        if (g_created)
        {
            Log::Line(L"Конфиг : создан с нуля со значениями по умолчанию.");
            return;
        }

        const int fileVer = GetInt(L"General", L"Version", 0);
        int addedSections = 0, addedKeys = 0;
        wchar_t buf[8192];

        for (const auto& s : kSections)
        {
            if (!SectionExists(s.name))
            {
                BuildSectionText(s, buf, ARRAYSIZE(buf));
                AppendText(buf);
                ++addedSections;
                Log::Line(L"    + секция [%s] дописана со значениями по умолчанию", s.name);
                continue;
            }
            for (int i = 0; i < s.nkeys; ++i)
            {
                if (KeyExists(s.name, s.keys[i].key)) { continue; }
                WritePrivateProfileStringW(s.name, s.keys[i].key, s.keys[i].def, g_path);
                ++addedKeys;
                Log::Line(L"    + ключ [%s] %s=%s дописан (значение по умолчанию)", s.name, s.keys[i].key, s.keys[i].def);
            }
        }

        if (addedSections || addedKeys)
        {
            Log::Line(L"Конфиг : слияние — добавлено секций %d, ключей %d; все существующие значения СОХРАНЕНЫ.",
                      addedSections, addedKeys);
        }
        else
        {
            Log::Line(L"Конфиг : все ключи на месте, изменений не потребовалось.");
        }

        if (fileVer != kVersion)
        {
            wchar_t v[16];
            wsprintfW(v, L"%d", kVersion);
            WritePrivateProfileStringW(L"General", L"Version", v, g_path);
            Log::Line(L"Конфиг : миграция Version %d -> %d выполнена (пользовательские значения не тронуты).", fileVer, kVersion);
        }
    }

    const wchar_t* Path()       { return g_path; }
    const wchar_t* BaseDir()    { return g_base; }
    bool           WasCreated() { return g_created; }

    int GetInt(const wchar_t* section, const wchar_t* key, int def)
    {
        return (int)GetPrivateProfileIntW(section, key, def, g_path);
    }

    bool GetBool(const wchar_t* section, const wchar_t* key, bool def)
    {
        return GetInt(section, key, def ? 1 : 0) != 0;
    }
}
