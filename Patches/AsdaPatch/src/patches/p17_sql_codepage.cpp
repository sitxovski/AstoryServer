// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  ⚠ ЭТОТ ПАТЧ В РЕЕСТРЕ НЕ ЗНАЧИТСЯ И В СБОРКЕ НЕ РАБОТАЕТ.
//    Доставить DLL в процессы работы с базой не удалось: у DBManager,
//    RelayServer, LoginManager и OperationServer в хвосте .rdata нет места под
//    новый блок дескрипторов импорта (inject_import.py отказывается). Поэтому
//    та же правка сделана БИНАРНО — площадка в нулевом хвосте .text, 28 байт:
//    RE/tools/patch_sql_codepage.py, документ
//    AstoryServer/Docs/_Common/sql-codepage-1256.md.
//    Файл сохранён на случай, если инъекцию в эти образы получится сделать:
//    тогда патч включается одной строкой в Registry.cpp. Логика ниже проверена
//    компиляцией и описывает ту же подмену, что делает бинарная площадка.
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//  P17 — кодовая страница текста SQL-запросов: CP_ACP -> 1256.
//
//  ЧТО ЛЕЧИМ. Любой русский текст, который серверная часть пишет в базу,
//  превращался в «????»: подпись игрока, сообщения чата в журнале, имена
//  персонажей, названия и объявления кланов, клички питомцев.
//
//  ПОЧЕМУ ТАК ВЫХОДИЛО. Базы игры имеют арабскую кодировку (`Arabic_CI_AS`,
//  кодовая страница 1256) — сервер изначально арабский. Запросы строятся
//  подстановкой текста в шаблон вида `EXEC UPCharIntroUp %d, %d, '%s'`, то есть
//  текст едет обычным литералом, без пометки «это Юникод». Дальше:
//
//      vsprintf в CHAR[4100]
//        -> MultiByteToWideChar(CP_ACP, ...)      <- ЗДЕСЬ, кодовая страница машины
//        -> ICommandText::SetCommandText (UTF-16)
//        -> SQL Server приводит литерал к `varchar` по кодировке БАЗЫ (1256)
//
//  У машины сервера кодовая страница 1251 (русская), у базы 1256 (арабская).
//  Русские байты становились кириллическими символами, а обратного пути в 1256
//  у кириллицы нет — каждый символ превращался в «?». Порча происходила ещё до
//  входа в хранимую процедуру, поэтому ни процедуры, ни типы столбцов ни при чём.
//
//  ЧТО ДЕЛАЕТ ПАТЧ. Подменяет кодовую страницу ровно в этом вызове: вместо
//  системной подставляется 1256 — та же, что у базы. Круговой путь становится
//  точным: кодовая страница 1256 обратима для ВСЕХ 256 байт (проверено
//  программно), поэтому байты, присланные клиентом, доходят до столбца
//  нетронутыми. Клиент читает их своей кодировкой и видит правильный русский.
//
//  ЧЕГО ПАТЧ НЕ ДЕЛАЕТ. Не трогает базу, схему, хранимые процедуры и уже
//  записанные данные — ни одного байта не переписывается и не переосмысляется.
//  Арабский текст, наоборот, тоже начинает доходить целым (сейчас он гибнет так
//  же, как русский). Обратный путь (чтение) не трогаем: строковые колонки идут
//  байт в байт (`DBTYPE_STR` из `DBCOLUMNINFO.wType` при `AutoTranslate=No`) —
//  подтверждено и кодом, и живой пробой.
//
//  ГДЕ СТАВИТСЯ. Прикладной вызов `MultiByteToWideChar` в каждом из процессов
//  РОВНО ОДИН (остальные сайты — внутри библиотеки времени выполнения), поэтому
//  перехват адресный: подменяется значение в слоте таблицы импорта, а решение
//  «подставлять 1256 или нет» принимается по адресу возврата. Промахнуться
//  некуда, код процесса при этом не меняется вовсе.
//
//      процесс                     слот импорта   адрес возврата
//      DBManager.exe               0x46611C       0x4478BF
//      RelayServer.exe (оба)       0x418044       0x411A14
//      LoginManager.exe            0x42E158       0x40F5C2
//      1LoginManager.exe           0x42E158       0x40F5C2
//      OperationServer.exe         0x40C004       0x406974
//
//  Якорь перед записью — десять байт `6A 00 6A 00 FF 15 <слот>` непосредственно
//  перед адресом возврата: два нулевых аргумента (флаги и кодовая страница
//  CP_ACP) и сам косвенный вызов. Сверено на живых копиях всех пяти образов.
//
//  Страховка: подмена срабатывает, только если текст начинается с `EXEC ` —
//  все 23 шаблона запросов в DBManager начинаются именно так. Отключается
//  ключом `RequireExecPrefix`.
//
//  Разбор: `Reports/dbmanager_string_path.md`.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <intrin.h>

namespace
{
    constexpr const wchar_t* kSection = L"P17_SqlCodePage";

    // Одна площадка: слот таблицы импорта и адрес возврата прикладного вызова.
    struct Target
    {
        const wchar_t* exe;      // имя образа в нижнем регистре
        DWORD          iatVa;    // слот MultiByteToWideChar в таблице импорта
        DWORD          retVa;    // адрес возврата прикладного вызова
    };

    const Target kTargets[] =
    {
        { L"dbmanager.exe",       0x46611C, 0x4478BF },
        { L"relayserver.exe",     0x418044, 0x411A14 },   // и обычный, и подземельный
        { L"loginmanager.exe",    0x42E158, 0x40F5C2 },
        { L"1loginmanager.exe",   0x42E158, 0x40F5C2 },
        { L"operationserver.exe", 0x40C004, 0x406974 },
    };

    // ── состояние перехвата ─────────────────────────────────────────────────
    using FnMbToWc = int (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int);

    FnMbToWc      g_orig        = nullptr;   // оригинал, снятый из слота
    DWORD         g_gateRet     = 0;         // адрес возврата нашей площадки
    UINT          g_codePage    = 1256;      // что подставляем вместо системной
    bool          g_needExec    = true;      // требовать префикс «EXEC »
    volatile LONG g_hits        = 0;         // сколько раз подменили
    volatile LONG g_firstLogged = 0;         // однократная запись в лог

    // Текст начинается с «EXEC » (без учёта регистра)?
    bool LooksLikeSql(LPCCH s, int cb)
    {
        if (!s) { return false; }
        if (cb >= 0 && cb < 5) { return false; }
        const char* p = s;
        const char  want[5] = { 'E', 'X', 'E', 'C', ' ' };
        for (int i = 0; i < 5; ++i)
        {
            char c = p[i];
            if (c >= 'a' && c <= 'z') { c = (char)(c - 'a' + 'A'); }
            if (c != want[i]) { return false; }
        }
        return true;
    }

    // Подставная MultiByteToWideChar. Всё, что не наша площадка, уходит в
    // оригинал без единого изменения.
    int WINAPI Thunk(UINT cp, DWORD flags, LPCCH mb, int cbmb, LPWSTR wc, int cchwc)
    {
        if (cp == CP_ACP && (DWORD)(ULONG_PTR)_ReturnAddress() == g_gateRet
            && (!g_needExec || LooksLikeSql(mb, cbmb)))
        {
            cp = g_codePage;
            InterlockedIncrement(&g_hits);
            // Одна строка в лог на весь запуск — чтобы было видно, что патч живой,
            // и при этом не трогать журнал из-под нагрузки.
            if (InterlockedCompareExchange(&g_firstLogged, 1, 0) == 0)
            {
                Log::Line(L"    P17: первая подмена кодовой страницы (%u) на запросе к базе",
                          g_codePage);
            }
        }
        return g_orig(cp, flags, mb, cbmb, wc, cchwc);
    }

    // Имя текущего образа в нижнем регистре.
    void SelfExeName(wchar_t* out, int cch)
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
            wchar_t c = name[i];
            out[i] = (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
        }
        out[i] = 0;
    }
}

PatchResult P17_SqlCodePage()
{
    if (!Config::GetBool(kSection, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    wchar_t self[MAX_PATH] = {};
    SelfExeName(self, ARRAYSIZE(self));

    const Target* t = nullptr;
    for (const auto& c : kTargets)
    {
        if (lstrcmpiW(self, c.exe) == 0) { t = &c; break; }
    }
    if (!t)
    {
        Log::Line(L"    P17: процесс «%s» в базу не ходит — площадки нет", self);
        return PatchResult::Disabled;
    }

    // ── якорь: 6A 00 6A 00 FF 15 <слот> ровно перед адресом возврата ────────
    BYTE expect[10] =
    {
        0x6A, 0x00,                 // push 0   — флаги
        0x6A, 0x00,                 // push 0   — кодовая страница CP_ACP
        0xFF, 0x15,                 // call dword ptr [...]
        0, 0, 0, 0                  // ... адрес слота, заполняется ниже
    };
    expect[6] = (BYTE)( t->iatVa        & 0xFF);
    expect[7] = (BYTE)((t->iatVa >>  8) & 0xFF);
    expect[8] = (BYTE)((t->iatVa >> 16) & 0xFF);
    expect[9] = (BYTE)((t->iatVa >> 24) & 0xFF);

    const DWORD siteVa = t->retVa - 10;
    if (!Hook::Verify(siteVa, expect, sizeof(expect)))
    {
        wchar_t got[64] = {};
        Hook::Dump(siteVa, sizeof(expect), got, ARRAYSIZE(got));
        Log::Line(L"    P17: якорь @0x%08X не совпал (в памяти: %s) — патч НЕ поставлен",
                  siteVa, got);
        return PatchResult::Mismatch;
    }

    // ── настройки ───────────────────────────────────────────────────────────
    const int cp = Config::GetInt(kSection, L"CodePage", 1256);
    if (cp <= 0 || cp > 65535)
    {
        Log::Line(L"    P17: CodePage=%d вне допустимого — патч НЕ поставлен", cp);
        return PatchResult::Failed;
    }
    if (!IsValidCodePage((UINT)cp))
    {
        Log::Line(L"    P17: кодовая страница %d в системе не установлена — патч НЕ поставлен", cp);
        return PatchResult::Failed;
    }
    g_codePage = (UINT)cp;
    g_needExec = Config::GetBool(kSection, L"RequireExecPrefix", true);
    g_gateRet  = t->retVa;

    // ── подмена значения в слоте таблицы импорта ────────────────────────────
    // Слот к этому моменту уже заполнен загрузчиком: DllMain зависимостей
    // вызывается после разбора импортов образа.
    void** slot = (void**)(ULONG_PTR)t->iatVa;
    g_orig = (FnMbToWc)*slot;
    if (!g_orig)
    {
        Log::Line(L"    P17: слот 0x%08X пуст — патч НЕ поставлен", t->iatVa);
        return PatchResult::Failed;
    }

    void* mine = (void*)&Thunk;
    if (!Hook::WriteBytes(t->iatVa, (const BYTE*)&mine, sizeof(mine)))
    {
        Log::Line(L"    P17: не удалось записать слот 0x%08X", t->iatVa);
        return PatchResult::Failed;
    }

    Log::Line(L"    P17: %s — слот 0x%08X: 0x%08X -> 0x%08X, площадка возврата 0x%08X, "
              L"кодовая страница %u, префикс «EXEC » %s",
              self, t->iatVa, (DWORD)(ULONG_PTR)g_orig, (DWORD)(ULONG_PTR)mine,
              g_gateRet, g_codePage, g_needExec ? L"требуется" : L"не требуется");
    return PatchResult::Applied;
}
