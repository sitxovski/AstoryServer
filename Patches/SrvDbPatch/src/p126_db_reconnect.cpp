// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P126 — ★ ИСПРАВЛЕНИЕ (дефект оригинала): RelayServer (три копии), ItemRelayServer, OperationServer после обрыва
//  связи с SQL Server открывают сессию заново и повторяют запрос один раз.
//
//  ЭТО НАША ПРАВКА (15.11.2026). То же, что P125 у LoginManager/DBManager; общий модуль
//  `..\DbReconnect\src\DbReconnectCore.cpp`. Разбор — `Reports\relay_db_reconnect\REPORT.md`,
//  описание — `AstoryServer\Docs\_Common\db-reconnect-p126-srvdbpatch.md`.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Класс работы с базой тот же, что у LoginManager (OLE DB, MSDASQL поверх DSN «joy1»), другая сборка: 10 источников
//  по 0xA410 б, 10 сессий по 0x1050 б. Источник открывается один раз при старте (RelayServer sub_411340,
//  ItemRelayServer sub_40B220, OperationServer sub_4062A0), сессии — sub_40FE80 / … ; функция запроса
//  (sub_411920 / sub_40B800 / sub_406880) при ошибке Execute пишет «%s :: Execute Error» в OLEDB_LOG и возвращает 0.
//  Повторного открытия нет ни в одной ветке. 14.11.2026 21:08:15 (самообновление Tailscale) все пять процессов
//  потеряли базу до перезапуска: RelayServer — UPTopFamePoint и все запросы чата/гильдий/рейтингов, ItemRelayServer —
//  обмен предметов NPC, OperationServer — запросы оператора.
//
//  ── ПЛОЩАДКА (одинаковая в трёх образах, отличаются адреса) ──
//      push eax                      ; cmd                         (ctxA, 1 б)
//      mov  eax, [edx+10h]           ; 8b 42 10    ← метод Execute из vtbl
//      mov  [esp+44h], ecx           ; 89 4c 24 44 ← сток сохраняет адрес поля строк (rec+0x4C) в локал
//      call eax                      ; ff d0
//      mov  edi, eax ; test edi,edi  ; 8b f8 85 ff (ctxB)
//  ★ ОТЛИЧИЕ ОТ P125: между загрузкой метода и вызовом вклинена запись в локал, поэтому 5 байт подряд не взять.
//  Заменяются все 9 байт: `mov [esp+44h], ecx` (тот же байт-в-байт, на том же месте стека — esp до вызова не менялся)
//  + `call rel32` → DbReconnect::ExecuteHook. eax после вызова = результат, как в стоке; edx/ecx вызываемый портит и
//  в стоке (stdcall COM), после вызова они не читаются до перезаписи.
//
//  ── ОБЪЕКТ ──
//  RelayServer: один глобальный объект 0x00427A30 (конструктор sub_411830 из инициализации CRT, источники по числу
//  [SERVERGROUP_COUNT_0] count в ini\DBInfo.ini). OperationServer: 0x00414660 (sub_406790). ItemRelayServer: объект НЕ
//  на постоянном месте — по одному в каждом CNpcSession (куча, `+0x68`, по 1 сессии на поток NPC) и временный на
//  стеке в sub_408110 (разовая выборка UPExchangeItem при старте). Поэтому для него objBase = 0: источник ищется по
//  самой записи (см. DbReconnectCore Locate).
//
//  ── СВЕРКА ПЕРЕД УСТАНОВКОЙ ──
//  9 байт площадки, соседние команды, `lea ebp,[esi+0F8h]` (адрес поля результата = запись + 8), `push offset IID_IRowset`
//  и сам IID, CLSID поставщика (MSDASQL), начало функции запроса. Не совпало хоть что-то — MISMATCH, патч не ставится.
//
//  ── СОСЕДИ ──
//  RelayServer: RelayGift (байтовая правка файла @0x4042A5, 0x4092F6, 0x4092FF, 0x40DD4A — другие функции).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "DbReconnectCore.h"

namespace
{
    const wchar_t* const kSection = L"P126_DbReconnect";

    // Описание одного образа.
    struct HostDef
    {
        const wchar_t* exe;        // имя exe (нижний регистр)
        const wchar_t* title;      // для журнала
        DWORD siteVa;              // mov eax,[edx+10h] ; mov [esp+44h],ecx ; call eax   (9 б)
        DWORD ctxAVa;              // push eax (cmd)
        DWORD ctxBVa;              // mov edi,eax ; test edi,edi
        DWORD leaVa;               // lea ebp,[esi+0F8h]
        DWORD iidPushVa;           // push offset IID_IRowset
        DWORD iidVa;               // IID_IRowset в .rdata
        DWORD clsidVa;             // CLSID поставщика, который сток отдаёт CoCreateInstance
        DWORD fnQuery;             // начало функции запроса
        DWORD objBase;             // объект класса (0 — режим поиска)
    };

    const HostDef kHosts[] =
    {
        { L"relayserver.exe",     L"RelayServer (RelayServer, Indun_RelayServer, Ch2_RelayServer)",
          0x00411ADB, 0x00411ADA, 0x00411AE4, 0x00411AC3, 0x00411AD3, 0x00423A78, 0x00420CC8, 0x00411920, 0x00427A30 },
        { L"itemrelayserver.exe", L"ItemRelayServer",
          0x0040B9BB, 0x0040B9BA, 0x0040B9C4, 0x0040B9A3, 0x0040B9B3, 0x0042D3E4, 0x004288BC, 0x0040B800, 0x00000000 },
        { L"operationserver.exe", L"OperationServer",
          0x00406A3B, 0x00406A3A, 0x00406A44, 0x00406A23, 0x00406A33, 0x0040EF68, 0x0040C29C, 0x00406880, 0x00414660 },
    };

    const BYTE kOrig[9]    = { 0x8B, 0x42, 0x10, 0x89, 0x4C, 0x24, 0x44, 0xFF, 0xD0 };
    const BYTE kCtxA[1]    = { 0x50 };
    const BYTE kCtxB[4]    = { 0x8B, 0xF8, 0x85, 0xFF };
    const BYTE kLea[6]     = { 0x8D, 0xAE, 0xF8, 0x00, 0x00, 0x00 };
    const BYTE kFnHead[6]  = { 0x81, 0xEC, 0x24, 0x08, 0x00, 0x00 };   // sub esp, 824h (все три образа)
    const BYTE kClsid[16]  = { 0xCB, 0x22, 0xB5, 0xC8, 0xF3, 0x5C, 0xCE, 0x11,
                               0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D };   // {C8B522CB-5CF3-11CE-ADE5-00AA0044773D} MSDASQL
    const BYTE kIidRowset[16] = { 0x7C, 0x3A, 0x73, 0x0C, 0x1C, 0x2A, 0xCE, 0x11,
                                  0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D };   // {0C733A7C-2A1C-11CE-ADE5-00AA0044773D} IID_IRowset

    // Раскладка этой сборки класса (декомпил трёх образов: eh vector constructor (this, 0xA410, 10, …),
    // (this + 240, 0x1050, 10, …), счётчик *(this + 105000) = +0x668A0, проверки a3 > 0xA / a4 > 0xA).
    DbReconnect::Layout MakeLayout()
    {
        DbReconnect::Layout l;
        l.srcSize  = 0xA410;
        l.sessSize = 0x1050;
        l.maxSrc   = 10;
        l.maxSess  = 10;
        l.countOff = 0x668A0;
        return l;
    }

    void LogSink(const wchar_t* line)
    {
        Log::Line(L"%s", line);
    }

    // Имя exe процесса в нижнем регистре.
    void SelfName(wchar_t* out, int cch)
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p) { if (*p == L'\\' || *p == L'/') { name = p + 1; } }
        int i = 0;
        for (; name[i] && i < cch - 1; ++i) { out[i] = (name[i] >= L'A' && name[i] <= L'Z') ? (wchar_t)(name[i] + 32) : name[i]; }
        out[i] = 0;
    }

    // Байты по VA совпадают (чтение под SEH: на чужом образе адреса может не быть).
    bool SameBytes(DWORD va, const BYTE* b, SIZE_T n)
    {
        __try { return memcmp((const void*)va, b, n) == 0; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // Какой образ: по имени exe; если имя не из трёх (стенд), — по CLSID на его месте и началу функции запроса.
    const HostDef* PickHost()
    {
        wchar_t self[MAX_PATH];
        SelfName(self, ARRAYSIZE(self));
        for (const HostDef& h : kHosts) { if (lstrcmpiW(self, h.exe) == 0) { return &h; } }
        for (const HostDef& h : kHosts)
        {
            if (SameBytes(h.clsidVa, kClsid, sizeof(kClsid)) && SameBytes(h.fnQuery, kFnHead, sizeof(kFnHead))) { return &h; }
        }
        return nullptr;
    }
}

// Счётчики для стенда и разбора на живом процессе (раскладка — DbReconnect::Stats, как у P125_GetStats).
extern "C" __declspec(dllexport) void __stdcall P126_GetStats(DbReconnect::Stats* out)
{
    DbReconnect::GetStats(out);
}

PatchResult P126_DbReconnect()
{
    if (!Config::GetBool(kSection, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const HostDef* h = PickHost();
    if (!h)
    {
        Log::Line(L"    MISMATCH P126: образ не опознан (ни имя exe, ни CLSID/функция запроса по адресам трёх известных образов)");
        return PatchResult::Mismatch;
    }

    DbReconnect::Settings st;
    st.retry             = Config::GetBool(kSection, L"Retry", true);
    st.probe             = Config::GetBool(kSection, L"Probe", true);
    st.releaseOld        = Config::GetBool(kSection, L"ReleaseOld", true);
    st.comInit           = Config::GetBool(kSection, L"ComInit", true);
    st.retryIntervalMs   = Config::GetInt (kSection, L"RetryIntervalMs", 10000);
    st.connectTimeoutSec = Config::GetInt (kSection, L"ConnectTimeoutSec", 5);
    st.logPerMinute      = Config::GetInt (kSection, L"LogPerMinute", 30);

    // OperationServer шлёт ВСЕ запросы через источник 0, сессию 0 (11 вызовов sub_406880 из sub_404030), а sub_404030
    // крутят потоки очереди — их число QueueThreadCount из ini\ServerInfo.ini (на стойке 1). При нескольких потоках
    // запись сессии делят потоки (сток и сам тогда гоняется на общем тексте запроса), и освобождать старую команду,
    // пока другой поток может в ней сидеть, нельзя — ReleaseOld принудительно 0 (утечка трёх объектов на обрыв).
    if (h->objBase == 0x00414660)
    {
        wchar_t ini[MAX_PATH];
        wsprintfW(ini, L"%sini\\ServerInfo.ini", Config::BaseDir());
        const UINT queues = GetPrivateProfileIntW(L"THREAD_INFO", L"QueueThreadCount", 0, ini);
        Log::Line(L"    P126: OperationServer, потоков очереди QueueThreadCount=%u (все запросы — сессия 0)", queues);
        if (queues > 1 && st.releaseOld)
        {
            st.releaseOld = false;
            Log::Line(L"    P126: потоков очереди больше одного — объекты оборванной сессии НЕ освобождаются (ReleaseOld=0 принудительно)");
        }
    }

    BYTE iidPush[5] = { 0x68 };
    *(DWORD*)(iidPush + 1) = h->iidVa;
    const Site sites[] =
    {
        { h->siteVa,    kOrig,      sizeof(kOrig)      },
        { h->ctxAVa,    kCtxA,      sizeof(kCtxA)      },
        { h->ctxBVa,    kCtxB,      sizeof(kCtxB)      },
        { h->leaVa,     kLea,       sizeof(kLea)       },
        { h->iidPushVa, iidPush,    sizeof(iidPush)    },
        { h->iidVa,     kIidRowset, sizeof(kIidRowset) },
        { h->clsidVa,   kClsid,     sizeof(kClsid)     },
        { h->fnQuery,   kFnHead,    sizeof(kFnHead)    },
    };
    if (!VerifyAllSites(L"P126", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    DbReconnect::Host host = { h->objBase, L"P126" };
    host.layout = MakeLayout();
    DbReconnect::Configure(host, st, &LogSink);

    // Новые 9 байт: mov [esp+44h], ecx (как в стоке) ; call rel32 → ExecuteHook.
    BYTE code[9] = { 0x89, 0x4C, 0x24, 0x44, 0xE8 };
    *(LONG*)(code + 5) = (LONG)((DWORD)&DbReconnect::ExecuteHook - (h->siteVa + 9));
    if (!Hook::WriteBytes(h->siteVa, code, sizeof(code)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P126: образ %s; вызов Execute @0x%08X (9 б: mov [esp+44h],ecx ; call) -> DbReconnect::ExecuteHook 0x%08X; %s",
              h->title, h->siteVa, (DWORD)&DbReconnect::ExecuteHook,
              h->objBase ? L"объект на постоянном месте" : L"объект не на постоянном месте — источник ищется по записи сессии");
    if (h->objBase) { Log::Line(L"    P126: объект 0x%08X, источник 0xA410 б, сессия 0x1050 б", h->objBase); }
    Log::Line(L"    P126: обрыв связи с базой -> сессия открывается заново%s; Probe=%d ReleaseOld=%d ComInit=%d "
              L"RetryIntervalMs=%d ConnectTimeoutSec=%d LogPerMinute=%d",
              st.retry ? L", запрос повторяется один раз" : L", запрос не повторяется (Retry=0)",
              st.probe ? 1 : 0, st.releaseOld ? 1 : 0, st.comInit ? 1 : 0, st.retryIntervalMs, st.connectTimeoutSec, st.logPerMinute);
    return PatchResult::Applied;
}
