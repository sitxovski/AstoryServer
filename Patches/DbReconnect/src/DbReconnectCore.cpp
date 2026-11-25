// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P125 — ★ ИСПРАВЛЕНИЕ (дефект оригинала): повторное подключение к SQL Server.
//
//  ЭТО НАША ПРАВКА. Общий модуль LoginPatch.dll (LoginManager) и DBPatch.dll (DBManager) — P125,
//  SrvDbPatch.dll (RelayServer ×3, ItemRelayServer, OperationServer) — P126 (15.11.2026; раскладка — Host::layout,
//  у ItemRelayServer объект не на постоянном месте — режим поиска источника по записи, см. Locate).
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Класс работы с базой (LoginManager sub_40E8E0…sub_40F440, DBManager sub_446BA0…sub_447720)
//  открывает источник MSDASQL и 10 сессий ОДИН раз при старте (sub_40EC40 / sub_446F00).
//  Функция запроса (sub_40F440 / sub_447720) при ошибке ICommand::Execute пишет строку
//  «… :: Execute Error» в OLEDB_LOG и возвращает 0. Проверки связи и повторного открытия
//  нет нигде: после любого обрыва TCP (14.11.2026 21:08:15 — самообновление Tailscale, через
//  адрес которого шли соединения) каждая сессия отвечает ошибкой 0x80004005 до перезапуска
//  процесса. Игроки получали «Login failed. Error 0», DBManager не читал и не писал ничего.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Косвенный вызов Execute в функции запроса заменён вызовом ExecuteHook (5 байт).
//  ExecuteHook зовёт Execute сам. Успех — возврат как в стоке. Ошибка:
//    1. Определяем, оборвана ли связь: SQLSTATE 08xxx или сетевой код в сведениях об ошибке;
//       обычная ошибка SQL (классы 21/22/23/37/40/42/S0) — сразу поведение стока;
//       если сведений нет или они неясны — проверка «SELECT 1» на той же сессии.
//    2. Связь оборвана — открываем для ЭТОЙ сессии свой источник (тот же CLSID и те же свойства,
//       что дал сток: DSN, пользователь, пароль), сессию и команду; подменяем три указателя в записи
//       сессии; старые объекты освобождаем.
//    3. Повторяем запрос ОДИН раз на новой команде и возвращаем его результат.
//  Не удалось открыть заново или повтор не прошёл — возвращается ошибка, сток ведёт себя как прежде.
//
//  ── ПОЧЕМУ СВОЙ ИСТОЧНИК НА СЕССИЮ, А НЕ ОБЩИЙ ──
//  Общий источник стока делят 10 потоков. Закрывать и открывать его заново из одного потока,
//  пока остальные девять выполняют запросы на своих сессиях, нельзя. Запись же одной сессии
//  принадлежит одному рабочему потоку (номер сессии = номер потока), её подмена никого не задевает.
//
//  ── ГРАНИЦЫ ──
//  • Повтор после обрыва НА ОТПРАВКЕ безопасен (запрос до сервера не дошёл). При обрыве на
//    ПРИЁМЕ ответа сервер мог успеть выполнить запрос — повтор выполнит его второй раз.
//    Выключается ключом Retry=0 (тогда сессия открывается заново, а запрос отдаёт ошибку стоку).
//  • После неудачной попытки сессия не пробует снова RetryIntervalMs — рабочий поток не висит
//    на каждом запросе, пока сервер базы недоступен.
//  • Всё тело после стокового Execute обёрнуто в SEH: при любом сбое модуля возвращается
//    исходная ошибка, поведение стока.
// ─────────────────────────────────────────────────────────────────────────────
#include "DbReconnectCore.h"
#include <oledb.h>
#include <oledberr.h>
#include <stdarg.h>
#include <stdio.h>

namespace
{
    // GUID-ы заданы здесь, чтобы модуль не зависел от библиотек SDK. Значения совпадают с теми,
    // что лежат в образах стока (сверено по адресам 0x4309C0/0x435A7C/0x435A6C/0x435A4C/0x435A3C/
    // 0x4359FC/0x4309B0 LoginManager и 0x478DA0/0x47DEAC/0x47DE9C/0x47DE7C/0x47DE6C/0x47DE2C/0x478D90 DBManager).
    const GUID kClsidMsdasql      = { 0xC8B522CB, 0x5CF3, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidDBInitialize   = { 0x0C733A8B, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidDBProperties   = { 0x0C733A8A, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidDBCreateSession= { 0x0C733A5D, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidDBCreateCommand= { 0x0C733A1D, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidCommandText    = { 0x0C733A27, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidErrorRecords   = { 0x0C733A67, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidSQLErrorInfo   = { 0x0C733A74, 0x2A1C, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kDbGuidDefault     = { 0xC8B521FB, 0x5CF3, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kPropSetDbInit     = { 0xC8B522BC, 0x5CF3, 0x11CE, { 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D } };
    const GUID kIidNull           = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

    const DBPROPID kPropInitTimeout = 0x42;   // DBPROP_INIT_TIMEOUT

    // Состояние одной сессии, открытой нами заново.
    struct Slot
    {
        IDBInitialize* dso;        // наш источник этой сессии (nullptr — сессия ещё стоковая)
        DWORD          lastFail;   // GetTickCount последней неудачной попытки
        bool           failed;     // последняя попытка открыть заново не удалась (lastFail действителен)
        LONG           reconnects; // сколько раз сессия открывалась заново
    };

    DbReconnect::Host     g_host     = { 0, L"P125" };
    DbReconnect::Settings g_set      = { true, true, true, true, 10000, 5, 30 };
    DbReconnect::LogFn    g_log      = nullptr;
    volatile LONG         g_on       = 0;
    DbReconnect::Stats    g_stats    = {};
    Slot                  g_slots[DbReconnect::kMaxSrc][DbReconnect::kMaxSess] = {};

    // ── режим поиска (objBase = 0, P126 ItemRelayServer) ────────────────────
    // Состояние сессии хранится по адресу её записи. Записи объектов, созданных в куче, живут до выхода процесса;
    // временный объект на стеке (ItemRelayServer sub_408110, разовая выборка при старте) может оставить запись, адрес
    // которой потом займёт другая — её состояние (наш источник, если он был открыт) тогда честно освободится при
    // следующем переподключении этого адреса, как «прежний источник сессии».
    struct Loose
    {
        BYTE* volatile rec;   // адрес записи сессии (nullptr — свободно)
        Slot           slot;
    };
    Loose g_loose[DbReconnect::kMaxLoose] = {};

    // Найти или занять ячейку для записи rec. nullptr — таблица полна (поведение стока).
    Slot* LooseSlot(BYTE* rec)
    {
        for (DWORD i = 0; i < DbReconnect::kMaxLoose; ++i)
        {
            BYTE* const cur = g_loose[i].rec;
            if (cur == rec) { return &g_loose[i].slot; }
            if (cur == nullptr)
            {
                BYTE* const was = (BYTE*)InterlockedCompareExchangePointer((PVOID volatile*)&g_loose[i].rec, rec, nullptr);
                if (was == nullptr || was == rec) { return &g_loose[i].slot; }
            }
        }
        return nullptr;
    }

    // Похоже ли место cand на открытый источник стока: DBPROPSET указывает на свои же 4 свойства, набор DBPROPSET_DBINIT,
    // источник создан. Чтение под SEH: кандидат с большим номером сессии может лежать перед объектом, вне памяти.
    bool LooksLikeSource(const BYTE* cand)
    {
        __try
        {
            const DBPROPSET* ps = (const DBPROPSET*)(cand + DbReconnect::kPropSetOff);
            return (const BYTE*)ps->rgProperties == cand + DbReconnect::kPropsOff &&
                   ps->cProperties >= 1 && ps->cProperties <= 8 &&
                   memcmp(&ps->guidPropertySet, &kPropSetDbInit, sizeof(GUID)) == 0 &&
                   *(void* const*)cand != nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // ── журнал с ограничением частоты ───────────────────────────────────────
    volatile LONG g_logWindow = 0;   // номер минуты текущего окна
    volatile LONG g_logCount  = 0;   // строк в текущем окне

    void LogLine(const wchar_t* fmt, ...)
    {
        if (!g_log) { return; }
        const LONG minute = (LONG)(GetTickCount() / 60000u);
        if (InterlockedExchange(&g_logWindow, minute) != minute) { InterlockedExchange(&g_logCount, 0); }
        if (InterlockedIncrement(&g_logCount) > (LONG)g_set.logPerMinute) { return; }

        wchar_t buf[700];
        va_list va;
        va_start(va, fmt);
        _vsnwprintf(buf, ARRAYSIZE(buf) - 1, fmt, va);
        va_end(va);
        buf[ARRAYSIZE(buf) - 1] = 0;
        g_log(buf);
    }

    // Имя процедуры из текста запроса: «EXEC UPUserLogin '…'» → «UPUserLogin».
    // Сам текст в журнал не идёт никогда (в нём логины, хеши паролей, адреса).
    void ProcName(const wchar_t* text, wchar_t* out, int cch)
    {
        int n = 0;
        out[0] = 0;
        if (!text) { return; }
        const wchar_t* p = text;
        while (*p == L' ') { ++p; }
        if ((p[0] == L'E' || p[0] == L'e') && (p[1] == L'X' || p[1] == L'x') &&
            (p[2] == L'E' || p[2] == L'e') && (p[3] == L'C' || p[3] == L'c'))
        {
            p += 4;
            if ((p[0] == L'U' || p[0] == L'u') && (p[1] == L'T' || p[1] == L't') && (p[2] == L'E' || p[2] == L'e')) { p += 3; }
            while (*p == L' ') { ++p; }
        }
        while (*p && *p != L' ' && *p != L'\'' && *p != L',' && n < cch - 1) { out[n++] = *p++; }
        out[n] = 0;
    }

    // ── что говорит об ошибке поставщик ─────────────────────────────────────
    enum Verdict { V_Unknown = 0, V_Dead = 1, V_Alive = 2 };

    // Сетевые коды, с которыми драйвер сообщает об оборванном соединении.
    bool IsNetCode(LONG native)
    {
        switch (native)
        {
            case 10054: case 10053: case 10060: case 10061: case 10065: case 10051:
            case 64: case 121: case 233: case 109: case 11:
                return true;
        }
        return false;
    }

    // Класс SQLSTATE, однозначно означающий обычную ошибку запроса на живом соединении.
    bool IsPlainSqlState(const wchar_t* st)
    {
        static const wchar_t* const kClasses[] = { L"21", L"22", L"23", L"37", L"40", L"42", L"S0" };
        for (const wchar_t* c : kClasses)
        {
            if (st[0] == c[0] && st[1] == c[1]) { return true; }
        }
        return false;
    }

    // Читает сведения об ошибке потока и возвращает их на место. Сток их после нас не читает: его функция описания
    // ошибки сама стирает их (SetErrorInfo(0, NULL) перед GetErrorInfo), возврат сделан для порядка.
    Verdict Classify(wchar_t* state, int cchState, LONG* native, wchar_t* desc, int cchDesc)
    {
        state[0] = 0; desc[0] = 0; *native = 0;
        IErrorInfo* ei = nullptr;
        if (GetErrorInfo(0, &ei) != S_OK || !ei) { return V_Unknown; }

        Verdict v = V_Unknown;
        IErrorRecords* recs = nullptr;
        if (SUCCEEDED(ei->QueryInterface(kIidErrorRecords, (void**)&recs)) && recs)
        {
            ULONG n = 0;
            recs->GetRecordCount(&n);
            for (ULONG i = 0; i < n && i < 16; ++i)
            {
                ISQLErrorInfo* sq = nullptr;
                if (FAILED(recs->GetCustomErrorObject(i, kIidSQLErrorInfo, (IUnknown**)&sq)) || !sq) { continue; }
                BSTR st = nullptr;
                LONG nat = 0;
                if (SUCCEEDED(sq->GetSQLInfo(&st, &nat)) && st)
                {
                    if (SysStringLen(st) >= 2)
                    {
                        // Порядок важен: 08xxx — обрыв; класс обычной ошибки SQL — связь жива (и сетевой код НЕ смотрим:
                        // 109, 121, 233 — ещё и номера обычных сообщений SQL Server); сетевой код учитывается только
                        // у классов 01 (предупреждение драйвера «ConnectionWrite»), HY и S1 (общая ошибка).
                        const bool cls08   = st[0] == L'0' && st[1] == L'8';
                        const bool plain   = IsPlainSqlState(st);
                        const bool general = (st[0] == L'0' && st[1] == L'1') || (st[0] == L'H' && st[1] == L'Y') ||
                                             (st[0] == L'S' && st[1] == L'1');
                        if (cls08 || (!plain && general && IsNetCode(nat)))
                        {
                            v = V_Dead;
                            lstrcpynW(state, st, cchState);
                            *native = nat;
                            // Текст именно этой записи (общий GetDescription у MSDASQL пуст).
                            IErrorInfo* rei = nullptr;
                            HRESULT hre = recs->GetErrorInfo(i, GetSystemDefaultLCID(), &rei);
                            if (FAILED(hre) || !rei) { rei = nullptr; hre = recs->GetErrorInfo(i, 0x0409, &rei); }
                            if (SUCCEEDED(hre) && rei)
                            {
                                BSTR rd = nullptr;
                                if (SUCCEEDED(rei->GetDescription(&rd)) && rd)
                                {
                                    lstrcpynW(desc, rd, cchDesc);
                                    SysFreeString(rd);
                                }
                                rei->Release();
                            }
                        }
                        else if (v == V_Unknown && plain)
                        {
                            v = V_Alive;
                            lstrcpynW(state, st, cchState);
                            *native = nat;
                        }
                        else if (state[0] == 0)
                        {
                            lstrcpynW(state, st, cchState);
                            *native = nat;
                        }
                    }
                    SysFreeString(st);
                }
                sq->Release();
            }
            recs->Release();
        }

        BSTR d = nullptr;
        if (SUCCEEDED(ei->GetDescription(&d)) && d)
        {
            if (desc[0] == 0) { lstrcpynW(desc, d, cchDesc); }
            SysFreeString(d);
        }

        SetErrorInfo(0, ei);
        ei->Release();
        return v;
    }

    // Проверка связи на той же команде. true — связь оборвана.
    // Неудача пробы считается обрывом, кроме случая, когда её собственная ошибка — обычная ошибка SQL.
    bool ProbeDead(ICommandText* cmd, const wchar_t* text, wchar_t* state, int cchState, LONG* native, wchar_t* desc, int cchDesc)
    {
        if (FAILED(cmd->SetCommandText(kDbGuidDefault, L"SELECT 1"))) { return false; }
        const HRESULT hr = cmd->Execute(nullptr, kIidNull, nullptr, nullptr, nullptr);
        if (SUCCEEDED(hr))
        {
            cmd->SetCommandText(kDbGuidDefault, text);   // вернуть текст запроса стока
            return false;
        }
        if (Classify(state, cchState, native, desc, cchDesc) == V_Alive)
        {
            cmd->SetCommandText(kDbGuidDefault, text);
            return false;
        }
        return true;
    }

    void SafeRelease(IUnknown* p)
    {
        if (!p) { return; }
        __try { p->Release(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.exceptions); }
    }

    void SafeCloseDso(IDBInitialize* dso)
    {
        if (!dso) { return; }
        __try { dso->Uninitialize(); dso->Release(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.exceptions); }
    }

    // COM на рабочем потоке. Сток зовёт CoInitialize только в главном потоке; чужие указатели рабочим потокам годятся
    // и так, но без COM на потоке (а) поставщик не оставляет сведений об ошибке — обрыв пришлось бы определять только
    // пробой, (б) CoCreateInstance откажет. Поэтому при ComInit=1 поток инициализируется один раз, перед первым Execute.
    __declspec(thread) int t_com = 0;   // 0 — ещё не пробовали, 1 — COM есть, 2 — не удалось

    bool EnsureCom()
    {
        if (t_com == 1) { return true; }
        const HRESULT h = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (h == S_FALSE) { CoUninitialize(); }                 // уже был — счётчик не трогаем
        const bool ok = h == S_OK || h == S_FALSE || h == RPC_E_CHANGED_MODE;   // S_OK оставляем до конца жизни потока
        t_com = ok ? 1 : 2;
        return ok;
    }

    // Создать цепочку источник → сессия → команда. Указатели пишутся в выходные параметры по мере создания,
    // чтобы вызывающий мог освободить набранное и при ошибке, и при исключении.
    HRESULT CreateChain(const DBPROPSET* stock, IDBInitialize** pDso, bool* pInit,
                        IDBCreateSession** pCs, IDBCreateCommand** pSess, ICommandText** pCmd)
    {
        // Копия свойств: SetProperties пишет в них статус, а источник стока общий для 10 потоков.
        DBPROP    props[8];
        DBPROPSET set;
        for (ULONG i = 0; i < stock->cProperties; ++i) { props[i] = stock->rgProperties[i]; }
        set.rgProperties    = props;
        set.cProperties     = stock->cProperties;
        set.guidPropertySet = stock->guidPropertySet;

        IDBProperties* prp = nullptr;
        HRESULT hr = CoCreateInstance(kClsidMsdasql, nullptr, CLSCTX_INPROC_SERVER, kIidDBInitialize, (void**)pDso);
        if (SUCCEEDED(hr) && *pDso) { hr = (*pDso)->QueryInterface(kIidDBProperties, (void**)&prp); }
        if (SUCCEEDED(hr) && prp)
        {
            hr = prp->SetProperties(1, &set);
            if (SUCCEEDED(hr) && g_set.connectTimeoutSec > 0)
            {
                // Предел ожидания подключения. Отказ поставщика в этом свойстве не мешает работе.
                DBPROP    tp;
                DBPROPSET ts;
                ZeroMemory(&tp, sizeof(tp));
                tp.dwPropertyID = kPropInitTimeout;
                tp.dwOptions    = DBPROPOPTIONS_OPTIONAL;
                tp.vValue.vt    = VT_I4;
                tp.vValue.lVal  = g_set.connectTimeoutSec;
                ts.rgProperties    = &tp;
                ts.cProperties     = 1;
                ts.guidPropertySet = kPropSetDbInit;
                prp->SetProperties(1, &ts);
            }
            prp->Release();
        }
        if (SUCCEEDED(hr)) { hr = (*pDso)->Initialize(); *pInit = SUCCEEDED(hr); }
        if (SUCCEEDED(hr)) { hr = (*pDso)->QueryInterface(kIidDBCreateSession, (void**)pCs); }
        if (SUCCEEDED(hr) && *pCs)   { hr = (*pCs)->CreateSession(nullptr, kIidDBCreateCommand, (IUnknown**)pSess); }
        if (SUCCEEDED(hr) && *pSess) { hr = (*pSess)->CreateCommand(nullptr, kIidCommandText, (IUnknown**)pCmd); }
        return hr;
    }

    // То же под SEH: исключение внутри поставщика или драйвера не должно оставить набранное висеть.
    HRESULT CreateChainGuarded(const DBPROPSET* stock, IDBInitialize** pDso, bool* pInit,
                               IDBCreateSession** pCs, IDBCreateCommand** pSess, ICommandText** pCmd)
    {
        __try
        {
            return CreateChain(stock, pDso, pInit, pCs, pSess, pCmd);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedIncrement(&g_stats.exceptions);
            return E_UNEXPECTED;
        }
    }

    // Открыть для сессии (rec) новый источник, сессию и команду и подменить указатели.
    // srcBase — начало источника стока (оттуда берутся свойства: DSN, пользователь, пароль).
    bool Reconnect(BYTE* srcBase, BYTE* rec, Slot& slot, HRESULT* why)
    {
        *why = E_FAIL;
        if (!EnsureCom()) { *why = CO_E_NOTINITIALIZED; return false; }

        // Свойства стока: DBPROPSET лежит в источнике, в нём указатель на 4 свойства.
        const DBPROPSET* stock = (const DBPROPSET*)(srcBase + DbReconnect::kPropSetOff);
        if (!stock->rgProperties || stock->cProperties == 0 || stock->cProperties > 8) { *why = E_INVALIDARG; return false; }

        IDBInitialize*    dso  = nullptr;
        IDBCreateSession* cs   = nullptr;
        IDBCreateCommand* sess = nullptr;
        ICommandText*     cmd  = nullptr;
        bool              init = false;
        const HRESULT hr = CreateChainGuarded(stock, &dso, &init, &cs, &sess, &cmd);

        if (FAILED(hr) || !cs || !sess || !cmd)
        {
            *why = FAILED(hr) ? hr : E_NOINTERFACE;
            SafeRelease(cmd);
            SafeRelease(sess);
            SafeRelease(cs);
            if (dso)
            {
                if (init) { SafeCloseDso(dso); } else { SafeRelease(dso); }
            }
            return false;
        }

        // Подмена трёх указателей записи сессии. Запись принадлежит вызвавшему потоку.
        IUnknown* oldCs   = *(IUnknown**)(rec + DbReconnect::kRecCreate);
        IUnknown* oldSess = *(IUnknown**)(rec + DbReconnect::kRecSession);
        IUnknown* oldCmd  = *(IUnknown**)(rec + DbReconnect::kRecCommand);
        *(void**)(rec + DbReconnect::kRecCreate)  = cs;
        *(void**)(rec + DbReconnect::kRecSession) = sess;
        *(void**)(rec + DbReconnect::kRecCommand) = cmd;

        IDBInitialize* oldDso = slot.dso;
        slot.dso = dso;
        InterlockedIncrement(&slot.reconnects);

        if (g_set.releaseOld)
        {
            SafeRelease(oldCmd);
            SafeRelease(oldSess);
            SafeRelease(oldCs);
            SafeCloseDso(oldDso);   // наш прежний источник этой сессии (при втором и следующих обрывах)
        }
        *why = S_OK;
        return true;
    }

    // Найти запись сессии по адресу поля результата. nullptr — не наш объект, поведение стока.
    // where — «источник N, сессия M» для журнала.
    Slot* Locate(void** ppRowset, void* cmd, BYTE** srcBase, BYTE** rec, wchar_t* where, int cchWhere)
    {
        if (!ppRowset) { return nullptr; }
        const DbReconnect::Layout& L = g_host.layout;
        BYTE* const r = (BYTE*)ppRowset - DbReconnect::kRecRowset;
        if (*(void**)(r + DbReconnect::kRecCommand) != cmd) { return nullptr; }

        if (g_host.objBase)
        {
            // Объект на постоянном месте (LoginManager, DBManager, RelayServer, OperationServer).
            BYTE* const obj   = (BYTE*)g_host.objBase;
            BYTE* const first = obj + DbReconnect::kSessOff;
            if (r < first) { return nullptr; }
            const DWORD off = (DWORD)(r - first);
            const DWORD s   = off / L.srcSize;
            const DWORD rem = off % L.srcSize;
            if (s >= L.maxSrc || s >= DbReconnect::kMaxSrc) { return nullptr; }
            if (rem % L.sessSize != 0)                     { return nullptr; }
            const DWORD j = rem / L.sessSize;
            if (j >= L.maxSess || j >= DbReconnect::kMaxSess) { return nullptr; }
            const LONG opened = *(LONG*)(obj + L.countOff);
            if (opened <= 0 || s >= (DWORD)opened)         { return nullptr; }
            *srcBase = obj + s * L.srcSize;
            *rec     = r;
            _snwprintf(where, cchWhere - 1, L"источник %u, сессия %u", s, j);
            where[cchWhere - 1] = 0;
            return &g_slots[s][j];
        }

        // Режим поиска (ItemRelayServer): номер сессии j неизвестен — источник = запись − 0xF0 − j·размер сессии,
        // берётся первый j, на месте которого лежит открытый источник (см. LooksLikeSource).
        for (DWORD j = 0; j < L.maxSess; ++j)
        {
            BYTE* const cand = r - DbReconnect::kSessOff - j * L.sessSize;
            if (cand > r || !LooksLikeSource(cand)) { continue; }
            Slot* const slot = LooseSlot(r);
            if (!slot) { return nullptr; }
            *srcBase = cand;
            *rec     = r;
            _snwprintf(where, cchWhere - 1, L"источник 0x%08X, сессия %u", (DWORD)cand, j);
            where[cchWhere - 1] = 0;
            return slot;
        }
        return nullptr;
    }

    // Разбор ошибки Execute. Возвращает то, что должен увидеть сток.
    HRESULT OnFailBody(HRESULT hr, ICommandText* cmd, void* outer, const GUID* riid,
                       void* params, void* rows, void** ppRowset)
    {
        InterlockedIncrement(&g_stats.execFail);

        BYTE*   srcBase = nullptr;
        BYTE*   rec     = nullptr;
        wchar_t where[64];
        Slot* const ps = Locate(ppRowset, cmd, &srcBase, &rec, where, ARRAYSIZE(where));
        if (!ps)
        {
            InterlockedIncrement(&g_stats.passthrough);
            return hr;
        }
        Slot& slot = *ps;
        const wchar_t* const text = (const wchar_t*)(rec + DbReconnect::kRecText);

        // Пауза после неудачной попытки — ДО разбора ошибки и пробы: пока база недоступна, запрос отдаёт ошибку стоку
        // сразу, без второго ожидания на мёртвом соединении.
        if (slot.failed && (DWORD)(GetTickCount() - slot.lastFail) < (DWORD)g_set.retryIntervalMs)
        {
            InterlockedIncrement(&g_stats.throttled);
            return hr;
        }

        wchar_t state[8], desc[200], proc[64];
        LONG    native = 0;
        Verdict v = Classify(state, ARRAYSIZE(state), &native, desc, ARRAYSIZE(desc));
        if (v == V_Alive)
        {
            InterlockedIncrement(&g_stats.aliveByState);
            return hr;
        }
        bool byProbe = false;
        if (v == V_Unknown)
        {
            if (!g_set.probe || !ProbeDead(cmd, text, state, ARRAYSIZE(state), &native, desc, ARRAYSIZE(desc)))
            {
                InterlockedIncrement(&g_stats.aliveByProbe);
                return hr;
            }
            byProbe = true;
            InterlockedIncrement(&g_stats.deadByProbe);
        }
        else
        {
            InterlockedIncrement(&g_stats.deadByState);
        }

        ProcName(text, proc, ARRAYSIZE(proc));

        // Причина одной строкой: чем определён обрыв, код, исходная ошибка, имя процедуры.
        wchar_t cause[420];
        _snwprintf(cause, ARRAYSIZE(cause) - 1, L"%s%s, код %ld, hr 0x%08X, «%s», запрос %s",
                   byProbe ? L"проверка SELECT 1, SQLSTATE " : L"SQLSTATE ", state,
                   native, (unsigned)hr, desc, proc);
        cause[ARRAYSIZE(cause) - 1] = 0;

        HRESULT why = E_FAIL;
        if (!Reconnect(srcBase, rec, slot, &why))
        {
            slot.lastFail = GetTickCount();
            slot.failed   = true;
            InterlockedIncrement(&g_stats.reconnectFail);
            LogLine(L"    %s: %s — связь с базой оборвана (%s); открыть заново НЕ удалось "
                    L"(hr 0x%08X), следующая попытка не раньше чем через %d мс",
                    g_host.tag, where, cause, (unsigned)why, g_set.retryIntervalMs);
            return hr;
        }
        slot.failed = false;
        InterlockedIncrement(&g_stats.reconnectOk);

        if (!g_set.retry)
        {
            LogLine(L"    %s: %s — связь с базой оборвана (%s); сессия открыта заново (раз %ld), "
                    L"запрос НЕ повторён (Retry=0)", g_host.tag, where, cause, slot.reconnects);
            return hr;
        }

        // Один повтор на новой команде.
        ICommandText* fresh = *(ICommandText**)(rec + DbReconnect::kRecCommand);
        HRESULT hr2 = fresh->SetCommandText(kDbGuidDefault, text);
        if (SUCCEEDED(hr2))
        {
            hr2 = fresh->Execute((IUnknown*)outer, *riid, (DBPARAMS*)params, (DBROWCOUNT*)rows, (IUnknown**)ppRowset);
        }
        if (SUCCEEDED(hr2)) { InterlockedIncrement(&g_stats.retryOk); }
        else                { InterlockedIncrement(&g_stats.retryFail); }
        LogLine(L"    %s: %s — связь с базой оборвана (%s); сессия открыта заново (раз %ld), "
                L"повтор запроса: %s (hr 0x%08X)", g_host.tag, where, cause, slot.reconnects,
                SUCCEEDED(hr2) ? L"УДАЧНО" : L"ошибка", (unsigned)hr2);
        return hr2;
    }

    HRESULT OnFail(HRESULT hr, ICommandText* cmd, void* outer, const GUID* riid,
                   void* params, void* rows, void** ppRowset)
    {
        __try
        {
            return OnFailBody(hr, cmd, outer, riid, params, rows, ppRowset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedIncrement(&g_stats.exceptions);
            return hr;
        }
    }
}

namespace DbReconnect
{
    void Configure(const Host& host, const Settings& settings, LogFn log)
    {
        g_host = host;
        g_set  = settings;
        // Раскладка не может выйти за таблицу состояний: лишние источники/сессии — поведение стока (Locate их не опознаёт).
        if (g_host.layout.maxSrc  > kMaxSrc)  { g_host.layout.maxSrc  = kMaxSrc; }
        if (g_host.layout.maxSess > kMaxSess) { g_host.layout.maxSess = kMaxSess; }
        if (g_host.layout.srcSize == 0 || g_host.layout.sessSize == 0) { g_host.layout = Layout(); }
        if (g_set.retryIntervalMs < 0)     { g_set.retryIntervalMs = 0; }
        if (g_set.retryIntervalMs > 600000){ g_set.retryIntervalMs = 600000; }
        if (g_set.connectTimeoutSec < 0)   { g_set.connectTimeoutSec = 0; }
        if (g_set.connectTimeoutSec > 60)  { g_set.connectTimeoutSec = 60; }
        if (g_set.logPerMinute < 0)        { g_set.logPerMinute = 0; }
        g_log = log;
        InterlockedExchange(&g_on, 1);
    }

    HRESULT __stdcall ExecuteHook(void* cmdV, void* outer, const GUID* riid,
                                  void* params, void* rows, void** ppRowset)
    {
        ICommandText* const cmd = (ICommandText*)cmdV;
        if (g_on && g_set.comInit && t_com == 0) { EnsureCom(); }   // один раз на поток — чтобы поставщик оставлял сведения об ошибке
        const HRESULT hr = cmd->Execute((IUnknown*)outer, *riid, (DBPARAMS*)params,
                                        (DBROWCOUNT*)rows, (IUnknown**)ppRowset);
        if (SUCCEEDED(hr) || !g_on) { return hr; }
        return OnFail(hr, cmd, outer, riid, params, rows, ppRowset);
    }

    void GetStats(Stats* out)
    {
        if (out) { *out = g_stats; }
    }
}
