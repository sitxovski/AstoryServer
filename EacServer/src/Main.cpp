// Copyright (c) 2026 @sitxovski (Discord)
// Main.cpp — точка входа AsdaEacServer.exe: разбор ключей, служба Windows (SCM), консольный режим, запуск слушателей.
//
// Ключи:
//   --console              работа в консоли (Ctrl+C — останов)
//   --service              запуск под SCM (так прописывает --install-service)
//   --install-service      создать службу AsdaEacServer (автозапуск, перезапуск при сбое) — НЕ выполнять до Э2-0
//   --uninstall-service    остановить и удалить службу
//   --config <путь>        ini (по умолчанию EacServer.ini рядом с exe)
//   --no-eos               не инициализировать EOS (стенды без секретов): REG → REG_RESULT 3
//   --eos-smoke            Initialize + Platform_Create + BeginSession + 3 с тиков, затем выход (нужен secrets\eos.json)
//   ★ только сборка стенда (ASDA_EAC_STAND): --fake-auth (таблица учёток без БД), --fake-eos (имитация EOS)
#include "EacCommon.h"
#include "Config.h"
#include "Log.h"
#include "Crypto.h"
#include "Jwt.h"
#include "SqlAuth.h"
#include "AsdaId.h"
#include "EosLayer.h"
#include "Core.h"
#include "AdminStatus.h"
#include "AsdaSecure.h"
#include <atomic>
#include <cstdio>

namespace
{
    using namespace Eac;

    const wchar_t* kServiceName = L"AsdaEacServer";                       // имя службы
    const wchar_t* kServiceDisplay = L"AsdaReborn EAC Server (AsdaId + sidecar)";

    std::atomic<bool> g_stop{ false };                                     // запрос останова
    SERVICE_STATUS_HANDLE g_svcHandle = nullptr;                           // дескриптор состояния службы
    SERVICE_STATUS g_svcStatus{};                                          // текущее состояние службы

    // Флаги командной строки.
    struct Args
    {
        bool console = false, service = false, install = false, uninstall = false, noEos = false, eosSmoke = false;
        bool fakeAuth = false, fakeEos = false;   // только стенд
        std::wstring probeLogin, probeMd5;         // только стенд: --sql-probe <логин> <md5> (пароль SQL — из stdin)
        bool sqlProbe = false;
        std::wstring probeStatusUi;                // только стенд: --sql-probe-status <UserIndex> (UPEacAuthStatus, только чтение)
        std::wstring config;
        bool bad = false; std::wstring badArg;
    };

    Args ParseArgs(int argc, wchar_t** argv)
    {
        Args a;
        for (int i = 1; i < argc; ++i)
        {
            std::wstring s = argv[i];
            if (s == L"--console") a.console = true;
            else if (s == L"--service") a.service = true;
            else if (s == L"--install-service") a.install = true;
            else if (s == L"--uninstall-service") a.uninstall = true;
            else if (s == L"--no-eos") a.noEos = true;
            else if (s == L"--eos-smoke") a.eosSmoke = true;
            else if (s == L"--config" && i + 1 < argc) a.config = argv[++i];
#ifdef ASDA_EAC_STAND
            else if (s == L"--fake-auth") a.fakeAuth = true;
            else if (s == L"--fake-eos") a.fakeEos = true;
            else if (s == L"--sql-probe" && i + 2 < argc) { a.sqlProbe = true; a.probeLogin = argv[++i]; a.probeMd5 = argv[++i]; }
            else if (s == L"--sql-probe-status" && i + 1 < argc) { a.sqlProbe = true; a.probeStatusUi = argv[++i]; }
#endif
            else { a.bad = true; a.badArg = s; }
        }
        if (a.config.empty()) a.config = ExeDir() + L"EacServer.ini";
        else a.config = ResolvePath(a.config);
        return a;
    }

    // Источник проверки, всегда отвечающий «ошибка» (нет секрета SQL) — AsdaId даёт 503, сайдкар работает.
    class ErrorAuth : public IAuthBackend
    {
    public:
        AuthResult Check(const std::string&, const std::string&) override { AuthResult r; r.verdict = AuthVerdict::Error; return r; }
        StatusResult CheckStatus(uint32_t) override { StatusResult r; r.verdict = AuthVerdict::Error; return r; }
        bool RecordFail(const std::string&, int& status) override { status = -1; return false; }
    };

    // Основная работа (консоль/служба). Код возврата: 0 — штатный останов.
    int RunServer(const Args& args)
    {
        Config cfg; std::string err;
        bool cfgOk = cfg.Load(args.config, &err);
        Log::Init(cfgOk ? cfg.logDir : ExeDir() + L"logs", args.console, cfgOk ? cfg.logLevel : 2);
        LOGI("main", "──── AsdaEacServer старт (pid %lu, %s) ────", GetCurrentProcessId(), args.service ? "служба" : "консоль");
#ifdef ASDA_EAC_STAND
        LOGW("main", "★ СБОРКА СТЕНДА (ASDA_EAC_STAND): доступны --fake-auth/--fake-eos — НЕ для стойки");
#endif
        if (!cfgOk) { LOGE("main", "конфиг: %s", err.c_str()); return 2; }
        LOGI("main", "ini %s: Mode=%d FailOpen=%d (окно %d с) BindTimeout=%d Grace=%d операторов %zu", Utf8(args.config).c_str(), cfg.mode,
             (int)cfg.failOpen, cfg.failOpenStartupSec, cfg.bindTimeoutSec, cfg.graceSec, cfg.operators.size());

        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { LOGE("main", "WSAStartup"); return 2; }

        // AsdaSecure: долговременный ключ сервера (тот же, что у P61/L07), только чтение.
        static AsdaSecure::PrivateKey secKey;
        if (!AsdaSecure::Init()) { LOGE("main", "AsdaSecure::Init (CNG) не удался: 0x%08lx", (unsigned long)AsdaSecure::LastStatus()); return 2; }
        if (!AsdaSecure::LoadPrivateKeyFile(cfg.secureKeyFile.c_str(), secKey))
        {
            LOGE("main", "ключ AsdaSecure не загружен: %s", Utf8(cfg.secureKeyFile).c_str());
            return 2;
        }
        AsdaSecure::ServerSignerLoad(secKey);   // sec2: дескрипторы подписи — один импорт на процесс
        AsdaSecure::EphemeralPoolStart(16);     // sec2: заготовки эфемерных пар ECDH
        LOGI("main", "ключ AsdaSecure загружен: %s", Utf8(cfg.secureKeyFile).c_str());

        // Ключ JWT RS256: загрузить или создать при первом запуске.
        static Crypto::RsaKey jwtKey;
        if (GetFileAttributesW(cfg.jwtKey.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            if (!jwtKey.Generate(2048) || !jwtKey.SaveFileNew(cfg.jwtKey, &err))
            {
                LOGE("main", "ключ JWT не создан (%s): %s", Utf8(cfg.jwtKey).c_str(), err.c_str());
                return 2;
            }
            LOGW("main", "создан НОВЫЙ ключ JWT RSA-2048: %s (kid=%s)", Utf8(cfg.jwtKey).c_str(), Jwt::Kid(jwtKey).c_str());
        }
        else if (!jwtKey.LoadFile(cfg.jwtKey, &err))
        {
            LOGE("main", "ключ JWT не загружен (%s): %s", Utf8(cfg.jwtKey).c_str(), err.c_str());
            return 2;
        }
        if (jwtKey.Bits() != 2048) { LOGE("main", "ключ JWT %u бит — нужен RSA-2048", jwtKey.Bits()); return 2; }

        // Источник проверки пароля.
        AsdaIdServer::AuthFactory factory;
#ifdef ASDA_EAC_STAND
        if (args.fakeAuth)
        {
            LOGW("main", "★ СТЕНД: --fake-auth — учётки из таблицы стенда, БД не используется");
            factory = [] { return MakeFakeAuth(); };
        }
#endif
        if (!factory)
        {
            std::string pw;
            if (ReadSecretLine(cfg.sqlPasswordFile, pw, &err))
            {
                std::string cs = cfg.sqlConnString; int to = cfg.sqlTimeoutSec;
                factory = [cs, pw, to] { return MakeOdbcAuth(cs, pw, to); };
                LOGI("main", "UPEacAuth: ODBC, пароль из %s", Utf8(cfg.sqlPasswordFile).c_str());
            }
            else
            {
                LOGE("main", "секрет SQL не прочитан (%s) — /token будет отвечать 503", err.c_str());
                factory = [] { return std::unique_ptr<IAuthBackend>(new ErrorAuth()); };
            }
            SecureZeroMemory(&pw[0], pw.size());
        }

        // EOS.
        std::unique_ptr<IEos> eos;
        EosSecrets sec;
#ifdef ASDA_EAC_STAND
        if (args.fakeEos) eos = MakeFakeEos();
#endif
        if (!eos)
        {
            if (args.noEos) eos = MakeNullEos();
            else if (sec.Load(cfg.eosJson, &err)) eos = MakeRealEos(cfg, sec);
            else { LOGE("main", "секреты EOS не прочитаны (%s) — EAC без EOS: REG → REG_RESULT 3", err.c_str()); eos = MakeNullEos(); }
        }

        AsdaIdServer id;
        if (!id.Start(cfg, &jwtKey, factory, &err)) { LOGE("main", "AsdaId: %s", err.c_str()); return 4; }
        Core core(cfg, eos.get(), &secKey);
        if (!core.Start(&err)) { LOGE("main", "ядро: %s", err.c_str()); id.Stop(); return 4; }
        // ★ А6.8 (22.11.2026): точка статуса для панели 127.0.0.1:[AdminStatus] Port (только чтение). Не запустилась — EAC работает без неё.
        AdminStatus::Board statusBoard;
        AdminStatus::Server statusSrv;
        if (statusSrv.Start(cfg, &statusBoard)) core.SetStatusBoard(&statusBoard);

        core.Run(g_stop);   // до останова

        statusSrv.Stop();
        LOGI("main", "останов: AsdaId…");
        id.Stop();
        AsdaSecure::EphemeralPoolStop();
        WSACleanup();
        LOGI("main", "──── AsdaEacServer остановлен ────");
        return 0;
    }

    BOOL WINAPI ConsoleCtrl(DWORD type)
    {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) { g_stop = true; return TRUE; }
        return FALSE;
    }

    // ── служба ────────────────────────────────────────────────────────────────────────────
    void ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint)
    {
        static DWORD checkpoint = 1;
        g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_svcStatus.dwCurrentState = state;
        g_svcStatus.dwControlsAccepted = state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
        g_svcStatus.dwWin32ExitCode = exitCode ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
        g_svcStatus.dwServiceSpecificExitCode = exitCode;
        g_svcStatus.dwWaitHint = waitHint;
        g_svcStatus.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
        SetServiceStatus(g_svcHandle, &g_svcStatus);
    }

    DWORD WINAPI SvcCtrl(DWORD ctrl, DWORD, LPVOID, LPVOID)
    {
        if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
        {
            ReportStatus(SERVICE_STOP_PENDING, 0, 10000);
            g_stop = true;
            return NO_ERROR;
        }
        return ctrl == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
    }

    Args g_args;   // ключи для ServiceMain

    void WINAPI SvcMain(DWORD, LPWSTR*)
    {
        g_svcHandle = RegisterServiceCtrlHandlerExW(kServiceName, SvcCtrl, nullptr);
        if (!g_svcHandle) return;
        ReportStatus(SERVICE_START_PENDING, 0, 10000);
        ReportStatus(SERVICE_RUNNING, 0, 0);
        int rc = RunServer(g_args);
        Log::Close();
        ReportStatus(SERVICE_STOPPED, (DWORD)rc, 0);
    }

    int InstallService()
    {
        wchar_t exe[MAX_PATH * 2];
        GetModuleFileNameW(nullptr, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
        std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --service";
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) { fwprintf(stderr, L"OpenSCManager: %lu (нужны права администратора)\n", GetLastError()); return 1; }
        SC_HANDLE svc = CreateServiceW(scm, kServiceName, kServiceDisplay, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                       SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, L"Tcpip\0\0", nullptr /*LocalSystem*/, nullptr);
        if (!svc) { fwprintf(stderr, L"CreateService: %lu\n", GetLastError()); CloseServiceHandle(scm); return 1; }
        SERVICE_DESCRIPTIONW d{ (LPWSTR)L"EAC для AsdaReborn: AsdaId (127.0.0.1:8444), сайдкар 15901, мост P73 127.0.0.1:15702" };
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &d);
        // Перезапуск при сбое: 5 с, 5 с, 30 с; сброс счётчика через сутки.
        SC_ACTION acts[3] = { { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 30000 } };
        SERVICE_FAILURE_ACTIONSW fa{}; fa.dwResetPeriod = 86400; fa.cActions = 3; fa.lpsaActions = acts;
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
        SERVICE_FAILURE_ACTIONS_FLAG ff{ TRUE };   // и при выходе с ненулевым кодом (не только при падении)
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &ff);
        SERVICE_DELAYED_AUTO_START_INFO da{ TRUE }; // после SQL Server и сети
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &da);
        wprintf(L"служба %ls создана: %ls\n", kServiceName, cmd.c_str());
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        return 0;
    }

    int UninstallService()
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) { fwprintf(stderr, L"OpenSCManager: %lu\n", GetLastError()); return 1; }
        SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!svc) { fwprintf(stderr, L"OpenService: %lu\n", GetLastError()); CloseServiceHandle(scm); return 1; }
        SERVICE_STATUS st{};
        if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
        {
            for (int i = 0; i < 30 && QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED; ++i) Sleep(500);
        }
        BOOL ok = DeleteService(svc);
        if (!ok) fwprintf(stderr, L"DeleteService: %lu\n", GetLastError());
        else wprintf(L"служба %ls удалена\n", kServiceName);
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        return ok ? 0 : 1;
    }

    void Usage()
    {
        wprintf(L"AsdaEacServer.exe --console | --service | --install-service | --uninstall-service | --eos-smoke  [--config <ini>] [--no-eos]\n");
    }
}

int wmain(int argc, wchar_t** argv)
{
    g_args = ParseArgs(argc, argv);
    if (g_args.bad) { SetConsoleOutputCP(CP_UTF8); fwprintf(stderr, L"неизвестный ключ: %ls\n", g_args.badArg.c_str()); Usage(); return 1; }
    if (g_args.install) return InstallService();
    if (g_args.uninstall) return UninstallService();
    if (g_args.eosSmoke)
    {
        Eac::Config cfg; std::string err;
        bool ok = cfg.Load(g_args.config, &err);
        Eac::Log::Init(ok ? cfg.logDir : Eac::ExeDir() + L"logs", true, 2);
        if (!ok) { LOGE("main", "конфиг: %s", err.c_str()); return 2; }
        Eac::EosSecrets sec;
        if (!sec.Load(cfg.eosJson, &err)) { LOGE("main", "--eos-smoke: секреты EOS не прочитаны: %s", err.c_str()); return 2; }
        int rc = Eac::EosSmoke(cfg, sec);
        Eac::Log::Close();
        return rc;
    }
#ifdef ASDA_EAC_STAND
    if (g_args.sqlProbe)
    {
        // ★ Стенд: один вызов UPEacAuth настоящим ODBC-путём. Пароль SQL — первой строкой stdin (на диск не пишется).
        Eac::Config cfg; std::string err;
        if (!cfg.Load(g_args.config, &err)) { fprintf(stderr, "конфиг: %s\n", err.c_str()); return 2; }
        Eac::Log::Init(cfg.logDir, true, 3);
        char line[512] = {};
        if (!fgets(line, sizeof(line), stdin)) { LOGE("main", "--sql-probe: пароль не передан в stdin"); return 2; }
        std::string pw(line);
        while (!pw.empty() && (pw.back() == '\n' || pw.back() == '\r' || pw.back() == ' ')) pw.pop_back();
        SecureZeroMemory(line, sizeof(line));
        auto auth = Eac::MakeOdbcAuth(cfg.sqlConnString, pw, cfg.sqlTimeoutSec);
        SecureZeroMemory(&pw[0], pw.size());
        if (!g_args.probeStatusUi.empty())
        {
            Eac::StatusResult r = auth->CheckStatus((uint32_t)_wtoi(g_args.probeStatusUi.c_str()));
            printf("SQLPROBE-STATUS verdict=%s status=%d pwTag=%s\n", r.verdict == Eac::AuthVerdict::Ok ? "ok" : r.verdict == Eac::AuthVerdict::Denied ? "denied" : "error",
                   r.status, r.pwTag.empty() ? "-" : "<16 hex>");
        }
        else
        {
            Eac::AuthResult r = auth->Check(Eac::Utf8(g_args.probeLogin), Eac::Utf8(g_args.probeMd5));
            printf("SQLPROBE verdict=%s status=%d userIndex=%u\n", r.verdict == Eac::AuthVerdict::Ok ? "ok" : r.verdict == Eac::AuthVerdict::Denied ? "denied" : "error",
                   r.status, r.userIndex);
        }
        Eac::Log::Close();
        return 0;
    }
#endif
    if (g_args.service)
    {
        SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)kServiceName, SvcMain }, { nullptr, nullptr } };
        if (!StartServiceCtrlDispatcherW(table)) { fwprintf(stderr, L"StartServiceCtrlDispatcher: %lu (запуск --service только из SCM)\n", GetLastError()); return 1; }
        return 0;
    }
    if (g_args.console)
    {
        SetConsoleCtrlHandler(ConsoleCtrl, TRUE);
        int rc = RunServer(g_args);
        Eac::Log::Close();
        return rc;
    }
    SetConsoleOutputCP(CP_UTF8);
    Usage();
    return 1;
}
