// Copyright (c) 2026 @sitxovski (Discord)
// Config.cpp — чтение EacServer.ini, eos.json и файлов секретов.
#include "EacCommon.h"
#include "Config.h"
#include "Json.h"
#include <algorithm>

namespace Eac
{
    namespace
    {
        // Строка из ini (UTF-16 → UTF-8), по умолчанию def.
        std::wstring IniW(const std::wstring& path, const wchar_t* sec, const wchar_t* key, const wchar_t* def)
        {
            wchar_t buf[4096];
            GetPrivateProfileStringW(sec, key, def, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])), path.c_str());
            std::wstring s(buf);
            // ';' в конце значения GetPrivateProfileString не режет — комментарии в ini только отдельной строкой.
            while (!s.empty() && (s.back() == L' ' || s.back() == L'\t')) s.pop_back();
            return s;
        }

        // Целое из ini с проверкой диапазона.
        bool IniInt(const std::wstring& path, const wchar_t* sec, const wchar_t* key, int& v, int lo, int hi, std::string* err)
        {
            std::wstring s = IniW(path, sec, key, L"");
            if (s.empty()) return true;   // нет ключа — значение по умолчанию
            wchar_t* end = nullptr;
            long x = wcstol(s.c_str(), &end, 10);
            if (!end || *end != 0 || x < lo || x > hi)
            {
                if (err) *err = "ini: [" + Utf8(sec) + "] " + Utf8(key) + "=" + Utf8(s) + " вне [" + std::to_string(lo) + ".." + std::to_string(hi) + "]";
                return false;
            }
            v = (int)x;
            return true;
        }

        bool IniBool(const std::wstring& path, const wchar_t* sec, const wchar_t* key, bool& v, std::string* err)
        {
            int x = v ? 1 : 0;
            if (!IniInt(path, sec, key, x, 0, 1, err)) return false;
            v = x != 0;
            return true;
        }

        std::string IniS(const std::wstring& path, const wchar_t* sec, const wchar_t* key, const std::string& def)
        {
            return Utf8(IniW(path, sec, key, Wide(def).c_str()));
        }

        // Список через ';' (элементы обрезаются по краям, пустые пропускаются).
        std::vector<std::wstring> IniList(const std::wstring& path, const wchar_t* sec, const wchar_t* key, const wchar_t* def)
        {
            std::vector<std::wstring> out;
            std::wstring s = IniW(path, sec, key, def), cur;
            auto flush = [&]() {
                size_t b = cur.find_first_not_of(L" \t"), e = cur.find_last_not_of(L" \t");
                if (b != std::wstring::npos) out.push_back(cur.substr(b, e - b + 1));
                cur.clear(); };
            for (wchar_t c : s) { if (c == L';') flush(); else cur += c; }
            flush();
            return out;
        }

        // Каталог без завершающего '\' (для сравнения путей образа).
        std::wstring NoTrailingSlash(std::wstring p)
        {
            while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
            return p;
        }
    }

    bool Config::Load(const std::wstring& path, std::string* err)
    {
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            if (err) *err = "ini не найден: " + Utf8(path);
            return false;
        }
        bool ok = true;
        // [General]
        ok &= IniInt(path, L"General", L"Mode", mode, 0, 2, err);
        ok &= IniBool(path, L"General", L"FailOpen", failOpen, err);
        ok &= IniInt(path, L"General", L"FailOpenStartupSec", failOpenStartupSec, 0, 3600, err);
        ok &= IniInt(path, L"General", L"EpicDownHoldSec", epicDownHoldSec, 1, 3600, err);
        ok &= IniInt(path, L"General", L"EpicDownWindowSec", epicDownWindowSec, 5, 3600, err);
        ok &= IniInt(path, L"General", L"EpicDownMinIps", epicDownMinIps, 1, 1000, err);
        ok &= IniInt(path, L"General", L"EpicDownRatioPct", epicDownRatioPct, 1, 100, err);
        ok &= IniInt(path, L"General", L"EosCallErrorsMax", eosCallErrorsMax, 1, 100000, err);
        ok &= IniInt(path, L"General", L"IdDegradedWindowSec", idDegradedWindowSec, 5, 3600, err);
        ok &= IniInt(path, L"General", L"IdDegradedMinRequests", idDegradedMinRequests, 1, 100000, err);
        ok &= IniInt(path, L"General", L"IdDegradedRatioPct", idDegradedRatioPct, 1, 100, err);
        logDir = ResolvePath(IniW(path, L"General", L"LogDir", L"logs"));
        ok &= IniInt(path, L"General", L"LogLevel", logLevel, 0, 3, err);
        ok &= IniInt(path, L"General", L"StatsSec", statsSec, 5, 3600, err);
        // [Secrets]
        eosJson         = ResolvePath(IniW(path, L"Secrets", L"EosJson", L"secrets\\eos.json"));
        jwtKey          = ResolvePath(IniW(path, L"Secrets", L"JwtKey", L"secrets\\jwt_rs256.key"));
        sqlPasswordFile = ResolvePath(IniW(path, L"Secrets", L"SqlPasswordFile", L"secrets\\sql_eac_auth.txt"));
        secureKeyFile   = ResolvePath(IniW(path, L"Secrets", L"SecureKeyFile", L"..\\GameServer\\secure_server.key"));
        // [Sidecar]
        sidecarBind = IniS(path, L"Sidecar", L"Bind", sidecarBind);
        ok &= IniInt(path, L"Sidecar", L"Port", sidecarPort, 1, 65535, err);
        ok &= IniInt(path, L"Sidecar", L"HandshakeTimeoutSec", handshakeTimeoutSec, 1, 120, err);
        ok &= IniInt(path, L"Sidecar", L"RegTimeoutSec", regTimeoutSec, 1, 600, err);
        ok &= IniInt(path, L"Sidecar", L"PingTimeoutSec", pingTimeoutSec, 1, 600, err);
        ok &= IniInt(path, L"Sidecar", L"VerifyTimeoutSec", verifyTimeoutSec, 1, 600, err);
        ok &= IniInt(path, L"Sidecar", L"MaxConnections", maxConnections, 1, 20000, err);
        ok &= IniInt(path, L"Sidecar", L"MaxUnregPerIp", maxUnregPerIp, 1, 10000, err);
        ok &= IniInt(path, L"Sidecar", L"MaxQueuedAcMsg", maxQueuedAcMsg, 0, 1024, err);
        ok &= IniInt(path, L"Sidecar", L"AuthTimeoutSec", authTimeoutSec, 1, 3600, err);
        ok &= IniInt(path, L"Sidecar", L"RegPerAccountMax", regPerAccountMax, 1, 1000, err);
        ok &= IniInt(path, L"Sidecar", L"RegPerAccountWindowSec", regPerAccountWindowSec, 1, 86400, err);
        ok &= IniInt(path, L"Sidecar", L"RegPerIpPerMin", regPerIpPerMin, 1, 100000, err);
        ok &= IniInt(path, L"Sidecar", L"BindKeepSec", bindKeepSec, 1, 86400, err);
        ok &= IniInt(path, L"Sidecar", L"MaxBindsPerSession", maxBindsPerSession, 1, 64, err);
        ok &= IniInt(path, L"Sidecar", L"AcceptPerPass", acceptPerPass, 1, 4096, err);
        ok &= IniInt(path, L"Sidecar", L"ConnectRatePerIp", connectRatePerIp, 1, 100000, err);
        ok &= IniInt(path, L"Sidecar", L"ConnectBurstPerIp", connectBurstPerIp, 1, 100000, err);
        ok &= IniInt(path, L"Sidecar", L"ConnectRateGlobal", connectRateGlobal, 1, 1000000, err);
        ok &= IniInt(path, L"Sidecar", L"ConnectBurstGlobal", connectBurstGlobal, 1, 1000000, err);
        ok &= IniInt(path, L"Sidecar", L"RejectSummarySec", rejectSummarySec, 1, 3600, err);
        // [Bridge]
        ok &= IniInt(path, L"Bridge", L"Port", bridgePort, 1, 65535, err);
        ok &= IniInt(path, L"Bridge", L"HelloTimeoutSec", bridgeHelloTimeoutSec, 1, 600, err);
        ok &= IniInt(path, L"Bridge", L"PingTimeoutSec", bridgePingTimeoutSec, 1, 600, err);
        ok &= IniInt(path, L"Bridge", L"OrphanSec", bridgeOrphanSec, 1, 86400, err);
        ok &= IniBool(path, L"Bridge", L"CheckPeerProcess", bridgeCheckPeer, err);
        bridgeImageNames = IniList(path, L"Bridge", L"AllowedImageNames", L"GameServer.exe");
        bridgeImageDirs.clear();
        for (const std::wstring& d : IniList(path, L"Bridge", L"AllowedImageDirs", L"..\\GameServer;..\\Indun_GameServer"))
        {
            // Нормализация: абсолютный путь от папки exe, без «..» (GetFullPathName), без завершающего '\'.
            std::wstring abs = ResolvePath(d);
            wchar_t full[MAX_PATH * 2]; DWORD n = GetFullPathNameW(abs.c_str(), (DWORD)(sizeof(full) / sizeof(full[0])), full, nullptr);
            bridgeImageDirs.push_back(NoTrailingSlash(n ? std::wstring(full, n) : abs));
        }
        if (bridgeCheckPeer && (bridgeImageNames.empty() || bridgeImageDirs.empty()))
        {
            if (err) *err = "ini: [Bridge] CheckPeerProcess=1, но AllowedImageNames/AllowedImageDirs пусты";
            ok = false;
        }
        // [Policy]
        ok &= IniInt(path, L"Policy", L"BindTimeoutSec", bindTimeoutSec, 1, 3600, err);
        ok &= IniInt(path, L"Policy", L"GraceSec", graceSec, 0, 3600, err);
        ok &= IniInt(path, L"Policy", L"KickRepeatSec", kickRepeatSec, 1, 3600, err);
        ok &= IniBool(path, L"Policy", L"RequireSameIp", requireSameIp, err);
        ok &= IniInt(path, L"Policy", L"RejectMemorySec", rejectMemorySec, 1, 86400, err);
        ok &= IniInt(path, L"Policy", L"VerifyWaitSec", verifyWaitSec, 0, 600, err);
        {
            // OperatorUserIndex=1,2,15 — через запятую/пробел
            std::string s = IniS(path, L"Policy", L"OperatorUserIndex", "");
            operators.clear();
            std::string cur;
            auto flush = [&]() -> bool {
                if (cur.empty()) return true;
                uint32_t v; if (!ParseUserIndex(cur, v)) { if (err) *err = "ini: OperatorUserIndex негоден: " + cur; return false; }
                operators.push_back(v); cur.clear(); return true; };
            for (char c : s)
            {
                if (c == ',' || c == ' ' || c == ';' || c == '\t') { ok &= flush(); }
                else cur += c;
            }
            ok &= flush();
        }
        // ★ Д2 / Д3 (22.11.2026)
        ok &= IniInt(path, L"Policy", L"RegFreeAfterAuthSec", regFreeAfterAuthSec, 0, 86400, err);
        // ★ Д3 ред. 2 (ревизия 64): поблажка одной учётке при сбое EOS Connect у её клиента
        authHistoryFile = ResolvePath(IniW(path, L"Policy", L"AuthHistoryFile", L"state\\auth_history.dat"));
        ok &= IniInt(path, L"Policy", L"AuthHistoryDays", authHistoryDays, 1, 365, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceTokenSec", connectGraceTokenSec, 1, 3600, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceSecPerDay", connectGraceSecPerDay, 0, 86400, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceEpisodeSec", connectGraceEpisodeSec, 1, 86400, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceEpisodeGapSec", connectGraceEpisodeGapSec, 1, 86400, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceDaysPer30", connectGraceDaysPer30, 0, 30, err);
        ok &= IniInt(path, L"Policy", L"ConnectGraceAfterViolationDays", connectGraceAfterViolationDays, 0, 365, err);
        // ★ Р68-3: окно K (окна по 24 ч) и запрет после нарушения считаются в пределах истории — история должна быть не короче их,
        //   иначе запись о нарушении стёрлась бы раньше конца запрета. Несогласованность — поблажка выключена (не вся служба).
        if (authHistoryDays < 30 || authHistoryDays < connectGraceAfterViolationDays)
            graceConfigError = "AuthHistoryDays=" + std::to_string(authHistoryDays) + " меньше 30 или ConnectGraceAfterViolationDays=" +
                               std::to_string(connectGraceAfterViolationDays);
        // [AsdaId]
        ok &= IniInt(path, L"AsdaId", L"Port", idPort, 1, 65535, err);
        issuer   = IniS(path, L"AsdaId", L"Issuer", issuer);
        audience = IniS(path, L"AsdaId", L"Audience", audience);
        ok &= IniInt(path, L"AsdaId", L"AccessTtlSec", accessTtlSec, 60, 86400, err);
        ok &= IniInt(path, L"AsdaId", L"RefreshTtlSec", refreshTtlSec, 1, 30 * 86400, err);
        ok &= IniInt(path, L"AsdaId", L"RefreshAbsoluteSec", refreshAbsoluteSec, 1, 365 * 86400, err);
        refreshFile = ResolvePath(IniW(path, L"AsdaId", L"RefreshFile", L"secrets\\refresh.dat"));
        ok &= IniInt(path, L"AsdaId", L"StatusRecheckSec", statusRecheckSec, 1, 86400, err);
        ok &= IniInt(path, L"AsdaId", L"TokenPerIpPerMin", tokenPerIpPerMin, 1, 100000, err);
        ok &= IniInt(path, L"AsdaId", L"LoginFailMax", loginFailMax, 1, 1000, err);
        ok &= IniInt(path, L"AsdaId", L"LoginFailPauseSec", loginFailPauseSec, 1, 86400, err);
        ok &= IniInt(path, L"AsdaId", L"LoginGlobalFailMax", loginGlobalFailMax, 1, 100000, err);
        {
            // LoginPauseStagesSec=60,300,3600 — ступени общей паузы логина (у пары первая ступень = LoginFailPauseSec).
            std::string st = IniS(path, L"AsdaId", L"LoginPauseStagesSec", "60,300,3600"), cur;
            loginPauseStagesSec.clear();
            auto flush = [&]() -> bool {
                if (cur.empty()) return true;
                char* e = nullptr; long v = strtol(cur.c_str(), &e, 10);
                if (!e || *e || v < 1 || v > 86400 * 7) { if (err) *err = "ini: LoginPauseStagesSec негоден: " + cur; return false; }
                loginPauseStagesSec.push_back((int)v); cur.clear(); return true; };
            for (char c : st) { if (c == ',' || c == ' ' || c == ';') ok &= flush(); else cur += c; }
            ok &= flush();
            if (loginPauseStagesSec.empty()) loginPauseStagesSec = { 60, 300, 3600 };
        }
        ok &= IniInt(path, L"AsdaId", L"LoginKnownIpDays", loginKnownIpDays, 0, 365, err);
        ok &= IniBool(path, L"AsdaId", L"FailWrite", failWrite, err);
        ok &= IniInt(path, L"AsdaId", L"FailWriteDelayMs", failWriteDelayMs, 0, 60000, err);
        ok &= IniInt(path, L"AsdaId", L"RequestDeadlineSec", requestDeadlineSec, 1, 120, err);
        ok &= IniInt(path, L"AsdaId", L"StatusLoginPort", statusLoginPort, 1, 65535, err);   // ★ 17.10.2026: /status
        ok &= IniInt(path, L"AsdaId", L"StatusGamePort", statusGamePort, 1, 65535, err);
        ok &= IniInt(path, L"AsdaId", L"StatusCacheMs", statusCacheMs, 250, 60000, err);
        ok &= IniInt(path, L"AsdaId", L"MaxPendingConns", maxPendingConns, 8, 100000, err);
        wwwDir = ResolvePath(IniW(path, L"AsdaId", L"WwwDir", L"www"));
        ok &= IniBool(path, L"AsdaId", L"TrustForwardedFor", trustForwardedFor, err);
        ok &= IniInt(path, L"AsdaId", L"Workers", idWorkers, 1, 64, err);
        ok &= IniInt(path, L"AsdaId", L"IoTimeoutSec", idIoTimeoutSec, 1, 120, err);
        ok &= IniInt(path, L"AsdaId", L"MaxRefreshPerUser", maxRefreshPerUser, 1, 1000, err);
        // ★ А6.8 (22.11.2026) [AdminStatus] — точка статуса для панели (AdminStatus.h).
        // ★ ревизия 61 М-2: ошибка в этой секции НЕ ломает загрузку конфига — точка выключается (statusConfigError → журнал при старте),
        //   EAC стартует. Ключи читаются в черновик и принимаются только целиком.
        {
            Config t = *this; std::string serr; bool sok = true;
            sok &= IniBool(path, L"AdminStatus", L"Enabled", t.statusEnabled, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"Port", t.statusPort, 1, 65535, &serr);
            t.statusSecretFile = ResolvePath(IniW(path, L"AdminStatus", L"SecretFile", L"secrets\\admin_status.key"));
            if (sok) sok &= IniInt(path, L"AdminStatus", L"ReqPerSec", t.statusReqPerSec, 1, 1000, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"ReqBurst", t.statusReqBurst, 1, 10000, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"FailPerMin", t.statusFailPerMin, 1, 1000, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"DeadlineMs", t.statusDeadlineMs, 100, 30000, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"SnapshotMaxAgeMs", t.statusSnapshotMaxAgeMs, 0, 60000, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"EventsPerAccount", t.statusEventsPerAccount, 1, 200, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"EventKeepSec", t.statusEventKeepSec, 60, 30 * 86400, &serr);
            if (sok) sok &= IniInt(path, L"AdminStatus", L"MaxAccounts", t.statusMaxAccounts, 10, 1000000, &serr);
            if (sok && t.statusEnabled && (t.statusPort == idPort || t.statusPort == bridgePort || t.statusPort == sidecarPort))
            {
                serr = "ini: [AdminStatus] Port совпадает с портом AsdaId / моста / сайдкара";
                sok = false;
            }
            if (sok)
            {
                statusEnabled = t.statusEnabled; statusPort = t.statusPort; statusSecretFile = t.statusSecretFile; statusReqPerSec = t.statusReqPerSec;
                statusReqBurst = t.statusReqBurst; statusFailPerMin = t.statusFailPerMin; statusDeadlineMs = t.statusDeadlineMs;
                statusSnapshotMaxAgeMs = t.statusSnapshotMaxAgeMs; statusEventsPerAccount = t.statusEventsPerAccount;
                statusEventKeepSec = t.statusEventKeepSec; statusMaxAccounts = t.statusMaxAccounts;
            }
            else { statusEnabled = false; statusConfigError = serr; }
        }
        // [Sql]
        sqlConnString = IniS(path, L"Sql", L"ConnectionString",
            "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,1433;Database=Joy1;UID=eac_auth;Encrypt=no");
        ok &= IniInt(path, L"Sql", L"TimeoutSec", sqlTimeoutSec, 1, 120, err);
        // [Eos]
        ok &= IniInt(path, L"Eos", L"RegisterTimeoutSec", eosRegisterTimeoutSec, 10, 120, err);   // MIN/MAX eos_anticheatserver_types.h:75-78
        ok &= IniInt(path, L"Eos", L"TickMs", eosTickMs, 5, 1000, err);
        eosServerName = IniS(path, L"Eos", L"ServerName", eosServerName);
        eosCacheDir = ResolvePath(IniW(path, L"Eos", L"CacheDir", L"cache"));
        ok &= IniInt(path, L"Eos", L"LogLevel", eosLogLevel, 0, 600, err);
        if (ok && (Lower(sqlConnString).find("pwd=") != std::string::npos || Lower(sqlConnString).find("password=") != std::string::npos))
        {
            if (err) *err = "ini: пароль в ConnectionString запрещён — только SqlPasswordFile";
            ok = false;
        }
        return ok;
    }

    bool Config::IsOperator(uint32_t userIndex) const
    {
        return std::find(operators.begin(), operators.end(), userIndex) != operators.end();
    }

    // Прочитать файл целиком (≤ 64 КиБ).
    static bool ReadSmallFile(const std::wstring& path, std::string& out, std::string* err)
    {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { if (err) *err = "не открыт " + Utf8(path) + " (" + std::to_string(GetLastError()) + ")"; return false; }
        LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
        if (sz.QuadPart > 65536) { CloseHandle(h); if (err) *err = "слишком большой " + Utf8(path); return false; }
        out.assign((size_t)sz.QuadPart, '\0');
        DWORD rd = 0; BOOL ok = out.empty() ? TRUE : ReadFile(h, &out[0], (DWORD)out.size(), &rd, nullptr);
        CloseHandle(h);
        if (!ok || rd != out.size()) { if (err) *err = "чтение " + Utf8(path); return false; }
        return true;
    }

    bool EosSecrets::Load(const std::wstring& path, std::string* err)
    {
        std::string text;
        if (!ReadSmallFile(path, text, err)) return false;
        Json::Value v; std::string jerr;
        bool parsed = Json::Parse(text, v, &jerr);
        SecureZeroMemory(&text[0], text.size());
        if (!parsed || v.type != Json::Type::Object) { if (err) *err = "eos.json: не JSON-объект (" + jerr + ")"; return false; }
        const Json::Value* sc = v.Get("serverClient");
        if (!v.GetString("productId", productId) || !v.GetString("sandboxId", sandboxId) ||
            !v.GetString("deploymentId", deploymentId) || !sc ||
            !sc->GetString("clientId", clientId) || !sc->GetString("clientSecret", clientSecret) ||
            productId.empty() || sandboxId.empty() || deploymentId.empty() || clientId.empty() || clientSecret.empty())
        {
            if (err) *err = "eos.json: нет productId/sandboxId/deploymentId/serverClient{clientId,clientSecret}";
            return false;
        }
        return true;
    }

    bool ReadSecretLine(const std::wstring& path, std::string& out, std::string* err)
    {
        std::string text;
        if (!ReadSmallFile(path, text, err)) return false;
        size_t b = 0;
        if (text.size() >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) b = 3;
        size_t e = text.find_first_of("\r\n", b);
        if (e == std::string::npos) e = text.size();
        while (b < e && (text[b] == ' ' || text[b] == '\t')) ++b;
        while (e > b && (text[e - 1] == ' ' || text[e - 1] == '\t')) --e;
        out.assign(text, b, e - b);
        SecureZeroMemory(&text[0], text.size());
        if (out.empty()) { if (err) *err = "пустой файл секрета " + Utf8(path); return false; }
        return true;
    }
}
