// Copyright (c) 2026 @sitxovski (Discord)
// StandCommon.h — общие помощники стендов AsdaEacServer (EAC Э1): проверки, запуск сервера стенда, ini, TCP, клиент AsdaSecure.
// Стенды запускают out\stand\AsdaEacServer_stand.exe как отдельный процесс (путь игрока: настоящие сокеты, настоящий ini,
// настоящий журнал) и проверяют ответы по сети и по журналу сервера. Секреты EOS не нужны (--no-eos / --fake-eos).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <share.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "AsdaSecure.h"
#include "Crypto.h"
#include "Json.h"

namespace Stand
{
    // Счётчики проверок.
    inline int& Passed() { static int v = 0; return v; }
    inline int& Failed() { static int v = 0; return v; }

    // Проверка с выводом.
    inline bool Check(bool ok, const char* what)
    {
        printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
        (ok ? Passed() : Failed())++;
        return ok;
    }
    inline bool Check(bool ok, const std::string& what) { return Check(ok, what.c_str()); }

    // Итог стенда (код возврата процесса).
    inline int Summary(const char* name)
    {
        printf("\n=== %s: пройдено %d, провалено %d ===\n", name, Passed(), Failed());
        return Failed() == 0 ? 0 : 1;
    }

    inline int64_t NowMs() { return (int64_t)GetTickCount64(); }

    // Папка exe стенда (с '\').
    inline std::wstring ExeDir()
    {
        wchar_t b[MAX_PATH * 2]; DWORD n = GetModuleFileNameW(nullptr, b, MAX_PATH * 2);
        std::wstring p(b, n); size_t k = p.find_last_of(L"\\/");
        return p.substr(0, k + 1);
    }

    inline std::string U8(const std::wstring& w)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s((size_t)n, '\0'); WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr); return s;
    }
    inline std::wstring W(const std::string& s)
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring w((size_t)n, L'\0'); MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n); return w;
    }

    // Удалить папку рекурсивно (только внутри out\stand\run).
    inline void RmTree(const std::wstring& dir)
    {
        WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                std::wstring n = fd.cFileName; if (n == L"." || n == L"..") continue;
                std::wstring p = dir + L"\\" + n;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RmTree(p); else DeleteFileW(p.c_str());
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        RemoveDirectoryW(dir.c_str());
    }

    // Рабочая папка сценария: out\stand\run\<name>\ (очищается).
    inline std::wstring RunDir(const std::string& name, bool clean = true)
    {
        std::wstring base = ExeDir() + L"run";
        CreateDirectoryW(base.c_str(), nullptr);
        std::wstring d = base + L"\\" + W(name);
        if (clean) RmTree(d);
        CreateDirectoryW(d.c_str(), nullptr);
        CreateDirectoryW((d + L"\\secrets").c_str(), nullptr);
        return d + L"\\";
    }

    // Ключ AsdaSecure стенда (создаётся в папке сценария) и его открытая часть для клиента.
    inline bool MakeSecureKey(const std::wstring& dir, AsdaSecure::PublicKey& pub)
    {
        AsdaSecure::Init();
        AsdaSecure::PrivateKey k;
        if (!AsdaSecure::GenerateLongTermKey(k)) return false;
        if (!AsdaSecure::SavePrivateKeyFile((dir + L"secure_server.key").c_str(), k)) return false;
        memcpy(pub.xy, k.xy, sizeof(pub.xy));
        return true;
    }

    // Имя exe текущего процесса (без пути) и его папка без завершающего '' — для [Bridge] AllowedImageNames/AllowedImageDirs.
    inline std::string SelfExeName() { std::wstring d = ExeDir(); wchar_t b[MAX_PATH * 2]; DWORD n = GetModuleFileNameW(nullptr, b, MAX_PATH * 2); return U8(std::wstring(b + d.size(), n - d.size())); }
    inline std::string SelfExeDirNoSlash() { std::wstring d = ExeDir(); d.pop_back(); return U8(d); }

    // Значение переопределения «ключ не писать» — сервер возьмёт своё умолчание (§8.6: проверка умолчаний).
    const char* const kIniDefault = "<умолчание>";

    // Записать ini сценария: базовые значения + переопределения "Секция.Ключ" → значение.
    // Ред. 3: стенд по умолчанию снимает пределы частоты (все клиенты стенда — с 127.0.0.1), а проверку процесса моста
    // оставляет ВКЛЮЧЁННОЙ — допускается exe самого стенда из его папки (он же играет роль P73).
    inline std::wstring WriteIni(const std::wstring& dir, int idPort, int sidePort, int brPort, const std::map<std::string, std::string>& ov)
    {
        std::map<std::string, std::map<std::string, std::string>> s;
        std::string d = U8(dir);
        s["General"] = { {"Mode", "2"}, {"FailOpen", "0"}, {"FailOpenStartupSec", "0"}, {"EpicDownHoldSec", "60"}, {"LogDir", d + "logs"}, {"LogLevel", "3"}, {"StatsSec", "5"} };
        s["Secrets"] = { {"EosJson", d + "secrets\\eos.json"}, {"JwtKey", d + "secrets\\jwt_rs256.key"}, {"SqlPasswordFile", d + "secrets\\sql_eac_auth.txt"}, {"SecureKeyFile", d + "secure_server.key"} };
        s["Sidecar"] = { {"Bind", "127.0.0.1"}, {"Port", std::to_string(sidePort)}, {"HandshakeTimeoutSec", "10"}, {"RegTimeoutSec", "30"}, {"PingTimeoutSec", "30"},
                         {"VerifyTimeoutSec", "45"}, {"MaxConnections", "2000"}, {"MaxUnregPerIp", "1000"}, {"MaxQueuedAcMsg", "64"},
                         {"ConnectRatePerIp", "100000"}, {"ConnectBurstPerIp", "100000"}, {"ConnectRateGlobal", "1000000"}, {"ConnectBurstGlobal", "1000000"},
                         {"RegPerIpPerMin", "100000"}, {"RegPerAccountMax", "1000"} };
        s["Bridge"] = { {"Port", std::to_string(brPort)}, {"HelloTimeoutSec", "10"}, {"PingTimeoutSec", "20"}, {"OrphanSec", "120"},
                        {"CheckPeerProcess", "1"}, {"AllowedImageNames", SelfExeName()}, {"AllowedImageDirs", SelfExeDirNoSlash()} };
        s["Policy"] = { {"BindTimeoutSec", "60"}, {"GraceSec", "30"}, {"KickRepeatSec", "30"}, {"OperatorUserIndex", ""} };
        s["AsdaId"] = { {"Port", std::to_string(idPort)}, {"TokenPerIpPerMin", "10"}, {"LoginFailMax", "5"}, {"LoginFailPauseSec", "60"}, {"TrustForwardedFor", "1"}, {"Workers", "4"},
                        {"RefreshFile", d + "secrets\\refresh.dat"}, {"WwwDir", d + "www"} };
        s["Eos"] = { {"CacheDir", d + "cache"} };
        // ★ А6.8 (22.11.2026): ASDA_STAND_STATUS=1 — все стенды с включённой точкой статуса и историей событий (порт 25891, секрет стенда):
        //   политика и протокол должны давать те же итоги, что без неё.
        char stEnv[8] = {};
        if (GetEnvironmentVariableA("ASDA_STAND_STATUS", stEnv, sizeof(stEnv)) && stEnv[0] == '1')
        {
            std::wstring kf = dir + L"secrets\\admin_status.key";
            CreateDirectoryW((dir + L"secrets").c_str(), nullptr);
            FILE* kfp = _wfopen(kf.c_str(), L"wb");
            if (kfp) { fputs("standstatus0123456789abcdef0123456789abcdef\r\n", kfp); fclose(kfp); }
            s["AdminStatus"] = { {"Enabled", "1"}, {"Port", "25891"}, {"SecretFile", U8(kf)} };
        }
        for (auto& kv : ov)
        {
            size_t p = kv.first.find('.');
            if (kv.second == kIniDefault) { s[kv.first.substr(0, p)].erase(kv.first.substr(p + 1)); continue; }   // ключа нет — умолчание сервера
            s[kv.first.substr(0, p)][kv.first.substr(p + 1)] = kv.second;
        }
        std::string text = "; ini стенда (создан автоматически)\r\n";
        for (auto& sec : s)
        {
            text += "[" + sec.first + "]\r\n";
            for (auto& kv : sec.second) text += kv.first + "=" + kv.second + "\r\n";
        }
        std::wstring path = dir + L"EacServer.ini";
        FILE* f = _wfopen(path.c_str(), L"wb"); if (f) { fwrite(text.data(), 1, text.size(), f); fclose(f); }
        return path;
    }

    // ── TCP ─────────────────────────────────────────────────────────────────────────────────
    inline void WsaInit() { static bool done = false; if (!done) { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); done = true; } }

    // srcIp — адрес источника из 127.0.0.0/8 (разные «IP клиентов» на одной машине; nullptr — по умолчанию).
    inline SOCKET Connect(int port, int timeoutMs = 3000, const char* srcIp = nullptr)
    {
        WsaInit();
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (srcIp)
        {
            sockaddr_in la{}; la.sin_family = AF_INET; inet_pton(AF_INET, srcIp, &la.sin_addr);
            if (bind(s, (sockaddr*)&la, sizeof(la)) != 0) { closesocket(s); return INVALID_SOCKET; }
        }
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port); inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        DWORD t = (DWORD)timeoutMs;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
        if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) { closesocket(s); return INVALID_SOCKET; }
        BOOL nd = TRUE; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
        return s;
    }

    inline bool SendAll(SOCKET s, const void* d, size_t n)
    {
        const char* p = (const char*)d;
        while (n) { int k = send(s, p, (int)n, 0); if (k <= 0) return false; p += k; n -= (size_t)k; }
        return true;
    }

    // Ждать, что порт слушается.
    inline bool WaitPort(int port, int timeoutMs)
    {
        int64_t end = NowMs() + timeoutMs;
        while (NowMs() < end)
        {
            SOCKET s = Connect(port, 500);
            if (s != INVALID_SOCKET) { closesocket(s); return true; }
            Sleep(100);
        }
        return false;
    }

    // Прочитать с таймаутом. >0 — байт, 0 — соединение закрыто сервером, -1 — таймаут, -2 — ошибка (RST и пр.).
    inline int RecvSome(SOCKET s, uint8_t* buf, int cap, int timeoutMs)
    {
        fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
        timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
        int r = select(0, &rs, nullptr, nullptr, &tv);
        if (r == 0) return -1;
        if (r < 0) return -2;
        int n = recv(s, (char*)buf, cap, 0);
        if (n == 0) return 0;
        if (n < 0) return -2;
        return n;
    }

    // Кадр «u16 len · u8 type · payload».
    inline std::vector<uint8_t> Frame(uint8_t type, const std::vector<uint8_t>& p)
    {
        std::vector<uint8_t> f; uint16_t len = (uint16_t)(1 + p.size());
        f.push_back((uint8_t)len); f.push_back((uint8_t)(len >> 8)); f.push_back(type); f.insert(f.end(), p.begin(), p.end());
        return f;
    }
    inline void PutU16(std::vector<uint8_t>& v, uint16_t x) { v.push_back((uint8_t)x); v.push_back((uint8_t)(x >> 8)); }
    inline void PutU32(std::vector<uint8_t>& v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> (8 * i))); }
    inline uint16_t GetU16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
    inline uint32_t GetU32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

    // Разборщик кадров из потока.
    struct FrameReader
    {
        std::vector<uint8_t> buf;
        // Вынуть кадр: true — есть (type, payload).
        bool Next(uint8_t& type, std::vector<uint8_t>& payload)
        {
            if (buf.size() < 2) return false;
            uint16_t len = GetU16(buf.data());
            if (len == 0 || buf.size() < 2u + len) return false;
            type = buf[2]; payload.assign(buf.begin() + 3, buf.begin() + 2 + len);
            buf.erase(buf.begin(), buf.begin() + 2 + len);
            return true;
        }
    };

    // Открытый TCP-клиент моста (без шифрования).
    struct PlainClient
    {
        SOCKET s = INVALID_SOCKET;
        FrameReader rd;
        bool closed = false;
        bool Open(int port) { s = Connect(port); closed = s == INVALID_SOCKET; return !closed; }
        void Close() { if (s != INVALID_SOCKET) { closesocket(s); s = INVALID_SOCKET; } }
        ~PlainClient() { Close(); }
        bool Send(uint8_t type, const std::vector<uint8_t>& p) { auto f = Frame(type, p); return SendAll(s, f.data(), f.size()); }
        bool SendRaw(const std::vector<uint8_t>& raw) { return SendAll(s, raw.data(), raw.size()); }
        // 1 — кадр, 0 — таймаут, -1 — закрыто.
        int Recv(uint8_t& type, std::vector<uint8_t>& p, int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (true)
            {
                if (rd.Next(type, p)) return 1;
                if (closed) return -1;
                int left = (int)(end - NowMs()); if (left <= 0) return 0;
                uint8_t b[8192]; int n = RecvSome(s, b, sizeof(b), left);
                if (n == -1) return 0;
                if (n <= 0) { closed = true; continue; }
                rd.buf.insert(rd.buf.end(), b, b + n);
            }
        }
        // Ждать кадр нужного типа (прочие пропускаются, PONG — молча). 1/0/-1.
        int RecvType(uint8_t want, std::vector<uint8_t>& p, int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (true)
            {
                int left = (int)(end - NowMs()); if (left <= 0) return 0;
                uint8_t t; int r = Recv(t, p, left);
                if (r != 1) return r;
                if (t == want) return 1;
            }
        }
    };

    // Клиент 15901 поверх AsdaSecure (SubServer::Eac).
    struct SecureClient
    {
        SOCKET s = INVALID_SOCKET;
        AsdaSecure::ClientChannel ch;
        FrameReader rd;
        bool closed = false;
        AsdaSecure::Err lastErr = AsdaSecure::Err::Ok;

        bool Open(int port, const AsdaSecure::PublicKey& pub, AsdaSecure::SubServer sub = AsdaSecure::SubServer::Eac, const char* srcIp = nullptr)
        {
            s = Connect(port, 3000, srcIp); if (s == INVALID_SOCKET) { closed = true; return false; }
            ch.Reset(); std::vector<uint8_t> hello;
            if (!ch.Start(sub, pub, hello)) return false;
            return SendAll(s, hello.data(), hello.size());
        }
        void Close() { if (s != INVALID_SOCKET) { closesocket(s); s = INVALID_SOCKET; } }
        ~SecureClient() { Close(); }

        // Принять порцию байт: false — закрыто/ошибка канала.
        bool Pump(int timeoutMs)
        {
            uint8_t b[16384]; int n = RecvSome(s, b, sizeof(b), timeoutMs);
            if (n == -1) return true;
            if (n <= 0) { closed = true; return false; }
            std::vector<uint8_t> plain;
            lastErr = ch.OnRecv(b, (size_t)n, plain);
            if (lastErr != AsdaSecure::Err::Ok) { closed = true; return false; }
            rd.buf.insert(rd.buf.end(), plain.begin(), plain.end());
            return true;
        }
        bool Handshake(int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (!ch.IsReady())
            {
                int left = (int)(end - NowMs()); if (left <= 0) return false;
                if (!Pump(left)) return false;
            }
            return true;
        }
        bool SendPlain(const std::vector<uint8_t>& plain)
        {
            std::vector<uint8_t> out;
            if (ch.OnSend(plain.data(), plain.size(), out) != AsdaSecure::Err::Ok) return false;
            return SendAll(s, out.data(), out.size());
        }
        bool Send(uint8_t type, const std::vector<uint8_t>& p) { return SendPlain(Frame(type, p)); }
        int Recv(uint8_t& type, std::vector<uint8_t>& p, int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (true)
            {
                if (rd.Next(type, p)) return 1;
                if (closed) return -1;
                int left = (int)(end - NowMs()); if (left <= 0) return 0;
                Pump(left);
            }
        }
        int RecvType(uint8_t want, std::vector<uint8_t>& p, int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (true)
            {
                int left = (int)(end - NowMs()); if (left <= 0) return 0;
                uint8_t t; int r = Recv(t, p, left);
                if (r != 1) return r;
                if (t == want) return 1;
            }
        }
        // Ждать закрытия сервером (кадры пропускаются). true — закрыто в срок.
        bool WaitClosed(int timeoutMs)
        {
            int64_t end = NowMs() + timeoutMs;
            while (!closed)
            {
                int left = (int)(end - NowMs()); if (left <= 0) return false;
                uint8_t t; std::vector<uint8_t> p; Recv(t, p, left);
            }
            return true;
        }
    };

    // REG: ver · platform · u16 n + PUID · u16 n + token.
    inline std::vector<uint8_t> RegPayload(uint8_t ver, uint8_t platform, const std::string& puid, const std::string& token)
    {
        std::vector<uint8_t> p; p.push_back(ver); p.push_back(platform);
        PutU16(p, (uint16_t)puid.size()); p.insert(p.end(), puid.begin(), puid.end());
        PutU16(p, (uint16_t)token.size()); p.insert(p.end(), token.begin(), token.end());
        return p;
    }

    // Токен для фальшивого EOS стенда: {"alg":"none"}.{"sub","puid",…extra}.ZmFrZQ. extra — дополнительные строковые поля
    // (ред. 3, см. EosLayer.h MakeFakeEos): "auth" remote|local|none, "authDelayMs", "eosres", "noanswer", "regerr".
    inline std::string FakeToken(const std::string& sub, const std::string& puid, const std::map<std::string, std::string>& extra = {})
    {
        std::string body = std::string("{\"sub\":\"") + sub + "\",\"puid\":\"" + puid + "\"";
        for (auto& kv : extra) body += ",\"" + kv.first + "\":\"" + kv.second + "\"";
        body += "}";
        return Eac::Crypto::B64Url(std::string("{\"alg\":\"none\",\"typ\":\"JWT\"}")) + "." + Eac::Crypto::B64Url(body) + ".ZmFrZQ";
    }

    // ── ред. 3: мост v2 и BIND ──────────────────────────────────────────────────────────────
    typedef std::vector<uint8_t> Bind32;   // привязка игрового канала, 32 байта
    // Случайная ненулевая привязка (у стенда нет P61 — значения произвольные, сайдкар только сравнивает).
    inline Bind32 RandBind() { Bind32 b(32); Eac::Crypto::Random(b.data(), b.size()); b[0] |= 1; return b; }
    inline Bind32 ZeroBind() { return Bind32(32, 0); }
    // HELLO v2: ver · kind · pid · gamePort. pid 0 → pid этого процесса (проверка владельца соединения).
    inline std::vector<uint8_t> HelloV(uint8_t ver, uint8_t kind, uint32_t pid, uint16_t port)
    {
        std::vector<uint8_t> p; p.push_back(ver); p.push_back(kind); PutU32(p, pid ? pid : GetCurrentProcessId()); PutU16(p, port); return p;
    }
    // LOGIN v2: userNum · userIndex · ipv4 (сетевой порядок; ip задан как 0xAABBCCDD = A.B.C.D) · seq · bind.
    inline std::vector<uint8_t> LoginV2(uint16_t un, uint32_t ui, uint32_t ip, uint32_t seq, const Bind32& b)
    {
        std::vector<uint8_t> p; PutU16(p, un); PutU32(p, ui);
        p.push_back((uint8_t)(ip >> 24)); p.push_back((uint8_t)(ip >> 16)); p.push_back((uint8_t)(ip >> 8)); p.push_back((uint8_t)ip);
        PutU32(p, seq); p.insert(p.end(), b.begin(), b.end()); return p;
    }
    // REBIND v2: userNum · oldUserIndex · sessionUserIndex · seq · bind.
    inline std::vector<uint8_t> RebindV2(uint16_t un, uint32_t oldUi, uint32_t sessUi, uint32_t seq, const Bind32& b)
    {
        std::vector<uint8_t> p; PutU16(p, un); PutU32(p, oldUi); PutU32(p, sessUi); PutU32(p, seq); p.insert(p.end(), b.begin(), b.end()); return p;
    }
    // BIND (0x05): serverKind · bind.
    inline std::vector<uint8_t> BindPayload(uint8_t kind, const Bind32& b) { std::vector<uint8_t> p; p.push_back(kind); p.insert(p.end(), b.begin(), b.end()); return p; }

    // PUID стенда из числа.
    inline std::string Puid(uint32_t n) { char b[40]; snprintf(b, sizeof(b), "0002%028x", n); return b; }

    // Клиент EAC: рукопожатие + REG учётки ui (PUID из puidN). Возврат — статус REG_RESULT или -1.
    inline int EacRegister(SecureClient& c, int port, const AsdaSecure::PublicKey& pub, uint32_t ui, uint32_t puidN,
                           const std::map<std::string, std::string>& extra = {}, const char* srcIp = nullptr, uint8_t platform = 1)
    {
        if (!c.Open(port, pub, AsdaSecure::SubServer::Eac, srcIp) || !c.Handshake(5000)) return -1;
        std::string puid = Puid(puidN);
        if (!c.Send(0x01, RegPayload(1, platform, puid, FakeToken(std::to_string(ui), puid, extra)))) return -1;
        std::vector<uint8_t> p;
        if (c.RecvType(0x81, p, 5000) != 1 || p.size() != 1) return -1;
        return p[0];
    }
    // BIND (ред. 3): возврат — статус BIND_RESULT или -1.
    inline int EacBind(SecureClient& c, uint8_t kind, const Bind32& b)
    {
        if (!c.Send(0x05, BindPayload(kind, b))) return -1;
        std::vector<uint8_t> p;
        if (c.RecvType(0x85, p, 3000) != 1 || p.size() != 1) return -1;
        return p[0];
    }

    // Простой HTTP-клиент AsdaId (для стендов деградации). Возврат — код ответа (0 — нет ответа).
    inline int HttpPost(int port, const std::string& path, const std::string& body, const std::string& xff)
    {
        SOCKET s = Connect(port, 5000);
        if (s == INVALID_SOCKET) return 0;
        std::string req = "POST " + path + " HTTP/1.1\r\nHost: @@ASTORY_AUTH_HOST@@\r\nContent-Type: application/json\r\nX-Forwarded-For: " + xff +
                          "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        SendAll(s, req.data(), req.size());
        std::string raw; uint8_t b[4096];
        while (true) { int n = RecvSome(s, b, sizeof(b), 5000); if (n <= 0) break; raw.append((char*)b, (size_t)n); }
        closesocket(s);
        return (raw.size() > 12 && raw.compare(0, 9, "HTTP/1.1 ") == 0) ? atoi(raw.c_str() + 9) : 0;
    }

    // ── процесс сервера стенда ─────────────────────────────────────────────────────────────
    struct Server
    {
        PROCESS_INFORMATION pi{};
        std::wstring dir;
        bool running = false;
        size_t logBase = 0;                  // длина журнала папки до запуска этого сервера (LogHasNew — только его строки)

        // exeName — имя exe сервера стенда в out\stand (★ 22.11: stand_cases --exe-dir — сборка «до»)
        bool Start(const std::wstring& runDir, const std::wstring& ini, const std::wstring& extra, int waitPort, const wchar_t* exeName = L"AsdaEacServer_stand.exe")
        {
            dir = runDir;
            logBase = Log().size();
            std::wstring exe = ExeDir() + exeName;
            std::wstring cmd = L"\"" + exe + L"\" --console --config \"" + ini + L"\" " + extra;
            SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
            HANDLE out = CreateFileW((runDir + L"stdout.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, 0, nullptr);
            STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = out; si.hStdError = out; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
            BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NEW_PROCESS_GROUP, nullptr, runDir.c_str(), &si, &pi);
            CloseHandle(out);
            if (!ok) { printf("  CreateProcess: %lu\n", GetLastError()); return false; }
            running = true;
            if (waitPort && !WaitPort(waitPort, 15000)) { printf("  порт %d не открылся\n", waitPort); return false; }
            return true;
        }

        // Останов: Ctrl+Break группе (штатный путь g_stop), иначе TerminateProcess. Возврат: true — вышел штатно.
        bool Stop()
        {
            if (!running) return true;
            bool graceful = false;
            if (GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId))
                graceful = WaitForSingleObject(pi.hProcess, 8000) == WAIT_OBJECT_0;
            if (!graceful) { TerminateProcess(pi.hProcess, 99); WaitForSingleObject(pi.hProcess, 5000); }
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            running = false;
            return graceful;
        }
        ~Server() { Stop(); }

        // Весь журнал сервера (все файлы logs\eac_*.log).
        std::string Log() const
        {
            std::string all;
            WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW((dir + L"logs\\eac_*.log").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) return all;
            do
            {
                FILE* f = _wfsopen((dir + L"logs\\" + fd.cFileName).c_str(), L"rb", _SH_DENYNO);
                if (!f) continue;
                char b[65536]; size_t n;
                while ((n = fread(b, 1, sizeof(b), f)) > 0) all.append(b, n);
                fclose(f);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
            return all;
        }
        bool LogHas(const std::string& s) const { return Log().find(s) != std::string::npos; }
        // Строка есть в журнале, записанном ЭТИМ запуском сервера (папка журнала общая у сценариев одного стенда).
        bool LogHasNew(const std::string& s) const { std::string l = Log(); return l.size() > logBase && l.find(s, logBase) != std::string::npos; }
        // Сколько раз строка встречается в журнале.
        int LogCount(const std::string& s) const { std::string l = Log(); int n = 0; for (size_t p = 0; (p = l.find(s, p)) != std::string::npos; p += s.size()) ++n; return n; }
        // Число строк журнала.
        size_t LogLines() const { std::string l = Log(); return (size_t)std::count(l.begin(), l.end(), '\n'); }
        // Ждать строку в журнале.
        bool WaitLog(const std::string& s, int timeoutMs) const
        {
            int64_t end = NowMs() + timeoutMs;
            while (NowMs() < end) { if (LogHas(s)) return true; Sleep(100); }
            return LogHas(s);
        }
    };
}
