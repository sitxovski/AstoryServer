// Copyright (c) 2026 @sitxovski (Discord)
// EosLayer.cpp — реализации IEos (см. EosLayer.h). Основа — Samples/AntiCheat/Server (EosSdk.cpp, AntiCheatServer.cpp,
// Main/ServerMain.cpp) EOS SDK 1.19.2.1. DLL EOSSDK-Win64-Shipping.dll грузится отложенно (/DELAYLOAD): с --no-eos
// процесс к ней не обращается вовсе.
#include "EacCommon.h"
#include "EosLayer.h"
#include "Crypto.h"
#include "Json.h"
#include "Log.h"
#include <eos_sdk.h>
#include <eos_logging.h>
#include <eos_connect.h>
#include <eos_anticheatserver.h>
#include <deque>
#include <set>
#include <map>
#include <cstring>

namespace Eac
{
    namespace
    {
        // Строки, которые нельзя пускать в журнал (секрет клиента и его Basic-форма).
        std::vector<std::string> g_redact;

        // Стандартный base64 (для Basic-формы секрета).
        std::string B64Std(const std::string& s)
        {
            static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string o; size_t i = 0;
            for (; i + 3 <= s.size(); i += 3)
            {
                uint32_t v = ((uint8_t)s[i] << 16) | ((uint8_t)s[i + 1] << 8) | (uint8_t)s[i + 2];
                o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; o += A[(v >> 6) & 63]; o += A[v & 63];
            }
            if (s.size() - i == 1) { uint32_t v = (uint8_t)s[i] << 16; o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; o += "=="; }
            else if (s.size() - i == 2) { uint32_t v = ((uint8_t)s[i] << 16) | ((uint8_t)s[i + 1] << 8); o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; o += A[(v >> 6) & 63]; o += '='; }
            return o;
        }

        // Вымарать секреты и токены из строки журнала EOS: известные секреты, значения после «Basic »/«Bearer »,
        // JWT-подобные куски «eyJ…».
        std::string Redact(std::string m)
        {
            for (const std::string& r : g_redact)
            {
                if (r.empty()) continue;
                size_t p;
                while ((p = m.find(r)) != std::string::npos) m.replace(p, r.size(), "***");
            }
            for (const char* key : { "Basic ", "Bearer ", "basic ", "bearer " })
            {
                size_t p = 0, kl = strlen(key);
                while ((p = m.find(key, p)) != std::string::npos)
                {
                    size_t b = p + kl, e = b;
                    while (e < m.size() && m[e] != ' ' && m[e] != '"' && m[e] != '\'' && m[e] != ',' && m[e] != '\r' && m[e] != '\n') ++e;
                    if (e > b) m.replace(b, e - b, "***");
                    p = b + 3;
                }
            }
            size_t p = 0;
            while ((p = m.find("eyJ", p)) != std::string::npos)
            {
                size_t e = p;
                while (e < m.size() && (isalnum((unsigned char)m[e]) || m[e] == '-' || m[e] == '_' || m[e] == '.')) ++e;
                if (e - p > 20) m.replace(p, e - p, "eyJ***");
                p += 3;
            }
            return m;
        }

        // Колбэк журнала EOS → наш журнал (тег "eos").
        void EOS_CALL OnEosLog(const EOS_LogMessage* msg)
        {
            if (!msg || msg->Level == EOS_ELogLevel::EOS_LOG_Off) return;
            std::string text = Redact(msg->Message ? msg->Message : "");
            const char* cat = msg->Category ? msg->Category : "?";
            if (msg->Level <= EOS_ELogLevel::EOS_LOG_Error) LOGE("eos", "%s: %s", cat, text.c_str());
            else if (msg->Level == EOS_ELogLevel::EOS_LOG_Warning) LOGW("eos", "%s: %s", cat, text.c_str());
            else LOGI("eos", "%s: %s", cat, text.c_str());
        }

        // Временный (сетевой/сервисный) ли результат — Epic недоступен, а не токен плох.
        bool IsTransient(EOS_EResult r)
        {
            switch (r)
            {
            case EOS_EResult::EOS_NoConnection: case EOS_EResult::EOS_TooManyRequests: case EOS_EResult::EOS_UnrecognizedResponse:
            case EOS_EResult::EOS_TimedOut: case EOS_EResult::EOS_ServiceFailure: case EOS_EResult::EOS_OperationWillRetry:
            case EOS_EResult::EOS_UnexpectedError:
                return true;
            default:
                return false;
            }
        }

        // DLL SDK рядом с exe? (отложенная загрузка бросила бы SEH-исключение при отсутствии)
        bool EosDllPresent()
        {
            std::wstring p = ExeDir() + L"EOSSDK-Win64-Shipping.dll";
            HMODULE h = LoadLibraryExW(p.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (!h) { LOGE("eos", "нет EOSSDK-Win64-Shipping.dll рядом с exe (%lu)", GetLastError()); return false; }
            return true;   // модуль остаётся загруженным — его же возьмёт отложенный импорт
        }

        // Общая инициализация SDK + платформы. plat — результат. false — отказ (журнал уже записан).
        bool InitSdkAndPlatform(const Config& cfg, const EosSecrets& sec, EOS_HPlatform& plat, bool& initDone)
        {
            plat = nullptr; initDone = false;
            if (!EosDllPresent()) return false;
            g_redact = { sec.clientSecret, B64Std(sec.clientId + ":" + sec.clientSecret) };

            EOS_InitializeOptions io = {};
            io.ApiVersion = EOS_INITIALIZE_API_LATEST;
            io.ProductName = "AsdaEacServer";
            io.ProductVersion = "1.0";
            EOS_EResult r = EOS_Initialize(&io);
            if (r != EOS_EResult::EOS_Success && r != EOS_EResult::EOS_AlreadyConfigured)
            {
                LOGE("eos", "EOS_Initialize: %s", EOS_EResult_ToString(r));
                return false;
            }
            initDone = true;
            if (EOS_Logging_SetCallback(&OnEosLog) == EOS_EResult::EOS_Success)
                EOS_Logging_SetLogLevel(EOS_ELogCategory::EOS_LC_ALL_CATEGORIES, (EOS_ELogLevel)cfg.eosLogLevel);
            else LOGW("eos", "EOS_Logging_SetCallback не удался");

            CreateDirectoryW(cfg.eosCacheDir.c_str(), nullptr);
            std::string cache = Utf8(cfg.eosCacheDir);
            EOS_Platform_Options po = {};
            po.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
            po.bIsServer = EOS_TRUE;                      // выделенный сервер
            po.Flags = EOS_PF_DISABLE_OVERLAY;            // оверлей серверу не нужен
            po.ProductId = sec.productId.c_str();
            po.SandboxId = sec.sandboxId.c_str();
            po.DeploymentId = sec.deploymentId.c_str();
            po.ClientCredentials.ClientId = sec.clientId.c_str();
            po.ClientCredentials.ClientSecret = sec.clientSecret.c_str();
            po.CacheDirectory = cache.c_str();
            po.EncryptionKey = nullptr;                   // хранилища (PlayerDataStorage/TitleStorage) не используются
            plat = EOS_Platform_Create(&po);
            if (!plat) { LOGE("eos", "EOS_Platform_Create вернул null"); return false; }
            LOGI("eos", "платформа создана: product=%s sandbox=%s deployment=%s client=%s (bIsServer, без оверлея)",
                 sec.productId.c_str(), sec.sandboxId.c_str(), sec.deploymentId.c_str(), sec.clientId.c_str());
            return true;
        }

        // ── Настоящий EOS ─────────────────────────────────────────────────────────────────
        class RealEos : public IEos
        {
        public:
            RealEos(const Config& c, const EosSecrets& s) : m_cfg(c), m_sec(s) {}
            ~RealEos() override { Stop(); }

            bool Start(IEosSink* sink) override
            {
                m_sink = sink;
                if (!InitSdkAndPlatform(m_cfg, m_sec, m_plat, m_init)) return false;
                m_ac = EOS_Platform_GetAntiCheatServerInterface(m_plat);
                m_conn = EOS_Platform_GetConnectInterface(m_plat);
                if (!m_ac || !m_conn) { LOGE("eos", "нет интерфейса AntiCheatServer/Connect"); return false; }
                {
                    EOS_AntiCheatServer_AddNotifyMessageToClientOptions o = {}; o.ApiVersion = EOS_ANTICHEATSERVER_ADDNOTIFYMESSAGETOCLIENT_API_LATEST;
                    m_nMsg = EOS_AntiCheatServer_AddNotifyMessageToClient(m_ac, &o, this, &OnMsg);
                }
                {
                    EOS_AntiCheatServer_AddNotifyClientActionRequiredOptions o = {}; o.ApiVersion = EOS_ANTICHEATSERVER_ADDNOTIFYCLIENTACTIONREQUIRED_API_LATEST;
                    m_nAct = EOS_AntiCheatServer_AddNotifyClientActionRequired(m_ac, &o, this, &OnAct);
                }
                {
                    EOS_AntiCheatServer_AddNotifyClientAuthStatusChangedOptions o = {}; o.ApiVersion = EOS_ANTICHEATSERVER_ADDNOTIFYCLIENTAUTHSTATUSCHANGED_API_LATEST;
                    m_nAuth = EOS_AntiCheatServer_AddNotifyClientAuthStatusChanged(m_ac, &o, this, &OnAuth);
                }
                EOS_AntiCheatServer_BeginSessionOptions bo = {};
                bo.ApiVersion = EOS_ANTICHEATSERVER_BEGINSESSION_API_LATEST;
                bo.RegisterTimeoutSeconds = (uint32_t)m_cfg.eosRegisterTimeoutSec;   // 60 (контракт/план §3.1)
                bo.ServerName = m_cfg.eosServerName.c_str();
                bo.bEnableGameplayData = EOS_FALSE;                                   // LogPlayer* не используем
                bo.LocalUserId = nullptr;                                             // выделенный сервер
                EOS_EResult r = EOS_AntiCheatServer_BeginSession(m_ac, &bo);
                m_started = r == EOS_EResult::EOS_Success;
                if (m_started) LOGI("eos", "BeginSession: успех (RegisterTimeout=%d, GameplayData=0)", m_cfg.eosRegisterTimeoutSec);
                else LOGE("eos", "BeginSession: %s", EOS_EResult_ToString(r));
                return m_started;
            }

            void Tick() override { if (m_plat) EOS_Platform_Tick(m_plat); }

            void Stop() override
            {
                if (m_ac)
                {
                    if (m_started)
                    {
                        EOS_AntiCheatServer_EndSessionOptions eo = {}; eo.ApiVersion = EOS_ANTICHEATSERVER_ENDSESSION_API_LATEST;
                        EOS_EResult r = EOS_AntiCheatServer_EndSession(m_ac, &eo);
                        LOGI("eos", "EndSession: %s", EOS_EResult_ToString(r));
                        m_started = false;
                    }
                    if (m_nMsg) EOS_AntiCheatServer_RemoveNotifyMessageToClient(m_ac, m_nMsg);
                    if (m_nAct) EOS_AntiCheatServer_RemoveNotifyClientActionRequired(m_ac, m_nAct);
                    if (m_nAuth) EOS_AntiCheatServer_RemoveNotifyClientAuthStatusChanged(m_ac, m_nAuth);
                    m_nMsg = m_nAct = m_nAuth = 0; m_ac = nullptr;
                }
                if (m_plat) { EOS_Platform_Release(m_plat); m_plat = nullptr; }
                if (m_init) { EOS_Shutdown(); m_init = false; }
            }

            bool SessionStarted() const override { return m_started; }

            bool VerifyIdToken(uint64_t reqId, const std::string& puid, const std::string& jwt) override
            {
                if (!m_conn) return false;
                EOS_ProductUserId pu = EOS_ProductUserId_FromString(puid.c_str());
                if (!EOS_ProductUserId_IsValid(pu)) return false;
                EOS_Connect_IdToken tok = {};
                tok.ApiVersion = EOS_CONNECT_IDTOKEN_API_LATEST;
                tok.ProductUserId = pu;
                tok.JsonWebToken = jwt.c_str();
                EOS_Connect_VerifyIdTokenOptions o = {};
                o.ApiVersion = EOS_CONNECT_VERIFYIDTOKEN_API_LATEST;
                o.IdToken = &tok;
                VerifyCtx* ctx = new VerifyCtx{ this, reqId };
                EOS_Connect_VerifyIdToken(m_conn, &o, ctx, &OnVerify);
                return true;
            }

            bool RegisterClient(uint64_t handle, const std::string& puid, uint8_t platform, const std::string& ip, std::string* err) override
            {
                if (!m_ac || !m_started) { if (err) *err = "сессия AntiCheatServer не начата"; return false; }
                EOS_AntiCheatServer_RegisterClientOptions o = {};
                o.ApiVersion = EOS_ANTICHEATSERVER_REGISTERCLIENT_API_LATEST;
                o.ClientHandle = (EOS_AntiCheatCommon_ClientHandle)(uintptr_t)handle;
                o.ClientType = EOS_EAntiCheatCommonClientType::EOS_ACCCT_ProtectedClient;
                o.ClientPlatform = (EOS_EAntiCheatCommonClientPlatform)platform;
                o.AccountId_DEPRECATED = nullptr;     // устаревшее — только UserId
                o.IpAddress = ip.empty() ? nullptr : ip.c_str();
                o.UserId = EOS_ProductUserId_FromString(puid.c_str());
                EOS_EResult r = EOS_AntiCheatServer_RegisterClient(m_ac, &o);
                if (r != EOS_EResult::EOS_Success) { if (IsTransient(r)) ++m_callErrors; if (err) *err = EOS_EResult_ToString(r); return false; }
                return true;
            }

            void UnregisterClient(uint64_t handle) override
            {
                if (!m_ac) return;
                EOS_AntiCheatServer_UnregisterClientOptions o = {};
                o.ApiVersion = EOS_ANTICHEATSERVER_UNREGISTERCLIENT_API_LATEST;
                o.ClientHandle = (EOS_AntiCheatCommon_ClientHandle)(uintptr_t)handle;
                EOS_EResult r = EOS_AntiCheatServer_UnregisterClient(m_ac, &o);
                if (r != EOS_EResult::EOS_Success) LOGW("eos", "UnregisterClient h=%llu: %s", (unsigned long long)handle, EOS_EResult_ToString(r));
            }

            bool ReceiveFromClient(uint64_t handle, const uint8_t* data, uint32_t len) override
            {
                if (!m_ac) return false;
                EOS_AntiCheatServer_ReceiveMessageFromClientOptions o = {};
                o.ApiVersion = EOS_ANTICHEATSERVER_RECEIVEMESSAGEFROMCLIENT_API_LATEST;
                o.ClientHandle = (EOS_AntiCheatCommon_ClientHandle)(uintptr_t)handle;
                o.Data = data;
                o.DataLengthBytes = len;
                EOS_EResult r = EOS_AntiCheatServer_ReceiveMessageFromClient(m_ac, &o);
                if (r != EOS_EResult::EOS_Success)
                {
                    if (IsTransient(r)) ++m_callErrors;
                    LOGW("eos", "ReceiveMessageFromClient h=%llu: %s", (unsigned long long)handle, EOS_EResult_ToString(r));
                    return false;
                }
                return true;
            }

            int TakeCallErrors() override { int n = m_callErrors; m_callErrors = 0; return n; }

            const char* Name() const override { return "EOS SDK 1.19.2.1"; }

        private:
            struct VerifyCtx { RealEos* self; uint64_t reqId; };   // контекст VerifyIdToken
            Config m_cfg; EosSecrets m_sec;
            IEosSink* m_sink = nullptr;
            EOS_HPlatform m_plat = nullptr;
            EOS_HAntiCheatServer m_ac = nullptr;
            EOS_HConnect m_conn = nullptr;
            EOS_NotificationId m_nMsg = 0, m_nAct = 0, m_nAuth = 0;
            bool m_init = false, m_started = false;
            int  m_callErrors = 0;            // временные ошибки RegisterClient/ReceiveMessageFromClient с прошлого TakeCallErrors

            static void EOS_CALL OnMsg(const EOS_AntiCheatCommon_OnMessageToClientCallbackInfo* d)
            {
                RealEos* self = (RealEos*)d->ClientData;
                if (self && self->m_sink) self->m_sink->OnEosMessageToClient((uint64_t)(uintptr_t)d->ClientHandle, (const uint8_t*)d->MessageData, d->MessageDataSizeBytes);
            }
            static void EOS_CALL OnAct(const EOS_AntiCheatCommon_OnClientActionRequiredCallbackInfo* d)
            {
                RealEos* self = (RealEos*)d->ClientData;
                if (self && self->m_sink) self->m_sink->OnEosActionRequired((uint64_t)(uintptr_t)d->ClientHandle, (int)d->ClientAction,
                                                                           (int)d->ActionReasonCode, d->ActionReasonDetailsString ? d->ActionReasonDetailsString : "");
            }
            static void EOS_CALL OnAuth(const EOS_AntiCheatCommon_OnClientAuthStatusChangedCallbackInfo* d)
            {
                RealEos* self = (RealEos*)d->ClientData;
                if (self && self->m_sink) self->m_sink->OnEosAuthStatus((uint64_t)(uintptr_t)d->ClientHandle, (int)d->ClientAuthStatus);
            }
            static void EOS_CALL OnVerify(const EOS_Connect_VerifyIdTokenCallbackInfo* d)
            {
                VerifyCtx* ctx = (VerifyCtx*)d->ClientData;
                if (!ctx) return;
                VerifyResult vr;
                vr.eosResult = (int)d->ResultCode;
                vr.eosResultText = EOS_EResult_ToString(d->ResultCode);
                vr.transient = IsTransient(d->ResultCode);
                if (d->ResultCode == EOS_EResult::EOS_Success)
                {
                    char buf[EOS_PRODUCTUSERID_MAX_LENGTH + 1] = {}; int32_t n = (int32_t)sizeof(buf);
                    if (d->ProductUserId && EOS_ProductUserId_ToString(d->ProductUserId, buf, &n) == EOS_EResult::EOS_Success) vr.puid = buf;
                    vr.accountInfo = d->bIsAccountInfoPresent == EOS_TRUE;
                    if (vr.accountInfo)
                    {
                        vr.accountType = (int)d->AccountIdType;
                        vr.accountId = d->AccountId ? d->AccountId : "";
                        vr.platform = d->Platform ? d->Platform : "";
                        vr.deviceType = d->DeviceType ? d->DeviceType : "";
                    }
                }
                if (ctx->self && ctx->self->m_sink) ctx->self->m_sink->OnEosVerifyDone(ctx->reqId, vr);
                delete ctx;
            }
        };

        // ── --no-eos ──────────────────────────────────────────────────────────────────────
        class NullEos : public IEos
        {
        public:
            bool Start(IEosSink*) override { LOGW("eos", "EOS НЕ инициализирован (--no-eos или нет eos.json): REG → REG_RESULT 3, BeginSession не вызывается"); return false; }
            void Tick() override {}
            void Stop() override {}
            bool SessionStarted() const override { return false; }
            bool VerifyIdToken(uint64_t, const std::string&, const std::string&) override { return false; }
            bool RegisterClient(uint64_t, const std::string&, uint8_t, const std::string&, std::string* err) override { if (err) *err = "--no-eos"; return false; }
            void UnregisterClient(uint64_t) override {}
            bool ReceiveFromClient(uint64_t, const uint8_t*, uint32_t) override { return false; }
            int TakeCallErrors() override { return 0; }
            const char* Name() const override { return "нет (--no-eos / нет eos.json)"; }
        };

#ifdef ASDA_EAC_STAND
        // ── Фальшивый EOS стенда ──────────────────────────────────────────────────────────
        class FakeEos : public IEos
        {
        public:
            bool Start(IEosSink* sink) override { m_sink = sink; m_started = true; LOGW("eos", "★ СТЕНД: фальшивый EOS (--fake-eos)"); return true; }
            void Tick() override
            {
                // Доставка созревших событий (как колбэки SDK изнутри Tick): по порядку, только те, чей срок наступил.
                int64_t now = NowMs();
                std::deque<Ev> due, keep;
                for (Ev& e : m_q) (e.dueMs <= now ? due : keep).push_back(std::move(e));
                m_q.swap(keep);
                for (Ev& e : due)
                {
                    if (e.kind == 0) m_sink->OnEosVerifyDone(e.id, e.vr);
                    else if (e.kind == 1) { if (m_reg.count(e.id)) m_sink->OnEosMessageToClient(e.id, e.data.data(), (uint32_t)e.data.size()); }
                    else if (e.kind == 2) { if (m_reg.count(e.id)) m_sink->OnEosActionRequired(e.id, 1, e.reason, "fake action"); }
                    else if (e.kind == 3) { if (m_reg.count(e.id)) m_sink->OnEosAuthStatus(e.id, e.reason); }
                }
            }
            void Stop() override { m_started = false; }
            bool SessionStarted() const override { return m_started; }
            bool VerifyIdToken(uint64_t reqId, const std::string& puid, const std::string& jwt) override
            {
                Ev e; e.kind = 0; e.id = reqId; e.dueMs = NowMs();
                e.vr.eosResult = 4; e.vr.eosResultText = "EOS_InvalidAuth";
                size_t p1 = jwt.find('.'), p2 = jwt.find('.', p1 + 1);
                std::vector<uint8_t> pl; Json::Value v; std::string sub, tp, res, noans, auth = "remote", delay, regerr;
                if (p1 != std::string::npos && p2 != std::string::npos && Crypto::B64UrlDecode(jwt.substr(p1 + 1, p2 - p1 - 1), pl) &&
                    Json::Parse(std::string(pl.begin(), pl.end()), v) && v.GetString("sub", sub) && v.GetString("puid", tp))
                {
                    v.GetString("eosres", res); v.GetString("noanswer", noans); v.GetString("auth", auth); v.GetString("authDelayMs", delay);
                    v.GetString("regerr", regerr);
                    if (noans == "1") return true;                       // ответа не будет (VerifyTimeoutSec ядра)
                    if (sub == "transient" && res.empty()) res = "NoConnection";
                    static const struct { const char* name; int code; } kTr[] = {
                        { "NoConnection", 1 }, { "TooManyRequests", 8 }, { "TimedOut", 27 }, { "ServiceFailure", 35 }, { "UnexpectedError", 0x7FFFFFFF } };
                    bool known = false;
                    for (auto& t : kTr) if (res == t.name) { e.vr.eosResult = t.code; e.vr.eosResultText = std::string("EOS_") + t.name; e.vr.transient = true; known = true; }
                    if (!known && tp == puid)
                    {
                        e.vr.eosResult = 0; e.vr.eosResultText = "EOS_Success"; e.vr.puid = puid;
                        e.vr.accountInfo = true; e.vr.accountType = 8; e.vr.accountId = sub; e.vr.platform = "Windows"; e.vr.deviceType = "PC";
                        Plan pn; pn.auth = auth; pn.delayMs = atoi(delay.c_str()); pn.regErr = regerr == "1";
                        m_plan[puid] = pn;
                    }
                }
                m_q.push_back(e);
                return true;
            }
            bool RegisterClient(uint64_t handle, const std::string& puid, uint8_t, const std::string&, std::string* err) override
            {
                Plan pn; auto it = m_plan.find(puid); if (it != m_plan.end()) pn = it->second;
                if (pn.regErr) { ++m_callErrors; if (err) *err = "EOS_ServiceFailure"; return false; }
                m_reg.insert(handle);
                int64_t now = NowMs();
                if (pn.auth == "remote" || pn.auth == "local") { Ev e; e.kind = 3; e.id = handle; e.reason = 1; e.dueMs = now; m_q.push_back(e); }
                if (pn.auth == "remote") { Ev e; e.kind = 3; e.id = handle; e.reason = 2; e.dueMs = now + pn.delayMs; m_q.push_back(e); }
                return true;
            }
            void UnregisterClient(uint64_t handle) override { m_reg.erase(handle); }
            bool ReceiveFromClient(uint64_t handle, const uint8_t* data, uint32_t len) override
            {
                if (!m_reg.count(handle)) return false;
                Ev e; e.id = handle; e.dueMs = NowMs();
                if (len > 7 && memcmp(data, "ACTION:", 7) == 0) { e.kind = 2; e.reason = atoi(std::string((const char*)data + 7, len - 7).c_str()); }
                else if (len > 5 && memcmp(data, "AUTH:", 5) == 0) { e.kind = 3; e.reason = atoi(std::string((const char*)data + 5, len - 5).c_str()); }
                else { e.kind = 1; e.data.assign(data, data + len); }
                m_q.push_back(e);
                return true;
            }
            int TakeCallErrors() override { int n = m_callErrors; m_callErrors = 0; return n; }
            const char* Name() const override { return "★ фальшивый EOS стенда"; }
        private:
            // Событие: kind 0 VerifyDone, 1 MessageToClient, 2 ActionRequired, 3 AuthStatus (reason = статус); dueMs — когда доставить.
            struct Ev { int kind = 0; uint64_t id = 0; VerifyResult vr; std::vector<uint8_t> data; int reason = 0; int64_t dueMs = 0; };
            // Сценарий учётки из токена: как вести себя RegisterClient и статусы аутентификации.
            struct Plan { std::string auth = "remote"; int delayMs = 0; bool regErr = false; };
            IEosSink* m_sink = nullptr;
            bool m_started = false;
            std::deque<Ev> m_q;
            std::set<uint64_t> m_reg;
            std::map<std::string, Plan> m_plan;   // PUID → сценарий последнего подтверждённого токена
            int m_callErrors = 0;
        };
#endif
    }

    std::unique_ptr<IEos> MakeRealEos(const Config& cfg, const EosSecrets& secrets) { return std::unique_ptr<IEos>(new RealEos(cfg, secrets)); }
    std::unique_ptr<IEos> MakeNullEos() { return std::unique_ptr<IEos>(new NullEos()); }
#ifdef ASDA_EAC_STAND
    std::unique_ptr<IEos> MakeFakeEos() { return std::unique_ptr<IEos>(new FakeEos()); }
#endif

    int EosSmoke(const Config& cfg, const EosSecrets& secrets)
    {
        // Отдельный приёмник: только журнал.
        struct Sink : IEosSink
        {
            void OnEosMessageToClient(uint64_t, const uint8_t*, uint32_t) override {}
            void OnEosActionRequired(uint64_t, int, int, const std::string&) override {}
            void OnEosAuthStatus(uint64_t, int) override {}
            void OnEosVerifyDone(uint64_t, const VerifyResult&) override {}
        } sink;
        RealEos eos(cfg, secrets);
        bool ok = eos.Start(&sink);
        LOGI("eos", "--eos-smoke: Platform_Create+BeginSession %s; тики 3 с", ok ? "УСПЕХ" : "ОТКАЗ");
        if (ok) for (int i = 0; i < 100; ++i) { eos.Tick(); Sleep(30); }
        eos.Stop();
        LOGI("eos", "--eos-smoke: итог %s", ok ? "OK" : "FAIL");
        return ok ? 0 : 3;
    }
}
