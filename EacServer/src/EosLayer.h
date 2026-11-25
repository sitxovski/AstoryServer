// Copyright (c) 2026 @sitxovski (Discord)
// EosLayer.h — прослойка над EOS SDK 1.19.2.1 (AntiCheatServer + Connect.VerifyIdToken) для нити ядра.
// Все вызовы — ТОЛЬКО из нити ядра (EOS SDK однопоточен по контракту образца Samples/AntiCheat/Server:
// Transport.Update + EOS_Platform_Tick в одной нити). Колбэки приходят изнутри Tick() в той же нити.
// Реализации:
//   * MakeRealEos   — настоящий SDK (Platform bIsServer, без оверлея, ClientCredentials AlphaServer);
//   * MakeNullEos   — ключ --no-eos: EOS не инициализируется, проверка токена → «внутренняя ошибка»;
//   * MakeFakeEos   — только сборка стенда (--fake-eos): имитация VerifyIdToken/RegisterClient/сообщений.
#pragma once
#include "Config.h"
#include <cstdint>
#include <string>
#include <memory>

namespace Eac
{
    // Итог EOS_Connect_VerifyIdToken.
    struct VerifyResult
    {
        int         eosResult = -1;        // EOS_EResult (0 = успех)
        std::string eosResultText;         // EOS_EResult_ToString
        bool        transient = false;     // сетевой/временный сбой Epic (→ REG_RESULT 3, FailOpen)
        bool        accountInfo = false;   // bIsAccountInfoPresent
        int         accountType = -1;      // EOS_EExternalAccountType (8 = OPENID)
        std::string accountId;             // AccountId (= наш sub = UserIndex)
        std::string puid;                  // ProductUserId из ответа (строкой)
        std::string platform, deviceType;  // для журнала
    };

    // Получатель событий EOS (реализует ядро).
    class IEosSink
    {
    public:
        virtual ~IEosSink() {}
        // EOS просит переслать клиенту сообщение (≤ 512 байт).
        virtual void OnEosMessageToClient(uint64_t handle, const uint8_t* data, uint32_t len) = 0;
        // ClientActionRequired: action (1 = RemovePlayer), reason (EOS_EAntiCheatCommonClientActionReason), details.
        virtual void OnEosActionRequired(uint64_t handle, int action, int reason, const std::string& details) = 0;
        // ClientAuthStatusChanged (1 LocalAuthComplete, 2 RemoteAuthComplete).
        virtual void OnEosAuthStatus(uint64_t handle, int status) = 0;
        // Результат VerifyIdToken для запроса reqId.
        virtual void OnEosVerifyDone(uint64_t reqId, const VerifyResult& r) = 0;
    };

    // Интерфейс прослойки.
    class IEos
    {
    public:
        virtual ~IEos() {}
        // Инициализация SDK, платформа, подписки, BeginSession. false — не удалось (процесс работает дальше, FailOpen).
        virtual bool Start(IEosSink* sink) = 0;
        // Тик (каждые TickMs).
        virtual void Tick() = 0;
        // EndSession, снятие подписок, Platform_Release, EOS_Shutdown.
        virtual void Stop() = 0;
        // Была ли успешная BeginSession (для FailOpen «до первой успешной BeginSession»).
        virtual bool SessionStarted() const = 0;
        // Запустить проверку ID-токена (асинхронно; ответ — OnEosVerifyDone). false — вызов не принят.
        virtual bool VerifyIdToken(uint64_t reqId, const std::string& puid, const std::string& jwt) = 0;
        // RegisterClient (ProtectedClient, UserId = PUID). err — текст EOS_EResult при отказе.
        virtual bool RegisterClient(uint64_t handle, const std::string& puid, uint8_t platform, const std::string& ip, std::string* err) = 0;
        // UnregisterClient.
        virtual void UnregisterClient(uint64_t handle) = 0;
        // ReceiveMessageFromClient.
        virtual bool ReceiveFromClient(uint64_t handle, const uint8_t* data, uint32_t len) = 0;
        // ред. 3 §8.3: число ВРЕМЕННЫХ ошибок вызовов EOS (RegisterClient/ReceiveMessageFromClient вернули сетевой/сервисный
        // EOS_EResult) с прошлого вызова — признак «Epic недоступен» по ошибкам в нити ядра (EOS_Platform_Tick сам кодов не даёт).
        virtual int TakeCallErrors() = 0;
        // Название реализации (журнал).
        virtual const char* Name() const = 0;
    };

    // Настоящий EOS. secrets — из eos.json.
    std::unique_ptr<IEos> MakeRealEos(const Config& cfg, const EosSecrets& secrets);
    // --no-eos.
    std::unique_ptr<IEos> MakeNullEos();
#ifdef ASDA_EAC_STAND
    // ★ Только стенд (--fake-eos). Токен «b64url({"alg":"none"}).b64url({"sub":"<ui>","puid":"<32hex>",…}).ZmFrZQ»:
    //   sub/puid совпали с REG → успех (AccountType OPENID, AccountId = sub); sub "transient" → EOS_NoConnection;
    //   иначе EOS_InvalidAuth. Необязательные строковые поля (ред. 3, стенды E1-01/E1-03):
    //     "auth":  "remote" (по умолчанию: после RegisterClient — LocalAuthComplete, затем RemoteAuthComplete), "local"
    //              (только LocalAuthComplete), "none" (статуса нет);  "authDelayMs": задержка RemoteAuthComplete, мс;
    //     "eosres": временный отказ VerifyIdToken с этим кодом ("TooManyRequests", "TimedOut", "NoConnection",
    //              "ServiceFailure", "UnexpectedError") — как у живого Epic;  "noanswer":"1" — VerifyIdToken без ответа;
    //     "regerr":"1" — RegisterClient отказывает временной ошибкой (EOS_ServiceFailure, считается в TakeCallErrors).
    //   ACMSG эхом возвращается клиенту; ACMSG "ACTION:<n>" → ClientActionRequired(reason n); "AUTH:<0|1|2>" →
    //   ClientAuthStatusChanged с этим статусом.
    std::unique_ptr<IEos> MakeFakeEos();
#endif

    // ★ --eos-smoke: Initialize + Platform_Create + BeginSession + 3 с тиков + EndSession. Код возврата процесса.
    int EosSmoke(const Config& cfg, const EosSecrets& secrets);
}
