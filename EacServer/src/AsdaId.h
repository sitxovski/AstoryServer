// Copyright (c) 2026 @sitxovski (Discord)
// AsdaId.h — HTTP/1.1-сервер выдачи OpenID-токенов (контракт §2), 127.0.0.1:8444, наружу — только через Caddy.
//   POST /token   {"login","password_md5"} → 200 {access_token, token_type, expires_in, refresh_token} | 401 | 429 | 400
//   POST /refresh {"refresh_token"}        → 200 (новый access + новый refresh, старый гасится) | 401
//   GET  /.well-known/jwks.json, GET /.well-known/openid-configuration
// Модель (ред. 3, E1-05): нить ввода-вывода (WSAPoll по всем соединениям, общий срок запроса RequestDeadlineSec от accept,
// статика JWKS/openid-configuration отвечается сразу) + пул рабочих нитей БД (у каждой своё ODBC-соединение; получают только
// прочитанный целиком запрос) + фоновая нить (отложенные UPEacAuthFail, сброс refresh на диск). Keep-alive нет (Connection: close).
// IP клиента: при TrustForwardedFor=1 и соединении с 127.0.0.1 — ПОСЛЕДНИЙ элемент X-Forwarded-For (его ставит Caddy),
// иначе адрес сокета. Лимиты: TokenPerIpPerMin /token в минуту с IP; неудачи — на пару (логин, IP) и на логин с растущей
// паузой (E1-06). Refresh-токены — хеши в secrets\refresh.dat под DPAPI LocalMachine (E1-10), перепроверка учётки (E1-19).
#pragma once
#include "Config.h"
#include "Crypto.h"
#include "SqlAuth.h"
#include <functional>
#include <memory>

namespace Eac
{
    class AsdaIdServer
    {
    public:
        // Фабрика источника проверки пароля — по одному на рабочую нить.
        using AuthFactory = std::function<std::unique_ptr<IAuthBackend>()>;

        AsdaIdServer();
        ~AsdaIdServer();
        // Запустить слушатель и нити. key — загруженный ключ JWT (живёт дольше сервера).
        bool Start(const Config& cfg, Crypto::RsaKey* key, AuthFactory factory, std::string* err);
        // Остановить и дождаться нитей.
        void Stop();

    private:
        struct Impl;
        Impl* m;
    };
}
