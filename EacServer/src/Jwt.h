// Copyright (c) 2026 @sitxovski (Discord)
// Jwt.h — JWT RS256 и JWKS для AsdaId (контракт §2).
//   заголовок {"alg":"RS256","typ":"JWT","kid":"<kid>"};
//   claims iss, aud, sub (UserIndex десятичной строкой), iat, nbf=iat, exp=iat+ttl, jti (16 случайных байт, base64url);
//   kid = base64url(SHA-256(n || e))[0..16] (n, e — big-endian без ведущих нулей).
#pragma once
#include "Crypto.h"
#include "Json.h"
#include <string>

namespace Eac { namespace Jwt
{
    // Идентификатор ключа (16 символов base64url).
    std::string Kid(const Crypto::RsaKey& key);
    // Тело /.well-known/jwks.json.
    std::string Jwks(const Crypto::RsaKey& key, const std::string& kid);
    // Выпустить access-токен. jtiOut — jti (для журнала). false — сбой подписи CNG.
    bool Issue(Crypto::RsaKey& key, const std::string& kid, const std::string& iss, const std::string& aud,
               const std::string& sub, int64_t iat, int ttlSec, std::string& token, std::string* jtiOut);
    // Проверить токен открытым ключом: формат, alg/typ/kid, подпись. header/claims — разобранные части.
    // (сервер сам токены не проверяет — это делает Epic по JWKS; функция нужна стенду AsdaId)
    bool Verify(Crypto::RsaKey& pub, const std::string& kid, const std::string& token,
                Json::Value& header, Json::Value& claims, std::string* err);
    // Структурная проверка «похоже на JWT»: 3 части base64url, заголовок — JSON-объект, длина ≤ max.
    // Сайдкар отсекает мусор до EOS (REG_RESULT 1), не проверяя подпись (её проверяет Epic в VerifyIdToken).
    bool LooksLikeJwt(const std::string& token, size_t maxLen);
}}
