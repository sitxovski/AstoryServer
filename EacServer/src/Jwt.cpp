// Copyright (c) 2026 @sitxovski (Discord)
// Jwt.cpp — выпуск/проверка JWT RS256 (см. Jwt.h).
#include "EacCommon.h"
#include "Jwt.h"

namespace Eac { namespace Jwt
{
    std::string Kid(const Crypto::RsaKey& key)
    {
        std::vector<uint8_t> ne(key.N());
        ne.insert(ne.end(), key.E().begin(), key.E().end());
        uint8_t h[32];
        if (!Crypto::Sha256(ne.data(), ne.size(), h)) return std::string();
        return Crypto::B64Url(h, 32).substr(0, 16);
    }

    std::string Jwks(const Crypto::RsaKey& key, const std::string& kid)
    {
        return std::string("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":") + Json::Quote(kid) +
               ",\"n\":" + Json::Quote(Crypto::B64Url(key.N().data(), key.N().size())) +
               ",\"e\":" + Json::Quote(Crypto::B64Url(key.E().data(), key.E().size())) + "}]}";
    }

    bool Issue(Crypto::RsaKey& key, const std::string& kid, const std::string& iss, const std::string& aud,
               const std::string& sub, int64_t iat, int ttlSec, std::string& token, std::string* jtiOut)
    {
        uint8_t rnd[16];
        if (!Crypto::Random(rnd, sizeof(rnd))) return false;
        std::string jti = Crypto::B64Url(rnd, sizeof(rnd));
        std::string header = std::string("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":") + Json::Quote(kid) + "}";
        std::string claims = std::string("{\"iss\":") + Json::Quote(iss) + ",\"aud\":" + Json::Quote(aud) +
                             ",\"sub\":" + Json::Quote(sub) + ",\"iat\":" + std::to_string(iat) +
                             ",\"nbf\":" + std::to_string(iat) + ",\"exp\":" + std::to_string(iat + ttlSec) +
                             ",\"jti\":" + Json::Quote(jti) + "}";
        std::string signingInput = Crypto::B64Url(header) + "." + Crypto::B64Url(claims);
        uint8_t h[32];
        if (!Crypto::Sha256(signingInput.data(), signingInput.size(), h)) return false;
        std::vector<uint8_t> sig;
        if (!key.SignSha256(h, sig)) return false;
        token = signingInput + "." + Crypto::B64Url(sig.data(), sig.size());
        if (jtiOut) *jtiOut = jti;
        return true;
    }

    // Разрезать токен на три части.
    static bool Split(const std::string& t, std::string& a, std::string& b, std::string& c)
    {
        size_t p1 = t.find('.'); if (p1 == std::string::npos) return false;
        size_t p2 = t.find('.', p1 + 1); if (p2 == std::string::npos) return false;
        if (t.find('.', p2 + 1) != std::string::npos) return false;
        a = t.substr(0, p1); b = t.substr(p1 + 1, p2 - p1 - 1); c = t.substr(p2 + 1);
        return !a.empty() && !b.empty() && !c.empty();
    }

    bool Verify(Crypto::RsaKey& pub, const std::string& kid, const std::string& token,
                Json::Value& header, Json::Value& claims, std::string* err)
    {
        std::string a, b, c;
        if (!Split(token, a, b, c)) { if (err) *err = "не 3 части"; return false; }
        std::vector<uint8_t> ha, cb, sg;
        if (!Crypto::B64UrlDecode(a, ha) || !Crypto::B64UrlDecode(b, cb) || !Crypto::B64UrlDecode(c, sg)) { if (err) *err = "не base64url"; return false; }
        if (!Json::Parse(std::string(ha.begin(), ha.end()), header) || header.type != Json::Type::Object) { if (err) *err = "заголовок не JSON"; return false; }
        if (!Json::Parse(std::string(cb.begin(), cb.end()), claims) || claims.type != Json::Type::Object) { if (err) *err = "claims не JSON"; return false; }
        std::string alg, typ, k;
        if (!header.GetString("alg", alg) || alg != "RS256" || !header.GetString("typ", typ) || typ != "JWT" ||
            !header.GetString("kid", k) || k != kid) { if (err) *err = "alg/typ/kid"; return false; }
        std::string input = a + "." + b;
        uint8_t h[32];
        if (!Crypto::Sha256(input.data(), input.size(), h)) { if (err) *err = "sha"; return false; }
        if (!pub.VerifySha256(h, sg.data(), sg.size())) { if (err) *err = "подпись не сошлась"; return false; }
        return true;
    }

    bool LooksLikeJwt(const std::string& token, size_t maxLen)
    {
        if (token.empty() || token.size() > maxLen) return false;
        std::string a, b, c;
        if (!Split(token, a, b, c)) return false;
        std::vector<uint8_t> ha, cb, sg;
        if (!Crypto::B64UrlDecode(a, ha) || !Crypto::B64UrlDecode(b, cb) || !Crypto::B64UrlDecode(c, sg)) return false;
        Json::Value hv, cv;
        if (!Json::Parse(std::string(ha.begin(), ha.end()), hv) || hv.type != Json::Type::Object) return false;
        if (!Json::Parse(std::string(cb.begin(), cb.end()), cv) || cv.type != Json::Type::Object) return false;
        return !sg.empty();
    }
}}
