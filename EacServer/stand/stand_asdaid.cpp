// Copyright (c) 2026 @sitxovski (Discord)
// stand_asdaid.cpp — стенд (а): клиент AsdaId против AsdaEacServer_stand.exe --no-eos --fake-auth.
// Проверяет: JWKS/openid-configuration, /token (200/401/400/429/503), JWT RS256 по собственному JWKS (kid, iss, aud, sub,
// iat/nbf/exp, jti), /refresh (ротация, старый гасится), лимит /token с IP, паузу после 5 неудач на логин,
// сохранение ключа JWT между запусками (kid тот же), 404/405, строгую схему JSON.
// Ред. 3: E1-05 — медленные клиенты не держат нити (общий срок запроса), статика .well-known для Caddy; E1-06 — неудачи на пару
// (логин, IP) и на логин с растущей паузой, «свои» IP не попадают под общую паузу, запись неудачи пароля (UPEacAuthFail);
// E1-10 — refresh на диске (DPAPI), переживает перезапуск, продление при использовании и абсолютный предел; E1-19 — перепроверка
// учётки на /refresh (блок, смена пароля, БД недоступна — проверка отложена).
#include "StandCommon.h"
#include "Jwt.h"
#include <thread>
#include <atomic>

using namespace Stand;

namespace
{
    int g_port = 18444;   // порт AsdaId стенда

    // HTTP-ответ.
    struct Resp { int code = 0; std::string body; std::string raw; };

    Resp Http(const std::string& method, const std::string& path, const std::string& body,
              const std::string& xff = "", const std::string& ctype = "application/json", const std::string& extraHdr = "")
    {
        Resp r;
        SOCKET s = Connect(g_port, 5000);
        if (s == INVALID_SOCKET) return r;
        std::string req = method + " " + path + " HTTP/1.1\r\nHost: @@ASTORY_AUTH_HOST@@\r\n";
        if (!ctype.empty()) req += "Content-Type: " + ctype + "\r\n";
        if (!xff.empty()) req += "X-Forwarded-For: " + xff + "\r\n";
        req += extraHdr;
        if (extraHdr.find("Transfer-Encoding") == std::string::npos) req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        req += "Connection: close\r\n\r\n" + body;
        SendAll(s, req.data(), req.size());
        uint8_t b[8192];
        while (true) { int n = RecvSome(s, b, sizeof(b), 5000); if (n <= 0) break; r.raw.append((char*)b, (size_t)n); }
        closesocket(s);
        if (r.raw.size() > 12 && r.raw.compare(0, 9, "HTTP/1.1 ") == 0) r.code = atoi(r.raw.c_str() + 9);
        size_t p = r.raw.find("\r\n\r\n");
        if (p != std::string::npos) r.body = r.raw.substr(p + 4);
        return r;
    }

    const char* kMd5 = "7787e2c49efec303a6d311a19d31b8b5";   // md5("stand-pass")

    std::string TokenBody(const std::string& login, const std::string& md5)
    {
        return "{\"login\":" + Eac::Json::Quote(login) + ",\"password_md5\":" + Eac::Json::Quote(md5) + "}";
    }

    // Разобранный ответ 200 /token.
    struct Pair { std::string access, refresh; bool ok = false; };

    Pair ParsePair(const Resp& r)
    {
        Pair p; Eac::Json::Value v;
        if (r.code != 200 || !Eac::Json::Parse(r.body, v)) return p;
        std::string tt; const Eac::Json::Value* ei = v.Get("expires_in");
        p.ok = v.GetString("access_token", p.access) && v.GetString("refresh_token", p.refresh) && v.GetString("token_type", tt) &&
               tt == "Bearer" && ei && ei->type == Eac::Json::Type::Number && ei->raw == "3600" && v.obj.size() == 4;
        return p;
    }

    // Ключ из JWKS.
    bool LoadJwks(Eac::Crypto::RsaKey& key, std::string& kid)
    {
        Resp r = Http("GET", "/.well-known/jwks.json", "", "", "");
        Eac::Json::Value v;
        if (r.code != 200 || !Eac::Json::Parse(r.body, v)) return false;
        const Eac::Json::Value* keys = v.Get("keys");
        if (!keys || keys->type != Eac::Json::Type::Array || keys->arr.size() != 1) return false;
        const Eac::Json::Value& k = keys->arr[0];
        std::string kty, use, alg, n, e;
        if (!k.GetString("kty", kty) || kty != "RSA" || !k.GetString("use", use) || use != "sig" || !k.GetString("alg", alg) || alg != "RS256" ||
            !k.GetString("kid", kid) || !k.GetString("n", n) || !k.GetString("e", e) || e != "AQAB") return false;
        std::vector<uint8_t> nb, eb;
        if (!Eac::Crypto::B64UrlDecode(n, nb) || !Eac::Crypto::B64UrlDecode(e, eb)) return false;
        if (!key.ImportPublic(nb, eb)) return false;
        // kid = base64url(SHA-256(n||e))[0..16]
        std::vector<uint8_t> ne(nb); ne.insert(ne.end(), eb.begin(), eb.end());
        uint8_t h[32]; Eac::Crypto::Sha256(ne.data(), ne.size(), h);
        return kid.size() == 16 && kid == Eac::Crypto::B64Url(h, 32).substr(0, 16) && key.Bits() == 2048;
    }

    bool CheckJwt(Eac::Crypto::RsaKey& key, const std::string& kid, const std::string& token, const std::string& wantSub, std::string& jti)
    {
        Eac::Json::Value h, c; std::string err;
        if (!Eac::Jwt::Verify(key, kid, token, h, c, &err)) { printf("    JWT: %s\n", err.c_str()); return false; }
        std::string iss, aud, sub;
        const Eac::Json::Value *iat = c.Get("iat"), *nbf = c.Get("nbf"), *exp = c.Get("exp");
        if (!c.GetString("iss", iss) || iss != "https://@@ASTORY_AUTH_HOST@@" || !c.GetString("aud", aud) || aud != "astory-eac" ||
            !c.GetString("sub", sub) || sub != wantSub || !c.GetString("jti", jti) || jti.size() < 16 || !iat || !nbf || !exp) return false;
        long long i = atoll(iat->raw.c_str()), n = atoll(nbf->raw.c_str()), e = atoll(exp->raw.c_str());
        time_t now = time(nullptr);
        return n == i && e == i + 3600 && i <= now + 5 && i >= now - 60 && h.obj.size() == 3 && c.obj.size() == 7;
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== stand_asdaid: AsdaId (/token, /refresh, JWKS) ===\n");
    std::wstring dir = RunDir("asdaid");
    AsdaSecure::PublicKey pub;
    if (!Check(MakeSecureKey(dir, pub), "ключ AsdaSecure стенда создан")) return Summary("stand_asdaid");
    std::wstring ini = WriteIni(dir, g_port, 25701, 25702, { {"AsdaId.LoginFailPauseSec", "3"}, {"AsdaId.LoginPauseStagesSec", "3,6,12"}, {"AsdaId.LoginGlobalFailMax", "10"},
                                                             {"AsdaId.FailWriteDelayMs", "200"}, {"AsdaId.RequestDeadlineSec", "2"}, {"AsdaId.WwwDir", U8(dir) + "www"},
                                                             {"General.Mode", "1"},
                                                             // ★ 17.10.2026 /status: «вход» = порт самого стенда (слушает), «игра» = закрытый порт
                                                             {"AsdaId.StatusLoginPort", std::to_string(g_port)}, {"AsdaId.StatusGamePort", "25799"},
                                                             {"AsdaId.StatusCacheMs", "300"} });
    std::string keepRefresh;   // refresh-токен, который должен пережить перезапуск (E1-10)
    std::string kid1;
    {
        Server srv;
        if (!Check(srv.Start(dir, ini, L"--no-eos --fake-auth", g_port), "сервер стенда запущен (--no-eos --fake-auth)")) return Summary("stand_asdaid");
        Check(GetFileAttributesW((dir + L"secrets\\jwt_rs256.key").c_str()) != INVALID_FILE_ATTRIBUTES, "ключ JWT создан при первом запуске");
        Check(srv.WaitLog("создан НОВЫЙ ключ JWT RSA-2048", 3000), "журнал: «создан НОВЫЙ ключ JWT»");

        printf("-- JWKS / openid-configuration\n");
        Eac::Crypto::RsaKey pk;
        Check(LoadJwks(pk, kid1), "JWKS: один ключ RSA/sig/RS256, e=AQAB, 2048 бит, kid = b64url(SHA-256(n||e))[0..16]");
        {
            Resp r = Http("GET", "/.well-known/openid-configuration", "", "", "");
            Check(r.code == 200 && r.body == "{\"issuer\":\"https://@@ASTORY_AUTH_HOST@@\",\"jwks_uri\":\"https://@@ASTORY_AUTH_HOST@@/.well-known/jwks.json\","
                                              "\"id_token_signing_alg_values_supported\":[\"RS256\"]}", "openid-configuration точно по контракту");
            Check(r.raw.find("Content-Type: application/json") != std::string::npos, "Content-Type: application/json");
        }

        printf("-- /token 200 и JWT\n");
        Resp t = Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.0.1");
        Pair p = ParsePair(t);
        Check(p.ok, "/token stand_ok → 200 {access_token, token_type=Bearer, expires_in=3600, refresh_token}");
        std::string jti1;
        Check(CheckJwt(pk, kid1, p.access, "777", jti1), "JWT: подпись по JWKS, iss/aud/sub=777/iat/nbf=iat/exp=iat+3600/jti");
        Check(p.refresh.size() == 43, "refresh_token: 43 символа base64url");
        Check(t.raw.find("Cache-Control: no-store") != std::string::npos, "ответ /token не кэшируется (no-store)");
        {
            Pair up = ParsePair(Http("POST", "/token", TokenBody("STAND_OK  ", "7787E2C49EFEC303A6D311A19D31B8B5"), "10.0.0.1"));
            std::string j; Check(up.ok && CheckJwt(pk, kid1, up.access, "777", j), "логин другим регистром + хвостовые пробелы, MD5 в верхнем регистре → 200");
            Check(j != jti1, "jti каждый раз новый");
        }

        printf("-- /refresh\n");
        {
            Resp r1 = Http("POST", "/refresh", "{\"refresh_token\":" + Eac::Json::Quote(p.refresh) + "}", "10.0.0.1");
            Pair p2 = ParsePair(r1);
            std::string j2;
            Check(p2.ok && CheckJwt(pk, kid1, p2.access, "777", j2), "/refresh → 200, новый JWT sub=777");
            Check(p2.refresh != p.refresh, "новый refresh_token отличается");
            Resp r2 = Http("POST", "/refresh", "{\"refresh_token\":" + Eac::Json::Quote(p.refresh) + "}", "10.0.0.1");
            Check(r2.code == 401 && r2.body == "{\"error\":\"invalid_grant\"}", "старый refresh погашен → 401 invalid_grant");
            Pair p3 = ParsePair(Http("POST", "/refresh", "{\"refresh_token\":" + Eac::Json::Quote(p2.refresh) + "}", "10.0.0.1"));
            Check(p3.ok, "новый refresh работает (цепочка)");
            Resp r4 = Http("POST", "/refresh", "{\"refresh_token\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", "10.0.0.1");
            Check(r4.code == 401, "неизвестный refresh → 401");
            Resp r5 = Http("POST", "/refresh", "{\"refresh_token\":\"short\"}", "10.0.0.1");
            Check(r5.code == 400, "негодный формат refresh → 400");
        }

        printf("-- 401 без различия причин\n");
        {
            Resp a = Http("POST", "/token", TokenBody("stand_ok", "00000000000000000000000000000000"), "10.0.0.4");
            Resp b = Http("POST", "/token", TokenBody("nobody_here", kMd5), "10.0.0.4");
            Resp c = Http("POST", "/token", TokenBody("stand_blocked", kMd5), "10.0.0.4");
            Check(a.code == 401 && a.body == "{\"error\":\"invalid_grant\"}", "неверный пароль → 401 invalid_grant");
            Check(b.code == 401 && b.body == a.body, "неизвестный логин → тот же 401");
            Check(c.code == 401 && c.body == a.body, "заблокированная учётка → тот же 401");
            Check(srv.WaitLog("login=stand_blocked → 401 (UPEacAuth статус 5", 2000), "журнал различает причину (статус 5), ответ — нет");
            Resp d = Http("POST", "/token", TokenBody("stand_dberror", kMd5), "10.0.0.4");
            Check(d.code == 503, "ошибка БД → 503 temporarily_unavailable (не 401)");
        }

        printf("-- 400 / 404 / 405 (строгая схема)\n");
        {
            const char* ip = "10.0.0.5";
            struct Bad { std::string body; std::string ct; const char* what; };
            std::vector<Bad> bads = {
                { "{\"login\":\"stand_ok\"}", "application/json", "нет password_md5" },
                { TokenBody("stand_ok", kMd5).insert(1, "\"x\":1,"), "application/json", "лишнее поле" },
                { "{\"login\":\"stand_ok\",\"login\":\"stand_ok\",\"password_md5\":\"7787e2c49efec303a6d311a19d31b8b5\"}", "application/json", "повтор ключа" },
                { "{\"login\":1,\"password_md5\":\"7787e2c49efec303a6d311a19d31b8b5\"}", "application/json", "login не строка" },
                { TokenBody("stand_ok", "7787e2c49efec303a6d311a19d31b8b"), "application/json", "MD5 31 символ" },
                { TokenBody("stand_ok", "7787e2c49efec303a6d311a19d31b8bz"), "application/json", "MD5 не hex" },
                { TokenBody("stand ok", kMd5), "application/json", "пробел внутри логина" },
                { TokenBody("\xd0\xb8\xd0\xb3\xd1\x80\xd0\xbe\xd0\xba", kMd5), "application/json", "кириллица в логине" },
                { TokenBody("stand_ok", kMd5) + ",", "application/json", "мусор после JSON" },
                { TokenBody("stand_ok", kMd5), "text/plain", "Content-Type не JSON" },
            };
            int okc = 0;
            for (auto& b : bads)
            {
                Resp r = Http("POST", "/token", b.body, ip, b.ct);
                bool ok = r.code == 400 && r.body == "{\"error\":\"invalid_request\"}";
                if (!ok) printf("    %s → %d %s\n", b.what, r.code, r.body.c_str());
                okc += ok;
                ip = (okc % 2) ? "10.0.0.6" : "10.0.0.5";   // не упереться в лимит IP
            }
            Check(okc == (int)bads.size(), "10 видов негодного /token → 400 invalid_request");
            Resp big = Http("POST", "/token", std::string(5000, 'x'), "10.0.0.7");
            Check(big.code == 400, "тело > 4096 → 400");
            Resp ch = Http("POST", "/token", "", "10.0.0.7", "application/json", "Transfer-Encoding: chunked\r\n");
            Check(ch.code == 400, "Transfer-Encoding: chunked → 400");
            Check(Http("GET", "/token", "", "10.0.0.7", "").code == 405, "GET /token → 405");
            Check(Http("POST", "/.well-known/jwks.json", "{}", "10.0.0.7").code == 405, "POST jwks → 405");
            Check(Http("GET", "/nope", "", "10.0.0.7", "").code == 404, "неизвестный путь → 404");
        }

        printf("-- GET /status (лаунчер: пинг и статус, 17.10.2026)\n");
        {
            Resp st = Http("GET", "/status", "", "10.0.0.7", "");
            Check(st.code == 200 && st.body == "{\"online\":false,\"login\":true,\"game\":false}",
                  "GET /status → 200 {online:false, login:true (порт стенда слушает), game:false (порт закрыт)}");
            Check(st.raw.find("Cache-Control: no-store") != std::string::npos, "/status не кэшируется у клиента (no-store)");
            Resp st2 = Http("GET", "/status", "", "10.0.0.8", "");
            Check(st2.code == 200 && st2.body == st.body, "повторный GET /status (из кэша) — тот же ответ");
            Check(Http("POST", "/status", "{}", "10.0.0.7").code == 405, "POST /status → 405");
        }

        printf("-- лимит 10 /token в минуту с IP\n");
        {
            int ok10 = 0;
            for (int i = 0; i < 10; ++i) ok10 += Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.0.20").code == 200;
            Resp r11 = Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.0.20");
            Check(ok10 == 10, "10 запросов с одного IP → 200");
            Check(r11.code == 429 && r11.body == "{\"error\":\"rate_limited\"}", "11-й → 429 rate_limited");
            Check(Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.0.21").code == 200, "другой IP не ограничен");
            Resp nx = Http("POST", "/token", TokenBody("stand_ok", kMd5), "garbage-not-ip");
            Check(nx.code == 200 || nx.code == 429, "негодный X-Forwarded-For → берётся адрес сокета (127.0.0.1)");
        }

        printf("-- E1-06: чужие неудачи не блокируют владельца; пауза пары (логин, IP); общая пауза логина по ступеням (стенд: 3/6/12 с)\n");
        {
            const std::string bad = "00000000000000000000000000000000";
            int c401 = 0;
            for (int i = 0; i < 5; ++i) c401 += Http("POST", "/token", TokenBody("stand_op", bad), "10.0.1." + std::to_string(i + 1)).code == 401;
            Check(c401 == 5, "5 неверных паролей stand_op с 5 разных IP → 401");
            Pair own = ParsePair(Http("POST", "/token", TokenBody("stand_op", kMd5), "10.0.1.9"));
            std::string j; Check(own.ok && CheckJwt(pk, kid1, own.access, "778", j), "владелец с верным паролем со своего IP → 200 (было: 429 на 60 с — E1-06)");
            int p401 = 0;
            for (int i = 0; i < 5; ++i) p401 += Http("POST", "/token", TokenBody("stand_op", bad), "10.0.2.1").code == 401;
            Check(p401 == 5, "5 неверных с одного IP (10.0.2.1) → 401");
            Check(srv.WaitLog("неудача №5 логина, №5 пары с последнего успеха", 1000), "§8.6 R3-07: журнал считает каждую неудачу (№5 логина и пары после успеха)");
            Check(Http("POST", "/token", TokenBody("stand_op", kMd5), "10.0.2.1").code == 429, "пауза ПАРЫ: 6-я с того же IP даже с верным паролем → 429");
            Check(srv.WaitLog("login=stand_op → 429 (пауза пары логин+IP", 1000), "журнал: пауза пары");
            Check(Http("POST", "/token", TokenBody("stand_op", kMd5), "10.0.2.2").code == 200, "с другого IP тот же логин → 200 (пауза пары не общая)");
            int g401 = 0;
            for (int i = 0; i < 10; ++i) g401 += Http("POST", "/token", TokenBody("stand_op", bad), "10.0.3." + std::to_string(i + 1)).code == 401;
            Check(g401 == 10, "10 неверных с 10 IP → 401");
            Check(srv.WaitLog("неудача №10 логина, №1 пары с последнего успеха", 1000), "§8.6 R3-07: сквозной номер неудачи логина — 10 (с 10 разных IP)");
            Check(srv.WaitLog("общая пауза логина 3 с", 1000), "журнал: общая пауза логина (ступень 1: 3 с)");
            Check(Http("POST", "/token", TokenBody("stand_op", kMd5), "10.0.3.20").code == 429, "общая пауза: новый IP с верным паролем → 429");
            Check(Http("POST", "/token", TokenBody("stand_op", kMd5), "10.0.1.9").code == 200, "общая пауза НЕ касается IP прежнего успешного входа (10.0.1.9) → 200, счёт сброшен");
            for (int i = 0; i < 10; ++i) Http("POST", "/token", TokenBody("stand_op", bad), "10.0.4." + std::to_string(i + 1));
            Sleep(3300);
            for (int i = 0; i < 10; ++i) Http("POST", "/token", TokenBody("stand_op", bad), "10.0.5." + std::to_string(i + 1));
            Check(srv.WaitLog("общая пауза логина 6 с", 1000), "без успеха пауза растёт: вторая ступень 6 с");
            Pair q = ParsePair(Http("POST", "/token", TokenBody("STAND_OP", kMd5), "10.0.1.9"));
            Check(q.ok && CheckJwt(pk, kid1, q.access, "778", j), "свой IP входит и во время паузы (ключ — логин без регистра)");
            Check(srv.WaitLog("UPEacAuthFail login=stand_op → статус 0 (засчитана в us_pwfail)", 3000), "неудача пароля записана в us_pwfail (UPEacAuthFail, отложенно)");
            Check(!srv.LogHas("UPEacAuthFail login=nobody_here") && !srv.LogHas("UPEacAuthFail login=stand_blocked"),
                  "UPEacAuthFail не зовётся для неизвестного логина (2) и блока (5) — только для неверного пароля (3)");
        }

        printf("-- E1-05: статика .well-known для Caddy; медленные клиенты не занимают нити\n");
        {
            std::string jw, oc;
            FILE* f = _wfopen((dir + L"www\\.well-known\\jwks.json").c_str(), L"rb");
            if (f) { char b[8192]; size_t n = fread(b, 1, sizeof(b), f); jw.assign(b, n); fclose(f); }
            f = _wfopen((dir + L"www\\.well-known\\openid-configuration").c_str(), L"rb");
            if (f) { char b[8192]; size_t n = fread(b, 1, sizeof(b), f); oc.assign(b, n); fclose(f); }
            Check(!jw.empty() && jw == Http("GET", "/.well-known/jwks.json", "", "", "").body, "www\\.well-known\\jwks.json записан и совпадает с ответом GET");
            Check(!oc.empty() && oc == Http("GET", "/.well-known/openid-configuration", "", "", "").body, "www\\.well-known\\openid-configuration записан и совпадает");
            std::vector<SOCKET> slow;
            for (int i = 0; i < 16; ++i) { SOCKET s = Connect(g_port, 5000); if (s != INVALID_SOCKET) { SendAll(s, "P", 1); slow.push_back(s); } }
            std::atomic<bool> stop{ false };
            std::thread drip([&] { for (int k = 0; k < 8 && !stop; ++k) { for (SOCKET s : slow) send(s, "O", 1, 0); Sleep(500); } });
            int64_t t0 = NowMs();
            Resp jr = Http("GET", "/.well-known/jwks.json", "", "", "");
            int64_t dj = NowMs() - t0;
            t0 = NowMs();
            Resp tr = Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.6.1");
            int64_t dt = NowMs() - t0;
            Check(slow.size() == 16, "16 медленных соединений по байту раз в 0,5 с (было: 4 таких клиента вешали AsdaId на 24+ с)");
            Check(jr.code == 200 && dj < 1000, "JWKS при медленных клиентах — " + std::to_string(dj) + " мс");
            Check(tr.code == 200 && dt < 1000, "/token при медленных клиентах — " + std::to_string(dt) + " мс");
            int closed = 0; int64_t end = NowMs() + 4000;
            for (SOCKET s : slow)
            {
                int left = (int)(end - NowMs()); if (left < 1) left = 1;
                uint8_t b[64]; int n = RecvSome(s, b, sizeof(b), left);
                closed += (n == 0 || n == -2);
            }
            stop = true; drip.join();
            for (SOCKET s : slow) closesocket(s);
            Check(closed == 16, "медленные закрыты сервером по сроку запроса (RequestDeadlineSec=2): " + std::to_string(closed) + "/16");
            Check(srv.WaitLog("закрыто по сроку запроса (2 с) 16", 11000), "журнал: сводка закрытых по сроку (раз в 10 с, не строка на каждое)");
        }

        // refresh, который должен пережить перезапуск (E1-10)
        { Pair kp = ParsePair(Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.0.7.1")); keepRefresh = kp.refresh; Check(kp.ok, "refresh для проверки перезапуска получен"); }

        printf("-- журнал без секретов\n");
        {
            std::string log = srv.Log();
            Check(log.find(kMd5) == std::string::npos && log.find("7787E2C4") == std::string::npos, "MD5 пароля в журнал не попал");
            Check(log.find(p.access) == std::string::npos && log.find(p.refresh) == std::string::npos, "токены целиком в журнал не попали");
        }
        bool graceful = srv.Stop();
        printf("  (останов: %s)\n", graceful ? "штатный, Ctrl+Break" : "TerminateProcess — у стенда нет консоли");
        if (graceful) Check(srv.LogHas("AsdaEacServer остановлен"), "штатный останов записан в журнал");
    }

    printf("-- ключ JWT сохраняется между запусками\n");
    {
        Server srv2;
        if (Check(srv2.Start(dir, ini, L"--no-eos --fake-auth", g_port), "повторный запуск"))
        {
            Eac::Crypto::RsaKey pk2; std::string kid2;
            Check(LoadJwks(pk2, kid2) && kid2 == kid1, "kid тот же — ключ загружен из файла, не создан заново");
            Check(!srv2.LogHas("создан НОВЫЙ ключ JWT") || srv2.Log().find("создан НОВЫЙ ключ JWT") == srv2.Log().rfind("создан НОВЫЙ ключ JWT"),
                  "второй раз ключ не создавался");
            // E1-10: refresh пережил перезапуск службы.
            Pair rp = ParsePair(Http("POST", "/refresh", "{\"refresh_token\":" + Eac::Json::Quote(keepRefresh) + "}", "10.0.7.1"));
            Check(!keepRefresh.empty() && rp.ok, "E1-10: refresh, выданный до перезапуска, принят после (хранилище на диске)");
            Check(srv2.WaitLog("refresh: загружено", 1000), "журнал: refresh загружены из secrets\\refresh.dat");
            std::string raw;
            FILE* f = _wfopen((dir + L"secrets\\refresh.dat").c_str(), L"rb");
            if (f) { char b[65536]; size_t n = fread(b, 1, sizeof(b), f); raw.assign(b, n); fclose(f); }
            Check(raw.size() > 100 && raw.find("stand_ok") == std::string::npos && raw.find("ASDARF01") == std::string::npos,
                  "refresh.dat зашифрован DPAPI (нет открытого логина и заголовка формата)");
            srv2.Stop();
        }
    }
    printf("-- E1-10 / E1-19: продление refresh при использовании, абсолютный предел, перепроверка учётки (RefreshTtlSec=8, Absolute=12, Recheck=1; время Unix — с точностью до секунды; ★ ревизия 68: запас ≥ 2 с на каждой границе)\n");
    {
        std::wstring d2 = RunDir("asdaid_ttl");
        AsdaSecure::PublicKey pub2; MakeSecureKey(d2, pub2);
        std::wstring ini2 = WriteIni(d2, g_port, 25701, 25702, { {"AsdaId.RefreshTtlSec", "8"}, {"AsdaId.RefreshAbsoluteSec", "12"}, {"AsdaId.StatusRecheckSec", "1"},
                                                                 {"AsdaId.WwwDir", U8(d2) + "www"}, {"AsdaId.TokenPerIpPerMin", "100"}, {"General.Mode", "1"} });
        Server srv;
        if (Check(srv.Start(d2, ini2, L"--no-eos --fake-auth", g_port), "сервер (короткие сроки refresh)"))
        {
            auto refresh = [&](const std::string& rt) { return Http("POST", "/refresh", "{\"refresh_token\":" + Eac::Json::Quote(rt) + "}", "10.1.0.1"); };
            auto token = [&]() { return ParsePair(Http("POST", "/token", TokenBody("stand_ok", kMd5), "10.1.0.1")); };
            Pair p = token();
            Sleep(2000); Pair p2 = ParsePair(refresh(p.refresh));
            Sleep(2000); Pair p3 = ParsePair(refresh(p2.refresh));
            Check(p.ok && p2.ok && p3.ok, "refresh через 2 с, 4 с (каждый раз — новый срок 8 с от использования) → 200");
            Sleep(2000); Pair p4 = ParsePair(refresh(p3.refresh));
            Sleep(2000); Pair p5 = ParsePair(refresh(p4.refresh));
            Sleep(2000); Pair p6 = ParsePair(refresh(p5.refresh));
            Check(p4.ok && p5.ok && p6.ok, "через 6, 8 и 10 с от /token (10 с > RefreshTtlSec=8) — 200: срок продлевается использованием");
            Sleep(4000); Resp r6 = refresh(p6.refresh);
            Check(r6.code == 401, "через 14 с от /token (абсолютный предел 12 с) → 401 — нужен вход паролем");
            Pair q = token(); Sleep(10500);
            Check(refresh(q.refresh).code == 401, "без использования дольше RefreshTtlSec → 401");
            Pair b = token();
            FILE* f = _wfopen((d2 + L"fake_block_777").c_str(), L"wb"); if (f) fclose(f);
            Sleep(1100);
            Check(refresh(b.refresh).code == 401 && srv.WaitLog("→ 401 (UPEacAuthStatus статус 5)", 1000), "E1-19: учётку заблокировали после входа → /refresh 401 (перепроверка UPEacAuthStatus)");
            DeleteFileW((d2 + L"fake_block_777").c_str());
            Pair c = token();
            f = _wfopen((d2 + L"fake_pwtag_777").c_str(), L"wb"); if (f) { fputs("1111111111111111", f); fclose(f); }
            Sleep(1100);
            Check(refresh(c.refresh).code == 401 && srv.WaitLog("→ 401 (пароль сменён после входа)", 1000), "E1-19: пароль сменён после входа → /refresh 401");
            DeleteFileW((d2 + L"fake_pwtag_777").c_str());
            Pair e = token();
            f = _wfopen((d2 + L"fake_dberror").c_str(), L"wb"); if (f) fclose(f);
            Sleep(1100);
            Check(ParsePair(refresh(e.refresh)).ok && srv.WaitLog("проверка отложена до следующего /refresh", 1000), "E1-19: БД недоступна при перепроверке → 200, проверка отложена");
            DeleteFileW((d2 + L"fake_dberror").c_str());
            srv.Stop();
        }
    }
    return Summary("stand_asdaid");
}
