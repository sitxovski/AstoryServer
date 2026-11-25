# Copyright (c) 2026 @sitxovski (Discord)
# asdaid_probe_r3.py — копия стенда ревизора eac/review_e1/asdaid_probe.py (agent-eac-review), адаптированная под ред. 3
# (agent-eac-server-fix, 16.10.2026): сценарии дефектов E1-05 и E1-06 теперь ожидают ИСПРАВЛЕННОЕ поведение.
# Исходник ревизора не меняется. Запуск: python -I asdaid_probe_r3.py (после build.bat test — нужен ключ out/stand/run/asdaid/secure_server.key).
# Запускает AsdaEacServer_stand.exe --fake-auth --no-eos на 127.0.0.1:18644 и проверяет: JWKS/OIDC, JWT RS256 независимой
# реализацией (cryptography), /refresh гасит старый, 401/429/503/400, лимиты, блокировку учётки чужими неудачами, медленных
# клиентов (slowloris), разбор Content-Length, секреты в журнале.
import base64, hashlib, json, os, shutil, signal, socket, subprocess, sys, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "..", "out", "stand"))
RUN = os.path.join(OUT, "run", "asdaid_probe_r3")
EXE = os.path.join(OUT, "AsdaEacServer_stand.exe")
PORT, SIDE, BR = 18644, 25901, 25902
ok = bad = 0


def check(c, what):
    """Проверка с выводом."""
    global ok, bad
    print("  [%s] %s" % (" OK " if c else "FAIL", what))
    if c:
        ok += 1
    else:
        bad += 1


def b64d(s):
    """base64url без дополнения → байты."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def http(method, path, body=None, headers=None, raw=None, timeout=10):
    """Один HTTP/1.1-запрос; возвращает (код, тело-строка). raw — отправить байты как есть."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    if raw is None:
        b = body.encode() if isinstance(body, str) else (body or b"")
        h = {"Host": "x", "Content-Length": str(len(b))}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        raw = ("%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n").encode() + b
    s.sendall(raw)
    data = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    except socket.timeout:
        pass
    s.close()
    if not data:
        return None, ""
    head, _, rest = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), rest.decode("utf-8", "replace")


def token(login, md5hex, ip):
    """POST /token от имени IP (X-Forwarded-For принимается только с 127.0.0.1 — как за Caddy)."""
    return http("POST", "/token", json.dumps({"login": login, "password_md5": md5hex}), {"X-Forwarded-For": ip})


# ── запуск сервера ──
if os.path.isdir(RUN):
    shutil.rmtree(RUN)
os.makedirs(os.path.join(RUN, "secrets"))
shutil.copy(os.path.join(OUT, "run", "asdaid", "secure_server.key"), os.path.join(RUN, "secure_server.key"))
ini = f"""[General]
Mode=2
FailOpen=1
LogDir={RUN}\\logs
LogLevel=3
[Secrets]
EosJson={RUN}\\secrets\\eos.json
JwtKey={RUN}\\secrets\\jwt_rs256.key
SqlPasswordFile={RUN}\\secrets\\sql.txt
SecureKeyFile={RUN}\\secure_server.key
[Sidecar]
Bind=127.0.0.1
Port={SIDE}
[AsdaId]
Port={PORT}
TokenPerIpPerMin=10
LoginFailMax=5
LoginFailPauseSec=60
TrustForwardedFor=1
Workers=4
IoTimeoutSec=10
RequestDeadlineSec=5
RefreshFile={RUN}\\secrets\\refresh.dat
WwwDir={RUN}\\www
[Bridge]
Port={BR}
AllowedImageDirs={RUN}
"""
open(os.path.join(RUN, "EacServer.ini"), "w", encoding="utf-8").write(ini)
srv = subprocess.Popen([EXE, "--console", "--no-eos", "--fake-auth", "--config", os.path.join(RUN, "EacServer.ini")], cwd=RUN,
                       stdout=open(os.path.join(RUN, "stdout.txt"), "wb"), stderr=subprocess.STDOUT,
                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
        break
    except OSError:
        time.sleep(0.1)

try:
    PW = hashlib.md5(b"stand-pass").hexdigest()
    print("== JWKS / OIDC ==")
    c, b = http("GET", "/.well-known/jwks.json")
    jw = json.loads(b)
    k = jw["keys"][0]
    check(c == 200 and set(k) == {"kty", "use", "alg", "kid", "n", "e"} and k["kty"] == "RSA" and k["use"] == "sig" and k["alg"] == "RS256"
          and k["e"] == "AQAB", "JWKS: поля и значения по контракту §2")
    n = int.from_bytes(b64d(k["n"]), "big")
    check(n.bit_length() == 2048 and b64d(k["n"])[0] != 0, "JWKS: n — 2048 бит, без ведущего нуля (каноничный base64url)")
    kid_expect = base64.urlsafe_b64encode(hashlib.sha256(b64d(k["n"]) + b64d(k["e"])).digest()).decode().rstrip("=")[:16]
    check(k["kid"] == kid_expect, "JWKS: kid = base64url(SHA-256(n||e))[0..16] (%s)" % k["kid"])
    c, b = http("GET", "/.well-known/openid-configuration")
    check(c == 200 and b == '{"issuer":"https://@@ASTORY_AUTH_HOST@@","jwks_uri":"https://@@ASTORY_AUTH_HOST@@/.well-known/jwks.json",'
          '"id_token_signing_alg_values_supported":["RS256"]}', "OIDC: тело байт в байт по контракту")
    pub = rsa.RSAPublicNumbers(int.from_bytes(b64d(k["e"]), "big"), n).public_key()

    print("== /token → JWT, независимая проверка ==")
    t0 = int(time.time())
    c, b = token("stand_ok", PW, "10.0.0.1")
    j = json.loads(b) if c == 200 else {}
    check(c == 200 and set(j) == {"access_token", "token_type", "expires_in", "refresh_token"} and j["token_type"] == "Bearer"
          and j["expires_in"] == 3600, "/token 200: поля ответа по контракту")
    h64, c64, s64 = j["access_token"].split(".")
    hdr, cl = json.loads(b64d(h64)), json.loads(b64d(c64))
    try:
        pub.verify(b64d(s64), (h64 + "." + c64).encode(), padding.PKCS1v15(), hashes.SHA256())
        sig_ok = True
    except Exception:
        sig_ok = False
    check(sig_ok, "подпись RS256 сходится по JWKS (cryptography, PKCS#1 v1.5 + SHA-256)")
    check(hdr == {"alg": "RS256", "typ": "JWT", "kid": k["kid"]}, "заголовок JWT = {alg,typ,kid} (%s)" % hdr)
    check(set(cl) == {"iss", "aud", "sub", "iat", "nbf", "exp", "jti"} and cl["iss"] == "https://@@ASTORY_AUTH_HOST@@" and cl["aud"] == "astory-eac"
          and cl["sub"] == "777" and cl["nbf"] == cl["iat"] and cl["exp"] == cl["iat"] + 3600 and abs(cl["iat"] - t0) <= 5 and len(cl["jti"]) >= 16,
          "claims: iss/aud/sub=777 (строка)/iat/nbf=iat/exp=iat+3600/jti (%s)" % cl)
    rt = j["refresh_token"]
    check(len(rt) == 43 and all(ch.isalnum() or ch in "-_" for ch in rt), "refresh_token: 43 символа base64url")

    print("== /refresh ==")
    c, b = http("POST", "/refresh", json.dumps({"refresh_token": rt}))
    j2 = json.loads(b) if c == 200 else {}
    check(c == 200 and j2.get("refresh_token") not in (None, rt), "/refresh 200: новая пара, новый refresh")
    c, b = http("POST", "/refresh", json.dumps({"refresh_token": rt}))
    check(c == 401 and b == '{"error":"invalid_grant"}', "старый refresh повторно → 401 invalid_grant")
    c, b = http("POST", "/refresh", json.dumps({"refresh_token": j2["refresh_token"]}))
    check(c == 200, "новый refresh работает (цепочка ротации)")

    print("== отказы ==")
    c, b = token("stand_ok", "0" * 32, "10.0.0.2")
    check(c == 401 and b == '{"error":"invalid_grant"}', "неверный пароль → 401")
    c, b = token("stand_blocked", PW, "10.0.0.2")
    check(c == 401 and b == '{"error":"invalid_grant"}', "заблокированная учётка → 401 (без различия)")
    c, b = token("stand_dberror", PW, "10.0.0.2")
    check(c == 503 and b == '{"error":"temporarily_unavailable"}', "ошибка БД → 503 temporarily_unavailable")
    for desc, raw in [
        ("Content-Length с '+'", b"POST /token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: +5\r\n\r\n{\"a\"}"),
        ("Content-Length отрицательный", b"POST /token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: -1\r\n\r\n"),
        ("два Content-Length", b"POST /token HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"),
        ("Transfer-Encoding: chunked", b"POST /token HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("лишние байты после тела (конвейер)", b"POST /token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}GET / HTTP/1.1\r\n\r\n"),
        ("заголовки > 8 КиБ", b"GET /.well-known/jwks.json HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n"),
        ("тело 4097 б", b"POST /token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 4097\r\n\r\n"),
        ("лишнее поле JSON", None),
    ]:
        if raw is None:
            c, b = http("POST", "/token", '{"login":"stand_ok","password_md5":"%s","x":"1"}' % PW, {"X-Forwarded-For": "10.0.0.3"})
        else:
            c, b = http(None, None, raw=raw)
        check(c == 400, "%s → 400 (получено %s)" % (desc, c))

    print("== лимиты ==")
    codes = [token("stand_ok", PW, "10.9.9.9")[0] for _ in range(11)]
    check(codes[:10] == [200] * 10 and codes[10] == 429, "10 /token с IP за минуту → 11-й 429 (%s)" % codes)
    # Блокировка учётки чужими неудачами: 5 неверных паролей с РАЗНЫХ IP, затем верный пароль владельца с его IP
    for i in range(5):
        token("stand_op", "f" * 32, "203.0.113.%d" % (i + 1))
    c, b = token("stand_op", PW, "198.51.100.7")
    check(c == 200, "E1-06 ИСПРАВЛЕН: 5 чужих неудач (5 разных IP) → владелец с верным паролем и своего IP получает 200 (%s)" % c)

    print("== медленные клиенты ==")
    slow = []
    for i in range(4):
        s = socket.create_connection(("127.0.0.1", PORT))
        s.sendall(b"GET /.well-known/jwks.json HTTP/1.1\r\n")
        slow.append(s)
    t = time.time()
    c = None
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=25)
        s.sendall(b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: x\r\n\r\n")
        # поддерживать медленных: по байту каждые 4 с (меньше IoTimeoutSec=10 на один recv)
        got = b""
        s.settimeout(1)
        while time.time() - t < 24 and not got:
            for q in slow:
                try:
                    q.sendall(b"X")
                except OSError:
                    pass
            try:
                got = s.recv(100)
            except socket.timeout:
                time.sleep(3)
        waited = time.time() - t
        check(got.startswith(b"HTTP/1.1 200") and waited < 2, "E1-05 ИСПРАВЛЕН: при 4 медленных соединениях (по байту раз в ~4 с) законный GET JWKS "
                                                            "отвечен за %.2f с" % waited)
        closed = 0
        for q in slow:
            q.settimeout(7)
            try:
                closed += q.recv(10) == b""
            except OSError:
                closed += 1
        check(closed == 4, "E1-05: медленные закрыты сервером по общему сроку запроса 5 с (%d/4)" % closed)
    finally:
        for q in slow:
            q.close()
    time.sleep(1)
    c, b = http("GET", "/.well-known/jwks.json")
    check(c == 200, "после закрытия медленных — сервис снова отвечает")

    print("== секреты в журнале ==")
    logtxt = ""
    for f in os.listdir(os.path.join(RUN, "logs")):
        logtxt += open(os.path.join(RUN, "logs", f), encoding="utf-8", errors="replace").read()
    check(PW not in logtxt and "f" * 32 not in logtxt, "MD5 пароля в журнал не попал")
    check(rt not in logtxt and j2["refresh_token"] not in logtxt and j["access_token"] not in logtxt and "eyJ" not in logtxt,
          "access/refresh токены в журнал не попали (только префиксы sha256)")
finally:
    try:
        srv.send_signal(signal.CTRL_BREAK_EVENT)
        srv.wait(8)
    except Exception:
        srv.kill()
print("\n=== asdaid_probe: пройдено %d, провалено %d ===" % (ok, bad))
sys.exit(1 if bad else 0)
