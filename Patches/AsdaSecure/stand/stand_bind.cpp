// Copyright (c) 2026 @sitxovski (Discord)
// stand_bind.cpp — стенд экспортёра привязки канала AsdaSecure (EAC ред. 3, 16.10.2026; контракт
//   Reports/anticheat/eac/CONTRACT.md §8.1). Цепочка доказательства:
//   1) CNG-эталон (своя реализация HKDF в стенде) == НЕЗАВИСИМЫЙ Python-вектор tools/gen_bind_vector.py (bind и ключи);
//   2) Session (сервер и клиент) == CNG-эталон на живых рукопожатиях: bind совпадает, а ключи направлений — те же, что
//      по прежней формуле (кадр, запечатанный эталонным ключом, открывается Session и наоборот);
//   3) каналы: у клиента и сервера одного соединения bind одинаков, у разных соединений — разный; Legacy/Unknown/до
//      рукопожатия/после Reset → false, выходной буфер при false не трогается.
//   Сборка с /DSTAND_NO_BIND — только проверки ключей (п. 1 и ключевая часть п. 2) против ПРЕЖНЕГО AsdaSecure.cpp:
//   так доказывается, что ключи направлений у старого и нового кода одинаковы (формула не изменилась).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include "AsdaSecure.h"
#ifndef STAND_NO_BIND
#include "AsdaServerBridge.h"   // AsdaWire::SlotChannelBinding — источник bind для P73 (через P61)
#endif

#pragma comment(lib, "bcrypt.lib")

using namespace AsdaSecure;

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

static int g_fail = 0;   // число проваленных проверок
static int g_ok = 0;     // число пройденных проверок
// Проверка с печатью итога (строки [OK] / [FAIL] считает раннер регресса).
static void CHECK(bool cond, const char* what)
{
    if (cond) { ++g_ok; printf("  [OK] %s\n", what); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what); }
}

// Тестовый вектор (генерируется tools/gen_bind_vector.py → bind_test_vector.inc).
struct Vec
{
    int     sub;            // под-сервер (2 Game, 3 Indun)
    uint8_t dC[32];         // закрытый скаляр эфемерного ключа клиента
    uint8_t pubC[64];       // открытый X||Y клиента
    uint8_t dS[32];         // закрытый скаляр эфемерного ключа сервера
    uint8_t pubS[64];       // открытый X||Y сервера
    uint8_t nonceC[16];     // nonce клиента
    uint8_t nonceS[16];     // nonce сервера
    uint8_t okm[88];        // ключи направлений c2sKey|c2sIv|s2cKey|s2cIv
    uint8_t bind[32];       // привязка канала
};
static const Vec kVec[] = {
#include "bind_test_vector.inc"
};

static BCRYPT_ALG_HANDLE g_ecdh = nullptr;   // ECDH P-256 стенда
static BCRYPT_ALG_HANDLE g_hmac = nullptr;   // HMAC-SHA256 стенда
static BCRYPT_ALG_HANDLE g_aes  = nullptr;   // AES-GCM стенда

// Открыть провайдеры CNG стенда (независимо от AsdaSecure::Init).
static bool OpenCng()
{
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_ecdh, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0))) return false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_hmac, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_aes, BCRYPT_AES_ALGORITHM, nullptr, 0))) return false;
    return NT_SUCCESS(BCryptSetProperty(g_aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
}

// HMAC-SHA256 эталона.
static bool RefHmac(const uint8_t* key, size_t kl, const uint8_t* msg, size_t ml, uint8_t out[32])
{
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!NT_SUCCESS(BCryptCreateHash(g_hmac, &h, nullptr, 0, (PUCHAR)key, (ULONG)kl, 0))) return false;
    bool ok = NT_SUCCESS(BCryptHashData(h, (PUCHAR)msg, (ULONG)ml, 0)) && NT_SUCCESS(BCryptFinishHash(h, out, 32, 0));
    BCryptDestroyHash(h);
    return ok;
}

// HKDF-Expand эталона (RFC 5869).
static bool RefExpand(const uint8_t prk[32], const uint8_t* info, size_t il, uint8_t* out, size_t n)
{
    std::vector<uint8_t> buf; uint8_t t[32]; size_t tl = 0, done = 0; uint8_t c = 1;
    while (done < n)
    {
        buf.assign(t, t + tl); buf.insert(buf.end(), info, info + il); buf.push_back(c);
        if (!RefHmac(prk, 32, buf.data(), buf.size(), t)) return false;
        tl = 32; size_t take = (n - done < 32) ? n - done : 32;
        memcpy(out + done, t, take); done += take; ++c;
    }
    return true;
}

// Эталонный вывод по контракту §8.1: okm (88) и bind (32) из приветствий и сырого X (big-endian).
static bool RefDerive(const uint8_t* ch, const uint8_t* sh, const uint8_t raw[32], uint8_t okm[88], uint8_t bind[32])
{
    uint8_t salt[32]; memcpy(salt, ch + 4 + 64, 16); memcpy(salt + 16, sh + 4 + 64, 16);
    uint8_t info[3 + 128 + 16];
    info[0] = 1; info[1] = ch[2]; info[2] = sh[2];
    memcpy(info + 3, ch + 4, 64); memcpy(info + 67, sh + 4, 64);
    static const uint8_t kKeys[16] = { 'A','s','d','a','S','e','c','u','r','e','/','v','1',0,0,0 };   // метка ключей
    static const uint8_t kBind[16] = { 'A','s','d','a','E','a','c','B','i','n','d','/','v','1',0,0 }; // метка привязки
    memcpy(info + 131, kKeys, 16);
    uint8_t prk[32];
    if (!RefHmac(salt, 32, raw, 32, prk)) return false;
    if (!RefExpand(prk, info, sizeof(info), okm, 88)) return false;
    memcpy(info + 131, kBind, 16);
    return RefExpand(prk, info, sizeof(info), bind, 32);
}

// Импорт закрытого эфемерного ECDH-ключа (d + X||Y).
static BCRYPT_KEY_HANDLE ImportPriv(const uint8_t d[32], const uint8_t xy[64])
{
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 96];
    BCRYPT_ECCKEY_BLOB* h = (BCRYPT_ECCKEY_BLOB*)blob; h->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC; h->cbKey = 32;
    memcpy(blob + sizeof(*h), xy, 64); memcpy(blob + sizeof(*h) + 64, d, 32);
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!NT_SUCCESS(BCryptImportKeyPair(g_ecdh, nullptr, BCRYPT_ECCPRIVATE_BLOB, &k, blob, sizeof(blob), 0))) return nullptr;
    return k;
}

// Сырой общий X (big-endian) между своим закрытым и чужим открытым.
static bool RawX(BCRYPT_KEY_HANDLE priv, const uint8_t peer[64], uint8_t out[32])
{
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB* h = (BCRYPT_ECCKEY_BLOB*)blob; h->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; h->cbKey = 32;
    memcpy(blob + sizeof(*h), peer, 64);
    BCRYPT_KEY_HANDLE pk = nullptr; BCRYPT_SECRET_HANDLE sec = nullptr;
    if (!NT_SUCCESS(BCryptImportKeyPair(g_ecdh, nullptr, BCRYPT_ECCPUBLIC_BLOB, &pk, blob, sizeof(blob), 0))) return false;
    NTSTATUS s = BCryptSecretAgreement(priv, pk, &sec, 0);
    BCryptDestroyKey(pk);
    if (!NT_SUCCESS(s)) return false;
    ULONG cb = 0;
    s = BCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET, nullptr, out, 32, &cb, 0);
    BCryptDestroySecret(sec);
    if (!NT_SUCCESS(s) || cb != 32) return false;
    for (int i = 0; i < 16; ++i) { uint8_t t = out[i]; out[i] = out[31 - i]; out[31 - i] = t; }   // LE → BE
    return true;
}

// Эталонный AES-GCM кадр формата Session::Seal: [u32 clen][u64 seq][ct][tag], AAD = clen||seq, IV = base XOR BE(seq).
static bool RefSeal(const uint8_t key[32], const uint8_t ivb[12], uint64_t seq, const std::vector<uint8_t>& plain,
                    std::vector<uint8_t>& frame)
{
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_aes, &k, nullptr, 0, (PUCHAR)key, 32, 0))) return false;
    uint8_t iv[12]; memcpy(iv, ivb, 12); for (int i = 0; i < 8; ++i) iv[11 - i] ^= (uint8_t)(seq >> (8 * i));
    uint32_t clen = (uint32_t)(plain.size() + 16);
    frame.assign(12 + plain.size() + 16, 0);
    memcpy(frame.data(), &clen, 4); memcpy(frame.data() + 4, &seq, 8);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = iv; ai.cbNonce = 12; ai.pbTag = frame.data() + 12 + plain.size(); ai.cbTag = 16;
    ai.pbAuthData = frame.data(); ai.cbAuthData = 12;
    ULONG done = 0;
    NTSTATUS s = BCryptEncrypt(k, (PUCHAR)plain.data(), (ULONG)plain.size(), &ai, nullptr, 0, frame.data() + 12, (ULONG)plain.size(), &done, 0);
    BCryptDestroyKey(k);
    return NT_SUCCESS(s);
}

// Эталонное вскрытие кадра Session::Seal.
static bool RefOpen(const uint8_t key[32], const uint8_t ivb[12], const std::vector<uint8_t>& frame, std::vector<uint8_t>& plain)
{
    if (frame.size() < 28) return false;
    uint32_t clen; uint64_t seq; memcpy(&clen, frame.data(), 4); memcpy(&seq, frame.data() + 4, 8);
    if (frame.size() != 12 + (size_t)clen) return false;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(g_aes, &k, nullptr, 0, (PUCHAR)key, 32, 0))) return false;
    uint8_t iv[12]; memcpy(iv, ivb, 12); for (int i = 0; i < 8; ++i) iv[11 - i] ^= (uint8_t)(seq >> (8 * i));
    size_t pl = clen - 16; plain.assign(pl, 0);
    uint8_t aad[12]; memcpy(aad, frame.data(), 12);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = iv; ai.cbNonce = 12; ai.pbTag = (PUCHAR)frame.data() + 12 + pl; ai.cbTag = 16; ai.pbAuthData = aad; ai.cbAuthData = 12;
    ULONG done = 0;
    NTSTATUS s = BCryptDecrypt(k, (PUCHAR)frame.data() + 12, (ULONG)pl, &ai, nullptr, 0, plain.data(), (ULONG)pl, &done, 0);
    BCryptDestroyKey(k);
    return NT_SUCCESS(s);
}

#ifndef STAND_NO_BIND
// «Сокет» моста в п. 4: стоковый Send слота кладёт байты сюда (ServerHello / шифротекст).
static std::vector<uint8_t> g_bridgeOut[AsdaWire::kMaxSlots];
// SendRawFn моста: 1 — принято (как стоковый Ciocp::Send).
static int BridgeSendRaw(void*, int slot, const void* data, int len)
{
    g_bridgeOut[slot].insert(g_bridgeOut[slot].end(), (const uint8_t*)data, (const uint8_t*)data + len);
    return 1;
}
#endif

// Hex-строка для печати.
static void Hex(const char* name, const uint8_t* p, size_t n)
{
    printf("    %s = ", name); for (size_t i = 0; i < n; ++i) printf("%02x", p[i]); printf("\n");
}

// Проверка, что ключи Session совпадают с эталонными okm в обе стороны (isClient — сторона Session).
static void CheckKeys(Session& s, const uint8_t okm[88], bool isClient, const char* tag)
{
    const uint8_t* c2sKey = okm; const uint8_t* c2sIv = okm + 32; const uint8_t* s2cKey = okm + 44; const uint8_t* s2cIv = okm + 76;
    char msg[160];
    for (int i = 0; i < 3; ++i)
    {
        // Входящее направление Session: эталон шифрует его ключом, Session открывает.
        std::vector<uint8_t> plain(37 + i * 100, (uint8_t)(0x40 + i)), frame, got;
        bool sealed = isClient ? RefSeal(s2cKey, s2cIv, s.RecvSeq() + 1, plain, frame) : RefSeal(c2sKey, c2sIv, s.RecvSeq() + 1, plain, frame);
        s.Feed(frame.data(), frame.size());
        bool opened = sealed && s.Next(got) && got == plain;
        snprintf(msg, sizeof msg, "%s: кадр эталона (ключ %s, seq %d) открыт Session — входящий ключ по прежней формуле", tag,
                 isClient ? "s2c" : "c2s", i + 1);
        CHECK(opened, msg);
        // Исходящее направление Session: Session запечатывает, эталон открывает.
        std::vector<uint8_t> out; got.clear();
        bool ok = s.Seal(plain.data(), plain.size(), out) == Err::Ok &&
                  (isClient ? RefOpen(c2sKey, c2sIv, out, got) : RefOpen(s2cKey, s2cIv, out, got)) && got == plain;
        snprintf(msg, sizeof msg, "%s: кадр Session (seq %d) открыт эталоном (ключ %s) — исходящий ключ по прежней формуле", tag, i + 1,
                 isClient ? "c2s" : "s2c");
        CHECK(ok, msg);
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== stand_bind: привязка канала AsdaSecure (EAC ред. 3, CONTRACT.md §8.1)%s ===\n",
#ifdef STAND_NO_BIND
           " — РЕЖИМ ПРЕЖНЕГО КОДА (только ключи)"
#else
           ""
#endif
    );
    if (!Init() || !OpenCng()) { printf("CNG недоступен\n"); return 1; }
    PrivateKey srvPriv; CHECK(GenerateLongTermKey(srvPriv), "долговременная пара сервера");
    PublicKey srvPub; memcpy(srvPub.xy, srvPriv.xy, kPubLen);

    // ── 1. CNG-эталон == независимый Python-вектор ──────────────────────────────────────────
    printf("-- 1. эталон стенда == вектор gen_bind_vector.py --\n");
    for (const Vec& v : kVec)
    {
        uint8_t ch[kClientHelloLen], sh[kServerHelloLen] = {0};
        ch[0] = kClientMagic; ch[1] = kVersion; ch[2] = (uint8_t)v.sub; ch[3] = 0;
        memcpy(ch + 4, v.pubC, 64); memcpy(ch + 68, v.nonceC, 16);
        sh[0] = kServerMagic; sh[1] = kVersion; sh[2] = (uint8_t)v.sub; sh[3] = 0;
        memcpy(sh + 4, v.pubS, 64); memcpy(sh + 68, v.nonceS, 16);
        BCRYPT_KEY_HANDLE kc = ImportPriv(v.dC, v.pubC), ks = ImportPriv(v.dS, v.pubS);
        CHECK(kc && ks, "импорт фиксированных эфемерных ключей вектора");
        uint8_t rawC[32] = {0}, rawS[32] = {0};
        CHECK(kc && RawX(kc, v.pubS, rawC) && ks && RawX(ks, v.pubC, rawS) && memcmp(rawC, rawS, 32) == 0, "ECDH: X одинаков у обеих сторон");
        uint8_t okm[88], bind[32];
        CHECK(RefDerive(ch, sh, rawC, okm, bind), "эталонный вывод");
        CHECK(memcmp(okm, v.okm, 88) == 0, v.sub == 2 ? "game: ключи направлений == вектор" : "indun: ключи направлений == вектор");
        CHECK(memcmp(bind, v.bind, 32) == 0, v.sub == 2 ? "game: bind == вектор" : "indun: bind == вектор");
        Hex("bind", bind, 32);
        if (kc) BCryptDestroyKey(kc);
        if (ks) BCryptDestroyKey(ks);
    }

    // ── 2а. Session-СЕРВЕР против эталона: клиентская сторона — фиксированный ключ вектора ───
    printf("-- 2а. Session::ServerAccept против эталона --\n");
    const SubServer subs[] = { SubServer::Login, SubServer::Game, SubServer::Indun, SubServer::Eac };
    for (SubServer sub : subs)
    {
        const Vec& v = kVec[0];
        uint8_t ch[kClientHelloLen];
        ch[0] = kClientMagic; ch[1] = kVersion; ch[2] = (uint8_t)sub; ch[3] = 0;
        memcpy(ch + 4, v.pubC, 64); memcpy(ch + 68, v.nonceC, 16);
        Session S; uint8_t sh[kServerHelloLen];
        CHECK(S.ServerAccept(ch, sizeof ch, sub, srvPriv, sh) == Err::Ok, "ServerAccept");
        uint8_t signed_[129]; memcpy(signed_, ch + 4, 64); memcpy(signed_ + 64, sh + 4, 64); signed_[128] = (uint8_t)sub;
        CHECK(VerifyData(srvPub, signed_, sizeof signed_, sh + 84), "подпись ServerHello прежняя (ePubC||ePubS||sub)");
        BCRYPT_KEY_HANDLE kc = ImportPriv(v.dC, v.pubC);
        uint8_t raw[32] = {0}, okm[88], bind[32];
        CHECK(kc && RawX(kc, sh + 4, raw) && RefDerive(ch, sh, raw, okm, bind), "эталон по ServerHello");
        if (kc) BCryptDestroyKey(kc);
#ifndef STAND_NO_BIND
        uint8_t b[32];
        CHECK(S.ChannelBinding(b) && memcmp(b, bind, 32) == 0, "Session(сервер).ChannelBinding == эталон");
#endif
        CheckKeys(S, okm, false, "сервер");
    }

    // ── 2б. Session-КЛИЕНТ против эталона: серверная сторона — фиксированный ключ вектора ────
    printf("-- 2б. Session::ClientHello/ClientFinish против эталона --\n");
    for (SubServer sub : subs)
    {
        const Vec& v = kVec[1];
        Session C; uint8_t ch[kClientHelloLen];
        CHECK(C.ClientHello(sub, srvPub, ch), "ClientHello");
        uint8_t sh[kServerHelloLen] = {0};
        sh[0] = kServerMagic; sh[1] = kVersion; sh[2] = (uint8_t)sub; sh[3] = 0;
        memcpy(sh + 4, v.pubS, 64); memcpy(sh + 68, v.nonceS, 16);
#ifndef STAND_NO_BIND
        uint8_t pre[32]; memset(pre, 0xEE, 32);
        bool f = C.ChannelBinding(pre); bool untouched = true; for (uint8_t x : pre) untouched &= (x == 0xEE);
        CHECK(!f && untouched, "Session до ClientFinish: ChannelBinding = false, буфер не тронут");
#endif
        CHECK(C.ClientFinish(sh, sizeof sh) == Err::Ok, "ClientFinish");
        BCRYPT_KEY_HANDLE ks = ImportPriv(v.dS, v.pubS);
        uint8_t raw[32] = {0}, okm[88], bind[32];
        CHECK(ks && RawX(ks, ch + 4, raw) && RefDerive(ch, sh, raw, okm, bind), "эталон по ClientHello");
        if (ks) BCryptDestroyKey(ks);
#ifndef STAND_NO_BIND
        uint8_t b[32];
        CHECK(C.ChannelBinding(b) && memcmp(b, bind, 32) == 0, "Session(клиент).ChannelBinding == эталон");
        CHECK(memcmp(b, okm, 32) != 0 && memcmp(b, okm + 44, 32) != 0, "bind не совпадает с ключами направлений");
#endif
        CheckKeys(C, okm, true, "клиент");
#ifndef STAND_NO_BIND
        C.Reset();
        CHECK(!C.ChannelBinding(b), "после Reset: false");
#endif
    }

#ifndef STAND_NO_BIND
    // ── 3. Каналы: одно соединение — один bind у обеих сторон, разные соединения — разные ──────
    printf("-- 3. ServerChannel/ClientChannel --\n");
    std::vector<std::vector<uint8_t>> seen;
    int sameSide = 0, total = 0;
    for (SubServer sub : subs)
        for (int n = 0; n < 8; ++n)
        {
            ServerChannel srv; srv.SetIdentity(sub, &srvPriv); srv.SetAllowLegacy(true); srv.Reset();
            ClientChannel cli; cli.Reset();
            std::vector<uint8_t> c2s, s2c, toP;
            uint8_t b1[32], b2[32];
            bool pre = srv.ChannelBinding(b1) || cli.ChannelBinding(b2);
            cli.Start(sub, srvPub, c2s);
            // ClientHello по частям: после первой части сервер в Secure, но рукопожатия нет.
            srv.OnRecv(c2s.data(), 10, toP, s2c);
            bool mid = srv.ChannelBinding(b1) || cli.ChannelBinding(b2);
            srv.OnRecv(c2s.data() + 10, c2s.size() - 10, toP, s2c);
            bool srvOnly = srv.ChannelBinding(b1) && !cli.ChannelBinding(b2);   // сервер готов, клиент ещё нет
            Err e = cli.OnRecv(s2c.data(), s2c.size(), toP);
            bool both = e == Err::Ok && srv.ChannelBinding(b1) && cli.ChannelBinding(b2);
            ++total;
            if (!pre && !mid && srvOnly && both && memcmp(b1, b2, 32) == 0) ++sameSide;
            seen.emplace_back(b1, b1 + 32);
            if (n == 0)
            {
                CHECK(!pre, "до рукопожатия: false у обеих сторон");
                CHECK(!mid, "ClientHello принят частично: false");
                CHECK(srvOnly, "сервер готов раньше клиента: у сервера true, у клиента false");
                CHECK(both && memcmp(b1, b2, 32) == 0, "одно соединение: bind клиента == bind сервера");
                cli.SetLegacy(true);
                CHECK(!cli.ChannelBinding(b2), "ClientChannel::SetLegacy(true): false");
                srv.Reset();
                CHECK(!srv.ChannelBinding(b1), "ServerChannel после Reset: false");
            }
        }
    {
        char m[120]; snprintf(m, sizeof m, "%d соединений: у каждого bind клиента == bind сервера (%d/%d)", total, sameSide, total);
        CHECK(sameSide == total, m);
        int dup = 0;
        for (size_t i = 0; i < seen.size(); ++i) for (size_t j = i + 1; j < seen.size(); ++j) dup += (seen[i] == seen[j]);
        snprintf(m, sizeof m, "разные соединения — разные bind (совпадений %d из %zu пар)", dup, seen.size() * (seen.size() - 1) / 2);
        CHECK(dup == 0, m);
    }
    // Повторное рукопожатие того же объекта (переподключение слота) — новый bind.
    {
        ServerChannel srv; srv.SetIdentity(SubServer::Game, &srvPriv);
        uint8_t prev[32] = {0}, cur[32]; bool differ = true, eq = true;
        for (int r = 0; r < 3; ++r)
        {
            srv.Reset(); ClientChannel cli; std::vector<uint8_t> c2s, s2c, toP;
            cli.Start(SubServer::Game, srvPub, c2s); srv.OnRecv(c2s.data(), c2s.size(), toP, s2c); cli.OnRecv(s2c.data(), s2c.size(), toP);
            uint8_t cb[32];
            eq &= srv.ChannelBinding(cur) && cli.ChannelBinding(cb) && memcmp(cur, cb, 32) == 0;
            if (r) differ &= memcmp(prev, cur, 32) != 0;
            memcpy(prev, cur, 32);
        }
        CHECK(eq && differ, "переподключение того же слота (Reset + рукопожатие): bind новый, у сторон одинаков");
    }
    // Legacy: старый кадр 0xFB → режим Legacy → привязки нет.
    {
        ServerChannel srv; srv.SetIdentity(SubServer::Game, &srvPriv); srv.SetAllowLegacy(true); srv.Reset();
        const uint8_t legacy[] = { 0xFB, 0x0A, 0x00, 0x01, 0x02, 0xA1, 0x0F, 0x00, 0x00, 0xFE };
        std::vector<uint8_t> toP, toS; uint8_t b[32]; memset(b, 0xEE, 32);
        Err e = srv.OnRecv(legacy, sizeof legacy, toP, toS);
        bool untouched = true; bool r = srv.ChannelBinding(b); for (uint8_t x : b) untouched &= (x == 0xEE);
        CHECK(e == Err::Ok && srv.GetMode() == Mode::Legacy && !r && untouched, "ServerChannel Legacy (0xFB): false, буфер не тронут");
        ClientChannel cli; cli.SetLegacy(true); cli.Reset();
        CHECK(!cli.ChannelBinding(b), "ClientChannel Legacy: false");
    }
    // Ошибка рукопожатия (подмена ключа сервера) — клиент привязки не получает.
    {
        PrivateKey other; GenerateLongTermKey(other);
        ServerChannel srv; srv.SetIdentity(SubServer::Game, &other); srv.Reset();
        ClientChannel cli; std::vector<uint8_t> c2s, s2c, toP; uint8_t b[32];
        cli.Start(SubServer::Game, srvPub, c2s); srv.OnRecv(c2s.data(), c2s.size(), toP, s2c);
        Err e = cli.OnRecv(s2c.data(), s2c.size(), toP);
        CHECK(e == Err::BadSignature && !cli.ChannelBinding(b), "BadSignature: у клиента false");
    }

    // ── 4. Мост сервера (AsdaWire, как в DLL P61): SlotChannelBinding слота == bind клиента ────────────────────────────
    printf("-- 4. AsdaWire::SlotChannelBinding (мост P61) --\n");
    {
        wchar_t keyPath[MAX_PATH];
        { wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp); _snwprintf_s(keyPath, MAX_PATH, _TRUNCATE, L"%sstand_bind_%lu.key", tmp, GetCurrentProcessId()); }
        CHECK(SavePrivateKeyFile(keyPath, srvPriv), "ключ сервера во временный файл");
        uint8_t b[32]; memset(b, 0xEE, 32);
        CHECK(!AsdaWire::SlotChannelBinding(5, b), "мост не инициализирован (P61 выключен): false");
        CHECK(AsdaWire::Init(SubServer::Game, keyPath, /*allowLegacy=*/true, &BridgeSendRaw), "AsdaWire::Init (Game, Legacy разрешён)");
        const int SEC = 5, LEG = 6, HALF = 7;
        AsdaWire::ResetSlot(SEC); AsdaWire::ResetSlot(LEG); AsdaWire::ResetSlot(HALF);
        CHECK(!AsdaWire::SlotChannelBinding(SEC, b), "слот после accept (Unknown): false");
        ClientChannel cli; std::vector<uint8_t> c2s, toP; const uint8_t* o = nullptr;
        cli.Start(SubServer::Game, srvPub, c2s);
        g_bridgeOut[SEC].clear();
        AsdaWire::RecvRoute(nullptr, SEC, c2s.data(), (int)c2s.size(), &o);
        CHECK(g_bridgeOut[SEC].size() == kServerHelloLen, "мост выдал ServerHello");
        Err e = cli.OnRecv(g_bridgeOut[SEC].data(), g_bridgeOut[SEC].size(), toP);
        uint8_t cb[32];
        CHECK(e == Err::Ok && cli.ChannelBinding(cb) && AsdaWire::SlotChannelBinding(SEC, b) && memcmp(b, cb, 32) == 0,
              "Secure-слот: SlotChannelBinding == bind клиента");
        CHECK(!AsdaWire::SlotChannelBinding(-1, b) && !AsdaWire::SlotChannelBinding(AsdaWire::kMaxSlots, b), "слот вне диапазона: false");
        // Старый клиент — Legacy.
        const uint8_t legacy[] = { 0xFB, 0x0A, 0x00, 0x01, 0x02, 0xA1, 0x0F, 0x00, 0x00, 0xFE };
        AsdaWire::RecvRoute(nullptr, LEG, legacy, sizeof legacy, &o);
        CHECK(AsdaWire::SlotMode(LEG) == 2 && !AsdaWire::SlotChannelBinding(LEG, b), "Legacy-слот: false");
        // Половина ClientHello — рукопожатия нет.
        ClientChannel c2; std::vector<uint8_t> h2; c2.Start(SubServer::Game, srvPub, h2);
        AsdaWire::RecvRoute(nullptr, HALF, h2.data(), 40, &o);
        CHECK(AsdaWire::SlotMode(HALF) == 1 && !AsdaWire::SlotChannelBinding(HALF, b), "ClientHello не весь: false");
        // Разрыв (SetConnectFlag 0) — отложенный сброс применяется в SlotChannelBinding.
        AsdaWire::ResetSlot(SEC, 0);
        CHECK(!AsdaWire::SlotChannelBinding(SEC, b), "после разрыва слота: false");
        // Новое соединение на том же слоте — новый bind.
        AsdaWire::ResetSlot(SEC);
        ClientChannel c3; std::vector<uint8_t> h3; c3.Start(SubServer::Game, srvPub, h3);
        g_bridgeOut[SEC].clear();
        AsdaWire::RecvRoute(nullptr, SEC, h3.data(), (int)h3.size(), &o);
        uint8_t cb3[32], b3[32];
        CHECK(c3.OnRecv(g_bridgeOut[SEC].data(), g_bridgeOut[SEC].size(), toP) == Err::Ok && c3.ChannelBinding(cb3) &&
              AsdaWire::SlotChannelBinding(SEC, b3) && memcmp(b3, cb3, 32) == 0 && memcmp(b3, cb, 32) != 0,
              "переподключение слота: новый bind, равен клиентскому");
        DeleteFileW(keyPath);
    }
#endif

    printf("== ИТОГ stand_bind: пройдено %d, провалов %d ==\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
