// Copyright (c) 2026 @sitxovski (Discord)
// AsdaSecure.cpp — реализация криптопрослойки на Windows CNG (bcrypt.dll). См. AsdaSecure.h.
//
// Соответствие решениям владельца:
//   • ECDH P-256 эфемерный на подключение (BCRYPT_ECDH_P256_ALGORITHM, BCryptSecretAgreement);
//   • ECDSA P-256 долговременный (BCRYPT_ECDSA_P256_ALGORITHM) — подпись сервера от посредника;
//   • HKDF-SHA256 (RFC 5869) над общим секретом → ключи c2s/s2c и базовые IV (вручную на HMAC-SHA256,
//     т.к. BCRYPT_HKDF_ALGORITHM есть не во всех сборках Windows — чтобы DLL шла и на старой ОС сервера);
//   • AES-256-GCM (BCRYPT_AES_ALGORITHM + BCRYPT_CHAIN_MODE_GCM), IV = ivBase XOR seq, seq растёт, anti-replay.
//
// Никаких OpenSSL/libsodium. Сборка /MT, только bcrypt.lib + ntdll (NTSTATUS).
// ★ sec2 (15.10.2026): ускорение рукопожатия сервера — общий провайдер SHA-256, кэш импортированного ключа подписи
//   (ServerSignerLoad: дескрипторы по одному на нить в момент подписи), пул одноразовых эфемерных пар ECDH в фоновой нити
//   (EphemeralPoolStart; пуст — генерация на месте). Протокол и формат приветствий не менялись.
#include "AsdaSecure.h"
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace AsdaSecure
{
    // ── Общие провайдеры (открываются один раз) ───────────────────────────────────────────
    namespace
    {
        BCRYPT_ALG_HANDLE g_hEcdh   = nullptr;   // ECDH P-256 (эфемерные ключи)
        BCRYPT_ALG_HANDLE g_hEcdsa  = nullptr;   // ECDSA P-256 (долговременные ключи)
        BCRYPT_ALG_HANDLE g_hAes    = nullptr;   // AES, режим GCM
        BCRYPT_ALG_HANDLE g_hSha256 = nullptr;   // HMAC-SHA256 (для HKDF)
        BCRYPT_ALG_HANDLE g_hRng    = nullptr;   // системный RNG
        BCRYPT_ALG_HANDLE g_hHash   = nullptr;   // ★ sec2: SHA-256 без HMAC (хэш под подпись) — раньше открывался на каждую подпись
        volatile long     g_status  = 0;         // последний NTSTATUS-отказ
        volatile long     g_inited  = 0;         // 0 — не инициализировано, 1 — ок (InterlockedCompareExchange)

        inline void SetStatus(NTSTATUS s) { g_status = (long)s; }

        // «ASDAKEY1» — метка файла закрытого ключа.
        const uint8_t kKeyFileTag[8] = { 'A','S','D','A','K','E','Y','1' };

        // Собрать публичный BLOB CNG (BCRYPT_ECCPUBLIC_BLOB) из сырых X||Y для импорта.
        //   magic(4) cbKey(4) X(32) Y(32). magic зависит от алгоритма (ECDH vs ECDSA).
        bool MakePublicBlob(ULONG magic, const uint8_t xy[kPubLen], uint8_t out[8 + kPubLen])
        {
            ULONG cb = 32;
            memcpy(out + 0, &magic, 4);
            memcpy(out + 4, &cb, 4);
            memcpy(out + 8, xy, kPubLen);
            return true;
        }
        // Собрать приватный BLOB CNG (BCRYPT_ECCPRIVATE_BLOB): magic(4) cbKey(4) X(32) Y(32) d(32).
        bool MakePrivateBlob(ULONG magic, const PrivateKey& key, uint8_t out[8 + kPubLen + kPrivLen])
        {
            ULONG cb = 32;
            memcpy(out + 0, &magic, 4);
            memcpy(out + 4, &cb, 4);
            memcpy(out + 8, key.xy, kPubLen);
            memcpy(out + 8 + kPubLen, key.d, kPrivLen);
            return true;
        }

        // HMAC-SHA256(key,msg) → mac[32].
        bool HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t mac[32])
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            NTSTATUS s = BCryptCreateHash(g_hSha256, &h, nullptr, 0, (PUCHAR)key, (ULONG)keyLen, 0);
            if (!NT_SUCCESS(s)) { SetStatus(s); return false; }
            bool ok = NT_SUCCESS(s = BCryptHashData(h, (PUCHAR)msg, (ULONG)msgLen, 0))
                   && NT_SUCCESS(s = BCryptFinishHash(h, mac, 32, 0));
            if (!ok) SetStatus(s);
            BCryptDestroyHash(h);
            return ok;
        }

        // HKDF-SHA256 (RFC 5869): extract(salt, ikm) → prk; expand(prk, info, L) → okm.
        bool HkdfExtract(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen, uint8_t prk[32])
        {
            uint8_t zero[32] = {0};
            if (!salt || saltLen == 0) { salt = zero; saltLen = 32; }
            return HmacSha256(salt, saltLen, ikm, ikmLen, prk);
        }
        bool HkdfExpand(const uint8_t prk[32], const uint8_t* info, size_t infoLen, uint8_t* okm, size_t okmLen)
        {
            uint8_t t[32]; size_t tLen = 0; uint8_t counter = 1; size_t done = 0;
            while (done < okmLen)
            {
                // T(n) = HMAC(prk, T(n-1) | info | counter)
                uint8_t buf[32 + 256 + 1];
                if (infoLen > 256) return false;
                size_t off = 0;
                memcpy(buf + off, t, tLen); off += tLen;
                memcpy(buf + off, info, infoLen); off += infoLen;
                buf[off++] = counter;
                if (!HmacSha256(prk, 32, buf, off, t)) return false;
                tLen = 32;
                size_t take = (okmLen - done < 32) ? (okmLen - done) : 32;
                memcpy(okm + done, t, take);
                done += take; ++counter;
            }
            return true;
        }
    }

    const char* ErrName(Err e)
    {
        switch (e)
        {
        case Err::Ok:           return "Ok";
        case Err::Arg:          return "Arg";
        case Err::Cng:          return "Cng";
        case Err::BadMagic:     return "BadMagic";
        case Err::BadVersion:   return "BadVersion";
        case Err::BadSubServer: return "BadSubServer";
        case Err::BadSignature: return "BadSignature";
        case Err::BadTag:       return "BadTag";
        case Err::Replay:       return "Replay";
        case Err::Format:       return "Format";
        case Err::State:        return "State";
        case Err::Legacy:       return "Legacy";
        }
        return "?";
    }

    long LastStatus() { return g_status; }
    void Wipe(void* p, size_t n) { if (p && n) SecureZeroMemory(p, n); }

    bool Init()
    {
        if (g_inited) return true;
        NTSTATUS s;
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hEcdh,   BCRYPT_ECDH_P256_ALGORITHM,  nullptr, 0))) { SetStatus(s); return false; }
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hEcdsa,  BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) { SetStatus(s); return false; }
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hAes,    BCRYPT_AES_ALGORITHM,        nullptr, 0))) { SetStatus(s); return false; }
        if (!NT_SUCCESS(s = BCryptSetProperty(g_hAes, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))             { SetStatus(s); return false; }
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hSha256, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) { SetStatus(s); return false; }
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hRng,    BCRYPT_RNG_ALGORITHM,        nullptr, 0))) { SetStatus(s); return false; }
        // ★ sec2: SHA-256 для подписи/проверки — один провайдер на процесс (сбой — Sha256 откроет временный, как раньше).
        if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&g_hHash,   BCRYPT_SHA256_ALGORITHM,     nullptr, 0))) { g_hHash = nullptr; }
        InterlockedExchange(&g_inited, 1);
        return true;
    }

    // ── ★ sec2: SHA-256, кэш ключа подписи, пул эфемерных пар ECDH (см. AsdaSecure.h) ─────────────────────────────────
    namespace
    {
        // SHA-256(data) → out[32]. Провайдер — общий (дескриптор алгоритма CNG допускает одновременное создание хэшей
        //   из разных нитей; так же общий g_hSha256 у HKDF). Нет общего — временный (прежнее поведение).
        bool Sha256(const uint8_t* data, size_t len, uint8_t out[32])
        {
            BCRYPT_ALG_HANDLE a = g_hHash; bool own = false; NTSTATUS s;
            if (!a)
            {
                if (!NT_SUCCESS(s = BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) { SetStatus(s); return false; }
                own = true;
            }
            BCRYPT_HASH_HANDLE h = nullptr;
            bool ok = NT_SUCCESS(s = BCryptCreateHash(a, &h, nullptr, 0, nullptr, 0, 0))
                   && NT_SUCCESS(s = BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0))
                   && NT_SUCCESS(s = BCryptFinishHash(h, out, 32, 0));
            if (h) BCryptDestroyHash(h);
            if (own) BCryptCloseAlgorithmProvider(a, 0);
            if (!ok) SetStatus(s);
            return ok;
        }

        // Импорт закрытого ECDSA-ключа в CNG (blob затирается).
        bool ImportSigner(const PrivateKey& key, BCRYPT_KEY_HANDLE* out)
        {
            uint8_t blob[8 + kPubLen + kPrivLen]; MakePrivateBlob(BCRYPT_ECDSA_PRIVATE_P256_MAGIC, key, blob);
            NTSTATUS s = BCryptImportKeyPair(g_hEcdsa, nullptr, BCRYPT_ECCPRIVATE_BLOB, out, blob, sizeof(blob), 0);
            Wipe(blob, sizeof(blob));
            if (!NT_SUCCESS(s)) { SetStatus(s); *out = nullptr; return false; }
            return true;
        }

        // Кэш ключа подписи: копия ключа (только память процесса) + дескрипторы. Состояние дескриптора: 0 пусто, 1 занят
        //   (импорт или подпись — у ОДНОЙ нити), 2 свободен. Захват — CAS 2→1 (или 0→1 с импортом), отдача — 1→2.
        PrivateKey        g_signerKey{};
        volatile LONG     g_signerReady = 0;
        BCRYPT_KEY_HANDLE g_signerH[kSignerHandles] = {};
        volatile LONG     g_signerSt[kSignerHandles] = {};
        volatile LONG     g_stSignCached = 0, g_stSignImport = 0, g_stSignHandles = 0;

        bool SameKey(const PrivateKey& a, const PrivateKey& b)
        {
            return memcmp(a.xy, b.xy, kPubLen) == 0 && memcmp(a.d, b.d, kPrivLen) == 0;
        }

        int AcquireSigner(const PrivateKey& key)
        {
            if (!g_signerReady || !SameKey(key, g_signerKey)) { return -1; }
            for (int i = 0; i < kSignerHandles; ++i)
            {
                if (g_signerSt[i] == 2 && InterlockedCompareExchange(&g_signerSt[i], 1, 2) == 2) { return i; }
            }
            for (int i = 0; i < kSignerHandles; ++i)
            {
                if (g_signerSt[i] == 0 && InterlockedCompareExchange(&g_signerSt[i], 1, 0) == 0)
                {
                    if (ImportSigner(g_signerKey, &g_signerH[i])) { InterlockedIncrement(&g_stSignHandles); return i; }
                    InterlockedExchange(&g_signerSt[i], 0);
                    return -1;
                }
            }
            return -1;                                   // все дескрипторы заняты — временный импорт
        }
        void ReleaseSigner(int i) { InterlockedExchange(&g_signerSt[i], 2); }

        // Пул эфемерных пар ECDH. Запись пула — дескриптор CNG + открытый ключ (для ServerHello). Замок — SRW (статический,
        //   без инициализации); под замком только перенос записей, генерация — вне замка.
        struct EphKey { BCRYPT_KEY_HANDLE h; uint8_t pub[kPubLen]; DWORD tick; };
        constexpr DWORD kEphMaxAgeMs = 10 * 60 * 1000;   // заготовка старше 10 мин не выдаётся (уничтожается) — пары не залёживаются
        SRWLOCK        g_poolLk = SRWLOCK_INIT;
        EphKey         g_pool[kEphPoolMax] = {};
        int            g_poolCount = 0;                  // под g_poolLk
        volatile LONG  g_poolTarget = 0;
        volatile LONG  g_poolStop = 0;
        HANDLE         g_poolEv = nullptr;               // авто-сброс: «пара взята / размер изменён / стоп»
        HANDLE         g_poolTh = nullptr;
        volatile LONG  g_poolThState = 0;                // 0 нет нити, 1 создаётся, 2 есть
        volatile LONG  g_stEphPool = 0, g_stEphInline = 0, g_stEphMade = 0, g_stEphDestroyed = 0;

        // Сгенерировать пару ECDH P-256 и экспортировать открытую часть.
        bool GenEph(BCRYPT_KEY_HANDLE* h, uint8_t pub[kPubLen])
        {
            *h = nullptr;
            NTSTATUS s;
            if (!NT_SUCCESS(s = BCryptGenerateKeyPair(g_hEcdh, h, 256, 0)) ||
                !NT_SUCCESS(s = BCryptFinalizeKeyPair(*h, 0))) { SetStatus(s); if (*h) { BCryptDestroyKey(*h); *h = nullptr; } return false; }
            uint8_t blob[8 + kPubLen]; ULONG cb = 0;
            if (!NT_SUCCESS(s = BCryptExportKey(*h, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &cb, 0)) || cb != sizeof(blob))
            {
                SetStatus(s); BCryptDestroyKey(*h); *h = nullptr; return false;
            }
            memcpy(pub, blob + 8, kPubLen);
            return true;
        }

        DWORD WINAPI EphPoolThread(LPVOID)
        {
            while (!g_poolStop)
            {
                AcquireSRWLockShared(&g_poolLk);
                const bool need = g_poolCount < (int)g_poolTarget;
                ReleaseSRWLockShared(&g_poolLk);
                if (need)
                {
                    EphKey e{};
                    if (!GenEph(&e.h, e.pub)) { WaitForSingleObject(g_poolEv, 200); continue; }   // CNG отказал — пауза
                    e.tick = GetTickCount();
                    bool kept = false;
                    AcquireSRWLockExclusive(&g_poolLk);
                    if (!g_poolStop && g_poolCount < (int)g_poolTarget) { g_pool[g_poolCount++] = e; kept = true; }
                    ReleaseSRWLockExclusive(&g_poolLk);
                    if (kept) { InterlockedIncrement(&g_stEphMade); }
                    else { BCryptDestroyKey(e.h); Wipe(e.pub, kPubLen); InterlockedIncrement(&g_stEphDestroyed); }
                    continue;
                }
                // Пул полон: самая старая заготовка (g_pool[0] — LIFO выдаёт с конца) старше половины срока — уничтожить, её место
                //   займёт свежая (пары не залёживаются и при простое сервера).
                AcquireSRWLockExclusive(&g_poolLk);
                if (g_poolCount > 0 && (DWORD)(GetTickCount() - g_pool[0].tick) > kEphMaxAgeMs / 2)
                {
                    BCryptDestroyKey(g_pool[0].h); InterlockedIncrement(&g_stEphDestroyed);
                    for (int i = 1; i < g_poolCount; ++i) { g_pool[i - 1] = g_pool[i]; }
                    --g_poolCount;
                    g_pool[g_poolCount].h = nullptr; Wipe(g_pool[g_poolCount].pub, kPubLen); g_pool[g_poolCount].tick = 0;
                    ReleaseSRWLockExclusive(&g_poolLk);
                    continue;
                }
                ReleaseSRWLockExclusive(&g_poolLk);
                WaitForSingleObject(g_poolEv, 1000);
            }
            return 0;
        }

        // Забрать пару из пула (одноразово: запись пула обнуляется и затирается). false — пул пуст / выключен.
        bool TakeEph(BCRYPT_KEY_HANDLE* h, uint8_t pub[kPubLen])
        {
            if (!g_poolTarget) { return false; }
            bool ok = false;
            AcquireSRWLockExclusive(&g_poolLk);
            const DWORD now = GetTickCount();                                            // под замком: tick записей не «из будущего»
            while (!ok && g_poolCount > 0)
            {
                EphKey& e = g_pool[--g_poolCount];
                if ((DWORD)(now - e.tick) > kEphMaxAgeMs)
                {
                    BCryptDestroyKey(e.h); InterlockedIncrement(&g_stEphDestroyed);   // залежалась — не выдаём
                }
                else
                {
                    *h = e.h; memcpy(pub, e.pub, kPubLen);
                    ok = true;
                }
                e.h = nullptr; Wipe(e.pub, kPubLen); e.tick = 0;
            }
            ReleaseSRWLockExclusive(&g_poolLk);
            if (g_poolEv) { SetEvent(g_poolEv); }                                       // пополнить
            if (ok) { InterlockedIncrement(&g_stEphPool); }
            return ok;
        }
    }

    bool ServerSignerLoad(const PrivateKey& key)
    {
        if (!Init()) { return false; }
        ServerSignerClear();
        g_signerKey = key;
        // Первый дескриптор — сразу (проверка, что ключ импортируется); остальные — по мере одновременных рукопожатий.
        if (!ImportSigner(g_signerKey, &g_signerH[0])) { Wipe(&g_signerKey, sizeof(g_signerKey)); return false; }
        InterlockedIncrement(&g_stSignHandles);
        InterlockedExchange(&g_signerSt[0], 2);
        InterlockedExchange(&g_signerReady, 1);
        return true;
    }

    void ServerSignerClear()
    {
        InterlockedExchange(&g_signerReady, 0);
        for (int i = 0; i < kSignerHandles; ++i)
        {
            if (InterlockedCompareExchange(&g_signerSt[i], 1, 2) == 2)
            {
                if (g_signerH[i]) { BCryptDestroyKey(g_signerH[i]); g_signerH[i] = nullptr; }
                InterlockedExchange(&g_signerSt[i], 0);
            }
        }
        Wipe(&g_signerKey, sizeof(g_signerKey));
    }

    bool EphemeralPoolStart(int size)
    {
        if (size < 0) { size = 0; }
        if (size > kEphPoolMax) { size = kEphPoolMax; }
        if (size > 0 && !Init()) { return false; }
        InterlockedExchange(&g_poolTarget, size);
        if (size == 0) { if (g_poolEv) { SetEvent(g_poolEv); } return true; }
        if (InterlockedCompareExchange(&g_poolThState, 1, 0) == 0)
        {
            InterlockedExchange(&g_poolStop, 0);
            if (!g_poolEv) { g_poolEv = CreateEventW(nullptr, FALSE, FALSE, nullptr); }
            HANDLE th = g_poolEv ? CreateThread(nullptr, 0, &EphPoolThread, nullptr, CREATE_SUSPENDED, nullptr) : nullptr;
            if (!th) { InterlockedExchange(&g_poolTarget, 0); InterlockedExchange(&g_poolThState, 0); return false; }
            SetThreadPriority(th, THREAD_PRIORITY_BELOW_NORMAL);   // заготовка не отнимает CPU у нитей IOCP
            g_poolTh = th;
            InterlockedExchange(&g_poolThState, 2);
            ResumeThread(th);
            return true;
        }
        while (g_poolThState == 1) { Sleep(0); }
        if (g_poolEv) { SetEvent(g_poolEv); }
        return g_poolThState == 2;
    }

    void EphemeralPoolStop()
    {
        if (InterlockedCompareExchange(&g_poolThState, 1, 2) == 2)
        {
            InterlockedExchange(&g_poolStop, 1);
            SetEvent(g_poolEv);
            WaitForSingleObject(g_poolTh, 10000);
            CloseHandle(g_poolTh); g_poolTh = nullptr;
            InterlockedExchange(&g_poolThState, 0);
        }
        InterlockedExchange(&g_poolTarget, 0);
        AcquireSRWLockExclusive(&g_poolLk);
        for (int i = 0; i < g_poolCount; ++i)
        {
            if (g_pool[i].h) { BCryptDestroyKey(g_pool[i].h); g_pool[i].h = nullptr; InterlockedIncrement(&g_stEphDestroyed); }
            Wipe(g_pool[i].pub, kPubLen);
        }
        g_poolCount = 0;
        ReleaseSRWLockExclusive(&g_poolLk);
    }

    void GetAccelStats(AccelStats* s)
    {
        if (!s) { return; }
        s->signCached = g_stSignCached; s->signImport = g_stSignImport; s->signHandles = g_stSignHandles;
        s->ephPool = g_stEphPool; s->ephInline = g_stEphInline; s->ephMade = g_stEphMade; s->ephDestroyed = g_stEphDestroyed;
        AcquireSRWLockShared(&g_poolLk);
        s->poolNow = g_poolCount;
        ReleaseSRWLockShared(&g_poolLk);
        s->poolTarget = g_poolTarget;
    }

    bool RandomBytes(void* out, size_t len)
    {
        if (!Init()) return false;
        NTSTATUS s = BCryptGenRandom(g_hRng, (PUCHAR)out, (ULONG)len, 0);
        if (!NT_SUCCESS(s)) { SetStatus(s); return false; }
        return true;
    }

    bool GenerateLongTermKey(PrivateKey& out)
    {
        if (!Init()) return false;
        BCRYPT_KEY_HANDLE k = nullptr; NTSTATUS s;
        if (!NT_SUCCESS(s = BCryptGenerateKeyPair(g_hEcdsa, &k, 256, 0)) ||
            !NT_SUCCESS(s = BCryptFinalizeKeyPair(k, 0))) { SetStatus(s); if (k) BCryptDestroyKey(k); return false; }
        uint8_t blob[8 + kPubLen + kPrivLen]; ULONG cb = 0;
        s = BCryptExportKey(k, nullptr, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob), &cb, 0);
        BCryptDestroyKey(k);
        if (!NT_SUCCESS(s) || cb != sizeof(blob)) { SetStatus(s); return false; }
        memcpy(out.xy, blob + 8, kPubLen);
        memcpy(out.d,  blob + 8 + kPubLen, kPrivLen);
        Wipe(blob, sizeof(blob));
        return true;
    }

    bool SignData(const PrivateKey& key, const uint8_t* data, size_t len, uint8_t sig[kSigLen])
    {
        if (!Init()) return false;
        uint8_t hash[32];
        if (!Sha256(data, len, hash)) return false;                     // ★ sec2: общий провайдер SHA-256
        // ★ sec2: ключ сервера загружен в кэш (ServerSignerLoad) — подпись кэшированным дескриптором без импорта.
        const int slot = AcquireSigner(key);
        if (slot >= 0)
        {
            ULONG cb = 0;
            const NTSTATUS s = BCryptSignHash(g_signerH[slot], nullptr, hash, 32, sig, kSigLen, &cb, 0);
            ReleaseSigner(slot);
            if (!NT_SUCCESS(s) || cb != kSigLen) { SetStatus(s); return false; }
            InterlockedIncrement(&g_stSignCached);
            return true;
        }
        BCRYPT_KEY_HANDLE k = nullptr; NTSTATUS s;
        if (!ImportSigner(key, &k)) return false;                       // прежний путь: импорт на каждую подпись
        ULONG cb = 0;
        s = BCryptSignHash(k, nullptr, hash, 32, sig, kSigLen, &cb, 0);
        BCryptDestroyKey(k);
        if (!NT_SUCCESS(s) || cb != kSigLen) { SetStatus(s); return false; }
        InterlockedIncrement(&g_stSignImport);
        return true;
    }

    bool VerifyData(const PublicKey& pub, const uint8_t* data, size_t len, const uint8_t sig[kSigLen])
    {
        if (!Init()) return false;
        uint8_t hash[32];
        if (!Sha256(data, len, hash)) return false;                     // ★ sec2: общий провайдер SHA-256
        uint8_t blob[8 + kPubLen]; MakePublicBlob(BCRYPT_ECDSA_PUBLIC_P256_MAGIC, pub.xy, blob);
        BCRYPT_KEY_HANDLE k = nullptr; NTSTATUS s;
        if (!NT_SUCCESS(s = BCryptImportKeyPair(g_hEcdsa, nullptr, BCRYPT_ECCPUBLIC_BLOB, &k, blob, sizeof(blob), 0))) { SetStatus(s); return false; }
        s = BCryptVerifySignature(k, nullptr, hash, 32, (PUCHAR)sig, kSigLen, 0);
        BCryptDestroyKey(k);
        return NT_SUCCESS(s);    // STATUS_INVALID_SIGNATURE → false (это не ошибка CNG, а честный отказ)
    }

    bool SavePrivateKeyFile(const wchar_t* path, const PrivateKey& key)
    {
        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        DWORD wr = 0; bool ok = true;
        ok = ok && WriteFile(f, kKeyFileTag, 8, &wr, nullptr) && wr == 8;
        ok = ok && WriteFile(f, key.d,  kPrivLen, &wr, nullptr) && wr == kPrivLen;
        ok = ok && WriteFile(f, key.xy, kPubLen,  &wr, nullptr) && wr == kPubLen;
        CloseHandle(f);
        return ok;
    }

    bool LoadPrivateKeyFile(const wchar_t* path, PrivateKey& out)
    {
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        uint8_t buf[8 + kPrivLen + kPubLen]; DWORD rd = 0;
        bool ok = ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd == sizeof(buf);
        CloseHandle(f);
        if (!ok || memcmp(buf, kKeyFileTag, 8) != 0) { Wipe(buf, sizeof(buf)); return false; }
        memcpy(out.d,  buf + 8, kPrivLen);
        memcpy(out.xy, buf + 8 + kPrivLen, kPubLen);
        Wipe(buf, sizeof(buf));
        return true;
    }

    bool WritePublicHeader(const wchar_t* path, const PublicKey& pub, const char* symbol)
    {
        FILE* f = _wfopen(path, L"wb");
        if (!f) return false;
        fprintf(f, "// server_public.h — долговременный ОТКРЫТЫЙ ключ сервера (ECDSA P-256, X||Y).\n");
        fprintf(f, "// Сгенерирован AsdaSecure keygen. Вшивается в клиент; проверяет подпись ServerHello.\n");
        fprintf(f, "// Закрытый ключ — только в файле рядом с серверной DLL, в исходники не попадает.\n");
        fprintf(f, "#pragma once\n#include <cstdint>\nstatic const uint8_t %s[64] = {\n    ", symbol ? symbol : "kAsdaServerPublicKey");
        for (int i = 0; i < 64; ++i) { fprintf(f, "0x%02X%s", pub.xy[i], (i == 63) ? "" : ((i % 12 == 11) ? ",\n    " : ", ")); }
        fprintf(f, "\n};\n");
        fclose(f);
        return true;
    }

    // ── Session ────────────────────────────────────────────────────────────────────────────
    struct Session::Impl
    {
        BCRYPT_KEY_HANDLE eph  = nullptr;   // эфемерный ECDH-ключ этой стороны (до вывода ключей)
        BCRYPT_KEY_HANDLE tx   = nullptr;   // AES-GCM ключ исходящего направления
        BCRYPT_KEY_HANDLE rx   = nullptr;   // AES-GCM ключ входящего направления
        uint8_t  myPub[kPubLen]  = {0};     // свой эфемерный открытый
        uint8_t  myNonce[kNonceLen] = {0};
        uint8_t  txIv[kIvLen]    = {0};     // базовый IV исходящего (XOR seq даёт IV кадра)
        uint8_t  rxIv[kIvLen]    = {0};
        uint8_t  txKey[kKeyLen]  = {0};     // держим сырьё ключа только для импорта (стенд может сверить)
        uint8_t  rxKey[kKeyLen]  = {0};
        uint8_t  clientHello[kClientHelloLen] = {0};  // своё ClientHello (клиенту нужно в ClientFinish для KDF)
    };

    Session::Session()
        : m_impl(new Impl()), m_ready(false), m_lastErr(Err::Ok),
          m_txSeq(0), m_rxSeq(0), m_inOff(0) { Init(); }

    Session::~Session() { Reset(); delete m_impl; }

    void Session::Reset()
    {
        if (m_impl)
        {
            if (m_impl->eph) BCryptDestroyKey(m_impl->eph);
            if (m_impl->tx)  BCryptDestroyKey(m_impl->tx);
            if (m_impl->rx)  BCryptDestroyKey(m_impl->rx);
            Wipe(m_impl->txKey, kKeyLen); Wipe(m_impl->rxKey, kKeyLen);
            Wipe(m_impl->txIv, kIvLen);   Wipe(m_impl->rxIv, kIvLen);
            *m_impl = Impl();
        }
        m_ready = false; m_lastErr = Err::Ok;
        m_txSeq = 0; m_rxSeq = 0; m_inOff = 0;
        m_in.clear();
    }

    // Общий секрет ECDH → HKDF → два ключа + два IV. Порядок меток фиксирует направления так,
    // что у клиента tx = c2s, у сервера tx = s2c (симметрично, без путаницы направлений).
    bool Session::DeriveKeys(const uint8_t* clientHello, const uint8_t* serverHello, bool isClient)
    {
        // Импортировать эфемерный открытый ключ ДРУГОЙ стороны из его приветствия.
        const uint8_t* peerPub = isClient ? (serverHello + 4) : (clientHello + 4);
        uint8_t blob[8 + kPubLen]; MakePublicBlob(BCRYPT_ECDH_PUBLIC_P256_MAGIC, peerPub, blob);
        BCRYPT_KEY_HANDLE peer = nullptr; NTSTATUS s;
        if (!NT_SUCCESS(s = BCryptImportKeyPair(g_hEcdh, nullptr, BCRYPT_ECCPUBLIC_BLOB, &peer, blob, sizeof(blob), 0))) { SetStatus(s); return false; }

        BCRYPT_SECRET_HANDLE secret = nullptr;
        s = BCryptSecretAgreement(m_impl->eph, peer, &secret, 0);
        BCryptDestroyKey(peer);
        if (!NT_SUCCESS(s)) { SetStatus(s); return false; }

        // Сырой общий X берём через BCRYPT_KDF_RAW_SECRET (возвращает little-endian — нормализуем).
        ULONG cb = 0;
        BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &cb, 0);
        uint8_t raw[48] = {0};
        if (cb == 0 || cb > sizeof(raw)) { BCryptDestroySecret(secret); SetStatus((NTSTATUS)-1); return false; }
        s = BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, raw, cb, &cb, 0);
        BCryptDestroySecret(secret);
        if (!NT_SUCCESS(s)) { SetStatus(s); return false; }
        for (ULONG i = 0; i < cb / 2; ++i) { uint8_t t = raw[i]; raw[i] = raw[cb-1-i]; raw[cb-1-i] = t; }  // LE→BE

        // Соль HKDF = оба nonce (клиент||сервер); info несёт версию, под-сервер и оба открытых ключа —
        // так ключ привязан к конкретному рукопожатию и под-серверу.
        uint8_t salt[2 * kNonceLen];
        memcpy(salt,             clientHello + 4 + kPubLen, kNonceLen);
        memcpy(salt + kNonceLen, serverHello + 4 + kPubLen, kNonceLen);
        uint8_t info[3 + 2 * kPubLen + 16];
        size_t io = 0;
        info[io++] = kVersion;
        info[io++] = clientHello[2];                 // под-сервер из ClientHello
        info[io++] = serverHello[2];
        memcpy(info + io, clientHello + 4, kPubLen); io += kPubLen;
        memcpy(info + io, serverHello + 4, kPubLen); io += kPubLen;
        memcpy(info + io, "AsdaSecure/v1\0\0", 16);   io += 16;

        uint8_t prk[32];
        if (!HkdfExtract(salt, sizeof(salt), raw, cb, prk)) { Wipe(raw, sizeof(raw)); return false; }
        Wipe(raw, sizeof(raw));
        // 2*(32 ключ + 12 IV) = 88 байт выходного материала; первая половина — c2s, вторая — s2c.
        uint8_t okm[2 * (kKeyLen + kIvLen)];
        if (!HkdfExpand(prk, info, sizeof(info), okm, sizeof(okm))) { Wipe(prk, 32); return false; }
        Wipe(prk, 32);

        const uint8_t* c2sKey = okm;
        const uint8_t* c2sIv  = okm + kKeyLen;
        const uint8_t* s2cKey = okm + kKeyLen + kIvLen;
        const uint8_t* s2cIv  = okm + 2 * kKeyLen + kIvLen;
        const uint8_t* txKey = isClient ? c2sKey : s2cKey;
        const uint8_t* txIv  = isClient ? c2sIv  : s2cIv;
        const uint8_t* rxKey = isClient ? s2cKey : c2sKey;
        const uint8_t* rxIv  = isClient ? s2cIv  : c2sIv;
        memcpy(m_impl->txKey, txKey, kKeyLen); memcpy(m_impl->txIv, txIv, kIvLen);
        memcpy(m_impl->rxKey, rxKey, kKeyLen); memcpy(m_impl->rxIv, rxIv, kIvLen);
        Wipe(okm, sizeof(okm));

        NTSTATUS s1 = BCryptGenerateSymmetricKey(g_hAes, &m_impl->tx, nullptr, 0, m_impl->txKey, kKeyLen, 0);
        NTSTATUS s2 = BCryptGenerateSymmetricKey(g_hAes, &m_impl->rx, nullptr, 0, m_impl->rxKey, kKeyLen, 0);
        if (!NT_SUCCESS(s1) || !NT_SUCCESS(s2)) { SetStatus(NT_SUCCESS(s1) ? s2 : s1); return false; }

        if (m_impl->eph) { BCryptDestroyKey(m_impl->eph); m_impl->eph = nullptr; }
        m_ready = true;
        return true;
    }

    bool Session::ClientHello(SubServer sub, const PublicKey& serverPub, uint8_t out[kClientHelloLen])
    {
        (void)serverPub;   // открытый ключ сервера нужен ClientFinish; тут только эфемерная пара
        if (!Init()) { m_lastErr = Err::Cng; return false; }
        Reset();
        NTSTATUS s;
        if (!NT_SUCCESS(s = BCryptGenerateKeyPair(g_hEcdh, &m_impl->eph, 256, 0)) ||
            !NT_SUCCESS(s = BCryptFinalizeKeyPair(m_impl->eph, 0))) { SetStatus(s); m_lastErr = Err::Cng; return false; }
        uint8_t blob[8 + kPubLen]; ULONG cb = 0;
        if (!NT_SUCCESS(s = BCryptExportKey(m_impl->eph, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &cb, 0)) || cb != sizeof(blob))
            { SetStatus(s); m_lastErr = Err::Cng; return false; }
        memcpy(m_impl->myPub, blob + 8, kPubLen);
        if (!RandomBytes(m_impl->myNonce, kNonceLen)) { m_lastErr = Err::Cng; return false; }
        out[0] = kClientMagic; out[1] = kVersion; out[2] = (uint8_t)sub; out[3] = 0;
        memcpy(out + 4, m_impl->myPub, kPubLen);
        memcpy(out + 4 + kPubLen, m_impl->myNonce, kNonceLen);
        memcpy(m_impl->clientHello, out, kClientHelloLen);   // понадобится в ClientFinish для KDF
        m_lastErr = Err::Ok;
        return true;
    }

    Err Session::ServerAccept(const uint8_t* hello, size_t len, SubServer sub, const PrivateKey& serverKey,
                              uint8_t out[kServerHelloLen])
    {
        if (!Init()) return m_lastErr = Err::Cng;
        if (!hello || len != kClientHelloLen) return m_lastErr = Err::Arg;
        if (hello[0] != kClientMagic)         return m_lastErr = Err::BadMagic;
        if (hello[1] != kVersion)             return m_lastErr = Err::BadVersion;
        if (hello[2] != (uint8_t)sub)         return m_lastErr = Err::BadSubServer;
        Reset();
        // ★ sec2: эфемерная пара — из пула заготовок (одноразово: пул её больше не выдаст; DeriveKeys/Reset уничтожат дескриптор),
        //   пул пуст / выключен — генерация на месте (как раньше).
        if (!TakeEph(&m_impl->eph, m_impl->myPub))
        {
            if (!GenEph(&m_impl->eph, m_impl->myPub)) return m_lastErr = Err::Cng;
            InterlockedIncrement(&g_stEphInline);
        }
        if (!RandomBytes(m_impl->myNonce, kNonceLen)) return m_lastErr = Err::Cng;

        out[0] = kServerMagic; out[1] = kVersion; out[2] = (uint8_t)sub; out[3] = 0;
        memcpy(out + 4, m_impl->myPub, kPubLen);
        memcpy(out + 4 + kPubLen, m_impl->myNonce, kNonceLen);
        // Подпись над (клиентский ePub || серверный ePub || под-сервер) — привязка сервера к рукопожатию.
        uint8_t signed_[kPubLen + kPubLen + 1];
        memcpy(signed_, hello + 4, kPubLen);
        memcpy(signed_ + kPubLen, m_impl->myPub, kPubLen);
        signed_[2 * kPubLen] = (uint8_t)sub;
        if (!SignData(serverKey, signed_, sizeof(signed_), out + 4 + kPubLen + kNonceLen)) return m_lastErr = Err::Cng;

        if (!DeriveKeys(hello, out, /*isClient=*/false)) return m_lastErr = Err::Cng;
        return m_lastErr = Err::Ok;
    }

    Err Session::ClientFinish(const uint8_t* hello, size_t len)
    {
        if (!hello || len != kServerHelloLen) return m_lastErr = Err::Arg;
        if (hello[0] != kServerMagic)         return m_lastErr = Err::BadMagic;
        if (hello[1] != kVersion)             return m_lastErr = Err::BadVersion;
        // Подпись ServerHello проверяет ClientChannel (у него вшит открытый ключ сервера) ДО вызова
        // ClientFinish; сюда мы попадаем только с уже проверенным приветствием. Здесь — вывод ключей
        // из нашего сохранённого ClientHello и принятого ServerHello.
        if (!DeriveKeys(m_impl->clientHello, hello, /*isClient=*/true)) return m_lastErr = Err::Cng;
        return m_lastErr = Err::Ok;
    }

    // IV кадра = базовый IV XOR big-endian(seq) в младшие 8 байт.
    static void MakeIv(const uint8_t base[kIvLen], uint64_t seq, uint8_t iv[kIvLen])
    {
        memcpy(iv, base, kIvLen);
        for (int i = 0; i < 8; ++i) iv[kIvLen - 1 - i] ^= (uint8_t)(seq >> (8 * i));
    }

    Err Session::Seal(const uint8_t* plain, size_t len, std::vector<uint8_t>& out)
    {
        if (!m_ready) return m_lastErr = Err::State;
        if (len > kMaxPlain) return m_lastErr = Err::Arg;
        uint64_t seq = ++m_txSeq;
        uint8_t iv[kIvLen]; MakeIv(m_impl->txIv, seq, iv);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        uint8_t tag[kTagLen];
        uint8_t aad[kFrameHdrLen];
        uint32_t clen = (uint32_t)(len + kTagLen);
        memcpy(aad, &clen, 4); memcpy(aad + 4, &seq, 8);   // AAD = len||seq (защищает заголовок кадра)
        info.pbNonce = iv; info.cbNonce = kIvLen;
        info.pbTag = tag;  info.cbTag = kTagLen;
        info.pbAuthData = aad; info.cbAuthData = kFrameHdrLen;

        size_t base = out.size();
        out.resize(base + kFrameHdrLen + len + kTagLen);
        uint8_t* p = out.data() + base;
        memcpy(p, &clen, 4); memcpy(p + 4, &seq, 8);
        ULONG done = 0;
        NTSTATUS s = BCryptEncrypt(m_impl->tx, (PUCHAR)plain, (ULONG)len, &info, nullptr, 0,
                                   p + kFrameHdrLen, (ULONG)len, &done, 0);
        if (!NT_SUCCESS(s)) { out.resize(base); SetStatus(s); return m_lastErr = Err::Cng; }
        memcpy(p + kFrameHdrLen + len, tag, kTagLen);
        return m_lastErr = Err::Ok;
    }

    Err Session::Feed(const uint8_t* data, size_t len)
    {
        if (!data || len == 0) return m_lastErr = Err::Ok;
        m_in.insert(m_in.end(), data, data + len);
        return m_lastErr = Err::Ok;
    }

    bool Session::Open(const uint8_t* frame, size_t frameLen, std::vector<uint8_t>& out)
    {
        uint32_t clen; uint64_t seq;
        memcpy(&clen, frame, 4); memcpy(&seq, frame + 4, 8);
        if (clen < kTagLen || clen > kMaxPlain + kTagLen) { m_lastErr = Err::Format; return false; }
        if (frameLen < kFrameHdrLen + clen)               { m_lastErr = Err::Format; return false; }
        // Anti-replay: seq обязан быть ровно «следующим». TCP упорядочен — всё иное есть атака/сбой.
        if (seq != m_rxSeq + 1) { m_lastErr = Err::Replay; return false; }
        size_t plainLen = clen - kTagLen;
        const uint8_t* ct  = frame + kFrameHdrLen;
        const uint8_t* tag = ct + plainLen;
        uint8_t iv[kIvLen]; MakeIv(m_impl->rxIv, seq, iv);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        uint8_t aad[kFrameHdrLen]; memcpy(aad, frame, kFrameHdrLen);
        info.pbNonce = iv; info.cbNonce = kIvLen;
        info.pbTag = (PUCHAR)tag; info.cbTag = kTagLen;
        info.pbAuthData = aad; info.cbAuthData = kFrameHdrLen;

        size_t base = out.size();
        out.resize(base + plainLen);
        ULONG done = 0;
        NTSTATUS s = BCryptDecrypt(m_impl->rx, (PUCHAR)ct, (ULONG)plainLen, &info, nullptr, 0,
                                   out.data() + base, (ULONG)plainLen, &done, 0);
        if (!NT_SUCCESS(s)) { out.resize(base); m_lastErr = Err::BadTag; return false; }   // STATUS_AUTH_TAG_MISMATCH
        m_rxSeq = seq;
        m_lastErr = Err::Ok;
        return true;
    }

    bool Session::Next(std::vector<uint8_t>& out)
    {
        out.clear();
        if (!m_ready) { m_lastErr = Err::State; return false; }
        size_t avail = m_in.size() - m_inOff;
        if (avail < kFrameHdrLen) return false;             // заголовок ещё не весь
        uint32_t clen; memcpy(&clen, m_in.data() + m_inOff, 4);
        if (clen < kTagLen || clen > kMaxPlain + kTagLen) { m_lastErr = Err::Format; return false; }
        if (avail < kFrameHdrLen + clen) return false;      // тело ещё не всё
        bool ok = Open(m_in.data() + m_inOff, kFrameHdrLen + clen, out);
        if (!ok) return false;
        m_inOff += kFrameHdrLen + clen;
        // Сжать накопитель, когда разобранный префикс велик.
        if (m_inOff > 65536 || m_inOff == m_in.size())
        {
            m_in.erase(m_in.begin(), m_in.begin() + m_inOff);
            m_inOff = 0;
        }
        return true;
    }
}
