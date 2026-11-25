// Copyright (c) 2026 @sitxovski (Discord)
// Crypto.cpp — CNG-реализация (см. Crypto.h).
#include "EacCommon.h"
#include "Crypto.h"
#include <bcrypt.h>
#include <cstring>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace Eac { namespace Crypto
{
    static const char kMagic[8] = { 'A','S','D','A','R','S','A','1' };   // заголовок файла ключа

    // Провайдеры CNG открываются один раз на процесс (явно, без псевдодескрипторов — работает на любой Windows 10/2016+).
    static BCRYPT_ALG_HANDLE g_sha = nullptr;   // SHA-256
    static BCRYPT_ALG_HANDLE g_rsa = nullptr;   // RSA
    static std::once_flag    g_once;            // однократное открытие

    static void OpenProviders()
    {
        std::call_once(g_once, [] {
            if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) g_sha = nullptr;
            if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0))) g_rsa = nullptr;
        });
    }

    bool Sha256(const void* data, size_t len, uint8_t out[32])
    {
        OpenProviders();
        if (!g_sha) return false;
        return NT_SUCCESS(BCryptHash(g_sha, nullptr, 0, (PUCHAR)data, (ULONG)len, out, 32));
    }

    bool Random(void* out, size_t len)
    {
        return NT_SUCCESS(BCryptGenRandom(nullptr, (PUCHAR)out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    }

    std::string B64Url(const uint8_t* d, size_t n)
    {
        static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string o; o.reserve((n * 4 + 2) / 3);
        size_t i = 0;
        for (; i + 3 <= n; i += 3)
        {
            uint32_t v = ((uint32_t)d[i] << 16) | ((uint32_t)d[i + 1] << 8) | d[i + 2];
            o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; o += A[(v >> 6) & 63]; o += A[v & 63];
        }
        if (n - i == 1) { uint32_t v = (uint32_t)d[i] << 16; o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; }
        else if (n - i == 2) { uint32_t v = ((uint32_t)d[i] << 16) | ((uint32_t)d[i + 1] << 8); o += A[(v >> 18) & 63]; o += A[(v >> 12) & 63]; o += A[(v >> 6) & 63]; }
        return o;
    }

    bool B64UrlDecode(const std::string& in, std::vector<uint8_t>& out)
    {
        out.clear();
        if (in.size() % 4 == 1) return false;
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '-') return 62; if (c == '_') return 63; return -1; };
        uint32_t acc = 0; int bits = 0;
        for (char c : in)
        {
            int v = val(c); if (v < 0) return false;
            acc = (acc << 6) | (uint32_t)v; bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back((uint8_t)(acc >> bits)); }
        }
        if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return false;   // неканонический хвост
        return true;
    }

    std::string Hex(const uint8_t* d, size_t n)
    {
        static const char* H = "0123456789abcdef";
        std::string o; o.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) { o += H[d[i] >> 4]; o += H[d[i] & 15]; }
        return o;
    }

    // ── RsaKey ─────────────────────────────────────────────────────────────────────────────
    RsaKey::RsaKey() : m_key(nullptr), m_bits(0) {}
    RsaKey::~RsaKey() { Free(); }

    void RsaKey::Free()
    {
        if (m_key) { BCryptDestroyKey((BCRYPT_KEY_HANDLE)m_key); m_key = nullptr; }
        m_n.clear(); m_e.clear(); m_bits = 0;
    }

    static void TrimLeadingZeros(std::vector<uint8_t>& v)
    {
        size_t k = 0; while (k + 1 < v.size() && v[k] == 0) ++k;
        if (k) v.erase(v.begin(), v.begin() + (ptrdiff_t)k);
    }

    bool RsaKey::ExtractPublic()
    {
        ULONG cb = 0;
        if (!NT_SUCCESS(BCryptExportKey((BCRYPT_KEY_HANDLE)m_key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &cb, 0))) return false;
        std::vector<uint8_t> blob(cb);
        if (!NT_SUCCESS(BCryptExportKey((BCRYPT_KEY_HANDLE)m_key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), cb, &cb, 0))) return false;
        if (cb < sizeof(BCRYPT_RSAKEY_BLOB)) return false;
        BCRYPT_RSAKEY_BLOB hdr; memcpy(&hdr, blob.data(), sizeof(hdr));
        size_t off = sizeof(hdr);
        if (off + hdr.cbPublicExp + hdr.cbModulus > cb) return false;
        m_e.assign(blob.begin() + off, blob.begin() + off + hdr.cbPublicExp);
        m_n.assign(blob.begin() + off + hdr.cbPublicExp, blob.begin() + off + hdr.cbPublicExp + hdr.cbModulus);
        TrimLeadingZeros(m_e); TrimLeadingZeros(m_n);
        m_bits = hdr.BitLength;
        SecureZeroMemory(blob.data(), blob.size());
        return true;
    }

    bool RsaKey::Generate(unsigned bits)
    {
        Free();
        OpenProviders(); if (!g_rsa) return false;
        BCRYPT_KEY_HANDLE k = nullptr;
        if (!NT_SUCCESS(BCryptGenerateKeyPair(g_rsa, &k, bits, 0))) return false;
        if (!NT_SUCCESS(BCryptFinalizeKeyPair(k, 0))) { BCryptDestroyKey(k); return false; }
        m_key = k;
        return ExtractPublic();
    }

    bool RsaKey::LoadFile(const std::wstring& path, std::string* err)
    {
        Free();
        OpenProviders(); if (!g_rsa) { if (err) *err = "CNG RSA недоступен"; return false; }
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { if (err) *err = "файл ключа не открыт (" + std::to_string(GetLastError()) + ")"; return false; }
        LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
        if (sz.QuadPart < 16 || sz.QuadPart > 16384) { CloseHandle(h); if (err) *err = "размер файла ключа негоден"; return false; }
        std::vector<uint8_t> buf((size_t)sz.QuadPart);
        DWORD rd = 0; BOOL ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr);
        CloseHandle(h);
        if (!ok || rd != buf.size() || memcmp(buf.data(), kMagic, 8) != 0) { SecureZeroMemory(buf.data(), buf.size()); if (err) *err = "формат файла ключа негоден"; return false; }
        BCRYPT_KEY_HANDLE k = nullptr;
        NTSTATUS s = BCryptImportKeyPair(g_rsa, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, &k, buf.data() + 8, (ULONG)(buf.size() - 8), 0);
        SecureZeroMemory(buf.data(), buf.size());
        if (!NT_SUCCESS(s)) { if (err) *err = "импорт ключа отклонён CNG"; return false; }
        m_key = k;
        if (!ExtractPublic()) { Free(); if (err) *err = "экспорт открытой части не удался"; return false; }
        return true;
    }

    bool RsaKey::SaveFileNew(const std::wstring& path, std::string* err)
    {
        if (!m_key) { if (err) *err = "нет ключа"; return false; }
        ULONG cb = 0;
        if (!NT_SUCCESS(BCryptExportKey((BCRYPT_KEY_HANDLE)m_key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &cb, 0))) { if (err) *err = "экспорт"; return false; }
        std::vector<uint8_t> buf(8 + cb);
        memcpy(buf.data(), kMagic, 8);
        if (!NT_SUCCESS(BCryptExportKey((BCRYPT_KEY_HANDLE)m_key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, buf.data() + 8, cb, &cb, 0))) { if (err) *err = "экспорт"; return false; }
        // CREATE_NEW: чужой/старый ключ никогда не перезаписывается; без явного дескриптора безопасности —
        // права наследуются от папки secrets (у неё ACL без наследования: Administrators, SYSTEM).
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { SecureZeroMemory(buf.data(), buf.size()); if (err) *err = "файл ключа не создан (" + std::to_string(GetLastError()) + ")"; return false; }
        DWORD wr = 0; BOOL ok = WriteFile(h, buf.data(), (DWORD)(8 + cb), &wr, nullptr) && FlushFileBuffers(h);
        CloseHandle(h);
        SecureZeroMemory(buf.data(), buf.size());
        if (!ok || wr != 8 + cb) { DeleteFileW(path.c_str()); if (err) *err = "запись файла ключа не удалась"; return false; }
        return true;
    }

    bool RsaKey::ImportPublic(const std::vector<uint8_t>& n, const std::vector<uint8_t>& e)
    {
        Free();
        OpenProviders(); if (!g_rsa) return false;
        if (n.empty() || e.empty() || n.size() > 1024 || e.size() > 16) return false;
        std::vector<uint8_t> blob(sizeof(BCRYPT_RSAKEY_BLOB) + e.size() + n.size());
        BCRYPT_RSAKEY_BLOB hdr{};
        hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC; hdr.BitLength = (ULONG)(n.size() * 8);
        hdr.cbPublicExp = (ULONG)e.size(); hdr.cbModulus = (ULONG)n.size();
        memcpy(blob.data(), &hdr, sizeof(hdr));
        memcpy(blob.data() + sizeof(hdr), e.data(), e.size());
        memcpy(blob.data() + sizeof(hdr) + e.size(), n.data(), n.size());
        BCRYPT_KEY_HANDLE k = nullptr;
        if (!NT_SUCCESS(BCryptImportKeyPair(g_rsa, nullptr, BCRYPT_RSAPUBLIC_BLOB, &k, blob.data(), (ULONG)blob.size(), 0))) return false;
        m_key = k;
        return ExtractPublic();
    }

    bool RsaKey::SignSha256(const uint8_t hash[32], std::vector<uint8_t>& sig)
    {
        if (!m_key) return false;
        std::lock_guard<std::mutex> lk(m_mu);
        BCRYPT_PKCS1_PADDING_INFO pad{ BCRYPT_SHA256_ALGORITHM };
        ULONG cb = 0;
        if (!NT_SUCCESS(BCryptSignHash((BCRYPT_KEY_HANDLE)m_key, &pad, (PUCHAR)hash, 32, nullptr, 0, &cb, BCRYPT_PAD_PKCS1))) return false;
        sig.resize(cb);
        if (!NT_SUCCESS(BCryptSignHash((BCRYPT_KEY_HANDLE)m_key, &pad, (PUCHAR)hash, 32, sig.data(), cb, &cb, BCRYPT_PAD_PKCS1))) return false;
        sig.resize(cb);
        return true;
    }

    bool RsaKey::VerifySha256(const uint8_t hash[32], const uint8_t* sig, size_t sigLen)
    {
        if (!m_key) return false;
        std::lock_guard<std::mutex> lk(m_mu);
        BCRYPT_PKCS1_PADDING_INFO pad{ BCRYPT_SHA256_ALGORITHM };
        return NT_SUCCESS(BCryptVerifySignature((BCRYPT_KEY_HANDLE)m_key, &pad, (PUCHAR)hash, 32, (PUCHAR)sig, (ULONG)sigLen, BCRYPT_PAD_PKCS1));
    }
}}
