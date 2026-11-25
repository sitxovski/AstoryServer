// Copyright (c) 2026 @sitxovski (Discord)
// Crypto.h — Windows CNG для AsdaId: SHA-256, случайные байты, base64url, RSA-2048 (RS256 = PKCS#1 v1.5 + SHA-256).
// Ключ JWT: файл secrets\jwt_rs256.key = "ASDARSA1" + BCRYPT_RSAFULLPRIVATE_BLOB. Создаётся при первом запуске,
// если его нет (CREATE_NEW — права наследуются от папки secrets). Открытая часть (n, e) идёт в JWKS.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>

namespace Eac { namespace Crypto
{
    // SHA-256 одного буфера.
    bool Sha256(const void* data, size_t len, uint8_t out[32]);
    // Криптослучайные байты (системный RNG).
    bool Random(void* out, size_t len);
    // base64url без '=' (RFC 7515 §2).
    std::string B64Url(const uint8_t* data, size_t len);
    inline std::string B64Url(const std::string& s) { return B64Url((const uint8_t*)s.data(), s.size()); }
    // Строгое декодирование base64url без '=' (лишние биты хвоста должны быть нулями). false — мусор.
    bool B64UrlDecode(const std::string& in, std::vector<uint8_t>& out);
    // Hex строчными.
    std::string Hex(const uint8_t* data, size_t len);

    // RSA-ключ (CNG). Не копируется. Подпись сериализуется собственной блокировкой (нити AsdaId).
    class RsaKey
    {
    public:
        RsaKey();
        ~RsaKey();
        RsaKey(const RsaKey&) = delete;
        RsaKey& operator=(const RsaKey&) = delete;

        // Сгенерировать новую пару (bits = 2048).
        bool Generate(unsigned bits);
        // Загрузить закрытый ключ из файла формата ASDARSA1.
        bool LoadFile(const std::wstring& path, std::string* err);
        // Сохранить закрытый ключ в НОВЫЙ файл (CREATE_NEW; существующий не перезаписывается).
        bool SaveFileNew(const std::wstring& path, std::string* err);
        // Импорт только открытой части (n, e big-endian) — для проверки подписи стендом.
        bool ImportPublic(const std::vector<uint8_t>& n, const std::vector<uint8_t>& e);
        // Подписать SHA-256-хеш (PKCS#1 v1.5). sig — 256 байт для RSA-2048.
        bool SignSha256(const uint8_t hash[32], std::vector<uint8_t>& sig);
        // Проверить подпись над SHA-256-хешем.
        bool VerifySha256(const uint8_t hash[32], const uint8_t* sig, size_t sigLen);
        // Модуль n и экспонента e (big-endian, без ведущих нулей) — для JWKS.
        const std::vector<uint8_t>& N() const { return m_n; }
        const std::vector<uint8_t>& E() const { return m_e; }
        bool Valid() const { return m_key != nullptr; }
        // Длина модуля в битах.
        unsigned Bits() const { return m_bits; }

    private:
        void* m_key;                  // BCRYPT_KEY_HANDLE
        std::vector<uint8_t> m_n;     // модуль
        std::vector<uint8_t> m_e;     // открытая экспонента
        unsigned m_bits;              // размер ключа
        std::mutex m_mu;              // сериализация BCryptSignHash
        bool ExtractPublic();         // заполнить m_n/m_e/m_bits из m_key
        void Free();
    };
}}
