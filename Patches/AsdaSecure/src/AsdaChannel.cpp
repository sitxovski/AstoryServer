// Copyright (c) 2026 @sitxovski (Discord)
// AsdaChannel.cpp — высокоуровневые каналы прослойки поверх AsdaSecure::Session.
//   ServerChannel — сторона под-сервера (в DLL): распознаёт старый клиент по первому байту,
//                   копит ClientHello, выпускает ServerHello, после рукопожатия шифрует/расшифровывает.
//   ClientChannel — сторона UE: шлёт ClientHello, проверяет подпись сервера, затем шифрует.
// Исходящее до завершения рукопожатия копится и выталкивается первым же вызовом после готовности —
// это снимает гонку «сервер/клиент успел послать прикладной пакет раньше, чем вывелись ключи».
#include "AsdaSecure.h"
#include <cstring>

namespace AsdaSecure
{
    // ── ServerChannel ───────────────────────────────────────────────────────────────────────
    ServerChannel::ServerChannel()
        : m_mode(Mode::Unknown), m_allowLegacy(true), m_sub(SubServer::Game), m_key(nullptr) {}

    void ServerChannel::Reset()
    {
        m_sess.Reset(); m_mode = Mode::Unknown;
        m_hello.clear(); m_pendingOut.clear();
    }

    Err ServerChannel::OnRecv(const uint8_t* data, size_t len,
                              std::vector<uint8_t>& toParser, std::vector<uint8_t>& toSocket)
    {
        toParser.clear(); toSocket.clear();
        if (!data && len) return Err::Arg;

        // Первый байт решает режим канала.
        if (m_mode == Mode::Unknown)
        {
            if (len == 0) return Err::Ok;
            uint8_t first = data[0];
            if (first == kLegacyMagic)
            {
                if (!m_allowLegacy) return Err::BadMagic;    // шифрование обязательно — старый клиент отвергнут
                m_mode = Mode::Legacy;
            }
            else if (first == kClientMagic)
            {
                m_mode = Mode::Secure;
            }
            else return Err::BadMagic;
        }

        if (m_mode == Mode::Legacy)
        {
            toParser.assign(data, data + len);               // байты идут в старый разборщик как есть
            return Err::Ok;
        }

        // Secure: до готовности копим ClientHello (может прийти по частям, вместе с хвостом прикладных байт).
        if (!m_sess.IsReady())
        {
            m_hello.insert(m_hello.end(), data, data + len);
            if (m_hello.size() < kClientHelloLen) return Err::Ok;   // ещё не весь ClientHello
            uint8_t serverHello[kServerHelloLen];
            if (!m_key) return Err::State;
            Err e = m_sess.ServerAccept(m_hello.data(), kClientHelloLen, m_sub, *m_key, serverHello);
            if (e != Err::Ok) return e;
            toSocket.assign(serverHello, serverHello + kServerHelloLen);   // ServerHello → в сокет (открытым)
            // Хвост после ClientHello — уже зашифрованные кадры: скормить сессии.
            if (m_hello.size() > kClientHelloLen)
                m_sess.Feed(m_hello.data() + kClientHelloLen, m_hello.size() - kClientHelloLen);
            m_hello.clear();
            // Исходящее, накопленное до готовности, запечатать и дослать.
            if (!m_pendingOut.empty())
            {
                Err se = m_sess.Seal(m_pendingOut.data(), m_pendingOut.size(), toSocket);
                m_pendingOut.clear();
                if (se != Err::Ok) return se;
            }
        }
        else
        {
            m_sess.Feed(data, len);
        }

        // Выбрать все готовые расшифрованные кадры.
        std::vector<uint8_t> frame;
        while (m_sess.Next(frame))
            toParser.insert(toParser.end(), frame.begin(), frame.end());
        return m_sess.LastError();
    }

    Err ServerChannel::OnSend(const uint8_t* plain, size_t len, std::vector<uint8_t>& toSocket)
    {
        toSocket.clear();
        if (m_mode == Mode::Legacy) { toSocket.assign(plain, plain + len); return Err::Ok; }
        if (!m_sess.IsReady())
        {
            m_pendingOut.insert(m_pendingOut.end(), plain, plain + len);   // ещё нет ключей — в очередь
            return Err::Ok;
        }
        return m_sess.Seal(plain, len, toSocket);
    }

    // ── ClientChannel ─────────────────────────────────────────────────────────────────────
    ClientChannel::ClientChannel() : m_legacy(false) {}

    void ClientChannel::Reset()
    {
        m_sess.Reset(); m_hello.clear(); m_pendingOut.clear();
    }

    bool ClientChannel::Start(SubServer sub, const PublicKey& serverPub, std::vector<uint8_t>& toSocket)
    {
        toSocket.clear();
        m_serverPub = serverPub;                 // запомнить для проверки подписи ServerHello
        if (m_legacy) return true;               // старый режим — приветствие не шлём
        uint8_t hello[kClientHelloLen];
        if (!m_sess.ClientHello(sub, serverPub, hello)) return false;
        memcpy(m_clientPub, hello + 4, kPubLen);
        m_sub = sub;
        toSocket.assign(hello, hello + kClientHelloLen);
        return true;
    }

    Err ClientChannel::OnRecv(const uint8_t* data, size_t len, std::vector<uint8_t>& toParser)
    {
        toParser.clear();
        if (m_legacy) { toParser.assign(data, data + len); return Err::Ok; }

        if (!m_sess.IsReady())
        {
            // ★ В7d: ответ, который ЗАВЕДОМО не ServerHello (сервер без шифрования прислал старый кадр 0xFB и т. п.),
            //   опознаётся по первому байту сразу — не ждём 148 байт и не выдаём это за «подпись не сошлась».
            if (m_hello.empty() && len > 0 && data[0] != kServerMagic) return Err::BadMagic;
            m_hello.insert(m_hello.end(), data, data + len);
            if (m_hello.size() < 2) return Err::Ok;
            if (m_hello[1] != kVersion) return Err::BadVersion;
            if (m_hello.size() < kServerHelloLen) return Err::Ok;
            // Проверить подпись сервера ДО вывода ключей: подписаны (clientPub || serverPub || под-сервер).
            const uint8_t* sPub = m_hello.data() + 4;
            const uint8_t* sig  = m_hello.data() + 4 + kPubLen + kNonceLen;
            uint8_t signed_[kPubLen + kPubLen + 1];
            memcpy(signed_, m_clientPub, kPubLen);
            memcpy(signed_ + kPubLen, sPub, kPubLen);
            signed_[2 * kPubLen] = (uint8_t)m_sub;
            if (!VerifyData(m_serverPub, signed_, sizeof(signed_), sig))
                return Err::BadSignature;        // подмена ключа сервера / посредник
            Err e = m_sess.ClientFinish(m_hello.data(), kServerHelloLen);
            if (e != Err::Ok) return e;
            if (m_hello.size() > kServerHelloLen)
                m_sess.Feed(m_hello.data() + kServerHelloLen, m_hello.size() - kServerHelloLen);
            m_hello.clear();
        }
        else
        {
            m_sess.Feed(data, len);
        }

        std::vector<uint8_t> frame;
        while (m_sess.Next(frame))
            toParser.insert(toParser.end(), frame.begin(), frame.end());
        return m_sess.LastError();
    }

    Err ClientChannel::OnSend(const uint8_t* plain, size_t len, std::vector<uint8_t>& toSocket)
    {
        toSocket.clear();
        if (m_legacy) { toSocket.assign(plain, plain + len); return Err::Ok; }
        if (!m_sess.IsReady())
        {
            m_pendingOut.insert(m_pendingOut.end(), plain, plain + len);
            return Err::Ok;
        }
        // Вытолкнуть очередь, накопленную до готовности, затем текущий пакет.
        if (!m_pendingOut.empty())
        {
            Err pe = m_sess.Seal(m_pendingOut.data(), m_pendingOut.size(), toSocket);
            m_pendingOut.clear();
            if (pe != Err::Ok) return pe;
        }
        return m_sess.Seal(plain, len, toSocket);
    }

    // ★ В7d: вытолкнуть очередь, накопленную до готовности, сразу после рукопожатия (а не со следующей отправкой).
    Err ClientChannel::Flush(std::vector<uint8_t>& toSocket)
    {
        toSocket.clear();
        if (m_legacy || !m_sess.IsReady() || m_pendingOut.empty()) return Err::Ok;
        Err e = m_sess.Seal(m_pendingOut.data(), m_pendingOut.size(), toSocket);
        m_pendingOut.clear();
        return e;
    }

    // ★ EAC ред. 3 (контракт §8.1): привязка соединения — только в режиме Secure после рукопожатия.
    bool ServerChannel::ChannelBinding(uint8_t out[kBindLen]) const
    {
        if (m_mode != Mode::Secure) return false;
        return m_sess.ChannelBinding(out);
    }

    // ★ EAC ред. 3: клиентская сторона — в Legacy привязки нет.
    bool ClientChannel::ChannelBinding(uint8_t out[kBindLen]) const
    {
        if (m_legacy) return false;
        return m_sess.ChannelBinding(out);
    }
}
