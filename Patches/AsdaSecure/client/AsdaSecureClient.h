// Copyright (c) 2026 @sitxovski (Discord)
// AsdaSecureClient.h — клиентский адаптер криптопрослойки поверх AsdaSecure::ClientChannel.
//
// КУДА ВСТАЁТ (НЕ коммитить в AstoryClient из этой волны — врезка в следующей волне):
//   Файл клиента: AstoryClient/Source/AsdaNet/Private/AsdaConnection.cpp.
//   Там транспорт — сырой FSocket; принятые байты копятся в FAsdaConnection::RecvBuffer,
//   кадры выбираются Asda::PacketFrame::Parse (де-frame + де-XOR), отправка —
//   PacketFrame::Build (frame + XOR) → FSocket::Send. XOR-слой (ChannelCipher) ОСТАЁТСЯ как есть:
//   шифрование трафика — ВНЕШНИЙ конверт поверх старого кадра, старый протокол внутри не меняется.
//
//   Три точки врезки в AsdaConnection.cpp:
//     1) Connect(): после успешного bConnected=true и до первой отправки — FAsdaSecureClient::Start(),
//        его выход (ClientHello) немедленно уйти через Socket->Send (а НЕ через SendPacket —
//        приветствие не кадр старого протокола).
//     2) SendPacket(): собранный frame (PacketFrame::Build, уже с XOR) пропустить через
//        FAsdaSecureClient::OnSend → в сокет уходит шифротекст. До готовности рукопожатия
//        OnSend копит кадр; очередь выталкивается первым Seal после готовности.
//     3) Tick(): принятые с сокета байты до занесения в RecvBuffer пропустить через
//        FAsdaSecureClient::OnRecv → в RecvBuffer кладётся расшифрованный старый поток,
//        дальше DrainFrames() работает без изменений.
//
// Совместимость на время перехода: конструктор берёт режим.
//   Secure  — шлём ClientHello, ждём ServerHello (проверка подписи вшитым ключом), затем AEAD.
//   Legacy  — приветствие не шлём, байты проходят как есть (как сейчас). Прослойка сервера
//             различает по первому байту (0xFB старый кадр vs 0xA5 приветствие).
#pragma once
#include "AsdaSecure.h"
#include <cstdint>
#include <vector>
#include <cstring>

class FAsdaSecureClient
{
public:
    FAsdaSecureClient() : m_started(false) {}

    // sub — под-сервер (Login для 15001, Game для 15601). legacy — старый режим без шифрования.
    void Configure(AsdaSecure::SubServer sub, bool legacy)
    {
        m_sub = sub;
        m_chan.Reset();
        m_chan.SetLegacy(legacy);
        m_started = false;
    }

    // Точка 1: вызвать сразу после установления соединения. outHello (если не пуст) — отправить в сокет.
    bool Start(std::vector<uint8_t>& outHello)
    {
        if (!AsdaSecure::Init()) return false;
        // Открытый ключ сервера вшит в клиент (server_public.h, генерит keygen).
        AsdaSecure::PublicKey pub;
        memcpy(pub.xy, GetServerPublicKey(), AsdaSecure::kPubLen);
        m_started = m_chan.Start(m_sub, pub, outHello);
        return m_started;
    }

    // Точка 2: исходящий собранный кадр (frame+XOR) → шифротекст в out. Легаси — out = копия frame.
    bool OnSend(const uint8_t* frame, size_t len, std::vector<uint8_t>& out)
    {
        m_lastErr = m_chan.OnSend(frame, len, out);
        return m_lastErr == AsdaSecure::Err::Ok;
    }

    // Точка 3: принятые с сокета байты → расшифрованный старый поток в out (идёт в RecvBuffer).
    // Возврат false = ошибка целостности/подписи: вызывающий рвёт соединение (как при FIN/RST).
    bool OnRecv(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
    {
        m_lastErr = m_chan.OnRecv(data, len, out);
        return m_lastErr == AsdaSecure::Err::Ok;
    }

    // ★ В7d: вытолкнуть очередь, накопленную до рукопожатия, СРАЗУ после готовности (out — шифротекст в сокет).
    //   Без этого кадр, отправленный до ServerHello (вход в мир 20000 сразу после connect), ждал бы следующей отправки.
    bool Flush(std::vector<uint8_t>& out)
    {
        m_lastErr = m_chan.Flush(out);
        return m_lastErr == AsdaSecure::Err::Ok;
    }
    bool HasPending() const { return m_chan.HasPending(); }

    bool IsReady() const { return m_chan.IsReady(); }
    bool IsLegacy() const { return m_chan.IsLegacy(); }
    // ★ В7d: последняя ошибка прослойки (для понятной причины разрыва в логе клиента).
    AsdaSecure::Err LastErr() const { return m_lastErr; }
    const char* LastErrName() const { return AsdaSecure::ErrName(m_lastErr); }

private:
    // Вшитый открытый ключ сервера. В сборке клиента — #include "server_public.h" и вернуть
    // kAsdaServerPublicKey. Здесь — слабый символ-заглушка для автономной сборки адаптера.
    static const uint8_t* GetServerPublicKey();

    AsdaSecure::ClientChannel m_chan;
    AsdaSecure::SubServer     m_sub = AsdaSecure::SubServer::Login;
    bool                      m_started;
    AsdaSecure::Err           m_lastErr = AsdaSecure::Err::Ok;   // ★ В7d
};
