// Copyright (c) 2026 @sitxovski (Discord)
// cli_wrap.cpp — обёртка КЛИЕНТСКОЙ копии AsdaSecure (AstoryClient/Source/AsdaNet/Private/Secure) для стенда ревизии R3.
//   Собирается с /DAsdaSecure=AsdaSecureCli и пустыми UE-шимами (shim/Windows/*.h): пространство имён клиентской копии
//   переименовано препроцессором, чтобы в одном exe жили и клиентская (игровое соединение), и серверная (канал 15901) копии.
//   Логика клиентской копии не меняется — компилируются её исходники как есть.
#include "AsdaSecure.h"
#include <vector>
#include <cstring>

// Открытый интерфейс для оркестратора (без типов AsdaSecure).
namespace CliGame
{
    // Канал клиента игрового соединения (ClientChannel клиентской копии).
    struct Chan { AsdaSecure::ClientChannel ch; };

    // Инициализировать CNG клиентской копии.
    bool Init() { return AsdaSecure::Init(); }

    // Начать рукопожатие под-сервера Game (2) с открытым ключом сервера pub64 → ClientHello.
    Chan* Start(const unsigned char pub64[64], std::vector<unsigned char>& hello)
    {
        Chan* c = new Chan();
        AsdaSecure::PublicKey pk; memcpy(pk.xy, pub64, 64);
        if (!c->ch.Start(AsdaSecure::SubServer::Game, pk, hello)) { delete c; return nullptr; }
        return c;
    }

    // Принять байты сервера. 0 — Ok, иначе код ошибки клиентской копии.
    int Recv(Chan* c, const unsigned char* d, size_t n, std::vector<unsigned char>& plain) { return (int)c->ch.OnRecv(d, n, plain); }

    // Рукопожатие завершено.
    bool Ready(Chan* c) { return c->ch.IsReady(); }

    // Привязка соединения (ClientChannel::ChannelBinding клиентской копии).
    bool Bind(Chan* c, unsigned char out[32]) { return c->ch.ChannelBinding(out); }

    // Сбросить канал (как Disconnect клиента) — после этого Bind обязан вернуть false.
    void Reset(Chan* c) { c->ch.Reset(); }

    // Освободить.
    void Free(Chan* c) { delete c; }
}
