// Copyright (c) 2026 @sitxovski (Discord)
// keygen.cpp — утилита генерации долговременной пары сервера (ECDSA P-256).
//   keygen <server_private.key> <server_public.h> [symbol]
// Пишет закрытый ключ в файл (лежит рядом с серверной DLL, в исходники НЕ коммитить) и
// заголовок с открытым ключом для вшивания в клиент. Запускать ОДИН раз при развёртывании;
// при ротации — заново, затем переложить файл рядом с DLL и пересобрать клиент.
#include "AsdaSecure.h"
#include <cstdio>
#include <windows.h>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        wprintf(L"Использование: keygen <server_private.key> <server_public.h> [symbol]\n");
        return 2;
    }
    if (!AsdaSecure::Init())
    {
        wprintf(L"CNG недоступен (NTSTATUS=0x%08lX)\n", AsdaSecure::LastStatus());
        return 1;
    }
    AsdaSecure::PrivateKey priv;
    if (!AsdaSecure::GenerateLongTermKey(priv))
    {
        wprintf(L"Генерация ключа не удалась (NTSTATUS=0x%08lX)\n", AsdaSecure::LastStatus());
        return 1;
    }
    AsdaSecure::PublicKey pub; memcpy(pub.xy, priv.xy, AsdaSecure::kPubLen);
    const char* sym = "kAsdaServerPublicKey";
    char symBuf[128] = {0};
    if (argc >= 4) { WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, symBuf, sizeof(symBuf) - 1, nullptr, nullptr); sym = symBuf; }

    if (!AsdaSecure::SavePrivateKeyFile(argv[1], priv)) { wprintf(L"Не удалось записать закрытый ключ: %s\n", argv[1]); AsdaSecure::Wipe(&priv, sizeof(priv)); return 1; }
    if (!AsdaSecure::WritePublicHeader(argv[2], pub, sym)) { wprintf(L"Не удалось записать заголовок: %s\n", argv[2]); AsdaSecure::Wipe(&priv, sizeof(priv)); return 1; }

    // Самопроверка: подпись/проверка на свежей паре.
    uint8_t msg[32]; AsdaSecure::RandomBytes(msg, sizeof(msg));
    uint8_t sig[AsdaSecure::kSigLen];
    bool ok = AsdaSecure::SignData(priv, msg, sizeof(msg), sig)
           && AsdaSecure::VerifyData(pub, msg, sizeof(msg), sig);
    AsdaSecure::Wipe(&priv, sizeof(priv));
    wprintf(L"Готово. Закрытый ключ: %s (положить рядом с DLL, права — владельцу).\n", argv[1]);
    wprintf(L"Открытый ключ: %s (символ %hs). Самопроверка подписи: %s\n", argv[2], sym, ok ? L"OK" : L"ОШИБКА");
    return ok ? 0 : 1;
}
