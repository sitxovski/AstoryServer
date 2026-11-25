// Copyright (c) 2026 @sitxovski (Discord)
// AsdaSecureClient.cpp — заглушка вшитого открытого ключа для АВТОНОМНОЙ сборки адаптера.
// В сборке клиента UE этот файл заменяется на #include "server_public.h" (вывод keygen),
// и GetServerPublicKey() возвращает kAsdaServerPublicKey. Нули здесь — только чтобы адаптер
// компилировался и линковался вне дерева UE; с нулевым ключом рукопожатие заведомо не пройдёт.
#include "AsdaSecureClient.h"

const uint8_t* FAsdaSecureClient::GetServerPublicKey()
{
    static const uint8_t kPlaceholder[AsdaSecure::kPubLen] = { 0 };
    return kPlaceholder;
}
