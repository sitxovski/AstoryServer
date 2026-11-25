// Copyright (c) 2026 @sitxovski (Discord)
// stand_nocng.cpp — ★ fix2 (НИЗК-5 ревизии INTEG3): поведение моста AsdaWire, когда CNG не открылся.
//
// Собирается из ТОГО ЖЕ AsdaServerBridge.cpp с /DASDAWIRE_STAND_NO_CNG (EnsureInit считает, что AsdaSecure::Init
// вернул false — таблица слотов не создаётся). В DLL этот макрос не определён.
// Ожидание:
//   • AllowLegacy=1 — байты идут как есть: RecvRoute отдаёт стоку исходный буфер, SendRoute шлёт кадр как есть
//     (старые клиенты работают; прежде ВСЕ клиенты теряли приём/отправку);
//   • AllowLegacy=0 — шифрование обязательно, а его нет: соединение закрывается на первом приёме (отчёт вида 0),
//     открытым ничего не шлётся.
// Сборка: AsdaSecure\build.bat (цель stand_nocng). Итог «ВСЁ СОШЛОСЬ» / ненулевой код.
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <windows.h>
#include <cstdio>
#include <vector>

static int g_fail = 0;
static void CHECK(bool ok, const char* what)
{
    printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what);
    if (!ok) { ++g_fail; }
}

static std::vector<uint8_t> g_s2c;             // «сокет» к клиенту
static int g_sent = 0, g_kills = 0, g_reports = 0, g_lastKind = -1, g_notifyCng = -1;
static int SendRaw(void*, int, const void* d, int n) { g_s2c.insert(g_s2c.end(), (const uint8_t*)d, (const uint8_t*)d + n); ++g_sent; return 1; }
static void Kill(void*, int) { ++g_kills; }
static void Report(void*, int, const AsdaWire::FailInfo& fi) { ++g_reports; g_lastKind = fi.kind; }
static void Notify(bool cng, bool) { g_notifyCng = cng ? 1 : 0; }

int main()
{
    printf("== stand_nocng: мост AsdaWire при сбое CNG (fix2, НИЗК-5) ==\n");
    const uint8_t legacy[12] = { 0xFB, 12, 0, 0, 0, 0, 0, 0xE8, 0x03, 1, 2, 0xFE };
    const uint8_t hello[8]   = { 0xA5, 1, 2, 3, 4, 5, 6, 7 };

    AsdaWire::SetFailureHooks(&Kill, &Report, &Notify, true);
    AsdaWire::Init(AsdaSecure::SubServer::Login, L"нет_ключа.key", /*allowLegacy=*/true, &SendRaw);
    CHECK(g_notifyCng == 0, "уведомление: CNG не открылся");
    CHECK(AsdaWire::IsBypass() && !AsdaWire::IsReady(), "мост в обходе (таблицы слотов нет), шифрование не готово");

    const uint8_t* out = nullptr;
    CHECK(AsdaWire::RecvRoute(nullptr, 3, legacy, sizeof(legacy), &out) == (int)sizeof(legacy) && out == legacy,
          "AllowLegacy=1: старый клиент — RecvRoute отдаёт стоку исходные байты");
    CHECK(AsdaWire::RecvRoute(nullptr, 4, hello, sizeof(hello), &out) == (int)sizeof(hello) && out == hello && g_kills == 0,
          "AllowLegacy=1: зашифрованный ClientHello уходит стоку как есть (ответа не будет), разрыва нет");
    CHECK(AsdaWire::SendRoute(nullptr, 3, legacy, sizeof(legacy)) == 1 && g_s2c.size() == sizeof(legacy),
          "AllowLegacy=1: SendRoute шлёт кадр как есть");
    AsdaWire::ResetSlot(3);                       // детур SetConnectFlag без таблицы — ничего не делает, не падает
    CHECK(!AsdaWire::SlotFailed(3) && AsdaWire::SlotMode(3) == 0, "ResetSlot/SlotFailed/SlotMode без таблицы — безопасно");
    AsdaWire::Counters c{}; AsdaWire::GetCounters(&c);
    CHECK(c.bypass == 3, "счётчик обхода = 3 (2 приёма + 1 отправка)");

    AsdaWire::SetAllowLegacy(false);
    g_s2c.clear(); g_sent = 0;
    CHECK(AsdaWire::RecvRoute(nullptr, 5, legacy, sizeof(legacy), &out) == -1 && g_kills == 1 && g_reports == 1 && g_lastKind == 0,
          "AllowLegacy=0: первый приём → разрыв, отчёт вида 0 (сбой сервера, не нарушение клиента)");
    CHECK(AsdaWire::SendRoute(nullptr, 5, legacy, sizeof(legacy)) == 0 && g_sent == 0, "AllowLegacy=0: открытым ничего не шлётся");

    printf(g_fail == 0 ? "\n== ВСЁ СОШЛОСЬ, провалов 0 ==\n" : "\n== ПРОВАЛОВ: %d ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
