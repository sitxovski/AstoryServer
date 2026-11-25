// Copyright (c) 2026 @sitxovski (Discord)
// stand_wire.cpp — интеграционный стенд «клиент ↔ прослойка ↔ старый сервер» БЕЗ запуска серверов.
//
// Проверяет именно ВРЕЗКУ (волна В7b): серверная сторона идёт через AsdaWire (тот же мост и та же
// таблица каналов по слоту, что подключается в LoginPatch.dll/AsdaPatch.dll), клиентская — через
// AsdaSecure::ClientChannel. «Сокет» и стоковые recv/WSASend заменены байтовыми очередями: что ушло
// в очередь c2s читает серверный OnRecv, что серверный SendRaw положил в s2c — читает клиентский OnRecv.
//
// Главный инвариант: поток, который «видит старый сервер» (то, что OnRecv отдаёт стоковой recv-функции),
// БАЙТ-В-БАЙТ равен старым кадрам FB|size|A|B|op|body|FE, собранным клиентом. И наоборот для s2c.
//
// Сборка: AsdaSecure\build.bat (цель stand_wire). Итог «ВСЁ СОШЛОСЬ» / ненулевой код при провале.
#include "AsdaSecure.h"
#include "AsdaServerBridge.h"
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>

using namespace AsdaSecure;

static int g_fail = 0;
static void CHECK(bool ok, const char* what)
{
    printf("  [%s] %s\n", ok ? "OK" : "ПРОВАЛ", what);
    if (!ok) { ++g_fail; }
}

// ── «Сеть»: по две байтовые очереди на слот (c2s — к серверу, s2c — к клиенту) ──
struct Wire { std::vector<uint8_t> c2s, s2c; };
static Wire g_wire[AsdaWire::kMaxSlots];

// SendRaw серверной прослойки: стоковый Ciocp::Send кладёт байты в сокет слота → в нашу очередь s2c.
// ★ fix2: SendRawFn возвращает итог стокового Send (1 — принят).
// ★ fix2c (Н-1): ПРЕДЕЛ СТОКА — Send копирует в буфер записи 0x1000 б (`0x5653B0(tag, ov+0x1C, 0x1000, src, n)`); при n > 0x1000
//   копии нет, а WriteFile уходит с n байтами обнулённого буфера (memset при выдаче из пула 0x5681D1). Имитируем это: в сокет —
//   n нулей, счётчик g_overSend.
static int g_overSend = 0;
static int SrvSendRaw(void* /*ciocpThis*/, int slot, const void* data, int len)
{
    auto& q = g_wire[slot].s2c;
    if (len > 0x1000) { ++g_overSend; q.insert(q.end(), (size_t)len, (uint8_t)0); return 1; }
    q.insert(q.end(), (const uint8_t*)data, (const uint8_t*)data + len);
    return 1;
}
// ★ fix2c (Н-1, приём): имитация стокового разборщика CopyToWriteBuffer — порция больше 0x1000 − 9 не помещается в буфер
//   сборки слота (0x1000 вместе с обрывком заголовка < 10 б) → счётчик g_overSink; иначе байты копятся как поток стока.
static int g_overSink = 0;
static std::vector<uint8_t> g_sinkSeen[AsdaWire::kMaxSlots];
static int MockSink(void* /*self*/, const void* data, int len, int slot)
{
    if (len > 0x1000 - 9) { ++g_overSink; return 0; }
    g_sinkSeen[slot].insert(g_sinkSeen[slot].end(), (const uint8_t*)data, (const uint8_t*)data + len);
    return 1;
}

// Старый серверный парсер (заглушка): просто накапливает то, что OnRecv отдал стоковой recv-функции.
static std::vector<uint8_t> g_srvSeen[AsdaWire::kMaxSlots];

// Прогнать всё, что накопилось в c2s слота, через серверный OnRecv (с нарезкой chunk байт; 0 = целиком).
static bool PumpToServer(void* thisPtr, int slot, int chunk)
{
    auto& q = g_wire[slot].c2s;
    size_t off = 0;
    while (off < q.size())
    {
        size_t n = chunk > 0 ? (size_t)chunk : (q.size() - off);
        if (off + n > q.size()) { n = q.size() - off; }
        int outLen = 0;
        const uint8_t* dec = AsdaWire::OnRecv(thisPtr, slot, q.data() + off, (int)n, &outLen);
        if (AsdaWire::SlotFailed(slot)) { return false; }
        if (dec && outLen > 0) { g_srvSeen[slot].insert(g_srvSeen[slot].end(), dec, dec + outLen); }
        off += n;
    }
    q.clear();
    return true;
}

// ★ В7d: подставные KillFn/ReportFn — в DLL это Ciocp::GetConnectFlag+DisConnect (→ SetConnectFlag(slot,0) →
//   ResetSlot) и PatchLog+ac.other. Здесь — счётчики и тот же сброс слота, что делает стоковый DisConnect.
static int g_killCalls = 0, g_lastKillSlot = -1, g_reportCalls = 0, g_lastKind = -1, g_lastFirst = -2;
// ★ fix2b: стоковый DisConnect → SetConnectFlag(slot, 0) — разрыв (флаг 0), не accept.
static void FakeKill(void* /*self*/, int slot) { ++g_killCalls; g_lastKillSlot = slot; AsdaWire::ResetSlot(slot, 0); }
static void FakeReport(void* /*self*/, int /*slot*/, const AsdaWire::FailInfo& fi)
{
    ++g_reportCalls; g_lastKind = fi.kind; g_lastFirst = fi.firstByte;
    printf("    отчёт: %s, вид %d, режим %d, фаза %d, первый байт %d, %d б\n", ErrName(fi.err), fi.kind, fi.mode, fi.phase, fi.firstByte, fi.bytes);
}

// Старый кадр: FB | size(u16 LE, полный размер кадра) | A(u16) | B(u16) | op(u16 LE) | body | FE.
static std::vector<uint8_t> MakeFrame(uint16_t op, const std::vector<uint8_t>& body)
{
    std::vector<uint8_t> f;
    uint16_t size = (uint16_t)(9 + body.size() + 1);
    f.push_back(0xFB);
    f.push_back(size & 0xFF); f.push_back(size >> 8);
    f.push_back(0); f.push_back(0);                 // A
    f.push_back(0); f.push_back(0);                 // B
    f.push_back(op & 0xFF); f.push_back(op >> 8);
    f.insert(f.end(), body.begin(), body.end());
    f.push_back(0xFE);
    return f;
}

int main()
{
    printf("== stand_wire: клиент <-> прослойка(AsdaWire) <-> старый сервер ==\n");
    if (!AsdaSecure::Init()) { printf("bcrypt недоступен\n"); return 2; }

    // Долговременная пара сервера → файл (как кладёт keygen рядом с DLL) + открытый ключ в клиент.
    PrivateKey priv{};
    CHECK(GenerateLongTermKey(priv), "генерация долговременной пары сервера");
    wchar_t keyPath[MAX_PATH];
    { wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp); _snwprintf(keyPath, MAX_PATH, L"%sstand_wire_%lu.key", tmp, GetCurrentProcessId()); }
    CHECK(SavePrivateKeyFile(keyPath, priv), "запись secure_server.key");
    PublicKey pub{}; memcpy(pub.xy, priv.xy, kPubLen);

    // Серверная прослойка (как в DLL): под-сервер Login, ключ из файла, старый клиент разрешён.
    CHECK(AsdaWire::Init(SubServer::Login, keyPath, /*allowLegacy=*/true, &SrvSendRaw), "AsdaWire::Init + загрузка ключа");
    CHECK(AsdaWire::IsReady(), "мост готов (ключ загружен)");

    const int SEC = 5;    // слот Secure-клиента
    const int LEG = 6;    // слот старого клиента (0xFB)

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Secure-клиент: рукопожатие + байт-в-байт в обе стороны
    // ─────────────────────────────────────────────────────────────────────────
    AsdaWire::ResetSlot(SEC);                         // accept → SetConnectFlag
    ClientChannel cli; cli.Reset();
    std::vector<uint8_t> toSock;
    CHECK(cli.Start(SubServer::Login, pub, toSock) && toSock.size() == kClientHelloLen, "ClientHello собран (84 б)");
    g_wire[SEC].c2s.insert(g_wire[SEC].c2s.end(), toSock.begin(), toSock.end());

    // Сервер принимает ClientHello (нарезка по 7 байт — проверка потоковой склейки) → ServerHello в s2c.
    CHECK(PumpToServer(nullptr, SEC, 7), "сервер принял ClientHello (нарезка 7 б)");
    CHECK(g_wire[SEC].s2c.size() == kServerHelloLen, "ServerHello ушёл клиенту (148 б)");

    // Клиент пытается послать кадр ДО готовности — должен уйти в очередь (ничего в c2s).
    std::vector<uint8_t> f1 = MakeFrame(0x3EB, std::vector<uint8_t>(32, 0xAB));
    std::vector<uint8_t> out;
    CHECK(cli.OnSend(f1.data(), f1.size(), out) == Err::Ok && out.empty(), "кадр до рукопожатия отложен (не слан)");

    // Клиент получает ServerHello (проверка подписи вшитым ключом) → готов.
    std::vector<uint8_t> dummy;
    Err ce = cli.OnRecv(g_wire[SEC].s2c.data(), (int)g_wire[SEC].s2c.size(), dummy);
    g_wire[SEC].s2c.clear();
    CHECK(ce == Err::Ok && cli.IsReady(), "клиент проверил подпись сервера, рукопожатие завершено");

    // Теперь отправка второго кадра вытолкнет очередь (f1) + f2.
    std::vector<uint8_t> f2 = MakeFrame(0xFAF, std::vector<uint8_t>(10, 0x55));
    CHECK(cli.OnSend(f2.data(), f2.size(), out) == Err::Ok && !out.empty(), "кадр после рукопожатия зашифрован");
    g_wire[SEC].c2s.insert(g_wire[SEC].c2s.end(), out.begin(), out.end());
    CHECK(PumpToServer(nullptr, SEC, 0), "сервер расшифровал поток");

    std::vector<uint8_t> expect = f1; expect.insert(expect.end(), f2.begin(), f2.end());
    CHECK(g_srvSeen[SEC] == expect, "старый сервер видит кадры БАЙТ-В-БАЙТ (c2s)");

    // Обратное направление: сервер шлёт старый кадр → клиент расшифровывает байт-в-байт.
    std::vector<uint8_t> sf = MakeFrame(0x3EC, std::vector<uint8_t>(64, 0x7E));
    g_wire[SEC].s2c.clear();
    CHECK(AsdaWire::SendRoute(nullptr, SEC, sf.data(), (int)sf.size()) == 1 && !g_wire[SEC].s2c.empty(),
          "сервер зашифровал исходящий кадр и отдал стоковому Send (SendRoute, fix2)");
    std::vector<uint8_t> cliSeen;
    CHECK(cli.OnRecv(g_wire[SEC].s2c.data(), g_wire[SEC].s2c.size(), cliSeen) == Err::Ok && cliSeen == sf, "клиент видит кадр БАЙТ-В-БАЙТ (s2c)");
    g_wire[SEC].s2c.clear();

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Старый клиент (0xFB) на другом слоте одновременно — режим Legacy, байты как есть
    // ─────────────────────────────────────────────────────────────────────────
    AsdaWire::ResetSlot(LEG);
    std::vector<uint8_t> legFrame = MakeFrame(0x3E8, std::vector<uint8_t>(16, 0x42));
    g_wire[LEG].c2s = legFrame;
    CHECK(PumpToServer(nullptr, LEG, 3), "старый клиент принят (нарезка 3 б)");
    CHECK(AsdaWire::SlotMode(LEG) == 2 /*Legacy*/, "слот старого клиента в режиме Legacy");
    CHECK(g_srvSeen[LEG] == legFrame, "старый клиент: поток без изменений БАЙТ-В-БАЙТ");
    CHECK(g_srvSeen[SEC] == expect, "Secure-слот не затронут параллельным старым клиентом");

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Разрыв посередине рукопожатия — без вывода, без краха
    // ─────────────────────────────────────────────────────────────────────────
    const int HS = 7;
    AsdaWire::ResetSlot(HS);
    ClientChannel cli3; cli3.Reset(); std::vector<uint8_t> hs;
    cli3.Start(SubServer::Login, pub, hs);
    int half = (int)hs.size() / 2;
    int o = 0; AsdaWire::OnRecv(nullptr, HS, hs.data(), half, &o);
    CHECK(o == 0 && !AsdaWire::SlotFailed(HS), "половина ClientHello: нет вывода, нет ошибки");
    AsdaWire::ResetSlot(HS);                           // разрыв
    CHECK(AsdaWire::SlotMode(HS) == 0, "после разрыва слот сброшен (Unknown)");

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Мусор на входе secure-канала (первый байт не FB/A5) — отказ
    // ─────────────────────────────────────────────────────────────────────────
    const int GB = 8;
    AsdaWire::ResetSlot(GB);
    AsdaWire::SetAllowLegacy(false);                   // строгий режим: только 0xA5
    uint8_t junk[16]; for (int i = 0; i < 16; ++i) { junk[i] = (uint8_t)(0x11 * i + 1); }
    int go = 0; AsdaWire::OnRecv(nullptr, GB, junk, 16, &go);
    CHECK(AsdaWire::SlotFailed(GB), "мусорный первый байт → слот помечен к закрытию");
    AsdaWire::SetAllowLegacy(true);

    // Порча тега: взять валидный шифр-кадр и испортить последний байт.
    const int TM = 9;
    AsdaWire::ResetSlot(TM);
    ClientChannel cli4; cli4.Reset(); std::vector<uint8_t> h4; cli4.Start(SubServer::Login, pub, h4);
    g_wire[TM].c2s = h4; PumpToServer(nullptr, TM, 0);
    cli4.OnRecv(g_wire[TM].s2c.data(), (int)g_wire[TM].s2c.size(), dummy); g_wire[TM].s2c.clear();
    std::vector<uint8_t> bad; cli4.OnSend(f2.data(), f2.size(), bad);
    CHECK(!bad.empty(), "кадр для теста порчи тега собран");
    bad.back() ^= 0xFF;
    int bo = 0; AsdaWire::OnRecv(nullptr, TM, bad.data(), (int)bad.size(), &bo);
    CHECK(AsdaWire::SlotFailed(TM), "порча тега GCM → слот помечен к закрытию");

    // ─────────────────────────────────────────────────────────────────────────
    // 6. ★ В7d: активный разрыв (RecvRoute → отчёт → KillFn), виды журнала 56–59, ограничитель,
    //    сбой отправки, проверка файла ключа, выталкивание очереди клиента (Flush) сразу после рукопожатия.
    // ─────────────────────────────────────────────────────────────────────────
    {
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/true);

        // Готовый Secure-канал на слоте: рукопожатие через мост; возвращает клиента.
        auto openSecure = [&](int slot, ClientChannel& c)
        {
            AsdaWire::ResetSlot(slot); g_wire[slot].c2s.clear(); g_wire[slot].s2c.clear(); g_srvSeen[slot].clear();
            c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
            const uint8_t* o = nullptr;
            AsdaWire::RecvRoute(nullptr, slot, h.data(), (int)h.size(), &o);
            std::vector<uint8_t> d; c.OnRecv(g_wire[slot].s2c.data(), g_wire[slot].s2c.size(), d); g_wire[slot].s2c.clear();
            return c.IsReady();
        };
        auto resetFake = [] { g_killCalls = 0; g_lastKillSlot = -1; g_reportCalls = 0; g_lastKind = -1; g_lastFirst = -2; };

        // 6.1 порча тега → −1, разрыв, вид 56
        const int K1 = 20; ClientChannel c1; resetFake();
        CHECK(openSecure(K1, c1), "В7d: Secure-канал для теста разрыва открыт");
        std::vector<uint8_t> ok1; c1.OnSend(f2.data(), f2.size(), ok1);
        const uint8_t* o = nullptr;
        CHECK(AsdaWire::RecvRoute(nullptr, K1, ok1.data(), (int)ok1.size(), &o) == (int)f2.size() && o && memcmp(o, f2.data(), f2.size()) == 0,
              "В7d: годный кадр через RecvRoute — длина и байты старого кадра");
        std::vector<uint8_t> bt; c1.OnSend(f2.data(), f2.size(), bt); bt[bt.size() - 3] ^= 0x40;
        CHECK(AsdaWire::RecvRoute(nullptr, K1, bt.data(), (int)bt.size(), &o) == -1, "В7d: порча тега → RecvRoute = −1 (разрыв)");
        CHECK(g_killCalls == 1 && g_lastKillSlot == K1, "В7d: KillFn вызван ровно 1 раз для этого слота");
        CHECK(g_reportCalls == 1 && g_lastKind == AsdaWire::kKindBadTag, "В7d: отчёт 1 раз, вид 56 (порча тега)");
        CHECK(!AsdaWire::SlotFailed(K1) && AsdaWire::SlotMode(K1) == 0, "В7d: после разрыва слот сброшен (SetConnectFlag→Reset)");

        // 6.2 повтор кадра → вид 57
        const int K2 = 21; ClientChannel c2; resetFake();
        openSecure(K2, c2);
        std::vector<uint8_t> r1; c2.OnSend(f2.data(), f2.size(), r1);
        AsdaWire::RecvRoute(nullptr, K2, r1.data(), (int)r1.size(), &o);
        CHECK(AsdaWire::RecvRoute(nullptr, K2, r1.data(), (int)r1.size(), &o) == -1 && g_lastKind == AsdaWire::kKindReplay && g_killCalls == 1,
              "В7d: повтор того же кадра → разрыв, вид 57");

        // 6.3 мусор до рукопожатия (первый байт не FB/A5) → вид 58
        const int K3 = 22; resetFake(); AsdaWire::ResetSlot(K3);
        CHECK(AsdaWire::RecvRoute(nullptr, K3, junk, 16, &o) == -1 && g_lastKind == AsdaWire::kKindHandshake && g_lastFirst == junk[0],
              "В7d: мусор до рукопожатия → разрыв, вид 58, первый байт в отчёте");

        // 6.4 приветствие 0xA5 с чужой версией → вид 58
        const int K4 = 23; resetFake(); AsdaWire::ResetSlot(K4);
        { ClientChannel cv; cv.Reset(); std::vector<uint8_t> hv; cv.Start(SubServer::Login, pub, hv); hv[1] ^= 0x7F;
          CHECK(AsdaWire::RecvRoute(nullptr, K4, hv.data(), (int)hv.size(), &o) == -1 && g_lastKind == AsdaWire::kKindHandshake,
                "В7d: ClientHello чужой версии → разрыв, вид 58"); }

        // 6.5 приветствие для другого под-сервера (Game на Login) → вид 58
        const int K5 = 24; resetFake(); AsdaWire::ResetSlot(K5);
        { ClientChannel cg; cg.Reset(); std::vector<uint8_t> hg; cg.Start(SubServer::Game, pub, hg);
          CHECK(AsdaWire::RecvRoute(nullptr, K5, hg.data(), (int)hg.size(), &o) == -1 && g_lastKind == AsdaWire::kKindHandshake,
                "В7d: ClientHello другому под-серверу → разрыв, вид 58"); }

        // 6.6 старый клиент при AllowLegacy=0 → вид 58, первый байт 0xFB
        const int K6 = 25; resetFake(); AsdaWire::SetAllowLegacy(false); AsdaWire::ResetSlot(K6);
        CHECK(AsdaWire::RecvRoute(nullptr, K6, legFrame.data(), (int)legFrame.size(), &o) == -1 && g_lastKind == AsdaWire::kKindHandshake && g_lastFirst == 0xFB,
              "В7d: старый клиент (0xFB) при AllowLegacy=0 → разрыв, вид 58, первый байт 0xFB");
        AsdaWire::SetAllowLegacy(true);

        // 6.7 длина кадра больше предела (заголовок clen = 64 КБ + 17) → вид 59
        const int K7 = 26; ClientChannel c7; resetFake(); openSecure(K7, c7);
        { uint8_t hdr[12] = {}; uint32_t clen = (uint32_t)(kMaxPlain + kTagLen + 1); memcpy(hdr, &clen, 4); uint64_t sq = 1; memcpy(hdr + 4, &sq, 8);
          CHECK(AsdaWire::RecvRoute(nullptr, K7, hdr, 12, &o) == -1 && g_lastKind == AsdaWire::kKindFormat,
                "В7d: длина кадра больше 64 КБ → разрыв, вид 59"); }
        // и меньше тега
        const int K7b = 27; ClientChannel c7b; resetFake(); openSecure(K7b, c7b);
        { uint8_t hdr[12] = {}; uint32_t clen = 3; memcpy(hdr, &clen, 4);
          CHECK(AsdaWire::RecvRoute(nullptr, K7b, hdr, 12, &o) == -1 && g_lastKind == AsdaWire::kKindFormat,
                "В7d: длина кадра меньше тега → разрыв, вид 59"); }

        // 6.8 KillOnViolation=0 — откат: 0, без разрыва, отчёт один раз
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/false);
        const int K8 = 28; ClientChannel c8; resetFake(); openSecure(K8, c8);
        std::vector<uint8_t> b8; c8.OnSend(f2.data(), f2.size(), b8); b8.back() ^= 1;
        const int r8a = AsdaWire::RecvRoute(nullptr, K8, b8.data(), (int)b8.size(), &o);
        const int r8b = AsdaWire::RecvRoute(nullptr, K8, b8.data(), (int)b8.size(), &o);
        CHECK(r8a == 0 && r8b == 0 && g_killCalls == 0 && g_reportCalls == 1, "В7d: KillOnViolation=0 — кадр отброшен, разрыва нет, отчёт один");
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/true);

        // 6.9 ★ fix2c: кадр > 64 КБ (прежде — сбой шифрования, фаза 1) теперь режется на кадры ≤ 4068 открытого текста и уходит
        //     целиком (каждый Send ≤ 0x1000). Ветка «сбой шифрования на отправке» осталась для ошибок CNG — размером её не достать.
        //     Слот в ошибке (здесь — после нарушения при KillOnViolation=0) дальше не шлёт.
        const int K9 = 29; ClientChannel c9; resetFake(); openSecure(K9, c9);
        std::vector<uint8_t> huge(kMaxPlain + 100, 0x11);
        g_wire[K9].s2c.clear(); const int ov0 = g_overSend;
        std::vector<uint8_t> hugeSeen;
        CHECK(AsdaWire::SendRoute(nullptr, K9, huge.data(), (int)huge.size()) == 1 && g_overSend == ov0
              && c9.OnRecv(g_wire[K9].s2c.data(), g_wire[K9].s2c.size(), hugeSeen) == Err::Ok && hugeSeen == huge,
              "fix2c: кадр 64 КБ + 100 — кусками по ≤ 4068, ни один Send не длиннее 0x1000, клиент получил его целиком");
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/false);
        std::vector<uint8_t> b9; c9.OnSend(f2.data(), f2.size(), b9); b9.back() ^= 1;
        AsdaWire::RecvRoute(nullptr, K9, b9.data(), (int)b9.size(), &o);
        g_wire[K9].s2c.clear();
        CHECK(AsdaWire::SendRoute(nullptr, K9, f2.data(), (int)f2.size()) == 0 && g_wire[K9].s2c.empty(),
              "В7d: слот в ошибке — дальнейшие отправки не уходят");
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/true);
        std::vector<uint8_t> g9; c9.OnSend(f2.data(), f2.size(), g9);
        CHECK(AsdaWire::RecvRoute(nullptr, K9, g9.data(), (int)g9.size(), &o) == -1 && g_killCalls == 1 && g_reportCalls == 1,
              "В7d: ближайший приём слота в ошибке → разрыв без второго отчёта");

        // 6.10 ограничитель строк PatchLog: 3 в минуту → из 5 подряд 3 разрешены, 2 подавлены
        AsdaWire::SetLogPerMinute(3);
        AsdaWire::Counters before{}; AsdaWire::GetCounters(&before);
        int allowed = 0; for (int i = 0; i < 5; ++i) { int sp = 0; if (AsdaWire::LogAllow(&sp)) { ++allowed; } }
        AsdaWire::Counters after{}; AsdaWire::GetCounters(&after);
        CHECK(allowed <= 3 && (after.logSuppressed - before.logSuppressed) >= 2, "В7d: ограничитель LogPerMinute=3 — лишние строки подавлены и посчитаны");
        AsdaWire::SetLogPerMinute(0);
        int sp0 = -1; CHECK(AsdaWire::LogAllow(&sp0) && sp0 >= 2, "В7d: без предела — строка разрешена и несёт число подавленных");

        // 6.11 проверка файла ключа без CNG
        wchar_t why[96];
        CHECK(AsdaWire::CheckKeyFile(keyPath, why, 96), "В7d: CheckKeyFile — годный ключ (104 б, ASDAKEY1)");
        wchar_t miss[MAX_PATH]; _snwprintf(miss, MAX_PATH, L"%s.нет", keyPath);
        CHECK(!AsdaWire::CheckKeyFile(miss, why, 96), "В7d: CheckKeyFile — нет файла → отказ с причиной");
        wchar_t badp[MAX_PATH]; _snwprintf(badp, MAX_PATH, L"%s.bad", keyPath);
        { FILE* f = _wfopen(badp, L"wb"); if (f) { fwrite("ASDAKEY1", 1, 8, f); fclose(f); } }
        CHECK(!AsdaWire::CheckKeyFile(badp, why, 96), "В7d: CheckKeyFile — обрезанный файл (8 б) → отказ");
        { FILE* f = _wfopen(badp, L"wb"); if (f) { std::vector<uint8_t> z(104, 0x33); fwrite(z.data(), 1, z.size(), f); fclose(f); } }
        CHECK(!AsdaWire::CheckKeyFile(badp, why, 96), "В7d: CheckKeyFile — 104 б без метки ASDAKEY1 → отказ");
        DeleteFileW(badp);

        // 6.12 клиент: кадр до рукопожатия выталкивается Flush сразу после ServerHello (без следующей отправки)
        const int K12 = 30; AsdaWire::ResetSlot(K12); g_srvSeen[K12].clear();
        ClientChannel cf; cf.Reset(); std::vector<uint8_t> hf; cf.Start(SubServer::Login, pub, hf);
        std::vector<uint8_t> early = MakeFrame(0x4E20 /*20000*/, std::vector<uint8_t>(40, 0x2C)), tmp;
        cf.OnSend(early.data(), early.size(), tmp);
        CHECK(tmp.empty() && cf.HasPending(), "В7d: кадр входа до рукопожатия в очереди клиента");
        AsdaWire::RecvRoute(nullptr, K12, hf.data(), (int)hf.size(), &o);
        std::vector<uint8_t> d12; cf.OnRecv(g_wire[K12].s2c.data(), g_wire[K12].s2c.size(), d12); g_wire[K12].s2c.clear();
        std::vector<uint8_t> fl; Err fe = cf.Flush(fl);
        CHECK(fe == Err::Ok && !fl.empty() && !cf.HasPending(), "В7d: Flush после ServerHello выдал шифротекст очереди");
        const int n12 = AsdaWire::RecvRoute(nullptr, K12, fl.data(), (int)fl.size(), &o);
        CHECK(n12 == (int)early.size() && o && memcmp(o, early.data(), early.size()) == 0, "В7d: сервер получил отложенный кадр БАЙТ-В-БАЙТ без следующей отправки");
        std::vector<uint8_t> fl2; CHECK(cf.Flush(fl2) == Err::Ok && fl2.empty(), "В7d: повторный Flush — пусто");

        // 6.13 клиент против сервера БЕЗ шифрования: сток отвечает старым кадром (0xFB…) → BadMagic сразу,
        //      частичный ServerHello → ни ошибки, ни готовности (это добирает срок ожидания клиента).
        { ClientChannel cl; cl.Reset(); std::vector<uint8_t> h, d; cl.Start(SubServer::Login, pub, h);
          std::vector<uint8_t> stockReply = MakeFrame(0x1005, std::vector<uint8_t>(6, 0));
          CHECK(cl.OnRecv(stockReply.data(), stockReply.size(), d) == Err::BadMagic && !cl.IsReady(),
                "В7d: клиент — ответ сервера без шифрования (0xFB…) → BadMagic сразу, без ожидания 148 б"); }
        { ClientChannel cl; cl.Reset(); std::vector<uint8_t> h, d; cl.Start(SubServer::Login, pub, h);
          AsdaWire::ResetSlot(31); g_wire[31].s2c.clear();
          const uint8_t* oo = nullptr; AsdaWire::RecvRoute(nullptr, 31, h.data(), (int)h.size(), &oo);
          std::vector<uint8_t> sh = g_wire[31].s2c; g_wire[31].s2c.clear();
          CHECK(cl.OnRecv(sh.data(), 40, d) == Err::Ok && !cl.IsReady(), "В7d: клиент — часть ServerHello: нет ошибки, нет готовности (ждёт срок)");
          sh[100] ^= 0x01;      // подменить байт подписи (84..147; первые 40 б уже приняты) → подпись не сойдётся
          CHECK(cl.OnRecv(sh.data() + 40, sh.size() - 40, d) == Err::BadSignature, "В7d: клиент — подменённый ServerHello → BadSignature"); }
        { ClientChannel cl; cl.Reset(); std::vector<uint8_t> h, d; cl.Start(SubServer::Login, pub, h);
          std::vector<uint8_t> fake(kServerHelloLen, 0); fake[0] = kServerMagic; fake[1] = (uint8_t)(kVersion + 1);
          CHECK(cl.OnRecv(fake.data(), fake.size(), d) == Err::BadVersion, "В7d: клиент — ServerHello чужой версии → BadVersion"); }
        // s2c: порча / повтор кадра сервера → клиент отвергает
        { const int K14 = 32; ClientChannel cc14; openSecure(K14, cc14);
          g_wire[K14].s2c.clear(); AsdaWire::SendRoute(nullptr, K14, f2.data(), (int)f2.size());
          std::vector<uint8_t> s1 = g_wire[K14].s2c, d1, d2; g_wire[K14].s2c.clear();
          CHECK(cc14.OnRecv(s1.data(), s1.size(), d1) == Err::Ok && d1 == f2, "В7d: клиент принял кадр сервера");
          CHECK(cc14.OnRecv(s1.data(), s1.size(), d2) == Err::Replay, "В7d: клиент — повтор кадра сервера → Replay");
          ClientChannel cc15; openSecure(K14, cc15);
          g_wire[K14].s2c.clear(); AsdaWire::SendRoute(nullptr, K14, f2.data(), (int)f2.size());
          std::vector<uint8_t> s2 = g_wire[K14].s2c, d3; g_wire[K14].s2c.clear(); s2[14] ^= 0x80;
          CHECK(cc15.OnRecv(s2.data(), s2.size(), d3) == Err::BadTag, "В7d: клиент — порча кадра сервера → BadTag"); }

        AsdaWire::Counters cc{}; AsdaWire::GetCounters(&cc);
        printf("  счётчики моста: разрывов %ld, отчётов %ld, подавлено строк %ld, сбоев отправки %ld\n", cc.kills, cc.reports, cc.logSuppressed, cc.sendFails);
        AsdaWire::SetFailureHooks(nullptr, nullptr, nullptr, true);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. ★ fix2 (ревизия INTEG3 Б-1/Б-2): отложенный сброс слота и атомарная отправка
    // ─────────────────────────────────────────────────────────────────────────
    {
        // 7.1 переиспользованный слот: старая сессия → DisConnect (ResetSlot) → accept (ResetSlot) → новый клиент.
        //     Новый клиент НИКОГДА не видит старых ключей/номеров: его рукопожатие проходит, кадры сервера — новым ключом.
        const int R = 40;
        AsdaWire::ResetSlot(R); g_wire[R].s2c.clear(); g_srvSeen[R].clear();
        ClientChannel oldc; oldc.Reset(); std::vector<uint8_t> ho; oldc.Start(SubServer::Login, pub, ho);
        const uint8_t* o = nullptr;
        AsdaWire::RecvRoute(nullptr, R, ho.data(), (int)ho.size(), &o);
        std::vector<uint8_t> d; oldc.OnRecv(g_wire[R].s2c.data(), g_wire[R].s2c.size(), d); g_wire[R].s2c.clear();
        CHECK(oldc.IsReady() && AsdaWire::SlotMode(R) == 1, "fix2: старая Secure-сессия на слоте открыта");
        for (int i = 0; i < 5; ++i) { AsdaWire::SendRoute(nullptr, R, f2.data(), (int)f2.size()); }
        g_wire[R].s2c.clear();
        AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
        AsdaWire::ResetSlot(R);                         // DisConnect → SetConnectFlag(X,0) — под L, без замка слота
        AsdaWire::ResetSlot(R);                         // accept     → SetConnectFlag(X,1) — до первого чтения
        AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
        CHECK(c1.resetsApplied == c0.resetsApplied, "fix2: ResetSlot сам сброс не применяет (только запрос, без замка слота)");
        ClientChannel newc; newc.Reset(); std::vector<uint8_t> hn; newc.Start(SubServer::Login, pub, hn);
        AsdaWire::RecvRoute(nullptr, R, hn.data(), (int)hn.size(), &o);
        AsdaWire::Counters c2{}; AsdaWire::GetCounters(&c2);
        CHECK(c2.resetsApplied == c0.resetsApplied + 1, "fix2: два запроса сброса применены одним сбросом на первом приёме нового клиента");
        CHECK(g_wire[R].s2c.size() == kServerHelloLen, "fix2: новый клиент получил ServerHello (не старый шифротекст)");
        std::vector<uint8_t> dn;
        CHECK(newc.OnRecv(g_wire[R].s2c.data(), g_wire[R].s2c.size(), dn) == Err::Ok && newc.IsReady(),
              "fix2: рукопожатие нового клиента на переиспользованном слоте прошло");
        g_wire[R].s2c.clear();
        CHECK(AsdaWire::SendRoute(nullptr, R, f2.data(), (int)f2.size()) == 1, "fix2: SendRoute после рукопожатия = итог стокового Send (1)");
        std::vector<uint8_t> sN = g_wire[R].s2c, pn, po; g_wire[R].s2c.clear();
        CHECK(newc.OnRecv(sN.data(), sN.size(), pn) == Err::Ok && pn == f2, "fix2: новый клиент расшифровал кадр (номер кадра начат заново)");
        CHECK(oldc.OnRecv(sN.data(), sN.size(), po) != Err::Ok, "fix2: старым ключом этот кадр не расшифровать");

        // 7.2 SendRoute до рукопожатия: 1 (в очереди канала), в сокет ничего; после ClientHello — ServerHello + очередь.
        const int Q = 41;
        AsdaWire::ResetSlot(Q); g_wire[Q].s2c.clear();
        CHECK(AsdaWire::SendRoute(nullptr, Q, f2.data(), (int)f2.size()) == 1 && g_wire[Q].s2c.empty(),
              "fix2: SendRoute до рукопожатия — кадр в очереди канала, в сокет ничего");
        ClientChannel qc; qc.Reset(); std::vector<uint8_t> hq; qc.Start(SubServer::Login, pub, hq);
        AsdaWire::RecvRoute(nullptr, Q, hq.data(), (int)hq.size(), &o);
        std::vector<uint8_t> dq;
        CHECK(g_wire[Q].s2c.size() > kServerHelloLen && qc.OnRecv(g_wire[Q].s2c.data(), g_wire[Q].s2c.size(), dq) == Err::Ok && dq == f2,
              "fix2: очередь до рукопожатия ушла за ServerHello тем же вызовом стокового Send");
        g_wire[Q].s2c.clear();

        // 7.3 Legacy-слот: SendRoute отдаёт кадр как есть.
        const int L = 42;
        AsdaWire::ResetSlot(L); g_wire[L].s2c.clear(); g_srvSeen[L].clear();
        g_wire[L].c2s = legFrame; PumpToServer(nullptr, L, 0);
        CHECK(AsdaWire::SendRoute(nullptr, L, sf.data(), (int)sf.size()) == 1 && g_wire[L].s2c == sf, "fix2: Legacy-слот — SendRoute шлёт кадр как есть");
        g_wire[L].s2c.clear();

        // 7.4 слот вне таблицы — сток как есть (у Ciocp не бывает, защитная ветка)
        CHECK(AsdaWire::RecvRoute(nullptr, AsdaWire::kMaxSlots, legFrame.data(), (int)legFrame.size(), &o) == (int)legFrame.size() && o == legFrame.data(),
              "fix2: RecvRoute для слота вне таблицы — байты стоку как есть");
        CHECK(!AsdaWire::IsBypass(), "fix2: CNG открыт — обхода нет");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. ★ fix2b: кадры сервера ДО рукопожатия (отказ LM 4101/2253, GS 6004 сразу после accept + DisConnect)
    // ─────────────────────────────────────────────────────────────────────────
    {
        AsdaWire::SetFailureHooks(&FakeKill, &FakeReport, nullptr, /*killOnViolation=*/true);
        AsdaWire::SetPreHandshake(64 * 1024, 5000, 0x00400000, 0x00400100);   // IoWorker — условный диапазон стенда
        AsdaWire::SetLingerMs(0);   // 8.1–8.8 — разрыв сразу после выдачи (поведение fix2b); пауза Н-2 — в 8.9
        const std::vector<uint8_t> refuse2253 = MakeFrame(2253, { 0x07, 0x00 });                 // «сервер переполнен» LM
        const std::vector<uint8_t> refuse4101 = MakeFrame(4101, { 22 });                         // «IP заблокирован» LM
        auto resetFake = [] { g_killCalls = 0; g_lastKillSlot = -1; g_reportCalls = 0; g_lastKind = -1; g_lastFirst = -2; };
        const uint8_t* o = nullptr;
        const uintptr_t kLogicRet = 0x00405A90;   // DisConnect из логики (ProcConnect), не из IoWorker

        // 8.1 Secure-клиент: 2253 до ClientHello + DisConnect → разрыв отложен → ClientHello → ServerHello + 2253 → разрыв
        { const int X = 50; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
          CHECK(AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size()) == 1 && g_wire[X].s2c.empty(),
                "fix2b: отказ 2253 до рукопожатия — в очереди слота, в сокет ничего");
          CHECK(AsdaWire::DisconnectGate(nullptr, X, kLogicRet), "fix2b: DisConnect при невыданной очереди — отложен");
          CHECK(AsdaWire::DisconnectGate(nullptr, X, kLogicRet), "fix2b: повторный DisConnect тоже ждёт");
          CHECK(AsdaWire::SendRoute(nullptr, X, f2.data(), (int)f2.size()) == 0, "fix2b: после отложенного DisConnect новые кадры не принимаются (как сток при флаге 0)");
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          CHECK(AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o) == -1 && g_killCalls == 1 && g_lastKillSlot == X,
                "fix2b: ClientHello → очередь выдана, отложенный DisConnect выполнен (RecvRoute = −1, KillFn 1 раз)");
          std::vector<uint8_t> d;
          CHECK(g_wire[X].s2c.size() > kServerHelloLen && c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && c.IsReady() && d == refuse2253,
                "fix2b: Secure-клиент получил ServerHello и за ним 2253 БАЙТ-В-БАЙТ (шифрованным)");
          AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
          CHECK(c1.preQueued - c0.preQueued == 1 && c1.preFlushed - c0.preFlushed == 1 && c1.deferredCloses - c0.deferredCloses == 1,
                "fix2b: счётчики — в очередь 1, выдач 1, отложенных разрывов 1");
          CHECK(!AsdaWire::DisconnectGate(nullptr, X, kLogicRet), "fix2b: после разрыва ворота DisConnect пропускают сток");
          g_wire[X].s2c.clear(); }

        // 8.2 Legacy-клиент: 2253 + DisConnect до первого байта → первый кадр клиента → 2253 как есть → разрыв, кадр клиента стоку не отдан
        { const int X = 51; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          AsdaWire::DisconnectGate(nullptr, X, kLogicRet);
          o = nullptr;
          CHECK(AsdaWire::RecvRoute(nullptr, X, legFrame.data(), (int)legFrame.size(), &o) == -1 && o == nullptr && g_killCalls == 1,
                "fix2b: Legacy — первый кадр клиента → разрыв (кадр стоку не отдан, в стоке сокет был бы закрыт)");
          CHECK(g_wire[X].s2c == refuse2253, "fix2b: Legacy-клиент получил 2253 как есть, БАЙТ-В-БАЙТ");
          g_wire[X].s2c.clear(); }

        // 8.3 отказ без DisConnect (4101 код 22 «IP заблокирован»): два кадра до рукопожатия — по порядку за ServerHello, сессия живёт
        { const int X = 52; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear(); g_srvSeen[X].clear();
          AsdaWire::SendRoute(nullptr, X, refuse4101.data(), (int)refuse4101.size());
          AsdaWire::SendRoute(nullptr, X, sf.data(), (int)sf.size());
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          CHECK(AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o) == 0 && g_killCalls == 0, "fix2b: без DisConnect — разрыва нет");
          std::vector<uint8_t> d, want = refuse4101; want.insert(want.end(), sf.begin(), sf.end());
          CHECK(c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == want, "fix2b: 4101 и следующий кадр — по порядку за ServerHello");
          g_wire[X].s2c.clear();
          std::vector<uint8_t> up; c.OnSend(f2.data(), f2.size(), up);
          CHECK(AsdaWire::RecvRoute(nullptr, X, up.data(), (int)up.size(), &o) == (int)f2.size() && memcmp(o, f2.data(), f2.size()) == 0,
                "fix2b: дальше сессия работает (кадр клиента расшифрован)");
          AsdaWire::SendRoute(nullptr, X, f2.data(), (int)f2.size());
          std::vector<uint8_t> d2; CHECK(c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d2) == Err::Ok && d2 == f2,
                "fix2b: номер кадра сервера после очереди — следующий (порядок seq верный)");
          g_wire[X].s2c.clear(); }

        // 8.4 сброс accept не стирает очередь нового соединения; кадр после разрыва (флаг 0) не копится — как сток
        { const int X = 53; resetFake(); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          AsdaWire::ResetSlot(X, 0);                                                            // разрыв прошлой сессии
          CHECK(AsdaWire::SendRoute(nullptr, X, f2.data(), (int)f2.size()) == 0, "fix2b: кадр после разрыва (флаг 0) — отвергнут, как стоковый Send");
          AsdaWire::ResetSlot(X, 1);                                                            // accept нового соединения
          AsdaWire::SendRoute(nullptr, X, refuse4101.data(), (int)refuse4101.size());           // отказ новому соединению
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o);
          std::vector<uint8_t> d; CHECK(c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == refuse4101,
                "fix2b: новому клиенту ушёл только его 4101 (кадр прошлой сессии не попал, сброс accept очередь не стёр)");
          g_wire[X].s2c.clear(); }

        // 8.5 предел очереди: сверх PreHandshakeQueueKB — отбрасывается и считается, остальное уходит
        { const int X = 54; resetFake(); AsdaWire::SetPreHandshake(100, 5000, 0x00400000, 0x00400100);
          AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
          const std::vector<uint8_t> big = MakeFrame(0x401, std::vector<uint8_t>(80, 0x31));
          const int r1 = AsdaWire::SendRoute(nullptr, X, big.data(), (int)big.size());
          const int r2 = AsdaWire::SendRoute(nullptr, X, big.data(), (int)big.size());
          AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
          CHECK(r1 == 1 && r2 == 0 && c1.preDropped - c0.preDropped == 1, "fix2b: предел очереди 100 б — второй кадр 90 б отброшен (preDropped +1), Send вернул 0");
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o);
          std::vector<uint8_t> d; CHECK(c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == big, "fix2b: принятый в очередь кадр дошёл");
          g_wire[X].s2c.clear(); AsdaWire::SetPreHandshake(64 * 1024, 5000, 0x00400000, 0x00400100); }

        // 8.6 DisConnect из IoWorkerThread (нулевой приём — сокет мёртв) не откладывается даже при невыданной очереди
        { const int X = 55; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1);
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          CHECK(!AsdaWire::DisconnectGate(nullptr, X, 0x00400080), "fix2b: DisConnect из IoWorkerThread — сток сразу (выдать некому)");
          AsdaWire::ResetSlot(X, 0); }

        // 8.7 клиент молчит — сторож закрывает по сроку PreHandshakeCloseMs (300 мс)
        { const int X = 56; resetFake(); AsdaWire::SetPreHandshake(64 * 1024, 300, 0x00400000, 0x00400100);
          AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1);
          AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          AsdaWire::DisconnectGate(nullptr, X, kLogicRet);
          for (int i = 0; i < 40 && g_killCalls == 0; ++i) { Sleep(50); }
          AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
          CHECK(g_killCalls == 1 && g_lastKillSlot == X && c1.deferTimeouts - c0.deferTimeouts == 1,
                "fix2b: клиент не прислал ни байта — сторож выполнил отложенный DisConnect по сроку");
          AsdaWire::SetPreHandshake(64 * 1024, 5000, 0x00400000, 0x00400100); }

        // 8.8 нарушение при отложенном разрыве: мусор вместо ClientHello → один разрыв, отчёт вида 58
        { const int X = 57; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1);
          AsdaWire::SetAllowLegacy(false);
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          AsdaWire::DisconnectGate(nullptr, X, kLogicRet);
          CHECK(AsdaWire::RecvRoute(nullptr, X, junk, 16, &o) == -1 && g_killCalls == 1 && g_reportCalls == 1 && g_lastKind == AsdaWire::kKindHandshake,
                "fix2b: мусор при отложенном разрыве — ровно один разрыв, отчёт вида 58");
          AsdaWire::SetAllowLegacy(true); }

        // ── ★ fix2c ──
        // 8.9 (Н-2) пауза 150 мс между выдачей отказа и разрывом: RecvRoute = −1 сразу, разрыв — сторожем не раньше 150 мс
        { const int X = 58; resetFake(); AsdaWire::SetLingerMs(150); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          AsdaWire::DisconnectGate(nullptr, X, kLogicRet);
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          const DWORD t0 = GetTickCount();
          const int r = AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o);
          const bool notYet = (g_killCalls == 0);
          std::vector<uint8_t> d; const bool got = c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == refuse2253;
          for (int i = 0; i < 40 && g_killCalls == 0; ++i) { Sleep(25); }
          const DWORD dt = GetTickCount() - t0;
          CHECK(r == -1 && notYet && got && g_killCalls == 1 && dt >= 140,
                "fix2c (Н-2): отказ выдан сразу, разрыв — сторожем через ≥ 150 мс (сокет стока закрывается RST)");
          printf("    пауза до разрыва: %lu мс\n", (unsigned long)dt);
          AsdaWire::SetLingerMs(0); }

        // 8.10 (Н-3) сброс слота после откладывания (DisConnect_NoLock + новое соединение) — отложенный разрыв НЕ задевает его
        { const int X = 59; resetFake(); AsdaWire::SetPreHandshake(64 * 1024, 200, 0x00400000, 0x00400100);
          AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1);
          AsdaWire::Counters c0{}; AsdaWire::GetCounters(&c0);
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          AsdaWire::DisconnectGate(nullptr, X, kLogicRet);
          AsdaWire::ResetSlot(X, 0);     // DisConnect_NoLock (ошибка WriteFile в Send) — мимо ворот: SetConnectFlag(X,0)
          AsdaWire::ResetSlot(X, 1);     // accept нового клиента на том же слоте
          for (int i = 0; i < 40; ++i) { Sleep(25); AsdaWire::Counters cc{}; AsdaWire::GetCounters(&cc); if (cc.deferStale > c0.deferStale) { break; } }
          AsdaWire::Counters c1{}; AsdaWire::GetCounters(&c1);
          CHECK(g_killCalls == 0 && c1.deferStale - c0.deferStale == 1, "fix2c (Н-3): отложенный разрыв снят по поколению — новое соединение не тронуто");
          AsdaWire::SetPreHandshake(64 * 1024, 5000, 0x00400000, 0x00400100); AsdaWire::ResetSlot(X, 0); }

        // 8.11 (Н-4) клиент сам закрыл соединение при отложенном разрыве — DisConnect из IoWorker идёт сразу (отложенный снят)
        { const int X = 60; resetFake(); AsdaWire::SetPreHandshake(64 * 1024, 200, 0x00400000, 0x00400100);
          AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1);
          AsdaWire::SendRoute(nullptr, X, refuse2253.data(), (int)refuse2253.size());
          CHECK(AsdaWire::DisconnectGate(nullptr, X, kLogicRet), "fix2c (Н-4): DisConnect логики — отложен");
          CHECK(!AsdaWire::DisconnectGate(nullptr, X, 0x00400080), "fix2c (Н-4): нулевой приём (IoWorker) при отложенном — сток сразу (сокет освобождается)");
          Sleep(500);                                                   // сторожу хватило бы 200 мс — он не должен разрывать второй раз
          CHECK(g_killCalls == 0, "fix2c (Н-4): отложенный разрыв снят — сторож второй DisConnect не делает");
          AsdaWire::ResetSlot(X, 0); AsdaWire::SetPreHandshake(64 * 1024, 5000, 0x00400000, 0x00400100); }

        // 8.12 (Н-1/Н-5) очередь до рукопожатия > 4 КБ — выдача кусками в пределе Send (Secure и Legacy)
        { const int X = 61; resetFake(); AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
          const int ov0 = g_overSend;
          std::vector<uint8_t> want;
          for (int i = 0; i < 4; ++i) { std::vector<uint8_t> f = MakeFrame((uint16_t)(0x500 + i), std::vector<uint8_t>(2500, (uint8_t)(0x40 + i)));
                                        AsdaWire::SendRoute(nullptr, X, f.data(), (int)f.size()); want.insert(want.end(), f.begin(), f.end()); }
          ClientChannel c; c.Reset(); std::vector<uint8_t> h; c.Start(SubServer::Login, pub, h);
          AsdaWire::RecvRoute(nullptr, X, h.data(), (int)h.size(), &o);
          std::vector<uint8_t> d;
          CHECK(g_overSend == ov0 && c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == want,
                "fix2c (Н-5): очередь 10 КБ до рукопожатия — Secure-клиенту кусками ≤ 0x1000, поток цел");
          const int Y = 62; AsdaWire::ResetSlot(Y, 0); AsdaWire::ResetSlot(Y, 1); g_wire[Y].s2c.clear(); g_srvSeen[Y].clear();
          for (int i = 0; i < 4; ++i) { std::vector<uint8_t> f = MakeFrame((uint16_t)(0x500 + i), std::vector<uint8_t>(2500, (uint8_t)(0x40 + i)));
                                        AsdaWire::SendRoute(nullptr, Y, f.data(), (int)f.size()); }
          g_wire[Y].c2s = legFrame; PumpToServer(nullptr, Y, 0);
          CHECK(g_overSend == ov0 && g_wire[Y].s2c == want, "fix2c (Н-5): очередь 10 КБ — Legacy-клиенту как есть кусками ≤ 0x1000");
          AsdaWire::ResetSlot(X, 0); AsdaWire::ResetSlot(Y, 0); }

        // 8.13 (Н-1) пакеты стока 4095 / 4096 / 8200 б на готовый Secure-канал: каждый Send ≤ 0x1000, поток цел
        { const int X = 63; ClientChannel c;
          { std::vector<uint8_t> h0; c.Reset(); c.Start(SubServer::Login, pub, h0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
            AsdaWire::RecvRoute(nullptr, X, h0.data(), (int)h0.size(), &o); std::vector<uint8_t> d0;
            c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d0); g_wire[X].s2c.clear(); }
          const int ov0 = g_overSend;
          std::vector<uint8_t> want;
          for (int len : { 4095, 4096, 8200, 4068, 4069 }) { std::vector<uint8_t> f(len, (uint8_t)(len & 0xFF)); f[0] = 0xFB;
                                                            AsdaWire::SendRoute(nullptr, X, f.data(), (int)f.size()); want.insert(want.end(), f.begin(), f.end()); }
          std::vector<uint8_t> d;
          CHECK(g_overSend == ov0 && c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d) == Err::Ok && d == want,
                "fix2c (Н-1): пакеты 4095/4096/8200/4068/4069 б — ни один Send не длиннее 0x1000, клиент получил поток целиком");
          AsdaWire::ResetSlot(X, 0); }

        // 8.14 (Н-1, приём) кадр клиента 12 КБ (очередь Flush) — стоку кусками ≤ 0x1000 − 9, поток цел
        { const int X = 64; ClientChannel c;
          { std::vector<uint8_t> h0; c.Reset(); c.Start(SubServer::Login, pub, h0); AsdaWire::ResetSlot(X, 1); g_wire[X].s2c.clear();
            AsdaWire::RecvRoute(nullptr, X, h0.data(), (int)h0.size(), &o); std::vector<uint8_t> d0;
            c.OnRecv(g_wire[X].s2c.data(), g_wire[X].s2c.size(), d0); g_wire[X].s2c.clear(); }
          g_sinkSeen[X].clear();
          AsdaWire::SetRecvSink(&MockSink);
          std::vector<uint8_t> big; for (int i = 0; i < 20; ++i) { std::vector<uint8_t> f = MakeFrame(0x3EB, std::vector<uint8_t>(600, (uint8_t)i)); big.insert(big.end(), f.begin(), f.end()); }
          std::vector<uint8_t> ct; c.OnSend(big.data(), big.size(), ct);
          const int os0 = g_overSink;
          const int r = AsdaWire::RecvRoute(nullptr, X, ct.data(), (int)ct.size(), &o);
          CHECK(r == 0 && g_overSink == os0 && g_sinkSeen[X] == big, "fix2c (Н-1): приём 12 КБ — разборщику стока кусками ≤ 4087, поток цел");
          AsdaWire::SetRecvSink(nullptr); AsdaWire::ResetSlot(X, 0); }

        AsdaWire::SetLingerMs(150);
        AsdaWire::SetFailureHooks(nullptr, nullptr, nullptr, true);
    }
    CHECK(g_overSend == 0, "fix2c (Н-1): за весь стенд ни одного вызова стокового Send длиннее 0x1000");

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Замер: µс на кадр через полный путь прослойки (seal на сервере + open у клиента)
    // ─────────────────────────────────────────────────────────────────────────
    {
        const int N = 20000;
        std::vector<uint8_t> body(256, 0x5A);
        std::vector<uint8_t> frame = MakeFrame(0x401, body);
        AsdaWire::ResetSlot(SEC);                       // свежий канал под замер
        ClientChannel m; m.Reset(); std::vector<uint8_t> mh; m.Start(SubServer::Login, pub, mh);
        g_wire[SEC].c2s = mh; g_srvSeen[SEC].clear(); PumpToServer(nullptr, SEC, 0);
        m.OnRecv(g_wire[SEC].s2c.data(), (int)g_wire[SEC].s2c.size(), dummy); g_wire[SEC].s2c.clear();
        LARGE_INTEGER fq, t0, t1; QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; ++i)
        {
            g_wire[SEC].s2c.clear(); AsdaWire::SendRoute(nullptr, SEC, frame.data(), (int)frame.size());
            std::vector<uint8_t> seen; m.OnRecv(g_wire[SEC].s2c.data(), g_wire[SEC].s2c.size(), seen);
        }
        QueryPerformanceCounter(&t1);
        double us = (double)(t1.QuadPart - t0.QuadPart) * 1e6 / fq.QuadPart / N;
        printf("  замер: %d кадров по %u б, %.3f мкс/кадр (seal сервер + open клиент)\n", N, (unsigned)frame.size(), us);
    }

    DeleteFileW(keyPath);
    printf(g_fail == 0 ? "\n== ВСЁ СОШЛОСЬ, провалов 0 ==\n" : "\n== ПРОВАЛОВ: %d ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
