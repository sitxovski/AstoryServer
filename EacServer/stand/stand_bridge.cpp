// Copyright (c) 2026 @sitxovski (Discord)
// stand_bridge.cpp — стенд (б): фальшивый P73 на мосту 127.0.0.1:15702 (протокол v2, ред. 3) против AsdaEacServer_stand.exe.
// Политика §5–§6 и §8: KICK 1 по BindTimeout, Mode 1 / FailOpen / оператор — без KICK, повтор KICK, LOGOUT, сброс таблицы по HELLO,
// REBIND; ред. 3 — защищена только Authenticated (RemoteAuthComplete) + совпавший ненулевой BIND (E1-01, E1-02): REG без
// RemoteAuthComplete → 4, только LocalAuthComplete → 4, карусель REG не продлевает отсчёт и упирается в лимит 3 REG/окно,
// вытеснение защищённой сессии → 4 через Grace, нет BIND / чужой BIND / нулевой bind → 6 (serverKind BIND не сверяется), RequireSameIp → 6;
// FailOpen по порогам (E1-03): одна временная REG не отключает кики, 5 IP — отключают; §8.6 R3-03: освобождения одной учётки нет;
// AsdaId деградировал → FailOpen (E1-09); ошибки вызовов EOS → FailOpen; HELLO ver=1 и чужой pid / образ процесса → отказ (E1-13);
// Mode 1: вытеснение без KICK клиенту (E1-18); разовое ожидание идущей проверки токена той же учётки (E1-12).
// §8.6 (REVIEW_R3): B24 — лимит REG 6/10 мин по умолчанию, REG, вытесняющая Authenticated с того же IP, в лимит не считается (R3-01);
// B25 — «P61 у процесса не активен» (≥ 5 LOGIN с нулевым bind за 120 с после HELLO): причина 6 не применяется, причина 1 работает (R3-04).
#include "StandCommon.h"
#include <thread>
#include <set>

using namespace Stand;

namespace
{
    const int kId = 18445, kSide = 25711, kBr = 25712;   // порты стенда
    AsdaSecure::PublicKey g_pub;

    // Ожидаемый KICK от сайдкара.
    struct Kick { uint16_t un = 0; uint32_t ui = 0; uint8_t reason = 0, eos = 0; };

    std::vector<uint8_t> Logout(uint16_t un, uint32_t ui, uint32_t seq) { std::vector<uint8_t> p; PutU16(p, un); PutU32(p, ui); PutU32(p, seq); return p; }

    // Ждать KICK. 1 — получен, 0 — нет за время, -1 — соединение закрыто.
    int WaitKick(PlainClient& c, Kick& k, int timeoutMs)
    {
        std::vector<uint8_t> p;
        int r = c.RecvType(0x21, p, timeoutMs);
        if (r != 1) return r;
        if (p.size() != 8) return -1;
        k.un = GetU16(p.data()); k.ui = GetU32(p.data() + 2); k.reason = p[6]; k.eos = p[7];
        return 1;
    }

    // Пинговать мост, пока ждём (P73 шлёт PING каждые 5 с).
    void Ping(PlainClient& c) { c.Send(0x14, {}); }

    // P73 v2 с HELLO от своего pid.
    bool OpenP73(PlainClient& c, uint8_t kind = 2, uint16_t port = 15601)
    {
        if (!c.Open(kBr)) return false;
        return c.Send(0x10, HelloV(2, kind, 0, port));
    }

    // Защищённая EAC-сессия: REG (учётка ui) → REG_RESULT 0 → BIND(kind, b) → BIND_RESULT 0. extra — сценарий фальшивого EOS.
    bool EacProtected(SecureClient& s, uint32_t ui, const Bind32& b, uint8_t kind = 2, const std::map<std::string, std::string>& extra = {}, uint32_t puidN = 0)
    {
        if (EacRegister(s, kSide, g_pub, ui, puidN ? puidN : ui, extra) != 0) return false;
        return EacBind(s, kind, b) == 0;
    }

    // Запуск сервера сценария.
    bool Run(Server& srv, const std::wstring& dir, const std::map<std::string, std::string>& ov, const wchar_t* extra)
    {
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, ov);
        return srv.Start(dir, ini, extra, kBr) && WaitPort(kSide, 5000);
    }

    // Строка журнала с решением: «… причина N … [<деталь> …] → …».
    bool LogDecision(const Server& srv, int reason, const std::string& detail, int ms)
    {
        return srv.WaitLog("причина " + std::to_string(reason), ms) && srv.WaitLog(detail, ms);
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== stand_bridge: фальшивый P73 (мост v2) и политика ред. 3 ===\n");
    std::wstring dir = RunDir("bridge");
    if (!Check(MakeSecureKey(dir, g_pub), "ключ AsdaSecure стенда создан")) return Summary("stand_bridge");
    const std::map<std::string, std::string> fast = { {"Policy.BindTimeoutSec", "2"}, {"Policy.GraceSec", "2"}, {"Policy.KickRepeatSec", "30"} };
    auto with = [&](std::map<std::string, std::string> m, std::initializer_list<std::pair<const std::string, std::string>> add) { for (auto& kv : add) m[kv.first] = kv.second; return m; };

    // ── B1: Mode=2, FailOpen=0 — KICK по BindTimeout, повтор, LOGOUT ─────────────────────────
    {
        printf("-- B1: Mode=2 FailOpen=0 BindTimeout=2 KickRepeat=2\n");
        Server srv;
        if (Check(Run(srv, dir, { {"Policy.BindTimeoutSec", "2"}, {"Policy.KickRepeatSec", "2"} }, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Ping(p73); std::vector<uint8_t> pl;
            Check(p73.RecvType(0x24, pl, 2000) == 1 && pl.empty(), "HELLO v2 от своего pid принят; PING → PONG");
            Check(srv.WaitLog("HELLO v2", 2000) && srv.LogHas("процесс pid " + std::to_string(GetCurrentProcessId())), "журнал: мост проверил процесс-владельца (pid стенда)");
            int64_t t0 = NowMs();
            p73.Send(0x11, LoginV2(5, 777, 0x0A000001, 1, RandBind()));
            Kick k;
            int r = WaitKick(p73, k, 5000);
            int64_t dt = NowMs() - t0;
            Check(r == 1 && k.un == 5 && k.ui == 777 && k.reason == 1 && k.eos == 0, "KICK userNum 5 / учётка 777 / причина 1 / eos 0");
            Check(dt >= 1800 && dt <= 3500, "KICK через ~BindTimeout (" + std::to_string(dt) + " мс)");
            Ping(p73);
            r = WaitKick(p73, k, 4000);
            Check(r == 1 && k.reason == 1, "P73 не снял сессию → KICK повторён через KickRepeat");
            p73.Send(0x12, Logout(5, 777, 2));
            Ping(p73);
            Check(WaitKick(p73, k, 3500) == 0, "после LOGOUT KICK больше нет");
            Check(srv.WaitLog("LOGOUT Game pid " + std::to_string(GetCurrentProcessId()) + ": учётка 777 userNum 5", 2000), "журнал: LOGOUT");
            p73.Send(0x11, LoginV2(6, 778, 0x0A000002, 10, RandBind()));
            p73.Send(0x12, Logout(6, 778, 9));
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 778, "LOGOUT с seq < LOGIN не снимает сессию (KICK 778 пришёл)");
            p73.Send(0x12, Logout(6, 778, 11));
            srv.Stop();
        }
    }
    // ── B2: Mode=1 — нет KICK, решение в журнале ────────────────────────────────────────────
    {
        printf("-- B2: Mode=1 (журнал)\n");
        Server srv;
        if (Check(Run(srv, dir, { {"General.Mode", "1"}, {"Policy.BindTimeoutSec", "2"} }, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73); p73.Send(0x11, LoginV2(7, 777, 0x0A000001, 1, RandBind()));
            Kick k; Ping(p73);
            Check(WaitKick(p73, k, 4500) == 0, "Mode=1: KICK не пришёл");
            Check(srv.WaitLog("причина 1 «нет EAC-сессии за BindTimeout» [EAC-сессии учётки нет] → KICK НЕ отправлен: Mode=1 (журнал)", 2000), "журнал: решение записано (Mode=1)");
            srv.Stop();
        }
    }
    // ── B3: FailOpen=1 без EOS (нет BeginSession) ───────────────────────────────────────────
    {
        printf("-- B3: Mode=2 FailOpen=1, --no-eos (BeginSession не было)\n");
        Server srv;
        if (Check(Run(srv, dir, { {"General.FailOpen", "1"}, {"Policy.BindTimeoutSec", "2"} }, L"--no-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73); p73.Send(0x11, LoginV2(8, 777, 0x0A000001, 1, RandBind()));
            Kick k; Ping(p73);
            Check(WaitKick(p73, k, 4500) == 0, "FailOpen (нет сессии EOS): KICK не пришёл");
            Check(srv.WaitLog("KICK НЕ отправлен: FailOpen: нет сессии AntiCheatServer", 2000), "журнал: «KICK НЕ отправлен: FailOpen: нет сессии AntiCheatServer»");
            srv.Stop();
        }
    }
    // ── B3b: FailOpen=1, окно после старта 3 с ─────────────────────────────────────────────
    {
        printf("-- B3b: FailOpen=1, окно после старта 3 с, BindTimeout=2\n");
        Server srv;
        if (Check(Run(srv, dir, { {"General.FailOpen", "1"}, {"General.FailOpenStartupSec", "3"}, {"Policy.BindTimeoutSec", "2"} }, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73, 3, 15602);
            int64_t t0 = NowMs();
            p73.Send(0x11, LoginV2(9, 777, 0x0A000001, 1, RandBind()));
            Kick k; Ping(p73);
            int r = WaitKick(p73, k, 8000);
            int64_t dt = NowMs() - t0;
            Check(r == 1 && k.reason == 1, "после окна FailOpen KICK пришёл (Indun)");
            Check(dt >= 4000, "KICK не раньше «окно + новый BindTimeout» (" + std::to_string(dt) + " мс)");
            Check(srv.LogHas("FailOpen снят — отсчёты BindTimeout/Grace начинаются заново"), "журнал: выход из FailOpen");
            srv.Stop();
        }
    }
    // ── B4: оператор ────────────────────────────────────────────────────────────────────────
    {
        printf("-- B4: OperatorUserIndex=777\n");
        Server srv;
        if (Check(Run(srv, dir, { {"Policy.OperatorUserIndex", "5, 777"}, {"Policy.BindTimeoutSec", "2"} }, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            p73.Send(0x11, LoginV2(10, 777, 0x0A000001, 1, RandBind()));
            p73.Send(0x11, LoginV2(11, 900, 0x0A000003, 2, RandBind()));
            Kick k; Ping(p73);
            int r = WaitKick(p73, k, 4500);
            Check(r == 1 && k.ui == 900, "KICK только не-оператору (900)");
            Check(WaitKick(p73, k, 1500) == 0, "оператору 777 KICK нет");
            Check(srv.WaitLog("KICK НЕ отправлен: оператор (только журнал)", 2000), "журнал: оператор");
            srv.Stop();
        }
    }
    // ── B5–B8: защищённые сессии, потеря канала, ClientActionRequired, вытеснение, отказ регистрации ──
    {
        printf("-- B5..B8: Authenticated + BIND (fake-eos), BindTimeout=2, Grace=2\n");
        Server srv;
        if (Check(Run(srv, dir, fast, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            SecureClient eac; Bind32 b5 = RandBind();
            Check(EacProtected(eac, 777, b5), "B5: EAC-сессия 777: REG_RESULT 0, BIND → BIND_RESULT 0");
            p73.Send(0x11, LoginV2(12, 777, 0x7F000001, 1, b5));
            Kick k; Ping(p73);
            Check(WaitKick(p73, k, 3500) == 0, "B5: Authenticated + совпавший BIND — KICK нет дольше BindTimeout");
            Check(srv.WaitLog("RemoteAuthComplete через", 1000) && srv.WaitLog("игровая сессия ЗАЩИЩЕНА", 1000), "B5: журнал: RemoteAuthComplete и «ЗАЩИЩЕНА»");
            int64_t t0 = NowMs();
            eac.Close();
            Ping(p73);
            int r = WaitKick(p73, k, 5000);
            int64_t dt = NowMs() - t0;
            Check(r == 1 && k.ui == 777 && k.reason == 3, "B5: канал 15901 потерян → KICK причина 3");
            Check(dt >= 1800 && dt <= 3800, "B5: через ~Grace (" + std::to_string(dt) + " мс)");
            p73.Send(0x12, Logout(12, 777, 2));

            SecureClient eac2; Bind32 b6 = RandBind();
            Check(EacProtected(eac2, 801, b6), "B6: защищённая EAC-сессия 801");
            p73.Send(0x11, LoginV2(13, 801, 0x7F000001, 3, b6));
            Sleep(300);
            eac2.Send(0x02, { 'A', 'C', 'T', 'I', 'O', 'N', ':', '6' });   // фальшивый EOS → ClientActionRequired(ClientViolation)
            std::vector<uint8_t> pl;
            Check(eac2.RecvType(0x03, pl, 3000) == 1 && pl.size() >= 4 && pl[0] == 2 && pl[1] == 6, "B6: клиенту KICK причина 2, EOS ClientViolation(6)");
            Ping(p73);
            r = WaitKick(p73, k, 3000);
            Check(r == 1 && k.ui == 801 && k.reason == 2 && k.eos == 6, "B6: P73 KICK учётка 801 причина 2 eos 6");
            Check(eac2.WaitClosed(3000), "B6: канал EAC закрыт сервером");
            p73.Send(0x12, Logout(13, 801, 4));

            SecureClient e1, e2; Bind32 b7 = RandBind();
            Check(EacProtected(e1, 802, b7), "B7: первая EAC-сессия 802 (защищает игру)");
            p73.Send(0x11, LoginV2(14, 802, 0x7F000001, 5, b7));
            Sleep(400);
            Check(EacProtected(e2, 802, b7, 2, {}, 8020), "B7: вторая EAC-сессия 802 (другой PUID) + BIND того же игрового соединения");
            Check(e1.RecvType(0x03, pl, 3000) == 1 && pl[0] == 5, "B7: старой — KICK 5 (Mode 2)");
            Ping(p73);
            Check(WaitKick(p73, k, 3500) == 0, "B7: игру не кикаем — новая сессия аутентифицирована и привязана раньше Grace");
            p73.Send(0x12, Logout(14, 802, 6));

            p73.Send(0x11, LoginV2(15, 803, 0x7F000001, 7, RandBind()));
            SecureClient e3;
            Check(EacRegister(e3, kSide, g_pub, 803, 803, {}, nullptr, 2 /*Mac*/) == 1, "B8: платформа Mac → REG_RESULT 1");
            Ping(p73);
            r = WaitKick(p73, k, 3000);
            Check(r == 1 && k.ui == 803 && k.reason == 4, "B8: по BindTimeout — KICK причина 4 (регистрация учётки отклонена)");
            p73.Send(0x12, Logout(15, 803, 8));
            srv.Stop();
        }
    }
    // ── B9: протокол моста v2, проверка процесса, сброс таблицы по HELLO ───────────────────
    {
        printf("-- B9: HELLO v2 обязателен; ver=1, чужой pid, кадры v1 — отказ (ред. 3 §8.1, §8.4)\n");
        Server srv;
        if (Check(Run(srv, dir, { {"Policy.BindTimeoutSec", "3"} }, L"--fake-eos --fake-auth"), "сервер запущен (CheckPeerProcess=1)"))
        {
            uint8_t t; std::vector<uint8_t> pl;
            { PlainClient c; c.Open(kBr); c.Send(0x11, LoginV2(1, 777, 1, 1, RandBind())); Check(c.Recv(t, pl, 3000) == -1, "LOGIN до HELLO → разрыв"); }
            { PlainClient c; c.Open(kBr); c.Send(0x10, HelloV(2, 7, 0, 1)); Check(c.Recv(t, pl, 3000) == -1, "HELLO с serverKind=7 → разрыв"); }
            { PlainClient c; c.Open(kBr); c.SendRaw({ 0x00, 0x00 }); Check(c.Recv(t, pl, 3000) == -1, "кадр len=0 → разрыв"); }
            { PlainClient c; c.Open(kBr); c.Send(0x10, HelloV(1, 2, 0, 15601)); Check(c.Recv(t, pl, 3000) == -1, "HELLO ver=1 → разрыв"); }
            Check(srv.WaitLog("HELLO ver=1 от pid " + std::to_string(GetCurrentProcessId()) + " — ОТКАЗ", 2000), "журнал: «HELLO ver=1 … ОТКАЗ: мост v1 … не поддерживается»");
            { PlainClient c; c.Open(kBr); c.Send(0x10, HelloV(2, 2, 4242, 15601)); Check(c.Recv(t, pl, 3000) == -1, "HELLO с чужим pid (4242) → разрыв (E1-13)"); }
            Check(srv.WaitLog("HELLO pid 4242 ≠ pid владельца соединения", 2000), "журнал: pid HELLO ≠ владелец соединения");
            { PlainClient c; OpenP73(c); std::vector<uint8_t> v1; PutU16(v1, 1); PutU32(v1, 777); PutU32(v1, 0); PutU32(v1, 1);
              c.Send(0x11, v1); Check(c.Recv(t, pl, 3000) == -1, "LOGIN v1 (14 байт без bind) после HELLO v2 → разрыв"); }
            Check(srv.WaitLog("LOGIN: длина 14 (v2 — 46)", 2000), "журнал: LOGIN длина 14");
            { PlainClient c; OpenP73(c); c.Send(0x13, std::vector<uint8_t>(14, 0)); Check(c.Recv(t, pl, 3000) == -1, "REBIND v1 (14 байт) → разрыв"); }
            srv.Stop();
        }
        Server srv2;
        if (Check(Run(srv2, dir, { {"Policy.BindTimeoutSec", "3"}, {"Bridge.AllowedImageNames", "GameServer.exe"} }, L"--fake-eos --fake-auth"),
                  "сервер с AllowedImageNames=GameServer.exe"))
        {
            PlainClient c; c.Open(kBr); c.Send(0x10, HelloV(2, 2, 0, 15601)); uint8_t t; std::vector<uint8_t> pl;
            Check(c.Recv(t, pl, 3000) == -1, "процесс не GameServer.exe → соединение закрыто сразу (E1-13)");
            Check(srv2.WaitLog("соединение отклонено: образ ", 2000) && srv2.LogHas("не из списка AllowedImageNames/AllowedImageDirs"), "журнал: образ не из списка");
            srv2.Stop();
        }
        printf("-- B9b: сброс таблицы по HELLO того же pid, смена pid (CheckPeerProcess=0: pid произвольные)\n");
        Server srv3;
        if (Check(Run(srv3, dir, { {"Policy.BindTimeoutSec", "3"}, {"Bridge.CheckPeerProcess", "0"} }, L"--fake-eos --fake-auth"), "сервер запущен (CheckPeerProcess=0)"))
        {
            PlainClient a; a.Open(kBr); a.Send(0x10, HelloV(2, 2, 5000, 15601));
            a.Send(0x11, LoginV2(20, 901, 1, 1, RandBind()));
            a.Send(0x11, LoginV2(21, 902, 1, 2, RandBind()));
            Ping(a); std::vector<uint8_t> pl; a.RecvType(0x24, pl, 2000);
            a.Close();
            Check(srv3.WaitLog("P73 закрыл соединение", 2000), "P73 отключился");
            PlainClient b; b.Open(kBr); b.Send(0x10, HelloV(2, 2, 5000, 15601));
            Check(srv3.WaitLog("pid 5000 порт 15601 (сброс таблицы этого pid: 2 сессий", 3000), "HELLO того же pid — прежняя таблица процесса сброшена (2 сессии)");
            b.Send(0x11, LoginV2(20, 901, 1, 3, RandBind()));
            Kick k; Ping(b);
            int r = WaitKick(b, k, 5000);
            Check(r == 1 && k.ui == 901 && k.un == 20, "после сброса: KICK по новому LOGIN (901)");
            Check(WaitKick(b, k, 2000) == 0 || k.ui != 902, "сброшенной сессии 902 KICK нет");
            b.Send(0x12, Logout(20, 901, 4));
            PlainClient c; c.Open(kBr); c.Send(0x10, HelloV(2, 2, 5001, 15601));
            c.Send(0x11, LoginV2(22, 903, 1, 1, RandBind()));
            Check(srv3.WaitLog("pid 5001 порт 15601 (сброс таблицы этого pid: 0 сессий, снято сессий прежнего процесса 0)", 2000),
                  "HELLO другого pid при живом P73 старого pid — его таблица не трогается");
            b.Close(); c.Close();
            Check(srv3.WaitLog("Game pid 5001) отключён", 3000), "оба P73 отключились");
            PlainClient d; d.Open(kBr); d.Send(0x10, HelloV(2, 2, 5002, 15601));
            Check(srv3.WaitLog("pid 5002 порт 15601 (сброс таблицы этого pid: 0 сессий, снято сессий прежнего процесса 1)", 2000),
                  "HELLO нового pid, старые процессы не подключены → их сессия (903) снята");
            srv3.Stop();
        }
    }
    // ── B10: REBIND v2 (вход соулмейтом) ─────────────────────────────────────────────────────
    {
        printf("-- B10: REBIND — EAC-сессия у учётки сессии, KICK с учёткой из LOGIN\n");
        Server srv;
        if (Check(Run(srv, dir, fast, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            SecureClient eacA; Bind32 b = RandBind();
            Check(EacProtected(eacA, 820, b), "EAC-сессия учётки A=820 (игрок) + BIND");
            p73.Send(0x11, LoginV2(30, 821, 0x7F000001, 1, b));            // персонаж учётки B=821 (CUser+0x174)
            p73.Send(0x13, RebindV2(30, 821, 820, 2, b));                  // учётка сессии — A
            Kick k; Ping(p73);
            Check(WaitKick(p73, k, 3500) == 0, "после REBIND на A (Authenticated + BIND) KICK нет дольше BindTimeout");
            Check(srv.WaitLog("учётка персонажа 821 → EAC-учётка сессии 820", 1000), "журнал: REBIND");
            int64_t t0 = NowMs();
            eacA.Close();
            Ping(p73);
            int r = WaitKick(p73, k, 5000);
            Check(r == 1 && k.reason == 3 && k.ui == 821 && k.un == 30, "канал A потерян → KICK причина 3 с userIndex из LOGIN (821), не 820");
            Check(NowMs() - t0 >= 1800, "через ~Grace");
            p73.Send(0x12, Logout(30, 821, 3));
            p73.Send(0x11, LoginV2(31, 823, 0x7F000001, 4, RandBind()));
            p73.Send(0x13, RebindV2(31, 999, 820, 5, RandBind()));
            Ping(p73);
            r = WaitKick(p73, k, 4000);
            Check(r == 1 && k.ui == 823 && k.reason == 1, "REBIND с неверным oldUserIndex пропущен → KICK 823 по BindTimeout");
            Check(srv.LogHas("REBIND userNum 31: сессии учётки 999 нет"), "журнал: REBIND пропущен");
            p73.Send(0x12, Logout(31, 823, 6));
            t0 = NowMs();
            p73.Send(0x11, LoginV2(32, 824, 0x7F000001, 7, RandBind()));
            Sleep(1500);
            p73.Send(0x13, RebindV2(32, 824, 825, 8, RandBind()));         // у 825 EAC-сессии нет
            Ping(p73);
            r = WaitKick(p73, k, 5000);
            int64_t dt = NowMs() - t0;
            Check(r == 1 && k.ui == 824 && k.reason == 1, "REBIND на учётку без EAC → KICK 824 причина 1");
            Check(dt >= 3300, "BindTimeout отсчитан заново от REBIND (" + std::to_string(dt) + " мс от LOGIN)");
            p73.Send(0x12, Logout(32, 824, 9));
            srv.Stop();
        }
    }
    // ── B11–B15: E1-01 — Authenticated = только RemoteAuthComplete; лимит REG; вытеснение не продлевает ─
    {
        printf("-- B11..B15: E1-01 (AuthTimeout=3, RegPerAccountMax=3)\n");
        Server srv;
        if (Check(Run(srv, dir, with(fast, { {"Sidecar.AuthTimeoutSec", "3"}, {"Sidecar.RegPerAccountMax", "3"}, {"Sidecar.RegPerAccountWindowSec", "300"} }), L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k; std::vector<uint8_t> pl;
            // B11: REG прошёл (RegisterClient), BIND совпал, но RemoteAuthComplete нет — НЕ защищена.
            SecureClient n1; Bind32 b11 = RandBind();
            int64_t tReg = NowMs();
            Check(EacProtected(n1, 830, b11, 2, { {"auth", "none"} }), "B11: REG_RESULT 0 и BIND_RESULT 0 без аутентификации EAC (BIND до Authenticated принимается)");
            p73.Send(0x11, LoginV2(40, 830, 0x7F000001, 1, b11));
            Ping(p73);
            int r = WaitKick(p73, k, 8000);   // ★ Д1 (22.11): решение — после AuthTimeout (3 с) + Grace (2 с), не позже BindTimeout + AuthTimeout + Grace
            Check(r == 1 && k.ui == 830 && k.reason == 4, "B11: RegisterClient без RemoteAuthComplete → KICK причина 4 (после AuthTimeout, Д1; было: защищена)");
            Check(srv.LogHas("[регистрация/аутентификация учётки отклонена]"), "B11: журнал: «регистрация/аутентификация учётки отклонена» (после AuthTimeout, Д1)");
            Check(n1.RecvType(0x03, pl, 3000) == 1 && pl.size() >= 4 && pl[0] == 4, "B11: AuthTimeout (3 с) → клиенту KICK 4");
            Check(n1.WaitClosed(3000) && NowMs() - tReg >= 2800, "B11: канал закрыт через ~AuthTimeout от RegisterClient");
            Check(srv.WaitLog("нет RemoteAuthComplete за 3 с", 1000), "B11: журнал: AuthTimeout");
            p73.Send(0x12, Logout(40, 830, 2));
            // B12: только LocalAuthComplete — тоже не защищена.
            SecureClient n2; Bind32 b12 = RandBind();
            Check(EacProtected(n2, 831, b12, 2, { {"auth", "local"} }), "B12: REG + BIND, EOS даёт только LocalAuthComplete");
            p73.Send(0x11, LoginV2(41, 831, 0x7F000001, 3, b12));
            Ping(p73);
            r = WaitKick(p73, k, 8000);
            Check(r == 1 && k.ui == 831 && k.reason == 4, "B12: LocalAuthComplete недостаточно → KICK 4");
            Check(srv.LogHas("ClientAuthStatus=LocalAuthComplete (учётка 831)"), "B12: журнал: LocalAuthComplete");
            p73.Send(0x12, Logout(41, 831, 4));
            // B13: RemoteAuthComplete через 1 с (раньше BindTimeout) — защищена, кика нет.
            SecureClient n3; Bind32 b13 = RandBind();
            Check(EacProtected(n3, 832, b13, 2, { {"authDelayMs", "1000"} }), "B13: REG + BIND ДО аутентификации (BIND_RESULT 0), RemoteAuthComplete через 1 с");
            p73.Send(0x11, LoginV2(42, 832, 0x7F000001, 5, b13));
            Ping(p73);
            Check(WaitKick(p73, k, 3500) == 0, "B13: защищена в момент, когда выполнены оба условия (BIND раньше, Authenticated позже) — KICK нет");
            p73.Send(0x12, Logout(42, 832, 6));
            // B14: карусель REG без аутентификации: вытеснения не продлевают отсчёт; 4-я REG за окно — REG_RESULT 3.
            Bind32 b14 = RandBind();
            int64_t t0 = NowMs();
            p73.Send(0x11, LoginV2(43, 833, 0x7F000001, 7, b14));
            SecureClient c1, c2, c3, c4;
            Check(EacProtected(c1, 833, b14, 2, { {"auth", "none"} }, 8331), "B14: REG#1 учётки 833");
            Sleep(400);
            Check(EacProtected(c2, 833, b14, 2, { {"auth", "none"} }, 8332), "B14: REG#2 вытесняет #1");
            Sleep(400);
            Check(EacProtected(c3, 833, b14, 2, { {"auth", "none"} }, 8333), "B14: REG#3 вытесняет #2");
            Check(EacRegister(c4, kSide, g_pub, 833, 8334, { {"auth", "none"} }) == 3, "B14: REG#4 за окно → REG_RESULT 3 (лимит 3 REG учётки)");
            Check(srv.WaitLog("учётка 833: REG сверх 3 за 300 с → REG_RESULT 3", 1000), "B14: журнал: лимит REG на учётку");
            Ping(p73);
            r = WaitKick(p73, k, 8000);
            int64_t dt = NowMs() - t0;
            Check(r == 1 && k.ui == 833 && k.reason == 4 && dt <= 7300,
                  "B14: KICK 4 не позже BindTimeout + AuthTimeout + Grace от LOGIN (" + std::to_string(dt) + " мс ≤ 7300) — карусель не продлила отсчёт (Д1 считает от срока игры)");
            p73.Send(0x12, Logout(43, 833, 8));
            // B15: защищённая игра; чужая REG той же учётки без аутентификации вытесняет — через Grace KICK 4, отсчёт не сброшен.
            SecureClient a, x; Bind32 b15 = RandBind();
            Check(EacProtected(a, 834, b15), "B15: защищённая сессия 834");
            p73.Send(0x11, LoginV2(44, 834, 0x7F000001, 9, b15));
            Ping(p73);
            Check(WaitKick(p73, k, 2500) == 0, "B15: защищена — KICK нет");
            int64_t t1 = NowMs();
            Check(EacRegister(x, kSide, g_pub, 834, 8341, { {"auth", "none"} }) == 0, "B15: чужая REG 834 (без EAC-клиента) вытесняет защищённую");
            Ping(p73);
            r = WaitKick(p73, k, 8000);
            dt = NowMs() - t1;
            Check(r == 1 && k.ui == 834 && k.reason == 4 && dt >= 1700 && dt <= 7300,
                  "B15: защита потеряна → KICK 4 не позже Grace + AuthTimeout + Grace (" + std::to_string(dt) + " мс, Д1)");
            Check(srv.LogHas("защита потеряна — EAC-сессия не аутентифицирована"), "B15: журнал: защита потеряна");
            p73.Send(0x12, Logout(44, 834, 10));
            srv.Stop();
        }
    }
    // ── B16–B17: E1-02 — привязка к игровому каналу ───────────────────────────────────────────
    {
        printf("-- B16: E1-02 — нет BIND / чужой BIND (второй ПК) / нулевой bind / другой serverKind → причина 6\n");
        Server srv;
        if (Check(Run(srv, dir, fast, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient s1;
            Check(EacRegister(s1, kSide, g_pub, 840, 840) == 0, "B16a: аутентифицированная сессия 840 без BIND");
            p73.Send(0x11, LoginV2(50, 840, 0x7F000001, 1, RandBind()));
            Ping(p73);
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 840 && k.reason == 6, "B16a: BIND не пришёл → KICK 6");
            Check(srv.LogHas("[BIND от EAC-сессии не пришёл]"), "B16a: журнал: BIND не пришёл");
            SecureClient s2; Bind32 pc2 = RandBind(), pc1 = RandBind();
            Check(EacProtected(s2, 841, pc2), "B16b: «второй ПК»: защищённый клиент учётки 841 привязан к СВОЕМУ игровому каналу");
            p73.Send(0x11, LoginV2(51, 841, 0x7F000001, 2, pc1));          // бот на ПК1 той же учётки — другой канал
            Ping(p73);
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 841 && k.reason == 6, "B16b: игровой канал без своей EAC-сессии → KICK 6 (обход «второй ПК» закрыт)");
            Check(srv.LogHas("[BIND EAC-сессии не совпал с bind игрового соединения]"), "B16b: журнал: BIND не совпал");
            SecureClient s3;
            Check(EacRegister(s3, kSide, g_pub, 842, 842) == 0 && EacBind(s3, 2, ZeroBind()) == 0, "B16c: сессия 842 + нулевой BIND (принят, не сопоставляется)");
            p73.Send(0x11, LoginV2(52, 842, 0x7F000001, 3, ZeroBind()));
            Ping(p73);
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 842 && k.reason == 6, "B16c: нулевой bind (Legacy / P61 выкл.) → KICK 6");
            Check(srv.LogHas("[нулевой bind игрового соединения"), "B16c: журнал: нулевой bind");
            SecureClient s4; Bind32 b4 = RandBind();
            Check(EacProtected(s4, 843, b4, 2), "B16d: BIND с serverKind=2 (клиент Indun от GameServer не отличает)");
            PlainClient indun; OpenP73(indun, 3, 15602);
            indun.Send(0x11, LoginV2(53, 843, 0x7F000001, 1, b4));         // игра на Indun (kind 3), bind тот же
            Ping(indun);
            Check(WaitKick(indun, k, 3500) == 0, "B16d: Indun-сессия, BIND с serverKind=2 — сверяется только bind → защищена, KICK нет");
            indun.Send(0x12, Logout(53, 843, 2));
            SecureClient s5; Bind32 b5 = RandBind();
            Check(EacRegister(s5, kSide, g_pub, 844, 844) == 0, "B16e: сессия 844");
            p73.Send(0x11, LoginV2(54, 844, 0x7F000001, 5, b5));
            Sleep(1000);
            Check(EacBind(s5, 2, b5) == 0, "B16e: BIND пришёл ПОСЛЕ LOGIN (переподключение игры)");
            Ping(p73);
            Check(WaitKick(p73, k, 3000) == 0, "B16e: BIND после LOGIN, раньше BindTimeout — KICK нет");
            Check(srv.WaitLog("игровое соединение привязано к EAC-сессии", 1000), "B16e: журнал: привязка сопоставлена");
            for (uint16_t un = 50; un <= 54; ++un) if (un != 53) p73.Send(0x12, Logout(un, 840 + (un - 50), 10));
            srv.Stop();
        }
        printf("-- B17: RequireSameIp=1\n");
        Server srv2;
        if (Check(Run(srv2, dir, with(fast, { {"Policy.RequireSameIp", "1"} }), L"--fake-eos --fake-auth"), "сервер запущен (RequireSameIp=1)"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient s1; Bind32 b = RandBind();
            Check(EacProtected(s1, 845, b), "B17: защищённая сессия 845 с 127.0.0.1");
            p73.Send(0x11, LoginV2(55, 845, 0x0A000001, 1, b));            // сервер видит игрока с 10.0.0.1
            Ping(p73);
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 845 && k.reason == 6, "B17: IP игры 10.0.0.1 ≠ IP канала EAC → KICK 6");
            Check(srv2.LogHas("(RequireSameIp=1)]"), "B17: журнал: IP");
            SecureClient s2; Bind32 b2 = RandBind();
            Check(EacProtected(s2, 846, b2), "B17: защищённая сессия 846 с 127.0.0.1");
            p73.Send(0x11, LoginV2(56, 846, 0x7F000001, 2, b2));
            Ping(p73);
            Check(WaitKick(p73, k, 3000) == 0, "B17: тот же IP — KICK нет");
            srv2.Stop();
        }
    }
    // ── B18–B21: E1-03 / E1-09 — FailOpen только по порогам ────────────────────────────────────
    {
        printf("-- B18: E1-03 — одна временная REG не включает FailOpen; 5 IP — включают (EpicDownHoldSec=3)\n");
        Server srv;
        if (Check(Run(srv, dir, with(fast, { {"General.FailOpen", "1"}, {"General.FailOpenStartupSec", "0"}, {"General.EpicDownHoldSec", "3"} }),
                      L"--fake-eos --fake-auth"), "сервер запущен (FailOpen=1)"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient atk;
            Check(EacRegister(atk, kSide, g_pub, 1, 99, { {"eosres", "TooManyRequests"} }) == 3, "B18a: REG с временным отказом Epic (TooManyRequests) → REG_RESULT 3");
            p73.Send(0x11, LoginV2(60, 850, 0x7F000001, 1, RandBind()));
            Ping(p73);
            Check(WaitKick(p73, k, 4000) == 1 && k.ui == 850 && k.reason == 1, "B18a: игрок без EAC КИКНУТ — одна чужая REG больше не включает FailOpen (было: S4.2)");
            Check(!srv.LogHas("Epic недоступен"), "B18a: журнал: «Epic недоступен» нет");
            p73.Send(0x12, Logout(60, 850, 2));
            const char* ips[] = { "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6" };
            int tr = 0;
            for (int i = 0; i < 5; ++i) { SecureClient c; tr += EacRegister(c, kSide, g_pub, 1, 100 + i, { {"eosres", "TimedOut"} }, ips[i]) == 3; }
            Check(tr == 5, "B18b: 5 временных отказов от 5 разных IP");
            Check(srv.WaitLog("Epic недоступен (временных отказов VerifyIdToken", 2000), "B18b: журнал: «Epic недоступен» по порогу (доля и IP)");
            p73.Send(0x11, LoginV2(61, 851, 0x7F000001, 3, RandBind()));
            Ping(p73);
            int64_t t0 = NowMs();
            int r = WaitKick(p73, k, 2500);
            Check(r == 0, "B18b: во время «Epic недоступен» — KICK нет");
            Check(srv.WaitLog("KICK НЕ отправлен: FailOpen: Epic недоступен", 1000), "B18b: журнал: «KICK НЕ отправлен: FailOpen: Epic недоступен»");
            r = WaitKick(p73, k, 6000);
            Check(r == 1 && k.ui == 851, "B18b: после EpicDownHoldSec — отсчёт заново и KICK (" + std::to_string(NowMs() - t0) + " мс)");
            p73.Send(0x12, Logout(61, 851, 4));
            srv.Stop();
        }
        printf("-- B19: §8.6 R3-03 — временный отказ VerifyIdToken НЕ освобождает учётку (только глобальный FailOpen по порогам)\n");
        Server srv2;
        if (Check(Run(srv2, dir, with(fast, { {"General.FailOpen", "1"}, {"General.FailOpenStartupSec", "0"}, {"General.EpicDownHoldSec", "30"},
                                              {"Policy.GraceSec", "3"}, {"Policy.VerifyWaitSec", "0"} }), L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient e; Bind32 b = RandBind();
            Check(EacProtected(e, 852, b), "B19: защищённая сессия 852 (PUID подтверждён Epic)");
            p73.Send(0x11, LoginV2(62, 852, 0x7F000001, 1, b));
            p73.Send(0x11, LoginV2(63, 853, 0x7F000001, 2, RandBind()));   // учётка без EAC — для контроля
            Sleep(500);
            int64_t t0 = NowMs();
            e.Close();
            Sleep(300);
            // Бот учётки 852 шлёт REG с PUID 852 и токеном, на котором Epic даёт временный отказ, — раз в 700 мс (продление было бы бесконечным).
            int tr = 0, n = 0;
            bool k852 = false, k853 = false; int r852 = -1; int64_t t852 = 0;
            while (NowMs() - t0 < 9000 && !(k852 && k853))
            {
                if (n < 10) { SecureClient t; tr += EacRegister(t, kSide, g_pub, 852, 852, { {"eosres", "ServiceFailure"} }) == 3; ++n; }
                Ping(p73);
                if (WaitKick(p73, k, 700) == 1)
                {
                    if (k.ui == 853) k853 = true;
                    if (k.ui == 852 && !k852) { k852 = true; r852 = k.reason; t852 = NowMs() - t0; }
                }
            }
            Check(n > 0 && tr == n, "B19: повторные REG 852 — временный отказ Epic → REG_RESULT 3 (" + std::to_string(tr) + " из " + std::to_string(n) + ")");
            Check(!srv2.LogHasNew("не кикать до повторной REG") && !srv2.LogHasNew("Epic недоступен"), "B19: журнал: освобождения учётки нет, глобального «Epic недоступен» нет (один IP)");
            Check(k853, "B19: учётке без EAC (853) KICK пришёл");
            Check(k852 && r852 == 3 && t852 >= 2700 && t852 <= 6500,
                  "B19: учётке 852 KICK 3 через Grace (" + std::to_string(t852) + " мс) — временные отказы её REG не продлевают (было: освобождение до повторной REG)");
            srv2.Stop();
        }
        printf("-- B20: E1-09 — AsdaId деградировал (доля 503) → FailOpen\n");
        Server srv3;
        if (Check(Run(srv3, dir, with(fast, { {"General.FailOpen", "1"}, {"General.FailOpenStartupSec", "0"}, {"General.EpicDownHoldSec", "3"} }),
                      L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            int n503 = 0;
            for (int i = 0; i < 5; ++i) n503 += HttpPost(kId, "/token", "{\"login\":\"stand_dberror\",\"password_md5\":\"7787e2c49efec303a6d311a19d31b8b5\"}", "10.9.0." + std::to_string(i + 1)) == 503;
            Check(n503 == 5, "B20: 5 × /token → 503 (БД недоступна)");
            Check(srv3.WaitLog("AsdaId деградировал: 503 в 100 % из 5", 2000), "B20: журнал AsdaId: деградация");
            p73.Send(0x11, LoginV2(64, 860, 0x7F000001, 1, RandBind()));
            Ping(p73);
            Check(WaitKick(p73, k, 2500) == 0, "B20: игрок без EAC при деградации AsdaId — KICK нет");
            Check(srv3.WaitLog("KICK НЕ отправлен: FailOpen: AsdaId деградировал", 1000), "B20: журнал: FailOpen по AsdaId");
            Ping(p73);
            Check(WaitKick(p73, k, 7000) == 1 && k.ui == 860, "B20: AsdaId исправен (окно прошло) → отсчёт заново и KICK");
            srv3.Stop();
        }
        printf("-- B21: временные ошибки вызовов EOS в нити ядра → «Epic недоступен»\n");
        Server srv4;
        if (Check(Run(srv4, dir, with(fast, { {"General.FailOpen", "1"}, {"General.FailOpenStartupSec", "0"}, {"General.EosCallErrorsMax", "3"} }),
                      L"--fake-eos --fake-auth"), "сервер запущен (EosCallErrorsMax=3)"))
        {
            int r3 = 0;
            for (int i = 0; i < 3; ++i) { SecureClient c; r3 += EacRegister(c, kSide, g_pub, 870 + i, 870 + i, { {"regerr", "1"} }) == 3; }
            Check(r3 == 3, "B21: 3 × RegisterClient отказал временной ошибкой → REG_RESULT 3");
            Check(srv4.WaitLog("Epic недоступен (временных ошибок вызовов EOS 3", 2000), "B21: журнал: «Epic недоступен» по ошибкам вызовов EOS");
            srv4.Stop();
        }
    }
    // ── B22: E1-18 — Mode 1: вытеснение без KICK клиенту ────────────────────────────────────
    {
        printf("-- B22: E1-18 — Mode=1, вытеснение: старому каналу KICK не шлётся, канал закрывается\n");
        Server srv;
        if (Check(Run(srv, dir, with(fast, { {"General.Mode", "1"} }), L"--fake-eos --fake-auth"), "сервер запущен (Mode=1)"))
        {
            SecureClient e1, e2; std::vector<uint8_t> pl;
            Check(EacRegister(e1, kSide, g_pub, 880, 880) == 0 && EacRegister(e2, kSide, g_pub, 880, 8801) == 0, "B22: две REG учётки 880");
            int r = e1.RecvType(0x03, pl, 2000);
            Check(r == -1 && e1.closed, "B22: старому — без KICK, канал закрыт");
            Check(srv.WaitLog("(Mode=1 — без KICK, канал закрыт)", 1000), "B22: журнал");
            srv.Stop();
        }
    }
    // ── B23: E1-12 — разовое ожидание идущей проверки токена той же учётки ──────────────────
    {
        printf("-- B23: E1-12 — Grace=2, VerifyWaitSec=3: потеря канала, повторная REG «зависла» в проверке\n");
        Server srv;
        if (Check(Run(srv, dir, with(fast, { {"Policy.VerifyWaitSec", "3"} }), L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient e; Bind32 b = RandBind();
            Check(EacProtected(e, 890, b), "B23: защищённая сессия 890");
            p73.Send(0x11, LoginV2(70, 890, 0x7F000001, 1, b));
            Sleep(500);
            int64_t t0 = NowMs();
            e.Close();
            Sleep(800);
            SecureClient hang;
            Check(hang.Open(kSide, g_pub) && hang.Handshake(3000) && hang.Send(0x01, RegPayload(1, 1, Puid(890), FakeToken("890", Puid(890), { {"noanswer", "1"} }))),
                  "B23: повторная REG того же PUID — Epic не отвечает");
            std::thread pinger([&] { for (int i = 0; i < 14 && !hang.closed; ++i) { hang.Send(0x04, {}); Sleep(500); } });
            Ping(p73);
            int r = WaitKick(p73, k, 8000);
            int64_t dt = NowMs() - t0;
            pinger.join();
            Check(srv.LogHas("учётка 890 userNum 70: срок вышел, но идёт проверка токена учётки — ждём до 3 с (один раз)"), "B23: журнал: ожидание проверки токена");
            Check(r == 1 && k.ui == 890 && k.reason == 3 && dt >= 4500 && dt <= 6500, "B23: KICK 3 после Grace + одного ожидания (" + std::to_string(dt) + " мс), не бесконечно");
            srv.Stop();
        }
    }
    // ── B24: §8.6 R3-01 — лимит REG 6/10 мин; вытеснение Authenticated с того же IP в лимит не считается ──────────
    {
        printf("-- B24: §8.6 R3-01 — умолчания RegPerAccountMax=6/600 с; переподключение аутентифицированного клиента с того же IP не считается\n");
        Server srv;
        if (Check(Run(srv, dir, with(fast, { {"Sidecar.RegPerIpPerMin", "100"}, {"Sidecar.RegPerAccountMax", kIniDefault}, {"Sidecar.RegPerAccountWindowSec", kIniDefault} }), L"--fake-eos --fake-auth"), "сервер запущен (лимит REG на учётку — умолчание)"))
        {
            Check(srv.WaitLog("REG на учётку 6/600 с", 2000), "B24: журнал старта: REG на учётку 6/600 с (умолчание §8.6)");
            PlainClient p73; OpenP73(p73);
            Kick k;
            // (а) честный клиент: 8 переподключений канала 15901 с того же IP; каждая прежняя сессия аутентифицирована → все приняты, кика нет.
            Bind32 b = RandBind();
            p73.Send(0x11, LoginV2(80, 900, 0x7F000001, 1, b));
            int ok = 0;
            std::vector<std::unique_ptr<SecureClient>> cs;
            for (int i = 0; i < 8; ++i)
            {
                cs.emplace_back(new SecureClient());
                ok += EacProtected(*cs.back(), 900, b, 2, {}, 9000 + i);
                Sleep(300);   // RemoteAuthComplete фальшивого EOS — на ближайшем такте
                Ping(p73);
            }
            Check(ok == 8, "B24а: 8 REG учётки 900 с одного IP подряд (каждая вытесняет аутентифицированную) — все REG_RESULT 0 (" + std::to_string(ok) + ")");
            Check(srv.WaitLog("учётка 900: REG вытесняет аутентифицированную EAC-сессию", 1000) && !srv.LogHas("учётка 900: REG сверх"),
                  "B24а: журнал: «в лимит REG не считается», предела нет");
            Ping(p73);
            Check(WaitKick(p73, k, 3000) == 0, "B24а: игровая сессия 900 не кикнута (перепривязка BIND после каждого переподключения)");
            p73.Send(0x12, Logout(80, 900, 2));
            // (б) без аутентификации (карусель): 6 REG приняты, 7-я → 3.
            std::vector<std::unique_ptr<SecureClient>> nc; int st[7];
            for (int i = 0; i < 7; ++i) { nc.emplace_back(new SecureClient()); st[i] = EacRegister(*nc.back(), kSide, g_pub, 901, 9100 + i, { {"auth", "none"} }); Sleep(150); }
            bool six = true; for (int i = 0; i < 6; ++i) six &= st[i] == 0;
            Check(six && st[6] == 3, "B24б: REG без RemoteAuthComplete — 6 приняты, 7-я → REG_RESULT 3 (" + std::to_string(st[6]) + ")");
            Check(srv.WaitLog("учётка 901: REG сверх 6 за 600 с → REG_RESULT 3", 1000), "B24б: журнал: предел 6 за 600 с");
            // (в) вытеснение аутентифицированной сессии с ДРУГОГО IP — считается: 6 приняты, 7-я → 3.
            const char* ips[2] = { "127.0.0.1", "127.0.0.2" };
            std::vector<std::unique_ptr<SecureClient>> xc; int sx[7];
            for (int i = 0; i < 7; ++i) { xc.emplace_back(new SecureClient()); sx[i] = EacRegister(*xc.back(), kSide, g_pub, 902, 9200 + i, {}, ips[i % 2]); Sleep(300); }
            bool six2 = true; for (int i = 0; i < 6; ++i) six2 &= sx[i] == 0;
            Check(six2 && sx[6] == 3, "B24в: вытеснение аутентифицированной сессии с другого IP — в лимите: 6 приняты, 7-я → 3 (" + std::to_string(sx[6]) + ")");
            srv.Stop();
        }
    }
    // ── B25: §8.6 R3-04 — «P61 у процесса не активен» ───────────────────────────────────────
    {
        printf("-- B25: §8.6 R3-04 — 5 LOGIN с нулевым bind за 120 с после HELLO: причина 6 не применяется, причина 1 работает\n");
        Server srv;
        if (Check(Run(srv, dir, fast, L"--fake-eos --fake-auth"), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Kick k;
            SecureClient a, c;
            Check(EacRegister(a, kSide, g_pub, 910, 910) == 0, "B25: EAC 910 аутентифицирована, BIND не шлёт (bind у процесса невозможен)");
            Check(EacProtected(c, 912, RandBind()), "B25: EAC 912 аутентифицирована, BIND со своим значением");
            for (uint16_t i = 0; i < 5; ++i) p73.Send(0x11, LoginV2(90 + i, 910 + i, 0x7F000001, 1, ZeroBind()));
            Check(srv.WaitLog("P61 у процесса не активен: GameServer pid " + std::to_string(GetCurrentProcessId()), 2000), "B25: журнал: «P61 у процесса не активен» после 5-го нулевого LOGIN");
            std::set<uint32_t> kicked; std::map<uint32_t, int> why;
            for (int i = 0; i < 6; ++i) { Ping(p73); if (WaitKick(p73, k, 700) == 1) { kicked.insert(k.ui); why[k.ui] = k.reason; } }
            Check(!kicked.count(910) && !kicked.count(912), "B25: 910 и 912 (EAC аутентифицирована, bind нулевой) — без KICK 6");
            Check(kicked.count(911) && why[911] == 1 && kicked.count(913) && why[913] == 1 && kicked.count(914) && why[914] == 1,
                  "B25: учётки без EAC (911, 913, 914) — KICK причина 1 по-прежнему");
            Check(srv.LogHas("без bind: P61 у процесса не активен"), "B25: журнал: защита без bind");
            // Контроль: Indun того же pid — другой процесс-источник; 4 нулевых LOGIN (< 5) — вывода нет, причина 6 применяется.
            PlainClient ind; OpenP73(ind, 3, 15602);
            SecureClient d;
            Check(EacRegister(d, kSide, g_pub, 920, 920) == 0, "B25: EAC 920 аутентифицирована");
            for (uint16_t i = 0; i < 4; ++i) ind.Send(0x11, LoginV2(100 + i, 920 + i, 0x7F000001, 1, ZeroBind()));
            bool k920 = false; int r920 = -1;
            for (int i = 0; i < 8 && !k920; ++i) { Ping(ind); Ping(p73); if (WaitKick(ind, k, 700) == 1 && k.ui == 920) { k920 = true; r920 = k.reason; } }
            Check(k920 && r920 == 6, "B25: Indun — 4 нулевых LOGIN (< 5): вывода нет, 920 → KICK 6 (" + std::to_string(r920) + ")");
            // Ненулевой LOGIN процесса отменяет вывод: причина 6 снова применяется к 910.
            p73.Send(0x11, LoginV2(96, 916, 0x7F000001, 2, RandBind()));
            Check(srv.WaitLog("LOGIN с ненулевым bind — P61 у процесса активен", 2000), "B25: журнал: ненулевой LOGIN — P61 активен, вывод снят");
            bool k910 = false; int r910 = -1;
            for (int i = 0; i < 10 && !k910; ++i) { Ping(p73); Ping(ind); if (WaitKick(p73, k, 700) == 1 && k.ui == 910) { k910 = true; r910 = k.reason; } }
            Check(k910 && r910 == 6, "B25: после отмены вывода 910 (нулевой bind) → KICK 6 через Grace (" + std::to_string(r910) + ")");
            srv.Stop();
        }
    }
    return Summary("stand_bridge");
}
