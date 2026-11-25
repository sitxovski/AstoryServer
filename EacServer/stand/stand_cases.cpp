// Copyright (c) 2026 @sitxovski (Discord)
// stand_cases.cpp — стенд (з) ★ 22.11.2026: 23 решения EacServer «KICK НЕ отправлен» (Mode=1, 24.10–17.11) из разбора
// Reports/anticheat/eac_mode1_kick_decisions_20261122.md, воспроизведённые в Mode=2 (кик включён) против AsdaEacServer_stand.exe.
//   A ×7 — канал 15901 оборвался вместе с клиентом, игровое соединение осталось: KICK причина 3 ОСТАЁТСЯ (мёртвое соединение);
//   B ×3 — честный клиент 14 раз перезапустился после падения: все REG приняты (Д2), KICK нет; B2 — REG отбит пределом с IP игры:
//          решение откладывается на окно предела (Д2), потом KICK 1;
//   C ×2 — C1 RemoteAuthComplete приходит позже BindTimeout (Д1): KICK нет; C2 RemoteAuth не пришёл, AuthTimeout, повторная REG
//          аутентифицирована в пределах Grace (Д1): KICK нет;
//   D ×11 — ред. 2 (ревизия 64): у клиента учётки с историей EAC не проходит EOS Connect (токены есть, EAC-сессии нет) — поблажка
//          ОДНОЙ учётке: учётки по одной, как 16–17.11 — KICK нет; без истории (75228) — KICK; «3 свои учётки + токены» — KICK всем;
//          бюджет исчерпан — KICK; ClientActionRequired под поблажкой — KICK 2;
//   Д4 — оператор в OperatorUserIndex: KICK не шлётся, решение одно.
// Запуск без ключей — против out\stand\AsdaEacServer_stand.exe; «--exe-dir <папка>» — против другой сборки (замер «до»).
#include "StandCommon.h"
#include <thread>
#include <sstream>
#include <aclapi.h>
#include <sddl.h>

using namespace Stand;

namespace
{
    const int kId = 18448, kSide = 25741, kBr = 25742;   // порты стенда
    AsdaSecure::PublicKey g_pub;
    const uint32_t kIpLocal = 0x7F000001;                 // IP игры = IP канала 15901 стенда (127.0.0.1)

    struct Kick { uint16_t un = 0; uint32_t ui = 0; uint8_t reason = 0; };

    std::vector<uint8_t> Logout(uint16_t un, uint32_t ui, uint32_t seq) { std::vector<uint8_t> p; PutU16(p, un); PutU32(p, ui); PutU32(p, seq); return p; }

    // Собрать все KICK за время ms (мост пингуется раз в секунду).
    std::vector<Kick> Kicks(PlainClient& p73, int ms)
    {
        std::vector<Kick> out;
        int64_t end = NowMs() + ms, lastPing = 0;
        while (NowMs() < end)
        {
            if (NowMs() - lastPing > 1000) { p73.Send(0x14, {}); lastPing = NowMs(); }
            uint8_t t; std::vector<uint8_t> p;
            int r = p73.Recv(t, p, (int)(std::min)((int64_t)200, end - NowMs()));
            if (r == 1 && t == 0x21 && p.size() == 8) { Kick k; k.un = GetU16(p.data()); k.ui = GetU32(p.data() + 2); k.reason = p[6]; out.push_back(k); }
            if (r == -1) break;
        }
        return out;
    }
    int CountKicks(const std::vector<Kick>& ks, uint32_t ui, int reason = -1)
    {
        int n = 0;
        for (auto& k : ks) if (k.ui == ui && (reason < 0 || k.reason == reason)) ++n;
        return n;
    }

    std::wstring g_exeDir;   // пусто — out\stand

    // ★ Р66-4: DACL папки — защищён от наследования, и в нём только SYSTEM, Administrators и пользователь процесса стенда.
    bool DirDaclStrict(const std::wstring& dir, std::string& info)
    {
        PACL dacl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        if (GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) { info = "нет"; return false; }
        SECURITY_DESCRIPTOR_CONTROL ctl = 0; DWORD rev = 0; GetSecurityDescriptorControl(sd, &ctl, &rev);
        HANDLE tok = nullptr; std::wstring me; uint8_t buf[256]; DWORD n = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok) && GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n))
        { LPWSTR x = nullptr; if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &x)) { me = x; LocalFree(x); } }
        if (tok) CloseHandle(tok);
        bool ok = (ctl & SE_DACL_PROTECTED) && dacl;
        info = (ctl & SE_DACL_PROTECTED) ? "защищён" : "наследуется";
        for (DWORD i = 0; ok && i < dacl->AceCount; ++i)
        {
            ACE_HEADER* h = nullptr; GetAce(dacl, i, (LPVOID*)&h);
            LPWSTR x = nullptr; ConvertSidToStringSidW(&((ACCESS_ALLOWED_ACE*)h)->SidStart, &x);
            std::wstring v = x ? x : L""; if (x) LocalFree(x);
            info += ", " + U8(v);
            if (v != L"S-1-5-18" && v != L"S-1-5-32-544" && v != me) ok = false;
        }
        LocalFree(sd);
        return ok;
    }

    bool Run(Server& srv, const std::wstring& dir, const std::map<std::string, std::string>& ov)
    {
        std::wstring ini = WriteIni(dir, kId, kSide, kBr, ov);
        if (!g_exeDir.empty())
        {
            // сборка «до»: тот же стенд против другой копии сервера стенда (копируется рядом под своим именем)
            CopyFileW((g_exeDir + L"AsdaEacServer_stand.exe").c_str(), (ExeDir() + L"AsdaEacServer_stand_cases_before.exe").c_str(), FALSE);
        }
        return srv.Start(dir, ini, L"--fake-eos --fake-auth", kBr, g_exeDir.empty() ? L"AsdaEacServer_stand.exe" : L"AsdaEacServer_stand_cases_before.exe")
               && WaitPort(kSide, 5000);
    }

    bool OpenP73(PlainClient& c) { return c.Open(kBr) && c.Send(0x10, HelloV(2, 2, 0, 15601)); }

    // Общие ключи сценариев: Mode=2, FailOpen=0, короткие сроки.
    std::map<std::string, std::string> Base()
    {
        return { {"General.Mode", "2"}, {"General.FailOpen", "0"}, {"Policy.BindTimeoutSec", "3"}, {"Policy.GraceSec", "2"}, {"Policy.KickRepeatSec", "30"},
                 {"Sidecar.AuthTimeoutSec", "5"}, {"Sidecar.RegPerAccountMax", "6"}, {"Sidecar.RegPerAccountWindowSec", "600"} };
    }
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    for (int i = 1; i + 1 < argc; ++i) if (std::string(argv[i]) == "--exe-dir") { g_exeDir = W(argv[i + 1]); if (g_exeDir.back() != L'\\') g_exeDir += L"\\"; }
    printf("=== stand_cases: 23 решения Mode=1 (разбор 22.11) в Mode=2%s ===\n", g_exeDir.empty() ? "" : " — СБОРКА «ДО»");
    std::wstring dir = RunDir("cases");
    if (!Check(MakeSecureKey(dir, g_pub), "ключ AsdaSecure стенда создан")) return Summary("stand_cases");
    int falseKicks = 0, keptKicks = 0;

    // ── A ×7: канал оборвался вместе с клиентом — KICK причина 3 остаётся ──────────────────────
    {
        printf("-- A: 7 обрывов канала 15901 при живом игровом соединении (группа A)\n");
        Server srv;
        if (Check(Run(srv, dir, Base()), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            std::vector<std::unique_ptr<SecureClient>> cl;
            for (int i = 0; i < 7; ++i)
            {
                const uint32_t ui = 801 + i; Bind32 b = RandBind();
                cl.emplace_back(new SecureClient());
                bool ok = EacRegister(*cl.back(), kSide, g_pub, ui, ui) == 0 && EacBind(*cl.back(), 2, b) == 0;
                p73.Send(0x11, LoginV2((uint16_t)(10 + i), ui, kIpLocal, (uint32_t)(i + 1), b));
                Check(ok, "A: учётка " + std::to_string(ui) + " защищена (REG + BIND)");
            }
            Sleep(800);
            for (auto& c : cl) c->Close();
            auto ks = Kicks(p73, 6000);
            int n = 0; for (int i = 0; i < 7; ++i) n += CountKicks(ks, 801 + i, 3) > 0;
            keptKicks += n;
            Check(n == 7, "A: KICK причина 3 по всем 7 «призракам» (" + std::to_string(n) + ") — так и задумано");
            srv.Stop();
        }
    }
    // ── B ×3: 14 перезапусков честного клиента — REG приняты, KICK нет ─────────────────────────
    {
        printf("-- B: 14 перезапусков клиента подряд (падения), RegPerAccountMax=6 (группа B)\n");
        Server srv;
        if (Check(Run(srv, dir, Base()), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            const uint32_t ui = 811;
            Bind32 b = RandBind();
            p73.Send(0x11, LoginV2(20, ui, kIpLocal, 1, b));
            int accepted = 0; std::vector<Kick> all;
            SecureClient last;   // 14-й запуск остаётся жить (как 27.10 01:23: сессия снова защищена)
            for (int k = 0; k < 14; ++k)
            {
                SecureClient c;
                SecureClient& cc = k == 13 ? last : c;
                int r = EacRegister(cc, kSide, g_pub, ui, ui);
                if (r == 0) { ++accepted; EacBind(cc, 2, b); }
                auto ks = Kicks(p73, 700);
                all.insert(all.end(), ks.begin(), ks.end());
                if (k == 13) break;
                c.Close();   // падение клиента
                ks = Kicks(p73, 300);
                all.insert(all.end(), ks.begin(), ks.end());
            }
            auto ks = Kicks(p73, 4000); all.insert(all.end(), ks.begin(), ks.end());
            int fk = CountKicks(all, ui);
            falseKicks += fk;
            Check(accepted == 14, "B: все 14 REG приняты (" + std::to_string(accepted) + ") — после аутентифицированной сессии с того же IP в предел не считаются (Д2)");
            Check(fk == 0, "B: ложных KICK нет (" + std::to_string(fk) + ")");
            srv.Stop();
        }
    }
    // ── B2: REG отбит пределом с IP игры у ранее защищённой сессии — решение откладывается на окно предела ─────
    {
        printf("-- B2: защищённая игра, затем 7 REG без аутентификации (Д2-бесплатные выключены, предел 6 за 10 с)\n");
        Server srv;
        auto ov = Base(); ov["Sidecar.RegPerAccountWindowSec"] = "10"; ov["Sidecar.AuthTimeoutSec"] = "60"; ov["Policy.RegFreeAfterAuthSec"] = "0";
        if (Check(Run(srv, dir, ov), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            const uint32_t ui = 812; Bind32 b = RandBind();
            p73.Send(0x11, LoginV2(21, ui, kIpLocal, 1, b));
            { SecureClient c0; Check(EacRegister(c0, kSide, g_pub, ui, ui) == 0 && EacBind(c0, 2, b) == 0, "B2: сначала защищённая сессия"); Kicks(p73, 800); }
            int limited = 0;
            for (int k = 0; k < 7; ++k)
            {
                SecureClient c;
                int r = EacRegister(c, kSide, g_pub, ui, ui, { {"auth", "none"} });
                if (r == 3) ++limited;
                c.Close();
            }
            Check(limited >= 1, "B2: REG сверх предела отбит (REG_RESULT 3: " + std::to_string(limited) + ")");
            auto early = Kicks(p73, 6000);
            Check(CountKicks(early, ui) == 0, "B2: пока REG отбит пределом — решения нет (ждём окно предела 10 с)");
            auto late = Kicks(p73, 9000);
            Check(CountKicks(late, ui) >= 1, "B2: после окна предела без EAC-сессии — KICK");
            srv.Stop();
        }
    }
    // ── C ×2: RemoteAuthComplete в пути / повторная REG после AuthTimeout ─────────────────────
    {
        printf("-- C: C1 RemoteAuth через 4 с при BindTimeout 3 с; C2 AuthTimeout 5 с, повторная REG через 1 с (группа C)\n");
        Server srv;
        auto ovc = Base(); ovc["Policy.GraceSec"] = "5";   // Grace на стойке 30 с; стенду хватает 5 с на повторную REG
        if (Check(Run(srv, dir, ovc), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            Bind32 b1 = RandBind(), b2 = RandBind();
            p73.Send(0x11, LoginV2(30, 821, kIpLocal, 1, b1));
            p73.Send(0x11, LoginV2(31, 822, kIpLocal, 2, b2));
            Sleep(2500);   // срок BindTimeout почти вышел
            SecureClient c1, c2;
            bool r1 = EacRegister(c1, kSide, g_pub, 821, 821, { {"authDelayMs", "4000"} }) == 0 && EacBind(c1, 2, b1) == 0;
            bool r2 = EacRegister(c2, kSide, g_pub, 822, 822, { {"auth", "none"} }) == 0 && EacBind(c2, 2, b2) == 0;
            Check(r1 && r2, "C: обе REG приняты");
            auto ks = Kicks(p73, 6500);   // C1: auth в ~6,5 с от LOGIN; C2: AuthTimeout в ~7,5 с
            c2.Close();
            SecureClient c2b;   // клиент переподключился через ~1 с после закрытия канала
            Sleep(800);
            bool r2b = EacRegister(c2b, kSide, g_pub, 822, 822) == 0 && EacBind(c2b, 2, b2) == 0;
            auto ks2 = Kicks(p73, 5000);
            ks.insert(ks.end(), ks2.begin(), ks2.end());
            int fk = CountKicks(ks, 821) + CountKicks(ks, 822);
            falseKicks += fk;
            Check(CountKicks(ks, 821) == 0, "C1: RemoteAuthComplete позже BindTimeout — KICK нет (Д1)");
            Check(r2b && CountKicks(ks, 822) == 0, "C2: AuthTimeout, повторная REG аутентифицирована в пределах Grace — KICK нет (Д1)");
            srv.Stop();
        }
    }
    // ── D (ред. 2, ревизия 64): поблажка ОДНОЙ учётке при сбое EOS Connect — реальная хронология 16–17.11 ─────────────
    //   Запуск 1: учётки 831, 832, 833 (как 75220, 75216, 1) и 835 проходят EAC (история на диске), служба останавливается.
    //   Запуск 2 (та же папка — история с диска): учётки по ОДНОЙ, друг за другом (на стойке — с разницей в часы), клиент получает
    //   токены AsdaId каждые ~1,5 с (на стойке /refresh каждые 11…66 с), REG нет — KICK нет; 75228-подобная 851 без истории — KICK;
    //   атака «3 свои учётки без истории + токены» — KICK всем трём; бюджет исчерпан (834, 4 с) — KICK сразу, без нового срока;
    //   ClientActionRequired под поблажкой (835) — KICK причина 2.
    {
        printf("-- D: поблажка одной учётке «Epic Connect не проходит» (хронология 16–17.11, история на диске)\n");
        std::wstring ddir = RunDir("cases_d");
        MakeSecureKey(ddir, g_pub);
        const std::string hfile = U8(ddir) + "state\\auth_history.dat";
        auto ov = Base(); ov["Policy.AuthHistoryFile"] = hfile; ov["Policy.ConnectGraceTokenSec"] = "5"; ov["Policy.ConnectGraceSecPerDay"] = "3600";
        {
            Server srv;
            if (Check(Run(srv, ddir, ov), "D: запуск 1 — сервер запущен"))
            {
                PlainClient p73; OpenP73(p73);
                for (uint32_t ui : { 831u, 832u, 833u, 834u, 835u, 836u, 837u, 838u })
                {
                    Bind32 b = RandBind(); SecureClient c;
                    bool ok = EacRegister(c, kSide, g_pub, ui, ui) == 0 && EacBind(c, 2, b) == 0;
                    Check(ok, "D: учётка " + std::to_string(ui) + " прошла EAC (RemoteAuthComplete) — история");
                    Kicks(p73, 300);
                }
                Check(srv.Stop(), "D: запуск 1 — штатный останов (история сохранена)");
            }
            FILE* hf = _wfopen(W(hfile).c_str(), L"rb"); int lines = 0; char lb[256];
            if (hf) { while (fgets(lb, sizeof(lb), hf)) ++lines; fclose(hf); }
            Check(lines == 9, "D: файл истории на диске — заголовок v3 + 8 учёток (" + std::to_string(lines) + " строк)");
            std::string acl; bool strict = DirDaclStrict(ddir + L"state", acl);
            Check(strict, "D (Р66-4): папку state\\ служба создала с DACL без наследования — SYSTEM, Administrators, пользователь службы (" + acl + ")");
        }
        auto tokenFor = [&](uint32_t ui, int k) {
            return HttpPost(kId, "/token", "{\"login\":\"stand_u" + std::to_string(ui) + "\",\"password_md5\":\"7787e2c49efec303a6d311a19d31b8b5\"}",
                            "10.9." + std::to_string(ui % 200) + "." + std::to_string(1 + k % 200)) == 200;
        };
        Server srv;
        if (Check(Run(srv, ddir, ov), "D: запуск 2 — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
        {
            Check(srv.WaitLog("история аутентификации учёток: 8 записей", 3000), "D: история подхвачена с диска после рестарта");
            PlainClient p73; OpenP73(p73);
            uint16_t un = 60; uint32_t seq = 1;
            // учётка по одной: игровые сессии без EAC, клиент получает токены (сбой Connect), 8 с — дольше BindTimeout 3 с
            auto oneAccount = [&](uint32_t ui, int games, int ms) -> int {
                std::vector<uint16_t> mine;
                for (int g = 0; g < games; ++g) { mine.push_back(un); p73.Send(0x11, LoginV2(un++, ui, kIpLocal, seq++, RandBind())); }
                std::vector<Kick> all; int k = 0;
                for (int64_t t0 = NowMs(); NowMs() - t0 < ms;) { tokenFor(ui, k++); auto ks = Kicks(p73, 1500); all.insert(all.end(), ks.begin(), ks.end()); }
                for (uint16_t u : mine) p73.Send(0x12, Logout(u, ui, seq++));   // игрок вышел (как 16.11: LOGOUT после серии /refresh)
                return CountKicks(all, ui);
            };
            int d1 = oneAccount(831, 7, 8000), d2 = oneAccount(832, 1, 8000), d3 = oneAccount(833, 3, 8000);
            falseKicks += d1 + d2 + d3;
            Check(d1 == 0 && d2 == 0 && d3 == 0, "D: хронология 16–17.11 (учётки по одной, 7 + 1 + 3 сессий) — ложных KICK нет (" +
                  std::to_string(d1) + "/" + std::to_string(d2) + "/" + std::to_string(d3) + ")");
            Check(srv.LogHasNew("Epic Connect у клиента не проходит"), "D: журнал — «Epic Connect у клиента не проходит» (поблажка учётки)");
            Check(!srv.LogHasNew("FailOpen включён"), "D: общего FailOpen нет — поблажка только своей учётке");
            // 75228-подобная: истории нет, токенов нет (клиент без EAC)
            p73.Send(0x11, LoginV2(un++, 851, kIpLocal, seq++, RandBind()));
            auto k851 = Kicks(p73, 5000);
            keptKicks += CountKicks(k851, 851, 1) > 0;
            Check(CountKicks(k851, 851, 1) >= 1, "D: учётка без истории и без токенов (как 75228 21.10) — KICK причина 1");
            // атака: 3 свои учётки без истории + токены — ничего не даёт
            for (uint32_t ui : { 841u, 842u, 843u }) p73.Send(0x11, LoginV2(un++, ui, kIpLocal, seq++, RandBind()));
            std::vector<Kick> ka; int kk = 0;
            for (int64_t t0 = NowMs(); NowMs() - t0 < 6000;) { for (uint32_t ui : { 841u, 842u, 843u }) tokenFor(ui, kk++); auto ks = Kicks(p73, 1000); ka.insert(ka.end(), ks.begin(), ks.end()); }
            int nA = (CountKicks(ka, 841, 1) > 0) + (CountKicks(ka, 842, 1) > 0) + (CountKicks(ka, 843, 1) > 0);
            Check(nA == 3, "D: атака «3 свои учётки без истории + токены» — KICK всем трём (" + std::to_string(nA) + "), поблажки нет");
            srv.Stop();
        }
        // бюджет: 4 с в сутки — потом KICK сразу (срок давно вышел, нового не даётся); ClientActionRequired под поблажкой — KICK 2
        auto ov2 = ov; ov2["Policy.ConnectGraceSecPerDay"] = "4";
        Server srv2;
        if (Check(Run(srv2, ddir, ov2), "D: запуск 3 (бюджет 4 с) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
        {
            PlainClient p73; OpenP73(p73);
            int64_t t0 = NowMs();
            p73.Send(0x11, LoginV2(70, 834, kIpLocal, 1, RandBind()));
            std::vector<Kick> kb; int k = 0;
            while (NowMs() - t0 < 12000 && CountKicks(kb, 834) == 0) { tokenFor(834, k++); auto ks = Kicks(p73, 1000); kb.insert(kb.end(), ks.begin(), ks.end()); }
            int64_t dt = NowMs() - t0;
            Check(CountKicks(kb, 834, 1) >= 1 && dt >= 6000 && dt <= 10000, "D: бюджет поблажки 4 с исчерпан — KICK причина 1 через срок 3 с + 4 с (" + std::to_string(dt) + " мс)");
            Check(srv2.LogHasNew("поблажка Connect — исчерпана за 24 ч"), "D: журнал — поблажка исчерпана за скользящие 24 ч (Р66-1)");
            // 835: под поблажкой (история, токены), затем EAC-сессия и нарушение — KICK 2 не глушится
            Bind32 b = RandBind();
            p73.Send(0x11, LoginV2(71, 835, kIpLocal, 2, b));
            for (int i = 0; i < 3; ++i) { tokenFor(835, 100 + i); Kicks(p73, 1000); }   // под поблажкой: срок 3 с вышел, KICK нет
            SecureClient c; bool reg = EacRegister(c, kSide, g_pub, 835, 835) == 0 && EacBind(c, 2, b) == 0;
            Kicks(p73, 500);
            c.Send(0x02, std::vector<uint8_t>({ 'A', 'C', 'T', 'I', 'O', 'N', ':', '6' }));
            auto kc = Kicks(p73, 3000);
            keptKicks += CountKicks(kc, 835, 2) > 0;
            Check(reg && CountKicks(kc, 835, 2) >= 1, "D: ClientActionRequired у учётки под поблажкой — KICK причина 2 (не глушится)");
            // ★ Р66-2: пойман → перезашёл без EAC, клиент получает токены — поблажки нет, KICK
            c.Close();
            p73.Send(0x12, Logout(71, 835, 3));
            p73.Send(0x11, LoginV2(72, 835, kIpLocal, 4, RandBind()));
            std::vector<Kick> kv; for (int i = 0; i < 7 && CountKicks(kv, 835, 1) == 0; ++i) { tokenFor(835, 200 + i); auto ks = Kicks(p73, 1000); kv.insert(kv.end(), ks.begin(), ks.end()); }
            keptKicks += CountKicks(kv, 835, 1) > 0;
            Check(CountKicks(kv, 835, 1) >= 1, "D (Р66-2): после нарушения EAC перезашёл без EAC с токенами — поблажки нет, KICK причина 1");
            // ★ Р66-3: REG от учётки в этой игровой сессии был и отбит (AuthTimeout) — Connect работает, поблажки нет
            p73.Send(0x11, LoginV2(73, 836, kIpLocal, 5, RandBind()));
            SecureClient c6; bool r6 = EacRegister(c6, kSide, g_pub, 836, 836, { {"auth", "none"} }) == 0;
            std::vector<Kick> k6; for (int i = 0; i < 16 && CountKicks(k6, 836) == 0; ++i) { tokenFor(836, 300 + i); auto ks = Kicks(p73, 1000); k6.insert(k6.end(), ks.begin(), ks.end()); }
            keptKicks += CountKicks(k6, 836) > 0;
            Check(r6 && CountKicks(k6, 836) >= 1, "D (Р66-3): REG был и отбит AuthTimeout, клиент получает токены — поблажки нет, KICK");
            srv2.Stop();
        }
        // ★ Р66-1: предел эпизода (3 с) и суток с поблажкой за 30 (у 837 уже 2 прошлых дня в файле) — KICK
        {
            FILE* hf = _wfopen(W(hfile).c_str(), L"ab");
            const long long now = (long long)time(nullptr);
            if (hf) { fprintf(hf, "837 %lld 0 0 0 0 2 %lld %lld 0\n", now - 3600, now - 5 * 86400, now - 3 * 86400); fclose(hf); }   // v4: 2 прошлых окна
            auto ov3 = ov; ov3["Policy.ConnectGraceEpisodeSec"] = "3";
            Server srv3;
            if (Check(Run(srv3, ddir, ov3), "D: запуск 4 (эпизод 3 с, суток 2 за 30) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
            {
                PlainClient p73; OpenP73(p73);
                p73.Send(0x11, LoginV2(80, 838, kIpLocal, 1, RandBind()));
                p73.Send(0x11, LoginV2(81, 837, kIpLocal, 2, RandBind()));
                std::vector<Kick> k8;
                for (int i = 0; i < 12 && (CountKicks(k8, 838) == 0 || CountKicks(k8, 837) == 0); ++i)
                { tokenFor(838, 400 + i); tokenFor(837, 500 + i); auto ks = Kicks(p73, 1000); k8.insert(k8.end(), ks.begin(), ks.end()); }
                keptKicks += (CountKicks(k8, 838) > 0) + (CountKicks(k8, 837) > 0);
                Check(CountKicks(k8, 838, 1) >= 1 && srv3.LogHasNew("поблажка Connect — эпизод исчерпан"), "D (Р66-1): эпизод поблажки 3 с исчерпан — KICK причина 1");
                Check(CountKicks(k8, 837, 1) >= 1 && srv3.LogHasNew("окон поблажки по 24 ч за период уже предел"), "D (Р66-1, Р68-2): 2 окна поблажки по 24 ч за период уже были — поблажки нет, KICK");
                srv3.Stop();
            }
        }
        // ★ Р68-1: 70 коротких эпизодов подряд (токены 1 с, перерыв 1,5 с) — расход за 24 ч и окна не вытесняются: бюджет 30 с кончается
        //   и дальше не возвращается; прошлое окно (3 суток назад) остаётся в файле
        {
            FILE* hf = _wfopen(W(hfile).c_str(), L"ab");
            const long long now = (long long)time(nullptr);
            if (hf) { fprintf(hf, "839 %lld 0 0 0 0 1 %lld 0\n", now - 3600, now - 3 * 86400); fclose(hf); }
            auto ov5 = ov; ov5["Policy.ConnectGraceTokenSec"] = "1"; ov5["Policy.ConnectGraceEpisodeGapSec"] = "1"; ov5["Policy.ConnectGraceSecPerDay"] = "30";
            Server srv5;
            if (Check(Run(srv5, ddir, ov5), "D: запуск 6 (70 коротких эпизодов) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
            {
                PlainClient p73; OpenP73(p73);
                p73.Send(0x11, LoginV2(95, 839, kIpLocal, 1, RandBind()));
                Kicks(p73, 3500);   // срок BindTimeout 3 с
                for (int i = 0; i < 70; ++i) { tokenFor(839, 700 + i); Kicks(p73, 1100); Sleep(1500); }
                const int eps = srv5.LogCount("учётка 839 userNum 95: Epic Connect у клиента не проходит");
                Check(eps >= 25, "D (Р68-1): коротких эпизодов поблажки — " + std::to_string(eps) + " (больше, чем уместилось бы в бюджет без учёта)");
                Check(srv5.LogHasNew("учётка 839: поблажка Connect — исчерпана за 24 ч"), "D (Р68-1): бюджет 30 с за 24 ч исчерпан, несмотря на много эпизодов");
                srv5.Stop();
            }
            FILE* rf = _wfopen(W(hfile).c_str(), L"rb"); std::string all; char lb[70000];
            if (rf) { while (fgets(lb, sizeof(lb), rf)) all += lb; fclose(rf); }
            size_t pos = all.find("\n839 ");
            long long used = 0; int nw = -1;
            if (pos != std::string::npos)
            {
                std::istringstream is(all.substr(pos + 1, all.find('\n', pos + 1) - pos - 1));
                unsigned long long ui, la, lv, es, ed, el; is >> ui >> la >> lv >> es >> ed >> el >> nw;
                for (int i = 0; i < nw; ++i) { long long w; is >> w; }
                int nu = 0; is >> nu;
                for (int i = 0; i < nu; ++i) { long long m, ms; char c; is >> m >> c >> ms; used += ms; }
            }
            Check(nw == 2 && used > 0 && used <= 31000, "D (Р68-1): в файле у 839 — 2 окна (прошлое не вытеснено) и расход за 24 ч " +
                  std::to_string(used) + " мс ≤ 30 с");
        }
        // ★ Р70-1 / Р70-2: настоящий эпизод поблажки дольше 3 минут (такт ядра 250 мс с живым дрожанием, полные минуты расхода) →
        //   рестарт службы → строка учётки загружена, расход по минутам ≤ 60000 мс, окна на месте, поблажка продолжается;
        //   плюс подложенная строка старого вида (минута 60187 мс, эпизод 99999 с) — прижата, а не выброшена.
        {
            auto ov7 = ov; ov7["Policy.ConnectGraceTokenSec"] = "5";
            {
                Server srv7;
                if (Check(Run(srv7, ddir, ov7), "D: запуск 7 (эпизод > 3 мин) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
                {
                    PlainClient p73; OpenP73(p73);
                    p73.Send(0x11, LoginV2(97, 832, kIpLocal, 1, RandBind()));
                    std::vector<Kick> k7; int k = 0;
                    for (int64_t t0 = NowMs(); NowMs() - t0 < 200000;) { tokenFor(832, 900 + k++); auto ks = Kicks(p73, 1500); k7.insert(k7.end(), ks.begin(), ks.end()); }
                    falseKicks += CountKicks(k7, 832);
                    Check(CountKicks(k7, 832) == 0, "D (Р70-1): эпизод поблажки 200 с с живым тактом — KICK нет");
                    Check(srv7.Stop(), "D: запуск 7 — штатный останов (история записана)");
                }
            }
            // строка 832 из файла: каждая минута ≤ 60000 мс, полных минут ≥ 2, окно есть
            auto readLine = [&](const char* uid) {
                FILE* rf = _wfopen(W(hfile).c_str(), L"rb"); std::string all; char lb[70000];
                if (rf) { while (fgets(lb, sizeof(lb), rf)) all += lb; fclose(rf); }
                size_t pos = all.find(std::string("\n") + uid + " ");
                return pos == std::string::npos ? std::string() : all.substr(pos + 1, all.find('\n', pos + 1) - pos - 1);
            };
            std::string l832 = readLine("832");
            int nw = -1, nu = -1, full = 0; long long maxMs = 0;
            {
                std::istringstream is(l832); unsigned long long ui, la, lv, es, ed, el; is >> ui >> la >> lv >> es >> ed >> el >> nw;
                for (int i = 0; i < nw; ++i) { long long w; is >> w; }
                is >> nu;
                for (int i = 0; i < nu; ++i) { long long m, ms; char c; is >> m >> c >> ms; maxMs = (std::max)(maxMs, ms); full += ms >= 59000; }
            }
            Check(!l832.empty() && nw >= 1 && full >= 2 && maxMs <= 60000, "D (Р70-1): в файле у 832 — окно " + std::to_string(nw) + ", полных минут " +
                  std::to_string(full) + ", наибольшая минута " + std::to_string(maxMs) + " мс ≤ 60000");
            // подложить строку старого вида с переполненными значениями
            FILE* hf = _wfopen(W(hfile).c_str(), L"ab");
            const long long now = (long long)time(nullptr);
            if (hf) { fprintf(hf, "868 %lld 0 %lld 99999 %lld 1 %lld 1 %lld:60187\n", now - 3600, now - 4000, now - 3000, now - 4000, (now - 4000) / 60); fclose(hf); }
            Server srv8;
            if (Check(Run(srv8, ddir, ov7), "D: запуск 8 (после рестарта) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
            {
                Check(!srv8.LogHasNew("негодных строк пропущено"), "D (Р70-1): после рестарта ни одна строка истории не выброшена");
                Check(srv8.LogHasNew("поправлены / пропущены отдельные поля"), "D (Р70-2): строка с минутой 60187 мс и эпизодом 99999 с — прижата, запись сохранена");
                PlainClient p73; OpenP73(p73);
                p73.Send(0x11, LoginV2(98, 832, kIpLocal, 1, RandBind()));
                p73.Send(0x11, LoginV2(99, 868, kIpLocal, 2, RandBind()));
                std::vector<Kick> k8; int k = 0;
                for (int64_t t0 = NowMs(); NowMs() - t0 < 7000;) { tokenFor(832, 1100 + k); tokenFor(868, 1200 + k); ++k; auto ks = Kicks(p73, 1200); k8.insert(k8.end(), ks.begin(), ks.end()); }
                falseKicks += CountKicks(k8, 832) + CountKicks(k8, 868);
                Check(CountKicks(k8, 832) == 0 && CountKicks(k8, 868) == 0, "D (Р70-1): история пережила рестарт — поблажка 832 и 868 продолжается, KICK нет");
                srv8.Stop();
            }
        }
        // ★ Р66-4: чужая папка state\ (DACL по наследству) с подложенной историей — служба ей не доверяет, поблажки нет
        {
            std::wstring udir = RunDir("cases_d4");
            MakeSecureKey(udir, g_pub);
            CreateDirectoryW((udir + L"state").c_str(), nullptr);
            const std::string uf = U8(udir) + "state\\auth_history.dat";
            FILE* hf = _wfopen(W(uf).c_str(), L"wb");
            if (hf) { fprintf(hf, "#asda-auth-history v3\n861 %lld 0 0\n", (long long)time(nullptr) - 60); fclose(hf); }
            auto ov4 = Base(); ov4["Policy.AuthHistoryFile"] = uf; ov4["Policy.ConnectGraceTokenSec"] = "5";
            Server srv4;
            if (Check(Run(srv4, udir, ov4), "D: запуск 5 (подложенная папка state) — сервер запущен") && Check(WaitPort(kId, 5000), "D: AsdaId слушает"))
            {
                Check(srv4.WaitLog("НЕ доверяю", 3000), "D (Р66-4): журнал — папке state\\ не доверяю, история пустая");
                PlainClient p73; OpenP73(p73);
                p73.Send(0x11, LoginV2(90, 861, kIpLocal, 1, RandBind()));
                std::vector<Kick> k9; for (int i = 0; i < 7 && CountKicks(k9, 861) == 0; ++i) { tokenFor(861, 600 + i); auto ks = Kicks(p73, 1000); k9.insert(k9.end(), ks.begin(), ks.end()); }
                keptKicks += CountKicks(k9, 861) > 0;
                Check(CountKicks(k9, 861, 1) >= 1, "D (Р66-4): подложенная история не действует — KICK причина 1");
                srv4.Stop();
            }
        }
    }
    // ── Д4: оператор в OperatorUserIndex — KICK не шлётся, решение одно ─────────────────────
    {
        printf("-- Д4: OperatorUserIndex=841, вход без EAC, KickRepeatSec=2\n");
        Server srv;
        auto ov = Base(); ov["Policy.OperatorUserIndex"] = "841"; ov["Policy.KickRepeatSec"] = "2";
        if (Check(Run(srv, dir, ov), "сервер запущен"))
        {
            PlainClient p73; OpenP73(p73);
            p73.Send(0x11, LoginV2(50, 841, kIpLocal, 1, RandBind()));
            auto ks = Kicks(p73, 9000);
            Check(CountKicks(ks, 841) == 0, "Д4: оператору KICK не шлётся (повторов каждые KickRepeatSec нет)");
            Check(srv.LogCount("оператор (только журнал)") == 1, "Д4: решение записано один раз (" + std::to_string(srv.LogCount("оператор (только журнал)")) + ")");
            srv.Stop();
        }
    }
    // ── Р68-3: AuthHistoryDays короче окна K / запрета после нарушения — поблажка выключена, EAC работает ───────────
    {
        printf("-- Р68-3: AuthHistoryDays=10 (< 30 и < ConnectGraceAfterViolationDays 30)\n");
        Server srv;
        auto ov = Base(); ov["Policy.AuthHistoryDays"] = "10"; ov["Policy.AuthHistoryFile"] = U8(dir) + "state_r683\\auth_history.dat";
        if (Check(Run(srv, dir, ov), "Р68-3: сервер запущен (конфиг загружен)"))
        {
            Check(srv.WaitLog("поблажка Connect ВЫКЛЮЧЕНА: ошибка ключей [Policy]", 3000), "Р68-3: журнал — поблажка выключена из-за несогласованных ключей");
            PlainClient p73; OpenP73(p73); p73.Send(0x14, {}); std::vector<uint8_t> pl;
            Check(p73.RecvType(0x24, pl, 2000) == 1, "Р68-3: мост отвечает PONG — EAC работает");
            srv.Stop();
        }
    }
    printf("  ИТОГ СЛУЧАЕВ: ложных KICK по группам B, C, D — %d; оставленных KICK (A ×7 «призраки», D: без истории, ClientActionRequired) — %d\n", falseKicks, keptKicks);
    return Summary("stand_cases");
}
