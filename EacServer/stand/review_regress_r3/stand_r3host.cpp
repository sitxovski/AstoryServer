// Copyright (c) 2026 @sitxovski (Discord)
// stand_r3host.cpp — стенд ревизии R3 (agent-eac-review-r3, 16.10.2026): НАСТОЯЩАЯ DLL основной AsdaPatch (P61 + P73 ред. 3)
//   в x86-хосте с образом стокового GameServer против ВНЕШНЕГО настоящего сайдкара (AsdaEacServer_stand.exe).
//   Отличие от стенда E1 (review_e1/e2e/stand_e2e.cpp): ставится ещё и P61 (прослойка AsdaSecure игрового соединения) —
//   рукопожатие клиента проходит через НАСТОЯЩИЙ AsdaWire внутри DLL (P61_RecvRouteC по .map), и P73 берёт bind слота своим
//   штатным путём P73_OnLogon → P61_SlotBinding → AsdaWire::SlotChannelBinding (P73_TestSetBind НЕ зовётся).
//   Управление по TCP 127.0.0.1:<ctl>, одна строка — один ответ:
//     user n ui | gm n ui | conn n flag | rx n <hex> (→ "ok r <hex отправленного сервером>") | l4001 n ui | l5058 n ui |
//     comm n mate | check n | stats | quit
// Запуск: stand_r3host.exe <GameServer.exe> <AsdaPatch.dll> <AsdaPatch.map> <p73mode 0|1> <bridgePort> <ctlPort>
//   рядом с exe должен лежать secure_server.key (кладёт оркестратор).
#include <winsock2.h>
#include "stand_e2e_base.inc"
#pragma comment(lib, "ws2_32.lib")

// Статистика P73 ред. 3 (19 полей, Patches.h); запас — чтобы рост структуры не испортил стек стенда.
struct P73StatsR3 { LONG v[64]; };

// Ответ в управляющее соединение.
static void Reply(SOCKET c, const char* fmt, ...)
{
    static char b[16384]; va_list ap; va_start(ap, fmt); _vsnprintf_s(b, _TRUNCATE, fmt, ap); va_end(ap);
    lstrcatA(b, "\n"); send(c, b, lstrlenA(b), 0);
}

// ── заглушки Ciocp для P61 ──
static BYTE  g_tx[0x226][8192];            // что «сервер» отправил в слот (ServerHello и пр.)
static int   g_txN[0x226] = {};
static volatile LONG g_sendN = 0;
// Ciocp::Send 0x561F20 — thiscall(this, slot, src, len), ret 0xC.
static int __fastcall M_CiocpSend(void*, void*, int slot, const void* src, int len)
{
    InterlockedIncrement(&g_sendN);
    slot = (short)slot;
    if (slot >= 0 && slot < 0x226 && len > 0 && g_txN[slot] + len <= (int)sizeof(g_tx[slot])) { memcpy(g_tx[slot] + g_txN[slot], src, len); g_txN[slot] += len; }
    return 1;
}
// Ciocp::GetConnectFlag 0x5629C0 — thiscall(this, slot), ret 4: 0 — P61_Kill не зовёт DisConnect (сокетов в стенде нет).
static volatile LONG g_killN = 0;
static int __fastcall M_GetConnFlag(void*, void*, int) { InterlockedIncrement(&g_killN); return 0; }

// Стоковый разборщик приёма sub_563C20 (thiscall this, buf, size, slot; ret 0xC) — поток Legacy-слота просто принимается.
static volatile LONG g_sinkN = 0;
static int __fastcall M_Sink(void*, void*, const void*, int size, int) { InterlockedIncrement(&g_sinkN); return size; }

// Поддельный объект Ciocp по раскладке P61 kStockLayout {lock 0x060D1830, sessPtr 0x060D1898, stride 0xA0BE, conn +4, inFlight +8,
//   pending +0xA0B2}: мост читает поля сессии под замком L до стокового Send. Сессия: conn=1, запись в полёте=1, досылка 0.
static BYTE* g_ciocp = nullptr;
static bool MakeCiocp()
{
    g_ciocp = (BYTE*)VirtualAlloc(nullptr, 0x060D2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE* sess = (BYTE*)VirtualAlloc(nullptr, 0x226 * 0xA0BE + 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_ciocp || !sess) { return false; }
    InitializeCriticalSection((CRITICAL_SECTION*)(g_ciocp + 0x060D1830));
    *(BYTE**)(g_ciocp + 0x060D1898) = sess;
    for (int i = 0; i < 0x226; ++i) { BYTE* q = sess + (size_t)i * 0xA0BE; *(LONG*)(q + 4) = 1; q[8] = 1; *(LONG*)(q + 0xA0B2) = 0; }
    return true;
}

// Адрес функции DLL по .map (Preferred load address 0x10000000).
static void* MapSym(HMODULE dll, const char* mapPath, const char* sym)
{
    FILE* f = nullptr; if (fopen_s(&f, mapPath, "rb") || !f) { return nullptr; }
    char line[1024]; DWORD rva = 0;
    while (fgets(line, sizeof(line), f))
    {
        char seg[32], name[512]; unsigned va = 0;
        if (sscanf_s(line, " %31s %511s %x", seg, (unsigned)sizeof(seg), name, (unsigned)sizeof(name), &va) == 3 && !lstrcmpA(name, sym)) { rva = va - 0x10000000u; break; }
    }
    fclose(f);
    return rva ? (BYTE*)dll + rva : nullptr;
}

typedef int (__cdecl *FnRecvRoute)(void* ciocpThis, int slot, const void* buf, int size, const unsigned char** out);
static FnRecvRoute pRecv = nullptr;

// Вызов приёма моста под SEH: исключение → код в журнал стенда, -1000.
static DWORD g_exCode = 0; static void* g_exAddr = nullptr;
static HMODULE g_dllMod = nullptr;
static int SehFilter(EXCEPTION_POINTERS* ep)
{
    g_exCode = ep->ExceptionRecord->ExceptionCode; g_exAddr = ep->ExceptionRecord->ExceptionAddress;
    // адреса возврата в DLL на стеке (для сверки с .map: RVA + 0x10000000)
    DWORD* sp = (DWORD*)ep->ContextRecord->Esp; int k = 0;
    printf("eax=%08X ecx=%08X edx=%08X; стек → DLL:", ep->ContextRecord->Eax, ep->ContextRecord->Ecx, ep->ContextRecord->Edx);
    for (int i = 0; i < 400 && k < 12; ++i) { DWORD v = sp[i]; if (v > (DWORD)g_dllMod && v < (DWORD)g_dllMod + 0x200000) { printf(" %08X", v - (DWORD)g_dllMod + 0x10000000); ++k; } }
    printf("\n");
    return EXCEPTION_EXECUTE_HANDLER;
}
static int SafeRecv(int slot, const BYTE* b, int n, const unsigned char** out)
{
    __try { return pRecv(g_ciocp, slot, b, n, out); }
    __except (SehFilter(GetExceptionInformation()))
    {
        HMODULE m = nullptr; char mn[MAX_PATH] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)g_exAddr, &m)) { GetModuleFileNameA(m, mn, MAX_PATH); }
        printf("модуль %s +0x%X\n", mn, (unsigned)((BYTE*)g_exAddr - (BYTE*)m));
        printf("исключение %08X по адресу %p\n", g_exCode, g_exAddr); return -1000; }
}

static int Hex(char c) { return c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : (c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1)); }

int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 7) { printf("usage: stand_r3host <GameServer.exe> <AsdaPatch.dll> <AsdaPatch.map> <p73mode> <bridgePort> <ctlPort>\n"); return 2; }
    char child[4] = "";
    if (!GetEnvironmentVariableA("STAND_P73_CHILD", child, sizeof(child))) { return Launch(); }
    const int p73mode = atoi(argv[4]), brPort = atoi(argv[5]), ctlPort = atoi(argv[6]);
    if (!MapHost(argv[1], 0x005B0000)) { return 2; }
    char sdir[MAX_PATH]; StandDir(sdir);
    ClearJournalDir(sdir);
    char cfgDir[MAX_PATH]; wsprintfA(cfgDir, "%sConfigSet", sdir); CreateDirectoryA(cfgDir, nullptr);
    char ini[MAX_PATH]; wsprintfA(ini, "%sConfigSet\\patches.ini", sdir);
    DeleteFileA(ini);
    const char* J = "P53_AcJournal";
    WritePrivateProfileStringA(J, "Enabled", "1", ini);
    WritePrivateProfileStringA(J, "StockSites", "0", ini);
    WritePrivateProfileStringA(J, "ConnectionString", "", ini);
    WritePrivateProfileStringA(J, "DbConfigFile", "no_such_DBMng.ini", ini);
    WritePrivateProfileStringA(J, "FlushIntervalMs", "100", ini);
    WritePrivateProfileStringA(J, "PurgeDays", "0", ini);
    WritePrivateProfileStringA(J, "ServerName", "STAND-r3", ini);
    WritePrivateProfileStringA(J, "PerSessionPerMinute", "600", ini);
    const char* S = "P61_TrafficEncryption";
    WritePrivateProfileStringA(S, "Enabled", "1", ini);
    WritePrivateProfileStringA(S, "AllowLegacy", "1", ini);
    WritePrivateProfileStringA(S, "KeyFile", "secure_server.key", ini);
    WritePrivateProfileStringA(S, "HandshakePool", "4", ini);
    const char* P = "P73_EacBridge";
    char portS[16]; wsprintfA(portS, "%d", brPort);
    WritePrivateProfileStringA(P, "Enabled", "1", ini);
    WritePrivateProfileStringA(P, "Mode", p73mode ? "1" : "0", ini);
    WritePrivateProfileStringA(P, "Port", portS, ini);
    // KickType НЕ задаётся — проверяется умолчание ред. 3 (6)
    WritePrivateProfileStringA(P, "ExemptOperators", "1", ini);
    WritePrivateProfileStringA(P, "KickPendingSec", "30", ini);
    WritePrivateProfileStringA(P, "PongTimeoutSec", "20", ini);
    WritePrivateProfileStringA(P, "ServerKind", "0", ini);
    WritePrivateProfileStringA(P, "GamePort", "15601", ini);
    WritePrivateProfileStringA("P47_IdentityOperatorGate", "Enabled", "0", ini);
    WritePrivateProfileStringA("P48_KickAutoBlock", "Enabled", "0", ini);

    Redirect(0x005324A0, (void*)&M_GetUser);
    Redirect(0x005324F0, (void*)&M_GetUserIx);
    Redirect(0x00532530, (void*)&M_GetSlot);
    Redirect(0x0052ED50, (void*)&M_IsGm);
    Redirect(0x004A7EA0, (void*)&M_GetGroup);
    Redirect(0x004C0A30, (void*)&M_GetDbConn);
    Redirect(0x005646C0, (void*)&M_SendDb);
    Redirect(0x00564F50, (void*)&M_GetSocket);
    Redirect(0x00569DF0, (void*)&M_SrvLog);
    *(DWORD*)0x00583230 = (DWORD)&M_getpeername;
    Redirect(0x0052EDB0, (void*)&M_Disc);
    Redirect(0x00526E40, (void*)&M_ExcDisc);
    Redirect(0x00561F20, (void*)&M_CiocpSend);     // Ciocp::Send (не площадка P61 — площадки это вызовы)
    Redirect(0x005629C0, (void*)&M_GetConnFlag);   // Ciocp::GetConnectFlag (не площадка)
    Redirect(0x00563C20, (void*)&M_Sink);          // CCircleQ::CopyToWriteBuffer (не площадка; площадка — вызов 0x564CD5)

    if (!MakeCiocp()) { printf("нет памяти под поддельный Ciocp\n"); return 2; }
    HMODULE dll = LoadLibraryA(argv[2]);
    if (!dll) { printf("LoadLibrary %s: %u\n", argv[2], GetLastError()); return 2; }
    g_dllMod = dll;
    pStats = Exp<FnStats>(dll, "P73_GetStats", "_P73_GetStats@4");
    pRecv = (FnRecvRoute)MapSym(dll, argv[3], "_P61_RecvRouteC");
    FnApply aJ = FindApply(dll, L"P53_AcJournal");
    FnApply a61 = FindApply(dll, L"P61_TrafficEncryption");
    FnApply a73 = FindApply(dll, L"P73_EacBridge");
    if (!aJ || !a61 || !a73 || !pStats || !pRecv) { printf("реестр/экспорт/символ .map не найден\n"); return 1; }
    aJ();
    const int r61 = a61();
    const int r73 = a73();
    printf("P61 установка = %d, P73 установка = %d (Mode=%d, мост 127.0.0.1:%d); P61_RecvRouteC @%p\n", r61, r73, p73mode, brPort, (void*)pRecv);
    if (r61 != 0 || r73 != 0) { return 1; }
    // P61 держит 0x562910 (детур SetConnectFlag) — P73 свой не ставит; продолжение 0x562915 → выход как функция.
    printf("0x562910: %02X (jmp ожидается E9 → P61_SetConnTramp)\n", *(BYTE*)0x00562910);
    Redirect(0x00527698, (void*)&LandOk);
    Redirect(0x0052CD44, (void*)&LandOk);
    Redirect(0x00562915, (void*)&LandConn);
    if (p73mode) { Redirect(0x00526CF1, (void*)&LandContinue); Redirect(0x00526E36, (void*)&LandLoop); }
    Redirect(0x00430B15, (void*)&LandOk);
    Redirect(0x005285F0, (void*)&M_CommunityRes);

    WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons((u_short)ctlPort); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (sockaddr*)&a, sizeof(a)) != 0 || listen(ls, 1) != 0) { printf("ctl bind %d: %d\n", ctlPort, WSAGetLastError()); return 1; }
    printf("ctl 127.0.0.1:%d ждёт оркестратор\n", ctlPort);
    SOCKET c = accept(ls, nullptr, nullptr);
    static char line[16384]; int ln = 0;
    static BYTE bin[8192];
    static char hexOut[16384 + 8];
    for (;;)
    {
        char ch; const int n = recv(c, &ch, 1, 0);
        if (n <= 0) { break; }
        if (ch != '\n') { if (ln < (int)sizeof(line) - 1) { line[ln++] = ch; } continue; }
        line[ln] = 0; ln = 0;
        char cmd[32] = ""; int x = 0, y = 0;
        sscanf_s(line, "%31s %d %d", cmd, (unsigned)sizeof(cmd), &x, &y);
        if (!lstrcmpA(cmd, "user"))       { NewUser(x, y, "R3", false); Reply(c, "ok"); }
        else if (!lstrcmpA(cmd, "gm"))    { NewUser(x, y, "R3GM", true); Reply(c, "ok"); }
        else if (!lstrcmpA(cmd, "l4001")) { Reply(c, "ok %d", Logon4001(x, y)); }
        else if (!lstrcmpA(cmd, "l5058")) { Reply(c, "ok %d", Logon5058(x, y)); }
        else if (!lstrcmpA(cmd, "comm"))  { Reply(c, "ok %d", Community(x, y)); }
        else if (!lstrcmpA(cmd, "conn"))  { if (x >= 0 && x < 0x226) { g_txN[x] = 0; } ((FnSetConn)0x00562910)(g_ciocp, nullptr, 0xDEAD0000 | (WORD)x, y); Reply(c, "ok"); }
        else if (!lstrcmpA(cmd, "rx"))
        {
            // rx n <hex>: байты клиента в НАСТОЯЩИЙ приём моста P61 (AsdaWire::RecvRoute), ответ — что сервер отправил в слот.
            const char* h = strchr(line, ' '); h = h ? strchr(h + 1, ' ') : nullptr;
            int nb = 0;
            if (h) { ++h; while (h[0] && h[1] && nb < (int)sizeof(bin)) { int hi = Hex(h[0]), lo = Hex(h[1]); if (hi < 0 || lo < 0) { break; } bin[nb++] = (BYTE)(hi * 16 + lo); h += 2; } }
            const int before = (x >= 0 && x < 0x226) ? g_txN[x] : 0;
            const unsigned char* out = nullptr;
            const int r = SafeRecv(x, bin, nb, &out);
            int k = 0; const int after = (x >= 0 && x < 0x226) ? g_txN[x] : 0;
            for (int i = before; i < after && k < 16384; ++i) { wsprintfA(hexOut + k, "%02x", g_tx[x][i]); k += 2; }
            hexOut[k] = 0;
            Reply(c, "ok %d %s", r, k ? hexOut : "-");
        }
        else if (!lstrcmpA(cmd, "check"))
        {
            const LONG d0 = g_discN; const int r = CheckUser(x);
            Reply(c, "ok %d disc %d type %d", r, (int)(g_discN - d0), (int)g_discType);
        }
        else if (!lstrcmpA(cmd, "stats"))
        {
            P73StatsR3 s = {}; ((void(__stdcall*)(P73StatsR3*))pStats)(&s);
            Reply(c, "ok logons %d loginSent %d logoutSent %d pong %d kickRecv %d kickQueued %d kickDone %d kickDropped %d connects %d disconnects %d "
                     "proto %d rebinds %d rebindSent %d loginBindZero %d kills %d",
                  s.v[0], s.v[2], s.v[3], s.v[5], s.v[6], s.v[7], s.v[8], s.v[9], s.v[13], s.v[14], s.v[15], s.v[16], s.v[17], s.v[18], (int)g_killN);
        }
        else if (!lstrcmpA(cmd, "quit")) { Reply(c, "ok"); break; }
        else { Reply(c, "err"); }
    }
    closesocket(c);
    TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}
