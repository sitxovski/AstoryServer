// Копия помощников stand_p73.cpp (AsdaPatch_w73/stand, только чтение) — для стенда ревизии E1
// stand_p73.cpp — СТЕНД P73 «мост EAC» в AsdaPatch.dll (2026-10-16, этап Э1-В).
//
// Сервер НЕ запускается. Стенд — отдельный x86-процесс (имя НЕ GameServer.exe, DllMain патчей сам не ставит):
//   1) раскладывает настоящий образ GameServer (.text/.rdata/.data) по его адресам 0x400000+;
//   2) ставит на адреса серверных функций, которые зовут патчи, переходы в свои заглушки (GetUser, GM-флаг, сокет/getpeername,
//      писатель логов, отправка в DBManager); кик (Send_DisConnectType / ExceptionDisConnetUser) — в заглушки-регистраторы;
//   3) грузит DLL, по реестру зовёт установку P53 (журнал → файл), при нужде P47/P48, и P73 — патч сверяет площадки и ставит
//      переходы В ПАМЯТЬ СТЕНДА;
//   4) гоняет НАСТОЯЩИЕ площадки: вход ветки успеха 4001 (0x527692) / 5058 (0x52CD3E), вход SetConnectFlag (0x562910),
//      площадку кика в CheckDisConnectUser (0x526CEB) — с подставным кадром ebp.
// Режимы:
//   unit     — кодек кадров (экспорт P73_TestEncode/P73_TestDecode), очередь KICK (P73_TestKick/P73_TestSweep) и её выполнение в
//              «нити карты»: сверка слота/UserIndex, оператор, срок, уход сессии; LOGIN/LOGOUT по площадкам. Сайдкара нет.
//   journal  — Mode=0: KICK только в журнал, площадка 0x526CEB НЕ ставится.
//   chain    — общие точки: P47 (Match20000) уже держит 0x527692/0x52CD3E — P73 своих стабов не ставит и зовётся из P47_LogonMatch;
//              P48 (CountTypes 3,6,12, порог 1) кик P73 не засчитывает (код 7), 2271 не уходит.
//   mismatch — испорчен байт площадки 0x526CEB: P73 обязан вернуть Mismatch и не тронуть ни одной площадки.
//   tcp      — с фальшивым сайдкаром (stand/fake_sidecar.py, сценарий std): переподключение, HELLO + LOGIN всех, живые LOGIN/LOGOUT,
//              KICK → выполнение, чужой KICK отброшен, разрыв сайдкаром → повтор, порченый кадр → разрыв P73, монотонный seq.
// Запуск: stand_p73.exe <GameServer.exe> <AsdaPatch.dll> <unit|journal|chain|mismatch|tcp> [порт] [python.exe]
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

static int g_bad = 0, g_ok = 0;
static void Check(bool c, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    char buf[1024]; _vsnprintf_s(buf, _TRUNCATE, fmt, ap); va_end(ap);
    printf("  [%s] %s\n", c ? "OK" : "!!", buf);
    if (c) { ++g_ok; } else { ++g_bad; }
}

// ── образ хоста по его адресам ───────────────────────────────────────────────
static bool MapHost(const char* path, DWORD limitVa)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { printf("нет файла %s\n", path); return false; }
    DWORD sz = GetFileSize(h, nullptr), rd = 0;
    BYTE* f = (BYTE*)VirtualAlloc(nullptr, sz, MEM_COMMIT, PAGE_READWRITE);
    ReadFile(h, f, sz, &rd, nullptr); CloseHandle(h);
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(f + ((IMAGE_DOS_HEADER*)f)->e_lfanew);
    const DWORD base = nt->OptionalHeader.ImageBase;
    BYTE* mem = (BYTE*)VirtualAlloc((void*)base, limitVa - base, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem != (BYTE*)base) { printf("не удалось занять 0x%08X..0x%08X (ошибка %u)\n", base, limitVa, GetLastError()); return false; }
    memcpy(mem, f, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        DWORD va = base + s[i].VirtualAddress;
        DWORD n = min(s[i].SizeOfRawData, s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData);
        if (va >= limitVa) { continue; }
        if (va + n > limitVa) { n = limitVa - va; }
        memcpy((void*)va, f + s[i].PointerToRawData, n);
    }
    VirtualFree(f, 0, MEM_RELEASE);
    return true;
}

static void Redirect(DWORD va, void* target)   // mov eax, imm32 ; jmp eax (7 байт)
{
    BYTE* p = (BYTE*)va;
    p[0] = 0xB8; *(DWORD*)(p + 1) = (DWORD)target; p[5] = 0xFF; p[6] = 0xE0;
}

// Функция установки патча по имени секции: wide-строка в образе DLL → указатель на неё в PatchEntry.
typedef int (*FnApply)();
static FnApply FindApply(HMODULE dll, const wchar_t* section)
{
    BYTE* b = (BYTE*)dll;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    const DWORD size = nt->OptionalHeader.SizeOfImage;
    DWORD tLo = 0, tHi = 0;
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int k = 0; k < nt->FileHeader.NumberOfSections; ++k)
    {
        if (!memcmp(s[k].Name, ".text", 5)) { tLo = (DWORD)b + s[k].VirtualAddress; tHi = tLo + s[k].Misc.VirtualSize; }
    }
    const int L = lstrlenW(section) * 2 + 2;
    for (DWORD i = 0; i + L < size; i += 2)
    {
        if (memcmp(b + i, section, L) != 0) { continue; }
        const DWORD strVa = (DWORD)(b + i);
        for (DWORD j = 0; j + 16 < size; j += 4)
        {
            if (*(DWORD*)(b + j) != strVa) { continue; }
            const DWORD title = *(DWORD*)(b + j + 4);
            const DWORD fn    = *(DWORD*)(b + j + 8);
            const DWORD hosts = *(DWORD*)(b + j + 12);
            const bool inImg  = title > (DWORD)b && title < (DWORD)b + size;
            const bool hostOk = hosts == 0 || (hosts > (DWORD)b && hosts < (DWORD)b + size);
            if (inImg && hostOk && fn >= tLo && fn < tHi) { return (FnApply)fn; }
        }
    }
    return nullptr;
}

// ── файловый журнал P53 ──────────────────────────────────────────────────────
static void StandDir(char* out) { GetModuleFileNameA(nullptr, out, MAX_PATH); char* p = strrchr(out, '\\'); if (p) { p[1] = 0; } }
static void ClearJournalDir(const char* dir)
{
    char d[MAX_PATH]; wsprintfA(d, "%sLog", dir); CreateDirectoryA(d, nullptr);
    wsprintfA(d, "%sLog\\Log_AcJournal", dir); CreateDirectoryA(d, nullptr);
    char pat[MAX_PATH]; wsprintfA(pat, "%sLog\\Log_AcJournal\\*.sql", dir);
    WIN32_FIND_DATAA fd; HANDLE f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) { return; }
    do { char p[MAX_PATH]; wsprintfA(p, "%sLog\\Log_AcJournal\\%s", dir, fd.cFileName); DeleteFileA(p); } while (FindNextFileA(f, &fd));
    FindClose(f);
}
static int CountInJournal(const char* dir, const char* needle)
{
    char pat[MAX_PATH]; wsprintfA(pat, "%sLog\\Log_AcJournal\\AcJournal_*.sql", dir);
    WIN32_FIND_DATAA fd; HANDLE f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) { return 0; }
    int n = 0;
    do
    {
        char path[MAX_PATH]; wsprintfA(path, "%sLog\\Log_AcJournal\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { continue; }
        DWORD sz = GetFileSize(h, nullptr), rd = 0;
        char* buf = (char*)malloc(sz + 1); ReadFile(h, buf, sz, &rd, nullptr); buf[rd] = 0; CloseHandle(h);
        for (const char* p = buf; (p = strstr(p, needle)) != nullptr; p += strlen(needle)) { ++n; }
        free(buf);
    } while (FindNextFileA(f, &fd));
    FindClose(f);
    return n;
}

// ── заглушки сервера ─────────────────────────────────────────────────────────
static const int kCUserSize = 0x41000;
static BYTE* g_users[0x226] = {};
static char  g_srvlog[256][512]; static int g_srvlogCat[256]; static volatile LONG g_srvlogN = 0;
static volatile LONG g_sendDbN = 0;
static volatile LONG g_discN = 0, g_discType = -1, g_discUser = -1, g_excN = 0;

static BYTE* NewUser(int userNum, int userIndex, const char* name, bool gm)
{
    if (!g_users[userNum]) { g_users[userNum] = (BYTE*)VirtualAlloc(nullptr, kCUserSize, MEM_COMMIT, PAGE_READWRITE); }
    BYTE* u = g_users[userNum];
    memset(u, 0, kCUserSize);
    *(short*)(u + 0x0C) = (short)userNum;
    u[0x2E] = 1;                                 // в мире
    *(int*)(u + 0x174) = userIndex;
    lstrcpynA((char*)(u + 0x178), name, 20);
    u[0x18C] = 2;
    u[0x40B9F] = gm ? 1 : 0;                     // GM-флаг
    return u;
}
static BYTE* __fastcall M_GetUser(void*, void*, int n)        { n = (short)n; return (n >= 0 && n < 0x226) ? g_users[n] : nullptr; }
static int   __fastcall M_GetUserIx(void*, void*, int n)      { n = (short)n; return (n >= 0 && n < 0x226 && g_users[n]) ? *(int*)(g_users[n] + 0x174) : -1; }
static char  __fastcall M_GetSlot(void*, void*, int n)        { n = (short)n; return (n >= 0 && n < 0x226 && g_users[n]) ? g_users[n][0x18C] : 0; }
static int   __fastcall M_IsGm(void*, void*, int n)           { n = (short)n; return (n >= 0 && n < 0x226 && g_users[n]) ? g_users[n][0x40B9F] : 0; }
static char  __fastcall M_GetGroup(void*, void*)              { return 1; }
static short __fastcall M_GetDbConn(void*, void*)             { return 0; }
static int   __fastcall M_SendDb(void*, void*, short, short, short, void*, short) { InterlockedIncrement(&g_sendDbN); return 1; }
static UINT_PTR __fastcall M_GetSocket(void*, void*, int n)   { return (UINT_PTR)(1000 + (short)n); }
static void __cdecl M_SrvLog(int cat, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    const LONG i = InterlockedIncrement(&g_srvlogN) - 1;
    if (i < 256) { _vsnprintf_s(g_srvlog[i], _TRUNCATE, fmt, ap); g_srvlogCat[i] = cat; }
    va_end(ap);
}
static int __stdcall M_getpeername(UINT_PTR s, void* name, int* len)
{
    if (!name || !len || *len < 16) { return -1; }
    BYTE* a = (BYTE*)name; memset(a, 0, 16);
    *(short*)a = 2; a[4] = 192; a[5] = 168; a[6] = 31; a[7] = (BYTE)(s - 1000);
    *len = 16; return 0;
}
// Send_DisConnectType (thiscall i16, u8; ret 8) и ExceptionDisConnetUser (thiscall i16, char*; ret 8) — регистраторы.
static void  __fastcall M_Disc(void*, void*, int n, int type)        { InterlockedIncrement(&g_discN); g_discType = (BYTE)type; g_discUser = (short)n; }
static void* __fastcall M_ExcDisc(void*, void*, int n, const char*)  { InterlockedIncrement(&g_excN); (void)n; return nullptr; }
// Тело Send_DisConnectType ПОСЛЕ пролога (0x52EDB6) — когда вход держит стаб P48 (режим chain): записать тип и выйти как функция.
static void __cdecl RecordDisc(int userNum, int type) { InterlockedIncrement(&g_discN); g_discType = (BYTE)type; g_discUser = (short)userNum; }
static __declspec(naked) void LandDiscBody()
{
    __asm
    {
        movzx eax, byte ptr [ebp+0x0C]
        push  eax
        movsx eax, word ptr [ebp+0x08]
        push  eax
        call  RecordDisc
        add   esp, 8
        mov   esp, ebp
        pop   ebp
        ret   8
    }
}
static const char* LastLog() { const LONG n = g_srvlogN; return n ? g_srvlog[(n - 1) & 255] : ""; }

// ── точки приземления ────────────────────────────────────────────────────────
static volatile int g_landed = -1;
static void __cdecl LandOk()       { g_landed = 1; }    // 0x527698 / 0x52CD44 — продолжение ветки успеха логона
static void __cdecl LandRefuse()   { g_landed = 9; }    // 0x52764D — стоковая ветка отказа 4001 (P47 сверка)
static void __cdecl LandContinue() { g_landed = 2; }    // 0x526CF1 — сток продолжает проверки игрока
static void __cdecl LandLoop()     { g_landed = 3; }    // 0x526E36 — следующий игрок (после кика)
// 0x562915 — тело SetConnectFlag после украденного пролога: выйти как функция (thiscall, 2 аргумента).
static __declspec(naked) void LandConn()
{
    __asm
    {
        mov   esp, ebp
        pop   ebp
        ret   8
    }
}

// ── запуск настоящего кода хоста с подставным кадром ebp ──
static void RunAt(DWORD va, BYTE* ebpFrame)
{
    __asm
    {
        mov   eax, va
        mov   edx, ebpFrame
        push  ebx
        push  esi
        push  edi
        push  ebp
        mov   ebp, edx
        call  eax
        pop   ebp
        pop   edi
        pop   esi
        pop   ebx
    }
}

struct P73_Stats
{
    LONG logons, logouts, loginSent, logoutSent, pingSent, pongReceived, kickReceived, kickQueued, kickDone, kickDropped,
         kickExpired, kickOperator, queueDropped, connects, disconnects, protoErrors, rebinds, rebindSent;
};
typedef void (__stdcall *FnStats)(P73_Stats*);
typedef int  (__stdcall *FnEncode)(int, const BYTE*, int, BYTE*, int);
typedef int  (__stdcall *FnDecode)(const BYTE*, int, int, BYTE*, int*, int, int*);
typedef void (__stdcall *FnKick)(const BYTE*);
typedef void (__stdcall *FnSweep)();
static FnStats  pStats;
static FnEncode pEncode;
static FnDecode pDecode;
static FnKick   pKick;
static FnSweep  pSweep;
static P73_Stats St() { P73_Stats s = {}; if (pStats) { pStats(&s); } return s; }

template <class T> static T Exp(HMODULE dll, const char* name, const char* deco)
{
    FARPROC p = GetProcAddress(dll, name);
    if (!p) { p = GetProcAddress(dll, deco); }
    return (T)p;
}

static int Launch()
{
    char cmd[2048] = "";
    lstrcpynA(cmd, GetCommandLineA(), sizeof(cmd));
    SetEnvironmentVariableA("STAND_P73_CHILD", "1");
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        printf("CreateProcess: %u\n", GetLastError()); return 2;
    }
    void* r1 = VirtualAllocEx(pi.hProcess, (void*)0x00400000, 0x005B0000 - 0x00400000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!r1) { printf("резерв диапазона в дочернем процессе не удался: %u\n", GetLastError()); TerminateProcess(pi.hProcess, 2); return 2; }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 2; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)code;
}

static bool Bytes(DWORD va, const char* hex)
{
    const BYTE* p = (const BYTE*)va;
    for (int i = 0; hex[i * 2]; ++i)
    {
        unsigned v; sscanf_s(hex + i * 2, "%2x", &v);
        if (p[i] != (BYTE)v) { return false; }
    }
    return true;
}
static DWORD JmpTarget(DWORD va) { return *(BYTE*)va == 0xE9 ? va + 5 + *(int*)(va + 1) : 0; }

// ── действия «сервера» ───────────────────────────────────────────────────────
static BYTE g_frame[0x3000];
static BYTE* Ebp() { memset(g_frame, 0, sizeof(g_frame)); return g_frame + 0x1800; }
static BYTE g_mgr[0x100] = {};

static int Logon4001(int userNum, int userIndex)
{
    BYTE* ebp = Ebp();
    *(int*)(ebp - 0x424) = userIndex;
    *(BYTE**)(ebp - 0x428) = g_users[userNum];
    *(DWORD*)(ebp + 8) = 0xBEEF0000u | (WORD)userNum;          // старшее слово — мусор, как в живом кадре
    *(void**)(ebp - 0x430) = g_mgr;
    g_landed = -1;
    RunAt(0x00527692, ebp);
    return g_landed;
}
static int Logon5058(int userNum, int userIndex)
{
    BYTE* ebp = Ebp();
    *(int*)(ebp - 0x430) = userIndex;
    *(BYTE**)(ebp - 0x434) = g_users[userNum];
    *(DWORD*)(ebp + 8) = 0xBEEF0000u | (WORD)userNum;
    g_landed = -1;
    RunAt(0x0052CD3E, ebp);
    return g_landed;
}
typedef void (__fastcall *FnSetConn)(void* self, void* edx, int slot, int flag);
static void SetConn(int slot, int flag) { ((FnSetConn)0x00562910)((void*)0x12345678, nullptr, 0xDEAD0000 | (WORD)slot, flag); }
// ★ ред. 2: стоковый charLogonCommunityRes_0 (0x5285F0, thiscall mgr, i16 userNum, пакет; ret 8) — заглушка: пишет блок
//   соулмейта, как сток из тела 2145 (SoulState CUser+0x182D3, iMateUserIndex CUser+0x182C6), и считает вызовы.
static volatile LONG g_commN = 0;
static int g_commMate[0x226] = {};      // 0 — не соулмейт; иначе iMateUserIndex (учётка сессии)
static void __fastcall M_CommunityRes(void*, void*, int n, void*)
{
    n = (short)n;
    InterlockedIncrement(&g_commN);
    if (n < 0 || n >= 0x226 || !g_users[n]) { return; }
    g_users[n][0x182D3] = g_commMate[n] ? 2 : 0;
    *(int*)(g_users[n] + 0x182C6) = g_commMate[n] ? g_commMate[n] : -1;
}
// Площадка 0x430B10 в диспетчере ответов БД: исполняем стоковый кусок 0x430AF8 (lea/push пакет, push userNum, ecx = CUserManager,
//   call) с подставным кадром; продолжение 0x430B15 перенаправлено в LandOk.
static BYTE g_thr[0x100] = {}, g_thrObj[0x100] = {};
static int Community(int userNum, int mate)
{
    g_commMate[userNum] = mate;
    BYTE* ebp = Ebp();
    *(DWORD*)(ebp - 0x08) = 0xABCD0000u | (WORD)userNum;
    *(void**)(ebp - 0x1028) = g_thrObj;
    *(void**)(g_thrObj + 4) = g_thr;
    *(void**)(g_thr + 0x34) = g_mgr;
    g_landed = -1;
    RunAt(0x00430AF8, ebp);
    return g_landed;
}

static int CheckUser(int userNum)
{
    BYTE* ebp = Ebp();
    *(void**)(ebp - 0x14) = g_mgr;
    *(DWORD*)(ebp - 0x08) = 0xFFFF0000u | (WORD)userNum;
    *(BYTE**)(ebp - 0x0C) = g_users[userNum];
    g_landed = -1;
    RunAt(0x00526CEB, ebp);
    return g_landed;
}
static void KickPayload(BYTE* p, int userNum, int userIndex, int our, int eos)
{
    *(WORD*)p = (WORD)userNum; memcpy(p + 2, &userIndex, 4); p[6] = (BYTE)our; p[7] = (BYTE)eos;
}

// ── status.json фальшивого сайдкара ──
static bool WaitPhase(const char* path, const char* phase, DWORD ms)
{
    const DWORD t0 = GetTickCount();
    char want[64]; wsprintfA(want, "\"%s\"", phase);   // ищем в списке пройденных фаз «seen» (и в текущей)
    while (GetTickCount() - t0 < ms)
    {
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            char buf[512] = {}; DWORD rd = 0; ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr); CloseHandle(h);
            if (strstr(buf, want)) { return true; }
        }
        Sleep(50);
    }
    return false;
}
template <class F> static bool WaitFor(F f, DWORD ms) { const DWORD t0 = GetTickCount(); while (GetTickCount() - t0 < ms) { if (f()) { return true; } Sleep(20); } return f(); }

