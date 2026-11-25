// Copyright (c) 2026 @sitxovski (Discord)
// test_l06.cpp — юнит-тест L06 (MAC из cred-блока → 5-й '%s' EXEC UPUserLogin) и цепочки L06→L03.
// Сборка (после vcvars32): cl /nologo /utf-8 /EHa /MT /Fo:obj\ tools\test_l06.cpp obj\l06_login_mac.obj
//   obj\l03_login_sql_refuse.obj obj\Config.obj obj\Log.obj obj\Hook.obj user32.lib kernel32.lib /Fe:obj\test_l06.exe
//   /link /BASE:0x30000000 /FIXED /DYNAMICBASE:NO      ← [fix13] обязательно: тест занимает адреса LoginManager 0x400000+
//
// [fix13, 2026-10-13] Раздел «установка»: настоящие L03_LoginSqlRefuse()/L06_LoginMac() ставятся на подставную площадку
// 0x407263 (`call sub_40F440`, байты стока; сборщик 0x40F440 → стаб) в ОБОИХ порядках (3→6 реестр, 6→3) и при каждом
// выключенном (Enabled из ConfigSet\patches.ini рядом с тестом); затем площадка исполняется как у стока (14 аргументов,
// add esp,38h вызывающего): честный вход, апостроф в логине/пароле, апостроф в MAC; баланс стека. Ожидание одно для
// обоих порядков. Тест запускает сам себя приостановленным и резервирует 0x400000.. в дочернем процессе (как stand_p66).
//
// Трамплин зовётся по-настоящему: подделывается кадр sub_406C20 (ebp → буфер, Buf1 = ebp-0x110) и
// 14 аргументов сборщика (cdecl); стаб сборщика записывает, что ему пришло 11-м аргументом.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

extern "C" int   __cdecl L06_SanitizeMac(const char* src, char* dst, int strict, int lower);
extern "C" void  __cdecl L06_TestSetup(void* next, int strict, int lower);
extern "C" void* __cdecl L06_TestGetTrampoline();
extern "C" void* __cdecl L03_TestGetTrampoline();
extern "C" void  __cdecl L03_TestSetup(void* builder);
enum class PatchResult { Applied, Disabled, Mismatch, Failed };
PatchResult L03_LoginSqlRefuse();
PatchResult L06_LoginMac();
namespace Config { bool Init(const wchar_t* baseDir); }

static int   g_fail = 0;
static int   g_builderCalls = 0;
static char  g_gotMac[64];
static const char* g_gotLogin = nullptr;
static const char* g_gotPass  = nullptr;
static void* g_gotOut = nullptr;
static int   g_gotArgc = 0;

#define CHECK(cond, msg) do { if (cond) printf("  ok: %s\n", msg); else { printf("  FAIL: %s\n", msg); g_fail = 1; } } while (0)

// Стаб sub_40F440: __cdecl varargs, как сток. Запоминает 7..11-й аргументы, ставит *out = 1.
static int __cdecl FakeBuilder(int ctx, int* out, int zero, int db, void* dst, const char* fmt, ...)
{
    (void)ctx; (void)zero; (void)db; (void)dst;
    ++g_builderCalls;
    va_list ap; va_start(ap, fmt);
    g_gotLogin = va_arg(ap, const char*);
    g_gotPass  = va_arg(ap, const char*);
    (void)va_arg(ap, const char*);     // ip
    (void)va_arg(ap, int);             // v45
    const char* mac = va_arg(ap, const char*);
    va_end(ap);
    strncpy(g_gotMac, mac ? mac : "(null)", 63); g_gotMac[63] = 0;
    g_gotOut = out;
    g_gotArgc = strstr(fmt, "UPUserLogin") ? 14 : 0;
    out[0] = 1;
    return 1;
}

// Вызов трамплина с поддельным кадром: ebp = frame, 14 аргументов cdecl, снятие 0x38 как у стока.
static BYTE  g_mem[0x400];
static void* g_args[14];
static int CallSite(void* tramp, BYTE* frame)
{
    int r = 0;
    __asm
    {
        push ebx
        push esi
        push edi
        mov  edi, tramp
        mov  ebx, frame
        lea  esi, g_args
        push ebp
        mov  ebp, ebx
        push dword ptr [esi + 52]
        push dword ptr [esi + 48]
        push dword ptr [esi + 44]
        push dword ptr [esi + 40]
        push dword ptr [esi + 36]
        push dword ptr [esi + 32]
        push dword ptr [esi + 28]
        push dword ptr [esi + 24]
        push dword ptr [esi + 20]
        push dword ptr [esi + 16]
        push dword ptr [esi + 12]
        push dword ptr [esi + 8]
        push dword ptr [esi + 4]
        push dword ptr [esi + 0]
        call edi
        add  esp, 0x38
        pop  ebp
        mov  r, eax
        pop  edi
        pop  esi
        pop  ebx
    }
    return r;
}

static int  g_out[5];
static char g_v33[12];
static int RunSite(void* tramp, const char* macField, const char* login, const char* pass)
{
    memset(g_mem, 0xCC, sizeof(g_mem));
    BYTE* frame = g_mem + 0x200;                 // Buf1 = frame-0x110 .. frame-0x1D
    memset(frame - 0x110, 0, 0xF3);
    if (macField) { memcpy(frame - 0x110 + 113, macField, strlen(macField) > 17 ? 17 : strlen(macField)); }
    memset(g_out, 0xEE, sizeof(g_out)); memset(g_v33, 0, sizeof(g_v33));
    g_builderCalls = 0; g_gotMac[0] = 0; g_gotLogin = g_gotPass = nullptr; g_gotOut = nullptr;
    static int   v45 = 2;
    static char  v29[12], v25[12], v16[32];
    g_args[0]  = (void*)0x43ACD8;  g_args[1] = g_out;  g_args[2] = 0;  g_args[3] = (void*)7;
    g_args[4]  = (void*)g_mem;     g_args[5] = (void*)"EXEC UPUserLogin '%s','%s','%s', %d, '%s', '%s', '%s', '%s'";
    g_args[6]  = (void*)login;     g_args[7] = (void*)pass;  g_args[8] = (void*)"192.168.10.50"; g_args[9] = (void*)v45;
    g_args[10] = g_v33;            g_args[11] = v29;   g_args[12] = v25;  g_args[13] = v16;
    if (!tramp) { return 0; }      // [fix13] только подготовка аргументов (раздел «установка» зовёт площадку сам)
    return CallSite(tramp, frame);
}

// ── [fix13] установка на подставной площадке ─────────────────────────────────
static const DWORD kSite = 0x00407263, kBuilder = 0x0040F440;
static volatile DWORD g_espIn = 0, g_espOut = 0;
static int RunSiteBal(void* target, BYTE* frame)   // как сток: 14 push, call цели площадки, add esp,38h; esp до/после
{
    int r = 0;
    __asm
    {
        push ebx
        push esi
        push edi
        mov  edi, target
        mov  ebx, frame
        lea  esi, g_args
        push ebp
        mov  [g_espIn], esp
        mov  ecx, 14
    L1: push dword ptr [esi + ecx*4 - 4]
        loop L1
        mov  ebp, ebx
        call edi
        add  esp, 0x38
        mov  [g_espOut], esp
        pop  ebp
        mov  r, eax
        pop  edi
        pop  esi
        pop  ebx
    }
    return r;
}
static int Launch()
{
    char cmd[2048] = ""; lstrcpynA(cmd, GetCommandLineA(), sizeof(cmd));
    SetEnvironmentVariableA("TEST_L06_CHILD", "1");
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) { printf("CreateProcess: %u\n", GetLastError()); return 2; }
    if (!VirtualAllocEx(pi.hProcess, (void*)0x00400000, 0x00011000, MEM_RESERVE, PAGE_EXECUTE_READWRITE))
    {
        printf("резерв 0x400000 в дочернем процессе: %u (тест собран без /BASE:0x30000000?)\n", GetLastError()); TerminateProcess(pi.hProcess, 2); return 2;
    }
    ResumeThread(pi.hThread); WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 2; GetExitCodeProcess(pi.hProcess, &code); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return (int)code;
}
static void InstallOrders()
{
    printf("Установка L03/L06 в обоих порядках (площадка 0x407263, [fix13]):\n");
    BYTE* p1 = (BYTE*)VirtualAlloc((void*)0x00407000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    BYTE* p2 = (BYTE*)VirtualAlloc((void*)0x0040F000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    CHECK(p1 && p2, "страницы 0x407000/0x40F000 заняты под площадку и сборщик");
    if (!p1 || !p2) { return; }
    BYTE* b = (BYTE*)kBuilder; b[0] = 0xB8; *(DWORD*)(b + 1) = (DWORD)&FakeBuilder; b[5] = 0xFF; b[6] = 0xE0;   // mov eax,FakeBuilder; jmp eax
    wchar_t dir[MAX_PATH]; GetModuleFileNameW(nullptr, dir, MAX_PATH);
    for (int i = lstrlenW(dir) - 1; i >= 0; --i) { if (dir[i] == L'\\') { dir[i + 1] = 0; break; } }
    wchar_t ini[MAX_PATH]; wsprintfW(ini, L"%sConfigSet\\patches.ini", dir);
    DeleteFileW(ini);
    Config::Init(dir);
    static const char* kOrders[2] = { "36", "63" };
    for (int oi = 0; oi < 2; ++oi)
    {
        for (int e3 = 1; e3 >= 0; --e3)
        {
            for (int e6 = 1; e6 >= 0; --e6)
            {
                WritePrivateProfileStringW(L"L03_LoginSqlRefuse", L"Enabled", e3 ? L"1" : L"0", ini);
                WritePrivateProfileStringW(L"L06_LoginMac", L"Enabled", e6 ? L"1" : L"0", ini);
                BYTE* s = (BYTE*)kSite; s[0] = 0xE8; *(DWORD*)(s + 1) = kBuilder - (kSite + 5);   // сток: call sub_40F440
                int r3 = -1, r6 = -1;
                for (const char* p = kOrders[oi]; *p; ++p)
                {
                    if (*p == '3') { r3 = (int)L03_LoginSqlRefuse(); }
                    if (*p == '6') { r6 = (int)L06_LoginMac(); }
                }
                char hdr[128];
                sprintf_s(hdr, "порядок %s, L03=%d L06=%d", kOrders[oi][0] == '3' ? "3→6" : "6→3", e3, e6);
                CHECK(r3 == (e3 ? 0 : 1) && r6 == (e6 ? 0 : 1), hdr);
                printf("    установка: L03 -> %d, L06 -> %d (0 Applied, 1 Disabled, 2 Mismatch)\n", r3, r6);
                void* target = (void*)(kSite + 5 + *(int*)(kSite + 1));
                if (!e3 && !e6) { CHECK(target == (void*)kBuilder, "  оба выключены — площадка = сток (call sub_40F440)"); }
                struct { const char* login; const char* pass; const char* mac; } cs[3] = {
                    { "hero",  "0123456789abcdef0123456789abcdef", "34-5A-60-55-34-76" },
                    { "he'ro", "0123456789abcdef0123456789abcdef", "34-5a-60-55-34-76" },
                    { "hero",  "0123456789abcdef0123456789abcdef", "34-5a-60-55-3'-76" } };
                for (int k = 0; k < 3; ++k)
                {
                    RunSite(nullptr, nullptr, nullptr, nullptr);   // подготовка кадра/аргументов (без вызова)
                    BYTE* frame = g_mem + 0x200;
                    memset(frame - 0x110, 0, 0xF3); memcpy(frame - 0x110 + 113, cs[k].mac, 17);
                    g_args[6] = (void*)cs[k].login; g_args[7] = (void*)cs[k].pass;
                    const int rr = RunSiteBal(target, frame);
                    const bool bal = g_espIn == g_espOut;
                    const bool refuse = e3 && strchr(cs[k].login, '\'') != nullptr;
                    const char* expMac = (e6 && !strchr(cs[k].mac, '\'')) ? "34-5a-60-55-34-76" : "";
                    char m[200];
                    if (refuse)
                    {
                        sprintf_s(m, "  %s: отказ L03 (сборщик не зван, *out=0), стек %s", cs[k].login, bal ? "ок" : "СБИТ");
                        CHECK(rr == 0 && g_builderCalls == 0 && g_out[0] == 0 && bal, m);
                    }
                    else
                    {
                        sprintf_s(m, "  %s / MAC %s: сборщик зван, 11-й = «%s» (ожид. «%s»), стек %s", cs[k].login, cs[k].mac, g_gotMac, expMac, bal ? "ок" : "СБИТ");
                        CHECK(rr == 1 && g_builderCalls == 1 && g_out[0] == 1 && strcmp(g_gotMac, expMac) == 0 && bal, m);
                    }
                }
            }
        }
    }
}

int main()
{
    { char c[4] = ""; if (!GetEnvironmentVariableA("TEST_L06_CHILD", c, sizeof(c))) { return Launch(); } }
    char dst[32];
    printf("L06 санитизация:\n");
    memset(dst, 'X', sizeof(dst));
    CHECK(L06_SanitizeMac("34-5a-60-55-34-76", dst, 1, 1) == 17 && strcmp(dst, "34-5a-60-55-34-76") == 0, "честный MAC → ровно 17 символов");
    CHECK(L06_SanitizeMac("34-5A-60-55-34-7F", dst, 1, 1) == 17 && strcmp(dst, "34-5a-60-55-34-7f") == 0, "верхний регистр → нижний (Lowercase=1)");
    CHECK(L06_SanitizeMac("34-5A-60-55-34-7F", dst, 1, 0) == 17 && strcmp(dst, "34-5A-60-55-34-7F") == 0, "Lowercase=0 — регистр сохранён");
    CHECK(L06_SanitizeMac("34-5a-60-55-34-7'", dst, 1, 1) == 0 && dst[0] == 0, "апостроф → пусто");
    CHECK(L06_SanitizeMac("'; DROP TABLE x--", dst, 0, 1) == 0 && dst[0] == 0, "инъекция → пусто даже при Strict=0");
    CHECK(L06_SanitizeMac("34-5a-60-55-34-76-ff", dst, 1, 1) == 17 && strcmp(dst, "34-5a-60-55-34-76") == 0, "поле читается не дальше 17 байт (18-й байт — соседнее поле)");
    CHECK(L06_SanitizeMac("0123456789abcdef0123", dst, 1, 1) == 0, "20 hex без тире (длиннее формата) → пусто при Strict=1");
    CHECK(L06_SanitizeMac("0123456789abcdef0123", dst, 0, 1) == 17 && strcmp(dst, "0123456789abcdef0") == 0, "Strict=0: набор [0-9a-f-], срез до 17");
    CHECK(L06_SanitizeMac("34-5a-60", dst, 1, 1) == 0, "короткий MAC → пусто при Strict=1");
    CHECK(L06_SanitizeMac("34-5a-60", dst, 0, 1) == 8 && strcmp(dst, "34-5a-60") == 0, "Strict=0: короткий принимается");
    CHECK(L06_SanitizeMac("345a60555434761", dst, 1, 1) == 0, "15 hex без тире → пусто");
    CHECK(L06_SanitizeMac("34:5a:60:55:34:76", dst, 1, 1) == 0, "двоеточия → пусто");
    CHECK(L06_SanitizeMac("34-5a-60-55-34-7g", dst, 1, 1) == 0, "не-hex символ → пусто");
    CHECK(L06_SanitizeMac("", dst, 1, 1) == 0 && dst[0] == 0, "пустое поле → пусто");
    CHECK(L06_SanitizeMac(nullptr, dst, 1, 1) == 0 && dst[0] == 0, "nullptr src безопасен");
    CHECK(L06_SanitizeMac("34-5a-60-55-34-76", nullptr, 1, 1) == 0, "nullptr dst безопасен");
    CHECK(L06_SanitizeMac((const char*)0x10, dst, 1, 1) == 0 && dst[0] == 0, "негодный указатель → пусто (SEH)");
    {   // поле без NUL, ровно 17 байт, дальше мусор — читаем только 17
        char raw[32]; memset(raw, 'Z', sizeof(raw)); memcpy(raw, "34-5a-60-55-34-76", 17);
        CHECK(L06_SanitizeMac(raw, dst, 1, 1) == 17 && strcmp(dst, "34-5a-60-55-34-76") == 0, "поле без NUL (как на проводе) → 17 символов");
    }

    printf("L06 трамплин (цепочка L06 → сборщик):\n");
    void* t06 = L06_TestGetTrampoline();
    L06_TestSetup((void*)&FakeBuilder, 1, 1);
    int r = RunSite(t06, "34-5a-60-55-34-76", "hero", "0123456789abcdef0123456789abcdef");
    CHECK(r == 1 && g_builderCalls == 1, "сборщик вызван, результат проброшен");
    CHECK(strcmp(g_gotMac, "34-5a-60-55-34-76") == 0 && strlen(g_gotMac) == 17, "11-й аргумент = MAC, ровно 17 символов");
    CHECK(g_gotLogin && strcmp(g_gotLogin, "hero") == 0 && g_gotPass && strcmp(g_gotPass, "0123456789abcdef0123456789abcdef") == 0, "7-й/8-й аргументы (логин/пароль) переложены верно");
    CHECK(g_gotOut == (void*)g_out && g_out[0] == 1, "2-й аргумент (out) — тот же указатель, *out от сборщика");
    CHECK(g_gotArgc == 14, "6-й аргумент (формат) переложен верно");
    CHECK(g_v33[0] == 0, "кадр вызывающего (v33) не тронут");
    r = RunSite(t06, "34-5a-60-55-34-7'", "hero", "pass");
    CHECK(r == 1 && g_builderCalls == 1 && g_gotMac[0] == 0, "мусорный MAC → сборщик вызван с пустой строкой");
    r = RunSite(t06, nullptr, "hero", "pass");
    CHECK(r == 1 && g_builderCalls == 1 && g_gotMac[0] == 0, "пустое поле (старый клиент) → пустая строка, как в стоке");

    printf("L06 → L03 → сборщик (цепочка):\n");
    void* t03 = L03_TestGetTrampoline();
    L03_TestSetup((void*)&FakeBuilder);
    L06_TestSetup(t03, 1, 1);
    r = RunSite(t06, "34-5A-60-55-34-76", "hero", "0123456789abcdef0123456789abcdef");
    CHECK(r == 1 && g_builderCalls == 1 && strcmp(g_gotMac, "34-5a-60-55-34-76") == 0, "честный вход: через L03 в сборщик, MAC на месте (в нижнем регистре)");
    r = RunSite(t06, "34-5a-60-55-34-76", "he'ro", "pass");
    CHECK(r == 0 && g_builderCalls == 0 && g_out[0] == 0, "апостроф в логине: L03 отказал, сборщик не вызван, *out = 0");
    r = RunSite(t06, "34-5a-60-55-34-76", "hero", "pa'ss");
    CHECK(r == 0 && g_builderCalls == 0 && g_out[0] == 0, "апостроф в пароле: L03 отказал через цепочку");
    r = RunSite(t06, "admin'--", "admin", "x");
    CHECK(r == 1 && g_builderCalls == 1 && g_gotMac[0] == 0, "апостроф в MAC (L03 его не смотрит): L06 обнулил, вход не сломан");

    InstallOrders();

    printf(g_fail ? "\n=== ЕСТЬ ОШИБКИ ===\n" : "\n=== ВСЕ ПРОВЕРКИ ПРОШЛИ ===\n");
    return g_fail;
}
