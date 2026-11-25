// Copyright (c) 2026 @sitxovski (Discord)
// test_l09.cpp — юнит-тест трамплина L09 (режим обслуживания, 21.11.2026). Площадку на настоящем образе проверяет стенд
// tools/stand_l09 (настоящий обработчик входа sub_406C20 с подменённой базой); здесь — только логика подмены отправки.
// Сборка и запуск — tools/regress_all.bat. Код возврата 0 — все проверки прошли.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

extern "C" BOOL __fastcall L09_Send(void* self, void* edx, int opcode, int size, int slot, const BYTE* body, int hdr, int pad);
extern "C" void __cdecl L09_TestSetup(void* send, int status, int code);
extern "C" long __cdecl L09_TestHits();
extern "C" int  __cdecl L09_WorldCheck(BYTE* fr, DWORD* argp);
extern "C" void __cdecl L09_TestSetupWorld(void* sql, int on, int missingSec);
extern "C" long __cdecl L09_TestWorldHits();
extern "C" int  __cdecl L09_MateGate(BYTE* fr, int realUser, int mate);           // ★ р43б Н-2
extern "C" void __cdecl L09_TestSetupErr(int errSec, int mateByL04c);            // ★ р43б Н-3 / Н-2
extern "C" long long __cdecl L09_TestWindowLeftMs();
extern "C" void __cdecl L09_TestClearWindow();

static int g_sqlCalls = 0, g_sqlOut = 1, g_sqlRefuse = 0, g_sqlUid = 0, g_sqlDbsrc = 0, g_sqlDb = 0;
static char g_sqlFmt[128];
static int __cdecl FakeSql(int ctx, int* out, int dbsrc, int db, BYTE* dst, const char* fmt, ...)
{
    (void)ctx;
    ++g_sqlCalls; g_sqlDbsrc = dbsrc; g_sqlDb = db;
    strncpy_s(g_sqlFmt, fmt ? fmt : "", _TRUNCATE);
    va_list ap; va_start(ap, fmt); g_sqlUid = va_arg(ap, int); va_end(ap);
    out[0] = g_sqlOut;
    if (g_sqlOut) { dst[0] = (BYTE)g_sqlRefuse; }
    return 1;
}

static int g_calls = 0, g_op = 0, g_size = 0, g_slot = 0, g_hdr = 0, g_pad = 0;
static BYTE g_body[16];
static void* g_self = nullptr;
static int g_fail = 0, g_ok = 0;

static BOOL __fastcall FakeSend(void* self, void*, int opcode, int size, int slot, const BYTE* body, int hdr, int pad)
{
    ++g_calls; g_self = self; g_op = (WORD)opcode; g_size = (WORD)size; g_slot = (short)slot; g_hdr = (WORD)hdr; g_pad = pad;
    memset(g_body, 0, sizeof(g_body));
    // негодный указатель тела трамплин пропускает как есть (стоковая отправка разбирается сама) — подставная отправка его не читает
    if ((UINT_PTR)body >= 0x10000) { memcpy(g_body, body, (WORD)size < 16 ? (WORD)size : 16); }
    return TRUE;
}

static void Check(bool c, const char* what)
{
    printf("  [%s] %s\n", c ? "OK" : "!!", what);
    if (c) { ++g_ok; } else { ++g_fail; }
}

static void Reset() { g_calls = 0; g_op = g_size = g_slot = g_hdr = g_pad = -1; g_self = nullptr; memset(g_body, 0xEE, sizeof(g_body)); }

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    L09_TestSetup((void*)&FakeSend, 28, 28);
    void* const net = (void*)0x5CFFD8;
    BYTE reply[8] = { 28, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0 };

    Reset();
    L09_Send(net, nullptr, 1004, 8, 0x00010007, reply, 3, 1);
    Check(g_calls == 1 && g_op == 4101 && g_size == 1 && g_body[0] == 28 && g_hdr == 3 && g_pad == 1 && g_slot == 7 && g_self == net,
          "1004/28 → один вызов 4101, размер 1, код 28, флаг 1, тот же слот и this (как AcceptIp); заголовок — эхо a3 стокового ответа (р43б, мелочь 3)");
    Check(L09_TestHits() == 1, "счётчик отказов +1");

    const int other[] = { 1, 2, 3, 4, 0, 8, 27, 29, 200 };
    for (int st : other)
    {
        Reset();
        BYTE b[8] = { (BYTE)st, 5, 1, 2, 3, 4, 0, 0 };
        L09_Send(net, nullptr, 1004, 8, 3, b, 9, 1);
        char msg[160];
        _snprintf_s(msg, _TRUNCATE, "1004/%d → без изменений (1004, размер 8, тело как есть, заголовок 9)", st);
        Check(g_calls == 1 && g_op == 1004 && g_size == 8 && g_body[0] == (BYTE)st && g_body[1] == 5 && g_hdr == 9 && g_slot == 3, msg);
    }
    Reset();
    L09_Send(net, nullptr, 1027, 8, 3, reply, 0, 1);
    Check(g_calls == 1 && g_op == 1027 && g_body[0] == 28, "другой опкод (1027) с первым байтом 28 → без изменений");
    Reset();
    L09_Send(net, nullptr, 0x10000 + 1004, 8, 3, reply, 0, 1);
    Check(g_calls == 1 && g_op == 4101, "опкод сравнивается по младшему слову (push eax/edx стока кладёт мусор в старшие 16 бит)");
    Reset();
    L09_Send(net, nullptr, 1004, 8, 3, nullptr, 0, 1);
    Check(g_calls == 1 && g_op == 1004, "тело nullptr → без изменений, без падения");
    Reset();
    L09_Send(net, nullptr, 1004, 8, 3, (const BYTE*)0x10, 0, 1);
    Check(g_calls == 1 && g_op == 1004, "негодный указатель тела → без изменений, исключение перехвачено");

    L09_TestSetup((void*)&FakeSend, 40, 20);
    Reset();
    BYTE b40[8] = { 40 };
    L09_Send(net, nullptr, 1004, 8, 1, b40, 0, 1);
    Check(g_op == 4101 && g_body[0] == 20, "Status=40 Code=20 из ini → 1004/40 становится 4101/20");
    Reset();
    L09_Send(net, nullptr, 1004, 8, 1, reply, 0, 1);
    Check(g_op == 1004 && g_body[0] == 28, "при Status=40 статус 28 идёт как был");

    // ★ ревизия 43 С-1: вход в мир (1016) — решение L09_WorldCheck (трамплин на настоящем образе — стенд stand_l09, режим world)
    L09_TestSetup((void*)&FakeSend, 28, 28);
    L09_TestSetupWorld((void*)&FakeSql, 1, 60);
    L09_TestSetupErr(2, 0);
    BYTE frame[128] = {};
    BYTE* fr = frame + 64;                                   // [ebp-0x28] — байт режима, [ebp+8] сессия, [ebp+0xC] заголовок
    *(short*)(fr + 8) = 9;                                   // сессия [ebp+8]
    *(short*)(fr + 0xC) = 0x44;                              // заголовок a3 [ebp+0xC]
    *(int*)(fr + 0x10) = 5;                                  // a4 [ebp+0x10]
    DWORD argp[11] = {};
    argp[3] = 2; argp[4] = 5;                                // dbsrc (DSN группы), db
    argp[8] = 3;                                             // служебная
    Reset(); g_sqlCalls = 0;
    int r = L09_WorldCheck(fr, argp);
    Check(r == 1 && g_sqlCalls == 0 && g_calls == 0, "вход в мир: служебная учётка 3 — пропуск без запроса к базе");
    argp[8] = 6001; g_sqlOut = 1; g_sqlRefuse = 1; Reset(); g_sqlCalls = 0;
    r = L09_WorldCheck(fr, argp);
    Check(r == 0 && g_sqlCalls == 1 && g_sqlUid == 6001 && g_sqlDbsrc == 0 && g_sqlDb == 5 && strcmp(g_sqlFmt, "EXEC adm.LoginMaintenanceGate %d") == 0,
          "вход в мир: учётка 6001 — EXEC adm.LoginMaintenanceGate 6001 на соединении 0 (база входа, р43б Н-1; не DSN группы 2), сессия базы потока 5");
    Check(g_calls == 1 && g_op == 4101 && g_size == 1 && g_body[0] == 28 && g_slot == 9 && g_hdr == 0x44 && g_pad == 1 && L09_TestWorldHits() == 1,
          "вход в мир: ответ 1 — сессии 9 ушёл 4101/28 (размер 1, заголовок — эхо a3 0x44, флаг 1), возврат 0 (дальше стоковая ветка ошибки)");
    g_sqlRefuse = 0; Reset();
    r = L09_WorldCheck(fr, argp);
    Check(r == 1 && g_calls == 0, "вход в мир: ответ 0 (режим выключен) — пропуск, ничего не отправлено");
    // ★ р43б Н-3: сбой запроса — окно «без проверки» растёт с числом сбоев подряд (2 → 4 → 8 … ≤ WorldMissingSec), успех сбрасывает
    g_sqlOut = 0; Reset(); g_sqlCalls = 0;
    r = L09_WorldCheck(fr, argp);
    const int r2 = L09_WorldCheck(fr, argp);
    long long w1 = L09_TestWindowLeftMs();
    Check(r == 1 && r2 == 1 && g_sqlCalls == 1 && g_calls == 0 && w1 > 1000 && w1 <= 2000,
          "вход в мир: первый сбой запроса (out = 0) — пропуск как без режима, окно без проверки 2 с, а не 60 (осталось %lld мс)");
    L09_TestClearWindow(); L09_WorldCheck(fr, argp); const long long w2 = L09_TestWindowLeftMs();
    L09_TestClearWindow(); L09_WorldCheck(fr, argp); const long long w3 = L09_TestWindowLeftMs();
    for (int i = 0; i < 6; ++i) { L09_TestClearWindow(); L09_WorldCheck(fr, argp); }
    const long long w9 = L09_TestWindowLeftMs();
    Check(w2 > 3000 && w2 <= 4000 && w3 > 7000 && w3 <= 8000 && w9 > 59000 && w9 <= 60000,
          "вход в мир: сбои подряд — окно 4 с, 8 с … потолок WorldMissingSec 60 с");
    L09_TestClearWindow(); g_sqlOut = 1; g_sqlRefuse = 0; L09_WorldCheck(fr, argp);
    g_sqlOut = 0; L09_WorldCheck(fr, argp); const long long w10 = L09_TestWindowLeftMs();
    Check(w10 > 1000 && w10 <= 2000, "вход в мир: успешный ответ сбрасывает счёт — следующий сбой снова открывает на 2 с");
    L09_TestClearWindow(); g_sqlOut = 1;
    // ★ р43б Н-2: режим 2 на площадке 0x40B41A
    *(fr - 0x28) = 2; argp[8] = 3; g_sqlRefuse = 1; Reset(); g_sqlCalls = 0;
    L09_TestSetupErr(2, 1);
    r = L09_WorldCheck(fr, argp);
    Check(r == 1 && g_sqlCalls == 0 && g_calls == 0, "режим 2 при стоящем L04c — решено там (до смены личности), площадка 0x40B41A пропускает");
    L09_TestSetupErr(2, 0);
    r = L09_WorldCheck(fr, argp);
    Check(r == 0 && g_sqlCalls == 1 && g_sqlUid == 0 && g_calls == 1 && g_op == 4101,
          "режим 2 без L04c, партнёр служебный 3 — учётка сессии неизвестна, гейт спрошен номером 0: в режиме обслуживания отказ");
    *(fr - 0x28) = 0; argp[8] = 6001;
    // ★ р43б Н-2: L09_MateGate — проверка из L04c по обеим учёткам
    g_sqlRefuse = 1; Reset(); g_sqlCalls = 0;
    r = L09_MateGate(fr, 6005, 3);
    Check(r == 0 && g_sqlCalls == 1 && g_sqlUid == 6005 && g_sqlDbsrc == 0 && g_sqlDb == 5 && g_calls == 1 && g_op == 4101 && g_body[0] == 28 && g_slot == 9,
          "соулмейт: игрок 6005 в паре с оператором 3 — гейт по учётке сессии 6005, отказ 4101/28 (личность ещё не сменена)");
    Reset(); g_sqlCalls = 0;
    r = L09_MateGate(fr, 3, 6006);
    Check(r == 0 && g_sqlCalls == 1 && g_sqlUid == 6006 && g_calls == 1, "соулмейт: оператор 3 входит персонажем игрока 6006 — гейт по партнёру, отказ");
    Reset(); g_sqlCalls = 0;
    r = L09_MateGate(fr, 3, 4);
    Check(r == 1 && g_sqlCalls == 0 && g_calls == 0, "соулмейт: обе учётки служебные — без запроса, пропуск");
    g_sqlRefuse = 0; Reset(); g_sqlCalls = 0;
    r = L09_MateGate(fr, 6005, 6006);
    Check(r == 1 && g_sqlCalls == 1 && g_calls == 0, "соулмейт: режим выключен (ответ 0) — один запрос, пропуск");
    L09_TestSetupWorld((void*)&FakeSql, 0, 60);
    g_sqlOut = 1; g_sqlRefuse = 1; Reset(); g_sqlCalls = 0;
    r = L09_WorldCheck(fr, argp);
    Check(r == 1 && g_sqlCalls == 0 && g_calls == 0, "вход в мир: WorldGate=0 — без запроса и без отказа");
    L09_TestSetupWorld((void*)&FakeSql, 1, 60);
    r = L09_WorldCheck((BYTE*)0x10, argp);
    Check(r == 1, "вход в мир: негодный кадр — пропуск, исключение перехвачено");

    printf("== итог: OK %d, ПРОВАЛОВ %d ==\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
