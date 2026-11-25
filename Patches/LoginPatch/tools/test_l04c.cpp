// Copyright (c) 2026 @sitxovski (Discord)
// test_l04c.cpp — юнит-тест L04c (1016 режим 2, сверка с MateUserindex) и L04c_SendRefuse.
// Кадр обработчика подделывается буфером: читаются только смещения из LoginApi.h.
// Сборка (после vcvars32): cl /nologo /utf-8 /EHa /MT tools\test_l04c.cpp obj\l04_login_identity.obj
//   obj\Config.obj obj\Log.obj obj\Hook.obj user32.lib kernel32.lib /Fe:obj\test_l04c.exe
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

extern "C" int  __cdecl L04c_Check(BYTE* fr);
extern "C" void __cdecl L04c_SendRefuse(BYTE* fr, int kind);
extern "C" void __cdecl L04c_SetMaintGate(void* fn);
extern "C" void __cdecl L04c_TestSetup(void* getSess, void* dbSrc, void* sql, void* send, int failOpen);

static int   g_sessUser = 0;       // что вернёт стаб sub_4038B0
static int   g_sqlOk    = 1;       // out[0] стаба сборщика
static BYTE  g_exists   = 1;       // dst[0]
static int   g_mate     = 0;       // dst[4..7]
static int   g_sqlArg1 = -1, g_sqlArg2 = -1, g_sqlDb = -1, g_sqlSrc = -1;
static char  g_sqlFmt[64];
static int   g_sendOp = 0, g_sendSize = 0, g_sendSlot = 0, g_sendHdr = 0, g_sendBody0 = -1;

// sub_4038B0: __thiscall(this, session) ret 4 — ecx игнорируем, session на стеке
static __declspec(naked) void FakeGetSess()
{
    __asm
    {
        mov eax, g_sessUser
        ret 4
    }
}
// sub_4060A0: __stdcall(group) ret 4
static int __stdcall FakeDbSrc(short group) { g_sqlSrc = group; return 7; }
// sub_40F440: __cdecl varargs
static int __cdecl FakeSql(int ctx, int* out, int dbsrc, int db, void* dst, const char* fmt, ...)
{
    (void)ctx; (void)dbsrc;
    va_list ap; va_start(ap, fmt);
    g_sqlArg1 = va_arg(ap, int); g_sqlArg2 = va_arg(ap, int);
    va_end(ap);
    g_sqlDb = db; strncpy(g_sqlFmt, fmt, 63); g_sqlFmt[63] = 0;
    BYTE* d = (BYTE*)dst; d[0] = g_exists; memcpy(d + 4, &g_mate, 4);
    out[0] = g_sqlOk;
    return g_sqlOk;
}
// sub_415A40: __thiscall(this, op, size, slot, body, hdr, pad). Свободную функцию __thiscall MSVC не даёт —
// эмулируем __fastcall: ecx=this, edx=мусор, остальное на стеке в том же порядке, callee снимает 24 байта.
static BOOL __fastcall FakeSend(void* self, int edxDummy, short op, short size, short slot, void* body, short hdr, int pad)
{
    (void)self; (void)edxDummy; (void)pad;
    g_sendOp = op; g_sendSize = size; g_sendSlot = slot; g_sendHdr = hdr; g_sendBody0 = ((BYTE*)body)[0];
    return TRUE;
}

// ★ р43б Н-2: подставная проверка режима обслуживания L09 (L09_MateGate): что спросили и что ответить
static int g_mgCalls = 0, g_mgReal = 0, g_mgMate = 0, g_mgAnswer = 1;
static int __cdecl FakeMaintGate(BYTE* fr, int realUser, int mate) { (void)fr; ++g_mgCalls; g_mgReal = realUser; g_mgMate = mate; return g_mgAnswer; }

static BYTE  g_mem[0x3400];
static BYTE* Frame(short session, int clientUi, short group, int db, short hdr)
{
    memset(g_mem, 0xCC, sizeof(g_mem));
    BYTE* fr = g_mem + 0x3000;                       // ниже кадра ≥ 0x2B00 байт (как у sub_40AD30)
    *(short*)(fr + 8)    = session;
    *(short*)(fr + 0xC)  = hdr;
    *(int*)(fr + 0x10)   = db;
    memcpy(fr - 0x27, &clientUi, 4);
    *(short*)(fr - 0x22) = group;
    *(fr - 0x28) = 2;                                 // режим 2
    return fr;
}

int main()
{
    int fail = 0;
    L04c_TestSetup((void*)&FakeGetSess, (void*)&FakeDbSrc, (void*)&FakeSql, (void*)&FakeSend, 0);

    // T1: пара совпала → 1; запрос UPCharExist(UserIndex сессии, group) — порядок аргументов как в 1005
    g_sessUser = 75180; g_mate = 2; g_exists = 1; g_sqlOk = 1;
    int r = L04c_Check(Frame(5, 2, 0, 0x1234, 9));
    if (r != 1 || g_sqlArg1 != 75180 || g_sqlArg2 != 0 || g_sqlDb != 0x1234 || g_sqlSrc != 0 || strcmp(g_sqlFmt, "EXEC UPCharExist %d,%d") != 0)
    { printf("T1 FAIL: r=%d args=(%d,%d) db=%x src=%d fmt=%s\n", r, g_sqlArg1, g_sqlArg2, g_sqlDb, g_sqlSrc, g_sqlFmt); fail = 1; }
    else printf("T1 ok: пара совпала -> пропуск; UPCharExist(%d,%d)\n", g_sqlArg1, g_sqlArg2);

    // T2: в пакете чужая учётка, не пара → 0
    g_mate = 2; r = L04c_Check(Frame(5, 999, 1, 1, 9));
    if (r != 0) { printf("T2 FAIL: r=%d\n", r); fail = 1; } else printf("T2 ok: не пара -> отказ\n");

    // T3: своя учётка в режиме 2 (не пара) → 0
    r = L04c_Check(Frame(5, 75180, 1, 1, 9));
    if (r != 0) { printf("T3 FAIL: r=%d\n", r); fail = 1; } else printf("T3 ok: своя учётка в режиме 2 -> отказ\n");

    // T4: пары нет (MateUserindex 0) и пакет с 0 → 0
    g_mate = 0; r = L04c_Check(Frame(5, 0, 1, 1, 9));
    if (r != 0) { printf("T4 FAIL: r=%d\n", r); fail = 1; } else printf("T4 ok: пары нет -> отказ\n");

    // T5: dst[0]==0 (учётки нет) → 0
    g_mate = 2; g_exists = 0; r = L04c_Check(Frame(5, 2, 1, 1, 9)); g_exists = 1;
    if (r != 0) { printf("T5 FAIL: r=%d\n", r); fail = 1; } else printf("T5 ok: учётка сессии не найдена -> отказ\n");

    // T6: ошибка БД, FailOpen=0 → 0; FailOpen=1 → 1
    g_sqlOk = 0; r = L04c_Check(Frame(5, 2, 1, 1, 9));
    if (r != 0) { printf("T6a FAIL: r=%d\n", r); fail = 1; } else printf("T6a ok: ошибка БД, FailOpen=0 -> отказ\n");
    L04c_TestSetup((void*)&FakeGetSess, (void*)&FakeDbSrc, (void*)&FakeSql, (void*)&FakeSend, 1);
    r = L04c_Check(Frame(5, 2, 1, 1, 9));
    if (r != 1) { printf("T6b FAIL: r=%d\n", r); fail = 1; } else printf("T6b ok: ошибка БД, FailOpen=1 -> пропуск\n");
    L04c_TestSetup((void*)&FakeGetSess, (void*)&FakeDbSrc, (void*)&FakeSql, (void*)&FakeSend, 0);
    g_sqlOk = 1;

    // T7: негодный указатель кадра → 0 (SEH, fail-closed)
    r = L04c_Check((BYTE*)0x10);
    if (r != 0) { printf("T7 FAIL: r=%d\n", r); fail = 1; } else printf("T7 ok: негодный кадр -> отказ без падения\n");

    // T8: отказ — 1027 (0x403), 651 б, код 3, session/hdr из кадра, буфер в [ebp-0x618]
    BYTE* fr = Frame(31, 2, 0, 1, 77);
    L04c_SendRefuse(fr, 0);
    if (g_sendOp != 0x403 || g_sendSize != 0x28B || g_sendSlot != 31 || g_sendHdr != 77 || g_sendBody0 != 3 || *(fr - 0x618) != 3 || *(fr - 0x618 + 650) != 0)
    { printf("T8 FAIL: op=%x size=%d slot=%d hdr=%d body0=%d\n", g_sendOp, g_sendSize, g_sendSlot, g_sendHdr, g_sendBody0); fail = 1; }
    else printf("T8 ok: отказ = 1027/651 б/код 3 из стокового буфера кадра\n");

    // ★ р43б Н-2: отказ режима обслуживания (kind 2) — 1027 код 0 (как стоковая ветка «UPCharSoulState Error»)
    fr = Frame(31, 2, 0, 1, 77);
    L04c_SendRefuse(fr, 2);
    if (g_sendOp != 0x403 || g_sendSize != 0x28B || g_sendSlot != 31 || g_sendHdr != 77 || g_sendBody0 != 0)
    { printf("T9 FAIL: op=%x body0=%d\n", g_sendOp, g_sendBody0); fail = 1; }
    else printf("T9 ok: отказ режима обслуживания = 1027/651 б/код 0\n");

    // T10: проверка режима L09 зовётся ПОСЛЕ сверки пары с (учётка сессии, учётка партнёра); 0 → L04c_Check = 2 (отказ, личность не меняется)
    L04c_SetMaintGate((void*)&FakeMaintGate);
    g_sessUser = 75180; g_mate = 2; g_exists = 1; g_sqlOk = 1; g_mgCalls = 0; g_mgAnswer = 0;
    r = L04c_Check(Frame(5, 2, 0, 1, 9));
    if (r != 2 || g_mgCalls != 1 || g_mgReal != 75180 || g_mgMate != 2) { printf("T10 FAIL: r=%d calls=%d real=%d mate=%d\n", r, g_mgCalls, g_mgReal, g_mgMate); fail = 1; }
    else printf("T10 ok: режим обслуживания отказал — L04c_Check = 2, спрошены обе учётки (%d, %d)\n", g_mgReal, g_mgMate);
    g_mgAnswer = 1; g_mgCalls = 0;
    r = L04c_Check(Frame(5, 2, 0, 1, 9));
    if (r != 1 || g_mgCalls != 1) { printf("T11 FAIL: r=%d calls=%d\n", r, g_mgCalls); fail = 1; }
    else printf("T11 ok: режим пропустил — L04c_Check = 1\n");
    g_mgCalls = 0; g_mgAnswer = 0;
    r = L04c_Check(Frame(5, 999, 0, 1, 9));
    if (r != 0 || g_mgCalls != 0) { printf("T12 FAIL: r=%d calls=%d\n", r, g_mgCalls); fail = 1; }
    else printf("T12 ok: не пара — отказ 0 (код 3) раньше проверки режима, режим не спрошен\n");
    L04c_SetMaintGate(nullptr);
    g_mgCalls = 0;
    r = L04c_Check(Frame(5, 2, 0, 1, 9));
    if (r != 1 || g_mgCalls != 0) { printf("T13 FAIL: r=%d calls=%d\n", r, g_mgCalls); fail = 1; }
    else printf("T13 ok: L09 не стоит (проверки нет) — пара проходит как раньше\n");

    printf(fail ? "\n=== ЕСТЬ ОШИБКИ ===\n" : "\n=== ВСЕ ПРОВЕРКИ ПРОШЛИ ===\n");
    return fail;
}
