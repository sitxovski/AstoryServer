// Copyright (c) 2026 @sitxovski (Discord)
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

extern "C" long __cdecl L01_TestInvoke(void* realLog, int macOn,
    const char* id1, const char* id2, const char* pass1, const char* pass2, const char* ip);

static char g_cap[1024];
static long __cdecl Sink(int level, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    _vsnprintf(g_cap, sizeof(g_cap)-1, fmt, ap);
    va_end(ap);
    printf("  [sink level=%d] %s\n", level, g_cap);
    return 0;
}

int main()
{
    // pass2 = сырое поле пакета: 32 байта MD5 БЕЗ нуля, сразу за ним MAC, затем мусор.
    char raw[64];
    memset(raw, 'a', sizeof(raw));
    memcpy(raw, "0123456789abcdef0123456789abcdef", 32);   // "хеш" 32 б, нуля нет
    memcpy(raw+32, "34-5a-60-55-34-76", 17);               // MAC
    raw[49] = 0; memset(raw+50,'Z',14);                    // дальше мусор (чтобы поймать over-read)
    char pass1[33]; memcpy(pass1,"0123456789abcdef0123456789abcdef",32); pass1[32]=0;

    int fail=0;
    printf("T1 (LogMac=1):\n");
    L01_TestInvoke((void*)&Sink, 1, "hero", "hero", pass1, raw, "192.168.10.50");
    if (strstr(g_cap,"0123456789abcdef")) { printf("  FAIL: хеш утёк\n"); fail=1; }
    if (!strstr(g_cap,"MAC 34-5a-60-55-34-76,")) { printf("  FAIL: MAC не то\n"); fail=1; }
    if (strstr(g_cap,"aaaa")||strstr(g_cap,"ZZ")) { printf("  FAIL: over-read\n"); fail=1; }
    if (!strstr(g_cap,"(masked)")) { printf("  FAIL: нет маски\n"); fail=1; }
    if (!strstr(g_cap,"hero/hero")) { printf("  FAIL: логин потерян\n"); fail=1; }

    printf("T2 (LogMac=0):\n");
    L01_TestInvoke((void*)&Sink, 0, "hero", "hero", pass1, raw, "192.168.10.50");
    if (strstr(g_cap,"MAC")) { printf("  FAIL: MAC при LogMac=0\n"); fail=1; }
    if (strstr(g_cap,"0123456789abcdef")) { printf("  FAIL: хеш утёк\n"); fail=1; }

    printf("T3 (MAC без нуля — обрезка 17):\n");
    char raw2[64]; memset(raw2,'b',sizeof(raw2));          // пароль+MAC без нулей вовсе
    L01_TestInvoke((void*)&Sink, 1, "x","x",pass1,raw2,"1.2.3.4");
    // MAC-поле = 17 байт 'b', потом должно оборваться (длина ровно 17)
    const char* m=strstr(g_cap,"MAC "); 
    if(m){ int k=0; m+=4; while(m[k]=='b')k++; if(k!=17){printf("  FAIL: MAC len=%d (ждём 17)\n",k);fail=1;} }
    else { printf("  FAIL: нет MAC\n"); fail=1; }

    printf("T4 (pass2=nullptr — SEH/защита):\n");
    L01_TestInvoke((void*)&Sink, 1, "y","y",pass1,nullptr,"1.2.3.4");
    if(!strstr(g_cap,"(masked)")){printf("  FAIL\n");fail=1;}

    printf(fail?"\n=== ЕСТЬ ОШИБКИ ===\n":"\n=== ВСЕ ПРОВЕРКИ ПРОШЛИ ===\n");
    return fail;
}
