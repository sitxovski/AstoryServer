// Copyright (c) 2026 @sitxovski (Discord)
#include <windows.h>
#include <stdio.h>
extern "C" void  __cdecl L04_TestSetup(void* getSess, void* builder);
extern "C" void* __cdecl L04_TestGetCharListTrampoline();

static int  g_stored=0;
static int  g_builderCalled=0;
static int  g_builderUserIdx=0;   // v14 (UserIndex, 7-й аргумент) переданный в сборщик
static int  g_builderGroup=0;     // v23 (группа, 8-й аргумент)
// ^ __thiscall у MSVC для свободной функции эмулируем через __fastcall(ecx,edx,...): ecx=this, но арг session на стеке.
//   Трамплин делает push session; mov ecx,this; call. __thiscall callee ожидает ecx=this, session на стеке, ret 4.
//   __fastcall(ecx,edx,stack...) с подписью (self,edx_dummy,session) не совпадёт по ret. Используем настоящий __thiscall:
// Переопределим правильно ниже.

// стаб сборщика sub_40F440 (__cdecl, 8 арг): ctx,out,dbsrc,a4,dst,fmt,v14,v23
static int __cdecl FakeBuilder(int ctx,int* out,int dbsrc,int a4,int dst,const char* fmt,int v14,int v23){
    (void)ctx;(void)dbsrc;(void)a4;(void)dst;(void)fmt;(void)v14;
    g_builderCalled=1; g_builderUserIdx=v14; g_builderGroup=v23; if(out)*out=1; return 1;
}

// Настоящий __thiscall стаб:
// __thiscall-стаб sub_4038B0: ecx=this (игнор), session на стеке, ret 4
static __declspec(naked) void FakeGetSessTC(){ __asm { mov eax, g_stored
 ret 4 } }

// Драйвер: строит кадр так, что [ebp+8]=session, и зовёт трамплин с 8 арг: v14=clientIdx (7-й, [esp+0x1C]),
// v23=group (8-й, [esp+0x20]) — порядок как у стока (cdecl, справа налево: сначала push группы).
typedef void(*TrampFn)();
static int __declspec(noinline) DrvCharList(int session, int clientIdx, int group, int* outPtr){
    TrampFn t=(TrampFn)L04_TestGetCharListTrampoline();
    int rv=0;
    __asm {
        // пушим 8 арг трамплина (в обратном порядке): v23=group, v14=clientIdx, fmt=0, dst=0, a4=0, dbsrc=0, out=outPtr, ctx=0
        mov eax, group
        push eax            // v23 = группа [esp+0x20 после call]
        mov eax, clientIdx
        push eax            // v14 = UserIndex [esp+0x1C после call]
        push 0              // dbsrc (8-й арг — в реальном вызове есть!)
        push 0              // fmt
        push 0              // dst
        push 0              // a4
        mov eax, outPtr
        push eax            // out [esp+8]
        push 0              // ctx
        // ВАЖНО: трамплин читает [ebp+8]=session. ebp сейчас наш (DrvCharList). session = [ebp+8]? 
        // session — 1-й арг DrvCharList => [ebp+8]. Да.
        call t
        add esp, 0x20       // снять 8 арг (как делает обработчик)
        mov rv, eax
    }
    return rv;
}
int main(){
    L04_TestSetup((void*)&FakeGetSessTC, (void*)&FakeBuilder);
    int fail=0, outv;

    // T1: учётка совпала, группа 0 (как у честного клиента на единственном сервере) -> сборщик вызван, оба арга проброшены
    g_stored=77; g_builderCalled=0; g_builderUserIdx=0; g_builderGroup=-1; outv=0;
    DrvCharList(77, 77, 0, &outv);
    if(!g_builderCalled){printf("T1 FAIL: сборщик не вызван при совпадении (группа 0)\n");fail=1;}
    else if(g_builderUserIdx!=77||g_builderGroup!=0){printf("T1 FAIL: v14=%d v23=%d\n",g_builderUserIdx,g_builderGroup);fail=1;}
    else printf("T1 ok: учётка совпала, группа 0 -> запрос выполнен (UserIndex=%d, group=%d)\n",g_builderUserIdx,g_builderGroup);

    // T1b: учётка совпала, группа 1 -> тоже пропуск
    g_stored=77; g_builderCalled=0; outv=0;
    DrvCharList(77, 77, 1, &outv);
    if(!g_builderCalled||g_builderGroup!=1){printf("T1b FAIL\n");fail=1;} else printf("T1b ok: учётка совпала, группа 1 -> запрос выполнен\n");

    // T2: НЕсовпадение -> сборщик НЕ вызван, *out=0
    g_stored=77; g_builderCalled=0; outv=123;
    DrvCharList(77, 999, 0, &outv);
    if(g_builderCalled){printf("T2 FAIL: сборщик вызван при подмене UserIndex\n");fail=1;}
    else if(outv!=0){printf("T2 FAIL: *out=%d (ждём 0)\n",outv);fail=1;}
    else printf("T2 ok: чужой UserIndex -> запрос НЕ выполнен, *out=0\n");

    // T3: группа численно равна учётке сессии, а UserIndex чужой -> отказ (ловит ошибку первой сборки: чтение [esp+0x20])
    g_stored=77; g_builderCalled=0; outv=123;
    DrvCharList(77, 999, 77, &outv);
    if(g_builderCalled||outv!=0){printf("T3 FAIL: сверялась группа вместо UserIndex\n");fail=1;}
    else printf("T3 ok: группа==учётка сессии, но UserIndex чужой -> отказ\n");

    printf(fail?"\n=== ЕСТЬ ОШИБКИ ===\n":"\n=== ВСЕ ПРОВЕРКИ ПРОШЛИ ===\n");
    return fail;
}
