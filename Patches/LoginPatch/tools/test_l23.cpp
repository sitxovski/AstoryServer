// Copyright (c) 2026 @sitxovski (Discord)
#include <windows.h>
#include <stdio.h>
#include <string.h>
extern "C" int  __cdecl L03_ShouldRefuse(const char* login, const char* pass);
extern "C" void __cdecl L02_MaskIfLogin(char* sql);

int main(){
    int fail=0;
    // --- L03 ---
    printf("L03:\n");
    if(L03_ShouldRefuse("hero","pass")!=0){printf("  FAIL чистый отклонён\n");fail=1;} else printf("  ok: чистый пропущен\n");
    if(L03_ShouldRefuse("he'ro","pass")!=1){printf("  FAIL апостроф в логине не пойман\n");fail=1;} else printf("  ok: логин с ' отклонён\n");
    if(L03_ShouldRefuse("hero","pa'ss")!=1){printf("  FAIL апостроф в пароле не пойман\n");fail=1;} else printf("  ok: пароль с ' отклонён\n");
    if(L03_ShouldRefuse(0,0)!=0){printf("  FAIL nullptr\n");fail=1;} else printf("  ok: nullptr безопасно\n");
    // инъекция classic: ' OR 1=1--
    if(L03_ShouldRefuse("admin'--","x")!=1){printf("  FAIL классич. инъекция\n");fail=1;} else printf("  ok: ' OR-инъекция отклонена\n");

    // --- L02 ---
    printf("L02:\n");
    char q1[256]; strcpy(q1,"EXEC UPUserLogin 'hero','0123456789abcdef0123456789abcdef','192.168.10.50', 2, '34-5a-60-55-34-76'");
    int len0=(int)strlen(q1);
    L02_MaskIfLogin(q1);
    printf("  -> %s\n", q1);
    if((int)strlen(q1)!=len0){printf("  FAIL длина изменилась\n");fail=1;}
    if(strstr(q1,"hero")||strstr(q1,"0123456789abcdef")||strstr(q1,"192.168.10.50")||strstr(q1,"34-5a")){printf("  FAIL секрет утёк\n");fail=1;}
    if(!strstr(q1,"EXEC UPUserLogin ")){printf("  FAIL форма запроса потеряна\n");fail=1;}
    if(!strstr(q1,"'****'")){printf("  FAIL маски нет\n");fail=1;}
    // не-логин запрос не трогаем
    char q2[128]; strcpy(q2,"EXEC UPCharInsert 'My''Name', 5");
    char q2save[128]; strcpy(q2save,q2);
    L02_MaskIfLogin(q2);
    if(strcmp(q2,q2save)!=0){printf("  FAIL не-логин запрос изменён: %s\n",q2);fail=1;} else printf("  ok: не-логин запрос не тронут\n");
    // nullptr
    L02_MaskIfLogin(0); printf("  ok: nullptr безопасно\n");

    printf(fail?"\n=== ЕСТЬ ОШИБКИ ===\n":"\n=== ВСЕ ПРОВЕРКИ ПРОШЛИ ===\n");
    return fail;
}
