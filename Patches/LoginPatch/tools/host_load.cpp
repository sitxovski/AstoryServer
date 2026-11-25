// Copyright (c) 2026 @sitxovski (Discord)
// host_load.cpp — сквозной прогон: грузит LoginPatch.dll в НЕ-LoginManager-хост. DllMain выполняет Init:
// создаёт ConfigSet\patches.ini и Log\Log_Patch\PatchLog_*.txt рядом с ЭТИМ exe; каждый патч должен дать
// MISMATCH (байты чужого образа не совпали) и ничего не записать. Сборка: cl /nologo /EHa /MT tools\host_load.cpp
// /Fe:obj\host_load.exe ; запуск: obj\host_load.exe out\LoginPatch.dll
#include <windows.h>
#include <stdio.h>
int main(int argc, char** argv)
{
    const char* dll = argc > 1 ? argv[1] : "out\\LoginPatch.dll";
    HMODULE h = LoadLibraryA(dll);
    if (!h) { printf("LoadLibrary(%s) failed: %lu\n", dll, GetLastError()); return 1; }
    FARPROC p = GetProcAddress(h, "LoginPatchInit");
    printf("loaded %s, LoginPatchInit=%p\n", dll, (void*)p);
    FreeLibrary(h);
    return 0;
}
