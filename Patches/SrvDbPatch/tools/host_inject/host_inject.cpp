// Copyright (c) 2026 @sitxovski (Discord)
// host_inject.cpp — проверка механизма загрузки SrvDbPatch.dll через инъекцию импорта (P126, 15.11.2026).
// Тестовый хост той же конфигурации, что RelayServer/ItemRelayServer/OperationServer: x86, фиксированная база 0x400000,
// IAT в начале .rdata, огромный BSS в .data (64 МБ). Его обрабатывает тот же inject() из inject_import_srvdb.py.
// Хост не вызывает DLL сам: если в main GetModuleHandle("SrvDbPatch.dll") != 0 — DLL подтянул загрузчик Windows ДО точки
// входа. Проверяется и то, что BSS цел (весь нулевой) и что DLL создала ConfigSet\srvdbpatch.ini и PatchLog.
#include <windows.h>
#include <stdio.h>
static char g_bss[64 * 1024 * 1024];          // как ~70 МБ BSS у трёх серверов
int main()
{
    HMODULE h = GetModuleHandleA("SrvDbPatch.dll");
    size_t nz = 0;
    for (size_t i = 0; i < sizeof(g_bss); i += 4096) { nz += g_bss[i] != 0; }
    printf("SrvDbPatch.dll %s (0x%p), BSS ненулевых страниц %zu, экспорт SrvDbPatchInit %p\n",
           h ? "ЗАГРУЖЕНА" : "НЕ загружена", (void*)h, nz, h ? (void*)GetProcAddress(h, "SrvDbPatchInit") : nullptr);
    return (h && nz == 0) ? 0 : 1;
}
