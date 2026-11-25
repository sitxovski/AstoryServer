// Copyright (c) 2026 @sitxovski (Discord)
/* slow_sqlcmd — стенд шлюза gp7, ревизия В2 (02.11.2026): имитация тайм-аута sqlcmd ДО и ПОСЛЕ коммита.
 * Запускает настоящий sqlcmd (путь — переменная REAL_SQLCMD) с той же командной строкой. Если существует файл SLOW_SQL_FLAG
 * вида «after|before <мс> <подстрока запроса>» и текст -Q содержит подстроку — файл удаляется (одноразово) и:
 *   before — пауза <мс> ДО запуска (шлюз убьёт процесс по тайм-ауту: запрос не выполнен);
 *   after  — запуск, затем пауза <мс> (шлюз убьёт процесс: транзакция уже закоммичена, ответ потерян).
 * Код возврата — код настоящего sqlcmd. Сборка: cl /nologo /O2 slow_sqlcmd.c */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Хвост собственной командной строки после argv[0] (кавычки сохраняются как есть). */
static const wchar_t* tail_after_argv0(const wchar_t* cl)
{
    const wchar_t* p = cl;            /* текущая позиция */
    if (*p == L'"') { ++p; while (*p && *p != L'"') { ++p; } if (*p) { ++p; } }
    else { while (*p && *p != L' ' && *p != L'\t') { ++p; } }
    return p;
}

int main(int argc, char** argv)
{
    const char* q = "";                         /* текст -Q */
    const char* flag = getenv("SLOW_SQL_FLAG"); /* файл-команда задержки */
    const char* real = getenv("REAL_SQLCMD");   /* настоящий sqlcmd */
    char mode[16] = "";                         /* after / before */
    char pat[256] = "";                         /* подстрока запроса */
    int ms = 0;                                 /* пауза, мс */
    int armed = 0;                              /* задержка сработала */
    wchar_t wreal[MAX_PATH];                    /* путь sqlcmd (UTF-16) */
    wchar_t* cmd;                               /* итоговая командная строка */
    STARTUPINFOW si;                            /* запуск */
    PROCESS_INFORMATION pi;                     /* процесс */
    DWORD code = 1;                             /* код возврата */
    size_t n;                                   /* длина */
    int i;                                      /* счётчик */
    for (i = 1; i < argc - 1; ++i) { if (!strcmp(argv[i], "-Q")) { q = argv[i + 1]; } }
    if (!real) { fprintf(stderr, "REAL_SQLCMD not set\n"); return 2; }
    if (flag) {
        FILE* f = fopen(flag, "rb");
        if (f) {
            if (fscanf(f, "%15s %d %255s", mode, &ms, pat) == 3 && strstr(q, pat)) { armed = 1; }
            fclose(f);
            if (armed) { DeleteFileA(flag); }
        }
    }
    if (armed && !strcmp(mode, "before")) { Sleep((DWORD)ms); }
    MultiByteToWideChar(CP_ACP, 0, real, -1, wreal, MAX_PATH);
    n = wcslen(wreal) + wcslen(tail_after_argv0(GetCommandLineW())) + 4;
    cmd = (wchar_t*)malloc(n * sizeof(wchar_t));
    swprintf(cmd, n, L"\"%s\"%s", wreal, tail_after_argv0(GetCommandLineW()));
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;           /* вывод sqlcmd — в те же каналы, что у обёртки */
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { fprintf(stderr, "CreateProcess failed %lu\n", GetLastError()); return 3; }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (armed && !strcmp(mode, "after")) { Sleep((DWORD)ms); }
    free(cmd);
    return (int)code;
}
