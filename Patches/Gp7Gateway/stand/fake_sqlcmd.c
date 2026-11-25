// Copyright (c) 2026 @sitxovski (Discord)
/* fake_sqlcmd — стенд шлюза gp7: пишет текст -Q в FAKE_SQL_LOG и печатает ответ как GP7_Purchase (status 1) + id. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char** argv)
{
    const char* q = "";
    for (int i = 1; i < argc - 1; ++i) { if (!strcmp(argv[i], "-Q")) { q = argv[i + 1]; } }
    const char* log = getenv("FAKE_SQL_LOG");
    if (log) { FILE* f = fopen(log, "ab"); if (f) { fprintf(f, "%s\n", q); fclose(f); } }
    if (strstr(q, "GP7_GetBalance")) { printf("999999|0|1\n"); return 0; }
    if (strstr(q, "GP7_Purchase"))   { printf("1|999999|0\n424242\n"); return 0; }
    return 0;
}
