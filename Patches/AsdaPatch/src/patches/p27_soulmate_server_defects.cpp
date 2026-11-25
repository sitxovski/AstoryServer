// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P27 — ★ ДЕФЕКТЫ СЕРВЕРНОЙ ЧАСТИ СОУЛМЕЙТА. Две независимые площадки,
//  каждая со своим ключом ini. Источник: `Reports/soulmate_6400.md` §12a.6.
//
//  ЭТО НАША ПРАВКА, а не перенос чужой.
//
//  ★★★ ВАЖНО ПРО ЭТАЛОН. Обе площадки сверены с ЖИВЫМ образом
//  (`\\@@ASTORY_SERVER_HOSTNAME@@\...\Working_ASDA\v2\GameServer\GameServer.exe`, MD5
//  E7B4AC38E8328AAA847BBD9BF261BB01) — байт в байт совпадают с нашим
//  `RE/ida/server_work/GameServer.exe`. Это существенно: у того же отчёта
//  дефект «С1 — MD5 пакетов не проверяется» ОПРОВЕРГНУТ ровно этой сверкой
//  (в живом образе стоит `je`, в нашем — `jmp`), и патча по нему нет.
//
//  ─────────────────────────────────────────────────────────────────────────
//  A. CastTimer — дефект С8. CheckSoulMateSkillCastingTime@0x00497440.
//
//  ── ЧТО НЕ ТАК ──
//  Отчёт называл это «16-битным чтением 32-битного тика». ДИЗАССЕМБЛЕР ЖИВОГО
//  ОБРАЗА говорит иначе (декомпилятор здесь врал, закон `false-negatives-method`):
//      00497509  mov eax, [ebp-0x198]                 ; pUser
//      0049750F  mov ecx, [ebp-0x194]                 ; GetTickCount()
//      00497515  sub ecx, dword ptr [eax+0x187E5]     ; ← вычитание ЧЕСТНО 32-битное
//      0049751B  mov word ptr [ebp-4], cx             ; ← а вот СОХРАНЕНИЕ усечено до 16 бит
//      0049752C  movsx ecx, word ptr [ebp-4]          ; ← и прочитано ЗНАКОВЫМ
//      00497530  cmp eax, ecx                         ; длительность каста (i16) vs прошло
//      00497532  jg  0x497613                         ; больше — «ещё кастуем», выход
//  Тик читается правильно; ломает усечение результата в ЗНАКОВОЕ 16-битное поле.
//  Как только с начала каста прошло больше 32 767 мс, значение становится
//  ОТРИЦАТЕЛЬНЫМ, условие «длительность > прошло» держится вечно, и каст не
//  завершается никогда; дальше картина повторяется с периодом 65 536 мс.
//  Симптом («навык соулмейта то срабатывает, то нет, примерно раз в минуту»)
//  описан верно, механизм в отчёте и в памятке — нет.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Зажимаем 32-битную разность по 0x7FFF ПЕРЕД усечением. Длительность каста —
//  знаковое 16-битное поле, то есть не больше 32 767, поэтому «прошло 0x7FFF»
//  гарантированно означает «прошло не меньше любой возможной длительности»,
//  и сравнение отрабатывает верно. Для нормальных значений (доли секунды)
//  вычисление не меняется ВООБЩЕ — зажим срабатывает только там, где сток и так
//  давал заведомо неверный отрицательный результат.
//
//  ─────────────────────────────────────────────────────────────────────────
//  B. SkillTableBounds — дефект С4. Загрузчик sub_4B3350@0x004B3350,
//     файл `.\SkillTable_Info\SoulmateSkill.ssi`.
//
//  ── ЧТО НЕ ТАК ──
//  Буфер выделяется СТРОГО на 100 записей (`push 0x2BC4` = 4 + 100*0x70), а цикл
//  чтения гейтится только размером файла и пишет по САМОСТОЯТЕЛЬНОМУ счётчику:
//      004B3457  mov eax, [ebp-0x70]              ; i
//      0049345A  cmp eax, [ebp-0x48]              ; nFileSizeLow
//      0049345D  jge 0x4B3493                     ; выход
//      004B3469  mov eax, [0x5F5ED8]              ; счётчик записей — БЕЗ верхней границы
//      004B346E  imul eax, eax, 0x70
//      004B3471  add eax, [0x5F5E38]
//      ...       ReadFile(hFile, eax, 0x70, ...)
//      004B3482  inc [0x5F5ED8]
//  Файл длиннее 11 200 байт ⇒ ReadFile пишет ЗА КОНЕЦ выделенной кучи.
//  ★ Счётчик 0x5F5ED8 к тому же не обнуляется перед циклом — повторный вызов
//  загрузчика начал бы писать за границу даже на маленьком файле.
//
//  ── НАСКОЛЬКО СРОЧНО ──
//  Извне НЕ эксплуатируется: длину задаёт файл на диске сервера, не пакет.
//  На живом сервере SoulmateSkill.ssi = 5 040 б = 45 записей из 100 — предел
//  сейчас НЕ достигнут, дефект спящий. Ставим как страховку: таблицу навыков
//  соулмейта мы собираемся расширять, и 101-я запись затрёт кучу молча.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Добавляем в условие цикла верхнюю границу счётчика (100). Лишние записи
//  файла просто не читаются, загрузчик возвращает успех, сервер стартует.
//
//  ── ЧТО БУДЕТ ПРИ ВКЛЮЧЕНИИ ──
//  Оба ключа на текущих данных поведение НЕ меняют: A правит только уже
//  сломанную ветку (>32 767 мс), B — только файл длиннее 100 записей.
//  Ни новых пакетов, ни отказов клиенту, ни изменений в БД патч не вносит.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

// ⚠ Смещения в __asm — ТОЛЬКО через #define (закон `msvc-inline-asm-offsets`):
//   C++-константа подставляет АДРЕС переменной, а не значение; на этом уже
//   роняли живой сервер.
#define CAST_START_TICK_OFF   0x187E5   // CUser+100325: тик начала каста (dword)
#define CAST_ELAPSED_CAP      0x7FFF    // потолок «прошло»: длительность каста — i16
#define SSI_MAX_RECORDS       100       // ёмкость буфера: (0x2BC4-4)/0x70 = 100

namespace
{
    // ── A. зажим «прошло» перед усечением ───────────────────────────────────
    constexpr DWORD kCastSiteVa = 0x00497515;   // sub ecx, dword ptr [eax+0x187E5]
    DWORD g_pCastRet            = 0x0049751B;   // возврат: `mov word ptr [ebp-4], cx`

    const BYTE kCastOrig[6] =
    {
        0x2B, 0x88, 0xE5, 0x87, 0x01, 0x00      // sub ecx, dword ptr [eax+0x187E5]
    };

    __declspec(naked) void CastElapsedClampTrampoline()
    {
        __asm
        {
            // eax = pUser, ecx = GetTickCount() — ровно как оставил сток.
            sub  ecx, dword ptr [eax + CAST_START_TICK_OFF]   // честная 32-битная разность
            cmp  ecx, CAST_ELAPSED_CAP
            jbe  CastDone                                     // без знака: обычный случай
            mov  ecx, CAST_ELAPSED_CAP                        // зажим: «прошло не меньше любой длительности»
        CastDone:
            jmp  dword ptr [g_pCastRet]                       // дальше сток: mov word [ebp-4], cx
        }
    }

    // ── B. верхняя граница числа записей .ssi ───────────────────────────────
    constexpr DWORD kSsiSiteVa = 0x004B3457;    // mov eax,[ebp-0x70] / cmp eax,[ebp-0x48]
    DWORD g_pSsiRet            = 0x004B345D;    // возврат: штатный `jge 0x4B3493`
    DWORD g_pSsiExit           = 0x004B3493;    // выход из цикла (штатная цель jge)
    DWORD g_pSsiCounter        = 0x005F5ED8;    // счётчик прочитанных записей

    const BYTE kSsiOrig[6] =
    {
        0x8B, 0x45, 0x90,                       // mov eax, dword ptr [ebp-0x70]
        0x3B, 0x45, 0xB8                        // cmp eax, dword ptr [ebp-0x48]
    };

    __declspec(naked) void SsiRecordBoundsTrampoline()
    {
        __asm
        {
            // Сначала своя граница: буфер выделен строго на SSI_MAX_RECORDS записей.
            mov  eax, dword ptr [g_pSsiCounter]
            mov  eax, dword ptr [eax]
            cmp  eax, SSI_MAX_RECORDS
            jge  SsiStop

            // Затем — воспроизводим стоковое условие и отдаём управление штатному jge:
            // флаги от этого cmp он и ждёт.
            mov  eax, dword ptr [ebp - 0x70]
            cmp  eax, dword ptr [ebp - 0x48]
            jmp  dword ptr [g_pSsiRet]

        SsiStop:
            jmp  dword ptr [g_pSsiExit]
        }
    }
}

PatchResult P27_SoulmateServerDefects()
{
    if (!Config::GetBool(L"P27_SoulmateServerDefects", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const bool doCast = Config::GetBool(L"P27_SoulmateServerDefects", L"CastTimerClamp",   true);
    const bool doSsi  = Config::GetBool(L"P27_SoulmateServerDefects", L"SkillTableBounds", true);
    if (!doCast && !doSsi)
    {
        return PatchResult::Disabled;
    }

    // Сверяем ВСЕ площадки до первой записи: патч ставится целиком или никак.
    const Site sites[] =
    {
        { kCastSiteVa, kCastOrig, sizeof(kCastOrig) },
        { kSsiSiteVa,  kSsiOrig,  sizeof(kSsiOrig)  },
    };
    if (!VerifyAllSites(L"P27", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (doCast)
    {
        if (!Hook::WriteJmp(kCastSiteVa, &CastElapsedClampTrampoline, sizeof(kCastOrig)))
        {
            return PatchResult::Failed;
        }
        Log::Line(L"    P27/A: перехват @0x%08X (6 б) -> трамплин 0x%08X, возврат 0x%08X",
                  kCastSiteVa, (DWORD)&CastElapsedClampTrampoline, g_pCastRet);
        Log::Line(L"    P27/A: «прошло с начала каста» зажато по 0x%X ДО усечения в i16 — "
                  L"каст навыка соулмейта больше не залипает после 32,7 с (дефект С8)",
                  CAST_ELAPSED_CAP);
    }

    if (doSsi)
    {
        if (!Hook::WriteJmp(kSsiSiteVa, &SsiRecordBoundsTrampoline, sizeof(kSsiOrig)))
        {
            return PatchResult::Failed;
        }
        Log::Line(L"    P27/B: перехват @0x%08X (6 б) -> трамплин 0x%08X, возврат 0x%08X, выход 0x%08X",
                  kSsiSiteVa, (DWORD)&SsiRecordBoundsTrampoline, g_pSsiRet, g_pSsiExit);
        Log::Line(L"    P27/B: чтение SoulmateSkill.ssi ограничено %d записями — закрыта "
                  L"запись за конец кучи на файле длиннее %d б (дефект С4)",
                  SSI_MAX_RECORDS, SSI_MAX_RECORDS * 0x70);
    }

    return PatchResult::Applied;
}
