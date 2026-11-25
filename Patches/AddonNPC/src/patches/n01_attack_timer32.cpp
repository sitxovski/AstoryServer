// Copyright (c) 2026 @sitxovski (Discord)
// n01_attack_timer32.cpp — АНТИЧИТ СКОРОСТИ АТАКИ СЧИТАЕТ ВРЕМЯ ПО 16 БИТАМ.
//
// СИМПТОМ
//   После паузы дольше минуты первые удары «не проходят»: персонаж бьёт, а ничего не
//   происходит — ни урона, ни промаха, ни ответа. Через секунду-две налаживается само.
//   При частом повторении сервер выкидывает игрока. Жалоба владельца 24.08.2026:
//   «то атакует, то не атакует».
//
// МЕХАНИЗМ
//   `CAi::Process_AttackedToMonster`. Момент последнего удара ХРАНИТСЯ 32-битным
//   (`mov [ebp+0FE90h], eax` — 4 байта), а СРАВНИВАЕТСЯ по младшим 16 битам:
//
//     0x45F596  mov   edi, [esp+298h]          ; текущий тик
//     0x45F59D  movsx eax, word [ebp+0FE94h]   ; требуемый интервал
//     0x45F5A4  mov   dx, di                   ; <- усечение до 16 бит
//     0x45F5A7  sub   dx, [ebp+0FE90h]         ; <- 16-битное вычитание
//     0x45F5AE  add   dx, 64h                  ; +100 мс допуска
//     0x45F5B2  movzx ecx, dx / movzx ecx, cx
//     0x45F5B8  cmp   ecx, eax
//     0x45F5BA  jge   <удар засчитан>
//
//   Арифметика по модулю 65536 верна, ПОКА пауза меньше ~65,4 с. Дольше — разность
//   заворачивается и выходит малой, управление уходит в ветку отказа:
//     • удар МОЛЧА отбрасывается — единственный такой silent drop в боевом пути;
//     • счётчик нарушений `+0FE60h` +1; при > 30 сервер шлёт 8905 и выкидывает игрока;
//     • ★ поле `+0FE90h` в ветке отказа НЕ обновляется, поэтому отбрасывается СЕРИЯ
//       ударов, и только потом всё налаживается.
//   Счётчик убывает на 1 за каждый удачный удар, поэтому до отключения доходит не сразу,
//   но пропуски видны немедленно.
//
// ЧТО ДЕЛАЕМ
//   Переводим вычисление в 32 бита — ровно то, чем оно и должно быть, раз тик хранится
//   32-битным. Порог, допуск 100 мс и счётчик нарушений НЕ трогаем: античит продолжает
//   ловить настоящее ускорение атаки. Длина кода сохраняется байт в байт, хвост добивается
//   `nop`, переходы и границы функций не двигаются.
//
//   Площадок две — в бинаре два «SpeedHack Check»: обычная атака и функция-двойник.
//   У двойника вдобавок снимается повторное усечение `movzx ecx, cx`, иначе 32 бита
//   тут же обрезались бы обратно.
//
// ⚠ Байты выверены на образе NpcServer.exe md5 d292e4ec4edfd5040d8fb39382664eab —
//   он побайтово совпадает с живым сервером (сверено 24.08.2026).
//   Тот же патч в виде отдельного скрипта (запасной путь, если инъекция DLL недоступна):
//   AstoryServer/Docs/NpcServer/patch_npc_attack_timer32.py
//
// ★ ДОПУСК 15 % (волна N16, решение владельца 15.10.2026) — ключ [N01_AttackTimer32] AttackToleranceRate
//   Сток прощает удару 100 мс: удар принят, если (тик − прошлый удар) + 100 ≥ dur, где dur (+0xFE94) —
//   серверная длительность прошлого удара (Combo.lst[тип оружия][шаг комбо] с поправками на баффы скорости,
//   после навыка — Skill.lst[навык]). Для ударов по 900–1620 мс это 6–11 %: сетевой джиттер и кадры
//   честного клиента копят счётчик +0xFE60, при > 30 — 8905 → кик 4101 код 6.
//   Теперь допуск = max(100 мс, dur · Rate / 100): нарушение — только если интервал короче dur БОЛЬШЕ,
//   чем на Rate % (при dur ≤ 666 мс остаются стоковые 100 мс). Rate = 0 — ставятся прежние байты N01
//   (допуск ровно 100 мс, как в стоке). Предел 0…50 (больше — зажимается, строка в PatchLog).
//   Реализация: в уже 32-битной площадке `add edx/eax, 64h` + `mov ecx, …` + nop заменяются на `call`
//   стаба (длина та же). Стаб: ecx (и регистр, где была сумма) = dt + допуск, с насыщением до 0xFFFFFFFF
//   при переносе; dur ≤ 0 → 0xFFFFFFFF (удар принят — как в стоке, где 16-битная сумма ≥ 0 всегда ≥ dur ≤ 0;
//   прежние байты N01 с `jae` такой удар отбрасывали бы). Порог 30, счётчик, 8905, строки Error_Log и
//   журнал N13 — без изменений; в строке «SpeedHack Check» последнее число = интервал + ДЕЙСТВУЮЩИЙ допуск.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    // ── площадка 1: Process_AttackedToMonster ────────────────────────────────
    const DWORD kVa1  = 0x45F5A4;
    const BYTE  kOrig1[] = {
        0x66,0x8B,0xD7,                          // mov   dx, di
        0x66,0x2B,0x95,0x90,0xFE,0x00,0x00,      // sub   dx, [ebp+0FE90h]
        0x66,0x83,0xC2,0x64,                     // add   dx, 64h
        0x0F,0xB7,0xCA,                          // movzx ecx, dx
        0x0F,0xB7,0xC9                           // movzx ecx, cx
    };
    const BYTE  kNew1[] = {
        0x8B,0xD7,                               // mov   edx, edi
        0x2B,0x95,0x90,0xFE,0x00,0x00,           // sub   edx, [ebp+0FE90h]
        0x83,0xC2,0x64,                          // add   edx, 64h
        0x8B,0xCA,                               // mov   ecx, edx
        0x90,0x90,0x90,0x90,0x90,0x90,0x90       // nop x7 — длина сохранена
    };

    // ── площадка 2: функция-двойник ──────────────────────────────────────────
    const DWORD kVa2  = 0x460151;
    const BYTE  kOrig2[] = {
        0x66,0x8B,0xC7,                          // mov   ax, di
        0x66,0x2B,0x85,0x90,0xFE,0x00,0x00,      // sub   ax, [ebp+0FE90h]
        0x66,0x05,0x64,0x00,                     // add   ax, 64h
        0x0F,0xB7,0xC8                           // movzx ecx, ax
    };
    const BYTE  kNew2[] = {
        0x8B,0xC7,                               // mov   eax, edi
        0x2B,0x85,0x90,0xFE,0x00,0x00,           // sub   eax, [ebp+0FE90h]
        0x83,0xC0,0x64,                          // add   eax, 64h
        0x8B,0xC8,                               // mov   ecx, eax
        0x90,0x90,0x90,0x90                      // nop x4
    };

    // ── площадка 3: у двойника снять повторное усечение ──────────────────────
    const DWORD kVa3  = 0x460169;
    const BYTE  kOrig3[] = { 0x0F,0xB7,0xC9 };   // movzx ecx, cx
    const BYTE  kNew3[]  = { 0x90,0x90,0x90 };

    // ── площадки 4/5 (★ 12.10.2026, дефект самого N01): сравнение «прошло ≥ нужно» было ЗНАКОВЫМ ──
    //  После перевода в 32 бита ecx = тик − StartTime + 100 стал сравниваться через `jge` (знаковый).
    //  Тик — GetTickCount сервера; при аптайме @@ASTORY_SERVER_HOSTNAME@@ > 24,8 сут он ≥ 2^31 и как знаковый отрицателен.
    //  Первый удар после входа (StartTime = 0) даёт ecx < 0 < eax → «SpeedHack Check», удар молча
    //  отброшен, а StartTime в ветке отказа не обновляется → отбрасываются ВСЕ удары до рестарта
    //  сервера (живьём 12.10 20:44: `StartTime 0, PDuration 0, Duration -1440411806`, аптайм ≈ 33 сут,
    //  стрельба «не работала»). Исправление: `jge` (0F 8D) → `jae` (0F 83) — беззнаковое сравнение,
    //  которое верно и при переходе тика через 2^31 и через 2^32. Стоковый 16-битный код был беззнаковым
    //  (movzx), так что это возврат к стоковой семантике при 32-битной арифметике.
    const DWORD kVa4  = 0x45F5BB;                // байт условия `jge 0x45F681` (0F 8D c1 00 00 00)
    const BYTE  kOrig4[] = { 0x8D };
    const BYTE  kNew4[]  = { 0x83 };             // jae
    const DWORD kVa5  = 0x46016F;                // двойник: `jge 0x460235`
    const BYTE  kOrig5[] = { 0x8D };
    const BYTE  kNew5[]  = { 0x83 };

    // ── площадки 1/2 при AttackToleranceRate > 0 (★ N16): вместо `add …, 64h; mov ecx, …; nop…` — call стаба ──
    //   основная: 0x45F5A4 `mov edx, edi` (2) + `sub edx, [ebp+0FE90h]` (6), затем @0x45F5AC call St_TolMain + nop×7
    //   двойник:  0x460151 `mov eax, edi` (2) + `sub eax, [ebp+0FE90h]` (6), затем @0x460159 call St_TolTwin + nop×4
    //   (байты первых 8 — те же, что в kNew1/kNew2; хвост пишет Hook::WriteCall с добивкой nop до длины площадки)
    const DWORD kVa1Call = kVa1 + 8;             // 0x45F5AC
    const DWORD kVa2Call = kVa2 + 8;             // 0x460159
    const SIZE_T kLen1Call = sizeof(kOrig1) - 8; // 12 = call(5) + nop×7 — конец площадки 0x45F5B8 (`cmp ecx, eax`)
    const SIZE_T kLen2Call = sizeof(kOrig2) - 8; // 9  = call(5) + nop×4 — конец площадки 0x460162 (`movsx eax, …`)

    const Site kSites[] = {
        { kVa1, kOrig1, sizeof(kOrig1) },
        { kVa2, kOrig2, sizeof(kOrig2) },
        { kVa3, kOrig3, sizeof(kOrig3) },
        { kVa4, kOrig4, sizeof(kOrig4) },
        { kVa5, kOrig5, sizeof(kOrig5) },
    };
}

// ── ★ N16: допуск в процентах длительности ─────────────────────────────────
// Процент допуска (0 = сток 100 мс). Пишется один раз при установке, до записи площадок.
static volatile LONG g_n01Rate = 0;

// dt — (тик − момент прошлого удара) по модулю 2^32 (истинный интервал при любом переходе тика);
// dur — требуемый интервал (+0xFE94, знаковый word). Возврат — то, что сток сравнивает с dur (`cmp ecx, eax; jae`).
extern "C" DWORD __stdcall N01_TolSum(DWORD dt, int dur)
{
    if (dur <= 0) { return 0xFFFFFFFFu; }                 // сток: 16-битная сумма ≥ 0 ≥ dur — удар принят
    DWORD tol = (DWORD)dur * (DWORD)g_n01Rate / 100u;     // dur ≤ 32767, Rate ≤ 50 — без переполнения
    if (tol < 100u) { tol = 100u; }                       // не строже стока
    const DWORD sum = dt + tol;
    return (sum < dt) ? 0xFFFFFFFFu : sum;                // перенос через 2^32 = очень давний удар — принят
}

namespace
{
    // Основная (Process_AttackedToMonster): вход edx = dt, eax = dur (movsx уже сделан @0x45F59D).
    // Выход: ecx = edx = сумма; eax = dur (сохранён); прочие регистры — как были (N01_TolSum — __stdcall).
    __declspec(naked) void St_TolMain()
    {
        __asm
        {
            push  eax                   // dur — сохранить
            push  eax                   // аргумент dur
            push  edx                   // аргумент dt
            call  N01_TolSum
            mov   ecx, eax
            mov   edx, eax
            pop   eax
            ret
        }
    }
    // Двойник (PvP, sub_45FF80): вход eax = dt, ebp = запись игрока; dur читается сам (сток грузит его
    // следующей инструкцией @0x460162 `movsx eax, word [ebp+0FE94h]`). Выход: ecx = eax = сумма; edx сохранён.
    __declspec(naked) void St_TolTwin()
    {
        __asm
        {
            push  edx
            movsx ecx, word ptr [ebp+0FE94h]
            push  ecx                   // аргумент dur
            push  eax                   // аргумент dt
            call  N01_TolSum
            mov   ecx, eax
            pop   edx
            ret
        }
    }
}

PatchResult N01_AttackTimer32()
{
    if (!Config::GetBool(L"N01_AttackTimer32", L"Enabled", true))
        return PatchResult::Disabled;

    int rate = Config::GetInt(L"N01_AttackTimer32", L"AttackToleranceRate", 15);
    if (rate < 0 || rate > 50)
    {
        const int was = rate;
        rate = (rate < 0) ? 0 : 50;
        Log::Line(L"    ! AttackToleranceRate=%d вне 0…50 — взято %d", was, rate);
    }

    // Правило проекта: ни один патч не пишет байты, не сверив ВСЕ свои площадки.
    if (!VerifyAllSites(L"N01_AttackTimer32", kSites, ARRAYSIZE(kSites)))
        return PatchResult::Mismatch;

    if (rate == 0)
    {
        // Прежние байты N01 (сборка 96cf74bc): допуск ровно 100 мс, как в стоке.
        if (!Hook::WriteBytes(kVa1, kNew1, sizeof(kNew1))) return PatchResult::Failed;
        if (!Hook::WriteBytes(kVa2, kNew2, sizeof(kNew2))) return PatchResult::Failed;
    }
    else
    {
        InterlockedExchange(&g_n01Rate, rate);
        if (!Hook::WriteBytes(kVa1, kNew1, 8)) return PatchResult::Failed;               // mov edx,edi; sub edx,[ebp+0FE90h]
        if (!Hook::WriteCall(kVa1Call, (void*)&St_TolMain, kLen1Call)) return PatchResult::Failed;
        if (!Hook::WriteBytes(kVa2, kNew2, 8)) return PatchResult::Failed;               // mov eax,edi; sub eax,[ebp+0FE90h]
        if (!Hook::WriteCall(kVa2Call, (void*)&St_TolTwin, kLen2Call)) return PatchResult::Failed;
    }
    if (!Hook::WriteBytes(kVa3, kNew3, sizeof(kNew3))) return PatchResult::Failed;
    if (!Hook::WriteBytes(kVa4, kNew4, sizeof(kNew4))) return PatchResult::Failed;
    if (!Hook::WriteBytes(kVa5, kNew5, sizeof(kNew5))) return PatchResult::Failed;

    if (rate == 0)
        Log::Line(L"    время между ударами считается 32-битным, сравнение беззнаковое (jae; аптайм сервера > 24,8 сут "
                  L"больше не отбрасывает удары); порог, допуск 100 мс (AttackToleranceRate=0) и счётчик нарушений не тронуты");
    else
        Log::Line(L"    время между ударами считается 32-битным, сравнение беззнаковое (jae); допуск = max(100 мс, %d %% "
                  L"длительности удара) — обычная атака и PvP (AttackToleranceRate=%d); порог 30 и счётчик нарушений не тронуты",
                  rate, rate);
    return PatchResult::Applied;
}
