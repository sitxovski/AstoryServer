// Copyright (c) 2026 @sitxovski (Discord)
// n21_respawn_free_tile.cpp — МОНСТР ПРИ ПОЯВЛЕНИИ НЕ ВСТАЁТ В КЛЕТКУ ДРУГОГО ЖИВОГО МОНСТРА (слот P93, 26.10.2026).
//
// [ИСПРАВЛЕНИЕ] дефекта стока (решение владельца 26.10: «да, всех, но убедись, что они не в одном тайле спаунятся»).
//
// МЕХАНИЗМ СТОКА (NpcServer CAi::Frame_Monster = sub_461C80, ветка «время возрождения вышло», NpcServer.exe.c:64650-65010)
//   Клетка появления выбирается так:
//     • одиночка без маршрута — клетка точки спауна из .svr (+30384/+30388 монстра);
//     • одиночка/вожак с маршрутом (+34356 ≠ 0) — случайная точка в прямоугольнике очередного отрезка маршрута
//       (sub_408AB0 = rand в [min, max]);
//     • член отряда — sub_41AFE0 «SearchAvailableTile»: смещение (размер+1 + rand % 3/6/9/12) от вожака в одной из
//       четырёх четвертей, до 5 попыток.
//   Затем (0x4628C0) проверяется только ПРОХОДИМОСТЬ клетки: sub_41A310 = GetTileState (статичная карта ./Map/<карта>,
//   загружается при старте, во время работы не пишется); занятая — sub_41AC10 ищет соседнюю проходимую.
//   Занятость клетки ДРУГИМ МОНСТРОМ сток не проверяет нигде: появившийся монстр может встать ровно в клетку того,
//   кто туда пришёл (погоня, блуждание), — клиент рисует их друг в друге.
//   Журналы игроков 21–26.10 (114 сессий): из 369 возрождений с известной первой клеткой 1 — в клетке другого живого
//   монстра, 15 — в соседней; клетки точек спауна в .svr все различны (23 карты).
//
// ЧТО ДЕЛАЕМ
//   На площадке 0x46292B (общая точка всех веток: клетка выбрана и проверена на проходимость, сейчас она запишется в
//   +30360/+30364 монстра) — если в этой клетке стоит ЖИВОЙ монстр той же карты (флаг +30292 бит 0), ищем по кольцам
//   1..Radius проходимую (GetTileState == 0) клетку без живого монстра, внутри кольца — случайную. Не нашли — клетка стока.
//   Позицию выбирает сервер — все клиенты и сам NpcServer видят одну и ту же клетку (клиентский разнос дал бы
//   рассинхрон с проверками дальности 8204/8940).
//
// ПЛОЩАДКА (сток d292e4ec / живой c02486d6 / Indun 0de2c559 / Ch2 7f79b5da — байты одинаковы, сверяет verify_n21.py)
//     0046292B  8B 54 24 30     mov  edx, [esp+30h]      ; ← сюда сходятся ветки 0x4628CF (jle) и 0x4628F0 (jge)
//     0046292F  8D 4F 08        lea  ecx, [edi+8]        ; монстр
//     00462932  66 89 B1 98 76 00 00  mov [ecx+7698h], si   ; x
//     00462939  66 89 99 9C 76 00 00  mov [ecx+769Ch], bx   ; z
//   Регистры: esi = x, ebx = z, edi = ячейка монстра (монстр = edi + 8), [esp+1Ch] = номер монстра на карте,
//   [esp+20h] = карта (this + 11547E4h: +4 ширина, +8 высота, +28h число клеток, +34h массив клеток по 12 б).
//   this = [esp+20h] − 11547E4h (сверяется с edi − номер × 92F8h); число монстров — [this + 2954858h].
//   В стабе: pushfd/pushad, новые x/z пишутся в сохранённые esi/ebx кадра pushad; после popad/popfd — исходные
//   `mov edx,[esp+34h]` (+4 на адрес возврата) и `lea ecx,[edi+8]`. Флаги после площадки никто не читает (следом
//   mov/mov/call). Переходов внутрь 0x46292C…0x462931 нет (verify_n21.py).
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЧЕРЕЗ #define (см. n03): C++-константа в `[reg + имя]` даёт АДРЕС.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const DWORD kVa     = 0x0046292B;                                              // mov edx,[esp+30h] / lea ecx,[edi+8]
    const BYTE  kOrig[] = { 0x8B, 0x54, 0x24, 0x30, 0x8D, 0x4F, 0x08 };
    const Site  kSites[] = { { kVa, kOrig, sizeof(kOrig) } };

    constexpr DWORD kMapOffset   = 0x011547E4;   // this + 11547E4h — карта (сектора, клетки) CAi
    constexpr DWORD kMobCountOff = 0x02954858;   // this + 2954858h — число монстров карты
    constexpr DWORD kSlotStride  = 0x92F8;       // ячейка монстра (37624 б), монстр = ячейка + 8
    constexpr DWORD kSlotFlags   = 0x765C;       // ячейка +765Ch (монстр +30292): бит 0 — живой, в мире
    constexpr DWORD kSlotX       = 0x76A0;       // ячейка +76A0h (монстр +7698h, +30360): x клетки (i16)
    constexpr DWORD kSlotZ       = 0x76A4;       // ячейка +76A4h (монстр +769Ch, +30364): z клетки (i16)

    #define N21_IDX  44h                 // [esp+1Ch] кадра в стабе: 1Ch + 24h (pushad/pushfd) + 4 (адрес возврата)
    #define N21_MAP  48h                 // [esp+20h] кадра в стабе
    #define N21_EDX  34h                 // исходная `mov edx,[esp+30h]` после popad/popfd: +4 на адрес возврата

    int  g_radius = 2;                   // Radius — сколько колец вокруг клетки стока обходить (1..5)
    LONG g_seed = 0;                     // своё ГПСЧ (rand стока не трогаем — его последовательность у NpcServer своя)
    volatile LONG g_hits = 0, g_busy = 0, g_moved = 0, g_noFree = 0, g_bad = 0;   // площадка / занято / разнесено / некуда / разбор

    // Живой монстр (не тот, что появляется) в клетке (x, z)?
    bool Occupied(const BYTE* self, int count, int x, int z, const BYTE* mobs)
    {
        for (int i = 0; i < count; ++i)
        {
            const BYTE* s = mobs + (DWORD)i * kSlotStride;
            if (s == self) { continue; }
            if ((*(const DWORD*)(s + kSlotFlags) & 1) == 0) { continue; }
            if (*(const short*)(s + kSlotX) == x && *(const short*)(s + kSlotZ) == z) { return true; }
        }
        return false;
    }

    // Клетка проходима (как sub_41AC10: состояние 0), координаты в границах карты.
    bool Walkable(const BYTE* map, int x, int z)
    {
        const int w = *(const int*)(map + 4), h = *(const int*)(map + 8), n = *(const int*)(map + 0x28);
        const BYTE* tiles = *(const BYTE* const*)(map + 0x34);
        if (!tiles || x < 0 || z < 0 || x >= w || z >= h) { return false; }
        const int idx = x + w * z;
        if (idx < 0 || idx >= n) { return false; }
        return *(const DWORD*)(tiles + 12 * idx) == 0;
    }

    unsigned NextRand()
    {
        const LONG v = InterlockedExchangeAdd(&g_seed, 0) * 1103515245 + 12345;
        InterlockedExchange(&g_seed, v);
        return (unsigned)(v >> 8) & 0x7FFFFF;
    }
}

// slot — ячейка монстра (edi), x/z — сохранённые esi/ebx кадра pushad, map — [esp+20h], idx — [esp+1Ch].
extern "C" void __stdcall N21_Pick(BYTE* slot, int* x, int* z, BYTE* map, int idx)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        if (!slot || !x || !z || !map || idx < 0) { InterlockedIncrement(&g_bad); return; }
        BYTE* self = map - kMapOffset;                                       // this
        if (self + (DWORD)idx * kSlotStride != slot) { InterlockedIncrement(&g_bad); return; }   // не тот кадр — сток
        const int count = *(const int*)(self + kMobCountOff);
        if (count <= 0 || idx >= count) { InterlockedIncrement(&g_bad); return; }
        const int x0 = *x, z0 = *z;
        if (!Occupied(slot, count, x0, z0, self)) { return; }
        InterlockedIncrement(&g_busy);
        for (int r = 1; r <= g_radius; ++r)
        {
            int cx[40], cz[40], n = 0;                                       // кольцо радиуса r: 8r клеток (r ≤ 5 → ≤ 40)
            for (int dz = -r; dz <= r; ++dz)
            {
                for (int dx = -r; dx <= r; ++dx)
                {
                    if (dx != -r && dx != r && dz != -r && dz != r) { continue; }
                    const int tx = x0 + dx, tz = z0 + dz;
                    if (tx <= 0 || tz <= 0) { continue; }                     // сток отвергает клетки ≤ 0 (0x4628B0)
                    if (!Walkable(map, tx, tz) || Occupied(slot, count, tx, tz, self)) { continue; }
                    if (n < 40) { cx[n] = tx; cz[n] = tz; ++n; }
                }
            }
            if (n > 0)
            {
                const int k = (int)(NextRand() % (unsigned)n);
                *x = cx[k]; *z = cz[k];
                InterlockedIncrement(&g_moved);
                return;
            }
        }
        InterlockedIncrement(&g_noFree);                                    // свободной нет — клетка стока
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_bad);
    }
}

// Счётчики (стенд): вызовы площадки, клетка занята, разнесено, свободной не нашлось, кадр не разобран.
extern "C" __declspec(dllexport) void __stdcall N21_Counters(LONG* hits, LONG* busy, LONG* moved, LONG* noFree, LONG* bad)
{
    if (hits) { *hits = g_hits; }
    if (busy) { *busy = g_busy; }
    if (moved) { *moved = g_moved; }
    if (noFree) { *noFree = g_noFree; }
    if (bad) { *bad = g_bad; }
}

namespace
{
    __declspec(naked) void St_RespawnFreeTile()
    {
        __asm
        {
            pushfd
            pushad
            mov     eax, esp
            push    dword ptr [eax + N21_IDX]   // номер монстра на карте
            push    dword ptr [eax + N21_MAP]   // карта
            lea     ecx, [eax + 10h]            // сохранённый ebx = z
            push    ecx
            lea     ecx, [eax + 4]              // сохранённый esi = x
            push    ecx
            push    edi                         // ячейка монстра
            call    N21_Pick                    // __stdcall, 20 б
            popad
            popfd
            mov     edx, dword ptr [esp + N21_EDX]   // исходная `mov edx,[esp+30h]` (+4 адрес возврата)
            lea     ecx, [edi + 8]                   // исходная `lea ecx,[edi+8]`
            ret
        }
    }
}

PatchResult N21_RespawnFreeTile()
{
    if (!Config::GetBool(L"N21_RespawnFreeTile", L"Enabled", true)) { return PatchResult::Disabled; }
    g_radius = Config::GetInt(L"N21_RespawnFreeTile", L"Radius", 2);
    if (g_radius < 1) { g_radius = 1; }
    if (g_radius > 5) { g_radius = 5; }
    InterlockedExchange(&g_seed, (LONG)GetTickCount());
    if (!VerifyAllSites(L"N21_RespawnFreeTile", kSites, ARRAYSIZE(kSites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteCall(kVa, (void*)&St_RespawnFreeTile, sizeof(kOrig))) { return PatchResult::Failed; }
    Log::Line(L"    N21: появившийся монстр не встаёт в клетку живого монстра — свободная проходимая клетка в радиусе %d", g_radius);
    return PatchResult::Applied;
}
