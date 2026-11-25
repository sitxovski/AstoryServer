// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P30 — ★ ЧИСЛО СЛОТОВ КАРТ 23 → MaxMaps (по умолчанию — сколько строк в MapInfo.txt).
//
//  ЭТО НАША ПРАВКА (решение владельца 2026-09-12: «поднять потолок числа карт,
//  чтобы хватило места будущим картам»), а не перенос чужой.
//  Документ: AstoryServer/Docs/GameServer/map-slots-30-p30.md
//  Разбор:   Reports/job4/FLAMMIOPLAIN_MAP_PLAN.md §3.2
//
//  ── ЧТО В ОРИГИНАЛЕ ──
//  Почти всё, что связано с картами, у GameServer динамическое:
//    • MapData_Info\MapInfo.txt         — первая строка N, массив new(236*N+4)  (dword_5F5EE8 / dword_5F5E18);
//    • MapData_Info\MapWarpCost.txt     — первая строка N, матрица N×N в куче;
//    • NpcServer\ini\MapInfo.ini        — new[68*N+4];
//    • ChannelManager                   — MaxMapCount из ini, массивы в куче.
//  Жёстко зашит РОВНО ОДИН массив — «карта открыта + её имя» из
//  MapData_Info\OpenMapInfo.ini: 23 записи по 0x33 б (1 б Use + 50 б Name),
//  статически по VA 0x0060A880 в .bss (конструктор sub_582670@0x582670).
//  Он же и есть потолок номеров карт: у карты без записи нет ни признака
//  «открыта», ни потока — именно поэтому карта 23 ^MineWar^ на живом мертва.
//
//  Одиннадцать площадок (сверены с ЖИВЫМ GameServer, ЖИВЫМ Indun_GameServer,
//  настоящим стоком GameServer.exe_before_mine_patch.exe и декомпильным образом —
//  совпали во всех четырёх, 2026-09-12):
//
//   VA          байты                    что
//   0x004A043E  83 F8 17                 cmp eax,23 — MapCount из OpenMapInfo.ini; >=23 → exit(1)
//   0x004A044B  6A 17                    push 23 — аргумент «Max %d» в тексте той же ошибки
//   0x004A04AE  83 BD 54EAFFFF 17        cmp [ebp-0x15AC],23 — цикл чтения секций MAP_0…MAP_22
//   0x004A04FD  88 8A 80A86000           mov [edx+0x60A880],cl      — запись Use
//   0x004A0513  05 81A86000              add eax,0x60A881           — адрес поля Name
//   0x004A0536  0F B6 82 80A86000        movzx eax,[edx+0x60A880]   — чтение Use (счётчик открытых)
//   0x004A537F  83 7D D0 17              cmp [ebp-0x30],23 — цикл раздачи потоков картам
//   0x004A538F  0F B6 91 80A86000        movzx edx,[ecx+0x60A880]   — Use в том же цикле
//   0x0052C610  0F B6 88 80A86000        movzx ecx,[eax+0x60A880]   — «карта-цель открыта?» в проверке портала
//   0x00582678  6A 17                    push 23  — счётчик в конструкторе массива
//   0x0058267C  68 80A86000              push 0x60A880 — база в том же конструкторе
//
//  Полнота списка доказана ДВУМЯ методами:
//    1) поиск литерала 0x0060A880 по ВСЕМУ файлу образа — 5 вхождений (+1 на
//       0x0060A881), все перечислены выше; секции .reloc у образа нет, адреса
//       абсолютные, спрятаться ссылке негде;
//    2) подомный дизассембл всех 3377 функций (capstone, границы из декомпила) с
//       выборкой команд с непосредственным 22/23/24: константа 23 вне трёх
//       перечисленных мест с картами не связана (остальное — уровни лога 0x16/0x17,
//       `add esp,0x18` и т.п.).
//
//  ── ПОЧЕМУ НЕЛЬЗЯ ПРОСТО «РАСТЯНУТЬ» МАССИВ ──
//  Он лежит впритык: 0x0060A880 … 0x0060AD14 (23*51 = 1173 б), а с 0x0060AD18
//  начинается объект CThreadManager (`mov ecx,0x60AD18; call LoadFameInfo` в
//  sub_582690@0x582690) — зазор ТРИ байта. Перед массивом, на 0x0060A87C, тоже
//  объект. Ещё одна запись затёрла бы указатель на таблицу виртуальных функций
//  CThreadManager. ⇒ массив обязан ПЕРЕЕХАТЬ.
//  (Чужой мод `.mapext`, который когда-то попал в наш декомпил, делал ровно это:
//   переносил массив на byte_68BF000 в добавленной секции PE. Мы повторяем идею,
//   но без правки самого exe: буфер живёт в НАШЕЙ DLL.)
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Буфер g_mapOpen[30*51] в .bss самой AsdaPatch.dll (нули — ровно то, что
//  делает поэлементный конструктор sub_4BE660: *this=0; memset(this+1,0,0x32)).
//  DllMain работает ДО EntryPoint хоста, то есть до `_initterm`, где вызывается
//  sub_582670 — к моменту конструирования массива и база, и счётчик уже наши.
//  В шести площадках правится только абсолютный адрес (disp32/imm32), в пяти —
//  только imm8 со счётчиком. Длина и кодировка команд не меняются.
//
//  ── ПОТОЛОК 30 И ПОЧЕМУ НЕ БОЛЬШЕ ──
//  Второй, независимый предел — массив Total_PortalConfig.Ini внутри CUserManager:
//  `vector constructor iterator(this+2656, 0x1F, 30, sub_530530)` (sub_522550@0x522550),
//  memset(this+2656, 0, 0x3A2) = 30*31 б. Он индексируется НОМЕРОМ КАРТЫ напрямую
//  (RecvContinent_PortalMove: `this + 31*mapId + 2656`), а проверяется только
//  `mapId < dword_5F5EE8`, то есть числом строк MapInfo.txt. Сразу за массивом,
//  на this+3588, лежит DWORD-флаг, а на this+3596 — массив 550 записей игроков по
//  0x231 б. ⇒ номер карты 30 и выше = чтение и разбор ЧУЖОЙ памяти.
//  Поэтому 30 — жёсткий предел P30. Больше 30 потребует переносить и этот массив,
//  а он адресуется от регистра `this`, простой правкой операнда не обойтись.
//
//  ── И ВТОРОЙ ЗАЖИМ: ЧИСЛО СТРОК MapInfo.txt ──
//  Цикл раздачи потоков для каждого j < cap читает Use[j], и ТОЛЬКО если он не ноль —
//  тип карты из dword_5F5E18 + 236*j + 63. Массив MapInfo.txt имеет ровно
//  dword_5F5EE8 записей. Значит cap выше числа строк MapInfo.txt безопасен лишь
//  пока у лишних секций MAP_k стоит Use=0. Чтобы этой мины не было вовсе, DLL сама
//  читает первое число MapData_Info\MapInfo.txt и зажимает cap им же.
//  Файл не прочитался — патч НЕ ставится (лучше 23, чем чтение за концом массива).
//
//  ── ЧЕГО ЭТОТ ПАТЧ НЕ ДЕЛАЕТ ──
//  Он НЕ оживляет карту 23 ^MineWar^ сам по себе. Слот и признак «открыта» она
//  получит, но: (1) её тип карты в MapInfo.txt = 6, а поток создаётся только для
//  типов 0, 1 и 3 — проверка `test edx,edx / cmp edx,1 / cmp edx,3` @0x4A53AB…0x4A53E6;
//  (2) на живом сервере нет ни одного её файла (.sim, .svr, .npc,
//  ^MineWar^_PortalConfig.Ini, ^MineWar^_ConnectIP.ini), и NpcServer о ней не знает
//  (ini\MapInfo.ini MapCount=23, то есть 0…22). Это отдельная работа по данным.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstdio>

namespace
{
    const wchar_t* const kSec = L"P30_MapSlots";

    constexpr int kStockSlots = 23;      // сколько слотов в стоке
    constexpr int kSlotSize   = 0x33;    // 51 б на запись: Use(1) + Name(50)
    // ★ Жёсткий предел: ёмкость массива Total_PortalConfig в CUserManager (30 записей
    //   по 31 б, this+2656). Индексируется номером карты напрямую — см. шапку.
    constexpr int kHardMax    = 30;

    // Новый массив «карта открыта + имя». Нули — это и есть состояние после
    // поэлементного конструктора стока (sub_4BE660).
    BYTE g_mapOpen[kHardMax * kSlotSize] = {};

    // Что именно правится в площадке.
    enum class Op
    {
        Imm8Count,    // байт-счётчик слотов (23 → cap)
        Abs32Base,    // абсолютный адрес массива
        Abs32Base1    // абсолютный адрес массива + 1 (поле Name)
    };

    struct MapSite
    {
        DWORD          va;         // адрес команды
        BYTE           orig[7];    // оригинальные байты (сверяются целиком)
        int            len;        // сколько из них значимы
        int            opOff;      // смещение операнда внутри площадки
        Op             op;
        const wchar_t* what;
    };

    const MapSite kSites[] =
    {
        { Srv::Hooks::kMapSlotsCountGate, { 0x83, 0xF8, 0x17 },                         3, 2, Op::Imm8Count,
          L"LoadFameInfo: cmp eax,23 — верхняя граница MapCount (иначе exit(1))" },
        { Srv::Hooks::kMapSlotsCountMsg,  { 0x6A, 0x17 },                               2, 1, Op::Imm8Count,
          L"LoadFameInfo: push 23 — число «Max %d» в тексте той же ошибки" },
        { Srv::Hooks::kMapSlotsReadLoop,  { 0x83, 0xBD, 0x54, 0xEA, 0xFF, 0xFF, 0x17 }, 7, 6, Op::Imm8Count,
          L"LoadFameInfo: цикл чтения секций MAP_0…MAP_22 из OpenMapInfo.ini" },
        { Srv::Hooks::kMapSlotsWriteUse,  { 0x88, 0x8A, 0x80, 0xA8, 0x60, 0x00 },       6, 2, Op::Abs32Base,
          L"LoadFameInfo: запись признака «карта открыта»" },
        { Srv::Hooks::kMapSlotsNameAddr,  { 0x05, 0x81, 0xA8, 0x60, 0x00 },             5, 1, Op::Abs32Base1,
          L"LoadFameInfo: адрес поля Name для GetPrivateProfileString" },
        { Srv::Hooks::kMapSlotsReadUse,   { 0x0F, 0xB6, 0x82, 0x80, 0xA8, 0x60, 0x00 }, 7, 3, Op::Abs32Base,
          L"LoadFameInfo: чтение Use для счётчика открытых карт" },
        { Srv::Hooks::kMapSlotsThrLoop,   { 0x83, 0x7D, 0xD0, 0x17 },                   4, 3, Op::Imm8Count,
          L"SetUserInfo_ThreadID_Mapping: цикл раздачи потоков картам" },
        { Srv::Hooks::kMapSlotsThrUse,    { 0x0F, 0xB6, 0x91, 0x80, 0xA8, 0x60, 0x00 }, 7, 3, Op::Abs32Base,
          L"SetUserInfo_ThreadID_Mapping: чтение Use в том же цикле" },
        { Srv::Hooks::kMapSlotsPortalUse, { 0x0F, 0xB6, 0x88, 0x80, 0xA8, 0x60, 0x00 }, 7, 3, Op::Abs32Base,
          L"sub_52C4C0: «карта-цель открыта?» в проверке зоны портала" },
        { Srv::Hooks::kMapSlotsCtorCount, { 0x6A, 0x17 },                               2, 1, Op::Imm8Count,
          L"sub_582670: число элементов в конструкторе массива" },
        { Srv::Hooks::kMapSlotsCtorBase,  { 0x68, 0x80, 0xA8, 0x60, 0x00 },             5, 1, Op::Abs32Base,
          L"sub_582670: база массива в конструкторе" },
    };

    // Первое число MapData_Info\MapInfo.txt — объявленное число карт.
    // -1: файл не открылся или первая лексема не число.
    int ReadMapInfoRows()
    {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"%sMapData_Info\\MapInfo.txt", Config::BaseDir());
        FILE* f = nullptr;
        if (_wfopen_s(&f, path, L"r") != 0 || !f) { return -1; }
        int n = -1;
        if (fscanf_s(f, "%d", &n) != 1) { n = -1; }
        fclose(f);
        return n;
    }

    // Справочно в лог: первое число MapWarpCost.txt (матрица N×N цен варпа).
    int ReadWarpCostN()
    {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"%sMapData_Info\\MapWarpCost.txt", Config::BaseDir());
        FILE* f = nullptr;
        if (_wfopen_s(&f, path, L"r") != 0 || !f) { return -1; }
        int n = -1;
        if (fscanf_s(f, "%d", &n) != 1) { n = -1; }
        fclose(f);
        return n;
    }
}

PatchResult P30_MapSlots()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        Log::Line(L"    P30: выключен — 23 слота карт и массив по 0x0060A880, как в стоке");
        return PatchResult::Disabled;
    }

    const int rows = ReadMapInfoRows();
    if (rows <= 0)
    {
        Log::Line(L"    P30: ! MapData_Info\\MapInfo.txt не прочитан — патч НЕ ставится "
                  L"(поднимать число слотов, не зная длины таблицы карт, значит рискнуть "
                  L"чтением за концом массива MapInfo)");
        return PatchResult::Failed;
    }

    int cap = Config::GetInt(kSec, L"MaxMaps", kHardMax);
    if (cap > kHardMax)
    {
        Log::Line(L"    P30: MaxMaps=%d больше жёсткого предела %d (ёмкость Total_PortalConfig "
                  L"в CUserManager) — взято %d", cap, kHardMax, kHardMax);
        cap = kHardMax;
    }
    if (cap > rows)
    {
        Log::Line(L"    P30: MaxMaps=%d больше числа строк MapInfo.txt (%d) — взято %d "
                  L"(лишние слоты некуда отображать)", cap, rows, rows);
        cap = rows;
    }
    if (cap < kStockSlots)
    {
        Log::Line(L"    P30: расчётный потолок %d не больше стокового %d — НИЧЕГО НЕ МЕНЯЕМ. "
                  L"Чтобы слотов стало больше, добавьте строки в MapData_Info\\MapInfo.txt "
                  L"(сейчас %d) и секции MAP_n в OpenMapInfo.ini", cap, kStockSlots, rows);
        return PatchResult::Disabled;
    }
    if (cap == kStockSlots)
    {
        Log::Line(L"    P30: потолок остаётся стоковым 23 (строк в MapInfo.txt %d) — "
                  L"массив не переносится, площадки не трогаются", rows);
        return PatchResult::Disabled;
    }

    const int warpN = ReadWarpCostN();
    Log::Line(L"    P30: MapInfo.txt строк %d, MapWarpCost.txt N=%d, жёсткий предел %d",
              rows, warpN, kHardMax);
    if (warpN > 0 && warpN < cap)
    {
        Log::Line(L"    P30: ~ MapWarpCost.txt описывает только %d×%d карт — для карт %d…%d "
                  L"цена телепорта не найдётся и переход по мировой карте будет отклонён. "
                  L"Матрицу надо расширить до %d×%d.", warpN, warpN, warpN, cap - 1, cap, cap);
    }

    // ── сверка ВСЕХ площадок до первой записи (всё или ничего) ──
    Site sites[ARRAYSIZE(kSites)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        sites[i] = { kSites[i].va, kSites[i].orig, (SIZE_T)kSites[i].len };
    }
    if (!VerifyAllSites(L"P30", sites, ARRAYSIZE(kSites))) { return PatchResult::Mismatch; }

    const DWORD newBase = (DWORD)(ULONG_PTR)&g_mapOpen[0];

    // ── запись; при сбое — откат уже записанных площадок ──
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        const MapSite& s = kSites[i];
        BYTE buf[sizeof(s.orig)];
        for (int k = 0; k < s.len; ++k) { buf[k] = s.orig[k]; }

        switch (s.op)
        {
            case Op::Imm8Count:
                buf[s.opOff] = (BYTE)cap;
                break;
            case Op::Abs32Base:
            case Op::Abs32Base1:
            {
                const DWORD v = (s.op == Op::Abs32Base) ? newBase : newBase + 1;
                buf[s.opOff + 0] = (BYTE)( v        & 0xFF);
                buf[s.opOff + 1] = (BYTE)((v >>  8) & 0xFF);
                buf[s.opOff + 2] = (BYTE)((v >> 16) & 0xFF);
                buf[s.opOff + 3] = (BYTE)((v >> 24) & 0xFF);
                break;
            }
        }

        if (!Hook::WriteBytes(s.va, buf, s.len))
        {
            for (int j = 0; j < i; ++j)
            {
                Hook::WriteBytes(kSites[j].va, kSites[j].orig, kSites[j].len);
            }
            Log::Line(L"    P30: ! запись @0x%08X не удалась — откат %d площадок, потолок 23",
                      s.va, i);
            return PatchResult::Failed;
        }
        Log::Line(L"    P30: @0x%08X %s  (%s)", s.va,
                  (s.op == Op::Imm8Count) ? L"23 -> счётчик" : L"0x0060A880 -> новая база",
                  s.what);
    }

    Log::Line(L"    P30: слотов карт 23 -> %d (номера 0…%d); массив перенесён "
              L"0x0060A880 -> 0x%08X (%d б в AsdaPatch.dll); площадок %d",
              cap, cap - 1, newBase, (int)sizeof(g_mapOpen), (int)ARRAYSIZE(kSites));
    return PatchResult::Applied;
}
