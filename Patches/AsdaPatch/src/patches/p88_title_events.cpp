// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P88 — [ПОРТ] СОБЫТИЯ ЗВАНИЙ 187–205 (задача владельца 26.10.2026: «Включи эти звания. И в клиенте, и в сервере. Пусть их смогут
//  получить все игроки, пофиг на класс»). Документ: AstoryServer/Docs/GameServer/title-events-p88.md.
//
//  ── ЧТО В СТОКЕ (GameServer.c = RE/ida/server_work, байты всех площадок — сток 4e20f0ad = живой = Indun e7b4ac38) ──
//  Звание копится одним накопителем sub_54A050(userMng, userNum, id, add, extra) (GameServer.c:126114): выход, если
//  FameInfo[id].+2 (кол. 1 «включено») == 0 или звание уже есть (sub_54A890, маска CUser+0x17DDC); при FameInfo[id].+92
//  (кол. 45) == 1 — «универсальный накопитель»: прогресс CUser[+0x17DFC] + 44·id += add, проверка sub_54B260 (:126677):
//  прогресс >= FameInfo[id].+4 (кол. 3) → AddFameBit sub_54A980 (2256 в БД, очки +86) + 6065 игроку; второй порог +88/+90
//  (кол. 43/44) → маска «найдено» + 6085; прогресс → 2257 → DBManager EXEC UPCharFameUp → dbo.CharFame (Condition1/2).
//  При кол. 45 == 0 прогресс считает зашитый switch по id; у 188…205 веток НЕТ (default: 0) — выдать нельзя никогда.
//  ★ Из 19 званий сток зовёт накопитель ТОЛЬКО для 187 — и то не из войны: Recv_UserSoulResult@0x49A8C0 (:62117,
//    вместе с 1 «Белоснежка» — яблоки с Другом) с add = 0. Для 188…205 вызовов нет ни одного (поиск по 204 вызовам sub_54A050
//    и всем переменным id). В FameInfo.txt у 187…205 (кроме 204) кол. 1 = 0, порог 1, очки 0, кол. 45 = 0 — заготовка.
//
//  ── ПРАВКА: 8 площадок, события берутся из стоковых обработчиков ─────────────────────────────────────────────────────────
//   A  0x4CBA1A SendCharDead@0x4CB480 (:80815): убийство на карте MAP_TYPE 4 (война фракций, RoseWar), сток уже начислил
//      очки отряду (AddRoseWarPoint 0x468080) и шлёт 6730 — убийце +1 к 187/188/189.
//   B1 0x4EFE7D / B2 0x4EFEDD sub_4EF270 (Char_FunctionItem_Use, :92468/:92479): сброс навыков предметом — полный
//      sub_4803A0 (Property 0x23/0x36/0x37) / частичный sub_480F20 (0x24) — +1 к 190.
//   C  0x4EFE24 тот же обработчик, Property 0x22 (расширение склада +30, зажим 270 = 0x10E @0x4EFD34): после 5456, если
//      CUser+0x1AE >= WarehouseMaxSlots — +1 к 191 (порог 1).
//   D  0x53EF2A recvDBCraftEnter@0x53EE30 (:121693), ответ БД 2666 успешен: изготовленный предмет (запись +18 эха,
//      статус +74 == 1) — зелье (PotionCodes) → 192; грейд 3 «Герой» → 193/194/195; грейд 4 «Легенда» → 196/197/198
//      (грейд — клиентский item_list, у серверной item_table его нет: файлы gen_title_grades_p88.py).
//   E  0x546F8B sub_546C00 (:124903, итог копки 5431 от NpcServer → 5430 код 1, добыча легла): клетка копавшего
//      CUser+0x54E6/+0x54E8 и карта [[mgr+4]+0x4950] в зоне ZonesRuins → 199, ZonesShipwreck → 200, ZonesOasis → 201;
//      находка — живой камень (IsSowelCode 0x532AE0) → 203.
//   F  0x456F45 sub_456D90 (PetExpProcess, :35317): стоковый вызов звания 224 при повышении уровня питомца → свой
//      переходник: сток (224 как было) + 1 к 202.
//   G  0x4D5CB8 CharItemPicking@0x4D43A0 (:84340): ветка штатных «звания за подбор» (51031 → 145/146, 56024 → 93…95):
//      код из TicketCodes (79382 «Юбилейный билет») → 205, прибавка = подобранное количество (+9 записи).
//  Все прибавки — через стоковый sub_54A050 (тот же userMng, что у соседних стоковых вызовов): владение, 2256/2257, 6065,
//  очки, «найдено» — штатные. Протокол НЕ меняется. Порог 190/192/199/200/201/202/203/205 в данных не задан — берётся из
//  ini (Threshold<id>) и пишется в FameInfo[id].+4 в памяти при первом событии после старта (синхронно с FameInfo.txt).
//  Журнал ac.other 109 (звание выдано событием P88) / 110 (строка FameInfo не готова: выключена или не накопитель — раз на
//  звание за запуск) / 111 (исключение). Откат: [P88_TitleEvents] Enabled=0 — ни одна площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <stdlib.h>

namespace
{
    const wchar_t* kSec = L"P88_TitleEvents";                  // секция patches.ini

    // ── площадки ──────────────────────────────────────────────────────────────────────────────────────────────────────
    // A: SendCharDead — после AddRoseWarPoint, перед ctor тела 6730 (`lea ecx,[ebp-458h]`, 6 б → jmp + nop).
    constexpr DWORD kSiteA = 0x004CBA1A;
    const BYTE kOrigA[6]   = { 0x8D, 0x8D, 0xA8, 0xFB, 0xFF, 0xFF };
    DWORD g_backA          = 0x004CBA20;                       // call sub_4CCF30 (ctor тела 6730)
    // B1/B2/C: Char_FunctionItem_Use — `jmp loc_4F0FF4` (LABEL_143) после полного/частичного сброса и расширения склада.
    constexpr DWORD kSiteB1 = 0x004EFE7D;
    const BYTE kOrigB1[5]   = { 0xE9, 0x72, 0x11, 0x00, 0x00 };
    constexpr DWORD kSiteB2 = 0x004EFEDD;
    const BYTE kOrigB2[5]   = { 0xE9, 0x12, 0x11, 0x00, 0x00 };
    constexpr DWORD kSiteC  = 0x004EFE24;
    const BYTE kOrigC[5]    = { 0xE9, 0xCB, 0x11, 0x00, 0x00 };
    DWORD g_backItemUse     = 0x004F0FF4;                      // LABEL_143 (общий хвост успешного применения)
    // D: recvDBCraftEnter — первая инструкция ветки «ответ БД == 1» (`mov eax,[ebp-460h]`, 6 б).
    constexpr DWORD kSiteD = 0x0053EF2A;
    const BYTE kOrigD[6]   = { 0x8B, 0x85, 0xA0, 0xFB, 0xFF, 0xFF };
    DWORD g_backD          = 0x0053EF30;                       // mov cl,[ebp-44Fh] (уровень ремесла из эха)
    // E: sub_546C00 — после выдачи добычи копки (`mov edx,[ebp-16h] ; push edx ; call sub_532A90`, 9 б).
    constexpr DWORD kSiteE = 0x00546F8B;
    const BYTE kOrigE[9]   = { 0x8B, 0x55, 0xEA, 0x52, 0xE8, 0xFC, 0xBA, 0xFE, 0xFF };
    DWORD g_backE          = 0x00546F94;                       // add esp,4 ; test eax,eax (стоковый разбор IsItemCode)
    DWORD g_pIsItemCode    = Srv::kIsItemCode;                 // 0x532A90 — повтор замещённого вызова в трамплине
    // F: sub_456D90 — `call sub_54A050` звания 224 (5 б → call переходника).
    constexpr DWORD kSiteF = 0x00456F45;
    const BYTE kOrigF[5]   = { 0xE8, 0x06, 0x31, 0x0F, 0x00 };
    // G: CharItemPicking — разбор кода «звания за подбор» (`mov eax,[ebp-560h]`, 6 б).
    constexpr DWORD kSiteG = 0x004D5CB8;
    const BYTE kOrigG[6]   = { 0x8B, 0x85, 0xA0, 0xFA, 0xFF, 0xFF };
    DWORD g_backG          = 0x004D5CBE;                       // mov [ebp-5F4h],eax

    // ── соседи (только сверка) ───────────────────────────────────────────────────────────────────────────────────────
    const BYTE kNbA1[9]  = { 0x83, 0xF8, 0x04, 0x0F, 0x85, 0x86, 0x01, 0x00, 0x00 };   // 0x4CB8E3 cmp eax,4 (MAP_TYPE) ; jne
    const BYTE kNbA2[10] = { 0x0F, 0xBF, 0x4D, 0x10, 0x0F, 0xBF, 0x55, 0x08, 0x3B, 0xCA }; // 0x4CB8EC убийца != жертва
    const BYTE kNbA3[5]  = { 0xE8, 0x66, 0xC6, 0xF9, 0xFF };                           // 0x4CBA15 call AddRoseWarPoint 0x468080
    const BYTE kNbA4[5]  = { 0xE8, 0x0B, 0x15, 0x00, 0x00 };                           // 0x4CBA20 call sub_4CCF30
    const BYTE kNbB1[5]  = { 0xE8, 0x23, 0x05, 0xF9, 0xFF };                           // 0x4EFE78 call sub_4803A0
    const BYTE kNbB2[5]  = { 0xE8, 0x43, 0x10, 0xF9, 0xFF };                           // 0x4EFED8 call sub_480F20
    const BYTE kNbB3[14] = { 0x66, 0x8B, 0x85, 0x60, 0xFE, 0xFF, 0xFF, 0x50,           // 0x4EFE64 mov ax,[ebp-1A0h] ; push eax
                             0x8B, 0x8D, 0x78, 0xFD, 0xFF, 0xFF };                     //          mov ecx,[ebp-288h]
    const BYTE kNbC1[6]  = { 0x81, 0xF9, 0x0E, 0x01, 0x00, 0x00 };                     // 0x4EFD34 cmp ecx,10Eh (зажим 270)
    const BYTE kNbC2[5]  = { 0xE8, 0xCC, 0x2A, 0xFD, 0xFF };                           // 0x4EFE1F call sub_4C28F0 (5456)
    const BYTE kNbC3[7]  = { 0x0F, 0xBF, 0x88, 0xAE, 0x01, 0x00, 0x00 };               // 0x4EFD10 movsx ecx,[eax+1AEh]
    const BYTE kNbD1[12] = { 0x0F, 0xBE, 0x8D, 0xA8, 0xFB, 0xFF, 0xFF, 0x83, 0xF9, 0x01, 0x74, 0x46 }; // 0x53EED8 ответ БД == 1
    const BYTE kNbD2[6]  = { 0x8A, 0x8D, 0xB1, 0xFB, 0xFF, 0xFF };                     // 0x53EF30 mov cl,[ebp-44Fh]
    const BYTE kNbE1[5]  = { 0xE8, 0x05, 0xFE, 0xEB, 0xFF };                           // 0x546F86 call sub_406D90
    const BYTE kNbE2[7]  = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x74, 0x36 };               // 0x546F94 add esp,4 ; test ; je
    const BYTE kNbF1[5]  = { 0x68, 0xE0, 0x00, 0x00, 0x00 };                           // 0x456F33 push 0E0h (звание 224)
    const BYTE kNbG1[18] = { 0x8B, 0x8D, 0x10, 0xFA, 0xFF, 0xFF, 0x8B, 0x51, 0x04,     // 0x4D5CA5 ecx = [[[ebp-5F0h]+4]+34h]
                             0x8B, 0x4A, 0x34, 0xE8, 0x9A, 0x43, 0x07, 0x00, 0xEB };   //          call sub_54A050 ; jmp
    const BYTE kNbG2[6]  = { 0x89, 0x85, 0x0C, 0xFA, 0xFF, 0xFF };                     // 0x4D5CBE mov [ebp-5F4h],eax
    const BYTE kNbAcc[6] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x38 };                     // 0x54A050 пролог накопителя

    // ── данные GameServer ─────────────────────────────────────────────────────────────────────────────────────────────
    constexpr DWORD kVaFameCount = 0x007DFFD4;                 // i32: записей FameInfo (как P25)
    constexpr DWORD kVaFameTable = 0x007DFFD8;                 // ptr: FameInfo, запись 96 б
    constexpr int   kFameRec     = 96;
    constexpr int   kFameEnabled = 2;                          // +2 b  кол. 1 «включено»
    constexpr int   kFameGoal    = 4;                          // +4 i32 кол. 3 порог
    constexpr int   kFameAccum   = 92;                         // +92 b кол. 45 универсальный накопитель
    constexpr int   kOffUserIdx  = 0x174;                      // CUser: UserIndex
    constexpr int   kOffCharSlot = 0x18C;                      // CUser: слот персонажа
    constexpr int   kOffWareSlots= 0x1AE;                      // CUser: ёмкость склада (i16; миснейм «MaxWeight»)
    constexpr int   kOffCellX    = 0x54E6;                     // CUser: серверная клетка X (добыча копки ложится сюда, 0x546D07)
    constexpr int   kOffCellZ    = 0x54E8;                     // CUser: серверная клетка Z
    constexpr int   kOffThreadMap= 0x4950;                     // CThreadRun: индекс карты (SendCharDead 0x4CB8CC)

    // ── звания ────────────────────────────────────────────────────────────────────────────────────────────────────────
    enum : short
    {
        kTWar1 = 187, kTWar2 = 188, kTWar3 = 189, kTSkillReset = 190, kTWarehouse = 191, kTPotion = 192,
        kTHero1 = 193, kTHero2 = 194, kTHero3 = 195, kTLegend1 = 196, kTLegend2 = 197, kTLegend3 = 198,
        kTRuins = 199, kTShip = 200, kTOasis = 201, kTPet = 202, kTSowel = 203, kTTicket = 205, kTPetStock = 224
    };
    // Звания, у которых порог задаёт ini (в данных числа нет); значения по умолчанию — ПРЕДЛОЖЕНИЕ, решает владелец.
    struct Goal { short id; int def; int value; };
    Goal g_goals[] =
    {
        { kTSkillReset, 10, 10 }, { kTPotion, 300, 300 }, { kTRuins, 100, 100 }, { kTShip, 100, 100 },
        { kTOasis, 200, 200 }, { kTPet, 50, 50 }, { kTSowel, 100, 100 }, { kTTicket, 500, 500 },
    };
    LONG g_notReady[256] = {};                                 // 1 — журнал 110 по званию уже записан
    LONG g_goalWarned[256] = {};                               // 1 — расхождение порога ini/FameInfo уже в логе

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1, выданы координатором: P88 — 109–111).
    constexpr BYTE kKindGrant    = 109;
    constexpr BYTE kKindNotReady = 110;
    constexpr BYTE kKindFault    = 111;

    // ── настройки ─────────────────────────────────────────────────────────────────────────────────────────────────────
    bool g_war = true, g_reset = true, g_resetPartial = true, g_ware = true, g_craft = true, g_dig = true, g_sowel = true;
    bool g_pet = true, g_pick = true, g_logGrant = true;
    int  g_wareMax = 270;                                      // сток: зажим 0x10E (0x4EFD34)

    struct Range { int lo, hi; };
    Range g_potion[64];  int g_potionN = 0;                    // PotionCodes
    Range g_ticket[64];  int g_ticketN = 0;                    // TicketCodes
    Range g_hero[1024];  int g_heroN = 0;                      // HeroCodesFile (грейд 3)
    Range g_legend[1024]; int g_legendN = 0;                   // LegendCodesFile (грейд 4)

    struct Zone { int map, x, z, r; };                         // r < 0 — вся карта
    Zone g_zones[3][16]; int g_zoneN[3] = {};                  // 0 руины (199), 1 корабль (200), 2 оазис (201)

    // ── функции GameServer ────────────────────────────────────────────────────────────────────────────────────────────
    typedef char  (__thiscall *FnTitleCount)(void* userMng, short userNum, short title, int add, int extra);   // sub_54A050
    FnTitleCount const pTitleCount = (FnTitleCount)0x0054A050;
    typedef BYTE* (__thiscall *FnGetUser)(void* userMng, short userNum);                                    // sub_5324A0
    FnGetUser const pGetUser = (FnGetUser)Srv::kGetUser;
    typedef BOOL  (__cdecl *FnIsCode)(int code);                                                            // sub_532AE0
    FnIsCode const pIsSowel = (FnIsCode)Srv::kIsSowelCode;
    typedef void  (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);                                       // sub_569DF0
    FnSrvLog const pSrvLog = (FnSrvLog)Srv::kLog;

    P88_Stats g_stats = {};

    bool InRanges(const Range* r, int n, int code)
    {
        int a = 0, b = n - 1;
        while (a <= b)
        {
            const int m = (a + b) / 2;
            if (code < r[m].lo) { b = m - 1; } else if (code > r[m].hi) { a = m + 1; } else { return true; }
        }
        return false;
    }

    // Разбор «a-b;c;d» (разделители ; , пробел) в отсортированные диапазоны. Возврат: число диапазонов, −1 — ошибка.
    int ParseRanges(const wchar_t* s, Range* out, int cap)
    {
        int n = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L';' || *p == L',' || *p == L' ' || *p == L'\t') { ++p; }
            if (!*p) { break; }
            if (*p < L'0' || *p > L'9') { return -1; }
            int a = 0;
            while (*p >= L'0' && *p <= L'9') { a = a * 10 + (*p - L'0'); if (a > 10000000) { return -1; } ++p; }
            int b = a;
            if (*p == L'-')
            {
                ++p;
                if (*p < L'0' || *p > L'9') { return -1; }
                b = 0;
                while (*p >= L'0' && *p <= L'9') { b = b * 10 + (*p - L'0'); if (b > 10000000) { return -1; } ++p; }
            }
            if (*p && *p != L';' && *p != L',' && *p != L' ' && *p != L'\t') { return -1; }
            if (b < a || n >= cap) { return -1; }
            out[n].lo = a; out[n].hi = b; ++n;
        }
        for (int i = 1; i < n; ++i)                            // сортировка вставками по lo (списки короткие)
        {
            Range t = out[i]; int j = i - 1;
            while (j >= 0 && out[j].lo > t.lo) { out[j + 1] = out[j]; --j; }
            out[j + 1] = t;
        }
        return n;
    }

    // Разбор зон «map[:x:z:r]» через ';'. map — индекс карты потока; без клетки — вся карта. Возврат: число зон, −1 — ошибка.
    int ParseZones(const wchar_t* s, Zone* out, int cap)
    {
        int n = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L';' || *p == L' ' || *p == L'\t') { ++p; }
            if (!*p) { break; }
            int v[4] = { 0, 0, 0, -1 }; int k = 0;
            for (;;)
            {
                if (*p < L'0' || *p > L'9') { return -1; }
                int a = 0;
                while (*p >= L'0' && *p <= L'9') { a = a * 10 + (*p - L'0'); if (a > 100000) { return -1; } ++p; }
                if (k >= 4) { return -1; }
                v[k++] = a;
                if (*p == L':') { ++p; continue; }
                break;
            }
            if (*p && *p != L';' && *p != L' ' && *p != L'\t') { return -1; }
            if (k != 1 && k != 4) { return -1; }               // «карта» или «карта:x:z:радиус»
            if (n >= cap) { return -1; }
            out[n].map = v[0];
            if (k == 1) { out[n].x = out[n].z = 0; out[n].r = -1; }
            else        { out[n].x = v[1]; out[n].z = v[2]; out[n].r = v[3]; }
            ++n;
        }
        return n;
    }

    // Файл диапазонов (формат announce_codes.txt): строки «код» / «начало-конец», '#'/';' — комментарий.
    int LoadRangesFile(const wchar_t* rel, Range* out, int cap)
    {
        wchar_t path[MAX_PATH];
        wsprintfW(path, L"%s%s", Config::BaseDir(), rel);
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Log::Line(L"    P88: ! файл кодов не найден: %s", path); return 0; }
        const DWORD size = GetFileSize(h, nullptr);
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, size + 1);
        if (!buf) { CloseHandle(h); return 0; }
        DWORD got = 0;
        ReadFile(h, buf, size, &got, nullptr);
        buf[got] = 0;
        CloseHandle(h);
        int n = 0;
        char* p = buf;
        while (*p && n < cap)
        {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { ++p; }
            if (!*p) { break; }
            if (*p == '#' || *p == ';') { while (*p && *p != '\n') { ++p; } continue; }
            const int lo = atoi(p);
            while (*p && *p != '-' && *p != '\r' && *p != '\n') { ++p; }
            const int hi = (*p == '-') ? atoi(p + 1) : lo;
            while (*p && *p != '\n') { ++p; }
            if (lo > 0 && hi >= lo && (n == 0 || lo > out[n - 1].hi)) { out[n].lo = lo; out[n].hi = hi; ++n; }
        }
        HeapFree(GetProcessHeap(), 0, buf);
        Log::Line(L"    P88: файл кодов %s — диапазонов %d", path, n);
        return n;
    }

    BYTE* FameRow(int id)
    {
        const int count = *(const int*)kVaFameCount;
        BYTE* table = *(BYTE**)kVaFameTable;
        if (!table || id < 0 || id >= count || count > 4096) { return nullptr; }
        return table + kFameRec * id;
    }

    // Пороги из ini → FameInfo[id].+4 в памяти (таблицу сервер грузит после установки патчей; повтор дешёвый).
    void ApplyGoals()
    {
        for (int i = 0; i < ARRAYSIZE(g_goals); ++i)
        {
            BYTE* row = FameRow(g_goals[i].id);
            if (!row) { continue; }
            int* goal = (int*)(row + kFameGoal);
            if (*goal != g_goals[i].value)
            {
                if (InterlockedExchange(&g_goalWarned[g_goals[i].id], 1) == 0)
                {
                    pSrvLog(Srv::kLogCatOperator, "P88 TitleEvents: title %d goal FameInfo %d -> ini %d", g_goals[i].id, *goal,
                            g_goals[i].value);
                }
                *goal = g_goals[i].value;
            }
        }
    }

    void Journal(BYTE kind, const BYTE* user, int userNum, int title, int v1, int v2, const char* text)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.userNum = (short)userNum;
        e.ip = userNum >= 0 ? P47_PeerIpv4(userNum) : 0;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIdx);
                e.charSlot  = user[kOffCharSlot];
                AcJournal::CopyName(e, user + Srv::kOffCharName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = title;             // item_code: звание
        e.v[1] = v1;                // value1:    прибавка / код предмета (по виду)
        e.v[2] = v2;                // value2:    площадка (1…8)
        AcJournal::CopyText(e, text);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    const char* SiteName(int site)
    {
        static const char* const k[] = { "?", "war", "reset", "reset2", "warehouse", "craft", "dig", "pet", "pickup" };
        return (site >= 0 && site < ARRAYSIZE(k)) ? k[site] : "?";
    }

    // Прибавка к званию через стоковый накопитель. Возврат: 1 — звание выдано этим вызовом.
    int Count(void* userMng, int userNum, short title, int add, int site, int detail)
    {
        if (!userMng || add <= 0) { return 0; }
        ApplyGoals();
        const BYTE* row = FameRow(title);
        if (!row || row[kFameEnabled] == 0 || row[kFameAccum] != 1)
        {
            InterlockedIncrement(&g_stats.notReady);
            if (InterlockedExchange(&g_notReady[title & 0xFF], 1) == 0)
            {
                char t[64];
                _snprintf_s(t, sizeof(t), _TRUNCATE, "P88 title %d FameInfo %s (site %s)", title,
                            !row ? "missing" : row[kFameEnabled] == 0 ? "disabled" : "not accumulator", SiteName(site));
                Journal(kKindNotReady, nullptr, userNum, title, add, site, t);
                pSrvLog(Srv::kLogCatOperator, "P88 TitleEvents: %s - event NOT counted (deploy FameInfo.txt)", t);
            }
            return 0;
        }
        BYTE* user = pGetUser(userMng, (short)userNum);
        if (!user) { return 0; }
        if (P21_FameOwned(user, title)) { InterlockedIncrement(&g_stats.owned); return 0; }
        pTitleCount(userMng, (short)userNum, title, add, 0);
        InterlockedIncrement(&g_stats.counted);
        if (!P21_FameOwned(user, title)) { return 0; }
        InterlockedIncrement(&g_stats.granted);
        if (g_logGrant)
        {
            char t[64];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P88 title %d granted (site %s, add %d, %d)", title, SiteName(site), add, detail);
            Journal(kKindGrant, user, userNum, title, detail, site, t);
            char name[24] = "?";
            __try { lstrcpynA(name, (const char*)(user + Srv::kOffCharName), 20); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            pSrvLog(Srv::kLogCatOperator, "P88 TitleEvents: UserNum %d (%s) title %d granted by %s (add %d, detail %d)",
                    userNum, name, title, SiteName(site), add, detail);
        }
        return 1;
    }

    bool InZones(int which, int map, int x, int z)
    {
        for (int i = 0; i < g_zoneN[which]; ++i)
        {
            const Zone& q = g_zones[which][i];
            if (q.map != map) { continue; }
            if (q.r < 0) { return true; }
            if (abs(x - q.x) <= q.r && abs(z - q.z) <= q.r) { return true; }
        }
        return false;
    }

    void* UserMngOfThreadOwner(BYTE* owner)                    // [[owner+4]+34h] — userMng (как у стоковых вызовов звания)
    {
        BYTE* thread = *(BYTE**)(owner + 4);
        return *(void**)(thread + 0x34);
    }
}

// ── C-часть трамплинов A…E, G: site — номер площадки, ebp — кадр стокового обработчика. ─────────────────────────────────
extern "C" void __stdcall P88_OnSite(int site, BYTE* ebp)
{
    __try
    {
        switch (site)
        {
        case 1:   // A SendCharDead: this [ebp-464h] = userMng, убийца [ebp+10h], жертва [ebp+8]
        {
            if (!g_war) { break; }
            void* mng = *(void**)(ebp - 0x464);
            const int killer = *(const short*)(ebp + 0x10);
            const int victim = *(const short*)(ebp + 0x08);
            InterlockedIncrement(&g_stats.warKills);
            Count(mng, killer, kTWar1, 1, site, victim);
            Count(mng, killer, kTWar2, 1, site, victim);
            Count(mng, killer, kTWar3, 1, site, victim);
            break;
        }
        case 2:   // B1 полный сброс навыков: this [ebp-288h], цель [ebp-1A0h]
        case 3:   // B2 частичный сброс
        {
            if (!g_reset || (site == 3 && !g_resetPartial)) { break; }
            InterlockedIncrement(&g_stats.resets);
            Count(*(void**)(ebp - 0x288), *(const short*)(ebp - 0x1A0), kTSkillReset, 1, site, site == 2 ? 1 : 2);
            break;
        }
        case 4:   // C расширение склада: CUser [ebp-14Ch] +0x1AE после зажима
        {
            if (!g_ware) { break; }
            const BYTE* user = *(BYTE**)(ebp - 0x14C);
            const int slots = user ? *(const short*)(user + kOffWareSlots) : 0;
            InterlockedIncrement(&g_stats.wareExpands);
            if (slots >= g_wareMax) { Count(*(void**)(ebp - 0x288), *(const short*)(ebp - 0x1A0), kTWarehouse, 1, site, slots); }
            break;
        }
        case 5:   // D ответ БД 2666 == 1: эхо 576 б [ebp-458h]; продукт +18 (код), статус +74
        {
            if (!g_craft) { break; }
            const BYTE* echo = ebp - 0x458;
            const int code = *(const int*)(echo + 18);
            const BYTE status = echo[74];
            if (status != 1 || code <= 0) { InterlockedIncrement(&g_stats.craftNoProduct); break; }
            InterlockedIncrement(&g_stats.crafts);
            void* mng = UserMngOfThreadOwner(*(BYTE**)(ebp - 0x4F0));
            const int num = *(const short*)(ebp + 8);
            if (InRanges(g_potion, g_potionN, code)) { Count(mng, num, kTPotion, 1, site, code); }
            if (InRanges(g_hero, g_heroN, code))
            {
                Count(mng, num, kTHero1, 1, site, code); Count(mng, num, kTHero2, 1, site, code); Count(mng, num, kTHero3, 1, site, code);
            }
            if (InRanges(g_legend, g_legendN, code))
            {
                Count(mng, num, kTLegend1, 1, site, code); Count(mng, num, kTLegend2, 1, site, code); Count(mng, num, kTLegend3, 1, site, code);
            }
            break;
        }
        case 6:   // E находка копки: this [ebp-20h] = userMng, userNum [ebp-8], код [ebp-16h], CUser [ebp-1Ch]
        {
            if (!g_dig) { break; }
            void* mng = *(void**)(ebp - 0x20);
            const int num  = *(const short*)(ebp - 8);
            const int code = *(const int*)(ebp - 0x16);
            const BYTE* user = *(BYTE**)(ebp - 0x1C);
            if (!user || code <= 0) { break; }
            InterlockedIncrement(&g_stats.digFinds);
            const int map = *(const int*)(*(BYTE**)((BYTE*)mng + 4) + kOffThreadMap);
            const int x = *(const short*)(user + kOffCellX), z = *(const short*)(user + kOffCellZ);
            const int detail = map * 1000000 + x * 1000 + z;
            if (InZones(0, map, x, z)) { Count(mng, num, kTRuins, 1, site, detail); }
            if (InZones(1, map, x, z)) { Count(mng, num, kTShip, 1, site, detail); }
            if (InZones(2, map, x, z)) { Count(mng, num, kTOasis, 1, site, detail); }
            if (g_sowel && pIsSowel(code)) { Count(mng, num, kTSowel, 1, site, code); }
            break;
        }
        case 8:   // G подбор: код [ebp-560h], количество +9 записи, получатель [ebp-5B4h]
        {
            if (!g_pick) { break; }
            const int code = *(const int*)(ebp - 0x560);
            if (!InRanges(g_ticket, g_ticketN, code)) { break; }
            int cnt = *(const int*)(ebp - 0x560 + 9);
            if (cnt < 1) { cnt = 1; }
            InterlockedIncrement(&g_stats.tickets);
            Count(UserMngOfThreadOwner(*(BYTE**)(ebp - 0x5F0)), *(const short*)(ebp - 0x5B4), kTTicket, cnt, site, code);
            break;
        }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        char t[48];
        _snprintf_s(t, sizeof(t), _TRUNCATE, "P88 fault at site %s", SiteName(site));
        Journal(kKindFault, nullptr, -1, 0, 0, site, t);
    }
}

// ── F: переходник вместо `call sub_54A050` звания 224 (sub_456D90, повышение уровня питомца). __fastcall = __thiscall стороны
//   вызова (ecx = userMng, edx не используется, 4 аргумента в стеке, чистит вызываемый). Сток зовётся первым и без изменений.
extern "C" char __fastcall P88_PetLevel(void* userMng, void* /*edx*/, int userNum, int title, int level, int extra)
{
    const char r = pTitleCount(userMng, (short)userNum, (short)title, level, extra);
    if (!g_pet || (short)title != kTPetStock) { return r; }
    __try
    {
        InterlockedIncrement(&g_stats.petLevels);
        Count(userMng, (short)userNum, kTPet, 1, 7, level);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        Journal(kKindFault, nullptr, (short)userNum, kTPet, level, 7, "P88 fault at site pet");
    }
    return r;
}

extern "C" __declspec(dllexport) void __stdcall P88_GetStats(P88_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Трамплины: регистры и флаги сохраняются целиком, затем повтор замещённых инструкций и возврат.
    __declspec(naked) void TrampA()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  1
            call  P88_OnSite
            popad
            popfd
            lea   ecx, [ebp-0x458]                 // замещённое: тело 6730
            jmp   dword ptr [g_backA]              // 0x4CBA20
        }
    }
    __declspec(naked) void TrampB1()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  2
            call  P88_OnSite
            popad
            popfd
            jmp   dword ptr [g_backItemUse]        // замещённое: jmp 0x4F0FF4
        }
    }
    __declspec(naked) void TrampB2()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  3
            call  P88_OnSite
            popad
            popfd
            jmp   dword ptr [g_backItemUse]
        }
    }
    __declspec(naked) void TrampC()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  4
            call  P88_OnSite
            popad
            popfd
            jmp   dword ptr [g_backItemUse]
        }
    }
    __declspec(naked) void TrampD()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  5
            call  P88_OnSite
            popad
            popfd
            mov   eax, dword ptr [ebp-0x460]       // замещённое: CUser
            jmp   dword ptr [g_backD]              // 0x53EF30
        }
    }
    __declspec(naked) void TrampE()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  6
            call  P88_OnSite
            popad
            popfd
            mov   edx, dword ptr [ebp-0x16]        // замещённое: код находки
            push  edx
            call  dword ptr [g_pIsItemCode]        // замещённое: call sub_532A90 (cdecl, стек чистит 0x546F94)
            jmp   dword ptr [g_backE]              // 0x546F94 add esp,4
        }
    }
    __declspec(naked) void TrampG()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            push  8
            call  P88_OnSite
            popad
            popfd
            mov   eax, dword ptr [ebp-0x560]       // замещённое: код подобранного
            jmp   dword ptr [g_backG]              // 0x4D5CBE
        }
    }

    // Строка ini с диапазонами кодов; ошибка разбора → значение по умолчанию.
    int ReadRanges(const wchar_t* key, const wchar_t* def, Range* out, int cap)
    {
        wchar_t s[512] = L"";
        Config::GetStr(kSec, key, def, s, ARRAYSIZE(s));
        int n = ParseRanges(s, out, cap);
        if (n < 0)
        {
            Log::Line(L"    P88: %s=\"%s\" не разобран — взято \"%s\"", key, s, def);
            n = ParseRanges(def, out, cap);
        }
        return n < 0 ? 0 : n;
    }

    int ReadZones(const wchar_t* key, const wchar_t* def, Zone* out, int cap)
    {
        wchar_t s[512] = L"";
        Config::GetStr(kSec, key, def, s, ARRAYSIZE(s));
        int n = ParseZones(s, out, cap);
        if (n < 0)
        {
            Log::Line(L"    P88: %s=\"%s\" не разобран — взято \"%s\"", key, s, def);
            n = ParseZones(def, out, cap);
        }
        return n < 0 ? 0 : n;
    }
}

PatchResult P88_TitleEvents()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_war          = Config::GetBool(kSec, L"WarKill", true);
    g_reset        = Config::GetBool(kSec, L"SkillReset", true);
    g_resetPartial = Config::GetBool(kSec, L"SkillResetPartial", true);
    g_ware         = Config::GetBool(kSec, L"WarehouseMax", true);
    g_wareMax      = Config::GetInt (kSec, L"WarehouseMaxSlots", 270);
    if (g_wareMax < 30 || g_wareMax > 270) { Log::Line(L"    P88: WarehouseMaxSlots=%d вне 30..270 — взято 270", g_wareMax); g_wareMax = 270; }
    g_craft        = Config::GetBool(kSec, L"Craft", true);
    g_dig          = Config::GetBool(kSec, L"Dig", true);
    g_sowel        = Config::GetBool(kSec, L"DigSowel", true);
    g_pet          = Config::GetBool(kSec, L"PetLevel", true);
    g_pick         = Config::GetBool(kSec, L"Pickup", true);
    g_logGrant     = Config::GetBool(kSec, L"LogGrant", true);

    for (int i = 0; i < ARRAYSIZE(g_goals); ++i)
    {
        wchar_t key[32];
        wsprintfW(key, L"Threshold%d", g_goals[i].id);
        int v = Config::GetInt(kSec, key, g_goals[i].def);
        if (v < 1 || v > 1000000) { Log::Line(L"    P88: %s=%d вне 1..1000000 — взято %d", key, v, g_goals[i].def); v = g_goals[i].def; }
        g_goals[i].value = v;
    }

    g_potionN = ReadRanges(L"PotionCodes", L"20594-20603;20620-20623", g_potion, ARRAYSIZE(g_potion));
    g_ticketN = ReadRanges(L"TicketCodes", L"79382", g_ticket, ARRAYSIZE(g_ticket));
    {
        wchar_t rel[MAX_PATH];
        Config::GetStr(kSec, L"HeroCodesFile", L"ConfigSet\\title_hero_p88.txt", rel, ARRAYSIZE(rel));
        g_heroN = rel[0] ? LoadRangesFile(rel, g_hero, ARRAYSIZE(g_hero)) : 0;
        Config::GetStr(kSec, L"LegendCodesFile", L"ConfigSet\\title_legend_p88.txt", rel, ARRAYSIZE(rel));
        g_legendN = rel[0] ? LoadRangesFile(rel, g_legend, ARRAYSIZE(g_legend)) : 0;
    }
    g_zoneN[0] = ReadZones(L"ZonesRuins",     L"1:352:436:20;1:153:286:20", g_zones[0], 16);
    g_zoneN[1] = ReadZones(L"ZonesShipwreck", L"6:350:277:20",              g_zones[1], 16);
    g_zoneN[2] = ReadZones(L"ZonesOasis",     L"13",                        g_zones[2], 16);

    const Site sites[] =
    {
        { kSiteA,  kOrigA,  sizeof(kOrigA)  }, { 0x004CB8E3, kNbA1, sizeof(kNbA1) }, { 0x004CB8EC, kNbA2, sizeof(kNbA2) },
        { 0x004CBA15, kNbA3, sizeof(kNbA3) },  { g_backA, kNbA4, sizeof(kNbA4) },
        { kSiteB1, kOrigB1, sizeof(kOrigB1) }, { kSiteB2, kOrigB2, sizeof(kOrigB2) }, { 0x004EFE78, kNbB1, sizeof(kNbB1) },
        { 0x004EFED8, kNbB2, sizeof(kNbB2) },  { 0x004EFE64, kNbB3, sizeof(kNbB3) },
        { kSiteC,  kOrigC,  sizeof(kOrigC)  }, { 0x004EFD34, kNbC1, sizeof(kNbC1) }, { 0x004EFE1F, kNbC2, sizeof(kNbC2) },
        { 0x004EFD10, kNbC3, sizeof(kNbC3) },
        { kSiteD,  kOrigD,  sizeof(kOrigD)  }, { 0x0053EED8, kNbD1, sizeof(kNbD1) }, { g_backD, kNbD2, sizeof(kNbD2) },
        { kSiteE,  kOrigE,  sizeof(kOrigE)  }, { 0x00546F86, kNbE1, sizeof(kNbE1) }, { g_backE, kNbE2, sizeof(kNbE2) },
        { kSiteF,  kOrigF,  sizeof(kOrigF)  }, { 0x00456F33, kNbF1, sizeof(kNbF1) },
        { kSiteG,  kOrigG,  sizeof(kOrigG)  }, { 0x004D5CA5, kNbG1, sizeof(kNbG1) }, { g_backG, kNbG2, sizeof(kNbG2) },
        { 0x0054A050, kNbAcc, sizeof(kNbAcc) },
    };
    if (!VerifyAllSites(L"P88", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (g_war   && !Hook::WriteJmp(kSiteA, &TrampA, sizeof(kOrigA)))   { return PatchResult::Failed; }
    if (g_reset && !Hook::WriteJmp(kSiteB1, &TrampB1, sizeof(kOrigB1))) { return PatchResult::Failed; }
    if (g_reset && g_resetPartial && !Hook::WriteJmp(kSiteB2, &TrampB2, sizeof(kOrigB2))) { return PatchResult::Failed; }
    if (g_ware  && !Hook::WriteJmp(kSiteC, &TrampC, sizeof(kOrigC)))   { return PatchResult::Failed; }
    if (g_craft && !Hook::WriteJmp(kSiteD, &TrampD, sizeof(kOrigD)))   { return PatchResult::Failed; }
    if (g_dig   && !Hook::WriteJmp(kSiteE, &TrampE, sizeof(kOrigE)))   { return PatchResult::Failed; }
    if (g_pet   && !Hook::WriteCall(kSiteF, (const void*)&P88_PetLevel, sizeof(kOrigF))) { return PatchResult::Failed; }
    if (g_pick  && !Hook::WriteJmp(kSiteG, &TrampG, sizeof(kOrigG)))   { return PatchResult::Failed; }

    Log::Line(L"    P88: звания 187–205 по событиям: война %d (A 0x%08X), сброс навыков %d/%d (B 0x%08X/0x%08X), склад %d до %d "
              L"(C 0x%08X), ремесло %d (D 0x%08X: зелий %d, герой %d, легенда %d диап.), копка %d/камни %d (E 0x%08X: зоны %d/%d/%d), "
              L"питомец %d (F 0x%08X), билеты %d (G 0x%08X, %d диап.)",
              g_war, kSiteA, g_reset, g_resetPartial, kSiteB1, kSiteB2, g_ware, g_wareMax, kSiteC, g_craft, kSiteD, g_potionN,
              g_heroN, g_legendN, g_dig, g_sowel, kSiteE, g_zoneN[0], g_zoneN[1], g_zoneN[2], g_pet, kSiteF, g_pick, kSiteG, g_ticketN);
    Log::Line(L"    P88: пороги из ini (ПРЕДЛОЖЕНИЕ, решает владелец): 190=%d 192=%d 199=%d 200=%d 201=%d 202=%d 203=%d 205=%d; "
              L"журнал ac.other 109/110/111", g_goals[0].value, g_goals[1].value, g_goals[2].value, g_goals[3].value,
              g_goals[4].value, g_goals[5].value, g_goals[6].value, g_goals[7].value);
    if (g_craft && (g_heroN == 0 || g_legendN == 0))
    {
        Log::Line(L"    P88: ! нет файла кодов героя/легенды — звания 193–198 не засчитываются (tools/gen_title_grades_p88.py)");
    }
    return PatchResult::Applied;
}
