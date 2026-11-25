// Copyright (c) 2026 @sitxovski (Discord)
// n22_quest_cells_ext.cpp — У NPC БОЛЬШЕ 10 ЯЧЕЕК «ВЫДАЁТ»/«ПРИНИМАЕТ» (таблица расширения), 31.10.2026, bug-quest-follow.
//
// [ИСПРАВЛЕНИЕ] предела стока (решение владельца 31.10: «позволить любым NPC быть неограниченными» вместо «обхода 44»).
//
// МЕХАНИЗМ СТОКА
//   Запись NPC `Quest\QuestNpcTable.Bin` — 1774 б: 10 ячеек «ВЫДАЁТ» по 86 б с +34 и 10 ячеек «ПРИНИМАЕТ» по 88 б с +894.
//   Ячейки читают ровно две функции (декомпил + скан образа на ссылки к указателю таблицы 0x47DAE4):
//     Process_Quest sub_420C10 (пакет 7103 ← клиентский 5041, сдача):  `cmp word [esp+2Ah], 9 / ja отказ` @0x420CB9, затем
//       копия записи на стек (esp+128h) и `movsx esi,[esp+2Ah]; imul esi,esi,58h; lea esi,[esp+esi+4A6h]` @0x420D3A →
//       `rep movsd` 22 dword ячейки в свой буфер;
//     Start_Quest sub_421020 (пакет 7101 ← клиентский 5043, выдача): `cmp word [esp+26h], 9` @0x4210AD, ячейка
//       `movsx esi,[esp+26h]; imul esi,esi,56h; lea esi,[esp+esi+142h]` @0x42112E → 21 dword + word.
//   Слот в пакете — u16 (старшее слово первого dword; клиент 5041/5043 — u16, GameServer пересылает без проверки), ответы
//   7102/7104 слота не содержат. Предел 10 — только эти две проверки и выборка из записи.
//
// ЧТО ДЕЛАЕМ (формат записи 1774 б не меняется)
//   Файл `Quest\QuestNpcTableExt.Bin` рядом с `QuestNpcTable.Bin` — ячейки со слотом 10…127 в ТОМ ЖЕ формате 88/86 б
//   (шапка 16 б "QNTX" / версия 1 / N / 0; запись 96 б: i16 npc, u8 вид 0 «ВЫДАЁТ» / 1 «ПРИНИМАЕТ», u8 0, u16 слот, u16 0,
//   ячейка 88 б). Генератор — `AstoryClient/Tools/asda_quest_cells_ext.py`, описание — `Reports/bug_quest_follow/
//   N22_PATCH_DESIGN.md`.
//   A/C: предел слота 9 → 127 (байт `imm8` проверки; отрицательные по-прежнему режет беззнаковый `ja`).
//   B/D: адрес ячейки — площадка: слот ≤ 9 → как в оригинале (копия записи на стеке); ≥ 10 → ячейка таблицы расширения;
//        такой ячейки нет → пустая ячейка (задание −1) → штатный путь «Exception» функции (ответ с кодом 100), как у битой ячейки.
//   Дальше обработка оригинальная: условия sub_41FD70, действие +35, награда, стадия.
//
// БЕЗОПАСНОСТЬ ВРЕЗКИ
//   • площадка выдаёт `esi` (то же, что писал исходный `lea`); портит `eax/ecx/edx` и флаги — сразу за площадкой исходный код
//     сам задаёт `ecx` (`mov ecx,16h/15h`), `edi` (`lea`), затем `eax`/`edx` (B: `mov eax,[esp+7Ch]`, `mov edx,[esp+7Ah]`;
//     D: `mov eax,[esp+72h]`, `lea edx,[esp+32h]`) — их прежние значения не читаются; `ebx/ebp/edi` не трогаем;
//   • `call` сдвигает `esp` на 4 — все смещения в площадке +4; вызов C-функции cdecl сохраняет `ebx/esi/edi/ebp`;
//   • длина площадок 15 б = `call rel32` (5) + 10 `nop`, границы инструкций не двигаются;
//   • смещения во встроенном ассемблере — только `#define` (урок N03: C++-константа в `[reg + имя]` = адрес переменной).
//   Таблица читается один раз при установке (DllMain): память — HeapAlloc без освобождения (указатели на ячейки живут весь
//   процесс), без std::vector и исключений. Путь — как у NpcServer: `.\Quest\…` от ТЕКУЩЕЙ папки процесса (загрузчик
//   sub_421360 открывает «.//Quest//QuestNpcTable.bin»; NpcServer текущую папку не меняет); копия у exe, если папки разные,
//   обязана совпадать байт в байт.
#include "Patches.h"
#include "../Config.h"
#include "../NpcApi.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const BYTE kOrigPqLimit[] = { 0x66, 0x83, 0x7C, 0x24, 0x2A, 0x09 };   // cmp word [esp+2Ah], 9
    const BYTE kOrigPqCell[]  = { 0x0F, 0xBF, 0x74, 0x24, 0x2A,             // movsx esi, word [esp+2Ah]
                                  0x6B, 0xF6, 0x58,                         // imul  esi, esi, 58h
                                  0x8D, 0xB4, 0x34, 0xA6, 0x04, 0x00, 0x00 };  // lea esi, [esp+esi+4A6h]
    const BYTE kOrigSqLimit[] = { 0x66, 0x83, 0x7C, 0x24, 0x26, 0x09 };   // cmp word [esp+26h], 9
    const BYTE kOrigSqCell[]  = { 0x0F, 0xBF, 0x74, 0x24, 0x26,             // movsx esi, word [esp+26h]
                                  0x6B, 0xF6, 0x56,                         // imul  esi, esi, 56h
                                  0x8D, 0xB4, 0x34, 0x42, 0x01, 0x00, 0x00 };  // lea esi, [esp+esi+142h]
    const Site kSites[] = {
        { Npc::Hooks::kQuestTakeLimit, kOrigPqLimit, sizeof(kOrigPqLimit) },
        { Npc::Hooks::kQuestTakeCell,  kOrigPqCell,  sizeof(kOrigPqCell)  },
        { Npc::Hooks::kQuestGiveLimit, kOrigSqLimit, sizeof(kOrigSqLimit) },
        { Npc::Hooks::kQuestGiveCell,  kOrigSqCell,  sizeof(kOrigSqCell)  },
    };
    // Новый предел слота. ПОЧЕМУ 127: проверка стока — `cmp word [esp+N], imm8` (6 б, `66 83 7C 24 N ib`), а imm8 знаково
    //   расширяется до слова: 0x7F = 127 — наибольшее положительное, которое влезает в ту же инструкцию (0x80…0xFF дали бы
    //   0xFF80…0xFFFF и пропустили бы отрицательные слоты). На практике это «без ограничений» (у NPC 10 + 118 ячеек каждого
    //   списка). ДАЛЬШЕ расширять — только сменой инструкции на `cmp word [esp+N], imm16` (`66 81 7C 24 N iw`, 7 б — другая
    //   длина): нужна врезка на месте проверки, а не замена байта.
    const BYTE kSlotMax = 127;

    // Одна ячейка таблицы расширения.
    struct ExtCell
    {
        short npc;       // индекс записи NPC (= npcId)
        BYTE  kind;      // 0 «ВЫДАЁТ», 1 «ПРИНИМАЕТ»
        WORD  slot;      // 10…127
        BYTE  cell[88];  // ячейка в формате записи (у «ВЫДАЁТ» значимы 86 б)
    };
    ExtCell* g_cells = nullptr;                // заполняется один раз в N22_QuestCellsExt (HeapAlloc, не освобождается), дальше только читается
    DWORD    g_count = 0;
    BYTE g_emptyCell[88];                      // ячейки нет: задание −1 → штатный путь «Exception»

    // Ячейка (вид, npc, слот ≥ 10) — cdecl, вызывается из площадок. Возвращает указатель на 88/86 б ячейки.
    const BYTE* __cdecl N22CellExt(int kind, int npc, int slot)
    {
        for (DWORD i = 0; i < g_count; ++i)
        {
            const ExtCell& c = g_cells[i];
            if (c.kind == kind && c.npc == npc && c.slot == slot) { return c.cell; }
        }
        return g_emptyCell;
    }

    // ⚠ Смещения — только #define (см. шапку). Внутри площадки +4 на адрес возврата.
    #define PQ_NPC   2Ch     // Process_Quest: word [esp+28h] — индекс NPC
    #define PQ_SLOT  2Eh     // Process_Quest: word [esp+2Ah] — слот
    #define PQ_TAKE  4AAh    // Process_Quest: копия записи esp+128h + 894 (+894 + 88·k)
    #define SQ_NPC   28h     // Start_Quest:   word [esp+24h]
    #define SQ_SLOT  2Ah     // Start_Quest:   word [esp+26h]
    #define SQ_GIVE  146h    // Start_Quest:   копия записи esp+120h + 34 (+34 + 86·k)

    // Площадка B (Process_Quest, «ПРИНИМАЕТ»). Выход: esi = адрес ячейки 88 б.
    __declspec(naked) void TakeCellEsi()
    {
        __asm
        {
            movsx   ecx, word ptr [esp + PQ_SLOT]
            cmp     ecx, 9
            ja      ext
            imul    ecx, ecx, 58h
            lea     esi, [esp + ecx + PQ_TAKE]
            ret
        ext:
            movsx   eax, word ptr [esp + PQ_NPC]
            push    ecx                  // слот
            push    eax                  // npc
            push    1                    // вид «ПРИНИМАЕТ»
            call    N22CellExt
            add     esp, 0Ch
            mov     esi, eax
            ret
        }
    }

    // Площадка D (Start_Quest, «ВЫДАЁТ»). Выход: esi = адрес ячейки 86 б.
    __declspec(naked) void GiveCellEsi()
    {
        __asm
        {
            movsx   ecx, word ptr [esp + SQ_SLOT]
            cmp     ecx, 9
            ja      ext
            imul    ecx, ecx, 56h
            lea     esi, [esp + ecx + SQ_GIVE]
            ret
        ext:
            movsx   eax, word ptr [esp + SQ_NPC]
            push    ecx
            push    eax
            push    0                    // вид «ВЫДАЁТ»
            call    N22CellExt
            add     esp, 0Ch
            mov     esi, eax
            ret
        }
    }

    // Файл целиком в кучу процесса. nullptr — нет файла / ошибка размера или чтения (причина — в *why). Без исключений.
    BYTE* ReadAll(const wchar_t* path, DWORD& size, const wchar_t*& why)
    {
        size = 0;
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { why = L"нет файла"; return nullptr; }
        LARGE_INTEGER li = {};
        if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 64 * 1024 * 1024)
        {
            CloseHandle(h);
            why = L"ошибка размера файла (GetFileSizeEx, пусто или > 64 МБ)";
            return nullptr;
        }
        size = (DWORD)li.QuadPart;
        BYTE* b = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
        DWORD got = 0;
        const BOOL ok = b && ReadFile(h, b, size, &got, nullptr) && got == size;
        CloseHandle(h);
        if (!ok)
        {
            if (b) { HeapFree(GetProcessHeap(), 0, b); }
            why = L"ошибка чтения";
            return nullptr;
        }
        return b;
    }

    // Число записей таблицы, как его считает загрузчик NpcServer sub_421360: размер файла / размер записи. −1 — нет файла.
    long long Records(const wchar_t* path, DWORD recSize)
    {
        WIN32_FILE_ATTRIBUTE_DATA fa = {};
        if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) { return -1; }
        const unsigned long long sz = ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
        return (long long)(sz / recSize);
    }

    // Чтение и проверка таблицы. false — патч не ставится (сервер как сток), причина — в журнале.
    bool LoadTable()
    {
        // Путь как у NpcServer — от текущей папки процесса; рядом — копия у exe (Config::BaseDir), если папки разные.
        wchar_t cwd[MAX_PATH] = L"", path[MAX_PATH], exePath[MAX_PATH], qnt[MAX_PATH], ct[MAX_PATH];
        const DWORD cl = GetCurrentDirectoryW(MAX_PATH, cwd);
        if (cl == 0 || cl >= MAX_PATH)
        {
            Log::Line(L"    [ERR] N22 не установлен: текущая папка процесса не получена — сервер как сток");
            return false;
        }
        wsprintfW(path, L"%s\\Quest\\QuestNpcTableExt.Bin", cwd);
        wsprintfW(qnt, L"%s\\Quest\\QuestNpcTable.Bin", cwd);
        wsprintfW(ct, L"%s\\Quest\\ConditionTable.Bin", cwd);
        wsprintfW(exePath, L"%sQuest\\QuestNpcTableExt.Bin", Config::BaseDir());
        DWORD size = 0;
        const wchar_t* why = L"";
        BYTE* b = ReadAll(path, size, why);
        if (!b)
        {
            Log::Line(L"    [ERR] N22 не установлен: QuestNpcTableExt.Bin — %s (%s) — сервер как сток, слоты > 9 отклоняются "
                      L"(сдачи из таблицы расширения, напр. задание 96 у Эллосы, не пройдут)", why, path);
            return false;
        }
        if (lstrcmpiW(path, exePath) != 0)
        {
            DWORD size2 = 0;
            const wchar_t* why2 = L"";
            BYTE* b2 = ReadAll(exePath, size2, why2);
            const bool same = b2 && size2 == size && memcmp(b, b2, size) == 0;
            if (b2) { HeapFree(GetProcessHeap(), 0, b2); }
            if (b2 && !same)
            {
                Log::Line(L"    [ERR] N22 не установлен: таблица у текущей папки (%s) и у exe (%s) РАЗНЫЕ — сервер как сток", path, exePath);
                HeapFree(GetProcessHeap(), 0, b);
                return false;
            }
        }
        const long long nNpc = Records(qnt, 1774), nCond = Records(ct, 146);
        bool good = size >= 16 && memcmp(b, "QNTX", 4) == 0;
        const DWORD ver = good ? *(const DWORD*)(b + 4) : 0, n = good ? *(const DWORD*)(b + 8) : 0;
        if (!good || ver != 1 || n > (size - 16) / 96 || size != 16 + 96 * n)   // n проверяется ДО умножения — переполнения нет
        {
            Log::Line(L"    [ERR] N22 не установлен: %s — шапка/версия/размер (версия %u, записей %u, размер %u; ждали QNTX, 1, 16 + 96·N)",
                      path, ver, n, size);
            HeapFree(GetProcessHeap(), 0, b);
            return false;
        }
        if (nNpc <= 0 || nCond <= 0)
        {
            Log::Line(L"    [ERR] N22 не установлен: нет QuestNpcTable.Bin / ConditionTable.Bin рядом с таблицей расширения (%s)", cwd);
            HeapFree(GetProcessHeap(), 0, b);
            return false;
        }
        ExtCell* cells = n ? (ExtCell*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ExtCell) * n) : nullptr;
        if (n && !cells)
        {
            Log::Line(L"    [ERR] N22 не установлен: нет памяти под %u ячеек", n);
            HeapFree(GetProcessHeap(), 0, b);
            return false;
        }
        for (DWORD i = 0; i < n; ++i)
        {
            const BYTE* r = b + 16 + 96 * i;
            ExtCell& c = cells[i];
            c.npc = *(const short*)r;
            c.kind = r[2];
            c.slot = *(const WORD*)(r + 4);
            memcpy(c.cell, r + 8, 88);
            bool bad = c.npc < 0 || c.npc >= nNpc || c.kind > 1 || r[3] != 0 || *(const WORD*)(r + 6) != 0 || c.slot < 10 || c.slot > kSlotMax;
            // Ключи условий: «ПРИНИМАЕТ» — 5 × i32 с +68, «ВЫДАЁТ» — с +66; каждый > 0 обязан быть номером записи ConditionTable.
            for (int k = 0; k < 5 && !bad; ++k)
            {
                const int key = *(const int*)(c.cell + (c.kind ? 68 : 66) + 4 * k);
                bad = key >= nCond;
            }
            for (DWORD j = 0; j < i && !bad; ++j)
            {
                bad = cells[j].kind == c.kind && cells[j].npc == c.npc && cells[j].slot == c.slot;
            }
            if (bad)
            {
                Log::Line(L"    [ERR] N22 не установлен: запись %u (npc %d вид %u слот %u) — вне формата, NPC ≥ %lld, ключ ≥ %lld "
                          L"или повтор", i, c.npc, c.kind, c.slot, nNpc, nCond);
                HeapFree(GetProcessHeap(), 0, cells);
                HeapFree(GetProcessHeap(), 0, b);
                return false;
            }
        }
        HeapFree(GetProcessHeap(), 0, b);
        g_cells = cells;
        g_count = n;
        return true;
    }
}

PatchResult N22_QuestCellsExt()
{
    if (!Config::GetBool(L"N22_QuestCellsExt", L"Enabled", true))
        return PatchResult::Disabled;

    if (!VerifyAllSites(L"N22_QuestCellsExt", kSites, ARRAYSIZE(kSites)))
        return PatchResult::Mismatch;

    memset(g_emptyCell, 0, sizeof(g_emptyCell));
    g_emptyCell[0] = 0xFF; g_emptyCell[1] = 0xFF;   // задание −1
    if (!LoadTable())
        return PatchResult::Failed;

    // Площадки ячеек — до пределов: пока предел 9, слот ≥ 10 до площадки не доходит.
    if (!Hook::WriteCall(Npc::Hooks::kQuestTakeCell, &TakeCellEsi, sizeof(kOrigPqCell)) ||
        !Hook::WriteCall(Npc::Hooks::kQuestGiveCell, &GiveCellEsi, sizeof(kOrigSqCell)) ||
        !Hook::WriteByteChecked(Npc::Hooks::kQuestTakeLimit + 5, 0x09, kSlotMax) ||
        !Hook::WriteByteChecked(Npc::Hooks::kQuestGiveLimit + 5, 0x09, kSlotMax))
        return PatchResult::Failed;

    int take = 0, give = 0;
    for (DWORD i = 0; i < g_count; ++i) { (g_cells[i].kind ? take : give) += 1; }
    Log::Line(L"    N22: ячейки NPC сверх 10 — таблица расширения: «ПРИНИМАЕТ» %d, «ВЫДАЁТ» %d (слоты 10…%u; 127 — предел imm8 "
              L"проверки стока, дальше — только сменой инструкции на imm16)", take, give, kSlotMax);
    for (DWORD i = 0; i < g_count; ++i)
    {
        const ExtCell& c = g_cells[i];
        Log::Line(L"      npc %d %s слот %u — задание %d", c.npc, c.kind ? L"ПРИНИМАЕТ" : L"ВЫДАЁТ", c.slot, *(const short*)c.cell);
    }
    return PatchResult::Applied;
}
