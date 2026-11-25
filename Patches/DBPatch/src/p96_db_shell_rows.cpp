// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P96 (DBManager) — [ПОРТ] 30.10.2026 СУМКА 60 ЯЧЕЕК: DBManager ОТДАЁТ GameServer ДО 60 СТРОК КОНТЕЙНЕРА 1.
//  Задача владельца 29.10 «инвентарь ×2» (сумка ShellInven 30 → 60). План: Reports/inventory_x2/PLAN.md §3.2,
//  разбор: Reports/inventory_x2/_research/db_dbm_other.md §2. Пара — AsdaPatch P96_InventoryX2 (GameServer,
//  Indun_GameServer, Ch2_GameServer): без него GameServer ячеек 30..59 не знает, а без ЭТОГО патча сумка из 31+
//  предмета приходит в GameServer обрезанной.
//
//  ── ЧТО В СТОКЕ ──────────────────────────────────────────────────────────────
//  Сумку (Plate 1) DBManager читает `EXEC UPPlateItem …,1` (ORDER BY Posx, без TOP; строка 57 б) и шлёт GameServer
//  пачками 2040 (заголовок Userindex 4 б + до 8 записей по 57 б), в конце 2041. Перед отправкой — обрезка:
//      if (rows > 30) { журнал "UPPlateItem SHELLINVEN_SLOTNUM …"; rows = 30; }
//  в двух функциях (DBManager.exe.c:16145 и :16369):
//      sub_422C20 Send_ShellInvenItem   (DB 0x7F7 DBM_SHELLINVENINFO_REQ)              — cmp/mov [ebp-0x3CE4], 1Eh
//      sub_423600 Send_AllInventoryItem (DB 0x7D1 вход 2001 и 0x829 портал 2089, Plate 1) — cmp/mov [ebp-0x738C], 1Eh
//  Строки идут по возрастанию Posx, поэтому при 31+ предмете молча отбрасываются ячейки 30..59: GameServer сочтёт их
//  пустыми, положит туда новый предмет, а INSERT в Joy1.dbo.Item упадёт на PK (Userindex, Charidx, Plate, Posx).
//
//  ── ПРАВКА ────────────────────────────────────────────────────────────────────
//  Четыре непосредственных операнда 0x1E → 0x3C (30 → 60), длина инструкций прежняя:
//      0x422E61  83 BD 1C C3 FF FF 1E        cmp dword ptr [ebp-0x3CE4], 1Eh   (+ 7E 36 jle 0x422EA0)
//      0x422E96  C7 85 1C C3 FF FF 1E 00 00 00  mov dword ptr [ebp-0x3CE4], 1Eh
//      0x423785  83 BD 74 8C FF FF 1E        cmp dword ptr [ebp-0x738C], 1Eh   (+ 7E 30 jle 0x4237BE)
//      0x4237B4  C7 85 74 8C FF FF 1E 00 00 00  mov dword ptr [ebp-0x738C], 1Eh
//  ★ ПО СИГНАТУРЕ, НЕ ПО АДРЕСУ: живой DBManager.exe (md5 3d05c835…) отличается от локальной копии разбора
//    (P17, строки IP, таблица импорта DBPatch). Каждая площадка ищется по 10-байтной сигнатуре во всём .text образа:
//    совпадение должно быть РОВНО ОДНО (0 или 2+ — Mismatch, ничего не пишется). Дополнительно сверяется связка
//    «cmp → jle → mov»: jle (7E xx) сразу за cmp и ведёт ровно за mov, mov ссылается на ту же ячейку кадра.
//    На 30.10 адреса в живом образе и в стоке (DBManager-Original.exe 4cec9b61…) совпадают с адресами выше; если
//    найденный адрес другой — в журнал пишется «сдвиг», патч ставится по найденному.
//  Ставится всё или ничего: сначала находятся и сверяются все четыре площадки, потом пишутся.
//
//  ── БУФЕРЫ (перепроверено по декомпилу и дизасму живого образа) ──────────────
//  • ответ процедуры: sub_422C20 v22 = 14 004 б ([ebp-0x36B8]), sub_423600 v32 = 14 000 б ([ebp-0x36B8]);
//    sub_4073D0 и так отказывает при rows × 57 ≥ 14 000. 60 × 57 = 3 420 < 14 000 (запас ×4).
//  • пачка 2040: v17/v27 = 472 б (memset 0x1D6), отправка при заполнении > 0x19D (413): максимум 4 + 8·57 = 460 ≤ 472 —
//    от числа строк не зависит; при 60 строках пачек 8 вместо 4, формат пачки и 2041 прежние.
//  • расходники (Plate 2) уже 60 — та же схема (0x423315/0x42334A, 0x423AEA/0x423B19, 3Ch), их не трогаем.
//  Протокол DB↔GS не меняется (old-server-protocol-compat).
//
//  Рантайм-кода у патча нет (чистая замена байт). Журнал DBManager «SHELLINVEN_SLOTNUM» остаётся — теперь он пишется
//  только при > 60 строк сумки (значит, в Item лежит лишнее — разбирать вручную).
//  Откат: ConfigSet\dbpatch.ini [P96_DbShellRows] Enabled=0 (сток: 30). ⚠ Перед этим убедиться, что в Joy1.dbo.Item нет
//  Описание: AstoryServer/Docs/DBManager/db-shell-rows-p96.md
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"

namespace
{
    const wchar_t* const S = L"P96_DbShellRows";

    constexpr DWORD kImageBase = 0x00400000;   // DBManager.exe (ImageBase, без ASLR) — тут же ищем .text
    constexpr int   kSigLen    = 10;           // длина сигнатуры площадки
    constexpr BYTE  kOld       = 0x1E;         // 30 строк сумки (сток)
    constexpr BYTE  kNew       = 0x3C;         // 60 строк сумки (как у расходников)

    // Описание одной площадки: имя для журнала, адрес в живом образе (справочно), сигнатура, смещение imm8 в ней.
    struct SigSite
    {
        const wchar_t* name;     // имя площадки для журнала
        DWORD          refVa;    // адрес в живом образе 3d05c835… (для сообщения «сдвиг»)
        BYTE           sig[kSigLen];   // байты сигнатуры (уникальны в .text)
        int            immOff;   // смещение байта 0x1E в сигнатуре
    };

    // Пары «cmp count,1Eh / jle / … / mov count,1Eh» в sub_422C20 и sub_423600 (Plate 1).
    const SigSite kSites[4] =
    {
        { L"422C20.cmp", 0x00422E61, { 0x83, 0xBD, 0x1C, 0xC3, 0xFF, 0xFF, 0x1E, 0x7E, 0x36, 0x0F }, 6 },   // cmp [ebp-0x3CE4],1Eh; jle +36h
        { L"422C20.mov", 0x00422E96, { 0xC7, 0x85, 0x1C, 0xC3, 0xFF, 0xFF, 0x1E, 0x00, 0x00, 0x00 }, 6 },   // mov [ebp-0x3CE4],1Eh
        { L"423600.cmp", 0x00423785, { 0x83, 0xBD, 0x74, 0x8C, 0xFF, 0xFF, 0x1E, 0x7E, 0x30, 0x0F }, 6 },   // cmp [ebp-0x738C],1Eh; jle +30h
        { L"423600.mov", 0x004237B4, { 0xC7, 0x85, 0x74, 0x8C, 0xFF, 0xFF, 0x1E, 0x00, 0x00, 0x00 }, 6 },   // mov [ebp-0x738C],1Eh
    };

    // Диапазон .text образа DBManager по заголовкам PE в памяти. false — заголовки не читаются.
    bool TextRange(DWORD& lo, DWORD& hi)
    {
        __try
        {
            const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)kImageBase;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) { return false; }
            const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(kImageBase + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) { return false; }
            const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                if (memcmp(s[i].Name, ".text", 5) == 0)
                {
                    lo = kImageBase + s[i].VirtualAddress;
                    hi = lo + (s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData);
                    return hi > lo;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return false;
    }

    // Число вхождений сигнатуры в [lo, hi); first — адрес первого вхождения (0, если нет).
    int CountSig(const BYTE* sig, DWORD lo, DWORD hi, DWORD& first)
    {
        int n = 0;
        first = 0;
        __try
        {
            for (DWORD a = lo; a + kSigLen <= hi; ++a)
            {
                if (*(const BYTE*)a != sig[0] || memcmp((const void*)a, sig, kSigLen) != 0) { continue; }
                if (n == 0) { first = a; }
                ++n;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return -1;
        }
        return n;
    }

    // Связка «cmp (7 б) → jle rel8 → … → mov (10 б)»: jle сразу за cmp и ведёт на инструкцию за mov;
    // ячейка кадра (disp32) у cmp и mov одна и та же. Защищает от совпадения сигнатуры в чужом месте.
    bool PairOk(DWORD cmpVa, DWORD movVa)
    {
        __try
        {
            const BYTE* c = (const BYTE*)cmpVa;
            const BYTE* m = (const BYTE*)movVa;
            if (c[7] != 0x7E) { return false; }                               // jle rel8
            const DWORD target = cmpVa + 9 + (DWORD)(int)(signed char)c[8];  // куда ведёт jle
            if (target != movVa + 10) { return false; }                       // ровно за mov
            if (movVa <= cmpVa || movVa - cmpVa > 0x60) { return false; }     // mov — в той же ветке, рядом
            return *(const DWORD*)(c + 2) == *(const DWORD*)(m + 2);          // одна ячейка [ebp-disp]
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}

PatchResult P96_DbShellRows()
{
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    DWORD lo = 0, hi = 0;
    if (!TextRange(lo, hi))
    {
        Log::Line(L"    P96db: ! заголовки PE образа 0x%08X не читаются — патч не ставится", kImageBase);
        return PatchResult::Mismatch;
    }

    // 1) найти и сверить все четыре площадки (до первой записи)
    DWORD found[4] = {};
    bool ok = true;
    for (int i = 0; i < 4; ++i)
    {
        const int n = CountSig(kSites[i].sig, lo, hi, found[i]);
        if (n != 1)
        {
            Log::Line(L"    P96db: ! площадка %s: сигнатура найдена %d раз в .text 0x%08X..0x%08X (нужно ровно 1)",
                      kSites[i].name, n, lo, hi);
            ok = false;
            continue;
        }
        if (found[i] != kSites[i].refVa)
        {
            Log::Line(L"    P96db: площадка %s найдена по сигнатуре на 0x%08X (сдвиг от 0x%08X живого образа 30.10)",
                      kSites[i].name, found[i], kSites[i].refVa);
        }
    }
    if (ok && (!PairOk(found[0], found[1]) || !PairOk(found[2], found[3])))
    {
        Log::Line(L"    P96db: ! связка cmp→jle→mov не сошлась (0x%08X/0x%08X, 0x%08X/0x%08X) — патч не ставится",
                  found[0], found[1], found[2], found[3]);
        ok = false;
    }
    if (!ok)
    {
        return PatchResult::Mismatch;
    }

    // 2) запись: 1Eh → 3Ch (WriteByteChecked ещё раз сверяет старый байт)
    bool wr = true;
    for (int i = 0; i < 4; ++i)
    {
        wr &= Hook::WriteByteChecked(found[i] + kSites[i].immOff, kOld, kNew);
    }
    if (!wr)
    {
        Log::Line(L"    P96db: ! ошибка записи хотя бы одной площадки — обрезка сумки может стоять частично");
        return PatchResult::Failed;
    }

    Log::Line(L"    P96db: 0x%08X/0x%08X (Send_ShellInvenItem 0x7F7) и 0x%08X/0x%08X (Send_AllInventoryItem 2001/2089): "
              L"обрезка строк сумки (Plate 1) 30 -> 60", found[0], found[1], found[2], found[3]);
    Log::Line(L"    P96db: пачки 2040 по 8 записей, буфер ответа 60x57 = 3420 < 14000; протокол не менялся");
    return PatchResult::Applied;
}
