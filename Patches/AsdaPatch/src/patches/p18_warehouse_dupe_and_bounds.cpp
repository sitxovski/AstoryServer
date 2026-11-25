// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P18 — СКЛАД (StoreHouse): дюп, чтение чужой памяти, мёртвые проверки границ,
//        немые отказы. ★ НАША ПРАВКА, не перенос чужой.
//
//  Источник дефектов: Reports/warehouse_net_server.md §12 (D2, D4, D9, D13,
//  D15, D18). КАЖДЫЙ дефект перепроверен заново по декомпилу
//  RE/ida/server_work/GameServer.c И по дизассемблеру ЖИВОГО образа
//  \\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\GameServer\GameServer.exe
//  (все 14 площадок байт-в-байт совпали с нашим образом).
//
//  Каждый дефект — ОТДЕЛЬНЫЙ ключ ini, чтобы включать по одному.
//
//  ── D4  FixKeepingDupe ─ ДЮП. CharItemKeeping@0x5094A0 ──────────────────────
//  Ветка-ловушка, пишущая в лог "CharItemKeeping(11)" (условие: ячейка лотка 45,
//  количество 8, на складе стопка того же предмета ровно 8 ([ebp-0x84] == 8 — НЕ «тип 8»),
//  флаги +0x51AC..+0x51AF == 1 и +0x51B0 == 0 — поля ОБЪЕКТА ПОТОКА КАРТЫ CThread
//  (*(CUserManager+4)), а не CUser; ★ 15.10.2026: это ЗАКЛАДКА — шаг 5 кодовой
//  комбинации, взводящей затирание 550 слотов в RunProcess 10024; её обезвреживает P72
//  (hidden-wipe-disarm-p72.md), D4 здесь закрывает только дюп через DB 2029),
//  ОТПРАВЛЯЕТ клиенту 5009 с кодом 5 (= отказ) и НЕ ДЕЛАЕТ return:
//      0050A6E6  E8 05 82 FB FF   call 0x4C28F0     ; 5009, код 5 — «отказ»
//      0050A6EB  E9 C6 02 00 00   jmp  0x50A9B6     ; ← общий ХВОСТ, а не выход!
//  Все остальные отказы этой функции выглядят иначе — `call 0x4C28F0` + `jmp
//  0x50ACBB` (эпилог), например @0x50A74D/0x50A752 и @0x50AA18/0x50AA1D.
//  Из-за пропущенного return операция после «отказа» ДОХОДИТ до DB-запроса 2029,
//  предмет реально уезжает в БД, а клиент уже получил «неудача» и предмет из
//  лотка не убрал. Дальше приходит второй 5009 с кодом 1 (успех) — рассинхрон
//  инвентаря и склада, рабочий вектор на дублирование.
//  ЛЕЧИМ: площадка 0x50A6E6 (5 б, ровно call) -> jmp на трамплин, трамплин
//  выполняет тот же call и уходит в ЭПИЛОГ 0x50ACBB — то есть делает ровно тот
//  `return`, которого не хватает. Штатный путь не затронут: 0x50A6EB (куда ведут
//  восемь `jne` при НЕвыполнении условия ловушки) остаётся нетронутым.
//
//  ── D2  FixPageRange4050 ─ ЧТЕНИЕ ЧУЖОЙ ПАМЯТИ ──────────────────────────────
//  Send_ClientStoreHouseItemInfo@0x529DA0 (опкод 4050), номер страницы — 5-й байт
//  расшифрованного блока, читается БЕЗ ЗНАКА и без проверки снизу:
//      00529EEC  0F B6 4D FC      movzx ecx, byte [ebp-4]   ; pageNo 0..255
//      00529EF0  6B C9 1E         imul  ecx, ecx, 30        ; v8 = 30*pageNo
//      00529EFF  83 EA 1E         sub   edx, 30             ; v15 = v8-30
//      00529F12  39 8D 0C F9..    cmp   v8, [CUser+0x1AE]   ; ёмкость склада
//      00529F18  7E 40            jle   продолжить
//  При pageNo == 0: v8 = 0, условие `0 <= ёмкость` ИСТИННО, цикл идёт от i = −30
//  до −1 и читает CUser+6342−1710 … CUser+6341, после чего отправляет прочитанное
//  клиенту пакетом 4051. Это утечка 1710 байт памяти CUser по запросу клиента.
//  Сверху защита есть и так: pageNo >= 10 даёт 30*pageNo > ёмкости (потолок 270).
//  ЛЕЧИМ: переписываем 25 байт 0x529EEC..0x529F04 так, что `sub` идёт по тому же
//  регистру и его знак сразу проверяется — при pageNo == 0 уходим в СУЩЕСТВУЮЩУЮ
//  ветку отказа "SlotCount Error" @0x529F1A. Байт в байт, без трамплина.
//
//  ── D18 FixReply4050OnReject ─ НЕМОЙ ОТКАЗ 4050 ─────────────────────────────
//  Та самая ветка отказа @0x529F1A только пишет строку в лог и уходит в эпилог:
//      00529F55  E9 49 01 00 00   jmp 0x52A0A3   ; эпилог, НИ ОДНОГО пакета
//  Клиент на 4050 ставит флаг «запрос в полёте» (CWarehouseWnd+22328, байт 0) и
//  снимает его ТОЛЬКО по приходу 4052. Без ответа флаг остаётся навсегда: склад
//  (вклад/забор/другие вкладки) заблокирован до перезахода в игру.
//  ЛЕЧИМ: тот же 5-байтовый jmp направляем не в эпилог, а на 0x52A083 — это
//  штатная отправка 4052 (конец страницы, 0 предметов) в хвосте УСПЕШНОГО пути,
//  которая сама затем падает в эпилог 0x52A0A3. Никакого нового кода: клиент
//  получает ровно тот пакет, что и при пустой странице, и снимает флаг.
//
//  ── D9  FixDbSlotBounds ─ МЁРТВАЯ ПРОВЕРКА ГРАНИЦ ───────────────────────────
//  Три загрузчика контейнеров из ответа БД написаны с `&&` вместо `||`:
//      if ( slot < 0 && slot > N ) лог; else memcpy(CUser + 57*slot + BASE, ...);
//  Условие невыполнимо ⇒ проверки НЕТ ВООБЩЕ, и любое значение slot из строки БД
//  пишет 57 байт по адресу CUser + 57*slot + BASE. В ассемблере это:
//      cmp  slot, 0 ; jge  memcpy   ← при slot >= 0 верхняя граница не смотрится
//      cmp  slot, N ; jg   лог
//  ЛЕЧИМ: `jge memcpy` -> `jl лог`. Тогда получается ровно `slot < 0 || slot > N`.
//  Площадки (все три — соседние функции одного семейства):
//    0x5296AC  recvDBShellInvenItemInfo@0x5295E0        N=30,  база 0x4BC
//    0x529826  recvDBSpendCellobInvenItemInfo@0x529700  N=60,  база 0xB6A
//    0x52994F  recvDBStoreHouseItemInfo@0x529880        N=270, база 0x18C6  ← СКЛАД
//  Больше таких площадок в образе нет: `grep "< 0 && .* > [0-9]"` по всему
//  GameServer.c даёт ровно эти три строки (112747 / 112786 / 112823).
//
//  ── D13 FixMoveCapacity ─ ПРЕДМЕТ В НЕВИДИМОЙ ЯЧЕЙКЕ ────────────────────────
//  CharItemMove@0x4CE3E0 (опкод 5000) сверяет ячейку склада с ЖЁСТКИМ 270:
//      004CE7FD  81 FA 0E 01 00 00  cmp edx, 270   ; источник, тип 5
//      004CE9D1  81 F9 0E 01 00 00  cmp ecx, 270   ; приёмник, тип 5
//  270 — это потолок массива (9 вкладок × 30), а не ёмкость КОНКРЕТНОГО игрока
//  (CUser+0x1AE, i16 — то самое поле, по которому 4050 отдаёт страницы). Игрок с
//  ёмкостью 30 может переложить предмет в ячейку 269: запись ляжет в массив, но
//  Send_ClientStoreHouseItemInfo её никогда не отдаст (страница > ёмкости), и
//  предмет становится невидимым и недоступным.
//  ЛЕЧИМ: обе площадки -> трамплины, которые берут CUser штатной sub_5324A0 и
//  сравнивают ячейку с CUser+0x1AE. Страховка: если CUser не нашёлся или поле
//  вне 1..270 — сравниваем со стоковыми 270 (поведение как было).
//
//  ── D15 FixMoveSilentReject ─ МОЛЧАНИЕ СЕРВЕРА ──────────────────────────────
//  В CharItemMove шесть переходов ведут на 0x4D12BB — это `xor eax,eax` СРАЗУ
//  перед эпилогом, то есть `return 0` БЕЗ ЕДИНОГО ПАКЕТА. Попадают туда все
//  неподдержанные сочетания тип-источника/тип-приёмника:
//      0x4CF0EC  источник 3, приёмник не 1 и не 2
//      0x4CFC99  источник 1, приёмник не 1 и не 3   ← «инвентарь -> склад» (D15)
//      0x4D09BE  источник 2, приёмник не 2 и не 3   ← «второй мешок -> склад» (D15)
//      0x4D0E4F  источник 4, приёмник не 4
//      0x4D0E5E  источник вообще не 1..5
//      0x4D1271  источник 5, приёмник не 5          ← «склад -> куда угодно ещё»
//  Клиент, отправляя 5000, ставит UI-замок (sub_922033(g_pUIManager,1)) и снимает
//  его только по приходу 5001. Молчание сервера = намертво залипший интерфейс.
//  ЛЕЧИМ: все шесть переходов направляем в LABEL_220 — штатный отказ этой же
//  функции «5001, код 2» (копия компилятора @0x4CF186; для 0x4D1271, где на
//  переход отведено всего 2 байта, есть своя копия LABEL_220 прямо следом,
//  @0x4D1273, поэтому там достаточно `jmp` на следующий байт).
//  Никакая ранее РАБОТАВШАЯ операция не затрагивается: во все шесть точек
//  попадают только сочетания, которые сервер и так отказывался выполнять.
//
//  ── D17 близость к NPC-кладовщику — НЕ РЕАЛИЗУЕТСЯ, и это осознанно ─────────
//  Подтверждено (см. .md документа патча): ни в одном из четырёх обработчиков
//  склада нет обращения к позиции/карте/NPC. НО закрывать это нельзя: в игре
//  есть штатный «свиток вызова склада» (Property == 0x70, GameServer.c:92692),
//  который по замыслу открывает склад ИЗ ЛЮБОЙ ТОЧКИ МИРА и на сервере не делает
//  вообще ничего — окно открывает клиент. Проверка близости к кладовщику сломала
//  бы этот предмет. Решение — за владельцем; здесь дефект только задокументирован.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P18_WarehouseDupeAndBounds";

    // ── адреса, к которым обращается код трамплинов ─────────────────────────
    DWORD g_pSendPacket   = 0x004C28F0;   // отправка пакета клиенту (thiscall, чистит стек сам)
    DWORD g_pKeepEpilogue = 0x0050ACBB;   // эпилог CharItemKeeping (тот же, куда уходят её отказы)
    DWORD g_pGetUser      = 0x005324A0;   // sub_5324A0(CUserManager* ecx, __int16 idx) -> CUser*
    DWORD g_pMoveRetSrc   = 0x004CE803;   // возврат D13-src: `jl 0x4CE850`
    DWORD g_pMoveRetDst   = 0x004CE9D7;   // возврат D13-dst: `jl 0x4CEA24`

    // ── D4 ──────────────────────────────────────────────────────────────────
    const DWORD kD4Site = 0x0050A6E6;
    const BYTE  kD4Orig[5] = { 0xE8, 0x05, 0x82, 0xFB, 0xFF };   // call 0x4C28F0

    // Вход по jmp: ecx = this, шесть аргументов 5009 уже на стеке — трогать нельзя.
    __declspec(naked) void KeepingDupeReturnTrampoline()
    {
        __asm
        {
            call  dword ptr [g_pSendPacket]     // тот же самый call, что и был
            jmp   dword ptr [g_pKeepEpilogue]   // ← недостающий return
        }
    }

    // ── D2 ──────────────────────────────────────────────────────────────────
    const DWORD kD2Site = 0x00529EEC;
    const BYTE  kD2Orig[25] =
    {
        0x0F, 0xB6, 0x4D, 0xFC,                     // movzx ecx, byte [ebp-4]      ; pageNo
        0x6B, 0xC9, 0x1E,                           // imul  ecx, ecx, 30
        0x89, 0x8D, 0x0C, 0xF9, 0xFF, 0xFF,         // mov   [ebp-0x6F4], ecx       ; v8
        0x8B, 0x95, 0x0C, 0xF9, 0xFF, 0xFF,         // mov   edx, [ebp-0x6F4]
        0x83, 0xEA, 0x1E,                           // sub   edx, 30                ; v15
        0x89, 0x55, 0xF4                            // mov   [ebp-0x0C], edx
    };
    const BYTE  kD2New[25] =
    {
        0x0F, 0xB6, 0x4D, 0xFC,                     // movzx ecx, byte [ebp-4]
        0x6B, 0xC9, 0x1E,                           // imul  ecx, ecx, 30
        0x89, 0x8D, 0x0C, 0xF9, 0xFF, 0xFF,         // mov   [ebp-0x6F4], ecx
        0x83, 0xE9, 0x1E,                           // sub   ecx, 30        ← флаги
        0x89, 0x4D, 0xF4,                           // mov   [ebp-0x0C], ecx  (mov флаги не трогает)
        0x78, 0x19,                                 // js    0x529F1A       ← pageNo == 0 -> отказ
        0x90, 0x90, 0x90, 0x90                      // nop x4 (добивка до 25 б)
    };

    // ── D18 ─────────────────────────────────────────────────────────────────
    const DWORD kD18Site = 0x00529F55;
    const BYTE  kD18Orig[5] = { 0xE9, 0x49, 0x01, 0x00, 0x00 };  // jmp 0x52A0A3 (эпилог)
    const BYTE  kD18New [5] = { 0xE9, 0x29, 0x01, 0x00, 0x00 };  // jmp 0x52A083 (отправка 4052)

    // ── D9 ──────────────────────────────────────────────────────────────────
    struct Flip { DWORD va; BYTE orig[2]; BYTE next[2]; const wchar_t* what; };
    const Flip kD9[] =
    {
        { 0x005296AC, { 0x7D, 0x06 }, { 0x7C, 0x27 }, L"recvDBShellInvenItemInfo (граница 30)" },
        { 0x00529826, { 0x7D, 0x06 }, { 0x7C, 0x27 }, L"recvDBSpendCellobInvenItemInfo (граница 60)" },
        { 0x0052994F, { 0x7D, 0x09 }, { 0x7C, 0x2A }, L"recvDBStoreHouseItemInfo (СКЛАД, граница 270)" },
    };

    // ── D13 ─────────────────────────────────────────────────────────────────
    const DWORD kD13SrcSite = 0x004CE7FD;
    const BYTE  kD13SrcOrig[6] = { 0x81, 0xFA, 0x0E, 0x01, 0x00, 0x00 };   // cmp edx, 270
    const DWORD kD13DstSite = 0x004CE9D1;
    const BYTE  kD13DstOrig[6] = { 0x81, 0xF9, 0x0E, 0x01, 0x00, 0x00 };   // cmp ecx, 270

    // Вход по jmp изнутри CharItemMove: ebp — кадр CharItemMove,
    // [ebp+8] = userIndex (i16), [ebp-0x2D8] = CUserManager* (this).
    // Задача: выставить флаги ровно так, как их выставил бы `cmp ячейка, ёмкость`,
    // и вернуться на следующий за площадкой `jl`. `pop` флаги не трогает.
    __declspec(naked) void MoveSrcBoundTrampoline()      // edx = ячейка-источник
    {
        __asm
        {
            push  eax
            push  ecx
            push  edx                               // сохранили ячейку
            movzx eax, word ptr [ebp+8]             // userIndex
            push  eax                               // аргумент sub_5324A0 (чистит сам)
            mov   ecx, dword ptr [ebp-0x2D8]        // CUserManager*
            call  dword ptr [g_pGetUser]
            test  eax, eax
            jz    SrcFallback
            movsx eax, word ptr [eax+0x1AE]         // ёмкость склада в ячейках
            test  eax, eax
            jle   SrcFallback
            cmp   eax, 0x10E
            jle   SrcHave
        SrcFallback:
            mov   eax, 0x10E                        // сток: потолок массива 270
        SrcHave:
            pop   edx                               // вернули ячейку
            cmp   edx, eax                          // ← флаги для `jl` по адресу возврата
            pop   ecx
            pop   eax
            jmp   dword ptr [g_pMoveRetSrc]
        }
    }

    __declspec(naked) void MoveDstBoundTrampoline()      // ecx = ячейка-приёмник
    {
        __asm
        {
            push  eax
            push  edx
            push  ecx                               // сохранили ячейку
            movzx eax, word ptr [ebp+8]
            push  eax
            mov   ecx, dword ptr [ebp-0x2D8]
            call  dword ptr [g_pGetUser]
            test  eax, eax
            jz    DstFallback
            movsx eax, word ptr [eax+0x1AE]
            test  eax, eax
            jle   DstFallback
            cmp   eax, 0x10E
            jle   DstHave
        DstFallback:
            mov   eax, 0x10E
        DstHave:
            pop   ecx                               // вернули ячейку
            cmp   ecx, eax
            pop   edx
            pop   eax
            jmp   dword ptr [g_pMoveRetDst]
        }
    }

    // ── D15 ─────────────────────────────────────────────────────────────────
    struct Silent { DWORD va; int len; BYTE orig[6]; BYTE next[6]; const wchar_t* what; };
    const Silent kD15[] =
    {
        { 0x004CF0EC, 5, { 0xE9, 0xCA, 0x21, 0x00, 0x00, 0 }, { 0xE9, 0x95, 0x00, 0x00, 0x00, 0 },
          L"источник 3, приёмник не 1/2" },
        { 0x004CFC99, 5, { 0xE9, 0x1D, 0x16, 0x00, 0x00, 0 }, { 0xE9, 0xE8, 0xF4, 0xFF, 0xFF, 0 },
          L"источник 1 (инвентарь), приёмник не 1/3 — сюда попадает приёмник 5 (склад)" },
        { 0x004D09BE, 5, { 0xE9, 0xF8, 0x08, 0x00, 0x00, 0 }, { 0xE9, 0xC3, 0xE7, 0xFF, 0xFF, 0 },
          L"источник 2, приёмник не 2/3 — сюда попадает приёмник 5 (склад)" },
        { 0x004D0E4F, 5, { 0xE9, 0x67, 0x04, 0x00, 0x00, 0 }, { 0xE9, 0x32, 0xE3, 0xFF, 0xFF, 0 },
          L"источник 4, приёмник не 4" },
        { 0x004D0E5E, 6, { 0x0F, 0x85, 0x57, 0x04, 0x00, 0x00 }, { 0x0F, 0x85, 0x22, 0xE3, 0xFF, 0xFF },
          L"источник не 1..5" },
        { 0x004D1271, 2, { 0xEB, 0x48, 0, 0, 0, 0 }, { 0xEB, 0x00, 0, 0, 0, 0 },
          L"источник 5 (склад), приёмник не 5" },
    };

    // Ставит одну байтовую площадку со сверкой. Возвращает false при несовпадении/ошибке.
    bool PutBytes(const wchar_t* tag, DWORD va, const BYTE* orig, const BYTE* next, SIZE_T len)
    {
        const Site s = { va, orig, len };
        if (!VerifyAllSites(tag, &s, 1)) { return false; }
        return Hook::WriteBytes(va, next, len);
    }
}

PatchResult P18_WarehouseDupeAndBounds()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const bool d4  = Config::GetBool(kSec, L"FixKeepingDupe",      true);
    const bool d2  = Config::GetBool(kSec, L"FixPageRange4050",    true);
    const bool d18 = Config::GetBool(kSec, L"FixReply4050OnReject", true);
    const bool d9  = Config::GetBool(kSec, L"FixDbSlotBounds",     true);
    const bool d13 = Config::GetBool(kSec, L"FixMoveCapacity",     true);
    const bool d15 = Config::GetBool(kSec, L"FixMoveSilentReject", true);

    // ── Сверяем ВСЕ включённые площадки ДО первой записи. Частично поставленный
    //    патч хуже неповставленного, поэтому либо всё, либо ничего.
    Site check[16];
    int  n = 0;
    if (d4)  { check[n].va = kD4Site;  check[n].orig = kD4Orig;  check[n].len = sizeof(kD4Orig);  ++n; }
    if (d2)  { check[n].va = kD2Site;  check[n].orig = kD2Orig;  check[n].len = sizeof(kD2Orig);  ++n; }
    if (d18) { check[n].va = kD18Site; check[n].orig = kD18Orig; check[n].len = sizeof(kD18Orig); ++n; }
    if (d9)  { for (const auto& f : kD9)  { check[n].va = f.va; check[n].orig = f.orig; check[n].len = 2; ++n; } }
    if (d13)
    {
        check[n].va = kD13SrcSite; check[n].orig = kD13SrcOrig; check[n].len = sizeof(kD13SrcOrig); ++n;
        check[n].va = kD13DstSite; check[n].orig = kD13DstOrig; check[n].len = sizeof(kD13DstOrig); ++n;
    }
    if (d15) { for (const auto& s : kD15) { check[n].va = s.va; check[n].orig = s.orig; check[n].len = (SIZE_T)s.len; ++n; } }

    if (n == 0)
    {
        Log::Line(L"    P18: все шесть исправлений выключены в ini — ставить нечего");
        return PatchResult::Disabled;
    }
    if (!VerifyAllSites(L"P18", check, n)) { return PatchResult::Mismatch; }

    // ── Запись ──────────────────────────────────────────────────────────────
    if (d4)
    {
        if (!Hook::WriteJmp(kD4Site, &KeepingDupeReturnTrampoline, sizeof(kD4Orig)))
        {
            return PatchResult::Failed;
        }
        Log::Line(L"    P18 D4  ДЮП: CharItemKeeping@0x5094A0 — ветка «CharItemKeeping(11)» слала "
                  L"5009 код 5 и БЕЗ return доходила до DB 2029; площадка 0x%08X -> трамплин "
                  L"0x%08X, выход в эпилог 0x%08X", kD4Site, (DWORD)&KeepingDupeReturnTrampoline,
                  g_pKeepEpilogue);
    }

    if (d2)
    {
        if (!PutBytes(L"P18/D2", kD2Site, kD2Orig, kD2New, sizeof(kD2Orig))) { return PatchResult::Failed; }
        Log::Line(L"    P18 D2  4050: страница 0 больше не читает CUser+6342-1710 и не отдаёт "
                  L"1710 б памяти клиенту — уходим в штатный отказ SlotCount Error (0x%08X)", 0x00529F1A);
    }

    if (d18)
    {
        if (!PutBytes(L"P18/D18", kD18Site, kD18Orig, kD18New, sizeof(kD18Orig))) { return PatchResult::Failed; }
        Log::Line(L"    P18 D18 4050: при отказе клиенту теперь уходит штатный 4052 (0x%08X) — "
                  L"снимается флаг «запрос в полёте», склад больше не залипает до перезахода", 0x0052A083);
    }

    if (d9)
    {
        for (const auto& f : kD9)
        {
            if (!PutBytes(L"P18/D9", f.va, f.orig, f.next, 2)) { return PatchResult::Failed; }
            Log::Line(L"    P18 D9  0x%08X: `slot<0 && slot>N` (никогда) -> `slot<0 || slot>N` — %s",
                      f.va, f.what);
        }
    }

    if (d13)
    {
        if (!Hook::WriteJmp(kD13SrcSite, &MoveSrcBoundTrampoline, sizeof(kD13SrcOrig))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(kD13DstSite, &MoveDstBoundTrampoline, sizeof(kD13DstOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P18 D13 CharItemMove: граница склада берётся из CUser+0x1AE (ёмкость игрока), "
                  L"а не из зашитых 270; площадки 0x%08X/0x%08X -> трамплины 0x%08X/0x%08X",
                  kD13SrcSite, kD13DstSite, (DWORD)&MoveSrcBoundTrampoline, (DWORD)&MoveDstBoundTrampoline);
    }

    if (d15)
    {
        for (const auto& s : kD15)
        {
            if (!PutBytes(L"P18/D15", s.va, s.orig, s.next, (SIZE_T)s.len)) { return PatchResult::Failed; }
            Log::Line(L"    P18 D15 0x%08X: немой `return 0` -> штатный отказ 5001 код 2 (LABEL_220) — %s",
                      s.va, s.what);
        }
    }

    return PatchResult::Applied;
}
