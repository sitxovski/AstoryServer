// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P19 — АУКЦИОН (CItemMediation / EXCHANGE_WIN 13000): запись за конец буфера
//        записей в обработчиках 9905 («купить») и 9909 («снять лот»).
//        ★ НАША ПРАВКА, не перенос чужой.
//
//  Отчёт-источник: Reports/npc_exchange_win_13000.md §9.6, дефекты S3 и S4.
//  ВСЁ ПЕРЕПРОВЕРЕНО ЗАНОВО по декомпилу RE/ida/server_work/GameServer.c И по
//  дизассемблеру ЖИВОГО образа
//  \\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\GameServer\GameServer.exe —
//  обе площадки и обе ветки отказа совпали в живом и в нашем образе байт в байт.
//
//  ── ОБЩИЙ МЕХАНИЗМ ОБОИХ ДЕФЕКТОВ ───────────────────────────────────────────
//  Оба обработчика разбирают хвост пакета как массив записей по 45 (0x2D) байт.
//  Длина пакета берётся из его же шапки (поле i16 по смещению +1) и проверяется
//  только на КРАТНОСТЬ: sub_5218A0@0x5218A0 требует (len-49) > 0 и
//  (len-49) % 45 == 0 — ВЕРХНЕГО предела нет вовсе, i16 допускает до 727 записей.
//  Тело цикла копирует запись в стековый буфер и ТОЛЬКО ПОТОМ сверяет счётчик:
//
//      memcpy(&Src[45*n], packet + i, 45);      // ← запись УЖЕ произошла
//      memcpy(&Send[off+15], &Src[45*n], 45);
//      off += 45;
//      if ( ++n > ПРЕДЕЛ ) { код отказа = 1; goto отказ; }
//
//  То есть проверка стоит на один шаг позже, чем нужно: запись с номером
//  «ПРЕДЕЛ+1» уже легла в память и лишь после этого сработал отказ.
//
//  ── S3 — 9905 «купить», Recv_TransAction_BuyItemReq@0x51AA10 ────────────────
//  Буфер: `char Src[364]` @ [ebp-0x58C]; сконструировано 8 записей по 45 = 360 б,
//  дальше по кадру лежат v19[8] @ [ebp-0x420], v20 @ [ebp-0x410], v21 @ [ebp-0x409],
//  v22 @ [ebp-0x408], v23 @ [ebp-0x404], v24 @ [ebp-0x400] и v25 @ [ebp-0x3FC].
//  Девятая запись пишет 45 байт по Src[360..404] = [ebp-0x424]..[ebp-0x3F7], то есть
//  затирает ВЕСЬ v19 (15-байтовая шапка, которая ниже уходит в пакет 9905 релею)
//  и все перечисленные счётчики. Живой код:
//      0051ACC5  6A 2D              push 0x2d
//      0051ACC7  8B 4D 0C           mov  ecx, [ebp+0xC]        ; пакет
//      ...       (memcpy в Src, memcpy в буфер отправки, off += 45)
//      0051AD16  8B 85 E0 F9 FF FF  mov  eax, [ebp-0x620]      ; счётчик записей
//      0051AD1C  83 C0 01           add  eax, 1
//      0051AD25  83 BD E0 F9 FF FF 08  cmp [ebp-0x620], 8      ; ← проверка ПОСЛЕ
//      0051AD2C  7E 09              jle  0x51AD37              ; продолжить цикл
//      0051AD2E  C6 45 EF 01        mov  byte [ebp-0x11], 1    ; код отказа 1
//      0051AD32  E9 38 05 00 00     jmp  0x51B26F              ; ветка ответа 9906
//
//  ── S4 — 9909 «снять лот», Recv_TransAction_DeleteItemReq@0x51E380 ──────────
//  То же самое, предел 10: `char Src[460]` @ [ebp-0x5EC], сконструировано 10×45 = 450 б,
//  следом v19[8] @ [ebp-0x420] и та же гряда счётчиков. Одиннадцатая запись пишет
//  Src[450..494] = [ebp-0x42A]..[ebp-0x3FE] — 35 байт ЗА концом объявленного массива.
//      0051E630  6A 2D              push 0x2d
//      0051E632  8B 4D 0C           mov  ecx, [ebp+0xC]
//      ...
//      0051E690  83 BD 9C F9 FF FF 0A  cmp [ebp-0x664], 0xA    ; ← проверка ПОСЛЕ
//      0051E697  7E 09              jle  0x51E6A2
//      0051E699  C6 45 EF 01        mov  byte [ebp-0x11], 1
//      0051E69D  E9 FC 04 00 00     jmp  0x51EB9E              ; ветка ответа 9910
//
//  ── ЧТО ИМЕННО ЛОМАЕТСЯ ─────────────────────────────────────────────────────
//  До сохранённого EIP запись НЕ достаёт (между Src и эпилогом ещё ~1 КБ локальных
//  переменных), так что это не захват управления, а УПРАВЛЯЕМАЯ ПОРЧА СОСЕДНИХ
//  ПЕРЕМЕННЫХ кадра: шапки запроса к ItemRelayServer и счётчиков цены/веса/
//  количества. Отправитель — клиент; штатный клиент шлёт максимум 8 и 10 записей
//  (ui_core.c / item_inventory.c), поэтому в норме путь недостижим, а собранный
//  вручную пакет достигает его гарантированно.
//
//  ── ЛЕЧЕНИЕ ─────────────────────────────────────────────────────────────────
//  Проверку переносим на ВХОД в тело цикла: площадка — первые 5 байт тела
//  (`push 0x2d` + `mov ecx,[ebp+0xC]`, ровно 5 байт) заменяется на jmp в трамплин.
//  Трамплин сверяет счётчик с тем же пределом и:
//    • счётчик < предела  -> выполняет те же две вытесненные команды и возвращается
//      на site+5, то есть цикл идёт как раньше, байт в байт;
//    • счётчик >= предела -> уходит на СУЩЕСТВУЮЩИЙ адрес отказа этой же функции
//      (0x51AD2E / 0x51E699) — тот самый `mov byte [ebp-0x11],1` + `jmp` в ветку,
//      которая отправляет клиенту штатный ответ 9906/9910 с кодом 1.
//  Никакого нового кода отказа не появляется, новых пакетов тоже.
//
//  ★ ШТАТНЫЙ ПУТЬ НЕ МЕНЯЕТСЯ. Ровно 8 (10) записей по-прежнему принимаются
//  полностью: после копирования восьмой (десятой) счётчик становится 8 (10), но
//  тело цикла в этот проход больше не выполняется — условие `i < len-1` уже ложно.
//  Новая проверка срабатывает только там, где сток и так возвращал отказ 1, —
//  разница лишь в том, что теперь отказ наступает ДО записи за буфер, а не после.
//
//  ── S1 (проверка целостности пакета) — ОПРОВЕРГНУТ, ПАТЧА НЕТ ───────────────
//  В отчёте §9.6 сказано, что sub_523F00@0x523F00 игнорирует результат memcmp и
//  всегда возвращает 1. Это верно для НАШЕГО образа RE/ida/server_work/GameServer.exe,
//  но НЕ для живого. Побайтовое сравнение двух образов (218 различий) показывает:
//      0x523F8B   наш EB 47 (jmp)  <->  живой 74 47 (je)
//      0x52400D   наш EB 41 (jmp)  <->  живой 74 41 (je)
//  и ещё пять таких же переворотов (0x526CFC, 0x526D3B, 0x526D7A, 0x526DB9, 0x526DEE).
//  В живом образе ветка несовпадения MD5 РАБОТАЕТ: наращивает счётчик нарушений у
//  CUser+8 и пишет в лог строку
//  "if( memcmp(szMD5, &pMsg[(HEADER_SIZE-1)+iSecretSize], MD5_SIZE) != 0 ) Command = %d"
//  (@0x598E10 / @0x598DC8), после чего обработчик возвращает 0.
//  Наш образ — сборка со снятой защитой, это её артефакт, а не дефект сервера.
//  Ключ ReportMd5GateState ничего не пишет в память: он лишь печатает в PatchLog
//  фактическое состояние обеих площадок, чтобы это можно было перепроверить на
//  живом процессе, не веря ни отчёту, ни этому комментарию.
//
//  ── S6 (исчерпание пула лотов) — ЭТО НЕ GameServer, ПАТЧА ЗДЕСЬ НЕТ ─────────
//  Дефект живёт в ItemRelayServer.exe и является дефектом ДАННЫХ, а не размера
//  пула. Разбор — в документе патча
//  AstoryServer/Docs/ItemRelayServer/lot-pool-exhaustion-s6.md.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P19_AuctionRecordBounds";

    // ── адреса, к которым обращается код трамплинов ─────────────────────────
    // (объявлены переменными, а не константами, потому что naked-ассемблер MSVC
    //  умеет `jmp dword ptr [метка]` только по адресу памяти)

    // 9905 «купить»: возврат в тело цикла и существующий адрес отказа.
    DWORD g_pBuyLoopBody   = 0x0051ACCA;   // site + 5: `add ecx, [ebp-0x20]`
    DWORD g_pBuyRefuse     = 0x0051AD2E;   // `mov byte [ebp-0x11],1` + `jmp 0x51B26F`

    // 9909 «снять лот»: то же самое.
    DWORD g_pDelLoopBody   = 0x0051E635;   // site + 5: `add ecx, [ebp-0x1C]`
    DWORD g_pDelRefuse     = 0x0051E699;   // `mov byte [ebp-0x11],1` + `jmp 0x51EB9E`

    // ── S3: площадка 9905 ───────────────────────────────────────────────────
    const DWORD kS3Site = 0x0051ACC5;
    // Сверяем 18 байт (всё начало тела цикла), а перезаписываем только первые 5.
    // Длинное окно нужно потому, что сама пятёрка `push 0x2d; mov ecx,[ebp+0xC]`
    // встречается в образе не один раз, и короткая сверка ничего не доказывает.
    const BYTE  kS3Orig[18] =
    {
        0x6A, 0x2D,                         // push 0x2d                 ; 45 байт
        0x8B, 0x4D, 0x0C,                   // mov  ecx, [ebp+0xC]       ; пакет
        0x03, 0x4D, 0xE0,                   // add  ecx, [ebp-0x20]      ; смещение i
        0x51,                               // push ecx
        0x8B, 0x95, 0xE0, 0xF9, 0xFF, 0xFF, // mov  edx, [ebp-0x620]     ; счётчик записей
        0x6B, 0xD2, 0x2D                    // imul edx, edx, 0x2d
    };
    // Ветка отказа — сверяем её тоже: трамплин прыгает ровно сюда.
    const DWORD kS3Refuse = 0x0051AD25;
    const BYTE  kS3RefuseOrig[13] =
    {
        0x83, 0xBD, 0xE0, 0xF9, 0xFF, 0xFF, 0x08,   // cmp  [ebp-0x620], 8
        0x7E, 0x09,                                 // jle  0x51AD37
        0xC6, 0x45, 0xEF, 0x01                      // mov  byte [ebp-0x11], 1  ← сюда
    };

    // ── S4: площадка 9909 ───────────────────────────────────────────────────
    const DWORD kS4Site = 0x0051E630;
    const BYTE  kS4Orig[18] =
    {
        0x6A, 0x2D,                         // push 0x2d
        0x8B, 0x4D, 0x0C,                   // mov  ecx, [ebp+0xC]
        0x03, 0x4D, 0xE4,                   // add  ecx, [ebp-0x1C]
        0x51,                               // push ecx
        0x8B, 0x95, 0x9C, 0xF9, 0xFF, 0xFF, // mov  edx, [ebp-0x664]     ; счётчик записей
        0x6B, 0xD2, 0x2D                    // imul edx, edx, 0x2d
    };
    const DWORD kS4Refuse = 0x0051E690;
    const BYTE  kS4RefuseOrig[13] =
    {
        0x83, 0xBD, 0x9C, 0xF9, 0xFF, 0xFF, 0x0A,   // cmp  [ebp-0x664], 0xA
        0x7E, 0x09,                                 // jle  0x51E6A2
        0xC6, 0x45, 0xEF, 0x01                      // mov  byte [ebp-0x11], 1  ← сюда
    };

    // ── S1: площадки MD5-проверки. ТОЛЬКО ЧТЕНИЕ, ничего не пишем. ──────────
    const DWORD kMd5Gate1 = 0x00523F8B;   // je 0x523FD4 — тело с секретом
    const DWORD kMd5Gate2 = 0x0052400D;   // je 0x524050 — тело без секрета

    // ── Трамплины ───────────────────────────────────────────────────────────
    // Вход по jmp с площадки: ebp — кадр обработчика, стек и все регистры ровно
    // такие же, как были бы на входе в тело цикла. Мы читаем только [ebp-...],
    // портим только флаги (их дальше никто не читает: следующая после вытесненных
    // команд инструкция — `add ecx, [ebp-...]`, она флаги сама и переопределяет).

    __declspec(naked) void BuyRecordBoundTrampoline()        // 9905, предел 8
    {
        __asm
        {
            cmp   dword ptr [ebp-0x620], 8      // записей уже скопировано
            jl    BuyOk                         // < 8 — место есть, копируем
            jmp   dword ptr [g_pBuyRefuse]      // >= 8 — штатный отказ 9906, код 1
        BuyOk:
            push  0x2d                          // ← вытесненные площадкой команды
            mov   ecx, dword ptr [ebp+0x0C]
            jmp   dword ptr [g_pBuyLoopBody]
        }
    }

    __declspec(naked) void DeleteRecordBoundTrampoline()     // 9909, предел 10
    {
        __asm
        {
            cmp   dword ptr [ebp-0x664], 0x0A
            jl    DelOk
            jmp   dword ptr [g_pDelRefuse]      // штатный отказ 9910, код 1
        DelOk:
            push  0x2d
            mov   ecx, dword ptr [ebp+0x0C]
            jmp   dword ptr [g_pDelLoopBody]
        }
    }

    // Печать фактического состояния MD5-гейта (S1). Ничего не изменяет.
    void ReportMd5Gate()
    {
        const BYTE b1 = *reinterpret_cast<const BYTE*>(kMd5Gate1);
        const BYTE b2 = *reinterpret_cast<const BYTE*>(kMd5Gate2);
        const bool on1 = (b1 == 0x74);   // je  = результат memcmp используется
        const bool on2 = (b2 == 0x74);
        Log::Line(L"    P19 S1  проверка целостности пакета (sub_523F00@0x523F00): "
                  L"0x%08X = %02X (%s), 0x%08X = %02X (%s)",
                  kMd5Gate1, b1, on1 ? L"РАБОТАЕТ" : (b1 == 0xEB ? L"СНЯТА (jmp)" : L"НЕОПОЗНАНО"),
                  kMd5Gate2, b2, on2 ? L"РАБОТАЕТ" : (b2 == 0xEB ? L"СНЯТА (jmp)" : L"НЕОПОЗНАНО"));
        if (on1 && on2)
        {
            Log::Line(L"    P19 S1  дефект S1 из отчёта ОПРОВЕРГНУТ для этого образа: "
                      L"обе ветки несовпадения MD5 на месте, патч не нужен и не ставится");
        }
        else
        {
            Log::Line(L"    P19 S1  ВНИМАНИЕ: образ собран со снятой проверкой подписи тела пакета. "
                      L"Это НЕ лечится здесь — нужен корректный образ GameServer.exe");
        }
    }
}

PatchResult P19_AuctionRecordBounds()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const bool s3   = Config::GetBool(kSec, L"FixBuyRecordBounds",    true);
    const bool s4   = Config::GetBool(kSec, L"FixDeleteRecordBounds", true);
    const bool s1rp = Config::GetBool(kSec, L"ReportMd5GateState",    true);

    // Диагностика S1 идёт первой и от сверки площадок не зависит: она ничего
    // не пишет в память и полезна даже тогда, когда сами правки не встали.
    if (s1rp) { ReportMd5Gate(); }

    if (!s3 && !s4)
    {
        Log::Line(L"    P19: оба исправления выключены в ini — ставить нечего");
        return s1rp ? PatchResult::Applied : PatchResult::Disabled;
    }

    // ── Сверяем ВСЕ включённые площадки ДО первой записи ────────────────────
    //    Частично поставленный патч хуже неповставленного: либо всё, либо ничего.
    Site check[4];
    int  n = 0;
    if (s3)
    {
        check[n].va = kS3Site;   check[n].orig = kS3Orig;       check[n].len = sizeof(kS3Orig);       ++n;
        check[n].va = kS3Refuse; check[n].orig = kS3RefuseOrig; check[n].len = sizeof(kS3RefuseOrig); ++n;
    }
    if (s4)
    {
        check[n].va = kS4Site;   check[n].orig = kS4Orig;       check[n].len = sizeof(kS4Orig);       ++n;
        check[n].va = kS4Refuse; check[n].orig = kS4RefuseOrig; check[n].len = sizeof(kS4RefuseOrig); ++n;
    }
    if (!VerifyAllSites(L"P19", check, n)) { return PatchResult::Mismatch; }

    // ── Запись ─────────────────────────────────────────────────────────────
    if (s3)
    {
        if (!Hook::WriteJmp(kS3Site, &BuyRecordBoundTrampoline, 5)) { return PatchResult::Failed; }
        Log::Line(L"    P19 S3  9905 «купить» (Recv_TransAction_BuyItemReq@0x51AA10): проверка "
                  L"«не больше 8 записей» перенесена ПЕРЕД memcpy; площадка 0x%08X -> трамплин "
                  L"0x%08X, отказ -> штатный 0x%08X (ответ 9906, код 1)",
                  kS3Site, (DWORD)&BuyRecordBoundTrampoline, g_pBuyRefuse);
    }

    if (s4)
    {
        if (!Hook::WriteJmp(kS4Site, &DeleteRecordBoundTrampoline, 5)) { return PatchResult::Failed; }
        Log::Line(L"    P19 S4  9909 «снять лот» (Recv_TransAction_DeleteItemReq@0x51E380): проверка "
                  L"«не больше 10 записей» перенесена ПЕРЕД memcpy; площадка 0x%08X -> трамплин "
                  L"0x%08X, отказ -> штатный 0x%08X (ответ 9910, код 1)",
                  kS4Site, (DWORD)&DeleteRecordBoundTrampoline, g_pDelRefuse);
    }

    return PatchResult::Applied;
}
