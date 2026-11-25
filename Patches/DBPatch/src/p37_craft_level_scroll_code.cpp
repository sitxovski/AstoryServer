// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P37 — ★★ КОД РЕЗУЛЬТАТА В ОТВЕТЕ 2668 (повышение уровня ремесла свитком).
//  DBManager, sub_445B60@0x00445B60 (приём DB-опкода 2667 от GameServer,
//  процедура `EXEC UP_CRT_CraftLevelScroll`, ответ 2668, 70 б).
//
//  ЭТО НАША ПРАВКА, а не перенос. Дефект Н-1 ревизии P35
//  (`Reports/craft/wave6_server_REVIEW.md` §5 С-1, §8 п.3), подтверждён вторым
//  методом (`Reports/craft/p36_r248_dbm.md` §3, `p36_r248_REVIEW.md` §3) и
//  третий раз — при сборке этого патча (`Reports/craft/p37_dbm.md` §1).
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Обработчик копирует тело запроса (70 б) в кадр `[ebp-0x3B48]` и СРАЗУ снимает
//  с него копию для ответа `[ebp-0x50]` (0x445C0D…0x445C1D: `mov ecx,0x11 /
//  lea esi,[ebp-0x3B48] / lea edi,[ebp-0x50] / rep movsd / movsw`). После процедуры
//  код результата пишется в ИСХОДНЫЙ буфер:
//      0x445CE7  mov byte [ebp-0x3B48], 1     ; процедура вернула 1 — успех
//      0x445D6D  mov byte [ebp-0x3B48], 0x63  ; 99 — процедура отказала
//      0x445DB3  mov byte [ebp-0x3B48], 0x62  ; 98 — ошибка выполнения SQL
//  а отправляется КОПИЯ (`lea r,[ebp-0x50] / push 0x46 / push 0xA6C / call
//  0x44E2F0`). Байт 0 копии — тот, что прислал сам GameServer, а он всегда ставит
//  там 1 (`RecvUser_CraftScrollLevelUP` 0x53F84A `mov byte [ebp-0x90],1`). Итог:
//  GameServer (`recvDBCraftScrollLevelUP` 0x53FA0D `cmp byte [ebp-0x90],1`) ВСЕГДА
//  видит «успех» — отказ процедуры и ошибка SQL до него не доходят. Соседние
//  обработчики ремесла (2662 `sub_445070`, 2664, 2666, 2670) пишут код в ту
//  копию, которую шлют, — дефект только у 2668.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Те же три инструкции, та же длина (7 б), другой адрес назначения:
//      C6 85 B8 C4 FF FF xx   mov byte [ebp-0x3B48], xx
//   →  C6 85 B0 FF FF FF xx   mov byte [ebp-0x50],   xx     (disp32 = -0x50)
//  Запись стоит ДО `call 0x44E2F0` во всех трёх ветках; между записью и отправкой
//  байт 0 копии никто не читает. `[ebp-0x3B48]` байт 0 после этих мест не читается
//  вовсе (только поля +2…, для строк журнала) — снятие записи туда безвредно.
//  Длина пакета, раскладка и опкод НЕ меняются (закон old-server-protocol-compat).
//
//  ── ЧТО БУДЕТ ПРИ ВКЛЮЧЕНИИ ──
//  Успех — как раньше (код 1). Отказ процедуры (99) и ошибка SQL (98) теперь доходят
//  до GameServer: ветка «RecvDB_CraftScrollLevelUP DB Error» → клиенту 6605 код 99
//  (сообщение 5563), свиток и уровень в памяти НЕ меняются. Замок P35 InFlightLock
//  снимается ответом с ЛЮБЫМ кодом (эхо charId по +2 не тронуто). После этого патча
//  становится достоверным ключ P35 `LevelScrollSync` (ставит уровень в память только
//  при настоящем коде 1).
//
//  Рантайм-кода у патча нет (чистая замена байт) — журнал в работе не пишется;
//  отказы 99/98 штатно журналирует сам DBManager («Recv_CraftScrollLevelUP(1)/(2)»).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"

namespace
{
    const wchar_t* const S = L"P37_CraftLevelScrollCode";

    // Три площадки: оригинал `mov byte [ebp-0x3B48], xx`.
    const BYTE kOrigOk [7] = { 0xC6, 0x85, 0xB8, 0xC4, 0xFF, 0xFF, 0x01 };   // 0x445CE7 — код 1
    const BYTE kOrig99 [7] = { 0xC6, 0x85, 0xB8, 0xC4, 0xFF, 0xFF, 0x63 };   // 0x445D6D — код 99
    const BYTE kOrig98 [7] = { 0xC6, 0x85, 0xB8, 0xC4, 0xFF, 0xFF, 0x62 };   // 0x445DB3 — код 98

    // Замена: `mov byte [ebp-0x50], xx` — запись в отправляемую копию.
    const BYTE kNewOk  [7] = { 0xC6, 0x85, 0xB0, 0xFF, 0xFF, 0xFF, 0x01 };
    const BYTE kNew99  [7] = { 0xC6, 0x85, 0xB0, 0xFF, 0xFF, 0xFF, 0x63 };
    const BYTE kNew98  [7] = { 0xC6, 0x85, 0xB0, 0xFF, 0xFF, 0xFF, 0x62 };

    constexpr DWORD kSiteOk = 0x00445CE7;
    constexpr DWORD kSite99 = 0x00445D6D;
    constexpr DWORD kSite98 = 0x00445DB3;
}

PatchResult P37_CraftLevelScrollCode()
{
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] =
    {
        { kSiteOk, kOrigOk, sizeof(kOrigOk) },
        { kSite99, kOrig99, sizeof(kOrig99) },
        { kSite98, kOrig98, sizeof(kOrig98) },
    };
    // Сверяем ВСЕ три до первой записи: либо ставим целиком, либо не ставим вовсе.
    if (!VerifyAllSites(L"P37", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    bool ok = true;
    ok &= Hook::WriteBytes(kSiteOk, kNewOk, sizeof(kNewOk));
    ok &= Hook::WriteBytes(kSite99, kNew99, sizeof(kNew99));
    ok &= Hook::WriteBytes(kSite98, kNew98, sizeof(kNew98));
    if (!ok)
    {
        Log::Line(L"    P37: ! ошибка записи хотя бы одной площадки — ответ 2668 может нести код частично");
        return PatchResult::Failed;
    }

    Log::Line(L"    P37: 0x%08X/0x%08X/0x%08X: mov byte [ebp-0x3B48],1/99/98 -> [ebp-0x50] "
              L"(отправляемая копия ответа 2668)", kSiteOk, kSite99, kSite98);
    Log::Line(L"    P37: ответ 2668 (UP_CRT_CraftLevelScroll) несёт настоящий код: 1 успех, "
              L"99 отказ процедуры, 98 ошибка SQL; протокол не менялся");
    return PatchResult::Applied;
}
