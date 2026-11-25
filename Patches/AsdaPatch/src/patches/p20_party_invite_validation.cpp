// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P20 — ОТРЯД: пропущенные проверки в обработчиках приглашения 5090 и 5094
//        и копипаста имени в итоговом обработчике создания отряда.
//        ★ НАША ПРАВКА, не перенос чужой.
//
//  Отчёт-источник: Reports/party_invite_2250.md §6, дефекты S1..S4.
//  Заявка:         AstoryServer/Docs/GameServer/party-invite-validation-gaps-OPEN.md
//
//  ── КАК ПРОВЕРЕНЫ АДРЕСА (это НЕ гипотезы из декомпила) ─────────────────────
//  1. Полный побайтовый диф нашего образа RE/ida/server_work/GameServer.exe
//     (MD5 68BA5176 2209007B 8AB47260 C92480D0) и ЖИВОГО
//     \\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\GameServer\GameServer.exe
//     (MD5 E7B4AC38 E8328AAA 847BBD9B F261BB01, 1 740 800 б): расхождений 218 байт.
//     В зоне отряда 0x44F450…0x450700 расхождений НОЛЬ — оба образа тут совпадают
//     байт в байт, и всё сказанное ниже относится к ЖИВОМУ серверу.
//  2. Каждая площадка прочитана в дизассемблере ЖИВОГО образа (байты — ниже).
//
//  ── S1 — 5090 «создать отряд»: нет проверки «цель ≠ отправитель» ────────────
//  sub_44F4C0@0x44F4C0. Во ВСЕЙ функции ровно пять сравнений:
//      0x44F50C  test eax,eax          ; результат sub_523F00 (подпись тела) — РАБОТАЕТ
//      0x44F557  cmp [ebp-0x68],0      ; отправитель найден
//      0x44F59C  cmp [ebp-4],0         ; цель найдена
//      0x44F5F6  cmp eax,4             ; тип зоны == 4
//      0x44F60F  cmp edx,ecx           ; отряды армий совпадают
//  Сравнения [ebp+8] (charIndex отправителя) с [ebp-0x6C] (userNum цели) НЕТ.
//  ⇒ самоприглашение блокирует только клиент (нотис 1093).
//
//  ── S2 — 5090 и 5094: нет проверок «я уже в отряде» / «я глава» ─────────────
//  В sub_44FDE0@0x44FDE0 (5094) список сравнений такой же (0x44FE2C, 0x44FE77,
//  0x44FEBC, 0x44FF16, 0x44FF2F) — и ни одного обращения к состоянию отряда
//  отправителя. Семантика полей CUser доказана записями в
//  recvResponseUserNewPartyCreate (GameServer.c:31997-32001) и
//  Recv_ResponseUser_InviteParty (:32230-32231), плюс идиомой чтения
//  `if (*(__int16*)(x+436) >= 0)` на :32709 и :32779:
//      +0x1B4 (436) i16 = индекс отряда; ОТРИЦАТЕЛЬНЫЙ = «не в отряде»;
//      +0x1B6 (438) u8  = 1 у главы отряда, 0 у рядового участника.
//
//  ── S4 — 5094: partyIndex берётся без проверки ──────────────────────────────
//      0x44FF97  mov ax, word [edx+0x1B4]   ; edx = pUser, БЕЗ проверки
//  Если отправитель не в отряде, наружу уходит −1. Лечится тем же гейтом, что S2:
//  после него поле гарантированно валидно, поэтому отдельного ключа у S4 нет.
//
//  ── S3 — копипаста имени в recvResponseUserNewPartyCreate@0x44F9D0 ──────────
//  Ветка «зона типа 4», два подряд вызова sub_532570 (получить имя по userNum):
//      0044FCEB  66 8B 45 E4   mov ax,[ebp-0x1C]   ; partyBody[0] — ПРИГЛАСИВШИЙ
//      0044FCF9  call 0x532570                     ; -> имя пригласившего
//      0044FD12  call 0x467AD0                     ; (…, partyBody[0], idx, имя)  ВЕРНО
//      0044FD17  66 8B 45 E4   mov ax,[ebp-0x1C]   ; ★ СНОВА пригласивший
//      0044FD25  call 0x532570                     ; -> имя ПРИГЛАСИВШЕГО
//      0044FD30  66 8B 4D EA   mov cx,[ebp-0x16]   ; partyBody[3] — приглашённый
//      0044FD3E  call 0x467AD0                     ; (…, partyBody[3], idx, ЧУЖОЕ имя)
//  ⇒ приглашённый регистрируется в квестовой системе отряда с именем пригласившего.
//  Лечение — ОДИН байт: смещение в команде по 0x44FD1A с E4 (−0x1C) на EA (−0x16).
//
//  ── ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ ─────────────────────────────────────────────────
//  «S5» первой редакции отчёта («sub_523F00 выбрасывает результат memcmp») —
//  ДУБЛЬ уже опровергнутого P19-S1. В ЖИВОМ образе 0x523F8B = 74 (je) и
//  0x52400D = 74 (je): подпись тела проверяется. Наш локальный образ — сборка со
//  снятой защитой (MEMANTO gameserver-decompile-stale). Патча нет и не будет;
//  фактическое состояние гейта печатает диагностика P19 (ReportMd5GateState).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* kSec = L"P20_PartyInviteValidation";

    // Включатели читаются из ini один раз и дальше живут байтами: трамплины
    // проверяют их прямо в коде, поэтому два дефекта делят одну площадку.
    BYTE g_s1SelfInvite = 1;   // «цель ≠ отправитель»
    BYTE g_s2PartyState = 1;   // «я не в отряде» (5090) / «я в отряде и глава» (5094)

    // ── адреса, куда прыгают трамплины ─────────────────────────────────────
    // (переменные, а не константы: naked-ассемблер MSVC умеет jmp только [метка])
    DWORD g_p5090Back   = 0x0044F5DF;  // площадка + 6: mov ecx,[eax+0x4950]
    DWORD g_p5090Refuse = 0x0044F650;  // `push 1` СРАЗУ ПОСЛЕ `mov byte [ebp-0x64],0Bh`
                                       //   — переиспользуем штатную отправку 5091 с НАШИМ кодом
    DWORD g_p5090Exit   = 0x0044F7AD;  // штатный эпилог (тихо, без пакета)
    DWORD g_p5094Back   = 0x0044FEFF;  // площадка + 6
    DWORD g_p5094Exit   = 0x004500AB;  // штатный эпилог

    // ── S1/S2 у 5090: площадка 0x44F5D9, 6 байт (две команды целиком) ──────
    const DWORD kSite5090 = 0x0044F5D9;
    // Сверяем 18 байт: пятёрка `mov edx,[ebp-0x74]; mov eax,[edx+4]` встречается
    //   в образе не раз, короткая сверка ничего не доказывает.
    const BYTE  kOrig5090[18] =
    {
        0x8B, 0x55, 0x8C,                   // mov  edx, [ebp-0x74]   ; this
        0x8B, 0x42, 0x04,                   // mov  eax, [edx+4]
        0x8B, 0x88, 0x50, 0x49, 0x00, 0x00, // mov  ecx, [eax+0x4950]
        0x69, 0xC9, 0xEC, 0x00, 0x00, 0x00  // imul ecx, ecx, 0xEC
    };
    // Ветка отказа 5091: сверяем и её — трамплин прыгает внутрь.
    const DWORD kRefuse5090 = 0x0044F64C;
    const BYTE  kRefuse5090Orig[12] =
    {
        0xC6, 0x45, 0x9C, 0x0B,             // mov  byte [ebp-0x64], 0Bh  ; код «другая армия»
        0x6A, 0x01,                         // push 1                     ; <- g_p5090Refuse
        0x6A, 0x00,                         // push 0
        0x8D, 0x55, 0x9C,                   // lea  edx, [ebp-0x64]
        0x52                                // push edx
    };

    // ── S2/S4 у 5094: площадка 0x44FEF9, 6 байт ────────────────────────────
    const DWORD kSite5094 = 0x0044FEF9;
    const BYTE  kOrig5094[18] =
    {
        0x8B, 0x55, 0xA0,                   // mov  edx, [ebp-0x60]   ; this
        0x8B, 0x42, 0x04,                   // mov  eax, [edx+4]
        0x8B, 0x88, 0x50, 0x49, 0x00, 0x00, // mov  ecx, [eax+0x4950]
        0x69, 0xC9, 0xEC, 0x00, 0x00, 0x00  // imul ecx, ecx, 0xEC
    };

    // ── S3: одна команда, один байт ────────────────────────────────────────
    const DWORD kSiteS3   = 0x0044FD17;
    const DWORD kByteS3   = 0x0044FD1A;   // само смещение внутри команды
    const BYTE  kOrigS3[19] =
    {
        0x66, 0x8B, 0x45, 0xE4,             // mov  ax, [ebp-0x1C]    ; <- чиним этот байт (E4)
        0x50,                               // push eax
        0x8B, 0x4D, 0xD0,                   // mov  ecx, [ebp-0x30]
        0x8B, 0x51, 0x04,                   // mov  edx, [ecx+4]
        0x8B, 0x4A, 0x34,                   // mov  ecx, [edx+0x34]
        0xE8, 0x46, 0x28, 0x0E, 0x00        // call 0x532570
    };

    // ── Трамплин 5090 ──────────────────────────────────────────────────────
    //  Вход по jmp с площадки: ebp — кадр sub_44F4C0, все локальные на месте.
    //  Портим eax/ecx/edx и флаги — это безопасно: вытесненные команды сами
    //  задают edx и eax, ecx задаётся следующей за возвратом командой
    //  (`mov ecx,[eax+0x4950]`), а флаги там же переопределяет `imul`.
    __declspec(naked) void Party5090Guard()
    {
        __asm
        {
            cmp   byte ptr [g_s1SelfInvite], 0
            je    SkipSelf
            movsx eax, word ptr [ebp+0x08]      // charIndex отправителя
            movsx ecx, word ptr [ebp-0x6C]      // userNum цели из тела пакета
            cmp   eax, ecx
            je    SilentDrop                    // сам себя — молча не выполняем
        SkipSelf:
            cmp   byte ptr [g_s2PartyState], 0
            je    Ok
            mov   eax, dword ptr [ebp-0x68]     // pUser отправителя
            movsx eax, word ptr [eax+0x1B4]     // индекс отряда
            test  eax, eax
            jns   AlreadyInParty                // >= 0 — уже в отряде
        Ok:
            mov   edx, dword ptr [ebp-0x74]     // <- вытесненные площадкой команды
            mov   eax, dword ptr [edx+0x04]
            jmp   dword ptr [g_p5090Back]
        SilentDrop:
            jmp   dword ptr [g_p5090Exit]
        AlreadyInParty:
            mov   byte ptr [ebp-0x64], 8        // код 8 -> клиентский нотис 1047
            jmp   dword ptr [g_p5090Refuse]     // штатная отправка 5091 и выход
        }
    }

    // ── Трамплин 5094 ──────────────────────────────────────────────────────
    //  Отказ здесь ТОЛЬКО молчаливый: у ответа 5095 нет кода «ты не глава»
    //  (Notice_ShowResultByCode@0xF391F0 знает коды 1..0xB, и ни один из них
    //  этого не значит), а выдумывать новый код значило бы менять и клиента.
    //  Штатный клиент сюда не приходит — его собственные гейты 1047/1089
    //  не дают отправить пакет.
    __declspec(naked) void Party5094Guard()
    {
        __asm
        {
            cmp   byte ptr [g_s1SelfInvite], 0
            je    SkipSelf2
            movsx eax, word ptr [ebp+0x08]      // charIndex отправителя
            movsx ecx, word ptr [ebp-0x58]      // charIndex цели из тела пакета
            cmp   eax, ecx
            je    SilentDrop2
        SkipSelf2:
            cmp   byte ptr [g_s2PartyState], 0
            je    Ok2
            mov   eax, dword ptr [ebp-0x54]     // pUser отправителя
            movsx ecx, word ptr [eax+0x1B4]     // индекс отряда
            test  ecx, ecx
            js    SilentDrop2                   // < 0 — вообще не в отряде (это же и S4)
            cmp   byte ptr [eax+0x1B6], 1       // 1 = глава отряда
            jne   SilentDrop2
        Ok2:
            mov   edx, dword ptr [ebp-0x60]     // <- вытесненные площадкой команды
            mov   eax, dword ptr [edx+0x04]
            jmp   dword ptr [g_p5094Back]
        SilentDrop2:
            jmp   dword ptr [g_p5094Exit]
        }
    }
}

PatchResult P20_PartyInviteValidation()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const bool s1 = Config::GetBool(kSec, L"FixSelfInvite",         true);
    const bool s2 = Config::GetBool(kSec, L"FixPartyStateGuard",    true);
    const bool s3 = Config::GetBool(kSec, L"FixQuestNameCopyPaste", true);

    g_s1SelfInvite = s1 ? 1 : 0;
    g_s2PartyState = s2 ? 1 : 0;

    if (!s1 && !s2 && !s3)
    {
        Log::Line(L"    P20: все исправления выключены в ini — ставить нечего");
        return PatchResult::Disabled;
    }

    // ── Сверяем ВСЕ нужные площадки ДО первой записи ────────────────────────
    //    Частично поставленный патч хуже неповставленного: либо всё, либо ничего.
    Site check[4];
    int  n = 0;
    if (s1 || s2)
    {
        check[n].va = kSite5090;   check[n].orig = kOrig5090;       check[n].len = sizeof(kOrig5090);       ++n;
        check[n].va = kRefuse5090; check[n].orig = kRefuse5090Orig; check[n].len = sizeof(kRefuse5090Orig); ++n;
        check[n].va = kSite5094;   check[n].orig = kOrig5094;       check[n].len = sizeof(kOrig5094);       ++n;
    }
    if (s3)
    {
        check[n].va = kSiteS3;     check[n].orig = kOrigS3;         check[n].len = sizeof(kOrigS3);         ++n;
    }
    if (!VerifyAllSites(L"P20", check, n)) { return PatchResult::Mismatch; }

    // ── Запись ─────────────────────────────────────────────────────────────
    if (s1 || s2)
    {
        if (!Hook::WriteJmp(kSite5090, &Party5090Guard, 6)) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(kSite5094, &Party5094Guard, 6)) { return PatchResult::Failed; }
        Log::Line(L"    P20 S1/S2/S4  5090 (sub_44F4C0) и 5094 (sub_44FDE0): гейт «цель != отправитель»=%s, "
                  L"гейт «состояние отряда»=%s; площадки 0x%08X -> 0x%08X и 0x%08X -> 0x%08X",
                  s1 ? L"вкл" : L"выкл", s2 ? L"вкл" : L"выкл",
                  kSite5090, (DWORD)&Party5090Guard, kSite5094, (DWORD)&Party5094Guard);
    }

    if (s3)
    {
        // Один байт: смещение −0x1C (E4) -> −0x16 (EA) во второй `mov ax,[ebp-…]`.
        if (!Hook::WriteByteChecked(kByteS3, 0xE4, 0xEA)) { return PatchResult::Failed; }
        Log::Line(L"    P20 S3  recvResponseUserNewPartyCreate@0x44F9D0: имя для второго sub_467AD0 "
                  L"теперь берётся у ПРИГЛАШЁННОГО (partyBody[3]), а не у пригласившего; "
                  L"байт 0x%08X: E4 -> EA", kByteS3);
    }

    return PatchResult::Applied;
}
