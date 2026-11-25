// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P01 — приём клиентского опкода 6616 (0x19D8) -> рассылка 6131 всем игрокам.
//
//  В стоке обработчика 6616 НЕТ: диспетчер sub_42A9D0 в этом диапазоне идёт
//  `… 0x19CC, 0x19D0, 0x1A2C …`, пакет молча выбрасывается. Клиент при этом умеет
//  его слать (netSendSignedPacket6616@0xA0F140) — отсюда известное «сервер УМЕЛ
//  анонсировать редкую добычу, но НИКОГДА не делал».
//
//  Перенос ранее собранного бинарного патча v2 (подтверждён живым тестом
//  2026-08-04: клиент -> 6616 -> сервер -> 6131 -> чужой клиент показал HERO_NOTICE).
//  Логика 1:1, только код кейва заменён на C-функцию в DLL.
//
//  Точка перехвата @0x42AB5C — самое начало бинарного дерева сравнений диспетчера:
//      81 BD 38 EF FF FF 75 17 00 00   cmp dword ptr [ebp-0x10C8], 0x1775
//  Следующая инструкция 0x42AB66 (`jg 0x42AD3F`) не трогается — стаб восстанавливает
//  и сравнение, и флаги (`jmp dword ptr [...]` флаги не меняет).
//
//  Кадр диспетчера (проверено):
//      [ebp-0x10C8] — разобранный опкод пакета
//      [ebp-0x10C4] — this диспетчера; CUserManager = [[this+4]+0x34]
//      [ebp-0x1048] — буфер пакета
//      [ebp-0x44]   — userNum
//      [ebp+8]      — указатель на маркер прогресса (штатные case пишут туда номер)
//
//  ⚠ Тело 6131 остаётся БАЙТ-В-БАЙТ как в проверенной версии v2: код предмета +
//    имя с сервера, байты 24..43 нулевые. Теги источника (P11) сюда не добавляются
//    намеренно — чтобы не менять поведение, подтверждённое живым тестом.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    // ── типизированные указатели на функции сервера ─────────────────────────
    typedef int   (__cdecl    *FnIsValidUserIdx)(short idx);
    typedef int   (__cdecl    *FnIsItemCode)(int code);
    typedef int   (__thiscall *FnSecretCheck)(void* mgr, __int64 ts, short idx, const char* fn);
    typedef int   (__thiscall *FnPktSignCheck)(void* mgr, void* pkt, unsigned len, short idx, int mode);
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);
    typedef int   (__thiscall *FnSendAllInMap)(void* mgr, short op, short len, void* buf, int flag);
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);

    const FnIsValidUserIdx SrvIsValidUserIdx = (FnIsValidUserIdx)Srv::kIsValidUserIdx;
    const FnIsItemCode     SrvIsItemCode     = (FnIsItemCode)Srv::kIsItemCode;
    const FnIsItemCode     SrvIsSowelCode    = (FnIsItemCode)Srv::kIsSowelCode;
    const FnSecretCheck    SrvSecretCheck    = (FnSecretCheck)Srv::kSecretCheck;
    const FnPktSignCheck   SrvPktSignCheck   = (FnPktSignCheck)Srv::kPktSignCheck;
    const FnGetUser        SrvGetUser        = (FnGetUser)Srv::kGetUser;
    const FnSendAllInMap   SrvSendAllInMap   = (FnSendAllInMap)Srv::kSendAllInMap;
    const FnSrvLog         SrvLog            = (FnSrvLog)Srv::kLog;

    // строки — те же, что в бинарной версии v2 (формат логов не меняем)
    const char kFnName[] = "Recv_RareItemNotice()";
    const char kFmtIn[]  = "RareItemNotice\tIN\tCode\t%d\tUserNum\t%d";
    const char kFmtFail[]= "RareItemNotice\tFAIL\tCode\t%d\tUserNum\t%d\tStage\t%d";
    const char kFmtOk[]  = "RareItemNotice\tOK\tCode\t%d\tUserNum\t%d";

    // Смещения тела пакета 6616 (48 б): секрет 8 @+9, MD5 @+17, подписанное тело 24 @+33.
    constexpr int kOffTs   = 9;
    constexpr int kOffBody = 33;
    constexpr int kBodyLen = 24;

    // ── сам обработчик ──────────────────────────────────────────────────────
    void __stdcall RareItemNotice(void* mgr, int userNum, BYTE* pkt)
    {
        const short idx = (short)userNum;
        const int itemCode = *(const int*)(pkt + kOffBody);

        SrvLog(Srv::kLogCatItem, kFmtIn, itemCode, userNum);

        int stage = 1;
        do
        {
            if (!SrvIsValidUserIdx(idx)) { break; }              // 1 — индекс вне диапазона

            stage = 2;
            __int64 ts = 0;
            memcpy(&ts, pkt + kOffTs, sizeof(ts));
            if (!SrvSecretCheck(mgr, ts, idx, kFnName)) { break; }   // 2 — анти-реплей

            stage = 3;
            if (!SrvPktSignCheck(mgr, pkt, kBodyLen, idx, 1)) { break; }  // 3 — MD5-подпись

            stage = 4;
            BYTE* user = SrvGetUser(mgr, idx);
            if (!user) { break; }                                // 4 — CUser не найден

            stage = 5;
            // ★★★ 2026-08-13 (rareloot2): код принимается ИЗ ДВУХ таблиц.
            //   Клиент шлёт 6616 из ЕДИНОЙ точки CItemManager_NotifyItemInfo@0xD0C8F0, а она
            //   выбирает таблицу через CItemManager_SelectTableByCode@0x9C3AA0:
            //     item_list   -> грейд itemRecord->itemGrade + фильтр по типу;
            //     sowell_list -> грейд sowelRecord->dropColorIndex[0], фильтра по типу НЕТ
            //                    (item_inventory.c:39524-39536).
            //   Т.е. САМОЦВЕТ с грейдом >= 3 отправляется клиентом штатно, а kIsItemCode
            //   (20551..dword_5F5EAC) его отвергал -> `FAIL Stage 5`, анонс терялся.
            //   Живое подтверждение: приз гачи 13.08 = код 9640 («Предмет из волчьего клыка»,
            //   sowell_list) — P11 отбросил его как SKIP_BADCODE по той же причине.
            //   Из 3 925 самоцветов 859 имеют GradeColorIndex >= 3, т.е. анонсируемы.
            if (!SrvIsItemCode(itemCode) && !SrvIsSowelCode(itemCode)) { break; }  // 5 — код вне обеих таблиц

            // тело 6131: код предмета + имя С СЕРВЕРА (поле имени из пакета игнорируется)
            BYTE body[Srv::kNoticeLen];
            memset(body, 0, sizeof(body));
            *(int*)body = itemCode;
            memcpy(body + 4, user + Srv::kOffCharName, 20);

            SrvSendAllInMap(mgr, (short)Srv::kOpItemAcquired, (short)Srv::kNoticeLen, body, 1);
            SrvLog(Srv::kLogCatItem, kFmtOk, itemCode, userNum);
            return;
        } while (0);

        SrvLog(Srv::kLogCatItem, kFmtFail, itemCode, userNum, stage);
    }

    // ── стаб ветки диспетчера ───────────────────────────────────────────────
    DWORD g_pSwitchTail = Srv::Hooks::kDispatchTail;    // 0x42F036 — общий хвост switch
    DWORD g_pHookRet    = Srv::Hooks::kDispatch6616 + 10;  // 0x42AB66

    const BYTE kOrig[10] =
    {
        0x81, 0xBD, 0x38, 0xEF, 0xFF, 0xFF, 0x75, 0x17, 0x00, 0x00
    };

    __declspec(naked) void DispatchStub()
    {
        __asm
        {
            cmp  dword ptr [ebp-0x10C8], 0x19D8
            jne  not_ours

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], 0x19D7         // маркер прогресса (как у штатных case)

            lea  eax, dword ptr [ebp-0x1048]
            push eax                             // pkt
            movsx ecx, word ptr [ebp-0x44]
            push ecx                             // userNum
            mov  edx, dword ptr [ebp-0x10C4]
            mov  eax, dword ptr [edx+4]
            mov  eax, dword ptr [eax+0x34]
            push eax                             // mgr
            call RareItemNotice                  // __stdcall — чистит 12 байт сам

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], 0x19D8
            jmp  dword ptr [g_pSwitchTail]

        not_ours:
            cmp  dword ptr [ebp-0x10C8], 0x1775  // восстановить исходное сравнение и флаги
            jmp  dword ptr [g_pHookRet]
        }
    }
}

PatchResult P01_RareItemNotice6616()
{
    if (!Config::GetBool(L"P01_RareItemNotice6616", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kDispatch6616, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P01", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kDispatch6616, &DispatchStub, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P01: перехват @0x%08X (10 б) -> стаб 0x%08X; "
              L"опкод 6616 -> рассылка 6131 всем, хвост switch 0x%08X",
              Srv::Hooks::kDispatch6616, (DWORD)&DispatchStub, g_pSwitchTail);
    return PatchResult::Applied;
}
