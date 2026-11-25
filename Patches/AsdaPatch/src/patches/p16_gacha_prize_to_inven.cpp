// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P16 — ★ ПРИЗ ПРЕМИУМ-ГАЧИ РЕАЛЬНО ПОПАДАЕТ В ИНВЕНТАРЬ.
//  Перехват в sub_4F7D10@0x4F7D10 (`RecvDB_InsertPremiumItem`, ответ БД на 2601),
//  ветка «гача» (BuyType == 3).  Полный разбор: Reports/gacha_prize_server_fix.md
//
//  ── ЧТО БЫЛО СЛОМАНО ──
//  Пара наших патчей P05 (запрос к GP7, код 105) + P06 (DB-пакет 2601) провела гачу
//  по маршруту ПРЕМИУМ-ШОПА. Этот маршрут по замыслу авторов кладёт покупку в
//  «премиум-список» БД и НЕ трогает инвентарь: обработчик ответа sub_4F7D10 в ветке
//  гачи заполняет тело 6578 только двумя полями —
//      004F7E1B  8A 45 F7 / 88 85 3C FF FF FF   тело+0  = статус
//      004F7E24  8B 4D DE / 89 8D 3D FF FF FF   тело+1  = код предмета
//  а остальные 57 байт записи предмета остаются такими, какими их сделал конструктор
//  sub_4FA410 -> sub_40A9F0@0x40A9F0:
//      0040AA18  C6 42 04 00         mov byte [edx+4],0        ; контейнер = 0
//      0040AA1F  66 C7 40 05 FF FF   mov word [eax+5],0xFFFF   ; слот      = −1
//  Именно эти нули и −1 владелец видел в живом пакете 6578
//  (`01 4F0B0100 00 FFFF …`, лог клиента 2026-08-17 22:18:23).
//  Дальше `sub_4D61E0(контейнер=0, слот=−1)` предмет не находил -> 6582 со статусом 10.
//
//  ⚠ Стоковая ветка гачи (DB 2553 -> 2554 -> `PrimiumGaCha@0x4F70B0`) авторами НЕ
//    дописана: сплошной скан живого образа на непосредственное 0x9F9 (2553) —
//    0 вхождений, и в GameServer.exe, и в DBManager.exe (для контроля 0x9FA/0x9FB/0xA29
//    находятся). То есть «ссылок-отправителей 2553 в срезе нет», а сам DBManager
//    (`Recv_PrimiumGaCha@0x43DAA0`) просто ЭХО-копирует 82 байта запроса в ответ
//    (`0043DB9F rep movsd 0x14 + movsw`), значит контейнер/слот обязан выбрать
//    GameServer ДО отправки. Возрождать 2553 нельзя: он тянет за собой хранимую
//    процедуру `UPGotChaCashItemBuy` (32 параметра) и повторное списание кэша,
//    а деньги у нас уже списал GP7-агент.
//
//  ── ЧЕМ ЛЕЧИМ: РАБОЧЕЙ ВЕТКОЙ ЭТОГО ЖЕ СЕРВЕРА ──
//  `Recv_PremiumItemToInven_Req@0x4F8340` — «перенести купленный премиум-предмет из
//  списка в инвентарь». Она ЖИВАЯ и проверена на нашем сервере ровно на призах гачи:
//      GameServer/Log/Log_MGamePremium/MoveToInven_20260806.txt
//      PremiumItemToInven_Req  Order 606711 ItemIndex 68432 Count 1 BuyType 3
//      PremiumItemToInven_Req success  iType 1  Pos 25, -1, -1, -1, -1, -1, -1
//      PremiumItemToInven_Res  Order 606711 Result 1 BuyType 3
//  Её формула (дизасм 0x4F8577…0x4F8976), которую патч повторяет ОДИН-В-ОДИН:
//      1) sub_5340B0(mgr, userNum, код, 0, &запись, 0, 0) == 1
//         — строит 57-байтовую запись и НАЗНАЧАЕТ КОНТЕЙНЕР (запись+4);
//      2) классификация кода: sub_532A90 / sub_532AE0 / sub_532B10
//         — даёт iType запроса и байт «состояние» записи+50;
//      3) ★ слот: sub_4D6740(mgr, userNum, контейнер, предыдущийСлот) для каждой
//         единицы count, старт с −1; −1 в ответе = «инвентарь полон» -> отказ;
//      4) sub_5646C0(0x7E0538, 2604, 87, seq, &запрос, userNum) — в БД.
//  Ответ БД 2605 обрабатывает СТОКОВЫЙ `sub_4F89D0@0x4F89D0`: он ещё раз зовёт
//  sub_4D6740 тем же контейнером, пишет слот в запись+5, кладёт запись через
//  sub_4D63F0 и шлёт клиенту 11007. Персистентность обеспечивает БД, наш код
//  инвентарь в памяти НЕ трогает — поэтому повторного слота не возникает.
//
//  Дополнительно патч вписывает готовую запись (уже с контейнером и слотом) в тело
//  ещё не отправленного пакета 6578 — тогда клиент видит ячейку приза, а последующий
//  6581 (`Recv_UserPrimiumGaChaReward` -> `sub_4D61E0(контейнер, слот)`) находит предмет.
//  Слот там тот же, что выберет sub_4F89D0: между нашим вызовом и приходом 2605
//  инвентарь этого персонажа никем не меняется (обработка пакетов пользователя
//  последовательна), а sub_4D6740 — чистая функция от состояния контейнера.
//
//  ── ТОЧКА ПЕРЕХВАТА ──
//      004F7E40  6A 00                push 0                    <-- ЗАМЕНЯЕМ (7 байт)
//      004F7E42  66 8B 45 08          mov  ax, word ptr [ebp+8]
//      004F7E46  50                   push eax
//      004F7E47  8D 8D 3C FF FF FF    lea  ecx,[ebp-0xC4]       <-- ВОЗВРАТ сюда
//  Площадка выбрана ПОСЛЕ того, как сток дозаполнил тело 6578 (статус/код/баланс),
//  и ДО первого push аргументов отправки — стек в этот момент чистый.
//  Безопасность: полный перебор кодировок rel8/rel32/jcc32 по всей .text плюс скан
//  всех DWORD образа — переходов и ссылок ВНУТРЬ 0x4F7E41…0x4F7E46 ноль.
//
//  ── ОТЛИЧИЕ ОТ ОРИГИНАЛА (осознанное, помечено) ──
//  Стоковый `Recv_PremiumItemToInven_Req` пишет слоты в массив из 7 элементов циклом
//  `for (i = 0; i < count; ++i)`, где count — БАЙТ из пакета, без верхней проверки
//  (0x4F8802 `movzx edx,[ebp-0x21C]`; 0x4F8846 `mov [ebp+eax*2-0x25],cx`) — при
//  count > 7 это запись за границу кадра. Наш патч зажимает count в 1..7 и пишет
//  предупреждение в лог. Дефект оригинала, исправляем и помечаем.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    // ── адреса функций GameServer, которые зовём (все проверены дизассемблером
    //    по живому образу; .text живого и стокового файла совпадает байт-в-байт) ──

    // char __thiscall GetServerGroup(void* obj)   @0x4A7EA0, obj = 0x60AD18
    typedef char (__thiscall *FnGetSrvGroup)(void*);
    // char __thiscall GetChannelNo(void* obj)     @0x4A7EB0, obj = 0x60AD18
    typedef char (__thiscall *FnGetChannel)(void*);
    // int  __thiscall GetUserIndex(void* mgr, __int16 userNum)          @0x5324F0
    typedef int  (__thiscall *FnGetUserIndex)(void*, __int16);
    // char __thiscall GetUserSubFlag(void* mgr, __int16 userNum)        @0x532530
    typedef char (__thiscall *FnGetSubFlag)(void*, __int16);
    // char __thiscall GetWorldFlag(void* mgr)                           @0x40C960
    typedef char (__thiscall *FnGetWorldFlag)(void*);
    // int  __thiscall BuildItemRec(void* mgr, __int16 userNum, int code,
    //                              int extra, void* rec, __int16 a6, __int16 a7) @0x5340B0
    //   -> 1 = запись построена; 2..7 = отказ (нет слота / неизвестный код)
    typedef int  (__thiscall *FnBuildItemRec)(void*, __int16, int, int, void*, __int16, __int16);
    // int  __thiscall FindFreeSlot(void* mgr, __int16 userNum,
    //                              __int16 container, __int16 afterSlot)          @0x4D6740
    typedef int  (__thiscall *FnFindFreeSlot)(void*, __int16, __int16, __int16);
    // __int16 __thiscall GetDbSeq(void* net)                                      @0x4C0A30
    typedef __int16 (__thiscall *FnGetDbSeq)(void*);
    // int __thiscall ConnSend(void* mgr, __int16 op, __int16 len,
    //                         __int16 seq, void* body, __int16 userNum)           @0x5646C0
    typedef int  (__thiscall *FnConnSend)(void*, __int16, __int16, __int16, void*, __int16);
    // void __thiscall ToInvenReqCtor(void* req)   @0x4FAE00 — конструктор 87-байтовой структуры
    typedef void (__thiscall *FnReqCtor)(void*);
    // BOOL __cdecl IsItemCode/IsSowelCode/IsFuncCode
    typedef int  (__cdecl *FnCodeCheck)(int);
    // void __cdecl Log(int cat, const char* fmt, ...)                             @0x569DF0
    typedef void (__cdecl *FnSrvLog)(int, const char*, ...);

    const FnGetSrvGroup  SrvGetSrvGroup  = (FnGetSrvGroup) 0x004A7EA0;
    const FnGetChannel   SrvGetChannel   = (FnGetChannel)  0x004A7EB0;
    const FnGetUserIndex SrvGetUserIndex = (FnGetUserIndex)0x005324F0;
    const FnGetSubFlag   SrvGetSubFlag   = (FnGetSubFlag)  0x00532530;
    const FnGetWorldFlag SrvGetWorldFlag = (FnGetWorldFlag)0x0040C960;
    const FnBuildItemRec SrvBuildItemRec = (FnBuildItemRec)0x005340B0;
    const FnFindFreeSlot SrvFindFreeSlot = (FnFindFreeSlot)0x004D6740;
    const FnGetDbSeq     SrvGetDbSeq     = (FnGetDbSeq)    0x004C0A30;
    const FnConnSend     SrvConnSend     = (FnConnSend)    0x005646C0;
    const FnReqCtor      SrvReqCtor      = (FnReqCtor)     0x004FAE00;
    const FnCodeCheck    SrvIsItemCode   = (FnCodeCheck)   0x00532A90;
    const FnCodeCheck    SrvIsSowelCode  = (FnCodeCheck)   0x00532AE0;
    const FnCodeCheck    SrvIsFuncCode   = (FnCodeCheck)   0x00532B10;
    const FnSrvLog       SrvLog          = (FnSrvLog)      0x00569DF0;

    // Объект-владелец номера сервера/канала: все 119 стоковых вызовов 0x4A7EA0/0x4A7EB0
    // идут с `mov ecx, 0x60AD18` (в т.ч. 0x4F84BC и 0x4F84EF в самой ToInven-ветке).
    void* const kChannelObj = (void*)0x0060AD18;
    // Глобальный CUserMoveManager — `this` для отправки серверу БД (0x4F8971).
    void* const kNetMoveMgr = (void*)0x007E0538;

    // Таблицы предметов и их шаги (сняты с 0x4F863D…0x4F8738).
    DWORD* const kItemTablePtr  = (DWORD*)0x005F5E98;  // шаг 0x47, база кода 20551
    DWORD* const kSowelTablePtr = (DWORD*)0x005F5E8C;  // шаг 0x2B, база кода  7001
    DWORD* const kFuncTablePtr  = (DWORD*)0x005F5E70;  // шаг 0x30, база кода     1

    const int  kLogCatPremium = 38;      // Log\Log_MGamePremium\MoveToInven_<дата>.txt
    const WORD kDbOpToInven   = 0x0A2C;  // 2604 — «премиум-предмет -> инвентарь»
    const WORD kDbLenToInven  = 87;      // длина тела 2604 (0x4F896A: push 0x57)

    // ── тело DB-пакета 2604, 87 байт ────────────────────────────────────────
    //  Раскладка снята с кадра Recv_PremiumItemToInven_Req@0x4F8340 (база ebp-0x6C)
    //  и подтверждена конструктором sub_4FAE00 (слоты @0x47 = −1, @0x55/@0x56 = 0)
    //  и читателем ответа sub_4F89D0 (`v15[17]` = контейнер, `v15[70]` = count,
    //  `v15[85]` = buyType, запись с 13).
#pragma pack(push, 1)
    struct ToInvenReq
    {
        BYTE  srvGroup;    // @0  sub_4A7EA0(0x60AD18)      — индекс группы серверов
        DWORD userIndex;   // @1  sub_5324F0(mgr, userNum)  — «UserIndex» биллинга
        BYTE  subFlag;     // @5  sub_532530(mgr, userNum)
        BYTE  channel;     // @6  sub_4A7EB0(0x60AD18)      — номер канала
        BYTE  worldFlag;   // @7  sub_40C960(mgr)
        BYTE  iType;       // @8  класс предмета для БД (0/1)
        DWORD order;       // @9  номер заказа в премиум-списке
        BYTE  rec[57];     // @13 запись предмета (+0 код, +4 контейнер, +5 слот i16)
        BYTE  count;       // @70 количество единиц
        short slot[7];     // @71 выбранные слоты (не занятые = −1)
        BYTE  buyType;     // @85 тип покупки (3 = гача)
        BYTE  tail;        // @86 конструктор ставит 0
    };
#pragma pack(pop)
    static_assert(sizeof(ToInvenReq) == 87, "тело DB-пакета 2604 обязано быть 87 байт");

    // Смещения полей в теле ответа БД 2601 (буфер sub_4F7D10 @ [ebp-0x80], 0x78 б).
    // Проверены и по дизасму (0x4F7DF3 …[ebp-0x27], 0x4F7E24 …[ebp-0x22] и т.д.),
    // и по стоковому отправителю SendNewPremiumPacket@0x4F7B20.
    const int kDbBuyType   = 89;   // BYTE  — 3 = гача, иначе премиум-шоп
    const int kDbOrder     = 90;   // DWORD — номер заказа
    const int kDbItemIndex = 94;   // DWORD — код предмета
    const int kDbCount     = 102;  // BYTE  — количество

    // Смещения внутри 57-байтовой записи предмета.
    const int kRecContainer = 4;   // BYTE  — 1 сумка, 2 второй контейнер, 3 надетое, 5 склад
    const int kRecSlot      = 5;   // i16   — индекс ячейки
    const int kRecState     = 50;  // BYTE  — «состояние» (2 = особый режим)

    // ── рабочая функция патча ───────────────────────────────────────────────
    //  mgr       — CUserManager из кадра sub_4F7D10 ([ebp-0x268]); тот же объект,
    //              который стоковая ToInven-ветка держит в [ebp-0x238].
    //  userNum   — [ebp+8] хоста.
    //  db2601    — тело ответа БД 2601 ([ebp-0x80], 0x78 б).
    //  body6578  — уже заполненное стоком тело пакета 6578 ([ebp-0xC4], 63 б).
    void __cdecl GachaPrizeToInven(void* mgr, int userNum, const BYTE* db2601, BYTE* body6578)
    {
        // Статус в теле 6578: сток положил туда Result из БД и заменил 2 на 3.
        // Работаем только при полном успехе вставки в премиум-список.
        if (body6578[0] != 1) { return; }

        const int   itemCode = *(const int*)(db2601 + kDbItemIndex);
        const int   order    = *(const int*)(db2601 + kDbOrder);
        const BYTE  buyType  = db2601[kDbBuyType];
        int         count    = db2601[kDbCount];

        // Зажим количества — см. «отличие от оригинала» в шапке.
        if (count < 1)
        {
            SrvLog(kLogCatPremium, "\tGaChaPrizeToInven skip\tOrder %d\tItemIndex %d\tCount %d", order, itemCode, count);
            return;
        }
        if (count > 7)
        {
            SrvLog(kLogCatPremium, "\tGaChaPrizeToInven clamp\tOrder %d\tItemIndex %d\tCount %d -> 7", order, itemCode, count);
            count = 7;
        }

        ToInvenReq req;
        SrvReqCtor(&req);                       // стоковый конструктор: слоты −1, order −1, запись предмета

        req.srvGroup  = SrvGetSrvGroup(kChannelObj);
        req.userIndex = (DWORD)SrvGetUserIndex(mgr, (__int16)userNum);
        req.subFlag   = SrvGetSubFlag(mgr, (__int16)userNum);
        req.channel   = SrvGetChannel(kChannelObj);
        req.worldFlag = SrvGetWorldFlag(mgr);
        req.order     = (DWORD)order;
        req.count     = (BYTE)count;
        req.buyType   = buyType;

        // ── шаг 1: построить запись предмета (назначает контейнер) ──
        const int built = SrvBuildItemRec(mgr, (__int16)userNum, itemCode, 0, req.rec, 0, 0);
        if (built != 1)
        {
            SrvLog(kLogCatPremium, "\tGaChaPrizeToInven failed\tOrder %d\tItemIndex %d\tBuildItemRec %d",
                   order, itemCode, built);
            return;
        }
        // ★ P98 (30.10.2026): sub_5340B0 с a4 = 0 даёт стопочному предмету Amount 0 (или копию существующей стопки N — дюп);
        //   P98_FixPremiumRecord приводит шаблон к 1 шт. и весу штуки (P98 выключен — шаблон не трогается).
        P98_FixPremiumRecord(mgr, userNum, itemCode, req.rec, count);

        // ── шаг 2: классификация кода -> iType запроса и байт «состояние» записи ──
        if (SrvIsItemCode(itemCode))
        {
            const BYTE* row = (const BYTE*)(*kItemTablePtr) + 0x47 * (itemCode - 20551);
            req.iType          = (row[0x24] == 0 || row[0x24] == 3) ? 1 : 0;
            req.rec[kRecState] = (row[0x3A] == 2) ? 2 : 0;
        }
        else if (SrvIsSowelCode(itemCode))
        {
            const BYTE* row = (const BYTE*)(*kSowelTablePtr) + 0x2B * (itemCode - 7001);
            req.iType          = 1;
            req.rec[kRecState] = (row[0x21] == 2) ? 2 : 0;
        }
        else if (SrvIsFuncCode(itemCode))
        {
            const BYTE* row = (const BYTE*)(*kFuncTablePtr) + 0x30 * (itemCode - 1);
            req.iType          = 0;
            req.rec[kRecState] = (row[0x2B] == 2) ? 2 : 0;
        }
        else
        {
            SrvLog(kLogCatPremium, "\tGaChaPrizeToInven failed\tOrder %d\tItemIndex %d invalid",
                   order, itemCode);
            return;
        }

        // ── шаг 3: свободные слоты (по одному на единицу), старт с −1 ──
        const BYTE container = req.rec[kRecContainer];
        int after = -1;
        for (int i = 0; i < count; ++i)
        {
            // ★ P100 (01.11.2026): складываемый спецпредмет — стопка ключа или новая ячейка с накопителем (как 11006 0x4F882E);
            //   P100 не активен / не спецпредмет — стоковый sub_4D6740.
            after = P100_PremiumSlot(mgr, userNum, itemCode, container, after, *(const int*)(req.rec + 9));
            req.slot[i] = (short)after;
            if (after == -1)
            {
                SrvLog(kLogCatPremium, "\tGaChaPrizeToInven failed\tOrder %d\tItemIndex %d\tno free slot in container %d",
                       order, itemCode, (int)container);
                return;     // ничего не отправляем: приз остаётся в премиум-списке
            }
        }

        // ── шаг 4: ячейка в теле 6578, чтобы клиент увидел приз и смог послать 6581 ──
        *(short*)(req.rec + kRecSlot) = req.slot[0];
        memcpy(body6578 + 1, req.rec, sizeof(req.rec));

        // ── шаг 5: запрос в БД (её ответ 2605 обработает стоковый sub_4F89D0) ──
        void* net = *(void**)((BYTE*)mgr + 4);
        const __int16 seq = SrvGetDbSeq(net);
        SrvConnSend(kNetMoveMgr, (__int16)kDbOpToInven, (__int16)kDbLenToInven, seq, &req, (__int16)userNum);

        SrvLog(kLogCatPremium,
               "\tGaChaPrizeToInven success\tOrder %d\tItemIndex %d\tCount %d\tiType %d\tContainer %d\tPos %d, %d, %d, %d, %d, %d, %d",
               order, itemCode, count, (int)req.iType, (int)container,
               req.slot[0], req.slot[1], req.slot[2], req.slot[3], req.slot[4], req.slot[5], req.slot[6]);
    }

    DWORD g_pRet = 0x004F7E47;      // возврат в хост: сразу за перехваченными 7 байтами

    const BYTE kOrig[7] =
    {
        0x6A, 0x00,                 // push 0
        0x66, 0x8B, 0x45, 0x08,     // mov  ax, word ptr [ebp+8]
        0x50                        // push eax
    };

    __declspec(naked) void GachaPrizeTrampoline()
    {
        __asm
        {
            // Кадр хоста цел: ebp принадлежит sub_4F7D10, стек в этой точке чистый
            // (сток ещё не начал класть аргументы отправки 6578).
            pushad
            pushfd
            lea   eax, [ebp-0x0C4]          // тело 6578 (63 б)
            push  eax
            lea   eax, [ebp-0x080]          // ответ БД 2601 (0x78 б)
            push  eax
            movsx eax, word ptr [ebp+8]     // userNum
            push  eax
            mov   eax, dword ptr [ebp-0x268]// CUserManager
            push  eax
            call  GachaPrizeToInven         // __cdecl — аргументы снимаем сами
            add   esp, 16
            popfd
            popad

            // ── оригинальные 7 байт ──
            // popad вернул eax в исходное состояние, поэтому `mov ax,…; push eax`
            // кладёт ровно то же 32-битное значение, что и сток.
            push  0
            mov   ax, word ptr [ebp+8]
            push  eax

            jmp   dword ptr [g_pRet]
        }
    }
}

PatchResult P16_GachaPrizeToInven()
{
    if (!Config::GetBool(L"P16_GachaPrizeToInven", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kGachaPrizeToInven, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P16", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kGachaPrizeToInven, &GachaPrizeTrampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P16: перехват @0x%08X (7 б) -> трамплин 0x%08X, возврат 0x%08X",
              Srv::Hooks::kGachaPrizeToInven, (DWORD)&GachaPrizeTrampoline, g_pRet);
    Log::Line(L"    P16: приз гачи (BuyType 3) переносится в инвентарь формулой рабочей ветки "
              L"Recv_PremiumItemToInven_Req: sub_5340B0 -> sub_4D6740 -> DB 2604; ячейка "
              L"дописывается в тело 6578");
    return PatchResult::Applied;
}
