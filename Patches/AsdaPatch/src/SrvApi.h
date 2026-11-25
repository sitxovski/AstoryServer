// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  SrvApi.h — ЕДИНСТВЕННЫЙ реестр адресов и сигнатур GameServer.exe.
//
//  Хост-бинарь: GameServer.exe_before_mine_patch.exe (сток от 15.12.2024),
//               MD5 4e20f0ad0b13a54454405eed31ffe447, размер 1 740 800 б,
//               ImageBase 0x400000, релокаций нет → адреса абсолютные.
//
//  ⚠ Все VA ниже проверены дизассемблером ИМЕННО по этому бинарю. Любой другой
//    билд (в т.ч. RE/ida/server_work/GameServer.exe — он НЕ сток, а BASE + патч
//    расширения карт) даст другие байты: каждый патч обязан сверять оригинал
//    перед установкой (Hook::Verify) и отказываться при несовпадении.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once
#include <windows.h>

namespace Srv
{
    // ── ожидаемые параметры хост-образа ─────────────────────────────────────
    constexpr DWORD  kImageBase   = 0x00400000;
    constexpr DWORD  kFileSize    = 1740800;
    constexpr DWORD  kTextVa      = 0x00401000;
    constexpr DWORD  kTextRawSize = 0x00182000;   // .text SizeOfRawData
    constexpr DWORD  kTextEnd     = 0x00583000;   // kTextVa + kTextRawSize
    constexpr DWORD  kRdataVa     = 0x00583000;
    constexpr DWORD  kRdataEnd    = 0x005A6000;

    // ── функции GameServer, которые зовём из патчей ─────────────────────────
    // Соглашения о вызовах записаны так, как их восстановил Hex-Rays по стоку.
    // BOOL  __cdecl    IsValidUserIdx(__int16 idx)                idx < 0x226
    constexpr DWORD kIsValidUserIdx = 0x005328F0;
    // BOOL  __cdecl    IsItemCode(int code)                       20551..dword_5F5EAC
    constexpr DWORD kIsItemCode     = 0x00532A90;
    // BOOL  __cdecl    IsSowelCode(int code)                      7001..dword_5F5EA0
    //   Парная проверка для ТАБЛИЦЫ САМОЦВЕТОВ (sowell_list). Байты стока проверены:
    //     0x532A90  55 8B EC 81 7D 08 47 50 00 00 …  cmp [ebp+8], 20551 ; cmp dword_5F5EAC
    //     0x532AE0  55 8B EC 81 7D 08 59 1B 00 00 …  cmp [ebp+8],  7001 ; cmp dword_5F5EA0
    //   Нужна P01: клиент шлёт 6616 и по САМОЦВЕТУ (CItemManager_NotifyItemInfo@0xD0C8F0
    //   берёт грейд из sowelRecord->dropColorIndex[0] и фильтр по типу не применяет —
    //   item_inventory.c:39524-39536), а kIsItemCode такой код отвергает как «вне таблицы».
    constexpr DWORD kIsSowelCode    = 0x00532AE0;
    constexpr int   kSowelCodeBase  = 7001;
    // int   __thiscall SecretCheck(void* mgr, __int64 ts, __int16 idx, const char* fn)
    constexpr DWORD kSecretCheck    = 0x00524390;
    // int   __stdcall  PktSignCheck(int* pkt, size_t len, __int16 idx, int mode)  — MD5 тела
    constexpr DWORD kPktSignCheck   = 0x00523F00;
    // CUser* __thiscall GetUser(void* mgr, __int16 idx)
    constexpr DWORD kGetUser        = 0x005324A0;
    // int   __thiscall GetUserNumber(void* mgr, __int16 idx)      — «UserIndex» для логов
    constexpr DWORD kGetUserNumber  = 0x005324F0;
    // BOOL  __thiscall SendAllPlayerInMap(void* mgr, __int16 op, __int16 len, void* buf, int flag)
    constexpr DWORD kSendAllInMap   = 0x0052E520;
    // BOOL  __thiscall SendSectorInAllUser(...)                   — зона «только сектор»
    constexpr DWORD kSendSectorAll  = 0x0052E630;
    // void  __cdecl    Log(int category, const char* fmt, ...)    1 = Log_Item, 6 = Log_Operator
    constexpr DWORD kLog            = 0x00569DF0;
    // void* __cdecl    memcpy / memset
    constexpr DWORD kMemcpy         = 0x0056A040;
    constexpr DWORD kMemset         = 0x0056A5A0;
    // BOOL  __thiscall IsOperator(void* mgr, __int16 idx)         — флаг оператора
    // ⚠ МИСНЕЙМ, оставлен ради P04 (закон false-negatives-method: имя врёт).
    //   На самом деле это ЧТЕНИЕ GM-ФЛАГА: `CUser[1].gap_B6E[2971]`, байт, который
    //   приезжает из dbo.CharGmInfo.GMFlag через UPCharGMInfo при входе.
    //   НАСТОЯЩИЙ операторский гейт — kIsOperatorIndex ниже. Стоковые GM-команды
    //   проверяют ОБА, и в этом порядке.
    constexpr DWORD kIsOperator     = 0x0052ED50;
    // BOOL  __thiscall IsOperatorUser(void* mgr, __int16 idx, int a3)
    //   ★ ОПЕРАТОРСКИЙ ГЕЙТ: UserIndex (CUser+0x174, читается sub_5324F0) в 0…5000.
    //   Закон server-operator-gate: по ИМЕНИ судить нельзя (ADM_* = оператор,
    //   GM_sitxovski с индексом 75180 — обычный игрок, хотя GMFlag у него стоит).
    //   a3 <= 0 — «спросить у сессии idx», иначе проверяется само a3.
    constexpr DWORD kIsOperatorIndex = 0x0052ECF0;
    // char  __thiscall GetServerGroup(void* self)                 — группа серверов
    //   Байт, который стоковые отправители кладут в тело DB-пакета (+7): его ждёт
    //   sub_407390 на стороне DBManager при выборе соединения с базой.
    constexpr DWORD kGetServerGroup = 0x004A7EA0;
    constexpr DWORD kServerGroupThis = 0x0060AD18;   // ecx у sub_4A7EA0 (см. 0x54AF2B)
    // short __thiscall GetDbSrvIdx(void* net)                     — индекс соединения
    //   с DBManager (тот, что стоковый отправитель 2256 берёт перед sub_5646C0).
    constexpr DWORD kGetDbSrvIdx    = 0x004C0A30;
    // void  __thiscall SendNoticeClient(void* mgr, const char* text)  → 3113 всем
    constexpr DWORD kSendNotice     = 0x00547A80;

    // ── P13: обвязка чата (всё снято с recvGlobalChatClient@0x547670 = обработчик 5086) ──
    // int  __thiscall SendPacket(void* net, __int16 op, __int16 bodyLen, __int16 userIdx,
    //                            void* body, __int16 a6, int a7)
    //   net = *(void**)(pUserMng + 4). Кадр строит sub_5643E0: totalLen = bodyLen + 10
    //   (0xFB, WORD totalLen, WORD a7, WORD userIdx, WORD opcode, тело, 0xFE).
    constexpr DWORD kSendPacket     = 0x004C28F0;
    // int  __thiscall GetUserIdxAt(void* mgr, int i)   — i-й слот списка онлайна
    //   возвращает mgr[0x4C354 + i*4]; при i >= 0x226 возвращает -1 (конец обхода)
    constexpr DWORD kGetUserIdxAt   = 0x00523E50;
    // char __thiscall IsUserInGame(void* mgr, __int16 idx)  — байт CUser+0x190
    constexpr DWORD kIsUserInGame   = 0x00532670;
    // BOOL __thiscall IsChatBlocked(void* mgr, __int16 idx) — гейт ВСЕХ чат-опкодов
    //   диспетчера (`if (!sub_52EEA0(...)) handler(...)`): байт CUser+0x182D3 == 1
    constexpr DWORD kIsChatBlocked  = 0x0052EEA0;
    // char* __thiscall GetCharNamePtr(void* mgr, __int16 idx) → CUser+0x178 (20 б cp1251)
    constexpr DWORD kGetCharNamePtr = 0x00532570;
    // char __thiscall GetUserSubFlag(void* mgr, __int16 idx) — байт CUser+0x18C
    //   (поле +4 записи чат-лога 3670)
    constexpr DWORD kGetUserSubFlag = 0x00532530;
    // void* __thiscall ChatLogRecInit(void* rec) — обнуление 106-байтовой записи чат-лога
    constexpr DWORD kChatLogRecInit = 0x00560DC0;
    // BOOL __thiscall ConnectSend(void* net, __int16 op, __int16 len, __int16 conn,
    //                             void* body, __int16 userIdx)   — отправка серверу-соседу
    constexpr DWORD kConnectSend    = 0x005646C0;
    // int  __thiscall GetChatSrvIdx(void* net) — WORD net+0x4960, индекс соединения
    //   лог-сервера чата (-1, если не подключён)
    constexpr DWORD kGetChatSrvIdx  = 0x004C0A90;
    // глобальный CUserMoveManager (this для ConnectSend); тот же, что в P11
    constexpr DWORD kNetMoveMgr     = 0x007E0538;
    // указатель на таблицу настроек серверов: запись 0xEC байт, +0x3F = тип карты.
    // Индекс записи = *(DWORD*)(*(DWORD*)(pUserMng + 4) + 0x4950).
    // Тип 4 = сервер, на котором recvGlobalChatClient выключает глобальный чат.
    constexpr DWORD kServerCfgTable = 0x005F5E18;
    constexpr int   kSrvCfgRecSize  = 0xEC;
    constexpr int   kOffSrvCfgIndex = 0x4950;   // в объекте *(pUserMng+4)
    constexpr int   kOffSrvMapType  = 0x3F;     // в записи таблицы
    constexpr int   kSrvMapTypeNoGlobalChat = 4;

    constexpr int   kLogCatItem     = 1;    // Log\Log_Item\ItemLog_<дата>.txt
    constexpr int   kLogCatOperator = 6;    // Log\Log_Operator\OperatorLog_<дата>.txt

    constexpr WORD  kOpItemAcquired = 6131; // S→C «игрок получил редкий предмет»
    constexpr int   kNoticeLen      = 44;   // длина тела 6131 (как в боссовой ветке оригинала)
    constexpr int   kItemCodeBase   = 20551;
    constexpr int   kOffCharName    = 376;  // CUser + 376 = имя персонажа (cp1251, 20 б)

    // ── P13: опкоды широких каналов чата ────────────────────────────────────
    constexpr WORD  kOpChatWideRecv = 6560;  // 0x19A0  C→S «Поиск отряда»/«Торговля»
    constexpr WORD  kOpChatWideSend = 6561;  // 0x19A1  S→C рассылка (Recv_WhisperOrSystemMessage)
    constexpr WORD  kOpChatLogDb    = 3670;  // 0x0E56  запись чата на лог-сервер (как у 5086)
    constexpr int   kChatLogRecLen  = 106;   // размер записи чат-лога 3670
    // ★ P14: РАЗМЕР БУФЕРА текста чата в наших патчах. В стоке было 80
    //   (`char chatText[80]` в recvGlobalChatClient); поднято до 160 — «вдвое».
    //   Это КОМПИЛЯТИВНАЯ ёмкость; ДЕЙСТВУЮЩИЙ предел лежит в g_chatMaxTextLen
    //   (Patches.h) и настраивается ключом [P14_ChatMessageLength] MaxTextLen.
    constexpr int   kChatMaxText      = 160;
    constexpr int   kChatMaxTextStock = 80;  // предел стока (и значение FixOverflowOnly=1)
    constexpr int   kChatWideHdrLen = 32;    // заголовок тела 6561 (клиент копирует 32 б)
    constexpr int   kFrameOverhead  = 10;    // totalLen = bodyLen + 10 (sub_5643E0)

    // ── смещения полей CUser, нужные P13 (все сняты дизассемблером) ─────────
    constexpr int   kOffUserNum     = 0x174; // int  — userNum; < 0 = слот не в игре
    constexpr int   kOffOnlineState = 0x2E;  // DWORD — должен быть == 1
    constexpr int   kOffChatSuppress= 0x141; // DWORD — должен быть == 0
    constexpr int   kOffUserSubFlag = 0x18C; // BYTE  — поле +4 записи чат-лога 3670
    constexpr int   kOffInGameFlag  = 0x190; // BYTE  — sub_532670

    // ── ★ P64 (A7/A8, 2026-10-12): поля состояния, которые читают стоковые предикаты диспетчера ──
    //   (все сняты дизасмом стока 4e20f0ad; тела предикатов побайтно равны живым e7b4ac38 — verify_p64.py)
    constexpr int   kOffDeadFlag     = 0x4F;    // DWORD — sub_4CB030 @0x4CB05D `mov edx,[ecx+4Fh]`; != 0 = мёртв
                                                //   (пишет sub_4CB070 @0x4CB0E7: CharMake тип 3 → 1, CharRegen* → 0)
    constexpr int   kOffExchangeFlag = 0x145;   // DWORD — sub_52BFF0 код 2 @0x52C070 `cmp [eax+145h],0` (обмен принят,
                                                //   CharExchangeAcceptReq @0x4DFF27 = 1)
    constexpr int   kOffStoreFlag    = 0x14D;   // DWORD — sub_52BFF0 код 4 @0x52C0DC `cmp [edx+14Dh],0` (личная лавка,
                                                //   CharSelfStoreReady @0x502D8C = 1)
    constexpr int   kOffAuctionFlag  = 0x15F;   // DWORD — sub_52BFF0 код 3 @0x52C0A6 `cmp [ecx+15Fh],0` (биржа: запрос
                                                //   в полёте, sub_521980 @0x5219AE)
    constexpr int   kOffFishingFlag  = 0x3F6B4; // BYTE  — sub_52BFF0 код 5 @0x52C10F `movzx ecx,byte [eax+3F6B4h]`
                                                //   (Recv_StartFishing @0x40F292 = 1)
    constexpr int   kOffSoulPartner  = 0x182B9; // DWORD — sub_52EE40 @0x52EE6D `cmp [ecx+182B9h],0` (> 0 = есть соулмейт)
    constexpr int   kOffSoulState    = 0x182D3; // BYTE  — sub_52EEA0 @0x52EECD (== 1 «душа»), sub_52EE40 @0x52EE79 (== 2 «одержим»)

    // ── точки перехвата (VA + оригинальные байты) ───────────────────────────
    // Значения проверены; ни один rel8/rel32/jcc во всей .text не ведёт ВНУТРЬ
    // этих диапазонов (проверено полным перебором кодировок по файлу).
    namespace Hooks
    {
        // P61 — ★ шифрование трафика (прослойка AsdaSecure), GameServer/Indun (15601). Зеркало L07 LM.
        //   Способ — замена call-инструкций + один детур входа SetConnectFlag. Межсервер (10000..10099)
        //   НЕ трогаем. Образ сток 4e20f0ad; живой/Indun e7b4ac38 — байты площадок идентичны (verify_p61.py).
        //   Приём клиента: единственная socket-recv в IoWorkerThread (sub_564900) —
        //     `call sub_563C20` @0x564CD5 (ecx=this CCircleQ; стек [+4]=buf, [+8]=size, [+0xC]=slot; ret 0xC).
        constexpr DWORD kP61RecvClientCall = 0x00564CD5;   // call sub_563C20 (5 б: e8 46 ef ff ff)
        constexpr DWORD kP61RecvSink       = 0x00563C20;   // сам sub_563C20
        //   Отправка: Ciocp::Send sub_561F20 (this=ecx; slot, Src, nBytes; ret 0xC). Три call-site.
        constexpr DWORD kP61SendCallA      = 0x004C2ACA;   // call sub_561F20 (5 б: e8 51 f4 09 00)
        constexpr DWORD kP61SendCallB      = 0x004C2BDC;   // call sub_561F20 (5 б: e8 3f f3 09 00)
        constexpr DWORD kP61SendCallC      = 0x0056435E;   // call sub_561F20 (5 б: e8 bd db ff ff)
        constexpr DWORD kP61SendFunc       = 0x00561F20;   // сам Ciocp::Send (зовётся напрямую для ServerHello)
        //   Reset канала: детур входа Ciocp::SetConnectFlag sub_562910 (accept/disc).
        constexpr DWORD kP61SetConnEntry   = 0x00562910;   // вход (5 б украсть: 55 8b ec 6a ff)
        constexpr DWORD kP61SetConnResume  = 0x00562915;   // продолжение тела после украденных 5 байт
        //   ★ В7d — активный разрыв при нарушении целостности: ШТАТНЫЙ путь стока «клиент закрыл соединение»
        //     (ветка нулевого приёма в IoWorkerThread @0x564B5E..0x564B83, дизасм сток 4e20f0ad):
        //       push slot; mov ecx,[ebp-24h]; call 0x5629C0 (Ciocp::GetConnectFlag); test; je;
        //       push slot; mov ecx,[ebp-24h]; call 0x561C30 (Ciocp::DisConnect); 0x564B83: jmp 0x564B92 → цикл.
        //     Ту же пару зовёт и стоковый кик sub_526E40 (___ExceptionDisConnetUser___, Hack Packet/Ping TimeOut).
        //     ecx на площадке приёма тот же [ebp-24h]. Обе функции thiscall(this, slot), ret 4.
        //     После разрыва трамплин возвращается на 0x564B83 (хвост стоковой ветки), минуя счётчик 0x564F30
        //     и ReadFile на закрытом сокете.
        constexpr DWORD kP61GetConnFlag    = 0x005629C0;   // Ciocp::GetConnectFlag (thiscall this,slot; ret 4)
        constexpr DWORD kP61DisConnect     = 0x00561C30;   // Ciocp::DisConnect     (thiscall this,slot; ret 4)
        constexpr DWORD kP61KillResume     = 0x00564B83;   // `jmp 0x564B92` (eb 0d) — хвост стоковой ветки разрыва

        // P01 — диспетчер клиентских пакетов sub_42A9D0, начало дерева сравнений
        constexpr DWORD kDispatch6616      = 0x0042AB5C;   // 81 BD 38 EF FF FF 75 17 00 00
        // общий хвост switch диспетчера (замер времени обработки пакета)
        constexpr DWORD kDispatchTail      = 0x0042F036;
        // P02 — ветка case 0x178E (6030) в диспетчере: цель call
        constexpr DWORD kGmNotice6030Call  = 0x0042CF5D;   // E8 9E 40 12 00  (call 0x551000)
        // P03 — Recv_OperatorCommand_Add
        constexpr DWORD kSkillPointLog     = 0x00551530;   // 8B 8D F4 FB FF FF E8 E5 D4 FD FF
        // P04 — Recv_OperatorCommand_Invincible
        constexpr DWORD kInvincibleGate    = 0x005518FF;   // 8B 55 F4 83 BA 3D BC 03 00 01
        // P05 — Recv_UserPrimiumGaCha
        constexpr DWORD kPrimiumGacha      = 0x004F7084;   // 26 байт
        // P06 — sub_4F6650
        constexpr DWORD kDb2601            = 0x004F6CA5;   // 89 95 43 FD FF FF
        // P07 — sub_43C690
        constexpr DWORD kSub43C690         = 0x0043C6DD;   // 8B 45 E0 8B 88 53 04 00 00
        // P08 — Char_FunctionItem_Use (⚠ снятие проверки, чужой обход)
        constexpr DWORD kFunctionItemUse   = 0x004ED8DE;   // E8 1D 66 03 00 85 C0 75 42
        // ★ P15 — Char_FunctionItem_Use: bounds-check кода предмета (НАША правка, не перенос).
        //   Первое из шести обращений к Function_Table по индексу (iCode-1)*48 без проверки:
        //   004ED9EF  8B 85 02 FE FF FF  mov eax,[ebp-0x1FE]   ← перехват (6 б)
        //   004ED9F5  83 E8 01 / 6B C0 30 / 8B 0D 70 5E 5F 00 / 0F B6 54 01 08
        constexpr DWORD kFunctionItemBounds = 0x004ED9EF;   // 8B 85 02 FE FF FF
        // ★ P16 — sub_4F7D10 (`RecvDB_InsertPremiumItem`, ответ БД на 2601), ветка
        //   «гача» (BuyType == 3). Площадка стоит ПОСЛЕ дозаполнения тела 6578
        //   стоком и ДО первого push аргументов отправки — стек здесь чистый:
        //     004F7E40  6A 00              push 0                  ← перехват (7 б)
        //     004F7E42  66 8B 45 08        mov  ax,[ebp+8]
        //     004F7E46  50                 push eax
        //     004F7E47  8D 8D 3C FF FF FF  lea  ecx,[ebp-0xC4]     ← возврат
        //   Безопасность: полный перебор кодировок rel8/rel32/jcc32 по .text +
        //   скан всех DWORD образа — входов в 0x4F7E41…0x4F7E46 ноль.
        constexpr DWORD kGachaPrizeToInven = 0x004F7E40;   // 6A 00 66 8B 45 08 50

        // ★ P09 УДАЛЁН 2026-08-17: это был чужой обход белого списка товаров кэш-шопа.
        //   Вместо него доделаны данные — SellItemTable.txt пересобран (415 кодов,
        //   iMaxItemCode 79428). Адреса площадок (0x5120B2/0x5120FF/0x512725/0x512772)
        //   сохранены в AstoryServer/Patches/AsdaPatch/removed/p09_chargeshop_checks_off.cpp.
        // P10 — Send_SectorInAddMonsterInfo / Send_SectorInNewAddMonsterInfo
        constexpr DWORD kSectorAddMonster  = 0x0041DE10;   // начало функции
        constexpr DWORD kSectorNewAddMon   = 0x004250A0;
        // P11 — серверные источники анонса
        constexpr DWORD kPickEpilogue      = 0x004D5E61;   // 8B 4D F4 33 CD          (CharItemPicking)
        constexpr DWORD kGachaSuccess      = 0x004F5637;   // 83 C4 1C EB 2A          (Recv_GachaItemUse)
        constexpr DWORD kPGachaSuccess     = 0x004F766E;   // B9 38 05 7E 00          (Recv_UserPrimiumGaChaReward)
        constexpr DWORD kRefineSuccess     = 0x00500602;   // 0F B6 8D EE FE FF FF    (CharShellItemUpgrade_0)
        // ★ P11 (доработка 2026-08-06) — ВХОД ВЕТКИ НЕУДАЧИ заточки, 7 байт:
        //   004FFFC5  C6 85 38 FE FF FF 08   mov byte [ebp-0x1C8], 8   (возврат 0x4FFFCC)
        //   Нужен потому, что дальше по ветке сервер ОБНУЛЯЕТ ступень и процент
        //   (0x500009 `mov byte [ebp-0x208],0`, 0x500010 `mov word [ebp-0x205],0`,
        //   а также второй такой же блок 0x500080/0x500087), и хук kRefineSuccess,
        //   стоящий ПОСЛЕ них, читает нули -> анонс неудачи рубился порогом.
        //   Здесь снимаем «ступень/процент ДО броска».
        //   Безопасность площадки (перебор ВСЕХ кодировок rel8/rel32/jcc/loop по .text
        //   + скан всех DWORD по образу): входов ровно два, оба на ПЕРВЫЙ байт —
        //   0x4FFF16 `jl` и 0x4FFF2A `jbe` (две половины 64-битного сравнения);
        //   внутрь 0x4FFFC6..0x4FFFCB не ведёт ничего (единственное срабатывание
        //   сканера 0x50003D -> 0x4FFFCA ложное: это операнд `jne` из `75 74`@0x50003C);
        //   абсолютных ссылок/таблиц переходов — ноль.
        //   ⇒ CFG-обход функции: 0x500602 НЕдостижим, если перерезать обе ветки
        //   исхода (0x4FFF30 успех / 0x4FFFC5 неудача), циклов в функции нет,
        //   флаг ok [ebp-0x112] пишется только в прологе (0) и на успехе (1)
        //   ⇒ `ok == 0` в хуке ⟺ прошли ровно через эту площадку.
        constexpr DWORD kRefineFailEntry   = 0x004FFFC5;   // C6 85 38 FE FF FF 08
        // P12 — строка IP по умолчанию в .rdata
        constexpr DWORD kDefaultIpString   = 0x00585610;   // "61.106.140.2xx"
        // P13 — ОБЩАЯ ветка default диспетчера sub_42A9D0 (IDA: def_42AC29).
        //   0042F020  0F BF 4D BC  movsx ecx, word ptr [ebp-0x44]
        //   0042F024  51           push  ecx
        //   0042F025  ... mov ecx, [[ebp-0x10C4]+4]+0x34 ; call sub_5244B0 (счётчик «мусорных»
        //                пакетов CUser+0x1E; после 6 штук sub_5244F0 считает клиента плохим)
        //   0042F036  общий хвост switch (kDispatchTail)
        //   Сюда сходятся ВСЕ default-ветки: 14 прямых jcc + записи 5 jump-таблиц.
        //   Проверено полным перебором кодировок по .text стока: ни один rel8/rel32
        //   не ведёт ВНУТРЬ 0x42F021..0x42F024 (0 совпадений) ⇒ 5 байт можно занять jmp.
        //   6560 (0x19A0) попадает сюда из `cmp [ebp-0x10C8],0FDh / ja` @0x42ADC9:
        //   таблица покрывает 0x189E..0x199B, 0x19A0 выше верхней границы.
        constexpr DWORD kDispatchDefault   = 0x0042F020;   // 0F BF 4D BC 51

        // ── P14 — длина сообщения чата + фикс трёх переполнений стека ───────
        //  Патч точечный: у каждой функции правятся кадр, ссылки на текстовый
        //  буфер, вызов memset, площадка зажима длины и гейт `<= 80`. Полная
        //  таблица из 52 площадок (адрес + оригинальные байты) живёт в
        //  src\patches\p14_chat_message_length.cpp — вынести её сюда нельзя,
        //  она осмысленна только вместе с раскладкой кадра каждой функции.
        //  Здесь — только точки входа обработчиков (проверены дизассемблером).
        constexpr DWORD kChatShout5084     = 0x005471A0;   // Recv_NormalChatClient
        constexpr DWORD kChatGlobal5086    = 0x00547670;   // recvGlobalChatClient
        constexpr DWORD kChatClan4120      = 0x00403F50;   // sub_403F50   (CClanManager)
        constexpr DWORD kChatWhisper5088   = 0x00547BD0;   // sub_547BD0
        constexpr DWORD kChatParty5105     = 0x00450FB0;   // sub_450FB0   (CPartyManager)
        constexpr DWORD kChatWhisperDeliver= 0x00547EB0;   // sub_547EB0 -> рассылка 5089
        constexpr DWORD kChatPartyDeliver  = 0x00451210;   // sub_451210 -> рассылка 5106
        // ⚠ 0x547030 — НЕ обработчик 5084 (ошибка ТЗ): это Send_CharAttackMotion.
        // ⚠ 6718 (чат армии) @0x466F50 намеренно НЕ патчится: пересылка 6719
        //    имеет фиксированную длину 101 и подписывается MD5 (sub_523F00, 0x6C).

        // ★ P29 — потолок уровня игрока: команды `cmp r32, 0x3B` (imm8 в VA+2).
        //   Байты сверены со стоком, живым GameServer, живым Indun_GameServer (2026-09-11).
        constexpr DWORD kLvlCapPartyExp    = 0x004C7F63;   // 83 FA 3B 7C 05  sub_4C7C70 PartyExpProcess
        constexpr DWORD kLvlCapSoulJarExp  = 0x004C8D91;   // 83 FA 3B 7C 05  sub_4C8CB0 SetForwardSoulJarExp
        constexpr DWORD kLvlCapMobExp      = 0x004CBB61;   // 83 FA 3B 7C 05  Recv_BattleServerFromCharParamExp_1
        constexpr DWORD kLvlCapExpUpDown   = 0x004CC592;   // 83 FA 3B 7C 0E  GetExpUpDownValue
        constexpr DWORD kLvlCapSoulJarReq  = 0x00495426;   // 83 F8 3B 7C 42  SoulJar_RequestUser_Req
        constexpr DWORD kLvlCapSmSkill31   = 0x0049D077;   // 83 F8 3B 7C 11  RecvChar_SoulMateSkillUse
        constexpr DWORD kLvlCapStatPoints  = 0x0052E8DA;   // 83 F8 3B 7F 17  sub_52E8A0 (+2 очка НАВЫКОВ, CUser+0x19B; имя константы — историческое)

        // ★ P30 — число слотов карт (массив «карта открыта + имя» из OpenMapInfo.ini).
        //   Стоковый массив: 23 записи по 0x33 б по VA 0x0060A880 (.bss, впритык к
        //   объекту CThreadManager на 0x0060AD18 — растянуть нельзя, только перенести).
        //   Байты сверены со стоком, живым GameServer, живым Indun_GameServer и
        //   декомпильным образом (2026-09-12) — совпали во всех четырёх.
        constexpr DWORD kMapSlotsArray     = 0x0060A880;   // база стокового массива (.bss)
        constexpr DWORD kMapSlotsCountGate = 0x004A043E;   // 83 F8 17              cmp eax,23 — граница MapCount
        constexpr DWORD kMapSlotsCountMsg  = 0x004A044B;   // 6A 17                 push 23 — «Max %d» в тексте ошибки
        constexpr DWORD kMapSlotsReadLoop  = 0x004A04AE;   // 83 BD 54EAFFFF 17     цикл чтения MAP_0…MAP_22
        constexpr DWORD kMapSlotsWriteUse  = 0x004A04FD;   // 88 8A 80A86000        запись Use
        constexpr DWORD kMapSlotsNameAddr  = 0x004A0513;   // 05 81A86000           адрес поля Name (база+1)
        constexpr DWORD kMapSlotsReadUse   = 0x004A0536;   // 0F B6 82 80A86000     чтение Use (счётчик открытых)
        constexpr DWORD kMapSlotsThrLoop   = 0x004A537F;   // 83 7D D0 17           цикл раздачи потоков картам
        constexpr DWORD kMapSlotsThrUse    = 0x004A538F;   // 0F B6 91 80A86000     Use в том же цикле
        constexpr DWORD kMapSlotsPortalUse = 0x0052C610;   // 0F B6 88 80A86000     «карта-цель открыта?» у портала
        constexpr DWORD kMapSlotsCtorCount = 0x00582678;   // 6A 17                 счётчик в конструкторе
        constexpr DWORD kMapSlotsCtorBase  = 0x0058267C;   // 68 80A86000           база в конструкторе
    }

    // ── смещения в кадрах стека (для трамплинов P11) ────────────────────────
    namespace Frame
    {
        // CharItemPicking@0x4D43A0
        constexpr int kPickResult   = -0x0B4;   // char  — 1 = успешный подбор
        constexpr int kPickItemRec  = -0x560;   // BYTE[60] — запись предмета (+0 = код)
        constexpr int kPickMgr      = -0x5F0;   // CUserManager*
        // Recv_GachaItemUse@0x4F48C0
        constexpr int kGachaPrize   = -0x0D4;   // int  — код ВЫИГРЫША (не коробки!)
        constexpr int kGachaBox     = -0x084;   // BYTE[60] — вскрытая коробка
        constexpr int kGachaMgr     = -0x194;
        // Recv_UserPrimiumGaChaReward@0x4F72B0
        constexpr int kPGachaCode   = -0x0D9;   // int  — код награды (пришёл от клиента)
        constexpr int kPGachaMgr    = -0x160;
        // CharShellItemUpgrade_0@0x4FEE50
        constexpr int kRefineOk     = -0x112;   // char — 1 = заточка удалась
        constexpr int kRefineItem   = -0x220;   // BYTE[60] — запись предмета
        constexpr int kRefineLevel  = -0x208;   // = kRefineItem + 24 — уровень «+N»
        constexpr int kRefinePct    = -0x205;   // = kRefineItem + 27 — WORD накопленный процент
        constexpr int kRefineTries  = -0x207;   // = kRefineItem + 25 — счётчик попыток
        constexpr int kRefineResult = -0x1C8;   // byte — код ответа клиенту (1 успех / 8 неудача)
        constexpr int kRefineMgr    = -0x2EC;
        constexpr int kRefineUserId = 8;        // [ebp+8] WORD — индекс игрока (arg_0)
        constexpr int kItemRecLevel = 24;       // байт «+N» в 57-байтовой записи предмета
        constexpr int kItemRecPct   = 27;       // WORD «процент» в той же записи
    }
}
