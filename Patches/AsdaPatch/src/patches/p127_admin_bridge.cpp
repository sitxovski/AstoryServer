// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P127 — МОСТ АДМИН-ЦЕНТРА (волна А2 «живой канал», 18.11.2026). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Разбор: Reports/admin_center/research_admin_bridge.md; документ: AstoryServer/Docs/GameServer/admin-bridge-p127.md;
//
//  РЕШЕНИЯ ВЛАДЕЛЬЦА 18.11: панели не важно, в игре ли игрок; транспорт — ОЧЕРЕДЬ В БАЗЕ AsdaAdmin (эта нить опрашивает её своим
//  ODBC, как P53 AcJournal); логин asda_bridge — только EXECUTE на adm.Bridge*; HMAC команд; каждая команда — не больше одного раза;
//  игрок вышел до выполнения — «нет на сервере»; «кто в игре» — adm.bridge_presence + пульс узла; выполнение — на нити карты игрока
//  на общей точке UserTick (0x526CEB, стаб P73 — второй врезки нет); мост на все 3 GameServer; первая выкладка — Mode=0.
//
//  ── ПОТОКИ ──
//   • Нить моста (своя): ODBC к AsdaAdmin, раз в PollMs — итоги команд (adm.BridgeResult), изменения присутствия
//     (adm.BridgePresenceSet/Del), захват (adm.BridgeClaim: UPDATE … OUTPUT — строка достаётся ровно одному узлу), проверка HMAC,
//     раскладка команды в очередь слота; раз в HeartbeatSec — пульс (adm.BridgeHeartbeat). Сеть и ожидания — только здесь.
//   • Нить карты (такт игрока, ~1 с; P73_OnCheckUser → P127_OnUserTick): снимок CUser в таблицу слота (учётка +0x174, слот
//     персонажа +0x18C, имя +0x178, карта [[mgr+4]+0x4950], клетка +0x54E6/+0x54E8, «в мире» +0x2E == 1, учётка сессии —
//     P48_IdentityOf) и выполнение команды слота функциями стока. Внутри листового замка — только копии, ни одного вызова наружу.
//   • Нить IOCP (P73_OnConnFlag → P127_OnConnFlag, под замком Ciocp) и диспетчер (P73_OnLogon → P127_OnLogon): только таблица слота.
//
//  ── КОМАНДЫ (op) ──
//   ping     — снимок «кто/где» с такта игрока (только чтение; выполняется и в Mode=0);
//   kick     — штатная пара стока Send_DisConnectType@0x52EDB0 (4101, тип KickType, умолчание 0 «Default» таблицы 0x5A62AC →
//              у клиента нотис 1002 «Сервер разорвал соединение») + ___ExceptionDisConnetUser___@0x526E40 → … AcceptStackClear@0x5236A0
//              → DisConnectUser@0x5245D0 (штатный выход с записью в БД), продолжение цикла 0x526E36 — как P73. P48 не засчитывает
//              (P127_KickInProgress, код 8), P58 — причина «AdminBridge(P127)»;
//   announce — sendNoticeClient@0x547A80 (3113, 107 б: +2 режим 0, +4 текст cp1251 ≤ 95, +100 RGB) — по разу на КАЖДЫЙ CUserManager
//              узла (функция рассылает только своему менеджеру), на такте любого его игрока;
//   move     — перенос на другую карту по клетке: общая точка P123_PortalMoveTo (проверки P123 + 5055 код 1).
//   give     — ★ А2.3 (v82): выдача предмета — перенос хвоста Recv_OperatorCommand_ItemGive@0x552360 после гейтов отправителя
//              (GS:129854–130320): ветки Function / Cellob / Item_Table (стопка 1…19, колчан, расходник, снаряжение), отказы стока 1…7,
//              ячейка sub_4D6740 (для F — через P100 площадку A4: P100_GmGivePick), стопка sub_4D6CE0, заряды FT+13 через P100_ChargesAt,
//              опции/самоцвет/ступень — ВЫБОР ОПЕРАТОРА (панель; «Случайно» — srvtables.roll_creation), сверенные с таблицами в памяти;
//              2231 UPGmItemAdd (оператор = служебный ADM_sitxovski 2/11, решение владельца) → запись в память (P100_WriteMerged —
//              площадка 0x5533A6), вес sub_43F880, 6044 цели. Журнал пишет сама процедура (JoyLog1.AdminItemLog); 6043 «оператору» не шлётся;
//   jump     — ★ А2.3 (v82): перенос в пределах своей карты — гейты CharJumpCommandPosition@0x54EF50 после проверок отправителя
//              (sub_4221D0 границы, sub_523ED0/523EA0 стоп хода, sub_41EC30 ближайшая проходимая), затем стоковая
//              CharJumpCommandPosition_0@0x54EBF0 (сектор, клетка CUser, 4056 себе и сектору, MapItem, монстры/NPC — как sub_521770).
//  Остальное — путь «кик + офлайн-запись» панели.
//
//  ── AT-MOST-ONCE ──
//   Захваченная строка (status 1) повторно не берётся никем; номер уже обработанной команды помнит и эта нить (кольцо 1024).
//   Сбой между выполнением и записью итога → строка остаётся в status 1 («неизвестно — проверьте»), повтора нет.
//   Сверка цели на такте: CUser+0x174 == Userindex, CUser+0x18C == Charidx и поколение соединения слота то же, что при захвате.
//
//  Откат: [P127_AdminBridge] Enabled=0 — ничего не ставится (UserTick остаётся только у P73 Mode=1).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <sql.h>
#include <sqlext.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <initializer_list>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    const wchar_t* kSec = L"P127_AdminBridge";
    constexpr int kProto = 2;                 // версия протокола моста (adm.bridge_node.proto; ★ ревизия 24: подпись "v2" — со сроком)

    constexpr int kSlots        = 0x226;      // userNum 0…549 (sub_5328F0)
    constexpr int kOffUserIndex = 0x174;      // CUser: учётка-владелец
    constexpr int kOffCharSlot  = 0x18C;      // CUser: слот персонажа (BYTE)
    constexpr int kOffInWorld   = 0x2E;       // CUser: 1 — в мире (CharMake/CharPortalMake)
    constexpr int kOffTileX     = 0x54E6;     // CUser: i16 клетка X (как P123)
    constexpr int kOffTileZ     = 0x54E8;
    constexpr int kOffThread    = 4;          // CUserManager+4 → поток карты
    constexpr int kOffMapIdx    = 0x4950;     // поток+0x4950 → номер карты (P120/P123)
    constexpr int kNoticeBody   = 107;        // тело 3113 (sendNoticeClient копирует 107 б с a2+9)
    constexpr int kNoticeText   = 95;         // текст ASCIIZ с +4, клиент читает ≤ 96 б
    constexpr int kMaxGlobal    = 8;          // одновременных объявлений
    constexpr int kMaxMgr       = 64;         // CUserManager-ов узла (нитей карт) в учёте объявления
    constexpr int kResCap       = 512;        // кольцо итогов
    constexpr int kDoneIds      = 1024;       // память обработанных номеров

    // ★ А2.2 (v81): + probe (снимок уровня/опыта/звания — только чтение), exp (опыт/уровень событием стока), title_add / title_del,
    //   fame_recalc (пересчёт №3 P25 одному игроку), notice (3113 одному игроку)
    // ★ А2.3 (v82): + give (выдача предмета), jump (перенос в своей карте)
    // ★ А5.2 (v83): + mob_pop (6045 — вызвать группу монстров к оператору), mob_return (6046 — вернуть группу)
    // ★ А5.4 (v84): + event_set (6038 — событие опыта/добычи), event_off (6040 — выключить), rank_recalc (6020 — пересчитать рейтинги)
    enum Op { kOpNone = 0, kOpPing, kOpKick, kOpAnnounce, kOpMove, kOpProbe, kOpExp, kOpTitleAdd, kOpTitleDel, kOpFame, kOpNotice,
              kOpGive, kOpJump, kOpMobPop, kOpMobReturn, kOpEventSet, kOpEventOff, kOpRankRecalc };
    enum Status { kStDone = 2, kStRefused = 3, kStAbsent = 4, kStJournal = 6 };

    // ── настройки ──
    volatile LONG g_enabled = 0;
    int     g_mode        = 0;                // 0 — только слушать, 1 — исполнять
    int     g_pollMs      = 500;
    int     g_heartbeatS  = 5;
    int     g_snapshotS   = 5;                // клетка игрока в присутствии обновляется не чаще
    int     g_pendingS    = 30;               // команда слота, не дошедшая до такта за столько, — «нет на сервере»
    int     g_kickType    = 0;                // 4101: 0 «Default» → клиент 1002 «Сервер разорвал соединение»
    int     g_claimMax    = 16;
    int     g_loginTo     = 5, g_queryTo = 10, g_reconnectS = 10;
    bool    g_soulSession = true;             // учётка сессии при входе соулмейтом (как P48)
    wchar_t g_node[33]    = L"";              // имя узла = папка exe
    wchar_t g_conn[1024]  = L"";              // строка ODBC (с паролем — не печатается)
    BYTE    g_key[64]     = {};               // ключ HMAC
    int     g_keyLen      = 0;

    // ── функции GameServer ──
    typedef void  (__fastcall *PFN_Disc)(void* self, void* edx, int userNum, int type);           // sub_52EDB0
    typedef void* (__fastcall *PFN_ExcDisc)(void* self, void* edx, int userNum, const char* fn);  // sub_526E40
    typedef int   (__fastcall *PFN_Notice)(void* mgr, void* edx, const BYTE* frameLike);          // sendNoticeClient 0x547A80
    typedef int   (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, const void* buf, int a6, int a7); // sub_4C28F0
    typedef char  (__fastcall *PFN_Fame)(void* mgr, void* edx, int userNum, int titleId);          // AddFameBit 0x54A980 / sub_54A7D0 (thiscall i16,i16; ret 8)
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                        // sub_569DF0
    PFN_Disc    const pDisc    = (PFN_Disc)   0x0052EDB0;
    PFN_ExcDisc const pExcDisc = (PFN_ExcDisc)0x00526E40;
    PFN_Notice  const pNotice  = (PFN_Notice) Srv::kSendNotice;
    PFN_ToClient const pToClient = (PFN_ToClient)Srv::kSendPacket;
    PFN_Fame    const pAddFame   = (PFN_Fame)  0x0054A980;   // AddFameBit: бит, очки, 2256 в базу (★ ревизия 25: 2257 — не он; id ≥ 256 — трамплин P21, 2331)
    PFN_Fame    const pFameSet   = (PFN_Fame)  0x0054A610;   // каскад наборов: собранный набор → звание набора (как сток после выдачи)
    typedef bool  (__fastcall *PFN_NotOwned)(void* mgr, void* edx, int userNum, int titleId, BYTE* b1, BYTE* b2);   // sub_54A890 ret 10h
    PFN_NotOwned const pNotOwned = (PFN_NotOwned)0x0054A890;   // true — звания НЕТ (как P25)
    constexpr int   kOffFameFound = 0x17E00;                  // CUser: маска «найдено» (4 qword; ниже 256)
    constexpr int   kOffFameRecs  = 0x17DFC;                  // CUser: ptr записей прогресса по 44 б (как P25)
    constexpr DWORD kVaFameTable  = 0x007DFFD8;               // FameInfo: запись 96 б, +4 порог (как P25)
    constexpr int   kTitleCount30 = 21;                       // звание «собрать N званий» — счётчик стоковой выдачи
    PFN_Fame    const pFameNote  = (PFN_Fame)  0x0054A7D0;   // нотис 6065 «звание получено» (sub_52E630 себе и сектору)
    const BYTE kFameOrig[3] = { 0x55, 0x8B, 0xEC };
    // ★ А2.2: что умеет узел (зависит от установленных патчей — общие точки сверены ими)
    bool g_canExp = false, g_canTitleAdd = false, g_canTitleDel = false, g_canFame = false;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;
    // начала вызываемых функций стока (сверка перед установкой)
    const BYTE kDiscOrig[3]   = { 0x55, 0x8B, 0xEC };     // 0x52EDB0 push ebp; mov ebp,esp
    const BYTE kExcOrig[3]    = { 0x55, 0x8B, 0xEC };     // 0x526E40
    const BYTE kNoticeOrig[3] = { 0x55, 0x8B, 0xEC };     // 0x547A80
    const BYTE kPrologue[3]   = { 0x55, 0x8B, 0xEC };     // ★ А2.3: пролог всех функций стока выдачи/переноса (снят дизасмом 19.11)

    // ── ★ А2.3: выдача предмета (хвост Recv_OperatorCommand_ItemGive@0x552360; соглашения — дизасм 19.11) ──
    typedef short (__fastcall *PFN_ParamW)(void* param, void* edx, int userNum);                       // sub_43FA00 текущий / sub_43FB20 предел, ret 4
    typedef int   (__fastcall *PFN_AddW)(void* param, void* edx, int userNum, int w, int a4, int a5); // sub_43F880(num, вес, 1, 0), ret 10h
    typedef int   (__fastcall *PFN_Router)(void* mgr, void* edx, int userNum, int plate, int after);  // sub_4D6740 свободная ячейка, ret 0Ch
    typedef int*  (__fastcall *PFN_Same)(void* mgr, void* edx, int* out, int userNum, int plate, int code); // sub_4D6CE0 {кол-во, ячейка<<16|вес}, ret 10h
    typedef void* (__fastcall *PFN_RecInit)(void* rec, void* edx);                                    // sub_40A9F0 заготовка записи 57 б, ret
    typedef int   (__fastcall *PFN_DbSend)(void* dbm, void* edx, int op, int len, int conn, void* body, int userNum); // sub_5646C0, ret 14h
    typedef int   (__fastcall *PFN_Conn)(void* thread, void* edx);                                    // sub_4C0A30 номер соединения БД потока, ret
    typedef char  (__fastcall *PFN_SlotOf)(void* mgr, void* edx, int userNum);                         // sub_532530 слот персонажа, ret 4
    typedef int   (__fastcall *PFN_UidOf)(void* mgr, void* edx, int userNum);                          // sub_5324F0 UserIndex, ret 4
    typedef char  (__fastcall *PFN_Group)(void* self, void* edx);                                      // sub_4A7EA0 (ecx=0x60AD18) группа серверов, ret
    typedef BOOL  (__cdecl    *PFN_InRange)(int code);                                                 // sub_532B10 / 532AE0 / 532A90
    PFN_ParamW  const pWCur    = (PFN_ParamW) 0x0043FA00;
    PFN_ParamW  const pWMax    = (PFN_ParamW) 0x0043FB20;
    PFN_AddW    const pAddW    = (PFN_AddW)   0x0043F880;
    PFN_Router  const pRouter  = (PFN_Router) 0x004D6740;
    PFN_Same    const pSame    = (PFN_Same)   0x004D6CE0;
    PFN_RecInit const pRecInit = (PFN_RecInit)0x0040A9F0;
    PFN_DbSend  const pDbSend  = (PFN_DbSend) 0x005646C0;
    PFN_Conn    const pConn    = (PFN_Conn)   0x004C0A30;
    PFN_SlotOf  const pSlotOf  = (PFN_SlotOf) 0x00532530;
    PFN_UidOf   const pUidOf   = (PFN_UidOf)  0x005324F0;
    PFN_Group   const pGroup   = (PFN_Group)  0x004A7EA0;
    PFN_InRange const pIsF     = (PFN_InRange)0x00532B10;
    PFN_InRange const pIsC     = (PFN_InRange)0x00532AE0;
    PFN_InRange const pIsI     = (PFN_InRange)0x00532A90;
    constexpr DWORD kVaDbMgr     = 0x007E0538;    // ecx sub_5646C0 (DBManager-очередь)
    constexpr DWORD kVaThreadMgr = 0x0060AD18;    // ecx sub_4A7EA0 / sub_4B7B00
    constexpr DWORD kVaFT = 0x005F5E70, kVaCT = 0x005F5E8C, kVaIT = 0x005F5E98;   // Function 48 б / Cellob 43 б / Item 71 б
    constexpr DWORD kVaOptGroups = 0x005F5E90, kVaOptCount = 0x005F5EBC;          // группы опций (5 б: u8 n, ptr записей 128 б)
    constexpr DWORD kVaSowel = 0x007DFFC4, kVaSowelCount = 0x007DFFC8;            // SowelCombine 172 б (ступень +8+j, самоцвет +60+4i, MaxUp +146)
    constexpr int   kGmOperUid  = 2;              // оператор в UPGmItemAdd: ADM_sitxovski (учётка 2, слот 11) — решение владельца 18.11, SELECT 19.11
    constexpr int   kGmOperSlot = 11;
    constexpr int   kGiveCopiesMax = 30;          // штук за команду (по 2231 на штуку; итог перечисляет ячейки — ≤ 400 символов)
    constexpr int   kGiveStackMax  = 19 * 30;     // стопкой за команду: сток даёт 1…19 за раз → до 30 стоковых выдач

    // ── ★ А2.3: перенос в своей карте (гейты CharJumpCommandPosition@0x54EF50, ядро CharJumpCommandPosition_0@0x54EBF0) ──
    typedef BOOL  (__fastcall *PFN_InMap)(void* map, void* edx, int x, int z);                          // sub_4221D0, ret 8
    typedef int   (__fastcall *PFN_Moving)(void* mgr, void* edx, int userNum);                          // sub_523ED0, ret 4
    typedef char  (__fastcall *PFN_StopMove)(void* mgr, void* edx, int userNum, const char* fn);        // sub_523EA0, ret 8
    typedef int*  (__fastcall *PFN_Nearest)(void* map, void* edx, int* out, int x, int z, float fx, float fz); // sub_41EC30, ret 14h
    typedef int   (__fastcall *PFN_Jump0)(void* mgr, void* edx, int userNum, int x, int z);              // 0x54EBF0, ret 0Ch
    PFN_InMap    const pInMap    = (PFN_InMap)   0x004221D0;
    PFN_Moving   const pMoving   = (PFN_Moving)  0x00523ED0;
    PFN_StopMove const pStopMove = (PFN_StopMove)0x00523EA0;
    PFN_Nearest  const pNearest  = (PFN_Nearest) 0x0041EC30;
    PFN_Jump0    const pJump0    = (PFN_Jump0)   0x0054EBF0;
    constexpr int kOffMapMgr = 0x0C;              // поток+0x0C → CMapManager карты
    bool g_canGive = false, g_canJump = false;

    // ═════════════════ ★ А5.2 (v83, 21.11.2026): призыв / возврат группы монстров (6045 / 6046) ═════════════════
    // Сток (GameServer.c:130327-130389, Recv_OperatorCommand_MonsterPop@0x5534C0 / MonsterReturn@0x553640): гейты — слот < 550,
    //   ОПЕРАТОР sub_52ECF0 (UserIndex 0…5000), токен, MD5; под P47 в диспетчере ещё GM-флаг sub_52ED50 (байт CUser+0x40B9F). Действие —
    //   ТОЛЬКО пересылка в NpcServer: sub_5646C0(CUserMoveManager, 6045|6046, 5|4, sub_4C0A60(поток карты), тело, userNum), тело
    //   {u16 userNum оператора (сервер перезаписывает), u16 номер группы, [u8 режим 6045: 0 — точка спавна ровно у оператора, ≠0 —
    //   случайная в своём прямоугольнике]}. NpcServer (CAi::Process_MonsterCall / Process_MonsterReturn) берёт координаты ИГРОКА-оператора
    //   из своей записи (поэтому нужен живой оператор на этой карте — цель команды), ответа нет. Мост делает ровно то же, что
    //   обработчик стока, в нити карты оператора (такт UserTick), без подделки пакета: те же гейты (оператор + GM-флаг), тот же вызов.
    typedef int   (__fastcall *PFN_ConnSend)(void* net, void* edx, int op, int len, int conn, const void* body, int userNum);   // 0x5646C0, ret 14h
    typedef int   (__fastcall *PFN_NpcConn)(void* thread, void* edx);                                                        // 0x4C0A60
    PFN_ConnSend const pConnSend = (PFN_ConnSend)0x005646C0;
    PFN_NpcConn  const pNpcConn  = (PFN_NpcConn) 0x004C0A60;
    constexpr int kOffGmFlag   = 0x40B9F;         // CUser+0x40B9F — GM-флаг (sub_52ED50; P47)
    constexpr int kOperatorMax = 5000;            // sub_52ECF0: UserIndex 0…5000
    bool g_canMob = false;

    // ★ А5.4 (v84): 6038 EventSet / 6040 EventOff / 6020 пересчёт рейтингов от имени оператора-цели (нить его карты).
    //   Сток (GameServer.c:129575-129830, Recv_OperatorCommand_EventSet@0x551BF0 / EventOff@0x5520A0): гейты — слот, оператор
    //   sub_52ECF0, GM-флаг sub_52ED50 (P47 и сам сток), токен, MD5; затем тело с затёртой шапкой {u16 (BYTE)sub_4A7EB0() — канал GS,
    //   u16 sub_40C960(mgr) — система GS, u16 userNum оператора} и проверки диапазонов (6038: месяцы 1…12, дни 1…31, часы ≤ 24,
    //   минуты ≤ 60 — беззнаково, тип < 2, значение 0.0…10.0; 6040: тип < 2); прошло — sub_5646C0(CUserMoveManager, 6038|6040, 29|15,
    //   sub_4C0A90(поток) — связь CONNECT_2 «Relay Server», тело, userNum); не прошло — 6039/6041 с [0]=0 оператору. Relay →
    //   ChannelManager → все NpcServer канала (−1 — все каналы), NpcServer пишет ./Event/Event.dat и отвечает 6039/6041 оператору.
    //   6020 — общая точка P25_RunRecalc (шаги 6–8 команды P25: порог частоты, пересчёт №3, 2333 в базу; ответ 2334 — строками
    //   оператору). Мост делает ровно то же, что сток, без подделки пакета.
    typedef int   (__fastcall *PFN_ByteOf)(void* self, void* edx);                                                         // 0x4A7EB0, 0x40C960
    PFN_NpcConn  const pRelayConn  = (PFN_NpcConn)0x004C0A90;      // поток+0x4960 (CONNECT_2 «Relay Server»), −1 — нет
    PFN_ByteOf   const pGsChannel  = (PFN_ByteOf) 0x004A7EB0;      // байт 0x5F5EB4 (qword_5F5EB0[4]) — канал GS (this не читается)
    PFN_ByteOf   const pGsSystem   = (PFN_ByteOf) 0x0040C960;      // байт mgr+0x8E9 — индекс системы GS
    bool g_canEvent = false, g_canRank = false;

    // ── таблица слотов (под g_lock — листовая секция) ──
    struct Cmd
    {
        __int64 id;          // 0 — нет
        int     op;          // Op
        int     uid, idx;    // цель
        LONG    gen;         // поколение соединения слота на момент захвата
        DWORD   expire;      // GetTickCount() крайнего срока
        int     a[3];        // move: карта, X, Z; title: id; exp: целевой уровень (−1 — по опыту)
        __int64 v;           // exp: целевой накопленный опыт (−1 — по уровню)
        char    text[100];   // notice: текст cp1251 (≤ 95 б) и RGB в text[96..98]
        int     g[10];       // ★ А2.3 give: код, количество, склад(0/1), o1, v1, o2, v2, самоцвет, ступень, ожидаемая сумка (−1 — любая)
    };
    struct Slot
    {
        bool  active;        // вход был, разрыва ещё нет
        bool  snap;          // снимок CUser есть (в мире)
        bool  dirty;         // присутствие надо отправить
        bool  gone;          // присутствие надо удалить
        int   uid, idx, suid, map;
        short x, z;
        char  name[21];
        void* mgr;
        DWORD snapTick;
        Cmd   cmd;
    };
    Slot          g_slot[kSlots] = {};
    volatile LONG g_gen[kSlots]  = {};
    volatile LONG g_cmdPending   = 0;
    volatile LONG g_globPending  = 0;

    struct Glob
    {
        __int64 id;
        BYTE    body[9 + kNoticeBody];       // «кадр»: sendNoticeClient читает тело с +9
        void*   done[kMaxMgr];
        int     nDone;
        DWORD   expire, first;
    };
    Glob g_glob[kMaxGlobal] = {};

    constexpr int kResText = 400;            // ★ А2.3: = adm.bridge_cmd.result NVARCHAR(400)
    struct Res { __int64 id; BYTE status; int code; wchar_t text[kResText]; };   // ★ А2.3: 400 = adm.bridge_cmd.result (ячейки выдачи)
    Res  g_res[kResCap];
    int  g_resHead = 0, g_resCount = 0;

    __int64 g_doneIds[kDoneIds] = {};
    int     g_doneAt = 0;

    CRITICAL_SECTION g_lock;
    bool g_lockReady = false;
    void Lock()   { if (g_lockReady) { EnterCriticalSection(&g_lock); } }
    void Unlock() { if (g_lockReady) { LeaveCriticalSection(&g_lock); } }

    __declspec(thread) int t_inKick = 0;
    P127_Stats g_stats = {};
    HANDLE g_thread = nullptr;

    // Итог в кольцо (под g_lock не обязательно: берёт сам). Переполнение — итог теряется (строка останется status 1).
    void PushResult(__int64 id, int status, int code, const wchar_t* fmt, ...)
    {
        wchar_t t[400];
        va_list ap; va_start(ap, fmt); _vsnwprintf_s(t, _TRUNCATE, fmt, ap); va_end(ap);
        if (status == kStDone) { InterlockedIncrement(&g_stats.done); }
        else if (status == kStRefused) { InterlockedIncrement(&g_stats.refused); }
        else if (status == kStAbsent) { InterlockedIncrement(&g_stats.absent); }
        else if (status == kStJournal) { InterlockedIncrement(&g_stats.journal); }
        Lock();
        if (g_resCount < kResCap)
        {
            Res& r = g_res[(g_resHead + g_resCount) % kResCap];
            r.id = id; r.status = (BYTE)status; r.code = code; lstrcpynW(r.text, t, ARRAYSIZE(r.text));
            ++g_resCount;
        }
        Unlock();
    }

    void NameW(const char* s, wchar_t* out, int cch)
    {
        char b[24] = {};
        for (int i = 0; i < 20 && s[i]; ++i) { b[i] = s[i]; }
        if (!MultiByteToWideChar(1251, 0, b, -1, out, cch)) { out[0] = 0; }
    }

    // ═════════════════════════ HMAC-SHA256 (BCrypt) ═════════════════════════
    bool Hmac(const BYTE* data, int n, BYTE out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE h = nullptr; bool ok = false;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) { return false; }
        if (BCryptCreateHash(alg, &h, nullptr, 0, g_key, (ULONG)g_keyLen, 0) == 0
            && BCryptHashData(h, (PUCHAR)data, (ULONG)n, 0) == 0 && BCryptFinishHash(h, out, 32, 0) == 0) { ok = true; }
        if (h) { BCryptDestroyHash(h); }
        BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }

    // Подпись команды (★ ревизия 24 К-2: v2 — со сроком): HMAC(ключ, UTF-8 "v2|nonce|op|uid|idx|node|args|ttl|deadline"),
    //   deadline — секунды UNIX UTC (тот же срок, что в adm.bridge_cmd.deadline; ставит панель). Возврат — false, если не собралась.
    bool MacOf(const wchar_t* nonce, const wchar_t* op, int uid, int idx, const wchar_t* node, const wchar_t* args, int ttl,
               __int64 deadline, BYTE m[32])
    {
        if (g_keyLen <= 0) { return false; }
        wchar_t* w = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, 1400 * sizeof(wchar_t));
        char* u = (char*)HeapAlloc(GetProcessHeap(), 0, 4200);
        bool ok = false;
        if (w && u)
        {
            _snwprintf_s(w, 1400, _TRUNCATE, L"v2|%s|%s|%d|%d|%s|%s|%d|%I64d", nonce, op, uid, idx, node, args, ttl, deadline);
            const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, u, 4200, nullptr, nullptr);
            ok = n > 1 && Hmac((const BYTE*)u, n - 1, m);
        }
        if (w) { HeapFree(GetProcessHeap(), 0, w); }
        if (u) { HeapFree(GetProcessHeap(), 0, u); }
        return ok;
    }

    // ★ ревизия 24 К-1: сравнение ВСЕХ разрядов wchar_t (не младшего байта), без раннего выхода.
    bool MacOk(const wchar_t* nonce, const wchar_t* op, int uid, int idx, const wchar_t* node, const wchar_t* args, int ttl,
               __int64 deadline, const wchar_t* macHex)
    {
        BYTE m[32];
        if (!MacOf(nonce, op, uid, idx, node, args, ttl, deadline, m)) { return false; }
        if (lstrlenW(macHex) != 64) { return false; }
        static const wchar_t hx[] = L"0123456789abcdef";
        unsigned diff = 0;
        for (int i = 0; i < 32; ++i)
        {
            diff |= (unsigned)(hx[m[i] >> 4] ^ macHex[2 * i]) | (unsigned)(hx[m[i] & 15] ^ macHex[2 * i + 1]);
        }
        return diff == 0;
    }

    // Текущее время UNIX UTC, с.
    __int64 NowUnix()
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        const __int64 t = ((__int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        return (t - 116444736000000000LL) / 10000000LL;
    }

    // ★ ревизия 24 К-2: память обработанных nonce (повтор той же строки, вставленной заново, — отказ). Только нить моста.
    constexpr int kNonceMem = 1024;
    wchar_t g_nonces[kNonceMem][40] = {};
    int     g_nonceAt = 0;
    bool SeenNonce(const wchar_t* nonce)
    {
        for (int i = 0; i < kNonceMem; ++i) { if (g_nonces[i][0] && !lstrcmpiW(g_nonces[i], nonce)) { return true; } }
        lstrcpynW(g_nonces[g_nonceAt], nonce, 40); g_nonceAt = (g_nonceAt + 1) % kNonceMem;
        return false;
    }

    // ═════════════════════════ разбор args "k=v;k=v;text=…" ═════════════════════════
    bool ArgInt(const wchar_t* args, const wchar_t* key, int* out)
    {
        const int kl = lstrlenW(key);
        for (const wchar_t* p = args; *p; )
        {
            if (!wcsncmp(p, key, kl) && p[kl] == L'=')
            {
                wchar_t* e = nullptr; const long v = wcstol(p + kl + 1, &e, 10);
                if (e == p + kl + 1 || (*e && *e != L';' && *e != L',')) { return false; }
                *out = (int)v; return true;
            }
            const wchar_t* q = wcschr(p, L';');
            if (!q) { break; }
            p = q + 1;
        }
        return false;
    }
    const wchar_t* ArgText(const wchar_t* args)    // всё после "text=" (последний ключ)
    {
        if (!wcsncmp(args, L"text=", 5)) { return args + 5; }
        const wchar_t* p = wcsstr(args, L";text=");
        return p ? p + 6 : nullptr;
    }
}

// ═════════════════════════ общие точки событий (P73) ═════════════════════════
extern "C" void __stdcall P127_OnLogon(int kind, int userNum, BYTE* user, int userIndex)
{
    (void)kind; (void)user;
    if (!g_enabled || userNum < 0 || userNum >= kSlots) { return; }
    Lock();
    Slot& s = g_slot[userNum];
    if (s.active && s.snap && s.uid != userIndex) { s.gone = true; }   // прежняя сессия слота без разрыва
    s.active = true; s.snap = false; s.uid = userIndex; s.idx = -1; s.dirty = false;
    Unlock();
    InterlockedIncrement(&g_stats.logons);
}

extern "C" void __stdcall P127_OnConnFlag(int slot, int flag)
{
    (void)flag;
    if (!g_enabled || slot < 0 || slot >= kSlots) { return; }
    __int64 dropped = 0;
    Lock();
    InterlockedIncrement(&g_gen[slot]);
    Slot& s = g_slot[slot];
    const bool was = s.active;
    if (s.active && s.snap) { s.gone = true; }
    s.active = false; s.snap = false; s.dirty = false; s.mgr = nullptr;
    if (s.cmd.id) { dropped = s.cmd.id; s.cmd.id = 0; InterlockedDecrement(&g_cmdPending); }
    Unlock();
    if (was) { InterlockedIncrement(&g_stats.logouts); }
    if (dropped) { PushResult(dropped, kStAbsent, 1, L"игрок вышел до выполнения (разрыв слота %d)", slot); }
}

int P127_KickInProgress()
{
    return t_inKick;
}

namespace
{
    // Снимок CUser (нить карты, вне замка — чтение под __try), затем копия в слот под замком.
    void Snapshot(void* mgr, int num, BYTE* user)
    {
        int uid = -1, idx = -1, inworld = 0, map = -1, suid = 0; short x = 0, z = 0; char name[21] = {};
        __try
        {
            uid = *(const int*)(user + kOffUserIndex);
            idx = user[kOffCharSlot];
            inworld = *(const int*)(user + kOffInWorld) == 1;
            x = *(const short*)(user + kOffTileX); z = *(const short*)(user + kOffTileZ);
            memcpy(name, user + Srv::kOffCharName, 20);
            BYTE* th = *(BYTE**)((BYTE*)mgr + kOffThread);
            map = th ? *(const int*)(th + kOffMapIdx) : -1;
            P48_Identity id; P48_IdentityOf(user, uid, g_soulSession, &id);
            suid = id.account > 0 ? id.account : uid;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return; }
        const DWORD now = GetTickCount();
        Lock();
        Slot& s = g_slot[num];
        if (s.active && s.uid == uid)
        {
            s.mgr = mgr;
            if (!inworld)
            {
                if (s.snap) { s.gone = true; s.snap = false; s.dirty = false; }
            }
            else
            {
                const bool keyChange = !s.snap || s.idx != idx || s.map != map || s.suid != suid || strcmp(s.name, name) != 0;
                const bool posDue = (s.x != x || s.z != z) && (DWORD)(now - s.snapTick) >= (DWORD)g_snapshotS * 1000u;
                if (keyChange || posDue)
                {
                    s.snap = true; s.idx = idx; s.map = map; s.suid = suid; s.x = x; s.z = z; lstrcpynA(s.name, name, sizeof(s.name));
                    s.snapTick = now; s.dirty = true; s.gone = false;
                    InterlockedIncrement(&g_stats.snapshots);
                }
            }
        }
        Unlock();
    }

    // Объявления: выполнить для этого менеджера те, что ещё не выполнены (нить карты).
    void RunGlobals(void* mgr)
    {
        for (int k = 0; k < kMaxGlobal; ++k)
        {
            BYTE frame[9 + kNoticeBody]; bool run = false; __int64 id = 0;
            Lock();
            Glob& g = g_glob[k];
            if (g.id)
            {
                bool seen = false;
                for (int i = 0; i < g.nDone; ++i) { if (g.done[i] == mgr) { seen = true; break; } }
                if (!seen && g.nDone < kMaxMgr)
                {
                    g.done[g.nDone++] = mgr; memcpy(frame, g.body, sizeof(frame)); run = true; id = g.id;
                    if (!g.first) { g.first = GetTickCount() | 1; }
                }
            }
            Unlock();
            if (!run) { continue; }
            __try { pNotice(mgr, nullptr, frame); InterlockedIncrement(&g_stats.notices); }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                InterlockedIncrement(&g_stats.faults);
                Log::Line(L"[P127] ! исключение в sendNoticeClient (команда %I64d) — пропущено", id);
            }
        }
    }

    // ═════════════════ ★ А2.3: выдача предмета (перенос хвоста Recv_OperatorCommand_ItemGive@0x552360) ═════════════════
    //  Порядок, ветки, коды отказа и разметка записи Src — дословно GS:129854–130320 (дизасм 0x552360…0x5534B6); отличия:
    //  (1) отправитель — мост: гейты оператора (0x52ECF0/0x52ED50/0x524390/0x523F00) не нужны, 6043 «оператору» не шлётся;
    //  (2) опции, самоцвет и ступень снаряжения — выбор оператора (панель), сверенный с таблицами в памяти (те же записи, из которых
    //      бросают sub_4A7EE0/4A7FC0/sub_4B7B00); вес самоцвета прибавляется, только если самоцвет поставлен (сток прибавлял и при
    //      выпавшем, но не подошедшем — для выбора оператора такого случая нет);
    //  (3) в 2231 оператор — служебный персонаж kGmOperUid/kGmOperSlot (решение владельца).
    struct GiveCell { short plate, posx; int amount; bool merged; };
    struct GiveOpts { int o[2], v[2], gem, up; };

    BYTE* TabRec(DWORD vaPtr, int idx, int size) { BYTE* t = *(BYTE**)vaPtr; return t ? t + size * idx : nullptr; }

    // Вид кода по веткам стока (без записи): 1 F, 2 Cellob, 3 колчан, 4 стопка, 5 расходник, 6 снаряжение; 0 — нет в таблицах (код 4).
    //   *plate — сумка, куда положит сток (bag: 0 — сумка, 1 — склад); −1 — bag недопустим (код 1).
    int GiveKind(int code, int bag, int* plate)
    {
        *plate = -1;
        if (pIsF(code)) { *plate = 1; return 1; }                                            // Function: всегда сумка 1, bag не читается
        if (pIsC(code)) { if (bag == 0) { *plate = 2; } else if (bag == 1) { *plate = 5; } return 2; }
        if (!pIsI(code)) { return 0; }
        const BYTE* it = TabRec(kVaIT, code - 20551, 71);
        const bool cons = it[7] == 4 && it[36] == 1;
        if (cons && it[35] && it[26] == 10 && it[7] == 4) { if (bag == 0) { *plate = 2; } else if (bag == 1) { *plate = 5; } return 3; }
        if (cons && it[35]) { if (bag == 0) { *plate = 2; } else if (bag == 1) { *plate = 5; } return 4; }
        if (cons)           { if (bag == 0) { *plate = 2; } else if (bag == 1) { *plate = 5; } return 5; }
        if (bag == 0) { *plate = 1; } else if (bag == 1) { *plate = 5; }
        return 6;
    }

    // Опция/значение снаряжения: есть ли тип t в группе g с ненулевым шансом (sub_4A7EE0) и значение v у ПЕРВОЙ записи типа t
    //   (sub_4A7FC0 берёт первую) с ненулевым шансом. Пороги накопительные: шанс записи = порог − предыдущий.
    bool OptionOk(int g, int t, int v)
    {
        if (t == -1) { return true; }                                                         // пары нет (−1 / 0, как у стока при промахе)
        if (g < 1 || g >= *(const int*)kVaOptCount) { return false; }
        const BYTE* grp = *(const BYTE* const*)kVaOptGroups + 5 * g;
        const int n = grp[0]; const BYTE* e0 = *(const BYTE* const*)(grp + 1);
        if (!e0) { return false; }
        bool typeOk = false; int prev = 0;
        for (int i = 0; i < n; ++i)
        {
            const BYTE* e = e0 + (i << 7);
            const int thr = *(const int*)(e + 2);
            if (*(const short*)(e + 6) == t && thr > prev && thr >= 1) { typeOk = true; }
            prev = thr > prev ? thr : prev;
        }
        if (!typeOk) { return false; }
        for (int i = 0; i < n; ++i)
        {
            const BYTE* e = e0 + (i << 7);
            if (*(const short*)(e + 6) != t) { continue; }
            int pv = 0;
            for (int j = 0; j < 20; ++j)
            {
                const int th = *(const int*)(e + 48 + 4 * j);
                if (*(const short*)(e + 8 + 2 * j) == v && th > pv && th >= 1) { return true; }
                pv = th > pv ? th : pv;
            }
            return false;
        }
        return false;
    }

    // Самоцвет гнезда 0 при создании: исход SowelCombine с ненулевым шансом и фильтр sub_4B7B00 (Cellob +11 == 0, вид +12 vs тип +26).
    bool GemOk(int code, int gem)
    {
        if (gem == 0) { return true; }                                                        // гнездо пустое — исход «мимо»
        const int k = code - 20551;
        if (k < 0 || k >= *(const int*)kVaSowelCount) { return false; }
        const BYTE* it = TabRec(kVaIT, k, 71);
        const BYTE* sc = TabRec(kVaSowel, k, 172);
        switch (it[26]) { case 0: case 1: case 2: case 3: case 4: case 8: case 9: break; default: return false; }
        bool listed = false;
        for (int i = 0; i < 10; ++i) { if (*(const int*)(sc + 60 + 4 * i) == gem && *(const int*)(sc + 100 + 4 * i) > 0) { listed = true; } }
        if (!listed || !pIsC(gem)) { return false; }
        const BYTE* ce = TabRec(kVaCT, gem - 7001, 43);
        if (ce[11]) { return false; }
        if (ce[12] == 9) { return it[26] == 9 && ((1ULL << it[27]) & *(const unsigned __int64*)(ce + 34)) != 0; }
        if (ce[12] == 8) { return it[26] == 8; }
        switch (ce[12]) { case 0: case 1: case 2: case 3: case 4: case 13: case 14: return it[26] <= 4; default: return false; }
    }

    // Ступень при создании: 0 или исход SowelCombine +8+j (1…10) с ненулевым шансом +20+4j.
    bool UpOk(int code, int up)
    {
        if (up == 0) { return true; }
        const int k = code - 20551;
        if (up < 1 || up > 10 || k < 0 || k >= *(const int*)kVaSowelCount) { return false; }
        const BYTE* it = TabRec(kVaIT, k, 71);
        switch (it[26]) { case 0: case 1: case 2: case 3: case 4: case 8: case 9: break; default: return false; }
        const BYTE* sc = TabRec(kVaSowel, k, 172);
        for (int j = 0; j < 10; ++j) { if ((signed char)sc[8 + j] == up && *(const int*)(sc + 20 + 4 * j) > 0) { return true; } }
        return false;
    }

    // Одна стоковая выдача (как один запрос 6042). Возврат: 0 — выдано (*out — ячейка), 1…7 — отказ стока (v55), 8 — исключение.
    //   *sent (если задан) — 1 после отправки 2231 (★ ревизия 29 К-9: исключение ПОСЛЕ 2231 — предмет мог лечь в БД, итог это отмечает).
    int GiveOne(void* mgr, int num, int uid, int code, int bag, int amt, const GiveOpts& op, GiveCell* out, int* sent = nullptr)
    {
        BYTE src[60] = {};
        BYTE* const th = *(BYTE**)((BYTE*)mgr + kOffThread);
        void* const param = *(void**)(th + 0x18);
        pRecInit(src, nullptr);
        const bool u16 = P97_WeightU16Active();                                              // P97: чтения v36/v45 — movzx (0x55261F…)
        const int cw = u16 ? (int)(WORD)pWCur(param, nullptr, num) : (int)pWCur(param, nullptr, num);
        const int mw = u16 ? (int)(WORD)pWMax(param, nullptr, num) : (int)pWMax(param, nullptr, num);
        int v53 = 0, v54 = (int)0xFFFF0000;                                                  // sub_4612F0: {0, ячейка −1}
        auto W14 = [&]() { return (int)*(short*)(src + 14); };
        short cell = -1;
        int plate = 0;
        const int kind = GiveKind(code, bag, &plate);
        if (!kind) { return 4; }
        if (plate < 0) { return 1; }
        *(int*)src = code;
        if (kind == 1)
        {
            cell = (short)P100_GmGivePick(mgr, num, code);                                    // площадка A4 0x5525B0 (P100 или сток)
            if (cell < 0) { return 2; }
            const BYTE* ft = TabRec(kVaFT, code - 1, 48);
            src[4] = 1; *(short*)(src + 5) = cell;
            *(int*)(src + 9) = P100_ChargesAt(ft + 13);                                       // FT+13 (0x5525F9: P100 [ИСПРАВЛЕНИЕ 300])
            *(short*)(src + 14) = *(const short*)(ft + 4);
            if (mw < W14() + cw) { return 6; }
        }
        else if (kind == 2)
        {
            cell = (short)pRouter(mgr, nullptr, num, plate, 0xFFFF);
            if (cell < 0) { return plate == 5 ? 3 : 2; }
            src[4] = (BYTE)plate; *(short*)(src + 5) = cell;
            *(short*)(src + 14) = TabRec(kVaCT, code - 7001, 43)[6];
            if (plate == 2 && mw < W14() + cw) { return 6; }
        }
        else
        {
            const BYTE* it = TabRec(kVaIT, code - 20551, 71);
            if (kind == 3)                                                                    // колчан: Amount = t+47
            {
                cell = (short)pRouter(mgr, nullptr, num, plate, 0xFFFF);
                if (cell < 0) { return plate == 5 ? 3 : 2; }
                src[4] = (BYTE)plate; *(short*)(src + 5) = cell;
                *(int*)(src + 9) = *(const short*)(it + 47);
                *(short*)(src + 14) = *(const short*)(it + 5);
                if (plate == 2 && mw < W14() + cw) { return 6; }
            }
            else if (kind == 4)                                                               // стопка: 1…19, к первой ячейке того же кода
            {
                if (amt <= 0 || amt >= 20) { return 7; }
                int pair[2] = { 0, 0 };
                const int* r = pSame(mgr, nullptr, pair, num, plate, code);
                v53 = r[0]; v54 = r[1];
                src[4] = (BYTE)plate;
                *(int*)(src + 9) = amt;
                *(short*)(src + 14) = (short)((short)amt * *(const short*)(it + 5));
                if (v53 <= 0 || v54 < 0)
                {
                    cell = (short)pRouter(mgr, nullptr, num, plate, 0xFFFF);
                    if (cell < 0) { return 2; }
                    *(short*)(src + 5) = cell;
                    if (plate == 2 && mw < W14() + cw) { return 6; }
                }
                else
                {
                    cell = (short)(v54 >> 16);
                    *(short*)(src + 5) = cell;
                    if (plate == 2 && mw < amt * *(const short*)(it + 5) + cw) { return 6; }
                }
            }
            else                                                                              // расходник (5) / снаряжение (6)
            {
                cell = (short)pRouter(mgr, nullptr, num, plate, 0xFFFF);
                if (cell < 0) { return plate == 5 ? 3 : 2; }
                src[4] = (BYTE)plate; *(short*)(src + 5) = cell;
                src[13] = it[4];
                *(short*)(src + 14) = *(const short*)(it + 5);
                if (kind == 6)
                {
                    for (int i = 0; i < 2; ++i)
                    {
                        *(short*)(src + 29 + 4 * i) = (short)op.o[i];
                        *(short*)(src + 31 + 4 * i) = (short)(op.o[i] == -1 ? 0 : op.v[i]);
                    }
                    if (op.gem)
                    {
                        *(short*)(src + 16) = (short)op.gem;
                        *(short*)(src + 14) = (short)(*(short*)(src + 14) + TabRec(kVaCT, op.gem - 7001, 43)[6]);
                    }
                    if (op.up > 0 && op.up <= 10) { src[24] = (BYTE)op.up; }
                    src[49] = 0;
                    src[26] = code <= 20551 ? 0 : TabRec(kVaSowel, code - 20551, 172)[146];
                    src[25] = 0;
                    *(short*)(src + 27) = 0; *(short*)(src + 51) = 0; *(short*)(src + 53) = 0; *(short*)(src + 55) = 0;
                }
                const bool chk = kind == 6 ? plate == 1 : plate == 2;
                if (chk && mw < W14() + cw) { return 6; }
            }
        }
        // ── 2231 UPGmItemAdd (68 б): +0 группа, +1 UserIndex цели, +5 слот цели, +6 UserIndex оператора, +10 слот оператора, +11 Src 57 б ──
        BYTE body[68] = {};
        body[0] = (BYTE)pGroup((void*)kVaThreadMgr, nullptr);
        *(int*)(body + 1) = pUidOf(mgr, nullptr, num);
        body[5] = (BYTE)pSlotOf(mgr, nullptr, num);
        *(int*)(body + 6) = kGmOperUid;
        body[10] = (BYTE)kGmOperSlot;
        memcpy(body + 11, src, 57);
        pDbSend((void*)kVaDbMgr, nullptr, 2231, 68, (short)pConn(th, nullptr), body, num);
        if (sent) { *sent = 1; }
        out->plate = (short)plate; out->posx = *(short*)(src + 5);                           // ячейка известна уже здесь (К-9)
        const int add9 = *(int*)(src + 9);                                                    // выдано этой записью (до слияния в памяти)
        const short w35 = *(short*)(src + 14);                                                // прибавка веса (до слияния стопки)
        bool merged = false;
        if (kind == 4 && v53 > 0 && (short)(v54 >> 16) >= 0)
        {
            *(int*)(src + 9) = amt + v53;
            *(short*)(src + 14) = (short)((short)v54 + amt * *(const short*)(TabRec(kVaIT, code - 20551, 71) + 5));
            merged = true;
        }
        if (P100_WriteMerged(mgr, num, src, 1)) { merged = true; }                            // площадка 0x5533A6 (P100 W_A4; без P100 — сток)
        // ★ [ИСПРАВЛЕНИЕ ДЕФЕКТА ОРИГИНАЛА, ревизия 29 К-3] сток (0x5533CB) прибавляет вес персонажу и при выдаче НА СКЛАД (plate 5): вес
        //   склада в вес персонажа не входит (сервер при загрузке: SUM(Weight) Plate <> 5; офлайн-путь панели так же) — до перезахода у игрока
        //   был ложный перегруз. Мост для склада вес не прибавляет; сумки 1/2 — как сток.
        if (plate != 5) { pAddW(param, nullptr, num, w35, 1, 0); }
        BYTE b6044[64] = {};                                                                  // 6044: i16 num, i32 UserIndex, u8 склад, Src
        *(short*)b6044 = (short)num; *(int*)(b6044 + 2) = uid; b6044[6] = (BYTE)bag; memcpy(b6044 + 7, src, 57);
        pToClient(th, nullptr, 6044, 64, num, b6044, num, 1);
        out->plate = (short)plate; out->posx = *(short*)(src + 5); out->merged = merged;
        out->amount = add9;
        return 0;
    }

    const wchar_t* GiveWhy(int c)
    {
        switch (c)
        {
        case 1: return L"неверная сумка для этого вида";        case 2: return L"нет свободной ячейки в сумке";
        case 3: return L"нет свободной ячейки на складе";       case 4: return L"кода нет в таблицах сервера";
        case 6: return L"перегруз (вес)";                       case 7: return L"количество стопки вне 1…19";
        case 8: return L"исключение в функции стока";           default: return L"отказ";
        }
    }

    void RunGive(void* mgr, int num, const Cmd& c, const char* nm, const wchar_t* wn)
    {
        const int code = c.g[0], q = c.g[1], bag = c.g[2];
        GiveOpts op = { { c.g[3], c.g[5] }, { c.g[4], c.g[6] }, c.g[7], c.g[8] };
        int plate = -1, kind = 0;
        __try { kind = GiveKind(code, bag, &plate); } __except (EXCEPTION_EXECUTE_HANDLER) { kind = -1; }
        if (kind <= 0) { PushResult(c.id, kStRefused, kind < 0 ? 38 : 34, L"выдача: %s", kind < 0 ? GiveWhy(8) : GiveWhy(4)); return; }
        if (plate < 0) { PushResult(c.id, kStRefused, 31, L"выдача: %s", GiveWhy(1)); return; }
        if (c.g[9] >= 0 && plate != c.g[9])
        {
            PushResult(c.id, kStRefused, 20, L"выдача: сервер положит в сумку %d, панель ждала %d — не выдаю", plate, c.g[9]); return;
        }
        if (q < 1 || q > (kind == 4 ? kGiveStackMax : kGiveCopiesMax)) { PushResult(c.id, kStRefused, 3, L"выдача: количество вне 1…%d", kind == 4 ? kGiveStackMax : kGiveCopiesMax); return; }
        bool okOpts = true;
        __try
        {
            if (kind == 6)
            {
                const BYTE* it = TabRec(kVaIT, code - 20551, 71);
                for (int i = 0; i < 2; ++i) { okOpts = okOpts && OptionOk(*(const short*)(it + 18 + 4 * i), op.o[i], op.v[i]); }
                okOpts = okOpts && GemOk(code, op.gem) && UpOk(code, op.up);
            }
            else { okOpts = op.o[0] == -1 && op.o[1] == -1 && op.gem == 0 && op.up == 0; }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { okOpts = false; }
        if (!okOpts) { PushResult(c.id, kStRefused, 19, L"выдача: опции/самоцвет/ступень не из таблиц сервера для этого предмета"); return; }
        GiveCell cells[kGiveCopiesMax] = {}; int nc = 0, given = 0, units = 0, stop = 0, after2231 = 0, faultCell = -1;
        const int reps = kind == 4 ? (q + 18) / 19 : q;
        for (int k = 0; k < reps; ++k)
        {
            const int amt = kind == 4 ? (q - units < 19 ? q - units : 19) : 0;
            GiveCell one = { -1, -1, 0, false };
            int r = 8, sent = 0;
            __try { r = GiveOne(mgr, num, c.uid, code, bag, amt, op, &one, &sent); }
            __except (EXCEPTION_EXECUTE_HANDLER) { r = 8; InterlockedIncrement(&g_stats.faults); }
            if (r == 8 && sent) { after2231 = 1; faultCell = one.posx; }                    // ★ ревизия 29 К-9
            if (r) { stop = r; break; }
            ++given; units += kind == 4 ? amt : 1;
            int j = 0; while (j < nc && !(cells[j].plate == one.plate && cells[j].posx == one.posx)) { ++j; }
            if (j < nc) { cells[j].amount += one.amount; cells[j].merged = true; }
            else if (nc < kGiveCopiesMax) { cells[nc++] = one; }
        }
        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: GIVE cmd %I64d UserNum %d [%.20s] UserIndex %d code %d q %d bag %d -> given %d (units %d) stop %d",
                    c.id, num, nm, c.uid, code, q, bag, given, units, stop);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (!given && !after2231) { PushResult(c.id, kStRefused, 30 + stop, L"выдача: %s", GiveWhy(stop)); return; }
        // ★ ревизия 29 К-4: строка ячеек — с запасом и проверкой: не влезла — trunc=1 (панель тогда не откатывает по итогу)
        wchar_t list[kResText] = L""; int n = 0, trunc = 0;
        for (int j = 0; j < nc && !trunc; ++j)
        {
            const int w = _snwprintf_s(list + n, ARRAYSIZE(list) - n, _TRUNCATE, L"%s%d.%d.%d", j ? L"," : L"", (int)cells[j].posx, cells[j].amount,
                                       cells[j].merged ? 1 : 0);
            if (w < 0) { trunc = 1; list[n] = 0; } else { n += w; }
        }
        if (nc >= kGiveCopiesMax && given > nc) { trunc = 1; }
        InterlockedIncrement(&g_stats.gives);
        wchar_t res[kResText];
        const int rn = _snwprintf_s(res, ARRAYSIZE(res), _TRUNCATE, L"given=%d;q=%d;units=%d;plate=%d;stop=%d;after2231=%d;fault=%d;trunc=%d;cells=%s",
                                    given, q, units, plate, stop, after2231, faultCell, trunc, list);
        if (rn < 0) { _snwprintf_s(res, ARRAYSIZE(res), _TRUNCATE, L"given=%d;q=%d;units=%d;plate=%d;stop=%d;after2231=%d;fault=%d;trunc=1;cells=",
                                   given, q, units, plate, stop, after2231, faultCell); }
        PushResult(c.id, kStDone, stop, L"%s", res);
        (void)wn;
    }

    // ═════════════════ ★ А2.3: перенос в своей карте ═════════════════
    void RunJump(void* mgr, int num, const Cmd& c, const char* nm)
    {
        int map = -1, x = -1, z = -1, ok = 0, why = 0;
        __try
        {
            BYTE* th = *(BYTE**)((BYTE*)mgr + kOffThread);
            map = *(const int*)(th + kOffMapIdx);
            void* mm = *(void**)(th + kOffMapMgr);
            if (map != c.a[0]) { why = 21; }
            else if (!pInMap(mm, nullptr, (short)c.a[1], (short)c.a[2])) { why = 22; }        // как 0x54F097 (до остановки хода)
            else
            {
                if (pMoving(mgr, nullptr, num)) { pStopMove(mgr, nullptr, num, "P127 AdminBridge jump"); }
                int pos[2] = { -1, -1 };
                const int* p = pNearest(mm, nullptr, pos, (short)c.a[1], (short)c.a[2], 0.0f, 0.0f);
                x = p[0]; z = p[1];
                if (x == -1 || z == -1) { why = 23; }
                else if (!(ok = pJump0(mgr, nullptr, num, (short)x, (short)z))) { why = 24; }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; ok = 0; InterlockedIncrement(&g_stats.faults); }
        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: JUMP cmd %I64d UserNum %d [%.20s] UserIndex %d map %d (%d,%d) -> (%d,%d): %s",
                    c.id, num, nm, c.uid, map, c.a[1], c.a[2], x, z, ok ? "ok" : "refused");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (ok) { InterlockedIncrement(&g_stats.moves); PushResult(c.id, kStDone, 0, L"x=%d;z=%d;map=%d", x, z, map); return; }
        static const wchar_t* const kWhy[] = { L"игрок уже на другой карте", L"клетка вне карты", L"рядом нет проходимой клетки",
                                               L"сектор вне карты" };
        PushResult(c.id, kStRefused, why, L"перенос в своей карте: %s", why == 8 ? L"исключение в функции стока" : kWhy[why - 21]);
    }

    // ═════════════════ ★ А5.2: 6045 / 6046 от имени оператора-цели (нить его карты) ═════════════════
    void RunMob(void* mgr, int num, BYTE* user, const Cmd& c, const char* nm)
    {
        const bool pop = c.op == kOpMobPop;
        int why = 0, conn = -1, ok = 0, gm = 0;
        __try { gm = user[kOffGmFlag]; } __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; }
        if (!why && (c.uid < 0 || c.uid > kOperatorMax)) { why = 31; }              // как sub_52ECF0
        else if (!why && gm != 1) { why = 32; }                                     // как P47 (sub_52ED50)
        if (!why)
        {
            __try
            {
                BYTE* th = *(BYTE**)((BYTE*)mgr + kOffThread);
                conn = th ? (short)pNpcConn(th, nullptr) : -1;
                if (conn < 0) { why = 33; }
                else
                {
                    BYTE body[5] = {};
                    *(WORD*)body = (WORD)num; *(WORD*)(body + 2) = (WORD)c.a[0]; body[4] = (BYTE)c.a[1];
                    ok = pConnSend((void*)Srv::kNetMoveMgr, nullptr, pop ? 6045 : 6046, pop ? 5 : 4, conn, body, num);
                    if (!ok) { why = 34; }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; ok = 0; InterlockedIncrement(&g_stats.faults); }
        }
        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: %s cmd %I64d UserNum %d [%.20s] UserIndex %d group %d mode %d conn %d: %s",
                    pop ? "MOBPOP 6045" : "MOBRETURN 6046", c.id, num, nm, c.uid, c.a[0], c.a[1], conn, ok ? "sent to NpcServer" : "refused");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (ok)
        {
            PushResult(c.id, kStDone, 0, L"%d отправлен в NpcServer: группа %d%s (ответа у стока нет)", pop ? 6045 : 6046, c.a[0],
                       pop ? (c.a[1] ? L", точка — случайная в прямоугольнике группы" : L", точка — у оператора") : L"");
            return;
        }
        static const wchar_t* const kWhy[] = { L"не служебная учётка (UserIndex вне 0…5000) — сток не выполнил бы",
                                               L"у персонажа нет GM-флага (CharGmInfo) — сток с P47 не выполнил бы",
                                               L"у карты нет связи с NpcServer", L"отправка в NpcServer не удалась" };
        PushResult(c.id, kStRefused, why, L"%s: %s", pop ? L"призыв монстров" : L"возврат монстров",
                   why == 8 ? L"исключение в функции стока" : kWhy[why - 31]);
    }

    // ═════════════════ ★ А5.4: 6038 / 6040 от имени оператора-цели (нить его карты) ═════════════════
    void RunEvent(void* mgr, int num, BYTE* user, const Cmd& c, const char* nm)
    {
        const bool set = c.op == kOpEventSet;
        int why = 0, conn = -1, ok = 0, gm = 0;
        __try { gm = user[kOffGmFlag]; } __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; }
        if (!why && (c.uid < 0 || c.uid > kOperatorMax)) { why = 31; }              // как sub_52ECF0
        else if (!why && gm != 1) { why = 32; }                                     // как сток и P47 (sub_52ED50)
        if (!why)
        {
            __try
            {
                BYTE* th = *(BYTE**)((BYTE*)mgr + kOffThread);
                conn = th ? (short)pRelayConn(th, nullptr) : -1;
                if (conn < 0) { why = 35; }
                else
                {
                    BYTE body[29] = {};                                             // 6038 — 29 б, 6040 — 15 б (как у стока)
                    *(WORD*)body       = (WORD)(BYTE)pGsChannel(mgr, nullptr);      // *(_WORD*)v28 = (unsigned __int8)sub_4A7EB0()
                    *(WORD*)(body + 2) = (WORD)(char)pGsSystem(mgr, nullptr);       // *(_WORD*)&v28[2] = sub_40C960(this)
                    *(WORD*)(body + 4) = (WORD)num;                                 // *(_WORD*)&v28[4] = a2
                    if (set)
                    {
                        for (int i = 0; i < 8; ++i) { body[6 + i] = (BYTE)c.g[i]; }  // S.мес/день/час/мин, E.мес/день/час/мин
                        body[14] = (BYTE)c.a[0];                                    // тип: 0 — добыча, 1 — опыт
                        const float f = (float)c.g[8] / 100.0f;
                        memcpy(body + 15, &f, 4);
                        *(int*)(body + 19) = c.a[1];                                // канал ChannelManager, −1 — все
                        *(int*)(body + 23) = c.a[2];                                // карта NpcServer, −1 — все
                        body[27] = (BYTE)(c.g[9] & 0xFF); body[28] = (BYTE)((c.g[9] >> 8) & 0xFF);   // MinLevel / MaxLevel
                    }
                    else
                    {
                        body[6] = (BYTE)c.a[0];
                        *(int*)(body + 7) = c.a[1];
                        *(int*)(body + 11) = c.a[2];
                    }
                    ok = pConnSend((void*)Srv::kNetMoveMgr, nullptr, set ? 6038 : 6040, set ? 29 : 15, conn, body, num);
                    if (!ok) { why = 34; }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; ok = 0; InterlockedIncrement(&g_stats.faults); }
        }
        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: %s cmd %I64d UserNum %d [%.20s] UserIndex %d type %d channel %d map %d conn %d: %s",
                    set ? "EVENTSET 6038" : "EVENTOFF 6040", c.id, num, nm, c.uid, c.a[0], c.a[1], c.a[2], conn, ok ? "Send Ok" : "refused");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (ok)
        {
            PushResult(c.id, kStDone, 0, L"%d отправлен в RelayServer (тип %d, канал %d, карта %d); итог пишут NpcServer в Event.dat и отвечают "
                       L"оператору 6039/6041", set ? 6038 : 6040, c.a[0], c.a[1], c.a[2]);
            return;
        }
        static const wchar_t* const kWhy[] = { L"не служебная учётка (UserIndex вне 0…5000) — сток не выполнил бы",
                                               L"у персонажа нет GM-флага (CharGmInfo) — сток не выполнил бы",
                                               L"?", L"отправка в RelayServer не удалась", L"у карты нет связи с RelayServer" };
        PushResult(c.id, kStRefused, why, L"%s: %s", set ? L"событие" : L"выключение события",
                   why == 8 ? L"исключение в функции стока" : kWhy[why - 31]);
    }

    // ═════════════════ ★ А5.4: 6020 «пересчитать рейтинги сейчас» (P25) от имени оператора-цели ═════════════════
    void RunRank(void* mgr, int num, BYTE* user, const Cmd& c, const char* nm)
    {
        int why = 0, gm = 0, r = -1, a = 0, b = 0;
        __try { gm = user[kOffGmFlag]; } __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; }
        if (!why && (c.uid < 0 || c.uid > kOperatorMax)) { why = 31; }              // как P25 (RequireOperatorIndex, sub_52ECF0)
        else if (!why && gm != 1) { why = 32; }                                     // как P25 (RequireGmFlag, sub_52ED50)
        if (!why)
        {
            __try { r = P25_RunRecalc(mgr, num, c.a[0], &a, &b); }
            __except (EXCEPTION_EXECUTE_HANDLER) { why = 8; r = -1; InterlockedIncrement(&g_stats.faults); }
        }
        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: RANKRECALC 6020 cmd %I64d UserNum %d [%.20s] UserIndex %d what %d: r=%d a=%d b=%d",
                    c.id, num, nm, c.uid, c.a[0], r, a, b);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (why) { PushResult(c.id, kStRefused, why, L"пересчёт рейтингов: %s", why == 8 ? L"исключение" : why == 31
                              ? L"не служебная учётка (UserIndex вне 0…5000) — P25 не выполнил бы" : L"у персонажа нет GM-флага (CharGmInfo) — P25 не выполнил бы"); return; }
        if (r == 0) { PushResult(c.id, kStDone, 0, L"what=%d;sent=1;granted=%d;players=%d", c.a[0], a, b); return; }
        if (r == 3) { PushResult(c.id, kStDone, 0, L"what=3;sent=0;granted=%d;players=%d", a, b); return; }
        if (r == 1) { PushResult(c.id, kStRefused, 36, L"пересчёт рейтингов: слишком часто — повтор через %d с (MinIntervalSec P25)", a); return; }
        if (r == 2) { PushResult(c.id, kStRefused, 37, L"пересчёт рейтингов: нет объекта сети карты — запрос в базу не отправлен"); return; }
        PushResult(c.id, kStRefused, 11, L"пересчёт рейтингов: P25 на этом узле не поставлен или выключен");
    }

    // Выполнить команду слота (нить карты). 1 — игрок выведен.
    int RunSlotCmd(void* mgr, int num, BYTE* user, const Cmd& c)
    {
        int cur = -1, curIdx = -1;
        __try { cur = *(const int*)(user + kOffUserIndex); curIdx = user[kOffCharSlot]; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (cur != c.uid || (c.idx >= 0 && curIdx != c.idx) || g_gen[num] != c.gen)
        {
            PushResult(c.id, kStAbsent, 2, L"в слоте %d уже другой игрок (учётка %d/%d, ждали %d/%d)", num, cur, curIdx, c.uid, c.idx);
            return 0;
        }
        char nm[24] = {}; __try { memcpy(nm, user + Srv::kOffCharName, 20); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        wchar_t wn[32]; NameW(nm, wn, ARRAYSIZE(wn));
        if (c.op == kOpPing)
        {
            Slot s; Lock(); s = g_slot[num]; Unlock();
            InterlockedIncrement(&g_stats.pings);
            PushResult(c.id, kStDone, 0, L"в игре: %s, слот %d, карта %d, клетка %d,%d", wn, num, s.map, (int)s.x, (int)s.z);
            return 0;
        }
        if (c.op == kOpMove)
        {
            const char* why = "";
            // ★ ревизия 24 К-7: адреса стока для переноса сверяет установка P123 — без неё перенос не выполняется
            if (!P123_Applied()) { PushResult(c.id, kStRefused, 11, L"перенос: P123 не установлен на этом узле"); return 0; }
            const int ok = P123_PortalMoveTo((BYTE*)mgr, num, c.a[0], c.a[1], c.a[2], &why);
            __try
            {
                pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: MOVE cmd %I64d UserNum %d [%.20s] UserIndex %d -> map %d (%d,%d): %s",
                        c.id, num, nm, c.uid, c.a[0], c.a[1], c.a[2], ok ? "5055 sent" : why);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            wchar_t ww[96]; MultiByteToWideChar(CP_ACP, 0, why, -1, ww, ARRAYSIZE(ww));
            if (ok) { InterlockedIncrement(&g_stats.moves); PushResult(c.id, kStDone, 0, L"5055 отправлен: %s → карта %d (%d,%d)", wn, c.a[0], c.a[1], c.a[2]); }
            else    { PushResult(c.id, kStRefused, 10, L"перенос отклонён: %s", ww); }
            return 0;
        }
        if (c.op == kOpProbe)
        {
            // только чтение: уровень и опыт — геттерами стока (если P75 стоит), звание — маской P21
            int lvl = -1, owned = -1, found = -1; __int64 exp = -1;
            __try
            {
                if (g_canExp) { lvl = P75_LevelOf(mgr, num); exp = P75_ExpOf(mgr, num); }
                if (c.a[0] >= 0) { owned = P21_FameOwned(user, c.a[0]) ? 1 : 0; }
                if (c.a[0] >= 0 && c.a[0] < 256)
                {
                    found = (((const unsigned __int64*)(user + kOffFameFound))[c.a[0] / 64] >> (c.a[0] % 64)) & 1 ? 1 : 0;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { lvl = -1; exp = -1; owned = -1; }
            Slot s; Lock(); s = g_slot[num]; Unlock();
            PushResult(c.id, kStDone, 0, L"lvl=%d;exp=%I64d;map=%d;x=%d;z=%d;owned=%d;found=%d;cap=%d", lvl, exp, s.map, (int)s.x, (int)s.z, owned,
                       found, g_canExp ? P75_CapLevel() : -1);
            return 0;
        }
        if (c.op == kOpExp)
        {
            // опыт/уровень — событием стока по одному уровню (P75_GrantTo); понижения у стока нет → отказ (панель: «кик + запись»)
            int lvl0 = -1, lvl1 = -1; __int64 exp0 = -1, exp1 = -1;
            __try { lvl0 = P75_LevelOf(mgr, num); exp0 = P75_ExpOf(mgr, num); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (exp0 < 0) { PushResult(c.id, kStRefused, 8, L"опыт: не прочитан"); return 0; }
            if (c.v <= exp0)
            {
                PushResult(c.id, kStRefused, 12, L"опыт: цель %I64d не больше текущего %I64d (уровень %d) — живьём только прибавка", c.v, exp0, lvl0);
                return 0;
            }
            if (c.a[0] >= 0 && c.a[0] > P75_CapLevel()) { PushResult(c.id, kStRefused, 3, L"опыт: уровень выше потолка"); return 0; }
            // ★ ревизия 25 К-1: на потолке сток опыт не копит (GameServer.c:81029) — честный отказ тем же правилом
            if (lvl0 >= P75_CapLevel())
            {
                PushResult(c.id, kStRefused, 16, L"опыт: персонаж на потолке уровня (%d) — сервер опыт не копит", P75_CapLevel()); return 0;
            }
            // ★ ревизия 25 К-2: проверка 4 зелья — ExpTable строго растёт до цели (иначе сток крутил бы прибавку по 1)
            if (!P75_ExpTableGrows(lvl0, c.v)) { PushResult(c.id, kStRefused, 17, L"опыт: таблица ExpTable не растёт до цели — не начисляю"); return 0; }
            int sk4036 = 0, skJar = 0, fb = 0;
            const int calls = P75_GrantTo(mgr, num, c.v, 200, &lvl1, &exp1, &sk4036, &skJar, &fb);   // ★ ревизия 25 М-1: ключи P75 действуют
            __try
            {
                pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: EXP cmd %I64d UserNum %d [%.20s] UserIndex %d Lv %d->%d Exp %I64d->%I64d calls %d "
                        "4036 skipped %d jar skipped %d fallback %d", c.id, num, nm, c.uid, lvl0, lvl1, exp0, exp1, calls, sk4036, skJar, fb);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (calls < 0)
            {
                InterlockedIncrement(&g_stats.faults);
                PushResult(c.id, kStRefused, 8, L"опыт: исключение в функции стока — проверьте персонажа (рекомендован рестарт узла)");
                return 0;
            }
            const bool reached = exp1 >= c.v;
            PushResult(c.id, reached ? kStDone : kStRefused, reached ? 0 : 15,
                       L"уровень %d → %d, опыт %I64d → %I64d (событий %d; 4036 подавлено %d, кувшин подавлен %d%s)%s",
                       lvl0, lvl1, exp0, exp1, calls, sk4036, skJar, fb ? L", резервный 4036" : L"", reached ? L"" : L" — цель не достигнута (потолок уровня)");
            return 0;
        }
        if (c.op == kOpTitleAdd || c.op == kOpTitleDel)
        {
            bool had = false, has = false;
            __try { had = P21_FameOwned(user, c.a[0]); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (c.op == kOpTitleAdd ? had : !had)
            {
                PushResult(c.id, kStRefused, 13, L"звание %d: %s", c.a[0], had ? L"уже есть" : L"его нет");
                return 0;
            }
            // ★ ревизия 25 М-3: живая выдача = стоковая выдача sub_54B260 БЕЗ условий: бит «найдено» и 6085/2266 стока здесь не
            //   воспроизводятся — поэтому живьём только звания < 256, уже «найденные» (тогда стоковый блок «найдено» ничего бы не делал);
            //   остальное — отказ 18 (панель ведёт «кик + запись», где офлайн-выдача ставит прогресс и бит сама)
            if (c.op == kOpTitleAdd)
            {
                int foundBit = 0;
                __try { foundBit = c.a[0] < 256 && ((((const unsigned __int64*)(user + kOffFameFound))[c.a[0] / 64] >> (c.a[0] % 64)) & 1); }
                __except (EXCEPTION_EXECUTE_HANDLER) { foundBit = 0; }
                if (!foundBit)
                {
                    PushResult(c.id, kStRefused, 18, L"звание %d: %s — живьём не выдаю (нужен полный путь)", c.a[0],
                               c.a[0] >= 256 ? L"номер 256+ (старшая маска P21/P22)" : L"ещё не «найдено»");
                    return 0;
                }
            }
            bool fault = false;
            __try
            {
                if (c.op == kOpTitleAdd)
                {
                    // стоковый блок выдачи sub_54B260 (v42), дословно: AddFameBit, 6065, каскад наборов, счётчик звания 21
                    pAddFame(mgr, nullptr, (short)num, (short)c.a[0]);
                    pFameNote(mgr, nullptr, (short)num, (short)c.a[0]);
                    pFameSet(mgr, nullptr, (short)num, (short)c.a[0]);
                    BYTE b1 = 0, b2 = 0;
                    if (pNotOwned(mgr, nullptr, (short)num, (short)kTitleCount30, &b1, &b2))
                    {
                        BYTE* recs = *(BYTE**)(user + kOffFameRecs);
                        const BYTE* tab = *(const BYTE* const*)kVaFameTable;
                        if (recs && tab)
                        {
                            int* cnt = (int*)(recs + 44 * kTitleCount30);
                            *cnt = *cnt + 1;
                            if (*cnt >= *(const int*)(tab + 96 * kTitleCount30 + 4))
                            {
                                pAddFame(mgr, nullptr, (short)num, (short)kTitleCount30);
                                pFameNote(mgr, nullptr, (short)num, (short)kTitleCount30);
                            }
                        }
                    }
                }
                else
                {
                    P24_RevokeTitle(mgr, user, num, c.a[0]);
                }
                has = P21_FameOwned(user, c.a[0]);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { fault = true; InterlockedIncrement(&g_stats.faults); }
            __try
            {
                pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: TITLE %s cmd %I64d UserNum %d [%.20s] UserIndex %d id %d: %s",
                        c.op == kOpTitleAdd ? "ADD" : "DEL", c.id, num, nm, c.uid, c.a[0], fault ? "exception" : (has == (c.op == kOpTitleAdd)) ? "ok" : "not applied");
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (fault) { PushResult(c.id, kStRefused, 8, L"звание: исключение в функции стока"); return 0; }
            if (has != (c.op == kOpTitleAdd)) { PushResult(c.id, kStRefused, 14, L"звание %d: сервер не применил (гейты AddFameBit/SubFameBit)", c.a[0]); return 0; }
            PushResult(c.id, kStDone, 0, L"звание %d %s: %s", c.a[0], c.op == kOpTitleAdd ? L"выдано" : L"снято", wn);
            return 0;
        }
        if (c.op == kOpFame)
        {
            int checked = 0, skipped = 0, granted = -1;
            __try { granted = P25_RecalcUser(mgr, num, &checked, &skipped); }
            __except (EXCEPTION_EXECUTE_HANDLER) { granted = -2; InterlockedIncrement(&g_stats.faults); }
            if (granted < 0) { PushResult(c.id, kStRefused, granted == -2 ? 8 : 11, L"пересчёт славы: %s", granted == -2 ? L"исключение" : L"P25 выключен или игрок не в мире"); return 0; }
            PushResult(c.id, kStDone, 0, L"пересчёт условий званий: выдано %d (проверено %d, без накопителя %d)", granted, checked, skipped);
            return 0;
        }
        if (c.op == kOpNotice)
        {
            BYTE body[kNoticeBody] = {};                          // 3113: +2 режим 0, +4 текст, +100 RGB (как sendNoticeClient)
            memcpy(body + 4, c.text, kNoticeText);
            body[100] = (BYTE)c.text[96]; body[101] = (BYTE)c.text[97]; body[102] = (BYTE)c.text[98];
            BYTE* thread = nullptr;
            __try { thread = *(BYTE**)((BYTE*)mgr + kOffThread); if (thread) { pToClient(thread, nullptr, 3113, kNoticeBody, num, body, 0, 1); } }
            __except (EXCEPTION_EXECUTE_HANDLER) { thread = nullptr; InterlockedIncrement(&g_stats.faults); }
            if (!thread) { PushResult(c.id, kStRefused, 8, L"нотис: не отправлен"); return 0; }
            InterlockedIncrement(&g_stats.notices);
            PushResult(c.id, kStDone, 0, L"нотис отправлен: %s", wn);
            return 0;
        }
        if (c.op == kOpGive) { RunGive(mgr, num, c, nm, wn); return 0; }      // ★ А2.3
        if (c.op == kOpJump) { RunJump(mgr, num, c, nm); return 0; }          // ★ А2.3
        if (c.op == kOpMobPop || c.op == kOpMobReturn) { RunMob(mgr, num, user, c, nm); return 0; }   // ★ А5.2
        if (c.op == kOpEventSet || c.op == kOpEventOff) { RunEvent(mgr, num, user, c, nm); return 0; } // ★ А5.4
        if (c.op == kOpRankRecalc) { RunRank(mgr, num, user, c, nm); return 0; }                       // ★ А5.4
        if (c.op == kOpKick)
        {
            // ★ ревизия 24 К-4: итог — ПОСЛЕ вызовов стока (имя уже скопировано в wn); исключение — отказ, а не «выполнена»
            __try
            {
                pSrvLog(Srv::kLogCatOperator, "P127 AdminBridge: KICK cmd %I64d UserNum %d [%.20s] UserIndex %d type %d", c.id, num, nm, c.uid, g_kickType);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Log::Line(L"[P127] КИК (команда %I64d): userNum %d, учётка %d — 4101 тип %d + ExceptionDisConnetUser", c.id, num, c.uid, g_kickType);
            t_inKick = 1;
            bool fault = false;
            __try
            {
                pDisc(mgr, nullptr, (short)num, g_kickType);
                pExcDisc(mgr, nullptr, (short)num, "P127 AdminBridge: admin kick");
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                fault = true;
                InterlockedIncrement(&g_stats.faults);
                Log::Line(L"[P127] ! исключение при кике userNum %d — пропущен", num);
            }
            t_inKick = 0;
            if (fault)
            {
                PushResult(c.id, kStRefused, 8, L"кик: исключение в функции стока (слот %d) — проверьте, вышел ли игрок", num);
                return 0;
            }
            InterlockedIncrement(&g_stats.kicks);
            PushResult(c.id, kStDone, 0, L"кик: %s (слот %d), 4101 тип %d — штатный выход с записью", wn, num, g_kickType);
            return 1;
        }
        PushResult(c.id, kStRefused, 3, L"неизвестная команда");
        return 0;
    }
}

// Нить карты: общая точка UserTick (из P73_OnCheckUser). 1 — игрок выведен (стаб продолжит цикл 0x526E36).
extern "C" int __stdcall P127_OnUserTick(void* mgr, int userNum, BYTE* user)
{
    if (!g_enabled) { return 0; }
    userNum = (short)userNum;
    if (userNum < 0 || userNum >= kSlots || !user || !mgr) { return 0; }
    Snapshot(mgr, userNum, user);
    if (g_globPending) { RunGlobals(mgr); }
    if (!g_cmdPending || !*(volatile __int64*)&g_slot[userNum].cmd.id) { return 0; }
    Cmd c = {};
    Lock();
    c = g_slot[userNum].cmd;
    if (c.id) { g_slot[userNum].cmd.id = 0; InterlockedDecrement(&g_cmdPending); }
    Unlock();
    if (!c.id) { return 0; }
    return RunSlotCmd(mgr, userNum, user, c);
}

// ═════════════════════════════ ODBC (только нить моста) ═════════════════════════════
namespace
{
    typedef SQLRETURN (SQL_API *F_AllocHandle)(SQLSMALLINT, SQLHANDLE, SQLHANDLE*);
    typedef SQLRETURN (SQL_API *F_FreeHandle)(SQLSMALLINT, SQLHANDLE);
    typedef SQLRETURN (SQL_API *F_SetEnvAttr)(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_SetConnectAttrW)(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_DriverConnectW)(SQLHDBC, SQLHWND, SQLWCHAR*, SQLSMALLINT, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*, SQLUSMALLINT);
    typedef SQLRETURN (SQL_API *F_ExecDirectW)(SQLHSTMT, SQLWCHAR*, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_MoreResults)(SQLHSTMT);
    typedef SQLRETURN (SQL_API *F_FreeStmt)(SQLHSTMT, SQLUSMALLINT);
    typedef SQLRETURN (SQL_API *F_SetStmtAttrW)(SQLHSTMT, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_Disconnect)(SQLHDBC);
    typedef SQLRETURN (SQL_API *F_GetDiagRecW)(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLWCHAR*, SQLINTEGER*, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*);
    typedef SQLRETURN (SQL_API *F_Fetch)(SQLHSTMT);
    typedef SQLRETURN (SQL_API *F_GetData)(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN*);
    typedef SQLRETURN (SQL_API *F_NumResultCols)(SQLHSTMT, SQLSMALLINT*);

    struct Odbc
    {
        HMODULE mod = nullptr;
        F_AllocHandle AllocHandle = nullptr; F_FreeHandle FreeHandle = nullptr; F_SetEnvAttr SetEnvAttr = nullptr;
        F_SetConnectAttrW SetConnectAttr = nullptr; F_DriverConnectW DriverConnect = nullptr; F_ExecDirectW ExecDirect = nullptr;
        F_MoreResults MoreResults = nullptr; F_FreeStmt FreeStmt = nullptr; F_SetStmtAttrW SetStmtAttr = nullptr;
        F_Disconnect Disconnect = nullptr; F_GetDiagRecW GetDiagRec = nullptr; F_Fetch Fetch = nullptr; F_GetData GetData = nullptr;
        F_NumResultCols NumResultCols = nullptr;
        SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC; bool up = false;
    } g_db;

    bool DbLoad()
    {
        if (g_db.mod) { return g_db.ExecDirect != nullptr; }
        g_db.mod = LoadLibraryW(L"odbc32.dll");
        if (!g_db.mod) { return false; }
        HMODULE m = g_db.mod;
        g_db.AllocHandle    = (F_AllocHandle)    GetProcAddress(m, "SQLAllocHandle");
        g_db.FreeHandle     = (F_FreeHandle)     GetProcAddress(m, "SQLFreeHandle");
        g_db.SetEnvAttr     = (F_SetEnvAttr)     GetProcAddress(m, "SQLSetEnvAttr");
        g_db.SetConnectAttr = (F_SetConnectAttrW)GetProcAddress(m, "SQLSetConnectAttrW");
        g_db.DriverConnect  = (F_DriverConnectW) GetProcAddress(m, "SQLDriverConnectW");
        g_db.ExecDirect     = (F_ExecDirectW)    GetProcAddress(m, "SQLExecDirectW");
        g_db.MoreResults    = (F_MoreResults)    GetProcAddress(m, "SQLMoreResults");
        g_db.FreeStmt       = (F_FreeStmt)       GetProcAddress(m, "SQLFreeStmt");
        g_db.SetStmtAttr    = (F_SetStmtAttrW)   GetProcAddress(m, "SQLSetStmtAttrW");
        g_db.Disconnect     = (F_Disconnect)     GetProcAddress(m, "SQLDisconnect");
        g_db.GetDiagRec     = (F_GetDiagRecW)    GetProcAddress(m, "SQLGetDiagRecW");
        g_db.Fetch          = (F_Fetch)          GetProcAddress(m, "SQLFetch");
        g_db.GetData        = (F_GetData)        GetProcAddress(m, "SQLGetData");
        g_db.NumResultCols  = (F_NumResultCols)  GetProcAddress(m, "SQLNumResultCols");
        return g_db.AllocHandle && g_db.FreeHandle && g_db.SetEnvAttr && g_db.SetConnectAttr && g_db.DriverConnect && g_db.ExecDirect
            && g_db.MoreResults && g_db.FreeStmt && g_db.SetStmtAttr && g_db.Disconnect && g_db.GetDiagRec && g_db.Fetch && g_db.GetData
            && g_db.NumResultCols;
    }

    void Diag(SQLSMALLINT type, SQLHANDLE h, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (!g_db.GetDiagRec || !h) { return; }
        SQLWCHAR st[8] = {}, msg[400] = {}; SQLINTEGER nat = 0; SQLSMALLINT len = 0;
        if (SQL_SUCCEEDED(g_db.GetDiagRec(type, h, 1, st, &nat, msg, ARRAYSIZE(msg), &len)))
        {
            _snwprintf_s(out, cch, _TRUNCATE, L"[%s/%d] %s", (wchar_t*)st, (int)nat, (wchar_t*)msg);
        }
    }

    void DbClose()
    {
        if (g_db.dbc != SQL_NULL_HDBC) { if (g_db.up) { g_db.Disconnect(g_db.dbc); } g_db.FreeHandle(SQL_HANDLE_DBC, g_db.dbc); g_db.dbc = SQL_NULL_HDBC; }
        if (g_db.env != SQL_NULL_HENV) { g_db.FreeHandle(SQL_HANDLE_ENV, g_db.env); g_db.env = SQL_NULL_HENV; }
        g_db.up = false;
    }

    bool DbConnect(wchar_t* err, int cch)
    {
        err[0] = 0;
        if (!DbLoad()) { lstrcpynW(err, L"odbc32.dll не загружена", cch); return false; }
        DbClose();
        if (!SQL_SUCCEEDED(g_db.AllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &g_db.env))) { lstrcpynW(err, L"SQLAllocHandle(ENV)", cch); return false; }
        g_db.SetEnvAttr(g_db.env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
        if (!SQL_SUCCEEDED(g_db.AllocHandle(SQL_HANDLE_DBC, g_db.env, &g_db.dbc))) { lstrcpynW(err, L"SQLAllocHandle(DBC)", cch); DbClose(); return false; }
        g_db.SetConnectAttr(g_db.dbc, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)(INT_PTR)g_loginTo, 0);
        g_db.SetConnectAttr(g_db.dbc, SQL_ATTR_CONNECTION_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTo, 0);
        SQLWCHAR outStr[1024]; SQLSMALLINT outLen = 0;
        if (!SQL_SUCCEEDED(g_db.DriverConnect(g_db.dbc, nullptr, (SQLWCHAR*)g_conn, SQL_NTS, outStr, ARRAYSIZE(outStr), &outLen, SQL_DRIVER_NOPROMPT)))
        {
            Diag(SQL_HANDLE_DBC, g_db.dbc, err, cch); DbClose(); return false;
        }
        g_db.up = true;
        InterlockedIncrement(&g_stats.dbConnects);
        return true;
    }

    // Выполнить пакет без результатов (все наборы пропускаются). false — ошибка (err).
    bool DbExec(const wchar_t* sql, wchar_t* err, int cch)
    {
        err[0] = 0;
        SQLHSTMT st = SQL_NULL_HSTMT;
        if (!SQL_SUCCEEDED(g_db.AllocHandle(SQL_HANDLE_STMT, g_db.dbc, &st))) { Diag(SQL_HANDLE_DBC, g_db.dbc, err, cch); return false; }
        g_db.SetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTo, 0);
        SQLRETURN r = g_db.ExecDirect(st, (SQLWCHAR*)sql, SQL_NTS);
        bool ok = SQL_SUCCEEDED(r) || r == SQL_NO_DATA;
        if (!ok) { Diag(SQL_HANDLE_STMT, st, err, cch); }
        for (int guard = 0; ok && guard < 512; ++guard)
        {
            r = g_db.MoreResults(st);
            if (r == SQL_NO_DATA) { break; }
            if (!SQL_SUCCEEDED(r)) { ok = false; Diag(SQL_HANDLE_STMT, st, err, cch); }
        }
        g_db.FreeStmt(st, SQL_CLOSE);
        g_db.FreeHandle(SQL_HANDLE_STMT, st);
        return ok;
    }

    // SQL-литерал N'…' (кавычки удваиваются, управляющие символы — пробел), не длиннее max символов текста.
    void Lit(wchar_t* out, int cch, const wchar_t* s, int max)
    {
        int k = 0;
        out[k++] = L'N'; out[k++] = L'\'';
        for (int i = 0; s[i] && i < max && k < cch - 4; ++i)
        {
            wchar_t ch = s[i] < 32 ? L' ' : s[i];
            if (ch == L'\'') { out[k++] = L'\''; }
            out[k++] = ch;
        }
        out[k++] = L'\''; out[k] = 0;
    }

    // Растущий буфер пакета SQL (только нить моста).
    struct Batch
    {
        wchar_t b[65536]; int n = 0; int items = 0;
        void Add(const wchar_t* fmt, ...)
        {
            va_list ap; va_start(ap, fmt);
            const int w = _vsnwprintf_s(b + n, ARRAYSIZE(b) - n, _TRUNCATE, fmt, ap);
            va_end(ap);
            if (w > 0) { n += w; ++items; }
        }
        bool Full() const { return n > (int)ARRAYSIZE(b) - 2048; }
        void Reset() { n = 0; items = 0; b[0] = 0; }
    };
    Batch g_batch;

    bool FlushBatch(wchar_t* err, int cch)
    {
        if (!g_batch.items) { return true; }
        const bool ok = DbExec(g_batch.b, err, cch);
        g_batch.Reset();
        return ok;
    }

    // Итоги команд → adm.BridgeResult.
    bool SendResults(wchar_t* err, int cch)
    {
        static Res tmp[48];                      // ★ А2.3: итог до 400 символов — 48 строк × ≤ 960 знаков влезают в пакет (64 К)
        for (;;)
        {
            int n = 0;
            Lock();
            while (n < 48 && g_resCount > 0) { tmp[n++] = g_res[g_resHead]; g_resHead = (g_resHead + 1) % kResCap; --g_resCount; }
            Unlock();
            if (!n) { return true; }
            wchar_t nodeL[80]; Lit(nodeL, ARRAYSIZE(nodeL), g_node, 32);
            for (int i = 0; i < n; ++i)
            {
                wchar_t t[900]; Lit(t, ARRAYSIZE(t), tmp[i].text, 400);
                g_batch.Add(L"EXEC adm.BridgeResult %I64d, %s, %d, %d, %s;\n", tmp[i].id, nodeL, (int)tmp[i].status, tmp[i].code, t);
            }
            InterlockedExchangeAdd(&g_stats.resultsSent, n);
            if (!FlushBatch(err, cch))
            {
                // база недоступна: итоги вернуть в начало кольца (не терять), повтор при следующем подключении
                Lock();
                for (int i = n - 1; i >= 0 && g_resCount < kResCap; --i)
                {
                    g_resHead = (g_resHead + kResCap - 1) % kResCap; g_res[g_resHead] = tmp[i]; ++g_resCount;
                }
                Unlock();
                return false;
            }
        }
    }

    // Изменения присутствия → adm.BridgePresenceSet/Del.
    bool SendPresence(wchar_t* err, int cch)
    {
        wchar_t nodeL[80]; Lit(nodeL, ARRAYSIZE(nodeL), g_node, 32);
        int sent = 0;
        for (int i = 0; i < kSlots; ++i)
        {
            Slot s; bool set = false, del = false;
            Lock();
            Slot& r = g_slot[i];
            if (r.gone) { del = true; r.gone = false; }
            if (r.dirty && r.snap) { set = true; r.dirty = false; s = r; }
            Unlock();
            if (del) { g_batch.Add(L"EXEC adm.BridgePresenceDel %s, %d;\n", nodeL, i); ++sent; }
            if (set)
            {
                wchar_t wn[32], nl[80]; NameW(s.name, wn, ARRAYSIZE(wn)); Lit(nl, ARRAYSIZE(nl), wn, 32);
                g_batch.Add(L"EXEC adm.BridgePresenceSet %s, %d, %d, %d, %d, %s, %d, %d, %d;\n", nodeL, i, s.uid, s.idx & 0xFF, s.suid, nl,
                            s.map, (int)s.x, (int)s.z);
                ++sent;
            }
            if (g_batch.Full() && !FlushBatch(err, cch)) { return false; }
        }
        InterlockedExchangeAdd(&g_stats.presenceSent, sent);
        return FlushBatch(err, cch);
    }

    // Все активные слоты со снимком — снова «к отправке» (после подключения: NodeStart стёр присутствие узла).
    void MarkAllDirty()
    {
        Lock();
        for (int i = 0; i < kSlots; ++i) { if (g_slot[i].active && g_slot[i].snap) { g_slot[i].dirty = true; } g_slot[i].gone = false; }
        Unlock();
    }

    bool SeenId(__int64 id)
    {
        for (int i = 0; i < kDoneIds; ++i) { if (g_doneIds[i] == id) { return true; } }
        g_doneIds[g_doneAt] = id; g_doneAt = (g_doneAt + 1) % kDoneIds;
        return false;
    }

    int OpOf(const wchar_t* op)
    {
        static const struct { const wchar_t* n; int op; } k[] = {
            { L"ping", kOpPing }, { L"kick", kOpKick }, { L"announce", kOpAnnounce }, { L"move", kOpMove }, { L"probe", kOpProbe },
            { L"exp", kOpExp }, { L"title_add", kOpTitleAdd }, { L"title_del", kOpTitleDel }, { L"fame_recalc", kOpFame },
            { L"notice", kOpNotice }, { L"give", kOpGive }, { L"jump", kOpJump }, { L"mob_pop", kOpMobPop }, { L"mob_return", kOpMobReturn },
            { L"event_set", kOpEventSet }, { L"event_off", kOpEventOff }, { L"rank_recalc", kOpRankRecalc } };
        for (const auto& e : k) { if (!lstrcmpW(op, e.n)) { return e.op; } }
        return kOpNone;
    }

    // 64-битное число из args ("k=v;…").
    bool ArgI64(const wchar_t* args, const wchar_t* key, __int64* out)
    {
        const int kl = lstrlenW(key);
        for (const wchar_t* p = args; *p; )
        {
            if (!wcsncmp(p, key, kl) && p[kl] == L'=')
            {
                wchar_t* e = nullptr; const __int64 v = _wcstoi64(p + kl + 1, &e, 10);
                if (e == p + kl + 1 || (*e && *e != L';')) { return false; }
                *out = v; return true;
            }
            const wchar_t* q = wcschr(p, L';');
            if (!q) { break; }
            p = q + 1;
        }
        return false;
    }

    // Захваченная команда (нить моста): подпись, режим, раскладка в слот / объявление.
    void Dispatch(__int64 id, const wchar_t* opS, int uid, int idx, const wchar_t* node, const wchar_t* args, const wchar_t* nonce,
                  int ttl, const wchar_t* mac, int leftS, __int64 deadline)
    {
        InterlockedIncrement(&g_stats.claimed);
        if (SeenId(id)) { Log::Line(L"[P127] ! команда %I64d пришла повторно — не выполняется (at-most-once)", id); return; }
        if (!MacOk(nonce, opS, uid, idx, node, args, ttl, deadline, mac))
        {
            InterlockedIncrement(&g_stats.macBad);
            Log::Line(L"[P127] ! команда %I64d (%s): подпись HMAC не сошлась — отказ", id, opS);
            PushResult(id, kStRefused, 1, L"подпись команды не сошлась (HMAC)");
            return;
        }
        // ★ ревизия 24 К-2: тот же nonce повторно (строка удалена и вставлена заново) — отказ; срок подписан и проверяется здесь
        if (SeenNonce(nonce))
        {
            InterlockedIncrement(&g_stats.macBad);
            PushResult(id, kStRefused, 6, L"повтор подписанной команды (тот же nonce) — отказ");
            return;
        }
        const __int64 now = NowUnix();
        if (deadline <= now)
        {
            PushResult(id, kStRefused, 7, L"срок подписанной команды истёк");
            return;
        }
        if (deadline - now < (__int64)leftS) { leftS = (int)(deadline - now); }
        const int op = OpOf(opS);
        if (op == kOpNone) { PushResult(id, kStRefused, 2, L"неизвестная команда %s", opS); return; }
        if (g_mode != 1 && op != kOpPing && op != kOpProbe)
        {
            Log::Line(L"[P127] команда %I64d (%s, учётка %d/%d) — Mode=0: только журнал", id, opS, uid, idx);
            PushResult(id, kStJournal, 0, L"узел в режиме «только слушать» (Mode=0): команда не выполнена");
            return;
        }
        int ttlLeft = leftS < 1 ? 1 : leftS;
        if (ttlLeft > g_pendingS) { ttlLeft = g_pendingS; }
        const DWORD expire = GetTickCount() + (DWORD)ttlLeft * 1000u;
        if (op == kOpAnnounce)
        {
            const wchar_t* text = ArgText(args);
            if (!text || !*text) { PushResult(id, kStRefused, 3, L"объявление без текста"); return; }
            int r = 255, g = 255, b = 255;
            ArgInt(args, L"r", &r); ArgInt(args, L"g", &g); ArgInt(args, L"b", &b);
            Lock();
            int k = 0; while (k < kMaxGlobal && g_glob[k].id) { ++k; }
            if (k == kMaxGlobal) { Unlock(); PushResult(id, kStRefused, 4, L"занято: уже %d объявлений в работе", kMaxGlobal); return; }
            Glob& gl = g_glob[k];
            memset(&gl, 0, sizeof(gl));
            BYTE* body = gl.body + 9;                     // 3113: +2 режим 0 (строка), +4 текст, +100 RGB
            char t1251[1024] = {};
            WideCharToMultiByte(1251, 0, text, -1, t1251, sizeof(t1251) - 1, nullptr, nullptr);
            memcpy(body + 4, t1251, kNoticeText);         // ≤ 95 б; хвост — нули (memset выше)
            body[4 + kNoticeText] = 0;
            body[100] = (BYTE)r; body[101] = (BYTE)g; body[102] = (BYTE)b;
            gl.expire = expire; gl.id = id;
            Unlock();
            InterlockedIncrement(&g_globPending);
            return;
        }
        int a[3] = { -1, -1, -1 }; __int64 v = -1; char text[100] = {};
        // ★ А2.2: возможности узла — до раскладки (честный отказ сразу, игрок не ждёт такта)
        if ((op == kOpExp && !g_canExp) || (op == kOpTitleAdd && !g_canTitleAdd) || (op == kOpTitleDel && !g_canTitleDel)
            || (op == kOpFame && !g_canFame))
        {
            PushResult(id, kStRefused, 11, L"%s: нужный патч (P75/P24/P25) на этом узле не установлен", opS); return;
        }
        if (op == kOpProbe && ArgInt(args, L"title", &a[0]) && (!g_canTitleDel || a[0] < 0 || a[0] >= P24_FameCount()))
        {
            a[0] = -1;                                           // ★ ревизия 25 К-5: id вне таблицы званий — владение не читается
        }
        if ((op == kOpTitleAdd || op == kOpTitleDel) && (!ArgInt(args, L"id", &a[0]) || a[0] < 0 || a[0] >= P24_FameCount()))
        {
            PushResult(id, kStRefused, 3, L"звание: нет id или id вне таблицы званий"); return;
        }
        if (op == kOpExp)
        {
            const bool hasLvl = ArgInt(args, L"level", &a[0]), hasExp = ArgI64(args, L"exp", &v);
            if (hasLvl == hasExp || (hasLvl && (a[0] < 1 || a[0] > P75_CapLevel())) || (hasExp && v < 0))
            {
                PushResult(id, kStRefused, 3, L"опыт: нужен ровно один из level (1…потолок) или exp (≥ 0)"); return;
            }
            if (hasLvl && !P75_ExpAt(a[0], &v)) { PushResult(id, kStRefused, 3, L"опыт: нет строки ExpTable для уровня %d", a[0]); return; }
            if (!hasLvl) { a[0] = -1; }
        }
        if (op == kOpNotice)
        {
            const wchar_t* t = ArgText(args);
            if (!t || !*t) { PushResult(id, kStRefused, 3, L"нотис без текста"); return; }
            int r = 255, g = 255, b = 255; ArgInt(args, L"r", &r); ArgInt(args, L"g", &g); ArgInt(args, L"b", &b);
            char t1251[1024] = {};
            WideCharToMultiByte(1251, 0, t, -1, t1251, sizeof(t1251) - 1, nullptr, nullptr);
            memcpy(text, t1251, kNoticeText); text[kNoticeText] = 0;
            text[96] = (char)r; text[97] = (char)g; text[98] = (char)b;
        }
        if ((op == kOpMove || op == kOpJump) && (!ArgInt(args, L"map", &a[0]) || !ArgInt(args, L"x", &a[1]) || !ArgInt(args, L"z", &a[2])))
        {
            PushResult(id, kStRefused, 3, L"перенос: нужны map, x, z"); return;
        }
        // ★ ревизия 29 К-2: клетка переноса в своей карте — своя проверка диапазона на узле (не полагаться на (short) и панель)
        if (op == kOpJump && (a[1] < 1 || a[1] > 32767 || a[2] < 1 || a[2] > 32767))
        {
            PushResult(id, kStRefused, 3, L"перенос: x, z вне 1…32767"); return;
        }
        // ★ А5.2: призыв / возврат группы — номер группы u16 (0…65535), режим призыва 0/1 (сток: u8, 0 — у оператора, ≠0 — случайная)
        if (op == kOpMobPop || op == kOpMobReturn)
        {
            a[1] = 0;
            if (!ArgInt(args, L"group", &a[0]) || a[0] < 0 || a[0] > 65535 || (op == kOpMobPop && ArgInt(args, L"mode", &a[1]) && a[1] != 0 && a[1] != 1))
            {
                PushResult(id, kStRefused, 3, L"монстры: нужна group 0…65535 (и mode 0/1 у призыва)"); return;
            }
            if (!g_canMob) { PushResult(id, kStRefused, 11, L"%s: начала функций стока на этом узле не сошлись — не выполняется", opS); return; }
        }
        // ★ А2.3: выдача / перенос в своей карте — функции стока сверены установкой
        if ((op == kOpGive && !g_canGive) || (op == kOpJump && !g_canJump))
        {
            PushResult(id, kStRefused, 11, L"%s: начала функций стока на этом узле не сошлись — не выполняется", opS); return;
        }
        int g[10] = { 0, 0, 0, -1, 0, -1, 0, 0, 0, -1 };
        // ★ А5.4: 6038 / 6040 / 6020 — разбор и диапазоны стока ДО такта (Recv_OperatorCommand_EventSet: месяц 1…12, день 1…31 — со
        //   знаком, час ≤ 24, минута ≤ 60 — беззнаково, тип < 2, значение 0.0…10.0; EventOff: тип < 2; канал и карту сток не проверяет,
        //   здесь — −1 или 0…99 / 0…49 (MapCount NpcServer ≤ 50 слотов Event.dat))
        if (op == kOpEventSet || op == kOpEventOff || op == kOpRankRecalc)
        {
            if ((op == kOpRankRecalc && !g_canRank) || (op != kOpRankRecalc && !g_canEvent))
            {
                PushResult(id, kStRefused, 11, L"%s: начала функций стока / P25 на этом узле не сошлись — не выполняется", opS); return;
            }
            if (op == kOpRankRecalc)
            {
                if (!ArgInt(args, L"what", &a[0]) || a[0] < 0 || a[0] > 3) { PushResult(id, kStRefused, 3, L"рейтинги: нужен what 0…3"); return; }
            }
            else
            {
                const bool okT = ArgInt(args, L"type", &a[0]) && (a[0] == 0 || a[0] == 1);
                const bool okC = ArgInt(args, L"chan", &a[1]) && a[1] >= -1 && a[1] <= 99;
                const bool okM = ArgInt(args, L"map", &a[2]) && a[2] >= -1 && a[2] <= 49;
                if (!(okT && okC && okM)) { PushResult(id, kStRefused, 3, L"событие: нужны type 0/1, chan −1…99, map −1…49"); return; }
            }
            if (op == kOpEventSet)
            {
                static const wchar_t* const kKeys[10] = { L"smon", L"sday", L"shour", L"smin", L"emon", L"eday", L"ehour", L"emin", L"v100", L"lv" };
                bool okA = true;
                for (int i = 0; i < 10 && okA; ++i) { okA = ArgInt(args, kKeys[i], &g[i]); }
                const bool okR = okA && g[0] >= 1 && g[0] <= 12 && g[1] >= 1 && g[1] <= 31 && g[2] >= 0 && g[2] <= 24 && g[3] >= 0 && g[3] <= 60
                                 && g[4] >= 1 && g[4] <= 12 && g[5] >= 1 && g[5] <= 31 && g[6] >= 0 && g[6] <= 24 && g[7] >= 0 && g[7] <= 60
                                 && g[8] >= 0 && g[8] <= 1000 && g[9] >= 0 && g[9] <= 0xFFFF;
                if (!okR) { PushResult(id, kStRefused, 3, L"событие: поля вне диапазонов стока (месяц 1…12, день 1…31, час 0…24, минута 0…60, "
                                       L"v100 0…1000, lv = MinLevel + 256·MaxLevel)"); return; }
            }
        }
        if (op == kOpGive)
        {
            static const wchar_t* const kKeys[10] = { L"code", L"q", L"ware", L"o1", L"v1", L"o2", L"v2", L"gem", L"up", L"plate" };
            bool okA = ArgInt(args, kKeys[0], &g[0]) && ArgInt(args, kKeys[1], &g[1]);
            for (int i = 2; i < 10 && okA; ++i) { int t = g[i]; if (ArgInt(args, kKeys[i], &t)) { g[i] = t; } }
            if (!okA || g[0] <= 0 || g[1] < 1 || g[1] > kGiveStackMax || (g[2] != 0 && g[2] != 1))
            {
                PushResult(id, kStRefused, 3, L"выдача: нужны code > 0, q 1…%d, ware 0/1", kGiveStackMax); return;
            }
        }
        int slot = -1; bool busy = false;
        Lock();
        for (int i = 0; i < kSlots; ++i)
        {
            const Slot& s = g_slot[i];
            if (s.active && s.snap && s.uid == uid && (idx < 0 || s.idx == idx)) { slot = i; break; }
        }
        if (slot >= 0)
        {
            Cmd& c = g_slot[slot].cmd;
            if (c.id) { busy = true; }
            else
            {
                c.id = id; c.op = op; c.uid = uid; c.idx = idx; c.gen = g_gen[slot]; c.expire = expire;
                c.a[0] = a[0]; c.a[1] = a[1]; c.a[2] = a[2]; c.v = v; memcpy(c.text, text, sizeof(c.text)); memcpy(c.g, g, sizeof(c.g));
                InterlockedIncrement(&g_cmdPending);
            }
        }
        Unlock();
        if (slot < 0) { PushResult(id, kStAbsent, 3, L"на узле нет персонажа %d/%d в игре", uid, idx); return; }
        if (busy) { PushResult(id, kStRefused, 5, L"у игрока уже есть команда в очереди — повторите"); return; }
    }

    bool Claim(wchar_t* err, int cch)
    {
        wchar_t sql[160]; wchar_t nodeL[80]; Lit(nodeL, ARRAYSIZE(nodeL), g_node, 32);
        _snwprintf_s(sql, _TRUNCATE, L"EXEC adm.BridgeClaim %s, %d", nodeL, g_claimMax);
        SQLHSTMT st = SQL_NULL_HSTMT;
        if (!SQL_SUCCEEDED(g_db.AllocHandle(SQL_HANDLE_STMT, g_db.dbc, &st))) { Diag(SQL_HANDLE_DBC, g_db.dbc, err, cch); return false; }
        g_db.SetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTo, 0);
        SQLRETURN r = g_db.ExecDirect(st, (SQLWCHAR*)sql, SQL_NTS);
        bool ok = SQL_SUCCEEDED(r) || r == SQL_NO_DATA;
        if (!ok) { Diag(SQL_HANDLE_STMT, st, err, cch); }
        // первый набор с колонками — строки захвата
        for (int guard = 0; ok && guard < 16; ++guard)
        {
            SQLSMALLINT cols = 0; g_db.NumResultCols(st, &cols);
            if (cols >= 11)
            {
                while (SQL_SUCCEEDED(g_db.Fetch(st)))
                {
                    SQLBIGINT id = 0, dl = 0; SQLINTEGER uid = 0, idx = 0, ttl = 0, left = 0; SQLLEN ind = 0;
                    static wchar_t op[32], node[40], args[420], nonce[40], mac[72];
                    op[0] = node[0] = args[0] = nonce[0] = mac[0] = 0;
                    g_db.GetData(st, 1, SQL_C_SBIGINT, &id, 0, &ind);
                    g_db.GetData(st, 2, SQL_C_WCHAR, op, sizeof(op), &ind);
                    g_db.GetData(st, 3, SQL_C_SLONG, &uid, 0, &ind);
                    g_db.GetData(st, 4, SQL_C_SLONG, &idx, 0, &ind);
                    g_db.GetData(st, 5, SQL_C_WCHAR, node, sizeof(node), &ind);
                    g_db.GetData(st, 6, SQL_C_WCHAR, args, sizeof(args), &ind); if (ind == SQL_NULL_DATA) { args[0] = 0; }
                    g_db.GetData(st, 7, SQL_C_WCHAR, nonce, sizeof(nonce), &ind);
                    g_db.GetData(st, 8, SQL_C_SLONG, &ttl, 0, &ind);
                    g_db.GetData(st, 9, SQL_C_WCHAR, mac, sizeof(mac), &ind);
                    g_db.GetData(st, 10, SQL_C_SLONG, &left, 0, &ind);
                    g_db.GetData(st, 11, SQL_C_SBIGINT, &dl, 0, &ind);   // ★ ревизия 24 К-2: срок (UNIX UTC) — часть подписи
                    // хвостовые пробелы CHAR → обрезать
                    for (wchar_t* w : { op, node, nonce, mac }) { int l = lstrlenW(w); while (l > 0 && w[l - 1] == L' ') { w[--l] = 0; } }
                    Dispatch((__int64)id, op, (int)uid, (int)idx, node, args, nonce, (int)ttl, mac, (int)left, (__int64)dl);
                }
                break;
            }
            r = g_db.MoreResults(st);
            if (r == SQL_NO_DATA) { break; }
            if (!SQL_SUCCEEDED(r)) { ok = false; Diag(SQL_HANDLE_STMT, st, err, cch); }
        }
        g_db.FreeStmt(st, SQL_CLOSE);
        g_db.FreeHandle(SQL_HANDLE_STMT, st);
        return ok;
    }

    // Пульс; 0 строк — строку узла перехватил другой процесс → заново NodeStart.
    bool Heartbeat(bool* lost, wchar_t* err, int cch)
    {
        *lost = false;
        int present = 0;
        Lock(); for (int i = 0; i < kSlots; ++i) { if (g_slot[i].active && g_slot[i].snap) { ++present; } } Unlock();
        wchar_t sql[300]; wchar_t nodeL[80]; Lit(nodeL, ARRAYSIZE(nodeL), g_node, 32);
        _snwprintf_s(sql, _TRUNCATE, L"EXEC adm.BridgeHeartbeat %s, %u, %d, %ld, %ld, %ld, %d", nodeL, GetCurrentProcessId(), g_mode,
                     g_stats.claimed, g_stats.done, g_stats.dbErrors, present);
        SQLHSTMT st = SQL_NULL_HSTMT;
        if (!SQL_SUCCEEDED(g_db.AllocHandle(SQL_HANDLE_STMT, g_db.dbc, &st))) { Diag(SQL_HANDLE_DBC, g_db.dbc, err, cch); return false; }
        g_db.SetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTo, 0);
        SQLRETURN r = g_db.ExecDirect(st, (SQLWCHAR*)sql, SQL_NTS);
        bool ok = SQL_SUCCEEDED(r);
        if (!ok) { Diag(SQL_HANDLE_STMT, st, err, cch); }
        else if (SQL_SUCCEEDED(g_db.Fetch(st))) { SQLINTEGER n = 0; SQLLEN ind = 0; g_db.GetData(st, 1, SQL_C_SLONG, &n, 0, &ind); *lost = n == 0; }
        g_db.FreeStmt(st, SQL_CLOSE);
        g_db.FreeHandle(SQL_HANDLE_STMT, st);
        return ok;
    }

    bool NodeStart(wchar_t* err, int cch)
    {
        wchar_t sql[300]; wchar_t nodeL[80]; Lit(nodeL, ARRAYSIZE(nodeL), g_node, 32);
        _snwprintf_s(sql, _TRUNCATE, L"EXEC adm.BridgeNodeStart %s, %u, %d, %d, %d", nodeL, GetCurrentProcessId(), Config::kVersion, kProto, g_mode);
        if (!DbExec(sql, err, cch)) { return false; }
        MarkAllDirty();
        return true;
    }

    // Просроченные команды слотов и завершение объявлений (нить моста).
    void Sweep()
    {
        const DWORD now = GetTickCount();
        if (g_cmdPending)
        {
            for (int i = 0; i < kSlots; ++i)
            {
                __int64 id = 0;
                Lock();
                Cmd& c = g_slot[i].cmd;
                if (c.id && (LONG)(now - c.expire) >= 0) { id = c.id; c.id = 0; InterlockedDecrement(&g_cmdPending); }
                Unlock();
                if (id) { PushResult(id, kStAbsent, 4, L"команда не дошла до такта игрока за срок (портал/выход)"); }
            }
        }
        if (g_globPending)
        {
            for (int k = 0; k < kMaxGlobal; ++k)
            {
                __int64 id = 0; int n = 0; bool fin = false;
                Lock();
                Glob& g = g_glob[k];
                if (g.id)
                {
                    // все менеджеры, у которых есть игроки, выполнили — или 3 с после первого, или срок
                    int need = 0, have = 0;
                    void* seen[kMaxMgr]; int ns = 0;
                    for (int i = 0; i < kSlots; ++i)
                    {
                        void* m = g_slot[i].active && g_slot[i].snap ? g_slot[i].mgr : nullptr;
                        if (!m) { continue; }
                        bool dup = false; for (int j = 0; j < ns; ++j) { if (seen[j] == m) { dup = true; break; } }
                        if (dup || ns >= kMaxMgr) { continue; }
                        seen[ns++] = m; ++need;
                        for (int j = 0; j < g.nDone; ++j) { if (g.done[j] == m) { ++have; break; } }
                    }
                    fin = have >= need || (g.first && (DWORD)(now - g.first) >= 3000u) || (LONG)(now - g.expire) >= 0;
                    if (fin) { id = g.id; n = g.nDone; g.id = 0; }
                }
                Unlock();
                if (fin)
                {
                    InterlockedDecrement(&g_globPending);
                    // ★ ревизия 24 К-5: никому не ушло (на узле нет игроков) — не «выполнена»
                    if (n > 0) { PushResult(id, kStDone, 0, L"объявление разослано: нитей карт %d", n); }
                    else       { PushResult(id, kStAbsent, 5, L"объявление: на узле нет игроков — некому разослать"); }
                }
            }
        }
    }

    DWORD WINAPI BridgeThread(void*)
    {
        DWORD lastHb = 0, lastTry = 0; bool logged = false;
        wchar_t err[512];
        for (;;)
        {
            if (!g_enabled) { break; }
            const DWORD now = GetTickCount();
            if (!g_db.up)
            {
                if (lastTry && (DWORD)(now - lastTry) < (DWORD)g_reconnectS * 1000u) { Sleep(g_pollMs); Sweep(); continue; }
                lastTry = now;
                if (!DbConnect(err, ARRAYSIZE(err)) || !NodeStart(err, ARRAYSIZE(err)))
                {
                    InterlockedIncrement(&g_stats.dbErrors);
                    if (!logged) { Log::Line(L"[P127] база AsdaAdmin недоступна — %s; переподключение каждые %d с, игра не блокируется", err, g_reconnectS); logged = true; }
                    DbClose();
                    Sleep(g_pollMs); Sweep(); continue;
                }
                Log::Line(L"[P127] мост подключён к AsdaAdmin: узел %s, PID %u, Mode=%d", g_node, GetCurrentProcessId(), g_mode);
                logged = false; lastHb = 0;
            }
            bool ok = SendResults(err, ARRAYSIZE(err)) && SendPresence(err, ARRAYSIZE(err)) && Claim(err, ARRAYSIZE(err));
            if (ok && (!lastHb || (DWORD)(now - lastHb) >= (DWORD)g_heartbeatS * 1000u))
            {
                bool lost = false;
                ok = Heartbeat(&lost, err, ARRAYSIZE(err));
                if (ok && lost) { Log::Line(L"[P127] строка узла %s у другого процесса — заново NodeStart", g_node); ok = NodeStart(err, ARRAYSIZE(err)); }
                lastHb = now;
            }
            if (!ok)
            {
                InterlockedIncrement(&g_stats.dbErrors);
                Log::Line(L"[P127] ошибка SQL: %s — переподключение", err);
                DbClose(); lastTry = now;
            }
            Sweep();
            Sleep(g_pollMs);
        }
        return 0;
    }

    // Секреты: файл SecretFile ([Bridge] Password, HmacKey = hex). Строка подключения — с паролем (не печатается).
    bool LoadSecrets(wchar_t* why, int cch)
    {
        wchar_t rel[MAX_PATH], path[MAX_PATH], full[MAX_PATH];
        Config::GetStr(kSec, L"SecretFile", L"ConfigSet\\admin_bridge.ini", rel, ARRAYSIZE(rel));
        if (rel[0] && rel[1] == L':') { lstrcpynW(path, rel, MAX_PATH); } else { _snwprintf_s(path, _TRUNCATE, L"%s%s", Config::BaseDir(), rel); }
        if (!GetFullPathNameW(path, MAX_PATH, full, nullptr)) { lstrcpynW(full, path, MAX_PATH); }
        if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) { _snwprintf_s(why, cch, _TRUNCATE, L"нет файла секретов %s", full); return false; }
        wchar_t pwd[256] = L"", key[160] = L"";
        GetPrivateProfileStringW(L"Bridge", L"Password", L"", pwd, ARRAYSIZE(pwd), full);
        GetPrivateProfileStringW(L"Bridge", L"HmacKey", L"", key, ARRAYSIZE(key), full);
        const int kl = lstrlenW(key);
        if (!pwd[0] || kl < 32 || kl > 128 || (kl & 1)) { _snwprintf_s(why, cch, _TRUNCATE, L"в %s нет Password или HmacKey (hex 32…128)", full); SecureZeroMemory(pwd, sizeof(pwd)); return false; }
        g_keyLen = kl / 2;
        for (int i = 0; i < g_keyLen; ++i)
        {
            int v = 0;
            for (int j = 0; j < 2; ++j)
            {
                const wchar_t c = key[2 * i + j];
                const int d = c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 : c >= L'A' && c <= L'F' ? c - L'A' + 10 : -1;
                if (d < 0) { g_keyLen = 0; SecureZeroMemory(pwd, sizeof(pwd)); SecureZeroMemory(key, sizeof(key)); lstrcpynW(why, L"HmacKey не hex", cch); return false; }
                v = v * 16 + d;
            }
            g_key[i] = (BYTE)v;
        }
        SecureZeroMemory(key, sizeof(key));
        wchar_t drv[64], srv[64], dbn[64], uid[64];
        Config::GetStr(kSec, L"Driver", L"SQL Server", drv, ARRAYSIZE(drv));
        Config::GetStr(kSec, L"Server", L"127.0.0.1,1433", srv, ARRAYSIZE(srv));
        Config::GetStr(kSec, L"Database", L"AsdaAdmin", dbn, ARRAYSIZE(dbn));
        Config::GetStr(kSec, L"Login", L"asda_bridge", uid, ARRAYSIZE(uid));
        wchar_t pq[600]; int k = 0;
        for (const wchar_t* p = pwd; *p && k < ARRAYSIZE(pq) - 3; ++p) { if (*p == L'}') { pq[k++] = L'}'; } pq[k++] = *p; }
        pq[k] = 0;
        _snwprintf_s(g_conn, _TRUNCATE, L"DRIVER={%s};SERVER=%s;DATABASE=%s;UID=%s;PWD={%s};APP=AsdaAdminBridge", drv, srv, dbn, uid, pq);
        SecureZeroMemory(pwd, sizeof(pwd)); SecureZeroMemory(pq, sizeof(pq));
        return true;
    }

    void ResolveNode()
    {
        wchar_t nm[33];
        Config::GetStr(kSec, L"NodeName", L"", nm, ARRAYSIZE(nm));
        if (nm[0]) { lstrcpynW(g_node, nm, ARRAYSIZE(g_node)); return; }
        wchar_t dir[MAX_PATH]; lstrcpynW(dir, Config::BaseDir(), MAX_PATH);
        int l = lstrlenW(dir);
        while (l > 0 && (dir[l - 1] == L'\\' || dir[l - 1] == L'/')) { dir[--l] = 0; }
        const wchar_t* last = dir;
        for (const wchar_t* p = dir; *p; ++p) { if (*p == L'\\' || *p == L'/') { last = p + 1; } }
        lstrcpynW(g_node, *last ? last : L"?", ARRAYSIZE(g_node));
    }

    int Clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

    // ★ ревизия 24 В-1: начало вызываемой функции стока. 1 — стоковый пролог (orig, 3 б), 2 — jmp rel32 (E9) с целью внутри этой DLL
    //   (врезка нашего же патча, стоящего раньше в реестре: вызов пройдёт через неё так же, как у стоковых вызывающих), 0 — иное.
    int FuncStartOk(DWORD va, const BYTE* orig)
    {
        if (Hook::Verify(va, orig, 3)) { return 1; }
        const BYTE* p = (const BYTE*)va;
        if (p[0] != 0xE9) { return 0; }
        const DWORD target = va + 5 + *(const DWORD*)(p + 1);
        HMODULE me = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)&FuncStartOk, &me) || !me) { return 0; }
        const BYTE* b = (const BYTE*)me;
        const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(b + ((const IMAGE_DOS_HEADER*)b)->e_lfanew);
        const DWORD lo = (DWORD)b, hi = lo + nt->OptionalHeader.SizeOfImage;
        return target >= lo && target < hi ? 2 : 0;
    }
}

extern "C" __declspec(dllexport) void __stdcall P127_GetStats(P127_Stats* out)
{
    if (out) { memcpy(out, &g_stats, sizeof(g_stats)); }
}

#ifdef ASDA_PATCH_STAND
// Стенд (только out\stand\AsdaPatch.dll): разложить команду так же, как после захвата, и прогнать просрочку/итоги без базы.
extern "C" __declspec(dllexport) void __stdcall P127_TestDispatch(__int64 id, const wchar_t* op, int uid, int idx, const wchar_t* node,
                                                                   const wchar_t* args, const wchar_t* nonce, int ttl, const wchar_t* mac, int leftS,
                                                                   __int64 deadline)
{
    Dispatch(id, op, uid, idx, node, args, nonce, ttl, mac, leftS, deadline);
}
// Текущее время UNIX UTC часами DLL (стенд считает срок подписи от него).
extern "C" __declspec(dllexport) __int64 __stdcall P127_TestNow() { return NowUnix(); }
extern "C" __declspec(dllexport) void __stdcall P127_TestSweep() { Sweep(); }
// ★ А2.3: тексты последних снятых итогов (до 16) — стенд разбирает ячейки выдачи и клетку переноса.
static wchar_t g_takenText[16][400];
extern "C" __declspec(dllexport) int __stdcall P127_TestTakenText(int i, wchar_t* out, int cch)
{
    if (i < 0 || i >= 16 || !out || cch < 1) { return 0; }
    lstrcpynW(out, g_takenText[i], cch); return 1;
}
// Снять итоги (до max): ids/status/code; возврат — сколько.
extern "C" __declspec(dllexport) int __stdcall P127_TestTakeResults(__int64* ids, int* st, int* code, int max)
{
    int n = 0;
    Lock();
    while (n < max && g_resCount > 0)
    {
        ids[n] = g_res[g_resHead].id; st[n] = g_res[g_resHead].status; code[n] = g_res[g_resHead].code;
        if (n < 16) { lstrcpynW(g_takenText[n], g_res[g_resHead].text, 400); }        // ★ А2.3: тексты итогов для стенда
        ++n; g_resHead = (g_resHead + 1) % kResCap; --g_resCount;
    }
    Unlock();
    return n;
}
// Подпись для стенда тем же ключом (hex 64 в out, 65 символов).
extern "C" __declspec(dllexport) int __stdcall P127_TestMac(const wchar_t* nonce, const wchar_t* op, int uid, int idx, const wchar_t* node,
                                                            const wchar_t* args, int ttl, __int64 deadline, wchar_t* out)
{
    BYTE m[32]; if (!MacOf(nonce, op, uid, idx, node, args, ttl, deadline, m)) { return 0; }
    static const wchar_t hx[] = L"0123456789abcdef";
    for (int i = 0; i < 32; ++i) { out[2 * i] = hx[m[i] >> 4]; out[2 * i + 1] = hx[m[i] & 15]; }
    out[64] = 0; return 1;
}
// Цепочка общих точек P73 → P127 (те же C-функции, что зовут стабы 4001/5058, детур SetConnectFlag и стаб UserTick 0x526CEB).
extern "C" __declspec(dllexport) void __stdcall P127_TestP73Logon(int kind, int num, BYTE* user, int uid) { P73_OnLogon(kind, num, user, uid); }
extern "C" __declspec(dllexport) void __stdcall P127_TestP73ConnFlag(int slot, int flag) { P73_OnConnFlag(slot, flag); }
extern "C" __declspec(dllexport) int  __stdcall P127_TestTick(void* mgr, int num, BYTE* user) { return P73_OnCheckUser(mgr, num, user); }
extern "C" __declspec(dllexport) int  __stdcall P127_TestInKick() { return P127_KickInProgress(); }
// ★ А2.3: одна стоковая выдача переносом хвоста 0x552360 (стенд stand_p100 сравнивает с настоящим обработчиком 6042).
//   opts: o1, v1, o2, v2, самоцвет, ступень; cell3: сумка, ячейка, выдано. Возврат — код стока (0 — выдано).
extern "C" __declspec(dllexport) int __stdcall P127_TestGiveOne(void* mgr, int num, int uid, int code, int bag, int amt, const int* opts, int* cell3)
{
    GiveOpts op = { { opts[0], opts[2] }, { opts[1], opts[3] }, opts[4], opts[5] };
    GiveCell c = {};
    const int r = GiveOne(mgr, num, uid, code, bag, amt, op, &c);
    cell3[0] = c.plate; cell3[1] = c.posx; cell3[2] = c.amount; cell3[3] = c.merged ? 1 : 0;
    return r;
}
// ★ ревизия 29 М-3: весь цикл RunGive (повторы, стопка по 19, остановка, строка cells) на настоящем мире стенда. g10 — как Cmd.g.
//   Возврат — статус итога; текст итога — в out.
extern "C" __declspec(dllexport) int __stdcall P127_TestRunGive(void* mgr, int num, int uid, const int* g10, wchar_t* out, int cch)
{
    Cmd c = {}; c.id = 990000 + num; c.op = kOpGive; c.uid = uid; memcpy(c.g, g10, sizeof(c.g));
    RunGive(mgr, num, c, "stand", L"stand");
    int st = -1; out[0] = 0;
    Lock();
    while (g_resCount > 0)
    {
        const Res& r = g_res[g_resHead];
        if (r.id == c.id) { st = r.status; _snwprintf_s(out, cch, _TRUNCATE, L"%d|%s", r.code, r.text); }
        g_resHead = (g_resHead + 1) % kResCap; --g_resCount;
    }
    Unlock();
    return st;
}
// ★ А2.3: сверка выбора оператора с таблицами (как RunGive): 1 — годится.
extern "C" __declspec(dllexport) int __stdcall P127_TestGiveCheck(int code, const int* opts)
{
    const BYTE* it = TabRec(kVaIT, code - 20551, 71);
    bool ok = true;
    for (int i = 0; i < 2; ++i) { ok = ok && OptionOk(*(const short*)(it + 18 + 4 * i), opts[2 * i], opts[2 * i + 1]); }
    return ok && GemOk(code, opts[4]) && UpOk(code, opts[5]) ? 1 : 0;
}
// Количество ожидающих (слоты / объявления).
extern "C" __declspec(dllexport) void __stdcall P127_TestPending(int* cmds, int* globs) { *cmds = g_cmdPending; *globs = g_globPending; }
#endif

PatchResult P127_AdminBridge()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", false)) { return PatchResult::Disabled; }
    g_mode       = Config::GetInt(kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_pollMs     = Clamp(Config::GetInt(kSec, L"PollMs", 500), 100, 5000);
    g_heartbeatS = Clamp(Config::GetInt(kSec, L"HeartbeatSec", 5), 1, 60);
    g_snapshotS  = Clamp(Config::GetInt(kSec, L"SnapshotSec", 5), 1, 300);
    g_pendingS   = Clamp(Config::GetInt(kSec, L"PendingSec", 30), 2, 300);
    g_kickType   = Clamp(Config::GetInt(kSec, L"KickType", 0), 0, 255);
    g_claimMax   = Clamp(Config::GetInt(kSec, L"ClaimMax", 16), 1, 64);
    g_loginTo    = Clamp(Config::GetInt(kSec, L"LoginTimeoutSec", 5), 1, 60);
    g_queryTo    = Clamp(Config::GetInt(kSec, L"QueryTimeoutSec", 10), 1, 120);
    g_reconnectS = Clamp(Config::GetInt(kSec, L"ReconnectSec", 10), 1, 600);
    g_soulSession = Config::GetBool(L"P48_KickAutoBlock", L"SoulMateSessionAccount", true);
    ResolveNode();

    wchar_t why[400];
    if (!LoadSecrets(why, ARRAYSIZE(why)))
    {
        Log::Line(L"    P127: [ОШИБКА] %s — мост не ставится (сток; секреты кладёт tools/deploy_p127.py)", why);
        return PatchResult::Failed;
    }
    if (!P73_EventsHooked())
    {
        Log::Line(L"    P127: [ОШИБКА] события входа/разрыва не доходят до общей точки (нужен P47 Match20000 или P73, и P61 или P73) — не ставится");
        return PatchResult::Failed;
    }
    // ★ ревизия 24 В-1: функции стока P127 только ВЫЗЫВАЕТ; их начало могут уже занимать врезки патчей, стоящих раньше в реестре
    //   (0x52EDB0 — jmp P48 DisconnectStub при любом Enabled P48). Годится: стоковый пролог `55 8B EC` ИЛИ jmp rel32 в ЭТУ DLL.
    const struct { DWORD va; const BYTE* orig; const wchar_t* name; } fns[] =
    {
        { 0x0052EDB0, kDiscOrig,   L"Send_DisConnectType" },
        { 0x00526E40, kExcOrig,    L"___ExceptionDisConnetUser___" },
        { Srv::kSendNotice, kNoticeOrig, L"sendNoticeClient" },
    };
    for (const auto& f : fns)
    {
        const int r = FuncStartOk(f.va, f.orig);
        if (!r)
        {
            wchar_t hex[40]; Hook::Dump(f.va, 6, hex, ARRAYSIZE(hex));
            Log::Line(L"    MISMATCH P127 @0x%08X (%s): ожидалось [55 8b ec] или jmp в AsdaPatch, в памяти [%s]", f.va, f.name, hex);
            return PatchResult::Mismatch;
        }
        Log::Line(L"    P127: 0x%08X %s — %s", f.va, f.name, r == 1 ? L"стоковый пролог" : L"врезка AsdaPatch (jmp в эту DLL) — вызов идёт через неё, как у стока");
    }
    // ★ А2.2: живые правки — только через общие точки патчей, которые сами сверили свои адреса
    g_canExp      = P75_Applied();
    g_canTitleDel = P24_Applied();
    g_canTitleAdd = P24_Applied() && FuncStartOk(0x0054A980, kFameOrig) && FuncStartOk(0x0054A7D0, kFameOrig)
                    && FuncStartOk(0x0054A610, kFameOrig) && FuncStartOk(0x0054A890, kFameOrig);
    g_canFame     = P25_Applied();
    // ★ А2.3: выдача и перенос в своей карте — функции стока только ВЫЗЫВАЮТСЯ (сток или jmp-врезка этой DLL в начале)
    {
        const DWORD giveFns[] = { 0x004D6740, 0x004D6CE0, 0x0040A9F0, 0x0043FA00, 0x0043FB20, 0x0043F880, 0x005646C0, 0x004C0A30,
                                  0x00532530, 0x005324F0, 0x004A7EA0, 0x004D63F0, Srv::kSendPacket };
        const DWORD jumpFns[] = { 0x004221D0, 0x00523ED0, 0x00523EA0, 0x0041EC30, 0x0054EBF0 };
        g_canGive = true; g_canJump = true;
        for (DWORD va : giveFns) { if (!FuncStartOk(va, kPrologue)) { g_canGive = false; Log::Line(L"    P127: выдача живьём ВЫКЛ — начало 0x%08X не сошлось", va); } }
        for (DWORD va : jumpFns) { if (!FuncStartOk(va, kPrologue)) { g_canJump = false; Log::Line(L"    P127: перенос в своей карте ВЫКЛ — начало 0x%08X не сошлось", va); } }
        // ★ А5.2: призыв / возврат монстров — вызываются sub_5646C0 и sub_4C0A60 (сток или jmp-врезка этой DLL)
        const DWORD mobFns[] = { 0x005646C0, 0x004C0A60 };
        g_canMob = true;
        for (DWORD va : mobFns) { if (!FuncStartOk(va, kPrologue)) { g_canMob = false; Log::Line(L"    P127: призыв монстров ВЫКЛ — начало 0x%08X не сошлось", va); } }
        Log::Line(L"    P127: живьём (v83): призыв / возврат группы монстров 6045/6046 %s", g_canMob ? L"да (оператор + GM-флаг, sub_5646C0 в NpcServer)" : L"НЕТ");
        // ★ А5.4: события 6038/6040 — вызываются sub_5646C0, sub_4C0A90, sub_4A7EB0, sub_40C960 (сток или jmp-врезка этой DLL);
        //   рейтинги 6020 — общая точка P25 (P25 сам сверил свои адреса)
        const DWORD evFns[] = { 0x005646C0, 0x004C0A90, 0x004A7EB0, 0x0040C960 };
        g_canEvent = true;
        for (DWORD va : evFns) { if (!FuncStartOk(va, kPrologue)) { g_canEvent = false; Log::Line(L"    P127: события ВЫКЛ — начало 0x%08X не сошлось", va); } }
        g_canRank = P25_Applied();
        Log::Line(L"    P127: живьём (v84): события 6038/6040 %s, пересчёт рейтингов 6020 %s",
                  g_canEvent ? L"да (оператор + GM-флаг, sub_5646C0 в RelayServer)" : L"НЕТ", g_canRank ? L"да (P25)" : L"НЕТ");
    }
    Log::Line(L"    P127: живьём (v81): опыт/уровень %s, звание выдать %s / снять %s, пересчёт славы %s, нотис одному — да",
              g_canExp ? L"да (P75)" : L"НЕТ (P75 не стоит)", g_canTitleAdd ? L"да" : L"НЕТ", g_canTitleDel ? L"да (P24)" : L"НЕТ (P24 не стоит)",
              g_canFame ? L"да (P25)" : L"НЕТ (P25 не стоит)");
    Log::Line(L"    P127: живьём (v82): выдача предмета %s (заряды и ячейка F — %s), перенос в своей карте %s",
              g_canGive ? L"да (хвост 0x552360, оператор 2/11)" : L"НЕТ", P100_Active() ? L"через P100" : L"сток (P100 не активен)",
              g_canJump ? L"да (0x54EBF0)" : L"НЕТ");
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    InterlockedExchange(&g_enabled, 1);
    if (!P73_UserTickInstall())
    {
        InterlockedExchange(&g_enabled, 0);
        Log::Line(L"    P127: [ОШИБКА] общая точка UserTick 0x526CEB не поставлена (байты не совпали) — мост выключен");
        return PatchResult::Mismatch;
    }
    if (!g_thread) { g_thread = CreateThread(nullptr, 0, &BridgeThread, nullptr, 0, nullptr); }
    if (!g_thread)
    {
        InterlockedExchange(&g_enabled, 0);
        Log::Line(L"    P127: [ОШИБКА] нить моста не создана (CreateThread %u) — мост выключен (UserTick работает вхолостую)", GetLastError());
        return PatchResult::Failed;
    }
    Log::Line(L"    P127: мост админ-центра — узел %s, Mode=%d (%s); опрос %d мс, пульс %d с; присутствие — такт игрока (UserTick 0x526CEB), "
              L"команды ping/kick/announce/move, кик 4101 тип %d (P48 не засчитывает); база — своё ODBC (логин и пароль из файла секретов)",
              g_node, g_mode, g_mode == 1 ? L"исполнять" : L"только слушать: присутствие и ping, прочее — журнал", g_pollMs, g_heartbeatS, g_kickType);
    return PatchResult::Applied;
}
