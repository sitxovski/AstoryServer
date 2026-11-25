// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P123 — GM-ПРЫЖОК НА ДРУГУЮ КАРТУ ПО КЛЕТКЕ (09.11.2026, пачка 20; решение владельца «Да, P123», номер и Config v77 — координатор).
//  Разбор: Reports/batch20/gm_teleport/README.md; документ AstoryServer/Docs/GameServer/gm-map-jump-p123.md.
//
//  ── СТОК (GameServer = Indun = Ch2, e7b4ac38) ──
//  6010 CharJumpCommandPosition@0x54EF50 (GS:128288): тело 4 б (i16 X, i16 Z), гейты слот / sub_52ECF0 (UserIndex 0…5000) / анти-повтор
//  sub_524390 / MD5 тела sub_523F00(4) → IsCheckPosInMaxPos → ближайшая проходимая клетка спиралью sub_41EC30 → 4056. Карта — только СВОЯ.
//  Переноса «карта + клетка» у стока нет (6014 — к игроку, 6084 — смена канала на своей карте и клетке; перебор операторских опкодов
//  диспетчера 0x1777…0x17FE — README §1).
//
//  ── ЧТО ДЕЛАЕТ P123 (клиент alpha-7.1.0 не затронут: он шлёт только 4-байтовую форму) ──
//  Площадка 0x54EF50 (9 б пролога `push ebp; mov ebp,esp; sub esp,80h`) → заглушка: кадр 6010 с телом 8 б (i16 X, i16 Z, i16 карта,
//  u16 метка 0xA123) обрабатывает P123, любой другой — сток без изменений (пролог исполняется в заглушке, возврат на 0x54EF59).
//  ⚠ ПО ДЛИНЕ ФОРМЫ НЕ РАЗЛИЧИТЬ: клиент (эталон CNetwork_Send a6=1, порт PacketFrame bPad) добивает кадр 0…19 нулевыми байтами,
//    стоковый 6010 приходит длиной 38…57 б. Поэтому признак — метка на месте [39..40] (у стоковой формы там нули паддинга или хвост 0xFE
//    за кадром) и MD5 по 8 б; клиент шлёт форму P123 без паддинга — кадр ровно 42 б (P55 для 6010: 38…57).
//  Форма 8 б:
//    гейты — слот (sub_5324A0), оператор sub_52ECF0 (UserIndex 0…5000) И GM-флаг P47_IsGmUser (sub_52ED50 == 1, общая точка P47/P68/
//    P69/P73; повторно здесь — чтобы P123 не зависел от того, включён ли P47), анти-повтор sub_524390, MD5 тела sub_523F00(8);
//    ★ v79 (09.11.2026, «не пускает на элитные карты»): гейт очереди отряда/RoseWar снят (ложный: слоты из 5058 порт-клиента = 0),
//    закрытая в OpenMapInfo карта GM-у разрешена (строка Send Ok помечает); RoseWar (тип 4) и инстансы (тип 2) — по-прежнему отказ.
//    ★ v78 (09.11.2026, живой отказ у GM_sitxovski): sub_52ED50 — `char __thiscall`: на 0x52ED98 `mov eax,[ebp-8]` (указатель CUser),
//    затем `mov al,[eax+…]` — старшие 24 бита eax = мусор указателя. В v77 результат читался как int и сравнивался с 1 → у ЛЮБОГО
//    настоящего GM ветка «не оператор», молча. Стенд не поймал: его заглушка возвращала чистый int. Теперь только P47_IsGmUser (char).
//    отказ, если: карта = своя (своя карта — 4-байтовой формой стока),
//    своя карта типа 4 (RoseWar, как 6014), карта назначения вне MapInfo.txt / тип не 0,1,3,6 / нет записи
//    Total_PortalConfig / нет активного потока этой карты в процессе / клетка вне карты или рядом нет проходимой (sub_41EC30 на
//    CMapManager ЭТОЙ карты — та же спираль, что CharPortalMake даст на прибытии; за краем карты CharPortalMake персонажа не ставит);
//    иначе 5055 код 1 (53 б, 1:1 как P120 / RecvContinent_PortalMove: IP и порт из Total_PortalConfig[карта], номер карты, клетка =
//    найденная проходимая) → клиент штатно: 5056 старой карте, 5058 с клеткой, CharPortalLogonReq → CharPortalMake.
//  Отказ — клиенту молча (ответа у стоковой 6010 тоже нет; текст причины клиенту не шлём — решение владельца 09.11), строка в
//  Log_Operator. ★ v78: не оператор / конверт (анти-повтор, MD5) тоже пишут строку в Log_Operator (в v77 молчал и журнал — причину
//  живого отказа пришлось выводить дизассемблером). Успех — «P123: … Send Ok» в Log_Operator.
//  Соседи: P41 сверяет 0x54EF59 (`mov [ebp-78h],ecx`) и ставит 0x54F2F6 — не пересекаются; P47 (гейт диспетчера) и P55 (6010: 38…57 б)
//  кадр 42 б пропускают. Откат: patches.ini [P123_GmMapJump] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstring>

namespace
{
    const wchar_t* const kSec = L"P123_GmMapJump";             // секция patches.ini

    // ── площадка ──
    constexpr DWORD kSite = 0x0054EF50;                       // CharJumpCommandPosition: push ebp; mov ebp,esp; sub esp,80h
    const BYTE kSiteOrig[9] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 };
    constexpr DWORD kBack = 0x0054EF59;                       // mov [ebp-78h],ecx (сверяет и P41)
    const BYTE kBackOrig[3] = { 0x89, 0x4D, 0x88 };
    constexpr DWORD kEpilog = 0x0054F3FB;                     // mov esp,ebp; pop ebp; ret 8 — сколько снимает обработчик
    const BYTE kEpilogOrig[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };
    constexpr int  kFrameMin = 42;                            // 9 шапка + 8 секрет + 16 MD5 + 8 тело + 1 хвост (клиент шлёт без паддинга)
    constexpr int  kPayload  = 8;
    constexpr int  kOffMagic = 39;                            // u16 метка формы P123 (кадр+33 тело, +6)
    constexpr WORD kMagic    = 0xA123;

    // ── объекты сервера (адреса сняты дизасмом стока, verify_p123) ──
    constexpr int   kOffThread    = 4;                        // CUserManager+4 → поток карты
    constexpr int   kOffMapIdx    = 0x4950;                   // поток+0x4950 → номер карты (как P120)
    constexpr int   kOffMapMng    = 0x0C;                     // поток+0x0C → CMapManager (6010: *(this+4)+12)
    constexpr int   kMapMngW      = 8;                        // CMapManager: i16 ширина в клетках (sub_4221D0)
    constexpr int   kMapMngH      = 10;                       // i16 высота
    constexpr int   kUserOffX     = 0x54E6;                   // CUser: i16 клетка X
    constexpr int   kUserOffZ     = 0x54E8;
    // (★ v79: CUser+0x3F43C — слоты очереди отряда/RoseWar — больше не читаем, см. Handle)
    constexpr int   kOffTotalPort = 0xA60;                    // CUserManager+2656: Total_PortalConfig, запись 31 б по номеру карты
    constexpr int   kTpRec        = 31;                       // +0 Use, +1 номер (u16), +5 IP 16 б, +25 порт
    constexpr DWORD kMapRows      = 0x005F5EE8;               // число строк MapInfo.txt
    constexpr DWORD kMapTable     = 0x005F5E18;               // указатель на таблицу MapInfo (запись 0xEC)
    constexpr int   kMapRec       = 0xEC;
    constexpr int   kMapOffType   = 0x3F;
    constexpr DWORD kOpenMapGate  = 0x005F5EF6;               // 1 = OpenMapInfo.ini прочитан
    constexpr DWORD kPortalUseOp  = 0x0052C610;               // movzx ecx,[eax+base] — массив open[] (P30 переносит)
    constexpr DWORD kCtorCountOp  = 0x00582678;               // push N — число слотов
    constexpr int   kOpenSlotSize = 0x33;
    constexpr int   kOpenHardMax  = 30;
    // CThreadManager (ecx у sub_4A83A0 в SendMonitorInfo 0x415E20 / 0x41633E)
    constexpr DWORD kThreadMgr    = 0x0060AD18;
    constexpr int   kTmThreads    = 0x08;                     // → база массива потоков
    constexpr int   kTmActive     = 0x18;                     // → байт «поток активен» по индексу
    constexpr int   kTmCount      = 0x1D5270;                 // число потоков (sub_4A83A0 / SearchThreadInfo)
    constexpr int   kTmInfo       = 0x1D569C;                 // → записи 0x2C б по индексу потока, +0x11 номер карты
    constexpr int   kThreadStride = 0x013851C8;               // размер потока
    constexpr int   kInfoRec      = 0x2C;
    constexpr int   kInfoOffMap   = 0x11;
    constexpr int   kReplyLen     = 53;
    constexpr WORD  kOpReply      = 5055;
    constexpr int   kLogCat       = 6;                        // Log_Operator — туда пишет и сток 6010

    typedef void        (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);                                     // sub_569DF0
    typedef BYTE*       (__fastcall *PFN_GetUser)(void* mgr, void* edx, int userNum);                             // sub_5324A0
    typedef int         (__fastcall *PFN_UserIndex)(void* mgr, void* edx, int userNum);                           // sub_5324F0
    typedef const char* (__fastcall *PFN_Name)(void* mgr, void* edx, int userNum);                                // sub_532570
    typedef int         (__fastcall *PFN_Replay)(void* mgr, void* edx, DWORD lo, DWORD hi, int userNum, const char* fn);   // sub_524390
    typedef int         (__fastcall *PFN_Sign)(void* mgr, void* edx, BYTE* frame, int len, int userNum, int mode);         // sub_523F00
    typedef int         (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, void* buf, int a6, int a7); // sub_4C28F0
    typedef int         (__fastcall *PFN_IsOpIdx)(void* mgr, void* edx, int userNum, int a3);                     // sub_52ECF0 ret 8
    // sub_52ED50 (GM-флаг) напрямую не вызываем: он `char` (старшие биты eax — мусор), только через P47_IsGmUser (★ v78).
    typedef int         (__fastcall *PFN_ThreadAt)(void* tm, void* edx, int k);                                   // sub_4A83A0 ret 4
    typedef int*        (__fastcall *PFN_Nearest)(void* map, void* edx, int* out, int x, int z, float a5, float a6); // sub_41EC30 ret 14h

    const FnSrvLog      SrvLog     = (FnSrvLog)Srv::kLog;
    const PFN_GetUser   pGetUser   = (PFN_GetUser)Srv::kGetUser;
    const PFN_UserIndex pUserIndex = (PFN_UserIndex)Srv::kGetUserNumber;
    const PFN_Name      pName      = (PFN_Name)Srv::kGetCharNamePtr;
    const PFN_Replay    pReplay    = (PFN_Replay)Srv::kSecretCheck;
    const PFN_Sign      pSign      = (PFN_Sign)Srv::kPktSignCheck;
    const PFN_ToClient  pToClient  = (PFN_ToClient)Srv::kSendPacket;
    const PFN_IsOpIdx   pIsOpIdx   = (PFN_IsOpIdx)Srv::kIsOperatorIndex;
    const PFN_ThreadAt  pThreadAt  = (PFN_ThreadAt)0x004A83A0;
    const PFN_Nearest   pNearest   = (PFN_Nearest)0x0041EC30;
    // Начала вызываемых напрямую функций стока (verify_p123 сверяет и ret).
    const BYTE kThreadAtOrig[6] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68 };   // 0x4A83A0
    const BYTE kNearestOrig[6]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x30 };   // 0x41EC30
    const BYTE kIsGmFlagOrig[6] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C };   // 0x52ED50
    // Опоры адресов менеджера потоков (SearchThreadInfo): cmp ecx,[eax+1D5270h] @0x4A852B; mov eax,[edx+18h] @0x4A853B;
    //   mov edx,[ecx+1D569Ch] @0x4A8554 + mov eax,[edx+eax+11h]; imul ecx,ecx,13851C8h @0x4A8576 + mov eax,[edx+8] @0x4A857F.
    const BYTE kTmCountRef[6]  = { 0x3B, 0x88, 0x70, 0x52, 0x1D, 0x00 };
    const BYTE kTmActiveRef[3] = { 0x8B, 0x42, 0x18 };
    const BYTE kTmInfoRef[10]  = { 0x8B, 0x91, 0x9C, 0x56, 0x1D, 0x00, 0x8B, 0x44, 0x02, 0x11 };
    const BYTE kTmStrideRef[9] = { 0x69, 0xC9, 0xC8, 0x51, 0x38, 0x01, 0x8B, 0x55, 0xB8 };
    const BYTE kTmBaseRef[3]   = { 0x8B, 0x42, 0x08 };
    const BYTE kTmThisRef[5]   = { 0xB9, 0x18, 0xAD, 0x60, 0x00 };   // mov ecx,60AD18h @0x415E20

    int  g_logMax = 30;
    P123_Stats g_stats = {};

    CRITICAL_SECTION g_logCs;
    bool  g_logCsInit = false;
    DWORD g_logWin = 0;
    int   g_logCnt = 0, g_logDrop = 0;

    bool LogAllowed()
    {
        if (!g_logCsInit) { return true; }
        int dropped = 0; bool ok;
        EnterCriticalSection(&g_logCs);
        const DWORD now = GetTickCount();
        if (g_logWin == 0 || (DWORD)(now - g_logWin) >= 60000) { dropped = g_logDrop; g_logWin = now ? now : 1; g_logCnt = 0; g_logDrop = 0; }
        ok = g_logCnt < g_logMax;
        if (ok) { ++g_logCnt; } else { ++g_logDrop; }
        LeaveCriticalSection(&g_logCs);
        if (dropped > 0) { SrvLog(kLogCat, "P123: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)", dropped, g_logMax); }
        return ok;
    }

    const char* SafeName(BYTE* mgr, int userNum)
    {
        const char* nm = "?";
        __try { const char* p = pName(mgr, nullptr, userNum); if (p) { nm = p; } } __except (EXCEPTION_EXECUTE_HANDLER) { nm = "?"; }
        return nm;
    }

    // Открыта ли карта — тем же массивом, что читает напольный портал 0x52C610 (как P40/P120).
    bool MapOpen(int dest)
    {
        if (*(const BYTE*)kOpenMapGate != 1) { return true; }
        const DWORD base  = *(const DWORD*)(kPortalUseOp + 3);
        int         slots = *(const BYTE*)(kCtorCountOp + 1);
        if (slots > kOpenHardMax) { slots = kOpenHardMax; }
        if (dest < 0 || dest >= slots) { return false; }
        return *(const BYTE*)(base + kOpenSlotSize * dest) != 0;
    }

    const BYTE* MapRec(int map)
    {
        const BYTE* t = *(const BYTE* const*)kMapTable;
        if (!t || map < 0 || map >= *(const int*)kMapRows) { return nullptr; }
        return t + kMapRec * map;
    }

    // CMapManager активного потока карты `map` в этом процессе (обход как у SearchThreadInfo). nullptr — потока нет.
    BYTE* MapManagerOf(int map)
    {
        BYTE* tm = (BYTE*)kThreadMgr;
        const int count = *(const int*)(tm + kTmCount);
        for (int k = 0; k < 1000; ++k)
        {
            const int i = pThreadAt(tm, nullptr, k);
            if (i < 0 || i >= count) { break; }
            const BYTE* active = *(const BYTE* const*)(tm + kTmActive);
            if (!active || !active[i]) { continue; }
            const BYTE* info = *(const BYTE* const*)(tm + kTmInfo);
            if (!info || *(const int*)(info + kInfoRec * i + kInfoOffMap) != map) { continue; }
            BYTE* threads = *(BYTE**)(tm + kTmThreads);
            if (!threads) { return nullptr; }
            return *(BYTE**)(threads + kThreadStride * i + kOffMapMng);
        }
        return nullptr;
    }

    void Refuse(BYTE* mgr, int userNum, int curMap, int dest, int x, int z, const char* why)
    {
        InterlockedIncrement(&g_stats.refused);
        if (LogAllowed())
        {
            SrvLog(kLogCat, "P123: CharJumpCommandPosition(Map) refused user %d [%.20s] map %d -> %d tile (%d,%d): %s", userNum,
                   SafeName(mgr, userNum), curMap, dest, x, z, why);
        }
    }

    // ★ 18.11.2026 (P127): проверки назначения и 5055 код 1 вынесены сюда без изменений — их же зовёт мост админ-центра
    //   (P123_PortalMoveTo). Возврат: 1 — 5055 отправлен, 0 — отказ (*why), −1 — нет игрока или потока (молча).
    int MoveCore(BYTE* mgr, int userNum, int dest, int x, int z, const char** why, int* curMapOut, int pos[2], bool* closedOut, BYTE** userOut)
    {
        BYTE* user = pGetUser(mgr, nullptr, userNum);
        BYTE* thread = user ? *(BYTE**)(mgr + kOffThread) : nullptr;
        if (!thread) { return -1; }
        *userOut = user;
        const int curMap = *(const int*)(thread + kOffMapIdx);
        *curMapOut = curMap;
        if (dest == curMap) { *why = "same map - the 4-byte stock form is used for it"; return 0; }
        // ★ v79: гейта «в очереди отряда/RoseWar» (3 слота CUser+0x3F43C, как у 6014) больше нет. Слоты переписывает
        //   CharPortalLogonReq@0x52CBE0 из тела 5058 клиента (байты 12…20); порт-клиент шлёт там нули (оригинал — состояние
        //   CampWar, без записи −1), и после ПЕРВОГО же перехода GM числился «в очереди» → отказ на любую карту (живой
        //   Log_Operator 09.11 19:42–19:44, карты 7 и 16). Стоковый портал эти слоты тоже не проверяет. Только путь P123.
        const BYTE* curRec = MapRec(curMap);
        if (curRec && curRec[kMapOffType] == 4) { *why = "current map is RoseWar"; return 0; }
        const BYTE* destRec = MapRec(dest);
        if (!destRec) { *why = "destination is outside MapInfo.txt"; return 0; }
        const int type = destRec[kMapOffType];
        if (type != 0 && type != 1 && type != 3 && type != 6) { *why = "destination map type is not a field/town/dungeon (0,1,3,6)"; return 0; }
        *closedOut = !MapOpen(dest);   // ★ v79: закрытая в OpenMapInfo карта GM-у не запрет (поток и сетка проверяются ниже)
        const BYTE* tp = mgr + kOffTotalPort + kTpRec * dest;
        if (!tp[0]) { *why = "no Total_PortalConfig record for destination"; return 0; }
        BYTE* map = MapManagerOf(dest);
        if (!map) { *why = "no active thread of the destination map in this GameServer"; return 0; }
        const int w = *(const short*)(map + kMapMngW), h = *(const short*)(map + kMapMngH);
        if (x <= 0 || z <= 0 || x >= w || z >= h) { *why = "tile outside the destination map"; return 0; }
        pos[0] = -1; pos[1] = -1;
        pNearest(map, nullptr, pos, x, z, 0.0f, 0.0f);
        if (pos[0] == -1 || pos[1] == -1) { *why = "no walkable tile near the requested one"; return 0; }

        BYTE body[kReplyLen];                                                     // 1:1 со стоковым конструктором sub_40DE70 (как P120)
        memset(body, 0, kReplyLen);
        *(short*)(body + 31) = -1;
        *(short*)(body + 33) = -1;
        memset(body + 35, 0xFF, 16);
        body[51] = 0xFF;
        body[52] = 0xFF;
        body[0] = 1;
        memcpy(body + 1, tp + 5, 16);                                             // IP
        *(WORD*)(body + 21) = *(const WORD*)(tp + 25);                            // порт
        *(WORD*)(body + 23) = *(const WORD*)(tp + 1);                             // номер карты
        *(short*)(body + 25) = (short)pos[0];                                     // клетка прибытия — проходимая
        *(short*)(body + 27) = (short)pos[1];
        pToClient(thread, nullptr, kOpReply, kReplyLen, userNum, body, 0, 1);
        *why = "ok";
        return 1;
    }

    // 1 — кадр наш (обработан или отклонён), 0 — сток.
    int Handle(BYTE* mgr, int userNum, BYTE* frame)
    {
        WORD size = 0;
        memcpy(&size, frame + 1, 2);
        if (size < kFrameMin || *(const WORD*)(frame + kOffMagic) != kMagic) { return 0; }   // 4-байтовая форма (с паддингом) — сток
        InterlockedIncrement(&g_stats.seen);
        if (!pGetUser(mgr, nullptr, userNum)) { return 1; }
        const int opIdx = pIsOpIdx(mgr, nullptr, userNum, -1);
        const bool gm = P47_IsGmUser(mgr, userNum);                               // ★ v78: char-результат sub_52ED50 (см. шапку)
        if (!opIdx || !gm)
        {
            InterlockedIncrement(&g_stats.notOperator);
            if (LogAllowed())
            {
                SrvLog(kLogCat, "P123: CharJumpCommandPosition(Map) dropped user %d [%.20s]: not an operator (UserIndex gate %d, GM flag %d)",
                       userNum, SafeName(mgr, userNum), opIdx ? 1 : 0, gm ? 1 : 0);
            }
            return 1;                                                             // клиенту — как сток и P47: молча
        }
        const DWORD lo = *(const DWORD*)(frame + 9), hi = *(const DWORD*)(frame + 13);
        if (!pReplay(mgr, nullptr, lo, hi, userNum, "P123 CharJumpCommandPosition(Map)"))
        {
            InterlockedIncrement(&g_stats.envelope);
            if (LogAllowed()) { SrvLog(kLogCat, "P123: CharJumpCommandPosition(Map) dropped user %d [%.20s]: replay check failed", userNum, SafeName(mgr, userNum)); }
            return 1;
        }
        if (!pSign(mgr, nullptr, frame, kPayload, userNum, 1))
        {
            InterlockedIncrement(&g_stats.envelope);
            if (LogAllowed()) { SrvLog(kLogCat, "P123: CharJumpCommandPosition(Map) dropped user %d [%.20s]: body MD5 mismatch", userNum, SafeName(mgr, userNum)); }
            return 1;
        }
        const int x = *(const short*)(frame + 33), z = *(const short*)(frame + 35), dest = *(const short*)(frame + 37);
        int curMap = -1, pos[2] = { -1, -1 }; bool closed = false; const char* why = nullptr;
        BYTE* user = nullptr;
        const int sent = MoveCore(mgr, userNum, dest, x, z, &why, &curMap, pos, &closed, &user);
        if (sent < 0) { return 1; }                                               // нет игрока / потока — молча, как раньше
        if (!sent) { Refuse(mgr, userNum, curMap, dest, x, z, why); return 1; }
        InterlockedIncrement(&g_stats.jumped);
        if (LogAllowed())
        {
            SrvLog(kLogCat, "P123: CharJumpCommandPosition(Map) Send Ok user %d [%.20s] UserIndex %d map %d (%d,%d) -> map %d (%d,%d) asked (%d,%d) port %u%s",
                   userNum, SafeName(mgr, userNum), pUserIndex(mgr, nullptr, userNum), curMap, (int)*(const short*)(user + kUserOffX),
                   (int)*(const short*)(user + kUserOffZ), dest, pos[0], pos[1], x, z,
                   (unsigned)*(const WORD*)(mgr + kOffTotalPort + kTpRec * dest + 25), closed ? " (map closed in OpenMapInfo.ini - allowed for GM)" : "");
        }
        return 1;
    }
}

// C-часть заглушки: 1 — кадр обработан P123 (обработчик возвращает 0), 0 — сток.
extern "C" int __stdcall P123_OnJump(BYTE* mgr, int userNum, BYTE* frame)
{
    __try
    {
        return Handle(mgr, userNum, frame);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        if (LogAllowed()) { SrvLog(kLogCat, "P123: exception while handling 6010 of user %d (ignored)", userNum); }
    }
    return 1;
}

// ★ P127: общая точка переноса для моста админ-центра (нить карты игрока; гейты оператора — не нужны: команда подписана панелью).
//   Счётчики и журнал P123 не трогает (журнал пишет P127).
// ★ P127 (ревизия 24 К-7): P123 установлен (опоры переноса сверены) — иначе мост перенос не выполняет.
static bool g_applied = false;
bool P123_Applied() { return g_applied; }

int P123_PortalMoveTo(BYTE* mgr, int userNum, int dest, int x, int z, const char** why)
{
    int curMap = -1, pos[2] = { -1, -1 }; bool closed = false; BYTE* user = nullptr;
    *why = "exception";
    __try { const int r = MoveCore(mgr, userNum, dest, x, z, why, &curMap, pos, &closed, &user); if (r < 0) { *why = "no user or map thread"; } return r > 0 ? 1 : 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { *why = "exception"; }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P123_GetStats(P123_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_back = kBack;

    // Вместо пролога CharJumpCommandPosition (`push ebp; mov ebp,esp; sub esp,80h`). На входе: ecx = CUserManager,
    //   [esp+4] userNum (i16 в dword), [esp+8] кадр.
    __declspec(naked) void St_Jump()
    {
        __asm
        {
            push  ecx                             // сохранить this
            mov   eax, dword ptr [esp + 0Ch]      // кадр
            push  eax
            movsx eax, word ptr [esp + 0Ch]       // userNum
            push  eax
            push  ecx                             // CUserManager
            call  P123_OnJump
            pop   ecx
            test  eax, eax
            jnz   handled
            push  ebp                             // пролог стока
            mov   ebp, esp
            sub   esp, 80h
            jmp   dword ptr [g_back]              // 0x54EF59
        handled:
            xor   eax, eax
            ret   8
        }
    }
}

PatchResult P123_GmMapJump()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_logMax = Config::GetInt(kSec, L"LogPerMinute", 30);
    if (g_logMax < 0) { g_logMax = 0; }
    if (!g_logCsInit) { InitializeCriticalSection(&g_logCs); g_logCsInit = true; }
    const Site sites[] =
    {
        { kSite,      kSiteOrig,     sizeof(kSiteOrig)     },
        { kBack,      kBackOrig,     sizeof(kBackOrig)     },
        { kEpilog,    kEpilogOrig,   sizeof(kEpilogOrig)   },
        { 0x004A83A0, kThreadAtOrig, sizeof(kThreadAtOrig) },
        { 0x0041EC30, kNearestOrig,  sizeof(kNearestOrig)  },
        { 0x0052ED50, kIsGmFlagOrig, sizeof(kIsGmFlagOrig) },
        { 0x004A852B, kTmCountRef,   sizeof(kTmCountRef)   },
        { 0x004A853B, kTmActiveRef,  sizeof(kTmActiveRef)  },
        { 0x004A8554, kTmInfoRef,    sizeof(kTmInfoRef)    },
        { 0x004A8576, kTmStrideRef,  sizeof(kTmStrideRef)  },
        { 0x004A857F, kTmBaseRef,    sizeof(kTmBaseRef)    },
        { 0x00415E20, kTmThisRef,    sizeof(kTmThisRef)    },
    };
    if (!VerifyAllSites(L"P123", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &St_Jump, sizeof(kSiteOrig))) { return PatchResult::Failed; }
    Log::Line(L"    P123: CharJumpCommandPosition @0x%08X (9 б) -> заглушка 0x%08X: 6010 тело 8 б (X, Z, карта, метка A123) -> 5055 код 1 на другую "
              L"карту (оператор + GM-флаг, клетка по CMapManager карты назначения); тело 4 б — сток", kSite, (DWORD)&St_Jump);
    g_applied = true;   // ★ P127 (ревизия 24 К-7): опоры MoveCore сверены — общая точка переноса годна
    return PatchResult::Applied;
}
