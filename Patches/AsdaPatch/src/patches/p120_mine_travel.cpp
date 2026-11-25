// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P120 — ПЕРЕХОД В «ШАХТУ» (карта 23 ^MineWar^ / MineWar) И ОБРАТНО (09.11.2026, пачка 20, решение владельца
//  «make possible to travel to Mine map … There is NPC in alpen, that have option to teleport to Mine»).
//  Разбор: Reports/batch20/mine/REPORT.md; документ AstoryServer/Docs/GameServer/mine-travel-p120.md.
//
//  ── ПОЧЕМУ ШАХТА МЕРТВА (сток e7b4ac38 = Ch2 = Indun; сток 4e20f0ad — те же байты) ──
//  (1) Слот карты 23 дал P30 (MaxMaps=30). (2) Тип карты 6 (MapInfo.txt, байт +0x3F записи 0xEC): поток карты создаёт только
//      SetUserInfo_ThreadID_Mapping @0x4A5360 и только типам 0/1/3 (asm 0x4A53AB…0x4A53E6); пять switch по типу (EndSelectThread
//      0x4A72BE, SearchThreadInfo 0x4A84BC, GetDisplayInfo 0x4C0BE5, напольный портал 0x52C741, CharPortalLogonRes 0x52D38E — полный
//      перебор .text по шаблону `movzx r,[r+r+3Fh] / cmp [ebp-x],5 / ja`) типа 6 не знают: вход на карту (SearchThreadInfo, default →
//      код 0) невозможен. Остальная логика типа 6 в стоке есть и рабочая: PvP-смерть (sub_4CB180), запрет лавки (CharSelfStoreReady
//      6301 код 7), призыв (5461 код 9), выход/обрыв → прежняя карта (DisConnectUser / PortalDisConnectUser, CUser+49149).
//  (3) Кнопки NPC 181 «Шахта» (Альпия, 30077 → 6746) и стражей 202/203/204 «В Альпию» (30078 → 6749) у GameServer НЕ ОБРАБАТЫВАЮТСЯ:
//      6746 (0x1A5A) и 6749 (0x1A5D) выше таблицы 0x19AF…0x1A58 диспетчера sub_42A9D0, `ja` @0x42AE1B уводит их в default 0x42F020
//      (там P13) — пакет лишь увеличивает счётчик «мусора» клиента. В этой сборке сервера системы войны за шахту нет вовсе.
//  (4) Данных карты на стойке нет (sim/svr/npc/PortalConfig/ConnectIP, NpcServer, Total_PortalConfig count=23) — их кладёт
//      deploy_p120.py, не DLL.
//
//  ── ЧТО ДЕЛАЕТ P120 (протокол не меняется; клиент alpha-7.0.0 уже шлёт 6746/6749 и принимает 5055 код 1 без своего запроса) ──
//  A 0x4A53DC (12 б) раздача потоков: тип 6 получает постоянный поток, как 0/1/3 (только при Use=1 в OpenMapInfo — проверка стока выше).
//  B/C/D 0x4A84BC / 0x4A72BE / 0x4C0BE5 — `ja default` (6 б, меняется только rel32): тип 6 → ветка типов 0/1/3 (вход, завершение
//      потока, строка состояния окна сервера).
//  E 0x52D38E — `ja default` CharPortalLogonRes: тип 6 → ветка 1/2/4/5 (точку привязки города не трогать; сток для 6 лишь писал
//      строку «switch(m_lpsMapInfo…)» в лог).
//  F 0x42AE1B — `ja default` диспетчера: 6746/6749 → P120_OnClient, иначе прежний default (P13 и сток).
//      6746: конверт (анти-повтор sub_524390 + MD5 sub_523F00 тела 4 б), charId тела == UserIndex сессии, текущая карта ∈ EnterFrom,
//            NPC из EnterNpc не дальше Range клеток (мера CNpcManager::TemporaryRequestProcess, как P40), карта-цель открыта
//            (OpenMapInfo по массиву 0x52C610, как P40/напольный портал) и есть запись Total_PortalConfig. Затем — РОВНО как
//            chatGameRoseWarGameJoin @0x463550 (вход стока на спецкарту): с карты типа 0 точка возврата sub_530C20(x,z) → DB 2235,
//            и 5055 код 1 (53 б, буфер как sub_40DE70) из записи Total_PortalConfig[цель] (IP 16 б, порт, номер, STARTPOS).
//      6749: то же с NPC из ExitNpc на карте MineMap; цель ExitTo, точка прибытия — первая пара точек MapInfo цели (+98/+108; у Альпии
//            115,320 у NPC 181), если она есть, иначе STARTPOS Total_PortalConfig. Точку возврата с карты типа 6 сток не пишет — не пишем.
//      Отказ — молча (RefuseCode=-1, строка в Log_Game) или 5055 с кодом RefuseCode (0 → клиент: нотис 1096).
//  G 0x52A755 (5 б) RecvCharRegen case 8 «база кампвара» — [ИСПРАВЛЕНИЕ]: на карте 23 клиент (и оригинал Recv_CharDeath_Apply, и порт
//      AsdaAfterDeathSubsystem) даёт после смерти ТОЛЬКО опцию 8 (4054 режим 8), а сток принимает её лишь на карте типа 4 (+ армия
//      sub_5328B0 ≥ 0) — на типе 6 пакет молча пропадал, игрок оставался мёртвым навсегда. Тип 6 → ветка режима 0 стока
//      (0x52A646: CharRegenVillage(this, idx, 0) — воскрешение в городе привязки, 4055). Ключ ReviveTownOnMine (1).
//  Журнал: Log_Game (канал 0), не чаще LogPerMinute строк в минуту.
//  Соседи: P13 0x42F020 (default, не тронут: стаб F уходит туда), P101 0x42AD02 (другая таблица), P30 0x4A537F/0x4A538F/0x4A043E…,
//  P40 0x549A15 — не пересекаются (verify_p120.py). Откат: [P120_MineTravel] Enabled=0 — ни одна площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstdlib>
#include <cstring>
#include <cwchar>

namespace
{
    const wchar_t* const kSec = L"P120_MineTravel";            // секция patches.ini

    // ── площадки ──
    constexpr DWORD kThreadSite = 0x004A53DC;                 // movzx edx,[ecx+eax+3Fh]; cmp edx,3; je 4A53E8; jmp 4A5376
    const BYTE kThreadOrig[12] = { 0x0F, 0xB6, 0x54, 0x01, 0x3F, 0x83, 0xFA, 0x03, 0x74, 0x02, 0xEB, 0x8E };
    constexpr DWORD kThreadTake = 0x004A53E8;                 // «тип годен» — создать поток
    constexpr DWORD kThreadSkip = 0x004A5376;                 // ++j

    struct JaSite { DWORD va; DWORD def; DWORD to6; int frm; const wchar_t* what; };
    // `0F 87 rel32` (ja default) после `cmp dword [ebp+frm],5`; to6 — куда вести тип 6.
    const JaSite kJa[4] =
    {
        { 0x004A84BC, 0x004A8E19, 0x004A84CC, -0x4C,  L"SearchThreadInfo (вход)" },
        { 0x004A72BE, 0x004A73C5, 0x004A72CE, -0x28,  L"EndSelectThread" },
        { 0x004C0BE5, 0x004C0E48, 0x004C0D77, -0x1C,  L"GetDisplayInfo" },
        { 0x0052D38E, 0x0052D524, 0x0052D3A1, -0x598, L"CharPortalLogonRes" },
    };
    // Таблицы switch: подтверждаем, что to6 — именно ветка типов 0/1/3 (или 1 для CharPortalLogonRes).
    struct TabCheck { DWORD table; int caseIdx; DWORD expect; };
    const TabCheck kTabs[4] =
    {
        { 0x004A8E24, 0, 0x004A84CC },
        { 0x004A73E8, 0, 0x004A72CE },
        { 0x004C0E84, 0, 0x004C0D77 },
        { 0x0052D71C, 1, 0x0052D3A1 },
    };

    // G: RecvCharRegen case 8 — cmp ecx,4 / jne выход (0x52A755…0x52A759).
    constexpr DWORD kRegenSite = 0x0052A755;
    const BYTE kRegenOrig[5] = { 0x83, 0xF9, 0x04, 0x75, 0x1C };
    constexpr DWORD kRegenBack = 0x0052A75A;                  // тип 4: проверка армии и CharRegenVillageMove_1 (сток)
    constexpr DWORD kRegenExit = 0x0052A776;                  // эпилог (пакет без ответа)
    constexpr DWORD kRegenTown = 0x0052A646;                  // ветка режима 0: push 0; push idx; call CharRegenVillage 0x52A780
    const BYTE kRegenTownOrig[11] = { 0x6A, 0x00, 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x4D, 0xE4, 0xE8 };

    constexpr DWORD kDispSite = 0x0042AE1B;                   // ja def_42AC29 (опкоды 6745…8005 вне таблицы 0x19AF…0x1A58)
    constexpr DWORD kDispDef  = 0x0042F020;                   // default (P13 / сток)
    constexpr DWORD kDispTail = 0x0042F036;                   // общий хвост switch
    constexpr int   kOp6746   = 6746 - 0x19AF;                // [ebp-10C8h] после sub edx,19AFh
    constexpr int   kOp6749   = 6749 - 0x19AF;

    // ── объекты сервера ──
    constexpr int   kOffThread    = 4;                        // CUserManager+4 → поток карты
    constexpr int   kOffMapIdx    = 0x4950;                   // поток+0x4950 → номер карты
    constexpr int   kOffNpcMng    = 0x14;                     // поток+0x14 → CNpcManager
    constexpr int   kOffNpcArr    = 0x08;                     // NpcMng+8 → рабочий массив NPC (0x6C б)
    constexpr int   kOffNpcCnt    = 0x10;                     // NpcMng+0x10 → i16 число NPC
    constexpr int   kNpcRecSize   = 0x6C;
    constexpr int   kNpcOffType   = 0x02;
    constexpr int   kNpcOffX      = 0x08;
    constexpr int   kNpcOffZ      = 0x0A;
    constexpr int   kUserOffX     = 0x54E6;                   // CUser: i16 клетка X (= v27[10867] стока)
    constexpr int   kUserOffZ     = 0x54E8;
    constexpr int   kOffTotalPort = 0xA60;                    // CUserManager+2656: Total_PortalConfig, запись 31 б по номеру карты
    constexpr int   kTpRec        = 31;                       // +0 Use, +1 номер (u16), +5 IP 16 б, +25 порт, +27 X, +29 Z
    constexpr DWORD kMapRows      = 0x005F5EE8;               // число строк MapInfo.txt
    constexpr DWORD kMapTable     = 0x005F5E18;               // указатель на таблицу MapInfo (запись 0xEC)
    constexpr int   kMapRec       = 0xEC;
    constexpr int   kMapOffType   = 0x3F;
    constexpr int   kMapOffPtCnt  = 96;                       // i16 число пар точек
    constexpr int   kMapOffPtX    = 98;                       // i16[5]
    constexpr int   kMapOffPtZ    = 108;                      // i16[5]
    constexpr DWORD kOpenMapGate  = 0x005F5EF6;               // 1 = OpenMapInfo.ini прочитан
    constexpr DWORD kPortalUseOp  = 0x0052C610;               // movzx ecx,[eax+base] — массив open[] (P30 переносит)
    constexpr DWORD kCtorCountOp  = 0x00582678;               // push N — число слотов
    constexpr int   kOpenSlotSize = 0x33;
    constexpr int   kOpenHardMax  = 30;
    constexpr int   kReplyLen     = 53;
    constexpr WORD  kOpReply      = 5055;

    typedef void        (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);                                     // sub_569DF0
    typedef BYTE*       (__fastcall *PFN_GetUser)(void* mgr, void* edx, int userNum);                             // sub_5324A0
    typedef int         (__fastcall *PFN_UserIndex)(void* mgr, void* edx, int userNum);                           // sub_5324F0
    typedef const char* (__fastcall *PFN_Name)(void* mgr, void* edx, int userNum);                                // sub_532570
    typedef int         (__fastcall *PFN_Replay)(void* mgr, void* edx, DWORD lo, DWORD hi, int userNum, const char* fn);   // sub_524390
    typedef int         (__fastcall *PFN_Sign)(void* mgr, void* edx, BYTE* frame, int len, int userNum, int mode);         // sub_523F00
    typedef int         (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, void* buf, int a6, int a7); // sub_4C28F0
    typedef void*       (__fastcall *PFN_SaveReturn)(void* mgr, void* edx, int userNum, int x, int z);            // sub_530C20 ret 0Ch

    const FnSrvLog       SrvLog     = (FnSrvLog)Srv::kLog;
    const PFN_GetUser    pGetUser   = (PFN_GetUser)Srv::kGetUser;
    const PFN_UserIndex  pUserIndex = (PFN_UserIndex)Srv::kGetUserNumber;
    const PFN_Name       pName      = (PFN_Name)Srv::kGetCharNamePtr;
    const PFN_Replay     pReplay    = (PFN_Replay)Srv::kSecretCheck;
    const PFN_Sign       pSign      = (PFN_Sign)Srv::kPktSignCheck;
    const PFN_ToClient   pToClient  = (PFN_ToClient)Srv::kSendPacket;
    const PFN_SaveReturn pSaveRet   = (PFN_SaveReturn)0x00530C20;
    // 0x530C20: push ebp; mov ebp,esp; sub esp,30h — начало sub_530C20 сверяется (её зовём напрямую; прочие функции стока — те же, что у P101).
    const BYTE kSaveRetOrig[6] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x30 };

    constexpr int kLogCat = 0;                                // Log_Game

    // ── настройки ──
    struct NpcSet { short t[8]; int n; };
    NpcSet g_enterNpc = {}, g_exitNpc = {};
    DWORD  g_enterFrom = 0;                                   // маска карт, с которых пускает 6746
    int    g_mineMap   = 23;
    int    g_exitTo    = 3;
    int    g_range     = 3;
    int    g_refuse    = -1;                                  // -1 = молча
    bool   g_exitMapPt = true;                                // 6749: точка прибытия — первая пара MapInfo цели
    bool   g_reviveTown = true;                               // G: 4054 режим 8 на карте типа 6 → воскрешение в городе
    int    g_logMax    = 30;

    P120_Stats g_stats = {};

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
        if (dropped > 0) { SrvLog(kLogCat, "P120: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)", dropped, g_logMax); }
        return ok;
    }

    // «181» / «202,203,204» → набор типов NPC. false — синтаксис битый.
    bool ParseNpc(const wchar_t* s, NpcSet& out)
    {
        out.n = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L' ' || *p == L',') { ++p; }
            if (!*p) { break; }
            wchar_t* end = nullptr;
            const long v = wcstol(p, &end, 10);
            if (end == p || v <= 0 || v >= 1024 || out.n >= 8) { return false; }
            out.t[out.n++] = (short)v;
            p = end;
        }
        return out.n > 0;
    }

    // «3» / «3,7» → маска карт 0…29.
    bool ParseMaps(const wchar_t* s, DWORD& mask)
    {
        mask = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L' ' || *p == L',') { ++p; }
            if (!*p) { break; }
            wchar_t* end = nullptr;
            const long v = wcstol(p, &end, 10);
            if (end == p || v < 0 || v >= kOpenHardMax) { return false; }
            mask |= 1u << v;
            p = end;
        }
        return mask != 0;
    }

    bool NpcIn(const NpcSet& s, short t)
    {
        for (int i = 0; i < s.n; ++i) { if (s.t[i] == t) { return true; } }
        return false;
    }

    // Открыта ли карта — тем же массивом, что читает напольный портал 0x52C610 (как P40).
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

    // NPC из набора на текущей карте не дальше g_range клеток от игрока (мера CNpcManager::TemporaryRequestProcess @0x438E30).
    bool NpcNear(BYTE* thread, const BYTE* user, const NpcSet& set, int& foundType)
    {
        const int ux = *(const short*)(user + kUserOffX);
        const int uz = *(const short*)(user + kUserOffZ);
        BYTE*       mng = *(BYTE**)(thread + kOffNpcMng);
        const BYTE* arr = mng ? *(const BYTE**)(mng + kOffNpcArr) : nullptr;
        const int   n   = mng ? *(const short*)(mng + kOffNpcCnt) : 0;
        for (int i = 0; arr && i < n; ++i)
        {
            const BYTE* r = arr + kNpcRecSize * i;
            const int x = *(const short*)(r + kNpcOffX);
            const int z = *(const short*)(r + kNpcOffZ);
            if (x < 0 || z < 0) { continue; }
            if (abs(x - ux) > g_range || abs(z - uz) > g_range) { continue; }
            const short t = *(const short*)(r + kNpcOffType);
            if (NpcIn(set, t)) { foundType = t; return true; }
        }
        return false;
    }

    // Буфер 5055 — 1:1 со стоковым конструктором sub_40DE70.
    void ReplyInit(BYTE* b)
    {
        memset(b, 0, kReplyLen);
        *(short*)(b + 23) = -1;
        *(short*)(b + 31) = -1;
        *(short*)(b + 33) = -1;
        memset(b + 35, 0xFF, 16);
        b[51] = 0xFF;
        b[52] = 0xFF;
    }

    void Refuse(BYTE* mgr, int userNum, int op, int curMap, int dest, const BYTE* user, const char* why)
    {
        InterlockedIncrement(&g_stats.refused);
        if (LogAllowed())
        {
            const char* nm = "?";
            __try { const char* p = pName(mgr, nullptr, userNum); if (p) { nm = p; } } __except (EXCEPTION_EXECUTE_HANDLER) { nm = "?"; }
            SrvLog(kLogCat, "P120: %d refused user %d [%.20s] map %d -> %d tile (%d,%d): %s; reply %s", op, userNum, nm, curMap, dest,
                   user ? (int)*(const short*)(user + kUserOffX) : -1, user ? (int)*(const short*)(user + kUserOffZ) : -1, why,
                   g_refuse < 0 ? "none" : "5055");
        }
        if (g_refuse < 0) { return; }
        BYTE body[kReplyLen];
        ReplyInit(body);
        body[0] = (BYTE)g_refuse;
        pToClient(*(void**)(mgr + kOffThread), nullptr, kOpReply, kReplyLen, userNum, body, 0, 1);
    }

    void Handle(int op, BYTE* mgr, int userNum, BYTE* frame, int packetLen)
    {
        const bool enter = (op == 6746);
        const int  payload = enter ? 4 : 6;
        if (packetLen - 10 < 24 + payload)
        {
            InterlockedIncrement(&g_stats.badLength);
            if (LogAllowed()) { SrvLog(kLogCat, "P120: %d from user %d too short (frame %d)", op, userNum, packetLen); }
            return;
        }
        const DWORD lo = *(const DWORD*)(frame + 9), hi = *(const DWORD*)(frame + 13);
        if (!pReplay(mgr, nullptr, lo, hi, userNum, enter ? "P120 MineEnter 6746()" : "P120 MineExit 6749()")) { InterlockedIncrement(&g_stats.envelope); return; }
        if (!pSign(mgr, nullptr, frame, payload, userNum, 1)) { InterlockedIncrement(&g_stats.envelope); return; }
        BYTE* user = pGetUser(mgr, nullptr, userNum);
        if (!user) { return; }
        BYTE* thread = *(BYTE**)(mgr + kOffThread);
        if (!thread) { return; }
        const int curMap = *(const int*)(thread + kOffMapIdx);
        const int dest   = enter ? g_mineMap : g_exitTo;

        const int charId = *(const int*)(frame + 33);
        if (charId != pUserIndex(mgr, nullptr, userNum)) { Refuse(mgr, userNum, op, curMap, dest, user, "charId of body differs from session"); return; }
        if (enter ? !(curMap >= 0 && curMap < 32 && ((g_enterFrom >> curMap) & 1u)) : curMap != g_mineMap)
        {
            Refuse(mgr, userNum, op, curMap, dest, user, "request from a wrong map"); return;
        }
        int npcType = -1;
        if (!NpcNear(thread, user, enter ? g_enterNpc : g_exitNpc, npcType)) { Refuse(mgr, userNum, op, curMap, dest, user, "no mine NPC within range"); return; }
        const BYTE* destRec = MapRec(dest);
        if (!destRec) { Refuse(mgr, userNum, op, curMap, dest, user, "destination is outside MapInfo.txt"); return; }
        if (!MapOpen(dest)) { Refuse(mgr, userNum, op, curMap, dest, user, "destination map closed in OpenMapInfo.ini"); return; }
        const BYTE* tp = mgr + kOffTotalPort + kTpRec * dest;
        if (!tp[0]) { Refuse(mgr, userNum, op, curMap, dest, user, "no Total_PortalConfig record for destination"); return; }

        // Точка возврата — как chatGameRoseWarGameJoin: только с карты типа 0.
        const BYTE* curRec = MapRec(curMap);
        const int ux = *(const short*)(user + kUserOffX), uz = *(const short*)(user + kUserOffZ);
        if (curRec && curRec[kMapOffType] == 0) { pSaveRet(mgr, nullptr, userNum, ux, uz); }

        BYTE body[kReplyLen];
        ReplyInit(body);
        body[0] = 1;
        memcpy(body + 1, tp + 5, 16);                                   // IP (как RecvContinent_PortalMove: 16 б, +17…+20 нули)
        *(WORD*)(body + 21) = *(const WORD*)(tp + 25);                  // порт
        *(WORD*)(body + 23) = *(const WORD*)(tp + 1);                   // номер карты
        short tx = *(const short*)(tp + 27), tz = *(const short*)(tp + 29);
        if (!enter && g_exitMapPt && *(const short*)(destRec + kMapOffPtCnt) > 0)
        {
            const short px = *(const short*)(destRec + kMapOffPtX), pz = *(const short*)(destRec + kMapOffPtZ);
            if (px > 0 && pz > 0) { tx = px; tz = pz; }
        }
        *(short*)(body + 25) = tx;
        *(short*)(body + 27) = tz;
        pToClient(thread, nullptr, kOpReply, kReplyLen, userNum, body, 0, 1);
        InterlockedIncrement(enter ? &g_stats.entered : &g_stats.exited);
        if (LogAllowed())
        {
            const char* nm = "?";
            __try { const char* p = pName(mgr, nullptr, userNum); if (p) { nm = p; } } __except (EXCEPTION_EXECUTE_HANDLER) { nm = "?"; }
            SrvLog(kLogCat, "P120: %d user %d [%.20s] UserIndex %d npc %d map %d (%d,%d) -> map %d (%d,%d) port %u", op, userNum, nm,
                   charId, npcType, curMap, ux, uz, dest, (int)tx, (int)tz, (unsigned)*(const WORD*)(tp + 25));
        }
    }
}

// C-часть стаба F: 1 — опкод наш (обработан, хвост switch), 0 — прежний default.
extern "C" int __stdcall P120_OnClient(int opRel, BYTE* mgr, int userNum, BYTE* frame, int packetLen)
{
    const int op = opRel + 0x19AF;
    InterlockedIncrement(&g_stats.seen);
    __try
    {
        Handle(op, mgr, userNum, frame, packetLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        if (LogAllowed()) { SrvLog(kLogCat, "P120: exception while handling %d of user %d (ignored)", op, userNum); }
    }
    return 1;
}

extern "C" __declspec(dllexport) void __stdcall P120_GetStats(P120_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    DWORD g_thrTake = kThreadTake, g_thrSkip = kThreadSkip;
    DWORD g_dispDef = kDispDef, g_dispTail = kDispTail;
    DWORD g_regenBack = kRegenBack, g_regenExit = kRegenExit, g_regenTown = kRegenTown;

    // G: вместо `cmp ecx,4; jne выход` в case 8 RecvCharRegen (ecx = тип текущей карты).
    __declspec(naked) void St_Regen()
    {
        __asm
        {
            cmp   ecx, 4
            jne   not4
            jmp   dword ptr [g_regenBack]
        not4:
            cmp   ecx, 6
            jne   rexit
            jmp   dword ptr [g_regenTown]         // тип 6: как режим 0 — CharRegenVillage(this, idx, 0)
        rexit:
            jmp   dword ptr [g_regenExit]
        }
    }
    DWORD g_jaDef[4] = { kJa[0].def, kJa[1].def, kJa[2].def, kJa[3].def };
    DWORD g_jaTo6[4] = { kJa[0].to6, kJa[1].to6, kJa[2].to6, kJa[3].to6 };

    // A: вместо `movzx edx,[ecx+eax+3Fh]; cmp edx,3; je; jmp` — тип 3 или 6 → создать поток.
    __declspec(naked) void St_Thread()
    {
        __asm
        {
            movzx edx, byte ptr [ecx+eax+3Fh]
            cmp   edx, 3
            je    take
            cmp   edx, 6
            je    take
            jmp   dword ptr [g_thrSkip]
        take:
            jmp   dword ptr [g_thrTake]
        }
    }

    // B/C/D/E: `ja default` после `cmp [ebp+frm],5`; флаги ja уже посчитаны — сюда попадаем только при типе > 5.
    __declspec(naked) void St_Search()
    {
        __asm
        {
            cmp   dword ptr [ebp-4Ch], 6
            jne   d
            jmp   dword ptr [g_jaTo6]
        d:  jmp   dword ptr [g_jaDef]
        }
    }
    __declspec(naked) void St_End()
    {
        __asm
        {
            cmp   dword ptr [ebp-28h], 6
            jne   d
            jmp   dword ptr [g_jaTo6+4]
        d:  jmp   dword ptr [g_jaDef+4]
        }
    }
    __declspec(naked) void St_Display()
    {
        __asm
        {
            cmp   dword ptr [ebp-1Ch], 6
            jne   d
            jmp   dword ptr [g_jaTo6+8]
        d:  jmp   dword ptr [g_jaDef+8]
        }
    }
    __declspec(naked) void St_Logon()
    {
        __asm
        {
            cmp   dword ptr [ebp-598h], 6
            jne   d
            jmp   dword ptr [g_jaTo6+12]
        d:  jmp   dword ptr [g_jaDef+12]
        }
    }

    // F: опкоды 6745…8005 вне таблицы. [ebp-10C8h] = опкод − 0x19AF.
    __declspec(naked) void St_Disp()
    {
        __asm
        {
            mov   eax, dword ptr [ebp-10C8h]
            cmp   eax, 0ABh                       // 6746
            je    ours
            cmp   eax, 0AEh                       // 6749
            je    ours
            jmp   dword ptr [g_dispDef]           // 0x42F020 — default (P13 / сток)
        ours:
            movsx edx, word ptr [ebp-34h]         // packetLen (полная длина кадра)
            push  edx
            lea   edx, [ebp-1048h]                // кадр пакета
            push  edx
            movsx edx, word ptr [ebp-44h]         // userNum
            push  edx
            mov   edx, dword ptr [ebp-10C4h]      // this диспетчера → [[+4]+34h] CUserManager
            mov   edx, dword ptr [edx+4]
            mov   edx, dword ptr [edx+34h]
            push  edx
            push  eax                             // опкод − 0x19AF
            call  P120_OnClient                   // __stdcall, 20 б
            jmp   dword ptr [g_dispTail]          // 0x42F036 — мимо счётчика «мусора»
        }
    }

    const void* const kStubs[4] = { &St_Search, &St_End, &St_Display, &St_Logon };

    // `0F 87 rel32` на old → тот же ja на new (длина и кодировка прежние).
    bool RetargetJa(DWORD va, DWORD oldTarget, const void* newTarget)
    {
        BYTE expect[6] = { 0x0F, 0x87 };
        *(DWORD*)(expect + 2) = oldTarget - (va + 6);
        if (!Hook::Verify(va, expect, 6)) { return false; }
        BYTE now[6] = { 0x0F, 0x87 };
        *(DWORD*)(now + 2) = (DWORD)newTarget - (va + 6);
        return Hook::WriteBytes(va, now, 6);
    }

    bool JaOrig(DWORD va, DWORD target, BYTE* out)
    {
        out[0] = 0x0F; out[1] = 0x87;
        *(DWORD*)(out + 2) = target - (va + 6);
        return true;
    }
}

PatchResult P120_MineTravel()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    wchar_t buf[128];
    Config::GetStr(kSec, L"EnterNpc", L"181", buf, ARRAYSIZE(buf));
    if (!ParseNpc(buf, g_enterNpc)) { Log::Line(L"    P120: ! EnterNpc «%s» не разобран — патч не ставится", buf); return PatchResult::Failed; }
    Config::GetStr(kSec, L"ExitNpc", L"202,203,204", buf, ARRAYSIZE(buf));
    if (!ParseNpc(buf, g_exitNpc)) { Log::Line(L"    P120: ! ExitNpc «%s» не разобран — патч не ставится", buf); return PatchResult::Failed; }
    Config::GetStr(kSec, L"EnterFrom", L"3", buf, ARRAYSIZE(buf));
    if (!ParseMaps(buf, g_enterFrom)) { Log::Line(L"    P120: ! EnterFrom «%s» не разобран — патч не ставится", buf); return PatchResult::Failed; }
    g_mineMap   = Config::GetInt(kSec, L"MineMap", 23);
    g_exitTo    = Config::GetInt(kSec, L"ExitTo", 3);
    g_range     = Config::GetInt(kSec, L"Range", 3);
    g_refuse    = Config::GetInt(kSec, L"RefuseCode", -1);
    g_exitMapPt = Config::GetBool(kSec, L"ExitPointFromMapInfo", true);
    g_reviveTown = Config::GetBool(kSec, L"ReviveTownOnMine", true);
    g_logMax    = Config::GetInt(kSec, L"LogPerMinute", 30);
    if (g_mineMap < 0 || g_mineMap >= kOpenHardMax || g_exitTo < 0 || g_exitTo >= kOpenHardMax || g_range < 0 || g_range > 16 || g_refuse > 255)
    {
        Log::Line(L"    P120: ! MineMap=%d ExitTo=%d Range=%d RefuseCode=%d вне пределов — патч не ставится", g_mineMap, g_exitTo, g_range, g_refuse);
        return PatchResult::Failed;
    }
    if (g_logMax < 1) { g_logMax = 1; }
    if (!g_logCsInit) { InitializeCriticalSection(&g_logCs); g_logCsInit = true; }

    // ── сверка всех площадок до первой записи ──
    BYTE ja[4][6], disp[6];
    for (int i = 0; i < 4; ++i) { JaOrig(kJa[i].va, kJa[i].def, ja[i]); }
    JaOrig(kDispSite, kDispDef, disp);
    const Site sites[] =
    {
        { kThreadSite, kThreadOrig, sizeof(kThreadOrig) },
        { kJa[0].va, ja[0], 6 }, { kJa[1].va, ja[1], 6 }, { kJa[2].va, ja[2], 6 }, { kJa[3].va, ja[3], 6 },
        { kDispSite, disp, 6 },
        { 0x00530C20, kSaveRetOrig, sizeof(kSaveRetOrig) },
        { kRegenSite, kRegenOrig, sizeof(kRegenOrig) },
        { kRegenTown, kRegenTownOrig, sizeof(kRegenTownOrig) },
    };
    if (!VerifyAllSites(L"P120", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    for (int i = 0; i < 4; ++i)
    {
        const DWORD got = *(const DWORD*)(kTabs[i].table + 4 * kTabs[i].caseIdx);
        if (got != kTabs[i].expect)
        {
            Log::Line(L"    MISMATCH P120 таблица 0x%08X[%d] = 0x%08X, ждали 0x%08X (%s)", kTabs[i].table, kTabs[i].caseIdx, got, kTabs[i].expect, kJa[i].what);
            return PatchResult::Mismatch;
        }
    }

    if (!Hook::WriteJmp(kThreadSite, &St_Thread, sizeof(kThreadOrig))) { return PatchResult::Failed; }
    for (int i = 0; i < 4; ++i)
    {
        if (!RetargetJa(kJa[i].va, kJa[i].def, kStubs[i])) { return PatchResult::Failed; }
    }
    if (!RetargetJa(kDispSite, kDispDef, &St_Disp)) { return PatchResult::Failed; }
    if (g_reviveTown && !Hook::WriteJmp(kRegenSite, &St_Regen, sizeof(kRegenOrig))) { return PatchResult::Failed; }

    Log::Line(L"    P120: раздача потоков @0x%08X (12 б) -> 0x%08X: тип карты 6 получает поток, как 0/1/3", kThreadSite, (DWORD)&St_Thread);
    for (int i = 0; i < 4; ++i)
    {
        Log::Line(L"    P120: %s ja @0x%08X -> 0x%08X: тип 6 -> 0x%08X, иначе 0x%08X", kJa[i].what, kJa[i].va, (DWORD)kStubs[i], kJa[i].to6, kJa[i].def);
    }
    Log::Line(L"    P120: диспетчер ja @0x%08X -> 0x%08X: 6746 (NPC %d…, карты-источники 0x%X) -> карта %d, 6749 (NPC %d…) -> карта %d; "
              L"дальность %d, отказ %d, точка выхода из MapInfo=%d",
              kDispSite, (DWORD)&St_Disp, (int)g_enterNpc.t[0], g_enterFrom, g_mineMap, (int)g_exitNpc.t[0], g_exitTo, g_range, g_refuse, (int)g_exitMapPt);
    if (g_reviveTown)
    {
        Log::Line(L"    P120: RecvCharRegen case 8 @0x%08X (5 б) -> 0x%08X: 4054 режим 8 на карте типа 6 -> CharRegenVillage (как режим 0, 0x%08X)",
                  kRegenSite, (DWORD)&St_Regen, kRegenTown);
    }
    else { Log::Line(L"    P120: ReviveTownOnMine=0 — RecvCharRegen не тронут (смерть в шахте: только воскрешение другим игроком/свитком)"); }
    return PatchResult::Applied;
}
