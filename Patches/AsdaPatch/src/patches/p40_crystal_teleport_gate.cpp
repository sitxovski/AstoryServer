// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P40 — ★ ТЕЛЕПОРТ КРИСТАЛЛОМ (опкод 5477): «у NPC» и «карта открыта»
//  (решение координатора 27.09.2026 по закону «дефекты оригинала исправляем»).
//
//  ЭТО НАША ПРАВКА, ДЕФЕКТ ОРИГИНАЛА. Разбор: Reports/owner_0927/world_transitions.md
//  §4.1 и вопрос В4; итог — Reports/owner_0927/p40_crystal.md;
//  документ — AstoryServer/Docs/GameServer/crystal-teleport-gate-p40.md
//
//  ── ДЕФЕКТ ──
//  Обработчик 5477 RecvContinent_PortalMove @0x5498A0 (декомпил GameServer.c:125903)
//  получает от клиента только номер карты-цели (i16, тело +33). Он проверяет подпись
//  и MD5 тела, номер < числа строк MapInfo.txt, флаг записи Total_PortalConfig и цену
//  MapWarpCost[откуда][куда] (-1 = запрет). Он НЕ проверяет:
//    (1) что игрок стоит у NPC-кристалла, у которого есть кнопка на эту карту;
//    (2) что карта-цель открыта в OpenMapInfo.ini (Use).
//  В матрице цен нет ни одного -1, поэтому одним пакетом можно уйти на любую карту
//  0…22 из любой точки, в том числе на закрытую (5/15/17/18/19…22 — у закрытой нет
//  потока, итог — обрыв соединения).
//
//  ── ЧЕМ ЛЕЧИМ (только логикой самого сервера и данными оригинала) ──
//  (1) «Карта открыта» — РОВНО как напольный портал sub_52C4C0 (asm 0x52C5F1…0x52C619):
//      `if (byte_5F5EF6 == 1 && !open[dest].Use) -> нельзя`. Массив open[] читается
//      через операнд САМОЙ стоковой команды 0x52C610 (`movzx ecx,[eax+base]`), число
//      слотов — через imm8 конструктора 0x582679 (`push 23`). Так проверка всегда
//      смотрит туда же, куда напольный портал: и в стоке (0x60A880, 23), и при P30
//      (буфер в DLL, cap). Номер ≥ числа слотов = записи нет = закрыта (как у P30).
//      Indun_GameServer работает без OpenMapInfo.ini (byte_5F5EF6 = 0) — проверка
//      там, как и у напольного портала, не действует.
//  (2) «У NPC» — единственная серверная мера близости игрока к объекту менеджера NPC:
//      CNpcManager::TemporaryRequestProcess @0x438E30 (asm 0x4390BB…0x43910F):
//      `abs(npc.x - user.tileX) > 3 || abs(npc.z - user.tileZ) > 3 -> далеко`
//      (npc = запись 0x6C б рабочего массива NpcMng+8, x/z @+8/+0xA; тайл игрока —
//      CUser+0x54E6/+0x54E8). Порог 3 клетки взят оттуда. Ищем NPC на ТЕКУЩЕЙ карте
//      (NpcMng = *(поток+0x14), поток = *(CUserManager+4)), тип NPC — запись +2.
//      Какой NPC куда ведёт — из данных клиента оригинала: NpcNsrButton (кнопки
//      30031, Param = строка WarpList, клиент шлёт младший байт MapId этой строки,
//      game_main.c:10086-10090) с учётом MenuCount из NpcNsrHeader (кнопки за
//      пределом MenuCount клиент не показывает). Видимые кнопки:
//        46 (Alpen)       → 7, 0, 1         50 (Sillaris)   → 7, 3, 6, 2
//        49 (Rein)        → 3               51 (Conquester) → 6, 0
//        52 (SunnyCoast)  → 2, 0            53 (Flammio)    → 3, 0, 16
//        55 (fieldofhonor/quizstage) → 3    201 (на сервере не расставлен) → 7
//        107 (Элла, Alpen) → 5 — ★ 06.11.2026: кнопка порта 30037 «Забытая Лощина» (добавлена 27.09, в один день с P40,
//          в таблицу не попала → все нажатия шли в отказ, нотис 1096). Единственный вход на карту 5.
//      Скрытые кнопки (ella/107 → 4, 138 → 3, eco/101 → 0) честный клиент послать не
//      может — в таблицу не входят. Таблица — ключ Crystals, владелец может править.
//
//  ── ОТКАЗ ──
//  Штатный отказ ЭТОГО ЖЕ обработчика: 5055 длиной 53 из того же буфера [ebp-0x3C]
//  (инициализирован стоковым sub_40DE70 в начале функции), меняется только байт кода
//  (сток шлёт 12 = «мало денег»). Для этого трамплин кладёт код в [ebp-0x3C] и уходит
//  на стоковую отправку 0x549AFF (она же шлёт код 12), дальше — стоковый эпилог.
//  Код по умолчанию 0: оригинальный клиент (Recv_PortalChannelChange @0xF45BD0,
//  network.c:42956) и порт (AsdaNetSubsystem.cpp OP_PORTAL_CHANNEL_CHANGE) оба
//  обрабатывают его — нотис 1096 в чат, игрок остаётся на месте; Net_RecvUiTick
//  клиент зовёт на любом 5055. RefuseCode = -1 — молча (как сток при -1 в матрице).
//  Раскладка пакетов НЕ меняется.
//
//  ── ПЛОЩАДКА ──
//    0x00549A15  C6 45 AB FF        mov byte  [ebp-0x55],0xFF    (v28 = -1)
//    0x00549A19  66 C7 45 C0 FF FF  mov word  [ebp-0x40],0xFFFF  (v33 = -1)
//  Сразу после проверки «цена > -1» (0x549A0A…0x549A10), до скидки фракции и денег.
//  10 байт → jmp + 5 nop. Обе команды трамплин повторяет на пути «пропустить».
//  Регистры: eax/ecx/edx на 0x549A1F пишутся до чтения, флаги тоже; ebx/esi/edi
//  C-функция сохраняет. Переходов внутрь площадки нет (скан .text, см. документ).
//  Байты функции 0x5498A0…0x549D10 одинаковы в стоке, живом GameServer, живом
//  Indun_GameServer и нашей базе IDA. С P01…P36 и P31/P32 не пересекается.
//
//  ЧЕСТНЫЙ ПУТЬ НЕ ЗАДЕТ: игрок у кристалла (клиент открывает окно разговора в
//  ±0.5 клетки от NPC, порт — в ±1.5), карта открыта — трамплин повторяет две
//  стоковые команды и возвращается на 0x549A1F; скидка фракции, списание денег,
//  отказ 12 и сам переход — стоковые, цены берутся как раньше.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstdlib>
#include <cwchar>

namespace
{
    const wchar_t* const S = L"P40_CrystalTeleportGate";

    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);        // 0x569DF0
    typedef char* (__thiscall *FnNamePtr)(void* mgr, short idx);                // 0x532570

    const FnSrvLog  SrvLog  = (FnSrvLog)Srv::kLog;
    const FnNamePtr SrvName = (FnNamePtr)Srv::kGetCharNamePtr;

    constexpr int kLogCat = 0;               // Log_Game (стоковые строки порталов, CharPortalLogonReq)

    // ── кадр RecvContinent_PortalMove (asm 0x5498A0…0x549D0A) ──
    constexpr int kFrmThis   = -0xC4;        // CUserManager* (this)
    constexpr int kFrmUser   = -0x5C;        // CUser* v27 (sub_5324A0)
    constexpr int kFrmDest   = -0x50;        // i16 v30 — карта-цель из пакета
    constexpr int kFrmCost   = -0x4C;        // int v31 — MapWarpCost[откуда][куда]
    constexpr int kFrmReply  = -0x3C;        // 53 б тело 5055 (v34), байт +0 — код
    constexpr int kFrmIdx    = 8;            // [ebp+8] i16 индекс игрока (arg0)

    // ── объекты сервера ──
    constexpr int kOffThread   = 4;          // CUserManager+4 → поток карты
    constexpr int kOffMapIdx   = 0x4950;     // поток+0x4950 → номер карты (sub_4C01A0)
    constexpr int kOffNpcMng   = 0x14;       // поток+0x14 → CNpcManager (sub_4C01A0: sub_435450(this+20))
    constexpr int kOffNpcArr   = 0x08;       // NpcMng+8 → рабочий массив NPC (0x6C б)
    constexpr int kOffNpcCnt   = 0x10;       // NpcMng+0x10 → i16 число NPC (LoadNpcInfo)
    constexpr int kNpcRecSize  = 0x6C;
    constexpr int kNpcOffType  = 0x02;       // i16 тип NPC (файл .npc +4)
    constexpr int kNpcOffX     = 0x08;       // i16 клетка X
    constexpr int kNpcOffZ     = 0x0A;       // i16 клетка Z
    constexpr int kUserOffX    = 0x54E6;     // CUser: i16 клетка X (0x4390CF)
    constexpr int kUserOffZ    = 0x54E8;     // CUser: i16 клетка Z (0x4390FA)

    // ── OpenMapInfo: через стоковые команды (следует за P30) ──
    constexpr DWORD kOpenMapGate  = 0x005F5EF6;   // byte_5F5EF6: 1 = OpenMapInfo.ini прочитан
    constexpr DWORD kPortalUseOp  = 0x0052C610;   // movzx ecx,[eax+base] — «карта-цель открыта?»
    constexpr DWORD kCtorCountOp  = 0x00582678;   // push N — число слотов массива
    constexpr int   kOpenSlotSize = 0x33;
    constexpr int   kOpenHardMax  = 30;           // жёсткий предел P30

    constexpr int   kMaxType      = 1024;         // типы NPC в данных < 300 (LoadNpcInfo: < 0x12C)

    // ── настройки ──
    bool g_checkNpc   = true;
    bool g_checkOpen  = true;
    int  g_range      = 3;
    int  g_refuseCode = 0;                        // -1 = молча
    int  g_logMax     = 30;

    // Таблица «тип NPC → маска карт» (карты 0…29 — по пределу P30).
    struct Crystal { short type; DWORD mask; };
    Crystal g_crystals[64];
    int     g_crystalCount = 0;
    const wchar_t* const kDefaultCrystals = L"46:7,0,1;49:3;50:7,3,6,2;51:6,0;52:2,0;53:3,0,16;55:3;201:7;107:5";

    DWORD g_pCont = 0x00549A1F;                   // продолжение стока после площадки
    DWORD g_pSend = 0x00549AFF;                   // стоковая отправка 5055 из [ebp-0x3C]
    DWORD g_pExit = 0x00549CFD;                   // стоковый эпилог

    // ═════════════════════════════════════════════════════════════════════════
    //  Журнал с пределом: не больше LogPerMinute строк P40 в минуту.
    // ═════════════════════════════════════════════════════════════════════════
    CRITICAL_SECTION g_logCs;
    bool             g_logCsInit = false;
    DWORD            g_logWin    = 0;
    int              g_logCnt    = 0;
    int              g_logDrop   = 0;

    bool LogAllowed()
    {
        if (!g_logCsInit) { return true; }
        int  dropped = 0;
        bool ok;
        EnterCriticalSection(&g_logCs);
        const DWORD now = GetTickCount();
        if (g_logWin == 0 || (DWORD)(now - g_logWin) >= 60000)
        {
            dropped   = g_logDrop;
            g_logWin  = now ? now : 1;   // [fix2, НИЗК-12 integ3] было now | 1: в кванте старта now-win=0xFFFFFFFF, окно сбрасывалось каждой строкой
            g_logCnt  = 0;
            g_logDrop = 0;
        }
        ok = g_logCnt < g_logMax;
        if (ok) { ++g_logCnt; } else { ++g_logDrop; }
        LeaveCriticalSection(&g_logCs);
        if (dropped > 0)
        {
            SrvLog(kLogCat, "P40: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)",
                   dropped, g_logMax);
        }
        return ok;
    }

    // Разбор «тип:карта,карта;тип:карта». false — синтаксис битый (патч не ставится).
    bool ParseCrystals(const wchar_t* s)
    {
        g_crystalCount = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L' ' || *p == L';') { ++p; }
            if (!*p) { break; }
            wchar_t* end = nullptr;
            const long t = wcstol(p, &end, 10);
            if (end == p || *end != L':' || t <= 0 || t >= kMaxType) { return false; }
            p = end + 1;
            DWORD mask = 0;
            for (;;)
            {
                while (*p == L' ') { ++p; }
                const long m = wcstol(p, &end, 10);
                if (end == p || m < 0 || m >= kOpenHardMax) { return false; }
                mask |= (1u << m);
                p = end;
                while (*p == L' ') { ++p; }
                if (*p == L',') { ++p; continue; }
                break;
            }
            if (*p && *p != L';') { return false; }
            if (g_crystalCount >= ARRAYSIZE(g_crystals)) { return false; }
            g_crystals[g_crystalCount].type = (short)t;
            g_crystals[g_crystalCount].mask = mask;
            ++g_crystalCount;
        }
        return g_crystalCount > 0;
    }

    bool CrystalLeadsTo(short type, int dest)
    {
        for (int i = 0; i < g_crystalCount; ++i)
        {
            if (g_crystals[i].type == type) { return (g_crystals[i].mask >> dest) & 1u; }
        }
        return false;
    }

    // Открыта ли карта — тем же массивом, что читает напольный портал 0x52C610.
    bool MapOpen(int dest)
    {
        if (*(const BYTE*)kOpenMapGate != 1) { return true; }            // OpenMapInfo не читался
        const DWORD base  = *(const DWORD*)(kPortalUseOp + 3);
        int         slots = *(const BYTE*)(kCtorCountOp + 1);
        if (slots > kOpenHardMax) { slots = kOpenHardMax; }
        if (dest < 0 || dest >= slots) { return false; }                   // записи нет
        return *(const BYTE*)(base + kOpenSlotSize * dest) != 0;
    }
}

extern "C"
{
// 0 — пропустить (сток дальше), 1 — отказ 5055 с кодом в [ebp-0x3C], 2 — молча.
int __cdecl P40_Gate(BYTE* ebp)
{
    const short idx  = *(const short*)(ebp + kFrmIdx);
    const int   dest = *(const short*)(ebp + kFrmDest);
    const char* why  = nullptr;
    int  curMap = -1, ux = -1, uz = -1;

    __try
    {
        BYTE* self   = *(BYTE**)(ebp + kFrmThis);
        BYTE* user   = *(BYTE**)(ebp + kFrmUser);
        BYTE* thread = self ? *(BYTE**)(self + kOffThread) : nullptr;
        if (!thread || !user) { return 0; }                                 // сток дальше сам решит
        curMap = *(const int*)(thread + kOffMapIdx);

        if (g_checkOpen && !MapOpen(dest)) { why = "destination map closed in OpenMapInfo.ini"; }

        if (!why && g_checkNpc)
        {
            ux = *(const short*)(user + kUserOffX);
            uz = *(const short*)(user + kUserOffZ);
            BYTE*       mng = *(BYTE**)(thread + kOffNpcMng);
            const BYTE* arr = mng ? *(const BYTE**)(mng + kOffNpcArr) : nullptr;
            const int   n   = mng ? *(const short*)(mng + kOffNpcCnt) : 0;
            bool found = false;
            for (int i = 0; arr && i < n && !found; ++i)
            {
                const BYTE* r = arr + kNpcRecSize * i;
                const int x = *(const short*)(r + kNpcOffX);
                const int z = *(const short*)(r + kNpcOffZ);
                if (x < 0 || z < 0) { continue; }
                if (abs(x - ux) > g_range || abs(z - uz) > g_range) { continue; }
                found = CrystalLeadsTo(*(const short*)(r + kNpcOffType), dest);
            }
            if (!found) { why = "no teleport NPC with this destination within range"; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Сбой чтения — не ломаем честный путь: пропускаем, как сток.
        if (LogAllowed()) { SrvLog(kLogCat, "P40: exception while checking 5477 of user %d, passed as stock", (int)idx); }
        return 0;
    }

    if (!why) { return 0; }

    if (LogAllowed())
    {
        const char* name = "?";
        __try
        {
            BYTE* self = *(BYTE**)(ebp + kFrmThis);
            const char* nm = self ? SrvName(self, idx) : nullptr;
            if (nm) { name = nm; }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { name = "?"; }
        SrvLog(kLogCat, "P40: 5477 refused user %d [%.20s] map %d -> %d tile (%d,%d) cost %d: %s; reply %s",
               (int)idx, name, curMap, dest, ux, uz, *(const int*)(ebp + kFrmCost), why,
               g_refuseCode < 0 ? "none" : "5055");
    }
    if (g_refuseCode < 0) { return 2; }
    *(ebp + kFrmReply) = (BYTE)g_refuseCode;
    return 1;
}
}

namespace
{
    // Площадка 0x549A15 (10 б): проверка, затем либо две стоковые команды и
    // возврат на 0x549A1F, либо стоковая отправка отказа, либо стоковый эпилог.
    __declspec(naked) void TrampGate()
    {
        __asm
        {
            push  ebp
            call  P40_Gate
            add   esp, 4
            cmp   eax, 1
            je    Send
            cmp   eax, 2
            je    Silent
            mov   byte ptr [ebp-0x55], 0xFF          // повтор вытесненных команд стока
            mov   word ptr [ebp-0x40], 0xFFFF
            jmp   dword ptr [g_pCont]                // три jmp подряд — опознание в verify_dll.py
        Send:
            jmp   dword ptr [g_pSend]
        Silent:
            jmp   dword ptr [g_pExit]
        }
    }

    const BYTE kSite[10]   = { 0xC6, 0x45, 0xAB, 0xFF, 0x66, 0xC7, 0x45, 0xC0, 0xFF, 0xFF };
    const BYTE kCont[6]    = { 0x8B, 0x8D, 0x3C, 0xFF, 0xFF, 0xFF };        // 0x549A1F mov ecx,[ebp-0xC4]
    // 0x549AFF: push 1; push 0; lea edx,[ebp-0x3C]; push edx; mov ax,[ebp+8]; push eax;
    //           push 0x35; push 0x13BF; mov ecx,[ebp-0xC4]; mov ecx,[ecx+4]; call 0x4C28F0; jmp 0x549CFD
    const BYTE kSend[39]   = { 0x6A, 0x01, 0x6A, 0x00, 0x8D, 0x55, 0xC4, 0x52, 0x66, 0x8B, 0x45, 0x08,
                               0x50, 0x6A, 0x35, 0x68, 0xBF, 0x13, 0x00, 0x00, 0x8B, 0x8D, 0x3C, 0xFF,
                               0xFF, 0xFF, 0x8B, 0x49, 0x04, 0xE8, 0xCF, 0x8D, 0xF7, 0xFF, 0xE9, 0xD7,
                               0x01, 0x00, 0x00 };
    const BYTE kExit[5]    = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD };              // 0x549CFD mov ecx,[ebp-4]; xor ecx,ebp
    // Отказ 12 стока пишет код в тот же буфер: mov byte [ebp-0x3C],0x0C @0x549AFB
    const BYTE kCode12[4]  = { 0xC6, 0x45, 0xC4, 0x0C };
    // Опоры чтения OpenMapInfo: код команды без операнда (операнд меняет P30)
    const BYTE kUseOp[3]   = { 0x0F, 0xB6, 0x88 };                          // 0x52C610 movzx ecx,[eax+disp32]
    const BYTE kCtorOp[1]  = { 0x6A };                                      // 0x582678 push imm8
    const BYTE kGate[3]    = { 0x0F, 0xB6, 0x05 };                          // 0x52C5F1 movzx eax, byte [0x5F5EF6]
}

PatchResult P40_CrystalTeleportGate()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    g_checkNpc  = Config::GetBool(S, L"CheckNpc", true);
    g_checkOpen = Config::GetBool(S, L"CheckOpenMap", true);
    if (!g_checkNpc && !g_checkOpen)
    {
        Log::Line(L"    P40: CheckNpc=0 и CheckOpenMap=0 — проверять нечего, площадка остаётся стоковой");
        return PatchResult::Disabled;
    }
    int r = Config::GetInt(S, L"NpcRange", 3);
    if (r < 1)  { r = 1; }
    if (r > 50) { r = 50; }
    g_range = r;
    int code = Config::GetInt(S, L"RefuseCode", 0);
    if (code < -1 || code > 255 || code == 1)
    {
        Log::Line(L"    P40: RefuseCode=%d недопустим (1 = «переход» у клиента) — взят 0", code);
        code = 0;
    }
    g_refuseCode = code;
    int perMin = Config::GetInt(S, L"LogPerMinute", 30);
    if (perMin < 1)    { perMin = 1; }
    if (perMin > 1000) { perMin = 1000; }
    g_logMax = perMin;

    wchar_t buf[512];
    Config::GetStr(S, L"Crystals", kDefaultCrystals, buf, ARRAYSIZE(buf));
    if (g_checkNpc && !ParseCrystals(buf))
    {
        Log::Line(L"    P40: ! ключ Crystals не разобран («%s») — патч НЕ ставится "
                  L"(формат: тип:карта,карта;тип:карта, карты 0…29)", buf);
        return PatchResult::Failed;
    }

    const Site sites[] =
    {
        { 0x00549A15, kSite,   sizeof(kSite)   },
        { 0x00549A1F, kCont,   sizeof(kCont)   },
        { 0x00549AFB, kCode12, sizeof(kCode12) },
        { 0x00549AFF, kSend,   sizeof(kSend)   },
        { 0x00549CFD, kExit,   sizeof(kExit)   },
        { 0x0052C5F1, kGate,   sizeof(kGate)   },
        { 0x0052C610, kUseOp,  sizeof(kUseOp)  },
        { 0x00582678, kCtorOp, sizeof(kCtorOp) },
    };
    if (!VerifyAllSites(L"P40", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    // Операнд 0x52C5F4 обязан указывать на byte_5F5EF6 (его P30 не трогает).
    if (*(const DWORD*)0x0052C5F4 != kOpenMapGate)
    {
        Log::Line(L"    P40: ! 0x0052C5F4 указывает не на 0x005F5EF6 — образ не тот, патч НЕ ставится");
        return PatchResult::Mismatch;
    }

    if (!g_logCsInit) { InitializeCriticalSection(&g_logCs); g_logCsInit = true; }

    const bool ok = Hook::WriteJmp(0x00549A15, (const void*)&TrampGate, sizeof(kSite));
    Log::Line(L"    P40: 5477 (кристалл): %s%s%s; @0x00549A15 -> 0x%08X; NpcRange=%d, "
              L"кристаллов %d, RefuseCode=%d, LogPerMinute=%d",
              g_checkNpc ? L"«у NPC»" : L"",
              (g_checkNpc && g_checkOpen) ? L" + " : L"",
              g_checkOpen ? L"«карта открыта» (массив напольного портала 0x52C610)" : L"",
              (DWORD)&TrampGate, g_range, g_crystalCount, g_refuseCode, g_logMax);
    return ok ? PatchResult::Applied : PatchResult::Failed;
}
