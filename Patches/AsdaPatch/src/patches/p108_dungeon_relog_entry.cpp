// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P108 — [ИСПРАВЛЕНИЕ] ПОВТОРНЫЙ ВХОД ИЗ ДАНЖА — В ТОЧКУ ВХОДА ДАНЖА (05.11.2026, сессия dungeon-relog; требование владельца
//  «при релоге/переподключении/перезапуске клиента в данже ставить в точку входа: нельзя пропустить прохождение и проложить
//  эксплойт-маршрут»). Документ: AstoryServer/Docs/GameServer/dungeon-relog-entry-p108.md.
//
//  Выход из игры, обрыв соединения и закрытие клиента идут ОДНИМ путём — DisConnectUser@0x5245D0 (GameServer.c:111155). Он
//  сохраняет персонажа пакетом в DBManager 2003 (DBM_CHARINFO_SAVE_REQ → EXEC UPLogoutGame, DBManager.exe.c:4290), тело
//  [ebp-5C0h]: +0 i16 X (тайл), +2 i16 Z, +4 канал, +5 i32 карта, +9 запись CUser. X/Z = CUser+0x54E6/+0x54E8 (текущая клетка);
//  карта — [ebp-15h] (i8). Для карт с атрибутом MapInfo (+0x3F) 1/2/4/5/6 сток подменяет карту и X/Z на точку возврата
//  (CUser+49149 / +49150 / +49152, иначе карта 3); строка журнала там до сих пор «if( (iMapIndex == 8) || (iMapIndex == 9) )» —
//  след прежнего правила для Palace of Queen / Castle of Chess. Данжи — атрибут 3 — из правила выпали: X/Z уходят как есть.
//  При входе LoginManager (Send_SelectChar, LoginManager.c:4227) и DBManager (DBM_CHARINFO_RES, DBManager.exe.c:3033) читают
//  EXEC UPCharPos (CharPos.Poridx/Posx/Posy) без проверок (подмена карты — только для 19/20/22 через UPCharDetailPos), а
//  charLogOnRes@0x5277D0 ставит X/Z из ответа БД. Итог стока: игрок встаёт в ту же клетку данжа.
//  Портальный выход (CUser+321) пакет 2003 не шлёт — сохраняет PortalDisConnectUser (2091 UPPortalLogOut, СТАРАЯ карта).
//  Турнирные копии 10/11 (атрибут 0): UPLogOutGame / UPUserNumUp Poridx 10/11 не сохраняют (вход вернёт на прежнюю карту), но
//  Posx/Posy пишут координаты турнирной карты — игрок появляется на прежней карте в чужой точке.
//
//  ── ЧТО ДЕЛАЕТ P108 (площадка 0x5257A0, 10 б; протокол клиента и пакеты БД не меняются) ──
//  Площадка — сразу после выбора X/Z стоком (обе ветки сходятся на loc_5257A0), до упаковки карты в пакет:
//    `movsx ecx, byte [ebp-15h]` · `mov [ebp-5BBh], ecx` → jmp в трамплин; трамплин зовёт P108_Decide(ebp), затем исполняет
//    замещённые команды и возвращается на 0x5257AA.
//  • Карта из EntryMaps (по умолчанию 8, 9, 17): X/Z := первая точка старта записи MapInfo.txt этой карты (+0x60 число точек,
//    +0x62 X, +0x6C Z) — та же точка, куда сток переносит игрока на картах атрибута 3 обработчиком 9915 (sub_521770 →
//    CharJumpCommandPosition_0) и куда ставят входные порталы оригинала (Rein→8 129,282; Sillaris→9 48,460).
//  • Карта из ReturnMaps (по умолчанию 10, 11) и она же — карта потока: карта := назначение первого портала своей карты
//    (PortalIP_Info\<Имя>_PortalConfig.Ini, таблица CUserManager+0x910 / +0x914, шаг 41 б), X/Z := его STARTPOS — ровно туда,
//    куда выводит выходной портал турнирной карты (T_Palace → Conquester 440,420; T_Chess → SunnyCoast 72,273). [ebp-15h]
//    меняется вместе с пакетом — как у стоковой ветки 1/2/4/5/6 (её же читают 2154 и строка журнала).
//  Остальные карты, мёртвый/живой — без изменений. Ключ [P108_DungeonRelogEntry] Enabled (0 — сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P108_DungeonRelogEntry";   // секция patches.ini

    // ── площадка и соседи (байты живого GameServer.exe e7b4ac38) ─────────────
    // 0x5257A0: movsx ecx, byte [ebp-15h] · mov [ebp-5BBh], ecx — карта в пакет 2003 (замещается).
    const DWORD kSite = 0x005257A0;
    const BYTE  kSiteOrig[10] = { 0x0F, 0xBE, 0x4D, 0xEB, 0x89, 0x8D, 0x45, 0xFA, 0xFF, 0xFF };
    // 0x5257AA: mov ecx, 0x60AD18 — продолжение (сток: канал для пакета, sub_4A7EA0).
    DWORD g_back = 0x005257AA;
    const BYTE  kBackOrig[5] = { 0xB9, 0x18, 0xAD, 0x60, 0x00 };
    // 0x525778: mov eax,[ebp-7C4h] · mov cx,[eax+54E6h] · mov [ebp-5C0h],cx — стоковый выбор X (ветка «как есть»).
    const BYTE  kPosX[20] = { 0x8B, 0x85, 0x3C, 0xF8, 0xFF, 0xFF, 0x66, 0x8B, 0x88, 0xE6, 0x54, 0x00, 0x00,
                              0x66, 0x89, 0x8D, 0x40, 0xFA, 0xFF, 0xFF };
    // 0x525818: lea eax,[ebp-5C0h] · push eax · mov ecx,[ebp-ACCh] · mov ecx,[ecx+4] — тело пакета и this (CUserManager).
    const BYTE  kBody[16] = { 0x8D, 0x85, 0x40, 0xFA, 0xFF, 0xFF, 0x50, 0x8B, 0x8D, 0x34, 0xF5, 0xFF, 0xFF, 0x8B, 0x49, 0x04 };
    // 0x52582D: push eax · push 0B7h · push 7D3h — отправка 2003 (длина 183).
    const BYTE  kSend[11] = { 0x50, 0x68, 0xB7, 0x00, 0x00, 0x00, 0x68, 0xD3, 0x07, 0x00, 0x00 };
    // 0x40C96A: mov al, byte [eax+8E9h] — sub_40C960: карта потока CUserManager.
    const BYTE  kMgrMapOp[6] = { 0x8A, 0x80, 0xE9, 0x08, 0x00, 0x00 };

    // ── кадр DisConnectUser ─────────────────────────────────────────────────
    constexpr int kFrMap  = -0x15;    // i8  карта сохранения (v72)
    constexpr int kFrPosX = -0x5C0;   // i16 X пакета 2003
    constexpr int kFrPosZ = -0x5BE;   // i16 Z пакета 2003
    constexpr int kFrUser = -0x7C4;   // CUser*
    constexpr int kFrMgr  = -0xACC;   // CUserManager* (this)

    // ── глобалы и раскладки стока ───────────────────────────────────────────
    constexpr DWORD kMapInfoPtr = 0x005F5E18;   // dword_5F5E18 — массив записей MapInfo.txt
    constexpr DWORD kMapCount   = 0x005F5EE8;   // dword_5F5EE8 — число записей
    constexpr int   kMiStride   = 0xEC;         // 236 б на карту (загрузчик GameServer.c:71949)
    constexpr int   kMiSizeX    = 0x58;         // i16 ширина карты в клетках (512)
    constexpr int   kMiSizeZ    = 0x5A;         // i16 высота карты (512)
    constexpr int   kMiPtCount  = 0x60;         // i16 число точек старта
    constexpr int   kMiPtX      = 0x62;         // i16 X точки 0 (+2·j)
    constexpr int   kMiPtZ      = 0x6C;         // i16 Z точки 0 (+2·j)
    constexpr int   kMgrMap     = 0x8E9;        // CUserManager: байт карты потока (sub_40C960)
    constexpr int   kMgrPtCount = 0x910;        // CUserManager: i32 число порталов своей карты (LoadPortalServerInfo, GameServer.c:110477)
    constexpr int   kMgrPortal  = 0x914;        // CUserManager: запись портала 0 (шаг 41)
    constexpr int   kPtStride   = 41;           // размер записи портала
    constexpr int   kPtDest     = 0;            // i32 Index — карта назначения
    constexpr int   kPtStartX   = 0x20;         // i16 STARTPOSX
    constexpr int   kPtStartZ   = 0x22;         // i16 STARTPOSZ
    constexpr int   kMaxPortals = 64;           // предел перебора (в файлах оригинала до 4)
    constexpr int   kOffName    = 0x178;        // CUser: имя персонажа cp1251
    constexpr int   kOffUi      = 0x174;        // CUser: учётка

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;

    // ── настройки ────────────────────────────────────────────────────────────
    bool g_enabled = false;
    bool g_entry[256] = {};    // карты «в точку входа MapInfo»
    bool g_return[256] = {};   // карты «к выходному порталу»
    int  g_logChannel = 0;

    // Счётчики (P108_GetStats): 0 вызовов, 1 точка входа, 2 возврат порталом, 3 нет точки/портала, 4 исключение.
    volatile LONG g_stats[5] = {};

    // Разбор списка «8,9,17» в маску карт; пустые и неверные элементы пропускаются.
    void ParseMaps(const wchar_t* s, bool* mask, wchar_t* echo, int cch)
    {
        memset(mask, 0, 256 * sizeof(bool));
        echo[0] = 0;
        int v = -1;
        for (const wchar_t* p = s;; ++p)
        {
            if (*p >= L'0' && *p <= L'9') { v = (v < 0 ? 0 : v) * 10 + (*p - L'0'); if (v > 255) { v = 256; } continue; }
            if (v >= 0 && v < 256 && !mask[v])
            {
                mask[v] = true;
                wchar_t n[8]; wsprintfW(n, echo[0] ? L",%d" : L"%d", v);
                if (lstrlenW(echo) + lstrlenW(n) < cch) { lstrcatW(echo, n); }
            }
            v = -1;
            if (!*p) { break; }
        }
    }

    // Запись MapInfo карты или nullptr.
    const BYTE* MapInfo(int map)
    {
        const BYTE* base = *(const BYTE* const*)kMapInfoPtr;
        const int count = *(const int*)kMapCount;
        if (!base || map < 0 || map >= count) { return nullptr; }
        return base + kMiStride * map;
    }

    // Строка стокового журнала о подмене.
    void Report(const BYTE* user, int mapFrom, int x0, int z0, int mapTo, int x1, int z1, const char* why)
    {
        __try
        {
            SrvLog(g_logChannel, "P108 DungeonRelogEntry: %s UserIndex %d: logout map %d (%d,%d) -> map %d (%d,%d) %s",
                   user ? (const char*)(user + kOffName) : "?", user ? *(const int*)(user + kOffUi) : -1,
                   mapFrom, x0, z0, mapTo, x1, z1, why);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// Решение площадки 0x5257A0. ebp — кадр DisConnectUser. Меняет X/Z пакета 2003 и, для турнирных карт, карту сохранения.
extern "C" __declspec(dllexport) void __stdcall P108_Decide(BYTE* ebp)
{
    if (!g_enabled) { return; }
    InterlockedIncrement(&g_stats[0]);
    __try
    {
        const int map = *(signed char*)(ebp + kFrMap);
        if (map < 0) { return; }
        short* px = (short*)(ebp + kFrPosX);
        short* pz = (short*)(ebp + kFrPosZ);
        const BYTE* user = *(const BYTE* const*)(ebp + kFrUser);
        const short x0 = *px, z0 = *pz;

        if (g_entry[map])
        {
            const BYTE* mi = MapInfo(map);
            const short n  = mi ? *(const short*)(mi + kMiPtCount) : 0;
            const short x  = mi ? *(const short*)(mi + kMiPtX) : 0;
            const short z  = mi ? *(const short*)(mi + kMiPtZ) : 0;
            const short sx = mi ? *(const short*)(mi + kMiSizeX) : 0;
            const short sz = mi ? *(const short*)(mi + kMiSizeZ) : 0;
            if (n > 0 && x > 0 && z > 0 && x < sx && z < sz)
            {
                *px = x; *pz = z;
                InterlockedIncrement(&g_stats[1]);
                Report(user, map, x0, z0, map, x, z, "(MapInfo start point)");
            }
            else
            {
                InterlockedIncrement(&g_stats[3]);
                Report(user, map, x0, z0, map, x0, z0, "(no MapInfo start point - stock)");
            }
            return;
        }

        if (g_return[map])
        {
            const BYTE* mgr = *(const BYTE* const*)(ebp + kFrMgr);
            const int own = mgr ? (int)(signed char)mgr[kMgrMap] : -1;
            const int cnt = (mgr && own == map) ? *(const int*)(mgr + kMgrPtCount) : 0;
            for (int i = 0; i < cnt && i < kMaxPortals; ++i)
            {
                const BYTE* pt = mgr + kMgrPortal + kPtStride * i;
                const int   dest = *(const int*)(pt + kPtDest);
                const short x = *(const short*)(pt + kPtStartX);
                const short z = *(const short*)(pt + kPtStartZ);
                const BYTE* mi = MapInfo(dest);
                if (dest == map || dest < 0 || dest > 127 || !mi || x <= 0 || z <= 0) { continue; }
                if (x >= *(const short*)(mi + kMiSizeX) || z >= *(const short*)(mi + kMiSizeZ)) { continue; }
                *(signed char*)(ebp + kFrMap) = (signed char)dest;
                *px = x; *pz = z;
                InterlockedIncrement(&g_stats[2]);
                Report(user, map, x0, z0, dest, x, z, "(exit portal of tournament map)");
                return;
            }
            InterlockedIncrement(&g_stats[3]);
            Report(user, map, x0, z0, map, x0, z0, "(no exit portal - stock)");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats[4]); }
}

// Счётчики для стенда: out[0..4] — вызовы, точка входа, возврат порталом, нет точки, исключения.
extern "C" __declspec(dllexport) void __stdcall P108_GetStats(int* out)
{
    for (int i = 0; i < 5; ++i) { out[i] = g_stats[i]; }
}

namespace
{
    // Трамплин площадки 0x5257A0: решение, затем замещённые команды стока.
    __declspec(naked) void St_P108()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P108_Decide
            popad
            popfd
            movsx ecx, byte ptr [ebp-15h]       // замещённое: карта сохранения
            mov   dword ptr [ebp-5BBh], ecx     // замещённое: карта в пакет 2003
            jmp   dword ptr [g_back]            // 0x5257AA
        }
    }
}

PatchResult P108_DungeonRelogEntry()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    wchar_t buf[256], echoE[128], echoR[128];
    Config::GetStr(kSec, L"EntryMaps", L"8,9,17", buf, ARRAYSIZE(buf));
    ParseMaps(buf, g_entry, echoE, ARRAYSIZE(echoE));
    Config::GetStr(kSec, L"ReturnMaps", L"10,11", buf, ARRAYSIZE(buf));
    ParseMaps(buf, g_return, echoR, ARRAYSIZE(echoR));
    for (int i = 0; i < 256; ++i) { if (g_entry[i]) { g_return[i] = false; } }   // карта в обоих списках — точка входа
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 0);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 0; }

    const Site check[] =
    {
        { kSite, kSiteOrig, sizeof(kSiteOrig) }, { g_back, kBackOrig, sizeof(kBackOrig) }, { 0x00525778, kPosX, sizeof(kPosX) },
        { 0x00525818, kBody, sizeof(kBody) }, { 0x0052582D, kSend, sizeof(kSend) }, { 0x0040C96A, kMgrMapOp, sizeof(kMgrMapOp) },
    };
    if (!VerifyAllSites(L"P108", check, ARRAYSIZE(check))) { g_enabled = false; return PatchResult::Mismatch; }

    g_enabled = true;
    if (!Hook::WriteJmp(kSite, (void*)&St_P108, sizeof(kSiteOrig))) { g_enabled = false; return PatchResult::Failed; }
    Log::Line(L"    P108: выход/обрыв в данже (DisConnectUser, пакет 2003 @0x%08X) — карты [%s] в первую точку старта MapInfo, "
              L"турнирные [%s] — к выходному порталу своей карты", kSite, echoE, echoR);
    return PatchResult::Applied;
}
