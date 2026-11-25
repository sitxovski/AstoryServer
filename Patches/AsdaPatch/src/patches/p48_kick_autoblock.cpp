// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P48 — ★ АВТОБЛОК после N античит-киков (волна А0, 2026-10-12, решение владельца 11.10:
//  «автоблок после 5 киков»). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Отчёт: `Reports/anticheat/wave_A0.md`; документ: `AstoryServer/Docs/GameServer/kick-autoblock-p48.md`.
//
//  ── ГДЕ СЧИТАЕМ ──
//  Все киков с причиной сервер отправляет одной функцией Send_DisConnectType sub_52EDB0@0x52EDB0
//  (thiscall CUserManager, userNum, тип; 4101 клиенту). Перехват ВХОДА (6 б `55 8BEC 83EC08`,
//  перебор кодировок по .text стока: переходов внутрь 0). Считаются только типы ini CountTypes
//  (по умолчанию 3 и 6):
//    3 — CheckDisConnectUser@0x526C20: «Secret Broken» (P49), «MD5 Broken», «NotKnow Packet»,
//        «Hack Packet» (в т.ч. отказы GM-гейта P47);
//    6 — sendSpeedHackDisConnect@0x527180 (сигнал NpcServer о скорости атаки).
//  НЕ считаются: 1 пинг, 2 повторный вход, 5 ошибки логона (в т.ч. отказы сверки личности P47/P50 —
//  там UserIndex ЗАЯВЛЕН клиентом и может быть чужим), 0xE/0xF переполнение.
//  ★ P73 (EAC, 2026-10-16): кик моста EAC (P73_KickInProgress в этой нити) не считается НИКОГДА, при любом CountTypes — код 7.
//  ★ P127 (18.11.2026): кик моста админ-центра (P127_KickInProgress) — тоже никогда, код 8.
//  ★ Счёт ведётся ТОЛЬКО для сессии, вошедшей в мир (CUser+0x2E == 1: ставят CharMake/CharPortalMake
//    после DB-логона, который сверил личность P50). До входа в мир UserIndex не подтверждён —
//    засчитывать кик в чужую учётку нельзя (иначе подставной клиент мог бы заблокировать оператора).
//
//  ── ЧТО ДЕЛАЕМ НА ПОРОГЕ ──
//  Шлём в DBManager штатный 2271 — тот же, что стоковый GM-блок sub_55A510 (6094) и
//  Recv_CharBlock@0x55A690: тело 12 б {u16 userNum, i32 UserIndex, u8 слот, u8 группа, i32 часы}
//  → DBManager sub_432950 → `EXEC UPHackBlock UserIndex, часы` (us_block = 5 + запись BlockList,
//  -1 = 30 лет). Срок — ini BlockHours (по умолчанию 24). Снятие по сроку — SQL P51 (UPUserLogin
//
//  ── ★ ac0r (2026-10-12, ревизия А0/А2 СРЕД-1): ВХОД СОУЛМЕЙТОМ ──
//  При входе в чужое расшаренное тело (LoginManager 1016 режим 2 → `UPCharSoulState @State=2`)
//  сессия GameServer получает UserIndex ХОЗЯИНА персонажа (CUser+0x174 = B), а играет учётка,
//  которая вошла в LoginManager (A). Где сервер держит A (по декомпилу и asm):
//    • CUser+0x182D3 (байт) — SoulState персонажа: 0 свой, 1 «душа», 2 вход соулмейтом (комментарий
//      автора `UPCharSoulState`; читает `sub_52EE40@0x52EE40`: `cmp [ecx+182B9h],0 / movzx [edx+182D3h]`);
//    • CUser+0x182C6 (DWORD) — iMateUserIndex блока соулмейта (база блока CUser+0x182B9, +13): грузит
//      `charLogonCommunityRes` (qmemcpy 0x5C б из DB-ответа 2145; лог «sSoulMateInfo.iMateUserIndex < 0»
//      по тому же байту тела), источник — `UPCharSoulMate @Userindex=B` → `SoulMate.Ouserindex` (= A),
//      ровно та же строка, по которой `UPCharSoulState` закрыл запись входа A и открыл запись B State 2.
//  Блок сбрасывается на каждую сессию (`ClearUserMemory sub_4A2DC0` копирует свежий блок 0x188 б в
//  CUser+99001), то есть признак не переживает отключение.
//  Решение координатора: кик и автоблок засчитываются учётке СЕССИИ ВХОДА (A), учётка-хозяин (B) не
//  трогается. При SoulState == 2: счёт и 2271 — на CUser+0x182C6; если там ≤ 0 (блок соулмейта не
//  пришёл) — кик НЕ засчитывается никому (строка в журнале), а не на хозяина. Ключ SoulMateSessionAccount
//  (0 — прежнее поведение: всегда CUser+0x174). DBManager для 2271 берёт из тела только UserIndex и
//  группу (`sub_432950` → `EXEC UPHackBlock UserIndex, часы`), слот тела не читает.
//
//  ── СЧЁТЧИК ──
//  Файл ini (CounterFile, по умолчанию `..\GameServer\ConfigSet\ac_kick_counter.ini` — общий для
//  GameServer и Indun_GameServer: у обоих он разрешается в одну папку) + именованный мьютекс
//  между процессами. Секция [Kicks], ключ = UserIndex, значение «счёт,начало_окна_unix».
//  WindowHours: счёт сгорает, если первое попадание старше окна (0 = не сгорает).
//  Кики — редкое событие, запись файла на каждое не нагружает поток.
//
//  ── ★ sec2 (2026-10-15, решение владельца 14.10: за поддельный/битый пакет — только ступени P69) ──
//  Кик тип 3 из CheckDisConnectUser (Secret 0x526D10 / MD5 0x526D4F / NotKnow 0x526D8E / Hack 0x526DCD — адрес возврата), чей
//  штатный счётчик вырос из-за нарушений целостности пакетов P55 1/2/4 так, что без них порог не превышен, — НЕ засчитывается
//  (код 6; доля считается в P55: P55_KickAttribution; Secret — значение до сброса стабом P49). Кик P69 KickOnBlock — код 5, как
//  было. P61 (канал) кика через Send_DisConnectType не даёт вовсе — рвёт DisConnect. Прочие кики P48 считает как раньше.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P48_KickAutoBlock";

    bool g_enabled     = true;
    int  g_threshold   = 5;      // киков до блока
    int  g_blockHours  = 24;     // срок блока в часах (-1 = 30 лет, как UPHackBlock)
    int  g_windowHours = 24;     // окно счёта (0 = без окна)
    bool g_inWorldOnly = true;   // считать только сессии, вошедшие в мир
    bool g_soulSession = true;   // ★ ac0r: вход соулмейтом — считать на учётку сессии (CUser+0x182C6)
    bool g_countType[16] = {};   // какие типы Send_DisConnectType считаются
    wchar_t g_counterFile[MAX_PATH] = L"";

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);       // sub_5324A0
    typedef int   (__fastcall *PFN_GetUserIndex)(void* self, void* edx, int userNum);  // sub_5324F0
    typedef char  (__fastcall *PFN_GetSlot)(void* self, void* edx, int userNum);       // sub_532530
    typedef char  (__fastcall *PFN_GetGroup)(void* self, void* edx);                   // sub_4A7EA0
    typedef short (__fastcall *PFN_GetDbConn)(void* self, void* edx);                  // sub_4C0A30
    typedef int   (__fastcall *PFN_SendDb)(void* self, void* edx, int op, int len,
                                           int connIdx, void* body, int userNum);      // sub_5646C0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);             // sub_569DF0

    PFN_GetUser      const pGetUser   = (PFN_GetUser)     Srv::kGetUser;
    PFN_GetUserIndex const pGetUserIx = (PFN_GetUserIndex)Srv::kGetUserNumber;
    PFN_GetSlot      const pGetSlot   = (PFN_GetSlot)     Srv::kGetUserSubFlag;
    PFN_GetGroup     const pGetGroup  = (PFN_GetGroup)    Srv::kGetServerGroup;
    PFN_GetDbConn    const pGetDbConn = (PFN_GetDbConn)   Srv::kGetDbSrvIdx;
    PFN_SendDb       const pSendDb    = (PFN_SendDb)      Srv::kConnectSend;
    PFN_SrvLog       const pSrvLog    = (PFN_SrvLog)      Srv::kLog;
    void* const kGroupThis = (void*)Srv::kServerGroupThis;
    void* const kNetMgr    = (void*)Srv::kNetMoveMgr;

    constexpr int   kOffInWorld = 0x2E;   // CUser: DWORD 1 = в мире (CharMake/CharPortalMake)
    constexpr int   kOffSoulState  = 0x182D3;   // ★ ac0r: CUser байт SoulState (2 = вход соулмейтом)
    constexpr int   kOffMateUserIx = 0x182C6;   // ★ ac0r: CUser DWORD iMateUserIndex блока соулмейта (= учётка сессии при SoulState 2)
    constexpr BYTE  kSoulStateMate = 2;
    constexpr WORD  kOpHackBlock = 2271;  // GS → DBManager: EXEC UPHackBlock
    constexpr int   kBlockLen    = 12;

    CRITICAL_SECTION g_lock;
    bool             g_lockReady = false;
    HANDLE           g_mutex     = nullptr;   // межпроцессный (GameServer + Indun)

    __int64 NowUnix()
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        return (__int64)(u.QuadPart / 10000000ULL) - 11644473600LL;
    }

    // Прибавить кик учётке; вернуть новый счёт. Под CS + мьютексом.
    int CounterAdd(int userIndex)
    {
        wchar_t key[16];  wsprintfW(key, L"%d", userIndex);
        wchar_t val[64] = L"";
        GetPrivateProfileStringW(L"Kicks", key, L"", val, ARRAYSIZE(val), g_counterFile);
        int count = 0; __int64 first = 0;
        if (val[0])
        {
            // формат «счёт,начало»
            const wchar_t* p = val;
            while (*p >= L'0' && *p <= L'9') { count = count * 10 + (*p - L'0'); ++p; }
            if (*p == L',') { ++p; while (*p >= L'0' && *p <= L'9') { first = first * 10 + (*p - L'0'); ++p; } }
        }
        const __int64 now = NowUnix();
        if (count <= 0 || first <= 0 || (g_windowHours > 0 && now - first > (__int64)g_windowHours * 3600))
        {
            count = 0; first = now;   // окно истекло — начинаем заново
        }
        ++count;
        wchar_t out[64];
        wsprintfW(out, L"%d,%u", count, (unsigned)first);
        WritePrivateProfileStringW(L"Kicks", key, out, g_counterFile);
        return count;
    }

    void CounterReset(int userIndex)
    {
        wchar_t key[16];  wsprintfW(key, L"%d", userIndex);
        WritePrivateProfileStringW(L"Kicks", key, nullptr, g_counterFile);   // удалить ключ
    }

    // Штатный DB-запрос блока (как GM-блок 6094 / Recv_CharBlock).
    bool SendHackBlock(void* mgr, int userNum, int userIndex, int hours)
    {
        void* net = *(void**)((BYTE*)mgr + 4);
        if (!net) { return false; }
        BYTE b[kBlockLen] = {};
        *(WORD*)&b[0] = (WORD)userNum;
        memcpy(&b[2], &userIndex, 4);
        b[6] = (BYTE)pGetSlot(mgr, nullptr, (short)userNum);
        b[7] = (BYTE)pGetGroup(kGroupThis, nullptr);
        memcpy(&b[8], &hours, 4);
        const short conn = pGetDbConn(net, nullptr);
        return pSendDb(kNetMgr, nullptr, kOpHackBlock, kBlockLen, conn, b, userNum) != 0;
    }
}

// ★ autoban (2026-10-14): общая точка P48 ↔ P69 — «чья учётка у сессии» по CUser (Patches.h P48_Identity).
//   Те же поля и правила, что у счёта киков ниже: в мире — CUser+0x2E == 1; вход соулмейтом — SoulState CUser+0x182D3 == 2
//   (при soulSession) → учётка сессии = iMateUserIndex CUser+0x182C6 (≤ 0 — неизвестна, 0); иначе — owner (CUser+0x174).
void P48_IdentityOf(const BYTE* user, int owner, bool soulSession, P48_Identity* out)
{
    out->inWorld = false; out->soul = AcJournal::kNone; out->soulMate = false; out->account = 0;
    if (!user) { return; }
    out->inWorld  = *(const DWORD*)(user + kOffInWorld) == 1;
    out->soul     = (int)user[kOffSoulState];
    out->soulMate = soulSession && user[kOffSoulState] == kSoulStateMate;
    if (out->soulMate)
    {
        const int mate = *(const int*)(user + kOffMateUserIx);
        out->account = mate > 0 ? mate : 0;
    }
    else
    {
        out->account = owner > 0 ? owner : 0;
    }
}

// ★ autoban: общая точка P48 ↔ P69 — штатный DB-запрос блока 2271 (тот же, что у автоблока по кикам). SEH — сбой = не отправлен.
bool P48_SendHackBlock(void* mgr, int userNum, int userIndex, int hours)
{
    if (!mgr || userNum < 0 || userNum >= 0x226 || userIndex <= 0) { return false; }
    bool ok = false;
    __try { ok = SendHackBlock(mgr, userNum, userIndex, hours); }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

// ★ acdb (P53): строка журнала античита ac.kick_block (кик любого типа или автоблок).
//   counted: 1/0 (засчитан в автоблок); why — код причины «не засчитан» (AcJournal.cpp NotCountedText).
static void JournalKick(BYTE kind, BYTE* user, int userNum, int type, DWORD retVa, int account, int owner,
                        int soul, int counted, int why, int count, int hours, int sent)
{
    AcJournal::Event e;
    AcJournal::Clear(e, AcJournal::kKickBlock, kind);
    e.userNum = (short)userNum;
    e.ip = P47_PeerIpv4(userNum);
    e.userIndex = account;
    e.opcode = kind == 2 ? kOpHackBlock : 4101;
    if (user)
    {
        __try { e.charSlot = user[0x18C]; AcJournal::CopyName(e, user + Srv::kOffCharName); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (kind == 1) { e.v[0] = type; e.v[1] = (int)retVa; e.v[2] = counted; e.v[3] = why; }
    if (count > 0) { e.v[4] = count; e.v[5] = g_threshold; }
    if (kind == 2) { e.v[6] = hours; e.v[7] = sent; }
    e.v[8] = soul;
    e.v[9] = owner;
    AcJournal::Push(e);
}

// Вызывается стабом на ВХОДЕ Send_DisConnectType (до отправки 4101 и до отключения).
//   ★ acdb: retVa — адрес возврата вызова (по нему журнал называет причину кика). Журнал пишет ВСЕ кики;
//   счёт автоблока — как прежде (только CountTypes, только сессии в мире, учётка сессии при соулмейте).
extern "C" void __stdcall P48_OnDisconnectType(void* mgr, int userNum, int type, DWORD retVa)
{
    if (!mgr) { return; }
    if (userNum < 0 || userNum >= 0x226) { return; }

    __try
    {
        BYTE* user = pGetUser(mgr, nullptr, (short)userNum);
        const int ownerIndex = user ? pGetUserIx(mgr, nullptr, (short)userNum) : -1;   // CUser+0x174 — хозяин персонажа
        // ★ sec2 (решение владельца 14.10): кик тип 3 из CheckDisConnectUser, вызванный нарушениями целостности пакетов P55 1/2/4
        //   (их наказывают только ступени P69), не засчитывается (код 6). Счётчик кика — по адресу возврата (kick_sites: 0x526D10
        //   Secret, 0x526D4F MD5, 0x526D8E NotKnow, 0x526DCD Hack); у Secret стаб P49 обнулил счётчик до вызова — берём значение до
        //   сброса. Любой кик завершает сессию — учёт доли P55 по слоту сбрасывается здесь же.
        const int kcWhich = type != 3 ? -1 : retVa == 0x00526D10 ? 0 : retVa == 0x00526D4F ? 1 : retVa == 0x00526D8E ? 2 : retVa == 0x00526DCD ? 3 : -1;
        int kcInteg = 0, kcOther = 0;
        const bool kcIntegrityOnly = P55_KickAttribution(user, userNum, kcWhich, kcWhich == 0 ? P49_TakeSecretPre(user) : -1, &kcInteg, &kcOther);
        const int soul = user ? (int)user[kOffSoulState] : AcJournal::kNone;
        const bool typeCounted = type >= 0 && type < ARRAYSIZE(g_countType) && g_countType[type];
        const int owner = ownerIndex > 0 ? ownerIndex : AcJournal::kNone;

        // ★ P73 (EAC, 2026-10-16, контракт §6 «кик не идёт в счётчик P48»): кик моста EAC (нить карты, P73_OnCheckUser → эта функция
        //   синхронно) — только журнал, код «не засчитан» 7, при любом CountTypes. Решение о наказании — за сайдкаром/EAC.
        if (P73_KickInProgress())
        {
            JournalKick(1, user, userNum, type, retVa, owner, owner, soul, 0, 7, 0, 0, 0);
            return;
        }
        // ★ P127 (А2, 18.11.2026, решение владельца): кик моста админ-центра (нить карты, P127_OnUserTick → эта функция синхронно) —
        //   админское действие, не нарушение: только журнал, код «не засчитан» 8, при любом CountTypes.
        if (P127_KickInProgress())
        {
            JournalKick(1, user, userNum, type, retVa, owner, owner, soul, 0, 8, 0, 0, 0);
            return;
        }

        if (!g_enabled || !typeCounted || !user || ownerIndex <= 0)
        {
            // Автоблоком не считается (P48 выключен / тип не из CountTypes / нет сессии) — только журнал.
            JournalKick(1, user, userNum, type, retVa, owner, owner, soul, 0, !g_enabled ? 4 : 1, 0, 0, 0);
            return;
        }
        if (g_inWorldOnly && *(const DWORD*)(user + kOffInWorld) != 1)
        {
            Log::Line(L"[P48] кик тип %d, userNum %d, UserIndex %d — НЕ засчитан (сессия не вошла в мир, "
                      L"личность не подтверждена)", type, userNum, ownerIndex);
            JournalKick(1, user, userNum, type, retVa, owner, owner, soul, 0, 2, 0, 0, 0);
            return;
        }
        // ★ ac0r: учётка сессии. Свой персонаж — UserIndex сессии = хозяин; вход соулмейтом — партнёр.
        //   ★ autoban: та же логика вынесена в общую точку P48_IdentityOf (её же зовёт P69).
        P48_Identity id;
        P48_IdentityOf(user, ownerIndex, g_soulSession, &id);
        int userIndex = ownerIndex;
        const bool soulMate = id.soulMate;
        if (soulMate)
        {
            const int mate = *(const int*)(user + kOffMateUserIx);
            if (id.account <= 0)
            {
                pSrvLog(Srv::kLogCatOperator, "P48 KickCount: UserNum %d type %d SoulState 2, MateUserIndex %d unknown -> not counted (owner %d untouched)",
                        userNum, type, mate, ownerIndex);
                Log::Line(L"[P48] кик тип %d, userNum %d: вход соулмейтом, учётка сессии неизвестна (MateUserIndex %d) — "
                          L"НЕ засчитан; хозяин персонажа %d не трогается", type, userNum, mate, ownerIndex);
                JournalKick(1, user, userNum, type, retVa, AcJournal::kNone, owner, soul, 0, 3, 0, 0, 0);
                return;
            }
            userIndex = id.account;
        }
        // ★ autoban: кик, назначенный самим P69 после его автоблока (KickOnBlock: штатный счётчик Hack Packet → тип 3), — не
        //   засчитывается P48 повторно (иначе одно нарушение-ступень дало бы и блок P69, и шаг к блоку P48). Метка — на учётку.
        if (P69_TakeKickMark(userNum, userIndex))
        {
            Log::Line(L"[P48] кик тип %d, userNum %d, UserIndex %d — НЕ засчитан (кик после автоблока P69)", type, userNum, userIndex);
            JournalKick(1, user, userNum, type, retVa, userIndex, owner, soul, 0, 5, 0, 0, 0);
            return;
        }
        // ★ sec2: кик штатного счётчика за нарушения P55 1/2/4 (то же нарушение уже в счёте P69) — не засчитывается.
        if (kcIntegrityOnly)
        {
            static const wchar_t* kKcName[4] = { L"Secret", L"MD5", L"NotKnow", L"Hack Packet" };
            Log::Line(L"[P48] кик тип %d (%s), userNum %d, UserIndex %d — НЕ засчитан: счётчик вырос из-за нарушений целостности пакетов "
                      L"P55 (%d из них, прочих %d ≤ порога) — наказывает только P69", type, kKcName[kcWhich], userNum, userIndex, kcInteg, kcOther);
            JournalKick(1, user, userNum, type, retVa, userIndex, owner, soul, 0, 6, 0, 0, 0);
            return;
        }

        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        if (g_mutex) { WaitForSingleObject(g_mutex, 2000); }
        const int count = CounterAdd(userIndex);
        if (g_mutex) { ReleaseMutex(g_mutex); }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        const bool block = count >= g_threshold;

        pSrvLog(Srv::kLogCatOperator, "P48 KickCount: UserIndex %d, UserNum %d, type %d, count %d/%d%s%s",
                userIndex, userNum, type, count, g_threshold, soulMate ? " (soulmate session, char owner untouched)" : "",
                block ? " -> AUTOBLOCK" : "");
        Log::Line(L"[P48] кик тип %d: UserIndex %d (userNum %d%s) — %d из %d", type, userIndex, userNum,
                  soulMate ? L", вход соулмейтом — учётка сессии" : L"", count, g_threshold);
        JournalKick(1, user, userNum, type, retVa, userIndex, owner, soul, 1, AcJournal::kNone, count, 0, 0);

        if (block)
        {
            bool ok = false;
            __try { ok = SendHackBlock(mgr, userNum, userIndex, g_blockHours); }
            __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
            // Счёт сбрасываем ТОЛЬКО после отправленного блока: если отправить не удалось,
            // следующий кик этой учётки повторит попытку.
            if (ok)
            {
                if (g_lockReady) { EnterCriticalSection(&g_lock); }
                if (g_mutex) { WaitForSingleObject(g_mutex, 2000); }
                CounterReset(userIndex);
                if (g_mutex) { ReleaseMutex(g_mutex); }
                if (g_lockReady) { LeaveCriticalSection(&g_lock); }
            }
            pSrvLog(Srv::kLogCatOperator, "P48 AutoBlock: UserIndex %d, hours %d, DB 2271 %s",
                    userIndex, g_blockHours, ok ? "sent" : "FAILED");
            Log::Line(L"[P48] ★ АВТОБЛОК: UserIndex %d на %d ч — 2271 (UPHackBlock) %s",
                      userIndex, g_blockHours, ok ? L"отправлен" : L"НЕ ОТПРАВЛЕН (повтор на следующем кике)");
            JournalKick(2, user, userNum, type, retVa, userIndex, owner, soul, 1, AcJournal::kNone, count, g_blockHours, ok ? 1 : 0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log::Line(L"[P48] ! исключение в счётчике киков (userNum %d, тип %d) — кик пройдёт как в стоке", userNum, type);
    }
}

namespace
{
    DWORD g_retDisc = 0x0052EDB6;   // после вытесненного пролога `push ebp; mov ebp,esp; sub esp,8`

    // Стаб входа sub_52EDB0. На входе: [esp] возврат, [esp+4] userNum (i16), [esp+8] тип (u8).
    //   ★ acdb: четвёртый аргумент — адрес возврата (откуда кик, для журнала P53).
    __declspec(naked) void DisconnectStub()
    {
        __asm
        {
            pushad                                 // +32
            push  dword ptr [esp+32]               // адрес возврата вызова
            movzx eax, byte ptr [esp+44]           // тип (после push: +40+4)
            push  eax
            movsx eax, word ptr [esp+44]           // userNum (после двух push: +36+8)
            push  eax
            push  ecx                              // CUserManager (this)
            call  P48_OnDisconnectType             // __stdcall, 16 б
            popad
            push  ebp                              // вытеснено
            mov   ebp, esp                         // вытеснено
            sub   esp, 8                           // вытеснено
            jmp   dword ptr [g_retDisc]
        }
    }

    const BYTE kOrigDisc[6] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 };

    // Разбор списка типов «3,6».
    void ParseTypes(const wchar_t* s)
    {
        for (int i = 0; i < ARRAYSIZE(g_countType); ++i) { g_countType[i] = false; }
        int v = -1;
        for (const wchar_t* p = s; ; ++p)
        {
            if (*p >= L'0' && *p <= L'9') { v = (v < 0 ? 0 : v * 10) + (*p - L'0'); continue; }
            if (v >= 0 && v < ARRAYSIZE(g_countType)) { g_countType[v] = true; }
            v = -1;
            if (!*p) { break; }
        }
    }
}

PatchResult P48_KickAutoBlock()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        // ★ acdb: автоблок выключен, но журнал P53 включён — перехват ставится только ради записи
        //   киков в ac.kick_block (счёт и блок не ведутся). Иначе — как раньше, без перехвата.
        g_enabled = false;
        if (Config::GetBool(L"P53_AcJournal", L"Enabled", true) && Config::GetBool(L"P53_AcJournal", L"KickJournalWhenP48Off", true))
        {
            const Site s0[] = { { 0x0052EDB0, kOrigDisc, sizeof(kOrigDisc) } };
            if (VerifyAllSites(L"P48", s0, ARRAYSIZE(s0)) && Hook::WriteJmp(0x0052EDB0, &DisconnectStub, sizeof(kOrigDisc)))
            {
                Log::Line(L"    P48: автоблок ВЫКЛЮЧЕН; перехват Send_DisConnectType стоит только для журнала P53");
            }
        }
        return PatchResult::Disabled;
    }
    g_threshold   = Config::GetInt(kSec, L"KickThreshold", 5);
    g_blockHours  = Config::GetInt(kSec, L"BlockHours", 24);
    g_windowHours = Config::GetInt(kSec, L"WindowHours", 24);
    g_inWorldOnly = Config::GetBool(kSec, L"InWorldOnly", true);
    g_soulSession = Config::GetBool(kSec, L"SoulMateSessionAccount", true);   // ★ ac0r
    if (g_threshold < 1)   { g_threshold = 1; }
    if (g_blockHours == 0 || g_blockHours < -1) { g_blockHours = 24; }   // 0 истёк бы сразу
    if (g_windowHours < 0) { g_windowHours = 0; }

    wchar_t types[64];
    Config::GetStr(kSec, L"CountTypes", L"3,6", types, ARRAYSIZE(types));
    ParseTypes(types);

    wchar_t rel[MAX_PATH];
    Config::GetStr(kSec, L"CounterFile", L"..\\GameServer\\ConfigSet\\ac_kick_counter.ini", rel, ARRAYSIZE(rel));
    wchar_t joined[MAX_PATH];
    if (rel[0] && rel[1] == L':') { lstrcpynW(joined, rel, MAX_PATH); }      // абсолютный путь
    else { wsprintfW(joined, L"%s%s", Config::BaseDir(), rel); }
    if (!GetFullPathNameW(joined, MAX_PATH, g_counterFile, nullptr)) { lstrcpynW(g_counterFile, joined, MAX_PATH); }
    // Папки нет (нестандартная раскладка) — свой ConfigSet.
    wchar_t dir[MAX_PATH]; lstrcpynW(dir, g_counterFile, MAX_PATH);
    for (int i = lstrlenW(dir) - 1; i >= 0; --i) { if (dir[i] == L'\\' || dir[i] == L'/') { dir[i] = 0; break; } }
    if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES)
    {
        wsprintfW(g_counterFile, L"%sConfigSet\\ac_kick_counter.ini", Config::BaseDir());
    }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    g_mutex = CreateMutexW(nullptr, FALSE, L"Local\\AsdaPatch_P48_KickCounter");

    const Site sites[] = { { 0x0052EDB0, kOrigDisc, sizeof(kOrigDisc) } };
    if (!VerifyAllSites(L"P48", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(0x0052EDB0, &DisconnectStub, sizeof(kOrigDisc))) { return PatchResult::Failed; }

    Log::Line(L"    P48: порог %d киков (типы %s, только в мире=%d, соулмейт -> учётка сессии=%d, окно %d ч) -> UPHackBlock на %d ч; "
              L"счётчик %s; мьютекс %s", g_threshold, types, g_inWorldOnly ? 1 : 0, g_soulSession ? 1 : 0, g_windowHours,
              g_blockHours, g_counterFile, g_mutex ? L"есть" : L"НЕТ (только внутри процесса)");
    return PatchResult::Applied;
}
