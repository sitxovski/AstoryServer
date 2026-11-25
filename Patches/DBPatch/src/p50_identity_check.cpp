// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P50 — ★ БЕЗОПАСНОСТЬ (античит, волна А0, 2026-10-12): сверка личности при DB-логоне
//  персонажа. Пара к GameServer P47 (часть C — IP пира в хвосте DB-запроса).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Мера 3 плана `Reports/anticheat/00_PLAN.md`.
//  Отчёт: `Reports/anticheat/wave_A0.md`; документ: `AstoryServer/Docs/DBManager/identity-check-p50.md`.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  GameServer шлёт в DBManager 2001 (вход, CharLogonReq) и 2089 (портал, CharPortalLogonReq) с
//  UserIndex/CharIdx ИЗ ПАКЕТА КЛИЕНТА. Обработчики sub_407480 (2001) и sub_417410 (2089)
//  сразу зовут `EXEC UPCharInfo …` и грузят персонажа — ни сверки с записью входа LoginManager
//  (JoyLog1.dbo.Loginfo: Userindex, IpAddress, Logout IS NULL), ни принадлежности слота учётке.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Подмена ЦЕЛИ двух `call` в диспетчере sub_402420 (5 б каждая, переходов внутрь нет):
//     0x004026D1  E8 AA4D0000  call sub_407480   (case 0x7D1 = 2001)
//     0x00402FE3  E8 28440100  call sub_417410   (case 0x829 = 2089)
//  Обёртка (то же соглашение: ecx = 0x49EAB8, в стеке conn, userNum, a5, pkt; ret 0x10) ДО
//  стокового обработчика выполняет `EXEC dbo.UP_AC_IdentityCheck UserIndex, CharIdx, 'IP'`
//  (процедура Joy1, SQL P51) и при отказе отвечает ШТАТНЫМ ответом-неудачей —
//  ровно тем, что сток шлёт при ошибке UPCharInfo:
//     2001 → 2002, тело 265 б, [0] = 0   (sub_407480: `v255 = 0; sub_44E2F0(2002, 265, …)`)
//     2089 → 2090, тело 262 б, [0] = 0   (sub_417410: `v167[0] = 0; sub_44E2F0(2090, 262, …)`)
//  GameServer на [0] == 0 кикает штатно (charLogOnRes / CharPortalLogonRes: 4101 код 5).
//  Иначе — вызов стокового обработчика без изменений.
//
//  Решение (каждое условие под своим ключом dbpatch.ini):
//     нет учётки (AccExists = 0)                         → отказ (всегда)
//     us_block <> 0                                       → отказ (RefuseBlocked)
//     слот не принадлежит учётке (CharOk = 0)             → отказ (всегда)
//     нет открытой записи входа (SessOpen = 0)            → отказ (RequireSession)
//     IP передан P47 и не совпал (IpMatch = 0)            → отказ (CheckIp)
//     IP не передан (старый AsdaPatch / P47 SendPeerIp=0) → отказ только при RequireIp=1
//  IpMatch = 2 — совпало через соулмейта: запись входа State=2 пишет UPCharSoulState с IP '0'
//  (дефект оригинала: `EXEC @Ip = UPLogOutUser` берёт код возврата, а не SELECT), поэтому
//  процедура сверяет IP с только что закрытой записью партнёра (SoulMate.Ouserindex).
//  Ошибка самого запроса (процедуры нет / база не ответила) → FailOpen=1: пропуск со строкой
//  в журнале (вход не ломается); FailOpen=0: отказ.
//
//  Хвост от P47: тело 2001 = 8 б + 'P47I' + IPv4 (16 б); тело 2089 = 12 б + 'P47I' + IPv4 (20 б).
//  Длина тела = WORD кадра [1..2] − 10 (sub_5646C0 GameServer: totalLen = len + 10).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "AcJournal.h"
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P50_IdentityCheck";

    bool g_enabled       = true;
    bool g_checkIp       = true;
    bool g_refuseBlocked = true;
    bool g_requireSess   = true;
    bool g_requireIp     = false;
    bool g_failOpen      = true;
    __declspec(thread) bool t_blocked = false;   // ★ acdb: последний отказ этого потока — по блоку учётки
    bool g_logPass       = false;
    bool g_code7         = true;    // ★ acdb (P54): отказ по блоку — метка в 2002/2090 → GameServer шлёт 4101 код 7

    typedef int  (__fastcall *PFN_GetConn)(void* self, void* edx, int groupIdx);           // sub_407390
    typedef int  (__cdecl    *PFN_Sql)(void* ds, void* status, int conn, int a3,
                                       void* out, const char* fmt, ...);                    // sub_447720
    typedef int  (__fastcall *PFN_Send)(void* self, void* edx, int op, int len,
                                        int connIdx, void* body, int userNum);              // sub_44E2F0
    typedef void (__fastcall *PFN_Handler)(void* self, void* edx, int conn, int userNum,
                                           int a5, BYTE* pkt);                              // sub_407480 / sub_417410

    PFN_GetConn const pGetConn = (PFN_GetConn) 0x00407390;
    PFN_Sql     const pSql     = (PFN_Sql)     0x00447720;
    PFN_Send    const pSend    = (PFN_Send)    0x0044E2F0;
    PFN_Handler const pOrig2001 = (PFN_Handler)0x00407480;
    PFN_Handler const pOrig2089 = (PFN_Handler)0x00417410;

    void* const kSendThis = (void*)0x0049EAF8;   // this отправителя ответов
    void* const kDataSrc  = (void*)0x0534E7F0;   // источник данных sub_447720
    const DWORD kVaGroupCount = 0x0F14E53C;      // dword_F14E53C — число групп серверов (сток сверяет)

    constexpr int   kSqlBuf  = 0x36B4;           // 14004 — как у стока
    constexpr DWORD kIpMagic = 0x49373450;       // 'P47I' — хвост от GameServer P47

    // Результат UP_AC_IdentityCheck: 5 × TINYINT подряд (раскладка строки — см. P23).
    constexpr int kCols = 5;
    struct Verdict
    {
        int  accExists, accBlock, charOk, sessOpen, ipMatch;
    };

    volatile LONG g_checked = 0, g_refused = 0, g_errors = 0;

    constexpr DWORD kBlockMagic = 0x42343550;   // 'P54B' — метка «отказ по блоку» в теле 2002/2090 (GameServer P54)

    // ★ acdb (P53): строка журнала ac.login_check_refusal.
    //   kind 1 — отказ, 2 — ошибка запроса (пропуск), 3 — ошибка запроса (отказ); why — код причины
    //   (AcJournal.cpp LoginReason); clientCode — код 4101, который увидит игрок (5/7) или kNone.
    void Journal(BYTE kind, int op, int userNum, int userIndex, int charIdx, DWORD ipv4, bool ipPresent,
                 const int* verdict, int why, int clientCode)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kLoginCheck, kind);
        e.userNum   = (short)userNum;
        e.userIndex = userIndex;
        e.charSlot  = charIdx;
        e.opcode    = op;
        e.ip        = ipPresent ? ipv4 : 0;
        if (verdict) { for (int i = 0; i < 5; ++i) { e.v[i] = verdict[i]; } }
        e.v[5] = ipPresent ? 1 : 0;
        e.v[6] = clientCode;
        e.v[7] = why;
        AcJournal::Push(e);
    }

    // IPv4 (сетевой порядок) → "a.b.c.d".
    void IpToStr(DWORD ip, char* out, int cch)
    {
        const BYTE* b = (const BYTE*)&ip;
        _snprintf(out, cch - 1, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        out[cch - 1] = 0;
    }

    // Запрос к базе. false — сам запрос не удался (тогда решает FailOpen).
    bool Query(int conn, int a5, int userIndex, int charIdx, const char* ip, Verdict* v)
    {
        BYTE* out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
        if (!out) { return false; }
        DWORD status[8] = {};
        char sql[160];
        // Апострофы — только наши (IP из цифр и точек); P28 чистит лишь '%s' ВНУТРИ кавычек формата,
        // а формат здесь "%s" без кавычек — строка уходит как есть.
        _snprintf(sql, sizeof(sql) - 1, "EXEC dbo.UP_AC_IdentityCheck %d, %d, '%s'", userIndex, charIdx, ip);
        sql[sizeof(sql) - 1] = 0;
        bool ok = false;
        __try
        {
            pSql(kDataSrc, status, conn, a5, out, "%s", sql);
            ok = status[0] != 0 && (int)status[1] == kCols && (int)status[2] == 1 && (int)status[3] >= kCols;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }
        if (ok)
        {
            v->accExists = out[0]; v->accBlock = out[1]; v->charOk = out[2]; v->sessOpen = out[3]; v->ipMatch = out[4];
        }
        HeapFree(GetProcessHeap(), 0, out);
        return ok;
    }

    // Общая проверка. true — пропустить в стоковый обработчик.
    bool Check(int op, int conn, int userNum, int a5, BYTE* pkt)
    {
        const int totalLen = *(const WORD*)(pkt + 1);
        const int bodyLen  = totalLen - 10;
        const BYTE* body   = pkt + 9;

        int group, userIndex, charIdx, stockLen;
        if (op == 2001)
        {
            stockLen = 8;
            if (bodyLen < stockLen) { return true; }                // сток сам разберётся
            memcpy(&userIndex, body, 4);
            group   = *(const short*)(body + 4);
            charIdx = *(const short*)(body + 6);
        }
        else
        {
            stockLen = 12;
            if (bodyLen < stockLen) { return true; }
            group = body[0];
            memcpy(&userIndex, body + 2, 4);
            charIdx = *(const short*)(body + 6);
        }
        // Те же границы, что у стока: при выходе за них сток отвечает ошибкой сам — не мешаем.
        const int groups = *(const int*)kVaGroupCount;
        if (userIndex < 0 || charIdx < 0 || group < 0 || group >= groups) { return true; }

        char ip[20] = "";
        bool ipPresent = false;
        DWORD ipRaw = 0;   // ★ acdb: IPv4 для журнала
        if (bodyLen >= stockLen + 8)
        {
            DWORD magic, ipv4;
            memcpy(&magic, body + stockLen, 4);
            memcpy(&ipv4,  body + stockLen + 4, 4);
            if (magic == kIpMagic && ipv4 != 0) { IpToStr(ipv4, ip, sizeof(ip)); ipPresent = true; ipRaw = ipv4; }
        }

        InterlockedIncrement(&g_checked);
        const int conn2 = pGetConn((void*)0x0049EAB8, nullptr, group);
        Verdict v = {};
        if (!Query(conn2, a5, userIndex, charIdx, (ipPresent && g_checkIp) ? ip : "", &v))
        {
            const LONG n = InterlockedIncrement(&g_errors);
            if (n <= 50 || (n % 500) == 0)
            {
                Log::Line(L"[P50] ! запрос UP_AC_IdentityCheck не выполнен (op %d, UserIndex %d, слот %d) — %s "
                          L"(ошибок всего %d)", op, userIndex, charIdx, g_failOpen ? L"пропуск (FailOpen=1)" : L"ОТКАЗ", (int)n);
            }
            Journal(g_failOpen ? 2 : 3, op, userNum, userIndex, charIdx, ipRaw, ipPresent, nullptr, 7,
                    g_failOpen ? AcJournal::kNone : 5);
            return g_failOpen;
        }

        const wchar_t* why = nullptr;
        int whyCode = 0;   // ★ acdb: код причины для журнала (AcJournal.cpp LoginReason)
        if (!v.accExists)                                        { why = L"нет учётки"; whyCode = 1; }
        else if (g_refuseBlocked && v.accBlock != 0)             { why = L"учётка заблокирована"; whyCode = 2; }
        else if (!v.charOk)                                      { why = L"слот не принадлежит учётке"; whyCode = 3; }
        else if (g_requireSess && !v.sessOpen)                   { why = L"нет открытой записи входа"; whyCode = 4; }
        else if (g_checkIp && ipPresent && v.ipMatch == 0)       { why = L"IP не совпал с записью входа"; whyCode = 5; }
        else if (g_requireIp && !ipPresent)                      { why = L"IP не передан (RequireIp=1)"; whyCode = 6; }

        if (!why)
        {
            if (g_logPass)
            {
                Log::Line(L"[P50] пропуск op %d: UserIndex %d слот %d IP %hs (сессия %d, IP %d)",
                          op, userIndex, charIdx, ipPresent ? ip : "—", v.sessOpen, v.ipMatch);
            }
            return true;
        }
        const LONG n = InterlockedIncrement(&g_refused);
        if (n <= 200 || (n % 1000) == 0)
        {
            Log::Line(L"[P50] ОТКАЗ op %d: %s — UserIndex %d, слот %d, IP %hs, userNum %d "
                      L"(учётка %d, блок %d, слот %d, сессия %d, IP %d; отказов всего %d)",
                      op, why, userIndex, charIdx, ipPresent ? ip : "—", userNum,
                      v.accExists, v.accBlock, v.charOk, v.sessOpen, v.ipMatch, (int)n);
        }
        // ★ acdb: отказ по блоку — код 7 для игрока (P54), прочие — штатный 5.
        t_blocked = whyCode == 2 && g_code7;
        const int verdict[5] = { v.accExists, v.accBlock, v.charOk, v.sessOpen, v.ipMatch };
        Journal(1, op, userNum, userIndex, charIdx, ipRaw, ipPresent, verdict, whyCode, t_blocked ? 7 : 5);
        return false;
    }

    // Штатный ответ-неудача (как сток при ошибке UPCharInfo).
    //   ★ acdb (P54): отказ ИМЕННО по блоку учётки — метка [1..4] = 'P54B', [5] = 1 (байт [0] = 0 как в стоке;
    //   GameServer в ветке неудачи читает только [0], наш P54 по метке шлёт игроку 4101 код 7).
    void SendFail(int op, int conn, int userNum, bool blocked)
    {
        BYTE body[272] = {};
        if (blocked) { memcpy(body + 1, &kBlockMagic, 4); body[5] = 1; }
        if (op == 2001) { pSend(kSendThis, nullptr, 2002, 265, conn, body, userNum); }
        else            { pSend(kSendThis, nullptr, 2090, 262, conn, body, userNum); }
    }
}

// Обёртки — то же соглашение, что у стоковых обработчиков (thiscall, 4 аргумента в стеке, ret 0x10).
void __fastcall P50_Wrap2001(void* self, void* edx, int conn, int userNum, int a5, BYTE* pkt)
{
    bool pass = true;
    t_blocked = false;
    if (g_enabled)
    {
        __try { pass = Check(2001, conn, userNum, a5, pkt); }
        __except (EXCEPTION_EXECUTE_HANDLER) { pass = true; }
    }
    if (!pass) { SendFail(2001, conn, userNum, t_blocked); return; }
    pOrig2001(self, edx, conn, userNum, a5, pkt);
}

void __fastcall P50_Wrap2089(void* self, void* edx, int conn, int userNum, int a5, BYTE* pkt)
{
    bool pass = true;
    t_blocked = false;
    if (g_enabled)
    {
        __try { pass = Check(2089, conn, userNum, a5, pkt); }
        __except (EXCEPTION_EXECUTE_HANDLER) { pass = true; }
    }
    if (!pass) { SendFail(2089, conn, userNum, t_blocked); return; }
    pOrig2089(self, edx, conn, userNum, a5, pkt);
}

PatchResult P50_IdentityCheck()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_checkIp       = Config::GetBool(kSec, L"CheckIp", true);
    g_refuseBlocked = Config::GetBool(kSec, L"RefuseBlocked", true);
    g_requireSess   = Config::GetBool(kSec, L"RequireSession", true);
    g_requireIp     = Config::GetBool(kSec, L"RequireIp", false);
    g_failOpen      = Config::GetBool(kSec, L"FailOpen", true);
    g_logPass       = Config::GetBool(kSec, L"LogPass", false);
    g_code7         = Config::GetBool(kSec, L"BlockedClientCode7", true);   // ★ acdb (P54)

    static const BYTE kOrig2001[5] = { 0xE8, 0xAA, 0x4D, 0x00, 0x00 };   // call 0x407480
    static const BYTE kOrig2089[5] = { 0xE8, 0x28, 0x44, 0x01, 0x00 };   // call 0x417410
    const Site sites[] =
    {
        { 0x004026D1, kOrig2001, sizeof(kOrig2001) },
        { 0x00402FE3, kOrig2089, sizeof(kOrig2089) },
    };
    if (!VerifyAllSites(L"P50", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteCall(0x004026D1, (const void*)&P50_Wrap2001, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x00402FE3, (const void*)&P50_Wrap2089, 5)) { return PatchResult::Failed; }

    Log::Line(L"    P50: 2001/2089 -> UP_AC_IdentityCheck до UPCharInfo; CheckIp=%d RefuseBlocked=%d "
              L"RequireSession=%d RequireIp=%d FailOpen=%d; отказ = штатный 2002/2090 [0]=0; "
              L"отказ по блоку -> метка P54 (игроку код 7)=%d",
              g_checkIp ? 1 : 0, g_refuseBlocked ? 1 : 0, g_requireSess ? 1 : 0, g_requireIp ? 1 : 0,
              g_failOpen ? 1 : 0, g_code7 ? 1 : 0);
    return PatchResult::Applied;
}
