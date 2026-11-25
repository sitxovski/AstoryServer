// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P109 — [ИСПРАВЛЕНИЕ] НАВЫК «НА СЕБЯ» НЕ НАНОСИТ УРОН САМОМУ КАСТЕРУ (05.11.2026, сессия job4-skills; жалоба игрока
//  «получаю урон, когда применяю King's Rage»; решение владельца «дефекты оригинала исправляем»).
//
//  Клиент: само-каст (вид 2, resourceType 0/1 — эталон `combatHandleSkillUse@0xE4B960` → `skillCastSelfSendPacket@0x9FE210`)
//    шлёт 5256 с ОДНОЙ записью 29 б: тип 1 (персонаж), idx = свой userNum.
//  GameServer `RecvChar_SkillUse@0x46F900` пересылает заявку NpcServer (внутренний 8205). NpcServer `SkillStart` (sub_418670,
//    NpcServer.exe.c:16689) для КАЖДОЙ записи-персонажа, если цель жива (+30292), считает урон навыка (sub_40BB00 → sub_4179D0:
//    урон @3, флаги @7) — проверки «цель = сам кастер» нет. У навыков с ненулевым множителем урона (.sif +0x3E/+0x40 «ms»)
//    это даёт реальный урон по себе: 611 Parry и 612 King's Rage (ms 100 + 20/ур.), 616 Violent Storm (120 + 45/ур.) — все три
//    активные само-касты 4-й профессии воина; в подсказках этих навыков [ms] нет (Parry/King's Rage — снижение/отражение урона,
//    Violent Storm — периодический урон состоянием 77 по врагам).
//  Ответ 8206 → диспетчер `ConnectSocketMsgProcess` @0x43164E → sub_470DB0@0x470DB0 (CSkillManager, a2 = userNum, a3 = пакет):
//    записи копируются из a3 + 14 + 29·i (число = (WORD[a3+1] − 15) / 29, не больше 20) и идут в sub_471C70 (цель-персонаж):
//    при бите 0 флагов — sub_486130 + sub_4CA330(цель, урон, кастер) = HP цели −= урон (у себя: 4058 «−1156» в живом журнале
//    Player5 03.11 20:51:00), затем 5257/5270 несёт ту же запись клиенту, и клиент ещё раз вычитает урон и пишет
//    «You have delivered 1156 damage to <себе> with Parry». Обычные само-баффы (ms = 0) приходят с уроном 0 и флагами 0x03.
//
//  ── ЧТО ДЕЛАЕТ P109 (9 байт входа sub_470DB0, протокол не меняется) ──
//  Вход sub_470DB0 (`push ebp · mov ebp,esp · sub esp,570h`) → jmp в трамплин: P109_Filter(a2, a3) на копии пакета ДО того, как
//    сток разложит записи: у каждой записи «тип 1 и idx == кастер» с ненулевым уроном урон := 0, флаги &= 0x03 (снимаются
//    крит 0x04 / блок 0x08 / IMMUNE 0x20 — признаки посчитанного удара; биты 0/1 остаются как у любого само-баффа, поэтому
//    наложение баффа, снятие своей невидимости 112/186 и прочая ветка sub_471C70 идут как раньше). Дальше — пролог стока и
//    jmp 0x470DB9. Записи-мобы, чужие игроки, PvP-цели не трогаются. Касты с временем (5270 → recvBattleCastingTimeEnd) берут
//    записи из той же копии (sub_47B580), поэтому исправлены тоже.
//  Площадку диспетчера 0x43164E держит P56 (снятие отметки «в пути»), поэтому P109 ставится на вход функции, а не на call.
//  Ключи [P109_SelfHitNoDamage]: Enabled (0 — сток), LogPerMinute (журнал Log_Skill не чаще N строк в минуту).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../SrvApi.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P109_SelfHitNoDamage";   // секция patches.ini

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);   // стоковый журнал sub_569DF0
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;                      // адрес журнала стока

    // ── площадка: вход sub_470DB0 (байты живого GameServer.exe e7b4ac38 = gs_stock) ─────────────
    // push ebp · mov ebp,esp · sub esp,570h
    const BYTE kEntryOrig[] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x70, 0x05, 0x00, 0x00 };
    // соседи (только сверка): продолжение 0x470DB9 — mov eax,[___security_cookie] · xor eax,ebp · mov [ebp-8],eax;
    //   копия записей (0x470E8F…) — разбор длины mov ax,[a3+1] не сверяется побайтно, P109 читает пакет сам по тем же правилам.
    const BYTE kBackOrig[]  = { 0xA1, 0xF0, 0x63, 0x5A, 0x00, 0x33, 0xC5, 0x89, 0x45, 0xF8 };
    // вызов из диспетчера 8206 (0x43163D): mov cx,[ebp-8] · push ecx — userNum кастера идёт вторым аргументом (a2)
    const BYTE kCallerArg[] = { 0x66, 0x8B, 0x4D, 0xF8, 0x51 };

    constexpr DWORD kEntry  = 0x00470DB0;   // вход sub_470DB0
    constexpr DWORD kBack   = 0x00470DB9;   // продолжение стока после пролога
    constexpr DWORD kCaller = 0x0043163D;   // подготовка аргументов в ConnectSocketMsgProcess (case 8206)

    constexpr int  kHdr       = 14;         // записи с a3 + 14 (GameServer.c:46354: a3 + 29·i + 14)
    constexpr int  kRecLen    = 29;         // длина записи цели
    constexpr int  kMaxRecs   = 20;         // сток: iRecvCount > 0x14 → отказ разбора
    constexpr BYTE kKeepFlags = 0x03;       // флаги обычного само-баффа (попадание + наложение)
    constexpr int  kLogCat    = 18;         // канал стока, в который sub_470DB0 пишет свой разбор (GameServer.c:46347)

    DWORD g_pBack = kBack;                  // косвенная цель возврата из трамплина (абсолютный адрес через память)

    // ── журнал с пределом (как у P31/P35) ──
    int              g_logMax    = 30;      // строк в минуту
    CRITICAL_SECTION g_logCs;               // защита окна журнала
    bool             g_logCsInit = false;   // секция создана
    DWORD            g_logWin    = 0;       // начало минутного окна
    int              g_logCnt    = 0;       // строк в окне
    int              g_logDrop   = 0;       // подавлено в окне

    // ── счётчики (экспорт P109_GetStats — для стенда и журнала) ──
    volatile LONG g_calls  = 0;             // входов в sub_470DB0
    volatile LONG g_fixed  = 0;             // записей «себя» с уроном, обнулённых P109
    volatile LONG g_bad    = 0;             // пакетов с непригодной длиной (оставлены стоку)
    volatile LONG g_except = 0;             // исключений при чтении пакета

    // Можно ли писать строку журнала (не больше g_logMax в минуту; о подавленных — одной строкой в начале нового окна).
    bool LogAllowed()
    {
        if (!g_logCsInit) { return false; }
        int  dropped = 0;
        bool ok;
        EnterCriticalSection(&g_logCs);
        const DWORD now = GetTickCount();
        if (g_logWin == 0 || (DWORD)(now - g_logWin) >= 60000)
        {
            dropped   = g_logDrop;
            g_logWin  = now ? now : 1;
            g_logCnt  = 0;
            g_logDrop = 0;
        }
        ok = g_logCnt < g_logMax;
        if (ok) { ++g_logCnt; } else { ++g_logDrop; }
        LeaveCriticalSection(&g_logCs);
        if (dropped > 0)
        {
            SrvLog(kLogCat, "P109: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)", dropped, g_logMax);
        }
        return ok;
    }
}

extern "C"
{
// C-часть трамплина: вызывается ДО пролога sub_470DB0. userNum — a2 стока (WORD в DWORD-слоте), pkt — a3 (кадр 8206 целиком:
//   [1] WORD длина, [9] результат, [10] i16 навык, [14…] записи). Пакет правится на месте: сток копирует записи из него позже.
__declspec(dllexport) void __stdcall P109_Filter(int userNum, BYTE* pkt)
{
    InterlockedIncrement(&g_calls);
    const short caster = (short)userNum;
    short skill = -1;
    int   nFix = 0;
    int   firstDmg = 0;
    BYTE  firstFlags = 0;
    __try
    {
        if (!pkt) { return; }
        const int size = *(const WORD*)(pkt + 1);
        const int body = size - 15;                                    // сток: (v26[0] − 15) / 0x1D, остаток должен быть 0
        if (body < 0 || body % kRecLen != 0 || body / kRecLen > kMaxRecs)
        {
            InterlockedIncrement(&g_bad);
            return;                                                    // сток сам отвергнет такой пакет (строка «iRecvCount»)
        }
        skill = *(const short*)(pkt + 10);
        const int n = body / kRecLen;
        for (int i = 0; i < n; ++i)
        {
            BYTE* rec = pkt + kHdr + kRecLen * i;
            if (rec[0] != 1) { continue; }                             // 0 — сущность (моб), не персонаж
            if (*(const short*)(rec + 1) != caster) { continue; }      // чужой игрок — урон законный
            const int dmg = *(const int*)(rec + 3);
            if (dmg == 0) { continue; }                                // обычный само-бафф
            if (nFix == 0) { firstDmg = dmg; firstFlags = rec[7]; }
            *(int*)(rec + 3) = 0;
            rec[7] = (BYTE)(rec[7] & kKeepFlags);
            ++nFix;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_except);
        return;
    }
    if (nFix > 0)
    {
        const LONG total = InterlockedExchangeAdd(&g_fixed, nFix) + nFix;
        if (LogAllowed())
        {
            SrvLog(kLogCat, "P109: user %d skill %d - self target damage %d (flags 0x%02X) zeroed in %d record(s) (total %ld)",
                   (int)caster, (int)skill, firstDmg, (unsigned)firstFlags, nFix, total);
        }
    }
}

// Счётчики: [0] входов, [1] обнулённых записей, [2] пакетов с непригодной длиной, [3] исключений.
__declspec(dllexport) void __stdcall P109_GetStats(int* out)
{
    if (!out) { return; }
    out[0] = (int)g_calls;
    out[1] = (int)g_fixed;
    out[2] = (int)g_bad;
    out[3] = (int)g_except;
}
}

namespace
{
    // Трамплин на месте пролога sub_470DB0. На входе: [esp] возврат в диспетчер, [esp+4] a2 (userNum), [esp+8] a3 (пакет),
    //   ecx — CSkillManager. Сохраняет все регистры и флаги, зовёт фильтр, повторяет снятый пролог и уходит на 0x470DB9.
    __declspec(naked) void P109_Tramp()
    {
        __asm
        {
            pushad
            pushfd
            push  dword ptr [esp+44]            // a3: 36 (pushad+pushfd) + 8
            push  dword ptr [esp+44]            // a2: после первого push сдвиг +4 → 36 + 4 + 4
            call  P109_Filter                   // __stdcall, 8 б
            popfd
            popad
            push  ebp                           // снятый пролог стока
            mov   ebp, esp
            sub   esp, 570h
            jmp   dword ptr [g_pBack]
        }
    }
}

PatchResult P109_SelfHitNoDamage()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    int perMin = Config::GetInt(kSec, L"LogPerMinute", 30);
    if (perMin < 1)    { perMin = 1; }
    if (perMin > 1000) { perMin = 1000; }
    g_logMax = perMin;

    const Site check[] =
    {
        { kEntry, kEntryOrig, sizeof(kEntryOrig) }, { kBack, kBackOrig, sizeof(kBackOrig) }, { kCaller, kCallerArg, sizeof(kCallerArg) },
    };
    if (!VerifyAllSites(L"P109", check, ARRAYSIZE(check))) { return PatchResult::Mismatch; }

    if (!g_logCsInit)
    {
        InitializeCriticalSection(&g_logCs);
        g_logCsInit = true;
    }

    if (!Hook::WriteJmp(kEntry, (const void*)&P109_Tramp, sizeof(kEntryOrig))) { return PatchResult::Failed; }
    if (*(const BYTE*)kEntry != 0xE9) { return PatchResult::Failed; }

    Log::Line(L"    P109: вход sub_470DB0 (ответ NpcServer 8206) @0x%08X 9 б → 0x%08X: запись цели «сам кастер» с уроном — урон 0, "
              L"флаги & 0x03 (сток: урон навыка по себе у 611/612/616)", kEntry, (DWORD)&P109_Tramp);
    Log::Line(L"    P109: журнал канала %d — не больше %d строк в минуту", kLogCat, g_logMax);
    return PatchResult::Applied;
}
