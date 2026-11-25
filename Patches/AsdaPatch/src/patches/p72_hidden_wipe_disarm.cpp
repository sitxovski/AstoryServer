// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P72 — ★ ОБЕЗВРЕЖИВАНИЕ СКРЫТОЙ ЗАКЛАДКИ «CharItemKeeping(11)» (безопасность, 2026-10-15).
//  [ОРИГИНАЛ — закладка в стоковом GameServer; сток, живой и Indun совпадают побайтно на всех площадках.]
//  Разбор: `Reports/anticheat/re_itemkeeping_hidden.md` (источник находки — `audit_signed_tick_20261015.md` §3.2 п.3, §6 п.1).
//  Документ: `AstoryServer/Docs/GameServer/hidden-wipe-disarm-p72.md`. Отчёт: `Reports/anticheat/wave_P72_20261015.md`.
//
//  ── ЧТО ДЕЛАЕТ ЗАКЛАДКА ──
//  В объекте потока карты (CThread = *(CUserManager+4); у RunProcess это `this` = [ebp-0xE4]) лежат пять байтовых флагов
//  +0x51AC…+0x51B0 и такт +0x51B4 (обнуляются конструктором sub_4BEEE0 @0x4BF14A…0x4BF17C). Пять штатных действий
//  с предметами, выполненных строго по порядку за ≤ 60 с (между минутными проверками блока 10024 RunProcess), взводят флаги:
//    1) 5000 CharItemMove: инвентарь ячейка 0 → ячейка 59, занятая (обмен)                    @0x4CFF17…0x4CFF98
//    2) 5006 CharItemDump: выбросить ячейку 48, количество 3                                   @0x4D3C9E…0x4D3D1A
//    3) 5028 CharSpendItemUse: зелье категории 200 из ячейки 50 под запрещающим состоянием   @0x4D9CA0…0x4D9D24
//    4) 5288 CharExchangeDragDropItem: в обмене положить ячейку 47 со стопкой ровно 9          @0x4E2ABD…0x4E2B38
//    5) 5008 CharItemKeeping: сдать на склад ячейку 45, количество 8, на складе стопка ровно 8  @0x50A5A0…0x50A6B0
//  После шага 5 (флаги = 1,1,1,1,1; +0x51B4 = GetTickCount) блок 10024 RunProcess (sub_4C0EA0, @0x4C2735…0x4C28A3) раз в минуту:
//      if (f1..f5 все == 1) { if ((int)(now − такт) > 600000) { for i in 0..549: p = sub_4BE060(0x60AD18, i);
//                                                                 if (p) memset(p + 0x174, 0, 0x45);   // @0x4C2839
//                                                               такт = now + rand(600000…6000000); } }
//      else { f1..f5 = 0; }                                                                      // @0x4C2869…0x4C28A3
//  memset затирает у ВСЕХ 550 слотов CUser процесса базовый блок персонажа +0x174 (0x45 б: charId, имя, уровень, опыт, группа):
//  онлайн-игроки теряют сохранение (DisConnectUser при charId ≤ 0 не шлёт 2003), свободные слоты (charId −1 → 0) становятся
//  «занятыми» — новые входы на этот GS отбиваются до рестарта; повтор через 20–110 мин до рестарта или «кода отмены».
//  P18 D4 (трамплин 0x50A6E6) стоит ПОСЛЕ взведения (@0x50A65A…0x50A6B0) и убирает только дюп через DB 2029.
//
//  ── ЧТО ДЕЛАЕТ P72 (две независимые меры, каждая — свой ключ ini) ──
//  DisarmTimer (мера 1, основная): площадка 0x4C2745 `0F 85 1E 01 00 00` (jne 0x4C2869) → `E9 1F 01 00 00 90` (jmp 0x4C2869).
//    Блок 10024 ВСЕГДА уходит в ветку сброса: флаги обнуляются раз в минуту, memset @0x4C2839 недостижим. Переходов внутрь
//    0x4C2746…0x4C274A нет (полный проход .text, verify_p72.py), байты одинаковы во всех трёх образах.
//  CatchArming (мера 2): площадка 0x50A651 `8B 95 14 FA FF FF` (mov edx,[ebp-0x5EC], первая инструкция блока взведения
//    @0x50A651…0x50A6B0) → jmp на трамплин. Трамплин зовёт P72_OnArmed(mgr = [ebp-0x5EC], userNum = [ebp+8]): флаги и такт
//    CThread обнуляются (взведение не происходит), событие уходит в журнал античита (ac.other 76), Log_Operator и — по ключу
//    AutoBlock — в штатный блок учётки 2271/UPHackBlock (общая точка P48_SendHackBlock). Регистры и флаги процессора
//    сохраняются (pushfd/pushad … popad/popfd). Дальше по ключу Response:
//      0 (умолчание) — «молча»: переход на 0x50A6EB (штатный хвост обработчика → DB 2029): для игрока это ОБЫЧНАЯ сдача
//          8 предметов на склад, квитанции-«отказа» 5009 код 5 и строки категории 26 нет — набравший комбинацию не узнаёт,
//          что его заметили; стоковой дюп-ветки здесь нет (в неё попадали только через взведение).
//      1 — «как сток»: переход на 0x50A6B6 (строка лога категории 26 «CharItemKeeping(11)», 5009 код 5; при P18 D4 — return
//          в эпилог без DB 2029, без P18 D4 — стоковый дефект дюпа D4).
//    Попытка набрать комбинацию — явный признак умысла (случайно — практически исключено, см. разбор §6): AutoBlock=1 шлёт
//    блок учётки сессии (P48_SendHackBlock, часы BlockHours, −1 бессрочно). Умолчание 0 — решение о санкции за владельцем.
//  Обе меры ставятся и в живой GameServer, и в Indun (тот же образ e7b4ac38). Аналогов в NpcServer/DBManager/LoginManager/
//  ItemRelayServer нет (разбор §7).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"P72_HiddenWipeDisarm";

    constexpr int  kOffFlags   = 0x51AC;   // CThread: пять байтов флагов шагов 1…5 (+0x51AC…+0x51B0)
    constexpr int  kFlagCount  = 5;
    constexpr int  kOffArmTick = 0x51B4;   // CThread: такт взведения (GetTickCount на шаге 5)
    constexpr BYTE kKindArmed  = 76;       // ac.other 76 — комбинация набрана, взвод обезврежен (реестр ac-journal-p53.md §9)
    constexpr int  kOpKeeping  = 5008;     // опкод шага 5 (CharItemKeeping)

    // ── мера 1: таймер затирания (RunProcess 10024, sub_4C0EA0) ─────────────
    const DWORD kTimerSite    = 0x004C2745;
    const BYTE  kTimerOrig[6] = { 0x0F, 0x85, 0x1E, 0x01, 0x00, 0x00 };   // jne 0x4C2869 (f1 != 1 → сброс)
    const BYTE  kTimerNew [6] = { 0xE9, 0x1F, 0x01, 0x00, 0x00, 0x90 };   // jmp 0x4C2869 ; nop — сброс ВСЕГДА
    // соседи меры 1 (только сверка, не пишутся)
    const DWORD kResetSite     = 0x004C2869;                                // ветка сброса: mov edx,[ebp-0xE4]
    const BYTE  kResetOrig[6]  = { 0x8B, 0x95, 0x1C, 0xFF, 0xFF, 0xFF };
    const DWORD kMemsetSite    = 0x004C2839;                                // call memset(p+0x174, 0, 0x45)
    const BYTE  kMemsetOrig[5] = { 0xE8, 0x62, 0x7D, 0x0A, 0x00 };
    const DWORD kLoopSite      = 0x004C27F2;                                // cmp [ebp-0xDC], 0x226 — 550 слотов
    const BYTE  kLoopOrig[10]  = { 0x81, 0xBD, 0x24, 0xFF, 0xFF, 0xFF, 0x26, 0x02, 0x00, 0x00 };

    // ── мера 2: взведение на шаге 5 (CharItemKeeping) ───────────────────────
    const DWORD kArmSite       = 0x0050A651;
    const BYTE  kArmOrig[6]    = { 0x8B, 0x95, 0x14, 0xFA, 0xFF, 0xFF };   // mov edx,[ebp-0x5EC] — первая запись флага f5
    DWORD g_pRouteSilent       = 0x0050A6EB;                                // jmp 0x50A9B6 — штатный хвост (обычная сдача, DB 2029)
    DWORD g_pRouteStock        = 0x0050A6B6;                                // push off_5961EC; push 0x1A; call Log — сток после взведения
    // соседи меры 2 (только сверка)
    const BYTE  kRouteSilentOrig[5] = { 0xE9, 0xC6, 0x02, 0x00, 0x00 };
    const BYTE  kRouteStockOrig[5]  = { 0x68, 0xEC, 0x61, 0x59, 0x00 };
    const DWORD kArmLastSite        = 0x0050A6B0;                           // mov [edx+0x51B4], eax — последняя запись взведения
    const BYTE  kArmLastOrig[6]     = { 0x89, 0x82, 0xB4, 0x51, 0x00, 0x00 };
    const DWORD kUserIdxSite        = 0x0050A6D1;                           // mov cx, word ptr [ebp+8] — userIndex в кадре
    const BYTE  kUserIdxOrig[4]     = { 0x66, 0x8B, 0x4D, 0x08 };

    // ── настройки ───────────────────────────────────────────────────────────
    int  g_response   = 0;      // 0 — молча (обычная сдача), 1 — как сток (5009 код 5 + лог кат. 26)
    bool g_autoBlock  = false;  // блок учётки сессии (2271/UPHackBlock через P48_SendHackBlock)
    int  g_blockHours = -1;     // часы блока; −1 — бессрочно
    bool g_exemptGm   = true;   // оператора (GM-флаг) не блокировать (журнал пишется всегда)

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef void (__cdecl *PFN_SrvLog)(int cat, const char* fmt, ...);        // sub_569DF0
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)Srv::kLog;

    P72_Stats g_stats = {};

    // Обнулить флаги и такт закладки у объекта потока карты. true — обнулено.
    bool ClearFlags(void* mgr)
    {
        bool ok = false;
        __try
        {
            BYTE* thread = *(BYTE**)((BYTE*)mgr + 4);
            if (thread)
            {
                for (int i = 0; i < kFlagCount; ++i) { thread[kOffFlags + i] = 0; }
                *(DWORD*)(thread + kOffArmTick) = 0;
                ok = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
        return ok;
    }
}

// ── C-часть трамплина: зовётся с площадки 0x50A651 ПЕРЕД записью флагов шага 5 ──
//   mgr — CUserManager ([ebp-0x5EC] кадра CharItemKeeping), userNum — слот сессии ([ebp+8]).
//   Возврат: 0 — продолжить как обычную сдачу (0x50A6EB), 1 — стоковый путь после взведения (0x50A6B6).
extern "C" __declspec(dllexport) int __stdcall P72_OnArmed(void* mgr, int userNum)
{
    InterlockedIncrement(&g_stats.caught);
    const bool cleared = ClearFlags(mgr);
    if (!cleared) { InterlockedIncrement(&g_stats.clearFailed); }

    P69_Session s = {};
    P69_ResolveSession(mgr, userNum, &s);          // CUser, учётка сессии, слот персонажа, GM-флаг (общая точка P69)
    const int account = s.account > 0 ? s.account : (s.owner > 0 ? s.owner : 0);

    int blocked = 0;                                // 0 — не слали, 1 — 2271 отправлен, 2 — отказ отправки, 3 — оператор освобождён
    if (g_autoBlock)
    {
        if (s.gm && g_exemptGm) { blocked = 3; }
        else if (s.account > 0)
        {
            blocked = P48_SendHackBlock(mgr, userNum, s.account, g_blockHours) ? 1 : 2;
            InterlockedIncrement(blocked == 1 ? &g_stats.blockSent : &g_stats.blockFailed);
        }
        else { blocked = 2; InterlockedIncrement(&g_stats.blockFailed); }
    }

    // журнал античита: ac.other 76
    AcJournal::Event e;
    AcJournal::Clear(e, AcJournal::kOther, kKindArmed);
    e.userNum   = (short)userNum;
    e.userIndex = account > 0 ? account : AcJournal::kNone;
    e.charSlot  = s.charSlot >= 0 ? s.charSlot : AcJournal::kNone;
    e.opcode    = kOpKeeping;
    e.ip        = P47_PeerIpv4(userNum);
    if (s.user)
    {
        __try { AcJournal::CopyName(e, s.user + Srv::kOffCharName); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    e.v[0] = g_response;        // item_code: 0 молча / 1 как сток
    e.v[1] = blocked;           // value1: 0 не слали / 1 2271 отправлен / 2 отказ / 3 оператор освобождён
    e.v[2] = s.state;           // value2: состояние сессии (0 до входа, 1 в мире, 2 соулмейт, 3 соулмейт без учётки, −1 нет CUser)
    char t[64];
    _snprintf_s(t, sizeof(t), _TRUNCATE, "P72 arm seq done; flags %s; resp %d; block %d", cleared ? "cleared" : "NOT cleared", g_response, blocked);
    AcJournal::CopyText(e, t);
    AcJournal::Push(e);

    char name[24] = "?";
    if (s.user)
    {
        __try { lstrcpynA(name, (const char*)(s.user + Srv::kOffCharName), 20); }
        __except (EXCEPTION_EXECUTE_HANDLER) { lstrcpyA(name, "?"); }
    }
    __try
    {
        pSrvLog(Srv::kLogCatOperator, "P72 HiddenWipeDisarm: CharItemKeeping(11) arming sequence completed by UserNum %d (UserIndex %d, CharN %s, "
                "state %d, gm %d) -> flags %s, response %s, autoblock %s",
                userNum, account, name, s.state, s.gm ? 1 : 0, cleared ? "cleared" : "NOT CLEARED", g_response ? "stock(5009 code 5)" : "silent(normal keeping)",
                blocked == 0 ? "off" : blocked == 1 ? "2271 sent" : blocked == 2 ? "FAILED" : "operator exempt");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (g_response) { InterlockedIncrement(&g_stats.routeStock); return 1; }
    InterlockedIncrement(&g_stats.routeSilent);
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P72_GetStats(P72_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Трамплин площадки 0x50A651. Вход по jmp: ebp — кадр CharItemKeeping ([ebp-0x5EC] = CUserManager*, [ebp+8] = userIndex
    // WORD). Регистры и флаги сохраняются целиком; выбор маршрута несём во флаге ZF между `test` и `jnz` (popad флаги не трогает,
    // popfd стоит уже после ветвления). Стек на выходе — как на входе.
    __declspec(naked) void ArmTrampoline()
    {
        __asm
        {
            pushfd
            pushad
            movzx eax, word ptr [ebp+8]             // userNum
            push  eax
            push  dword ptr [ebp-0x5EC]             // CUserManager*
            call  P72_OnArmed                       // stdcall: чистит 8 байт сам
            test  eax, eax                          // ZF = (маршрут 0 — молча)
            popad
            jnz   RouteStock
            popfd
            jmp   dword ptr [g_pRouteSilent]        // 0x50A6EB — обычная сдача
        RouteStock:
            popfd
            jmp   dword ptr [g_pRouteStock]         // 0x50A6B6 — стоковый путь после взведения
        }
    }
}

PatchResult P72_HiddenWipeDisarm()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    const bool disarm = Config::GetBool(kSec, L"DisarmTimer", true);
    const bool catchA = Config::GetBool(kSec, L"CatchArming", true);
    g_response   = Config::GetInt (kSec, L"Response", 0) ? 1 : 0;
    g_autoBlock  = Config::GetBool(kSec, L"AutoBlock", false);
    g_blockHours = Config::GetInt (kSec, L"BlockHours", -1);
    g_exemptGm   = Config::GetBool(kSec, L"ExemptOperators", true);
    if (g_blockHours == 0 || g_blockHours < -1) { g_blockHours = -1; Log::Line(L"    P72: BlockHours негоден (0 или < -1) — взято -1 (бессрочно)"); }
    if (!disarm && !catchA)
    {
        Log::Line(L"    P72: DisarmTimer=0 и CatchArming=0 — ставить нечего");
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ площадок и соседей включённых мер ДО первой записи ──────
    Site check[9];      // [ревизия 15.10 КОСМ-1] максимум 9 площадок/соседей
    int  n = 0;
    if (disarm)
    {
        check[n++] = { kTimerSite,  kTimerOrig,  sizeof(kTimerOrig)  };
        check[n++] = { kResetSite,  kResetOrig,  sizeof(kResetOrig)  };
        check[n++] = { kMemsetSite, kMemsetOrig, sizeof(kMemsetOrig) };
        check[n++] = { kLoopSite,   kLoopOrig,   sizeof(kLoopOrig)   };
    }
    if (catchA)
    {
        check[n++] = { kArmSite,        kArmOrig,         sizeof(kArmOrig)         };
        check[n++] = { g_pRouteSilent,  kRouteSilentOrig, sizeof(kRouteSilentOrig) };
        check[n++] = { g_pRouteStock,   kRouteStockOrig,  sizeof(kRouteStockOrig)  };
        check[n++] = { kArmLastSite,    kArmLastOrig,     sizeof(kArmLastOrig)     };
        check[n++] = { kUserIdxSite,    kUserIdxOrig,     sizeof(kUserIdxOrig)     };
    }
    if (!VerifyAllSites(L"P72", check, n)) { return PatchResult::Mismatch; }

    // ── запись ──────────────────────────────────────────────────────────────
    if (disarm)
    {
        if (!Hook::WriteBytes(kTimerSite, kTimerNew, sizeof(kTimerNew))) { return PatchResult::Failed; }
        Log::Line(L"    P72 DisarmTimer: RunProcess 10024 @0x%08X `jne 0x4C2869` -> `jmp 0x4C2869` — ветка сброса флагов всегда, "
                  L"memset(CUser+0x174, 0, 0x45) по 550 слотам @0x%08X недостижим", kTimerSite, kMemsetSite);
    }
    if (catchA)
    {
        if (!Hook::WriteJmp(kArmSite, &ArmTrampoline, sizeof(kArmOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P72 CatchArming: CharItemKeeping шаг 5 @0x%08X -> трамплин 0x%08X: флаги CThread+0x51AC..0x51B0 и такт +0x51B4 "
                  L"обнуляются, журнал ac.other %d + Log_Operator; маршрут %s (0x%08X); AutoBlock=%d (часы %d, операторы %s)",
                  kArmSite, (DWORD)&ArmTrampoline, kKindArmed, g_response ? L"как сток: 5009 код 5" : L"молча: обычная сдача",
                  g_response ? g_pRouteStock : g_pRouteSilent, g_autoBlock ? 1 : 0, g_blockHours, g_exemptGm ? L"освобождены" : L"блокируются");
    }
    return PatchResult::Applied;
}
