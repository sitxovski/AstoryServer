// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P57 — ★ ХОД: порог «Hack Position» → кик, пределы 4006, позиция 4008 из проверенных полей
//  (античит, волна A6 «ход + причина отключения + редкий дроп», 2026-10-12; план 00_PLAN.md мера 12,
//  01_network_protocol.md F10, 02_parts/movement_teleport.md MV-1/MV-2). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  Отчёт: `Reports/anticheat/wave_A6_move_p1_p4.md`; документ: `AstoryServer/Docs/GameServer/move-guard-p57.md`.
//
//  ── ЧТО ДЕЛАЕТ ──
//  A. Счётчик штатных срабатываний «CharMove Hack Position» (0x54543D) / «CharReMove Hack Position» (0x545A84)
//     на СЕССИЮ за окно HackPosWindowSec. События берутся у P53 (его площадки зовут P57_OnHackPosition);
//     если P53 площадки не ставил (выключен / StockSites=0) — P57 ставит на те же два `call sub_569DF0`
//     свои стабы той же формы (стаб → P57 → стоковый писатель логов). Порог HackPosKickThreshold:
//       Mode=0 (журнал) — строка в Log_Game + журнал P53 (ac.move_combat вид 14), кика НЕТ;
//       Mode=1 (отказ)  — кик штатной парой Send_DisConnectType(KickType) + ExceptionDisConnectUser
//                         (как sendSpeedHackDisConnect@0x527180), выполняется ПОСЛЕ стокового хвоста
//                         ветки Hack Position (площадки `call sub_4C58F0` 0x5454DE / 0x545B25 = LABEL_41:
//                         позиция уже откатана, 4007 result=5 отправлен) — так же, как стоковая ветка
//                         «CharMove Exception» зовёт ExceptionDisConnectUser и выходит. Тип 6 считает P48 (автоблок).
//     ★ Фон владельца: 114 срабатываний в архиве логов — все на его учётках с честным портом (GM-телепорты,
//       смена карты); порог по умолчанию 30 за 10 мин — выше любого наблюдённого всплеска (см. отчёт §2).
//  B. 4006 CharMove (MV-2, F10): площадка `call sub_55FF20` 0x54531D (проверка campwar — последняя стоковая
//     проверка перед ветвлением «с места / в движении»). Стаб зовёт сток, и если тот вернул 1 — наши проверки:
//       1) длина отрезка клиентская-текущая → цель > MaxStepLen (ед.; 0 = не проверять). [p57fix 15.10] Значение
//          ниже kStepLenFloor (72 500 = диагональ карты 512×512 + запас) поднимается до него (строка в PatchLog):
//          у оригинала длину отрезка ограничивает только карта (автоход по пути), прежние 4000 ловили честный
//          дальний клик (15.10 на живом: 4769 ед.);
//       2) в движении: НАКОПЛЕННЫЙ БЮДЖЕТ ХОДА (см. «p57fix» ниже);
//       3) в движении: клетка клиентской позиции вне карты (sub_4221D0) или непроходима (sub_41A010).
//     ★ p57fix (2026-10-15, ложные срабатывания на честной игре владельца, event_id 7255–7257). Было:
//       мс(старт→клиент) > (сейчас − CUser+0x5502) + запас. Но +0x5502 — НЕ такт старта отрезка: MoveSyncProcess
//       (0x5427D0, LABEL_44 0x542F2A..0x542F4F) на КАЖДОМ шаге делает +0x550E += dt и +0x5502 += dt (dt = сейчас − +0x5502),
//       т.е. +0x5502 = такт последнего шага синхронизации (16…78 мс назад), а время отрезка копится в +0x550E. Отсюда
//       «клиент 4434/9624 мс от старта при elapsed 78/16». И сама идея «запас на пакет» дыру не закрывала: сток уже
//       режет опережение > 1000 мс на КАЖДЫЙ 4006 (CharReMove Hack Position), а частыми 4006 опережение копится.
//       Стало: опережение клиента на отрезке по НАКОПЛЕННОМУ ПУТИ —
//         lead = (|старт→клиент| − |старт→серверная текущая|) / скорость − экстраполяция,
//         экстраполяция = min(сейчас − +0x5502, +0x5506 − +0x550E) пока отрезок не пройден (серверная точка стоит
//         с последнего шага синхронизации), скорость — текущая серверная +0x54FE (sub_5588F0: 0.35 + баффы/транспорт,
//         предел 0.66 ед/мс; меняется посреди отрезка с 6071 — поэтому сравниваются РАССТОЯНИЯ, уже пройденные
//         сервером со своими скоростями, а в мс переводится только разница);
//       положительное lead списывается из бюджета сессии (ёмкость BudgetReserveMs, пополнение BudgetRefillPermille ‰
//       реального времени); lead больше остатка → нарушение. Честный клиент (ход по гранту 4007) отстаёт от сервера
//       на задержку ответа → lead ≤ 0; положительное — лишь дрожание сети.
//     ★ p57fix2 (ревизия review_P57_fix.md СРЕДН-1): сервер сам простаивает после КАЖДОГО 4006 в движении — сток пишет
//       +0x5506 = +0x550E = dist (0x545B3C..0x545B8F), следующий шаг MoveSyncProcess (раз в ≥100 мс, ~109) идёт в ветку
//       «отрезок пройден» и начинает новый отрезок БЕЗ движения (+0x5502 := сейчас 0x542EB6, dt := 0 0x542EBC). Этот
//       простой (в среднем ~55 мс на пакет) прежняя формула считала опережением клиента: честные клики ≥ 5/с и WASD с
//       камерой (4/с) давали ложные нарушения. Теперь из lead вычитается простой сервера с прошлого 4006 (Sess::lastMoveTick):
//         отрезок ещё не перезапущен (+0x5506 ≤ +0x550E) — сервер стоит с прошлого пакета: idle = сейчас − lastMoveTick;
//         перезапущен — его такт = +0x5502 − +0x550E (оба копятся += dt): idle = (+0x5502 − +0x550E) − lastMoveTick;
//       idle не больше 250 мс (больше двух шагов синхронизации — не простой перезапуска).
//     ⚠ Допуск по замыслу: пополнение BudgetRefillPermille (250 ‰) = ПОСТОЯННОЕ ускорение до +25 % не ловится (ловится
//       с ~+30 %). Выбрано так, чтобы честный ход при дрожании сети/нагрузке сервера не давал строк ни при какой частоте
//       пакетов; ниже пополнение — раньше ложные на частых кликах. Всплеск сверх пополнения — не больше BudgetReserveMs.
//     Нарушение: Mode=0 — только журнал; Mode=1 — переход в СТОКОВОЕ тело «Hack Position» той же ветки
//     (0x545425 с места / 0x545A6C в движении): лог стока, позиция клиента := серверная, 4007 result=5,
//     остановка, 8105 на NpcServer, return 0 — ничего своего в протокол не добавляем. Стоковые проверки
//     границ, направления и campwar не меняются и идут ДО наших; [p57fix2, ревизия НИЗК-1] стоковый допуск 1000 мс
//     (сравнение 0x545A5F, «CharReMove Hack Position») стоит ПОСЛЕ площадки 0x54531D, т.е. идёт уже после P57.
//  C. 4008 CharStop (MV-1): LABEL_35 (0x546427) пишет позицию из НЕПРОВЕРЕННЫХ полей [5],[9] тела, тогда как
//     допуск 1000 мс и границы карты прошли поля [13],[17]. Стаб перед записью: расхождение > StopFieldTolerance
//     → Mode=0 журнал; Mode=1 — в кадре тела [5],[9] := [13],[17], дальше сток пишет проверенные значения
//     (ответ 4009 и рассылка тоже уходят с проверенными). Порт шлёт [5]==[13], [9]==[17] (FillMoveBody).
//     Гейты состояния sub_52BFF0 / контроля sub_484D20, которых у 4008 нет, — ТОЛЬКО журнал (StopGateJournal):
//     отказ без недели наблюдения запрещён планом §6. [fix13, 2026-10-13] Гейт состояния — ЧТЕНИЕМ поля «мёртв»
//     DWORD CUser+0x4F (код 1 стокового sub_52BFF0 через sub_4CB030 0x4CB05D; опора сверяется при установке), а НЕ
//     вызовом sub_52BFF0: тот на КАЖДОМ вызове, включая код 0, шлёт клиенту 6001 {опкод, код} (push 0x1771 → sub_4C28F0),
//     а сток 4008 его не зовёт — было лишнее 6001 {4008, …} на каждую остановку (у мёртвого/занятого — «отклонено»).
//     sub_484D20 ничего не шлёт (чистые чтения CUser) — зовётся как раньше.
//  Смещения CUser — по дизасму стока (CharMove 0x544EB0 / CharStop 0x545C70, живой e7b4ac38 = сток):
//     0x1C карта (i16), 0x54E4 направление, 0x54E6/0x54E8 клетка, 0x54EE/0x54F2 текущая X/Z, 0x54F6/0x54FA цель,
//     0x54FE скорость (ед/мс), 0x5502 такт последнего шага MoveSyncProcess (при старте отрезка = сейчас, далее
//     += dt на каждом шаге — [p57fix] НЕ такт старта), 0x5506 длительность отрезка мс, 0x550E пройдено мс на отрезке,
//     0x551A/0x551E старт отрезка, 0x5522/0x5526 следующая цель клиента (в движении).
//  Кадры: CharMove this=[ebp-0x484], pUser=[ebp-0x44C], tickNow=[ebp-0x448], тело=[ebp-0x2C], userNum=[ebp+8];
//         CharStop this=[ebp-0x450], pUser=[ebp-0x440], тело=[ebp-0x2C], userNum=[ebp+8].
//  Площадки — 5-байтовые `E8 rel32` целиком и 9 б (две инструкции) на LABEL_35; переходов внутрь нет
//  (tools/verify_p57.py: сток 4e20f0ad, живой/Indun e7b4ac38). С P01…P54 не пересекаются (P53 — те же две
//  площадки лога, но P57 ставит их только если они ещё стоковые).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>
#include <math.h>

namespace
{
    const wchar_t* kSec = L"P57_MoveGuard";

    // [p57fix] Предел длины отрезка 4006. У клиента-оригинала отрезок ничем, кроме карты, не ограничен: клик по земле —
    // прямой отрезок до видимой точки (дальняя плоскость игровой камеры 12 500, 0x958F78), автоход по пути (миникарта,
    // большая карта, маршрут к порталу/NPC, обход при закрытой линии) — прямые отрезки между точками смены направления
    // A* по ВСЕЙ сетке 512×512 (Pathfind_BuildCheckpointRoute@0xFBCE50, pathFindAStar@0xFBC3B0) — до 51 000 по оси и
    // ~72 400 по диагонали. Любой порог ниже диагонали карты ловит честный автоход, поэтому нижняя граница = диагональ
    // сетки 512×512 (72 408) с запасом: проверка срабатывает только на отрезке, которого на карте быть не может.
    constexpr int kStepLenFloor   = 72500;   // ниже — не принимается (честный автоход/дальний клик)
    constexpr int kStepLenDefault = 72500;   // умолчание ключа MaxStepLen

    bool  g_enabled        = true;
    int   g_mode           = 0;       // 0 журнал, 1 отказ/кик
    int   g_kickThreshold  = 30;      // срабатываний Hack Position за окно → кик
    int   g_windowSec      = 600;     // окно счёта
    int   g_kickType       = 6;       // тип Send_DisConnectType (6 = SpeedHack; считает P48)
    int   g_maxStepLen     = kStepLenDefault; // предел отрезка 4006, ед. (0 = не проверять; ниже kStepLenFloor — поднимается)
    int   g_budgetReserve  = 3000;    // [p57fix] ЁМКОСТЬ бюджета опережения, мс (запас на всплеск дрожания сети)
    int   g_budgetRefill   = 250;     // [p57fix] пополнение бюджета, ‰ реального времени (250 = 250 мс за секунду)
    bool  g_checkPassable  = true;    // клетка клиентской позиции (в движении)
    float g_stopTolerance  = 1.0f;    // 4008: допуск расхождения [5],[9] и [13],[17], ед.
    bool  g_stopGateJournal = true;   // 4008: журнал гейтов состояния/контроля
    int   g_journalIntervalSec = 10;  // не чаще одной строки на (сессия, вид)

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);                 // sub_5324A0
    typedef int   (__fastcall *PFN_IsMoving)(void* self, void* edx, int userNum);                // sub_523ED0
    typedef int   (__fastcall *PFN_CtrlGate)(void* skillMgr, void* edx, int userNum);            // sub_484D20
    typedef int   (__fastcall *PFN_TileOk)(void* mapMgr, void* edx, int tx, int tz);             // sub_4221D0 / sub_41A010
    typedef void  (__fastcall *PFN_Disc)(void* self, void* edx, int userNum, int type);          // sub_52EDB0 (thiscall i16,u8)
    typedef void* (__fastcall *PFN_ExcDisc)(void* self, void* edx, int userNum, const char* fn); // sub_526E40
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                       // sub_569DF0

    PFN_GetUser   const pGetUser   = (PFN_GetUser)  Srv::kGetUser;
    PFN_IsMoving  const pIsMoving  = (PFN_IsMoving) 0x00523ED0;
    PFN_CtrlGate  const pCtrlGate  = (PFN_CtrlGate) 0x00484D20;
    PFN_TileOk    const pTileIn    = (PFN_TileOk)   0x004221D0;   // границы карты
    PFN_TileOk    const pTilePass  = (PFN_TileOk)   0x0041A010;   // проходимость (бит 0 клетки)
    PFN_Disc      const pDisc      = (PFN_Disc)     0x0052EDB0;
    PFN_ExcDisc   const pExcDisc   = (PFN_ExcDisc)  0x00526E40;
    PFN_SrvLog    const pSrvLog    = (PFN_SrvLog)   Srv::kLog;

    constexpr int kOffMap      = 0x1C;
    constexpr int kOffUserNumW = 0x0C;
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffName     = 0x178;
    constexpr int kOffSlot     = 0x18C;
    constexpr int kOffCurX = 0x54EE, kOffCurZ = 0x54F2;
    constexpr int kOffSpeed = 0x54FE;
    constexpr int kOffSyncTick = 0x5502;   // такт последнего шага MoveSyncProcess (НЕ старт отрезка — p57fix)
    constexpr int kOffPathMs   = 0x5506;   // длительность отрезка, мс
    constexpr int kOffSegMs    = 0x550E;   // пройдено на отрезке, мс (копится MoveSyncProcess)
    constexpr int kOffStartX = 0x551A, kOffStartZ = 0x551E;

    // Виды журнала (ac.move_combat): 14..20 — P57 (1..5 заняты P53/N13, 6..13 — P56/N14; при интеграции 12.10 сдвинуто с 6..12).
    enum Kind : BYTE { kThreshold = 14, kKick = 15, kStepLen = 16, kBudget = 17, kPassable = 18, kStopFields = 19, kStopGate = 20 };

    struct Sess
    {
        int   userIndex;      // чья сессия (смена → сброс)
        DWORD winStart;       // такт начала окна
        int   count;          // Hack Position в окне
        BYTE  pendingKick;    // 1 — кик на хвосте ветки Hack Position
        DWORD lastJournal[21];// такт последней строки по виду (ограничитель; индекс = вид 14..20)
        int   suppressed[21]; // подавлено ограничителем
        DWORD lastMoveTick;   // [p57fix2] такт прошлого 4006 (CharMove tickNow), дошедшего до P57; 0 — не было
        BYTE  budgetInit;     // [p57fix] бюджет опережения заведён
        int   budget;         // [p57fix] остаток бюджета опережения, мс (0..BudgetReserveMs)
        DWORD budgetTick;     // [p57fix] такт последнего пополнения
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_hits = 0, g_kicks = 0, g_viol = 0;   // для стенда / лога

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    // Сессия слота: другая учётка в слоте = новая сессия — счёт, окно и ограничители начинаются заново.
    Sess& SessOf(int userNum, const BYTE* user)
    {
        Sess& s = g_sess[userNum];
        const int userIndex = *(const int*)(user + kOffUserIndex);
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        return s;
    }

    // Ограничитель: true — писать; иначе копим suppressed.
    bool Allow(Sess& s, int kind, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.lastJournal[kind] && now - s.lastJournal[kind] < (DWORD)g_journalIntervalSec * 1000) { ++s.suppressed[kind]; return false; }
        s.lastJournal[kind] = now;
        return true;
    }

    void Journal(BYTE kind, const BYTE* user, int userNum, int opcode, __int64 w0, __int64 w1, int v1, int v2, int v3, int v4, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = P47_PeerIpv4(userNum);
        e.suppressed = suppressed;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIndex);
                e.charSlot  = user[kOffSlot];
                e.v[0]      = *(const short*)(user + kOffMap);
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.w[0] = w0; e.w[1] = w1; e.v[1] = v1; e.v[2] = v2; e.v[3] = v3; e.v[4] = v4;
        AcJournal::Push(e);
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }

    float Dist(float x0, float z0, float x1, float z1)
    {
        const float dx = x1 - x0, dz = z1 - z0;
        return sqrtf(dx * dx + dz * dz);
    }
}

// ── A. событие «Hack Position» (из P53 или своих площадок). kind 1 = CharMove, 2 = CharReMove ──
extern "C" void __stdcall P57_OnHackPosition(int kind, void* mgr, BYTE* user)
{
    if (!g_enabled || !user || !mgr) { return; }
    __try
    {
        InterlockedIncrement(&g_hits);
        const int userNum = *(const short*)(user + kOffUserNumW);
        if (!SessOk(userNum)) { return; }
        const int userIndex = *(const int*)(user + kOffUserIndex);
        const DWORD now = GetTickCount();
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = SessOf(userNum, user);
        if (s.winStart == 0 || now - s.winStart > (DWORD)g_windowSec * 1000)
        {
            s.winStart = now; s.count = 0; s.pendingKick = 0;
        }
        const int count = ++s.count;
        const DWORD winStart = s.winStart;
        bool fire = false;
        if (count == g_kickThreshold || (count > g_kickThreshold && (count - g_kickThreshold) % g_kickThreshold == 0))
        {
            fire = true;
            if (g_mode == 1) { s.pendingKick = 1; }
        }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        if (!fire) { return; }
        if (g_mode == 1)
        {
            // Кик — на хвосте ветки (P57_AfterHackBody), здесь только отметка.
            pSrvLog(0, "P57 MoveGuard: %s Hack Position %d/%d in %d s, UserNum %d, UserIndex %d -> kick pending (type %d)",
                    kind == 1 ? "CharMove" : "CharReMove", count, g_kickThreshold, g_windowSec, userNum, userIndex, g_kickType);
        }
        else
        {
            pSrvLog(0, "P57 MoveGuard: %s Hack Position %d/%d in %d s, UserNum %d, UserIndex %d, %s -> JOURNAL ONLY (Mode=0)",
                    kind == 1 ? "CharMove" : "CharReMove", count, g_kickThreshold, g_windowSec, userNum, userIndex, NameOf(user));
            Journal(kThreshold, user, userNum, 4006, winStart, now, (int)(now - winStart), count, g_kickThreshold, g_windowSec, 0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Хвост стоковой ветки Hack Position (после sub_4C58F0 на LABEL_41): выполнить отложенный кик.
extern "C" void __stdcall P57_AfterHackBody(BYTE* ebp)
{
    if (!g_enabled || g_mode != 1) { return; }
    __try
    {
        void* mgr = *(void**)(ebp - 0x484);
        BYTE* user = *(BYTE**)(ebp - 0x44C);
        const int userNum = *(const short*)(ebp + 8);
        if (!mgr || !user || !SessOk(userNum)) { return; }
        Sess& s = g_sess[userNum];
        if (!s.pendingKick) { return; }
        int count, userIndex; DWORD winStart;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        s.pendingKick = 0; count = s.count; userIndex = s.userIndex; winStart = s.winStart;
        s.count = 0; s.winStart = 0;   // новое окно после кика
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        const DWORD now = GetTickCount();
        InterlockedIncrement(&g_kicks);
        pSrvLog(0, "P57 MoveGuard: KICK UserNum %d, UserIndex %d, %s: Hack Position %d/%d in %d s (type %d)",
                userNum, userIndex, NameOf(user), count, g_kickThreshold, g_windowSec, g_kickType);
        Log::Line(L"[P57] кик: userNum %d, UserIndex %d — Hack Position %d/%d за %d с (тип %d)", userNum, userIndex, count, g_kickThreshold, g_windowSec, g_kickType);
        Journal(kKick, user, userNum, 4006, winStart, now, (int)(now - winStart), count, g_kickThreshold, g_kickType, 0);
        pDisc(mgr, nullptr, (short)userNum, g_kickType);                                   // 4101 + Sleep(50) (считает P48)
        pExcDisc(mgr, nullptr, (short)userNum, "P57 MoveGuard: Hack Position threshold");  // ___ExceptionDisConnetUser___ + разрыв
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log::Line(L"[P57] ! исключение при кике — пропущен");
    }
}

// [p57fix2, ревизия НИЗК-3] Sess в OnMove4006/OnStop4008 меняется без g_lock: игрок привязан к одной нити карты
//   (SetUserInfo_ThreadID_Mapping), его 4006/4008 и MoveSyncProcess идут в этой нити, общих данных между нитями нет.
// ── B. 4006 после стоковой campwar-проверки. Возврат: 0 пропуск, 1 → тело CharMove Hack, 2 → тело CharReMove Hack ──
extern "C" int __stdcall P57_OnMove4006(BYTE* ebp)
{
    if (!g_enabled) { return 0; }
    int verdict = 0;
    __try
    {
        void* mgr = *(void**)(ebp - 0x484);
        BYTE* user = *(BYTE**)(ebp - 0x44C);
        const DWORD tickNow = *(const DWORD*)(ebp - 0x448);
        const BYTE* body = ebp - 0x2C;
        const int userNum = *(const short*)(ebp + 8);
        if (!mgr || !user || !SessOk(userNum)) { return 0; }
        const bool moving = pIsMoving(mgr, nullptr, (short)userNum) != 0;
        const float cx = *(const float*)(body + 5),  cz = *(const float*)(body + 9);
        const float dx = *(const float*)(body + 13), dz = *(const float*)(body + 17);
        Sess& s = SessOf(userNum, user);
        bool viol = false;

        // 1) длина отрезка
        if (g_maxStepLen > 0)
        {
            const float len = Dist(cx, cz, dx, dz);
            if (len > (float)g_maxStepLen)
            {
                viol = true;
                const bool w = Allow(s, kStepLen, tickNow);
                if (w)
                {
                    pSrvLog(0, "P57 MoveGuard: 4006 step %.0f > MaxStepLen %d, %s UserNum %d (%.0f,%.0f)->(%.0f,%.0f) moving %d%s",
                            len, g_maxStepLen, NameOf(user), userNum, cx, cz, dx, dz, moving ? 1 : 0, g_mode ? " -> REFUSE" : " (journal)");
                    Journal(kStepLen, user, userNum, 4006, AcJournal::kNone, tickNow, moving ? 1 : 0, 0, (int)len, g_maxStepLen, s.suppressed[kStepLen]);
                    s.suppressed[kStepLen] = 0;
                }
            }
        }
        if (moving)
        {
            // 2) [p57fix] накопленный бюджет хода: опережение клиента на отрезке по накопленному пути (шапка «p57fix»)
            const float speed    = *(const float*)(user + kOffSpeed);
            const DWORD syncTick = *(const DWORD*)(user + kOffSyncTick);
            const DWORD pathMs   = *(const DWORD*)(user + kOffPathMs);
            const DWORD segMs    = *(const DWORD*)(user + kOffSegMs);
            const float sx = *(const float*)(user + kOffStartX), sz = *(const float*)(user + kOffStartZ);
            const float px = *(const float*)(user + kOffCurX),   pz = *(const float*)(user + kOffCurZ);
            if (speed > 0.001f && syncTick != 0)
            {
                // с последнего шага синхронизации серверная точка стоит: добавляем пройденное за это время,
                // но не дальше конца отрезка (отрезок пройден — сервер ждёт следующую цель)
                const DWORD sinceSync = (int)(tickNow - syncTick) > 0 ? tickNow - syncTick : 0;
                const DWORD remainMs  = pathMs > segMs ? pathMs - segMs : 0;
                const DWORD extraMs   = sinceSync < remainMs ? sinceSync : remainMs;
                const float dCli  = Dist(sx, sz, cx, cz);
                const float dServ = Dist(sx, sz, px, pz);
                const int msClient = (int)(dCli / speed);
                const int msServer = (int)(dServ / speed) + (int)extraMs;
                // [p57fix2] простой сервера на перезапуске отрезка после прошлого 4006 (шапка «p57fix2»)
                DWORD idleMs = 0;
                if (s.lastMoveTick != 0)
                {
                    const DWORD from = pathMs <= segMs ? tickNow : syncTick - segMs;   // не перезапущен — стоит до сих пор
                    const int d = (int)(from - s.lastMoveTick);
                    idleMs = d > 0 ? (DWORD)d : 0;
                    if (idleMs > 250) { idleMs = 250; }
                }
                const int lead     = (int)((dCli - dServ) / speed) - (int)extraMs - (int)idleMs;
                // пополнение бюджета сессии
                if (!s.budgetInit) { s.budgetInit = 1; s.budget = g_budgetReserve; s.budgetTick = tickNow; }
                else
                {
                    const DWORD dt = (int)(tickNow - s.budgetTick) > 0 ? tickNow - s.budgetTick : 0;
                    const __int64 add = (__int64)dt * g_budgetRefill / 1000;
                    s.budget = (int)((__int64)s.budget + add > g_budgetReserve ? g_budgetReserve : (__int64)s.budget + add);
                    s.budgetTick = tickNow;
                }
                if (lead > 0)
                {
                    const int before = s.budget;
                    if (lead > before)
                    {
                        s.budget = 0;
                        viol = true;
                        if (Allow(s, kBudget, tickNow))
                        {
                            pSrvLog(0, "P57 MoveGuard: 4006 client %d ms from segment start, server %d ms: lead %d > budget %d ms, %s UserNum %d%s",
                                    msClient, msServer, lead, before, NameOf(user), userNum, g_mode ? " -> REFUSE" : " (journal)");
                            Journal(kBudget, user, userNum, 4006, (__int64)(DWORD)(tickNow - (DWORD)msServer), tickNow,
                                    msServer, lead, msClient, before, s.suppressed[kBudget]);
                            s.suppressed[kBudget] = 0;
                        }
                    }
                    else { s.budget = before - lead; }
                }
            }
            // 3) клетка клиентской позиции
            if (g_checkPassable)
            {
                void* mapMgr = *(void**)(*(BYTE**)((BYTE*)mgr + 4) + 12);
                const int tx = (int)(cx / 100.0f), tz = (int)(cz / 100.0f);
                const bool inMap = tx > 0 && tz > 0 && pTileIn(mapMgr, nullptr, tx, tz) != 0;
                const bool pass  = inMap && pTilePass(mapMgr, nullptr, tx, tz) != 0;
                if (!pass)
                {
                    viol = true;
                    if (Allow(s, kPassable, tickNow))
                    {
                        pSrvLog(0, "P57 MoveGuard: 4006 client tile %d,%d %s, %s UserNum %d%s",
                                tx, tz, inMap ? "not passable" : "out of map", NameOf(user), userNum, g_mode ? " -> REFUSE" : " (journal)");
                        Journal(kPassable, user, userNum, 4006, AcJournal::kNone, tickNow, inMap ? 1 : 0, 0, tx, tz, s.suppressed[kPassable]);
                        s.suppressed[kPassable] = 0;
                    }
                }
            }
        }
        s.lastMoveTick = tickNow;   // [p57fix2] и с места, и в движении
        if (viol) { InterlockedIncrement(&g_viol); }
        if (viol && g_mode == 1) { verdict = moving ? 2 : 1; }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── C. 4008 перед LABEL_35: позиция из проверенных полей; гейты — журнал ──
extern "C" void __stdcall P57_OnStop4008(BYTE* ebp)
{
    if (!g_enabled) { return; }
    __try
    {
        void* mgr = *(void**)(ebp - 0x450);
        BYTE* user = *(BYTE**)(ebp - 0x440);
        BYTE* body = ebp - 0x2C;
        const int userNum = *(const short*)(ebp + 8);
        if (!mgr || !user || !SessOk(userNum)) { return; }
        const DWORD now = GetTickCount();
        Sess& s = SessOf(userNum, user);
        float* p5  = (float*)(body + 5);  float* p9  = (float*)(body + 9);
        const float f13 = *(const float*)(body + 13), f17 = *(const float*)(body + 17);
        const float ddx = fabsf(*p5 - f13), ddz = fabsf(*p9 - f17);
        if (ddx > g_stopTolerance || ddz > g_stopTolerance)
        {
            InterlockedIncrement(&g_viol);
            if (Allow(s, kStopFields, now))
            {
                pSrvLog(0, "P57 MoveGuard: 4008 pos fields (%.0f,%.0f) != checked (%.0f,%.0f), %s UserNum %d%s",
                        *p5, *p9, f13, f17, NameOf(user), userNum, g_mode ? " -> checked fields used" : " (journal)");
                Journal(kStopFields, user, userNum, 4008, AcJournal::kNone, now, g_mode, 0, (int)ddx, (int)ddz, s.suppressed[kStopFields]);
                s.suppressed[kStopFields] = 0;
            }
            if (g_mode == 1) { *p5 = f13; *p9 = f17; }   // сток дальше пишет проверенные значения
        }
        if (g_stopGateJournal)
        {
            int gate = 0;
            // код 1 стокового sub_52BFF0 = «мёртв» (DWORD +0x4F); сама функция не зовётся — она шлёт 6001 (см. шапку C)
            const BYTE* gu = pGetUser(mgr, nullptr, (short)userNum);
            if (gu && *(const int*)(gu + Srv::kOffDeadFlag) != 0) { gate = 1; }
            else
            {
                void* skillMgr = *(void**)(*(BYTE**)((BYTE*)mgr + 4) + 44);
                if (skillMgr && pCtrlGate(skillMgr, nullptr, (short)userNum)) { gate = 2; }
            }
            if (gate && Allow(s, kStopGate, now))
            {
                pSrvLog(0, "P57 MoveGuard: 4008 under %s gate (journal only), %s UserNum %d",
                        gate == 1 ? "state (sub_52BFF0)" : "control (sub_484D20)", NameOf(user), userNum);
                Journal(kStopGate, user, userNum, 4008, AcJournal::kNone, now, 0, 0, gate, 0, s.suppressed[kStopGate]);
                s.suppressed[kStopGate] = 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

extern "C" void __stdcall P57_GetStats(int* hits, int* kicks, int* viol)
{
    if (hits) { *hits = g_hits; } if (kicks) { *kicks = g_kicks; } if (viol) { *viol = g_viol; }
}

namespace
{
    DWORD g_p55FF20     = 0x0055FF20;   // стоковая цель площадки B
    DWORD g_p4C58F0     = 0x004C58F0;   // стоковая цель площадок A (LABEL_41)
    DWORD g_pSrvLog     = 0x00569DF0;   // стоковая цель площадок лога (если ставим сами)
    DWORD g_hackMove    = 0x00545425;   // тело «CharMove Hack Position»
    DWORD g_hackReMove  = 0x00545A6C;   // тело «CharReMove Hack Position»
    DWORD g_retStop     = 0x00546430;   // после вытесненных `mov eax,[ebp-440h]; fld [ebp-27h]`

    // B. вместо `call sub_55FF20` (thiscall: ecx = CUserMoveManager, [esp+4] userNum, [esp+8] posDst, ret 8).
    __declspec(naked) void St_Move4006()
    {
        __asm
        {
            push  dword ptr [esp+8]            // posDst
            push  dword ptr [esp+8]            // userNum
            call  dword ptr [g_p55FF20]        // сток (снимает 8 б)
            cmp   al, 1
            jne   done                         // сток отказал — его результат
            pushad
            push  ebp
            call  P57_OnMove4006               // __stdcall(ebp) → eax
            mov   dword ptr [esp+28], eax      // в сохранённый eax
            popad
            test  eax, eax
            jz    pass
            add   esp, 12                      // адрес возврата + 2 аргумента стока
            cmp   eax, 2
            je    remove_
            jmp   dword ptr [g_hackMove]
        remove_:
            jmp   dword ptr [g_hackReMove]
        pass:
            mov   al, 1
        done:
            ret   8
        }
    }

    // A. вместо `call sub_4C58F0` на LABEL_41 (thiscall, 4 аргумента, ret 10h): сток, затем отложенный кик.
    __declspec(naked) void St_AfterHack()
    {
        __asm
        {
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            push  dword ptr [esp+16]
            call  dword ptr [g_p4C58F0]
            pushad
            push  ebp
            call  P57_AfterHackBody
            popad
            ret   0x10
        }
    }

    // C. LABEL_35 CharStop: вытеснены `mov eax,[ebp-440h]` (6 б) и `fld dword ptr [ebp-27h]` (3 б).
    __declspec(naked) void St_Stop4008()
    {
        __asm
        {
            pushad
            push  ebp
            call  P57_OnStop4008
            popad
            mov   eax, dword ptr [ebp-0x440]
            fld   dword ptr [ebp-0x27]
            jmp   dword ptr [g_retStop]
        }
    }

    // Свои площадки лога (только если P53 их не занял): как у P53 — [esp] вид, [esp+4] возврат, [esp+8…] аргументы.
    __declspec(naked) void LogTail()
    {
        __asm
        {
            pushad
            mov   eax, dword ptr [esp+48]      // 3-й аргумент писателя = имя персонажа (CUser+0x178)
            test  eax, eax
            jz    skip
            sub   eax, 0x178
            push  eax                          // user
            push  ecx                          // mgr (ecx вызывающего = CUserManager)
            push  dword ptr [esp+40]           // вид
            call  P57_OnHackPosition
        skip:
            popad
            add   esp, 4
            jmp   dword ptr [g_pSrvLog]
        }
    }
    __declspec(naked) void St_LogMove()   { __asm { push 1 } __asm { jmp LogTail } }
    __declspec(naked) void St_LogReMove() { __asm { push 2 } __asm { jmp LogTail } }

    const BYTE kOrigMove4006[5] = { 0xE8, 0xFE, 0xAB, 0x01, 0x00 };   // 0x54531D call 0x55FF20
    const BYTE kOrigAfter1[5]   = { 0xE8, 0x0D, 0x04, 0xF8, 0xFF };   // 0x5454DE call 0x4C58F0
    const BYTE kOrigAfter2[5]   = { 0xE8, 0xC6, 0xFD, 0xF7, 0xFF };   // 0x545B25 call 0x4C58F0
    const BYTE kOrigStop[9]     = { 0x8B, 0x85, 0xC0, 0xFB, 0xFF, 0xFF, 0xD9, 0x45, 0xD9 };   // 0x546427
    const BYTE kOrigLogMove[5]  = { 0xE8, 0xAE, 0x49, 0x02, 0x00 };   // 0x54543D call 0x569DF0
    const BYTE kOrigLogReMove[5]= { 0xE8, 0x67, 0x43, 0x02, 0x00 };   // 0x545A84 call 0x569DF0
    // Соседи, на которые опираются переходы стабов.
    const BYTE kNbHackMove[4]   = { 0x66, 0x8B, 0x55, 0x08 };         // 0x545425 mov dx,[ebp+8]
    const BYTE kNbHackReMove[4] = { 0x66, 0x8B, 0x45, 0x08 };         // 0x545A6C mov ax,[ebp+8]
    const BYTE kNbRetStop[6]    = { 0xD9, 0x98, 0xEE, 0x54, 0x00, 0x00 };   // 0x546430 fstp [eax+54EEh]
    const BYTE kRefDead[3]      = { 0x8B, 0x51, 0x4F };                     // 0x4CB05D mov edx,[ecx+4Fh] (sub_4CB030, код 1 sub_52BFF0)
    // [p57fix] опоры бюджета хода: LABEL_44 MoveSyncProcess копит время отрезка в +0x550E и сдвигает такт шага +0x5502.
    const BYTE kRefSegAcc[6]    = { 0x89, 0x90, 0x0E, 0x55, 0x00, 0x00 };   // 0x542F34 mov [eax+550Eh],edx
    const BYTE kRefSyncAcc[6]   = { 0x89, 0x90, 0x02, 0x55, 0x00, 0x00 };   // 0x542F49 mov [eax+5502h],edx
}

PatchResult P57_MoveGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode           = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_kickThreshold  = Config::GetInt(kSec, L"HackPosKickThreshold", 30);
    g_windowSec      = Config::GetInt(kSec, L"HackPosWindowSec", 600);
    g_kickType       = Config::GetInt(kSec, L"KickType", 6);
    g_maxStepLen     = Config::GetInt(kSec, L"MaxStepLen", kStepLenDefault);
    g_budgetReserve  = Config::GetInt(kSec, L"BudgetReserveMs", 3000);
    g_budgetRefill   = Config::GetInt(kSec, L"BudgetRefillPermille", 250);
    g_checkPassable  = Config::GetBool(kSec, L"CheckPassable", true);
    g_stopTolerance  = (float)Config::GetInt(kSec, L"StopFieldTolerance", 1);
    g_stopGateJournal = Config::GetBool(kSec, L"StopGateJournal", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_kickThreshold < 2) { g_kickThreshold = 2; }
    if (g_windowSec < 1) { g_windowSec = 1; }
    if (g_kickType < 0 || g_kickType > 15) { g_kickType = 6; }
    if (g_budgetReserve < 0) { g_budgetReserve = 0; }
    if (g_budgetRefill < 0) { g_budgetRefill = 0; }
    if (g_budgetRefill > 1000) { g_budgetRefill = 1000; }
    // [p57fix] ниже честного дальнего клика порог не опускается (0 = выкл. — как было)
    const int stepLenIni = g_maxStepLen;
    if (g_maxStepLen > 0 && g_maxStepLen < kStepLenFloor)
    {
        g_maxStepLen = kStepLenFloor;
        Log::Line(L"    P57: MaxStepLen=%d ниже диагонали карты (честный автоход/дальний клик) — поднят до %d (move-guard-p57.md «p57fix»)", stepLenIni, kStepLenFloor);
    }
    if (g_stopTolerance < 0.0f) { g_stopTolerance = 0.0f; }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    const Site sites[] =
    {
        { 0x0054531D, kOrigMove4006, sizeof(kOrigMove4006) },
        { 0x005454DE, kOrigAfter1,   sizeof(kOrigAfter1)   },
        { 0x00545B25, kOrigAfter2,   sizeof(kOrigAfter2)   },
        { 0x00546427, kOrigStop,     sizeof(kOrigStop)     },
        { 0x00545425, kNbHackMove,   sizeof(kNbHackMove)   },
        { 0x00545A6C, kNbHackReMove, sizeof(kNbHackReMove) },
        { 0x00546430, kNbRetStop,    sizeof(kNbRetStop)    },
        { 0x004CB05D, kRefDead,      sizeof(kRefDead)      },   // [fix13] поле «мёртв» для журнала гейта 4008
        { 0x00542F34, kRefSegAcc,    sizeof(kRefSegAcc)    },   // [p57fix] MoveSyncProcess: +0x550E += dt
        { 0x00542F49, kRefSyncAcc,   sizeof(kRefSyncAcc)   },   // [p57fix] MoveSyncProcess: +0x5502 += dt (такт шага, не старт)
    };
    if (!VerifyAllSites(L"P57", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    // Площадки лога: ставим сами только если они ещё стоковые (P53 ставит свои раньше по реестру и зовёт нас).
    const bool logMoveStock   = Hook::Verify(0x0054543D, kOrigLogMove,   sizeof(kOrigLogMove));
    const bool logReMoveStock = Hook::Verify(0x00545A84, kOrigLogReMove, sizeof(kOrigLogReMove));
    if (logMoveStock != logReMoveStock)
    {
        Log::Line(L"    P57: ! площадки лога Hack Position в разном состоянии (0x54543D сток=%d, 0x545A84 сток=%d) — не ставлю",
                  logMoveStock ? 1 : 0, logReMoveStock ? 1 : 0);
        return PatchResult::Mismatch;
    }

    if (!Hook::WriteCall(0x0054531D, &St_Move4006, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x005454DE, &St_AfterHack, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteCall(0x00545B25, &St_AfterHack, 5)) { return PatchResult::Failed; }
    if (!Hook::WriteJmp (0x00546427, &St_Stop4008, 9))  { return PatchResult::Failed; }
    if (logMoveStock)
    {
        if (!Hook::WriteCall(0x0054543D, &St_LogMove, 5))   { return PatchResult::Failed; }
        if (!Hook::WriteCall(0x00545A84, &St_LogReMove, 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    P57: режим %s; Hack Position: порог %d за %d с → %s; 4006: MaxStepLen %d, бюджет хода %d мс (+%d‰), клетка=%d; "
              L"4008: допуск полей %d, гейты журнал=%d; строки не чаще 1/%d с; площадки лога %s",
              g_mode ? L"ОТКАЗ/КИК" : L"ЖУРНАЛ", g_kickThreshold, g_windowSec,
              g_mode ? L"кик (тип задан KickType)" : L"журнал", g_maxStepLen, g_budgetReserve, g_budgetRefill, g_checkPassable ? 1 : 0,
              (int)g_stopTolerance, g_stopGateJournal ? 1 : 0, g_journalIntervalSec,
              logMoveStock ? L"СВОИ (P53 их не ставил)" : L"P53 (зовёт P57)");
    return PatchResult::Applied;
}
