// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P55 — ★ ОБЩИЙ ВАЛИДАТОР КЛИЕНТСКИХ ПАКЕТОВ (античит, волна В4, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Мера 8 плана `Reports/anticheat/00_PLAN.md` (§4 В4, §8.2 L1);
//  анализ `01_network_protocol.md` §4 (реализуемость общего слоя), F7/F8.
//  Отчёт: `Reports/anticheat/wave_A4_validator.md`; документ: `AstoryServer/Docs/GameServer/packet-validator-p55.md`.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  • Рамка приёма (CopyToWriteBuffer@0x5656D0) проверяет только 0xFB / size ∈ [1..700] / 0xFE; заявленный размер
//    кадра с ожидаемым для опкода почти нигде не сверяется (явно — только аукцион sub_5218A0 и чат). Обработчики
//    копируют ФИКСИРОВАННЫЕ длины из 4096-байтового слота: короткий кадр даёт нули, длинный — лишний хвост
//    молча игнорируется. Нет и лимита частоты на сессию: диспетчер sub_42A9D0 считает пакеты только глобально
//    по опкоду (0x5A79C0), сессионных счётчиков частоты нет.
//
//  ── ЧЕМ ЛЕЧИМ (без новых площадок в .text) ──
//  Гейт зовётся ПЕРВЫМ в C-функции гейта P47 (P47_OperatorGate, площадка 0x42AB4F — запись опкода в кадр
//  диспетчера, ветка userNum < 10000, т. е. только клиентские пакеты) с теми же аргументами
//  (CUserManager, опкод, userNum, кадр). Отказ = обработчик не вызывается (выход стаба P47 в общий хвост
//  switch 0x42F036, как у P01/P47) — протокол клиента не меняется.
//  1. ДЛИНА КАДРА (CheckLength). WORD size = кадр+1 — весь кадр (с 0xFB и 0xFE: GetReadBuffer@0x42A6B0
//     проверяет `pkt[size-1] == 0xFE`). Таблица OpcodeLengths.h (генератор tools/gen_opcode_lengths.py из
//     декомпила): minSize = 9 заголовок + 8 секрет (если есть) + 16 MD5 + LEN (аргумент sub_523F00@0x523F00:
//     при a5=1 MD5 с +17, тело с +33; при a5=0 MD5 с +9, тело с +25) + 1 хвост; maxSize = minSize + 19
//     (паддинг клиента CNetwork_Send a6=1: (+11)%20) или 0 = верх не проверять (чат и переменные формы).
//     Опкод без записи в таблице — длина НЕ проверяется (только общее правило «кадр не короче 10 б =
//     заголовок 9 + хвост»). ★ 5450: LEN 0x101 (клиент), не стоковые 0x89 — см. P49.
//  2. ЧАСТОТА (CheckRate). Token-bucket на (userNum, класс опкода): классы движение / бой-навыки / чат /
//     предметы-торговля / тяжёлые-БД / GM / прочее (класс — в той же таблице). Пороги — ключи ini
//     Rate<Класс>PerSec (пополнение) и Rate<Класс>Burst (запас); умолчания щедрые, 0 = класс без лимита.
//     Массив per-userNum, O(1) на пакет, без аллокаций и блокировок (слот userNum обслуживает один поток карты).
//  3. РЕЖИМ (Mode). 0 = ТОЛЬКО ЖУРНАЛ (умолчание; план §6: «не включать отказы без недели наблюдения»):
//     обработчик вызывается как в стоке, нарушение — в журнал. 1 = ОТКАЗ: обработчик не вызывается и
//     (HackPacketOnRefuse=1) +1 к штатному счётчику «Hack Packet» sub_524540@0x524540 (CUser+0x22) →
//     штатный кик CheckDisConnectUser@0x526C20 при > 5 (sub_524580), тип 3. Иначе — тихий сброс.
//  4. ЖУРНАЛ. Не на каждый пакет — только нарушения, с ограничителем на (userNum, вид): одна строка в
//     JournalIntervalSec (60 с), подавленные считаются и печатаются в следующей (repeat_suppressed).
//     (LogHits). Неизвестные опкоды (default диспетчера) НЕ дублируются: их пишет P53 (ac.other, вид 3,
//     площадка 0x42F031); здесь они только считаются в статистике.
//
//  ── ЗАВИСИМОСТИ ──
//  Стаб гейта ставит P47 (ключ [P47] Enabled=1; P47 ставит его и при OperatorGmFlag=0, если P55 включён —
//  общая точка P55_GateWanted). P53 — журнал (выключен → только PatchLog). Площадок своих нет: байты
//  площадки 0x42AB4F сверяет P47 (8B45FC 0FB74807 898D38EFFFFF, одинаковы в стоке 4e20f0ad и живых e7b4ac38).
//  ★ sec2 (2026-10-15): доля нарушений P55 1/2/4 в штатных счётчиках кика (Secret/MD5/NotKnow/Hack) — по приросту между пакетами
//  слота; P48 по ней не засчитывает кик за поддельный/битый пакет (наказывает только P69). Экспорт P55_GetKickStats/P55_TestKickAttr.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include "../OpcodeLengths.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P55_PacketValidator";

    // ── настройки (patches.ini) ─────────────────────────────────────────────
    volatile LONG g_enabled   = 0;     // патч установлен и включён (гейт работает)
    int  g_mode        = 0;            // 0 — только журнал, 1 — отказ
    bool g_checkLen    = true;         // проверка длины кадра
    bool g_checkRate   = true;         // лимит частоты по классам
    bool g_hackOnRefuse= true;         // в режиме отказа: +1 к штатному счётчику Hack Packet
    bool g_logHits     = true;         // строки в PatchLog (с ограничителем)
    int  g_journalSec  = 60;           // ограничитель журнала: одна строка на (userNum, вид) за столько секунд
    int  g_perSec[OpLen::kClassCount] = { 60, 60, 40, 10, 30, 10, 30 };   // пополнение, пакетов/с (0 = без лимита)
    int  g_burst [OpLen::kClassCount] = { 120, 120, 80, 20, 60, 20, 60 };  // запас (ёмкость ведра), пакетов

    struct RateKey { const wchar_t* perSec; const wchar_t* burst; };
    const RateKey kRateKeys[OpLen::kClassCount] =
    {
        { L"RateOtherPerSec",  L"RateOtherBurst"  },
        { L"RateMovePerSec",   L"RateMoveBurst"   },
        { L"RateCombatPerSec", L"RateCombatBurst" },
        { L"RateChatPerSec",   L"RateChatBurst"   },
        { L"RateItemPerSec",   L"RateItemBurst"   },
        { L"RateDbPerSec",     L"RateDbBurst"     },
        { L"RateGmPerSec",     L"RateGmBurst"     },
    };

    // ── функции GameServer (соглашения — как у стоковых вызовов) ─────────────
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);    // sub_5324A0
    typedef void* (__fastcall *PFN_HackCount)(void* self, void* edx, int userNum);  // sub_524540: ++CUser+0x22
    PFN_GetUser   const pGetUser   = (PFN_GetUser)  Srv::kGetUser;    // 0x5324A0
    PFN_HackCount const pHackCount = (PFN_HackCount)0x00524540;

    constexpr int kSlots     = 0x226;   // userNum 0…549 (sub_5328F0)
    constexpr int kMinFrame  = 10;      // заголовок 9 + хвост 0xFE
    constexpr int kOffUserIndex = 0x174;
    constexpr int kOffSlot      = 0x18C;
    constexpr DWORD kGateSite   = 0x0042AB4F;   // площадка стаба P47 (должен стоять jmp)

    // ── token-bucket на (userNum, класс) ─────────────────────────────────────
    //   tokens — в тысячных долях пакета (пополнение perSec за 1000 мс = perSec·dt милли-жетонов за dt мс).
    struct Bucket { LONG tokens; DWORD lastTick; DWORD secStart; LONG secCount; };
    Bucket g_bucket[kSlots][OpLen::kClassCount] = {};

    // ── ограничитель журнала на (userNum, вид 1..4) ──────────────────────────
    struct JLimit { DWORD lastTick; LONG suppressed; BYTE used; };
    JLimit g_jlimit[kSlots][5] = {};

    // ── статистика ───────────────────────────────────────────────────────────
    P55_Stats g_stats = {};

    CRITICAL_SECTION g_logLock;
    bool g_logLockReady = false;

    // true — печатать/писать (и *suppressedOut = сколько подавлено с прошлой строки); false — подавить.
    bool JournalAllow(int userNum, int kind, LONG* suppressedOut)
    {
        *suppressedOut = 0;
        if (kind < 1 || kind > 4) { return true; }
        JLimit& j = g_jlimit[userNum][kind];
        const DWORD now = GetTickCount();
        if (j.used && g_journalSec > 0 && (DWORD)(now - j.lastTick) < (DWORD)g_journalSec * 1000u)
        {
            InterlockedIncrement(&j.suppressed);
            InterlockedIncrement(&g_stats.suppressed);
            return false;
        }
        *suppressedOut = j.used ? InterlockedExchange(&j.suppressed, 0) : 0;
        j.used = 1; j.lastTick = now;
        return true;
    }

    // Одно нарушение → журнал P53 (ac.packet_validator) + строка PatchLog (под ограничителем).
    void Report(void* mgr, int userNum, int opcode, int kind, const OpLen::Info* info, int size, int cls,
                int secCount, int action)
    {
        LONG suppressed = 0;
        if (!JournalAllow(userNum, kind, &suppressed)) { return; }
        InterlockedIncrement(&g_stats.journaled);

        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kPacketValidator, (BYTE)kind);
        e.userNum = (short)userNum;
        e.opcode  = opcode;
        // ★ autoban (P69, 2026-10-14): адрес — живой getpeername, при отказе (клиент уже сбросил соединение) — IP этого
        //   соединения из кэша P69 (заполняет P61 на первом приёме, сбрасывает на accept/разрыве; без P61 кэша нет).
        e.ip      = P69_SlotIp(userNum);
        // ★ autoban: user_index — только ПОДТВЕРЖДЁННАЯ учётка СЕССИИ (сессия в мире; вход соулмейтом — iMateUserIndex, как P48).
        //   До входа в мир CUser+0x174 — номер, ЗАЯВЛЕННЫЙ клиентом в 20000: прежде он писался в user_index и попадал в
        //   v_top_offenders/v_account_daily чужой учётке. Теперь он в char_owner_user_index (v[9]), состояние — session_state (v[8]).
        P69_Session ss;
        P69_ResolveSession(mgr, userNum, &ss);
        e.userIndex = ss.account > 0 ? ss.account : AcJournal::kNone;
        e.charSlot  = ss.charSlot >= 0 ? ss.charSlot : AcJournal::kNone;
        if (ss.user)
        {
            __try { AcJournal::CopyName(e, ss.user + Srv::kOffCharName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = size;
        e.v[1] = info->opcode ? info->minSize : kMinFrame;
        e.v[2] = info->opcode ? (info->maxSize ? info->maxSize : AcJournal::kNone) : AcJournal::kNone;
        e.v[3] = cls;
        e.v[4] = g_perSec[cls];
        e.v[5] = g_burst[cls];
        e.v[6] = secCount;
        e.v[7] = action;
        e.v[8] = ss.state >= 0 ? ss.state : AcJournal::kNone;   // ★ autoban: session_state
        e.v[9] = ss.owner > 0 ? ss.owner : AcJournal::kNone;    // ★ autoban: char_owner_user_index (CUser+0x174)
        if (info->handler) { AcJournal::CopyText(e, info->handler); }
        e.suppressed = (int)suppressed;
        AcJournal::Push(e);
        // ★ autoban (P69): счёт нарушения целостности учётке — ровно одно на строку журнала (тот же ограничитель на (сессия, вид):
        //   подавленные повторы не добавляют счёт — иначе один битый клиент набрал бы 51 за секунду). Виды — CountP55Kinds (1,2,4).
        P69_OnViolation(ss, userNum, kP69SrcP55, kind, e.ip, opcode);

        if (!g_logHits) { return; }
        static const wchar_t* kKindText[5] = { L"?", L"кадр короче min", L"кадр длиннее max", L"частота класса", L"кадр короче заголовка" };
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        Log::Line(L"[P55] %s: опкод %d (%S) userNum %d UserIndex %d размер %d [min %d, max %d] класс %d, за 1 с %d (лимит %d/с, запас %d) → %s, подавлено %d",
                  kKindText[kind], opcode, info->handler ? info->handler : "?", userNum,
                  e.userIndex == AcJournal::kNone ? -1 : e.userIndex, size, e.v[1],
                  e.v[2] == AcJournal::kNone ? 0 : e.v[2], cls, secCount, g_perSec[cls], g_burst[cls],
                  action == 1 ? L"отказ + Hack Packet" : (action == 2 ? L"отказ (тихо)" : L"журнал"), (int)suppressed);
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
    }
}

// ── ★ sec2 (решение владельца 14.10 «за поддельный/битый пакет наказывают только ступени P69»): ДОЛЯ НАРУШЕНИЙ P55 В ШТАТНЫХ
//   СЧЁТЧИКАХ КИКА. CheckDisConnectUser@0x526C20 кикает (Send_DisConnectType тип 3 — его считает P48) по четырём счётчикам CUser
//   (GameServer.c): Secret +0x04 (растит sub_524390 при немонотонном токене, кик sub_524440 «> 20» — стаб P49), MD5 +0x08 (растит
//   sub_523F00 при несошедшемся MD5 тела, кик sub_524070 «> 5»), NotKnow +0x1E (sub_5244B0, кик sub_5244F0 «> 5»), Hack +0x22
//   (sub_524540, кик sub_524580 «> 5»). Нарушение P55 1/2/4 (кадр короче/длиннее/без заголовка — его считает P69) растит их так:
//   • Mode=1 + HackPacketOnRefuse=1 — сам P55 +1 к Hack (pHackCount ниже);
//   • Mode=0 (журнал, режим альфы) — кадр уходит обработчику: у короткого кадра MD5 считается по чужим байтам буфера 4096 →
//     MD5 +1 (sub_523F00), секрет/неизвестный опкод/флаги покупки — свои счётчики стока;
//   • P69 KickOnBlock — Hack = 6 (метка P69_TakeKickMark, уже не считается P48).
//   Учёт: на каждом пакете слота гейт снимает 4 счётчика и приписывает прирост с прошлого пакета ПРЕДЫДУЩЕМУ кадру (обработчик
//   кадра идёт сразу за гейтом в той же нити): кадр P55 1/2/4 → «целостность», иначе → «прочее». Собственный +1 P55 и +1 гейта
//   P47 (★ sec2c: P55_PendOtherHack — объявлен «прочим» под замком ДО инкремента) учитываются без гонки с киком другой нити. Начало сессии (20000) и любой кик (P55_KickAttribution) — сброс. P48 на кике тип 3
//   спрашивает P55_KickAttribution: прирост «целостности» > 0 и без него порог не превышен (прочее ≤ порога) — кик вызван
//   нарушениями, за которые наказывает только P69, P48 его НЕ считает (код 6).
//   ★ sec2c (ревизия SEC2 Н-4/Н-5, 2026-10-15): «прочее» P47 — через pendingOther под KcLock; условие «не засчитан» — база счётчика
//   на начале учёта + прочее ≤ порога (порог стока на полное значение). Значение Secret до сброса — по CUser (P49, Н-3).
namespace
{
    constexpr int kKc = 4;                                        // 0 Secret, 1 MD5, 2 NotKnow, 3 Hack
    const int  kKcOff[kKc]    = { 0x04, 0x08, 0x1E, 0x22 };
    const int  kKcThresh[kKc] = { 20, 5, 5, 5 };                  // кик при «> порога» (sub_524440 / sub_524070 / sub_5244F0 / sub_524580)
    // ★ sec2c: pendingOther — +1 к счётчику, объявленные «прочим» ДО самого инкремента (P47 под замком перед pHackCount, Н-4);
    //   base — значение счётчика на начале учёта (Н-5: порог стока — на полное значение, base + прочее).
    struct KcAttr { volatile LONG lock; LONG valid; LONG prevFlag; LONG last[kKc]; LONG integ[kKc]; LONG other[kKc];
                    LONG pendingOther[kKc]; LONG base[kKc]; };
    KcAttr g_kc[kSlots] = {};

    void KcLock(KcAttr& a)   { while (InterlockedCompareExchange(&a.lock, 1, 0) != 0) { YieldProcessor(); } }
    void KcUnlock(KcAttr& a) { InterlockedExchange(&a.lock, 0); }

    bool KcRead(const BYTE* u, LONG v[kKc])
    {
        if (!u) { return false; }
        __try { for (int i = 0; i < kKc; ++i) { v[i] = *(const LONG*)(u + kKcOff[i]); } return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    // ★ sec2c (Н-5): база = значение счётчика на начале учёта (valid 0 → 1). Сток обнуляет все 4 счётчика при старте
    //   (sub_4A1FF0 0x4A2093/0x4A20B0/0x4A213F/0x4A215C) и при освобождении слота ClearUserMemory (sub_4A2DC0 0x4A2F97/0x4A2FB5/
    //   0x4A2FD3/0x4A2FF1 — декомпил + дизасм gs_stock), так что на 20000 база обычно 0; не 0 — учёт начат посреди сессии
    //   (первый пакет после кика другой нити, включение P55 на ходу): прирост до начала учёта тоже против порога.
    void KcResetLocked(KcAttr& a, const LONG* cur)
    {
        for (int i = 0; i < kKc; ++i)
        {
            a.last[i] = cur ? cur[i] : 0; a.integ[i] = 0; a.other[i] = 0; a.pendingOther[i] = 0;
            a.base[i] = cur && cur[i] > 0 ? cur[i] : 0;
        }
        a.valid = cur ? 1 : 0; a.prevFlag = 0;
    }
    // Прирост с прошлого снимка: сначала объявленным заранее «прочим» (pendingOther, Н-4), остаток — классу предыдущего кадра.
    //   Счётчик уменьшился (сброс P49 / новая сессия без 20000) — начать заново (база 0, весь текущий — прирост).
    void KcAccountLocked(KcAttr& a, const LONG cur[kKc])
    {
        if (!a.valid) { KcResetLocked(a, cur); return; }
        for (int i = 0; i < kKc; ++i)
        {
            LONG d = cur[i] - a.last[i];
            if (d < 0) { a.integ[i] = 0; a.other[i] = 0; a.base[i] = 0; d = cur[i] > 0 ? cur[i] : 0; }
            if (d > 0 && a.pendingOther[i] > 0)
            {
                const LONG p = d < a.pendingOther[i] ? d : a.pendingOther[i];
                a.other[i] += p; a.pendingOther[i] -= p; d -= p;
            }
            if (d > 0) { if (a.prevFlag) { a.integ[i] += d; } else { a.other[i] += d; } }
            a.last[i] = cur[i];
        }
    }
    P55_KickStats g_kcStats = {};
}

// ★ sec2c (Н-4): P47 ПЕРЕД своим +1 к Hack (CountAsHackPacket=1; это не нарушение P55) объявляет его «прочим» под замком учёта.
//   Прежде (sec2) +1 вносился ПОСЛЕ pHackCount отдельным шагом: кик другой нити между ними (P55_KickAttribution) отдавал этот +1
//   классу предыдущего кадра — после короткого кадра P55 честный кик за отказы P47 уходил в «не засчитан». Теперь прирост,
//   кто бы его ни снял (следующий пакет слота или кик), сначала гасит pendingOther. Учёт не начат (valid 0) — объявлять нечего.
void P55_PendOtherHack(int userNum)
{
    if (userNum < 0 || userNum >= kSlots) { return; }
    KcAttr& a = g_kc[userNum];
    KcLock(a);
    if (a.valid) { a.pendingOther[3] += 1; }
    KcUnlock(a);
}
// P47: pHackCount упал (SEH) — +1 не случился, снять объявление (если его ещё не погасил прирост; сброс учёта уже обнулил).
void P55_CancelOtherHack(int userNum)
{
    if (userNum < 0 || userNum >= kSlots) { return; }
    KcAttr& a = g_kc[userNum];
    KcLock(a);
    if (a.pendingOther[3] > 0) { a.pendingOther[3] -= 1; }
    KcUnlock(a);
}

// P48 на ВХОДЕ Send_DisConnectType (любой кик — сессия кончается, учёт сбрасывается). which — счётчик кика тип 3 (0..3; −1 — не
//   CheckDisConnectUser), pre — значение счётчика ДО сброса стабом P49 (только Secret; −1 — читать из CUser). true — прирост
//   «целостности» есть и без него счётчик не превысил бы порог: кик вызван нарушениями P55 1/2/4 — P48 не считает.
bool P55_KickAttribution(const BYTE* user, int userNum, int which, int pre, int* integOut, int* otherOut)
{
    if (integOut) { *integOut = 0; }
    if (otherOut) { *otherOut = 0; }
    if (userNum < 0 || userNum >= kSlots) { return false; }
    LONG cur[kKc];
    const bool have = KcRead(user, cur);
    if (have && which >= 0 && which < kKc && pre >= 0) { cur[which] = pre; }
    KcAttr& a = g_kc[userNum];
    int integ = 0, other = 0, base = 0;
    KcLock(a);
    if (a.valid && have) { KcAccountLocked(a, cur); }
    if (a.valid && which >= 0 && which < kKc) { integ = (int)a.integ[which]; other = (int)a.other[which]; base = (int)a.base[which]; }
    KcResetLocked(a, nullptr);
    KcUnlock(a);
    if (integOut) { *integOut = integ; }
    if (otherOut) { *otherOut = base + other; }
    // ★ sec2c (Н-5): порог стока — на полное значение счётчика: без «целостности» осталось бы база + прочее.
    const bool only = which >= 0 && which < kKc && integ > 0 && base + other <= kKcThresh[which];
    if (which >= 0) { InterlockedIncrement(only ? &g_kcStats.integrityOnly : &g_kcStats.counted); }
    return only;
}

extern "C" __declspec(dllexport) void __stdcall P55_GetKickStats(P55_KickStats* s)
{
    if (s) { memcpy(s, &g_kcStats, sizeof(g_kcStats)); }
}
// Только для стенда: доля слота (integ/other по счётчикам) без сброса. op 0 — integ[which], 1 — other[which], 2 — valid,
//   ★ sec2c: 3 — base[which], 4 — pendingOther[which].
extern "C" __declspec(dllexport) int __stdcall P55_TestKickAttr(int userNum, int op, int which)
{
    if (userNum < 0 || userNum >= kSlots || which < 0 || which >= kKc) { return -1; }
    KcAttr& a = g_kc[userNum];
    KcLock(a);
    const int r = op == 0 ? (int)a.integ[which] : op == 1 ? (int)a.other[which] : op == 3 ? (int)a.base[which]
                : op == 4 ? (int)a.pendingOther[which] : (int)a.valid;
    KcUnlock(a);
    return r;
}

// ── общая точка для P47: нужен ли стаб гейта 0x42AB4F ради P55 ──────────────
bool P55_GateWanted()
{
    return Config::GetBool(kSec, L"Enabled", true);
}

// ── гейт: 1 — пропустить в switch, 0 — обработчик не вызывать (только Mode=1) ─
//   Зовёт P47_OperatorGate ПЕРВЫМ (до своей логики). Аргументы те же, что у стаба P47.
int P55_PacketGate(void* mgr, int opcode, int userNum, const BYTE* pkt)
{
    if (!g_enabled || !pkt) { return 1; }
    if (userNum < 0 || userNum >= kSlots) { return 1; }
    InterlockedIncrement(&g_stats.checked);

    WORD size = 0;
    __try { memcpy(&size, pkt + 1, 2); } __except (EXCEPTION_EXECUTE_HANDLER) { return 1; }

    // ★ sec2: прирост штатных счётчиков кика с прошлого пакета слота — предыдущему кадру; 20000 — новая сессия (сброс учёта).
    KcAttr& kc = g_kc[userNum];
    {
        BYTE* u = nullptr;
        if (mgr) { __try { u = pGetUser(mgr, nullptr, (short)userNum); } __except (EXCEPTION_EXECUTE_HANDLER) { u = nullptr; } }
        LONG cur[kKc];
        const bool have = KcRead(u, cur);
        KcLock(kc);
        if (opcode == 20000) { KcResetLocked(kc, have ? cur : nullptr); }
        else if (have)       { KcAccountLocked(kc, cur); }
        KcUnlock(kc);
    }

    const OpLen::Info* info = &OpLen::kInfo[0];
    if (opcode >= 0 && opcode < OpLen::kOpcodeMax) { info = &OpLen::kInfo[OpLen::kIndex[opcode]]; }
    else if (opcode == 20000)                       { info = &OpLen::kInfo[OpLen::kIndexAcceptEx]; }   // вне индекса
    if (!info->opcode) { InterlockedIncrement(&g_stats.noLen); }
    const int cls = info->opcode ? info->cls : (int)OpLen::kOther;

    // 1. длина кадра
    int lenKind = 0;
    if (g_checkLen)
    {
        if (size < kMinFrame)                                     { lenKind = 4; InterlockedIncrement(&g_stats.hdrShort); }
        else if (!info->opcode)                                   { /* длина неизвестна — не проверяем */ }
        else if (size < info->minSize)                            { lenKind = 1; InterlockedIncrement(&g_stats.lenShort); }
        else if (info->maxSize && size > info->maxSize)           { lenKind = 2; InterlockedIncrement(&g_stats.lenLong); }
    }

    // 2. частота класса
    int rateKind = 0, secCount = 0;
    if (g_checkRate && g_perSec[cls] > 0)
    {
        Bucket& b = g_bucket[userNum][cls];
        const DWORD now = GetTickCount();
        if (b.lastTick == 0) { b.tokens = g_burst[cls] * 1000; b.lastTick = now; b.secStart = now; b.secCount = 0; }
        const DWORD dt = now - b.lastTick;
        if (dt)
        {
            const LONGLONG add = (LONGLONG)g_perSec[cls] * (LONGLONG)(dt > 60000 ? 60000 : dt);
            LONGLONG t = (LONGLONG)b.tokens + add;
            const LONGLONG cap = (LONGLONG)g_burst[cls] * 1000;
            b.tokens = (LONG)(t > cap ? cap : t);
            b.lastTick = now;
        }
        if ((DWORD)(now - b.secStart) >= 1000u) { b.secStart = now; b.secCount = 0; }
        secCount = (int)++b.secCount;
        if (b.tokens >= 1000) { b.tokens -= 1000; }
        else                  { rateKind = 3; InterlockedIncrement(&g_stats.rate); }
    }

    // ★ sec2: класс ЭТОГО кадра для прироста счётчиков кика его обработчиком (кадр 1/2/4 — «целостность», наказывает только P69).
    KcLock(kc); kc.prevFlag = lenKind ? 1 : 0; KcUnlock(kc);
    if (!lenKind && !rateKind) { return 1; }

    // 3. вердикт
    const int action = g_mode == 1 ? (g_hackOnRefuse ? 1 : 2) : 0;
    if (lenKind)  { Report(mgr, userNum, opcode, lenKind,  info, size, cls, secCount, action); }
    if (rateKind) { Report(mgr, userNum, opcode, rateKind, info, size, cls, secCount, action); }
    if (action == 0) { return 1; }

    InterlockedIncrement(&g_stats.refused);
    if (action == 1 && mgr)
    {
        bool hc = false;
        __try { pHackCount(mgr, nullptr, (short)userNum); InterlockedIncrement(&g_stats.hackCounted); hc = true; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        // ★ sec2: свой +1 к Hack — сразу в учёт (кадр 1/2/4 — «целостность»; только частота 3 — «прочее»), без двойного счёта.
        if (hc) { KcLock(kc); if (kc.valid) { kc.last[3] += 1; if (lenKind) { kc.integ[3] += 1; } else { kc.other[3] += 1; } } KcUnlock(kc); }
    }
    return 0;
}

// ── для стенда и строки PatchLog ────────────────────────────────────────────
extern "C" __declspec(dllexport) void __stdcall P55_GetStats(P55_Stats* s)
{
    if (s) { memcpy(s, &g_stats, sizeof(g_stats)); }
}

extern "C" __declspec(dllexport) void __stdcall P55_ResetState()
{
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_bucket, 0, sizeof(g_bucket));
    memset(g_jlimit, 0, sizeof(g_jlimit));
    memset(g_kc, 0, sizeof(g_kc));               // ★ sec2
    memset(&g_kcStats, 0, sizeof(g_kcStats));
}

PatchResult P55_PacketValidator()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode         = Config::GetInt (kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_checkLen     = Config::GetBool(kSec, L"CheckLength", true);
    g_checkRate    = Config::GetBool(kSec, L"CheckRate", true);
    g_hackOnRefuse = Config::GetBool(kSec, L"HackPacketOnRefuse", true);
    g_logHits      = Config::GetBool(kSec, L"LogHits", true);
    g_journalSec   = Config::GetInt (kSec, L"JournalIntervalSec", 60);
    if (g_journalSec < 0)     { g_journalSec = 0; }
    if (g_journalSec > 86400) { g_journalSec = 86400; }
    for (int c = 0; c < OpLen::kClassCount; ++c)
    {
        g_perSec[c] = Config::GetInt(kSec, kRateKeys[c].perSec, g_perSec[c]);
        g_burst[c]  = Config::GetInt(kSec, kRateKeys[c].burst,  g_burst[c]);
        if (g_perSec[c] < 0)     { g_perSec[c] = 0; }
        if (g_perSec[c] > 10000) { g_perSec[c] = 10000; }
        if (g_burst[c] < 1)      { g_burst[c] = 1; }
        if (g_burst[c] > 100000) { g_burst[c] = 100000; }
    }
    if (!g_logLockReady) { InitializeCriticalSection(&g_logLock); g_logLockReady = true; }

    // Зависимость: стаб гейта ставит P47 (площадка 0x42AB4F). Без него гейт никто не зовёт.
    if (!Config::GetBool(L"P47_IdentityOperatorGate", L"Enabled", true))
    {
        Log::Line(L"    P55: [P47_IdentityOperatorGate] Enabled=0 — стаб гейта 0x42AB4F не стоит, валидатор НЕ работает");
        return PatchResult::Failed;
    }
    BYTE first = 0;
    __try { first = *(const BYTE*)kGateSite; } __except (EXCEPTION_EXECUTE_HANDLER) { first = 0; }
    if (first != 0xE9)
    {
        Log::Line(L"    P55: на 0x%08X нет jmp стаба P47 (байт 0x%02X) — валидатор НЕ работает", kGateSite, first);
        return PatchResult::Failed;
    }

    P55_ResetState();
    InterlockedExchange(&g_enabled, 1);
    Log::Line(L"    P55: Mode=%d (%s) CheckLength=%d CheckRate=%d HackPacketOnRefuse=%d LogHits=%d JournalIntervalSec=%d; "
              L"таблица длин: %d опкодов (индекс 0..0x%X); лимиты/с (запас): прочее %d(%d) движение %d(%d) бой %d(%d) "
              L"чат %d(%d) предметы %d(%d) БД %d(%d) GM %d(%d)",
              g_mode, g_mode == 1 ? L"ОТКАЗ" : L"только журнал", g_checkLen ? 1 : 0, g_checkRate ? 1 : 0,
              g_hackOnRefuse ? 1 : 0, g_logHits ? 1 : 0, g_journalSec, OpLen::kInfoCount - 1, OpLen::kOpcodeMax - 1,
              g_perSec[0], g_burst[0], g_perSec[1], g_burst[1], g_perSec[2], g_burst[2], g_perSec[3], g_burst[3],
              g_perSec[4], g_burst[4], g_perSec[5], g_burst[5], g_perSec[6], g_burst[6]);
    return PatchResult::Applied;
}
