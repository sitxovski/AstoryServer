// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P47 — ★ БЕЗОПАСНОСТЬ (античит, волна А0, 2026-10-12): привязка личности на входе
//  в GameServer и обязательный GM-флаг для операторских команд.
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Мера 3 плана `Reports/anticheat/00_PLAN.md` (+ §8 A1).
//  Отчёт: `Reports/anticheat/wave_A0.md`; документ: `AstoryServer/Docs/GameServer/identity-operator-gate-p47.md`.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  1. UserIndex (CUser+0x174) берётся из тела пакета клиента: сначала 20000 (AcceptExUser@0x5233A0
//     пишет его безусловно), затем 4001 (CharLogonReq@0x527500) / 5058 (CharPortalLogonReq@0x52CBE0)
//     переписывают его тем, что пришло в своём теле. Сверки с сессией LoginManager нет нигде.
//  2. Операторский гейт sub_52ECF0 = только «UserIndex в 0…5000». Гейт GM-флага sub_52ED50
//     (байт CUser+0x40B9F, приходит из БД: UPCharGMInfo → DB-ответ 2801 → sub_560160, который
//     сверяет UserIndex с CUser+0x174) стоит лишь у 9 операторских обработчиков из ~30; у 6146 нет
//     даже sub_52ECF0 у отправителя (TJ-1), у 6184 сброс обучения (-1) пускается по 0…5000 (TUT-1).
//
//  ── ЧЕМ ЛЕЧИМ (три части, у каждой свой ключ ini; протокол клиента НЕ меняется) ──
//  A. ГЕЙТ GM-ФЛАГА В ДИСПЕТЧЕРЕ (OperatorGmFlag). Площадка 0x42AB4F — запись опкода в кадр
//     диспетчера sub_42A9D0 (13 б: mov eax,[ebp-4] / movzx ecx,[eax+7] / mov [ebp-0x10C8],ecx),
//     ПЕРЕД деревом сравнений и перед стабом P01 (0x42AB5C) — цепочка без пересечения.
//     Для операторских опкодов при GM-флаге != 1 обработчик НЕ вызывается (выход в общий хвост
//     switch 0x42F036, как у P01). До входа в мир (до DB-ответа 2801) флаг = 0 у всех
//     (ClearUserMemory → sub_4A2DC0 обнуляет +0x40B9F), поэтому окно «20000 → 4001» закрыто.
//     Полный список (скан диспетчера: все обработчики с входным гейтом sub_52ECF0):
//       4209 RecvClient_Command_Call_AllUser_Map, 6005 Hide, 6007 DeleteMapAreaItem_GM,
//       6010 CharJumpCommandPosition, 6012 Summon, 6014 Meet, 6018 Kick, 6020 (P25 пересчёт),
//       6022 Kill, 6024 Kill_0, 6026 Move, 6028/6029 Local/GlobalChat, 6030 (P02 объявление),
//       6032 Add, 6033 GetMob, 6035 Invincible, 6036 GetValue, 6038 EventSet, 6040 EventOff,
//       6042 ItemGive, 6045 MonsterPop, 6046 MonsterReturn, 6058 UserSkillCoolTimeAllOff,
//       6075 UserCharValue, 6094 GM-блок (sub_55A510), 6145 CountDown, 6147 MapBlock.
//     Условные (розничный клиент шлёт их и не-операторам — режем только операторскую часть):
//       6146 RecvClient_TargetJump — без GM-флага пропускаются ТОЛЬКО розничные формы эталона:
//            режим 0, цель = свой userNum, шестёрка {259,234,285,277,272,256} / {225,234,252,277,238,256}
//            (NPC-коды 30071/30072, game_main.c:10287-10296) и режим 1, цель −1, шестёрка
//            {240,214,270,228,195,189} (конец отсчёта типа 2, ui_core.c:86991) — последняя только
//            в окне после принятого от оператора 6145 с типом 2 (CountdownWindow).
//       6147 — розничная форма конца отсчёта типа 1 (режим 1, 0, 0, ui_core.c:86987) у не-оператора
//            отбрасывается молча, как в стоке (там отсекал sub_52ECF0 при UserIndex > 5000).
//       6184 — ветка сброса (номер обучения −1) требует GM-флаг; обычные обновления не трогаются.
//     ★ ac0r (2026-10-12, ревизия А0/А2 СРЕД-2, решение координатора): отказ — ТИХИЙ СБРОС. Обработчик
//     не вызывается, счётчик Hack Packet НЕ растёт (ключ CountAsHackPacket, умолчание 0) — значит, и
//     кика код 3, и засчёта в автоблок P48 от отказа гейта нет: обычный игрок с операторским префиксом
//     имени (GM_/ADM_) и клиентской пробой прав не должен копить кики. Строка в Log_Operator остаётся,
//     но не чаще одного раза в RefusalLogIntervalSec (60 с) на сессию (слот userNum + UserIndex; новый
//     логон 4001/5058 начинает отсчёт заново), подавленные отказы считаются и печатаются в следующей.
//     Прежнее поведение (+1 к sub_524540, кик при > 5) — CountAsHackPacket=1.
//     Розничные формы (6146/6147/6184) без флага — молча, без счётчика (как и было).
//  B. СВЕРКА UserIndex 4001/5058 С 20000 (Match20000). Площадки — вход ветки «успех» стоковой
//     проверки тела: 0x527692 (CharLogonReq) и 0x52CD3E (CharPortalLogonReq). Если UserIndex
//     логона != CUser+0x174 (записан при 20000) — уходим в стоковую ветку отказа
//     (0x52764D / 0x52CCF9: лог «Exception…», +0x32 = 1, кик 4101 код 5, отключение).
//  C. IP ПИРА В DB-ЗАПРОС ЛОГОНА (SendPeerIp). Площадки — `push len; push op` перед отправкой
//     2001 (0x52773F, тело 8 б) и 2089 (0x52CF05, тело 12 б) в DBManager. К телу дописывается
//     8 б: магия 'P47I' + IPv4 пира (getpeername по сокету userNum, тот же путь, что
//     sub_565150). Стоковый DBManager читает фиксированный префикс и хвост игнорирует;
//     DBPatch P50 по нему сверяет UserIndex/CharIdx/IP с записью входа (JoyLog1.dbo.Loginfo).
//
//  ── ПЛОЩАДКИ (полный перебор кодировок rel8/rel32/jcc32 + abs32 по .text стока: переходов
//     ВНУТРЬ ни одной — 0 кандидатов; с P01…P46 не пересекаются, проверено по SITES verify_dll):
//     0x0042AB4F  8B45FC 0FB74807 898D38EFFFFF   (13 б) → GateStub
//     0x00527692  8B95D8FBFFFF                   (6 б)  → LogonMatchStub
//     0x0052CD3E  8B85CCFBFFFF                   (6 б)  → PortalMatchStub
//     0x0052773F  6A08 68D1070000                (7 б)  → LogonIpStub
//     0x0052CF05  6A0C 6829080000                (7 б)  → PortalIpStub
//  Байты одинаковы в стоке 4e20f0ad…, живом GameServer и живом Indun_GameServer (e7b4ac38…).
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
    const wchar_t* kSec = L"P47_IdentityOperatorGate";

    // ── настройки (patches.ini) ─────────────────────────────────────────────
    bool g_gmGate       = true;   // A: GM-флаг обязателен для операторских опкодов
    bool g_countHack    = false;  // A: отказ по операторской команде → штатный счётчик Hack Packet (★ ac0r: умолч. 0)
    bool g_tjRetail     = true;   // A: 6146 без флага — только розничные формы эталона
    bool g_tjWindow     = true;   // A: форма «конец отсчёта» 6146 — только в окне после 6145 типа 2
    bool g_match20000   = true;   // B: UserIndex логона == UserIndex из 20000
    bool g_sendIp       = true;   // C: IP пира в DB-запрос 2001/2089
    bool g_runtimeLog   = true;   // строки отказов в PatchLog (антифлуд)
    int  g_windowSlackS = 60;     // запас окна отсчёта сверх заявленной длительности, с
    int  g_refuseLogSec = 60;     // ★ ac0r: не чаще одной строки отказа в Log_Operator на сессию за столько секунд

    // ── функции GameServer (соглашения — как у стоковых вызовов) ─────────────
    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);      // sub_5324A0
    typedef int   (__fastcall *PFN_GetUserIndex)(void* self, void* edx, int userNum); // sub_5324F0
    typedef char  (__fastcall *PFN_IsGm)(void* self, void* edx, int userNum);         // sub_52ED50
    typedef void* (__fastcall *PFN_HackCount)(void* self, void* edx, int userNum);    // sub_524540
    typedef UINT_PTR (__fastcall *PFN_GetSocket)(void* self, void* edx, int userNum); // sub_564F50
    typedef int   (__stdcall  *PFN_GetPeerName)(UINT_PTR s, void* name, int* len);    // ws2_32!getpeername
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);            // sub_569DF0

    PFN_GetUser      const pGetUser   = (PFN_GetUser)     Srv::kGetUser;         // 0x5324A0
    PFN_GetUserIndex const pGetUserIx = (PFN_GetUserIndex)Srv::kGetUserNumber;   // 0x5324F0
    PFN_IsGm         const pIsGm      = (PFN_IsGm)        Srv::kIsOperator;      // 0x52ED50 (GM-флаг)
    PFN_HackCount    const pHackCount = (PFN_HackCount)   0x00524540;            // ++CUser+0x22
    PFN_GetSocket    const pGetSocket = (PFN_GetSocket)   0x00564F50;            // сокет по userNum
    PFN_SrvLog       const pSrvLog    = (PFN_SrvLog)      Srv::kLog;
    void* const kNetMgr               = (void*)Srv::kNetMoveMgr;                 // 0x7E0538 (this sub_564F50)
    const DWORD kIatGetPeerName       = 0x00583230;                              // IAT ws2_32!getpeername

    constexpr int kOffUserIndex = 0x174;   // CUser: UserIndex (пишут 20000/4001/5058)
    constexpr int kPayload      = 33;      // смещение полезной нагрузки в кадре (9 заголовок + 8 секрет + 16 MD5)

    // ── классификация опкодов ────────────────────────────────────────────────
    enum OpKind : BYTE
    {
        kNone      = 0,   // не операторский
        kOperator  = 1,   // операторская команда целиком
        kTargetJmp = 2,   // 6146 — розничные формы пропускаются
        kMapBlock  = 3,   // 6147 — розничная форма конца отсчёта молча отбрасывается
        kTutorial  = 4,   // 6184 — операторская только ветка сброса (−1)
        kCountDown = 5,   // 6145 — операторская; у принятой (тип 2) открывает окно 6146
    };

    struct OpRule { WORD op; OpKind kind; };

    const OpRule kRules[] =
    {
        { 4209, kOperator }, { 6005, kOperator }, { 6007, kOperator }, { 6010, kOperator },
        { 6012, kOperator }, { 6014, kOperator }, { 6018, kOperator }, { 6020, kOperator },
        { 6022, kOperator }, { 6024, kOperator }, { 6026, kOperator }, { 6028, kOperator },
        { 6029, kOperator }, { 6030, kOperator }, { 6032, kOperator }, { 6033, kOperator },
        { 6035, kOperator }, { 6036, kOperator }, { 6038, kOperator }, { 6040, kOperator },
        { 6042, kOperator }, { 6045, kOperator }, { 6046, kOperator }, { 6058, kOperator },
        { 6075, kOperator }, { 6094, kOperator }, { 6145, kCountDown }, { 6146, kTargetJmp },
        { 6147, kMapBlock }, { 6184, kTutorial },
    };

    OpKind Classify(int op)
    {
        for (int i = 0; i < ARRAYSIZE(kRules); ++i)
        {
            if (kRules[i].op == op) { return kRules[i].kind; }
        }
        return kNone;
    }

    // Розничные шестёрки 6146 (эталон клиента, см. шапку).
    const int kJumpNpcA[6]   = { 259, 234, 285, 277, 272, 256 };   // 30071
    const int kJumpNpcB[6]   = { 225, 234, 252, 277, 238, 256 };   // 30072
    const int kJumpCountd[6] = { 240, 214, 270, 228, 195, 189 };   // конец отсчёта типа 2

    // Окно «после отсчёта типа 2»: до какого GetTickCount принимать розничный 6146 режима 1.
    volatile LONG g_tjWindowUntil = 0;
    volatile LONG g_tjWindowSet   = 0;

    bool SixEquals(const BYTE* p, const int* six)
    {
        for (int i = 0; i < 6; ++i)
        {
            int v; memcpy(&v, p + 4 * i, 4);
            if (v != six[i]) { return false; }
        }
        return true;
    }

    // ── антифлуд и сериализация журнала ──────────────────────────────────────
    CRITICAL_SECTION g_logLock;
    bool             g_logLockReady = false;
    volatile LONG    g_refusals     = 0;   // отказов гейта A
    volatile LONG    g_mismatches   = 0;   // отказов сверки B
    volatile LONG    g_ipAppended   = 0;   // дописанных IP (C)

    // ★ ac0r: ограничитель строк отказа гейта A — одна строка на сессию за g_refuseLogSec.
    //   Сессия = слот userNum + UserIndex (CUser+0x174, его пишет 20000); P47_LogonMatch (4001/5058 —
    //   вход в этот процесс) начинает отсчёт заново. Подавленные отказы копятся и печатаются в
    //   следующей строке. Под g_logLock (диспетчер зовут потоки разных карт).
    struct RefuseLogSlot { int userIndex; DWORD lastTick; bool used; LONG suppressed; };
    RefuseLogSlot g_refuseLog[0x226] = {};

    // true — строку печатать (и *suppressedOut = сколько подавлено с прошлой); false — подавить.
    bool RefuseLogAllow(int userNum, int userIndex, LONG* suppressedOut)
    {
        *suppressedOut = 0;
        if (userNum < 0 || userNum >= 0x226) { return true; }
        bool allow = true;
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        RefuseLogSlot& r = g_refuseLog[userNum];
        const DWORD now = GetTickCount();
        if (r.used && r.userIndex == userIndex && g_refuseLogSec > 0
            && (DWORD)(now - r.lastTick) < (DWORD)g_refuseLogSec * 1000u)
        {
            ++r.suppressed;
            allow = false;
        }
        else
        {
            *suppressedOut = (r.used && r.userIndex == userIndex) ? r.suppressed : 0;
            r.used = true; r.userIndex = userIndex; r.lastTick = now; r.suppressed = 0;
        }
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
        return allow;
    }

    // Новый логон в слоте — новая сессия: ограничитель забывает прошлую.
    void RefuseLogReset(int userNum)
    {
        if (userNum < 0 || userNum >= 0x226) { return; }
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        g_refuseLog[userNum].used = false;
        g_refuseLog[userNum].suppressed = 0;
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
    }

    void LogLimited(volatile LONG* counter, const wchar_t* fmt, int a, int b, int c, int d)
    {
        const LONG n = InterlockedIncrement(counter);
        if (!g_runtimeLog)               { return; }
        if (n > 200 && (n % 1000) != 0)  { return; }
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        Log::Line(fmt, a, b, c, d, (int)n);
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
    }

    // IPv4 пира по userNum (0 — не определён). Тот же путь, что стоковый sub_565150,
    // но с проверкой результата getpeername (у стока при ошибке читается мусор стека).
    // ★ acdb: общая точка — P47_PeerIpv4 (Patches.h) зовут журнал P53 и P48.
    DWORD PeerIpv4(int userNum)
    {
        if (userNum < 0 || userNum >= 0x226) { return 0; }
        PFN_GetPeerName gp = *(PFN_GetPeerName*)kIatGetPeerName;
        if (!gp) { return 0; }
        __try
        {
            const UINT_PTR s = pGetSocket(kNetMgr, nullptr, userNum);
            if (s == 0 || s == (UINT_PTR)~0) { return 0; }
            BYTE sa[16] = {};
            int  len = sizeof(sa);
            if (gp(s, sa, &len) != 0)            { return 0; }
            if (*(const WORD*)sa != 2 /*AF_INET*/) { return 0; }
            DWORD ip; memcpy(&ip, sa + 4, 4);   // sin_addr, порядок байт сетевой
            return ip;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    // Буфер дописанного тела — на поток (sub_5646C0 копирует тело синхронно).
    __declspec(thread) BYTE t_body[64];

    constexpr DWORD kIpMagic = 0x49373450;   // 'P47I' (байты 50 34 37 49) — признак хвоста для P50

    // ★ acdb (P53): строка журнала античита ac.operator_refusal / ac.identity_mismatch.
    void JournalUser(AcJournal::Event& e, void* mgr, int userNum)
    {
        e.userNum = (short)userNum;
        e.ip = PeerIpv4(userNum);
        if (!mgr) { return; }
        __try
        {
            const BYTE* u = pGetUser(mgr, nullptr, (short)userNum);
            if (u)
            {
                e.userIndex = *(const int*)(u + kOffUserIndex);
                e.charSlot  = u[0x18C];
                AcJournal::CopyName(e, u + Srv::kOffCharName);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ★ acdb: IPv4 пира по userNum для журнала (общая точка; 0 — не определён).
DWORD P47_PeerIpv4(int userNum)
{
    return PeerIpv4(userNum);
}

// ★ integ3 (13.10.2026): «отправитель — оператор» — ТОТ ЖЕ признак, что у гейта A: sub_52ED50(mgr, userNum) == 1,
//   т. е. байт GM-флага CUser+0x40B9F (его ставит только ответ DBManager 2801 → sub_560160 после EXEC UPCharGMInfo
//   при загрузке персонажа; до DB-логона 0 — ClearUserMemory → sub_4A2DC0). Общая точка: P47_OperatorGate и P68.
bool P47_IsGmUser(void* mgr, int userNum)
{
    if (!mgr) { return false; }
    bool gm = false;
    __try { gm = pIsGm(mgr, nullptr, (short)userNum) == 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { gm = false; }
    return gm;
}

// ── A. Гейт диспетчера: 1 — пропустить в switch, 0 — обработчик не вызывать ──
extern "C" int __stdcall P47_OperatorGate(void* mgr, int opcode, int userNum, const BYTE* pkt)
{
    // ★ P55 (В4, 2026-10-12): общий валидатор пакетов — ПЕРВЫМ в цепочке (длина кадра / частота класса).
    //   0 = обработчик не вызывать (только в режиме отказа P55); в режиме журнала всегда 1.
    if (!P55_PacketGate(mgr, opcode, userNum, pkt)) { return 0; }
    // ★ P64 (A7, 2026-10-12): общая преамбула состояния персонажа — ВТОРЫМ, сразу после P55 (мёртв / занят /
    //   душа / одержим / не в игре по спискам опкодов). 0 = обработчик не вызывать (только Mode=1); в журнале всегда 1.
    if (!P64_StateGate(mgr, opcode, userNum, pkt)) { return 0; }
    // ★ P69 (autoban, 2026-10-14): запомнить CUserManager слота (одна запись указателя) — по нему P61 (поток приёма IOCP, своего
    //   CUserManager не имеет) находит CUser сессии для учётки в журнале и счёта автоблока. Ничего не решает и не отклоняет.
    //   ТРЕТЬИМ, после P55 и P64 (порядок цепочки сверяют verify_p55/verify_p64; оба получают CUserManager сами); пакет, отклонённый
    //   ими в Mode=1, кэш не обновляет — обновит следующий пакет сессии.
    P69_OnClientPacket(mgr, userNum);
    // ★ P129 (А6.12, 22.11.2026): журнал и заглушка чата — ЧЕТВЁРТЫМ, после P55/P64/P69 (в журнал идёт только то, что дошло бы до
    //   обработчика). Опкоды чата операторскими не бывают (Classify), поэтому до гейта GM-флага. 0 = обработчик не вызывать
    //   (заглушка при Mode=1); иначе всегда 1.
    if (!P129_ChatGate(mgr, opcode, userNum, pkt)) { return 0; }
    if (!g_gmGate || !mgr) { return 1; }
    const OpKind kind = Classify(opcode);
    if (kind == kNone) { return 1; }

    const bool gm = P47_IsGmUser(mgr, userNum);   // ★ integ3: общая точка (тот же вызов sub_52ED50 == 1, SEH)

    const BYTE* body = pkt + kPayload;
    if (gm)
    {
        // Отсчёт оператора типа 2 → открыть окно розничного 6146 режима 1.
        if (kind == kCountDown && g_tjWindow)
        {
            int  secs; memcpy(&secs, body, 4);
            short act; memcpy(&act, body + 5, 2);
            if (act == 2)
            {
                if (secs < 0)    { secs = 0; }
                if (secs > 7200) { secs = 7200; }
                InterlockedExchange(&g_tjWindowUntil, (LONG)(GetTickCount() + (DWORD)(secs + g_windowSlackS) * 1000u));
                InterlockedExchange(&g_tjWindowSet, 1);
            }
        }
        return 1;
    }

    bool count = true;   // засчитать ли отказ в Hack Packet
    BYTE jkind = 1;      // ★ acdb: вид отказа для журнала (ac.operator_refusal, AcJournal.cpp KindText)
    switch (kind)
    {
    case kTutorial:
    {
        short tut; memcpy(&tut, body + 6, 2);
        if (tut != -1) { return 1; }          // обычное обновление обучения — как сток
        count = false;                        // сброс без флага: у стока не-оператор = нет действия
        jkind = 6;
        break;
    }
    case kTargetJmp:
    {
        if (!g_tjRetail) { return 1; }
        const BYTE mode = body[0];
        short tgt; memcpy(&tgt, body + 1, 2);
        if (mode == 0 && tgt == (short)userNum
            && (SixEquals(body + 3, kJumpNpcA) || SixEquals(body + 3, kJumpNpcB)))
        {
            return 1;                         // NPC 30071/30072 — розничная форма
        }
        jkind = 2;
        if (mode == 1 && tgt == -1 && SixEquals(body + 3, kJumpCountd))
        {
            if (!g_tjWindow) { return 1; }
            const DWORD until = (DWORD)g_tjWindowUntil;
            if (g_tjWindowSet && (int)(until - GetTickCount()) > 0) { return 1; }
            count = false;                    // розничная форма вне окна — молча
            jkind = 3;
        }
        break;
    }
    case kMapBlock:
    {
        int a, b; memcpy(&a, body + 1, 4); memcpy(&b, body + 5, 4);
        jkind = 5;
        if (body[0] == 1 && a == 0 && b == 0) { count = false; jkind = 4; }   // розничный конец отсчёта типа 1
        break;
    }
    default:
        break;
    }

    int ui = -1;
    __try { ui = pGetUserIx(mgr, nullptr, (short)userNum); } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }

    // Штатный журнал оператора (Log_Operator), как стоковые «Send Fail». ★ ac0r: не чаще раза в
    //   g_refuseLogSec на сессию; отказ при этом всё равно тихий (обработчик не зовётся).
    const bool hack = count && g_countHack;
    LONG suppressed = 0;
    if (RefuseLogAllow(userNum, ui, &suppressed))
    {
        pSrvLog(Srv::kLogCatOperator, "P47 OperatorGate: op %d refused (GMFlag != 1) UserNum %d UserIndex %d%s, suppressed %d",
                opcode, userNum, ui, hack ? " [HackPacket+1]" : " [silent drop]", (int)suppressed);
        LogLimited(&g_refusals, L"[P47] отказ: операторский опкод %d без GM-флага, userNum %d, UserIndex %d, "
                   L"счётчик Hack Packet %d (всего отказов %d)", opcode, userNum, ui, hack ? 1 : 0);
        // ★ acdb (P53): та же строка — в журнал античита в базе (тем же ограничителем: раз в
        //   RefusalLogIntervalSec на сессию, подавленные — repeat_suppressed).
        AcJournal::Event je;
        AcJournal::Clear(je, AcJournal::kOperatorRefusal, jkind);
        JournalUser(je, mgr, userNum);
        if (je.userIndex == AcJournal::kNone && ui != -1) { je.userIndex = ui; }
        je.opcode = opcode;
        je.v[0] = 0;                // GM-флаг (отказ только при != 1)
        je.v[1] = hack ? 1 : 0;
        je.suppressed = (int)suppressed;
        AcJournal::Push(je);
    }
    else
    {
        InterlockedIncrement(&g_refusals);
    }

    if (hack)
    {
        // ★ sec2/sec2c (Н-4): +1 к Hack от отказа P47 — «прочее» (не нарушение P55), P48 его считает. Объявляется под замком учёта
        //   P55 ДО инкремента: кик другой нити между инкрементом и учётом больше не отдаёт его классу предыдущего кадра.
        P55_PendOtherHack(userNum);
        bool hc = false;
        __try { pHackCount(mgr, nullptr, (short)userNum); hc = true; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (!hc) { P55_CancelOtherHack(userNum); }
    }
    return 0;
}

// ── B. Сверка UserIndex логона с UserIndex из 20000: 1 — совпало (или выключено) ──
static int LogonMatchCore(int kind, int userNum, BYTE* user, int pktUserIndex)
{
    RefuseLogReset(userNum);   // ★ ac0r: логон 4001/5058 — новая сессия для ограничителя строк отказа
    if (!g_match20000 || !user) { return 1; }
    int cur = -1;
    __try { cur = *(const int*)(user + kOffUserIndex); } __except (EXCEPTION_EXECUTE_HANDLER) { return 1; }
    if (cur == pktUserIndex) { return 1; }

    pSrvLog(0, "P47 LogonMatch: %s UserIndex %d != 20000 UserIndex %d, UserNum %d -> refused",
            kind == 1 ? "4001" : "5058", pktUserIndex, cur, userNum);
    // ★ acdb (P53): несовпадение личности — в журнал античита (ac.identity_mismatch).
    {
        AcJournal::Event je;
        AcJournal::Clear(je, AcJournal::kIdentityMismatch, (BYTE)(kind == 1 ? 1 : 2));
        je.userNum = (short)userNum;
        je.ip = PeerIpv4(userNum);
        je.userIndex = cur;
        je.opcode = kind == 1 ? 4001 : 5058;
        je.v[0] = pktUserIndex;
        je.v[1] = cur;
        __try { AcJournal::CopyName(je, user + Srv::kOffCharName); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        AcJournal::Push(je);
    }
    LogLimited(&g_mismatches, L"[P47] отказ логона %d: UserIndex логона %d != UserIndex 20000 %d, userNum %d "
               L"(всего %d)", kind == 1 ? 4001 : 5058, pktUserIndex, cur, userNum);
    return 0;
}

// Стабы 0x527692/0x52CD3E. ★ P73 (EAC, 2026-10-16): общая точка — на ветке «совпало» (сток идёт в успех логона) сообщить мосту EAC
//   (LOGIN сайдкару). Отказ сверки → стоковая ветка отказа, LOGIN не уходит. P73 выключен — его колбэк сразу выходит.
extern "C" int __stdcall P47_LogonMatch(int kind, int userNum, BYTE* user, int pktUserIndex)
{
    const int r = LogonMatchCore(kind, userNum, user, pktUserIndex);
    if (r) { P73_OnLogon(kind, userNum, user, pktUserIndex); }
    return r;
}

// ★ P73: стабы логона 0x527692/0x52CD3E поставлены этим патчем (тогда P73 своих на те же байты не ставит).
static bool g_logonStubs = false;
bool P47_LogonHooked()
{
    return g_logonStubs;
}

// ── C. Подготовка тела DB-запроса логона: возвращает новую длину, args[1] — указатель тела ──
//   args — указатель на уже положенные стоком аргументы sub_5646C0: [0] dbIdx, [1] тело, [2] userNum.
extern "C" int __stdcall P47_PrepareDbBody(int userNum, DWORD* args, int stockLen)
{
    if (!g_sendIp || !args || stockLen <= 0 || stockLen > 32) { return stockLen; }
    const DWORD ip = PeerIpv4(userNum);
    if (ip == 0) { return stockLen; }   // IP не определён — тело как в стоке (P50 решит по RequireIp)
    __try
    {
        memcpy(t_body, (const void*)args[1], stockLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return stockLen;
    }
    memcpy(t_body + stockLen,     &kIpMagic, 4);
    memcpy(t_body + stockLen + 4, &ip, 4);
    args[1] = (DWORD)(UINT_PTR)t_body;
    InterlockedIncrement(&g_ipAppended);
    return stockLen + 8;
}

namespace
{
    // Адреса возврата/переходов (косвенно — `jmp dword ptr [...]`, флаги не трогает).
    DWORD g_retGate      = 0x0042AB5C;   // начало дерева сравнений (там же стаб P01)
    DWORD g_switchTail   = Srv::Hooks::kDispatchTail;   // 0x42F036 — общий хвост switch
    DWORD g_ret4001      = 0x00527698;   // после `mov edx,[ebp-0x428]`
    DWORD g_refuse4001   = 0x0052764D;   // стоковая ветка отказа CharLogonReq
    DWORD g_ret5058      = 0x0052CD44;   // после `mov eax,[ebp-0x434]`
    DWORD g_refuse5058   = 0x0052CCF9;   // стоковая ветка отказа CharPortalLogonReq
    DWORD g_retIp4001    = 0x00527746;   // `mov ecx,0x7E0538` перед call sub_5646C0
    DWORD g_retIp5058    = 0x0052CF0C;

    // ── A. Стаб диспетчера @0x42AB4F ─────────────────────────────────────────
    //   Повторяет три вытесненные команды, спрашивает гейт и либо идёт в дерево сравнений
    //   (0x42AB5C, где стоит стаб P01), либо в общий хвост switch (обработчик не зовётся).
    __declspec(naked) void GateStub()
    {
        __asm
        {
            mov   eax, dword ptr [ebp-4]           // вытеснено: pkt
            movzx ecx, word ptr [eax+7]            // вытеснено: опкод
            mov   dword ptr [ebp-0x10C8], ecx      // вытеснено: опкод в кадр
            pushad
            push  dword ptr [ebp-4]                // pkt
            movsx eax, word ptr [ebp-0x44]
            push  eax                              // userNum
            push  ecx                              // опкод
            mov   edx, dword ptr [ebp-0x10C4]
            mov   eax, dword ptr [edx+4]
            mov   eax, dword ptr [eax+0x34]
            push  eax                              // CUserManager
            call  P47_OperatorGate                 // __stdcall — чистит 16 б сам
            mov   dword ptr [esp+28], eax          // результат → сохранённый eax
            popad
            test  eax, eax
            jz    g_refuse
            mov   eax, dword ptr [ebp-4]           // как после вытесненных команд: eax = pkt
            jmp   dword ptr [g_retGate]
        g_refuse:
            jmp   dword ptr [g_switchTail]
        }
    }

    // ── B. 4001 @0x527692: вход ветки «успех» CharLogonReq ──────────────────
    __declspec(naked) void LogonMatchStub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x424]            // UserIndex из тела 4001
            push  dword ptr [ebp-0x428]            // CUser*
            movsx eax, word ptr [ebp+8]
            push  eax                              // userNum
            push  1                                // вид: 4001
            call  P47_LogonMatch
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            jz    l_refuse
            mov   edx, dword ptr [ebp-0x428]       // вытеснено
            jmp   dword ptr [g_ret4001]
        l_refuse:
            jmp   dword ptr [g_refuse4001]
        }
    }

    // ── B. 5058 @0x52CD3E: вход ветки «успех» CharPortalLogonReq ─────────────
    __declspec(naked) void PortalMatchStub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x430]            // UserIndex из тела 5058
            push  dword ptr [ebp-0x434]            // CUser*
            movsx eax, word ptr [ebp+8]
            push  eax                              // userNum
            push  2                                // вид: 5058
            call  P47_LogonMatch
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            jz    p_refuse
            mov   eax, dword ptr [ebp-0x434]       // вытеснено
            jmp   dword ptr [g_ret5058]
        p_refuse:
            jmp   dword ptr [g_refuse5058]
        }
    }

    // ── C. 2001 @0x52773F: вместо `push 8; push 0x7D1` ───────────────────────
    //   На стеке уже лежат (сверху): dbIdx, &тело, userNum — аргументы sub_5646C0.
    __declspec(naked) void LogonIpStub()
    {
        __asm
        {
            pushad
            lea   eax, [esp+32]                    // → [dbIdx, &тело, userNum]
            push  8                                // стоковая длина тела 2001
            push  eax
            movsx ecx, word ptr [ebp+8]
            push  ecx                              // userNum
            call  P47_PrepareDbBody
            mov   dword ptr [esp+28], eax
            popad
            push  eax                              // длина (8 или 16)
            push  0x7D1                            // опкод 2001
            jmp   dword ptr [g_retIp4001]
        }
    }

    // ── C. 2089 @0x52CF05: вместо `push 0xC; push 0x829` ─────────────────────
    __declspec(naked) void PortalIpStub()
    {
        __asm
        {
            pushad
            lea   eax, [esp+32]
            push  12                               // стоковая длина тела 2089
            push  eax
            movsx ecx, word ptr [ebp+8]
            push  ecx
            call  P47_PrepareDbBody
            mov   dword ptr [esp+28], eax
            popad
            push  eax                              // длина (12 или 20)
            push  0x829                            // опкод 2089
            jmp   dword ptr [g_retIp5058]
        }
    }

    const BYTE kOrigGate[13]   = { 0x8B,0x45,0xFC, 0x0F,0xB7,0x48,0x07, 0x89,0x8D,0x38,0xEF,0xFF,0xFF };
    const BYTE kOrig4001[6]    = { 0x8B,0x95,0xD8,0xFB,0xFF,0xFF };
    const BYTE kOrig5058[6]    = { 0x8B,0x85,0xCC,0xFB,0xFF,0xFF };
    const BYTE kOrigIp4001[7]  = { 0x6A,0x08, 0x68,0xD1,0x07,0x00,0x00 };
    const BYTE kOrigIp5058[7]  = { 0x6A,0x0C, 0x68,0x29,0x08,0x00,0x00 };
}

PatchResult P47_IdentityOperatorGate()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_gmGate     = Config::GetBool(kSec, L"OperatorGmFlag", true);
    g_countHack  = Config::GetBool(kSec, L"CountAsHackPacket", false);   // ★ ac0r: тихий сброс по умолчанию
    g_tjRetail   = Config::GetBool(kSec, L"TargetJumpRetailOnly", true);
    g_tjWindow   = Config::GetBool(kSec, L"TargetJumpCountdownWindow", true);
    g_match20000 = Config::GetBool(kSec, L"Match20000", true);
    g_sendIp     = Config::GetBool(kSec, L"SendPeerIp", true);
    g_runtimeLog = Config::GetBool(kSec, L"RuntimeLog", true);
    g_windowSlackS = Config::GetInt(kSec, L"CountdownSlackSec", 60);
    if (g_windowSlackS < 0)    { g_windowSlackS = 0; }
    if (g_windowSlackS > 3600) { g_windowSlackS = 3600; }
    g_refuseLogSec = Config::GetInt(kSec, L"RefusalLogIntervalSec", 60);
    if (g_refuseLogSec < 0)     { g_refuseLogSec = 0; }
    if (g_refuseLogSec > 86400) { g_refuseLogSec = 86400; }

    if (!g_logLockReady) { InitializeCriticalSection(&g_logLock); g_logLockReady = true; }

    // Сверяем ВСЕ площадки до первой записи: несовпадение любой — патч не ставится целиком.
    const Site sites[] =
    {
        { 0x0042AB4F, kOrigGate,   sizeof(kOrigGate)   },
        { 0x00527692, kOrig4001,   sizeof(kOrig4001)   },
        { 0x0052CD3E, kOrig5058,   sizeof(kOrig5058)   },
        { 0x0052773F, kOrigIp4001, sizeof(kOrigIp4001) },
        { 0x0052CF05, kOrigIp5058, sizeof(kOrigIp5058) },
    };
    if (!VerifyAllSites(L"P47", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    int placed = 0;
    // ★ P55 (В4): стаб гейта нужен и при OperatorGmFlag=0, если включён валидатор пакетов (общая точка).
    const bool p55 = P55_GateWanted();
    // ★ P64 (A7): то же для общей преамбулы состояния (общая точка P64_GateWanted).
    const bool p64 = P64_GateWanted();
    // ★ P129 (А6.12): то же для журнала и заглушки чата (общая точка P129_GateWanted).
    const bool p129 = P129_GateWanted();
    if (g_gmGate || p55 || p64 || p129)
    {
        if (!Hook::WriteJmp(0x0042AB4F, &GateStub, sizeof(kOrigGate))) { return PatchResult::Failed; }
        ++placed;
        if (!g_gmGate)
        {
            Log::Line(L"    P47: стаб гейта 0x42AB4F поставлен ради %s%s (OperatorGmFlag=0)",
                      (p55 && p64) ? L"P55/P64" : (p55 ? L"P55" : (p64 ? L"P64" : L"")),
                      p129 ? ((p55 || p64) ? L"/P129" : L"P129") : L"");
        }
    }
    if (g_match20000)
    {
        if (!Hook::WriteJmp(0x00527692, &LogonMatchStub,  sizeof(kOrig4001))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x0052CD3E, &PortalMatchStub, sizeof(kOrig5058))) { return PatchResult::Failed; }
        placed += 2;
        g_logonStubs = true;   // ★ P73: общая точка логона — мост EAC зовётся из P47_LogonMatch
    }
    if (g_sendIp)
    {
        if (!Hook::WriteJmp(0x0052773F, &LogonIpStub,  sizeof(kOrigIp4001))) { return PatchResult::Failed; }
        if (!Hook::WriteJmp(0x0052CF05, &PortalIpStub, sizeof(kOrigIp5058))) { return PatchResult::Failed; }
        placed += 2;
    }

    Log::Line(L"    P47: OperatorGmFlag=%d (опкодов %d, Hack Packet=%d, строка отказа раз в %d с на сессию, 6146 розн.=%d, "
              L"окно отсчёта=%d/+%d с) Match20000=%d SendPeerIp=%d; площадок поставлено %d из 5",
              g_gmGate ? 1 : 0, (int)ARRAYSIZE(kRules), g_countHack ? 1 : 0, g_refuseLogSec, g_tjRetail ? 1 : 0,
              g_tjWindow ? 1 : 0, g_windowSlackS, g_match20000 ? 1 : 0, g_sendIp ? 1 : 0, placed);
    return PatchResult::Applied;
}
