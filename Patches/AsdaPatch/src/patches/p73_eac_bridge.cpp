// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P73 — ★ МОСТ EAC (античит EAC, этап Э1-В, 2026-10-16). [ПОРТ/СЕРВЕР-ДОРАБОТКА]
//  План: `Reports/anticheat/EAC_PLAN.md` §3.1 К3; контракт: `Reports/anticheat/eac/CONTRACT.md` §4–§6.
//  Документ: `AstoryServer/Docs/GameServer/eac-bridge-p73.md`; отчёт: `Reports/anticheat/eac/P73_REPORT.md`.
//
//  GameServer и Indun_GameServer — один образ (сток 4e20f0ad = живой e7b4ac38 по байтам площадок), одна DLL.
//
//  ── ЧТО ДЕЛАЕТ ──
//  Связывает игровые сессии GameServer с сайдкаром AsdaEacServer (TCP 127.0.0.1:Port, по умолчанию 15702, без шифрования):
//    • LOGIN  — на успехе входа 4001 (CharLogonReq 0x527500, вход ветки «тело верно» 0x527692) и 5058 (CharPortalLogonReq
//               0x52CBE0, вход той же ветки 0x52CD3E): userNum, UserIndex (тело пакета, сток тут же пишет его в CUser+0x174),
//               IPv4 пира (P69_SlotIp: живой getpeername, при отказе — кэш соединения);
//    • LOGOUT — на разрыве: Ciocp::SetConnectFlag 0x562910 с флагом 0 (слот Ciocp = userNum: BufferingDisConnect 0x563B60
//               кладёт в кадр 10000 тот же номер). Флаг 1 (accept) на слоте с живой записью — тоже LOGOUT прежней сессии;
//    • KICK   — от сайдкара: очередь по слоту → выполнение в НИТИ КАРТЫ, которой принадлежит игрок, на ближайшем проходе
//               CheckDisConnectUser 0x526C20 (RunProcess 10015, раз в ~1 с — тот же такт, на котором стоковый код и P69 KickOnBlock
//               выводят игрока). Перед киком: CUser в игре (онлайн-список менеджера, CUser+0x174 ≥ 0), CUser+0x174 == userIndex
//               KICK и запись LOGIN этого слота с тем же UserIndex (слот мог переиспользоваться). Кик — ШТАТНОЙ парой стока
//               Send_DisConnectType 0x52EDB0 (4101, тип KickType, по умолчанию 6 — ★ ред. 3) + ___ExceptionDisConnetUser___ 0x526E40,
//               затем продолжение цикла 0x526E36 — ровно как стоковые ветки кика того же цикла. Тип 6 («SpeedHack» таблицы
//               0x5A62AC) у клиента — нотис 1106 «отключён за нечестную игру» (AsdaDisconnectPopupSubsystem ReasonToNoticeId),
//               тот же текст, что при кике по каналу 15901; прежнее умолчание 12 давало нотис 14000 про HackShield (E1-07).
//               P48 этот кик в счётчик автоблока не засчитывает (признак P73_KickInProgress, код «не засчитан» 7), P58 пишет
//               причину «EAC(P73)».
//  Сеть, блокировки и ожидания — ТОЛЬКО в своей фоновой нити. Нити карт/IOCP: копия записи в кольцо под листовой критической
//  секцией (внутри неё ни одного вызова наружу), без системных вызовов.
//
//  ── ОБЩИЕ ТОЧКИ (вторая врезка на те же байты НЕ ставится) ──
//    • 0x527692 / 0x52CD3E — стабы P47 (Match20000). Если P47 их поставил (P47_LogonHooked), P73 зовётся из P47_LogonMatch
//      на ветке «совпало»; иначе P73 ставит свои стабы на те же 6 б (только наблюдение, без ветки отказа).
//    • 0x562910 — детур P61 (SetConnectFlag). Если P61 поставлен (P61_SetConnHooked), P73 зовётся из P61_ResetSlotC; иначе
//      P73 ставит свой детур на те же 5 б.
//    • 0x430B10 — ★ ред. 2 (REBIND): `call charLogonCommunityRes_0` (0x5285F0, ответ БД 2145 DBM_COMMUNITY_INFO_RES) в
//      диспетчере ответов БД → трамплин: сток, затем P73_OnCommunityRes. Учётка сессии — общей точкой P48_IdentityOf (тот же
//      источник, что у счёта киков P48/P69; ★ ред. 3 — ключ свой: [P73_EacBridge] SoulMateSessionAccount). Врезок на 2145 до P73 не было.
//    • 0x526CEB — НОВАЯ площадка (P73 Mode=1): CheckDisConnectUser, вход ветки «CUser есть, +0x174 ≥ 0»
//      (`mov edx,[ebp-0Ch]; mov eax,[edx+0Ch]`, 6 б; переходов внутрь нет — tools/verify_p73.py).
//      ★ P127 (18.11.2026, А2 «живой канал»): эта площадка — ОБЩАЯ ТОЧКА «такт игрока» UserTick. Стаб один (CheckStub), C-часть
//      P73_OnCheckUser: сначала KICK P73 (как было), затем P127_OnUserTick (мост админ-центра). Ставит площадку тот, кто первый
//      (P73 при Mode=1 или P127 через P73_UserTickInstall), вторая врезка на те же байты не ставится. Поведение P73 не меняется.
//      Там же общие точки событий: P73_OnLogon/P73_OnConnFlag первым делом зовут P127_OnLogon/P127_OnConnFlag (независимо от
//      Enabled P73 — их вызывают стабы P47 и детур P61 при любом состоянии P73).
//
//  ── ★ РЕД. 3 (контракт §8, ревизия eac/REVIEW_E1.md) ──
//    • E1-02 привязка к игровому каналу: HELLO ver=2; к LOGIN и REBIND дописан u8[32] bind — ServerChannel::ChannelBinding
//      соединения слота (общая точка P61_SlotBinding → AsdaWire::SlotChannelBinding). Берётся на LOGIN (нить карты, вне замков
//      Ciocp и вне g_lock) и хранится в записи слота: REBIND и снимок после переподключения несут ТОТ ЖЕ bind. Слот Legacy,
//      рукопожатие не завершено или P61 не поставлен — 32 нуля (сайдкар тогда считает сессию незащищённой, причина 6).
//    • E1-07: KickType по умолчанию 6 (клиент — нотис 1106, тот же текст, что у кика по каналу 15901); P48 не засчитывает
//      (P73_KickInProgress, код 7) при любом CountTypes, в том числе 6 из умолчания «3,6».
//      значение [P48_KickAutoBlock] SoulMateSessionAccount (прежнее поведение ред. 2), при отсутствии ключа читается оно же.
//
//  ── ★ §8.6 (повторная ревизия eac/REVIEW_R3.md, 16.10) ──
//    • R3-05: тестовый код P73 (экспорты P73_TestEncode/TestDecode/TestKick/TestSweep/TestSetBind/TestLogonHook и подмена
//      источника bind таблицей стенда) — ТОЛЬКО в стендовой сборке (макрос ASDA_PATCH_STAND, build.bat → out\stand\AsdaPatch.dll).
//      Рабочая out\AsdaPatch.dll их не содержит и не экспортирует (verify_p73.py, dumpbin /exports).
//    • R3-06: гонка LOGIN/LOGOUT — поколение соединения слота g_slotGen (растёт в P73_OnConnFlag под g_lock). P73_OnLogon
//      снимает его ДО P69_SlotIp/SlotBind и сверяет под g_lock перед записью: если за это время слот разорвали или на нём
//      новое соединение, логон относится к ушедшему соединению — LOGIN не пишется (нет фантомной сессии у сайдкара и bind
//      нового соединения не попадёт в старый логон), счётчик loginRaced, строка PatchLog. Нить карты: одно чтение volatile
//      LONG и тот же листовой g_lock — новых замков и вызовов наружу нет.
// ─────────────────────────────────────────────────────────────────────────────
#include <winsock2.h>          // ДО windows.h (Patches.h): иначе windows.h втянет winsock.h v1 и определения разойдутся
#include <ws2tcpip.h>
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

namespace
{
    const wchar_t* kSec = L"P73_EacBridge";

    constexpr int   kSlots        = 0x226;   // userNum / слот Ciocp 0…549 (sub_5328F0: idx < 0x226)
    constexpr int   kOffUserIndex = 0x174;   // CUser: UserIndex (пишут 20000/4001/5058)
    constexpr int   kOffSlot      = 0x18C;   // CUser: слот персонажа
    constexpr DWORD kPingMs       = 5000;    // контракт §4: PING каждые 5 с
    constexpr DWORD kBackoffMinMs = 500;     // первая пауза переподключения
    constexpr DWORD kBackoffMaxMs = 5000;    // контракт/задание: back-off до 5 с
    constexpr DWORD kConnectMs    = 2000;    // предел ожидания connect к 127.0.0.1
    constexpr DWORD kSendTimeoutMs = 3000;   // SO_SNDTIMEO: сайдкар не читает дольше — соединение считаем потерянным
    constexpr DWORD kPollMs       = 50;      // шаг цикла нити: select на приём и выборка очереди LOGIN/LOGOUT

    // ── настройки (patches.ini [P73_EacBridge]) ─────────────────────────────
    volatile LONG g_enabled     = 0;       // 1 — патч поставлен, колбэки работают
    int  g_mode           = 0;             // 0 — журнал (KICK пишется, не выполняется), 1 — KICK выполняется
    int  g_port           = 15702;         // порт сайдкара на 127.0.0.1
    int  g_serverKind     = 2;             // HELLO serverKind: 2 Game, 3 Indun
    int  g_gamePort       = 0;             // HELLO gamePort (ConfigSet\ServerIPPORT.txt, 3-я строка)
    int  g_kickType       = 6;             // ★ ред. 3 (E1-07): тип 4101 кика — 6 (клиент: нотис 1106 «отключён за нечестную игру»)
    bool g_exemptGm       = true;          // оператор (GM-флаг) не кикается — только журнал (вид 83)
    int  g_pendingSec     = 30;            // KICK, не выполненный за столько секунд, отбрасывается (вид 81, причина 3)
    int  g_pongTimeoutSec = 20;            // без единого кадра от сайдкара столько секунд — переподключение (0 — не следить)
    int  g_queueCap       = 4096;          // ёмкость кольца LOGIN/LOGOUT
    bool g_soulSession    = true;          // ★ ред. 3 (E1-20): [P73_EacBridge] SoulMateSessionAccount (умолчание — значение ключа P48)

    // ── функции GameServer ──────────────────────────────────────────────────
    typedef void  (__fastcall *PFN_Disc)(void* self, void* edx, int userNum, int type);           // sub_52EDB0 (thiscall i16,u8)
    typedef void* (__fastcall *PFN_ExcDisc)(void* self, void* edx, int userNum, const char* fn);  // sub_526E40
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                        // sub_569DF0
    PFN_Disc    const pDisc    = (PFN_Disc)   0x0052EDB0;
    PFN_ExcDisc const pExcDisc = (PFN_ExcDisc)0x00526E40;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    // ── типы кадров (контракт §4) ───────────────────────────────────────────
    enum FrameType : BYTE
    {
        kFrHello  = 0x10,   // P73→С: u8 ver=2 (ред. 3) · u8 serverKind · u32 pid · u16 gamePort
        kFrLogin  = 0x11,   // P73→С: u16 userNum · u32 userIndex · u32 ipv4 (сетевой порядок) · u32 seq · u8[32] bind (ред. 3)
        kFrLogout = 0x12,   // P73→С: u16 userNum · u32 userIndex · u32 seq
        kFrRebind = 0x13,   // P73→С: u16 userNum · u32 oldUserIndex · u32 sessionUserIndex · u32 seq · u8[32] bind (ред. 2/3)
        kFrPing   = 0x14,   // P73→С: пусто
        kFrKick   = 0x21,   // С→P73: u16 userNum · u32 userIndex · u8 ourReason · u8 eosReason
        kFrPong   = 0x24,   // С→P73: пусто
    };
    constexpr int kFrameMax  = 4096;       // предел поля len (type + payload)
    constexpr int kKickBody  = 8;          // длина полезной нагрузки KICK
    constexpr BYTE kHelloVer = 2;          // ★ ред. 3: версия моста в HELLO (LOGIN/REBIND с bind)
    constexpr int kBind      = 32;         // ★ ред. 3: длина bind (AsdaSecure::kBindLen)
    constexpr int kLoginBody = 14 + kBind; // ★ ред. 3: LOGIN = 14 + bind = 46 б
    constexpr int kRebindBody = 14 + kBind;// ★ ред. 3: REBIND = 14 + bind = 46 б
}

// ═════════════════════════════ кодек кадров ═════════════════════════════════
//   Кадр: u16 len (type + payload, little-endian) · u8 type · payload. 1 ≤ len ≤ 4096.
namespace P73Wire
{
    // Собрать кадр в out. Возврат — длина кадра (3 + n) или −1 (n вне 0…4095 / мало места).
    int Encode(BYTE type, const BYTE* payload, int n, BYTE* out, int cap)
    {
        if (n < 0 || n > kFrameMax - 1 || cap < 3 + n || !out) { return -1; }
        const WORD len = (WORD)(n + 1);
        out[0] = (BYTE)(len & 0xFF);
        out[1] = (BYTE)(len >> 8);
        out[2] = type;
        if (n) { memcpy(out + 3, payload, n); }
        return 3 + n;
    }

    // Накопитель приёма: сырые байты сокета, из которых вынимаются целые кадры.
    struct Rx
    {
        BYTE buf[2 * (kFrameMax + 2)];   // запас на один целый кадр + хвост следующего
        int  len;                        // байт в buf
    };

    // Вынуть один целый кадр из начала rx. Возврат: 1 — кадр есть (type/payload/n заполнены, указатель payload живёт до
    //   следующего Consume), 0 — нужно больше байт, −1 — нарушение протокола (len == 0 или len > 4096).
    int Peek(const Rx& rx, BYTE* type, const BYTE** payload, int* n)
    {
        if (rx.len < 2) { return 0; }
        const int len = rx.buf[0] | (rx.buf[1] << 8);
        if (len < 1 || len > kFrameMax) { return -1; }
        if (rx.len < 2 + len) { return 0; }
        *type = rx.buf[2];
        *payload = rx.buf + 3;
        *n = len - 1;
        return 1;
    }

    // Снять первый кадр (после Peek == 1).
    void Consume(Rx& rx)
    {
        const int len = rx.buf[0] | (rx.buf[1] << 8);
        const int total = 2 + len;
        memmove(rx.buf, rx.buf + total, rx.len - total);
        rx.len -= total;
    }

    // Записать little-endian значения в буфер.
    inline void Put16(BYTE* p, WORD v)  { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); }
    inline void Put32(BYTE* p, DWORD v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); p[2] = (BYTE)(v >> 16); p[3] = (BYTE)(v >> 24); }
    inline WORD  Get16(const BYTE* p)   { return (WORD)(p[0] | (p[1] << 8)); }
    inline DWORD Get32(const BYTE* p)   { return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24); }
}

namespace
{
    // ── таблица сессий и кольцо исходящих событий (под g_lock — листовая секция) ──
    struct Sess
    {
        bool  active;      // LOGIN был, LOGOUT ещё нет
        int   sessionIndex;// ★ ред. 2: учётка сессии из REBIND (вход соулмейтом), 0 — совпадает с userIndex / неизвестна
        int   userIndex;   // UserIndex логона
        DWORD ip;          // IPv4 пира (сетевой порядок), 0 — не определён
        BYTE  bind[kBind]; // ★ ред. 3: привязка канала соединения слота на момент LOGIN (нули — Legacy / P61 нет)
    };
    Sess g_sess[kSlots] = {};

    struct OutEv
    {
        BYTE  type;        // kFrLogin / kFrLogout / kFrRebind
        short userNum;     // слот
        int   userIndex;   // UserIndex
        DWORD ip;          // для LOGIN; для REBIND — sessionUserIndex
        BYTE  bind[kBind]; // ★ ред. 3: bind слота для LOGIN/REBIND (для LOGOUT не используется)
    };

#ifdef ASDA_PATCH_STAND
    // ★ ред. 3: подмена источника bind для стенда (P73_TestSetBind); ★ §8.6 R3-05 — только в стендовой сборке.
    volatile LONG g_testBindOn = 0;        // 1 — стенд задал таблицу bind (источник P61 не опрашивается)
    BYTE          g_testBind[kSlots][kBind] = {};   // bind слотов, заданные стендом (нули — «Legacy»)
    // ★ §8.6 R3-06: обратный вызов стенда между SlotBind и записью LOGIN (имитация разрыва слота в этот момент).
    typedef void (__stdcall *PFN_TestLogonHook)(int slot);
    PFN_TestLogonHook volatile g_testLogonHook = nullptr;
#endif
    // ★ §8.6 R3-06: поколение соединения слота — растёт на каждом SetConnectFlag (разрыв/accept) под g_lock.
    volatile LONG g_slotGen[kSlots] = {};
    OutEv*        g_ring      = nullptr;   // g_queueCap записей
    int           g_head      = 0;         // следующая на выдачу
    int           g_count     = 0;         // записей в кольце
    bool          g_connected = false;     // нить держит соединение — события ставятся в кольцо (иначе только таблица)
    LONG          g_dropped   = 0;         // отброшено при переполнении в текущем эпизоде (под g_lock)
    CRITICAL_SECTION g_lock;
    bool          g_lockReady = false;

    // ── отложенный KICK по слоту ────────────────────────────────────────────
    struct PendKick
    {
        int   userIndex;   // 0 — нет (UserIndex KICK; учётка 0 у сайдкара не бывает — отвергается при приёме)
        BYTE  ourReason;   // контракт §5
        BYTE  eosReason;   // EOS_EAntiCheatCommonClientActionReason
        DWORD tick;        // такт постановки
    };
    PendKick      g_kick[kSlots] = {};
    volatile LONG g_kickPending  = 0;      // сколько слотов с отложенным KICK (быстрый выход в нити карты)

    // ── признак «идёт кик P73» для P48/P58 (та же нить: Send_DisConnectType синхронен) ──
    __declspec(thread) int t_inKick = 0;   // 0 — нет; иначе 0x100 | ourReason

    // ── статистика (экспорт P73_GetStats — стенд) ──
    P73_Stats g_stats = {};

    volatile LONG g_seq = 0;               // seq LOGIN/LOGOUT, монотонно в пределах процесса
    HANDLE        g_thread = nullptr;

    // ── журнал P53: ac.other 77–84 ──
    void Journal(BYTE kind, int userNum, int userIndex, DWORD ip, int v0, int v1, int v2, const char* detail,
                 const BYTE* user = nullptr, int opcode = AcJournal::kNone)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.userNum   = (short)userNum;
        e.userIndex = userIndex;
        e.ip        = ip;
        e.opcode    = opcode;
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        if (user)
        {
            __try { e.charSlot = user[kOffSlot]; AcJournal::CopyName(e, user + Srv::kOffCharName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (detail) { AcJournal::CopyText(e, detail); }
        AcJournal::Push(e);
    }

    // Поставить событие в кольцо (под g_lock). Нет соединения — не ставится (после подключения нить сама разошлёт LOGIN всех
    //   активных). Переполнение — событие отбрасывается, счётчик эпизода растёт; нить переподключится (ресинхронизация).
    void EnqueueLocked(BYTE type, int userNum, int userIndex, DWORD ip, const BYTE* bind = nullptr)
    {
        if (!g_connected || !g_ring) { return; }
        if (g_count >= g_queueCap) { ++g_dropped; InterlockedIncrement(&g_stats.queueDropped); return; }
        OutEv& e = g_ring[(g_head + g_count) % g_queueCap];
        e.type = type; e.userNum = (short)userNum; e.userIndex = userIndex; e.ip = ip;
        if (bind) { memcpy(e.bind, bind, kBind); } else { memset(e.bind, 0, kBind); }   // ★ ред. 3
        ++g_count;
    }

    // ★ ред. 3: bind соединения слота — общая точка P61 (ServerChannel::ChannelBinding под замком слота моста). Нить карты, вне
    //   g_lock и вне замка Ciocp. false (out = нули) — Legacy / рукопожатие не завершено / P61 не поставлен / слот сброшен.
    bool SlotBind(int slot, BYTE out[kBind])
    {
        memset(out, 0, kBind);
#ifdef ASDA_PATCH_STAND
        if (g_testBindOn)
        {
            memcpy(out, g_testBind[slot], kBind);
            for (int i = 0; i < kBind; ++i) { if (out[i]) { return true; } }
            return false;
        }
#endif
        if (!P61_SlotBinding(slot, out)) { memset(out, 0, kBind); return false; }
        return true;
    }

    // Снять отложенный KICK слота (под g_lock). Возврат — снятая запись (userIndex 0 — не было).
    PendKick TakeKickLocked(int slot)
    {
        PendKick k = g_kick[slot];
        if (k.userIndex)
        {
            g_kick[slot].userIndex = 0;
            InterlockedDecrement(&g_kickPending);
        }
        return k;
    }

    void Lock()   { if (g_lockReady) { EnterCriticalSection(&g_lock); } }
    void Unlock() { if (g_lockReady) { LeaveCriticalSection(&g_lock); } }

    void IpText(DWORD ip, char* out, int cch)
    {
        const BYTE* q = (const BYTE*)&ip;
        _snprintf_s(out, cch, _TRUNCATE, "%u.%u.%u.%u", q[0], q[1], q[2], q[3]);
    }
}

// ═════════════════════════ общие точки (зовут P47/P61/стабы) ═════════════════

// LOGIN: успех 4001 (kind 1) / 5058 (kind 2). Нить карты (диспетчер). user — CUser слота, userIndex — из тела логона.
extern "C" void __stdcall P73_OnLogon(int kind, int userNum, BYTE* user, int userIndex)
{
    P127_OnLogon(kind, userNum, user, userIndex);   // ★ P127: общая точка входа (только таблица слота под листовым замком)
    (void)kind; (void)user;
    if (!g_enabled || userNum < 0 || userNum >= kSlots || userIndex < 0) { return; }
    const LONG gen0 = g_slotGen[userNum];        // ★ §8.6 R3-06: поколение соединения слота до сбора LOGIN (вне замков)
    const DWORD ip = P69_SlotIp(userNum);       // живой getpeername (кэш соединения — запасной путь)
    BYTE bind[kBind];
    const bool bound = SlotBind(userNum, bind);  // ★ ред. 3: bind игрового соединения (до g_lock: берёт замок слота моста P61)
#ifdef ASDA_PATCH_STAND
    if (PFN_TestLogonHook h = g_testLogonHook) { h(userNum); }   // стенд: разрыв слота «между SlotBind и записью»
#endif
    PendKick stale = {};
    Lock();
    if (g_slotGen[userNum] != gen0)
    {
        // ★ §8.6 R3-06: пока собирался LOGIN, соединение слота разорвано или заменено (P73_OnConnFlag уже снял сессию) —
        //   логон принадлежит ушедшему соединению: LOGIN не пишется (иначе LOGIN после LOGOUT — фантом у сайдкара, а при
        //   новом соединении — bind чужого рукопожатия в старом логоне).
        const LONG gen1 = g_slotGen[userNum];
        Unlock();
        InterlockedIncrement(&g_stats.loginRaced);
        Log::Line(L"[P73] LOGIN не записан: userNum %d, UserIndex %d — соединение слота сменилось во время входа (поколение %ld → %ld)",
                  userNum, userIndex, gen0, gen1);
        return;
    }
    Sess& s = g_sess[userNum];
    if (s.active && s.userIndex != userIndex)
    {
        EnqueueLocked(kFrLogout, userNum, s.userIndex, 0);   // в слоте прежняя сессия без разрыва — закрыть её у сайдкара
    }
    if (g_kick[userNum].userIndex && g_kick[userNum].userIndex != userIndex) { stale = TakeKickLocked(userNum); }
    s.active = true; s.userIndex = userIndex; s.ip = ip; s.sessionIndex = 0;   // новый логон — REBIND заново по 2145
    memcpy(s.bind, bind, kBind);
    EnqueueLocked(kFrLogin, userNum, userIndex, ip, bind);
    Unlock();
    InterlockedIncrement(&g_stats.logons);
    if (!bound) { InterlockedIncrement(&g_stats.loginBindZero); }
    if (stale.userIndex)
    {
        InterlockedIncrement(&g_stats.kickDropped);
        Journal(81, userNum, stale.userIndex, ip, stale.ourReason, stale.eosReason, 4, "P73 KICK dropped: slot re-logged by another UserIndex");
    }
}

// Разрыв/accept слота: Ciocp::SetConnectFlag(slot, flag). Нить IOCP/accept, ПОД замком Ciocp — только таблица и кольцо.
extern "C" void __stdcall P73_OnConnFlag(int slot, int flag)
{
    P127_OnConnFlag(slot, flag);   // ★ P127: общая точка разрыва (нить IOCP под замком Ciocp — только таблица слота, листовой замок)
    P128_OnConnFlag(slot, flag);   // ★ P128 (А5.10): сброс таблицы значков слота (без замков и вызовов наружу)
    (void)flag;   // и 0 (разрыв), и 1 (новое соединение на слоте) закрывают прежнюю сессию слота
    if (!g_enabled || slot < 0 || slot >= kSlots) { return; }
    PendKick stale = {};
    int ui = 0; DWORD ip = 0; bool was = false;
    Lock();
    InterlockedIncrement(&g_slotGen[slot]);   // ★ §8.6 R3-06: новое поколение соединения слота (сверяет P73_OnLogon)
    Sess& s = g_sess[slot];
    if (s.active)
    {
        was = true; ui = s.userIndex; ip = s.ip;
        EnqueueLocked(kFrLogout, slot, s.userIndex, 0);
        s.active = false; s.userIndex = 0; s.ip = 0; s.sessionIndex = 0;
        memset(s.bind, 0, kBind);   // ★ ред. 3
    }
    stale = TakeKickLocked(slot);
    Unlock();
    if (was) { InterlockedIncrement(&g_stats.logouts); }
    if (stale.userIndex)
    {
        InterlockedIncrement(&g_stats.kickDropped);
        Journal(81, slot, stale.userIndex, ip, stale.ourReason, stale.eosReason, 4, "P73 KICK dropped: session left before kick");
    }
    (void)ui;
}

// ★ ред. 2: ответ БД 2145 обработан стоком (charLogonCommunityRes_0 записал блок соулмейта CUser+0x182B9…). Нить карты.
//   Вход соулмейтом (SoulState 2) с известной учёткой сессии ≠ CUser+0x174 → REBIND (один раз на логон; повтор — только при смене).
extern "C" void __stdcall P73_OnCommunityRes(void* mgr, int userNum)
{
    userNum = (short)userNum;
    if (!g_enabled || !mgr || userNum < 0 || userNum >= kSlots) { return; }
    int owner = 0, account = 0; bool mate = false;
    __try
    {
        const BYTE* u = (const BYTE*)((BYTE* (__fastcall*)(void*, void*, int))Srv::kGetUser)(mgr, nullptr, (short)userNum);
        if (!u) { return; }
        owner = *(const int*)(u + kOffUserIndex);
        P48_Identity id;
        P48_IdentityOf(u, owner, g_soulSession, &id);   // общая точка P48/P69: SoulState 2 → iMateUserIndex CUser+0x182C6
        mate = id.soulMate; account = id.account;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!mate || account <= 0 || account == owner) { return; }
    bool sent = false;
    Lock();
    Sess& s = g_sess[userNum];
    if (s.active && s.userIndex == owner && s.sessionIndex != account)
    {
        s.sessionIndex = account;
        EnqueueLocked(kFrRebind, userNum, owner, (DWORD)account, s.bind);   // ★ ред. 3: тот же bind слота, что в LOGIN
        sent = true;
    }
    Unlock();
    if (sent)
    {
        InterlockedIncrement(&g_stats.rebinds);
        Log::Line(L"[P73] вход соулмейтом: userNum %d — персонаж учётки %d, учётка сессии %d → REBIND", userNum, owner, account);
    }
}

// ★ Признак «идёт кик P73» в этой нити: 0 — нет, иначе 0x100 | ourReason. Зовут P48 (не засчитывать) и P58 (имя причины).
int P73_KickInProgress()
{
    return t_inKick;
}

// Нить карты, CheckDisConnectUser (площадка 0x526CEB): KICK P73. 1 — игрок выведен, 0 — нет.
static int P73_KickCheck(void* mgr, int userNum, BYTE* user)
{
    if (!g_kickPending) { return 0; }                                   // быстрый выход: KICK в очереди нет
    userNum = (short)userNum;
    if (userNum < 0 || userNum >= kSlots || !user || !mgr) { return 0; }
    if (!*(volatile int*)&g_kick[userNum].userIndex) { return 0; }
    Lock();
    const PendKick k = TakeKickLocked(userNum);
    const Sess s = g_sess[userNum];
    Unlock();
    if (!k.userIndex) { return 0; }                                     // другая нить уже сняла

    int cur = -1;
    __try { cur = *(const int*)(user + kOffUserIndex); } __except (EXCEPTION_EXECUTE_HANDLER) { cur = -1; }
    char d[64];
    if (cur != k.userIndex || !s.active || s.userIndex != k.userIndex)
    {
        InterlockedIncrement(&g_stats.kickDropped);
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P73 KICK dropped: CUser+0x174 %d, LOGIN %d", cur, s.active ? s.userIndex : -1);
        Journal(81, userNum, k.userIndex, s.ip, k.ourReason, k.eosReason, 2, d, user);
        Log::Line(L"[P73] KICK отброшен: userNum %d — UserIndex KICK %d, в CUser %d, в записи LOGIN %d (слот переиспользован)",
                  userNum, k.userIndex, cur, s.active ? s.userIndex : -1);
        return 0;
    }
    if (g_exemptGm && P47_IsGmUser(mgr, userNum))
    {
        InterlockedIncrement(&g_stats.kickOperator);
        Journal(83, userNum, k.userIndex, s.ip, k.ourReason, k.eosReason, 1, "P73 KICK not executed: operator (GM flag)", user);
        Log::Line(L"[P73] KICK НЕ выполнен: userNum %d, UserIndex %d — оператор (GM-флаг), причина %d/%d — только журнал",
                  userNum, k.userIndex, k.ourReason, k.eosReason);
        return 0;
    }

    const DWORD waited = GetTickCount() - k.tick;
    char ip[20]; IpText(s.ip, ip, sizeof(ip));
    __try
    {
        pSrvLog(Srv::kLogCatOperator, "P73 EacBridge: KICK UserNum %d, UserIndex %d, CharN %s, IP %s, reason %d/%d, type %d, waited %u ms",
                userNum, k.userIndex, (const char*)(user + Srv::kOffCharName), ip, (int)k.ourReason, (int)k.eosReason, g_kickType, waited);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    Log::Line(L"[P73] KICK выполнен: userNum %d, UserIndex %d, причина %d (EOS %d), 4101 тип %d, ожидание %u мс",
              userNum, k.userIndex, k.ourReason, k.eosReason, g_kickType, waited);
    _snprintf_s(d, sizeof(d), _TRUNCATE, "P73 KICK done: 4101 type %d, waited %u ms", g_kickType, waited);
    Journal(80, userNum, k.userIndex, s.ip, k.ourReason, k.eosReason, g_kickType, d, user, 4101);   // до разрыва: CUser ещё цел

    t_inKick = 0x100 | k.ourReason;
    __try
    {
        pDisc(mgr, nullptr, (short)userNum, g_kickType);                       // 4101 + Sleep(50); P48 — не засчитывает (код 7)
        pExcDisc(mgr, nullptr, (short)userNum, "P73 EacBridge: EAC kick");    // ___ExceptionDisConnetUser___ + разрыв
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log::Line(L"[P73] ! исключение при кике userNum %d — пропущен", userNum);
    }
    t_inKick = 0;
    InterlockedIncrement(&g_stats.kickDone);
    return 1;
}

// ★ P127: ОБЩАЯ ТОЧКА UserTick — C-часть стаба 0x526CEB (нить карты, CheckDisConnectUser, CUser в игре). Сначала KICK P73 (поведение
//   P73 прежнее), затем такт моста админ-центра P127 (снимок присутствия, команды). 1 — игрок выведен (стаб продолжит цикл 0x526E36).
extern "C" int __stdcall P73_OnCheckUser(void* mgr, int userNum, BYTE* user)
{
    if (P73_KickCheck(mgr, userNum, user)) { return 1; }
    P128_OnUserTick(mgr, userNum, user);   // ★ P128 (А5.10): значок события Event.dat всем — только чтение зеркала и 6039/6041 своему игроку
    return P127_OnUserTick(mgr, userNum, user);
}

// ═════════════════════════════ нить моста ═══════════════════════════════════
namespace
{
    // Отправить всё (блокирующий сокет, SO_SNDTIMEO). false — соединение потеряно.
    bool SendAll(SOCKET s, const BYTE* p, int n)
    {
        while (n > 0)
        {
            const int w = send(s, (const char*)p, n, 0);
            if (w <= 0) { return false; }
            p += w; n -= w;
        }
        return true;
    }

    bool SendFrame(SOCKET s, BYTE type, const BYTE* payload, int n)
    {
        BYTE f[64];
        const int len = P73Wire::Encode(type, payload, n, f, sizeof(f));
        return len > 0 && SendAll(s, f, len);
    }

    // ★ ред. 3: LOGIN v2 — u16 userNum · u32 userIndex · u32 ipv4 · u32 seq · u8[32] bind (46 б).
    bool SendLogin(SOCKET s, int userNum, int userIndex, DWORD ip, const BYTE* bind)
    {
        BYTE p[kLoginBody];
        P73Wire::Put16(p, (WORD)userNum);
        P73Wire::Put32(p + 2, (DWORD)userIndex);
        memcpy(p + 6, &ip, 4);                                     // sin_addr как есть: байты a.b.c.d (сетевой порядок)
        P73Wire::Put32(p + 10, (DWORD)InterlockedIncrement(&g_seq));
        memcpy(p + 14, bind, kBind);
        if (!SendFrame(s, kFrLogin, p, sizeof(p))) { return false; }
        InterlockedIncrement(&g_stats.loginSent);
        return true;
    }

    // ★ ред. 2/3: REBIND — u16 userNum · u32 oldUserIndex · u32 sessionUserIndex · u32 seq · u8[32] bind (46 б).
    bool SendRebind(SOCKET s, int userNum, int oldUserIndex, int sessionUserIndex, const BYTE* bind)
    {
        BYTE p[kRebindBody];
        P73Wire::Put16(p, (WORD)userNum);
        P73Wire::Put32(p + 2, (DWORD)oldUserIndex);
        P73Wire::Put32(p + 6, (DWORD)sessionUserIndex);
        P73Wire::Put32(p + 10, (DWORD)InterlockedIncrement(&g_seq));
        memcpy(p + 14, bind, kBind);
        if (!SendFrame(s, kFrRebind, p, sizeof(p))) { return false; }
        InterlockedIncrement(&g_stats.rebindSent);
        return true;
    }

    bool SendLogout(SOCKET s, int userNum, int userIndex)
    {
        BYTE p[10];
        P73Wire::Put16(p, (WORD)userNum);
        P73Wire::Put32(p + 2, (DWORD)userIndex);
        P73Wire::Put32(p + 6, (DWORD)InterlockedIncrement(&g_seq));
        if (!SendFrame(s, kFrLogout, p, sizeof(p))) { return false; }
        InterlockedIncrement(&g_stats.logoutSent);
        return true;
    }

    // Неблокирующий connect к 127.0.0.1:port с пределом kConnectMs; возвращает блокирующий сокет или INVALID_SOCKET.
    SOCKET ConnectLocal(int port, int* errOut)
    {
        *errOut = 0;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { *errOut = WSAGetLastError(); return INVALID_SOCKET; }
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_port = htons((u_short)port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);                // контракт §4: ТОЛЬКО 127.0.0.1
        if (connect(s, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR)
        {
            const int e = WSAGetLastError();
            if (e != WSAEWOULDBLOCK) { *errOut = e; closesocket(s); return INVALID_SOCKET; }
            fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
            timeval tv = { (long)(kConnectMs / 1000), (long)((kConnectMs % 1000) * 1000) };
            const int r = select(0, nullptr, &wr, &ex, &tv);
            if (r <= 0 || FD_ISSET(s, &ex) || !FD_ISSET(s, &wr))
            {
                int soErr = 0, sl = sizeof(soErr);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &sl);
                *errOut = r == 0 ? WSAETIMEDOUT : (soErr ? soErr : WSAECONNREFUSED);
                closesocket(s);
                return INVALID_SOCKET;
            }
        }
        nb = 0;
        ioctlsocket(s, FIONBIO, &nb);
        BOOL nd = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
        DWORD to = kSendTimeoutMs;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
        return s;
    }

    // KICK от сайдкара (нить моста). payload — 8 б.
    void OnKickFrame(const BYTE* p)
    {
        const int   userNum   = (short)P73Wire::Get16(p);
        const int   userIndex = (int)P73Wire::Get32(p + 2);
        const BYTE  ourReason = p[6];
        const BYTE  eosReason = p[7];
        InterlockedIncrement(&g_stats.kickReceived);
        if (g_mode != 1)
        {
            DWORD ip = 0;
            if (userNum >= 0 && userNum < kSlots) { Lock(); ip = g_sess[userNum].ip; Unlock(); }
            Journal(79, userNum, userIndex, ip, ourReason, eosReason, 0, "P73 KICK received (Mode=0: journal only)");
            Log::Line(L"[P73] KICK получен (Mode=0 — только журнал): userNum %d, UserIndex %d, причина %d (EOS %d)",
                      userNum, userIndex, ourReason, eosReason);
            return;
        }
        int why = 0; int slotIndex = -1; DWORD ip = 0;
        Lock();
        if (userNum < 0 || userNum >= kSlots || userIndex <= 0)   { why = 1; }
        else if (!g_sess[userNum].active)                         { why = 1; }
        else if (g_sess[userNum].userIndex != userIndex)          { why = 2; slotIndex = g_sess[userNum].userIndex; ip = g_sess[userNum].ip; }
        else
        {
            ip = g_sess[userNum].ip;
            if (!g_kick[userNum].userIndex) { InterlockedIncrement(&g_kickPending); }
            g_kick[userNum].userIndex = userIndex;
            g_kick[userNum].ourReason = ourReason;
            g_kick[userNum].eosReason = eosReason;
            g_kick[userNum].tick      = GetTickCount();
        }
        Unlock();
        if (why)
        {
            InterlockedIncrement(&g_stats.kickDropped);
            char d[64];
            _snprintf_s(d, sizeof(d), _TRUNCATE, "P73 KICK dropped on receive: slot LOGIN %d", slotIndex);
            Journal(81, userNum, userIndex, ip, ourReason, eosReason, why, d);
            Log::Line(L"[P73] KICK отброшен при приёме: userNum %d, UserIndex %d — %s (в слоте %d)", userNum, userIndex,
                      why == 1 ? L"в слоте нет сессии" : L"в слоте другой UserIndex", slotIndex);
            return;
        }
        InterlockedIncrement(&g_stats.kickQueued);
        Journal(79, userNum, userIndex, ip, ourReason, eosReason, 1, "P73 KICK received, queued for map thread");
        Log::Line(L"[P73] KICK получен: userNum %d, UserIndex %d, причина %d (EOS %d) — в очереди нити карты", userNum, userIndex,
                  ourReason, eosReason);
    }

    // Отбросить отложенные KICK старше g_pendingSec (нить моста, раз в секунду).
    void SweepExpired()
    {
        if (!g_kickPending) { return; }
        const DWORD now = GetTickCount();
        for (int i = 0; i < kSlots; ++i)
        {
            if (!*(volatile int*)&g_kick[i].userIndex) { continue; }
            PendKick k = {}; DWORD ip = 0;
            Lock();
            if (g_kick[i].userIndex && (DWORD)(now - g_kick[i].tick) >= (DWORD)g_pendingSec * 1000u)
            {
                k = TakeKickLocked(i);
                ip = g_sess[i].ip;
            }
            Unlock();
            if (k.userIndex)
            {
                InterlockedIncrement(&g_stats.kickExpired);
                Journal(81, i, k.userIndex, ip, k.ourReason, k.eosReason, 3, "P73 KICK dropped: not executed in KickPendingSec");
                Log::Line(L"[P73] KICK отброшен: userNum %d, UserIndex %d — не выполнен за %d с (проход CheckDisConnectUser не дошёл)",
                          i, k.userIndex, g_pendingSec);
            }
        }
    }

    // Причины потери соединения (вид 78, item_code).
    enum LossReason { kLossRecv = 1, kLossSend = 2, kLossPong = 3, kLossProto = 4, kLossResync = 5 };

    const wchar_t* LossText(int r)
    {
        return r == kLossRecv ? L"сайдкар закрыл соединение / ошибка приёма" : r == kLossSend ? L"ошибка отправки"
             : r == kLossPong ? L"нет кадров от сайдкара дольше PongTimeoutSec" : r == kLossProto ? L"нарушение протокола сайдкаром"
             : L"ресинхронизация после переполнения очереди";
    }

    // Одна сессия соединения. Возврат — причина потери, *wsaErr — код Winsock (0 — нет), *wasUp — HELLO и LOGIN всех ушли
    //   (сессия состоялась; иначе это неудачная попытка подключения, а не «потеря»).
    int RunSession(SOCKET s, int* wsaErr, bool* wasUp)
    {
        *wsaErr = 0;
        *wasUp = false;
        // Снимок активных сессий и включение кольца — атомарно: всё, что придёт после, ляжет в кольцо.
        static Sess snap[kSlots];
        Lock();
        g_connected = true; g_head = 0; g_count = 0; g_dropped = 0;
        memcpy(snap, g_sess, sizeof(snap));
        Unlock();

        BYTE h[8];
        h[0] = kHelloVer;                                          // ver (★ ред. 3: 2 — LOGIN/REBIND с bind)
        h[1] = (BYTE)g_serverKind;
        P73Wire::Put32(h + 2, GetCurrentProcessId());
        P73Wire::Put16(h + 6, (WORD)g_gamePort);
        int relogin = 0, zeroBind = 0;
        if (!SendFrame(s, kFrHello, h, sizeof(h))) { *wsaErr = WSAGetLastError(); return kLossSend; }
        for (int i = 0; i < kSlots; ++i)
        {
            if (!snap[i].active) { continue; }
            { int nz = 0; for (int k = 0; k < kBind; ++k) { nz |= snap[i].bind[k]; } if (!nz) { ++zeroBind; } }   // ★ ред. 3
            // ★ ред. 3: bind из записи слота (взят на LOGIN) — тот же, что ушёл в первом LOGIN этой сессии
            if (!SendLogin(s, i, snap[i].userIndex, snap[i].ip, snap[i].bind)) { *wsaErr = WSAGetLastError(); return kLossSend; }
            // ★ ред. 2: вход соулмейтом — сразу за LOGIN снова REBIND на учётку сессии
            if (snap[i].sessionIndex && !SendRebind(s, i, snap[i].userIndex, snap[i].sessionIndex, snap[i].bind)) { *wsaErr = WSAGetLastError(); return kLossSend; }
            ++relogin;
        }
        *wasUp = true;
        InterlockedIncrement(&g_stats.connects);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P73 up 127.0.0.1:%d pid %u gamePort %d", g_port, GetCurrentProcessId(), g_gamePort);
        Journal(77, -1, AcJournal::kNone, 0, g_serverKind, g_port, relogin, d);
        Log::Line(L"[P73] мост подключён: 127.0.0.1:%d, HELLO v%d (вид сервера %d, PID %u, игровой порт %d), LOGIN всех в игре: %d "
                  L"(из них с нулевым bind: %d)", g_port, (int)kHelloVer, g_serverKind, GetCurrentProcessId(), g_gamePort, relogin, zeroBind);

        static P73Wire::Rx rx;
        rx.len = 0;
        DWORD lastPing = GetTickCount(), lastRx = lastPing, lastSweep = lastPing;
        static OutEv batch[256];
        for (;;)
        {
            if (!g_enabled) { return kLossRecv; }
            // 1) исходящие LOGIN/LOGOUT
            for (;;)
            {
                int n = 0; LONG dropped = 0;
                Lock();
                dropped = g_dropped;
                while (n < ARRAYSIZE(batch) && g_count > 0)
                {
                    batch[n++] = g_ring[g_head];
                    g_head = (g_head + 1) % g_queueCap; --g_count;
                }
                Unlock();
                if (dropped)
                {
                    // Событие потеряно — сайдкар видит неполную картину: переподключиться и разослать LOGIN всех заново.
                    char t[64];
                    _snprintf_s(t, sizeof(t), _TRUNCATE, "P73 queue overflow: %d dropped, cap %d; resync", (int)dropped, g_queueCap);
                    Journal(82, -1, AcJournal::kNone, 0, (int)dropped, g_queueCap, 0, t);
                    Log::Line(L"[P73] очередь LOGIN/LOGOUT переполнена (ёмкость %d): отброшено %d — переподключение с повторной рассылкой",
                              g_queueCap, (int)dropped);
                    return kLossResync;
                }
                for (int i = 0; i < n; ++i)
                {
                    const bool ok = batch[i].type == kFrLogin  ? SendLogin(s, batch[i].userNum, batch[i].userIndex, batch[i].ip, batch[i].bind)
                                  : batch[i].type == kFrRebind ? SendRebind(s, batch[i].userNum, batch[i].userIndex, (int)batch[i].ip, batch[i].bind)
                                                              : SendLogout(s, batch[i].userNum, batch[i].userIndex);
                    if (!ok) { *wsaErr = WSAGetLastError(); return kLossSend; }
                }
                if (n < ARRAYSIZE(batch)) { break; }
            }
            // 2) PING / слежение за сайдкаром / просроченные KICK
            const DWORD now = GetTickCount();
            if (now - lastPing >= kPingMs)
            {
                if (!SendFrame(s, kFrPing, nullptr, 0)) { *wsaErr = WSAGetLastError(); return kLossSend; }
                lastPing = now;
                InterlockedIncrement(&g_stats.pingSent);
            }
            if (g_pongTimeoutSec > 0 && now - lastRx >= (DWORD)g_pongTimeoutSec * 1000u) { return kLossPong; }
            if (now - lastSweep >= 1000) { SweepExpired(); lastSweep = now; }
            // 3) приём
            fd_set rd; FD_ZERO(&rd); FD_SET(s, &rd);
            timeval tv = { 0, (long)kPollMs * 1000 };
            const int r = select(0, &rd, nullptr, nullptr, &tv);
            if (r == SOCKET_ERROR) { *wsaErr = WSAGetLastError(); return kLossRecv; }
            if (r == 0) { continue; }
            const int got = recv(s, (char*)rx.buf + rx.len, (int)sizeof(rx.buf) - rx.len, 0);
            if (got <= 0) { *wsaErr = got < 0 ? WSAGetLastError() : 0; return kLossRecv; }
            rx.len += got;
            lastRx = GetTickCount();
            for (;;)
            {
                BYTE type = 0; const BYTE* pl = nullptr; int n = 0;
                const int pr = P73Wire::Peek(rx, &type, &pl, &n);
                if (pr == 0) { break; }
                bool bad = pr < 0;
                if (!bad)
                {
                    if (type == kFrKick && n == kKickBody)   { OnKickFrame(pl); }
                    else if (type == kFrPong && n == 0)      { InterlockedIncrement(&g_stats.pongReceived); }
                    else                                     { bad = true; }
                }
                if (bad)
                {
                    const int len = rx.len >= 2 ? (rx.buf[0] | (rx.buf[1] << 8)) : -1;
                    InterlockedIncrement(&g_stats.protoErrors);
                    char t[64];
                    _snprintf_s(t, sizeof(t), _TRUNCATE, "P73 protocol: type 0x%02X len %d", pr < 0 ? -1 : type, len);
                    Journal(84, -1, AcJournal::kNone, 0, pr < 0 ? -1 : (int)type, len, 0, t);
                    Log::Line(L"[P73] нарушение протокола сайдкаром: тип 0x%02X, len %d — соединение закрыто", pr < 0 ? 0xFF : type, len);
                    return kLossProto;
                }
                P73Wire::Consume(rx);
            }
        }
    }

    DWORD WINAPI BridgeThread(void*)
    {
        WSADATA wd;
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
        {
            Log::Line(L"[P73] ! WSAStartup не удался — мост не работает (игра не затронута)");
            return 0;
        }
        DWORD backoff = kBackoffMinMs;
        bool  downLogged = false;
        for (;;)
        {
            if (!g_enabled) { break; }
            int err = 0;
            SOCKET s = ConnectLocal(g_port, &err);
            if (s == INVALID_SOCKET)
            {
                if (!downLogged)
                {
                    Log::Line(L"[P73] сайдкар 127.0.0.1:%d недоступен (Winsock %d) — переподключение молча, back-off до %u мс; "
                              L"игра не блокируется", g_port, err, kBackoffMaxMs);
                    downLogged = true;
                }
                Sleep(backoff);
                backoff = backoff * 2 > kBackoffMaxMs ? kBackoffMaxMs : backoff * 2;
                continue;
            }
            const DWORD upAt = GetTickCount();
            int wsaErr = 0; bool wasUp = false;
            const int why = RunSession(s, &wsaErr, &wasUp);
            closesocket(s);
            Lock();
            g_connected = false; g_head = 0; g_count = 0; g_dropped = 0;   // события до следующего снимка не нужны
            Unlock();
            if (!wasUp)
            {
                // Соединение принято, но HELLO/LOGIN не ушли — как неудачная попытка: одна строка на смену состояния, back-off.
                if (!downLogged)
                {
                    Log::Line(L"[P73] сайдкар 127.0.0.1:%d принял соединение, но HELLO не ушёл (Winsock %d) — переподключение молча", g_port, wsaErr);
                    downLogged = true;
                }
                Sleep(backoff);
                backoff = backoff * 2 > kBackoffMaxMs ? kBackoffMaxMs : backoff * 2;
                continue;
            }
            backoff = kBackoffMinMs;
            downLogged = false;
            InterlockedIncrement(&g_stats.disconnects);
            const int upSec = (int)((GetTickCount() - upAt) / 1000);
            char t[64];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P73 down: reason %d, up %d s, wsa %d", why, upSec, wsaErr);
            Journal(78, -1, AcJournal::kNone, 0, why, upSec, wsaErr, t);
            Log::Line(L"[P73] мост потерян: %s (Winsock %d), был подключён %d с — переподключение", LossText(why), wsaErr, upSec);
            Sleep(why == kLossResync ? 0 : backoff);   // ресинхронизация — сразу; иначе — первая ступень back-off
        }
        WSACleanup();
        return 0;
    }

    // ── ★ P127: общие точки, поставленные этим файлом (UserTick и свои стабы событий) ──
    bool g_tickPlaced = false;       // площадка 0x526CEB записана (P73 Mode=1 или P73_UserTickInstall)
    bool g_ownLogon   = false;       // свои стабы 4001/5058 (P47 не поставил свои)
    bool g_ownConn    = false;       // свой детур SetConnectFlag (P61 не поставил свой)

    // ── стабы ───────────────────────────────────────────────────────────────
    DWORD g_ret4001  = 0x00527698;   // после вытесненного `mov edx,[ebp-0x428]`
    DWORD g_ret5058  = 0x0052CD44;   // после вытесненного `mov eax,[ebp-0x434]`
    DWORD g_retConn  = 0x00562915;   // тело SetConnectFlag после украденных 5 б (`push ebp; mov ebp,esp; push -1`)
    DWORD g_retCheck = 0x00526CF1;   // CheckDisConnectUser: `push eax` перед call sub_524440 (после вытесненных 6 б)
    DWORD g_pCommunityRes = 0x005285F0;   // ★ ред. 2: стоковый charLogonCommunityRes_0 (thiscall mgr, i16 userNum, pkt; ret 8)
    DWORD g_retLoop  = 0x00526E36;   // CheckDisConnectUser: `jmp 0x526C45` — следующий игрок (как после стоковых киков)

    // 4001 @0x527692 (только если P47 свой стаб не поставил): наблюдение, без ветки отказа.
    __declspec(naked) void Logon4001Stub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x424]            // UserIndex из тела 4001
            push  dword ptr [ebp-0x428]            // CUser*
            movsx eax, word ptr [ebp+8]
            push  eax                              // userNum
            push  1                                // вид: 4001
            call  P73_OnLogon                      // __stdcall, 16 б
            popad
            mov   edx, dword ptr [ebp-0x428]       // вытеснено
            jmp   dword ptr [g_ret4001]
        }
    }

    // 5058 @0x52CD3E (только если P47 свой стаб не поставил).
    __declspec(naked) void Logon5058Stub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x430]            // UserIndex из тела 5058
            push  dword ptr [ebp-0x434]            // CUser*
            movsx eax, word ptr [ebp+8]
            push  eax                              // userNum
            push  2                                // вид: 5058
            call  P73_OnLogon
            popad
            mov   eax, dword ptr [ebp-0x434]       // вытеснено
            jmp   dword ptr [g_ret5058]
        }
    }

    // Вход Ciocp::SetConnectFlag 0x562910 (только если P61 свой детур не поставил). thiscall(this, i16 slot, int flag), ret 8.
    __declspec(naked) void SetConnStub()
    {
        __asm
        {
            pushad
            push  dword ptr [esp+0x28]             // flag — orig [esp+8] + 0x20 (pushad)
            movsx eax, word ptr [esp+0x28]         // slot — orig [esp+4] + 0x20 + 4 (push выше)
            push  eax
            call  P73_OnConnFlag                   // __stdcall, 8 б
            popad
            push  ebp                              // украдено
            mov   ebp, esp
            push  -1
            jmp   dword ptr [g_retConn]
        }
    }

    // ★ ред. 2: вместо `call 0x5285F0` @0x430B10 (ecx = CUserManager, [esp+4] userNum, [esp+8] пакет): сток, затем P73.
    __declspec(naked) void CommunityTramp()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  ecx                              // CUserManager
            push  dword ptr [ebp+0x0C]             // пакет 2145
            push  dword ptr [ebp+0x08]             // userNum
            call  dword ptr [g_pCommunityRes]      // сток (ecx = CUserManager), ret 8
            pop   ecx
            pushad
            movsx eax, word ptr [ebp+0x08]
            push  eax                              // userNum
            push  ecx                              // CUserManager
            call  P73_OnCommunityRes               // __stdcall, 8 б
            popad
            mov   esp, ebp
            pop   ebp
            ret   8
        }
    }

    // CheckDisConnectUser @0x526CEB: [ebp-14h] CUserManager, [ebp-8] userNum (sub_523E50), [ebp-0Ch] CUser.
    __declspec(naked) void CheckStub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp-0x0C]             // CUser*
            movsx eax, word ptr [ebp-0x08]
            push  eax                              // userNum
            push  dword ptr [ebp-0x14]             // CUserManager
            call  P73_OnCheckUser                  // __stdcall, 12 б → eax
            mov   dword ptr [esp+28], eax          // результат → сохранённый eax
            popad
            test  eax, eax
            jnz   kicked
            mov   edx, dword ptr [ebp-0x0C]        // вытеснено
            mov   eax, dword ptr [edx+0x0C]        // вытеснено
            jmp   dword ptr [g_retCheck]
        kicked:
            jmp   dword ptr [g_retLoop]
        }
    }

    const BYTE kOrig4001[6]   = { 0x8B,0x95,0xD8,0xFB,0xFF,0xFF };              // mov edx,[ebp-0x428]
    const BYTE kOrig5058[6]   = { 0x8B,0x85,0xCC,0xFB,0xFF,0xFF };              // mov eax,[ebp-0x434]
    const BYTE kOrigConn[5]   = { 0x55,0x8B,0xEC,0x6A,0xFF };                   // push ebp; mov ebp,esp; push -1
    const BYTE kOrigCheck[6]  = { 0x8B,0x55,0xF4,0x8B,0x42,0x0C };              // mov edx,[ebp-0Ch]; mov eax,[edx+0Ch]
    // соседи (только сверка): адреса возврата и кадр
    const BYTE kNbCheckRet[8] = { 0x50,0x8B,0x4D,0xEC,0xE8,0x46,0xD7,0xFF };    // 0x526CF1 push eax; mov ecx,[ebp-14h]; call 0x524440
    const BYTE kNbLoop[5]     = { 0xE9,0x0A,0xFE,0xFF,0xFF };                   // 0x526E36 jmp 0x526C45
    const BYTE kNbUser[3]     = { 0x89,0x45,0xF4 };                             // 0x526CC2 mov [ebp-0Ch],eax (CUser)
    const BYTE kNbNum[3]      = { 0x89,0x45,0xF8 };                             // 0x526C8C mov [ebp-8],eax (userNum)
    const BYTE kNbMgr[3]      = { 0x89,0x4D,0xEC };                             // 0x526C26 mov [ebp-14h],ecx (CUserManager)
    const BYTE kNb4001Ret[7]  = { 0x66,0x8B,0x85,0xE4,0xFB,0xFF,0xFF };         // 0x527698 mov ax,[ebp-0x41C]
    const BYTE kNb5058Ret[6]  = { 0x8B,0x8D,0xD0,0xFB,0xFF,0xFF };              // 0x52CD44 mov ecx,[ebp-0x430]
    const BYTE kOrigComm[5]   = { 0xE8,0xDB,0x7A,0x0F,0x00 };                   // 0x430B10 call 0x5285F0 (charLogonCommunityRes_0)
    const BYTE kNbCommArgs[13]= { 0x66,0x8B,0x45,0xF8,0x50,0x8B,0x8D,0xD8,0xEF,0xFF,0xFF,0x8B,0x51 };   // 0x430AFF mov ax,[ebp-8]; push eax; mov ecx,[ebp-0x1028]; mov edx,[ecx+4]…
    const BYTE kNbCommRet[4]  = { 0x66,0x8B,0x45,0xF8 };                        // 0x430B15 mov ax,[ebp-8] (результат стока не читается)
    const BYTE kNbCommEntry[3]= { 0x55,0x8B,0xEC };                             // 0x5285F0 push ebp; mov ebp,esp
    const BYTE kNbConnRet[5]  = { 0x68,0xD8,0x24,0x58,0x00 };                   // 0x562915 push 0x5824D8 (SEH-пролог SetConnectFlag)

    // Вид сервера и игровой порт из окружения процесса.
    void ResolveServer()
    {
        const int kind = Config::GetInt(kSec, L"ServerKind", 0);
        if (kind == 2 || kind == 3) { g_serverKind = kind; }
        else
        {
            wchar_t dir[MAX_PATH]; lstrcpynW(dir, Config::BaseDir(), MAX_PATH);
            CharLowerW(dir);
            g_serverKind = wcsstr(dir, L"indun") ? 3 : 2;      // Indun_GameServer\ — тот же образ, своя папка
        }
        g_gamePort = Config::GetInt(kSec, L"GamePort", 0);
        if (g_gamePort > 0 && g_gamePort < 65536) { return; }
        g_gamePort = 0;
        wchar_t path[MAX_PATH]; _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%sConfigSet\\ServerIPPORT.txt", Config::BaseDir());
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        char buf[256] = {}; DWORD rd = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
        CloseHandle(h);
        int line = 0; const char* p = buf;
        while (*p && line < 2) { if (*p == '\n') { ++line; } ++p; }   // 3-я строка — порт (как AcJournal ResolveServer)
        int port = 0; bool digits = false;
        while (*p == ' ' || *p == '\t') { ++p; }
        while (*p >= '0' && *p <= '9') { port = port * 10 + (*p - '0'); digits = true; ++p; if (port > 65535) { break; } }
        if (digits && port > 0 && port < 65536) { g_gamePort = port; }
    }
}

// ── для стенда (на сервере не зовутся) ──────────────────────────────────────
extern "C" __declspec(dllexport) void __stdcall P73_GetStats(P73_Stats* out)
{
    if (out) { memcpy(out, &g_stats, sizeof(g_stats)); }
}
#ifdef ASDA_PATCH_STAND
// ★ §8.6 R3-05: всё ниже до #endif — только стендовая сборка (out\stand\AsdaPatch.dll); в рабочей DLL этих экспортов нет.
// Кодек: собрать кадр. Возврат — длина или −1.
extern "C" __declspec(dllexport) int __stdcall P73_TestEncode(int type, const BYTE* payload, int n, BYTE* out, int cap)
{
    return P73Wire::Encode((BYTE)type, payload, n, out, cap);
}
// Кодек: разобрать поток data[0..n) порциями chunk (имитация recv). types/lens — до max кадров. Возврат — число кадров,
//   −1 — нарушение протокола; *rest — байт хвоста (неполный кадр).
extern "C" __declspec(dllexport) int __stdcall P73_TestDecode(const BYTE* data, int n, int chunk, BYTE* types, int* lens, int max, int* rest)
{
    static P73Wire::Rx rx;
    rx.len = 0;
    int frames = 0, pos = 0;
    if (chunk <= 0) { chunk = n; }
    while (pos < n)
    {
        int take = n - pos < chunk ? n - pos : chunk;
        if (take > (int)sizeof(rx.buf) - rx.len) { take = (int)sizeof(rx.buf) - rx.len; }
        if (take <= 0) { return -1; }
        memcpy(rx.buf + rx.len, data + pos, take);
        rx.len += take; pos += take;
        for (;;)
        {
            BYTE t; const BYTE* pl; int len;
            const int r = P73Wire::Peek(rx, &t, &pl, &len);
            if (r < 0) { return -1; }
            if (r == 0) { break; }
            if (frames < max) { types[frames] = t; lens[frames] = len; }
            ++frames;
            P73Wire::Consume(rx);
        }
    }
    if (rest) { *rest = rx.len; }
    return frames;
}
// Очередь KICK: подать полезную нагрузку KICK (8 б) тем же обработчиком, что и нить моста.
extern "C" __declspec(dllexport) void __stdcall P73_TestKick(const BYTE* payload8)
{
    if (payload8) { OnKickFrame(payload8); }
}
// Очередь KICK: прогнать просроченные (как нить моста раз в секунду).
extern "C" __declspec(dllexport) void __stdcall P73_TestSweep()
{
    SweepExpired();
}
// ★ ред. 3: стенд задаёт bind слота (32 б; nullptr — нули, «Legacy») вместо опроса P61 — в стенде нет живого Ciocp и сокетов,
//   поэтому рукопожатие AsdaSecure на слоте не проходит. Первый вызов переключает источник на таблицу стенда до конца процесса.
//   Цепочка P61_SlotBinding → AsdaWire::SlotChannelBinding проверяется стендом AsdaSecure stand_bind (§4) и verify_p73.
extern "C" __declspec(dllexport) void __stdcall P73_TestSetBind(int slot, const BYTE* bind32)
{
    if (slot < 0 || slot >= kSlots) { return; }
    if (bind32) { memcpy(g_testBind[slot], bind32, kBind); } else { memset(g_testBind[slot], 0, kBind); }
    InterlockedExchange(&g_testBindOn, 1);
}
// ★ §8.6 R3-06: стенд ставит обратный вызов, который P73_OnLogon зовёт между SlotBind и записью LOGIN (nullptr — снять).
extern "C" __declspec(dllexport) void __stdcall P73_TestLogonHook(PFN_TestLogonHook fn)
{
    g_testLogonHook = fn;
}
#endif   // ASDA_PATCH_STAND

// ★ P127: общая точка UserTick — поставить стаб такта игрока на 0x526CEB, если его ещё нет (P73 выключен или Mode=0). Тот же
//   CheckStub, те же сверки площадки и соседей, что у P73 Mode=1. true — площадка стоит (была или поставлена сейчас).
bool P73_UserTickInstall()
{
    if (g_tickPlaced) { return true; }
    const Site sites[] =
    {
        { 0x00526CEB, kOrigCheck,  sizeof(kOrigCheck)  },
        { 0x00526CF1, kNbCheckRet, sizeof(kNbCheckRet) },
        { 0x00526E36, kNbLoop,     sizeof(kNbLoop)     },
        { 0x00526CC2, kNbUser,     sizeof(kNbUser)     },
        { 0x00526C8C, kNbNum,      sizeof(kNbNum)      },
        { 0x00526C26, kNbMgr,      sizeof(kNbMgr)      },
    };
    if (!VerifyAllSites(L"UserTick", sites, ARRAYSIZE(sites))) { return false; }
    if (!Hook::WriteJmp(0x00526CEB, (void*)&CheckStub, sizeof(kOrigCheck))) { return false; }
    g_tickPlaced = true;
    Log::Line(L"    UserTick: общая точка такта игрока 0x526CEB поставлена (CheckStub → P73_OnCheckUser → KICK P73, затем P127)");
    return true;
}

// ★ P127: доходят ли события входа/разрыва до P73_OnLogon / P73_OnConnFlag (через стабы P47/детур P61 или свои стабы P73).
bool P73_EventsHooked()
{
    return (P47_LogonHooked() || g_ownLogon) && (P61_SetConnHooked() || g_ownConn);
}

PatchResult P73_EacBridge()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", false)) { return PatchResult::Disabled; }
    g_mode = Config::GetInt(kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_port = Config::GetInt(kSec, L"Port", 15702);
    if (g_port <= 0 || g_port > 65535) { g_port = 15702; }
    g_kickType = Config::GetInt(kSec, L"KickType", 6);              // ★ ред. 3 (E1-07): 6 → клиент нотис 1106
    if (g_kickType < 0 || g_kickType > 255) { g_kickType = 6; }
    g_exemptGm = Config::GetBool(kSec, L"ExemptOperators", true);
    g_pendingSec = Config::GetInt(kSec, L"KickPendingSec", 30);
    if (g_pendingSec < 2)    { g_pendingSec = 2; }
    if (g_pendingSec > 3600) { g_pendingSec = 3600; }
    g_pongTimeoutSec = Config::GetInt(kSec, L"PongTimeoutSec", 20);
    if (g_pongTimeoutSec < 0)                              { g_pongTimeoutSec = 0; }
    if (g_pongTimeoutSec > 0 && g_pongTimeoutSec < 10)     { g_pongTimeoutSec = 10; }   // меньше двух PING — ложные разрывы
    if (g_pongTimeoutSec > 3600)                           { g_pongTimeoutSec = 3600; }
    //   дописывает ключ P73 со значением ключа P48, так что поведение после обновления DLL не меняется.
    g_soulSession = Config::GetBool(kSec, L"SoulMateSessionAccount",
                                    Config::GetBool(L"P48_KickAutoBlock", L"SoulMateSessionAccount", true));
    g_queueCap = Config::GetInt(kSec, L"QueueSize", 4096);
    if (g_queueCap < 64)     { g_queueCap = 64; }
    if (g_queueCap > 65536)  { g_queueCap = 65536; }
    ResolveServer();

    // Общие точки: стабы логона P47 и детур SetConnectFlag P61 — если стоят, второй врезки на те же байты НЕ ставим.
    const bool viaP47 = P47_LogonHooked();
    const bool viaP61 = P61_SetConnHooked();
    const bool check  = g_mode == 1;                  // площадка кика нужна только для выполнения KICK

    Site sites[16]; int ns = 0;
    sites[ns++] = { 0x00430B10, kOrigComm,    sizeof(kOrigComm)    };   // ★ ред. 2: REBIND по 2145
    sites[ns++] = { 0x00430AFF, kNbCommArgs,  sizeof(kNbCommArgs)  };
    sites[ns++] = { 0x00430B15, kNbCommRet,   sizeof(kNbCommRet)   };
    sites[ns++] = { 0x005285F0, kNbCommEntry, sizeof(kNbCommEntry) };
    if (!viaP47)
    {
        sites[ns++] = { 0x00527692, kOrig4001,  sizeof(kOrig4001)  };
        sites[ns++] = { 0x0052CD3E, kOrig5058,  sizeof(kOrig5058)  };
    }
    sites[ns++] = { 0x00527698, kNb4001Ret, sizeof(kNb4001Ret) };
    sites[ns++] = { 0x0052CD44, kNb5058Ret, sizeof(kNb5058Ret) };
    if (!viaP61) { sites[ns++] = { 0x00562910, kOrigConn, sizeof(kOrigConn) }; }
    sites[ns++] = { 0x00562915, kNbConnRet, sizeof(kNbConnRet) };
    if (check)
    {
        sites[ns++] = { 0x00526CEB, kOrigCheck,  sizeof(kOrigCheck)  };
        sites[ns++] = { 0x00526CF1, kNbCheckRet, sizeof(kNbCheckRet) };
        sites[ns++] = { 0x00526E36, kNbLoop,     sizeof(kNbLoop)     };
        sites[ns++] = { 0x00526CC2, kNbUser,     sizeof(kNbUser)     };
        sites[ns++] = { 0x00526C8C, kNbNum,      sizeof(kNbNum)      };
        sites[ns++] = { 0x00526C26, kNbMgr,      sizeof(kNbMgr)      };
    }
    if (!VerifyAllSites(L"P73", sites, ns)) { return PatchResult::Mismatch; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    if (!g_ring)
    {
        g_ring = (OutEv*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OutEv) * (SIZE_T)g_queueCap);
        if (!g_ring) { Log::Line(L"    P73: [ОШИБКА] нет памяти под кольцо событий (%d записей)", g_queueCap); return PatchResult::Failed; }
    }

    // Колбэки включаются ДО записи площадок; при сбое любой записи уже записанные возвращаются к оригиналу.
    InterlockedExchange(&g_enabled, 1);
    struct W { DWORD va; const BYTE* orig; SIZE_T len; void* to; };
    W writes[5]; int nw = 0;
    if (!viaP47) { writes[nw++] = { 0x00527692, kOrig4001, 6, (void*)&Logon4001Stub };
                   writes[nw++] = { 0x0052CD3E, kOrig5058, 6, (void*)&Logon5058Stub }; }
    if (!viaP61) { writes[nw++] = { 0x00562910, kOrigConn, 5, (void*)&SetConnStub }; }
    if (check)   { writes[nw++] = { 0x00526CEB, kOrigCheck, 6, (void*)&CheckStub }; }
    const int commAt = nw;   // ★ ред. 2: 0x430B10 — call (не jmp): трамплин возвращается сам
    writes[nw++] = { 0x00430B10, kOrigComm, 5, (void*)&CommunityTramp };
    int ok = 0;
    for (; ok < nw; ++ok)
    {
        const bool w = ok == commAt ? Hook::WriteCall(writes[ok].va, writes[ok].to, writes[ok].len)
                                    : Hook::WriteJmp(writes[ok].va, writes[ok].to, writes[ok].len);
        if (!w) { break; }
    }
    if (ok != nw)
    {
        for (int i = ok - 1; i >= 0; --i) { Hook::WriteBytes(writes[i].va, writes[i].orig, writes[i].len); }
        InterlockedExchange(&g_enabled, 0);
        Log::Line(L"    P73: [ОШИБКА] запись площадки 0x%08X не прошла — записанные возвращены к оригиналу; сток", writes[ok].va);
        return PatchResult::Failed;
    }

    // ★ P127: какие общие точки поставил сам P73 (UserTick 0x526CEB, свои стабы логона/разрыва)
    if (check)   { g_tickPlaced = true; }
    if (!viaP47) { g_ownLogon = true; }
    if (!viaP61) { g_ownConn = true; }

    if (!g_thread) { g_thread = CreateThread(nullptr, 0, &BridgeThread, nullptr, 0, nullptr); }
    if (!g_thread)
    {
        // Без нити сайдкар ничего не узнает: колбэки выключаются (площадки остаются — они только наблюдают, KICK не придёт).
        InterlockedExchange(&g_enabled, 0);
        Log::Line(L"    P73: [ОШИБКА] нить моста не создана (CreateThread %u) — мост выключен, площадки работают вхолостую", GetLastError());
        return PatchResult::Failed;
    }

    Log::Line(L"    P73: мост EAC → 127.0.0.1:%d; Mode=%d (%s); вид сервера %d, игровой порт %d; LOGIN 4001/5058 — %s; LOGOUT — %s",
              g_port, g_mode, g_mode == 1 ? L"KICK выполняется" : L"только журнал, KICK не выполняется",
              g_serverKind, g_gamePort, viaP47 ? L"цепочка стабов P47" : L"свои стабы 0x527692/0x52CD3E",
              viaP61 ? L"цепочка детура P61" : L"свой детур 0x562910");
    if (check)
    {
        Log::Line(L"    P73: KICK — в нити карты на проходе CheckDisConnectUser (площадка 0x526CEB): сверка CUser+0x174, 4101 тип %d + "
                  L"ExceptionDisConnetUser; операторы %s; ожидание не дольше %d с; P48 не засчитывает", g_kickType,
                  g_exemptGm ? L"не кикаются (журнал)" : L"КИКАЮТСЯ", g_pendingSec);
    }
    Log::Line(L"    P73: REBIND (вход соулмейтом) — по ответу БД 2145 (call 0x430B10 → трамплин), учётка сессии — P48_IdentityOf, "
              L"[P73_EacBridge] SoulMateSessionAccount=%d%s", g_soulSession ? 1 : 0, g_soulSession ? L"" : L" (REBIND не шлётся)");
    Log::Line(L"    P73: HELLO ver=2; LOGIN/REBIND несут bind игрового канала — %s", P61_SetConnHooked()
              ? L"ServerChannel слота P61 (Legacy / рукопожатие не завершено — нули)"
              : L"P61 НЕ поставлен — у всех нули (сайдкар ред. 3 §8.6: «P61 у процесса не активен», причина 6 не применяется; Mode 2 — только после P61)");
    Log::Line(L"    P73: PING 5 с, без кадров сайдкара %d с — переподключение%s; кольцо %d событий; журнал ac.other 77–84",
              g_pongTimeoutSec, g_pongTimeoutSec ? L"" : L" (слежение выкл)", g_queueCap);
    return PatchResult::Applied;
}
