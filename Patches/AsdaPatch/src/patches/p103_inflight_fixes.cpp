// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P103 — [ИСПРАВЛЕНИЕ] «В ПОЛЁТЕ»: КОРОБКА ПРИ ОТКАЗЕ БД И ОТКАТ ФУНКЦИОНАЛЬНЫХ ПРЕДМЕТОВ (04.11.2026, AsdaPatch v60).
//  Разбор и доказательства: Reports/item_dedup/p103/P103_REPORT.md (живой журнал, FuncLog, стенд tools/stand_p103).
//
//  ── S1 (бит Sites 1) КОРОБКА 6096: отказ БД оставлял записи накопителя P100 на 60 с ──
//  Поток: Recv_OpenPackageItem@0x55A820 → P95 раскладывает позиции (P100_BoxPlace/P100_ReserveNew: записи накопителя «слияние» /
//  «резерв новой ячейки», жизнь PendingTtlSec = 60 с) → 2272 в DBManager (sub_432B20: EXEC UPBundleItemUse; ответ 2273 — ЭХО
//  записей запроса, байт [5] = Flag процедуры) → ответ sub_55B1C0@0x55B1C0: `if (v15[5] == 1)` — запись в память (там площадка
//  P100 W_A6 0x55B483 снимает записи накопителя); иначе — сразу 6097 клиенту, в память НИЧЕГО (сток верен: БД откатила).
//  Flag 0 бывает: CATCH процедуры (ошибка SQL, напр. PK_Item_1 — память и БД разошлись по ячейке), коробки нет в (BPlate, BPosx),
//  @@ROWCOUNT ≠ 1. Тогда записи P100 живут 60 с: перемещение/использование этих ячеек отказано (вид 156 «in flight», код 18), в
//  резерв новой ячейки сливаются чужие позиции. Живое: LUFFY 03.11 19:40:47 и 19:47:48 (UPBundleItemUse PK (2,12,1,6)) → 19:48:37
//  отказ перемещения ячейки 6; GM_sitxovski 02.11 23:12:24/:33 (коробки без строк BundleUse) → отказы 23:12:28/:38.
//  Площадка 0x55B251 `movzx ecx, byte [ebp-26Bh]` (байт результата, сразу перед `cmp ecx,1 / jne 0x55B6A5`, только при живом
//  CUser): результат ≠ 1 → P100_ReleaseRecs по 5 записям эха ([ebp-270h]+13, шаг 57) — та же снимаемая запись, что у успешного
//  ответа (ячейка, добавка). Вид 168. Дальше — сток (6097 с кодом БД).
//
//  ── S2 (бит 2) 5450 Char_FunctionItem_Use: заряд списан в БД, ответ отказал «CoolTime Not Spend» (код 12) ──
//  Сток: запрос проверяет группу отката FT+38 (sub_4DA990 @0x4EE5DE, LABEL_69) и откат кода FT+18 (sub_4F27F0 @0x4EDDC7), шлёт 2140
//  (0x4EEE13 «InvenUse», FT+25 == 3; 0x4EF02E «Use» — площадка P75); ставит откат ТОЛЬКО ответ sub_4EF270 (sub_4DA920 группы,
//  sub_4F2640 кода). DBManager на 2140 ВСЕГДА отвечает 2141 (эхо тела, [0] = Flag), UPSkillItemSpend списывает без транзакции.
//  Второй запрос до первого ответа проходит проверку, БД списывает второй заряд, второй ответ видит группу и отказывает кодом 12 —
//  память уменьшена один раз, БД дважды (живые: 8 зарядов, Player21 75215 и Player58 75210, коды 37 и 498; FuncLog 25.10/27.10).
//  Откат кода без группы: ответ не отказывает, а регистрирует откат только если его нет — двойной запрос = двойной эффект (обход
//  отката; на живых логах не встречался).
//  P103: замок «в полёте» на (слот + учётка, группа FT+38 > 0) и (слот + учётка, код при FT+18 > 0 — ключ CodeLatch) — ставится при
//  уходе 2140 (обе площадки), снимается ПОСЛЕ стокового ответа 2141 (площадка вызова 0x430AB1 в ConnectSocketMsgProcess, любой
//  исход: успех, Flag 0, отказ) или по LatchTtlMs (потерянный ответ). Проверка — на входе LABEL_69 0x4EE5A1 (сюда приходят все
//  пути 2140): замок жив → [ebp-121h] = 12 (группа, как стоковый отказ группы) / 8 (код, как стоковый отказ sub_4F27F0) и общий
//  выход 0x4EF0C3 — 5451 клиенту, в БД ничего. Повтор журнала FuncLog за 22 дня: замок отказал бы ровно 9 запросам — 8 потерянным
//  зарядам и 1 отказу БД; ни одного успешного применения (p103_funcaudit.py).
//
//  ── S3 (бит 4) автоприменение (sub_4F1550, слот баффа 25, ОЗ ≤ 30 %): та же группа отката, запрос 2223 тип 25, ответ 2224 ──
//  Ответ sub_4F3D90 ставит группу (sub_4DA920) и не отказывает — сам автоприменение заряд не теряет, но ручное 5450 той же группы,
//  ушедшее до его ответа, теряет заряд (ответ 2141 увидит группу). P103: проверка группы автоприменения 0x4F1648 (`call sub_4DA990`)
//  видит замок как откат; замок ставится при уходе 2223 (площадку 0x4F1771 держит P100 — он зовёт P103_OnDbSent; без P100 — своя
//  площадка) и снимается после ответа 2224 (площадка вызова 0x432391).
//  Журнал ac.other 168 (S1: снято записей), 169 (S2/S3: отказ до БД — группа/код в полёте), 170 (исключение — решение стока).
//  Ключи [P103_InFlightFixes]: Enabled, Sites (1|2|4, по умолчанию 7), LatchTtlMs (10000), CodeLatch (1), JournalIntervalSec,
//  ItemLogChannel (1), FuncLogChannel (8).
//  Соседи: P75 (0x4EDDC7, 0x4EF02E — цепочка P75_ChainDbSend, 0x4EF606), P102 S5 (0x4EDDE1, выход 0x4EF0C3 — только переход),
//  P100 (0x55B483, 0x4F1771, 0x4EDD35), P63 (0x432E0E — вызов sub_55B1C0 в диспетчере, другая площадка), P82 (0x4F2820, 0x4F2672).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P103_InFlightFixes";   // секция patches.ini

    constexpr BYTE kKindBoxRelease = 168;   // ac.other 168 — коробка: отказ БД 2273, записи накопителя P100 сняты
    constexpr BYTE kKindLatch      = 169;   // ac.other 169 — 5450/автоприменение: группа/код отката в полёте, отказ до БД
    constexpr BYTE kKindFault      = 170;   // ac.other 170 — исключение, решение стока
    constexpr int  kKindBase = 168, kKindCount = 3;

    // ── CUser / таблицы (сток) ──────────────────────────────────────────────
    constexpr int   kOffUserIndex = 0x174;       // учётка (sub_5324F0)
    constexpr int   kOffName      = 0x178;       // имя персонажа cp1251
    constexpr int   kOffSlot      = 0x18C;       // слот персонажа
    constexpr int   kMaxUsers     = 0x226;       // 550 слотов (sub_5328F0)
    constexpr DWORD kFuncTablePtr = 0x005F5E70;  // dword_5F5E70 → Function_Table, запись 48 б, индекс (код − 1)
    constexpr DWORD kFuncMaxPtr   = 0x005F5EA4;  // число кодов Function_Table
    constexpr int   kFuncRec = 48;
    constexpr int   kFtCooldown = 18;            // FT+18 — откат кода, мс (i32; sub_4DA920 берёт i16)
    constexpr int   kFtGroup    = 38;            // FT+38 — группа отката (u8; 0 — нет)
    constexpr int   kRec = 57;                   // запись предмета

    typedef BOOL (__fastcall *PFN_CoolOk)(void* self, void* edx, int userNum, int group);   // sub_4DA990 thiscall(i16, u8) ret 8
    typedef void (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                    // sub_569DF0
    PFN_CoolOk const pCoolOk = (PFN_CoolOk)0x004DA990;
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)Srv::kLog;

    // ── площадки ─────────────────────────────────────────────────────────────
    // S1: 0x55B251 movzx ecx, byte [ebp-26Bh] (7 б) → стаб; продолжение 0x55B258 cmp ecx,1
    const DWORD kS1 = 0x0055B251; DWORD g_s1Back = 0x0055B258;
    const BYTE kS1Orig[7]  = { 0x0F, 0xB6, 0x8D, 0x95, 0xFD, 0xFF, 0xFF };
    const BYTE kS1Back[9]  = { 0x83, 0xF9, 0x01, 0x0F, 0x85, 0x44, 0x04, 0x00, 0x00 };   // cmp ecx,1 ; jne 0x55B6A5
    const BYTE kS1Prev[5]  = { 0xE9, 0xB9, 0x04, 0x00, 0x00 };                          // 0x55B24C jmp 0x55B70A (CUser нет)
    const BYTE kS1Copy[6]  = { 0x8D, 0xBD, 0x90, 0xFD, 0xFF, 0xFF };                    // 0x55B219 lea edi,[ebp-270h] — эхо ответа
    const BYTE kS1Src[3]   = { 0x8B, 0x75, 0x0C };                                      // 0x55B20E mov esi,[ebp+0Ch] — пакет
    const BYTE kS1This[6]  = { 0x89, 0x8D, 0x6C, 0xFD, 0xFF, 0xFF };                    // 0x55B1D5 mov [ebp-294h],ecx — this
    // S2 проверка: 0x4EE5A1 mov ecx,[ebp-204h] (6 б, вход LABEL_69) → стаб; продолжение 0x4EE5A7; отказ → 0x4EF0C3
    const DWORD kS2Gate = 0x004EE5A1; DWORD g_s2Back = 0x004EE5A7; DWORD g_s2Refuse = 0x004EF0C3;
    const BYTE kS2GateOrig[6] = { 0x8B, 0x8D, 0xFC, 0xFD, 0xFF, 0xFF };
    const BYTE kS2GateBack[3] = { 0x83, 0xE9, 0x01 };                                   // sub ecx,1
    const BYTE kS2Group[5]    = { 0xE8, 0xAD, 0xC3, 0xFE, 0xFF };                       // 0x4EE5DE call sub_4DA990 (стоковая проверка группы)
    const BYTE kS2Code12[7]   = { 0xC6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF, 0x0C };           // 0x4EE5E7 mov byte [ebp-121h],0Ch
    const BYTE kS2Exit[7]     = { 0x0F, 0xB6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF };           // 0x4EF0C3 movzx eax, byte [ebp-121h]
    const BYTE kS2This[6]     = { 0x8B, 0x8D, 0x08, 0xFD, 0xFF, 0xFF };                 // 0x4EE5D8 mov ecx,[ebp-2F8h] — this
    // S2 уход 2140: 0x4EEE13 (своя) и 0x4EF02E (P75 или своя): call sub_5646C0
    const DWORD kS2SendA = 0x004EEE13, kS2SendB = 0x004EF02E, kDbSend = 0x005646C0;
    const BYTE kS2SendAOrig[5] = { 0xE8, 0xA8, 0x58, 0x07, 0x00 };
    const BYTE kS2SendBOrig[5] = { 0xE8, 0x8D, 0x56, 0x07, 0x00 };
    const BYTE kS2SendArgs[15] = { 0x68, 0xC0, 0x00, 0x00, 0x00, 0x68, 0x5C, 0x08, 0x00, 0x00, 0xB9, 0x38, 0x05, 0x7E, 0x00 };   // push 0C0h; push 85Ch; mov ecx,7E0538h
    const BYTE kDbSendProlog[3] = { 0x55, 0x8B, 0xEC };
    // S2 ответ 2141: 0x430AB1 call sub_4EF270 в ConnectSocketMsgProcess
    const DWORD kS2Reply = 0x00430AB1, kStock2141 = 0x004EF270;
    const BYTE kS2ReplyOrig[5]  = { 0xE8, 0xBA, 0xE7, 0x0B, 0x00 };
    const BYTE kS2ReplyArgs[18] = { 0x51, 0x66, 0x8B, 0x55, 0xF8, 0x52, 0x8B, 0x85, 0xD8, 0xEF, 0xFF, 0xFF, 0x8B, 0x48, 0x04, 0x8B, 0x49, 0x34 };   // 0x430A9F
    const BYTE kS2ReplyAfter[9] = { 0x8B, 0x55, 0x08, 0xC7, 0x02, 0x30, 0x04, 0x00, 0x00 };   // 0x430AB6 *arg0 = 1072
    const BYTE kStock2141Prolog[3] = { 0x55, 0x8B, 0xEC };
    // S3 проверка автоприменения: 0x4F1648 call sub_4DA990
    const DWORD kS3Gate = 0x004F1648;
    const BYTE kS3GateOrig[5] = { 0xE8, 0x43, 0x93, 0xFE, 0xFF };
    const BYTE kS3GateArgs[12] = { 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x70, 0xFF, 0xFF, 0xFF };   // 0x4F163C push edx(группа); push ax; mov ecx,[ebp-90h]
    const BYTE kS3GateAfter[4] = { 0x85, 0xC0, 0x75, 0x33 };                            // 0x4F164D test eax,eax ; jne 0x4F1684
    // S3 уход 2223: 0x4F1771 call sub_5646C0 (площадка P100 G_AUTOUSE; без P100 — своя)
    const DWORD kS3Send = 0x004F1771;
    const BYTE kS3SendOrig[5] = { 0xE8, 0x4A, 0x2F, 0x07, 0x00 };
    const BYTE kS3SendArgs[12] = { 0x6A, 0x13, 0x68, 0xAF, 0x08, 0x00, 0x00, 0xB9, 0x38, 0x05, 0x7E, 0x00 };   // 0x4F1765 push 13h; push 8AFh; mov ecx,7E0538h
    // S3 ответ 2224: 0x432391 call sub_4F3D90
    const DWORD kS3Reply = 0x00432391, kStock2224 = 0x004F3D90;
    const BYTE kS3ReplyOrig[5]  = { 0xE8, 0xFA, 0x19, 0x0C, 0x00 };
    const BYTE kS3ReplyArgs[18] = { 0x52, 0x66, 0x8B, 0x45, 0xF8, 0x50, 0x8B, 0x8D, 0xD8, 0xEF, 0xFF, 0xFF, 0x8B, 0x51, 0x04, 0x8B, 0x4A, 0x34 };   // 0x43237F
    const BYTE kS3ReplyAfter[9] = { 0x8B, 0x45, 0x08, 0xC7, 0x00, 0x22, 0x05, 0x00, 0x00 };   // 0x432396 *arg0 = 1314
    const BYTE kStock2224Prolog[3] = { 0x55, 0x8B, 0xEC };

    DWORD g_pNextSend  = kDbSend;      // «следующий вызов» стаба ухода (sub_5646C0; при цепочке за P75 — то, что стояло у P75)
    DWORD g_pStock2141 = kStock2141;   // стоковый приём 2141
    DWORD g_pStock2224 = kStock2224;   // стоковый приём 2224

    // ── настройки ────────────────────────────────────────────────────────────
    bool  g_enabled = false;           // P103 стоит
    DWORD g_sites = 7;                 // 1 коробка, 2 5450, 4 автоприменение
    bool  g_s2On = false, g_s3On = false;
    DWORD g_ttlMs = 10000;             // жизнь замка без ответа БД
    bool  g_codeLatch = true;          // замок кода при FT+18 > 0
    int   g_journalIntervalSec = 10;
    int   g_itemLog = 1, g_funcLog = 8;

    P103_Stats g_stats = {};

    // ── замок «в полёте»: на слот до 8 записей (группа / код), хозяин — учётка ──
    struct Fl { BYTE kind; BYTE src; short id; DWORD tick; };   // kind 1 группа, 2 код; src 1 — 2140, 2 — 2223
    struct Slot { int userIndex; int n; Fl e[8]; };
    Slot g_fl[kMaxUsers] = {};
    struct Sess { int userIndex; DWORD last[kKindCount]; int sup[kKindCount]; };
    Sess g_sess[kMaxUsers] = {};
    CRITICAL_SECTION g_cs; bool g_csReady = false;
    struct Lock { Lock() { if (g_csReady) { EnterCriticalSection(&g_cs); } } ~Lock() { if (g_csReady) { LeaveCriticalSection(&g_cs); } } };

    const BYTE* FtRow(int code) { return *(const BYTE**)kFuncTablePtr + kFuncRec * (code - 1); }
    bool FtCode(int code) { return code >= 1 && code <= *(const int*)kFuncMaxPtr; }
    int  GroupOf(int code) { return FtCode(code) ? (int)FtRow(code)[kFtGroup] : 0; }
    int  CoolOf(int code) { return FtCode(code) ? *(const int*)(FtRow(code) + kFtCooldown) : 0; }

    BYTE* UserOf(void* mgr, int userNum)
    {
        __try { return (mgr && userNum >= 0 && userNum < kMaxUsers) ? *(BYTE**)((BYTE*)mgr + 0x40 + 4 * userNum) : nullptr; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }
    int UiOf(const BYTE* user)
    {
        __try { return user ? *(const int*)(user + kOffUserIndex) : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // Записи слота (смена учётки — сброс; просроченные — снимаются). Под Lock.
    Slot* SlotOf(int userNum, int ui)
    {
        if (userNum < 0 || userNum >= kMaxUsers) { return nullptr; }
        Slot& s = g_fl[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        const DWORD now = GetTickCount();
        int w = 0;
        for (int i = 0; i < s.n; ++i)
        {
            if (now - s.e[i].tick >= g_ttlMs) { InterlockedIncrement(&g_stats.latchExpired); continue; }
            s.e[w++] = s.e[i];
        }
        s.n = w;
        return &s;
    }
    void Put(Slot* s, BYTE kind, BYTE src, int id)
    {
        DWORD now = GetTickCount(); if (!now) { now = 1; }
        for (int i = 0; i < s->n; ++i) { if (s->e[i].kind == kind && s->e[i].id == id) { s->e[i].tick = now; s->e[i].src = src; return; } }
        if (s->n >= 8) { memmove(&s->e[0], &s->e[1], sizeof(Fl) * 7); s->n = 7; }
        Fl& f = s->e[s->n++]; f.kind = kind; f.src = src; f.id = (short)id; f.tick = now;
        InterlockedIncrement(&g_stats.latchSet);
    }
    int Find(const Slot* s, BYTE kind, int id) { for (int i = 0; i < s->n; ++i) { if (s->e[i].kind == kind && s->e[i].id == id) { return i; } } return -1; }
    void Drop(Slot* s, BYTE kind, int id)
    {
        const int i = Find(s, kind, id);
        if (i < 0) { return; }
        memmove(&s->e[i], &s->e[i + 1], sizeof(Fl) * (s->n - i - 1));
        --s->n;
        InterlockedIncrement(&g_stats.latchCleared);
    }

    // Ограничитель журнала: одна строка на (слот, вид) за JournalIntervalSec.
    bool Allow(int userNum, int ui, BYTE kind, int* supOut)
    {
        *supOut = 0;
        const int k = kind - kKindBase;
        if (userNum < 0 || userNum >= kMaxUsers || k < 0 || k >= kKindCount) { return true; }
        DWORD now = GetTickCount(); if (!now) { now = 1; }
        Lock l;
        Sess& s = g_sess[userNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        if (g_journalIntervalSec > 0 && s.last[k] && now - s.last[k] < (DWORD)g_journalIntervalSec * 1000) { ++s.sup[k]; return false; }
        s.last[k] = now; *supOut = s.sup[k]; s.sup[k] = 0;
        return true;
    }

    // Строка стокового лога + ac.other (под ограничителем).
    void Report(BYTE kind, int channel, int opcode, const BYTE* user, int userNum, int v0, int v1, int v2, const char* detail, const char* logText)
    {
        const int ui0 = UiOf(user);
        int sup = 0;
        if (!Allow(userNum, ui0, kind, &sup)) { InterlockedIncrement(&g_stats.suppressed); return; }
        const char* name = "?";
        __try { if (user) { name = (const char*)(user + kOffName); } } __except (EXCEPTION_EXECUTE_HANDLER) { name = "?"; }
        __try { pSrvLog(channel, "\t[P103] InFlight\t%d\tUserNum %d\tUserIndex %d\tNick %s\t%s%s", opcode, userNum, ui0, name, logText, sup ? " (+suppressed)" : ""); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = (userNum >= 0 && userNum < kMaxUsers) ? P47_PeerIpv4(userNum) : 0;
        e.suppressed = sup;
        if (user)
        {
            __try { e.userIndex = ui0; e.charSlot = user[kOffSlot]; AcJournal::CopyName(e, user + kOffName); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }
    void Fault(int opcode, int userNum, DWORD code)
    {
        InterlockedIncrement(&g_stats.faults);
        char d[64];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P103 %d exception 0x%08X -> stock", opcode, code);
        Report(kKindFault, g_itemLog, opcode, nullptr, userNum, opcode, (int)code, AcJournal::kNone, d, "exception -> stock decision");
    }

    // Замок по коду: 12 — группа в полёте, 8 — код в полёте, 0 — нет. Под Lock.
    int Hit(Slot* s, int code, int* grpOut, int* srcOut)
    {
        const int grp = GroupOf(code);
        *grpOut = grp; *srcOut = 0;
        if (grp > 0) { const int i = Find(s, 1, grp); if (i >= 0) { *srcOut = s->e[i].src; return 12; } }
        if (g_codeLatch && CoolOf(code) > 0) { const int i = Find(s, 2, code); if (i >= 0) { *srcOut = s->e[i].src; return 8; } }
        return 0;
    }

    // Обёртки под замком (функции с __try не могут держать объект Lock — C2712).
    int GateHit(int userNum, int ui, int code, int* grp, int* src)
    {
        Lock l;
        Slot* s = SlotOf(userNum, ui);
        return s ? Hit(s, code, grp, src) : 0;
    }
    void LatchPut(int userNum, int ui, int grp, int code, BYTE src)
    {
        Lock l;
        Slot* s = SlotOf(userNum, ui);
        if (!s) { return; }
        if (grp > 0) { Put(s, 1, src, grp); }
        if (code > 0) { Put(s, 2, src, code); }
    }
    void LatchDrop(int userNum, int ui, int grp, int code)
    {
        Lock l;
        if (userNum < 0 || userNum >= kMaxUsers || g_fl[userNum].userIndex != ui) { return; }
        Slot* s = &g_fl[userNum];
        if (grp > 0) { Drop(s, 1, grp); }
        Drop(s, 2, code);
    }
    int AutoHit(int userNum, int ui, int group, int* src)
    {
        Lock l;
        Slot* s = SlotOf(userNum, ui);
        if (!s) { return -1; }
        const int i = Find(s, 1, group);
        if (i >= 0) { *src = s->e[i].src; }
        return i;
    }
}

// ── S1: ответ 2273 (sub_55B1C0, после «CUser есть»). Результат ≠ 1 — снять записи накопителя P100 по эху записей. ──
extern "C" void __stdcall P103_OnBoxReply(BYTE* ebp)
{
    if (!g_enabled || !(g_sites & 1)) { return; }
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        InterlockedIncrement(&g_stats.boxReplies);
        const BYTE* body = ebp - 0x270;                  // v15: эхо тела 2272 (0x12A б) — [5] результат, [6] код коробки, [13] 5 записей
        if (body[5] == 1 || !P100_Active()) { return; }
        void* mgr = *(void**)(ebp - 0x294);
        userNum = *(const short*)(ebp + 8);
        InterlockedIncrement(&g_stats.boxRefused);
        int slots[5] = { -1, -1, -1, -1, -1 };
        const int rel = P100_ReleaseRecs(mgr, userNum, body + 13, 5, kRec, slots);
        if (rel <= 0) { return; }
        InterlockedExchangeAdd(&g_stats.boxReleased, rel);
        const BYTE* user = UserOf(mgr, userNum);
        const int box = *(const int*)(body + 6);
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P103 2273 box %d DB flag %d: %d in-flight entries released", box, body[5], rel);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "box %d: DB refused (flag %d), nothing written - %d in-flight charge-stack entries released (cells %d %d %d %d %d)",
                    box, body[5], rel, slots[0], slots[1], slots[2], slots[3], slots[4]);
        Report(kKindBoxRelease, g_itemLog, 6096, user, userNum, box, rel, slots[0], d, t);
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { Fault(2273, userNum, exc); }
}

// ── S2: вход LABEL_69 Char_FunctionItem_Use. 0 — сток; 12/8 — отказ до БД (код в [ebp-121h] пишет стаб). ──
extern "C" int __stdcall P103_OnUseGate(BYTE* ebp)
{
    if (!g_s2On) { return 0; }
    int userNum = -1;
    DWORD exc = 0;
    __try
    {
        InterlockedIncrement(&g_stats.gateChecks);
        void* mgr = *(void**)(ebp - 0x2F8);
        userNum = *(const short*)(ebp + 8);
        const int code = *(const int*)(ebp - 0x204);     // v87 — код ячейки (sub_532B10 проверен стоком)
        const BYTE* user = UserOf(mgr, userNum);
        if (!user) { return 0; }
        const int ui = UiOf(user);
        int grp = 0, src = 0;
        const int r = GateHit(userNum, ui, code, &grp, &src);
        if (!r) { return 0; }
        InterlockedIncrement(r == 12 ? &g_stats.refusedGroup : &g_stats.refusedCode);
        char d[64], t[200];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P103 5450 code %d %s %d in flight (%s) -> 5451 %d", code, r == 12 ? "group" : "code",
                    r == 12 ? grp : code, src == 2 ? "2223" : "2140", r);
        _snprintf_s(t, sizeof(t), _TRUNCATE, "item %d: previous request of cooldown %s %d still in DB (%s), no reply yet -> REFUSE 5451 code %d before DB",
                    code, r == 12 ? "group" : "code", r == 12 ? grp : code, src == 2 ? "auto-use 2223" : "2140", r);
        Report(kKindLatch, g_funcLog, 5450, user, userNum, code, r == 12 ? 1 : 2, r == 12 ? grp : code, d, t);
        return r;
    }
    __except (exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { Fault(5450, userNum, exc); }
    return 0;
}

// ── уход в БД (S2: 2140 с 0x4EEE13/0x4EF02E; S3: 2223 тип 25 — из стаба 0x4F1771 или из P100 G_AUTOUSE): поставить замок. ──
extern "C" void __stdcall P103_OnDbSent(int op, const BYTE* body, int userNum)
{
    if (!g_enabled || !body) { return; }
    const short un = (short)userNum;
    __try
    {
        BYTE src = 0;
        if ((short)op == 2140 && g_s2On) { src = 1; }
        else if ((short)op == 2223 && g_s3On && *(const short*)(body + 17) == 25) { src = 2; }
        if (!src) { return; }
        const int ui = *(const int*)(body + 2), code = *(const int*)(body + 7);   // тело: +2 учётка, +7 код (sendGacha… / Char_FunctionItem_Use)
        const int grp = GroupOf(code), cd = CoolOf(code);
        const bool byCode = g_codeLatch && cd > 0 && src == 1;
        if (grp <= 0 && !byCode) { return; }
        LatchPut(un, ui, grp, byCode ? code : 0, src);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { Fault(op, un, GetExceptionCode()); }
}

// Стаб ухода: замок — только при удачной отправке (sub_5646C0 ≠ 0).
extern "C" void __stdcall P103_AfterDbSend(int op, const BYTE* body, int userNum, int sent)
{
    if (sent) { P103_OnDbSent(op, body, userNum); }
    else { InterlockedIncrement(&g_stats.sendFailed); }
}

// ── после стокового ответа 2141 / 2224 (любой исход): снять замок группы и кода. ──
extern "C" void __stdcall P103_OnReply(int op, int userNum, const BYTE* pkt)
{
    if (!g_enabled || !pkt) { return; }
    const short un = (short)userNum;
    __try
    {
        const BYTE* body = pkt + 9;                      // эхо тела запроса, [0] = Flag
        if (op == 2224 && *(const short*)(body + 17) != 25) { return; }
        const int ui = *(const int*)(body + 2), code = *(const int*)(body + 7);
        LatchDrop(un, ui, GroupOf(code), code);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { Fault(op, un, GetExceptionCode()); }
}

// ── S3: проверка группы автоприменения (вместо sub_4DA990 @0x4F1648). Сток + замок группы в полёте = «откат». ──
extern "C" BOOL __stdcall P103_AutoGate(void* self, int userNum, int group)
{
    const BOOL ok = pCoolOk(self, nullptr, (short)userNum, (BYTE)group);
    if (!ok || !g_s3On || (BYTE)group == 0) { return ok; }
    __try
    {
        const BYTE* user = UserOf(self, (short)userNum);
        if (!user) { return ok; }
        int src = 0;
        const int hit = AutoHit((short)userNum, UiOf(user), (BYTE)group, &src);
        if (hit < 0) { return ok; }
        InterlockedIncrement(&g_stats.refusedAuto);
        char d[64], t[160];
        _snprintf_s(d, sizeof(d), _TRUNCATE, "P103 2223 auto-use group %d in flight (%s) -> cooldown", (BYTE)group, src == 2 ? "2223" : "2140");
        _snprintf_s(t, sizeof(t), _TRUNCATE, "auto-use: cooldown group %d still in DB (%s) -> treated as cooldown (stock 5451 code 12)",
                    (BYTE)group, src == 2 ? "auto-use 2223" : "5450 2140");
        Report(kKindLatch, g_funcLog, 2223, user, (short)userNum, 0, 3, (BYTE)group, d, t);
        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { Fault(2223, (short)userNum, GetExceptionCode()); }
    return ok;
}

extern "C" __declspec(dllexport) void __stdcall P103_GetStats(P103_Stats* out) { if (out) { *out = g_stats; } }

namespace
{
    // S1: вместо `movzx ecx, byte [ebp-26Bh]`.
    __declspec(naked) void St_BoxReply()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P103_OnBoxReply
            popad
            popfd
            movzx ecx, byte ptr [ebp - 26Bh]
            jmp   dword ptr [g_s1Back]              // 0x55B258
        }
    }
    // S2 проверка: вместо `mov ecx,[ebp-204h]` на входе LABEL_69.
    __declspec(naked) void St_UseGate()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  P103_OnUseGate
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   ecx, dword ptr [ebp - 204h]
            jmp   dword ptr [g_s2Back]              // 0x4EE5A7
        refuse:
            mov   byte ptr [ebp - 121h], al         // 12 / 8 — код 5451 (как стоковые отказы группы / кода)
            popad
            popfd
            jmp   dword ptr [g_s2Refuse]            // 0x4EF0C3 — общий выход: 5451 клиенту, в БД ничего
        }
    }
    // Уход в БД (вместо sub_5646C0; thiscall: ecx = CUserMoveManager; [esp+4] op, +8 len, +12 conn, +16 тело, +20 номер; ret 14h):
    //   «следующий вызов» с теми же 5 аргументами и ecx, затем P103_AfterDbSend(op, тело, номер, eax) — замок ставится ТОЛЬКО если
    //   отправка удалась (sub_5646C0 = 0: индекс соединения, длина ≥ 700, ошибка ConnectSend — ответа не будет). eax стока сохранён.
    //   Ревизия 04.11 (S-1): ставить до отправки — замок жил бы LatchTtlMs без ответа. Логика GS однопоточна (RunProcess: клиент, затем
    //   ConnectSocketMsgProcess), ответ не может прийти раньше, чем замок поставлен.
    __declspec(naked) void St_DbSend()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  ecx                           // this
            push  dword ptr [ebp+24]            // номер
            push  dword ptr [ebp+20]            // тело
            push  dword ptr [ebp+16]            // conn
            push  dword ptr [ebp+12]            // len
            push  dword ptr [ebp+8]             // op
            call  dword ptr [g_pNextSend]       // ecx = this; ret 14h
            push  eax
            push  eax                           // результат
            push  dword ptr [ebp+24]            // номер
            push  dword ptr [ebp+20]            // тело
            push  dword ptr [ebp+8]             // op
            call  P103_AfterDbSend              // stdcall, 16 б
            pop   eax
            pop   ecx
            pop   ebp
            ret   14h
        }
    }
    // Ответ 2141 (вместо call sub_4EF270; thiscall: ecx = this, [esp+4] UserNum (i16 в младшем слове), [esp+8] пакет; ret 8):
    //   стоковый приём, затем P103_OnReply — eax стока сохранён.
    __declspec(naked) void St_Reply2141()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  dword ptr [ebp+12]            // пакет
            push  dword ptr [ebp+8]             // UserNum
            call  dword ptr [g_pStock2141]      // ecx = this как пришёл; ret 8
            push  eax
            push  dword ptr [ebp+12]
            push  dword ptr [ebp+8]
            push  2141
            call  P103_OnReply                  // stdcall, 12 б
            pop   eax
            pop   ebp
            ret   8
        }
    }
    __declspec(naked) void St_Reply2224()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  dword ptr [ebp+12]
            push  dword ptr [ebp+8]
            call  dword ptr [g_pStock2224]
            push  eax
            push  dword ptr [ebp+12]
            push  dword ptr [ebp+8]
            push  2224
            call  P103_OnReply
            pop   eax
            pop   ebp
            ret   8
        }
    }
    // S3 проверка группы автоприменения (вместо call sub_4DA990; thiscall: ecx = this, [esp+4] UserNum, [esp+8] группа; ret 8).
    __declspec(naked) void St_AutoGate()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+12]            // группа ([esp+8] до push ecx)
            push  dword ptr [esp+12]            // UserNum ([esp+4])
            push  ecx                           // this
            call  P103_AutoGate                 // stdcall, 12 б
            pop   ecx
            ret   8
        }
    }

    DWORD CallTarget(DWORD va) { const BYTE* p = (const BYTE*)va; return p[0] == 0xE8 ? (DWORD)(va + 5 + *(const int*)(p + 1)) : 0; }
}

PatchResult P103_InFlightFixes()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_sites = (DWORD)Config::GetInt(kSec, L"Sites", 7) & 7u;
    const int ttl = Config::GetInt(kSec, L"LatchTtlMs", 10000);
    g_ttlMs = (ttl >= 1000 && ttl <= 60000) ? (DWORD)ttl : 10000;
    g_codeLatch = Config::GetBool(kSec, L"CodeLatch", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_itemLog = Config::GetInt(kSec, L"ItemLogChannel", 1);
    g_funcLog = Config::GetInt(kSec, L"FuncLogChannel", 8);
    if (g_itemLog < 0 || g_itemLog > 60) { g_itemLog = 1; }
    if (g_funcLog < 0 || g_funcLog > 60) { g_funcLog = 8; }

    // ── 0x4EF02E: своя площадка (байты стока) или цепочка за P75 ─────────────
    const void* p75 = P75_DbSendStub();
    const bool chainP75 = p75 && CallTarget(kS2SendB) == (DWORD)p75;
    // ── 0x4F1771: площадка P100 (уведомление из P100_Call5) или своя ─────────
    const bool viaP100 = CallTarget(kS3Send) != kDbSend;

    // ── сверка площадок и соседей ДО записи ─────────────────────────────────
    Site check[32];
    int n = 0;
    if (g_sites & 1)
    {
        check[n++] = { kS1, kS1Orig, sizeof(kS1Orig) };          check[n++] = { g_s1Back, kS1Back, sizeof(kS1Back) };
        check[n++] = { 0x0055B24C, kS1Prev, sizeof(kS1Prev) };   check[n++] = { 0x0055B219, kS1Copy, sizeof(kS1Copy) };
        check[n++] = { 0x0055B20E, kS1Src, sizeof(kS1Src) };     check[n++] = { 0x0055B1D5, kS1This, sizeof(kS1This) };
    }
    if (g_sites & 2)
    {
        check[n++] = { kS2Gate, kS2GateOrig, sizeof(kS2GateOrig) };   check[n++] = { g_s2Back, kS2GateBack, sizeof(kS2GateBack) };
        check[n++] = { 0x004EE5DE, kS2Group, sizeof(kS2Group) };      check[n++] = { 0x004EE5E7, kS2Code12, sizeof(kS2Code12) };
        check[n++] = { g_s2Refuse, kS2Exit, sizeof(kS2Exit) };        check[n++] = { 0x004EE5D8, kS2This, sizeof(kS2This) };
        check[n++] = { kS2SendA, kS2SendAOrig, sizeof(kS2SendAOrig) }; check[n++] = { 0x004EEE04, kS2SendArgs, sizeof(kS2SendArgs) };
        if (!chainP75) { check[n++] = { kS2SendB, kS2SendBOrig, sizeof(kS2SendBOrig) }; }
        check[n++] = { 0x004EF01F, kS2SendArgs, sizeof(kS2SendArgs) };
        check[n++] = { kDbSend, kDbSendProlog, sizeof(kDbSendProlog) };
        check[n++] = { kS2Reply, kS2ReplyOrig, sizeof(kS2ReplyOrig) }; check[n++] = { 0x00430A9F, kS2ReplyArgs, sizeof(kS2ReplyArgs) };
        check[n++] = { 0x00430AB6, kS2ReplyAfter, sizeof(kS2ReplyAfter) }; check[n++] = { kStock2141, kStock2141Prolog, sizeof(kStock2141Prolog) };
    }
    if (g_sites & 4)
    {
        check[n++] = { kS3Gate, kS3GateOrig, sizeof(kS3GateOrig) };   check[n++] = { 0x004F163C, kS3GateArgs, sizeof(kS3GateArgs) };
        check[n++] = { 0x004F164D, kS3GateAfter, sizeof(kS3GateAfter) };
        if (!viaP100) { check[n++] = { kS3Send, kS3SendOrig, sizeof(kS3SendOrig) }; }
        check[n++] = { 0x004F1765, kS3SendArgs, sizeof(kS3SendArgs) };
        check[n++] = { kS3Reply, kS3ReplyOrig, sizeof(kS3ReplyOrig) }; check[n++] = { 0x0043237F, kS3ReplyArgs, sizeof(kS3ReplyArgs) };
        check[n++] = { 0x00432396, kS3ReplyAfter, sizeof(kS3ReplyAfter) }; check[n++] = { kStock2224, kStock2224Prolog, sizeof(kStock2224Prolog) };
    }
    if (!VerifyAllSites(L"P103", check, n)) { g_enabled = false; return PatchResult::Mismatch; }
    if ((g_sites & 4) && viaP100 && !P100_Active())
    {
        Log::Line(L"    P103: ! 0x%08X занят не P100 (цель 0x%08X) — бит 4 снят", kS3Send, CallTarget(kS3Send));
        g_sites &= ~4u;
    }

    if (!g_csReady) { InitializeCriticalSection(&g_cs); g_csReady = true; }
    memset(g_fl, 0, sizeof(g_fl));
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    // ── запись: сначала снятие (ответы), затем постановка (уходы), последней — проверка ──
    bool ok = true;
    if (g_sites & 1) { ok &= Hook::WriteJmp(kS1, (void*)&St_BoxReply, sizeof(kS1Orig)); }
    if (ok && (g_sites & 2))
    {
        ok &= Hook::WriteCall(kS2Reply, (void*)&St_Reply2141, 5);
        if (ok) { ok &= Hook::WriteCall(kS2SendA, (void*)&St_DbSend, 5); }
        if (ok)
        {
            if (chainP75)
            {
                // общий g_pNextSend верен, только если у P75 «следующим» стоял сам sub_5646C0 (ревизия 04.11, N-4)
                const DWORD prev = P75_ChainDbSend((DWORD)&St_DbSend);
                if (prev != kDbSend)
                {
                    P75_ChainDbSend(prev);
                    Log::Line(L"    P103: ! у P75 «следующий вызов» 0x%08X, а не sub_5646C0 — цепочка 0x4EF02E не ставится", prev);
                    ok = false;
                }
            }
            else { ok &= Hook::WriteCall(kS2SendB, (void*)&St_DbSend, 5); }
        }
        g_s2On = ok;
        if (ok) { ok &= Hook::WriteJmp(kS2Gate, (void*)&St_UseGate, sizeof(kS2GateOrig)); }
    }
    if (ok && (g_sites & 4))
    {
        ok &= Hook::WriteCall(kS3Reply, (void*)&St_Reply2224, 5);
        if (ok && !viaP100) { ok &= Hook::WriteCall(kS3Send, (void*)&St_DbSend, 5); }
        g_s3On = ok;
        if (ok) { ok &= Hook::WriteCall(kS3Gate, (void*)&St_AutoGate, 5); }
    }
    if (!ok)
    {
        Log::Line(L"    P103: ! запись площадки не удалась — стоящие площадки остаются (S2 %d, S3 %d); Enabled=0 и рестарт", g_s2On, g_s3On);
        return PatchResult::Failed;
    }
    Log::Line(L"    P103: Sites 0x%X — коробка 0x55B251 (отказ БД 2273 снимает записи P100); 5450: проверка 0x4EE5A1, уход 0x4EEE13 и 0x4EF02E (%s), "
              L"снятие после 2141 0x430AB1; автоприменение: проверка 0x4F1648, уход 0x4F1771 (%s), снятие после 2224 0x432391; "
              L"замок %u мс, код FT+18 %s; журнал ac.other 168–170 не чаще 1 раза в %d с",
              g_sites, chainP75 ? L"цепочка за P75" : L"своя", viaP100 ? L"уведомление P100" : L"своя", g_ttlMs, g_codeLatch ? L"да" : L"нет",
              g_journalIntervalSec);
    return PatchResult::Applied;
}
