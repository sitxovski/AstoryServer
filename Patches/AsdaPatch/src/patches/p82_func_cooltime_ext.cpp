// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P82 — ★ ОТКАТ ФУНКЦИОНАЛЬНЫХ ПРЕДМЕТОВ С КОДОМ ≥ 600 (полная копия стоковой механики, решение координатора 24.10.2026).
//  [ИСПРАВЛЕНИЕ] — предел стока; протокол НЕ меняется (5451/5452/5465/2157 — стоковые тела и опкоды).
//  Документ: `AstoryServer/Docs/GameServer/func-cooltime-ext-p82.md`. Сток (4e20f0ad), живой GameServer и Indun (e7b4ac38)
//  совпадают побайтно во всех площадках (проверка tools/verify_p82.py, стенд tools/stand_p82).
//
//  ── ПРЕДЕЛ СТОКА ──
//  Откат «по коду» функционального предмета (Function_Table +18, мс) сток держит в таблице CUser+0x3BC41: 600 записей
//  по 12 б {i32 код, u32 длительность, u32 такт старта}, индекс = код. ВСЕ 9 мест стока ограничены кодом < 0x258:
//    проверка sub_4F27F0 (5450 → отказ 5451 код 8), регистрация sub_4F2640 (ответ БД 2141), снятие sub_4F2710 (5452),
//    такт sub_4F24E0 (TimerProcess), сохранение sub_52EEF0 (2157 UPItemCooltime, цикл i < 600), сброс sub_4A2DC0
//    (ClearUserMemory), конструктор 0x4A0610; восстановление charLogonCoolTimeSaveRes@0x528EA0 и
//    charPortalLogonCoolTimeSaveRes@0x52E030 пишут CUser+0x3BC41+12·код БЕЗ проверки (код ≥ 600 = порча памяти CUser).
//  Итог стока: sub_4F27F0 для кода ≥ 600 ВСЕГДА 0 → предметы 600…637 (маунты донора fable) не применяются никогда («Откат:»).
//
//  ── ЧТО ДЕЛАЕТ P82 (для кодов 600…Function_Table.count; коды < 600 — сток, байт в байт) ──
//  Своя таблица откатов по слоту (0..549): до kCap записей {код, длительность, старт}, хозяин слота — Userindex (CUser+0x174).
//    C  0x4F2820 (9 б, sub_4F27F0: cmp код,258h / jl) — код ≥ 600: запись активна → 0 (отказ 8, как сток), иначе 1.
//    G  0x4F2672 (9 б, sub_4F2640) — код ≥ 600: как сток — только если запись не активна и +18 > 0; выход 0x4F2709.
//    T  0x543353 (call sub_4F24E0 в TimerProcess) — своя проверка истечения (как sub_4F24E0/sub_4F2710: перевод такта,
//       elapsed ≥ длительности → снять, 5452 {i32 код} себе), затем сток.
//    S  0x52F374 (call 0x5646C0 — уход 2157 в БД из sub_52EEF0) — свои записи в свободные места блока предметов тела
//       (+186 + 6·j, код −1): правило стока — остаток/1000 > 2 → секунды; истёкшая → снять + 5452. Мест нет → журнал 92.
//    R1 0x5290BE (6 б, вход в мир) / R2 0x52E23A (6 б, после портала) — запись блока восстановления с кодом ≥ 600 НЕ идёт
//       в стоковую запись: код в Function_Table → своя таблица (длительность 1000·сек, старт сейчас), копия 6 б в тело 5465
//       клиенту, групповой откат sub_4DA920(+38) — как сток; код вне таблицы → отброшен, журнал 91 (ловушка закрыта).
//       ★ Страж R1/R2 ставится и при Enabled=0 (ключ RestoreGuard): строки ≥ 600 в dbo.ItemCoolTime не портят CUser.
//    Z  0x527399 (call sub_4A2DC0 в ClearUserMemory — там же сток сбрасывает свою таблицу) — своя таблица слота очищается.
//  Групповой откат (+38, sub_4DA990/sub_4DA920, отказ 12) у кодов ≥ 600 — сток (ветка 5450 и ответ БД его не ограничивают).
//  Журнал P53 ac.other: 91 (восстановление: код вне Function_Table — отброшен), 92 (сохранение: нет места в блоке 2157),
//  93 (своя таблица слота заполнена — отказ 8 / откат не записан) — не чаще JournalIntervalSec на (слот, вид).
//  Строки FuncLog (канал LogChannel = 8, рядом со стоковыми [REQUEST]/[USE]): «[P82] FuncCoolTime REG/END/SAVE/LOAD/DROP».
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>
#include <string.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"

namespace
{
    const wchar_t* kSec = L"P82_FuncCoolTimeExt";

    // ── площадки ─────────────────────────────────────────────────────────────
    // C: sub_4F27F0 (BOOL __thiscall (this, i16 num, u32 code), ret 8) — проверка отката
    const DWORD kSiteC        = 0x004F2820;
    const BYTE  kOrigC[9]     = { 0x81, 0x7D, 0x0C, 0x58, 0x02, 0x00, 0x00, 0x7C, 0x04 };   // cmp [ebp+0Ch],258h ; jl 0x4F282D
    const BYTE  kCProlog[9]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8 };   // 0x4F27F0: [ebp-8] = this
    const BYTE  kCReject[4]   = { 0x33, 0xC0, 0xEB, 0x1C };                                 // 0x4F2829: xor eax,eax ; jmp 0x4F2849
    const BYTE  kCBackO[6]    = { 0x8B, 0x4D, 0x0C, 0x6B, 0xC9, 0x0C };                     // 0x4F282D: mov ecx,[ebp+0Ch] ; imul 0Ch
    const BYTE  kCExitO[6]    = { 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };                     // 0x4F2849: эпилог, ret 8
    DWORD g_pCBack = 0x004F282D, g_pCExit = 0x004F2849;
    // G: sub_4F2640 (__thiscall (this, i16 num, u32 code), ret 8) — регистрация отката (ответ БД 2141)
    const DWORD kSiteG        = 0x004F2672;
    const BYTE  kOrigG[9]     = { 0x81, 0x7D, 0x0C, 0x58, 0x02, 0x00, 0x00, 0x7C, 0x05 };   // cmp [ebp+0Ch],258h ; jl 0x4F2680
    const BYTE  kGProlog[10]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x56, 0x89, 0x4D, 0xF8 };   // 0x4F2640: push esi ; [ebp-8] = this
    const BYTE  kGSkip[5]     = { 0xE9, 0x89, 0x00, 0x00, 0x00 };                           // 0x4F267B: jmp 0x4F2709
    const BYTE  kGBackO[6]    = { 0x8B, 0x4D, 0x0C, 0x6B, 0xC9, 0x0C };                     // 0x4F2680
    const BYTE  kGExitO[7]    = { 0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };               // 0x4F2709: pop esi ; эпилог
    DWORD g_pGBack = 0x004F2680, g_pGExit = 0x004F2709;
    // T: TimerProcess@0x5431C0 — call sub_4F24E0 (__thiscall (this, i16 num), ret 4)
    const DWORD kSiteT        = 0x00543353;
    const BYTE  kOrigT[5]     = { 0xE8, 0x88, 0xF1, 0xFA, 0xFF };
    const BYTE  kTArgs[11]    = { 0x8B, 0x55, 0xF0, 0x66, 0x8B, 0x42, 0x0C, 0x50, 0x8B, 0x4D, 0xE8 };   // 0x543348: push num ; ecx = this
    const BYTE  kTProlog[6]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20 };                     // 0x4F24E0
    DWORD g_pStockTick = 0x004F24E0;
    // S: sub_52EEF0 — call 0x5646C0 (уход 2157 в БД; __thiscall (CUserMoveManager*, op, len, conn, body, num), ret 14h)
    const DWORD kSiteS        = 0x0052F374;
    const BYTE  kOrigS[5]     = { 0xE8, 0x47, 0x53, 0x03, 0x00 };
    const BYTE  kSArgs[42]    = { 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8D, 0x95, 0x28, 0xFD, 0xFF, 0xFF, 0x52, 0x8B, 0x85, 0x1C, 0xFC,
                                  0xFF, 0xFF, 0x8B, 0x48, 0x04, 0xE8, 0xCC, 0x16, 0xF9, 0xFF, 0x50, 0x68, 0x6E, 0x01, 0x00, 0x00,
                                  0x68, 0x6D, 0x08, 0x00, 0x00, 0xB9, 0x38, 0x05, 0x7E, 0x00 };   // 0x52F34A: num; тело [ebp-2D8h]; this [ebp-3E4h]; 16Eh; 86Dh
    const BYTE  kDbSendPro[3] = { 0x55, 0x8B, 0xEC };                                       // 0x5646C0
    DWORD g_pDbSend = 0x005646C0;
    // R1: charLogonCoolTimeSaveRes@0x528EA0 — цикл блока предметов (j = [ebp-6F0h])
    const DWORD kSiteR1       = 0x005290BE;
    const BYTE  kOrigR1[6]    = { 0x8B, 0x95, 0x10, 0xF9, 0xFF, 0xFF };                     // mov edx,[ebp-6F0h]
    const BYTE  kR1Head[21]   = { 0x8B, 0x8D, 0x10, 0xF9, 0xFF, 0xFF, 0x6B, 0xC9, 0x06, 0x83, 0xBC, 0x0D, 0xE1, 0xFD, 0xFF, 0xFF,
                                  0x00, 0x7D, 0x02, 0xEB, 0xCF };                           // 0x5290A9: код [ebp+6j-21Fh] < 0 → дальше
    const BYTE  kR1Back[10]   = { 0x6B, 0xD2, 0x06, 0x8B, 0x84, 0x15, 0xE1, 0xFD, 0xFF, 0xFF };   // 0x5290C4
    const BYTE  kR1Next[9]    = { 0x8B, 0x85, 0x10, 0xF9, 0xFF, 0xFF, 0x83, 0xC0, 0x01 };   // 0x52908D: ++j
    const BYTE  kR1This[6]    = { 0x89, 0x8D, 0x0C, 0xF9, 0xFF, 0xFF };                     // 0x528EB6: [ebp-6F4h] = this
    const BYTE  kR1Sec[8]     = { 0x0F, 0xBF, 0x8C, 0x05, 0xE5, 0xFD, 0xFF, 0xFF };         // 0x529115: сек [ebp+6j-21Bh]
    const BYTE  kR1Dst[7]     = { 0x8D, 0x8C, 0x05, 0x4C, 0xFF, 0xFF, 0xFF };               // 0x529155: тело 5465 [ebp+6j-0B4h]
    DWORD g_pR1Back = 0x005290C4, g_pR1Next = 0x0052908D;
    // R2: charPortalLogonCoolTimeSaveRes@0x52E030 — то же (j = [ebp-6F8h])
    const DWORD kSiteR2       = 0x0052E23A;
    const BYTE  kOrigR2[6]    = { 0x8B, 0x95, 0x08, 0xF9, 0xFF, 0xFF };
    const BYTE  kR2Head[21]   = { 0x8B, 0x8D, 0x08, 0xF9, 0xFF, 0xFF, 0x6B, 0xC9, 0x06, 0x83, 0xBC, 0x0D, 0xDD, 0xFD, 0xFF, 0xFF,
                                  0x00, 0x7D, 0x02, 0xEB, 0xCF };                           // 0x52E225: код [ebp+6j-223h]
    const BYTE  kR2Back[10]   = { 0x6B, 0xD2, 0x06, 0x8B, 0x84, 0x15, 0xDD, 0xFD, 0xFF, 0xFF };   // 0x52E240
    const BYTE  kR2Next[9]    = { 0x8B, 0x85, 0x08, 0xF9, 0xFF, 0xFF, 0x83, 0xC0, 0x01 };   // 0x52E209
    const BYTE  kR2This[6]    = { 0x89, 0x8D, 0x04, 0xF9, 0xFF, 0xFF };                     // 0x52E046: [ebp-6FCh] = this
    const BYTE  kR2Sec[8]     = { 0x0F, 0xBF, 0x8C, 0x05, 0xE1, 0xFD, 0xFF, 0xFF };         // 0x52E291: сек [ebp+6j-21Fh]
    const BYTE  kR2Dst[7]     = { 0x8D, 0x8C, 0x05, 0x4C, 0xFF, 0xFF, 0xFF };               // 0x52E2D1: тело 5465 [ebp+6j-0B4h]
    DWORD g_pR2Back = 0x0052E240, g_pR2Next = 0x0052E209;
    // Z: ClearUserMemory@0x527350 — call sub_4A2DC0 (__thiscall (0x60AD18, i16 num, u8), ret 8): сток сбрасывает свою таблицу
    const DWORD kSiteZ        = 0x00527399;
    const BYTE  kOrigZ[5]     = { 0xE8, 0x22, 0xBA, 0xF7, 0xFF };
    const BYTE  kZArgs[9]     = { 0x8A, 0x45, 0x0C, 0x50, 0x66, 0x8B, 0x4D, 0x08, 0x51 };   // 0x52738B: push a3 ; push num
    const BYTE  kZAfter[6]    = { 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00 };                     // 0x52739E
    const BYTE  kResetPro[5]  = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };                           // 0x4A2DC0
    DWORD g_pReset = 0x004A2DC0;
    // функции сервера
    const BYTE  kGroupPro[6]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 };                     // 0x4DA920
    constexpr DWORD kGroupSet  = 0x004DA920;   // int __thiscall (this, i16 num, i16 длительность мс, u8 группа) — групповой откат
    constexpr DWORD kFuncTable = 0x005F5E70;   // Function_Table: записи по 48 б, (код − 1) · 48
    constexpr DWORD kFuncCount = 0x005F5EA4;   // число записей Function_Table
    constexpr int   kRecLen    = 48;
    constexpr int   kOffDur    = 18;           // +18 u32 откат по коду, мс
    constexpr int   kOffGroup  = 38;           // +38 u8 группа отката (0 — нет)

    constexpr int kBase       = 0x258;         // 600 — предел стоковой таблицы
    constexpr int kSlots      = 0x226;         // 550 слотов
    constexpr int kCap        = 64;            // записей своей таблицы на слот (сохраняется не больше 30 — предел блока 2157)
    constexpr int kOffUserIndex = 0x174;       // CUser: Userindex
    constexpr int kOffSlot      = 0x18C;       // CUser: Charidx (слот персонажа)
    constexpr int kOffName      = 0x178;       // CUser: имя cp1251
    constexpr int kSaveItems    = 186;         // тело 2157: блок предметов 30 × {i32 код, i16 сек}
    constexpr int kSaveCount    = 30;
    constexpr short kOp5452     = 5452;

    typedef BYTE* (__thiscall *FnGetUser)(void* self, short num);
    typedef int   (__thiscall *FnSendPacket)(void* net, short op, short len, short to, void* body, short from, int pad);
    typedef int   (__thiscall *FnGroupSet)(void* self, short num, short durMs, BYTE group);
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);
    const FnGetUser    GetUser    = (FnGetUser)Srv::kGetUser;
    const FnSendPacket SendPacket = (FnSendPacket)Srv::kSendPacket;
    const FnGroupSet   GroupSet   = (FnGroupSet)kGroupSet;
    const FnSrvLog     SrvLog     = (FnSrvLog)Srv::kLog;

    // Виды журнала ac.other — реестр ac-journal-p53.md §9 (P81 — 88…90): 91…93.
    enum Kind : BYTE { kKindBadRestore = 91, kKindSaveFull = 92, kKindTableFull = 93 };
    enum JIdx : int  { kJBad = 0, kJSave = 1, kJFull = 2 };

    struct Ent  { int code; DWORD dur; DWORD start; };
    struct Slot { int ui; volatile LONG n; Ent e[kCap]; DWORD jLast[3]; int jSup[3]; };
    Slot g_slot[kSlots] = {};
    CRITICAL_SECTION g_cs; bool g_csReady = false;

    // ── настройки ──
    bool g_on        = false;   // механика P82 (площадки C/G/T/S/Z) поставлена
    bool g_guard     = false;   // страж восстановления R1/R2 поставлен
    bool g_saveRest  = true;    // SaveRestore: сохранять/восстанавливать свои откаты через 2157/5465
    bool g_trace     = true;    // строки FuncLog
    int  g_logChannel = 8;      // Log_Func
    int  g_journalIntervalSec = 10;
    volatile LONG g_logN = 0;

    P82_Stats g_stats = {};

    bool SlotOk(int num) { return num >= 0 && num < kSlots; }
    bool ShouldLog() { const LONG n = InterlockedIncrement(&g_logN); return g_trace && (n <= 5000 || (n % 1000) == 0); }

    BYTE* FuncRec(int code)
    {
        BYTE* t = *(BYTE**)kFuncTable;
        const int n = *(int*)kFuncCount;
        if (!t || code < 1 || code > n) { return nullptr; }
        return t + kRecLen * (code - 1);
    }

    int IndexOf(const BYTE* user)
    {
        int ui = -1;
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); } } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }
        return ui;
    }

    // Число записей Function_Table (−1 — память не читается: стенд без .bss).
    int FuncCountSafe()
    {
        int n = -1;
        __try { n = *(const int*)kFuncCount; } __except (EXCEPTION_EXECUTE_HANDLER) { n = -1; }
        return n;
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }

    // Слот под g_cs: другой Userindex — записи прежнего хозяина сброшены (выход не дошёл до площадки Z).
    Slot& SlotOf(int num, int ui)
    {
        Slot& s = g_slot[num];
        if (s.ui != ui)
        {
            if (s.n) { InterlockedIncrement(&g_stats.staleReset); }
            memset(&s, 0, sizeof(s));
            s.ui = ui;
        }
        return s;
    }

    int Find(const Slot& s, int code)
    {
        for (int i = 0; i < s.n; ++i) { if (s.e[i].code == code) { return i; } }
        return -1;
    }

    void Remove(Slot& s, int i)
    {
        s.e[i] = s.e[s.n - 1];
        InterlockedDecrement(&s.n);
    }

    // Истёк ли откат (как sub_4F24E0: такт меньше старта — старт = такт; elapsed ≥ длительности).
    bool Expired(Ent& e, DWORD now, DWORD* remain)
    {
        if (now < e.start) { e.start = now; }
        const DWORD el = now - e.start;
        if (el >= e.dur) { if (remain) { *remain = 0; } return true; }
        if (remain) { *remain = e.dur - el; }
        return false;
    }

    // Под g_cs: разрешить строку журнала (слот, вид) не чаще g_journalIntervalSec.
    bool AllowJournal(Slot& s, int j, DWORD now, int* sup)
    {
        if (g_journalIntervalSec > 0 && s.jLast[j] && now - s.jLast[j] < (DWORD)g_journalIntervalSec * 1000)
        {
            ++s.jSup[j];
            return false;
        }
        s.jLast[j] = now ? now : 1;
        *sup = s.jSup[j];
        s.jSup[j] = 0;
        return true;
    }

    void Journal(BYTE kind, int opcode, const BYTE* user, int num, int v0, int v1, int v2, const char* text, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)num;
        e.ip = P47_PeerIpv4(num);
        e.suppressed = suppressed;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIndex);
                e.charSlot  = user[kOffSlot];
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, text);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    // Журнал вида kind с ограничителем слота (берёт g_cs сам).
    void JournalLimited(int j, BYTE kind, int opcode, const BYTE* user, int num, int ui, int v0, int v1, int v2, const char* text)
    {
        int sup = 0; bool write = false;
        if (ui < 0 || !SlotOk(num)) { Journal(kind, opcode, user, num, v0, v1, v2, text, 0); return; }   // нет CUser — слот не трогаем
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        write = AllowJournal(s, j, GetTickCount(), &sup);
        LeaveCriticalSection(&g_cs);
        if (write) { Journal(kind, opcode, user, num, v0, v1, v2, text, sup); }
        else { InterlockedIncrement(&g_stats.suppressed); }
    }

    void Send5452(void* self, short num, int code)
    {
        __try
        {
            void* net = *(void**)((BYTE*)self + 4);
            int body = code;
            SendPacket(net, kOp5452, 4, num, &body, 0, 1);       // как sub_4F2710: (net, 5452, 4, num, &код, 0, 1)
            InterlockedIncrement(&g_stats.sent5452);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    }
}

// ── C: проверка отката кода ≥ 600 (вместо стокового «всегда 0»). 1 — можно, 0 — отказ 5451 код 8 ──
extern "C" int __stdcall P82_Check(void* self, int num32, int code)
{
    const short num = (short)num32;
    InterlockedIncrement(&g_stats.checkSeen);
    if (!g_on) { return 0; }
    __try
    {
        BYTE* user = GetUser(self, num);
        if (!user || !SlotOk(num)) { return 0; }                     // сток: нет CUser → 0
        const int ui = IndexOf(user);
        int r = 1; bool full = false;
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        if (Find(s, code) >= 0) { r = 0; }                           // запись активна (снимает только такт T — как сток)
        else if (s.n >= kCap) { r = 0; full = true; }
        LeaveCriticalSection(&g_cs);
        if (r == 0 && !full) { InterlockedIncrement(&g_stats.checkActive); }
        if (full)
        {
            InterlockedIncrement(&g_stats.tableFull);
            char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "5450 code %d: P82 table full (%d) -> refuse 8", code, kCap);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime FULL..! %s, UserIndex:%d, Code:%d, Cap:%d -> Result 8", NameOf(user), ui, code, kCap); }
            JournalLimited(kJFull, kKindTableFull, 5450, user, num, ui, code, kCap, 1, d);
        }
        return r;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); return 0; }
}

// ── G: регистрация отката кода ≥ 600 (ответ БД 2141). Как sub_4F2640: запись не активна и +18 > 0 ──
extern "C" void __stdcall P82_Register(void* self, int num32, int code)
{
    const short num = (short)num32;
    if (!g_on) { return; }
    __try
    {
        BYTE* user = GetUser(self, num);
        if (!user || !SlotOk(num)) { return; }
        const BYTE* rec = FuncRec(code);
        if (!rec) { return; }
        const DWORD dur = *(const DWORD*)(rec + kOffDur);
        if ((int)dur <= 0) { InterlockedIncrement(&g_stats.regNoDur); return; }   // сток: *(int*)(+18) > 0
        const int ui = IndexOf(user);
        int what = 0;   // 1 — записано, 2 — уже активна, 3 — нет места
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        if (Find(s, code) >= 0) { what = 2; }
        else if (s.n >= kCap) { what = 3; }
        else
        {
            Ent& e = s.e[s.n];
            e.code = code; e.dur = dur; e.start = GetTickCount();
            InterlockedIncrement(&s.n);
            what = 1;
        }
        LeaveCriticalSection(&g_cs);
        if (what == 1)
        {
            InterlockedIncrement(&g_stats.regAdded);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime REG..! %s, UserIndex:%d, Code:%d, CoolTime:%u", NameOf(user), ui, code, dur); }
        }
        else if (what == 2) { InterlockedIncrement(&g_stats.regActive); }
        else
        {
            InterlockedIncrement(&g_stats.tableFull);
            char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "2141 code %d: P82 table full (%d), cooltime lost", code, kCap);
            JournalLimited(kJFull, kKindTableFull, 2141, user, num, ui, code, kCap, 2, d);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
}

// ── T: такт TimerProcess (до стокового sub_4F24E0): истёкшие свои записи снимаются, 5452 себе (как sub_4F2710) ──
extern "C" void __stdcall P82_Tick(void* self, int num32)
{
    const short num = (short)num32;
    if (!g_on || !SlotOk(num) || g_slot[num].n == 0) { return; }
    __try
    {
        BYTE* user = GetUser(self, num);
        if (!user) { return; }
        const int ui = IndexOf(user);
        int codes[kCap]; int k = 0;
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        const DWORD now = GetTickCount();
        for (int i = 0; i < s.n; )
        {
            if (Expired(s.e[i], now, nullptr)) { codes[k++] = s.e[i].code; Remove(s, i); }
            else { ++i; }
        }
        LeaveCriticalSection(&g_cs);
        for (int i = 0; i < k; ++i)
        {
            InterlockedIncrement(&g_stats.expired);
            Send5452(self, num, codes[i]);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime END..! %s, UserIndex:%d, Code:%d -> 5452", NameOf(user), ui, codes[i]); }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
}

// ── S: уход 2157 в БД (выход/портал, sub_52EEF0): свои откаты — в свободные места блока предметов (правило стока) ──
extern "C" void __stdcall P82_OnSave(void* self, BYTE* body, int num32)
{
    const short num = (short)num32;
    if (!g_on || !g_saveRest || !body || !SlotOk(num) || g_slot[num].n == 0) { return; }
    __try
    {
        BYTE* user = GetUser(self, num);
        if (!user) { return; }
        const int ui = IndexOf(user);
        int endCodes[kCap]; int ke = 0;
        int lostCode[kCap]; int lostSec[kCap]; int kl = 0;
        int savedCode[kCap]; int savedSec[kCap]; int ks = 0;
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        const DWORD now = GetTickCount();
        for (int i = 0; i < s.n; )
        {
            DWORD remain = 0;
            if (Expired(s.e[i], now, &remain)) { endCodes[ke++] = s.e[i].code; Remove(s, i); continue; }   // сток: sub_4F2710
            const DWORD sec = remain / 1000;
            if (sec > 2)                                                                                  // сток: v26 > 2
            {
                int j = 0;
                while (j < kSaveCount && *(const int*)(body + kSaveItems + 6 * j) != -1) { ++j; }
                if (j < kSaveCount)
                {
                    *(int*)(body + kSaveItems + 6 * j) = s.e[i].code;
                    *(short*)(body + kSaveItems + 6 * j + 4) = (short)sec;
                    savedCode[ks] = s.e[i].code; savedSec[ks] = (int)sec; ++ks;
                }
                else { lostCode[kl] = s.e[i].code; lostSec[kl] = (int)sec; ++kl; }
            }
            else { InterlockedIncrement(&g_stats.saveShort); }
            ++i;
        }
        LeaveCriticalSection(&g_cs);
        for (int i = 0; i < ke; ++i) { InterlockedIncrement(&g_stats.expired); Send5452(self, num, endCodes[i]); }
        for (int i = 0; i < ks; ++i)
        {
            InterlockedIncrement(&g_stats.saved);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime SAVE..! %s, UserIndex:%d, Code:%d, Remain:%d s (2157)", NameOf(user), ui, savedCode[i], savedSec[i]); }
        }
        for (int i = 0; i < kl; ++i)
        {
            InterlockedIncrement(&g_stats.saveNoRoom);
            char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "2157 code %d remain %d s: no free item entry (30)", lostCode[i], lostSec[i]);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime SAVE_FULL..! %s, UserIndex:%d, Code:%d, Remain:%d s - not saved", NameOf(user), ui, lostCode[i], lostSec[i]); }
            JournalLimited(kJSave, kKindSaveFull, 2157, user, num, ui, lostCode[i], lostSec[i], kSaveCount, d);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
}

// ── R1/R2: запись блока восстановления с кодом ≥ 600 (вход в мир / портал). site: 1 — 0x528EA0, 2 — 0x52E030 ──
//   Стоковая запись CUser+0x3BC41+12·код не выполняется ни при каком исходе (трамплин уходит на ++j).
extern "C" void __stdcall P82_OnRestore(int site, BYTE* ebp)
{
    __try
    {
        const int j     = *(const int*)(ebp - (site == 2 ? 0x6F8 : 0x6F0));
        if (j < 0 || j >= kSaveCount) { InterlockedIncrement(&g_stats.faults); return; }
        BYTE* entry     = ebp - (site == 2 ? 0x223 : 0x21F) + 6 * j;
        BYTE* dst       = ebp - 0xB4 + 6 * j;                         // тело 5465 клиенту: блок предметов
        void* self      = *(void**)(ebp - (site == 2 ? 0x6FC : 0x6F4));
        const short num = *(const short*)(ebp + 8);
        const int code  = *(const int*)entry;
        const int sec   = *(const short*)(entry + 4);
        BYTE* user = GetUser(self, num);
        const int ui = IndexOf(user);
        const BYTE* rec = FuncRec(code);
        if (!rec)
        {
            InterlockedIncrement(&g_stats.restoreBad);
            char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "%s code %d sec %d: not in Function_Table, dropped", site == 2 ? "portal" : "logon", code, sec);
            SrvLog(g_logChannel, "\t[P82] FuncCoolTime DROP..! %s, UserIndex:%d, Code:%d, Remain:%d s - not a function item (stock would corrupt CUser)",
                   NameOf(user), ui, code, sec);
            JournalLimited(kJBad, kKindBadRestore, 5465, user, num, ui, code, sec, site, d);
            return;
        }
        if (!g_on || !g_saveRest || !user || !SlotOk(num))
        {
            InterlockedIncrement(&g_stats.restoreOff);
            if (ShouldLog()) { SrvLog(g_logChannel, "\t[P82] FuncCoolTime DROP..! %s, UserIndex:%d, Code:%d, Remain:%d s - P82 off (guard only)", NameOf(user), ui, code, sec); }
            return;
        }
        const DWORD dur = sec > 0 ? (DWORD)(1000 * sec) : 0;          // сток: 1000·сек (≤ 0 — истечёт следующим тактом)
        bool full = false;
        EnterCriticalSection(&g_cs);
        Slot& s = SlotOf(num, ui);
        int i = Find(s, code);
        if (i < 0 && s.n < kCap) { i = s.n; InterlockedIncrement(&s.n); }
        if (i >= 0) { s.e[i].code = code; s.e[i].dur = dur; s.e[i].start = GetTickCount(); }
        else { full = true; }
        LeaveCriticalSection(&g_cs);
        if (full)
        {
            InterlockedIncrement(&g_stats.tableFull);
            char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "restore code %d: P82 table full (%d), cooltime lost", code, kCap);
            JournalLimited(kJFull, kKindTableFull, 5465, user, num, ui, code, kCap, 3, d);
            return;
        }
        memcpy(dst, entry, 6);                                        // сток: memcpy(тело 5465 + 6j, запись, 6)
        const BYTE group = rec[kOffGroup];
        if (group) { GroupSet(self, num, (short)(1000 * sec), group); InterlockedIncrement(&g_stats.groupSet); }   // сток: word длительности
        InterlockedIncrement(&g_stats.restored);
        if (ShouldLog())
        {
            SrvLog(g_logChannel, "\t[P82] FuncCoolTime LOAD..! %s, UserIndex:%d, Code:%d, Remain:%d s, Group:%d (%s)", NameOf(user), ui, code, sec,
                   group, site == 2 ? "portal" : "logon");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
}

// ── Z: ClearUserMemory (рядом со стоковым сбросом sub_4A2DC0) — своя таблица слота очищается ──
extern "C" void __stdcall P82_OnUserClear(int num32)
{
    const short num = (short)num32;
    if (!g_on || !SlotOk(num)) { return; }
    EnterCriticalSection(&g_cs);
    if (g_slot[num].n) { InterlockedIncrement(&g_stats.cleared); }
    memset(&g_slot[num], 0, sizeof(Slot));
    LeaveCriticalSection(&g_cs);
}

extern "C" __declspec(dllexport) void __stdcall P82_GetStats(P82_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // C. Вход по jmp из 0x4F2820 (код ≥ 0 уже проверен стоком 0x4F281A). [ebp-8] = this, [ebp+8] = num, [ebp+0Ch] = код.
    __declspec(naked) void TrampC()
    {
        __asm
        {
            cmp   dword ptr [ebp+0Ch], 258h        // замещённое
            jl    BackC
            push  dword ptr [ebp+0Ch]              // код
            movsx eax, word ptr [ebp+8]
            push  eax                              // num
            push  dword ptr [ebp-8]                // this
            call  P82_Check                        // stdcall, 12 б; eax = результат (BOOL, как сток)
            jmp   dword ptr [g_pCExit]             // 0x4F2849 — эпилог, ret 8
        BackC:
            jmp   dword ptr [g_pCBack]             // 0x4F282D — сток (код < 600)
        }
    }

    // G. Вход по jmp из 0x4F2672 (код ≥ 0 проверен стоком 0x4F266C). Выход 0x4F2709 (pop esi — сохранён прологом).
    __declspec(naked) void TrampG()
    {
        __asm
        {
            cmp   dword ptr [ebp+0Ch], 258h        // замещённое
            jl    BackG
            push  dword ptr [ebp+0Ch]
            movsx eax, word ptr [ebp+8]
            push  eax
            push  dword ptr [ebp-8]
            call  P82_Register                     // stdcall, 12 б
            jmp   dword ptr [g_pGExit]             // 0x4F2709
        BackG:
            jmp   dword ptr [g_pGBack]             // 0x4F2680
        }
    }

    // T. Вместо `call sub_4F24E0` в TimerProcess: ecx = this, [esp+4] = num. Свой такт, затем хвостом — сток (ret 4 его).
    __declspec(naked) void TrampT()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+8]                // num
            push  ecx                              // this
            call  P82_Tick                         // stdcall, 8 б
            pop   ecx
            jmp   dword ptr [g_pStockTick]         // 0x4F24E0
        }
    }

    // S. Вместо `call 0x5646C0` (2157): [esp+4] op, +8 len, +12 conn, +16 тело, +20 num; this sub_52EEF0 — [ebp-3E4h].
    __declspec(naked) void TrampS()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+24]               // num   ([esp+20] до push ecx)
            push  dword ptr [esp+24]               // тело  ([esp+16] до двух push)
            push  dword ptr [ebp-3E4h]             // this
            call  P82_OnSave                       // stdcall, 12 б
            pop   ecx
            jmp   dword ptr [g_pDbSend]            // 0x5646C0 — уход в БД (сток)
        }
    }

    // R1. Вход по jmp из 0x5290BE: запись j с кодом ≥ 0. Код < 600 — сток (edx = j); иначе P82 и ++j.
    __declspec(naked) void TrampR1()
    {
        __asm
        {
            mov   edx, dword ptr [ebp-6F0h]        // замещённое: j
            mov   eax, edx
            imul  eax, eax, 6
            cmp   dword ptr [ebp+eax-21Fh], 258h
            jl    BackR1
            push  ebp
            push  1
            call  P82_OnRestore                    // stdcall, 8 б
            jmp   dword ptr [g_pR1Next]            // 0x52908D — ++j (стоковая запись CUser не выполняется)
        BackR1:
            jmp   dword ptr [g_pR1Back]            // 0x5290C4
        }
    }

    // R2. Вход по jmp из 0x52E23A (портал): то же, j = [ebp-6F8h], запись [ebp+6j-223h].
    __declspec(naked) void TrampR2()
    {
        __asm
        {
            mov   edx, dword ptr [ebp-6F8h]
            mov   eax, edx
            imul  eax, eax, 6
            cmp   dword ptr [ebp+eax-223h], 258h
            jl    BackR2
            push  ebp
            push  2
            call  P82_OnRestore
            jmp   dword ptr [g_pR2Next]            // 0x52E209
        BackR2:
            jmp   dword ptr [g_pR2Back]            // 0x52E240
        }
    }

    // Z. Вместо `call sub_4A2DC0` в ClearUserMemory: [esp+4] = num (i16 в dword), [esp+8] = a3; ecx = 0x60AD18.
    __declspec(naked) void TrampZ()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+8]                // num
            call  P82_OnUserClear                  // stdcall, 4 б
            pop   ecx
            jmp   dword ptr [g_pReset]             // 0x4A2DC0 — стоковый сброс CUser (ret 8)
        }
    }
}

PatchResult P82_FuncCoolTimeExt()
{
    const bool enabled = Config::GetBool(kSec, L"Enabled", true);
    const bool guard   = Config::GetBool(kSec, L"RestoreGuard", true);
    g_saveRest = Config::GetBool(kSec, L"SaveRestore", true);
    g_trace    = Config::GetBool(kSec, L"LogEvents", true);
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 8);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 8; }
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    if (!enabled && !guard)
    {
        Log::Line(L"    P82: выключен (Enabled=0, RestoreGuard=0) — коды >= 600 как в стоке: применение всегда «откат» (5451 код 8); "
                  L"! строки >= 600 в dbo.ItemCoolTime при входе испортят CUser");
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    Site check[40];
    int  k = 0;
    check[k++] = { kSiteR1,    kOrigR1,  sizeof(kOrigR1)  };
    check[k++] = { 0x005290A9, kR1Head,  sizeof(kR1Head)  };
    check[k++] = { g_pR1Back,  kR1Back,  sizeof(kR1Back)  };
    check[k++] = { g_pR1Next,  kR1Next,  sizeof(kR1Next)  };
    check[k++] = { 0x00528EB6, kR1This,  sizeof(kR1This)  };
    check[k++] = { 0x00529115, kR1Sec,   sizeof(kR1Sec)   };
    check[k++] = { 0x00529155, kR1Dst,   sizeof(kR1Dst)   };
    check[k++] = { kSiteR2,    kOrigR2,  sizeof(kOrigR2)  };
    check[k++] = { 0x0052E225, kR2Head,  sizeof(kR2Head)  };
    check[k++] = { g_pR2Back,  kR2Back,  sizeof(kR2Back)  };
    check[k++] = { g_pR2Next,  kR2Next,  sizeof(kR2Next)  };
    check[k++] = { 0x0052E046, kR2This,  sizeof(kR2This)  };
    check[k++] = { 0x0052E291, kR2Sec,   sizeof(kR2Sec)   };
    check[k++] = { 0x0052E2D1, kR2Dst,   sizeof(kR2Dst)   };
    check[k++] = { kGroupSet,  kGroupPro, sizeof(kGroupPro) };
    if (enabled)
    {
        check[k++] = { kSiteC,     kOrigC,    sizeof(kOrigC)    };
        check[k++] = { 0x004F27F0, kCProlog,  sizeof(kCProlog)  };
        check[k++] = { 0x004F2829, kCReject,  sizeof(kCReject)  };
        check[k++] = { g_pCBack,   kCBackO,   sizeof(kCBackO)   };
        check[k++] = { g_pCExit,   kCExitO,   sizeof(kCExitO)   };
        check[k++] = { kSiteG,     kOrigG,    sizeof(kOrigG)    };
        check[k++] = { 0x004F2640, kGProlog,  sizeof(kGProlog)  };
        check[k++] = { 0x004F267B, kGSkip,    sizeof(kGSkip)    };
        check[k++] = { g_pGBack,   kGBackO,   sizeof(kGBackO)   };
        check[k++] = { g_pGExit,   kGExitO,   sizeof(kGExitO)   };
        check[k++] = { kSiteT,     kOrigT,    sizeof(kOrigT)    };
        check[k++] = { 0x00543348, kTArgs,    sizeof(kTArgs)    };
        check[k++] = { g_pStockTick, kTProlog, sizeof(kTProlog) };
        check[k++] = { kSiteS,     kOrigS,    sizeof(kOrigS)    };
        check[k++] = { 0x0052F34A, kSArgs,    sizeof(kSArgs)    };
        check[k++] = { g_pDbSend,  kDbSendPro, sizeof(kDbSendPro) };
        check[k++] = { kSiteZ,     kOrigZ,    sizeof(kOrigZ)    };
        check[k++] = { 0x0052738B, kZArgs,    sizeof(kZArgs)    };
        check[k++] = { 0x0052739E, kZAfter,   sizeof(kZAfter)   };
        check[k++] = { g_pReset,   kResetPro, sizeof(kResetPro) };
    }
    if (!VerifyAllSites(L"P82", check, k)) { return PatchResult::Mismatch; }

    if (!g_csReady) { InitializeCriticalSection(&g_cs); g_csReady = true; }
    memset(g_slot, 0, sizeof(g_slot));
    g_on = enabled;

    // ── запись: сначала сброс/такт/сохранение (без C/G своих записей нет — чистый сток), затем G, последней C; страж R ──
    struct W { DWORD va; const void* stub; SIZE_T len; bool jmp; } writes[8];
    int w = 0;
    if (enabled)
    {
        writes[w++] = { kSiteZ, &TrampZ, sizeof(kOrigZ), false };
        writes[w++] = { kSiteT, &TrampT, sizeof(kOrigT), false };
        writes[w++] = { kSiteS, &TrampS, sizeof(kOrigS), false };
    }
    writes[w++] = { kSiteR1, &TrampR1, sizeof(kOrigR1), true };
    writes[w++] = { kSiteR2, &TrampR2, sizeof(kOrigR2), true };
    if (enabled)
    {
        writes[w++] = { kSiteG, &TrampG, sizeof(kOrigG), true };
        writes[w++] = { kSiteC, &TrampC, sizeof(kOrigC), true };
    }
    for (int i = 0; i < w; ++i)
    {
        const bool ok = writes[i].jmp ? Hook::WriteJmp(writes[i].va, writes[i].stub, writes[i].len)
                                      : Hook::WriteCall(writes[i].va, writes[i].stub, writes[i].len);
        if (!ok)
        {
            Log::Line(L"    P82: ! запись @0x%08X не удалась — патч остаётся частично, НЕ использовать: Enabled=0 и рестарт", writes[i].va);
            return PatchResult::Failed;
        }
    }
    g_guard = true;

    const int fcount = FuncCountSafe();   // стенды с сырыми секциями (stand_map) .bss не раскладывают — чтение под __try
    if (enabled)
    {
        Log::Line(L"    P82: откат функциональных предметов с кодом 600..%d (Function_Table, записей %d) — своя таблица до %d записей на слот; "
                  L"C @0x%08X -> 0x%08X (проверка, отказ 8), G @0x%08X -> 0x%08X (регистрация), T @0x%08X (такт, 5452), "
                  L"Z @0x%08X (сброс слота в ClearUserMemory)", fcount, fcount, kCap, kSiteC, (DWORD)&TrampC, kSiteG, (DWORD)&TrampG,
                  kSiteT, kSiteZ);
        Log::Line(L"    P82: сохранение/восстановление через 2157/5465 (dbo.ItemCoolTime): %s; S @0x%08X; групповой откат (+38) — сток",
                  g_saveRest ? L"ВКЛ" : L"выкл (SaveRestore=0 — откаты >= 600 при выходе теряются)", kSiteS);
    }
    else
    {
        Log::Line(L"    P82: Enabled=0 — механика выключена (коды >= 600 как в стоке: отказ 8); стоит ТОЛЬКО страж восстановления");
    }
    Log::Line(L"    P82: страж восстановления R1 @0x%08X (вход) / R2 @0x%08X (портал): код >= 600 в стоковую запись CUser+0x3BC41 не идёт%s; "
              L"журнал ac.other 91/92/93 — не чаще 1/%d с на (слот, вид); FuncLog канал %d%s",
              kSiteR1, kSiteR2, enabled && g_saveRest ? L" (в Function_Table — своя таблица + 5465)" : L" (отбрасывается)",
              g_journalIntervalSec, g_logChannel, g_trace ? L"" : L" (LogEvents=0)");
    if (fcount >= 0 && fcount < kBase) { Log::Line(L"    P82: Function_Table %d записей (< 600) — кодов >= 600 нет, патч стоит вхолостую", fcount); }
    return PatchResult::Applied;
}
