// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L08 — ★ ИСПРАВЛЕНИЕ [ОРИГИНАЛ]: утечка массива активных подключений CUser.
//
//  ЭТО НАША ПРАВКА дефекта стока (окно клиента 1098 «The connection to the server was lost due to
//  an unstable network» при входе = 4101 код 1 из пинг-сторожа Check_DisconnectUser).
//
//  ── ПРИЧИНА ──
//  Кадры 20000 (accept) и 10000 (разрыв) идут в одну очередь, её разбирают 10 потоков. ProcConnect
//  (0x405A90) ждёт замок CUserProc и только потом зовёт SetEmpty_ListenArray (0x403160); ClearConnect
//  (0x405FE0) замка не берёт и зовёт ClearListenArrayIndex (0x4034A0) сразу. У соединения, закрытого
//  сразу после connect (сканер, health-check, отказ L07), Clear приходит РАНЬШЕ SetEmpty: позиция слота
//  ещё −1 → «failed 1», ничего не снято; затем SetEmpty добавляет запись для мёртвого соединения.
//  Следующее подключение на тот же слот добавляет ВТОРУЮ запись (позиция перезаписана), Clear снимает
//  только её → мёртвые копии слота копятся. Сторож (WM_TIMER 2, раз в 8 с) по каждой копии делает
//  ++PingCount → у живого игрока на этом слоте счётчик растёт в N раз быстрее → >5 → кик 4101 код 1
//  через 4–8 с после входа. Число записей (CurrentUserCount) растёт до 550 → SetEmpty отказывает всем.
//
//  ── ЧЕМ ЛЕЧИМ (все части — под замком массива this+0xCDA8C, он рекурсивный) ──
//  Признак «соединение слота разорвано» — сокет слота IOCP = −1: его пишет только close 0x4183F0 (из DisConnect
//  и из IoWorker), новый accept 0x41887F пишет живой сокет ДО вброса своего кадра 20000. Флаг IOCP (+4) НЕ берём:
//  BufferingAccept 0x415630 ставит его в 1 на каждый кадр данных и может оставить 1 у уже закрытого слота (ревизия).
//  1) ReuseSlot  — площадка 0x405E25 (call SetEmpty из ProcConnect): если у слота уже есть валидная
//     запись (pos ≤ последний индекс и arr[pos] == слот) — вторую не добавляем, запись переиспользуется:
//     поля слота размечаются как в стоковом SetEmpty, плюс личность сессии и блоки входа сбрасываются
//     как в стоковом Clear (новое соединение не наследует прежний вход — L04). Счётчики не растут.
//  2) EarlyClear — там же, после SetEmpty: если соединение слота УЖЕ разорвано (сокет −1), запись сразу
//     снимается стоковым Clear. ProcConnect после успешного SetEmpty записи не касается (дизасм 0x405E37:
//     при результате 1 — сразу выход), так что ранний Clear ничего не ломает; запоздалый кадр 10000 даст
//     стоковое безвредное «failed 1».
//  3) LateClear  — площадка 0x406048 (call Clear из ClearConnect, кадр 10000): DisConnect закрывает сокет и
//     возвращает слот в список свободных ДО вброса 10000, accept замка Ciocp не берёт — новое соединение B
//     может занять слот раньше, чем разобран кадр разрыва прежнего A. Сток тогда снимал запись B и стирал его
//     поля. Путь IoWorker «тип 0xA» (0x4163F1 → 0x416410) вбрасывает 10000 ДО закрытия сокета, поэтому
//     «сокет ≠ −1» ждём до LateWaitMs: стал −1 — законный разрыв, стоковый Clear; остался живым — на слоте уже
//     новое соединение: запись и номер сохраняются (их переиспользует ProcConnect B), сбрасываются только
//     личность/блоки входа/счётчики прежнего входа, как у Clear.
//  4) Sweep      — площадка 0x401BFB (call Check_DisconnectUser в WndProc): перед стоковым сторожем
//     из массива удаляются записи-сироты (pos[arr[i]] ≠ i, номер вне 0..549, −1 внутри), хвост за
//     последним индексом приводится к −1, счётчик подключений (+0xA8) сверяется с числом записей.
//     Сам сторож вызывается ПОСЛЕ отпускания замка массива: сток берёт замки в порядке CUserProc →
//     массив (ProcConnect, кик сторожа), обратный порядок дал бы взаимоблокировку.
//  Живые записи и честный кик за 6 пропущенных пингов не трогаются.
//
//  ── ГРАНИЦЫ ──
//  • Три замены call rel32 (5 б) со сверкой оригинала; слоты сервер-сервер (≥ 550) идут в сток как есть.
//  • Enabled=0 — сток. Под-ключи выключают части по отдельности (ReuseSlot=0 и EarlyClear=0 одновременно —
//    площадка 0x405E25 не ставится; LateClear=0 — 0x406048; Sweep=0 — 0x401BFB).
//  • Журнал PatchLog: строка на событие, не больше LogPerMinute в минуту (подавленные — числом в следующей);
//    строки собираются под замком, а пишутся на диск ПОСЛЕ его отпускания (вход других игроков не ждёт диска).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"
#include <stdarg.h>

namespace
{
    namespace H = Login::Hooks;

    // Стоковые функции (thiscall).
    using SetEmptyFn = int (__thiscall*)(void* /*self*/, short /*slot*/, const char* /*ip*/);
    using ClearFn    = void(__thiscall*)(void* /*self*/, int /*slot*/);
    using SweepFn    = void(__thiscall*)(void* /*self*/);

    SetEmptyFn g_setEmpty = (SetEmptyFn)H::kSetEmptyFunc;   // SetEmpty_ListenArray 0x403160
    ClearFn    g_clear    = (ClearFn)H::kClearFunc;         // ClearListenArrayIndex 0x4034A0
    SweepFn    g_sweep    = (SweepFn)H::kSweepFunc;         // Check_DisconnectUser 0x406560

    bool g_reuseOn   = true;   // часть 1
    bool g_earlyOn   = true;   // часть 2
    bool g_lateOn    = true;   // часть 3
    bool g_sweepOn   = true;   // часть 4
    int  g_lateWait  = 100;    // мс ожидания закрытия сокета на кадре 10000 (часть 3)
    int  g_logPerMin = 30;     // предел строк PatchLog в минуту (0 — без предела)

    // Окно предела журнала (меняется только под замком массива — гонок нет).
    DWORD g_logWinStart = 0;
    int   g_logInWin    = 0;
    int   g_logDropped  = 0;

    // Строки журнала, собранные под замком массива; пишутся после его отпускания (Flush).
    struct LogBatch
    {
        int     n = 0;
        wchar_t msg[32][200];
    };

    // ── раскладка объекта пользователей (this = 0x66B4DA0) ──
    BYTE* Users() { return (BYTE*)H::kSessionObj; }
    CRITICAL_SECTION* ArrCs() { return (CRITICAL_SECTION*)(Users() + H::kUsrCs); }
    volatile LONG* LastIdx() { return (volatile LONG*)(Users() + H::kUsrCount); }   // индекс последней записи, пусто = −1
    volatile LONG* ConnCnt() { return (volatile LONG*)(Users() + H::kUsrUsers); }   // число подключений (= записей)
    int* Arr() { return (int*)(Users() + H::kUsrArr); }
    BYTE* Slot(int s) { return Users() + H::kSlotStride * s; }
    int& SlotPos(int s) { return *(int*)(Slot(s) + H::kSlotPos); }

    // Строка журнала под пределом в минуту — в пакет. Вызывать ТОЛЬКО под замком массива.
    void LogEv(LogBatch& b, const wchar_t* fmt, ...)
    {
        if (g_logPerMin > 0)
        {
            const DWORD now = GetTickCount();
            if (now - g_logWinStart >= 60000) { g_logWinStart = now; g_logInWin = 0; }
            if (g_logInWin >= g_logPerMin) { ++g_logDropped; return; }
            ++g_logInWin;
        }
        if (b.n >= (int)ARRAYSIZE(b.msg)) { ++g_logDropped; return; }
        wchar_t text[160];
        va_list ap;
        va_start(ap, fmt);
        wvsprintfW(text, fmt, ap);
        va_end(ap);
        if (g_logDropped > 0)
        {
            wsprintfW(b.msg[b.n++], L"    L08: %s (+%d строк подавлено пределом LogPerMinute)", text, g_logDropped);
            g_logDropped = 0;
        }
        else
        {
            wsprintfW(b.msg[b.n++], L"    L08: %s", text);
        }
    }

    // Запись пакета строк в PatchLog — ПОСЛЕ отпускания замка массива.
    void Flush(const LogBatch& b)
    {
        for (int i = 0; i < b.n; ++i) { Log::Line(L"%s", b.msg[i]); }
    }

    // Сокет слота IOCP (+0): −1 — соединение закрыто (см. LoginApi.h kIocpSockOff). Ошибка чтения — «живой» (сток).
    bool SlotSocketClosed(int s)
    {
        __try
        {
            const DWORD base = *(const DWORD*)H::kIocpSlotsPtr;
            if (!base) { return false; }
            const BYTE* io = (const BYTE*)base + H::kIocpSlotStride * (DWORD)s;
            return *(const volatile DWORD*)(io + H::kIocpSockOff) == 0xFFFFFFFFu;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // У слота есть валидная запись: позиция в пределах массива и запись указывает на этот слот.
    bool SlotTracked(int s)
    {
        const int pos = SlotPos(s);
        return pos >= 0 && pos <= *LastIdx() && pos < H::kMaxUsers && Arr()[pos] == s;
    }

    // Сброс следов прежнего входа — поля, которые стоковый Clear обнуляет (0x40361D…0x403706), кроме номера,
    // позиции и IP (их держит/перепишет новое соединение).
    void ResetLogin(int s)
    {
        BYTE* p = Slot(s);
        *(int*)  (p + H::kSlotF1)    = 0;
        *(int*)  (p + H::kSlotF2)    = 0;
        *(int*)  (p + H::kSlotF3)    = 0;
        *(int*)  (p + H::kSlotPing)  = 0;
        *(short*)(p + H::kSlotW1)    = 0;
        *(short*)(p + H::kSlotW2)    = 0;
        *(int*)  (p + H::kSlotIdent) = -1;
        memset(p + H::kSlotBlkA, 0, 0x3D);
        memset(p + H::kSlotBlkB, 0, 0x20);
    }

    // Разметка слота нового соединения без добавления записи: поля — как стоковый SetEmpty
    // (0x4031FE…0x4032C5), личность сессии и блоки входа — как стоковый Clear (0x403678, 0x4036E6, 0x403706).
    void ReinitSlot(int s, const char* ip)
    {
        ResetLogin(s);
        BYTE* p = Slot(s);
        *(short*)(p + H::kSlotNum) = (short)s;
        char* dst = (char*)(p + H::kSlotIp);
        memset(dst, 0, 0x14);
        if (ip)
        {
            for (int i = 0; i < 0x14 && ip[i]; ++i) { dst[i] = ip[i]; }   // strncpy(dst, ip, 0x14), как сток
        }
    }
}

// Замена `call SetEmpty_ListenArray` в ProcConnect (0x405E25). thiscall → fastcall (ecx = this, edx — мусор,
// стек: slot, ip; снимаем 8 б, как ret 8 стока).
extern "C" int __fastcall L08_SetEmpty(void* self, void* /*edx*/, short slot, const char* ip)
{
    const int s = slot;
    if (self != (void*)Users() || s < 0 || s >= H::kMaxUsers)
    {
        return g_setEmpty(self, slot, ip);
    }

    LogBatch lb;
    EnterCriticalSection(ArrCs());
    int r;
    if (g_reuseOn && SlotTracked(s))
    {
        ReinitSlot(s, ip);
        r = 1;
        LogEv(lb, L"дубль слота %d предотвращён — запись %d переиспользована (записей %d)",
              s, SlotPos(s), *LastIdx() + 1);
    }
    else
    {
        r = g_setEmpty(self, slot, ip);
    }
    if (g_earlyOn && r == 1 && SlotSocketClosed(s))
    {
        g_clear(self, s);
        LogEv(lb, L"слот %d: соединение закрыто до ProcConnect — запись снята сразу (записей %d)",
              s, *LastIdx() + 1);
    }
    LeaveCriticalSection(ArrCs());
    Flush(lb);
    return r;
}

// Замена `call ClearListenArrayIndex` в ClearConnect (0x406048, кадр 10000). thiscall → fastcall, снимаем 4 б.
extern "C" void __fastcall L08_QueueClear(void* self, void* /*edx*/, int slot)
{
    const int s = slot;
    if (self != (void*)Users() || s < 0 || s >= H::kMaxUsers || SlotSocketClosed(s))
    {
        g_clear(self, s);                   // обычный случай: сокет уже −1 (DisConnect закрыл до вброса 10000)
        return;
    }
    // Сокет ещё живой: либо путь «тип 0xA» (закрытие сразу за вбросом), либо слот уже занят новым соединением.
    const DWORD t0 = GetTickCount();
    while (!SlotSocketClosed(s) && GetTickCount() - t0 < (DWORD)g_lateWait) { Sleep(1); }
    if (SlotSocketClosed(s))
    {
        g_clear(self, s);
        return;
    }
    LogBatch lb;
    EnterCriticalSection(ArrCs());
    ResetLogin(s);
    LogEv(lb, L"слот %d: поздний кадр разрыва — на слоте уже новое соединение, запись сохранена, вход прежнего сброшен (записей %d)",
          s, *LastIdx() + 1);
    LeaveCriticalSection(ArrCs());
    Flush(lb);
}

// Самоочистка массива под замком. Возвращает число удалённых записей. Экспонируется для стенда.
extern "C" int __cdecl L08_SweepArray()
{
    LogBatch lb;
    EnterCriticalSection(ArrCs());
    int* arr = Arr();
    LONG last = *LastIdx();
    if (last >= H::kMaxUsers)                                  // сток не пускает дальше 548; порча — приводим к пределу
    {
        InterlockedExchange(LastIdx(), H::kMaxUsers - 1);
        last = H::kMaxUsers - 1;
    }
    int removed = 0;
    for (int i = 0; i <= last; )
    {
        const int s = arr[i];
        const bool orphan = s < 0 || s >= H::kMaxUsers || SlotPos(s) != i;
        if (!orphan) { ++i; continue; }
        // Удаление как в стоковом Clear: на место i — последняя запись, хвост −1, оба счётчика −1.
        const int m = arr[last];
        arr[i] = m;
        if (i != last && m >= 0 && m < H::kMaxUsers && SlotPos(m) == last) { SlotPos(m) = i; }
        arr[last] = -1;
        --last;
        InterlockedDecrement(LastIdx());
        InterlockedDecrement(ConnCnt());
        ++removed;
        LogEv(lb, L"сторож: запись-сирота слота %d (позиция %d) удалена (записей %d)", s, i, last + 1);
    }
    // Хвост за последней записью — −1 (стоковый сторож читает до первого −1).
    int tail = 0;
    for (int j = (int)(last + 1 < 0 ? 0 : last + 1); j < H::kMaxUsers; ++j)
    {
        if (arr[j] != -1) { arr[j] = -1; ++tail; }
    }
    if (tail > 0) { LogEv(lb, L"сторож: хвост массива очищен (%d ячеек за индексом %d)", tail, (int)last); }
    // Число подключений = число записей (сток: +0xA8 и +0x944 меняются парой, +0xA8 = индекс + 1).
    const LONG want = *LastIdx() + 1;
    const LONG have = *ConnCnt();
    if (have != want)
    {
        InterlockedExchange(ConnCnt(), want);
        LogEv(lb, L"сторож: счётчик подключений %d -> %d (по числу записей)", (int)have, (int)want);
    }
    LeaveCriticalSection(ArrCs());
    Flush(lb);
    return removed;
}

// Замена `call Check_DisconnectUser` в WndProc (0x401BFB): самоочистка, затем стоковый сторож (без замка массива).
extern "C" void __fastcall L08_Sweep(void* self, void* /*edx*/)
{
    if (g_sweepOn) { L08_SweepArray(); }
    g_sweep(self);
}

namespace
{
    const BYTE kSetEmptyOrig[5] = { 0xE8, 0x36, 0xD3, 0xFF, 0xFF };   // call 0x403160 @0x405E25
    const BYTE kClearOrig[5]    = { 0xE8, 0x53, 0xD4, 0xFF, 0xFF };   // call 0x4034A0 @0x406048
    const BYTE kSweepOrig[5]    = { 0xE8, 0x60, 0x49, 0x00, 0x00 };   // call 0x406560 @0x401BFB
}

PatchResult L08_ListenArrayLeak()
{
    const wchar_t* S = L"L08_ListenArrayLeak";
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_reuseOn   = Config::GetBool(S, L"ReuseSlot", true);
    g_earlyOn   = Config::GetBool(S, L"EarlyClear", true);
    g_lateOn    = Config::GetBool(S, L"LateClear", true);
    g_sweepOn   = Config::GetBool(S, L"Sweep", true);
    g_lateWait  = Config::GetInt(S, L"LateWaitMs", 100);
    if (g_lateWait < 1)    { g_lateWait = 1; }
    if (g_lateWait > 1000) { g_lateWait = 1000; }
    g_logPerMin = Config::GetInt(S, L"LogPerMinute", 30);
    if (g_logPerMin < 0) { g_logPerMin = 0; }

    struct Part { bool on; DWORD va; const BYTE* orig; const void* to; const wchar_t* what; };
    const Part parts[3] =
    {
        { g_reuseOn || g_earlyOn, H::kSetEmptyCall,   kSetEmptyOrig, (const void*)&L08_SetEmpty,   L"ProcConnect->SetEmpty" },
        { g_lateOn,               H::kQueueClearCall, kClearOrig,    (const void*)&L08_QueueClear, L"ClearConnect->Clear" },
        { g_sweepOn,              H::kSweepCall,      kSweepOrig,    (const void*)&L08_Sweep,      L"сторож" },
    };
    if (!parts[0].on && !parts[1].on && !parts[2].on)
    {
        Log::Line(L"    L08: ReuseSlot=0, EarlyClear=0, LateClear=0, Sweep=0 — нечего ставить");
        return PatchResult::Disabled;
    }

    // Сверка всех площадок до записи: несовпадение любой — патч не ставится целиком.
    const Site sites[3] =
    {
        { parts[0].va, parts[0].orig, 5 },
        { parts[1].va, parts[1].orig, 5 },
        { parts[2].va, parts[2].orig, 5 },
    };
    if (!VerifyAllSites(S, sites, 3))
    {
        return PatchResult::Mismatch;
    }

    for (int i = 0; i < 3; ++i)
    {
        if (!parts[i].on) { continue; }
        if (!Hook::WriteCall(parts[i].va, parts[i].to, 5))
        {
            Log::Line(L"    L08: запись не удалась на 0x%08X", parts[i].va);
            for (int k = 0; k < i; ++k)   // не оставлять половину: уже записанные площадки — обратно в сток
            {
                if (parts[k].on) { Hook::WriteBytes(parts[k].va, parts[k].orig, 5); }
            }
            return PatchResult::Failed;
        }
    }
    Log::Line(L"    L08: ProcConnect->SetEmpty 0x%08X %s; ClearConnect->Clear 0x%08X %s; сторож 0x%08X %s; "
              L"ReuseSlot=%d EarlyClear=%d LateWaitMs=%d LogPerMinute=%d",
              parts[0].va, parts[0].on ? L"перехвачен" : L"сток",
              parts[1].va, parts[1].on ? L"перехвачен" : L"сток",
              parts[2].va, parts[2].on ? L"перехвачен" : L"сток",
              g_reuseOn ? 1 : 0, g_earlyOn ? 1 : 0, g_lateWait, g_logPerMin);
    return PatchResult::Applied;
}
