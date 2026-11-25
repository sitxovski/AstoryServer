// Copyright (c) 2026 @sitxovski (Discord)
// AsdaServerBridge.cpp — реализация моста (см. AsdaServerBridge.h).
//
// ★ fix2 (2026-10-13, ревизия INTEG3 Б-1/Б-2) — ПОРЯДОК ЗАМКОВ ВЕЗДЕ «замок слота cs_X → замок Ciocp L»:
//   • Б-1: ResetSlot (детур SetConnectFlag, зовётся ПОД L из DisConnect/accept/ошибки WriteFile) замок слота НЕ берёт —
//     только InterlockedIncrement(resetReq). Сброс применяется под cs_X на входе в каждую функцию, работающую со слотом
//     (RecvRoute/OnRecv, SendRoute, SlotFailed, SlotMode) — ApplyResetLocked. Обратного ребра L → cs_X больше нет.
//   • Б-2: SendRoute шифрует И вызывает стоковый Ciocp::Send одним куском под cs_X: порядок номеров кадров на проводе =
//     порядок шифрования; скретч s.sealed за пределы замка не выходит.
#include "AsdaServerBridge.h"
#include <windows.h>
#include <vector>
#include <cstring>
#include <cwchar>
#include <new>

using namespace AsdaSecure;

namespace
{
    struct Slot
    {
        ServerChannel        chan;
        std::vector<uint8_t> toParser;    // расшифрованный старый поток (возврат RecvRoute; читает только поток приёма слота)
        std::vector<uint8_t> toSocket;    // ServerHello / очередь исходящего (уходит сразу, под cs)
        std::vector<uint8_t> sealed;      // шифротекст (только под cs, внутри SendRoute)
        CRITICAL_SECTION     cs;
        volatile LONG        resetReq;    // ★ fix2: запросы сброса (ResetSlot под замком Ciocp — без cs, Interlocked)
        LONG                 resetSeen;   // ★ fix2: последний применённый запрос (только под cs)
        bool                 failed;
        bool                 identitySet;
        bool                 reported;    // ★ В7d: отчёт о нарушении уже сделан (одна строка на соединение)
        AsdaWire::FailInfo   fail;        // ★ В7d: сведения о первой фатальной ошибке слота
        // ★ fix2b (кадры сервера ДО рукопожатия: отказы LM 4101/2253, GS 6004 «сервер переполнен» сразу после accept)
        std::vector<uint8_t> preQ;        // старые кадры, отправленные сервером, пока режим канала не известен (только под cs)
        volatile LONG        preBytes;    // = preQ.size(); читается БЕЗ замка воротами DisConnect (под замком Ciocp)
        volatile LONG        closing;     // DisConnect отложен: новые кадры не принимаются (сток при флаге 0 их роняет)
        volatile LONG        deferKill;   // 1 — DisConnect отложен до выдачи очереди (владелец разрыва — кто снимет 1→0)
        volatile LONG        deferTick;   // когда отложен (GetTickCount, 0 → 1)
        void* volatile       deferThis;   // this Ciocp отложенного DisConnect
    };

    Slot* volatile g_slots = nullptr;      // массив kMaxSlots; публикуется ПОСЛЕ построения всех слотов (живёт весь процесс)
    PrivateKey   g_key{};
    bool         g_hasKey   = false;
    bool         g_cngOk    = false;
    SubServer    g_sub      = SubServer::Game;
    bool         g_allow    = true;
    AsdaWire::SendRawFn    g_sendRaw    = nullptr;
    AsdaWire::KillFn       g_kill       = nullptr;   // ★ В7d
    AsdaWire::ReportFn     g_report     = nullptr;   // ★ В7d
    AsdaWire::InitNotifyFn g_initNotify = nullptr;   // ★ В7d
    bool         g_killOnViolation = true;            // ★ В7d
    wchar_t      g_keyPath[260] = {};
    volatile LONG g_inited  = 0;           // 0 — не инициализирован, 1 — идёт, 2 — готов

    // ★ В7d: счётчики и ограничитель строк PatchLog. ★ fix2: + применённые сбросы, обход при сбое CNG.
    volatile LONG g_kills = 0, g_reports = 0, g_logSuppr = 0, g_sendFails = 0, g_resets = 0, g_bypass = 0;
    // ★ fix2b: кадры до рукопожатия и отложенный разрыв.
    volatile LONG g_connFlag[AsdaWire::kMaxSlots] = {};   // флаг соединения слота (= стоковый [slot+4], пишет детур SetConnectFlag)
    volatile LONG g_preMax      = 64 * 1024;   // PreHandshakeQueueKB: предел очереди слота до рукопожатия, байт (0 — не копить)
    volatile LONG g_deferMs     = 5000;        // PreHandshakeCloseMs: сколько ждать первых байт клиента при отложенном DisConnect (0 — не откладывать)
    uintptr_t     g_ioLo = 0, g_ioHi = 0;      // IoWorkerThread [lo, hi): DisConnect оттуда (сокет уже мёртв) не откладывается
    volatile LONG g_preQueued = 0, g_preFlushed = 0, g_preDropped = 0, g_deferred = 0, g_deferTimeouts = 0;
    volatile LONG g_watchdog = 0;              // 0 — нить сторожа не создана, 1 — создана

    volatile LONG g_perMinute   = 30;      // строк PatchLog в минуту (0 — без ограничения)
    volatile LONG g_winStart    = 0;       // начало окна (GetTickCount; 0 — окна ещё не было)
    volatile LONG g_winCount    = 0;       // строк в окне
    volatile LONG g_pendingSup  = 0;       // подавлено с последней разрешённой строки

    void EnsureIdentity(Slot& s)
    {
        if (!s.identitySet)
        {
            s.chan.SetIdentity(g_sub, g_hasKey ? &g_key : nullptr);
            s.chan.SetAllowLegacy(g_allow);
            s.identitySet = true;
        }
    }

    // ★ fix2: применить отложенный запрос сброса (ТОЛЬКО под s.cs). Новый клиент на переиспользованном слоте не видит
    //   старых ключей/номеров: accept (SetConnectFlag(X,1)) ставит запрос ДО первого чтения сокета (0x563D1D раньше
    //   ReadFile 0x564ABA/0x564EB3; LM аналогично), а любое обращение к каналу начинается с этой функции.
    //   Буферы toParser/sealed не трогаем: toParser читает стоковый разборщик потока приёма после выхода из замка.
    void ApplyResetLocked(Slot& s)
    {
        const LONG req = InterlockedCompareExchange(&s.resetReq, 0, 0);   // чтение с барьером
        if (req == s.resetSeen) { return; }
        s.chan.Reset();
        s.identitySet = false;
        EnsureIdentity(s);
        s.failed = false;
        s.reported = false;
        memset(&s.fail, 0, sizeof(s.fail));
        // ★ fix2b: очередь до рукопожатия и отложенный разрыв относятся к ПРОШЛОЙ сессии. Кадры новой сессии в очередь
        //   встают только при флаге соединения 1 (SendRoute), а ResetSlot(X,1) сперва ставит запрос сброса, затем флаг —
        //   значит, сброс accept применяется ДО постановки первого кадра нового соединения и его очередь не стирает.
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        InterlockedExchange(&s.closing, 0);
        InterlockedExchange(&s.deferKill, 0);
        s.resetSeen = req;
        InterlockedIncrement(&g_resets);
    }

    // ★ fix2b: выдать очередь до рукопожатия в toSocket (под cs, сразу после того, как канал стал готов).
    //   Legacy — как есть; Secure — шифрованными кадрами по ≤ kMaxPlain (каждый старый кадр ≤ 4 КБ, порядок сохраняется),
    //   за ServerHello тем же вызовом стокового Send. Ошибка шифрования — сбой сервера (фаза 1).
    Err FlushPreQueueLocked(Slot& s)
    {
        Err e = Err::Ok;
        size_t off = 0;
        while (off < s.preQ.size())
        {
            const size_t n = (s.preQ.size() - off) > kMaxPlain ? kMaxPlain : (s.preQ.size() - off);
            e = s.chan.OnSend(s.preQ.data() + off, n, s.sealed);
            if (e != Err::Ok) { break; }
            s.toSocket.insert(s.toSocket.end(), s.sealed.begin(), s.sealed.end());
            off += n;
        }
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        if (e == Err::Ok) { InterlockedIncrement(&g_preFlushed); }
        return e;
    }

    // Запомнить первую фатальную ошибку слота (под слотовым локом).
    void MarkFail(Slot& s, Err e, int phase, const void* data, int len)
    {
        if (s.failed) { return; }          // первая причина — главная; следующие не перетирают
        s.failed = true;
        s.fail.err       = e;
        s.fail.mode      = (int)s.chan.GetMode();
        s.fail.phase     = phase;
        s.fail.firstByte = (data && len > 0) ? ((const uint8_t*)data)[0] : -1;
        s.fail.bytes     = len;
        // Приём: любая ошибка вызвана присланными байтами (Cng на приёме = негодная точка ECDH в ClientHello) — вид 56..59;
        // отправка: сбой на стороне сервера — вид 0 (только PatchLog, не нарушение клиента).
        const int k = AsdaWire::KindForErr(e);
        s.fail.kind      = (phase == 0) ? (k ? k : AsdaWire::kKindHandshake) : 0;
    }

    // Разбор порции приёма под cs (общая часть OnRecv/RecvRoute). Возврат — длина расшифрованного (>0, *out) или 0.
    //   ServerHello/очередь исходящего уходят стоковым Send ЗДЕСЬ, под cs_X (порядок «cs_X → L»).
    int RecvLocked(Slot& s, void* ciocpThis, int slot, const void* in, int len, const uint8_t** out)
    {
        if (s.failed) { return 0; }        // ★ В7d: слот уже в ошибке (например, сбой шифрования на отправке)
        EnsureIdentity(s);
        Err e = s.chan.OnRecv((const uint8_t*)in, (size_t)len, s.toParser, s.toSocket);
        Err fe = Err::Ok;
        if (e == Err::Ok && !s.preQ.empty() && s.chan.IsReady())
        {
            fe = FlushPreQueueLocked(s);              // ★ fix2b: кадры до рукопожатия — сразу за ServerHello / как есть (Legacy)
        }
        if (!s.toSocket.empty() && g_sendRaw)
        {
            g_sendRaw(ciocpThis, slot, s.toSocket.data(), (int)s.toSocket.size());
        }
        if (e != Err::Ok || fe != Err::Ok)
        {
            // BadTag/Replay/BadMagic/Format/… — вызывающий закроет слот; очередь до рукопожатия этой сессии больше не нужна
            if (e != Err::Ok) { MarkFail(s, e, /*phase=*/0, in, len); } else { MarkFail(s, fe, /*phase=*/1, in, len); }
            s.preQ.clear();
            InterlockedExchange(&s.preBytes, 0);
            return 0;
        }
        if (s.toParser.empty()) { return 0; }
        *out = s.toParser.data();
        return (int)s.toParser.size();
    }
}

namespace AsdaWire
{
    void Configure(SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw)
    {
        g_sub     = sub;
        g_allow   = allowLegacy;
        g_sendRaw = sendRaw;
        g_keyPath[0] = 0;
        if (keyPath)
        {
            int i = 0;
            for (; keyPath[i] && i < (int)(sizeof(g_keyPath) / sizeof(wchar_t)) - 1; ++i) { g_keyPath[i] = keyPath[i]; }
            g_keyPath[i] = 0;
        }
    }

    void SetFailureHooks(KillFn kill, ReportFn report, InitNotifyFn initNotify, bool killOnViolation)
    {
        g_kill            = kill;
        g_report          = report;
        g_initNotify      = initNotify;
        g_killOnViolation = killOnViolation;
    }

    bool EnsureInit()
    {
        // Фаза перехода 0→1 делает ровно один поток; остальные ждут завершения (busy-wait коротко).
        // ★ fix2: под замком Ciocp не зовётся (ResetSlot его больше не вызывает) — ожидание здесь не держит L.
        LONG prev = InterlockedCompareExchange(&g_inited, 1, 0);
        if (prev == 2) { return g_hasKey; }
        if (prev == 1)
        {
            while (g_inited == 1) { Sleep(0); }
            return g_hasKey;
        }
        // prev == 0 — инициализируем здесь (уже вне DllMain: первый вызов с рабочего потока IOCP).
#ifdef ASDAWIRE_STAND_NO_CNG
        const bool cngOk = false;          // только стенд stand_nocng: имитация «CNG не открылся» (в DLL не определено)
#else
        const bool cngOk = AsdaSecure::Init();
#endif
        if (cngOk)
        {
            g_cngOk = true;
            Slot* t = (Slot*)::operator new(sizeof(Slot) * kMaxSlots);
            for (int i = 0; i < kMaxSlots; ++i)
            {
                new (&t[i]) Slot();
                InitializeCriticalSection(&t[i].cs);
                t[i].resetReq = 0;
                t[i].resetSeen = 0;
                t[i].failed = false;
                t[i].identitySet = false;
                t[i].reported = false;
                memset(&t[i].fail, 0, sizeof(t[i].fail));
            }
            g_hasKey = (g_keyPath[0] && AsdaSecure::LoadPrivateKeyFile(g_keyPath, g_key));
            InterlockedExchangePointer((PVOID volatile*)&g_slots, t);   // публикация ПОСЛЕ построения (барьер)
        }
        InterlockedExchange(&g_inited, 2);
        if (g_initNotify) { g_initNotify(g_cngOk, g_hasKey); }
        return g_hasKey;
    }

    bool Init(SubServer sub, const wchar_t* keyPath, bool allowLegacy, SendRawFn sendRaw)
    {
        Configure(sub, keyPath, allowLegacy, sendRaw);
        return EnsureInit();
    }

    bool IsReady() { return g_inited == 2 && g_hasKey; }

    bool IsBypass() { return g_inited == 2 && !g_slots; }

    void SetAllowLegacy(bool allow)
    {
        g_allow = allow;
        Slot* sl = g_slots;
        if (!sl) { return; }
        for (int i = 0; i < kMaxSlots; ++i)
        {
            EnterCriticalSection(&sl[i].cs);
            sl[i].chan.SetAllowLegacy(allow);
            LeaveCriticalSection(&sl[i].cs);
        }
    }

    bool CheckKeyFile(const wchar_t* path, wchar_t* why, int whyLen)
    {
        auto say = [&](const wchar_t* t) { if (why && whyLen > 0) { wcsncpy_s(why, (size_t)whyLen, t, _TRUNCATE); } };
        if (!path || !path[0]) { say(L"путь к ключу пуст (KeyFile)"); return false; }
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE)
        {
            const DWORD le = GetLastError();
            say(le == ERROR_FILE_NOT_FOUND || le == ERROR_PATH_NOT_FOUND ? L"файл ключа не найден"
              : le == ERROR_ACCESS_DENIED ? L"нет доступа к файлу ключа (права)" : L"файл ключа не открывается");
            return false;
        }
        LARGE_INTEGER sz{};
        const bool szOk = GetFileSizeEx(f, &sz) != FALSE;
        uint8_t buf[8] = {};
        DWORD rd = 0;
        const bool rdOk = ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd == sizeof(buf);
        CloseHandle(f);
        if (!szOk || sz.QuadPart != (LONGLONG)(8 + kPrivLen + kPubLen)) { say(L"размер файла ключа не 104 байта (повреждён/не тот файл)"); return false; }
        if (!rdOk || memcmp(buf, "ASDAKEY1", 8) != 0) { SecureZeroMemory(buf, sizeof(buf)); say(L"нет метки ASDAKEY1 (не файл ключа keygen)"); return false; }
        SecureZeroMemory(buf, sizeof(buf));
        say(L"ок");
        return true;
    }

    int KindForErr(Err e)
    {
        switch (e)
        {
        case Err::BadTag:       return kKindBadTag;
        case Err::Replay:       return kKindReplay;
        case Err::Format:       return kKindFormat;
        case Err::BadMagic:
        case Err::BadVersion:
        case Err::BadSubServer:
        case Err::BadSignature:
        case Err::State:
        case Err::Arg:
        case Err::Legacy:       return kKindHandshake;
        default:                return 0;      // Cng/Ok — сбой сервера, не нарушение клиента
        }
    }

    void SetLogPerMinute(int perMinute) { InterlockedExchange(&g_perMinute, perMinute < 0 ? 0 : perMinute); }

    bool LogAllow(int* suppressed)
    {
        if (suppressed) { *suppressed = 0; }
        const LONG lim = g_perMinute;
        if (lim <= 0)
        {
            if (suppressed) { *suppressed = InterlockedExchange(&g_pendingSup, 0); }
            return true;
        }
        // ★ fix2 (НИЗК-6 integ3, урок N01b): окно — в БЕЗЗНАКОВОЙ разности тиков. Знаковое (LONG)(now-start) после
        //   24,8 суток без строк становилось отрицательным, окно не сбрасывалось до следующих 24,8 суток.
        DWORD now = GetTickCount();
        if (now == 0) { now = 1; }                 // 0 — признак «окна ещё не было»
        const LONG start = g_winStart;
        if (start == 0 || (DWORD)(now - (DWORD)start) >= 60000u)
        {
            // Новое окно: кто первым сменил начало — обнуляет счётчик.
            if (InterlockedCompareExchange(&g_winStart, (LONG)now, start) == start)
            {
                InterlockedExchange(&g_winCount, 0);
            }
        }
        if (InterlockedIncrement(&g_winCount) > lim)
        {
            InterlockedIncrement(&g_pendingSup);
            InterlockedIncrement(&g_logSuppr);
            return false;
        }
        if (suppressed) { *suppressed = InterlockedExchange(&g_pendingSup, 0); }
        return true;
    }

    // ★ fix2 (Б-1): БЕЗ замка слота и без EnsureInit — зовётся из детура SetConnectFlag ПОД замком Ciocp L.
    //   До инициализации слотов сбрасывать нечего (сессий ещё нет). Сброс применит ApplyResetLocked под cs_X.
    //   ★ fix2b: connectFlag — значение стокового флага соединения (SetConnectFlag(X,1) accept / (X,0) разрыв). Порядок:
    //   accept — сперва запрос сброса, потом флаг 1 (кадр новой сессии встанет в очередь только после применения сброса);
    //   разрыв — сперва флаг 0 (новые кадры не копятся, как сток их роняет), потом запрос сброса.
    void ResetSlot(int slot, int connectFlag)
    {
        if (slot < 0 || slot >= kMaxSlots) { return; }
        Slot* sl = g_slots;
        if (connectFlag)
        {
            if (sl) { InterlockedIncrement(&sl[slot].resetReq); }
            InterlockedExchange(&g_connFlag[slot], 1);
        }
        else
        {
            InterlockedExchange(&g_connFlag[slot], 0);
            if (sl) { InterlockedIncrement(&sl[slot].resetReq); }
        }
    }

    void SetPreHandshake(int maxBytes, int closeDelayMs, uintptr_t ioWorkerLo, uintptr_t ioWorkerHi)
    {
        InterlockedExchange(&g_preMax, maxBytes < 0 ? 0 : maxBytes);
        InterlockedExchange(&g_deferMs, closeDelayMs < 0 ? 0 : closeDelayMs);
        g_ioLo = ioWorkerLo; g_ioHi = ioWorkerHi;
    }
}

namespace
{
    // ★ fix2b: выполнить отложенный DisConnect слота (владелец — кто снял deferKill 1→0). Очередь до рукопожатия к этому
    //   моменту выдана (RecvRoute) или выброшена (сторож: клиент молчит); ворота DisConnect видят preBytes==0 и пропускают сток.
    void RunDeferredKill(int slot)
    {
        Slot& s = g_slots[slot];
        void* self = s.deferThis;
        EnterCriticalSection(&s.cs);
        s.preQ.clear();
        InterlockedExchange(&s.preBytes, 0);
        LeaveCriticalSection(&s.cs);
        if (g_kill) { g_kill(self, slot); }       // ВНЕ замка слота: GetConnectFlag + DisConnect (замок Ciocp)
    }

    // ★ fix2b: сторож отложенных разрывов — клиент не прислал ни байта за PreHandshakeCloseMs → разрыв, очередь выбрасывается.
    DWORD WINAPI DeferWatch(LPVOID)
    {
        for (;;)
        {
            Sleep(250);
            Slot* sl = g_slots;
            const DWORD lim = (DWORD)g_deferMs;
            if (!sl) { continue; }
            const DWORD now = GetTickCount();
            for (int i = 0; i < AsdaWire::kMaxSlots; ++i)
            {
                Slot& s = sl[i];
                if (!s.deferKill) { continue; }
                if ((DWORD)(now - (DWORD)s.deferTick) < lim) { continue; }
                if (InterlockedCompareExchange(&s.deferKill, 0, 1) != 1) { continue; }   // разрыв уже взял приём
                InterlockedIncrement(&g_deferTimeouts);
                RunDeferredKill(i);
            }
        }
    }
}

namespace AsdaWire
{
    // ★ fix2b: ворота входа Ciocp::DisConnect. Зовутся БЕЗ замка слота (вход DisConnect бывает под замком Ciocp — только
    //   Interlocked-поля). true — отложить (сток не выполнять, вернуть 1): у слота есть невыданные кадры до рукопожатия
    //   (отказ сервера 4101/2253/6004 сразу после accept), и разрыв идёт не из IoWorkerThread (там сокет уже мёртв).
    //   Разрыв выполнит приём (после выдачи очереди за ServerHello / как есть Legacy-клиенту) или сторож по сроку.
    bool DisconnectGate(void* ciocpThis, int slot, uintptr_t retAddr)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots || g_deferMs <= 0) { return false; }
        Slot& s = sl[slot];
        if (s.deferKill) { return true; }                                   // уже отложен — повторный DisConnect тоже ждёт
        if (s.preBytes <= 0) { return false; }                              // нечего выдавать — сток как есть
        if (retAddr >= g_ioLo && retAddr < g_ioHi) { return false; }        // нулевой приём/ошибка сокета — выдать некому
        s.deferThis = ciocpThis;
        DWORD t = GetTickCount(); if (t == 0) { t = 1; }
        InterlockedExchange(&s.deferTick, (LONG)t);
        InterlockedExchange(&s.closing, 1);
        if (InterlockedCompareExchange(&s.deferKill, 1, 0) != 0) { return true; }
        bool watchOk = true;
        if (InterlockedCompareExchange(&g_watchdog, 1, 0) == 0)
        {
            HANDLE h = CreateThread(nullptr, 0, &DeferWatch, nullptr, 0, nullptr);   // вне DllMain: первый отложенный разрыв
            if (h) { CloseHandle(h); } else { InterlockedExchange(&g_watchdog, 0); watchOk = false; }
        }
        // Повторная проверка: приём мог выдать очередь между чтением preBytes и установкой deferKill (тогда он разрыв уже не
        //   возьмёт). Нет сторожа — тоже не откладываем. Кто снял deferKill 1→0 — тот и выполняет разрыв: здесь — сток сейчас.
        if ((s.preBytes <= 0 || !watchOk) && InterlockedCompareExchange(&s.deferKill, 0, 1) == 1)
        {
            InterlockedExchange(&s.closing, 0);
            return false;
        }
        InterlockedIncrement(&g_deferred);
        return true;
    }

    const uint8_t* OnRecv(void* ciocpThis, int slot, const void* in, int len, int* outLen)
    {
        if (outLen) { *outLen = 0; }
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return nullptr; }
        Slot& s = sl[slot];
        const uint8_t* p = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const int n = RecvLocked(s, ciocpThis, slot, in, len, &p);
        LeaveCriticalSection(&s.cs);
        if (n > 0 && outLen) { *outLen = n; }
        return n > 0 ? p : nullptr;
    }

    int RecvRoute(void* ciocpThis, int slot, const void* in, int len, const uint8_t** out)
    {
        if (out) { *out = nullptr; }
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl)
        {
            // ★ fix2 (НИЗК-5 integ3): CNG не открылся — таблицы слотов нет. AllowLegacy=1: байты как есть (сток, Legacy) —
            //   старые клиенты работают; зашифрованный ClientHello уходит стоковому разборщику и ответа не получает.
            //   AllowLegacy=0: шифрование обязательно, а его нет — соединение закрывается (строка PatchLog, вид 0).
            if (g_allow)
            {
                InterlockedIncrement(&g_bypass);
                if (out) { *out = (const uint8_t*)in; }
                return len > 0 ? len : 0;
            }
            FailInfo fi{}; fi.err = Err::Cng; fi.mode = 0; fi.phase = 0; fi.firstByte = (in && len > 0) ? ((const uint8_t*)in)[0] : -1;
            fi.bytes = len; fi.kind = 0;
            if (g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
            if (!g_killOnViolation || !g_kill) { return 0; }
            InterlockedIncrement(&g_kills);
            g_kill(ciocpThis, slot);
            return -1;
        }
        if (slot < 0 || slot >= kMaxSlots)
        {
            if (out) { *out = (const uint8_t*)in; }           // вне таблицы (у Ciocp не бывает: a2 >= 0x226 — отказ) — сток
            return len > 0 ? len : 0;
        }

        Slot& s = sl[slot];
        FailInfo fi{};
        bool failedNow = false, doReport = false;
        const uint8_t* p = nullptr;
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const int n = RecvLocked(s, ciocpThis, slot, in, len, &p);
        if (s.failed)
        {
            failedNow = true;
            fi = s.fail;                                       // снимок под тем же захватом: сброс не вклинится
            if (!s.reported) { s.reported = true; doReport = true; }
        }
        LeaveCriticalSection(&s.cs);
        if (!failedNow)
        {
            // ★ fix2b: сервер отказал соединению до рукопожатия (DisConnect отложен воротами), очередь уже выдана клиенту —
            //   выполнить отложенный разрыв; присланное клиентом стоку не отдаём (в стоке сокет был бы уже закрыт).
            if (s.deferKill && s.preBytes <= 0 && InterlockedCompareExchange(&s.deferKill, 0, 1) == 1)
            {
                RunDeferredKill(slot);
                return -1;
            }
            if (n > 0 && out) { *out = p; }
            return n > 0 ? n : 0;
        }

        // ── нарушение: отчёт (один раз на соединение) → разрыв штатным путём ──
        if (doReport && g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
        // ★ fix2b: сервер уже отказал соединению (DisConnect отложен) — разрыв нужен в любом режиме; очередь выброшена (RecvLocked).
        if (InterlockedCompareExchange(&s.deferKill, 0, 1) == 1) { RunDeferredKill(slot); return -1; }
        if (!g_killOnViolation || !g_kill) { return 0; }   // режим «только отбросить» (откат поведения В7b)
        InterlockedIncrement(&g_kills);
        g_kill(ciocpThis, slot);                           // ВНЕ слотового лока: DisConnect → SetConnectFlag → ResetSlot
        return -1;
    }

    int SendRoute(void* ciocpThis, int slot, const void* frame, int len)
    {
        EnsureInit();
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots)
        {
            // ★ fix2 (НИЗК-5): CNG не открылся / вне таблицы — сток как есть. При AllowLegacy=0 без CNG открытым не шлём
            //   (соединение и так будет закрыто на первом приёме).
            if (!sl && !g_allow) { return 0; }
            if (!sl) { InterlockedIncrement(&g_bypass); }
            return g_sendRaw ? g_sendRaw(ciocpThis, slot, frame, len) : 0;
        }
        Slot& s = sl[slot];
        int rc = 0;
        bool doReport = false;
        FailInfo fi{};
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        if (s.closing)
        {
            rc = 0;                                       // ★ fix2b: DisConnect отложен — сток после разрыва кадры роняет
        }
        else if (!s.failed && !s.chan.IsReady())
        {
            // ★ fix2b: канал ещё не готов (режим не известен / рукопожатие не завершено) — кадр в очередь слота; уйдёт сразу за
            //   ServerHello (Secure) или как есть (Legacy) в том порядке, в каком отправлялся. Флаг соединения 0 — сток такой
            //   Send отвергает (возврат 0), мост тоже. Предел PreHandshakeQueueKB: лишнее отбрасывается и считается (preDropped).
            if (!g_connFlag[slot] || len <= 0) { rc = 0; }
            else if ((LONG)s.preQ.size() + len > g_preMax) { rc = 0; InterlockedIncrement(&g_preDropped); }
            else
            {
                s.preQ.insert(s.preQ.end(), (const uint8_t*)frame, (const uint8_t*)frame + len);
                InterlockedExchange(&s.preBytes, (LONG)s.preQ.size());
                InterlockedIncrement(&g_preQueued);
                rc = 1;                                   // для вызывающего «принят» (как стоковый Send)
            }
        }
        else if (!s.failed)                               // ★ В7d: слот к закрытию — не слать
        {
            EnsureIdentity(s);
            Err e = s.chan.OnSend((const uint8_t*)frame, (size_t)len, s.sealed);
            if (e == Err::Ok)
            {
                if (!s.sealed.empty())
                {
                    // ★ fix2 (Б-2): стоковый Send ПОД cs_X — номер кадра, присвоенный шифрованием, уходит в буфер сокета
                    //   (Ciocp копирует под L: WriteFile либо досылочный буфер +178, который SendTemp шлёт по порядку) в том
                    //   же порядке, в каком кадры шифровались.
                    rc = g_sendRaw ? g_sendRaw(ciocpThis, slot, s.sealed.data(), (int)s.sealed.size()) : 0;
                }
                else
                {
                    rc = 1;                               // отложен до рукопожатия (очередь канала) — для вызывающего «принят»
                }
            }
            else
            {
                MarkFail(s, e, /*phase=*/1, frame, len);
                InterlockedIncrement(&g_sendFails);
                if (!s.reported) { s.reported = true; doReport = true; fi = s.fail; }
            }
        }
        LeaveCriticalSection(&s.cs);
        if (doReport && g_report) { InterlockedIncrement(&g_reports); g_report(ciocpThis, slot, fi); }
        return rc;
    }

    bool SlotFailed(int slot)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return false; }
        Slot& s = sl[slot];
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const bool f = s.failed;
        LeaveCriticalSection(&s.cs);
        return f;
    }

    int SlotMode(int slot)
    {
        Slot* sl = g_slots;
        if (!sl || slot < 0 || slot >= kMaxSlots) { return 0; }
        Slot& s = sl[slot];
        EnterCriticalSection(&s.cs);
        ApplyResetLocked(s);
        const int m = (int)s.chan.GetMode();
        LeaveCriticalSection(&s.cs);
        return m;
    }

    void GetCounters(Counters* c)
    {
        if (!c) { return; }
        c->kills = g_kills; c->reports = g_reports; c->logSuppressed = g_logSuppr; c->sendFails = g_sendFails;
        c->resetsApplied = g_resets; c->bypass = g_bypass;
        c->preQueued = g_preQueued; c->preFlushed = g_preFlushed; c->preDropped = g_preDropped;
        c->deferredCloses = g_deferred; c->deferTimeouts = g_deferTimeouts;
    }
}
