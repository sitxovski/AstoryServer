// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L07 — ★ ШИФРОВАНИЕ ТРАФИКА (прослойка AsdaSecure) в LoginManager (15001).
//  Волна В7b «врезка». План: Reports/anticheat/00_PLAN.md «Дополнение 11.10».
//  Дизайн: AstoryServer/Docs/_Common/traffic-encryption-design.md.
//  Документ патча: AstoryServer/Docs/LoginManager/L07-traffic-encryption.md.
//
//  ── ЧТО ДЕЛАЕТ ──
//  Встаёт между сокетом и разборщиком старого кадра `FB|size|A|B|op…FE`, НЕ меняя старый протокол.
//    • приём (socket-recv клиентского слота в IoWorkerThread) → расшифровка AEAD → стоковый разборщик;
//    • отправка (оба call-site Ciocp::Send)                   → шифрование AEAD перед WriteFile;
//    • accept/disc (вход SetConnectFlag)                      → Reset канала слота.
//  Схема TLS-типа: ECDH P-256 на подключение, ECDSA-подпись сервера вшитым в клиент ключом,
//  AES-256-GCM с номером кадра. Вся криптология — в AsdaSecure/AsdaWire (CNG). Закрытый ключ —
//  файл `secure_server.key` рядом с DLL (кладёт владелец; keygen). Нет файла → патч не включается.
//
//  ── СОВМЕСТИМОСТЬ ПЕРЕХОДА ──
//  AllowLegacy=1 (умолчание): старый клиент (первый байт 0xFB) идёт без шифрования, 0xA5 — рукопожатие.
//  Когда все клиенты обновлены — AllowLegacy=0 закрывает старый протокол.
//
//  ── БЕЗОПАСНОСТЬ ВРЕЗКИ ──
//  • Enabled=0 по умолчанию — сток не меняется; трамплины НЕ ставятся.
//  • CNG/bcrypt открывается ЛЕНИВО (AsdaWire::EnsureInit на первом вызове трамплина, рабочий поток IOCP),
//    а НЕ в DllMain (там грузить модули нельзя — loader lock).
//  • Состояние канала — на слот, под своей критической секцией (Ciocp::Send берёт свой лок уже после
//    нашего call-site; IOCP крутит несколько рабочих потоков).
//  • ★ В7d (2026-10-13): нарушение целостности (порча тега / повтор номера / мусор до рукопожатия / длина кадра
//    вне предела / старый клиент при AllowLegacy=0) → строка в PatchLog (ограничитель LogPerMinute) + журнал
//    античита ac.other виды 56–59 → РАЗРЫВ штатным путём стока «клиент закрыл соединение»: Ciocp::GetConnectFlag
//    0x414550 + Ciocp::DisConnect 0x4138D0 (ветка нулевого приёма IoWorkerThread), возврат на её хвост 0x416463.
//    KillOnViolation=0 — откат к поведению В7b (кадр только отбрасывается).
//  • ★ В7d: Enabled=1 без годного файла ключа (нет / не 104 б / нет метки ASDAKEY1) — патч НЕ ставится (сток,
//    старый протокол), в PatchLog — причина. Сервер не падает и вход не блокируется молча.
//  • Межсервер (10000..10099) НЕ трогаем.
//  • ★ fix2 (2026-10-13, ревизия INTEG3): Б-1 — детур SetConnectFlag (под замком Ciocp L, DisConnect 0x41390B → 0x41399B →
//    0x4155A3) только ставит запрос сброса слота, без замка слота; отправка — AsdaWire::SendRoute (шифрование и стоковый
//    Send под замком слота). Порядок замков везде «слот → Ciocp». НИЗК-5: CNG не открылся — байты как есть (AllowLegacy=1).
//    НИЗК-7: детур SetConnectFlag пишется первым, при сбое записи площадки возвращаются к оригиналу.
//  • ★ fix2d (2026-10-14, П-1/П-2): мост перед стоковым Send под тем же замком Ciocp читает досылку слота; кадр, который сток
//    стёр бы вместе с досылкой (≥ 0x9F9C), ждёт в очереди слота моста (TxQueueKB, 1 МБ; сторож раз в 50 мс). Отказ стокового
//    Send / переполнение очереди / потеря кадра стоком у Secure-слота — разрыв, PatchLog «[досылка]», ac.other 61. Новых площадок нет.
//  • ★ fix2e (2026-10-14, ревизия fix2d Ф-1): общий предел очередей моста на процесс TxQueueTotalMB (64 МБ; сверх — разрыв слота,
//    ac.other 61 причина 4); сбой выделения памяти перехвачен внутри моста — разрыв слота (причина 5), LoginManager не падает.
//  ★ sec2 (2026-10-15, блок В плана альфы): Е-1 — очередь моста сбойного слота (не вид 61) освобождается сразу; Е-2 — справедливая
//  доля общего предела (TxQueueFairKB: тяжёлый слот рвётся сам, при лёгком сторож вытесняет наибольшую очередь — вид 61 причина 6);
//  рукопожатие — ключ подписи импортируется один раз, пары ECDH заготавливает фоновая нить (HandshakeKeyCache/HandshakePool, ~0,8 мс
//  CPU вместо ~1,9); ДОПУСК до рукопожатия (стойка в интернете): ConnPerIpMax/ConnPerIpWindowSec (вид 63), MaxPendingHandshakes (64),
//  HandshakeDeadlineMs (65) — разрыв штатным DisConnect до ServerAccept, PatchLog «[допуск]». Детур SetConnectFlag передаёт this Ciocp.
//  ★ sec2b (2026-10-15, ревизия SEC2): MaxPendingPerIp (16) — предел незавершённых рукопожатий с одного адреса (вид 64, текст
//  журнала «from IP»); при AllowLegacy=1 молчащий сокет по сроку снимается со счёта незавершённых (С-1); вытеснение очереди — только
//  если она под замком всё ещё наибольшая (Н-2); общий предел TxQueueTotalMB — по реальной памяти кадров (Н-6, value2 вида 61).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"
#include "AsdaServerBridge.h"
#include "AsdaSecure.h"
#include "AcJournal.h"   // ★ В7d: ac.other 56–59 (общий модуль AsdaPatch/src/AcJournal.cpp)
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"L07_TrafficEncryption";

    // Стоковый Ciocp::Send (this=ecx; a2=slot, Src, nBytes; ret 0xC). Для отправки ServerHello.
    using SendFn = int(__thiscall*)(void* self, int slot, const void* src, int len);

    // SendRaw прослойки: положить СЫРЫЕ байты в сокет слота стоковым Send'ом. Зовётся из OnRecv
    // (под его слотовым локом) на рабочем потоке IOCP. Настоящий Ciocp::Send не хукнут по входу
    // (мы меняем только call-site) — рекурсии в наш трамплин нет.
    // ★ fix2: возвращает итог стокового Ciocp::Send (1/0). Зовётся ТОЛЬКО под замком слота (SendRoute/RecvRoute).
    int SrvSendRaw(void* ciocpThis, int slot, const void* data, int len)
    {
        return ((SendFn)Login::Hooks::kSendFunc)(ciocpThis, slot, data, len);
    }

    // ── ★ autoban (2026-10-14): адрес и учётка в журнал нарушений канала ─────────────────────────────────────────────
    //   IP пира — живой getpeername (PeerIpv4 ниже); клиент, сбросивший соединение раньше отчёта, даёт отказ getpeername —
    //   тогда IP ЭТОГО соединения из кэша: снимается на первом приёме слота (AS_RecvRouteC), сбрасывается на accept/разрыве
    //   (AS_ResetSlotC, вход SetConnectFlag). Только Interlocked — AS_ResetSlotC зовётся под замком Ciocp.
    volatile LONG g_slotIp[AsdaWire::kMaxSlots] = {};
    DWORD PeerIpv4(void* self, int slot);   // определена ниже (сокет — стоковый геттер 0x416830)
    void NoteSlotIp(void* self, int slot)
    {
        if (slot < 0 || slot >= AsdaWire::kMaxSlots || g_slotIp[slot] != 0) { return; }
        const DWORD ip = PeerIpv4(self, slot);
        if (ip) { InterlockedCompareExchange(&g_slotIp[slot], (LONG)ip, 0); }
    }
    DWORD SlotIp(void* self, int slot)
    {
        const DWORD live = PeerIpv4(self, slot);
        if (live || slot < 0 || slot >= AsdaWire::kMaxSlots) { return live; }
        return (DWORD)g_slotIp[slot];
    }
    //   Учётка сессии LoginManager: `*(DWORD*)(&dword_66B4DA0 + 143*slot + 759878)` (LoginApi.h L04) — пишет sub_4037B0 после
    //   UPUserLogin со статусом 1 (пароль сверен, LoginManager.c:2597-2599), −1 при освобождении слота (ClearListenArrayIndex,
    //   LoginManager.c:1047); номер сессии = слот Ciocp (sub_415A40: `a4 >= 0x226` и GetConnectFlag(this, a4)). Читается БЕЗ
    //   замка сессий (this+842380): отчёт моста бывает и на пути отправки под чужими замками вызывающего; DWORD — только для журнала.
    //   До логина — 0 (в журнал NULL). ⚠ После выбора персонажа соулмейта (1016 режим 2) сток переписывает сессию на учётку
    //   хозяина персонажа (L04c сверяет пару) — нарушение после этого запишется на хозяина; блока из LoginManager нет (P69 — GS).
    constexpr int kSessStride = 143, kSessUserIx = 759878;
    int SessionAccount(int slot)
    {
        if (slot < 0 || slot >= AsdaWire::kMaxSlots) { return 0; }
        int v = -1;
        __try { v = *(const int*)(Login::Hooks::kSessionObj + kSessStride * slot + kSessUserIx); }
        __except (EXCEPTION_EXECUTE_HANDLER) { v = -1; }
        return v > 0 ? v : 0;
    }

    // C-обёртки (cdecl) для naked-трамплинов.
    // ★ В7d: >0 — длина расшифрованного потока (*out); 0 — отдавать нечего; −1 — нарушение, соединение закрыто.
    extern "C" int __cdecl AS_RecvRouteC(void* ciocpThis, int slot, const void* buf, int size, const unsigned char** out)
    {
        NoteSlotIp(ciocpThis, slot);   // ★ autoban: IP пира раз на соединение
        return AsdaWire::RecvRoute(ciocpThis, slot, buf, size, out);
    }
    // ★ fix2 (Б-2): шифрование + стоковый Send атомарно под замком слота; возврат — итог стокового Send.
    extern "C" int __cdecl AS_SendRouteC(void* ciocpThis, int slot, const void* frame, int len)
    {
        return AsdaWire::SendRoute(ciocpThis, slot, frame, len);
    }
    // ★ fix2c (Н-1, приём): стоковый разборщик приёма sub_415600 (→ CopyToWriteBuffer 0x418C00) — thiscall(this, buf, size, slot), ret 0xC. Мост отдаёт ему
    //   расшифрованный поток кусками ≤ 0x1000 − 9 (как порции ReadFile 0x1000), без своих замков.
    using SinkTFn = int(__thiscall*)(void* self, const void* buf, int size, int slot);
    int L07_SinkC(void* self, const void* data, int len, int slot)
    {
        return ((SinkTFn)0x00415600)(self, data, len, slot);
    }

    // ★ fix2b: второй аргумент SetConnectFlag (1 accept / 0 разрыв) — очередь кадров до рукопожатия новой сессии не стирается.
    //   ★ sec2: + this Ciocp (ecx детура) — сторож допуска рвёт молчащее соединение под замком L этого Ciocp.
    extern "C" void __cdecl AS_ResetSlotC(void* self, int slot, int flag)
    {
        if (slot >= 0 && slot < AsdaWire::kMaxSlots) { InterlockedExchange(&g_slotIp[slot], 0); }   // ★ autoban: новое соединение / разрыв
        AsdaWire::ResetSlotEx(self, slot, flag);
    }
    // ★ fix2b: ворота входа Ciocp::DisConnect 0x004138D0: 1 — отложить (у слота невыданные кадры до рукопожатия — отказ сервера сразу
    //   после accept), сток не выполнять и вернуть 1; 0 — сток как есть. Без замков моста (вход бывает под замком Ciocp).
    extern "C" int __cdecl L07_DiscGateC(void* self, int slot, unsigned int retAddr)
    {
        return AsdaWire::DisconnectGate(self, slot, (uintptr_t)retAddr) ? 1 : 0;
    }

    // ── ★ В7d: разрыв, отчёт, уведомление об инициализации ─────────────────────
    using SlotFn = int(__thiscall*)(void* self, int slot);              // GetConnectFlag / DisConnect / GetSocket
    typedef int (__stdcall* PFN_GetPeerName)(UINT_PTR s, void* name, int* len);   // ws2_32!getpeername

    bool g_journal = false;   // журнал античита запущен этой DLL (AcJournal::Start вернул 0)
    bool g_allowLegacy = true; // ★ fix2: AllowLegacy из ini (для текста строки о сбое CNG)

    // Закрыть соединение слота ШТАТНЫМ путём стока (ветка нулевого приёма IoWorkerThread):
    //   if (Ciocp::GetConnectFlag(this, slot)) Ciocp::DisConnect(this, slot);
    void L07_Kill(void* self, int slot)
    {
        __try
        {
            if (((SlotFn)Login::Hooks::kGetConnFlag)(self, slot)) { ((SlotFn)Login::Hooks::kDisConnect)(self, slot); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // IPv4 пира слота (сетевой порядок; 0 — не определён). Сокет — стоковый геттер 0x416830 (this, slot).
    DWORD PeerIpv4(void* self, int slot)
    {
        if (!self || slot < 0 || slot >= AsdaWire::kMaxSlots) { return 0; }
        static PFN_GetPeerName s_gp = nullptr;
        if (!s_gp)
        {
            HMODULE ws = GetModuleHandleW(L"ws2_32.dll");   // LoginManager импортирует ws2_32 — модуль уже загружен
            if (ws) { s_gp = (PFN_GetPeerName)GetProcAddress(ws, "getpeername"); }
            if (!s_gp) { return 0; }
        }
        __try
        {
            const UINT_PTR sock = (UINT_PTR)((SlotFn)Login::Hooks::kGetSocket)(self, slot);
            if (sock == 0 || sock == (UINT_PTR)~0) { return 0; }
            BYTE sa[16] = {};
            int  len = sizeof(sa);
            if (s_gp(sock, sa, &len) != 0 || *(const WORD*)sa != 2 /*AF_INET*/) { return 0; }
            DWORD ip; memcpy(&ip, sa + 4, 4);
            return ip;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // ★ sec2: IPv4 пира слота для допуска подключений (живой getpeername; 0 — не определён).
    uint32_t L07_PeerIp(void* self, int slot) { return (uint32_t)PeerIpv4(self, slot); }

    const wchar_t* ModeName(int m) { return m == 1 ? L"Secure" : (m == 2 ? L"Legacy" : L"до рукопожатия"); }

    // ★ fix2d (П-2): причина сбоя доставки шифрованного кадра (вид 61) — для PatchLog и поля detail журнала.
    const wchar_t* SendFailText(int reason)
    {
        return reason == AsdaWire::kSendFailRefused  ? L"стоковый Send отказал (ошибка WriteFile — сток закрыл сокет)"
             : reason == AsdaWire::kSendFailQueueMax ? L"очередь моста больше TxQueueKB (клиент долго не читает сокет)"
             : reason == AsdaWire::kSendFailTotalMax ? L"все очереди моста процесса больше TxQueueTotalMB (многие клиенты разом не читают сокет)"   // ★ fix2e
             : reason == AsdaWire::kSendFailNoMem    ? L"нехватка памяти в мосте (сбой выделения перехвачен, процесс работает)"                    // ★ fix2e
             : reason == AsdaWire::kSendFailTotalEvict ? L"общий предел TxQueueTotalMB превышен — вытеснена наибольшая очередь процесса (эта)"   // ★ sec2 (Е-2)
             : L"сток потерял кадр (пул перекрытых структур исчерпан / досылка без записи в полёте)";
    }
    const char* SendFailShort(int reason)
    {
        return reason == AsdaWire::kSendFailRefused ? "stock Send refused" : reason == AsdaWire::kSendFailQueueMax ? "bridge queue full"
             : reason == AsdaWire::kSendFailTotalMax ? "queues total cap" : reason == AsdaWire::kSendFailNoMem ? "out of memory"
             : reason == AsdaWire::kSendFailTotalEvict ? "total cap, largest evicted" : "stock lost frame";
    }

    // Отчёт о нарушении: PatchLog (ограничитель LogPerMinute) + ac.other 56–59, ★ fix2d 61. Зовётся ДО разрыва (IP ещё читается).
    void L07_Report(void* self, int slot, const AsdaWire::FailInfo& fi)
    {
        const DWORD ip = SlotIp(self, slot);           // ★ autoban: живой getpeername, при отказе — IP соединения из кэша
        const int account = SessionAccount(slot);      // ★ autoban: учётка сессии после UPUserLogin; до логина 0 → NULL
        const BYTE* q = (const BYTE*)&ip;
        int sup = 0;
        // ★ fix2d (П-2): шифрованный кадр Secure-слота не доставить по порядку — разрыв с причиной (сбой сервера/сети, не клиента).
        //   Журнал: item_code = причина 1..5, value1 = байт в очереди моста, value2 = длина стоковой досылки (NULL — не читалась);
        //   ★ fix2e: для причин 4 (общий предел TxQueueTotalMB) и 5 (нехватка памяти) value2 = байт во ВСЕХ очередях моста процесса.
        // ★ sec2: ДОПУСК подключений до рукопожатия (виды 63–65): адрес — из решения моста (fi.ip), учётки нет (до логина).
        //   Журнал: value1 = счёт (63 подключений с адреса / 64 незавершённых / 65 возраст, мс), value2 = предел, value3 = 63 окно, с /
        //   64–65 подавлено ограничителем отчётов моста.
        if (fi.kind >= AsdaWire::kKindConnRate && fi.kind <= AsdaWire::kKindHsDeadline)
        {
            const DWORD aip = fi.ip ? (DWORD)fi.ip : ip;
            const BYTE* a = (const BYTE*)&aip;
            if (AsdaWire::LogAllow(&sup))
            {
                if (fi.kind == AsdaWire::kKindConnRate)
                    Log::Line(L"    L07: [допуск] слот %d IP %u.%u.%u.%u: %d-е подключение с адреса за %d с (предел ConnPerIpMax %d) — разрыв до рукопожатия (вид 63; дальше по адресу в этом окне — без строк)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.extra, fi.limit);
                else if (fi.kind == AsdaWire::kKindPendingCap && fi.mode == 1)   // ★ sec2b (Н-1): предел с адреса
                    Log::Line(L"    L07: [допуск] слот %d IP %u.%u.%u.%u: незавершённых рукопожатий с этого адреса %d (предел MaxPendingPerIp %d) — новое соединение разорвано (вид 64; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.extra);
                else if (fi.kind == AsdaWire::kKindPendingCap)
                    Log::Line(L"    L07: [допуск] слот %d IP %u.%u.%u.%u: незавершённых рукопожатий %d (предел MaxPendingHandshakes %d) — новое соединение разорвано (вид 64; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.extra);
                else
                    Log::Line(L"    L07: [допуск] слот %d IP %u.%u.%u.%u: рукопожатие не завершено за %d мс (срок HandshakeDeadlineMs %d), %s — разрыв (вид 65; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.mode == 0 ? L"клиент молчит" : L"клиент начал и бросил", fi.extra);
                if (sup > 0) { Log::Line(L"    L07: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
            }
            if (g_journal)
            {
                AcJournal::Event e;
                AcJournal::Clear(e, AcJournal::kOther, (BYTE)fi.kind);
                e.userNum = (short)slot;
                e.ip      = aip;
                e.v[0]    = fi.count;
                e.v[1]    = fi.limit;
                e.v[2]    = fi.extra;
                char t[64];
                if (fi.kind == AsdaWire::kKindConnRate)        { _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: conn rate %d/%d per %ds", fi.count, fi.limit, fi.extra); }
                else if (fi.kind == AsdaWire::kKindPendingCap) { _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: pending handshakes%s %d/%d", fi.mode == 1 ? " from IP" : "", fi.count, fi.limit); }
                else { _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: handshake %d/%d ms, %s", fi.count, fi.limit, fi.mode == 0 ? "silent" : "partial"); }
                AcJournal::CopyText(e, t);
                AcJournal::Push(e);
            }
            return;
        }
        if (fi.kind == AsdaWire::kKindSendFail)
        {
            if (AsdaWire::LogAllow(&sup))
            {
                Log::Line(L"    L07: [досылка] слот %d IP %u.%u.%u.%u: %s (вид 61, причина %d; в очереди моста %d б, досылка стока %d б, во всех очередях моста %d б) — разрыв",
                          slot, q[0], q[1], q[2], q[3], SendFailText(fi.reason), fi.reason, fi.queued, fi.pending, fi.total);
                if (sup > 0) { Log::Line(L"    L07: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
            }
            if (g_journal)
            {
                AcJournal::Event e;
                AcJournal::Clear(e, AcJournal::kOther, (BYTE)AsdaWire::kKindSendFail);
                e.userNum = (short)slot;
                e.ip      = ip;
                if (account > 0) { e.userIndex = account; }   // ★ autoban
                e.v[0]    = fi.reason;
                e.v[1]    = fi.queued;
                e.v[2]    = (fi.reason == AsdaWire::kSendFailTotalMax || fi.reason == AsdaWire::kSendFailNoMem || fi.reason == AsdaWire::kSendFailTotalEvict) ? fi.total   // ★ fix2e/sec2
                      : (fi.pending >= 0 ? fi.pending : AcJournal::kNone);
                char t[64];
                if (fi.reason == AsdaWire::kSendFailTotalMax || fi.reason == AsdaWire::kSendFailNoMem || fi.reason == AsdaWire::kSendFailTotalEvict)   // ★ fix2e/sec2: + общий объём
                { _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: %s, q %d, all %d", SendFailShort(fi.reason), fi.queued, fi.total); }
                else { _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: %s, queue %d b", SendFailShort(fi.reason), fi.queued); }
                AcJournal::CopyText(e, t);
                AcJournal::Push(e);
            }
            return;
        }
        if (AsdaWire::LogAllow(&sup))
        {
            wchar_t err[32]; MultiByteToWideChar(CP_ACP, 0, AsdaSecure::ErrName(fi.err), -1, err, 32);
            wchar_t fb[8] = L"—";
            if (fi.firstByte >= 0) { _snwprintf_s(fb, 8, _TRUNCATE, L"0x%02X", fi.firstByte); }
            Log::Line(L"    L07: [нарушение канала] слот %d IP %u.%u.%u.%u: %s (вид %d), %s, %s %d б, первый байт %s%s; %s",
                      slot, q[0], q[1], q[2], q[3], err, fi.kind, ModeName(fi.mode),
                      fi.phase == 0 ? L"приём" : L"отправка", fi.bytes, fb,
                      (fi.mode == 0 && fi.firstByte == 0xFB) ? L" (старый клиент при AllowLegacy=0)" : L"",
                      fi.phase == 0 ? L"соединение закрывается штатным DisConnect" : L"кадр не отправлен, разрыв на ближайшем приёме");
            if (sup > 0) { Log::Line(L"    L07: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
        }
        if (g_journal && fi.kind > 0)
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, (BYTE)fi.kind);
            e.userNum = (short)slot;
            e.ip      = ip;
            if (account > 0) { e.userIndex = account; }       // ★ autoban: учётка сессии (после логина)
            e.v[0]    = (int)fi.err;     // код ошибки прослойки (AsdaSecure::Err)
            e.v[1]    = fi.mode;         // 0 до рукопожатия / 1 Secure / 2 Legacy
            e.v[2]    = fi.firstByte >= 0 ? fi.firstByte : AcJournal::kNone;   // первый байт порции (0xFB — старый клиент); нет — NULL (fix2, НИЗК-11)
            char t[64];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "L07 LoginManager: %s, %d b", AsdaSecure::ErrName(fi.err), fi.bytes);
            AcJournal::CopyText(e, t);
            AcJournal::Push(e);
        }
    }

    void L07_InitNotify(bool cngOk, bool keyOk)
    {
        // ★ fix2 (НИЗК-5): при сбое CNG мост пропускает байты как есть (AsdaWire::IsBypass) — текст соответствует коду.
        if (!cngOk)       { Log::Line(g_allowLegacy
                                ? L"    L07: [ОШИБКА] CNG (bcrypt) не открылся — шифрования нет: старые клиенты (AllowLegacy=1) работают как сток, зашифрованные не получат ServerHello"
                                : L"    L07: [ОШИБКА] CNG (bcrypt) не открылся при AllowLegacy=0 — каждое соединение закрывается на первом приёме (строка «нарушение канала», вид 0)"); }
        else if (!keyOk)  { Log::Line(L"    L07: [ОШИБКА] ключ не загрузился при первом соединении — зашифрованные клиенты будут отвергнуты"); }
        else              { Log::Line(L"    L07: CNG открыт, ключ загружен (первое соединение) — шифрование работает"); }
    }

    // ── Трамплин приёма (замена `call sub_415600` @0x4165B5) ──────────────────
    //  Вход: ecx=this(Ciocp, [ebp-24h] IoWorkerThread); [esp+4]=buf, [esp+8]=size, [esp+0xC]=slot. Возврат ret 0xC.
    //  ★ В7d: при −1 (нарушение, DisConnect уже выполнен) адрес возврата заменяется на kKillResume 0x416463 —
    //  хвост стоковой ветки разрыва (`jmp 0x416472` → начало цикла GetQueuedCompletionStatus). Стек одинаков:
    //  ret 0xC снимает три аргумента, обе точки — границы операторов одного кадра IoWorkerThread.
    __declspec(naked) void L07_RecvTramp()
    {
        __asm
        {
            push ebp
            mov  ebp, esp
            push esi
            push edi
            push ebx
            mov  esi, ecx                 // this (Ciocp)
            sub  esp, 4                   // [esp] = out (указатель на расшифрованное)
            mov  eax, esp
            push eax                      // &out
            push dword ptr [ebp+0x0C]     // size
            push dword ptr [ebp+0x08]     // buf
            push dword ptr [ebp+0x10]     // slot
            push esi                      // ciocpThis
            call AS_RecvRouteC            // cdecl (ciocpThis,slot,buf,size,&out)->int
            add  esp, 20
            mov  edi, [esp]               // out
            add  esp, 4
            mov  ebx, eax                 // результат
            test ebx, ebx
            js   killed                   // −1 — соединение закрыто штатным DisConnect
            jz   done                     // 0 — отдавать нечего
            test edi, edi
            jz   done
            push dword ptr [ebp+0x10]     // slot
            push ebx                      // size = длина расшифрованного
            push edi                      // buf  = расшифрованное
            mov  ecx, esi                 // this
            mov  eax, 0x00415600          // стоковый sub_415600 (ret 0xC)
            call eax
            jmp  done
        killed:
            mov  dword ptr [ebp+4], 0x00416463   // Login::Hooks::kKillResume — хвост стоковой ветки разрыва
        done:
            pop  ebx
            pop  edi
            pop  esi
            mov  esp, ebp
            pop  ebp
            ret  0x0C
        }
    }

    // ── Трамплин отправки (замена `call sub_413AB0` на обоих call-site) ───────
    //  Вход: ecx=this; [esp+4]=slot, [esp+8]=Src, [esp+0xC]=nBytes. Возврат ret 0xC.
    //  ★ fix2 (Б-2): стоковый Send 0x413AB0 зовёт SendRoute под замком слота (через SrvSendRaw), трамплин — нет.
    //  Возврат eax — итог стокового Send.
    __declspec(naked) void L07_SendTramp()
    {
        __asm
        {
            push ebp
            mov  ebp, esp
            push dword ptr [ebp+0x10]     // nBytes
            push dword ptr [ebp+0x0C]     // Src
            push dword ptr [ebp+0x08]     // slot
            push ecx                      // ciocpThis
            call AS_SendRouteC            // cdecl (this,slot,Src,n) -> int
            add  esp, 16
            pop  ebp
            ret  0x0C
        }
    }

    // ── Трамплин Reset (детур входа SetConnectFlag; украдено 5 байт: 55 8b ec 6a ff) ──
    //  Вход: ecx=this; [esp+4]=slot(word), [esp+8]=flag. Reset канала, затем — стоковое тело.
    __declspec(naked) void L07_SetConnTramp()
    {
        __asm
        {
            pushad
            mov   eax, dword ptr [esp+0x28]   // ★ fix2b: flag — orig [esp+8] + 0x20 (pushad)
            push  eax
            movzx eax, word ptr [esp+0x28]    // slot — orig [esp+4] + 0x20 + 4 (push выше)
            push  eax
            push  ecx                         // ★ sec2: this (Ciocp) — pushad ecx не меняет
            call AS_ResetSlotC                // cdecl(this, slot, flag)
            add   esp, 12
            popad
            push ebp
            mov  ebp, esp
            push -1
            mov  eax, 0x004144A5
            jmp  eax
        }
    }

    // ★ fix2b: детур входа Ciocp::DisConnect 0x004138D0 (украдено 5 б: 55 8b ec 6a ff, продолжение 0x004138D5). thiscall(this, slot), ret 4.
    //   Ворота L07_DiscGateC: 1 — разрыв отложен до выдачи кадров до рукопожатия (eax=1, как сток для годного слота).
    __declspec(naked) void L07_DiscTramp()
    {
        __asm
        {
            pushad
            push  dword ptr [esp+0x20]        // адрес возврата вызывающего (orig [esp] + 0x20)
            movzx eax, word ptr [esp+0x28]    // slot — orig [esp+4] + 0x20 + 4
            push  eax
            push  ecx                         // this (Ciocp)
            call  L07_DiscGateC              // cdecl(this, slot, ret) -> 0/1
            add   esp, 12
            mov   dword ptr [esp+0x1C], eax   // в сохранённый eax
            popad
            test  eax, eax
            jnz   deferred
            push  ebp                         // украденный пролог
            mov   ebp, esp
            push  -1
            mov   eax, 0x004138D5
            jmp   eax
        deferred:
            mov   eax, 1
            ret   4
        }
    }

    // ★ fix2d (П-1): раскладка стокового Ciocp::Send/SendTemp LM (дизасм 0x413AB0/0x4141D0 — тот же код Ciocp, что GS, сдвиг
    //   0x14E470): замок L this+0x60D1830 (RAII 0x41A620 → EnterCriticalSection), сессии [this+0x60D1898] + slot·0xA0BE, +4 флаг
    //   соединения (0x413B5A), +8 запись в полёте (0x413B91), +0xA0B2 длина досылки (0x413BB1), порог стирания 0x9F9C (0x413BBB),
    //   буфер записи 0x1000 (0x413ECE). Сверено verify_traffic на 3 образах LM. Новых площадок нет.
    const AsdaWire::StockSendLayout kStockLayout = { 0x060D1830u, 0x060D1898u, 0xA0BEu, 4u, 8u, 0xA0B2u, 0x9F9C, 0x1000 };

    const unsigned char kRecvCallOrig[5] = { 0xE8, 0x46, 0xF0, 0xFF, 0xFF };  // call 0x415600
    const unsigned char kSendCallAOrig[5] = { 0xE8, 0xB3, 0xE0, 0xFF, 0xFF }; // call 0x413AB0
    const unsigned char kSendCallBOrig[5] = { 0xE8, 0x8D, 0xDB, 0xFF, 0xFF }; // call 0x413AB0
    const unsigned char kSetConnOrig[5]   = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };  // push ebp;mov ebp,esp;push -1
    const unsigned char kDiscOrig[5]      = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };   // ★ fix2b: вход DisConnect 0x004138D0 (push ebp;mov ebp,esp;push -1)
    // ★ В7d: стоковая ветка разрыва (только СВЕРКА, не пишется): call GetConnectFlag / call DisConnect / jmp хвоста.
    const unsigned char kKillFlagCall[5]  = { 0xE8, 0xFD, 0xE0, 0xFF, 0xFF }; // @0x41644E call 0x414550
    const unsigned char kKillDiscCall[5]  = { 0xE8, 0x6D, 0xD4, 0xFF, 0xFF }; // @0x41645E call 0x4138D0
    const unsigned char kKillResumeOrig[2]= { 0xEB, 0x0D };                   // @0x416463 jmp 0x416472
    const unsigned char kKillLoopJmp[5]   = { 0xE9, 0x9C, 0xFD, 0xFF, 0xFF }; // @0x416472 jmp 0x416213 (цикл)
}

PatchResult L07_TrafficEncryption()
{
    if (!Config::GetBool(kSec, L"Enabled", false))
    {
        return PatchResult::Disabled;      // ★ по умолчанию ВЫКЛ — сток не меняется
    }

    const bool allowLegacy = Config::GetBool(kSec, L"AllowLegacy", true);
    const bool killOnBad   = Config::GetBool(kSec, L"KillOnViolation", true);   // ★ В7d
    const int  logPerMin   = Config::GetInt (kSec, L"LogPerMinute", 30);        // ★ В7d
    const int  preKB       = Config::GetInt (kSec, L"PreHandshakeQueueKB", 64);  // ★ fix2b: очередь кадров до рукопожатия, КБ (0 — не копить)
    const int  preCloseMs  = Config::GetInt (kSec, L"PreHandshakeCloseMs", 5000); // ★ fix2b: отложенный DisConnect ждёт клиента, мс (0 — не откладывать)
    const int  lingerMs    = Config::GetInt (kSec, L"PreHandshakeLingerMs", 150); // ★ fix2c (Н-2): пауза выдача → разрыв, мс (сокет закрывается RST)
    int        txKB        = Config::GetInt (kSec, L"TxQueueKB", 1024);           // ★ fix2d (П-1): очередь шифрованных кадров слота, КБ (0 — без очереди)
    txKB = txKB < 0 ? 0 : (txKB > 65536 ? 65536 : txKB);
    int        txTotMB     = Config::GetInt (kSec, L"TxQueueTotalMB", 64);        // ★ fix2e (ревизия fix2d, Ф-1): общий предел очередей моста на процесс, МБ
    txTotMB = txTotMB < 1 ? 1 : (txTotMB > 1024 ? 1024 : txTotMB);
    // ★ sec2 (блок В плана альфы): справедливая доля общего предела (Е-2), ускорение рукопожатия, допуск подключений до рукопожатия.
    int fairKB    = Config::GetInt (kSec, L"TxQueueFairKB", 256);           // «тяжёлый» слот при общем пределе: очередь ≥ средней или ≥ N КБ
    fairKB = fairKB < 0 ? 0 : (fairKB > 65536 ? 65536 : fairKB);
    const bool hsCache = Config::GetBool(kSec, L"HandshakeKeyCache", true); // ключ подписи импортируется один раз (в памяти процесса)
    int hsPool    = Config::GetInt (kSec, L"HandshakePool", 16);            // пар ECDH заранее (фоновая нить), 0 — на месте
    hsPool = hsPool < 0 ? 0 : (hsPool > AsdaSecure::kEphPoolMax ? AsdaSecure::kEphPoolMax : hsPool);
    int perIpMax  = Config::GetInt (kSec, L"ConnPerIpMax", 120);            // новых подключений с адреса за окно (0 — без предела)
    perIpMax = perIpMax < 0 ? 0 : (perIpMax > 100000 ? 100000 : perIpMax);
    int perIpWin  = Config::GetInt (kSec, L"ConnPerIpWindowSec", 60);
    perIpWin = perIpWin < 1 ? 1 : (perIpWin > 3600 ? 3600 : perIpWin);
    int maxPend   = Config::GetInt (kSec, L"MaxPendingHandshakes", 64);     // незавершённых рукопожатий на процесс (0 — без предела)
    maxPend = maxPend < 0 ? 0 : (maxPend > AsdaWire::kMaxSlots ? AsdaWire::kMaxSlots : maxPend);
    int hsDeadline = Config::GetInt(kSec, L"HandshakeDeadlineMs", 10000);   // срок рукопожатия после accept (0 — без срока)
    hsDeadline = hsDeadline <= 0 ? 0 : (hsDeadline < 1000 ? 1000 : (hsDeadline > 120000 ? 120000 : hsDeadline));
    int admGap    = Config::GetInt (kSec, L"AdmissionLogGapMs", 5000);      // отчёты видов 64/65 не чаще (подавленные — в value3)
    admGap = admGap < 0 ? 0 : (admGap > 600000 ? 600000 : admGap);
    int maxPendIp = Config::GetInt (kSec, L"MaxPendingPerIp", 16);          // ★ sec2b (ревизия SEC2 Н-1): незавершённых с ОДНОГО адреса (0 — без предела)
    maxPendIp = maxPendIp < 0 ? 0 : (maxPendIp > AsdaWire::kMaxSlots ? AsdaWire::kMaxSlots : maxPendIp);
    wchar_t keyFile[128];
    Config::GetStr(kSec, L"KeyFile", L"secure_server.key", keyFile, 128);

    // Полный путь ключа = папка LoginManager + имя файла (ограниченная склейка; усечённый путь = «не найден»).
    wchar_t keyPath[MAX_PATH];
    _snwprintf_s(keyPath, MAX_PATH, _TRUNCATE, L"%s%s", Config::BaseDir(), keyFile);

    // ★ В7d: ключ проверяется ДО установки (без CNG — можно в DllMain). Негодный ключ → патч не ставится:
    //   LoginManager работает как сток (старый протокол), причина — в PatchLog. Не падаем и не блокируем вход молча.
    wchar_t why[96];
    if (!AsdaWire::CheckKeyFile(keyPath, why, 96))
    {
        Log::Line(L"    L07: Enabled=1, но ключ %s НЕ ГОДИТСЯ: %s — прослойка НЕ поставлена, LoginManager работает", keyFile, why);
        Log::Line(L"    L07:   как сток (старый протокол, старые клиенты входят); зашифрованный клиент получит отказ рукопожатия");
        Log::Line(L"    L07:   по таймауту. Исправить: положить secure_server.key (104 б, keygen) рядом с LoginManager.exe.");
        return PatchResult::Failed;
    }

    g_allowLegacy = allowLegacy;           // ★ fix2: для текста L07_InitNotify (сбой CNG)
    // Запомнить параметры (CNG откроется лениво на первом трамплине — НЕ в DllMain).
    AsdaWire::Configure(AsdaSecure::SubServer::Login, keyPath, allowLegacy, &SrvSendRaw);
    AsdaWire::SetFailureHooks(&L07_Kill, &L07_Report, &L07_InitNotify, killOnBad);
    AsdaWire::SetLogPerMinute(logPerMin);
    AsdaWire::SetLingerMs(lingerMs);                 // ★ fix2c (Н-2)
    AsdaWire::SetRecvSink(&L07_SinkC);               // ★ fix2c (Н-1): приём кусками в пределе буфера стока
    AsdaWire::SetStockSendLayout(&kStockLayout);     // ★ fix2d (П-1): кадр, который досылка стока не вместит, — в очередь моста
    AsdaWire::SetTxQueueMax(txKB * 1024);            // ★ fix2d (П-1/П-2)
    AsdaWire::SetTxQueueTotalMax(txTotMB * 1024 * 1024);   // ★ fix2e (Ф-1): сверх — разрыв слота, ac.other 61 причина 4
    AsdaWire::SetTxFairShare(fairKB * 1024);         // ★ sec2 (Е-2): лёгкий слот не рвём, сторож вытесняет наибольшую очередь (причина 6)
    AsdaWire::SetHandshakeAccel(hsCache, hsPool);    // ★ sec2: применится лениво в EnsureInit (не в DllMain)
    {
        AsdaWire::AdmissionCfg adm{ perIpMax, perIpWin * 1000, maxPend, hsDeadline, admGap, maxPendIp };   // ★ sec2b: + предел с адреса
        AsdaWire::SetAdmission(&adm, &L07_PeerIp);   // ★ sec2: виды 63–65
    }
    // ★ fix2b: DisConnect из IoWorkerThread sub_4161E0 (нулевой приём / ошибка сокета) не откладывается — выдать некому.
    AsdaWire::SetPreHandshake((preKB < 0 ? 0 : (preKB > 1024 ? 1024 : preKB)) * 1024, preCloseMs < 0 ? 0 : (preCloseMs > 60000 ? 60000 : preCloseMs),
                              0x004161E0, 0x004167E0);

    // Сверка оригиналов всех площадок (+ стоковой ветки разрыва — она не пишется, но на неё уходит трамплин).
    const Site sites[] = {
        { Login::Hooks::kRecvClientCall, kRecvCallOrig,   5 },
        { Login::Hooks::kSendCallA,      kSendCallAOrig,  5 },
        { Login::Hooks::kSendCallB,      kSendCallBOrig,  5 },
        { Login::Hooks::kSetConnEntry,   kSetConnOrig,    5 },
        { Login::Hooks::kDisConnect,     kDiscOrig,       5 },   // ★ fix2b: вход DisConnect (детур ворот отложенного разрыва)
        { 0x0041644E,                    kKillFlagCall,   5 },
        { 0x0041645E,                    kKillDiscCall,   5 },
        { Login::Hooks::kKillResume,     kKillResumeOrig, 2 },
        { 0x00416472,                    kKillLoopJmp,    5 },
    };
    if (!VerifyAllSites(kSec, sites, 9))
    {
        return PatchResult::Mismatch;
    }

    // ★ fix2 (НИЗК-7): детур SetConnectFlag — ПЕРВЫМ; при сбое любой записи уже записанные площадки возвращаются
    //   к оригинальным байтам (сток целиком, без recv/send без сброса слота).
    struct W { DWORD va; const unsigned char* orig; bool jmp; void* to; };
    const W writes[] = {
        { Login::Hooks::kSetConnEntry,   kSetConnOrig,   true,  (void*)&L07_SetConnTramp },
        { Login::Hooks::kDisConnect, kDiscOrig, true, (void*)&L07_DiscTramp },   // ★ fix2b
        { Login::Hooks::kRecvClientCall, kRecvCallOrig,  false, (void*)&L07_RecvTramp },
        { Login::Hooks::kSendCallA,      kSendCallAOrig, false, (void*)&L07_SendTramp },
        { Login::Hooks::kSendCallB,      kSendCallBOrig, false, (void*)&L07_SendTramp },
    };
    int ok = 0;
    for (; ok < 5; ++ok)
    {
        const W& w = writes[ok];
        if (!(w.jmp ? Hook::WriteJmp(w.va, w.to, 5) : Hook::WriteCall(w.va, w.to, 5))) { break; }
    }
    if (ok != 5)
    {
        int back = 0;
        for (int i = ok - 1; i >= 0; --i) { if (Hook::WriteBytes(writes[i].va, writes[i].orig, 5)) { ++back; } }
        Log::Line(L"    L07: [ОШИБКА] запись площадки %d из 5 (0x%08X) не прошла — возвращено к оригиналу %d из %d записанных; сток",
                  ok + 1, writes[ok].va, back, ok);
        return PatchResult::Failed;
    }

    // ★ В7d: журнал античита (ac.other 56–59, ★ fix2d 61) — та же база joylog1, секция [P53_AcJournal] этого patches.ini.
    const int jr = AcJournal::Start(L"LoginPatch");
    g_journal = (jr == 0);

    Log::Line(L"    L07: прослойка шифрования установлена (recv+2×send+SetConnectFlag+DisConnect); ключ %s (104 б, ASDAKEY1); старый клиент %s",
              keyFile, allowLegacy ? L"разрешён (переход)" : L"ЗАПРЕЩЁН");
    Log::Line(L"    L07: нарушение канала → %s; строк PatchLog не больше %d/мин; журнал ac.other 56–59, 61: %s",
              killOnBad ? L"РАЗРЫВ штатным DisConnect" : L"кадр отбрасывается (KillOnViolation=0)", logPerMin,
              g_journal ? L"включён" : (jr == 1 ? L"выключен ([P53_AcJournal] Enabled=0)" : L"НЕ ЗАПУЩЕН (ошибка очереди/потока)"));
    Log::Line(L"    L07: кадры сервера до рукопожатия — в очередь слота (не больше %d КБ), сразу за ServerHello / как есть старому клиенту; "
              L"DisConnect при невыданной очереди отложен до первых байт клиента, не дольше %d мс, после выдачи — пауза %d мс", preKB, preCloseMs, lingerMs);
    Log::Line(L"    L07: кадр шифрования не больше 0x1000 б (открытый текст ≤ 4068 на кадр — буфер записи Ciocp::Send), приём стоку — кусками ≤ 4087 б");
    Log::Line(L"    L07: досылка стока полна (0x9F9C) — шифрованные кадры ждут в очереди слота (не больше %d КБ на слот и %d МБ на все слоты, "
              L"выталкивает сторож); отказ стокового Send / переполнение очереди / общий предел / нехватка памяти — разрыв, журнал ac.other 61",
              txKB, txTotMB);
    Log::Line(L"    L07: общий предел очередей — справедливая доля: слот с очередью ≥ средней или ≥ %d КБ рвётся сам (причина 4), иначе кадр "
              L"принимается до предела + 1/8, а сторож вытесняет наибольшую очередь (причина 6)", fairKB);
    Log::Line(L"    L07: рукопожатие — ключ подписи %s, пул пар ECDH %d (%s); ключи только в памяти процесса", hsCache ? L"импортируется один раз" : L"импортируется на каждое рукопожатие",
              hsPool, hsPool ? L"фоновая нить, каждая пара одноразовая" : L"выкл — пара на месте");
    Log::Line(L"    L07: допуск до рукопожатия — с адреса не больше %d подключений за %d с (вид 63), незавершённых рукопожатий не больше %d, с одного адреса — %d (вид 64), "
              L"срок рукопожатия %d мс (вид 65%s); сверх — разрыв штатным DisConnect до рукопожатия, PatchLog «[допуск]», журнал ac.other 63–65 "
              L"(64/65 — не чаще раза в %d мс)", perIpMax, perIpWin, maxPend, maxPendIp, hsDeadline,
              allowLegacy ? L"; молчащий сокет при AllowLegacy=1 не рвётся, но по сроку снимается со счёта незавершённых" : L"", admGap);
    Log::Line(L"    L07: CNG/ключ загрузятся лениво при первом соединении (строка «CNG открыт, ключ загружен»)");
    return PatchResult::Applied;
}
