// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P61 — ★ ШИФРОВАНИЕ ТРАФИКА (прослойка AsdaSecure) в GameServer/Indun (15601).
//  Волна В7b «врезка». Зеркало L07 (LoginManager). План: 00_PLAN.md «Дополнение 11.10».
//  Дизайн: AstoryServer/Docs/_Common/traffic-encryption-design.md.
//  Документ: AstoryServer/Docs/GameServer/traffic-encryption-p61.md.
//
//  Встаёт между сокетом и разборщиком старого кадра `FB|size|A|B|op…FE`, НЕ меняя протокол:
//    • приём (socket-recv клиентского слота в IoWorkerThread sub_564900) → расшифровка → разборщик;
//    • отправка (три call-site Ciocp::Send sub_561F20)                   → шифрование перед WriteFile;
//    • accept/disc (вход SetConnectFlag sub_562910)                     → Reset канала слота.
//  Крипто — AsdaSecure/AsdaWire (CNG): ECDH P-256, ECDSA-подпись сервера, AES-256-GCM, seq против повтора.
//  Закрытый ключ — файл secure_server.key рядом с GameServer.exe (кладёт владелец; keygen). Нет — выкл.
//
//  GameServer.exe и Indun_GameServer\GameServer.exe — ОДИН образ/роль/ключ → под-сервер Game для обоих.
//
//  Безопасность: Enabled=0 по умолчанию; CNG открывается лениво (не в DllMain); состояние на слот под
//  своим локом; межсервер не трогаем.
//  ★ В7d (2026-10-13): нарушение целостности (порча тега / повтор номера / мусор до рукопожатия / длина кадра вне
//  предела / старый клиент при AllowLegacy=0) → PatchLog (ограничитель LogPerMinute) + журнал ac.other виды 56–59
//  → РАЗРЫВ штатным путём стока «клиент закрыл соединение»: Ciocp::GetConnectFlag 0x5629C0 + Ciocp::DisConnect
//  0x561C30 (ветка нулевого приёма IoWorkerThread; ту же пару зовёт стоковый кик sub_526E40), возврат на её хвост
//  0x564B83. KillOnViolation=0 — откат к поведению В7b (кадр только отбрасывается).
//  ★ В7d: Enabled=1 без годного файла ключа (нет / не 104 б / нет метки ASDAKEY1) — патч НЕ ставится (сток), причина
//  в PatchLog. Сервер не падает и вход не блокируется молча.
//  ★ fix2 (2026-10-13, ревизия INTEG3): Б-1 — детур SetConnectFlag (зовётся ПОД замком Ciocp) только ставит запрос сброса
//  слота, без замка слота; Б-2 — трамплин отправки зовёт AsdaWire::SendRoute: шифрование и стоковый Send под замком слота
//  (порядок номеров кадров = порядок на проводе при 21 нити карт + нить 6004). Порядок замков везде «слот → Ciocp».
//  НИЗК-5: CNG не открылся — байты как есть (AllowLegacy=1). НИЗК-7: детур SetConnectFlag пишется первым, при сбое любой
//  записи уже записанные площадки возвращаются к оригиналу.
//  Площадки сверены на стоке (4e20f0ad) и живом/Indun (e7b4ac38) — verify_p61.py.
//  ★ fix2d (2026-10-14, хвост ревизии FIX2 «переполнение досылки стока», П-1/П-2): мост перед стоковым Send под тем же замком
//  Ciocp читает досылку слота; кадр, который сток стёр бы вместе с досылкой (≥ 0x9F9C), ждёт в очереди слота моста (TxQueueKB,
//  1 МБ; выталкивает сторож раз в 50 мс). Отказ стокового Send / переполнение очереди / потеря кадра стоком у Secure-слота —
//  разрыв, PatchLog «[досылка]», журнал ac.other 61. Новых площадок нет; Legacy — как сток.
//  ★ fix2e (2026-10-14, ревизия fix2d Ф-1): общий предел очередей моста на процесс TxQueueTotalMB (64 МБ; сверх — разрыв этого
//  слота, ac.other 61 причина 4, value2 = общий объём); сбой выделения памяти в мосте перехвачен внутри моста — разрыв слота
//  (причина 5), исключение в naked-трамплин и сток не выходит, GameServer не падает.
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
#include <stdio.h>   // [fix13] _snprintf_s / _snwprintf_s — ограниченные форматтеры
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "AsdaServerBridge.h"
#include "AsdaSecure.h"
#include "../AcJournal.h"   // ★ В7d: ac.other 56–59

namespace
{
    const wchar_t* kSec = L"P61_TrafficEncryption";
    bool g_allowLegacy = true;             // ★ fix2: AllowLegacy из ini (для текста строки о сбое CNG)
    bool AsdaWire_AllowLegacyNow() { return g_allowLegacy; }

    using SendFn = int(__thiscall*)(void* self, int slot, const void* src, int len);

    // ★ fix2: возвращает итог стокового Ciocp::Send (1/0). Зовётся ТОЛЬКО под замком слота (SendRoute/OnRecv).
    int SrvSendRaw(void* ciocpThis, int slot, const void* data, int len)
    {
        return ((SendFn)Srv::Hooks::kP61SendFunc)(ciocpThis, slot, data, len);
    }

    // ★ В7d: >0 — длина расшифрованного потока (*out); 0 — отдавать нечего; −1 — нарушение, соединение закрыто.
    extern "C" int __cdecl P61_RecvRouteC(void* ciocpThis, int slot, const void* buf, int size, const unsigned char** out)
    {
        P69_NoteSlotIp(slot);   // ★ autoban: IP пира раз на соединение (кэш сбрасывает P61_ResetSlotC) — для журнала, если клиент уже сбросил сокет
        return AsdaWire::RecvRoute(ciocpThis, slot, buf, size, out);
    }
    // ★ fix2 (Б-2): шифрование + стоковый Send атомарно под замком слота; возврат — итог стокового Send.
    extern "C" int __cdecl P61_SendRouteC(void* ciocpThis, int slot, const void* frame, int len)
    {
        return AsdaWire::SendRoute(ciocpThis, slot, frame, len);
    }
    // ★ fix2c (Н-1, приём): стоковый разборщик приёма sub_563C20 (CCircleQ::CopyToWriteBuffer) — thiscall(this, buf, size, slot), ret 0xC. Мост отдаёт ему
    //   расшифрованный поток кусками ≤ 0x1000 − 9 (как порции ReadFile 0x1000), без своих замков.
    using SinkTFn = int(__thiscall*)(void* self, const void* buf, int size, int slot);
    int P61_SinkC(void* self, const void* data, int len, int slot)
    {
        return ((SinkTFn)0x00563C20)(self, data, len, slot);
    }

    // ★ fix2b: второй аргумент SetConnectFlag (1 accept / 0 разрыв) — очередь кадров до рукопожатия новой сессии не стирается.
    //   ★ sec2: + this Ciocp (ecx детура) — сторож допуска рвёт молчащее соединение под замком L этого Ciocp.
    extern "C" void __cdecl P61_ResetSlotC(void* self, int slot, int flag)
    {
        P73_OnConnFlag(slot, flag);   // ★ P73 (EAC, 2026-10-16): общая точка — LOGOUT сессии слота сайдкару (только таблица/кольцо под листовым замком)
        P69_SlotReset(slot);    // ★ autoban: новое соединение / разрыв — забыть IP, CUserManager и метку кика слота (только Interlocked)
        AsdaWire::ResetSlotEx(self, slot, flag);
    }
    // ★ sec2: IPv4 пира слота для допуска (живой getpeername — общая точка P47; 0 — не определён).
    uint32_t P61_PeerIp(void* /*self*/, int slot) { return (uint32_t)P47_PeerIpv4(slot); }
    // ★ fix2b: ворота входа Ciocp::DisConnect 0x00561C30: 1 — отложить (у слота невыданные кадры до рукопожатия — отказ сервера сразу
    //   после accept), сток не выполнять и вернуть 1; 0 — сток как есть. Без замков моста (вход бывает под замком Ciocp).
    extern "C" int __cdecl P61_DiscGateC(void* self, int slot, unsigned int retAddr)
    {
        return AsdaWire::DisconnectGate(self, slot, (uintptr_t)retAddr) ? 1 : 0;
    }

    // ── ★ В7d: разрыв, отчёт, уведомление об инициализации ─────────────────────
    using SlotFn = int(__thiscall*)(void* self, int slot);   // Ciocp::GetConnectFlag / Ciocp::DisConnect

    // Закрыть соединение слота ШТАТНЫМ путём стока (ветка нулевого приёма IoWorkerThread и стоковый кик sub_526E40):
    //   if (Ciocp::GetConnectFlag(this, slot)) Ciocp::DisConnect(this, slot);
    void P61_Kill(void* self, int slot)
    {
        __try
        {
            if (((SlotFn)Srv::Hooks::kP61GetConnFlag)(self, slot)) { ((SlotFn)Srv::Hooks::kP61DisConnect)(self, slot); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    const wchar_t* ModeName(int m) { return m == 1 ? L"Secure" : (m == 2 ? L"Legacy" : L"до рукопожатия"); }

    // Отчёт о нарушении: PatchLog (ограничитель LogPerMinute) + ac.other 56–59. Зовётся ДО разрыва (IP ещё читается).
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

    void P61_Report(void* /*self*/, int slot, const AsdaWire::FailInfo& fi)
    {
        // ★ autoban (P69, 2026-10-14): адрес — живой getpeername (общая точка acdb), при отказе — IP ЭТОГО соединения из кэша P69
        //   (снят на первом приёме); учётка — CUser слота через CUserManager, запомненный гейтом P47 (поток IOCP своего не имеет):
        //   только подтверждённая учётка сессии (в мире; соулмейт — iMateUserIndex), до входа в мир — NULL.
        const DWORD ip = P69_SlotIp(slot);
        const BYTE* q = (const BYTE*)&ip;
        int sup = 0;
        P69_Session ss;
        P69_ResolveSession(nullptr, slot, &ss);
        // ★ fix2d (П-2): шифрованный кадр Secure-слота не доставить по порядку — разрыв с причиной (сбой сервера/сети, не клиента).
        //   Журнал: item_code = причина 1..5, value1 = байт в очереди моста, value2 = длина стоковой досылки (NULL — не читалась);
        //   ★ fix2e: для причин 4 (общий предел TxQueueTotalMB) и 5 (нехватка памяти) value2 = байт во ВСЕХ очередях моста процесса.
        // ★ sec2: ДОПУСК подключений до рукопожатия (виды 63–65): адрес — из решения моста (fi.ip), учётки нет (до логина).
        //   Журнал: item_code — нет; value1 = счёт (63 подключений с адреса / 64 незавершённых / 65 возраст, мс), value2 = предел,
        //   value3 = 63 окно, с / 64–65 подавлено ограничителем отчётов моста. Не нарушение целостности — в счёт P69 не идёт.
        if (fi.kind >= AsdaWire::kKindConnRate && fi.kind <= AsdaWire::kKindHsDeadline)
        {
            const DWORD aip = fi.ip ? (DWORD)fi.ip : ip;
            const BYTE* a = (const BYTE*)&aip;
            if (AsdaWire::LogAllow(&sup))
            {
                if (fi.kind == AsdaWire::kKindConnRate)
                    Log::Line(L"    P61: [допуск] слот %d IP %u.%u.%u.%u: %d-е подключение с адреса за %d с (предел ConnPerIpMax %d) — разрыв до рукопожатия (вид 63; дальше по адресу в этом окне — без строк)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.extra, fi.limit);
                else if (fi.kind == AsdaWire::kKindPendingCap && fi.mode == 1)   // ★ sec2b (Н-1): предел с адреса
                    Log::Line(L"    P61: [допуск] слот %d IP %u.%u.%u.%u: незавершённых рукопожатий с этого адреса %d (предел MaxPendingPerIp %d) — новое соединение разорвано (вид 64; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.extra);
                else if (fi.kind == AsdaWire::kKindPendingCap)
                    Log::Line(L"    P61: [допуск] слот %d IP %u.%u.%u.%u: незавершённых рукопожатий %d (предел MaxPendingHandshakes %d) — новое соединение разорвано (вид 64; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.extra);
                else
                    Log::Line(L"    P61: [допуск] слот %d IP %u.%u.%u.%u: рукопожатие не завершено за %d мс (срок HandshakeDeadlineMs %d), %s — разрыв (вид 65; подавлено отчётов %d)",
                              slot, a[0], a[1], a[2], a[3], fi.count, fi.limit, fi.mode == 0 ? L"клиент молчит" : L"клиент начал и бросил", fi.extra);
                if (sup > 0) { Log::Line(L"    P61: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
            }
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, (BYTE)fi.kind);
            e.userNum = (short)slot;
            e.ip      = aip;
            e.v[0]    = fi.count;
            e.v[1]    = fi.limit;
            e.v[2]    = fi.extra;
            char t[64];
            if (fi.kind == AsdaWire::kKindConnRate)        { _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: conn rate %d/%d per %ds", fi.count, fi.limit, fi.extra); }
            else if (fi.kind == AsdaWire::kKindPendingCap) { _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: pending handshakes%s %d/%d", fi.mode == 1 ? " from IP" : "", fi.count, fi.limit); }
            else { _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: handshake %d/%d ms, %s", fi.count, fi.limit, fi.mode == 0 ? "silent" : "partial"); }
            AcJournal::CopyText(e, t);
            AcJournal::Push(e);
            return;
        }
        if (fi.kind == AsdaWire::kKindSendFail)
        {
            if (AsdaWire::LogAllow(&sup))
            {
                Log::Line(L"    P61: [досылка] слот %d IP %u.%u.%u.%u: %s (вид 61, причина %d; в очереди моста %d б, досылка стока %d б, во всех очередях моста %d б) — разрыв",
                          slot, q[0], q[1], q[2], q[3], SendFailText(fi.reason), fi.reason, fi.queued, fi.pending, fi.total);
                if (sup > 0) { Log::Line(L"    P61: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
            }
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, (BYTE)AsdaWire::kKindSendFail);
            e.userNum = (short)slot;
            e.ip      = ip;
            if (ss.account > 0) { e.userIndex = ss.account; e.charSlot = ss.charSlot; }   // ★ autoban: для чтения (не счёт: сбой доставки)
            e.v[0]    = fi.reason;
            e.v[1]    = fi.queued;
            e.v[2]    = (fi.reason == AsdaWire::kSendFailTotalMax || fi.reason == AsdaWire::kSendFailNoMem || fi.reason == AsdaWire::kSendFailTotalEvict) ? fi.total   // ★ fix2e/sec2
                      : (fi.pending >= 0 ? fi.pending : AcJournal::kNone);
            char t[64];
            if (fi.reason == AsdaWire::kSendFailTotalMax || fi.reason == AsdaWire::kSendFailNoMem || fi.reason == AsdaWire::kSendFailTotalEvict)   // ★ fix2e/sec2: + общий объём
                { _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: %s, q %d, all %d", SendFailShort(fi.reason), fi.queued, fi.total); }
                else { _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: %s, queue %d b", SendFailShort(fi.reason), fi.queued); }
            AcJournal::CopyText(e, t);
            AcJournal::Push(e);
            return;
        }
        if (AsdaWire::LogAllow(&sup))
        {
            wchar_t err[32]; MultiByteToWideChar(CP_ACP, 0, AsdaSecure::ErrName(fi.err), -1, err, 32);
            wchar_t fb[8] = L"—";
            if (fi.firstByte >= 0) { _snwprintf_s(fb, 8, _TRUNCATE, L"0x%02X", fi.firstByte); }
            Log::Line(L"    P61: [нарушение канала] слот %d IP %u.%u.%u.%u: %s (вид %d), %s, %s %d б, первый байт %s%s; %s",
                      slot, q[0], q[1], q[2], q[3], err, fi.kind, ModeName(fi.mode),
                      fi.phase == 0 ? L"приём" : L"отправка", fi.bytes, fb,
                      (fi.mode == 0 && fi.firstByte == 0xFB) ? L" (старый клиент при AllowLegacy=0)" : L"",
                      fi.phase == 0 ? L"соединение закрывается штатным DisConnect" : L"кадр не отправлен, разрыв на ближайшем приёме");
            if (sup > 0) { Log::Line(L"    P61: (до этой строки подавлено ограничителем LogPerMinute: %d)", sup); }
        }
        if (fi.kind > 0)
        {
            AcJournal::Event e;
            AcJournal::Clear(e, AcJournal::kOther, (BYTE)fi.kind);
            e.userNum = (short)slot;
            e.ip      = ip;
            if (ss.account > 0) { e.userIndex = ss.account; e.charSlot = ss.charSlot; }   // ★ autoban: подтверждённая учётка сессии
            if (ss.user)
            {
                __try { AcJournal::CopyName(e, ss.user + Srv::kOffCharName); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
            e.v[0]    = (int)fi.err;     // код ошибки прослойки (AsdaSecure::Err)
            e.v[1]    = fi.mode;         // 0 до рукопожатия / 1 Secure / 2 Legacy
            e.v[2]    = fi.firstByte >= 0 ? fi.firstByte : AcJournal::kNone;   // первый байт порции (0xFB — старый клиент); нет — NULL (fix2, НИЗК-11)
            char t[64];
            _snprintf_s(t, sizeof(t), _TRUNCATE, "P61 GameServer: %s, %d b", AsdaSecure::ErrName(fi.err), fi.bytes);
            AcJournal::CopyText(e, t);
            AcJournal::Push(e);          // журнал не запущен (P53 выкл) — вернёт false, ничего не ждёт
        }
        // ★ autoban (P69): нарушение канала, присланное КЛИЕНТОМ (приём, виды 56..59), — в счёт автоблока учётки. Сбои сервера
        //   (отправка, вид 0) и доставки (вид 61, причины 1..5) сюда не доходят — не вина игрока. Один отчёт на соединение (мост).
        if (fi.kind >= AsdaWire::kKindBadTag && fi.kind <= AsdaWire::kKindFormat && fi.phase == 0)
        {
            P69_OnViolation(ss, slot, kP69SrcP61, fi.kind, ip, AcJournal::kNone);
        }
    }

    void P61_InitNotify(bool cngOk, bool keyOk)
    {
        // ★ fix2 (НИЗК-5): при сбое CNG мост пропускает байты как есть (AsdaWire::IsBypass) — текст соответствует коду.
        if (!cngOk)       { Log::Line(AsdaWire_AllowLegacyNow()
                                ? L"    P61: [ОШИБКА] CNG (bcrypt) не открылся — шифрования нет: старые клиенты (AllowLegacy=1) работают как сток, зашифрованные не получат ServerHello"
                                : L"    P61: [ОШИБКА] CNG (bcrypt) не открылся при AllowLegacy=0 — каждое соединение закрывается на первом приёме (строка «нарушение канала», вид 0)"); }
        else if (!keyOk)  { Log::Line(L"    P61: [ОШИБКА] ключ не загрузился при первом соединении — зашифрованные клиенты будут отвергнуты"); }
        else              { Log::Line(L"    P61: CNG открыт, ключ загружен (первое соединение) — шифрование работает"); }
    }

    // Приём: замена `call sub_563C20` @0x564CD5. ecx=this(Ciocp, [ebp-24h]); [esp+4]=buf,[esp+8]=size,[esp+0xC]=slot; ret 0xC.
    //  ★ В7d: при −1 (нарушение, DisConnect уже выполнен) адрес возврата заменяется на kP61KillResume 0x564B83 —
    //  хвост стоковой ветки разрыва (`jmp 0x564B92` → начало цикла). Стек одинаков: ret 0xC снимает три аргумента,
    //  обе точки — границы операторов одного кадра IoWorkerThread.
    __declspec(naked) void P61_RecvTramp()
    {
        __asm
        {
            push ebp
            mov  ebp, esp
            push esi
            push edi
            push ebx
            mov  esi, ecx
            sub  esp, 4                   // [esp] = out
            mov  eax, esp
            push eax                      // &out
            push dword ptr [ebp+0x0C]     // size
            push dword ptr [ebp+0x08]     // buf
            push dword ptr [ebp+0x10]     // slot
            push esi                      // ciocpThis
            call P61_RecvRouteC           // cdecl -> int
            add  esp, 20
            mov  edi, [esp]               // out
            add  esp, 4
            mov  ebx, eax
            test ebx, ebx
            js   killed                   // −1 — соединение закрыто штатным DisConnect
            jz   done                     // 0 — отдавать нечего
            test edi, edi
            jz   done
            push dword ptr [ebp+0x10]
            push ebx
            push edi
            mov  ecx, esi
            mov  eax, 0x00563C20
            call eax
            jmp  done
        killed:
            mov  dword ptr [ebp+4], 0x00564B83   // Srv::Hooks::kP61KillResume — хвост стоковой ветки разрыва
        done:
            pop  ebx
            pop  edi
            pop  esi
            mov  esp, ebp
            pop  ebp
            ret  0x0C
        }
    }

    // Отправка: замена `call sub_561F20` на трёх call-site. ecx=this; [esp+4]=slot,[esp+8]=Src,[esp+0xC]=nBytes; ret 0xC.
    //  ★ fix2 (Б-2): стоковый Send трамплин сам больше НЕ зовёт — его зовёт SendRoute под замком слота (раньше трамплин
    //  звал его после выхода из замка: две нити одного слота уходили на провод не в порядке номеров кадров).
    //  Возврат eax — итог стокового Send (вызывающие 0x4C2ACF/0x4C2BE1/0x56435E его не используют).
    __declspec(naked) void P61_SendTramp()
    {
        __asm
        {
            push ebp
            mov  ebp, esp
            push dword ptr [ebp+0x10]     // nBytes
            push dword ptr [ebp+0x0C]     // Src
            push dword ptr [ebp+0x08]     // slot
            push ecx                      // ciocpThis
            call P61_SendRouteC           // cdecl (this,slot,Src,n) -> int
            add  esp, 16
            pop  ebp
            ret  0x0C
        }
    }

    // Reset: детур входа SetConnectFlag sub_562910. Украдено 5 байт: 55 8b ec 6a ff. Возврат 0x562915.
    __declspec(naked) void P61_SetConnTramp()
    {
        __asm
        {
            pushad
            mov   eax, dword ptr [esp+0x28]   // ★ fix2b: flag — orig [esp+8] + 0x20 (pushad)
            push  eax
            movzx eax, word ptr [esp+0x28]    // slot — orig [esp+4] + 0x20 + 4 (push выше)
            push  eax
            push  ecx                          // ★ sec2: this (Ciocp) — pushad ecx не меняет
            call P61_ResetSlotC                // cdecl(this, slot, flag)
            add   esp, 12
            popad
            push ebp
            mov  ebp, esp
            push -1
            mov  eax, 0x00562915
            jmp  eax
        }
    }

    // ★ fix2b: детур входа Ciocp::DisConnect 0x00561C30 (украдено 5 б: 55 8b ec 6a ff, продолжение 0x00561C35). thiscall(this, slot), ret 4.
    //   Ворота P61_DiscGateC: 1 — разрыв отложен до выдачи кадров до рукопожатия (eax=1, как сток для годного слота).
    __declspec(naked) void P61_DiscTramp()
    {
        __asm
        {
            pushad
            push  dword ptr [esp+0x20]        // адрес возврата вызывающего (orig [esp] + 0x20)
            movzx eax, word ptr [esp+0x28]    // slot — orig [esp+4] + 0x20 + 4
            push  eax
            push  ecx                         // this (Ciocp)
            call  P61_DiscGateC              // cdecl(this, slot, ret) -> 0/1
            add   esp, 12
            mov   dword ptr [esp+0x1C], eax   // в сохранённый eax
            popad
            test  eax, eax
            jnz   deferred
            push  ebp                         // украденный пролог
            mov   ebp, esp
            push  -1
            mov   eax, 0x00561C35
            jmp   eax
        deferred:
            mov   eax, 1
            ret   4
        }
    }

    // ★ fix2d (П-1): раскладка стокового Ciocp::Send/SendTemp (дизасм GS 0x561F20/0x562640, одинаково в стоке 4e20f0ad и
    //   живом/Indun e7b4ac38 — verify_traffic): замок L this+0x60D1830 (RAII 0x568D50 → EnterCriticalSection), сессии
    //   [this+0x60D1898] + slot·0xA0BE, +4 флаг соединения (0x561FCA), +8 запись в полёте (0x562001), +0xA0B2 длина досылки
    //   (0x562021), порог стирания 0x9F9C (0x56202B), буфер записи 0x1000 (ветка досылки без записи 0x562343). Новых площадок нет —
    //   мост только читает поля под тем же L и зовёт стоковый Send.
    const AsdaWire::StockSendLayout kStockLayout = { 0x060D1830u, 0x060D1898u, 0xA0BEu, 4u, 8u, 0xA0B2u, 0x9F9C, 0x1000 };

    const unsigned char kRecvCallOrig[5]  = { 0xE8, 0x46, 0xEF, 0xFF, 0xFF };  // call 0x563C20
    const unsigned char kSendCallAOrig[5] = { 0xE8, 0x51, 0xF4, 0x09, 0x00 };  // call 0x561F20
    const unsigned char kSendCallBOrig[5] = { 0xE8, 0x3F, 0xF3, 0x09, 0x00 };  // call 0x561F20
    const unsigned char kSendCallCOrig[5] = { 0xE8, 0xBD, 0xDB, 0xFF, 0xFF };  // call 0x561F20
    const unsigned char kSetConnOrig[5]   = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };  // push ebp;mov ebp,esp;push -1
    const unsigned char kDiscOrig[5]      = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };   // ★ fix2b: вход DisConnect 0x00561C30 (push ebp;mov ebp,esp;push -1)
    // ★ В7d: стоковая ветка разрыва (только СВЕРКА, не пишется): call GetConnectFlag / call DisConnect / jmp хвоста.
    const unsigned char kKillFlagCall[5]  = { 0xE8, 0x4D, 0xDE, 0xFF, 0xFF };  // @0x564B6E call 0x5629C0
    const unsigned char kKillDiscCall[5]  = { 0xE8, 0xAD, 0xD0, 0xFF, 0xFF };  // @0x564B7E call 0x561C30
    const unsigned char kKillResumeOrig[2]= { 0xEB, 0x0D };                    // @0x564B83 jmp 0x564B92
    const unsigned char kKillLoopJmp[5]   = { 0xE9, 0x9C, 0xFD, 0xFF, 0xFF };  // @0x564B92 jmp 0x564933 (цикл)
}

// ★ P73 (EAC, 2026-10-16): детур входа SetConnectFlag 0x562910 поставлен этим патчем (общая точка LOGOUT моста EAC).
static bool g_setConnPlaced = false;
bool P61_SetConnHooked()
{
    return g_setConnPlaced;
}

// ★ EAC ред. 3 (контракт §8.1): bind игрового соединения слота для моста EAC P73 (LOGIN/REBIND). Только когда прослойка
//   поставлена целиком (g_setConnPlaced — последняя запись установки); иначе мост не инициализирован и привязки нет.
static_assert(AsdaSecure::kBindLen == 32, "P61_SlotBinding: длина bind 32 б (контракт EAC §8.1)");
bool P61_SlotBinding(int slot, BYTE out[32])
{
    if (!g_setConnPlaced || !out) { return false; }
    return AsdaWire::SlotChannelBinding(slot, out);
}

PatchResult P61_TrafficEncryption()
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

    // [fix13, 2026-10-13] было lstrcpynW + lstrcatW (KeyFile из ini до 127 символов к папке сервера без проверки длины) —
    // ограниченная склейка, ноль гарантирован; усечённый путь просто не найдёт ключ (штатная ветка «нет ключа»).
    wchar_t keyPath[MAX_PATH];
    _snwprintf_s(keyPath, MAX_PATH, _TRUNCATE, L"%s%s", Config::BaseDir(), keyFile);

    // ★ В7d: ключ проверяется ДО установки (без CNG — можно в DllMain). Негодный ключ → патч не ставится:
    //   GameServer работает как сток (старый протокол), причина — в PatchLog. Не падаем и не блокируем вход молча.
    wchar_t why[96];
    if (!AsdaWire::CheckKeyFile(keyPath, why, 96))
    {
        Log::Line(L"    P61: Enabled=1, но ключ %s НЕ ГОДИТСЯ: %s — прослойка НЕ поставлена, сервер работает", keyFile, why);
        Log::Line(L"    P61:   как сток (старый протокол, старые клиенты входят); зашифрованный клиент получит отказ рукопожатия");
        Log::Line(L"    P61:   по таймауту. Исправить: положить secure_server.key (104 б, keygen) рядом с GameServer.exe.");
        return PatchResult::Failed;
    }

    g_allowLegacy = allowLegacy;           // ★ fix2: для текста P61_InitNotify (сбой CNG)
    // GameServer и Indun — один образ/роль/ключ → под-сервер Game для обоих.
    AsdaWire::Configure(AsdaSecure::SubServer::Game, keyPath, allowLegacy, &SrvSendRaw);
    AsdaWire::SetFailureHooks(&P61_Kill, &P61_Report, &P61_InitNotify, killOnBad);
    AsdaWire::SetLogPerMinute(logPerMin);
    AsdaWire::SetLingerMs(lingerMs);                 // ★ fix2c (Н-2)
    AsdaWire::SetRecvSink(&P61_SinkC);               // ★ fix2c (Н-1): приём кусками в пределе буфера стока
    AsdaWire::SetStockSendLayout(&kStockLayout);     // ★ fix2d (П-1): кадр, который досылка стока не вместит, — в очередь моста
    AsdaWire::SetTxQueueMax(txKB * 1024);            // ★ fix2d (П-1/П-2)
    AsdaWire::SetTxQueueTotalMax(txTotMB * 1024 * 1024);   // ★ fix2e (Ф-1): сверх — разрыв слота, ac.other 61 причина 4
    AsdaWire::SetTxFairShare(fairKB * 1024);         // ★ sec2 (Е-2): лёгкий слот не рвём, сторож вытесняет наибольшую очередь (причина 6)
    AsdaWire::SetHandshakeAccel(hsCache, hsPool);    // ★ sec2: применится лениво в EnsureInit (не в DllMain)
    {
        AsdaWire::AdmissionCfg adm{ perIpMax, perIpWin * 1000, maxPend, hsDeadline, admGap, maxPendIp };   // ★ sec2b: + предел с адреса
        AsdaWire::SetAdmission(&adm, &P61_PeerIp);   // ★ sec2: виды 63–65
    }
    // ★ fix2b: DisConnect из GetQueueData2/IoWorkerThread 0x564900 (нулевой приём / ошибка сокета) не откладывается — выдать некому.
    AsdaWire::SetPreHandshake((preKB < 0 ? 0 : (preKB > 1024 ? 1024 : preKB)) * 1024, preCloseMs < 0 ? 0 : (preCloseMs > 60000 ? 60000 : preCloseMs),
                              0x00564900, 0x00564F00);

    const Site sites[] = {
        { Srv::Hooks::kP61RecvClientCall, kRecvCallOrig,   5 },
        { Srv::Hooks::kP61SendCallA,      kSendCallAOrig,  5 },
        { Srv::Hooks::kP61SendCallB,      kSendCallBOrig,  5 },
        { Srv::Hooks::kP61SendCallC,      kSendCallCOrig,  5 },
        { Srv::Hooks::kP61SetConnEntry,   kSetConnOrig,    5 },
        { Srv::Hooks::kP61DisConnect,     kDiscOrig,       5 },   // ★ fix2b: вход DisConnect (детур ворот отложенного разрыва)
        { 0x00564B6E,                     kKillFlagCall,   5 },   // ★ В7d: сверка стоковой ветки разрыва
        { 0x00564B7E,                     kKillDiscCall,   5 },
        { Srv::Hooks::kP61KillResume,     kKillResumeOrig, 2 },
        { 0x00564B92,                     kKillLoopJmp,    5 },
    };
    if (!VerifyAllSites(kSec, sites, 10))
    {
        return PatchResult::Mismatch;
    }

    // ★ fix2 (НИЗК-7): детур SetConnectFlag — ПЕРВЫМ (без него recv/send на переиспользованном слоте получили бы чужую
    //   сессию); при сбое любой записи уже записанные площадки возвращаются к оригинальным байтам — сток целиком.
    struct W { DWORD va; const unsigned char* orig; bool jmp; void* to; };
    const W writes[] = {
        { Srv::Hooks::kP61SetConnEntry,   kSetConnOrig,   true,  (void*)&P61_SetConnTramp },
        { Srv::Hooks::kP61DisConnect, kDiscOrig, true, (void*)&P61_DiscTramp },   // ★ fix2b
        { Srv::Hooks::kP61RecvClientCall, kRecvCallOrig,  false, (void*)&P61_RecvTramp },
        { Srv::Hooks::kP61SendCallA,      kSendCallAOrig, false, (void*)&P61_SendTramp },
        { Srv::Hooks::kP61SendCallB,      kSendCallBOrig, false, (void*)&P61_SendTramp },
        { Srv::Hooks::kP61SendCallC,      kSendCallCOrig, false, (void*)&P61_SendTramp },
    };
    int ok = 0;
    for (; ok < 6; ++ok)
    {
        const W& w = writes[ok];
        if (!(w.jmp ? Hook::WriteJmp(w.va, w.to, 5) : Hook::WriteCall(w.va, w.to, 5))) { break; }
    }
    if (ok != 6)
    {
        int back = 0;
        for (int i = ok - 1; i >= 0; --i) { if (Hook::WriteBytes(writes[i].va, writes[i].orig, 5)) { ++back; } }
        Log::Line(L"    P61: [ОШИБКА] запись площадки %d из 6 (0x%08X) не прошла — возвращено к оригиналу %d из %d записанных; сток",
                  ok + 1, writes[ok].va, back, ok);
        return PatchResult::Failed;
    }
    g_setConnPlaced = true;   // ★ P73: детур SetConnectFlag стоит — мост EAC зовётся из P61_ResetSlotC, своего на 0x562910 не ставит

    Log::Line(L"    P61: прослойка шифрования установлена (recv+3xsend+SetConnectFlag+DisConnect); ключ %s (104 б, ASDAKEY1); старый клиент %s",
              keyFile, allowLegacy ? L"разрешён (переход)" : L"ЗАПРЕЩЁН");
    Log::Line(L"    P61: нарушение канала → %s; строк PatchLog не больше %d/мин; журнал ac.other 56–59, 61 (через P53)",
              killOnBad ? L"РАЗРЫВ штатным DisConnect" : L"кадр отбрасывается (KillOnViolation=0)", logPerMin);
    Log::Line(L"    P61: кадры сервера до рукопожатия — в очередь слота (не больше %d КБ), сразу за ServerHello / как есть старому клиенту; "
              L"DisConnect при невыданной очереди отложен до первых байт клиента, не дольше %d мс, после выдачи — пауза %d мс", preKB, preCloseMs, lingerMs);
    Log::Line(L"    P61: кадр шифрования не больше 0x1000 б (открытый текст ≤ 4068 на кадр — буфер записи Ciocp::Send), приём стоку — кусками ≤ 4087 б");
    Log::Line(L"    P61: досылка стока полна (0x9F9C) — шифрованные кадры ждут в очереди слота (не больше %d КБ на слот и %d МБ на все слоты, "
              L"выталкивает сторож); отказ стокового Send / переполнение очереди / общий предел / нехватка памяти — разрыв, журнал ac.other 61",
              txKB, txTotMB);
    Log::Line(L"    P61: общий предел очередей — справедливая доля: слот с очередью ≥ средней или ≥ %d КБ рвётся сам (причина 4), иначе кадр "
              L"принимается до предела + 1/8, а сторож вытесняет наибольшую очередь (причина 6)", fairKB);
    Log::Line(L"    P61: рукопожатие — ключ подписи %s, пул пар ECDH %d (%s); ключи только в памяти процесса", hsCache ? L"импортируется один раз" : L"импортируется на каждое рукопожатие",
              hsPool, hsPool ? L"фоновая нить, каждая пара одноразовая" : L"выкл — пара на месте");
    Log::Line(L"    P61: допуск до рукопожатия — с адреса не больше %d подключений за %d с (вид 63), незавершённых рукопожатий не больше %d, с одного адреса — %d (вид 64), "
              L"срок рукопожатия %d мс (вид 65%s); сверх — разрыв штатным DisConnect до рукопожатия, PatchLog «[допуск]», журнал ac.other 63–65 "
              L"(64/65 — не чаще раза в %d мс)", perIpMax, perIpWin, maxPend, maxPendIp, hsDeadline,
              allowLegacy ? L"; молчащий сокет при AllowLegacy=1 не рвётся, но по сроку снимается со счёта незавершённых" : L"", admGap);
    Log::Line(L"    P61: CNG/ключ загрузятся лениво при первом соединении (строка «CNG открыт, ключ загружен»)");
    return PatchResult::Applied;
}
