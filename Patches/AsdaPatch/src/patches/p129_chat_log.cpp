// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P129 — ЖУРНАЛ ЧАТА И ЗАГЛУШКА (шаг А6.12 админ-центра, 22.11.2026; решение владельца 22.11, ADMIN_TOOL_PLAN.md §6 п.5). [ПОРТ]
//  Документ: AstoryServer/Docs/GameServer/chat-log-p129.md; отчёт: Reports/admin_center/impl_a612_chat_20261122.md.
//
//  ── ЧТО В СТОКЕ (реверс, отчёт §1) ──
//   Журнала чата нет. Сток его задумал: GameServer шлёт запись 3670 (5084/5086) в RelayServer, тот её разбирает (RelayServer.c:5902
//   sub_40A260 → sub_40A1CF) и зовёт EXEC UPUserChat — как и для шёпота 3105 / отряда 3107 (sub_4014CB/sub_40198B). Процедуры
//   UPUserChat нет ни в одной базе, поэтому ничего не пишется (★ ревизия 60 Н-2: прежде здесь было «3670 не разбирает»). Если её
//   завести, сток начнёт писать второй журнал параллельно P129. Заглушки нет.
//   Все каналы чата клиента входят в GameServer одним диспетчером sub_42A9D0 (опкоды ниже, адреса — kChannels), шёпот / отряд /
//   клан GameServer пересылает в RelayServer (3105 / 3107 / 4121) — значит, отправителя и текст видно на GameServer отправителя.
//   ChannelManager текста не видит (только разводит 5087 крика предметом по каналам, ChannelManager.c sub_4042C7).
//
//  ── ЧТО ДЕЛАЕТ ──
//   1. Общая точка гейта P47 (стаб 0x42AB4F, до switch; P47_OperatorGate → после P55/P64/P69) зовёт P129_ChatGate: для опкода
//      чата — разобрать текст по разметке обработчика стока, отправителя — по подтверждённой сессии (P69_ResolveSession:
//      учётка сессии, у соулмейта — iMateUserIndex), поставить событие в очередь ChatJournal (без ожидания) и проверить кэш заглушек.
//      Заглушка и Mode=1 — 0 (обработчик не зовётся, текст никому не уходит) + нотис 3113 игроку; Mode=0 — только пометка в журнале.
//   2. Крик предметом (FunctionItem 0x31/0x32). ★ ревизия 60 Н-5: отказ — ДО расхода. Предмет списывает DBManager по запросу из
//      Char_FunctionItem_Use@0x4ED780 (клиент 5450); ответ БД разбирает sub_4EF270 («[DB_RECV] SendChar_FunctionItem_Use»,
//      GameServer.c:92264) и лишь затем кричит sub_4F5F30. Поэтому заглушка проверяется в ЗАПРОСЕ — общая точка P121 (0x4EDEB3,
//      категория +8 до switch; текст запроса v88[55] = [ebp-0x1C9], CUserManager [ebp-0x2F8], слот [ebp+8]): заглушка и Mode=1 →
//      штатный отказ стока 0x4EF0C3 (5451 с кодом RefuseCode P121, в DBManager ничего не уходит — предмет цел) + нотис 3113.
//      Площадки call sub_4F5F30 @0x4F0C6D / @0x4F0C88 (ответ БД) только пишут журнал разосланного крика и никогда не отказывают:
//      там предмет уже списан.
//   Гейт чата стока (sub_52EEA0, SoulState CUser+0x182D3 == 1) у опкодов 5084/5086/5088/5105/6316 повторён: такой текст сток не
//   рассылает — в журнал не идёт.
//  Откат: [P129_ChatLog] Enabled=0 — гейт возвращает 1 сразу, площадки крика не ставятся.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../ChatJournal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int __stdcall P129_OnShout(void* mgr, int userNum, const char* text, int kind);   // из ShoutStub (ниже)

namespace
{
    const wchar_t* kSec = L"P129_ChatLog";

    constexpr int  kSlots       = 0x226;     // userNum 0…549
    constexpr int  kOffThread   = 4;         // CUserManager+4 → поток карты
    constexpr int  kOffMapIdx   = 0x4950;    // поток+0x4950 → номер карты (как гейт 5084 стока: 236 * [[mgr+4]+18768])
    constexpr int  kOffName     = 0x178;     // CUser: имя персонажа, 20 б (sub_532570)
    constexpr int  kTextHard    = 199;       // потолок текста (RelayServer, P14 kMaxTextHard)
    constexpr int  kTextFixed   = 80;        // поля фиксированной длины (6718 / 6313 / крик предметом)
    constexpr int  kNoticeBody  = 107;       // тело 3113 (sendNoticeClient копирует 107 б)
    constexpr int  kNoticeText  = 95;        // байт текста 3113 (+4…+98, +99 — ноль)
    constexpr DWORD kShoutFn    = 0x004F5F30;   // sub_4F5F30 — крик предметом (Send_FuncItem_Shout → RelayServer 5087)
    constexpr DWORD kGateSite   = 0x0042AB4F;   // площадка стаба P47 (должен стоять jmp)
    constexpr int  kOpShoutItem = 5450;      // опкод применения функционального предмета (запись журнала крика)

    typedef BOOL (__fastcall *PFN_IsChatBlocked)(void* mgr, void* edx, short idx);    // sub_52EEA0
    typedef int  (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, const void* buf, int a6, int a7); // sub_4C28F0
    PFN_IsChatBlocked const pIsChatBlocked = (PFN_IsChatBlocked)Srv::kIsChatBlocked;
    PFN_ToClient      const pToClient      = (PFN_ToClient)Srv::kSendPacket;

    // ── настройки ──
    volatile LONG g_on       = 0;        // гейт работает
    int     g_mode           = 0;        // 0 — только журнал; 1 — заглушка действует
    DWORD   g_logMask        = 0x7FE;    // LogChannelMask — каналы журнала (бит = 1 << код канала)
    DWORD   g_muteMask       = 0x7FE;    // MuteChannelMask — каналы, на которые действует заглушка
    bool    g_exemptGm       = true;     // ExemptOperators — GM-флаг не глушится
    int     g_noticeMode     = 101;      // NoticeMode — режим 3113 (101 — новый клиент: loc + минуты atoi(текст); 0 — баннер текстом)
    int     g_noticeCp       = 1251;     // NoticeCodePage — кодировка текста нотиса
    int     g_noticeSec      = 3;        // NoticeIntervalSec — не чаще раза в N с одному слоту
    BYTE    g_rgb[3]         = { 0xFF, 0x50, 0x50 };   // NoticeRgb
    wchar_t g_noticeTpl[256] = L"";      // NoticeText (пусто — встроенный)
    bool    g_runtimeLog     = true;     // RuntimeLog — строки [P129] отказа в PatchLog (с ограничителем)
    bool    g_shoutHook      = true;     // ShoutItemHook — площадки крика предметом
    bool    g_logOn          = false;    // журнал принимает события (ChatJournal LogEnabled)

    // ★ встроенный текст нотиса: число минут ПЕРВЫМ (режим 101 — клиент Astory следующего выпуска берёт atoi(текст), как режим 100
    //   эталона uiNoticeUpdate3Line_BC90), дальше — текст для клиента прежней версии (у него неизвестный режим = только строка в ленте).
    const wchar_t* kNoticeDefault = L"{min} мин. — чат заблокирован до {until} / Chat muted until {until}";

    volatile LONG g_noticeTick[kSlots] = {};   // когда слоту последний раз слали нотис (GetTickCount, 0 — не слали)

    struct Stats
    {
        LONG seen;        // чат-событий разобрано
        LONG logged;      // поставлено в журнал
        LONG refused;     // отказано (Mode=1)
        LONG wouldRefuse; // заглушка есть, Mode=0
        LONG notices;     // нотисов 3113 отправлено
        LONG blockedStock;// гейт стока sub_52EEA0 — не в журнал
        LONG shouts;      // крик предметом разобран
        LONG faults;      // исключений (поймано)
        LONG logLines;    // строк PatchLog об отказах
        LONG shoutRefusedBeforeUse; // ★ ревизия 60 Н-5: крик предметом отклонён в запросе (предмет цел)
    } g_stats = {};

    // Разметка канала по обработчику стока (адреса — живой GameServer.exe e7b4ac38, сверены stand_p129).
    struct ChanSpec
    {
        int  opcode;      // опкод клиента
        BYTE channel;     // ChatJournal::Channel
        int  textOff;     // смещение текста от начала кадра (0xFB)
        int  lenSub;      // длина текста = размер кадра − lenSub (0 — поле фиксированной длины kTextFixed)
        bool stockGate;   // диспетчер зовёт обработчик только при !sub_52EEA0
        int  subOff;      // смещение байта подканала (−1 — нет)
        int  targetOff;   // смещение имени адресата 20 б (−1 — нет)
        int  targetNumOff;// смещение WORD userNum адресата (−1 — нет)
    };
    const ChanSpec kChannels[] =
    {
        // 5084 Recv_NormalChatClient@0x5471A0 (call 0x42BBB9): memcpy(text, pkt+9, packetLen-10)          GameServer.c:125057
        { 5084, ChatJournal::kChNormal,      9, 10, true,  -1, -1, -1 },
        // 5086 recvGlobalChatClient@0x547670 (call 0x42BC0C): заголовок 27 б с +9, текст pkt+36, (len-10)-27; байт +11 — флаг
        { 5086, ChatJournal::kChGlobal,     36, 37, true,  11, -1, -1 },
        // 6560 (P13, вне дерева switch): +9 тип канала, текст +10, bodyLen-1; ★ ревизия 60 М-1: P13 сам отвергает при sub_52EEA0
        //   (p13_chat_wide_channels_6560.cpp:172) — гейт стока повторён
        { 6560, ChatJournal::kChWide,       10, 11, true,   9, -1, -1 },
        // 5088 sub_547BD0 (call 0x42BC5F): v19 = pkt[9] (вид), имя адресата pkt+10 (20 б), текст pkt+30, a3-31   GameServer.c:125286
        { 5088, ChatJournal::kChWhisper,    30, 31, true,   9, 10, -1 },
        // 5105 sub_450FB0 (call 0x42C246): 2 б с +9, текст pkt+11, a3-12                                        GameServer.c:32610
        { 5105, ChatJournal::kChParty,      11, 12, true,  -1, -1, -1 },
        // 4120 sub_403F50 (call 0x42B54E): текст pkt+37, (a3-10)-28                                             GameServer.c:1537
        { 4120, ChatJournal::kChClan,       37, 38, false, -1, -1, -1 },
        // 6718 User_Game_RegistCancel_2@0x466F50 (call 0x42E7D5): тело 0x6C с +33, текст v6[7] = pkt+61, 80 б    GameServer.c:42015
        { 6718, ChatJournal::kChArmy,       61,  0, false, -1, -1, -1 },
        // 6313 Recv_SelfStoreChatClient@0x507930 (call 0x42E5E2): тело 0x6A с +33, хозяин лавки WORD +37, текст +59, 80 б
        { 6313, ChatJournal::kChStore,      59,  0, false, -1, -1, 37 },
        // 6316 Recv_SelfStoreGlobalChat@0x508B40 (call 0x42E635): текст pkt+36, (a3-10)-27                     GameServer.c:102024
        { 6316, ChatJournal::kChStoreShout, 36, 37, true,  -1, -1, -1 },
    };

    const ChanSpec* FindSpec(int opcode)
    {
        switch (opcode)
        {
        case 5084: return &kChannels[0];
        case 5086: return &kChannels[1];
        case 6560: return &kChannels[2];
        case 5088: return &kChannels[3];
        case 5105: return &kChannels[4];
        case 4120: return &kChannels[5];
        case 6718: return &kChannels[6];
        case 6313: return &kChannels[7];
        case 6316: return &kChannels[8];
        }
        return nullptr;
    }

    __int64 NowFt() { FILETIME f; GetSystemTimeAsFileTime(&f); return ((__int64)f.dwHighDateTime << 32) | f.dwLowDateTime; }

    // Копия строки сервера / пакета до нуля или предела (память может быть мусорной — SEH у вызывающего).
    int CopyZ(char* dst, int cap, const BYTE* src, int max)
    {
        int i = 0;
        for (; i < max && i < cap - 1 && src[i]; ++i) { dst[i] = (char)src[i]; }
        dst[i] = 0;
        return i;
    }

    // Текст нотиса заглушки по шаблону: {min} — минут осталось (вверх), {until} — местное время конца «дд.мм.гг чч:мм».
    int BuildNotice(BYTE* body, __int64 untilFt, __int64 nowFt)
    {
        memset(body, 0, kNoticeBody);
        *(WORD*)(body + 2) = (WORD)g_noticeMode;
        __int64 mins = (untilFt - nowFt + 600000000LL - 1) / 600000000LL;   // 1 мин = 6e8 сотен нс, округление вверх
        if (mins < 1) { mins = 1; }
        FILETIME f; f.dwLowDateTime = (DWORD)untilFt; f.dwHighDateTime = (DWORD)(untilFt >> 32);
        SYSTEMTIME u = {}, l = {};
        FileTimeToSystemTime(&f, &u);
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &u, &l)) { l = u; }
        wchar_t sMin[24], sUntil[24];
        _snwprintf_s(sMin, _TRUNCATE, L"%I64d", mins);
        _snwprintf_s(sUntil, _TRUNCATE, L"%02d.%02d.%02d %02d:%02d", l.wDay, l.wMonth, l.wYear % 100, l.wHour, l.wMinute);
        const wchar_t* tpl = g_noticeTpl[0] ? g_noticeTpl : kNoticeDefault;
        wchar_t out[512]; int k = 0;
        for (const wchar_t* p = tpl; *p && k < ARRAYSIZE(out) - 32; )
        {
            if (!wcsncmp(p, L"{min}", 5))        { for (const wchar_t* s = sMin; *s; ++s) { out[k++] = *s; } p += 5; }
            else if (!wcsncmp(p, L"{until}", 7)) { for (const wchar_t* s = sUntil; *s; ++s) { out[k++] = *s; } p += 7; }
            else { out[k++] = *p++; }
        }
        out[k] = 0;
        // ★ ревизия 60 М-3: преобразование в достаточный буфер и обрезка по 95 б (раньше длинный шаблон давал пустой нотис —
        //   ERROR_INSUFFICIENT_BUFFER); кодовая страница проверена при установке (только однобайтные).
        char tmp[1024];
        int n = WideCharToMultiByte(g_noticeCp, 0, out, -1, tmp, sizeof(tmp), "?", nullptr);
        if (n <= 0) { n = WideCharToMultiByte(1251, 0, out, -1, tmp, sizeof(tmp), "?", nullptr); }
        if (n <= 0) { tmp[0] = 0; n = 1; }
        int len = n - 1; if (len > kNoticeText) { len = kNoticeText; }
        memcpy(body + 4, tmp, len);
        body[4 + len] = 0;
        body[4 + kNoticeText] = 0;                                   // +99 — гарантированный ноль
        body[100] = g_rgb[0]; body[101] = g_rgb[1]; body[102] = g_rgb[2];
        return n;
    }

    void SendNotice(void* mgr, int userNum, __int64 untilFt, __int64 nowFt)
    {
        if (userNum < 0 || userNum >= kSlots) { return; }
        const DWORD t = GetTickCount() ? GetTickCount() : 1;
        const DWORD last = (DWORD)g_noticeTick[userNum];
        if (last != 0 && (DWORD)(t - last) < (DWORD)g_noticeSec * 1000u) { return; }
        InterlockedExchange(&g_noticeTick[userNum], (LONG)t);
        BYTE body[kNoticeBody];
        BuildNotice(body, untilFt, nowFt);
        __try
        {
            BYTE* thread = *(BYTE**)((BYTE*)mgr + kOffThread);
            if (thread) { pToClient(thread, nullptr, 3113, kNoticeBody, userNum, body, 0, 1); InterlockedIncrement(&g_stats.notices); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    }

    // Политика Decide: обычный гейт (журнал + отказ), только отказ (запрос крика — журнал лишь при отказе), без отказа (ответ БД крика).
    enum Policy { kPolGate = 0, kPolRefuseOnly = 1, kPolNoRefuse = 2 };

    // Общая часть: сессия, заглушка, событие. text/len — уже вырезанный текст. → 1 пропустить, 0 отказать.
    int Decide(void* mgr, int opcode, int userNum, BYTE channel, BYTE sub, const BYTE* text, int len,
               const BYTE* target, int targetNum, int policy = kPolGate)
    {
        const DWORD bit = 1u << channel;
        const bool doLog = (g_logMask & bit) != 0 && g_logOn;
        const bool doMute = (g_muteMask & bit) != 0;
        if (!doLog && !doMute) { return 1; }
        if (policy == kPolRefuseOnly && (!doMute || g_mode != 1)) { return 1; }

        P69_Session s;
        P69_ResolveSession(mgr, userNum, &s);

        ChatJournal::Event e;
        ChatJournal::Clear(e);
        e.opcode = opcode; e.userNum = (short)userNum; e.channel = channel; e.sub = sub;
        e.account  = s.account > 0 ? s.account : ChatJournal::kNone;
        e.owner    = s.owner > 0 ? s.owner : ChatJournal::kNone;
        e.charSlot = s.charSlot >= 0 ? s.charSlot : ChatJournal::kNone;
        e.sessState = s.state >= 0 ? (BYTE)s.state : 0xFF;
        e.gm = s.gm ? 1 : 0;
        e.targetNum = targetNum;
        __try
        {
            if (s.user) { CopyZ(e.name, sizeof(e.name), s.user + kOffName, ChatJournal::kNameMax); }
            if (target) { CopyZ(e.target, sizeof(e.target), target, ChatJournal::kNameMax); }
            BYTE* thread = *(BYTE**)((BYTE*)mgr + kOffThread);
            if (thread) { e.mapIndex = *(const int*)(thread + kOffMapIdx); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
        if (len > ChatJournal::kTextMax) { len = ChatJournal::kTextMax; }
        memcpy(e.text, text, len);
        e.textLen = (BYTE)len;

        // заглушка (кэш, без запроса к базе)
        int result = 1;
        ChatJournal::MuteRow m = {};
        const __int64 now = NowFt();
        const bool muted = doMute && !(s.gm && g_exemptGm) && ChatJournal::FindMute(s.account, s.owner, s.charSlot, now, &m);
        if (policy == kPolRefuseOnly && !muted) { return 1; }   // запрос крика без заглушки — журнал напишет ответ БД
        if (muted)
        {
            e.muteId = m.id;
            if (g_mode == 1 && policy != kPolNoRefuse)
            {
                e.muteState = 1;
                result = 0;
                InterlockedIncrement(&g_stats.refused);
                SendNotice(mgr, userNum, m.untilFt, now);
            }
            else
            {
                e.muteState = 2;
                InterlockedIncrement(&g_stats.wouldRefuse);
            }
            if (g_runtimeLog)
            {
                const LONG c = InterlockedIncrement(&g_stats.logLines);
                if (c <= 50 || (c % 500) == 0)
                {
                    Log::Line(L"[P129] %s: заглушка %I64d — учётка %d, персонаж %d/%d, слот %d, опкод %d (строк всего %d)",
                              g_mode == 1 ? L"ОТКАЗ" : L"был бы отказ (Mode=0)", m.id, s.account, s.owner, s.charSlot, userNum, opcode, (int)c);
                }
            }
        }
        if (doLog && ChatJournal::Push(e)) { InterlockedIncrement(&g_stats.logged); }
        return result;
    }

    // ── крик предметом: стаб на месте call sub_4F5F30 (thiscall: ecx = CUserManager, [esp+4] idx, [esp+8] текст, [esp+0xC] вид) ──
    DWORD g_shoutOrig = kShoutFn;
    __declspec(naked) void ShoutStub()
    {
        __asm
        {
            push  ecx                                // сохранить this
            push  dword ptr [esp+0x10]               // вид (1/2)
            push  dword ptr [esp+0x10]               // текст
            push  dword ptr [esp+0x10]               // idx
            push  ecx                                // CUserManager
            call  P129_OnShout                       // __stdcall, 16 б; eax: 1 — рассылать (★ ревизия 60 Н-5: отказа здесь нет)
            pop   ecx
            test  eax, eax
            jz    s_drop
            jmp   dword ptr [g_shoutOrig]            // сток: стек и ecx как у исходного вызова
        s_drop:
            xor   eax, eax
            ret   0x0C                               // thiscall: вызываемый снимает 3 аргумента
        }
    }

    // площадки крика: mov ecx,[ebp-0x288] + call sub_4F5F30 (11 б сверяются, пишутся 5 б call)
    const BYTE kShoutA[11] = { 0x8B, 0x8D, 0x78, 0xFD, 0xFF, 0xFF, 0xE8, 0xBE, 0x52, 0x00, 0x00 };   // 0x4F0C67 / call @0x4F0C6D
    const BYTE kShoutB[11] = { 0x8B, 0x8D, 0x78, 0xFD, 0xFF, 0xFF, 0xE8, 0xA3, 0x52, 0x00, 0x00 };   // 0x4F0C82 / call @0x4F0C88
    constexpr DWORD kShoutSiteA = 0x004F0C6D, kShoutSiteB = 0x004F0C88;
    bool g_shoutPlaced = false;
}

// ── гейт: общая точка P47_OperatorGate (после P55/P64/P69). 1 — пропустить в switch, 0 — обработчик не вызывать ──
int P129_ChatGate(void* mgr, int opcode, int userNum, const BYTE* pkt)
{
    if (!g_on || !mgr || !pkt) { return 1; }
    const ChanSpec* c = FindSpec(opcode);
    if (!c) { return 1; }
    if (userNum < 0 || userNum >= kSlots) { return 1; }
    int r = 1;
    __try
    {
        WORD size = 0; memcpy(&size, pkt + 1, 2);                 // размер кадра (= packetLen обработчика)
        int len = c->lenSub ? (int)(short)size - c->lenSub : kTextFixed;
        if (len > kTextHard) { len = kTextHard; }
        if (len <= 0) { return 1; }                               // сток такой текст отвергает — не в журнал
        const BYTE* text = pkt + c->textOff;
        int n = 0; while (n < len && text[n]) { ++n; }
        if (n <= 0) { return 1; }
        if (c->stockGate && pIsChatBlocked(mgr, nullptr, (short)userNum)) { InterlockedIncrement(&g_stats.blockedStock); return 1; }
        InterlockedIncrement(&g_stats.seen);
        const BYTE sub = c->subOff >= 0 ? pkt[c->subOff] : 0xFF;
        const int tnum = c->targetNumOff >= 0 ? (int)*(const short*)(pkt + c->targetNumOff) : ChatJournal::kNone;
        r = Decide(mgr, opcode, userNum, c->channel, sub, text, n, c->targetOff >= 0 ? pkt + c->targetOff : nullptr, tnum);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); r = 1; }
    return r;
}

// ── крик предметом, ответ БД (из ShoutStub): только журнал (предмет уже списан — отказывать нельзя). Всегда 1 ──
extern "C" int __stdcall P129_OnShout(void* mgr, int userNum, const char* text, int kind)
{
    if (!g_on || !mgr || !text) { return 1; }
    userNum = (short)userNum;
    if (userNum < 0 || userNum >= kSlots) { return 1; }
    int r = 1;
    __try
    {
        int n = 0; while (n < kTextFixed - 1 && text[n]) { ++n; }   // сток: strlen < 80 (sub_4F5F30)
        if (n <= 0) { return 1; }
        InterlockedIncrement(&g_stats.shouts);
        InterlockedIncrement(&g_stats.seen);
        r = Decide(mgr, kOpShoutItem, userNum, ChatJournal::kChShoutItem, (BYTE)kind, (const BYTE*)text, n, nullptr, ChatJournal::kNone,
                   kPolNoRefuse);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); r = 1; }
    return r;
}

// ── крик предметом, ЗАПРОС клиента 5450 (из P121_Gate, категории 0x31/0x32; ebp — кадр Char_FunctionItem_Use@0x4ED780) ──
//   1 — заглушка при Mode=1: отказ стока 5451 до расхода предмета (+ нотис 3113, строка журнала mute_state=1); 0 — сток.
//   Подпись MD5 и анти-повтор пакета уже проверены стоком (площадка 0x4EDEB3 — после них, перед switch по категории).
extern "C" int __stdcall P129_ShoutRequestGate(BYTE* ebp)
{
    if (!g_on || !g_shoutHook || g_mode != 1 || !ebp) { return 0; }
    int r = 1;
    __try
    {
        void* mgr = *(void**)(ebp - 0x2F8);                       // mov [ebp-2F8h], ecx (0x4ED795)
        const int userNum = *(const short*)(ebp + 8);             // arg0 — слот
        const char* text = (const char*)(ebp - 0x200 + 55);       // v88[55] — текст крика (case 0x31/0x32: strlen(&v88[55]))
        if (!mgr || userNum < 0 || userNum >= kSlots) { return 0; }
        int n = 0; while (n < kTextFixed - 1 && text[n]) { ++n; }
        if (n <= 0) { return 0; }                                 // пустой — сток сам отвергнет (код 24 «NoMessege»)
        // ★ ревизия 62 М-3: подканал = вид крика, как в ответе БД: sub_4EF270 (GameServer.c:92656) зовёт sub_4F5F30 с видом 2, если
        //   WORD Function_Table +9 строки предмета == 1, иначе 1; код предмета из сумки — [ebp-0x204] (по нему же берётся категория
        //   на площадке 0x4EDEA8). Таблица недоступна — подканал пуст.
        BYTE kind = 0xFF;
        __try
        {
            const int code = *(const int*)(ebp - 0x204);
            const BYTE* tbl = *(BYTE* const*)0x005F5E70;
            if (tbl && code > 0) { kind = *(const WORD*)(tbl + 48 * (code - 1) + 9) == 1 ? 2 : 1; }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { kind = 0xFF; }
        r = Decide(mgr, kOpShoutItem, userNum, ChatJournal::kChShoutItem, kind, (const BYTE*)text, n, nullptr, ChatJournal::kNone,
                   kPolRefuseOnly);
        if (r == 0) { InterlockedIncrement(&g_stats.shoutRefusedBeforeUse); }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); r = 1; }
    return r == 0 ? 1 : 0;
}

bool P129_ShoutGateWanted()
{
    return Config::GetBool(kSec, L"Enabled", true) && Config::GetBool(kSec, L"ShoutItemHook", true);
}

bool P129_GateWanted()
{
    return Config::GetBool(kSec, L"Enabled", true);
}

// Статистика (стенд, PatchLog).
extern "C" __declspec(dllexport) void __stdcall P129_GetStats(LONG* out12)
{
    if (!out12) { return; }
    ChatJournal::Stats j; ChatJournal::GetStats(&j);
    out12[0] = g_stats.seen; out12[1] = g_stats.logged; out12[2] = g_stats.refused; out12[3] = g_stats.wouldRefuse;
    out12[4] = g_stats.notices; out12[5] = g_stats.blockedStock; out12[6] = g_stats.shouts; out12[7] = g_stats.faults;
    out12[8] = j.pushed; out12[9] = j.dropped; out12[10] = j.writtenDb; out12[11] = j.writtenFile;
}

#ifdef ASDA_PATCH_STAND
// ── только стендовая сборка (/DASDA_PATCH_STAND) ──
extern "C" int __stdcall P47_OperatorGate(void* mgr, int opcode, int userNum, const BYTE* pkt);
// Настоящая цепочка гейта P47 (P55 → P64 → P69 → P129 → операторский гейт), как её зовёт стаб 0x42AB4F.
extern "C" __declspec(dllexport) int __stdcall P129_TestGate(void* mgr, int opcode, int userNum, const BYTE* pkt)
{
    return P47_OperatorGate(mgr, opcode, userNum, pkt);
}
// Подменить кэш заглушек: rows — тройки {scope, userIndex, charSlot}, minutes — срок от «сейчас», id = 1000 + i.
extern "C" __declspec(dllexport) void __stdcall P129_TestSetMutes(const int* rows, int n, int minutes)
{
    ChatJournal::MuteRow m[64];
    if (n > 64) { n = 64; }
    const __int64 now = NowFt();
    for (int i = 0; i < n; ++i)
    {
        m[i].scope = (BYTE)rows[i * 3]; m[i].userIndex = rows[i * 3 + 1]; m[i].charSlot = rows[i * 3 + 2];
        m[i].id = 1000 + i; m[i].untilFt = now + (__int64)minutes * 600000000LL;
    }
    ChatJournal::TestSetMutes(m, n);
}
extern "C" __declspec(dllexport) void __stdcall P129_TestJournalStats(LONG* out12)
{
    ChatJournal::Stats j; ChatJournal::GetStats(&j);
    out12[0] = j.pushed; out12[1] = j.dropped; out12[2] = j.writtenDb; out12[3] = j.writtenFile; out12[4] = j.dbErrors;
    out12[5] = j.queued; out12[6] = j.fileSkipped; out12[7] = j.muteRows; out12[8] = j.muteLoads; out12[9] = j.muteErrors;
    out12[10] = j.purges; out12[11] = j.dbUp ? 1 : 0;
}
extern "C" __declspec(dllexport) void __stdcall P129_TestKick() { ChatJournal::Kick(); }
extern "C" __declspec(dllexport) void __stdcall P129_TestResetNotice() { for (int i = 0; i < kSlots; ++i) { g_noticeTick[i] = 0; } }
// ★ ревизия 60 Н-5: отказов крика в запросе
extern "C" __declspec(dllexport) LONG __stdcall P129_TestShoutRefused() { return g_stats.shoutRefusedBeforeUse; }
// ★ ревизия 60 Н-5: настоящая общая точка P121_Gate (как её зовёт заглушка 0x4EDEB3) с поддельным кадром Char_FunctionItem_Use
extern "C" __declspec(dllexport) int __stdcall P129_TestShoutRequest(BYTE* ebp, int cat) { return P121_Gate(ebp, cat); }
#endif

PatchResult P129_ChatLog()
{
    InterlockedExchange(&g_on, 0);
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode       = Config::GetInt(kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_logMask    = (DWORD)Config::GetInt(kSec, L"LogChannelMask", 0x7FE) & 0x7FEu;
    g_muteMask   = (DWORD)Config::GetInt(kSec, L"MuteChannelMask", 0x7FE) & 0x7FEu;
    g_exemptGm   = Config::GetBool(kSec, L"ExemptOperators", true);
    g_noticeMode = Config::GetInt(kSec, L"NoticeMode", 101) & 0xFFFF;
    g_noticeCp   = Config::GetInt(kSec, L"NoticeCodePage", 1251);
    {
        // ★ ревизия 60 М-3: только однобайтная кодовая страница (клиент читает текст 3113 как cp1251/гибрид); иначе — 1251
        CPINFO ci = {};
        if (!GetCPInfo((UINT)g_noticeCp, &ci) || ci.MaxCharSize != 1)
        {
            Log::Line(L"    P129: NoticeCodePage=%d не однобайтная или неизвестна — взята 1251", g_noticeCp);
            g_noticeCp = 1251;
        }
    }
    g_noticeSec  = Config::GetInt(kSec, L"NoticeIntervalSec", 3);
    if (g_noticeSec < 0)    { g_noticeSec = 0; }
    if (g_noticeSec > 3600) { g_noticeSec = 3600; }
    g_runtimeLog = Config::GetBool(kSec, L"RuntimeLog", true);
    g_shoutHook  = Config::GetBool(kSec, L"ShoutItemHook", true);
    Config::GetStr(kSec, L"NoticeText", L"", g_noticeTpl, ARRAYSIZE(g_noticeTpl));
    {
        wchar_t rgb[16]; Config::GetStr(kSec, L"NoticeRgb", L"FF5050", rgb, ARRAYSIZE(rgb));
        const DWORD v = wcstoul(rgb, nullptr, 16);
        g_rgb[0] = (BYTE)(v >> 16); g_rgb[1] = (BYTE)(v >> 8); g_rgb[2] = (BYTE)v;
    }

    // Зависимость: стаб гейта ставит P47 (площадка 0x42AB4F) — как у P55.
    if (!Config::GetBool(L"P47_IdentityOperatorGate", L"Enabled", true))
    {
        Log::Line(L"    P129: [P47_IdentityOperatorGate] Enabled=0 — стаб гейта 0x42AB4F не стоит, журнал и заглушка чата НЕ работают");
        return PatchResult::Failed;
    }
    BYTE first = 0;
    __try { first = *(const BYTE*)kGateSite; } __except (EXCEPTION_EXECUTE_HANDLER) { first = 0; }
    if (first != 0xE9)
    {
        Log::Line(L"    P129: на 0x%08X нет jmp стаба P47 (байт 0x%02X) — журнал и заглушка чата НЕ работают", kGateSite, first);
        return PatchResult::Failed;
    }

    // площадки крика предметом — сверка до записи
    if (g_shoutHook && !g_shoutPlaced)
    {
        const Site sites[] = { { kShoutSiteA - 6, kShoutA, sizeof(kShoutA) }, { kShoutSiteB - 6, kShoutB, sizeof(kShoutB) } };
        if (!VerifyAllSites(L"P129", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    }

    const int js = ChatJournal::Start();
    if (js == 3)
    {
        Log::Line(L"    P129: журнал чата не запущен (очередь/поток не созданы) — патч не ставится");
        return PatchResult::Failed;
    }
    g_logOn = js == 0;

    if (g_shoutHook && !g_shoutPlaced)
    {
        if (!Hook::WriteCall(kShoutSiteA, &ShoutStub, 5)) { return PatchResult::Failed; }
        if (!Hook::WriteCall(kShoutSiteB, &ShoutStub, 5)) { return PatchResult::Failed; }
        g_shoutPlaced = true;
    }
    InterlockedExchange(&g_on, 1);
    // ★ ревизия 60 Н-5: отказ крику до расхода — через общую точку P121 0x4EDEB3 (P121 ставит её и при своём Enabled=0)
    BYTE p121 = 0;
    __try { p121 = *(const BYTE*)0x004EDEB3; } __except (EXCEPTION_EXECUTE_HANDLER) { p121 = 0; }
    if (g_shoutHook && p121 != 0xE9)
    {
        Log::Line(L"    P129: ★ площадки P121 0x4EDEB3 нет (байт 0x%02X) — крик предметом под заглушкой НЕ отклоняется (предмет тратить "
                  L"нельзя: только журнал mute_state=2)", p121);
    }

    Log::Line(L"    P129: журнал и заглушка чата — Mode=%d (%s), каналы журнала 0x%X, заглушки 0x%X, GM %s, нотис 3113 режим %d "
              L"(не чаще раза в %d с), крик предметом %s; точка — гейт P47 0x42AB4F (5084/5086/6560/5088/5105/4120/6718/6313/6316)",
              g_mode, g_mode == 1 ? L"заглушка ДЕЙСТВУЕТ" : L"только журнал", g_logMask, g_muteMask,
              g_exemptGm ? L"не глушится" : L"глушится", g_noticeMode, g_noticeSec,
              g_shoutPlaced ? (p121 == 0xE9 ? L"@0x4F0C6D/0x4F0C88, отказ до расхода @0x4EDEB3 (P121)" : L"@0x4F0C6D/0x4F0C88 только журнал")
                            : L"выкл");
    return PatchResult::Applied;
}
