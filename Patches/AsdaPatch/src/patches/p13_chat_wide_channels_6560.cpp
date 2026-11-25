// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P13 — «широкие» каналы чата: приём 6560 (0x19A0) -> рассылка 6561 (0x19A1).
//
//  ЗАЧЕМ. Клиент (и оригинальный, и наш порт) отправляет каналы «Поиск отряда»
//  (channelType = 1) и «Торговля» (channelType = 2) опкодом 6560 и ждёт рассылку
//  6561. В GameServer.exe обработчика НЕТ ВООБЩЕ: 0x19A0/0x19A1 попадают в дыру
//  между рядами case 0x189E…0x199B и 0x19AF…, поэтому пакет уходит в общий
//  default и лишь увеличивает счётчик «мусорных» пакетов клиента.
//
//  ─── ГДЕ ХУК ────────────────────────────────────────────────────────────────
//  Точка — ОБЩАЯ ветка default диспетчера sub_42A9D0 @0x0042F020 (IDA def_42AC29):
//      0042F020  0F BF 4D BC   movsx ecx, word ptr [ebp-0x44]   ; charIndex
//      0042F024  51            push  ecx
//      0042F025  8B 95 3C EF.. mov   edx, [ebp-0x10C4]          ; this диспетчера
//                              mov   eax, [edx+4] / mov ecx, [eax+0x34]
//      0042F031  E8 ..         call  sub_5244B0                 ; ++CUser+0x1E
//      0042F036  <общий хвост switch>
//  Почему именно сюда, а не в jump-table: диапазон 0x189E…0x199B свёрнут в таблицу
//  (`sub edx,0x189E; cmp ...,0FDh; ja def`), 0x19A0 выше верхней границы и в
//  таблицу физически не попадает. Ветка default — ЕДИНСТВЕННАЯ точка, куда
//  сходятся все необработанные опкоды всех пяти таблиц и 14 прямых jcc.
//  Полный перебор кодировок по .text стока: ни один rel8/rel32/jcc не ведёт
//  ВНУТРЬ 0x42F021..0x42F024 -> 5 байт под jmp занять безопасно.
//
//  Кадр диспетчера (сверено с case 0x13DE = 5086 @0x42BBCC):
//      [ebp-4]      -> буфер пакета (v25; хвост switch читает опкод именно так)
//      [ebp-0x44]   __int16 charIndex   (индекс сессии)
//      [ebp-0x34]   __int16 packetLen   (ПОЛНАЯ длина кадра)
//      [ebp-0x1048] сам буфер пакета
//      [ebp-0x10C4] this диспетчера; CUserManager = [[this+4]+0x34]
//      [ebp+8]      указатель на маркер прогресса (штатные case пишут туда номер)
//
//  ─── КАДР ПАКЕТА (sub_5643E0 @0x5643E0) ─────────────────────────────────────
//      +0  BYTE  0xFB
//      +1  WORD  totalLen = bodyLen + 10
//      +3  WORD  a7 | +5 WORD userIdx | +7 WORD opcode
//      +9  тело (bodyLen байт)
//      +9+bodyLen BYTE 0xFE
//  ⇒ bodyLen = packetLen - 10. Ровно так же считает и оригинальный обработчик
//    5086: memcpy(chatText, pPacket + 36, (packetLen - 10) - 27).
//
//  ─── ВХОД 6560 (эталон ChatInput_SendChannel@0xBA4A20, chat.c:2529) ─────────
//      +0  BYTE  channelType
//      +1..      текст cp1251 БЕЗ завершающего нуля; sendLen = strlen(text) + 1
//  ⇒ textLen = bodyLen - 1.
//
//  ─── ВЫХОД 6561 (эталон Recv_WhisperOrSystemMessage@0xBA8560, network.c:10823) ─
//  Клиент: payloadLen = totalLen - 9 - 32; memcpy(msgText, body+32, payloadLen-1).
//  С учётом totalLen = bodyLen + 10 это даёт РОВНО textLen байт при bodyLen =
//  32 + textLen — то есть заголовок 32 байта и текст без нуля:
//      +0   BYTE  вид = 1   (5 = нотис предмета, не наш случай)
//      +1   BYTE  channelType — эхо пришедшего (клиент: Chat_AddChatLine(..., ch+7, ...))
//      +2..+11    клиентом не разбираются -> нули
//      +12  char[20] имя отправителя (cp1251, из CUser+0x178)
//      +32  текст (<= 80 б)
//  Цвет и формат строки клиент подставляет сам (loc 20030 "[%s] > [%s]",
//  канал 1 -> FF8C91FF, канал 2 -> FF99CC00) — в пакете их нет.
//
//  ─── ОБВЯЗКА 1:1 С recvGlobalChatClient@0x547670 (обработчик 5086) ──────────
//   1) диспетчер гейтит ВСЕ чат-опкоды: `if (!sub_52EEA0(mgr, idx)) handler(...)`;
//   2) гейт типа сервера: тип карты 4 -> глобальный чат выключен;
//   3) отправитель: sub_5324A0 (CUser) + sub_532670 (байт CUser+0x190);
//   4) обход онлайна: sub_523E50(mgr, i) -> sub_5328F0(idx) -> sub_5324A0(mgr, idx),
//      фильтры получателя  CUser+0x174 >= 0 && CUser+0x2E == 1 && CUser+0x141 == 0;
//   5) отправка sub_4C28F0(*(void**)(mgr+4), op, bodyLen, idx, body, 0, 0);
//   6) хвост: запись чата на лог-сервер (3670, 106 б) через sub_5646C0.
//  ★ Антифлуд НЕ реализуется намеренно: его нет и в 5086 (не выдумываем механику,
//    которой на сервере нет). Ограничение частоты стоит на клиенте.
//
//  ★ ЕДИНСТВЕННОЕ, чего в оригинале нет и вывести неоткуда, — код ТИПА чата в
//    записи 3670 (у глобального чата это 7). Поэтому пересылка на лог-сервер
//    реализована полностью, но включается ключом ChatLogType (0 = не слать).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

namespace
{
    // ── типизированные указатели на функции сервера ─────────────────────────
    typedef int   (__cdecl    *FnIsValidUserIdx)(short idx);
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);
    typedef int   (__thiscall *FnGetUserIdxAt)(void* mgr, int i);
    typedef char  (__thiscall *FnIsUserInGame)(void* mgr, short idx);
    typedef int   (__thiscall *FnIsChatBlocked)(void* mgr, short idx);
    typedef char* (__thiscall *FnGetCharNamePtr)(void* mgr, short idx);
    typedef char  (__thiscall *FnGetUserSubFlag)(void* mgr, short idx);
    typedef int   (__thiscall *FnGetUserNumber)(void* mgr, short idx);
    typedef int   (__thiscall *FnSendPacket)(void* net, short op, short len, short idx,
                                             void* body, short a6, int a7);
    typedef void* (__thiscall *FnChatLogRecInit)(void* rec);
    typedef int   (__thiscall *FnGetChatSrvIdx)(void* net);
    typedef int   (__thiscall *FnConnectSend)(void* net, short op, short len, short conn,
                                              void* body, short idx);
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);

    const FnIsValidUserIdx SrvIsValidUserIdx = (FnIsValidUserIdx)Srv::kIsValidUserIdx;
    const FnGetUser        SrvGetUser        = (FnGetUser)Srv::kGetUser;
    const FnGetUserIdxAt   SrvGetUserIdxAt   = (FnGetUserIdxAt)Srv::kGetUserIdxAt;
    const FnIsUserInGame   SrvIsUserInGame   = (FnIsUserInGame)Srv::kIsUserInGame;
    const FnIsChatBlocked  SrvIsChatBlocked  = (FnIsChatBlocked)Srv::kIsChatBlocked;
    const FnGetCharNamePtr SrvGetCharNamePtr = (FnGetCharNamePtr)Srv::kGetCharNamePtr;
    const FnGetUserSubFlag SrvGetUserSubFlag = (FnGetUserSubFlag)Srv::kGetUserSubFlag;
    const FnGetUserNumber  SrvGetUserNumber  = (FnGetUserNumber)Srv::kGetUserNumber;
    const FnSendPacket     SrvSendPacket     = (FnSendPacket)Srv::kSendPacket;
    const FnChatLogRecInit SrvChatLogRecInit = (FnChatLogRecInit)Srv::kChatLogRecInit;
    const FnGetChatSrvIdx  SrvGetChatSrvIdx  = (FnGetChatSrvIdx)Srv::kGetChatSrvIdx;
    const FnConnectSend    SrvConnectSend    = (FnConnectSend)Srv::kConnectSend;
    const FnSrvLog         SrvLog            = (FnSrvLog)Srv::kLog;

    // сторож бесконечного цикла — 1:1 со строкой оригинала «Recv_GlobalChatClient()»
    const char kFnName[] = "Recv_ChatWideChannel_6560()";
    constexpr int kSrvLogCatLoopGuard = 13;

    // ── настройки (читаются один раз при установке патча) ───────────────────
    unsigned g_channelMask   = 0x06;   // биты разрешённых каналов: 1 и 2
    bool     g_respectMapGate = true;  // гейт «тип сервера 4 -> широкий чат выключен»
    int      g_chatLogType    = 0;     // код типа для записи 3670; 0 = не отправлять
    bool     g_runtimeLog     = true;  // строки [chat6560] в PatchLog

    // Лог рантайма. Log::Line сама по себе не сериализована, а обработчики пакетов
    // сервера могут работать в нескольких потоках -> собственная критическая секция.
    CRITICAL_SECTION g_logLock;
    bool             g_logLockReady = false;

    void RtLog(const wchar_t* fmt, ...)
    {
        if (!g_runtimeLog) { return; }
        wchar_t buf[1024];
        va_list ap;
        va_start(ap, fmt);
        _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
        va_end(ap);
        if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
        Log::Line(L"%s", buf);
        if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
    }

    // cp1251 -> UTF-16 для лога (имя персонажа и текст приходят в cp1251)
    void ToWide(const char* src, int len, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (len <= 0) { return; }
        int n = MultiByteToWideChar(1251, 0, src, len, out, cch - 1);
        if (n < 0) { n = 0; }
        out[n] = 0;
    }

    // Гейт «сервер, на котором глобальный чат выключен» — 1:1 с recvGlobalChatClient:
    //   *(BYTE*)(*(DWORD*)0x5F5E18 + 0xEC * *(DWORD*)(*(DWORD*)(mgr+4) + 0x4950) + 0x3F) != 4
    bool ServerAllowsWideChat(void* mgr)
    {
        const BYTE* net = *(const BYTE**)((const BYTE*)mgr + 4);
        if (!net) { return false; }
        const DWORD cfgIdx = *(const DWORD*)(net + Srv::kOffSrvCfgIndex);
        const BYTE* tbl = *(const BYTE**)Srv::kServerCfgTable;
        if (!tbl) { return true; }              // таблица не загружена — вести себя как «не 4»
        const BYTE mapType = tbl[Srv::kSrvCfgRecSize * cfgIdx + Srv::kOffSrvMapType];
        return mapType != Srv::kSrvMapTypeNoGlobalChat;
    }
}

// ═══════════════════════ обработчик (зовётся стабом) ════════════════════════
extern "C" void __stdcall AsdaOnChatWide6560(void* mgr, int charIndex, int packetLen, BYTE* pkt)
{
    // 0) гейт, которым диспетчер закрывает ВСЕ чат-опкоды (5084/5086/5088/6316)
    if (SrvIsChatBlocked(mgr, (short)charIndex))
    {
        RtLog(L"[chat6560] reject: user=%d чат заблокирован (sub_52EEA0)", charIndex);
        return;
    }

    // 1) длина
    const int bodyLen = packetLen - Srv::kFrameOverhead;
    if (bodyLen < 2)
    {
        RtLog(L"[chat6560] reject: len=%d too short", bodyLen);
        return;
    }

    const BYTE* body = pkt + 9;
    const unsigned channel = body[0];

    // 2) канал: обслуживаем только те, что разрешены маской (по умолчанию 1 и 2).
    //    Канал 0 («По всем каналам») из клиента убран -> отвергаем.
    if (channel > 31u || ((g_channelMask >> channel) & 1u) == 0u)
    {
        RtLog(L"[chat6560] reject: channel=%u not served (маска 0x%X)", channel, g_channelMask);
        return;
    }

    // 3) гейт типа сервера (как у глобального чата)
    if (g_respectMapGate && !ServerAllowsWideChat(mgr))
    {
        RtLog(L"[chat6560] reject: тип карты сервера = 4, широкий чат выключен "
              L"(как у recvGlobalChatClient)");
        return;
    }

    // 4) текст: клиент шлёт ровно strlen байт без нуля. Режем по ДЕЙСТВУЮЩЕМУ
    //    пределу g_chatMaxTextLen (P14): до P14 это стоковые 80 — как `chatText[80]`
    //    в recvGlobalChatClient; с P14 — значение [P14_ChatMessageLength] MaxTextLen.
    //    Ёмкость самого буфера — Srv::kChatMaxText, предел никогда её не превышает.
    char text[Srv::kChatMaxText + 1];
    memset(text, 0, sizeof(text));
    int limit = g_chatMaxTextLen;
    if (limit > Srv::kChatMaxText) { limit = Srv::kChatMaxText; }
    if (limit < 1)                 { limit = 1; }
    int textLen = bodyLen - 1;
    if (textLen > limit) { textLen = limit; }
    memcpy(text, body + 1, textLen);
    textLen = (int)strlen(text);            // оригинал 5086 тоже меряет strlen
    if (textLen <= 0)
    {
        RtLog(L"[chat6560] reject: пустой текст (channel=%u)", channel);
        return;
    }

    // 5) отправитель
    BYTE* sender = SrvGetUser(mgr, (short)charIndex);
    if (!sender)
    {
        RtLog(L"[chat6560] reject: CUser не найден, user=%d", charIndex);
        return;
    }
    if (!SrvIsUserInGame(mgr, (short)charIndex))
    {
        RtLog(L"[chat6560] reject: user=%d не в игре (CUser+0x190 == 0)", charIndex);
        return;
    }
    const char* senderName = (const char*)(sender + Srv::kOffCharName);

    wchar_t wName[32], wText[Srv::kChatMaxText + 1];
    ToWide(senderName, (int)strnlen(senderName, 20), wName, ARRAYSIZE(wName));
    ToWide(text, textLen, wText, ARRAYSIZE(wText));
    RtLog(L"[chat6560] recv from user=%d (%s) channel=%u len=%d text=\"%s\"",
          charIndex, wName, channel, bodyLen, wText);

    // 6) тело 6561
    BYTE out[Srv::kChatWideHdrLen + Srv::kChatMaxText];
    memset(out, 0, sizeof(out));
    out[0] = 1;                              // вид: сообщение широкого канала
    out[1] = (BYTE)channel;                  // эхо номера канала — клиент красит по нему
    memcpy(out + 12, senderName, 20);        // имя отправителя С СЕРВЕРА
    memcpy(out + Srv::kChatWideHdrLen, text, textLen);
    const int outLen = Srv::kChatWideHdrLen + textLen;

    // 7) рассылка всем онлайн-игрокам сервера — тот же цикл и те же фильтры,
    //    что у recvGlobalChatClient (5087), только опкод 6561 и своё тело.
    void* net = *(void**)((BYTE*)mgr + 4);
    if (!net)
    {
        // оригинал этого не проверяет (объект всегда есть); нам разыменование
        // нуля из нашего кода стоило бы падения GameServer — страхуемся.
        RtLog(L"[chat6560] reject: *(mgr+4) == NULL, рассылка невозможна");
        return;
    }
    int iter = 0, sent = 0, guard = 0;
    for (;;)
    {
        if (++guard > 1000) { SrvLog(kSrvLogCatLoopGuard, kFnName); guard = 0; }

        const short idx = (short)SrvGetUserIdxAt(mgr, iter++);
        if (!SrvIsValidUserIdx(idx)) { break; }

        BYTE* u = SrvGetUser(mgr, idx);
        if (!u) { continue; }

        if (*(const int*)(u + Srv::kOffUserNum) >= 0
            && *(const DWORD*)(u + Srv::kOffOnlineState) == 1
            && *(const DWORD*)(u + Srv::kOffChatSuppress) == 0)
        {
            SrvSendPacket(net, (short)Srv::kOpChatWideSend, (short)outLen, idx, out, 0, 0);
            ++sent;
        }
    }

    RtLog(L"[chat6560] broadcast 6561 channel=%u sender=%s recipients=%d bodyLen=%d",
          channel, wName, sent, outLen);

    // 8) запись чата на лог-сервер — 1:1 с хвостом recvGlobalChatClient (3670, 106 б):
    //    +0 int userNum | +4 BYTE CUser+0x18C | +5 char[20] имя | +25 BYTE тип | +26 char[80] текст
    if (g_chatLogType > 0)
    {
        BYTE rec[Srv::kChatLogRecLen];
        SrvChatLogRecInit(rec);
        rec[4] = (BYTE)SrvGetUserSubFlag(mgr, (short)charIndex);
        rec[25] = (BYTE)g_chatLogType;
        *(int*)rec = SrvGetUserNumber(mgr, (short)charIndex);
        const char* nm = SrvGetCharNamePtr(mgr, (short)charIndex);
        if (nm) { memcpy(rec + 5, nm, 20); }
        // ★ поле текста в записи 3670 — РОВНО 80 байт (запись фиксирована на 106):
        //   оригинальный хвост 5086 копирует `memcpy(v16, chatText, sizeof(v16))`
        //   при `_BYTE v16[80]`. Даже когда предел чата поднят до 160, в лог
        //   уходят первые 80 байт — формат записи менять нельзя (ТЗ §7.5.1).
        memcpy(rec + 26, text, Srv::kChatMaxTextStock);
        const short conn = (short)SrvGetChatSrvIdx(net);
        SrvConnectSend((void*)Srv::kNetMoveMgr, (short)Srv::kOpChatLogDb,
                       (short)Srv::kChatLogRecLen, conn, rec, (short)charIndex);
    }
}

// ═════════════════════════════ стаб default-ветки ═══════════════════════════
namespace
{
    DWORD g_pDefaultRet = Srv::Hooks::kDispatchDefault + 5;   // 0x0042F025
    DWORD g_pSwitchTail = Srv::Hooks::kDispatchTail;          // 0x0042F036

    const BYTE kOrig[5] = { 0x0F, 0xBF, 0x4D, 0xBC, 0x51 };

    __declspec(naked) void DispatchDefaultStub()
    {
        __asm
        {
            mov  eax, dword ptr [ebp-4]          // v25 — буфер пакета
            cmp  word ptr [eax+7], 19A0h         // опкод 6560?
            jne  not_ours

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], 19A0h          // маркер прогресса «вошли»

            lea  eax, dword ptr [ebp-1048h]
            push eax                             // pkt
            movsx ecx, word ptr [ebp-34h]
            push ecx                             // packetLen (полная длина кадра)
            movsx ecx, word ptr [ebp-44h]
            push ecx                             // charIndex
            mov  edx, dword ptr [ebp-10C4h]
            mov  eax, dword ptr [edx+4]
            mov  eax, dword ptr [eax+34h]
            push eax                             // CUserManager
            call AsdaOnChatWide6560              // __stdcall — чистит 16 байт сам

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], 19A1h          // маркер прогресса «вышли»
            jmp  dword ptr [g_pSwitchTail]       // мимо sub_5244B0 (счётчик мусора)

        not_ours:
            movsx ecx, word ptr [ebp-44h]        // оригинал: movsx ecx,[ebp-0x44]; push ecx
            push ecx
            jmp  dword ptr [g_pDefaultRet]
        }
    }
}

PatchResult P13_ChatWideChannels6560()
{
    const wchar_t* S = L"P13_ChatWideChannels6560";
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    g_channelMask    = (unsigned)Config::GetInt(S, L"AllowedChannelMask", 0x06);
    g_respectMapGate = Config::GetBool(S, L"RespectServerMapTypeGate", true);
    g_chatLogType    = Config::GetInt(S, L"ChatLogType", 0);
    g_runtimeLog     = Config::GetBool(S, L"RuntimeLog", true);

    if (!g_logLockReady)
    {
        InitializeCriticalSection(&g_logLock);
        g_logLockReady = true;
    }

    const Site sites[] = { { Srv::Hooks::kDispatchDefault, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P13", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kDispatchDefault, &DispatchDefaultStub, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P13: перехват default диспетчера @0x%08X (5 б) -> стаб 0x%08X; "
              L"6560 -> рассылка 6561 всем онлайн; маска каналов 0x%X, "
              L"гейт типа сервера=%d, чат-лог 3670 тип=%d, лог рантайма=%d; "
              L"возврат 0x%08X, хвост switch 0x%08X",
              Srv::Hooks::kDispatchDefault, (DWORD)&DispatchDefaultStub,
              g_channelMask, (int)g_respectMapGate, g_chatLogType, (int)g_runtimeLog,
              g_pDefaultRet, g_pSwitchTail);
    return PatchResult::Applied;
}
