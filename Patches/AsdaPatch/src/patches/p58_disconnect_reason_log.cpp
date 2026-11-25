// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P58 — ★ ПРИЧИНА ОТКЛЮЧЕНИЯ В ОБЩИЙ ЛОГ ВСЕГДА (П1 плана 04_detection_response.md §6.2; волна A6, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Документ: `AstoryServer/Docs/GameServer/disconnect-reason-log-p58.md`.
//
//  Сток: Send_DisConnectType sub_52EDB0@0x52EDB0 пишет строку «[CALL] Send_DisConnectType() UserNum:%d
//  DisConnectType:%s(%d)» ТОЛЬКО когда тип сервера (таблица 0x5F5E18, запись 0xEC, +0x3F) == 4 — и в канал 31
//  (Log_RoseWar), GameServer.c:115149-115150. На обычном сервере причина кика в файл-логах не остаётся
//  (есть только «___ExceptionDisConnetUser___ CallFunc = …» без кода 4101).
//  Правка: ОДНА площадка 0x52EDE4 (`cmp edx,4; jne 0x52EE0E` = 5 б) → стаб: наша строка в канал LogChannel
//  (по умолчанию 0 = Log_Game) ВСЕГДА, затем те же `cmp edx,4 / jne` — стоковое поведение типа 4 не меняется.
//  Строка: стоковый формат + имя персонажа, UserIndex, IP пира и адрес возврата (откуда кик):
//    "[CALL] Send_DisConnectType() \tUserNum:%d \tDisConnectType:%s(%d) \tCharN:%s \tUserIndex:%d \tIP:%s \tFrom:0x%08X"
//  Имя типа — из стоковой таблицы off_5A62AC (15 записей, 0..14; проверено дампом .rdata), вне её — "Unknown":
//  сток индексирует таблицу любым байтом типа (у типа 15 указатель уже мусорный) — поэтому без защиты
//  «включить ветку всегда» нельзя.
//  Кадр: P48 держит вход функции (6 б пролога, возврат 0x52EDB6) — пролог к нашей площадке уже выполнен:
//  [ebp-8] = CUserManager (this), [ebp+8] = userNum (i16), [ebp+0xC] = тип (u8), [ebp+4] = адрес возврата.
//  Площадка целиком = две инструкции, переходов внутрь нет (verify_p57.py), с P01…P57 не пересекается.
//  ★ P73 (EAC, 2026-10-16): кик моста EAC (P73_KickInProgress в этой нити) пишется с именем причины «EAC(P73)» вместо стокового.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>   // [fix13] _snprintf_s / _snwprintf_s — ограниченные форматтеры
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P58_DisconnectReasonLog";

    int  g_channel = 0;   // канал sub_569DF0 (0 = Log_Game)

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);         // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog) Srv::kLog;

    constexpr DWORD kTypeTable  = 0x005A62AC;   // off_5A62AC: const char* [15]
    constexpr int   kTypeCount  = 15;
    constexpr int   kOffUserIndex = 0x174;
    constexpr int   kOffName      = 0x178;

    volatile LONG g_lines = 0;
}

extern "C" void __stdcall P58_OnDisconnect(void* mgr, int userNum, int type, DWORD retVa)
{
    __try
    {
        const char* typeName = "Unknown";
        if (type >= 0 && type < kTypeCount)
        {
            const char* p = ((const char* const*)kTypeTable)[type];
            if (p) { typeName = p; }
        }
        // ★ P73 (EAC, 2026-10-16): кик моста EAC (тип KickType, по умолчанию 12 «HackShield» стоковой таблицы) — своё имя причины.
        if (P73_KickInProgress()) { typeName = "EAC(P73)"; }
        if (P127_KickInProgress()) { typeName = "AdminBridge(P127)"; }   // ★ P127: кик моста админ-центра — своё имя причины
        const char* name = "?";
        int userIndex = -1;
        char ip[20] = "?";
        if (mgr && userNum >= 0 && userNum < 0x226)
        {
            BYTE* user = pGetUser(mgr, nullptr, (short)userNum);
            if (user)
            {
                name = (const char*)(user + kOffName);
                userIndex = *(const int*)(user + kOffUserIndex);
            }
            const DWORD a = P47_PeerIpv4(userNum);   // сетевой порядок; 0 — нет
            if (a) { _snprintf_s(ip, sizeof(ip), _TRUNCATE, "%u.%u.%u.%u", a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF); }   // [fix13] ограниченный форматтер
        }
        InterlockedIncrement(&g_lines);
        pSrvLog(g_channel, "[CALL] Send_DisConnectType() \tUserNum:%d \tDisConnectType:%s(%d) \tCharN:%s \tUserIndex:%d \tIP:%s \tFrom:0x%08X",
                userNum, typeName, type, name, userIndex, ip, retVa);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

extern "C" int __stdcall P58_GetLines() { return g_lines; }

namespace
{
    DWORD g_retStock = 0x0052EDE9;   // тип 4: стоковая строка в канал 31
    DWORD g_retSkip  = 0x0052EE0E;   // иначе: отправка 4101

    // Площадка 0x52EDE4: вытеснены `cmp edx,4` (3 б) и `jne 0x52EE0E` (2 б). edx = тип сервера.
    __declspec(naked) void DiscLogStub()
    {
        __asm
        {
            pushad
            push  dword ptr [ebp+4]            // адрес возврата Send_DisConnectType (откуда кик)
            movzx eax, byte ptr [ebp+0xC]      // тип
            push  eax
            movsx eax, word ptr [ebp+8]        // userNum
            push  eax
            push  dword ptr [ebp-8]            // CUserManager
            call  P58_OnDisconnect             // __stdcall, 16 б
            popad
            cmp   edx, 4                       // вытеснено
            je    stock
            jmp   dword ptr [g_retSkip]        // вытеснено: jne 0x52EE0E
        stock:
            jmp   dword ptr [g_retStock]
        }
    }

    const BYTE kOrig[5]     = { 0x83, 0xFA, 0x04, 0x75, 0x25 };          // 0x52EDE4
    const BYTE kNbStock[4]  = { 0x0F, 0xB6, 0x45, 0x0C };                // 0x52EDE9 movzx eax,[ebp+0Ch]
    const BYTE kNbSkip[4]   = { 0x6A, 0x01, 0x6A, 0x00 };                // 0x52EE0E push 1; push 0
    const BYTE kNbPush31[7] = { 0x68, 0xC8, 0xA9, 0x59, 0x00, 0x6A, 0x1F }; // 0x52EDFF push fmt; push 31
}

PatchResult P58_DisconnectReasonLog()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_channel = Config::GetInt(kSec, L"LogChannel", 0);
    if (g_channel < 0 || g_channel > 60) { g_channel = 0; }

    const Site sites[] =
    {
        { 0x0052EDE4, kOrig,     sizeof(kOrig)     },
        { 0x0052EDE9, kNbStock,  sizeof(kNbStock)  },
        { 0x0052EE0E, kNbSkip,   sizeof(kNbSkip)   },
        { 0x0052EDFF, kNbPush31, sizeof(kNbPush31) },
    };
    if (!VerifyAllSites(L"P58", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    // Таблица имён типов должна лежать в .rdata и содержать указатели в .rdata (как в стоке).
    for (int i = 0; i < kTypeCount; ++i)
    {
        const DWORD p = ((const DWORD*)kTypeTable)[i];
        if (p < Srv::kRdataVa || p >= Srv::kRdataEnd)
        {
            Log::Line(L"    P58: ! off_5A62AC[%d] = 0x%08X вне .rdata — таблица не та, не ставлю", i, p);
            return PatchResult::Mismatch;
        }
    }
    if (!Hook::WriteJmp(0x0052EDE4, &DiscLogStub, 5)) { return PatchResult::Failed; }
    Log::Line(L"    P58: причина отключения (4101) пишется в канал %d (%s) всегда; стоковая строка типа 4 в Log_RoseWar сохранена",
              g_channel, g_channel == 0 ? L"Log_Game" : L"см. таблицу каналов");
    return PatchResult::Applied;
}
