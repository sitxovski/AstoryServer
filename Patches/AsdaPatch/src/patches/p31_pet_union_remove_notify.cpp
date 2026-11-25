// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P31 — ★ ЮНИОН ПИТОМЦЕВ: ШТАТНЫЙ 6111 НА КАЖДЫЙ СЪЕДЕННЫЙ МАТЕРИАЛ (2026-09-27)
//
//  ЭТО НАША ПРАВКА (дефект стока). Документ патча:
//  AstoryServer/Docs/GameServer/pet-union-remove-notify-p31.md; итог волны —
//  Reports/owner_0927/p31_p32.md.
//
//  Ответ юниона 6113 (sub_4590E0, ответ БД) несёт uid трёх съеденных материалов
//  УРЕЗАННЫМИ до 16 бит (0x4591A9: mov ax,[ebp+edx*4-0x78] → тело +50/+52/+54),
//  а клиент ищет их со знаковым расширением и сравнивает с полным 32-битным uid
//  (npc_mob_pet.c:7677 / :5549) ⇒ материалы с uid ≥ 32768 остаются в окне
//  питомцев фантомами до релога. Расширить поле нельзя: тело 56 б упирается в
//  cookie кадра (ebp-4), клиент читает ровно 56 — раскладка пакетов НЕ меняется.
//
//  Лечение — досылка ШТАТНОГО 6111 (ответ «выбросить питомца», 9 б:
//  charId@0 · uid@4 (32 бита) · код@8 = 1 «удалён»), ровно в той точке, где сервер
//  сам удаляет слот материала: `call sub_455D90` @0x00459264 — вызывается только
//  когда слот НАЙДЕН (сравнение полного uid @0x459245). Код 1 — единственный,
//  на который клиент действует (item_enhance.c:4750), и он штатный для 6111
//  (recvPetLiberateReq@0x4587B0 пересылает 1 из ответа БД). Нотиса у 6111 нет.
//  Буфер пакетов пользователя — FIFO (PackingSendPacket дописывает в хвост), поэтому
//  все 6111 уходят ДО 6113 этого же юниона.
//
//  ★ Площадка (1), сверена побайтно 27.09.2026 в ЧЕТЫРЁХ образах: наш
//  RE/ida/server_work/GameServer.exe, ЖИВОЙ v2\GameServer и v2\Indun_GameServer
//  (все MD5 E7B4AC38…) и сток GameServer.exe_before_mine_patch.exe (4E20F0AD…).
//    0x0045925A  8B 4D 80              mov  ecx,[ebp-0x80]    ; arg0 = запись игрока
//                51                    push ecx
//                8B 8D 6C FF FF FF     mov  ecx,[ebp-0x94]    ; this
//    0x00459264  E8 27 CB FF FF        call 0x00455D90        ; ★ цель → трамплин
//    0x00459269  EB 02                 jmp  0x0045926D        ; возврат (не трогается)
//  sub_455D90 — единственный вызывающий (скан E8/E9 по .text), завершается `retn 8`
//  (0x00455F51 C2 08 00) ⇒ трамплин уходит в него ХВОСТОВЫМ jmp со стеком входа.
//  Переходов внутрь 0x459265…0x459268 нет (док §3.4). С P01…P36 не пересекается.
//
//  Кадр sub_4590E0 на момент вызова (перепроверено capstone по образу 27.09):
//    [ebp-0x94] this (CUser-менеджер)        — для 6111: this = *[ebp-0x94] (как у 6113 @0x4592F8)
//    [ebp-0x7C] charId запроса                — сверен с CUser+0x174 @0x459163
//    [ebp-0x8C] j — номер материала 0…2       — цикл 0x4591DC…0x4591FE
//    [ebp+4*j-0x78] uid материала, 32 бита    — то же выражение, что в сравнении @0x459245
//    [ebp-0x90] индекс слота 0…29             — второй аргумент sub_455D90
//    [ebp+8]    индекс пользователя (i16)     — как у отправки 6113 @0x4592EC
//
//  Ключи [P31_PetUnionRemoveNotify]:
//    Enabled      — главный выключатель (по умолчанию 0: на живом не испытан, включает
//                   владелец после проверки — док §5)
//    LogPerMinute — предел строк P31 в Log_Pet (категория 27) в минуту (1…1000, 30);
//                   сверх предела строки считаются и подытоживаются одной строкой.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P31_PetUnionRemoveNotify";

    // int __thiscall sub_4C28F0(mgr, opcode, size, userIdx, body, a6, a7) — retn 18h
    typedef int  (__thiscall *FnSendPacket)(void* mgr, short op, short size, short userIdx,
                                            const void* body, short a6, int a7);
    typedef void (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);             // 0x569DF0

    const FnSendPacket SrvSend = (FnSendPacket)0x004C28F0;
    const FnSrvLog     SrvLog  = (FnSrvLog)Srv::kLog;

    constexpr short kOp6111    = 6111;     // 0x17DF — ответ «выбросить питомца»
    constexpr short kBody6111  = 9;        // push 9 у обоих штатных отправителей (0x45877D / 0x458A27)
    constexpr BYTE  kCodeGone  = 1;        // «удалён» — клиент действует только при 1
    constexpr int   kLogCatPet = 27;       // Log\Log_Pet (GameServer.c:64741)

    // Кадр sub_4590E0
    constexpr int kFrmThis    = -0x94;
    constexpr int kFrmSlot    = -0x90;
    constexpr int kFrmJ       = -0x8C;
    constexpr int kFrmCharId  = -0x7C;
    constexpr int kFrmUidBase = -0x78;
    constexpr int kFrmUserIdx =  8;

    // Косвенная цель хвостового перехода: адрес абсолютный, через память —
    //   ни один регистр не портится (тот же приём, что в P02/P36).
    DWORD g_pPetSlotClear = 0x00455D90;    // int __thiscall (this, CUser* arg0, i16 slot) — retn 8

    // mov ecx,[ebp-0x80]; push ecx; mov ecx,[ebp-0x94]; call 0x00455D90
    const BYTE kOrigSite[15] =
    {
        0x8B, 0x4D, 0x80,
        0x51,
        0x8B, 0x8D, 0x6C, 0xFF, 0xFF, 0xFF,
        0xE8, 0x27, 0xCB, 0xFF, 0xFF
    };
    constexpr DWORD kSiteVerify = 0x0045925A;
    constexpr DWORD kSiteCall   = 0x00459264;

    // ── журнал с пределом (как у P35): не больше LogPerMinute строк в минуту ──
    int              g_logMax    = 30;
    CRITICAL_SECTION g_logCs;
    bool             g_logCsInit = false;
    DWORD            g_logWin    = 0;
    int              g_logCnt    = 0;
    int              g_logDrop   = 0;
    volatile LONG    g_sent      = 0;      // всего досланных 6111 за жизнь процесса

    bool LogAllowed()
    {
        if (!g_logCsInit) { return false; }
        int  dropped = 0;
        bool ok;
        EnterCriticalSection(&g_logCs);
        const DWORD now = GetTickCount();
        if (g_logWin == 0 || (DWORD)(now - g_logWin) >= 60000)
        {
            dropped   = g_logDrop;
            g_logWin  = now ? now : 1;   // [fix2, НИЗК-12 integ3] было now | 1: в кванте старта now-win=0xFFFFFFFF, окно сбрасывалось каждой строкой
            g_logCnt  = 0;
            g_logDrop = 0;
        }
        ok = g_logCnt < g_logMax;
        if (ok) { ++g_logCnt; } else { ++g_logDrop; }
        LeaveCriticalSection(&g_logCs);
        if (dropped > 0)
        {
            SrvLog(kLogCatPet, "P31: %d log line(s) suppressed during the previous minute (LogPerMinute=%d)",
                   dropped, g_logMax);
        }
        return ok;
    }
}

extern "C"
{
// Вызывается из трамплина ДО sub_455D90 (обе его входные проверки — arg0 != 0 и
// слот < 30 — к этому моменту уже выполнены самим циклом sub_4590E0).
// ebp — кадр sub_4590E0. Чтение кадра под __try; отправка — ВНЕ __try: исключение
// внутри PackingSendPacket глотать нельзя (там блокировка буфера пользователя).
void __cdecl P31_OnPetRemoved(BYTE* ebp)
{
    void* mgr     = nullptr;
    int   charId  = 0;
    int   uid     = 0;
    int   slot    = -1;
    short userIdx = -1;
    __try
    {
        const int j = *(const int*)(ebp + kFrmJ);
        if (j < 0 || j > 2) { return; }                        // цикл по 3 материалам
        BYTE* self = *(BYTE**)(ebp + kFrmThis);
        if (!self) { return; }
        mgr     = *(void**)self;                               // как у 6113: mov ecx,[ebp-94h]; mov ecx,[ecx]
        charId  = *(const int*)(ebp + kFrmCharId);
        uid     = *(const int*)(ebp + kFrmUidBase + 4 * j);
        slot    = *(const int*)(ebp + kFrmSlot);
        userIdx = *(const short*)(ebp + kFrmUserIdx);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!mgr) { return; }

    // Тело 6111 — 9 б, раскладка штатных отправителей: charId@0, uid@4, код@8.
    BYTE body[12] = {};
    *(int*)(body + 0) = charId;
    *(int*)(body + 4) = uid;
    body[8]           = kCodeGone;
    SrvSend(mgr, kOp6111, kBody6111, userIdx, body, -1, 1);   // a6/a7 — как у штатных 6111

    const LONG n = InterlockedIncrement(&g_sent);
    if (LogAllowed())
    {
        SrvLog(kLogCatPet, "P31: pet union - material uid %d (slot %d) removed, char %d user %d -> 6111 sent (total %ld)",
               uid, slot, charId, (int)userIdx, n);
    }
}
}

namespace
{
    // Трамплин на месте `call 0x00455D90`. Сохраняет ВСЕ регистры и флаги (в т.ч.
    //   ecx = this оригинала), шлёт 6111 и уходит в sub_455D90 хвостовым jmp:
    //   стек ровно как на входе, поэтому её `retn 8` вернёт на 0x00459269 и снимет
    //   оба аргумента.
    __declspec(naked) void P31_Tramp()
    {
        __asm
        {
            pushad
            pushfd
            push  ebp                           // кадр sub_4590E0 (call его не менял)
            call  P31_OnPetRemoved
            add   esp, 4
            popfd
            popad
            jmp   dword ptr [g_pPetSlotClear]
        }
    }
}

PatchResult P31_PetUnionRemoveNotify()
{
    // По умолчанию ВЫКЛЮЧЕН — на живом не испытан (док §5, §7).
    if (!Config::GetBool(S, L"Enabled", false)) { return PatchResult::Disabled; }

    int perMin = Config::GetInt(S, L"LogPerMinute", 30);
    if (perMin < 1)    { perMin = 1; }
    if (perMin > 1000) { perMin = 1000; }
    g_logMax = perMin;

    // Сверяем не 5 байт call'а, а все 15 байт подхода к нему.
    const Site sites[] = { { kSiteVerify, kOrigSite, sizeof(kOrigSite) } };
    if (!VerifyAllSites(L"P31", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!g_logCsInit)
    {
        InitializeCriticalSection(&g_logCs);
        g_logCsInit = true;
    }

    if (!Hook::WriteCall(kSiteCall, (const void*)&P31_Tramp, 5)) { return PatchResult::Failed; }

    Log::Line(L"    P31: call @0x00459264: 0x00455D90 -> 0x%08X (трамплин: 6111 на съеденный материал юниона)",
              (DWORD)&P31_Tramp);
    Log::Line(L"    P31: журнал Log_Pet — не больше %d строк в минуту", g_logMax);
    return PatchResult::Applied;
}
