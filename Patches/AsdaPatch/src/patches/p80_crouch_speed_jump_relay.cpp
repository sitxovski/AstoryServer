// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P80 — ★ ХОД ВПРИСЯДКУ ×0.5 И ПРЫЖОК С БЕГА СОСЕДЯМ (решение владельца 24.10.2026; порт: ходьба вприсядку из донора
//  AsdaFableClassic, клавиша Ctrl). [ПОРТ] — у стока этих механик нет; протокол НЕ меняется (поля и опкоды стоковые).
//  Документ: `AstoryServer/Docs/GameServer/crouch-speed-jump-relay-p80.md`. Сток, живой GameServer и Indun совпадают побайтно на
//  всех площадках (живой = Indun, md5 e7b4ac38; проверка tools/verify_p80.py, стенд tools/stand_p80).
//
//  ── S1. СКОРОСТЬ ПРИСЕДА (RecalcMoveSpeed@0x5588F0) ──
//  Сервер считает скорость сам: 0.35 + баффы/транспорт, потолок 0.66, пол 0, затем ДЕЛИТ НА 2, если у игрока состояние навыка
//  112 «Скрытность» (byte CUser+0x999E) или 186 «Быстрая маскировка» (byte CUser+0xA08E) — массив состояний CUser с базы 0x8F1E,
//  шаг 24 б (сверено: 29 → +0x91D6, 30 → +0x91EE, 230 → +0xA4AE, 241 → +0xA5B6 в той же функции). Код:
//      0x558B2B mov edx,[ebp-0Ch] ; movzx eax,byte[edx+999Eh] ; test ; jg 0x558B47       (112 → деление)
//      0x558B39 mov ecx,[ebp-0Ch] ; movzx edx,byte[ecx+0A08Eh] ; test ; jle 0x558B53     (186 нет → мимо)  ← ПЛОЩАДКА 14 б
//      0x558B47 fld [ebp-4] ; fdiv qword[0x5874A0] (= 2.0) ; fstp [ebp-4]                 (деление)
//      0x558B53 movzx eax,byte[ebp+0Ch] …                                                  (запись +0x54FE / рассылка 6071)
//  Клиент порта в приседе шлёт 4006 со статусом хода @+3 = 4 (CrouchStatus) вместо 2. Сток статус принимает (2/4/6/8 →
//  пересчёт скорости), пишет его в word CUser+0x54E4 ДО вызова sub_5588F0 (CharMove обе ветки, 0x5455xx) и эхом рассылает 4007
//  соседям; NpcServer (Send_BattleServerToCharParamAll) считает 4 «идёт». P80: трамплин повторяет проверку 186 и добавляет
//  «word[CUser+0x54E4] == CrouchStatus» → то же стоковое деление на 2. До площадки код доходит, только если 112 нет; при 186
//  трамплин уходит в деление сразу — двойного деления (невидим + присед) нет. Скорость попадает в +0x54FE и в 4007 @+21 —
//  соседи идут тем же темпом; P57 считает бюджет по +0x54FE — согласованно. На 4008 CharStop пишет 0 → обычная скорость.
//
//  ── S2. ПРЫЖОК С БЕГА СОСЕДЯМ (CharEMotionSync sub_546730, 4024 → 4025) ──
//  Сток пропускает 4024 ТОЛЬКО стоя: 0x5468B8 call sub_523ED0 (dword CUser+0x33 «в стеке хода», ставит SetEmpty_UserMoveStack
//  0x542300 на 4006, снимает sub_542520 на 4008/ревизии) ; test ; je 0x5468C6 ; 0x5468C1 jmp 0x5469AF ← ПЛОЩАДКА 5 б (выход
//  без рассылки). Прыжок порта с бега (4024 код 131) поэтому соседям не доходил. P80: в ходу код == RelayWhileMoving (131) →
//  переход на 0x546946 — байт шлема CUser+0x4A6 в тело и стоковая рассылка 4025 13 б сектору кроме себя (sub_52E6D0); запись
//  кода в CUser+0x54E4 (0x5468EE) и курса +0x5512/+0x5516 пропускаются: статус хода (2/4) и NpcServer не портятся. Хвост
//  0x546978 (112/113 → sub_54A050) для 131 не срабатывает. Прочие коды в ходу — как сток (выход). Стоя — сток без изменений.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P80_CrouchSpeedJumpRelay";

    // ── S1: скорость приседа (RecalcMoveSpeed@0x5588F0) ─────────────────────
    const DWORD kSpeedSite      = 0x00558B39;
    const BYTE  kSpeedOrig[14]  = { 0x8B, 0x4D, 0xF4,                          // mov ecx,[ebp-0Ch]        (CUser)
                                    0x0F, 0xB6, 0x91, 0x8E, 0xA0, 0x00, 0x00,  // movzx edx,byte[ecx+0A08Eh] (сост. 186)
                                    0x85, 0xD2,                                // test edx,edx
                                    0x7E, 0x0C };                              // jle 0x558B53
    // соседи S1 (только сверка)
    const DWORD kSpeed112Site   = 0x00558B2B;                                  // проверка 112 — до площадки
    const BYTE  kSpeed112Orig[14] = { 0x8B, 0x55, 0xF4, 0x0F, 0xB6, 0x82, 0x9E, 0x99, 0x00, 0x00, 0x85, 0xC0, 0x7F, 0x0E };  // jg 0x558B47
    DWORD g_pHalf               = 0x00558B47;                                  // fld [ebp-4] ; fdiv qword[0x5874A0] ; fstp [ebp-4]
    const BYTE  kHalfOrig[12]   = { 0xD9, 0x45, 0xFC, 0xDC, 0x35, 0xA0, 0x74, 0x58, 0x00, 0xD9, 0x5D, 0xFC };
    DWORD g_pAfter              = 0x00558B53;                                  // movzx eax,byte[ebp+0Ch] — запись/рассылка
    const BYTE  kAfterOrig[4]   = { 0x0F, 0xB6, 0x45, 0x0C };
    const DWORD kTwoSite        = 0x005874A0;                                  // константа делителя (double 2.0)
    const BYTE  kTwoOrig[8]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40 };

    // ── S2: прыжок с бега соседям (sub_546730) ──────────────────────────────
    const DWORD kRelaySite      = 0x005468C1;
    const BYTE  kRelayOrig[5]   = { 0xE9, 0xE9, 0x00, 0x00, 0x00 };            // jmp 0x5469AF (в ходу — выход)
    // соседи S2 (только сверка)
    const DWORD kMovingSite     = 0x005468B8;                                  // call sub_523ED0 ; test eax,eax ; je 0x5468C6
    const BYTE  kMovingOrig[9]  = { 0xE8, 0x13, 0xD6, 0xFD, 0xFF, 0x85, 0xC0, 0x74, 0x05 };
    const DWORD kCodeSite       = 0x005468C6;                                  // movsx eax,word[ebp-416h] — код действия
    const BYTE  kCodeOrig[7]    = { 0x0F, 0xBF, 0x85, 0xEA, 0xFB, 0xFF, 0xFF };
    DWORD g_pRelay              = 0x00546946;                                  // mov eax,[ebp-42Ch] ; mov cl,[eax+4A6h] → 4025
    const BYTE  kRelayDstOrig[12] = { 0x8B, 0x85, 0xD4, 0xFB, 0xFF, 0xFF, 0x8A, 0x88, 0xA6, 0x04, 0x00, 0x00 };
    DWORD g_pExit               = 0x005469AF;                                  // эпилог: mov ecx,[ebp-4] ; xor ecx,ebp
    const BYTE  kExitOrig[5]    = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD };

    // ── настройки (читает трамплин) ─────────────────────────────────────────
    int g_crouchOn     = 0;     // CrouchHalve: 1 — статус приседа делит скорость на 2
    int g_crouchStatus = 4;     // CrouchStatus: статус хода 4006 @+3 приседа (2..8; 2 = обычный бег — запрещено)
    int g_relayOn      = 0;     // 1 — RelayWhileMoving задан
    int g_relayCode    = 131;   // RelayWhileMoving: код 4024, рассылаемый соседям и в ходу (100…400), 0 — выкл

    P80_Stats g_stats = {};

    // Трамплин S1. Вход по jmp из 0x558B39: ebp — кадр sub_5588F0 ([ebp-0Ch] = CUser, не NULL — функция вышла бы раньше).
    //   ecx/edx/eax и флаги на обоих выходах свободны (сток их перезаписывает). Стек не трогаем.
    __declspec(naked) void SpeedTrampoline()
    {
        __asm
        {
            mov   ecx, dword ptr [ebp-0Ch]
            movzx edx, byte ptr [ecx+0A08Eh]        // состояние 186 — как сток
            test  edx, edx
            jg    Half186
            cmp   g_crouchOn, 0
            je    After
            movzx edx, word ptr [ecx+54E4h]         // статус хода из 4006 @+3 (CharMove пишет до вызова)
            cmp   edx, g_crouchStatus
            jne   After
            lock inc dword ptr [g_stats.crouchHalved]
            jmp   dword ptr [g_pHalf]               // 0x558B47 — стоковое деление на 2.0
        Half186:
            lock inc dword ptr [g_stats.hide186]
            jmp   dword ptr [g_pHalf]
        After:
            jmp   dword ptr [g_pAfter]              // 0x558B53 — без деления
        }
    }

    // Трамплин S2. Вход по jmp из 0x5468C1 (игрок в стеке хода): ebp — кадр sub_546730, [ebp-416h] — код действия тела 4024.
    //   eax и флаги на обоих выходах свободны (0x546946 и 0x5469AF перезаписывают). Стек не трогаем.
    __declspec(naked) void RelayTrampoline()
    {
        __asm
        {
            cmp   g_relayOn, 0
            je    Exit
            movsx eax, word ptr [ebp-416h]
            cmp   eax, g_relayCode
            jne   Drop
            lock inc dword ptr [g_stats.relayed]
            jmp   dword ptr [g_pRelay]              // 0x546946 — байт шлема + 4025 сектору (sub_52E6D0)
        Drop:
            lock inc dword ptr [g_stats.droppedMoving]
        Exit:
            jmp   dword ptr [g_pExit]               // 0x5469AF — как сток: выход без рассылки
        }
    }
}

extern "C" __declspec(dllexport) void __stdcall P80_GetStats(P80_Stats* out)
{
    if (out) { *out = g_stats; }
}

PatchResult P80_CrouchSpeedJumpRelay()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    const bool crouch = Config::GetBool(kSec, L"CrouchHalve", true);
    int status        = Config::GetInt (kSec, L"CrouchStatus", 4);
    int relay         = Config::GetInt (kSec, L"RelayWhileMoving", 131);
    // ★ Ревизия 24.10 (мелочь 1): статус приседа — только 4. 2 — обычный бег; 6 NpcServer считает «не идёт»
    //   (`Send_BattleServerToCharParamAll`: идёт = 2/4/8); 8 и прочие клиент порта не шлёт.
    if (status != 4)
    {
        Log::Line(L"    P80: CrouchStatus=%d негоден (допускается только 4) — взято 4", status);
        status = 4;
    }
    // ★ Ревизия 24.10 (мелочь 2): особые коды сервера в ходу не рассылаем — у них свои ветки/смысл вне рассылки:
    //   112/113 (sub_54A050 после рассылки), 200 (мёртв), 300/301 (GM-скрытие, Send_HideCommand), 108 (сидение), 110/114 (копание, P66).
    if (relay != 0 && (relay < 100 || relay > 400 || relay == 108 || relay == 110 || relay == 112 || relay == 113 || relay == 114
                       || relay == 200 || relay == 300 || relay == 301))
    {
        Log::Line(L"    P80: RelayWhileMoving=%d негоден (вне 100..400 или особый код сервера 108/110/112/113/114/200/300/301) — рассылка в ходу выключена", relay);
        relay = 0;
    }
    if (!crouch && relay == 0)
    {
        Log::Line(L"    P80: CrouchHalve=0 и RelayWhileMoving=0 — ставить нечего");
        return PatchResult::Disabled;
    }

    // ── сверка ВСЕХ площадок и соседей включённых мер ДО первой записи ──────
    Site check[10];
    int  n = 0;
    if (crouch)
    {
        check[n++] = { kSpeedSite,    kSpeedOrig,    sizeof(kSpeedOrig)    };
        check[n++] = { kSpeed112Site, kSpeed112Orig, sizeof(kSpeed112Orig) };
        check[n++] = { g_pHalf,       kHalfOrig,     sizeof(kHalfOrig)     };
        check[n++] = { g_pAfter,      kAfterOrig,    sizeof(kAfterOrig)    };
        check[n++] = { kTwoSite,      kTwoOrig,      sizeof(kTwoOrig)      };
    }
    if (relay != 0)
    {
        check[n++] = { kRelaySite,  kRelayOrig,    sizeof(kRelayOrig)    };
        check[n++] = { kMovingSite, kMovingOrig,   sizeof(kMovingOrig)   };
        check[n++] = { kCodeSite,   kCodeOrig,     sizeof(kCodeOrig)     };
        check[n++] = { g_pRelay,    kRelayDstOrig, sizeof(kRelayDstOrig) };
        check[n++] = { g_pExit,     kExitOrig,     sizeof(kExitOrig)     };
    }
    if (!VerifyAllSites(L"P80", check, n)) { return PatchResult::Mismatch; }

    g_crouchOn     = crouch ? 1 : 0;
    g_crouchStatus = status;
    g_relayCode    = relay;
    g_relayOn      = relay != 0 ? 1 : 0;

    // ── запись ──────────────────────────────────────────────────────────────
    if (crouch)
    {
        if (!Hook::WriteJmp(kSpeedSite, &SpeedTrampoline, sizeof(kSpeedOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P80 CrouchHalve: RecalcMoveSpeed @0x%08X -> трамплин 0x%08X: статус хода CUser+0x54E4 == %d (4006 @+3) "
                  L"делит скорость на 2 стоковой веткой 0x%08X (как состояния 112/186, без двойного деления)",
                  kSpeedSite, (DWORD)&SpeedTrampoline, status, g_pHalf);
    }
    if (relay != 0)
    {
        if (!Hook::WriteJmp(kRelaySite, &RelayTrampoline, sizeof(kRelayOrig))) { return PatchResult::Failed; }
        Log::Line(L"    P80 RelayWhileMoving: CharEMotionSync @0x%08X -> трамплин 0x%08X: 4024 код %d в ходу -> 4025 сектору "
                  L"(0x%08X, без записи CUser+0x54E4 и курса); прочие коды в ходу — как сток",
                  kRelaySite, (DWORD)&RelayTrampoline, relay, g_pRelay);
    }
    return PatchResult::Applied;
}
