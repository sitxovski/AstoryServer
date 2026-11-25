// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P53 — ★ ЖУРНАЛ АНТИЧИТА В БАЗЕ, сторона GameServer (волна acdb, 2026-10-12).
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Решение владельца 12.10: таблицы по видам нарушений, легкочитаемо, запись без
//  задержки. Модуль записи — ../AcJournal.cpp (очередь без блокировок + фоновый поток + своё ODBC).
//  Отчёт: `Reports/anticheat/wave_A3_dbjournal.md`; документ: `AstoryServer/Docs/GameServer/ac-journal-p53.md`.
//
//  ── ИСТОЧНИКИ СОБЫТИЙ GAMESERVER ──
//  1. Наши патчи (вызов AcJournal::Push прямо в коде): P47 гейт (ac.operator_refusal), P47 сверка 20000
//     (ac.identity_mismatch), P48 кики/автоблок (ac.kick_block) — см. p47/p48.
//  2. ШТАТНЫЕ проверки сервера — у каждой уже есть синхронная строка в файловый лог через sub_569DF0.
//     Перехватываем ровно эти вызовы (подмена цели `call rel32` → наш стаб → тот же sub_569DF0), поэтому
//     остальные 1743 вызова писателя логов не затронуты, а файл-лог сервера пишется как раньше:
//        VA вызова  формат строки (канал)                                   → таблица / вид
//        0x54543D   "CharMove Hack Position %s Error" (0)                   → move_combat 1
//        0x545A84   "CharReMove Hack Position %s Error" (0)                 → move_combat 2
//        0x5272B4   "\tHackCheck\t%d/%d\t%s\r\n" (19)                       → move_combat 3
//        0x52440E   "\t%d\t%s\tSecret Error\tUser %d, Server %d, %s" (16)   → sign_replay 1
//        0x52448B   "\t%d\t%s\tSecret Error Disconnect...!" (16)            → sign_replay 2
//        0x523FC5   "if( memcmp(szMD5, …+iSecretSize…) Command = %d" (2)    → sign_replay 3
//        0x524044   "if( memcmp(szMD5, …(HEADER_SIZE-1)…) Command = %d" (2) → sign_replay 4
//        0x4ED910   "\t[E] SendChar_FunctionItem_Use() MD5 Error..! %s, UserIndex:%d" (8) → sign_replay 5
//        0x50F561   "CharItemBuy() CellobItem ShopBuyFlag Error = %d, %s" (1) → other 1
//        0x50F91F   "CharItemBuy() NormalItem ShopBuyFlag Error %d = %d =%d= %s" (1) → other 2
//     и штатный счётчик «неизвестный опкод» — `call sub_5244B0` в общей ветке default диспетчера:
//        0x42F031   call sub_5244B0 (NotKnow Packet ++, опкод в кадре диспетчера [ebp-0x10C8]) → other 3
//  Контекст из кадра/аргументов (все смещения сверены дизасмом живого e7b4ac38 = сток для этих мест):
//     имя персонажа = CUser+0x178 (sub_532570 `add eax,178h`) ⇒ CUser = имя − 0x178; userNum = WORD CUser+0xC;
//     UserIndex = CUser+0x174; секрет: счётчик ошибок CUser+4; MD5: счётчик CUser+8, CUser в [ebp-0x10]
//     sub_523F00; пинг: счётчик HackCheck BYTE CUser+45; покупка: код товара [ebp-0x208], userNum [ebp+8],
//     менеджер [ebp-0x408]; default диспетчера: опкод [ebp-0x10C8], userNum — аргумент sub_5244B0.
//  Площадки — только 5-байтовые `E8 rel32` (вся инструкция), входов внутрь нет (verify_acdb.py);
//  с P01…P49 не пересекаются (ближайшая — P13 0x42F020..0x42F024).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P53_AcJournal";

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);   // sub_5324A0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;

    constexpr int kOffName      = 0x178;   // CUser: имя персонажа (cp1251)
    constexpr int kOffUserNumW  = 0x0C;    // CUser: WORD userNum (arrayIndex)
    constexpr int kOffUserIndex = 0x174;   // CUser: UserIndex
    constexpr int kOffSlot      = 0x18C;   // CUser: BYTE слот персонажа (sub_532530)

    // Виды площадок (константа в стабе → смысл).
    enum SiteKind : int
    {
        kCharMove = 1, kCharReMove, kHackCheck, kSecretErr, kSecretDisc, kMd5Secret, kMd5Plain, kItem5450,
        kShopCellob, kShopNormal, kNotKnow,
    };

    struct SiteDef { DWORD va; DWORD target; DWORD fmt; int kind; };
    // va — `call rel32`, target — его стоковая цель, fmt — ожидаемая строка формата (push перед call; 0 — нет).
    const SiteDef kSites[] =
    {
        { 0x0054543D, 0x00569DF0, 0x0059CB58, kCharMove   },
        { 0x00545A84, 0x00569DF0, 0x0059CB1C, kCharReMove },
        { 0x005272B4, 0x00569DF0, 0x00599624, kHackCheck  },
        { 0x0052440E, 0x00569DF0, 0x00598E64, kSecretErr  },
        { 0x0052448B, 0x00569DF0, 0x00598E90, kSecretDisc },
        { 0x00523FC5, 0x00569DF0, 0x00598E10, kMd5Secret  },
        { 0x00524044, 0x00569DF0, 0x00598DC8, kMd5Plain   },
        { 0x004ED910, 0x00569DF0, 0x00593448, kItem5450   },
        { 0x0050F561, 0x00569DF0, 0x00596730, kShopCellob },
        { 0x0050F91F, 0x00569DF0, 0x005966F4, kShopNormal },
        { 0x0042F031, 0x005244B0, 0,          kNotKnow    },
    };

    volatile LONG g_hits = 0;

    // Заполнить общие поля из CUser (под SEH — указатель приходит из кадра сервера).
    void FromUser(AcJournal::Event& e, const BYTE* user)
    {
        if (!user) { return; }
        __try
        {
            e.userNum   = *(const short*)(user + kOffUserNumW);
            e.userIndex = *(const int*)(user + kOffUserIndex);
            e.charSlot  = user[kOffSlot];
            AcJournal::CopyName(e, user + kOffName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (e.userNum >= 0) { e.ip = P47_PeerIpv4(e.userNum); }
    }
}

// Общий обработчик площадок: kind — вид, mgr — ecx вызывающего, ebp — его кадр,
// st — [0] адрес возврата, [1..] аргументы вызова (для писателя логов: [1] канал, [2] формат, [3..] значения).
extern "C" void __stdcall P53_OnSite(int kind, void* mgr, BYTE* ebp, const DWORD* st)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        AcJournal::Event e;
        const BYTE* user = nullptr;
        switch (kind)
        {
        case kCharMove:
        case kCharReMove:
            AcJournal::Clear(e, AcJournal::kMoveCombat, kind == kCharMove ? 1 : 2);
            e.opcode = 4006;                                          // CharMove — запрос хода
            if (st[3]) { user = (const BYTE*)st[3] - kOffName; }
            if (user) { P57_OnHackPosition(kind == kCharMove ? 1 : 2, mgr, (BYTE*)user); }   // ★ A6: счётчик/порог P57
            break;
        case kHackCheck:
            AcJournal::Clear(e, AcJournal::kMoveCombat, 3);
            e.opcode = 1000;                                          // пинг
            e.w[0] = (DWORD)st[3]; e.w[1] = (DWORD)st[4];
            e.v[1] = (int)((DWORD)st[4] - (DWORD)st[3]);
            if (st[5]) { user = (const BYTE*)st[5] - kOffName; e.v[2] = user[45]; }
            break;
        case kSecretErr:
            AcJournal::Clear(e, AcJournal::kSignReplay, 1);
            e.w[0] = (int)st[5]; e.w[1] = (int)st[6];
            AcJournal::CopyText(e, (const void*)st[7]);             // обработчик (строка сервера)
            if (st[4]) { user = (const BYTE*)st[4] - kOffName; e.v[0] = *(const int*)(user + 4) + 1; }
            break;
        case kSecretDisc:
            AcJournal::Clear(e, AcJournal::kSignReplay, 2);
            if (st[4]) { user = (const BYTE*)st[4] - kOffName; e.v[0] = *(const int*)(user + 4); }
            break;
        case kMd5Secret:
        case kMd5Plain:
            AcJournal::Clear(e, AcJournal::kSignReplay, kind == kMd5Secret ? 3 : 4);
            e.opcode = (int)(st[3] & 0xFFFF);
            user = *(BYTE* const*)(ebp - 0x10);                       // v9 = CUser (sub_523F00)
            if (user) { e.v[0] = *(const int*)(user + 8); }
            break;
        case kItem5450:
            AcJournal::Clear(e, AcJournal::kSignReplay, 5);
            e.opcode = 5450;
            AcJournal::CopyText(e, "Char_FunctionItem_Use()");
            if (st[3]) { user = (const BYTE*)st[3] - kOffName; }
            break;
        case kShopCellob:
        case kShopNormal:
        {
            AcJournal::Clear(e, AcJournal::kOther, kind == kShopCellob ? 1 : 2);
            e.opcode = 5020;                                          // CharItemBuy
            e.v[0] = *(const int*)(ebp - 0x208);                      // код товара
            if (kind == kShopNormal) { e.v[1] = (int)st[4]; }         // флаг продажи в таблице
            const DWORD name = kind == kShopCellob ? st[4] : st[6];
            if (name) { user = (const BYTE*)name - kOffName; }
            break;
        }
        case kNotKnow:
        {
            AcJournal::Clear(e, AcJournal::kOther, 3);
            e.opcode = *(const int*)(ebp - 0x10C8);                   // опкод в кадре диспетчера
            const int userNum = (short)st[1];
            if (mgr) { user = pGetUser(mgr, nullptr, (short)userNum); }
            if (user) { e.v[1] = *(const int*)(user + 0x1E) + 1; }  // NotKnow после ++
            if (!user) { e.userNum = (short)userNum; }
            break;
        }
        default:
            return;
        }
        FromUser(e, user);
        AcJournal::Push(e);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Журнал не должен мешать серверу: при любой ошибке разбора — молча дальше в сток.
    }
}

namespace
{
    DWORD g_pSrvLog  = 0x00569DF0;   // стоковая цель площадок писателя логов
    DWORD g_pNotKnow = 0x005244B0;   // стоковая цель площадки default диспетчера

    // Общий хвост площадок писателя логов. На входе: [esp] вид, [esp+4] адрес возврата, [esp+8…] аргументы.
    __declspec(naked) void LogTail()
    {
        __asm
        {
            pushad                                 // +32
            lea   eax, [esp+36]                    // st: адрес возврата и аргументы
            push  eax
            push  ebp                              // кадр вызывающего
            push  ecx                              // ecx вызывающего
            push  dword ptr [esp+44]               // вид
            call  P53_OnSite                       // __stdcall, 16 б
            popad
            add   esp, 4                           // снять вид
            jmp   dword ptr [g_pSrvLog]            // дальше — стоковый sub_569DF0 с теми же аргументами
        }
    }

    // То же для `call sub_5244B0` (thiscall: ecx = CUserManager, [esp+4] = userNum).
    __declspec(naked) void NotKnowTail()
    {
        __asm
        {
            pushad
            lea   eax, [esp+36]
            push  eax
            push  ebp
            push  ecx
            push  dword ptr [esp+44]
            call  P53_OnSite
            popad
            add   esp, 4
            jmp   dword ptr [g_pNotKnow]
        }
    }

    __declspec(naked) void St_CharMove()   { __asm { push 1  } __asm { jmp LogTail } }
    __declspec(naked) void St_CharReMove() { __asm { push 2  } __asm { jmp LogTail } }
    __declspec(naked) void St_HackCheck()  { __asm { push 3  } __asm { jmp LogTail } }
    __declspec(naked) void St_SecretErr()  { __asm { push 4  } __asm { jmp LogTail } }
    __declspec(naked) void St_SecretDisc() { __asm { push 5  } __asm { jmp LogTail } }
    __declspec(naked) void St_Md5Secret()  { __asm { push 6  } __asm { jmp LogTail } }
    __declspec(naked) void St_Md5Plain()   { __asm { push 7  } __asm { jmp LogTail } }
    __declspec(naked) void St_Item5450()   { __asm { push 8  } __asm { jmp LogTail } }
    __declspec(naked) void St_ShopCellob() { __asm { push 9  } __asm { jmp LogTail } }
    __declspec(naked) void St_ShopNormal() { __asm { push 10 } __asm { jmp LogTail } }
    __declspec(naked) void St_NotKnow()    { __asm { push 11 } __asm { jmp NotKnowTail } }

    void* const kStubs[] =
    {
        (void*)&St_CharMove, (void*)&St_CharReMove, (void*)&St_HackCheck, (void*)&St_SecretErr, (void*)&St_SecretDisc,
        (void*)&St_Md5Secret, (void*)&St_Md5Plain, (void*)&St_Item5450, (void*)&St_ShopCellob, (void*)&St_ShopNormal,
        (void*)&St_NotKnow,
    };
}

PatchResult P53_AcJournal()
{
    // 1. Запуск записи (очередь + поток). Выключено — ни очереди, ни площадок.
    const int r = AcJournal::Start(L"AsdaPatch");
    if (r == 1) { return PatchResult::Disabled; }
    if (r != 0) { Log::Line(L"    P53: не удалось создать очередь/поток журнала"); return PatchResult::Failed; }

    // 2. Площадки штатных проверок (ключ StockSites).
    if (!Config::GetBool(kSec, L"StockSites", true))
    {
        Log::Line(L"    P53: StockSites=0 — штатные проверки в журнал не зеркалируются (только события P47/P48)");
        return PatchResult::Applied;
    }
    BYTE orig[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        orig[i][0] = 0xE8;
        const int rel = (int)(kSites[i].target - (kSites[i].va + 5));
        memcpy(&orig[i][1], &rel, 4);
        sites[i].va = kSites[i].va; sites[i].orig = orig[i]; sites[i].len = 5;
    }
    if (!VerifyAllSites(L"P53", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    // Строка формата перед вызовом — та, что ожидаем (push imm32 в 4…20 б до call).
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!kSites[i].fmt) { continue; }
        bool found = false;
        for (int back = 5; back <= 24 && !found; ++back)
        {
            const BYTE* p = (const BYTE*)(kSites[i].va - back);
            found = p[0] == 0x68 && *(const DWORD*)(p + 1) == kSites[i].fmt;
        }
        if (!found)
        {
            Log::Line(L"    P53: ! у площадки 0x%08X нет push строки формата 0x%08X — площадки не ставятся", kSites[i].va, kSites[i].fmt);
            return PatchResult::Mismatch;
        }
    }
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!Hook::WriteCall(kSites[i].va, kStubs[i], 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    P53: площадок штатных проверок поставлено %d (ход/пинг, секрет/MD5/5450, покупка, неизвестный опкод)",
              (int)ARRAYSIZE(kSites));
    return PatchResult::Applied;
}
