// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P87 — [ИСПРАВЛЕНИЕ] 26.10.2026 СТАРТОВЫЕ НАВЫКИ 4-Й ПРОФЕССИИ ПО ПОДКЛАССУ (дефект оригинала GameServer).
//  Документ: AstoryServer/Docs/GameServer/job4-start-skills-p87.md (разбор двумя методами, данные стойки, что не меняется).
//
//  ── ЧТО В СТОКЕ (GameServer.c, сверено по дизасму сток 4e20f0ad / живой и Indun e7b4ac38 — байты площадки одинаковы) ──
//  4-я профессия на сервере — ПОДКЛАСС: SetSubJobChangeProcess sub_461010 (GameServer.c:39225) пишет цель в CUser+0x191
//  (Nick_name_[13]), основной класс CUser+0x190 (Nick_name_[12]) остаётся 3/14/25, счётчик профессий CUser+CurWeight+3 растёт до 4.
//  После смены (награда квеста, GameServer.c:37955-37962 и :38182-38188) при счётчике 4 зовётся sub_481CE0(skill, user, 1)
//  (GameServer.c:51460); он же — из изучения навыка sub_47E9B0 (:50716, a3 = 0). sub_481CE0: switch (CUser+0x191) по
//  4/6/15/17/26/28 — очки категорий 1–3 / 4–6 / 7–9 (CUser+0xC024+4·кат) ≥ 60 (a3=1) или ровно 60 (a3=0) и в двух категориях
//  4-й профессии 0 → LABEL_99 (loc_4820C6): sub_48A8C0(skill, user, X − 1) — выдаёт навыки строки X таблицы
//  SkillTable_Info\ChangeJobAddSkillTable.txt (загрузчик GameServer.c:71655: строка id → запись id−1 по 8 б @0x600B60:
//  +0 i16 число, +4 указатель на i16 коды; id 1…39) и шлёт 5252.
//  ★ ДЕФЕКТ: в LABEL_99 X = ОСНОВНОЙ класс CUser+0x190, а не подкласс (дизасм 0x4820C6 `mov edx,[ebp-0Ch]`;
//    0x4820C9 `movzx eax, byte ptr [edx+190h]`; 0x4820D0 `sub eax,1`; `push eax` … `call sub_48A8C0` 0x4820E2). Персонаж,
//    ставший 4-й профессией, повторно получает строку 3-й ступени (3/14/25), а строку своего подкласса (4: 617 619 632 633 634;
//    15: 826 828 841 842 843; 26: 1050 1051 1062 1065 1066 — категории навыков 10/11/12, требование очков 0, без
//    предшественников по SkillInfo.sif) не получает никогда; прочие навыки категорий 10–12 SkillPointTable.spt выдаёт по очкам
//    категории — до них без стартовых не дойти.
//
//  ── ПРАВКА ───────────────────────────────────────────────────────────────────────────────────────────────────
//  Площадка 0x4820C9 (7 б, `movzx eax, byte ptr [edx+190h]`) → jmp на трамплин + 2 nop. Трамплин исполняет ту же стоковую
//  инструкцию (CUser тот же, сбой — как у стока), сохраняет регистры и флаги (pushfd/pushad), зовёт P87_PickRow, кладёт ответ
//  в слот EAX кадра pushad (без глобальных переменных — нити карт работают параллельно) и возвращается на 0x4820D0 (`sub eax,1`).
//  P87_PickRow: подкласс S = CUser+0x191; 1 ≤ S ≤ 39 и число навыков строки S > 0 → строка S (журнал ac.other 106); иначе
//  стоковое значение CUser+0x190 (журнал 107 — строк для 6/17/28 в таблице нет ни в стоке, ни на живом сервере, данные не
//  выдумываем: решение о строках — за владельцем); исключение чтения → стоковое значение (журнал 108).
//  ★ Побочное стока сохранено: sub_48A8C0 по arg4 2/13/24 (строки 3/14/25) первым делом зовёт счётчик звания
//    sub_54A050(userMng, user, 24/25/26, 0, 0) (0x48A9A3…0x48AA14) — звание «3-я профессия» (FameInfo: включено, цель 1,
//    +92 = 0 → счётчик +1 и выдача, если звания ещё нет; есть — sub_54A890 вернёт 0 и ничего не произойдёт). С подклассом arg4
//    станет 3/14/25 — вызова в sub_48A8C0 не будет, поэтому P87 зовёт sub_54A050 сам, РОВНО как сток (тот же userMng
//    [[[[skill+4]+2Ch]+4]+34h], те же аргументы), до выдачи навыков — для персонажа без этого звания поведение не меняется.
//  Журнал: item_code = S, value1 = стоковый класс, value2 = число навыков строки (108 — этап сбоя), detail «P87 …»;
//    Log_Operator — строка на каждое событие. Откат: patches.ini [P87_Job4StartSkills] Enabled=0 — площадка не ставится (сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"P87_Job4StartSkills";              // секция patches.ini

    // ── площадка (LABEL_99 sub_481CE0, loc_4820C6) ─────────────────────────────
    constexpr DWORD kSite    = 0x004820C9;                     // movzx eax, byte ptr [edx+190h]
    constexpr DWORD kSiteLen = 7;                              // jmp rel32 + 2 nop
    const BYTE kSiteOrig[kSiteLen] = { 0x0F, 0xB6, 0x82, 0x90, 0x01, 0x00, 0x00 };
    DWORD g_pRet = 0x004820D0;                                 // sub eax,1 ; push eax — возврат (константа, только чтение)

    // ── соседи площадки (только сверка, не пишутся) ────────────────────────────
    constexpr DWORD kPreSite  = 0x004820C6;                    // mov edx,[ebp-0Ch] — CUser* (var_C) в edx на входе трамплина
    const BYTE kPreOrig[3]    = { 0x8B, 0x55, 0xF4 };
    constexpr DWORD kPostSite = 0x004820D0;                    // sub eax,1 / push eax / mov cx,[ebp+8] / push ecx /
    const BYTE kPostOrig[23]  =                                // mov edx,[ebp-10h] / mov eax,[edx+4] / mov ecx,[eax+2Ch] /
    {                                                          // call sub_48A8C0
        0x83, 0xE8, 0x01, 0x50, 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x55, 0xF0,
        0x8B, 0x42, 0x04, 0x8B, 0x48, 0x2C, 0xE8, 0xD9, 0x87, 0x00, 0x00
    };
    // sub_48A8C0: выбор звания по arg4 (+1 == 3/0xE/0x19 → 24/25/26) и вызов sub_54A050 (0x48A9A3…0x48AA19)
    constexpr DWORD kTitleSite = 0x0048A9A3;
    const BYTE kTitleOrig[] =
    {
        0x0F, 0xB6, 0x55, 0x0C, 0x83, 0xC2, 0x01, 0x89, 0x95, 0xEC, 0xF7, 0xFF, 0xFF,            // movzx edx,arg4 ; add edx,1 ; mov [ebp-814h],edx
        0x83, 0xBD, 0xEC, 0xF7, 0xFF, 0xFF, 0x03, 0x74, 0x14,                                    // cmp 3   ; je → 18h
        0x83, 0xBD, 0xEC, 0xF7, 0xFF, 0xFF, 0x0E, 0x74, 0x16,                                    // cmp 0Eh ; je → 19h
        0x83, 0xBD, 0xEC, 0xF7, 0xFF, 0xFF, 0x19, 0x74, 0x18, 0xEB, 0x1F,                        // cmp 19h ; je → 1Ah ; jmp
        0x66, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x18, 0x00, 0xEB, 0x14,                        // mov [ebp-8Ch],18h
        0x66, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x19, 0x00, 0xEB, 0x09,                        // mov [ebp-8Ch],19h
        0x66, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x1A, 0x00,                                    // mov [ebp-8Ch],1Ah
        0x0F, 0xBF, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x85, 0xC0, 0x74, 0x22,                        // movsx eax ; test ; je
        0x6A, 0x00, 0x6A, 0x00, 0x66, 0x8B, 0x8D, 0x74, 0xFF, 0xFF, 0xFF, 0x51,                  // push 0 ; push 0 ; push звание
        0x66, 0x8B, 0x55, 0x08, 0x52,                                                            // push a2
        0x8B, 0x85, 0xF0, 0xF7, 0xFF, 0xFF, 0x8B, 0x48, 0x04, 0x8B, 0x49, 0x34,                  // ecx = [[this+4]+34h]
        0xE8, 0x37, 0xF6, 0x0B, 0x00                                                             // call sub_54A050
    };
    // sub_48A8C0: чтение таблицы строк @0x600B60 (число) / @0x600B64 (указатель) по arg4 (0x48AA3B / 0x48AA53)
    constexpr DWORD kCountSite = 0x0048AA3B;
    const BYTE kCountOrig[12] = { 0x0F, 0xB6, 0x45, 0x0C, 0x0F, 0xBF, 0x0C, 0xC5, 0x60, 0x0B, 0x60, 0x00 };
    constexpr DWORD kCodesSite = 0x0048AA53;
    const BYTE kCodesOrig[11] = { 0x0F, 0xB6, 0x55, 0x0C, 0x8B, 0x04, 0xD5, 0x64, 0x0B, 0x60, 0x00 };

    // ── данные GameServer ──────────────────────────────────────────────────────
    constexpr DWORD kRowTable    = 0x00600B60;                 // ChangeJobAddSkillTable: 39 записей по 8 б (+0 i16 число, +4 i16*)
    constexpr int   kRowStride   = 8;
    constexpr int   kRowCount    = 39;                         // загрузчик принимает id 1…39
    constexpr int   kOffJob      = 0x190;                      // CUser: основной класс (Nick_name_[12])
    constexpr int   kOffSubJob   = 0x191;                      // CUser: подкласс 4-й профессии (Nick_name_[13])
    constexpr int   kOffUserIdx  = 0x174;                      // CUser: UserIndex (учётка) — sub_5324F0
    constexpr int   kOffCharSlot = 0x18C;                      // CUser: слот персонажа (байт)
    constexpr DWORD kTitleCount  = 0x0054A050;                 // sub_54A050 — счётчик звания (thiscall userMng, a2, a3, arg8, argC)
    constexpr int   kOpSkillList = 5252;                       // опкод выдачи списка навыков (sub_48A8C0 → 5252)

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1, выданы координатором: P87 — 106–108).
    constexpr BYTE kKindRow    = 106;                          // выдано по строке подкласса
    constexpr BYTE kKindNoRow  = 107;                          // строки подкласса нет — стоковая строка класса
    constexpr BYTE kKindFault  = 108;                          // исключение — стоковая строка класса

    // Функции GameServer.
    typedef char (__thiscall *FnTitleCount)(void* userMng, short userNum, short title, int add, int extra);   // sub_54A050
    FnTitleCount const pTitleCount = (FnTitleCount)kTitleCount;
    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);                                         // sub_569DF0
    FnSrvLog const pSrvLog = (FnSrvLog)Srv::kLog;

    P87_Stats g_stats = {};                                    // счётчики (экспорт P87_GetStats)

    // Звание, которое sub_48A8C0 зовёт по своей строке arg4 (= строка − 1): 2 → 24, 13 → 25, 24 → 26, иначе 0 (как 0x48A9A3).
    short StockTitleForRow(int row)
    {
        switch (row - 1)
        {
        case 2:  return 24;
        case 13: return 25;
        case 24: return 26;
        }
        return 0;
    }

    // Строка журнала ac.other + строка Log_Operator.
    void Report(BYTE kind, const BYTE* user, int userNum, int a3, int sub, int job, int row, int n, int title)
    {
        int account = AcJournal::kNone, slot = AcJournal::kNone;
        char name[24] = "?";
        __try
        {
            account = *(const int*)(user + kOffUserIdx);
            slot    = user[kOffCharSlot];
            lstrcpynA(name, (const char*)(user + Srv::kOffCharName), 20);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { lstrcpyA(name, "?"); }

        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.userNum   = (short)userNum;
        e.userIndex = account;
        e.charSlot  = slot;
        e.opcode    = kOpSkillList;
        e.ip        = P47_PeerIpv4(userNum);
        __try { AcJournal::CopyName(e, user + Srv::kOffCharName); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        e.v[0] = sub;               // item_code: подкласс CUser+0x191
        e.v[1] = job;               // value1:    основной класс CUser+0x190 (стоковая строка)
        e.v[2] = n;                 // value2:    навыков в выбранной строке (108 — этап сбоя: 1 чтение, 2 вызов звания)
        char t[64];
        _snprintf_s(t, sizeof(t), _TRUNCATE, "P87 sub %d job %d row %d n %d a3 %d title %d", sub, job, row, n, a3, title);
        AcJournal::CopyText(e, t);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }

        __try
        {
            pSrvLog(Srv::kLogCatOperator, "P87 Job4StartSkills: UserNum %d (UserIndex %d, CharN %s) SubJob %d Job %d a3 %d -> "
                    "ChangeJobAddSkillTable row %d (%d skills)%s%s", userNum, account == AcJournal::kNone ? -1 : account, name,
                    sub, job, a3, row, n,
                    kind == kKindRow ? " by subclass" : kind == kKindNoRow ? " stock (no subclass row)" : " stock (FAULT)",
                    title ? (title > 0 ? ", title counter kept" : ", title counter FAULT") : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ── C-часть трамплина площадки 0x4820C9 (LABEL_99 sub_481CE0) ─────────────────────────────────────────────────────
//   skill — CSkillManager (this sub_481CE0, [ebp-10h]); user — CUser ([ebp-0Ch], edx); userNum — a2 ([ebp+8]);
//   a3 — 1 смена профессии / 0 изучение навыка ([ebp+0Ch]); stockRow — CUser+0x190, прочитанный стоковой инструкцией.
//   Возврат: строка ChangeJobAddSkillTable (до `sub eax,1`): S — по подклассу, stockRow — как сток.
extern "C" int __stdcall P87_PickRow(BYTE* skill, BYTE* user, int userNum, int a3, int stockRow)
{
    InterlockedIncrement(&g_stats.seen);
    stockRow &= 0xFF;
    int sub = -1, n = -1;
    __try
    {
        sub = user[kOffSubJob];
        if (sub >= 1 && sub <= kRowCount)
        {
            n = *(const short*)(kRowTable + kRowStride * (sub - 1));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        Report(kKindFault, user, userNum, a3, sub, stockRow, stockRow, 1, 0);
        return stockRow;
    }

    if (n <= 0)
    {
        // Строки подкласса нет (6/17/28) или подкласс вне 1…39 — сток: строка основного класса.
        InterlockedIncrement(&g_stats.noRow);
        Report(kKindNoRow, user, userNum, a3, sub, stockRow, stockRow, n, 0);
        return stockRow;
    }

    // ★ Побочное стока: звание «3-я профессия», которое sub_48A8C0 зовёт по строке основного класса (3/14/25 → 24/25/26).
    int titleRes = 0;                                          // 0 — не нужно; 1 — вызвано; −1 — сбой вызова
    const short title = StockTitleForRow(stockRow);
    if (title && sub != stockRow)
    {
        __try
        {
            BYTE* thread  = *(BYTE**)(skill + 4);              // CSkillManager::m_pcThread
            BYTE* skill2  = *(BYTE**)(thread + 0x2C);          // m_pcThread->m_pcSkillMng (this sub_48A8C0, 0x4820DF)
            BYTE* thread2 = *(BYTE**)(skill2 + 4);
            void* userMng = *(void**)(thread2 + 0x34);         // ecx sub_54A050 в sub_48A8C0 (0x48AA08…0x48AA11)
            pTitleCount(userMng, (short)userNum, title, 0, 0);
            titleRes = 1;
            InterlockedIncrement(&g_stats.titleCalls);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            titleRes = -1;
            InterlockedIncrement(&g_stats.faults);
            Report(kKindFault, user, userNum, a3, sub, stockRow, sub, 2, -1);
        }
    }

    InterlockedIncrement(&g_stats.picked);
    Report(kKindRow, user, userNum, a3, sub, stockRow, sub, n, titleRes);
    return sub;
}

extern "C" __declspec(dllexport) void __stdcall P87_GetStats(P87_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Трамплин площадки 0x4820C9. Вход по jmp: edx = CUser* ([ebp-0Ch]), ebp — кадр sub_481CE0 ([ebp-10h] = this,
    // [ebp+8] = a2 WORD, [ebp+0Ch] = a3). Стоковая инструкция исполняется первой (тот же сбой, что у стока), затем регистры
    // и флаги сохраняются целиком; ответ P87_PickRow пишется в слот EAX кадра pushad ([esp+28]) — после popad он в EAX.
    __declspec(naked) void PickRowTrampoline()
    {
        __asm
        {
            movzx eax, byte ptr [edx+0x190]          // ── оригинальная инструкция площадки: стоковая строка (класс) ──
            pushfd
            pushad
            push  eax                                // stockRow
            push  dword ptr [ebp+0x0C]               // a3
            movsx eax, word ptr [ebp+0x08]           // a2 — userNum
            push  eax
            push  edx                                // CUser*
            push  dword ptr [ebp-0x10]               // CSkillManager* (this)
            call  P87_PickRow                        // __stdcall: чистит 5 аргументов
            mov   dword ptr [esp+28], eax            // слот EAX в кадре pushad
            popad
            popfd
            jmp   dword ptr [g_pRet]                 // 0x4820D0: sub eax,1 ; push eax ; … call sub_48A8C0
        }
    }
}

PatchResult P87_Job4StartSkills()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    // ── сверка ВСЕХ площадок и соседей ДО записи ─────────────────────────────
    const Site sites[] =
    {
        { kSite,       kSiteOrig,  sizeof(kSiteOrig)  },
        { kPreSite,    kPreOrig,   sizeof(kPreOrig)   },
        { kPostSite,   kPostOrig,  sizeof(kPostOrig)  },
        { kTitleSite,  kTitleOrig, sizeof(kTitleOrig) },
        { kCountSite,  kCountOrig, sizeof(kCountOrig) },
        { kCodesSite,  kCodesOrig, sizeof(kCodesOrig) },
    };
    if (!VerifyAllSites(L"P87", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    // Непустых строк таблицы на момент установки — только для лога: таблицу сервер может загрузить и позже,
    //   P87_PickRow читает её при каждом вызове.
    int rows = 0;
    __try
    {
        for (int i = 0; i < kRowCount; ++i) { if (*(const short*)(kRowTable + kRowStride * i) > 0) { ++rows; } }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { rows = -1; }

    if (!Hook::WriteJmp(kSite, &PickRowTrampoline, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P87: sub_481CE0 LABEL_99 @0x%08X (7 б, movzx eax,[edx+190h]) -> трамплин 0x%08X, возврат 0x%08X: строка "
              L"ChangeJobAddSkillTable по подклассу CUser+0x191 (нет строки — сток CUser+0x190); звание 24/25/26 — как сток; "
              L"журнал ac.other 106/107/108; строк таблицы сейчас %d", kSite, (DWORD)&PickRowTrampoline, g_pRet, rows);
    return PatchResult::Applied;
}
