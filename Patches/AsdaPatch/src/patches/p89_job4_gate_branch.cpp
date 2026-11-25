// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P89 — [ИСПРАВЛЕНИЕ] 26.10.2026 ГЕЙТ СТАРТОВЫХ НАВЫКОВ 4-Й ПРОФЕССИИ ПО ВЕТКЕ (дефект оригинала GameServer).
//  Документ: AstoryServer/Docs/GameServer/job4-gate-branch-p89.md (разбор двумя методами, данные, стенд).
//
//  ── ЧТО В СТОКЕ (GameServer.c:51460, дизасм сток 4e20f0ad / живой и Indun e7b4ac38 — тело 0x481CE0…0x48212C одинаково) ──
//  sub_481CE0(skill, userNum, a3) — выдача стартовых навыков 4-й профессии. Зовут ровно 3 места, все при счётчике профессий
//  CUser+0x1B3 == 4: награда квеста 0x45D533 и 0x45DE95 (a3 = 1, смена профессии) и изучение навыка sub_47E9B0 0x47EDD0
//  (a3 = 0) — ПОСЛЕ sub_4760E0 (уровень навыка) и ++очков категории навыка CUser+0xC024+4·SkillInfo[+0xBD] (0x47ECA8…).
//  switch (CUser+0x191 − 4) по таблицам byte_48210C / jpt_481D49 @0x4820F0 (0x481D3F…0x481D49): сумма очков категорий
//  1–3 (подклассы 4/6), 4–6 (15/17), 7–9 (26/28) ≥ 60 (a3 ≠ 0) или ровно 60 (a3 = 0) и в паре «категорий 4-й профессии» ≤ 0
//  → LABEL_99 0x4820C6 (sub_48A8C0 — выдача строки ChangeJobAddSkillTable; строку выбирает P87), иначе эпилог 0x4820E7.
//  Пара категорий зашита по 2 на ветку: 4/6 → 10/11 (0x481D8C/0x481D98 …), 15/17 → 12/13 (0xC054/0xC058), 26/28 → 14/15
//  (0xC05C/0xC060) — 24 сравнения `cmp dword ptr [reg+0C04Ch…0C060h], 0`. Данные SkillInfo.sif (сток = живой 1acb5eaa):
//  деревья 4-й профессии — ОДНА категория на ветку: 10 боец (29 навыков, маска классов 1–11), 11 лучник (28, 12–22),
//  12 маг (28, 23–33); навыков категорий 13–15 нет (их очки всегда 0). Т. е. у бойца пара 10/11 = «своя 10 + чужое дерево
//  лучника» (у бойца там всегда 0) — гейт верен; у лучника 12/13 = «дерево мага + пусто», у мага 14/15 = «пусто + пусто» —
//  гейт по своей ветке НЕ закрывается никогда. Пары — след раскладки «по категории на подкласс» (10…15), данные её не имеют.
//  ★ ДЕФЕКТ: лучник/маг 4-й профессии с ровно 60 очками в обычных деревьях при КАЖДОМ очке в своём дереве 11/12 (a3 = 0)
//    снова проходит гейт → sub_48A8C0 → sub_475650 (GameServer.c:47766) пишет уровень навыка +0xC0C4+38·id = 0 и добавляет
//    запись в список боя (+359, предел 100). Стартовые пять сбрасываются в 0 сразу после вложения, очки категории потрачены.
//    С P87 (строки подклассов 15/26; со строками 17/28 — и для них) это достижимо.
//
//  ── ПРАВКА ───────────────────────────────────────────────────────────────────────────────────────────────────
//  Площадка 0x481D3F (17 б: mov eax,[ebp-14h] / movzx ecx, byte_48210C[eax] / jmp jpt_481D49[ecx*4]) — диспетчер switch,
//  достигается только при CUser+0x191 ∈ 4…28 → jmp на трамплин + 12 nop. Трамплин зовёт P89_Dispatch (this [ebp-10h],
//  CUser [ebp-0Ch], userNum [ebp+8], a3 [ebp+0Ch]) и делает jmp на возвращённый адрес (регистры на всех целях не живые:
//  ветки switch, LABEL_99 и эпилог читают только кадр ebp; ebx/esi/edi сохраняет __stdcall).
//  P89_Dispatch: для 4/6/15/17/26/28 считает гейт стока (та же сумма, та же пара) и гейт по ветке (сумма та же, категория
//  4-й профессии ОДНА — своя: 10 / 11 / 12). Mode=1 — решение по ветке: LABEL_99 0x4820C6 или эпилог 0x4820E7; Mode=0 —
//  только журнал: адрес ветки стока из его же таблиц (поведение стока). Прочие подклассы — всегда ветка стока.
//  ★ SkipOwnedRow=1: при стоящем P87 (площадка 0x4820C9 ведёт в эту DLL) и непустой строке подкласса, если ВСЕ навыки
//    строки у персонажа уже есть (+0xC0C0+38·id > 0 — так «есть ли навык» решает sub_47E9B0 через sub_4769C0), повтор не
//    выдаётся. Уровни повтор не трогает и без этого (очки категории = сумма уровней её навыков — загрузка sub_475290, изучение,
//    сбросы; гейт по ветке пропускает только при 0 очков своей категории), но повтор шлёт 5252/8114 и плодит записи списка
//    боя +359 (предел 100) — например, изучение навыка категории 0 при ровно 60 очках.
//  Журнал ac.other: 112 — гейт по ветке разошёлся со стоком; 113 — строка подкласса уже выдана целиком (повтор не выдан /
//    при Mode=0 — выдан бы не был); 114 — исключение (ветка стока). Log_Operator — строка на каждое событие.
//  Откат: patches.ini [P89_Job4GateBranch] Enabled=0 — площадка не ставится (сток); Mode=0 — только журнал.
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
    const wchar_t* kSec = L"P89_Job4GateBranch";               // секция patches.ini

    // ── площадка: диспетчер switch sub_481CE0 ─────────────────────────────────
    constexpr DWORD kSite    = 0x00481D3F;                     // mov eax,[ebp-14h] ; movzx ecx,byte_48210C[eax] ; jmp jpt[ecx*4]
    constexpr DWORD kSiteLen = 17;                             // jmp rel32 + 12 nop
    const BYTE kSiteOrig[kSiteLen] =
    {
        0x8B, 0x45, 0xEC,                                      // mov   eax, [ebp-14h]          (подкласс − 4)
        0x0F, 0xB6, 0x88, 0x0C, 0x21, 0x48, 0x00,              // movzx ecx, byte ptr [eax+48210Ch]
        0xFF, 0x24, 0x8D, 0xF0, 0x20, 0x48, 0x00               // jmp   dword ptr [ecx*4+4820F0h]
    };

    // ── соседи (только сверка, не пишутся) ───────────────────────────────────
    //   Пролог и чтение подкласса 0x481CE0…0x481D3F: кадр [ebp-10h] = this, [ebp-0Ch] = CUser (sub_5324A0), [ebp-4] = 0
    //   (сумма), [ebp-14h] = CUser+0x191 − 4, ja 0x4820C4 при > 0x18.
    constexpr DWORD kHeadSite = 0x00481CE0;
    const BYTE kHeadOrig[] =
    {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x89, 0x4D, 0xF0, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8B,
        0x45, 0x08, 0x50, 0x8B, 0x4D, 0xF0, 0x8B, 0x51, 0x04, 0x8B, 0x4A, 0x34, 0xE8, 0x8F, 0x07, 0x0B,
        0x00, 0x89, 0x45, 0xF4, 0x83, 0x7D, 0xF4, 0x00, 0x75, 0x05, 0xE9, 0xC8, 0x03, 0x00, 0x00, 0x8B,
        0x45, 0xF4, 0x0F, 0xB6, 0x88, 0x91, 0x01, 0x00, 0x00, 0x89, 0x4D, 0xEC, 0x8B, 0x55, 0xEC, 0x83,
        0xEA, 0x04, 0x89, 0x55, 0xEC, 0x83, 0x7D, 0xEC, 0x18, 0x0F, 0x87, 0x85, 0x03, 0x00, 0x00
    };
    constexpr DWORD kLabel99   = 0x004820C6;                   // LABEL_99: mov edx,[ebp-0Ch] (0x4820C9 — площадка P87)
    const BYTE kLabel99Orig[3] = { 0x8B, 0x55, 0xF4 };
    constexpr DWORD kEpilogue  = 0x004820E7;                   // mov esp,ebp ; pop ebp ; retn 8
    const BYTE kEpilogueOrig[6] = { 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };
    constexpr DWORD kJpt = 0x004820F0;                         // jpt_481D49: 4, 6, 15, 17, 26, 28, default
    const BYTE kJptOrig[28] =
    {
        0x50, 0x1D, 0x48, 0x00, 0xE9, 0x1D, 0x48, 0x00, 0x82, 0x1E, 0x48, 0x00, 0x1B, 0x1F, 0x48, 0x00,
        0xB4, 0x1F, 0x48, 0x00, 0x47, 0x20, 0x48, 0x00, 0xC4, 0x20, 0x48, 0x00
    };
    constexpr DWORD kIdx = 0x0048210C;                         // byte_48210C: (подкласс − 4) → номер ветки jpt
    const BYTE kIdxOrig[25] =
    {
        0x00, 0x06, 0x01, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x02, 0x06,
        0x03, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x04, 0x06, 0x05
    };
    // Ветки switch 0x481D50…0x4820C6 (886 б: суммы категорий и 24 сравнения пар) — их логику P89 повторяет для журнала и
    //   решения стока; сверка по FNV-1a (три образа одинаковы, verify_p89).
    constexpr DWORD kCasesLo   = 0x00481D50;
    constexpr DWORD kCasesHi   = 0x004820C6;
    constexpr DWORD kCasesFnv  = 0x6299432F;

    // ── данные GameServer ──────────────────────────────────────────────────────
    constexpr int   kOffSubJob   = 0x191;                      // CUser: подкласс 4-й профессии (Nick_name_[13])
    constexpr int   kOffJob      = 0x190;                      // CUser: основной класс (Nick_name_[12])
    constexpr int   kOffCatPts   = 0xC024;                     // CUser: очки категории c — +0xC024 + 4·c (39 категорий)
    constexpr int   kOffSkillId  = 0xC0C0;                     // CUser: навык id — +0xC0C0 + 38·id (> 0 — навык есть)
    constexpr int   kSkillStride = 38;
    constexpr int   kOffUserIdx  = 0x174;                      // CUser: UserIndex (учётка)
    constexpr int   kOffCharSlot = 0x18C;                      // CUser: слот персонажа
    constexpr DWORD kSkillCount  = 0x005F5ECC;                 // dword_5F5ECC — число записей SkillInfo (граница sub_475650)
    constexpr DWORD kRowTable    = 0x00600B60;                 // ChangeJobAddSkillTable: 39 записей по 8 б (+0 i16 n, +4 i16*)
    constexpr int   kRowStride   = 8;
    constexpr int   kRowCount    = 39;
    constexpr DWORD kP87Site     = 0x004820C9;                 // площадка P87 (jmp в DLL — строку выбирает P87)
    constexpr int   kGateSum     = 60;                         // порог суммы обычных деревьев (cmp [ebp-4], 3Ch)
    constexpr int   kOpSkillList = 5252;                       // опкод выдачи навыков (для журнала)

    // Виды журнала ac.other (реестр ac-journal-p53.md §9.1, выданы координатором: P89 — 112–114).
    constexpr BYTE kKindDiverge = 112;                         // гейт по ветке ≠ гейт стока
    constexpr BYTE kKindOwned   = 113;                         // строка подкласса уже выдана целиком — повтор не выдан
    constexpr BYTE kKindFault   = 114;                         // исключение — ветка стока

    typedef void (__cdecl *FnSrvLog)(int cat, const char* fmt, ...);                                         // sub_569DF0
    FnSrvLog const pSrvLog = (FnSrvLog)Srv::kLog;

    int  g_mode      = 1;                                      // 1 — решение по ветке; 0 — только журнал (сток)
    bool g_skipOwned = true;                                   // повтор уже выданной строки подкласса не выдавать
    DWORD g_modLo = 0, g_modHi = 0;                            // границы образа этой DLL (проверка «P87 стоит»)
    P89_Stats g_stats = {};                                    // счётчики (экспорт P89_GetStats)

    // Ветка подкласса: первая категория обычных деревьев, пара стока, своя категория 4-й профессии. false — не 4-я профессия.
    bool Branch(int sub, int& firstCat, int& stockA, int& stockB, int& ownCat)
    {
        switch (sub)
        {
        case 4:  case 6:  firstCat = 1; stockA = 10; stockB = 11; ownCat = 10; return true;   // боец
        case 15: case 17: firstCat = 4; stockA = 12; stockB = 13; ownCat = 11; return true;   // лучник
        case 26: case 28: firstCat = 7; stockA = 14; stockB = 15; ownCat = 12; return true;   // маг
        }
        return false;
    }

    // Площадка P87 ведёт в эту DLL — LABEL_99 выдаёт строку подкласса (если она непуста).
    bool P87Installed()
    {
        const BYTE* p = (const BYTE*)kP87Site;
        if (p[0] != 0xE9) { return false; }
        const DWORD to = kP87Site + 5 + *(const INT32*)(p + 1);
        return to >= g_modLo && to < g_modHi;
    }

    // Все навыки строки подкласса уже есть у персонажа. n — навыков в строке (0 — строки нет).
    bool RowOwned(const BYTE* user, int sub, int& n)
    {
        n = 0;
        if (sub < 1 || sub > kRowCount) { return false; }
        n = *(const short*)(kRowTable + kRowStride * (sub - 1));
        const short* codes = *(short* const*)(kRowTable + kRowStride * (sub - 1) + 4);
        if (n <= 0 || !codes) { n = n < 0 ? 0 : n; return false; }
        const int skills = *(const int*)kSkillCount;
        for (int i = 0; i < n; ++i)
        {
            const int id = codes[i];
            if (id < 500 || id >= skills) { return false; }    // вне границ sub_475650 — решает сток
            if (*(const int*)(user + kOffSkillId + kSkillStride * id) <= 0) { return false; }
        }
        return true;
    }

    // Строка журнала ac.other + строка Log_Operator.
    void Report(BYTE kind, const BYTE* user, int userNum, int sub, int a3, int sum, int own, int ownPts, int stockGrant,
                int fixGrant, int rowN)
    {
        int account = AcJournal::kNone, slot = AcJournal::kNone, job = -1;
        char name[24] = "?";
        __try
        {
            account = *(const int*)(user + kOffUserIdx);
            slot    = user[kOffCharSlot];
            job     = user[kOffJob];
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
        e.v[0] = sub;                                          // item_code: подкласс CUser+0x191
        e.v[1] = sum;                                          // value1:    сумма очков обычных деревьев ветки
        e.v[2] = kind == kKindOwned ? rowN : ownPts;           // value2:    очки своей категории (113 — навыков в строке)
        char t[96];
        _snprintf_s(t, sizeof(t), _TRUNCATE, "P89 sub %d job %d a3 %d sum %d cat %d=%d stock %d fix %d n %d mode %d",
                    sub, job, a3, sum, own, ownPts, stockGrant, fixGrant, rowN, g_mode);
        AcJournal::CopyText(e, t);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }

        __try
        {
            const char* what = kind == kKindDiverge ? (g_mode ? "branch gate applied (stock differs)" : "JOURNAL ONLY: branch gate differs from stock")
                             : kind == kKindOwned   ? (g_mode ? "subclass row already owned - repeat not granted" : "JOURNAL ONLY: subclass row already owned")
                             : "FAULT - stock branch";
            pSrvLog(Srv::kLogCatOperator, "P89 Job4GateBranch: UserNum %d (UserIndex %d, CharN %s) SubJob %d a3 %d sum %d cat%d=%d "
                    "stock %d branch %d row %d: %s", userNum, account == AcJournal::kNone ? -1 : account, name, sub, a3, sum,
                    own, ownPts, stockGrant, fixGrant, rowN, what);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // Адрес ветки стока для (подкласс − 4) из его же таблиц byte_48210C / jpt_481D49.
    DWORD StockTarget(int idx)
    {
        const BYTE k = *(const BYTE*)(kIdx + idx);
        return *(const DWORD*)(kJpt + 4 * k);
    }
}

// ── C-часть трамплина площадки 0x481D3F (диспетчер switch sub_481CE0) ─────────────────────────────────────────────
//   skill — CSkillManager (this, [ebp-10h]); user — CUser ([ebp-0Ch]); userNum — a2 ([ebp+8]); a3 — 1 смена профессии /
//   0 изучение навыка ([ebp+0Ch]). Возврат: адрес продолжения — ветка стока, LABEL_99 0x4820C6 или эпилог 0x4820E7.
extern "C" DWORD __stdcall P89_Dispatch(BYTE* skill, BYTE* user, int userNum, int a3)
{
    (void)skill;
    InterlockedIncrement(&g_stats.seen);
    int sub = -1, idx = 0;
    DWORD stockTo = kEpilogue;
    __try
    {
        sub = user[kOffSubJob];
        idx = sub - 4;                                         // сток: ja 0x4820C4 отсёк > 0x18 — сюда только 0…0x18
        if (idx < 0 || idx > 0x18) { return 0x004820C4; }      // не бывает (беззнаковое сравнение стока) — default стока
        stockTo = StockTarget(idx);

        int firstCat = 0, stockA = 0, stockB = 0, own = 0;
        if (!Branch(sub, firstCat, stockA, stockB, own)) { return stockTo; }
        InterlockedIncrement(&g_stats.job4);

        const int* cat = (const int*)(user + kOffCatPts);
        int sum = 0;
        for (int c = firstCat; c < firstCat + 3; ++c) { sum += cat[c]; }
        const bool sumOk      = a3 ? sum >= kGateSum : sum == kGateSum;
        const int  stockGrant = (sumOk && cat[stockA] <= 0 && cat[stockB] <= 0) ? 1 : 0;
        const int  fixGrant   = (sumOk && cat[own] <= 0) ? 1 : 0;
        if (stockGrant) { InterlockedIncrement(&g_stats.stockGrant); }
        if (fixGrant)   { InterlockedIncrement(&g_stats.fixGrant); }

        // Повтор уже выданной строки подкласса — только когда строку выбирает P87 (иначе выдаётся строка класса, сток).
        int rowN = 0;
        const int  wantGrant = g_mode ? fixGrant : stockGrant;
        const bool owned     = g_skipOwned && wantGrant && P87Installed() && RowOwned(user, sub, rowN);

        if (stockGrant != fixGrant)
        {
            InterlockedIncrement(&g_stats.diverged);
            Report(kKindDiverge, user, userNum, sub, a3, sum, own, cat[own], stockGrant, fixGrant, rowN);
        }
        if (owned)
        {
            InterlockedIncrement(&g_stats.ownedSkip);
            Report(kKindOwned, user, userNum, sub, a3, sum, own, cat[own], stockGrant, fixGrant, rowN);
        }
        if (!g_mode) { return stockTo; }                       // только журнал: ветка стока, решает его код
        return (fixGrant && !owned) ? kLabel99 : kEpilogue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try { Report(kKindFault, user, userNum, sub, a3, -1, -1, -1, -1, -1, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return stockTo;
    }
}

extern "C" __declspec(dllexport) void __stdcall P89_GetStats(P89_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Трамплин площадки 0x481D3F. Вход по jmp из sub_481CE0: ebp — его кадр ([ebp-10h] this, [ebp-0Ch] CUser, [ebp+8] a2
    //   WORD, [ebp+0Ch] a3), esp = ebp − 14h. Выход — jmp на адрес, который вернул P89_Dispatch (__stdcall чистит 4 аргумента,
    //   esp возвращается к ebp − 14h; eax/ecx/edx/флаги на целях не живые — каждая цель сначала читает кадр).
    __declspec(naked) void DispatchTrampoline()
    {
        __asm
        {
            push  dword ptr [ebp+0x0C]               // a3
            movsx eax, word ptr [ebp+0x08]           // a2 — userNum
            push  eax
            push  dword ptr [ebp-0x0C]               // CUser*
            push  dword ptr [ebp-0x10]               // CSkillManager* (this)
            call  P89_Dispatch
            jmp   eax                                // ветка стока / LABEL_99 0x4820C6 / эпилог 0x4820E7
        }
    }

    // FNV-1a 32 участка образа (сверка веток switch).
    DWORD Fnv(DWORD lo, DWORD hi)
    {
        DWORD h = 0x811C9DC5;
        for (const BYTE* p = (const BYTE*)lo; p < (const BYTE*)hi; ++p) { h = (h ^ *p) * 0x01000193; }
        return h;
    }
}

PatchResult P89_Job4GateBranch()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_mode      = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    g_skipOwned = Config::GetBool(kSec, L"SkipOwnedRow", true);

    // ── сверка ВСЕХ площадок и соседей ДО записи ─────────────────────────────
    const Site sites[] =
    {
        { kSite,      kSiteOrig,     sizeof(kSiteOrig)     },
        { kHeadSite,  kHeadOrig,     sizeof(kHeadOrig)     },
        { kLabel99,   kLabel99Orig,  sizeof(kLabel99Orig)  },
        { kEpilogue,  kEpilogueOrig, sizeof(kEpilogueOrig) },
        { kJpt,       kJptOrig,      sizeof(kJptOrig)      },
        { kIdx,       kIdxOrig,      sizeof(kIdxOrig)      },
    };
    if (!VerifyAllSites(L"P89", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    DWORD fnv = 0;
    __try { fnv = Fnv(kCasesLo, kCasesHi); }
    __except (EXCEPTION_EXECUTE_HANDLER) { fnv = 0; }
    if (fnv != kCasesFnv)
    {
        Log::Line(L"    P89: ветки switch sub_481CE0 0x%08X…0x%08X — FNV 0x%08X, ждём 0x%08X: НЕ сток, не ставится",
                  kCasesLo, kCasesHi, fnv, kCasesFnv);
        return PatchResult::Mismatch;
    }

    HMODULE self = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&P89_Dispatch, &self) && self)
    {
        const BYTE* b = (const BYTE*)self;
        const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(b + ((const IMAGE_DOS_HEADER*)b)->e_lfanew);
        g_modLo = (DWORD)b;
        g_modHi = g_modLo + nt->OptionalHeader.SizeOfImage;
    }

    if (!Hook::WriteJmp(kSite, &DispatchTrampoline, kSiteLen)) { return PatchResult::Failed; }
    Log::Line(L"    P89: sub_481CE0 switch @0x%08X (17 б) -> трамплин 0x%08X: гейт 4-й профессии по своей категории ветки "
              L"(боец 10, лучник 11, маг 12; сток — пары 10/11, 12/13, 14/15); Mode=%d (%s); SkipOwnedRow=%d; P87 %s; "
              L"журнал ac.other 112/113/114", kSite, (DWORD)&DispatchTrampoline, g_mode,
              g_mode ? L"решение по ветке" : L"только журнал", g_skipOwned ? 1 : 0,
              P87Installed() ? L"стоит" : L"не стоит");
    return PatchResult::Applied;
}
