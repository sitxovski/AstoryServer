// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P34 — ★ ФИКСИРОВАННЫЕ ОПЦИИ ОЖЕРЕЛИЙ, КОТОРЫЕ СЕРВЕР НЕ ПРИМЕНЯЛ
//  (решение владельца 25.09.2026: серверный патч одобрен).
//
//  ЭТО НАША ПРАВКА. Разбор: Reports/gear_upgrade/option_types_server_map.md
//  (§1, §5) и итог этой волны Reports/gear_upgrade/p34_necklace.md,
//  документ патча: AstoryServer/Docs/GameServer/necklace-fixed-options-p34.md
//
//  Фиксированная опция предмета — item_table +12 (тип, u8 при загрузке) и +14
//  (значение, i32), загрузчик sub_4A96A0. GameServer суммирует её вместе с
//  парами доп-опций в sub_445DD0 (3 блока: коды аксессуаров CUser+0x2D9/+0x312/
//  +0x34B — те же, что уходят в 8101/8305 по смещениям +61/+65/+69) — но ТОЛЬКО
//  для тех типов, которые сам спрашивает (83 вызова, все литералы). Типы 4, 24,
//  61 не спрашивает никто → у 8 + 13 + 2 ожерелий строка в подсказке есть,
//  эффекта нет.
//
//  Ключи (секция [P34_NecklaceFixedOptions]):
//    CritToBattleServer — тип 4 «Крит при атаке %». Крит считает NpcServer
//        (sub_457280 / sub_459C50) по сырым парам из 8101/8305: каждая пара
//        с типом 4 прибавляется к шансу (sub_457280 — зажим 100 по шагам,
//        sub_459C50 — итог режется до 75). Фиксированную опцию туда
//        никто не кладёт. Патч дописывает её в ТОТ ЖЕ массив пар 50×(тип,знач)
//        готовой записи 370 б (свободная пара — тип <= 0, пустая у сервера = −1; иначе слияние с
//        существующей парой типа 4) — ровно тот путь, которым приходит крит
//        с любой другой вещи. Размер и раскладка пакета не меняются, NpcServer
//        не трогается.
//    DropRateStat — тип 61 «Шанс выпадения трофея %». Бонус дропа у сервера
//        один: CUser+0x46F (sub_43F790: сумма самоцветов Cellob вида 7,
//        sub_44B0D0), уходит в NpcServer (8101/8305/8209 → игрок+30852) и там
//        множит КАЖДЫЙ шанс дропа: rate·(1 + x/100) (sub_42E3A0 — броски
//        Process_MonsterDead sub_437A30, sub_45C8B0, кража навыком sub_4353F0/
//        sub_435640). Патч прибавляет к полю sub_445DD0(idx, 61) — штатную сумму
//        GameServer по типу (пары 11 слотов + фиксированная опция 3 аксессуаров),
//        так же, как считаются HP (5/303), стихии и прочие статы.
//
//  ★ 26.09: тип 24 лечит P36 (p36_craft_success_option.cpp, решение владельца —
//  порог ступени × (1 + N/100)). Ниже — исходное обоснование P34.
//  Тип 24 «Успешное изготовление %» НЕ ЛЕЧИТСЯ: у сервера нет ни одного
//  модификатора шанса ремесла (RecvUser_CraftEnter @0x53DBA0 — пороги рецепта
//  против sub_5329A0(0,100000), без бонусов игрока), формулу пришлось бы
//  выдумать. Вопрос владельцу — в отчёте p34_necklace.md §4.
//
//  ★ Площадки (3), сверены побайтно: наш RE/ida/server_work/GameServer.exe,
//  ЖИВОЙ v2\GameServer\GameServer.exe и v2\Indun_GameServer\GameServer.exe
//  (все MD5 E7B4AC38…) и сток GameServer.exe_before_mine_patch.exe.
//  Переходов внутрь площадок нет (полный скан .text). С другими патчами
//  не пересекаются.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* const S = L"P34_NecklaceFixedOptions";

    // ── функции и данные GameServer ─────────────────────────────────────────
    typedef BOOL  (__cdecl    *FnIsItemCode)(int code);                              // 0x532A90
    typedef int   (__thiscall *FnOptSum)(void* paramMgr, short idx, short type);     // 0x445DD0, ret 8
    typedef void* (__cdecl    *FnMemcpy)(void* dst, const void* src, size_t n);      // 0x56A040
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);             // 0x569DF0

    const FnIsItemCode SrvIsItemCode = (FnIsItemCode)Srv::kIsItemCode;
    const FnOptSum     SrvOptSum     = (FnOptSum)0x00445DD0;
    const FnMemcpy     SrvMemcpy     = (FnMemcpy)Srv::kMemcpy;
    const FnSrvLog     SrvLog        = (FnSrvLog)Srv::kLog;

    constexpr DWORD kItemTablePtr = 0x005F5E98;   // dword_5F5E98 — база item_table (asm 0x445F2F)
    constexpr int   kItemRec      = 71;           // 0x47 — запись item_table
    constexpr int   kItemFixType  = 12;           // +12 WORD  фиксированная опция: тип
    constexpr int   kItemFixValue = 14;           // +14 DWORD фиксированная опция: значение

    // Запись игрока в 8101/8305 (370 б) — снято с обоих упаковщиков:
    //   +61/+65/+69  DWORD коды аксессуаров слотов 5/6/7 (у 8305 [ebp-0x143…-0x13B])
    //   +132         50 × (i16 тип, i16 значение), слоты 0…9 по 5 пар (у 8305 [ebp-0xFC])
    constexpr int   kRecAccCode0  = 61;
    constexpr int   kRecPairs     = 132;
    constexpr int   kPairCount    = 50;
    constexpr int   kPairsPerSlot = 5;
    constexpr int   kFirstAccSlot = 5;

    constexpr short kOptCrit      = 4;            // «Крит при атаке %»
    constexpr short kOptDrop      = 61;           // «Шанс выпадения трофея %»

    bool g_crit = true;
    bool g_drop = true;

    constexpr LONG kBusyLogMax  = 20;             // предел строк «пары заняты» в Log_Item
    volatile LONG  g_busyLogged = 0;

    // адреса возврата трамплинов (читаются из naked-кода как [переменная])
    DWORD g_p8305Next = 0x004C6B61;   // вслед за `je` — ветка 8305 (a3 != 0)
    DWORD g_p8305Je   = 0x004C6B98;   // цель `je` — ветка 8101 (a3 == 0)
    DWORD g_pDropRet  = 0x0043F805;   // `mov [ebp-0xC], eax` — флаги от нашего add

    short ClampI16(int v)
    {
        if (v >  32767) { return  32767; }
        if (v < -32768) { return -32768; }
        return (short)v;
    }

    // ★ Ревизия К-1: ПУСТАЯ пара у сервера — тип −1 (0xFFFF), а не 0: конструктор
    //   пары sub_40C8B0 пишет (−1,−1), предмет sub_40A9F0 создаёт 5 таких пар,
    //   сброс CUser sub_4B2970, снятие вещи sub_4D6540 и создание sub_5340B0
    //   (пары 2…4) оставляют (−1,−1). Клиент пустым считает OptId <= 0.
    //   Ни один потребитель пар в NpcServer на тип <= 0 не реагирует: все
    //   сравнивают с конкретными типами (4/302, 57, 85/86, 89/90, 91, 94/95),
    //   а switch'и 25…90 и 39…52/316 идут через `sub; cmp; ja` — отрицательное
    //   и 0 уходят в default (0x40CA91, 0x40A945, 0x40BF35).
    inline bool IsFreePair(short t) { return t <= 0; }

    // Дописать значение типа 4 в пары записи. Порядок: (1) свободная пара в
    // собственных 5 парах слота аксессуара, (2) любая свободная пара,
    // (3) слияние с существующей парой типа 4. NpcServer суммирует ВСЕ пары
    // типа 4: sub_457280 — с зажимом 100 на каждом шаге, sub_459C50 — без
    // зажима по шагам, итог режется до 75. От места и числа пар результат для
    // неотрицательных значений не зависит ни там, ни там.
    bool AddCritPair(BYTE* rec, int accSlot, int value)
    {
        short* p = (short*)(rec + kRecPairs);
        const int own = (kFirstAccSlot + accSlot) * kPairsPerSlot;
        for (int i = own; i < own + kPairsPerSlot; ++i)
        {
            if (IsFreePair(p[2 * i])) { p[2 * i] = kOptCrit; p[2 * i + 1] = ClampI16(value); return true; }
        }
        for (int i = 0; i < kPairCount; ++i)
        {
            if (IsFreePair(p[2 * i])) { p[2 * i] = kOptCrit; p[2 * i + 1] = ClampI16(value); return true; }
        }
        for (int i = 0; i < kPairCount; ++i)
        {
            if (p[2 * i] == kOptCrit) { p[2 * i + 1] = ClampI16(p[2 * i + 1] + value); return true; }
        }
        return false;
    }
}

// ═══════════════════════════ C-обработчики ═════════════════════════════════
extern "C"
{
// Тип 4: правка готовой записи 370 б. Повторяет три блока фиксированной опции
// sub_445DD0 (код > 0 и тип == 4 → + значение), плюс проверка кода по таблице
// (sub_532A90), которой у стока нет: чужой код не даст чтения мимо item_table.
void __cdecl P34_FixRecord(BYTE* rec)
{
    if (!g_crit || !rec) { return; }
    __try
    {
        const BYTE* tbl = *(const BYTE**)kItemTablePtr;
        if (!tbl) { return; }
        for (int s = 0; s < 3; ++s)
        {
            const int code = *(const int*)(rec + kRecAccCode0 + 4 * s);
            if (code <= 0 || !SrvIsItemCode(code)) { continue; }
            const BYTE* it = tbl + kItemRec * (code - Srv::kItemCodeBase);
            if (*(const short*)(it + kItemFixType) != kOptCrit) { continue; }
            const int v = *(const int*)(it + kItemFixValue);
            if (v == 0) { continue; }
            if (!AddCritPair(rec, s, v))
            {
                // Запись собирается на каждую смену экипировки/прочности — журнал
                // ограничен первыми kBusyLogMax случаями за время жизни процесса.
                const LONG n = InterlockedIncrement(&g_busyLogged);
                if (n <= kBusyLogMax)
                {
                    SrvLog(Srv::kLogCatItem, "P34: fixed crit option of item %d (value %d) not sent to "
                                             "battle server - all 50 option pairs are busy%s", code, v,
                           n == kBusyLogMax ? " (further messages suppressed)" : "");
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// 8101 из Send_BattleServerToCharParamAll: подмена `call memcpy` @0x004C6276,
// который копирует запись игрока в общий буфер пакета. Сигнатура — как у memcpy.
void* __cdecl P34_Copy8101(void* dst, const void* src, size_t n)
{
    void* r = SrvMemcpy(dst, src, n);
    if (n == 0x172) { P34_FixRecord((BYTE*)dst); }
    return r;
}

// Тип 61: добавка к полю CUser+0x46F. Вызывается из трамплина с кадром
// sub_43F790: [ebp-0x14] = CParamManager (this), [ebp+8] = индекс игрока.
int __cdecl P34_DropAdd(BYTE* ebp)
{
    if (!g_drop) { return 0; }
    __try
    {
        void*       pm  = *(void**)(ebp - 0x14);
        const short idx = *(short*)(ebp + 8);
        if (!pm) { return 0; }
        int v = SrvOptSum(pm, idx, kOptDrop);
        if (v >  30000) { v =  30000; }
        if (v < -30000) { v = -30000; }
        return v;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}
}

namespace
{
    // 8305/8101 из sub_4C62F0: площадка 0x004C6B5B `cmp dword [ebp+0xC],0 / je 0x4C6B98`
    // (6 б) — запись собрана в [ebp-0x180], дальше только отправка одной из
    // двух веток. Регистры и флаги сохраняем, вытесненные инструкции повторяем.
    __declspec(naked) void Tramp8305()
    {
        __asm
        {
            pushad
            pushfd
            lea   eax, [ebp - 0x180]
            push  eax
            call  P34_FixRecord
            add   esp, 4
            popfd
            popad
            cmp   dword ptr [ebp + 0xC], 0                   // вытесненные инструкции
            je    Go8101
            jmp   dword ptr [g_p8305Next]
        Go8101:
            jmp   dword ptr [g_p8305Je]
        }
    }

    // sub_43F790 @0x0043F7FF: `mov eax,[ebp-8] / add eax,[ebp-4]` (6 б) — сумма
    // sub_4437C0 + sub_44B0D0. К ней прибавляем сумму типа 61; `add` последним,
    // чтобы стоковый `jns` @0x43F808 (зажим отрицательного в 0) видел НАШ итог.
    // eax — результат, ecx/edx дальше пишутся до чтения (0x43F811, 0x43F814).
    __declspec(naked) void TrampDrop()
    {
        __asm
        {
            push  ebp
            call  P34_DropAdd
            add   esp, 4
            mov   ecx, eax
            mov   eax, dword ptr [ebp - 8]                   // вытесненные инструкции
            add   eax, dword ptr [ebp - 4]
            add   eax, ecx
            jmp   dword ptr [g_pDropRet]
        }
    }

    const BYTE kCopy8101[5] = { 0xE8, 0xC5, 0x3D, 0x0A, 0x00 };             // 0x4C6276 call memcpy
    const BYTE kSend8305[6] = { 0x83, 0x7D, 0x0C, 0x00, 0x74, 0x37 };       // 0x4C6B5B cmp [ebp+0xC],0; je
    const BYTE kDropSum[6]  = { 0x8B, 0x45, 0xF8, 0x03, 0x45, 0xFC };       // 0x43F7FF mov eax,[ebp-8]; add eax,[ebp-4]
}

PatchResult P34_NecklaceFixedOptions()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    g_crit = Config::GetBool(S, L"CritToBattleServer", true);
    g_drop = Config::GetBool(S, L"DropRateStat",       true);
    if (!g_crit && !g_drop) { return PatchResult::Disabled; }

    // сверка ВСЕХ площадок до первой записи
    const Site sites[] =
    {
        { 0x004C6276, kCopy8101, sizeof(kCopy8101) },
        { 0x004C6B5B, kSend8305, sizeof(kSend8305) },
        { 0x0043F7FF, kDropSum,  sizeof(kDropSum)  },
    };
    if (!VerifyAllSites(L"P34", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    bool ok = true;
    if (g_crit)
    {
        ok &= Hook::WriteCall(0x004C6276, (const void*)&P34_Copy8101, 5);
        ok &= Hook::WriteJmp (0x004C6B5B, (const void*)&Tramp8305,    sizeof(kSend8305));
        Log::Line(L"    P34/тип 4: фиксированный крит аксессуаров дописывается в пары 8101/8305 — "
                  L"8101 (все игроки) @0x004C6276 -> 0x%08X, 8305/8101 (один игрок) @0x004C6B5B -> 0x%08X",
                  (DWORD)&P34_Copy8101, (DWORD)&Tramp8305);
    }
    if (g_drop)
    {
        ok &= Hook::WriteJmp(0x0043F7FF, (const void*)&TrampDrop, sizeof(kDropSum));
        Log::Line(L"    P34/тип 61: к бонусу дропа CUser+0x46F прибавляется sub_445DD0(61) "
                  L"@0x0043F7FF -> 0x%08X", (DWORD)&TrampDrop);
    }
    Log::Line(L"    P34/тип 24: не здесь — см. P36_CraftSuccessOption (решение владельца 26.09).");
    return ok ? PatchResult::Applied : PatchResult::Failed;
}
