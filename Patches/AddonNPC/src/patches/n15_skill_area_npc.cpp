// Copyright (c) 2026 @sitxovski (Discord)
// n15_skill_area_npc.cpp — ★ ЦЕНТР И РАДИУС ПЛОЩАДНОГО НАВЫКА, сторона NpcServer (N15; остаток меры 9 плана
// античита «серверные лимиты боя», волна В5b, 2026-10-12). Пара к AsdaPatch P56 (GameServer) и N14.
//
// ЧТО УЖЕ ЕСТЬ В СТОКЕ (ничего не меняем; доказано дизасмом трёх образов — отчёт wave_A5b_combat_rest.md)
//   Заявка 8205 (навык игрока, из 5256) и 8940 (навык стража, из 6158) несут iSkillIndex, iUserArrayIndex,
//   iTargetX, iTargetZ — «центр» навыка, который прислал клиент (шапка 5256/6158 байты +3/+5).
//   1) ЦЕНТР ПРОТИВ КАСТЕРА — `sub_42C4B0` (коробка; __userpurge: ecx=дальность навыка `sub_40C0F0`
//      («Skill Distance» = байт слота +0x7A61… с баффами типа 57), ebx=iTargetX, edi=20, esi=Y кастера
//      (+30364), [esp+4]=X кастера (+30360), [esp+8]=iTargetZ). Центр дальше (дальность+20) клеток по любой оси →
//      al=0 → код 10 в ответе 8206/8941 (→ 5257/6159 код 10), целей не обрабатывает. Площадки:
//      `call sub_42C4B0` @0x418912 (SkillStart sub_418670) и @0x415061 (SoulGuarderSkillStart sub_414E10).
//   2) ЦЕЛЬ ПРОТИВ ЦЕНТРА — `sub_4179D0` (игрок) / `sub_414690` (страж), __stdcall(buf, rec, mobs, players):
//      цель дальше (радиус+20) клеток от центра по любой оси → `return 0` БЕЗ строки и без кода — цель
//      молча пропущена (в список результата попадает, урона/эффекта нет). Площадки: `call sub_4179D0`
//      @0x418C72 (цель-игрок) и @0x418F28 (цель-моб); `call sub_414690` @0x415339 и @0x4155B8.
//   Раскладка буфера навыка (a1) — по стокам кадра SkillStart (esp-относительные, v73 = esp+0x25C):
//      игрок: +216 запись кастера (mov [esp+0x334],ebp @0x418813), +221 радиус (byte [esp+0x339] @0x4188B0),
//             +222/+224 iTargetX/iTargetZ (word [esp+0x33A]/[esp+0x33C] @0x4188A0), +304/+306 X/Y цели
//             (word [esp+0x38C]/[esp+0x38E] @0x418B89/@0x418B9E ← запись цели +30360/+30364);
//      страж (буфер = esp+0x41C): +116 кастер (@0x414FB2), +121 радиус (@0x415012), +122/+124 центр
//             (@0x415042/@0x415034), +204/+206 X/Y цели (@0x415263/@0x41524B).
//      sub_4179D0 читает ровно +0xDD/+0xDE/+0xE0/+0x130/+0x132 (@0x4179EF), sub_414690 — +0x79/+0x7A/+0x7C/+0xCC/+0xCE.
//
// ЧТО ДЕЛАЕТ N15
//   • Зеркалит оба молчаливых отказа стока в журнал античита (ac.move_combat, виды 21/22) — тем же
//     приёмом, что N13/N14: подмена цели `call` → стаб → считает то же, что сток, → пишет строку → сток.
//   • Даёт СВОЙ, более строгий допуск: CenterSlackCells / TargetSlackCells (по умолчанию 20 = как сток,
//     то есть ничего не меняется). Если допуск меньше 20 и центр/цель вне (дальность|радиус + допуск) —
//     строка в журнал; при Mode=1 — ШТАТНЫЙ отказ: центр → al=0 (сток ставит код 10), цель → eax=0 без
//     вызова стока (та же молчаливая пропажа цели, что у стока). Mode=0 — только журнал.
//   • Одна строка вида 22 на заявку (цели одного каста идут подряд в одном вызове SkillStart).
//   userNum кастера = WORD запись+0x7864, имя +0x7714 (как у N13/N14); индекс навыка — из кадра вызывающего
//   ([esp+0x1C] у игрока / [esp+0x20] у стража — байты соседей сверяются) и из записи +65540 после центра.
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"
#include "AcJournal.h"
#include <string.h>
#include <stdio.h>

namespace
{
    const wchar_t* kSec = L"N15_SkillArea";

    constexpr int kOffName    = 0x7714;   // запись игрока: имя
    constexpr int kOffUserNum = 0x7864;   // запись игрока: WORD userNum (слот GameServer)
    constexpr int kOffPosX    = 30360;    // запись игрока: WORD X (та же, что сток шлёт в sub_42C4B0)
    constexpr int kOffPosY    = 30364;    // запись игрока: WORD Y
    constexpr int kOffSkill   = 65540;    // запись игрока: WORD индекс навыка текущей заявки (ставится после центра)
    constexpr int kUsers      = 0x226;
    constexpr int kStockSlack = 20;       // допуск стока (edi=20 у центра, «+20» у цели)

    enum SiteKind : int { kCenterPlayer = 1, kCenterGuard, kTargetPlayer, kTargetGuard };

    // Смещения в буфере навыка по виду (игрок / страж).
    struct BufLayout { int caster, radius, cx, cz, tx, tz; };
    const BufLayout kPlayerBuf = { 216, 221, 222, 224, 304, 306 };
    const BufLayout kGuardBuf  = { 116, 121, 122, 124, 204, 206 };

    int  g_mode        = 0;    // 0 журнал / 1 отказ (только для СВОЕГО допуска; отказ стока и так штатный)
    int  g_centerSlack = kStockSlack;
    int  g_targetSlack = kStockSlack;
    volatile LONG g_hits = 0, g_journal = 0, g_refused = 0;

    struct UserState { DWORD lastTargetTick; WORD lastTargetSkill; WORD pad; LONG violations; };
    UserState g_st[kUsers] = {};

    int Abs(int v) { return v < 0 ? -v : v; }
    int Max(int a, int b) { return a > b ? a : b; }

    // Коробка стока sub_42C4B0 один к одному: x∈[cx−tol−extra, cx+tol+extra], y∈[cy−tol−extra, cy+tol+extra].
    bool StockBox(int tol, int x, int extra, int cy, int cx, int y)
    {
        return cx - tol - extra <= x && extra + cx + tol >= x && cy - tol - extra <= y && extra + cy + tol >= y;
    }

    int UserNumOf(const BYTE* rec)
    {
        if (!rec) { return -1; }
        __try { return *(const short*)(rec + kOffUserNum); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    void Journal(BYTE kind, int opcode, const BYTE* rec, int dist, int limit, int skill, const char* text)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kMoveCombat, kind);
        e.opcode = opcode;
        e.w[1]   = GetTickCount();
        e.v[1]   = dist;                 // interval_ms ← расстояние в клетках max(|dx|,|dz|)
        e.v[3]   = limit;                // p_duration ← порог (дальность|радиус + допуск)
        e.v[4]   = skill;                // duration ← индекс навыка
        const int un = UserNumOf(rec);
        e.userNum = (short)un;
        if (un >= 0 && un < kUsers) { e.v[2] = g_st[un].violations; }
        if (rec) { AcJournal::CopyName(e, rec + kOffName); }
        if (text) { AcJournal::CopyText(e, text); }
        InterlockedIncrement(&g_journal);
        AcJournal::Push(e);
    }
    void Bump(const BYTE* rec)
    {
        const int un = UserNumOf(rec);
        if (un >= 0 && un < kUsers) { InterlockedIncrement(&g_st[un].violations); }
    }
}

// Площадки sub_42C4B0 (центр против кастера). Регистры стока: ecx=дальность, ebx=iTargetX, edi=20 (extra),
// esi=Y кастера, ebp=запись кастера; st: [0] адрес возврата, [1] X кастера, [2] iTargetZ, [3…] кадр вызывающего.
// Возврат: 0 — дальше сток (его результат), 1 — отказ (al=0 → код 10).
extern "C" int __stdcall N15_Center(int kind, int dist, int tx, int extra, int cy, const BYTE* caster, const DWORD* st)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        const int cx = (short)st[1], tz = (short)st[2];
        const int frameOff = kind == kCenterPlayer ? 0x1C : 0x20;         // [esp+0x1C] / [esp+0x20] у вызывающего
        const int skill = *(const short*)((const BYTE*)st + 12 + frameOff);
        const int opcode = kind == kCenterPlayer ? 8205 : 8940;
        const int d = Max(Abs(tx - cx), Abs(tz - cy));
        char text[64];
        if (!StockBox(dist, tx, extra, cy, cx, tz))
        {
            // Штатный отказ стока (код 10) — только зеркало.
            Bump(caster);
            _snprintf_s(text, _TRUNCATE, "stock code 10: c=%d,%d p=%d,%d dist=%d", tx, tz, cx, cy, dist);
            Journal(21, opcode, caster, d, dist + extra, skill, text);
            return 0;
        }
        if (g_centerSlack < kStockSlack && !StockBox(dist, tx, g_centerSlack, cy, cx, tz))
        {
            Bump(caster);
            _snprintf_s(text, _TRUNCATE, "N15 slack %d: c=%d,%d p=%d,%d dist=%d", g_centerSlack, tx, tz, cx, cy, dist);
            Journal(21, opcode, caster, d, dist + g_centerSlack, skill, text);
            if (g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Площадки sub_4179D0 / sub_414690 (цель против центра). st: [0] адрес возврата, [1] буфер навыка, [2] запись
// цели (29 б: [0] тип, [1..2] индекс), [3] массив мобов, [4] массив игроков. Возврат: 0 — сток, 1 — eax=0 без стока.
extern "C" int __stdcall N15_Target(int kind, const DWORD* st)
{
    __try
    {
        InterlockedIncrement(&g_hits);
        const BufLayout& L = kind == kTargetPlayer ? kPlayerBuf : kGuardBuf;
        const BYTE* buf = (const BYTE*)st[1];
        const BYTE* rec = (const BYTE*)st[2];
        if (!buf) { return 0; }
        const BYTE* caster = *(const BYTE* const*)(buf + L.caster);
        const int radius = *(const char*)(buf + L.radius);
        const int cx = *(const short*)(buf + L.cx), cz = *(const short*)(buf + L.cz);
        const int tx = *(const short*)(buf + L.tx), tz = *(const short*)(buf + L.tz);
        const int tType = rec ? rec[0] : -1;
        const int tIdx  = rec ? *(const short*)(rec + 1) : -1;
        const int opcode = kind == kTargetPlayer ? 8205 : 8940;
        int skill = 0;
        if (caster) { skill = *(const short*)(caster + kOffSkill); }
        const int d = Max(Abs(tx - cx), Abs(tz - cz));
        // Сток: cx−r−20 > tx → 0; cx+r+20 < tx → 0; то же по z.
        const bool stockFail = (cx - radius - kStockSlack > tx) || (cx + radius + kStockSlack < tx)
                            || (cz - radius - kStockSlack > tz) || (cz + radius + kStockSlack < tz);
        const bool ownFail = g_targetSlack < kStockSlack &&
                             ((cx - radius - g_targetSlack > tx) || (cx + radius + g_targetSlack < tx)
                           || (cz - radius - g_targetSlack > tz) || (cz + radius + g_targetSlack < tz));
        if (!stockFail && !ownFail) { return 0; }
        // Одна строка на заявку: тот же навык того же кастера в пределах 100 мс — не дублируем.
        const int un = UserNumOf(caster);
        const DWORD now = GetTickCount();
        bool write = true;
        if (un >= 0 && un < kUsers)
        {
            UserState& S = g_st[un];
            if (S.lastTargetSkill == (WORD)skill && now - S.lastTargetTick < 100) { write = false; }
            else { S.lastTargetSkill = (WORD)skill; S.lastTargetTick = now; }
        }
        if (write)
        {
            Bump(caster);
            char text[64];
            _snprintf_s(text, _TRUNCATE, "%s t=%d,%d c=%d,%d r=%d tgt=%d/%d", stockFail ? "stock" : "N15",
                        tx, tz, cx, cz, radius, tType, tIdx);
            Journal(22, opcode, caster, d, radius + (stockFail ? kStockSlack : g_targetSlack), skill, text);
        }
        if (!stockFail && ownFail && g_mode == 1) { InterlockedIncrement(&g_refused); return 1; }
        return 0;   // сток сам вернёт 0 при stockFail
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

namespace
{
    DWORD g_pCenter = 0x0042C4B0;   // sub_42C4B0 (userpurge, ret 8)
    DWORD g_pTgtP   = 0x004179D0;   // sub_4179D0 (stdcall, ret 0x10)
    DWORD g_pTgtG   = 0x00414690;   // sub_414690 (stdcall, ret 0x10)

    // Хвост центра: [esp] вид, [esp+4] адрес возврата, [esp+8] X кастера, [esp+12] iTargetZ.
    __declspec(naked) void CenterTail()
    {
        __asm
        {
            pushad                                 // +32
            lea   eax, [esp+36]                    // st → [ret]
            push  eax
            push  ebp                              // запись кастера
            push  esi                              // Y кастера
            push  edi                              // extra (20)
            push  ebx                              // iTargetX
            push  ecx                              // дальность
            push  dword ptr [esp+56]               // вид (32 + 4 + 24 = 60 → [esp+56] после 6 push: 32+24=56 ✓)
            call  N15_Center                       // __stdcall, 28 б
            test  eax, eax
            jnz   refuse
            popad
            add   esp, 4                           // снять вид
            jmp   dword ptr [g_pCenter]            // сток с теми же регистрами/стеком
        refuse:
            popad
            add   esp, 4
            xor   eax, eax                         // al=0 → сток ставит код 10
            ret   8
        }
    }
    __declspec(naked) void St_CenterPlayer() { __asm { push kCenterPlayer } __asm { jmp CenterTail } }
    __declspec(naked) void St_CenterGuard()  { __asm { push kCenterGuard }  __asm { jmp CenterTail } }

    // Хвост цели: [esp] вид, [esp+4] адрес возврата, [esp+8…] a1..a4.
    __declspec(naked) void TargetTail()
    {
        __asm
        {
            pushad
            lea   eax, [esp+36]
            push  eax
            push  dword ptr [esp+36]               // вид
            call  N15_Target                       // __stdcall, 8 б
            test  eax, eax
            jnz   refuse
            popad
            cmp   dword ptr [esp], kTargetPlayer
            je    player
            add   esp, 4
            jmp   dword ptr [g_pTgtG]
        player:
            add   esp, 4
            jmp   dword ptr [g_pTgtP]
        refuse:
            popad
            add   esp, 4
            xor   eax, eax                         // 0 — цель молча пропущена (как у стока)
            ret   0x10
        }
    }
    __declspec(naked) void St_TargetPlayer() { __asm { push kTargetPlayer } __asm { jmp TargetTail } }
    __declspec(naked) void St_TargetGuard()  { __asm { push kTargetGuard }  __asm { jmp TargetTail } }

    struct SiteDef { DWORD va; DWORD target; void* stub; const wchar_t* what; };
    const SiteDef kSites[] =
    {
        { 0x00418912, 0x0042C4B0, (void*)&St_CenterPlayer, L"8205 центр против кастера (SkillStart)" },
        { 0x00415061, 0x0042C4B0, (void*)&St_CenterGuard,  L"8940 центр против кастера (SoulGuarderSkillStart)" },
        { 0x00418C72, 0x004179D0, (void*)&St_TargetPlayer, L"8205 цель-игрок против центра" },
        { 0x00418F28, 0x004179D0, (void*)&St_TargetPlayer, L"8205 цель-моб против центра" },
        { 0x00415339, 0x00414690, (void*)&St_TargetGuard,  L"8940 цель-игрок против центра" },
        { 0x004155B8, 0x00414690, (void*)&St_TargetGuard,  L"8940 цель-моб против центра" },
    };

    // Соседи: байты, на которые опираются регистры/смещения (сверяются, не меняются).
    struct Neighbour { DWORD va; const BYTE* bytes; SIZE_T len; const wchar_t* what; };
    const BYTE kNEdiP[]   = { 0xBF,0x14,0x00,0x00,0x00 };                                           // mov edi,20 @0x41890D
    const BYTE kNCode10P[]= { 0x84,0xC0,0x75,0x09,0xC6,0x44,0x24,0x24,0x0A };                       // test al; jne; mov [esp+0x24],10
    const BYTE kNSkillP[] = { 0x0F,0xB7,0x54,0x24,0x1C };                                           // movzx edx,[esp+0x1C] @0x4188DA
    const BYTE kNEdiG[]   = { 0xBF,0x14,0x00,0x00,0x00 };                                           // @0x415055
    const BYTE kNCode10G[]= { 0x84,0xC0,0x75,0x09,0xC6,0x44,0x24,0x18,0x0A };                       // @0x415066
    const BYTE kNSkillG[] = { 0x0F,0xB7,0x54,0x24,0x20 };                                           // @0x415019
    const BYTE kNCasterP[]= { 0x89,0xAC,0x24,0x34,0x03,0x00,0x00 };                                 // mov [esp+0x334],ebp → +216
    const BYTE kNCenterP[]= { 0x66,0x89,0x8C,0x24,0x3A,0x03,0x00,0x00,0x66,0x89,0xB4,0x24,0x3C,0x03,0x00,0x00 }; // +222/+224
    const BYTE kNRadP[]   = { 0x88,0x94,0x24,0x39,0x03,0x00,0x00 };                                 // +221
    const BYTE kNTx1P[]   = { 0x66,0x89,0x8C,0x24,0x8C,0x03 };                                      // +304 (цель-игрок)
    const BYTE kNTz1P[]   = { 0x66,0x89,0x94,0x24,0x8E,0x03,0x00,0x00 };                            // +306
    const BYTE kNHeadP[]  = { 0x0F,0xBF,0x9D,0xDE,0x00,0x00,0x00,0x0F,0xBE,0x8D,0xDD,0x00,0x00,0x00,
                              0x0F,0xBF,0xBD,0xE0,0x00,0x00,0x00,0x0F,0xBF,0xB5,0x30,0x01,0x00,0x00 }; // sub_4179D0: +222/+221/+224/+304
    const BYTE kNPushP1[] = { 0x8D,0x8C,0x24,0x44,0x02,0x00,0x00,0x51,0x8D,0x94,0x24,0x68,0x02,0x00,0x00,0x52 }; // v72, v73 @0x418C62
    const BYTE kNPushP2[] = { 0x8D,0x84,0x24,0x44,0x02,0x00,0x00,0x50,0x8D,0x8C,0x24,0x68,0x02,0x00,0x00,0x51 }; // @0x418F18
    const BYTE kNCasterG[]= { 0x89,0xAC,0x24,0x90,0x04,0x00,0x00 };                                 // +116 @0x414FB2
    const BYTE kNRadG[]   = { 0x88,0x94,0x24,0x95,0x04,0x00,0x00 };                                 // +121 @0x415012
    const BYTE kNCzG[]    = { 0x66,0x89,0x8C,0x24,0x98,0x04,0x00,0x00 };                            // +124 @0x415034
    const BYTE kNCxG[]    = { 0x66,0x89,0xB4,0x24,0x96,0x04,0x00,0x00 };                            // +122 @0x415042
    const BYTE kNTzG[]    = { 0x66,0x89,0x84,0x24,0xEA,0x04,0x00,0x00 };                            // +206 @0x41524B
    const BYTE kNTxG[]    = { 0x66,0x89,0x94,0x24,0xE8,0x04,0x00,0x00 };                            // +204 @0x415263
    const BYTE kNHeadG[]  = { 0x0F,0xBF,0x5D,0x7A,0x0F,0xBE,0x4D,0x79,0x0F,0xBF,0x7D,0x7C,0x0F,0xBF,0xB5,0xCC,0x00,0x00,0x00 }; // sub_414690
    const BYTE kNPushG[]  = { 0x8D,0x94,0x24,0x04,0x04,0x00,0x00,0x52,0x8D,0x84,0x24,0x28,0x04,0x00,0x00,0x50 }; // @0x415329/@0x4155A8
    const BYTE kNBox[]    = { 0x8B,0x54,0x24,0x04,0x8B,0xC2,0x55 };                                 // sub_42C4B0 пролог
    const Neighbour kNeighbours[] =
    {
        { 0x0041890D, kNEdiP,    sizeof(kNEdiP),    L"8205 центр: mov edi,20 перед call" },
        { 0x00418917, kNCode10P, sizeof(kNCode10P), L"8205 центр: al=0 → код 10" },
        { 0x004188DA, kNSkillP,  sizeof(kNSkillP),  L"8205 центр: индекс навыка [esp+0x1C]" },
        { 0x00415055, kNEdiG,    sizeof(kNEdiG),    L"8940 центр: mov edi,20 перед call" },
        { 0x00415066, kNCode10G, sizeof(kNCode10G), L"8940 центр: al=0 → код 10" },
        { 0x00415019, kNSkillG,  sizeof(kNSkillG),  L"8940 центр: индекс навыка [esp+0x20]" },
        { 0x00418813, kNCasterP, sizeof(kNCasterP), L"8205 буфер +216 = запись кастера" },
        { 0x004188A0, kNCenterP, sizeof(kNCenterP), L"8205 буфер +222/+224 = iTargetX/iTargetZ" },
        { 0x004188B0, kNRadP,    sizeof(kNRadP),    L"8205 буфер +221 = радиус" },
        { 0x00418B89, kNTx1P,    sizeof(kNTx1P),    L"8205 буфер +304 = X цели" },
        { 0x00418B9E, kNTz1P,    sizeof(kNTz1P),    L"8205 буфер +306 = Y цели" },
        { 0x004179EF, kNHeadP,   sizeof(kNHeadP),   L"sub_4179D0 читает +222/+221/+224/+304" },
        { 0x00418C62, kNPushP1,  sizeof(kNPushP1),  L"8205 цель-игрок: push v72, v73" },
        { 0x00418F18, kNPushP2,  sizeof(kNPushP2),  L"8205 цель-моб: push v72, v73" },
        { 0x00414FB2, kNCasterG, sizeof(kNCasterG), L"8940 буфер +116 = запись кастера" },
        { 0x00415012, kNRadG,    sizeof(kNRadG),    L"8940 буфер +121 = радиус" },
        { 0x00415034, kNCzG,     sizeof(kNCzG),     L"8940 буфер +124 = iTargetZ" },
        { 0x00415042, kNCxG,     sizeof(kNCxG),     L"8940 буфер +122 = iTargetX" },
        { 0x0041524B, kNTzG,     sizeof(kNTzG),     L"8940 буфер +206 = Y цели" },
        { 0x00415263, kNTxG,     sizeof(kNTxG),     L"8940 буфер +204 = X цели" },
        { 0x004146AF, kNHeadG,   sizeof(kNHeadG),   L"sub_414690 читает +122/+121/+124/+204" },
        { 0x00415329, kNPushG,   sizeof(kNPushG),   L"8940 цель-игрок: push v58, v59" },
        { 0x004155A8, kNPushG,   sizeof(kNPushG),   L"8940 цель-моб: push v58, v59" },
        { 0x0042C4B0, kNBox,     sizeof(kNBox),     L"sub_42C4B0 пролог" },
    };
}

PatchResult N15_SkillArea()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    if (!Config::GetBool(L"P53_AcJournal", L"Enabled", true))
    {
        Log::Line(L"    N15: журнал P53 выключен — площадок центра/радиуса не ставим (писать некуда)");
        return PatchResult::Disabled;
    }
    g_mode        = Config::GetInt(kSec, L"Mode", 0) == 1 ? 1 : 0;
    g_centerSlack = Config::GetInt(kSec, L"CenterSlackCells", kStockSlack);
    g_targetSlack = Config::GetInt(kSec, L"TargetSlackCells", kStockSlack);
    if (g_centerSlack < 0) { g_centerSlack = 0; }
    if (g_centerSlack > kStockSlack) { g_centerSlack = kStockSlack; }   // мягче стока быть нельзя — сток откажет раньше
    if (g_targetSlack < 0) { g_targetSlack = 0; }
    if (g_targetSlack > kStockSlack) { g_targetSlack = kStockSlack; }

    BYTE orig[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites) + ARRAYSIZE(kNeighbours)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        orig[i][0] = 0xE8;
        const int rel = (int)(kSites[i].target - (kSites[i].va + 5));
        memcpy(orig[i] + 1, &rel, 4);
        sites[i].va = kSites[i].va; sites[i].orig = orig[i]; sites[i].len = 5;
    }
    for (int i = 0; i < ARRAYSIZE(kNeighbours); ++i)
    {
        Site& s = sites[ARRAYSIZE(kSites) + i];
        s.va = kNeighbours[i].va; s.orig = kNeighbours[i].bytes; s.len = kNeighbours[i].len;
    }
    if (!VerifyAllSites(L"N15", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    memset(g_st, 0, sizeof(g_st));
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!Hook::WriteCall(kSites[i].va, kSites[i].stub, 5)) { return PatchResult::Failed; }
    }
    Log::Line(L"    N15: площадок %d (центр 8205/8940 ×2, цель против центра ×4); Mode=%d (%s); "
              L"CenterSlackCells=%d; TargetSlackCells=%d (20 = допуск стока, журнал только зеркалит штатные отказы)",
              (int)ARRAYSIZE(kSites), g_mode, g_mode ? L"отказ штатным путём при своём допуске" : L"только журнал",
              g_centerSlack, g_targetSlack);
    return PatchResult::Applied;
}
