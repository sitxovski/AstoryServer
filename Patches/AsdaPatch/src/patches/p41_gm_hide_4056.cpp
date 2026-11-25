// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P41 — ★ СКРЫТЫЙ ОПЕРАТОР: 4056 («появление»: воскрешение/прыжок/перенос) НЕ УХОДИТ СОСЕДЯМ
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] доводка GM-невидимости (P39/N11/N12, решение владельца «добить до
//  конца», 27.09.2026). Разбор: Reports/owner_0927/gm_hide_npc_2.md §3;
//  документ — AstoryServer/Docs/GameServer/gm-hide-4056-p41.md
//
//  ── ДЕФЕКТ ──
//  Скрытый оператор (CUser+0x3BC3B = 300, пишут только Send_HideCommand@0x54E970 и вход) после
//  смерти ВСЕГДА возрождается «на месте» (RecvCharRegen@0x52A570: оператор → Type 4 →
//  CharRegenSelfPosition@0x52B1C0), и тот рассылает 4056 ВСЕМУ сектору через sub_52E630.
//  Тело 4056 (22 б, sub_531BA0): +0 номер игрока, +2/+4 клетка X/Z, +6 HP, +10 MP, +12 опыт.
//  То есть соседи получают номер скрытого, его точное место и сигнал «здесь появился» —
//  клиент порта (до правки 27.09) играл на этом месте столб света и звук. Признак 244795 ни одно
//  место отправки 4056 не читает (проверено по всем 9 местам, см. таблицу ниже).
//  То же у прыжков/переносов оператора: 4056 уходит СТАРОМУ сектору (всем, кроме себя) с клеткой
//  НОВОГО места — скрытый GM, прыгнувший командой, выдавал, куда прыгнул.
//  [ОРИГИНАЛ] клиента: GameNet_OnLocalPlayerMapEntry@0xF43390 (game_main.c:12871) эффект на
//  персонаже с битом скрытия не играет, бит не снимает; но 2D-звук чужого играет без проверки,
//  а сами данные пакета (номер + клетка) доходят до любого клиента.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Соседям 4056 скрытого оператора НЕ шлём; себе — шлём, как сток (HP/MP/опыт/клетка нужны
//  самому оператору). Условие «скрытый оператор» — ровно как у стоковых гейтов
//  RecvChar_SkillUse@0x46FA4C / RecvChar_SkillUse_0@0x48E60E:
//      IsOperatorIndex(mgr, idx, -1) != 0  &&  word CUser[+0x3BC3B] == 300
//  Чей 4056 — по самому телу (+0 номер игрока): скрываем ровно того, чьё место выдаётся.
//
//  ── ПЛОЩАДКИ (все — `call rel32`, 5 б, подмена цели; переходов внутрь нет — скан .text) ──
//   «сектору, кроме себя» SendPacket_ClippingSectorInOtherUser@0x41EA80 (ecx = объект карты,
//     6 арг. в стеке: сектор, кроме, опкод, длина, тело, 1; ret 18h); this-менеджер — в кадре:
//     0x0052AE41  CharRegenVillageMove@0x52AB80        this [ebp-0x58]
//     0x0052BE8B  CharSoulMateRecallPosition@0x52BAE0  this [ebp-0x78]
//     0x0054EE63  CharJumpCommandPosition_0@0x54EBF0   this [ebp-0x5C]
//     0x0054F2F6  CharJumpCommandPosition@0x54EF50     this [ebp-0x78]
//     0x00550ED9  Send_MoveCommand@0x550A80            this [ebp-0x8C]
//     0x0055E8D7  RecvClient_TargetJump@0x55E4E0 (1)   this [ebp-0x94]
//     0x0055EDBE  RecvClient_TargetJump@0x55E4E0 (2)   this [ebp-0x94]
//     (this = ecx на входе функции: `mov [ebp-X], ecx` в прологе — сверено по всем семи)
//     Скрытый → вызов не делается, возврат как у ret 18h (eax = 1; после вызова eax нигде
//     не читается до перезаписи — сверено).
//   «сектору, включая себя» sub_52E630 (thiscall, ecx = CUserManager, 5 арг.: номер, опкод,
//     длина, тело, 1; ret 14h):
//     0x0052B8D3  CharRegenSelfPosition@0x52B1C0 (Type 1/4/5/6/7 — у оператора всегда 4)
//     0x0055D599  CharRegenVillageMove_1@0x55D2A0 («CharRegenRoseWarPosition»)
//     Скрытый → вместо рассылки ОДИН пакет себе стоковой отправкой SendPacket@0x4C28F0 с
//     теми же аргументами, что у парных мест «себе» (0x52AE1D: op, len, кому=idx, тело,
//     от=idx, 1).
//  Байты функций-получателей (0x41EA80, 0x52E630, 0x4C28F0, 0x5324A0, 0x52ECF0) и всех
//  девяти площадок одинаковы в живом GameServer, живом Indun_GameServer (оба e7b4ac38…) и в
//  нашей базе IDA; с P01…P40 не пересекается (grep адресов по src/patches).
//
//  ── ЧЕСТНЫЙ ПУТЬ НЕ ЗАДЕТ ──
//  Не оператор или не скрыт → хвостовой jmp в стоковую функцию с нетронутыми стеком и ecx.
//
//  ── ДОРАБОТКА 2026-09-27 (ревизия gm_hide_npc_2_REVIEW.md, СРЕДН-1): доотправка 4056 на ПОКАЗЕ ──
//  Пока оператор скрыт, его 4056 «появление» соседям подавляется (выше). Если за это время он
//  умер и возродился, СМЕРТЬ (4053) соседям всё-таки уходит (SendCharDead@0x4CB480 →
//  sub_52E630 без проверки скрытия) — и у соседей он остаётся ТРУПОМ; после GM-прыжка — на СТАРОЙ
//  клетке. Показ (Send_HideCommand@0x54E970, ветка 301) шлёт соседям только 4025 код 301 (13 б:
//  номер, 301, байт) через sub_52E6D0@0x54EB5A — БЕЗ клетки/HP, поэтому рассинхрон держится до
//  следующего пакета состояния.
//  Лечим: каждый подавленный 4056 помечает номер оператора в таблице g_mark (под Interlocked).
//  На показе (перед стоковой отправкой 4025) трамплин на 0x54EB5A: если номер помечен — соседям
//  уходит СВЕЖИЙ 4056 (клетка CUser+0x54E6/0x54E8, HP sub_43CED0, MP sub_43D510, опыт sub_4CABC0,
//  «действие» из зеркала признака CUser+0x54E4) стоковой отправкой sub_52E6D0 (сектору КРОМЕ себя,
//  тот же адресат, что у подавленного 4056), затем пометка снимается. Бит скрытия у соседей ещё
//  стоит — порт эффект/звук не сыграет (гейт OnMapEntryFx), а идущий следом 4025/301 снимет бит и
//  покажет персонажа уже на верной клетке и живым. Раскладку пакета 4056 (22 б) НЕ меняем —
//  собираем ровно так, как CharJumpCommandPosition_0@0x54EBF0. Ключ ResendOnShow (по умолчанию 1).
//  Тайл берём из CUser+0x54E6/0x54E8 (зеркало gap_4954[2930/2932] — то же поле, что кладёт в тело
//  4056 сток; сверено дизасмом Send_HideCommand: a5[1] 4025 читается из CUser+0x54E4).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P41_GmHide4056";

    typedef void* (__thiscall *FnGetUser)(void* mgr, short idx);                          // 0x5324A0
    typedef BOOL  (__thiscall *FnIsOpIdx)(void* mgr, short idx, int a3);                  // 0x52ECF0
    typedef int   (__thiscall *FnSendPkt)(void* net, short op, short len, short to,
                                          void* body, short from, int a7);                // 0x4C28F0
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);                  // 0x569DF0

    const FnGetUser GetUser  = (FnGetUser)Srv::kGetUser;
    const FnIsOpIdx IsOpIdx  = (FnIsOpIdx)Srv::kIsOperatorIndex;
    const FnSendPkt SendPkt  = (FnSendPkt)Srv::kSendPacket;
    const FnSrvLog  SrvLog   = (FnSrvLog)Srv::kLog;

    constexpr int   kOffHide    = 0x3BC3B;   // CUser: word 300 = скрыт (Send_HideCommand 0x54EAAA)
    constexpr short kHidden     = 300;
    constexpr int   kOffNet     = 4;         // CUserManager+4 → сетевой объект (SendPacket)
    constexpr int   kLogCat     = Srv::kLogCatOperator;   // Log_Operator

    DWORD g_pOther = 0x0041EA80;             // SendPacket_ClippingSectorInOtherUser
    DWORD g_pAll   = 0x0052E630;             // sub_52E630 — сектору, включая себя
    DWORD g_pSend6D0 = 0x0052E6D0;           // sub_52E6D0 — сектору КРОМЕ себя (доотправка на показе)

    bool          g_other   = true;          // ключ OtherSector
    bool          g_selfReg = true;          // ключ SelfRegen
    bool          g_resend  = true;          // ключ ResendOnShow (доработка СРЕДН-1)
    bool          g_trace   = true;          // ключ LogEvents
    volatile LONG g_cnt     = 0;

    bool ShouldLog(LONG n) { return g_trace && (n <= 50 || (n % 1000) == 0); }

    // ── Доработка: таблица «чей 4056 был подавлен, пока оператор скрыт» ──
    //   Индекс = userNum (i16). Пишет каждая подавляющая площадка, снимает — показ.
    //   Без блокировок: одна ячейка на номер, атомарный обмен (события редки).
    constexpr int kMarkMax = 8192;           // > предела онлайна (LoginManager cap 550…)
    volatile LONG g_mark[kMarkMax] = { 0 };
    void MarkSet(short num)  { if (num >= 0 && num < kMarkMax) InterlockedExchange(&g_mark[num], 1); }
    bool MarkTake(short num) { return num >= 0 && num < kMarkMax && InterlockedExchange(&g_mark[num], 0) != 0; }

    // ── Хелперы сборки тела 4056 на показе (как CharJumpCommandPosition_0@0x54EBF0) ──
    typedef int       (__thiscall *FnHp)(void* param, short num);   // 0x43CED0 — текущее HP
    typedef short     (__thiscall *FnMp)(void* param, short num);   // 0x43D510 — текущее MP
    typedef long long (__thiscall *FnExp)(void* mgr, short num);    // 0x4CABC0 — опыт (8 б тела)
    typedef int       (__thiscall *FnSnd6D0)(void* mgr, short num, short op, short len, void* body, int flag); // 0x52E6D0
    const FnHp     RHp  = (FnHp)0x0043CED0;
    const FnMp     RMp  = (FnMp)0x0043D510;
    const FnExp    RExp = (FnExp)0x004CABC0;
    const FnSnd6D0 RSnd = (FnSnd6D0)0x0052E6D0;
    constexpr int kOffTileX = 0x54E6;        // CUser: клетка X (i16) — зеркало gap_4954[2930]
    constexpr int kOffTileZ = 0x54E8;        // CUser: клетка Z (i16) — зеркало gap_4954[2932]
    constexpr int kOffState = 0x54E4;        // CUser: зеркало признака показа (поле «действие» 4056)
    constexpr int kOffThr   = 4;             // CUserManager+4 = m_pcThread (сетевой объект)
    constexpr int kOffParam = 24;            // m_pcThread+24 = CParamManager

    // «Скрытый оператор» — как стоковые гейты навыков: оператор по UserIndex И признак 300.
    bool IsHiddenOperator(void* mgr, short idx)
    {
        if (!mgr || idx < 0) { return false; }
        __try
        {
            BYTE* user = (BYTE*)GetUser(mgr, idx);
            if (!user) { return false; }
            if (*(const short*)(user + kOffHide) != kHidden) { return false; }
            return IsOpIdx(mgr, idx, -1) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
}

extern "C"
{
// «Сектору, кроме себя»: 1 — не слать (скрытый оператор), 0 — сток.
int __cdecl P41_OtherGate(int thisOff, BYTE* ebp, const BYTE* body, int site)
{
    if (!g_other || !body) { return 0; }
    void* mgr = nullptr;
    short idx = -1;
    __try { mgr = *(void**)(ebp + thisOff); idx = *(const short*)body; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (!IsHiddenOperator(mgr, idx)) { return 0; }
    MarkSet(idx);   // доработка: 4056 подавлен -> на показе доотправим соседям свежий
    const LONG n = InterlockedIncrement(&g_cnt);
    if (ShouldLog(n))
    {
        SrvLog(kLogCat, "P41: 4056 of hidden operator %d NOT sent to old sector (site 0x%08X, total %ld)",
               (int)idx, (unsigned)site, (long)n);
    }
    return 1;
}

// «Сектору, включая себя»: 1 — отправлено только себе, 0 — сток.
int __cdecl P41_AllGate(void* mgr, int idxArg, int op, int len, void* body, int flag, int site)
{
    if (!g_selfReg || !body) { return 0; }
    short who = -1;
    __try { who = *(const short*)body; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (!IsHiddenOperator(mgr, who)) { return 0; }
    MarkSet(who);   // доработка: воскрешение/RoseWar подавлено соседям -> доотправим на показе
    const short self = (short)idxArg;
    __try
    {
        void* net = *(void**)((BYTE*)mgr + kOffNet);
        SendPkt(net, (short)op, (short)len, self, body, self, flag);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        SrvLog(kLogCat, "P41: exception while sending 4056 to hidden operator %d itself", (int)self);
    }
    const LONG n = InterlockedIncrement(&g_cnt);
    if (ShouldLog(n))
    {
        SrvLog(kLogCat, "P41: 4056 of hidden operator %d sent to himself only (site 0x%08X, total %ld)",
               (int)who, (unsigned)site, (long)n);
    }
    return 1;
}

// ── Доработка: на показе (Send_HideCommand, 4025 код 301) доотправить соседям свежий 4056 ──
//   a5body = тело 4025 ({num, state}); state 301 = показ. Если 4056 этого оператора был
//   подавлен (пометка) — собираем тело 4056 (22 б) как CharJumpCommandPosition_0 и шлём
//   сектору КРОМЕ себя (sub_52E6D0), затем снимаем пометку. Раскладку пакета не меняем.
void __cdecl P41_ShowResend(void* mgr, int arg0, const short* a5body)
{
    if (!g_resend || !mgr) { return; }
    const short num = (short)arg0;
    __try { if (a5body[1] != 301) { return; } }        // не показ (300 = скрытие) — ничего
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!MarkTake(num)) { return; }                    // 4056 не подавлялся — доотправка не нужна
    __try
    {
        BYTE* user = (BYTE*)GetUser(mgr, num);
        if (!user) { return; }
        BYTE body[22];
        memset(body, 0, sizeof(body));
        *(short*)(body + 0)      = num;                                 // +0  номер
        *(short*)(body + 2)      = *(const short*)(user + kOffTileX);   // +2  клетка X
        *(short*)(body + 4)      = *(const short*)(user + kOffTileZ);   // +4  клетка Z
        void* thr   = *(void**)((BYTE*)mgr + kOffThr);
        void* param = *(void**)((BYTE*)thr + kOffParam);
        const int hp = RHp(param, num);                                 // текущее HP
        if (hp <= 0)                                                    // МЕЛК-1: мёртв — «появление»
        {                                                              //   не слать; пометку вернуть,
            MarkSet(num);                                              //   доотправим при оживлении/показе.
            if (ShouldLog(InterlockedIncrement(&g_cnt)))
                SrvLog(kLogCat, "P41: show of dead hidden operator %d — 4056 not resent (HP<=0)", (int)num);
            return;
        }
        *(int*)(body + 6)        = hp;                                  // +6  HP (4 б)
        *(short*)(body + 10)     = RMp(param, num);                     // +10 MP (2 б)
        *(long long*)(body + 12) = RExp(mgr, num);                      // +12 опыт (8 б)
        const short st = *(const short*)(user + kOffState);
        *(short*)(body + 20)     = (st == 200) ? 200 : 0;              // +20 «действие» (как сток)
        RSnd(mgr, num, 4056, 22, body, 1);                             // соседям КРОМЕ себя
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        SrvLog(kLogCat, "P41: exception while resending 4056 for shown operator %d", (int)num);
        return;
    }
    const LONG n = InterlockedIncrement(&g_cnt);
    if (ShouldLog(n))
    {
        SrvLog(kLogCat, "P41: fresh 4056 resent to neighbors on SHOW of operator %d (total %ld)",
               (int)num, (long)n);
    }
}
}

namespace
{
    // ── «сектору, кроме себя»: общий трамплин ──
    // На входе: [esp] = смещение this в кадре, [esp+4] = площадка (VA), [esp+8] = возврат к стоку,
    // [esp+0Ch…+20h] = 6 аргументов 0x41EA80 (тело — [esp+1Ch]); ecx — объект карты.
    __declspec(naked) void OtherCommon()
    {
        __asm
        {
            push  ecx
            push  edx
            push  eax
            // [esp+0Ch]=off [esp+10h]=site [esp+14h]=ret [esp+18h]=сектор … [esp+28h]=тело
            push  dword ptr [esp + 10h]          // site
            push  dword ptr [esp + 2Ch]          // тело (сдвиг +4)
            push  ebp                            // кадр вызывающего
            push  dword ptr [esp + 18h]          // off (сдвиг +0Ch)
            call  P41_OtherGate
            add   esp, 16
            test  eax, eax
            pop   eax
            pop   edx
            pop   ecx
            jnz   Skip
            add   esp, 8                         // off, site
            jmp   dword ptr [g_pOther]           // сток: стек и ecx как у исходного call
        Skip:
            add   esp, 8
            mov   eax, 1
            ret   18h
        }
    }

    // Площадочные стабы: кладут смещение this и адрес площадки, дальше — общий трамплин.
    #define P41_STUB(name, off, site)                  \
        __declspec(naked) void name()                  \
        {                                              \
            __asm { push site }                        \
            __asm { push off }                         \
            __asm { jmp OtherCommon }                  \
        }
    P41_STUB(StubVillage,  -58h, 0052AE41h)
    P41_STUB(StubSoulMate, -78h, 0052BE8Bh)
    P41_STUB(StubJump0,    -5Ch, 0054EE63h)
    P41_STUB(StubJump,     -78h, 0054F2F6h)
    P41_STUB(StubMoveCmd,  -8Ch, 00550ED9h)
    P41_STUB(StubTgtJump1, -94h, 0055E8D7h)
    P41_STUB(StubTgtJump2, -94h, 0055EDBEh)

    // ── «сектору, включая себя»: общий трамплин ──
    // На входе: [esp] = площадка, [esp+4] = возврат, [esp+8…+18h] = 5 аргументов sub_52E630; ecx = mgr.
    __declspec(naked) void AllCommon()
    {
        __asm
        {
            push  ecx
            push  edx
            push  eax
            // [esp+0Ch]=site [esp+10h]=ret [esp+14h]=номер [18h]=опкод [1Ch]=длина [20h]=тело [24h]=флаг
            push  dword ptr [esp + 0Ch]          // site
            push  dword ptr [esp + 28h]          // флаг   (+4)
            push  dword ptr [esp + 28h]          // тело   (+8)
            push  dword ptr [esp + 28h]          // длина  (+0Ch)
            push  dword ptr [esp + 28h]          // опкод  (+10h)
            push  dword ptr [esp + 28h]          // номер  (+14h)
            push  ecx                            // mgr
            call  P41_AllGate
            add   esp, 28
            test  eax, eax
            pop   eax
            pop   edx
            pop   ecx
            jnz   Done
            add   esp, 4                         // site
            jmp   dword ptr [g_pAll]
        Done:
            add   esp, 4
            ret   14h
        }
    }

    #define P41_STUB_ALL(name, site)                   \
        __declspec(naked) void name()                  \
        {                                              \
            __asm { push site }                        \
            __asm { jmp AllCommon }                    \
        }
    P41_STUB_ALL(StubRegenSelf, 0052B8D3h)
    P41_STUB_ALL(StubRoseWar,   0055D599h)

    // ── Доработка: трамплин на 0x54EB5A (стоковый call sub_52E6D0 = 4025 показа) ──
    //   Стоковая раскладка вызова: ecx=mgr; [esp]=ret(0x54EB5F); [esp+4]=arg0(num);
    //   [esp+8]=4025; [esp+0Ch]=13; [esp+10h]=a5body; [esp+14h]=1. Сначала — доотправка
    //   4056 (если оператор показывается и был подавлен), затем стоковая отправка 4025.
    __declspec(naked) void ShowTramp()
    {
        __asm
        {
            push  ecx
            push  edx
            push  eax
            push  dword ptr [esp+0x1C]     // a5body
            push  dword ptr [esp+0x14]     // arg0 (num)
            push  ecx                      // mgr
            call  P41_ShowResend
            add   esp, 12
            pop   eax
            pop   edx
            pop   ecx
            jmp   dword ptr [g_pSend6D0]   // стоковая отправка 4025 -> ret 14h -> 0x54EB5F
        }
    }

    struct P41Site { DWORD va; DWORD target; void (*stub)(); bool all; };
    const P41Site kSites[] =
    {
        { 0x0052AE41, 0x0041EA80, &StubVillage,   false },
        { 0x0052BE8B, 0x0041EA80, &StubSoulMate,  false },
        { 0x0054EE63, 0x0041EA80, &StubJump0,     false },
        { 0x0054F2F6, 0x0041EA80, &StubJump,      false },
        { 0x00550ED9, 0x0041EA80, &StubMoveCmd,   false },
        { 0x0055E8D7, 0x0041EA80, &StubTgtJump1,  false },
        { 0x0055EDBE, 0x0041EA80, &StubTgtJump2,  false },
        { 0x0052B8D3, 0x0052E630, &StubRegenSelf, true  },
        { 0x0055D599, 0x0052E630, &StubRoseWar,   true  },
    };

    // Стоковые байты: E8 + rel32 на цель.
    void MakeCall(BYTE out[5], DWORD va, DWORD target)
    {
        out[0] = 0xE8;
        *(DWORD*)(out + 1) = target - (va + 5);
    }

    // Пролог «this в кадре»: `mov [ebp-X], ecx` = 89 4D xx (disp8) / 89 8D xx xx xx xx (disp32).
    struct ThisSlot { DWORD va; BYTE b[6]; int len; };
    const ThisSlot kThis[] =
    {
        { 0x0052AB86, { 0x89, 0x4D, 0xA8 }, 3 },                         // CharRegenVillageMove    [ebp-58h]
        { 0x0052BAE9, { 0x89, 0x4D, 0x88 }, 3 },                         // CharSoulMateRecall      [ebp-78h]
        { 0x0054EBF6, { 0x89, 0x4D, 0xA4 }, 3 },                         // CharJumpCommandPos_0    [ebp-5Ch]
        { 0x0054EF59, { 0x89, 0x4D, 0x88 }, 3 },                         // CharJumpCommandPos      [ebp-78h]
        { 0x00550A89, { 0x89, 0x8D, 0x74, 0xFF, 0xFF, 0xFF }, 6 },       // Send_MoveCommand        [ebp-8Ch]
        { 0x0055E4E9, { 0x89, 0x8D, 0x6C, 0xFF, 0xFF, 0xFF }, 6 },       // RecvClient_TargetJump   [ebp-94h]
    };
    // Опкод 4056 и длина 22 перед каждой площадкой: `push 16h / push 0FD8h` (6A 16 68 D8 0F 00 00).
    const BYTE k4056Push[7] = { 0x6A, 0x16, 0x68, 0xD8, 0x0F, 0x00, 0x00 };
    const DWORD kPushAt[9] = { 0x0052AE28, 0x0052BE71, 0x0054EE49, 0x0054F2DC, 0x00550EBC,
                               0x0055E8BA, 0x0055EDA1, 0x0052B8C4, 0x0055D58A };
    // Входы получателей (сверка — те ли это функции).
    const BYTE kOtherHead[] = { 0x55, 0x8B, 0xEC };                                  // 0x41EA80
    const BYTE kAllHead[]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8 };  // 0x52E630
    const BYTE kAllRet[]    = { 0xC2, 0x14, 0x00 };                                  // 0x52E688 ret 14h
    const BYTE kOtherRet[]  = { 0xC2, 0x18, 0x00 };                                  // 0x41EC2B ret 18h
    // Доработка: площадка показа — стоковый `call sub_52E6D0` (4025) в Send_HideCommand.
    constexpr DWORD kShowVA = 0x0054EB5A;
    const BYTE kShowCall[5] = { 0xE8, 0x71, 0xFB, 0xFD, 0xFF };                      // call 0x52E6D0
    const BYTE k6D0Head[]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 };                // 0x52E6D0 вход
}

PatchResult P41_GmHide4056()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    g_other   = Config::GetBool(S, L"OtherSector",  true);
    g_selfReg = Config::GetBool(S, L"SelfRegen",    true);
    g_resend  = Config::GetBool(S, L"ResendOnShow", true);
    g_trace   = Config::GetBool(S, L"LogEvents",    true);
    if (!g_other && !g_selfReg && !g_resend)
    {
        Log::Line(L"    P41: OtherSector=0, SelfRegen=0, ResendOnShow=0 — площадки остаются стоковыми");
        return PatchResult::Disabled;
    }

    // Сверка ВСЕГО до первой записи.
    BYTE calls[ARRAYSIZE(kSites)][5];
    Site sites[ARRAYSIZE(kSites) + ARRAYSIZE(kThis) + ARRAYSIZE(kPushAt) + 4 + 2];
    int n = 0;
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        MakeCall(calls[i], kSites[i].va, kSites[i].target);
        sites[n++] = { kSites[i].va, calls[i], 5 };
    }
    for (int i = 0; i < ARRAYSIZE(kThis); ++i) { sites[n++] = { kThis[i].va, kThis[i].b, (SIZE_T)kThis[i].len }; }
    for (int i = 0; i < ARRAYSIZE(kPushAt); ++i) { sites[n++] = { kPushAt[i], k4056Push, sizeof(k4056Push) }; }
    sites[n++] = { 0x0041EA80, kOtherHead, sizeof(kOtherHead) };
    sites[n++] = { 0x0041EC2B, kOtherRet,  sizeof(kOtherRet)  };
    sites[n++] = { 0x0052E630, kAllHead,   sizeof(kAllHead)   };
    sites[n++] = { 0x0052E688, kAllRet,    sizeof(kAllRet)    };
    // Доработка: площадка показа + вход получателя доотправки.
    sites[n++] = { kShowVA,     kShowCall,  sizeof(kShowCall)  };
    sites[n++] = { 0x0052E6D0,  k6D0Head,   sizeof(k6D0Head)   };
    if (!VerifyAllSites(L"P41", sites, n)) { return PatchResult::Mismatch; }

    int done = 0;
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (kSites[i].all ? !g_selfReg : !g_other) { continue; }
        if (!Hook::WriteCall(kSites[i].va, (const void*)kSites[i].stub, 5)) { return PatchResult::Failed; }
        ++done;
    }
    // Доработка: подмена стокового call 4025 на трамплин доотправки 4056.
    if (g_resend)
    {
        if (!Hook::WriteCall(kShowVA, (const void*)&ShowTramp, 5)) { return PatchResult::Failed; }
        ++done;
    }
    Log::Line(L"    P41: 4056 скрытого оператора соседям не уходит: прыжки/переносы (7 мест) %s, "
              L"воскрешение на месте (2 места, себе — отдельно) %s, доотправка 4056 на показе %s; "
              L"площадок поставлено %d",
              g_other ? L"ВКЛ" : L"выкл", g_selfReg ? L"ВКЛ" : L"выкл",
              g_resend ? L"ВКЛ" : L"выкл", done);
    return PatchResult::Applied;
}
