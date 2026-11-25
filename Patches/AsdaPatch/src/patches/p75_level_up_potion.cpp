// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P75 — ЗЕЛЬЕ ПОВЫШЕНИЯ УРОВНЯ (функциональный предмет 558, «Level Up Potion»), 2026-10-19.
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] Слово владельца 19.10.2026: «правильно — вычислением нужного опыта». Подсказка клиента:
//  «Зелье, с помощью которого можно дойти до 70 уровня. Каждый персонаж может использовать его только один раз.»
//  Документ: AstoryServer/Docs/GameServer/level-up-potion-p75.md; ревизия Reports/p75_level_up_potion/REVIEW.md.
//  ★ ред. 2 (19.10, ревизия + решение координатора): SQL-часть «один раз» СНЯТА (обёртка UPSkillItemSpend откачена на dev-БД,
//    хэш стока 77CCE1FD сошёлся) — при обрыве между 2140 и 2141 она навсегда запирала зелье без опыта. «Один раз на персонажа»
//    держит гейт уровня шага 1 (после успеха уровень ≥ 70, уровень не убывает — потеря опыта при смерти зажата ExpTable[lvl]).
//    Вместо неё — замок «зелье в пути» на слот (по образцу P63): ставится при уходе 2140 в БД (площадка S 0x4EF02E — уже ПОСЛЕ всех
//    штатных проверок), снимается в шаге 2, по тайм-ауту LockTimeoutMs и на выходе (ClearUserMemory: общая точка P63 →
//    P75_OnUserClear, без P63 — своя площадка 0x527374). Второе 558 при замке — тот же отказ 5451 код 0.
//
//  ── ЧТО В СТОКЕ ──
//  У сервера этой функции нет: строка 558 Function_Table.txt — заглушка `SpecialItem_558`, категория 6 (+8) «+% ОЗ»,
//  значение 60, 1800 с, +37 = 2 (временный бафф). Особой ветки для 558 в Char_FunctionItem_Use@0x4ED780 (5450) и в
//  приёме ответа БД sub_4EF270 нет (GameServer.c:91529–92139, 92143–92809): стоком 558 = бафф «+60 % ОЗ на 30 мин».
//  Поток применения (сток):
//    5450 → Char_FunctionItem_Use: проверки (подпись, состояние, уровень предмета +6/+7, ячейка, откат sub_4F27F0,
//      группа отката +38, цель +24) → в БД 2140 → UPSkillItemSpend (DBManager Recv_FunctionItemSpend, списание в БД) →
//    2141 → sub_4EF270: откат +38, sub_4F2640 (рег. предмета), +37 == 2 → бафф, switch(+8), списание в памяти, 5451 успех.
//    Отказ на первом шаге — 5451 с кодом [ebp-0x121] через общий выход 0x4EF0C3 (в БД ничего не уходит, предмет цел).
//
//  ── ЧТО ДЕЛАЕТ P75 ──
//  Шаг 1 (до БД). Площадка U 0x4EDDC7 `call 0x4F27F0` (проверка отката предмета) → заглушка: для кода ItemCode решает
//    P75_UseGate; отказ — тот же, что у штатных проверок этой функции: [ebp-0x121] = 0 и общий выход 0x4EF0C3 → 5451 код 0
//    (клиент: плашка 12837 «Не удалось использовать инструмент»), в БД ничего не уходит, предмет НЕ тратится.
//    Отказ: уровень ≥ TargetLevel; потолок P29 (imm8 @0x4CBB63) < TargetLevel; ExpTable не годна (нет строки, не растёт,
//    опыт уже ≥ ExpTable[TargetLevel]); запись Function_Table не та (категория ≠ RequireCategory, цель +24 ≠ 1 «на себя»,
//    списание +12 не 1/2). Иначе — штатный sub_4F27F0 (откат) и дальше сток. +37 записи (= 2, «бафф») в ПАМЯТИ
//    приводится к 0 — бафф «+60 % ОЗ» не ставится (файл таблицы не правится; DLL снята — снова сток).
//    Ещё отказ: замок «зелье в пути» этого персонажа (Userindex + Charidx) не снят и не истёк.
//  Площадка S 0x4EF02E (`call 0x5646C0` — уход 2140 «Use» в БД): при коде ItemCode ставит замок слота (тело 2140: +2 Userindex,
//    +6 Charidx, +7 код); дальше — сток. Путь 0x4EEE13 («InvenUse», +25 == 3) зелью закрыт проверкой записи (+25 ≠ 3).
//  Шаг 2 (ответ БД, предмет уже списан в БД). Площадка D 0x4EF606 `call 0x4F2640` → заглушка: сток, затем для ItemCode —
//    начисление ровно ExpTable[TargetLevel] − текущий опыт ШТАТНОЙ функцией Recv_BattleServerFromCharParamExp_1@0x4CBA90
//    в режиме «наградного» опыта (a3 = 0, a5 = 1, a6 = 1.0f — как награды заданий recvDBLimitationResult, GameServer.c:120798):
//    один вызов = ровно один уровень (прибавка зажата диапазоном уровня), повтор до TargetLevel. Каждый уровень — сток:
//    уровень/опыт в CUser, условия славы sub_54A050(6..10), статы класса sub_43AF30, +2 очка навыков sub_52E8A0 (CUser+0x19B, тело 4036 +11)
//    (выше 59 — только с P29), пересчёт sub_443A80/sub_43A3E0, БД 2005 UPLevelUp, LevelUp-лог, NpcServer sub_4C62F0.
//    Множители опыта (события GameServerEvent, зелья опыта 103, бонусы, GetExpUpDownValue) НЕ участвуют: функция зовётся
//    напрямую, как награды. Итог — ровно начало TargetLevel.
//  Сведения клиенту (ключи): SingleLevelUpPacket=1 — 4036 «новый уровень» себе (0x4CBFEC) и сектору (0x4CC009) уходит
//    ОДИН раз — на последнем уровне (сток шлёт на каждом: 58 звуков/эффектов/баннеров подряд); тело то же стоковое (абсолютные
//    уровень/опыт/очки/статы). SuppressSoulJar=1 — кувшин души (Send_SoulJarProcessBarExp, 0x4CC08D/0x4CC27E: +30 % прибавки)
//    от зелья не наполняется (это не опыт боя/заданий; иначе — канал перекачки опыта соулмейту). Площадки опыта — только
//    в рамках начисления P75 на этой нити (TLS), прочий опыт идёт стоком.
//  Журнал: PatchLog + FuncLog сервера (канал 8, рядом с [REQUEST]/[USE] стока). Журнала античита нет (не нарушение).
//  Соседи: P15 0x4ED9EF, P65 0x4EDD82, P08/P49 0x4ED8CF/0x4ED8DE, P29 0x4CBB61 (только читаем imm8) — не пересекаются.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <cstdio>
#include <cstdarg>

namespace
{
    const wchar_t* kSec = L"P75_LevelUpPotion";

    // ── площадки (все `call rel32`, 5 б; сверены на стоке 4e20f0ad, живом GameServer и Indun e7b4ac38) ──────────
    constexpr DWORD kSiteUse    = 0x004EDDC7;   // Char_FunctionItem_Use: call 0x4F27F0 (откат предмета)
    constexpr DWORD kSiteDb     = 0x004EF606;   // sub_4EF270 (ответ БД 2141): call 0x4F2640 (регистрация предмета)
    constexpr DWORD kSiteLvSelf = 0x004CBFEC;   // Recv_BattleServerFromCharParamExp_1: call 0x4C28F0 (4036 себе)
    constexpr DWORD kSiteLvSect = 0x004CC009;   //   … call 0x52E6D0 (4036 сектору кроме себя)
    constexpr DWORD kSiteJarUp  = 0x004CC08D;   //   … call 0x495790 (кувшин души, ветка «новый уровень»)
    constexpr DWORD kSiteJarExp = 0x004CC27E;   //   … call 0x495790 (кувшин души, ветка «опыт без уровня»)
    const BYTE kOrigUse[5]    = { 0xE8, 0x24, 0x4A, 0x00, 0x00 };   // → 0x4F27F0
    const BYTE kOrigDb[5]     = { 0xE8, 0x35, 0x30, 0x00, 0x00 };   // → 0x4F2640
    const BYTE kOrigLvSelf[5] = { 0xE8, 0xFF, 0x68, 0xFF, 0xFF };   // → 0x4C28F0
    const BYTE kOrigLvSect[5] = { 0xE8, 0xC2, 0x26, 0x06, 0x00 };   // → 0x52E6D0
    const BYTE kOrigJarUp[5]  = { 0xE8, 0xFE, 0x96, 0xFC, 0xFF };   // → 0x495790
    const BYTE kOrigJarExp[5] = { 0xE8, 0x0D, 0x95, 0xFC, 0xFF };   // → 0x495790

    // ── соседи (только сверка) ─────────────────────────────────────────────
    // 0x4EDDB5: mov eax,[ebp-16Ch] (код ячейки); push eax; mov cx,[ebp+8]; push ecx; mov ecx,[ebp-2F8h] (this)
    const BYTE kUseArgs[]  = { 0x8B, 0x85, 0x94, 0xFE, 0xFF, 0xFF, 0x50, 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x8D, 0x08, 0xFD, 0xFF, 0xFF };
    // 0x4EDDCC: test eax,eax; jne 0x4EDDE1; mov byte [ebp-121h],8; jmp 0x4EF0C3 — штатный отказ «откат»
    const BYTE kUseAfter[] = { 0x85, 0xC0, 0x75, 0x11, 0xC6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF, 0x08, 0xE9, 0xE7, 0x12, 0x00, 0x00 };
    // 0x4EF0C3: movzx eax, byte [ebp-121h] — общий выход отказа (5451 с этим кодом)
    const BYTE kReject[]   = { 0x0F, 0xB6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF };
    // 0x4EF5F4: mov edx,[ebp-140h] (код); push edx; mov ax,[ebp+8]; push eax; mov ecx,[ebp-288h] (this)
    const BYTE kDbArgs[]   = { 0x8B, 0x95, 0xC0, 0xFE, 0xFF, 0xFF, 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x78, 0xFD, 0xFF, 0xFF };
    // 0x4EF60B: mov ecx,[ebp-140h]; sub ecx,1; imul ecx,ecx,30h; mov edx,[0x5F5E70]; movzx eax,byte[edx+ecx+25h]; cmp eax,2
    const BYTE kDbAfter[]  = { 0x8B, 0x8D, 0xC0, 0xFE, 0xFF, 0xFF, 0x83, 0xE9, 0x01, 0x6B, 0xC9, 0x30, 0x8B, 0x15, 0x70, 0x5E, 0x5F, 0x00,
                               0x0F, 0xB6, 0x44, 0x0A, 0x25, 0x83, 0xF8, 0x02 };
    // 0x4CBFCC: push 1; mov ax,[ebp+8]; push eax; lea ecx,[ebp-78h]; push ecx; mov dx,[ebp+8]; push edx; push 75h; push 0FC4h;
    //           mov eax,[ebp-16Ch]; mov ecx,[eax+4]   — SendPacket(net, 4036, 117, кому, тело, от, 1)
    const BYTE kLvSelfArgs[] = { 0x6A, 0x01, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8D, 0x4D, 0x88, 0x51, 0x66, 0x8B, 0x55, 0x08, 0x52, 0x6A, 0x75,
                                 0x68, 0xC4, 0x0F, 0x00, 0x00, 0x8B, 0x85, 0x94, 0xFE, 0xFF, 0xFF, 0x8B, 0x48, 0x04 };
    // 0x4CBFF1: push 1; lea ecx,[ebp-78h]; push ecx; push 75h; push 0FC4h; mov dx,[ebp+8]; push edx; mov ecx,[ebp-16Ch]
    const BYTE kLvSectArgs[] = { 0x6A, 0x01, 0x8D, 0x4D, 0x88, 0x51, 0x6A, 0x75, 0x68, 0xC4, 0x0F, 0x00, 0x00, 0x66, 0x8B, 0x55, 0x08, 0x52,
                                 0x8B, 0x8D, 0x94, 0xFE, 0xFF, 0xFF };
    // 0x4CC00E: push 1; mov eax,[ebp-128h]; push eax; mov ecx,[ebp-16Ch]; call 0x4C62F0 — после 4036 (eax/ecx/edx не читаются)
    const BYTE kLvAfter[]    = { 0x6A, 0x01, 0x8B, 0x85, 0xD8, 0xFE, 0xFF, 0xFF, 0x50, 0x8B, 0x8D, 0x94, 0xFE, 0xFF, 0xFF };
    // 0x4CC081: …mov ecx,[ebp-16Ch]; mov edx,[ecx+4]; mov ecx,[edx+30h] — кувшин (CSoulMateManager); за вызовом jmp 0x4CC283
    const BYTE kJarUpTail[]  = { 0x8B, 0x8D, 0x94, 0xFE, 0xFF, 0xFF, 0x8B, 0x51, 0x04, 0x8B, 0x4A, 0x30, 0xE8, 0xFE, 0x96, 0xFC, 0xFF,
                                 0xE9, 0xEC, 0x01, 0x00, 0x00 };
    // 0x4CC272: …то же; за вызовом pop edi; pop esi; mov esp,ebp; pop ebp; ret 18h
    const BYTE kJarExpTail[] = { 0x8B, 0x8D, 0x94, 0xFE, 0xFF, 0xFF, 0x8B, 0x51, 0x04, 0x8B, 0x4A, 0x30, 0xE8, 0x0D, 0x95, 0xFC, 0xFF,
                                 0x5F, 0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x18, 0x00 };
    // 0x4CBA90: пролог Recv_BattleServerFromCharParamExp_1 (push ebp; mov ebp,esp; sub esp,174h)
    const BYTE kExpProlog[]  = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x74, 0x01, 0x00, 0x00 };
    // 0x4CBB61: cmp edx, imm8 (потолок — P29 правит imm8 @+2); jl 0x4CBB6B
    const BYTE kCapHead[]    = { 0x83, 0xFA };
    const BYTE kCapTail[]    = { 0x7C, 0x05 };

    // ★ ред. 2: площадка S — уход 2140 «Use» в БД (LABEL_145, после всех штатных проверок шага 1)
    constexpr DWORD kSiteSend = 0x004EF02E;
    const BYTE kOrigSend[5]   = { 0xE8, 0x8D, 0x56, 0x07, 0x00 };   // → 0x5646C0
    // 0x4EF019: call 0x4C0A30 (conn); push eax; push 0C0h (len); push 85Ch (2140); mov ecx, 7E0538h (CUserMoveManager)
    const BYTE kSendArgs[]    = { 0xE8, 0x12, 0x1A, 0xFD, 0xFF, 0x50, 0x68, 0xC0, 0x00, 0x00, 0x00, 0x68, 0x5C, 0x08, 0x00, 0x00,
                                  0xB9, 0x38, 0x05, 0x7E, 0x00 };
    const BYTE kSendAfter[]   = { 0x0F, 0xBF, 0x85, 0x2E, 0xFF, 0xFF, 0xFF };   // 0x4EF033 movsx eax, word [ebp-0D2h]
    const BYTE kDbSendProlog[] = { 0x55, 0x8B, 0xEC };                           // 0x5646C0
    // ★ ред. 2: выход сессии — ClearUserMemory@0x527350, `call sub_569DF0` @0x527374 (та же площадка, что у P63 SessionClear)
    const BYTE kOrigClear[5]  = { 0xE8, 0x77, 0x2A, 0x04, 0x00 };
    const BYTE kClearProlog[] = { 0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC };   // 0x527350
    const BYTE kClearAfter[]  = { 0x83, 0xC4, 0x18 };                           // 0x527379 add esp, 18h

    // ── функции и данные GameServer ─────────────────────────────────────────
    constexpr DWORD kCoolCheck  = 0x004F27F0;   // BOOL __thiscall (mgr, i16 num, u32 code) — ret 8
    constexpr DWORD kFuncReg    = 0x004F2640;   // void __thiscall (mgr, i16 num, u32 code) — ret 8
    constexpr DWORD kReject0    = 0x004EF0C3;   // общий выход отказа Char_FunctionItem_Use
    constexpr DWORD kExpAdd     = 0x004CBA90;   // Recv_BattleServerFromCharParamExp_1 — ret 18h
    constexpr DWORD kGetLevel   = 0x005325F0;   // char    __thiscall (mgr, i16 num) — CUser+0x192
    constexpr DWORD kGetExp     = 0x004CABC0;   // __int64 __thiscall (mgr, i16 num) — CUser+0x193
    constexpr DWORD kGetCharIdx = 0x00532530;   // char    __thiscall (mgr, i16 num) — Charidx персонажа (в теле 2140 +6)
    constexpr DWORD kDbSend     = 0x005646C0;   // int __thiscall (CUserMoveManager*, op, len, conn, body, num) — ret 14h
    constexpr DWORD kClearVa    = 0x00527374;   // ClearUserMemory@0x527350: call sub_569DF0 (выход сессии; общая точка P63)
    constexpr DWORD kGetPoints  = 0x0052EA20;   // i16     __thiscall (mgr, i16 num) — CUser+0x19B (очки навыков; тело 4036 +11)
    constexpr DWORD kSendOther  = 0x0052E6D0;   // int __thiscall (mgr, i16 num, i16 op, i16 len, void* body, int pad) — ret 14h
    constexpr DWORD kSoulJar    = 0x00495790;   // LONG __thiscall (CSoulMateManager*, i16, __int64, int) — ret 10h
    constexpr DWORD kCapImm     = 0x004CBB63;   // imm8 потолка уровня в Recv_BattleServerFromCharParamExp_1 (P29)
    constexpr DWORD kFuncTable  = 0x005F5E70;   // Function_Table: записи по 48 б, (код − 1) · 48
    constexpr DWORD kFuncCount  = 0x005F5EA4;   // число записей Function_Table
    constexpr DWORD kExpTable   = 0x005F5E88;   // ExpTable: [0..N] по 9 б, +1 i64 накопленный опыт; N+1 — dword перед массивом
    constexpr int   kRecLen     = 48;
    constexpr int   kOffCat     = 8;            // +8  категория (switch шагов 1 и 2)
    constexpr int   kOffSpend   = 12;           // +12 списание: 1 — удалить, 2 — минус один, 3 — не тратить
    constexpr int   kOffTarget  = 24;           // +24 цель: 1 — на себя
    constexpr int   kOffBuff    = 37;           // +37 == 2 → временный бафф (sub_4F1890) — единственное чтение @0x4EF61D
    constexpr int   kOffMgr     = 0x34;         // CThread+0x34 → CUserManager (как 0x43CE5E)
    constexpr int   kOffUserIdx = 0x174;        // CUser+0x174 — Userindex (учётка), CUser+0x178 — имя
    constexpr int   kOffName    = 0x178;
    constexpr int   kOffBase36  = 0x42F;        // тело 4036 +13: 36 б (как 0x4CBF9E)
    constexpr int   kOffStat68  = 0x453;        // тело 4036 +49: 68 б (как 0x4CBFB9)
    constexpr int   kSlots      = 0x226;        // 550 слотов CUserManager (sub_5643E0: userNum < 0x226) — размер таблицы замков
    constexpr int   kOffClick   = 25;           // +25 == 3 — путь «InvenUse» (2140 с 0x4EEE13); зелью закрыт
    constexpr short kOp2140     = 2140;         // в БД: списание функционального предмета (UPSkillItemSpend)
    constexpr DWORD kFloatOne   = 0x3F800000;   // a6 = 1.0f, как у наград заданий
    constexpr short kOp4036     = 4036;
    constexpr short kLen4036    = 117;

    typedef BYTE*   (__thiscall *FnGetUser)(void* mgr, short num);
    typedef char    (__thiscall *FnGetLevel)(void* mgr, short num);
    typedef __int64 (__thiscall *FnGetExp)(void* mgr, short num);
    typedef short   (__thiscall *FnGetPoints)(void* mgr, short num);
    typedef char    (__thiscall *FnGetCharIdx)(void* mgr, short num);
    typedef char    (__thiscall *FnExpAdd)(void* mgr, short num, short a3, __int64 gain, int a5, int a6);
    typedef int     (__thiscall *FnSendPacket)(void* net, short op, short len, short to, void* body, short from, int pad);
    typedef int     (__thiscall *FnSendOther)(void* mgr, short num, short op, short len, void* body, int pad);
    typedef void    (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);
    const FnGetUser    GetUser    = (FnGetUser)Srv::kGetUser;
    const FnGetLevel   GetLevel   = (FnGetLevel)kGetLevel;
    const FnGetExp     GetExp     = (FnGetExp)kGetExp;
    const FnGetPoints  GetPoints  = (FnGetPoints)kGetPoints;
    const FnGetCharIdx GetCharIdx = (FnGetCharIdx)kGetCharIdx;
    const FnExpAdd     ExpAdd     = (FnExpAdd)kExpAdd;
    const FnSendPacket SendPacket = (FnSendPacket)Srv::kSendPacket;
    const FnSendOther  SendOther  = (FnSendOther)kSendOther;
    const FnSrvLog     SrvLog     = (FnSrvLog)Srv::kLog;
    constexpr int kLogCatFunc = 8;              // Log\Log_Func\FuncLog_<дата>.txt (сток: [REQUEST]/[DB_SEND]/[USE])

    // адреса для заглушек (косвенные переходы)
    DWORD g_pCoolCheck  = kCoolCheck;
    DWORD g_pFuncReg    = kFuncReg;
    DWORD g_pReject0    = kReject0;
    DWORD g_pSendPacket = Srv::kSendPacket;
    DWORD g_pSendOther  = kSendOther;
    DWORD g_pSoulJar    = kSoulJar;
    DWORD g_pDbSend     = kDbSend;
    DWORD g_pSrvLog     = Srv::kLog;

    // ── настройки ───────────────────────────────────────────────────────────
    int  g_code      = 558;
    int  g_target    = 70;
    int  g_reqCat    = 6;
    bool g_single    = true;
    bool g_noJar     = true;
    bool g_funcLog   = true;
    bool g_trace     = true;
    DWORD g_lockMs   = 15000;                   // тайм-аут замка «в пути» (как P63 LockTimeoutMs)
    bool g_installed = false;                   // патч поставлен (P75_OnUserClear из общей точки P63 — только тогда)
    bool g_clearOwn  = false;                   // площадку ClearUserMemory записал сам P75 (P63 её не держит)

    // ── замок «зелье в пути» на слот: персонаж (Userindex + Charidx), такт постановки (0 — нет) ──
    struct Lock { DWORD tick; int ui; int ci; };
    Lock g_lock[kSlots] = {};
    CRITICAL_SECTION g_cs;
    bool g_csReady = false;

    // ── состояние начисления на нити карты (TLS) ────────────────────────────
    struct GrantTls { int active; int final; int skipped4036; int skippedJar; };
    DWORD g_tls = TLS_OUT_OF_INDEXES;
    volatile LONG g_buffFixed = 0;              // +37 записи приведено к 0 (раз за процесс — в лог)
    volatile LONG g_logN      = 0;
    P75_Stats g_stats = {};

    bool ShouldLog() { const LONG n = InterlockedIncrement(&g_logN); return g_trace && (n <= 2000 || (n % 1000) == 0); }

    GrantTls* Tls()
    {
        if (g_tls == TLS_OUT_OF_INDEXES) { return nullptr; }
        return (GrantTls*)TlsGetValue(g_tls);
    }

    void* MgrOf(void* self)
    {
        __try
        {
            BYTE* thr = *(BYTE**)((BYTE*)self + 4);
            void* mgr = thr ? *(void**)(thr + kOffMgr) : nullptr;
            return mgr ? mgr : self;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return self; }
    }

    BYTE* FuncRec(int code)
    {
        BYTE* t = *(BYTE**)kFuncTable;
        const int n = *(int*)kFuncCount;
        if (!t || code < 1 || code > n) { return nullptr; }
        return t + kRecLen * (code - 1);
    }

    // ExpTable[lvl] (накопленный опыт начала уровня); false — нет таблицы / индекс вне [0..N]
    bool ExpAt(int lvl, __int64* out)
    {
        BYTE* t = *(BYTE**)kExpTable;
        if (!t || lvl < 0) { return false; }
        const int count = *(int*)(t - 4);           // N + 1 (загрузчик sub_4AC640: *(Block) = N + 1, массив с Block+4)
        if (lvl >= count) { return false; }
        *out = *(__int64*)(t + 9 * lvl + 1);
        return true;
    }

    // Причины отказа шага 1 (номер — индекс статистики refused[]).
    enum Refuse { R_None = 0, R_Level = 1, R_Cap = 2, R_Table = 3, R_Record = 4, R_NoUser = 5, R_Fault = 6, R_InFlight = 7 };
    const wchar_t* RefuseText(int r)
    {
        switch (r)
        {
            case R_Level:  return L"уровень уже не ниже целевого";
            case R_Cap:    return L"потолок уровня сервера (P29) ниже целевого";
            case R_Table:  return L"ExpTable не годна (нет строки / не растёт / опыт уже не меньше целевого)";
            case R_Record: return L"запись Function_Table не та (категория / цель / списание)";
            case R_NoUser: return L"персонаж не найден";
            case R_Fault:  return L"исключение при чтении данных";
            case R_InFlight: return L"замок «зелье в пути»: предыдущее применение ещё не вернулось из БД";
        }
        return L"?";
    }

    // Общая проверка условий начисления (шаг 1 и шаг 2). Пишет уровень/опыт/цель для журнала.
    int CheckGrant(void* mgr, short num, int* lvlOut, __int64* expOut, __int64* targetExpOut)
    {
        __try
        {
            BYTE* u = GetUser(mgr, num);
            if (!u) { return R_NoUser; }
            const int lvl = (BYTE)GetLevel(mgr, num);
            const __int64 exp = GetExp(mgr, num);
            *lvlOut = lvl; *expOut = exp;
            if (lvl >= g_target) { return R_Level; }
            if (*(const BYTE*)kCapImm < (BYTE)g_target) { return R_Cap; }
            __int64 et = 0, prev = 0, cur = 0;
            if (!ExpAt(g_target, &et)) { return R_Table; }
            *targetExpOut = et;
            if (exp >= et || exp < 0) { return R_Table; }
            // ExpTable строго растёт от текущего уровня до целевого — иначе вызов зажмёт прибавку в 1 и уровня не даст
            if (!ExpAt(lvl, &prev)) { return R_Table; }
            for (int l = lvl + 1; l <= g_target; ++l)
            {
                if (!ExpAt(l, &cur) || cur <= prev) { return R_Table; }
                prev = cur;
            }
            return R_None;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return R_Fault; }
    }

    // Запись Function_Table годна для P75: категория без отказов шага 2, цель «на себя», списание 1/2.
    //   +37 (бафф) в памяти приводится к 0. Возвращает false — запись не годна.
    bool PrepareRecord(int code)
    {
        __try
        {
            BYTE* r = FuncRec(code);
            if (!r) { return false; }
            if (r[kOffCat] != (BYTE)g_reqCat || r[kOffTarget] != 1 || r[kOffClick] == 3 || (r[kOffSpend] != 1 && r[kOffSpend] != 2)) { return false; }
            if (r[kOffBuff] == 2)
            {
                r[kOffBuff] = 0;
                if (InterlockedExchange(&g_buffFixed, 1) == 0)
                {
                    Log::Line(L"[P75] Function_Table[%d] +37 = 2 (временный бафф стока «+%d %% ОЗ на %u с») -> 0 в памяти "
                              L"(файл таблицы не тронут): зелье — мгновенное, без баффа", code, *(short*)(r + 9), *(DWORD*)(r + 14));
                }
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // Резервный 4036 (стоковая раскладка тела, 0x4CBF82…0x4CC009): если начисление оборвалось ДО последнего уровня,
    //   а промежуточные 4036 были подавлены — клиент и соседи обязаны увидеть фактическое состояние.
    void SendFallback4036(void* mgr, short num)
    {
        __try
        {
            BYTE* u = GetUser(mgr, num);
            if (!u) { return; }
            BYTE body[kLen4036] = {};
            *(short*)body = num;
            body[2] = (BYTE)GetLevel(mgr, num);
            *(__int64*)(body + 3) = GetExp(mgr, num);
            *(short*)(body + 11) = GetPoints(mgr, num);
            memcpy(body + 13, u + kOffBase36, 36);
            memcpy(body + 49, u + kOffStat68, 68);
            void* net = *(void**)((BYTE*)mgr + 4);
            SendPacket(net, kOp4036, kLen4036, num, body, num, 1);
            SendOther(mgr, num, kOp4036, kLen4036, body, 1);
            InterlockedIncrement(&g_stats.fallback4036);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_stats.faults); }
    }

    void FuncLog(const char* fmt, ...)
    {
        if (!g_funcLog) { return; }
        char buf[512];
        va_list ap; va_start(ap, fmt);
        _vsnprintf_s(buf, _TRUNCATE, fmt, ap);
        va_end(ap);
        __try { SrvLog(kLogCatFunc, "%s", buf); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    void NameOf(void* mgr, short num, char* out, int cch)
    {
        out[0] = 0;
        __try
        {
            BYTE* u = GetUser(mgr, num);
            if (u) { lstrcpynA(out, (const char*)(u + kOffName), cch); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
    }

    int UserIndexOf(void* mgr, short num)
    {
        __try { BYTE* u = GetUser(mgr, num); return u ? *(int*)(u + kOffUserIdx) : -1; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    int CharIdxOf(void* mgr, short num)
    {
        __try { return GetUser(mgr, num) ? (BYTE)GetCharIdx(mgr, num) : -1; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    bool SlotOk(int num) { return num >= 0 && num < kSlots; }
    void Lk()   { if (g_csReady) { EnterCriticalSection(&g_cs); } }
    void Unlk() { if (g_csReady) { LeaveCriticalSection(&g_cs); } }

    // Замок активен для этого персонажа (тот же Userindex + Charidx, не истёк). Истёкший / чужой — снимается.
    bool LockActive(int num, int ui, int ci, DWORD* ageMs)
    {
        if (!SlotOk(num)) { return false; }
        bool on = false;
        Lk();
        Lock& L = g_lock[num];
        if (L.tick)
        {
            const DWORD age = GetTickCount() - L.tick;      // модульная разность: переход GetTickCount через 2^32 безопасен
            if (L.ui == ui && L.ci == ci && age < g_lockMs) { on = true; if (ageMs) { *ageMs = age; } }
            else
            {
                if (L.ui == ui && L.ci == ci) { InterlockedIncrement(&g_stats.lockExpired); }
                L.tick = 0; L.ui = 0; L.ci = 0;
            }
        }
        Unlk();
        return on;
    }

    void LockSet(int num, int ui, int ci)
    {
        if (!SlotOk(num)) { return; }
        Lk();
        const DWORD now = GetTickCount();
        g_lock[num].tick = now ? now : 1;
        g_lock[num].ui = ui; g_lock[num].ci = ci;
        Unlk();
        InterlockedIncrement(&g_stats.lockSet);
    }

    // Снять замок слота (ui = −1 — любой персонаж: выход сессии). true — был снят.
    bool LockRelease(int num, int ui, int ci)
    {
        if (!SlotOk(num)) { return false; }
        bool was = false;
        Lk();
        Lock& L = g_lock[num];
        if (L.tick && (ui == -1 || (L.ui == ui && L.ci == ci))) { was = true; L.tick = 0; L.ui = 0; L.ci = 0; }
        Unlk();
        return was;
    }
}

// ── шаг 1: решение по 5450 (зовётся заглушкой площадки U вместо проверки отката) ──
//   1 — отказ (заглушка ставит код 0 и уходит на общий выход 0x4EF0C3), 0 — дальше сток (sub_4F27F0 и т. д.).
//   Строки «пропущено» здесь нет: дальше идут штатные проверки (откат, +6/+7, +38, цель) — строка уходит в FuncLog на
//   площадке S (уход 2140 в БД), когда пройдены и они.
extern "C" int __stdcall P75_UseGate(void* self, int num32, int code)
{
    if (code != g_code) { return 0; }
    const short num = (short)num32;
    InterlockedIncrement(&g_stats.gateSeen);
    void* mgr = MgrOf(self);
    int lvl = -1; __int64 exp = -1, tgt = -1;
    int why = CheckGrant(mgr, num, &lvl, &exp, &tgt);
    if (why == R_NoUser) { return 0; }                     // сток откажет сам (персонажа нет)
    const int ui = UserIndexOf(mgr, num), ci = CharIdxOf(mgr, num);
    DWORD age = 0;
    if (why == R_None && LockActive(num, ui, ci, &age)) { why = R_InFlight; }
    if (why == R_None && !PrepareRecord(code)) { why = R_Record; }
    char name[24]; NameOf(mgr, num, name, sizeof(name));
    if (why != R_None)
    {
        if (why >= 0 && why < 8) { InterlockedIncrement(&g_stats.refused[why]); }
        if (ShouldLog())
        {
            Log::Line(L"[P75] 5450 код %d ОТКАЗ (5451 код 0, предмет цел): userNum %d, Userindex %d, Charidx %d, уровень %d, "
                      L"опыт %I64d, цель %d (%I64d) — %s (возраст замка %u мс)", code, num, ui, ci, lvl, exp, g_target, tgt,
                      RefuseText(why), age);
        }
        FuncLog("\t[P75] LevelUpPotion REFUSE..! %s, UserIndex:%d, CharIdx:%d, Code:%d, Lv:%d, Exp:%I64d, Target:%d, Reason:%d, LockAgeMs:%u",
                name, ui, ci, code, lvl, exp, g_target, why, age);
        return 1;
    }
    InterlockedIncrement(&g_stats.gatePassed);
    return 0;
}

// ── площадка S: 2140 «Use» уходит в БД (все штатные проверки шага 1 пройдены) — замок «зелье в пути» ──
//   Тело 2140 (кадр Char_FunctionItem_Use [ebp-118h]): +2 i32 Userindex (sub_5324F0), +6 u8 Charidx (sub_532530), +7 i32 код.
extern "C" void __stdcall P75_OnDbSend(void* mgrIn, int op, const BYTE* body, int num32)
{
    if ((short)op != kOp2140 || !body) { return; }
    int ui = 0, ci = 0, code = 0;
    __try { ui = *(const int*)(body + 2); ci = body[6]; code = *(const int*)(body + 7); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (code != g_code) { return; }
    const short num = (short)num32;
    LockSet(num, ui, ci);
    void* mgr = MgrOf(mgrIn);
    char name[24]; NameOf(mgr, num, name, sizeof(name));
    int lvl = -1; __int64 exp = -1, tgt = -1;
    __try { lvl = (BYTE)GetLevel(mgr, num); exp = GetExp(mgr, num); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    ExpAt(g_target, &tgt);
    FuncLog("\t[P75] LevelUpPotion DB_SEND..! %s, UserIndex:%d, CharIdx:%d, Code:%d, Lv:%d, Exp:%I64d, Target:%d, NeedExp:%I64d, LockMs:%u",
            name, ui, ci, code, lvl, exp, g_target, tgt - exp, g_lockMs);
}

// ── выход сессии (ClearUserMemory): замок слота снимается. Общая точка P63_OnUserClear или своя площадка 0x527374 ──
extern "C" void __stdcall P75_OnUserClear(int num32)
{
    if (!g_installed) { return; }
    if (LockRelease((short)num32, -1, -1)) { InterlockedIncrement(&g_stats.lockCleared); }
}

// ── шаг 2: после штатной регистрации предмета в ответе БД (предмет в БД уже списан) ──
extern "C" void __stdcall P75_AfterDbUse(void* self, int num32, int code)
{
    if (code != g_code) { return; }
    const short num = (short)num32;
    InterlockedIncrement(&g_stats.dbSeen);
    void* mgr = MgrOf(self);
    PrepareRecord(code);                                   // +37 → 0 до чтения @0x4EF61D (повторно — без вреда)
    char name[24]; NameOf(mgr, num, name, sizeof(name));
    const int ui = UserIndexOf(mgr, num), ci = CharIdxOf(mgr, num);
    int lvl0 = -1; __int64 exp0 = -1, tgt = -1;
    const int why = CheckGrant(mgr, num, &lvl0, &exp0, &tgt);
    if (why != R_None)
    {
        // Нужный опыт ≤ 0 / уровень уже ≥ цели к ответу БД. При замке «в пути» второго 558 в полёте нет, а сам персонаж
        //   до 70 за мс ответа БД не дойдёт — случай невозможен, кроме истечения LockTimeoutMs (ответ БД дольше тайм-аута).
        //   Предмет списан БД — сток доведёт до 5451 успеха; опыт не трогаем.
        InterlockedIncrement(&g_stats.dbNoGrant);
        if (LockRelease(num, ui, ci)) { InterlockedIncrement(&g_stats.lockReleased); }
        Log::Line(L"[P75] ! ответ БД, код %d: начисления НЕТ (предмет уже списан БД): userNum %d, Userindex %d, Charidx %d, "
                  L"уровень %d, опыт %I64d — %s", code, num, ui, ci, lvl0, exp0, RefuseText(why));
        FuncLog("\t[P75] LevelUpPotion NO_GRANT..! %s, UserIndex:%d, CharIdx:%d, Code:%d, Lv:%d, Exp:%I64d, Reason:%d",
                name, ui, ci, code, lvl0, exp0, why);
        return;
    }

    GrantTls st = { 1, 0, 0, 0 };
    if (g_tls != TLS_OUT_OF_INDEXES) { TlsSetValue(g_tls, &st); }
    int calls = 0, lvl = lvl0;
    __int64 exp = exp0;
    bool aborted = false, fault = false;
    __try
    {
        while (lvl < g_target && calls < 200)
        {
            const __int64 gain = tgt - exp;
            if (gain <= 0) { break; }
            st.final = (lvl + 1 >= g_target) ? 1 : 0;
            ExpAdd(mgr, num, 0, gain, 1, (int)kFloatOne);
            ++calls;
            const int nl = (BYTE)GetLevel(mgr, num);
            const __int64 ne = GetExp(mgr, num);
            if (nl <= lvl) { aborted = true; lvl = nl; exp = ne; break; }   // уровня не дал — не крутимся
            lvl = nl; exp = ne;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { aborted = true; fault = true; InterlockedIncrement(&g_stats.faults); }
    if (g_tls != TLS_OUT_OF_INDEXES) { TlsSetValue(g_tls, nullptr); }
    if (fault)
    {
        // Исключение ВНУТРИ штатного кода повышения (или геттеров): состояние могло остаться частичным (уровень записан, пакеты/БД —
        //   нет). Сток упал бы с дампом; здесь процесс жив, но картина — в журнал громко.
        __try { lvl = (BYTE)GetLevel(mgr, num); exp = GetExp(mgr, num); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        Log::Line(L"[P75] !!! ИСКЛЮЧЕНИЕ внутри Recv_BattleServerFromCharParamExp_1 при начислении: userNum %d, Userindex %d, "
                  L"Charidx %d, уровень %d -> %d, опыт %I64d -> %I64d, вызовов %d — состояние могло остаться частичным, "
                  L"РЕКОМЕНДОВАН РЕСТАРТ процесса", num, ui, ci, lvl0, lvl, exp0, exp, calls);
        FuncLog("\t[P75] LevelUpPotion EXCEPTION..! %s, UserIndex:%d, CharIdx:%d, Lv:%d->%d, Exp:%I64d->%I64d, Calls:%d - restart advised",
                name, ui, ci, lvl0, lvl, exp0, exp, calls);
    }
    InterlockedExchangeAdd(&g_stats.levelsGranted, lvl - lvl0);
    InterlockedExchangeAdd(&g_stats.skipped4036, st.skipped4036);
    InterlockedExchangeAdd(&g_stats.skippedJar, st.skippedJar);
    if (LockRelease(num, ui, ci)) { InterlockedIncrement(&g_stats.lockReleased); }

    const bool done = (lvl == g_target && exp == tgt);
    // промежуточные 4036 подавлены, а последнего не было (обрыв) — шлём фактическое состояние стоковым телом
    if (st.skipped4036 > 0 && !(done && st.final)) { SendFallback4036(mgr, num); }
    if (done) { InterlockedIncrement(&g_stats.granted); } else { InterlockedIncrement(&g_stats.grantShort); }
    Log::Line(L"[P75] %s: userNum %d, Userindex %d, Charidx %d, уровень %d -> %d, опыт %I64d -> %I64d (цель %I64d), вызовов %d, "
              L"4036 подавлено %d, кувшин подавлен %d%s",
              done ? L"НАЧИСЛЕНО" : L"! НАЧИСЛЕНО НЕ ПОЛНОСТЬЮ", num, ui, ci, lvl0, lvl, exp0, exp, tgt, calls,
              st.skipped4036, st.skippedJar, aborted ? L" (обрыв цикла)" : L"");
    FuncLog("\t[P75] LevelUpPotion %s..! %s, UserIndex:%d, CharIdx:%d, Code:%d, Lv:%d->%d, Exp:%I64d->%I64d, Calls:%d",
            done ? "GRANT" : "GRANT_SHORT", name, ui, ci, code, lvl0, lvl, exp0, exp, calls);
}

// ── площадки опыта: 1 — 4036 себе, 2 — 4036 сектору, 3 — кувшин души. 1 — не слать (только внутри начисления P75) ──
extern "C" int __stdcall P75_SkipSend(int kind)
{
    GrantTls* st = Tls();
    if (!st || !st->active) { return 0; }
    if ((kind == 1 || kind == 2) && g_single && !st->final)
    {
        if (kind == 1) { ++st->skipped4036; }
        return 1;
    }
    if (kind == 3 && g_noJar) { ++st->skippedJar; return 1; }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P75_GetStats(P75_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Площадка U (0x4EDDC7): вход по `call` вместо sub_4F27F0: ecx = this, [esp] = возврат (0x4EDDCC), [esp+4] = номер,
    //   [esp+8] = код ячейки. Пропуск — хвостовой переход в sub_4F27F0 с тем же стеком/ecx (он сам вернётся на 0x4EDDCC и
    //   снимет 8 б). Отказ — снять возврат и 2 аргумента, [ebp-121h] = 0 (ebp кадра Char_FunctionItem_Use не тронут), на 0x4EF0C3.
    __declspec(naked) void StubUseGate()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+12]            // код
            push  dword ptr [esp+12]            // номер
            push  ecx                           // this
            call  P75_UseGate                   // stdcall, 12 б
            pop   ecx
            test  eax, eax
            jnz   DoRefuse
            jmp   dword ptr [g_pCoolCheck]
        DoRefuse:
            add   esp, 12
            mov   byte ptr [ebp-0x121], 0
            jmp   dword ptr [g_pReject0]
        }
    }

    // Площадка D (0x4EF606): вместо sub_4F2640 — сток с теми же аргументами и ecx, затем P75_AfterDbUse. ret 8, как sub_4F2640.
    __declspec(naked) void StubDbUse()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            push  ecx                           // [ebp-4] = this
            push  dword ptr [ebp+12]            // код
            push  dword ptr [ebp+8]             // номер
            call  dword ptr [g_pFuncReg]        // thiscall, ret 8
            push  dword ptr [ebp+12]
            push  dword ptr [ebp+8]
            push  dword ptr [ebp-4]
            call  P75_AfterDbUse                // stdcall, 12 б
            mov   esp, ebp
            pop   ebp
            ret   8
        }
    }

    // 4036 себе (0x4CBFEC): SendPacket, ret 18h. Внутри начисления P75 и не на последнем уровне — не слать.
    __declspec(naked) void StubLvSelf()
    {
        __asm
        {
            push  ecx
            push  1
            call  P75_SkipSend
            pop   ecx
            test  eax, eax
            jnz   Skip
            jmp   dword ptr [g_pSendPacket]
        Skip:
            xor   eax, eax
            ret   0x18
        }
    }

    // 4036 сектору (0x4CC009): sub_52E6D0, ret 14h.
    __declspec(naked) void StubLvSect()
    {
        __asm
        {
            push  ecx
            push  2
            call  P75_SkipSend
            pop   ecx
            test  eax, eax
            jnz   Skip
            jmp   dword ptr [g_pSendOther]
        Skip:
            xor   eax, eax
            ret   0x14
        }
    }

    // Площадка S (0x4EF02E): вместо sub_5646C0 (thiscall: ecx = CUserMoveManager; [esp+4] op, +8 len, +12 conn, +16 тело,
    //   +20 номер; ret 14h). P75_OnDbSend(mgr = [ebp-2F8h] кадра Char_FunctionItem_Use, op, тело, номер), затем хвостовой
    //   переход в сток со всем стеком и ecx как были.
    __declspec(naked) void StubDbSend()
    {
        __asm
        {
            push  ecx
            push  dword ptr [esp+24]            // номер ([esp+20] до push ecx)
            push  dword ptr [esp+24]            // тело  ([esp+16])
            push  dword ptr [esp+16]            // op    ([esp+4])
            push  dword ptr [ebp-0x2F8]         // this Char_FunctionItem_Use (CUserManager)
            call  P75_OnDbSend                  // stdcall, 16 б
            pop   ecx
            jmp   dword ptr [g_pDbSend]
        }
    }

    // Своя площадка выхода (только если её не держит P63): вместо `call sub_569DF0` в ClearUserMemory@0x527350
    //   (cdecl, стек не трогаем; [ebp+8] = слот i16 кадра ClearUserMemory) — как P63 St_Clear.
    __declspec(naked) void StubClear()
    {
        __asm
        {
            pushad                              // ecx, а не eax: байтовый образ отличен от P63 St_Clear (verify_p63 ищет его по сигнатуре)
            movsx ecx, word ptr [ebp+8]
            push  ecx
            call  P75_OnUserClear               // stdcall, 4 б
            popad
            jmp   dword ptr [g_pSrvLog]
        }
    }

    // Кувшин души (0x4CC08D, 0x4CC27E): Send_SoulJarProcessBarExp, ret 10h.
    __declspec(naked) void StubJar()
    {
        __asm
        {
            push  ecx
            push  3
            call  P75_SkipSend
            pop   ecx
            test  eax, eax
            jnz   Skip
            jmp   dword ptr [g_pSoulJar]
        Skip:
            xor   eax, eax
            ret   0x10
        }
    }
}

// ★ P103 (04.11.2026): цепочка площадки S 0x4EF02E (уход 2140). Если площадку записал P75, P103 байты не пишет, а кладёт свой стаб
//   в «следующий вызов» StubDbSend (как P62/P63 у отправок): P75 → P103 → sub_5646C0. Стек и ecx на входе стаба P103 — стоковые.
const void* P75_DbSendStub() { return g_installed ? (const void*)&StubDbSend : nullptr; }
DWORD P75_ChainDbSend(DWORD next) { const DWORD prev = g_pDbSend; g_pDbSend = next; return prev; }

static bool g_p75Applied = false;   // ★ P127 А2.2: P75 поставлен (адреса опыта сверены)

PatchResult P75_LevelUpPotion()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        Log::Line(L"    P75: выключен — предмет 558 работает как в стоке (заглушка: бафф «+60 %% ОЗ»)");
        return PatchResult::Disabled;
    }
    g_code    = Config::GetInt (kSec, L"ItemCode", 558);
    g_target  = Config::GetInt (kSec, L"TargetLevel", 70);
    g_reqCat  = Config::GetInt (kSec, L"RequireCategory", 6);
    g_single  = Config::GetBool(kSec, L"SingleLevelUpPacket", true);
    g_noJar   = Config::GetBool(kSec, L"SuppressSoulJar", true);
    g_funcLog = Config::GetBool(kSec, L"FuncLog", true);
    g_trace   = Config::GetBool(kSec, L"LogEvents", true);
    const int lockMs = Config::GetInt(kSec, L"LockTimeoutMs", 15000);
    const bool clearOn = Config::GetBool(kSec, L"ReleaseOnExit", true);
    if (lockMs < 1000 || lockMs > 600000) { Log::Line(L"    P75: ! LockTimeoutMs=%d вне 1000..600000 — патч НЕ ставится", lockMs); return PatchResult::Failed; }
    g_lockMs = (DWORD)lockMs;
    if (g_code < 1 || g_code >= 0x258)  { Log::Line(L"    P75: ! ItemCode=%d вне 1..599 — патч НЕ ставится", g_code); return PatchResult::Failed; }
    if (g_target < 2 || g_target > 127) { Log::Line(L"    P75: ! TargetLevel=%d вне 2..127 — патч НЕ ставится", g_target); return PatchResult::Failed; }
    if (g_reqCat < 0 || g_reqCat > 255) { Log::Line(L"    P75: ! RequireCategory=%d вне 0..255 — патч НЕ ставится", g_reqCat); return PatchResult::Failed; }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    Site check[24];
    int  n = 0;
    check[n++] = { kSiteUse,    kOrigUse,    sizeof(kOrigUse)    };
    check[n++] = { 0x004EDDB5,  kUseArgs,    sizeof(kUseArgs)    };
    check[n++] = { 0x004EDDCC,  kUseAfter,   sizeof(kUseAfter)   };
    check[n++] = { kReject0,    kReject,     sizeof(kReject)     };
    check[n++] = { kSiteDb,     kOrigDb,     sizeof(kOrigDb)     };
    check[n++] = { 0x004EF5F4,  kDbArgs,     sizeof(kDbArgs)     };
    check[n++] = { 0x004EF60B,  kDbAfter,    sizeof(kDbAfter)    };
    check[n++] = { kExpAdd,     kExpProlog,  sizeof(kExpProlog)  };
    check[n++] = { 0x004CBB61,  kCapHead,    sizeof(kCapHead)    };
    check[n++] = { 0x004CBB64,  kCapTail,    sizeof(kCapTail)    };
    if (g_single)
    {
        check[n++] = { kSiteLvSelf, kOrigLvSelf, sizeof(kOrigLvSelf) };
        check[n++] = { 0x004CBFCC,  kLvSelfArgs, sizeof(kLvSelfArgs) };
        check[n++] = { kSiteLvSect, kOrigLvSect, sizeof(kOrigLvSect) };
        check[n++] = { 0x004CBFF1,  kLvSectArgs, sizeof(kLvSectArgs) };
        check[n++] = { 0x004CC00E,  kLvAfter,    sizeof(kLvAfter)    };
    }
    if (g_noJar)
    {
        check[n++] = { 0x004CC081,  kJarUpTail,  sizeof(kJarUpTail)  };   // включает площадку 0x4CC08D
        check[n++] = { 0x004CC272,  kJarExpTail, sizeof(kJarExpTail) };   // включает площадку 0x4CC27E
    }
    check[n++] = { kSiteSend,   kOrigSend,   sizeof(kOrigSend)   };
    check[n++] = { 0x004EF019,  kSendArgs,   sizeof(kSendArgs)   };
    check[n++] = { 0x004EF033,  kSendAfter,  sizeof(kSendAfter)  };
    check[n++] = { kDbSend,     kDbSendProlog, sizeof(kDbSendProlog) };
    // выход: площадку ClearUserMemory держит P63 (SessionClear) — P75 зовётся из P63_OnUserClear; иначе — своя
    const bool viaP63 = clearOn && P63_ClearHooked();
    const bool ownClear = clearOn && !viaP63;
    if (ownClear)
    {
        check[n++] = { kClearVa,    kOrigClear,  sizeof(kOrigClear)  };
        check[n++] = { 0x00527350,  kClearProlog, sizeof(kClearProlog) };
        check[n++] = { 0x00527379,  kClearAfter, sizeof(kClearAfter) };
    }
    if (!VerifyAllSites(L"P75", check, n)) { return PatchResult::Mismatch; }
    InitializeCriticalSection(&g_cs);
    g_csReady = true;
    memset(g_lock, 0, sizeof(g_lock));

    g_tls = TlsAlloc();
    if (g_tls == TLS_OUT_OF_INDEXES && (g_single || g_noJar))
    {
        Log::Line(L"    P75: ! TlsAlloc не удался — патч НЕ ставится (без TLS подавление 4036/кувшина задело бы чужой опыт)");
        return PatchResult::Failed;
    }

    // ── запись: сначала площадки опыта (без начисления P75 они — чистый сток), затем шаг 2, последним — шаг 1 ──
    struct W { DWORD va; const void* stub; } writes[8];
    int w = 0;
    if (ownClear) { writes[w++] = { kClearVa, &StubClear }; }
    if (g_single) { writes[w++] = { kSiteLvSelf, &StubLvSelf }; writes[w++] = { kSiteLvSect, &StubLvSect }; }
    if (g_noJar)  { writes[w++] = { kSiteJarUp, &StubJar }; writes[w++] = { kSiteJarExp, &StubJar }; }
    writes[w++] = { kSiteDb,  &StubDbUse };
    writes[w++] = { kSiteSend, &StubDbSend };
    writes[w++] = { kSiteUse, &StubUseGate };
    for (int i = 0; i < w; ++i)
    {
        if (!Hook::WriteCall(writes[i].va, writes[i].stub, 5))
        {
            Log::Line(L"    P75: ! запись @0x%08X не удалась — патч остаётся частично (см. выше), НЕ использовать: Enabled=0 и рестарт",
                      writes[i].va);
            return PatchResult::Failed;
        }
    }

    g_clearOwn  = ownClear;
    g_installed = true;
    const BYTE cap = *(const BYTE*)kCapImm;
    Log::Line(L"    P75: предмет %d «Зелье повышения уровня» — до уровня %d вычислением опыта (ExpTable[%d] - текущий), "
              L"штатным Recv_BattleServerFromCharParamExp_1 (награда, a5=1) по уровню за вызов, без множителей", g_code, g_target, g_target);
    Log::Line(L"    P75: шаг 1 @0x%08X (call 0x4F27F0 -> 0x%08X): отказ 5451 код 0 при уровне >= %d / потолке < %d / негодной "
              L"ExpTable или записи (категория %d, цель «на себя», списание 1/2); шаг 2 @0x%08X (call 0x4F2640 -> 0x%08X)",
              kSiteUse, (DWORD)&StubUseGate, g_target, g_target, g_reqCat, kSiteDb, (DWORD)&StubDbUse);
    Log::Line(L"    P75: 4036 один раз (последний уровень) %s; кувшин души от зелья %s; потолок уровня сейчас %u (imm8 @0x%08X — "
              L"P29 ставится раньше)%s",
              g_single ? L"ВКЛ" : L"выкл (сток: на каждом)", g_noJar ? L"НЕ наполняется" : L"наполняется (сток)", cap, kCapImm,
              cap < (BYTE)g_target ? L" — ! НИЖЕ ЦЕЛИ: применение будет отклоняться" : L"");
    Log::Line(L"    P75: «один раз на персонажа» — гейт уровня шага 1; замок «зелье в пути» @0x%08X (уход 2140 -> 0x%08X), тайм-аут %u мс, "
              L"снятие на выходе: %s", kSiteSend, (DWORD)&StubDbSend, g_lockMs,
              !clearOn ? L"выкл (ReleaseOnExit=0, только тайм-аут)" : viaP63 ? L"общая точка P63 (ClearUserMemory 0x527374 под P63)"
                       : L"своя площадка ClearUserMemory 0x527374");
    g_p75Applied = true;   // ★ P127 А2.2: адреса функций опыта сверены — общая точка начисления годна
    return PatchResult::Applied;
}

// ═══════════════ ★ P127 А2.2 (18.11.2026; ★ ревизия 25 М-1): общая точка «опыт живьём» для моста админ-центра ═══════════════
//   Ведёт себя РОВНО как шаг 2 зелья: тот же режим награды Recv_BattleServerFromCharParamExp_1@0x4CBA90 (a3 = 0, a5 = 1, a6 = 1.0f),
//   не больше одного уровня за вызов, и то же состояние TLS GrantTls → площадки P75 (P75_SkipSend) действуют и на мост: при
//   SingleLevelUpPacket=1 4036 себе и сектору уходит только на ПОСЛЕДНЕМ (финальном) уровне, при обрыве — резервный 4036 фактического
//   состояния (SendFallback4036); при SuppressSoulJar=1 кувшин души не наполняется. Ключи 0 — сток. Нить карты игрока.
//   Без установленного P75 (адреса не сверены) — не зовётся (P75_Applied).
bool P75_Applied() { return g_p75Applied; }
bool P75_ExpAt(int lvl, __int64* out) { return ExpAt(lvl, out); }
int  P75_CapLevel() { return *(const BYTE*)kCapImm; }
int  P75_LevelOf(void* mgr, int num) { return (BYTE)GetLevel(mgr, (short)num); }
__int64 P75_ExpOf(void* mgr, int num) { return GetExp(mgr, (short)num); }
// Проверка 4 шага 1 зелья (ревизия 25 К-2): ExpTable строго растёт от уровня lvl до уровня, где лежит target (и на шаг дальше —
//   порог следующего уровня). false — таблица не годна.
bool P75_ExpTableGrows(int lvl, __int64 target)
{
    __int64 prev = 0, cur = 0;
    if (!ExpAt(lvl, &prev)) { return false; }
    for (int l = lvl + 1; l < 256; ++l)
    {
        if (!ExpAt(l, &cur)) { return false; }
        if (cur <= prev) { return false; }
        if (cur > target) { return true; }       // нашёлся порог выше цели — участок до цели растёт
        prev = cur;
    }
    return false;
}
// Начислять до накопленного опыта target (не больше maxCalls вызовов). Возврат — число вызовов (−1 — исключение внутри стока);
//   *lvl1/*exp1 — итог по памяти; *sk4036/*skJar — подавлено площадками P75; *fallback — 1, если ушёл резервный 4036.
int P75_GrantTo(void* mgr, int num, __int64 target, int maxCalls, int* lvl1, __int64* exp1, int* sk4036, int* skJar, int* fallback)
{
    int calls = 0;
    GrantTls st = { 1, 0, 0, 0 };
    *sk4036 = 0; *skJar = 0; *fallback = 0;
    if (g_tls != TLS_OUT_OF_INDEXES) { TlsSetValue(g_tls, &st); }
    bool fault = false;
    __try
    {
        for (; calls < maxCalls; ++calls)
        {
            const __int64 exp = GetExp(mgr, (short)num);
            if (exp >= target) { break; }
            const int lvl = (BYTE)GetLevel(mgr, (short)num);
            // финальный вызов — после него цель лежит внутри достигнутого уровня (как st.final шага 2: lvl + 1 >= цели)
            __int64 n1 = 0, n2 = 0;
            const bool in1 = ExpAt(lvl + 1, &n1), in2 = ExpAt(lvl + 2, &n2);
            st.final = (!in1 || target < n1 || !in2 || target < n2) ? 1 : 0;
            ExpAdd(mgr, (short)num, 0, target - exp, 1, (int)kFloatOne);
            if (GetExp(mgr, (short)num) <= exp && (BYTE)GetLevel(mgr, (short)num) <= lvl) { ++calls; break; }   // прироста нет (потолок)
        }
        *lvl1 = (BYTE)GetLevel(mgr, (short)num);
        *exp1 = GetExp(mgr, (short)num);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { fault = true; InterlockedIncrement(&g_stats.faults); }
    if (g_tls != TLS_OUT_OF_INDEXES) { TlsSetValue(g_tls, nullptr); }
    *sk4036 = st.skipped4036; *skJar = st.skippedJar;
    InterlockedExchangeAdd(&g_stats.skipped4036, st.skipped4036);
    InterlockedExchangeAdd(&g_stats.skippedJar, st.skippedJar);
    if (fault) { return -1; }
    const bool done = *exp1 >= target;
    // промежуточные 4036 подавлены, а последнего не было (обрыв / потолок) — фактическое состояние стоковым телом (как шаг 2)
    if (st.skipped4036 > 0 && !(done && st.final)) { SendFallback4036(mgr, (short)num); *fallback = 1; }
    return calls;
}

#ifdef ASDA_PATCH_STAND
// Стенд P127: та же развилка площадок P75 (1 — 4036 себе, 2 — сектору, 3 — кувшин), что зовут стабы внутри 0x4CBA90.
extern "C" __declspec(dllexport) int __stdcall P75_TestSkip(int kind) { return P75_SkipSend(kind); }
#endif
