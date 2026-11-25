// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P42 — ★ СКРЫТЫЙ ОПЕРАТОР НЕ ЯВЛЯЕТСЯ ДОПУСТИМОЙ ЦЕЛЬЮ БОЕВЫХ ДЕЙСТВИЙ ИГРОКОВ
//  [ПОРТ/СЕРВЕР-ДОРАБОТКА] паритет с оригиналом «мастер игры наблюдает скрытно»
//  (решение владельца 27.09.2026). Разбор: Reports/owner_0927/gm_hide_npc_2.md §5,
//  ревизия gm_hide_npc_2_REVIEW.md (СРЕДН-2); клиентская часть исключения скрытых из
//  выбора цели уже сделана (pick_hidden_filter.md), серверная — здесь.
//  Документ — AstoryServer/Docs/GameServer/gm-hide-attack-p42.md
//
//  ── ДЕФЕКТ ──
//  Сервер НИГДЕ не сверяет признак скрытия у ЦЕЛИ (CUser+0x3BC3B == 300 — ставит только
//  оператор Send_HideCommand@0x54E970, ни один не-оператор его не носит). Игрок собранным
//  вручную пакетом (или площадным навыком, чьи цели/жертвы приходят от клиента либо
//  собираются перебором сектора) может ударить/наложить эффект по невидимому оператору.
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Во всех точках применения боевого действия к цели-игроку: если цель — игрок с поднятым
//  признаком скрытия оператора, цель считается НЕДОПУСТИМОЙ ровно тем же путём, каким
//  сервер уже отклоняет невалидную/мёртвую/несуществующую цель (штатный reject/continue/
//  skip). Новых пакетов НЕТ, протокол НЕ меняется. Самоприменение НЕ трогаем: цель
//  отклоняется только когда она НЕ совпадает с исполнителем (target != caster) — скрытый
//  оператор и без того не может кастовать (гейты RecvChar_SkillUse), но защита от
//  самоблокировки оставлена.
//
//  ── ПРИЗНАК СКРЫТОГО ОПЕРАТОРА ──
//  Ровно как стоковые гейты навыков (RecvChar_SkillUse@0x46FA4C, л.45922):
//      IsOperatorIndex(mgr, idx, -1) != 0  &&  word CUser[+0x3BC3B] == 300
//  Где цель уже материализована как CUser* — читаем признак прямо из неё (флаг носит
//  только оператор, поэтому одного признака достаточно); где есть только номер —
//  берём CUser* через GetUser(mgr, idx).
//
//  ── ТОЧКИ (11; VA/байты сверены с живым GameServer, Indun и базой IDA, md5 e7b4ac38) ──
//   ★ reject у C2..C5 — это СТОКОВЫЙ блок «цель невалидна», который сам ставит [ebp-4]=-1,
//   разрушает локальный объект (call 0x49BF20) и уходит в SEH-эпилог. Прыгаем именно в НЕГО
//   (не сразу в эпилог), иначе утечёт объект и слетит SEH-запись.
//   ЦЕНТРАЛЬНАЯ проверка допустимости цели (a2=атакующий, a3=ЦЕЛЬ, 0=нельзя):
//     C1  sub_556DB0@0x556DB0 (вход) — 8 вызывающих: удар 4201/4203, списки целей навыка
//         игрока и стража, часть разлётов. Скрытая цель (a3) → возврат 0 (ret 0Ch).
//   ОБХОДЫ sub_556DB0 (реверс независимый, второй метод — скан call rel32 по живому образу):
//     C2  sub_471C70@0x471D18 — результат навыка игрока по цели a6a[ebp-0x24].
//         Обход: recvBattleCastingTimeEnd. Скрытая цель (a6a != a2) → jmp 0x471D3E (dtor + SEH, ret 0x2C).
//     C3  sub_48FE40@0x48FF04 — результат навыка стража по цели a1[ebp-0x28].
//         Обход: recvBattleSoulGuarderSkillCastingEnd. → jmp 0x48FF2A (dtor + SEH, ret 0x2C).
//     C4  sub_473360@0x47340D — наложение состояния (CSkillManager), цель a3[ebp+0xC],
//         CUser* уже в [ebp-0x68]. Скрытая (a3 != a2) → jmp 0x473413 (dtor v26 + эпилог, ret 0x18).
//     C5  sub_4913E0@0x49148D — наложение состояния от стража, цель a7[ebp+0xC],
//         CUser* в [ebp-0x68]. Скрытая (a7 != a2) → jmp 0x491493 (dtor + эпилог, ret 0x18).
//     C8  EXPLOSION_ARROW@0x486B22 — разлёт стрелы (перебор сектора; 556DB0 не зовёт).
//         Жертва (eax=CUser*) скрыта → jmp 0x486BF9 (пропуск, как штатный self-skip).
//     C9  GUARDIAN_NORMAL_ATTACK_AREA@0x487205 — разлёт стража. → jmp 0x4873CC.
//     C10 sub_426B00@0x427972 — перенос урона МОНСТРА на СОУЛМЕЙТА (партнёр [ebp-0x54]).
//         Скрыт — перенос НЕ делаем (jmp 0x42797A, цель остаётся исходным игроком).
//     C11 sub_49DDA0@0x49DE69 — цели навыка соулмейта (список из пакета клиента).
//         Скрытая цель (CUser* v80=[ebp-0x1c]) → jmp 0x49DDD3 (continue, пропуск цели).
//     C12 sub_555800@0x55678C — перенос урона на СОУЛМЕЙТА при обычном ударе ИГРОКА
//         (партнёр [ebp-0x11c]). Скрыт — перенос НЕ делаем (jmp 0x556797). [СРЕДН-2 ревизии]
//     C13 sub_4839D0@0x483C3D — перенос урона на СОУЛМЕЙТА при навыке монстра
//         (партнёр [ebp-0x14]). Скрыт — перенос НЕ делаем (jmp 0x483C45). [СРЕДН-2 ревизии]
//  Для C4/C5/C11 CUser* цели уже в кадре — признак читаем прямо из неё; для C2/C3/C10/C12/C13
//  и C1 — через GetUser(mgr, idx). userMng: CSkillManager [[ebp-0xE0]+4]+0x34] (C2),
//  CSoulGuarderManager [[ebp-0xC4]+4]+0x34] (C3), CMonsterManager [[ebp-0x138]+4]+0x34] (C10),
//  [[ebp-0x140]+4]+0x34] (C12), [[ebp-0x48]+4]+0x34] (C13), ecx (C1).
//
//  ── ★ C6/C7 УБРАНЫ (ревизия МЕЛК-3 / п.4): члены площадного 925 — это ЛЕЧЕНИЕ, не атака ──
//  sub_485940 = SetCurrentHpTimeValue(..., 2, 1, 4, 276): режим 2 = ПРИБАВКА HP (групповое
//  лечение 925). Гашение членов гасило бы лечение скрытого оператора союзником — это НЕ боевое
//  действие против него (как «групповые баффы на скрытого согруппника действуют», эталон
//  pick_hidden_filter.md). Прежние C6/C7 (0x473D34/0x491DC2) сняты — заодно ушёл и несбалансированный
//  стек СРЕДН-1 (у стоковых площадок аргумент sub_485940 снимается самой функцией).
//
//  ── ЧЕСТНЫЙ ПУТЬ НЕ ЗАДЕТ ──
//  Цель не скрыта (или это сам исполнитель) → трамплин доигрывает вытесненные стоковые
//  команды и уходит на адрес сразу за площадкой; регистры/стек/флаги как у стока (сверено
//  verify_p42.py: ESP и callee-saved на каждой ветке равны стоку).
//  «Ранний ret на входе» НЕЛЬЗЯ (у C2..C5 в прологе стоит SEH-фрейм) — reject идёт в
//  штатный SEH-безопасный блок «цель невалидна» самой функции.
//  С P01…P41 не пересекается (см. verify_dll.py, раздел пересечений).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P42_GmHideTarget";

    typedef void* (__thiscall *FnGetUser)(void* mgr, short idx);            // 0x5324A0
    typedef BOOL  (__thiscall *FnIsOpIdx)(void* mgr, short idx, int a3);    // 0x52ECF0
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);    // 0x569DF0

    const FnGetUser GetUser = (FnGetUser)Srv::kGetUser;
    const FnIsOpIdx IsOpIdx = (FnIsOpIdx)Srv::kIsOperatorIndex;
    const FnSrvLog  SrvLog  = (FnSrvLog)Srv::kLog;

    constexpr int   kOffHide = 0x3BC3B;              // CUser: word 300 = скрыт (как P41)
    constexpr short kHidden  = 300;
    constexpr int   kLogCat  = Srv::kLogCatOperator; // Log_Operator

    bool          g_enabled = true;   // главный выключатель
    bool          g_central = true;   // C1  (sub_556DB0)
    bool          g_skills  = true;   // C2..C7 (навыки/состояния игрока и стража, площадные члены)
    bool          g_spreads = true;   // C8/C9 (разлёты стрелы/стража)
    bool          g_soul    = true;   // C10/C11 (соулмейт)
    bool          g_trace   = true;   // журнал
    volatile LONG g_cnt     = 0;

    bool ShouldLog(LONG n) { return g_trace && (n <= 50 || (n % 1000) == 0); }

    // Признак скрытого оператора по готовому CUser* (флаг носит только оператор).
    // reject, если цель скрыта И это НЕ сам исполнитель (target != caster).
    __forceinline bool UserHidden(const void* pUser)
    {
        if (!pUser) { return false; }
        __try { return *(const short*)((const BYTE*)pUser + kOffHide) == kHidden; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
}

extern "C"
{
// По ГОТОВОМУ CUser* цели (C4/C5/C11). 1 — отклонить (скрытый оператор, не сам исполнитель).
int __cdecl P42_RejectByUser(const void* pUser, int targetIdx, int casterIdx)
{
    if (!g_enabled) { return 0; }
    if (targetIdx == casterIdx) { return 0; }
    if (!UserHidden(pUser)) { return 0; }
    const LONG n = InterlockedIncrement(&g_cnt);
    if (ShouldLog(n))
    {
        SrvLog(kLogCat, "P42: hidden operator %d rejected as target of %d (byUser, total %ld)",
               targetIdx, casterIdx, (long)n);
    }
    return 1;
}

// По НОМЕРУ цели через менеджер (C1/C2/C3/C6/C7/C10). 1 — отклонить.
int __cdecl P42_RejectByIdx(void* mgr, int targetIdx, int casterIdx)
{
    if (!g_enabled) { return 0; }
    if (targetIdx == casterIdx || targetIdx < 0 || !mgr) { return 0; }
    bool hidden = false;
    __try
    {
        BYTE* user = (BYTE*)GetUser(mgr, (short)targetIdx);
        if (!user) { return 0; }
        if (*(const short*)(user + kOffHide) != kHidden) { return 0; }
        hidden = IsOpIdx(mgr, (short)targetIdx, -1) != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (!hidden) { return 0; }
    const LONG n = InterlockedIncrement(&g_cnt);
    if (ShouldLog(n))
    {
        SrvLog(kLogCat, "P42: hidden operator %d rejected as target of %d (byIdx, total %ld)",
               targetIdx, casterIdx, (long)n);
    }
    return 1;
}
}

namespace
{
    // ── Адреса штатных reject/resume/skip для косвенных jmp (host VA) ──
    DWORD g_c1_resume  = 0x00556DB6;   // C1: за вытесненным прологом sub_556DB0
    // ★ reject у C2..C5 идёт в СТОКОВЫЙ блок «невалидная цель»: он ставит [ebp-4]=-1,
    //   разрушает локальный объект (call 0x49BF20) и уходит в SEH-эпилог. Прыгать сразу
    //   в эпилог НЕЛЬЗЯ — утечёт объект и слетит SEH-запись.
    DWORD g_c2_reject  = 0x00471D3E;   // C2: sub_471C70 — mov [ebp-4],-1; dtor v44; jmp эпилог
    DWORD g_c2_resume  = 0x00471D1E;
    DWORD g_c3_reject  = 0x0048FF2A;   // C3: sub_48FE40 — mov [ebp-4],-1; dtor; jmp эпилог
    DWORD g_c3_resume  = 0x0048FF0A;
    DWORD g_c4_fall    = 0x00473413;   // C4: стоковый путь «цель невалидна» (dtor v26 + эпилог)
    DWORD g_c4_jne     = 0x00473427;   // C4: стоковое продолжение (v25 != 0)
    DWORD g_c5_fall    = 0x00491493;   // C5: стоковый путь «цель невалидна»
    DWORD g_c5_jne     = 0x004914A7;   // C5: стоковое продолжение
    DWORD g_c8_skip    = 0x00486BF9;   // C8: continue разлёта стрелы
    DWORD g_c8_resume  = 0x00486B2A;
    DWORD g_c9_skip    = 0x004873CC;   // C9: continue разлёта стража
    DWORD g_c9_resume  = 0x0048720D;
    DWORD g_c10_to     = 0x0042797A;   // C10: точка после переноса на соулмейта (удар монстра)
    DWORD g_c11_skip   = 0x0049DDD3;   // C11: continue цикла целей соулмейта
    DWORD g_c11_resume = 0x0049DE70;
    DWORD g_c12_to     = 0x00556797;   // C12: точка после переноса на соулмейта (удар ИГРОКА)
    DWORD g_c13_to     = 0x00483C45;   // C13: точка после переноса на соулмейта (навык монстра)

    // ── C1: вход sub_556DB0 — скрытая цель a3 -> return 0 (ret 0Ch) ──
    __declspec(naked) void StubCentral()
    {
        __asm
        {
            // вход: ecx=mgr; [esp+4]=a2 (атакующий), [esp+8]=a3 (цель), [esp+0Ch]=a4
            push  ecx
            push  edx
            push  eax
            movsx eax, word ptr [esp+0x14]   // a3 (цель)
            movsx edx, word ptr [esp+0x10]   // a2 (исполнитель)
            push  edx                        // caster
            push  eax                        // target
            push  ecx                        // mgr
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            pop   eax
            pop   edx
            pop   ecx
            jnz   reject
            // не скрыт: доиграть пролог `push ebp; mov ebp,esp; sub esp,0x1c` -> 0x556DB6
            push  ebp
            mov   ebp, esp
            sub   esp, 0x1c
            jmp   dword ptr [g_c1_resume]
        reject:
            xor   eax, eax
            ret   0Ch
        }
    }

    // ── C2: sub_471C70 @0x471D18 — скрытая цель a6a -> jmp reject ──
    __declspec(naked) void StubC2()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0xE0]            // this (CSkillManager)
            mov   eax, [eax+4]               // m_pcThread
            mov   eax, [eax+0x34]            // m_cUserMng
            movsx ecx, word ptr [ebp+8]      // a2 (caster)
            movsx edx, word ptr [ebp-0x24]   // a6a (target)
            push  ecx
            push  edx
            push  eax
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            popad
            jnz   reject
            mov   edx, [ebp+0xf]             // доиграть: mov edx,[ebp+0xf]; mov [ebp-0x48],edx
            mov   [ebp-0x48], edx
            jmp   dword ptr [g_c2_resume]
        reject:
            jmp   dword ptr [g_c2_reject]
        }
    }

    // ── C3: sub_48FE40 @0x48FF04 — скрытая цель a1 -> jmp reject ──
    __declspec(naked) void StubC3()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0xC4]            // this (CSoulGuarderManager)
            mov   eax, [eax+4]
            mov   eax, [eax+0x34]            // m_cUserMng
            movsx ecx, word ptr [ebp+8]      // a2 (caster)
            movsx edx, word ptr [ebp-0x28]   // a1 (target)
            push  ecx
            push  edx
            push  eax
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            popad
            jnz   reject
            mov   edx, [ebp+0xf]             // доиграть: mov edx,[ebp+0xf]; mov [ebp-0x4c],edx
            mov   [ebp-0x4c], edx
            jmp   dword ptr [g_c3_resume]
        reject:
            jmp   dword ptr [g_c3_reject]
        }
    }

    // ── C4: sub_473360 @0x47340D — CUser* цели уже в [ebp-0x68] ──
    __declspec(naked) void StubC4()
    {
        __asm
        {
            pushad
            movsx ecx, word ptr [ebp+8]      // a2 (caster)
            movsx edx, word ptr [ebp+0xc]    // a3 (target idx)
            mov   eax, [ebp-0x68]            // CUser* цели
            push  ecx
            push  edx
            push  eax
            call  P42_RejectByUser
            add   esp, 12
            test  eax, eax
            popad
            jnz   reject
            // доиграть штатную проверку `cmp [ebp-0x68],0; jne 0x473427`
            cmp   dword ptr [ebp-0x68], 0
            jne   c4_ok
        reject:                              // скрытая цель ИЛИ v25==0 -> стоковый reject
            jmp   dword ptr [g_c4_fall]
        c4_ok:
            jmp   dword ptr [g_c4_jne]       // v25 != 0 -> стоковое продолжение
        }
    }

    // ── C5: sub_4913E0 @0x49148D — CUser* цели уже в [ebp-0x68] ──
    __declspec(naked) void StubC5()
    {
        __asm
        {
            pushad
            movsx ecx, word ptr [ebp+8]      // a2 (caster)
            movsx edx, word ptr [ebp+0xc]    // a7 (target idx)
            mov   eax, [ebp-0x68]            // CUser* цели
            push  ecx
            push  edx
            push  eax
            call  P42_RejectByUser
            add   esp, 12
            test  eax, eax
            popad
            jnz   reject
            cmp   dword ptr [ebp-0x68], 0
            jne   c5_ok
        reject:                              // скрытая цель ИЛИ v26==0 -> стоковый reject
            jmp   dword ptr [g_c5_fall]
        c5_ok:
            jmp   dword ptr [g_c5_jne]
        }
    }

    // ── C12: sub_555800 @0x55678C — перенос урона на соулмейта (обычный удар ИГРОКА) ──
    //   Партнёр [ebp-0x11c]; если скрыт — перенос НЕ делаем (jmp 0x556797, цель остаётся игроком).
    __declspec(naked) void StubC12()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0x140]           // this
            mov   eax, [eax+4]
            mov   eax, [eax+0x34]            // m_cUserMng
            movsx ecx, word ptr [ebp-0x11c]  // партнёр-соулмейт
            push  -1
            push  ecx
            push  eax
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            popad
            jnz   skip                       // партнёр скрыт -> перенос НЕ делаем
            mov   cx, word ptr [ebp-0x11c]   // доиграть: mov cx,[ebp-0x11c]; mov [ebp-0x50],cx
            mov   word ptr [ebp-0x50], cx
        skip:
            jmp   dword ptr [g_c12_to]
        }
    }

    // ── C13: sub_4839D0 @0x483C3D — перенос урона на соулмейта (навык монстра) ──
    //   Партнёр [ebp-0x14]; если скрыт — перенос НЕ делаем (jmp 0x483C45).
    __declspec(naked) void StubC13()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0x48]            // this
            mov   eax, [eax+4]
            mov   eax, [eax+0x34]            // m_cUserMng
            movsx ecx, word ptr [ebp-0x14]   // партнёр-соулмейт
            push  -1
            push  ecx
            push  eax
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            popad
            jnz   skip
            mov   dx, word ptr [ebp-0x14]    // доиграть: mov dx,[ebp-0x14]; mov [ebp-0x20],dx
            mov   word ptr [ebp-0x20], dx
        skip:
            jmp   dword ptr [g_c13_to]
        }
    }

    // ── C8: EXPLOSION_ARROW @0x486B22 — жертва eax=CUser* (перебор сектора) ──
    __declspec(naked) void StubC8()
    {
        __asm
        {
            // eax = CUser* жертвы (задан на 0x486B1F). Стоковый self-skip уже отсеял
            // самого атакующего, поэтому исключение исполнителя тут не нужно.
            cmp   word ptr [eax+0x3BC3B], 300
            je    skip
            mov   cx, word ptr [eax+0xc]     // доиграть: mov cx,[eax+0xc]; mov [ebp-4],cx
            mov   word ptr [ebp-4], cx
            jmp   dword ptr [g_c8_resume]
        skip:
            jmp   dword ptr [g_c8_skip]
        }
    }

    // ── C9: GUARDIAN_NORMAL_ATTACK_AREA @0x487205 — жертва eax=CUser* ──
    __declspec(naked) void StubC9()
    {
        __asm
        {
            cmp   word ptr [eax+0x3BC3B], 300
            je    skip
            mov   cx, word ptr [eax+0xc]
            mov   word ptr [ebp-4], cx
            jmp   dword ptr [g_c9_resume]
        skip:
            jmp   dword ptr [g_c9_skip]
        }
    }

    // ── C10: sub_426B00 @0x427972 — перенос урона на соулмейта [ebp-0x54] ──
    __declspec(naked) void StubC10()
    {
        __asm
        {
            pushad
            mov   eax, [ebp-0x138]           // this (CMonsterManager)
            mov   eax, [eax+4]
            mov   eax, [eax+0x34]            // m_cUserMng
            movsx ecx, word ptr [ebp-0x54]   // партнёр-соулмейт (кандидат на перенос)
            push  -1
            push  ecx
            push  eax
            call  P42_RejectByIdx
            add   esp, 12
            test  eax, eax
            popad
            jnz   skip                       // партнёр скрыт -> перенос НЕ делаем
            mov   cx, word ptr [ebp-0x54]    // доиграть: mov cx,[ebp-0x54]; mov [ebp-0x14],cx
            mov   word ptr [ebp-0x14], cx
        skip:
            jmp   dword ptr [g_c10_to]       // обе ветки -> 0x42797A
        }
    }

    // ── C11: sub_49DDA0 @0x49DE69 — цель соулмейт-навыка (CUser* v80=[ebp-0x1c]) ──
    __declspec(naked) void StubC11()
    {
        __asm
        {
            pushad
            movsx edx, word ptr [ebp-0x10]   // текущая цель (номер)
            mov   eax, [ebp-0x1c]            // v80 = CUser* цели
            push  -1                         // список из пакета — self-исключение не нужно
            push  edx
            push  eax
            call  P42_RejectByUser
            add   esp, 12
            test  eax, eax
            popad
            jnz   skip
            // доиграть `movsx edx,[ebp+0x14]; cmp edx,0x27` (флаги нужны на 0x49DE70)
            movsx edx, word ptr [ebp+0x14]
            cmp   edx, 0x27
            jmp   dword ptr [g_c11_resume]
        skip:
            jmp   dword ptr [g_c11_skip]
        }
    }

    // ── Реестр площадок: VA, ожидаемые байты, длина, стаб ──
    struct P42Site { DWORD va; const BYTE* orig; SIZE_T len; void (*stub)(); int group; };
    // группы: 0=central, 1=skills, 2=spreads, 3=soul
    const BYTE kC1[]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C };                   // 0x556DB0
    const BYTE kC2[]  = { 0x8B, 0x55, 0x0F, 0x89, 0x55, 0xB8 };                   // 0x471D18
    const BYTE kC3[]  = { 0x8B, 0x55, 0x0F, 0x89, 0x55, 0xB4 };                   // 0x48FF04
    const BYTE kC4[]  = { 0x83, 0x7D, 0x98, 0x00, 0x75, 0x14 };                   // 0x47340D
    const BYTE kC5[]  = { 0x83, 0x7D, 0x98, 0x00, 0x75, 0x14 };                   // 0x49148D
    const BYTE kC8[]  = { 0x66, 0x8B, 0x48, 0x0C, 0x66, 0x89, 0x4D, 0xFC };       // 0x486B22
    const BYTE kC9[]  = { 0x66, 0x8B, 0x48, 0x0C, 0x66, 0x89, 0x4D, 0xFC };       // 0x487205
    const BYTE kC10[] = { 0x66, 0x8B, 0x4D, 0xAC, 0x66, 0x89, 0x4D, 0xEC };       // 0x427972
    const BYTE kC11[] = { 0x0F, 0xBF, 0x55, 0x14, 0x83, 0xFA, 0x27 };             // 0x49DE69
    const BYTE kC12[] = { 0x66, 0x8B, 0x8D, 0xE4, 0xFE, 0xFF, 0xFF, 0x66, 0x89, 0x4D, 0xB0 }; // 0x55678C (11)
    const BYTE kC13[] = { 0x66, 0x8B, 0x55, 0xEC, 0x66, 0x89, 0x55, 0xE0 };       // 0x483C3D (8)

    const P42Site kSites[] =
    {
        { 0x00556DB0, kC1,  sizeof(kC1),  &StubCentral, 0 },
        { 0x00471D18, kC2,  sizeof(kC2),  &StubC2,      1 },
        { 0x0048FF04, kC3,  sizeof(kC3),  &StubC3,      1 },
        { 0x0047340D, kC4,  sizeof(kC4),  &StubC4,      1 },
        { 0x0049148D, kC5,  sizeof(kC5),  &StubC5,      1 },
        { 0x00486B22, kC8,  sizeof(kC8),  &StubC8,      2 },
        { 0x00487205, kC9,  sizeof(kC9),  &StubC9,      2 },
        { 0x00427972, kC10, sizeof(kC10), &StubC10,     3 },
        { 0x0049DE69, kC11, sizeof(kC11), &StubC11,     3 },
        { 0x0055678C, kC12, sizeof(kC12), &StubC12,     3 },
        { 0x00483C3D, kC13, sizeof(kC13), &StubC13,     3 },
    };

    bool GroupOn(int g)
    {
        switch (g)
        {
        case 0:  return g_central;
        case 1:  return g_skills;
        case 2:  return g_spreads;
        default: return g_soul;
        }
    }
}

PatchResult P42_GmHideTarget()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    g_enabled = true;
    g_central = Config::GetBool(S, L"GateCentral",   true);
    g_skills  = Config::GetBool(S, L"GateSkills",    true);
    g_spreads = Config::GetBool(S, L"GateSpreads",   true);
    g_soul    = Config::GetBool(S, L"GateSoulmate",  true);
    g_trace   = Config::GetBool(S, L"LogEvents",     true);
    if (!g_central && !g_skills && !g_spreads && !g_soul)
    {
        Log::Line(L"    P42: все группы выключены — площадки остаются стоковыми");
        return PatchResult::Disabled;
    }

    // Сверка ВСЕХ площадок до первой записи.
    Site sites[ARRAYSIZE(kSites)];
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        sites[i] = { kSites[i].va, kSites[i].orig, kSites[i].len };
    }
    if (!VerifyAllSites(L"P42", sites, ARRAYSIZE(kSites))) { return PatchResult::Mismatch; }

    int done = 0;
    for (int i = 0; i < ARRAYSIZE(kSites); ++i)
    {
        if (!GroupOn(kSites[i].group)) { continue; }
        if (!Hook::WriteJmp(kSites[i].va, (const void*)kSites[i].stub, kSites[i].len)) { return PatchResult::Failed; }
        ++done;
    }
    Log::Line(L"    P42: скрытый оператор — недопустимая цель боя игроков; площадок поставлено %d "
              L"(центр %s, навыки %s, разлёты %s, соулмейт %s)", done,
              g_central ? L"ВКЛ" : L"выкл", g_skills ? L"ВКЛ" : L"выкл",
              g_spreads ? L"ВКЛ" : L"выкл", g_soul ? L"ВКЛ" : L"выкл");
    return PatchResult::Applied;
}
