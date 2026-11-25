// Copyright (c) 2026 @sitxovski (Discord)
// n12_gm_hide_hate.cpp — P39-доводка (N12): угроза к скрытому оператору НЕ ВОЗНИКАЕТ ВНОВЬ,
//                      одиночный навык монстра НЕ ЗАДЕВАЕТ скрытого.
//                      [ПОРТ/СЕРВЕР-ДОРАБОТКА] поверх N11 (P39). Разбор: Reports/owner_0927/gm_hide_npc_2.md
//
// ЗАЧЕМ (ревизия P39, СРЕДН-1)
//   N11 вычищает угрозу к скрытому ОДИН раз — по пакету 8115. Если угроза потом появится снова,
//   навык монстра с выбором цели «по угрозе» (типы 3/4/5 в `sub_40EE50`) выберет скрытого, а
//   одиночный удар навыка (`sub_40C200`, ветка «одна цель», 0x40C60A) состояние цели не проверяет
//   вовсе — попадёт. Цель потом снимет N11-A, но один удар возможен.
//
// ВСЕ ПУТИ ДОБАВЛЕНИЯ УГРОЗЫ (реверс 27.09, двумя методами)
//   1) capstone по всему .text: `call 0x43D2C0` — 17 мест, других ссылок на адрес нет:
//        sub_4137F0 ×3 (навык СТРАЖА ДУШИ, «SoulGuarderSkillDamageAndHateCheck»),
//        sub_4156C0, sub_415A30, sub_415DE0 ×2, sub_416790 ×4, sub_417340 ×3 (навыки игрока),
//        sub_428770 (CPlayer::ProcessSkillHate — угроза лекарю/баффера),
//        sub_43FEB0 (ProcessSkill_Provocation — провокация), sub_4423C0 (DamageAndHateCheck — урон).
//   2) запись номера игрока в список угрозы (+31352 = 0x7A78): все `mov [..+7A78h], r16` — только
//      внутри самой `sub_43D2C0` (0x43D577, 0x43D6A4); 0x460D0A/0x460D88 — dword в чужой структуре.
//      Декомпиль: остальные обращения к +31352 (sub_4352A0 HateReset, sub_422520, sub_4287F0
//      QuickHide, sub_43D0D0, sub_447B30, sub_448350 …) только ЧИТАЮТ или правят уже
//      существующую запись — новую не создают.
//   ⇒ Единственная точка входа угрозы — `sub_43D2C0` (OnHated). Гейт в её начале закрывает
//     страж души, навыки, провокацию, «угрозу лекарю», урон — все источники разом.
//
// ПЛОЩАДКИ
//   H  0x43D2C0  начало `sub_43D2C0(eax=угроза, ecx=монстр, [esp+4]=номер игрока i16, [esp+8]=урон,
//                [esp+12]=флаг)`, 9 байт `push ebx / push ebp / mov ebx,eax / mov ax,[esp+0Ch]`.
//                jmp на врезку: номер игрока 0..999, массив игроков монстра (+0x7748 — тот же, что
//                читает OnBattle 0x447B4F), бит 2 записи (+30292) ⇒ `ret 0Ch` — вызова «не было»
//                (ни угрозы, ни входа в бой, ни смены цели). Иначе — исходные 4 инструкции и
//                возврат на 0x43D2C9.
//   I  0x40C649  ветка «одна цель» `sub_40C200`: `movsx edx, byte [esi+8F7Ch]` — начало добавления
//                жертвы. Цель-игрок (байт +0x91C4 ≠ 0) со скрытым битом ⇒ переход на 0x40C687
//                (после добавления): жертва не добавляется, навык уходит «в пустоту». Координаты
//                цели (+0x8F78/+0x8F7A) к этому месту уже записаны — это точка скрытия, которую
//                все видели (GameServer под скрытием отбрасывает движение 4024), нового она не
//                выдаёт.
//
// ЧЕГО НЕ ТРОГАЕМ (и почему)
//   * Прямые записи цели монстра из записи игрока (0x40AC01, 0x40C7D7 — эффект 0x27 провокации
//     навыком; 0x431AF1, 0x4410E5, 0x441392 — эффекты навыков игрока): все они ставят целью
//     ИСПОЛНИТЕЛЯ навыка. Скрытый навыки применять не может — GameServer глушит их гейтом
//     `IsOperator && 244795==300` (RecvChar_SkillUse 0x46FA4C, навык стража RecvChar_SkillUse_0
//     0x48E60E). Даже при подделке цель снимет N11-A в том же кадре ДО удара (ProcessState →
//     OnBattle идёт раньше ProcessAction), а угрозу не даст H.
//   * Копирование цели вожака (вой/отряд/хозяин) — вожак скрытого целью не держит (H + N11-A).
//
// ⚠ Смещения во встроенном ассемблере — только #define (урок 24.08, см. n03).
#include "Patches.h"
#include "../Config.h"
#include "../NpcApi.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* const kSec = L"N12_GmHideHate";

    // push ebx / push ebp / mov ebx,eax / mov ax, word ptr [esp+0Ch]
    const BYTE kOrigH[] = { 0x53, 0x55, 0x8B, 0xD8, 0x66, 0x8B, 0x44, 0x24, 0x0C };
    // movsx edx, byte ptr [esi+8F7Ch]
    const BYTE kOrigI[] = { 0x0F, 0xBE, 0x96, 0x7C, 0x8F, 0x00, 0x00 };

    const Site kSiteH = { Npc::Hooks::kGmHideHateAdd,     kOrigH, sizeof(kOrigH) };
    const Site kSiteI = { Npc::Hooks::kGmHideSingleVictim, kOrigI, sizeof(kOrigI) };

    // Смещения для встроенного ассемблера.
    #define USER_STATE   7654h    // +30292: биты состояния записи игрока (1 = жив, 2 = скрыт)
    #define USER_SIZE    10AA8h   // 68264: шаг массива игроков
    #define MAX_USERS    3E8h     // 1000: предел номера игрока (как в OnBattle 0x447B6D)
    #define MOB_USERS    7748h    // +30536: монстр → массив игроков (OnBattle 0x447B4F)
    #define MOB_TGT_KIND 91C4h    // +37316: байт «цель навыка — игрок»
    #define MOB_VCOUNT   8F7Ch    // +36732: число жертв навыка
    #define HIDE_BIT     2

    DWORD g_hateCont  = Npc::Hooks::kGmHideHateAdd + sizeof(kOrigH);   // 0x43D2C9
    DWORD g_victimSkip = Npc::Hooks::kGmHideSingleVictimSkip;           // 0x40C687

    bool          g_trace = true;
    volatile LONG g_hateBlocked   = 0;
    volatile LONG g_victimBlocked = 0;

    // Журнал без лавины: первые 20 событий каждого вида, дальше — каждое 1000-е.
    bool ShouldLog(LONG n) { return n <= 20 || (n % 1000) == 0; }

    void __cdecl OnHateBlocked(BYTE* mob, int userNum)
    {
        const LONG n = InterlockedIncrement(&g_hateBlocked);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N12] угроза к скрытому не добавлена: монстр %ld, игрок #%d (всего %ld)",
                      (long)*(LONG*)(mob + 30356), userNum, (long)n);
    }

    void __cdecl OnVictimBlocked(BYTE* mob, int userNum)
    {
        const LONG n = InterlockedIncrement(&g_victimBlocked);
        if (g_trace && ShouldLog(n))
            Log::Line(L"    [N12] навык монстра %ld по одной цели: скрытый игрок #%d не задет (всего %ld)",
                      (long)*(LONG*)(mob + 30356), userNum, (long)n);
    }

    // H: jmp из 0x43D2C0. На входе: eax = угроза, ecx = монстр, [esp] = возврат,
    //    [esp+4] = номер игрока (i16), [esp+8] = урон, [esp+12] = флаг; вызываемый снимает 12 б.
    __declspec(naked) void HateGate()
    {
        __asm
        {
            push    edx
            push    eax
            movsx   eax, word ptr [esp + 12]         // номер игрока
            test    eax, eax
            jl      orig
            cmp     eax, MAX_USERS
            jge     orig
            mov     edx, dword ptr [ecx + MOB_USERS]
            test    edx, edx
            jz      orig
            imul    eax, eax, USER_SIZE
            test    byte ptr [edx + eax + USER_STATE], HIDE_BIT
            jz      orig
            // скрытый: вызова «не было»
            pop     eax
            pop     edx
            pushad
            pushfd
            movsx   eax, word ptr [esp + 40]         // 36 (pushad+pushfd) + 4 (возврат)
            push    eax
            push    ecx
            call    OnHateBlocked
            add     esp, 8
            popfd
            popad
            ret     12
        orig:
            pop     eax
            pop     edx
            push    ebx                              // исходные инструкции 0x43D2C0..0x43D2C8
            push    ebp
            mov     ebx, eax
            mov     ax, word ptr [esp + 0Ch]
            jmp     dword ptr [g_hateCont]
        }
    }

    // I: call из 0x40C649 (вместо `movsx edx, byte [esi+8F7Ch]`, 7 б).
    //    esi = монстр, ebx = массив игроков, cx = номер цели, байт [esi+91C4h] ≠ 0 — цель игрок.
    __declspec(naked) void SingleVictimGate()
    {
        __asm
        {
            cmp     byte ptr [esi + MOB_TGT_KIND], 0
            je      orig
            push    eax
            movsx   eax, cx
            imul    eax, eax, USER_SIZE
            test    byte ptr [ebx + eax + USER_STATE], HIDE_BIT
            pop     eax
            jz      orig
            // скрытый: жертву не добавляем, продолжаем с 0x40C687
            pushad
            pushfd
            movsx   eax, cx
            push    eax
            push    esi
            call    OnVictimBlocked
            add     esp, 8
            popfd
            popad
            push    eax
            mov     eax, dword ptr [g_victimSkip]
            mov     dword ptr [esp + 4], eax         // подменить адрес возврата
            pop     eax
            ret
        orig:
            movsx   edx, byte ptr [esi + MOB_VCOUNT]
            ret
        }
    }
}

PatchResult N12_GmHideHate()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
        return PatchResult::Disabled;

    const bool hate   = Config::GetBool(kSec, L"BlockHate",    true);   // H
    const bool victim = Config::GetBool(kSec, L"SingleVictim", true);   // I
    g_trace           = Config::GetBool(kSec, L"LogEvents",    true);

    const Site all[] = { kSiteH, kSiteI };
    if (!VerifyAllSites(kSec, all, ARRAYSIZE(all)))
        return PatchResult::Mismatch;

    if (hate   && !Hook::WriteJmp (kSiteH.va, &HateGate,         kSiteH.len)) return PatchResult::Failed;
    if (victim && !Hook::WriteCall(kSiteI.va, &SingleVictimGate, kSiteI.len)) return PatchResult::Failed;

    Log::Line(L"    скрытый оператор: угроза к нему не добавляется %s, одиночный навык монстра не задевает %s",
              hate ? L"ВКЛ" : L"выкл", victim ? L"ВКЛ" : L"выкл");
    return PatchResult::Applied;
}
