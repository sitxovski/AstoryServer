// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P71 — ★ АБСОЛЮТНЫЕ СРОКИ GameServer ПРИ ПЕРЕХОДЕ GetTickCount ЧЕРЕЗ 2^32 (оборона dev-сервера, 2026-10-15).
//  [ОРИГИНАЛ — дефект стока] Аудит: Reports/anticheat/audit_signed_tick_20261015.md (§3.2 строки 4–7, §4 п. 5–6,
//  §5 «P71», §6 п. 2). Отчёт волны: Reports/anticheat/wave_P71_20261015.md; ревизия review_P71P72_20261015.md (КРИТ-1 → p71fix).
//  Документ: AstoryServer/Docs/GameServer/tick-deadline-wrap-p71.md. Образец — P18 (Site/VerifyAllSites/стабы).
//
//  Такт = GetTickCount = аптайм хоста @@ASTORY_SERVER_HOSTNAME@@. 29.10.2026 09:51:50 UTC он проходит через 2^32 и обнуляется. Сток хранит
//  четыре СРОКА как абсолютные такты и сравнивает их с «сейчас» БЕЗЗНАКОВО (`cmp now, срок; jb/jae/ja`): срок, взведённый
//  до обнуления (~0xFFxxxxxx), после обнуления «не наступает» 49,7 суток. Лечение — МОДУЛЬНОЕ сравнение: «срок не наступил»
//  ⇔ (int)(now − срок) < 0. Разность берётся по модулю 2^32, поэтому переход через 2^32 и аптайм ≥ 2^31 одинаково безвредны,
//  пока расстояние до срока < 24,8 сут (у всех площадок — секунды/минуты; у штрафа лагеря — MaxPenaltySec, см. ниже).
//
//  ── ПЛОЩАДКИ (живой = Indun e7b4ac38 = сток 4e20f0ad, побайтно; tools/verify_p71.py) ──
//  A. ХРАНИТЕЛЬ ДУШИ, sub_48B4C0 (TimerProcess 0x5431C0 → для каждого игрока в мире): раз в 15 с sub_48B570(…,3,1) снимает
//     по 1 монете души (лог «[COIN]», 6157). Срок CUser+0x3F461 = такт + 15000 (писатели 0x48B106 sub_48AFF0, 0x48E15E
//     sub_48E0A0 — DB-пакет 2473, 0x48B521 — сам). Читатель один: 0x48B4FD `cmp ecx(now),[eax+3F461h]` / 0x48B503 `jb`.
//     Проверки «поле ≠ 0» у стока НЕТ: при поле 0 (слот CUser, не тронутый с запуска) сток считает «истёк» (now ≥ 0) и
//     взводит срок. Стаб повторяет это: 0 → CF=0 («истёк»), иначе CF = знак(now − срок).
//  B. СОГЛАСИЕ ОТРЯДА, sub_46C090 (голосование, 3 слота × 0x41): срок this+0x122+0x41·i = такт + 15000 (писатель один —
//     0x46BE37 в sub_46BA..); читатели: 0x46C0F4 «≠ 0» (остаётся), 0x46C111 `cmp edx(now),[ecx+eax+122h]` / 0x46C118 `jb rel32`.
//  C. ШТРАФ ЛАГЕРЯ (RoseWar), CUser+0x3F454. Поток данных (§6 п. 2 аудита был открыт):
//     DB-пакет 2460 (DBManager sub_43A140: `EXEC UPCharCamp UserIndex, CharIdx`, байты 12..15 результата) → GS sub_465FC0
//     (0x465FC0, диспетчер DB-ответов case 0x99C) пишет +0x3F454 = 1000 × значение (0x466082..0x466090) и ТУТ ЖЕ сравнивает
//     с GetTickCount (0x4660FD/0x466103 `jae`): «не истёк» → 6741 флаг 1, иначе поле := 0 и 2471 Time 0. TimerProcess
//     (sub_46A960, 0x46A9A8/0x46A9AE `jb`): истёк → поле := 0, 2471 Time 0 (sub_46AA10), 6741 флаг 0. Разрыв (DisConnectUser
//     0x525CAC, PortalDisConnectUser 0x5268BF): sub_46AA10(поле) → «[I] Convert Penalty Time..!! … Time:%d» = поле/1000 с →
//     2471 → DBManager sub_43ABB0 `EXEC UPCharCampPenaltyUpdate UserIndex, CharIdx, Time`.
//     ★ p71fix (ревизия 15.10, КРИТ-1): вызовов sub_46AA10 в GS ПЯТЬ, а не четыре. Пятый — КИК ГОЛОСОВАНИЕМ ОТРЯДА,
//     sub_46C090 ветка «[KICK] User Kick..!!» (GameServer.c:44131): 0x46C32F `call [GetTickCount]`; 0x46C335 `add eax,1B7740h`
//     (+30 мин); 0x46C349 `call sub_46AA10` → в БД уходит АБСОЛЮТНЫЙ такт/1000, не длительность. Поле кикнутого при этом
//     не пишется (писатели +0x3F454 в .text: только 0x46608B, 0x46613B, 0x46A9B3); он уходит порталом 5055/−1, штраф
//     приходит с 2460 при следующем входе. В стоке это самосогласовано В ПРЕДЕЛАХ ОДНОГО АПТАЙМА: кик в t → БД (t+1800000)/1000
//     → при входе поле ≈ t+1800000 → `now < поле` ещё ~30 мин. Дефекты стока: переход 2^32 (цель P71) и рестарт ХОСТА: старое
//     абсолютное значение при малом новом такте «висит» до 49,7 сут.
//     Лечение (ключ FixTimer3F454, шесть площадок одним ключом — формат значения в БД обязан быть единым):
//       C5 (p71fix) 0x46C335 `05 40 77 1B 00` → `B8 40 77 1B 00` (`mov eax,1B7740h`): в БД от кика уходит ДЛИТЕЛЬНОСТЬ 1800 с;
//          GetTickCount по 0x46C32F по-прежнему зовётся, результат не нужен (eax после площадки — только push для sub_46AA10).
//       C1 запись 0x466082: срок := now + 1000·с (стаб St71_PenaltyWrite). с ≤ 0 → 0 (нет штрафа). с > MaxPenaltySec (ini,
//          умолчание 604800 = 7 сут; штатный штраф 1800 с) → это СТАРОЕ АБСОЛЮТНОЕ ЗНАЧЕНИЕ ПРЕЖНЕЙ СЕМАНТИКИ (кик до P71:
//          такт/1000 ≈ аптайм в секундах) или мусор: поле := now − 1 (ненулевой ИСТЁКШИЙ срок) + строка PatchLog и Log_Operator
//          (P71_StalePenalty). Дальше сток сам: 0x4660FD «истёк» → поле := 0, 2471 Time 0 → СТИРАЕТ значение в БД (при поле 0
//          сток ничего не шлёт — поэтому не 0, а истёкший срок). Потолка 24,8 сут больше нет: всё, что выше MaxPenaltySec,
//          громко обнуляется; MaxPenaltySec > 2 147 483 режется до него (иначе 1000·с переполняет int) со строкой PatchLog.
//       C1b/C2 — модульные сравнения при входе и в TimerProcess (стабы на месте `cmp`, jcc стока не меняются).
//       C3 разрыв/портал 0x525CAC/0x5268BF: edx := ОСТАТОК (int)(срок − now) ≥ 0 вместо самого срока (остаток/1000 уходит в БД
//          как раньше, остаток ≤ 0 → 0 = снять штраф).
//     Гейты «поле ≠ 0» (0x4660EB, 0x46612F, 0x46A999, 0x463E6C, 0x525C9D, 0x5268B0, 0x5433A3) не меняются. 6707 код 9
//     (RegistUser 0x463E7C) шлёт младшее слово поля — у стока осмысленно только при t+1800000 < 65536 (аптайм < 1 мин), иначе
//     мусор; после P71 — мусор всегда (НИЗК-2 ревизии, не трогаем; что делает клиент — вне охвата).
//  D. ПРЕДМЕТЫ НА ЗЕМЛЕ, MapItemDeleteProcess (0x4224B0): T = GetTickCount − 300000 (0x422555..0x422560 → [ebp-4]);
//     0x422650 `mov eax,[edx+25h]` (такт падения) / `cmp eax,[ebp-4]` / 0x422656 `ja` (пропустить, если моложе 5 мин).
//     Стаб: eax = такт (как сток); такт 0 → ZF=1 (удалить, как сток: 0 ≤ T); иначе CF/ZF от (такт − T) << 1:
//     `ja` ⇔ CF=0 ∧ ZF=0 ⇔ (int)(такт − T) > 0.
//
//  ── СТАБЫ ── `call стаб` + nop'ы на месте `cmp` (или `mov`): следующий `jcc` стока не меняется, стаб выставляет ровно те
//  флаги, которые он читает (jb/jae — CF; ja — CF и ZF). `shl r,1` даёт CF = бит 31 разности (знак по модулю 2^32).
//  Регистры и стек (кроме результата стока: eax на D, edx на C-разрыв) сохраняются; push/pop и ret флаги не трогают.
//  ⚠ ПРЕДОСТЕРЕЖЕНИЕ АУДИТА (§4): на всех площадках срок пишется ПОЗЖЕ такта кадра только как «свежий такт + 15000/штраф»,
//  т.е. всегда в будущем; знак стоку нигде не нужен. Устаревший срок (слот не тронут > 24,8 сут при работающем процессе)
//  возможен только у A и перезаписывается DB-пакетом 2473 при входе.
//  Правило: сначала сверяются ВСЕ площадки и соседи (jcc) включённых групп, потом пишется. Пересечений с P01…P69 нет
//  (ни один патч не трогает 0x4224B0…0x4226B0, 0x465FC0…0x466160, 0x46A960…0x46AA10, 0x46C090…0x46C3C0, 0x48B4C0…0x48B530,
//  0x525C97…0x525CC9, 0x5268AA…0x5268DC — grep по src/patches; ревизия 15.10 подтвердила независимо: 169 VA, ±0x40 пусто).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../SrvApi.h"

// ⚠ Смещения в __asm — ТОЛЬКО #define (MSVC подставляет адрес константы вместо значения, см. n03/n04 в AddonNPC).
#define P71_SOUL_DEADLINE   3F461h      // CUser+0x3F461: срок периодики хранителя души (такт + 15000)
#define P71_PARTY_DEADLINE  122h        // отряд this+0x122+0x41·i: срок согласия (такт + 15000)
#define P71_PENALTY         3F454h      // CUser+0x3F454: срок штрафа лагеря (после P71 — абсолютный такт, 0 = нет)
#define P71_ITEM_TICK       25h         // предмет на земле +0x25: такт падения
#define P71_FRAME_USER      2Ch         // sub_465FC0: [ebp-2Ch] = CUser*
#define P71_FRAME_T         4           // MapItemDeleteProcess: [ebp-4] = now − 300000

// [p71fix] Значение штрафа из БД больше MaxPenaltySec — старое абсолютное значение прежней семантики (или мусор): строка в
// PatchLog и Log_Operator, возврат «сейчас» (через ту же ячейку импорта GetTickCount, что и сток/стенд). Зовётся из стаба
// St71_PenaltyWrite (cdecl, редкий путь). user — CUser* (имя +0x178, UserIndex +0x174).
extern "C" DWORD __cdecl P71_StalePenalty(DWORD secs, const BYTE* user);

namespace
{
    const wchar_t* kSec = L"P71_TickDeadlineWrap";

    // Ячейка импорта kernel32!GetTickCount в образе GameServer (та же, что зовёт сток: `call dword ptr [583028h]`).
    // Читается в момент вызова (стенд подменяет содержимое ячейки), поэтому через регистр, а не `call [imm]`.
    DWORD g_iatGetTickCount = 0x00583028;

    // [p71fix] Предел значения штрафа из БД, с (ключ MaxPenaltySec; выше — старое абсолютное значение/мусор → обнулить громко).
    // Умолчание 7 сут при штатном штрафе 1800 с; жёсткий потолок 2 147 483 (1000·с должно помещаться в int).
    constexpr DWORD kMaxPenaltySecDefault = 604800;
    constexpr DWORD kMaxPenaltySecCeiling = 2147483;
    DWORD g_maxPenaltySec = kMaxPenaltySecDefault;

    typedef void (__cdecl *PFN_SrvLog)(int cat, const char* fmt, ...);   // sub_569DF0
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)Srv::kLog;

    // ── A. Хранитель души: вход ecx = now, eax = CUser. Выход: CF = 1 ⇔ срок не наступил (для `jb` @0x48B503).
    //    Поле 0 → CF = 0 («истёк», как сток при now ≥ 0). Регистры не меняются.
    __declspec(naked) void St71_SoulGuarder()
    {
        __asm
        {
            push  edx
            mov   edx, dword ptr [eax + P71_SOUL_DEADLINE]
            test  edx, edx                      // CF = 0
            jz    done
            neg   edx
            add   edx, ecx                      // now − срок
            shl   edx, 1                        // CF = бит 31 (знак разности по модулю 2^32)
        done:
            pop   edx
            ret
        }
    }

    // ── B. Согласие отряда: вход edx = now, ecx = this, eax = 0x41·i. Выход: CF = 1 ⇔ не наступил (для `jb` @0x46C118).
    __declspec(naked) void St71_PartyConsent()
    {
        __asm
        {
            push  edx
            sub   edx, dword ptr [ecx + eax + P71_PARTY_DEADLINE]
            shl   edx, 1
            pop   edx
            ret
        }
    }

    // ── C1. Запись штрафа (sub_465FC0, вытеснены `imul eax,eax,3E8h; mov ecx,[ebp-2Ch]; mov [ecx+3F454h],eax`):
    //    вход eax = длительность, с (из БД); [ebp-2Ch] = CUser. Пишет [CUser+3F454h]:
    //      с ≤ 0                → 0 (штрафа нет);
    //      с > MaxPenaltySec    → [p71fix] старое абсолютное значение/мусор: now − 1 (ненулевой ИСТЁКШИЙ срок — сток следом
    //                             сам обнулит поле и пошлёт 2471 Time 0, стерев значение в БД) + P71_StalePenalty (лог);
    //      иначе                → now + 1000·с (сумма ровно 0 → 1, чтобы не слиться с «нет штрафа»).
    //    eax = записанное (у стока eax = 1000·с; дальше eax не читается — 0x466091 `lea ecx,[ebp-8]; call sub_49B9B0`). ecx/edx сохраняются.
    __declspec(naked) void St71_PenaltyWrite()
    {
        __asm
        {
            push  ecx
            push  edx
            test  eax, eax
            jle   zero                          // ≤ 0 с — штрафа нет
            cmp   eax, dword ptr [g_maxPenaltySec]
            ja    stale                         // [p71fix] больше предела — прежняя семантика/мусор
            imul  eax, eax, 1000
            push  eax                           // мс
            mov   eax, g_iatGetTickCount
            call  dword ptr [eax]               // eax = now (ecx/edx сохранены выше)
            pop   ecx
            add   eax, ecx                      // срок = now + мс
            jnz   store
            mov   eax, 1
            jmp   store
        stale:
            mov   ecx, dword ptr [ebp - P71_FRAME_USER]
            push  ecx                           // user
            push  eax                           // secs
            call  P71_StalePenalty              // cdecl: лог; eax = now
            add   esp, 8
            sub   eax, 1                        // now − 1: истёкший, ненулевой
            jnz   store
            sub   eax, 1                        // now было 1 → 0xFFFFFFFF (тоже истёкший по модулю: 1 − (−1) = 2 ≥ 0)
            jmp   store
        zero:
            xor   eax, eax
        store:
            mov   ecx, dword ptr [ebp - P71_FRAME_USER]
            mov   dword ptr [ecx + P71_PENALTY], eax
            pop   edx
            pop   ecx
            ret
        }
    }

    // ── C1b. Вход (sub_465FC0 после записи): eax = now, ecx = CUser. CF = 1 ⇔ не наступил (для `jae` @0x466103: истёк ⇔ CF=0).
    __declspec(naked) void St71_PenaltyLoginCmp()
    {
        __asm
        {
            push  eax
            sub   eax, dword ptr [ecx + P71_PENALTY]
            shl   eax, 1
            pop   eax
            ret
        }
    }

    // ── C2. TimerProcess (sub_46A960): edx = now, ecx = CUser. CF = 1 ⇔ не наступил (для `jb` @0x46A9AE).
    __declspec(naked) void St71_PenaltyTimerCmp()
    {
        __asm
        {
            push  edx
            sub   edx, dword ptr [ecx + P71_PENALTY]
            shl   edx, 1
            pop   edx
            ret
        }
    }

    // ── C3. Разрыв/портал (вытеснено `mov edx,[ecx+3F454h]`): ecx = CUser. Выход edx = остаток, мс = (int)(срок − now),
    //    отрицательный → 0 (истёк: 2471 Time 0 снимает штраф в БД). eax/ecx сохраняются. Сток дальше: push edx → sub_46AA10.
    __declspec(naked) void St71_PenaltyRemain()
    {
        __asm
        {
            push  eax
            push  ecx
            mov   eax, g_iatGetTickCount
            call  dword ptr [eax]               // eax = now
            pop   ecx
            mov   edx, dword ptr [ecx + P71_PENALTY]
            sub   edx, eax                      // срок − now
            jns   done
            xor   edx, edx
        done:
            pop   eax
            ret
        }
    }

    // ── D. Предметы на земле (вытеснено `mov eax,[edx+25h]; cmp eax,[ebp-4]`): edx = предмет, [ebp-4] = T = now − 300000.
    //    Выход: eax = такт падения (как сток); флаги для `ja` @0x422656: взять ⇔ (int)(такт − T) > 0; такт 0 → ZF=1 (удалить).
    __declspec(naked) void St71_MapItem()
    {
        __asm
        {
            mov   eax, dword ptr [edx + P71_ITEM_TICK]
            test  eax, eax                      // CF = 0, ZF = (такт == 0)
            jz    done
            push  eax
            sub   eax, dword ptr [ebp - P71_FRAME_T]
            shl   eax, 1                        // CF = знак, ZF ⇔ разность ∈ {0, 2^31}
            pop   eax
        done:
            ret
        }
    }

    // ── Площадки со стабами: что вытесняется (сверяется и пишется) и сосед — jcc/код стока сразу после (только сверяется).
    struct Place
    {
        int         group;      // 1 A, 2 B, 3 C, 4 D
        DWORD       va;         // площадка
        const BYTE* orig;       // исходные байты площадки
        SIZE_T      len;        // длина площадки (≥ 5: call rel32 + nop'ы)
        void      (*stub)();    // стаб
        DWORD       nextVa;     // сосед (jcc стока / код после площадки) — не меняется
        const BYTE* next;       // байты соседа
        SIZE_T      nextLen;
        const wchar_t* what;    // для лога
    };

    // A
    const BYTE kA_Cmp[6]   = { 0x3B, 0x88, 0x61, 0xF4, 0x03, 0x00 };                   // cmp ecx,[eax+3F461h]
    const BYTE kA_Jb[2]    = { 0x72, 0x22 };                                           // jb 0x48B527
    // B
    const BYTE kB_Cmp[7]   = { 0x3B, 0x94, 0x01, 0x22, 0x01, 0x00, 0x00 };             // cmp edx,[ecx+eax+122h]
    const BYTE kB_Jb[6]    = { 0x0F, 0x82, 0x9A, 0x02, 0x00, 0x00 };                   // jb 0x46C3B8
    // C
    const BYTE kC_Write[15] = { 0x69, 0xC0, 0xE8, 0x03, 0x00, 0x00,                    // imul eax,eax,3E8h
                                0x8B, 0x4D, 0xD4,                                      // mov ecx,[ebp-2Ch]
                                0x89, 0x81, 0x54, 0xF4, 0x03, 0x00 };                  // mov [ecx+3F454h],eax
    const BYTE kC_WriteNext[3] = { 0x8D, 0x4D, 0xF8 };                                 // lea ecx,[ebp-8] (eax дальше мёртв)
    const BYTE kC_LoginCmp[6] = { 0x3B, 0x81, 0x54, 0xF4, 0x03, 0x00 };                // cmp eax,[ecx+3F454h]
    const BYTE kC_LoginJae[2] = { 0x73, 0x27 };                                        // jae 0x46612C
    const BYTE kC_TimerCmp[6] = { 0x3B, 0x91, 0x54, 0xF4, 0x03, 0x00 };                // cmp edx,[ecx+3F454h]
    const BYTE kC_TimerJb[2]  = { 0x72, 0x51 };                                        // jb 0x46AA01
    const BYTE kC_Read[6]     = { 0x8B, 0x91, 0x54, 0xF4, 0x03, 0x00 };                // mov edx,[ecx+3F454h]
    const BYTE kC_ReadNext[5] = { 0x52, 0x66, 0x8B, 0x45, 0x08 };                      // push edx; mov ax,[ebp+8]
    // D
    const BYTE kD_Cmp[6]   = { 0x8B, 0x42, 0x25, 0x3B, 0x45, 0xFC };                   // mov eax,[edx+25h]; cmp eax,[ebp-4]
    const BYTE kD_Ja[2]    = { 0x77, 0x51 };                                           // ja 0x4226A9

    const Place kPlaces[] =
    {
        { 1, 0x0048B4FD, kA_Cmp,      sizeof(kA_Cmp),      &St71_SoulGuarder,     0x0048B503, kA_Jb,        sizeof(kA_Jb),        L"A хранитель души sub_48B4C0: cmp now,[CUser+3F461h] / jb" },
        { 2, 0x0046C111, kB_Cmp,      sizeof(kB_Cmp),      &St71_PartyConsent,    0x0046C118, kB_Jb,        sizeof(kB_Jb),        L"B согласие отряда sub_46C090: cmp now,[this+eax+122h] / jb" },
        { 3, 0x00466082, kC_Write,    sizeof(kC_Write),    &St71_PenaltyWrite,    0x00466091, kC_WriteNext, sizeof(kC_WriteNext), L"C1 штраф лагеря sub_465FC0: [CUser+3F454h] := now + 1000*с (> MaxPenaltySec — истёкший срок + лог)" },
        { 3, 0x004660FD, kC_LoginCmp, sizeof(kC_LoginCmp), &St71_PenaltyLoginCmp, 0x00466103, kC_LoginJae,  sizeof(kC_LoginJae),  L"C1b штраф при входе sub_465FC0: cmp now,[CUser+3F454h] / jae" },
        { 3, 0x0046A9A8, kC_TimerCmp, sizeof(kC_TimerCmp), &St71_PenaltyTimerCmp, 0x0046A9AE, kC_TimerJb,   sizeof(kC_TimerJb),   L"C2 штраф TimerProcess sub_46A960: cmp now,[CUser+3F454h] / jb" },
        { 3, 0x00525CAC, kC_Read,     sizeof(kC_Read),     &St71_PenaltyRemain,   0x00525CB2, kC_ReadNext,  sizeof(kC_ReadNext),  L"C3a остаток штрафа на разрыв DisConnectUser: edx := (int)(срок − now)" },
        { 3, 0x005268BF, kC_Read,     sizeof(kC_Read),     &St71_PenaltyRemain,   0x005268C5, kC_ReadNext,  sizeof(kC_ReadNext),  L"C3b остаток штрафа на портал PortalDisConnectUser: edx := (int)(срок − now)" },
        { 4, 0x00422650, kD_Cmp,      sizeof(kD_Cmp),      &St71_MapItem,         0x00422656, kD_Ja,        sizeof(kD_Ja),        L"D предметы на земле MapItemDeleteProcess: mov eax,[item+25h]; cmp eax,[ebp-4] / ja" },
    };

    // ── [p71fix] C5: байтовая площадка кика голосованием (sub_46C090): `add eax,1B7740h` → `mov eax,1B7740h`.
    //    Соседи: 0x46C32F `call [GetTickCount]` (остаётся, результат затирается), 0x46C33A `push eax; mov dx,[ebp-0B0h]; push edx`,
    //    0x46C349 `call sub_46AA10`. В БД от кика уходит 1 800 000 / 1000 = 1800 с — длительность, как и в остальных путях C.
    const DWORD kC5_Va      = 0x0046C335;
    const BYTE  kC5_Orig[5] = { 0x05, 0x40, 0x77, 0x1B, 0x00 };                        // add eax,1B7740h
    const BYTE  kC5_New[5]  = { 0xB8, 0x40, 0x77, 0x1B, 0x00 };                        // mov eax,1B7740h
    const BYTE  kC5_Prev[6] = { 0xFF, 0x15, 0x28, 0x30, 0x58, 0x00 };                  // 0x46C32F call [583028h]
    const BYTE  kC5_Next[9] = { 0x50, 0x66, 0x8B, 0x95, 0x50, 0xFF, 0xFF, 0xFF, 0x52 }; // 0x46C33A push eax; mov dx,[ebp-B0h]; push edx
    const BYTE  kC5_Call[5] = { 0xE8, 0xC2, 0xE6, 0xFF, 0xFF };                        // 0x46C349 call 0x46AA10

    // Опоры: GetTickCount стока через ту же ячейку импорта (0x4660F4 — вход; 0x46A98D — TimerProcess; 0x422555 — предметы),
    // вычисление T и писатели сроков «такт + 15000» — убеждаемся, что образ тот, под который разобраны стабы.
    const BYTE kIatCall[6]      = { 0xFF, 0x15, 0x28, 0x30, 0x58, 0x00 };             // call dword ptr [583028h]
    const BYTE kT_Calc[8]       = { 0x2D, 0xE0, 0x93, 0x04, 0x00, 0x89, 0x45, 0xFC };   // sub eax,493E0h; mov [ebp-4],eax
    const BYTE kA_Write1[11]    = { 0x05, 0x98, 0x3A, 0x00, 0x00, 0x8B, 0x4D, 0xF8, 0x89, 0x81, 0x61 };   // 0x48B0FE add eax,3A98h; mov ecx,[ebp-8]; mov [ecx+3F461h]…
    const BYTE kA_Write2[11]    = { 0x05, 0x98, 0x3A, 0x00, 0x00, 0x8B, 0x4D, 0xF8, 0x89, 0x81, 0x61 };   // 0x48B519
    const BYTE kA_Write3[11]    = { 0x05, 0x98, 0x3A, 0x00, 0x00, 0x8B, 0x4D, 0xDC, 0x89, 0x81, 0x61 };   // 0x48E156
    const BYTE kB_Write[5]      = { 0x05, 0x98, 0x3A, 0x00, 0x00 };                                       // 0x46BE28 add eax,3A98h
    const BYTE kB_WriteStore[7] = { 0x89, 0x84, 0x11, 0x22, 0x01, 0x00, 0x00 };                           // 0x46BE37 mov [ecx+edx+122h],eax
    const BYTE kC_Gate[7]       = { 0x83, 0xB8, 0x54, 0xF4, 0x03, 0x00, 0x00 };                           // cmp [eax+3F454h],0 (0x4660EB, 0x46A999, 0x525C9D, 0x5268B0)
    const BYTE kC_Zero[10]      = { 0xC7, 0x80, 0x54, 0xF4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };         // 0x46A9B3 mov [eax+3F454h],0
    const BYTE kC_Expired[12]   = { 0x8B, 0x45, 0xD4, 0x83, 0xB8, 0x54, 0xF4, 0x03, 0x00, 0x00, 0x74, 0x24 }; // 0x46612C «истёк при входе»: поле ≠ 0 → обнулить + 2471 Time 0

    struct Anchor { int group; DWORD va; const BYTE* b; SIZE_T len; const wchar_t* what; };
    const Anchor kAnchors[] =
    {
        { 1, 0x0048B4EE, kIatCall,      sizeof(kIatCall),      L"A: call [GetTickCount] перед сравнением" },
        { 1, 0x0048B0FE, kA_Write1,     sizeof(kA_Write1),     L"A: писатель срока sub_48AFF0 (такт + 15000)" },
        { 1, 0x0048B519, kA_Write2,     sizeof(kA_Write2),     L"A: писатель срока sub_48B4C0 (такт + 15000)" },
        { 1, 0x0048E156, kA_Write3,     sizeof(kA_Write3),     L"A: писатель срока sub_48E0A0 (такт + 15000)" },
        { 2, 0x0046C0DF, kIatCall,      sizeof(kIatCall),      L"B: call [GetTickCount] перед сравнением" },
        { 2, 0x0046BE28, kB_Write,      sizeof(kB_Write),      L"B: писатель срока (такт + 15000)" },
        { 2, 0x0046BE37, kB_WriteStore, sizeof(kB_WriteStore), L"B: запись [this+edx+122h]" },
        { 3, 0x004660EB, kC_Gate,       sizeof(kC_Gate),       L"C: гейт ≠0 при входе" },
        { 3, 0x004660F4, kIatCall,      sizeof(kIatCall),      L"C: call [GetTickCount] при входе" },
        { 3, 0x0046612C, kC_Expired,    sizeof(kC_Expired),    L"C: ветка «истёк при входе» (обнуление + 2471 Time 0) — опора обнуления старых значений" },
        { 3, 0x0046A98D, kIatCall,      sizeof(kIatCall),      L"C: call [GetTickCount] в TimerProcess" },
        { 3, 0x0046A999, kC_Gate,       sizeof(kC_Gate),       L"C: гейт ≠0 в TimerProcess" },
        { 3, 0x0046A9B3, kC_Zero,       sizeof(kC_Zero),       L"C: обнуление срока в TimerProcess" },
        { 3, 0x00525C9D, kC_Gate,       sizeof(kC_Gate),       L"C: гейт ≠0 на разрыв" },
        { 3, 0x005268B0, kC_Gate,       sizeof(kC_Gate),       L"C: гейт ≠0 на портал" },
        { 3, 0x0046C32F, kC5_Prev,      sizeof(kC5_Prev),      L"C5: call [GetTickCount] перед кик-штрафом" },
        { 3, 0x0046C33A, kC5_Next,      sizeof(kC5_Next),      L"C5: push eax; mov dx,[ebp-0B0h]; push edx после площадки" },
        { 3, 0x0046C349, kC5_Call,      sizeof(kC5_Call),      L"C5: call sub_46AA10 (2471)" },
        { 4, 0x00422555, kIatCall,      sizeof(kIatCall),      L"D: call [GetTickCount] в начале карты" },
        { 4, 0x0042255B, kT_Calc,       sizeof(kT_Calc),       L"D: T = now − 300000 → [ebp-4]" },
    };

    volatile LONG g_staleCount = 0;   // [p71fix] сколько раз значение из БД обнулено как старое/мусор (для лога/стенда)
}

// [p71fix] Лог «старого» значения штрафа и возврат «сейчас». Регистры/стек: обычная cdecl-функция, стаб сохраняет ecx/edx сам.
extern "C" DWORD __cdecl P71_StalePenalty(DWORD secs, const BYTE* user)
{
    InterlockedIncrement(&g_staleCount);
    int  userIndex = 0;
    char name[21] = "?";
    __try
    {
        if (user)
        {
            userIndex = *(const int*)(user + 0x174);
            lstrcpynA(name, (const char*)(user + 0x178), 21);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { lstrcpyA(name, "?"); }
    Log::Line(L"    P71: penalty value %u s > MaxPenaltySec %u, treated as stale absolute tick, cleared (UserIndex %d, %S)",
              secs, g_maxPenaltySec, userIndex, name);
    __try
    {
        pSrvLog(Srv::kLogCatOperator, "[P71] penalty value %u s > MaxPenaltySec %u, treated as stale absolute tick, cleared  UserIndex:%d  Name:%s",
                secs, g_maxPenaltySec, userIndex, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    typedef DWORD (WINAPI *PFN_Tick)();
    return ((PFN_Tick)(*(const DWORD*)g_iatGetTickCount))();
}

PatchResult P71_TickDeadlineWrap()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    const bool on[5] =
    {
        false,
        Config::GetBool(kSec, L"FixSoulGuarder",   true),
        Config::GetBool(kSec, L"FixPartyConsent",  true),
        Config::GetBool(kSec, L"FixTimer3F454",    true),
        Config::GetBool(kSec, L"FixMapItemDelete", true),
    };
    // [p71fix] предел значения штрафа из БД
    {
        const int v = Config::GetInt(kSec, L"MaxPenaltySec", (int)kMaxPenaltySecDefault);
        if (v <= 0)
        {
            g_maxPenaltySec = kMaxPenaltySecDefault;
            Log::Line(L"    P71: MaxPenaltySec=%d недопустим — взято умолчание %u с", v, g_maxPenaltySec);
        }
        else if ((DWORD)v > kMaxPenaltySecCeiling)
        {
            g_maxPenaltySec = kMaxPenaltySecCeiling;
            Log::Line(L"    P71: MaxPenaltySec=%d выше потолка (1000*с должно помещаться в int) — взято %u с", v, g_maxPenaltySec);
        }
        else { g_maxPenaltySec = (DWORD)v; }
    }

    // ── Сверка ВСЕХ площадок, соседей и опор включённых групп ДО первой записи: либо всё, либо ничего.
    Site check[48];
    int  n = 0;
    for (const auto& p : kPlaces)
    {
        if (!on[p.group]) { continue; }
        check[n].va = p.va;     check[n].orig = p.orig; check[n].len = p.len;     ++n;
        check[n].va = p.nextVa; check[n].orig = p.next; check[n].len = p.nextLen; ++n;
    }
    if (on[3]) { check[n].va = kC5_Va; check[n].orig = kC5_Orig; check[n].len = sizeof(kC5_Orig); ++n; }
    for (const auto& a : kAnchors)
    {
        if (!on[a.group]) { continue; }
        check[n].va = a.va; check[n].orig = a.b; check[n].len = a.len; ++n;
    }
    if (n == 0)
    {
        Log::Line(L"    P71: все четыре группы выключены в ini — ставить нечего");
        return PatchResult::Disabled;
    }
    if (!VerifyAllSites(L"P71", check, n)) { return PatchResult::Mismatch; }

    // Ячейка импорта должна указывать внутрь kernel32 (а не быть RVA/нулём): иначе стабы C1/C3 звали бы мусор.
    {
        const DWORD fn = *(const DWORD*)g_iatGetTickCount;
        const DWORD k32 = (DWORD)GetModuleHandleW(L"kernel32.dll");
        const DWORD ours = (DWORD)GetProcAddress((HMODULE)k32, "GetTickCount");
        if (on[3] && fn != ours)
        {
            // Допустимо: ячейка перенаправлена (стенд) — но только на код вне образа GameServer и не нуль.
            if (fn == 0 || (fn >= 0x00400000 && fn < 0x00600000))
            {
                Log::Line(L"    P71: ячейка импорта GetTickCount 0x%08X = 0x%08X (ожидалось 0x%08X) — патч НЕ ставится",
                          g_iatGetTickCount, fn, ours);
                return PatchResult::Mismatch;
            }
            Log::Line(L"    P71: ячейка импорта GetTickCount 0x%08X перенаправлена на 0x%08X (kernel32: 0x%08X) — принято",
                      g_iatGetTickCount, fn, ours);
        }
    }

    // ── Запись
    for (const auto& p : kPlaces)
    {
        if (!on[p.group]) { continue; }
        if (!Hook::WriteCall(p.va, (const void*)p.stub, p.len)) { return PatchResult::Failed; }
        Log::Line(L"    P71 %s — 0x%08X (%u б) -> call стаб 0x%08X; сосед 0x%08X не тронут",
                  p.what, p.va, (unsigned)p.len, (DWORD)p.stub, p.nextVa);
    }
    if (on[3])
    {
        if (!Hook::WriteBytes(kC5_Va, kC5_New, sizeof(kC5_New))) { return PatchResult::Failed; }
        Log::Line(L"    P71 C5 кик голосованием sub_46C090 — 0x%08X `add eax,1B7740h` -> `mov eax,1B7740h`: в БД (2471) уходит "
                  L"длительность 1800 с, а не абсолютный такт/1000 [p71fix КРИТ-1]", kC5_Va);
    }
    if (on[1]) { Log::Line(L"    P71 A: хранитель души — модульное сравнение срока CUser+0x3F461 (срок 0 = истёк, как сток)"); }
    if (on[2]) { Log::Line(L"    P71 B: согласие отряда — модульное сравнение срока this+0x122+0x41*i"); }
    if (on[3]) { Log::Line(L"    P71 C: штраф лагеря CUser+0x3F454 — срок := now + 1000*с из БД; сравнения модульные; на разрыв/портал в БД "
                           L"уходит ОСТАТОК; кик голосованием шлёт 1800 с; значение > MaxPenaltySec=%u с — старое абсолютное/мусор, "
                           L"обнуляется (истёкший срок -> сток шлёт 2471 Time 0) со строкой лога", g_maxPenaltySec); }
    if (on[4]) { Log::Line(L"    P71 D: предметы на земле — модульное сравнение такта падения с now − 300000 (такт 0 = удалить, как сток)"); }
    for (int g = 1; g <= 4; ++g)
    {
        if (!on[g]) { Log::Line(L"    P71: группа %d выключена ключом ini — площадки не тронуты", g); }
    }
    return PatchResult::Applied;
}
