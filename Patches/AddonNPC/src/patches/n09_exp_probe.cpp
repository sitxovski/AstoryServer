// Copyright (c) 2026 @sitxovski (Discord)
// n09_exp_probe.cpp — ДИАГНОСТИКА РАСЧЁТА ОПЫТА. Ничего не меняет, только пишет в журнал.
//
// ЗАЧЕМ
//   Владелец 2026-08-25: «иногда получаю опыт +1». Клиент ни при чём — число приходит готовым
//   пакетом 4038, и абсолютный опыт растёт ровно на единицу. Формула разобрана
//   (`Reports/exp_share_npcserver.md`), но неизвестно, какой из множителей падает:
//   записанный за игроком урон или что-то ещё. Эта площадка снимает сами числа на живом сервере.
//
// ГДЕ
//   `sub_437A30` (раздача награды), блок расчёта доли:
//
//     00437db6  mov   ecx, [esp+18h]          ; ecx -> поле «накопленный урон» записи игрока
//     00437dba  fild  dword ptr [ecx]         ; урон игрока
//     00437dbc  fidiv dword ptr [ebp+7A38h]   ; / максимум здоровья монстра (31288)
//     00437dc2  fimul dword ptr [esp+1Ch]     ; * базовый опыт монстра
//     00437dc6  fadd  qword ptr [4792A8h]     ; + 0.9  (округление вверх)
//     00437dcc  call  463050h                 ; -> целое, результат в eax
//     00437dd1  mov   edx, [ebp+7748h]        ; ← ВРЕЗАЕМСЯ СЮДА (6 байт)
//     00437ddd  mov   esi, eax                ; esi = опыт до штрафа за разницу уровней
//
//   На момент врезки уже посчитан результат (eax) и доступны все три множителя.
//
// ЧТО ПИШЕМ
//   урон игрока, максимум здоровья монстра, базовый опыт, полученное целое.
//   По этим четырём числам сразу видно, какой множитель обнулился.
//
// БЕЗОПАСНОСТЬ
//   • площадка сохраняет ВСЕ регистры и флаги (`pushad`/`pushfd`), поэтому исходный код
//     продолжает работать с теми же значениями;
//   • после восстановления выполняем ровно ту инструкцию, которую заменили, и возвращаемся;
//   • длина площадки 6 байт = `call rel32` (5) + `nop` (1) — границы функции не двигаются;
//   • ⚠ `pushad` смещает `esp` на 32, `pushfd` ещё на 4, поэтому обращения к `[esp+…]`
//     внутри площадки идут со сдвигом +36.
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЧЕРЕЗ #define (см. пояснение в n03):
//   C++-константа в операнде `[reg + имя]` подставляет АДРЕС переменной. На этом 24.08.2026
//   упал живой NpcServer.
#include "Patches.h"
#include "../Config.h"
#include "../NpcApi.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const DWORD kVa = 0x00437DD1;                                   // mov edx, [ebp+7748h]
    const BYTE  kOrig[] = { 0x8B, 0x95, 0x48, 0x77, 0x00, 0x00 };   // ровно она
    const Site  kSites[] = { { kVa, kOrig, sizeof(kOrig) } };

    #define MOB_MAXHP   7A38h   // 31288, i32: максимум здоровья монстра (относительно ebp)
    // ⚠ Сдвиг стека внутри площадки = pushad (32) + pushfd (4) = 36 = 24h.
    #define ARG_DMGPTR  3Ch     // [esp+18h] + 24h: указатель на поле урона игрока
    #define ARG_BASEEXP 40h     // [esp+1Ch] + 24h: базовый опыт монстра

    // Снятые значения — раскладываем в статические ячейки, чтобы вызвать журнал уже из C++.
    volatile long g_dmg = 0, g_maxHp = 0, g_baseExp = 0, g_result = 0;

    void __cdecl WriteLine()
    {
        Log::Line(L"    [опыт] урон игрока=%ld, максимум здоровья=%ld, базовый опыт=%ld -> начислено %ld",
                  g_dmg, g_maxHp, g_baseExp, g_result);
    }

    __declspec(naked) void ExpProbe()
    {
        __asm
        {
            pushad
            pushfd
            // результат расчёта лежит в eax на момент врезки
            mov     ecx, [esp + 20h]            // сохранённый eax из pushad (edi,esi,ebp,esp,ebx,edx,ecx,eax)
            mov     g_result, ecx
            mov     ecx, [esp + ARG_DMGPTR]     // указатель на поле урона записи игрока
            mov     ecx, [ecx]
            mov     g_dmg, ecx
            mov     ecx, [ebp + MOB_MAXHP]
            mov     g_maxHp, ecx
            mov     ecx, [esp + ARG_BASEEXP]
            mov     g_baseExp, ecx
            call    WriteLine
            popfd
            popad
            // исходная инструкция, которую заменили
            mov     edx, [ebp + 7748h]
            ret
        }
    }
}

PatchResult N09_ExpProbe()
{
    // По умолчанию ВЫКЛЮЧЕНА: это диагностика, а не правка. Включать на время замера.
    if (!Config::GetBool(L"N09_ExpProbe", L"Enabled", false))
        return PatchResult::Disabled;

    if (!VerifyAllSites(L"N09_ExpProbe", kSites, ARRAYSIZE(kSites)))
        return PatchResult::Mismatch;

    if (!Hook::WriteCall(kVa, &ExpProbe, sizeof(kOrig)))
        return PatchResult::Failed;

    Log::Line(L"    диагностика опыта включена: на каждую выдачу пишем урон игрока, максимум "
              L"здоровья монстра, базовый опыт и начисленное значение (правок в расчёт НЕ вносим)");
    return PatchResult::Applied;
}
