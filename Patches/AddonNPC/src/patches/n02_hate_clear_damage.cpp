// Copyright (c) 2026 @sitxovski (Discord)
// n02_hate_clear_damage.cpp — ВОЗРОЖДЕНИЕ МОНСТРА ЧИСТИТ НАКОПЛЕННЫЙ УРОН В СПИСКЕ УГРОЗЫ.
//
// СИМПТОМ
//   Изредка убийство монстра проходит «вхолостую»: монстр умер, а опыта, добычи и
//   квестового прогресса нет. Либо добыча достаётся не тому игроку.
//
// МЕХАНИЗМ — два дефекта, работающие в паре
//   Список угрозы: 20 записей по 16 байт, начало `+31352`.
//       +0  i16  индекс игрока (0xFFFF = запись пуста)
//       +4  i32
//       +8  i32
//       +12 i32  накопленный урон  <- им решается, КОМУ достанется опыт и добыча
//
//   Дефект 1 — поиск победителя не проверяет занятость первой записи
//   (`NpcServer.exe.c:41195-41215`):
//       v3 = 0;                          // победитель по умолчанию — запись 0
//       v4 = *(int *)(a1 + 31364);       // её урон, БЕЗ проверки занятости
//       v6 = (int *)(a1 + 31380);        // сравниваем с записями 1..19
//       do { if ( *((WORD *)v6 - 6) != 0xFFFF ) { … } … }   // занятость только у 1..19
//
//   Дефект 2 — возрождение чистит запись не полностью (`sub_43E300`, `:44956-44964`):
//       v6 = (DWORD *)(a1 + 31356);  v7 = 20;
//       do { v6[1] = 0; *v6 = 0; *((WORD *)v6 - 2) = -1; v6 += 4; --v7; } while (v7);
//   Обнуляются +0, +4, +8. Поле +12 НЕ трогается — переживает смерть монстра.
//
//   Итог: в записи 0 остаётся мусор от прошлой жизни. Если он не меньше урона настоящих
//   участников боя, победителем объявляется пустая запись, сервер получает некорректный
//   индекс владельца и уходит в раннюю ошибку. Реальное срабатывание в живом журнале:
//   `Exception_20260803.txt:705` («ItemOwnerIndex is invalid»).
//
// ЧТО ДЕЛАЕМ
//   Чиним дефект 2 — он и есть источник мусора. Поиск не трогаем: без мусора он на этом
//   сценарии перестаёт ошибаться. (Правку самого поиска делать через врезку — она станет
//   возможна теперь, когда правки живут в DLL; пока не сделана.)
//
//   Цикл переписан так, чтобы уложиться в ТЕ ЖЕ 18 байт:
//       было:  nop / mov [eax+4],esi / mov [eax],esi / mov word [eax-4],di
//              add eax,16 / sub ecx,1 / jnz
//       стало: mov [eax+4],esi / mov [eax],esi / mov [eax+8],esi / mov word [eax-4],di
//              add eax,16 / dec ecx / jnz
//   Три нужных байта взяты из снятого байта выравнивания (1) и замены `sub ecx,1` на
//   однобайтовый `dec ecx` (2). `esi` в этом месте уже равен нулю — им же обнуляются два
//   других поля; `di` = 0xFFFF. `dec` не трогает флаг переноса, а следующая за циклом
//   инструкция (`mov eax, [ebp+8]`) флаги не читает — поведение не меняется.
//
// ⚠ Байты выверены на образе NpcServer.exe md5 d292e4ec4edfd5040d8fb39382664eab.
//   Запасной путь в виде скрипта:
//   AstoryServer/Docs/NpcServer/patch_npc_hate_clear_damage.py
#include "Patches.h"
#include "../Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const DWORD kVa = 0x43E42F;
    const BYTE  kOrig[] = {
        0x90,                                // nop
        0x89,0x70,0x04,                      // mov  [eax+4], esi
        0x89,0x30,                           // mov  [eax], esi
        0x66,0x89,0x78,0xFC,                 // mov  word [eax-4], di
        0x83,0xC0,0x10,                      // add  eax, 16
        0x83,0xE9,0x01,                      // sub  ecx, 1
        0x75,0xEF                            // jnz  loop
    };
    const BYTE  kNew[] = {
        0x89,0x70,0x04,                      // mov  [eax+4], esi
        0x89,0x30,                           // mov  [eax], esi
        0x89,0x70,0x08,                      // mov  [eax+8], esi   <- НОВОЕ: обнуление +12
        0x66,0x89,0x78,0xFC,                 // mov  word [eax-4], di
        0x83,0xC0,0x10,                      // add  eax, 16
        0x49,                                // dec  ecx
        0x75,0xEE                            // jnz  loop (метка сдвинулась на 1 байт назад)
    };
    static_assert(sizeof(kOrig) == sizeof(kNew), "длина площадки обязана совпадать");

    const Site kSites[] = { { kVa, kOrig, sizeof(kOrig) } };
}

PatchResult N02_HateClearDamage()
{
    if (!Config::GetBool(L"N02_HateClearDamage", L"Enabled", true))
        return PatchResult::Disabled;

    if (!VerifyAllSites(L"N02_HateClearDamage", kSites, ARRAYSIZE(kSites)))
        return PatchResult::Mismatch;

    if (!Hook::WriteBytes(kVa, kNew, sizeof(kNew))) return PatchResult::Failed;

    Log::Line(L"    возрождение монстра обнуляет и накопленный урон (+12) в каждой из 20 "
              L"записей списка угрозы");
    return PatchResult::Applied;
}
