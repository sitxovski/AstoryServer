// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P05 — премиум-гача: добавленная отправка в хвосте Recv_UserPrimiumGaCha@0x4F6F10.
//  Перенос 1:1 бинарного кейва живого сервера (0x582843).
//
//  Сток @0x4F7084 (26 байт, дальше идёт /GS-эпилог функции):
//      movsx eax, byte ptr [ebp-0x5C]
//      imul  eax, eax, 6
//      mov   ecx, dword ptr [0x7E0380]
//      mov   edx, dword ptr [ecx+eax+2]
//      mov   dword ptr [ebp-0x48], edx
//      mov   al,  byte ptr [ebp-0x5C]
//      mov   byte ptr [ebp-0x55], al
//    0x4F709E: mov ecx,[ebp-4]; xor ecx,ebp   <-- ВОЗВРАТ сюда
//
//  Патч воспроизводит эти инструкции и добавляет: конструктор структуры 0x78 байт
//  на стеке (sub_4FAD00), заполнение пяти полей и отправку через sub_4F60E0
//  с кодом 105 (0x69).
//
//  ★ НАЗНАЧЕНИЕ ПОДТВЕРЖДЕНО (аудит 2026-08-17, Reports/gacha_server_patch_audit.md —
//    прежняя пометка «гипотеза» снята): `sub_4F60E0` — диспетчер запросов к GP7-агенту,
//    а `case 105 (0x69)` @0x4F64C6 = «LuckyBox Item Buy Request» (команда 0x50, длина 173,
//    subtype 2). Это РОДНОЙ код разработчиков, который в стоке НЕ ЗАВЕДЁН: успешная ветка
//    считала цену и уходила в /GS-эпилог, а `case 105` был недостижим ни прямо, ни косвенно
//    (сплошной скан .text: 3 площадки вызова 0x4F60E0 с кодами 153/121/137, литерал адреса —
//    0 вхождений). Патч подключает существующую ветку, а не изобретает протокол.
//    Размер записи подтверждён трижды: `sub esp,0x78` ↔ `rep movsd 0x1E` в case 105 ↔
//    `push 0x78` эталонного отправителя.
//
//  ⚠ Д2 (остаётся как в оригинале): поле @94 = `itemCode` получает индекс коробки. Наш GP7
//    для subtype 2 его не читает (награда выбирается из пула по boxType@71), в логах
//    `requestItemCode=0`. Не правим: без реверса оригинального арабского агента нельзя
//    утверждать, что там должно лежать — возможно, авторы `case 105` и задумывали индекс.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_pCtor0x78 = 0x004FAD00;     // __thiscall(void* buf) — конструктор структуры 0x78
    DWORD g_pSend     = 0x004F60E0;     // __thiscall(mgr, int code, __int16 userNum, void* buf)
    DWORD g_pRet      = 0x004F709E;     // возврат в хост

    // ★ Д1 (правка 2026-08-17, санкция юзера): номер канала сервера.
    //   `0x4A7EB0` — __thiscall(this) → канал в al. Тело: `push ebp; mov ebp,esp; push ecx;
    //   mov [ebp-4],ecx; mov al, byte ptr [0x5F5EB4]; mov esp,ebp; pop ebp; ret` — то есть
    //   `this` сохраняется, но НЕ используется: значение читается из глобала. Все 119 вызовов
    //   в стоке идут с `mov ecx, 0x60AD18`, поэтому и здесь передаём тот же объект.
    //   ⚠ В отчёте аудита функция описана как «__cdecl без аргументов» — это неточность,
    //     проверено по байтам стока (GameServer.exe_before_mine_patch.exe, MD5 4e20f0ad…).
    DWORD g_pGetChannel = 0x004A7EB0;
    DWORD g_pChannelObj = 0x0060AD18;

    const BYTE kOrig[26] =
    {
        0x0F,0xBE,0x45,0xA4,                    // movsx eax, byte ptr [ebp-0x5C]
        0x6B,0xC0,0x06,                         // imul  eax, eax, 6
        0x8B,0x0D,0x80,0x03,0x7E,0x00,          // mov   ecx, dword ptr [0x7E0380]
        0x8B,0x54,0x01,0x02,                    // mov   edx, dword ptr [ecx+eax+2]
        0x89,0x55,0xB8,                         // mov   dword ptr [ebp-0x48], edx
        0x8A,0x45,0xA4,                         // mov   al,  byte ptr [ebp-0x5C]
        0x88,0x45,0xAB                          // mov   byte ptr [ebp-0x55], al
    };

    __declspec(naked) void PrimiumGachaTrampoline()
    {
        __asm
        {
            // ── оригинальные инструкции ──
            movsx eax, byte ptr [ebp-0x5C]
            imul  eax, eax, 6
            // ⚠ ds: обязателен: без сегментного префикса MSVC собирает [число] как
            //   ЗАГРУЗКУ КОНСТАНТЫ (mov ecx, imm32), а не чтение памяти.
            mov   ecx, dword ptr ds:[0x007E0380]
            mov   edx, dword ptr [ecx+eax+2]
            mov   dword ptr [ebp-0x48], edx
            mov   al,  byte ptr [ebp-0x5C]
            mov   byte ptr [ebp-0x55], al

            // ── добавленная отправка ──
            sub   esp, 0x78
            lea   ecx, [esp]
            call  dword ptr [g_pCtor0x78]
            mov   eax, dword ptr [ebp-0x60]
            mov   dword ptr [esp+1], eax
            movzx eax, byte ptr [ebp-0x5C]
            mov   byte ptr [esp+5], al          // @5  = boxType (индекс коробки — так и надо)
            mov   dword ptr [esp+0x5E], eax     // @94 = itemCode; см. Д2 в шапке — оставлено как в оригинале

            // ★★★ ПРАВКА Д1 (2026-08-17, санкция юзера). Было: `mov byte ptr [esp+6], al` —
            //   в поле @6 попадал ИНДЕКС КОРОБКИ, а `case 105` формирует из него строку
            //   `sprintf("channel%d", rec[3]+1)` → payload@112 исходящего пакета 0x50.
            //   Эталонные ветки (`case 121`, `SendNewPremiumPacket`) кладут туда НАСТОЯЩИЙ
            //   номер канала из 0x4A7EB0. Пока в PrimiumGaChaPriceTable.txt одна строка,
            //   индекс всегда 0 и наружу уходило «channel1» — то есть дефект был латентным;
            //   со второй строкой в таблице в биллинг уходил бы неверный канал.
            //   Откат правки = удалить этот блок и вернуть `mov byte ptr [esp+6], al`.
            push  eax                           // сохранить индекс (eax нужен ниже)
            mov   ecx, dword ptr [g_pChannelObj]
            call  dword ptr [g_pGetChannel]     // __thiscall(this) → канал в al
            mov   byte ptr [esp+0x0A], al       // @6 записи; +4 из-за push
            pop   eax

            mov   eax, dword ptr [ebp-0x48]
            mov   dword ptr [esp+0x67], eax     // @103 = price из PrimiumGaChaPriceTable
            lea   eax, [esp]
            push  eax
            mov   dx, word ptr [ebp+8]
            push  edx
            push  0x69                          // 105
            mov   ecx, dword ptr [ebp-0x68]
            call  dword ptr [g_pSend]           // callee чистит 3 аргумента
            add   esp, 0x78

            jmp   dword ptr [g_pRet]
        }
    }
}

PatchResult P05_PrimiumGachaExtraSend()
{
    if (!Config::GetBool(L"P05_PrimiumGachaExtraSend", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] = { { Srv::Hooks::kPrimiumGacha, kOrig, sizeof(kOrig) } };
    if (!VerifyAllSites(L"P05", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(Srv::Hooks::kPrimiumGacha, &PrimiumGachaTrampoline, sizeof(kOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P05: перехват @0x%08X (26 б) -> трамплин 0x%08X, возврат 0x%08X",
              Srv::Hooks::kPrimiumGacha, (DWORD)&PrimiumGachaTrampoline, g_pRet);
    return PatchResult::Applied;
}
