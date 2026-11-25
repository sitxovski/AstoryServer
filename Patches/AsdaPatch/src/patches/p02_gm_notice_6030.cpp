// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P02 — GM-объявление: клиентский опкод 6030 -> sendNoticeClient (3113 всем).
//
//  В стоке ветка диспетчера case 0x178E (6030) зовёт Send_ScreenShotCommand
//  @0x551000 — по сути мёртвую команду. Живой сервер подменял цель вызова
//  @0x42CF5D на свой code-cave, который под гейтом «оператор?» отправлял тело
//  пакета (со смещения +0x18) в sendNoticeClient.
//
//  Место вызова в стоке (проверено дизассемблером):
//      0x42CF45  lea  edx, [ebp-0x1048]      ; a3 = буфер пакета
//      0x42CF4B  push edx
//      0x42CF4C  mov  ax,  [ebp-0x44]        ; arg0 = userNum
//      0x42CF50  push eax
//      0x42CF51  mov  ecx, [ebp-0x10C4]
//      0x42CF57  mov  edx, [ecx+4]
//      0x42CF5A  mov  ecx, [edx+0x34]        ; ecx = CUserManager
//      0x42CF5D  call 0x551000               <-- ЗАМЕНЯЕМ цель на свой обработчик
//  Сигнатура: int __thiscall (CUserManager*, __int16 userNum, int* pkt), ret 8.
//
//  ★ ИСПРАВЛЕНА МИНА ОРИГИНАЛЬНОЙ ПРАВКИ. В бинарном кейве @0x582A80 пролог
//    делал `push ecx` (резервируя локал [ebp-4]), но `mov [ebp-4], ecx`
//    ОТСУТСТВОВАЛ — оба последующих `mov ecx,[ebp-4]` читали неинициализированную
//    ячейку стека. Работало лишь потому, что там обычно оказывалось сохранённое
//    значение вызывающего. Здесь this сохраняется явно.
//
//  ⚠ Известное ограничение (сохранено как в оригинале, не «чиним» молча):
//    тело пакета не валидируется (нет Secret/MD5-проверки) и берётся как
//    C-строка от pkt+0x18. Путь закрыт гейтом оператора. Кандидат на отдельную
//    доработку — см. док.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    // Косвенные цели: адреса абсолютные, вызываем через память,
    // чтобы не портить регистры вычислением адреса.
    DWORD g_pIsOperator = Srv::kIsOperator;     // char __thiscall (mgr, __int16 idx)
    DWORD g_pSendNotice = Srv::kSendNotice;     // BOOL __thiscall (mgr, const char* text)

    // call 0x551000
    const BYTE kOrigCall[5] = { 0xE8, 0x9E, 0x40, 0x12, 0x00 };

    __declspec(naked) void GmNoticeHandler()
    {
        __asm
        {
            push ebp
            mov  ebp, esp
            push ecx                            // локал [ebp-4]
            mov  dword ptr [ebp-4], ecx         // * ФИКС: сохранить this (мина оригинала)

            movsx eax, word ptr [ebp+8]         // userNum
            push eax
            mov  ecx, dword ptr [ebp-4]
            call dword ptr [g_pIsOperator]      // callee чистит 4 байта
            test al, al
            je   skip                           // не оператор -> тихий выход

            mov  eax, dword ptr [ebp+0x0C]      // pkt
            add  eax, 0x18                      // тело объявления
            push eax
            mov  ecx, dword ptr [ebp-4]
            call dword ptr [g_pSendNotice]      // callee чистит 4 байта
        skip:
            mov  esp, ebp
            pop  ebp
            ret  8
        }
    }
}

PatchResult P02_GmNotice6030()
{
    if (!Config::GetBool(L"P02_GmNotice6030", L"Enabled", true)) { return PatchResult::Disabled; }

    const Site sites[] = { { Srv::Hooks::kGmNotice6030Call, kOrigCall, sizeof(kOrigCall) } };
    if (!VerifyAllSites(L"P02", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteCall(Srv::Hooks::kGmNotice6030Call, &GmNoticeHandler, sizeof(kOrigCall)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P02: call @0x%08X: 0x%08X (Send_ScreenShotCommand) -> 0x%08X (наш обработчик)",
              Srv::Hooks::kGmNotice6030Call, 0x00551000, (DWORD)&GmNoticeHandler);
    return PatchResult::Applied;
}
