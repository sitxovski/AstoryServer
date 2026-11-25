// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P106 — [ИСПРАВЛЕНИЕ] ПРИНЯВШИЙ ДРУЖБУ ПОЛУЧАЕТ 4151 ПРИ ФЛАГЕ 2 `UPFriendAdd` (05.11.2026, сессия friend-accept;
//  решение владельца «дефекты оригинала исправляем»). Документ: AstoryServer/Docs/GameServer/friend-accept-notify-p106.md.
//
//  Принявший (B) шлёт 0x1039 → Recv_UserFriendOK@0x537BF0 (GameServer.c:118977) → DB 2215 с заголовком userNum = пригласивший
//  (A), блок 16 б: +2 userIndex A, +6 charIdx A, +7 i16 userNum A, +9 i16 userNum B, +11 userIndex B, +15 charIdx B.
//  DBManager sub_42AD80 (RE/ida/db_work/DBManager.exe.c:19285): EXEC UPFriendAdd @Userindex=A, @Fuserindex=B; эхо блока,
//  байт 0 = Flag. Флаги процедуры: 1 — добавлены обе строки; 2 — у A уже был B, вставлена строка B→A; 3 — у B уже был A,
//  вставлена строка A→B; 4/5/6 — полон список A/B/обоих; 7 — оба уже друзья; 0 — ошибка.
//  Ответ 2216 (0x8A8) → sub_406370@0x406370 (GameServer.c:2542): для 1/2/3 при обоих в сети — 4151 код 1 с записью B
//  ПРИГЛАСИВШЕМУ (A, 0x40651B); затем `if (flag == 1 || flag == 3)` (0x406520…0x406530) — 4151 код 1 с записью A ПРИНЯВШЕМУ (B,
//  0x406618).
//
//  ── ДЕФЕКТ ──
//  Флаг 2: в БД появилась строка B→A (список B пополнился), а B не получает 4151 — ни сообщения «добавлен в друзья», ни записи
//  в списке до перезахода. При флаге 3 сток, наоборот, шлёт B запись A, которая у него уже была (безвредно: клиент обновляет
//  запись по ключу). Условие, по смыслу процедуры, должно пропускать все три флага успеха.
//
//  ── ЧТО ДЕЛАЕТ P106 (22 байта, протокол 4151 / 2215 / 2216 не меняется) ──
//  Участок 0x406520 (22 б) `movzx eax,[ebp-34h]; cmp eax,1; je 0x406536; movzx ecx,[ebp-34h]; cmp ecx,3; jne 0x40661D` заменяется
//  на `movzx eax,[ebp-34h]; dec eax; cmp eax,2; ja 0x40661D; nop8` — ветка принявшего идёт при флаге 1…3 (проверка явная,
//  не по инварианту ветки выше). eax/ecx после участка читаются только после новой записи (0x406545 / 0x406548) — регистры
//  стока не нужны. Переходов внутрь 0x406521…0x406535 нет (verify_p106). Ключ [P106_FriendAcceptNotify] Enabled (0 — сток).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P106_FriendAcceptNotify";   // секция patches.ini

    // ── площадки и соседи (байты живого GameServer.exe e7b4ac38) ─────────────
    // 0x406520: movzx eax,[ebp-34h] · cmp eax,1 · je 0x406536 · movzx ecx,[ebp-34h] · cmp ecx,3 · jne 0x40661D — условие стока.
    const BYTE kCond[] = { 0x0F, 0xB6, 0x45, 0xCC, 0x83, 0xF8, 0x01, 0x74, 0x0D, 0x0F, 0xB6, 0x4D, 0xCC, 0x83, 0xF9, 0x03,
                           0x0F, 0x85, 0xE7, 0x00, 0x00, 0x00 };
    // То же место после P106: movzx eax,[ebp-34h] · dec eax · cmp eax,2 · ja 0x40661D · nop dword [eax+eax+0] (8 б).
    const BYTE kNew[]  = { 0x0F, 0xB6, 0x45, 0xCC, 0x48, 0x83, 0xF8, 0x02, 0x0F, 0x87, 0xEF, 0x00, 0x00, 0x00,
                           0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static_assert(sizeof(kCond) == sizeof(kNew), "P106: длина участка");
    // 0x4063A8: movzx edx,[ebp-34h] · cmp edx,1 · je · movzx eax,[ebp-34h] · cmp eax,2 · je · movzx ecx,[ebp-34h] · cmp ecx,3 · je —
    //   вход ветки успеха (флаг 1/2/3).
    const BYTE kGate[] = { 0x0F, 0xB6, 0x55, 0xCC, 0x83, 0xFA, 0x01, 0x74, 0x3C, 0x0F, 0xB6, 0x45, 0xCC, 0x83, 0xF8, 0x02, 0x74, 0x33,
                           0x0F, 0xB6, 0x4D, 0xCC, 0x83, 0xF9, 0x03, 0x74, 0x2A };
    // 0x406509: mov cx,[ebp+8] · push ecx · push 20h · push 1037h — 4151 пригласившему (a2).
    const BYTE kSendA[] = { 0x66, 0x8B, 0x4D, 0x08, 0x51, 0x6A, 0x20, 0x68, 0x37, 0x10, 0x00, 0x00 };
    // 0x406536: mov [ebp-5Ch],0 · mov dx,[ebp+8] · push edx — начало ветки принявшего (CUser пригласившего для записи).
    const BYTE kBranch[] = { 0xC7, 0x45, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8B, 0x55, 0x08, 0x52 };
    // 0x406606: mov dx,[ebp-2Bh] · push edx · push 20h · push 1037h — 4151 принявшему (блок +9).
    const BYTE kSendB[] = { 0x66, 0x8B, 0x55, 0xD5, 0x52, 0x6A, 0x20, 0x68, 0x37, 0x10, 0x00, 0x00 };
    // 0x40661D: mov ecx,[ebp-4] · xor ecx,ebp — эпилог (цель перехода «не слать»).
    const BYTE kEpi[] = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD };

    constexpr DWORD kSite = 0x00406520;   // условие ветки принявшего
}

PatchResult P106_FriendAcceptNotify()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }

    const Site check[] =
    {
        { kSite, kCond, sizeof(kCond) }, { 0x004063A8, kGate, sizeof(kGate) }, { 0x00406509, kSendA, sizeof(kSendA) },
        { 0x00406536, kBranch, sizeof(kBranch) }, { 0x00406606, kSendB, sizeof(kSendB) }, { 0x0040661D, kEpi, sizeof(kEpi) },
    };
    if (!VerifyAllSites(L"P106", check, ARRAYSIZE(check))) { return PatchResult::Mismatch; }

    if (!Hook::WriteBytes(kSite, kNew, sizeof(kNew))) { return PatchResult::Failed; }
    if (memcmp((const void*)kSite, kNew, sizeof(kNew)) != 0) { return PatchResult::Failed; }
    Log::Line(L"    P106: ответ дружбы 2216 (sub_406370) — 4151 принявшему при флаге UPFriendAdd 1…3 (сток: только 1 и 3; "
              L"при 2 строка B→A в БД есть, а принявший не узнавал); участок @0x%08X 22 б", kSite);
    return PatchResult::Applied;
}
