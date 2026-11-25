// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P32 — ★ ПИТОМЦЫ: ОТКАЗ ПО charId УХОДИЛ ЧУЖИМ ОПКОДОМ 6101 (2026-09-27)
//
//  ЭТО НАША ПРАВКА (дефект стока, копипаста опкода). Документ патча:
//  AstoryServer/Docs/GameServer/pet-wrong-opcode-6101-p32.md; итог волны —
//  Reports/owner_0927/p31_p32.md.
//
//  Две ветки «charId запроса не совпал с CUser+0x174» отвечают опкодом 6101
//  (ответ на призыв, тело 9 б), но телом ЧУЖОГО размера:
//    ПД1  Recv_IncubatorReq   @0x454F70 (GameServer.c:34563-34566): тело 18 б = 6103;
//    ПД2  Recv_PetConditionUp @0x4576E0 (GameServer.c:35529-35532): тело 89 б = 6109.
//  Оригинальный клиент уводит такой 6101 в refineHandleItemLockNotify (network.c:552),
//  тот отсекает его по charId −1 — окно инкубатора залипает «жду ответа».
//
//  Лечение: меняется ТОЛЬКО байт immediate опкода (VA+1 команды push 17D5h).
//  Длина тела, тело, кадр, вызовы — стоковые. Раскладка пакетов НЕ меняется:
//  исправленный опкод получает ровно тот размер тела, который его приёмник читает
//  (6103 — 18 б, npc_mob_pet.c:5075; 6109 — 89 б, network.c:25896). Коды ответа —
//  стоковые (конструкторы sub_45B7F0 / sub_45B920 кладут 0), клиенту известны:
//  6103 код 0 → default:break + общий хвост «сброс окна» (npc_mob_pet.c:5155-5163);
//  6109 → charId −1 ≠ свой → безопасный no-op (network.c:25905).
//
//  ★ Площадки (2), сверены побайтно 27.09.2026 в ЧЕТЫРЁХ образах: наш
//  RE/ida/server_work/GameServer.exe, ЖИВОЙ v2\GameServer и v2\Indun_GameServer
//  (все MD5 E7B4AC38…) и сток GameServer.exe_before_mine_patch.exe (4E20F0AD…).
//  Сверяются 7 байт «push <длина>; push 17D5h» — с длиной ЧУЖОГО опкода площадка
//  неотличима от законного 6101 быть не может (у всех 5 законных 6101 — `6A 09`).
//    A  0x00455100  6A 12 68 D5 17 00 00   push 12h; push 17D5h   → байт 0x455103 D5→D7 (6103)
//    B  0x0045786C  6A 59 68 D5 17 00 00   push 59h; push 17D5h   → байт 0x45786F D5→DD (6109)
//  Переходов внутрь 0x455103…0x455106 и 0x45786F…0x457872 нет (сплошной скан
//  rel8/rel32/jcc + абсолютные DWORD, док §3). С P01…P36 не пересекается.
//
//  Ключи [P32_PetWrongOpcode6101]:
//    Enabled        — главный выключатель секции (1)
//    FixIncubator   — ПД1: 6101 → 6103 в отказе Recv_IncubatorReq (1)
//    FixConditionUp — ПД2: 6101 → 6109 в отказе Recv_PetConditionUp (1)
//  Журнал: только строки установки в PatchLog (2 строки). Сами срабатывания сервер
//  пишет штатно в Log_Pet («… UserInfo incorrect...!», GameServer.c:34565/35531) —
//  своего журнала у патча нет, наводнить нечем.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* const S = L"P32_PetWrongOpcode6101";

    // push <длина тела>; push 17D5h (6101)
    const BYTE kOrigA[7] = { 0x6A, 0x12, 0x68, 0xD5, 0x17, 0x00, 0x00 };   // 18 = тело 6103
    const BYTE kOrigB[7] = { 0x6A, 0x59, 0x68, 0xD5, 0x17, 0x00, 0x00 };   // 89 = тело 6109

    constexpr DWORD kSiteA = 0x00455100;   // Recv_IncubatorReq, отказ по charId
    constexpr DWORD kSiteB = 0x0045786C;   // Recv_PetConditionUp, отказ по charId
}

PatchResult P32_PetWrongOpcode6101()
{
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }

    const bool fixA = Config::GetBool(S, L"FixIncubator",   true);
    const bool fixB = Config::GetBool(S, L"FixConditionUp", true);
    if (!fixA && !fixB) { return PatchResult::Disabled; }

    // Сверяем ОБЕ площадки до любой записи: половинчатая установка недопустима,
    //   даже если одна из правок выключена ключом.
    const Site sites[] =
    {
        { kSiteA, kOrigA, sizeof(kOrigA) },
        { kSiteB, kOrigB, sizeof(kOrigB) },
    };
    if (!VerifyAllSites(L"P32", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (fixA)
    {
        if (!Hook::WriteByteChecked(kSiteA + 3, 0xD5, 0xD7)) { return PatchResult::Failed; }
        Log::Line(L"    P32: 0x00455102 17D5 -> 17D7 (6101 -> 6103, Recv_IncubatorReq, отказ по charId)");
    }
    else
    {
        Log::Line(L"    P32: FixIncubator=0 — 0x00455102 остаётся 6101 (сток)");
    }
    if (fixB)
    {
        if (!Hook::WriteByteChecked(kSiteB + 3, 0xD5, 0xDD)) { return PatchResult::Failed; }
        Log::Line(L"    P32: 0x0045786E 17D5 -> 17DD (6101 -> 6109, Recv_PetConditionUp, отказ по charId)");
    }
    else
    {
        Log::Line(L"    P32: FixConditionUp=0 — 0x0045786E остаётся 6101 (сток)");
    }
    return PatchResult::Applied;
}
