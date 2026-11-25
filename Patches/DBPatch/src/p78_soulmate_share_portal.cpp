// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P78 — ★★ СТРОКИ «ПОДЕЛИТЬСЯ» СОУЛМЕЙТА ПРИ ПОРТАЛЕ (DB 2089) РАЗБИРАЮТСЯ С ВЕРНЫМ ШАГОМ.
//  DBManager, sub_417410@0x00417410 (приём DB-опкода 2089 от GameServer `CharPortalLogonReq`,
//  ответ-сводка соулмейта 2145, 238 б).
//
//  ДЕФЕКТ [ОРИГИНАЛ, сервер]. Оба обработчика логона — вход 2001 (sub_407480) и портал 2089
//  (sub_417410) — после `EXEC UPSoulMateShare` раскладывают строки результата (Charidx tinyint,
//  Charname varchar(20), Share tinyint = 22 байта на строку) в блок соулмейта: имя i → 20 байт,
//  флаг i → 1 байт. Вход делает это верно:
//      0x409732  lea edx,[ebp+ecx-0x734F]   ; имя = строка + 1 (буфер строк [ebp-0x7350])
//      0x40975B  lea eax,[ebp+edx-0x733B]   ; флаг = строка + 0x15
//      0x40977F  add eax,0x16               ; шаг строки 22
//  а портал — со шагом 21 и без пропуска байта Charidx:
//      0x419156  lea ecx,[ebp+eax-0x72E8]   ; имя = строка + 0  (буфер строк [ebp-0x72E8])
//      0x41917F  lea edx,[ebp+ecx-0x72D4]   ; флаг = строка + 0x14 (это последний байт ИМЕНИ)
//      0x4191A3  add edx,0x15               ; шаг строки 21
//  Итог после КАЖДОГО портала: в CUser+99031..99093 GameServer (блок соулмейта) имя 1 = байт 0x0A +
//  19 байт имени, имена 2/3 сдвинуты, а Share1..3 = байты имён (для имени короче 19–20 символов — 0).
//  Блок уходит клиенту в 5220 (смена состояния пары, `Send_SoulMateInfo`), а клик по любой галке
//  5221 пишет эти нули в dbo.CharInfo.Share (`UPSoulMateOptionUp`) — «флаг share сбрасывается».
//  Доказано двумя методами: декомпил (`RE/ida/db_work/DBManager.exe.c:11106-11111` против
//  `:3330-3335`) и дизассемблер живого образа (md5 3d05c835…, байты ниже).
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Три замены той же длины — раскладка портала становится байт в байт как у входа:
//      8D 8C 05 18 8D FF FF   lea ecx,[ebp+eax-0x72E8]  →  8D 8C 05 19 8D FF FF  lea ecx,[ebp+eax-0x72E7]
//      8D 94 0D 2C 8D FF FF   lea edx,[ebp+ecx-0x72D4]  →  8D 94 0D 2D 8D FF FF  lea edx,[ebp+ecx-0x72D3]
//      83 C2 15               add edx,0x15              →  83 C2 16              add edx,0x16
//  Чтение не выходит за буфер: строк не больше 3 (гейт `> 3 → 3` стоит выше), 3·22 = 66 б в
//  буфере 0x36B0 б. Длина ответа 2145, раскладка и опкоды НЕ меняются (old-server-protocol-compat).
//  строки по слотам 10/11/12, поэтому «строка i» и есть «слот Charidx 10+i» и при входе, и при портале.
//  Площадки внутри sub_417410; P50 перехватывает ВЫЗОВ этой функции в диспетчере (0x402FE3) и с ними
//  не пересекается.
//
//  Рантайм-кода у патча нет (чистая замена байт) — журнал в работе не пишется.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"

namespace
{
    const wchar_t* const S = L"P78_SoulmateSharePortal";

    // Оригинал (сток = живой образ): разбор строк UPSoulMateShare в обработчике портала 2089.
    const BYTE kOrigName [7] = { 0x8D, 0x8C, 0x05, 0x18, 0x8D, 0xFF, 0xFF };   // 0x419156 lea ecx,[ebp+eax-0x72E8]
    const BYTE kOrigShare[7] = { 0x8D, 0x94, 0x0D, 0x2C, 0x8D, 0xFF, 0xFF };   // 0x41917F lea edx,[ebp+ecx-0x72D4]
    const BYTE kOrigStep [3] = { 0x83, 0xC2, 0x15 };                           // 0x4191A3 add edx,0x15

    // Замена: та же раскладка, что у входа 2001 (имя +1, флаг +0x15, шаг 0x16).
    const BYTE kNewName  [7] = { 0x8D, 0x8C, 0x05, 0x19, 0x8D, 0xFF, 0xFF };   // lea ecx,[ebp+eax-0x72E7]
    const BYTE kNewShare [7] = { 0x8D, 0x94, 0x0D, 0x2D, 0x8D, 0xFF, 0xFF };   // lea edx,[ebp+ecx-0x72D3]
    const BYTE kNewStep  [3] = { 0x83, 0xC2, 0x16 };                           // add edx,0x16

    constexpr DWORD kSiteName  = 0x00419156;
    constexpr DWORD kSiteShare = 0x0041917F;
    constexpr DWORD kSiteStep  = 0x004191A3;
}

PatchResult P78_SoulmateSharePortal()
{
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    const Site sites[] =
    {
        { kSiteName,  kOrigName,  sizeof(kOrigName)  },
        { kSiteShare, kOrigShare, sizeof(kOrigShare) },
        { kSiteStep,  kOrigStep,  sizeof(kOrigStep)  },
    };
    // Сверяем ВСЕ три до первой записи: либо ставим целиком, либо не ставим вовсе
    //   (частичная замена дала бы ещё более кривую раскладку, чем сток).
    if (!VerifyAllSites(L"P78", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    bool ok = true;
    ok &= Hook::WriteBytes(kSiteName,  kNewName,  sizeof(kNewName));
    ok &= Hook::WriteBytes(kSiteShare, kNewShare, sizeof(kNewShare));
    ok &= Hook::WriteBytes(kSiteStep,  kNewStep,  sizeof(kNewStep));
    if (!ok)
    {
        Log::Line(L"    P78: ! ошибка записи хотя бы одной площадки — раскладка share при портале может быть частичной");
        return PatchResult::Failed;
    }

    Log::Line(L"    P78: 0x%08X/0x%08X/0x%08X: разбор UPSoulMateShare в портале 2089 — имя +1, флаг +0x15, шаг 0x16 "
              L"(как у входа 2001)", kSiteName, kSiteShare, kSiteStep);
    Log::Line(L"    P78: имена и флаги «поделиться» соулмейта после портала больше не сдвигаются; протокол не менялся");
    return PatchResult::Applied;
}
