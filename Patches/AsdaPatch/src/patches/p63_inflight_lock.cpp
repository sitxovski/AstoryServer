// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P63 — ★ ОБЩИЙ ЗАМОК «ЗАПРОС В БД В ПОЛЁТЕ» (античит, волна A7 «экономика / предметы / рыбалка-лут-квесты»,
//  2026-10-12; план 00_PLAN.md §8 механизм L2 + приоритет A6; 02_parts/economy2_handlers.md «Топ-5» п.5,
//  02_parts/fishing_loot_quests.md FISH-2 / FISH-5 / QUEST-3). [СЕРВЕР-ДОРАБОТКА, протокол не меняется]
//  Документ: `AstoryServer/Docs/GameServer/inflight-lock-p63.md`.
//
//  ── ДЫРА ──
//  У 25 обработчиков состояние меняется ТОЛЬКО в приёме ответа DBManager, а сам обработчик лишь проверяет память
//  и шлёт запрос (sub_5646C0). Пока ответ в пути, повтор того же пакета проходит все проверки заново и даёт ВТОРОЙ
//  запрос в БД (двойная покупка/разборка/награда/…). Свой замок есть только у 5018/5020 (gap_145[11]),
//  5033/6500 (gap_145[15]) и 6504 (P33 N-2) — здесь обобщение P33 N-2 на остальные семьи.
//
//  ── ЧТО ДЕЛАЕТ ──
//  Таблица замков g_lock[слот 0..0x225][семья] = (UserIndex, такт). Привязка к UserIndex: другая учётка в слоте =
//  замок чужой (не действует); тайм-аут LockTimeoutMs — потерянный ответ БД не запирает семью навсегда.
//  A. ПОСТАНОВКА — площадка `call sub_5646C0` (E8 rel32) в каждом обработчике, общий стаб St_Send: опкод БД и
//     индекс слота берутся со стека вызова (thiscall: [esp+4] op, [esp+20] userIdx), UserIndex — через `this`
//     обработчика из его кадра ([ebp-disp], адрес прологa `mov [ebp-disp],ecx` в таблице) → CUserManager →
//     sub_5324A0 → CUser+0x174. Замок уже стоит и жив: Mode=0 — журнал (вид 35), запрос ПРОХОДИТ;
//     Mode=1 — повторная отправка в БД подавляется (вид 37): стаб возвращает 0 и снимает 5 аргументов (ret 14h)
//     без вызова ConnectSend — клиент дубля ответа не получает, ответ на ПЕРВЫЙ запрос придёт как обычно (как
//     P33 N-2 «атомарная постановка»). Иначе замок ставится атомарно (критическая секция) и запрос уходит.
//  B. СНЯТИЕ — подмена `call recvDBxxx` в диспетчере ответов ConnectSocketMsgProcess@0x42FAB0 (как P33 у
//     0x432CE5; общий хвост 0x43462B занят P21 — не трогаем): стаб St_Reply_N → P63_ReplyWrap → СТОКОВЫЙ приём
//     ответа (eax возвращается как есть) → снятие ПОСЛЕ обработки (ревизия P33 М-2). Ответ для другой учётки
//     в слоте (UserIndex не совпал) замок НЕ снимает (вид 39); ответ после тайм-аута — вид 38 (замок уже не
//     действовал). Ответ 2270 (6098) приходит без UserNum в вызове — слот читается из тела (+0, как сток
//     sub_559900: `sub_5324A0(this, *(__int16*)v17)`).
//  C. РАННИЙ ОТКАЗ (Mode=1, EarlyRefuse=1) — там, где у обработчика есть штатная ветка «занят»: подмена
//     `call sub_52BFF0` у 5048 (0x5118FC → LABEL_4: 5049 код 0, GameServer.c:104505) и 6162 (0x515111 →
//     штатный хвост без ответа, GameServer.c:106139). Стаб зовёт сток; если сток вернул 0 и замок семьи
//     жив — возвращает 1 («занят»), и обработчик идёт СВОЕЙ веткой (6001 от sub_52BFF0 не шлётся — как
//     P33_PreambleGate у 6500…6506). Площадки sub_52BFF0 у 6502/6506 заняты P33 Д-1 — там только подавление.
//  D. ВЫХОД — `call sub_569DF0` внутри CUserManager::ClearUserMemory@0x527350 (0x527374, зовётся из всех 7
//     веток DisConnectUser, GameServer.c:111312…111612): все замки слота сбрасываются ДО обнуления
//     m_lpsUserInfo[slot]. Стаб хвостом уходит в писатель логов, стек не меняется.
//  Семьи (клиентский опкод → запрос БД → ответ БД): 5048→2072→2073, 6162→2469→2470, 6096→2272→2273,
//  6098→2270→2270, 6502→2302→2303, 6506→2306→2307, 6549→2527→2528, 6551→2529→2530, 6553→2531→2532,
//  5433→2165→2165, 5468→2229→2229, 6555→2533→2534, 6586→2568→2569, 6140→2452→2453, питомцы 6102→2275→2276,
//  6108→2278→2279, 6110→2280→2281, 6112→2282→2283, 6118→2292→2293, 6121→2294→2294, 6148→2464→2465,
//  рыбалка 6171→2577→2578 (FISH-2), 6182→2587→2588 (FISH-5), задания 6591→2653→2654, 6593→2657→2658 (QUEST-3).
//  НЕ СДЕЛАНО (доказательно): 5070 CharChargeShopBuy — запрос уходит в GP7 через sub_4F60E0 (0x4F62D0, опкод 80),
//  6-й аргумент ConnectSend там НЕ слот (sub_4C0250 — индекс потока), ответ 0x51 приходит от агента GP7 с тремя
//  типами (покупка/причёска/коробка) в одном опкоде, слот только в теле (+100), а реальный «полёт» кончается
//  ответом 2602 (RecvDB_InsertPremiumItem — площадки P06/P16). 6100 CallPet — у 2284 ответа нет (снять нечем).
//  Честный порт шлёт один запрос до ответа (FAsdaReplyLatch, asda.Disassembly.SingleInFlight и т. п.) — замок
//  на честном пути не срабатывает.
//  ЦЕПОЧКА С P62 (integ2, 2026-10-12): площадки отправки 6096/6506/6549/6555/6112 — тот же `call sub_5646C0`, что у
//  P62 (уникальность слотов). Если P62 их уже поставил (rel32 → стаб P62 этой площадки), P63 байты НЕ пишет: сверяет
//  исходные по таблице P62 и кладёт St_Send в слот «следующий вызов» стаба P62 (P62_ChainSend, Patches.h). Порядок в
//  рантайме P62 → P63 → sub_5646C0: отказ P62 не ставит замок. St_Send площадку по адресу возврата не определяет
//  (семья — по опкоду БД [esp+4], слот — [esp+20], this — из кадра ebp), а P62 уходит в него хвостовым jmp — вход тот же.
//  Безопасность: все площадки — `E8 rel32` целиком, байты сверены в трёх образах (сток 4e20f0ad, живой/Indun
//  e7b4ac38), переходов внутрь нет (tools/verify_p63.py); соседи — пролог `mov [ebp-disp],ecx` каждого
//  обработчика и прологи стоковых приёмов. Все чтения памяти сервера под __try.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P63_InFlightLock";

    constexpr int kMaxUser  = 0x226;   // слотов сессий (sub_5328F0)
    constexpr int kFamCount = 25;      // семей (см. kFam)
    constexpr int kKinds    = 5;       // видов журнала (35..39) — для ограничителя

    // Виды журнала (ac.other): 35..39 выданы координатором A7.
    enum Kind : BYTE { kDupJournal = 35, kDupEarly = 36, kDupSuppressed = 37, kLateReply = 38, kStaleReply = 39 };

    bool  g_enabled      = true;
    int   g_mode         = 0;        // 0 журнал, 1 отказ/подавление
    DWORD g_timeoutMs    = 15000;    // жизнь замка без ответа
    int   g_journalSec   = 10;       // ограничитель: не чаще 1 строки на (слот, вид)
    bool  g_earlyRefuse  = true;     // площадки sub_52BFF0 у 5048/6162
    bool  g_sessionClear = true;     // площадка ClearUserMemory
    bool  g_clearHooked  = false;    // ★ P75: площадку ClearUserMemory записал P63 (тогда P75 зовётся из P63_OnUserClear)
    int   g_logChannel   = 1;        // sub_569DF0: 1 = Log_Item
    bool  g_famOn[kFamCount] = {};

    typedef BYTE* (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);              // sub_5324A0 (thiscall i16)
    typedef int   (__fastcall *PFN_Recv2)(void* self, void* edx, int userNum, int pkt);        // recvDBxxx(this, UserNum, s)
    typedef int   (__fastcall *PFN_Recv1)(void* self, void* edx, int pkt);                     // sub_559900(this, s)
    typedef void  (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                     // sub_569DF0
    PFN_GetUser const pGetUser = (PFN_GetUser)Srv::kGetUser;
    PFN_SrvLog  const pSrvLog  = (PFN_SrvLog)Srv::kLog;

    constexpr int kOffUserNumW  = 0x0C;    // CUser+0x0C — слот (i16), самопроверка менеджера
    constexpr int kOffUserIndex = 0x174;   // CUser+0x174 — UserIndex (учётка)
    constexpr int kOffName      = 0x178;
    constexpr int kOffSlot      = 0x18C;
    constexpr int kOffBlockMgr  = 0x34;    // блок менеджеров потока (+0x34 = CUserManager; диспетчер: *(edx0[1]+52))

    // Как из `this` обработчика/приёма добраться до CUserManager (по декомпилу каждой функции):
    //   0 — this и есть CUserManager (`sub_5324A0((CUser*)this, arg0)`);
    //   1 — *(this+0)+0x34   (`*((CUser**)this->vftable + 13)`: CPetManager, CFishingManager);
    //   2 — *(this+4)+0x34   (`*((CUser**)*(this+1) + 13)` / `*(this->gap_4+52)`: для CUserManager = сам себя).
    struct Fam
    {
        WORD        clientOp, dbReq, dbReply;
        DWORD       sendVa;  BYTE sendBytes[5];          // call sub_5646C0 в обработчике
        int         thisDisp; BYTE thisKind;             // [ebp - thisDisp] = this обработчика
        DWORD       prologVa; BYTE prologBytes[6]; BYTE prologLen;   // сосед: mov [ebp-disp], ecx
        DWORD       replyVa; BYTE replyBytes[5];         // call recvDBxxx в ConnectSocketMsgProcess
        DWORD       replyTarget; BYTE replyNArgs; BYTE replyKind;
        const char* handler; const char* recv; const wchar_t* key;
    };
    // Все адреса/байты сняты capstone с gs_stock (= живой/Indun на этих местах), см. verify_p63.py.
    const Fam kFam[kFamCount] =
    {
    { 5048, 2072, 2073, 0x00511B76, { 0xE8, 0x45, 0x2B, 0x05, 0x00 }, 0x170, 0, 0x00511803, { 0x89, 0x8D, 0x90, 0xFE, 0xFF, 0xFF }, 6,
      0x00430814, { 0xE8, 0x77, 0x13, 0x0E, 0x00 }, 0x00511B90, 2, 0, "CharQuestItemBuy", "sub_511B90", L"Lock5048" },
    { 6162, 2469, 2470, 0x00516896, { 0xE8, 0x25, 0xDE, 0x04, 0x00 }, 0x1A0, 0, 0x00514FF3, { 0x89, 0x8D, 0x60, 0xFE, 0xFF, 0xFF }, 6,
      0x00433D21, { 0xE8, 0x8A, 0x2B, 0x0E, 0x00 }, 0x005168B0, 2, 0, "CharRoseWarStoreBuy", "sub_5168B0", L"Lock6162" },
    { 6096, 2272, 2273, 0x0055AE4F, { 0xE8, 0x6C, 0x98, 0x00, 0x00 }, 0x418, 0, 0x0055A835, { 0x89, 0x8D, 0xE8, 0xFB, 0xFF, 0xFF }, 6,
      0x00432E0E, { 0xE8, 0xAD, 0x83, 0x12, 0x00 }, 0x0055B1C0, 2, 0, "Recv_OpenPackageItem", "sub_55B1C0", L"Lock6096" },
    { 6098, 2270, 2270, 0x00554A17, { 0xE8, 0xA4, 0xFC, 0x00, 0x00 }, 0x3E4, 0, 0x00554343, { 0x89, 0x8D, 0x1C, 0xFC, 0xFF, 0xFF }, 6,
      0x00432DA6, { 0xE8, 0x55, 0x6B, 0x12, 0x00 }, 0x00559900, 1, 0, "EventItemRequestReq", "sub_559900", L"Lock6098" },
    { 6502, 2302, 2303, 0x004FE8E1, { 0xE8, 0xDA, 0x5D, 0x06, 0x00 }, 0x198, 0, 0x004FD9C5, { 0x89, 0x8D, 0x68, 0xFE, 0xFF, 0xFF }, 6,
      0x00432CB1, { 0xE8, 0x4A, 0xBC, 0x0C, 0x00 }, 0x004FE900, 2, 0, "Recv_User_Disassemble", "sub_4FE900", L"Lock6502" },
    { 6506, 2306, 2307, 0x00501A5C, { 0xE8, 0x5F, 0x2C, 0x06, 0x00 }, 0x4BC, 0, 0x00500F25, { 0x89, 0x8D, 0x44, 0xFB, 0xFF, 0xFF }, 6,
      0x00432D19, { 0xE8, 0x62, 0xED, 0x0C, 0x00 }, 0x00501A80, 2, 0, "Recv_User_ShellItemUpgradeReset", "recvDBShellItemUpgradeReset", L"Lock6506" },
    { 6549, 2527, 2528, 0x00535202, { 0xE8, 0xB9, 0xF4, 0x02, 0x00 }, 0x618, 2, 0x00534655, { 0x89, 0x8D, 0xE8, 0xF9, 0xFF, 0xFF }, 6,
      0x00433AA0, { 0xE8, 0xBB, 0x17, 0x10, 0x00 }, 0x00535260, 2, 2, "Recv_UserUpgradeExtraction", "recvDBUpgradeExtraction", L"Lock6549" },
    { 6551, 2529, 2530, 0x00535F91, { 0xE8, 0x2A, 0xE7, 0x02, 0x00 }, 0x1BC, 2, 0x005358D5, { 0x89, 0x8D, 0x44, 0xFE, 0xFF, 0xFF }, 6,
      0x00433AD4, { 0xE8, 0xD7, 0x24, 0x10, 0x00 }, 0x00535FB0, 2, 2, "Recv_UserUpgradeBless", "recvDBUpgradeBless", L"Lock6551" },
    { 6553, 2531, 2532, 0x005369E5, { 0xE8, 0xD6, 0xDC, 0x02, 0x00 }, 0x144, 2, 0x00536473, { 0x89, 0x8D, 0xBC, 0xFE, 0xFF, 0xFF }, 6,
      0x00433B08, { 0xE8, 0xF3, 0x2E, 0x10, 0x00 }, 0x00536A00, 2, 2, "Recv_UserItemOptionTrans", "recvDBItemOptionTrans", L"Lock6553" },
    { 5433, 2165, 2165, 0x00514C49, { 0xE8, 0x72, 0xFA, 0x04, 0x00 }, 0x260, 0, 0x00513F93, { 0x89, 0x8D, 0xA0, 0xFD, 0xFF, 0xFF }, 6,
      0x00430BF9, { 0xE8, 0x62, 0x40, 0x0E, 0x00 }, 0x00514C60, 2, 0, "Recv_ShellItemOption_Extraction", "recvDBShellItemOptionExtraction", L"Lock5433" },
    { 5468, 2229, 2229, 0x004F55FC, { 0xE8, 0xBF, 0xF0, 0x06, 0x00 }, 0x194, 0, 0x004F48D3, { 0x89, 0x8D, 0x6C, 0xFE, 0xFF, 0xFF }, 6,
      0x0043122C, { 0xE8, 0x4F, 0x44, 0x0C, 0x00 }, 0x004F5680, 2, 0, "Recv_GachaItemUse", "sendGachaItemUse", L"Lock5468" },
    { 6555, 2533, 2534, 0x005376F3, { 0xE8, 0xC8, 0xCF, 0x02, 0x00 }, 0x298, 2, 0x00536EF5, { 0x89, 0x8D, 0x68, 0xFD, 0xFF, 0xFF }, 6,
      0x00433B3C, { 0xE8, 0x0F, 0x3C, 0x10, 0x00 }, 0x00537750, 2, 2, "Recv_UserPrimiumSum", "recvDBPrimiumSum", L"Lock6555" },
    { 6586, 2568, 2569, 0x00539398, { 0xE8, 0x23, 0xB3, 0x02, 0x00 }, 0x2C, 2, 0x00539216, { 0x89, 0x4D, 0xD4, 0x00, 0x00, 0x00 }, 3,
      0x004342AE, { 0xE8, 0xFD, 0x50, 0x10, 0x00 }, 0x005393B0, 2, 2, "Recv_UserStarPointUpdate", "recvDBStarPointUpdate", L"Lock6586" },
    { 6140, 2452, 2453, 0x0055DC98, { 0xE8, 0x23, 0x6A, 0x00, 0x00 }, 0xEC, 0, 0x0055D923, { 0x89, 0x8D, 0x14, 0xFF, 0xFF, 0xFF }, 6,
      0x0043332A, { 0xE8, 0x21, 0xAA, 0x12, 0x00 }, 0x0055DD50, 2, 2, "RecvClient_CharNameChange", "sub_55DD50", L"Lock6140" },
    { 6102, 2275, 2276, 0x00455828, { 0xE8, 0x93, 0xEE, 0x10, 0x00 }, 0xF8, 1, 0x00454F83, { 0x89, 0x8D, 0x08, 0xFF, 0xFF, 0xFF }, 6,
      0x00432E42, { 0xE8, 0x19, 0x2A, 0x02, 0x00 }, 0x00455860, 2, 1, "Recv_IncubatorReq", "recvDBIncubatorReq", L"Lock6102" },
    { 6108, 2278, 2279, 0x00457DF3, { 0xE8, 0xC8, 0xC8, 0x10, 0x00 }, 0x130, 1, 0x004576F5, { 0x89, 0x8D, 0xD0, 0xFE, 0xFF, 0xFF }, 6,
      0x00432EB2, { 0xE8, 0x59, 0x4F, 0x02, 0x00 }, 0x00457E10, 2, 1, "Recv_PetConditionUp", "sub_457E10", L"Lock6108" },
    { 6110, 2280, 2281, 0x0045873C, { 0xE8, 0x7F, 0xBF, 0x10, 0x00 }, 0x40, 1, 0x00458566, { 0x89, 0x4D, 0xC0, 0x00, 0x00, 0x00 }, 3,
      0x00432EE6, { 0xE8, 0xC5, 0x58, 0x02, 0x00 }, 0x004587B0, 2, 1, "Recv_PetLiberate_Req", "recvPetLiberateReq", L"Lock6110" },
    { 6112, 2282, 2283, 0x004590C7, { 0xE8, 0xF4, 0xB5, 0x10, 0x00 }, 0xF0, 1, 0x00458A73, { 0x89, 0x8D, 0x10, 0xFF, 0xFF, 0xFF }, 6,
      0x00432F1A, { 0xE8, 0xC1, 0x61, 0x02, 0x00 }, 0x004590E0, 2, 1, "Recv_PetUnion_Req", "sub_4590E0", L"Lock6112" },
    { 6118, 2292, 2293, 0x00459895, { 0xE8, 0x26, 0xAE, 0x10, 0x00 }, 0x70, 1, 0x00459640, { 0x89, 0x4D, 0x90, 0x00, 0x00, 0x00 }, 3,
      0x00432FB6, { 0xE8, 0x25, 0x69, 0x02, 0x00 }, 0x004598E0, 2, 1, "Recv_PetNameChange_Req", "sub_4598E0", L"Lock6118" },
    { 6121, 2294, 2294, 0x00459F92, { 0xE8, 0x29, 0xA7, 0x10, 0x00 }, 0x84, 1, 0x00459C33, { 0x89, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF }, 6,
      0x00432FEA, { 0xE8, 0xD1, 0x6F, 0x02, 0x00 }, 0x00459FC0, 2, 1, "Recv_PetPossessionCountUp_Req", "recvPetPossessionCountUpReq", L"Lock6121" },
    { 6148, 2464, 2465, 0x0045ADD6, { 0xE8, 0xE5, 0x98, 0x10, 0x00 }, 0x16C, 1, 0x0045A303, { 0x89, 0x8D, 0x94, 0xFE, 0xFF, 0xFF }, 6,
      0x00433392, { 0xE8, 0xC9, 0x7A, 0x02, 0x00 }, 0x0045AE60, 2, 1, "RecvClient_PetMaxLevelUp", "recvDBPetMaxLevelUp", L"Lock6148" },
    { 6171, 2577, 2578, 0x0041041B, { 0xE8, 0xA0, 0x42, 0x15, 0x00 }, 0x228, 1, 0x0040F7F5, { 0x89, 0x8D, 0xD8, 0xFD, 0xFF, 0xFF }, 6,
      0x00433F9F, { 0xE8, 0x1C, 0xC8, 0xFD, 0xFF }, 0x004107C0, 2, 1, "Recv_EndFishing", "sub_4107C0", L"Lock6171" },
    { 6182, 2587, 2588, 0x00413486, { 0xE8, 0x35, 0x12, 0x15, 0x00 }, 0xE8, 1, 0x00412D73, { 0x89, 0x8D, 0x18, 0xFF, 0xFF, 0xFF }, 6,
      0x004340E9, { 0xE8, 0xB2, 0xF3, 0xFD, 0xFF }, 0x004134A0, 2, 1, "Recv_FishingBookReward", "sub_4134A0", L"Lock6182" },
    { 6591, 2653, 2654, 0x0053A4B5, { 0xE8, 0x06, 0xA2, 0x02, 0x00 }, 0xA8, 2, 0x00539D2B, { 0x89, 0x8D, 0x58, 0xFF, 0xFF, 0xFF }, 6,
      0x00434354, { 0xE8, 0x97, 0x62, 0x10, 0x00 }, 0x0053A5F0, 2, 2, "RecvUser_LimitationQuestEnter", "recvDBLimitationEnter", L"Lock6591" },
    { 6593, 2657, 2658, 0x0053BFA3, { 0xE8, 0x18, 0x87, 0x02, 0x00 }, 0x724, 2, 0x0053AC55, { 0x89, 0x8D, 0xDC, 0xF8, 0xFF, 0xFF }, 6,
      0x004343BC, { 0xE8, 0xBF, 0x7D, 0x10, 0x00 }, 0x0053C180, 2, 2, "RecvUser_LimitationQuestResult", "recvDBLimitationResult", L"Lock6593" },
    };

    // Ранний отказ (C): площадки `call sub_52BFF0` там, где они не заняты P33 (6502/6506 — заняты Д-1).
    struct BusySite { WORD clientOp; DWORD va; BYTE bytes[5]; const char* where; };
    const BusySite kBusy[] =
    {
        { 5048, 0x005118FC, { 0xE8, 0xEF, 0xA6, 0x01, 0x00 }, "CharQuestItemBuy: busy -> LABEL_4 (5049 code 0)" },
        { 6162, 0x00515111, { 0xE8, 0xDA, 0x6E, 0x01, 0x00 }, "CharRoseWarStoreBuy: busy -> stock tail (silent)" },
    };
    // Выход (D): `call sub_569DF0` внутри CUserManager::ClearUserMemory@0x527350 ([ebp+8] = слот, i16).
    constexpr DWORD kClearVa = 0x00527374;
    const BYTE kClearBytes[5]   = { 0xE8, 0x77, 0x2A, 0x04, 0x00 };
    const BYTE kClearProlog[7]  = { 0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC };   // 0x527350
    const BYTE kClearAfter[3]   = { 0x83, 0xC4, 0x18 };                           // 0x527379 add esp,18h
    const BYTE kPreambleProlog[3] = { 0x55, 0x8B, 0xEC };                         // 0x52BFF0
    const BYTE kConnectSendProlog[3] = { 0x55, 0x8B, 0xEC };                      // 0x5646C0

    // ── замки и ограничитель ────────────────────────────────────────────────
    struct Lock { int userIndex; DWORD tick; };     // tick == 0 — свободно
    Lock g_lock[kMaxUser][kFamCount] = {};
    struct Sess { int userIndex; DWORD lastJournal[kKinds]; int suppressed[kKinds]; };
    Sess g_sess[kMaxUser] = {};
    CRITICAL_SECTION g_cs; bool g_csReady = false;

    P63_Stats g_st = {};

    bool SlotOk(int n) { return n >= 0 && n < kMaxUser; }

    int FamByReq(int dbOp)   { for (int i = 0; i < kFamCount; ++i) { if (kFam[i].dbReq == dbOp) { return i; } } return -1; }
    int FamByClient(int op)  { for (int i = 0; i < kFamCount; ++i) { if (kFam[i].clientOp == op) { return i; } } return -1; }

    BYTE* ResolveMgr(void* self, BYTE kind)
    {
        __try
        {
            BYTE* p = (BYTE*)self;
            if (!p) { return nullptr; }
            if (kind == 1) { p = *(BYTE**)(*(BYTE**)p + kOffBlockMgr); }
            else if (kind == 2) { p = *(BYTE**)(*(BYTE**)(p + 4) + kOffBlockMgr); }
            return p;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    // CUser слота через менеджер; самопроверка CUser+0x0C == слот (иначе менеджер не тот — пользователь «неизвестен»).
    BYTE* UserOf(BYTE* mgr, int userNum)
    {
        if (!mgr || !SlotOk(userNum)) { return nullptr; }
        __try
        {
            BYTE* u = pGetUser(mgr, nullptr, (short)userNum);
            if (u && *(const short*)(u + kOffUserNumW) != (short)userNum) { InterlockedIncrement(&g_st.badMgr); return nullptr; }
            return u;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_st.badMgr); return nullptr; }
    }
    int UserIndexOf(const BYTE* u)
    {
        if (!u) { return 0; }
        __try { return *(const int*)(u + kOffUserIndex); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // Сессия слота для ограничителя: другая учётка — счётчики заново.
    Sess& SessOf(int userNum, int userIndex)
    {
        Sess& s = g_sess[userNum];
        if (s.userIndex != userIndex) { memset(&s, 0, sizeof(s)); s.userIndex = userIndex; }
        return s;
    }
    bool Allow(Sess& s, int kindIdx, DWORD now)
    {
        if (g_journalSec <= 0) { return true; }
        if (s.lastJournal[kindIdx] && now - s.lastJournal[kindIdx] < (DWORD)g_journalSec * 1000)
        {
            ++s.suppressed[kindIdx]; InterlockedIncrement(&g_st.journalSuppressed); return false;
        }
        s.lastJournal[kindIdx] = now;
        return true;
    }

    void Journal(BYTE kind, const BYTE* user, int userNum, int fam, int dbOp, int ms, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = kFam[fam].clientOp;
        e.userNum = (short)userNum;
        e.ip = P47_PeerIpv4(userNum);
        e.suppressed = suppressed;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIndex);
                e.charSlot  = user[kOffSlot];
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = dbOp; e.v[1] = ms; e.v[2] = g_mode;
        AcJournal::CopyText(e, kFam[fam].handler);
        AcJournal::Push(e);
        InterlockedIncrement(&g_st.journaled);
    }
    const char* NameOf(const BYTE* u) { return u ? (const char*)(u + kOffName) : "?"; }

    // Снятие замка после ответа БД (общее для обоих обёрток).
    void Release(int fam, int userNum, const BYTE* user, int userIndex)
    {
        if (!SlotOk(userNum)) { return; }
        const DWORD now = GetTickCount();
        int outcome = 0; DWORD age = 0; int lockUi = 0;
        if (g_csReady) { EnterCriticalSection(&g_cs); }
        Lock& L = g_lock[userNum][fam];
        if (L.tick)
        {
            age = now - L.tick; lockUi = L.userIndex;
            if (!user || L.userIndex == userIndex)
            {
                outcome = age >= g_timeoutMs ? 2 : 1;      // 1 снят вовремя, 2 снят, но ответ опоздал
                L.tick = 0; L.userIndex = 0;
            }
            else { outcome = 3; }                            // чужая учётка — не трогаем
        }
        if (g_csReady) { LeaveCriticalSection(&g_cs); }
        if (outcome == 1 || outcome == 2) { InterlockedIncrement(&g_st.released); }
        if (outcome == 2)
        {
            InterlockedIncrement(&g_st.lateReply);
            Sess& s = SessOf(userNum, userIndex);
            if (Allow(s, 3, now))
            {
                pSrvLog(g_logChannel, "P63 InFlightLock: DB reply %d for %s (slot %d, UserIndex %d) arrived after %u ms > LockTimeoutMs %u - lock had expired",
                        (int)kFam[fam].dbReply, kFam[fam].handler, userNum, userIndex, age, g_timeoutMs);
                Journal(kLateReply, user, userNum, fam, kFam[fam].dbReply, (int)age, s.suppressed[3]); s.suppressed[3] = 0;
            }
        }
        else if (outcome == 3)
        {
            InterlockedIncrement(&g_st.staleReply);
            Sess& s = SessOf(userNum, userIndex);
            if (Allow(s, 4, now))
            {
                pSrvLog(g_logChannel, "P63 InFlightLock: DB reply %d for slot %d belongs to UserIndex %d, slot now has UserIndex %d - lock kept",
                        (int)kFam[fam].dbReply, userNum, lockUi, userIndex);
                Journal(kStaleReply, user, userNum, fam, kFam[fam].dbReply, (int)age, s.suppressed[4]); s.suppressed[4] = 0;
            }
        }
    }
}

// ═══════════════════════════ C-обработчики стабов ═══════════════════════════
extern "C"
{
// A. Точка отправки в БД. 1 — отправлять, 0 — подавить (Mode=1, дубль в полёте).
int __stdcall P63_OnSend(int dbOp, int userNumRaw, BYTE* ebp)
{
    if (!g_enabled) { return 1; }
    const int fam = FamByReq(dbOp & 0xFFFF);
    const int userNum = (short)userNumRaw;
    if (fam < 0 || !g_famOn[fam] || !SlotOk(userNum)) { return 1; }
    int verdict = 1;
    __try
    {
        void* self = *(void**)(ebp - kFam[fam].thisDisp);
        BYTE* mgr  = ResolveMgr(self, kFam[fam].thisKind);
        BYTE* user = UserOf(mgr, userNum);
        const int ui = UserIndexOf(user);
        const DWORD now = GetTickCount();
        bool dup = false; DWORD age = 0;
        if (g_csReady) { EnterCriticalSection(&g_cs); }
        Lock& L = g_lock[userNum][fam];
        if (L.tick && L.userIndex == ui && (now - L.tick) < g_timeoutMs) { dup = true; age = now - L.tick; }
        else
        {
            if (L.tick) { InterlockedIncrement(&g_st.expired); }   // просроченный/чужой — перезапись
            L.userIndex = ui; L.tick = now ? now : 1;      // 0 = «свободно»; НЕ `now|1`: при чётном now разность now-tick заворачивается (замок казался просроченным — грабли P33 N-2)
            InterlockedIncrement(&g_st.locksSet);
        }
        if (g_csReady) { LeaveCriticalSection(&g_cs); }
        if (dup)
        {
            Sess& s = SessOf(userNum, ui);
            if (g_mode == 1)
            {
                verdict = 0;
                InterlockedIncrement(&g_st.dupSuppressed);
                if (Allow(s, 2, now))
                {
                    pSrvLog(g_logChannel, "P63 InFlightLock: %s (%d) from slot %d UserIndex %d %s - DB request %d SUPPRESSED, previous one in flight for %u ms (Mode=1)",
                            kFam[fam].handler, (int)kFam[fam].clientOp, userNum, ui, NameOf(user), dbOp, age);
                    Journal(kDupSuppressed, user, userNum, fam, dbOp, (int)age, s.suppressed[2]); s.suppressed[2] = 0;
                }
            }
            else
            {
                InterlockedIncrement(&g_st.dupJournal);
                if (Allow(s, 0, now))
                {
                    pSrvLog(g_logChannel, "P63 InFlightLock: %s (%d) from slot %d UserIndex %d %s - duplicate while DB request %d in flight for %u ms -> JOURNAL ONLY (Mode=0)",
                            kFam[fam].handler, (int)kFam[fam].clientOp, userNum, ui, NameOf(user), dbOp, age);
                    Journal(kDupJournal, user, userNum, fam, dbOp, (int)age, s.suppressed[0]); s.suppressed[0] = 0;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 1; }
    return verdict;
}

// C. Ранний отказ: сток sub_52BFF0 вернул 0; 1 — «занят» (замок семьи жив, Mode=1), 0 — дальше по стоку.
int __stdcall P63_EarlyGate(void* mgr, int userNumRaw, int clientOp)
{
    if (!g_enabled || g_mode != 1 || !g_earlyRefuse) { return 0; }
    const int fam = FamByClient(clientOp & 0xFFFF);
    const int userNum = (short)userNumRaw;
    if (fam < 0 || !g_famOn[fam] || !SlotOk(userNum)) { return 0; }
    int r = 0;
    __try
    {
        BYTE* user = UserOf((BYTE*)mgr, userNum);
        const int ui = UserIndexOf(user);
        const DWORD now = GetTickCount();
        bool busy = false; DWORD age = 0;
        if (g_csReady) { EnterCriticalSection(&g_cs); }
        const Lock& L = g_lock[userNum][fam];
        if (L.tick && L.userIndex == ui && (now - L.tick) < g_timeoutMs) { busy = true; age = now - L.tick; }
        if (g_csReady) { LeaveCriticalSection(&g_cs); }
        if (busy)
        {
            r = 1;
            InterlockedIncrement(&g_st.dupEarly);
            Sess& s = SessOf(userNum, ui);
            if (Allow(s, 1, now))
            {
                pSrvLog(g_logChannel, "P63 InFlightLock: %s (%d) from slot %d UserIndex %d %s - previous DB request %d in flight for %u ms -> stock BUSY branch (Mode=1)",
                        kFam[fam].handler, clientOp, userNum, ui, NameOf(user), (int)kFam[fam].dbReq, age);
                Journal(kDupEarly, user, userNum, fam, kFam[fam].dbReq, (int)age, s.suppressed[1]); s.suppressed[1] = 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = 0; }
    return r;
}

// B. Приём ответа БД (this, UserNum, s): сток, затем снятие.
int __stdcall P63_ReplyWrap2(int fam, void* self, int userNumRaw, int pkt)
{
    const int userNum = (short)userNumRaw;
    BYTE* user = nullptr; int ui = 0;
    if (g_enabled && fam >= 0 && fam < kFamCount)
    {
        user = UserOf(ResolveMgr(self, kFam[fam].replyKind), userNum);
        ui = UserIndexOf(user);
    }
    const int r = ((PFN_Recv2)kFam[fam].replyTarget)(self, nullptr, userNum, pkt);
    if (g_enabled && fam >= 0 && fam < kFamCount) { Release(fam, userNum, user, ui); }
    return r;
}
// B'. Приём ответа БД (this, s) — 2270: слот в теле (+0), как у стока sub_559900.
int __stdcall P63_ReplyWrap1(int fam, void* self, int pkt)
{
    int userNum = -1; BYTE* user = nullptr; int ui = 0;
    if (g_enabled && fam >= 0 && fam < kFamCount)
    {
        __try { userNum = *(const short*)(pkt + 9); } __except (EXCEPTION_EXECUTE_HANDLER) { userNum = -1; }
        user = UserOf(ResolveMgr(self, kFam[fam].replyKind), userNum);
        ui = UserIndexOf(user);
    }
    const int r = ((PFN_Recv1)kFam[fam].replyTarget)(self, nullptr, pkt);
    if (g_enabled && fam >= 0 && fam < kFamCount && SlotOk(userNum)) { Release(fam, userNum, user, ui); }
    return r;
}

// D. Выход сессии (ClearUserMemory): сбросить все замки слота.
void __stdcall P63_OnUserClear(int userNumRaw)
{
    P75_OnUserClear(userNumRaw);   // ★ P75 (19.10.2026): общая точка — замок «зелье 558 в пути» слота снимается на выходе (без P75 — пусто)
    const int userNum = (short)userNumRaw;
    if (!g_enabled || !SlotOk(userNum)) { return; }
    int n = 0;
    if (g_csReady) { EnterCriticalSection(&g_cs); }
    for (int i = 0; i < kFamCount; ++i) { if (g_lock[userNum][i].tick) { ++n; g_lock[userNum][i].tick = 0; g_lock[userNum][i].userIndex = 0; } }
    memset(&g_sess[userNum], 0, sizeof(Sess));
    if (g_csReady) { LeaveCriticalSection(&g_cs); }
    if (n) { InterlockedExchangeAdd(&g_st.cleared, n); }
}

__declspec(dllexport) void __stdcall P63_GetStats(P63_Stats* s) { if (s) { *s = g_st; } }
}   // extern "C"

// ═══════════════════════════ стабы ══════════════════════════════════════════
namespace
{
    DWORD g_pConnectSend = Srv::kConnectSend;   // 0x5646C0
    DWORD g_pPreamble    = 0x0052BFF0;          // сток «занят»
    DWORD g_pSrvLog      = Srv::kLog;           // 0x569DF0

    // A. вместо `call sub_5646C0` (thiscall: ecx = CUserMoveManager; [esp+4] op, +8 len, +12 conn, +16 body, +20 userIdx;
    //    ebp = кадр обработчика). Пропуск — хвостовой переход в сток со всем стеком как был; подавление — ret 14h, eax=0.
    __declspec(naked) void St_Send()
    {
        __asm
        {
            pushad
            push  ebp
            push  dword ptr [esp+56]           // userIdx  ([esp+20] до pushad/push ebp)
            push  dword ptr [esp+44]           // op       ([esp+4])
            call  P63_OnSend                   // __stdcall(op, userIdx, ebp) — снимает 12 б
            mov   dword ptr [esp+28], eax      // в сохранённый eax
            popad
            test  eax, eax
            jz    suppress
            jmp   dword ptr [g_pConnectSend]
        suppress:
            xor   eax, eax
            ret   0x14
        }
    }

    // C. вместо `call sub_52BFF0` (thiscall: ecx = CUserManager; [esp+4] userNum, [esp+8] opcode; ret 8).
    __declspec(naked) void St_Busy()
    {
        __asm
        {
            push  ecx                          // сохранить mgr
            push  dword ptr [esp+12]           // opcode
            push  dword ptr [esp+12]           // userNum
            mov   ecx, dword ptr [esp+8]       // this = mgr
            call  dword ptr [g_pPreamble]      // сток (снимает 8)
            pop   ecx
            test  al, al
            jnz   done                         // сток уже отказал — его результат
            pushad
            push  dword ptr [esp+40]           // opcode
            push  dword ptr [esp+40]           // userNum
            push  ecx                          // mgr
            call  P63_EarlyGate                // __stdcall(mgr, userNum, opcode) → 0/1
            mov   dword ptr [esp+28], eax
            popad
        done:
            ret   8
        }
    }

    // B. общий хвост: [esp] = номер семьи, [esp+4] = адрес возврата, [esp+8] = UserNum, [esp+12] = s; ecx = this.
    __declspec(naked) void ReplyCommon2()
    {
        __asm
        {
            pop   eax                          // семья
            push  dword ptr [esp+8]            // s
            push  dword ptr [esp+8]            // UserNum
            push  ecx                          // this
            push  eax                          // семья
            call  P63_ReplyWrap2               // __stdcall(fam, this, UserNum, s) — снимает 16
            ret   8
        }
    }
    // B'. 2270: [esp] = семья, [esp+4] = возврат, [esp+8] = s; ecx = this.
    __declspec(naked) void ReplyCommon1()
    {
        __asm
        {
            pop   eax
            push  dword ptr [esp+4]            // s
            push  ecx
            push  eax
            call  P63_ReplyWrap1               // __stdcall(fam, this, s) — снимает 12
            ret   4
        }
    }
#define P63_REPLY_STUB(n, tail) __declspec(naked) void St_Reply_##n() { __asm { push n } __asm { jmp tail } }
    P63_REPLY_STUB(0,  ReplyCommon2) P63_REPLY_STUB(1,  ReplyCommon2) P63_REPLY_STUB(2,  ReplyCommon2) P63_REPLY_STUB(3,  ReplyCommon1)
    P63_REPLY_STUB(4,  ReplyCommon2) P63_REPLY_STUB(5,  ReplyCommon2) P63_REPLY_STUB(6,  ReplyCommon2) P63_REPLY_STUB(7,  ReplyCommon2)
    P63_REPLY_STUB(8,  ReplyCommon2) P63_REPLY_STUB(9,  ReplyCommon2) P63_REPLY_STUB(10, ReplyCommon2) P63_REPLY_STUB(11, ReplyCommon2)
    P63_REPLY_STUB(12, ReplyCommon2) P63_REPLY_STUB(13, ReplyCommon2) P63_REPLY_STUB(14, ReplyCommon2) P63_REPLY_STUB(15, ReplyCommon2)
    P63_REPLY_STUB(16, ReplyCommon2) P63_REPLY_STUB(17, ReplyCommon2) P63_REPLY_STUB(18, ReplyCommon2) P63_REPLY_STUB(19, ReplyCommon2)
    P63_REPLY_STUB(20, ReplyCommon2) P63_REPLY_STUB(21, ReplyCommon2) P63_REPLY_STUB(22, ReplyCommon2) P63_REPLY_STUB(23, ReplyCommon2)
    P63_REPLY_STUB(24, ReplyCommon2)
#undef P63_REPLY_STUB
    void (*const kReplyStub[kFamCount])() =
    {
        St_Reply_0,  St_Reply_1,  St_Reply_2,  St_Reply_3,  St_Reply_4,  St_Reply_5,  St_Reply_6,  St_Reply_7,  St_Reply_8,
        St_Reply_9,  St_Reply_10, St_Reply_11, St_Reply_12, St_Reply_13, St_Reply_14, St_Reply_15, St_Reply_16, St_Reply_17,
        St_Reply_18, St_Reply_19, St_Reply_20, St_Reply_21, St_Reply_22, St_Reply_23, St_Reply_24,
    };

    // D. вместо `call sub_569DF0` в ClearUserMemory (cdecl, стек не трогаем; [ebp+8] = слот i16 кадра ClearUserMemory).
    __declspec(naked) void St_Clear()
    {
        __asm
        {
            pushad
            movsx eax, word ptr [ebp+8]
            push  eax
            call  P63_OnUserClear              // __stdcall(userNum)
            popad
            jmp   dword ptr [g_pSrvLog]
        }
    }
}

namespace
{
    bool g_sendOwn[kFamCount]   = {};   // площадку отправки семьи записал сам P63 (rel32 → St_Send)
    bool g_sendChain[kFamCount] = {};   // площадка стоит под P62 — St_Send подставлен в его слот «следующий вызов»
}

// ── общая точка P63 → P75 (Patches.h): ClearUserMemory 0x527374 стоит под P63 — P75 свою площадку не пишет ──
bool P63_ClearHooked() { return g_clearHooked; }

// ── общая точка P62 ↔ P63 (Patches.h) ──
const void* P63_SendStubAt(DWORD va)
{
    for (int i = 0; i < kFamCount; ++i) { if (kFam[i].sendVa == va) { return g_sendOwn[i] ? (const void*)&St_Send : nullptr; } }
    return nullptr;
}
const BYTE* P63_SendOrigAt(DWORD va)
{
    for (int i = 0; i < kFamCount; ++i) { if (kFam[i].sendVa == va) { return kFam[i].sendBytes; } }
    return nullptr;
}

PatchResult P63_InFlightLock()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode         = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    int t          = Config::GetInt(kSec, L"LockTimeoutMs", 15000);
    if (t < 1000) { t = 1000; } if (t > 120000) { t = 120000; }
    g_timeoutMs    = (DWORD)t;
    g_journalSec   = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    g_earlyRefuse  = Config::GetBool(kSec, L"EarlyRefuse", true);
    g_sessionClear = Config::GetBool(kSec, L"SessionClear", true);
    g_logChannel   = Config::GetInt(kSec, L"LogChannel", 1);
    int nOn = 0;
    for (int i = 0; i < kFamCount; ++i) { g_famOn[i] = Config::GetBool(kSec, kFam[i].key, true); nOn += g_famOn[i] ? 1 : 0; }
    if (!g_csReady) { InitializeCriticalSection(&g_cs); g_csReady = true; }
    memset(g_lock, 0, sizeof(g_lock));
    memset(g_sess, 0, sizeof(g_sess));
    memset(&g_st, 0, sizeof(g_st));
    if (nOn == 0) { Log::Line(L"    P63: все семьи выключены ключами Lock<op> — ставить нечего"); return PatchResult::Disabled; }

    // Площадки и соседи — только для включённых семей (+ общие).
    Site sites[kFamCount * 4 + 8]; int n = 0;
    for (int i = 0; i < kFamCount; ++i)
    {
        if (!g_famOn[i]) { continue; }
        // ★ integ2: площадка уже под P62 (rel32 → стаб P62 ЭТОЙ площадки) — байты не пишем, исходные сверяем по таблице
        //   P62 (он их сверил при установке); St_Send встаёт в слот «следующий вызов» P62. Порядок: P62 → P63 → сток.
        g_sendOwn[i] = false; g_sendChain[i] = false;
        {
            const void* p62 = P62_SendStubAt(kFam[i].sendVa);
            const BYTE* p62orig = P62_SendOrigAt(kFam[i].sendVa);
            DWORD tgt = 0;
            __try { const BYTE* q = (const BYTE*)kFam[i].sendVa; if (q[0] == 0xE8) { tgt = kFam[i].sendVa + 5 + *(const DWORD*)(q + 1); } }
            __except (EXCEPTION_EXECUTE_HANDLER) { tgt = 0; }
            if (p62 && p62orig && tgt == (DWORD)p62)
            {
                if (memcmp(p62orig, kFam[i].sendBytes, 5) != 0)
                {
                    Log::Line(L"    MISMATCH P63 @0x%08X: площадка под P62, но исходные байты таблиц P62 и P63 разные", kFam[i].sendVa);
                    return PatchResult::Mismatch;
                }
                g_sendChain[i] = true;
            }
        }
        if (!g_sendChain[i]) { sites[n++] = { kFam[i].sendVa, kFam[i].sendBytes, 5 }; }
        sites[n++] = { kFam[i].prologVa,    kFam[i].prologBytes, kFam[i].prologLen };
        sites[n++] = { kFam[i].replyVa,     kFam[i].replyBytes,  5 };
        sites[n++] = { kFam[i].replyTarget, kPreambleProlog,     3 };     // пролог стокового приёма: push ebp; mov ebp,esp
    }
    bool busyOn[ARRAYSIZE(kBusy)] = {};
    if (g_earlyRefuse)
    {
        for (int b = 0; b < (int)ARRAYSIZE(kBusy); ++b)
        {
            const int f = FamByClient(kBusy[b].clientOp);
            busyOn[b] = f >= 0 && g_famOn[f];
            if (busyOn[b]) { sites[n++] = { kBusy[b].va, kBusy[b].bytes, 5 }; }
        }
        sites[n++] = { 0x0052BFF0, kPreambleProlog, 3 };
    }
    if (g_sessionClear)
    {
        sites[n++] = { kClearVa, kClearBytes, 5 };
        sites[n++] = { 0x00527350, kClearProlog, sizeof(kClearProlog) };
        sites[n++] = { 0x00527379, kClearAfter, sizeof(kClearAfter) };
    }
    sites[n++] = { Srv::kConnectSend, kConnectSendProlog, 3 };
    if (!VerifyAllSites(L"P63", sites, n)) { return PatchResult::Mismatch; }
    int nChain = 0;

    for (int i = 0; i < kFamCount; ++i)
    {
        if (!g_famOn[i]) { continue; }
        // Снятие ставим ДО постановки: замок, поставленный раньше, чем площадка ответа готова, не снялся бы.
        if (!Hook::WriteCall(kFam[i].replyVa, (const void*)kReplyStub[i],  5)) { return PatchResult::Failed; }
        if (g_sendChain[i])
        {
            if (!P62_ChainSend(kFam[i].sendVa, (const void*)&St_Send)) { return PatchResult::Failed; }
            ++nChain;
            Log::Line(L"    P63: %hs (%d) — цепочка через P62 @0x%08X: P62 → P63 → sub_5646C0", kFam[i].handler, (int)kFam[i].clientOp, kFam[i].sendVa);
        }
        else
        {
            if (!Hook::WriteCall(kFam[i].sendVa, (const void*)&St_Send, 5)) { return PatchResult::Failed; }
            g_sendOwn[i] = true;
        }
    }
    int nBusy = 0;
    if (g_earlyRefuse)
    {
        for (int b = 0; b < (int)ARRAYSIZE(kBusy); ++b)
        {
            if (!busyOn[b]) { continue; }
            if (!Hook::WriteCall(kBusy[b].va, (const void*)&St_Busy, 5)) { return PatchResult::Failed; }
            ++nBusy;
        }
    }
    if (g_sessionClear)
    {
        if (!Hook::WriteCall(kClearVa, (const void*)&St_Clear, 5)) { return PatchResult::Failed; }
        g_clearHooked = true;
    }
    Log::Line(L"    P63: режим %s; семей %d/%d (постановка у call sub_5646C0, из них через P62 %d; снятие в диспетчере ответов БД); "
              L"тайм-аут %u мс; ранний отказ «занят» у %d обработчиков (5048/6162); сброс при выходе %s; строки не чаще 1/%d с; лог канал %d",
              g_mode ? L"ОТКАЗ/ПОДАВЛЕНИЕ" : L"ЖУРНАЛ", nOn, kFamCount, nChain, g_timeoutMs, nBusy,
              g_sessionClear ? L"ДА" : L"нет", g_journalSec, g_logChannel);
    return PatchResult::Applied;
}
