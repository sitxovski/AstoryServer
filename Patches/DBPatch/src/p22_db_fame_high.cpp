// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P22 — DBManager: ХРАНЕНИЕ СТАРШЕЙ ПОЛОВИНЫ МАСКИ СЛАВЫ (звания id 256…511).
//        ★ НАША ПРАВКА. Ходит В НАШЕЙ DLL, а не прямым патчем образа.
//
//  Пара к P21 (GameServer). Отчёт: Reports/title_mask_512.md,
//  документ патча: AstoryServer/Docs/DBManager/db-fame-high-p22.md
//
//  ── ПОЧЕМУ ВСЁ-ТАКИ DLL, А НЕ ПРЯМОЙ ПАТЧ ───────────────────────────────────
//  В Registry.cpp с 24.08 стояло, что в процессы, работающие с базой, DLL не
//  доставить — «в хвосте .rdata нет места под новый блок дескрипторов импорта».
//  Это оказалось ЛОЖНЫМ «НЕТ» (закон false-negatives-method): смотрели ТОЛЬКО
//  хвост .rdata. Пересчёт по ЖИВОМУ образу (MD5 294C4E03…, 536 576 б):
//      нужно  238 б (10 дескрипторов 200 + "AsdaPatch.dll" 14 + hint/имя 16 + INT 8)
//               + 8 б IAT на ЗАПИСЫВАЕМОЙ странице
//      хвост .rdata RVA 0x7FF48…0x80000 =  184 б  ← этого и не хватало
//      хвост .text  RVA 0x657AB…0x66000 = 2133 б  ← ХВАТАЕТ (там же с 24.08 живёт P17)
//      хвост .data  RVA 0x814FD…0x82000 = 2819 б, секция C0000040 = R+W ← под IAT
//  Инъекция сделана `tools/inject_import_db.py`: меняются ровно 116 байт в трёх
//  местах (8 б DataDirectory[IMPORT], 238 б блока, 8 б IAT), `.text` кода не тронут.
//
//  ── ЧТО ДЕЛАЕТ ПАТЧ ─────────────────────────────────────────────────────────
//  Добавляет DBManager'у ДВА НОВЫХ DB-опкода (существующие обработчики не тронуты):
//      2330 (0x91A) GS→DB  «дай старшую половину»  → EXEC UPCharFameBankHi / …ProgressHi
//                                                     → ответ 2332 (0x91C), тело 72 б
//      2331 (0x91B) GS→DB  «сохрани старшую половину» → EXEC UPCharFameBankHiUp / …ProgressHiUp
//  заводит таблицу `dbo.CharFameHigh`. Существующие процедуры и таблицы НЕ меняются.
//
//  ── ГДЕ ВЕШАЕМСЯ ────────────────────────────────────────────────────────────
//  Диспетчер DB-пакетов — `sub_402420@0x402420`. Опкод берётся из ЗАГОЛОВКА пакета:
//      0x402543  movzx eax, word ptr [edx+7]   ⇒ опкод = word[+7], тело с +9
//  Ветвление — три диапазона с таблицами переходов (`0x405550`, `0x405758`,
//  `0x40594C`); ВСЕ ветки, и обработанные, и `default`, сходятся в эпилоге
//  `0x4054B4` (там меряется время обработки). Вешаемся ИМЕННО В ЭПИЛОГЕ: одна
//  площадка, ни одна существующая ветка не переписана, а свои опкоды мы узнаём
//  сами по заголовку. Для чужих опкодов трамплин делает ровно один `cmp` и уходит.
//
//  Локальные диспетчера (сверены с дизассемблером ЖИВОГО образа):
//      [ebp-0x0C] = указатель на пакет   (0x4024A3  lea eax,[ebp-0x1030]; mov [ebp-0xC],eax)
//      [ebp-0x08] = a1 = word[+5]        (0x4024D2…0x4024D9)
//      [ebp-0x04] = a2 = word[+3]        (0x4024DC…0x4024E3)
//      [ebp+0x08] = a3 — его обработчики передают в `sub_447720`
//  Обработчики получают ровно это: `push Src; push [ebp+8]; push [ebp-4]; push [ebp-8];
//  mov ecx,0x49EAB8; call <handler>` (0x404129…0x404141).
//
//  ── ФУНКЦИИ ОБРАЗА, КОТОРЫЕ ЗОВЁМ (снято с `sub_42F890@0x42F890`) ───────────
//      sub_407390@0x407390  __thiscall(this=0x49EAB8, i16 группаСерверов) -> connIdx
//      sub_447720@0x447720  __cdecl(ds=0x534E7F0, status, connIdx, a3, out, fmt, ...)
//                           стек чистит вызывающий (`add esp,0x40` на 16 аргументов)
//      sub_44E2F0@0x44E2F0  __thiscall(this=0x49EAF8, op, len, a1, body, a2), ret 0x14
//                           (a1/a2 — те же word[+5]/word[+3]: 0x407691/0x40769C)
//
//  ── МЯГКАЯ ДЕГРАДАЦИЯ, если процедур в базе ЕЩЁ НЕТ ─────────────────────────
//  Два рубежа:
//   1. штатный: `sub_447720` возвращает признак неудачи в status[0] — так же, как
//      у стоковых обработчиков (`if (!v39[0] || !v45) → лог`), мы просто выходим;
//   2. страховочный: сам вызов обёрнут в `__try/__except` (DLL собирается с `/EHa`),
//      поэтому даже исключение внутри не выпустит наружу и не уронит DBManager.
//  После первой неудачи взводится флаг и запросы больше не шлются до перезапуска —
//  чтобы не забивать журнал на каждом входе персонажа.
//  ⚠ ЧЕСТНО: проверить это ПРОГОНОМ нельзя — DBManager локально не запускается
//  (нет базы и остального окружения). Порог 1 доказан кодом стоковых обработчиков,
//  порог 2 — языковой конструкцией. Прогоном не подтверждён ни один.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* kSec = L"P22_DbFameHigh";

    bool g_enabled = true;
    bool g_load    = true;   // 2330 -> чтение + ответ 2332
    bool g_save    = true;   // 2331 -> запись

    // ★ ЗАКОН msvc-inline-asm-offsets: числа для ассемблера — только через #define.
    //   C++-константа в `__asm` даёт АДРЕС переменной, а не значение (этим уже
    //   роняли живой сервер).
    #define DBP_PKT   0x0C      // [ebp-0x0C] указатель на пакет
    #define DBP_A1    0x08      // [ebp-0x08] a1 = word[+5]
    #define DBP_A2    0x04      // [ebp-0x04] a2 = word[+3]
    #define DBP_A3    0x08      // [ebp+0x08] a3
    #define DBP_QPC   0x18      // [ebp-0x18] буфер счётчика времени (вытесненная команда)

    // ── адреса ЖИВОГО DBManager.exe ────────────────────────────────────────
    constexpr DWORD kOpLoadHi  = 0x91A;      // 2330 GS->DB «дай старшую половину»
    constexpr DWORD kOpSaveHi  = 0x91B;      // 2331 GS->DB «сохрани старшую половину»
    constexpr DWORD kOpReplyHi = 0x91C;      // 2332 DB->GS ответ
    constexpr int   kBodyLoad  = 8;          // тело 2330
    constexpr int   kBodySave  = 8 + 64;     // тело 2331
    constexpr int   kBodyReply = 8 + 64;     // тело 2332
    constexpr int   kSqlBuf    = 0x36B4;     // размер буфера результата (как у стока)

    typedef int  (__fastcall *PFN_GetConn)(void* self, void* edx, int groupIdx);
    typedef int  (__cdecl    *PFN_Sql)(void* ds, void* status, int conn, int a3,
                                       void* out, const char* fmt, ...);
    typedef int  (__fastcall *PFN_Send)(void* self, void* edx, int op, int len,
                                        int a1, void* body, int a2);

    PFN_GetConn const pGetConn = (PFN_GetConn) 0x00407390;
    PFN_Sql     const pSql     = (PFN_Sql)     0x00447720;
    PFN_Send    const pSend    = (PFN_Send)    0x0044E2F0;

    void* const kDispThis = (void*)0x0049EAB8;   // this обработчиков (ecx диспетчера)
    void* const kSendThis = (void*)0x0049EAF8;   // this отправителя ответов
    void* const kDataSrc  = (void*)0x00534E7F0;  // источник данных для sub_447720

    // Признак «процедур в базе нет» — после первой неудачи больше не тревожим базу.
    volatile LONG g_sqlBroken = 0;

    // Один вызов SQL под двумя рубежами защиты. true — получилось.
    bool RunSql(void* status, int conn, int a3, void* out, const char* fmt,
                int p1, int p2, const unsigned __int64* q /*может быть nullptr*/)
    {
        if (g_sqlBroken) { return false; }
        *(DWORD*)status = 0;
        __try
        {
            if (q)
            {
                pSql(kDataSrc, status, conn, a3, out, fmt, p1, p2, q[0], q[1], q[2], q[3]);
            }
            else
            {
                pSql(kDataSrc, status, conn, a3, out, fmt, p1, p2);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedExchange(&g_sqlBroken, 1);
            Log::Line(L"    P22: ! исключение при выполнении запроса — старшая половина "
                      L"маски званий отключена до перезапуска (миграция базы не выполнена?)");
            return false;
        }
        if (*(DWORD*)status == 0)
        {
            InterlockedExchange(&g_sqlBroken, 1);
            Log::Line(L"    P22: ! запрос не выполнился — процедур CharFameHigh в базе нет? "
                      L"Старшая половина маски званий отключена до перезапуска");
            return false;
        }
        return true;
    }

    // ── обработчик 2330: прочитать обе старшие половины и ответить 2332 ────
    void HandleLoadHi(BYTE* body, int a1, int a2, int a3)
    {
        const int   charId  = *(int*)(body + 2);
        const int   charIdx = (int)(signed char)body[6];
        const int   group   = (int)(signed char)body[7];

        BYTE  status[32] = {};
        BYTE* sqlOut = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
        if (!sqlOut) { return; }

        BYTE reply[kBodyReply] = {};
        *(short*)&reply[0] = *(short*)&body[0];
        *(int*)  &reply[2] = charId;
        reply[6] = (BYTE)charIdx;

        const int conn = pGetConn(kDispThis, nullptr, group);
        bool ok = RunSql(status, conn, a3, sqlOut,
                         "EXEC UPCharFameBankHi %d, %d", charId, charIdx, nullptr);
        if (ok) { memcpy(&reply[8], sqlOut, 32); }

        if (ok)
        {
            memset(sqlOut, 0, kSqlBuf);
            ok = RunSql(status, conn, a3, sqlOut,
                        "EXEC UPCharFameProgressHi %d, %d", charId, charIdx, nullptr);
            if (ok) { memcpy(&reply[40], sqlOut, 32); }
        }

        HeapFree(GetProcessHeap(), 0, sqlOut);
        if (!ok) { return; }                       // молча: GameServer оставит нули

        pSend(kSendThis, nullptr, (int)kOpReplyHi, kBodyReply, a1, reply, a2);
    }

    // ── обработчик 2331: сохранить обе старшие половины ────────────────────
    void HandleSaveHi(BYTE* body, int /*a1*/, int /*a2*/, int a3)
    {
        const int charId  = *(int*)(body + 2);
        const int charIdx = (int)(signed char)body[6];
        const int group   = (int)(signed char)body[7];

        BYTE  status[32] = {};
        BYTE* sqlOut = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
        if (!sqlOut) { return; }

        unsigned __int64 bank[4], prog[4];
        memcpy(bank, body + 8,  32);
        memcpy(prog, body + 40, 32);

        const int conn = pGetConn(kDispThis, nullptr, group);
        RunSql(status, conn, a3, sqlOut,
               "EXEC UPCharFameBankHiUp %d, %d, %I64d, %I64d, %I64d, %I64d",
               charId, charIdx, bank);
        memset(sqlOut, 0, kSqlBuf);
        RunSql(status, conn, a3, sqlOut,
               "EXEC UPCharFameProgressHiUp %d, %d, %I64d, %I64d, %I64d, %I64d",
               charId, charIdx, prog);
        HeapFree(GetProcessHeap(), 0, sqlOut);
    }

    // ── разбор: вызывается из трамплина, ebp — кадр диспетчера ─────────────
    void __cdecl DbFameDispatch(BYTE* hostEbp)
    {
        BYTE* pkt = *(BYTE**)(hostEbp - DBP_PKT);
        if (!pkt) { return; }
        const DWORD op = *(WORD*)(pkt + 7);
        if (op != kOpLoadHi && op != kOpSaveHi) { return; }

        const int a1 = *(int*)(hostEbp - DBP_A1);
        const int a2 = *(int*)(hostEbp - DBP_A2);
        const int a3 = *(int*)(hostEbp + DBP_A3);
        BYTE*     body = pkt + 9;

        if (op == kOpLoadHi && g_load) { HandleLoadHi(body, a1, a2, a3); }
        if (op == kOpSaveHi && g_save) { HandleSaveHi(body, a1, a2, a3); }
    }

    // ── трамплин на эпилоге диспетчера 0x4054B4 (10 байт) ──────────────────
    //   Вытеснено: lea eax,[ebp-0x18]; push eax; call dword ptr [0x466040]
    //   (замер времени; результат в eax дальше не используется — 0x4054BE
    //   читает [ebp-0x18]). Возврат на 0x4054BE.
    DWORD g_dbBack    = 0x004054BE;   // куда вернуться
    DWORD g_dbQpcSlot = 0x00466040;   // слот импорта счётчика времени

    __declspec(naked) void TrampDbDispatch()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp                      // кадр диспетчера
            call  DbFameDispatch
            add   esp, 4
            popad
            popfd
            lea   eax, [ebp-DBP_QPC]       // ── вытесненные команды ──
            push  eax
            mov   eax, [g_dbQpcSlot]
            call  dword ptr [eax]
            jmp   [g_dbBack]
        }
    }

    // ── площадка (байты сняты с ЖИВОГО образа) ─────────────────────────────
    const DWORD kSiteDisp = 0x004054B4;
    const BYTE  kOrigDisp[16] =
    {
        0x8D, 0x45, 0xE8,                   // lea  eax, [ebp-0x18]
        0x50,                               // push eax
        0xFF, 0x15, 0x40, 0x60, 0x46, 0x00, // call dword ptr [0x466040]
        0x8B, 0x4D, 0xE8,                   // mov  ecx, [ebp-0x18]   (уже за площадкой)
        0x2B, 0x4D, 0xD8                    // sub  ecx, [ebp-0x28]
    };
}

PatchResult P22_DbFameHigh()
{
    g_enabled = Config::GetBool(kSec, L"Enabled", true);
    if (!g_enabled) { return PatchResult::Disabled; }
    g_load = Config::GetBool(kSec, L"LoadHigh", true);
    g_save = Config::GetBool(kSec, L"SaveHigh", true);

    const Site sites[] = { { kSiteDisp, kOrigDisp, sizeof(kOrigDisp) } };
    if (!VerifyAllSites(L"P22", sites, ARRAYSIZE(sites)))
    {
        return PatchResult::Mismatch;
    }

    if (!Hook::WriteJmp(kSiteDisp, (const void*)&TrampDbDispatch, 10))
    {
        return PatchResult::Failed;
    }
    Log::Line(L"    P22: DBManager принимает опкоды 2330 (дай старшую половину) и "
              L"2331 (сохрани), отвечает 2332 (@%08X)", kSiteDisp);
    Log::Line(L"    P22: ! нужны процедуры UPCharFameBankHi/HiUp и UPCharFameProgressHi/HiUp "
              L"(SQL/title_mask_512_01_migrate.sql); без них — одна запись в журнал и отключение");
    return PatchResult::Applied;
}
