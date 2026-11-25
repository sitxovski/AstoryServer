// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P21 — МАСКА СЛАВЫ (ЗВАНИЯ / Fame) РАСШИРЕНА С 256 ДО 512 БИТ.
//        ★ НАША ПРАВКА, не перенос чужой.
//
//  Отчёты-источники: Reports/title_mask_512.md (эта работа),
//                    Reports/title_system.md   (система званий целиком, дефект D3).
//
//  ── ЗАЧЕМ ───────────────────────────────────────────────────────────────────
//  Сервер держит «получено» и «найдено» РОВНО ПО 256 БИТ на игрока, поэтому звания
//  с id ≥ 256 недостижимы: бита для них не существует. В клиентской таблице
//  `title_list` таких званий 24 (id 256…279), свободных номеров ниже 256 нет.
//
//  ── ГДЕ ЖИВУТ 256 БИТ (адреса сверены с ЖИВЫМ образом, см. «ДИФ» ниже) ───────
//    CUser+0x17DD0 (97744) i32   — очки славы
//    CUser+0x17DD8 (97752) i32   — троттл смены звания (60 с)
//    CUser+0x17DDC (97756) 32 б  — маска «ПОЛУЧЕНО», 4 qword
//    CUser+0x17DFC (97788) ptr   — массив записей по 44 б (по одной на звание)
//    CUser+0x17E00 (97792) 32 б  — маска «НАЙДЕНО», 4 qword
//    CUser+0x174   (372)   i32   — charId (сверен: 0x54BD7F `mov edx,[ecx+0x174]`)
//    CUser+0x178   (376)         — имя персонажа
//  ★ Маска «получено» и маска «найдено» РАЗДЕЛЕНЫ УКАЗАТЕЛЕМ на массив записей —
//    то есть НАРАСТИТЬ маску НА МЕСТЕ НЕЛЬЗЯ: следующие 4 байта заняты.
//
//  Гейты «слово < 4» (то есть id < 256) — ПЯТЬ штук, полный список получен сплошным
//  сканом дизассемблера ЖИВОГО образа по всему тракту славы:
//    0x54A910  cmp ecx,4   в CheckFameBit      @0x54A890 (возвращает «бита ЕЩЁ НЕТ»)
//    0x54A9FC  cmp edx,4   в AddFameBit        @0x54A980
//    0x54AE10  cmp ecx,4   в SubFameBit        @0x54AD00
//    0x54CB26  cmp eax,4   в ChangeActiveFame  @0x54C820 — гейт «владею ли званием»
//                          у обработчика 6067 «НАДЕТЬ звание»
//    0x54CF77  cmp eax,4   в DeleteFameInfo    @0x54CE30 — тот же гейт у 6069 «УДАЛИТЬ»
//  (плюс 0x54B1E8 — цикл по 4 словам при сборке DB-тела 2266 внутри SubFameBit;
//   наш «высокий» путь его не использует, тело строим сами.)
//  Верхняя граница числа записей FameInfo.txt:
//    0x4A19AA  cmp dword [edx+0x1D52BC], 0x100  → «FameInfo count over» (загрузчик
//              FameInfo.txt — это sub_4A18F0@0x4A18F0; «LoadFameInfo@0x49F410» из
//              прежнего отчёта — ВЫЗЫВАЮЩАЯ его функция инициализации, миснейм).
//  ★★★ ЭТО ЕДИНСТВЕННЫЙ `cmp …,0x100` ВО ВСЁМ ТРАКТЕ. Проверено сплошным
//  дизассемблированием ЖИВОГО образа по зонам 0x49F410…0x4A0000, 0x4A18F0…0x4A1FF0,
//  0x4A1FF0…0x4A2CF0, 0x4A2DC0…0x4A4870, 0x54A7D0…0x54B260, 0x54BD10…0x54D710:
//  совпадение ровно одно — 0x4A19AA. Размер выделения таблицы (`96*count`,
//  0x4A19DE…0x4A19F3: `mov edx,0x60; mul edx; call operator new`) и все обходы
//  (`imul …,0x60`) считаются ОТ СЧЁТЧИКА и масштабируются сами — второго зашитого
//  256 или 96*256 рядом НЕТ.
//  ⚠ ЦЕНА ОШИБКИ ПОРЯДКА: при count > предела загрузчик делает ранний выход
//  (`sub_5684D0("FameInfo count over"); return 0`), а вызывающая функция на это
//  отвечает `exit(1)` (GameServer.c:64741-64748) — то есть GameServer НЕ ЗАПУСТИТСЯ
//  вовсе. Файл на 280 записей класть ТОЛЬКО ПОСЛЕ установки этой DLL.
//  Длины тел пакетов клиенту:
//    0x54C019  push 0x17B2 / push 0x2A  — 6066 «маска получено», 42 б
//    0x54C527  push 0x17C6 / push 0x26  — 6086 «маска найдено»,  38 б
//  Глобальные:
//    0x7DFFD4 i32  — число записей FameInfo (гейт `id < count` во всех трёх функциях)
//    0x7DFFD8 ptr  — таблица FameInfo, запись 96 б (+0x56 очки, +0x1A+10m тройки бонусов)
//
//  ── ДИФ С ЖИВЫМ ОБРАЗОМ (закон gameserver-decompile-stale) ───────────────────
//  Полный побайтовый диф нашего RE/ida/server_work/GameServer.exe
//  (MD5 68BA5176 2209007B 8AB47260 C92480D0) и ЖИВОГО
//  \\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\GameServer\GameServer.exe
//  (MD5 E7B4AC38 E8328AAA 847BBD9B F261BB01, 1 740 800 б): 218 байт в 52 участках.
//  Участки .text: 0x4A0440…0x4A053D, 0x4A5382…0x4A53E8, 0x4C0BE1, 0x523F8B, 0x52400D,
//  0x526CFC…0x526DEF, 0x52C613, 0x582679…0x58288D. ★ НИ ОДИН из них не попадает в
//  зоны этого патча (0x4A18F0…0x4A1FF0, 0x4A2800…0x4A2830, 0x54A890…0x54B260,
//  0x54BD10…0x54C540): расхождений НОЛЬ, всё сказанное относится к ЖИВОМУ серверу.
//  Байты каждой площадки прочитаны в дизассемблере ЖИВОГО образа (они ниже, в kOrig*).
//
//  ── СХЕМА СОВМЕСТИМОСТИ (клиент и сервер обновляются РАЗДЕЛЬНО) ──────────────
//  ★ ФОРМАТ САМООПИСАТЕЛЕН ПО ДЛИНЕ ТЕЛА, расширение дописано В ХВОСТ:
//      6066: 42 б (старый) → 74 б (новый), [42..73] = биты 256…511 «получено»;
//      6086: 38 б (старый) → 70 б (новый), [38..69] = биты 256…511 «найдено».
//  Старая часть НЕ сдвинута, поэтому СТАРЫЙ клиент читает свои фиксированные
//  0x2A/0x26 байт (`netOnCharEquipUpdate@0xE9A6F0`, `netHandler_OnCharData32@0xE9A7D0`
//  копируют ровно 0x20 байт маски) и хвост ПРОСТО НЕ ЗАМЕЧАЕТ — рукопожатие не нужно.
//  НОВЫЙ клиент смотрит на длину тела и понимает оба формата (`UAsdaTitleSubsystem::
//  ParseMaskBody`, откат `asda.Title.Mask512 0`).
//  Обратное направление (C→S 6067/6069) не меняется вовсе: там titleId уже i16.
//  ★ Второе доказательство того, что приёмник клиента длиной не ограничен: опкод 2255
//  той же системы ходит ПЕРЕМЕННОЙ длины (6 + 46·N) через тот же читатель.
//
//  ── ГДЕ ХРАНИМ БИТЫ 256…511 ─────────────────────────────────────────────────
//  В CUser места нет (см. выше). Поэтому берём ХВОСТ МАССИВА ЗАПИСЕЙ звания:
//  массив выделяется на игрока как `operator new(44 * fameCount)` в sub_4A1FF0
//  (call @0x4A2824, результат кладётся в CUser+0x17DFC — сверено @0x4A289C), и мы
//  подменяем ЭТОТ вызов своим: выделяем на 64 байта больше и обнуляем добавку.
//    хвост[0..31]  — биты 256…511 маски «получено»
//    хвост[32..63] — биты 256…511 маски «найдено»
//  Хвост живёт и умирает вместе с массивом, отдельных таблиц и индексов не нужно.
//
//  ── ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ ─────────────────────────────────────────────────
//  1. ★ СОХРАНЕНИЯ В БАЗУ У БИТОВ 256…511 НЕТ. Маска ездит в БД пакетами 2256 (82 б),
//     2257 (54 б) и 2266 (40 б) — во всех трёх ровно 4 qword, и принимает их
//     DBManager, а не GameServer. Расширение хранения = правка DBManager + колонки
//     в базе, это РЕШЕНИЕ ВЛАДЕЛЬЦА (подробности в отчёте). Поэтому на «высоком»
//     пути мы НАМЕРЕННО не шлём 2256/2257/2266: id ≥ 256 для DBManager вне
//     диапазона (у него свой контроль `RecvDBUserFameInfo … iFameIndex Error`).
//     Следствие: звание с id ≥ 256, выданное в сессии, ПОСЛЕ ПЕРЕЗАХОДА пропадёт,
//     пока не появится поддержка в базе.
//  2. Одного кода мало: `ConfigSet\FameInfo.txt` на живом содержит 251 запись
//     (id 0…250), а гейт `id < count` стоит во ВСЕХ трёх функциях. Чтобы звания
//     256…279 существовали и на сервере, таблицу надо дорастить до 280 записей —
//     это правка ДАННЫХ (авторитет — сервер), см. отчёт и PORT_PENDING.
//  3. Стоковый путь (id < 256) НЕ ТРОГАЕТСЯ ВООБЩЕ: наши трамплины стоят на входе
//     и при id < 256 доигрывают вытесненный пролог и уходят в оригинальный код
//     байт в байт. Любая ошибка в новом коде может задеть только звания ≥ 256.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* kSec = L"P21_TitleMask512";

    // ── Ключи ini (каждая часть — свой ключ) ────────────────────────────────
    bool g_raiseCap    = true;   // предел FameInfo.txt 256 → 512
    bool g_allocTail   = true;   // хвост из 64 б под биты 256…511
    bool g_highBitOps  = true;   // Check/Add/Sub понимают id 256…511
    bool g_ext6066     = true;   // 6066 уходит расширенным (74 б)
    bool g_ext6086     = true;   // 6086 уходит расширенным (70 б)
    bool g_dbHigh      = true;   // обмен старшей половиной с базой (2330/2331/2332)
    bool g_highFame    = true;   // ★ 18.11.2026: слава за звания 256…511 при входе (приём 2332) — ключ HighFamePoints

    // ── Константы образа (ЖИВОЙ GameServer.exe, MD5 E7B4AC38…) ─────────────
    constexpr DWORD kVaFameCount   = 0x007DFFD4;  // i32  — число записей FameInfo
    constexpr DWORD kVaFameTable   = 0x007DFFD8;  // ptr  — таблица FameInfo, запись 96 б

    constexpr DWORD kOffCharId     = 0x00174;     // CUser: charId i32
    constexpr DWORD kOffFamePoint  = 0x17DD0;     // CUser: очки славы i32
    constexpr DWORD kOffMaskOwned  = 0x17DDC;     // CUser: маска «получено», 32 б
    constexpr DWORD kOffRecords    = 0x17DFC;     // CUser: ptr на массив записей по 44 б
    constexpr DWORD kOffMaskFound  = 0x17E00;     // CUser: маска «найдено», 32 б

    constexpr int   kLowBits       = 256;         // столько бит было в оригинале
    constexpr int   kMaskBytes     = 32;          // 256 бит = 32 байта (половина маски)
    constexpr int   kTailBytes     = 64;          // наш хвост: 32 «получено» + 32 «найдено»
    constexpr int   kFameRecSize   = 44;          // запись массива званий
    constexpr int   kFameTabRec    = 96;          // запись таблицы FameInfo

    constexpr int   kOp6066        = 0x17B2;      // маска «получено» → клиенту
    constexpr int   kOp6086        = 0x17C6;      // маска «найдено»  → клиенту
    constexpr int   kBody6066Old   = 42;
    constexpr int   kBody6066New   = 74;
    constexpr int   kBody6086Old   = 38;
    constexpr int   kBody6086New   = 70;

    // ── Функции образа, которые мы зовём ───────────────────────────────────
    typedef void*  (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);      // sub_5324A0
    typedef short  (__cdecl    *PFN_StatCalc)(int lo, int hi);                          // sub_5329A0
    typedef int    (__fastcall *PFN_SendToUser)(void* self, void* edx, int op, int len,
                                                int userNum, void* body, int a5, int a6); // sub_4C28F0
    typedef void*  (__cdecl    *PFN_OperatorNew)(size_t n);                             // 0x56ACE9
    typedef void   (__fastcall *PFN_ClearRec)(void* self, void* edx);                   // sub_54F410

    // ── обмен с базой (пара к патчу DBManager P22) ─────────────────────────
    //   Адреса и соглашения сняты с ЖИВОГО образа по месту отправки 2256
    //   (0x54AC8A…0x54ACAB) — тем же путём уходят 2257/2266/2274/8501.
    typedef int   (__fastcall *PFN_GetCharId)(void* self, void* edx, int userNum); // sub_5324F0
    typedef char  (__fastcall *PFN_GetCharIdx)(void* self, void* edx, int userNum);// sub_532530
    typedef char  (__fastcall *PFN_GetGroup)(void* self, void* edx);               // sub_4A7EA0
    typedef short (__fastcall *PFN_GetSendId)(void* self, void* edx);              // sub_4C0A30
    typedef int   (__fastcall *PFN_SendDb)(void* self, void* edx, int op, int len,
                                           int sendId, void* body, int userNum);   // sub_5646C0

    PFN_GetCharId  const pGetCharId  = (PFN_GetCharId)  0x005324F0;
    PFN_GetCharIdx const pGetCharIdx = (PFN_GetCharIdx) 0x00532530;
    PFN_GetGroup   const pGetGroup   = (PFN_GetGroup)   0x004A7EA0;
    PFN_GetSendId  const pGetSendId  = (PFN_GetSendId)  0x004C0A30;
    PFN_SendDb     const pSendDb     = (PFN_SendDb)     0x005646C0;
    void* const kGroupThis = (void*)0x0060AD18;   // ecx у sub_4A7EA0 (0x54AF2B)
    void* const kDbMgr     = (void*)0x007E0538;   // ecx у sub_5646C0 (0x54ACA6)

    constexpr int kOpDbLoadHi  = 0x91A;   // 2330 GS->DB «дай старшую половину»
    constexpr int kOpDbSaveHi  = 0x91B;   // 2331 GS->DB «сохрани старшую половину»
    constexpr int kOpDbReplyHi = 0x91C;   // 2332 DB->GS ответ
    constexpr int kDbBodyLoad  = 8;
    constexpr int kOpDbFamePt  = 2274;    // GS->DB «очки славы» (UPCharFamePointUp, абсолютно) — тело 12 б, как в recvDB
    constexpr int kDbBodySave  = 8 + 64;

    PFN_GetUser     const pGetUser     = (PFN_GetUser)     0x005324A0;
    PFN_StatCalc    const pStatCalc    = (PFN_StatCalc)    0x005329A0;
    PFN_SendToUser  const pSendToUser  = (PFN_SendToUser)  0x004C28F0;
    PFN_OperatorNew const pOperatorNew = (PFN_OperatorNew) 0x0056ACE9;
    PFN_ClearRec    const pClearRec    = (PFN_ClearRec)    0x0054F410;

    // ── Размер массива записей, запомненный нашим аллокатором ──────────────
    //   Все выделения идут с ОДНИМ и тем же n (= 44 * fameCount), поэтому одного
    //   числа хватает. Если вдруг придёт другой размер — гасим «высокий» путь:
    //   лучше отказ, чем чтение чужой памяти.
    volatile LONG g_fameRecordsBytes = 0;
    volatile LONG g_tailBroken       = 0;

    // ── TLS: CUser, чью маску сейчас собирает вызывающая функция ───────────
    //   Ставится трамплином на входе recvDBUserFameBitInfo / recvDBUserOpenFameBitInfo,
    //   читается подменённым вызовом отправки. Оба события идут в ОДНОМ вызове
    //   одного потока, поэтому потокобезопасно и без глобальных гонок.
    __declspec(thread) void* t_fameUser = nullptr;

    inline BYTE* UserPtr(void* u, DWORD off) { return (BYTE*)u + off; }

    // Хвост из 64 байт: биты 256…511 обеих масок. nullptr — хранилища нет.
    BYTE* HighTail(void* pUser)
    {
        if (!pUser || g_tailBroken || g_fameRecordsBytes <= 0) { return nullptr; }
        BYTE* recs = *(BYTE**)UserPtr(pUser, kOffRecords);
        if (!recs) { return nullptr; }
        return recs + g_fameRecordsBytes;
    }
    inline BYTE* HighOwned(void* pUser) { BYTE* t = HighTail(pUser); return t ? t : nullptr; }
    inline BYTE* HighFound(void* pUser) { BYTE* t = HighTail(pUser); return t ? t + kMaskBytes : nullptr; }

    // Опережающее объявление: определение ниже, рядом с остальным обменом с базой.
    void SendDbHigh(void* fameSelf, int userNum, bool bSave);

    inline int   FameCount()      { return *(int*)  kVaFameCount; }
    inline BYTE* FameTable()      { return *(BYTE**)kVaFameTable; }
    inline BYTE* FameRow(int id)  { BYTE* t = FameTable(); return t ? t + kFameTabRec * id : nullptr; }

    // Бит id (id ≥ 256) в 32-байтной половине.
    inline bool  HiGet(const BYTE* hi, int id) { const int b = id - kLowBits; return (hi[b >> 3] & (1u << (b & 7))) != 0; }
    inline void  HiSet(BYTE* hi, int id)       { const int b = id - kLowBits; hi[b >> 3] |= (BYTE)(1u << (b & 7)); }
    inline void  HiClr(BYTE* hi, int id)       { const int b = id - kLowBits; hi[b >> 3] &= (BYTE)~(1u << (b & 7)); }

    // ── Отправка расширенных масок клиенту ─────────────────────────────────
    //   `fameSelf` — this функции семейства славы; отправитель лежит в *(void**)(this+4)
    //   (сверено: recvDB @0x54C01E `mov eax,[ebp-0x374]` / `mov ecx,[eax+4]`).
    void SendMask6066(void* fameSelf, void* pUser, int userNum)
    {
        if (!fameSelf || !pUser) { return; }
        void* sender = *(void**)((BYTE*)fameSelf + 4);
        if (!sender) { return; }
        BYTE  body[kBody6066New] = {};
        *(short*)&body[0] = (short)userNum;                                   // userIdx
        *(int*)  &body[2] = *(int*)UserPtr(pUser, kOffCharId);                // charId
        *(int*)  &body[6] = *(int*)UserPtr(pUser, kOffFamePoint);             // очки славы
        memcpy(&body[10], UserPtr(pUser, kOffMaskOwned), kMaskBytes);         // биты 0…255
        const BYTE* hi = HighOwned(pUser);
        const int   len = (g_ext6066 && hi) ? kBody6066New : kBody6066Old;
        if (g_ext6066 && hi) { memcpy(&body[kBody6066Old], hi, kMaskBytes); } // биты 256…511
        pSendToUser(sender, nullptr, kOp6066, len, userNum, body, 0, 1);
    }

    void SendMask6086(void* fameSelf, void* pUser, int userNum)
    {
        if (!fameSelf || !pUser) { return; }
        void* sender = *(void**)((BYTE*)fameSelf + 4);
        if (!sender) { return; }
        BYTE  body[kBody6086New] = {};
        // ★ У 6086 порядок полей ОБРАТНЫЙ к 6066 — так в оригинале.
        *(int*)  &body[0] = *(int*)UserPtr(pUser, kOffCharId);                // charId
        *(short*)&body[4] = (short)userNum;                                   // userIdx
        memcpy(&body[6], UserPtr(pUser, kOffMaskFound), kMaskBytes);          // биты 0…255
        const BYTE* hi = HighFound(pUser);
        const int   len = (g_ext6086 && hi) ? kBody6086New : kBody6086Old;
        if (g_ext6086 && hi) { memcpy(&body[kBody6086Old], hi, kMaskBytes); }
        pSendToUser(sender, nullptr, kOp6086, len, userNum, body, 0, 1);
    }

    // ═══════════════════ «ВЫСОКИЕ» РЕАЛИЗАЦИИ (id 256…511) ═══════════════════
    //  Каждая — точная копия стоковой ветки для одного слова маски, но по хвосту
    //  и БЕЗ пакетов в базу (см. «ЧЕГО ЗДЕСЬ НЕТ», п.1).

    // CheckFameBit: «звания ЕЩЁ НЕТ» (стоковая семантика — истина, когда бит НЕ взведён).
    // outWord/outBit заполняются так же, как в стоке: id/64 и id%64.
    int __cdecl HighCheck(void* self, int userNum, int titleId, BYTE* outWord, BYTE* outBit)
    {
        if (titleId < 0 || titleId >= FameCount()) { return 0; }
        void* pUser = pGetUser(self, nullptr, userNum);
        if (!pUser) { return 0; }
        if (outWord) { *outWord = (BYTE)(titleId / 64); }
        if (outBit)  { *outBit  = (BYTE)(titleId % 64); }
        const BYTE* hi = HighOwned(pUser);
        if (!hi) { return 0; }                       // хранилища нет — считаем «нельзя»
        return HiGet(hi, titleId) ? 0 : 1;
    }

    // AddFameBit: взвести бит, начислить очки, заполнить слоты бонусов записи.
    int __cdecl HighAdd(void* self, int userNum, int titleId)
    {
        if (titleId < 0 || titleId >= FameCount()) { return 0; }
        void* pUser = pGetUser(self, nullptr, userNum);
        if (!pUser) { return 0; }
        BYTE* hi = HighOwned(pUser);
        BYTE* row = FameRow(titleId);
        BYTE* recs = *(BYTE**)UserPtr(pUser, kOffRecords);
        if (!hi || !row || !recs)
        {
            Log::Line(L"    P21: ! звание %d: хранилища для битов 256…511 нет, выдача пропущена", titleId);
            return 0;
        }
        if (HiGet(hi, titleId)) { return 1; }        // уже есть — стоку тоже нечего делать
        HiSet(hi, titleId);

        // Очки славы: FameInfo[id]+0x56 (i16), как в стоке @0x54AAC8.
        *(int*)UserPtr(pUser, kOffFamePoint) += *(short*)(row + 0x56);

        // Шесть слотов бонусов записи: FameInfo[id]+0x1A+10m → запись+8+6m (стоки @0x54AB08…).
        BYTE* rec = recs + kFameRecSize * titleId;
        for (int m = 0; m < 6; ++m)
        {
            const BYTE* src = row + 0x1A + 10 * m;
            if (*(short*)(src + 0) > -1)
            {
                *(short*)(rec + 8 + 6 * m + 0) = *(short*)(src + 0);
                *(short*)(rec + 8 + 6 * m + 2) = pStatCalc(*(short*)(src + 2), *(short*)(src + 4));
                *(short*)(rec + 8 + 6 * m + 4) = pStatCalc(*(short*)(src + 6), *(short*)(src + 8));
            }
        }

        // Клиенту — полная маска расширенным телом. В базу НЕ шлём (п.1 шапки).
        SendMask6066(self, pUser, userNum);
        SendDbHigh(self, userNum, /*bSave*/ true);   // 2331 -> DBManager (P22)
        Log::Line(L"    P21: звание %d ВЫДАНО (бит %d маски «получено»)", titleId, titleId);
        return 1;
    }

    // SubFameBit: снять бит «получено», обнулить запись, снять очки, поставить «найдено».
    int __cdecl HighSub(void* self, int userNum, int titleId)
    {
        if (titleId < 0 || titleId >= FameCount()) { return 0; }
        void* pUser = pGetUser(self, nullptr, userNum);
        if (!pUser) { return 0; }
        BYTE* hiOwn = HighOwned(pUser);
        BYTE* hiFnd = HighFound(pUser);
        BYTE* row   = FameRow(titleId);
        BYTE* recs  = *(BYTE**)UserPtr(pUser, kOffRecords);
        if (!hiOwn || !hiFnd || !row || !recs) { return 0; }

        HiClr(hiOwn, titleId);
        BYTE* rec = recs + kFameRecSize * titleId;
        *(int*)(rec + 0) = 0;
        *(int*)(rec + 4) = 0;
        pClearRec(rec, nullptr);                      // sub_54F410 — сброс шести троек

        int* pts = (int*)UserPtr(pUser, kOffFamePoint);
        *pts -= *(short*)(row + 0x56);
        if (*pts < 0) { *pts = 0; }                   // стоковая отсечка @0x54AF11

        SendMask6066(self, pUser, userNum);
        if (!HiGet(hiFnd, titleId))                   // стоковая ветка «секрет открыт»
        {
            HiSet(hiFnd, titleId);
            SendMask6086(self, pUser, userNum);
        }
        SendDbHigh(self, userNum, /*bSave*/ true);   // 2331 -> DBManager (P22)
        Log::Line(L"    P21: звание %d СНЯТО (бит %d)", titleId, titleId);
        return 1;
    }

    // ═══════════════════ ПОДМЕНА operator new для массива записей ════════════
    //  Патчим ОДИН call @0x4A2824 (результат уходит в CUser+0x17DFC — @0x4A289C).
    void* __cdecl NewFameRecords(size_t n)
    {
        void* p = pOperatorNew(n + kTailBytes);
        if (!p) { return p; }
        memset((BYTE*)p + n, 0, kTailBytes);          // хвост обязан быть чистым
        const LONG want = (LONG)n;
        const LONG had  = InterlockedCompareExchange(&g_fameRecordsBytes, want, 0);
        if (had != 0 && had != want)
        {
            // Разные размеры — арифметика «recs + n» перестаёт быть однозначной.
            InterlockedExchange(&g_tailBroken, 1);
            Log::Line(L"    P21: ! массив званий выделен разными размерами (%d и %d) — "
                      L"биты 256…511 отключены", had, want);
        }
        return p;
    }

    // ═══════════════════ ТРАМПЛИНЫ НА ВХОДЕ ФУНКЦИЙ ══════════════════════════
    //  Общая схема: ставим `jmp` на вход, в трамплине решаем «высокий id или нет».
    //  Стоковая ветка ДОИГРЫВАЕТ вытесненный пролог и уходит в оригинал — то есть
    //  для id < 256 поведение байт в байт прежнее.
    //  (переменные, а не константы: naked-ассемблер MSVC умеет jmp только [метка])
    DWORD g_checkBack = 0x0054A896;   // CheckFameBit + 6  (после `push ebp; mov ebp,esp; sub esp,0x18`)
    DWORD g_addBack   = 0x0054A986;   // AddFameBit   + 6  (после `… sub esp,0x78`)
    DWORD g_subBack   = 0x0054AD09;   // SubFameBit   + 9  (после `… sub esp,0xE0`)
    DWORD g_dbFameBack   = 0x0054BD19; // recvDBUserFameBitInfo     + 9
    DWORD g_dbOpenBack   = 0x0054C436; // recvDBUserOpenFameBitInfo + 6

    // ── CheckFameBit @0x54A890: __thiscall(userNum i16, titleId i16, BYTE*, BYTE*), ret 0x10
    __declspec(naked) void TrampCheck()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            // [ebp+4] ret · [ebp+8] userNum · [ebp+0Ch] titleId · [ebp+10h] outWord · [ebp+14h] outBit
            cmp   byte ptr [g_highBitOps], 0
            je    Stock
            movsx eax, word ptr [ebp+0Ch]
            cmp   eax, 100h
            jl    Stock
            push  dword ptr [ebp+14h]
            push  dword ptr [ebp+10h]
            push  eax                       // titleId
            movsx edx, word ptr [ebp+8]
            push  edx                       // userNum
            push  ecx                       // this
            call  HighCheck
            add   esp, 20
            pop   ebp
            ret   10h
        Stock:
            pop   ebp
            push  ebp                       // доигрываем вытесненный пролог
            mov   ebp, esp
            sub   esp, 18h
            jmp   [g_checkBack]
        }
    }

    // ── AddFameBit @0x54A980: __thiscall(userNum i16, titleId i16), ret 8
    __declspec(naked) void TrampAdd()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            cmp   byte ptr [g_highBitOps], 0
            je    Stock
            movsx eax, word ptr [ebp+0Ch]
            cmp   eax, 100h
            jl    Stock
            push  eax                       // titleId
            movsx edx, word ptr [ebp+8]
            push  edx                       // userNum
            push  ecx                       // this
            call  HighAdd
            add   esp, 12
            pop   ebp
            ret   8
        Stock:
            pop   ebp
            push  ebp
            mov   ebp, esp
            sub   esp, 78h
            jmp   [g_addBack]
        }
    }

    // ── SubFameBit @0x54AD00: __thiscall(userNum i16, titleId i16), ret 8
    __declspec(naked) void TrampSub()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            cmp   byte ptr [g_highBitOps], 0
            je    Stock
            movsx eax, word ptr [ebp+0Ch]
            cmp   eax, 100h
            jl    Stock
            push  eax
            movsx edx, word ptr [ebp+8]
            push  edx
            push  ecx
            call  HighSub
            add   esp, 12
            pop   ebp
            ret   8
        Stock:
            pop   ebp
            push  ebp
            mov   ebp, esp
            sub   esp, 0E0h
            jmp   [g_subBack]
        }
    }

    // ═══ ГЕЙТ «ВЛАДЕЮ ЛИ ЗВАНИЕМ» у 6067 «надеть» и 6069 «удалить» ═══════════
    //  Найдено сплошным сканом (2026-08-29): кроме Check/Add/Sub есть ЕЩЁ ДВА гейта
    //  `(unsigned)(id/64) < 4`, и без них звание id ≥ 256 нельзя ни НАДЕТЬ, ни УДАЛИТЬ,
    //  даже когда оно получено.
    //  Оба места устроены одинаково: к моменту гейта уже посчитаны слово и бит, а
    //  указатель на CUser лежит в локальной. Мы подменяем ровно блок гейта; для
    //  id < 256 трамплин ДОСЛОВНО повторяет стоковую проверку и уходит в стоковый код.

    // Читает бит id ≥ 256 из нашего хвоста. word 4…7, bit 0…63.
    int __cdecl HighOwnedBit(void* pUser, int bit, int word)
    {
        const BYTE* hi = HighOwned(pUser);
        if (!hi || word < 4 || word > 7) { return 0; }
        const int b = (word - 4) * 64 + bit;          // 0…255 внутри хвоста
        return (hi[b >> 3] & (1u << (b & 7))) ? 1 : 0;
    }

    // ── ChangeActiveFame @0x54C820 (опкод 6067 «надеть звание») ────────────
    //  Площадка 0x54CB1A, 22 байта — весь блок гейта целиком:
    //    movsx edx,[ebp-0x59] ; test ; jl отказ ; movsx eax,[ebp-0x59] ; cmp eax,4
    //    ; jl продолжение ; jmp 0x54CE14 (отказ)
    //  Локальные кадра: [ebp-0x59] слово, [ebp-0x4D] бит, [ebp-0x40] CUser*.
    DWORD g_wearDeny  = 0x0054CE14;   // штатный отказ «звания нет»
    DWORD g_wearAllow = 0x0054CB81;   // штатное продолжение ПОСЛЕ проверки бита
    DWORD g_wearCont  = 0x0054CB30;   // стоковая ветка: проверка бита низкой маски

    __declspec(naked) void TrampWear()
    {
        __asm
        {
            cmp   byte ptr [g_highBitOps], 0
            je    StockGate
            movsx eax, byte ptr [ebp-0x59]        // слово маски
            cmp   eax, 4
            jl    StockGate
            cmp   eax, 8
            jge   Deny
            push  eax                             // word
            movzx edx, byte ptr [ebp-0x4D]        // bit
            push  edx
            push  dword ptr [ebp-0x40]            // CUser*
            call  HighOwnedBit
            add   esp, 12
            test  eax, eax
            jne   Allow
        Deny:
            jmp   [g_wearDeny]
        Allow:
            jmp   [g_wearAllow]
        StockGate:                                // ДОСЛОВНО стоковая проверка
            movsx edx, byte ptr [ebp-0x59]
            test  edx, edx
            jl    Deny
            movsx eax, byte ptr [ebp-0x59]
            cmp   eax, 4
            jge   Deny
            jmp   [g_wearCont]
        }
    }

    // ── DeleteFameInfo @0x54CE30 (опкод 6069 «удалить звание») ─────────────
    //  Площадка 0x54CF6B, 26 байт: тот же блок + `mov byte [ebp-0xA],0` (код ответа
    //  6070 = «звания нет») и `jmp 0x54D1C8`.
    //  Локальные кадра: [ebp-0x31] слово, [ebp-0x11] бит, [ebp-0x38] CUser*.
    DWORD g_delDeny  = 0x0054D1C8;    // штатный выход с кодом ответа 0
    DWORD g_delAllow = 0x0054CFDA;    // штатное продолжение (зовёт SubFameBit)
    DWORD g_delCont  = 0x0054CF8A;    // стоковая ветка: проверка бита низкой маски

    __declspec(naked) void TrampDel()
    {
        __asm
        {
            cmp   byte ptr [g_highBitOps], 0
            je    StockGate
            movsx eax, byte ptr [ebp-0x31]
            cmp   eax, 4
            jl    StockGate
            cmp   eax, 8
            jge   Deny
            push  eax
            movzx edx, byte ptr [ebp-0x11]
            push  edx
            push  dword ptr [ebp-0x38]
            call  HighOwnedBit
            add   esp, 12
            test  eax, eax
            jne   Allow
        Deny:
            mov   byte ptr [ebp-0x0A], 0          // код ответа 6070 «звания нет»
            jmp   [g_delDeny]
        Allow:
            jmp   [g_delAllow]
        StockGate:
            movsx edx, byte ptr [ebp-0x31]
            test  edx, edx
            jl    Deny
            movsx eax, byte ptr [ebp-0x31]
            cmp   eax, 4
            jge   Deny
            jmp   [g_delCont]
        }
    }

    // ── recvDBUserFameBitInfo @0x54BD10: __thiscall(userNum i16, msgPtr)
    //   Момент ЗАГРУЗКИ ПЕРСОНАЖА: база только что прошила маску «получено» четырьмя
    //   qword'ами. Битов 256…511 база не хранит, поэтому хвост обязан быть чистым —
    //   иначе прежний владелец слота оставил бы в нём свои звания.
    void __cdecl OnFameBitInfo(void* self, int userNum)
    {
        void* pUser = pGetUser(self, nullptr, userNum);
        t_fameUser = pUser;
        BYTE* hi = HighOwned(pUser);
        if (hi) { memset(hi, 0, kMaskBytes); }
        // ★ и сразу просим базу прислать старшую половину (ответ 2332 придёт следом).
        SendDbHigh(self, userNum, /*bSave*/ false);
    }

    __declspec(naked) void TrampDbFame()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            pushad
            movsx edx, word ptr [ebp+8]
            push  edx
            push  ecx
            call  OnFameBitInfo
            add   esp, 8
            popad
            pop   ebp
            push  ebp
            mov   ebp, esp
            sub   esp, 384h
            jmp   [g_dbFameBack]
        }
    }

    // ── recvDBUserOpenFameBitInfo @0x54C430: то же для маски «найдено».
    void __cdecl OnOpenFameBitInfo(void* self, int userNum)
    {
        void* pUser = pGetUser(self, nullptr, userNum);
        t_fameUser = pUser;
        BYTE* hi = HighFound(pUser);
        if (hi) { memset(hi, 0, kMaskBytes); }
    }

    __declspec(naked) void TrampDbOpenFame()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            pushad
            movsx edx, word ptr [ebp+8]
            push  edx
            push  ecx
            call  OnOpenFameBitInfo
            add   esp, 8
            popad
            pop   ebp
            push  ebp
            mov   ebp, esp
            sub   esp, 60h
            jmp   [g_dbOpenBack]
        }
    }

    // ═══════════════════ ОБМЕН СТАРШЕЙ ПОЛОВИНОЙ С БАЗОЙ ════════════════════
    //  Пара к патчу DBManager P22. Существующие DB-пакеты 2256/2257/2266 несут
    //  ровно 4 qword и удлинять их нельзя, поэтому заводим ДВА СВОИХ опкода:
    //      2330 «дай старшую половину»    (тело 8 б)  -> ответ 2332 (тело 72 б)
    //      2331 «сохрани старшую половину» (тело 72 б)
    //  Раскладка первых восьми байт повторяет тело 2256, чтобы DBManager брал
    //  поля с тех же смещений: [0..1] userNum, [2..5] charId, [6] CharIdx,
    //  [7] группа серверов (её ждёт sub_407390 на той стороне).
    //  ⚠ НЕ обновлённый DBManager такие опкоды просто не узнаёт: три диапазона
    //  его switch дают `ja` в эпилог, обработчика нет, ошибки нет — поэтому
    //  включать этот обмен безопасно даже до подмены DBManager.

    void SendDbHigh(void* fameSelf, int userNum, bool bSave)
    {
        if (!g_dbHigh || !fameSelf) { return; }
        void* pUser = pGetUser(fameSelf, nullptr, userNum);
        if (!pUser) { return; }
        const BYTE* hiOwn = HighOwned(pUser);
        const BYTE* hiFnd = HighFound(pUser);
        if (bSave && (!hiOwn || !hiFnd)) { return; }

        BYTE body[kDbBodySave] = {};
        *(short*)&body[0] = (short)userNum;
        *(int*)  &body[2] = pGetCharId(fameSelf, nullptr, userNum);
        body[6] = (BYTE)pGetCharIdx(fameSelf, nullptr, userNum);
        body[7] = (BYTE)pGetGroup(kGroupThis, nullptr);
        if (bSave)
        {
            memcpy(&body[8],  hiOwn, kMaskBytes);
            memcpy(&body[40], hiFnd, kMaskBytes);
        }
        void* sender = *(void**)((BYTE*)fameSelf + 4);
        if (!sender) { return; }
        const short sendId = pGetSendId(sender, nullptr);
        pSendDb(kDbMgr, nullptr,
                bSave ? kOpDbSaveHi : kOpDbLoadHi,
                bSave ? kDbBodySave : kDbBodyLoad,
                sendId, body, userNum);
    }

    // Слава целиком (биты 0…FameCount−1) → CUser и, если изменилась, в базу пакетом 2274 (раскладка тела — как recvDB
    // @0x54C0xx: [0..1] userNum, [2..5] charId, [6] CharIdx, [7] группа серверов, [8..11] очки).
    void RecalcFamePoint(void* fameSelf, void* pUser, int userNum)
    {
        const BYTE* lo = UserPtr(pUser, kOffMaskOwned);
        const BYTE* hi = HighOwned(pUser);
        const int   n  = FameCount();
        if (!lo || !hi || n <= 0) { return; }
        int fame = 0;
        for (int id = 0; id < n && id < 2 * kLowBits; ++id)
        {
            const bool owned = id < kLowBits ? (lo[id >> 3] & (1u << (id & 7))) != 0 : HiGet(hi, id);
            BYTE* row = FameRow(id);
            if (owned && row) { fame += *(short*)(row + 0x56); }
        }
        int* cur = (int*)UserPtr(pUser, kOffFamePoint);
        if (*cur == fame) { return; }
        Log::Line(L"    P21: слава %d -> %d (с учётом званий 256…511)", *cur, fame);
        *cur = fame;
        void* sender = *(void**)((BYTE*)fameSelf + 4);
        if (!sender) { return; }
        BYTE body[12] = {};
        *(short*)&body[0] = (short)userNum;
        *(int*)  &body[2] = pGetCharId(fameSelf, nullptr, userNum);
        body[6] = (BYTE)pGetCharIdx(fameSelf, nullptr, userNum);
        body[7] = (BYTE)pGetGroup(kGroupThis, nullptr);
        *(int*)  &body[8] = fame;
        pSendDb(kDbMgr, nullptr, kOpDbFamePt, sizeof(body), pGetSendId(sender, nullptr), body, userNum);
    }

    // ── Приём 2332: заливка старшей половины из базы ────────────────────────
    //  Диспетчер ответов базы — `ConnectSocketMsgProcess@0x42FAB0`; все ветки,
    //  и обработанные, и неизвестные, сходятся в эпилоге 0x43462B (там меряется
    //  время). Вешаемся там же, где P22 в DBManager: одна площадка, ни одна
    //  существующая ветка не переписана.
    //  Локальные кадра (сверены с ЖИВЫМ образом):
    //      [ebp-0x04]   = указатель на пакет   (0x434650 mov ecx,[ebp-4]; movzx edx,[ecx+7])
    //      [ebp-0x08]   = userNum (i16)        (0x43276B mov cx,[ebp-8])
    //      [ebp-0x1028] = объект, из которого достаётся this славы:
    //                     *(void**)(*(void**)(local+4)+0x34)   (0x432770…0x432779)
    #define GSD_PKT   0x04
    #define GSD_UNUM  0x08
    #define GSD_OBJ   0x1028

    void __cdecl OnDbHighReply(BYTE* hostEbp)
    {
        if (!g_dbHigh) { return; }
        BYTE* pkt = *(BYTE**)(hostEbp - GSD_PKT);
        if (!pkt) { return; }
        if (*(WORD*)(pkt + 7) != (WORD)kOpDbReplyHi) { return; }

        BYTE* obj = *(BYTE**)(hostEbp - GSD_OBJ);
        if (!obj) { return; }
        void* fameSelf = *(void**)(*(BYTE**)(obj + 4) + 0x34);
        if (!fameSelf) { return; }

        BYTE* body    = pkt + 9;
        const int userNum = *(short*)&body[0];
        const int charId  = *(int*)&body[2];

        void* pUser = pGetUser(fameSelf, nullptr, userNum);
        if (!pUser) { return; }
        // ★ закон wrong-notice-check-packet-first: сверяем, что ответ про ЭТОГО игрока.
        if (*(int*)UserPtr(pUser, kOffCharId) != charId) { return; }

        BYTE* hiOwn = HighOwned(pUser);
        BYTE* hiFnd = HighFound(pUser);
        if (!hiOwn || !hiFnd) { return; }
        memcpy(hiOwn, &body[8],  kMaskBytes);
        memcpy(hiFnd, &body[40], kMaskBytes);

        // ★ 18.11.2026 (решение владельца, разбор Reports/admin_center/research_titles_honor.md §2.3): стоковый recvDB
        //   (GameServer.c:127100) считает славу ТОЛЬКО по битам 0…255 и пишет её в базу (2274) — слава званий 256…511
        //   пропадала при каждом входе. Здесь старшая половина уже на месте: слава = Σ FameInfo[id]+0x56 по ВСЕМ полученным
        //   битам (пересчёт целиком, а не «+=»: повторный ответ 2332 не удвоит очки), и если она изменилась — та же запись
        //   2274, что у стока. Клиент получает её ниже в 6066 (body[6] — очки славы).
        if (g_highFame) { RecalcFamePoint(fameSelf, pUser, userNum); }

        // Клиенту уже ушли короткие 6066/6086 (их шлёт recvDB до нашего ответа) —
        // догоняем расширенными, теперь с наполненной старшей половиной.
        SendMask6066(fameSelf, pUser, userNum);
        SendMask6086(fameSelf, pUser, userNum);
    }

    DWORD g_gsDbBack  = 0x00434631;   // возврат за вытесненную команду
    DWORD g_gsTimeSlot = 0x00583028;  // слот импорта счётчика времени

    __declspec(naked) void TrampDbReply()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp
            call  OnDbHighReply
            add   esp, 4
            popad
            popfd
            mov   eax, [g_gsTimeSlot]     // ── вытесненная команда ──
            call  dword ptr [eax]         //    (её eax нужен следующей команде)
            jmp   [g_gsDbBack]
        }
    }

    // ═══════════════════ ПОДМЕНА ОТПРАВКИ 6066 / 6086 ════════════════════════
    //  Меняем ТОЛЬКО `call sub_4C28F0` на площадках отправки (5 байт в 5 байт).
    //  Соглашение то же: __thiscall с шестью стековыми аргументами (ret 0x18),
    //  в C это __fastcall с фиктивным edx.
    int __fastcall SendHook6066(void* self, void* edx, int op, int len, int userNum,
                                void* body, int a5, int a6)
    {
        BYTE  ext[kBody6066New];
        BYTE* hi = HighOwned(t_fameUser);
        if (g_ext6066 && hi && len == kBody6066Old && body)
        {
            memcpy(ext, body, kBody6066Old);
            memcpy(ext + kBody6066Old, hi, kMaskBytes);
            return pSendToUser(self, edx, op, kBody6066New, userNum, ext, a5, a6);
        }
        return pSendToUser(self, edx, op, len, userNum, body, a5, a6);
    }

    int __fastcall SendHook6086(void* self, void* edx, int op, int len, int userNum,
                                void* body, int a5, int a6)
    {
        BYTE  ext[kBody6086New];
        BYTE* hi = HighFound(t_fameUser);
        if (g_ext6086 && hi && len == kBody6086Old && body)
        {
            memcpy(ext, body, kBody6086Old);
            memcpy(ext + kBody6086Old, hi, kMaskBytes);
            return pSendToUser(self, edx, op, kBody6086New, userNum, ext, a5, a6);
        }
        return pSendToUser(self, edx, op, len, userNum, body, a5, a6);
    }

    // ═══════════════════ ПЛОЩАДКИ (байты сняты с ЖИВОГО образа) ══════════════

    // S1 — предел числа записей FameInfo.txt. Правим ОДИН dword-иммедиат.
    const DWORD kSiteCap    = 0x004A19AA;
    const DWORD kCapImmVa   = 0x004A19B0;   // сам иммедиат внутри команды
    const BYTE  kOrigCap[14] =
    {
        0x81, 0xBA, 0xBC, 0x52, 0x1D, 0x00, 0x00, 0x01, 0x00, 0x00, // cmp dword [edx+0x1D52BC],0x100
        0x7E, 0x14,                                                 // jle 0x4A19CA
        0x68, 0x88                                                  // push offset "FameInfo count over"
    };
    const BYTE  kCapNew[4]  = { 0x00, 0x02, 0x00, 0x00 };           // 0x100 → 0x200

    // S2 — выделение массива записей званий: call operator new.
    const DWORD kSiteAlloc  = 0x004A2824;
    const BYTE  kOrigAlloc[16] =
    {
        0xE8, 0xC0, 0x84, 0x0C, 0x00,                               // call 0x56ACE9 (operator new)
        0x83, 0xC4, 0x04,                                           // add  esp,4
        0x89, 0x85, 0x74, 0xFF, 0xFF, 0xFF,                         // mov  [ebp-0x8C],eax
        0xC6, 0x45                                                  // mov  byte [ebp-4],1 (начало)
    };

    // S3 — вход CheckFameBit.
    const DWORD kSiteCheck  = 0x0054A890;
    const BYTE  kOrigCheck[12] =
    {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18,                         // push ebp; mov ebp,esp; sub esp,0x18
        0x89, 0x4D, 0xF0,                                           // mov  [ebp-0x10],ecx
        0x0F, 0xBF, 0x45                                            // movsx eax,word [ebp+0xC] (начало)
    };

    // S4 — вход AddFameBit.
    const DWORD kSiteAdd    = 0x0054A980;
    const BYTE  kOrigAdd[12] =
    {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x78,                         // push ebp; mov ebp,esp; sub esp,0x78
        0x56,                                                       // push esi
        0x89, 0x4D, 0x88,                                           // mov  [ebp-0x78],ecx
        0x0F, 0xBF                                                  // movsx … (начало)
    };

    // S5 — вход SubFameBit (пролог 9 байт).
    const DWORD kSiteSub    = 0x0054AD00;
    const BYTE  kOrigSub[15] =
    {
        0x55, 0x8B, 0xEC,                                           // push ebp; mov ebp,esp
        0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00,                         // sub  esp,0xE0
        0x56,                                                       // push esi
        0x89, 0x8D, 0x28, 0xFF, 0xFF                                // mov  [ebp-0xD8],ecx (начало)
    };

    // S5а — гейт владения в ChangeActiveFame (6067 «надеть»), 22 байта.
    const DWORD kSiteWear = 0x0054CB1A;
    const BYTE  kOrigWear[22] =
    {
        0x0F, 0xBE, 0x55, 0xA7,             // movsx edx, byte [ebp-0x59]   ; слово маски
        0x85, 0xD2,                         // test  edx, edx
        0x7C, 0x09,                         // jl    0x54CB2B (отказ)
        0x0F, 0xBE, 0x45, 0xA7,             // movsx eax, byte [ebp-0x59]
        0x83, 0xF8, 0x04,                   // cmp   eax, 4                 ; ★ гейт id < 256
        0x7C, 0x05,                         // jl    0x54CB30 (проверка бита)
        0xE9, 0xE4, 0x02, 0x00, 0x00        // jmp   0x54CE14 (отказ)
    };

    // S5б — гейт владения в DeleteFameInfo (6069 «удалить»), 26 байт.
    const DWORD kSiteDel = 0x0054CF6B;
    const BYTE  kOrigDel[26] =
    {
        0x0F, 0xBE, 0x55, 0xCF,             // movsx edx, byte [ebp-0x31]
        0x85, 0xD2,                         // test  edx, edx
        0x7C, 0x09,                         // jl    0x54CF7C
        0x0F, 0xBE, 0x45, 0xCF,             // movsx eax, byte [ebp-0x31]
        0x83, 0xF8, 0x04,                   // cmp   eax, 4                 ; ★ гейт id < 256
        0x7C, 0x0E,                         // jl    0x54CF8A
        0xC6, 0x45, 0xF6, 0x00,             // mov   byte [ebp-0xA], 0      ; код ответа 6070
        0xE9, 0x43, 0x02, 0x00, 0x00        // jmp   0x54D1C8
    };

    // S10 — эпилог диспетчера ответов базы (приём 2332).
    const DWORD kSiteDbReply = 0x0043462B;
    const BYTE  kOrigDbReply[12] =
    {
        0xFF, 0x15, 0x28, 0x30, 0x58, 0x00, // call dword ptr [0x583028]
        0x2B, 0x85, 0xE0, 0xEF, 0xFF, 0xFF  // sub  eax, [ebp-0x1020]
    };

    // S6 — вход recvDBUserFameBitInfo (пролог 9 байт).
    const DWORD kSiteDbFame = 0x0054BD10;
    const BYTE  kOrigDbFame[14] =
    {
        0x55, 0x8B, 0xEC,                                           // push ebp; mov ebp,esp
        0x81, 0xEC, 0x84, 0x03, 0x00, 0x00,                         // sub  esp,0x384
        0xA1, 0xF0, 0x63, 0x5A, 0x00                                // mov  eax,[0x5A63F0] (куки)
    };

    // S7 — отправка 6066 в recvDBUserFameBitInfo.
    const DWORD kSiteSend6066 = 0x0054C027;
    const BYTE  kOrigSend6066[16] =
    {
        0x6A, 0x2A,                                                 // push 0x2A (длина 42) — @0x54C017
        0x68, 0xB2, 0x17, 0x00, 0x00,                               // push 0x17B2 (6066)
        0x8B, 0x85, 0x8C, 0xFC, 0xFF, 0xFF,                         // mov  eax,[ebp-0x374]
        0x8B, 0x48, 0x04                                            // mov  ecx,[eax+4]
    };
    const DWORD kSend6066CallVa = 0x0054C027;                       // сам `call sub_4C28F0`
    const BYTE  kOrigSend6066Call[5] = { 0xE8, 0xC4, 0x68, 0xF7, 0xFF };

    // S8 — вход recvDBUserOpenFameBitInfo.
    const DWORD kSiteDbOpen = 0x0054C430;
    const BYTE  kOrigDbOpen[12] =
    {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x60,                         // push ebp; mov ebp,esp; sub esp,0x60
        0x56, 0x57,                                                 // push esi; push edi
        0x89, 0x4D, 0xA0,                                           // mov  [ebp-0x60],ecx
        0xC7                                                        // mov  dword [ebp-0x54],0 (начало)
    };

    // S9 — отправка 6086 в recvDBUserOpenFameBitInfo.
    const DWORD kSiteSend6086 = 0x0054C532;
    const BYTE  kOrigSend6086[13] =
    {
        0x6A, 0x26,                                                 // push 0x26 (длина 38) — @0x54C525
        0x68, 0xC6, 0x17, 0x00, 0x00,                               // push 0x17C6 (6086)
        0x8B, 0x55, 0xA0,                                           // mov  edx,[ebp-0x60]
        0x8B, 0x4A, 0x04                                            // mov  ecx,[edx+4]
    };
    const BYTE  kOrigSend6086Call[5] = { 0xE8, 0xB9, 0x63, 0xF7, 0xFF };
}

// ═══════════════ ОБЩИЕ ТОЧКИ ДЛЯ ДРУГИХ ПАТЧЕЙ (закон port-shared-points) ════
//  P24 «снятие рейтингового звания» обязан спрашивать владение и слать маски
//  ТОЙ ЖЕ логикой, что и P21, иначе звания 256…511 разъедутся: их бит лежит не
//  в CUser, а в хвосте массива записей, о котором знает только этот файл.
//  Поэтому наружу отдаются три тонкие обёртки, а не копия кода.

// Владеет ли игрок званием titleId. Учитывает обе половины маски «получено».
// При выключенном P21 (хвоста нет) для id ≥ 256 честно возвращает false.
bool P21_FameOwned(void* pUser, int titleId)
{
    if (!pUser || titleId < 0) { return false; }
    if (titleId < kLowBits)
    {
        const unsigned __int64* m = (const unsigned __int64*)UserPtr(pUser, kOffMaskOwned);
        return (m[titleId / 64] & (1ULL << (titleId % 64))) != 0;
    }
    const BYTE* hi = HighOwned(pUser);
    return hi ? HiGet(hi, titleId) : false;
}

// Маска «получено» владельцу: 42 б в стоке, 74 б когда старшая половина жива.
void P21_SendFameMask6066(void* fameSelf, void* pUser, int userNum)
{
    SendMask6066(fameSelf, pUser, userNum);
}

// Маска «найдено» владельцу: 38 б в стоке, 70 б когда старшая половина жива.
void P21_SendFameMask6086(void* fameSelf, void* pUser, int userNum)
{
    SendMask6086(fameSelf, pUser, userNum);
}

PatchResult P21_TitleMask512()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_raiseCap   = Config::GetBool(kSec, L"RaiseFameInfoCap", true);
    g_allocTail  = Config::GetBool(kSec, L"AllocHighMaskTail", true);
    g_highBitOps = Config::GetBool(kSec, L"HighBitOps",        true);
    g_ext6066    = Config::GetBool(kSec, L"Extend6066",        true);
    g_ext6086    = Config::GetBool(kSec, L"Extend6086",        true);
    g_dbHigh     = Config::GetBool(kSec, L"DbHighExchange",    true);
    g_highFame   = Config::GetBool(kSec, L"HighFamePoints",    true);

    // Хранилище битов 256…511 живёт в хвосте массива записей — без него
    // ни операции, ни расширенные пакеты смысла не имеют.
    if (!g_allocTail && (g_highBitOps || g_ext6066 || g_ext6086 || g_dbHigh))
    {
        Log::Line(L"    P21: AllocHighMaskTail=0 ⇒ HighBitOps/Extend6066/Extend6086/DbHighExchange "
                  L"выключены (хранить биты 256…511 негде)");
        g_highBitOps = false; g_ext6066 = false; g_ext6086 = false; g_dbHigh = false;
    }

    // ── Сверка ВСЕХ площадок до единой записи ──────────────────────────────
    const Site sites[] =
    {
        { kSiteCap,       kOrigCap,       sizeof(kOrigCap)       },
        { kSiteAlloc,     kOrigAlloc,     sizeof(kOrigAlloc)     },
        { kSiteCheck,     kOrigCheck,     sizeof(kOrigCheck)     },
        { kSiteAdd,       kOrigAdd,       sizeof(kOrigAdd)       },
        { kSiteSub,       kOrigSub,       sizeof(kOrigSub)       },
        { kSiteWear,      kOrigWear,      sizeof(kOrigWear)      },
        { kSiteDel,       kOrigDel,       sizeof(kOrigDel)       },
        { kSiteDbFame,    kOrigDbFame,    sizeof(kOrigDbFame)    },
        { kSiteSend6066 - 16, kOrigSend6066, sizeof(kOrigSend6066) },
        { kSiteDbOpen,    kOrigDbOpen,    sizeof(kOrigDbOpen)    },
        { kSiteDbReply,   kOrigDbReply,   sizeof(kOrigDbReply)   },
        { kSiteSend6086 - 13, kOrigSend6086, sizeof(kOrigSend6086) },
    };
    if (!VerifyAllSites(L"P21", sites, ARRAYSIZE(sites)))
    {
        return PatchResult::Mismatch;
    }
    if (!Hook::Verify(kSend6066CallVa, kOrigSend6066Call, sizeof(kOrigSend6066Call)) ||
        !Hook::Verify(kSiteSend6086,   kOrigSend6086Call, sizeof(kOrigSend6086Call)))
    {
        Log::Line(L"    P21: ! команда `call sub_4C28F0` на площадке отправки не совпала");
        return PatchResult::Mismatch;
    }

    bool ok = true;

    // S1 — предел FameInfo.txt 256 → 512.
    if (g_raiseCap)
    {
        ok &= Hook::WriteBytes(kCapImmVa, kCapNew, sizeof(kCapNew));
        Log::Line(L"    P21: предел FameInfo.txt 256 → 512 (@%08X)", kCapImmVa);
    }

    // S2 — хвост 64 б под биты 256…511.
    if (g_allocTail)
    {
        ok &= Hook::WriteCall(kSiteAlloc, (const void*)&NewFameRecords, 5);
        Log::Line(L"    P21: массив записей званий выделяется с хвостом %d б (@%08X)",
                  kTailBytes, kSiteAlloc);
    }

    // S3…S5 — операции над битами 256…511.
    if (g_highBitOps)
    {
        ok &= Hook::WriteJmp(kSiteCheck, (const void*)&TrampCheck, 6);
        ok &= Hook::WriteJmp(kSiteAdd,   (const void*)&TrampAdd,   6);
        ok &= Hook::WriteJmp(kSiteSub,   (const void*)&TrampSub,   9);
        ok &= Hook::WriteJmp(kSiteWear,  (const void*)&TrampWear,  22);
        ok &= Hook::WriteJmp(kSiteDel,   (const void*)&TrampDel,   26);
        Log::Line(L"    P21: Check/Add/Sub FameBit понимают id 256…511 "
                  L"(@%08X, @%08X, @%08X); id < 256 идут стоковым кодом",
                  kSiteCheck, kSiteAdd, kSiteSub);
        Log::Line(L"    P21: гейты владения 6067 «надеть» (@%08X) и 6069 «удалить» (@%08X) "
                  L"понимают id 256…511", kSiteWear, kSiteDel);
    }

    // S6…S9 — чистка хвоста при загрузке персонажа и расширенные пакеты.
    if (g_ext6066)
    {
        ok &= Hook::WriteJmp(kSiteDbFame, (const void*)&TrampDbFame, 9);
        ok &= Hook::WriteCall(kSend6066CallVa, (const void*)&SendHook6066, 5);
        Log::Line(L"    P21: 6066 уходит расширенным (42 → 74 б), хвост чистится при загрузке (@%08X)",
                  kSiteDbFame);
    }
    if (g_ext6086)
    {
        ok &= Hook::WriteJmp(kSiteDbOpen, (const void*)&TrampDbOpenFame, 6);
        ok &= Hook::WriteCall(kSiteSend6086, (const void*)&SendHook6086, 5);
        Log::Line(L"    P21: 6086 уходит расширенным (38 → 70 б) (@%08X)", kSiteDbOpen);
    }

    // S10 — приём ответа 2332 с старшей половиной из базы.
    if (g_dbHigh)
    {
        ok &= Hook::WriteJmp(kSiteDbReply, (const void*)&TrampDbReply, 6);
        Log::Line(L"    P21: обмен с базой включён — 2330 «дай» при входе, 2331 «сохрани» "
                  L"при выдаче/снятии, приём 2332 (@%08X). Нужен патч DBManager P22 и SQL-миграция",
                  kSiteDbReply);
    }

    // Честное предупреждение в журнал: без правки базы биты 256…511 не переживают перезаход,
    // а без дорощенной FameInfo.txt звания 256…279 сервером вообще не существуют.
    if (!g_dbHigh)
    {
        Log::Line(L"    P21: ! обмен с базой выключен — биты 256…511 живут только до перезахода");
    }
    Log::Line(L"    P21: ! ConfigSet\\FameInfo.txt должен содержать не меньше 280 записей, "
              L"иначе гейт «id < count» отсечёт звания 256…279");

    return ok ? PatchResult::Applied : PatchResult::Failed;
}
