// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P24 — СНЯТИЕ РЕЙТИНГОВОГО ЗВАНИЯ У ПРЕЖНЕГО ЛИДЕРА.
//        ★ НАША ПРАВКА (починка дефекта оригинала), не перенос чужой.
//
//  Документ патча: AstoryServer/Docs/GameServer/fame-rating-revoke-p24.md
//  Связанное:      P21 (маска славы 512 бит) — общие точки берём у него,
//                  P23 (DBPatch.dll) — ОТПРАВИТЕЛЬ смены лидера и правка базы.
//
//  ── ЧТО СЛОМАНО В ОРИГИНАЛЕ ─────────────────────────────────────────────────
//  Рейтинговые звания — это пять записей FameInfo с `Group == 1`, id 65…69:
//  максимальный уровень на сервере / среди воинов / лучников / магов и «больше
//  всех золота». Выдаёт их приёмник межсерверных опкодов 3404…3408
//  `sub_54D710@0x54D710` (вызов из `ConnectSocketMsgProcess@0x42FAB0`,
//  ветки `case 0xD4C…0xD51`). Тело пакета: заголовок 9 байт + N записей по 13:
//      +0 значение i32 · +4 UserIndex i32 · +8 userNum i16 (+2 б мусора) · +12 флаг i8
//  ★ ПОЛЕ +4 — ЭТО UserIndex (индекс аккаунта, CUser+0x174), а НЕ charId.
//    Доказано строками журнала самого сервера: «ServerUserIndex=%d»,
//    «BaseUserIndex=%d ServerUserIndex=%d BaseCharIndex=%d ServerCharIndex=%d»
//    с аргументом *(DWORD*)(pUser+372); индекс персонажа лежит рядом, CUser+396.
//    В документе P21 это поле названо charId — МИСНЕЙМ, поле одно и то же.
//    На поиск это не влияет: у аккаунта в игре одновременно одна сессия.
//  Число записей считается как `(len - 10) / 13`, остаток обязан быть нулём.
//  На каждую запись вызывается `AddFameBit@0x54A980` + `sub_54A7D0` (нотис 6065).
//
//  ★★★ СНЯТИЯ У ПРЕЖНЕГО ЛИДЕРА В ОРИГИНАЛЕ НЕТ ВООБЩЕ.
//  Единственный вызов `SubFameBit@0x54AD00` идёт из `DeleteFameInfo@0x54CE30`
//  по КЛИЕНТСКОМУ пакету 6069 «удалить звание», а звание с `Group == 1` клиент
//  удалять не даёт (`questItem_ValidateSelection@0xE99C30`, нотис 2428). То есть
//  выданное рейтинговое звание оставалось у игрока НАВСЕГДА, и «максимальный
//  уровень на сервере» со временем носили бы все, кто когда-либо был первым.
//  Это дефект оригинала — чиним и помечаем (закон fix-original-defects).
//
//  Дефектов на самом деле ЧЕТЫРЕ, и все четыре лечатся здесь:
//   D1. снятия нет вовсе (см. выше);
//   D2. `sub_54D710` при первой же ненайденной сессии делает НЕ `continue`,
//       а ВЫХОД ИЗ ВСЕГО ПАКЕТА (`0x54D875` и `0x54D897` уходят на `0x54D950`),
//       поэтому один офлайн-игрок в списке съедал бы выдачу всем остальным;
//   D3. `SubFameBit` НЕ шлёт клиенту ничего: ни маску 6066, ни маску «найдено»
//       6086 (хотя бит «найдено» взводит и в базу 2266 отправляет). Маска 6066
//       уходит клиенту РОВНО В ОДНОМ месте — `recvDBUserFameBitInfo@0x54BD10`,
//       то есть только при входе персонажа в игру. Без правки снятое звание
//       осталось бы у клиента до перезахода;
//   D4. `DeleteFameInfo`, снимая НАДЕТОЕ звание, обнуляет активный слот и шлёт
//       в базу 2258, но НЕ рассылает 6068 — плашка над головой у окружающих
//       (и у самого игрока) продолжает показывать снятое звание.
//
//  ── КТО ИНИЦИИРУЕТ СНЯТИЕ И ПОЧЕМУ ИМЕННО ТАК ───────────────────────────────
//  Инициатор — ОТПРАВИТЕЛЬ (патч P23 в DBPatch.dll), а не этот приёмник.
//  Доводы (каждый сам по себе решающий):
//   1. GameServer НЕ ЗНАЕТ прежнего держателя. Ни одного поля «текущий владелец
//      звания 65…69» в образе нет: сплошной поиск по тракту славы дал только
//      маски на игрока (CUser+0x17DDC / +0x17E00) и таблицу FameInfo — записи
//      «кто носит» нет ни в CUser, ни в глобальных 0x7DFFD4/0x7DFFD8.
//   2. Прежний держатель может быть ОФЛАЙН или сидеть на ДРУГОМ процессе
//      (Indun_GameServer, соседний канал). У этого процесса его CUser нет,
//      а значит нет ни маски, ни способа её изменить.
//   3. Маска хранится в БАЗЕ (dbo.CharFameBank, процедуры UPCharFameBankUp /
//      UPCharFameProgressUp). Единственный, кто может снять звание у офлайнового
//      игрока, — сторона базы. Она же ведёт `dbo.FameRatingHolder` и потому уже
//      знает и прежнего, и нового держателя. Просить GameServer «найти прежнего»
//      значило бы делать ту же работу второй раз и хуже.
//  ⇒ Разделение ответственности:
//      P23 (DBPatch): пишет базу ВСЕГДА (и новому, и прежнему — снятие и выдача),
//                     затем шлёт 3404…3408 всем подключённым GameServer'ам
//                     ради ЖИВЫХ СЕССИЙ;
//      P24 (здесь):   применяет присланное к тем, кто сейчас онлайн ЗДЕСЬ, и
//                     доводит до клиента немедленно.
//  Порядок безразличен, операция идемпотентна: снятие у уже снятого — тихий
//  выход, а SubFameBit со своей стороны тоже отправит в базу 2256/2257.
//
//  ── КАК ОТЛИЧИТЬ «ВЫДАТЬ» ОТ «СНЯТЬ» ────────────────────────────────────────
//  ★ Новых опкодов НЕ ЗАВОДИМ. В записи 13 байт уже есть ФЛАГОВЫЙ БАЙТ (+12),
//  который сток читает и никуда не девает:
//      0054D859  8A4A0C   mov cl, byte ptr [edx+0xC]
//      0054D85C  884DD4   mov byte ptr [ebp-0x2C], cl      ; и БОЛЬШЕ НИГДЕ
//  Проверено сплошным дизассемблированием всей функции 0x54D710…0x54D960:
//  обращений к [ebp-0x2C] на чтение НЕТ. Байт мёртв, отправителя у этих опкодов
//  в оригинале не существует вовсе (сплошной поиск 3404…3408 по DBManager.exe,
//  LoginManager.exe, NpcServer.exe, ItemRelayServer.exe — ни одной отправки),
//  поэтому назначить ему смысл ничего не ломает:
//      флаг 0 — ВЫДАТЬ (стоковое поведение, байт в байт)
//      флаг 1 — СНЯТЬ
//  Плюс такого решения: снятие у прежнего и выдача новому едут ОДНИМ пакетом,
//  в одном порядке, без нового опкода и без второй площадки в диспетчере
//  (её эпилог 0x43462B уже занят P21 — приёмом ответа 2332).
//
//  ── userNum ОТПРАВИТЕЛЮ ЗНАТЬ НЕОБЯЗАТЕЛЬНО ─────────────────────────────────
//  `UserIndex (i32) ≠ userNum (i16)`: userNum — это НОМЕР ЖИВОЙ СЕССИИ, он свой
//  у каждого GameServer и меняется при каждом входе. Сторона базы его знать не
//  обязана. Поэтому приёмник умеет искать игрока САМ, по UserIndex:
//  таблица сессий — `менеджер + 0x40 + 4*userNum` (сверено в `sub_5324A0`
//  @0x5324CC `cmp dword [edx+ecx*4+0x40],0`), предел 0x226 = 550
//  (`sub_5328F0` @0x5328FF `cmp ecx,0x226`; совпадает с cap 550 LoginManager).
//  Договор: `userNum = 0xFFFF` — «не знаю, ищи сам». Любое другое значение
//  сначала пробуется как подсказка и принимается, только если UserIndex совпал.
//
//  ── ЧЕМ КОНЧАЕТСЯ СНЯТИЕ (КОНТРАКТ ПАКЕТОВ ДЛЯ КЛИЕНТСКОЙ СТОРОНЫ) ──────────
//  Порядок фиксирован, ровно такой (при `Enabled=1` и всех ключах по умолчанию):
//    1. 2256 (82 б) в базу  — маска «получено» без снятого бита   [из SubFameBit]
//    2. 2257 (54 б) в базу  — обнулённая запись звания            [из SubFameBit]
//    3. 2266 (40 б) в базу  — маска «найдено», если бит взведён    [из SubFameBit]
//       (при id ≥ 256 вместо 1…3 уходит 2331 патча P21 — там маска другая)
//    4. 2258 (12 б) в базу  — активные слоты, ТОЛЬКО если звание было надето
//    5. 6068 (14 б) ВЛАДЕЛЬЦУ  — новые активные слоты (плашка), только если надето
//    6. 6068 (14 б) ОКРУЖАЮЩИМ (сектор, без себя) — то же самое
//    7. 6066 (42 или 74 б) ВЛАДЕЛЬЦУ — полная маска «получено»
//    8. 6086 (38 или 70 б) ВЛАДЕЛЬЦУ — полная маска «найдено»
//    9. 6070 (13 б) ВЛАДЕЛЬЦУ — «звание удалено», код 1
//  Тела:
//    6068: [0] i16 userNum · [2] i32 UserIndex · [6] i32 CUser+0x17DD4 ·
//          [10] i16 активный слот 0 · [12] i16 активный слот 1
//    6070: [0] i16 userNum · [2] i32 UserIndex · [6] i8 код (1 = удалено) ·
//          [7] i16 id звания · [9] i32 очки славы (CUser+0x17DD0)
//    6066/6086 — как в P21 (старая часть на месте, +32 б в хвост при id ≥ 256).
//
//  ── ПОЧЕМУ СНЯТИЕ ДОЕЗЖАЕТ БЕЗ ОТКРЫТИЯ ОКНА 18700 ──────────────────────────
//  Все девять пакетов уходят САМИ, по приходу 3404…3408, а не в ответ на запрос
//  клиента. Живой (НЕ обновлённый) клиент их уже понимает:
//    0x17B2 (6066) → netOnCharEquipUpdate@0xE9A6F0   — пишет маску;
//    0x17B4 (6068) → charTitle_RecvTitleSlotUpdate   — обновляет плашку;
//    0x17B6 (6070) → обработчик @0xE9BE80: при коде 1 снимает бит и правит очки
//                    БЕЗУСЛОВНО, а перерисовку списка делает только если окно
//                    открыто (`if (*(_BYTE *)(*(this+1)+292))`) —
//                    ★ то есть маска у клиента чинится и при ЗАКРЫТОМ окне;
//    0x17C6 (6086) → netHandler_OnCharData32@0xE9A7D0 — маска «найдено».
//  Все четыре разобраны в диспетчере безусловно, гейта «окно открыто» на входе
//  нет. Перерисовка окна/плашки/уведомление — зона клиентского агента.
//
//  ── ДИФ С ЖИВЫМ ОБРАЗОМ (закон gameserver-decompile-stale) ──────────────────
//  Сверены RE/ida/server_work/GameServer.exe (MD5 68BA5176 2209007B 8AB47260
//  C92480D0) и живой GameServer\GameServer.exe (MD5 E7B4AC38 E8328AAA 847BBD9B
//  F261BB01), оба 1 740 800 б: 218 байт в 52 участках. НИ ОДИН не попадает в
//  зоны этого патча (0x54D710…0x54D980 приёмник, 0x54AD00…0x54B260 SubFameBit,
//  0x54C820…0x54D210 ChangeActiveFame/DeleteFameInfo/sub_54D210,
//  0x5324A0…0x532560, 0x52E630…0x52E730, 0x4C28F0, 0x5646C0) — расхождений НОЛЬ.
//  Скрипт: scratchpad/p24/diffzone.py, дизассемблер площадок: scratchpad/p24/gsdis.py.
//  Байты обеих площадок ниже (kOrigResolve / kOrigApply) сняты с ЖИВОГО образа.
//
//  ── ЧЕГО ПАТЧ НЕ ДЕЛАЕТ ─────────────────────────────────────────────────────
//  1. Не снимает звание у ОФЛАЙНОВОГО игрока и не ходит в базу за него: у него
//     нет CUser, а все DB-пакеты славы адресуются живой сессией (userNum) и несут
//     маску, которой у процесса нет. Это структурно зона базы — патч P23.
//     Когда такой игрок войдёт, `recvDBUserFameBitInfo` пришлёт ему уже
//     урезанную маску — штатным стоковым путём.
//  2. Не заводит и не ведёт таблицу держателей — это тоже P23 (dbo.FameRatingHolder).
//  3. Не трогает Indun_GameServer (решение владельца от 2026-08-04).
//  4. Не меняет ветку опкода 3409 (0xD51) — она про поле CUser+0x17DD4 и рассылку
//     6078, к званиям отношения не имеет; флаг записи в ней по-прежнему не читается.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Config.h"
#include "Hook.h"
#include "Log.h"

namespace
{
    const wchar_t* kSec = L"P24_FameRatingRevoke";

    // ── Ключи ini (каждая часть — свой ключ) ────────────────────────────────
    bool g_resolveByUserIdx = true;   // искать игрока по UserIndex + не рвать пакет (D2)
    bool g_revokeOnFlag    = true;   // флаг записи 1 = снять звание (D1)
    bool g_clearActive     = true;   // снять надетое звание и его бонусы (штрих 1)
    bool g_broadcastPlate  = true;   // разослать 6068 себе и окружающим (штрих 2, D4)
    bool g_pushMask        = true;   // отправить владельцу 6066/6086 (штрих 3, D3)
    bool g_notify6070      = true;   // отправить владельцу 6070 «звание удалено»
    bool g_logRecv         = true;   // ★ диагностика прихода 3404…3409 в Log_Title

    // ── Константы образа (ЖИВОЙ GameServer.exe, MD5 E7B4AC38…) ─────────────
    constexpr DWORD kVaFameCount    = 0x007DFFD4;  // i32 — число записей FameInfo

    constexpr DWORD kOffUserIndex   = 0x00174;     // CUser: UserIndex i32 (индекс аккаунта)
    constexpr DWORD kOffName        = 0x00178;     // CUser: имя персонажа (лог @0x54AA52)
    constexpr DWORD kOffCharIdx     = 0x0018C;     // CUser: слот персонажа i8 (sub_532530 @0x53255D)
    constexpr DWORD kOffFamePoint   = 0x17DD0;     // CUser: очки славы i32 (тело 6070)
    constexpr DWORD kOffRankValue   = 0x17DD4;     // CUser: значение опкода 3409 (тело 6068)
    constexpr DWORD kOffActiveSlot  = 0x17E20;     // CUser: активное звание, шаг 38 б, 2 слота
    constexpr int   kActiveStride   = 38;          // слот: i16 id + 6 троек по 6 б
    constexpr int   kActiveCount    = 2;           // слотов ровно два (сток: `for i<2`)

    constexpr int   kUserSlotBase   = 0x40;        // менеджер: таблица сессий, шаг 4 б
    constexpr int   kUserSlotMax    = 0x226;       // предел userNum (sub_5328F0 @0x5328FF)
    constexpr int   kUserNumUnknown = 0xFFFF;      // договор: «userNum не знаю, ищи по UserIndex»

    constexpr int   kOp6068         = 0x17B4;      // активные слоты (плашка)
    constexpr int   kOp6070         = 0x17B6;      // результат удаления звания
    constexpr int   kBody6068       = 14;
    constexpr int   kBody6070       = 13;
    constexpr int   kOpDb2258       = 2258;        // активные слоты -> база
    constexpr int   kBodyDb2258     = 12;

    // ── Функции образа, которые мы зовём (все адреса сверены с ЖИВЫМ образом) ─
    typedef void*  (__fastcall *PFN_GetUser)   (void* self, void* edx, int userNum);        // sub_5324A0
    typedef int    (__fastcall *PFN_GetCharId) (void* self, void* edx, int userNum);        // sub_5324F0
    typedef char   (__fastcall *PFN_GetCharIdx)(void* self, void* edx, int userNum);        // sub_532530
    typedef char   (__fastcall *PFN_GetGroup)  (void* self, void* edx);                     // sub_4A7EA0
    typedef short  (__fastcall *PFN_GetSendId) (void* self, void* edx);                     // sub_4C0A30
    typedef char   (__fastcall *PFN_SubFame)   (void* self, void* edx, int userNum, int id); // sub_54AD00
    typedef int    (__fastcall *PFN_SendToUser)(void* self, void* edx, int op, int len,
                                                int userNum, void* body, int a5, int a6);   // sub_4C28F0
    typedef int    (__fastcall *PFN_SendOther) (void* self, void* edx, int userNum, int op,
                                                int len, void* body, int a6);               // sub_52E6D0
    typedef int    (__fastcall *PFN_SendDb)    (void* self, void* edx, int op, int len,
                                                int sendId, void* body, int userNum);       // sub_5646C0
    typedef int    (__fastcall *PFN_TitleBonus)(void* self, void* edx, int userNum, int stat,
                                                int val, int a5, int apply);                // sub_54D210

    PFN_GetUser    const pGetUser    = (PFN_GetUser)    0x005324A0;
    PFN_GetCharId  const pGetCharId  = (PFN_GetCharId)  0x005324F0;
    PFN_GetCharIdx const pGetCharIdx = (PFN_GetCharIdx) 0x00532530;
    PFN_GetGroup   const pGetGroup   = (PFN_GetGroup)   0x004A7EA0;
    PFN_GetSendId  const pGetSendId  = (PFN_GetSendId)  0x004C0A30;
    PFN_SubFame    const pSubFameBit = (PFN_SubFame)    0x0054AD00;
    PFN_SendToUser const pSendToUser = (PFN_SendToUser) 0x004C28F0;
    PFN_SendOther  const pSendOther  = (PFN_SendOther)  0x0052E6D0;
    PFN_SendDb     const pSendDb     = (PFN_SendDb)     0x005646C0;
    PFN_TitleBonus const pTitleBonus = (PFN_TitleBonus) 0x0054D210;

    void* const kGroupThis = (void*)0x0060AD18;   // ecx у sub_4A7EA0 (сверено @0x54CD7A)
    void* const kDbMgr     = (void*)0x007E0538;   // ecx у sub_5646C0 (сверено @0x54ACA6)

    // ── Смещения кадра sub_54D710 (сверены с ЖИВЫМ образом) ────────────────
    //  ⚠ Закон msvc-inline-asm-offsets: числа для `__asm` — ТОЛЬКО через #define
    //    (C++-константа в квадратных скобках подставляет её АДРЕС).
    //    Ими же пользуется C-код, читающий кадр по указателю hostEbp.
    #define F_ACTIVE_ID   0x20   /* [ebp-0x20] i16 : id звания (65…69) или 0xD51 */
    #define F_USER        0x24   /* [ebp-0x24] ptr : CUser* текущей записи        */
    #define F_RECCOUNT    0x28   /* [ebp-0x28] i16 : число записей в пакете       */
    #define F_FLAG        0x2C   /* [ebp-0x2C] i8  : флаг записи (мёртвый в стоке)*/
    #define F_UNUM        0x30   /* [ebp-0x30] i32 : слово 0 = userNum, слово 1 = резерв */
    #define F_USERIDX     0x34   /* [ebp-0x34] i32 : UserIndex записи             */
    #define F_VALUE       0x38   /* [ebp-0x38] i32 : значение записи              */
    #define F_INDEX       0x3C   /* [ebp-0x3C] i32 : счётчик цикла по записям     */
    #define F_THIS        0x40   /* [ebp-0x40] ptr : менеджер пользователей       */

    inline BYTE* UserPtr(void* u, DWORD off) { return (BYTE*)u + off; }
    inline int   FameCount()                 { return *(int*)kVaFameCount; }

    // ── ★ ДИАГНОСТИКА В ШТАТНЫЙ ЖУРНАЛ СЕРВЕРА ─────────────────────────────
    //  `sub_569DF0(канал, формат, ...)` — __cdecl, стек чистит вызывающий
    //  (сверено @0x54AA60: `push 0x19; call 0x569DF0; add esp,0x30`).
    //  Канал 25 (0x19) — это `Log/Log_Title/Title_ГГГГММДД.txt`, тот самый файл,
    //  где AddFameBit печатает «Add Before/After Title». Кладём диагностику ТУДА
    //  же: рядом с результатом, с меткой времени, и без своей инфраструктуры.
    //  ⚠ Строки ТОЛЬКО ASCII: файл пишется как есть, а .cpp собирается с /utf-8 —
    //    кириллица легла бы в журнал мусором. Поэтому здесь транслит.
    typedef int (__cdecl *PFN_SrvLog)(int channel, const char* fmt, ...);
    PFN_SrvLog const pSrvLog = (PFN_SrvLog)0x00569DF0;
    constexpr int kLogTitle = 25;                 // канал Log_Title

    // Активный слот i: i16 id, дальше шесть троек (i16 стат, i16 A, i16 B).
    inline short* ActiveSlot(void* pUser, int i)
    {
        return (short*)UserPtr(pUser, kOffActiveSlot + kActiveStride * i);
    }

    // ── Поиск живой сессии ──────────────────────────────────────────────────
    //   Таблица сессий: менеджер + 0x40 + 4*userNum (sub_5324A0 @0x5324CC),
    //   предел 0x226 = 550 (sub_5328F0 @0x5328FF).
    //
    //   ★★★ ПОЧЕМУ ОДНОГО UserIndex МАЛО (живой прогон 30.08).
    //   UserIndex — это индекс АККАУНТА, а не персонажа. На живом сервере в
    //   18:20:14 вошёл `GM_Rimy`, а в 18:21:02 — `ADM_sitxovski`, и у ОБОИХ
    //   UserIndex = 2 (журнал Log_Title: «RecvDB 2, GM_Rimy» и «RecvDB 2,
    //   ADM_sitxovski», логин-журнал: у обоих `UserID Rimy`). Поиск по одному
    //   UserIndex в такой момент неоднозначен и может вернуть НЕ ТОГО персонажа.
    //   Поэтому сверяем ещё и слот персонажа (CUser+0x18C, sub_532530 @0x53255D).
    struct SessionScan
    {
        void* pExact;      // совпал UserIndex И слот персонажа
        WORD  numExact;
        void* pLoose;      // совпал только UserIndex (первый попавшийся)
        WORD  numLoose;
        int   nOnline;     // всего живых сессий
        int   nSameUser;   // из них с этим UserIndex
    };

    void ScanSessions(void* mgr, int userIndex, int charIdx, SessionScan* out)
    {
        out->pExact = nullptr; out->numExact = 0;
        out->pLoose = nullptr; out->numLoose = 0;
        out->nOnline = 0; out->nSameUser = 0;
        if (!mgr) { return; }
        BYTE** tab = (BYTE**)((BYTE*)mgr + kUserSlotBase);
        for (int i = 0; i < kUserSlotMax; ++i)
        {
            BYTE* p = tab[i];
            if (!p) { continue; }
            ++out->nOnline;
            if (*(int*)UserPtr(p, kOffUserIndex) != userIndex) { continue; }
            ++out->nSameUser;
            if (!out->pLoose) { out->pLoose = p; out->numLoose = (WORD)i; }
            if (charIdx >= 0 && *(BYTE*)UserPtr(p, kOffCharIdx) == (BYTE)charIdx && !out->pExact)
            {
                out->pExact = p; out->numExact = (WORD)i;
            }
        }
    }

    // ── Отправка 6068 «активные звания» (плашка над головой) ────────────────
    //   Тело и оба адресата — дословно как в ChangeActiveFame@0x54CD15…0x54CD6D.
    void SendActiveTitles6068(void* mgr, void* pUser, int userNum)
    {
        void* sender = *(void**)((BYTE*)mgr + 4);
        if (!sender) { return; }
        BYTE body[kBody6068] = {};
        *(short*)&body[0]  = (short)userNum;
        *(int*)  &body[2]  = pGetCharId(mgr, nullptr, userNum);
        *(int*)  &body[6]  = *(int*)UserPtr(pUser, kOffRankValue);
        for (int i = 0; i < kActiveCount; ++i)
        {
            *(short*)&body[10 + 2 * i] = *ActiveSlot(pUser, i);
        }
        pSendToUser(sender, nullptr, kOp6068, kBody6068, userNum, body, 0, 1); // себе
        pSendOther (mgr,    nullptr, userNum, kOp6068, kBody6068, body, 1);    // окружающим
    }

    // ── Отправка 2258 «активные звания» в базу ──────────────────────────────
    //   Тело — дословно как в DeleteFameInfo@0x54D0xx / ChangeActiveFame.
    void SendActiveTitlesToDb(void* mgr, void* pUser, int userNum)
    {
        void* sender = *(void**)((BYTE*)mgr + 4);
        if (!sender) { return; }
        BYTE body[kBodyDb2258] = {};
        *(short*)&body[0] = (short)userNum;
        *(int*)  &body[2] = pGetCharId(mgr, nullptr, userNum);
        body[6] = (BYTE)pGetCharIdx(mgr, nullptr, userNum);
        body[7] = (BYTE)pGetGroup(kGroupThis, nullptr);
        for (int i = 0; i < kActiveCount; ++i)
        {
            *(short*)&body[8 + 2 * i] = *ActiveSlot(pUser, i);
        }
        pSendDb(kDbMgr, nullptr, kOpDb2258, kBodyDb2258,
                pGetSendId(sender, nullptr), body, userNum);
    }

    // ── Отправка 6070 «звание удалено» ──────────────────────────────────────
    //   Код 1 — клиент снимает бит и правит очки БЕЗУСЛОВНО, окно может быть закрыто.
    void SendDeleteNotice6070(void* mgr, void* pUser, int userNum, int titleId)
    {
        void* sender = *(void**)((BYTE*)mgr + 4);
        if (!sender) { return; }
        BYTE body[kBody6070] = {};
        *(short*)&body[0] = (short)userNum;
        *(int*)  &body[2] = pGetCharId(mgr, nullptr, userNum);
        body[6]           = 1;                       // код «удалено»
        *(short*)&body[7] = (short)titleId;
        *(int*)  &body[9] = *(int*)UserPtr(pUser, kOffFamePoint);
        pSendToUser(sender, nullptr, kOp6070, kBody6070, userNum, body, 0, 1);
    }

    // ═══════════════════ САМО СНЯТИЕ ════════════════════════════════════════
    //  Вызывается из трамплина внутри sub_54D710. Мы уже в диспетчере пакетов,
    //  то есть ровно там, где стоковый код и сам шлёт 2256/6065 — отложенного
    //  тика не нужно, повторного входа в сеть не возникает (закон
    //  no-reentrant-net-callbacks соблюдён: ни одна из вызываемых функций не
    //  читает сокет и не возвращается в диспетчер).
    void __cdecl RevokeFameTitle(void* mgr, void* pUser, int userNum, int titleId)
    {
        if (!mgr || !pUser) { return; }
        if (titleId < 0 || titleId >= FameCount()) { return; }

        // Не владеет — тихий выход. Снятие обязано быть идемпотентным: базу мог
        // уже поправить P23, а пакет прийти следом.
        if (!P21_FameOwned(pUser, titleId))
        {
            Log::Line(L"    P24: звание %d у сессии %d уже снято — пропуск", titleId, userNum);
            return;
        }

        // 1. Бит, очки, запись + сохранение в базу (2256/2257/2266; при id ≥ 256
        //    сработает трамплин P21 и уйдёт 2331).
        pSubFameBit(mgr, nullptr, userNum, titleId);

        // 2. Штрих 1 — надетое звание. Дословно ветка DeleteFameInfo@0x54CFF0:
        //    снять бонусы (sub_54D210 с признаком 0), обнулить тройки, слот = -1.
        bool worn = false;
        if (g_clearActive)
        {
            for (int i = 0; i < kActiveCount; ++i)
            {
                short* slot = ActiveSlot(pUser, i);
                if (*slot != (short)titleId) { continue; }
                *slot = -1;
                for (int j = 0; j < 6; ++j)
                {
                    short* tr = slot + 1 + 3 * j;          // тройка j: +2 + 6*j
                    pTitleBonus(mgr, nullptr, userNum, tr[0], tr[1], tr[2], 0);
                    tr[0] = -1; tr[1] = 0; tr[2] = 0;
                }
                worn = true;
            }
            if (worn) { SendActiveTitlesToDb(mgr, pUser, userNum); }
        }

        // 3. Штрих 2 — плашка над головой у себя и у окружающих (дефект D4:
        //    стоковый DeleteFameInfo этого не делает вовсе).
        if (worn && g_broadcastPlate) { SendActiveTitles6068(mgr, pUser, userNum); }

        // 4. Штрих 3 — маски владельцу немедленно (дефект D3: в стоке 6066
        //    уходит ТОЛЬКО при входе в игру).
        if (g_pushMask)
        {
            P21_SendFameMask6066(mgr, pUser, userNum);
            P21_SendFameMask6086(mgr, pUser, userNum);
        }
        if (g_notify6070) { SendDeleteNotice6070(mgr, pUser, userNum, titleId); }

        Log::Line(L"    P24: звание %d СНЯТО у сессии %d%s", titleId, userNum,
                  worn ? L" (было надето — плашка обновлена)" : L"");
    }

    // ── Разбор одной записи пакета: кто это и что с ним делать ─────────────
    //   Читаем кадр вызывающей функции по указателю hostEbp — так же, как
    //   P21 читает кадр диспетчера в OnDbHighReply. Возвращаем CUser* или 0.
    //   Найденный userNum пишем в кадр ([ebp-0x30], слово 0), чтобы дальше вся
    //   функция — и ветка выдачи, и ветка 3409 — работала с ПРАВИЛЬНЫМ номером
    //   сессии, а не с подсказкой отправителя.
    //
    //   Порядок разбора (от надёжного к запасному):
    //     1) точное совпадение UserIndex + слот персонажа;
    //     2) подсказка userNum из пакета — принимается, только если UserIndex
    //        совпал И (слот не задан ИЛИ слот совпал);
    //     3) совпадение по одному UserIndex — только когда слот НЕ задан.
    //   ★ Если слот задан, а точного совпадения нет, мы НЕ применяем запись:
    //     лучше пропустить, чем выдать звание не тому персонажу аккаунта.
    //
    //   Слот персонажа берём из ДВУХ «резервных» байт записи (+10…+11), которые
    //   сток читает в старшее слово [ebp-0x30] и никогда не использует.
    //   Договор с отправителем (P23): 0 — «слот не задан» (сегодняшнее
    //   поведение, отправитель кладёт туда нули), иначе Charidx + 1.
    void* __cdecl ResolveFameUser(void* mgr, void* pUserHint, BYTE* hostEbp)
    {
        const int  titleId   = *(short*)(hostEbp - F_ACTIVE_ID);
        const int  value     = *(int*)  (hostEbp - F_VALUE);
        const int  userIndex = *(int*)  (hostEbp - F_USERIDX);
        WORD*      pUserNum  = (WORD*)  (hostEbp - F_UNUM);
        const WORD slotRaw   = *(WORD*) (hostEbp - F_UNUM + 2);   // «резерв» записи
        const BYTE flag      = *(BYTE*) (hostEbp - F_FLAG);
        const int  recNo     = *(int*)  (hostEbp - F_INDEX);
        // 0 — слот не задан; иначе отправитель прислал Charidx + 1.
        const int  charIdx   = (slotRaw == 0 || slotRaw == 0xFFFF) ? -1 : (int)slotRaw - 1;

        SessionScan sc;
        ScanSessions(mgr, userIndex, charIdx, &sc);

        void*       found = nullptr;
        const char* how   = "no";
        if (sc.pExact)
        {
            found = sc.pExact; *pUserNum = sc.numExact; how = "exact";
        }
        else if (pUserHint && *(int*)UserPtr(pUserHint, kOffUserIndex) == userIndex &&
                 (charIdx < 0 || *(BYTE*)UserPtr(pUserHint, kOffCharIdx) == (BYTE)charIdx))
        {
            found = pUserHint; how = "hint";          // userNum из пакета уже верный
        }
        else if (charIdx < 0 && g_resolveByUserIdx && sc.pLoose)
        {
            found = sc.pLoose; *pUserNum = sc.numLoose; how = "userIdx";
        }
        else if (!g_resolveByUserIdx)
        {
            how = "off";                              // поиск выключен ключом ini
        }

        if (g_logRecv)
        {
            pSrvLog(kLogTitle,
                    "\tP24\tREC #%d\ttitle=%d\tflag=%d\tuserIdx=%d\tslotRaw=%d\tuserNum=%d\tval=%d"
                    "\t-> %s\tuserNum=%d\tname=%s\tslot=%d\t(online=%d sameUserIdx=%d)",
                    recNo, titleId, (int)flag, userIndex, (int)slotRaw, (int)*pUserNum, value,
                    how, found ? (int)*pUserNum : -1,
                    found ? (const char*)UserPtr(found, kOffName) : "-",
                    found ? (int)*(BYTE*)UserPtr(found, kOffCharIdx) : -1,
                    sc.nOnline, sc.nSameUser);
        }
        return found;
    }

    // ── ★ Приход пакета 3404…3409: пишем ДО всех гейтов ─────────────────────
    //   Ставится на ВХОДЕ sub_54D710, поэтому строка появляется даже когда
    //   пакет отбивается проверкой длины `(len-10) % 13` или опкодом.
    //   Именно молчание этого места скрывало дефект: в журнале не было ничего.
    void __cdecl OnRatingPacket(int op, int len, BYTE* pkt)
    {
        if (!g_logRecv) { return; }
        const int n   = (len - 10) / 13;
        const int rem = (len - 10) % 13;
        pSrvLog(kLogTitle, "\tP24\tRECV\top=%d\tlen=%d\tN=%d\trem=%d\tpkt=%s",
                op, len, n, rem, pkt ? "yes" : "null");
    }

    // ═══════════════════ ТРАМПЛИНЫ ══════════════════════════════════════════
    //  Оба стоят ВНУТРИ тела цикла sub_54D710 и работают с кадром вызывающей
    //  функции, поэтому ebp трогать нельзя (заходим по jmp, а не по call).
    //  ⚠ Смещения кадра — через #define, объявлены выше (закон
    //  msvc-inline-asm-offsets).

    // Адреса возврата — переменные, а не константы: naked-ассемблер MSVC умеет
    // только `jmp [метка]` с косвенностью через память.
    DWORD g_contLoop     = 0x0054D825;   // `i++` — следующая запись пакета
    DWORD g_afterIdCheck = 0x0054D8AB;   // сразу ЗА стоковой проверкой UserIndex
    DWORD g_contApply    = 0x0054D93C;   // `jmp 0x54D825` — конец тела цикла
    DWORD g_addFameBit   = 0x0054A980;   // AddFameBit  (перехвачен P21 при id ≥ 256)
    DWORD g_fameNotice   = 0x0054A7D0;   // нотис 6065 «звание получено»

    // ── Площадка A @0x54D86F (60 б): «сессии нет» + «UserIndex не тот» → выход ─
    //   Стоковые байты: два одинаковых блока, каждый ставит [ebp-4] = -1,
    //   зовёт деструктор объекта кадра и уходит на 0x54D950 (ВЫХОД ИЗ ПАКЕТА).
    //   Мы заменяем оба на «найти игрока; не нашли — следующая запись».
    __declspec(naked) void TrampResolveUser()
    {
        __asm
        {
            push  ebp                           // кадр sub_54D710 целиком
            push  dword ptr [ebp - F_USER]      // CUser* по подсказке (может быть 0)
            push  dword ptr [ebp - F_THIS]      // менеджер пользователей
            call  ResolveFameUser
            add   esp, 12
            test  eax, eax
            je    Skip
            mov   dword ptr [ebp - F_USER], eax // сток дальше читает именно её
            jmp   [g_afterIdCheck]
        Skip:
            jmp   [g_contLoop]                  // не онлайн ЗДЕСЬ — не наша запись
        }
    }

    // Лог решения «выдать». Если следом в журнале НЕТ «Add Before Title» —
    // значит отказал уже сам AddFameBit (его гейты: id < числа записей
    // FameInfo и sub_5324A0(userNum) != 0).
    void __cdecl OnGrantRecord(int titleId, int userNum)
    {
        pSrvLog(kLogTitle, "	P24	GRANT	title=%d	userNum=%d", titleId, userNum);
    }

    // ── Площадка C @0x54D710 (5 б): ВХОД приёмника ──────────────────────────
    //   Пишем строку ДО всех гейтов функции. Вытесняются ровно первые 5 байт
    //   пролога `push ebp; mov ebp,esp; push -1` — их и доигрываем.
    //   Кадр на момент трамплина: [ebp+8] a2 опкод, [ebp+0xC] a3 длина,
    //   [ebp+0x10] a4 указатель на пакет (сверено с местом вызова @0x54D71E).
    DWORD g_enterBack = 0x0054D715;   // за вытесненными пятью байтами

    __declspec(naked) void TrampEnterRecv()
    {
        __asm
        {
            push  ebp
            mov   ebp, esp
            pushad
            push  dword ptr [ebp+0x10]        // a4 — указатель на пакет
            movsx eax, word ptr [ebp+0x0C]
            push  eax                         // a3 — длина
            movsx edx, word ptr [ebp+0x08]
            push  edx                         // a2 — опкод
            call  OnRatingPacket
            add   esp, 12
            popad
            pop   ebp
            push  ebp                         // доигрываем пролог: 55 8B EC 6A FF
            mov   ebp, esp
            push  -1
            jmp   [g_enterBack]
        }
    }

    // ── Площадка B @0x54D8B7 (36 б): блок выдачи звания ──────────────────────
    //   Стоковые байты — ровно два вызова: AddFameBit и нотис 6065. Ветка
    //   «выдать» повторяет их ДОСЛОВНО (включая push регистров с мусором в
    //   старшем слове — обе функции принимают i16), поэтому при флаге 0
    //   поведение байт в байт прежнее.
    __declspec(naked) void TrampApplyRecord()
    {
        __asm
        {
            cmp   byte ptr [g_revokeOnFlag], 0
            je    Grant
            cmp   byte ptr [ebp - F_FLAG], 1     // 1 = СНЯТЬ
            jne   Grant
            movsx eax, word ptr [ebp - F_ACTIVE_ID]
            push  eax                            // id звания
            movzx edx, word ptr [ebp - F_UNUM]
            push  edx                            // userNum
            push  dword ptr [ebp - F_USER]       // CUser*
            push  dword ptr [ebp - F_THIS]       // менеджер
            call  RevokeFameTitle
            add   esp, 16
            jmp   [g_contApply]
        Grant:
            cmp   byte ptr [g_logRecv], 0
            je    GrantStock
            pushad
            movzx eax, word ptr [ebp - F_UNUM]
            push  eax
            movsx edx, word ptr [ebp - F_ACTIVE_ID]
            push  edx
            call  OnGrantRecord
            add   esp, 8
            popad
        GrantStock:                              // ДОСЛОВНО стоковый блок
            mov   ax, word ptr [ebp - F_ACTIVE_ID]
            push  eax
            mov   cx, word ptr [ebp - F_UNUM]
            push  ecx
            mov   ecx, dword ptr [ebp - F_THIS]
            call  dword ptr [g_addFameBit]
            mov   dx, word ptr [ebp - F_ACTIVE_ID]
            push  edx
            mov   ax, word ptr [ebp - F_UNUM]
            push  eax
            mov   ecx, dword ptr [ebp - F_THIS]
            call  dword ptr [g_fameNotice]
            jmp   [g_contApply]
        }
    }

    // ═══════════════════ ПЛОЩАДКИ (байты сняты с ЖИВОГО образа) ══════════════

    // A — 0x54D86F, 60 байт: `cmp [ebp-0x24],0 / jne` + выход, затем
    //     `cmp UserIndex` + выход. Оба выхода вели на 0x54D950 (конец функции).
    const DWORD kSiteResolve = 0x0054D86F;
    const BYTE  kOrigResolve[60] =
    {
        0x83, 0x7D, 0xDC, 0x00,                         // cmp   dword [ebp-0x24],0
        0x75, 0x14,                                     // jne   0x54D889
        0xC7, 0x45, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF,       // mov   dword [ebp-4],-1
        0x8D, 0x4D, 0xC8,                               // lea   ecx,[ebp-0x38]
        0xE8, 0x9C, 0xE6, 0xF4, 0xFF,                   // call  0x49BF20
        0xE9, 0xC7, 0x00, 0x00, 0x00,                   // jmp   0x54D950  ★ выход из пакета
        0x8B, 0x45, 0xDC,                               // mov   eax,[ebp-0x24]
        0x8B, 0x88, 0x74, 0x01, 0x00, 0x00,             // mov   ecx,[eax+0x174] ; UserIndex
        0x3B, 0x4D, 0xCC,                               // cmp   ecx,[ebp-0x34]
        0x74, 0x14,                                     // je    0x54D8AB
        0xC7, 0x45, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF,       // mov   dword [ebp-4],-1
        0x8D, 0x4D, 0xC8,                               // lea   ecx,[ebp-0x38]
        0xE8, 0x7A, 0xE6, 0xF4, 0xFF,                   // call  0x49BF20
        0xE9, 0xA5, 0x00, 0x00, 0x00                    // jmp   0x54D950  ★ выход из пакета
    };

    // B — 0x54D8B7, 36 байт: блок выдачи звания (AddFameBit + нотис 6065).
    const DWORD kSiteApply = 0x0054D8B7;
    const BYTE  kOrigApply[36] =
    {
        0x66, 0x8B, 0x45, 0xE0,                         // mov   ax,[ebp-0x20]     ; id звания
        0x50,                                           // push  eax
        0x66, 0x8B, 0x4D, 0xD0,                         // mov   cx,[ebp-0x30]     ; userNum
        0x51,                                           // push  ecx
        0x8B, 0x4D, 0xC0,                               // mov   ecx,[ebp-0x40]
        0xE8, 0xB7, 0xD0, 0xFF, 0xFF,                   // call  0x54A980  AddFameBit
        0x66, 0x8B, 0x55, 0xE0,                         // mov   dx,[ebp-0x20]
        0x52,                                           // push  edx
        0x66, 0x8B, 0x45, 0xD0,                         // mov   ax,[ebp-0x30]
        0x50,                                           // push  eax
        0x8B, 0x4D, 0xC0,                               // mov   ecx,[ebp-0x40]
        0xE8, 0xF5, 0xCE, 0xFF, 0xFF                    // call  0x54A7D0  нотис 6065
    };

    // C — 0x54D710, 5 байт: вход приёмника (пролог push ebp; mov ebp,esp; push -1).
    //     Сверяем 14 байт — весь SEH-пролог, чтобы не попасть в чужую функцию.
    const DWORD kSiteEnter = 0x0054D710;
    const BYTE  kOrigEnter[14] =
    {
        0x55,                                           // push  ebp
        0x8B, 0xEC,                                     // mov   ebp,esp
        0x6A, 0xFF,                                     // push  -1        ← конец 5 вытесняемых
        0x68, 0x08, 0x21, 0x58, 0x00,                   // push  0x582108  (SEH scope table)
        0x64, 0xA1, 0x00, 0x00                          // mov   eax,fs:[0] (начало)
    };

    // Контроль соседей: сразу за площадкой B обязан лежать `jmp 0x54D93C`,
    // а на 0x54D93C — `jmp 0x54D825` (конец тела цикла). Сверяем оба, чтобы
    // адреса возврата трамплинов не оказались наугад.
    const DWORD kSiteTail  = 0x0054D8DB;
    const BYTE  kOrigTail[7] =
    {
        0xEB, 0x5F,                                     // jmp   0x54D93C
        0x0F, 0xBF, 0x4D, 0xE0,                         // movsx ecx,word [ebp-0x20]  (ветка 3409)
        0x81                                            // cmp   ecx,0xD51 (начало)
    };
    const DWORD kSiteCont  = 0x0054D93C;
    const BYTE  kOrigCont[5] =
    {
        0xE9, 0xE4, 0xFE, 0xFF, 0xFF                    // jmp   0x54D825 (i++)
    };
}

static bool g_p24Applied = false;   // ★ P127 А2.2: P24 поставлен

PatchResult P24_FameRatingRevoke()
{
    if (!Config::GetBool(kSec, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_resolveByUserIdx = Config::GetBool(kSec, L"ResolveByUserIndex",  true);
    g_revokeOnFlag    = Config::GetBool(kSec, L"RevokeOnFlag",     true);
    g_clearActive     = Config::GetBool(kSec, L"ClearActiveTitle", true);
    g_broadcastPlate  = Config::GetBool(kSec, L"BroadcastPlate",   true);
    g_pushMask        = Config::GetBool(kSec, L"PushMaskToOwner",  true);
    g_notify6070      = Config::GetBool(kSec, L"Notify6070",       true);
    g_logRecv         = Config::GetBool(kSec, L"LogRecv",          true);

    // ── Сверка ВСЕХ площадок (и двух соседей) до единой записи ─────────────
    const Site sites[] =
    {
        { kSiteEnter,   kOrigEnter,   sizeof(kOrigEnter)   },
        { kSiteResolve, kOrigResolve, sizeof(kOrigResolve) },
        { kSiteApply,   kOrigApply,   sizeof(kOrigApply)   },
        { kSiteTail,    kOrigTail,    sizeof(kOrigTail)    },
        { kSiteCont,    kOrigCont,    sizeof(kOrigCont)    },
    };
    if (!VerifyAllSites(L"P24", sites, ARRAYSIZE(sites)))
    {
        return PatchResult::Mismatch;
    }

    bool ok = true;

    // C — диагностика прихода 3404…3409 в штатный Log_Title.
    if (g_logRecv)
    {
        ok &= Hook::WriteJmp(kSiteEnter, (const void*)&TrampEnterRecv, 5);
        Log::Line(L"    P24: диагностика включена — каждый приход 3404…3409 и разбор "
                  L"каждой записи пишутся в Log/Log_Title (@%08X)", kSiteEnter);
    }

    // A — «не нашли сессию» больше не рвёт пакет; ищем игрока по UserIndex (D2).
    if (g_resolveByUserIdx || g_revokeOnFlag)
    {
        ok &= Hook::WriteJmp(kSiteResolve, (const void*)&TrampResolveUser, sizeof(kOrigResolve));
        Log::Line(L"    P24: приёмник 3404…3408 ищет игрока по UserIndex и не рвёт пакет "
                  L"на первой ненайденной сессии (@%08X)", kSiteResolve);
    }

    // B — флаг записи: 0 выдать (как в стоке), 1 снять (D1 + штрихи 1…3).
    if (g_revokeOnFlag)
    {
        ok &= Hook::WriteJmp(kSiteApply, (const void*)&TrampApplyRecord, sizeof(kOrigApply));
        Log::Line(L"    P24: флаг записи 1 = СНЯТЬ звание у прежнего лидера (@%08X); "
                  L"флаг 0 — стоковая выдача байт в байт", kSiteApply);
        Log::Line(L"    P24: при снятии уходит: 2256/2257[/2266] и 2258 в базу, "
                  L"6068 себе и окружающим, 6066 + 6086 и 6070 владельцу");
    }
    else
    {
        Log::Line(L"    P24: ! RevokeOnFlag=0 — снятия НЕТ, работает только починка "
                  L"обхода записей пакета");
    }

    // Честное предупреждение: без отправителя патч бездействует.
    Log::Line(L"    P24: ! отправитель смены лидера и снятие у ОФЛАЙНОВОГО игрока — "
              L"сторона базы (патч P23 в DBPatch.dll, таблица dbo.FameRatingHolder). "
              L"Без него опкоды 3404…3408 не приходят вовсе.");

    g_p24Applied = ok;   // ★ P127 А2.2: площадки и функции снятия сверены
    return ok ? PatchResult::Applied : PatchResult::Failed;
}

// ★ P127 А2.2 (18.11.2026): снятие звания живьём для моста админ-центра — ТА ЖЕ процедура, что у снятия рейтингового звания
//   (SubFameBit + 2256/2257[/2266], надетое — снять с бонусами и 2258, плашка 6068 себе и окружающим, маски 6066/6086, нотис 6070).
//   Нить карты игрока. Без установленного P24 не зовётся.
bool P24_Applied() { return g_p24Applied; }
int  P24_FameCount() { return FameCount(); }
void P24_RevokeTitle(void* mgr, void* pUser, int userNum, int titleId) { RevokeFameTitle(mgr, pUser, userNum, titleId); }
