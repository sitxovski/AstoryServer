// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P23 — DBManager: ОТПРАВИТЕЛЬ РЕЙТИНГОВЫХ ЗВАНИЙ 65…69 (опкоды 3404…3408).
//        ★ НАША ПРАВКА. Живёт в нашей DLL, образ DBManager.exe не меняется.
//
//  Документ патча:  AstoryServer/Docs/DBManager/title-rank-feed-p23.md
//  Пара в GameServer: P24 «снятие звания у прежнего лидера» (AsdaPatch.dll)
//
//  ── ЗАЧЕМ ───────────────────────────────────────────────────────────────────
//  Звания 65…69 вкладки «Соревнование» раздаёт GameServer в `sub_54D710@0x54D710`
//  по МЕЖСЕРВЕРНЫМ опкодам 3404→65, 3405→66, 3406→67, 3407→68, 3408→69
//  («Впереди планеты всей», «Бог сражений/лучников/магии», «Богатенький буратино»).
//  Приёмник в живом образе рабочий, а ОТПРАВИТЕЛЯ нет НИ В ОДНОМ из 59 .exe/.dll
//  сервера — поэтому звания недостижимы. Патч и есть недостающий отправитель.
//
//  ── ★★★ ГЛАВНОЕ ДОКАЗАТЕЛЬСТВО: DBManager МОЖЕТ слать в этот канал ──────────
//  Сомнение было в поле заголовка `word[+5]`:
//      GameServer, приём (`ConnectSocketMsgProcess@0x42FAB0`):
//          0x42FB5E  mov  dx, word ptr [ecx+5]
//          0x42FB7C  movsx ecx, word [ebp-0x14]
//          0x42FB80  cmp  ecx, 0x2710
//          0x42FB86  jl   0x434667      ← 0x434667 = `jmp 0x42FAFC`, т.е. ПАКЕТ ВЫБРОШЕН
//      т.е. GameServer разбирает только пакеты с word[+5] >= 10000, а
//      DBManager (`sub_402420@0x4024C2`) — ровно наоборот, только с word[+5] < 10000.
//      При этом отправители по обе стороны кладут в `+5` СВОЙ индекс соединения:
//          GameServer  `sub_5646C0@0x564803`  mov word [buf+5], cx   ; cx = 0…99
//          DBManager   `sub_44E2F0@0x44E3B5`  mov word [buf+5], ax   ; ax = 0…349
//      Противоречие снимается приёмной стороной: сборщик потока
//      `sub_5656D0@0x565B6D` (GameServer) ПЕРЕЗАПИСЫВАЕТ это поле своим номером
//      сокета ПЕРЕД постановкой пакета в очередь:
//          0x565B66  mov ecx, [ebp-0x20]      ; буфер пакета
//          0x565B69  mov dx,  word [ebp+0x10] ; номер сокета
//          0x565B6D  mov word ptr [ecx+5], dx
//      а номер «исходящего» (connect) сокета у GameServer = 10000 + слот
//      (`0x563E2F  sub ecx, 0x2710`, верхняя граница 0x2774 = 10000+100).
//      ⇒ ЧТО ОТПРАВИТЕЛЬ ПОЛОЖИЛ В `+5`, НЕ ИМЕЕТ ЗНАЧЕНИЯ. Гейт `>=10000`
//      выполняется автоматически, потому что GameServer сам его и проставляет.
//  Второй метод (закон false-negatives-method): в этом же диспетчере GameServer
//  разбирает опкоды 0x875…0x8DE — это ОТВЕТЫ DBManager (`DBM_SKILLWINDOW_INFO_END`,
//  `recvDB`, `recvDBUserFameInfo`). Они ходят по тому же соединению, тем же
//  конвертом, через ту же `sub_44E2F0`. Значит канал существует и работает.
//
//  ── КОНВЕРТ ────────────────────────────────────────────────────────────────
//  Один и тот же для всего межпроцессного семейства, БЕЗ подписи и без секрета
//  (закон packet-envelope-two-kinds: конверт с MD5 — это клиент↔сервер и
//  ItemRelayServer, здесь его нет):
//      [0]      0xFB   HEAD
//      [1..2]   Size = длина тела + 10
//      [3..4]   userNum (i16) — GameServer раздаёт его обработчикам как индекс игрока
//      [5..6]   номер соединения (перезаписывается приёмником, см. выше)
//      [7..8]   опкод
//      [9..]    тело
//      [Size-1] 0xFE   TAIL
//  Паддинга здесь нет вовсе (закон packet-size-check-no-padding касается другого
//  семейства): длина тела 3404…3408 обязана быть кратна 13, иначе приёмник
//  `(a3-10) % 13 != 0` молча выходит.
//
//  ── ТЕЛО 3404…3408: ЗАПИСЬ 13 БАЙТ (снято с `sub_54D710`) ───────────────────
//      +0  значение i32  (для 3404…3408 сток его НЕ читает, читает только 3409)
//      +4  charId    i32 — сверяется с `*(DWORD*)CUser->gap_16B` (= `CCharacter+372`);
//                          в базе это `@Userindex` (`DBManager.exe.c:21495`)
//      +8  userNum   i16 — по нему берётся CUser (`sub_5324A0`)
//      +10 слот+1    u16 — ★ с P24 это НЕ резерв: `Charidx + 1`, 0 = «слот не задан»
//      +12 признак   i8  — в стоке МЁРТВЫЙ (`0x54D859 mov cl,[edx+0xC]`, и больше нигде)
//  ⚠ Сток при первом же несовпадении делает `break`, а не `continue` — поэтому
//    шлём ПО ОДНОЙ записи в пакете (тело 13 б, Size 23).
//  ★ P24 это починил (ненайденная сессия больше не рвёт пакет), и ограничение
//    формально снято. Оставляем «по одной записи» намеренно: так патч остаётся
//    безопасным и при выключенном/не подменённом P24, а выигрыша от группировки
//    нет — записей за проход единицы. Правило про userNum 0…549 остаётся в силе
//    в любом случае: оно про стоковую проверку sub_5328F0, а не про разрыв списка.
//  ★ charId (i32) ≠ userNum (i16) — закон charid-vs-usernum: перепутать нельзя,
//    сервер МОЛЧА проигнорирует пакет.
//
//  ── ★★★ У ОДНОГО АККАУНТА БЫВАЕТ НЕСКОЛЬКО ЖИВЫХ СЕССИЙ ────────────────────
//  Доказано P24 на боевом: `GM_Rimy` и `ADM_sitxovski` — ОДИН аккаунт
//  (`UserIndex = 2`), слоты 10 и 11, оба в игре (входы 18:20:14 и 18:21:02,
//  в логине у обоих `UserID Rimy`, в `Log_Title` у обоих `RecvDB 2`).
//  Поэтому «UserIndex → сессия» НЕ однозначно, и поиск только по нему промахивался.
//  Мы обязаны класть в запись слот персонажа (+10…+11 = `Charidx + 1`), тогда
//  P24 ищет точно: UserIndex + слот, затем подсказка userNum, и лишь потом
//  одиночный UserIndex — и то только когда слот не задан.
//
//  ── ★★★ ДОГОВОР С P24 (GameServer) ─────────────────────────────────────────
//  P24 оживляет мёртвый байт +12:
//      +12 = 0  — ВЫДАТЬ звание (стоковый блок повторён байт в байт);
//      +12 = 1  — СНЯТЬ звание у прежнего держателя.
//  Операция идемпотентна: снятие у уже снятого — тихий выход на стороне P24.
//
//  ── ★★★ userNum: ТОЛЬКО 0…549, ИНАЧЕ НЕ ШЛЁМ ВОВСЕ ─────────────────────────
//  В первой редакции здесь стоял «договор: userNum = 0xFFFF — ищи сам по charId».
//  ЭТО БЫЛО ОШИБКОЙ, и вот доказательство из живого тракта:
//      sub_5324A0@0x5324B5 -> sub_5328F0:
//          0x5328F3  movsx eax, word ptr [ebp+8]
//          0x5328F7  test eax, eax ; jl  -> вернуть 0
//          0x5328FF  cmp  ecx, 0x226 ; jl -> вернуть 1
//      ⇒ годно только 0 <= (i16)userNum < 0x226 (550). 0xFFFF как i16 = −1,
//        проверку НЕ проходит, sub_5324A0 отдаёт nullptr, и СТОКОВЫЙ sub_54D710
//        делает `break` — выбрасывает ВЕСЬ ОСТАТОК СПИСКА записей пакета.
//  Ловушка в том, что 0xFFFF всё же «работает», НО ТОЛЬКО пока жив P24 с ключом
//  ResolveByUserIdx=1: его площадка A @0x54D86F подменяет стоковый выход на поиск
//  по UserIndex (`ResolveFameUser` -> `FindUserByUserIndex`). Полагаться на чужой
//  ini-ключ нельзя, поэтому правило простое и одностороннее:
//      в пакет попадают ТОЛЬКО записи с 0 <= userNum <= 549;
//      для всех остальных операция идёт ЧЕРЕЗ БАЗУ, а пакет не шлётся вовсе.
//  ★ Мы и так кладём по ОДНОЙ записи в пакет, поэтому каскад «первая запись
//    убила вторую» у нас невозможен по построению; но слать заведомо обречённый
//    пакет всё равно незачем.
//
//  Один проход (по умолчанию раз в 600 с):
//      1. EXEC dbo.UPTopLevelAll             → 1 строка  (звание 65)
//      2. EXEC dbo.UPTopLevelClass           → 3 строки  (звания 66, 67, 68)
//      3. EXEC dbo.UPTopGold                 → 1 строка  (звание 69)
//      4. на каждую строку с CharId <> 0:
//         EXEC dbo.UPFameRatingHolderUp @TitleId,@CharId,@CharIdx,@Value → прежний держатель
//         если IsChanged = 1 и PrevGranted = 1 и PrevCharId <> 0 — шлём СНЯТИЕ прежнему;
//         затем шлём ВЫДАЧУ новому и EXEC dbo.UPFameRatingHolderFlagUp @TitleId,@CharId,1
//      5. EXEC dbo.UPFameRatingHolder        → 5 строк состояния; кому Granted = 0,
//         тем повторяем выдачу (пережитый рестарт / лидер выиграл, будучи офлайн)
//      6. EXEC dbo.UPFameRatingRevokeList    → очередь снятия (до 50); шлём снятие,
//         затем EXEC dbo.UPFameRatingRevokeUp @Id
//  ★ Пустого набора не бывает никогда: `sub_447720` считает 0 строк НЕУДАЧЕЙ вызова.
//    «Кандидата нет» приходит строкой с CharId = 0, пустая очередь — строкой с Id = 0.
//  ★ Ни `SET TRANSACTION ISOLATION LEVEL`, ни `XACT_ABORT` мы не шлём: они липнут
//    к соединению, а DBManager переиспользует его под стоковые процедуры.
//
//  ── ★★★ РАСКЛАДКА СТРОКИ РЕЗУЛЬТАТА (доказана биндингом внутри sub_447720) ──
//  `sub_447720` строит массив DBBINDING по 52 байта на столбец:
//      +0  iOrdinal = i+1                                  (0x447A18…)
//      +4  obValue  = НАКОПИТЕЛЬ  (+308)                   ← смещение столбца
//      +28 dwPart   = 1 (DBPART_VALUE)
//      +40 cbMaxLen = DBCOLUMNINFO.ulColumnSize (colinfo+16)
//      +48 wType    = DBCOLUMNINFO.wType        (colinfo+20)
//      накопитель += ulColumnSize
//  ⇒ строка УПАКОВАНА ВПЛОТНУЮ, без выравнивания, в НАТИВНОМ типе столбца,
//    а полный размер строки уезжает в `status[3]`, число строк — в `status[2]`,
//    число столбцов — в `status[1]` (`a2[1]=v19`, `a2[2]=v18`, `a2[3]=v20`).
//    Та же модель уже работает в P22 (4 × BIGINT = 32 б с начала строки).
//
//  ── ПОЧЕМУ НЕТ СВОЕГО ПОТОКА (закон no-reentrant-net-callbacks) ─────────────
//  Пересчёт раз в N секунд взводит ФЛАГ, а выполняется на ближайшем ТИКЕ —
//  то есть на рабочем потоке самого DBManager, в его же кадре диспетчера, с его
//  же `a3` и его же соединением к базе. Ровно так работают стоковые обработчики
//  (`sub_407480` и др.): сначала `sub_447720`, потом `sub_44E2F0`. Своего потока
//  нет намеренно: (1) создавать поток в DllMain нельзя — загрузчик держит блокировку;
//  (2) чужой поток не имеет законного `a3` и не входит в модель OLEDB-сессий образа.
//  Побочный эффект: если в игре нет НИ ОДНОГО игрока, DB-пакетов нет и пересчёт
//  не идёт — но и раздавать звание тогда некому (приёмнику нужен живой CUser).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Config.h"
#include "Hook.h"
#include "Log.h"
#include <stdio.h>   // _snprintf: wsprintfA НЕ умеет %I64d, а величины у нас BIGINT

namespace
{
    const wchar_t* kSec = L"P23_TitleRankFeed";

    // ── настройки из dbpatch.ini ────────────────────────────────────────────
    bool g_enabled     = true;   // главный выключатель секции
    bool g_send        = true;   // слать ли пакеты (0 = только считать и писать в журнал)
    bool g_matchSlot   = true;   // сверять слот персонажа (исправление дефекта оригинала)
    bool g_useOnline   = true;   // доверять ли подсказке IsOnline из базы
    bool g_clearSlot   = true;   // просить базу снимать звание и со слота «надето»
    int  g_intervalSec = 600;    // период пересчёта, секунды (решение владельца — 10 минут)
    int  g_group       = 0;      // группа серверов для выбора соединения с базой
    int  g_maxGrantTry = 3;      // сколько раз подряд пытаться выдать, пока бит не появится

    // ── ★ GM-команда «пересчитать СЕЙЧАС» (пара к патчу GameServer P25) ─────
    bool g_onDemand      = true; // принимать опкод 2333 и отвечать 2334
    bool g_fpOnDemand    = true; // включать в команду пересчёт №2 (топ по очкам славы)
    int  g_minForceSec   = 60;   // ★ АВТОРИТЕТНЫЙ порог частоты (зеркало в patches.ini)
    int  g_fpIntervalSec = 0;    // периодический пересчёт №2; 0 = только по команде

    // ── адреса ЖИВОГО DBManager.exe (сверены дизассемблером) ────────────────
    // ★ ЗАКОН msvc-inline-asm-offsets: числа для `__asm` — ТОЛЬКО через #define.
    //   C++-константа внутри `__asm` даёт АДРЕС переменной, а не значение.
    #define P23_QPC_HI   0x18    // [ebp-0x18] конец замера времени (вытесненная команда)
    #define P23_QPC_LO   0x28    // [ebp-0x28] начало замера времени (вытесненная команда)

    constexpr DWORD kFrmPkt  = 0x0C;   // [ebp-0x0C] указатель на пакет
    constexpr DWORD kFrmA3   = 0x08;   // [ebp+0x08] a3 — его ждёт sub_447720

    constexpr int   kOpRankBase = 3404;   // 3404 → звание 65, …, 3408 → звание 69
    constexpr int   kTitleBase  = 65;     // первое рейтинговое звание
    constexpr int   kTitleLast  = 69;     // последнее рейтинговое звание
    constexpr int   kRatings    = 5;      // сколько рейтингов
    constexpr int   kRecLen     = 13;     // длина одной записи тела
    constexpr int   kSqlBuf     = 0x36B4; // 14004 — размер буфера результата, как у стока

    constexpr BYTE  kFlagGrant  = 0;      // договор с P24: 0 = выдать
    constexpr BYTE  kFlagRevoke = 1;      // договор с P24: 1 = снять

    // ★★★ ГОДНЫЙ ДИАПАЗОН userNum — 0…549. Доказано дизассемблером ЖИВОГО тракта:
    //   sub_5324A0@0x5324B5 зовёт sub_5328F0, а тот
    //       0x5328F3  movsx eax, word [ebp+8]
    //       0x5328F7  test eax,eax ; jl  -> 0
    //       0x5328FF  cmp  ecx,0x226 ; jl -> 1
    //   т.е. годно только 0 <= (i16)userNum < 0x226 (550). Значение вне диапазона
    //   даёт nullptr, а СТОКОВЫЙ sub_54D710 на этом делает `break` и выбрасывает
    //   ВЕСЬ ОСТАТОК СПИСКА записей пакета.
    //
    // ⚠ РАНЬШЕ ЗДЕСЬ БЫЛО 0xFFFF «не знаю, ищи по charId» — это была ОШИБКА.
    //   0xFFFF как i16 = -1, диапазон не проходит. Ловушка в том, что оно всё же
    //   «работает», НО ТОЛЬКО пока жив P24 с ключом ResolveByUserIdx=1: его
    //   площадка A @0x54D86F подменяет стоковый выход на поиск по UserIndex
    //   (`ResolveFameUser` → `FindUserByUserIndex`). При выключенном или ещё не
    //   подменённом P24 тот же пакет молча съедается. Полагаться на чужой
    //   ini-ключ нельзя — поэтому запись с негодным userNum НЕ ОТПРАВЛЯЕТСЯ ВОВСЕ.
    constexpr int   kUserSlotMax = 0x226;  // 550, предел sub_5328F0@0x5328FF
    constexpr int   kNoUserNum   = -1;     // «сессии нет» — пакет не шлём

    // Годен ли userNum для пакета. База отдаёт ту же −1 как единый признак
    // «не слать» (представление нормализует NULL / <0 / >549), своей проверки
    // поверх неё не изобретаем — просто применяем один и тот же порог.
    inline bool Sendable(int userNum)
    {
        return userNum >= 0 && userNum < kUserSlotMax;
    }

    constexpr int   kMaxConn    = 350;    // предел sub_44E2F0 (`cmp edx,0x15E`)
    constexpr int   kMaxRevoke  = 50;     // UPFameRatingRevokeList отдаёт не больше 50

    // ── ★★★ ПЕРЕСЧЁТ №2: МЕСТО В ТОПЕ ПО ОЧКАМ СЛАВЫ (опкод 3409) ───────────
    //  Это то самое, «что в 3 часа ночи каждый раз происходит». Разобрано до конца:
    //
    //  КТО ЗАПУСКАЕТ В ОРИГИНАЛЕ. Задача `ChannelManager` «Title Rank Process»
    //  (журнал `ChannelManager\Error_Log\TitleLog_<дата>.txt`, записи вида
    //  «03:00:00:139»). В самом `ChannelManager.exe` есть и РУЧНОЙ запуск —
    //  строка-подсказка консоли `'o' : Title Rank Process` рядом с `'x' : Program
    //  Terminate` и `'r' : Reconnect`. То есть кнопка была всегда, но только на
    //  консоли процесса; из игры её не достать — это и просил закрыть владелец.
    //
    //  КТО СЧИТАЕТ. Единственный образ сервера, где есть строка `EXEC UPTopFamePoint`,
    //  — `RelayServer.exe` (MD5 97CDA850…; тот же файл лежит в Indun_RelayServer).
    //  Сплошной `strings` по всем 59 .exe: `FamePoint`/`FameRank`/`Title Rank`
    //  встречаются ещё только в ChannelManager (без SQL) и в DBManager (другие
    //  процедуры). Рядом с вызовом — `CConnectionManager::SendFameRankInfo()`.
    //
    //  ★★★ ЧТО ИМЕННО ДЕЛАЕТ ПРОЦЕДУРА (снято с ЖИВОЙ базы, sys.sql_modules):
    //      CREATE PROC dbo.UPTopFamePoint AS
    //        truncate table FamePointRank
    //        INSERT INTO dbo.FamePointRank (Ranking,Userindex,Charidx)
    //          SELECT RANK() OVER (ORDER BY Fmpoint DESC), userindex, charidx
    //          FROM dbo.CharFameBank WHERE Userindex > 5000
    //        SELECT TOP 100 c.Ranking, c.Userindex, p.UserNum, p.Threadidx,
    //                       p.Channel, p.Gsidx
    //          FROM dbo.FamePointRank c INNER JOIN Charpos p
    //               ON c.Userindex=p.Userindex AND c.Charidx=p.Charidx
    //          WHERE p.Userindex > 5000
    //          ORDER BY c.Ranking, p.Usernum
    //  ⇒ она САМА пересчитывает таблицу (а не только читает её, как предполагал
    //    план) и САМА возвращает готовый список. Параметров нет. Фильтр
    //    `Userindex > 5000` — это тот же операторский диапазон 0…5000: GM-учётки
    //    в рейтинг не попадают (см. закон server-operator-gate).
    //
    //  ★★★ СТРОКА РЕЗУЛЬТАТА = ГОТОВАЯ ЗАПИСЬ ПАКЕТА. Типы столбцов живой базы:
    //      Ranking   int      4 б  →  +0  значение i32   (3409 читает ИМЕННО его)
    //      Userindex int      4 б  →  +4  UserIndex i32
    //      UserNum   smallint 2 б  →  +8  userNum i16   (-1 = игрок не в сети)
    //      Threadidx tinyint  1 б  →  +10 «резерв», приёмник не читает
    //      Channel   tinyint  1 б  →  +11 «резерв», приёмник не читает
    //      Gsidx     tinyint  1 б  →  +12 «мёртвый признак» стока
    //  Итого РОВНО 13 байт — та же запись, что у 3404…3408. Упаковка вплотную
    //  (см. разбор биндинга sub_447720 в шапке), поэтому строку можно слать в
    //  пакет БЕЗ ПЕРЕСБОРКИ. Это же объясняет, откуда у записи взялись «резерв»
    //  и «мёртвый байт»: RelayServer просто блитит строку запроса.
    //  ⚠ Байт +12 у нас занят договором с P24 (0 выдать / 1 снять), но у опкода
    //    3409 P24 в дело не вступает — ветка 3409 в sub_54D710 отдельная и флаг
    //    не читает. Поэтому Gsidx едет как есть.
    //
    //  ОТСЕВ ОФЛАЙНА — как в оригинале: RelayServer пропускает запись, если
    //  `word[запись+8] > -1` не выполняется. Повторяем ровно это.
    constexpr int   kOpFamePoint = 3409;  // «место в рейтинге по очкам славы»
    constexpr int   kFpCols      = 6;     // столбцов в ответе UPTopFamePoint
    constexpr int   kFpMaxRows   = 100;   // SELECT TOP 100
    constexpr int   kFpUserNumAt = 8;     // смещение userNum i16 внутри строки

    // ── ★ GM-команда: опкоды и раскладка ответа ────────────────────────────
    //  Пара — патч GameServer P25 (AsdaPatch.dll). Раскладка тела 2334
    //  ПРОДУБЛИРОВАНА в p25_gm_rating_recalc.cpp: менять только парой.
    constexpr int kOpForce      = 0x91D;   // 2333 GS→DB «пересчитать сейчас»
    constexpr int kOpReport     = 0x91E;   // 2334 DB→GS «результат пересчёта»

    constexpr int kFrcUserNum   = 0;   // тело 2333: i16 сессия оператора
    constexpr int kFrcUserIdx   = 2;   //            i32 UserIndex оператора
    constexpr int kFrcCharIdx   = 6;   //            i8  слот персонажа
    constexpr int kFrcGroup     = 7;   //            i8  группа серверов
    constexpr int kFrcWhat      = 8;   //            i8  0 оба / 1 звания / 2 топ
    constexpr int kFrcLen       = 10;  //            всего 10 байт

    constexpr int kRepUserNum   = 0;   // тело 2334: i16 кому отвечаем
    constexpr int kRepUserIdx   = 2;   //            i32 UserIndex (сверка на той стороне)
    constexpr int kRepCharIdx   = 6;   //            i8  слот персонажа
    constexpr int kRepStatus    = 7;   //            i8  код итога
    constexpr int kRepMs        = 8;   //            i32 длительность прохода, мс
    constexpr int kRepChanged   = 12;  //            i32 сменилось лидеров
    constexpr int kRepRevoked   = 16;  //            i32 обработано снятий
    constexpr int kRepRegrant   = 20;  //            i32 довыдано
    constexpr int kRepRankRows  = 24;  //            i32 строк топа славы
    constexpr int kRepRankSent  = 28;  //            i32 из них отправлено
    constexpr int kRepLeaders   = 32;  //            i8  сколько записей идёт следом
    constexpr int kRepList      = 33;  //            далее N × (i8 titleId + char[21])
    constexpr int kRepRecLen    = 22;
    constexpr int kRepMaxList   = kRatings;
    constexpr int kRepMaxLen    = kRepList + kRepRecLen * kRepMaxList;

    // Коды итога (их печатает P25 оператору).
    constexpr int kStatusOk       = 0;   // проход выполнен
    constexpr int kStatusBusy     = 1;   // предыдущий проход ещё идёт
    constexpr int kStatusTooOften = 2;   // не вышел порог MinForceSec
    constexpr int kStatusDbDown   = 3;   // база не ответила / миграции нет
    constexpr int kStatusOff      = 4;   // приём команды выключен в dbpatch.ini

    // Что собираем за проход, чтобы отчитаться оператору.
    struct ForceReport
    {
        int  status;
        int  ms;
        int  changed;      // сменилось лидеров (звания 65…69)
        int  revoked;      // обработано заданий снятия
        int  regrant;      // довыдано (Granted было 0)
        int  rankRows;     // строк в топе по очкам славы
        int  rankSent;     // из них отправлено живым сессиям
        int  nLead;        // сколько записей лидеров заполнено
        BYTE leadTitle[kRepMaxList];
        char leadName[kRepMaxList][21];   // сырые байты имени из базы, как в строке
    };

    // ── смещения столбцов в строке результата (упаковка вплотную, см. шапку) ─
    // Топ-процедуры (8 столбцов): TitleId u8 · CharIdx u8 · IsOnline u8 ·
    //                             Value i32 · CharId i32 · UserNum i32 ·
    //                             ValueRaw i64 · CharName NCHAR(21)
    constexpr int kTopCols     = 8;
    constexpr int kTopTitleId  = 0;
    constexpr int kTopCharIdx  = 1;
    constexpr int kTopOnline   = 2;
    constexpr int kTopValue    = 3;
    constexpr int kTopCharId   = 7;
    constexpr int kTopUserNum  = 11;
    constexpr int kTopValueRaw = 15;
    constexpr int kTopName     = 23;
    constexpr int kTopMinRow   = 23;      // до имени всё, что нам нужно

    // UPFameRatingHolderUp (7 столбцов): TitleId u8 · IsChanged u8 · PrevCharIdx u8 ·
    //                                    PrevGranted u8 · PrevCharId i32 ·
    //                                    PrevValue i64 · PrevName NCHAR(21)
    constexpr int kHupCols       = 7;
    constexpr int kHupTitleId    = 0;
    constexpr int kHupChanged    = 1;
    constexpr int kHupPrevSlot   = 2;
    constexpr int kHupPrevGrant  = 3;
    constexpr int kHupPrevCharId = 4;
    constexpr int kHupPrevValue  = 8;
    constexpr int kHupName       = 16;
    constexpr int kHupMinRow     = 16;

    // UPFameRatingHolder (12 столбцов). Нужны только первые четыре поля,
    // они лежат до дат, чья ширина у провайдера неочевидна.
    // ★ UPCharFameBitInfo — ТОЛЬКО ЧТЕНИЕ: стоит ли бит звания в маске.
    //     SELECT FameIdx SMALLINT · Result TINYINT · BitWasSet TINYINT ·
    //            InSlot TINYINT · RowFound TINYINT · Half TINYINT ·
    //            CharIdx TINYINT · UserIndex INT
    //   8 столбцов, строка 12 б, строковых столбцов нет.
    //   Result и BitWasSet — одно и то же значение (@set), берём BitWasSet.
    //   ★ Обе половины маски покрыты ВНУТРИ процедуры: при id < 256 она смотрит
    //     CharFameBank.Fame1..4, при id >= 256 — CharFameHigh.BankHi1..4 (P22),
    //     а Half говорит, какую половину смотрели. Арифметику «слово = id/64,
    //     бит = id%64» в DLL НЕ повторяем — иначе завели бы второй источник правды.
    constexpr int kBiCols      = 8;
    constexpr int kBiFameIdx   = 0;
    constexpr int kBiResult    = 2;
    constexpr int kBiBitWasSet = 3;
    constexpr int kBiInSlot    = 4;
    constexpr int kBiRowFound  = 5;
    constexpr int kBiHalf      = 6;
    constexpr int kBiMinRow    = 12;

    constexpr int kHolCols     = 12;
    constexpr int kHolTitleId  = 0;
    constexpr int kHolCharIdx  = 1;
    constexpr int kHolGranted  = 2;
    constexpr int kHolCharId   = 4;
    constexpr int kHolValue    = 12;
    constexpr int kHolMinRow   = 20;

    // UPFameRatingRevokeList (7 столбцов): Id i64 · TitleId u8 · CharIdx u8 ·
    //                                      IsOnline u8 · CharId i32 · UserNum i32 · CharName
    constexpr int kRevCols     = 7;
    constexpr int kRevId       = 0;
    constexpr int kRevTitleId  = 8;
    constexpr int kRevCharIdx  = 9;
    constexpr int kRevOnline   = 10;
    constexpr int kRevCharId   = 11;
    constexpr int kRevUserNum  = 15;
    constexpr int kRevName     = 19;
    constexpr int kRevMinRow   = 19;

    // ★ UPCharFameBitDis — прямое снятие бита звания В БАЗЕ (и у офлайнового).
    //   Одна строка, 9 столбцов, строковых нет: FameIdx i16 @0 · Result u8 @2 ·
    //   BitWasSet u8 @3 · SlotCleared u8 @4 · OptionCleared u8 @5 · RowFound u8 @6 ·
    //   Half u8 @7 · CharIdx u8 @8 · UserIndex i32 @9  (итого 13 б)
    constexpr int kBdCols      = 9;
    constexpr int kBdFameIdx   = 0;
    constexpr int kBdResult    = 2;
    constexpr int kBdBitWasSet = 3;
    constexpr int kBdSlotClr   = 4;
    constexpr int kBdOptClr    = 5;
    constexpr int kBdRowFound  = 6;
    constexpr int kBdHalf      = 7;
    constexpr int kBdMinRow    = 13;

    typedef int  (__fastcall *PFN_GetConn)(void* self, void* edx, int groupIdx);
    typedef int  (__cdecl    *PFN_Sql)(void* ds, void* status, int conn, int a3,
                                       void* out, const char* fmt, ...);
    typedef int  (__fastcall *PFN_Send)(void* self, void* edx, int op, int len,
                                        int connIdx, void* body, int userNum);

    PFN_GetConn const pGetConn = (PFN_GetConn) 0x00407390;  // __thiscall(ecx=this, i16) ret 4
    PFN_Sql     const pSql     = (PFN_Sql)     0x00447720;  // __cdecl, стек чистит вызывающий
    PFN_Send    const pSend    = (PFN_Send)    0x0044E2F0;  // __thiscall, ret 0x14

    void* const kDispThis = (void*)0x0049EAB8;   // this диспетчера/обработчиков
    void* const kSendThis = (void*)0x0049EAF8;   // this отправителя ответов
    void* const kDataSrc  = (void*)0x00534E7F0;  // источник данных для sub_447720

    // ── чтение упакованной строки (без предположений о выравнивании) ────────
    inline int   RdU8 (const BYTE* p, int o) { return p[o]; }
    inline int   RdI32(const BYTE* p, int o) { int   v; memcpy(&v, p + o, 4); return v; }
    inline __int64 RdI64(const BYTE* p, int o) { __int64 v; memcpy(&v, p + o, 8); return v; }

    // ★ Имя персонажа: CHAR(21) — НЕ-юникод, РОВНО 21 БАЙТ, добито пробелами.
    //   Тип поменян агентом по базе 30.08.2026 по нашему же предупреждению:
    //   у символьных столбцов `ulColumnSize` в OLE DB — длина в СИМВОЛАХ, поэтому
    //   `NCHAR(21)` дал бы `DBTYPE_WSTR` с `cbMaxLen = 21` при нужных 42 байтах,
    //   и имя приехало бы битым. `CHAR(21)` → `DBTYPE_STR`, 21 символ = 21 байт.
    //   Столбец с именем ВЕЗДЕ последний, поэтому на смещения чисел он не влияет.
    constexpr int kNameBytes = 21;

    void RdName(const BYTE* p, int o, int room, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (room <= o) { return; }
        int n = kNameBytes;
        if (room - o < n) { n = room - o; }
        char tmp[kNameBytes + 1] = {};
        if (n > kNameBytes) { n = kNameBytes; }
        memcpy(tmp, p + o, n);
        tmp[n] = 0;
        while (n > 0 && (tmp[n - 1] == ' ' || tmp[n - 1] == 0)) { tmp[--n] = 0; }
        // Кодовая страница у базы 1256 (P17 переводит запросы в неё же).
        if (MultiByteToWideChar(CP_ACP, 0, tmp, -1, out, cch) == 0) { out[0] = 0; }
    }

    // ── таблица онлайна: charId → живая сессия ──────────────────────────────
    // Прямая адресация по остатку; коллизия просто вытесняет старую запись —
    // потеря означает лишь то, что для этой сессии не найдётся годного userNum
    // и операция уйдёт через базу, без живого пакета (см. Sendable).
    constexpr int kRosterSize = 2048;        // степень двойки

    struct RosterEntry
    {
        int   charId;      // тот же i32, что едет в записи (+4); в базе — @Userindex
        int   userNum;     // номер живой сессии в GameServer (i16, храним как int)
        int   charSlot;    // Charidx, слот персонажа 0…2
        int   connIdx;     // номер соединения DBManager, по которому пришёл пакет
        DWORD tick;        // когда последний раз видели
    };

    RosterEntry g_roster[kRosterSize] = {};

    // Набор живых соединений: с каких номеров к нам приходили DB-пакеты.
    // По ним и рассылаем — там сидят GameServer и Indun_GameServer (порт 15101
    // фигурирует только в GameServer\ConnectIP_Info\*.ini и в ServerIPPORT.txt
    // самого DBManager, чужих клиентов на слушающем сокете нет).
    bool g_conn[kMaxConn] = {};

    void RosterPut(int charId, int userNum, int charSlot, int connIdx)
    {
        if (charId == 0 || userNum < 0) { return; }
        RosterEntry& e = g_roster[(unsigned)charId & (kRosterSize - 1)];
        e.charId   = charId;
        e.userNum  = userNum;
        e.charSlot = charSlot;
        e.connIdx  = connIdx;
        e.tick     = GetTickCount();
    }

    bool RosterGet(int charId, RosterEntry* out)
    {
        const RosterEntry& e = g_roster[(unsigned)charId & (kRosterSize - 1)];
        if (charId == 0 || e.charId != charId) { return false; }
        *out = e;
        return true;
    }

    // ── список опкодов с «8-байтовой шапкой» тела ───────────────────────────
    //   userNum i16 @+0 · charId i32 @+2 · Charidx i8 @+6 · группа i8 @+7
    //   (сняты с обработчиков DBManager, у всех `sub_407390(SHIBYTE(...))`)
    const WORD kPrefixOps[] =
    {
        2250, 2252, 2256, 2257, 2258, 2262, 2266,   // стоковые «славы»/«посещения»
        2330, 2331,                                  // наши, из P22
        2531, 2533, 2539, 2541, 2547, 2653, 2667, 2670
    };

    bool IsPrefixOp(WORD op)
    {
        for (int i = 0; i < ARRAYSIZE(kPrefixOps); ++i)
        {
            if (kPrefixOps[i] == op) { return true; }
        }
        return false;
    }

    // ── состояние пересчёта ─────────────────────────────────────────────────
    volatile LONG g_busy      = 0;   // один поток за раз
    volatile LONG g_sqlBroken = 0;   // база не отвечает — больше не тревожим
    int           g_failStreak = 0;  // подряд неудачных проходов
    DWORD         g_lastRun   = 0;   // GetTickCount последнего пересчёта

    // ★ Защита от бесконечного долбления: сколько проходов подряд мы уже пытаемся
    //   выдать это звание, а бит в маске так и не появился. Счётчик привязан к
    //   держателю: сменился charId — счёт начинается заново.
    int g_grantTry[kRatings] = {};
    int g_grantFor[kRatings] = {};
    DWORD         g_lastForced = 0;  // GetTickCount последней GM-команды
    bool          g_everForced = false;
    DWORD         g_lastFpRun  = 0;  // GetTickCount последнего пересчёта №2

    constexpr int kMaxFailStreak = 3;   // после стольких неудач подряд — отключаемся

    // ── один вызов процедуры под двумя рубежами защиты ──────────────────────
    //  status[0] — признак успеха, status[1] — число столбцов,
    //  status[2] — число строк, status[3] — размер строки.
    //  Второй рубеж — `__try/__except` (DLL собирается с /EHa).
    bool RunSql(DWORD* status, int conn, int a3, void* out, const char* sql)
    {
        if (g_sqlBroken) { return false; }
        status[0] = 0; status[1] = 0; status[2] = 0; status[3] = 0;
        memset(out, 0, kSqlBuf);
        __try
        {
            pSql(kDataSrc, status, conn, a3, out, "%s", sql);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedExchange(&g_sqlBroken, 1);
            Log::Line(L"    P23: ! исключение на запросе «%hs» — отправитель званий 65…69 "
                      L"отключён до перезапуска (миграция базы не выполнена?)", sql);
            return false;
        }
        return status[0] != 0;
    }

    // Проверка формы ответа. false — форма не та, работать нельзя.
    bool RowsOk(const wchar_t* what, const DWORD* status, int cols, int minRow, int maxRows)
    {
        const int rows   = (int)status[2];
        const int stride = (int)status[3];
        if ((int)status[1] != cols || rows < 1 || stride < minRow
            || rows > maxRows || rows * stride > kSqlBuf)
        {
            Log::Line(L"    P23: ! %s вернула не ту форму (столбцов %d, ждём %d; строк %d; "
                      L"шаг %d, ждём >= %d) — проход прерван",
                      what, (int)status[1], cols, rows, stride, minRow);
            return false;
        }
        return true;
    }

    // ── ★★★ СВЕРКА С ФАКТОМ: стоит ли бит звания в маске персонажа ─────────
    //  Единственный способ узнать, ДОШЛА ли выдача: путь 3404…3408 односторонний,
    //  GameServer подтверждения не шлёт (в приёмнике sub_54D710 ответа нет вовсе).
    //  Поэтому «заявленное» состояние (FameRatingHolder.Granted) сверяем с
    //  «фактическим» (маска в базе) на КАЖДОМ проходе.
    //  ⚠ Затирает out/status — вызывать только там, где строки уже сняты в свой массив.
    //  Возвращает false, если сам запрос не выполнился (тогда решения не меняем).
    bool QueryBit(DWORD* status, int conn, int a3, void* out,
                  int charId, int slot, int titleId,
                  bool* bitSet, bool* rowFound, bool* inSlot, int* half)
    {
        *bitSet = false; *rowFound = false; *inSlot = false; *half = 0;

        char sql[160] = {};
        _snprintf(sql, sizeof(sql) - 1,
                  "EXEC dbo.UPCharFameBitInfo %d, %d, %d", charId, slot, titleId);
        if (!RunSql(status, conn, a3, out, sql)) { return false; }
        if (!RowsOk(L"UPCharFameBitInfo", status, kBiCols, kBiMinRow, 1)) { return false; }

        const BYTE* b = (const BYTE*)out;
        *bitSet   = RdU8(b, kBiBitWasSet) != 0;
        *rowFound = RdU8(b, kBiRowFound)  != 0;
        *inSlot   = RdU8(b, kBiInSlot)    != 0;
        *half     = RdU8(b, kBiHalf);
        return true;
    }

    // ── отправка одной записи ВСЕМ подключённым GameServer'ам ───────────────
    //   flag = 0 выдать / 1 снять; userNum обязан быть в 0…549 (см. Sendable),
    //   иначе стоковый sub_54D710 оборвёт разбор пакета.
    //
    //   ★★★ charSlot — НОМЕР СЛОТА ПЕРСОНАЖА (`Charidx`), в записи лежит как
    //   `слот + 1` в байтах +10…+11. Плюс единица нужна, чтобы отличить
    //   «слот не задан» (0) от «слот 0». Зачем вообще:
    //     на этом сервере у ОДНОГО аккаунта может быть НЕСКОЛЬКО ЖИВЫХ СЕССИЙ
    //     одновременно (доказано P24: `GM_Rimy` и `ADM_sitxovski` — оба
    //     UserIndex = 2, слоты 10 и 11, входы 18:20:14 и 18:21:02). Поиск только
    //     по UserIndex находил не того персонажа либо не находил вовсе, и выдача
    //     не доезжала. P24 теперь ищет точно: UserIndex + слот (`CUser+0x18C`),
    //     затем подсказка userNum, и лишь потом одиночный UserIndex — и то
    //     только когда слот НЕ задан. Пока мы клали сюда нули, точный поиск
    //     не включался и работал именно тот запасной путь, который промахивался.
    int SendRecord(int titleId, int charId, int userNum, int value, BYTE flag, int charSlot)
    {
        // ★ Последний рубеж: наружу не должна уйти запись с негодным userNum,
        //   даже если выше по коду кто-то забыл проверить (см. Sendable).
        if (!Sendable(userNum)) { return 0; }

        BYTE rec[kRecLen] = {};
        *(int*)  &rec[0]  = value;               // значение (сток читает только у 3409)
        *(int*)  &rec[4]  = charId;              // сверяется с CUser->gap_16B
        *(short*)&rec[8]  = (short)(WORD)userNum;

        // ★ +10…+11 = слот + 1. `Charidx` в базе — TINYINT (0…255), но
        //   подстраховываемся: всё, что вне 0…65534, считаем «слот не задан» (0),
        //   и тогда P24 честно уходит на запасной путь вместо ложного точного.
        WORD slotField = 0;
        if (charSlot >= 0 && charSlot <= 65534) { slotField = (WORD)(charSlot + 1); }
        *(WORD*)&rec[10] = slotField;

        rec[12] = flag;                          // ★ P24: 0 = выдать, 1 = снять

        const int op = kOpRankBase + (titleId - kTitleBase);
        int sent = 0;
        for (int c = 0; c < kMaxConn; ++c)
        {
            if (!g_conn[c]) { continue; }
            // sub_44E2F0 сама проверяет живость соединения (sub_44CF90) и
            // возвращает 0 для мёртвого — отдельная проверка не нужна.
            if (pSend(kSendThis, nullptr, op, kRecLen, c, rec, userNum)) { ++sent; }
        }
        return sent;
    }

    // ── Решение «слать ли живой пакет» и с каким userNum ────────────────────
    //  Два источника, оба проверяются одним порогом Sendable (0…549):
    //    1) наша таблица онлайна — самый надёжный признак: мы своими глазами
    //       видели DB-пакеты этой сессии и знаем её номер;
    //    2) столбец UserNum из базы (dbo.CharPos.Usernum через представление);
    //       представление уже нормализует NULL / <0 / >549 в −1 «не слать».
    //  false = пакет НЕ отправляем (в *why — причина для журнала). Это НЕ отказ
    //  от операции: правка в базе идёт всё равно, своим путём.
    bool Resolve(int charId, int charSlot, int dbUserNum, int* userNum, const wchar_t** why)
    {
        *userNum = kNoUserNum;

        RosterEntry e;
        if (RosterGet(charId, &e))
        {
            if (g_matchSlot && e.charSlot != charSlot)
            {
                // ★ Дефект ОРИГИНАЛА (закон fix-original-defects): ни сток, ни P24
                //   не сверяют Charidx, а у аккаунта до трёх персонажей — звание
                //   ушло бы ДРУГОМУ персонажу того же аккаунта.
                *why = L"в игре другой слот этого аккаунта (MatchCharSlot=1)";
                return false;
            }
            if (Sendable(e.userNum))
            {
                *userNum = e.userNum;
                *why = L"";
                return true;
            }
        }

        if (g_useOnline && Sendable(dbUserNum))
        {
            *userNum = dbUserNum;
            *why = L"";
            return true;
        }

        // ★ Сюда попадают офлайновые и все, у кого userNum вне 0…549.
        //   Такую запись слать НЕЛЬЗЯ: стоковый sub_54D710 на ней делает `break`
        //   и теряет весь остаток пакета (см. комментарий у kUserSlotMax).
        *why = L"сессии нет или userNum вне 0…549 — пакет не шлём";
        return false;
    }

    // ── сам пересчёт. Выполняется на рабочем потоке DBManager ───────────────
    //  rep — куда сложить числа для отчёта оператору (nullptr при обычном
    //  проходе по таймеру: считать некому и отправлять некуда).
    void RunPass(int a3, ForceReport* rep = nullptr)
    {
        BYTE* out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
        if (!out) { return; }

        DWORD status[8] = {};
        const int conn = pGetConn(kDispThis, nullptr, g_group);
        bool ok = true;

        // ── шаги 1…3: пятёрка лидеров ──────────────────────────────────────
        // rawName — те же 21 байт имени, что лежат в строке ответа, БЕЗ перекодировки:
        // они уезжают в отчёт оператору и дальше в чат, где кодировка та же.
        struct TopRow { int titleId, charId, charSlot, online, userNum, value; __int64 raw;
                        wchar_t name[24]; char rawName[21]; };
        TopRow top[kRatings] = {};
        int    topN = 0;

        static const struct { const char* sql; int rows; } kTopCalls[] =
        {
            { "EXEC dbo.UPTopLevelAll",   1 },   // звание 65
            { "EXEC dbo.UPTopLevelClass", 3 },   // звания 66, 67, 68
            { "EXEC dbo.UPTopGold",       1 },   // звание 69
        };

        for (int c = 0; c < ARRAYSIZE(kTopCalls) && ok; ++c)
        {
            if (!RunSql(status, conn, a3, out, kTopCalls[c].sql))
            {
                Log::Line(L"    P23: ! запрос «%hs» не выполнился", kTopCalls[c].sql);
                ok = false;
                break;
            }
            if (!RowsOk(L"топ-процедура", status, kTopCols, kTopMinRow, kRatings)) { ok = false; break; }

            const int rows   = (int)status[2];
            const int stride = (int)status[3];
            for (int r = 0; r < rows && topN < kRatings; ++r)
            {
                const BYTE* row = out + r * stride;
                TopRow& t = top[topN];
                t.titleId  = RdU8 (row, kTopTitleId);
                t.charSlot = RdU8 (row, kTopCharIdx);
                t.online   = RdU8 (row, kTopOnline);
                t.value    = RdI32(row, kTopValue);
                t.charId   = RdI32(row, kTopCharId);
                t.userNum  = RdI32(row, kTopUserNum);   // база уже нормализует «не слать» в −1
                t.raw      = RdI64(row, kTopValueRaw);
                RdName(row, kTopName, stride, t.name, ARRAYSIZE(t.name));
                // сырые байты имени — для отчёта оператору (см. RdName: там же
                // разобрано, почему столбец CHAR(21) и почему он всегда последний)
                if (stride >= kTopName + kNameBytes)
                {
                    memcpy(t.rawName, row + kTopName, kNameBytes);
                }
                if (t.titleId < kTitleBase || t.titleId > kTitleLast)
                {
                    Log::Line(L"    P23: ! «%hs» строка %d: TitleId=%d вне 65…69 — "
                              L"раскладка строки не сошлась, проход прерван",
                              kTopCalls[c].sql, r, t.titleId);
                    ok = false;
                    break;
                }
                ++topN;
            }
        }

        // ── шаг 4: держатель + смена лидера ────────────────────────────────
        for (int i = 0; i < topN && ok; ++i)
        {
            const TopRow& t = top[i];
            if (t.charId == 0) { continue; }          // кандидата нет — не ошибка

            char sql[256] = {};
            _snprintf(sql, sizeof(sql) - 1, "EXEC dbo.UPFameRatingHolderUp %d, %d, %d, %I64d",
                      t.titleId, t.charId, t.charSlot, t.raw);
            if (!RunSql(status, conn, a3, out, sql))
            {
                Log::Line(L"    P23: ! UPFameRatingHolderUp не выполнилась (звание %d)", t.titleId);
                ok = false;
                break;
            }
            if (!RowsOk(L"UPFameRatingHolderUp", status, kHupCols, kHupMinRow, 1)) { ok = false; break; }

            const BYTE* row = out;
            const int changed    = RdU8 (row, kHupChanged);
            const int prevSlot   = RdU8 (row, kHupPrevSlot);
            const int prevGrant  = RdU8 (row, kHupPrevGrant);
            const int prevCharId = RdI32(row, kHupPrevCharId);
            wchar_t prevName[24]; RdName(row, kHupName, (int)status[3], prevName, ARRAYSIZE(prevName));

            if (!changed)
            {
                // ★ Не молчим: судьба каждого из пяти званий должна быть видна
                //   в журнале — иначе пропажа выдачи ловится только по базе.
                Log::Line(L"    P23: звание %d — лидер не сменился (charId=%d слот %d «%s»)",
                          t.titleId, t.charId, t.charSlot, t.name);
                continue;
            }

            // ★ для отчёта оператору (GM-команда): кто теперь носит это звание.
            //   Считаем СМЕНУ ЛИДЕРА, а не факт отправки пакета: смена уже
            //   записана в базу, даже если живой сессии сейчас нет.
            if (rep)
            {
                ++rep->changed;
                if (rep->nLead < kRepMaxList)
                {
                    rep->leadTitle[rep->nLead] = (BYTE)t.titleId;
                    memcpy(rep->leadName[rep->nLead], t.rawName, sizeof(t.rawName));
                    ++rep->nLead;
                }
            }

            // 4a. Прежнего держателя САМИ НЕ ТРОГАЕМ: `UPFameRatingHolderUp` уже
            //     положила задание в `dbo.FameRatingRevoke` в СВОЕЙ транзакции.
            //     Шаг 6 этого же прохода разберёт очередь единым путём
            //     (база + пакет + отметка), поэтому второго кода снятия нет.
            if (prevCharId != 0 && prevGrant && prevCharId != t.charId)
            {
                Log::Line(L"    P23: звание %d — прежний держатель charId=%d слот %d «%s» "
                          L"поставлен в очередь снятия (разберём на шаге 6 этого прохода)",
                          t.titleId, prevCharId, prevSlot, prevName);
            }

            // 4b. выдать новому (признак 0) + отметить выдачу в базе
            int unum = kNoUserNum;
            const wchar_t* why = L"";
            if (!Resolve(t.charId, t.charSlot, t.userNum, &unum, &why))
            {
                Log::Line(L"    P23: звание %d — новый лидер charId=%d слот %d «%s» значение=%I64d, "
                          L"живая выдача отложена: %s (запись держателя в базе поставлена)",
                          t.titleId, t.charId, t.charSlot, t.name, t.raw, why);
                continue;                              // Granted остаётся 0 — добьём на шаге 5
            }

            const int n = g_send ? SendRecord(t.titleId, t.charId, unum, t.value, kFlagGrant, t.charSlot) : 0;
            Log::Line(L"    P23: звание %d ← charId=%d слот %d «%s» значение=%I64d "
                      L"(опкод %d, признак 0, userNum=%d%s, соединений %d)%s",
                      t.titleId, t.charId, t.charSlot, t.name, t.raw,
                      kOpRankBase + (t.titleId - kTitleBase), unum, L"", n,
                      g_send ? L"" : L" [SendPackets=0]");

            if (g_send && n > 0)
            {
                _snprintf(sql, sizeof(sql) - 1, "EXEC dbo.UPFameRatingHolderFlagUp %d, %d, 1", t.titleId, t.charId);
                RunSql(status, conn, a3, out, sql);    // результат нам не нужен
            }
        }

        // ── шаг 5: СВЕРКА заявленного с фактическим + довыдача ─────────────
        //
        // ★★★ ДЕФЕКТ, НАЙДЕННЫЙ ЖИВЫМ ПРОГОНОМ 30.08.2026 (выдавалось ровно ОДНО
        //     звание за проход, остальные пропадали МОЛЧА):
        //     цикл шёл ПО БУФЕРУ `out`, а внутри цикла вызывался
        //     `UPFameRatingHolderFlagUp` через ту же `RunSql`, которая делает
        //     `memset(out, 0, kSqlBuf)` и кладёт туда СВОЙ однострочный ответ.
        //     После первой же отметки строки 2…5 читались из обнулённого буфера,
        //     давали `titleId = 0` и молча отбрасывались проверкой диапазона.
        //     Симптом на боевом: у charId=2 выдалось 65, а 67 и 69 остались
        //     Granted = 0; в журнале — ровно одна строка «ДОВЫДАНО».
        //     Лечение: СНАЧАЛА снять весь набор строк в свой массив, и только
        //     потом ходить в базу. Ровно так уже сделано в шаге 6 — здесь забыли.
        if (ok && RunSql(status, conn, a3, out, "EXEC dbo.UPFameRatingHolder")
            && RowsOk(L"UPFameRatingHolder", status, kHolCols, kHolMinRow, kRatings))
        {
            struct HolRow { int titleId, slot, granted, charId; __int64 val; };
            HolRow hol[kRatings] = {};
            int    holN = 0;

            {   // ← снимок ДО любого вложенного запроса
                const int rows   = (int)status[2];
                const int stride = (int)status[3];
                for (int r = 0; r < rows && holN < kRatings; ++r)
                {
                    const BYTE* row = out + r * stride;
                    HolRow& h = hol[holN];
                    h.titleId = RdU8 (row, kHolTitleId);
                    h.slot    = RdU8 (row, kHolCharIdx);
                    h.granted = RdU8 (row, kHolGranted);
                    h.charId  = RdI32(row, kHolCharId);
                    h.val     = RdI64(row, kHolValue);
                    ++holN;
                }
            }

            for (int r = 0; r < holN; ++r)
            {
                const HolRow& h = hol[r];

                // ★ Судьба КАЖДОГО звания видна в журнале — молчаливых пропусков
                //   больше нет (именно из-за них дефект затёртого буфера жил незаметно).
                if (h.titleId < kTitleBase || h.titleId > kTitleLast)
                {
                    Log::Line(L"    P23: звание ? — ПРОПУЩЕНО: TitleId=%d вне 65…69 "
                              L"(строка %d ответа UPFameRatingHolder)", h.titleId, r);
                    continue;
                }
                const int rating = h.titleId - kTitleBase;
                if (h.charId == 0)
                {
                    g_grantTry[rating] = 0; g_grantFor[rating] = 0;
                    Log::Line(L"    P23: звание %d — ПРОПУЩЕНО: держателя нет (CharId=0)",
                              h.titleId);
                    continue;
                }

                // ── ★★★ СВЕРКА ЗАЯВЛЕННОГО С ФАКТИЧЕСКИМ ──────────────────
                //  Granted = 1 ставится по факту ОТПРАВКИ, а не применения:
                //  подтверждения нам никто не шлёт. Значит отметка может врать —
                //  пакет мог потеряться (обрыв разбора списка, рестарт сервера,
                //  отвалившееся соединение, выход игрока между отправкой и
                //  применением). Поэтому каждый проход спрашиваем маску.
                bool bitSet = false, rowFound = false, inSlot = false;
                int  half = 0;
                const bool asked = QueryBit(status, conn, a3, out,
                                            h.charId, h.slot, h.titleId,
                                            &bitSet, &rowFound, &inSlot, &half);
                if (!asked)
                {
                    Log::Line(L"    P23: звание %d — ПРОПУЩЕНО: UPCharFameBitInfo не "
                              L"ответила, состояние не сверено (charId=%d слот %d)",
                              h.titleId, h.charId, h.slot);
                    continue;                       // решений на догадках не принимаем
                }

                // Смена держателя обнуляет счётчик попыток.
                if (g_grantFor[rating] != h.charId)
                {
                    g_grantFor[rating] = h.charId;
                    g_grantTry[rating] = 0;
                }

                if (h.granted && bitSet)
                {
                    g_grantTry[rating] = 0;         // всё сошлось
                    Log::Line(L"    P23: звание %d — выдано и подтверждено маской "
                              L"(charId=%d слот %d, половина %s%s)",
                              h.titleId, h.charId, h.slot,
                              half ? L"старшая" : L"младшая",
                              inSlot ? L", надето" : L"");
                    continue;
                }

                // ── рассинхрон или обычная довыдача ───────────────────────
                const bool lied = (h.granted != 0);  // отметка стояла, а бита нет
                if (lied)
                {
                    Log::Line(L"    P23: ★ звание %d — ОТМЕТКА ВРАЛА (Granted=1, а бита в "
                              L"маске НЕТ): charId=%d слот %d, строка маски %s. "
                              L"Сбрасываю отметку и выдаю повторно",
                              h.titleId, h.charId, h.slot,
                              rowFound ? L"есть" : L"ОТСУТСТВУЕТ");

                    // Сначала честно снимаем отметку в базе: если упадём между
                    // сбросом и выдачей, состояние останется «не выдано», и
                    // следующий проход доделает. Обратный порядок оставил бы ложь.
                    char sql0[128] = {};
                    _snprintf(sql0, sizeof(sql0) - 1,
                              "EXEC dbo.UPFameRatingHolderFlagUp %d, %d, 0", h.titleId, h.charId);
                    RunSql(status, conn, a3, out, sql0);
                }

                // ★ Предохранитель от бесконечного долбления.
                if (g_grantTry[rating] >= g_maxGrantTry)
                {
                    Log::Line(L"    P23: !!! звание %d — ВЫДАЧА НЕ ДОХОДИТ: %d попыток подряд, "
                              L"бит в маске так и не появился (charId=%d слот %d, строка маски %s). "
                              L"Больше не пытаюсь до смены держателя или перезапуска — РАЗБИРАЙТЕСЬ",
                              h.titleId, g_grantTry[rating], h.charId, h.slot,
                              rowFound ? L"есть" : L"ОТСУТСТВУЕТ");
                    continue;
                }

                // ★ У UPFameRatingHolder столбца UserNum нет — опираемся только
                //   на свою таблицу онлайна.
                int unum = kNoUserNum;
                const wchar_t* why = L"";
                if (!Resolve(h.charId, h.slot, kNoUserNum, &unum, &why))
                {
                    Log::Line(L"    P23: звание %d — ПРОПУЩЕНО: charId=%d слот %d, %s "
                              L"(Granted=0, повторим на следующем проходе)",
                              h.titleId, h.charId, h.slot, why);
                    continue;                       // попытку не считаем: мы даже не слали
                }

                const int v = (h.val > 2147483647i64) ? 2147483647 : (int)h.val;
                const int n = g_send ? SendRecord(h.titleId, h.charId, unum, v, kFlagGrant, h.slot) : 0;
                if (n > 0) { ++g_grantTry[rating]; }
                if (rep) { ++rep->regrant; }

                Log::Line(L"    P23: звание %d — %s charId=%d слот %d значение=%I64d "
                          L"(опкод %d, признак 0, userNum=%d, соединений %d, попытка %d из %d)%s",
                          h.titleId,
                          lied ? L"ВЫДАНО ПОВТОРНО" : L"ВЫДАНО",
                          h.charId, h.slot, h.val,
                          kOpRankBase + (h.titleId - kTitleBase), unum, n,
                          g_grantTry[rating], g_maxGrantTry,
                          g_send ? L"" : L" [SendPackets=0]");

                // ★ Отметку ставим КАК МОЖНО ПОЗЖЕ — только после того, как пакет
                //   реально ушёл хотя бы в одно соединение.
                if (g_send && n > 0)
                {
                    char sql[128] = {};
                    _snprintf(sql, sizeof(sql) - 1,
                              "EXEC dbo.UPFameRatingHolderFlagUp %d, %d, 1", h.titleId, h.charId);
                    // ⚠ Затирает out и status — строки сняты в hol[] заранее.
                    if (!RunSql(status, conn, a3, out, sql))
                    {
                        Log::Line(L"    P23: ! звание %d — пакет ушёл, но отметить Granted=1 "
                                  L"не удалось; повторим на следующем проходе", h.titleId);
                    }
                }
                else if (n == 0)
                {
                    Log::Line(L"    P23: звание %d — пакет НЕ ушёл ни в одно соединение, "
                              L"отметку Granted не ставим", h.titleId);
                }
            }
        }

        // ── шаг 6: очередь снятия (пережила рестарт; здесь же догоняем офлайн) ──
        if (ok && RunSql(status, conn, a3, out, "EXEC dbo.UPFameRatingRevokeList")
            && RowsOk(L"UPFameRatingRevokeList", status, kRevCols, kRevMinRow, kMaxRevoke))
        {
            const int rows   = (int)status[2];
            const int stride = (int)status[3];
            // Строки копируем ДО первого вложенного запроса: `out` будет перезаписан.
            struct RevRow { __int64 id; int titleId, slot, online, charId, userNum; wchar_t name[24]; };
            RevRow rev[kMaxRevoke] = {};
            int    revN = 0;
            for (int r = 0; r < rows && revN < kMaxRevoke; ++r)
            {
                const BYTE* row = out + r * stride;
                RevRow& q = rev[revN];
                q.id      = RdI64(row, kRevId);
                q.titleId = RdU8 (row, kRevTitleId);
                q.slot    = RdU8 (row, kRevCharIdx);
                q.online  = RdU8 (row, kRevOnline);
                q.charId  = RdI32(row, kRevCharId);
                q.userNum = RdI32(row, kRevUserNum);   // база нормализует «не слать» в −1
                RdName(row, kRevName, stride, q.name, ARRAYSIZE(q.name));
                if (q.id == 0 || q.charId == 0) { continue; }   // пустая очередь
                if (q.titleId < kTitleBase || q.titleId > kTitleLast) { continue; }
                ++revN;
            }

            for (int i = 0; i < revN; ++i)
            {
                const RevRow& q = rev[i];
                char sql[192] = {};

                // 6a. ★ СНЯТИЕ В БАЗЕ — работает и для офлайнового, и для онлайнового.
                //     Закрывает дыру «до IntervalSec носит уже отобранное звание»:
                //     при следующем входе стоковый путь (UPCharFameBank → 2256 →
                //     recvDBUserFameBitInfo) отдаст уже урезанную маску.
                //     Покрыты обе половины маски (id < 256 и id >= 256, P22).
                bool dbOk = false, bitWasSet = false, slotCleared = false, rowFound = false;
                int  half = 0;
                _snprintf(sql, sizeof(sql) - 1,
                          "EXEC dbo.UPCharFameBitDis %d, %d, %d, %d, 1",
                          q.charId, q.slot, q.titleId, g_clearSlot ? 1 : 0);
                if (RunSql(status, conn, a3, out, sql)
                    && RowsOk(L"UPCharFameBitDis", status, kBdCols, kBdMinRow, 1))
                {
                    const BYTE* b = out;
                    dbOk        = RdU8(b, kBdResult)   != 0;
                    bitWasSet   = RdU8(b, kBdBitWasSet)!= 0;
                    slotCleared = RdU8(b, kBdSlotClr)  != 0;
                    rowFound    = RdU8(b, kBdRowFound) != 0;
                    half        = RdU8(b, kBdHalf);

                    if (!dbOk && !rowFound)
                    {
                        // Строки маски у персонажа нет вовсе — повторять бессмысленно,
                        // но задание закрываем, иначе оно будет крутиться вечно.
                        Log::Line(L"    P23: звание %d — очередь #%I64d: у charId=%d слот %d «%s» "
                                  L"НЕТ строки маски (RowFound=0) — задание закрыто без снятия",
                                  q.titleId, q.id, q.charId, q.slot, q.name);
                    }
                    else if (!dbOk)
                    {
                        Log::Line(L"    P23: звание %d — очередь #%I64d: в базе снимать было нечего "
                                  L"(бит уже чист), считаем успехом", q.titleId, q.id);
                    }
                    else
                    {
                        Log::Line(L"    P23: звание %d — очередь #%I64d: бит снят В БАЗЕ у charId=%d "
                                  L"слот %d «%s» (половина маски %s)",
                                  q.titleId, q.id, q.charId, q.slot, q.name,
                                  half ? L"старшая, CharFameHigh" : L"младшая, CharFameBank");
                    }
                    // ⚠ Слот мог не очиститься: если SQL-тип Fmidx1/Fmidx2 окажется
                    //   tinyint, -1 туда не влезет. Не молчим об этом (просил агент базы).
                    if (g_clearSlot && bitWasSet && !slotCleared)
                    {
                        Log::Line(L"    P23: ! звание %d, очередь #%I64d: бит снят, а СЛОТ НЕ ОЧИЩЕН "
                                  L"(SlotCleared=0). Если персонаж носил звание — проверьте тип "
                                  L"Fmidx1/Fmidx2 в базе (tinyint не примет -1) и поставьте "
                                  L"[P23_TitleRankFeed] ClearSlot=0", q.titleId, q.id);
                    }
                }
                else
                {
                    Log::Line(L"    P23: ! звание %d, очередь #%I64d: UPCharFameBitDis не отработала "
                              L"— задание оставлено в очереди", q.titleId, q.id);
                    continue;                 // НЕ отмечаем Done: попробуем в следующий проход
                }

                // 6b. ★ И ПАКЕТ ТОЖЕ — правка базы НЕ заменяет его для живой сессии:
                //     сессия (в том числе на другом канале) при выходе может записать
                //     свою маску ПОВЕРХ снятого в базе бита. Предупреждение агента базы.
                //     ⚠ Но только с ГОДНЫМ userNum (0…549): запись с негодным номером
                //     стоковый sub_54D710 не пропускает, а обрывает разбор пакета.
                int unum = kNoUserNum;
                const wchar_t* why = L"";
                // Слот здесь не сверяем: снятие адресовано конкретному charId,
                // и «не тот слот» не повод оставить чужое звание висеть.
                RosterEntry e;
                if (RosterGet(q.charId, &e) && Sendable(e.userNum))   { unum = e.userNum; }
                else if (g_useOnline && Sendable(q.userNum))          { unum = q.userNum; }
                else { why = L"сессии нет или userNum вне 0…549"; }

                const int n = (Sendable(unum) && g_send)
                            ? SendRecord(q.titleId, q.charId, unum, 0, kFlagRevoke, q.slot) : 0;

                if (Sendable(unum))
                {
                    Log::Line(L"    P23: звание %d — очередь #%I64d: %s (опкод %d, признак 1, "
                              L"userNum=%d, соединений %d)",
                              q.titleId, q.id,
                              g_send ? L"пакет снятия отправлен" : L"пакет подавлен [SendPackets=0]",
                              kOpRankBase + (q.titleId - kTitleBase), unum, n);
                }
                else
                {
                    Log::Line(L"    P23: звание %d — очередь #%I64d: пакет НЕ шлём (%s). "
                              L"Снятие уже сделано В БАЗЕ — при входе персонаж получит "
                              L"урезанную маску штатным путём",
                              q.titleId, q.id, why);
                }

                if (rep) { ++rep->revoked; }          // «снято» в отчёт оператору

                // 6c. отметить задание выполненным
                if (g_send)
                {
                    _snprintf(sql, sizeof(sql) - 1, "EXEC dbo.UPFameRatingRevokeUp %I64d", q.id);
                    RunSql(status, conn, a3, out, sql);
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, out);

        if (rep && !ok) { rep->status = kStatusDbDown; }

        // ★ Итог прохода одной строкой — сразу видно, все ли пять званий разобраны.
        Log::Line(L"    P23: === проход окончен: рейтингов разобрано %d из %d, "
                  L"смен лидера %d, довыдач %d, снятий %d ===",
                  topN, kRatings,
                  rep ? rep->changed : -1, rep ? rep->regrant : -1, rep ? rep->revoked : -1);

        // ── учёт неудач: транзиентный сбой не должен убивать патч навсегда ──
        if (ok)
        {
            g_failStreak = 0;
        }
        else if (++g_failStreak >= kMaxFailStreak)
        {
            InterlockedExchange(&g_sqlBroken, 1);
            Log::Line(L"    P23: ! %d неудачных прохода подряд — отправитель званий 65…69 "
                      L"отключён до перезапуска (нет процедур рейтингов в базе?)", g_failStreak);
        }
    }


    // ── ★★★ ПЕРЕСЧЁТ №2: EXEC UPTopFamePoint → рассылка 3409 ────────────────
    //  Это ровно то, что делает стоковый RelayServer по задаче ChannelManager
    //  «Title Rank Process» в 03:00 (и по клавише консоли, см. блок констант
    //  kOpFamePoint выше — там же доказательство «строка ответа = запись пакета»).
    //
    //  ⚠ Пакет шлём ПО ОДНОЙ записи, как и 3404…3408: стоковый приёмник
    //    sub_54D710 при первом же несовпадении делает break, а не continue,
    //    поэтому один чужой/офлайновый в списке съел бы весь остаток.
    //  ⚠ Рассылаем по тем же живым соединениям, что и звания (g_conn): там сидят
    //    GameServer и Indun_GameServer; лишний адресат просто не найдёт у себя
    //    сессию и запись пропадёт без последствий.
    //  Возвращает false, только если ЗАПРОС не выполнился (это ошибка прохода).
    bool RunFamePointPass(int a3, int conn, DWORD* status, BYTE* out,
                          int* outRows, int* outSent)
    {
        *outRows = 0;
        *outSent = 0;

        if (!RunSql(status, conn, a3, out, "EXEC dbo.UPTopFamePoint"))
        {
            Log::Line(L"    P23: ! EXEC dbo.UPTopFamePoint не выполнилась — "
                      L"место в топе по очкам славы не пересчитано");
            // ★ Самая частая причина — ПУСТОЙ набор строк: sub_447720 считает ноль
            //   строк НЕУДАЧЕЙ вызова, а стоковая процедура фильтрует
            //   `WHERE Userindex > 5000` (это операторский диапазон 0…5000).
            //   После перенумерации аккаунтов (sitxovski -> 1, Rimy -> 2) под фильтр
            //   не попадает НИКТО, и топ славы законно пуст. Менять стоковую
            //   процедуру мы не вправе — говорим об этом прямо.
            Log::Line(L"    P23:   подсказка: dbo.UPTopFamePoint отбирает только "
                      L"Userindex > 5000. Если все аккаунты имеют меньшие номера, "
                      L"набор ПУСТ, и это не сбой базы, а её стоковый фильтр");
            return false;
        }
        // Форма ответа: 6 столбцов, строка ровно 13 байт (int·int·smallint·3×tinyint).
        // Нулевых наборов у sub_447720 не бывает: при пустом топе приедет строка,
        // которую отсеет проверка userNum, поэтому rows >= 1 законно.
        if (!RowsOk(L"UPTopFamePoint", status, kFpCols, kRecLen, kFpMaxRows))
        {
            return false;
        }

        const int rows   = (int)status[2];
        const int stride = (int)status[3];
        *outRows = rows;

        // ★ Вложенных запросов в этом цикле НЕТ — `out` не затирается (та самая
        //   ловушка, на которой сгорел шаг 5: RunSql делает memset(out) и кладёт
        //   туда свой ответ, поэтому строки 2…N читались из нулей). Здесь мы
        //   только шлём пакеты, поэтому снимок в отдельный массив не нужен.
        int offline = 0;
        for (int r = 0; r < rows; ++r)
        {
            const BYTE* row = out + r * stride;

            // Отсев офлайна — 1:1 с оригиналом (`word[запись+8] > -1`).
            const int unum = *(const short*)(row + kFpUserNumAt);
            if (!Sendable(unum)) { ++offline; continue; }

            // ★ Строку шлём КАК ЕСТЬ: она уже и есть 13-байтная запись пакета.
            BYTE rec[kRecLen];
            memcpy(rec, row, kRecLen);

            // ★★★ ВНИМАНИЕ: с приходом P24 байты +10…+11 ПЕРЕСТАЛИ быть резервом —
            //   теперь это «слот персонажа + 1», и при непустом значении приёмник
            //   переходит на ТОЧНЫЙ поиск, а при несовпадении запись НЕ применяет.
            //   Здесь строка приходит из СТОКОВОЙ `UPTopFamePoint` (6 столбцов:
            //   int·int·smallint·3×tinyint), и что лежит в двух её последних
            //   tinyint-ах — мы не знаем: тела процедуры у нас нет, она не наша.
            //   Пока это не выяснено, честно объявляем «слот не задан» (0), чтобы
            //   P24 работал по стоковому пути и поведение 3409 не изменилось.
            //   ⚠ Если окажется, что один из этих столбцов — реальный Charidx,
            //   сюда надо будет класть `Charidx + 1`, и топ славы станет точным.
            *(WORD*)&rec[10] = 0;

            int sent = 0;
            if (g_send)
            {
                for (int c = 0; c < kMaxConn; ++c)
                {
                    if (!g_conn[c]) { continue; }
                    if (pSend(kSendThis, nullptr, kOpFamePoint, kRecLen, c, rec, unum)) { ++sent; }
                }
            }
            if (sent > 0 || !g_send) { ++(*outSent); }
        }

        // ★ Без молчаливых пропусков: видно и сколько строк было, и сколько из них
        //   отсеяно как «не в сети» — иначе «разослано 0» неотличимо от поломки.
        Log::Line(L"    P23: топ по очкам славы пересчитан (EXEC dbo.UPTopFamePoint): "
                  L"строк %d, отсеяно офлайновых %d, разослано 3409 живым сессиям %d%s",
                  *outRows, offline, *outSent, g_send ? L"" : L" [SendPackets=0]");
        return true;
    }

    // ── ★ отчёт оператору: тело 2334 обратно тому GameServer'у, что попросил ─
    void SendForceReport(const BYTE* frcBody, int connIdx, const ForceReport& rep)
    {
        BYTE body[kRepMaxLen] = {};
        memcpy(&body[kRepUserNum], frcBody + kFrcUserNum, 2);   // i16 сессия оператора
        memcpy(&body[kRepUserIdx], frcBody + kFrcUserIdx, 4);   // i32 UserIndex
        body[kRepCharIdx] = frcBody[kFrcCharIdx];
        body[kRepStatus]  = (BYTE)rep.status;
        *(int*)&body[kRepMs]       = rep.ms;
        *(int*)&body[kRepChanged]  = rep.changed;
        *(int*)&body[kRepRevoked]  = rep.revoked;
        *(int*)&body[kRepRegrant]  = rep.regrant;
        *(int*)&body[kRepRankRows] = rep.rankRows;
        *(int*)&body[kRepRankSent] = rep.rankSent;

        int n = rep.nLead;
        if (n > kRepMaxList) { n = kRepMaxList; }
        body[kRepLeaders] = (BYTE)n;
        for (int i = 0; i < n; ++i)
        {
            BYTE* r = body + kRepList + kRepRecLen * i;
            r[0] = rep.leadTitle[i];
            memcpy(r + 1, rep.leadName[i], 21);
        }
        const int len = kRepList + kRepRecLen * n;

        // Отвечаем ИМЕННО в то соединение, откуда пришла команда: на другом
        // канале этой сессии нет, и ответ там был бы отброшен.
        if (connIdx < 0 || connIdx >= kMaxConn) { return; }
        pSend(kSendThis, nullptr, kOpReport, len, connIdx, body,
              *(const short*)(frcBody + kFrcUserNum));
    }

    // ── ★ GM-команда «пересчитать СЕЙЧАС» (опкод 2333 от патча P25) ─────────
    //  Выполняется ЗДЕСЬ ЖЕ, на рабочем потоке DBManager, в кадре его диспетчера:
    //  у нас есть законный `a3` и живое соединение с базой — ровно те условия,
    //  в которых работают стоковые обработчики. Своего потока патч не заводит.
    void RunForced(int a3, const BYTE* frcBody, int connIdx)
    {
        ForceReport rep = {};
        rep.status = kStatusOk;

        int what = frcBody[kFrcWhat];
        if (what < 0 || what > 2) { what = 0; }

        if (!g_onDemand)
        {
            rep.status = kStatusOff;
            SendForceReport(frcBody, connIdx, rep);
            return;
        }
        if (g_sqlBroken)
        {
            rep.status = kStatusDbDown;
            SendForceReport(frcBody, connIdx, rep);
            return;
        }

        // Порог частоты — АВТОРИТЕТНЫЙ (в GameServer стоит только зеркало).
        const DWORD now = GetTickCount();
        if (g_everForced && (DWORD)(now - g_lastForced) < (DWORD)g_minForceSec * 1000u)
        {
            rep.status = kStatusTooOften;
            SendForceReport(frcBody, connIdx, rep);
            Log::Line(L"    P23: GM-команда отклонена — не вышел порог MinForceSec=%d с",
                      g_minForceSec);
            return;
        }

        // Один проход за раз: и таймерный, и командный делят один флаг.
        if (InterlockedCompareExchange(&g_busy, 1, 0) != 0)
        {
            rep.status = kStatusBusy;
            SendForceReport(frcBody, connIdx, rep);
            return;
        }

        g_lastForced = now;
        g_everForced = true;
        const DWORD t0 = GetTickCount();

        // ── пересчёт №1: рейтинговые звания 65…69 ──────────────────────────
        if (what == 0 || what == 1)
        {
            g_lastRun = now;                 // командный проход сдвигает и таймер
            RunPass(a3, &rep);
        }

        // ── пересчёт №2: место в топе по очкам славы (то, что идёт в 03:00) ─
        if ((what == 0 || what == 2) && g_fpOnDemand && rep.status == kStatusOk)
        {
            BYTE* out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
            if (out)
            {
                DWORD st[8] = {};
                const int conn = pGetConn(kDispThis, nullptr, g_group);
                int rowsN = 0, sentN = 0;
                if (RunFamePointPass(a3, conn, st, out, &rowsN, &sentN))
                {
                    rep.rankRows = rowsN;
                    rep.rankSent = sentN;
                    g_lastFpRun  = now;
                }
                else
                {
                    rep.status = kStatusDbDown;
                }
                HeapFree(GetProcessHeap(), 0, out);
            }
        }

        rep.ms = (int)(GetTickCount() - t0);
        InterlockedExchange(&g_busy, 0);

        Log::Line(L"    P23: ★ GM-команда «пересчитать сейчас» (что=%d, соединение %d): "
                  L"итог=%d, %d мс, сменилось лидеров %d, снято %d, довыдано %d, "
                  L"строк топа славы %d (разослано %d)",
                  what, connIdx, rep.status, rep.ms, rep.changed, rep.revoked,
                  rep.regrant, rep.rankRows, rep.rankSent);

        SendForceReport(frcBody, connIdx, rep);
    }

    // ── наблюдатель: зовётся из трамплина, ebp — кадр диспетчера ────────────
    void __cdecl TitleRankTick(BYTE* hostEbp)
    {
        BYTE* pkt = *(BYTE**)(hostEbp - kFrmPkt);
        if (!pkt) { return; }

        const WORD op      = *(WORD*)(pkt + 7);
        const int  userNum = *(short*)(pkt + 3);
        const int  connIdx = *(WORD*)(pkt + 5);
        const BYTE* body   = pkt + 9;

        // 1) запомнить живое соединение — по ним пойдёт рассылка
        if (connIdx >= 0 && connIdx < kMaxConn) { g_conn[connIdx] = true; }

        // 2) пополнение таблицы онлайна (дёшево: сравнение опкода)
        if (op == 2001)
        {
            // CharLogonReq: charId i32 @+0, группа i16 @+4, Charidx i16 @+6
            RosterPut(*(const int*)(body + 0), userNum, *(const short*)(body + 6), connIdx);
        }
        else if (IsPrefixOp(op))
        {
            // «8-байтовая шапка»: charId i32 @+2, Charidx i8 @+6
            RosterPut(*(const int*)(body + 2), userNum, (signed char)body[6], connIdx);
        }

        // 3) ★ GM-команда «пересчитать СЕЙЧАС» (пара — патч GameServer P25).
        //    Стоковый диспетчер этот опкод не знает и уже прошёл мимо, а мы стоим
        //    в его ЭПИЛОГЕ — то есть разбираем ровно то, что сток выбросил.
        if (op == (WORD)kOpForce)
        {
            const int bodyLen = (int)*(WORD*)(pkt + 1) - 10;
            if (bodyLen >= kFrcLen)
            {
                RunForced(*(int*)(hostEbp + kFrmA3), body, connIdx);
            }
            return;                       // этот пакет больше ничем не занят
        }

        // 4) отложенный пересчёт: флаг по времени + выполнение на этом же тике
        if (g_sqlBroken) { return; }
        const DWORD now = GetTickCount();

        // 4а. периодический пересчёт №2 (топ по очкам славы). По умолчанию
        //     ВЫКЛЮЧЕН (0): в оригинале его гоняет ChannelManager в 03:00, и
        //     дублировать чужое расписание мы не вправе. Ключ — на случай, если
        //     владелец захочет чаще.
        if (g_fpIntervalSec > 0
            && (DWORD)(now - g_lastFpRun) >= (DWORD)g_fpIntervalSec * 1000u
            && InterlockedCompareExchange(&g_busy, 1, 0) == 0)
        {
            g_lastFpRun = now;
            BYTE* out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kSqlBuf);
            if (out)
            {
                DWORD st[8] = {};
                const int conn = pGetConn(kDispThis, nullptr, g_group);
                int rowsN = 0, sentN = 0;
                RunFamePointPass(*(int*)(hostEbp + kFrmA3), conn, st, out, &rowsN, &sentN);
                HeapFree(GetProcessHeap(), 0, out);
            }
            InterlockedExchange(&g_busy, 0);
        }

        // 4б. периодический пересчёт №1 (рейтинговые звания 65…69).
        if ((DWORD)(now - g_lastRun) < (DWORD)g_intervalSec * 1000u) { return; }
        if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) { return; }
        g_lastRun = now;
        RunPass(*(int*)(hostEbp + kFrmA3));
        InterlockedExchange(&g_busy, 0);
    }

    // ── трамплин на 0x4054BE (6 байт) ──────────────────────────────────────
    //   Вытеснено: mov ecx,[ebp-0x18]; sub ecx,[ebp-0x28]   (разность замера времени)
    //   Возврат на 0x4054C4. Все регистры и флаги сохраняются: следующая команда
    //   хоста (`mov edx,[ebp-0x14]; sbb edx,[ebp-0x24]`) продолжает 64-битное
    //   вычитание и ЗАВИСИТ ОТ ФЛАГА ПЕРЕНОСА, поэтому `sub` замыкает трамплин.
    DWORD g_p23Back = 0x004054C4;   // куда вернуться

    __declspec(naked) void TrampTitleRank()
    {
        __asm
        {
            pushfd
            pushad
            push  ebp                      // кадр диспетчера
            call  TitleRankTick
            add   esp, 4
            popad
            popfd
            mov   ecx, [ebp-P23_QPC_HI]    // ── вытесненные команды ──
            sub   ecx, [ebp-P23_QPC_LO]
            jmp   [g_p23Back]
        }
    }

    // ── площадка (байты сняты с ЖИВОГО образа DBManager.exe) ───────────────
    const DWORD kSiteTick = 0x004054BE;
    const BYTE  kOrigTick[6] =
    {
        0x8B, 0x4D, 0xE8,                   // mov ecx, [ebp-0x18]
        0x2B, 0x4D, 0xD8                    // sub ecx, [ebp-0x28]
    };
}

PatchResult P23_TitleRankFeed()
{
    g_enabled = Config::GetBool(kSec, L"Enabled", true);
    if (!g_enabled) { return PatchResult::Disabled; }

    g_send      = Config::GetBool(kSec, L"SendPackets", true);
    g_matchSlot = Config::GetBool(kSec, L"MatchCharSlot", true);
    g_useOnline = Config::GetBool(kSec, L"TrustIsOnline", true);
    g_clearSlot = Config::GetBool(kSec, L"ClearSlot", true);
    g_group     = Config::GetInt (kSec, L"ServerGroup", 0);

    g_maxGrantTry = Config::GetInt(kSec, L"MaxGrantAttempts", 3);
    if (g_maxGrantTry < 1)   { g_maxGrantTry = 1;   }
    if (g_maxGrantTry > 100) { g_maxGrantTry = 100; }

    g_intervalSec = Config::GetInt(kSec, L"IntervalSec", 600);
    if (g_intervalSec < 30)    { g_intervalSec = 30;    }   // защита от опечатки в ini
    if (g_intervalSec > 86400) { g_intervalSec = 86400; }

    // ★ GM-команда «пересчитать сейчас» (пара — патч GameServer P25).
    g_onDemand      = Config::GetBool(kSec, L"OnDemand", true);
    g_fpOnDemand    = Config::GetBool(kSec, L"FamePointOnDemand", true);
    g_minForceSec   = Config::GetInt (kSec, L"MinForceSec", 60);
    g_fpIntervalSec = Config::GetInt (kSec, L"FamePointIntervalSec", 0);
    if (g_minForceSec < 0)         { g_minForceSec = 0;         }
    if (g_minForceSec > 86400)     { g_minForceSec = 86400;     }
    if (g_fpIntervalSec < 0)       { g_fpIntervalSec = 0;       }
    if (g_fpIntervalSec > 0 && g_fpIntervalSec < 60) { g_fpIntervalSec = 60; }
    if (g_fpIntervalSec > 86400)   { g_fpIntervalSec = 86400;   }

    const Site sites[] = { { kSiteTick, kOrigTick, sizeof(kOrigTick) } };
    if (!VerifyAllSites(L"P23", sites, ARRAYSIZE(sites)))
    {
        return PatchResult::Mismatch;
    }

    if (!Hook::WriteJmp(kSiteTick, (const void*)&TrampTitleRank, sizeof(kOrigTick)))
    {
        return PatchResult::Failed;
    }

    // Первый пересчёт — не сразу после старта: дать серверу подняться и дать
    // таблице онлайна наполниться.
    g_lastRun = GetTickCount();

    Log::Line(L"    P23: отправитель званий 65…69 (опкоды 3404…3408) — пересчёт раз в %d с "
              L"(@%08X)", g_intervalSec, kSiteTick);
    Log::Line(L"    P23: проход = UPTopLevelAll + UPTopLevelClass + UPTopGold → "
              L"UPFameRatingHolderUp → UPFameRatingHolder → UPFameRatingRevokeList → "
              L"UPCharFameBitDis + пакет + UPFameRatingRevokeUp");
    Log::Line(L"    P23: признак записи по договору с P24 — 0 выдать / 1 снять; "
              L"в пакет уходит только userNum из 0…549 (sub_5328F0@0x5328FF), "
              L"для остальных операция идёт через базу");
    Log::Line(L"    P23: сверка слота персонажа %s; подсказка IsOnline %s; отправка %s",
              g_matchSlot ? L"включена" : L"выключена",
              g_useOnline ? L"учитывается" : L"игнорируется",
              g_send ? L"включена" : L"ВЫКЛЮЧЕНА (только журнал)");
    Log::Line(L"    P23: снятие = ВСЕГДА правка базы (UPCharFameBitDis, ClearSlot=%d) "
              L"ПЛЮС пакет живой сессии — правка базы пакет НЕ заменяет", g_clearSlot ? 1 : 0);
    Log::Line(L"    P23: в записи +10…+11 идёт слот персонажа + 1 (0 = не задан) — "
              L"у одного аккаунта бывает несколько живых сессий, и P24 по этому полю "
              L"ищет ТОЧНО (UserIndex + слот)");
    Log::Line(L"    P23: САМОЗАЖИВЛЕНИЕ — каждый проход сверяет Granted с фактическим битом "
              L"маски (UPCharFameBitInfo); отметка врала → сброс в 0 и выдача заново, "
              L"не более %d попыток подряд (MaxGrantAttempts)", g_maxGrantTry);
    Log::Line(L"    P23: ★ GM-команда «пересчитать сейчас»: приём 2333 %s, ответ 2334; "
              L"порог MinForceSec=%d с (авторитетный; зеркало — patches.ini P25)",
              g_onDemand ? L"включён" : L"ВЫКЛЮЧЕН", g_minForceSec);
    Log::Line(L"    P23: ★ пересчёт №2 «место в топе по очкам славы» = EXEC dbo.UPTopFamePoint "
              L"→ опкод 3409 (строка ответа 13 б = готовая запись пакета). "
              L"По команде: %s. Периодически: %s",
              g_fpOnDemand ? L"да" : L"нет",
              g_fpIntervalSec > 0 ? L"включено (см. FamePointIntervalSec)"
                                  : L"ВЫКЛЮЧЕНО — в оригинале это делает ChannelManager в 03:00");
    Log::Line(L"    P23: ! нужна SQL-миграция рейтингов (SQL/fame_rating_01_migrate.sql, "
              L"16 объектов); без процедур — 3 неудачных прохода и отключение до перезапуска");
    return PatchResult::Applied;
}
