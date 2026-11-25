// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P25 — GM-КОМАНДА «ПЕРЕСЧИТАТЬ РЕЙТИНГИ СЕЙЧАС» (клиентский опкод 6020).
//        ★ НАША ПРАВКА. Живёт в AsdaPatch.dll, образ GameServer.exe не меняется.
//
//  Документ патча:  AstoryServer/Docs/GameServer/gm-rating-recalc-p25.md
//  Пара в DBManager: P23 (DBPatch.dll) — он и делает ОБА пересчёта.
//  Соседи: P24 (приём 3404…3408), P21 (маска славы 512 бит), P22 (2330…2332).
//
//  ── ЗАЧЕМ ───────────────────────────────────────────────────────────────────
//  Владелец: «нужен пересчёт по команде GM через админ-меню, причём не только
//  рейтинговых званий, но и общей позиции игрока в топе — того, что в 3 часа
//  ночи каждый раз происходит».
//  Пересчётов ДВА, и оба в оригинале запускаются только по расписанию:
//    №1 звания 65…69 — наш P23, таймер IntervalSec (по умолчанию 600 с);
//    №2 место в топе по очкам славы — стоковый `EXEC UPTopFamePoint` →
//       опкод 3409; гоняет задача ChannelManager «Title Rank Process» ежедневно
//       в 03:00 (журнал ChannelManager\Error_Log\TitleLog_*.txt). ★ В самом
//       ChannelManager.exe есть строка-команда консоли `'o' : Title Rank Process`,
//       то есть ручной запуск в оригинале ЕСТЬ — но только с консоли процесса,
//       из игры его не достать. Эта правка и делает его достижимым из игры.
//  ★ ПОПРАВКА ВЛАДЕЛЬЦА (позже 30.08): «я просил для ВСЕХ званий, а не только для
//  соревновательных». Поэтому пересчётов стало ТРИ, и третий — главный:
//    №3 ПРОВЕРКА УСЛОВИЙ ВСЕХ 280 ЗВАНИЙ по уже накопленному прогрессу
//       у КАЖДОГО игрока, который сейчас в игре (выдаёт то, что заслужено, но не
//       выдано). Разбор — в блоке «ЧТО ТАКОЕ ПЕРЕСЧЁТ №3» ниже.
//  Команда запускает все три немедленно и отвечает результатом в чат.
//
//  ── ★★★ ГДЕ ПРИНИМАЕМ КОМАНДУ: МЁРТВЫЙ КЕЙС 0x1784 ──────────────────────────
//  Новых мест в jump-таблице диспетчера клиентских пакетов `sub_42A9D0` не
//  завести, а ветку `default` уже занял P13 (широкие каналы чата 6560).
//  Искать место не пришлось: в ряду ОПЕРАТОРСКИХ опкодов (0x1782 Kick,
//  0x1786 Kill, 0x1790 Add, 0x1793 Invincible, …) сток содержит ПУСТОЙ кейс:
//      0042CDFB  8B 4D 08              mov ecx,[ebp+8]
//      0042CDFE  C7 01 F7 00 00 00     mov dword [ecx],0F7h   ; маркер 247
//      0042CE04  8B 55 08              mov edx,[ebp+8]
//      0042CE07  C7 02 F8 00 00 00     mov dword [edx],0F8h   ; маркер 248
//      0042CE0D  E9 24 22 00 00        jmp 0x42F036           ; хвост switch
//  Ни одного вызова — опкод 0x1784 (6020) принимается и молча выбрасывается.
//  ★ Доказательства, что площадка наша и свободна (двумя методами):
//    1) единственный вход в неё — запись jump-таблицы `0x42F5C0 -> 0x42CDFB`
//       (сплошной поиск абсолютной ссылки по .text/.rdata/.data — она одна);
//    2) сплошной перебор кодировок rel8/rel32/jcc по всей .text: ни один
//       переход не ведёт ВНУТРЬ 0x42CDFC…0x42CDFF ⇒ 5 байт под `jmp` свободны;
//    3) опкод 6020 не шлёт и оригинальный КЛИЕНТ: во всём декомпиле
//       (`RE/etalon/*.c`) 6020 встречается только как id контрола окна.
//
//  ── КАДР ДИСПЕТЧЕРА (тот же, что у P13; сверен с кейсом 0x1786 @0x42CE12) ───
//      [ebp-0x04]    -> буфер пакета (хвост switch читает опкод так)
//      [ebp-0x34]    __int16 packetLen  (ПОЛНАЯ длина кадра)
//      [ebp-0x44]    __int16 charIndex  (номер сессии = userNum)
//      [ebp-0x1048]  сам буфер пакета
//      [ebp-0x10C4]  this диспетчера; CUserManager = [[this+4]+0x34]
//      [ebp+0x08]    указатель на маркер прогресса
//
//  ── ★★★ ГЕЙТ ОПЕРАТОРА — 1:1 СО СТОКОВЫМИ GM-КОМАНДАМИ ──────────────────────
//  Все семь стоковых операторских обработчиков (Kick/Kill/Add/GetMob/EventSet/
//  EventOff/ItemGive) открываются ОДНОЙ И ТОЙ ЖЕ цепочкой из пяти проверок:
//      1) sub_5328F0(idx)          — индекс сессии в пределах 0x226;
//      2) sub_52ECF0(mgr, idx, -1) — ★ IsOperatorUser: UserIndex (CUser+0x174)
//                                    в диапазоне 0…5000. ЭТО и есть операторский
//                                    гейт; по ИМЕНИ проверять нельзя (закон
//                                    server-operator-gate: ADM_* = оператор,
//                                    GM_sitxovski с индексом 75180 — обычный игрок);
//      3) sub_52ED50(mgr, idx) == 1 — байт GM-полномочий на CUser, приезжает из
//                                    dbo.CharGmInfo.GMFlag через UPCharGMInfo;
//      4) sub_524390(mgr, token, idx, "имя") — анти-тампер (монотонный счётчик);
//      5) sub_523F00(pkt, len, idx, 1)       — MD5 тела (конверт «секрет+MD5»).
//  Повторяем все пять и в том же порядке. ⚠ Обе учётки владельца обязаны совпасть:
//  GM-флаг в базе у `GM_sitxovski` СТОИТ (dbo.CharGmInfo, GMFlag=1), но UserIndex
//  у него 75180 ⇒ шаг 2 его не пропустит. Команда работает под `ADM_*`
//  (UserIndex 2), как и все остальные операторские команды сервера. Это СТОКОВЫЙ
//  гейт, не наше ограничение.
//
//  ── ★★★ ЧТО ТАКОЕ ПЕРЕСЧЁТ №3 И ЧТО В НЁМ ФИЗИЧЕСКИ НЕВОЗМОЖНО ──────────────
//  Как звания выдаются в оригинале (адреса проверены дизассемблером):
//    * `sub_54A050@0x54A050` — НАКОПИТЕЛЬ ПО СОБЫТИЮ. Его зовут из 204 мест сервера
//      (убил моба, поднял уровень, скрафтил, вошёл в зону…) с приращением `arg8`.
//      Он прибавляет приращение к записи персонажа (массив записей по 44 б,
//      указатель `CUser+0x17DFC`, запись на звание) и зовёт проверку условия.
//    * `sub_54B260@0x54B260` — ПРОВЕРКА УСЛОВИЯ. Либо «универсальный» путь
//      (байт `+92` записи FameInfo, т. е. колонка 45 файла = 1): просто
//      `значение >= порог` из колонки 3; либо зашитый в EXE `switch` по id
//      (191 ветка, id 0…246). Совпало — `AddFameBit@0x54A980` (он же шлёт в базу
//      2256, то есть выданное переживает перезаход), нотис `6065` и каскад
//      «звание-набор» `sub_54A610`.
//    * `sub_54A890@0x54A890` — гейт «звание ещё НЕ получено» (маска `CUser+0x17DDC`).
//  ★★★ ПЕРИОДИЧЕСКОЙ ПРОВЕРКИ УСЛОВИЙ В ОРИГИНАЛЕ НЕТ. `TimerProcess@0x5431C0`
//  обходит всех онлайн-игроков каждый тик, но по славе трогает РОВНО ОДНО звание —
//  `sub_54A050(this, idx, 22, 0, 0)`, id 22 («время в игре», его значение считается
//  как `GetTickCount() - запись`). Всё остальное начисляется ТОЛЬКО по событию.
//  ⇒ Если условие выполнилось в момент, когда событие не пришло (данные правили
//  руками, звание добавили в FameInfo.txt задним числом, порог понизили), звание
//  не выдаётся НИКОГДА. Это и чинит пересчёт №3.
//
//  ★★★ ЧЕСТНО О ГРАНИЦАХ (закон never-invent-only-original):
//  «Пересчитать» условие можно ТОЛЬКО там, где значение прогресса ГДЕ-ТО ЛЕЖИТ.
//  Разбор всех 280 записей живого `ConfigSet\FameInfo.txt` против обоих switch:
//    • 92 звания ВЫКЛЮЧЕНЫ колонкой 1 (`sub_54A050` выходит на первой же проверке
//      байта `+2`) — не трогаем;
//    • 51 звание с колонкой 45 = 1 — универсальный накопитель ⇒ ПЕРЕСЧИТЫВАЕМО;
//    • 89 званий идут стоковым `switch` и ХРАНЯТ накопитель в записи ⇒ ПЕРЕСЧИТЫВАЕМО;
//    • 2 звания (29, 45) считают процент полученных званий по маске самого игрока —
//      значение вычисляет сама `sub_54B260` ⇒ ПЕРЕСЧИТЫВАЕМО;
//    • 7 званий (5, 43 и 6…10) читают ЖИВОЕ поле `CUser` (+0x182C5 и +0x192,
//      сняты дизассемблером `0x54A2AA` и `0x54A2BC`) ⇒ ПЕРЕСЧИТЫВАЕМО;
//    • 1 звание (22) — время в игре, `GetTickCount() - запись` ⇒ ПЕРЕСЧИТЫВАЕМО;
//    • ★ 25 званий (47…55, 149, 152, 155, 158, 161, 164, 167, 170, 172, 174,
//      176, 178, 180, 182, 184, 186, 224…227, 231) берут значение ИЗ САМОГО СОБЫТИЯ
//      и НИГДЕ его не сохраняют ⇒ ПЕРЕСЧИТАТЬ НЕЛЬЗЯ, их пропускаем;
//    • 12 званий (21, 56, 65…69, 129, 133…136) не описаны НИ ОДНОЙ веткой и не имеют
//      колонки 45 = 1 ⇒ в оригинале недостижимы вовсе (65…69 — как раз рейтинговые,
//      их раздаёт пересчёт №1 по пакетам 3404…3408).
//  ⇒ Обещать «пересчитаем всё» было бы враньём: «убей 100 мобов» задним числом
//  не восстановить, если счётчик никто не вёл. Команда честно делает то, что
//  возможно: ПРОГОНЯЕТ ПРОВЕРКУ УСЛОВИЙ ПО ТЕКУЩИМ НАКОПИТЕЛЯМ.
//
//  ★ ОФЛАЙНОВЫЕ ПЕРСОНАЖИ НЕ ОХВАЧЕНЫ. Накопители живут в `CUser`, то есть только
//  у тех, кто сейчас в игре; в базе лежит лишь маска полученного и сохранённый
//  прогресс, а 191 ветку условий в T-SQL мы повторять не станем (это была бы
//  ВТОРАЯ реализация тех же правил — прямой путь к расхождению). Пересчёт для
//  офлайна возможен только как отдельная процедура базы; её контракт описан в
//  документе патча, но сама она не пишется здесь.
//
//  ── ПОБОЧНЫЕ ЭФФЕКТЫ, КОТОРЫХ МЫ ИЗБЕГАЕМ ──────────────────────────────────
//   * `sub_54B260` зовётся с `a6 = 0` ⇒ НЕ шлёт в базу пакет 2257 (54 б) на каждое
//     звание каждого игрока. Сток шлёт его при каждом событии; при обходе 280×N
//     это был бы поток мусора.
//   * Звания, которые игрок уже носит, пропускаются гейтом `sub_54A890` — иначе
//     на каждый прогон летел бы повторный нотис 6065.
//   * `sub_54A050` НЕ используется намеренно: у него есть ветки с ПОБОЧНЫМ
//     ЭФФЕКТОМ даже при нулевом приращении — id 38 увеличивает счётчик на 1,
//     id 237…244 при `arg8 <= 0` увеличивают второй счётчик. Прогон командой
//     накручивал бы прогресс. Поэтому зовём проверку напрямую.
//
//  ── КОНВЕРТ И ТЕЛО 6020 (как у всех операторских команд) ────────────────────
//      кадр:   [0]=0xFB [1..2]=len [3..4] [5..6] [7..8]=опкод [9..]=тело [len-1]=0xFE
//      тело:   [0..7] анти-тампер токен, [8..23] MD5(payload), [24..] payload
//      payload (8 байт):
//        +0 BYTE  что пересчитать:
//                 0 = ВСЁ (условия всех званий + рейтинговые 65…69 + топ славы)
//                 1 = только рейтинговые звания 65…69
//                 2 = только место в топе по очкам славы
//                 3 = только условия всех званий у тех, кто сейчас в игре
//        +1..7    резерв, нули
//  ⇒ полная длина кадра = 9 + (24 + 8) + 1 = 42 байта.
//
//  ── ЧТО ДЕЛАЕТ КОМАНДА ──────────────────────────────────────────────────────
//  Сам GameServer НЕ считает ничего: соединения с базой у него нет вовсе, все
//  запросы идут через DBManager. Поэтому команда — это ОДИН пакет соседу:
//      2333 (0x91D) GS→DB «пересчитать сейчас», тело 10 б
//  и ответ
//      2334 (0x91E) DB→GS «результат», тело 33 + 22*N б (N ≤ 5 сменившихся лидеров)
//  Раскладка первых восьми байт повторяет тело 2256/2330/2331, чтобы DBManager
//  брал поля с привычных смещений (закон port-shared-points — общая форма шапки).
//  ⚠ НЕ обновлённый DBManager такой опкод просто не узнаёт: три диапазона его
//  switch дают `ja` в эпилог, обработчика нет, ошибки нет — включать команду
//  безопасно даже до подмены DBPatch.dll (оператор просто не дождётся ответа).
//
//  ── ГДЕ ПРИНИМАЕМ ОТВЕТ 2334 ────────────────────────────────────────────────
//  Диспетчер ответов базы — `ConnectSocketMsgProcess@0x42FAB0`. Его ЭПИЛОГ
//  (0x43462B) уже занят P21 (приём 2332), поэтому берём ДРУГУЮ свою площадку —
//  ветку `default` того же switch:
//      004345FC  8B 45 08              mov eax,[ebp+8]
//      004345FF  C7 00 48 08 00 00     mov dword [eax],848h
//      00434605  8D 8D E8 EF FF FF     lea ecx,[ebp-0x1018]   ← счётчик «мусорных»
//      ...       call sub_4F6E60
//      00434625  C7 02 49 08 00 00     mov dword [edx],849h
//      0043462B  <эпилог, площадка P21>
//  Наш опкод 2334 стоку неизвестен ⇒ он гарантированно приходит именно сюда.
//  Сплошной перебор кодировок по .text: ни один переход не ведёт внутрь
//  0x4345FD…0x434604, абсолютных ссылок туда тоже нет ⇒ площадка свободна.
//  Кадр (сверен с P21 и с дизассемблером): [ebp-0x04] пакет, [ebp-0x08] userNum,
//  [ebp-0x1028] объект, из которого достаётся CUserManager: *(*(obj+4)+0x34).
//
//  ── ОТВЕТ ОПЕРАТОРУ ─────────────────────────────────────────────────────────
//  Текст уходит СТОКОВЫМ опкодом 6561 (`Recv_WhisperOrSystemMessage@0xBA8560`),
//  которым уже пользуется P13: тело 32 байта шапки + текст cp1251 без нуля,
//  +0 вид = 1, +1 номер канала, +12 char[20] имя отправителя. Новых клиентских
//  опкодов не заводим — строки увидит и оригинальный клиент, и порт.
//
//  ── ЗАЩИТА ОТ ЗЛОУПОТРЕБЛЕНИЯ ───────────────────────────────────────────────
//  Пересчёт трогает всю таблицу персонажей и `dbo.Item`, поэтому частые запуски
//  кладут базу. Порог стоит в ДВУХ местах: здесь (MinIntervalSec — мгновенный
//  отказ, в базу не ходим) и на стороне P23 (MinForceSec — авторитетный, он
//  считает реально выполненные проходы). Оба ключа в своих ini.
//
//  ── ЧЕГО ЗДЕСЬ НЕТ ──────────────────────────────────────────────────────────
//  Своего потока и своего таймера нет: и приём команды, и приём ответа
//  происходят на рабочем потоке сервера в его же диспетчерах — ровно как у
//  стоковых операторских команд, которые точно так же шлют соседу прямо из
//  обработчика (Recv_OperatorCommand_EventSet → sub_5646C0). Закон
//  no-reentrant-net-callbacks здесь ни при чём: он про КЛИЕНТСКИЙ цикл разбора
//  кадров (FAsdaConnection::DrainFrames) и запрещает рвать соединение и грузить
//  уровень; мы не делаем ни того, ни другого — только отправляем пакет.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P25_GmRatingRecalc";

    // ── настройки из patches.ini ────────────────────────────────────────────
    bool g_enabled        = true;   // главный выключатель секции
    bool g_needOperator   = true;   // сверять sub_52ECF0 (UserIndex 0…5000)
    bool g_needGmFlag     = true;   // сверять sub_52ED50 (dbo.CharGmInfo.GMFlag)
    bool g_needSecret     = true;   // сверять анти-тампер токен и MD5 тела
    int  g_minIntervalSec = 60;     // не чаще раза в N секунд (зеркало порога P23)
    int  g_replyChannel   = 0;      // номер канала в теле 6561 (клиент красит по нему)
    bool g_sweepTitles    = true;   // пересчёт №3: условия ВСЕХ званий у онлайн-игроков
    int  g_maxGrants      = 2000;   // предохранитель: сколько званий выдать за один проход

    // ── опкоды ──────────────────────────────────────────────────────────────
    constexpr WORD kOpGmCmd    = 0x1784;   // 6020 C→S «пересчитать рейтинги сейчас»
    constexpr WORD kOpDbForce  = 0x91D;    // 2333 GS→DB «пересчитать сейчас»
    constexpr WORD kOpDbReport = 0x91E;    // 2334 DB→GS «результат пересчёта»

    constexpr int  kPayloadLen = 8;                   // payload 6020
    constexpr int  kDbForceLen = 10;                  // тело 2333
    constexpr int  kFrameMin   = 33 + kPayloadLen;    // минимум байт в кадре 6020

    // Раскладка тела 2334 (собирается в p23_db_title_rank.cpp — там же и дубль
    // этих смещений; менять только парой, иначе отчёт приедет мусором).
    constexpr int kRepUserNum  = 0;    // i16 сессия оператора
    constexpr int kRepUserIdx  = 2;    // i32 UserIndex оператора
    constexpr int kRepCharIdx  = 6;    // i8  слот персонажа
    constexpr int kRepStatus   = 7;    // i8  код итога (см. kStatus* ниже)
    constexpr int kRepMs       = 8;    // i32 длительность прохода, мс
    constexpr int kRepChanged  = 12;   // i32 сменилось лидеров
    constexpr int kRepRevoked  = 16;   // i32 обработано снятий
    constexpr int kRepRegrant  = 20;   // i32 довыдано (Granted было 0)
    constexpr int kRepRankRows = 24;   // i32 строк в топе по очкам славы
    constexpr int kRepRankSent = 28;   // i32 из них отправлено живым сессиям
    constexpr int kRepLeaders  = 32;   // i8  сколько записей лидеров идёт следом
    constexpr int kRepList     = 33;   // далее N × (i8 titleId + char[21] имя)
    constexpr int kRepRecLen   = 22;   // длина одной записи списка лидеров
    constexpr int kRepMaxList  = 5;    // рейтинговых званий ровно пять (65…69)
    constexpr int kRepMinLen   = kRepList;                        // минимум тела
    constexpr int kRepMaxLen   = kRepList + kRepRecLen * kRepMaxList;

    // Коды итога (их проставляет P23; здесь только печатаем).
    constexpr int kStatusOk       = 0;   // проход выполнен
    constexpr int kStatusBusy     = 1;   // предыдущий проход ещё идёт
    constexpr int kStatusTooOften = 2;   // не вышел порог MinForceSec
    constexpr int kStatusDbDown   = 3;   // база не ответила / миграции нет
    constexpr int kStatusOff      = 4;   // приём команды выключен в dbpatch.ini

    // ── ★ тракт славы: адреса и смещения (сняты дизассемблером, см. шапку) ──
    //   Те же значения уже используются в P21/P24 — общая точка, не дубль вслепую.
    constexpr DWORD kVaFameCount  = 0x007DFFD4;  // i32  — число записей FameInfo
    constexpr DWORD kVaFameTable  = 0x007DFFD8;  // ptr  — таблица FameInfo, запись 96 б
    constexpr int   kFameTabRec   = 96;          // размер записи таблицы
    constexpr int   kFameRecStep  = 44;          // размер записи прогресса у персонажа
    constexpr int   kOffRecords   = 0x17DFC;     // CUser: ptr на массив записей по 44 б
    constexpr int   kOffUserIndex = 0x174;       // CUser: UserIndex i32 (< 0 = слот пуст)
    constexpr int   kOffOnline    = 0x2E;        // CUser: DWORD, должен быть == 1
    // Байт «звание включено» в записи FameInfo (колонка 1 файла). Его же проверяет
    // стоковый sub_54A050 первым делом: `if (*(BYTE*)(rec + 96*id + 2))`.
    constexpr int   kFameEnabled  = 2;
    // Живые поля CUser для семи званий, которые НЕ ведут накопитель:
    //   ids 5, 43   -> 0x54A2AA  movzx ecx, byte ptr [eax+0x182C5]
    //   ids 6…10    -> 0x54A2BC  movzx eax, byte ptr [edx+0x192]
    constexpr int   kOffLiveA     = 0x182C5;
    constexpr int   kOffLiveB     = 0x192;
    constexpr int   kTitleTimePlayed = 22;       // «время в игре»: GetTickCount() - запись

    // ★ Звания, значение которых приходит В СОБЫТИИ и нигде не сохраняется.
    //   Пересчитать их нечем — пропускаем (см. разбор в шапке). Список получен
    //   разбором обоих switch, а не на глаз: ветки `v12 = arg8` и прямой вызов
    //   sub_54B260 с arg8/argC в sub_54A050.
    const short kNoStore[] =
    {
        20, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        149, 152, 155, 158, 161, 164, 167, 170, 172, 174, 176, 178, 180, 182, 184, 186,
        224, 225, 226, 227, 231
    };

    bool IsNoStore(int id)
    {
        for (int i = 0; i < ARRAYSIZE(kNoStore); ++i)
        {
            if (kNoStore[i] == (short)id) { return true; }
        }
        return false;
    }

    // ── функции образа ──────────────────────────────────────────────────────
    typedef int    (__cdecl    *PFN_IsValidIdx)(short idx);                           // sub_5328F0
    typedef int    (__fastcall *PFN_IsOperator)(void* self, void* edx, short idx,
                                                int a3);                              // sub_52ECF0
    typedef char   (__fastcall *PFN_IsGm)(void* self, void* edx, short idx);           // sub_52ED50
    typedef int    (__fastcall *PFN_SecretCheck)(void* self, void* edx, __int64 ts,
                                                 short idx, const char* fn);           // sub_524390
    typedef int    (__stdcall  *PFN_SignCheck)(void* pkt, unsigned len, short idx,
                                               int mode);                              // sub_523F00
    typedef void*  (__fastcall *PFN_GetUser)(void* self, void* edx, int userNum);       // sub_5324A0
    typedef int    (__fastcall *PFN_GetUserIndex)(void* self, void* edx, int userNum);  // sub_5324F0
    typedef char   (__fastcall *PFN_GetCharIdx)(void* self, void* edx, int userNum);    // sub_532530
    typedef char   (__fastcall *PFN_GetGroup)(void* self, void* edx);                   // sub_4A7EA0
    typedef short  (__fastcall *PFN_GetDbConn)(void* self, void* edx);                  // sub_4C0A30
    typedef int    (__fastcall *PFN_SendDb)(void* self, void* edx, int op, int len,
                                            int connIdx, void* body, int userNum);      // sub_5646C0
    typedef int    (__fastcall *PFN_SendToUser)(void* self, void* edx, int op, int len,
                                                int userNum, void* body, int a5, int a6);// sub_4C28F0
    typedef int    (__thiscall *PFN_GetUserIdxAt)(void* self, int i);                   // sub_523E50
    typedef bool   (__fastcall *PFN_NotOwned)(void* self, void* edx, short idx, short id,
                                              BYTE* a4, BYTE* a5);                       // sub_54A890
    typedef bool   (__fastcall *PFN_CheckFame)(void* self, void* edx, short idx, short id,
                                               int value, int value2, char toDb);         // sub_54B260
    typedef void   (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);             // sub_569DF0

    PFN_IsValidIdx   const pIsValidIdx  = (PFN_IsValidIdx)  Srv::kIsValidUserIdx;
    PFN_IsOperator   const pIsOperator  = (PFN_IsOperator)  Srv::kIsOperatorIndex;   // 0x52ECF0
    PFN_IsGm         const pIsGm        = (PFN_IsGm)        Srv::kIsOperator;        // 0x52ED50
    PFN_SecretCheck  const pSecretCheck = (PFN_SecretCheck) Srv::kSecretCheck;
    PFN_SignCheck    const pSignCheck   = (PFN_SignCheck)   Srv::kPktSignCheck;
    PFN_GetUser      const pGetUser     = (PFN_GetUser)     Srv::kGetUser;
    PFN_GetUserIndex const pGetUserIdx  = (PFN_GetUserIndex)Srv::kGetUserNumber;     // 0x5324F0
    PFN_GetCharIdx   const pGetCharIdx  = (PFN_GetCharIdx)  Srv::kGetUserSubFlag;    // 0x532530
    PFN_GetGroup     const pGetGroup    = (PFN_GetGroup)    Srv::kGetServerGroup;    // 0x4A7EA0
    PFN_GetDbConn    const pGetDbConn   = (PFN_GetDbConn)   Srv::kGetDbSrvIdx;       // 0x4C0A30
    PFN_SendDb       const pSendDb      = (PFN_SendDb)      Srv::kConnectSend;       // 0x5646C0
    PFN_SendToUser   const pSendToUser  = (PFN_SendToUser)  Srv::kSendPacket;        // 0x4C28F0
    PFN_SrvLog       const pSrvLog      = (PFN_SrvLog)      Srv::kLog;
    // ★ Обход списка онлайна и тракт славы — те же точки, что зовёт сток.
    PFN_GetUserIdxAt const pGetIdxAt    = (PFN_GetUserIdxAt)Srv::kGetUserIdxAt;      // 0x523E50
    PFN_NotOwned     const pNotOwned    = (PFN_NotOwned)    0x0054A890;
    PFN_CheckFame    const pCheckFame   = (PFN_CheckFame)   0x0054B260;

    inline int   FameCount()     { return *(int*)  kVaFameCount; }
    inline BYTE* FameTable()     { return *(BYTE**)kVaFameTable; }

    void* const kGroupThis = (void*)Srv::kServerGroupThis;   // ecx у sub_4A7EA0
    void* const kNetMgr    = (void*)Srv::kNetMoveMgr;        // ecx у sub_5646C0

    // Имя функции для журнала анти-тампера — в том же стиле, что у стока
    // («Recv_OperatorCommand_EventSet()» и т. п.). Только ASCII: строка уезжает
    // в узкий лог сервера как есть.
    const char kFnName[] = "Recv_OperatorCommand_RatingRecalc()";

    // ── защита от частых запусков ───────────────────────────────────────────
    //   Мгновенный отказ ДО похода в базу. Авторитетный порог — на стороне P23.
    DWORD g_lastRun = 0;
    bool  g_everRun = false;

    // ── cp1251 для тела 6561 ────────────────────────────────────────────────
    //   Исходник компилируется с /utf-8, поэтому русские строки живут широкими,
    //   а в пакет уезжают переведёнными в cp1251 — ровно так же поступает Log.cpp.
    int ToCp1251(const wchar_t* src, char* out, int room)
    {
        const int n = WideCharToMultiByte(1251, 0, src, -1, out, room, "?", nullptr);
        return n > 0 ? n - 1 : 0;      // без завершающего нуля: 6561 его не несёт
    }

    // Отправка ОДНОЙ строки оператору стоковым 6561 (см. шапку и P13).
    void SendLine(void* mgr, int userNum, const wchar_t* text)
    {
        void* net = *(void**)((BYTE*)mgr + 4);
        if (!net) { return; }

        BYTE body[Srv::kChatWideHdrLen + Srv::kChatMaxText];
        memset(body, 0, sizeof(body));
        body[0] = 1;                                   // вид: строка широкого канала
        body[1] = (BYTE)g_replyChannel;                // номер канала (цвет у клиента)
        memcpy(body + 12, "SYSTEM", 6);                // имя отправителя (20 б, cp1251)

        char* dst = (char*)(body + Srv::kChatWideHdrLen);
        int   len = ToCp1251(text, dst, Srv::kChatMaxText);
        if (len <= 0) { return; }
        if (len > g_chatMaxTextLen) { len = g_chatMaxTextLen; }

        pSendToUser(net, nullptr, Srv::kOpChatWideSend,
                    Srv::kChatWideHdrLen + len, userNum, body, 0, 0);
    }

    // ── ★★★ ПЕРЕСЧЁТ №3: ПРОВЕРКА УСЛОВИЙ ВСЕХ ЗВАНИЙ У ОНЛАЙН-ИГРОКОВ ──────
    //  Обход списка сессий — теми же тремя функциями, что и стоковый
    //  `TimerProcess@0x5431C0`: sub_523E50 (i-й слот) → sub_5328F0 (годен ли) →
    //  sub_5324A0 (CUser), с его же фильтрами «UserIndex >= 0 и состояние == 1».
    //  Дальше по каждому званию: гейт «включено» (байт +2 записи FameInfo),
    //  гейт «ещё не получено» (sub_54A890) и стоковая проверка sub_54B260
    //  с a6 = 0 (без DB-пакета 2257).
    //  Возвращает число выданных званий; заполняет счётчики для отчёта.
    int SweepUser(void* mgr, short idx, BYTE* pUser, int count, const BYTE* table, int* outChecked, int* outSkipped, int budget);

    int SweepAllTitles(void* mgr, int* outPlayers, int* outChecked, int* outSkipped)
    {
        *outPlayers = 0;
        *outChecked = 0;
        *outSkipped = 0;
        if (!g_sweepTitles || !mgr) { return 0; }

        const int   count = FameCount();
        const BYTE* table = FameTable();
        if (count <= 0 || count > 4096 || !table) { return 0; }

        int granted = 0;
        int iter    = 0;
        int guard   = 0;

        for (;;)
        {
            // Сторож бесконечного цикла — 1:1 с TimerProcess/recvGlobalChatClient.
            if (++guard > 1000) { pSrvLog(Srv::kLogCatOperator, "SweepAllTitles() loop guard"); guard = 0; }

            const short idx = (short)pGetIdxAt(mgr, iter++);
            if (!pIsValidIdx(idx)) { break; }

            BYTE* pUser = (BYTE*)pGetUser(mgr, nullptr, idx);
            if (!pUser) { continue; }
            if (*(const int*)(pUser + kOffUserIndex) < 0)      { continue; }
            if (*(const DWORD*)(pUser + kOffOnline) != 1)      { continue; }

            if (!*(BYTE**)(pUser + kOffRecords)) { continue; }
            ++(*outPlayers);

            // ★ 18.11.2026 (P127 А2.2): тело обхода одного игрока вынесено в SweepUser без изменений — его же зовёт мост админ-центра
            granted += SweepUser(mgr, idx, pUser, count, table, outChecked, outSkipped, g_maxGrants - granted);
            if (granted >= g_maxGrants)
            {
                pSrvLog(Srv::kLogCatOperator,
                        "SweepAllTitles() stopped: MaxGrantsPerPass=%d reached", g_maxGrants);
                return granted;
            }
        }
        return granted;
    }

    // Проверка условий всех званий одного игрока в игре (накопители — в CUser). Возврат — сколько выдано (не больше budget).
    int SweepUser(void* mgr, short idx, BYTE* pUser, int count, const BYTE* table, int* outChecked, int* outSkipped, int budget)
    {
        int granted = 0;
        BYTE* recs = *(BYTE**)(pUser + kOffRecords);
        if (!recs || budget <= 0) { return 0; }
        {
            for (int id = 0; id < count; ++id)
            {
                const BYTE* row = table + kFameTabRec * id;
                if (row[kFameEnabled] == 0) { continue; }   // звание выключено колонкой 1

                if (IsNoStore(id))                          // значение живёт только в событии
                {
                    ++(*outSkipped);
                    continue;
                }

                BYTE b1 = 0, b2 = 0;
                if (!pNotOwned(mgr, nullptr, idx, (short)id, &b1, &b2))
                {
                    continue;                               // уже получено — молчим
                }

                const BYTE* rec = recs + kFameRecStep * id;
                int value  = *(const int*)(rec + 0);
                int value2 = *(const int*)(rec + 4);

                // Три группы, где значение НЕ в записи, а живое (см. шапку).
                if (id == kTitleTimePlayed)
                {
                    value = (int)(GetTickCount() - (DWORD)value);
                }
                else if (id == 5 || id == 43)
                {
                    value = pUser[kOffLiveA];
                }
                else if (id >= 6 && id <= 10)
                {
                    value = pUser[kOffLiveB];
                }
                // Для 29 и 45 значение считает сама sub_54B260 (процент по маске),
                // переданное игнорируется — специально ничего не делаем.

                ++(*outChecked);
                if (pCheckFame(mgr, nullptr, idx, (short)id, value, value2, /*toDb*/ 0))
                {
                    ++granted;
                    if (granted >= budget) { return granted; }   // предел прохода (MaxGrantsPerPass) — сообщение пишет вызывающий
                }
            }
        }
        return granted;
    }

    // ── ПРИЁМ ОТВЕТА 2334 ───────────────────────────────────────────────────
    //   Зовётся из стаба, поставленного в ветку default диспетчера ответов базы.
    //   ★ ЗАКОН msvc-inline-asm-offsets: смещения кадра — только через #define.
    #define GSD_PKT   0x04      // [ebp-0x04] указатель на пакет
    #define GSD_OBJ   0x1028    // [ebp-0x1028] объект: CUserManager = *(*(obj+4)+0x34)

    void __cdecl OnRatingReport(BYTE* hostEbp)
    {
        if (!g_enabled) { return; }
        BYTE* pkt = *(BYTE**)(hostEbp - GSD_PKT);
        if (!pkt) { return; }
        if (*(WORD*)(pkt + 7) != kOpDbReport) { return; }

        const int bodyLen = (int)*(WORD*)(pkt + 1) - Srv::kFrameOverhead;
        if (bodyLen < kRepMinLen || bodyLen > kRepMaxLen) { return; }

        BYTE* obj = *(BYTE**)(hostEbp - GSD_OBJ);
        if (!obj) { return; }
        BYTE* inner = *(BYTE**)(obj + 4);
        if (!inner) { return; }
        void* mgr = *(void**)(inner + 0x34);
        if (!mgr) { return; }

        const BYTE* body    = pkt + 9;
        const int   userNum = *(short*)&body[kRepUserNum];
        const int   userIdx = *(int*)  &body[kRepUserIdx];

        // ★ закон wrong-notice-check-packet-first: ответ должен быть про ТУ ЖЕ
        //   сессию. userNum — лишь подсказка, решает UserIndex.
        if (!pIsValidIdx((short)userNum)) { return; }
        if (!pGetUser(mgr, nullptr, userNum)) { return; }
        if (pGetUserIdx(mgr, nullptr, userNum) != userIdx) { return; }

        const int status  = body[kRepStatus];
        const int ms      = *(int*)&body[kRepMs];
        const int changed = *(int*)&body[kRepChanged];
        const int revoked = *(int*)&body[kRepRevoked];
        const int regrant = *(int*)&body[kRepRegrant];
        const int rows    = *(int*)&body[kRepRankRows];
        const int sent    = *(int*)&body[kRepRankSent];
        int       nLead   = body[kRepLeaders];
        if (nLead > kRepMaxList) { nLead = kRepMaxList; }
        if (kRepList + kRepRecLen * nLead > bodyLen) { nLead = 0; }   // тело короче списка

        wchar_t line[220];

        if (status != kStatusOk)
        {
            const wchar_t* why =
                status == kStatusBusy     ? L"предыдущий пересчёт ещё идёт"
              : status == kStatusTooOften ? L"слишком часто — порог MinForceSec ещё не вышел"
              : status == kStatusDbDown   ? L"база не ответила (нет SQL-миграции рейтингов?)"
              : status == kStatusOff      ? L"приём команды выключен в dbpatch.ini"
              :                             L"неизвестный код итога";
            wsprintfW(line, L"[Рейтинги] Пересчёт НЕ выполнен: %s.", why);
            SendLine(mgr, userNum, line);
            pSrvLog(Srv::kLogCatOperator, "%s report: status=%d UserIndex=%d",
                    kFnName, status, userIdx);
            return;
        }

        wsprintfW(line, L"[Рейтинги] Пересчёт выполнен за %d мс.", ms);
        SendLine(mgr, userNum, line);

        wsprintfW(line, L"[Рейтинги] Звания 65…69: сменилось лидеров %d, снято %d, "
                        L"довыдано %d.", changed, revoked, regrant);
        SendLine(mgr, userNum, line);

        wsprintfW(line, L"[Рейтинги] Топ по очкам славы: строк %d, разослано живым "
                        L"сессиям %d.", rows, sent);
        SendLine(mgr, userNum, line);

        // Поимённо: кто теперь носит каждое сменившееся звание.
        for (int i = 0; i < nLead; ++i)
        {
            const BYTE* rec     = body + kRepList + kRepRecLen * i;
            const int   titleId = rec[0];

            // Имя приходит из базы РОВНО 21 байтом, добитым пробелами.
            char name[22] = {};
            memcpy(name, rec + 1, 21);
            for (int k = 20; k >= 0 && (name[k] == ' ' || name[k] == 0); --k) { name[k] = 0; }

            wchar_t wname[32] = {};
            MultiByteToWideChar(1251, 0, name, -1, wname, ARRAYSIZE(wname));

            wsprintfW(line, L"[Рейтинги]   звание %d — новый лидер: %s", titleId, wname);
            SendLine(mgr, userNum, line);
        }

        pSrvLog(Srv::kLogCatOperator,
                "%s report Ok : UserIndex=%d ms=%d changed=%d revoked=%d regrant=%d "
                "rankRows=%d rankSent=%d", kFnName, userIdx, ms, changed, revoked,
                regrant, rows, sent);
    }
}

// ══════════════ приём команды 6020 (зовётся стабом площадки A) ═══════════════
// ★ P127 А5.4 (21.11.2026): шаги 6–8 команды 6020 вынесены дословно в общую точку (поведение команды не изменилось) — ее же
//   зовёт мост админ-центра (P25_RunRecalc) от имени оператора в игре. → 0 запрос ушёл в базу; 3 только №3 (база не нужна);
//   1 слишком часто (outA — секунд до повтора); 2 нет объекта сети. outA/outB при 0 и 3 — выдано званий / персонажей в игре
//   (только если пересчёт №3 был).
static int RunRecalcCore(void* mgr, short idx, int what, int* outA, int* outB)
{
    // 6) порог частоты — мгновенный отказ, в базу не ходим
    const DWORD now = GetTickCount();
    if (g_everRun && (DWORD)(now - g_lastRun) < (DWORD)g_minIntervalSec * 1000u)
    {
        const int left = (int)(((DWORD)g_minIntervalSec * 1000u - (now - g_lastRun)) / 1000u) + 1;
        wchar_t line[200];
        wsprintfW(line, L"[Рейтинги] Слишком часто: повторный пересчёт можно запустить "
                        L"через %d с.", left);
        SendLine(mgr, idx, line);
        pSrvLog(Srv::kLogCatOperator, "%s Send Fail OK : too often (%d sec left)",
                kFnName, left);
        if (outA) { *outA = left; }
        return 1;
    }
    g_lastRun = now;
    g_everRun = true;

    // 7) ★ ПЕРЕСЧЁТ №3 — здесь и сейчас, локально: накопители всех званий лежат
    //    в CUser онлайн-игроков, база для этого не нужна вовсе.
    if (what == 0 || what == 3)
    {
        const DWORD t0 = GetTickCount();
        int players = 0, checked = 0, skipped = 0;
        const int granted = SweepAllTitles(mgr, &players, &checked, &skipped);
        const int ms = (int)(GetTickCount() - t0);

        wchar_t l1[200];
        wsprintfW(l1, L"[Звания] Условия проверены у %d персонажей в игре: выдано званий %d "
                      L"(проверок %d, за %d мс).", players, granted, checked, ms);
        SendLine(mgr, idx, l1);

        if (skipped > 0)
        {
            // Честно и каждый раз: 25 званий пересчитать НЕЧЕМ (значение живёт
            // только в самом событии и нигде не сохраняется), а офлайновых
            // персонажей мы не видим вовсе — их накопителей нет в памяти.
            wsprintfW(l1, L"[Звания] Пропущено проверок %d: у этих званий прогресс нигде "
                          L"не хранится. Персонажи не в игре не охвачены.", skipped);
            SendLine(mgr, idx, l1);
        }

        pSrvLog(Srv::kLogCatOperator,
                "%s sweep: players=%d checked=%d granted=%d skipped=%d ms=%d",
                kFnName, players, checked, granted, skipped, ms);

        if (outA) { *outA = granted; }
        if (outB) { *outB = players; }
        if (what == 3)
        {
            return 3;                                 // база в этом режиме не нужна
        }
    }

    // 8) просим базу: один пакет соседу, ответ придёт опкодом 2334.
    //    Шапка тела — та же, что у 2256/2330/2331 (userNum, UserIndex, Charidx,
    //    группа серверов), чтобы DBManager читал поля с привычных смещений.
    void* net = *(void**)((BYTE*)mgr + 4);
    if (!net)
    {
        pSrvLog(Srv::kLogCatOperator, "%s Send Fail OK : net object is NULL", kFnName);
        return 2;
    }

    BYTE body[kDbForceLen] = {};
    *(short*)&body[0] = (short)idx;
    *(int*)  &body[2] = pGetUserIdx (mgr, nullptr, idx);
    body[6]           = (BYTE)pGetCharIdx(mgr, nullptr, idx);
    body[7]           = (BYTE)pGetGroup  (kGroupThis, nullptr);
    body[8]           = (BYTE)what;                   // 0 оба / 1 звания / 2 топ
    body[9]           = 0;                            // резерв

    const short conn = pGetDbConn(net, nullptr);
    pSendDb(kNetMgr, nullptr, kOpDbForce, kDbForceLen, conn, body, idx);

    wchar_t line[200];
    wsprintfW(line, L"[Рейтинги] Запрос отправлен в базу (%s). Ждём результат…",
              what == 1 ? L"только рейтинговые звания 65…69"
                        : (what == 2 ? L"только место в топе по очкам славы"
                                     : L"рейтинговые звания 65…69 и место в топе"));
    SendLine(mgr, idx, line);

    pSrvLog(Srv::kLogCatOperator, "%s Send Ok : UserIndex=%d what=%d conn=%d",
            kFnName, pGetUserIdx(mgr, nullptr, idx), what, (int)conn);
    return 0;
}

//  extern "C" __stdcall — ровно как у P13: имя без украшений, стек чистит сама.
extern "C" void __stdcall AsdaOnGmRatingRecalc(void* mgr, int charIndex,
                                               int packetLen, BYTE* pkt)
{
    if (!g_enabled || !mgr || !pkt) { return; }
    if (*(WORD*)(pkt + 7) != kOpGmCmd) { return; }   // чужой опкод в нашем кейсе

    const short idx = (short)charIndex;

    // 1) индекс сессии в пределах таблицы (стоковый sub_5328F0)
    if (!pIsValidIdx(idx)) { return; }

    // 2) ★ операторский гейт: UserIndex в 0…5000 (стоковый sub_52ECF0)
    if (g_needOperator && !pIsOperator(mgr, nullptr, idx, -1))
    {
        pSrvLog(Srv::kLogCatOperator, "%s Send Fail OK : not operator (UserIndex=%d)",
                kFnName, pGetUserIdx(mgr, nullptr, idx));
        return;                                       // молча, как сток
    }

    // 3) ★ GM-флаг из базы (стоковый sub_52ED50; dbo.CharGmInfo.GMFlag)
    if (g_needGmFlag && pIsGm(mgr, nullptr, idx) != 1)
    {
        pSrvLog(Srv::kLogCatOperator, "%s Send Fail OK : no GM flag (UserIndex=%d)",
                kFnName, pGetUserIdx(mgr, nullptr, idx));
        return;
    }

    // 4) длина кадра: 9 заголовка + 24 (токен+MD5) + payload
    if (packetLen < kFrameMin)
    {
        pSrvLog(Srv::kLogCatOperator, "%s Packet Size Error Size=%d", kFnName, packetLen);
        return;
    }

    // 5) анти-тампер (монотонный счётчик) и MD5 тела — как у всех GM-команд
    if (g_needSecret)
    {
        __int64 token = 0;
        memcpy(&token, pkt + 9, sizeof(token));
        if (!pSecretCheck(mgr, nullptr, token, idx, kFnName)) { return; }
        if (!pSignCheck(pkt, (unsigned)kPayloadLen, idx, 1))  { return; }
    }

    const BYTE* payload = pkt + 33;
    int what = payload[0];
    if (what < 0 || what > 3) { what = 0; }           // 0 = все три пересчёта

    RunRecalcCore(mgr, idx, what, nullptr, nullptr);
}

// ═════════════════════════ стабы (naked, MSVC x86) ═══════════════════════════
namespace
{
    // ★ ЗАКОН msvc-inline-asm-offsets: числа для `__asm` — ТОЛЬКО через #define.
    //   C++-константа внутри `__asm` даёт АДРЕС переменной, а не значение.
    #define P25_MARK_IN    0xF7        // маркер прогресса «вошли»  (сток кейса 0x1784)
    #define P25_MARK_OUT   0xF8        // маркер прогресса «вышли»  (сток кейса 0x1784)
    #define P25_DBMARK_IN  0x848       // маркер прогресса ветки default (сток)
    #define P25_DBMARK_OUT 0x849
    #define P25_OP_REPORT  0x91E       // 2334 — наш ответ из базы

    DWORD g_pSwitchTail = Srv::Hooks::kDispatchTail;   // 0x0042F036 — хвост switch
    DWORD g_pDbTail     = 0x0043462B;                  // эпилог диспетчера ответов базы
    DWORD g_pDbDefBack  = 0x00434605;                  // возврат за вытесненные команды

    // Площадка A — мёртвый кейс 0x1784 диспетчера клиентских пакетов.
    //   Выхода «не наш опкод» нет намеренно: сток в этом кейсе не делал НИЧЕГО,
    //   поэтому уход в хвост switch ведёт себя ровно как оригинал.
    __declspec(naked) void GmCmdStub()
    {
        __asm
        {
            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], P25_MARK_IN     // маркер прогресса, как в стоке

            lea  eax, dword ptr [ebp-1048h]
            push eax                              // pkt
            movsx ecx, word ptr [ebp-34h]
            push ecx                              // packetLen (полная длина кадра)
            movsx ecx, word ptr [ebp-44h]
            push ecx                              // charIndex (номер сессии)
            mov  edx, dword ptr [ebp-10C4h]
            mov  eax, dword ptr [edx+4]
            mov  eax, dword ptr [eax+34h]
            push eax                              // CUserManager
            call AsdaOnGmRatingRecalc             // __stdcall — чистит 16 байт сам

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], P25_MARK_OUT
            jmp  dword ptr [g_pSwitchTail]        // хвост switch (сток делает так же)
        }
    }

    // Площадка B — ветка default диспетчера ответов базы.
    __declspec(naked) void DbDefaultStub()
    {
        __asm
        {
            mov  eax, dword ptr [ebp-4]           // указатель на пакет
            cmp  word ptr [eax+7], P25_OP_REPORT  // наш 2334?
            jne  not_ours

            pushfd
            pushad
            push ebp
            call OnRatingReport                   // __cdecl(hostEbp)
            add  esp, 4
            popad
            popfd

            mov  edx, dword ptr [ebp+8]
            mov  dword ptr [edx], P25_DBMARK_OUT  // маркер «вышли»
            jmp  dword ptr [g_pDbTail]            // мимо счётчика «мусорных» пакетов

        not_ours:
            mov  eax, dword ptr [ebp+8]           // ── вытесненные команды ──
            mov  dword ptr [eax], P25_DBMARK_IN
            jmp  dword ptr [g_pDbDefBack]
        }
    }

    // ── площадки (байты сняты со СТОКА GameServer.exe_before_mine_patch.exe,
    //    MD5 4E20F0AD0B13A54454405EED31FFE447, 1 740 800 б) ──────────────────
    const DWORD kSiteGmCase = 0x0042CDFB;
    const BYTE  kOrigGmCase[5] =
    {
        0x8B, 0x4D, 0x08,                   // mov ecx,[ebp+8]
        0xC7, 0x01                          // mov dword [ecx],0F7h (начало)
    };

    const DWORD kSiteDbDefault = 0x004345FC;
    const BYTE  kOrigDbDefault[9] =
    {
        0x8B, 0x45, 0x08,                   // mov eax,[ebp+8]
        0xC7, 0x00, 0x48, 0x08, 0x00, 0x00  // mov dword [eax],848h
    };
}

static bool g_p25Applied = false;   // ★ P127 А2.2: P25 поставлен

PatchResult P25_GmRatingRecalc()
{
    g_enabled = Config::GetBool(kSec, L"Enabled", true);
    if (!g_enabled) { return PatchResult::Disabled; }

    g_needOperator   = Config::GetBool(kSec, L"RequireOperatorIndex", true);
    g_needGmFlag     = Config::GetBool(kSec, L"RequireGmFlag", true);
    g_needSecret     = Config::GetBool(kSec, L"CheckPacketSignature", true);
    g_minIntervalSec = Config::GetInt (kSec, L"MinIntervalSec", 60);
    g_replyChannel   = Config::GetInt (kSec, L"ReplyChannel", 0);
    g_sweepTitles    = Config::GetBool(kSec, L"SweepAllTitles", true);
    g_maxGrants      = Config::GetInt (kSec, L"MaxGrantsPerPass", 2000);
    if (g_maxGrants < 1)      { g_maxGrants = 1;      }
    if (g_maxGrants > 100000) { g_maxGrants = 100000; }
    if (g_minIntervalSec < 0)     { g_minIntervalSec = 0;     }
    if (g_minIntervalSec > 86400) { g_minIntervalSec = 86400; }
    if (g_replyChannel < 0 || g_replyChannel > 255) { g_replyChannel = 0; }

    const Site sites[] =
    {
        { kSiteGmCase,    kOrigGmCase,    sizeof(kOrigGmCase)    },
        { kSiteDbDefault, kOrigDbDefault, sizeof(kOrigDbDefault) },
    };
    if (!VerifyAllSites(L"P25", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (!Hook::WriteJmp(kSiteGmCase, (const void*)&GmCmdStub, sizeof(kOrigGmCase)))
    {
        return PatchResult::Failed;
    }
    if (!Hook::WriteJmp(kSiteDbDefault, (const void*)&DbDefaultStub, sizeof(kOrigDbDefault)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P25: GM-команда «пересчитать рейтинги» — приём 6020 в МЁРТВОМ кейсе "
              L"0x1784 (@%08X), ответ 2334 в ветке default диспетчера базы (@%08X)",
              kSiteGmCase, kSiteDbDefault);
    Log::Line(L"    P25: гейт 1:1 со стоковыми GM-командами — sub_5328F0 + sub_52ECF0 "
              L"(UserIndex 0…5000, %s) + sub_52ED50 (GMFlag, %s) + анти-тампер и MD5 (%s)",
              g_needOperator ? L"включён" : L"ВЫКЛЮЧЕН",
              g_needGmFlag   ? L"включён" : L"ВЫКЛЮЧЕН",
              g_needSecret   ? L"включены" : L"ВЫКЛЮЧЕНЫ");
    Log::Line(L"    P25: пересчёт условий ВСЕХ званий у онлайн-игроков %s "
              L"(sub_54B260 с a6=0, гейт sub_54A890, предел выдач за проход %d). "
              L"★ 25 званий пересчитать нечем: их значение живёт только в событии; "
              L"персонажи не в игре не охвачены — накопители лежат в CUser",
              g_sweepTitles ? L"включён" : L"ВЫКЛЮЧЕН", g_maxGrants);
    Log::Line(L"    P25: рейтинговые 65…69 и топ славы считает база: шлём 2333 (10 б), "
              L"ждём 2334; сам GameServer к базе не подключён");
    Log::Line(L"    P25: порог частоты %d с (авторитетный порог — MinForceSec на стороне "
              L"P23); ответ оператору идёт стоковым 6561, канал %d",
              g_minIntervalSec, g_replyChannel);
    Log::Line(L"    P25: ! нужен DBPatch.dll с P23 (приём 2333) и SQL-миграция рейтингов; "
              L"★ команда доступна ТОЛЬКО учётке с UserIndex 0…5000 (ADM_*): "
              L"у GM_sitxovski индекс 75180, его не пропустит стоковый sub_52ECF0");
    g_p25Applied = true;   // ★ P127 А2.2: функции пересчёта №3 сверены
    return PatchResult::Applied;
}

// ★ P127 А2.2 (18.11.2026): пересчёт №3 для ОДНОГО игрока в игре (мост админ-центра) — тот же SweepUser, что у GM-команды 6020.
//   Нить карты игрока. → выдано званий; −1 — P25 не поставлен / пересчёт выключен / игрока нет.
bool P25_Applied() { return g_p25Applied; }
// ★ P127 А5.4 (21.11.2026): «пересчитать рейтинги сейчас» от имени оператора-цели моста — шаги 6–8 команды 6020 (RunRecalcCore):
//   те же порог частоты, пересчёт №3 и запрос 2333 в базу, ответ 2334 придёт оператору строками, как у команды из игры. Гейты
//   оператора и GM-флага делает мост (как сток); подписи пакета у моста нет. Нить карты оператора. −1 — P25 не поставлен / выключен.
int P25_RunRecalc(void* mgr, int userNum, int what, int* outA, int* outB)
{
    if (outA) { *outA = 0; }
    if (outB) { *outB = 0; }
    if (!g_p25Applied || !g_enabled || !mgr || what < 0 || what > 3) { return -1; }
    return RunRecalcCore(mgr, (short)userNum, what, outA, outB);
}
int P25_RecalcUser(void* mgr, int userNum, int* checked, int* skipped)
{
    *checked = 0; *skipped = 0;
    if (!g_p25Applied || !g_sweepTitles || !mgr) { return -1; }
    const int count = FameCount();
    const BYTE* table = FameTable();
    if (count <= 0 || count > 4096 || !table) { return -1; }
    BYTE* pUser = (BYTE*)pGetUser(mgr, nullptr, (short)userNum);
    if (!pUser || *(const int*)(pUser + kOffUserIndex) < 0 || *(const DWORD*)(pUser + kOffOnline) != 1) { return -1; }
    return SweepUser(mgr, (short)userNum, pUser, count, table, checked, skipped, g_maxGrants);
}
