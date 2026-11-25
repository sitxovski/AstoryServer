// Copyright (c) 2026 @sitxovski (Discord)
// Config.cpp — <DBManager>\ConfigSet\dbpatch.ini.
//
// Механика повторяет AsdaPatch (бережное слияние через штатные Win-ini API), но
// набор секций свой: только то, что имеет смысл в процессе работы с базой.
#include "Config.h"
#include "Log.h"
#include <windows.h>

namespace
{
    // ── описание одного ключа: имя, значение по умолчанию, комментарий ──────
    struct IniKey
    {
        const wchar_t* key;
        const wchar_t* def;
        const wchar_t* comment;     // пишется ПЕРЕД ключом, уже с \r\n
    };

    struct IniSection
    {
        const wchar_t* name;
        const wchar_t* header;      // шапка секции, уже с \r\n
        const IniKey*  keys;
        int            keyCount;
    };

    // ── [General] ──────────────────────────────────────────────────────────
    // ⚠ Version НЕ хранится здесь строкой: значение подставляется из
    //   Config::kVersion в BuildSectionText. Ровно из-за расхождения шаблона и
    //   константы AsdaPatch 30.08.2026 свежесозданный ini объявлялся негодным.
    const IniKey kGeneral[] =
    {
        { L"Version", L"",          // ← значение подставляется из kVersion
          L"; Версия формата файла. Меняет только сама DLL при миграции.\r\n" },
        { L"MasterEnable", L"0",
          L"; * ГЛАВНЫЙ ВЫКЛЮЧАТЕЛЬ. 0 = не ставить НИ ОДИН патч (DBManager работает\r\n"
          L";   как сток). Штатный режим первой проверки: убедиться, что DLL грузится\r\n"
          L";   и процесс поднимается, и только потом поставить 1.\r\n" },
        { L"LogEnabled", L"1",
          L"; * Журнал установки: Log\\Log_Patch\\PatchLog_<ГГГГММДД>.txt\r\n" },
    };

    // ── [P22_DbFameHigh] ───────────────────────────────────────────────────
    const IniKey kDbFameHigh[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = DBManager не знает новых опкодов,\r\n"
          L";   старшая половина маски званий не сохраняется (как было до правки).\r\n" },
        { L"LoadHigh", L"1",
          L"; * Опкод 2330 «дай старшую половину»: EXEC UPCharFameBankHi и\r\n"
          L";   UPCharFameProgressHi, ответ 2332 (72 б). 0 = не отвечать.\r\n" },
        { L"SaveHigh", L"1",
          L"; * Опкод 2331 «сохрани старшую половину»: EXEC UPCharFameBankHiUp и\r\n"
          L";   UPCharFameProgressHiUp. 0 = не сохранять.\r\n" },
    };

    // ── [P23_TitleRankFeed] ────────────────────────────────────────────────
    const IniKey kTitleRankFeed[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = звания 65…69 никто не раздаёт\r\n"
          L";   (как было в оригинале: приёмник есть, отправителя нет).\r\n" },
        { L"IntervalSec", L"600",
          L"; * Период пересчёта лидеров, СЕКУНДЫ. Решение владельца — 10 минут.\r\n"
          L";   Допустимо 30…86400; значение вне диапазона подтягивается к границе.\r\n"
          L";   Пересчёт идёт НА РАБОЧЕМ ПОТОКЕ DBManager по ближайшему DB-пакету\r\n"
          L";   после истечения периода — своего потока патч не создаёт.\r\n"
          L";   Один проход: UPTopLevelAll + UPTopLevelClass + UPTopGold →\r\n"
          L";   UPFameRatingHolderUp → UPFameRatingHolder → UPFameRatingRevokeList →\r\n"
          L";   UPCharFameBitDis (снятие бита в базе, и у офлайнового) + пакет + UPFameRatingRevokeUp.\r\n" },
        { L"TrustIsOnline", L"1",
          L"; * Доверять ли столбцу UserNum из базы (dbo.CharPos.Usernum через\r\n"
          L";   представление; NULL / <0 / >549 там уже нормализованы в -1).\r\n"
          L";   1 = брать его как подсказку, когда своей записи об этой сессии нет.\r\n"
          L";   0 = верить ТОЛЬКО собственной таблице онлайна (мы своими глазами\r\n"
          L";   видели DB-пакеты этой сессии). При подозрении на мусор в CharPos - 0.\r\n"
          L";   * В пакет в любом случае уходит только userNum из 0...549: вне этого\r\n"
          L";   диапазона стоковый sub_54D710 обрывает разбор пакета (break).\r\n" },
        { L"MaxGrantAttempts", L"3",
          L"; * САМОЗАЖИВЛЕНИЕ: сколько проходов подряд пытаться выдать звание, если\r\n"
          L";   бит в маске персонажа так и не появился. Отметка Granted ставится по\r\n"
          L";   факту ОТПРАВКИ пакета (подтверждения применения приёмник не шлёт),\r\n"
          L";   поэтому каждый проход она сверяется с фактом через UPCharFameBitInfo:\r\n"
          L";   отметка есть, а бита нет -> сброс в 0 и выдача заново.\r\n"
          L";   Исчерпав попытки, патч перестаёт долбить и пишет громкую строку в журнал.\r\n"
          L";   Счёт обнуляется при смене держателя звания. Допустимо 1...100.\r\n" },
        { L"ClearSlot", L"1",
          L"; * Просить базу снимать звание и со слота «надето» (Fmidx1/Fmidx2 -> -1).\r\n"
          L";   ⚠ Если SQL-тип Fmidx1/Fmidx2 окажется tinyint, -1 туда не влезет —\r\n"
          L";   в журнале появится строка «бит снят, а СЛОТ НЕ ОЧИЩЕН». Тогда ставьте 0.\r\n" },
        { L"SendPackets", L"1",
          L"; * 0 = ничего не отправлять, только считать и писать в журнал\r\n"
          L";   (режим холостой проверки миграции на боевом сервере).\r\n" },
        { L"MatchCharSlot", L"1",
          L"; * Исправление дефекта ОРИГИНАЛА: ни сток, ни P24 не сверяют Charidx,\r\n"
          L";   поэтому звание могло достаться ДРУГОМУ персонажу того же аккаунта.\r\n"
          L";   1 = придержать живую выдачу, если по таблице онлайна в игре другой слот;\r\n"
          L";   запись держателя в базе при этом уже стоит. 0 = как в оригинале.\r\n" },
        { L"OnDemand", L"1",
          L"; * ★ GM-КОМАНДА «ПЕРЕСЧИТАТЬ СЕЙЧАС». Пара — патч GameServer P25\r\n"
          L";   (AsdaPatch.dll): оператор шлёт опкод 6020, GameServer передаёт сюда\r\n"
          L";   опкод 2333, мы делаем ОБА пересчёта и отвечаем 2334 (числа + имена\r\n"
          L";   новых лидеров), которые P25 печатает оператору в чат.\r\n"
          L";   0 = команду не принимать (пересчёт только по расписанию).\r\n" },
        { L"MinForceSec", L"60",
          L"; * ★ АВТОРИТЕТНЫЙ порог частоты GM-команды, секунды. Проход трогает\r\n"
          L";   всю таблицу персонажей и dbo.Item — частые запуски кладут базу.\r\n"
          L";   Второй, «мгновенный» порог стоит в GameServer (patches.ini,\r\n"
          L";   [P25_GmRatingRecalc] MinIntervalSec); отказ по нему приходит быстрее,\r\n"
          L";   но решает всё равно ЭТОТ ключ — он считает реально выполненные проходы.\r\n"
          L";   0 = не ограничивать (не рекомендуется).\r\n" },
        { L"FamePointOnDemand", L"1",
          L"; * ★ ПЕРЕСЧЁТ №2 в составе GM-команды: EXEC dbo.UPTopFamePoint -> опкод 3409\r\n"
          L";   («место в рейтинге по очкам славы»). Это ровно то, что в оригинале\r\n"
          L";   происходит в 03:00: процедура САМА чистит и заново набивает\r\n"
          L";   dbo.FamePointRank (RANK() OVER (ORDER BY Fmpoint DESC) по dbo.CharFameBank,\r\n"
          L";   Userindex > 5000 — то есть GM-учётки в рейтинг не попадают) и САМА\r\n"
          L";   возвращает TOP 100 строк по 13 байт, которые и есть записи пакета.\r\n"
          L";   0 = команда пересчитывает только звания 65…69.\r\n" },
        { L"FamePointIntervalSec", L"0",
          L"; * Периодический пересчёт №2 БЕЗ команды, секунды. По умолчанию 0 =\r\n"
          L";   ВЫКЛЮЧЕН: в оригинале это делает задача ChannelManager «Title Rank\r\n"
          L";   Process» ежедневно в 03:00 (журнал ChannelManager\\Error_Log\\TitleLog_*.txt),\r\n"
          L";   и дублировать чужое расписание мы не вправе. Значение < 60 подтягивается\r\n"
          L";   к 60. Ставьте, только если владелец хочет обновлять топ чаще.\r\n" },
        { L"ServerGroup", L"0",
          L"; * Группа серверов для выбора соединения с базой (DBMng.ini,\r\n"
          L";   [SERVERGROUP] count = 1 ⇒ 0). Меняйте только вместе с DBMng.ini.\r\n" },
    };

    // ── [P26_SoulmateNoteSqli] ─────────────────────────────────────────────
    const IniKey kSoulmateNoteSqli[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = записка соулмейта уходит в sprintf\r\n"
          L";   как в оригинале, вместе с SQL-инъекцией (см. описание секции).\r\n"
          L";   ★ Включение НИЧЕГО не меняет для честного клиента: он и сам\r\n"
          L";   заменяет апостроф на обратную кавычку и шлёт 1..64 символа.\r\n" },
    };

    // ── [P28_SqlArgEscape] ─────────────────────────────────────────────────
    const IniKey kSqlArgEscape[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = запросы к базе собираются как в стоке,\r\n"
          L";   вместе со ВСЕМ классом SQL-инъекций (24 площадки с текстом из пакета).\r\n"
          L";   * Включение НИЧЕГО не меняет для честного клиента: апострофов он\r\n"
          L";   не шлёт. Уже лежащие в базе записи патч НЕ трогает вообще — он правит\r\n"
          L";   копию тела пакета в кадре, а не содержимое таблиц.\r\n" },
        { L"MaxScan", L"4096",
          L"; * Предел чтения ОДНОЙ строки-аргумента, байт (64...4096).\r\n"
          L";   Чтение и так идёт до первого нуля; предел — страховка на случай\r\n"
          L";   незавершённой строки. Столько же прочитал бы стоковый vsprintf,\r\n"
          L";   то есть зону чтения патч НЕ расширяет.\r\n" },
        { L"LogHits", L"0",
          L"; * Диагностика: писать в журнал факт замены (число апострофов и имя\r\n"
          L";   запроса; САМ ТЕКСТ игрока в журнал НЕ попадает). Не более 20 строк\r\n"
          L";   за запуск. По умолчанию 0 — на боевом сервере не нужен.\r\n" },
    };

    // ── [P37_CraftLevelScrollCode] ─────────────────────────────────────────
    const IniKey kCraftLevelScrollCode[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = ответ 2668 снова всегда несёт код 1\r\n"
          L";   (как в стоке): отказ процедуры и ошибка SQL выглядят для GameServer\r\n"
          L";   успехом. ⚠ При 0 выключить и P35 LevelScrollSync в patches.ini\r\n"
          L";   GameServer / Indun_GameServer — он достоверен только с этим патчем.\r\n" },
    };

    // ── [P85_DbPostRows] (25.10.2026): список премиум-почты до 49 записей ──
    const IniKey kPostRows[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: больше 7 записей UPCashitemList → пустой список.\r\n" },
    };

    // ── [P96_DbShellRows] (30.10.2026): строки сумки (Plate 1) до 60 ──
    const IniKey kShellRows[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: больше 30 строк сумки → в GameServer уходят 30 (ячейки 30..59\r\n"
          L";   отбрасываются). ⚠ 0 только вместе с откатом AsdaPatch P96 и после проверки, что в Item нет Plate 1 Posx >= 30.\r\n" },
    };

    // ── [P78_SoulmateSharePortal] (23.10.2026): строки «поделиться» соулмейта при портале 2089 ──
    const IniKey kSoulmateSharePortal[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: портал 2089 разбирает строки UPSoulMateShare\r\n"
          L";   шагом 21 без байта Charidx — имена и флаги «поделиться» соулмейта в блоке CUser сдвигаются\r\n"
          L";   (Share = байты имени), и следующий клик по галке (5221) записывает их в БД.\r\n" },
    };

    // ── [P50_IdentityCheck] — античит А0 (2026-10-12): сверка личности при DB-логоне ──
    const IniKey kIdentityCheck[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = 2001/2089 идут в сток без сверки (как до 12.10).\r\n" },
        { L"CheckIp", L"1",
          L"; * Сверять IP пира (хвост от GameServer P47) с открытой записью входа\r\n"
          L";   JoyLog1.dbo.Loginfo (или с только что закрытой записью соулмейта).\r\n" },
        { L"RefuseBlocked", L"1",
          L"; * Отказ, если us_block учётки <> 0 (блок, выданный уже после входа в LoginManager).\r\n" },
        { L"RequireSession", L"1",
          L"; * Отказ, если у учётки нет открытой записи входа (Logout IS NULL).\r\n" },
        { L"RequireIp", L"0",
          L"; Отказ, если IP не передан (старый AsdaPatch или P47 SendPeerIp=0).\r\n" },
        { L"FailOpen", L"1",
          L"; * Ошибка самого запроса (процедуры нет, база не ответила): 1 = пропуск со строкой\r\n"
          L";   в журнале, 0 = отказ.\r\n" },
        { L"LogPass", L"0",
          L"; Писать в журнал и успешные проверки (диагностика).\r\n" },
        { L"BlockedClientCode7", L"1",
          L"; * ★ acdb (P54): отказ ИМЕННО по блоку учётки (в т. ч. вход соулмейтом в персонажа\r\n"
          L";   заблокированного хозяина) помечается в ответе 2002/2090, и GameServer (P54) шлёт игроку\r\n"
          L";   4101 код 7 «учетная запись заблокирована». 0 = код 5 «недостаточно данных», как было.\r\n" },
    };

    // ── [P53_AcJournal] — античит acdb (12.10.2026): журнал античита в БД joylog1.ac ──
    const IniKey kAcJournal[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель журнала. 0 = ни очереди, ни потока (отказы P50 — только в PatchLog).\r\n" },
        { L"ConnectionString", L"",
          L"; Строка подключения ODBC. Пусто = DSN/логин/пароль из DbConfigFile (DBMng.ini).\r\n" },
        { L"DbConfigFile", L"DBMng.ini",
          L"; Откуда взять GAMEDNS/GAMEUSER/GAMEPASS (относительно папки DBManager.exe).\r\n" },
        { L"DbConfigSection", L"DB_DNS0_0", nullptr },
        { L"Database", L"joylog1", L"; База журнала (схема ac).\r\n" },
        { L"FlushIntervalMs", L"2000", L"; Период записи пакета, мс.\r\n" },
        { L"BatchMax", L"500", L"; Событий в одном пакете INSERT (1..1000).\r\n" },
        { L"QueueCapacity", L"4096",
          L"; Ёмкость очереди. Переполнение — событие отбрасывается и считается, поток БД не ждёт.\r\n" },
        { L"PerSessionPerMinute", L"60", nullptr },
        { L"ReconnectSec", L"30", L"; Пауза между попытками подключения.\r\n" },
        { L"FileFallback", L"1",
          L"; База недоступна — пакет в Log\\Log_AcJournal\\AcJournal_<дата>.sql (sqlcmd -i). 0 = отбрасывать.\r\n" },
        // ★ fix2 (СРЕДН-4 integ3): предел файлового журнала
        { L"FileRowsPerMinute", L"3000", L"; Не больше N событий в файл в минуту (остальные — счётчиком + сводка «пропущено K»). 0 = без.\r\n" },
        { L"MaxFileMB", L"256", L"; Потолок суточного файла AcJournal_<дата>.sql, МБ. 0 = без.\r\n" },
        { L"FileDir", L"", L"; Папка файлового журнала. Пусто = <exe>\\Log\\Log_AcJournal.\r\n" },
        { L"PurgeDays", L"0", L"; Очистку журнала ведёт GameServer (P53 там: 90 сут). 0 = не чистить отсюда.\r\n" },
        { L"ServerName", L"", L"; Имя источника в журнале. Пусто = имя папки exe.\r\n" },
        { L"NameCodePage", L"1251", nullptr },
        { L"LoginTimeoutSec", L"5", nullptr },
        { L"QueryTimeoutSec", L"15", nullptr },
    };

    // ── [P125_DbReconnect] (15.11.2026): повторное подключение к SQL Server после обрыва связи ──
    const IniKey kDbReconnect[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: после обрыва связи с базой каждая сессия отвечает\r\n"
          L";   ошибкой до перезапуска процесса.\r\n" },
        { L"Retry", L"1",
          L"; * 1 = после удачного переподключения запрос повторяется ОДИН раз. 0 = сессия открывается заново,\r\n"
          L";   но запрос, на котором обнаружен обрыв, отдаёт ошибку стоку (следующие запросы уже работают).\r\n"
          L";   Обрыв на отправке запроса повторять безопасно; при обрыве на приёме ответа сервер мог успеть\r\n"
          L";   выполнить запрос — повтор выполнит его второй раз.\r\n" },
        { L"Probe", L"1",
          L"; * 1 = если по сведениям об ошибке неясно, жива ли связь, сессия проверяется запросом SELECT 1.\r\n"
          L";   0 = переподключение только при SQLSTATE 08xxx или сетевом коде ошибки.\r\n" },
        { L"ReleaseOld", L"1",
          L"; * 1 = объекты оборванной сессии освобождаются. 0 = остаются висеть (на случай зависания драйвера\r\n"
          L";   при закрытии мёртвого соединения).\r\n" },
        { L"ComInit", L"1",
          L"; * 1 = COM на рабочем потоке включается один раз перед его первым запросом: без этого поставщик не оставляет\r\n"
          L";   сведений об ошибке и обрыв определяется только проверкой SELECT 1. 0 = потоки как в стоке.\r\n" },
        { L"RetryIntervalMs", L"10000",
          L"; * После НЕудачной попытки открыть сессию заново следующая попытка на этой сессии — не раньше чем\r\n"
          L";   через столько миллисекунд (рабочий поток не ждёт подключения на каждом запросе).\r\n" },
        { L"ConnectTimeoutSec", L"5",
          L"; * Предел ожидания нового подключения, секунд (0 — как у драйвера).\r\n" },
        { L"LogPerMinute", L"30",
          L"; * Строк PatchLog о переподключениях в минуту, не больше.\r\n" },
    };

    const IniSection kSections[] =
    {
        { L"General",
          L"; ===========================================================================\r\n"
          L"; AsdaReborn — патчи DBManager. Ставит DBPatch.dll (грузится через таблицу\r\n"
          L"; импорта DBManager.exe, ДО точки входа). Патчи применяются В ПАМЯТИ.\r\n"
          L";\r\n"
          L"; ★ Это НЕ patches.ini от GameServer. У каждого процесса своя DLL и свой\r\n"
          L";   файл настроек: DBPatch.dll + dbpatch.ini здесь, AsdaPatch.dll +\r\n"
          L";   patches.ini у GameServer, AddonNPC.dll у NpcServer.\r\n"
          L";\r\n"
          L"; Правится при ОСТАНОВЛЕННОМ процессе, читается один раз при старте.\r\n"
          L"; * Ваши правки НЕ ТЕРЯЮТСЯ: при обновлении DLL дописывает только\r\n"
          L";   НЕДОСТАЮЩИЕ ключи и секции, существующие значения остаются как есть.\r\n"
          L"; Описание: AstoryServer\\Docs\\DBManager\\db-fame-high-p22.md\r\n"
          L"; ===========================================================================\r\n",
          kGeneral, ARRAYSIZE(kGeneral) },

        { L"P22_DbFameHigh",
          L"; * НАША правка (30.08.2026). Пара к P21 (GameServer): старшая половина\r\n"
          L";   маски славы (звания id 256…511) должна переживать перезаход, а\r\n"
          L";   DB-пакеты 2256/2257/2266 несут ровно 4 qword и удлинять их нельзя.\r\n"
          L";   Добавлены ДВА НОВЫХ опкода: 2330 «дай» и 2331 «сохрани», ответ 2332.\r\n"
          L";   Существующие обработчики, таблицы и процедуры НЕ тронуты — данные\r\n"
          L";   ложатся в НОВУЮ таблицу dbo.CharFameHigh.\r\n"
          L";   !! Требует SQL-миграции: SQL/title_mask_512_01_migrate.sql.\r\n"
          L";   Без процедур патч пишет одну строчку в журнал и отключается.\r\n",
          kDbFameHigh, ARRAYSIZE(kDbFameHigh) },

        { L"P23_TitleRankFeed",
          L"; * НАША правка (30.08.2026). Рейтинговые звания 65…69 вкладки\r\n"
          L";   «Соревнование»: «Впереди планеты всей», «Бог сражений/лучников/магии»,\r\n"
          L";   «Богатенький буратино». Приёмник в GameServer рабочий (опкоды\r\n"
          L";   3404…3408, sub_54D710@0x54D710), а ОТПРАВИТЕЛЯ не было ни в одном\r\n"
          L";   образе сервера — звания были недостижимы. Патч и есть отправитель.\r\n"
          L";   !! Требует SQL-миграции рейтингов: SQL/fame_rating_01_migrate.sql\r\n"
          L";   (14 объектов, только CREATE, идемпотентно). Без процедур патч делает\r\n"
          L";   3 неудачных прохода, пишет строку в журнал и отключается до перезапуска.\r\n"
          L";   Пара в GameServer — P24 (снятие звания у прежнего лидера).\r\n",
          kTitleRankFeed, ARRAYSIZE(kTitleRankFeed) },

        { L"P26_SoulmateNoteSqli",
          L"; * НАША правка (30.08.2026), БЕЗОПАСНОСТЬ. Записка соулмейта (клиентский\r\n"
          L";   опкод 6052 -> DB-опкод 2238) склеивалась в текст запроса обычным\r\n"
          L";   sprintf-ом: EXEC UPSoulMateNoteInput %d, %d, '%s' — апостроф в тексте\r\n"
          L";   закрывал литерал, и остаток записки уходил в SQL Server как КОД.\r\n"
          L";   Единственной защитой была КЛИЕНТСКАЯ замена ' на ` — она обходится\r\n"
          L";   подделкой пакета. Хранимая процедура тут не помогает: она сама\r\n"
          L";   параметризована, инъекция происходит раньше, при сборке команды.\r\n"
          L";   Патч чистит поле записки в кадре ДО сборки запроса: апостроф -> `\r\n"
          L";   (ровно как штатный клиент) и жёсткий терминатор в байте [64]\r\n"
          L";   (заодно закрыт дефект С6 — незавершённая строка на 65 непустых байт).\r\n"
          L";   SQL-миграции НЕ требует. Описание:\r\n"
          L";   AstoryServer\\Docs\\DBManager\\soulmate-note-sqli-p26.md\r\n",
          kSoulmateNoteSqli, ARRAYSIZE(kSoulmateNoteSqli) },

        { L"P28_SqlArgEscape",
          L"; * НАША правка (30.08.2026), БЕЗОПАСНОСТЬ. ОБЩЕЕ закрытие класса:\r\n"
          L";   одна площадка вместо 24. Все обработчики DB-опкодов кладут текст из\r\n"
          L";   тела пакета в кадр и отдают его общему сборщику запроса\r\n"
          L";   sub_447720@0x00447720, а тот делает vsprintf по формату вида\r\n"
          L";   EXEC UPxxx %d, %d, '%s' — БЕЗ экранирования апострофа.\r\n"
          L";   Проверены ВСЕ 25 таких площадок: у 24 строка-аргумент указывает в\r\n"
          L";   кадр со свежескопированным телом пакета (текст задаёт игрок),\r\n"
          L";   у одной (sub_42B9A0) там пустой указатель.\r\n"
          L";   Патч разбирает строку формата, следит за кавычками и чистит только\r\n"
          L";   те аргументы-строки, что стоят ВНУТРИ кавычек: апостроф меняется на\r\n"
          L";   обратную кавычку, ровно как это делает штатный клиент. Длина текста\r\n"
          L";   сохраняется, строка остаётся читаемой — НИЧЕГО не обрезается.\r\n"
          L";   Дополняет P26 (тот ещё ставит терминатор поля записки), не заменяет.\r\n"
          L";   SQL-миграции НЕ требует. Описание:\r\n"
          L";   AstoryServer\\Docs\\DBManager\\sql-arg-escape-p28.md\r\n",
          kSqlArgEscape, ARRAYSIZE(kSqlArgEscape) },

        { L"P37_CraftLevelScrollCode",
          L"; * НАША правка (27.09.2026). Ремесло: повышение уровня свитком\r\n"
          L";   (GameServer 6604 -> DB 2667 -> EXEC UP_CRT_CraftLevelScroll -> 2668).\r\n"
          L";   Обработчик sub_445B60 снимал копию запроса для ответа ДО процедуры,\r\n"
          L";   а код 1/99/98 писал в исходный буфер — GameServer всегда получал 1.\r\n"
          L";   Патч: три замены по 7 б (0x445CE7/0x445D6D/0x445DB3), код пишется в\r\n"
          L";   отправляемую копию. Протокол прежний, SQL-миграции НЕ требует.\r\n"
          L";   Описание: AstoryServer\\Docs\\DBManager\\craft-level-scroll-code-p37.md\r\n",
          kCraftLevelScrollCode, ARRAYSIZE(kCraftLevelScrollCode) },

        { L"P50_IdentityCheck",
          L"; * НАША правка, БЕЗОПАСНОСТЬ (античит А0, 12.10.2026). Вход 2001 и портал 2089:\r\n"
          L";   до UPCharInfo — EXEC dbo.UP_AC_IdentityCheck (Joy1, SQL P51): учётка есть и не\r\n"
          L";   заблокирована, слот принадлежит учётке, есть открытая запись входа, IP пира\r\n"
          L";   совпал (хвост от GameServer P47). Отказ — штатный ответ 2002/2090 [0]=0.\r\n"
          L";   Описание: AstoryServer\\Docs\\DBManager\\identity-check-p50.md\r\n",
          kIdentityCheck, ARRAYSIZE(kIdentityCheck) },

        { L"P53_AcJournal",
          L"; * НАША правка (античит, волна acdb, 12.10.2026, решение владельца): журнал античита в\r\n"
          L";   БД joylog1.ac. Из DBManager пишутся отказы сверки входа P50 (ac.login_check_refusal).\r\n"
          L";   Запись без задержки: очередь без блокировок + фоновый поток + своё соединение ODBC\r\n"
          L";   (не через поток запросов DBManager); база недоступна — файловый журнал.\r\n"
          L";   Описание: AstoryServer\\Docs\\GameServer\\ac-journal-p53.md\r\n",
          kAcJournal, ARRAYSIZE(kAcJournal) },

        { L"P78_SoulmateSharePortal",
          L"; * НАША правка (23.10.2026, слово владельца). Соулмейт, блок «поделиться персонажем»:\r\n"
          L";   вход 2001 (sub_407480) кладёт строки EXEC UPSoulMateShare (Charidx, Charname, Share = 22 б)\r\n"
          L";   верно, а портал 2089 (sub_417410) — шагом 21 и с байта Charidx: после каждого портала\r\n"
          L";   имена сдвинуты, Share1..3 = 0. Патч: три замены байт (0x419156/0x41917F/0x4191A3) — как у\r\n"
          L";   входа. Протокол прежний. Пара — SQL upsoulmateshare_fix_20261023.sql (ровно 3 строки по слотам).\r\n"
          L";   Описание: AstoryServer\\Docs\\DBManager\\soulmate-share-slots-p78.md\r\n",
          kSoulmateSharePortal, ARRAYSIZE(kSoulmateSharePortal) },

        { L"P85_DbPostRows",
          L"; * НАША правка (25.10.2026, слово владельца, дефект оригинала). Премиум-почта: обработчик 2602\r\n"
          L";   (sub_43EF50) принимал от UPCashitemList не больше 70 байт (7 записей) — иначе пустой список.\r\n"
          L";   Корзина = несколько записей одного заказа, окно 7 строк × 7 ячеек ⇒ потолок 490 байт (49 записей),\r\n"
          L";   площадка 0x43F0DC. Протокол 2603/11005 прежний. Журнал ac.other 102.\r\n"
          L";   ⚠ 0 = сток: тогда откатить и SQL premrows (иначе у игроков с корзиной ящик пуст).\r\n",
          kPostRows, ARRAYSIZE(kPostRows) },

        { L"P96_DbShellRows",
          L"; * НАША правка (30.10.2026, задача владельца «инвентарь ×2»: сумка 30 → 60). Отдача сумки (Plate 1)\r\n"
          L";   в GameServer — sub_422C20 (0x7F7) и sub_423600 (вход 2001 / портал 2089) — обрезала ответ UPPlateItem\r\n"
          L";   до 30 строк. Патч: 4 байта 1Eh -> 3Ch, площадки по сигнатуре. Буфер 60x57 = 3420 < 14000, протокол прежний.\r\n"
          L";   Пара — AsdaPatch [P96_InventoryX2] у GameServer. Описание: AstoryServer\\Docs\\DBManager\\db-shell-rows-p96.md\r\n",
          kShellRows, ARRAYSIZE(kShellRows) },

        { L"P125_DbReconnect",
          L"; * НАША правка (15.11.2026, дефект оригинала). После обрыва связи с SQL Server (14.11.2026 21:08 — обновление\r\n"
          L";   Tailscale, через адрес которого шли соединения) DBManager отвечал ошибкой 80004005 на каждый запрос до\r\n"
          L";   перезапуска: сток открывает источник и 10 сессий один раз при старте и никогда не открывает заново.\r\n"
          L";   Патч: вызов Execute в sub_447720 (0x447B49, 5 б) идёт через DBPatch — при обрыве сессия открывается\r\n"
          L";   заново и запрос повторяется один раз. Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p125.md\r\n",
          kDbReconnect, ARRAYSIZE(kDbReconnect) },
    };

    // ── состояние ───────────────────────────────────────────────────────────
    wchar_t g_path[MAX_PATH] = L"";
    wchar_t g_base[MAX_PATH] = L"";
    bool    g_created = false;

    // Дописать текст в конец файла (ini-API умеет только ключи, шапки пишем сами).
    void AppendText(const wchar_t* text)
    {
        HANDLE h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        SetFilePointer(h, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(h, text, (DWORD)(lstrlenW(text) * sizeof(wchar_t)), &written, nullptr);
        CloseHandle(h);
    }

    // Собрать полный текст секции: шапка + ключи с комментариями.
    void BuildSectionText(const IniSection& s, wchar_t* out, unsigned cch)
    {
        wchar_t tmp[2048];
        out[0] = 0;
        wsprintfW(tmp, L"[%s]\r\n", s.name);
        lstrcatW(out, tmp);
        if (s.header) { lstrcatW(out, s.header); }
        for (int i = 0; i < s.keyCount; ++i)
        {
            if (s.keys[i].comment) { lstrcatW(out, s.keys[i].comment); }
            // ★ Version — единственный ключ, значение которого берётся из кода.
            if (lstrcmpiW(s.keys[i].key, L"Version") == 0 && s.keys[i].def[0] == 0)
            {
                wsprintfW(tmp, L"%s=%d\r\n", s.keys[i].key, Config::kVersion);
            }
            else
            {
                wsprintfW(tmp, L"%s=%s\r\n", s.keys[i].key, s.keys[i].def);
            }
            lstrcatW(out, tmp);
        }
        lstrcatW(out, L"\r\n");
        (void)cch;
    }

    bool SectionExists(const wchar_t* name)
    {
        wchar_t buf[4];
        SetLastError(0);
        DWORD n = GetPrivateProfileSectionW(name, buf, ARRAYSIZE(buf), g_path);
        return n > 0 || GetLastError() == ERROR_MORE_DATA;
    }

    bool KeyExists(const wchar_t* section, const wchar_t* key)
    {
        wchar_t buf[8];
        GetPrivateProfileStringW(section, key, L"\x01", buf, ARRAYSIZE(buf), g_path);
        return buf[0] != L'\x01';
    }

    void CreateFull()
    {
        HANDLE h = CreateFileW(g_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        const WORD bom = 0xFEFF;                    // UTF-16LE — родной формат Win-ini API
        DWORD w = 0;
        WriteFile(h, &bom, sizeof(bom), &w, nullptr);
        CloseHandle(h);

        wchar_t buf[8192];
        for (const auto& s : kSections)
        {
            BuildSectionText(s, buf, ARRAYSIZE(buf));
            AppendText(buf);
        }
        g_created = true;
    }
}

namespace Config
{
    bool Init(const wchar_t* baseDir)
    {
        lstrcpynW(g_base, baseDir, MAX_PATH);
        wchar_t dir[MAX_PATH];
        wsprintfW(dir, L"%sConfigSet", baseDir);
        CreateDirectoryW(dir, nullptr);
        wsprintfW(g_path, L"%s\\dbpatch.ini", dir);

        if (GetFileAttributesW(g_path) == INVALID_FILE_ATTRIBUTES) { CreateFull(); }
        return GetFileAttributesW(g_path) != INVALID_FILE_ATTRIBUTES;
    }

    const wchar_t* Path()      { return g_path; }
    const wchar_t* BaseDir()   { return g_base; }
    bool WasCreated()          { return g_created; }

    int GetInt(const wchar_t* section, const wchar_t* key, int def)
    {
        return (int)GetPrivateProfileIntW(section, key, def, g_path);
    }

    bool GetBool(const wchar_t* section, const wchar_t* key, bool def)
    {
        return GetInt(section, key, def ? 1 : 0) != 0;
    }

    void GetStr(const wchar_t* section, const wchar_t* key, const wchar_t* def,
                wchar_t* out, int cch)
    {
        GetPrivateProfileStringW(section, key, def, out, cch, g_path);
    }

    // Досоздание недостающих секций/ключей. Существующие значения не трогаются.
    void MergeMissing()
    {
        if (g_created)
        {
            Log::Line(L"Конфиг : создан с нуля со значениями по умолчанию (Version=%d).",
                         kVersion);
            return;
        }

        const int fileVer = GetInt(L"General", L"Version", 0);
        int addedSections = 0, addedKeys = 0;
        wchar_t buf[8192];

        for (const auto& s : kSections)
        {
            if (!SectionExists(s.name))
            {
                BuildSectionText(s, buf, ARRAYSIZE(buf));
                AppendText(buf);
                ++addedSections;
                Log::Line(L"Конфиг : добавлена секция [%s].", s.name);
                continue;
            }
            for (int i = 0; i < s.keyCount; ++i)
            {
                if (KeyExists(s.name, s.keys[i].key)) { continue; }
                wchar_t v[32];
                const wchar_t* val = s.keys[i].def;
                if (lstrcmpiW(s.keys[i].key, L"Version") == 0 && val[0] == 0)
                {
                    wsprintfW(v, L"%d", kVersion);
                    val = v;
                }
                WritePrivateProfileStringW(s.name, s.keys[i].key, val, g_path);
                ++addedKeys;
                Log::Line(L"Конфиг : добавлен ключ [%s] %s = %s.",
                             s.name, s.keys[i].key, val);
            }
        }

        if (fileVer != kVersion)
        {
            wchar_t v[16];
            wsprintfW(v, L"%d", kVersion);
            WritePrivateProfileStringW(L"General", L"Version", v, g_path);
            Log::Line(L"Конфиг : миграция Version %d -> %d выполнена "
                         L"(пользовательские значения не тронуты).", fileVer, kVersion);
        }
        else if (addedSections == 0 && addedKeys == 0)
        {
            Log::Line(L"Конфиг : актуален, дописывать нечего.");
        }
    }
}
