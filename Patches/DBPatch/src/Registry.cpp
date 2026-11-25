// Copyright (c) 2026 @sitxovski (Discord)
// Registry.cpp — реестр патчей DBPatch.dll.
//
// ★ Здесь живут ТОЛЬКО патчи процесса DBManager. Патчи GameServer (P01…P21)
//   находятся в другой сборке (AstoryServer/Patches/AsdaPatch) и в другой DLL. Разделение
//   сделано 30.08.2026 по образцу AddonNPC.dll (NpcServer): одна DLL — один хост.
//   Причина: общая DLL, подложенная к DBManager, создавала там свой patches.ini
//   и сверяла ЧУЖИЕ якоря GameServer в чужом образе.
#include "Patches.h"

// Реализация патча живёт в p22_db_fame_high.cpp.
PatchResult P22_DbFameHigh();
// Реализация патча живёт в p23_db_title_rank.cpp.
PatchResult P23_TitleRankFeed();
// Реализация патча живёт в p26_soulmate_note_sqli.cpp.
PatchResult P26_SoulmateNoteSqli();
// Реализация патча живёт в p28_sql_arg_escape.cpp.
PatchResult P28_SqlArgEscape();
// Реализация патча живёт в p37_craft_level_scroll_code.cpp.
PatchResult P37_CraftLevelScrollCode();
// Реализация патча живёт в p50_identity_check.cpp.
PatchResult P50_IdentityCheck();
PatchResult P53_AcJournalDb();   // ★ acdb: журнал античита в БД (p53_ac_journal_db.cpp)
// Реализация патча живёт в p78_soulmate_share_portal.cpp.
PatchResult P78_SoulmateSharePortal();
PatchResult P85_DbPostRows();   // ★ 25.10.2026 премиум-почта: список ящика до 49 записей (p85_db_post_rows.cpp)
PatchResult P125_DbReconnect(); // ★ 15.11.2026 повторное подключение к SQL Server после обрыва связи (p125_db_reconnect.cpp)
PatchResult P96_DbShellRows();  // ★ 30.10.2026 сумка 60 ячеек: строки Plate 1 до 60 (p96_db_shell_rows.cpp)

namespace
{
    const PatchEntry kPatches[] =
    {
        // ★ P22 — DBManager: старшая половина маски славы (звания id 256…511).
        //   Пара к P21 (GameServer): P21 расширяет маску до 512 бит в памяти
        //   сервера, а P22 даёт этой половине пережить перезаход персонажа.
        //   Существующие DB-опкоды не тронуты: добавлены два новых (2330/2331)
        //   и ответ 2332; данные ложатся в новую таблицу dbo.CharFameHigh.
        { L"P22_DbFameHigh",
          L"звания: старшая половина маски славы в базе (id 256…511)",
          &P22_DbFameHigh,
          L"dbmanager.exe" },

        // ★ P23 — DBManager: отправитель рейтинговых званий 65…69 (опкоды
        //   3404…3408). Приёмник в GameServer (sub_54D710@0x54D710) рабочий, а
        //   отправителя не было НИ В ОДНОМ образе сервера — звания были
        //   недостижимы. Пересчёт раз в N секунд (по умолчанию 600) выполняется
        //   на рабочем потоке DBManager по флагу времени, своего потока нет.
        { L"P23_TitleRankFeed",
          L"звания 65…69: отправитель рейтингов (опкоды 3404…3408)",
          &P23_TitleRankFeed,
          L"dbmanager.exe" },

        // ★ P26 — DBManager, БЕЗОПАСНОСТЬ: SQL-инъекция в записках соулмейта
        //   (дефект С5 отчёта `Reports/soulmate_6400.md` §12a.6) и
        //   незавершённая строка записки (С6). Площадка своя, ни с P22, ни с
        //   P23 не пересекается; порядок установки безразличен.
        { L"P26_SoulmateNoteSqli",
          L"записка соулмейта (2238): SQL-инъекция и незавершённая строка",
          &P26_SoulmateNoteSqli,
          L"dbmanager.exe" },

        // ★ P28 — DBManager, БЕЗОПАСНОСТЬ: ОБЩЕЕ закрытие класса SQL-инъекций.
        //   Перехват общего сборщика запросов sub_447720 — одна площадка вместо
        //   24 точечных. Ставится ПОСЛЕ P26: тот чистит записку в обработчике и
        //   до P28 доносит её уже обеззараженной (порядок, впрочем, безразличен —
        //   вторая чистка просто ничего не находит).
        //   ⚠ Площадка — ВХОД функции (0x00447720); бинарный патч P17 стоит
        //   ВНУТРИ неё (0x004478B9) и с этой площадкой не пересекается.
        { L"P28_SqlArgEscape",
          L"все запросы к базе: экранирование апострофа в аргументах '%s'",
          &P28_SqlArgEscape,
          L"dbmanager.exe" },

        // ★ P37 — DBManager: ответ 2668 (повышение уровня ремесла свитком) нёс
        //   код запроса (всегда 1) вместо кода процедуры — код 1/99/98 писался в
        //   исходный буфер, а отправлялась копия, снятая ДО процедуры (Н-1
        //   ревизии P35). Три замены по 7 б в sub_445B60, протокол прежний.
        //   Пара в GameServer — P35 LevelScrollSync (достоверен только с P37).
        { L"P37_CraftLevelScrollCode",
          L"ремесло: настоящий код результата в ответе 2668 (свиток уровня)",
          &P37_CraftLevelScrollCode,
          L"dbmanager.exe" },

        // ★ P50 — DBManager, БЕЗОПАСНОСТЬ (античит А0, 12.10.2026): сверка личности при
        //   DB-логоне персонажа (2001 вход / 2089 портал) с записью входа LoginManager
        //   (JoyLog1.dbo.Loginfo) через EXEC dbo.UP_AC_IdentityCheck; отказ — штатный
        //   ответ-неудача 2002/2090. Пара к GameServer P47 (IP пира в хвосте запроса).
        //   Площадки — цели двух call в диспетчере (0x4026D1/0x402FE3), с P22/P23/P26/P28/P37
        //   не пересекаются.
        { L"P50_IdentityCheck",
          L"вход/портал 2001/2089: сверка UserIndex/слота/IP с записью входа",
          &P50_IdentityCheck,
          L"dbmanager.exe" },

        // ★ P53 — журнал античита в БД (волна acdb, 12.10.2026): очередь + фоновый поток + своё ODBC.
        //   Из DBManager — отказы сверки входа P50. Площадок нет (код в P50).
        { L"P53_AcJournal",
          L"журнал античита в БД (joylog1.ac): отказы сверки входа P50",
          &P53_AcJournalDb,
          L"dbmanager.exe" },

        // ★ P78 — DBManager (23.10.2026, слово владельца «сразу правим»): портал 2089 разбирал строки
        //   UPSoulMateShare шагом 21 без пропуска байта Charidx — имена и флаги «поделиться» соулмейта
        //   сдвигались после КАЖДОГО портала (Share = байты имени, обычно 0). Три замены байт в sub_417410
        //   (0x419156/0x41917F/0x4191A3) — раскладка как у входа 2001. Пара — P78-SQL (UPSoulMateShare
        //   отдаёт ровно 3 строки по слотам 10/11/12). С P22/P23/P26/P28/P37/P50/P53 не пересекается.
        { L"P78_SoulmateSharePortal",
          L"портал 2089: строки «поделиться» соулмейта — шаг 22, как у входа",
          &P78_SoulmateSharePortal,
          L"dbmanager.exe" },

        { L"P85_DbPostRows",
          L"премиум-почта: список ящика 2602/2603 до 49 записей (7 строк окна × 7 ячеек), корзина gp7 целиком",
          &P85_DbPostRows,
          L"dbmanager.exe" },

        // ★ P96 — DBManager (30.10.2026, «инвентарь ×2», пара к AsdaPatch P96_InventoryX2): обрезка строк сумки
        //   (Plate 1) «> 30 → 30» в sub_422C20 (0x7F7) и sub_423600 (вход 2001 / портал 2089) поднята до 60.
        //   Четыре imm8 1Eh → 3Ch, площадки ищутся ПО СИГНАТУРЕ в .text (живой образ ≠ локальный разбор).
        //   С P22/P23/P26/P28/P37/P50/P53/P78/P85 не пересекается (verify_p96_db.py).
        { L"P96_DbShellRows",
          L"сумка 60 ячеек: строки Plate 1 (UPPlateItem) в GameServer до 60 (сток — 30)",
          &P96_DbShellRows,
          L"dbmanager.exe" },

        // ★ P125 — DBManager (15.11.2026, дефект оригинала): после обрыва связи с SQL Server сессия открывается
        //   заново, запрос повторяется один раз. Площадка — вызов Execute внутри sub_447720 (0x447B49, 5 б);
        //   с P28 (вход 0x447720) и бинарным P17 (0x4478B9) не пересекается. Общий модуль с LoginPatch:
        //   AstoryServer/Patches/DbReconnect/src/DbReconnectCore.cpp.
        { L"P125_DbReconnect",
          L"база: после обрыва связи сессия открывается заново, запрос повторяется один раз (сток — ошибка до перезапуска)",
          &P125_DbReconnect,
          L"dbmanager.exe" },
    };
}

const PatchEntry* g_patches    = kPatches;
const int         g_patchCount = ARRAYSIZE(kPatches);
