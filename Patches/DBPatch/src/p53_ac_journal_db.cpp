// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P53 — ★ ЖУРНАЛ АНТИЧИТА В БАЗЕ, сторона DBManager (волна acdb, 2026-10-12).
//  Модуль записи общий: ../../AsdaPatch/src/AcJournal.cpp (очередь без блокировок + фоновый поток + своё
//  соединение ODBC — НЕ через поток запросов DBManager sub_447720). Событие пишет P50 (ac.login_check_refusal).
//  Документ: `AstoryServer/Docs/GameServer/ac-journal-p53.md`.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Log.h"
#include "AcJournal.h"

// Запуск журнала по [P53_AcJournal] dbpatch.ini. Площадок нет.
PatchResult P53_AcJournalDb()
{
    const int r = AcJournal::Start(L"DBPatch");
    if (r == 1) { return PatchResult::Disabled; }
    if (r != 0) { Log::Line(L"    P53: не удалось создать очередь/поток журнала"); return PatchResult::Failed; }
    return PatchResult::Applied;
}
