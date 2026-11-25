// Copyright (c) 2026 @sitxovski (Discord)
// AcJournal.h — ЖУРНАЛ АНТИЧИТА В БАЗЕ (P53, волна acdb, 2026-10-12).
//
// Общий модуль трёх DLL (AsdaPatch — GameServer/Indun, DBPatch — DBManager, AddonNPC — NpcServer):
// исходник один (AstoryServer/Patches/AsdaPatch/src/AcJournal.cpp), компилируется в каждую DLL.
//
// Решение владельца 12.10: «делать красиво, чтобы все данные были легкодоступные и легкочитаемые.
//
// ── ЗАПИСЬ БЕЗ ЗАДЕРЖКИ ИГРОВОГО ПОТОКА ──
//   • Push() — только копия ~200 б в ячейку кольцевой очереди без блокировок (MPMC Вьюкова, CAS):
//     ни мьютексов, ни ожиданий, ни системных вызовов (кроме редкого SetEvent «пора писать»).
//     Очередь полна — событие отбрасывается и считается; отброшенные попадают в журнал отдельной
//     служебной строкой (ac.other), игровой поток не ждёт никогда.
//   • Фоновый поток: раз в FlushIntervalMs (или когда накопилось BatchMax/2) забирает до BatchMax
//     событий и пишет ОДНИМ пакетом SQL (INSERT … VALUES (…),(…) по таблицам) через СВОЁ соединение
//     ODBC (odbc32.dll грузится лениво в этом же потоке; игровой поток запросов DBManager не участвует).
//     (его можно потом выполнить sqlcmd), переподключение — не чаще ReconnectSec.
//   • Ограничитель на сессию (таблицы ход/бой, подпись/повторы, прочее): не больше PerSessionPerMinute
//     строк на (вид таблицы, userNum) в минуту, подавленные — в колонке repeat_suppressed следующей строки.
#pragma once
#include <windows.h>

namespace AcJournal
{
    // Таблица журнала (вид нарушения). Номера — индексы в AcJournal.cpp, не менять.
    enum Table : BYTE
    {
        kOperatorRefusal  = 1,   // ac.operator_refusal    — отказ операторской команды (P47)
        kIdentityMismatch = 2,   // ac.identity_mismatch   — несовпадение личности при входе (P47 B)
        kLoginCheck       = 3,   // ac.login_check_refusal — отказ сверки входа (P50, DBManager)
        kKickBlock        = 4,   // ac.kick_block          — кики (все причины) и автоблоки (P48)
        kSignReplay       = 5,   // ac.sign_replay         — подпись/повторы (секрет, MD5, 5450)
        kMoveCombat       = 6,   // ac.move_combat         — ход и бой
        kOther            = 7,   // ac.other               — прочее и служебные строки журнала
        kPacketValidator  = 8,   // ac.packet_validator    — ★ P55 (В4): длина кадра / частота по классу опкода
        kTableCount       = 9,
    };

    constexpr int kNone = (int)0x80000000;   // «значения нет» → NULL в базе

    // Событие. Заполняется в игровом потоке (только простые копии), в текст превращается в фоне.
    struct Event
    {
        BYTE    table;          // Table
        BYTE    kind;           // вид внутри таблицы (код → русский текст в фоне, см. AcJournal.cpp)
        short   userNum;        // слот соединения на сервере; -1 — нет
        int     userIndex;      // учётка; kNone — нет
        int     charSlot;       // слот персонажа; kNone — нет
        int     opcode;         // опкод; kNone — нет
        DWORD   ip;             // IPv4 в сетевом порядке; 0 — нет
        __int64 utc;            // время события (FILETIME UTC) — ставит Push
        int     v[12];          // поля таблицы; смысл — по таблице (AcJournal.cpp, AppendRow)
        __int64 w[2];           // 64-битные поля (такты, счётчики анти-повтора)
        int     suppressed;     // ставит ограничитель/источник: сколько таких же подавлено перед этим
        char    name[24];       // имя персонажа, cp1251 (CUser+0x178 у GameServer)
        char    text[64];       // строка-деталь (имя обработчика сервера и т. п.)
    };

    // Сбросить событие: все поля «нет», таблица и вид заданы.
    void Clear(Event& e, Table t, BYTE kind);

    // Скопировать строку источника (cp1251) в поле события, безопасно к мусорной памяти.
    void CopyName(Event& e, const void* src);
    void CopyText(Event& e, const void* src);

    // Поставить событие в очередь. Никогда не ждёт. false — журнал выключен/не запущен, очередь полна
    // (событие посчитано как отброшенное) или подавлено ограничителем.
    bool Push(Event& e);

    // Запуск журнала по секции ini [P53_AcJournal] своей DLL (Config:: этой DLL).
    //   product — имя DLL для служебной строки («AsdaPatch» / «DBPatch» / «AddonNPC»).
    // Возврат: 0 — запущен, 1 — выключен в ini, 3 — ошибка (очередь/поток не созданы).
    int Start(const wchar_t* product);

    // Статистика (для стенда и строки в PatchLog).
    struct Stats
    {
        LONG pushed;        // принято в очередь
        LONG dropped;       // отброшено при переполнении
        LONG suppressed;    // подавлено ограничителем
        LONG writtenDb;     // записано в базу
        LONG writtenFile;   // записано в файловый журнал
        LONG dbErrors;      // неудачных пакетов в базу
        LONG queued;        // сейчас в очереди
        bool dbUp;          // соединение с базой есть
        LONG fileSkipped;   // ★ fix2: НЕ записано в файл (FileRowsPerMinute / потолок MaxFileMB / ошибка файла)
    };
    void GetStats(Stats* s);

    // Записать всё, что осталось в очереди, в файловый журнал (выход процесса; без базы).
    void FlushToFileOnExit();

    // Только для стенда: немедленно разбудить писатель.
    void Kick();
}
