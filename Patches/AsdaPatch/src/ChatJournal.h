// Copyright (c) 2026 @sitxovski (Discord)
// ChatJournal.h — ЖУРНАЛ ЧАТА И КЭШ ЗАГЛУШЕК (P129, шаг А6.12 админ-центра, 22.11.2026). Только AsdaPatch (GameServer ×3).
//
// Решение владельца 22.11 (ADMIN_TOOL_PLAN.md §6 п.5): журнал чата + заглушка на срок, хранить 90 дней.
//
// ── ЗАПИСЬ БЕЗ ЗАДЕРЖКИ ИГРОВОГО ПОТОКА (тот же приём, что AcJournal P53) ──
//   • Push() — копия ~300 б в ячейку кольцевой очереди без блокировок (MPMC Вьюкова, CAS); очередь полна — событие
//     отбрасывается и считается (dropped), игровой поток не ждёт никогда.
//   • Фоновый поток: раз в FlushIntervalMs (или когда накопилось BatchMax/2) — до BatchMax событий одним пакетом SQL
//     (INSERT INTO chat.message … VALUES …) через СВОЁ соединение ODBC (odbc32.dll грузится лениво в этом потоке).
//   • Тот же поток раз в MuteRefreshSec читает действующие заглушки (EXEC chat.UP_ChatMuteActive) в КЭШ; раз в сутки —
//     очистка журнала старше RetentionDays (EXEC chat.UP_ChatJournalPurge).
// ── КЭШ ЗАГЛУШЕК ──
//   Два буфера со счётчиками читателей: фоновый поток пишет неактивный буфер (только когда его никто не читает) и публикует
//   его одной атомарной записью; игровой поток читает без блокировок, без ожидания и без запросов к базе (отметка в счётчике
//   буфера + проверка, что буфер всё ещё активный; ждёт только фоновый поток).
//   База недоступна — действует последний прочитанный список (сроки всё равно сверяются по часам сервера).
#pragma once
#include <windows.h>

namespace ChatJournal
{
    constexpr int kNone     = (int)0x80000000;   // «значения нет» → NULL в базе
    constexpr int kTextMax  = 200;                // байт текста в событии (потолок смежных процессов P14 — 199 + запас)
    constexpr int kNameMax  = 20;                 // байт имени (CUser+0x178, поле пакета)

    // Коды каналов (колонка chat.message.channel; бит канала в масках ini = 1 << код).
    enum Channel : BYTE
    {
        kChNormal    = 1,    // 5084 общий (рассылка 5085 в радиусе 300 клеток)
        kChGlobal    = 2,    // 5086 глобальный (рассылка 5087 всем на процессе)
        kChWide      = 3,    // 6560 широкие каналы «поиск отряда» / «торговля» (P13 → 6561)
        kChWhisper   = 4,    // 5088 шёпот (RelayServer 3105 → 5089)
        kChParty     = 5,    // 5105 отряд (RelayServer 3107 → 5106)
        kChClan      = 6,    // 4120 клан (RelayServer 4121 → 4121)
        kChArmy      = 7,    // 6718 армия (6719)
        kChStore     = 8,    // 6313 чат личной лавки (6314)
        kChStoreShout= 9,    // 6316 крик лавки (5087)
        kChShoutItem = 10,   // крик предметом (FunctionItem 0x31/0x32 → RelayServer 5087 → все каналы)
        kChCount     = 11,
    };

    // Событие чата. Заполняется в игровом потоке (только копии), в текст SQL превращается в фоне.
    struct Event
    {
        __int64 utc;            // время (FILETIME UTC) — ставит Push
        __int64 muteId;         // заглушка, по которой отказ / «был бы отказ»; 0 — нет
        int     opcode;         // опкод клиента (5084 …), у крика предметом — 5450
        int     account;        // учётка СЕССИИ (P69_ResolveSession; соулмейт — iMateUserIndex); kNone — неизвестна
        int     owner;          // хозяин персонажа CUser+0x174; kNone — нет
        int     charSlot;       // слот персонажа CUser+0x18C; kNone — нет
        int     mapIndex;       // карта потока [[mgr+4]+0x4950]; kNone — нет
        int     targetNum;      // userNum адресата (лавка 6313 — хозяин лавки); kNone — нет
        short   userNum;        // слот соединения
        BYTE    channel;        // код канала (P129: 1 обычный … 10 крик предметом)
        BYTE    sub;            // подканал: 6560 — тип канала, 5086 — байт флага, 5088 — вид шёпота, крик — вид; 0xFF — нет
        BYTE    muteState;      // 0 — нет заглушки; 1 — отказано (Mode=1); 2 — заглушка есть, но Mode=0 (только журнал)
        BYTE    sessState;      // P69_Session.state: 0 до входа, 1 в мире, 2 соулмейт, 3 соулмейт без учётки; 0xFF — нет CUser
        BYTE    gm;             // GM-флаг сессии (P47_IsGmUser)
        BYTE    textLen;        // байт текста (0…kTextMax)
        char    name[kNameMax + 1];     // имя персонажа (байты сервера, гибрид провода Astory)
        char    target[kNameMax + 1];   // имя адресата (шёпот 5088, поле пакета); пусто — нет
        BYTE    text[kTextMax];         // текст как пришёл (без завершающего нуля)
    };

    // Строка кэша заглушек.
    struct MuteRow
    {
        __int64 id;             // chat.mute.mute_id
        __int64 untilFt;        // до какого момента (FILETIME UTC)
        int     userIndex;      // учётка (scope 1 — учётка сессии; scope 2 — хозяин персонажа)
        int     charSlot;       // слот персонажа (scope 2); −1 — все персонажи
        BYTE    scope;          // 1 — учётка, 2 — персонаж
    };

    // Сбросить событие: все поля «нет».
    void Clear(Event& e);

    // Поставить событие в очередь. Никогда не ждёт. false — журнал не запущен или очередь полна (событие посчитано).
    bool Push(Event& e);

    // Запуск по секции ini [P129_ChatLog] (Config:: AsdaPatch). 0 — запущен, 1 — журнал выключен (LogEnabled=0, кэш
    // заглушек всё равно обновляется), 3 — ошибка (очередь/поток не созданы).
    int Start();

    // Найти действующую заглушку для сессии: учётка сессии (scope 1) или хозяин+слот персонажа (scope 2). Без блокировок.
    //   nowFt — текущее время FILETIME UTC. true — найдена (out заполнен: id и срок).
    bool FindMute(int account, int owner, int charSlot, __int64 nowFt, MuteRow* out);

    // Статистика (для стенда и строки в PatchLog).
    struct Stats
    {
        LONG pushed;        // принято в очередь
        LONG dropped;       // отброшено при переполнении
        LONG writtenDb;     // записано в базу
        LONG writtenFile;   // записано в файловый журнал
        LONG dbErrors;      // неудачных пакетов в базу
        LONG queued;        // сейчас в очереди
        LONG fileSkipped;   // не записано в файл (предел строк в минуту / потолок файла / ошибка)
        LONG muteRows;      // строк в действующем кэше заглушек
        LONG muteLoads;     // удачных обновлений кэша из базы
        LONG muteErrors;    // неудачных обновлений кэша
        LONG purges;        // выполненных очисток
        bool dbUp;          // соединение с базой есть
    };
    void GetStats(Stats* s);

    // Записать остаток очереди в файловый журнал (выход процесса; без базы).
    void FlushToFileOnExit();

    // Разбудить писатель (стенд).
    void Kick();

    // Только для стенда: подменить кэш заглушек (как будто прочитан из базы).
    void TestSetMutes(const MuteRow* rows, int n);
}
