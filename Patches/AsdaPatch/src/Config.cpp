// Copyright (c) 2026 @sitxovski (Discord)
#include "Config.h"
#include "Log.h"

// ─────────────────────────────────────────────────────────────────────────────
//  Декларативное описание patches.ini. ОДИН источник правды и для создания
//  файла с нуля, и для досоздания недостающих ключей в уже правленом файле.
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
    struct IniKey
    {
        const wchar_t* key;
        const wchar_t* def;
        const wchar_t* comment;     // комментарий перед ключом (может быть многострочным)
    };

    struct IniSection
    {
        const wchar_t* name;
        const wchar_t* comment;     // блок комментария перед [секцией]
        const IniKey*  keys;
        int            nkeys;
    };

    const IniKey kGeneral[] =
    {
        // ⚠ ЭТО ЧИСЛО ОБЯЗАНО СОВПАДАТЬ с Config::kVersion (Config.h). Расхождение
        //   уже ловили (шаблон 4 / код 7): свежесозданный ini объявлялся негодным
        //   и НИ ОДИН патч не ставился. Поднял до 27 вместе с kVersion (исправления по
        //   ревизии: P42 C6/C7→C12/C13, P43 гейт продавца, P41 мёртвый; до этого 26 — P43;
        //   25 — P38; 24 — P42; 23 — ResendOnShow в P41; 22 — P41; 21 — P40; 20 — P31/P32).
        //   28 — секция [P44_ExchangeIntegrity] (обмен/лавка, 2026-09-29).
        //   32 — секция [P46_StoreShoutOverflow] (БЕЗОПАСНОСТЬ: переполнение стека в
        //        крике лавки 6316, 2026-10-08). 29/30/31 — ревизии P44 (без новых секций).
        //   33 — секции [P47_IdentityOperatorGate], [P48_KickAutoBlock],
        //        [P49_OriginalChecksRestore] (античит, волна А0, 2026-10-12).
        //   34 — ревизия А0 (ac0r, 2026-10-12): P47 CountAsHackPacket=0 по умолчанию (тихий сброс) +
        //        RefusalLogIntervalSec; P48 SoulMateSessionAccount (вход соулмейтом — учётка сессии).
        //   35 — секции [P53_AcJournal] и [P54_BlockedLoginMessage] (античит, волна acdb, 2026-10-12).
        //   36 — секции [P55_PacketValidator], [P56_CombatLimits], [P57_MoveGuard], [P58_DisconnectReasonLog],
        //        [P59_RareDropJournal] (античит, волны В4/В5/A6, интеграция 2026-10-12).
        //   37 — P56b + P60–P67 + P61 (интеграция 2026-10-12): секции [P60_ValueGuard], [P61_TrafficEncryption],
        //        [P62_SlotUniqueness], [P63_InFlightLock], [P64_StatePreamble], [P65_ConsumableType],
        //        [P66_PositionGuard], [P67_GachaRewardVariant] (античит, волна A7 + В5b + В7b).
        //   38 — P68 + тик замков (интеграция integ3, 2026-10-13): секция [P68_CharNameGuard] (античит A13 «имя
        //        персонажа»); такт замков P33/P35/P44 `now ? now : 1` вместо `GetTickCount() | 1` (без новых ключей).
        //   39 — P69 (античит autoban, 2026-10-14): секция [P69_IntegrityAutoBlock] — ступенчатый автоблок за нарушения
        //        целостности пакетов (20 → 24 ч, 50 → 720 ч, больше → бессрочно), Mode=0 — только журнал.
        //   40 — sec2b (2026-10-15): ключ MaxPendingPerIp в [P61_TrafficEncryption].
        //   41 — p57fix (2026-10-15): ключ BudgetRefillPermille в [P57_MoveGuard]; MaxStepLen по умолчанию 72500.
        //   42 — P71 + P72 (2026-10-15): секции [P72_HiddenWipeDisarm] (безопасность: закладка CharItemKeeping(11) — таймер
        //        затирания 550 слотов + перехват взведения) и [P71_TickDeadlineWrap] (сроки GameServer через переход 2^32;
        //        p71fix по ревизии 15.10: ключ MaxPenaltySec — предел штрафа лагеря из БД, выше — старое абсолютное значение).
        //   43 — sec2c (2026-10-15): атрибуция кика P47/P48/P49/P55 без гонок нитей карт (ревизия SEC2 Н-3/Н-4/Н-5), без новых ключей.
        //   44 — P73 (античит EAC, 2026-10-16): секция [P73_EacBridge] — мост к сайдкару AsdaEacServer (Enabled=0, Mode=0).
        //   45 — P74 (синхронизация боя Ф3, 2026-10-17): секция [P74_HpSectorSync] — снимок HP 4058 соседям по сектору.
        //   47 — P75 (2026-10-19): секция [P75_LevelUpPotion] — зелье повышения уровня 558 (до 70 вычислением опыта).
        //   48 — P76 (2026-10-21): секция [P76_SowelSlotBounds] — поля пакетов живых камней 5022/5024/5031.
        //   49 — P29 ред. 2 (2026-10-21): новых ключей нет; зажим по AppleExpLimit/SoulStoneExpLimit, «очки навыков».
        //   50 — P77 (2026-10-22): секция [P77_MoveSyncStopPoint] — 4009 в точку сервера при молчаливой остановке хода.
        //   51 — P79 (2026-10-24): новых ключей нет; длина 2244 в таблице P55 — 34..53 (была ложная 253..∞).
        //   52 — P80 (2026-10-24): секция [P80_CrouchSpeedJumpRelay] — ход вприсядку ×0.5 (статус 4006 = 4), прыжок 4024 131 в ходу соседям.
        //   53 — P81 (2026-10-24): секция [P81_ActionCodeGuard] — код 4024 вне законных от не-оператора отклоняется, «Dancer» не чаще клипа.
        //   54 — P82 (2026-10-24): секция [P82_FuncCoolTimeExt] — откат функциональных предметов с кодом >= 600 своей таблицей.
        //   55/56 — P96/P97 (2026-10-30): сумка 30→60, вес u16. 57 — P100 (2026-11-01): секция [P100_ChargeStack] — заряды спецпредметов
        //        складываются при получении (шаблон здесь до 57 отставал на 54 — поднят вместе с kVersion).
        //   58 — P101 (2026-11-02): секция [P101_CashGift] — подарок из кэш-магазина (Enabled=0).
        //   59 — P102 (2026-11-02): секция [P102_DefectFixes] — дефекты оригинала выдачи (разборка, книга рыбака, снятие лотов 9910, воскрешение 5450 — 04.11).
        //   60 — P103 (2026-11-04): секция [P103_InFlightFixes] — коробка при отказе БД (записи P100), замок отката 5450 / автоприменения.
        //   62 — P100 эхо 2604 (2026-11-05): ключ EchoAllCodes в [P100_ChargeStack] — ответ премиум-почты кладёт в ячейку эха БД для всех кодов.
        //   63 — P106 (2026-11-05): секция [P106_FriendAcceptNotify] — 4151 принявшему дружбу и при флаге UPFriendAdd 2.
        //   64 — P107 (2026-11-05): секция [P107_CantActGate] — оглушённый/испуганный не атакует (кроме навыков 736/984), 14 — нельзя.
        //   65 — P108 (2026-11-05): секция [P108_DungeonRelogEntry] — выход из данжа сохраняется в точку входа (турнирные — к выходу).
        //   66 — P109 (2026-11-05): секция [P109_SelfHitNoDamage] — навык «на себя» не наносит урон самому кастеру (611/612/616).
        //   67 — P110 (2026-11-05): секция [P110_Job4PointPools] — пулы очков навыков: основные ≤ 110, 4-я профессия — сверх 110.
        //   68 — P111 (2026-11-05): секция [P111_HatchSupplement] — добавка вылупления +30%, в слот 3 инкубатора только подтип 108.
        //   69 — P112 (2026-11-06): секция [P112_PartyExpSpread] — разброс уровней отряда в опыте: весь отряд, настоящий минимум.
        //   71 — P114 (2026-11-07): секция [P114_BoardExpBonus] — опыт заданий доски через GetExpUpDownValue, как у обычных заданий.
        //   72 — P117 (2026-11-09): секция [P117_PlusPackOnce] — набор уровня не применяется, пока действует прежний (5451 код 0x10).
        //   73 — P120 (2026-11-09): секция [P120_MineTravel] — переход в шахту (карта 23) у NPC 181 и обратно; тип карты 6 получает поток.
        //   74 — P118 (2026-11-09): секция [P118_AuctionTradeBlock] — заявка/согласие обмена отменяются, пока игрок работает с аукционом.
        //   75 — P121 (2026-11-09): секция [P121_CharRenameGuard] — предмет смены имени (категория 111) через 5450 не тратится (5451 код 0).
        //   76 — P122 (2026-11-09): секция [P122_PetFuncFloor] — функция питомца не ниже значения PetInfo_Table.
        //   77 — P123 (2026-11-09): секция [P123_GmMapJump] — GM-прыжок на другую карту по клетке (6010 тело 8 б с меткой → 5055 код 1).
        //   78 — P123 ред. 2 (2026-11-09): GM-флаг через P47_IsGmUser (char), журнал отброшенных; новых ключей нет.
        //   79 — P123 ред. 3 (2026-11-09): GM-прыжок без ложного гейта очереди (слоты из 5058 порт-клиента), закрытые карты GM-у; ключей нет.
        //   80 — P127 (2026-11-18): секция [P127_AdminBridge] — мост админ-центра (очередь AsdaAdmin, присутствие, kick/announce/move).
        //   81 — P127 А2.2 (2026-11-18): живые правки моста (probe/exp/title_add/title_del/fame_recalc/notice); новых ключей нет.
        //   82 — P127 А2.3 (2026-11-19): живые give (хвост 0x552360, оператор 2/11) и jump (CharJumpCommandPosition_0 0x54EBF0); новых ключей нет.
        //   83 — P127 А5.2 (2026-11-21): mob_pop / mob_return (6045 / 6046 от имени оператора, sub_5646C0 в NpcServer); новых ключей нет.
        //   84 — P127 А5.4 (2026-11-21): event_set / event_off (6038 / 6040 в RelayServer) и rank_recalc (6020, P25_RunRecalc); новых ключей нет.
        //   85 — P128 (2026-11-21): секция [P128_EventBadgeAll] — значок события Event.dat (6039/6041) всем игрокам в мире.
        //   86 — P129 (2026-11-22): секция [P129_ChatLog] — журнал чата (joylog1.chat) и заглушка чата на срок (нотис 3113).
        { L"Version", L"86",
          L"; Версия формата файла. Меняет только сама DLL при миграции.\r\n" },
        { L"MasterEnable", L"0",
          L"; * ГЛАВНЫЙ ВЫКЛЮЧАТЕЛЬ. 0 = не ставить НИ ОДИН патч (сервер работает как сток).\r\n"
          L";   При создании файла стоит 0 — это проверка каркаса: сервер должен подняться\r\n"
          L";   и создать PatchLog. После успешной проверки поставить 1.\r\n" },
        { L"LogEnabled", L"1",
          L"; Вести лог установки патчей.\r\n" },
    };

    const IniKey kEnabled[] = { { L"Enabled", L"1", nullptr } };

    const IniKey kIp[] =
    {
        { L"Value", L"127.0.0.1",
          L"; Строка IP по умолчанию в .rdata (в стоке 61.106.140.206).\r\n"
          L"; Максимум 15 символов. Пустое значение = не трогать.\r\n" },
    };

    const IniKey kAnnounce[] =
    {
        { L"PickupEnabled",       L"1", L"; Подбор редкого предмета с земли (грейд >= 3):\r\n" },
        { L"GachaEnabled",        L"1", L"; Гача-коробка/бустер (грейд >= 3). Анонсируется ВЫИГРЫШ, не коробка.\r\n" },
        { L"PremiumGachaEnabled", L"1", L"; Премиум-гача (грейд >= 3). ! Код награды приходит от клиента.\r\n" },
        { L"RefineEnabled",       L"1",
          L"; Заточка. Грейд НЕ требуется — анонсируем любую экипировку.\r\n" },
        { L"RefineThresholdLevel", L"6",
          L"; * ПОРОГ анонса — по СТУПЕНИ улучшения (item+24, диапазон 0..20).\r\n"
          L";   Ступень игроку не показывается, но считать порог удобнее по ней.\r\n"
          L";   (старый ключ RefineThreshold больше НЕ читается)\r\n" },
        { L"RefineThresholdPercent", L"0",
          L"; Доп. порог по ПРОЦЕНТУ (item+27 — то, что игрок видит как \"+N%\").\r\n"
          L";   0 = не учитывать. Если задан — анонс только когда выполнены ОБА порога.\r\n" },
        { L"RefineFailEnabled",   L"1",
          L"; Анонс НЕУДАЧИ: после зелёного анонса успеха следующая ПРОВАЛЬНАЯ попытка\r\n"
          L";   улучшить ТОТ ЖЕ предмет объявляется красной строкой. Одна красная строка\r\n"
          L";   на один зелёный анонс — после выдачи состояние снимается.\r\n" },
        { L"RefineFailRequiresPriorSuccess", L"1",
          L"; 1 = красная строка только ПОСЛЕ зелёного анонса ТОГО ЖЕ предмета\r\n"
          L";     (штатное поведение: одна красная на одну зелёную).\r\n"
          L"; 0 = анонсировать ЛЮБУЮ неудачу по предмету, ступень которого уже >=\r\n"
          L";     RefineThresholdLevel, даже если зелёного анонса до этого не было.\r\n"
          L";     Ставьте 0, если ждёте анонс провала на УЖЕ прокачанном предмете.\r\n" },
        { L"RefineFailWindowSec", L"600",
          L"; Срок годности взведённого состояния, секунд. Страхует от того, что номер\r\n"
          L";   слота игрока после выхода займёт другой персонаж.\r\n" },
        { L"Scope",               L"0", L"; Зона рассылки: 0 = все игроки сервера, 1 = только сектор.\r\n" },
        { L"GradeTableFile", L"ConfigSet\\announce_codes.txt",
          L"; Таблица кодов \"анонсируемых\" предметов (грейд >= 3 и подходящий тип).\r\n"
          L"; Путь относительно папки GameServer. Генерируется скриптом\r\n"
          L"; AstoryServer\\Patches\\AsdaPatch\\tools\\gen_announce_codes.py. Если файла нет — источники\r\n"
          L"; подбор/гача/премиум-гача НЕ анонсируют (защита от спама).\r\n" },
    };

    const IniKey kChatWide[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"AllowedChannelMask", L"6",
          L"; * Битовая маска ОБСЛУЖИВАЕМЫХ каналов, значение ДЕСЯТИЧНОЕ (бит N = канал N):\r\n"
          L";     бит 0 (=1)  канал 0 «По всем каналам» — из клиента УБРАН, по умолчанию ВЫКЛ;\r\n"
          L";     бит 1 (=2)  канал 1 «Поиск отряда»;\r\n"
          L";     бит 2 (=4)  канал 2 «Торговля».\r\n"
          L";   6 = 2|4 = только «Поиск отряда» и «Торговля» (штатное значение).\r\n"
          L";   Каналы вне маски отвергаются со строкой в логе, ничего не рассылается.\r\n" },
        { L"RespectServerMapTypeGate", L"1",
          L"; Повторять гейт глобального чата: если тип карты этого сервера = 4\r\n"
          L";   (таблица настроек серверов, запись +0x3F), широкий чат не работает —\r\n"
          L";   ровно так ведёт себя оригинальный recvGlobalChatClient (5086).\r\n"
          L";   0 = обслуживать широкие каналы даже на таком сервере.\r\n" },
        { L"ChatLogType", L"0",
          L"; Пересылка сообщения на ЛОГ-СЕРВЕР чата (пакет 3670, запись 106 б) — то же,\r\n"
          L";   что делает хвост обработчика 5086. Значение = код ТИПА чата в записи.\r\n"
          L";   У глобального чата это 7; для широких каналов код в оригинале НЕ ЗАДАН,\r\n"
          L";   поэтому по умолчанию 0 = НЕ отправлять (не выдумываем константу).\r\n"
          L";   Поставьте нужный код, если лог-сервер должен видеть эти сообщения.\r\n" },
        { L"RuntimeLog", L"1",
          L"; Писать строки [chat6560] (приём, отказы, рассылка) в PatchLog.\r\n"
          L";   Это диагностика; при большом трафике можно выключить (0).\r\n" },
    };

    const IniKey kChatLen[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"MaxTextLen", L"160",
          L"; * МАКСИМАЛЬНАЯ ДЛИНА текста сообщения чата В БАЙТАХ (текст cp1251,\r\n"
          L";   один символ = один байт). В стоке 80, значение по умолчанию 160 = «вдвое».\r\n"
          L";   Действует на каналы: 5084 общий/крик, 5086 глобальный, 4120 клан,\r\n"
          L";   5088 шёпот, 5105 отряд, а также на 6560 «Поиск отряда»/«Торговля» (P13).\r\n"
          L";   ! ПОТОЛОК 199: столько принимает RelayServer (буферы 200 б, проверки\r\n"
          L";     1..199/1..200 в обработчиках 4121 и 3107). Больше ставить НЕЛЬЗЯ.\r\n"
          L";   ! Клиентское поле ввода должно быть ограничено НЕ БОЛЬШЕ этого числа\r\n"
          L";     (наш порт ставит 136 при MaxTextLen=160; оригинальный клиент — 68).\r\n"
          L";   ! Канал армии/фракции (6718) НЕ затронут и остаётся на 80 байтах:\r\n"
          L";     его пересылка 6719 имеет фиксированную длину 101 и подпись MD5.\r\n"
          L";   ! Запись чата на лог-сервер (пакет 3670, 106 б) в любом случае\r\n"
          L";     содержит первые 80 байт — формат записи фиксирован.\r\n" },
        { L"FixOverflowOnly", L"0",
          L"; 1 = ТОЛЬКО закрыть переполнения стека, предел оставить стоковым (80).\r\n"
          L";   Режим для случая «клиент ещё не обновлён, но дыры закрыть надо».\r\n"
          L";   MaxTextLen при этом игнорируется.\r\n" },
        { L"RuntimeLog", L"1",
          L"; Писать в PatchLog строки [chatlen] * OVERFLOW BLOCKED — они появляются\r\n"
          L";   ТОЛЬКО когда клиент заявил длину больше предела (модифицированный\r\n"
          L";   клиент или рассинхрон лимитов). Флуд лога ограничен автоматически.\r\n" },
    };

    // ★ P17 — единственный патч, живущий не в GameServer, а в процессах работы с базой.
    // ★ P17 — единственный патч, живущий не в GameServer, а в процессах работы с базой.
    const IniKey kSqlCp[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"CodePage", L"1256",
          L"; Кодовая страница, в которой текст запроса переводится в Юникод перед\r\n"
          L";   отправкой в базу. Должна СОВПАДАТЬ с кодировкой базы, иначе символы,\r\n"
          L";   которых в ней нет, превращаются в вопросительные знаки. Базы игры\r\n"
          L";   арабские (Arabic_CI_AS = 1256), а машина сервера стоит на 1251 —\r\n"
          L";   отсюда и потеря всего русского. 1256 обратима для всех 256 байт,\r\n"
          L";   поэтому байты доходят до столбца нетронутыми: и русские, и арабские.\r\n"
          L";   Менять только вместе с кодировкой базы.\r\n" },
        { L"RequireExecPrefix", L"1",
          L"; Подменять кодовую страницу только у строк, начинающихся с EXEC —\r\n"
          L";   все 23 шаблона запросов начинаются именно так. Страховка на случай,\r\n"
          L";   если через ту же точку пойдёт что-то постороннее. 0 = снять условие.\r\n" },
    };

    // ★ P18 — склад: дюп + границы + немые отказы. Каждый дефект отдельным ключом.
    const IniKey kWarehouse[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = не ставить НИ ОДНО из исправлений ниже.\r\n" },
        { L"FixKeepingDupe", L"1",
          L"; * D4 — ДЮП. CharItemKeeping@0x5094A0: ветка-ловушка, пишущая в лог\r\n"
          L";   \"CharItemKeeping(11)\", отправляет клиенту 5009 с кодом 5 (отказ) и НЕ\r\n"
          L";   делает return — операция всё равно доходит до DB-запроса 2029. Клиент\r\n"
          L";   уже получил отказ и предмет из лотка не убрал, потом приходит второй\r\n"
          L";   5009 с кодом 1 (успех). 1 = возвращаться сразу после отказа.\r\n" },
        { L"FixPageRange4050", L"1",
          L"; * D2 — ЧТЕНИЕ ЧУЖОЙ ПАМЯТИ. Send_ClientStoreHouseItemInfo (опкод 4050) при\r\n"
          L";   номере страницы 0 читает 1710 байт ДО начала массива склада (CUser+6342)\r\n"
          L";   и отправляет их клиенту пакетом 4051. Штатный клиент шлёт 1..9, но\r\n"
          L";   собранный вручную пакет даёт утечку памяти. 1 = страница 0 отклоняется.\r\n" },
        { L"FixReply4050OnReject", L"1",
          L"; * D18 — при отказе на 4050 сервер не отвечал НИЧЕГО, а клиент снимает свой\r\n"
          L";   флаг \"запрос в полёте\" только по 4052 — склад залипал до перезахода.\r\n"
          L";   1 = отправлять штатный 4052 (конец страницы, 0 предметов).\r\n" },
        { L"FixDbSlotBounds", L"1",
          L"; * D9 — МЁРТВАЯ ПРОВЕРКА ГРАНИЦ в трёх загрузчиках контейнеров из ответа БД:\r\n"
          L";   написано \"slot < 0 && slot > N\" (невыполнимо) вместо \"|| \". Проверки нет,\r\n"
          L";   любой slot из строки БД пишет 57 байт по CUser + 57*slot + база.\r\n"
          L";   Площадки: 0x5296AC (инвентарь, 30), 0x529826 (второй мешок, 60),\r\n"
          L";   0x52994F (СКЛАД, 270). 1 = проверка начинает работать.\r\n" },
        { L"FixMoveCapacity", L"1",
          L"; * D13 — CharItemMove (опкод 5000) сверяет ячейку склада с зашитыми 270\r\n"
          L";   (потолок массива), а не с ёмкостью КОНКРЕТНОГО игрока (CUser+0x1AE).\r\n"
          L";   Игрок с ёмкостью 30 мог переложить предмет в ячейку 269 — 4050 её\r\n"
          L";   никогда не отдаст, предмет становится невидимым и недоступным.\r\n"
          L";   1 = граница берётся из ёмкости игрока (при её порче — стоковые 270).\r\n" },
        { L"FixMoveSilentReject", L"1",
          L"; * D15 — шесть сочетаний тип-источника/тип-приёмника в CharItemMove\r\n"
          L";   заканчиваются \"return 0\" без единого пакета (в т.ч. источник 1 или 2 +\r\n"
          L";   приёмник 5 = склад). Клиент на 5000 ставит UI-замок и снимает его только\r\n"
          L";   по 5001 — интерфейс залипал намертво. 1 = отвечать штатным отказом\r\n"
          L";   \"5001, код 2\" (та же ветка, что у всех прочих отказов этой функции).\r\n"
          L";   Ни одна ранее РАБОТАВШАЯ операция не затрагивается: во все шесть точек\r\n"
          L";   попадают только сочетания, которые сервер и так отказывался выполнять.\r\n" },
    };

    // ★ P19 — аукцион: запись за конец буфера записей в 9905/9909.
    //   Каждый дефект включается отдельным ключом.
    const IniKey kAuction[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = не ставить НИ ОДНО из исправлений ниже.\r\n" },
        { L"FixBuyRecordBounds", L"1",
          L"; * S3 — 9905 «КУПИТЬ» (Recv_TransAction_BuyItemReq@0x51AA10). Цикл разбора\r\n"
          L";   хвоста пакета копирует запись в 45 байт в стековый буфер на 8 записей\r\n"
          L";   И ТОЛЬКО ПОТОМ сверяет счётчик. Девятая запись ложится за конец\r\n"
          L";   буфера и затирает соседние переменные кадра, в том числе 15-байтную\r\n"
          L";   шапку запроса, уходящую в ItemRelayServer. Верхнего предела длины\r\n"
          L";   пакета нет вовсе — sub_5218A0 проверяет только кратность 45.\r\n"
          L";   1 = проверка идёт ДО копирования. Штатный путь НЕ меняется:\r\n"
          L";   ровно 8 записей по-прежнему принимаются, а отказ уходит тем\r\n"
          L";   же штатным ответом 9906 с кодом 1, что и в стоке.\r\n" },
        { L"FixDeleteRecordBounds", L"1",
          L"; * S4 — 9909 «СНЯТЬ ЛОТ» (Recv_TransAction_DeleteItemReq@0x51E380). То же\r\n"
          L";   самое с пределом 10: одиннадцатая запись пишет 35 байт за конец\r\n"
          L";   объявленного массива. 1 = проверка идёт ДО копирования, отказ —\r\n"
          L";   штатный ответ 9910 с кодом 1.\r\n" },
        { L"ReportMd5GateState", L"1",
          L"; * S1 — ДИАГНОСТИКА, НИЧЕГО НЕ МЕНЯЕТ. Отчёт утверждал, что сверка\r\n"
          L";   подписи тела пакета (sub_523F00@0x523F00) отключена. В ЖИВОМ образе\r\n"
          L";   она РАБОТАЕТ (0x523F8B = 74, 0x52400D = 74); EB стоит только в нашей\r\n"
          L";   локальной копии со снятой защитой — оттуда и ошибка в отчёте.\r\n"
          L";   1 = напечатать фактическое состояние обеих площадок в PatchLog.\r\n" },
    };

    // ★ P21 — маска славы (звания) расширена с 256 до 512 бит.
    const IniKey kTitleMask512[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = сервер остаётся на 256-битной маске славы,\r\n"
          L";   то есть звания с id 256 и выше получить нельзя (как в стоке).\r\n" },
        { L"RaiseFameInfoCap", L"1",
          L"; * Предел числа записей ConfigSet\\FameInfo.txt: 256 -> 512\r\n"
          L";   (загрузчик sub_4A18F0@0x4A18F0, отказ «FameInfo count over»).\r\n"
          L";   ⚠ Сам по себе НИЧЕГО не даёт: во всех трёх функциях работы с битами\r\n"
          L";   стоит гейт «id < число записей», поэтому таблицу надо ещё и ДОРАСТИТЬ\r\n"
          L";   (на живом в ней 251 запись, id 0…250; клиентская title_list знает 280).\r\n" },
        { L"AllocHighMaskTail", L"1",
          L"; * Хранилище битов 256…511. В CUser места нет: маска «получено»\r\n"
          L";   (CUser+0x17DDC) и маска «найдено» (CUser+0x17E00) разделены указателем\r\n"
          L";   на массив записей званий, нарастить их на месте нельзя. Поэтому массив\r\n"
          L";   записей (operator new(44*N) @0x4A2824) выделяется на 64 байта длиннее:\r\n"
          L";   32 байта — старшая половина «получено», 32 — старшая половина «найдено».\r\n"
          L";   0 = хранить биты негде, все остальные части секции гаснут автоматически.\r\n" },
        { L"HighBitOps", L"1",
          L"; * Операции над битами 256…511 в CheckFameBit@0x54A890, AddFameBit@0x54A980\r\n"
          L";   и SubFameBit@0x54AD00. Трамплин стоит на ВХОДЕ: при id < 256 доигрывает\r\n"
          L";   вытесненный пролог и уходит в СТОКОВЫЙ код байт в байт, так что штатные\r\n"
          L";   звания не задеты вовсе.\r\n"
          L";   ⚠ В базу биты 256…511 НЕ сохраняются: DB-пакеты 2256/2257/2266 несут\r\n"
          L";   ровно 4 qword, а принимает их DBManager. До правки базы такое звание\r\n"
          L";   живёт до перезахода персонажа.\r\n" },
        { L"Extend6066", L"1",
          L"; * Пакет 6066 «маска получено» уходит клиенту расширенным: 42 -> 74 байта,\r\n"
          L";   [42..73] = биты 256…511. Старая часть НЕ сдвинута, поэтому НЕ обновлённый\r\n"
          L";   клиент читает свои 42 байта и хвост просто не замечает.\r\n" },
        { L"Extend6086", L"1",
          L"; * Пакет 6086 «маска найдено»: 38 -> 70 байт, [38..69] = биты 256…511.\r\n"
          L";   ★ У 6086 порядок полей обратный к 6066 (сначала charId) — так в стоке.\r\n" },
        { L"DbHighExchange", L"1",
          L"; * Обмен старшей половиной с базой (пара к патчу DBManager P22).\r\n"
          L";   При входе персонажа уходит опкод 2330 «дай старшую половину», ответ\r\n"
          L";   2332 наполняет её и догоняет клиента расширенными 6066/6086; при\r\n"
          L";   выдаче и снятии звания id >= 256 уходит 2331 «сохрани».\r\n"
          L";   Существующие DB-пакеты 2256/2257/2266 не тронуты — они несут ровно\r\n"
          L";   4 qword, удлинять их нельзя.\r\n"
          L";   ⚠ Требует патча DBManager (P22) и SQL-миграции\r\n"
          L";   (SQL/title_mask_512_01_migrate.sql). БЕЗОПАСНО включать и раньше них:\r\n"
          L";   необновлённый DBManager этих опкодов просто не знает — все три\r\n"
          L";   диапазона его switch дают переход в эпилог, обработчика нет,\r\n"
          L";   ошибки нет. Просто звание id >= 256 не переживёт перезаход.\r\n"
          L";   0 = не ходить в базу вовсе (старшая половина живёт до перезахода).\r\n" },
    };

    // ★ P25 — GM-команда «пересчитать рейтинги сейчас» (опкод 6020).
    // ── [P27_SoulmateServerDefects] ────────────────────────────────────────
    const IniKey kSoulmateServerDefects[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = обе площадки остаются стоковыми.\r\n" },
        { L"CastTimerClamp", L"1",
          L"; * Дефект С8: зажать «прошло с начала каста» по 0x7FFF ПЕРЕД усечением\r\n"
          L";   в знаковое 16-битное поле. Без этого навык соулмейта перестаёт\r\n"
          L";   завершаться, как только с начала каста прошло больше 32,7 с.\r\n"
          L";   0 = оставить сток (каст «то работает, то нет» с периодом ~65 с).\r\n" },
        { L"SkillTableBounds", L"1",
          L"; * Дефект С4: ограничить чтение SoulmateSkill.ssi сотней записей —\r\n"
          L";   ровно столько вмещает выделенный буфер. Файл длиннее 11 200 байт\r\n"
          L";   в стоке пишет за конец кучи. Сейчас файл 5 040 б (45 записей),\r\n"
          L";   то есть ключ — страховка на будущее расширение таблицы.\r\n"
          L";   0 = оставить сток (без верхней границы).\r\n" },
    };

    // ── [P29_LevelCap] — потолок уровня игрока ─────────────────────────────
    const IniKey kLevelCap[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = потолок 59, как в стоке (все 7 площадок\r\n"
          L";   остаются стоковыми).\r\n" },
        { L"MaxLevel", L"100",
          L"; * Новый потолок уровня игрока (в стоке 59). Опыт идёт, пока уровень\r\n"
          L";   МЕНЬШЕ этого числа, т.е. MaxLevel — последний достижимый уровень.\r\n"
          L";   DLL сама зажимает его сверху длиной таблиц ConfigSet: ExpTable−1,\r\n"
          L";   ClassStat/4, Standard, AppleExpLimit, SoulStoneExpLimit\r\n"
          L";   (сейчас 150 / 100 / 100 / 151 / 151 ⇒ предел 100) и 127.\r\n"
          L";   Если таблица не читается — патч НЕ ставится, потолок остаётся 59.\r\n"
          L";   ⚠ Выше 100 без продления ClassStat.txt/Standard.txt подниматься нельзя:\r\n"
          L";   сервер берёт из них характеристики по уровню.\r\n" },
        { L"SoulmateGates", L"1",
          L"; * Кувшин души (партнёр должен быть ниже потолка, отказ 6) и навык\r\n"
          L";   соулмейта 31 (отказ 29 на потолке) — тоже переводятся на MaxLevel.\r\n"
          L";   0 = в этих двух местах остаётся 59 (кувшин и навык 31 перестанут\r\n"
          L";   работать для игроков 59+, хотя опыт им уже положен).\r\n" },
        { L"StatPoints", L"1",
          L"; * +2 очка НАВЫКОВ за каждый уровень до MaxLevel включительно (имя ключа\r\n"
          L";   историческое: это очки навыков CUser+0x19B, не характеристик).\r\n"
          L";   0 = как в стоке: очки только до 59-го, уровни 60+ очков не дают.\r\n" },
    };

    // -- [P30_MapSlots] -- число слотов карт -----------------------------
    const IniKey kMapSlots[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = 23 слота карт и стоковый массив\r\n"
          L";   на 0x0060A880, как в стоке (карты с номером 23 и выше мертвы).\r\n" },
        { L"MaxMaps", L"30",
          L"; * Сколько слотов карт заводить (в стоке 23, то есть номера 0...22).\r\n"
          L";   DLL сама зажимает это число сверху ДВУМЯ пределами:\r\n"
          L";     1) 30 - жёстко: столько записей в массиве Total_PortalConfig\r\n"
          L";        внутри CUserManager (this+2656, 30 записей по 31 б). Он\r\n"
          L";        индексируется НОМЕРОМ карты напрямую, а сразу за ним лежит\r\n"
          L";        массив игроков - номер 30 и выше означал бы разбор чужой памяти;\r\n"
          L";     2) числом строк в MapData_Info\\MapInfo.txt - иначе у слота нет\r\n"
          L";        записи в таблице карт, и включённая секция MAP_n читала бы\r\n"
          L";        за концом этой таблицы.\r\n"
          L";   => чтобы слотов стало больше, СНАЧАЛА добавьте строку в MapInfo.txt.\r\n"
          L";   Если MapInfo.txt не читается - патч НЕ ставится, остаются стоковые 23.\r\n"
          L";   Не забудьте расширить и матрицу MapData_Info\\MapWarpCost.txt до N*N,\r\n"
          L";   секции MAP_n в OpenMapInfo.ini, [MAX_INIT_THREAD] COUNT в\r\n"
          L";   ConfigSet\\ThreadInfo.ini (не меньше числа карт с Use=1) и записи в\r\n"
          L";   PortalIP_Info\\Total_PortalConfig.Ini - они идут ПО НОМЕРУ карты.\r\n" },
    };

    // -- [P33_GearUpgradeServerDefects] -- заточка 6504/6505 (волна 6) --------
    const IniKey kGearUpgrade[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = vse 33 ploshchadki ostayutsya stokovymi.\r\n" },
        { L"SoulPossessGate", L"1",
          L"; * D-1: 6500/6502/6504/6506 zakryty dlya 'dushi' (SoulState==1, sub_52EEA0 -\r\n"
          L";   rovno kak u legasi-zatochki 5033 v dispetchere) i dlya 'oderzhimogo'\r\n"
          L";   (SoulState==2, sub_52EE40 - kak u prodazhi/pokupki i drugikh operatsiy s veshchami).\r\n"
          L";   Otkaz idyot SOBSTVENNOY vetkoy obrabotchika 'deystvie zablokirovano'.\r\n" },
        { L"SilentCodes", L"1",
          L"; * D-2/D-3: 19 otkazov kodom 0 (klient na nyom ne pokazyvaet NICHEGO) ->\r\n"
          L";   kod 5 'Uluchshenie ne udalos' (50009), v tom chisle dlya slota < 0\r\n"
          L";   (kod 4 u klienta = 50008 'Eto ne lichnyy predmet' - ne po smyslu);\r\n"
          L";   2 'prevysheno maksimalnoe kolichestvo' (50006) dlya vykhoda\r\n"
          L";   za tablitsu OverUpgrade. Novykh kodov NET - tolko te, chto klient znaet.\r\n" },
        { L"GradeCode6", L"1",
          L"; * N-7: 'grejd svitka ne tot' shlyot kod 6 (50010 'Nepodkhodyashchiy uroven')\r\n"
          L";   vmesto 3 (50007 'Nedostatochno kuponov').\r\n" },
        { L"ZeroLimitGuard", L"1",
          L"; * N-14: predmet s predelom SowelCombine (kolonka 45) <= 0 NE tochitsya: kod 7\r\n"
          L";   (50011 'Predmet nelzya uluchshit') DO broska. V stoke on s pervoy popytki\r\n"
          L";   popadal v sverkh-rezhim, i proval so svitkom UNICHTOZHAL veshch.\r\n" },
        { L"ScrollCountFirst", L"1",
          L"; * D-7: 'svitkov menshe nuzhnogo' proveryaetsya DO broska GSCh (kod 3).\r\n" },
        { L"HelperWeight", L"1",
          L"; * N-1: ves izraskhodovannykh pomoshchnikov 97/98 spisyvaetsya s gruza\r\n"
          L";   personazha (v stoke spisyvalsya tolko ves svitka - gruz ros s kazhdoy zatochkoy).\r\n" },
        { L"SyncErrorLog", L"1",
          L"; * D-4: stroka 'Recv_DB_ShellItemUpgrade UserIndex Sync Error' dopolnena\r\n"
          L";   slotom i oboimi UserIndex. Otvet klientu v etoy vetke NE shlyotsya namerenno:\r\n"
          L";   slot uzhe zanyat drugim personazhem.\r\n" },
        { L"InFlightLock", L"1",
          L"; * N-2: 'odna popytka v polyote': poka ne prishyol otvet bazy 2305, vtoroy 6504\r\n"
          L";   togo zhe personazha otbrasyvaetsya (otvet kodom 0, kak u 5033) - posle\r\n"
          L";   shtatnoy proverki podpisi/antipovtora. V stoke dva\r\n"
          L";   klika = DVA broska po odnomu predmetu i dve zapisi v bazu.\r\n" },
        { L"LockTimeoutMs", L"15000",
          L"; Skolko zhdat otveta bazy, prezhde chem schest zamok protukhshim (1000...120000).\r\n" },
        { L"SowelColumn57", L"1",
          L"; * D-5: zagruzchik SowelCombine.txt pisal kolonki 56 i 57 v ODNO pole +0xA6 -\r\n"
          L";   kolonka 56 teryalas. Teper 57 -> +0xA8. Oba polya serverom ne chitayutsya,\r\n"
          L";   na igru ne vliyaet - vosstanavlivaet dannye v pamyati.\r\n" },
        { L"OptionIndexBounds", L"1",
          L"; * N-15 (naydeno volnoy 6): na stupenyakh 7...20 nomer dop-optsii predmeta\r\n"
          L";   indeksiruet OptionUpgrade.txt (93 zapisi) BEZ proverki granits - u predmeta\r\n"
          L";   bez optsii tam -1, v Item_OptionTable.txt est nomera 94, 95, 105, 300...329.\r\n"
          L";   Chtenie chuzhoy pamyati kuchi. Vne tablitsy - znachenie optsii ne menyaetsya.\r\n"
          L";   Dve ploshchadki: zatochka 6504 i blagoslovenie 6551 (Recv_UserUpgradeBless).\r\n" },
    };

    // -- [P34_NecklaceFixedOptions] -- фиксированные опции ожерелий 4/61 -----
    const IniKey kNecklace[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = vse 3 ploshchadki ostayutsya stokovymi.\r\n" },
        { L"CritToBattleServer", L"1",
          L"; * Tip 4 'Krit pri atake %' (8 ozheleliy): fiksirovannaya optsiya aksessuara\r\n"
          L";   dopisyvaetsya v pary optsiy zapisi igroka 8101/8305 dlya NpcServer - tem zhe\r\n"
          L";   putyom, kotorym prikhodit krit s lyuboy drugoy veshchi (sub_457280: kazhdaya para\r\n"
          L";   tipa 4 + k shansu, zazhim 100). Razmer i raskladka paketa ne menyayutsya.\r\n" },
        { L"DropRateStat", L"1",
          L"; * Tip 61 'Shans vypadeniya trofeya %' (2 ozherelya): summa tipa 61\r\n"
          L";   (sub_445DD0) pribavlyaetsya k bonusu dropa CUser+0x46F. NpcServer mnozhit\r\n"
          L";   kazhdyy shans dropa na (1 + bonus/100) - kak u samotsvetov Cellob vida 7.\r\n"
          L"; Tip 24 'Uspeshnoe izgotovlenie %' - v sektsii [P36_CraftSuccessOption].\r\n" },
    };

    // -- [P35_CraftServerDefects] -- ремесло 6598/6600/6602/6604 (оборона) ------
    const IniKey kCraft[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = vse 39 ploshchadok ostayutsya stokovymi.\r\n" },
        { L"TsSecretCheck", L"1",
          L"; * S-5: rezultat shtatnoy antipovtornoy proverki sub_524390 (TS-sekret)\r\n"
          L";   soblyudaetsya v 6598/6600/6602/6604, kak vo vsekh prochikh obrabotchikakh.\r\n"
          L";   V stoke on vyzyvalsya, no rezultat ignorirovalsya - povtor paketov prokhodil.\r\n" },
        { L"StateGate", L"1",
          L"; * S-13: remeslo zakryto, poka personazh myortv (+0x4F), v obmene (+0x145),\r\n"
          L";   na auktsione (+0x15F), PRODAYOT v svoey lavke (+0x14D i +0x151 = svoy\r\n"
          L";   indeks; posetitelyu chuzhoy lavki mozhno), na rybalke (+0x3F6B4) -\r\n"
          L";   rovno prichiny shtatnoy preambuly sub_52BFF0. Otkaz kodom, kotoryy klient\r\n"
          L";   znaet: 6599/6601 kod 10, 6603 kod 0, 6605 kod 99. 6001 NE shlyotsya.\r\n" },
        { L"InFlightLock", L"1",
          L"; * S-3/S-18: 'odna operatsiya remesla v polyote' na personazha - poka ne\r\n"
          L";   prishyol otvet bazy (2662/2664/2666/2668), lyuboy iz 4 opkodov togo zhe\r\n"
          L";   personazha otbrasyvaetsya BEZ otveta. V stoke N paketov do otveta bazy davali\r\n"
          L";   N broskov po odnomu naboru materialov, opyt personazha xN i obkhod limita\r\n"
          L";   retseptov povtorom 6600. Zamok snimaetsya otvetom bazy, razryvom, portalom.\r\n" },
        { L"LockTimeoutMs", L"15000",
          L"; Skolko zhdat otveta bazy, prezhde chem schest zamok protukhshim (1000...120000).\r\n" },
        { L"ContainerGuard", L"1",
          L"; * S-1/S-2: materialy, katalizatory i svitki berutsya TOLKO iz konteynerov\r\n"
          L";   sumki 1 i 2. Konteyner 4 (sposobnosti) v stoke ronyal GameServer ODNIM\r\n"
          L";   paketom (memcpy v nullptr), 3 (nadetoe) i 5 (sklad) prinimalis.\r\n" },
        { L"RecipeBounds", L"1",
          L"; * D-D2/D-8/S-9: izuchenie 6598 - ne dalshe strok CraftRecipeInfo.txt i 576\r\n"
          L";   (yomkost maski); izgotovlenie 6602 - strok Info i iMakeIndex v predelakh\r\n"
          L";   CraftRecipeMake. Svitok retsepta 248 (item 79360) -> kod 10. Zabyvanie 6600 -\r\n"
          L";   do 576: retsept vne tablitsy, izuchennyy do patcha, zabyvaetsya.\r\n" },
        { L"ClientCodes", L"1",
          L"; * S-7/D-12: kody, kotorykh klient ne znaet: 6603 kod 10 (okno viselo) ->\r\n"
          L";   3 'Nedostatochno materialov' (materialy, vid katalizatora) i 0 (uroven\r\n"
          L";   remesla nizhe stupeni 0); 6605 kod 0 (molchanie) -> 99.\r\n" },
        { L"CatalystStack", L"1",
          L"; * S-4: katalizator stopkoy >1 raskhoduet SAM SEBYA (count-1, ves); v stoke\r\n"
          L";   on ne raskhodovalsya, a edinitsu teryal material j.\r\n" },
        { L"CatalystGhost", L"1",
          L"; * S-21: izraskhodovannyy katalizator ukhodit v 6603 s count 0, a ne polnoy\r\n"
          L";   kopiey ('prizrak' v inventare klienta).\r\n" },
        { L"CraftListMask", L"1",
          L"; * S-19: recvDBCraftList chitaet 576 bit maski (9 qword paketa), a ne 580 -\r\n"
          L";   bez fantomnykh retseptov 576...579 iz pamyati za paketom.\r\n" },
        { L"LevelScrollCode", L"1",
          L"; * S-20: svitok urovnya ne nayden POSLE zapisi bazy -> kod 99 vmesto 0\r\n"
          L";   (kod 0 klient molcha propuskaet).\r\n" },
        { L"LevelScrollSync", L"1",
          L"; * S-20: v tom zhe sluchae uroven iz otveta bazy stavitsya i v pamyat.\r\n"
          L";   VKL po umolchaniyu s 27.09.2026 (reshenie vladeltsa): para k DBManager P37\r\n"
          L";   (dbpatch.ini [P37_CraftLevelScrollCode]) - s nim otvet 2668 neset nastoyashchiy\r\n"
          L";   kod, i kod 1 = baza deystvitelno zapisala uroven. BEZ P37 stavit 0 (defekt N-1:\r\n"
          L";   2668 vsegda kod 1). Ostatok S-1: svitok v etoy vetke v pamyati NE raskhoduetsya\r\n"
          L";   (tolko gonka modklienta, chestnyy klient syuda ne popadaet).\r\n" },
        { L"LogPerMinute", L"30",
          L"; Predel strok P35 v zhurnale Log_Craft (kategoriya 26) v minutu (1...1000).\r\n"
          L";   Ostalnye schitayutsya i podytozhivayutsya odnoy strokoy.\r\n" },
    };

    // -- [P36_CraftSuccessOption] -- опция 24 «Успешное изготовление %» -------
    const IniKey kCraftOpt[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = ploshchadka 0x0053E7DF ostayotsya stokovoy.\r\n" },
        { L"CraftSuccessOption", L"1",
          L"; * Tip 24 'Uspeshnoe izgotovlenie +N %' (13 amuletov): porog KAZHDOY stupeni\r\n"
          L";   lestnitsy remesla (CraftRecipeMake kol.24...30) umnozhaetsya na (1 + N/100),\r\n"
          L";   ne vyshe 100000 - kak bonus dropa (rate x (1 + x/100)). N - summa tipa 24\r\n"
          L";   po vsemu nadetomu (sub_445DD0: pary 11 slotov + fiks. optsiya aksessuarov).\r\n"
          L";   'Velikiy uspekh' (+1 sht.) NE menyaetsya.\r\n" },
        { L"MaxBonusPercent", L"1000",
          L"; Predel summy N v protsentakh (0...10000) - zashchita ot krivykh dannykh.\r\n" },
    };

    // -- [P32_PetWrongOpcode6101] -- pitomtsy: otkaz po charId opkodom 6101 -------
    const IniKey kPetOpcode[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = obe ploshchadki ostayutsya stokovymi (6101).\r\n" },
        { L"FixIncubator", L"1",
          L"; * PD1: Recv_IncubatorReq, otkaz 'charId ne tot' - 6101 s telom 18 b -> 6103\r\n"
          L";   (bayt 0x00455103 D5 -> D7). Klient sbrasyvaet zalipshee okno inkubatora.\r\n" },
        { L"FixConditionUp", L"1",
          L"; * PD2: Recv_PetConditionUp, otkaz 'charId ne tot' - 6101 s telom 89 b -> 6109\r\n"
          L";   (bayt 0x0045786F D5 -> DD). U klienta - bezopasnyy no-op (charId -1).\r\n" },
    };

    // -- [P31_PetUnionRemoveNotify] -- yunion pitomtsev: 6111 na syedennyy material --
    const IniKey kPetUnion[] =
    {
        { L"Enabled", L"0",
          L"; Glavnyy vyklyuchatel. Po umolchaniyu 0: na zhivom ne ispytan. 1 = posle\r\n"
          L";   uspeshnogo yuniona (6112 -> 6113) na KAZHDYY realno udalyonnyy material\r\n"
          L";   uhodit shtatnyy 6111 (9 b: charId, uid 32 bita, kod 1) - DO 6113.\r\n"
          L";   Lechit fantomy materialov s uid >= 32768 v okne pitomtsev.\r\n" },
        { L"LogPerMinute", L"30",
          L"; Predel strok P31 v zhurnale Log_Pet (kategoriya 27) v minutu (1...1000).\r\n"
          L";   Ostalnye schitayutsya i podytozhivayutsya odnoy strokoy.\r\n" },
    };

    // -- [P40_CrystalTeleportGate] -- teleport kristallom 5477 -------------------
    const IniKey kCrystalGate[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = ploshchadka 0x00549A15 ostayotsya stokovoy\r\n"
          L";   (5477 bez proverok, kak v originale).\r\n" },
        { L"CheckNpc", L"1",
          L"; * Igrok obyazan stoyat u NPC-kristalla, u kotorogo est knopka na etu kartu:\r\n"
          L";   NPC tekushchey karty v predelakh NpcRange kletok (po X i po Z, kak\r\n"
          L";   CNpcManager::TemporaryRequestProcess @0x438E30) s tipom iz spiska Crystals.\r\n" },
        { L"CheckOpenMap", L"1",
          L"; * Karta-tsel obyazana byt otkryta v OpenMapInfo.ini (Use) - tot zhe massiv, chto\r\n"
          L";   chitaet napolnyy portal (0x52C610; pri P30 - bufer DLL). Bez OpenMapInfo\r\n"
          L";   (Indun_GameServer) proverka ne deystvuet - kak u napolnogo portala.\r\n" },
        { L"NpcRange", L"3",
          L"; Radius v kletkakh (1...50). 3 - edinstvennaya mera blizosti k NPC u servera\r\n"
          L";   (@0x4390E1/0x43910C). Klient otkryvaet razgovor v +-0.5 kletki (port +-1.5).\r\n" },
        { L"Crystals", L"46:7,0,1;49:3;50:7,3,6,2;51:6,0;52:2,0;53:3,0,16;55:3;201:7;107:5",
          L"; Tip NPC : karty, kuda vedut ego VIDIMYE knopki (NpcNsrButton 30031 + WarpList,\r\n"
          L";   MenuCount iz NpcNsrHeader). 107:5 - knopka Elly 30037. Skrytye knopki (ella 107 -> 4, 138 -> 3,\r\n"
          L";   eco 101 -> 0) chestnyy klient poslat ne mozhet - ikh net. Karty 0...29.\r\n" },
        { L"RefuseCode", L"0",
          L"; Kod otkaza v 5055 (telo 53 b - stokovyy bufer etogo zhe obrabotchika).\r\n"
          L";   0 - klient (original i port) pishet notis 1096 i ostavlyaet igroka na meste.\r\n"
          L";   -1 - molcha (kak stok pri -1 v MapWarpCost). 1 zapreshchyon (eto 'perekhod').\r\n" },
        { L"LogPerMinute", L"30",
          L"; Predel strok P40 v zhurnale Log_Game (kategoriya 0) v minutu (1...1000).\r\n"
          L";   Ostalnye schitayutsya i podytozhivayutsya odnoy strokoy.\r\n" },
    };

    // -- [P41_GmHide4056] -- skrytyy operator: 4056 sosedyam ne ukhodit ---------
    const IniKey kGmHide4056[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = vse 9 ploshchadok ostayutsya stokovymi.\r\n" },
        { L"OtherSector", L"1",
          L"; * Pryzhki/perenosy skrytogo operatora (7 mest: gorod na toy zhe karte,\r\n"
          L";   vyzov partnyora, GM-pryzhki, Send_MoveCommand, TargetJump): 4056 s kletkoy\r\n"
          L";   NOVOGO mesta ne ukhodit STAROMU sektoru.\r\n" },
        { L"SelfRegen", L"1",
          L"; * Voskreshenie na meste (CharRegenSelfPosition; u operatora vsegda Type 4)\r\n"
          L";   i RoseWar: 4056 skrytogo ukhodit TOLKO emu samomu, ne vsemu sektoru.\r\n" },
        { L"ResendOnShow", L"1",
          L"; * Dorabotka SREDN-1: na POKAZE skrytogo operatora (Send_HideCommand, 4025\r\n"
          L";   kod 301) sosedyam dootpravlyaetsya svezhiy 4056 (kletka/HP/MP/opyt), esli\r\n"
          L";   ego 4056 byl podavlen poka on skryt. Inache posle smerti/pryzhka pod\r\n"
          L";   skrytiem sosed derzhal by ego trupom / na staroy kletke do pokaza.\r\n" },
        { L"LogEvents", L"1",
          L"; Stroki P41 v Log_Operator (pervye 50, dalshe kazhdaya 1000-ya).\r\n" },
    };

    // -- [P42_GmHideTarget] -- skrytyy operator ne dopustimaya tsel boya igrokov ------
    const IniKey kGmHideTarget[] =
    {
        { L"Enabled", L"1",
          L"; Glavnyy vyklyuchatel sektsii. 0 = vse 11 ploshchadok ostayutsya stokovymi.\r\n" },
        { L"GateCentral", L"1",
          L"; * Tsentralnaya proverka dopustimosti tseli sub_556DB0 (udar 4201/4203, spiski\r\n"
          L";   tseley navyka igroka i strazha, chast razlyotov): skrytyy operator kak TSEL -> 0.\r\n" },
        { L"GateSkills", L"1",
          L"; * Obkhody sub_556DB0: rezultaty navyka igroka/strazha (zavershenie kasta),\r\n"
          L";   nalozhenie sostoyaniy i ikh ploshchadnye chleny (navyk 925).\r\n" },
        { L"GateSpreads", L"1",
          L"; * Razlyoty urona EXPLOSION_ARROW i GUARDIAN_NORMAL_ATTACK_AREA (perebor sektora).\r\n" },
        { L"GateSoulmate", L"1",
          L"; * Perenos urona na soulmeyta i tseli navyka soulmeyta (spisok iz paketa klienta).\r\n" },
        { L"LogEvents", L"1",
          L"; Stroki P42 v Log_Operator (pervye 50, dalshe kazhdaya 1000-ya).\r\n" },
    };

    // -- [P38_ClanSlotCap] -- limit mest klana: proverka sveryaet pribavku +10 ----------
    const IniKey kClanSlotCap[] =
    {
        { L"Enabled", L"1",
          L"; * Proverka rasshireniya klana sveryala 'limit+5 <= 100', a pribavlyala +10.\r\n"
          L";   Pri RUCHNOY pravke BD klan mog uyti za 100 (do 105). Odin bayt 0x40494D:\r\n"
          L";   05 -> 0A (proveryat tu zhe pribavku). Chestnyy put (limit <= 90) ne zadet.\r\n"
          L";   0 = ostavit stok (05).\r\n" },
    };

    // -- [P43_StorePriceCap] -- potolok tseny lichnoy lavki 100mln -> 1mlrd -------------
    const IniKey kStorePriceCap[] =
    {
        { L"Enabled", L"1",
          L"; * Potolok tseny lichnoy lavki (StreetStall) 100mln -> 1mlrd. DVA capa:\r\n"
          L";   otkrytie 0x50338C (tsena za ed.) i pokupka 0x5056D5 (summa lota) - oba\r\n"
          L";   obyazatelny (inache lot dorozhe 100mln otkryt mozhno, a kupit net).\r\n"
          L";   0 = ostavit stok (100mln).\r\n" },
        { L"GuardOverflow", L"1",
          L"; * Zashchita ot perepolneniya int32 v kol-vo x tsena (3 tramplina): pri\r\n"
          L";   perepolnenii summa obnulyaetsya, shtatnaya proverka <=0 otklonyaet lot/\r\n"
          L";   pokupku (6303/6310). Rekomenduetsya 1 vmeste s podnyatiem capa.\r\n" },
    };

    // -- [P44_ExchangeIntegrity] -- korrektnost pryamogo obmena 528x i lichnoy lavki 630x --
    const IniKey kExchangeIntegrity[] =
    {
        { L"Enabled", L"1",
          L"; * Glavnyy vyklyuchatel sektsii. 0 = vse ploshchadki obmena/lavki ostayutsya\r\n"
          L";   stokovymi. Otdelnye gruppy nizhe.\r\n" },
        { L"CompleteLock", L"1",
          L"; * SO-1: zavershenie obmena (CharExchangeCompleteReq 0x4E48B3). Zamok 'v polyote'\r\n"
          L";   mezhdu zaprosom v BD i otvetom BD (snimaetsya v edinstvennoy tochke\r\n"
          L";   osvobozhdeniya okna 0x4DF6D0) + sverka OBEIH fiksatsiy (+657/+658). Povtornyy\r\n"
          L";   5293 po tomu zhe oknu do otveta BD otbrasyvaetsya (bez BD-zaprosa).\r\n" },
        { L"WindowBounds", L"1",
          L"; * SO-3: verkhnie granitsy windowIndex (< 550) v 5288/5290/5291/5293 i yacheyki\r\n"
          L";   lotka (< 5) v 5288. Otkaz shtatnym putyom (log / 5289 kod 0).\r\n" },
        { L"StoreSlotBounds", L"1",
          L"; * SL-1: granitsa indeksa lota vitriny (0..9) v pokupke 6309\r\n"
          L";   (CharSelfStoreBuyItem, oba tsikla). Otkaz shtatnym 6310 (kod 2/5), zamok\r\n"
          L";   pokupki sbrasyvaetsya.\r\n" },
        { L"DeathCancelExchange", L"1",
          L"; * Sbros obmena v moment smerti (SendCharDead 0x4CB5D8): pri CUser+0x145 vyzov\r\n"
          L";   CharExchanageCancelReq(this, userNum, nullptr, CUser+0x149) - kak re. Partnyoru\r\n"
          L";   ukhodit 5287, okno osvobozhdaetsya. 0 = obmen zhivyot do razryva/regena.\r\n" },
        { L"DeferMaxMs", L"30000",
          L"; * SREDN-A/E2: poka okno zhdyot otveta BD, otmena/razryv/regen uchastnika otkladyvayut\r\n"
          L";   osvobozhdenie okna (ego osvobodit otvet BD) - no ne dolshe etogo predela v ms.\r\n"
          L";   Starshe predela (net svyazi s DBManager) - osvobozhdenie shtatnoe. Min 1000.\r\n" },
        { L"AcceptNeedsRequest", L"0",
          L"; * SO-4: prinyatie obmena trebuet visyashchey zayavki (CharExchangeReq zapisyvaet,\r\n"
          L";   AcceptReq sveryaet). VYKL po umolchaniyu - reshenie vladeltsa (original zhivyot\r\n"
          L";   s etim). Vklyuchat posle sverki na zhivom, kto eshchyo zovyot Req/Accept.\r\n" },
        { L"AcceptTtlMs", L"60000",
          L"; * SO-4: srok zhizni zapisi zayavki v ms (s zapasom nad klientskimi 33 s), chtoby\r\n"
          L";   ni odna chestnaya zayavka ne byla otklonena. Deystvuet tolko pri\r\n"
          L";   AcceptNeedsRequest=1.\r\n" },
        { L"PartnerFlagGuard", L"1",
          L"; * Punkt 2 (O1 MELK-6): otmena/otkaz odnoy storony NE sbrasyvaet +0x145/+0x149\r\n"
          L";   vtoroy storony, esli ta zanyata REALNYM obmenom (+0x149 != -1). Dve tochki:\r\n"
          L";   CharExchanageCancelReq vetka -2 (0x4E01E2) i CharExchangeAcceptReq otkaz\r\n"
          L";   (0x4DFFE2 / 0x4E001C). 0 = stokovoe bezuslovnoe snyatie flaga partnyora.\r\n" },
        { L"StoreGuestLock", L"1",
          L"; * Punkt 3 (L2 S-1/SREDN-2): (3a) vykhod gostya iz lavki NE snimaet zamok pokupki\r\n"
          L";   khozyaina +0x5AEF (NOP na 0x50448C) - inache vtoraya parallelnaya 6309 na tot zhe\r\n"
          L";   lot (dyup). (3b) CharSelfStoreInfo (0x5047B4) pered poiskom slota chistit\r\n"
          L";   zastryavshie sloty guest[] (zhivoy userIndex != sokhranyonnomu +1517) i\r\n"
          L";   korrektiruet schyotchik +1432. 0 = stokovoe povedenie.\r\n" },
        { L"RefusalBySide", L"1",
          L"; * Punkt 4 (O4 MELK-1): kody otkaza itoga obmena 'net mesta/peresyp' 5294/5295\r\n"
          L";   razdayutsya storone s nekhvatkoy (1/2 = 'ty', 3/4 = 'partnyor'), a ne po roli.\r\n"
          L";   CharNormalItemExchangeComplete (0x4E75F7) i CharShellItemExchangeComplete\r\n"
          L";   (0x4E4E7E); marshrut po arg8 (triggernувshaya storona poluchaet svoy bufer).\r\n"
          L";   0 = stokovoe (triggernувshaya storona vsegda slyshit 'ty').\r\n" },
    };

    const IniKey kGmRatingRecalc[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = опкод 6020 снова МЁРТВЫЙ, как в стоке\r\n"
          L";   (сервер его принимает и молча выбрасывает), пересчёт только по\r\n"
          L";   расписанию: звания — таймер P23, топ славы — 03:00 у ChannelManager.\r\n" },
        { L"RequireOperatorIndex", L"1",
          L"; * ★ ОПЕРАТОРСКИЙ ГЕЙТ стока: sub_52ECF0 — UserIndex (CUser+0x174)\r\n"
          L";   обязан быть в диапазоне 0…5000. Ровно эту проверку делают ВСЕ семь\r\n"
          L";   стоковых операторских команд (Kick/Kill/Add/GetMob/EventSet/EventOff/\r\n"
          L";   ItemGive). По ИМЕНИ судить нельзя: ADM_* — оператор, а GM_* может быть\r\n"
          L";   обычным игроком. ⚠ 0 ставить только для отладки: команда пересчитывает\r\n"
          L";   всю базу и проходит по всем игрокам в игре.\r\n" },
        { L"RequireGmFlag", L"1",
          L"; * Вторая стоковая проверка: sub_52ED50 — байт GM-полномочий на CUser,\r\n"
          L";   приезжает из dbo.CharGmInfo.GMFlag через UPCharGMInfo при входе.\r\n"
          L";   Стоковые команды требуют ОБА признака, поэтому и мы требуем оба.\r\n" },
        { L"CheckPacketSignature", L"1",
          L"; * Анти-тампер (sub_524390, монотонный счётчик) и MD5 тела (sub_523F00\r\n"
          L";   с признаком 1 — конверт «секрет+MD5»). Как у всех GM-команд.\r\n"
          L";   0 = не сверять (только для отладки собранным вручную пакетом).\r\n" },
        { L"MinIntervalSec", L"60",
          L"; * Защита от злоупотребления: не чаще одного запуска в N секунд.\r\n"
          L";   Здесь порог МГНОВЕННЫЙ — отказ выдаётся не сходив в базу вовсе.\r\n"
          L";   Авторитетный порог живёт на стороне базы: dbpatch.ini,\r\n"
          L";   [P23_TitleRankFeed] MinForceSec (он считает реальные проходы).\r\n"
          L";   0 = не ограничивать здесь (порог P23 всё равно останется).\r\n" },
        { L"SweepAllTitles", L"1",
          L"; * ★ ПЕРЕСЧЁТ УСЛОВИЙ ВСЕХ ЗВАНИЙ у тех, кто СЕЙЧАС В ИГРЕ. Обходим\r\n"
          L";   список сессий теми же функциями, что стоковый TimerProcess@0x5431C0,\r\n"
          L";   и по каждому званию зовём стоковую проверку sub_54B260@0x54B260\r\n"
          L";   с признаком «в базу не слать» (иначе на каждое звание каждого игрока\r\n"
          L";   улетал бы DB-пакет 2257). Уже полученные звания пропускает гейт\r\n"
          L";   sub_54A890. Выданное сохраняется само — AddFameBit шлёт в базу 2256.\r\n"
          L";\r\n"
          L";   ★★★ ЧЕСТНО О ГРАНИЦАХ. В оригинале ПЕРИОДИЧЕСКОЙ проверки условий НЕТ\r\n"
          L";   вообще: TimerProcess трогает ровно одно звание (id 22, время в игре),\r\n"
          L";   всё остальное начисляется ТОЛЬКО по событию (sub_54A050, 204 вызова).\r\n"
          L";   Поэтому пересчитать можно лишь то, чей прогресс ГДЕ-ТО ЛЕЖИТ. Разбор\r\n"
          L";   всех 280 записей ConfigSet\\FameInfo.txt:\r\n"
          L";     92 — выключены колонкой 1 (не трогаем);\r\n"
          L";     51 — колонка 45 = 1, универсальный накопитель  -> ПЕРЕСЧИТЫВАЕМО;\r\n"
          L";     89 — стоковый switch, накопитель в записи       -> ПЕРЕСЧИТЫВАЕМО;\r\n"
          L";      2 — id 29 и 45 (процент по маске игрока)       -> ПЕРЕСЧИТЫВАЕМО;\r\n"
          L";      7 — id 5, 43 и 6…10 (живое поле CUser)         -> ПЕРЕСЧИТЫВАЕМО;\r\n"
          L";      1 — id 22 (время в игре)                       -> ПЕРЕСЧИТЫВАЕМО;\r\n"
          L";     25 — значение приходит В СОБЫТИИ и НИГДЕ не хранится -> НЕЛЬЗЯ;\r\n"
          L";      1 — id 32: ветки накопления нет вовсе, значение всегда 0;\r\n"
          L";     12 — нет ни одной ветки условия (в т. ч. рейтинговые 65…69,\r\n"
          L";          их раздаёт отдельный пересчёт по пакетам 3404…3408).\r\n"
          L";   ★ Персонажи НЕ В ИГРЕ не охвачены: накопители лежат в CUser. Для них\r\n"
          L";   нужна отдельная процедура базы — её контракт описан в документе патча.\r\n"
          L";   0 = не проверять условия, оставить только рейтинговые и топ славы.\r\n" },
        { L"MaxGrantsPerPass", L"2000",
          L"; * Предохранитель: сколько званий разрешено выдать за ОДИН проход.\r\n"
          L";   Каждая выдача — это нотис 6065 игроку и DB-пакет 2256, поэтому на\r\n"
          L";   полном сервере первый прогон может дать заметный всплеск трафика.\r\n"
          L";   Дойдя до предела, проход останавливается и пишет строку в журнал\r\n"
          L";   Log_Operator; повторный запуск продолжит с того же места.\r\n" },
        { L"ReplyChannel", L"0",
          L"; * Номер канала в теле стокового 6561, которым уходит ответ оператору.\r\n"
          L";   Клиент красит строку по нему (0 = как обычное системное сообщение,\r\n"
          L";   1 = «Поиск отряда», 2 = «Торговля»). Новых опкодов клиенту не нужно.\r\n" },
    };

    // ★ P24 — снятие рейтингового звания у прежнего лидера.
    const IniKey kFameRatingRevoke[] =
    {
        { L"Enabled", L"1",
          L"; Главный выключатель секции. 0 = приёмник 3404…3408 остаётся стоковым:\r\n"
          L";   звание только ВЫДАЁТСЯ и не снимается никогда (дефект оригинала).\r\n" },
        { L"ResolveByUserIndex", L"1",
          L"; * Площадка 0x54D86F. Две беды стока разом:\r\n"
          L";   1) игрок ищется ТОЛЬКО по подсказке userNum из пакета, а userNum —\r\n"
          L";      номер живой сессии, стороне базы он неизвестен. Теперь при\r\n"
          L";      userNum = 0xFFFF (или при несовпадении UserIndex) сервер ищет сам,\r\n"
          L";      перебором таблицы сессий «менеджер+0x40+4*n», предел 550;\r\n"
          L";   2) при ненайденной сессии сток делал не «следующая запись», а ВЫХОД\r\n"
          L";      ИЗ ВСЕГО ПАКЕТА — один офлайн-игрок в списке съедал выдачу всем\r\n"
          L";      остальным. Теперь запись просто пропускается.\r\n" },
        { L"RevokeOnFlag", L"1",
          L"; * Площадка 0x54D8B7. Флаговый байт записи (+12), в стоке МЁРТВЫЙ\r\n"
          L";   (читается в [ebp-0x2C] и больше нигде), получает смысл:\r\n"
          L";     0 — ВЫДАТЬ звание (стоковый блок повторён байт в байт);\r\n"
          L";     1 — СНЯТЬ звание у прежнего лидера.\r\n"
          L";   Новых опкодов не заводится: снятие и выдача едут одним пакетом.\r\n" },
        { L"ClearActiveTitle", L"1",
          L"; * Если снимаемое звание было НАДЕТО — снять и активное: обнулить слот\r\n"
          L";   (CUser+0x17E20, шаг 38 б, 2 слота), снять шесть бонусов через\r\n"
          L";   sub_54D210 с признаком 0 и отправить в базу 2258 (12 б).\r\n"
          L";   Ровно то, что делает DeleteFameInfo по клиентскому 6069.\r\n" },
        { L"BroadcastPlate", L"1",
          L"; * Разослать 6068 (14 б) владельцу и окружающим по сектору, чтобы плашка\r\n"
          L";   над головой обновилась у всех, кто рядом. ★ Дефект оригинала:\r\n"
          L";   DeleteFameInfo активный слот обнуляет, а 6068 НЕ шлёт вовсе —\r\n"
          L";   снятое звание висело над головой до смены карты.\r\n" },
        { L"PushMaskToOwner", L"1",
          L"; * Отправить владельцу обновлённые маски 6066 «получено» и 6086 «найдено»\r\n"
          L";   СРАЗУ. ★ Дефект оригинала: 6066 уходит клиенту ровно в одном месте —\r\n"
          L";   recvDBUserFameBitInfo@0x54BD10, то есть только при входе в игру.\r\n"
          L";   Без этого ключа снятие доехало бы до клиента лишь после перезахода.\r\n"
          L";   Длина тела берётся у P21 (42/74 и 38/70 б) — общая точка.\r\n" },
        { L"LogRecv", L"1",
          L"; * ДИАГНОСТИКА. Каждый приход опкодов 3404…3409 и разбор КАЖДОЙ записи\r\n"
          L";   пишутся в штатный журнал сервера Log/Log_Title/Title_ГГГГММДД.txt —\r\n"
          L";   туда же, где AddFameBit печатает «Add Before/After Title».\r\n"
          L";   Строки: «P24 RECV op/len/N/rem» (вход приёмника, ДО всех гейтов),\r\n"
          L";   «P24 REC #n title/flag/userIdx/slotRaw/userNum/val -> как найден»,\r\n"
          L";   «P24 GRANT title/userNum». ★ Именно молчание этого места 30.08\r\n"
          L";   скрыло, почему выдача не доезжает. Оставлять включённым.\r\n"
          L";   0 = не писать и НЕ ставить площадку на входе sub_54D710.\r\n" },
        { L"Notify6070", L"1",
          L"; * Отправить владельцу 6070 (13 б) «звание удалено», код 1.\r\n"
          L";   ★★★ Это и есть «ультимативное снятие»: обработчик живого клиента\r\n"
          L";   @0xE9BE80 при коде 1 снимает бит и правит очки БЕЗУСЛОВНО, а окно\r\n"
          L";   званий 18700 перерисовывает только если оно открыто. То есть звание\r\n"
          L";   забирается, даже когда игрок окно не открывал и не перезаходил.\r\n"
          L";   0 = не слать (маску всё равно поправит 6066).\r\n" },
    };

    // -- [P46_StoreShoutOverflow] -- krik lichnoy lavki 6316: perepolnenie steka --
    const IniKey kStoreShoutOverflow[] =
    {
        { L"Enabled", L"1",
          L"; * BEZOPASNOST. Zakrytie perepolneniya steka v obrabotchike 'krika' lichnoy\r\n"
          L";   lavki 6316 (Recv_SelfStoreGlobalChat @0x508B40 -> rassylka 5087). Stok\r\n"
          L";   kopiruet telo paketa v char[80] BEZ proverki dliny (proverka <700 i\r\n"
          L";   predel strlen<80 stoyat POSLE memcpy). Odna ploshchadka 0x508B59 zazhimaet\r\n"
          L";   dlinu kopii v [0..80] DO memcpy: dlinnoe telo ne zatiraet kadr, korotkoe\r\n"
          L";   (otritsatelnaya dlina) -> 0. Predel teksta OSTAYOTSYA stokovym 80 (klient\r\n"
          L";   rezhet do 79); perenosa bufera i snyatiya geyta <80 ne trebuetsya; legalnye\r\n"
          L";   pakety prohodyat bayt-v-bayt kak v stoke. 0 = ostavit stok (DYRA OTKRYTA).\r\n" },
        { L"RuntimeLog", L"1",
          L"; * Pisat stroku '[storechat6316] * OVERFLOW BLOCKED' tolko pri FAKTICHESKOY\r\n"
          L";   obrezke (zayavlennaya dlina > predela) - marker popytki perepolneniya ili\r\n"
          L";   rassinhrona limita s klientom. Antiflud: pervye 50, dalshe kazhdoe 500-e.\r\n" },
    };

    // -- [P47_IdentityOperatorGate] -- antichit A0: GM-flag, sverka lichnosti, IP v DB-logon --
    const IniKey kIdentityOperatorGate[] =
    {
        { L"Enabled", L"1",
          L"; * Glavnyy vyklyuchatel P47. 0 = vse tri chasti vyklyucheny (stok).\r\n" },
        { L"OperatorGmFlag", L"1",
          L"; * A. GM-flag (CharGmInfo -> CUser+0x40B9F) OBYAZATELEN dlya vseh operatorskih\r\n"
          L";   opkodov: 4209, 6005, 6007, 6010, 6012, 6014, 6018, 6020, 6022, 6024, 6026, 6028,\r\n"
          L";   6029, 6030, 6032, 6033, 6035, 6036, 6038, 6040, 6042, 6045, 6046, 6058, 6075,\r\n"
          L";   6094, 6145, 6147; uslovno 6146 i 6184 (sm. nizhe). Bez flaga obrabotchik ne\r\n"
          L";   vyzyvaetsya, stroka v Log_Operator. 0 = stok (tolko gate UserIndex 0..5000).\r\n" },
        { L"CountAsHackPacket", L"0",
          L"; * 0 (umolch., ac0r) = otkaz po operatorskoy komande - TIHIY SBROS: obrabotchik ne\r\n"
          L";   vyzyvaetsya, schyotchik Hack Packet ne rastyot, kika kod 3 i zaschyota v P48 net.\r\n"
          L";   1 = kak v A0: +1 k shtatnomu schyotchiku Hack Packet (sub_524540; pri > 5 kik).\r\n"
          L";   Roznichnye formy 6146/6147/6184 bez flaga - vsegda MOLCHA, bez schyotchika.\r\n" },
        { L"RefusalLogIntervalSec", L"60",
          L"; Stroka otkaza v Log_Operator - ne chashche odnoy za stolko sekund na sessiyu\r\n"
          L";   (slot userNum + UserIndex; novyy logon 4001/5058 - novaya sessiya). Podavlennye\r\n"
          L";   otkazy schitayutsya ('suppressed N' v sleduyushchey stroke). 0 = kazhdyy otkaz.\r\n" },
        { L"TargetJumpRetailOnly", L"1",
          L"; * 6146 bez GM-flaga - tolko roznichnye formy etalona: rezhim 0, tsel = svoy\r\n"
          L";   userNum, shestyorka NPC 30071/30072; rezhim 1, tsel -1, shestyorka kontsa\r\n"
          L";   otschyota. Ostalnoe (chuzhaya tsel, svoi koordinaty) - tolko s flagom.\r\n"
          L";   0 = 6146 kak v stoke (bez gate otpravitelya).\r\n" },
        { L"TargetJumpCountdownWindow", L"1",
          L"; * Forma 'konets otschyota' 6146 bez flaga prinimaetsya tolko v okne posle\r\n"
          L";   prinyatogo ot operatora 6145 s tipom 2 (dlitelnost + CountdownSlackSec).\r\n"
          L";   0 = prinimat vsegda (kak stok).\r\n" },
        { L"CountdownSlackSec", L"60",
          L"; Zapas okna otschyota sverh zayavlennoy dlitelnosti, sekundy (0..3600).\r\n" },
        { L"Match20000", L"1",
          L"; * B. UserIndex v 4001/5058 obyazan sovpadat s UserIndex iz 20000 (CUser+0x174),\r\n"
          L";   inache - shtatnyy otkaz logona (kik 4101 kod 5). 0 = stok.\r\n" },
        { L"SendPeerIp", L"1",
          L"; * C. K telu DB-zaprosa 2001/2089 dopisyvaetsya 'P47I' + IPv4 pira. Nuzhen\r\n"
          L";   DBPatch P50 (sverka s JoyLog1.dbo.Loginfo). Stokovyy DBManager hvost\r\n"
          L";   ignoriruet. 0 = telo kak v stoke (P50 proverit bez IP).\r\n" },
        { L"RuntimeLog", L"1",
          L"; Stroki otkazov v PatchLog (antiflud: pervye 200, dalee kazhdyy 1000-y).\r\n" },
    };

    // -- [P48_KickAutoBlock] -- antichit A0: avtoblok posle N kikov --
    const IniKey kKickAutoBlock[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = avtobloka net (kiki - kak v stoke).\r\n" },
        { L"KickThreshold", L"5",
          L"; * Skolko antichit-kikov do bloka (reshenie vladeltsa 11.10: 5).\r\n" },
        { L"BlockHours", L"24",
          L"; * Srok bloka v chasah (UPHackBlock; -1 = 30 let). Snyatie po sroku - pri\r\n"
          L";   vhode (UPUserLogin, SQL P51) ili skriptom SQL/ac0_unblock_user.sql.\r\n" },
        { L"WindowHours", L"24",
          L"; Okno schyota: schyot sgoraet, esli pervyy kik starshe okna. 0 = ne sgoraet.\r\n" },
        { L"CountTypes", L"3,6",
          L"; Kakie tipy Send_DisConnectType schitat: 3 = narushenie protokola (Secret/MD5/\r\n"
          L";   NotKnow/Hack Packet), 6 = speedhack (NpcServer). 1/2/5 NE schitat: ping,\r\n"
          L";   povtornyy vhod, oshibka logona (UserIndex tam ne podtverzhdyon).\r\n" },
        { L"InWorldOnly", L"1",
          L"; * Schitat tolko sessii, voshedshie v mir (CUser+0x2E = 1): do vhoda UserIndex\r\n"
          L";   ne podtverzhdyon, kik nelzya zapisyvat na chuzhuyu uchyotku. NE vyklyuchat.\r\n" },
        { L"SoulMateSessionAccount", L"1",
          L"; * Vhod soulmeytom (SoulState 2, CUser+0x182D3): kik i avtoblok zaschityvayutsya\r\n"
          L";   uchyotke SESSII vhoda (iMateUserIndex, CUser+0x182C6), a ne hozyainu personazha\r\n"
          L";   (CUser+0x174). Uchyotka sessii neizvestna - kik ne zaschityvaetsya. 0 = kak v A0.\r\n" },
        { L"CounterFile", L"..\\GameServer\\ConfigSet\\ac_kick_counter.ini",
          L"; Fayl schyotchika (otnositelno papki exe; obshchiy dlya GameServer i Indun).\r\n" },
    };

    // -- [P49_OriginalChecksRestore] -- mera 11: vozvrat shtatnyh proverok originala --
    const IniKey kOriginalChecksRestore[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = obe proverki kak v stoke/na zhivom do 12.10.\r\n" },
        { L"SecretRepeatKick", L"1",
          L"; * Kik 'Secret Broken Count' pri > 20 oshibkah anti-povtora (sub_524440 v stoke\r\n"
          L";   vsegda 0). 0 = tolko zhurnal Log_Secret, kak ran'she.\r\n" },
        { L"FunctionItemMd5Full", L"1",
          L"; * 5450: podpis proveryaetsya po 0x101 baytam (stolko podpisyvaet klient),\r\n"
          L";   vmesto 0x89 - i obhod P08 NE stavitsya. 0 = vernut P08 (proverka snyata).\r\n" },
    };

    // -- [P56_CombatLimits] -- antichit V5 (mera 9): limity boya GameServer --
    const IniKey kCombatLimits[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ni odnoy ploshchadki (boy kak v stoke: tolko proverki NpcServer).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (ac.move_combat vidy 7-11), 1 = otkaz shtatnymi kodami:\r\n"
          L";   5256 povtor zayavki v puti -> 5257 kod 7; 4026/4028 ranshe pola -> 4027 kod 0;\r\n"
          L";   4201/4203 ranshe pola ili dalshe PvpMaxCells -> 4202 kod 0. Vklyuchat posle nedeli zhurnala.\r\n" },
        { L"DedupeRefuse", L"1",
          L"; * Povtor pary (tip, indeks) v spiske tseley 5256/6158 -> otkaz shtatnym putyom sub_52BFF0\r\n"
          L";   (5257/6159 kod 0) NEZAVISIMO ot Mode: chestnyy klient dubley ne shlyot. 0 = tolko zhurnal (vid 6).\r\n" },
        { L"InFlightTimeoutMs", L"2000",
          L"; Skolko derzhat otmetku 'zayavka 5256 v puti k NpcServer' bez otveta 8206 (100..10000).\r\n" },
        { L"AttackFloorMs", L"200",
          L"; Pol intervala mezhdu 4026/4028 odnogo igroka po GetTickCount GameServer, ms (0 = vykl).\r\n"
          L";   Tochnyy interval po oruzhiyu schitaet NpcServer (N01); zdes grubaya vtoraya liniya.\r\n" },
        { L"PvpFloorMs", L"200",
          L"; Pol intervala mezhdu 4201/4203 odnogo igroka, ms (0 = vykl).\r\n" },
        { L"PvpMaxCells", L"6",
          L"; Dalnost PvP-udara po kletkam CUser (+0x54E6/+0x54E8), max(|dx|,|dy|). Stok NpcServer - 4 kletki.\r\n"
          L";   0 = vykl.\r\n" },
        { L"SkillMaxCells", L"20",
          L"; Dalnost tseli-igroka (tip 1) v zayavke 5256/6158 po kletkam; TOLKO zhurnal (vid 11). 0 = vykl.\r\n" },
    };

    // -- [P57_MoveGuard] -- antichit A6: hod (porog Hack Position -> kik, predely 4006, 4008) --
    const IniKey kMoveGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = patch ne stavitsya (hod - kak v stoke).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (stroki v Log_Game + ac.move_combat vidy 14..20), kika i otkazov NET.\r\n"
          L";   1 = otkaz/kik: porog Hack Position -> kik; narushenie 4006 -> stokovoe telo Hack Position\r\n"
          L";   (4007 result=5, otkat pozitsii); 4008 -> pozitsiya iz proverennyh poley [13],[17].\r\n"
          L";   Vklyuchat 1 tolko posle nedeli nablyudeniya zhurnala (plan 00_PLAN.md par.6).\r\n" },
        { L"HackPosKickThreshold", L"30",
          L"; * Skolko shtatnyh 'CharMove/CharReMove Hack Position' na SESSIYU za okno -> kik (Mode=1)\r\n"
          L";   ili stroka 'porog dostignut' (Mode=0). Fon chestnogo klienta: v arhive logov vladeltsa\r\n"
          L";   maksimum 23 za sutki na uchyotku (GM-teleporty), sm. otchyot wave_A6. Minimum 2.\r\n" },
        { L"HackPosWindowSec", L"600",
          L"; Okno schyota, s. Schyot sbrasyvaetsya pri smene uchyotki v slote i posle kika.\r\n" },
        { L"KickType", L"6",
          L"; Tip Send_DisConnectType pri kike: 6 = SpeedHack (klient: loc 1106; schitaet P48 CountTypes),\r\n"
          L";   3 = narushenie protokola (loc 1100). 0..15.\r\n" },
        { L"MaxStepLen", L"72500",
          L"; 4006: predel dliny otrezka 'tekushchaya klienta -> tsel', ed. (100 = kletka). 0 = ne proveryat.\r\n"
          L";   p57fix 15.10: u originala dlinu otrezka ogranichivaet tolko karta (avtohod po puti - do ~72400 po\r\n"
          L";   diagonali setki 512x512); chestnyy dalniy klik 4769 ed. lovilsya porogom 4000. Znachenie nizhe 72500\r\n"
          L";   DLL podnimaet do 72500 (stroka v PatchLog), sm. move-guard-p57.md 'p57fix'.\r\n" },
        { L"BudgetReserveMs", L"3000",
          L"; 4006 v dvizhenii (p57fix 15.10): EMKOST byudzheta operezheniya, ms. Operezhenie = (|start->klient| -\r\n"
          L";   |start->servernaya tochka|) / skorost - ekstrapolyatsiya s poslednego shaga MoveSyncProcess; polozhitelnoe\r\n"
          L";   spisyvaetsya iz byudzheta sessii; bolshe ostatka -> narushenie (vid 17). Do 15.10 merili ot +0x5502\r\n"
          L";   (takt SHAGA sinhronizatsii, ne starta otrezka) -> lozhnye srabatyvaniya.\r\n" },
        { L"BudgetRefillPermille", L"250",
          L"; Popolnenie byudzheta operezheniya, promille realnogo vremeni (250 = 250 ms za sekundu; 0..1000).\r\n" },
        { L"CheckPassable", L"1",
          L"; 4006 v dvizhenii: kletka pozitsii klienta vne karty ili neprohodima (sub_41A010) -> narushenie.\r\n" },
        { L"StopFieldTolerance", L"1",
          L"; 4008: dopusk rashozhdeniya poley [5],[9] (pishutsya stokom) i [13],[17] (proverennye), ed.\r\n" },
        { L"StopGateJournal", L"1",
          L"; 4008 pod geytom sostoyaniya (sub_52BFF0) / kontrolya (sub_484D20) - TOLKO zhurnal (vid 12), otkaza net.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki na (sessiya, vid) za N s; podavlennye - v repeat_suppressed sleduyushchey.\r\n" },
    };

    // -- [P58_DisconnectReasonLog] -- antichit A6 (P1): prichina otklyucheniya v obshchiy log --
    const IniKey kDisconnectReasonLog[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = kak v stoke (prichina 4101 pishetsya tolko na servere tipa 4 v Log_RoseWar).\r\n" },
        { L"LogChannel", L"0",
          L"; Kanal sub_569DF0: 0 = Log_Game (obshchiy), 6 = Log_Operator, 31 = Log_RoseWar.\r\n" },
    };

    // -- [P59_RareDropJournal] -- antichit A6 (P4): zhurnal redkogo dropa --
    const IniKey kRareDropJournal[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. Porog 'redkogo' = tablitsa P11 (GradeTableFile v [P11_ServerAnnounceSources],\r\n"
          L";   ConfigSet\\announce_codes.txt: greyd >= 3, kak u anonsa 6616/6131). Pustaya tablitsa = patch ne stavitsya.\r\n" },
        { L"Pickup", L"1",
          L"; Zhurnalirovat i podbor redkogo (5012) cherez tramplin P11 (stavitsya i pri P11 PickupEnabled=0).\r\n" },
        { L"LogChannel", L"29",
          L"; Kanal fayl-loga: 29 = Log_UserEvent (svobodnyy), 1 = Log_Item, 0 = Log_Game.\r\n" },
        { L"MaxPerMinute", L"120",
          L"; Ogranichitel: ne bolshe N strok v minutu na protsess; sverh - schitayutsya v repeat_suppressed.\r\n" },
    };

    // -- [P60_ValueGuard] -- antichit A7 (L5, A3/A4): znacheniya po servernym tablitsam --
    const IniKey kValueGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = patch ne stavitsya (obrabotchiki - kak v stoke).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (stroki 'P60 ValueGuard' v Log_Item + ac.other vidy 20..29), otkazov NET.\r\n"
          L";   1 = shtatnyy otkaz togo zhe obrabotchika: 5020 -> 5021 kod 0 (kolichestvo) / 4 (summa) / 3 (ves);\r\n"
          L";   6180 -> 6181 kod 8; 6150 -> 6151 kod 6; 5048 -> 5049 kod 4; 5041 -> 'return 0' (kak bez predmeta);\r\n"
          L";   6586 -> tihiy vyhod (kak u sosedey pri neudache anti-povtora); 6521 -> 6522 kod 3.\r\n"
          L";   Vklyuchat 1 tolko posle nedeli nablyudeniya zhurnala (plan 00_PLAN.md par.6).\r\n" },
        { L"Buy5020", L"1",
          L"; 5020 pokupka u NPC: kolichestvo <= 0 (vid 20), > MaxBuyCount (vid 21), summa tsena*kol-vo ili ves*kol-vo\r\n"
          L";   v int64 > INT_MAX (vid 22). Tolko stopochnaya vetka stoka (+7==4,+36==1,+26!=10,+35!=0); ekipirovka\r\n"
          L";   (port shlyot -1) ne proveryaetsya - stok kolichestvo tam ne chitaet.\r\n" },
        { L"MaxBuyCount", L"32767",
          L"; Verhnyaya granitsa kolichestva v pozitsii 5020. V Item_Table.txt maks. stopki NET (+35 - bulev flag),\r\n"
          L";   klient schitaet maksimum kak dengi/tsena, pole v pakete i16 -> umolchanie 32767. Szhimat po zhurnalu.\r\n" },
        { L"Fish6180", L"1",
          L"; 6180 kniga rybaka: kolichestvo <= 0 (vid 23) -> 6181 kod 8 (tot zhe, chto stok pri 'bolshe stopki').\r\n" },
        { L"Title6150", L"1",
          L"; 6150 doklad ob ohote: kolichestvo <= 0 (vid 24) -> 6151 kod 6.\r\n" },
        { L"QuestBook5048", L"1",
          L"; 5048 pokupka knigi zadaniy: kod vne 2001..dword_5F5EA8 (sub_532B30 propuskaet 20000+N) (vid 25) -> 5049 kod 4.\r\n" },
        { L"QuestReward5041", L"1",
          L"; 5041 sdacha kvesta (sub_45DEE0): nomer nagrady vne 1..N RewardTable (vid 26) -> shtatnyy return 0.\r\n" },
        { L"StarPoint6586", L"1",
          L"; 6586 znak zodiaka: rezultat anti-povtora (stok ignoriroval, vid 27) i znak vne 1..StarPointMax (vid 28)\r\n"
          L";   -> tihiy vyhod bez otveta (kak u sosedey 6180/6150 pri neudache anti-povtora).\r\n" },
        { L"StarPointMax", L"12",
          L"; Znakov zodiaka (Constellation.BIN klienta: 12; port shlyot 1..12).\r\n" },
        { L"ClanGrade6521", L"1",
          L"; 6521 stupen klana: stupen vne 2..5, tsel = otpravitel, stupen ne nizhe sobstvennoy (vid 29) -> 6522 kod 3.\r\n"
          L";   Nahodka 'ne podtverzhdena' (DB UPClanMemberGradeUp mozhet proveryat sama) - derzhat Mode=0 i smotret zhurnal.\r\n" },
        { L"NameChange6140", L"0",
          L"; ZAREZERVIROVANO: proverka imeni 6138/6140 realizovana OTDELNYM patchem [P68_CharNameGuard] (A13, 2026-10-13)\r\n"
          L";   i SQL A13 (UPNickCheck/UPCharRename/UPCreateChar). Zdes lyuboe znachenie - ploshchadki ne stavyatsya.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki na (sessiya, vid) za N s; podavlennye - v repeat_suppressed sleduyushchey.\r\n" },
    };

    const IniKey kP61[] =
    {
        { L"Enabled", L"0",
          L"; * 0 = ne stavitsya (stok). Proslojka shifrovaniya trafika (AsdaSecure): ECDH P-256 na\r\n"
          L";   podklyuchenie, podpis servera ECDSA (klyuch vshit v klient), AES-256-GCM s nomerom kadra.\r\n" },
        { L"AllowLegacy", L"1",
          L"; 1 = staryy klient (pervyy bayt 0xFB) idet bez shifrovaniya (perehod); 0 = tolko 0xA5.\r\n" },
        { L"KeyFile", L"secure_server.key",
          L"; Fayl zakrytogo klyucha ryadom s GameServer.exe (kladet vladelets, generit keygen).\r\n"
          L";   Net fayla - shifrovanie ne vklyuchitsya. Poryadok vkl na dev: snachala Enabled=1 zdes,\r\n"
          L";   potom v kliente cvar asda.Net.Secure=1. Otkat - Enabled=0.\r\n"
          L";   V7d: fayl proveryaetsya pri starte (104 b, metka ASDAKEY1); negodnyy - patch NE stavitsya\r\n"
          L";   (stok, staryy protokol), prichina v PatchLog.\r\n" },
        { L"KillOnViolation", L"1",
          L"; V7d: 1 = narushenie kanala (porcha tega, povtor nomera kadra, musor do rukopozhatiya, dlina kadra,\r\n"
          L";   staryy klient pri AllowLegacy=0) - RAZRYV shtatnym Ciocp::DisConnect + PatchLog + ac.other 56-59.\r\n"
          L";   0 = kadr tolko otbrasyvaetsya (povedenie V7b, otkat).\r\n" },
        { L"LogPerMinute", L"30",
          L"; V7d: ne bolshe N strok o narusheniyah v PatchLog v minutu (ostalnye schitayutsya; 0 = bez limita).\r\n" },
        // ★ fix2b: кадры сервера до рукопожатия (6004 «сервер переполнен» сразу после accept) не теряются
        { L"PreHandshakeQueueKB", L"64",
          L"; fix2b: kadry servera DO rukopozhatiya (otkaz 6004 srazu posle accept) - v ochered slota (ne bolshe N KB),\r\n"
          L";   uhodyat srazu za ServerHello / kak est staromu klientu. 0 = ne kopit (kadry teryayutsya, kak do fix2b).\r\n" },
        { L"PreHandshakeCloseMs", L"5000",
          L"; fix2b: DisConnect pri nevydannoy ocheredi otkladyvaetsya do pervyh bayt klienta, ne dolshe N ms. 0 = ne otkladyvat.\r\n" },
        { L"PreHandshakeLingerMs", L"150",
          L"; fix2c: pauza mezhdu vydachey otkaza i razryvom, ms (sokety zakryvayutsya RST; stok GS zhdal Sleep(100)). 0 = srazu.\r\n" },
        // ★ fix2d (П-1/П-2): очередь шифрованных кадров слота, когда досылка стокового Send (0x9F9C) полна
        { L"TxQueueKB", L"1024",
          L"; fix2d: shifrovannye kadry, kotorye dosylka stokovogo Send (0x9F9C) ne vmestit (klient ne chitaet soket - zagruzka karty),\r\n"
          L";   zhdut v ocheredi slota (ne bolshe N KB, vytalkivaet storozh). Perepolnenie / otkaz stoka - razryv + ac.other 61.\r\n"
          L";   0 = bez ocheredi (dosylka polna - srazu razryv).\r\n" },
        // ★ fix2e (ревизия fix2d, Ф-1): общий предел очередей моста на процесс
        { L"TxQueueTotalMB", L"64",
          L"; fix2e: obshchiy predel ocheredey mosta na VES process (vse sloty vmeste), MB (1-1024). Esli mnogo klientov razom ne chitayut\r\n"
          L";   soket (sboy seti, zloumyshlennik) - sverh predela razryv slota, chya ochered ne pomestilas, + ac.other 61 prichina 4.\r\n"
          L";   Nehvatka pamyati v moste - razryv slota (prichina 5), process ne padaet.\r\n" },
        // ★ sec2 (блок В плана альфы, стойка в интернете): справедливая доля предела, ускорение рукопожатия, допуск до рукопожатия
        { L"TxQueueFairKB", L"256",
          L"; sec2: pri obshchem predele rvyotsya tolko 'tyazhyolyy' slot (ochered >= sredney ili >= N KB, prichina 4); 'lyogkomu'\r\n"
          L";   (chestnyy klient gruzit kartu) kadr prinimaetsya do predela + 1/8, a storozh vytesnyaet NAIBOLSHUYU ochered (prichina 6).\r\n"
          L";   0 = tolko srednyaya.\r\n" },
        { L"HandshakeKeyCache", L"1",
          L"; sec2: klyuch podpisi importiruetsya v CNG odin raz (tolko v pamyati processa); 0 = na kazhdoe rukopozhatie (kak ran'she).\r\n" },
        { L"HandshakePool", L"16",
          L"; sec2: par ECDH zagotovleno fonovoy nityu (0-64), kazhdaya odnorazovaya, starshe 10 min ne vydayotsya; 0 = generatsiya na meste.\r\n" },
        { L"ConnPerIpMax", L"120",
          L"; sec2: ne bolshe N novyh podklyucheniy s odnogo adresa za okno ConnPerIpWindowSec (0 = bez predela); sverh - razryv\r\n"
          L";   DO rukopozhatiya + PatchLog '[dopusk]' + ac.other 63 (odna stroka na adres za okno). 120/60 s: 50 testerov za odnim NAT\r\n"
          L";   (vhod + povtor) s zapasom; potok s odnogo adresa - ne bolshe 2 rukopozhatiy/s.\r\n" },
        { L"ConnPerIpWindowSec", L"60",
          L"; sec2: okno predela s adresa, s (1-3600).\r\n" },
        { L"MaxPendingHandshakes", L"64",
          L"; sec2: ne bolshe N soedineniy 'accept est, rukopozhatie ne zaversheno' na process (0 = bez predela); sverh - novoe\r\n"
          L";   soedinenie razorvano + ac.other 64.\r\n" },
        { L"HandshakeDeadlineMs", L"10000",
          L"; sec2: rukopozhatie ne zaversheno za N ms posle podklyucheniya - razryv + ac.other 65 (0 = bez sroka). Molchashchiy soket\r\n"
          L";   (ni bayta) - tolko pri AllowLegacy=0 (staryy klient mog otkryt soket zaranee). Klient zhdyot rukopozhatie 5 s.\r\n"
          L";   sec2b: pri AllowLegacy=1 molchashchiy soket po sroku ne rvyotsya, no snimaetsya so schyota nezavershyonnyh.\r\n" },
        { L"AdmissionLogGapMs", L"5000",
          L"; sec2: stroki PatchLog i zhurnal vidov 64/65 ne chashche raza v N ms (podavlennye - v value3).\r\n" },
        // ★ sec2b (ревизия SEC2 Н-1): предел незавершённых рукопожатий с ОДНОГО адреса (один адрес не отсекает всех остальных)
        { L"MaxPendingPerIp", L"16",
          L"; sec2b: ne bolshe N nezavershyonnyh rukopozhatiy s ODNOGO adresa (0 = bez predela); sverh - novoe soedinenie s etogo\r\n"
          L";   adresa razorvano + ac.other 64 (tekst 'from IP'). Ostalnye adresa ne zatragivayutsya.\r\n" },
    };

    // -- [P62_SlotUniqueness] -- antichit A7 (L3/A5): unikalnost slotov v mnogoslotovyh operatsiyah --
    const IniKey kSlotUniqueness[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. Odna obshchaya proverka 'pary (konteyner, slot)/uid v zayavke unikalny i\r\n"
          L";   v granitsah konteynera' pered otpravkoy v DBManager u 5018/6549/6506/6555/6096/6112 i\r\n"
          L";   'slot 0 != slot 1' u 6067 (zvaniya).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (umolchanie): stroka 'P62 SlotUniqueness: ...' v log servera + ac.other vidy 30..34,\r\n"
          L";   obrabotchik rabotaet kak v stoke. 1 = OTKAZ shtatnym kodom togo zhe obrabotchika (5019 kod 0,\r\n"
          L";   6550 kod 2, 6507 kod 5, 6556 kod 10, 6097 kod 7, 6113 kod 3; 6067 - slot 1 := -1).\r\n" },
        { L"CheckBounds", L"1",
          L"; Vid 31: ssylka na pustoy slot / vne granits konteynera (sub_4D61E0 veshch ne nahodit) u 5018/6549/6506/6555.\r\n"
          L";   U 5018 stok pri etom beryot KOD PREDYDUSHCHEY zapisi. 0 = tolko povtory.\r\n" },
        { L"Sell5018",        L"1", L"; Ploshchadki po obrabotchikam (0 = ne stavit): 5018 prodazha NPC (5 zapisey).\r\n" },
        { L"Extraction6549",  L"1", L"; 6549 izvlechenie (8 materialov + istochnik).\r\n" },
        { L"Reset6506",       L"1", L"; 6506 sbros/vosstanovlenie uluchsheniy (10 materialov + tsel, tolko vid 1).\r\n" },
        { L"PrimiumSum6555",  L"1", L"; 6555 premium-summa (5 materialov).\r\n" },
        { L"OpenPackage6096", L"1", L"; 6096 vskrytie korobki (do 5 tselevyh slotov + slot korobki; tolko povtory).\r\n" },
        { L"PetUnion6112",    L"1", L"; 6112 yunion pitomtsev (3 uid materialov).\r\n" },
        { L"Fame6067",        L"1", L"; 6067 nadet zvanie: slot 0 != slot 1.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal sub_569DF0 dlya strok narusheniy: 1 = Log_Item, 0 = Log_Game.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ogranichitel: odna stroka (log + zhurnal) na (sessiya, vid) za stolko sekund; podavlennye\r\n"
          L";   schitayutsya (repeat_suppressed). 0 = bez ogranichitelya.\r\n" },
    };

    // -- [P63_InFlightLock] -- antichit A7 (L2): obshchiy zamok "zapros v BD v polyote" --
    const IniKey kInFlightLock[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. Zamok (slot, semya) s privyazkoy k UserIndex: povtor zaprosa, poka otvet DBManager\r\n"
          L";   eshchyo v puti, vidit zamok. Stavitsya u call sub_5646C0, snimaetsya v priyome otveta BD (posle obrabotki).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (dubl pishetsya v ac.other vid 35 i Log_Item, zapros PROHODIT). 1 = otkaz: u 5048/6162 -\r\n"
          L";   rannyaya shtatnaya vetka 'zanyat' (vid 36), u ostalnyh - povtornaya otpravka v BD podavlyaetsya (vid 37),\r\n"
          L";   klient dublya otveta ne poluchaet (otvet na PERVYY zapros pridyot kak obychno). Protokol ne menyaetsya.\r\n" },
        { L"LockTimeoutMs", L"15000",
          L"; Zhizn zamka bez otveta BD, ms (1000..120000). Poteryannyy otvet ne zapiraet semyu navsegda; otvet posle\r\n"
          L";   taym-auta - vid 38 (tolko zhurnal).\r\n" },
        { L"EarlyRefuse", L"1",
          L"; Mode=1: ranniy otkaz vetkoy 'zanyat' (call sub_52BFF0) u 5048 (0x5118FC -> 5049 kod 0) i 6162 (0x515111).\r\n"
          L";   U 6502/6506 eti ploshchadki zanyaty P33 - tam tolko podavlenie otpravki.\r\n" },
        { L"SessionClear", L"1",
          L"; Sbros vseh zamkov slota pri vyhode (CUserManager::ClearUserMemory 0x527374, vse 7 vetok DisConnectUser).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ogranichitel: ne chashche odnoy stroki na (slot, vid) za N s; podavlennye - v repeat_suppressed. 0 = bez.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal sub_569DF0 dlya strok P63: 1 = Log_Item, 0 = Log_Game.\r\n" },
        // Semi (klientskiy opkod -> zapros BD -> otvet BD). 0 = ne stavit ploshchadki etoy semi.
        { L"Lock5048", L"1", L"; CharQuestItemBuy 2072/2073 (ranniy otkaz: 5049 kod 0)\r\n" },
        { L"Lock6162", L"1", L"; CharRoseWarStoreBuy 2469/2470 (ranniy otkaz: shtatnyy hvost bez otveta)\r\n" },
        { L"Lock6096", L"1", L"; Recv_OpenPackageItem 2272/2273\r\n" },
        { L"Lock6098", L"1", L"; EventItemRequestReq 2270/2270 (slot v tele otveta +0)\r\n" },
        { L"Lock6502", L"1", L"; Recv_User_Disassemble 2302/2303\r\n" },
        { L"Lock6506", L"1", L"; Recv_User_ShellItemUpgradeReset 2306/2307\r\n" },
        { L"Lock6549", L"1", L"; Recv_UserUpgradeExtraction 2527/2528\r\n" },
        { L"Lock6551", L"1", L"; Recv_UserUpgradeBless 2529/2530\r\n" },
        { L"Lock6553", L"1", L"; Recv_UserItemOptionTrans 2531/2532\r\n" },
        { L"Lock5433", L"1", L"; Recv_ShellItemOption_Extraction 2165/2165\r\n" },
        { L"Lock5468", L"1", L"; Recv_GachaItemUse 2229/2229\r\n" },
        { L"Lock6555", L"1", L"; Recv_UserPrimiumSum 2533/2534\r\n" },
        { L"Lock6586", L"1", L"; Recv_UserStarPointUpdate 2568/2569\r\n" },
        { L"Lock6140", L"1", L"; RecvClient_CharNameChange 2452/2453\r\n" },
        { L"Lock6102", L"1", L"; pitomtsy: Recv_IncubatorReq 2275/2276\r\n" },
        { L"Lock6108", L"1", L"; pitomtsy: Recv_PetConditionUp 2278/2279\r\n" },
        { L"Lock6110", L"1", L"; pitomtsy: Recv_PetLiberate_Req 2280/2281\r\n" },
        { L"Lock6112", L"1", L"; pitomtsy: Recv_PetUnion_Req 2282/2283\r\n" },
        { L"Lock6118", L"1", L"; pitomtsy: Recv_PetNameChange_Req 2292/2293\r\n" },
        { L"Lock6121", L"1", L"; pitomtsy: Recv_PetPossessionCountUp_Req 2294/2294\r\n" },
        { L"Lock6148", L"1", L"; pitomtsy: RecvClient_PetMaxLevelUp 2464/2465\r\n" },
        { L"Lock6171", L"1", L"; rybalka: Recv_EndFishing 2577/2578 (FISH-2)\r\n" },
        { L"Lock6182", L"1", L"; rybalka: Recv_FishingBookReward 2587/2588 (FISH-5)\r\n" },
        { L"Lock6591", L"1", L"; zadaniya: RecvUser_LimitationQuestEnter 2653/2654\r\n" },
        { L"Lock6593", L"1", L"; zadaniya: RecvUser_LimitationQuestResult 2657/2658 (QUEST-3)\r\n" },
    };

    // -- [P65_ConsumableType] -- antichit A7 (L5/A9): tip rashodnika po Function_Table --
    const IniKey kConsumableType[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (chetyre ploshchadki `call sub_532B10`: 6551 @0x535B01, 6553 @0x53664A, 5433 @0x514A79,\r\n"
          L";   5450 @0x4EDD82).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (narushenie propuskaetsya kak v stoke, stroka v Log_Item + ac.other vidy 45..48);\r\n"
          L";   1 = OTKAZ shtatnoy sosedney vetkoy obrabotchika: 6552/6554 kod 2, 5434 kod 0, 5451 kod 9.\r\n"
          L";   Vklyuchat 1 tolko posle nedeli nablyudeniya zhurnala (chestnyy port ne dolzhen popadat).\r\n" },
        { L"CheckBless", L"1",
          L"; 6551 UpgradeBless: tip svitka (bayt +8 zapisi Function_Table) dolzhen byt v BlessTypes.\r\n" },
        { L"BlessTypes", L"204,206",
          L"; Tipy svitka blagosloveniya. Stok 6549 porozhdaet ih tolko iz zapisey tipa 204 (kod 401) i 206 (kod 363).\r\n"
          L";   Pusto = ne proveryat.\r\n" },
        { L"CheckOptionTrans", L"1",
          L"; 6553 ItemOptionTrans: tip svitka obmena optsiy dolzhen byt v OptionTransTypes.\r\n" },
        { L"OptionTransTypes", L"67",
          L"; Po klientu: okno obmena optsiy berjot tolko special_itemlist.SubType==67 (kody 364/365/366/458/546).\r\n"
          L";   Vnimanie: kody 367 i 393 u klienta SubType 67, a v servernoy tablitse tip 17/15 (tablitsy razoshlis) -\r\n"
          L";   pri Mode=1 oni budut otvergnuty; smotret zhurnal vid 46. Pusto = ne proveryat.\r\n" },
        { L"CheckHelper", L"1",
          L"; 5433 ShellItemOption_Extraction: tip pomoshchnika (bonus k shansu iz +9) dolzhen byt v HelperTypes.\r\n" },
        { L"HelperTypes", L"96",
          L"; Po klientu: pod-panel svitka-bustera berjot tolko SubType==96 (kody 289/290/291/459). Pusto = ne proveryat.\r\n" },
        { L"CheckUseCode", L"1",
          L"; 5450 Char_FunctionItem_Use: kod iz paketa (po nemu geyty sostoyaniya/pola/urovnya) == kod v slote (po nemu deystvie).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ogranichitel: ne chashche odnoy stroki na (sessiya, ploshchadka); podavlennye - v repeat_suppressed.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal sub_569DF0 dlya stroki narusheniya: 1 = Log_Item, 0 = Log_Game.\r\n" },
    };

    // -- [P66_PositionGuard] -- antichit A7 (L6/A10): sverka s servernoy kletkoy/sostoyaniem --
    const IniKey kPositionGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = patch ne stavitsya (5012/5427/6093/5428 - kak v stoke).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (stroki v Log_Game/Log_Item + ac.move_combat vidy 24..30), otkazov NET.\r\n"
          L";   1 = otkaz STOKOVYMI vetkami: 5012 -> LABEL_103 (5013 result=0); 5427 -> vetka 'kletka vne karty'\r\n"
          L";   (molcha, log kanala 2); 6093 -> vozvrat 0 bez voskresheniya (molcha); 5428 -> vetka 'Exception Error'.\r\n"
          L";   Vklyuchat 1 tolko posle nedeli nablyudeniya zhurnala (plan 00_PLAN.md par.6).\r\n" },
        { L"PickupCheck", L"1",
          L"; 5012: sravnivat SERVERNUYU kletku (CUser+0x54E6/8) s kletkoy predmeta iz paketa (stok sravnivaet dve\r\n"
          L";   kletki IZ PAKETA, |cli-item| < 7).\r\n" },
        { L"PickupTileTolerance", L"9",
          L"; 5012: max(|srvX-itemX|,|srvZ-itemZ|) >= N -> narushenie. 9 = stokovye 7 + 2 kletki zapasa (tik hoda,\r\n"
          L";   okruglenie CharStop); chestnyy klient shlyot 5012 stoya NA kletke predmeta ili v 3 kletkah.\r\n" },
        { L"ReturnItemOnRefuse", L"1",
          L"; LOOT-2 - ISPRAVLENIE DEFEKTA ORIGINALA (ne antichit), rabotaet pri LYUBOM Mode: na vetkah otkaza LABEL_103\r\n"
          L";   predmet, uzhe snyatyy s karty (GetSearchPickingItemInfo), vernut na kartu (sub_41EFD0). Dengi (20551)\r\n"
          L";   ne vozvrashchayutsya (vetki posle razdachi po otryadu); nakopitelnyy predmet s kolichestvom <= 0 (vetka\r\n"
          L";   'iAmount <= 0', stok uzhe razoslal 5015) - tozhe ne vozvrashchaetsya. 0 = kak v stoke (predmet propadaet).\r\n" },
        { L"RecallCheck", L"1",
          L"; 5427: trebovat ozhidanie zova (dostavka 5236 partnyoru), partnyora v slote, odnu kartu i kletku zova.\r\n" },
        { L"RecallWindowSec", L"120",
          L"; 5427: srok ozhidaniya s momenta dostavki 5236, s.\r\n" },
        { L"RecallTileTolerance", L"3",
          L"; 5427: kletka paketa = kletke zova (tochno) ILI ne dalshe N kletok ot TEKUSHCHEY kletki partnyora.\r\n" },
        { L"RecallGate", L"1",
          L"; 5427: geyt sostoyaniya po polyam stokovogo sub_52BFF0 (1 myortv, 2 obmen, 3 birzha, 4 lavka, 5 rybalka);\r\n"
          L";   sama funktsiya NE vyzyvaetsya (ona shlyot klientu 6001 dazhe pri kode 0), paket ne uhodit.\r\n" },
        { L"ResCheck", L"1",
          L"; 6093: podtverzhdenie tolko po zapomnennomu predlozheniyu sub_52B070 (kto/tip/protsent), tsel = otpravitel.\r\n" },
        { L"ResOfferWindowSec", L"330",
          L"; 6093: srok predlozheniya, s (taymer menyu smerti 300 s + zapas).\r\n" },
        { L"MiningCheck", L"1",
          L"; 5428: trebovat start kopaniya (5028 lopata -> 5429 na NpcServer) i sostoyanie deystviya.\r\n" },
        { L"MinDigMs", L"5000",
          L"; 5428: minimum ms ot starta (zhivoy NpcServer\\ini\\Collection.ini: CollectionTypeAniTime 6000/9000) - 1 s zapasa.\r\n" },
        { L"DigWindowSec", L"60",
          L"; 5428: start starshe N s ne schitaetsya.\r\n" },
        { L"RequireDigState", L"1",
          L"; 5428: CUser+0x54E4 (kod deystviya iz 4024) dolzhen byt v DigStates.\r\n" },
        { L"DigStates", L"110,114",
          L"; Kody deystviya kopaniya: 110 lopata, 114 avto-lopata (etalon Item_UseShovelingTool).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki na (sessiya, vid) za N s; podavlennye - v repeat_suppressed sleduyushchey.\r\n" },
    };

    // -- [P67_GachaRewardVariant] -- antichit A7 (A2): 6581 variant priza gachi; 6579 rezultat ruletki --
    const IniKey kGachaRewardVariant[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. Ploshchadki: 6581 `call sub_4A7EA0` 0x4F75F5 (posle stokovyh proverok, pered DB-2555)\r\n"
          L";   i 6579 `call sub_524390` 0x49A963. Stavitsya tolko pri sovpadenii baytov (stok = zhivoy GameServer/Indun).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (ac.other vidy 50..52 + Log_Item 'P67 ...'), nichego ne otklonyaetsya.\r\n"
          L";   1 = otkaz: 6581 -> STOKOVOE telo otkaza (3) = 6582 kod 10; 6579 -> tihiy vyhod stoka (kak pri\r\n"
          L";   oshibke sekreta), bez otveta. Pered Mode=1 sverit tablitsy porta i servera (tools/verify_p67.py --tables):\r\n"
          L";   LinkWord korobok rashoditsya, chestnye pary mogut poluchit otkaz.\r\n" },
        { L"RequirePrizeInTable", L"1",
          L"; 6581: kod priza v yacheyke obyazan byt v PrimiumGaChaTable.txt (massiv servera, 9 b/zapis). 0 = ne proveryat\r\n"
          L";   (naprimer, esli v pochte lezhat prizy iz STAROY tablitsy gachi).\r\n" },
        { L"ZeroKeyIsViolation", L"1",
          L"; 6581, korobka (subType 200/201): LinkWord (+65 Item_Table) == 0 u priza ili varianta pri variant != priz\r\n"
          L";   = 'semeystva net' (kak otsechka porta) -> narushenie. 0 = schitat neproveryaemym (propusk bez zhurnala).\r\n" },
        { L"NonPackageSameCodeOnly", L"1",
          L"; 6581, ne-korobka: SetCode (klyuch semeystva) serveru nedostupen -> variant obyazan sovpadat s prizom.\r\n"
          L";   0 = ne proveryat (ostayotsya tolko stokovaya proverka 'klass 3').\r\n" },
        { L"SoulResultGuard", L"1",
          L"; Stavit ploshchadku 6579 (Recv_UserSoulResult): flag aktivnoy ruletki CUser+99252 obyazatelen.\r\n" },
        { L"RequireTerminalCell", L"1",
          L"; 6579: kletka (stroka +99382, stolbets +99384) obyazana byt finalnoy (tablitsa +36+col < 0), granitsy stoka.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ogranichitel: ne chashche odnoy stroki zhurnala/loga na (sessiya, vid) za N s; podavlennye - v suppressed.\r\n" },
    };

    // -- [P71_TickDeadlineWrap] -- oborona: modulnye sravneniya srokov GameServer pri perehode GetTickCount cherez 2^32 --
    const IniKey kTickDeadlineWrap[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavit ni odnoy ploshchadki (stok: srok, vzvedyonnyy do obnuleniya takta 29.10.2026 09:51:50 UTC,\r\n"
          L";   ne nastupaet 49,7 sut).\r\n" },
        { L"FixSoulGuarder", L"1",
          L"; * Hranitel dushi (sub_48B4C0, 0x48B4FD): periodika raz v 15 s (monety dushi) - srok CUser+0x3F461 sravnivaetsya\r\n"
          L";   modulno ((int)(now - srok) < 0 = ne nastupil). Srok 0 = istyok (kak stok).\r\n" },
        { L"FixPartyConsent", L"1",
          L"; * Soglasie otryada (sub_46C090, 0x46C111): srok golosovaniya 15 s (this+0x122+0x41*i) - modulno.\r\n" },
        { L"FixTimer3F454", L"1",
          L"; * Shtraf lagerya RoseWar CUser+0x3F454 (DB 2460 -> sub_465FC0; TimerProcess sub_46A960; razryv/portal -> 2471):\r\n"
          L";   znachenie iz BD - DLITELNOST v sekundah; stok pisal 1000*s kak srok ot nulya aptayma i pri aptayme >= dlitelnosti\r\n"
          L";   snimal shtraf na pervom vhode (2471 Time 0). Teper: srok := now + 1000*s (0x466082), sravneniya 0x4660FD/0x46A9A8\r\n"
          L";   modulnye, na razryv (0x525CAC/0x5268BF) v BD uhodit OSTATOK, ne srok. Potolok 24,8 sut (2 147 483 s).\r\n" },
        { L"FixMapItemDelete", L"1",
          L"; * Predmety na zemle (MapItemDeleteProcess, 0x422650): udalenie cherez 5 min - takt padeniya sravnivaetsya s\r\n"
          L";   now - 300000 modulno. Takt 0 = udalit (kak stok).\r\n" },
        { L"MaxPenaltySec", L"604800",
          L"; * [p71fix] Predel znacheniya shtrafa lagerya iz BD, s (shtatnyy shtraf - kik golosovaniem - 1800 s; umolchanie 7 sut).\r\n"
          L";   Bolshe - STAROE ABSOLYUTNOE znachenie prezhney semantiki (kik do P71 pisal v BD takt/1000 = aptaym v sekundah)\r\n"
          L";   ili musor: pole := istyokshiy srok -> stok sam shlyot 2471 Time 0 i stiraet ego v BD; stroka PatchLog + Log_Operator.\r\n"
          L";   Potolok 2 147 483 (1000*s dolzhno pomeshchatsya v int). Kik golosovaniem (0x46C335) teper shlyot v BD 1800 s.\r\n" },
    };

    // -- [P73_EacBridge] -- antichit EAC (etap E1-V, 2026-10-16): most GameServer/Indun <-> saydkar AsdaEacServer --
    const IniKey kEacBridge[] =
    {
        { L"Enabled", L"0",
          L"; * 0 = ne stavitsya (stok). 1 = fonovaya nit - TCP-klient k saydkaru 127.0.0.1:Port (tolko lokalno, bez shifrovaniya):\r\n"
          L";   HELLO, PING 5 s, LOGIN na uspehe 4001/5058, LOGOUT na razryve, posle perepodklyucheniya - LOGIN vseh v igre.\r\n"
          L";   Saydkara net - igra ne blokiruetsya, odna stroka v PatchLog na smenu sostoyaniya, back-off do 5 s.\r\n" },
        { L"Mode", L"0",
          L"; * 0 = ZHURNAL: KICK ot saydkara pishetsya (ac.other 79), igrok NE kikaetsya; ploshchadka 0x526CEB ne stavitsya.\r\n"
          L";   1 = KICK vypolnyaetsya v niti karty na prohode CheckDisConnectUser (~1 s): sverka CUser+0x174 == UserIndex KICK,\r\n"
          L";   4101 (KickType) + ExceptionDisConnetUser. Kik NE idyot v schyotchik avtobloka P48.\r\n" },
        { L"Port", L"15702",
          L"; Port saydkara na 127.0.0.1 (kontrakt EAC par. 4).\r\n" },
        { L"KickType", L"6",
          L"; Tip 4101 pri kike (bayt prichiny klientu). * red. 3: 6 = u klienta notis 1106 'otklyuchyon za nechestnuyu igru'\r\n"
          L";   (tot zhe tekst, chto pri kike po kanalu 15901). Schyotchik avtobloka P48 etot kik NE schitaet pri lyubom CountTypes\r\n"
          L";   (kod 'ne zaschitan' 7); v PatchLog/Log_Game (P58) prichina pishetsya kak 'EAC(P73)'. 12 = notis 14000 pro HackShield.\r\n" },
        { L"ExemptOperators", L"1",
          L"; * 1 = operatora (GM-flag, sub_52ED50 == 1, kak P47/P69) ne kikat - tolko zhurnal ac.other 83.\r\n" },
        { L"KickPendingSec", L"30",
          L"; KICK, ne vypolnennyy za stolko sekund (igrok ne proshyol cherez CheckDisConnectUser), otbrasyvaetsya (ac.other 81).\r\n" },
        { L"PongTimeoutSec", L"20",
          L"; Ni odnogo kadra ot saydkara stolko sekund - soedinenie schitaetsya poteryannym (perepodklyuchenie). 0 = ne sledit.\r\n" },
        { L"QueueSize", L"4096",
          L"; Yomkost kolca sobytiy LOGIN/LOGOUT (64..65536). Perepolnenie - zhurnal ac.other 82 i perepodklyuchenie s rassylkoy.\r\n" },
        { L"ServerKind", L"0",
          L"; Vid servera v HELLO: 0 = avto (papka exe soderzhit 'Indun' -> 3, inache 2), 2 = Game, 3 = Indun.\r\n" },
        { L"GamePort", L"0",
          L"; Igrovoy port v HELLO: 0 = avto (ConfigSet\\ServerIPPORT.txt, 3-ya stroka).\r\n" },
        { L"SoulMateSessionAccount", L"1",
          L"; * red. 3: vhod soulmeytom (uchyotka A igraet personazhem uchyotki B): 1 = posle otveta BD 2145 slat REBIND na\r\n"
          L";   uchyotku sessii A (EAC-sessiya u A), 0 = ne slat (saydkar zhdyot EAC u B). Pri migratsii ini klyuch poluchaet\r\n"
          L";   tekushchee znachenie [P48_KickAutoBlock] SoulMateSessionAccount.\r\n" },
    };

    // -- [P77_MoveSyncStopPoint] -- 4009 v tochku servera pri molchalivoy ostanovke hoda (2026-10-22) --
    const IniKey kMoveSyncStopPoint[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok: MoveSyncProcess molcha snimaet igroka so steka hoda, klientu nichego -\r\n"
          L";   sleduyushchiy 4006 daet 'CharMove Hack Position'). 1 = posle stoka klientu shtatnyy 4009 v tochku servera.\r\n" },
        { L"BlockedTile", L"1",
          L"; Vetka 'don't move tile' (0x542B49): sleduyushchaya kletka neprohodima (sub_41A010).\r\n" },
        { L"PosOverMap", L"1",
          L"; Vetka 'iMovePos Max Over' (0x542B11): kletka za kraem karty.\r\n" },
        { L"PosBelowMap", L"1",
          L"; Vetka 'iMovePos - Value2' (0x542ACB): kletka <= 0.\r\n" },
        { L"MotionStartZero", L"1",
          L"; Vetka 'iMotionStartTime = 0' (0x542968): takt starta otrezka 0 pri sostoyanii hoda.\r\n" },
        { L"SendToSector", L"1",
          L"; 1 = 4009 i sosedyam po sektoru (sub_52E6D0, krome sebya), kak CharStop 'Revision Pos'; 0 = tolko sebe.\r\n" },
        { L"SkipHiddenOperators", L"1",
          L"; 1 = skrytomu operatoru (CUser+0x3BC3B == 300) sosedyam ne slat (sebe - vsegda), kak P74.\r\n" },
        { L"MinIntervalMs", L"0",
          L"; Pol na sessiyu mezhdu 4009 ot P77, ms (0 = net; povtora i tak net: 4009 - odin na kazhdoe snyatie so steka,\r\n"
          L";   vernut na stek mozhet tolko CharMove). 0..60000.\r\n" },
        { L"LogEvents", L"1",
          L"; Stroka v PatchLog na sobytie (ne chashche LogIntervalSec na sessiyu, s chislom propushchennyh).\r\n" },
        { L"LogIntervalSec", L"10",
          L"; 0..3600; 0 = kazhdoe sobytie.\r\n" },
    };

    // -- [P80_CrouchSpeedJumpRelay] -- hod vprisyadku x0.5 i pryzhok s bega sosedyam (2026-10-24) --
    const IniKey kCrouchSpeedJumpRelay[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok: skorost' ot statusa hoda ne zavisit; 4024 v hodu ne rassylaetsya).\r\n" },
        { L"CrouchHalve", L"1",
          L"; 1 = status hoda 4006 @+3 == CrouchStatus (CUser+0x54E4) delit skorost' na 2 stokovoy vetkoy (kak sostoyaniya\r\n"
          L";   112/186 skrytnosti; vmeste s nimi - odno delenie). 0 = skorost' kak stok.\r\n" },
        { L"CrouchStatus", L"4",
          L"; Status hoda prisyada (klient porta shlet 4 vmesto 2). Dopuskaetsya tolko 4 (inoe -> 4).\r\n" },
        { L"RelayWhileMoving", L"131",
          L"; Kod 4024 (100..400), kotoryy rassylaetsya sosedyam 4025 i v hodu (131 = pryzhok porta). Stok v hodu 4024 molcha\r\n"
          L";   otbrasyvaet. V hodu kod NE pishetsya v CUser+0x54E4 (status hoda ne portitsya). 0 = kak stok.\r\n"
          L";   Osobye kody servera 108/110/112/113/114/200/300/301 nelzya (rassylka vyklyuchaetsya).\r\n" },
    };

    // -- [P82_FuncCoolTimeExt] -- otkat funktsionalnyh predmetov s kodom >= 600 (2026-10-24) --
    const IniKey kFuncCoolTimeExt[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = mehanika ne stavitsya (stok: tablitsa otkata po kodu CUser+0x3BC41 - 600 kodov, sub_4F27F0 dlya koda >= 600\r\n"
          L";   VSEGDA 'otkat' - 5451 kod 8; mounty fable 600..637 ne primenyayutsya). 1 = svoya tablitsa: proverka 0x4F2820,\r\n"
          L";   registratsiya 0x4F2672, takt 0x543353 (5452), sbros 0x527399 - kak u stokovyh kodov.\r\n" },
        { L"SaveRestore", L"1",
          L"; 1 = otkaty >= 600 sohranyayutsya pri vyhode/portale v 2157 (dbo.ItemCoolTime, svobodnye mesta bloka iz 30) i\r\n"
          L";   vosstanavlivayutsya pri vhode (svoya tablitsa + telo 5465 klientu + gruppovoy otkat, kak stok). 0 = ne sohranyat.\r\n" },
        { L"RestoreGuard", L"1",
          L"; * Strazh vosstanovleniya (0x5290BE vhod / 0x52E23A portal): zapis s kodom >= 600 NE idyot v stokovuyu zapis CUser\r\n"
          L";   (stok pisal by za predel tablitsy - porcha pamyati). Stavitsya i pri Enabled=0. Vyklyuchat NELZYA, poka v\r\n"
          L";   dbo.ItemCoolTime est stroki >= 600 (ochistka - tools/p82_rollback_purge.sql).\r\n" },
        { L"LogEvents", L"1",
          L"; Stroki '[P82] FuncCoolTime REG/END/SAVE/LOAD/DROP' v kanal LogChannel (ryadom so stokovymi [REQUEST]/[USE]).\r\n" },
        { L"LogChannel", L"8",
          L"; Kanal stokovogo loga sub_569DF0 (8 = Log_Func).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 91 (vosstanovlenie: kod vne Function_Table) / 92 (sohranenie: net mesta v 2157) / 93 (tablitsa\r\n"
          L";   slota zapolnena) - ne chashche 1 raza za stolko sekund na (slot, vid). 0 = kazhdyy raz.\r\n" },
    };

    // -- [P87_Job4StartSkills] -- startovye navyki 4-y professii po podklassu (2026-10-26, ISPRAVLENIE defekta originala) --
    const IniKey kJob4StartSkills[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadka 0x4820C9 (sub_481CE0 LABEL_99): stroka ChangeJobAddSkillTable po PODKLASSU CUser+0x191 (4/15/26),\r\n"
          L";   esli ona est; net stroki (6/17/28) - stok. Zvanie 24/25/26 (sub_54A050 iz sub_48A8C0) vyzyvaetsya kak v stoke.\r\n"
          L";   0 = stok: personazh 4-y professii povtorno poluchaet stroku 3-y stupeni (3/14/25), svoi startovye navyki - nikogda.\r\n" },
    };

    // -- [P88_TitleEvents] -- sobytiya zvaniy 187-205 cherez stokovyy nakopitel sub_54A050 (2026-10-26, PORT) --
    const IniKey kTitleEvents[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ni odna ploshchadka ne stavitsya (stok: u 188..205 net ni odnogo vyzova nakopitelya - zvaniya nedostizhimy).\r\n"
          L";   Para - dannye FameInfo.txt (kol. 1 vklyucheno, kol. 3 porog, kol. 42 ochki, kol. 45 = 1 nakopitel) obeih papok.\r\n" },
        { L"WarKill", L"1",
          L"; 187/188/189 (25/100/1000 vragov): ubiystvo na karte MAP_TYPE 4 (voyna fraktsiy) - SendCharDead 0x4CBA1A, posle\r\n"
          L";   stokovogo nachisleniya ochkov otryadu (ubiytsa != zhertva, ubiytsa v igre).\r\n" },
        { L"SkillReset", L"1",
          L"; 190: sbros navykov predmetom (polnyy sub_4803A0, Property 0x23/0x36/0x37) - 0x4EFE7D.\r\n" },
        { L"SkillResetPartial", L"1",
          L"; 190: chastichnyy sbros (sub_480F20, Property 0x24) - 0x4EFEDD. 0 = schitat tolko polnyy.\r\n" },
        { L"WarehouseMax", L"1",
          L"; 191 (porog 1): posle rasshireniya sklada predmetom (Property 0x22) emkost CUser+0x1AE >= WarehouseMaxSlots - 0x4EFE24.\r\n" },
        { L"WarehouseMaxSlots", L"270",
          L"; Predel sklada (stok zazhimaet 270 = 0x10E @0x4EFD34). 30..270.\r\n" },
        { L"Craft", L"1",
          L"; 192..198: otvet BD remesla 2666 == 1 s produktom (status +74 == 1) - recvDBCraftEnter 0x53EF2A.\r\n" },
        { L"PotionCodes", L"20594-20603;20620-20623",
          L"; 192: kody izgotovlennyh zeliy (produkty retseptov 5..18 CraftRecipeInfo, vse stupeni). Format a-b;c.\r\n" },
        { L"HeroCodesFile", L"ConfigSet\\title_hero_p88.txt",
          L"; 193/194/195 (1/100/500): kody ItemGrade 3 'Geroy' (klientskiy item_list, tools/gen_title_grades_p88.py).\r\n" },
        { L"LegendCodesFile", L"ConfigSet\\title_legend_p88.txt",
          L"; 196/197/198 (1/50/100): kody ItemGrade 4 'Legenda'.\r\n" },
        { L"Dig", L"1",
          L"; 199/200/201: udachnaya nahodka kopki (5431 -> 5430 kod 1, dobycha legla) v zone - sub_546C00 0x546F8B.\r\n" },
        { L"ZonesRuins", L"1:352:436:20;1:153:286:20",
          L"; 199 'v ruinah': zony 'karta:x:z:radius' ili 'karta' (vsya karta) cherez ';'. Kletka - CUser+0x54E6/+0x54E8.\r\n"
          L";   Umolchanie - PREDLOZHENIE: Reka Dozhdya (1) vokrug NPC 82/83 'Drevnie ruiny', radius 20 kletok.\r\n" },
        { L"ZonesShipwreck", L"6:350:277:20",
          L"; 200 'na zatonuvshem korable': PREDLOZHENIE - Solnechnyy Bereg (6) vokrug NPC 129 'Oblomki korablya', radius 20.\r\n" },
        { L"ZonesOasis", L"13",
          L"; 201 'v oazise': PREDLOZHENIE - vsya karta Flabis (13) (podskazka samotsveta 1212 'oazis v pustyne Flabisa').\r\n" },
        { L"DigSowel", L"1",
          L"; 203: nahodka kopki - zhivoy kamen (IsSowelCode 0x532AE0).\r\n" },
        { L"PetLevel", L"1",
          L"; 202: povyshenie urovnya pitomtsa (stokovyy vyzov zvaniya 224 v sub_456D90 0x456F45 -> perehodnik, 224 kak stok).\r\n" },
        { L"Pickup", L"1",
          L"; 205: podbor koda iz TicketCodes (vetka 'zvaniya za podbor' CharItemPicking 0x4D5CB8), pribavka = kolichestvo.\r\n" },
        { L"TicketCodes", L"79382",
          L"; 205: kody yubileynyh biletov (79382 'Yubileynyy bilet').\r\n" },
        { L"Threshold190", L"10",
          L"; Porogi bez chisla v dannyh - PREDLOZHENIE, reshaet vladelets; pishutsya v FameInfo[id].+4 v pamyati. 1..1000000.\r\n"
          L";   190 - sbrosov navykov.\r\n" },
        { L"Threshold192", L"300", L"; 192 - izgotovlennyh zeliy.\r\n" },
        { L"Threshold199", L"100", L"; 199 - nahodok kopki v ruinah.\r\n" },
        { L"Threshold200", L"100", L"; 200 - nahodok kopki u korablya.\r\n" },
        { L"Threshold201", L"200", L"; 201 - nahodok kopki v oazise.\r\n" },
        { L"Threshold202", L"50",  L"; 202 - povysheniy urovnya pitomtsev.\r\n" },
        { L"Threshold203", L"100", L"; 203 - zhivyh kamney, vykopannyh lopatoy.\r\n" },
        { L"Threshold205", L"500", L"; 205 - podobrannyh yubileynyh biletov.\r\n" },
        { L"LogGrant", L"1",
          L"; Stroka Log_Operator i zhurnal ac.other 109 na kazhdoe zvanie, vydannoe sobytiem P88.\r\n" },
    };

    // -- [P89_Job4GateBranch] -- geyt startovyh navykov 4-y professii po kategorii vetki (2026-10-26, ISPRAVLENIE defekta originala) --
    const IniKey kJob4GateBranch[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadka 0x481D3F (dispetcher switch sub_481CE0, 17 b) -> tramplin. 0 = stok: geyt '0 ochkov v kategoriyah\r\n"
          L";   4-y professii' po param 10/11 (boets), 12/13 (luchnik), 14/15 (mag) - u luchnika/maga s rovno 60 ochkami kazhdoe\r\n"
          L";   ochko v svoyom dereve 11/12 povtorno vydayot startovuyu stroku (uroven 0, ochki potracheny).\r\n" },
        { L"Mode", L"1",
          L"; 1 = reshenie po kategorii svoey vetki: boets 10, luchnik 11, mag 12 (summa obychnyh derevev - kak v stoke).\r\n"
          L"; 0 = TOLKO ZHURNAL: povedenie stoka, raznoglasie - ac.other 112 i stroka Log_Operator.\r\n" },
        { L"SkipOwnedRow", L"1",
          L"; 1 = esli stoit P87 i VSE navyki stroki podklassa ChangeJobAddSkillTable u personazha uzhe est - povtor ne vydayotsya\r\n"
          L";   (ac.other 113): bez etogo povtor pri rovno 60 ochkah shlyot 5252/8114 i plodit zapisi spiska boya +359 (predel 100).\r\n"
          L"; 0 = povtor vydayotsya kak v stoke (urovni ne teryayutsya: geyt po vetke propuskaet tolko pri 0 ochkov svoey kategorii).\r\n" },
    };

    // -- [P91_ExpCapRate] -- potolok opyta za moba x reyt sobytiya (2026-10-26, reshenie vladeltsa, volna exprate) --
    const IniKey kExpCapRate[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadki 0x4CBC09 (odinochka) i 0x4C8012 (otryad), po 35 b -> tramplin. 0 = stok.\r\n" },
        { L"CapDivisor", L"9",
          L"; Delitel potolka: potolok = opyt_urovnya / CapDivisor (stok 9 = 11.1% urovnya za moba). Dopustimo 1..1000.\r\n" },
        { L"CapScalesWithRate", L"1",
          L"; 1 = potolok umnozhaetsya na max(1, fEvent + LuckyHours) - reyt sobytiya rabotaet i na nizkih urovnyah\r\n"
          L";     (lichnye % bafov/zeliy v potolok NE vhodyat). 0 = bez reyta: CapScalesWithRate=0 + CapDivisor=9 = stok.\r\n" },
        { L"SoloSite", L"1",
          L"; 1 = ploshchadka odinochki (Recv_BattleServerFromCharParamExp_1, paket NpcServer 8301).\r\n" },
        { L"PartySite", L"1",
          L"; 1 = ploshchadka otryada (sub_4C7C70, paket NpcServer 8306).\r\n" },
    };

    // -- [P92_HostileTargetGuard] -- vrednyy effekt navyka igroka - tolko na vrazhdebnogo igroka (2026-10-26, volna bowfx) --
    const IniKey kHostileTargetGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadki S1 0x486B3A, S2 0x48722A, S3 0x486E1A, S4 0x428453, S5 0x46FCCB -> tramplin. 0 = stok.\r\n" },
        { L"Mode", L"1",
          L"; 1 = vrednyy effekt na NE vrazhdebnogo igroka ne primenyaetsya (pravilo sub_556DB0(ispolnitel, zhertva, -1) -\r\n"
          L";   kak udar 4201: rezhim 0 - nelzya, duel - tolko sopernik, svobodnyy boy - ne svoi, voyna - ne svoya komanda).\r\n"
          L"; 0 = TOLKO ZHURNAL: povedenie stoka, ac.other 121/122 i stroka loga.\r\n" },
        { L"SplashSites", L"1",
          L"; 1 = S1 'Vzryv' 173 (navyk 788) i S2 ploshchadnoy prok hraniteley 248 - bili vseh igrokov vokrug bez proverki.\r\n" },
        { L"ReflectSite", L"1",
          L"; 1 = S3 otrazhenie hraniteley 220: stok sveryal po ID sostoyaniya 220 (+52 = 0) - pravilo perevyornuto\r\n"
          L";   (rezhim 0 - uron vsem, duel - vsem krome sopernika). Teper - pravilo udara, sebya ne bet.\r\n" },
        { L"NpcRecordSite", L"1",
          L"; 1 = S4 zapisi 8009 ot NpcServer 'tsel - igrok' (lovushki 110/181/185, effekty 77/119, pautina 745) sveryayutsya\r\n"
          L";   po istine GameServer (NpcServer sveryaet sam po zerkalu rezhima - strahovka ot rashozhdeniya).\r\n" },
        { L"HostileSkills", L"1004",
          L"; S5: navyki 5256, kotorye sveryayutsya kak VRAZHDEBNYE, hotya v SkillInfo +52 != 6. 1004 'Kleymo lda' (+52 = 5:\r\n"
          L";   'ne pozvolyaet protivniku stavit lovushki' - stok puskal na mirnyh, a v dueli - na vseh krome sopernika).\r\n"
          L";   Format a-b;c;d (0..1199). Pusto = ploshchadka S5 ne stavitsya.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 121/122/123 i stroka loga - ne chashche 1 raza za stolko sekund na (ispolnitel, ploshchadka);\r\n"
          L";   podavlennye - v repeat_suppressed. 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"0",
          L"; Kanal stokovogo loga sub_569DF0 (0 = Log_Game).\r\n" },
    };

    // -- [P94_SoulmateSelfEcho] -- soobshcheniya pary ne sebe i ne chuzhoy pare (2026-10-26, volna charpos) --
    const IniKey kSoulmateSelfEcho[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadki S1 0x494631 (3314->5110), S2 0x493D2B (3310->5112), S3 0x494A2F (3312->5227), S4 0x49407C (3320->5111)\r\n"
          L";   -> tramplin. 0 = stok.\r\n" },
        { L"Mode", L"1",
          L"; 1 = soobshchenie pary, prishedshee SAMOMU otpravitelyu (tot zhe slot, karta i kanal; u 5110 i uchyotka personazha) ili\r\n"
          L";   igroku DRUGOY pary (ForeignCheck), klientu ne otpravlyaetsya i Drug ne zapisyvaetsya (vyhod na epilog obrabotchika).\r\n"
          L"; 0 = TOLKO ZHURNAL: povedenie stoka, ac.other 130/131 i stroka loga.\r\n" },
        { L"ForeignCheck", L"1",
          L"; 1 = S1/S2/S4: u poluchatelya est para (Smidx > 0) i ona ne ta, chto v pakete - soobshchenie chuzhoy pary (vid 131).\r\n"
          L";   Smidx <= 0 (para eshchyo sozdayotsya) - kak v stoke. S3 (5227) Smidx sveryaet sam stok. 0 = ne sveryat.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 130/131/132 i stroka loga - ne chashche 1 raza za stolko sekund na (slot poluchatelya, ploshchadka);\r\n"
          L";   podavlennye - v repeat_suppressed. 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"0",
          L"; Kanal stokovogo loga sub_569DF0 (0 = Log_Game).\r\n" },
    };

    // -- [P95_ItemUseGuard] -- korobki 6096 (raskladka + uroven), buster 5468 i rashodnik 5028 (uroven) (2026-10-29, volna bugs6) --
    const IniKey kItemUseGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadki S1/S2 0x55AB2A (6096), S3 0x4F4BC5 (5468), S4 0x4D8F30 (5028) -> tramplin. 0 = stok.\r\n" },
        { L"Placement", L"1",
          L"; 1 = 6096: yacheyki-priyomniki pozitsiy korobki privodyatsya k pravilu SERVERA (konteyner po tablitse servera, stopka\r\n"
          L";   - v slot stopki, zanyataya/chuzhaya/povtornaya yacheyka - pervaya svobodnaya); svobodnoy net - 6097 kod 7.\r\n"
          L";   Zhurnal ac.other 140. 0 = stok (kody 7/11 pri raznyh tablitsah klienta i servera).\r\n" },
        { L"LevelGate", L"1",
          L"; 1 = min. uroven (+8 Item_Table) korobki 6096, bustera 5468 i rashodnika 5028 vyshe urovnya personazha - otkaz\r\n"
          L";   (vidy 141/142/143). 0 = stok (uroven ne proveryaetsya).\r\n" },
        { L"PackageLevelCode", L"3",
          L"; Kod otkaza 6097 po urovnyu korobki (2..11; klient pokazyvaet 99310+kod).\r\n" },
        { L"GachaLevelCode", L"3",
          L"; Kod otkaza 5469 po urovnyu bustera (1..8; 3 = 'Fail to use booster item').\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 140..144 i stroka loga - ne chashche 1 raza za stolko sekund na (slot, vid);\r\n"
          L";   podavlennye - v repeat_suppressed. 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal stokovogo loga sub_569DF0 (1 = Log_Item).\r\n" },
    };

    // -- [P81_ActionCodeGuard] -- strazh koda deystviya 4024 i chastoty zvaniya 'Dancer' (2026-10-24) --
    const IniKey kActionCodeGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok: CharEMotionSync prinimaet lyuboy kod 100..400 - 300/301 delayut igroka 'skrytym\r\n"
          L";   operatorom' u sosedey, 200 - 'myortvym' dlya mobov; flud 112/113 nabivaet zvanie 'Dancer').\r\n" },
        { L"Mode", L"1",
          L"; 1 = kod vne AllowedCodes ot NE-operatora otbrasyvaetsya (bez zapisi statusa CUser+0x54E4 i bez 4025 sosedyam),\r\n"
          L";   'Dancer' chashche DanceCountMinSec ne zaschityvaetsya; 0 = tolko zhurnal (povedenie stoka).\r\n" },
        { L"AllowedCodes", L"100-110;112-117;122;124;127;128;131;400",
          L"; Zakonnye kody 4024 chestnogo klienta (original 35 mest + port: 131 = pryzhok). Format: a-b;c;d. Kody vne 100..400\r\n"
          L";   stok otbrasyvaet sam (0 - tozhe). Operator (GM-flag, sub_52ED50 == 1) - kak stok pri lyubom kode.\r\n"
          L";   200/300/301 ne vnosit: eto podmena 'myortv' / skrytiya operatora (skrytie - tolko paketom 6005).\r\n" },
        { L"DanceCountMinSec", L"12",
          L"; Zvanie 'Dancer' (sub_54A050 indeks 13, kody 112/113) - ne chashche 1 raza za stolko sekund na sessiyu (klip tantsa\r\n"
          L";   13.33 s, zapas 1.3 s na zaderzhku seti; animatsiya sosedyam idyot kak stok). 0 = kak stok (ploshchadka ne stavitsya). 0..3600.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 88 (stoya) / 89 (v hodu) / 90 (tanets) i stroka loga - ne chashche 1 raza za stolko sekund\r\n"
          L";   na (sessiya, vid); podavlennye - v repeat_suppressed. 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"0",
          L"; Kanal stokovogo loga sub_569DF0 (0 = Log_Game).\r\n" },
    };

    // -- [P76_SowelSlotBounds] -- polya paketov zhivyh kamney 5022/5024/5031 (2026-10-21) --
    const IniKey kSowelSlotBounds[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok). 1 = polya tela 5022/5024/5031 sveryayutsya s pravilami chestnogo klienta:\r\n"
          L";   5022 - konteyner predmeta 1/3, gnezdo 0..3; 5024 - to zhe + konteyner kamnya 2; 5031 - konteynery 2/2.\r\n" },
        { L"Mode", L"1",
          L"; 1 = otkaz shtatnoy vetkoy (5023/5025/5032 kod 0) do lyuboy zapisi; 0 = tolko zhurnal (kak stok).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 85..87 i stroka loga - ne chashche 1 raza za stolko sekund na (sessiya, vid). 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal stokovogo loga sub_569DF0 (1 = Log_Item).\r\n" },
    };

    // -- [P75_LevelUpPotion] -- zelye povysheniya urovnya 558 (2026-10-19): do TargetLevel vychisleniem opyta --
    const IniKey kLevelUpPotion[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok: predmet 558 - zaglushka 'SpecialItem_558', baff '+60 protsentov OZ na 30 min').\r\n"
          L";   1 = ExpTable[TargetLevel] minus tekushchiy opyt nachislyaetsya SHTATNOY Recv_BattleServerFromCharParamExp_1\r\n"
          L";   (kak nagrada zadaniy: a5=1) po urovnyu za vyzov, BEZ mnozhiteley (sobytiya, zelya opyta). Itog - rovno nachalo urovnya.\r\n"
          L";   'Odin raz na personazha' - gate urovnya shaga 1 (posle uspeha uroven >= 70, uroven ne ubyvaet); zamok 'v puti' (nizhe).\r\n" },
        { L"ItemCode", L"558",
          L"; Kod funktsionalnogo predmeta (Function_Table / special_itemlist).\r\n" },
        { L"LockTimeoutMs", L"15000",
          L"; * Zamok 'zelye v puti' na personazha: stavitsya pri ukhode 2140 v BD (0x4EF02E), snimaetsya v otvete BD (shag 2),\r\n"
          L";   na vyhode sessii i po etomu taym-autu (1000..600000 ms, kak P63 LockTimeoutMs). Vtoroe zelye pri zamke - otkaz kod 0.\r\n" },
        { L"ReleaseOnExit", L"1",
          L"; * 1 = zamok snimaetsya na vyhode (ClearUserMemory 0x527374: obshchaya tochka P63 SessionClear, bez P63 - svoya\r\n"
          L";   ploshchadka). 0 = tolko taym-aut.\r\n" },
        { L"TargetLevel", L"70",
          L"; Uroven, do kotorogo vedyot zelye (klient: 'mozhno doyti do 70 urovnya'). Uroven >= TargetLevel - otkaz 5451 kod 0\r\n"
          L";   (plashka 12837), predmet tsel. Nuzhny potolok P29 >= TargetLevel (inache otkaz) i stroka ExpTable.\r\n" },
        { L"RequireCategory", L"6",
          L"; Kategoriya zapisi Function_Table (+8), pri kotoroy zelye primenyaetsya (6 - kak v stoke). Inaya - otkaz: u chasti\r\n"
          L";   kategoriy shag 2 stoka otkazyvaet POSLE spisaniya v BD. Baff zapisi (+37 = 2) DLL obnulyaet v PAMYATI, fayl ne pravitsya.\r\n" },
        { L"SingleLevelUpPacket", L"1",
          L"; * 1 = paket 4036 'novyy uroven' sebe i sektoru - ODIN raz, na poslednem urovne (stok shlyot na kazhdom: 58 zvukov,\r\n"
          L";   effektov i bannerov podryad). Telo - stokovoe (absolyutnye uroven/opyt/ochki navykov/staty). 0 = kak stok.\r\n" },
        { L"SuppressSoulJar", L"1",
          L"; * 1 = kuvshin dushi (Send_SoulJarProcessBarExp, 30 protsentov pribavki) ot zelya NE napolnyaetsya. 0 = kak stok.\r\n" },
        { L"FuncLog", L"1",
          L"; Stroki '[P75] LevelUpPotion ...' v Log\\Log_Func\\FuncLog (ryadom so stokovymi [REQUEST]/[USE]).\r\n" },
        { L"LogEvents", L"1",
          L"; Stroki PatchLog ob otkazah shaga 1 (pervye 2000, dalee kazhdaya 1000-ya); nachisleniya - vsegda.\r\n" },
    };

    // -- [P74_HpSectorSync] -- sinhronizatsiya boya F3 (2026-10-17): snimok HP 4058 sosedyam po sektoru --
    const IniKey kHpSectorSync[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya (stok: HP chuzhogo igroka sosedi vidyat tolko posle zelya/navyka - tipy 2/4).\r\n"
          L";   1 = paket 4058 (snimok HP) uhodit sebe KAK STOK i tot zhe paket - sosedyam po sektoru 3x3 krome sebya\r\n"
          L";   (sub_52E6D0). Tsifru nad igrokom klient risuet dlya tipov 1/4/6 - sosedyam oni idut tolko tihoy kopiey (InstantToSector).\r\n" },
        { L"DamageToSector", L"1",
          L"; * Uron po igroku (sub_43C690 @0x43C854 pri a5=1: navyki, uron po vremeni, otrazhenie) - tip 0. Obychnye udary mobov\r\n"
          L";   i obychnaya ataka PvP idut s a5=0 (4058 ne shlyotsya dazhe sebe) - zdes NE pokryty.\r\n" },
        { L"RegenToSector", L"1",
          L"; * Izmeneniya vo vremeni (SetCurrentHpTimeValue @0x43CE82, vetka 'ne 2/4'): estestvennyy regen raz v 5 s,\r\n"
          L";   lechenie po vremeni, yad, vampirizm - tipy iz TimeTypeMask.\r\n" },
        { L"InstantToSector", L"1",
          L"; * red. 2 (Version 46): mgnovennoe lechenie tipov 1 (predmet: CharSpendItemUse, sub_4F3D90) i 6 (50 protsentov v zone,\r\n"
          L";   sub_46AB50) - sosedyam KOPIYA tela s tipom 0 i navykom -1 (tihaya zapis bez tsifry); sebe - original kak stok.\r\n"
          L";   0 = tipy 1/6 sosedyam ne shlyutsya. Rabotaet pri RegenToSector=1.\r\n" },
        { L"RegenMinIntervalMs", L"0",
          L"; Prorezhivanie RegenToSector: sosedyam ne chashche, chem raz v N ms na igroka (0 = kazhdoe - umolchanie red. 2;\r\n"
          L";   sobytiy malo: regen raz v 5 s, lechenie/yad po vremeni ~raz v 3 s). Pri >0 vybroshennoe znachenie ne doshlyotsya\r\n"
          L";   do sleduyushchego sobytiya; HP 0 i HP = maksimum uhodyat VSEGDA. Tipy 1/6 ne prorezhivayutsya. Sebe - vsegda (kak stok).\r\n" },
        { L"DamageMinIntervalMs", L"0",
          L"; Prorezhivanie DamageToSector, ms na igroka (0 = kazhdyy udar). HP 0 i maksimum - vsegda.\r\n" },
        { L"TimeTypeMask", L"41",
          L"; Bitovaya maska tihih tipov dlya RegenToSector: bit N = tip N. 41 = tipy 0/3/5. Bity 1/4/6 (klient risuet tsifru;\r\n"
          L";   1/6 idut klyuchom InstantToSector) i 2/4 (stok sam shlyot sektoru) sbrasyvayutsya VSEGDA.\r\n" },
        { L"SkipHiddenOperators", L"1",
          L"; * 1 = HP skrytogo operatora (CUser+0x3BC3B = 300 i operatorskiy indeks, kak P41) sosedyam ne shlyotsya\r\n"
          L";   (vse tipy, vklyuchaya 1/6). Stokovaya rassylka tipov 2/4 (sub_52E630) - vne ohvata P74.\r\n" },
        { L"LogEvents", L"1",
          L"; Stroki PatchLog o pervyh 3 rassylkah kazhdoy ploshchadki i dalee kazhdoy 100000-y.\r\n" },
    };

    // -- [P72_HiddenWipeDisarm] -- BEZOPASNOST: zakladka CharItemKeeping(11) stokovogo GameServer (taymer zatiraniya 550 slotov) --
    const IniKey kHiddenWipeDisarm[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. NE VYKLYUCHAT: v stokovom GameServer (stok = zhivoy = Indun) est ZAKLADKA - kodovaya kombinatsiya\r\n"
          L";   iz 5 shtatnyh deystviy s predmetami (5000/5006/5028/5288/5008, tochnye yacheyki i kolichestva, za <= 60 s) vzvodit\r\n"
          L";   5 flagov potoka karty (CThread+0x51AC..0x51B0), posle chego RunProcess 10024 raz v 10-110 min zatiraet bazovyy blok\r\n"
          L";   personazha (CUser+0x174, 0x45 b: charId/imya/uroven/opyt) u VSEH 550 slotov protsessa: onlayn-igroki teryayut\r\n"
          L";   sohranenie, svobodnye sloty 'zanyaty' do restarta. Razbor: Reports/anticheat/re_itemkeeping_hidden.md\r\n" },
        { L"DisarmTimer", L"1",
          L"; * Mera 1 (osnovnaya): RunProcess 10024 @0x4C2745 `jne 0x4C2869` -> `jmp 0x4C2869` - vetka sbrosa flagov VSEGDA,\r\n"
          L";   memset po 550 slotam @0x4C2839 nedostizhim. Stavitsya i v GameServer, i v Indun (odin obraz).\r\n" },
        { L"CatchArming", L"1",
          L"; * Mera 2: shag 5 (CharItemKeeping @0x50A651) -> tramplin: flagi i takt vzvedeniya obnulyayutsya DO zapisi,\r\n"
          L";   sobytie - v zhurnal antichita ac.other 76 i Log_Operator ('P72 HiddenWipeDisarm: ...').\r\n" },
        { L"Response", L"0",
          L"; * Chto vidit igrok, nabravshiy kombinatsiyu (tolko pri CatchArming=1):\r\n"
          L";   0 = MOLCHA: obychnaya sdacha 8 predmetov na sklad (shtatnyy hvost 0x50A6EB -> DB 2029), bez kvitantsii-'otkaza'\r\n"
          L";       5009 kod 5 i bez stroki kategorii 26 - zloumyshlennik ne uznayot, chto zamechen.\r\n"
          L";   1 = KAK STOK: stroka 'CharItemKeeping(11)' kat. 26 + 5009 kod 5 (0x50A6B6); pri P18 FixKeepingDupe=1 - return\r\n"
          L";       bez DB 2029, pri 0 - stokovyy defekt dyupa D4.\r\n" },
        { L"AutoBlock", L"0",
          L"; Nabrat kombinatsiyu sluchayno prakticheski nevozmozhno (tochnye yacheyki 0/59, 48, 50, 47, 45; kolichestva 3, 9, 8;\r\n"
          L";   zapreshchayushchee sostoyanie; vtoroy igrok dlya obmena; poryadok za <= 60 s) - eto priznak umysla.\r\n"
          L";   1 = blok uchyotki SESSII shtatnym 2271/UPHackBlock (kak P48/P69, obshchaya tochka P48_SendHackBlock) na BlockHours.\r\n"
          L";   0 (umolchanie) = tolko zhurnal; sanktsiya - reshenie vladeltsa po stroke ac.other 76.\r\n" },
        { L"BlockHours", L"-1",
          L"; Chasy bloka pri AutoBlock=1; -1 = bessrochno (30 let UPHackBlock).\r\n" },
        { L"ExemptOperators", L"1",
          L"; * 1 = operatora (GM-flag, sub_52ED50 == 1, kak P47/P69) NE blokirovat (zhurnal i Log_Operator pishutsya vsegda).\r\n" },
    };

    // -- [P69_IntegrityAutoBlock] -- antichit autoban: stupenchatyy avtoblok za narusheniya tselostnosti paketov --
    const IniKey kIntegrityAutoBlock[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = schyota net (narusheniya - tolko v zhurnale istochnika P55/P61, kak ran'she).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL: stupen' dostignuta -> stroka ac.other 62 'byl by blok' + PatchLog + Log_Operator,\r\n"
          L";   2271 ne uhodit (do alfy). 1 = BLOK: shtatnyy DB-zapros 2271 -> EXEC UPHackBlock UserIndex, chasy\r\n"
          L";   (kak GM-blok 6094 i avtoblok P48). Schyotchiki Mode=0 i Mode=1 - raznye sektsii fayla ([Mode0]/[Mode1]).\r\n" },
        { L"Stage1Count", L"20",
          L"; * Stupeni (reshenie vladeltsa 14.10): StageNCount narusheniy uchyotki VSEGO (bez okna) -> blok na StageNHours\r\n"
          L";   chasov (-1 = bessrochno, 30 let UPHackBlock). Kazhdaya stupen' srabatyvaet odin raz. Porogi strogo po\r\n"
          L";   vozrastaniyu, srok ne 0; inache berutsya umolchaniya 20/24, 50/720, 51/-1.\r\n" },
        { L"Stage1Hours", L"24",  nullptr },
        { L"Stage2Count", L"50",  nullptr },
        { L"Stage2Hours", L"720", nullptr },
        { L"Stage3Count", L"51",  nullptr },
        { L"Stage3Hours", L"-1",  nullptr },
        { L"CountP55Kinds", L"1,2,4",
          L"; Vidy P55 (ac.packet_validator), kotorye schitayutsya: 1 kadr koroche min, 2 dlinnee max, 4 koroche zagolovka.\r\n"
          L";   3 (chastota klassa) NE schitat: eto temp, a ne porcha kadra. Schyot - po strokam zhurnala P55 (ogranichitel\r\n"
          L";   JournalIntervalSec na sessiyu i vid), podavlennye povtory ne pribavlyayut.\r\n" },
        { L"CountChannelKinds", L"56,57,58,59",
          L"; Vidy narusheniya kanala P61 (ac.other), prislannye KLIENTOM: 56 teg GCM, 57 povtor nomera, 58 musor do\r\n"
          L";   rukopozhatiya, 59 dlina kadra. 61 (sboy dostavki: Send/ochered/pamyat') i 0 (sboy servera) ne schitayutsya NIKOGDA.\r\n" },
        { L"ExemptOperators", L"1",
          L"; * Operatory (GM-flag, sub_52ED50 == 1, kak geyt P47) ne schitayutsya i ne blokiruyutsya. NE vyklyuchat.\r\n" },
        { L"SoulMateSessionAccount", L"1",
          L"; * Vhod soulmeytom (SoulState 2): schyot na uchyotku SESSII (iMateUserIndex CUser+0x182C6), kak P48.\r\n" },
        { L"KickOnBlock", L"1",
          L"; Mode=1: igrok, ostavshiysya v igre posle bloka (istochnik P55 - validator ne rvyot soedinenie), vyvoditsya\r\n"
          L";   shtatno: schyotchik Hack Packet > 5 -> kik tip 3 (CheckDisConnectUser). Etot kik P48 ne schitaet.\r\n" },
        { L"LogCounted", L"1",
          L"; Stroka PatchLog na kazhdoe zaschitannoe narushenie (stupeni pishutsya vsegda).\r\n" },
        { L"CounterFile", L"..\\GameServer\\ConfigSet\\ac_integrity_counter.ini",
          L"; Fayl schyotchika (otnositelno papki exe; obshchiy dlya GameServer i Indun). Uchyotka -> 'schyot,stupen,pervoe,poslednee'.\r\n"
          L";   Snyat blok: SQL/ac0_unblock_user.sql; obnulit schyot - udalit stroku uchyotki pri ostanovlennoy stoyke.\r\n" },
    };

    // -- [P68_CharNameGuard] -- antichit A13: imya personazha 6138/6140 + 2453 imya v pamyati tolko pri uspehe BD --
    const IniKey kCharNameGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 0 = ne stavitsya. Ploshchadki `call memcpy` kopii imeni v telo BD: 6138 0x55D8CE (posle VSEH stokovyh proverok,\r\n"
          L";   pered DB 2450 UPNickCheck), 6140 0x55DC6C (pered DB 2452 UPCharRename), 2453 0x55DFDF (imya v CUser+0x178).\r\n"
          L";   Stavitsya tolko pri sovpadenii baytov (stok = zhivoy GameServer/Indun).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (ac.other vidy 53/54 + Log_Item 'P68 ...'), nichego ne otklonyaetsya.\r\n"
          L";   1 = otkaz: 6138 -> otvet 6139 flag 3 (kak 'LewdWord' UPNickCheck; klient 109404 'Imya uzhe zanyato'),\r\n"
          L";   2450 ne uhodit; 6140 -> STOKOVYY hvost 6141 s kodom 0 (kak otkaz BD; klient 109411).\r\n" },
        { L"NameCharset", L"0",
          L"; Dopustimye simvoly imeni (pravila klienta-originala validateStringByLocale@0x956090):\r\n"
          L";   0 = A-Z a-z 0-9 (etalon isValidNameCharAscii@0x9570A0; reshenie vladeltsa 08.10 - port asda.Text.NameLocale 0);\r\n"
          L";   1 = + lokali 7/8 originala (bayty cp1251/cp1256 >= 0xC0, 0xA8, 0xB8) + kodeki porta (marker 0x98 + cp1256;\r\n"
          L";       strogiy UTF-8 kirillitsy/arabitsy). Stavit 1 VMESTE s asda.Text.NameLocale 1 v portu i Charset=1 v SQL A13.\r\n"
          L";   Vsegda: nul v pole 20 b (dlina <= 19), net bayt 0x01..0x1F i 0x7F, ne pusto.\r\n" },
        { L"Check6138", L"1",
          L"; 6138 RecvClient_CharNameCheck: pravilo imeni (vid 53).\r\n" },
        { L"Check6140", L"1",
          L"; 6140 RecvClient_CharNameChange: pravilo imeni (vid 53) i Require6138Before6140 (vid 54).\r\n" },
        { L"Require6138Before6140", L"1",
          L"; 6140 tolko s imenem POSLEDNEGO 6138 etoy sessii (chestnyy klient shlyot tot zhe bufer; inache obhod proverki\r\n"
          L";   zanyatosti i LewdWordList - ih delaet tolko UPNickCheck). Vid 54.\r\n" },
        { L"KeepNameOnDbFail", L"1",
          L"; * Ispravlenie defekta STOKA (ne zavisit ot Mode): otvet BD 2453 kopiroval novoe imya v CUser+0x178 pri LYUBOM\r\n"
          L";   flage (0 oshibka, 2/3 klan, 4 aukcion) - v BD imya prezhnee, a v pamyati servera novoe do perezahoda.\r\n"
          L";   1 = kopirovat tolko pri flage 1 (kak stok snimaet predmet). 0 = povedenie stoka.\r\n" },
        { L"OperatorExempt", L"1",
          L"; * 1 = operator (GM-flag CUser+0x40B9F == 1, tot zhe priznak, chto u P47: sub_52ED50; stavit DBManager\r\n"
          L";   iz UPCharGMInfo / Joy1.dbo.CharGmInfo pri vhode) - pravilo imeni (vid 53) i sverka s poslednim 6138 (vid 54)\r\n"
          L";   NE primenyayutsya: ni zhurnala, ni otkaza (reshenie vladeltsa 13.10). KeepNameOnDbFail ot klyucha ne zavisit.\r\n"
          L";   0 = proveryat i operatorov.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ogranichitel: ne chashche odnoy stroki zhurnala/loga na (sessiya, vid) za N s; podavlennye - v suppressed.\r\n" },
    };

    // -- [P53_AcJournal] -- antichit acdb: zhurnal v BD joylog1.ac --
    const IniKey kAcJournal[] =
    {
        { L"Enabled", L"1",
          L"; * Glavnyy vyklyuchatel zhurnala. 0 = ni ocheredi, ni potoka, ni ploshchadok.\r\n" },
        { L"StockSites", L"1",
          L"; * Zerkalo shtatnyh proverok servera v zhurnal (11 vyzovov: CharMove Hack Position,\r\n"
          L";   HackCheck pinga, Secret Error, MD5 paketa, podpis 5450, pokupka zapreshchyonnogo,\r\n"
          L";   neizvestnyy opkod). Fayl-logi servera pishutsya kak ran'she. 0 = tolko P47/P48.\r\n" },
        { L"KickJournalWhenP48Off", L"1",
          L"; Pri P48 Enabled=0 vsyo ravno stavit perehvat Send_DisConnectType tolko dlya zhurnala kikov.\r\n" },
        { L"ConnectionString", L"",
          L"; Stroka podklyucheniya ODBC. Pusto = DSN/login/parol iz DbConfigFile (kak u DBManager).\r\n" },
        { L"DbConfigFile", L"..\\DBManager\\DBMng.ini",
          L"; Otkuda vzyat GAMEDNS/GAMEUSER/GAMEPASS (otnositelno papki exe).\r\n" },
        { L"DbConfigSection", L"DB_DNS0_0", nullptr },
        { L"Database", L"joylog1",
          L"; Baza zhurnala (shema ac, SQL/acdb_01_migrate.sql).\r\n" },
        { L"FlushIntervalMs", L"2000",
          L"; Raz v skolko ms fonovyy potok pishet paket (ili ranshe, kogda nakopilos BatchMax/2).\r\n" },
        { L"BatchMax", L"500", L"; Sobytiy v odnom pakete INSERT (1..1000).\r\n" },
        { L"QueueCapacity", L"16384",
          L"; Yomkost ocheredi (stepen 2). Perepolnenie - sobytie otbrasyvaetsya i schitaetsya,\r\n"
          L";   igrovoy potok NIKOGDA ne zhdyot.\r\n" },
        { L"PerSessionPerMinute", L"60",
          L"; Ogranichitel strok na sessiyu v minutu (hod/boy, podpis/povtory, prochee). 0 = bez.\r\n" },
        { L"ReconnectSec", L"30", L"; Pauza mezhdu popytkami podklyucheniya k baze.\r\n" },
        { L"FileFallback", L"1",
          L"; Baza nedostupna - paket pishetsya v Log\\Log_AcJournal\\AcJournal_<data>.sql (mozhno\r\n"
          L";   vypolnit potom: sqlcmd -i). 0 = otbrasyvat.\r\n" },
        // ★ fix2 (СРЕДН-4 integ3): предел файлового журнала (флуд при недоступной базе)
        { L"FileRowsPerMinute", L"3000",
          L"; Ne bolshe N sobytiy v fayl v minutu na process (ostalnye - v schyotchik + svodka 'propushcheno K'). 0 = bez.\r\n" },
        { L"MaxFileMB", L"256",
          L"; Potolok sutochnogo fayla AcJournal_<data>.sql, MB: dalshe sobytiya dnya v fayl ne pishutsya. 0 = bez.\r\n" },
        { L"FileDir", L"",
          L"; Papka faylovogo zhurnala. Pusto = <exe>\\Log\\Log_AcJournal; otnositelnyy put - ot papki exe.\r\n" },
        { L"PurgeDays", L"90",
          L"; Raz v sutki udalyat zapisi starshe N sutok (ac.UP_AC_JournalPurge). 0 = ne chistit.\r\n" },
        { L"ServerName", L"", L"; Imya istochnika v zhurnale. Pusto = imya papki exe.\r\n" },
        { L"NameCodePage", L"1251", L"; Kodovaya stranitsa imyon personazhey v pamyati servera.\r\n" },
        { L"LoginTimeoutSec", L"5", nullptr },
        { L"QueryTimeoutSec", L"15", nullptr },
    };

    // -- [P55_PacketValidator] -- antichit V4: obshchiy validator paketov (dlina kadra + chastota) --
    const IniKey kPacketValidator[] =
    {
        { L"Enabled", L"1",
          L"; * Glavnyy vyklyuchatel. Trebuet [P47_IdentityOperatorGate] Enabled=1 (stab geyta 0x42AB4F).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (umolchanie): obrabotchik vyzyvaetsya kak v stoke, narushenie - v zhurnal.\r\n"
          L";   1 = OTKAZ: obrabotchik ne vyzyvaetsya; s HackPacketOnRefuse=1 eshchyo +1 k schyotchiku\r\n"
          L";   Hack Packet (shtatnyy kik pri > 5). Vklyuchat tolko posle nedeli nablyudeniya zhurnala.\r\n" },
        { L"CheckLength", L"1",
          L"; Proverka razmera kadra po opkodu: [min, min+19] (padding klienta); 0 = vyklyuchit.\r\n" },
        { L"CheckRate", L"1",
          L"; Limit chastoty paketov po klassu opkoda (token-bucket na sessiyu); 0 = vyklyuchit.\r\n" },
        { L"HackPacketOnRefuse", L"1",
          L"; Pri Mode=1: 1 = otkaz schitaetsya v shtatnyy Hack Packet (kik > 5), 0 = tihiy sbros.\r\n" },
        { L"LogHits", L"1",
          L"; Stroki narusheniy v PatchLog (pod tem zhe ogranichitelem, chto i zhurnal).\r\n" },
        { L"JournalIntervalSec", L"60",
          L"; Ogranichitel: odna stroka zhurnala na (sessiya, vid narusheniya) za stolko sekund;\r\n"
          L";   podavlennye schitayutsya (repeat_suppressed). 0 = bez ogranichitelya.\r\n" },
        { L"RateOtherPerSec",  L"60",  L"; Klass 'prochee': popolnenie, paketov/s (0 = bez limita) i zapas (burst).\r\n" },
        { L"RateOtherBurst",   L"120", nullptr },
        { L"RateMovePerSec",   L"60",  L"; Klass 'dvizhenie' (4006/4008/4010/4032/4034...).\r\n" },
        { L"RateMoveBurst",    L"120", nullptr },
        { L"RateCombatPerSec", L"40",  L"; Klass 'boy/navyki' (ataka, navyki, tseli).\r\n" },
        { L"RateCombatBurst",  L"80",  nullptr },
        { L"RateChatPerSec",   L"10",  L"; Klass 'chat' (5084/5086/5088/5105/4120/6316/6560/6718).\r\n" },
        { L"RateChatBurst",    L"20",  nullptr },
        { L"RateItemPerSec",   L"30",  L"; Klass 'predmety/torgovlya' (inventar, magaziny, obmen, auktsion, gacha, zatochka).\r\n" },
        { L"RateItemBurst",    L"60",  nullptr },
        { L"RateDbPerSec",     L"10",  L"; Klass 'tyazhyolye-BD' (logon 4001/5058, sklad, pokupka 5020/5070, auktsion 99xx, pochta).\r\n" },
        { L"RateDbBurst",      L"20",  nullptr },
        { L"RateGmPerSec",     L"30",  L"; Klass 'GM' (operatorskie komandy 60xx, 4209).\r\n" },
        { L"RateGmBurst",      L"60",  nullptr },
    };

    // -- [P64_StatePreamble] -- antichit A7 (L4/A8): obshchaya preambula sostoyaniya personazha --
    const IniKey kStatePreamble[] =
    {
        { L"Enabled", L"1",
          L"; * Glavnyy vyklyuchatel. Trebuet [P47_IdentityOperatorGate] Enabled=1 (stab geyta 0x42AB4F).\r\n" },
        { L"Mode", L"0",
          L"; * 0 = TOLKO ZHURNAL (umolchanie): obrabotchik vyzyvaetsya kak v stoke, narushenie - v zhurnal.\r\n"
          L";   1 = TIHIY OTKAZ: obrabotchik ne vyzyvaetsya (rovno kak stok molcha propuskaet obrabotchik pod\r\n"
          L";   geytom 'dusha'); nikakih novyh paketov/kodov. Vklyuchat tolko posle nedeli nablyudeniya zhurnala.\r\n" },
        { L"Opcodes", L"",
          L"; Obshchiy spisok opkodov cherez ';'. PUSTO (umolchanie) = ob'edinenie spiskov semey nizhe.\r\n"
          L";   Zadan = proveryayutsya TOLKO eti opkody (semya - iz spiskov nizhe, chuzhoy opkod = semya 'prochee').\r\n" },
        { L"RespectStockGates", L"1",
          L"; 1 = u opkodov, gde 'zanyat/myortv' uzhe sprashivaet sam obrabotchik (sub_52BFF0 vnutri: 6162, 6502,\r\n"
          L";   6506, 4201, 4203, 6158, 6165, 6176), eti dva zapreta NE dubliruyutsya - inache v Mode=1 tihiy otkaz\r\n"
          L";   podmenil by shtatnyy otvet stoka (4202 kod 0 / 6001 kod N / 6166 kod 117). 0 = proveryat vsyo.\r\n" },
        { L"OpcodesEconomy", L"6096;6098;6549;6551;6553;5433;6555;6586;6140;6162;6502;6506",
          L"; Semya 'ekonomika/progress': nabor 6096, obmen u NPC 6098, izvlechenie/blagoslovenie/perenos optsii\r\n"
          L";   6549/6551/6553, pomoshchnik 5433, premium-summa 6555, znak zodiaka 6586, smena imeni 6140,\r\n"
          L";   magazin voyny 6162, razbor 6502, sbros shell-apgreyda 6506.\r\n" },
        { L"MaskEconomy", L"dead;busy;ingame",
          L"; Maska zapretov semi. Tokeny cherez ';': dead (CUser+0x4F), busy (= exchange;auction;store;fishing -\r\n"
          L";   kody 2..5 sub_52BFF0), exchange (+0x145), auction (+0x15F), store (+0x14D), fishing (+0x3F6B4),\r\n"
          L";   soul (+0x182D3 == 1), possess (+0x182B9 > 0 && +0x182D3 == 2), ingame (+0x190 == 0 = narushenie), none.\r\n"
          L";   * soul/possess po umolchaniyu VYKLYUCHENY vo vseh semyah: stok eti opkody ne geytit, i chestnyy port\r\n"
          L";   shlyot ih v oboih sostoyaniyah (tablitsa AsdaSoul/AsdaPossess porta povtoryaet dispetcher).\r\n" },
        { L"OpcodesPets", L"6100;6102;6108;6110;6112;6114;6116;6118;6121;6148",
          L"; Semya 'pitomtsy': vyzov 6100, inkubator 6102, sostoyanie 6108, osvobozhdenie 6110, ob'edinenie 6112,\r\n"
          L";   kletka 6114/6116, imya 6118, schyotchik 6121, maks. uroven 6148.\r\n" },
        { L"MaskPets", L"dead;busy;ingame", nullptr },
        { L"OpcodesCombat", L"4201;4203;6158",
          L"; Semya 'boy': PvP-udar 4201/4203, navyk strazha 6158 (B-03: net geyta 'dusha'). 'zanyat/myortv' u nih\r\n"
          L";   sprashivaet stok (RespectStockGates), tak chto po umolchaniyu deystvuet tolko 'ingame'.\r\n" },
        { L"MaskCombat", L"dead;busy;ingame", nullptr },
        { L"OpcodesFishing", L"6165;6167;6169;6171;6176;6178;6180;6182",
          L"; Semya 'rybalka': snast 6165, start 6167, faza 6169, konets 6171, kniga 6176/6178/6180/6182.\r\n" },
        { L"MaskFishing", L"dead;exchange;auction;store;ingame",
          L"; Bez 'fishing': 6169/6171 zakonno prihodyat VO VREMYA rybalki.\r\n" },
        { L"OpcodesQuest", L"6591;6593",
          L"; Semya 'zadaniya': ogranichennye zadaniya - vhod 6591, itog 6593.\r\n" },
        { L"MaskQuest", L"dead;busy;ingame", nullptr },
        { L"OpcodesMisc", L"6150;6067;5428;6127",
          L"; Semya 'prochee': znaki ohoty 6150, aktivnoe zvanie 6067, konets kopaniya 5428, kosti 6127.\r\n" },
        { L"MaskMisc", L"dead;busy;ingame", nullptr },
        { L"LogHits", L"1",
          L"; Stroki narusheniy v PatchLog (pod tem zhe ogranichitelem, chto i zhurnal).\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal shtatnogo loga servera sub_569DF0 dlya stroki 'P64 ...': 1 = Log_Item, 0 = Log_Game, 6 = Log_Operator.\r\n" },
        { L"JournalIntervalSec", L"60",
          L"; Ogranichitel: odna stroka zhurnala na (sessiya, vid narusheniya) za stolko sekund;\r\n"
          L";   podavlennye schitayutsya (repeat_suppressed). 0 = bez ogranichitelya.\r\n" },
    };

    // -- [P96_InventoryX2] -- sumka 30 -> 60 (bokovoye khranilishche DLL, 2026-10-30) --
    const IniKey kInventoryX2[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = konteyner 1 (sumka) perenesyon v g_bag[550][60][57] v DLL: 9 routerov,\r\n"
          L";   recvDB, 4045, PrimiumSum, EventItem, ochistka, 19 imm 1E->3C, kanareyка.\r\n"
          L";   0 = stok (30 yacheyek, staroye smeshcheniye CUser+0x4BC).\r\n"
          L";   ★ PEREVAL P95: pri P96 razmyer sumki 60, inache 30 (P95_ItemUseGuard).\r\n" },
    };

    // -- [P97_WeightU16] -- ves i16 -> u16 (do 65535, potolok 60000; 2026-10-30) --
    const IniKey kWeightU16[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ves unsigned short (0..65535): 129 movsx->movzx, 10 pereschotov registrom,\r\n"
          L";   4 potolka 30000->60000, 5 trampolinov CraftEnter 0..65535.\r\n"
          L";   0 = stok (signed short, 0..32767, potolok 30000).\r\n"
          L";   ★ P35 CatStack: pri P97 zatirayem [ebp-238h] v 0..65535 (a ne 0..32767).\r\n" },
    };

    // -- [P98_PremiumStackAmount] -- premium-pochta 11006: stopochnyy predmet = 1 sht. (2026-10-30, volna bugs7) --
    const IniKey kPremiumStackAmount[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ploshchadka S1 0x4F8636 (11006 Recv_PremiumItemToInven_Req, posle 'sub_5340B0 == 1') -> tramplin:\r\n"
          L";   stopochnyy predmet (konteyner 2, Item_Table +35, tip != 10) prihodit Amount 1 i ves shtuki (stok: Amount 0 -\r\n"
          L";   predmet nerabochiy, ili kopiya sushchestvuyushchey stopki N - dyup). Zhurnal ac.other 150/151/152. 0 = stok.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 150..152 i stroka loga - ne chashche 1 raza za stolko sekund na (slot, vid);\r\n"
          L";   podavlennye - v repeat_suppressed. 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"38",
          L"; Kanal stokovogo loga sub_569DF0 (38 = Log_MGamePremium, MoveToInven_<data>.txt).\r\n" },
    };

    // -- [P99_UpgradeSplitStone] -- razdelenie uluchsheniya 6549: kamen svoego tipa (2026-10-31) --
    const IniKey kUpgradeSplitStone[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = Recv_UserUpgradeExtraction 0x534640: usloviya vetok vybora gotovogo kamnya menyayutsya mestami\r\n"
          L";   (imm 0x534DD2 01->02, 0x534E88 02->01): oruzhie -> 401 (podtip 204), prochee -> 363 (206). 0 = stok (naoborot).\r\n" },
    };

    // -- [P101_CashGift] -- podarok iz kesh-magazina (2026-11-02, reshenie vladelca; PROJECT_P101.md) --
    const IniKey kCashGift[] =
    {
        { L"Enabled", L"0",
          L"; * 1 = podarok iz kesh-magazina rabotaet: 5072 (proverka imeni) -> DB 2132; 5074 -> GP7 0x52 HOLD (dengi zamorazhivayutsya\r\n"
          L";   DO otpravki) -> 5076 v rele -> 5077 -> 0x52 COMMIT/REFUND, 5075. Vklyuchat po shagam PROJECT_P101.md par.7\r\n"
          L";   (SQL Joy1 + GP7, rele/CM 237 b, gp7 server.js) - inache HOLD uydet v staryy shlyuz. 0 = stok (5072/5074 ne obrabatyvayutsya).\r\n" },
        { L"Sites", L"1",
          L"; Maska tochek: 1 = 5072 (DB 2132 + marshrut 2133), 2 = 5074/HOLD + otvet 0x53, 4 = 5077-settle (zamena sub_513DF0),\r\n"
          L";   (PROJECT_P101.md par.7: snachala Sites=1 - tolko proverka imeni, zatem Sites=15.)\r\n"
          L";   8 = poluchatel (raskladka, sliyanie zaryadov P100, FT+13 300, otvet 2135, poluchatel ne v slote -> 5077 0).\r\n"
          L";   Bit 2 bez bita 4 nedopustim (stok spisal by lokalno) - bit 4 vklyuchaetsya sam; bit 2 bez bita 1 - bit 1 sam; zhurnal 163.\r\n" },
        { L"HoldTimeoutSec", L"120",
          L"; Skolko sekund zhdat otveta GP7 / 5077 ot poluchatelya. Po istechenii - zhurnal ac.other 162, blok otpravitelya snimaetsya,\r\n"
          L";   AVTOMATICHESKOGO VOZVRATA NET (predmety mogli vydatsya) - ruchnaya sverka GP7GiftLog state='H' (gift_reconcile.py).\r\n" },
        { L"SettleMaxSec", L"1800",
          L"; COMMIT/REFUND v GP7 povtoryayutsya do otveta (pauza 1.5 -> 5 -> 30 s; idempotentno) ne dolshe stolkikh sekund (60..86400),\r\n"
          L";   zatem zhurnal ac.other 162 i ruchnaya sverka.\r\n" },
        { L"MaxInFlight", L"1",
          L"; Podarkov 'v polete' na uchetku otpravitelya (1..8). Sverh - 5075 kod 0.\r\n" },
        { L"RouteMaxAgeSec", L"300",
          L"; Skolko sekund godna proverka imeni (otvet 2133) dlya 5074. Starshe - 5075 kod 0, nuzhna novaya proverka. 0 = bez sroka.\r\n" },
        { L"LogChannel", L"22",
          L"; Kanal stokovogo loga sub_569DF0 (22 - kanal 'CharChargeShopBuy() Start').\r\n" },
    };

    // -- [P102_DefectFixes] -- defekty originala vydachi predmetov (2026-11-02, reshenie vladelca) --
    const IniKey kDefectFixes[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ispravleniya P102 stoyat (sm. Sites). 0 = stok.\r\n" },
        { L"Sites", L"31",
          L"; Maska: 1 = razborka 6502 - specpredmet (kamni 401/363) s zaryadami i vesom cherez @Weight (stok: Amount 0);\r\n"
          L";   2 = kniga rybaka 6182 - @Amount specpredmeta = zaryady (stok: kolichestvo iz tablicy knigi);\r\n"
          L";   4 = otvet knigi pri oshibke BD - bez zapisi pustoy knigi v CUser (ochki rybalki) i bez vtorogo 6183;\r\n"
          L";   8 = snyatie lotov 9910 - proverka mesta DO cikla, otkaz 3/4 bez zapisi v pamyat (stok: otkaz posredi cikla);\r\n"
          L";   16 = svitok voskresheniya 5450 (FT kategoriya 48) - otkaz DO BD, esli personazh zhiv ili est lishnie celi\r\n"
          L";        (stok: zaryad spisyvalsya v BD, otvet otkazyval 'Not Dead', pamyat ne umenshalas - stroki s Amount 0).\r\n" },
        { L"ReviveLatchMs", L"3000",
          L"; Bit 16: vtoroy zapros svitka voskresheniya togo zhe slota ranshe stolko ms - otkaz do BD (pervyy esche v polete). 0 = bez zamka.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki ac.other 164..167 na (slot, vid) za stolko sekund.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal stokovogo loga sub_569DF0.\r\n" },
    };

    // -- [P103_InFlightFixes] -- "v polete": korobka pri otkaze BD, zamok otkata 5450 (2026-11-04) --
    const IniKey kInFlightFixes[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = ispravleniya P103 stoyat (sm. Sites). 0 = stok.\r\n" },
        { L"Sites", L"7",
          L"; Maska: 1 = korobka 6096 - otvet BD 2273 s otkazom (Flag 0) snimaet zapisi nakopitelya P100 (stok: v pamyat nichego,\r\n"
          L";        zapisi P100 zhili 60 s - peremeshchenie yacheek otkazano, vid 156);\r\n"
          L";   2 = 5450 - vtoroy zapros toy zhe gruppy otkata FT+38 (i togo zhe koda pri FT+18 > 0) do otveta 2141 na pervyy -\r\n"
          L";        otkaz DO BD kodom 12 / 8 (stok: zaryad spisan v BD, otvet otkazyval 'CoolTime Not Spend');\r\n"
          L";   4 = avtoprimenenie 2223/2224 - tot zhe zamok gruppy (ruchnoe 5450 ne teryaet zaryad iz-za avtoprimeneniya).\r\n" },
        { L"LatchTtlMs", L"10000",
          L"; Zhizn zamka bez otveta BD, ms (1000..60000). Otvet BD snimaet zamok srazu.\r\n" },
        { L"CodeLatch", L"1",
          L"; 1 = zamok i po kodu (FT+18 > 0): dvoynoy zapros do otveta - odin effekt (stok: dva effekta, obhod otkata koda).\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki ac.other 168..170 na (slot, vid) za stolko sekund.\r\n" },
        { L"ItemLogChannel", L"1",
          L"; Kanal stokovogo loga sub_569DF0 dlya korobki (1 = Log_Item).\r\n" },
        { L"FuncLogChannel", L"8",
          L"; Kanal stokovogo loga sub_569DF0 dlya 5450 (8 = Log_Func, ryadom s [REQUEST]/[USE]).\r\n" },
    };

    // -- [P106_FriendAcceptNotify] -- 4151 prinyavshemu druzhbu pri flage UPFriendAdd 2 (2026-11-05) --
    const IniKey kFriendAcceptNotify[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = otvet druzhby 2216 (sub_406370): 4151 kod 1 prinyavshemu pri flage UPFriendAdd 1..3 (uchastok 0x406520, 22 b).\r\n"
          L";   0 = stok: prinyavshiy poluchaet 4151 tolko pri flage 1 i 3 (pri 2 stroka v BD est, a soobshcheniya i zapisi net).\r\n" },
    };

    // -- [P107_CantActGate] -- oglushennyy/ispugannyy ne atakuet i ne primenyaet navyki, krome 736/984 (2026-11-05) --
    const IniKey kCantActGate[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = gejt sub_484E40 (4026/4028/5256/4201/4203): pri oglushenii (3) i strahe (4) - tolko navyki 736/984, 'Moshchnoe\r\n"
          L";   oglushenie' (14) - nelzya (uchastki 0x484EBB 38 b, 0x484EEF 36 b, 0x484F4D 2 b).\r\n"
          L";   0 = stok: oglushennyy i ispugannyy atakuyut i primenyayut lyubye navyki, 14 ne proveryaetsya.\r\n" },
    };

    // -- [P108_DungeonRelogEntry] -- vyhod iz danzha sohranyaetsya v tochku vhoda (2026-11-05) --
    const IniKey kDungeonRelogEntry[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = DisConnectUser (vyhod/obryv, paket 2003, uchastok 0x5257A0 10 b): karty EntryMaps - v pervuyu tochku starta\r\n"
          L";   MapInfo.txt; karty ReturnMaps - na kartu i STARTPOS pervogo portala svoey karty (PortalIP_Info).\r\n"
          L";   0 = stok: kletka sohranyaetsya kak est'.\r\n" },
        { L"EntryMaps", L"8,9,17",
          L"; Karty (cherez zapyatuyu) - v tochku vhoda MapInfo: 8 Palace_of_Queen 129,282; 9 Castle_of_Chess 48,460;\r\n"
          L";   17 Castle_of_Chaos 105,230. Karta bez tochki starta v MapInfo - stok.\r\n" },
        { L"ReturnMaps", L"10,11",
          L"; Turnirnye karty - k vyhodnomu portalu: 10 -> Conquester 440,420; 11 -> SunnyCoast 72,273 (Poridx 10/11 BD ne hranit).\r\n" },
        { L"LogChannel", L"0",
          L"; Kanal stokovogo loga sub_569DF0 dlya stroki 'P108 DungeonRelogEntry' (0 = osnovnoy).\r\n" },
    };

    // -- [P109_SelfHitNoDamage] -- navyk "na sebya" ne nanosit uron samomu kasteru (2026-11-05) --
    const IniKey kSelfHitNoDamage[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = vhod sub_470DB0 (otvet NpcServer 8206, uchastok 0x470DB0 9 b): zapis' celi tip 1 s idx = kaster i uronom != 0 -\r\n"
          L";   uron 0, flagi & 0x03 (kak u obychnogo samo-baffa). Navyki 611 Parry, 612 King's Rage, 616 Violent Storm.\r\n"
          L";   0 = stok: kaster poluchaet uron sobstvennogo navyka (HP -= uron, 5257 nesyot ego klientu).\r\n" },
        { L"LogPerMinute", L"30",
          L"; Ne bol'she N strok 'P109' v minutu v stokovyy log (kanal 18, kak u RecvBattle_SkillUse); 1..1000.\r\n" },
    };

    // -- [P110_Job4PointPools] -- puly ochkov navykov: osnovnye derev'ya <= 110, 4-ya professiya - sverh 110 (2026-11-05) --
    const IniKey kJob4PointPools[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = Recv_SkillPoint_SkillActive (5253, uchastok 0x4778B3 14 b): navyk dereva Job4Trees - ostatok\r\n"
          L";   'osnovnye + svobodnye - MainCap' (s urovnya MinLevel, nizhe 0); navyk dereva MainTrees - ostatok 'MainCap - osnovnye';\r\n"
          L";   ostatok men'she chisla ochkov zaprosa - otkaz 5254. 0 = stok: proveryaetsya tol'ko obshchiy schet.\r\n" },
        { L"Mode", L"1",
          L"; 1 = reshenie (otkaz); 0 = tol'ko zhurnal ac.other 171/172 (stok uchit navyk).\r\n" },
        { L"MainCap", L"110",
          L"; Limit osnovnyh derev'ev = vse ochki do 59-go urovnya (2*59-8); konstanta klienta originala Skill_BuildTreeUI.\r\n" },
        { L"MinLevel", L"60",
          L"; Uroven', s kotorogo est' pul 4-y professii (klient originala: nizhe - schetchik 0).\r\n" },
        { L"Job4Trees", L"10,11,12",
          L"; Derev'ya 4-y professii (SkillInfo.sif +0xBD): 10 boets, 11 luchnik, 12 mag.\r\n" },
        { L"MainTrees", L"1,2,3,4,5,6,7,8,9",
          L"; Osnovnye derev'ya: 1-3 boets, 4-6 luchnik, 7-9 mag. Derevo 0 i ne iz spiskov - stok.\r\n" },
        { L"Job4RefuseCode", L"8",
          L"; Kod otkaza 5254 dlya dereva 4-y professii: 8 = notis 111701 'nedostatochno ochkov posle 4-y professii'.\r\n" },
        { L"MainRefuseCode", L"3",
          L"; Kod otkaza 5254 dlya osnovnogo pula: 3 = notis 2202 'Nedostatochno ochkov navyka.'\r\n" },
        { L"ExemptMaxUserIndex", L"0",
          L"; Uchetki s UserIndex <= N ne proveryayutsya (operatory <= 5000); 0 = proveryayutsya vse.\r\n" },
        { L"JournalIntervalSec", L"60",
          L"; Ne chashche odnoy stroki zhurnala ac.other na (slot, vid) za N s; stroka Log_Operator - na kazhdyy otkaz.\r\n" },
    };

    // -- [P111_HatchSupplement] -- dobavka vylupleniya 298/322 daet obeshchannye +30%, v slot 3 inkubatora - tol'ko podtip 108 (2026-11-05) --
    const IniKey kHatchSupplement[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = Recv_IncubatorReq (6102, uchastok 0x4556C3 6 b): znachenie predmeta slota 3 podtipa SupplementSubType umnozhaetsya na\r\n"
          L";   SupplementScale (ne bol'she 100000 = 100%); chuzhoy podtip - otkaz 6103 kod 5. 0 = stok: znachenie 30 pribavlyaetsya k shansu\r\n"
          L";   v stotysyachnyh kak est' (+0,03 p.p. vmesto +30%), podtip slota 3 ne sveryaetsya.\r\n" },
        { L"Mode", L"1",
          L"; 1 = reshenie; 0 = tol'ko zhurnal ac.other 174/176 (stok: znachenie i otkaz ne menyayutsya).\r\n" },
        { L"SupplementSubType", L"108",
          L"; Podtip dobavki (Function_Table 298/322; klient originala puskaet v slot 3 tol'ko ego).\r\n" },
        { L"SupplementScale", L"1000",
          L"; Mnozhitel' znacheniya: tablica shansov - v stotysyachnyh, znachenie dobavki - v protsentah (30 -> 30000 = +30 p.p.). 1 = kak stok.\r\n" },
        { L"PercentBelow", L"1000",
          L"; Znacheniya men'she poroga zapisany v protsentah i umnozhayutsya; ot poroga - uzhe v stotysyachnyh (zapis' 429 = 30000), kak est'.\r\n" },
        { L"RequireSubType", L"1",
          L"; 1 = otkaz 6103 kod 5, esli v slote 3 predmet chuzhogo podtipa; 0 = takoy predmet idyot po stoku.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Ne chashche odnoy stroki zhurnala ac.other na (slot, vid) za N s; stroka Log_Operator - na kazhdoe sobytie.\r\n" },
    };

    // -- [P114_BoardExpBonus] -- opyt zadaniy doski cherez GetExpUpDownValue, kak u obychnykh zadaniy (2026-11-07) --
    const IniKey kBoardExpBonus[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = recvDBLimitationResult (uchastok 0x53C4F9 5 b): opyt zadaniy doski usilivaetsya zel'yami, sobytiyami i bonusami, kak opyt obychnogo zadaniya.\r\n"
          L";   0 = stok: opyt tablitsy bez usileniy.\r\n" },
    };

    // -- [P117_PlusPackOnce] -- nabor urovnya ne primenyaetsya, poka deystvuet prezhniy (2026-11-09) --
    const IniKey kPlusPackOnce[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = Char_FunctionItem_Use case 120 (uchastok 0x4EE25B 6 b): esli ostatok nabora urovnya CUser+0xBFC7 > 0 - otkaz 5451 kod 0x10\r\n"
          L";   (klient: notis 12849), v DBManager nichego ne ukhodit, predmet tsel. 0 = stok: povtor tratit predmet i sbrasyvaet srok.\r\n" },
        { L"FuncLog", L"1",
          L"; 1 = stroka [P117] v Log_Func na kazhdyy otkaz; 0 = bez zhurnala.\r\n" },
    };

    // -- [P120_MineTravel] -- perekhod v shakhtu (karta 23) i obratno (2026-11-09) --
    const IniKey kMineTravel[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = tip karty 6 poluchaet potok i vkhod (uchastki 0x4A53DC 12 b, ja 0x4A84BC / 0x4A72BE / 0x4C0BE5 / 0x52D38E),\r\n"
          L";   priyom 6746 (knopka 'Shakhta' NPC 181) i 6749 (knopka 'V Al'piyu' strazhey shakhty) - ja dispetchera 0x42AE1B -> 5055 kod 1.\r\n"
          L";   0 = stok: shakhta bez potoka, 6746/6749 ukhodyat v default. Dannye karty (sim/svr/npc/PortalConfig) kladyot deploy_p120.py.\r\n" },
        { L"EnterNpc", L"181",
          L"; Tipy NPC, u kotorykh 6746 vedyot v shakhtu (cherez zapyatuyu).\r\n" },
        { L"EnterFrom", L"3",
          L"; Karty, s kotorykh 6746 puskaet v shakhtu (3 = Al'piya).\r\n" },
        { L"MineMap", L"23",
          L"; Nomer karty shakhty (MapInfo.txt, Total_PortalConfig).\r\n" },
        { L"ExitNpc", L"202,203,204",
          L"; Tipy NPC na karte shakhty, u kotorykh 6749 vedyot obratno.\r\n" },
        { L"ExitTo", L"3",
          L"; Karta, kuda vedyot 6749.\r\n" },
        { L"ExitPointFromMapInfo", L"1",
          L"; 1 = tochka pribytiya 6749 - pervaya para tochek MapInfo.txt karty ExitTo (u Al'pii 115,320 u NPC 181); 0 = STARTPOS Total_PortalConfig.\r\n" },
        { L"ReviveTownOnMine", L"1",
          L"; * ISPRAVLENIE: 1 = 4054 rezhim 8 ('baza kempvara' - edinstvennaya optsiya posle smerti na karte 23) na karte tipa 6 -\r\n"
          L";   voskreshenie v gorode privyazki (kak rezhim 0, RecvCharRegen uchastok 0x52A755 5 b). 0 = stok: igrok ostayotsya myortvym.\r\n" },
        { L"Range", L"3",
          L"; Dal'nost' do NPC v kletkakh (kak P40 i CNpcManager::TemporaryRequestProcess).\r\n" },
        { L"RefuseCode", L"-1",
          L"; Otkaz: -1 = molcha (stroka v Log_Game); inache 5055 s etim kodom (0 -> klient: notis 1096).\r\n" },
        { L"LogPerMinute", L"30",
          L"; Ne bol'she strok P120 v Log_Game za minutu.\r\n" },
    };

    // -- [P118_AuctionTradeBlock] -- obmen otmenyaetsya, poka igrok rabotaet s auktsionom (2026-11-09) --
    const IniKey kAuctionTradeBlock[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = metka 'rabotaet s auktsionom' v prologakh 9901/9903/9905/9907/9909 (po 10 b); 5282 (uchastok 0x4DFA09) pri svezhey metke\r\n"
          L";   zayavitelya - 5283 kod 5 (klient: 5011), tseli - kod 4 (5010); 5284-soglasie (uchastok 0x4DFE27) - 5285 kod 0 obeim (5007).\r\n"
          L";   0 = stok: obmen ne znaet ob auktsione.\r\n" },
        { L"WindowSec", L"120",
          L"; Skol'ko sekund posle poslednego auktsionnogo zaprosa igrok schitaetsya 'na auktsione' (5..3600).\r\n" },
        { L"StormGuard", L"0",
          L"; 1 = pustoy otvet 9908 (net lotov v kategorii) zamenyaetsya odnoy zapis'yu 62 b so statusom StormStatus (uchastok 0x51A9D6 7 b):\r\n"
          L";   klient alpha-7.0.0 togda ne shlyot 9907 beskonechno. 0 = stok (pustoe telo).\r\n" },
        { L"StormStatus", L"3",
          L"; Status zapisi StormGuard (bayt +4). 0, 1 i 100 klient obrabatyvaet - zamenyayutsya na 3.\r\n" },
        { L"LogPerMinute", L"30",
          L"; Ne bol'she strok P118 v Log_Game za minutu.\r\n" },
    };

    // -- [P121_CharRenameGuard] -- predmet smeny imeni ne tratitsya cherez 5450 (2026-11-09) --
    const IniKey kCharRenameGuard[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = Char_FunctionItem_Use (uchastok 0x4EDEB3 6 b, do switch po kategorii): kategoriya Subtype - otkaz 5451 kodom RefuseCode,\r\n"
          L";   v DBManager nichego ne ukhodit, predmet tsel. 0 = stok: 5450 spisyvaet predmet smeny imeni (DB 2140), imya ne menyaetsya.\r\n"
          L";   * Uchastok obshchiy s P129: pri [P129_ChatLog] Enabled=1 i ShoutItemHook=1 on stavitsya i pri Enabled=0 - krik predmetom\r\n"
          L";   (kategorii 0x31/0x32) pod zaglushkoy chata (Mode=1) poluchaet tot zhe otkaz 5451 s etim zhe RefuseCode, predmet tsel.\r\n" },
        { L"Subtype", L"111",
          L"; Kategoriya Function_Table (+8), kotoruyu 5450 ne prinimaet (111 = smena imeni, predmet 357).\r\n" },
        { L"RefuseCode", L"0",
          L"; Kod 5451 otkaza (0 -> klient: notis 12837 'Ne udalos' ispol'zovat' instrument'). Obshchiy s otkazom krika P129.\r\n" },
        { L"FuncLog", L"1",
          L"; 1 = stroka [P121] v Log_Func na kazhdyy otkaz; 0 = bez zhurnala.\r\n" },
    };

    // -- [P112_PartyExpSpread] -- razbros urovney otryada v opyte: ves' otryad, nastoyashchiy minimum (2026-11-06) --
    const IniKey kPartyExpSpread[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = priyom 8306 sub_4C7650 (uchastok 0x4C7A8E 12 b): razbros urovney schitaetsya po vsemu otryadu, minimum nastoyashchiy.\r\n"
          L";   0 = stok: tol'ko bivshie s raznitsey <= 6, minimum startuet s 59 (otryad s maksimumom 69+ opyta ne poluchaet).\r\n" },
        { L"Mode", L"1",
          L"; 1 = reshenie; 0 = reshenie stoka, raskhozhdeniya tol'ko v zhurnal ac.other 181/182.\r\n" },
        { L"SpreadLimit", L"10",
          L"; Razbros urovney otryada ot etogo znacheniya - opyta net nikomu. Derzhat' ravnym [N24_LowMobLoot] SpreadLimit v AddonNPC.\r\n" },
        { L"SpreadWholeParty", L"1",
          L"; 1 = vse igroki etogo GameServer s tem zhe nomerom otryada; 0 = tol'ko zapisi paketa 8306.\r\n" },
        { L"FixMin59", L"1",
          L"; 1 = nastoyashchiy minimum; 0 = kak stok, ne vyshe 59.\r\n" },
        { L"JournalIntervalSec", L"60",
          L"; Ne chashche odnoy stroki zhurnala na (otryad, vid) za N s.\r\n" },
    };

    // -- [P100_ChargeStack] -- zaryady specpredmetov skladyvayutsya pri poluchenii (2026-11-01, reshenie vladelca) --
    const IniKey kChargeStack[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = vhodyashchiy specpredmet (kod 1..637, klyuch v ConfigSet\\charge_groups.txt > 0) pribavlyaet zaryady k pervoy po Posx\r\n"
          L";   yacheyke sumki togo zhe klyucha (kod yacheyki ne menyaetsya, ves ne rastet). Esli md5 ItemTable_Info\\Function_Table.txt\r\n"
          L";   != ft_md5 v charge_groups.txt - P100 ne stavitsya (stok), zapis v zhurnal ac.other 157. 0 = stok.\r\n" },
        { L"Cap", L"30000",
          L"; Potolok zaryadov v yacheyke (1..30000; CRT_UPCheckItem - SMALLINT). Sverh - sleduyushchaya yacheyka klyucha, inache novaya.\r\n" },
        { L"Sites", L"-1",
          L"; Maska putey (bit = 1 - skladyvat): 0 premium-pochta 11006 (+P16), 1 gacha 5468, 2 sunduk 6540, 3 GM 6042,\r\n"
          L";   4 magazin osady 6162, 5 korobki 6096 (P95), 6 sobytiya 6098, 7 podarok - REZERV (P101), 8 kvest, 9 limit/kraft/ruletka,\r\n"
          L";   10 rybalka, 11 razborka, 12 voyna roz, 13 obmen shell, 14 lichnaya lavka, 15 aukcion, 16 sklad->sumka. -1 = vse.\r\n"
          L";   Vyklyuchennyy bit - novaya yacheyka kak stok (otvetnaya storona sliyaniya rabotaet vsegda).\r\n" },
        { L"TradeMerge", L"1",
          L"; 1 = perenosy (bity 13..16: obmen, lavka, aukcion, sklad) tozhe skladyvayutsya. 0 = perenosy kak stok.\r\n" },
        { L"FixCharges", L"1",
          L"; * ISPRAVLENIE: zaryady vydachi - tok.9 FT celikom (stok hranit v u8: 505/506/515 davali 44 vmesto 300). 0 = stok.\r\n" },
        { L"PendingTtlSec", L"60",
          L"; Skolko sekund pomnit dobavku 'v polete' (zhdet otveta BD) - dlya potolka i sliyaniya sleduyushchih kopiy.\r\n" },
        { L"JournalIntervalSec", L"10",
          L"; Zhurnal ac.other 153..157 i stroka loga - ne chashche 1 raza za stolko sekund na (slot, vid). 0 = kazhdyy raz.\r\n" },
        { L"LogChannel", L"1",
          L"; Kanal stokovogo loga sub_569DF0 (1 = Log_Item).\r\n" },
        { L"EchoAllCodes", L"1",
          L"; * ISPRAVLENIE (2026-11-05): 1 = otvet 2604 premium-pochty kladet predmet v sumke v yacheyku EHA BD (tuda ego polozhila\r\n"
          L";   procedura) dlya LYUBOGO koda; zanyataya v pamyati yacheyka eha - stokovyy vybor + zhurnal ac.other 156. 0 = kak bylo\r\n"
          L";   (eho tolko dlya kodov s klyuchom; zapros propuskal rezervy v polete, otvet - net -> pamyat i BD v raznyh yacheykah).\r\n" },
    };

    // -- [P122_PetFuncFloor] -- funktsiya pitomtsa ne nizhe tablitsy (2026-11-09) --
    const IniKey kPetFuncFloor[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = sub_459AD0 (uchastok 0x459C0E 7 b): znachenie funktsii pitomtsa = max(raschyot po urovnyu i sytosti, PetInfo_Table).\r\n"
          L";   0 = stok: (int)(mnozhitel' urovnya * znachenie / 100), sytost' <= 39 -> 0 (na 1-m urovne +0% i +1%).\r\n" },
        { L"FloorWhenHungry", L"0",
          L"; 0 = u golodnogo (sytost' <= 39) 0, kak u stoka (slovo vladel'tsa); 1 = pol i u golodnogo.\r\n" },
    };

    // -- [P123_GmMapJump] -- GM-pryzhok na druguyu kartu po kletke (2026-11-09) --
    const IniKey kGmMapJump[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = CharJumpCommandPosition (uchastok 0x54EF50 9 b): 6010 s telom 8 b (X, Z, karta, metka A123) perenosit operatora\r\n"
          L";   (UserIndex 0..5000 i GM-flag) na DRUGUYU kartu: 5055 kod 1 iz Total_PortalConfig, kletka - prokhodimaya po karte naznacheniya.\r\n"
          L";   Telo 4 b (svoya karta) - stok. 0 = stok dlya vsekh kadrov.\r\n" },
        { L"LogPerMinute", L"30",
          L"; Predel strok P123 v Log_Operator v minutu.\r\n" },
    };

    // -- [P127_AdminBridge] -- most admin-tsentra (2026-11-18) --
    const IniKey kAdminBridge[] =
    {
        { L"Enabled", L"0",
          L"; * 1 = most admin-tsentra: fonovaya nit' oprashivaet ochered' AsdaAdmin.adm.bridge_cmd svoim ODBC (login asda_bridge - tol'ko\r\n"
          L";   EXECUTE adm.Bridge*), pishet prisutstvie (kto v igre) i pul's uzla; komandy vypolnyayutsya v niti karty igroka na obshchey\r\n"
          L";   tochke UserTick 0x526CEB (stab P73). 0 = nichego ne stavitsya (stok).\r\n" },
        { L"Mode", L"0",
          L"; 0 = tol'ko slushat': prisutstvie i ping; kick/announce/move - itog 'zhurnal' (status 6), nichego ne vypolnyaetsya.\r\n"
          L"; 1 = vypolnyat' komandy (kick 4101+ExceptionDisConnetUser, ob'yavlenie 3113, perenos 5055).\r\n" },
        { L"PollMs", L"500",
          L"; Shag oprosa ocheredi, ms (100...5000).\r\n" },
        { L"HeartbeatSec", L"5",
          L"; Pul's uzla v adm.bridge_node, s. Panel' schitaet most nedostupnym, esli pul's starshe 15 s.\r\n" },
        { L"SnapshotSec", L"5",
          L"; Kletka igroka v prisutstvii obnovlyaetsya ne chashche, s (vkhod, karta, imya - srazu).\r\n" },
        { L"PendingSec", L"30",
          L"; Komanda, ne doshedshaya do takta igroka za stol'ko s, - itog 'net na servere' (status 4).\r\n" },
        { L"KickType", L"0",
          L"; Tip 4101 kika mosta: 0 'Default' (klient: notis 1002 'Server razorval soedinenie'). P48 ne zaschityvaet (kod 8).\r\n" },
        { L"ClaimMax", L"16",
          L"; Komand za odin zakhvat (1...64).\r\n" },
        { L"SecretFile", L"ConfigSet\\admin_bridge.ini",
          L"; Fayl sekretov ([Bridge] Password, HmacKey = hex) otnositel'no papki exe. Kladyot tools/deploy_p127.py; prava - Administrators/SYSTEM.\r\n" },
        { L"Driver", L"SQL Server",
          L"; Drayver ODBC (32-bitnyy). Server/Database/Login - nizhe.\r\n" },
        { L"Server", L"127.0.0.1,1433", L"" },
        { L"Database", L"AsdaAdmin", L"" },
        { L"Login", L"asda_bridge", L"" },
        { L"NodeName", L"",
          L"; Imya uzla v adm.bridge_node. Pusto = papka exe (GameServer / Ch2_GameServer / Indun_GameServer).\r\n" },
        { L"LoginTimeoutSec", L"5", L"" },
        { L"QueryTimeoutSec", L"10", L"" },
        { L"ReconnectSec", L"10",
          L"; Baza nedostupna - povtor podklyucheniya ne chashche, s. Igra ne blokiruetsya.\r\n" },
    };

    // -- [P128_EventBadgeAll] -- znachok sobytiya Event.dat vsem (2026-11-21) --
    const IniKey kEventBadgeAll[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = na takte igroka v mire (UserTick 0x526CEB) GameServer shlyot emu 6039 / 6041 (te zhe tela, chto stok shlyot operatoru),\r\n"
          L";   kogda menyaetsya sostoyanie sobytiya Event.dat ego karty (tip 0 'dobycha i zoloto', tip 1 'opyt'): vkhod v mir, smena karty,\r\n"
          L";   komanda 6038/6040, nachalo/konets okna po chasam servera. 0 = stok (znachok vidit tol'ko operator).\r\n" },
        { L"ExpWithLuckyHours", L"1",
          L"; 1 = mnozhitel' znachka opyta = sobytie + schastlivyy chas GameServerEvent.txt (real'nyy reyt igroka); 0 = tol'ko sobytie.\r\n" },
    };

    // -- [P129_ChatLog] -- zhurnal chata i zaglushka (2026-11-22, A6.12) --
    const IniKey kChatLog[] =
    {
        { L"Enabled", L"1",
          L"; * 1 = obshchiy geyt P47 (0x42AB4F) razbiraet vse kanaly chata klienta (5084/5086/6560/5088/5105/4120/6718/6313/6316)\r\n"
          L";   i krik predmetom (call 0x4F0C6D/0x4F0C88): zhurnal joylog1.chat.message + proverka zaglushki chat.mute. 0 = stok.\r\n" },
        { L"Mode", L"0",
          L"; 0 = tol'ko zhurnal (zaglushka tol'ko pomechaetsya: mute_state=2); 1 = zaglushka DEYSTVUET: tekst nikomu ne ukhodit,\r\n"
          L";   igroku - notis 3113 (mute_state=1).\r\n" },
        { L"LogEnabled", L"1",
          L"; 1 = pisat' zhurnal chata v bazu (ochered' bez ozhidaniya igrovogo potoka); 0 = ne pisat' (zaglushka rabotaet).\r\n" },
        { L"LogChannelMask", L"2046",
          L"; Desyatichnaya maska kanalov zhurnala (bit = 1 << kod): 1 obychnyy, 2 global'nyy, 3 shirokie 6560, 4 shyopot, 5 otryad,\r\n"
          L";   6 klan, 7 armiya, 8 lavka, 9 krik lavki, 10 krik predmetom. 2046 = vse.\r\n" },
        { L"MuteChannelMask", L"2046",
          L"; Ta zhe maska - na kakie kanaly deystvuet zaglushka. 2046 = vse.\r\n" },
        { L"ExemptOperators", L"1",
          L"; 1 = sessiya s GM-flagom ne glushitsya.\r\n" },
        { L"RetentionDays", L"90",
          L"; Khranit' zhurnal N sutok (raz v sutki EXEC chat.UP_ChatJournalPurge). 0 = ne chistit'.\r\n" },
        { L"MuteRefreshSec", L"15",
          L"; Raz v N s perechityvat' deystvuyushchie zaglushki (EXEC chat.UP_ChatMuteActive) v kesh. Novaya zaglushka - ne pozzhe N s.\r\n" },
        { L"NoticeMode", L"101",
          L"; Rezhim notisa 3113 (+2). 101 = novyy klient Astory: stroka loc s chislom minut (atoi teksta); staryy klient -\r\n"
          L";   tol'ko krasnaya stroka v lente chata. 0 = banner tekstom u vsekh klientov.\r\n" },
        { L"NoticeText", L"",
          L"; Tekst notisa (pusto = vstroennyy: '{min} min. - chat zablokirovan do {until} / Chat muted until {until}').\r\n"
          L";   {min} - minut ostalos' (dolzhno byt' PERVYM pri NoticeMode=101), {until} - mestnoe vremya kontsa. Ne bol'she 95 bayt cp1251.\r\n" },
        { L"NoticeRgb", L"FF5050",
          L"; Tsvet notisa RGB (hex).\r\n" },
        { L"NoticeIntervalSec", L"3",
          L"; Ne chashche raza v N s odnomu igroku (otkaz soobshcheniyu - vsegda).\r\n" },
        { L"ShoutItemHook", L"1",
          L"; 1 = krik predmetom (FunctionItem 0x31/0x32) tozhe v zhurnal i pod zaglushku.\r\n" },
        { L"RuntimeLog", L"1",
          L"; Stroki [P129] otkaza v PatchLog (pervye 50, dalee kazhdaya 500-ya).\r\n" },
        { L"QueueCapacity", L"16384",
          L"; Emkost' ocheredi zhurnala (sobytiy). Perepolnenie - sobytie otbrasyvaetsya i schitaetsya, igra ne zhdyot.\r\n" },
        { L"FlushIntervalMs", L"2000",
          L"; Period zapisi paketa v bazu, ms.\r\n" },
        { L"BatchMax", L"500",
          L"; Sobytiy v odnom pakete (<= 1000).\r\n" },
        { L"Database", L"joylog1",
          L"; Baza zhurnala (skhema chat).\r\n" },
        { L"DbConfigFile", L"..\\DBManager\\DBMng.ini",
          L"; Otkuda GAMEDNS/GAMEUSER/GAMEPASS (kak u P53). Parol' v zhurnal ne pishetsya.\r\n" },
        { L"FileFallback", L"1",
          L"; Baza nedostupna - pakety v Log\\Log_ChatJournal\\ChatJournal_<data>.sql.\r\n" },
        // ★ ревизия 60 М-3: все ключи, которые читает код, — в шаблоне с пределами
        { L"NoticeCodePage", L"1251",
          L"; Kodovaya stranitsa teksta notisa 3113. Tol'ko odnobaytnaya (1250..1258); inache - 1251.\r\n" },
        { L"TextCodePage", L"1251",
          L"; Kodovaya stranitsa teksta bez UTF-8 i bez markera 0x98 (pravilo klienta Astory). Tol'ko odnobaytnaya; inache - 1251.\r\n" },
        { L"ReconnectSec", L"30",
          L"; Pauza mezhdu popytkami podklyucheniya k baze, s (1..3600).\r\n" },
        { L"MaxMutes", L"4096",
          L"; Strok v keshe zaglushek (16..16384); lishnie ne zagruzhayutsya (stroka v PatchLog).\r\n" },
        { L"LoginTimeoutSec", L"5",
          L"; Taym-aut podklyucheniya, s (1..120).\r\n" },
        { L"QueryTimeoutSec", L"15",
          L"; Taym-aut zaprosa, s (1..600).\r\n" },
        { L"FileRowsPerMinute", L"3000",
          L"; Ne bol'she N sobytiy v fayl v minutu (0 - bez predela, do 1000000).\r\n" },
        { L"MaxFileMB", L"256",
          L"; Potolok sutochnogo fayla, MB (0 - bez predela, do 4096).\r\n" },
        { L"ConnectionString", L"",
          L"; Pusto = DSN/login/parol' iz DbConfigFile (kak P53). Inache - polnaya stroka ODBC (parol' v zhurnal ne pishetsya).\r\n" },
        { L"DbConfigSection", L"DB_DNS0_0",
          L"; Sektsiya DbConfigFile s GAMEDNS/GAMEUSER/GAMEPASS.\r\n" },
        { L"ServerName", L"",
          L"; Imya istochnika v zhurnale (pusto = papka exe: GameServer / Indun_GameServer / Ch2_GameServer).\r\n" },
        { L"FileDir", L"",
          L"; Papka faylovogo zhurnala (pusto = <exe>\\Log\\Log_ChatJournal; otnositel'nyy put' - ot papki exe).\r\n" },
    };

    const IniSection kSections[] =
    {
        { L"General",
          L"; ===========================================================================\r\n"
          L"; AsdaReborn — патчи GameServer. Ставит AsdaPatch.dll (грузится через таблицу\r\n"
          L"; импорта GameServer.exe, ДО точки входа). Патчи применяются В ПАМЯТИ, файл\r\n"
          L"; GameServer.exe на диске остаётся чистым стоком.\r\n"
          L";\r\n"
          L"; Правится при ОСТАНОВЛЕННОМ сервере, читается один раз при старте процесса.\r\n"
          L"; * Ваши правки НЕ ТЕРЯЮТСЯ: при обновлении DLL дописывает только НЕДОСТАЮЩИЕ\r\n"
          L";   ключи и секции, существующие значения остаются как есть.\r\n"
          L"; Лог установки: Log\\Log_Patch\\PatchLog_<ГГГГММДД>.txt\r\n"
          L"; Описание: AstoryServer\\Docs\\GameServer\\dll-loader-and-patches.md\r\n"
          L"; ===========================================================================\r\n",
          kGeneral, ARRAYSIZE(kGeneral) },

        { L"P01_RareItemNotice6616",
          L"; === ПЕРЕНЕСЕНО ИЗ СТАРЫХ БИНАРНЫХ ПРАВОК ==================================\r\n"
          L"\r\n"
          L"; Приём клиентского опкода 6616 (в стоке обработчика НЕТ) -> ретрансляция 6131\r\n"
          L"; всем игрокам сервера = анонс редкой добычи.\r\n"
          L"; Проверки: индекс -> анти-реплей (Secret) -> MD5-подпись тела -> CUser -> код.\r\n"
          L"; Имя игрока берётся С СЕРВЕРА (CUser+376), поле имени из пакета игнорируется.\r\n",
          kEnabled, 1 },

        { L"P02_GmNotice6030",
          L"; Клиентский опкод 6030 (в стоке — мёртвый Send_ScreenShotCommand) превращён в\r\n"
          L"; GM-команду \"объявление\": тело пакета (+0x18) -> sendNoticeClient -> 3113 ВСЕМ.\r\n"
          L"; Гейт по флагу оператора (sub_52ED50).\r\n"
          L"; * В нашей реализации исправлена мина оригинальной бинарной правки: там ecx\r\n"
          L";   читался из НЕинициализированного [ebp-4] (пролог делал push ecx, но не\r\n"
          L";   mov [ebp-4],ecx). Работало по счастливой раскладке стека вызывающего.\r\n",
          kEnabled, 1 },

        { L"P03_OperatorSkillPointLog",
          L"; Диагностика: при операторской выдаче скиллпоинтов пишет строку\r\n"
          L"; \"SKILLPOINT: user=%d now=%d\" в Log_Operator. Логику игры не меняет.\r\n",
          kEnabled, 1 },

        { L"P04_InvincibleGmGate",
          L"; Режим \"неуязвимость\" — только оператору (в стоке мог включить любой игрок).\r\n"
          L"; ! Отключение этого патча ОСЛАБЛЯЕТ защиту.\r\n",
          kEnabled, 1 },

        { L"P05_PrimiumGachaExtraSend",
          L"; Премиум-гача: добавленная отправка (sub_4F60E0, буфер 0x78, код 105).\r\n"
          L"; ! Назначение — гипотеза (см. док), байты перенесены 1:1 с живого сервера.\r\n",
          kEnabled, 1 },

        { L"P06_Db2601Send",
          L"; sub_4F6650: отправка DB-пакета 2601 (120 б) при выполнении условия в ветке.\r\n"
          L"; ! Назначение — гипотеза, байты перенесены 1:1.\r\n",
          kEnabled, 1 },

        { L"P07_Sub43C690EarlyExit",
          L"; sub_43C690: если поле CUser+0x3BC3D не ноль (неуязвимый/GM) — вернуть 1 сразу.\r\n"
          L"; ! Назначение — гипотеза, байты перенесены 1:1.\r\n",
          kEnabled, 1 },

        { L"P08_FunctionItemUseCheckOff",
          L"; !! ЭТО ОБХОД, А НЕ ФИКС. Char_FunctionItem_Use: снята проверка (вызов+тест\r\n"
          L";    заменены на \"результат = 1\"). Правка ЧУЖОГО происхождения, найдена дифом\r\n"
          L";    живого сервера; автор и мотив в проекте не зафиксированы.\r\n"
          L";    1 = поведение как сейчас на живом сервере (ничего не меняем).\r\n"
          L";    Отключение (0) ВЕРНЁТ штатную проверку — использование функциональных\r\n"
          L";    предметов начнёт отваливаться там, где обход её глушил. Менять только\r\n"
          L";    осознанно и с проверкой на игроках.\r\n",
          kEnabled, 1 },

        { L"P15_FunctionItemCodeBounds",
          L"; * NASHA pravka (audit 2026-08-17), a ne perenos chuzhoy.\r\n"
          L";   Char_FunctionItem_Use (5450): kod predmeta iz paketa ispolzovalsya kak indeks\r\n"
          L";   Function_Table BEZ proverki diapazona - shest obrashcheniy podryad. Proizvolnyy\r\n"
          L";   kod v pakete uvodil chtenie za granitsy massiva i RONYAL GameServer odnim paketom.\r\n"
          L";   Patch proveryaet kod shtatnoy sub_532B10 (1..chislo zapisey Function_Table.txt) i\r\n"
          L";   pri vyhode za diapazon otvechaet shtatnym otkazom, kak sosednyaya proverka.\r\n"
          L";   1 = zashchita vklyuchena (rekomenduetsya). 0 = vernut uyazvimoe povedenie originala.\r\n",
          kEnabled, 1 },

        { L"P16_GachaPrizeToInven",
          L"; * NASHA pravka (2026-08-18), a ne perenos chuzhoy.\r\n"
          L";   Priz premium-gachi ranshe ostavalsya v premium-spiske BD: patchi P05+P06\r\n"
          L";   vedut gachu po marshrutu premium-SHOPA (DB 2601), a on po zamyslu avtorov\r\n"
          L";   v inventar nichego ne kladet. Otvet 6578 uhodil s konteynerom 0 i slotom -1\r\n"
          L";   (znacheniya konstruktora zapisi sub_40A9F0), poetomu 6581 vsegda poluchal 10.\r\n"
          L";   Patch dodelyvaet marshrut formuloy RABOCHEY vetki servera\r\n"
          L";   Recv_PremiumItemToInven_Req: sub_5340B0 (zapis + konteyner) -> sub_4D6740\r\n"
          L";   (svobodnyy slot) -> DB 2604; otvet 2605 obrabatyvaet stokovyy sub_4F89D0.\r\n"
          L";   Dopolnitelno yacheyka vpisyvaetsya v telo 6578, chtoby klient videl priz.\r\n"
          L";   1 = priz padaet v inventar (rekomenduetsya).\r\n"
          L";   0 = kak sechas: priz ostaetsya v premium-spiske, igrok tyanet ego vruchnuyu.\r\n",
          kEnabled, 1 },
        { L"P12_DefaultServerIp", nullptr, kIp, ARRAYSIZE(kIp) },

        { L"P10_SectorIndexBoundsGuard",
          L"; === НОВОЕ ================================================================\r\n"
          L"\r\n"
          L"; Верхняя граница индекса сектора в Send_SectorInAddMonsterInfo и\r\n"
          L"; Send_SectorInNewAddMonsterInfo: в стоке проверяется только \">= 0\", индекс\r\n"
          L"; больше числа секторов читает указатель за границей кучи -> крэш GameServer.\r\n",
          kEnabled, 1 },

        { L"P11_ServerAnnounceSources",
          L"; Серверные источники анонса 6131 — сервер решает сам, клиенту не доверяем.\r\n",
          kAnnounce, ARRAYSIZE(kAnnounce) },

        { L"P13_ChatWideChannels6560",
          L"; «Широкие» каналы чата «Поиск отряда» (1) и «Торговля» (2). Клиент шлёт их\r\n"
          L"; опкодом 6560 и ждёт рассылку 6561; в стоке обработчика 6560 НЕТ ВООБЩЕ —\r\n"
          L"; пакет уходил в общую ветку default и только копил счётчик «мусорных»\r\n"
          L"; пакетов клиента. Патч перехватывает default диспетчера, разбирает 6560 и\r\n"
          L"; рассылает 6561 ВСЕМ онлайн-игрокам сервера — тем же циклом и теми же\r\n"
          L"; фильтрами онлайна, что у глобального чата 5086/5087.\r\n"
          L"; Серверного антифлуда нет намеренно: его нет и в 5086; ограничение частоты\r\n"
          L"; стоит на клиенте (кулдаун канала + антиповтор).\r\n",
          kChatWide, ARRAYSIZE(kChatWide) },

        { L"P14_ChatMessageLength",
          L"; Длина сообщения чата 80 -> 160 байт И ЗАКРЫТИЕ ТРЁХ ПЕРЕПОЛНЕНИЙ СТЕКА.\r\n"
          L"; !! В стоке обработчики 5084, 5086 и 4120 копируют тело пакета в стековый\r\n"
          L";    char[80] БЕЗ проверки длины (проверка `<= 80` стоит НИЖЕ, уже после\r\n"
          L";    memcpy): модифицированный клиент кладёт туда до ~690 байт и затирает\r\n"
          L";    кадр стека вплоть до адреса возврата. Плюс длина считается знаковой —\r\n"
          L";    короткий пакет даёт отрицательное значение (memcpy получает ~4 ГБ).\r\n"
          L";    Патч зажимает длину ДО копирования и переселяет текстовый буфер в\r\n"
          L";    собственные 256 байт на дне кадра. ЭТО ФИКС БЕЗОПАСНОСТИ — держать\r\n"
          L";    включённым даже если увеличение длины не нужно (см. FixOverflowOnly).\r\n"
          L"; Затрагиваемые функции стока: 0x5471A0 (5084), 0x547670 (5086),\r\n"
          L";    0x403F50 (4120), 0x547BD0 (5088), 0x450FB0 (5105), 0x547EB0 (доставка\r\n"
          L";    шёпота -> 5089), 0x451210 (доставка чата отряда -> 5106).\r\n",
          kChatLen, ARRAYSIZE(kChatLen) },

        { L"P17_SqlCodePage",
          L"; ★ Русский текст в базе. Ставится НЕ в GameServer, а в процессах, которые\r\n"
          L";   ходят в базу: DBManager, RelayServer (оба), LoginManager, OperationServer.\r\n"
          L"; Симптом: подпись игрока, чат в журнале, имена персонажей, названия кланов\r\n"
          L";   и клички питомцев сохранялись как вопросительные знаки.\r\n"
          L"; Причина: базы игры арабские, а запрос везёт текст обычным литералом; перед\r\n"
          L";   отправкой он переводится в Юникод по кодовой странице МАШИНЫ (1251),\r\n"
          L";   и база, приводя литерал обратно к своей (1256), теряет кириллицу.\r\n"
          L"; Лечение: подставить в этом переводе 1256 — ту же, что у базы. База, схема,\r\n"
          L";   процедуры и уже записанные данные НЕ трогаются вовсе.\r\n"
          L"; Разбор: Reports/dbmanager_string_path.md\r\n",
          kSqlCp, ARRAYSIZE(kSqlCp) },
        { L"P18_WarehouseDupeAndBounds",
          L"; * NASHA pravka (2026-08-27), a ne perenos chuzhoy. Sklad (StoreHouse).\r\n"
          L";   Reversirovano zanovo po dekompilu i po ZHIVOMU obrazu GameServer.exe -\r\n"
          L";   vse 14 ploshchadok bayt-v-bayt sovpali. Otchet: Reports/warehouse_net_server.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/warehouse-dupe-and-bounds-p18.md\r\n"
          L";   Kazhdyy defekt vklyuchaetsya otdelnym klyuchom - mozhno stavit po odnomu.\r\n",
          kWarehouse, ARRAYSIZE(kWarehouse) },
        { L"P19_AuctionRecordBounds",
          L"; * NASHA pravka (2026-08-27), a ne perenos chuzhoy. Auktsion (CItemMediation,\r\n"
          L";   okno EXCHANGE_WIN 13000, opkody 9905 kupit i 9909 snyat lot).\r\n"
          L";   Proverka chisla zapisey stoit POSLE memcpy 45 bayt - devyataya (odinnadtsataya)\r\n"
          L";   zapis lozhitsya za konets stekovogo bufera i zatiraet sosedniye peremennye kadra.\r\n"
          L";   Verkhnego predela dliny paketa net vovse (sub_5218A0 - tolko kratnost 45).\r\n"
          L";   Reversirovano po dekompilu I po ZHIVOMU obrazu GameServer.exe - sovpalo bayt v bayt.\r\n"
          L";   Otchet: Reports/npc_exchange_win_13000.md (S3, S4)\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/auction-record-bounds-p19.md\r\n"
          L";   S1 iz togo zhe otcheta OPROVERGNUT, S6 zhivet v ItemRelayServer (defekt DANNYKH).\r\n",
          kAuction, ARRAYSIZE(kAuction) },
        { L"P21_TitleMask512",
          L"; * NASHA pravka (2026-08-29), a ne perenos chuzhoy. Zvaniya (Fame), okno 18700.\r\n"
          L";   Maska slavy byla ROVNO 256 bit i u klienta, i u servera, poetomu zvaniya\r\n"
          L";   s id 256…279 (ikh 24 v title_list) byli nedostizhimy - bita dlya nikh net.\r\n"
          L";   Rasshireno do 512 bit. Format paketov 6066/6086 SAMOOPISATELEN PO DLINE:\r\n"
          L";   staraya chast na meste, +32 bayta dopisany V KHVOST, staryy klient ikh\r\n"
          L";   prosto ne zamechaet. Obratnoye napravleniye (6067/6069) ne menyalos.\r\n"
          L";   Ploshchadki svereny s ZHIVYM obrazom GameServer.exe - raskhozhdeniy 0.\r\n"
          L";   Otchet: Reports/title_mask_512.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/title-mask-512-p21.md\r\n",
          kTitleMask512, ARRAYSIZE(kTitleMask512) },
        { L"P24_FameRatingRevoke",
          L"; * NASHA pravka (2026-08-30). Reytingovye zvaniya (Group==1, id 65…69):\r\n"
          L";   \"max uroven na servere / sredi voinov / luchnikov / magov / bolshe zolota\".\r\n"
          L";   V ORIGINALE SNYATIYA U PREZHNEGO LIDERA NET VOOBSHCHE: SubFameBit@0x54AD00\r\n"
          L";   zovyotsya tolko iz DeleteFameInfo po klientskomu 6069, a zvaniye Group==1\r\n"
          L";   klient udalyat ne dayot (notis 2428) - vydannoye ostavalos NAVSEGDA.\r\n"
          L";   Chinim v priyomnike 3404…3408 sub_54D710@0x54D710: bayt-flag zapisi\r\n"
          L";   (v stoke MYORTVYY) teper znachit 0=vydat, 1=snyat.\r\n"
          L";   Otpravitel smeny lidera i snyatiye u OFFLAYN-igroka - storona bazy\r\n"
          L";   (patch P23 v DBPatch.dll, tablitsa dbo.FameRatingHolder).\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/fame-rating-revoke-p24.md\r\n",
          kFameRatingRevoke, ARRAYSIZE(kFameRatingRevoke) },
        { L"P25_GmRatingRecalc",
          L"; * NASHA pravka (2026-08-30). GM-komanda \"pereschitat reytingi SEYCHAS\".\r\n"
          L";   Pereschyotov TRI, i vse tri v originale tolko po raspisaniyu:\r\n"
          L";     1) usloviya VSEKH zvaniy - v originale periodicheskoy proverki NET\r\n"
          L";        voobshche (TimerProcess trogaet rovno odno zvaniye, id 22);\r\n"
          L";     2) zvaniya 65…69 - nash P23 (DBPatch.dll), taymer IntervalSec = 600 s;\r\n"
          L";     3) mesto v tope po ochkam slavy - stokovyy EXEC UPTopFamePoint ->\r\n"
          L";        opkod 3409, zadacha ChannelManager \"Title Rank Process\" v 03:00.\r\n"
          L";   Ruchnoy zapusk (3) v originale est, no TOLKO s konsoli ChannelManager\r\n"
          L";   (stroka 'o' : Title Rank Process v obraze) - iz igry nedostupen.\r\n"
          L";   Komanda prinimaetsya MYORTVYM operatorskim keysom 0x1784 (opkod 6020):\r\n"
          L";   v stoke etot case ne delaet NICHEGO, tolko pishet dva markera progressa.\r\n"
          L";   Rezhim zadayotsya pervym baytom payload: 0=vsyo, 1=65…69, 2=top slavy,\r\n"
          L";   3=tolko usloviya vsekh zvaniy.\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/gm-rating-recalc-p25.md\r\n",
          kGmRatingRecalc, ARRAYSIZE(kGmRatingRecalc) },
        { L"P27_SoulmateServerDefects",
          L"; * NASHA pravka (2026-08-30), BEZOPASNOST. Dva defekta servernoy chasti\r\n"
          L";   soulmate iz otchyota Reports/soulmate_6400.md 12a.6:\r\n"
          L";     S8 - CheckSoulMateSkillCastingTime@0x497440: raznost \"proshlo s\r\n"
          L";          nachala kasta\" schitaetsya 32-bitno, no SOKHRANYAETSYA v\r\n"
          L";          znakovoye 16-bitnoye pole. Posle 32767 ms znacheniye stanovitsya\r\n"
          L";          otritsatelnym i kast navyka NIKOGDA ne zavershaetsya; dalshe\r\n"
          L";          kartina povtoryaetsya s periodom 65536 ms. Lechim zazhimom 0x7FFF.\r\n"
          L";          (V otchyote defekt opisan kak \"16-bitnoye chteniye tika\" -\r\n"
          L";           dizassembler zhivogo obraza eto ne podtverdil, mekhanizm drugoy.)\r\n"
          L";     S4 - zagruzchik SoulmateSkill.ssi (sub_4B3350@0x4B3350) vydelyaet bufer\r\n"
          L";          strogo na 100 zapisey, a chitaet po razmeru fayla bez verkhney\r\n"
          L";          granitsy: fayl > 11200 b pishet ZA KONETS kuchi. Izvne NE\r\n"
          L";          ekspluatiruetsya (dlinu zadayot fayl na diske). Seychas fayl\r\n"
          L";          5040 b = 45 zapisey, defekt spyashchiy - stavim kak strakhovku.\r\n"
          L";   Na tekushchikh dannykh OBA klyucha povedeniye NE menyayut.\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/soulmate-server-defects-p27.md\r\n",
          kSoulmateServerDefects, ARRAYSIZE(kSoulmateServerDefects) },
        { L"P29_LevelCap",
          L"; * NASHA pravka (2026-09-11), reshenie vladeltsa: potolok urovnya igroka\r\n"
          L";   59 -> MaxLevel (po umolchaniyu 100). V stoke 59 zashit konstantoy 0x3B\r\n"
          L";   v SEMI funktsiyakh (opyt za moba/otryad/kuvshin, GetExpUpDownValue,\r\n"
          L";   kuvshin partnyora, navyk soulmate 31, +2 ochka navykov).\r\n"
          L";   Pravitsya tolko bayt imm8 v kazhdoy komande cmp.\r\n"
          L";   Tablitsy ConfigSet uzhe dlinnee: ExpTable 151, ClassStat/Standard 100.\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/level-cap-100-p29.md\r\n",
          kLevelCap, ARRAYSIZE(kLevelCap) },
        { L"P30_MapSlots",
          L"; * NASHA pravka (2026-09-12), reshenie vladeltsa: chislo SLOTOV kart\r\n"
          L";   23 -> MaxMaps. U GameServer pochti vsyo po kartam dinamicheskoe\r\n"
          L";   (MapInfo.txt, MapWarpCost.txt, NpcServer, ChannelManager), a zhyostko\r\n"
          L";   zashit ROVNO ODIN massiv - \"karta otkryta + imya\" iz OpenMapInfo.ini:\r\n"
          L";   23 zapisi po 0x33 b na VA 0x0060A880. Rastyanut ego nelzya - on vplotnuyu\r\n"
          L";   k obektu CThreadManager (0x0060AD18), poetomu massiv PEREEZZHAET v bufer\r\n"
          L";   samoy AsdaPatch.dll, a v 11 ploshchadkakh pravyatsya adres i schyotchik.\r\n"
          L";   Karta bez zapisi ne imeet ni priznaka \"otkryta\", ni potoka - imenno\r\n"
          L";   poetomu karta 23 ^MineWar^ na zhivom mertva.\r\n"
          L";   ! Sam po sebe patch ^MineWar^ NE ozhivlyaet: u neyo tip karty 6, a potok\r\n"
          L";   sozdayotsya tolko dlya tipov 0, 1 i 3, i eyo faylov (.sim/.svr/.npc/\r\n"
          L";   _PortalConfig.Ini/_ConnectIP.ini) na servere net.\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/map-slots-30-p30.md\r\n",
          kMapSlots, ARRAYSIZE(kMapSlots) },
        { L"P33_GearUpgradeServerDefects",
          L"; * NASHA pravka (2026-09-25). Zatochka (okno 'Uluchshenie snaryazheniya' 20000,\r\n"
          L";   6504 -> 6505, baza 2304/2305). Defekty volny 6: gejt dushi/oderzhimosti,\r\n"
          L";   'tikhie' otkazy kodom 0, predel 0 = unichtozhenie, net zamka 'odna popytka',\r\n"
          L";   ves pomoshchnikov, kolonka SowelCombine. Protokol NE menyaetsya.\r\n"
          L"; 33 ploshchadki, vse svereny s ZHIVYM GameServer i Indun - raskhozhdeniy 0.\r\n"
          L";   Otchyot: Reports/gear_upgrade/wave6_server.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/gear-upgrade-server-defects-p33.md\r\n",
          kGearUpgrade, ARRAYSIZE(kGearUpgrade) },
        { L"P34_NecklaceFixedOptions",
          L"; * NASHA pravka (2026-09-25), patch odobren vladeltsem. Fiksirovannye optsii\r\n"
          L";   ozheleliy (item_table +12/+14), kotorye server pokazyval, no ne primenyal:\r\n"
          L";   4 (krit) i 61 (shans trofeev). 3 ploshchadki, svereny s ZHIVYM GameServer\r\n"
          L";   i Indun - raskhozhdeniy 0. Protokol NE menyaetsya.\r\n"
          L";   Otchyot: Reports/gear_upgrade/p34_necklace.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/necklace-fixed-options-p34.md\r\n",
          kNecklace, ARRAYSIZE(kNecklace) },
        { L"P35_CraftServerDefects",
          L"; * NASHA pravka (2026-09-25). Remeslo (okna 76000/77000/77500; 6598/6600/6602/6604\r\n"
          L";   -> 6599/6601/6603/6605, baza 2661...2668). Oboronitelnye pravki: zamok 'odna\r\n"
          L";   operatsiya v polyote', TS-sekret, gejt sostoyaniya, konteynery (konteyner 4\r\n"
          L";   ronyal server), granitsy retsepta, kody vmesto tishiny, katalizator stopkoy,\r\n"
          L";   maska 576 bit, uroven svitkom posle bazy. Protokol NE menyaetsya.\r\n"
          L"; 39 ploshchadok, vse svereny s ZHIVYM GameServer i Indun - raskhozhdeniy 0.\r\n"
          L";   Otchyot: Reports/craft/wave6_server.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/craft-server-defects-p35.md\r\n",
          kCraft, ARRAYSIZE(kCraft) },
        { L"P36_CraftSuccessOption",
          L"; * NASHA pravka (2026-09-26), reshenie vladeltsa. Optsiya 24 'Uspeshnoe\r\n"
          L";   izgotovlenie +N %' (fiks. optsiya 13 amuletov), kotoruyu server pokazyval,\r\n"
          L";   no ne primenyal. 1 ploshchadka (0x0053E7DF), sverena s ZHIVYM GameServer\r\n"
          L";   i Indun - raskhozhdeniy 0. Protokol NE menyaetsya.\r\n"
          L";   Otchyot: Reports/craft/p36_r248_dbm.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/craft-success-option-p36.md\r\n",
          kCraftOpt, ARRAYSIZE(kCraftOpt) },
        { L"P32_PetWrongOpcode6101",
          L"; * NASHA pravka (2026-09-27). Pitomtsy: dve vetki otkaza 'charId zaprosa ne tot'\r\n"
          L";   otvechali opkodom 6101 (otvet na prizyv, telo 9 b) s telom CHUZHOGO razmera\r\n"
          L";   (18 b = 6103, 89 b = 6109) - kopipasta opkoda. Menyaetsya tolko bayt opkoda,\r\n"
          L";   dlina i telo stokovye - protokol NE menyaetsya. 2 ploshchadki, svereny s\r\n"
          L";   ZHIVYM GameServer i Indun i so stokom - raskhozhdeniy 0.\r\n"
          L";   Otchyot: Reports/owner_0927/p31_p32.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/pet-wrong-opcode-6101-p32.md\r\n",
          kPetOpcode, ARRAYSIZE(kPetOpcode) },
        { L"P31_PetUnionRemoveNotify",
          L"; * NASHA pravka (2026-09-27). Yunion pitomtsev: otvet 6113 nesyot uid syedennykh\r\n"
          L";   materialov UREZANNYMI do 16 bit - u uid >= 32768 klient ikh ne nakhodit.\r\n"
          L";   Pole rasshirit nelzya (telo 56 b upiraetsya v cookie kadra), poetomu na\r\n"
          L";   kazhdyy udalyonnyy material dosylaetsya SHTATNYY 6111. Protokol NE menyaetsya.\r\n"
          L";   1 ploshchadka (call @0x00459264), sverena s ZHIVYM GameServer i Indun i so\r\n"
          L";   stokom - raskhozhdeniy 0.\r\n"
          L";   Otchyot: Reports/owner_0927/p31_p32.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/pet-union-remove-notify-p31.md\r\n",
          kPetUnion, ARRAYSIZE(kPetUnion) },
        { L"P40_CrystalTeleportGate",
          L"; * NASHA pravka (2026-09-27), defekt originala. Teleport kristallom (5477,\r\n"
          L";   RecvContinent_PortalMove @0x5498A0) ne proveryal ni blizost NPC, ni\r\n"
          L";   OpenMapInfo - lyubuyu kartu 0...22 mozhno bylo zakazat paketom. Tsena i sam\r\n"
          L";   perekhod - stokovye. Otkaz - stokovyy 5055 etogo zhe obrabotchika.\r\n"
          L";   1 ploshchadka (0x00549A15), sverena s ZHIVYM GameServer i Indun i so stokom -\r\n"
          L";   raskhozhdeniy 0. Protokol NE menyaetsya.\r\n"
          L";   Otchyot: Reports/owner_0927/p40_crystal.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/crystal-teleport-gate-p40.md\r\n",
          kCrystalGate, ARRAYSIZE(kCrystalGate) },
        { L"P41_GmHide4056",
          L"; * NASHA dorabotka (2026-09-27), dovodka GM-nevidimosti (P39). Skrytyy operator\r\n"
          L";   (CUser+0x3BC3B = 300) posle smerti vsegda voskresaet na meste, i server slal\r\n"
          L";   4056 (nomer + kletka + HP) VSEMU sektoru - sosedi uznavali, gde on. To zhe pri\r\n"
          L";   GM-pryzhkakh: staromu sektoru ukhodila kletka novogo mesta. Teper sosedyam\r\n"
          L";   4056 skrytogo ne ukhodit, sebe - kak v stoke. Uslovie kak u stokovykh geytov\r\n"
          L";   navykov: operator po UserIndex I priznak 300. 9 ploshchadok (call), sverena s\r\n"
          L";   ZHIVYM GameServer i Indun - raskhozhdeniy 0. Protokol NE menyaetsya.\r\n"
          L";   Otchyot: Reports/owner_0927/gm_hide_npc_2.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/gm-hide-4056-p41.md\r\n",
          kGmHide4056, ARRAYSIZE(kGmHide4056) },
        { L"P42_GmHideTarget",
          L"; * NASHA dorabotka (2026-09-27), paritet s originalom 'master igry nablyudaet\r\n"
          L";   skrytno': skrytyy operator (CUser+0x3BC3B = 300) NE dopustimaya TSEL boevykh\r\n"
          L";   deystviy igrokov. Server nigde ne sveryal priznak skrytiya u tseli. 11\r\n"
          L";   ploshchadok: sub_556DB0 (vkhod) + 10 obkhodov (rezultaty navykov, sostoyaniya,\r\n"
          L";   ploshchadnye chleny 925, razlyoty strely/strazha, soulmeyt). Otkaz - shtatnym\r\n"
          L";   putyom (return 0 / SEH-epilog / continue), novykh paketov net, protokol NE\r\n"
          L";   menyaetsya, samoprimenenie ne trogaem. Svereno s ZHIVYM GameServer i Indun - 0.\r\n"
          L";   Otchyot: Reports/owner_0927/gm_hide_npc_2.md (S5); klient - pick_hidden_filter.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/gm-hide-attack-p42.md\r\n",
          kGmHideTarget, ARRAYSIZE(kGmHideTarget) },
        { L"P38_ClanSlotCap",
          L"; * NASHA pravka (2026-09-27), defekt originala: proverka rasshireniya klana\r\n"
          L";   sveryala 'limit+5 <= 100', a pribavlyala +10 - pri ruchnoy pravke BD klan mog\r\n"
          L";   uyti za 100 (do 105). Odin bayt 0x40494D: 05 -> 0A. Ploshchadki osnovnogo i\r\n"
          L";   Indun. Protokol NE menyaetsya, otkaz shtatnyy (kod 3 -> notis 12453).\r\n"
          L";   Otchyot: Reports/owner_0927/who_clan_REVIEW.md (s.4)\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/clan-slot-cap-p38.md\r\n",
          kClanSlotCap, ARRAYSIZE(kClanSlotCap) },
        { L"P43_StorePriceCap",
          L"; * NASHA pravka (2026-09-27, reshenie vladeltsa): potolok tseny lichnoy lavki\r\n"
          L";   (StreetStall, opkody 6300..6306) 100mln -> 1mlrd. Dva capa (otkrytie i\r\n"
          L";   pokupka) + zashchita ot perepolneniya int32 (kol-vo x tsena). Kesh-shop ne\r\n"
          L";   tronut. Svereno s zhivym GameServer i Indun - 0.\r\n"
          L";   Otchyot: Reports/owner_0927/world_data_0927.md #18\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/store-price-cap-p43.md\r\n",
          kStorePriceCap, ARRAYSIZE(kStorePriceCap) },
        { L"P44_ExchangeIntegrity",
          L"; * NASHA pravka (2026-09-29): korrektnost pryamogo obmena (528x) i lichnoy lavki\r\n"
          L";   (630x). SO-1 zamok zaversheniya + sverka fiksatsiy; SO-3 granitsy windowIndex/\r\n"
          L";   yacheyki; SL-1 granitsa lota vitriny; sbros obmena pri smerti; SO-4 (zayavka\r\n"
          L";   pered prinyatiem) - VYKL po umolchaniyu. Otkaz shtatnym putyom, protokol NE\r\n"
          L";   menyaetsya. Ploshchadki osnovnogo GameServer i Indun, s P01..P43 ne peresekaetsya.\r\n"
          L";   Otchyot: Reports/trade/trade_re_report.md (s.3)\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/trade-p44.md\r\n",
          kExchangeIntegrity, ARRAYSIZE(kExchangeIntegrity) },
        { L"P46_StoreShoutOverflow",
          L"; * NASHA pravka, BEZOPASNOST (2026-10-08): zakrytie perepolneniya steka v\r\n"
          L";   obrabotchike 'krika' lichnoy lavki 6316 (Recv_SelfStoreGlobalChat @0x508B40\r\n"
          L";   -> rassylka 5087). Stok kopiruet telo paketa v char[80] BEZ proverki dliny.\r\n"
          L";   Tot zhe klass, chto P14 zakryl dlya 5084/5086/4120; v spisok P14 ne voshla.\r\n"
          L";   Predel NE podnimaetsya (lavka ostayotsya na 80): odna ploshchadka 0x508B59\r\n"
          L";   zazhimaet dlinu kopii v [0..80] DO memcpy. Scan .text: 6316 - edinstvennyy\r\n"
          L";   nezakrytyy obrabotchik etogo klassa. Ploshchadka osnovnogo GameServer i\r\n"
          L";   Indun (binar bayt-v-bayt tot zhe), s P01..P44 ne peresekaetsya.\r\n"
          L";   Otchyot: Reports/owner_1008/p6316_shout_overflow.md\r\n"
          L";   Dokument patcha: AstoryServer/Docs/GameServer/store-shout-overflow-p46.md\r\n",
          kStoreShoutOverflow, ARRAYSIZE(kStoreShoutOverflow) },
        { L"P47_IdentityOperatorGate",
          L"; * NASHA pravka, BEZOPASNOST (antichit A0, 2026-10-12): A) GM-flag obyazatelen dlya\r\n"
          L";   vseh operatorskih opkodov (gate v dispetchere 0x42AB4F pered P01); B) UserIndex\r\n"
          L";   4001/5058 == UserIndex iz 20000 (0x527692/0x52CD3E -> shtatnyy otkaz);\r\n"
          L";   C) IP pira v DB-logon 2001/2089 (0x52773F/0x52CF05) dlya DBPatch P50.\r\n"
          L";   Protokol klienta NE menyaetsya. Otchyot: Reports/anticheat/wave_A0.md\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/identity-operator-gate-p47.md\r\n",
          kIdentityOperatorGate, ARRAYSIZE(kIdentityOperatorGate) },
        { L"P48_KickAutoBlock",
          L"; * NASHA pravka (antichit A0, 2026-10-12): posle N kikov (tipy 3/6) sessii v mire -\r\n"
          L";   shtatnyy DB-zapros 2271 -> EXEC UPHackBlock UserIndex, chasy. Ploshchadka - vhod\r\n"
          L";   Send_DisConnectType 0x52EDB0. Snyat blok: SQL/ac0_unblock_user.sql.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/kick-autoblock-p48.md\r\n",
          kKickAutoBlock, ARRAYSIZE(kKickAutoBlock) },
        { L"P49_OriginalChecksRestore",
          L"; * Mera 11 (2026-10-12): vozvrat shtatnyh proverok originala - kik za povtory\r\n"
          L";   (0x524496) i podpis 5450 (0x4ED8CF: dlina 0x89 -> 0x101).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/original-checks-p49.md\r\n",
          kOriginalChecksRestore, ARRAYSIZE(kOriginalChecksRestore) },
        { L"P53_AcJournal",
          L"; * NASHA pravka (antichit, volna acdb, 2026-10-12, reshenie vladeltsa 12.10): zhurnal\r\n"
          L";   antichita v BD joylog1.ac - tablitsy po vidam narusheniy, predstavleniya dlya chteniya.\r\n"
          L";   Zapis BEZ zaderzhki igrovogo potoka: ochered bez blokirovok + fonovyy potok + svoyo\r\n"
          L";   soedinenie ODBC, paketnaya vstavka; baza nedostupna - faylovyy zhurnal.\r\n"
          L";   SQL: AstoryServer/Docs/SQL/acdb_01_migrate.sql, shpargalka acdb_cheatsheet.sql\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/ac-journal-p53.md\r\n",
          kAcJournal, ARRAYSIZE(kAcJournal) },
        { L"P54_BlockedLoginMessage",
          L"; * NASHA pravka (acdb, 2026-10-12): otkaz P50 po bloku uchyotki (v t.ch. vhod soulmeytom\r\n"
          L";   v personazha zablokirovannogo hozyaina) -> 4101 kod 7 = shtatnoe soobshchenie originala\r\n"
          L";   'uchetnaya zapis zablokirovana' (loc 1107) vmesto koda 5 'nedostatochno dannyh'.\r\n"
          L";   Para: DBPatch P50 BlockedClientCode7=1. 0 = kod 5 kak v stoke.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/blocked-login-message-p54.md\r\n",
          kEnabled, 1 },
        { L"P55_PacketValidator",
          L"; * NASHA pravka (antichit, volna V4, 2026-10-12; plan mera 8): obshchiy validator klientskih\r\n"
          L";   paketov pered dispetcherom - dlina kadra po opkodu (tablitsa iz dekompila, 260 opkodov) i\r\n"
          L";   chastota po klassu opkoda (token-bucket na sessiyu). Svoih ploshchadok net: zovyotsya iz\r\n"
          L";   C-geyta P47 (stab 0x42AB4F). Zhurnal: joylog1.ac.packet_validator (P53) + PatchLog.\r\n"
          L";   Po umolchaniyu TOLKO ZHURNAL (Mode=0); otkaz - cherez shtatnyy schyotchik Hack Packet.\r\n"
          L";   SQL: AstoryServer/Docs/SQL/acdb_p55_01_migrate.sql\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/packet-validator-p55.md\r\n",
          kPacketValidator, ARRAYSIZE(kPacketValidator) },
        { L"P56_CombatLimits",
          L"; * NASHA pravka (antichit, volna V5 'servernye limity boya', mera 9 plana, 2026-10-12):\r\n"
          L";   9 ploshchadok call rel32 v GameServer: 5256 (povtory tseley B-01, zayavka v puti B-02 -\r\n"
          L";   otkat i MP fiksiruyutsya tolko po otvetu 8206), 6158 (povtory), 4026/4028/4201/4203 (pol\r\n"
          L";   intervala po vremeni servera, dalnost PvP po kletkam CUser). Chastotu po oruzhiyu i dalnost\r\n"
          L";   do monstra schitaet NpcServer (N01/N13/N14). Po umolchaniyu TOLKO ZHURNAL (Mode=0).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/combat-limits-p56.md\r\n",
          kCombatLimits, ARRAYSIZE(kCombatLimits) },
        { L"P57_MoveGuard",
          L"; * NASHA pravka (antichit, volna A6, 2026-10-12; mera 12 plana, MV-1/MV-2): schyot shtatnyh\r\n"
          L";   'Hack Position' na sessiyu -> kik po porogu; 4006: predel otrezka, byudzhet vremeni, kletka\r\n"
          L";   klienta (otkaz = stokovoe telo Hack Position, result=5); 4008: pozitsiya iz proverennyh poley.\r\n"
          L";   Po umolchaniyu Mode=0 - TOLKO ZHURNAL. Ploshchadki CharMove 0x54531D/0x5454DE/0x545B25,\r\n"
          L";   CharStop 0x546427 (+ 0x54543D/0x545A84, esli ih ne zanyal P53).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/move-guard-p57.md\r\n",
          kMoveGuard, ARRAYSIZE(kMoveGuard) },
        { L"P58_DisconnectReasonLog",
          L"; * NASHA pravka (antichit A6, P1 plana, 2026-10-12): Send_DisConnectType (0x52EDE4) pishet\r\n"
          L";   '[CALL] Send_DisConnectType() UserNum/tip/CharN/UserIndex/IP/From' v obshchiy log VSEGDA\r\n"
          L";   (stok - tolko pri tipe servera 4 i tolko v Log_RoseWar). Bezopasno: tolko zhurnal.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/disconnect-reason-log-p58.md\r\n",
          kDisconnectReasonLog, ARRAYSIZE(kDisconnectReasonLog) },
        { L"P59_RareDropJournal",
          L"; * NASHA pravka (antichit A6, P4 plana, 2026-10-12): drop redkogo s monstrov (vhod\r\n"
          L";   recvBattleServerFromItemDrop 0x4C9370) i podbor redkogo (tramplin P11) -> Log_UserEvent +\r\n"
          L";   ac.other (vidy 4/5). Tolko zhurnal, s ogranichitelem.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/rare-drop-journal-p59.md\r\n",
          kRareDropJournal, ARRAYSIZE(kRareDropJournal) },
        { L"P60_ValueGuard",
          L"; * NASHA pravka (antichit, volna A7, mehanizm L5 / prioritety A3-A4, 2026-10-12): znacheniya iz paketov\r\n"
          L";   sveryayutsya s servernymi tablitsami i zdravym smyslom: 5020 (kolichestvo, summa v int64), 6180/6150\r\n"
          L";   (znak kolichestva), 5048 (kod knigi), 5041 (nomer nagrady), 6586 (anti-povtor, znak), 6521 (stupen).\r\n"
          L";   Po umolchaniyu Mode=0 - TOLKO ZHURNAL. Ploshchadki 0x50F3F0, 0x4125CC, 0x55F1AD, 0x511978, 0x45E0F1,\r\n"
          L";   0x539278/0x5392DB, 0x409AD0 (vse `call rel32`). 6140 ne realizovano (filtra imeni v GameServer net).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/value-guard-p60.md\r\n",
          kValueGuard, ARRAYSIZE(kValueGuard) },
        { L"P61_TrafficEncryption",
          L"; * NASHA proslojka (shifrovanie trafika, volna V7b, 2026-10-12): ECDH P-256 + ECDSA +\r\n"
          L";   AES-256-GCM poverh starogo protokola. Enabled=0 - stok (trampliny ne stavyatsya).\r\n"
          L";   Pri Enabled=1 nuzhen KeyFile ryadom s GameServer.exe. Zerkalo L07 LoginManager.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/traffic-encryption-p61.md\r\n",
          kP61, ARRAYSIZE(kP61) },
        { L"P62_SlotUniqueness",
          L"; * NASHA pravka (antichit A7, mehanizm L3 / prioritet A5, 2026-10-12): unikalnost par (konteyner, slot)\r\n"
          L";   i uid v mnogoslotovyh zayavkah 5018/6549/6506/6555/6096/6112 (ploshchadki - call sub_5646C0 pered\r\n"
          L";   otpravkoy v DBManager: 0x50E991/0x535202/0x501A5C/0x5376F3/0x55AE4F/0x4590C7) i 'slot 0 != slot 1'\r\n"
          L";   u 6067 (0x54C8E5). Mode=0 - tolko zhurnal (ac.other vidy 30..34).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/slot-uniqueness-p62.md\r\n",
          kSlotUniqueness, ARRAYSIZE(kSlotUniqueness) },
        { L"P63_InFlightLock",
          L"; * NASHA pravka (antichit A7, mehanizm L2, 2026-10-12): obshchiy zamok 'zapros v BD v polyote' dlya 25 semey\r\n"
          L";   (pokupki 5048/6162, pakety 6096, sobytiya 6098, razborka/sbros/izvlechenie/blagoslovenie/perenos/summa\r\n"
          L";   6502/6506/6549/6551/6553/5433/6555, gacha 5468, zvyozdy 6586, imya 6140, pitomtsy 6102..6148, rybalka\r\n"
          L";   6171/6182, zadaniya 6591/6593). Obobshchenie P33 N-2: postanovka u call sub_5646C0, snyatie v priyome\r\n"
          L";   otveta BD (ConnectSocketMsgProcess), sbros pri vyhode (ClearUserMemory). Mode=0 - tolko zhurnal.\r\n"
          L";   NE zakryto: 5070 CharChargeShopBuy (GP7, opkod 80/0x51, slot ne v vyzove) i 6100 CallPet (otveta net).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/inflight-lock-p63.md\r\n",
          kInFlightLock, ARRAYSIZE(kInFlightLock) },
        { L"P64_StatePreamble",
          L"; * NASHA pravka (antichit, volna A7, mehanizm L4 / prioritet A8 plana, 2026-10-12): obshchaya\r\n"
          L";   preambula sostoyaniya personazha dlya opkodov, u kotoryh stok ne sprashivaet ni 'zanyat'\r\n"
          L";   (sub_52BFF0), ni 'dusha' (sub_52EEA0), ni 'oderzhim' (sub_52EE40): ekonomika/progress, pitomtsy,\r\n"
          L";   PvP 4201/4203 i 6158, rybalka, ogranichennye zadaniya. Chitaet te zhe polya CUser, chto stokovye\r\n"
          L";   predikaty. Svoih ploshchadok net: zovyotsya VTORYM (posle P55) iz C-geyta P47 (stab 0x42AB4F).\r\n"
          L";   Zhurnal: joylog1.ac.other vidy 40..44 (P53) + PatchLog + Log_Item. Po umolchaniyu TOLKO ZHURNAL.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/state-preamble-p64.md\r\n",
          kStatePreamble, ARRAYSIZE(kStatePreamble) },
        { L"P65_ConsumableType",
          L"; * NASHA pravka (antichit A7, mehanizm L5 / prioritet A9, 2026-10-12): tip rashodnika po servernoy\r\n"
          L";   Function_Table v 6551 (svitok blagosloveniya), 6553 (svitok obmena optsiy), 5433 (pomoshchnik) i\r\n"
          L";   ravenstvo koda paketa i koda slota v 5450. Mode=0 - tolko zhurnal (ac.other 45..48).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/consumable-type-p65.md\r\n",
          kConsumableType, ARRAYSIZE(kConsumableType) },
        { L"P66_PositionGuard",
          L"; * NASHA pravka (antichit, volna A7, mehanizm L6 'sverka s servernoy pozitsiey/sostoyaniem', A10, 2026-10-12):\r\n"
          L";   5012 podbor - servernaya kletka protiv kletki predmeta (+ vozvrat snyatogo predmeta na vetkah otkaza);\r\n"
          L";   5427 zov druga - ozhidanie iz dostavki 5236, kletka partnyora, geyt; 6093 voskreshenie - predlozhenie\r\n"
          L";   sub_52B070 pomnitsya, tsel = otpravitel; 5428 konets kopaniya - start 5028/5429, sostoyanie 4024, MinDigMs.\r\n"
          L";   Po umolchaniyu Mode=0 - TOLKO ZHURNAL. Ploshchadki 0x4D465A/0x4D5999, 0x52BBF5/0x49ED38, 0x52B0CC/0x52B1AC,\r\n"
          L";   0x4D9BEB/0x546B21 (E8 rel32; LABEL_103 - 7 b).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/position-guard-p66.md\r\n",
          kPositionGuard, ARRAYSIZE(kPositionGuard) },
        { L"P67_GachaRewardVariant",
          L"; * NASHA pravka (antichit A7, prioritet A2, krit 5, 2026-10-12): 6581 Recv_UserPrimiumGaChaReward -\r\n"
          L";   variant priza obyazan byt iz semeystva priza (korobka: LinkWord +65; ne-korobka: tot zhe kod),\r\n"
          L";   priz - iz PrimiumGaChaTable; otkaz = stokovoe telo 6582 kod 10. 6579 Recv_UserSoulResult - tolko pri\r\n"
          L";   aktivnoy ruletke na finalnoy kletke (tihiy vyhod stoka). Mode=0 - zhurnal ac.other 50..52.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/gacha-reward-variant-p67.md\r\n",
          kGachaRewardVariant, ARRAYSIZE(kGachaRewardVariant) },
        { L"P68_CharNameGuard",
          L"; * NASHA pravka (antichit A13 'imya personazha', 2026-10-13): 6138/6140 - imya iz paketa uhodilo v BD bez\r\n"
          L";   proverki (pravila tolko u klienta). Proverka po pravilam klienta-originala (nul v 20 b, upravlyayushchie bayty,\r\n"
          L";   simvoly lokali - NameCharset), 6140 tolko posle 6138 s tem zhe imenem; otkaz = 6139 flag 3 / 6141 kod 0.\r\n"
          L";   2453: imya v pamyati - tolko pri uspehe BD (defekt stoka). Mode=0 - zhurnal ac.other 53/54 (55 - SQL A13).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/char-name-check-p68.md\r\n",
          kCharNameGuard, ARRAYSIZE(kCharNameGuard) },
        { L"P69_IntegrityAutoBlock",
          L"; * NASHA pravka (antichit autoban, 2026-10-14, reshenie vladeltsa 14.10): stupenchatyy avtoblok uchyotki za\r\n"
          L";   narusheniya tselostnosti paketov (P55 vidy 1/2/4, kanal P61 vidy 56-59): 20 -> 24 ch, 50 -> 720 ch, bolshe ->\r\n"
          L";   bessrochno. Tolko podtverzhdyonnaya uchyotka sessii v mire; do vhoda - tolko zhurnal; operatory ne blokiruyutsya.\r\n"
          L";   Mode=0 (umolchanie) - tolko zhurnal 'byl by blok' (ac.other 62). Ploshchadok net.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/integrity-autoblock-p69.md\r\n",
          kIntegrityAutoBlock, ARRAYSIZE(kIntegrityAutoBlock) },
        { L"P71_TickDeadlineWrap",
          L"; * NASHA pravka (oborona dev-servera, 2026-10-15, audit znakovyh taktov): takt GetTickCount hosta 29.10.2026\r\n"
          L";   09:51:50 UTC prohodit cherez 2^32. Chetyre absolyutnyh sroka GameServer (hranitel dushi, soglasie otryada,\r\n"
          L";   shtraf lagerya CUser+0x3F454, predmety na zemle) sravnivayutsya so vremenem MODULNO - stok sravnival\r\n"
          L";   bezznakovo, i srok, vzvedyonnyy do obnuleniya, ne nastupal 49,7 sut. Zhurnala antichita net.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/tick-deadline-wrap-p71.md\r\n",
          kTickDeadlineWrap, ARRAYSIZE(kTickDeadlineWrap) },
        { L"P72_HiddenWipeDisarm",
          L"; * NASHA pravka, BEZOPASNOST (2026-10-15): v stokovom GameServer (stok = zhivoy = Indun) naydena ZAKLADKA -\r\n"
          L";   kodovaya kombinatsiya 5 deystviy s predmetami vzvodit periodicheskoe zatiranie bazovogo bloka personazha u vseh\r\n"
          L";   550 slotov protsessa (RunProcess 10024). Mera 1: taymer otklyuchyon (jne->jmp @0x4C2745). Mera 2: vzvedenie\r\n"
          L";   perehvacheno (tramplin @0x50A651): flagi obnulyayutsya, zhurnal ac.other 76 + Log_Operator, Response/AutoBlock.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/hidden-wipe-disarm-p72.md\r\n",
          kHiddenWipeDisarm, ARRAYSIZE(kHiddenWipeDisarm) },
        { L"P73_EacBridge",
          L"; * NASHA pravka (antichit EAC, etap E1-V, 2026-10-16; kontrakt Reports/anticheat/eac/CONTRACT.md par. 4-6):\r\n"
          L";   most k saydkaru AsdaEacServer 127.0.0.1:15702 - LOGIN/LOGOUT igrovyh sessiy, KICK ot EAC v niti karty.\r\n"
          L";   Obshchie tochki: stab logona P47 (0x527692/0x52CD3E), detur SetConnectFlag P61 (0x562910); svoya ploshchadka\r\n"
          L";   0x526CEB (CheckDisConnectUser) - tolko pri Mode=1. Zhurnal ac.other 77-84.\r\n"
          L";   * red. 3: HELLO ver=2, LOGIN/REBIND nesut bind igrovogo kanala AsdaSecure (P61; Legacy/bez P61 - nuli).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/eac-bridge-p73.md\r\n",
          kEacBridge, ARRAYSIZE(kEacBridge) },
        { L"P74_HpSectorSync",
          L"; * NASHA pravka (sinhronizatsiya boya, faza F3, 2026-10-17; proekt Reports/combat_sync_2026-10-17/03_DESIGN.md\r\n"
          L";   par. 6): snimok HP 4058 posle urona po igroku (0x43C854) i izmeneniy vo vremeni (0x43CE82) stok shlyot tolko\r\n"
          L";   sebe - sosedi ne vidyat HP chuzhogo igroka. Teper: sebe kak stok + tot zhe paket sosedyam po sektoru 3x3.\r\n"
          L";   Bez tsifr u klienta (tipy 1/6 - tihoy kopiey, red. 2), skrytyy operator - net. Zhurnala antichita net.\r\n"
          L";   Uron - tolko sub_43C690 s a5=1 (navyki/uron po vremeni/otrazhenie); obychnye udary mobov i PvP - ne pokryty.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/hp-sector-sync-p74.md\r\n",
          kHpSectorSync, ARRAYSIZE(kHpSectorSync) },
        { L"P75_LevelUpPotion",
          L"; * NASHA pravka (slovo vladeltsa 2026-10-19): funktsionalnyy predmet 558 'Zelye povysheniya urovnya' - do 70 urovnya\r\n"
          L";   vychisleniem opyta (ExpTable[70] minus tekushchiy), shtatnym povysheniem urovnya, bez mnozhiteley. Shag 1 (5450,\r\n"
          L";   0x4EDDC7) - otkaz 5451 kod 0, predmet tsel; shag 2 (otvet BD, 0x4EF606) - nachislenie. 4036 - odin raz (0x4CBFEC/\r\n"
          L";   0x4CC009), kuvshin dushi ot zelya - net (0x4CC08D/0x4CC27E). Stavitsya POSLE P29 i P63. 'Odin raz' - gate urovnya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/level-up-potion-p75.md\r\n",
          kLevelUpPotion, ARRAYSIZE(kLevelUpPotion) },
        { L"P76_SowelSlotBounds",
          L"; * NASHA pravka (reshenie vladeltsa 2026-10-21): polya paketov zhivyh kamney (5022 izvlechenie, 5024 vstavka,\r\n"
          L";   5031 'svyatost') sveryayutsya s pravilami chestnogo klienta; vne predelov - shtatnyy otkaz kodom 0 do lyuboy\r\n"
          L";   zapisi. Ploshchadki - vyzov sub_52BFF0 (0x4DBDEF/0x4DC51E/0x4DE70E). Zhurnal antichita ac.other 85..87.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/sowel-slot-bounds-p76.md\r\n",
          kSowelSlotBounds, ARRAYSIZE(kSowelSlotBounds) },
        { L"P77_MoveSyncStopPoint",
          L"; * NASHA pravka (reshenie vladeltsa 2026-10-22): MoveSyncProcess na neprohodimoy kletke / krae karty /\r\n"
          L";   'iMotionStartTime = 0' molcha snimal igroka so steka hoda - klient shel dalshe, sleduyushchiy 4006 daval\r\n"
          L";   'CharMove Hack Position' i snap. Teper posle stoka - shtatnyy 4009 v tochku servera sebe i sektoru (kak CharStop\r\n"
          L";   'Revision Pos'). Protokol ne menyaetsya. Ploshchadki - call 0x542520 (0x542968/0x542ACB/0x542B11/0x542B49).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/move-sync-stop-point-p77.md\r\n",
          kMoveSyncStopPoint, ARRAYSIZE(kMoveSyncStopPoint) },
        { L"P80_CrouchSpeedJumpRelay",
          L"; * NASHA pravka (reshenie vladeltsa 2026-10-24): hod vprisyadku porta (donor AsdaFableClassic, Ctrl). Klient v prisyade\r\n"
          L";   shlet 4006 so statusom hoda 4 (stok prinimaet 2/4/6/8 i rassylaet sosedyam v 4007) - server delit skorost' na 2\r\n"
          L";   (RecalcMoveSpeed 0x558B39, kak skrytnost' 112/186). Pryzhok s bega (4024 kod 131) teper' rassylaetsya sosedyam i v\r\n"
          L";   hodu (CharEMotionSync 0x5468C1). Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/crouch-speed-jump-relay-p80.md\r\n",
          kCrouchSpeedJumpRelay, ARRAYSIZE(kCrouchSpeedJumpRelay) },
        { L"P81_ActionCodeGuard",
          L"; * NASHA pravka (reshenie vladeltsa 2026-10-24, dyra stoka B-07): CharEMotionSync (4024) prinimal lyuboy kod\r\n"
          L";   100..400. Teper kod vne AllowedCodes ot ne-operatora otbrasyvaetsya do zapisi statusa (0x5468E1, stoya) i pered\r\n"
          L";   rassylkoy 4025 v hodu (0x546952, put P80); zvanie 'Dancer' (112/113) - ne chashche DanceCountMinSec (0x546978).\r\n"
          L";   Zhurnal ac.other 88..90. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/action-code-guard-p81.md\r\n",
          kActionCodeGuard, ARRAYSIZE(kActionCodeGuard) },
        { L"P82_FuncCoolTimeExt",
          L"; * NASHA pravka (reshenie koordinatora 2026-10-24): otkat funktsionalnogo predmeta po kodu stok derzhit v tablitse\r\n"
          L";   na 600 kodov - dlya koda >= 600 primenenie VSEGDA otklonyalos kodom 8 ('Otkat:'), mounty fable 600..637 ne\r\n"
          L";   rabotali. Teper - svoya tablitsa s toy zhe mehanikoy (proverka/registratsiya/5452/sohranenie 2157/vosstanovlenie\r\n"
          L";   5465/sbros), gruppovoy otkat - stok. Strazh vosstanovleniya zakryvaet porchu CUser kodom >= 600 iz BD.\r\n"
          L";   Zhurnal ac.other 91..93. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/func-cooltime-ext-p82.md\r\n",
          kFuncCoolTimeExt, ARRAYSIZE(kFuncCoolTimeExt) },
        { L"P85_PremiumCartRows",
          L"; * NASHA pravka (slovo vladeltsa 2026-10-25, defekt originala): korzina premium-magazina 5070 (do 7 pozitsiy) -\r\n"
          L";   CharChargeShopBuy summiruet tseny vseh, a shlyuzu gp7 (sub_4F60E0 vetka 137) otdaval tolko kod pozitsii 0 -\r\n"
          L";   prihodila 1 veshch. Teper v hvost zaprosa (pole channel @112) pishutsya metka CRT7 i 7 kodov (0x4F62AC).\r\n"
          L";   Para: DBPatch P85, SQL premrows_fix_20261025.sql, gp7-server/server.js. Zhurnal ac.other 100..101.\r\n"
          L";   0 = stokovyy zapros (shlyuz s rejectCartTotal otkazhet korzine bez spisaniya).\r\n",
          kEnabled, ARRAYSIZE(kEnabled) },
        { L"P87_Job4StartSkills",
          L"; * ISPRAVLENIE defekta originala (2026-10-26): 4-ya professiya na servere - podklass CUser+0x191, osnovnoy klass\r\n"
          L";   CUser+0x190 ostayotsya 3/14/25. Posle smeny professii sub_481CE0 vydaval navyki stroki OSNOVNOGO klassa - stroki\r\n"
          L";   podklassa 4/15/26 ChangeJobAddSkillTable (startovye navyki 4-y professii) ne vydavalis nikogda. Teper - stroka\r\n"
          L";   podklassa; dlya 6/17/28 strok v tablitse net - stok (reshenie o strokah - za vladeltsem). Zhurnal ac.other 106..108.\r\n"
          L";   Protokol ne menyaetsya. Dokument: AstoryServer/Docs/GameServer/job4-start-skills-p87.md\r\n",
          kJob4StartSkills, ARRAYSIZE(kJob4StartSkills) },
        { L"P88_TitleEvents",
          L"; * PORT (zadacha vladeltsa 2026-10-26 'vklyuchi zvaniya 187-205, poluchit' mogut vse'): u 188..205 v stoke net ni odnogo\r\n"
          L";   vyzova nakopitelya zvaniy sub_54A050 (u 187 - tolko iz rezultata dushi s pribavkoy 0). Sobytiya berutsya iz stokovyh\r\n"
          L";   obrabotchikov: voyna fraktsiy, sbros navykov, sklad, remeslo 2666, kopka, pitomets, podbor. Vydacha, 2256/2257, 6065,\r\n"
          L";   ochki - stokovye. Zhurnal ac.other 109..111. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/title-events-p88.md\r\n",
          kTitleEvents, ARRAYSIZE(kTitleEvents) },
        { L"P89_Job4GateBranch",
          L"; * ISPRAVLENIE defekta originala (2026-10-26): geyt startovyh navykov 4-y professii sub_481CE0 proveryal '0 ochkov\r\n"
          L";   v kategoriyah 4-y professii' parami 10/11, 12/13, 14/15, a derevya 4-y professii - 10/11/12 (kategoriy 13-15 v\r\n"
          L";   SkillInfo net). U luchnika (15/17) i maga (26/28) s rovno 60 ochkami v obychnyh derevyah kazhdoe izuchenie navyka\r\n"
          L";   svoego dereva povtorno vydavalo startovuyu stroku - uroven navykov 0. Teper - kategoriya svoey vetki. Stavitsya\r\n"
          L";   posle P87. Zhurnal ac.other 112..114. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/job4-gate-branch-p89.md\r\n",
          kJob4GateBranch, ARRAYSIZE(kJob4GateBranch) },
        { L"P91_ExpCapRate",
          L"; * ISPRAVLENIE (2026-10-26, reshenie vladeltsa): stok rezhet opyt za moba do 1/9 urovnya POSLE reyta - na ur. 1-3\r\n"
          L";   x2/x3/x5 dayut odno i to zhe (zhaloba 'Exp x3 dayot tolko 10%'). Teper potolok x max(1, fEvent + LuckyHours).\r\n"
          L";   Zadaniya/GM/zelye P75 ne zatronuty. Zhurnal ac.other 118/119. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/exp-cap-rate-p91.md\r\n",
          kExpCapRate, ARRAYSIZE(kExpCapRate) },
        { L"P92_HostileTargetGuard",
          L"; * ISPRAVLENIE (2026-10-26, zadacha vladeltsa 'navyki dlya mobov i vrazhdebnyh igrokov veshayutsya na mirnyh'):\r\n"
          L";   ploshchadnye proki 'Vzryv' 173 i hranitelya 248 bili vseh igrokov vokrug, otrazhenie 220 sveryalos naoborot,\r\n"
          L";   'Kleymo lda' 1004 shlo na mirnyh. Teper vrednyy effekt - tolko na vrazhdebnogo po pravilu originala (udar 4201).\r\n"
          L";   Zhurnal ac.other 121..123. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/hostile-target-guard-p92.md\r\n",
          kHostileTargetGuard, ARRAYSIZE(kHostileTargetGuard) },
        { L"P94_SoulmateSelfEcho",
          L"; * ISPRAVLENIE (2026-10-26, bag Player17 'panel Druga pokazyvaet svoyo imya'): nomer slota Druga server beryot iz\r\n"
          L";   ustarevshey stroki dbo.CharPos (portalnyy vyhod bez vhoda na novuyu kartu, restart stoyki) - soobshcheniya pary\r\n"
          L";   uhodili samomu sebe (5110 'Drug voshyol' o sebe) ili postoronnemu igroku. Teper takie soobshcheniya ne otpravlyayutsya.\r\n"
          L";   Zhurnal ac.other 130..132. Protokol ne menyaetsya. Koren - SQL charpos_fix_20261026.sql (sbros CharPos).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/soulmate-self-echo-p94.md\r\n",
          kSoulmateSelfEcho, ARRAYSIZE(kSoulmateSelfEcho) },
        { L"P95_ItemUseGuard",
          L"; * ISPRAVLENIE (2026-10-29, bagi igrokov '7.Information error in empty inventory' i kod 11 pri vskrytii korobok,\r\n"
          L";   'buster otkryvaetsya nizhe urovnya'): klient vybiraet yacheyki pozitsiy korobki po SVOEY tablitse predmetov, a server\r\n"
          L";   sveryaet po svoey - teper pozitsii raskladyvayutsya po pravilu servera; min. uroven korobki/bustera/rashodnika\r\n"
          L";   proveryaetsya (defekt originala). Zhurnal ac.other 140..144. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/item-use-guard-p95.md\r\n",
          kItemUseGuard, ARRAYSIZE(kItemUseGuard) },
        { L"P96_InventoryX2",
          L"; * INVENTAR ×2 (2026-10-30): konteyner 1 (sumka) perenositsya v bokovoye khranilishche DLL g_bag[550][60][57].\r\n"
          L";   9 routerov case 1, recvDB, 4045, PrimiumSum, EventItem, ochistka sub_4A2DC0. 19 imm 1E->3C (granitsa 30->60).\r\n"
          L";   Staraya oblast CUser+0x4BC..0xB69 - kanareyка (vid 145). Zhurnal ac.other 145..147.\r\n"
          L";   ★ Vykladka TOLKO vmeste s DBPatch P96 i SQL-migratsiyey (PLAN §4).\r\n"
          L";   Dokument: Reports/inventory_x2/P96_P97_BRIEF.md\r\n",
          kInventoryX2, ARRAYSIZE(kInventoryX2) },
        { L"P97_WeightU16",
          L"; * VES u16 (2026-10-30): pole vesa predmetov — unsigned short (0..65535), potolok 60000.\r\n"
          L";   129 movsx->movzx, 10 pereschotov registrom, 4 potolka 30000->60000, 5 trampolinov CraftEnter.\r\n"
          L";   ★ GM_sitxovski: MaxWeight 64000 (> potolka 60000) — P97 korrekten; potolok 60000 tolko dlya pribavki predmetom.\r\n"
          L";   Dokument: Reports/inventory_x2/P96_P97_BRIEF.md\r\n",
          kWeightU16, ARRAYSIZE(kWeightU16) },
        { L"P98_PremiumStackAmount",
          L"; * ISPRAVLENIE (2026-10-30, bagi igrokov 'znak ohoty 75521: Vse = 0, sdacha kodom 6', svitki iz premium-magazina\r\n"
          L";   s kolichestvom 0): premium-pochta 11006 stroila zapis stopochnogo predmeta s Amount 0 (a pri nalichii stopki N -\r\n"
          L";   s Amount N, dyup). Teper kazhdaya yacheyka dostavki - stopka iz 1 sht. Zhurnal ac.other 150..152.\r\n"
          L";   Protokol ne menyaetsya. Remont uzhe isporchennyh zapisey - SQL v deploy_p98.py.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/premium-stack-amount-p98.md\r\n",
          kPremiumStackAmount, ARRAYSIZE(kPremiumStackAmount) },
        { L"P99_UpgradeSplitStone",
          L"; * ISPRAVLENIE (2026-10-31, okno 'Razdelenie uluchsheniya' 50500): stok vydaval gotovyy kamen chuzhogo tipa -\r\n"
          L";   oruzhie poluchalo 363 (kamen DOSPEHA, 206), prochee - 401 (kamen ORUZHIYA, 204); klient klal ih tolko na chuzhoy tip.\r\n"
          L";   Protokol ne menyaetsya. Dokument: AstoryServer/Docs/GameServer/upgrade-split-stone-p99.md\r\n",
          kUpgradeSplitStone, ARRAYSIZE(kUpgradeSplitStone) },
        { L"P100_ChargeStack",
          L"; * ISPRAVLENIE (2026-11-01, reshenie vladelca): zaryady specpredmetov pri LYUBOM poluchenii (pochta, korobki, gacha,\r\n"
          L";   kvest, obmen, lavka, aukcion, sklad...) skladyvayutsya v yacheyku togo zhe klyucha, a ne zanimayut novuyu.\r\n"
          L";   Protokol ne menyaetsya; processy BD Joy1 - otdelnaya volna SQL. Proekt: Reports/item_dedup/charges/P100_PROJECT.md\r\n",
          kChargeStack, ARRAYSIZE(kChargeStack) },
        { L"P101_CashGift",
          L"; * PODAROK IZ KESH-MAGAZINA (2026-11-02, reshenie vladelca): otpravlyayushchaya polovina GameServer (5072/5074) vosstanovlena\r\n"
          L";   po kontraktam; dengi - cherez GP7 (0x52/0x53: HOLD do otpravki, COMMIT/REFUND po 5077). Zhurnal ac.other 158..163.\r\n"
          L";   Proekt: Reports/cash_gift/PROJECT_P101.md; itog p101/DLL_DONE.md\r\n",
          kCashGift, ARRAYSIZE(kCashGift) },
        { L"P102_DefectFixes",
          L"; * ISPRAVLENIE (2026-11-02, reshenie vladelca): defekty originala vydachi - razborka (zaryady i ves specpredmeta),\r\n"
          L";   kniga rybaka (@Amount; oshibka BD bez porchi ochkov rybalki), snyatie lotov 9910 (mesto do cikla),\r\n"
          L";   svitok voskresheniya 5450 (otkaz do BD, esli zhiv). Protokol ne menyaetsya.\r\n"
          L";   Zhurnal ac.other 164..167. Razbor: Reports/item_dedup/charges (P102)\r\n",
          kDefectFixes, ARRAYSIZE(kDefectFixes) },
        { L"P103_InFlightFixes",
          L"; * ISPRAVLENIE (2026-11-04): 'v polete' - korobka 6096 pri otkaze BD snimaet zapisi P100 (peremeshchenie yacheek bez\r\n"
          L";   60-sekundnogo otkaza), 5450 i avtoprimenenie - zamok gruppy/koda otkata do otveta BD (zaryad ne teryaetsya).\r\n"
          L";   Protokol ne menyaetsya. Zhurnal ac.other 168..170. Razbor: Reports/item_dedup/p103/P103_REPORT.md\r\n",
          kInFlightFixes, ARRAYSIZE(kInFlightFixes) },
        { L"P106_FriendAcceptNotify",
          L"; * ISPRAVLENIE (2026-11-05, sessiya friend-accept): UPFriendAdd flag 2 (u priglasivshego uzhe byl prinyavshiy) vstavlyaet\r\n"
          L";   stroku prinyavshego, no stok ne slal emu 4151 - ni soobshcheniya, ni zapisi v spiske do perezahoda.\r\n"
          L";   Protokol ne menyaetsya, zhurnala net. Dokument: AstoryServer/Docs/GameServer/friend-accept-notify-p106.md\r\n",
          kFriendAcceptNotify, ARRAYSIZE(kFriendAcceptNotify) },
        { L"P107_CantActGate",
          L"; * ISPRAVLENIE (2026-11-05, sessiya stun-attack): obshchiy gejt 'ne mozhet deystvovat' sub_484E40 pri oglushenii (3) i\r\n"
          L";   strahe (4) vsegda propuskal ataku i navyki (zadumano - tolko 736/984), 'Moshchnoe oglushenie' (14) ne proveryal.\r\n"
          L";   Protokol ne menyaetsya, zhurnala net. Otchet: AstoryServer/Docs/GameServer/cant-act-gate-p107.md\r\n",
          kCantActGate, ARRAYSIZE(kCantActGate) },
        { L"P108_DungeonRelogEntry",
          L"; * ISPRAVLENIE (2026-11-05, sessiya dungeon-relog, trebovanie vladelca): vyhod, obryv i zakrytie klienta v danzhe\r\n"
          L";   (DisConnectUser, paket 2003 -> UPLogoutGame) sohranyali kletku kak est' - povtornyy vhod v tu zhe tochku (propusk\r\n"
          L";   prohozhdeniya, eksployt-marshrut). Teper' - tochka vhoda danzha. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/dungeon-relog-entry-p108.md\r\n",
          kDungeonRelogEntry, ARRAYSIZE(kDungeonRelogEntry) },
        { L"P109_SelfHitNoDamage",
          L"; * ISPRAVLENIE (2026-11-05, sessiya job4-skills, zhaloba 'uron pri King's Rage'): NpcServer schital uron navyka po zapisi\r\n"
          L";   celi 'sam kaster' (samo-kast 611/612/616 s mnozhitelem ms > 0), GameServer vychital ego iz HP kastera.\r\n"
          L";   Protokol ne menyaetsya. Dokument: AstoryServer/Docs/GameServer/self-hit-no-damage-p109.md\r\n",
          kSelfHitNoDamage, ARRAYSIZE(kSelfHitNoDamage) },
        { L"P110_Job4PointPools",
          L"; * ISPRAVLENIE (2026-11-05, sessiya job4-points, zhaloba 'mozhno vyiti za limit ochkov 4-y professii, uzhe -8'): 5253\r\n"
          L";   proveryal tol'ko obshchiy schet ochkov - navyk 4-y professii bral ochki osnovnyh derev'ev (limit 110), osnovnoy - ochki\r\n"
          L";   4-y professii. Protokol ne menyaetsya (5254 kod 8/3 - iz tablicy klienta originala). Dannye igrokov - SQL\r\n"
          L";   AstoryServer/SQL/job4_points_fix_20261105.sql. Dokument: AstoryServer/Docs/GameServer/job4-point-pools-p110.md\r\n",
          kJob4PointPools, ARRAYSIZE(kJob4PointPools) },
        { L"P111_HatchSupplement",
          L"; * ISPRAVLENIE (2026-11-05, sessiya pet-hatch-summon, zhaloba 'dobavka vylupleniya ne rabotaet'): 6102 pribavlyal znachenie\r\n"
          L";   dobavki (30) k shansu v stotysyachnyh - +0,03 p.p. vmesto +30% iz podskazki originala; podtip slota 3 ne sveryalsya.\r\n"
          L";   Protokol ne menyaetsya (6103 kod 5 - shtatnyy otkaz stoka). Dokument: AstoryServer/Docs/GameServer/hatch-supplement-p111.md\r\n",
          kHatchSupplement, ARRAYSIZE(kHatchSupplement) },
        { L"P112_PartyExpSpread",
          L"; * ISPRAVLENIE (2026-11-06, sessiya pet-hatch-summon, slovo vladel'tsa 'NO EXP AND NO LOOT FOR EVERYONE'): razbros urovney otryada\r\n"
          L";   v opyte videl tol'ko bivshih s raznitsey <= 6, a minimum startoval s 59. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/party-exp-spread-p112.md\r\n",
          kPartyExpSpread, ARRAYSIZE(kPartyExpSpread) },
        { L"P114_BoardExpBonus",
          L"; * ISPRAVLENIE (2026-11-07, paket 11 bag 8, slovo vladel'tsa 'EXP rewards from Quest Board missions are not boosted by EXP potions'):\r\n"
          L";   opyt zadaniy dosok shyol mimo GetExpUpDownValue. Protokol ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/board-exp-bonus-p114.md\r\n",
          kBoardExpBonus, ARRAYSIZE(kBoardExpBonus) },
        { L"P117_PlusPackOnce",
          L"; * ISPRAVLENIE (2026-11-09, paket 19 bag 9, reshenie vladel'tsa 'zapretit' primenenie novogo zel'ya urovnya, poka deystvuet prezhnee'):\r\n"
          L";   povtor nabora urovnya tratil predmet i nachinal srok zanovo. Protokol ne menyaetsya (5451 kod 0x10 - shtatnyy kod otkaza).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/plus-pack-once-p117.md\r\n",
          kPlusPackOnce, ARRAYSIZE(kPlusPackOnce) },
        { L"P120_MineTravel",
          L"; * NASHA pravka (2026-11-09, paket 20, reshenie vladel'tsa 'make possible to travel to Mine'): karta 23 tipa 6 ne poluchala\r\n"
          L";   potoka, a 6746/6749 (knopki NPC shakhty) server ne obrabatyval. Protokol ne menyaetsya (5055 kod 1 - kak u kristalla).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/mine-travel-p120.md\r\n",
          kMineTravel, ARRAYSIZE(kMineTravel) },
        { L"P118_AuctionTradeBlock",
          L"; * ISPRAVLENIE (2026-11-09, paket 20 bag 3, slovo vladel'tsa 'any trade request should be canceled by server while communicating\r\n"
          L";   with auction'): server ne znal ob auktsione, zayavka i soglasie obmena prokhodili. Protokol ne menyaetsya (shtatnye 5283/5285).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/auction-trade-block-p118.md\r\n",
          kAuctionTradeBlock, ARRAYSIZE(kAuctionTradeBlock) },
        { L"P121_CharRenameGuard",
          L"; * ISPRAVLENIE (2026-11-09, paket 20 bag 8, reshenie vladel'tsa 'Da, P121'): predmet smeny imeni (kategoriya 111, kod 357) cherez 5450\r\n"
          L";   spisyvalsya v DB 2140, imya ne menyalos' (klient alpha-7.0.0 ne znaet okna 7900). Protokol ne menyaetsya (5451 - shtatnyy otkaz).\r\n"
          L";   Proverku imeni 6138/6140 delaet P68 (Mode=1 stavit deploy_p121.py). Dokument: AstoryServer/Docs/GameServer/char-rename-guard-p121.md\r\n",
          kCharRenameGuard, ARRAYSIZE(kCharRenameGuard) },
        { L"P122_PetFuncFloor",
          L"; * NASHA pravka (2026-11-09, paket 20 bag 4, reshenie vladel'tsa 'Ne nizhe tablitsy'): funktsiya pitomtsa na nizkom urovne\r\n"
          L";   i pri nizkoy sytosti davala +0% / +1%. Protokol ne menyaetsya (to zhe pole zapisi pitomtsa).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/pet-func-floor-p122.md\r\n",
          kPetFuncFloor, ARRAYSIZE(kPetFuncFloor) },
        { L"P123_GmMapJump",
          L"; * NASHA pravka (2026-11-09, paket 20, reshenie vladel'tsa 'Da, P123'): GM Ctrl+klik po karte mira/mini-karte perenosit na lyubuyu\r\n"
          L";   kartu. U stoka 6010 - tol'ko svoya karta. Klient alpha-7.1.0 shlyot tol'ko telo 4 b - dlya nego nichego ne menyaetsya.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/gm-map-jump-p123.md\r\n",
          kGmMapJump, ARRAYSIZE(kGmMapJump) },
        { L"P127_AdminBridge",
          L"; * NASHA pravka (2026-11-18, volna A2 'zhivoy kanal', resheniya vladel'tsa 18.11): most admin-tsentra -> rabotayushchiy GameServer.\r\n"
          L";   Protokol klienta ne menyaetsya (tol'ko stokovye 4101/3113/5055). Pervaya vykladka - Mode=0.\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/admin-bridge-p127.md\r\n",
          kAdminBridge, ARRAYSIZE(kAdminBridge) },
        { L"P128_EventBadgeAll",
          L"; * NASHA pravka (2026-11-21, A5.10, slovo vladel'tsa): znachok sobytiya Event.dat (6039/6041) vsem igrokam, ne tol'ko operatoru.\r\n"
          L";   Klient Astory na 6039/6041 tol'ko zazhigaet/gasit znachok (bez stroki v chat).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/event-badge-all-p128.md\r\n",
          kEventBadgeAll, ARRAYSIZE(kEventBadgeAll) },
        { L"P129_ChatLog",
          L"; * NASHA pravka (2026-11-22, A6.12, reshenie vladel'tsa 22.11 N5): zhurnal chata (90 sutok) i zaglushka chata na srok.\r\n"
          L";   Skhema joylog1.chat (AstoryServer/Docs/SQL/chat_01_migrate.sql). Pervaya vykladka - Mode=0 (tol'ko zhurnal).\r\n"
          L";   Dokument: AstoryServer/Docs/GameServer/chat-log-p129.md\r\n",
          kChatLog, ARRAYSIZE(kChatLog) },
    };

    // ── состояние ───────────────────────────────────────────────────────────
    wchar_t g_path[MAX_PATH] = L"";
    wchar_t g_base[MAX_PATH] = L"";
    bool    g_created        = false;

    // Кодировка существующего файла: UTF-16LE (BOM) или ANSI.
    bool FileIsUtf16()
    {
        HANDLE h = CreateFileW(g_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return true; }
        BYTE  bom[2] = {};
        DWORD got = 0;
        ReadFile(h, bom, 2, &got, nullptr);
        CloseHandle(h);
        return got == 2 && bom[0] == 0xFF && bom[1] == 0xFE;
    }

    // Дописать текст в КОНЕЦ файла в его собственной кодировке.
    // (администратор мог пересохранить ini как ANSI — тогда пишем cp1251)
    void AppendText(const wchar_t* text)
    {
        const bool utf16 = FileIsUtf16();
        HANDLE h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { return; }
        SetFilePointer(h, 0, nullptr, FILE_END);
        DWORD w = 0;
        if (utf16)
        {
            WriteFile(h, text, (DWORD)(lstrlenW(text) * sizeof(wchar_t)), &w, nullptr);
        }
        else
        {
            int need = WideCharToMultiByte(1251, 0, text, -1, nullptr, 0, "?", nullptr);
            char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, need);
            if (buf)
            {
                WideCharToMultiByte(1251, 0, text, -1, buf, need, "?", nullptr);
                WriteFile(h, buf, (DWORD)(need - 1), &w, nullptr);
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }
        CloseHandle(h);
    }

    // Полный текст одной секции: комментарии + [имя] + ключи со значениями по умолчанию.
    void BuildSectionText(const IniSection& s, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (s.comment) { lstrcpynW(out, s.comment, cch); }
        wchar_t tmp[768];
        wsprintfW(tmp, L"[%s]\r\n", s.name);
        lstrcatW(out, tmp);
        for (int i = 0; i < s.nkeys; ++i)
        {
            if (s.keys[i].comment) { lstrcatW(out, s.keys[i].comment); }
            wsprintfW(tmp, L"%s=%s\r\n", s.keys[i].key, s.keys[i].def);
            lstrcatW(out, tmp);
        }
        lstrcatW(out, L"\r\n");
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
        wsprintfW(g_path, L"%s\\patches.ini", dir);

        if (GetFileAttributesW(g_path) == INVALID_FILE_ATTRIBUTES) { CreateFull(); }
        return GetFileAttributesW(g_path) != INVALID_FILE_ATTRIBUTES;
    }

    void MergeMissing()
    {
        if (g_created)
        {
            Log::Line(L"Конфиг : создан с нуля со значениями по умолчанию.");
            return;
        }

        const int fileVer = GetInt(L"General", L"Version", 0);
        int addedSections = 0, addedKeys = 0;
        wchar_t buf[8192];
        // ★ EAC ред. 3 (E1-20): был ли у P73 свой ключ учётки соулмейта ДО слияния (иначе его допишет общий цикл значением
        //   шаблона, а нужно — текущее значение ключа P48, по которому P73 работал в ред. 2).
        const bool p73SoulHad = SectionExists(L"P73_EacBridge") && KeyExists(L"P73_EacBridge", L"SoulMateSessionAccount");

        for (const auto& s : kSections)
        {
            if (!SectionExists(s.name))
            {
                BuildSectionText(s, buf, ARRAYSIZE(buf));
                AppendText(buf);
                ++addedSections;
                Log::Line(L"    + секция [%s] дописана со значениями по умолчанию", s.name);
                continue;
            }
            for (int i = 0; i < s.nkeys; ++i)
            {
                if (KeyExists(s.name, s.keys[i].key)) { continue; }
                WritePrivateProfileStringW(s.name, s.keys[i].key, s.keys[i].def, g_path);
                ++addedKeys;
                Log::Line(L"    + ключ [%s] %s=%s дописан (значение по умолчанию)",
                          s.name, s.keys[i].key, s.keys[i].def);
            }
        }

        // ★ Version 46 (P74 ред. 2): прежнее умолчание RegenMinIntervalMs=250 → 0 (выброшенное прореживанием значение не
        //   дошлётся «хвостом»). Меняем ТОЛЬКО ровно 250 у файлов версии 45 (P74 появился в 45; иное значение — выбор администратора).
        if (fileVer == 45 && SectionExists(L"P74_HpSectorSync") && KeyExists(L"P74_HpSectorSync", L"RegenMinIntervalMs")
            && GetInt(L"P74_HpSectorSync", L"RegenMinIntervalMs", -1) == 250)
        {
            WritePrivateProfileStringW(L"P74_HpSectorSync", L"RegenMinIntervalMs", L"0", g_path);
            Log::Line(L"    = ключ [P74_HpSectorSync] RegenMinIntervalMs=250 (прежнее умолчание v45) -> 0 (умолчание v46: без прореживания)");
        }

        if (!p73SoulHad)
        {
            // ★ EAC ред. 3: ключ P73 только что появился — перенести в него значение P48 (поведение REBIND не меняется).
            const bool v = GetBool(L"P48_KickAutoBlock", L"SoulMateSessionAccount", true);
            WritePrivateProfileStringW(L"P73_EacBridge", L"SoulMateSessionAccount", v ? L"1" : L"0", g_path);
            Log::Line(L"    = ключ [P73_EacBridge] SoulMateSessionAccount=%d — перенесён из [P48_KickAutoBlock] SoulMateSessionAccount", v ? 1 : 0);
        }

        if (addedSections || addedKeys)
        {
            Log::Line(L"Конфиг : слияние — добавлено секций %d, ключей %d; "
                      L"все существующие значения СОХРАНЕНЫ.", addedSections, addedKeys);
        }
        else
        {
            Log::Line(L"Конфиг : все ключи на месте, изменений не потребовалось.");
        }

        if (fileVer != kVersion)
        {
            wchar_t v[16];
            wsprintfW(v, L"%d", kVersion);
            WritePrivateProfileStringW(L"General", L"Version", v, g_path);
            Log::Line(L"Конфиг : миграция Version %d -> %d выполнена "
                      L"(пользовательские значения не тронуты).", fileVer, kVersion);
        }
    }

    const wchar_t* Path()       { return g_path; }
    const wchar_t* BaseDir()    { return g_base; }
    bool           WasCreated() { return g_created; }

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
}
