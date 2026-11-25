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
        // ⚠ Значение ОБЯЗАНО совпадать с Config::kVersion: свежесозданный файл с меньшей версией
        //   DllMain отвергает («Version=N не поддерживается») и не ставит ни одного патча
        //   (поймано сквозным прогоном 12.10.2026 при переходе 5→6).
        //   8 — sec2b (15.10.2026): ключ MaxPendingPerIp в [L07_TrafficEncryption].
        //   9 — L08 (27.10.2026): секция [L08_ListenArrayLeak].
        //   10 — P125 (15.11.2026): секция [P125_DbReconnect].
        //   11 — L09 (21.11.2026): секция [L09_LoginMaintenance].
        { L"Version", L"11",
          L"; Версия формата файла. Меняет только сама DLL при миграции.\r\n" },
        { L"MasterEnable", L"0",
          L"; * ГЛАВНЫЙ ВЫКЛЮЧАТЕЛЬ. 0 = не ставить НИ ОДИН патч (сервер работает как сток).\r\n"
          L";   При создании файла стоит 0 — это проверка каркаса: сервер должен подняться\r\n"
          L";   и создать PatchLog. После успешной проверки поставить 1.\r\n" },
        { L"LogEnabled", L"1",
          L"; Вести лог установки патчей.\r\n" },
    };

    const IniKey kL01[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"LogMac",  L"1", nullptr },
    };

    const IniKey kL03[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"MaxScan", L"256", nullptr },
        { L"LogHits", L"1", nullptr },
    };

    const IniKey kL02[] =
    {
        { L"Enabled", L"1", nullptr },
        { L"LogHits", L"1", nullptr },
    };

    const IniKey kL04[] =
    {
        { L"Enabled",          L"1", nullptr },
        { L"CheckCharList",    L"1", nullptr },
        { L"CheckSelectChar",  L"1", nullptr },
        { L"CheckSoulMate",    L"1", nullptr },
        { L"SoulMateFailOpen", L"0", nullptr },
        { L"LogHits",          L"1", nullptr },
    };

    const IniKey kL05[] =
    {
        { L"Enabled", L"1", nullptr },
    };

    const IniKey kL06[] =
    {
        { L"Enabled",   L"1", nullptr },
        { L"Strict",    L"1", nullptr },
        { L"Lowercase", L"1", nullptr },
        { L"LogBad",    L"1", nullptr },
    };

    const IniKey kL07[] =
    {
        { L"Enabled",     L"0", nullptr },          // ★ по умолчанию ВЫКЛ — сток не меняется
        { L"AllowLegacy", L"1", nullptr },          // 1 — старый клиент (0xFB) без шифрования (переход)
        { L"KeyFile",     L"secure_server.key", nullptr },
        { L"KillOnViolation", L"1", nullptr },      // ★ В7d: 1 — нарушение канала → разрыв штатным DisConnect; 0 — только отброс
        { L"LogPerMinute",    L"30", nullptr },     // ★ В7d: предел строк о нарушениях в PatchLog в минуту (0 — без предела)
        { L"PreHandshakeQueueKB", L"64", nullptr },  // ★ fix2b: очередь кадров до рукопожатия (4101/2253 после accept), КБ; 0 — не копить
        { L"PreHandshakeCloseMs", L"5000", nullptr }, // ★ fix2b: отложенный DisConnect ждёт первых байт клиента, мс; 0 — не откладывать
        { L"PreHandshakeLingerMs", L"150", nullptr }, // ★ fix2c (Н-2): пауза между выдачей отказа и разрывом, мс (сокет закрывается RST)
        { L"TxQueueKB", L"1024", nullptr },           // ★ fix2d (П-1): очередь шифрованных кадров слота при полной досылке стока, КБ; 0 — без очереди
        { L"TxQueueTotalMB", L"64", nullptr },        // ★ fix2e (Ф-1): общий предел очередей моста на процесс, МБ (1…1024); сверх — разрыв слота, ac.other 61 причина 4
        // ★ sec2 (блок В плана альфы, стойка в интернете)
        { L"TxQueueFairKB", L"256", nullptr },        // Е-2: при общем пределе рвётся слот с очередью ≥ средней или ≥ N КБ; лёгкий — нет (сторож вытесняет наибольшую, причина 6)
        { L"HandshakeKeyCache", L"1", nullptr },      // ключ подписи импортируется в CNG один раз (в памяти процесса); 0 — на каждое рукопожатие
        { L"HandshakePool", L"16", nullptr },         // пар ECDH заготовлено фоновой нитью (0…64), каждая одноразовая; 0 — генерация на месте
        { L"ConnPerIpMax", L"120", nullptr },         // новых подключений с одного адреса за окно (0 — без предела); сверх — разрыв до рукопожатия, ac.other 63
        { L"ConnPerIpWindowSec", L"60", nullptr },    // окно предела с адреса, с (1…3600)
        { L"MaxPendingHandshakes", L"64", nullptr },  // незавершённых рукопожатий на процесс (0 — без предела); сверх — новое соединение разорвано, ac.other 64
        { L"HandshakeDeadlineMs", L"10000", nullptr },// срок рукопожатия после подключения, мс (0 — без срока; молчащий сокет — только при AllowLegacy=0), ac.other 65
        { L"AdmissionLogGapMs", L"5000", nullptr },   // строки/журнал видов 64/65 не чаще раза в N мс (подавленные — в value3)
        { L"MaxPendingPerIp", L"16", nullptr },       // ★ sec2b (ревизия SEC2 Н-1): незавершённых рукопожатий с ОДНОГО адреса (0 — без предела); сверх — разрыв, ac.other 64 «from IP»
    };

    const IniKey kL08[] =
    {
        { L"Enabled",      L"1",  nullptr },
        { L"ReuseSlot",    L"1",  nullptr },
        { L"EarlyClear",   L"1",  nullptr },
        { L"LateClear",    L"1",  nullptr },
        { L"LateWaitMs",   L"100", nullptr },
        { L"Sweep",        L"1",  nullptr },
        { L"LogPerMinute", L"30", nullptr },
    };

    // ★ В7d: журнал античита LoginManager (ac.other 56–59). Запускается ТОЛЬКО при L07 Enabled=1 (из L07).
    //   Ключи — как у AsdaPatch [P53_AcJournal] (общий модуль AsdaPatch/src/AcJournal.cpp); PurgeDays=0 —
    //   очистку старых записей делает GameServer, не LoginManager.
    const IniKey kAcJournal[] =
    {
        { L"Enabled",             L"1", nullptr },
        { L"ConnectionString",    L"", nullptr },
        { L"DbConfigFile",        L"..\\DBManager\\DBMng.ini", nullptr },
        { L"DbConfigSection",     L"DB_DNS0_0", nullptr },
        { L"Database",            L"joylog1", nullptr },
        { L"FlushIntervalMs",     L"2000", nullptr },
        { L"BatchMax",            L"500", nullptr },
        { L"QueueCapacity",       L"4096", nullptr },
        { L"PerSessionPerMinute", L"60", nullptr },
        { L"ReconnectSec",        L"30", nullptr },
        { L"FileFallback",        L"1", nullptr },
        // ★ fix2 (СРЕДН-4 integ3): флуд мусорными соединениями (вид 58) при недоступной базе — не больше 3000 событий
        //   в файл в минуту и не больше 256 МБ в сутки (раньше ~10 МБ/мин без предела).
        { L"FileRowsPerMinute",   L"3000", nullptr },
        { L"MaxFileMB",           L"256", nullptr },
        { L"FileDir",             L"", nullptr },
        { L"PurgeDays",           L"0", nullptr },
        { L"ServerName",          L"", nullptr },
        { L"NameCodePage",        L"1251", nullptr },
        { L"LoginTimeoutSec",     L"5", nullptr },
        { L"QueryTimeoutSec",     L"15", nullptr },
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

    // ── [L09_LoginMaintenance] (21.11.2026): отказ входа в режиме обслуживания — стоковым кодом 4101/28 ──
    const IniKey kL09[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как без патча: отказ процедуры (статус 28) уходит клиенту ответом 1004/28.\r\n" },
        { L"Status", L"28",
          L"; * Статус UPUserLogin, который значит «обслуживание» (так отвечает врезка L09 в процедуре; 1…255, не 1…7).\r\n" },
        { L"Code", L"28",
          L"; * Код 4101, который получит клиент. 28 = стоковый «Идут профилактические работы на сервере» (нотис 7017,\r\n"
          L";   соединение не рвётся — как у стокового отказа AcceptIp). Допустимы только коды с текстом у клиента: 13, 15, 20-22, 24-32.\r\n" },
        { L"WorldGate", L"1",
          L"; * 1 = и вход В МИР с выбора персонажа (1016) проверяется процедурой adm.LoginMaintenanceGate (кто вошёл до включения\r\n"
          L";   режима, в мир не войдёт). 0 = только вход в игру (1003).\r\n" },
        { L"WorldMissingSec", L"60",
          L"; * Процедуры adm.LoginMaintenanceGate нет / ошибка запроса — вход в мир пропускается; при сбоях подряд проверка не повторяется\r\n"
          L";   НЕ ДОЛЬШЕ стольких секунд (потолок окна, 5…3600).\r\n" },
        { L"WorldErrorSec", L"2",
          L"; * Окно «без проверки» после ПЕРВОГО сбоя запроса гейта, секунд (1…WorldMissingSec); каждый следующий сбой подряд — вдвое\r\n"
          L";   дольше, успешный ответ сбрасывает. Каждый сбой и восстановление — строка PatchLog (её показывает панель).\r\n" },
        { L"LogPerMinute", L"30",
          L"; * Строк PatchLog об отказах в минуту, не больше (0 — без предела).\r\n" },
    };

    const IniSection kSections[] =
    {
        { L"General",
          L"; ===========================================================================\r\n"
          L"; AsdaReborn — патчи LoginManager. Ставит LoginPatch.dll (грузится через таблицу\r\n"
          L"; импорта LoginManager.exe, ДО точки входа). Патчи применяются В ПАМЯТИ; в файле\r\n"
          L"; LoginManager.exe изменена только таблица импорта, код (.text) не тронут.\r\n"
          L";\r\n"
          L"; Правится при ОСТАНОВЛЕННОМ сервере, читается один раз при старте процесса.\r\n"
          L"; * Ваши правки НЕ ТЕРЯЮТСЯ: при обновлении DLL дописывает только НЕДОСТАЮЩИЕ\r\n"
          L";   ключи и секции, существующие значения остаются как есть.\r\n"
          L"; Лог установки: Log\\Log_Patch\\PatchLog_<ГГГГММДД>.txt\r\n"
          L"; Описание: AstoryServer\\Docs\\LoginManager\\loginpatch-dll-loader.md\r\n"
          L"; ! Не путать с Patch.ini в папке сервера — это автообновление оригинала.\r\n"
          L"; ===========================================================================\r\n",
          kGeneral, ARRAYSIZE(kGeneral) },

        { L"L01_LoginLogMask",
          L"; === L01 (безопасность, НАША ПРАВКА) ======================================\r\n"
          L"\r\n"
          L"; Журнал входа (OTP_Report) писал MD5 пароля открытым текстом, а второе поле\r\n"
          L"; пароля бралось из сырого пакета без завершающего нуля и переполнением чтения\r\n"
          L"; захватывало соседнее поле MAC. Патч маскирует хеш пароля и выводит MAC\r\n"
          L"; отдельным полем с жёстким ограничением 17 байт.\r\n"
          L";   Enabled=0 — журнал как в оригинале (с MD5 и MAC внахлёст).\r\n"
          L";   LogMac=0  — не писать поле MAC вообще (ещё строже; теряется признак для\r\n"
          L";              разбора мультиаккаунта).\r\n",
          kL01, ARRAYSIZE(kL01) },

        { L"L03_LoginSqlRefuse",
          L"; === L03 (безопасность, НАША ПРАВКА) ======================================\r\n"
          L"\r\n"
          L"; Логин и пароль из пакета подставлялись в SQL (EXEC UPUserLogin '%s','%s',…)\r\n"
          L"; без экранирования. Апостроф в этих полях = попытка инъекции (легитимный логин\r\n"
          L"; и пароль апострофов не содержат). Патч при апострофе ОТКАЗЫВАЕТ во входе ещё\r\n"
          L"; до сборки строки, штатным путём (клиент получает отказ). Второй рубеж к\r\n"
          L"; проверке в самой процедуре.\r\n"
          L";   Enabled=0 — поведение оригинала.\r\n"
          L";   MaxScan   — предел сканирования поля (32..4096).\r\n"
          L";   LogHits=1 — строка в журнал на каждый отказ (без текста логина).\r\n",
          kL03, ARRAYSIZE(kL03) },

        { L"L02_LoginSqlLogMask",
          L"; === L02 (безопасность, НАША ПРАВКА) ======================================\r\n"
          L"\r\n"
          L"; При ошибке базы сборщик SQL писал в OLEDB_LOG полный текст запроса. Для входа\r\n"
          L"; это логин, MD5 пароля (без соли), IP и MAC открытым текстом. Патч маскирует\r\n"
          L"; содержимое кавычек в запросе UPUserLogin (форма и длина сохраняются); другие\r\n"
          L"; запросы в логах не меняются. Исполнение запроса не затрагивается.\r\n"
          L";   Enabled=0 — журнал как в оригинале.\r\n"
          L";   LogHits=1 — отметка в журнал установки патчей о факте маскировки.\r\n",
          kL02, ARRAYSIZE(kL02) },

        { L"L04_LoginIdentity",
          L"; === L04 (безопасность, НАША ПРАВКА) ======================================\r\n"
          L"\r\n"
          L"; Номер учётки (UserIndex) брался из пакета и не всегда сверялся с личностью\r\n"
          L"; сессии, подтверждённой на входе. Патч привязывает UserIndex к сессии:\r\n"
          L";   CheckCharList=1    — 1005: список персонажей только для своей учётки;\r\n"
          L";   CheckSelectChar=1  — 1016: сверка и для режима 1 (вход «душой»), не только 0 (обычный);\r\n"
          L";   CheckSoulMate=1    — 1016 режим 2 (вход персонажем соулмейта): чужой UserIndex в пакете\r\n"
          L";                        обязан быть MateUserindex учётки сессии (UPCharExist), иначе отказ 1027/3;\r\n"
          L";   SoulMateFailOpen=0 — если запрос UPCharExist не выполнился: 0 — отказ, 1 — пропустить как сток.\r\n"
          L";   Enabled=0 — поведение оригинала; LogHits=1 — строки в журнал.\r\n",
          kL04, ARRAYSIZE(kL04) },
        { L"L05_LogoutMd5Len",
          L"; === L05 (дефект оригинала, НАША ПРАВКА) ==================================\r\n"
          L"\r\n"
          L"; Опкоды 1010 (логаут) и 1028 (возврат из игры) сверяли MD5 тела по 61 байту, а клиент\r\n"
          L"; подписывает 32 — проверка не сходилась никогда (прежний образ её просто обходил).\r\n"
          L"; Патч правит длину на 32: проверка включена и сходится. Enabled=0 — сток (вечный отказ).\r\n",
          kL05, ARRAYSIZE(kL05) },
        { L"L06_LoginMac",
          L"; === L06 (античит П5, НАША ПРАВКА) =======================================\r\n"
          L"\r\n"
          L"; Сервер вызывал EXEC UPUserLogin с ПУСТЫМ 5-м аргументом (@Mac) — переменная в кадре\r\n"
          L"; обработчика никогда не заполнялась, хотя клиент присылает MAC в cred-блоке (+113,\r\n"
          L"; 17 символов xx-xx-xx-xx-xx-xx). Поэтому LogInfo.Mac пуст и отчёт «мультиаккаунт» слеп.\r\n"
          L"; Патч подставляет MAC из пакета (та же площадка, что L03; ставится после него).\r\n"
          L";   Enabled=0   — как в оригинале (в процедуру уходит пустая строка).\r\n"
          L";   Strict=1    — принимать только ровно 17 символов вида hh-hh-hh-hh-hh-hh; 0 — любой\r\n"
          L";                 набор из [0-9a-fA-F-] до 17 символов. Всё прочее (мусор, апостроф) → пусто.\r\n"
          L";   Lowercase=1 — A-F приводятся к a-f (единый регистр для группировки по MAC).\r\n"
          L";   LogBad=1    — отметка в журнал, когда непустое поле MAC отброшено (первые 20).\r\n",
          kL06, ARRAYSIZE(kL06) },
        { L"L07_TrafficEncryption",
          L"; === L07 (шифрование трафика, НАША ПРОСЛОЙКА) =============================\r\n"
          L"\r\n"
          L"; Прослойка AsdaSecure поверх старого протокола: ECDH P-256 на подключение,\r\n"
          L"; подпись сервера ECDSA (ключ вшит в клиент), AES-256-GCM с номером кадра.\r\n"
          L"; Enabled=0 — сток (трамплины не ставятся). При Enabled=1 нужен файл закрытого ключа\r\n"
          L"; KeyFile рядом с LoginManager.exe (кладёт владелец, генерит keygen); нет файла —\r\n"
          L"; шифрование не включится. AllowLegacy=1 — старый клиент (первый байт 0xFB) идёт без\r\n"
          L"; шифрования на время перехода; 0 — только зашифрованные клиенты (0xA5).\r\n"
          L"; Порядок включения на dev: сначала Enabled=1 здесь (старые клиенты ещё работают),\r\n"
          L"; потом в клиенте cvar asda.Net.Secure=1. Откат — Enabled=0.\r\n"
          L"; ★ В7d: файл ключа проверяется при старте (104 б, метка ASDAKEY1); негодный — патч НЕ ставится\r\n"
          L"; (сток, старый протокол), причина в PatchLog. KillOnViolation=1 — нарушение канала (порча тега,\r\n"
          L"; повтор номера кадра, мусор до рукопожатия, длина кадра, старый клиент при AllowLegacy=0) →\r\n"
          L"; разрыв штатным Ciocp::DisConnect + строка PatchLog (не больше LogPerMinute в минуту) + журнал\r\n"
          L"; ac.other виды 56–59 (секция [P53_AcJournal] ниже); 0 — кадр только отбрасывается (откат).\r\n",
          kL07, ARRAYSIZE(kL07) },
        { L"P53_AcJournal",
          L"; === Журнал античита LoginManager (★ В7d) ================================\r\n"
          L"\r\n"
          L"; Общий модуль журнала (как у GameServer): события ac.other 56–59 от L07 — в базу joylog1\r\n"
          L"; одним пакетом из фонового потока (вход игроков не ждёт). Запускается ТОЛЬКО при\r\n"
          L"; [L07_TrafficEncryption] Enabled=1. База недоступна — файл Log\\Log_AcJournal\\*.sql.\r\n"
          L"; Enabled=0 — без журнала (строки остаются в PatchLog). PurgeDays=0 — чистит GameServer.\r\n",
          kAcJournal, ARRAYSIZE(kAcJournal) },
        { L"L08_ListenArrayLeak",
          L"; === L08 (дефект оригинала, НАША ПРАВКА) ==================================\r\n"
          L"\r\n"
          L"; Массив активных подключений копил «мёртвые» копии слота: соединение, закрытое сразу после\r\n"
          L"; connect, снималось (Clear) раньше, чем добавлялось (SetEmpty), и запись оставалась навсегда.\r\n"
          L"; Пинг-сторож считал пропуски по каждой копии — игрок на этом слоте получал окно «соединение\r\n"
          L"; потеряно» (1098) через 4–8 с после входа; при 550 записях вход отказывал всем.\r\n"
          L";   ReuseSlot=1    — повторный SetEmpty слота с живой записью не добавляет вторую (переиспользует).\r\n"
          L";   EarlyClear=1   — соединение уже закрыто к моменту ProcConnect → запись снимается сразу.\r\n"
          L";   LateClear=1    — кадр разрыва пришёл, когда слот уже занят новым соединением (сокет живой дольше\r\n"
          L";                    LateWaitMs мс) → запись нового соединения не снимается, сбрасывается только прежний вход.\r\n"
          L";   Sweep=1        — перед пинг-сторожем (раз в 8 с) удаляются записи-сироты, счётчик сверяется.\r\n"
          L";   LogPerMinute   — предел строк о событиях в PatchLog в минуту (0 — без предела).\r\n"
          L";   Enabled=0 — поведение оригинала.\r\n",
          kL08, ARRAYSIZE(kL08) },
        { L"P125_DbReconnect",
          L"; === P125 (дефект оригинала, НАША ПРАВКА, 15.11.2026) =====================\r\n"
          L"\r\n"
          L"; После обрыва связи с SQL Server LoginManager отвечал на каждый вход «Login failed. Error 0»\r\n"
          L"; ([LOGIN] UPUserLogin Error) до перезапуска: сток открывает источник и 10 сессий один раз при\r\n"
          L"; старте и никогда не открывает заново. Патч: вызов Execute в sub_40F440 (0x40F7A9, 5 б) идёт\r\n"
          L"; через LoginPatch — при обрыве сессия открывается заново и запрос повторяется один раз.\r\n"
          L"; Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p125.md\r\n",
          kDbReconnect, ARRAYSIZE(kDbReconnect) },
        { L"L09_LoginMaintenance",
          L"; === L09 (НАША ПРАВКА, 21.11.2026; админ-центр А5.3) ======================\r\n"
          L"\r\n"
          L"; Режим обслуживания: решение принимает процедура UPUserLogin (врезка L09, таблица Joy1 adm.LoginMaintenance):\r\n"
          L"; учётке вне 1…5000 она отвечает статусом 28. Сток прочие статусы пересылает клиенту как 1004/<статус>\r\n"
          L"; (клиент пишет «ошибка входа 28»). Патч меняет ЭТОТ ответ на стоковый отказ 4101 код 28 = нотис 7017\r\n"
          L"; «Идут профилактические работы на сервере» (так сток отвечает по AcceptIp.ini). Площадка — общий вызов\r\n"
          L"; отправки 1004 обработчика входа (call 0x415A40 @0x407B2F, 5 б); прочие статусы не трогаются.\r\n"
          L"; Вход в мир (1016): перед EXEC UPCharSoulState (call 0x40F440 @0x40B41A) — EXEC adm.LoginMaintenanceGate.\r\n"
          L"; Описание: AstoryServer\\Docs\\LoginManager\\L09-login-maintenance.md\r\n",
          kL09, ARRAYSIZE(kL09) },
        // Секции патчей добавляются сюда (по одной на патч, имя = PatchEntry::section).
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
