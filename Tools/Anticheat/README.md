# Tools/anticheat - суточный отчёт античита (мера 4, только чтение) и журнал дел (В6)

Скрипты разбирают журналы серверов с шары и делают SELECT-отчёты по dev-БД. **Ничего не меняют** (кроме `ac_case.py` - раздел «Дела»): шара открывается
на чтение, любой SQL проходит проверку «только SELECT» (`db_connect.assert_select_only`). Серверы и клиент не запускаются.
План и обоснование: `Reports/anticheat/04_detection_response.md` (§3 метрики, §6.1 скрипты), отчёт волны:
`Reports/anticheat/wave_B1_daily_report.md`.

## Файлы

| Файл | Что |
|---|---|
| `ac_daily_report.py` | точка входа: аргументы, сборка метрик, Markdown + CSV, `--selftest` |
| `ac_metrics_logs.py` | метрики по файловым журналам: M1 M5 M6 M6b M7 M7d M8 M9 M11 M12 M12o |
| `ac_metrics_db.py` | SELECT-отчёты: M3, M4, M8 (`LogInfo`), сводка `joylog1.ac`, замена `ui:N` на логин |
| `ac_common.py` | разбор формата строк, пороги `THR`, типы `Ctx`/`Metric` |
| `db_connect.py` | подключение к dev-БД (основа - `dbq.py`); пароль читается с шары из `PasswordSQL.txt`, в репозитории его нет |
| `ac_case_config.json` | конфиг журнала дел: хранилище доказательств, срок апелляции/хранения, лестница санкций |

Побочных эффектов при импорте нет (всё под `main()`); `python -I` допустим.

## Запуск

```
python ac_daily_report.py                              # вчера, шара по умолчанию, отчёт в Reports\anticheat\daily
python ac_daily_report.py --date 2026-10-11            # конкретный день
python ac_daily_report.py --date 2026-10-12 --days 81  # окно в 81 день, заканчивающееся 12.10 (архив логов)
python ac_daily_report.py --root "//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/ASDA/Working_ASDA/v2" --out D:\tmp\ac
python ac_daily_report.py --no-db                      # без SELECT-отчётов
python ac_daily_report.py --thr m5_burst_n=3 --thr m1_z=4   # поменять порог на один прогон
python ac_daily_report.py --owner-regex "(?i)(sitx|rimy)"   # свой список «ников владельца»
python -I ac_daily_report.py --selftest                # самопроверка на синтетике (без шары и БД)
```

Аргументы: `--date YYYY-MM-DD` (последний день окна, по умолчанию вчера), `--days N` (длина окна, по умолчанию 1),
`--root` (папка `v2`; в Python-пути к шаре **прямые слэши**), `--out` (папка отчёта), `--otp-archive` (архив старых
`OTP_Report`, по умолчанию `@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-12_otp_report_archive`), `--servers`, `--npc-servers`,
`--owner-regex`, `--no-db`, `--thr KEY=VAL`, `--selftest`.

Выход в `--out`: `ac_report_<дата>.md` (для окна больше суток - `ac_report_<с>_<по>.md`) и CSV: `ac_<тег>_<метрика>.csv`
(все события: время, источник, субъект, вид, деталь, файл, IP; UTF-8 с BOM, открывается в Excel) и `..._t<N>.csv`
(таблицы БД-метрик). Вверху отчёта - «Итог»: метрика, всего, число субъектов, среднее и максимум на субъекта, топ-5,
сколько событий вне списка владельца, флаги (вне владельца / фон владельца), статус.

**БД и `python -I`:** `pyodbc` стоит в пользовательском site-packages, а `-I` его не видит. С `-I` метрики M3/M4/ACJ честно
пишут «нет данных» (разбор файлов работает полностью). Для SELECT-отчётов запускать без `-I`.
Если таблиц или столбцов нет - метрика пишет «нет данных», отчёт не падает (набор таблиц `Trade*`/`PersonalStore*` берётся
из `sys.tables`/`sys.columns`).

## Метрики

Источники и формулы - из 04 §3. «Пороги-кандидаты» подобраны по §3 и меняются через `--thr`; на реальном онлайне их
надо калибровать (на dev играют только владелец и тестовые ники).

| # | Что | Источник | Порог-кандидат (ключ) |
|---|---|---|---|
| M1 | опыт в час: (Exp выхода - Exp входа) / длительность сессии | `Log_LevelUp` | сессии от 5 мин; флаг > 5 x медианы уровня при группе >= 5 сессий (`m1_min_session_s`, `m1_z`, `m1_min_group`) |
| M3 | пары сделок: число записей, предметы и золото в каждую сторону, асимметрия (окно отчёта и 7 дней); с 22.11.2026 сумма — переданное (дельта у владельца баланса строки), золото лавки — покупатель → продавец, стопка золота `TradeItemFrom` Code 20551 — золото (`pair_rows`) | JoyLog1 `Trade*`, `PersonalStore*` (без зеркальных `...To`) | >= 5 записей пары; золото >= 1 000 000 в одну сторону при нуле обратно (`m3_pair_deals`, `m3_gold_oneway`) |
| M4 | дубли: `Uuid` > 1 раза в `Joy1.Item`, `Uuid` и в `Item`, и в `Del_item`, `Serial` передан >= 3 раз | Joy1 `Item`, `Del_item`, JoyLog1 `Serial` | любой дубль; цепочка `m4_chain` |
| M5 | откат позиции `CharMove`/`CharReMove Hack Position` | `Log_Game` | >= 5 на ник за 10 мин (`m5_burst_n`, `m5_burst_min`) |
| M6 | античит скорости атаки NpcServer: `Count`, `Duration/PDuration` | `NpcServer\Error_Log\SpeedHack_*` (читаются только файлы нужных дат, потоково) | ratio < 0.8 не реже 10 раз на ник; `Count` > 30 (`m6_ratio`, `m6_ratio_n`, `m6_count`) |
| M6b | спидхак по пингу GameServer: `Warning` (два пинга < 6 с), `HackCheck` (4 подряд) | `Log_SpeedHack` | шумный детектор (04 §2.1); флаг только `HackCheck` вне владельца |
| M7 | подделка пакета: `Secret Error`, MD5-несовпадение, ошибки предметов, кик `GetMD5_Cmp` LoginManager | `Log_Secret`, `Log_Exception_Asm`, `Log_Item`, `LoginoutCheck` | любое значение вне владельца |
| M7d | исключительные отключения `___ExceptionDisConnetUser___` (функция, ник, IP) | `Log_Game`, `Log_Exception_Asm`, `Log_Operator` | справочно; флаг на не-Ping отключения вне владельца |
| M8 | мультиаккаунт: граф логин - IP - MAC | `OTP_Report` (MAC попадает в строку случайно), `JoyLog1.LogInfo`, `LoginProc` | >= 3 логина на IP/MAC, >= 3 IP на логин (`m8_group_n`); в dev-LAN IP слабый признак |
| M9 | длительность сессий (сессии портала склеены, разрыв <= 120 с) | `Log_LevelUp` | сессия > 8 ч, онлайн >= 16 ч за сутки (`m9_session_h`, `m9_day_h`) |
| M11 | GM-команды: `ItemGive`, Kick, Kill, Move, Summon, чат (Hide - рутина, не считается) | `Log_Operator` | выдача на не-владельческий ник или команда не-владельческого ника |
| M12 | неудачные входы: status 2/3/5, `Failed Count`, `Block User` | `OTP_Report`, `LoginProc` | > 5 за 10 мин с IP/логина (`m12_fail_n`, `m12_win_min`) |
| M12o | вход при уже открытой сессии (status 4, `Overlap`) | `OTP_Report`, `LoginProc` | справочно |
| ACJ | сводка журнала `joylog1.ac` (P53): число строк в 7 таблицах, события окна по видам, топ нарушителей | `joylog1.ac.*`, `v_events`, `v_top_offenders` | справочно; служебные «журнал:» не считаются |

Не вошло (вне задачи): M2 (золото в час - нужен снимок `Charinfo`), M10 (редкий лут `Log_GachaItem`).

## Как читать результат

- **«Вне владельца»** - события на никах/логинах, не совпавших с `--owner-regex`. По умолчанию владельцем считаются
  `sitx*`, `rimy`, `kreemdfgre`, `ssssiiiiii`, `testbot*`, `GM_*`, `ADM_*` (служебные GM- и тестовые учётки dev). Список -
  допущение; уточняйте `--owner-regex`. Чистые учётки должны давать ноль, учётки владельца - фон (04 §волна В1).
- **Флаги** делятся на «вне владельца» (кандидаты на разбор) и «фон владельца» (справочно). Один флаг - повод посмотреть
  CSV, а не доказательство: по §4 плана дело требует второго независимого источника.
- `ui:N` - userindex без ника (`Log_Item`, `Log_Exception_Asm`). Скрипт заменяет его на `логин(ui:N)` по
  `AsdaStoryOp.dbo.Us_member`; если строки нет (индексы прежней базы), берёт ники из `Log_Operator` (`UserID = ник, N`).
- Не открылся журнал (занят писателем без общего доступа, исчез между листингом и чтением) - статус «ошибка» у метрик этого
  канала с причиной в заметке, остальные считаются. С 22.11.2026 так и для общих источников: `Log_LevelUp` (M1, M9) и `OTP_Report`
  (M8, M12, M12o) - раньше их сбой ронял весь отчёт (ревизия 56 админ-центра). Нет файла - метрика без него («событий нет»).
  Уточнение (ревизия 57): третий общий источник - таблица подключений `LoginProc` у M8; при его сбое «ошибка» у M8 (M12 / M12o
  читают LoginProc сами и получают свою «ошибку»), остальной отчёт считается.
- Год в строках GameServer/LoginManager отсутствует - берётся из имени файла. Файлы читаются как UTF-8, строки с ошибкой
  декодирования - как cp1251 (встречаются оба вида). Время NpcServer - из строки + дата из имени файла.

## Гигиена

- Из `OTP_Report` берутся только логин, IP, MAC (хвост поля пароля) и статус; **хеши паролей в память дальше регулярки
  не идут и в отчёты/CSV не попадают** (проверка: ни одной 32-символьной hex-строки в выходных файлах).
- Пароль БД читается с шары при подключении и нигде не пишется. Не копируйте `PasswordSQL.txt` в репозиторий.
- Большие каналы (`Log_Frame`, `Log_AliveCheck`, весь `NpcServer\Error_Log` кроме `SpeedHack_*`) не читаются.
- Выходные файлы содержат ники, логины и IP - хранить вне Perforce/шары (04 §4).

## Дела (журнал санкций, волна В6)

Принципы (`Reports/anticheat/00_PLAN.md` §3, `04_detection_response.md` §4-5): **санкцию выносит человек** по делу с
доказательствами из **двух независимых источников**; автоматика стойки - только кик и автоблок P48/P69. Суточный отчёт даёт флаги,
`Reports/anticheat/wave_B6_sanctions.md`.

### Хранилище доказательств
- Корень - `evidence_root` в `ac_case_config.json` (по умолчанию `D:/AsdaCases`, локально у владельца), переопределяется переменной
  `ASDA_CASES_DIR` или ключом `--store`. **Шара стойки запрещена** (журналы там без контроля доступа); внутри `@@ASTORY_DEV_ROOT_FWD@@`
  (Perforce) - предупреждение. Хранить не меньше `retention_days` (180) дней после закрытия.
- Папка дела `AC-NNNN/`: `files/` (копии и выдержки), `exports/` (выгрузки событий), `reports/` (отчёты отката), `manifest.json`
  (копия реестра), `case.md` (по `show --md`). Реестр с sha256 - в `joylog1.san.evidence`; строки событий `ac.*` - полным снимком
  в `san.case_event` (журнал `ac` чистится DLL, дело - нет).
- Журналы входа LoginManager (`OTP_Report`, `LoginMngError`) - только выдержкой: `--excerpt` маскирует 32-hex (MD5 паролей).

### Команды
```
python ac_case.py --by <кто> open --user <логин> [--char <ник>] --title "суть" [--hypothesis "..."] [--training]
python ac_case.py attach AC-0001 --event move_combat:7158 --event packet_validator:151      # события журнала ac.*
python ac_case.py attach AC-0001 --events-auto 2026-10-12T20:30:00 2026-10-12T20:50:00      # все события окна по учётке/персонажам
python ac_case.py attach AC-0001 --file "//@@ASTORY_SERVER_HOSTNAME@@/.../SpeedHack_20261012.txt" --source "NpcServer SpeedHack" --excerpt "GM_sitxovski"
python ac_case.py export AC-0001 [--format json,csv]        # выгрузка событий дела в exports/ + sha256 в реестр
python ac_case.py ladder [--check]                          # лестница; --check - сверка сроков с patches.ini стойки (P48/P69)
python ac_case.py decide AC-0001 --step 3 [--hours 1] --text "на основании чего" [--reason-en "latin"] --yes
python ac_case.py execute AC-0001 --text "предупреждение отправлено GM_..."   # ступени 1, 2, 6 - ручное исполнение
python ac_case.py withdraw AC-0001 --text "почему"          # отозвать НЕисполненное решение
python ac_case.py lift AC-0001 --text "..." --yes [--all-blocks]
python ac_case.py appeal AC-0001 --text "..." [--who игрок] [--late "почему"]
python ac_case.py --by <другой> appeal AC-0001 --resolve upheld|overturned --text "..."
python ac_case.py close AC-0001 --outcome sanctioned|acquitted|no_action --text "..."
python ac_case.py rollback-report AC-0001 --serial <GUID> | --window FROM TO   # отчёт «что откатить», БЕЗ записи
python ac_case.py verify [AC-0001]                          # целостность: файлы/sha256, лишние файлы, снимки событий, BlockList
python ac_case.py show AC-0001 [--md]  |  python ac_case.py list [--status S] [--user L]
python ac_case.py selftest [--db]                           # без БД (-I допустим); --db - полный цикл на dev-БД в транзакции с откатом
```
`--by` - кто действует (по умолчанию `USERNAME`); пишется в историю, `decided_by`, `appeal_reviewed_by`.

### Ход дела и правила
| статус | как попасть | что проверяется |
|---|---|---|
| open | `open` | учётка есть в `Us_member`, персонаж - в `Charinfo` |
| evidence | первый `attach` | событие есть в `ac.*` (снимок + sha256), файл скопирован/выдержан и sha256 копии = источнику |
| decision | `decide` | ступень 0..6; со ступени 3 - два независимых источника (иначе `--override-two-sources` под запись); ступень 6 - нужен `rollback-report`; блок - подтверждение (`--yes` или ввод номера дела) |
| executed | `decide` ступени 3-5 (блок сразу) / 0 (наблюдение) / `execute` (1, 2, 6) | после блока: `us_block = 5` и строка `BlockList` с причиной `AC-NNNN …`, иначе откат транзакции; срок апелляции `appeal_days` (14) |
| appeal | `appeal` | только на исполненное/закрытое с санкцией; после срока - `--late` |
| closed | `close` / `appeal --resolve overturned` | `verify` прошёл (иначе `--force-unverified` под запись); снятие решения - только апелляцией и только после `lift`; пересмотр - другим лицом (иначе `--same-person`) |

- Каждая команда - одна транзакция: при отказе или ошибке в БД ничего не пишется, свежие файлы команды удаляются.
  подстановкой логина, часов, причины; md5 скрипта - в деле). `lift` отказывает, если у учётки есть блоки не этого дела
  (`OPBlockDel` снимает все) - ключ `--all-blocks`. После `lift` печатается проверка входа по данным БД (`us_block`, `BlockList`,
  пароль задан, замок неудач).
- **Откат по Serial** - `rollback-report` читает `Joy1.Item`/`Del_item` и журналы JoyLog1 с `Serial` (182 таблицы), пишет в
  `reports/` отчёт (MD + JSON): где предмет сейчас, цепочка передач, предложение и шаблон SQL **для копии базы**. Инструмент в
  игровые таблицы не пишет; откат выполняет владелец отдельным шагом, затем `execute`.
- Материалы не удаляются: история, события и реестр файлов защищены триггерами (UPDATE/DELETE - отказ).

### Учебное дело AC-0001 (14.10)
Учётка оператора `sitxovski` (CharGmInfo UserIndex 1, Charidx 10 `GM_sitxovski`): 13 событий `ac.*` 12.10 20:37-20:45 (P57, NpcServer
SpeedHack, P55) + выдержка `NpcServer\Error_Log\SpeedHack_20261012.txt` + выгрузка JSON/CSV → решение «ступень 3, 1 ч» → блок
возможен. Подробно - `wave_B6_sanctions.md` §5.

