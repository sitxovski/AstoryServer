# Админ-центр Astory, волна А7 «Выпуски, сбои, сообщество» — реестр изменений волны (А7.1–А7.11)

* **Дата:** 23.11.2026 16:44 — 24.11.2026 (итог волны А7.11)
* **Ред.:** 1 — итог волны (А7.11): что где, таблицы, процедуры, операции, права, файлы бота, задания ПК, решения владельца, ревизии, хронология
* **Статус:** ✅ волна закрыта. Шаги А7.1, А7.2, А7.4, А7.5, А7.6, А7.7, А7.10 выложены; А7.9 не делается (решение владельца №4);
  А7.3 и А7.8 не сделаны — ждут выпуска клиента / выпуска лаунчера (см. таблицу). Отложенное — `Docs/Port/PORT_PENDING_ON_SYSTEMS.md`
  §«24.11.2026 — итог волны А7».
* **Процесс / путь:** служба панели `@@ASTORY_SERVER_ROOT@@\AdminCenter` (задание планировщика Windows `AsdaAdminCenter`, https :17890); база `AsdaAdmin`
  (все объекты волны); бот Oracle — на ПК владельца (`AstoryAdminCenter/DiscordBot/oracle_bot.py`, вотчдог — задача ПК `\OracleBotWatchdog` →
  `ensure_oracle.ps1`); хранилище сбоев `LogDrop` на сервере (только чтение по SSH / scp); сервер обновлений `@@ASTORY_UPDATE_HOST@@` (только чтение HTTPS).
* **Тип:** код службы + SQL своей базы (adminc_26…31) + бот на ПК + консоль ПК (`asda_admin.py releases push / crashes sync / notes push`).
  Игровые базы, стойка, DLL и конфиги сервера волной **не менялись**; общих рестартов стойки не было.
* **Отчёты:** `Reports/admin_center/impl_a7_releases_20261123.md` (все шаги и §«Итог волны А7»), разбор `research_a7_releases_20261123.md`;
  ревизии `review74…86_*.md`. План — `Docs/Port/plan/ADMIN_TOOL_PLAN.md` §5.3, решения владельца — §6 п.6.

## Что (по шагам)
| Шаг | Что | SQL / права |
|---|---|---|
| А7.1 Выпуски: статус | раздел «Выпуски» `#/releases`: каналы alpha и launcher снаружи (версия, seq, `min_version`, срок подписи Ed25519 от корня лаунчера; предупреждение 14 / 3 суток); снимок ПК (`releases.log`, Inbox, итоги батников, ключи «есть / срок») | `adminc_26_releases` (adm.ReleasePcStatus) |
| А7.2 Сбои клиента | раздел «Сбои клиента» `#/crashes`: сбор `.acrash` по SSH / scp (шары нет), расшифровка на ПК, место «код + 3 кадра exe», версия по времени сессии; квота LogDrop; удаление `.alog` старше 60 суток | `adminc_27_crashes` (adm.ClientCrash / ClientCrashSig / ClientCrashSync, процедуры ClientCrashPut / ClientCrashSyncAdd) |
| А7.3 Точная версия и символы | **не сделан** — нужен выпуск клиента (`release=` / `seq=` в сведениях сегмента) и PDB каждого выпуска в DEPLOY | — |
| А7.4 Очередь Discord | `adm.Outbox`, флажок «и в Discord» у объявления (сейчас и по расписанию), экран «Очередь Discord» `#/outbox`; бот `outbox_bot.py` — белые списки каналов (announcements, форум updates, test-info) и ролей (News / Patch / Playtest Ping), без @everyone / @here, срок годности, один раз по номеру | `adminc_28_outbox` (+ verify под asda_reports, 15) |
| А7.5 Telegram владельцу | строки `transport = 'telegram'` в `adm.Outbox`; выключатели `adm.NotifyRule` (общий `_master` — нет строки = ВЫКЛ), `adm.NotifyState`, `adm.NotifyBeat`; 10 событий, поиск службой раз в 5 мин; пределы 10 / ч, 40 / сутки; раздел `#/telegram`; отправитель — цикл `tg_loop` в боте (`tg_bot.py`: только sendMessage и getMe) | `adminc_29_telegram` (+ verify, 17) |
| А7.6 Сообщество | раздел «Сообщество» `#/community`: копия реестра бота (заявки, тестеры, предупреждения, баны) раз в 5 мин; команды боту — очередь `adm.BotCmd`, белый список 10 команд, роль только Beta Tester, PROTECTED — отказ; бан + `account.block` одной операцией; откат обратной командой | `adminc_30_community` (+ verify, 36) |
| А7.7 Заметки к выпуску | раздел «Заметки к выпуску» `#/notes`: снимок changelog с ПК (`notes push`), разбор в службе, черновик, публикация в форум updates с Patch Ping через `adm.Outbox` (вид `notes`), учёт опубликованного | `adminc_31_notes` (+ verify, 17) |
| А7.8 Новости лаунчера | **не сделан** — нужен выпуск лаунчера и согласование вида окна с владельцем (решение №5) | — |
| А7.9 Минимальная версия на входе | **не делается** — решение владельца №4 (лаунчер и так обновляет игру перед «Играть») | — |
| А7.10 Справка по операциям | каталог `core/opdoc.py` (165 операций, RU / EN: что меняет, перезапуск, откат), `GET /api/opdoc`, блок в окне подтверждения, страница `#/help`; самотест полноты | — |
| А7.11 Итог | полный самотест, сверка сервера, реестр, план, отложенное, changelog | — |

## Таблицы и процедуры (база AsdaAdmin, схема adm)
| SQL | Таблицы | Процедуры панели (asda_admin) | Процедуры бота (asda_reports) |
|---|---|---|---|
| `adminc_26_releases` | ReleasePcStatus | ReleasePcPrune (уборка старых снимков — `release.prune` из `core/sched.DAILY`); прямые права: SELECT, INSERT, UPDATE только seen_utc / seen_count, DELETE нет | — |
| `adminc_27_crashes` | ClientCrash, ClientCrashSig, ClientCrashSync | ClientCrashPut, ClientCrashSyncAdd (прямой записи нет) | — |
| `adminc_28_outbox` | Outbox | OutboxPut, OutboxRelease, OutboxCancel, OutboxRetry, OutboxDelete | OutboxClaim, OutboxDone, OutboxDelClaim, OutboxDelDone |
| `adminc_29_telegram` | NotifyRule, NotifyState, NotifyBeat (+ строки telegram в Outbox) | TgNotifyPut, TgTestPut, TgRuleSet, TgStateSet, TgBeatSet | TgClaim, TgDone, TgBeatGet, TgLocalNote |
| `adminc_30_community` | BotSnap, BotApp, BotTester, BotWarn, BotBan, BotStaff (модераторы из снимка и признак `on_server` — по ним защита от бана), BotCmd | BotCmdPut, BotCmdRelease, BotCmdCancel, BotCmdRetry | BotCmdClaim, BotCmdDone, BotSnapPut |
| `adminc_31_notes` | NotesSnap, NotesEntry (постоянный реестр записей, `what_hash`), NotesDraft, NotesPost, NotesPostEntry | NotesSnapPut, NotesSnapDone, NotesEntryPut, NotesEntrySync, NotesEntryHide, NotesDraftSet, NotesPublishPut, NotesMarkPut, NotesMarkRevoke, NotesOutboxClose (10) | — (бот публикует заметки через Outbox) |



## Операции и права (core/ops, core/auth PERMS)
| Право | Роли | Операции |
|---|---|---|
| releases.view | owner, admin | — (просмотр «Выпуски») |
| releases.push | owner | `release.push` (задание ПК), `release.prune` |
| crash.view | owner, admin | — (просмотр «Сбои клиента») |
| crash.sync / crash.prune | owner | `crash.sync` (задание ПК); `crash.alog_prune` (слово и второй фактор, без автоматики) |
| outbox.view | owner, admin | — (просмотр «Очередь Discord») |
| community.post | owner, admin | `outbox.cancel`, `outbox.retry`, `outbox.test`, флажок «и в Discord» у `live.announce`; `notes.publish`, `notes.mark`, `notes.resolve` |
| community.delete | owner | `outbox.delete` (удалить опубликованное; отката нет) |
| notify.view / notify.manage | owner | `notify.rule.set`, `telegram.ping` (только getMe), `telegram.test` (проверочное сообщение — настоящая отправка) |
| community.view | owner, admin, gm | — (просмотр «Сообщество») |
| community.manage | owner, admin | `community.app.decide`, `community.tester.add / remove`, `community.warns.clear`, `community.cmd.cancel / retry`, `community.test` |
| community.ban | owner, admin | `community.ban`, `community.unban`, `community.ban.check` (блок учётки — своим правом players.block / unblock) |
| notes.view / notes.draft | owner, admin | `notes.draft`, `notes.hide` |
| notes.push | owner | `notes.push` (задание ПК), `notes.resync` |
| status.view | все роли | `GET /api/opdoc` (справка) |

Права логинов после волны (verify, 24.11): asda_admin 205, asda_ops 457, asda_bridge 15, asda_reports 19 + outbox 15 + telegram 17 + community 36 + notes 17.
PROBE службы: routes=107, ops=165.

## Бот Oracle на ПК (`AstoryAdminCenter/DiscordBot`, на сервер не выкладывается)
| Файл | Что | md5 (24.11) |
|---|---|---|
| `oracle_bot.py` | главный процесс; циклы очереди Discord, Telegram, команд и снимка реестра | `b668a2cc4d49e60fabf96a9afc5dc9d1` |
| `outbox_bot.py` | публикация и удаление из `adm.Outbox` (журнал `outbox_ledger.json`) | `15509bec4aa9b7a12e8ab907ef78fd5d` |
| `tg_bot.py` | отправитель Telegram (sendMessage, getMe; секрет `telegram.env`) | `60f36fb333fac03c2dc8915c645a6037` |
| `community_bot.py` | снимок реестра `state.json` → `adm.BotSnapPut`, исполнение `adm.BotCmd` | `94d999019e74f49026b062c22305d203` |
| `ensure_oracle.ps1` | вотчдог (задача ПК `\OracleBotWatchdog`, раз в 5 мин, замок порта 47653) | `3f624a4df084e0cd4c44d0e320e145b4` |
| `player_reports.py` | жалобы А6.11 (волной не менялся) | `d81d7be7f4f7e394850e2750ed174463` |
| `community_staff.json` | модераторы для снимка (`adm.BotStaff`), правится руками — шапка `StaffBook` | `b4e1d6344da76586bb3b89c6a8ae5724` |
| `test_outbox_bot.py` | тесты очереди Discord (подставной Discord), 26 / 26 | `9313bcb5dc60452279b6584737bd3383` |
| `test_tg_bot.py` | тесты отправителя Telegram (HTTP-заглушка), 22 / 22 | `79e5d04f196cf600936c154e59cf53cd` |
| `test_community_bot.py` | тесты команд и снимка (подставной Discord), 33 / 33 | `7679ff33558470f960be27d186122264` |

Секреты бота на ПК: `reports.env` (логин asda_reports), `telegram.env` (токен) — права пока наследуются (Users — чтение), сужение — за владельцем.
Рядом с ботом изменён `AstoryServer/Patches/AsdaPatch/tools/restart_stack.py` (`67c4ed5a…`, А7.5: отметка `@@ASTORY_SERVER_ROOT@@\stack_activity.txt`).

## Задания и задачи ПК
* Консоль ПК: `asda_admin.py releases push` (А7.1), `crashes sync` (А7.2; ключ LogSeal под DPAPI учётки, сбор — `AstoryClient/Tools/LogSeal/fetch_and_decrypt.py`
  `6cfc7fb6…`), `notes push` (А7.7). То же — задания ПК в «Заданиях» панели (исполняются, пока открыта консоль `jobs watch`).
* Задачи планировщика ПК — **не созданы** (настройка системы, за владельцем): `deploy/schtasks/release_push.xml` (`Astory\ReleasePush`, S4U, при
  входе +5 мин и каждые 4 ч, md5 `44a55ce1…`), `crash_sync.xml` (`Astory\CrashSync`, только при входе — DPAPI, md5 `607c329c…`); инструкция —
  `deploy/schtasks/README.md`. Для `notes push` задачи нет (по брифу не ставилась).

## Решения владельца по волне (23.11.2026, разбор §4)
№1 сбои расшифровываются на ПК, в панель только сводка; №2 Discord — только по флажку, тексты EN / RU / AR руками; №3 Telegram — только
владельцу, только отправка, с ПК; №4 минимальная версия на входе — не делать (А7.9 ✖); №5 новости лаунчера — файл на @@ASTORY_AUTH_HOST@@, вид окна
— отдельным согласованием (А7.8 ждёт); №6 выпуск — только статус, сам выпуск батниками; №7 changelog для игроков — черновик и публикация
кнопкой; №8 `.alog` 60 суток, `.acrash` без срока, удаление операцией owner; №9 реестр заявок и тестеров остаётся у бота.

## Ревизии волны
| Ревизия | Шаг | Итог |
|---|---|---|
| 74 | А7.1 | В 0 / М 4 / К 7 — исправлено (в т. ч. М-1 откат keyring на сервере обновлений) |
| 75 | А7.2 | В 0 / М 3 / К 8 — исправлено (в т. ч. `crash.sync` проверяет ключ LogSeal до scp, задача «только при входе») |
| 76 | А7.4 | В 0 / М 2 / К 7 — исправлено всё |
| 77, 78 | А7.5 | 77 — В 2 / М 6 / К 7; 78 (проверка исправлений) — В 1 / М 2 / К 8; исправлено всё |
| 79, 80, 81 | А7.6 | В 2 / М 9; В 1 / М 7; В 0 / М 5 — исправлено всё |
| 82, 83, 84 | А7.7 | К 0 / В 2 / М 7; К 0 / В 1 / М 7; К 0 / В 0 / М 2 / Н 3 — исправлено всё (Н-1, Н-3 р84 — без правки, см. отчёт) |
| 85, 86 | А7.10 | К 0 / В 7 / М 11; К 0 / В 0 / М 5 — исправлено всё |
| 87 | А7.11 (итог) | К 0 / В 2 / М 4 / Н 5 — исправлены В-1, В-2, М-1…М-4, Н-1…Н-3 (ред. 2 ниже) |

Шкала: в ревизиях 74–78 «К» — мелочи (самый низкий уровень, ниже М: комментарии, тексты, косметика); с ревизии 79 «К» — критично (выше В).

## Зачем
План админ-центра §4 (выпуски и сборки, сбои клиента, сообщество и оповещения) и решения владельца по волне А7 (§6 п.6, 23.11): видеть
состояние выпуска и падения клиента из панели, не держа ключей на сервере; отвечать сообществу (Discord) и получать оповещения (Telegram)
через одну очередь, которую исполняет бот на ПК — сервер Discord и Telegram не видит.

## Риски / связанное
* Всё наружу (Discord, Telegram, команды боту) — только бот на ПК: ПК выключен — очереди копятся, срок годности записей их гасит.
* Белые списки каналов, ролей и форума у бота и живой Discord ни разу не сверялись настоящей публикацией; не совпадут — бот откажет с причиной.
* Telegram выключен общим выключателем до слова владельца; события на dev ни разу не срабатывали.
* Задачи ПК не созданы — «Выпуски» и «Сбои клиента» обновляются только вручную; S4U у `Astory\ReleasePush` не проверен (ключ `.ssh`, Tailscale без входа).
* Секреты бота на ПК наследуют чтение Users; резервных копий ключей выпуска нет.
* `crash.alog_prune` на настоящих файлах не запускался (кандидаты — с 18.12).
* Числа операций А7 («134 → 165») включают 3 операции посещаемости А6.10 (`attendance.*`, выложена 23.11, `adminc_25`) — см. реестр А6, ред. 2.

## Бэкап
* Код ПК — по шагам `@@ASTORY_DEV_ROOT@@\_backup\2026-11-23_a7*`, `2026-11-24_a7*`; итог — `@@ASTORY_DEV_ROOT@@\_backup\2026-11-24_a711\`.
* Служба панели — `@@ASTORY_SERVER_ROOT@@\AdminCenter\_backup\<метка>` каждой выкладки (ниже).

## Откат
1. Панель — служба из `@@ASTORY_SERVER_ROOT@@\AdminCenter\_backup\<метка>` нужной точки (до волны — `20261123_164418` хранит состояние перед А7.1) или
2. Бот — прежние файлы из бэкапов шагов и перезапуск через `ensure_oracle.ps1` (остановить процесс → вотчдог поднимет).
3. Telegram — выключить общий выключатель (удалить строку `_master` / кнопка в разделе); Discord — отменить ждущие записи в «Очереди Discord».

## Рестарт
Стойка — не перезапускалась (15 процессов с 22.11 22:51). Служба панели — каждой выкладкой (22 успешные). Бот Oracle — 9 штатных перезапусков
через `ensure_oracle.ps1` (43652 → 44168 → 62916 → 62204; 72456 → 59096 → 55952 → 64904 → 48252 → 50388; 87312 → 51136 в 10:34) и 1 вотчдогом
(50388 → 87312 в 09:29); PID 72456 в записях шагов без происхождения.

## Хронология выкладок панели (часы ПК)
### 23.11.2026
* 16:44 — А7.1 «Выпуски»: `_backup\20261123_164418`, adminc_26 OK, routes=100 ops=138. 19:05 — ревизия 74: `_backup\20261123_190542`, ops=139.
* 19:50 — А7.2 «Сбои» (crashes не был в `load_all`, ops=139); 20:31 — повтор: `_backup\20261123_203105`, adminc_27 OK, ops=141, asda_admin 122.
  21:17 — ревизия 75: `_backup\20261123_211701`.
* 22:10 — А7.4 «Очередь Discord»: `_backup\20261123_221034`, adminc_28 OK, routes=102 ops=145, asda_admin 133, outbox 15; бот 43652 → 44168 (22:25).
  22:59 — ревизия 76: `_backup\20261123_225959`, asda_admin 135; бот → 62916 (23:14).
### 24.11.2026
* 00:11 — А7.5 «Telegram»: `_backup\20261124_001147`, adminc_29 OK, routes=103 ops=148, asda_admin 145, telegram 16; бот → 62204 (00:25).
  00:52 — ревизия 77: `_backup\20261124_005241`, telegram 17. 01:25 — ревизия 78: `_backup\20261124_012554`; бот → 59096 (01:39).
* 02:21 / 02:37 — А7.6 «Сообщество»: `_backup\20261124_022139`, `_backup\20261124_023734`, adminc_30 OK, routes=104 ops=157, asda_admin 161,
  community 16; бот → 55952 (02:35). 03:20 — ревизия 79: `_backup\20261124_032050`, ops=158, asda_admin 181, community 36; бот → 64904.
  03:51 — ревизия 80: `_backup\20261124_035138`; бот → 48252. 04:17 — ревизия 81: `_backup\20261124_041701`; бот → 50388.
* 05:09 — А7.7 «Заметки»: `_backup\20261124_050935`, adminc_31 OK, routes=105 ops=162, asda_admin 199, notes 12. 06:02 — ревизия 82:
  `_backup\20261124_060229`, ops=165, asda_admin 204, notes 16. 09:51 — ревизия 83: `_backup\20261124_095152`, asda_admin 205, notes 17.
  10:54 — ревизия 84: `_backup\20261124_105444`.
* 12:22 — А7.10 «Справка»: `_backup\20261124_122248`, routes=106. 13:47 — ревизия 85: `_backup\20261124_134717`, routes=107.
  14:20 — ревизия 86: `_backup\20261124_142030`.

## Ред. 1 — 24.11.2026, А7.11 «Итог волны А7» (отчёт `impl_a7_releases_20261123.md` §«Итог волны А7»)
* **Самотесты.** Офлайн целиком — 2516 / 0. Живой полный, разделён как в А6.13: 26 читающих блоков — 184 / 1 (тест `live`) → повтор 8 / 0;
  пишущие только в AsdaAdmin с отметкой «тест» — `shops` 9 / 0, `stack,econ,releases,crashes,outbox,telegram,community,notes` 57 / 0 (после
  исправления теста `stack`); читающие части блока C и `attendance` — 17 / 0; записывающие в игровые базы подблоки не гонялись.
* **Ложные FAIL, исправлены тесты** (`tests/selftest_stack_a5.py`, `tests/selftest_live_a5.py`): `live()` не вызывали `domains.load_all()` →
  «неизвестная операция live.announce / char.move». Код службы не менялся, выкладки не было.
* **Что стоит на сервере (24.11, SSH, только чтение):** md5 719 / 719 файлов службы = ПК (+6 строящихся справочников); PROBE routes=107
  ops=165; 58 объектов adminc_26…31 (20 таблиц + 38 процедур); verify — asda_reports 19 / 15 / 17 / 36 / 17, asda_admin 205, asda_ops 457, asda_bridge 15 — все 0 расхождений;
  без входа 401 (VPN, LAN с сервера); `adm.Outbox` и `adm.BotCmd` — только проверочные, id сообщений Discord нет; общий выключатель Telegram —
  ВЫКЛ (строки `_master` нет); `adm.BotSnap` свежий; бот Oracle PID 51136 с 10:34, «готов»; стойка — 15 процессов с 22.11 22:51.
* **Проверочные записи прогона:** Outbox №22 (Discord, test), №23 (Telegram, selftest), №24 (notes, test); BotCmd №12, №13 (test);
  NotesSnap №4; ReleasePcStatus — снимок №2 не изменился; ClientCrashSync — без изменений. Всё в итоге «тест», наружу ничего.
* **Бэкап кода:** `@@ASTORY_DEV_ROOT@@\_backup\2026-11-24_a711\` (два теста, план, реестр отложенного, отчёт, changelog, памятка).
* **Рестарт:** стойки — нет; службы панели — нет; бота — нет.

## Ред. 2 — 24.11.2026, исправления по ревизии 87 (`Reports/admin_center/review87_a7_summary_20261124.md`)
* В-1: таблица SQL дополнена (ReleasePcPrune, BotStaff, NotesEntry, все 10 процедур заметок, процедуры Tg*), число объектов — 58 (20 таблиц +
  38 процедур), перепроверено по SQL-файлам и по серверу (только чтение).
* М-4: свой счёт ревизии 78 и пояснение шкалы «К». Н-2: разделы «Зачем» и «Риски / связанное». Н-3: тесты бота и `community_staff.json`.
* Часы в хронологии — по ПК (в реестре А6 — по серверу).
* В-2: пункты «Не проверено» всех шагов — в `PORT_PENDING_ON_SYSTEMS.md` §«итог волны А7», «ДОПОЛНЕНИЕ» (11 пунктов). М-2: реестр А6, ред. 2
  (А6.10). Н-1: `load_all()` в `live()` тестов events / maint / shops, `--only events,maint,shops` — 24 / 0. М-1: уточнение в changelog.
