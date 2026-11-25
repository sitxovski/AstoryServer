# Админ-центр, волна А0 — база AsdaAdmin, логин asda_admin, служба панели

* **Дата:** 16.11.2026
* **Статус:** ✅ выложено 16.11.2026 14:10, действует; ред. 4–6 (18:18–19:00) — все интерфейсы по HTTPS, защита от перебора; права 21/21, живой самотест 108/0
* **Процесс / путь:** не игровой процесс. SQL Server @@ASTORY_SERVER_HOSTNAME@@\SQLEXPRESS (новая база `AsdaAdmin`, новый логин `asda_admin`,
  пользователь `asda_admin` в Joy1 / AsdaStoryOp / joylog1 / AsdaStoryLogin); служба `@@ASTORY_SERVER_ROOT@@\AdminCenter\`
  (задача планировщика `AsdaAdminCenter`), правило брандмауэра `AsdaAdminCenter`.
* **Тип:** новая служба + SQL (база, логин, права) + настройка ОС (задача, брандмауэр).

## Что

| Что | Значение |
|---|---|
| Логин | `asda_admin` (SQL, CHECK_POLICY ON, по умолчанию AsdaAdmin, НЕ sysadmin). Пароль — только в `@@ASTORY_SERVER_ROOT@@\AdminCenter\secrets\asda_admin.ini` (права Administrators + SYSTEM, наследование снято), там же `TOTP_KEY` |
| Права в игровых базах | `db_datareader` в Joy1, AsdaStoryOp, joylog1, AsdaStoryLogin; `DENY SELECT` на `AsdaStoryLogin.dbo.[user].password`. Записи, EXEC — нет |
| Права в AsdaAdmin | users/sessions — SELECT/INSERT/UPDATE/DELETE; audit — SELECT/INSERT + UPDATE(undone_by), DELETE запрещён |
| Служба | `asda_admin.py serve` (Python 3.13 Administrator'а, pyodbc; без внешних пакетов), слушает **@@ASTORY_SERVER_VPN_IP@@:17890** (только адрес VPN) |
| Запуск | задача `AsdaAdminCenter`: ONSTART, SYSTEM, `cmd.exe /c @@ASTORY_SERVER_ROOT@@\AdminCenter\run_service.bat` (перезапуск через 10 с) |
| Брандмауэр | входящий TCP 17890 только из 100.64.0.0/10 |
| Журнал службы | `@@ASTORY_SERVER_ROOT@@\AdminCenter\logs\service.log` (ротация на 20 МБ) |

## Зачем
План владельца «админ-центр» (`Docs/Port/plan/ADMIN_TOOL_PLAN.md`, волна А0): панель только для чтения —
состояние стойки, карточки учётки/персонажа, лента журналов, след предмета; вход по ролям со вторым фактором и журналом
действий. Узкий логин вместо `devgsaccount`: служба физически не может писать в игровые базы.

## Как ставилось
`AstoryAdminCenter/deploy/deploy_admin_center.py`: самотест → архив по scp → секреты (один раз) → SQL под
Windows-входом Administrator через shared memory (`sqlcmd -S lpc:.\SQLEXPRESS -E` — sysadmin; ★ у `devgsaccount`
прав CREATE DATABASE / ALTER ANY LOGIN НЕТ, проверено 16.11) → проверка прав под asda_admin

## Бэкап
Изменений существующих объектов нет (только новые). Игровые базы, процессы и файлы стойки `v2` не тронуты.
Прежние версии службы — `@@ASTORY_SERVER_ROOT@@\AdminCenter\_backup\<метка>` (5 последних).

## Откат (пошагово)
1. `schtasks /End /TN AsdaAdminCenter` и `schtasks /Delete /TN AsdaAdminCenter /F`; завершить python `asda_admin.py serve`.
2. `netsh advfirewall firewall delete rule name=AsdaAdminCenter`.
4. Удалить `@@ASTORY_SERVER_ROOT@@\AdminCenter`.

## Рестарт
Игровой стойке не нужен. Служба стартует сама при загрузке машины.

## Риски / связанное
* Порт 17890 выбран, т.к. 8800–8999 на ПК владельца зарезервированы Windows; со стойкой (15xxx) не пересекается.
* Трафик панели — HTTP внутри VPN (Tailscale шифрует); наружу порт не пробрасывать.
* Следующие волны (А1+) добавят логину EXECUTE на конкретные процедуры — отдельной записью реестра.

## Ред. 2 — 16.11.2026 ~14:50 (по ревизии `Reports/admin_center/A0_REVIEW.md`)
* Права игровых баз: к `db_datareader` добавлен `DENY INSERT, UPDATE, DELETE, EXECUTE, ALTER, REFERENCES, CREATE …` на уровне
  каждой из 4 баз (через `public` у asda_admin было EXECUTE на `sp_creatediagram` и др. в AsdaStoryOp/AsdaStoryLogin —
* Каталог `@@ASTORY_SERVER_ROOT@@\AdminCenter`: наследование от `H:\` снято (было право BUILTIN\Users создавать файлы — подложенный модуль
  Python выполнился бы от SYSTEM); корень — только Administrators и SYSTEM, вложенное наследует, `secrets` — свои права.
* Задача `AsdaAdminCenter` пересоздана через `Register-ScheduledTask`: лимит выполнения **нет** (у `schtasks /Create` по
  умолчанию 72 ч — служба остановилась бы 19.11), перезапуск задачи при сбое.
* В `adm.users` добавлен столбец `totp_last` (одноразовость кода второго фактора).
* Откат ред. 2 — тот же, что у установки целиком (раздел «Откат» выше).

## Ред. 3 — 16.11.2026 ~15:07 (перепроверка ревизии)
второго фактора, рубеж «только чтение» ловит слово сразу после цифры. Проверка прав 21/21, живой самотест 84/0.
Замечания для владельца (не исправлялось — окружение сервера): у учётки `@@ASTORY_SERVER_HOSTNAME@@\ufed_bot` полный доступ к каталогу
Python службы `C:\Users\Administrator\AppData\Local\Programs\Python\Python313` (через site-packages — код от SYSTEM).
**Решение владельца 16.11.2026: оставить как есть** (права ufed_bot не трогать).

## Ред. 4 — 16.11.2026 ~18:18 (слово владельца: «панель на всех интерфейсах, не только Tailscale»; игровой скин)
* Служба слушает **0.0.0.0:17890 только по HTTPS** (`netstat`: `0.0.0.0:17890 LISTENING`). Сертификат самоподписанный:
  ECDSA P-256, 10 лет, SAN @@ASTORY_SERVER_VPN_IP@@ / @@ASTORY_SERVER_LAN_IP@@ / @@ASTORY_SERVER_WAN_IP@@ / 127.0.0.1 / @@ASTORY_SERVER_HOSTNAME@@ / localhost.
  Файлы `secrets\tls.crt` и `secrets\tls.key`, у ключа права только Administrators и SYSTEM. Отпечаток SHA-256:
  `EC:3A:D4:9F:4D:84:C2:46:6A:DA:DA:4D:DD:64:58:2C:D5:62:BE:6D:01:B8:CB:C2:99:14:81:8F:BD:2E:F4:3F`.
  Без сертификата служба на сервере не стартует.
* Брандмауэр `AsdaAdminCenter`: входящий TCP 17890 с **любых** адресов (было — только 100.64.0.0/10).
* Заголовок Host — только адреса сервера (`config.public_hosts`), cookie с `Secure`.
* Внешний адрес работает, только если на роутере проброшен TCP 17890 → @@ASTORY_SERVER_LAN_IP@@. Роутер не трогался. Изнутри
  сервера внешний адрес не открывается, а с ПК владельца его не проверить: там TUN-прокси.
* Вид панели — элементы окон клиента (`web/skin/`); на сервере это только новые статические файлы.
* Откат ред. 4: `netsh advfirewall firewall set rule name=AsdaAdminCenter new remoteip=100.64.0.0/10`; в
  `@@ASTORY_SERVER_ROOT@@\AdminCenter\config.ini` секция `[admin]`: `bind_host = @@ASTORY_SERVER_VPN_IP@@`, `tls = 0` (служба вернётся к HTTP на
  VPN); перезапуск — `schtasks /End` + `/Run /TN AsdaAdminCenter`. Прежний код — `@@ASTORY_SERVER_ROOT@@\AdminCenter\_backup\<метка>`.

## Ред. 5 — 16.11.2026 ~18:35 (исправления по ревизии «скин и HTTPS»)
Только код службы, без изменений в SQL и ОС:
* строгий Content-Length (С1);
* предел соединений: 64 всего, 12 с одного адреса;
* запрос целиком за 20 с;
* окно на логин снаружи доверенных сетей: 12 попыток за 10 мин;
* не больше 2 одновременных проверок пароля;
* снаружи VPN и частных сетей — вход только со вторым фактором;
* один общий отказ без шага «нужен код».

Открытый сертификат: `AstoryAdminCenter/deploy/asda_admin_center.crt` (отпечаток выше, EC:3A:D4…). Права 21/21, живой
самотест 104/0. Откат — как в ред. 4 (код из `_backup`).

## Ред. 6 — 16.11.2026 ~19:00 (перепроверка исправлений)
Только код службы:
* доверенная сеть — только 100.64.0.0/10 (VPN) и loopback; домашняя сеть снята из-за возможного SNAT роутера;
* раздельные пределы для интернета и VPN: соединения и слот проверки пароля;
* таймер сторожа снимается при сорванном рукопожатии, счётчик соединений не утекает;
* self.password — под семафором и замком.

Права 21/21, живой самотест 108/0, шаг 8 выкладки проверяет цепочку по `deploy/asda_admin_center.crt`.
