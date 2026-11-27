<div align="center">

[English](README.md) · **Русский** · [العربية](README.ar.md)

### ❤️ Нравится проект? Поддержите труд на [**Boosty**](https://boosty.to/sitxovski_yurii)

### 💬 Присоединяйтесь к нашему сообществу в [**Discord**](https://discord.gg/DBPFczQKb2)

# Astory Server

**Патчи и службы, на которых работает игровой сервер Astory**

[Astory Client](https://github.com/sitxovski/AstoryClient) · [Astory Server](https://github.com/sitxovski/AstoryServer) · [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter)

</div>

---

> ⚠️ **Дисклеймер.** Этот пакет (Только репозиторий. Проект - ручная работа с помощью ИИ) собран с помощью **Claude Code** и может содержать ошибки. Пишите мне в личные сообщения в Discord (**@sitxovski**) — помогу.

## Что внутри

| Папка | Что это |
|---|---|
| `Patches` | DLL-патчи для процессов сервера: исправления, новые функции, античит, мост для панели |
| `EacServer` | сервер Easy Anti-Cheat |
| `LogDrop` | приёмник журналов сбоев и диагностики клиента |
| `Patches\Gp7Gateway` | шлюз магазина и баланса (Node.js) |
| `Tools` | отчёты и метрики античита |
| `Docs` | как устроен каждый патч — начните с [`Docs/INDEX.md`](Docs/INDEX.md) |
| `Prerequisites` | что установить, как собрать и запустить |

> 📦 **Сам игровой сервер и чистые базы скачиваются отдельно** — [*AstoryServer Files* и *AstoryServer Database* (Google Drive)](https://drive.google.com/drive/folders/1GWlBoy64nsW05HBMXS-slBLDQinwxh4h?usp=sharing). Установка, SQL Server, связь с клиентом и порты роутера: [Prerequisites/README.md](Prerequisites/README.md).

## Быстрый старт

1. **Установка** — `Prerequisites\install_prerequisites.bat` на ПК и `... -Server` на сервере ([подробно](Prerequisites/README.md)).
2. **Настройка** — `_setup\configure.bat` (адрес сервера, папки, ключ SSH — [где их взять](_setup/SETUP.md)).
   Запустите его во всех трёх клонах; ответы переиспользуются, в других клонах спросят только новое.
3. **Сервер** — распакуйте *AstoryServer Files* и *AstoryServer Database* на сервере и запустите
   `Prerequisites\setup_server.ps1 -Firewall`: он копирует стек, восстанавливает базы, создаёт логины SQL, источники ODBC и ключи, ставит службы EAC / Caddy / LogDrop;
   затем скопируйте выведенный `keys\server_public.h` в Astory Client и пересоберите клиент ([по шагам](Prerequisites/README.md#2-set-up-the-server--step-by-step)).
4. **Сборка** — `Patches\<имя>\build.bat`, `EacServer\build.bat`, `LogDrop\build.bat`.
5. **Выкладка** — скрипт `deploy_*.py` рядом с каждой частью (по умолчанию — сухой прогон).

Игроки подключаются через [Astory Client](https://github.com/sitxovski/AstoryClient).
Управлять сервером из браузера — [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter).

## Автор

Автор — **@sitxovski** (Discord).

Можно использовать свободно и без ограничений — [лицензия MIT](LICENSE). **Только укажите автора — @sitxovski (Discord) —
и ссылку на этот репозиторий, когда копируете, форкаете или используете любую часть проекта.**

---

<div align="center">

### ❤️ Поддержите труд на [**Boosty**](https://boosty.to/sitxovski_yurii)

### 💬 Присоединяйтесь к нашему сообществу в [**Discord**](https://discord.gg/DBPFczQKb2)

</div>
