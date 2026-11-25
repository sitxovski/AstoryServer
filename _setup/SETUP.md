# Astory — setup for your own machines and accounts

Copyright (c) 2026 @sitxovski (Discord)

The public sources of **Astory Admin Center**, **Astory Client** and **Astory Server** do not contain the original author's
addresses, paths, host names, accounts or keys. In their place there are placeholders like `@@ASTORY_SERVER_VPN_IP@@`.

> **Кратко по-русски.** Запустите `_setup\configure.bat`: он спросит ваши адреса, пути, домены и ключи Epic, подставит их
> в этот репозиторий (ответы, уже данные в соседнем репозитории Astory, он подставит сам) и при желании сгенерирует новые ключи шифрования клиента. Где взять каждое значение — таблица ниже.
> Пароли, токены и закрытые ключи в исходниках не хранятся вообще: их создают скрипты выкладки или вы сами (раздел 3).

## 1. Run the configurator

1. Install **Python 3.11+** (with `pip install cryptography`) and **PowerShell 5.1+** (built into Windows).
2. Double-click `_setup\configure.bat` (or `powershell -ExecutionPolicy Bypass -File _setup\configure.ps1`).
3. Answer the questions (only the values used by THIS repository are asked; answers already given in another Astory
   repository cloned next to it are offered as defaults). **Enter** keeps the default in brackets, **`-`** skips a value (the placeholder stays; run again later).
4. Astory Client only: say **y** to generate new pak keys (or later: `python AstoryClient\Tools\gen_build_crypto.py`).
5. Check what is left: `_setup\configure.bat -Check`.

Your answers are saved to `_setup\astory.settings.local.json` (git-ignored — never commit it).
`configure.ps1 -NonInteractive` replays that file without questions (e.g. on a second PC).
Placeholders are replaced **in place** — run the script on a fresh clone; to change a value, `git checkout -- .` and run again.

## 2. Values the configurator asks for

| Placeholder | What it is | Where to get it |
|---|---|---|
| `ASTORY_DEV_ROOT` | folder on your development PC holding the projects | any folder (see "Folder layout" below) |
| `ASTORY_DEV_USER` | your Windows user name | `echo %USERNAME%` |
| `ASTORY_DEV_PC` | your PC name (with `ASTORY_DEV_USER` it is also the `<UserId>` of the Admin Center scheduled tasks) | `echo %COMPUTERNAME%` |
| `ASTORY_DEV_PYTHON` | python.exe on your PC for the Admin Center scheduled tasks (`deploy\schtasks`) | `where python` (offered automatically); empty = you don't use the tasks |
| `ASTORY_SERVER_HOSTNAME` | Windows name of the game server machine | on the server: `hostname` |
| `ASTORY_SERVER_ROOT` | server folder with `Working_ASDA\v2` (game stack), `AdminCenter`, `DbBackup` | where you unpacked the server stack |
| `ASTORY_SERVER_VPN_IP` | server address in your VPN | on the server: `tailscale ip -4` ([Tailscale](https://tailscale.com) is free for small teams); without a VPN — the LAN address |
| `ASTORY_SERVER_LAN_IP` | server address in the local network | on the server: `ipconfig` |
| `ASTORY_SERVER_WAN_IP` | public internet address of the server | <https://ifconfig.me> from the server network, or the router status page |
| `ASTORY_SSH_KEY_NAME` | SSH key file in `%USERPROFILE%\.ssh` used by the tools to reach the server | `ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\astory_server`; on the server install *OpenSSH Server* (Settings → Optional features) and append the `.pub` file to `C:\ProgramData\ssh\administrators_authorized_keys` |
| `ASTORY_DOMAIN` | your web domain | your domain registrar |
| `ASTORY_AUTH_HOST` | host of the auth / EAC token node (AsdaId) that the launcher and client talk to | a DNS A record to the server + a TLS certificate (e.g. [Let's Encrypt](https://letsencrypt.org), `win-acme` on Windows); see `AstoryServer\EacServer\README.md` |
| `ASTORY_UPDATE_HOST` | HTTPS host that serves launcher/game updates | a DNS record + any static HTTPS hosting; the store is uploaded by `AstoryClient\DEPLOY\Patch\4_Upload.bat` |
| `ASTORY_TELEGRAM_BOT` | Telegram bot name for owner notifications (Admin Center) | Telegram → [@BotFather](https://t.me/BotFather) → `/newbot` |
| `ASTORY_EOS_PRODUCT_ID` | Epic Online Services product | <https://dev.epicgames.com/portal> → your product → *Product Settings* → *SDK Download & Credentials* |
| `ASTORY_EOS_SANDBOX_ID` | EOS sandbox | same page |
| `ASTORY_EOS_DEPLOYMENT_ID` | EOS deployment | same page |
| `ASTORY_EOS_CLIENT_ID` / `ASTORY_EOS_CLIENT_SECRET` | EOS client for the **game client** (policy *GameClient*) | *Product Settings* → *Clients* → *Add new client*. Enable **Easy Anti-Cheat** for the product in the portal; under *Anti-Cheat* download the integrity keys `base_private.key` and `base_public.cer` into the root of `<ASTORY_DEV_ROOT>\ThirdParty\EOS-SDK-58105819-Release-v1.19.2.1\` (never into git) |
| `ASTORY_LAUNCHER_ROOT_PUBKEY` | public root key the launcher trusts for update signatures (64 hex) | `python AstoryClient\Tools\asda_release.py keys init` → hex of `keys\root.pub` in your release store; leave empty on the first run and run the configurator again |
| `ASTORY_UPDATE_SSH_HOST` / `ASTORY_UPDATE_SSH_USER` / `ASTORY_UPDATE_SSH_ROOT` | where the release tools upload updates over SFTP | your update server (host usually = `ASTORY_UPDATE_HOST`, a dedicated SFTP user, the web root such as `/www`); pin its host key first — `AstoryClient\DEPLOY\README.md` |
| `ASTORY_LOGSEAL_KEY_ID` | id of your sealed-log key (16 hex; several: comma-separated) — the launcher uploads and LogDrop accepts only logs sealed with it | `python AstoryClient\Tools\asda_logseal.py keygen` → `AstoryClient\Tools\data\logseal\current.txt`; leave empty on the first run, run configure again after keygen |
| `ASTORY_INSTALLER_APP_GUID` | unique id of your player installer | generated automatically on the first run — never change it later |
| `ASTORY_SERVER_PYTHON` | python.exe on the game server (Admin Center service) | on the server: `where python` |
| `ASTORY_DB_PASSWORD` | password of the SQL login `devgsaccount` the game server uses | make it up; `AstoryServer\Prerequisites\setup_server.ps1` creates the login |
| `ASTORY_DISCORD_*` | ids of your Discord server, channels and roles (Admin Center bot) | Discord → *Developer Mode* on → right-click → *Copy ID*; configure shows where each is used. Needed by the bot: `GENERAL`, `LOBBY_CH`, `SUPPORT_CH`, `BUG_REPORTS`, `STAFF_CHAT`, `MOD_LOG`, `CHAT_CATEGORY`; for `/register`: `GUILD`, `INSTALLER_CH`, `INSTALLER_MSG`; the rest (`RULES_CH`, `DONATIONS_*`, `SUGGESTIONS_CH`, `IMPORTANT_CAT`) are optional. A missing id never crashes the bot — that feature is switched off and the log says so; configure lists what is still empty |

Derived automatically: `ASTORY_DEV_ROOT_FWD`, `ASTORY_DEV_ROOT_ESC`, `ASTORY_SERVER_ROOT_FWD`, `ASTORY_SERVER_ROOT_ESC`
(the same paths with `/` and `\\`). Generated, never typed: the client pak keys (by `gen_build_crypto.py`).

## 3. Secrets that are never in the sources

Passwords, tokens and private keys are created on your side. Keep them out of git (`.gitignore` already covers them).

### Astory Admin Center (`AstoryAdminCenter`)
| Secret | Created by | Notes |
|---|---|---|
| SQL logins `asda_admin`, `asda_ops`, `asda_bridge`, `asda_reports` and their passwords; `TOTP_KEY` | `deploy\deploy_admin_center.py` on the first deploy (random) | stored only on the server in `<ASTORY_SERVER_ROOT>\AdminCenter\secrets\asda_admin.ini` (Administrators + SYSTEM only) |
| HTTPS certificate of the panel | same deploy, first run (self-signed ECDSA, 10 years) | the public part is saved as `deploy\asda_admin_center.crt` — install it on your devices as a trusted root |
| first panel user | you: `python asda_admin.py user-add <login> --role owner` | then enable two-factor in "My account" |
| Telegram bot token + your chat id | you, from @BotFather and `https://api.telegram.org/bot<token>/getUpdates` after writing to the bot | put into `AstoryAdminCenter\DiscordBot\telegram.env` (`TG_TOKEN=…`, `TG_CHAT=…`) — the panel never sees it |
| SQL Server | you: SQL Server Express with the game databases (Joy1, joylog1, AsdaStoryOp, AsdaStoryLogin) | the deploy connects as Windows `Administrator` via shared memory to create the logins |
| SQL instance name (not a placeholder) | you | the deploy uses `SQLEXPRESS`; for another instance set the environment variable `ASTORY_SQL_INSTANCE` on the PC you deploy from |
| Bot proxy (optional) | you | the bots connect directly by default; to use a proxy put `DISCORD_PROXY=` / `TELEGRAM_PROXY=` (or `HTTPS_PROXY=`) into `AstoryAdminCenter\DiscordBot\.env` |

### Astory Server (`AstoryServer`)
| Secret | Created by | Notes |
|---|---|---|
| Admin bridge (P127) password + HMAC key | the Astory Admin Center deploy (`deploy_admin_center.py`, random) → `<ASTORY_SERVER_ROOT>\AdminCenter\secrets\asda_admin.ini` | copied into `GameServer*\ConfigSet\admin_bridge.ini` by `Prerequisites\setup_server.ps1 -SyncAdminBridge` (or `Patches\AsdaPatch\tools\deploy_p127.py`); restart the stack after it. Until then the bridge is off |
| EAC server: `secrets\eos.json` | you | `{"productId","sandboxId","deploymentId","clientId","clientSecret"}` of a **separate trusted-server client** (*Product Settings → Clients*, policy for game servers / *TrustedServer*) |
| EAC server: `jwt_rs256.key`, `refresh.dat` | EacServer on first start | stay in `EacServer\secrets` |
| Traffic encryption key `secure_server.key` | `Prerequisites\setup_server.ps1` (via `gen_secure_key.py`; `-NewSecureKey` for a new pair) | private half next to the game servers and LoginManager; the public half `<ASTORY_SERVER_ROOT>\keys\server_public.h` goes into the client `Source\AsdaNet\Private\Secure\` — rebuild the client |
| SQL logins `eac_auth` (EAC server) and `logdrop_ro` (LogDrop), EAC certificate signatures | `AstoryServer\Prerequisites\setup_server.ps1` (random passwords) | written to `EacServer\secrets\sql_eac_auth.txt` and `LogDrop\service\secrets\sql_logdrop_ro.txt` of the stack |
| `AdminStatus` secret (EAC status for the panel) | EacServer deploy (≥ 32 chars) | a copy goes to `<ASTORY_SERVER_ROOT>\AdminCenter\secrets\eac_status.key` |
| gp7 gateway keys | `Patches\Gp7Gateway\deploy_gp7_*.py` | see the scripts' headers |

### Astory Client (`AstoryClient`)

* Clone it into a folder named exactly `AstoryClient` (a GitHub ZIP unpacks as `AstoryClient-main` — rename it).
* Unreal Engine not installed by the Epic Games Launcher: set the environment variable `ASDA_UE_DIR` to the engine folder.
* Before the first Shipping build: `python AstoryClient\Tools\asda_logseal.py keygen`, back it up with `… export-backup`, put the key id into `ASTORY_LOGSEAL_KEY_ID` (run configure again) and rebuild the launcher — details in `AstoryClient\Prerequisites\README.md`.

| Secret | Created by | Notes |
|---|---|---|
| pak encryption key + signing key pair | `AstoryClient\Tools\gen_build_crypto.py` (new keys per build) | writes `Config\DefaultCrypto.ini` and `Source\AsdaCore\Private\Crypto\AsdaPakKey.generated.h` (both git-ignored — they hold your real keys); without them the client builds but pak files are not encrypted |
| release keys (root + release) for launcher updates | `AstoryClient\Tools\asda_release.py keys init`; back up with `AstoryClient\DEPLOY\Patch\Keys_Backup.bat` | the root **public** key goes to `ASTORY_LAUNCHER_ROOT_PUBKEY`; private keys never leave your PC |
| upload SSH key for the update host | you (`ssh-keygen`) | `%USERPROFILE%\.ssh\asdaupd_upload`, see `DEPLOY\README.md` |
| Unreal Engine 5.8, Visual Studio 2022, Inno Setup 6.5+ | you | `DEPLOY\README.md` → requirements |

## 4. Folder layout

Clone the three repositories **side by side** into one folder (this folder is `ASTORY_DEV_ROOT`):

```
<ASTORY_DEV_ROOT>
  AstoryClient\            https://github.com/sitxovski/AstoryClient  (+ Content\ from "AstoryClient Resources")
  AstoryServer\            https://github.com/sitxovski/AstoryServer
  AstoryAdminCenter\       https://github.com/sitxovski/AstoryAdminCenter
  ThirdParty\              you add: EOS SDK 1.19.2.1 (EOS-SDK-58105819-Release-v1.19.2.1) from the Epic Developer Portal
  Releases\                created by the release tools (update store, keys) - keep it private
  Donors\                  optional: original game client / server files read by the import tools
```

Each repository works on its own; tools that use another project (for example the Admin Center deploy reading the
anti-cheat tools of Astory Server) find it next to them. Python tools take their base paths from
`AstoryClient\Tools\asda_paths.py` (each can be overridden by an environment variable: `ASDA_ROOT`, `ASDA_DONORS`, ...).

## 5. Not included

* Original game client and server binaries, game data dumps and extracted raw assets — you need your own legal copy.
* Build outputs, caches, test-run results, logs, backups and rollback scripts.
* Third-party code keeps its own license (`AstoryClient\Launcher\third_party\zstd`, `AstoryClient\Source\ThirdParty`,
  `AstoryClient\Launcher\third_party`).
* Imported textures in `AstoryClient\Content` remember a neutral source path (editor import metadata only, not used by the game) - re-import them from your own exported PNG files if you ever need to.

## 6. Texts inside assets to change in the editor

* `Content/AsdaAssets/UI/Login/WBP_LOGIN_WIN` shows a web address on the login window (`astory.example`): open the widget in the Unreal Editor and type your domain.
