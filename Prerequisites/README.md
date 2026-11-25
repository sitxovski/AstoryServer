# Astory Server — prerequisites, setup, connection, ports

Copyright (c) 2026 @sitxovski (Discord)

This repository holds the **source code** (patches, EAC server, LogDrop, tools, docs); the databases come only as clean `.bak` files. The ready game server and its
databases are two separate downloads — [Google Drive](https://drive.google.com/drive/folders/1GWlBoy64nsW05HBMXS-slBLDQinwxh4h?usp=sharing):

| Download | Put it into | What it is |
|---|---|---|
| **AstoryServer Files** | `AstoryServer\ServerFiles\` | the game server stack: LoginManager, GameServer ×3, NpcServer ×3, DBManager, ChannelManager, Relay / Operation / ItemRelay / OverlapCheck servers, EacServer (+ Caddy), LogDrop, gp7 gateway, configs and game data — no logs, no passwords, no keys |
| **AstoryServer Database** | `AstoryServer\Database\` | clean SQL Server backups `Joy1.bak`, `joylog1.bak`, `AsdaStoryOp.bak`, `AsdaStoryLogin.bak` — all game tables, procedures and reference data, **no player data** |

## 1. Install (game server machine)

| What | Version / settings | How |
|---|---|---|
| Windows | Windows Server 2019+ or Windows 10/11, x64, **static LAN address** | the stack processes are 32-bit, EacServer is 64-bit; every process listens on `ASTORY_SERVER_LAN_IP` — if DHCP gives the server another address the stack does not start (set a static IP or a DHCP reservation on the router) |
| **Microsoft SQL Server 2019 Express** | **15.0.2210.4** (RTM-GDR, KB5132751) — the version Astory runs on; any later 2019 update also works | <https://www.microsoft.com/download/details.aspx?id=101064> → *Custom* install |
| ↳ instance name | **`SQLEXPRESS`** | named instance (`<PC>\SQLEXPRESS`) |
| ↳ authentication | **Mixed Mode** (SQL Server and Windows) | the stack logs in as `devgsaccount`; `setup_server.ps1` stops early if it is not set (`-FixSql` sets it) |
| ↳ server collation | **`Cyrillic_General_CI_AS`** | *Server Configuration → Collation*. The databases keep their own collations (`Arabic_CI_AS`, `SQL_Latin1_General_CP1_CI_AS`); with another **server** collation (= `tempdb`) procedures with temporary tables fail with "collation conflict" |
| ↳ TCP/IP | enabled, port **1433** | *SQL Server Configuration Manager → Protocols → TCP/IP → Enabled*, *IPAll → TCP Port 1433*, restart the service (`-FixSql` does it). EacServer and the Admin Center connect over `tcp:127.0.0.1,1433` |
| ↳ command line tools | `sqlcmd` of SQL Server 2019 | installed with SQL Server 2019 (`…\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE`; the gp7 gateway calls this path). The new go-sqlcmd (winget `Microsoft.Sqlcmd`) is not tested with these scripts |
| ↳ disk space | ≥ 3 GB free on the SQL data drive | the small `.bak` files grow on restore (Joy1 ≈ 1 GB data + 1 GB log); `setup_server.ps1` checks it |
| ODBC driver "SQL Server" | built into Windows | used by the stack (`SQLSRV32.dll`) |
| Microsoft ODBC Driver 17 for SQL Server | latest | winget `Microsoft.msodbcsql.17` (tools, EacServer, Admin Center) |
| Visual C++ Redistributable 2015–2022 | x86 **and** x64 | winget `Microsoft.VCRedist.2015+.x86`, `Microsoft.VCRedist.2015+.x64` |
| Node.js LTS | 18+ | winget `OpenJS.NodeJS.LTS` (gp7 gateway) |
| Python | 3.11+ | winget `Python.Python.3.13`; `pip install -r requirements.txt` (deploy tools; `cryptography` also makes the traffic encryption key) |
| OpenSSH Server | — | `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` (deploy from your PC) |
| a domain name | — | an A record (e.g. `game.example.com`) → the server's public IP; it is `ASTORY_AUTH_HOST` |

To **build** the source on your PC you also need Visual Studio 2022 (C++ x86 + x64) and the EOS SDK 1.19.2.1 —
`install_prerequisites.bat` (on the PC) installs the tools.

### Which Windows account runs the stack

`start.bat` starts 32-bit programs that open the databases through the ODBC data sources `joy1`, `AsdaStoryOP`, `AsdaStoryLogin`.
`setup_server.ps1` creates them as **user** data sources of the account that runs the script (shown as "the stack will run as …").
So log on to the server as the account that will start the stack (for example `Administrator`) and run the script there with
*Run as administrator*. If you elevate with **another** administrator's password, the data sources land in that other account and
DBManager / LoginManager report "data source not found". Use `-SystemDsn` to create 32-bit **system** data sources that every account sees.
The services (EacServer, Caddy, LogDrop) run under their own accounts and do not need these data sources.

## 2. Set up the server — step by step

1. Install SQL Server 2019 Express as above.
2. Clone this repository, download [*AstoryServer Files.zip* and *AstoryServer Database.zip*](https://drive.google.com/drive/folders/1GWlBoy64nsW05HBMXS-slBLDQinwxh4h?usp=sharing) and unpack both into this
   folder (you get `ServerFiles\` and `Database\`).
3. Run **`_setup\configure.bat`**. It asks your values and writes them into the sources **and into `ServerFiles`**:
   server LAN / public IP, host name, server folder, domain, the `devgsaccount` password (`ASTORY_DB_PASSWORD`, also used by
   `DBInfo.ini [SQL_INFO]` of Operation / ItemRelay / Relay servers), and the LogSeal key id of your client (`ASTORY_LOGSEAL_KEY_ID`, see the table below).
4. Run as Administrator, logged on as the account that will run the stack:
   **`powershell -ExecutionPolicy Bypass -File Prerequisites\setup_server.ps1 -Firewall`**
   * checks: no placeholders left, SQL Server in Mixed Mode with TCP 1433 (`-FixSql` fixes both and restarts SQL Server), free disk space;
   * copies `ServerFiles` to `<ASTORY_SERVER_ROOT>\Working_ASDA\v2`. Into an **existing** stack it copies only the missing files, so your
     edited ini files stay; `-UpdateFiles` overwrites them with the package versions. The folder must be exactly
     `<ASTORY_SERVER_ROOT>\Working_ASDA\v2` (LogDrop.ini, EacServer.ini and the Caddyfile hold this absolute path);
   * restores the 4 databases into SQL Server (from a copy in the SQL Server data folder, owner `sa`). Existing databases are skipped;
     `-Force` overwrites them — run `stop_servers.bat` and close the Admin Center / SSMS first (open connections are cut);
   * creates the login `devgsaccount` (db_owner in the 4 databases, no server roles);
   * creates the logins `eac_auth` (EAC server) and `logdrop_ro` (LogDrop) with random passwords, re-signs the EAC
     procedures with fresh certificates and writes the passwords into the files the two services read (rights: Administrators,
     SYSTEM and, for LogDrop, `NT SERVICE\AsdaLogDrop` only);
   * creates the ODBC data sources `joy1`, `AsdaStoryOP`, `AsdaStoryLogin` (driver *SQL Server*, `AutoTranslate=No`) — see "Which Windows account";
   * makes the **traffic encryption key** if the stack has none (see step 6);
   * copies the admin bridge secrets from the Admin Center, if it is already deployed (see step 8);
   * installs the Windows services **AsdaEacServer**, **AsdaCaddy**, **AsdaLogDrop** (asks before each; `-SkipServices` skips them);
   * `-Firewall`: opens the player ports below in Windows Firewall.
5. Easy Anti-Cheat: put the credentials of your EOS **trusted server** client into `EacServer\secrets\eos.json`
   (`{"productId","sandboxId","deploymentId","clientId","clientSecret"}`, see `_setup\SETUP.md`), then `sc start AsdaEacServer`.
6. **Client key:** `setup_server.ps1` printed `"<ASTORY_SERVER_ROOT>\keys\server_public.h"`. Copy it over
   `AstoryClient\Source\AsdaNet\Private\Secure\server_public.h` and **build the client** — the client checks the server signature with
   this public key; a client with another key cannot log in. Keep a backup of the `keys` folder (it also holds the private key).
   New pair later: `setup_server.ps1 -NewSecureKey` (all clients must be rebuilt).
7. Forward the ports on your router (table below). Players inside your own LAN who connect by the domain need *NAT loopback / hairpin NAT* on the router.
8. Optional, the admin panel: deploy [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter), then run
   `setup_server.ps1 -SyncAdminBridge` and restart the stack — this copies `BRIDGE_PASSWORD` / `BRIDGE_HMAC_KEY` of the panel into
   `GameServer*\ConfigSet\admin_bridge.ini` (until then the bridge is off; nothing else depends on it).
9. Start: `<ASTORY_SERVER_ROOT>\Working_ASDA\v2\start.bat` (stop: `stop_servers.bat`; the three services keep running — `sc stop <name>`).

### Files that are not in the package

| File (in `Working_ASDA\v2`) | What it is | How you get it |
|---|---|---|
| `GameServer\`, `Ch2_GameServer\`, `Indun_GameServer\`, `LoginManager\` `secure_server.key` | private key of the traffic encryption (P61 / L07; EacServer reads `..\GameServer\secure_server.key` for the channel 15901) | `setup_server.ps1` makes it (`gen_secure_key.py`, or `Patches\AsdaSecure\out\keygen.exe`); its public half `server_public.h` goes into the client (step 6) |
| `EacServer\secrets\eos.json` | EOS trusted-server client | you, from the Epic Developer Portal (step 5) |
| `EacServer\secrets\sql_eac_auth.txt`, `LogDrop\service\secrets\sql_logdrop_ro.txt` | SQL passwords of `eac_auth` / `logdrop_ro` | `setup_server.ps1` (random) |
| `EacServer\secrets\jwt_rs256.key`, `refresh.dat`, `EacServer\www\.well-known\jwks.json` | token signing key, refresh tokens, public JWKS | EacServer creates them on its first start |
| `EacServer\secrets\admin_status.key` | secret of the `/status` page for the Admin Center (≥ 32 chars) | optional — without it `/status` is off; the Admin Center deploy notes describe it |
| `EacServer\caddy\data\` | Let's Encrypt account and certificates | Caddy creates it on its first start (TLS-ALPN on port 443; port 80 is not used) |
| `GameServer*\ConfigSet\admin_bridge.ini` values | admin bridge password + HMAC key | from the Admin Center (step 8) |
| `LogDrop\service\LogDrop.ini` `KeyIds` | key id (16 hex) of the LogSeal key built into **your** client — LogDrop accepts only logs sealed with it | `configure.bat` asks `ASTORY_LOGSEAL_KEY_ID`; `python AstoryClient\Tools\asda_logseal.py keygen` prints it (also in `AstoryClient\Tools\data\logseal\current.txt`); the same value goes into the client and the launcher |
| `GameServer*\HSPub.key` | public key of the old HackShield anti-cheat (not used: Easy Anti-Cheat replaces it, GameServer does not load HackShield) | not needed; from your own original server files if you ever turn HackShield on |
| logs, crash dumps | — | the stack writes them into the empty `Log*`, `Error_Log`, `OLEDB_LOG`, `PatchLog` folders |

`gp7-server\config.json` has `"testFixedBalance": 999999` (test mode: every account sees 999 999 premium points and purchases do not
lower it). Set it to `0` for real balances from `AsdaStoryLogin`.

## 3. What connects the client to the server

| Where | Setting | Value |
|---|---|---|
| client (compiled in) | `ASTORY_AUTH_HOST` (`Source\AsdaReborn\Public\Login\AsdaServerAddress.h`) | your domain; the client connects to **login port 15001** of this host |
| client (compiled in) | `Source\AsdaNet\Private\Secure\server_public.h` | the public key made by `setup_server.ps1` (section 2, step 6) |
| server `LoginManager\GameServerIP\*.ini`, `*\ConnectIPPORT.ini`, `*\UDP.ini`, `*\AcceptIp.ini`, `*\Patch.ini`, `GameServer\ConnectIP_Info\*.ini`, `ChannelManager\ini\Server_Info.ini` | `IP=` / `AcceptIpAddr000=` / `…ServerIp=` | the server's **LAN** address (`ASTORY_SERVER_LAN_IP`). When the login server hands a private address to the client, the client replaces it with `ASTORY_AUTH_HOST` |
| server `GameServer\PortalIP_Info\*.Ini`, `GameServer\ConfigSet\VillageServerConfig.Ini`, `ChannelManager\ini\Indun_Info.ini`, `ChannelManager\ini\EventMap.ini` | `IP=` / `GameServerIP_00=` | the server's **public** address (`ASTORY_SERVER_WAN_IP`) |
| server `DBManager\DBMng.ini`, `LoginManager\LoginMng.ini`, `*RelayServer\ini\DBInfo.ini`, `OperationServer\ini\DBInfo.ini`, `ItemRelayServer\ini\DBInfo.ini` | `GAMEDNS` / `GAMEUSER` / `GAMEPASS`, `[SQL_INFO] Id` / `Pass` / `Name` | ODBC data source `joy1`, login `devgsaccount`, its password (`ASTORY_DB_PASSWORD`) |
| server `EacServer\caddy\Caddyfile`, `EacServer\EacServer.ini` | site name, `Issuer` | your domain (Caddy gets a Let's Encrypt certificate itself through port 443) |
| launcher | `ASTORY_UPDATE_HOST`, `ASTORY_LAUNCHER_ROOT_PUBKEY` | your update host and release key (see Astory Client) |

All of these are placeholders filled by `_setup\configure.bat` — you normally do not edit them by hand.
Build the client **after** configuring it with the same domain and after copying `server_public.h`: [Astory Client](https://github.com/sitxovski/AstoryClient).

## 4. Ports

**Forward on the router (TCP → the server's LAN IP) and allow in Windows Firewall — players need them** (`setup_server.ps1 -Firewall` opens them):

| Port | Process | Purpose |
|---|---|---|
| 15001 | LoginManager | login, server / character list |
| 15601 | GameServer | game world, channel 1 |
| 15621 | Ch2_GameServer | game world, channel 2 |
| 15651 | Indun_GameServer | dungeons |
| 15901 | EacServer (sidecar) | Easy Anti-Cheat channel — the client connects to it directly |
| 443 | Caddy (service AsdaCaddy) | HTTPS: auth / EAC tokens (AsdaId), client log upload (LogDrop), status; Let's Encrypt certificate (TLS-ALPN) |

Port 80 is not needed (the Caddyfile disables the HTTP challenge; Caddy's HTTP port is 18080, local only).

**Only through your VPN / LAN — never forward to the internet:**

| Port | Process | Purpose |
|---|---|---|
| 22 | OpenSSH Server | deploy from your PC |
| 17890 | Astory Admin Center | the admin web panel ([Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter)) |
| 1433 | SQL Server | databases |
| 3389 | Remote Desktop | administration |

**Internal — the stack processes talk to each other on the LAN address / localhost; no forwarding:**
15101 DBManager · 15201 OverlapCheckServer · 15301 ChannelManager · 15401 ItemRelayServer · 15501 OperationServer ·
15701 / 15721 / 15751 NpcServer ×3 · 15801 / 15821 / 15851 RelayServer ×3 · 15702 EacServer ↔ GameServer bridge (127.0.0.1) ·
8444 / 8447 EacServer (behind Caddy) · 8446 LogDrop (behind Caddy) · 18080 Caddy HTTP (local) · 15022 gp7 gateway · 6116 / 6117 · 15995–15999.

## 5. Build the source (your PC)

| Part | Build | Output |
|---|---|---|
| AsdaPatch (GameServer DLL) | `Patches\AsdaPatch\build.bat` | `Patches\AsdaPatch\out\AsdaPatch.dll` |
| LoginPatch, DBPatch, SrvDbPatch, AddonNPC, AsdaSecure | `Patches\<name>\build.bat` | `Patches\<name>\out\` (AsdaSecure: also `keygen.exe`) |
| EacServer (x64) | `EacServer\build.bat` (needs the EOS SDK in `<ASTORY_DEV_ROOT>\ThirdParty\`) | `EacServer\out\AsdaEacServer.exe` |
| LogDrop | `LogDrop\build.bat` | `LogDrop\out\AsdaLogDrop.exe` |

Deploy a change: the `deploy_*.py` script next to the code (`Patches\<name>\tools\`) — dry run by default, copies over SSH with a
backup and md5 check. Stack restart with an in-game countdown: `python Patches\AsdaPatch\tools\restart_stack.py`.
Tools: `install_prerequisites.bat` (PC) / `install_prerequisites.bat -Server` (server).
