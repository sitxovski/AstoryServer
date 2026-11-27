<div align="center">

**English** · [Русский](README.ru.md) · [العربية](README.ar.md)

### ❤️ Like the project? Support the hard work on [**Boosty**](https://boosty.to/sitxovski_yurii)

### 💬 Join our community on [**Discord**](https://discord.gg/DBPFczQKb2)

# Astory Server

**Patches and services that power the Astory game server**

[Astory Client](https://github.com/sitxovski/AstoryClient) · [Astory Server](https://github.com/sitxovski/AstoryServer) · [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter)

</div>

---

> ⚠️ **Disclaimer.** This package (Not whole project!) was built using **Claude Code** and may contain issues. Feel free to DM me on Discord (**@sitxovski**) to get support.

## What's inside

| Folder | What it is |
|---|---|
| `Patches` | DLL patches for the server processes: fixes, new features, anti-cheat, admin bridge |
| `EacServer` | Easy Anti-Cheat server |
| `LogDrop` | receiver for client crash and diagnostic logs |
| `Patches\Gp7Gateway` | shop and balance gateway (Node.js) |
| `Tools` | anti-cheat reports and metrics |
| `Docs` | how every patch works — start with [`Docs/INDEX.md`](Docs/INDEX.md) |
| `Prerequisites` | what to install, how to build and run |

> 📦 **The game server and its clean databases are separate downloads** — [*AstoryServer Files* and *AstoryServer Database* (Google Drive)](https://drive.google.com/drive/folders/1GWlBoy64nsW05HBMXS-slBLDQinwxh4h?usp=sharing). Setup, SQL Server, connecting the client and router ports: [Prerequisites/README.md](Prerequisites/README.md).

## Quick start

1. **Install** — run `Prerequisites\install_prerequisites.bat` on your PC and `... -Server` on the server ([details](Prerequisites/README.md)).
2. **Configure** — run `_setup\configure.bat` (server address, folders, SSH key — [where to get them](_setup/SETUP.md)).
   Run it in all three clones; the answers are reused, so the other clones ask only what is new.
3. **Server** — unpack *AstoryServer Files* and *AstoryServer Database* on the server and run
   `Prerequisites\setup_server.ps1 -Firewall`: it copies the stack, restores the databases, creates the SQL logins, ODBC sources and keys, installs the EAC / Caddy / LogDrop services;
   then copy the printed `keys\server_public.h` into Astory Client and rebuild it ([step by step](Prerequisites/README.md#2-set-up-the-server--step-by-step)).
4. **Build** — `Patches\<name>\build.bat`, `EacServer\build.bat`, `LogDrop\build.bat`.
5. **Deploy** — the `deploy_*.py` script next to each part (dry run by default).

Players connect with [Astory Client](https://github.com/sitxovski/AstoryClient).
Manage the server from the browser with [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter).

## Credits

Made by **@sitxovski** (Discord).

Free to use for anything, no restrictions — [MIT License](LICENSE). **Just credit the original author — @sitxovski (Discord) —
and link to this repository when you copy, fork or reuse any part of it.**

---

<div align="center">

### ❤️ Support the hard work on [**Boosty**](https://boosty.to/sitxovski_yurii)

### 💬 Join our community on [**Discord**](https://discord.gg/DBPFczQKb2)

</div>
