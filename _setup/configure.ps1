# Copyright (c) 2026 @sitxovski (Discord)
#
# configure.ps1 - one-time setup of this Astory repository for YOUR machines and accounts.
#
# The public sources contain placeholders like @@ASTORY_SERVER_VPN_IP@@ instead of the original author's addresses, paths,
# host names and keys. This script asks for your values (or reads them from _setup\astory.settings.local.json),
# replaces every placeholder in this repository and (Astory Client only) can generate fresh pak keys.
# Answers given in another Astory repository cloned next to this one are offered as defaults.
# Where to get each value: _setup\SETUP.md.
#
# Usage:
#   configure.bat                         interactive (asks every value, Enter keeps the shown default)
#   configure.ps1 -NonInteractive         take everything from astory.settings.local.json / defaults, ask nothing
#   configure.ps1 -Check                  only list placeholders that are still left in the sources
#
# Run it on a FRESH copy of the sources: placeholders are replaced in place. To change a value later, restore the
# files from git (git checkout -- .) and run it again. Your answers are saved to _setup\astory.settings.local.json
# (never commit that file - it is in .gitignore).

param(
    [switch]$NonInteractive,
    [switch]$Check,
    [string]$SettingsFile = ""
)

$ErrorActionPreference = 'Stop'
$SetupDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Project = Split-Path -Parent $SetupDir          # this repository (AstoryClient, AstoryServer or AstoryAdminCenter)
$Root = Split-Path -Parent $Project              # the folder where the Astory repositories are cloned side by side
if (-not $SettingsFile) { $SettingsFile = Join-Path $SetupDir 'astory.settings.local.json' }

$SkipDirs = @('Content', '.git', '__pycache__', '_setup', 'Binaries', 'Intermediate', 'Saved', 'DerivedDataCache')
$TextExt = @('.py', '.cpp', '.h', '.hpp', '.c', '.cc', '.cs', '.js', '.mjs', '.ts', '.ps1', '.psm1', '.bat', '.cmd', '.sql', '.css',
             '.html', '.htm', '.md', '.txt', '.ini', '.json', '.cfg', '.conf', '.toml', '.yml', '.yaml', '.xml', '.iss', '.cmake',
             '.uproject', '.uplugin', '.csv', '.tsv', '.rc', '.manifest', '.svg', '.sh', '.inc', '.def')

# ---------------------------------------------------------------------------------------------------------------------
# Settings: token, question, default, hint (where to get it). Order = order of questions.
# ---------------------------------------------------------------------------------------------------------------------
$Settings = @(
    @{ T = 'ASTORY_DEV_ROOT';          Q = 'Folder on your PC where the Astory repositories are cloned side by side (AstoryClient, AstoryServer, AstoryAdminCenter)'; D = $Root;
       H = 'The parent folder of this repository (the default). Tools that work across projects find each other there.' },
    @{ T = 'ASTORY_DEV_USER';          Q = 'Your Windows user name on the development PC';                        D = $env:USERNAME;
       H = 'echo %USERNAME% in a command prompt.' },
    @{ T = 'ASTORY_DEV_PC';            Q = 'Your development PC name';                                            D = $env:COMPUTERNAME;
       H = 'echo %COMPUTERNAME% in a command prompt. Also used as <UserId> PC\user of the Admin Center scheduled tasks.' },
    @{ T = 'ASTORY_DEV_PYTHON';        Q = 'Full path to python.exe on your development PC (Admin Center scheduled tasks)'; D = '';
       H = 'where python (not the WindowsApps stub). Leave empty if you do not use the scheduled tasks.' },
    @{ T = 'ASTORY_SERVER_HOSTNAME';   Q = 'Game server Windows machine name';                                    D = '';
       H = 'e.g. GAMESERVER. On the server: hostname (or echo %COMPUTERNAME%).' },
    @{ T = 'ASTORY_SERVER_ROOT';       Q = 'Game server root folder (holds Working_ASDA\v2, AdminCenter, DbBackup)'; D = 'C:\ASDA';
       H = 'The folder on the server where you unpacked the game server stack.' },
    @{ T = 'ASTORY_DB_PASSWORD';       Q = 'Password of the SQL Server login "devgsaccount" (the game server stack uses it)'; D = '';
       H = 'Make up a strong password (letters + digits, no quotes). Prerequisites\setup_server.ps1 creates the login with it.' },
    @{ T = 'ASTORY_SERVER_PYTHON';     Q = 'Full path to python.exe on the game server (runs the Admin Center service)'; D = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe';
       H = 'On the server: where python (Python 3.11+; the default is a per-user install of Python 3.13 for Administrator).' },
    @{ T = 'ASTORY_SERVER_VPN_IP';     Q = 'Game server address in your VPN (Tailscale / WireGuard)';             D = '';
       H = 'e.g. 100.64.0.1. On the server: tailscale ip -4. Without a VPN use the LAN address here too.' },
    @{ T = 'ASTORY_SERVER_LAN_IP';     Q = 'Game server address in your local network';                           D = '';
       H = 'e.g. 192.168.0.10. On the server: ipconfig -> IPv4 Address of the network adapter.' },
    @{ T = 'ASTORY_SERVER_WAN_IP';     Q = 'Public (internet) address of the game server';                        D = '';
       H = 'e.g. 203.0.113.10. Open https://ifconfig.me from the server network, or your router status page. Players connect to it.' },
    @{ T = 'ASTORY_SSH_KEY_NAME';      Q = 'SSH key file name in %USERPROFILE%\.ssh used to reach the server';     D = 'astory_server';
       H = 'ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\astory_server, then append the .pub file to the server file C:\ProgramData\ssh\administrators_authorized_keys (OpenSSH Server must be installed on the server).' },
    @{ T = 'ASTORY_DOMAIN';            Q = 'Your main web domain';                                                 D = '';
       H = 'e.g. example.com. The domain you own (DNS at your registrar).' },
    @{ T = 'ASTORY_AUTH_HOST';         Q = 'Host name of the auth / EAC token node (AsdaId) used by the launcher';  D = '';
       H = 'e.g. auth.example.com. A DNS A record pointing to the server, with a TLS certificate (e.g. Let''s Encrypt). See AstoryServer\EacServer\README.md.' },
    @{ T = 'ASTORY_UPDATE_HOST';       Q = 'Host name of the update server (launcher downloads)';                  D = '';
       H = 'e.g. update.example.com. A DNS record for the HTTPS host that serves the release store uploaded by AstoryClient\DEPLOY\Patch.' },
    @{ T = 'ASTORY_UPDATE_SSH_HOST';   Q = 'SSH / SFTP host the release tools upload updates to';                  D = '';
       H = 'Usually the same as ASTORY_UPDATE_HOST (offered as default). Pin its host key first: AstoryClient\DEPLOY\README.md (ssh-keyscan + fingerprint check).' },
    @{ T = 'ASTORY_UPDATE_SSH_USER';   Q = 'SFTP user for uploading updates';                                     D = 'asdaupd';
       H = 'A user you created on the update server (a chroot SFTP-only user is recommended).' },
    @{ T = 'ASTORY_UPDATE_SSH_ROOT';   Q = 'Web root of the update site inside the SFTP account (starts with /)';  D = '/www';
       H = 'The folder your web server serves as ASTORY_UPDATE_HOST.' },
    @{ T = 'ASTORY_LOGSEAL_KEY_ID';    Q = 'Sealed-log key id (16 hex chars)';                                    D = '';
       H = 'python AstoryClient\Tools\asda_logseal.py keygen, then the content of AstoryClient\Tools\data\logseal\current.txt. Leave empty now and run configure again after keygen.' },
    @{ T = 'ASTORY_INSTALLER_APP_GUID'; Q = 'Installer AppId GUID (unique for your game, never change it later)';  D = '';
       H = 'Press Enter: a new random GUID is generated once and kept in astory.settings.local.json.' },
    @{ T = 'ASTORY_TELEGRAM_BOT';      Q = 'Telegram bot user name for owner notifications (without @)';            D = '';
       H = 'e.g. my_astory_bot. Create a bot with @BotFather in Telegram (/newbot). The token itself is NOT stored in the sources - see SETUP.md.' },
    @{ T = 'ASTORY_EOS_PRODUCT_ID';    Q = 'Epic Online Services: Product ID';                                     D = '';
       H = 'https://dev.epicgames.com/portal -> your product -> Product Settings -> SDK Download & Credentials.' },
    @{ T = 'ASTORY_EOS_SANDBOX_ID';    Q = 'Epic Online Services: Sandbox ID';                                     D = '';
       H = 'Same page: the sandbox you use (Live / Stage / Dev).' },
    @{ T = 'ASTORY_EOS_DEPLOYMENT_ID'; Q = 'Epic Online Services: Deployment ID';                                  D = '';
       H = 'Same page: the deployment of that sandbox.' },
    @{ T = 'ASTORY_EOS_CLIENT_ID';     Q = 'Epic Online Services: GAME CLIENT Client ID';                          D = '';
       H = 'Product Settings -> Clients -> add a client with the "GameClient" policy. (The EAC server uses a separate trusted-server client - SETUP.md.)' },
    @{ T = 'ASTORY_EOS_CLIENT_SECRET'; Q = 'Epic Online Services: GAME CLIENT Client Secret';                      D = '';
       H = 'Shown next to the Client ID. A game-client secret ships inside the game, it is not a server secret.' },
    @{ T = 'ASTORY_LAUNCHER_ROOT_PUBKEY'; Q = 'Launcher update root public key (64 hex chars)';                    D = '';
       H = 'python AstoryClient\Tools\asda_release.py keys init -> hex of keys\root.pub in your release store. Leave empty now and run configure again after keys init.' }
)
$Derived = @{
    'ASTORY_DEV_ROOT_FWD'    = { param($v) $v['ASTORY_DEV_ROOT'].Replace('\', '/') }
    'ASTORY_DEV_ROOT_ESC'    = { param($v) $v['ASTORY_DEV_ROOT'].Replace('\', '\\') }
    'ASTORY_SERVER_ROOT_FWD' = { param($v) $v['ASTORY_SERVER_ROOT'].Replace('\', '/') }
    'ASTORY_SERVER_ROOT_ESC' = { param($v) $v['ASTORY_SERVER_ROOT'].Replace('\', '\\') }
}
# generated by AstoryClient\Tools\gen_build_crypto.py (asked below), not typed in
$Generated = @('ASTORY_PAK_ENCRYPTION_KEY', 'ASTORY_PAK_SIGNING_MODULUS', 'ASTORY_PAK_SIGNING_PRIVATE_EXPONENT', 'ASTORY_PAK_KEY_BUILD_ID')

function Get-SourceFiles {
    Get-ChildItem -LiteralPath $Project -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
        $rel = $_.FullName.Substring($Project.Length)
        $parts = $rel.Split('\')
        -not ($parts | Where-Object { $SkipDirs -contains $_ }) -and
        (($TextExt -contains $_.Extension.ToLower()) -or $_.Name -eq 'CMakeLists.txt' -or ($_.Extension -eq '' -and $_.Length -lt 1MB))
    }
}

# Byte-safe text access: UTF-16 files (with BOM) are decoded as UTF-16; everything else as Latin-1, which maps every byte to
# one character and back unchanged - so legacy Korean / Cyrillic / UTF-8 files keep their bytes; only the ASCII
# placeholders are replaced (the inserted value is written as UTF-8 bytes).
$Latin1 = [Text.Encoding]::GetEncoding(28591)
function Read-Utf8([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return @{ Text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2); Kind = 'utf16' }
    }
    return @{ Text = $Latin1.GetString($bytes); Kind = 'bytes' }
}
function Write-Text([string]$path, [string]$text, [string]$kind) {
    if ($kind -eq 'utf16') { [IO.File]::WriteAllBytes($path, [byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes($text)) }
    else { [IO.File]::WriteAllBytes($path, $Latin1.GetBytes($text)) }
}
function As-Bytes([string]$value, [string]$kind) {
    if ($kind -eq 'utf16') { return $value }
    return $Latin1.GetString([Text.Encoding]::UTF8.GetBytes($value))   # UTF-8 bytes, carried through Latin-1
}

function Show-Left {
    $left = @{}
    foreach ($f in Get-SourceFiles) {
        $t = (Read-Utf8 $f.FullName).Text
        foreach ($m in [regex]::Matches($t, '@@(ASTORY_[A-Z0-9_]+)@@')) { $left[$m.Groups[1].Value] = 1 + [int]$left[$m.Groups[1].Value] }
    }
    if ($left.Count -eq 0) { Write-Host 'No placeholders left - the sources are configured.' -ForegroundColor Green; return }
    Write-Host 'Placeholders still in the sources:' -ForegroundColor Yellow
    $left.GetEnumerator() | Sort-Object Name | ForEach-Object { '  {0,-40} {1}' -f $_.Name, $_.Value }
}

if ($Check) { Show-Left; exit 0 }

# ---------------------------------------------------------------------------------------------------------------------
# 1. values
# ---------------------------------------------------------------------------------------------------------------------
# answers: this repository first, then the other Astory repositories cloned next to it (so you type each value once)
$saved = @{}
$files = @($SettingsFile) + @(Get-ChildItem -Path (Join-Path $Root 'Astory*\_setup\astory.settings.local.json') -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach ($sf in $files) {
    if (-not (Test-Path $sf)) { continue }
    (Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { if (-not $saved.ContainsKey($_.Name)) { $saved[$_.Name] = $_.Value } }
}
# only the placeholders that really are in this repository are asked
$present = @{}
foreach ($f in Get-SourceFiles) {
    foreach ($m in [regex]::Matches((Read-Utf8 $f.FullName).Text, '@@(ASTORY_[A-Z0-9_]+)@@')) { $present[$m.Groups[1].Value] = 1 }
}
$values = @{}
Write-Host ''
Write-Host 'Astory - configure the sources for your machines and accounts' -ForegroundColor Cyan
Write-Host 'Enter keeps the value in [brackets]. A single "-" skips the value (placeholder stays, run again later).'
Write-Host ''
foreach ($s in $Settings) {
    if (-not ($present.ContainsKey($s.T) -or $present.ContainsKey($s.T + '_FWD') -or $present.ContainsKey($s.T + '_ESC'))) { continue }
    $def = if ($saved.ContainsKey($s.T)) { [string]$saved[$s.T] } else { [string]$s.D }
    if (-not $def -and $s.T -eq 'ASTORY_UPDATE_SSH_HOST' -and $values.ContainsKey('ASTORY_UPDATE_HOST')) { $def = $values['ASTORY_UPDATE_HOST'] }
    if (-not $def -and $s.T -eq 'ASTORY_DEV_PYTHON') {
        $py = Get-Command python -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
        if ($py) { $def = $py.Source }
    }
    if (-not $def -and $s.T -eq 'ASTORY_INSTALLER_APP_GUID') { $def = [guid]::NewGuid().ToString().ToUpper() }
    if ($NonInteractive) { $v = $def }
    else {
        Write-Host ($s.Q) -ForegroundColor White
        Write-Host ('  where: ' + $s.H) -ForegroundColor DarkGray
        $v = Read-Host ('  [' + $def + ']')
        if ($v -eq '') { $v = $def }
    }
    if ($v -eq '-' -or $v -eq '') { Write-Host ('  skipped: ' + $s.T) -ForegroundColor DarkYellow; continue }
    $values[$s.T] = $v.Trim()
}
# other placeholders found in the sources (Discord IDs of the bot and anything not in the list above): ask each, showing where it is used
$known = @{}; foreach ($s in $Settings) { $known[$s.T] = 1 }; foreach ($k in $Derived.Keys) { $known[$k] = 1 }; foreach ($k in $Generated) { $known[$k] = 1 }
$extra = [ordered]@{}
foreach ($f in Get-SourceFiles) {
    $lines = (Read-Utf8 $f.FullName).Text -split "`n"
    for ($n = 0; $n -lt $lines.Count; $n++) {
        foreach ($m in [regex]::Matches($lines[$n], '@@(ASTORY_[A-Z0-9_]+)@@')) {
            $t = $m.Groups[1].Value
            if ($t.EndsWith('_ns')) { continue }
            if (-not $known.ContainsKey($t) -and -not $extra.Contains($t)) {
                $extra[$t] = ('{0}:{1}  {2}' -f $f.FullName.Substring($Project.Length + 1), ($n + 1), $lines[$n].Trim())
            }
        }
    }
}
# Discord ids the Admin Center bot needs (others are optional: a missing id only switches its feature off)
$DiscordBotRequired = @('ASTORY_DISCORD_GENERAL', 'ASTORY_DISCORD_LOBBY_CH', 'ASTORY_DISCORD_SUPPORT_CH', 'ASTORY_DISCORD_BUG_REPORTS',
    'ASTORY_DISCORD_STAFF_CHAT', 'ASTORY_DISCORD_MOD_LOG', 'ASTORY_DISCORD_CHAT_CATEGORY',
    'ASTORY_DISCORD_GUILD', 'ASTORY_DISCORD_INSTALLER_CH', 'ASTORY_DISCORD_INSTALLER_MSG')
$discordLeft = New-Object System.Collections.Generic.List[string]
foreach ($t in $extra.Keys) {
    $def = if ($saved.ContainsKey($t)) { [string]$saved[$t] } else { '' }
    if (-not $def -and $t -like 'ASTORY_SECRET_*') {
        # passwords / HMAC keys of the server stack: a fresh random value is offered (64 hex chars)
        $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
        $def = -join ($b | ForEach-Object { $_.ToString('x2') })
    }
    if ($NonInteractive) { $v = $def }
    else {
        Write-Host $t -ForegroundColor White
        if ($t -like 'ASTORY_DISCORD_*') {
            Write-Host '  where: Discord -> User Settings -> Advanced -> Developer Mode ON, then right-click the server / channel / role / user -> Copy ID.' -ForegroundColor DarkGray
            if ($DiscordBotRequired -contains $t) { Write-Host '  needed by the Discord bot (/register uses GUILD + INSTALLER_*)' -ForegroundColor DarkYellow }
            else { Write-Host '  optional: empty = this feature of the bot stays off' -ForegroundColor DarkGray }
        }
        $ctx = $extra[$t]; if ($ctx.Length -gt 160) { $ctx = $ctx.Substring(0, 160) + '...' }
        Write-Host ('  used in: ' + $ctx) -ForegroundColor DarkGray
        $v = Read-Host ('  [' + $def + ']')
        if ($v -eq '') { $v = $def }
    }
    if ($v -eq '-' -or $v -eq '') {
        if ($t -like 'ASTORY_DISCORD_*') { $discordLeft.Add($t) }
        if (-not $NonInteractive) { Write-Host ('  skipped: ' + $t) -ForegroundColor DarkYellow }
        continue
    }
    $values[$t] = $v.Trim()
}
if ($discordLeft.Count) {
    Write-Host ''
    Write-Host ('Discord ids not set (' + $discordLeft.Count + '): the bot starts, these features stay off until you run configure again:') -ForegroundColor DarkYellow
    foreach ($t in $discordLeft) { Write-Host ('  ' + $t + $(if ($DiscordBotRequired -contains $t) { '   <- needed by the bot' } else { '' })) }
}
if ($values.ContainsKey('ASTORY_LOGSEAL_KEY_ID') -and $values['ASTORY_LOGSEAL_KEY_ID'] -notmatch '^[0-9a-fA-F]{16}(,[0-9a-fA-F]{16})*$') {
    throw 'ASTORY_LOGSEAL_KEY_ID must be 16 hex characters (several: comma-separated) (Tools\data\logseal\current.txt after keygen)'
}
if ($values.ContainsKey('ASTORY_UPDATE_SSH_ROOT') -and -not $values['ASTORY_UPDATE_SSH_ROOT'].StartsWith('/')) {
    throw 'ASTORY_UPDATE_SSH_ROOT must start with /'
}
if ($values.ContainsKey('ASTORY_LAUNCHER_ROOT_PUBKEY') -and $values['ASTORY_LAUNCHER_ROOT_PUBKEY'] -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ASTORY_LAUNCHER_ROOT_PUBKEY must be 64 hex characters (hex of root.pub)'
}
foreach ($k in $Derived.Keys) {
    $src = $k -replace '_(FWD|ESC)$', ''
    if ($values.ContainsKey($src)) { $values[$k] = & $Derived[$k] $values }
}
foreach ($k in $values.Keys) {
    if ($values[$k] -match '[^\x20-\x7E]') { Write-Host ('Note: ' + $k + ' contains non-ASCII characters - the old server ini files are not UTF-8; prefer plain ASCII (paths, names).') -ForegroundColor Yellow }
}
$out = [ordered]@{}
foreach ($k in ($saved.Keys | Sort-Object)) { $out[$k] = $saved[$k] }   # keep earlier answers
foreach ($s in $Settings) { if ($values.ContainsKey($s.T)) { $out[$s.T] = $values[$s.T] } }
foreach ($t in $extra.Keys) { if ($values.ContainsKey($t)) { $out[$t] = $values[$t] } }
($out | ConvertTo-Json) | Set-Content -Path $SettingsFile -Encoding UTF8
Write-Host ''
Write-Host ('Answers saved to ' + $SettingsFile + ' (keep it private, it is git-ignored).')

# ---------------------------------------------------------------------------------------------------------------------
# 2. replace placeholders
# ---------------------------------------------------------------------------------------------------------------------
$changed = 0
foreach ($f in Get-SourceFiles) {
    $r = Read-Utf8 $f.FullName
    $t = $r.Text
    if ($t.IndexOf('@@ASTORY_') -lt 0) { continue }
    $o = $t
    foreach ($k in ($values.Keys | Sort-Object { -$_.Length })) { $t = $t.Replace('@@' + $k + '@@', (As-Bytes $values[$k] $r.Kind)) }
    if ($t -ne $o) {
        Write-Text $f.FullName $t $r.Kind
        $changed++
    }
}
Write-Host ('Placeholders replaced in ' + $changed + ' files.') -ForegroundColor Green

# ---------------------------------------------------------------------------------------------------------------------
# 3. client pak keys (encryption + signing) - generated, never typed in
# ---------------------------------------------------------------------------------------------------------------------
$gen = Join-Path $Project 'Tools\gen_build_crypto.py'
if (Test-Path $gen) {
    $ans = if ($NonInteractive) { 'n' } else { Read-Host 'Generate NEW client pak encryption/signing keys now (needs python 3 + cryptography)? [y/N]' }
    if ($ans -match '^[yY]') {
        & python $gen
        if ($LASTEXITCODE -ne 0) { Write-Host 'gen_build_crypto.py failed - run it later: python AstoryClient\Tools\gen_build_crypto.py' -ForegroundColor Red }
    } else {
        Write-Host 'Pak keys not generated. Before packaging the client run: python AstoryClient\Tools\gen_build_crypto.py' -ForegroundColor DarkYellow
    }
}

Write-Host ''
Show-Left
Write-Host ''
Write-Host 'Secrets that are NOT placeholders (passwords, tokens, private keys) are created on first deploy or by you - see _setup\SETUP.md.'
