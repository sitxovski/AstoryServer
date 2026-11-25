# Copyright (c) 2026 @sitxovski (Discord)
#
# setup_server.ps1 - put the Astory game server on THIS machine (run as Administrator, on the game server,
# from the Windows account that will run the stack - see Prerequisites\README.md "Which account").
#
#   0. checks: settings from _setup\configure.bat, no placeholders left, SQL Server in Mixed Mode with TCP 1433, free disk space
#   1. copies the server files (download "AstoryServer Files" -> AstoryServer\ServerFiles) to <ASTORY_SERVER_ROOT>\Working_ASDA\v2
#      (into an existing stack only the missing files, unless -UpdateFiles)
#   2. restores the 4 clean databases (download "AstoryServer Database" -> AstoryServer\Database\*.bak)
#   3. creates the SQL login "devgsaccount" (password = ASTORY_DB_PASSWORD), db_owner in the 4 databases (no server roles)
#   3b. creates the logins eac_auth (EAC server) and logdrop_ro (LogDrop) with random passwords, signs the EAC procedures
#   4. creates the ODBC data sources joy1 / AsdaStoryOP / AsdaStoryLogin (current user, or -SystemDsn for all users)
#   5. traffic encryption key secure_server.key (P61 / L07 / EAC channel): makes a new pair if the stack has none
#   6. admin bridge P127 secrets from the Admin Center (when it is already deployed; later: -SyncAdminBridge)
#   7. Windows services AsdaEacServer, AsdaCaddy, AsdaLogDrop (asks before each one)
#   8. (optional, -Firewall) opens the player ports in Windows Firewall
#
# Run _setup\configure.bat FIRST: it fills your addresses and passwords into ServerFiles.
#   powershell -ExecutionPolicy Bypass -File Prerequisites\setup_server.ps1 [-Firewall] [-Force] [-UpdateFiles] [-SystemDsn] [-FixSql]
#   powershell -ExecutionPolicy Bypass -File Prerequisites\setup_server.ps1 -SyncAdminBridge      (after the Admin Center deploy)
#   powershell -ExecutionPolicy Bypass -File Prerequisites\setup_server.ps1 -NewSecureKey         (new encryption key = rebuild the client)
param(
    [string]$SqlInstance = '.\SQLEXPRESS',
    [string]$StackRoot = '',  # must be <ASTORY_SERVER_ROOT>\Working_ASDA\v2: the configs hold that absolute path
    [switch]$Firewall,        # open the player ports in Windows Firewall
    [switch]$Force,           # restore the databases even if they already exist (OVERWRITES them; stop the stack first)
    [switch]$UpdateFiles,     # overwrite files of an existing stack with the package versions (your edits there are lost)
    [switch]$SystemDsn,       # ODBC data sources for every Windows user (32-bit system DSN) instead of the current user
    [switch]$FixSql,          # switch SQL Server to Mixed Mode and enable TCP 1433 (restarts the SQL Server service)
    [switch]$NewSecureKey,    # make a new traffic encryption key even if the stack has one
    [switch]$SyncAdminBridge, # only step 6: copy the admin bridge secrets from the Admin Center into the stack
    [switch]$SkipServices,    # do not install the Windows services
    [switch]$Yes              # answer "yes" to every question
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$files = Join-Path $repo 'ServerFiles'
$dbdir = Join-Path $repo 'Database'
$settings = Join-Path $repo '_setup\astory.settings.local.json'
$dbs = @('Joy1', 'joylog1', 'AsdaStoryOp', 'AsdaStoryLogin')
$runner = [Security.Principal.WindowsIdentity]::GetCurrent().Name     # the account that runs the stack (start.bat)

function Step([string]$t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Ask([string]$q) {
    if ($Yes) { return $true }
    return -not ((Read-Host ($q + ' [Y/n]')) -match '^[nN]')
}
# sqlcmd with the query in a temporary file: no $(...) substitution (-x), quotes and passwords never on the command line
function Sql([string]$q, [string]$db = 'master') {
    $tmp = [IO.Path]::Combine($env:TEMP, 'astory_' + [guid]::NewGuid().ToString('N') + '.sql')
    [IO.File]::WriteAllText($tmp, "SET NOCOUNT ON;`r`n" + $q, (New-Object Text.UTF8Encoding $false))
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # PS 5.1: stderr of a native program must not throw early
    try {
        $r = & sqlcmd -S $SqlInstance -E -d $db -b -I -x -W -h -1 -s '|' -f 65001 -i $tmp 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $r = @($r | ForEach-Object { "$_" })
    if ($code -ne 0) { throw ("sqlcmd (" + $db + "): " + ($r -join ' ')) }
    return $r
}
function Sql1([string]$q, [string]$db = 'master') { return ([string](Sql $q $db | Select-Object -First 1)).Trim() }
function New-Secret([int]$n = 40) {
    # letters + digits; one upper, one lower and one digit always present (CHECK_POLICY and certificate passwords need 3 classes)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray()
    $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return 'Aa7' + (-join ($b | ForEach-Object { $chars[$_ % $chars.Length] }))
}
# SID of a service account "NT SERVICE\<name>" (S-1-5-80-<SHA-1 of the upper-case name>) - works before the service exists
function Get-ServiceSid([string]$name) {
    $h = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($name.ToUpperInvariant()))
    $p = for ($i = 0; $i -lt 20; $i += 4) { [BitConverter]::ToUInt32($h, $i) }
    return 'S-1-5-80-' + ($p -join '-')
}
function Set-Acl-Tight([string]$path, [string[]]$extra = @(), [switch]$Dir) {
    # only Administrators, SYSTEM (+ the given entries, icacls syntax "*SID:R" / "user:R"): no inherited "Users: Read"
    $f = if ($Dir) { '(OI)(CI)F' } else { 'F' }
    $a = @($path, '/inheritance:r', '/grant:r', ('*S-1-5-32-544:' + $f), ('*S-1-5-18:' + $f)) + @($extra | Where-Object { $_ })
    & icacls @a /q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $path ($LASTEXITCODE)" }
}
# a password / key file: created empty with tight rights first, the value is written afterwards
function Write-Secret([string]$path, [string]$value, [string[]]$readers = @(), [Text.Encoding]$enc = $null) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    if (-not $enc) { $enc = New-Object Text.UTF8Encoding $false }
    [IO.File]::WriteAllText($path, '')
    Set-Acl-Tight $path ($readers | ForEach-Object { $_ + ':R' })
    [IO.File]::WriteAllText($path, $value, $enc)
}
function Invoke-Sc([string]$argline) {
    # sc.exe through Start-Process: the argument line goes to sc.exe verbatim (PS 5.1 mangles embedded quotes otherwise)
    $p = Start-Process -FilePath "$env:WINDIR\system32\sc.exe" -ArgumentList $argline -Wait -NoNewWindow -PassThru
    return $p.ExitCode
}

# 0. checks ------------------------------------------------------------------------------------------------------------
$admin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this script as Administrator (right-click PowerShell -> Run as administrator).' }
if (-not (Test-Path $settings)) { throw 'Run _setup\configure.bat first (it saves your answers to _setup\astory.settings.local.json).' }
$cfg = Get-Content $settings -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $cfg.ASTORY_SERVER_ROOT) { throw 'ASTORY_SERVER_ROOT is empty - run _setup\configure.bat and set the server folder (for example C:\ASDA).' }
$serverRoot = ([string]$cfg.ASTORY_SERVER_ROOT).TrimEnd('\')
$expected = Join-Path $serverRoot 'Working_ASDA\v2'
if (-not $StackRoot) { $StackRoot = $expected }
if ($StackRoot.TrimEnd('\') -ne $expected) {
    throw "-StackRoot must be $expected : LogDrop.ini, EacServer.ini and the Caddyfile hold this absolute path. To use another folder change ASTORY_SERVER_ROOT (fresh ServerFiles + configure.bat)."
}
$bridgeIni = @('GameServer', 'Ch2_GameServer', 'Indun_GameServer') | ForEach-Object { Join-Path $StackRoot "$_\ConfigSet\admin_bridge.ini" }
$acSecrets = Join-Path $serverRoot 'AdminCenter\secrets\asda_admin.ini'

function Sync-AdminBridge {
    # Admin Center is the only source of these two values: deploy_admin_center.py creates BRIDGE_PASSWORD (SQL login asda_bridge)
    # and BRIDGE_HMAC_KEY (command signature) once in its secrets file; every GameServer needs the same pair in admin_bridge.ini.
    Step 'admin bridge P127 (Admin Center <-> GameServer)'
    if (-not (Test-Path -LiteralPath $acSecrets)) {
        Write-Host "No $acSecrets yet - deploy Astory Admin Center first, then run: setup_server.ps1 -SyncAdminBridge (the bridge stays off until then)." -ForegroundColor DarkYellow
        return
    }
    $v = @{}
    foreach ($l in Get-Content -LiteralPath $acSecrets -Encoding UTF8) { if ($l -match '^\s*(BRIDGE_PASSWORD|BRIDGE_HMAC_KEY)\s*=\s*(.+)$') { $v[$Matches[1]] = $Matches[2].Trim().Trim('"') } }
    if (-not $v['BRIDGE_PASSWORD'] -or $v['BRIDGE_HMAC_KEY'] -notmatch '^[0-9a-fA-F]{64}$') {
        Write-Host "$acSecrets has no BRIDGE_PASSWORD / BRIDGE_HMAC_KEY - run the Admin Center deploy again (its step 4 adds them), then -SyncAdminBridge." -ForegroundColor DarkYellow
        return
    }
    $txt = "; Admin bridge P127 secrets (setup_server.ps1, from AdminCenter\secrets\asda_admin.ini). Do not copy, do not print.`r`n[Bridge]`r`nPassword=" +
           $v['BRIDGE_PASSWORD'] + "`r`nHmacKey=" + $v['BRIDGE_HMAC_KEY'] + "`r`n"
    foreach ($f in $bridgeIni) {
        if (-not (Test-Path -LiteralPath (Split-Path $f))) { continue }
        Write-Secret $f $txt @($runner) (New-Object Text.UnicodeEncoding($false, $true))
        Write-Host "written $f (Administrators, SYSTEM, $runner)"
    }
    $v.Clear(); Remove-Variable txt
    Write-Host 'Restart the GameServers (stop_servers.bat, start.bat) to load the new values.'
}
if ($SyncAdminBridge) { Sync-AdminBridge; exit 0 }

if (-not $cfg.ASTORY_DB_PASSWORD) { throw 'ASTORY_DB_PASSWORD is empty - run _setup\configure.bat and set it.' }
$sqlcmd = Get-Command sqlcmd -ErrorAction SilentlyContinue
if (-not $sqlcmd) { throw 'sqlcmd not found - install SQL Server 2019 Express with its command line tools (see README.md).' }
if ($sqlcmd.Source -notmatch '(?i)Microsoft SQL Server') {
    Write-Host ("Note: sqlcmd is {0}. This script is tested with the sqlcmd of SQL Server 2019 (Client SDK\ODBC\...\Tools\Binn)." -f $sqlcmd.Source) -ForegroundColor Yellow
}
Step 'checks'
Write-Host "the stack will run as: $runner (start.bat must be started by this account$(if ($SystemDsn) { ' - or any account: -SystemDsn' }))"
if (-not (Test-Path $files)) { throw "No $files - download ""AstoryServer Files"" and unpack it so that AstoryServer\ServerFiles\GameServer exists." }
$textExt = @('.ini', '.cfg', '.json', '.txt', '.bat', '.cmd', '.ps1', '.py', '.js', '.md', '.conf', '.xml', '.yml', '.yaml', '')
$left = Get-ChildItem $files -Recurse -File -Force | Where-Object { ($textExt -contains $_.Extension.ToLower()) -and $_.Length -lt 4MB } |
        Select-String -Pattern '@@ASTORY_' -SimpleMatch -List -ErrorAction SilentlyContinue
if (-not $left) {   # UTF-16 ini files of the patches
    $left = Get-ChildItem $files -Recurse -File -Force -Include *.ini | Select-String -Pattern '@@ASTORY_' -SimpleMatch -List -Encoding Unicode -ErrorAction SilentlyContinue
}
if ($left) { Write-Host ("Placeholders still in {0} files (e.g. {1}) - run _setup\configure.bat first." -f @($left).Count, @($left)[0].Path) -ForegroundColor Yellow; throw 'not configured' }
Write-Host 'ServerFiles configured (no placeholders)'
$ldKeys = Select-String -LiteralPath (Join-Path $files 'LogDrop\service\LogDrop.ini') -Pattern '^\s*KeyIds\s*=\s*(.*)$' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ldKeys -and $ldKeys.Matches[0].Groups[1].Value.Trim() -notmatch '^[0-9a-fA-F]{16}(\s*,\s*[0-9a-fA-F]{16})*$') {
    throw 'LogDrop.ini KeyIds must be the 16-hex key id(s) of your client LogSeal key (ASTORY_LOGSEAL_KEY_ID; python AstoryClient\Tools\asda_logseal.py keygen prints it).'
}

# SQL Server: reachable, Mixed Mode, TCP 1433 (EacServer and the Admin Center use tcp:127.0.0.1,1433; the stack uses ODBC)
$inst = if ($SqlInstance -match '\\(.+)$') { $Matches[1] } else { 'MSSQLSERVER' }
$svcName = if ($inst -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { 'MSSQL$' + $inst }
$mode = Sql1 "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int)"
$tcp = Sql1 "SELECT COUNT(*) FROM sys.dm_tcp_listener_states WHERE type_desc = N'TSQL' AND port = 1433 AND state_desc = N'ONLINE'"
if ($mode -eq '1' -or $tcp -eq '0') {
    $what = @(); if ($mode -eq '1') { $what += 'Windows-only authentication (needs Mixed Mode)' }; if ($tcp -eq '0') { $what += 'no TCP listener on port 1433' }
    if (-not $FixSql) {
        throw ("SQL Server: " + ($what -join '; ') + ". Fix it in SSMS (server Properties -> Security -> SQL Server and Windows Authentication mode) and " +
               "SQL Server Configuration Manager (Protocols for $inst -> TCP/IP -> Enabled, IPAll TCP Port 1433, TCP Dynamic Ports empty), restart the service - or run again with -FixSql.")
    }
    $id = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$inst
    if (-not $id) { throw "instance $inst not found in the registry" }
    $k = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$id\MSSQLServer"
    if ($mode -eq '1') { Set-ItemProperty $k -Name LoginMode -Value 2 -Type DWord; Write-Host 'Mixed Mode set' }
    if ($tcp -eq '0') {
        Set-ItemProperty "$k\SuperSocketNetLib\Tcp" -Name Enabled -Value 1 -Type DWord
        Set-ItemProperty "$k\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort -Value '1433'
        Set-ItemProperty "$k\SuperSocketNetLib\Tcp\IPAll" -Name TcpDynamicPorts -Value ''
        Write-Host 'TCP/IP enabled on port 1433'
    }
    Write-Host "restarting $svcName ..."
    Restart-Service -Name $svcName -Force
    Start-Sleep -Seconds 5
    $mode = Sql1 "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int)"
    $tcp = Sql1 "SELECT COUNT(*) FROM sys.dm_tcp_listener_states WHERE type_desc = N'TSQL' AND port = 1433 AND state_desc = N'ONLINE'"
    if ($mode -eq '1' -or $tcp -eq '0') { throw 'SQL Server still not in Mixed Mode / not on TCP 1433 - check SQL Server Configuration Manager (another program on port 1433?).' }
}
Write-Host "SQL Server $SqlInstance : Mixed Mode, TCP 1433"
$data = Sql1 "SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(260))"
$logp = Sql1 "SELECT CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(260))"

# 1. server files ---------------------------------------------------------------------------------------------------
Step "server files -> $StackRoot"
$fresh = -not (Test-Path $StackRoot) -or -not (Get-ChildItem $StackRoot -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
New-Item -ItemType Directory -Force $StackRoot | Out-Null
if ($fresh -or $UpdateFiles) {
    if (-not $fresh) { Write-Host '-UpdateFiles: files of the stack are overwritten with the package versions' -ForegroundColor Yellow }
    & robocopy $files $StackRoot /E /R:1 /W:1 /NP /NFL /NDL | Out-Null
} else {
    # existing stack: only files that are missing there (your edited ini files stay as they are)
    & robocopy $files $StackRoot /E /XC /XN /XO /R:1 /W:1 /NP /NFL /NDL | Out-Null
    Write-Host 'existing stack: only missing files copied (use -UpdateFiles to overwrite with the package versions)'
}
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
Write-Host 'copied'
if ($SqlInstance -ne '.\SQLEXPRESS') {
    # LogDrop (shared memory) and the gp7 gateway name the instance in their configs; follow -SqlInstance
    $l1 = [Text.Encoding]::GetEncoding(28591)
    foreach ($f in @((Join-Path $StackRoot 'LogDrop\service\LogDrop.ini'), (Join-Path $StackRoot 'gp7-server\config.json'))) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $t = $l1.GetString([IO.File]::ReadAllBytes($f))
        $n = $t.Replace('lpc:.\SQLEXPRESS', 'lpc:' + $SqlInstance).Replace('localhost\\SQLEXPRESS', $SqlInstance.Replace('.\', 'localhost\').Replace('\', '\\'))
        if ($n -ne $t) { [IO.File]::WriteAllBytes($f, $l1.GetBytes($n)); Write-Host "SQL instance $SqlInstance -> $f" }
    }
}

# 2. databases ------------------------------------------------------------------------------------------------------
Step 'databases'
foreach ($db in $dbs) {
    $bak = Join-Path $dbdir "$db.bak"
    if (-not (Test-Path $bak)) { throw "No $bak - download ""AstoryServer Database"" into AstoryServer\Database." }
    $exists = (Sql1 "SELECT CASE WHEN DB_ID(N'$db') IS NULL THEN 0 ELSE 1 END") -eq '1'
    if ($exists -and -not $Force) { Write-Host "$db already exists - skipped (use -Force to overwrite it)" -ForegroundColor DarkYellow; continue }
    # the SQL Server service reads the backup from its own data folder (no rights to Downloads / Desktop needed)
    $copy = Join-Path $data "$db.restore.bak"
    Copy-Item $bak $copy -Force
    try {
        $fl = Sql "RESTORE FILELISTONLY FROM DISK = N'$copy'"
        $move = @(); $i = 0; $need = [long]0; $bad = @()
        foreach ($l in $fl) {
            $c = $l -split '\|'     # columns by position: LogicalName|PhysicalName|Type|FileGroupName|Size|...
            if ($c.Count -lt 5 -or $c[2] -notmatch '^[DLFS]$') { continue }
            $i++; $logical = $c[0]; $type = $c[2]; $need += [long]$c[4]
            switch ($type) {
                'D' { $target = Join-Path $data ("{0}_{1}.{2}" -f $db, $i, $(if ($i -eq 1) { 'mdf' } else { 'ndf' })) }
                'L' { $target = Join-Path $logp ("{0}_{1}.ldf" -f $db, $i) }
                default { $target = Join-Path $data ("{0}_{1}_{2}" -f $db, $type, $i) }   # full-text catalog / FILESTREAM: a folder
            }
            $move += "MOVE N'" + $logical.Replace("'", "''") + "' TO N'" + $target + "'"
        }
        if ($move.Count -lt 2) { throw "RESTORE FILELISTONLY of $bak gave no data/log files: $($fl -join ' ')" }
        $drive = (Split-Path -Qualifier $data)
        $free = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'").FreeSpace
        if ($free -and $need -gt $free) { throw ("{0} needs {1:N1} GB on {2}, free {3:N1} GB" -f $db, ($need / 1GB), $drive, ($free / 1GB)) }
        Write-Host ("{0}: {1} files, {2:N2} GB after restore" -f $db, $move.Count, ($need / 1GB))
        if ($exists) {
            Write-Host "  $db exists: stop the stack (stop_servers.bat), the Admin Center and SSMS first - open connections are cut now" -ForegroundColor Yellow
            $old = Sql "SELECT physical_name FROM sys.master_files WHERE database_id = DB_ID(N'$db')"
            Sql "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;" | Out-Null
        }
        try {
            Sql ("RESTORE DATABASE [$db] FROM DISK = N'$copy' WITH " + ($move -join ', ') + ", REPLACE, RECOVERY;") | Out-Null
        } finally {
            if ($exists) { Sql "IF DB_ID(N'$db') IS NOT NULL ALTER DATABASE [$db] SET MULTI_USER;" | Out-Null }
        }
        if ($exists -and $old) {
            $now = Sql "SELECT physical_name FROM sys.master_files WHERE database_id = DB_ID(N'$db')"
            $orphan = @($old | Where-Object { $now -notcontains $_ -and (Test-Path -LiteralPath $_) })
            if ($orphan) { Write-Host ("  old files of $db no longer used (delete them yourself if you do not need them): " + ($orphan -join ', ')) -ForegroundColor DarkYellow }
        }
    } finally { Remove-Item $copy -Force -ErrorAction SilentlyContinue }
    # the backup remembers the owner of the author's machine - give the database to sa
    Sql "ALTER AUTHORIZATION ON DATABASE::[$db] TO [sa];" | Out-Null
    Write-Host "$db restored"
}

# 3. login ----------------------------------------------------------------------------------------------------------
Step 'SQL login devgsaccount'
$pw = ([string]$cfg.ASTORY_DB_PASSWORD).Replace("'", "''")
Sql ("IF SUSER_ID(N'devgsaccount') IS NULL CREATE LOGIN [devgsaccount] WITH PASSWORD = N'$pw', CHECK_POLICY = OFF, DEFAULT_DATABASE = [Joy1]; " +
     "ELSE ALTER LOGIN [devgsaccount] WITH PASSWORD = N'$pw'; " +
     # no server roles (as on the original server): db_owner in the 4 databases is all the stack needs
     "IF IS_SRVROLEMEMBER(N'serveradmin', N'devgsaccount') = 1 ALTER SERVER ROLE [serveradmin] DROP MEMBER [devgsaccount];") | Out-Null
Remove-Variable pw
foreach ($db in $dbs) {
    Sql ("IF USER_ID(N'devgsaccount') IS NULL CREATE USER [devgsaccount] FOR LOGIN [devgsaccount]; ELSE ALTER USER [devgsaccount] WITH LOGIN = [devgsaccount]; " +
         "ALTER ROLE [db_owner] ADD MEMBER [devgsaccount];") $db | Out-Null
}
Write-Host 'login ready'

# 3b. Easy Anti-Cheat server and LogDrop: their own minimal SQL logins -------------------------------------------------
#   EacServer logs in as "eac_auth" and may only EXECUTE three procedures in Joy1. Those procedures read the accounts in
#   AsdaStoryOp through certificate signatures (the certificate exists in both databases, its private key is removed right
#   after signing). LogDrop logs in as "logdrop_ro" and may only read Us_member.Us_id. Passwords are random and go only into
#   the password files the two services read.
Step 'EAC server and LogDrop logins'
$certPw = New-Secret
$signed = @(
    @{ Proc = 'UPEacAuth'; Cert = 'EacAuthSign'
       Grants = @('GRANT SELECT ON dbo.Us_member TO [{0}]', 'GRANT SELECT ON dbo.BlockList TO [{0}]') },
    @{ Proc = 'UPEacAuthStatus'; Cert = 'EacAuthStatusSign'
       Grants = @('GRANT SELECT ON dbo.Us_member (Userindex, us_block, Flag, us_pwhash) TO [{0}]', 'GRANT SELECT ON dbo.BlockList (Userindex, CloseDate) TO [{0}]') },
    @{ Proc = 'UPEacAuthFail'; Cert = 'EacAuthFailSign'
       Grants = @('GRANT SELECT ON dbo.Us_member (Userindex, us_id, us_pwfail, us_pwfail_at) TO [{0}]', 'GRANT UPDATE ON dbo.Us_member (us_pwfail, us_pwfail_at) TO [{0}]') }
)
$eacProcs = @()
foreach ($s in $signed) {
    $p = $s.Proc; $c = $s.Cert; $u = $c + '_u'
    if ((Sql1 "SELECT CASE WHEN OBJECT_ID(N'dbo.$p', N'P') IS NULL THEN 0 ELSE 1 END" 'Joy1') -ne '1') {
        Write-Host "dbo.$p not in Joy1 - skipped" -ForegroundColor DarkYellow; continue
    }
    # fresh certificate: old ones have no private key any more (removed after signing)
    Sql "IF USER_ID(N'$u') IS NOT NULL DROP USER [$u]; IF CERT_ID(N'$c') IS NOT NULL DROP CERTIFICATE [$c];" 'AsdaStoryOp' | Out-Null
    Sql ("IF CERT_ID(N'$c') IS NOT NULL AND EXISTS (SELECT 1 FROM sys.crypt_properties cp JOIN sys.certificates ce ON ce.thumbprint = cp.thumbprint " +
         "WHERE cp.major_id = OBJECT_ID(N'dbo.$p') AND ce.name = N'$c') DROP SIGNATURE FROM dbo.[$p] BY CERTIFICATE [$c]; " +
         "IF USER_ID(N'$u') IS NOT NULL DROP USER [$u]; IF CERT_ID(N'$c') IS NOT NULL DROP CERTIFICATE [$c];") 'Joy1' | Out-Null
    Sql ("CREATE CERTIFICATE [$c] ENCRYPTION BY PASSWORD = N'$certPw' WITH SUBJECT = N'Astory $p signer', EXPIRY_DATE = '20991231'; " +
         "ADD SIGNATURE TO dbo.[$p] BY CERTIFICATE [$c] WITH PASSWORD = N'$certPw'; " +
         "DECLARE @pub varbinary(max) = CERTENCODED(CERT_ID(N'$c')); " +
         "DECLARE @q nvarchar(max) = N'USE AsdaStoryOp; CREATE CERTIFICATE [$c] FROM BINARY = ' + CONVERT(nvarchar(max), @pub, 1) + N';'; EXEC (@q); " +
         "ALTER CERTIFICATE [$c] REMOVE PRIVATE KEY;") 'Joy1' | Out-Null
    Sql (("CREATE USER [$u] FROM CERTIFICATE [$c]; " + (($s.Grants | ForEach-Object { $_ -f $u }) -join '; ') + ';')) 'AsdaStoryOp' | Out-Null
    $eacProcs += $p
    Write-Host "dbo.$p signed ($c)"
}
Remove-Variable certPw
$eacPw = New-Secret
Sql ("IF SUSER_ID(N'eac_auth') IS NULL CREATE LOGIN [eac_auth] WITH PASSWORD = N'$eacPw', DEFAULT_DATABASE = [Joy1], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF; " +
     "ELSE ALTER LOGIN [eac_auth] WITH PASSWORD = N'$eacPw', DEFAULT_DATABASE = [Joy1], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;") | Out-Null
Sql ("IF USER_ID(N'eac_auth') IS NULL CREATE USER [eac_auth] FOR LOGIN [eac_auth]; ELSE ALTER USER [eac_auth] WITH LOGIN = [eac_auth]; " +
     (($eacProcs | ForEach-Object { "GRANT EXECUTE ON dbo.[$_] TO [eac_auth]" }) -join '; ') + ';') 'Joy1' | Out-Null
$eacSec = Join-Path $StackRoot 'EacServer\secrets'
New-Item -ItemType Directory -Force $eacSec | Out-Null
Set-Acl-Tight $eacSec @() -Dir          # EacServer runs as LocalSystem
Write-Secret (Join-Path $eacSec 'sql_eac_auth.txt') $eacPw
Remove-Variable eacPw
Write-Host 'login eac_auth ready (password: EacServer\secrets\sql_eac_auth.txt, Administrators + SYSTEM only)'

$ldSid = Get-ServiceSid 'AsdaLogDrop'                          # NT SERVICE\AsdaLogDrop (sidtype restricted: needs explicit rights)
$ldPw = New-Secret
Sql ("IF SUSER_ID(N'logdrop_ro') IS NULL CREATE LOGIN [logdrop_ro] WITH PASSWORD = N'$ldPw', DEFAULT_DATABASE = [AsdaStoryOp], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF; " +
     "ELSE ALTER LOGIN [logdrop_ro] WITH PASSWORD = N'$ldPw';") | Out-Null
Sql ("IF USER_ID(N'logdrop_ro') IS NULL CREATE USER [logdrop_ro] FOR LOGIN [logdrop_ro]; ELSE ALTER USER [logdrop_ro] WITH LOGIN = [logdrop_ro]; " +
     "GRANT SELECT ON dbo.Us_member (Us_id) TO [logdrop_ro];") 'AsdaStoryOp' | Out-Null
$ldIni = Join-Path $StackRoot 'LogDrop\service\LogDrop.ini'
$ldFile = Join-Path $StackRoot 'LogDrop\service\secrets\sql_logdrop_ro.txt'
if (Test-Path $ldIni) {
    $line = Select-String -LiteralPath $ldIni -Pattern '^\s*SqlPasswordFile\s*=\s*(.+)$' | Select-Object -First 1
    if ($line) { $ldFile = $line.Matches[0].Groups[1].Value.Trim() }
}
New-Item -ItemType Directory -Force (Split-Path $ldFile) | Out-Null
Set-Acl-Tight (Split-Path $ldFile) @("*${ldSid}:(OI)(CI)R") -Dir
Write-Secret $ldFile $ldPw @("*$ldSid")
Remove-Variable ldPw
Write-Host "login logdrop_ro ready (password: $ldFile, Administrators + SYSTEM + NT SERVICE\AsdaLogDrop read)"

# 4. ODBC data sources ------------------------------------------------------------------------------------------------
$server = $SqlInstance.Replace('.\', $env:COMPUTERNAME + '\')
$dsn = @{ 'joy1' = 'Joy1'; 'AsdaStoryOP' = 'AsdaStoryOp'; 'AsdaStoryLogin' = 'AsdaStoryLogin' }
if ($SystemDsn) {
    Step 'ODBC data sources (32-bit system DSN, every Windows user)'
    $base = 'HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI'          # the stack processes are 32-bit
} else {
    Step "ODBC data sources (Windows user $runner)"
    $base = 'HKCU:\Software\ODBC\ODBC.INI'
}
New-Item -Path "$base\ODBC Data Sources" -Force | Out-Null
foreach ($k in $dsn.Keys) {
    $p = "$base\$k"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty $p -Name Driver -Value "$env:WINDIR\system32\SQLSRV32.dll"   # a 32-bit process reads SysWOW64\SQLSRV32.dll from this path
    Set-ItemProperty $p -Name Server -Value $server
    Set-ItemProperty $p -Name Database -Value $dsn[$k]
    Set-ItemProperty $p -Name LastUser -Value 'devgsaccount'
    Set-ItemProperty $p -Name AutoTranslate -Value 'No'        # keeps Arabic / Korean / Cyrillic texts intact
    Set-ItemProperty "$base\ODBC Data Sources" -Name $k -Value 'SQL Server'
    Write-Host "$k -> $server / $($dsn[$k])"
}
if (-not $SystemDsn) { Write-Host "Start the stack as $runner (a user DSN is seen only by this account; -SystemDsn for any account)." -ForegroundColor DarkYellow }

# 5. traffic encryption key (P61 GameServer x3, L07 LoginManager, EAC channel 15901) ------------------------------------
Step 'traffic encryption key secure_server.key'
$keyDirs = @('GameServer', 'Ch2_GameServer', 'Indun_GameServer', 'LoginManager') | ForEach-Object { Join-Path $StackRoot $_ }
$keyMain = Join-Path $keyDirs[0] 'secure_server.key'
$keysOut = Join-Path $serverRoot 'keys'
if ((Test-Path $keyMain) -and -not $NewSecureKey) {
    Write-Host "the stack already has $keyMain - kept (-NewSecureKey makes a new pair)"
} else {
    $gen = Join-Path $PSScriptRoot 'gen_secure_key.py'
    New-Item -ItemType Directory -Force $keysOut | Out-Null
    Set-Acl-Tight $keysOut @() -Dir
    $tmpKey = Join-Path $keysOut 'secure_server.key'
    $pub = Join-Path $keysOut 'server_public.h'
    $py = Get-Command python -ErrorAction SilentlyContinue
    $kg = Join-Path $repo 'Patches\AsdaSecure\out\keygen.exe'
    $rc = 1
    if ($py) { & $py.Source $gen $tmpKey $pub; $rc = $LASTEXITCODE }
    if ($rc -ne 0 -and (Test-Path $kg)) { & $kg $tmpKey $pub; $rc = $LASTEXITCODE }
    if ($rc -ne 0 -or -not (Test-Path $tmpKey)) {
        throw "Could not make the key: install Python 3 + 'pip install cryptography' (or build Patches\AsdaSecure\build.bat), then run again."
    }
    foreach ($d in $keyDirs) {
        if (-not (Test-Path $d)) { continue }
        $dst = Join-Path $d 'secure_server.key'
        [IO.File]::WriteAllBytes($dst, [byte[]]@())
        Set-Acl-Tight $dst @("${runner}:R")
        [IO.File]::WriteAllBytes($dst, [IO.File]::ReadAllBytes($tmpKey))
        Write-Host "key -> $dst"
    }
    Write-Host ("NEW KEY PAIR. Copy {0} into AstoryClient\Source\AsdaNet\Private\Secure\server_public.h and REBUILD the client: " -f $pub) -ForegroundColor Yellow
    Write-Host '  a client with another public key cannot log in (ServerHello signature). Keep a backup of the keys folder.' -ForegroundColor Yellow
}

# 6. admin bridge P127 ------------------------------------------------------------------------------------------------
Sync-AdminBridge

# 7. Windows services -------------------------------------------------------------------------------------------------
if (-not $SkipServices) {
    Step 'Windows services (EAC server, Caddy HTTPS, LogDrop)'
    $eacExe = Join-Path $StackRoot 'EacServer\AsdaEacServer.exe'
    $caddyExe = Join-Path $StackRoot 'EacServer\caddy\caddy.exe'
    $caddyFile = Join-Path $StackRoot 'EacServer\caddy\Caddyfile'
    $ldExe = Join-Path $StackRoot 'LogDrop\service\AsdaLogDrop.exe'
    $fail = 'reset= 86400 actions= restart/5000/restart/5000/restart/30000'

    if (Get-Service AsdaEacServer -ErrorAction SilentlyContinue) { Write-Host 'AsdaEacServer already installed - kept' }
    elseif ((Test-Path $eacExe) -and (Ask 'Install service AsdaEacServer (AsdaId 127.0.0.1:8444, EAC channel 15901, LocalSystem, delayed auto-start)?')) {
        & $eacExe --install-service
        if ($LASTEXITCODE -ne 0) { throw "AsdaEacServer --install-service ($LASTEXITCODE)" }
        Invoke-Sc 'config AsdaEacServer DisplayName= "Astory EAC Server (AsdaId + sidecar)"' | Out-Null
        Write-Host 'AsdaEacServer installed'
    }
    if (Get-Service AsdaCaddy -ErrorAction SilentlyContinue) { Write-Host 'AsdaCaddy already installed - kept' }
    elseif ((Test-Path $caddyExe) -and (Ask 'Install service AsdaCaddy (HTTPS 443 for AsdaId / LogDrop, Let''s Encrypt certificate, LocalSystem)?')) {
        $bin = '\"' + $caddyExe + '\" run --config \"' + $caddyFile + '\" --adapter caddyfile'
        if ((Invoke-Sc ('create AsdaCaddy binPath= "' + $bin + '" start= auto DisplayName= "Astory Caddy (HTTPS)"')) -ne 0) { throw 'sc create AsdaCaddy' }
        Invoke-Sc 'description AsdaCaddy "HTTPS 443 for AsdaId / JWKS (EAC) and LogDrop. Remove: sc stop AsdaCaddy & sc delete AsdaCaddy"' | Out-Null
        Invoke-Sc "failure AsdaCaddy $fail" | Out-Null
        Write-Host 'AsdaCaddy installed'
    }
    if (Get-Service AsdaLogDrop -ErrorAction SilentlyContinue) { Write-Host 'AsdaLogDrop already installed - kept' }
    elseif ((Test-Path $ldExe) -and (Ask 'Install service AsdaLogDrop (client log intake 127.0.0.1:8446 behind Caddy, NT SERVICE\AsdaLogDrop, restricted)?')) {
        if ((Invoke-Sc ('create AsdaLogDrop binPath= "\"' + $ldExe + '\"" start= delayed-auto obj= "NT SERVICE\AsdaLogDrop" DisplayName= "Astory LogDrop (client log intake)"')) -ne 0) { throw 'sc create AsdaLogDrop' }
        Invoke-Sc 'description AsdaLogDrop "POST /api/v1/ingest behind Caddy; 127.0.0.1:8446; stores sealed client logs in v2\LogDrop"' | Out-Null
        Invoke-Sc "failure AsdaLogDrop $fail" | Out-Null
        if ((Invoke-Sc 'sidtype AsdaLogDrop restricted') -ne 0) { throw 'sc sidtype AsdaLogDrop' }
        Invoke-Sc 'privs AsdaLogDrop SeChangeNotifyPrivilege' | Out-Null
        Write-Host 'AsdaLogDrop installed'
    }
    # LogDrop folders (restricted service token: writes only where the service SID is named explicitly); player logs stay
    # readable only by Administrators, SYSTEM and the service
    $ldRoot = Join-Path $StackRoot 'LogDrop'; $ldSvc = Join-Path $ldRoot 'service'; $ldLogs = Join-Path $ldSvc 'logs'
    if (Test-Path $ldSvc) {
        New-Item -ItemType Directory -Force $ldLogs | Out-Null
        Set-Acl-Tight $ldRoot @("*${ldSid}:(OI)(CI)M") -Dir
        Set-Acl-Tight $ldSvc @("*${ldSid}:(OI)(CI)RX") -Dir
        & icacls $ldLogs /inheritance:e /grant:r "*${ldSid}:(OI)(CI)M" /q | Out-Null
        Set-Acl-Tight (Split-Path $ldFile) @("*${ldSid}:(OI)(CI)R") -Dir
        Write-Host 'LogDrop folder rights: Administrators, SYSTEM, NT SERVICE\AsdaLogDrop'
    }
    $eos = Join-Path $eacSec 'eos.json'
    foreach ($n in 'AsdaEacServer', 'AsdaCaddy', 'AsdaLogDrop') {
        $svc = Get-Service $n -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq 'Running') { continue }
        if ($n -eq 'AsdaEacServer' -and -not (Test-Path $eos)) { Write-Host "AsdaEacServer not started: put $eos first (Prerequisites\README.md), then: sc start AsdaEacServer" -ForegroundColor DarkYellow; continue }
        if (Ask "Start $n now?") { Start-Service $n; Write-Host "$n started" }
    }
}

# 8. firewall (optional) --------------------------------------------------------------------------------------------
if ($Firewall) {
    Step 'Windows Firewall (player ports)'
    $rules = @(
        @{ Name = 'Astory Login'; Port = '15001' },
        @{ Name = 'Astory GameServers'; Port = '15601,15621,15651' },
        @{ Name = 'Astory EAC channel'; Port = '15901' },
        @{ Name = 'Astory HTTPS (auth, EAC tokens, logs)'; Port = '443' }
    )
    foreach ($r in $rules) {
        if (-not (Ask ("Allow inbound TCP {0} ({1})?" -f $r.Port, $r.Name))) { continue }
        Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP -LocalPort ($r.Port -split ',') -Action Allow | Out-Null
        Write-Host ("allowed {0}" -f $r.Port)
    }
}

Step 'done'
Write-Host "Start the stack as ${runner}: $StackRoot\start.bat   (stop: stop_servers.bat). Ports and router setup: Prerequisites\README.md."
if (-not (Test-Path (Join-Path $eacSec 'eos.json'))) { Write-Host "Still to do: $eacSec\eos.json (EOS trusted-server client), then sc start AsdaEacServer." -ForegroundColor Yellow }
