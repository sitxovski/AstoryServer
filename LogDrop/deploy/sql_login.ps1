# Copyright (c) 2026 @sitxovski (Discord)
# sql_login.ps1 — SQL-вход logdrop_ro для службы AsdaLogDrop (★ ревизия 19.10, В6: под sidtype restricted SSPI не работает).
#   Пароль — 40 случайных символов, генерируется здесь, пишется только в LogDrop\service\secrets\sql_logdrop_ro.txt
#   (ACL: Administrators, SYSTEM, NT SERVICE\AsdaLogDrop — чтение) и передаётся в SQL параметром (не в командной строке).
$ErrorActionPreference = 'Stop'
$Sec  = '@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\LogDrop\service\secrets'
$File = Join-Path $Sec 'sql_logdrop_ro.txt'
$Acct = 'NT SERVICE\AsdaLogDrop'

New-Item -ItemType Directory -Force $Sec | Out-Null
& icacls $Sec /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' "${Acct}:(OI)(CI)R" /q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls secrets: $LASTEXITCODE" }

$con = New-Object System.Data.SqlClient.SqlConnection 'Data Source=lpc:.\SQLEXPRESS;Initial Catalog=master;Integrated Security=SSPI;Connect Timeout=5'
$con.Open()
try {
    $cmd = $con.CreateCommand()
    $cmd.CommandText = "SELECT CASE WHEN SUSER_ID(N'logdrop_ro') IS NULL THEN 0 ELSE 1 END"
    $exists = [int]$cmd.ExecuteScalar()
    if ($exists -eq 1 -and (Test-Path $File)) { 'logdrop_ro: вход и пароль уже есть — без изменений'; return }
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 40
    $rng.GetBytes($buf)
    $pw = 'Ld#7' + (-join ($buf | ForEach-Object { $chars[$_ % $chars.Length] }))    # префикс — для требований сложности
    $cmd.Parameters.Add('@p', [System.Data.SqlDbType]::NVarChar, 128).Value = $pw
    if ($exists -eq 0) {
        $cmd.CommandText = "DECLARE @s nvarchar(400) = N'CREATE LOGIN [logdrop_ro] WITH PASSWORD = ' + QUOTENAME(@p, '''') + N', DEFAULT_DATABASE = [AsdaStoryOp], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF'; EXEC (@s);"
    } else {
        $cmd.CommandText = "DECLARE @s nvarchar(400) = N'ALTER LOGIN [logdrop_ro] WITH PASSWORD = ' + QUOTENAME(@p, ''''); EXEC (@s);"
    }
    [void]$cmd.ExecuteNonQuery()
    [IO.File]::WriteAllText($File, $pw, (New-Object Text.UTF8Encoding $false))
    $pw = $null
    'logdrop_ro: ' + $(if ($exists -eq 0) { 'вход создан' } else { 'пароль обновлён' }) + '; пароль — в ' + $File
} finally { $con.Close() }
