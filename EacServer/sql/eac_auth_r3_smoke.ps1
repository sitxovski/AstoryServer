# Copyright (c) 2026 @sitxovski (Discord)
# eac_auth_r3_smoke.ps1 — проверка ред. 3 (UPEacAuthStatus, UPEacAuthFail) на сервере (16.10.2026). Запуск на @@ASTORY_SERVER_HOSTNAME@@ от администратора:
#   powershell -NoProfile -ExecutionPolicy Bypass -File eac_auth_r3_smoke.ps1
# 1) живой вызов под eac_auth: только безопасные случаи (несуществующие учётки/логины, чтение статуса реальной учётки);
#    у eac_auth нет прямых прав; Us_member/BlockList (включая us_pwfail/us_pwfail_at) не изменились; подписи на месте,
#    закрытых ключей у сертификатов ред. 3 нет; права пользователей-из-сертификата — ровно перечисленные столбцы;
# 2) логика: копии ЖИВЫХ текстов UPEacAuthStatus/UPEacAuthFail (и живой UPUserLogin — для сверки замка) во временных
#    процедурах над временными таблицами сессии; рабочие базы при этом не читаются и не пишутся.
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Check($ok, $what) { if ($ok) { $script:pass++; "  [ OK ] $what" } else { $script:fail++; "  [FAIL] $what" } }
$pw = ([IO.File]::ReadAllText('@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\EacServer\secrets\sql_eac_auth.txt')).Trim()
function AdminConn { $c = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=Joy1;Integrated Security=SSPI'; $c.Open(); $c }
function EacConn {
  $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
  $b['Data Source'] = 'tcp:127.0.0.1,1433'; $b['Initial Catalog'] = 'Joy1'; $b['User ID'] = 'eac_auth'; $b['Password'] = $pw; $b['Pooling'] = $false
  $c = New-Object System.Data.SqlClient.SqlConnection $b.ConnectionString; $c.Open(); $c
}
function Scalar($c, $q) { $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $cmd.ExecuteScalar() }
# Вызов процедуры с одним параметром; ответ «Status» или «Status/PwTag».
function Call1($c, $name, $pname, $ptype, $val) {
  $cmd = $c.CreateCommand(); $cmd.CommandText = $name; $cmd.CommandType = 'StoredProcedure'
  if ($ptype -eq 'int') { $p = $cmd.Parameters.Add($pname, [Data.SqlDbType]::Int) } else { $p = $cmd.Parameters.Add($pname, [Data.SqlDbType]::VarChar, 64) }
  if ($null -eq $val) { $p.Value = [DBNull]::Value } else { $p.Value = $val }
  $r = $cmd.ExecuteReader(); $null = $r.Read()
  $s = [int]$r[0]
  $t = if ($r.FieldCount -gt 1) { if ($r.IsDBNull(1)) { 'null' } else { [string]$r[1] } } else { $null }
  $r.Close()
  if ($null -eq $t) { return "$s" } else { return "$s/$t" }
}
$snapQ = "SELECT CONVERT(varchar(20), CHECKSUM_AGG(BINARY_CHECKSUM(Userindex, us_block, Flag, us_pwfail, us_pwfail_at, us_pwhash, us_pwsalt, Loginidx))) + '|' + CONVERT(varchar(10), COUNT(*)) + '|' + (SELECT CONVERT(varchar(10), COUNT(*)) FROM AsdaStoryOP.dbo.BlockList) FROM AsdaStoryOP.dbo.Us_member"
$a = AdminConn
$before = Scalar $a $snapQ
$ulBefore = Scalar $a "SELECT CONVERT(varchar(30), modify_date, 121) FROM sys.objects WHERE object_id = OBJECT_ID('dbo.UPUserLogin')"

"-- 1. живой вызов под eac_auth"
$e = EacConn
Check ((Call1 $e 'dbo.UPEacAuthStatus' '@userindex' 'int' 2147483647) -eq '2/null') 'UPEacAuthStatus: несуществующий UserIndex → 2'
Check ((Call1 $e 'dbo.UPEacAuthStatus' '@userindex' 'int' $null) -eq '2/null') 'UPEacAuthStatus: NULL → 2'
$ui = Scalar $a "SELECT Userindex FROM AsdaStoryOP.dbo.Us_member WHERE us_id = 'sitxovski'"
$st = Call1 $e 'dbo.UPEacAuthStatus' '@userindex' 'int' $ui
$expTag = Scalar $a "SELECT LOWER(CONVERT(VARCHAR(16), SUBSTRING(HASHBYTES('SHA2_256', us_pwhash), 1, 8), 2)) FROM AsdaStoryOP.dbo.Us_member WHERE Userindex = $ui"
Check (($st -split '/')[1] -eq $expTag -and ($st -split '/')[1].Length -eq 16) 'UPEacAuthStatus sitxovski: отпечаток пароля — 16 hex = первые 8 байт SHA2_256(us_pwhash) (значение не выводится)'
"     статус sitxovski: " + ($st -split '/')[0]
Check ((Call1 $e 'dbo.UPEacAuthFail' '@login' 'str' 'no_such_login_r3') -eq '2') 'UPEacAuthFail: неизвестный логин → 2 (ничего не пишется)'
Check ((Call1 $e 'dbo.UPEacAuthFail' '@login' 'str' 'bad login!') -eq '2') 'UPEacAuthFail: негодный логин → 2'
Check ((Call1 $e 'dbo.UPEacAuthFail' '@login' 'str' $null) -eq '2') 'UPEacAuthFail: NULL → 2'
foreach ($q in @('UPDATE AsdaStoryOP.dbo.Us_member SET us_pwfail = us_pwfail WHERE 1 = 0', 'SELECT TOP 1 us_pwfail FROM AsdaStoryOP.dbo.Us_member',
                 'SELECT TOP 1 1 FROM AsdaStoryOP.dbo.BlockList', "SELECT HASHBYTES('SHA2_256', us_pwhash) FROM AsdaStoryOP.dbo.Us_member")) {
  $denied = $false; try { $null = Scalar $e $q } catch { $denied = $true }
  Check $denied ('у eac_auth нет права: ' + $q)
}
$e.Close()
Check ((Scalar $a $snapQ) -eq $before) "Us_member (вкл. us_pwfail/us_pwfail_at) и BlockList не изменились ($before)"
Check ((Scalar $a "SELECT COUNT(*) FROM Joy1.sys.crypt_properties WHERE major_id IN (OBJECT_ID('Joy1.dbo.UPEacAuthStatus'), OBJECT_ID('Joy1.dbo.UPEacAuthFail'))") -eq 2) 'обе процедуры подписаны'
Check ((Scalar $a "SELECT COUNT(*) FROM Joy1.sys.certificates WHERE name IN ('EacAuthStatusSign','EacAuthFailSign') AND pvt_key_encryption_type = 'NA'") -eq 2) 'закрытых ключей у сертификатов ред. 3 нет (REMOVE PRIVATE KEY)'
$permQ = @"
SELECT u.name + ':' + p.permission_name + ':' + OBJECT_NAME(p.major_id, DB_ID('AsdaStoryOp')) + '.' + ISNULL(c.name, '*') COLLATE DATABASE_DEFAULT
FROM AsdaStoryOp.sys.database_permissions p JOIN AsdaStoryOp.sys.database_principals u ON u.principal_id = p.grantee_principal_id
LEFT JOIN AsdaStoryOp.sys.columns c ON c.object_id = p.major_id AND c.column_id = p.minor_id
WHERE u.name IN ('EacAuthStatusSign_u', 'EacAuthFailSign_u') AND p.permission_name <> 'CONNECT'
"@
# Все строки первого столбца, через запятую.
function Rows($c, $q) { $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $r = $cmd.ExecuteReader(); $o = @(); while ($r.Read()) { $o += [string]$r[0] }; $r.Close(); $o -join ',' }
$perm = Rows $a $permQ
"     права: $perm"
$expPerm = 'EacAuthFailSign_u:SELECT:Us_member.us_id,EacAuthFailSign_u:SELECT:Us_member.us_pwfail,EacAuthFailSign_u:SELECT:Us_member.us_pwfail_at,EacAuthFailSign_u:SELECT:Us_member.Userindex,EacAuthFailSign_u:UPDATE:Us_member.us_pwfail,EacAuthFailSign_u:UPDATE:Us_member.us_pwfail_at,EacAuthStatusSign_u:SELECT:BlockList.CloseDate,EacAuthStatusSign_u:SELECT:Us_member.Flag,EacAuthStatusSign_u:SELECT:Us_member.us_block,EacAuthStatusSign_u:SELECT:Us_member.us_pwhash,EacAuthStatusSign_u:SELECT:BlockList.Userindex,EacAuthStatusSign_u:SELECT:Us_member.Userindex'
$norm = { param($x) (($x -split ',') | Sort-Object) -join ',' }
Check ((& $norm $perm) -eq (& $norm $expPerm)) 'права пользователей-из-сертификата — ровно эти столбцы (UPDATE только us_pwfail, us_pwfail_at)'
Check ((Scalar $a "SELECT COUNT(*) FROM Joy1.sys.database_permissions p JOIN Joy1.sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.name = 'eac_auth' AND p.permission_name = 'EXECUTE' AND p.major_id IN (OBJECT_ID('Joy1.dbo.UPEacAuth'), OBJECT_ID('Joy1.dbo.UPEacAuthStatus'), OBJECT_ID('Joy1.dbo.UPEacAuthFail'))") -eq 3) 'eac_auth: EXECUTE на UPEacAuth, UPEacAuthStatus, UPEacAuthFail'
Check ((Scalar $a "SELECT COUNT(*) FROM Joy1.sys.database_permissions p JOIN Joy1.sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.name = 'eac_auth' AND p.permission_name NOT IN ('CONNECT', 'EXECUTE')") -eq 0) 'у eac_auth в Joy1 нет других прав'

"-- 2. логика на копиях живых текстов (временные таблицы сессии)"
$c2 = AdminConn
$setup = @'
USE tempdb;
CREATE TABLE #us_member (Userindex INT, us_id VARCHAR(61) COLLATE Arabic_CI_AS, us_block TINYINT, Flag TINYINT, us_pwhash BINARY(32), us_pwsalt BINARY(16), us_pwfail TINYINT NOT NULL DEFAULT 0, us_pwfail_at DATETIME,
  Seridx TINYINT NULL, Gsidx TINYINT NULL, Threadidx TINYINT NULL, Channel TINYINT NULL, Poridx TINYINT NULL, UserNum SMALLINT NULL);
CREATE TABLE #BlockList (Userindex INT, CloseDate SMALLDATETIME);
'@
$null = Scalar $c2 $setup
function TempProc($name, $tname) {
  $def = Scalar $a "SELECT definition FROM sys.sql_modules WHERE object_id = OBJECT_ID('$name')"
  $t = $def.Replace("CREATE PROCEDURE $name", "CREATE PROCEDURE $tname").Replace('CREATE PROC [dbo].[UPUserLogin]', "CREATE PROC $tname").Replace('AsdaStoryOP.dbo.us_member', '#us_member').Replace('AsdaStoryOP.dbo.BlockList', '#BlockList').Replace('dbo.FN_AC_PwHash', 'Joy1.dbo.FN_AC_PwHash').Replace('EXEC dbo.UP_AC_LiftExpiredBlock @AcUi', 'SET @AcUi = @AcUi')
  Check (($t -ne $def) -and ($t -notmatch 'AsdaStoryOP\.dbo\.(us_member|BlockList)')) "копия ${name} → ${tname}: ссылок на рабочие таблицы не осталось"
  $null = Scalar $c2 $t
}
TempProc 'dbo.UPEacAuthStatus' '#St_t'
TempProc 'dbo.UPEacAuthFail' '#Fa_t'
TempProc 'dbo.UPUserLogin' '#Ul_t'
$fill = @'
DELETE #us_member; DELETE #BlockList;
DECLARE @s BINARY(16) = CRYPT_GEN_RANDOM(16), @m VARCHAR(32) = LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', 'pw1'), 2));
DECLARE @h BINARY(32) = Joy1.dbo.FN_AC_PwHash(@s, @m);
INSERT #us_member (Userindex, us_id, us_block, Flag, us_pwhash, us_pwsalt, us_pwfail, us_pwfail_at) VALUES
 (1,'okuser',0,0,@h,@s,0,NULL),(4,'blocked',5,0,@h,@s,0,NULL),(5,'expired',5,0,@h,@s,0,NULL),(6,'blocknorows',5,0,@h,@s,0,NULL),
 (7,'weird',3,0,@h,@s,0,NULL),(8,'ingame',0,1,@h,@s,0,NULL),(9,'badflag',0,7,@h,@s,0,NULL),(10,'nopw',0,0,NULL,NULL,0,NULL),
 (21,'ula',0,0,@h,@s,0,NULL),(22,'fab',0,0,@h,@s,0,NULL);
INSERT #BlockList VALUES (4, DATEADD(DAY,1,GETDATE())),(5, DATEADD(DAY,-1,GETDATE())),(5, DATEADD(DAY,-2,GETDATE()));
'@
$null = Scalar $c2 $fill
function St($ui) { Call1 $c2 '#St_t' '@userindex' 'int' $ui }
$tag1 = Scalar $c2 "SELECT LOWER(CONVERT(VARCHAR(16), SUBSTRING(HASHBYTES('SHA2_256', us_pwhash), 1, 8), 2)) FROM #us_member WHERE Userindex = 1"
Check ((St 1) -eq "0/$tag1") 'Status: обычная учётка → 0 + отпечаток'
Check ((St 4) -like '5/*') 'Status: блок действует → 5'
Check ((St 5) -like '0/*') 'Status: все CloseDate прошли (вход снял бы блок) → 0'
Check ((St 6) -like '5/*') 'Status: us_block=5 без строк BlockList → 5'
Check ((St 7) -like '6/*') 'Status: us_block=3 → 6'
Check ((St 8) -like '0/*') 'Status: Flag=1 (в игре) → 0'
Check ((St 9) -like '6/*') 'Status: Flag=7 → 6'
Check ((St 10) -eq '3/null') 'Status: пароль не задан → 3'
Check ((St 99) -eq '2/null') 'Status: учётки нет → 2'
$null = Scalar $c2 "UPDATE #us_member SET us_pwhash = Joy1.dbo.FN_AC_PwHash(us_pwsalt, LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', 'pw2'), 2))) WHERE Userindex = 1"
Check ((St 1) -ne "0/$tag1" -and (St 1) -like '0/*') 'Status: смена пароля → другой отпечаток'

function Fa($login) { Call1 $c2 '#Fa_t' '@login' 'str' $login }
function Row($ui) { Scalar $c2 "SELECT CONVERT(varchar(5), us_pwfail) + ':' + CASE WHEN us_pwfail_at IS NULL THEN 'null' WHEN us_pwfail_at > DATEADD(SECOND, -3, GETDATE()) THEN 'now' ELSE 'old' END FROM #us_member WHERE Userindex = $ui" }
function SetRow($ui, $f, $agoSec) { $at = if ($null -eq $agoSec) { 'NULL' } else { "DATEADD(SECOND, -$agoSec, GETDATE())" }; $null = Scalar $c2 "UPDATE #us_member SET us_pwfail = $f, us_pwfail_at = $at WHERE Userindex = $ui" }
SetRow 22 0 $null
Check ((Fa 'fab') -eq '0' -and (Row 22) -eq '1:now') 'Fail: 0/NULL → засчитана, 1, время = сейчас'
Check ((Fa 'FAB  ') -eq '1' -and (Row 22) -eq '1:now') 'Fail: повтор через < 5 с (другой регистр + пробелы — та же учётка) → не засчитана (тот же ввод)'
SetRow 22 1 6
Check ((Fa 'fab') -eq '0' -and (Row 22) -eq '2:now') 'Fail: через 6 с → засчитана, 2'
SetRow 22 9 60
Check ((Fa 'fab') -eq '0' -and (Row 22) -eq '10:now') 'Fail: 9 → 10 (замок начинается)'
SetRow 22 10 60
Check ((Fa 'fab') -eq '4' -and (Row 22) -eq '10:old') 'Fail: замок (10, минуту назад) → 4, счётчик и время не меняются'
SetRow 22 10 (20 * 60)
Check ((Fa 'fab') -eq '0' -and (Row 22) -eq '1:now') 'Fail: замок истёк (20 мин) → окно заново, 1'
SetRow 22 255 60
Check ((Fa 'fab') -eq '4') 'Fail: 255 минуту назад — замок → 4'
SetRow 22 7 (16 * 60)
Check ((Fa 'fab') -eq '0' -and (Row 22) -eq '1:now') 'Fail: 7 неудач 16 мин назад (вне окна 15) → 1'
Check ((Fa 'nobody') -eq '2') 'Fail: учётки нет → 2'
Check ((Fa ('a' * 62)) -eq '2') 'Fail: логин 62 символа → 2'
Check ((Fa ([string][char]0x043E + 'kuser')) -eq '2') 'Fail: кириллица → 2'

"-- 3. сверка замка с живой UPUserLogin (неверный пароль) на одинаковых состояниях"
function Ul($login) { $cmd = $c2.CreateCommand(); $cmd.CommandText = "EXEC #Ul_t @id='$login', @pwd='00000000000000000000000000000000', @Ip='0.0.0.0', @igsAccoutid=0, @Mac='m', @Unk1=NULL, @Unk2=NULL, @Unk3=NULL"; $r = $cmd.ExecuteReader(); $null = $r.Read(); $f = [int]$r[0]; $r.Close(); $f }
$cases = @(@(0, $null), @(3, 60), @(9, 60), @(10, 60), @(10, (20 * 60)), @(254, 60), @(255, 60), @(5, (16 * 60)), @(12, (14 * 60)))
foreach ($cs in $cases) {
  SetRow 21 $cs[0] $cs[1]; SetRow 22 $cs[0] $cs[1]
  $flag = Ul 'ula'; $null = Fa 'fab'
  $ra = Row 21; $rb = Row 22
  Check ($flag -eq 3 -and $ra -eq $rb) ("состояние $($cs[0]) / " + $(if ($null -eq $cs[1]) { 'NULL' } else { "$($cs[1]) с назад" }) + ": UPUserLogin → $ra, UPEacAuthFail → $rb")
}
# Единственное отличие по замыслу: неудача, записанная < 5 с назад (тот же ввод игрока уже засчитан LoginManager-ом), не засчитывается.
SetRow 21 4 2; SetRow 22 4 2
$flag = Ul 'ula'; $fs = Fa 'fab'
Check ((Row 21) -eq '5:now' -and $fs -eq '1' -and (Row 22) -eq '4:now') "состояние 4 / 2 с назад: UPUserLogin → $(Row 21) (+1), UPEacAuthFail → статус $fs, $(Row 22) (повтор того же ввода не засчитан — по замыслу)"
$c2.Close()
Check ((Scalar $a "SELECT CONVERT(varchar(30), modify_date, 121) FROM sys.objects WHERE object_id = OBJECT_ID('dbo.UPUserLogin')") -eq $ulBefore) "UPUserLogin не изменена ($ulBefore)"
Check ((Scalar $a $snapQ) -eq $before) 'рабочие таблицы не изменились после логических проверок'
$a.Close()
$pw = $null
"ИТОГ: пройдено $pass, провалено $fail"
