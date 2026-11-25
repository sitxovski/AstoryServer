# Copyright (c) 2026 @sitxovski (Discord)
# Astory Server - install what is needed to build the server patches / EAC server and to run the deploy tools.
#   install_prerequisites.bat            development PC (build + deploy over SSH)
#   install_prerequisites.bat -Server    game server machine
#   add -Yes to install everything without questions
param([switch]$Server, [switch]$Yes)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\_setup\install_common.ps1')
if (-not (Test-Winget)) { exit 1 }

$pkgs = @(
    @{ Name = 'Python 3.13'; Id = 'Python.Python.3.13'; Why = 'deploy, verification and anti-cheat tools' },
    @{ Name = 'Microsoft ODBC Driver 17 for SQL Server'; Id = 'Microsoft.msodbcsql.17'; Why = 'tools and EacServer connect to SQL Server' }
)
if ($Server) {
    $pkgs += @{ Name = 'Visual C++ Redistributable 2015-2022 x86'; Id = 'Microsoft.VCRedist.2015+.x86'; Why = 'the 32-bit game server processes' }
    $pkgs += @{ Name = 'Visual C++ Redistributable 2015-2022 x64'; Id = 'Microsoft.VCRedist.2015+.x64'; Why = 'EacServer (64-bit)' }
    $pkgs += @{ Name = 'sqlcmd'; Id = 'Microsoft.Sqlcmd'; Why = 'Prerequisites\setup_server.ps1 restores the databases with it' }
    $pkgs += @{ Name = 'Node.js LTS'; Id = 'OpenJS.NodeJS.LTS'; Why = 'runs Patches\Gp7Gateway\server.js (shop / balance gateway)' }
    $pkgs += @{ Name = 'Tailscale (optional)'; Id = 'Tailscale.Tailscale'; Why = 'private VPN address for SSH and the admin panel' }
} else {
    $vs = '--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ' +
          '--add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended --passive --wait'
    $pkgs += @{ Name = 'Visual Studio 2022 Build Tools (C++ x86 + x64)'; Id = 'Microsoft.VisualStudio.2022.BuildTools'; Override = $vs;
                Why = 'build.bat of every patch (x86 DLLs) and EacServer (x64) use vcvars32 / vcvars64' }
    $pkgs += @{ Name = 'Node.js LTS'; Id = 'OpenJS.NodeJS.LTS'; Why = 'node --check / stands of the gp7 gateway before deploy' }
    $pkgs += @{ Name = 'Git'; Id = 'Git.Git'; Why = 'getting the sources' }
}
$failed = Install-Packages -Packages $pkgs -Yes:$Yes
$pyok = Install-PythonRequirements (Join-Path $PSScriptRoot 'requirements.txt')

$manual = @(
    'The original game server stack (LoginManager, GameServer, NpcServer, DBManager ...) and its databases are NOT in this repository - install your copy into <ASTORY_SERVER_ROOT>\Working_ASDA\v2 on the server.',
    '.NET Framework 4.x is part of Windows - LogDrop\build.bat uses its csc.exe.'
)
if ($Server) {
    $manual += 'SQL Server 2019 Express (the version Astory runs on - not 2022): https://www.microsoft.com/download/details.aspx?id=101064 -> Custom: instance SQLEXPRESS, Mixed Mode authentication, server collation Cyrillic_General_CI_AS, then enable TCP/IP 1433 in SQL Server Configuration Manager.'
    $manual += 'OpenSSH Server (as Administrator): Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 ; Start-Service sshd ; Set-Service sshd -StartupType Automatic'
    $manual += 'SQL Server: enable TCP/IP on port 1433 and restore / attach the game databases.'
} else {
    $manual += 'Run _setup\configure.bat in the repository root (server addresses, paths, SSH key).'
}
Show-Manual $manual
if ($failed) { Write-Host ('Failed: ' + ($failed -join ', ')) -ForegroundColor Red }
if (-not $pyok) { Write-Host 'Python packages were not installed - see the message above.' -ForegroundColor Yellow }
