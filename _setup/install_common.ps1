# Copyright (c) 2026 @sitxovski (Discord)
#
# install_common.ps1 - shared helper for <Project>\Prerequisites\install_prerequisites.ps1.
# Installs Windows packages with winget (asks before each one unless -Yes) and Python packages from requirements.txt.
# Everything it cannot install automatically is printed as a manual step at the end.

function Test-Winget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host 'winget not found. Install "App Installer" from the Microsoft Store (or https://aka.ms/getwinget), then run again.' -ForegroundColor Red
        return $false
    }
    return $true
}

function Test-Installed([string]$Id) {
    $out = & winget list --id $Id --exact --accept-source-agreements 2>$null | Out-String
    return ($out -match [regex]::Escape($Id))
}

# PATH of this window does not see programs installed a moment ago - reload it from the registry
function Update-SessionPath {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($m, $u) | Where-Object { $_ }) -join ';'
}

function Install-Packages {
    param([object[]]$Packages, [switch]$Yes)
    $failed = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Packages) {
        Write-Host ''
        Write-Host ($p.Name + '  (' + $p.Id + ')') -ForegroundColor White
        Write-Host ('  why: ' + $p.Why) -ForegroundColor DarkGray
        if (Test-Installed $p.Id) {
            Write-Host '  already installed' -ForegroundColor Green
            if ($p.Note) { Write-Host ('  note: ' + $p.Note) -ForegroundColor DarkYellow }
            continue
        }
        if (-not $Yes) {
            $a = Read-Host '  install now? [Y/n]'
            if ($a -match '^[nN]') { Write-Host '  skipped' -ForegroundColor DarkYellow; continue }
        }
        $wa = @('install', '--id', $p.Id, '--exact', '--accept-package-agreements', '--accept-source-agreements')
        if ($p.Override) { $wa += @('--override', $p.Override) }
        & winget @wa | Out-Host                       # progress on screen, not into the return value
        if ($LASTEXITCODE -ne 0) { Write-Host ('  winget exit code ' + $LASTEXITCODE) -ForegroundColor Red; $failed.Add($p.Name) }
    }
    Update-SessionPath
    return , $failed.ToArray()
}

function Get-RealPython {
    Update-SessionPath
    $c = Get-Command python -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
    return $c
}

function Install-PythonRequirements([string]$Requirements) {
    if (-not (Test-Path $Requirements)) { return $true }
    $py = Get-RealPython
    if (-not $py) {
        Write-Host 'Python is not installed (or only the Microsoft Store stub is in PATH). Install Python 3.11+ and run this script again in a NEW window.' -ForegroundColor Yellow
        return $false
    }
    Write-Host ''
    Write-Host ('pip install -r ' + $Requirements + '   (' + $py.Source + ')') -ForegroundColor White
    & $py.Source -m pip install --upgrade pip | Out-Host
    & $py.Source -m pip install -r $Requirements | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Show-Manual([string[]]$Steps) {
    if (-not $Steps) { return }
    Write-Host ''
    Write-Host 'Manual steps (cannot be installed automatically):' -ForegroundColor Cyan
    $i = 1
    foreach ($s in $Steps) { Write-Host ('  ' + $i + '. ' + $s); $i++ }
}
