[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$LogFile = "C:\setup_log.txt"

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Level: $Message"
    $color = switch ($Level) {
        "INFO" { "Cyan" }
        "WARN" { "Yellow" }
        default { "Red" }
    }
    Write-Host $entry -ForegroundColor $color
    if ($Level -eq "ERROR") {
        Add-Content -Path $LogFile -Value $entry
    }
}

function Assert-PowerShellVersion {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log -Level "ERROR" -Message "PowerShell 5.0+ is required."
        exit 1
    }
}

function Disable-Defender {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true
        Write-Log "Windows Defender protections disabled for installation window."
    } catch {
        Write-Log -Level "WARN" -Message "Could not fully disable Defender: $_"
    }
}

function Install-Winget {
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
        Write-Log "Winget already installed."
        return
    }

    try {
        $bundlePath = "C:\Packages\winget.msixbundle"
        New-Item -ItemType Directory -Path (Split-Path $bundlePath) -Force | Out-Null
        Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile $bundlePath -UseBasicParsing
        Add-AppxPackage -Path $bundlePath | Out-Null
        Write-Log "Winget installed."
    } catch {
        Write-Log -Level "ERROR" -Message "Winget installation failed: $_"
    }
}

function Install-WingetPackage {
    param([Parameter(Mandatory)][string]$Id)
    try {
        winget install --id $Id -e --silent --accept-source-agreements --accept-package-agreements | Out-Null
        Write-Log "Installed $Id"
    } catch {
        Write-Log -Level "WARN" -Message "Failed to install $Id: $_"
    }
}

function Ensure-Module {
    param([Parameter(Mandatory)][string]$Name)
    try {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Install-Module -Name $Name -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Log "Installed module $Name"
        } else {
            Write-Log "Module $Name already installed."
        }
    } catch {
        Write-Log -Level "WARN" -Message "Module $Name failed to install: $_"
    }
}

function Clone-Repo {
    param(
        [Parameter(Mandatory)][string]$EncodedUrl,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        Write-Log -Level "ERROR" -Message "Git missing. Cannot clone repositories."
        return
    }

    if (Test-Path $Path) {
        Write-Log -Level "WARN" -Message "$Path already exists. Skipping clone."
        return
    }

    try {
        New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null
        $url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedUrl))
        git clone $url $Path | Out-Null
        Write-Log "Cloned $url to $Path"
    } catch {
        Write-Log -Level "WARN" -Message "Failed to clone $Path: $_"
    }
}

function Configure-Desktop {
    try {
        Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "Background" -Value "0 0 0"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value ""
        RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
        Write-Log "Desktop set to black background."
    } catch {
        Write-Log -Level "WARN" -Message "Desktop configuration failed: $_"
    }
}

function Finalize-Setup {
    try {
        New-Item -Path "C:\endofscriptreached_final" -ItemType Directory -Force | Out-Null
        Write-Log "Setup marker written. Restarting computer."
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to restart computer: $_"
    }
}

Assert-PowerShellVersion
Disable-Defender
Install-Winget

foreach ($pkg in @(
    "Git.Git",
    "Python.Python.3",
    "Microsoft.VisualStudio.2022.BuildTools",
    "Microsoft.AzureCLI",
    "GhidraFoundation.Ghidra",
    "Nmap.Nmap",
    "Microsoft.PowerToys",
    "JanDeDobbeleer.OhMyPosh",
    "Notepad++.Notepad++"
)) {
    Install-WingetPackage -Id $pkg
}

foreach ($module in @("AADInternals","Microsoft.Graph","AzureAD","AzureAD.Standard.Preview","MSOnline","Az","Az.Resources")) {
    Ensure-Module -Name $module
}

New-Item -ItemType Directory -Path "C:\Tools" -Force | Out-Null

foreach ($repo in @(
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL05ldFNQSS9HcmFwaFJ1bm5lci5naXQ="; path = "C:\Tools\GraphRunner" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9BenVyZUhvdW5kLmdpdA=="; path = "C:\Tools\AzureHound" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9DZXJ0aWZ5LmdpdA=="; path = "C:\Tools\Certify" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9SdWJldXMuZ2l0"; path = "C:\Tools\Rubeus" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0luaXRpYWxJbXBhY3QvUG93ZXJadXJlLmdpdA=="; path = "C:\Tools\PowerZure" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL1N0b3JtU3BvdHRlci9TdG9ybVNwb3R0ZXIuZ2l0"; path = "C:\Tools\StormSpotter" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9ST0FERmlyc3QtUmVsZWFzZS5naXQ="; path = "C:\Tools\ROADRecon" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0F6dXJlQURQZW50ZXN0aW5nL0F6dXJlQURSZWNvbi5naXQ="; path = "C:\Tools\AzureADRecon" },
    @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9TZWF0YmVsdC5naXQ="; path = "C:\Tools\Seatbelt" }
)) {
    Clone-Repo -EncodedUrl $repo.url -Path $repo.path
}

try {
    Import-Module "C:\Tools\GraphRunner\GraphRunner.psm1" -Force -ErrorAction Stop
    Write-Log "GraphRunner imported."
} catch {
    Write-Log -Level "WARN" -Message "GraphRunner import failed: $_"
}

Configure-Desktop
Finalize-Setup
