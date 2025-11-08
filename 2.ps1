Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$LogFile = "C:\setup_log.txt"

#region Logging Helpers
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
#endregion

function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log -Level "ERROR" -Message "Run this script from an elevated PowerShell prompt."
        exit 1
    }
}

function Disable-DefenderStack {
    Write-Log "Configuring Defender to avoid interference."
    try {
        Set-MpPreference -ExclusionPath "C:\", "C:\Windows\Temp", "C:\Packages" -ErrorAction Stop
        $tamperPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        if (Test-Path $tamperPath) {
            Set-ItemProperty -Path $tamperPath -Name "TamperProtection" -Value 0 -Force -ErrorAction Stop
        }

        $defenderFlags = @{
            DisableRealtimeMonitoring                = $true
            DisableBehaviorMonitoring                = $true
            DisableBlockAtFirstSeen                  = $true
            DisableIOAVProtection                    = $true
            DisablePrivacyMode                       = $true
            SignatureDisableUpdateOnStartupWithoutEngine = $true
        }
        foreach ($flag in $defenderFlags.Keys) {
            $params = @{ ErrorAction = 'Stop' }
            $params[$flag] = $defenderFlags[$flag]
            Set-MpPreference @params
        }

        $timeout = 0
        while ((Get-MpComputerStatus).RealTimeProtectionEnabled -and $timeout -lt 60) {
            Start-Sleep -Seconds 2
            $timeout += 2
        }
        if ((Get-MpComputerStatus).RealTimeProtectionEnabled) {
            Write-Log -Level "WARN" -Message "Realtime protection still enabled. Manual review recommended."
        } else {
            Write-Log "Realtime protection fully disabled."
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to harden Defender: $_"
    }
}

function Configure-Networking {
    Write-Log "Tweaking firewall and networking for unrestricted outbound access."
    try {
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 0 /f | Out-Null
        New-NetFirewallRule -DisplayName "Allow Outbound Traffic" -Direction Outbound -Action Allow -Protocol Any -ErrorAction Stop | Out-Null
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
        Start-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
        Start-Service -Name BITS -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Level "WARN" -Message "Networking configuration hit an issue: $_"
    }
}

function Configure-RemoteAccess {
    Write-Log "Enabling WinRM HTTPS and RDP connectivity."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
        $httpsListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys["Transport"] -eq "HTTPS" }
        if (-not $httpsListener) {
            $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
            New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -Port 5986 -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to configure remote access: $_"
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
        Write-Log "Installed package $Id"
    } catch {
        Write-Log -Level "WARN" -Message "Failed installing $Id via Winget: $_"
    }
}

function Ensure-PowerShellModule {
    param([Parameter(Mandatory)][string]$Name)
    try {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Install-Module -Name $Name -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Log "Installed module $Name"
        } else {
            Write-Log "Module $Name already available."
        }
    } catch {
        Write-Log -Level "WARN" -Message "Module $Name failed to install: $_"
    }
}

function Clone-OffensiveRepository {
    param(
        [Parameter(Mandatory)][string]$EncodedUrl,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        Write-Log -Level "ERROR" -Message "Git is required before cloning tools."
        return
    }

    $decodedUrl = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedUrl))
    if (Test-Path $Path) {
        Write-Log -Level "WARN" -Message "Path $Path already exists. Skipping clone."
        return
    }

    try {
        New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null
        git clone $decodedUrl $Path | Out-Null
        Write-Log "Cloned $decodedUrl to $Path"
    } catch {
        Write-Log -Level "WARN" -Message "Failed cloning $decodedUrl: $_"
    }
}

function Install-ToolsSuite {
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
        Ensure-PowerShellModule -Name $module
    }

    foreach ($repo in @(
        @{ url = "aHR0cHM6Ly9naXRodWIuY29tL05ldFNQSS9HcmFwaFJ1bm5lci5naXQ="; path = "C:\Tools\GraphRunner" },
        @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9BenVyZUhvdW5kLmdpdA=="; path = "C:\Tools\AzureHound" },
        @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9DZXJ0aWZ5LmdpdA=="; path = "C:\Tools\Certify" },
        @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9SdWJldXMuZ2l0"; path = "C:\Tools\Rubeus" }
    )) {
        Clone-OffensiveRepository -EncodedUrl $repo.url -Path $repo.path
    }

    try {
        Import-Module "C:\Tools\GraphRunner\GraphRunner.psm1" -Force -ErrorAction Stop
        Write-Log "Imported GraphRunner module."
    } catch {
        Write-Log -Level "WARN" -Message "GraphRunner module import failed: $_"
    }
}

function Finalize-System {
    try {
        New-Item -Path "C:\endofscriptreached_final" -ItemType Directory -Force | Out-Null
        Write-Log "Marker folder created. Rebooting to finalize."
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to restart computer: $_"
    }
}

Assert-Administrator
Disable-DefenderStack
Configure-Networking
Configure-RemoteAccess
Install-ToolsSuite
Finalize-System
