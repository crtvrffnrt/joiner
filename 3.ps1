[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Username,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Domain,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Password,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Resource_Group
)

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
    $entry = "$timestamp - ${Level}: $Message"
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

function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log -Level "ERROR" -Message "Run this script from an elevated PowerShell prompt."
        exit 1
    }
}

function Configure-DefenderExclusions {
    try {
        Set-MpPreference -ExclusionPath "C:\*" -ErrorAction Stop
        Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
        Write-Log "Defender exclusions and execution policy applied."
    } catch {
        Write-Log -Level "WARN" -Message "Defender or execution policy configuration failed: $_"
    }
}

function Relax-NetworkSecurity {
    Write-Log "Relaxing outbound security controls for tooling bootstrap."
    try {
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 0 /f | Out-Null
        New-NetFirewallRule -DisplayName "Allow Outbound Traffic" -Direction Outbound -Action Allow -Protocol Any -ErrorAction Stop | Out-Null
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
        Start-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
        Start-Service -Name BITS -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Level "WARN" -Message "Networking relaxation failed: $_"
    }
}

function Enable-WinRMHttps {
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
        Write-Log "WinRM over HTTPS enabled on port 5986."
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to configure WinRM HTTPS: $_"
    }
}

function Set-KeyboardAndLsass {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name InstallLanguage -Value "0407"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name Default -Value "de-DE"

        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\International\User Profile"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name "Languages" -Value "de-DE"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord -Force
        Write-Log "Keyboard layout switched to de-DE and LSASS protection disabled."
    } catch {
        Write-Log -Level "WARN" -Message "Failed to adjust keyboard or LSASS settings: $_"
    }
}

function Finalize-Restart {
    try {
        New-Item -Path "C:\endofscriptreached_3" -ItemType Directory -Force | Out-Null
        Write-Log "Marker directory created. Restarting host."
        Start-Sleep -Seconds 2
        Restart-Computer -Force
    } catch {
        Write-Log -Level "ERROR" -Message "Could not restart computer: $_"
    }
}

Assert-Administrator
Configure-DefenderExclusions
Relax-NetworkSecurity
Enable-WinRMHttps
Set-KeyboardAndLsass
Finalize-Restart
