param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)
# Logging Functions
Function Log-Info($Message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - INFO: $Message" -ForegroundColor Cyan
}

Function Log-Error($Message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorMsg = "$timestamp - ERROR: $Message"
    Write-Host $errorMsg -ForegroundColor Red
    Add-Content -Path "C:\setup_log.txt" -Value $errorMsg
}
Write-Host "neu"
# Ensure PowerShell is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Please run this script as Administrator!" -ForegroundColor Red
    exit 1
}
try {
    Set-MpPreference -ExclusionPath "C:\*" -ErrorAction Stop
    Write-Host "Added 'C:\*' as a Defender exclusion path."

} catch {
    Write-Host "ERROR: Failed to modify Windows Defender settings: $_"
}
try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    Write-Host "Set PowerShell Execution Policy to Unrestricted." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to modify execution policy: $_" -ForegroundColor Yellow
}
# ---- Ensure Internet Access ----
Write-Host "Ensuring internet access and disabling restrictive security policies..." -ForegroundColor Cyan

# 1. Disable Internet Explorer Enhanced Security Configuration (ESC)
try {
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 0 /f
    Write-Host "Disabled Internet Explorer Enhanced Security Configuration." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to disable IE Enhanced Security: $_" -ForegroundColor Yellow
}

# 2. Ensure outbound connections are allowed in Windows Firewall
try {
    New-NetFirewallRule -DisplayName "Allow Outbound Traffic" -Direction Outbound -Action Allow -Protocol Any -ErrorAction Stop
    Write-Host "Firewall rule added to allow all outbound traffic." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Firewall rule might already exist or failed to apply: $_" -ForegroundColor Yellow
}

# 3. Set network profile to "Private" to avoid unidentified network issues
try {
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    Write-Host "Network profile set to Private." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to set network profile, check manually if needed: $_" -ForegroundColor Yellow
}

# 4. Start necessary services for outbound communication
try {
    Start-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
    Start-Service -Name BITS -ErrorAction SilentlyContinue
    Write-Host "Started WinHttpAutoProxy and BITS services." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to start WinHttpAutoProxySvc or BITS: $_" -ForegroundColor Yellow
}



# Set TLS to prevent connectivity issues
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
## Enable WinRM
try {
    Write-Host "Enabling WinRM HTTPS listener on port 5986..." -ForegroundColor Cyan

    Enable-PSRemoting -Force -SkipNetworkProfileCheck

    # Check for an existing HTTPS listener; if none, create one
    $httpsListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys["Transport"] -eq "HTTPS" }
    if (-not $httpsListener) {
        $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
        New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -Port 5986 -CertificateThumbPrint $cert.Thumbprint -Force
        Write-Host "HTTPS listener created on port 5986." -ForegroundColor Green
    } else {
        Write-Host "HTTPS listener already exists." -ForegroundColor Yellow
    }

    # Add firewall rule for HTTPS WinRM
    if (-not (Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
        Write-Host "Firewall rule for WinRM HTTPS added." -ForegroundColor Green
    } else {
        Write-Host "Firewall rule for WinRM HTTPS already exists." -ForegroundColor Yellow
    }
} catch {
    Write-Host "ERROR: Failed to enable WinRM HTTPS listener: $_" -ForegroundColor Red
}

# Set Keyboard Layout to German (DE)
try {
    Write-Host "Setting keyboard layout to German (DE)..." -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name InstallLanguage -Value "0407"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name Default -Value "de-DE"
    
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\International\User Profile"
    if (!(Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force
    }
    Set-ItemProperty -Path $RegistryPath -Name "Languages" -Value "de-DE"
    
    Write-Host "Keyboard layout set to German successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to set keyboard layout: $_" -ForegroundColor Red
}
try {
     Write-Host "Disabling LSASS Protection..." -ForegroundColor Cyan
       $LSASSPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
     Set-ItemProperty -Path $LSASSPath -Name "RunAsPPL" -Value 0 -Type DWord -Force
    Write-Host "LSASS Protection disabled successfully!" -ForegroundColor Green
} catch {
     Write-Host "ERROR: Failed to disable LSASS Protection: $_" -ForegroundColor Red
 }

try {
    Log-Info "Creating marker file and restarting computer to complete setup..."
    mkdir "C:\endofscriptreached_3" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Restart-Computer -Force
} catch {
    Log-Error "Failed to restart computer: $_"
}
