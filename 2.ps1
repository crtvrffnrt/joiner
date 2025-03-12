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

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Error "Please run this script as Administrator!"
    exit 1
}

# Set Execution Policy
try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    Log-Info "PowerShell Execution Policy set to Unrestricted."
} catch {
    Log-Error "Failed to set Execution Policy: $_"
}

# Ensure Internet Access and update security settings
Log-Info "Ensuring internet access and disabling restrictive security policies..."

# 1. Disable Internet Explorer Enhanced Security Configuration
try {
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 0 /f
    Log-Info "Disabled Internet Explorer Enhanced Security Configuration."
} catch {
    Log-Error "Failed to disable IE Enhanced Security: $_"
}

# 2. Allow all outbound traffic in Windows Firewall
try {
    New-NetFirewallRule -DisplayName "Allow Outbound Traffic" -Direction Outbound -Action Allow -Protocol Any -ErrorAction Stop
    Log-Info "Firewall rule added to allow all outbound traffic."
} catch {
    Log-Error "Firewall rule might already exist or failed to apply: $_"
}

# 3. Set network profile to "Private"
try {
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    Log-Info "Network profile set to Private."
} catch {
    Log-Error "Failed to set network profile: $_"
}

# 4. Start necessary services for outbound communication
try {
    Start-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
    Start-Service -Name BITS -ErrorAction SilentlyContinue
    Log-Info "Started WinHttpAutoProxySvc and BITS services."
} catch {
    Log-Error "Failed to start necessary services: $_"
}

# Disable Windows Defender realtime monitoring (if supported)
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Log-Info "Windows Defender real-time monitoring disabled."
} catch {
    Log-Error "Failed to disable Windows Defender monitoring: $_"
}

# Set TLS to prevent connectivity issues
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

# Update NuGet and PowerShellGet provider
try {
    Log-Info "Updating PowerShellGet and NuGet Package Provider..."
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Install-Module PowerShellGet -Force -SkipPublisherCheck -ErrorAction Stop
    Log-Info "PowerShellGet and NuGet updated successfully."
} catch {
    Log-Error "Failed to update PowerShellGet/NuGet: $_"
}

Start-Sleep -Seconds 15

# Create secure credentials
try {
    $CleanUsername = $username.Trim("'")
    $CleanDomain = $domain.Trim("'")
    $SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$CleanUsername@$CleanDomain", $SecurePassword)
    Log-Info "Credentials created successfully."
} catch {
    Log-Error "Failed to create credentials: $_"
    exit 1
}

Start-Sleep -Seconds 5

# Configure Auto-Login
try {
    Log-Info "Configuring Auto-Logon..."
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path $regPath -Name "DefaultUsername" -Value $username
    Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value $domain
    Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $password
    Log-Info "Auto-Logon configured."
} catch {
    Log-Error "Failed to configure Auto-Logon: $_"
}

# Configure MDM Enrollment Registry Keys
try {
    Log-Info "Configuring MDM Enrollment Registry Keys..."
    $MDMRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
    New-Item -Path $MDMRegPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "AutoEnrollMDM" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "UseAADCredentialType" -Value 1 -PropertyType DWORD -Force | Out-Null
    Log-Info "MDM Enrollment registry keys configured."
} catch {
    Log-Error "Failed to configure MDM registry keys: $_"
}

# Suppress Windows Welcome Experience and Privacy Settings
try {
    Log-Info "Suppressing Windows Welcome Experience and Privacy Settings..."
    $OOBERegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
    New-ItemProperty -Path $OOBERegPath -Name "HidePrivacySettings" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBERegPath -Name "SkipMachineOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBERegPath -Name "SkipUserOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    Log-Info "OOBE settings suppressed."
} catch {
    Log-Error "Failed to suppress Windows Welcome Experience: $_"
}

# Set Keyboard Layout and Regional Settings (for Windows 10/11)
try {
    Log-Info "Setting keyboard layout and regional settings to German (de-DE)..."
    Set-WinUILanguageOverride -Language de-DE
    Set-WinUserLanguageList -LanguageList de-DE -Force
    Set-WinSystemLocale -SystemLocale de-DE
    Set-Culture -CultureInfo de-DE
    Set-WinHomeLocation -GeoId 94   # 94 corresponds to Germany
    Log-Info "Keyboard layout and regional settings applied."
} catch {
    Log-Error "Failed to set keyboard layout/regional settings: $_"
}

# Additional configuration for Windows Server 2025 may be applied here.
# (For example, conditionally check OS version if needed)
# $os = Get-CimInstance Win32_OperatingSystem
# if ($os.Caption -match "Windows Server") {
#     Log-Info "Detected Windows Server environment. Running server-specific configuration..."
#     # Insert server-specific commands here
# }

# Disable LSASS Protection
try {
    Log-Info "Disabling LSASS Protection..."
    $LSASSPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $LSASSPath -Name "RunAsPPL" -Value 0 -Type DWord -Force
    Log-Info "LSASS Protection disabled."
} catch {
    Log-Error "Failed to disable LSASS Protection: $_"
}

# Final Restart to Apply Changes
try {
    Log-Info "Creating marker file and restarting computer to complete setup..."
    mkdir "C:\Users\joiner\Desktop\endofscriptreached" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Restart-Computer -Force
} catch {
    Log-Error "Failed to restart computer: $_"
}
