param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)
Write-Host "neu"
# Ensure PowerShell is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Please run this script as Administrator!" -ForegroundColor Red
    exit 1
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

# 5. Ensure PowerShell Execution Policy is unrestricted
try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    Write-Host "Set PowerShell Execution Policy to Unrestricted." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to modify execution policy: $_" -ForegroundColor Yellow
}
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "Windows Defender real-time monitoring disabled."
} catch {
    Write-Host "ERROR: Failed to disable Windows Defender monitoring: $_"
}

# Set TLS to prevent connectivity issues
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

# Install NuGet Package Provider
try {
    Write-Host "Updating PowerShellGet and NuGet..." -ForegroundColor Cyan
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Install-Module PowerShellGet -Force -SkipPublisherCheck -ErrorAction Stop
    Write-Host "PowerShellGet and NuGet updated successfully!" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to update PowerShellGet/NuGet: $_" -ForegroundColor Yellow
}

Start-Sleep -Seconds 15
# Create secure credentials
try {
    $CleanUsername = $username.Trim("'")  # Remove any surrounding single quotes
    $CleanDomain = $domain.Trim("'")      # Remove any surrounding single quotes

    $SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$CleanUsername@$CleanDomain", $SecurePassword)

    Write-Host "Credentials created successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to create credentials: $_" -ForegroundColor Red
    exit 1
}
Start-Sleep -Seconds 5
$Credential
# Logging Function
Function Log($Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "C:\setup_log.txt" -Value "$Timestamp - $Message"
}
Write-Host "1" >> C:\log.txt
Start-Sleep -Seconds 15
# Install AADInternals Modules with Retry Logic
$MaxRetries = 3
$RetryCount = 0
$ModuleInstalled = $false

while ($RetryCount -lt $MaxRetries -and -not $ModuleInstalled) {
    try {
        Write-Host "Installing AADInternals modules (Attempt: $($RetryCount + 1))..." -ForegroundColor Cyan
        Install-Module -Name AADInternals -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
        Install-Module -Name AADInternals-Endpoints -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
        $ModuleInstalled = $true
        Write-Host "AADInternals modules installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Failed to install AADInternals modules. Retrying... ($_)" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $RetryCount++
    }
}

if (-not $ModuleInstalled) {
    Write-Host "ERROR: Failed to install AADInternals modules after $MaxRetries attempts. Exiting..." -ForegroundColor Red
    exit 1
}

# Verify module installation
if (-not (Get-Module -ListAvailable -Name AADInternals)) {
    Write-Host "ERROR: AADInternals module is not available. Exiting..." -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 5

# Import AADInternals Modules
try {
    Write-Host "Importing AADInternals modules..." -ForegroundColor Cyan
    Import-Module AADInternals -Force -ErrorAction Stop
    Import-Module AADInternals-Endpoints -Force -ErrorAction Stop
    Write-Host "AADInternals modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to import AADInternals modules: $_" -ForegroundColor Red
    exit 1
}
Start-Sleep -Seconds 15
##Setting empty Useragent
Set-AADIntSetting -Setting "User-Agent" -Value " "# Attempt to acquire AAD Join Token
## Auth
Write-Host "before: AADIntAccessTokenForAADJoin"
Write-Host $password
Get-AADIntAccessTokenForAADJoin -Credentials $Credential -SaveToCache -ErrorAction Stop
Write-Host "after: AADIntAccessTokenForAADJoin"
Write-Host $password
Start-Sleep -Seconds 5
# Register Device to Azure AD
# --- Replace this block in your script ---
$maxRetries = 5
$delaySeconds = 20
$registered = $false
for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
    Write-Host "Registering device to Azure AD (Attempt: $attempt/$maxRetries)..." -ForegroundColor Cyan
    try {
        $DeviceInfo = Join-AADIntDeviceToAzureAD -DeviceName $RESOURCE_GROUP -DeviceType "Windows" -OSVersion "2025" -JoinType Join -ErrorAction Stop
        Write-Host "Device Joined to EntraId successfully! Device ID: $($DeviceInfo.DeviceId)" -ForegroundColor Green
        $registered = $true
        break
    } catch {
        Write-Host "ERROR: Failed to register device to Azure AD (Attempt $attempt): $_" -ForegroundColor Red
        if ($attempt -lt $maxRetries) {
            Write-Host "Waiting $delaySeconds seconds before retrying..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delaySeconds
        }
    }
}
if (-not $registered) {
    Write-Host "ERROR: All attempts to register the device have failed. Exiting..." -ForegroundColor Red
    exit 1
}
Get-AADIntCache > C:\to.json
# --- End of replacement snippet ---
# Attempt to export the Refresh Token
# Configure Registry for MDM Enrollment
try {
    Write-Host "Configuring MDM Enrollment Registry Keys..." -ForegroundColor Cyan
    $MDMRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
    New-Item -Path $MDMRegPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "AutoEnrollMDM" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "UseAADCredentialType" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "MDM Enrollment registry keys configured successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to configure MDM registry keys: $_" -ForegroundColor Red
}
# Restart Computer to Apply Changes
Write-Host "Restarting computer to complete Azure AD Join & MDM Enrollment..." -ForegroundColor Cyan
Start-Sleep -Seconds 2
# Enable Auto-Login for the specified user
# Configure Auto-Logon
try {
    Write-Host "Configuring Auto-Logon..." -ForegroundColor Cyan
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path $RegPath -Name "DefaultUsername" -Value $username
    Set-ItemProperty -Path $RegPath -Name "DefaultDomainName" -Value $domain
    Set-ItemProperty -Path $RegPath -Name "DefaultPassword" -Value $password
    Write-Host "Auto-Logon configured successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to configure Auto-Logon: $_" -ForegroundColor Red
}
# Suppress Windows Welcome Experience and Privacy Settings
try {
    Write-Host "Suppressing Windows Welcome Experience and Privacy Settings..." -ForegroundColor Cyan
    $OOBERegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
    New-ItemProperty -Path $OOBERegPath -Name "HidePrivacySettings" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBERegPath -Name "SkipMachineOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBERegPath -Name "SkipUserOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "Windows Welcome Experience and Privacy Settings suppressed successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to suppress Windows Welcome Experience and Privacy Settings: $_" -ForegroundColor Red
}
# Set Keyboard Layout to German (DE)
try {
    Write-Host "Setting keyboard layout to German (DE)..." -ForegroundColor Cyan
    Set-WinUILanguageOverride -Language de-DE
    Set-WinUserLanguageList -LanguageList de-DE -Force
    Set-WinSystemLocale -SystemLocale de-DE
    Set-Culture -CultureInfo de-DE
    Set-WinHomeLocation -GeoId 94  # 94 corresponds to Germany
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
# Skip First Visit Welcome Screen (Privacy, Diagnostics, Find My Device)
try {
    Write-Host "Configuring OOBE settings to skip first-visit setup..." -ForegroundColor Cyan
    $OOBEPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
    New-ItemProperty -Path $OOBEPath -Name "DisablePrivacyExperience" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBEPath -Name "SkipMachineOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $OOBEPath -Name "SkipUserOOBE" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "OOBE settings configured successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to configure OOBE settings: $_" -ForegroundColor Red
}
# Restart System to Apply Entra ID Join & MDM Enrollment
Write-Host "Restarting computer to complete Azure AD Join & MDM Enrollment..." -ForegroundColor Cyan
mkdir "C:\Users\joiner\Desktop\endofscriptreached"
Start-Sleep -Seconds 1
Restart-Computer -Force
