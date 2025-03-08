param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)
# Ensure PowerShell is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Please run this script as Administrator!" -ForegroundColor Red
    exit 1
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
    $SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$username@$domain", $SecurePassword)
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
Set-AADIntUserAgent -Device Windows
# Attempt to acquire AAD Join Token
Start-Sleep -Seconds 5
# Register Device to Azure AD
try {
    Write-Host "Registering device to Azure AD..." -ForegroundColor Cyan
    $DeviceInfo = Join-AADIntDeviceToAzureAD -DeviceName $RESOURCE_GROUP -DeviceType "Server" -OSVersion "2025" -JoinType Register -ErrorAction Stop
    Write-Host "Device registered to Azure AD successfully! Device ID: $($DeviceInfo.DeviceId)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to register device to Azure AD: $_" -ForegroundColor Red
    exit 1
}
# Attempt to export the Refresh Token
try {
    @{RefreshToken=$AADToken.RefreshToken} | ConvertTo-Json | Out-File "C:\to.json" -Encoding utf8
    Write-Host "Refresh Token exported successfully." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to export Refresh Token: $_" -ForegroundColor Red
    exit 1
}
# Attempt to export the Access Token
try {
    @{AccessToken=$AADToken.AccessToken} | ConvertTo-Json | Out-File "C:\ac.json" -Encoding utf8
    Write-Host "Access Token exported successfully." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to export Access Token: $_" -ForegroundColor Red
    exit 1
}
Write-Host "All operations completed successfully!" -ForegroundColor Green
Start-Sleep -Seconds 5
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
Start-Sleep -Seconds 10
Restart-Computer -Force
