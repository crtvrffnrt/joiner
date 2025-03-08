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
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    write "Windows Defender real-time monitoring disabled."
} catch {
    write "ERROR: Failed to disable Windows Defender monitoring: $_"
}
refreshenv
# Set TLS to prevent connectivity issues
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
refreshenv
# Install NuGet Package Provider
Write-Host "Installing NuGet Package Provider..." -ForegroundColor Cyan
try {
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Write-Host "NuGet Package Provider installed successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to install NuGet: $_" -ForegroundColor Red
    exit 1
}
Start-Sleep -Seconds 5
refreshenv
# Create secure credentials
try {
    $SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$username@$domain", $SecurePassword)
    Write-Host "Credentials created successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to create credentials: $_" -ForegroundColor Red
    exit 1
}

# Logging Function
Function Log($Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "C:\setup_log.txt" -Value "$Timestamp - $Message"
}
refreshenv
# Install AADInternals Modules with Retry Logic
$MaxRetries = 3
$RetryCount = 0
$ModuleInstalled = $false

while ($RetryCount -lt $MaxRetries -and -not $ModuleInstalled) {
    try {
        Write-Host "Installing AADInternals modules (Attempt: $($RetryCount + 1))..." -ForegroundColor Cyan
        Install-Module -Name AADInternals -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        Install-Module -Name AADInternals-Endpoints -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
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
refreshenv
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
Start-Sleep -Seconds 5

# Acquire AAD Join Token
try {
    Write-Host "Acquiring Azure AD Join Token..." -ForegroundColor Cyan
    $AADToken = Get-AADIntAccessTokenForAADJoin -Credentials $Credential -SaveToCache -ErrorAction Stop
    @{RefreshToken=$AADToken.RefreshToken} | ConvertTo-Json | Out-File "C:\to.json" -Encoding utf8
    @{AccessToken=$AADToken.AccessToken} | ConvertTo-Json | Out-File "C:\ac.json" -Encoding utf8
    Write-Host "Azure AD Join token acquired and saved!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to acquire Azure AD Join token: $_" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 5

# Register Device to Azure AD
try {
    Write-Host "Registering device to Azure AD..." -ForegroundColor Cyan
    $DeviceInfo = Join-AADIntDeviceToAzureAD -DeviceName $RESOURCE_GROUP -DeviceType "Server" -OSVersion "Windows Server 2025" -JoinType Register -Credentials $Credential -ErrorAction Stop
    Write-Host "Device registered to Azure AD successfully! Device ID: $($DeviceInfo.DeviceId)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to register device to Azure AD: $_" -ForegroundColor Red
    exit 1
}

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
