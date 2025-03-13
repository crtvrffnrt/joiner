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

# Create secure credentials
try {
    # Ensure username, domain, and password are not null or empty
    if (-not $username -or -not $domain -or -not $password) {
        throw "Username, domain, or password cannot be empty!"
    }
    $CleanUsername = $username.Trim("'")  # Remove any surrounding single quotes
    $CleanDomain = $domain.Trim("'")      # Remove any surrounding single quotes
    # Ensure cleaned values are not empty
    if (-not $CleanUsername -or -not $CleanDomain) {
        throw "Cleaned username or domain is empty after processing!"
    }
    # Convert password to SecureString
    $SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
    # Create PSCredential object
    $Credential = New-Object System.Management.Automation.PSCredential("$CleanUsername@$CleanDomain", $SecurePassword)
    Write-Host "Credentials created successfully!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to create credentials: $_" -ForegroundColor Red
    exit 1
}
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
        Start-Sleep -Seconds 1
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
## Get-AADIntAccessTokenForAADJoin -Credentials $Credential -SaveToCache -ErrorAction Stop

# Register Device to Azure AD
## $maxRetries = 5
## $delaySeconds = 20
## $registered = $false
## for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
##     Write-Host "Registering device to Azure AD (Attempt: $attempt/$maxRetries)..." -ForegroundColor Cyan
##     try {
##         $DeviceInfo = Join-AADIntDeviceToAzureAD -DeviceName $RESOURCE_GROUP -DeviceType "Windows" -OSVersion "2025" -JoinType Join -ErrorAction Stop
##         Write-Host "Device Joined to EntraId successfully! Device ID: $($DeviceInfo.DeviceId)" -ForegroundColor Green
##         $registered = $true
##         break
##     } catch {
##         Write-Host "ERROR: Failed to register device to Azure AD (Attempt $attempt): $_" -ForegroundColor Red
##         if ($attempt -lt $maxRetries) {
##             Write-Host "Waiting $delaySeconds seconds before retrying..." -ForegroundColor Yellow
##             Start-Sleep -Seconds $delaySeconds
##         }
##     }
## }
## if (-not $registered) {
##     Write-Host "ERROR: All attempts to register the device have failed. Exiting..." -ForegroundColor Red
##     exit 1
## }
## Get-AADIntCache > C:\to.json
# --- End of replacement snippet ---
# Attempt to export the Refresh Token
# Configure Registry for MDM Enrollment
## try {
##     Write-Host "Configuring MDM Enrollment Registry Keys..." -ForegroundColor Cyan
##     $MDMRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
##     New-Item -Path $MDMRegPath -Force -ErrorAction Stop | Out-Null
##     New-ItemProperty -Path $MDMRegPath -Name "AutoEnrollMDM" -Value 1 -PropertyType DWORD -Force | Out-Null
##     New-ItemProperty -Path $MDMRegPath -Name "UseAADCredentialType" -Value 1 -PropertyType DWORD -Force | Out-Null
##     Write-Host "MDM Enrollment registry keys configured successfully!" -ForegroundColor Green
## } catch {
##     Write-Host "ERROR: Failed to configure MDM registry keys: $_" -ForegroundColor Red
## }
# Restart Computer to Apply Changes
# -----------------------------
# Enable WinRM HTTPS Listener
# -----------------------------
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

# Suppress Windows Welcome Experience and Privacy Settings
try {
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\PostBoot.ps1"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "PostBootConfig" -Action $Action -Trigger $Trigger -RunLevel Highest -Force
Write-Host "Scheduled PostBootConfig task to apply settings after user login."

} catch {
    Write-Host "ERROR: Failed to suppress Windows Welcome Experience and Privacy Settings: $_" -ForegroundColor Red
}
# Set Keyboard Layout to German (DE)
try {
    Write-Host "Setting keyboard layout to German (DE)..." -ForegroundColor Cyan
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name InstallLanguage -Value "0407"
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name Default -Value "de-DE"
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\International\User Profile" -Name "Languages" -Value "de-DE"
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
# Ski
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
try {
    Log-Info "Creating marker file and restarting computer to complete setup..."
    mkdir "C:\endofscriptreached" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Restart-Computer -Force
} catch {
    Log-Error "Failed to restart computer: $_"
}
