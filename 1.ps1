
# Merged Setup Script (1.ps1)
# This script performs the following steps:
# 1. Installs Nuget PackageProvider and waits.
# 2. Creates credentials.
# 3. Defines a logging function.
# 4. Installs AADInternals modules.
# 5. Installs Python.
# 6. Disables Windows Defender real-time monitoring.
# 7. Imports AADInternals modules (with retry logic).
# 8. Re-creates credentials (if needed).
# 9. Acquires AAD Join token and exports tokens.
# 10. Registers the device to Azure AD.
# 11. Acquires Intune MDM token and enrolls the device in Intune.
# 12. Configures registry settings for MDM.
# 13. Adds the computer to the AzureAD domain.
# 14. Downloads, extracts, and installs dependencies for the pytune repository,
#     and finally executes the pytune script.

Start-Sleep -Seconds 5
Install-PackageProvider -Name Nuget -Force -ErrorAction Stop
Start-Sleep -Seconds 5

# Create credentials
try {
    $SecurePassword = ConvertTo-SecureString "$password" -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$username@$domain", $SecurePassword)
    Write "Credentials created."
} catch {
    Write "ERROR: Failed to create credentials: $_"
    exit
}

# Define Log function (used by subsequent operations)
Function Log($Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "C:\setup_log.txt" -Value "$Timestamp - $Message"
}

# Install AADInternals modules
try {
    Install-Module -Name AADInternals,AADInternals-Endpoints -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
    Write "AADInternals modules installed successfully."
} catch {
    Write "ERROR: Failed to install AADInternals modules: $_"
    exit
}

# Install Python
Write "Starting Python installation..."
$pythonUrl = "https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe"
$installerPath = "$env:TEMP\python-3.10.9-amd64.exe"
Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
Remove-Item $installerPath -Force
Write "Python installation completed successfully."

Start-Sleep -Seconds 5

# Disable Windows Defender real-time monitoring
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write "Windows Defender real-time monitoring disabled."
} catch {
    Write "ERROR: Failed to disable Windows Defender monitoring: $_"
}

# Re-install AADInternals modules and import with retry logic
try {
    Install-Module -Name AADInternals,AADInternals-Endpoints -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
    Write "AADInternals modules installed successfully."
} catch {
    Write "ERROR: Failed to install AADInternals modules: $_"
    exit
}
Start-Sleep -Seconds 5
try {
    $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath','User') + ';' + [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
    Import-Module AADInternals,AADInternals-Endpoints -Force -ErrorAction Stop
    Write-Output "AADInternals modules imported."
} catch {
    Write-Output "WARNING: Initial module import failed. Attempting reinstallation."
    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            Install-Module -Name AADInternals,AADInternals-Endpoints -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Output "Reinstallation attempt $attempt successful."
            $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath','User') + ';' + [System.Environment]::GetEnvironmentVariable('PSModulePath','Machine')
            $null = Get-Module -ListAvailable -Refresh
            Import-Module AADInternals,AADInternals-Endpoints -Force -ErrorAction Stop
            Write-Output "AADInternals modules imported successfully on attempt $attempt."
            break
        } catch {
            Write-Output "ERROR: Reinstallation/import attempt $attempt failed: $_"
            if ($attempt -eq $maxRetries) {
                Write-Output "ERROR: Maximum retry attempts reached. Continuing without AADInternals modules."
            } else {
                Start-Sleep -Seconds 5
            }
        }
    }
}
Start-Sleep -Seconds 5
try {
    $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath','User') + ';' + [System.Environment]::GetEnvironmentVariable('PSModulePath','Machine')
    Import-Module AADInternals,AADInternals-Endpoints -Force -ErrorAction Stop
    Write "AADInternals modules imported."
} catch {
    Write "ERROR: Failed to import AADInternals modules: $_"
    exit
}
Start-Sleep -Seconds 5

# Re-create credentials (if needed)
try {
    $SecurePassword = ConvertTo-SecureString "$password" -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential("$username@$domain", $SecurePassword)
    Write "Credentials created."
} catch {
    Write "ERROR: Failed to create credentials: $_"
    exit
}
Start-Sleep -Seconds 5

# Acquire AAD Join token and export tokens
try {
    $AADToken = Get-AADIntAccessTokenForAADJoin -Credentials $Credential -SaveToCache -ErrorAction Stop
    @{RefreshToken=$AADToken.RefreshToken} | ConvertTo-Json | Out-File "C:\to.json" -Encoding utf8
    @{AccessToken=$AADToken.AccessToken} | ConvertTo-Json | Out-File "C:\ac.json" -Encoding utf8
    Write "AAD Join token acquired and tokens exported."
} catch {
    Write "ERROR: Failed to acquire Azure AD Join token: $_"
    exit
}
Start-Sleep -Seconds 5

# Register device to Azure AD
try {
    $DeviceInfo = Join-AADIntDeviceToAzureAD -DeviceName "$RESOURCE_GROUP" -DeviceType "WindowsServer" -OSVersion "This is a phishig test" -JoinType Register -Credentials $Credential -ErrorAction Stop
    Write "Device registered to Azure AD. Device ID: $($DeviceInfo.DeviceId)"
} catch {
    Write "ERROR: Failed to register device to Azure AD: $_"
    exit
}
Start-Sleep -Seconds 5

# Acquire Intune MDM token
try {
    $PfxFile = "$($DeviceInfo.DeviceId).pfx"
    $IntuneToken = Get-AADIntAccessTokenForIntuneMDM -PfxFileName $PfxFile -SaveToCache -ErrorAction Stop
    Write "Intune MDM token acquired."
} catch {
    Write "ERROR: Failed to acquire Intune MDM token: $_"
}
Start-Sleep -Seconds 5

# Enroll device in Intune
try {
    $IntuneEnrollment = Join-AADIntDeviceToIntune -DeviceName "$RESOURCE_GROUP" -AccessToken $IntuneToken -ErrorAction Stop
    Write "Device enrolled in Intune. Certificate Thumbprint: $($IntuneEnrollment.Thumbprint)"
} catch {
    Write "ERROR: Failed to enroll device into Intune: $_"
}
Start-Sleep -Seconds 5

# Configure registry for MDM enrollment
try {
    $MDMRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
    New-Item -Path $MDMRegPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "AutoEnrollMDM" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $MDMRegPath -Name "UseAADCredentialType" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write "Registry MDM enrollment keys configured."
} catch {
    Write "ERROR: Failed to configure MDM registry keys: $_"
}

# Add computer to AzureAD domain
try {
    Add-Computer -DomainName "AzureAD" -Credential $Credential -Force -Restart -ErrorAction Stop
    Write "Computer added to AzureAD domain successfully. Restarting..."
} catch {
    Write "ERROR: Failed to add computer to AzureAD domain: $_"
}
Start-Sleep -Seconds 5

# Pytune installation
Write "Downloading pytune repository from GitHub..."
$repoUrl = "https://github.com/secureworks/pytune/archive/refs/heads/main.zip"
$zipPath = "$env:TEMP\pytune-main.zip"
Invoke-WebRequest -Uri $repoUrl -OutFile $zipPath

Write "Extracting repository..."
$extractPath = "C:\pytune-main"
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
Remove-Item $zipPath -Force

Write "Installing Python dependencies..."
Set-Location "$extractPath\pytune-main"
python -m pip install --upgrade pip
if (Test-Path ".\requirements.txt") {
    python -m pip install -r .\requirements.txt
} else {
    Write "No requirements.txt found. Skipping dependency installation."
}
Write "Executing pytune script..."
python pytune.py --help
