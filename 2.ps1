#region Logging Functions

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
#endregion

#region Admin Check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Error "Please run this script as Administrator!"
    exit 1
}
#endregion

#region Windows Defender and Execution Policy Adjustments
try {
    Set-MpPreference -ExclusionPath "C:\*" -ErrorAction Stop
    Log-Info "Added 'C:\*' as Defender exclusion path."
} catch {
    Log-Error "Failed to modify Windows Defender settings: $_"
}

try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    Log-Info "Set PowerShell Execution Policy to Unrestricted."
} catch {
    Log-Error "Failed to modify execution policy: $_"
}
#endregion

#region Internet and Firewall Configuration
try {
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 0 /f
    Log-Info "Disabled IE Enhanced Security Configuration."
} catch {
    Log-Error "Failed to disable IE Enhanced Security: $_"
}

try {
    New-NetFirewallRule -DisplayName "Allow Outbound Traffic" -Direction Outbound -Action Allow -Protocol Any
    Log-Info "Firewall rule added to allow all outbound traffic."
} catch {
    Log-Error "Failed to apply firewall outbound rule: $_"
}

try {
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    Log-Info "Network profile set to Private."
} catch {
    Log-Error "Failed to set network profile: $_"
}

try {
    Start-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
    Start-Service -Name BITS -ErrorAction SilentlyContinue
    Log-Info "Started WinHttpAutoProxySvc and BITS services."
} catch {
    Log-Error "Failed to start WinHttpAutoProxySvc or BITS: $_"
}
#endregion

#region WinRM and RDP Setup
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13

try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Log-Info "Enabled PowerShell Remoting."

    $httpsListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys["Transport"] -eq "HTTPS" }
    if (-not $httpsListener) {
        $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
        New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -Port 5986 -CertificateThumbPrint $cert.Thumbprint -Force
        Log-Info "Created HTTPS listener for WinRM."
    } else {
        Log-Info "HTTPS listener already exists."
    }

    if (-not (Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
        Log-Info "Firewall rule added for WinRM HTTPS."
    } else {
        Log-Info "WinRM HTTPS firewall rule already exists."
    }
} catch {
    Log-Error "Failed to enable WinRM HTTPS: $_"
}

try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Log-Info "Enabled RDP access."
} catch {
    Log-Error "Failed to enable RDP: $_"
}
#endregion

#region Keyboard Layout Adjustment
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name InstallLanguage -Value "0407"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name Default -Value "de-DE"
    Log-Info "Set keyboard layout to German (DE)."
} catch {
    Log-Error "Failed to set keyboard layout: $_"
}
#endregion

#region LSASS Protection Disable
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord -Force
    Log-Info "Disabled LSASS Protection."
} catch {
    Log-Error "Failed to disable LSASS protection: $_"
}
#endregion

#region Tool Installation Section
try {
    # Install Winget
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile C:\winget.msixbundle
        Add-AppxPackage -Path C:\winget.msixbundle
        Log-Info "Installed Winget."
    } else {
        Log-Info "Winget already installed."
    }

    # Install Git, Python, Visual Studio Build Tools
    winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    winget install --id Python.Python.3 -e --accept-source-agreements --accept-package-agreements
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements
    Log-Info "Installed Git, Python, and VS Build Tools."

    # Install Roadtools
    pip install roadtools

    # Install PowerShell Modules
    Install-Module -Name AADInternals -Force -Scope CurrentUser
    Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
    Install-Module -Name AzureAD -Force -Scope CurrentUser
    Install-Module -Name AzureAD.Standard.Preview -Force -Scope CurrentUser
    Install-Module -Name MSOnline -Force -Scope CurrentUser

    # Clone GraphRunner
    git clone https://github.com/NetSPI/GraphRunner.git C:\Tools\GraphRunner
    Import-Module C:\Tools\GraphRunner\GraphRunner.psm1

    # Clone AzureHound
    git clone https://github.com/BloodHoundAD/AzureHound.git C:\Tools\AzureHound

    # Clone Certify
    git clone https://github.com/GhostPack/Certify.git C:\Tools\Certify

    # Clone Rubeus
    git clone https://github.com/GhostPack/Rubeus.git C:\Tools\Rubeus

    Log-Info "Downloaded and installed major Azure/M365 pentesting tools."
} catch {
    Log-Error "Tool installation failed: $_"
}
#endregion

#region Completion
try {
    mkdir "C:\endofscriptreached_final" -ErrorAction SilentlyContinue
    Log-Info "Setup completed successfully. Restarting VM to finalize installation."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} catch {
    Log-Error "Failed to restart computer: $_"
}
#endregion
