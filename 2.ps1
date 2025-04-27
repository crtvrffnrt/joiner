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

#region Pre-Defender Hardening
try {
    Set-MpPreference -ExclusionPath "C:\", "C:\Windows\Temp", "C:\Packages"
    Log-Info "Early Defender exclusion added for C:\\ and system temp directories."
} catch {
    Log-Error "Failed to set Defender exclusions early: $_"
}

try {
    $tamperPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    if (Test-Path $tamperPath) {
        Set-ItemProperty -Path $tamperPath -Name "TamperProtection" -Value 0 -Force
        Log-Info "Tamper Protection disabled via registry."
    } else {
        Log-Error "Tamper Protection registry path not found."
    }
} catch {
    Log-Error "Failed to disable Tamper Protection: $_"
}

try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableBlockAtFirstSeen $true
    Set-MpPreference -DisableIOAVProtection $true
    Set-MpPreference -DisablePrivacyMode $true
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
    Log-Info "Real-Time Protection features disabled."
} catch {
    Log-Error "Failed to disable Real-Time Protection: $_"
}

$timeout = 0
while ((Get-MpComputerStatus).RealTimeProtectionEnabled -eq $true -and $timeout -lt 60) {
    Log-Info "Waiting for Real-Time Protection to fully disable..."
    Start-Sleep -Seconds 2
    $timeout += 2
}

if ((Get-MpComputerStatus).RealTimeProtectionEnabled -eq $true) {
    Log-Error "Defender Real-Time Protection still active after waiting. Potential blocking risk remains!"
} else {
    Log-Info "Defender Real-Time Protection is fully disabled."
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
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Log-Info "Disabled Windows Firewall for all profiles."
} catch {
    Log-Error "Failed to disable Windows Firewall: $_"
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

#region Tool Installation Section
try {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9ha2EubXMvZ2V0d2luZ2V0"))) | Out-File -FilePath "C:\\winget.msixbundle"
        Add-AppxPackage -Path "C:\\winget.msixbundle"
        Log-Info "Installed Winget."
    } else {
        Log-Info "Winget already installed."
    }

    winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    Log-Info "Installed Git."

    winget install --id Python.Python.3 -e --accept-source-agreements --accept-package-agreements
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements
    Log-Info "Installed Python and VS Build Tools."

    Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cGlwIGluc3RhbGwgc2V0dGluZ3MgaGVyZQ==")))

    $modules = @("AADInternals", "Microsoft.Graph", "AzureAD", "AzureAD.Standard.Preview", "MSOnline")
    foreach ($mod in $modules) {
        Install-Module -Name $mod -Force -Scope CurrentUser
    }

    $repos = @(
        @{url="aHR0cHM6Ly9naXRodWIuY29tL05ldFNQSS9HcmFwaFJ1bm5lci5naXQ="; path="C:\\Tools\\GraphRunner"},
        @{url="aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9BenVyZUhvdW5kLmdpdA=="; path="C:\\Tools\\AzureHound"},
        @{url="aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9DZXJ0aWZ5LmdpdA=="; path="C:\\Tools\\Certify"},
        @{url="aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9SdWJldXMuZ2l0"; path="C:\\Tools\\Rubeus"}
    )
    foreach ($repo in $repos) {
        git clone ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($repo.url))) $repo.path
    }

    Import-Module "C:\\Tools\\GraphRunner\\GraphRunner.psm1"
    Log-Info "Downloaded and installed major Azure/M365 pentesting tools."
} catch {
    Log-Error "Tool installation failed: $_"
}
#endregion

#region Completion
try {
    mkdir "C:\\endofscriptreached_final" -ErrorAction SilentlyContinue
    Log-Info "Setup completed successfully. Restarting VM to finalize installation."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} catch {
    Log-Error "Failed to restart computer: $_"
}
#endregion
