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

#region Pre-Checks
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Log-Error "PowerShell version too old. Exiting."
    exit 1
}
#endregion

#region Disable Defender Again (Double Hardening)
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableBlockAtFirstSeen $true
    Log-Info "Confirmed Defender Real-Time Protection disabled again."
} catch {
    Log-Error "Failed to double-disable Defender protections: $_"
}
#endregion

#region Install Winget (if missing)
try {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile C:\winget.msixbundle
        Add-AppxPackage -Path C:\winget.msixbundle
        Log-Info "Winget installed successfully."
    } else {
        Log-Info "Winget already installed."
    }
} catch {
    Log-Error "Winget installation failed: $_"
}
#endregion

#region Install Tools via Winget
try {
    winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    winget install --id Python.Python.3 -e --accept-source-agreements --accept-package-agreements
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements
    Log-Info "Git, Python, BuildTools installed via Winget."
} catch {
    Log-Error "Failed installing packages via Winget: $_"
}
#endregion

#region Install PowerShell Modules
try {
    $modules = @("AADInternals", "Microsoft.Graph", "AzureAD", "AzureAD.Standard.Preview", "MSOnline")
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Install-Module -Name $mod -Force -Scope CurrentUser -AllowClobber
            Log-Info "Installed module: $mod"
        } else {
            Log-Info "Module already installed: $mod"
        }
    }
} catch {
    Log-Error "Failed installing PowerShell modules: $_"
}
#endregion

#region Clone Repositories Obfuscated
Function Safe-GitClone($repoEncoded, $destinationPath) {
    try {
        $repoURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($repoEncoded))
        git clone $repoURL $destinationPath
        Log-Info "Cloned repo to $destinationPath"
    } catch {
        Log-Error "Git clone failed for $destinationPath: $_"
    }
}

try {
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        Log-Error "Git not available. Cannot clone repositories."
    } else {
        $repos = @(
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL05ldFNQSS9HcmFwaFJ1bm5lci5naXQ="; path = "C:\Tools\GraphRunner" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9BenVyZUhvdW5kLmdpdA=="; path = "C:\Tools\AzureHound" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9DZXJ0aWZ5LmdpdA=="; path = "C:\Tools\Certify" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9SdWJldXMuZ2l0"; path = "C:\Tools\Rubeus" }
        )
        foreach ($repo in $repos) {
            Safe-GitClone -repoEncoded $repo.url -destinationPath $repo.path
        }
    }
} catch {
    Log-Error "Exception during Git cloning phase: $_"
}
#endregion

#region Final Adjustments
try {
    Import-Module "C:\Tools\GraphRunner\GraphRunner.psm1" -Force
    Log-Info "Imported GraphRunner module."
} catch {
    Log-Error "Failed importing GraphRunner: $_"
}

try {
    Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "Background" -Value "0 0 0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value ""
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
    Log-Info "Desktop background set to solid black."
} catch {
    Log-Error "Failed setting desktop background: $_"
}
#endregion

#region Completion
try {
    mkdir "C:\endofscriptreached_final" -ErrorAction SilentlyContinue
    Log-Info "Full setup completed. Restarting VM."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} catch {
    Log-Error "Failed final reboot: $_"
}
#endregion
