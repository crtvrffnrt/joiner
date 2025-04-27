#region Logging Functions
Function Log-Info($Message) { $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; Write-Host "$timestamp - INFO: $Message" -ForegroundColor Cyan }
Function Log-Error($Message) { $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $errorMsg = "$timestamp - ERROR: $Message"; Write-Host $errorMsg -ForegroundColor Red; Add-Content -Path "C:\setup_log.txt" -Value $errorMsg }
#endregion

#region Pre-Checks
if ($PSVersionTable.PSVersion.Major -lt 5) { Log-Error "PowerShell version too old. Exiting."; exit 1 }
#endregion

#region Disable Defender (Double Hardening)
try { Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true; Log-Info "Defender protections disabled." } catch { Log-Error "Failed disabling Defender: $_" }
#endregion

#region Install Winget (if missing)
try {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile C:\winget.msixbundle; Add-AppxPackage -Path C:\winget.msixbundle
        Log-Info "Winget installed."
    } else { Log-Info "Winget already present." }
} catch { Log-Error "Winget installation failed: $_" }
#endregion

#region Install Tools via Winget
try {
    $apps = @(
        "Git.Git", "Python.Python.3", "Microsoft.VisualStudio.2022.BuildTools",
        "Microsoft.AzureCLI", "GhidraFoundation.Ghidra", "Nmap.Nmap",
        "Microsoft.PowerToys", "JanDeDobbeleer.OhMyPosh", "Notepad++.Notepad++"
    )
    foreach ($app in $apps) { winget install --id $app -e --accept-source-agreements --accept-package-agreements }
    Log-Info "Core apps installed via Winget."
} catch { Log-Error "Winget apps installation failed: $_" }
#endregion

#region Install PowerShell Modules
try {
    $modules = @("AADInternals", "Microsoft.Graph", "AzureAD", "AzureAD.Standard.Preview", "MSOnline", "Az", "Az.Resources")
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Install-Module -Name $mod -Force -Scope CurrentUser -AllowClobber
            Log-Info "Installed PowerShell module: $mod"
        } else { Log-Info "Module already available: $mod" }
    }
} catch { Log-Error "PowerShell modules installation failed: $_" }
#endregion

#region Clone Offensive Tools (Encoded URLs)
Function Safe-GitClone($repoEncoded, $destinationPath) {
    try {
        $repoURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($repoEncoded))
        git clone $repoURL $destinationPath
        Log-Info "Cloned: $destinationPath"
    } catch { Log-Error "Git clone failed for $destinationPath: $_" }
}

try {
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) { Log-Error "Git missing." }
    else {
        $repos = @(
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL05ldFNQSS9HcmFwaFJ1bm5lci5naXQ="; path = "C:\Tools\GraphRunner" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9BenVyZUhvdW5kLmdpdA=="; path = "C:\Tools\AzureHound" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9DZXJ0aWZ5LmdpdA=="; path = "C:\Tools\Certify" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9SdWJldXMuZ2l0"; path = "C:\Tools\Rubeus" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0luaXRpYWxJbXBhY3QvUG93ZXJadXJlLmdpdA=="; path = "C:\Tools\PowerZure" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL1N0b3JtU3BvdHRlci9TdG9ybVNwb3R0ZXIuZ2l0"; path = "C:\Tools\StormSpotter" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0Jsb29kSG91bmRBRC9ST0FERmlyc3QtUmVsZWFzZS5naXQ="; path = "C:\Tools\ROADRecon" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0F6dXJlQURQZW50ZXN0aW5nL0F6dXJlQURSZWNvbi5naXQ="; path = "C:\Tools\AzureADRecon" },
            @{ url = "aHR0cHM6Ly9naXRodWIuY29tL0dob3N0UGFjay9TZWF0YmVsdC5naXQ="; path = "C:\Tools\Seatbelt" }
        )
        foreach ($repo in $repos) { Safe-GitClone -repoEncoded $repo.url -destinationPath $repo.path }
    }
} catch { Log-Error "Git cloning phase failed: $_" }
#endregion

#region Import Custom Modules if Needed
try { Import-Module "C:\Tools\GraphRunner\GraphRunner.psm1" -Force; Log-Info "GraphRunner imported." } catch { Log-Error "Import GraphRunner failed: $_" }
#endregion

#region Final Adjustments
try {
    Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "Background" -Value "0 0 0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value ""
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
    Log-Info "Desktop set to black."
} catch { Log-Error "Desktop config failed: $_" }
#endregion

#region Completion
try { mkdir "C:\endofscriptreached_final" -ErrorAction SilentlyContinue; Log-Info "Setup completed. Restarting..."; Start-Sleep -Seconds 5; Restart-Computer -Force } catch { Log-Error "Reboot failed: $_" }
#endregion
