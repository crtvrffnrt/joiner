[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Username,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Domain,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Password,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Resource_Group
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
    $entry = "$timestamp - ${Level}: $Message"
    $color = if ($Level -eq "ERROR") { "Red" } else { "Cyan" }
    Write-Host $entry -ForegroundColor $color

    if ($Level -eq "ERROR") {
        Add-Content -Path $LogFile -Value $entry
    }
}

try {
    $safeFolderName = ("{0}-1scriptwasexecuted" -f $Resource_Group) -replace '[^\w\-]', "_"
    $dirPath = Join-Path -Path "C:\" -ChildPath $safeFolderName
    if (-not (Test-Path $dirPath)) {
        New-Item -Path $dirPath -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created directory $dirPath"
    } else {
        Write-Log -Message "Directory $dirPath already exists. Contents will be overwritten."
    }

    $outputFile = Join-Path -Path $dirPath -ChildPath "params.txt"
    $content = @"
Username: $Username
Domain: $Domain
Password: $Password
Resource Group: $Resource_Group
"@

    $content | Set-Content -Path $outputFile -Encoding UTF8
    Write-Log -Message "Parameter capture saved to $outputFile"
} catch {
    Write-Log -Message "Failed to persist parameters: $_" -Level "ERROR"
    exit 1
}
