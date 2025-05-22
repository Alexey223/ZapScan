# scripts/deploy.ps1
param (
    [string]$OutputDir = "dist"
)

function Write-Log {
    param([string]$Level, [string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$timestamp] [$Level] $Message"
}

# Очистка и создание директории
if (Test-Path $OutputDir) {
    Write-Log "INFO" "Removing existing '$OutputDir' directory..."
    Remove-Item -Recurse -Force $OutputDir
}

Write-Log "INFO" "Creating '$OutputDir' directory..."
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Список файлов для копирования
$filesToCopy = @(
    "Start-ZapScan.ps1",
    "Start-ZapScan.Tests.ps1",
    "README.md"
)

foreach ($file in $filesToCopy) {
    if (Test-Path $file) {
        Copy-Item $file -Destination $OutputDir
        Write-Log "INFO" "Copied '$file' to '$OutputDir'"
    } else {
        Write-Log "WARNING" "File '$file' not found. Skipping..."
    }
}

Write-Log "INFO" "Deployment completed." 