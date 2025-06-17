# Uninstall Credential Provider PowerShell Script
# Run as Administrator

param(
    [string]$InstallPath = "C:\Program Files\ForgotPasswordProvider\",
    [string]$ProviderGUID = "{D1A5B6C7-1234-4E5F-8A9B-1234567890AB}"
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Uninstalling Credential Provider..." -ForegroundColor Green

# Remove registry entry
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGUID"
if (Test-Path $RegPath) {
    Remove-Item $RegPath -Force
    Write-Host "Removed registry entry: $RegPath" -ForegroundColor Yellow
} else {
    Write-Host "Registry entry not found: $RegPath" -ForegroundColor Yellow
}

# Remove installation directory
if (Test-Path $InstallPath) {
    Remove-Item $InstallPath -Recurse -Force
    Write-Host "Removed installation directory: $InstallPath" -ForegroundColor Yellow
} else {
    Write-Host "Installation directory not found: $InstallPath" -ForegroundColor Yellow
}

Write-Host "Uninstallation complete!" -ForegroundColor Green
Write-Host "Please restart the computer for changes to take effect." -ForegroundColor Cyan 