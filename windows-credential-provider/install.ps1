# Install Credential Provider PowerShell Script
# Run as Administrator

param(
    [string]$DllPath = ".\ForgotPasswordProvider.dll",
    [string]$InstallPath = "C:\Program Files\ForgotPasswordProvider\",
    [string]$ProviderGUID = "{D1A5B6C7-1234-4E5F-8A9B-1234567890AB}"
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Installing Credential Provider..." -ForegroundColor Green

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force
    Write-Host "Created directory: $InstallPath" -ForegroundColor Yellow
}

# Copy DLL to installation directory
$DllDestPath = Join-Path $InstallPath "ForgotPasswordProvider.dll"
Copy-Item $DllPath $DllDestPath -Force
Write-Host "Copied DLL to: $DllDestPath" -ForegroundColor Yellow

# Register in registry
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGUID"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "(Default)" -Value $DllDestPath
Write-Host "Registered in registry: $RegPath" -ForegroundColor Yellow

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Please restart the computer or log off/log on to see the 'Forgot Password?' tile on the lock screen." -ForegroundColor Cyan 