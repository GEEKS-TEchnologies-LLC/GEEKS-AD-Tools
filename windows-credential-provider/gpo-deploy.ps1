# Group Policy Deployment Script for Credential Provider
# This script can be used as a startup script in Group Policy

param(
    [string]$NetworkShare = "\\your-server\share\ForgotPasswordProvider\",
    [string]$InstallPath = "C:\Program Files\ForgotPasswordProvider\",
    [string]$ProviderGUID = "{D1A5B6C7-1234-4E5F-8A9B-1234567890AB}"
)

# Log file for troubleshooting
$LogFile = "C:\Windows\Temp\CredProviderInstall.log"
$LogMessage = "Starting Credential Provider deployment at $(Get-Date)"

# Function to write to log
function Write-Log {
    param([string]$Message)
    $LogMessage = "$(Get-Date): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

Write-Log "Starting deployment..."

# Check if DLL exists on network share
$DllSourcePath = Join-Path $NetworkShare "ForgotPasswordProvider.dll"
if (!(Test-Path $DllSourcePath)) {
    Write-Log "ERROR: DLL not found at $DllSourcePath"
    exit 1
}

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Log "Created directory: $InstallPath"
}

# Copy DLL to installation directory
$DllDestPath = Join-Path $InstallPath "ForgotPasswordProvider.dll"
Copy-Item $DllSourcePath $DllDestPath -Force
Write-Log "Copied DLL to: $DllDestPath"

# Register in registry
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGUID"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "(Default)" -Value $DllDestPath
Write-Log "Registered in registry: $RegPath"

Write-Log "Deployment completed successfully" 