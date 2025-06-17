# GEEKS Credential Provider Uninstallation Script
# Run as Administrator

param(
    [switch]$Force
)

# Script information
$ScriptName = "GEEKS-CredentialProvider-Uninstall"
$ScriptVersion = "1.3.0"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogMessage
    Write-EventLog -LogName Application -Source $ScriptName -EventId 2000 -EntryType Information -Message $LogMessage -ErrorAction SilentlyContinue
}

# Error handling function
function Write-ErrorLog {
    param(
        [string]$Message,
        [string]$Exception = ""
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [ERROR] $Message"
    if ($Exception) {
        $LogMessage += " Exception: $Exception"
    }
    
    Write-Host $LogMessage -ForegroundColor Red
    Write-EventLog -LogName Application -Source $ScriptName -EventId 2001 -EntryType Error -Message $LogMessage -ErrorAction SilentlyContinue
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Create event log source
function New-EventLogSource {
    try {
        if (![System.Diagnostics.EventLog]::SourceExists($ScriptName)) {
            New-EventLog -LogName Application -Source $ScriptName
            Write-Log "Created event log source: $ScriptName"
        }
    } catch {
        Write-ErrorLog "Failed to create event log source" $_.Exception.Message
    }
}

# Get script directory
function Get-ScriptDirectory {
    return Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Main uninstallation function
function Uninstall-CredentialProvider {
    Write-Log "Starting GEEKS Credential Provider uninstallation..."
    
    $scriptDir = Get-ScriptDirectory
    $dllPath = Join-Path $scriptDir "GEEKS-CredentialProvider.dll"
    
    try {
        # Unregister the DLL if it exists
        if (Test-Path $dllPath) {
            Write-Log "Unregistering credential provider DLL..."
            $result = & regsvr32.exe /s /u $dllPath
            if ($LASTEXITCODE -ne 0) {
                Write-ErrorLog "Failed to unregister DLL with regsvr32"
                return $false
            }
            Write-Log "DLL unregistered successfully"
        } else {
            Write-Log "DLL not found, skipping unregistration"
        }
        
        # Remove registry settings
        Write-Log "Removing registry settings..."
        $registryPath = "HKLM:\SOFTWARE\GEEKS\CredentialProvider"
        
        if (Test-Path $registryPath) {
            Remove-Item -Path $registryPath -Recurse -Force
            Write-Log "Registry settings removed"
        } else {
            Write-Log "Registry settings not found"
        }
        
        # Remove credential provider registration
        $credProviderPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
        if (Test-Path $credProviderPath) {
            Remove-Item -Path $credProviderPath -Recurse -Force
            Write-Log "Credential provider registration removed"
        }
        
        # Remove CLSID registration
        $clsidPath = "HKCR:\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
        if (Test-Path $clsidPath) {
            Remove-Item -Path $clsidPath -Recurse -Force
            Write-Log "CLSID registration removed"
        }
        
        # Restart credential provider service
        Write-Log "Restarting credential provider service..."
        try {
            Stop-Service -Name "CredentialManager" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Service -Name "CredentialManager" -ErrorAction SilentlyContinue
            Write-Log "Credential provider service restarted"
        } catch {
            Write-Log "Warning: Could not restart credential provider service. Manual restart may be required."
        }
        
        Write-Log "GEEKS Credential Provider uninstallation completed successfully"
        return $true
        
    } catch {
        Write-ErrorLog "Uninstallation failed" $_.Exception.Message
        return $false
    }
}

# Main execution
try {
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider Uninstaller v$ScriptVersion"
    Write-Log "=================================================="
    
    # Check administrator privileges
    if (!(Test-Administrator)) {
        Write-ErrorLog "This script must be run as Administrator"
        Write-Log "Please right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    
    # Check if installed
    $registryPath = "HKLM:\SOFTWARE\GEEKS\CredentialProvider"
    if (!(Test-Path $registryPath) -and !$Force) {
        Write-Log "GEEKS Credential Provider does not appear to be installed"
        $response = Read-Host "Do you want to continue with cleanup anyway? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Log "Uninstallation cancelled by user"
            exit 0
        }
    }
    
    # Confirm uninstallation
    if (!$Force) {
        Write-Log "This will remove the GEEKS Credential Provider from this computer."
        $response = Read-Host "Are you sure you want to continue? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Log "Uninstallation cancelled by user"
            exit 0
        }
    }
    
    # Perform uninstallation
    $success = Uninstall-CredentialProvider
    
    if ($success) {
        Write-Log "Uninstallation completed successfully!"
        Write-Log "The credential provider has been removed from this computer"
    } else {
        Write-ErrorLog "Uninstallation failed"
        exit 1
    }
    
} catch {
    Write-ErrorLog "Unexpected error during uninstallation" $_.Exception.Message
    exit 1
} 