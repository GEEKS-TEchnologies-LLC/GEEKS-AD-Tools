# GEEKS Credential Provider Installation Script
# Run as Administrator

param(
    [string]$PortalURL = "http://localhost:5000/reset-password",
    [switch]$Force,
    [switch]$Debug
)

# Script information
$ScriptName = "GEEKS-CredentialProvider-Install"
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 1000 -EntryType Information -Message $LogMessage -ErrorAction SilentlyContinue
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 1001 -EntryType Error -Message $LogMessage -ErrorAction SilentlyContinue
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check system requirements
function Test-SystemRequirements {
    Write-Log "Checking system requirements..."
    
    # Check Windows version
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [System.Version]$osInfo.Version
    
    if ($osVersion.Major -lt 10) {
        Write-ErrorLog "Windows 10 or later is required. Current version: $($osInfo.Caption)"
        return $false
    }
    
    Write-Log "Windows version: $($osInfo.Caption) - OK"
    
    # Check if domain joined
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        Write-Log "Domain joined: $($computerSystem.Domain) - OK"
    } else {
        Write-Log "Warning: Computer is not domain joined"
    }
    
    return $true
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

# Main installation function
function Install-CredentialProvider {
    param(
        [string]$PortalURL,
        [bool]$Debug
    )
    
    Write-Log "Starting GEEKS Credential Provider installation..."
    Write-Log "Portal URL: $PortalURL"
    Write-Log "Debug mode: $Debug"
    
    $scriptDir = Get-ScriptDirectory
    $dllPath = Join-Path $scriptDir "GEEKS-CredentialProvider.dll"
    
    # Check if DLL exists
    if (!(Test-Path $dllPath)) {
        Write-ErrorLog "Credential provider DLL not found: $dllPath"
        Write-Log "Please ensure the DLL is built and available in the script directory"
        return $false
    }
    
    try {
        # Register the DLL
        Write-Log "Registering credential provider DLL..."
        $result = & regsvr32.exe /s $dllPath
        if ($LASTEXITCODE -ne 0) {
            Write-ErrorLog "Failed to register DLL with regsvr32"
            return $false
        }
        Write-Log "DLL registered successfully"
        
        # Configure registry settings
        Write-Log "Configuring registry settings..."
        $registryPath = "HKLM:\SOFTWARE\GEEKS\CredentialProvider"
        
        # Create registry key if it doesn't exist
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Set configuration values
        Set-ItemProperty -Path $registryPath -Name "PortalURL" -Value $PortalURL -Type String
        Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $registryPath -Name "Debug" -Value ([int]$Debug) -Type DWord
        
        Write-Log "Registry configuration completed"
        
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
        
        # Test portal connectivity
        Write-Log "Testing portal connectivity..."
        try {
            $response = Invoke-WebRequest -Uri $PortalURL -Method Head -TimeoutSec 10 -ErrorAction Stop
            Write-Log "Portal connectivity test: SUCCESS (Status: $($response.StatusCode))"
        } catch {
            Write-ErrorLog "Portal connectivity test failed" $_.Exception.Message
            Write-Log "Warning: Portal may not be accessible. Please verify the URL and network connectivity."
        }
        
        Write-Log "GEEKS Credential Provider installation completed successfully"
        return $true
        
    } catch {
        Write-ErrorLog "Installation failed" $_.Exception.Message
        return $false
    }
}

# Main execution
try {
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider Installer v$ScriptVersion"
    Write-Log "================================================"
    
    # Check administrator privileges
    if (!(Test-Administrator)) {
        Write-ErrorLog "This script must be run as Administrator"
        Write-Log "Please right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    
    # Check system requirements
    if (!(Test-SystemRequirements)) {
        Write-ErrorLog "System requirements not met"
        exit 1
    }
    
    # Check if already installed
    $registryPath = "HKLM:\SOFTWARE\GEEKS\CredentialProvider"
    if ((Test-Path $registryPath) -and !$Force) {
        Write-Log "GEEKS Credential Provider appears to be already installed"
        $response = Read-Host "Do you want to reinstall? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Log "Installation cancelled by user"
            exit 0
        }
    }
    
    # Perform installation
    $success = Install-CredentialProvider -PortalURL $PortalURL -Debug $Debug
    
    if ($success) {
        Write-Log "Installation completed successfully!"
        Write-Log "The credential provider will be available after the next logon or system restart"
        Write-Log "To test immediately, lock the workstation and look for the 'Forgot Password?' option"
    } else {
        Write-ErrorLog "Installation failed"
        exit 1
    }
    
} catch {
    Write-ErrorLog "Unexpected error during installation" $_.Exception.Message
    exit 1
} 