# GEEKS Credential Provider Group Policy Deployment Script
# Run as Administrator on Domain Controller

param(
    [Parameter(Mandatory=$true)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$true)]
    [string]$GPO,
    
    [string]$PortalURL = "http://localhost:5000/reset-password",
    [string]$SourcePath = "\\$DomainController\SYSVOL\$env:USERDNSDOMAIN\Policies\GEEKS-CredentialProvider",
    [switch]$Force,
    [switch]$Debug
)

# Script information
$ScriptName = "GEEKS-CredentialProvider-GPO"
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 3000 -EntryType Information -Message $LogMessage -ErrorAction SilentlyContinue
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 3001 -EntryType Error -Message $LogMessage -ErrorAction SilentlyContinue
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if Group Policy Management is available
function Test-GPOModule {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        return $true
    } catch {
        Write-ErrorLog "Group Policy module not available. Please install Group Policy Management Tools."
        return $false
    }
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

# Create GPO deployment
function New-GPODployment {
    param(
        [string]$GPO,
        [string]$PortalURL,
        [string]$SourcePath,
        [bool]$Debug
    )
    
    Write-Log "Creating GPO deployment for: $GPO"
    Write-Log "Portal URL: $PortalURL"
    Write-Log "Source Path: $SourcePath"
    
    try {
        # Check if GPO exists
        $existingGPO = Get-GPO -Name $GPO -ErrorAction SilentlyContinue
        if ($existingGPO -and !$Force) {
            Write-Log "GPO '$GPO' already exists"
            $response = Read-Host "Do you want to update the existing GPO? (y/N)"
            if ($response -ne "y" -and $response -ne "Y") {
                Write-Log "GPO deployment cancelled by user"
                return $false
            }
        }
        
        # Create or update GPO
        if (!$existingGPO) {
            Write-Log "Creating new GPO: $GPO"
            New-GPO -Name $GPO -Comment "GEEKS Credential Provider Deployment"
        } else {
            Write-Log "Updating existing GPO: $GPO"
        }
        
        # Create source directory structure
        $scriptDir = Get-ScriptDirectory
        $gpoScriptsPath = Join-Path $SourcePath "Scripts"
        $gpoFilesPath = Join-Path $SourcePath "Files"
        
        if (!(Test-Path $gpoScriptsPath)) {
            New-Item -Path $gpoScriptsPath -ItemType Directory -Force | Out-Null
        }
        if (!(Test-Path $gpoFilesPath)) {
            New-Item -Path $gpoFilesPath -ItemType Directory -Force | Out-Null
        }
        
        # Copy files to GPO share
        Write-Log "Copying files to GPO share..."
        
        # Copy DLL
        $dllSource = Join-Path $scriptDir "GEEKS-CredentialProvider.dll"
        $dllDest = Join-Path $gpoFilesPath "GEEKS-CredentialProvider.dll"
        if (Test-Path $dllSource) {
            Copy-Item -Path $dllSource -Destination $dllDest -Force
            Write-Log "DLL copied to GPO share"
        } else {
            Write-ErrorLog "DLL not found: $dllSource"
            return $false
        }
        
        # Create installation script for GPO
        $installScript = @"
# GEEKS Credential Provider GPO Installation Script
# This script is deployed via Group Policy

param(
    [string]`$PortalURL = "$PortalURL"
)

# Script information
`$ScriptName = "GEEKS-CredentialProvider-GPO"
`$ScriptVersion = "1.3.0"

# Logging function
function Write-Log {
    param(
        [string]`$Message,
        [string]`$Level = "INFO"
    )
    
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogMessage = "[`$Timestamp] [`$Level] `$Message"
    
    Write-Host `$LogMessage
    Write-EventLog -LogName Application -Source `$ScriptName -EventId 4000 -EntryType Information -Message `$LogMessage -ErrorAction SilentlyContinue
}

# Error handling function
function Write-ErrorLog {
    param(
        [string]`$Message,
        [string]`$Exception = ""
    )
    
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogMessage = "[`$Timestamp] [ERROR] `$Message"
    if (`$Exception) {
        `$LogMessage += " Exception: `$Exception"
    }
    
    Write-Host `$LogMessage -ForegroundColor Red
    Write-EventLog -LogName Application -Source `$ScriptName -EventId 4001 -EntryType Error -Message `$LogMessage -ErrorAction SilentlyContinue
}

# Create event log source
function New-EventLogSource {
    try {
        if (![System.Diagnostics.EventLog]::SourceExists(`$ScriptName)) {
            New-EventLog -LogName Application -Source `$ScriptName
            Write-Log "Created event log source: `$ScriptName"
        }
    } catch {
        Write-ErrorLog "Failed to create event log source" `$_.Exception.Message
    }
}

# Main installation function
function Install-CredentialProvider {
    param(
        [string]`$PortalURL
    )
    
    Write-Log "Starting GEEKS Credential Provider GPO installation..."
    Write-Log "Portal URL: `$PortalURL"
    
    try {
        # Get script directory (GPO share)
        `$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
        `$dllPath = Join-Path `$scriptDir "GEEKS-CredentialProvider.dll"
        
        # Check if DLL exists
        if (!(Test-Path `$dllPath)) {
            Write-ErrorLog "Credential provider DLL not found: `$dllPath"
            return `$false
        }
        
        # Register the DLL
        Write-Log "Registering credential provider DLL..."
        `$result = & regsvr32.exe /s `$dllPath
        if (`$LASTEXITCODE -ne 0) {
            Write-ErrorLog "Failed to register DLL with regsvr32"
            return `$false
        }
        Write-Log "DLL registered successfully"
        
        # Configure registry settings
        Write-Log "Configuring registry settings..."
        `$registryPath = "HKLM:\SOFTWARE\GEEKS\CredentialProvider"
        
        # Create registry key if it doesn't exist
        if (!(Test-Path `$registryPath)) {
            New-Item -Path `$registryPath -Force | Out-Null
        }
        
        # Set configuration values
        Set-ItemProperty -Path `$registryPath -Name "PortalURL" -Value `$PortalURL -Type String
        Set-ItemProperty -Path `$registryPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path `$registryPath -Name "Debug" -Value 0 -Type DWord
        
        Write-Log "Registry configuration completed"
        
        Write-Log "GEEKS Credential Provider GPO installation completed successfully"
        return `$true
        
    } catch {
        Write-ErrorLog "Installation failed" `$_.Exception.Message
        return `$false
    }
}

# Main execution
try {
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider GPO Installer v`$ScriptVersion"
    Write-Log "====================================================="
    
    # Perform installation
    `$success = Install-CredentialProvider -PortalURL `$PortalURL
    
    if (`$success) {
        Write-Log "GPO installation completed successfully!"
    } else {
        Write-ErrorLog "GPO installation failed"
        exit 1
    }
    
} catch {
    Write-ErrorLog "Unexpected error during GPO installation" `$_.Exception.Message
    exit 1
}
"@
        
        $installScriptPath = Join-Path $gpoScriptsPath "Install-GEEKS-CredentialProvider.ps1"
        $installScript | Out-File -FilePath $installScriptPath -Encoding UTF8
        Write-Log "Installation script created: $installScriptPath"
        
        # Configure GPO startup script
        Write-Log "Configuring GPO startup script..."
        Set-GPOStartupScript -Name $GPO -Command "powershell.exe" -Arguments "-ExecutionPolicy Bypass -File `"$installScriptPath`" -PortalURL `"$PortalURL`""
        
        # Configure GPO settings
        Write-Log "Configuring GPO settings..."
        
        # Set PowerShell execution policy
        Set-GPRegistryValue -Name $GPO -Key "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -ValueName "ExecutionPolicy" -Type String -Value "RemoteSigned"
        
        # Configure credential provider settings
        Set-GPRegistryValue -Name $GPO -Key "HKLM\SOFTWARE\GEEKS\CredentialProvider" -ValueName "PortalURL" -Type String -Value $PortalURL
        Set-GPRegistryValue -Name $GPO -Key "HKLM\SOFTWARE\GEEKS\CredentialProvider" -ValueName "Enabled" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPO -Key "HKLM\SOFTWARE\GEEKS\CredentialProvider" -ValueName "Debug" -Type DWord -Value ([int]$Debug)
        
        Write-Log "GPO deployment completed successfully"
        return $true
        
    } catch {
        Write-ErrorLog "GPO deployment failed" $_.Exception.Message
        return $false
    }
}

# Main execution
try {
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider GPO Deployer v$ScriptVersion"
    Write-Log "====================================================="
    
    # Check administrator privileges
    if (!(Test-Administrator)) {
        Write-ErrorLog "This script must be run as Administrator"
        Write-Log "Please right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    
    # Check Group Policy module
    if (!(Test-GPOModule)) {
        Write-ErrorLog "Group Policy Management Tools not available"
        exit 1
    }
    
    # Test domain controller connectivity
    Write-Log "Testing domain controller connectivity..."
    try {
        $dc = Get-ADDomainController -Identity $DomainController -ErrorAction Stop
        Write-Log "Domain controller connectivity: SUCCESS ($($dc.Name))"
    } catch {
        Write-ErrorLog "Failed to connect to domain controller: $DomainController"
        exit 1
    }
    
    # Perform GPO deployment
    $success = New-GPODployment -GPO $GPO -PortalURL $PortalURL -SourcePath $SourcePath -Debug $Debug
    
    if ($success) {
        Write-Log "GPO deployment completed successfully!"
        Write-Log "GPO '$GPO' has been created and configured"
        Write-Log "Link the GPO to target OUs to deploy the credential provider"
        Write-Log "Files are available at: $SourcePath"
    } else {
        Write-ErrorLog "GPO deployment failed"
        exit 1
    }
    
} catch {
    Write-ErrorLog "Unexpected error during GPO deployment" $_.Exception.Message
    exit 1
} 