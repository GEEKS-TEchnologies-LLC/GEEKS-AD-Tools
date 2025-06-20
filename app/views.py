from flask import Blueprint, render_template, redirect, url_for, request, flash
from .ad import (
    save_ad_config, load_ad_config, test_ad_connection,
    get_admin_groups, set_admin_groups, is_user_in_admin_group,
    create_ad_group, add_user_to_group,
    search_users, get_user_details, create_user, delete_user, disable_user, enable_user, reset_user_password, force_password_change,
    get_user_groups, remove_user_from_group,
    get_ad_statistics, get_ad_health_status, authenticate_user
)
from flask import current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import Admin
from . import db
from werkzeug.security import generate_password_hash
from functools import wraps
import os
from .audit import (
    log_login, log_password_reset, log_user_action, log_admin_action, log_system_event,
    get_audit_logs, export_audit_logs_csv, get_audit_stats
)
from .bug_report import generate_bug_report, save_bug_report, get_bug_report_summary

main = Blueprint('main', __name__)

@main.before_app_request
def enforce_setup():
    # Allow access to setup, admin_register, admin_login, welcome, and static files without AD config
    allowed_endpoints = ('main.setup', 'main.admin_register', 'main.admin_login', 'main.welcome', 'main.home', 'static')
    if not load_ad_config() and request.endpoint not in allowed_endpoints:
        return redirect(url_for('main.home'))

@main.route('/')
def home():
    config = load_ad_config()
    if not config:
        return render_template('welcome.html')
    return render_template('home.html', config=config)

@main.route('/welcome')
def welcome():
    return render_template('welcome.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('main.admin_login'))
        # Add more admin checks if needed
        return f(*args, **kwargs)
    return decorated_function

@main.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    # If there's already an admin, redirect to login
    if Admin.query.count() > 0:
        flash('Admin registration is disabled. Please log in.', 'info')
        return redirect(url_for('main.admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin(username=username)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        flash('Admin registered. Please log in.', 'success')
        return redirect(url_for('main.admin_login'))
    return render_template('admin_register.html')

@main.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Try local admin login first
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            log_login(username, 'success', {'method': 'local'})
            flash('Logged in as local admin.', 'success')
            return redirect(url_for('main.home'))
        # Try AD admin login if AD is configured
        config = load_ad_config()
        if config:
            # Authenticate with AD using the new robust function
            ok, msg = authenticate_user(username, password)

            if ok:
                # Check if user is in an admin group
                if is_user_in_admin_group(username, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'], config['ad_base_dn']):
                    # Create or update AD admin record
                    admin = Admin.query.filter_by(username=username).first()
                    if not admin:
                        admin = Admin(username=username)
                        admin.password_hash = ''  # No local password
                        db.session.add(admin)
                    # Optionally, set a flag for AD-based admin
                    # admin.is_ad_admin = True
                    db.session.commit()
                    login_user(admin)
                    log_login(username, 'success', {'method': 'ad'})
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('main.admin_dashboard'))
                else:
                    log_login(username, 'failure', {'reason': 'not_in_admin_group'})
                    flash('User is not in an admin group.', 'danger')
            else:
                log_login(username, 'failure', {'reason': 'invalid_credentials'})
                flash(msg, 'danger')
        else:
            log_login(username, 'failure', {'reason': 'invalid_credentials'})
            flash('Invalid credentials.', 'danger')
    return render_template('admin_login.html')

@main.route('/admin/logout')
@login_required
def admin_logout():
    if current_user.is_authenticated:
        log_login(current_user.username, 'success', {'action': 'logout'})
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('main.home'))

@main.route('/setup', methods=['GET', 'POST'])
def setup():
    config = load_ad_config()
    if config and not current_user.is_authenticated:
        flash('You must be an administrator to change the configuration.', 'danger')
        return redirect(url_for('main.admin_login'))

    if request.method == 'POST':
        config_data = {
            'ad_server': request.form['ad_server'],
            'ad_port': request.form['ad_port'],
            'ad_bind_dn': request.form['ad_bind_dn'],
            'ad_password': request.form['ad_password'],
            'ad_base_dn': request.form['ad_base_dn'],
            'users_ou': request.form.get('users_ou'),
            'groups_ou': request.form.get('groups_ou')
        }
        save_ad_config(config_data)
        ok, msg = test_ad_connection(
            config_data['ad_server'],
            config_data['ad_port'],
            config_data['ad_bind_dn'],
            config_data['ad_password']
        )
        if ok:
            flash('Setup saved and AD connection successful!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash(f'AD connection failed: {msg}', 'danger')
    
    config = load_ad_config()
    return render_template('setup.html', config=config)

@main.route('/ad_test', methods=['POST'])
def ad_test():
    config = load_ad_config()
    if not config:
        return {'status': 'error', 'message': 'Not configured'}, 400
    ok, msg = test_ad_connection(
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password']
    )
    if ok:
        return {'status': 'success', 'message': msg}
    else:
        return {'status': 'error', 'message': msg}, 400

@main.route('/reset', methods=['GET', 'POST'])
def reset():
    return render_template('reset.html')

@main.route('/admin/groups', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_groups():
    groups = get_admin_groups()
    if request.method == 'POST':
        new_group = request.form.get('new_group')
        if new_group and new_group not in groups:
            groups.append(new_group)
            set_admin_groups(groups)
            flash(f'Added admin group: {new_group}', 'success')
        remove_group = request.form.get('remove_group')
        if remove_group and remove_group in groups:
            groups.remove(remove_group)
            set_admin_groups(groups)
            flash(f'Removed admin group: {remove_group}', 'info')
    return render_template('admin_groups.html', groups=groups)

@main.route('/admin/create_group', methods=['POST'])
@login_required
@admin_required
def create_group():
    group_name = request.form['group_name']
    config = load_ad_config()
    ok, msg = create_ad_group(
        group_name,
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password'],
        config['ad_base_dn']
    )
    if ok:
        flash(msg, 'success')
    else:
        flash(msg, 'danger')
    return redirect(url_for('main.admin_groups'))

@main.route('/admin/add_user_to_group', methods=['POST'])
@login_required
@admin_required
def add_user_to_group_route():
    user_dn = request.form['user_dn']
    group_name = request.form['group_name']
    config = load_ad_config()
    ok, msg = add_user_to_group(
        user_dn,
        group_name,
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password'],
        config['ad_base_dn']
    )
    if ok:
        flash(msg, 'success')
    else:
        flash(msg, 'danger')
    return redirect(url_for('main.admin_groups'))

@main.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Example: Read last 20 log lines
    log_path = 'app/logs/app.log'
    logs = []
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = f.readlines()[-20:]
    
    # Get audit statistics
    audit_stats = get_audit_stats(days=30)
    
    # Get AD statistics if configured
    ad_stats = None
    ad_health = None
    config = load_ad_config()
    if config:
        ok, stats = get_ad_statistics(
            config['ad_server'],
            config['ad_port'],
            config['ad_bind_dn'],
            config['ad_password'],
            config['ad_base_dn']
        )
        if ok:
            ad_stats = stats
        
        # Get AD health status
        ok, health = get_ad_health_status(
            config['ad_server'],
            config['ad_port'],
            config['ad_bind_dn'],
            config['ad_password'],
            config['ad_base_dn']
        )
        if ok:
            ad_health = health
    
    # Example: System status (placeholder)
    status = {
        'AD Configured': bool(config),
        'Admin Groups': get_admin_groups(),
    }
    return render_template('admin_dashboard.html', logs=logs, status=status, audit_stats=audit_stats, ad_stats=ad_stats, ad_health=ad_health)

@main.route('/admin/ad-dashboard')
@login_required
@admin_required
def ad_dashboard():
    """Detailed AD dashboard with charts and statistics"""
    config = load_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    # Get AD statistics
    ok, stats = get_ad_statistics(
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password'],
        config['ad_base_dn']
    )
    
    if not ok:
        flash(f'Failed to get AD statistics: {stats}', 'danger')
        stats = None
    
    # Get AD health status
    ok, health = get_ad_health_status(
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password'],
        config['ad_base_dn']
    )
    
    if not ok:
        flash(f'Failed to get AD health status: {health}', 'danger')
        health = None
    
    return render_template('ad_dashboard.html', ad_stats=stats, ad_health=health)

@main.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def user_search():
    users = []
    query = ''
    if request.method == 'POST':
        query = request.form['query']
        config = load_ad_config()
        users = search_users(query, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'], config['ad_base_dn'])
    return render_template('user_search.html', users=users, query=query)

@main.route('/admin/user/<path:user_dn>', methods=['GET', 'POST'])
@login_required
@admin_required
def user_details(user_dn):
    config = load_ad_config()
    details = get_user_details(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
    groups = get_user_groups(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
    msg = None
    if request.method == 'POST':
        action = request.form['action']
        username = details.get('sAMAccountName', ['Unknown'])[0] if details else 'Unknown'
        
        if action == 'delete':
            ok, msg = delete_user(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
            log_user_action('delete', username, 'success' if ok else 'failure', {'user_dn': user_dn})
        elif action == 'disable':
            ok, msg = disable_user(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
            log_user_action('disable', username, 'success' if ok else 'failure', {'user_dn': user_dn})
        elif action == 'enable':
            ok, msg = enable_user(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
            log_user_action('enable', username, 'success' if ok else 'failure', {'user_dn': user_dn})
        elif action == 'reset_password':
            new_pw = request.form['new_password']
            ok, msg = reset_user_password(user_dn, new_pw, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
            log_user_action('reset_password', username, 'success' if ok else 'failure', {'user_dn': user_dn})
        elif action == 'force_pw_change':
            ok, msg = force_password_change(user_dn, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'])
            log_user_action('force_pw_change', username, 'success' if ok else 'failure', {'user_dn': user_dn})
        elif action == 'add_group':
            group_name = request.form['group_name']
            ok, msg = add_user_to_group(user_dn, group_name, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'], config['ad_base_dn'])
            log_user_action('add_group', username, 'success' if ok else 'failure', {'user_dn': user_dn, 'group': group_name})
        elif action == 'remove_group':
            group_name = request.form['group_name']
            ok, msg = remove_user_from_group(user_dn, group_name, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'], config['ad_base_dn'])
            log_user_action('remove_group', username, 'success' if ok else 'failure', {'user_dn': user_dn, 'group': group_name})
        
        if ok:
            flash(msg, 'success')
        else:
            flash(msg, 'danger')
        return redirect(url_for('main.user_details', user_dn=user_dn))
    return render_template('user_details.html', details=details, user_dn=user_dn, msg=msg, groups=groups)

@main.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user_route():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        display_name = request.form['display_name']
        mail = request.form['mail']
        config = load_ad_config()
        ok, msg = create_user(username, password, display_name, mail, config['ad_server'], config['ad_port'], config['ad_bind_dn'], config['ad_password'], config['ad_base_dn'])
        log_user_action('create', username, 'success' if ok else 'failure', {'display_name': display_name, 'mail': mail})
        if ok:
            flash(msg, 'success')
            return redirect(url_for('main.user_search'))
        else:
            flash(msg, 'danger')
    return render_template('create_user.html')

@main.route('/admin/gpo-deployment')
@login_required
@admin_required
def gpo_deployment():
    return render_template('gpo_deployment.html')

@main.route('/admin/generate-gpo-script', methods=['POST'])
@login_required
@admin_required
def generate_gpo_script():
    domain_controller = request.form.get('domain_controller', '')
    gpo_name = request.form.get('gpo_name', 'GEEKS-CredentialProvider')
    portal_url = request.form.get('portal_url', 'http://localhost:5000/reset-password')
    
    if not domain_controller:
        flash('Domain Controller is required', 'danger')
        return redirect(url_for('main.gpo_deployment'))
    
    # Generate the GPO deployment script
    script_content = f'''# GEEKS Credential Provider Group Policy Deployment Script
# Generated by GEEKS-AD-Plus Admin Portal
# Run as Administrator on Domain Controller

param(
    [Parameter(Mandatory=$true)]
    [string]$DomainController = "{domain_controller}",
    
    [Parameter(Mandatory=$true)]
    [string]$GPO = "{gpo_name}",
    
    [string]$PortalURL = "{portal_url}",
    [string]$SourcePath = "\\\\$DomainController\\SYSVOL\\$env:USERDNSDOMAIN\\Policies\\GEEKS-CredentialProvider",
    [switch]$Force,
    [switch]$Debug
)

# Script information
$ScriptName = "GEEKS-CredentialProvider-GPO"
$ScriptVersion = "1.3.0"

# Logging function
function Write-Log {{
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogMessage
    Write-EventLog -LogName Application -Source $ScriptName -EventId 3000 -EntryType Information -Message $LogMessage -ErrorAction SilentlyContinue
}}

# Error handling function
function Write-ErrorLog {{
    param(
        [string]$Message,
        [string]$Exception = ""
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [ERROR] $Message"
    if ($Exception) {{
        $LogMessage += " Exception: $Exception"
    }}
    
    Write-Host $LogMessage -ForegroundColor Red
    Write-EventLog -LogName Application -Source $ScriptName -EventId 3001 -EntryType Error -Message $LogMessage -ErrorAction SilentlyContinue
}}

# Check if running as Administrator
function Test-Administrator {{
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}}

# Check if Group Policy Management is available
function Test-GPOModule {{
    try {{
        Import-Module GroupPolicy -ErrorAction Stop
        return $true
    }} catch {{
        Write-ErrorLog "Group Policy module not available. Please install Group Policy Management Tools."
        return $false
    }}
}}

# Create event log source
function New-EventLogSource {{
    try {{
        if (![System.Diagnostics.EventLog]::SourceExists($ScriptName)) {{
            New-EventLog -LogName Application -Source $ScriptName
            Write-Log "Created event log source: $ScriptName"
        }}
    }} catch {{
        Write-ErrorLog "Failed to create event log source" $_.Exception.Message
    }}
}}

# Get script directory
function Get-ScriptDirectory {{
    return Split-Path -Parent $MyInvocation.MyCommand.Path
}}

# Create GPO deployment
function New-GPODployment {{
    param(
        [string]$GPO,
        [string]$PortalURL,
        [string]$SourcePath,
        [bool]$Debug
    )
    
    Write-Log "Creating GPO deployment for: $GPO"
    Write-Log "Portal URL: $PortalURL"
    Write-Log "Source Path: $SourcePath"
    
    try {{
        # Check if GPO exists
        $existingGPO = Get-GPO -Name $GPO -ErrorAction SilentlyContinue
        if ($existingGPO -and !$Force) {{
            Write-Log "GPO '$GPO' already exists"
            $response = Read-Host "Do you want to update the existing GPO? (y/N)"
            if ($response -ne "y" -and $response -ne "Y") {{
                Write-Log "GPO deployment cancelled by user"
                return $false
            }}
        }}
        
        # Create or update GPO
        if (!$existingGPO) {{
            Write-Log "Creating new GPO: $GPO"
            New-GPO -Name $GPO -Comment "GEEKS Credential Provider Deployment"
        }} else {{
            Write-Log "Updating existing GPO: $GPO"
        }}
        
        # Create source directory structure
        $scriptDir = Get-ScriptDirectory
        $gpoScriptsPath = Join-Path $SourcePath "Scripts"
        $gpoFilesPath = Join-Path $SourcePath "Files"
        
        if (!(Test-Path $gpoScriptsPath)) {{
            New-Item -Path $gpoScriptsPath -ItemType Directory -Force | Out-Null
        }}
        if (!(Test-Path $gpoFilesPath)) {{
            New-Item -Path $gpoFilesPath -ItemType Directory -Force | Out-Null
        }}
        
        # Copy files to GPO share
        Write-Log "Copying files to GPO share..."
        
        # Copy DLL
        $dllSource = Join-Path $scriptDir "GEEKS-CredentialProvider.dll"
        $dllDest = Join-Path $gpoFilesPath "GEEKS-CredentialProvider.dll"
        if (Test-Path $dllSource) {{
            Copy-Item -Path $dllSource -Destination $dllDest -Force
            Write-Log "DLL copied to GPO share"
        }} else {{
            Write-ErrorLog "DLL not found: $dllSource"
            return $false
        }}
        
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
function Write-Log {{
    param(
        [string]`$Message,
        [string]`$Level = "INFO"
    )
    
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogMessage = "[`$Timestamp] [`$Level] `$Message"
    
    Write-Host `$LogMessage
    Write-EventLog -LogName Application -Source `$ScriptName -EventId 4000 -EntryType Information -Message `$LogMessage -ErrorAction SilentlyContinue
}}

# Error handling function
function Write-ErrorLog {{
    param(
        [string]`$Message,
        [string]`$Exception = ""
    )
    
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogMessage = "[`$Timestamp] [ERROR] `$Message"
    if (`$Exception) {{
        `$LogMessage += " Exception: `$Exception"
    }}
    
    Write-Host `$LogMessage -ForegroundColor Red
    Write-EventLog -LogName Application -Source `$ScriptName -EventId 4001 -EntryType Error -Message `$LogMessage -ErrorAction SilentlyContinue
}}

# Create event log source
function New-EventLogSource {{
    try {{
        if (![System.Diagnostics.EventLog]::SourceExists(`$ScriptName)) {{
            New-EventLog -LogName Application -Source `$ScriptName
            Write-Log "Created event log source: `$ScriptName"
        }}
    }} catch {{
        Write-ErrorLog "Failed to create event log source" `$_.Exception.Message
    }}
}}

# Main installation function
function Install-CredentialProvider {{
    param(
        [string]`$PortalURL
    )
    
    Write-Log "Starting GEEKS Credential Provider GPO installation..."
    Write-Log "Portal URL: `$PortalURL"
    
    try {{
        # Get script directory (GPO share)
        `$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
        `$dllPath = Join-Path `$scriptDir "GEEKS-CredentialProvider.dll"
        
        # Check if DLL exists
        if (!(Test-Path `$dllPath)) {{
            Write-ErrorLog "Credential provider DLL not found: `$dllPath"
            return `$false
        }}
        
        # Register the DLL
        Write-Log "Registering credential provider DLL..."
        `$result = & regsvr32.exe /s `$dllPath
        if (`$LASTEXITCODE -ne 0) {{
            Write-ErrorLog "Failed to register DLL with regsvr32"
            return `$false
        }}
        Write-Log "DLL registered successfully"
        
        # Configure registry settings
        Write-Log "Configuring registry settings..."
        `$registryPath = "HKLM:\\SOFTWARE\\GEEKS\\CredentialProvider"
        
        # Create registry key if it doesn't exist
        if (!(Test-Path `$registryPath)) {{
            New-Item -Path `$registryPath -Force | Out-Null
        }}
        
        # Set configuration values
        Set-ItemProperty -Path `$registryPath -Name "PortalURL" -Value `$PortalURL -Type String
        Set-ItemProperty -Path `$registryPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path `$registryPath -Name "Debug" -Value 0 -Type DWord
        
        Write-Log "Registry configuration completed"
        
        Write-Log "GEEKS Credential Provider GPO installation completed successfully"
        return `$true
        
    }} catch {{
        Write-ErrorLog "Installation failed" `$_.Exception.Message
        return `$false
    }}
}}

# Main execution
try {{
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider GPO Installer v`$ScriptVersion"
    Write-Log "====================================================="
    
    # Perform installation
    `$success = Install-CredentialProvider -PortalURL `$PortalURL
    
    if (`$success) {{
        Write-Log "GPO installation completed successfully!"
    }} else {{
        Write-ErrorLog "GPO installation failed"
        exit 1
    }}
    
}} catch {{
    Write-ErrorLog "Unexpected error during GPO installation" `$_.Exception.Message
    exit 1
}}
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
        Set-GPRegistryValue -Name $GPO -Key "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell" -ValueName "ExecutionPolicy" -Type String -Value "RemoteSigned"
        
        # Configure credential provider settings
        Set-GPRegistryValue -Name $GPO -Key "HKLM\\SOFTWARE\\GEEKS\\CredentialProvider" -ValueName "PortalURL" -Type String -Value $PortalURL
        Set-GPRegistryValue -Name $GPO -Key "HKLM\\SOFTWARE\\GEEKS\\CredentialProvider" -ValueName "Enabled" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPO -Key "HKLM\\SOFTWARE\\GEEKS\\CredentialProvider" -ValueName "Debug" -Type DWord -Value ([int]$Debug)
        
        Write-Log "GPO deployment completed successfully"
        return $true
        
    }} catch {{
        Write-ErrorLog "GPO deployment failed" $_.Exception.Message
        return $false
    }}
}}

# Main execution
try {{
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider GPO Deployer v$ScriptVersion"
    Write-Log "====================================================="
    
    # Check administrator privileges
    if (!(Test-Administrator)) {{
        Write-ErrorLog "This script must be run as Administrator"
        Write-Log "Please right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }}
    
    # Check Group Policy module
    if (!(Test-GPOModule)) {{
        Write-ErrorLog "Group Policy Management Tools not available"
        exit 1
    }}
    
    # Test domain controller connectivity
    Write-Log "Testing domain controller connectivity..."
    try {{
        $dc = Get-ADDomainController -Identity $DomainController -ErrorAction Stop
        Write-Log "Domain controller connectivity: SUCCESS ($($dc.Name))"
    }} catch {{
        Write-ErrorLog "Failed to connect to domain controller: $DomainController"
        exit 1
    }}
    
    # Perform GPO deployment
    $success = New-GPODployment -GPO $GPO -PortalURL $PortalURL -SourcePath $SourcePath -Debug $Debug
    
    if ($success) {{
        Write-Log "GPO deployment completed successfully!"
        Write-Log "GPO '$GPO' has been created and configured"
        Write-Log "Link the GPO to target OUs to deploy the credential provider"
        Write-Log "Files are available at: $SourcePath"
    }} else {{
        Write-ErrorLog "GPO deployment failed"
        exit 1
    }}
    
}} catch {{
    Write-ErrorLog "Unexpected error during GPO deployment" $_.Exception.Message
    exit 1
}}
'''
    
    # Log the GPO script generation
    log_admin_action('gpo_script_generated', 'success', {
        'domain_controller': domain_controller,
        'gpo_name': gpo_name,
        'portal_url': portal_url
    })
    
    # Return the script as a downloadable file
    from flask import Response
    return Response(
        script_content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="GEEKS-CredentialProvider-GPO-Deploy.ps1"'}
    )

@main.route('/admin/audit', methods=['GET', 'POST'])
@login_required
@admin_required
def audit_logs():
    if request.method == 'POST':
        # Handle export request
        if 'export' in request.form:
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            user = request.form.get('user')
            action = request.form.get('action')
            result = request.form.get('result')
            
            # Convert date strings to datetime objects
            from datetime import datetime
            start_dt = datetime.strptime(start_date, '%Y-%m-%d') if start_date else None
            end_dt = datetime.strptime(end_date, '%Y-%m-%d') if end_date else None
            
            csv_data = export_audit_logs_csv(start_dt, end_dt, user, action, result)
            from flask import Response
            return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'})
    
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user = request.args.get('user')
    action = request.args.get('action')
    result = request.args.get('result')
    
    # Convert date strings to datetime objects
    from datetime import datetime
    start_dt = datetime.strptime(start_date, '%Y-%m-%d') if start_date else None
    end_dt = datetime.strptime(end_date, '%Y-%m-%d') if end_date else None
    
    # Get filtered logs
    logs = get_audit_logs(start_dt, end_dt, user, action, result, limit=100)
    
    return render_template('audit_logs.html', logs=logs, 
                         start_date=start_date, end_date=end_date, 
                         user=user, action=action, result=result)

@main.route('/bug-report', methods=['GET', 'POST'])
def bug_report():
    if request.method == 'POST':
        description = request.form.get('description', '')
        user_email = request.form.get('email', '')
        include_logs = 'include_logs' in request.form
        include_config = 'include_config' in request.form
        
        if description:
            report = generate_bug_report(description, user_email, include_logs, include_config)
            filename = save_bug_report(report)
            
            if filename:
                flash('Bug report submitted successfully!', 'success')
                # Log the bug report submission
                log_admin_action('bug_report_submitted', 'success', {'filename': filename, 'description': description[:100]})
            else:
                flash('Failed to save bug report.', 'danger')
                log_admin_action('bug_report_submitted', 'failure', {'description': description[:100]})
        else:
            flash('Please provide a description of the issue.', 'danger')
    
    return render_template('bug_report.html')

@main.route('/admin/bug-reports')
@login_required
@admin_required
def view_bug_reports():
    reports = get_bug_report_summary()
    return render_template('bug_reports.html', reports=reports)

@main.route('/admin/bug-report/<filename>')
@login_required
@admin_required
def view_bug_report(filename):
    import json
    try:
        with open(f'bug_reports/{filename}', 'r') as f:
            report = json.load(f)
        return render_template('bug_report_detail.html', report=report, filename=filename)
    except Exception as e:
        flash(f'Error reading bug report: {e}', 'danger')
        return redirect(url_for('main.view_bug_reports'))

@main.route('/admin/bug-report/<filename>/download')
@login_required
@admin_required
def download_bug_report(filename):
    import json
    try:
        with open(f'bug_reports/{filename}', 'r') as f:
            report = json.load(f)
        
        from flask import Response
        return Response(
            json.dumps(report, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        flash(f'Error downloading bug report: {e}', 'danger')
        return redirect(url_for('main.view_bug_reports'))

@main.route('/reset-config', methods=['POST'])
def reset_config():
    """Reset AD configuration (for troubleshooting)"""
    try:
        import os
        config_file = 'app/ad_config.json'
        if os.path.exists(config_file):
            os.remove(config_file)
        flash('AD configuration has been reset. Please reconfigure.', 'info')
    except Exception as e:
        flash(f'Error resetting configuration: {e}', 'danger')
    return redirect(url_for('main.welcome')) 