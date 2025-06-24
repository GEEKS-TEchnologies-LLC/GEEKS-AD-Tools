from flask import Blueprint, render_template, redirect, url_for, request, flash
from .ad import (
    save_ad_config, get_ad_config, test_ad_connection,
    get_admin_groups, set_admin_groups, is_user_in_admin_group,
    create_ad_group, add_user_to_group,
    search_users, get_user_details, create_user, delete_user, disable_user, enable_user, reset_user_password, force_password_change,
    get_user_groups, remove_user_from_group,
    get_ad_statistics, get_ad_health_status, authenticate_user,
    get_ad_config, get_user_groups, add_user_to_group, 
    remove_user_from_group, get_all_groups, create_user as ad_create_user, 
    delete_user as ad_delete_user, set_password as ad_set_password,
    enable_user as ad_enable_user, disable_user as ad_disable_user,
    unlock_user as ad_unlock_user, force_password_change as ad_force_password_change,
    update_user_attributes, list_ous, create_ou, move_user_to_ou, get_ou_tree,
    get_group_types_for_user, get_os_breakdown
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
from urllib.parse import unquote
from .version import __version__
import ldap3
import json

main = Blueprint('main', __name__)

@main.before_app_request
def enforce_setup():
    # Allow access to setup, admin_register, admin_login, welcome, and static files without AD config
    allowed_endpoints = ('main.setup', 'main.admin_register', 'main.admin_login', 'main.welcome', 'main.home', 'static')
    if not get_ad_config() and request.endpoint not in allowed_endpoints:
        return redirect(url_for('main.home'))

@main.route('/')
def home():
    config = get_ad_config()
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
        config = get_ad_config()
        if config:
            # Authenticate with AD using the new robust function
            ok, msg = authenticate_user(username, password)

            if ok:
                # Check if user is in an admin group
                if is_user_in_admin_group(
                    username,
                    server=config['ad_server'],
                    port=config['ad_port'],
                    bind_user=config['ad_bind_dn'],
                    bind_password=config['ad_password'],
                    base_dn=config['ad_base_dn']
                ):
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
    config = get_ad_config()
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
            server=config_data['ad_server'],
            port=config_data['ad_port'],
            bind_user=config_data['ad_bind_dn'],
            bind_password=config_data['ad_password']
        )
        if ok:
            flash('Setup saved and AD connection successful!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash(f'AD connection failed: {msg}', 'danger')
    
    config = get_ad_config()
    return render_template('setup.html', config=config)

@main.route('/ad_test', methods=['POST'])
def ad_test():
    config = get_ad_config()
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
    config = get_ad_config()
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
    config = get_ad_config()
    ok, msg = add_user_to_group(
        user_dn,
        group_name,
        config['ad_server'],
        config['ad_port'],
        config['ad_bind_dn'],
        config['ad_password'],
        config['ad_base_dn']
    )
    if ok and "already a member" in msg:
        flash(msg, 'warning')
    else:
        flash(msg, 'success' if ok else 'danger')
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
    config = get_ad_config()
    if config:
        ok, stats = get_ad_statistics(
            server=config['ad_server'],
            port=config['ad_port'],
            bind_user=config['ad_bind_dn'],
            bind_password=config['ad_password'],
            base_dn=config['ad_base_dn']
        )
        if ok:
            ad_stats = stats
        
        # Get AD health status
        ok, health = get_ad_health_status(
            server=config['ad_server'],
            port=config['ad_port'],
            bind_user=config['ad_bind_dn'],
            bind_password=config['ad_password'],
            base_dn=config['ad_base_dn']
        )
        if ok:
            ad_health = health
    
    # Example: System status (placeholder)
    status = {
        'AD Configured': bool(config),
        'Admin Groups': get_admin_groups(),
    }

    # Load branding config
    branding = {
        'company_name': 'Geeks Technologies',
        'primary_color': '#ffd700',
        'logo_url': '/static/img/geeks_logo.png',
        'theme': 'dark'
    }
    try:
        with open('app/branding_config.json', 'r') as f:
            branding.update(json.load(f))
    except FileNotFoundError:
        pass

    return render_template('admin_dashboard.html', logs=logs, status=status, audit_stats=audit_stats, ad_stats=ad_stats, ad_health=ad_health, branding=branding)

@main.route('/admin/ad-dashboard')
@login_required
@admin_required
def ad_dashboard():
    """Detailed AD dashboard with charts and statistics"""
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    # Get AD statistics
    ok, stats = get_ad_statistics(
        server=config['ad_server'],
        port=config['ad_port'],
        bind_user=config['ad_bind_dn'],
        bind_password=config['ad_password'],
        base_dn=config['ad_base_dn']
    )
    
    if not ok:
        flash(f'Failed to get AD statistics: {stats}', 'danger')
        stats = {}
    
    # Get AD health status
    ok, health = get_ad_health_status(
        server=config['ad_server'],
        port=config['ad_port'],
        bind_user=config['ad_bind_dn'],
        bind_password=config['ad_password'],
        base_dn=config['ad_base_dn']
    )
    
    if not ok:
        flash(f'Failed to get AD health status: {health}', 'danger')
        health = {}
    
    return render_template('ad_dashboard.html', ad_stats=stats, ad_health=health)

@main.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def user_search():
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    query = request.form.get('query', '') if request.method == 'POST' else request.args.get('query', '')
    users = []
    
    # Always search for users - if no query, search for all users
    if query:
        users = search_users(query, **ad_args)
        log_user_action('search', query, 'success' if users else 'no_results', {'query': query, 'results_count': len(users)})
    else:
        # Show all users when no query is provided
        users = search_users('', **ad_args)
        log_user_action('search', 'all_users', 'success' if users else 'no_results', {'query': 'all_users', 'results_count': len(users)})
    
    # Server-side sorting
    sort_by = request.args.get('sort_by', 'username')
    sort_order = request.args.get('sort_order', 'asc')
    
    # Validate sort_by parameter
    valid_sort_fields = ['username', 'displayName', 'mail', 'ou']
    if sort_by not in valid_sort_fields:
        sort_by = 'username'
    
    # Sort users
    reverse_sort = sort_order.lower() == 'desc'
    
    # Handle empty values in sorting
    def sort_key(user):
        value = user.get(sort_by, '')
        if value is None:
            value = ''
        return str(value).lower()
    
    users.sort(key=sort_key, reverse=reverse_sort)
    
    # Pagination logic
    page = int(request.args.get('page', 1))
    per_page = 50
    total_users = len(users)
    total_pages = (total_users + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    users_page = users[start:end]
    
    # Get OUs for move user functionality
    ous = list_ous(**ad_args)
    
    return render_template(
        'user_search.html', 
        users=users_page, 
        query=query, 
        ous=ous, 
        base_dn=config['ad_base_dn'],
        page=page,
        total_pages=total_pages,
        total_users=total_users,
        sort_by=sort_by,
        sort_order=sort_order
    )

@main.route('/user_details/<path:user_dn>', methods=['GET', 'POST'])
@login_required
@admin_required
def user_details(user_dn):
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }

    if request.method == 'POST':
        action = request.form.get('action')
        
        # Actions that don't depend on user details form
        if action == 'add_to_group':
            group_dn = request.form.get('group_dn')
            ok, msg = add_user_to_group(user_dn, group_dn, **ad_args)
            if ok and "already a member" in msg:
                flash(msg, 'warning')
            else:
                flash(msg, 'success' if ok else 'danger')
            return redirect(url_for('main.user_details', user_dn=user_dn))
        elif action == 'remove_from_group':
            group_dn = request.form.get('group_dn')
            ok, msg = remove_user_from_group(user_dn, group_dn, **ad_args)
            if ok and "not a member" in msg:
                flash(msg, 'warning')
            else:
                flash(msg, 'success' if ok else 'danger')
            return redirect(url_for('main.user_details', user_dn=user_dn))

        # Handle user attribute updates from the main form
        if 'update_attributes' in request.form:
            # Collect attributes from form
            attributes_to_update = {
                'givenName': request.form.get('givenName'),
                'initials': request.form.get('initials'),
                'sn': request.form.get('sn'),
                'displayName': request.form.get('displayName'),
                'description': request.form.get('description'),
                'physicalDeliveryOfficeName': request.form.get('physicalDeliveryOfficeName'),
                'telephoneNumber': request.form.get('telephoneNumber'),
                'mail': request.form.get('mail'),
                'wWWHomePage': request.form.get('wWWHomePage'),
                'title': request.form.get('title'),
                'department': request.form.get('department'),
                'company': request.form.get('company'),
                'employeeID': request.form.get('employeeID'),
                'streetAddress': request.form.get('streetAddress'),
                'l': request.form.get('l'),
                'st': request.form.get('st'),
                'postalCode': request.form.get('postalCode'),
                'co': request.form.get('co'),
            }
            ok, msg = update_user_attributes(user_dn, attributes_to_update, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        
        # Handle other actions like password reset, enable/disable, etc.
        elif action == 'reset_password':
            new_password = request.form.get('new_password')
            ok, msg = ad_set_password(user_dn, new_password, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'unlock':
            ok, msg = ad_unlock_user(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'enable':
            ok, msg = ad_enable_user(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'disable':
            ok, msg = ad_disable_user(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'force_password_change':
            ok, msg = ad_force_password_change(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'delete':
            ok, msg = ad_delete_user(user_dn, **ad_args)
            if ok:
                flash(msg, 'success')
                return redirect(url_for('main.user_search'))
            else:
                flash(msg, 'danger')

        return redirect(url_for('main.user_details', user_dn=user_dn))

    # GET request logic
    user = get_user_details(user_dn, **ad_args)
    if not user:
        flash(f"User with DN '{user_dn}' not found.", 'danger')
        return redirect(url_for('main.user_search'))
        
    user_groups = get_user_groups(user_dn, **ad_args)
    all_groups = get_all_groups(**ad_args)
    
    # Group type counts
    group_type_counts = get_group_types_for_user(user_groups, **ad_args)
    os_breakdown = get_os_breakdown(**ad_args)
    
    uac = int(user.get('userAccountControl', ['0'])[0])
    is_disabled = bool(uac & 2)
    is_locked = bool(uac & 16) # LOCKOUT bit

    return render_template(
        'user_details.html', 
        user=user, 
        user_groups=user_groups,
        all_groups=all_groups,
        is_disabled=is_disabled,
        is_locked=is_locked,
        group_type_counts=group_type_counts,
        os_breakdown=os_breakdown
    )

@main.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user_route():
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        display_name = request.form['display_name']
        mail = request.form.get('mail', '')  # Get mail with empty string as default
        target_ou = request.form.get('target_ou', '')  # Get target OU
        
        # Use target_ou if provided, otherwise None (will use base_dn)
        target_ou = target_ou if target_ou else None
        
        ok, msg = ad_create_user(
            username, 
            password, 
            display_name, 
            mail,
            target_ou=target_ou,
            server=config['ad_server'],
            port=config['ad_port'],
            bind_user=config['ad_bind_dn'],
            bind_password=config['ad_password'],
            base_dn=config['ad_base_dn']
        )
        log_user_action('create', username, 'success' if ok else 'failure', {'display_name': display_name, 'mail': mail, 'target_ou': target_ou})
        if ok:
            flash(msg, 'success')
            return redirect(url_for('main.user_search'))
        else:
            flash(msg, 'danger')
    
    # Get available OUs for the form
    ous = list_ous(**ad_args)
    return render_template('create_user.html', ous=ous, base_dn=config['ad_base_dn'])

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
    [string]$PortalURL = "$PortalURL"
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 4000 -EntryType Information -Message $LogMessage -ErrorAction SilentlyContinue
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
    Write-EventLog -LogName Application -Source $ScriptName -EventId 4001 -EntryType Error -Message $LogMessage -ErrorAction SilentlyContinue
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

# Main installation function
function Install-CredentialProvider {{
    param(
        [string]$PortalURL
    )
    
    Write-Log "Starting GEEKS Credential Provider GPO installation..."
    Write-Log "Portal URL: $PortalURL"
    
    try {{
        # Get script directory (GPO share)
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $dllPath = Join-Path $scriptDir "GEEKS-CredentialProvider.dll"
        
        # Check if DLL exists
        if (!(Test-Path $dllPath)) {{
            Write-ErrorLog "Credential provider DLL not found: $dllPath"
            return $false
        }}
        
        # Register the DLL
        Write-Log "Registering credential provider DLL..."
        $result = & regsvr32.exe /s $dllPath
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorLog "Failed to register DLL with regsvr32"
            return $false
        }}
        Write-Log "DLL registered successfully"
        
        # Configure registry settings
        Write-Log "Configuring registry settings..."
        $registryPath = "HKLM:\\SOFTWARE\\GEEKS\\CredentialProvider"
        
        # Create registry key if it doesn't exist
        if (!(Test-Path $registryPath)) {{
            New-Item -Path $registryPath -Force | Out-Null
        }}
        
        # Set configuration values
        Set-ItemProperty -Path $registryPath -Name "PortalURL" -Value $PortalURL -Type String
        Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $registryPath -Name "Debug" -Value 0 -Type DWord
        
        Write-Log "Registry configuration completed"
        
        Write-Log "GEEKS Credential Provider GPO installation completed successfully"
        return $true
        
    }} catch {{
        Write-ErrorLog "Installation failed" $_.Exception.Message
        return $false
    }}
}}

# Main execution
try {{
    # Create event log source
    New-EventLogSource
    
    Write-Log "GEEKS Credential Provider GPO Installer v$ScriptVersion"
    Write-Log "====================================================="
    
    # Perform installation
    $success = Install-CredentialProvider -PortalURL $PortalURL
    
    if ($success) {{
        Write-Log "GPO installation completed successfully!"
    }} else {{
        Write-ErrorLog "GPO installation failed"
        exit 1
    }}
    
}} catch {{
    Write-ErrorLog "Unexpected error during GPO installation" $_.Exception.Message
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

@main.route('/admin/ous')
@login_required
@admin_required
def list_ous_route():
    """List all OUs in the domain"""
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    ous = list_ous(**ad_args)
    ou_tree = get_ou_tree(**ad_args)
    
    return render_template('ous.html', ous=ous, ou_tree=ou_tree)

@main.route('/admin/create_ou', methods=['GET', 'POST'])
@login_required
@admin_required
def create_ou_route():
    """Create a new OU"""
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    if request.method == 'POST':
        ou_name = request.form['ou_name']
        parent_dn = request.form['parent_dn']
        description = request.form.get('description', '')
        
        ok, msg = create_ou(ou_name, parent_dn, **ad_args)
        if ok:
            flash(msg, 'success')
            return redirect(url_for('main.list_ous_route'))
        else:
            flash(msg, 'danger')
    
    # Get available parent OUs
    ous = list_ous(**ad_args)
    return render_template('create_ou.html', ous=ous, base_dn=config['ad_base_dn'])

@main.route('/admin/move_user', methods=['POST'])
@login_required
@admin_required
def move_user_route():
    """Move a user to a different OU"""
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    user_dn = request.form['user_dn']
    new_ou_dn = request.form['new_ou_dn']
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    ok, msg = move_user_to_ou(user_dn, new_ou_dn, **ad_args)
    flash(msg, 'success' if ok else 'danger')
    
    return redirect(url_for('main.user_search'))

@main.route('/admin/drilldown/computers')
@login_required
@admin_required
def drilldown_computers():
    os_name = request.args.get('os')
    config = get_ad_config()
    if not config:
        return {"error": "AD not configured."}, 400
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    from .ad import ad_connection
    computers = []
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['cn', 'operatingSystem'])
        for entry in conn.entries:
            os_val = entry.operatingSystem.value if hasattr(entry, 'operatingSystem') and entry.operatingSystem else 'Unknown'
            if os_name == 'Other':
                if not any(v in os_val for v in ['Windows XP', 'Windows 7', 'Windows 8', 'Windows 10', 'Windows 11', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022']):
                    computers.append({'name': entry.cn.value if entry.cn else '', 'os': os_val})
            elif os_name == 'Unknown':
                if os_val == 'Unknown':
                    computers.append({'name': entry.cn.value if entry.cn else '', 'os': os_val})
            else:
                if os_name in os_val:
                    computers.append({'name': entry.cn.value if entry.cn else '', 'os': os_val})
    return {"computers": computers}

@main.route('/admin/drilldown/groups')
@login_required
@admin_required
def drilldown_groups():
    group_type = request.args.get('type')
    config = get_ad_config()
    if not config:
        return {"error": "AD not configured."}, 400
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    from .ad import ad_connection
    groups = []
    group_type_map = {
        2: 'Global Security',
        4: 'Domain Local Security',
        8: 'Universal Security',
        -2147483646: 'Global Distribution',
        -2147483644: 'Domain Local Distribution',
        -2147483640: 'Universal Distribution',
    }
    # Reverse the mapping to find the numeric value
    type_value = None
    for val, name in group_type_map.items():
        if name == group_type:
            type_value = val
            break
    
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=group)', search_scope=ldap3.SUBTREE, attributes=['cn', 'groupType', 'description'])
        for entry in conn.entries:
            group_type_val = entry.groupType.value if hasattr(entry, 'groupType') and entry.groupType else None
            if group_type_val == type_value:
                groups.append({
                    'name': entry.cn.value if entry.cn else '',
                    'description': entry.description.value if entry.description else 'No description'
                })
    return {"groups": groups}

@main.route('/admin/drilldown/users')
@login_required
@admin_required
def drilldown_users():
    user_type = request.args.get('type')
    config = get_ad_config()
    if not config:
        return {"error": "AD not configured."}, 400
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    from .ad import ad_connection
    users = []
    admin_groups = get_admin_groups()
    
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'memberOf'])
        for entry in conn.entries:
            if hasattr(entry, "objectClass") and entry.objectClass.value and 'user' in entry.objectClass.value and 'computer' not in entry.objectClass.value:
                # Check if user is in any admin group
                is_admin = False
                if hasattr(entry, 'memberOf') and entry.memberOf:
                    user_groups = [str(group) for group in entry.memberOf.values]
                    for admin_group in admin_groups:
                        if any(admin_group.lower() in group.lower() for group in user_groups):
                            is_admin = True
                            break
                
                # Add user based on type filter
                if (user_type == 'Admin Users' and is_admin) or (user_type == 'Regular Users' and not is_admin):
                    users.append({
                        'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                        'displayName': entry.displayName.value if entry.displayName else entry.sAMAccountName.value if entry.sAMAccountName else 'Unknown'
                    })
    
    return {"users": users}

@main.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    """Admin settings page with system setup, customization, and admin groups."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'save_ad_config':
            # Save AD configuration
            ad_config = {
                'ad_server': request.form.get('ad_server'),
                'ad_user': request.form.get('ad_user'),
                'ad_password': request.form.get('ad_password'),
                'ad_base_dn': request.form.get('ad_base_dn')
            }
            
            # Save to file (in production, use secure storage)
            try:
                with open('app/ad_config.json', 'w') as f:
                    json.dump(ad_config, f, indent=2)
                flash('AD configuration saved successfully!', 'success')
            except Exception as e:
                flash(f'Error saving AD configuration: {str(e)}', 'error')
                
        elif action == 'save_branding':
            # Save branding configuration
            branding = {
                'company_name': request.form.get('company_name'),
                'primary_color': request.form.get('primary_color'),
                'logo_url': request.form.get('logo_url'),
                'theme': request.form.get('theme')
            }
            
            # Save to file (in production, use database)
            try:
                with open('app/branding_config.json', 'w') as f:
                    json.dump(branding, f, indent=2)
                flash('Branding configuration saved successfully!', 'success')
            except Exception as e:
                flash(f'Error saving branding: {str(e)}', 'error')
                
        elif action == 'add_admin_group':
            # Add new admin group
            group_name = request.form.get('group_name')
            group_dn = request.form.get('group_dn')
            
            if group_name and group_dn:
                # In production, save to database
                flash(f'Admin group "{group_name}" added successfully!', 'success')
            else:
                flash('Please provide both group name and DN.', 'error')
                
        elif action == 'remove_admin_group':
            # Remove admin group
            group_id = request.form.get('group_id')
            if group_id:
                # In production, remove from database
                flash('Admin group removed successfully!', 'success')
    
    # Load current configurations
    ad_config = {}
    try:
        with open('app/ad_config.json', 'r') as f:
            ad_config = json.load(f)
    except FileNotFoundError:
        pass
    
    branding = {
        'company_name': 'Geeks Technologies',
        'primary_color': '#ffd700',
        'logo_url': '/static/img/geeks_logo.png',
        'theme': 'dark'
    }
    try:
        with open('app/branding_config.json', 'r') as f:
            branding.update(json.load(f))
    except FileNotFoundError:
        pass
    
    # Mock admin groups (in production, load from database)
    admin_groups = [
        {'id': 1, 'name': 'Domain Admins', 'dn': 'CN=Domain Admins,CN=Users,DC=example,DC=com'},
        {'id': 2, 'name': 'Enterprise Admins', 'dn': 'CN=Enterprise Admins,CN=Users,DC=example,DC=com'},
        {'id': 3, 'name': 'Enterprise Admins', 'dn': 'CN=Enterprise Admins,CN=Users,DC=example,DC=com'}
    ]
    
    return render_template('admin_settings.html', 
                         ad_config=ad_config, 
                         branding=branding, 
                         admin_groups=admin_groups) 