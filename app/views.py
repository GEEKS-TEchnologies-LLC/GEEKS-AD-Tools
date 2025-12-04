from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from app.exchange import ExchangeManager
import json
import os
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
    get_group_types_for_user, get_os_breakdown, get_organization_ous,
    set_user_manager, remove_user_manager, get_user_manager
)
from flask import current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import Admin, DepartmentManager, UserDirectReport
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
from .version_checker import get_version_info, check_github_version
from .updater import Updater
import ldap3
import json
from datetime import datetime, timezone
from flask import session
# License validation removed - no license server available
import csv
import io
from werkzeug.utils import secure_filename
import tempfile
from flask import Response

main = Blueprint('main', __name__)

def get_branding_config():
    """Get branding configuration from file or return defaults"""
    branding = {
        'company_name': 'Geeks Technologies',
        'primary_color': '#ffd700',
        'logo_url': '/static/img/geeks_logo.png',
        'theme': 'dark',
        'secondary_color': '#ffb347',
        'custom_css': ''
    }
    try:
        with open('app/branding_config.json', 'r') as f:
            branding.update(json.load(f))
    except FileNotFoundError:
        pass
    return branding

def save_branding_config(branding_data):
    """Save branding configuration to file"""
    try:
        with open('app/branding_config.json', 'w') as f:
            json.dump(branding_data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving branding config: {e}")
        return False

@main.before_app_request
def enforce_setup():
    # Allow access to setup, admin_register, admin_login, welcome, home, and static without AD config
    allowed_endpoints = (
        'main.setup', 'main.admin_register', 'main.admin_login', 'main.welcome', 'main.home', 'static'
    )
    if not get_ad_config() and request.endpoint not in allowed_endpoints:
        return redirect(url_for('main.home'))

@main.route('/')
def home():
    config = get_ad_config()
    if not config:
        return render_template('welcome.html')
    branding = get_branding_config()
    return render_template(
        'home.html',
        config=config,
        branding=branding,
        email_control_activated=False,
        password_reset_activated=False
    )

@main.route('/welcome')
def welcome():
    return render_template(
        'welcome.html',
        email_control_activated=False,
        password_reset_activated=False
    )

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
    """Legacy admin login - redirect to unified login"""
    return redirect(url_for('main.unified_login'))

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
        # Get password from secure storage or form
        from .credentials import get_credential
        ad_password = request.form.get('ad_password') or get_credential('ad_password') or ''
        
        # Save password to secure storage if provided
        if request.form.get('ad_password'):
            from .credentials import set_credential
            set_credential('ad_password', request.form['ad_password'])
        
        config_data = {
            'ad_server': request.form['ad_server'],
            'ad_port': request.form['ad_port'],
            'ad_bind_dn': request.form['ad_bind_dn'],
            'ad_password': '',  # Don't store in config file
            'ad_base_dn': request.form['ad_base_dn'],
            'users_ou': request.form.get('users_ou', ''),
            'groups_ou': request.form.get('groups_ou', '')
        }
        
        # Set up organization_ous if users_ou is provided
        if request.form.get('users_ou'):
            if 'organization_ous' not in config_data:
                config_data['organization_ous'] = {}
            config_data['organization_ous']['primary_users_ou'] = request.form.get('users_ou')
            config_data['organization_ous']['primary_users_label'] = request.form.get('users_ou').split('OU=')[-1].split(',')[0] if 'OU=' in request.form.get('users_ou') else 'Users'
        
        save_ad_config(config_data)
        # Get password from secure storage for testing
        test_password = get_credential('ad_password') or request.form.get('ad_password', '')
        
        ok, msg = test_ad_connection(
            server=config_data['ad_server'],
            port=config_data['ad_port'],
            bind_user=config_data['ad_bind_dn'],
            bind_password=test_password
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
    """Password reset page"""
    from app.models import get_password_policy, get_ad_password_info
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Please enter a username.', 'error')
            return render_template('reset.html')
        
        # Get AD password information if available
        ad_password_info = get_ad_password_info(username)
        
        # Check if user exists and get their info
        config = get_ad_config()
        if not config:
            flash('Active Directory configuration not available.', 'error')
            return render_template('reset.html')
        
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        users = search_users(username, **ad_args)
        if not users:
            flash('User not found in Active Directory.', 'error')
            return render_template('reset.html')
        
        user_info = users[0]
        
        # Check password status from AD
        if ad_password_info:
            if ad_password_info['account_disabled']:
                flash('Account is disabled. Please contact your administrator.', 'error')
                return render_template('reset.html')
            
            if ad_password_info['is_locked_out']:
                flash('Account is locked out. Please contact your administrator.', 'error')
                return render_template('reset.html')
            
            if not ad_password_info['pwd_can_change']:
                flash('Password cannot be changed for this account. Please contact your administrator.', 'error')
                return render_template('reset.html')
            
            if ad_password_info['smart_card_required']:
                flash('This account requires a smart card for authentication. Please contact your administrator.', 'error')
                return render_template('reset.html')
        
        # Store user info in session for the next step
        session['reset_username'] = username
        session['reset_user_info'] = user_info
        session['reset_ad_info'] = ad_password_info
        
        return redirect(url_for('main.reset_password'))
    
    return render_template('reset.html')

@main.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Password reset form with security questions"""
    from app.models import SecurityQuestion, PasswordReset, get_password_policy, validate_password_against_policy
    from app.models import get_ad_password_info
    
    username = session.get('reset_username')
    user_info = session.get('reset_user_info')
    ad_password_info = session.get('reset_ad_info')
    
    if not username or not user_info:
        flash('Please start the password reset process from the beginning.', 'error')
        return redirect(url_for('main.reset'))
    
    # Get password policy (use AD policy if available)
    policy = get_password_policy()
    if ad_password_info and ad_password_info['domain_policy']:
        policy.update(ad_password_info['domain_policy'])
    
    if request.method == 'POST':
        # Get form data
        security_answer = request.form.get('security_answer', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate security question
        security_question = SecurityQuestion.query.filter_by(username=username).first()
        if not security_question:
            flash('Security question not set up. Please contact your administrator.', 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
        
        if not security_question.check_answer(security_answer):
            flash('Incorrect security answer.', 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
        
        # Validate passwords
        if not new_password:
            flash('Please enter a new password.', 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
        
        # Validate password against policy
        validation_result = validate_password_against_policy(new_password, username)
        if not validation_result['valid']:
            flash(f"Password does not meet requirements: {validation_result['message']}", 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
        
        # Attempt to reset password in AD
        try:
            config = get_ad_config()
            if not config:
                flash('Active Directory configuration not available.', 'error')
                return render_template('reset_password.html', 
                                     username=username, 
                                     user_info=user_info,
                                     ad_password_info=ad_password_info,
                                     policy=policy)
            
            # Reset password in AD
            success = reset_user_password(username, new_password, **{
                'server': config['ad_server'],
                'port': config['ad_port'],
                'bind_user': config['ad_bind_dn'],
                'bind_password': config['ad_password'],
                'base_dn': config['ad_base_dn']
            })
            
            if success:
                # Log the password reset
                reset_record = PasswordReset(
                    username=username,
                    reset_by='self_reset',
                    reset_method='security_question',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                    success=True
                )
                db.session.add(reset_record)
                db.session.commit()
                
                # Clear session
                session.pop('reset_username', None)
                session.pop('reset_user_info', None)
                session.pop('reset_ad_info', None)
                
                flash('Password has been reset successfully!', 'success')
                return redirect(url_for('main.login'))
            else:
                flash('Failed to reset password in Active Directory. Please try again or contact your administrator.', 'error')
                return render_template('reset_password.html', 
                                     username=username, 
                                     user_info=user_info,
                                     ad_password_info=ad_password_info,
                                     policy=policy)
                
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash('An error occurred while resetting the password. Please try again or contact your administrator.', 'error')
            return render_template('reset_password.html', 
                                 username=username, 
                                 user_info=user_info,
                                 ad_password_info=ad_password_info,
                                 policy=policy)
    
    return render_template('reset_password.html', 
                         username=username, 
                         user_info=user_info,
                         ad_password_info=ad_password_info,
                         policy=policy)

@main.route('/admin/groups', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_groups():
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'set_admin_groups':
            groups = request.form.getlist('admin_groups')
            set_admin_groups(groups)
            flash('Admin groups updated successfully.', 'success')
        elif action == 'create_group':
            group_name = request.form.get('group_name')
            group_type = request.form.get('group_type', 'Security')
            if group_name:
                ok, msg = create_ad_group(
                    group_name,
                    group_type=group_type,
                    server=config['ad_server'],
                    port=config['ad_port'],
                    bind_user=config['ad_bind_dn'],
                    bind_password=config['ad_password'],
                    base_dn=config['ad_base_dn']
                )
                flash(msg, 'success' if ok else 'danger')
        elif action == 'add_user_to_group':
            username = request.form.get('username')
            group_name = request.form.get('group_name')
            if username and group_name:
                ok, msg = add_user_to_group(
                    username,
                    group_name,
                    server=config['ad_server'],
                    port=config['ad_port'],
                    bind_user=config['ad_bind_dn'],
                    bind_password=config['ad_password'],
                    base_dn=config['ad_base_dn']
                )
                flash(msg, 'success' if ok else 'danger')
    
    # Get current admin groups
    admin_groups_list = get_admin_groups()
    
    # Get all groups for selection
    ok, all_groups = get_all_groups(
        server=config['ad_server'],
        port=config['ad_port'],
        bind_user=config['ad_bind_dn'],
        bind_password=config['ad_password'],
        base_dn=config['ad_base_dn']
    )
    
    if not ok:
        flash(f'Failed to get groups: {all_groups}', 'warning')
        all_groups = []
    
    return render_template('admin_groups.html', admin_groups=admin_groups_list, all_groups=all_groups)

@main.route('/admin/create_group', methods=['POST'])
@login_required
@admin_required
def create_group():
    config = get_ad_config()
    if not config:
        return jsonify({'success': False, 'message': 'AD not configured'})
    
    group_name = request.form.get('group_name')
    group_type = request.form.get('group_type', 'Security')
    
    if not group_name:
        return jsonify({'success': False, 'message': 'Group name is required'})
    
    ok, msg = create_ad_group(
        group_name,
        group_type=group_type,
        server=config['ad_server'],
        port=config['ad_port'],
        bind_user=config['ad_bind_dn'],
        bind_password=config['ad_password'],
        base_dn=config['ad_base_dn']
    )
    
    return jsonify({'success': ok, 'message': msg})

@main.route('/admin/add_user_to_group', methods=['POST'])
@login_required
@admin_required
def add_user_to_group_route():
    config = get_ad_config()
    if not config:
        return jsonify({'success': False, 'message': 'AD not configured'})
    
    username = request.form.get('username')
    group_name = request.form.get('group_name')
    
    if not username or not group_name:
        return jsonify({'success': False, 'message': 'Username and group name are required'})
    
    ok, msg = add_user_to_group(
        username,
        group_name,
        server=config['ad_server'],
        port=config['ad_port'],
        bind_user=config['ad_bind_dn'],
        bind_password=config['ad_password'],
        base_dn=config['ad_base_dn']
    )
    
    return jsonify({'success': ok, 'message': msg})

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
    status_filter = request.form.get('status_filter', 'all') if request.method == 'POST' else request.args.get('status_filter', 'all')
    
    # Handle OU exclusions
    exclude_ous = []
    if request.method == 'POST':
        exclude_ous_raw = request.form.get('exclude_ous', '')
    else:
        exclude_ous_raw = request.args.get('exclude_ous', '')
    
    if exclude_ous_raw:
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
    
    users = []
    
    # Always search for users - if no query, search for all users
    if query:
        users = search_users(query, status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)
        log_user_action('search', query, 'success' if users else 'no_results', {'query': query, 'status_filter': status_filter, 'exclude_ous': exclude_ous, 'results_count': len(users)})
    else:
        # Show all users when no query is provided
        users = search_users('', status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)
        log_user_action('search', 'all_users', 'success' if users else 'no_results', {'query': 'all_users', 'status_filter': status_filter, 'exclude_ous': exclude_ous, 'results_count': len(users)})
    
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
    
    print(f"DEBUG: page={page}, start={start}, end={end}, users_page_len={len(users_page)}, total_users={total_users}")
    
    # Get OUs for move user functionality
    ous = list_ous(**ad_args)
    
    # Get user statistics for Exchange migration planning
    user_stats = {
        'total_enabled': 0,
        'total_disabled': 0,
        'with_email': 0,
        'without_email': 0,
        'active_users': 0,  # Enabled users not in excluded OUs
        'primary_users_total': 0,  # Total users in primary users OU
        'service_accounts': 0,
        'internal_tools': 0
    }
    
    # Get organization OU configuration
    from .ad import get_organization_ous, get_primary_users_label
    org_ous = get_organization_ous(ad_args.get('ad_base_dn'))
    primary_users_label = get_primary_users_label()
    
    # Count users by status and email - use already fetched users list
    for user in users:
        # All users shown are already filtered to be in primary users OU and not in Disabled Users OU
        user_stats['primary_users_total'] += 1
        
        if user.get('accountStatus') == 'enabled':
            user_stats['total_enabled'] += 1
            user_stats['active_users'] += 1  # Active = enabled and not in disabled OU
        else:
            user_stats['total_disabled'] += 1
            
        if user.get('mail'):
            user_stats['with_email'] += 1
        else:
            user_stats['without_email'] += 1
        
        # Compute category counts for Service Accounts and Internal Tools (for migration planning)
        # Use the already-fetched users list instead of making another query
        dn = user.get('distinguishedName') or user.get('dn') or ''
        mail = (user.get('mail') or '').strip()
        if mail and user.get('accountStatus') == 'enabled':
            service_accounts_ou = org_ous['service_accounts_ou']
            internal_tools_ou = org_ous['internal_tools_ou']
            if service_accounts_ou in dn or 'Service Accounts' in dn:
                user_stats['service_accounts'] += 1
            elif internal_tools_ou in dn or 'Internal Tools' in dn:
                user_stats['internal_tools'] += 1
    
    return render_template(
        'user_search.html', 
        users=users_page, 
        query=query, 
        status_filter=status_filter,
        exclude_ous=exclude_ous,
        exclude_ous_str=','.join(exclude_ous),
        ous=ous, 
        base_dn=config['ad_base_dn'],
        primary_users_label=primary_users_label,
        page=page,
        total_pages=total_pages,
        total_users=total_users,
        sort_by=sort_by,
        sort_order=sort_order,
        user_stats=user_stats
    )

@main.route('/api/users/stats')
@login_required
@admin_required
def api_get_user_stats():
    """API endpoint to get filtered user statistics"""
    try:
        config = get_ad_config()
        if not config:
            return jsonify({'success': False, 'error': 'AD not configured'}), 400
        
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        # Get filter parameters
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        
        # Get stats filter parameters
        include_disabled = request.args.get('include_disabled', '1') == '1'
        include_no_email = request.args.get('include_no_email', '1') == '1'
        include_service_accounts = request.args.get('include_service_accounts', '1') == '1'
        include_internal_tools = request.args.get('include_internal_tools', '1') == '1'
        
        # Get all users (for accurate stats)
        all_users = search_users(query, status_filter='all', exclude_ous=[], **ad_args)
        
        # Get organization OU configuration
        from .ad import get_organization_ous, get_primary_users_label
        org_ous = get_organization_ous(ad_args.get('ad_base_dn'))
        primary_users_label = get_primary_users_label()
        
        # Initialize stats
        user_stats = {
            'total_enabled': 0,
            'total_disabled': 0,
            'with_email': 0,
            'without_email': 0,
            'active_users': 0,
            'primary_users_total': 0,
            'service_accounts': 0,
            'internal_tools': 0
        }
        
        # Count users with filters applied
        for user in all_users:
            # Check if user is in primary users OU
            dn = user.get('distinguishedName') or user.get('dn') or ''
            if 'OU=Disabled Users' in dn or org_ous.get('disabled_users_ou', '') in dn:
                continue  # Always exclude disabled users OU
            
            # Check excluded OUs
            if exclude_ous:
                should_exclude = False
                for excluded_ou in exclude_ous:
                    if excluded_ou.strip() and excluded_ou.strip() in dn:
                        should_exclude = True
                        break
                if should_exclude:
                    continue
            
            # Apply status filter
            if status_filter == 'enabled' and user.get('accountStatus') != 'enabled':
                continue
            if status_filter == 'disabled' and user.get('accountStatus') != 'disabled':
                continue
            
            # Count primary users
            user_stats['primary_users_total'] += 1
            
            # Count by status
            if user.get('accountStatus') == 'enabled':
                user_stats['total_enabled'] += 1
                if include_disabled:  # Only count as active if including disabled
                    user_stats['active_users'] += 1
            else:
                if include_disabled:
                    user_stats['total_disabled'] += 1
            
            # Count by email
            has_email = bool(user.get('mail'))
            if has_email:
                user_stats['with_email'] += 1
            else:
                if include_no_email:
                    user_stats['without_email'] += 1
            
            # Count service accounts and internal tools
            mail = (user.get('mail') or '').strip()
            if mail and user.get('accountStatus') == 'enabled':
                service_accounts_ou = org_ous.get('service_accounts_ou', '')
                internal_tools_ou = org_ous.get('internal_tools_ou', '')
                if service_accounts_ou in dn or 'Service Accounts' in dn:
                    if include_service_accounts:
                        user_stats['service_accounts'] += 1
                elif internal_tools_ou in dn or 'Internal Tools' in dn:
                    if include_internal_tools:
                        user_stats['internal_tools'] += 1
        
        # Recalculate active users based on filters
        if include_disabled and include_no_email:
            user_stats['active_users'] = user_stats['total_enabled']
        else:
            # Active = enabled, with email, and respecting other filters
            user_stats['active_users'] = 0
            for user in all_users:
                dn = user.get('distinguishedName') or user.get('dn') or ''
                if 'OU=Disabled Users' in dn or org_ous.get('disabled_users_ou', '') in dn:
                    continue
                if exclude_ous:
                    should_exclude = False
                    for excluded_ou in exclude_ous:
                        if excluded_ou.strip() and excluded_ou.strip() in dn:
                            should_exclude = True
                            break
                    if should_exclude:
                        continue
                if status_filter == 'enabled' and user.get('accountStatus') != 'enabled':
                    continue
                if status_filter == 'disabled' and user.get('accountStatus') != 'disabled':
                    continue
                if user.get('accountStatus') == 'enabled' and user.get('mail'):
                    if not include_service_accounts:
                        if 'Service Accounts' in dn or org_ous.get('service_accounts_ou', '') in dn:
                            continue
                    if not include_internal_tools:
                        if 'Internal Tools' in dn or org_ous.get('internal_tools_ou', '') in dn:
                            continue
                    user_stats['active_users'] += 1
        
        return jsonify({
            'success': True,
            'stats': user_stats
        })
    except Exception as e:
        current_app.logger.error(f"Error getting user stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@main.route('/admin/export/mailbox_ready')
@login_required
@admin_required
def export_mailbox_ready():
    """Export CSV of mailbox-ready users (enabled and with email) with mailbox sizes.

    Respects current filters from the user search page: query, status_filter, exclude_ous.
    Always enforces enabled status and requires non-empty email for export.
    Columns: Name, Username, Email, Mailbox Size
    Includes latest cached mailbox size data if available.
    """
    from .models import MailboxSizeCache
    import json
    
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

    # Pull filters from querystring to match current page state
    query = request.args.get('query', '')
    exclude_ous_raw = request.args.get('exclude_ous', '')
    exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
    exclude_ous_str = exclude_ous_raw
    status_filter = 'enabled'

    # Always enforce enabled for mailbox-ready
    users = search_users(query, status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)

    # Get cached mailbox sizes for current user and filters
    # Try multiple cache keys since data might be stored with different status_filter values
    mailbox_sizes = {}
    cache_entry = None
    
    # First try with 'enabled' status filter
    cache_entry = db.session.query(MailboxSizeCache).filter_by(
        username=current_user.username,
        query=query,
        status_filter='enabled',
        exclude_ous=exclude_ous_str
    ).first()
    
    # If not found, try with 'all' status filter (since user might have fetched with 'all')
    if not cache_entry:
        cache_entry = db.session.query(MailboxSizeCache).filter_by(
            username=current_user.username,
            query=query,
            status_filter='all',
            exclude_ous=exclude_ous_str
        ).first()
    
    if cache_entry:
        try:
            mailbox_sizes = json.loads(cache_entry.mailbox_sizes)
            current_app.logger.info(f"Found cached mailbox sizes for export: {len(mailbox_sizes)} entries")
        except json.JSONDecodeError:
            current_app.logger.warning(f"Error parsing cached mailbox sizes for export: {current_user.username}")
    else:
        current_app.logger.warning(f"No cached mailbox sizes found for export (query={query}, status_filter=enabled/all, exclude_ous={exclude_ous_str})")

    # Keep only users with an email address and include mailbox sizes
    mailbox_ready = []
    for u in users:
        mail = (u.get('mail') or '').strip()
        if mail:
            # Get mailbox size from cache (case-insensitive lookup)
            mail_lower = mail.lower()
            size_info = mailbox_sizes.get(mail_lower, {})
            mailbox_size_bytes = size_info.get('TotalItemSize', 0) if isinstance(size_info, dict) else 0
            
            # Convert bytes to readable format (KB/MB/GB)
            if mailbox_size_bytes:
                if mailbox_size_bytes < 1024:  # Less than 1 KB
                    size_str = f"{mailbox_size_bytes} B"
                elif mailbox_size_bytes < 1024 * 1024:  # Less than 1 MB
                    size_str = f"{mailbox_size_bytes / 1024:.2f} KB"
                elif mailbox_size_bytes < 1024 * 1024 * 1024:  # Less than 1 GB
                    size_str = f"{mailbox_size_bytes / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{mailbox_size_bytes / (1024 * 1024 * 1024):.2f} GB"
            else:
                size_str = 'Not available'
            
            mailbox_ready.append({
                'Name': u.get('displayName') or '',
                'Username': u.get('sAMAccountName') or u.get('username') or '',
                'Email': mail,
                'Mailbox Size': size_str
            })

    # Build CSV
    def generate_csv(rows):
        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Name', 'Username', 'Email', 'Mailbox Size'])
        for r in rows:
            writer.writerow([r['Name'], r['Username'], r['Email'], r['Mailbox Size']])
        return output.getvalue()

    csv_data = generate_csv(mailbox_ready)
    filename = 'mailbox_ready_users.csv'
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@main.route('/admin/export/migration_ready')
@login_required
@admin_required
def export_migration_ready():
    """Export migration-ready users grouped by department OU to CSV and XLSX.
    
    Respects current filters from the user search page: query, status_filter, exclude_ous.
    Always enforces enabled status and requires non-empty email for export.
    """
    import sys
    import os
    from collections import defaultdict
    from flask import Response
    from datetime import datetime
    
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': int(config['ad_port']),
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    # Get filters from query string
    query = request.args.get('query', '')
    status_filter = request.args.get('status_filter', 'enabled')  # Respect user's filter choice
    exclude_ous_raw = request.args.get('exclude_ous', '')
    exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
    require_email = request.args.get('require_email', '1') == '1'  # Default to requiring email
    group_by_department = request.args.get('group_by_department', '1') == '1'  # Default to grouping
    
    try:
        # Search for users with current filters (respect all filters including status)
        users = search_users(query, status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)
        
        # Helper function to extract department from OU
        def extract_department_from_ou(dn):
            """Extract department name from OU path."""
            if not dn:
                return "Unknown"
            parts = dn.split(',')
            ous = []
            for part in parts:
                part = part.strip()
                if part.startswith('OU='):
                    ou_name = part.replace('OU=', '')
                    if ou_name.lower() not in ['users', 'disabled users', 'service accounts', 'internal tools', 'sunray users', 'sunray']:
                        ous.append(ou_name)
            if ous:
                return ous[0]
            for part in parts:
                if part.startswith('CN='):
                    cn_name = part.replace('CN=', '')
                    if cn_name.lower() not in ['users']:
                        return cn_name
            return "Root"
        
        # Filter users based on criteria
        migration_ready = []
        for user in users:
            email = (user.get('mail') or '').strip()
            # Apply require_email filter if enabled
            if require_email and not email:
                continue  # Skip users without email
            
            # Extract department from OU
            dn = user.get('distinguishedName') or user.get('dn') or ''
            department = extract_department_from_ou(dn)
            
            user_data = {
                'Name': user.get('displayName') or user.get('cn') or '',
                'Username': user.get('sAMAccountName') or user.get('username') or '',
                'Email': email,
                'Department': department,
                'OU Path': dn,
                'Title': user.get('title') or '',
                'Department (AD)': user.get('department') or '',
                'Company': user.get('company') or '',
                'Phone': user.get('telephoneNumber') or user.get('phone') or '',
                'Mobile': user.get('mobile') or user.get('mobilePhone') or '',
            }
            migration_ready.append(user_data)
        
        if not migration_ready:
            # Return empty file instead of redirecting (for background export)
            export_format = request.args.get('format', 'csv').lower()
            if export_format == 'xlsx':
                try:
                    import pandas as pd
                    from io import BytesIO
                    output = BytesIO()
                    with pd.ExcelWriter(output, engine='openpyxl') as writer:
                        pd.DataFrame([{'Message': 'No users found matching the selected filters'}]).to_excel(writer, sheet_name='No Data', index=False)
                    output.seek(0)
                    filename = f'migration_ready_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
                    return Response(
                        output.read(),
                        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        headers={'Content-Disposition': f'attachment; filename={filename}'}
                    )
                except ImportError:
                    pass
            # CSV fallback
            import io
            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Message'])
            writer.writerow(['No users found matching the selected filters'])
            filename = f'migration_ready_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        
        # Group by department if requested
        if group_by_department:
            users_by_dept = defaultdict(list)
            for user in migration_ready:
                department = user.get('Department', 'Unknown')
                users_by_dept[department].append(user)
            # Sort departments
            users_by_dept = dict(sorted(users_by_dept.items()))
        else:
            # Single flat list
            users_by_dept = {'All Users': migration_ready}
        
        # Determine export format
        export_format = request.args.get('format', 'csv').lower()
        
        if export_format == 'xlsx':
            # XLSX export
            try:
                import pandas as pd
                from io import BytesIO
                
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    if group_by_department:
                        # Summary sheet
                        summary_data = []
                        for department, dept_users in sorted(users_by_dept.items()):
                            summary_data.append({
                                'Department': department,
                                'User Count': len(dept_users)
                            })
                        summary_df = pd.DataFrame(summary_data)
                        summary_df.to_excel(writer, sheet_name='Summary', index=False)
                        
                        # Department sheets
                        for department, dept_users in sorted(users_by_dept.items()):
                            sheet_name = department[:31] if len(department) <= 31 else department[:28] + '...'
                            df = pd.DataFrame(dept_users)
                            column_order = ['Name', 'Username', 'Email', 'Title', 
                                          'Department (AD)', 'Company', 'Phone', 'Mobile']
                            existing_columns = [col for col in column_order if col in df.columns]
                            if existing_columns:
                                df = df[existing_columns]
                            df.to_excel(writer, sheet_name=sheet_name, index=False)
                    else:
                        # Single sheet export
                        df = pd.DataFrame(migration_ready)
                        column_order = ['Name', 'Username', 'Email', 'Title', 
                                      'Department (AD)', 'Company', 'Phone', 'Mobile']
                        existing_columns = [col for col in column_order if col in df.columns]
                        if existing_columns:
                            df = df[existing_columns]
                        df.to_excel(writer, sheet_name='All Users', index=False)
                
                output.seek(0)
                filename = f'migration_ready_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
                return Response(
                    output.read(),
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    headers={'Content-Disposition': f'attachment; filename={filename}'}
                )
            except ImportError:
                flash('XLSX export requires pandas and openpyxl. Install with: pip install pandas openpyxl', 'error')
                return redirect(url_for('main.user_search'))
        else:
            # CSV export (default)
            import io
            import csv
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            if group_by_department:
                writer.writerow(['Department', 'Name', 'Username', 'Email', 'Title', 
                               'Department (AD)', 'Company', 'Phone', 'Mobile', 'OU Path'])
                
                # Write data grouped by department
                for department, dept_users in sorted(users_by_dept.items()):
                    for user in sorted(dept_users, key=lambda x: x.get('Name', '')):
                        writer.writerow([
                            department,
                            user.get('Name', ''),
                            user.get('Username', ''),
                            user.get('Email', ''),
                            user.get('Title', ''),
                            user.get('Department (AD)', ''),
                            user.get('Company', ''),
                            user.get('Phone', ''),
                            user.get('Mobile', ''),
                            user.get('OU Path', '')
                        ])
            else:
                # Flat export without department grouping
                writer.writerow(['Name', 'Username', 'Email', 'Title', 
                               'Department (AD)', 'Company', 'Phone', 'Mobile', 'OU Path'])
                
                for user in sorted(migration_ready, key=lambda x: x.get('Name', '')):
                    writer.writerow([
                        user.get('Name', ''),
                        user.get('Username', ''),
                        user.get('Email', ''),
                        user.get('Title', ''),
                        user.get('Department (AD)', ''),
                        user.get('Company', ''),
                        user.get('Phone', ''),
                        user.get('Mobile', ''),
                        user.get('OU Path', '')
                    ])
            
            csv_data = output.getvalue()
            filename = f'migration_ready_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
    except Exception as e:
        current_app.logger.error(f"Error exporting migration-ready users: {e}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        flash(f'Error exporting migration-ready users: {str(e)}', 'error')
        return redirect(url_for('main.user_search'))


@main.route('/admin/export/service_accounts')
@login_required
@admin_required
def export_service_accounts():
    """Export CSV of Service Accounts (any with email, matched by DN substring)."""
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

    query = request.args.get('query', '')
    exclude_ous_raw = request.args.get('exclude_ous', '')
    exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]

    users = search_users(query, status_filter='all', exclude_ous=exclude_ous, **ad_args)
    rows = []
    for u in users:
        dn = u.get('distinguishedName') or u.get('dn') or ''
        mail = (u.get('mail') or '').strip()
        if 'Service Accounts' in dn and mail:
            rows.append({
                'Name': u.get('displayName') or '',
                'Username': u.get('sAMAccountName') or u.get('username') or '',
                'Email': mail
            })

    def gen_csv(rows):
        import io, csv
        s = io.StringIO()
        w = csv.writer(s)
        w.writerow(['Name', 'Username', 'Email'])
        for r in rows:
            w.writerow([r['Name'], r['Username'], r['Email']])
        return s.getvalue()

    return Response(
        gen_csv(rows),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=service_accounts.csv'}
    )


@main.route('/admin/export/internal_tools')
@login_required
@admin_required
def export_internal_tools():
    """Export CSV of Internal Tools (any with email, matched by DN substring)."""
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

    query = request.args.get('query', '')
    exclude_ous_raw = request.args.get('exclude_ous', '')
    exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]

    users = search_users(query, status_filter='all', exclude_ous=exclude_ous, **ad_args)
    rows = []
    for u in users:
        dn = u.get('distinguishedName') or u.get('dn') or ''
        mail = (u.get('mail') or '').strip()
        if 'Internal Tools' in dn and mail:
            rows.append({
                'Name': u.get('displayName') or '',
                'Username': u.get('sAMAccountName') or u.get('username') or '',
                'Email': mail
            })

    def gen_csv(rows):
        import io, csv
        s = io.StringIO()
        w = csv.writer(s)
        w.writerow(['Name', 'Username', 'Email'])
        for r in rows:
            w.writerow([r['Name'], r['Username'], r['Email']])
        return s.getvalue()

    return Response(
        gen_csv(rows),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=internal_tools.csv'}
    )


def get_exchange_config():
    """Get Exchange configuration with secure credential injection"""
    config_path = os.path.join(os.path.dirname(__file__), 'exchange_config.json')
    config = None
    
    # Load base config from file (non-sensitive data)
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            pass
    
    if config is None:
        config = {
            'exchange_server': '',
            'username': '',
            'password': '',
            'domain': '',
            'enabled': False
        }
    
    # Inject secure password if available
    try:
        from .credentials import get_credential
        secure_password = get_credential('exchange_password')
        if secure_password:
            config['password'] = secure_password
    except Exception as e:
        current_app.logger.debug(f"Could not load secure Exchange credentials: {e}")
    
    return config


@main.route('/admin/exchange/setup')
@login_required
@admin_required
def exchange_setup():
    """Exchange configuration page"""
    config = get_exchange_config()
    return render_template('exchange_setup.html', config=config)


@main.route('/admin/exchange/save_config', methods=['POST'])
@login_required
@admin_required
def save_exchange_config():
    """Save Exchange configuration with secure password storage"""
    try:
        from .credentials import save_credentials
        
        password = request.form.get('password', '')
        config = {
            'exchange_server': request.form.get('exchange_server', ''),
            'username': request.form.get('username', ''),
            'password': '',  # Don't store password in config file
            'domain': request.form.get('domain', ''),
            'enabled': request.form.get('enabled') == 'on'
        }
        
        # Save non-sensitive config to file
        config_path = os.path.join(os.path.dirname(__file__), 'exchange_config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Save password securely
        if password:
            save_credentials({'exchange_password': password})
        
        flash('Exchange configuration saved successfully!', 'success')
    except Exception as e:
        current_app.logger.error(f"Error saving Exchange configuration: {e}")
        flash(f'Error saving Exchange configuration: {str(e)}', 'danger')
    
    return redirect(url_for('main.exchange_setup'))


@main.route('/admin/exchange/test_connection')
@login_required
@admin_required
def test_exchange_connection():
    """Test Exchange connection"""
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        success, message = exchange.test_connection()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main.route('/admin/exchange/mailbox_sizes')
@login_required
@admin_required
def get_mailbox_sizes():
    """Get mailbox sizes for current user list - stores in database cache"""
    from .models import MailboxSizeCache
    import json
    
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        # Get current filters
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        exclude_ous_str = exclude_ous_raw  # Keep original string for storage
        
        # Get AD config
        ad_config = get_ad_config()
        if not ad_config:
            return jsonify({'success': False, 'message': 'AD not configured'})
        
        ad_args = {
            'server': ad_config['ad_server'],
            'port': ad_config['ad_port'],
            'bind_user': ad_config['ad_bind_dn'],
            'bind_password': ad_config['ad_password'],
            'base_dn': ad_config['ad_base_dn']
        }
        
        # Get users with emails
        users = search_users(query, status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)
        user_emails = [user.get('mail').lower() if user.get('mail') else None for user in users if user.get('mail')]
        user_emails = [email for email in user_emails if email]  # Remove None values
        
        if not user_emails:
            # Store empty result in cache
            cache_entry = db.session.query(MailboxSizeCache).filter_by(
                username=current_user.username,
                query=query,
                status_filter=status_filter,
                exclude_ous=exclude_ous_str
            ).first()
            
            if cache_entry:
                cache_entry.mailbox_sizes = json.dumps({})
                cache_entry.updated_at = datetime.now(timezone.utc)
            else:
                cache_entry = MailboxSizeCache(
                    username=current_user.username,
                    query=query,
                    status_filter=status_filter,
                    exclude_ous=exclude_ous_str,
                    mailbox_sizes=json.dumps({})
                )
                db.session.add(cache_entry)
            db.session.commit()
            return jsonify({'success': True, 'mailbox_sizes': {}})
        
        # Get mailbox sizes
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        mailbox_sizes = exchange.get_mailbox_sizes(user_emails)
        current_app.logger.info(f"Retrieved mailbox sizes for {len(mailbox_sizes)} mailboxes out of {len(user_emails)} requested")
        
        # Store in database cache (overwrite existing if present)
        cache_entry = db.session.query(MailboxSizeCache).filter_by(
            username=current_user.username,
            query=query,
            status_filter=status_filter,
            exclude_ous=exclude_ous_str
        ).first()
        
        if cache_entry:
            # Update existing entry
            cache_entry.mailbox_sizes = json.dumps(mailbox_sizes)
            cache_entry.updated_at = datetime.now(timezone.utc)
        else:
            # Create new entry
            cache_entry = MailboxSizeCache(
                username=current_user.username,
                query=query,
                status_filter=status_filter,
                exclude_ous=exclude_ous_str,
                mailbox_sizes=json.dumps(mailbox_sizes)
            )
            db.session.add(cache_entry)
        
        db.session.commit()
        current_app.logger.info(f"Stored mailbox sizes in cache for user {current_user.username}")
        
        return jsonify({'success': True, 'mailbox_sizes': mailbox_sizes})
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        current_app.logger.error(f"Error getting mailbox sizes: {e}")
        current_app.logger.error(f"Traceback: {error_details}")
        current_app.logger.error(f"Request params: query={query}, status_filter={status_filter}, exclude_ous={exclude_ous}")
        current_app.logger.error(f"User emails count: {len(user_emails) if 'user_emails' in locals() else 'N/A'}")
        return jsonify({'success': False, 'message': str(e), 'error_type': type(e).__name__})

@main.route('/admin/exchange/mailbox_sizes/cached')
@login_required
@admin_required
def get_cached_mailbox_sizes():
    """Get cached mailbox sizes from database for current user and filters"""
    from .models import MailboxSizeCache
    import json
    
    try:
        # Get current filters
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        exclude_ous_str = exclude_ous_raw  # Keep original string for lookup
        
        # Look up cached data
        cache_entry = db.session.query(MailboxSizeCache).filter_by(
            username=current_user.username,
            query=query,
            status_filter=status_filter,
            exclude_ous=exclude_ous_str
        ).first()
        
        if cache_entry:
            try:
                mailbox_sizes = json.loads(cache_entry.mailbox_sizes)
                return jsonify({
                    'success': True, 
                    'mailbox_sizes': mailbox_sizes,
                    'cached': True,
                    'updated_at': cache_entry.updated_at.isoformat()
                })
            except json.JSONDecodeError:
                current_app.logger.error(f"Error parsing cached mailbox sizes for user {current_user.username}")
                return jsonify({'success': False, 'message': 'Invalid cached data'})
        else:
            return jsonify({
                'success': True, 
                'mailbox_sizes': {},
                'cached': False,
                'message': 'No cached data found'
            })
        
    except Exception as e:
        current_app.logger.error(f"Error getting cached mailbox sizes: {e}")
        return jsonify({'success': False, 'message': str(e)})


@main.route('/admin/exchange/cleanup_mailbox', methods=['POST'])
@login_required
@admin_required
def cleanup_mailbox():
    """Cleanup a specific mailbox"""
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        email = request.form.get('email')
        cleanup_options = {
            'empty_deleted_items': request.form.get('empty_deleted_items') == 'on',
            'clean_sent_items_days': int(request.form.get('clean_sent_items_days', 0)) or None,
            'clean_old_items_days': int(request.form.get('clean_old_items_days', 0)) or None
        }
        
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        success, message = exchange.cleanup_mailbox(email, cleanup_options)
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main.route('/admin/exchange/create_mailbox', methods=['POST'])
@login_required
@admin_required
def create_mailbox():
    """Create mailbox for a user"""
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        email = request.form.get('email')
        display_name = request.form.get('display_name')
        database = request.form.get('database') or None
        
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        success, message = exchange.create_mailbox(email, display_name, database)
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main.route('/admin/exchange/orphaned_mailboxes')
@login_required
@admin_required
def get_orphaned_mailboxes():
    """Get orphaned mailboxes - those that exist in Exchange but not in active AD users"""
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        # Get current filters
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        
        # Get AD config
        ad_config = get_ad_config()
        if not ad_config:
            return jsonify({'success': False, 'message': 'AD not configured'})
        
        ad_args = {
            'server': ad_config['ad_server'],
            'port': ad_config['ad_port'],
            'bind_user': ad_config['ad_bind_dn'],
            'bind_password': ad_config['ad_password'],
            'base_dn': ad_config['ad_base_dn']
        }
        
        # Get ALL active users with emails (for orphaned mailbox detection, ignore filters except disabled users)
        # This includes regular users, service accounts, and internal tools
        base_dn = ad_config['ad_base_dn']
        user_emails = set()
        
        # Get all enabled users from primary users OU (including service accounts and internal tools)
        all_users = search_users('', status_filter='enabled', exclude_ous=[], **ad_args)
        user_emails.update([user.get('mail').lower() for user in all_users if user.get('mail')])
        
        # Also explicitly get Service Accounts and Internal Tools if they're in separate OUs
        # Search in Service Accounts OU
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SUBTREE
            server = Server(ad_config['ad_server'], port=int(ad_config['ad_port']), get_info=ALL)
            conn = Connection(server, 
                             user=ad_config['ad_bind_dn'], 
                             password=ad_config['ad_password'], 
                             auto_bind=True)
            
            # Search Service Accounts OU
            service_accounts_base = f'OU=Service Accounts,{base_dn}'
            try:
                conn.search(service_accounts_base, 
                           '(&(objectClass=user)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', 
                           search_scope=SUBTREE,
                           attributes=['mail'])
                for entry in conn.entries:
                    if entry.mail:
                        user_emails.add(entry.mail.value.lower())
            except Exception:
                pass  # Service Accounts OU might not exist
            
            # Search Internal Tools OU
            internal_tools_base = f'OU=Internal Tools,{base_dn}'
            try:
                conn.search(internal_tools_base, 
                           '(&(objectClass=user)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', 
                           search_scope=SUBTREE,
                           attributes=['mail'])
                for entry in conn.entries:
                    if entry.mail:
                        user_emails.add(entry.mail.value.lower())
            except Exception:
                pass  # Internal Tools OU might not exist
            
            conn.unbind()
        except Exception as e:
            current_app.logger.warning(f"Could not search separate OUs for orphaned mailbox check: {e}")
        
        # Convert to list for compatibility
        user_emails = list(user_emails)
        current_app.logger.info(f"Checking orphaned mailboxes against {len(user_emails)} active email addresses")
        
        # Get Exchange manager
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        # Find orphaned mailboxes
        orphaned_data = exchange.find_orphaned_mailboxes(user_emails)
        
        return jsonify({
            'success': True, 
            'orphaned_mailboxes': orphaned_data['orphaned'],
            'missing_mailboxes': orphaned_data['missing'],
            'total_orphaned': len(orphaned_data['orphaned']),
            'total_missing': len(orphaned_data['missing'])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main.route('/admin/exchange/export_orphaned_mailboxes')
@login_required
@admin_required
def export_orphaned_mailboxes():
    """Export orphaned mailboxes to CSV"""
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        flash('Exchange not configured', 'warning')
        return redirect(url_for('main.user_search'))
    
    try:
        # Get current filters
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        
        # Get AD config
        ad_config = get_ad_config()
        if not ad_config:
            flash('AD not configured', 'warning')
            return redirect(url_for('main.user_search'))
        
        ad_args = {
            'server': ad_config['ad_server'],
            'port': ad_config['ad_port'],
            'bind_user': ad_config['ad_bind_dn'],
            'bind_password': ad_config['ad_password'],
            'base_dn': ad_config['ad_base_dn']
        }
        
        # Get ALL active users with emails (for orphaned mailbox detection, ignore filters except disabled users)
        # This includes regular users, service accounts, and internal tools
        base_dn = ad_config['ad_base_dn']
        user_emails = set()
        
        # Get all enabled users from primary users OU (including service accounts and internal tools)
        all_users = search_users('', status_filter='enabled', exclude_ous=[], **ad_args)
        user_emails.update([user.get('mail').lower() for user in all_users if user.get('mail')])
        
        # Also explicitly get Service Accounts and Internal Tools if they're in separate OUs
        # Search in Service Accounts OU
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SUBTREE
            server = Server(ad_config['ad_server'], port=int(ad_config['ad_port']), get_info=ALL)
            conn = Connection(server, 
                             user=ad_config['ad_bind_dn'], 
                             password=ad_config['ad_password'], 
                             auto_bind=True)
            
            # Search Service Accounts OU
            service_accounts_base = f'OU=Service Accounts,{base_dn}'
            try:
                conn.search(service_accounts_base, 
                           '(&(objectClass=user)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', 
                           search_scope=SUBTREE,
                           attributes=['mail'])
                for entry in conn.entries:
                    if entry.mail:
                        user_emails.add(entry.mail.value.lower())
            except Exception:
                pass  # Service Accounts OU might not exist
            
            # Search Internal Tools OU
            internal_tools_base = f'OU=Internal Tools,{base_dn}'
            try:
                conn.search(internal_tools_base, 
                           '(&(objectClass=user)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', 
                           search_scope=SUBTREE,
                           attributes=['mail'])
                for entry in conn.entries:
                    if entry.mail:
                        user_emails.add(entry.mail.value.lower())
            except Exception:
                pass  # Internal Tools OU might not exist
            
            conn.unbind()
        except Exception as e:
            current_app.logger.warning(f"Could not search separate OUs for orphaned mailbox check: {e}")
        
        # Convert to list for compatibility
        user_emails = list(user_emails)
        current_app.logger.info(f"Checking orphaned mailboxes against {len(user_emails)} active email addresses")
        
        # Get Exchange manager
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        # Find orphaned mailboxes
        orphaned_data = exchange.find_orphaned_mailboxes(user_emails)
        
        # Create CSV
        import io, csv
        si = io.StringIO()
        cw = csv.writer(si)
        
        # Write orphaned mailboxes
        cw.writerow(['Type', 'DisplayName', 'Email', 'Size_MB', 'ItemCount', 'LastLogon', 'Database'])
        for mb in orphaned_data['orphaned']:
            size_mb = round(mb.get('TotalItemSize', 0) / (1024 * 1024)) if mb.get('TotalItemSize') else 0
            last_logon = mb.get('LastLogonTime', 'Never')
            if last_logon and last_logon != 'Never':
                try:
                    last_logon = last_logon.split('T')[0]  # Just the date part
                except:
                    pass
            cw.writerow([
                'Orphaned',
                mb.get('DisplayName', 'N/A'),
                mb.get('PrimarySmtpAddress', 'N/A'),
                size_mb,
                mb.get('ItemCount', 0),
                last_logon,
                mb.get('Database', 'N/A')
            ])
        
        # Write missing mailboxes
        for mb in orphaned_data['missing']:
            cw.writerow([
                'Missing',
                mb.get('DisplayName', 'N/A'),
                mb.get('PrimarySmtpAddress', 'N/A'),
                0,
                0,
                'N/A',
                'N/A'
            ])
        
        output = si.getvalue()
        response = Response(output, mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=orphaned_mailboxes.csv"
        return response
        
    except Exception as e:
        flash(f'Error exporting orphaned mailboxes: {str(e)}', 'danger')
        return redirect(url_for('main.user_search'))

@main.route('/admin/exchange/archive_orphaned_mailboxes', methods=['POST'])
@login_required
@admin_required
def archive_orphaned_mailboxes():
    """Archive orphaned mailboxes to PST, zip them on Exchange server, then download or transfer"""
    import zipfile
    import shutil
    import os
    from datetime import datetime
    import time
    
    config = get_exchange_config()
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': 'Exchange not configured'})
    
    try:
        # Get request parameters
        data = request.get_json()
        use_local_temp = data.get('use_local_temp', True)  # Use local Exchange temp by default
        archive_path = data.get('archive_path', '')  # Local Exchange path or network share (if not using temp)
        remove_after_archive = data.get('remove_after_archive', False)  # Whether to remove mailboxes after archiving
        download_zip = data.get('download_zip', False)  # Whether to download zip file to Flask app
        transfer_to_file_store = data.get('transfer_to_file_store', False)  # Whether to transfer to file store
        file_store_path = data.get('file_store_path', '')  # File store network path (e.g., \\server\share\archives)
        
        # If using local temp, archive_path can be empty (will use system temp)
        if not use_local_temp and not archive_path:
            return jsonify({'success': False, 'message': 'Archive path is required when not using local temp'})
        
        # Get AD config to find orphaned mailboxes
        ad_config = get_ad_config()
        if not ad_config:
            return jsonify({'success': False, 'message': 'AD not configured'})
        
        ad_args = {
            'server': ad_config['ad_server'],
            'port': ad_config['ad_port'],
            'bind_user': ad_config['ad_bind_dn'],
            'bind_password': ad_config['ad_password'],
            'base_dn': ad_config['ad_base_dn']
        }
        
        # Get ALL active users with emails (same logic as get_orphaned_mailboxes)
        base_dn = ad_config['ad_base_dn']
        user_emails = set()
        
        all_users = search_users('', status_filter='enabled', exclude_ous=[], **ad_args)
        user_emails.update([user.get('mail').lower() for user in all_users if user.get('mail')])
        
        # Also get Service Accounts and Internal Tools
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SUBTREE
            from .ad import get_organization_ous
            org_ous = get_organization_ous(ad_config['ad_base_dn'])
            
            server = Server(ad_config['ad_server'], port=int(ad_config['ad_port']), get_info=ALL)
            conn = Connection(server, 
                             user=ad_config['ad_bind_dn'], 
                             password=ad_config['ad_password'], 
                             auto_bind=True)
            
            # Search Service Accounts OU
            search_base = org_ous['service_accounts_ou']
            conn.search(search_base, '(&(objectClass=user)(mail=*))', attributes=['mail'])
            for entry in conn.entries:
                mail = entry.mail.values[0] if hasattr(entry, 'mail') and entry.mail.values else None
                if mail:
                    user_emails.add(mail.lower())
            
            # Search Internal Tools OU
            search_base = org_ous['internal_tools_ou']
            conn.search(search_base, '(&(objectClass=user)(mail=*))', attributes=['mail'])
            for entry in conn.entries:
                mail = entry.mail.values[0] if hasattr(entry, 'mail') and entry.mail.values else None
                if mail:
                    user_emails.add(mail.lower())
            
            conn.unbind()
        except Exception as e:
            current_app.logger.warning(f"Could not search separate OUs for orphaned mailbox check: {e}")
        
        # Get Exchange manager
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )
        
        # Find orphaned mailboxes
        orphaned_data = exchange.find_orphaned_mailboxes(list(user_emails))
        orphaned_mailboxes = orphaned_data.get('orphaned', [])
        
        if not orphaned_mailboxes:
            return jsonify({'success': True, 'message': 'No orphaned mailboxes found', 'archived': 0, 'removed': 0})
        
        current_app.logger.info(f"Found {len(orphaned_mailboxes)} orphaned mailboxes to archive")
        
        # Archive each mailbox
        archived_count = 0
        failed_archives = []
        export_requests = []
        
        current_app.logger.info(f"Starting archive process for {len(orphaned_mailboxes)} mailboxes")
        
        for idx, mailbox in enumerate(orphaned_mailboxes, 1):
            email = mailbox.get('PrimarySmtpAddress')
            if not email:
                current_app.logger.warning(f"Skipping mailbox {idx}/{len(orphaned_mailboxes)}: no email address")
                continue
            
            current_app.logger.info(f"Archiving mailbox {idx}/{len(orphaned_mailboxes)}: {email}")
            
            try:
                # Use local temp if specified, otherwise use network share
                success, message = exchange.archive_mailbox(email, archive_path, use_local_temp=use_local_temp)
                
                if success:
                    archived_count += 1
                    export_requests.append({'email': email, 'message': message})
                    current_app.logger.info(f"Successfully archived {email}: {message}")
                else:
                    failed_archives.append({'email': email, 'error': message})
                    current_app.logger.error(f"Failed to archive {email}: {message}")
            except Exception as e:
                current_app.logger.error(f"Exception archiving {email}: {str(e)}", exc_info=True)
                failed_archives.append({'email': email, 'error': str(e)})
        
        # Wait for export requests to complete (poll status)
        current_app.logger.info(f"Created {archived_count} export requests. Waiting for exports to complete...")
        if export_requests:
            current_app.logger.info(f"Export request details: {export_requests[:5]}")  # Log first 5
        
        # Poll export request status until all complete
        # Get list of emails that were successfully queued
        export_emails = [req['email'] for req in export_requests if 'email' in req]
        
        if export_emails:
            current_app.logger.info(f"Polling export status for {len(export_emails)} mailboxes...")
            # Wait up to 60 minutes, polling every 30 seconds
            export_status = exchange.wait_for_exports_complete(export_emails, max_wait_minutes=60, poll_interval_seconds=30)
            
            # Check if all completed
            incomplete = [email for email, info in export_status.items() if not info.get('completed', False)]
            if incomplete:
                current_app.logger.warning(f"{len(incomplete)} export(s) did not complete: {incomplete[:5]}")
            else:
                current_app.logger.info("All export requests completed successfully!")
        
        # Create zip file on Exchange server containing all PST files
        zip_file_path = None
        zip_file_downloaded = False
        zip_file_bytes = None
        
        if archived_count > 0:
            # If using local temp and archive_path is empty, we need to get the actual temp path
            actual_archive_path = archive_path
            if use_local_temp and (not archive_path or archive_path == ''):
                # Get the temp directory path that was used for exports
                get_temp_cmd = "[System.IO.Path]::Combine($env:TEMP, 'ExchangeArchives')"
                temp_success, temp_stdout, temp_stderr = exchange._run_powershell_command(get_temp_cmd)
                if temp_success and temp_stdout:
                    actual_archive_path = temp_stdout.strip()
                    current_app.logger.info(f"Resolved temp archive path: {actual_archive_path}")
                else:
                    # Fallback
                    actual_archive_path = 'C:\\Temp\\ExchangeArchives'
                    current_app.logger.warning(f"Failed to resolve temp path, using fallback: {actual_archive_path}")
            
            current_app.logger.info(f"Creating zip file from {archived_count} PST files in {actual_archive_path}")
            
            # Generate zip filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            zip_filename = f"orphaned_mailboxes_{timestamp}.zip"
            
            # Use the resolved archive path
            zip_location = actual_archive_path if actual_archive_path else archive_path
            
            # Create zip file on Exchange server (in same location as PST files or temp)
            zip_success = False
            zip_result = None
            zip_success, zip_result = exchange.zip_pst_files(actual_archive_path, zip_filename, zip_location=zip_location)
            
            if zip_success:
                zip_file_path = zip_result  # Path to zip file on Exchange server
                current_app.logger.info(f"Successfully created zip file on Exchange server: {zip_file_path}")
                
                # Download zip file if requested
                if download_zip:
                    current_app.logger.info("Downloading zip file from Exchange server...")
                    download_success, zip_bytes, download_error = exchange.download_zip_file(zip_file_path)
                    if download_success:
                        zip_file_bytes = zip_bytes
                        zip_file_downloaded = True
                        current_app.logger.info(f"Successfully downloaded zip file: {len(zip_bytes)} bytes")
                    else:
                        current_app.logger.warning(f"Failed to download zip file: {download_error}")
                
                # Transfer zip file to file store if requested
                if transfer_to_file_store and file_store_path:
                    current_app.logger.info(f"Transferring zip file to file store: {file_store_path}")
                    transfer_success, transfer_message = exchange.transfer_zip_file(zip_file_path, file_store_path)
                    if transfer_success:
                        current_app.logger.info(f"Successfully transferred zip file: {transfer_message}")
                        # Update zip_file_path to reflect transfer location
                        zip_file_path = os.path.join(file_store_path, zip_filename) if os.path.isdir(file_store_path) else file_store_path
                    else:
                        current_app.logger.warning(f"Failed to transfer zip file: {transfer_message}")
                elif transfer_to_file_store and not file_store_path:
                    current_app.logger.warning("transfer_to_file_store is True but file_store_path is not provided")
            else:
                current_app.logger.error(f"Failed to create zip file: {zip_result}")
                # DO NOT set zip_file_path if zip creation failed
                zip_file_path = None
            
            # Clean up individual PST files after zipping (keep only zip file)
            # ONLY clean up if zip was successfully created
            if zip_file_path and zip_success:
                current_app.logger.info("Cleaning up individual PST files (keeping zip file only)...")
                cleanup_success, cleanup_message = exchange.cleanup_pst_files(actual_archive_path if 'actual_archive_path' in locals() else archive_path, keep_zip=True)
                if cleanup_success:
                    current_app.logger.info(f"Cleanup successful: {cleanup_message}")
                else:
                    current_app.logger.warning(f"Cleanup warning: {cleanup_message}")
            else:
                current_app.logger.warning(f"NOT cleaning up PST files because zip creation failed. PST files may still be in: {actual_archive_path if 'actual_archive_path' in locals() else archive_path}")
        
        # Remove mailboxes if requested
        # IMPORTANT: Only remove mailboxes if zip was successfully created to avoid data loss
        removed_count = 0
        failed_removals = []
        
        if remove_after_archive and zip_file_path and zip_success:
            current_app.logger.info("Removing mailboxes after successful archive...")
            for mailbox in orphaned_mailboxes:
                email = mailbox.get('PrimarySmtpAddress')
                if not email:
                    continue
                
                # Skip if archive failed for this mailbox
                if any(f['email'] == email for f in failed_archives):
                    continue
                
                current_app.logger.info(f"Removing mailbox: {email}")
                success, message = exchange.remove_mailbox(email, permanent=False)
                
                if success:
                    removed_count += 1
                else:
                    failed_removals.append({'email': email, 'error': message})
        
        # Log the action
        log_admin_action('archive_orphaned_mailboxes', 'success' if archived_count > 0 else 'failure',
                        f"Archived {archived_count} orphaned mailboxes, removed {removed_count}, failed: {len(failed_archives)}")
        
        response_data = {
            'success': True,
            'message': f'Archived {archived_count} of {len(orphaned_mailboxes)} orphaned mailboxes',
            'archived': archived_count,
            'removed': removed_count,
            'total': len(orphaned_mailboxes),
            'failed_archives': failed_archives,
            'failed_removals': failed_removals,
            'zip_file': zip_file_path if zip_file_path else None,
            'archive_path': archive_path,
            'zip_downloaded': zip_file_downloaded
        }
        
        # If zip file was downloaded, include it in response (base64 encoded)
        if zip_file_downloaded and zip_file_bytes:
            import base64
            response_data['zip_file_base64'] = base64.b64encode(zip_file_bytes).decode('utf-8')
            response_data['zip_filename'] = zip_filename
        
        return jsonify(response_data)
        
    except Exception as e:
        current_app.logger.error(f"Error archiving orphaned mailboxes: {str(e)}")
        log_admin_action('archive_orphaned_mailboxes', 'error', str(e))
        return jsonify({'success': False, 'message': str(e)})

@main.route('/user_details/<path:user_dn>', methods=['GET', 'POST'])
@login_required
@admin_required
def user_details(user_dn):
    print(f"DEBUG: user_details called with method: {request.method}")
    print(f"DEBUG: user_dn: {user_dn}")
    
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
        print("DEBUG: Received POST to user_details for", user_dn)
        print("DEBUG: All form data:", dict(request.form))
        print("DEBUG: All request data:", dict(request.values))
        action = request.form.get('action')
        print("DEBUG: Action:", action)
        
        # Handle user attribute updates from the main form (Save Changes button)
        if action == 'save_attributes' or 'update_attributes' in request.form:
            print("DEBUG: Processing save_attributes/update_attributes request")
            print("DEBUG: All form data:", dict(request.form))
            
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
            
            # Filter out None values and show what we're actually updating
            filtered_attributes = {k: v for k, v in attributes_to_update.items() if v is not None}
            print("DEBUG: Filtered attributes to update:", filtered_attributes)
            
            print("DEBUG: save_attributes POST", attributes_to_update)
            ok, msg = update_user_attributes(user_dn, attributes_to_update, **ad_args)
            print("DEBUG: update_user_attributes result", ok, msg)
            flash(msg, 'success' if ok else 'danger')
            return redirect(url_for('main.user_details', user_dn=user_dn))
        
        # Actions that don't depend on user details form
        elif action == 'add_to_group':
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
        elif action == 'move_user':
            new_ou_dn = request.form.get('new_ou')
            if new_ou_dn:
                ok, msg = move_user_to_ou(user_dn, new_ou_dn, **ad_args)
                flash(msg, 'success' if ok else 'danger')
                return redirect(url_for('main.user_details', user_dn=user_dn))
            else:
                flash('Please select a destination OU.', 'warning')
        elif action == 'delete':
            ok, msg = ad_delete_user(user_dn, **ad_args)
            if ok:
                flash(msg, 'success')
                return redirect(url_for('main.user_search'))
            else:
                flash(msg, 'danger')
        else:
            print("DEBUG: No matching action found for:", action)
            flash('Unknown action', 'warning')

        return redirect(url_for('main.user_details', user_dn=user_dn))

    # GET request logic
    print("DEBUG: Processing GET request for user_details")
    user = get_user_details(user_dn, **ad_args)
    if not user:
        flash(f"User with DN '{user_dn}' not found.", 'danger')
        return redirect(url_for('main.user_search'))
    
    # Fetch manager display name if possible
    manager_display_name = None
    manager_dn = user.get('manager', [None])[0] if user.get('manager') else None
    if manager_dn:
        from .ad import ad_connection
        with ad_connection(**ad_args) as conn:
            if conn.search(manager_dn, '(objectClass=user)', search_scope=ldap3.BASE, attributes=['displayName']):
                entry = conn.entries[0]
                if hasattr(entry, 'displayName') and entry.displayName:
                    manager_display_name = entry.displayName.value

    user_groups = get_user_groups(user_dn, **ad_args)
    all_groups = get_all_groups(**ad_args)
    
    # Get OUs for move user functionality
    ous = list_ous(**ad_args)
    
    # Group type counts
    group_type_counts = get_group_types_for_user(user_groups, **ad_args)
    os_breakdown = get_os_breakdown(**ad_args)
    
    uac = int(user.get('userAccountControl', ['0'])[0])
    is_disabled = bool(uac & 2)
    is_locked = bool(uac & 16) # LOCKOUT bit

    # Get password information
    password_info = None
    password_expired = False
    password_expiring_soon = False
    password_never_expires = False
    days_until_reset = None
    policy = None
    
    try:
        # Get password information using the same logic as user_profile
        from app.models import get_ad_password_info, get_ad_password_policy
        
        # Get user password info
        password_info = get_ad_password_info(user_dn)
        
        if password_info:
            # Get domain password policy
            policy = get_ad_password_policy(user_dn)
            
            if policy and password_info.get('pwd_last_set'):
                # Calculate password status
                if policy.get('max_age_days', 0) == 0:
                    password_never_expires = True
                else:
                    days_until_reset = password_info.get('days_until_expiry')
                    
                    if days_until_reset is not None:
                        if days_until_reset < 0:
                            password_expired = True
                        elif days_until_reset <= 14:  # Default warning threshold
                            password_expiring_soon = True
    except Exception as e:
        print(f"Error getting password info: {e}")
        # Continue without password info if there's an error

    return render_template(
        'user_details.html', 
        user=user, 
        user_groups=user_groups,
        all_groups=all_groups,
        ous=ous,
        is_disabled=is_disabled,
        is_locked=is_locked,
        group_type_counts=group_type_counts,
        os_breakdown=os_breakdown,
        manager_display_name=manager_display_name,
        password_info=password_info,
        password_expired=password_expired,
        password_expiring_soon=password_expiring_soon,
        password_never_expires=password_never_expires,
        days_until_reset=days_until_reset,
        policy=policy
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
    
    # Check Exchange configuration
    exchange_config = get_exchange_config()
    exchange_enabled = exchange_config and exchange_config.get('enabled', False)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        display_name = request.form['display_name']
        mail = request.form.get('mail', '').strip()
        target_ou = request.form.get('target_ou', '')
        given_name = request.form.get('given_name', '').strip()
        surname = request.form.get('surname', '').strip()
        title = request.form.get('title', '').strip()
        department = request.form.get('department', '').strip()
        telephone_number = request.form.get('telephone_number', '').strip()
        create_mailbox = request.form.get('create_mailbox') == 'on' and exchange_enabled
        selected_groups = request.form.getlist('groups')  # Get list of selected group DNs
        
        # Use target_ou if provided, otherwise None (will use base_dn)
        target_ou = target_ou if target_ou else None
        
        # Create user
        ok, msg, user_dn = ad_create_user(
            username, 
            password, 
            display_name, 
            mail=mail if mail else None,
            target_ou=target_ou,
            given_name=given_name if given_name else None,
            surname=surname if surname else None,
            title=title if title else None,
            department=department if department else None,
            telephone_number=telephone_number if telephone_number else None,
            server=config['ad_server'],
            port=config['ad_port'],
            bind_user=config['ad_bind_dn'],
            bind_password=config['ad_password'],
            base_dn=config['ad_base_dn']
        )
        
        if ok and user_dn:
            # Add user to selected groups
            group_messages = []
            for group_dn in selected_groups:
                if group_dn:
                    group_ok, group_msg = add_user_to_group(user_dn, group_dn, **ad_args)
                    if group_ok:
                        group_messages.append(f"Added to group: {group_msg}")
                    else:
                        group_messages.append(f"Group add warning: {group_msg}")
            
            # Create mailbox if requested and Exchange is configured
            mailbox_message = ""
            if create_mailbox and mail:
                try:
                    exchange = ExchangeManager(
                        exchange_server=exchange_config['exchange_server'],
                        username=exchange_config['username'],
                        password=exchange_config['password'],
                        domain=exchange_config['domain']
                    )
                    mailbox_ok, mailbox_msg = exchange.create_mailbox(mail, display_name)
                    if mailbox_ok:
                        mailbox_message = f" Mailbox created: {mailbox_msg}"
                    else:
                        mailbox_message = f" Mailbox creation failed: {mailbox_msg}"
                except Exception as e:
                    mailbox_message = f" Mailbox creation error: {str(e)}"
            
            # Combine messages
            full_message = msg
            if group_messages:
                full_message += " " + " ".join(group_messages)
            if mailbox_message:
                full_message += mailbox_message
            
            log_user_action('create', username, 'success', {
                'display_name': display_name, 
                'mail': mail, 
                'target_ou': target_ou,
                'groups': selected_groups,
                'mailbox_created': create_mailbox
            })
            flash(full_message, 'success')
            return redirect(url_for('main.user_search'))
        else:
            log_user_action('create', username, 'failure', {'display_name': display_name, 'mail': mail, 'target_ou': target_ou})
            flash(msg, 'danger')
    
    # Get available OUs and groups for the form
    ous = list_ous(**ad_args)
    all_groups = get_all_groups(**ad_args)
    
    # Filter OUs to get departments (OUs under "Sunray Users")
    # Get the primary users OU from config
    org_ous = get_organization_ous()
    primary_users_ou = org_ous.get('primary_users_ou', 'OU=Sunray Users,OU=Sunray,DC=sunray,DC=internal')
    
    # Filter OUs that are direct children of the primary users OU
    departments = []
    seen_departments = set()
    
    # OUs are returned as dictionaries with 'dn' and 'name' keys
    for ou in ous:
        ou_dn = ou.get('dn', '') if isinstance(ou, dict) else (ou.dn if hasattr(ou, 'dn') else str(ou))
        ou_name = ou.get('name', '') if isinstance(ou, dict) else (ou.name if hasattr(ou, 'name') else '')
        
        # Check if this OU is directly under the primary users OU
        # The OU DN should be: OU=DepartmentName,OU=Sunray Users,OU=Sunray,DC=...
        if primary_users_ou.lower() in ou_dn.lower():
            # Extract the first OU name (the department name)
            ou_parts = ou_dn.split(',')
            department_name = None
            
            for part in ou_parts:
                part = part.strip()
                if part.startswith('OU='):
                    ou_name_from_dn = part.replace('OU=', '')
                    # Skip the primary users OU itself and common structural OUs
                    skip_names = ['sunray users', 'users', 'disabled users', 'service accounts', 
                                 'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                                 'admins', 'managers', 'management', 'western gaming']
                    if ou_name_from_dn.lower() not in skip_names:
                        department_name = ou_name_from_dn
                        break
            
            # Use the extracted name or the OU name attribute
            if department_name:
                final_name = department_name
            elif ou_name:
                # Check if the OU name itself should be skipped
                skip_names = ['sunray users', 'users', 'disabled users', 'service accounts', 
                             'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                             'admins', 'managers', 'management', 'western gaming']
                if ou_name.lower() not in skip_names:
                    final_name = ou_name
                else:
                    continue
            else:
                continue
            
            # Only add if we haven't seen this department before
            if final_name and final_name.lower() not in seen_departments:
                departments.append({'name': final_name, 'dn': ou_dn})
                seen_departments.add(final_name.lower())
    
    # Sort departments alphabetically
    departments.sort(key=lambda x: x['name'].lower())
    
    return render_template('create_user.html', 
                         ous=ous, 
                         base_dn=config['ad_base_dn'],
                         groups=all_groups,
                         departments=departments,
                         exchange_enabled=exchange_enabled)

@main.route('/admin/managers', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_managers():
    """Manage department managers and direct reports"""
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
    
    # Get departments
    org_ous = get_organization_ous()
    primary_users_ou = org_ous.get('primary_users_ou', 'OU=Sunray Users,OU=Sunray,DC=sunray,DC=internal')
    ous = list_ous(**ad_args)
    
    # Filter departments (same logic as create_user)
    departments = []
    seen_departments = set()
    for ou in ous:
        ou_dn = ou.get('dn', '') if isinstance(ou, dict) else (ou.dn if hasattr(ou, 'dn') else str(ou))
        ou_name = ou.get('name', '') if isinstance(ou, dict) else (ou.name if hasattr(ou, 'name') else '')
        
        if primary_users_ou.lower() in ou_dn.lower():
            ou_parts = ou_dn.split(',')
            department_name = None
            for part in ou_parts:
                part = part.strip()
                if part.startswith('OU='):
                    ou_name_from_dn = part.replace('OU=', '')
                    skip_names = ['sunray users', 'users', 'disabled users', 'service accounts', 
                                 'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                                 'admins', 'managers', 'management', 'western gaming']
                    if ou_name_from_dn.lower() not in skip_names:
                        department_name = ou_name_from_dn
                        break
            
            if department_name:
                final_name = department_name
            elif ou_name:
                skip_names = ['sunray users', 'users', 'disabled users', 'service accounts', 
                             'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                             'admins', 'managers', 'management', 'western gaming']
                if ou_name.lower() not in skip_names:
                    final_name = ou_name
                else:
                    continue
            else:
                continue
            
            if final_name and final_name.lower() not in seen_departments:
                departments.append({'name': final_name, 'dn': ou_dn})
                seen_departments.add(final_name.lower())
    
    departments.sort(key=lambda x: x['name'].lower())
    
    # Get existing department managers
    dept_managers = {}
    for dept_mgr in DepartmentManager.query.all():
        dept_managers[dept_mgr.department] = dept_mgr
    
    # Get all direct reports
    direct_reports = UserDirectReport.query.all()
    
    # Group direct reports by manager
    reports_by_manager = {}
    for report in direct_reports:
        if report.manager_username not in reports_by_manager:
            reports_by_manager[report.manager_username] = []
        reports_by_manager[report.manager_username].append(report)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'set_department_manager':
            department = request.form.get('department')
            manager_username = request.form.get('manager_username')
            
            if not department or not manager_username:
                flash('Department and manager are required.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get manager details from AD
            users = search_users(manager_username, **ad_args)
            if not users:
                flash(f'Manager user "{manager_username}" not found.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            manager = users[0]
            manager_dn = manager.get('distinguishedName') or manager.get('dn')
            manager_display = manager.get('displayName') or manager.get('cn') or manager_username
            
            # Update or create department manager
            dept_mgr = DepartmentManager.query.filter_by(department=department).first()
            if dept_mgr:
                dept_mgr.manager_username = manager_username
                dept_mgr.manager_dn = manager_dn
                dept_mgr.manager_display_name = manager_display
                dept_mgr.updated_at = datetime.now(timezone.utc)
            else:
                dept_mgr = DepartmentManager(
                    department=department,
                    manager_username=manager_username,
                    manager_dn=manager_dn,
                    manager_display_name=manager_display
                )
                db.session.add(dept_mgr)
            
            db.session.commit()
            flash(f'Manager for {department} set to {manager_display}.', 'success')
            return redirect(url_for('main.manage_managers'))
        
        elif action == 'assign_direct_report':
            manager_username = request.form.get('manager_username')
            employee_username = request.form.get('employee_username')
            
            if not manager_username or not employee_username:
                flash('Manager and employee are required.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get manager and employee details from AD
            managers = search_users(manager_username, **ad_args)
            employees = search_users(employee_username, **ad_args)
            
            if not managers:
                flash(f'Manager user "{manager_username}" not found.', 'danger')
                return redirect(url_for('main.manage_managers'))
            if not employees:
                flash(f'Employee user "{employee_username}" not found.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            manager = managers[0]
            employee = employees[0]
            manager_dn = manager.get('distinguishedName') or manager.get('dn')
            employee_dn = employee.get('distinguishedName') or employee.get('dn')
            employee_display = employee.get('displayName') or employee.get('cn') or employee_username
            employee_dept = employee.get('department') or ''
            
            # Check if same department
            manager_dept = manager.get('department') or ''
            is_same_dept = (employee_dept.lower() == manager_dept.lower())
            
            # Update or create direct report
            direct_report = UserDirectReport.query.filter_by(employee_username=employee_username).first()
            if direct_report:
                direct_report.manager_username = manager_username
                direct_report.manager_dn = manager_dn
                direct_report.employee_dn = employee_dn
                direct_report.employee_display_name = employee_display
                direct_report.department = employee_dept
                direct_report.is_same_department = is_same_dept
                direct_report.updated_at = datetime.now(timezone.utc)
            else:
                direct_report = UserDirectReport(
                    manager_username=manager_username,
                    manager_dn=manager_dn,
                    employee_username=employee_username,
                    employee_dn=employee_dn,
                    employee_display_name=employee_display,
                    department=employee_dept,
                    is_same_department=is_same_dept
                )
                db.session.add(direct_report)
            
            # Update AD manager attribute
            set_user_manager(employee_dn, manager_dn, **ad_args)
            
            db.session.commit()
            flash(f'Direct report assigned: {employee_display} -> {manager.get("displayName", manager_username)}.', 'success')
            return redirect(url_for('main.manage_managers'))
        
        elif action == 'bulk_assign_department':
            department = request.form.get('department')
            
            if not department:
                flash('Department is required.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get department manager
            dept_mgr = DepartmentManager.query.filter_by(department=department).first()
            if not dept_mgr:
                flash(f'No manager assigned for {department}. Please assign a manager first.', 'warning')
                return redirect(url_for('main.manage_managers'))
            
            # Find department OU
            dept_ou = None
            for dept in departments:
                if dept['name'] == department:
                    dept_ou = dept['dn']
                    break
            
            if not dept_ou:
                flash(f'Could not find OU for department {department}.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get all users in this department OU
            dept_users = search_users('', status_filter='all', **ad_args)
            dept_users = [u for u in dept_users if dept_ou.lower() in (u.get('distinguishedName') or u.get('dn') or '').lower()]
            
            manager_dn = dept_mgr.manager_dn
            assigned_count = 0
            skipped_count = 0
            
            for user in dept_users:
                user_dn = user.get('distinguishedName') or user.get('dn')
                username = user.get('sAMAccountName') or user.get('username')
                display_name = user.get('displayName') or user.get('cn') or username
                
                # Skip if already assigned
                existing = UserDirectReport.query.filter_by(employee_username=username).first()
                if existing:
                    skipped_count += 1
                    continue
                
                # Create direct report record
                direct_report = UserDirectReport(
                    manager_username=dept_mgr.manager_username,
                    manager_dn=manager_dn,
                    employee_username=username,
                    employee_dn=user_dn,
                    employee_display_name=display_name,
                    department=department,
                    is_same_department=True
                )
                db.session.add(direct_report)
                
                # Update AD manager attribute
                set_user_manager(user_dn, manager_dn, **ad_args)
                assigned_count += 1
            
            db.session.commit()
            flash(f'Bulk assignment complete: {assigned_count} users assigned, {skipped_count} already assigned.', 'success')
            return redirect(url_for('main.manage_managers'))
        
        elif action == 'remove_direct_report':
            report_id = request.form.get('report_id')
            if report_id:
                report = UserDirectReport.query.get(report_id)
                if report:
                    # Remove manager from AD
                    remove_user_manager(report.employee_dn, **ad_args)
                    db.session.delete(report)
                    db.session.commit()
                    flash('Direct report removed.', 'success')
            return redirect(url_for('main.manage_managers'))
    
    return render_template('manage_managers.html',
                         departments=departments,
                         dept_managers=dept_managers,
                         reports_by_manager=reports_by_manager)

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
            result = save_bug_report(report)
            
            if result and result.get('filename'):
                # Check if GitHub issue was created
                if result.get('github_issue_url'):
                    flash(f'Bug report submitted successfully! GitHub issue created: {result["github_issue_url"]}', 'success')
                    log_admin_action('bug_report_submitted', 'success', {
                        'filename': result['filename'],
                        'github_issue_url': result['github_issue_url'],
                        'description': description[:100]
                    })
                else:
                    flash(f'Bug report saved locally. {result.get("github_issue_message", "GitHub issue creation failed")}', 'warning')
                    log_admin_action('bug_report_submitted', 'partial', {
                        'filename': result['filename'],
                        'github_error': result.get('github_issue_message', 'Unknown error'),
                        'description': description[:100]
                    })
            else:
                error_msg = result.get('github_issue_message', 'Failed to save bug report') if result else 'Failed to save bug report'
                flash(f'Error: {error_msg}', 'danger')
                log_admin_action('bug_report_submitted', 'failure', {'description': description[:100], 'error': error_msg})
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

@main.route('/admin/disable_user', methods=['POST'])
@login_required
@admin_required
def disable_user_route():
    """Disable a user from the user search table"""
    config = get_ad_config()
    if not config:
        return jsonify({'success': False, 'message': 'AD not configured. Please complete setup first.'}), 400
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    user_dn = request.form.get('user_dn')
    if not user_dn:
        return jsonify({'success': False, 'message': 'No user specified.'}), 400
    
    ok, msg = ad_disable_user(user_dn, **ad_args)
    return jsonify({'success': ok, 'message': msg})

@main.route('/admin/enable_user', methods=['POST'])
@login_required
@admin_required
def enable_user_route():
    """Enable a user from the user search table"""
    config = get_ad_config()
    if not config:
        return jsonify({'success': False, 'message': 'AD not configured. Please complete setup first.'}), 400
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    user_dn = request.form.get('user_dn')
    if not user_dn:
        return jsonify({'success': False, 'message': 'No user specified.'}), 400
    
    ok, msg = ad_enable_user(user_dn, **ad_args)
    return jsonify({'success': ok, 'message': msg})

@main.route('/admin/move_user', methods=['POST'])
@login_required
@admin_required
def move_user_route():
    """Move a user to a different OU"""
    config = get_ad_config()
    if not config:
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            return jsonify({'success': False, 'message': 'AD not configured. Please complete setup first.'}), 400
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    user_dn = request.form.get('user_dn')
    new_ou_dn = request.form.get('new_ou') or request.form.get('new_ou_dn')
    
    if not user_dn or not new_ou_dn:
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            return jsonify({'success': False, 'message': 'Missing required parameters.'}), 400
        flash('Missing required parameters.', 'danger')
        return redirect(url_for('main.user_search'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    ok, msg = move_user_to_ou(user_dn, new_ou_dn, **ad_args)
    
    # Check if this is an AJAX request
    if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
        return jsonify({'success': ok, 'message': msg})
    
    # Regular form submission
    flash(msg, 'success' if ok else 'danger')
    
    # Preserve current search parameters when redirecting
    redirect_params = {}
    if request.form.get('query'):
        redirect_params['query'] = request.form['query']
    if request.form.get('status_filter') and request.form['status_filter'] != 'all':
        redirect_params['status_filter'] = request.form['status_filter']
    if request.form.get('exclude_ous'):
        redirect_params['exclude_ous'] = request.form['exclude_ous']
    if request.form.get('sort_by'):
        redirect_params['sort_by'] = request.form['sort_by']
    if request.form.get('sort_order'):
        redirect_params['sort_order'] = request.form['sort_order']
    if request.form.get('page'):
        redirect_params['page'] = request.form['page']
    
    return redirect(url_for('main.user_search', **redirect_params))

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
    from .ad import ad_connection, get_admin_groups
    users = []
    admin_groups = get_admin_groups()
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'memberOf', 'objectClass'])
        for entry in conn.entries:
            # Only process real users (not computer accounts)
            is_user = False
            debug_msg = ''
            if hasattr(entry, 'objectClass') and entry.objectClass.value:
                object_classes = entry.objectClass.value
                if isinstance(object_classes, list):
                    is_user = 'user' in object_classes and 'computer' not in object_classes
                    debug_msg = f"objectClass(list): {object_classes} -> is_user={is_user}"
                else:
                    object_classes_str = str(object_classes).lower()
                    is_user = 'user' in object_classes_str and 'computer' not in object_classes_str
                    debug_msg = f"objectClass(str): {object_classes_str} -> is_user={is_user}"
            else:
                debug_msg = f"No objectClass for {getattr(entry, 'sAMAccountName', 'UNKNOWN')}"
            if not is_user:
                print(f"DEBUG: Skipping {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
                continue
            print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
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
    ad_config = get_ad_config()
    branding = get_branding_config()
    admin_groups = get_admin_groups()
    
    # Load main config.json for debug setting
    import json
    import os
    from .credentials import get_credential
    main_config = {}
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                main_config = json.load(f)
        except:
            pass
    
    # Check if GitHub token is configured
    github_token_configured = bool(get_credential('github_token', ''))
    
    if request.method == 'POST':
        # Handle branding updates
        if 'action' in request.form and request.form['action'] == 'save_branding':
            branding_data = {
                'company_name': request.form.get('company_name', 'GEEKS-AD-Plus'),
                'logo_url': request.form.get('logo_url', ''),
                'primary_color': request.form.get('primary_color', '#ffd700'),
                'secondary_color': request.form.get('secondary_color', '#ffb347'),
                'custom_css': request.form.get('custom_css', '')
            }
            save_branding_config(branding_data)
            flash('Branding settings updated successfully!', 'success')
            return redirect(url_for('main.admin_settings'))
        
        # Handle admin group additions
        elif 'action' in request.form and request.form['action'] == 'add_admin_group':
            new_group = request.form.get('new_group', '').strip()
            if new_group and new_group not in admin_groups:
                admin_groups.append(new_group)
                set_admin_groups(admin_groups)
                flash(f'Added admin group: {new_group}', 'success')
            elif new_group in admin_groups:
                flash(f'Admin group already exists: {new_group}', 'warning')
            return redirect(url_for('main.admin_settings'))
        
        # Handle admin group removals
        elif 'action' in request.form and request.form['action'] == 'remove_admin_group':
            remove_group = request.form.get('remove_group', '').strip()
            if remove_group in admin_groups:
                admin_groups.remove(remove_group)
                set_admin_groups(admin_groups)
                flash(f'Removed admin group: {remove_group}', 'info')
            return redirect(url_for('main.admin_settings'))
        
        # Handle debug settings updates
        elif 'action' in request.form and request.form['action'] == 'save_debug_settings':
            # Update config.json with debug settings
            import json
            import os
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
            
            try:
                # Load existing config
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        config_data = json.load(f)
                else:
                    config_data = {}
                
                # Update debug setting
                config_data['debug'] = 'debug_mode' in request.form
                
                # Also update branding for UI settings
                branding_data = branding.copy() if branding else {}
                branding_data['flash_countdown'] = 'flash_countdown' in request.form
                branding_data['debug_mode'] = 'debug_mode' in request.form
                
                # Flash timeout setting
                try:
                    flash_timeout = int(request.form.get('flash_timeout', 180))
                    flash_timeout = max(30, min(600, flash_timeout))  # Clamp between 30-600 seconds
                    branding_data['flash_timeout'] = flash_timeout
                except ValueError:
                    branding_data['flash_timeout'] = 180
                
                # Log level setting
                log_level = request.form.get('log_level', 'INFO')
                if log_level in ['INFO', 'DEBUG', 'WARNING', 'ERROR']:
                    branding_data['log_level'] = log_level
                
                # Save config.json
                with open(config_path, 'w') as f:
                    json.dump(config_data, f, indent=2)
                
                # Save branding config
                save_branding_config(branding_data)
                flash('Debug settings updated successfully!', 'success')
            except Exception as e:
                current_app.logger.error(f"Error saving debug settings: {e}")
                flash(f'Error saving debug settings: {str(e)}', 'danger')
            
            return redirect(url_for('main.admin_settings'))
        
        # Handle homepage settings updates
        elif 'action' in request.form and request.form['action'] == 'save_homepage':
            # Update branding config with homepage settings
            branding_data = branding.copy() if branding else {}
            
            # General homepage settings
            branding_data['homepage_title'] = request.form.get('homepage_title', 'Welcome to GEEKS-AD-Plus')
            branding_data['homepage_subtitle'] = request.form.get('homepage_subtitle', 'This portal allows you to reset your Active Directory password securely and manage your organization\'s AD infrastructure.')
            
            # Password reset card (always shown)
            branding_data['password_reset_title'] = request.form.get('password_reset_title', 'Password Reset')
            branding_data['password_reset_description'] = request.form.get('password_reset_description', 'Securely reset your Active Directory password with self-service functionality.')
            
            # Bug reporting card
            branding_data['show_bug_reporting'] = 'show_bug_reporting' in request.form
            branding_data['bug_reporting_title'] = request.form.get('bug_reporting_title', 'Bug Reporting')
            branding_data['bug_reporting_description'] = request.form.get('bug_reporting_description', 'Report issues and bugs with detailed system information for quick resolution.')
            branding_data['bug_reporting_link'] = request.form.get('bug_reporting_link', '/bug-report')
            
            # Custom feature cards
            branding_data['show_custom_card_1'] = 'show_custom_card_1' in request.form
            branding_data['custom_card_1_icon'] = request.form.get('custom_card_1_icon', 'fas fa-info')
            branding_data['custom_card_1_title'] = request.form.get('custom_card_1_title', '')
            branding_data['custom_card_1_description'] = request.form.get('custom_card_1_description', '')
            branding_data['custom_card_1_link'] = request.form.get('custom_card_1_link', '')
            
            branding_data['show_custom_card_2'] = 'show_custom_card_2' in request.form
            branding_data['custom_card_2_icon'] = request.form.get('custom_card_2_icon', 'fas fa-info')
            branding_data['custom_card_2_title'] = request.form.get('custom_card_2_title', '')
            branding_data['custom_card_2_description'] = request.form.get('custom_card_2_description', '')
            branding_data['custom_card_2_link'] = request.form.get('custom_card_2_link', '')
            
            save_branding_config(branding_data)
            flash('Homepage configuration saved successfully!', 'success')
            return redirect(url_for('main.admin_settings'))
        
        # Handle GitHub token configuration
        elif 'action' in request.form and request.form['action'] == 'save_github_token':
            from .credentials import set_credential, save_credentials
            import os
            
            github_token = request.form.get('github_token', '').strip()
            github_repo = request.form.get('github_repo', '').strip()
            
            # Only update token if a new one was provided (not the placeholder)
            if github_token and github_token != '***CONFIGURED***':
                if set_credential('github_token', github_token):
                    flash('GitHub token saved securely!', 'success')
                else:
                    flash('Error saving GitHub token', 'danger')
            
            # Update repository in config.json
            if github_repo:
                config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
                try:
                    if os.path.exists(config_path):
                        with open(config_path, 'r') as f:
                            config_data = json.load(f)
                    else:
                        config_data = {}
                    
                    config_data['github_repo'] = github_repo
                    
                    with open(config_path, 'w') as f:
                        json.dump(config_data, f, indent=2)
                    
                    flash('GitHub repository updated!', 'success')
                except Exception as e:
                    current_app.logger.error(f"Error saving GitHub repo: {e}")
                    flash(f'Error saving GitHub repository: {str(e)}', 'danger')
            
            return redirect(url_for('main.admin_settings'))
        
        # Handle password policy updates
        elif 'action' in request.form and request.form['action'] == 'save_password_policy':
            # Update branding config with password policy settings
            branding_data = branding.copy() if branding else {}
            
            # Password policy settings
            branding_data['password_max_age_days'] = int(request.form.get('max_password_age', 90))
            branding_data['password_warning_days'] = int(request.form.get('max_password_age', 90)) // 6  # Default to 1/6 of max age
            branding_data['password_min_length'] = int(request.form.get('min_password_length', 8))
            branding_data['password_require_complexity'] = request.form.get('password_complexity', 'medium') != 'low'
            branding_data['password_history_count'] = int(request.form.get('password_history', 5))
            
            save_branding_config(branding_data)
            flash('Password policy saved successfully!', 'success')
            return redirect(url_for('main.admin_settings'))
    
    return render_template('admin_settings.html', 
                         config=main_config,  # Use main_config which includes debug setting
                         ad_config=ad_config,  # Pass AD config separately
                         branding=branding,
                         github_token_configured=github_token_configured, 
                         admin_groups=admin_groups)

@main.route('/test-form', methods=['GET', 'POST'])
def test_form():
    if request.method == 'POST':
        print("DEBUG: Test form submitted")
        print("DEBUG: Form data:", dict(request.form))
        return f"Form submitted successfully! Data: {dict(request.form)}"
    return '''
    <html>
    <body>
        <h1>Test Form</h1>
        <form method="POST">
            <input type="text" name="test_field" value="test value">
            <button type="submit">Submit Test</button>
        </form>
    </body>
    </html>
    '''

@main.route('/test-user-details')
def test_user_details():
    return render_template('test_user_details.html')

@main.route('/admin/get_all_groups')
@login_required
@admin_required
def get_all_groups_route():
    """Get all AD groups for searchable dropdown"""
    config = get_ad_config()
    if not config:
        return jsonify({'error': 'AD not configured'}), 400
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    try:
        groups = get_all_groups(**ad_args)
        # Convert Group objects to simple dictionaries
        group_list = [{'name': group.name, 'dn': group.dn} for group in groups]
        return jsonify({'groups': group_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/admin/get_flash_config')
def get_flash_config():
    """Get flash message configuration for JavaScript"""
    branding = get_branding_config()
    return jsonify({
        'flash_countdown': branding.get('flash_countdown', False),
        'flash_timeout': branding.get('flash_timeout', 180),
        'debug_mode': branding.get('debug_mode', False)
    })

@main.route('/login', methods=['GET', 'POST'])
def unified_login():
    """Unified login page for both admin and regular users"""
    if current_user.is_authenticated:
        # Check if user has a view mode set, otherwise use their role
        view_mode = session.get('view_mode', session.get('role', 'user'))
        if view_mode == 'admin':
            return redirect(url_for('main.dashboard'))
        else:
            return redirect(url_for('main.dashboard'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            error = 'Username and password are required.'
        else:
            # First try local admin login
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                login_user(admin)
                session['role'] = 'admin'
                session['view_mode'] = 'admin'
                log_login(username, 'success', {'method': 'local_admin'})
                flash('Logged in as administrator.', 'success')
                return redirect(url_for('main.dashboard'))
            
            # Try AD authentication
            config = get_ad_config()
            if config:
                ok, msg = authenticate_user(username, password)
                if ok:
                    # Check if user is in admin group
                    is_admin_user = is_user_in_admin_group(
                        username,
                        server=config['ad_server'],
                        port=config['ad_port'],
                        bind_user=config['ad_bind_dn'],
                        bind_password=config['ad_password'],
                        base_dn=config['ad_base_dn']
                    )
                    
                    if is_admin_user:
                        # Create or update AD admin record
                        admin = Admin.query.filter_by(username=username).first()
                        if not admin:
                            admin = Admin(username=username)
                            admin.password_hash = ''  # No local password for AD users
                            db.session.add(admin)
                            db.session.commit()
                        
                        login_user(admin)
                        session['role'] = 'admin'
                        session['view_mode'] = 'admin'
                        log_login(username, 'success', {'method': 'ad_admin'})
                        flash('Logged in as administrator.', 'success')
                        return redirect(url_for('main.dashboard'))
                    else:
                        # Regular user
                        user = Admin.query.filter_by(username=username).first()
                        if not user:
                            user = Admin(username=username)
                            user.password_hash = ''  # No local password for AD users
                            db.session.add(user)
                            db.session.commit()
                        
                        login_user(user)
                        session['role'] = 'user'
                        session['view_mode'] = 'user'
                        log_login(username, 'success', {'method': 'ad_user'})
                        flash('Logged in successfully.', 'success')
                        return redirect(url_for('main.dashboard'))
                else:
                    log_login(username, 'failure', {'reason': 'invalid_credentials'})
                    error = msg or 'Invalid credentials.'
            else:
                log_login(username, 'failure', {'reason': 'ad_not_configured'})
                error = 'Active Directory not configured.'
    
    return render_template('login.html', error=error)

@main.route('/dashboard')
@login_required
def dashboard():
    """Unified dashboard that shows admin or user view based on role and view mode"""
    role = session.get('role', 'user')
    view_mode = session.get('view_mode', role)
    
    if view_mode == 'admin':
        return admin_dashboard_content()
    else:
        return user_dashboard_content()

def admin_dashboard_content():
    """Generate content for admin dashboard"""
    from app.ad import get_ad_statistics, get_ad_health_status
    from app.models import AuditLog, Task, PasswordReset
    from datetime import datetime, timezone, timedelta
    import json
    from .audit import get_audit_stats
    
    # Get audit statistics
    audit_stats = get_audit_stats(days=30)
    
    # Get AD configuration
    config = get_ad_config()
    if not config:
        return render_template('admin_dashboard.html', 
                             error="AD not configured. Please complete setup first.",
                             stats=None, health=None, recent_activity=None, 
                             pending_tasks=None, password_stats=None, branding=get_branding_config(), audit_stats=None)
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    # Get AD statistics and health status
    success, stats = get_ad_statistics(**ad_args)
    health = get_ad_health_status(**ad_args)
    
    # Get recent activity (last 24 hours, fallback to most recent if empty)
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    recent_activity = AuditLog.query.filter(
        AuditLog.timestamp >= yesterday
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()
    print(f"DEBUG: Recent logs in last 24h: {len(recent_activity)}")
    if not recent_activity:
        recent_activity = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
        print(f"DEBUG: Fallback to most recent logs: {len(recent_activity)}")
    
    # Get pending tasks
    pending_tasks = Task.query.filter(
        Task.status == 'pending'
    ).order_by(Task.assigned_at.desc()).limit(5).all()
    
    # Get password statistics with caching (cache for 5 minutes)
    cache_key = 'password_stats_cache'
    cache_timeout = 300  # 5 minutes
    
    # Check if we have cached password stats
    from flask import g
    if hasattr(g, cache_key):
        cached_data = getattr(g, cache_key)
        if cached_data and (datetime.now(timezone.utc) - cached_data['timestamp']).total_seconds() < cache_timeout:
            password_stats = cached_data['stats']
        else:
            password_stats = get_password_status_stats()
            setattr(g, cache_key, {
                'stats': password_stats,
                'timestamp': datetime.now(timezone.utc)
            })
    else:
        password_stats = get_password_status_stats()
        setattr(g, cache_key, {
            'stats': password_stats,
            'timestamp': datetime.now(timezone.utc)
        })
    
    # Load branding config
    branding = get_branding_config()
    
    return render_template('admin_dashboard.html', 
                         ad_stats=stats if success else None, 
                         ad_health=health,
                         recent_activity=recent_activity,
                         pending_tasks=pending_tasks,
                         password_stats=password_stats,
                         branding=branding,
                         audit_stats=audit_stats,
                         logs=recent_activity  # For compatibility with the template
    )

def user_dashboard_content():
    """User dashboard content - extracted from original user_dashboard route"""
    from app.models import Task, SecurityQuestion
    
    # Get user's tasks
    tasks = Task.query.filter_by(username=current_user.username).order_by(
        Task.priority.desc(), 
        Task.assigned_at.desc()
    ).all()
    
    # Get user's security question status
    security_question = SecurityQuestion.query.filter_by(username=current_user.username).first()
    
    # Get AD user information
    config = get_ad_config()
    user_info = None
    if config:
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        # Search for user in AD
        users = search_users(current_user.username, **ad_args)
        if users:
            user_info = users[0]
    
    # Task statistics
    pending_tasks = [t for t in tasks if t.status == 'pending']
    completed_tasks = [t for t in tasks if t.status == 'completed']
    overdue_tasks = [t for t in pending_tasks if t.is_overdue()]
    
    return render_template('user_dashboard.html', 
                         tasks=tasks,
                         pending_tasks=pending_tasks,
                         completed_tasks=completed_tasks,
                         overdue_tasks=overdue_tasks,
                         security_question=security_question,
                         user_info=user_info)

@main.route('/switch_view')
@login_required
def switch_view():
    """Switch between admin and user view modes"""
    role = session.get('role', 'user')
    
    # Only allow admins to switch views
    if role == 'admin':
        current_view = session.get('view_mode', 'admin')
        new_view = 'user' if current_view == 'admin' else 'admin'
        session['view_mode'] = new_view
        flash(f'Switched to {new_view.title()} view.', 'info')
    else:
        flash('You do not have permission to switch views.', 'warning')
    
    return redirect(url_for('main.dashboard'))

@main.route('/logout')
@login_required
def unified_logout():
    """Unified logout for both admin and user"""
    if current_user.is_authenticated:
        log_login(current_user.username, 'success', {'action': 'logout'})
    
    # Clear session data
    session.pop('role', None)
    session.pop('view_mode', None)
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.home'))

@main.route('/user/logout')
@login_required
def user_logout():
    """Legacy user logout - redirect to unified logout"""
    return redirect(url_for('main.unified_logout'))

# Update the old dashboard routes to redirect to the new unified dashboard
@main.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Legacy admin dashboard - redirect to unified dashboard"""
    return redirect(url_for('main.dashboard'))

@main.route('/user/dashboard')
@login_required
def user_dashboard():
    """Legacy user dashboard - redirect to unified dashboard"""
    return redirect(url_for('main.dashboard'))

@main.route('/user/complete-task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    """Complete a task assigned to the current user"""
    from app.models import Task
    
    task = Task.query.get_or_404(task_id)
    
    # Verify the task belongs to the current user
    if task.username != current_user.username:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Verify the task is pending
    if task.status != 'pending':
        return jsonify({'success': False, 'message': 'Task is not pending'}), 400
    
    # Mark task as completed
    task.status = 'completed'
    task.completed_at = datetime.utcnow()
    
    try:
        db.session.commit()
        
        # Log the action
        from .audit import log_event
        log_event(
            action='task_completed',
            details=f'Completed task: {task.title}',
            result='success',
            user=current_user.username
        )
        
        return jsonify({'success': True, 'message': 'Task completed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error completing task'}), 500

@main.route('/admin/assign-task', methods=['GET', 'POST'])
@admin_required
def assign_task():
    """Admin interface to assign tasks to users"""
    from app.models import Task
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        task_type = request.form.get('task_type', '').strip()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'medium').strip()
        due_date_str = request.form.get('due_date', '').strip()
        
        if not username or not task_type or not title:
            flash('Username, task type, and title are required.', 'error')
            return redirect(url_for('main.assign_task'))
        
        # Verify user exists in AD
        config = get_ad_config()
        if config:
            ad_args = {
                'server': config['ad_server'],
                'port': config['ad_port'],
                'bind_user': config['ad_bind_dn'],
                'bind_password': config['ad_password'],
                'base_dn': config['ad_base_dn']
            }
            
            users = search_users(username, **ad_args)
            if not users:
                flash(f'User "{username}" not found in Active Directory.', 'error')
                return redirect(url_for('main.assign_task'))
        
        # Parse due date
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid due date format. Use YYYY-MM-DD.', 'error')
                return redirect(url_for('main.assign_task'))
        
        # Create task
        task = Task(
            username=username,
            task_type=task_type,
            title=title,
            description=description,
            priority=priority,
            due_date=due_date,
            assigned_by=current_user.username
        )
        
        try:
            db.session.add(task)
            db.session.commit()
            
            # Log the action
            from .audit import log_event
            log_event(
                action='task_assigned',
                details=f'Assigned task "{title}" to {username}',
                result='success',
                user=current_user.username
            )
            
            flash(f'Task "{title}" assigned to {username} successfully.', 'success')
            return redirect(url_for('main.admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error assigning task.', 'error')
            return redirect(url_for('main.assign_task'))
    
    # Get list of users for assignment
    config = get_ad_config()
    users = []
    if config:
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        # Get all users (limit to first 100 for performance)
        users = search_users('', **ad_args)[:100]
    
    return render_template('admin_assign_task.html', users=users)

@main.route('/admin/tasks')
@admin_required
def admin_tasks():
    """Admin view of all tasks"""
    from app.models import Task
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    username_filter = request.args.get('username', '').strip()
    
    # Build query
    query = Task.query
    
    if status_filter:
        query = query.filter(Task.status == status_filter)
    if priority_filter:
        query = query.filter(Task.priority == priority_filter)
    if username_filter:
        query = query.filter(Task.username.ilike(f'%{username_filter}%'))
    
    # Order by priority and assignment date
    tasks = query.order_by(Task.priority.desc(), Task.assigned_at.desc()).all()
    
    # Get statistics
    total_tasks = Task.query.count()
    pending_tasks = Task.query.filter_by(status='pending').count()
    completed_tasks = Task.query.filter_by(status='completed').count()
    overdue_tasks = sum(1 for t in Task.query.filter_by(status='pending').all() if t.is_overdue())
    
    return render_template('admin_tasks.html', 
                         tasks=tasks,
                         total_tasks=total_tasks,
                         pending_tasks=pending_tasks,
                         completed_tasks=completed_tasks,
                         overdue_tasks=overdue_tasks,
                         status_filter=status_filter,
                         priority_filter=priority_filter,
                         username_filter=username_filter) 

@main.route('/admin/delete-task/<int:task_id>', methods=['POST'])
@admin_required
def delete_task(task_id):
    """Delete a task (admin only)"""
    from app.models import Task
    
    task = Task.query.get_or_404(task_id)
    
    try:
        # Log the action before deletion
        from .audit import log_event
        log_event(
            action='task_deleted',
            details=f'Deleted task: {task.title} (assigned to {task.username})',
            result='success',
            user=current_user.username
        )
        
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Task deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error deleting task'}), 500 

@main.route('/user/profile')
@login_required
def user_profile():
    """User profile page showing password reset history and account information"""
    from app.models import PasswordReset, SecurityQuestion
    from app.models import get_password_reset_history, calculate_days_until_reset, is_password_expired, is_password_expiring_soon, get_password_policy
    from app.models import get_ad_password_info, get_comprehensive_password_history
    
    # Get AD password information
    ad_password_info = get_ad_password_info(current_user.username)
    
    # Get user's password reset history (local + AD context)
    password_history = get_comprehensive_password_history(current_user.username)
    
    # Get password policy and status
    policy = get_password_policy()
    
    # Use AD information if available, fall back to local calculations
    if ad_password_info:
        days_until_reset = ad_password_info['days_until_expiry'] if ad_password_info['days_until_expiry'] is not None else 0
        password_expired = ad_password_info['password_status'] == 'expired'
        password_expiring_soon = ad_password_info['password_status'] == 'expiring_soon'
        password_never_expires = ad_password_info['password_never_expires']
        account_disabled = ad_password_info['account_disabled']
        is_locked_out = ad_password_info['is_locked_out']
        pwd_must_change = ad_password_info['pwd_must_change']
        pwd_can_change = ad_password_info['pwd_can_change']
        
        # Use AD domain policy if available
        if ad_password_info['domain_policy']:
            policy.update(ad_password_info['domain_policy'])
    else:
        # Fall back to local calculations
        days_until_reset = calculate_days_until_reset(current_user.username)
        password_expired = is_password_expired(current_user.username)
        password_expiring_soon = is_password_expiring_soon(current_user.username)
        password_never_expires = False
        account_disabled = False
        is_locked_out = False
        pwd_must_change = False
        pwd_can_change = True
    
    # Get user's security question status
    from app.models import get_user_security_questions
    security_questions = get_user_security_questions(current_user.username)
    
    # Get AD user information
    config = get_ad_config()
    user_info = None
    if config:
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        # Search for user in AD
        users = search_users(current_user.username, **ad_args)
        if users:
            user_info = users[0]
    
    return render_template('user_profile.html', 
                         reset_history=password_history['combined_history'],
                         ad_password_info=ad_password_info,
                         password_history_info=password_history,
                         days_until_reset=days_until_reset,
                         password_expired=password_expired,
                         password_expiring_soon=password_expiring_soon,
                         password_never_expires=password_never_expires,
                         account_disabled=account_disabled,
                         is_locked_out=is_locked_out,
                         pwd_must_change=pwd_must_change,
                         pwd_can_change=pwd_can_change,
                         policy=policy,
                         security_questions=security_questions,
                         user_info=user_info)

@main.route('/admin/profile')
@admin_required
def admin_profile():
    """Admin profile page showing password reset history and account information"""
    from app.models import PasswordReset, SecurityQuestion
    from app.models import get_password_reset_history, calculate_days_until_reset, is_password_expired, is_password_expiring_soon, get_password_policy
    from app.models import get_ad_password_info, get_comprehensive_password_history
    
    # Get AD password information
    ad_password_info = get_ad_password_info(current_user.username)
    
    # Get admin's password reset history (local + AD context)
    password_history = get_comprehensive_password_history(current_user.username)
    
    # Get password policy and status
    policy = get_password_policy()
    
    # Use AD information if available, fall back to local calculations
    if ad_password_info:
        days_until_reset = ad_password_info['days_until_expiry'] if ad_password_info['days_until_expiry'] is not None else 0
        password_expired = ad_password_info['password_status'] == 'expired'
        password_expiring_soon = ad_password_info['password_status'] == 'expiring_soon'
        password_never_expires = ad_password_info['password_never_expires']
        account_disabled = ad_password_info['account_disabled']
        is_locked_out = ad_password_info['is_locked_out']
        pwd_must_change = ad_password_info['pwd_must_change']
        pwd_can_change = ad_password_info['pwd_can_change']
        
        # Use AD domain policy if available
        if ad_password_info['domain_policy']:
            policy.update(ad_password_info['domain_policy'])
    else:
        # Fall back to local calculations
        days_until_reset = calculate_days_until_reset(current_user.username)
        password_expired = is_password_expired(current_user.username)
        password_expiring_soon = is_password_expiring_soon(current_user.username)
        password_never_expires = False
        account_disabled = False
        is_locked_out = False
        pwd_must_change = False
        pwd_can_change = True
    
    # Get admin's security question status
    from app.models import get_user_security_questions
    security_questions = get_user_security_questions(current_user.username)
    
    # Get AD user information
    config = get_ad_config()
    user_info = None
    if config:
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        # Search for user in AD
        users = search_users(current_user.username, **ad_args)
        if users:
            user_info = users[0]
    
    return render_template('admin_profile.html', 
                         reset_history=password_history['combined_history'],
                         ad_password_info=ad_password_info,
                         password_history_info=password_history,
                         days_until_reset=days_until_reset,
                         password_expired=password_expired,
                         password_expiring_soon=password_expiring_soon,
                         password_never_expires=password_never_expires,
                         account_disabled=account_disabled,
                         is_locked_out=is_locked_out,
                         pwd_must_change=pwd_must_change,
                         pwd_can_change=pwd_can_change,
                         policy=policy,
                         security_questions=security_questions,
                         user_info=user_info)

@main.route('/user/setup-security-question', methods=['GET', 'POST'])
@login_required
def setup_security_question():
    """Setup security questions for password recovery"""
    from app.models import SecurityQuestion, get_user_security_questions, create_or_update_security_question, has_complete_security_questions, PREDEFINED_SECURITY_QUESTIONS
    
    # Generate CAPTCHA for form (moved to beginning to ensure it's always available)
    import random
    captcha_num1 = random.randint(1, 10)
    captcha_num2 = random.randint(1, 10)
    captcha_answer = str(captcha_num1 + captcha_num2)
    
    # Get existing security questions
    existing_questions = get_user_security_questions(current_user.username)
    
    if request.method == 'POST':
        # Validate CAPTCHA
        captcha_answer = request.form.get('captcha_answer', '').strip()
        expected_captcha = request.form.get('expected_captcha', '').strip()
        
        if not captcha_answer or captcha_answer != expected_captcha:
            flash('CAPTCHA answer is incorrect.', 'error')
            return render_template('setup_security_question.html', 
                                 existing_questions=existing_questions,
                                 predefined_questions=PREDEFINED_SECURITY_QUESTIONS,
                                 captcha_num1=captcha_num1,
                                 captcha_num2=captcha_num2,
                                 captcha_answer=captcha_answer)
        
        # Process all 3 questions
        questions_updated = 0
        try:
            for i in range(1, 4):
                question_text = request.form.get(f'question_{i}', '').strip()
                answer_text = request.form.get(f'answer_{i}', '').strip()
                
                if question_text and answer_text:
                    # Create or update the question
                    question_obj = create_or_update_security_question(
                        current_user.username, 
                        i, 
                        question_text, 
                        answer_text
                    )
                    db.session.add(question_obj)
                    questions_updated += 1
            
            if questions_updated > 0:
                db.session.commit()
                
                # Log the action
                from .audit import log_event
                log_event(
                    action='security_question_setup',
                    details=f'{questions_updated} security question(s) {"updated" if existing_questions else "set up"}',
                    result='success',
                    user=current_user.username,
                    ip_address=request.remote_addr
                )
                
                if has_complete_security_questions(current_user.username):
                    flash('All 3 security questions set up successfully!', 'success')
                else:
                    flash(f'{questions_updated} security question(s) saved. Please complete all 3 questions for enhanced security.', 'warning')
                
                # Always redirect to dashboard after successful setup/update
                return redirect(url_for('main.user_dashboard'))
            else:
                flash('Please provide at least one question and answer.', 'error')
                
        except Exception as e:
            db.session.rollback()
            flash('Error setting up security questions. Please try again.', 'error')
            return render_template('setup_security_question.html', 
                                 existing_questions=existing_questions,
                                 predefined_questions=PREDEFINED_SECURITY_QUESTIONS,
                                 captcha_num1=captcha_num1,
                                 captcha_num2=captcha_num2,
                                 captcha_answer=captcha_answer)
    
    return render_template('setup_security_question.html', 
                         existing_questions=existing_questions,
                         predefined_questions=PREDEFINED_SECURITY_QUESTIONS,
                         captcha_num1=captcha_num1,
                         captcha_num2=captcha_num2,
                         captcha_answer=captcha_answer)

@main.route('/user/reset-password', methods=['GET', 'POST'])
@login_required
def user_reset_password():
    """Password reset for logged-in users"""
    from app.models import PasswordReset, get_next_security_question, has_complete_security_questions
    
    # Get the next security question to ask (cycling through available questions)
    last_used_question = request.args.get('last_question', type=int)
    security_question = get_next_security_question(current_user.username, last_used_question)
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        security_answer = request.form.get('security_answer', '').strip()
        
        # Validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('user_reset_password.html', 
                                 security_question=security_question,
                                 user_info=get_user_info(current_user.username),
                                 requirements=get_dynamic_password_requirements(current_user.username))
        
        # Validate new password
        if not new_password or new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('user_reset_password.html', 
                                 security_question=security_question,
                                 user_info=get_user_info(current_user.username),
                                 requirements=get_dynamic_password_requirements(current_user.username))
        
        # Validate security answer if question exists
        if security_question and not security_question.check_answer(security_answer):
            flash('Security answer is incorrect.', 'error')
            return render_template('user_reset_password.html', 
                                 security_question=security_question,
                                 user_info=get_user_info(current_user.username),
                                 requirements=get_dynamic_password_requirements(current_user.username))
        
        # Validate password policy
        from app.models import validate_password_against_ad_policy, get_dynamic_password_requirements
        
        # Get dynamic password requirements from AD
        requirements = get_dynamic_password_requirements(current_user.username)
        
        # Validate password against AD policy
        is_valid, errors = validate_password_against_ad_policy(new_password, current_user.username)
        
        if not is_valid:
            error_message = "Password does not meet requirements:\n" + "\n".join(f"• {error}" for error in errors)
            flash(error_message, 'error')
            return render_template('user_reset_password.html', 
                                 security_question=security_question,
                                 user_info=get_user_info(current_user.username),
                                 requirements=requirements)
        
        try:
            # Update password in AD
            config = get_ad_config()
            if config:
                ad_args = {
                    'server': config['ad_server'],
                    'port': config['ad_port'],
                    'bind_user': config['ad_bind_dn'],
                    'bind_password': config['ad_password'],
                    'base_dn': config['ad_base_dn']
                }
                
                # Search for user in AD
                users = search_users(current_user.username, **ad_args)
                if users:
                    user_dn = users[0]['dn']
                    
                    # Change password in AD
                    success = change_user_password(user_dn, current_password, new_password, **ad_args)
                    
                    if success:
                        # Log the password reset
                        reset_record = PasswordReset(
                            username=current_user.username,
                            reset_by=current_user.username,
                            method='self',
                            ip_address=request.remote_addr,
                            user_agent=request.headers.get('User-Agent'),
                            success=True,
                            notes='Password reset by logged-in user'
                        )
                        db.session.add(reset_record)
                        db.session.commit()
                        
                        # Log the action
                        from .audit import log_event
                        log_event(
                            action='password_reset',
                            details='Password reset by logged-in user',
                            result='success',
                            user=current_user.username,
                            ip_address=request.remote_addr
                        )
                        
                        flash('Password updated successfully!', 'success')
                        return redirect(url_for('main.user_dashboard'))
                    else:
                        flash('Failed to update password in Active Directory. Please contact your administrator.', 'error')
                else:
                    flash('User not found in Active Directory.', 'error')
            else:
                flash('Active Directory configuration not available.', 'error')
                
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating password: {str(e)}', 'error')
        
        return render_template('user_reset_password.html', 
                             security_question=security_question,
                             user_info=get_user_info(current_user.username),
                             requirements=get_dynamic_password_requirements(current_user.username))
    
    # Get user info for display
    user_info = get_user_info(current_user.username)
    
    # Get dynamic password requirements
    requirements = get_dynamic_password_requirements(current_user.username)
    
    return render_template('user_reset_password.html', 
                         security_question=security_question,
                         user_info=user_info,
                         requirements=requirements)

def get_user_info(username):
    """Helper function to get user info from AD"""
    config = get_ad_config()
    if config:
        ad_args = {
            'server': config['ad_server'],
            'port': config['ad_port'],
            'bind_user': config['ad_bind_dn'],
            'bind_password': config['ad_password'],
            'base_dn': config['ad_base_dn']
        }
        
        users = search_users(username, **ad_args)
        if users:
            return users[0]
    return None

@main.route('/test-password-info/<path:user_dn>')
def test_password_info(user_dn):
    """Test route to verify password info functionality without authentication"""
    from app.models import get_ad_password_info, get_ad_password_policy, get_last_password_reset
    
    try:
        # Extract username from DN
        username = user_dn.split(',')[0].replace('CN=', '') if ',' in user_dn else user_dn
        
        # Test the password info function
        password_info = get_ad_password_info(user_dn)
        policy = get_ad_password_policy(user_dn)
        
        result = {
            'user_dn': user_dn,
            'password_info_found': password_info is not None,
            'policy_found': policy is not None,
            'password_info': password_info,
            'policy': policy
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'user_dn': user_dn
        }), 500

def get_password_status_stats():
    """Get password status statistics for all users in AD - OPTIMIZED VERSION"""
    from datetime import datetime, timezone, timedelta
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
    from flask import request, session
    
    config = get_ad_config()
    if not config:
        return None
    
    # Check if debug is enabled
    debug_enabled = request.args.get('debug') == '1' or session.get('dashboard_debug')
    
    try:
        # Connect to AD once
        server = Server(config['ad_server'], port=int(config['ad_port']), get_info=ALL)
        conn = Connection(server, 
                         user=config['ad_bind_dn'], 
                         password=config['ad_password'], 
                         auto_bind=True)
        
        # Get domain password policy first
        domain_dn = config['ad_base_dn']
        conn.search(domain_dn, '(objectClass=domain)', 
                   attributes=['maxPwdAge', 'minPwdLength', 'pwdHistoryLength'])
        
        max_pwd_age_days = 90  # Default
        if conn.entries:
            domain = conn.entries[0]
            if domain.maxPwdAge and domain.maxPwdAge.value != 0:
                max_age = domain.maxPwdAge.value
                if isinstance(max_age, timedelta):
                    max_pwd_age_days = int(max_age.total_seconds() // 86400)
                elif isinstance(max_age, (int, float)):
                    max_pwd_age_days = abs(max_age) // (10**7 * 60 * 60 * 24)
        
        # Search in primary users OU (matching user search behavior)
        from .ad import get_organization_ous
        org_ous = get_organization_ous(base_dn)
        primary_users_base = org_ous['primary_users_ou']
        disabled_users_ou = org_ous['disabled_users_ou']
        
        # Default excluded OUs (matching user search behavior)
        default_exclude_ous = [disabled_users_ou, org_ous['service_accounts_ou'], org_ous['internal_tools_ou']]
        
        # Get all users with password attributes - search only in primary users OU
        conn.search(primary_users_base, 
                   '(objectClass=user)', 
                   search_scope=SUBTREE,
                   attributes=['sAMAccountName', 'displayName', 'distinguishedName', 
                             'pwdLastSet', 'userAccountControl', 'whenChanged', 'whenCreated', 'objectClass'])
        
        password_stats = {
            'valid': 0,
            'expiring_soon': 0,
            'expired': 0,
            'never_expires': 0,
            'unknown': 0,
            'total': 0
        }
        
        now = datetime.now(timezone.utc)
        
        for entry in conn.entries:
            # Only process real users (not computer accounts)
            is_user = False
            debug_msg = ''
            if hasattr(entry, 'objectClass') and entry.objectClass.value:
                object_classes = entry.objectClass.value
                if isinstance(object_classes, list):
                    is_user = 'user' in object_classes and 'computer' not in object_classes
                    debug_msg = f"objectClass(list): {object_classes} -> is_user={is_user}"
                else:
                    object_classes_str = str(object_classes).lower()
                    is_user = 'user' in object_classes_str and 'computer' not in object_classes_str
                    debug_msg = f"objectClass(str): {object_classes_str} -> is_user={is_user}"
            else:
                debug_msg = f"No objectClass for {getattr(entry, 'sAMAccountName', 'UNKNOWN')}"
            if not is_user:
                if debug_enabled:
                    print(f"DEBUG: Skipping {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
                continue
            
            # Filter out excluded OUs (matching user search behavior)
            user_dn = entry.distinguishedName.value
            should_exclude = False
            
            # Always exclude users in Disabled Users OU
            if disabled_users_ou in user_dn or 'OU=Disabled Users' in user_dn:
                should_exclude = True
                if debug_enabled:
                    print(f"DEBUG: Excluding user in Disabled Users OU: {user_dn}")
            
            # Check additional excluded OUs
            if not should_exclude:
                for excluded_ou in default_exclude_ous:
                    if excluded_ou.strip() and excluded_ou.strip() in user_dn:
                        should_exclude = True
                        if debug_enabled:
                            print(f"DEBUG: Excluding user in {excluded_ou}: {user_dn}")
                        break
            
            if should_exclude:
                continue
            
            if debug_enabled:
                print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
            
            # Parse user account control
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
            account_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
            
            # Skip disabled accounts
            if account_disabled:
                if debug_enabled:
                    print(f"DEBUG: Skipping disabled account: {getattr(entry, 'sAMAccountName', 'UNKNOWN')}")
                continue
            
            password_stats['total'] += 1
            password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
            # Parse password last set
            pwd_last_set = None
            if entry.pwdLastSet and entry.pwdLastSet.value and entry.pwdLastSet.value != 0:
                ad_time = entry.pwdLastSet.value
                if isinstance(ad_time, datetime):
                    pwd_last_set = ad_time
                elif isinstance(ad_time, int) and ad_time > 0:
                    seconds_since_1601 = ad_time // (10**7)
                    seconds_since_1970 = seconds_since_1601 - 11644473600
                    pwd_last_set = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
            # Use whenChanged as fallback if more recent than pwdLastSet
            if entry.whenChanged and entry.whenChanged.value:
                when_changed = entry.whenChanged.value
                if isinstance(when_changed, datetime):
                    if pwd_last_set is None or when_changed > pwd_last_set:
                        pwd_last_set = when_changed
                elif isinstance(when_changed, int) and when_changed > 0:
                    seconds_since_1601 = when_changed // (10**7)
                    seconds_since_1970 = seconds_since_1601 - 11644473600
                    when_changed_dt = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                    if pwd_last_set is None or when_changed_dt > pwd_last_set:
                        pwd_last_set = when_changed_dt
            # Calculate password status
            user_data = {
                'dn': entry.distinguishedName.value,
                'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                'displayName': entry.displayName.value if entry.displayName else ''
            }
            user_status = None
            if password_never_expires:
                user_status = 'never_expires'
                password_stats['never_expires'] += 1
            elif pwd_last_set:
                days_since_last_set = (now - pwd_last_set).days
                days_until_expiry = max_pwd_age_days - days_since_last_set
                if days_until_expiry <= 0:
                    user_status = 'expired'
                    password_stats['expired'] += 1
                elif days_until_expiry <= 14:  # Default warning threshold
                    user_status = 'expiring_soon'
                    password_stats['expiring_soon'] += 1
                else:
                    user_status = 'valid'
                    password_stats['valid'] += 1
            else:
                user_status = 'unknown'
                password_stats['unknown'] += 1
            if debug_enabled:
                print(f"DEBUG: user={user_data['username']} status={user_status}")
        
        conn.unbind()
        return password_stats
        
    except Exception as e:
        print(f"Error getting password status stats: {e}")
        return None

@main.route('/admin/drilldown/passwords/<status>')
@login_required
@admin_required
def drilldown_passwords(status):
    """Drilldown view for password status categories - OPTIMIZED VERSION"""
    from datetime import datetime, timezone, timedelta
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
    
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    debug_enabled = request.args.get('debug') == '1' or session.get('dashboard_debug')
    if 'debug' in request.args:
        session['dashboard_debug'] = request.args.get('debug') == '1'
    
    # Simple caching for drilldown data (cache for 2 minutes)
    cache_key = f'drilldown_cache_{status}'
    cache_timeout = 120  # 2 minutes
    
    from flask import g
    if hasattr(g, cache_key):
        cached_data = getattr(g, cache_key)
        if cached_data and (datetime.now(timezone.utc) - cached_data['timestamp']).total_seconds() < cache_timeout:
            if request.args.get('modal') == '1':
                return render_template('drilldown_passwords.html', users=cached_data['users'], status=status, title=cached_data['title'], modal=True)
            else:
                return render_template('drilldown_passwords.html', users=cached_data['users'], status=status, title=cached_data['title'], modal=False)
    
    try:
        # Connect to AD once
        server = Server(config['ad_server'], port=int(config['ad_port']), get_info=ALL)
        conn = Connection(server, 
                         user=config['ad_bind_dn'], 
                         password=config['ad_password'], 
                         auto_bind=True)
        
        # Get domain password policy first
        domain_dn = config['ad_base_dn']
        conn.search(domain_dn, '(objectClass=domain)', 
                   attributes=['maxPwdAge', 'minPwdLength', 'pwdHistoryLength'])
        
        max_pwd_age_days = 90  # Default
        if conn.entries:
            domain = conn.entries[0]
            if domain.maxPwdAge and domain.maxPwdAge.value != 0:
                max_age = domain.maxPwdAge.value
                if isinstance(max_age, timedelta):
                    max_pwd_age_days = int(max_age.total_seconds() // 86400)
                elif isinstance(max_age, (int, float)):
                    max_pwd_age_days = abs(max_age) // (10**7 * 60 * 60 * 24)
        
        # Search in primary users OU (matching user search behavior)
        from .ad import get_organization_ous
        org_ous = get_organization_ous(base_dn)
        primary_users_base = org_ous['primary_users_ou']
        disabled_users_ou = org_ous['disabled_users_ou']
        
        # Default excluded OUs (matching user search behavior)
        default_exclude_ous = [disabled_users_ou, org_ous['service_accounts_ou'], org_ous['internal_tools_ou']]
        
        # Get all users with password attributes - search only in primary users OU
        conn.search(primary_users_base, 
                   '(objectClass=user)', 
                   search_scope=SUBTREE,
                   attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail',
                             'pwdLastSet', 'userAccountControl', 'whenChanged', 'whenCreated',
                             'lockoutTime', 'accountExpires', 'lastLogon', 'lastLogonTimestamp', 'objectClass'])
        
        filtered_users = []
        now = datetime.now(timezone.utc)
        
        for entry in conn.entries:
            # Only process real users (not computer accounts)
            is_user = False
            debug_msg = ''
            if hasattr(entry, 'objectClass') and entry.objectClass.value:
                object_classes = entry.objectClass.value
                if isinstance(object_classes, list):
                    is_user = 'user' in object_classes and 'computer' not in object_classes
                    debug_msg = f"objectClass(list): {object_classes} -> is_user={is_user}"
                else:
                    object_classes_str = str(object_classes).lower()
                    is_user = 'user' in object_classes_str and 'computer' not in object_classes_str
                    debug_msg = f"objectClass(str): {object_classes_str} -> is_user={is_user}"
            else:
                debug_msg = f"No objectClass for {getattr(entry, 'sAMAccountName', 'UNKNOWN')}"
            if not is_user:
                if debug_enabled:
                    print(f"DEBUG: Skipping {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
                continue
            
            # Filter out excluded OUs (matching user search behavior)
            user_dn = entry.distinguishedName.value
            should_exclude = False
            
            # Always exclude users in Disabled Users OU
            if disabled_users_ou in user_dn or 'OU=Disabled Users' in user_dn:
                should_exclude = True
                if debug_enabled:
                    print(f"DEBUG: Excluding user in Disabled Users OU: {user_dn}")
            
            # Check additional excluded OUs
            if not should_exclude:
                for excluded_ou in default_exclude_ous:
                    if excluded_ou.strip() and excluded_ou.strip() in user_dn:
                        should_exclude = True
                        if debug_enabled:
                            print(f"DEBUG: Excluding user in {excluded_ou}: {user_dn}")
                        break
            
            if should_exclude:
                continue
            
            if debug_enabled:
                print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
            
            # Parse user account control
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
            account_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
            
            # Skip disabled accounts
            if account_disabled:
                if debug_enabled:
                    print(f"DEBUG: Skipping disabled account: {getattr(entry, 'sAMAccountName', 'UNKNOWN')}")
                continue
            
            password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
            
            # Parse password last set
            pwd_last_set = None
            if entry.pwdLastSet and entry.pwdLastSet.value and entry.pwdLastSet.value != 0:
                ad_time = entry.pwdLastSet.value
                if isinstance(ad_time, datetime):
                    pwd_last_set = ad_time
                elif isinstance(ad_time, int) and ad_time > 0:
                    seconds_since_1601 = ad_time // (10**7)
                    seconds_since_1970 = seconds_since_1601 - 11644473600
                    pwd_last_set = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
            
            # Use whenChanged as fallback if more recent than pwdLastSet
            if entry.whenChanged and entry.whenChanged.value:
                when_changed = entry.whenChanged.value
                if isinstance(when_changed, datetime):
                    if pwd_last_set is None or when_changed > pwd_last_set:
                        pwd_last_set = when_changed
                elif isinstance(when_changed, int) and when_changed > 0:
                    seconds_since_1601 = when_changed // (10**7)
                    seconds_since_1970 = seconds_since_1601 - 11644473600
                    when_changed_dt = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                    if pwd_last_set is None or when_changed_dt > pwd_last_set:
                        pwd_last_set = when_changed_dt
            
            # Calculate password status
            user_status = 'unknown'
            days_until_expiry = None
            days_since_last_set = None
            
            if password_never_expires:
                user_status = 'never_expires'
            elif pwd_last_set:
                days_since_last_set = (now - pwd_last_set).days
                days_until_expiry = max_pwd_age_days - days_since_last_set
                
                if days_until_expiry <= 0:
                    user_status = 'expired'
                elif days_until_expiry <= 14:  # Warning threshold
                    user_status = 'expiring_soon'
                else:
                    user_status = 'valid'
            
            # Only include users matching the requested status
            if user_status == status:
                # Parse additional attributes for display
                lockout_time = None
                if entry.lockoutTime and entry.lockoutTime.value and entry.lockoutTime.value != 0:
                    ad_time = entry.lockoutTime.value
                    if isinstance(ad_time, datetime):
                        lockout_time = ad_time
                    elif isinstance(ad_time, int) and ad_time > 0:
                        seconds_since_1601 = ad_time // (10**7)
                        seconds_since_1970 = seconds_since_1601 - 11644473600
                        lockout_time = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                
                account_expires = None
                if entry.accountExpires and entry.accountExpires.value and entry.accountExpires.value != 0:
                    ad_time = entry.accountExpires.value
                    if isinstance(ad_time, datetime):
                        account_expires = ad_time
                    elif isinstance(ad_time, int) and ad_time > 0:
                        seconds_since_1601 = ad_time // (10**7)
                        seconds_since_1970 = seconds_since_1601 - 11644473600
                        account_expires = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                
                last_logon = None
                if entry.lastLogon and entry.lastLogon.value and entry.lastLogon.value != 0:
                    ad_time = entry.lastLogon.value
                    if isinstance(ad_time, datetime):
                        last_logon = ad_time
                    elif isinstance(ad_time, int) and ad_time > 0:
                        seconds_since_1601 = ad_time // (10**7)
                        seconds_since_1970 = seconds_since_1601 - 11644473600
                        last_logon = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                    # If it's a string, try to parse as int
                    elif isinstance(ad_time, str):
                        try:
                            ad_time_int = int(ad_time)
                            if ad_time_int > 0:
                                seconds_since_1601 = ad_time_int // (10**7)
                                seconds_since_1970 = seconds_since_1601 - 11644473600
                                last_logon = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                        except Exception:
                            last_logon = None
                
                last_logon_timestamp = None
                if entry.lastLogonTimestamp and entry.lastLogonTimestamp.value and entry.lastLogonTimestamp.value != 0:
                    ad_time = entry.lastLogonTimestamp.value
                    if isinstance(ad_time, datetime):
                        last_logon_timestamp = ad_time
                    elif isinstance(ad_time, int) and ad_time > 0:
                        seconds_since_1601 = ad_time // (10**7)
                        seconds_since_1970 = seconds_since_1601 - 11644473600
                        last_logon_timestamp = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                
                # Create user data with password info
                user_data = {
                    'dn': entry.distinguishedName.value,
                    'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                    'displayName': entry.displayName.value if entry.displayName else '',
                    'mail': entry.mail.value if entry.mail else '',
                    'ou': '',  # You can parse OU from DN if needed
                    'password_info': {
                        'pwd_last_set': pwd_last_set,
                        'days_since_last_set': days_since_last_set,
                        'days_until_expiry': days_until_expiry,
                        'password_status': user_status,
                        'password_never_expires': password_never_expires,
                        'lockout_time': lockout_time,
                        'account_expires': account_expires,
                        'last_logon_timestamp': last_logon_timestamp
                    }
                }
                
                filtered_users.append(user_data)
        
        conn.unbind()
        
        # Sort users appropriately
        if status in ['expiring_soon', 'expired']:
            filtered_users.sort(key=lambda x: x['password_info']['days_until_expiry'] or 999)
        elif status == 'valid':
            filtered_users.sort(key=lambda x: x['password_info']['days_until_expiry'] or 0, reverse=True)
        else:
            filtered_users.sort(key=lambda x: x['username'])
        
        status_titles = {
            'valid': 'Valid Passwords',
            'expiring_soon': 'Passwords Expiring Soon',
            'expired': 'Expired Passwords',
            'never_expires': 'Passwords Never Expire',
            'unknown': 'Unknown Password Status'
        }
        
        title = status_titles.get(status, status.title())
        
        # Cache the results
        setattr(g, cache_key, {
            'users': filtered_users,
            'title': title,
            'timestamp': datetime.now(timezone.utc)
        })
        
        if request.args.get('modal') == '1':
            return render_template('drilldown_passwords_table.html', users=filtered_users, status=status, title=title, modal=True)
        else:
            return render_template('drilldown_passwords.html', users=filtered_users, status=status, title=title, modal=False)
        
    except Exception as e:
        print(f"Error in drilldown_passwords: {e}")
        flash(f'Error retrieving password data: {e}', 'error')
        return redirect(url_for('main.admin_dashboard'))

@main.route('/test-password-stats')
def test_password_stats():
    """Test route to verify password status statistics functionality"""
    try:
        password_stats = get_password_status_stats()
        
        if password_stats:
            result = {
                'total_users': password_stats['total'],
                'valid_passwords': len(password_stats['valid']),
                'expiring_soon': len(password_stats['expiring_soon']),
                'expired_passwords': len(password_stats['expired']),
                'never_expires': len(password_stats['never_expires']),
                'unknown': len(password_stats['unknown']),
                'sample_users': {
                    'valid': [user['username'] for user in password_stats['valid'][:3]],
                    'expiring_soon': [user['username'] for user in password_stats['expiring_soon'][:3]],
                    'expired': [user['username'] for user in password_stats['expired'][:3]]
                }
            }
        else:
            result = {'error': 'Failed to get password statistics'}
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/admin/drilldown/userstatus/<status>')
@login_required
@admin_required
def drilldown_userstatus(status):
    from datetime import datetime, timezone
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
    
    config = get_ad_config()
    if not config:
        flash('AD not configured. Please complete setup first.', 'warning')
        return redirect(url_for('main.setup'))
    
    debug_enabled = request.args.get('debug') == '1' or session.get('dashboard_debug')
    if 'debug' in request.args:
        session['dashboard_debug'] = request.args.get('dashboard_debug') == '1'
    
    filtered_users = []
    try:
        server = Server(config['ad_server'], get_info=ALL)
        conn = Connection(server, user=config['ad_bind_dn'], password=config['ad_password'], auto_bind=True)
        
        conn.search(config['ad_base_dn'], '(objectClass=user)', search_scope=SUBTREE,
                   attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail', 'userAccountControl', 'lockoutTime', 'lastLogon', 'objectClass'])
        
        for entry in conn.entries:
            # Only process real users (not computer accounts)
            is_user = False
            debug_msg = ''
            if hasattr(entry, 'objectClass') and entry.objectClass.value:
                object_classes = entry.objectClass.value
                if isinstance(object_classes, list):
                    is_user = 'user' in object_classes and 'computer' not in object_classes
                    debug_msg = f"objectClass(list): {object_classes} -> is_user={is_user}"
                else:
                    object_classes_str = str(object_classes).lower()
                    is_user = 'user' in object_classes_str and 'computer' not in object_classes_str
                    debug_msg = f"objectClass(str): {object_classes_str} -> is_user={is_user}"
            else:
                debug_msg = f"No objectClass for {getattr(entry, 'sAMAccountName', 'UNKNOWN')}"
            
            if not is_user:
                if debug_enabled:
                    print(f"DEBUG: Skipping {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
                continue
            
            if debug_enabled:
                print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
            
            # Determine user status
            uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 0
            # Robust lockoutTime check
            locked = False
            if hasattr(entry, 'lockoutTime') and entry.lockoutTime and entry.lockoutTime.value:
                lockout_val = entry.lockoutTime.value
                if isinstance(lockout_val, int):
                    locked = lockout_val != 0
                elif isinstance(lockout_val, str):
                    try:
                        locked = int(lockout_val) != 0
                    except Exception:
                        locked = False
                elif isinstance(lockout_val, datetime):
                    # If it's a datetime, treat as locked if not epoch
                    locked = lockout_val.timestamp() > 0
            expired_password = False  # You may want to add logic for this if available
            enabled = not (uac & 2)
            disabled = (uac & 2) != 0
            
            # Map to status label
            user_status = None
            if locked:
                user_status = 'locked'
            elif disabled:
                user_status = 'disabled'
            elif expired_password:
                user_status = 'expired_password'
            elif enabled:
                user_status = 'enabled'
            else:
                user_status = 'unknown'
            
            if user_status != status:
                continue
            
            # Last logon
            last_logon = None
            if hasattr(entry, 'lastLogon') and entry.lastLogon and entry.lastLogon.value:
                ad_time = entry.lastLogon.value
                if isinstance(ad_time, datetime):
                    last_logon = ad_time
                elif isinstance(ad_time, int) and ad_time > 0:
                    seconds_since_1601 = ad_time // (10**7)
                    seconds_since_1970 = seconds_since_1601 - 11644473600
                    last_logon = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                # If it's a string, try to parse as int
                elif isinstance(ad_time, str):
                    try:
                        ad_time_int = int(ad_time)
                        if ad_time_int > 0:
                            seconds_since_1601 = ad_time_int // (10**7)
                            seconds_since_1970 = seconds_since_1601 - 11644473600
                            last_logon = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
                    except Exception:
                        last_logon = None
            
            user_data = {
                'dn': entry.distinguishedName.value,
                'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                'displayName': entry.displayName.value if entry.displayName else '',
                'mail': entry.mail.value if entry.mail else '',
                'ou': '',  # You can parse OU from DN if needed
                'status': user_status,
                'last_logon': last_logon
            }
            
            filtered_users.append(user_data)
        
        conn.unbind()
        
        status_titles = {
            'enabled': 'Enabled Users',
            'disabled': 'Disabled Users',
            'locked': 'Locked Users',
            'expired_password': 'Users with Expired Passwords',
            'unknown': 'Unknown Status Users'
        }
        
        title = status_titles.get(status, status.title())
        
        if request.args.get('modal') == '1':
            return render_template('drilldown_userstatus_table.html', users=filtered_users, status=status, title=title, modal=True)
        else:
            return render_template('drilldown_userstatus.html', users=filtered_users, status=status, title=title, modal=False)
            
    except Exception as e:
        print(f"Error in drilldown_userstatus: {e}")
        flash(f'Error retrieving user status data: {e}', 'error')
        return redirect(url_for('main.admin_dashboard'))

# License entry route removed - no license server available

@main.route('/admin/csv-import', methods=['GET', 'POST'])
@login_required
@admin_required
def csv_import():
    """CSV import for employee data with AD comparison"""
    if request.method == 'POST':
        print("DEBUG: CSV import POST request received")
        
        if 'csv_file' not in request.files:
            print("DEBUG: No csv_file in request.files")
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['csv_file']
        print(f"DEBUG: File received: {file.filename}")
        
        if file.filename == '':
            print("DEBUG: Empty filename")
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if not file.filename.endswith('.csv'):
            print("DEBUG: Not a CSV file")
            flash('Please upload a CSV file', 'error')
            return redirect(request.url)
        
        try:
            print("DEBUG: Starting CSV processing")
            # Read CSV content
            csv_content = file.read().decode('utf-8')
            print(f"DEBUG: CSV content length: {len(csv_content)}")
            print(f"DEBUG: First 500 characters of CSV: {repr(csv_content[:500])}")
            
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            print(f"DEBUG: CSV columns: {csv_reader.fieldnames}")
            
            # Extract employee data
            csv_employees = []
            row_count = 0
            for row in csv_reader:
                row_count += 1
                print(f"DEBUG: Raw row {row_count}: {row}")
                
                # Skip completely empty rows
                if not any(row.values()):
                    print(f"DEBUG: Skipping empty row {row_count}")
                    continue
                
                # Handle different possible column names
                employee_id = row.get('Employee ID', row.get('Employee Id', row.get('employee_id', row.get('ID', ''))))
                
                # Handle separate first and last name columns
                first_name = row.get('First Name', row.get('first_name', ''))
                last_name = row.get('Last Name', row.get('last_name', ''))
                full_name = row.get('Name', row.get('name', row.get('Full Name', '')))
                
                # Combine first and last name if they exist, otherwise use full_name
                if first_name and last_name:
                    name = f"{first_name.strip()} {last_name.strip()}"
                else:
                    name = full_name
                
                email = row.get('Email', row.get('email', ''))
                job_title = row.get('Default Jobs (HR)', row.get('Job Title', row.get('job_title', '')))
                
                print(f"DEBUG: Processing row {row_count} - ID: '{employee_id}', First: '{first_name}', Last: '{last_name}', Full: '{full_name}', Combined: '{name}', Email: '{email}', Job: '{job_title}'")
                print(f"DEBUG: Row {row_count} - All keys: {list(row.keys())}")
                print(f"DEBUG: Row {row_count} - All values: {list(row.values())}")
                
                # Only show first few rows to avoid spam
                if row_count <= 3:
                    print(f"DEBUG: Row {row_count} - Raw row data: {row}")
                
                if employee_id and name:
                    csv_employees.append({
                        'employee_id': employee_id.strip(),
                        'name': name.strip(),
                        'email': email.strip() if email else '',
                        'job_title': job_title.strip() if job_title else ''
                    })
            
            print(f"DEBUG: Found {len(csv_employees)} valid CSV employees")
            print(f"DEBUG: First few CSV employees:")
            for i, emp in enumerate(csv_employees[:5]):
                print(f"DEBUG:   {i+1}. {emp}")
            if len(csv_employees) > 5:
                print(f"DEBUG:   ... and {len(csv_employees) - 5} more employees")
            
            if not csv_employees:
                flash('No valid employee data found in CSV', 'error')
                return redirect(request.url)
            
            # Get AD users
            print("DEBUG: Getting AD config")
            config = get_ad_config()
            if not config:
                print("DEBUG: No AD config available")
                flash('AD configuration not available', 'error')
                return redirect(request.url)
            
            print(f"DEBUG: AD config found - server: {config['ad_server']}")
            print(f"DEBUG: Full AD config: {config}")
            
            ad_args = {
                'server': config['ad_server'],
                'port': config['ad_port'],
                'bind_user': config['ad_bind_dn'],
                'bind_password': config['ad_password'],
                'base_dn': config.get('ad_base_dn', config.get('base_dn'))
            }
            print(f"DEBUG: AD args prepared - server: {ad_args['server']}, port: {ad_args['port']}, base_dn: {ad_args['base_dn']}")
            
            # Search for all users in AD
            print("DEBUG: Searching AD users")
            ad_users = search_users('*', **ad_args)
            print(f"DEBUG: Found {len(ad_users)} AD users")
            if ad_users:
                print(f"DEBUG: First few AD users:")
                for i, user in enumerate(ad_users[:5]):
                    print(f"DEBUG:   {i+1}. {user.get('displayName', 'N/A')} ({user.get('sAMAccountName', 'N/A')}) - Employee ID: {user.get('employeeID', 'N/A')}")
            else:
                print("ERROR: No AD users found from live AD. Check connection, credentials, or base DN.")
                flash('No AD users found from Active Directory. Please check your AD connection, credentials, or base DN.', 'error')
                return redirect(request.url)
            
            # Compare CSV with AD users
            matched_users = []
            unmatched_csv = []
            unmatched_ad = []
            
            # Create lookup for AD users by name
            ad_user_lookup = {}
            print(f"DEBUG: Creating AD user lookup with {len(ad_users)} users")
            for user in ad_users:
                display_name = user.get('displayName', '')
                sam_account = user.get('sAMAccountName', '')
                employee_id = user.get('employeeID', '')
                
                # Add to lookup by display name
                if display_name:
                    ad_user_lookup[display_name.lower()] = user
                
                # Add to lookup by SAM account name
                if sam_account:
                    ad_user_lookup[sam_account.lower()] = user
                
                # Add to lookup by employee ID if it exists
                if employee_id:
                    ad_user_lookup[employee_id.lower()] = user
                
                print(f"DEBUG: Added to lookup - Display: '{display_name}', SAM: '{sam_account}', Employee ID: '{employee_id}'")
            
            print(f"DEBUG: AD user lookup created with {len(ad_user_lookup)} entries")
            print(f"DEBUG: Sample lookup keys: {list(ad_user_lookup.keys())[:10]}")
            
            # Check each CSV employee
            for csv_emp in csv_employees:
                csv_name_lower = csv_emp['name'].lower()
                csv_id_lower = csv_emp['employee_id'].lower()
                
                # Try to match by name or employee ID
                print(f"DEBUG: Searching for AD user with name: '{csv_emp['name']}' (ID: '{csv_emp['employee_id']}')")
                matched_user = None
                
                # First try exact employee ID match
                if csv_emp['employee_id'] in ad_user_lookup:
                    matched_user = ad_user_lookup[csv_emp['employee_id']]
                    print(f"DEBUG: Found exact employee ID match: '{csv_emp['employee_id']}' -> {matched_user.get('sAMAccountName', 'N/A')}")
                
                # If no exact match, try name matching
                if not matched_user:
                    for ad_name, ad_user in ad_user_lookup.items():
                        # Skip employee ID keys for name matching
                        if ad_name.isdigit() or ad_name.startswith('emp'):
                            continue
                        
                        # Try various name matching strategies
                        if (csv_name_lower == ad_name or  # Exact match
                            csv_name_lower in ad_name or  # CSV name is part of AD name
                            ad_name in csv_name_lower):   # AD name is part of CSV name
                            matched_user = ad_user
                            print(f"DEBUG: Found name match: '{csv_name_lower}' matches '{ad_name}' -> {ad_user.get('sAMAccountName', 'N/A')}")
                            break
                
                if not matched_user:
                    print(f"DEBUG: No match found for '{csv_emp['name']}' (ID: '{csv_emp['employee_id']}')")
                    print(f"DEBUG: Available AD names (first 10): {[k for k in ad_user_lookup.keys() if not k.isdigit() and not k.startswith('emp')][:10]}")
                
                if matched_user:
                    # Update AD user with employee ID and job title if not present
                    current_employee_id = matched_user.get('employeeID', '')
                    current_title = matched_user.get('title', '')
                    updates_made = []
                    
                    # Update employee ID if not present
                    if not current_employee_id and csv_emp['employee_id']:
                        try:
                            update_user_employee_id(matched_user['distinguishedName'], csv_emp['employee_id'], **ad_args)
                            matched_user['employeeID'] = csv_emp['employee_id']
                            updates_made.append('employee_id')
                        except Exception as e:
                            print(f"Error updating employee ID for {matched_user['distinguishedName']}: {e}")
                    
                    # Update job title if provided and different
                    if csv_emp.get('job_title') and csv_emp['job_title'] != current_title:
                        try:
                            update_user_attributes(matched_user['distinguishedName'], {'title': csv_emp['job_title']}, **ad_args)
                            matched_user['title'] = csv_emp['job_title']
                            updates_made.append('job_title')
                        except Exception as e:
                            print(f"Error updating job title for {matched_user['distinguishedName']}: {e}")
                    
                    matched_users.append({
                        'csv_data': csv_emp,
                        'ad_user': matched_user,
                        'updated': len(updates_made) > 0,
                        'updates': updates_made
                    })
                else:
                    unmatched_csv.append(csv_emp)
            
            # Find AD users not in CSV
            # Create a set of matched AD user DNs for efficient lookup
            matched_ad_dns = {match['ad_user']['distinguishedName'] for match in matched_users}
            
            for ad_user in ad_users:
                # If this AD user wasn't matched to any CSV user, it's AD-only
                if ad_user['distinguishedName'] not in matched_ad_dns:
                    unmatched_ad.append(ad_user)
            
            print(f"DEBUG: Processing complete - Matched: {len(matched_users)}, CSV-only: {len(unmatched_csv)}, AD-only: {len(unmatched_ad)}")
            if matched_users:
                print(f"DEBUG: Matched users:")
                for i, match in enumerate(matched_users[:5]):
                    print(f"DEBUG:   {i+1}. {match['csv_data']['name']} (ID: {match['csv_data']['employee_id']}) -> {match['ad_user']['sAMAccountName']}")
                if len(matched_users) > 5:
                    print(f"DEBUG:   ... and {len(matched_users) - 5} more matches")
            
            # Store only keys in session, full results in temp file
            session['csv_import_results_keys'] = {
                'matched_users': [u['csv_data']['employee_id'] for u in matched_users],
                'unmatched_csv': [u['employee_id'] for u in unmatched_csv],
                'unmatched_ad': [u['sAMAccountName'] for u in unmatched_ad],
                'total_csv': len(csv_employees),
                'total_ad': len(ad_users)
            }
            save_import_results({
                'matched_users': matched_users,
                'unmatched_csv': unmatched_csv,
                'unmatched_ad': unmatched_ad,
                'total_csv': len(csv_employees),
                'total_ad': len(ad_users)
            })
            flash(f'CSV import completed: {len(matched_users)} matched, {len(unmatched_csv)} CSV-only, {len(unmatched_ad)} AD-only', 'success')
            return redirect(url_for('main.csv_import_results'))
            
        except Exception as e:
            print(f"DEBUG: Exception during CSV processing: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f'Error processing CSV: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('csv_import.html')

@main.route('/admin/csv-import-results')
@login_required
@admin_required
def csv_import_results():
    """Display CSV import results"""
    results = load_import_results()
    if not results:
        flash('No import results found. Please upload a CSV file first.', 'warning')
        return redirect(url_for('main.csv_import'))
    return render_template('csv_import_results.html', results=results)

@main.route('/admin/bulk-disable-users', methods=['POST'])
@login_required
@admin_required
def bulk_disable_users():
    """Bulk disable users not in CSV and move to disabled OU"""
    results = session.get('csv_import_results')
    if not results:
        flash('No import results found. Please upload a CSV file first.', 'warning')
        return redirect(url_for('main.csv_import'))
    
    config = get_ad_config()
    if not config:
        flash('AD configuration not available', 'error')
        return redirect(url_for('main.csv_import_results'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['base_dn']
    }
    
    # Get disabled users OU
    from .ad import get_disabled_users_ou
    disabled_ou = request.form.get('disabled_ou', get_disabled_users_ou())
    
    success_count = 0
    error_count = 0
    errors = []
    
    # Process unmatched AD users
    for user in results['unmatched_ad']:
        try:
            user_dn = user['distinguishedName']
            
            # Disable user
            disable_user(user_dn, **ad_args)
            
            # Move to disabled OU
            move_user_to_ou(user_dn, disabled_ou, **ad_args)
            
            success_count += 1
            
        except Exception as e:
            error_count += 1
            errors.append(f"Error processing {user.get('displayName', 'Unknown')}: {str(e)}")
    
    if success_count > 0:
        flash(f'Successfully disabled and moved {success_count} users to {disabled_ou}', 'success')
    
    if error_count > 0:
        flash(f'Failed to process {error_count} users. Check logs for details.', 'error')
        for error in errors[:5]:  # Show first 5 errors
            flash(error, 'error')
    
    return redirect(url_for('main.csv_import_results'))

@main.route('/admin/export-unmatched-csv')
@login_required
@admin_required
def export_unmatched_csv():
    """Export unmatched CSV users to a new CSV file"""
    results = session.get('csv_import_results')
    if not results:
        flash('No import results found', 'warning')
        return redirect(url_for('main.csv_import'))
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Employee ID', 'Name', 'Email', 'Status'])
    
    for user in results['unmatched_csv']:
        writer.writerow([
            user['employee_id'],
            user['name'],
            user['email'],
            'Not in AD'
        ])
    
    output.seek(0)
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=unmatched_users.csv'}
    )

@main.route('/admin/export-unmatched-ad')
@login_required
@admin_required
def export_unmatched_ad():
    """Export unmatched AD users to a CSV file"""
    results = session.get('csv_import_results')
    if not results:
        flash('No import results found', 'warning')
        return redirect(url_for('main.csv_import'))
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Display Name', 'Username', 'Email', 'Employee ID', 'OU', 'Status'])
    
    for user in results['unmatched_ad']:
        writer.writerow([
            user.get('displayName', ''),
            user.get('sAMAccountName', ''),
            user.get('mail', ''),
            user.get('employeeID', ''),
            user.get('distinguishedName', '').split(',OU=')[-1] if ',OU=' in user.get('distinguishedName', '') else '',
            'Not in CSV'
        ])
    
    output.seek(0)
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=unmatched_ad_users.csv'}
    )

@main.route('/admin/bulk-action-ad-users', methods=['POST'])
@login_required
@admin_required
def bulk_action_ad_users():
    """Handle bulk actions on selected AD users"""
    action_type = request.form.get('action_type')
    selected_users = request.form.getlist('selected_users')
    from .ad import get_disabled_users_ou
    disabled_ou = request.form.get('disabled_ou', get_disabled_users_ou())
    
    if not action_type or not selected_users:
        flash('No action or users selected', 'warning')
        return redirect(url_for('main.csv_import_results'))
    
    config = get_ad_config()
    if not config:
        flash('AD configuration not available', 'error')
        return redirect(url_for('main.csv_import_results'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    success_count = 0
    error_count = 0
    errors = []
    
    print(f"DEBUG: Bulk action '{action_type}' on {len(selected_users)} users")
    
    for user_dn in selected_users:
        try:
            if action_type == 'disable':
                result, msg = disable_user(user_dn, **ad_args)
                if result:
                    success_count += 1
                    print(f"DEBUG: Disabled user {user_dn}")
                else:
                    error_count += 1
                    errors.append(f"Failed to disable {user_dn}: {msg}")
                    
            elif action_type == 'move_to_disabled':
                result, msg = move_user_to_ou(user_dn, disabled_ou, **ad_args)
                if result:
                    success_count += 1
                    print(f"DEBUG: Moved user {user_dn} to {disabled_ou}")
                else:
                    error_count += 1
                    errors.append(f"Failed to move {user_dn}: {msg}")
                    
            elif action_type == 'delete':
                result, msg = delete_user(user_dn, **ad_args)
                if result:
                    success_count += 1
                    print(f"DEBUG: Deleted user {user_dn}")
                else:
                    error_count += 1
                    errors.append(f"Failed to delete {user_dn}: {msg}")
                    
            elif action_type == 'export':
                # This will be handled by the export function
                success_count += 1
                
        except Exception as e:
            error_count += 1
            errors.append(f"Error processing {user_dn}: {str(e)}")
            print(f"DEBUG: Exception processing {user_dn}: {str(e)}")
    
    # Handle export action
    if action_type == 'export':
        return export_selected_ad_users(selected_user_dns, **ad_args)
    
    # Show results
    if success_count > 0:
        action_descriptions = {
            'disable': 'disabled',
            'move_to_disabled': f'moved to {disabled_ou}',
            'delete': 'deleted'
        }
        flash(f'Successfully {action_descriptions.get(action_type, "processed")} {success_count} users', 'success')
    
    if error_count > 0:
        flash(f'Failed to process {error_count} users. Check logs for details.', 'error')
        for error in errors[:5]:  # Show first 5 errors
            flash(error, 'error')
    
    return redirect(url_for('main.csv_import_results'))

def export_selected_ad_users(selected_user_dns, **ad_args):
    """Export selected AD users to CSV"""
    from flask import Response
    
    # Get user details for selected DNs
    selected_users = []
    for user_dn in selected_user_dns:
        user_details = get_user_details(user_dn, **ad_args)
        if user_details:
            selected_users.append(user_details)
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Display Name', 'Username', 'Email', 'Employee ID', 'OU', 'Status'])
    
    for user in selected_users:
        display_name = user.get('displayName', [''])[0] if user.get('displayName') else ''
        username = user.get('sAMAccountName', [''])[0] if user.get('sAMAccountName') else ''
        email = user.get('mail', [''])[0] if user.get('mail') else ''
        employee_id = user.get('employeeID', [''])[0] if user.get('employeeID') else ''
        dn = user.get('distinguishedName', [''])[0] if user.get('distinguishedName') else ''
        ou = dn.split(',OU=')[-1] if ',OU=' in dn else ''
        
        writer.writerow([display_name, username, email, employee_id, ou, 'Selected for Export'])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=selected_ad_users.csv'}
    )

# Helper to store and load import results from a temp file
IMPORT_RESULTS_FILE = os.path.join(tempfile.gettempdir(), 'geeks_ad_plus_import_results.json')

def save_import_results(results):
    with open(IMPORT_RESULTS_FILE, 'w') as f:
        json.dump(results, f)

def load_import_results():
    if os.path.exists(IMPORT_RESULTS_FILE):
        with open(IMPORT_RESULTS_FILE, 'r') as f:
            return json.load(f)
    return None

@main.route('/api/version/check')
@login_required
def check_version():
    """API endpoint to check for updates"""
    try:
        force_refresh = request.args.get('force', 'false').lower() == 'true'
        version_data = check_github_version(force_refresh=force_refresh)
        return jsonify({
            'success': True,
            'current_version': version_data['current_version'],
            'latest_version': version_data['latest_version'],
            'update_available': version_data['update_available'],
            'release_url': version_data['release_url'],
            'release_notes': version_data['release_notes'],
            'changelog': version_data.get('changelog'),
            'error': version_data['error'],
            'cached': version_data['cached']
        })
    except Exception as e:
        current_app.logger.error(f"Error checking version: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main.route('/admin/updates')
@login_required
@admin_required
def updates_page():
    """Update management page"""
    try:
        updater = Updater()
        update_info = updater.check_update_available()
        backups = updater.get_backup_list()
        
        return render_template('updates.html',
                             update_info=update_info,
                             backups=backups,
                             current_version=__version__)
    except Exception as e:
        current_app.logger.error(f"Error loading updates page: {e}")
        flash(f'Error loading updates page: {str(e)}', 'danger')
        return redirect(url_for('main.home'))

@main.route('/api/updates/check')
@login_required
@admin_required
def api_check_updates():
    """API endpoint to check for updates"""
    try:
        updater = Updater()
        update_info = updater.check_update_available()
        
        # Changelog is already included from version_checker via check_update_available
        # But we can also try to get it locally if not available
        if update_info.get('available') and update_info.get('latest_version') and not update_info.get('changelog'):
            try:
                from .version_checker import get_changelog_for_version
                changelog = get_changelog_for_version(update_info['latest_version'])
                if changelog:
                    update_info['changelog'] = changelog
            except:
                pass
        
        return jsonify({
            'success': True,
            **update_info
        })
    except Exception as e:
        current_app.logger.error(f"Error checking updates: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main.route('/api/updates/perform', methods=['POST'])
@login_required
@admin_required
def api_perform_update():
    """API endpoint to perform update"""
    try:
        data = request.get_json()
        version = data.get('version') if data else None
        
        updater = Updater()
        result = updater.perform_update(version=version)
        
        if result.get('success'):
            log_admin_action('system_update', f"Updated to version {version or 'latest'}", 'success')
        
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error performing update: {e}")
        return jsonify({
            'success': False,
            'message': f'Error performing update: {str(e)}'
        }), 500

@main.route('/api/updates/rollback', methods=['POST'])
@login_required
@admin_required
def api_rollback():
    """API endpoint to rollback to a backup"""
    try:
        data = request.get_json()
        backup_dir = data.get('backup_dir') if data else None
        
        if not backup_dir:
            return jsonify({
                'success': False,
                'message': 'Backup directory not specified'
            }), 400
        
        updater = Updater()
        result = updater.rollback(backup_dir)
        
        if result.get('success'):
            log_admin_action('system_rollback', f"Rolled back to backup: {backup_dir}", 'success')
        
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error during rollback: {e}")
        return jsonify({
            'success': False,
            'message': f'Error during rollback: {str(e)}'
        }), 500

@main.route('/api/updates/backups')
@login_required
@admin_required
def api_get_backups():
    """API endpoint to get list of backups"""
    try:
        updater = Updater()
        backups = updater.get_backup_list()
        return jsonify({
            'success': True,
            'backups': backups
        })
    except Exception as e:
        current_app.logger.error(f"Error getting backups: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500