from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
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
from datetime import datetime
from flask import session

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
    # Allow access to setup, admin_register, admin_login, welcome, and static files without AD config
    allowed_endpoints = ('main.setup', 'main.admin_register', 'main.admin_login', 'main.welcome', 'main.home', 'static')
    if not get_ad_config() and request.endpoint not in allowed_endpoints:
        return redirect(url_for('main.home'))

@main.route('/')
def home():
    config = get_ad_config()
    if not config:
        return render_template('welcome.html')
    branding = get_branding_config()
    return render_template('home.html', config=config, branding=branding)

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
    
    print(f"DEBUG: page={page}, start={start}, end={end}, users_page_len={len(users_page)}, total_users={total_users}")
    
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
    config = get_ad_config()
    branding = get_branding_config()
    admin_groups = get_admin_groups()
    
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
            # Update branding config with debug settings
            branding_data = branding.copy() if branding else {}
            
            # Flash message countdown setting
            branding_data['flash_countdown'] = 'flash_countdown' in request.form
            
            # Debug mode setting
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
            
            save_branding_config(branding_data)
            flash('Debug settings updated successfully!', 'success')
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
                         config=config, 
                         branding=branding, 
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
        log_action(
            user=current_user.username,
            action='task_completed',
            details=f'Completed task: {task.title}',
            result='success'
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
            log_action(
                user=current_user.username,
                action='task_assigned',
                details=f'Assigned task "{title}" to {username}',
                result='success'
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
        log_action(
            user=current_user.username,
            action='task_deleted',
            details=f'Deleted task: {task.title} (assigned to {task.username})',
            result='success'
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
                log_action(
                    user=current_user.username,
                    action='security_question_setup',
                    details=f'{questions_updated} security question(s) {"updated" if existing_questions else "set up"}',
                    result='success',
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
                        log_action(
                            user=current_user.username,
                            action='password_reset',
                            details='Password reset by logged-in user',
                            result='success',
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
        
        # Get all users with password attributes in a single query
        conn.search(config['ad_base_dn'], 
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
            if debug_enabled:
                print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
            password_stats['total'] += 1
            # Parse user account control
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
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
        
        # Get all users with password attributes in a single query
        conn.search(config['ad_base_dn'], 
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
            if debug_enabled:
                print(f"DEBUG: Including {getattr(entry, 'sAMAccountName', 'UNKNOWN')} - {debug_msg}")
            
            # Parse user account control
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
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