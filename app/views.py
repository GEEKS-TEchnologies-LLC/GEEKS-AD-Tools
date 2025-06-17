from flask import Blueprint, render_template, redirect, url_for, request, flash
from .ad import (
    save_ad_config, load_ad_config, test_ad_connection,
    get_admin_groups, set_admin_groups, is_user_in_admin_group,
    create_ad_group, add_user_to_group
)
from flask import current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import Admin, db
from werkzeug.security import generate_password_hash
from functools import wraps
import os

main = Blueprint('main', __name__)

@main.before_app_request
def enforce_setup():
    if not load_ad_config() and request.endpoint not in ('main.setup', 'static'):
        return redirect(url_for('main.setup'))

@main.route('/')
def home():
    config = load_ad_config()
    return render_template('home.html', config=config)

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
    if Admin.query.first():
        flash('Admin already registered. Please log in.', 'info')
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
            flash('Logged in as local admin.', 'success')
            return redirect(url_for('main.home'))
        # Try AD admin login if AD is configured
        config = load_ad_config()
        if config:
            ok, msg = test_ad_connection(
                config['ad_server'],
                config['ad_port'],
                config['ad_bind_dn'],
                config['ad_password']
            )
            if ok:
                # Check if user is in admin group
                if is_user_in_admin_group(
                    username,
                    config['ad_server'],
                    config['ad_port'],
                    config['ad_bind_dn'],
                    config['ad_password'],
                    config['ad_base_dn']
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
                    flash('Logged in as AD admin.', 'success')
                    return redirect(url_for('main.home'))
                else:
                    flash('You are not a member of an admin group.', 'danger')
            else:
                flash(f'AD connection failed: {msg}', 'danger')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('admin_login.html')

@main.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('main.home'))

@main.route('/setup', methods=['GET', 'POST'])
@login_required
@admin_required
def setup():
    if request.method == 'POST':
        config = {
            'ad_server': request.form['ad_server'],
            'ad_port': request.form['ad_port'],
            'ad_bind_dn': request.form['ad_bind_dn'],
            'ad_password': request.form['ad_password'],
            'ad_base_dn': request.form['ad_base_dn']
        }
        save_ad_config(config)
        ok, msg = test_ad_connection(
            config['ad_server'],
            config['ad_port'],
            config['ad_bind_dn'],
            config['ad_password']
        )
        if ok:
            flash('Setup saved and AD connection successful!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash(f'AD connection failed: {msg}', 'danger')
    return render_template('setup.html')

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
    # Example: System status (placeholder)
    status = {
        'AD Configured': bool(load_ad_config()),
        'Admin Groups': get_admin_groups(),
    }
    return render_template('admin_dashboard.html', logs=logs, status=status) 