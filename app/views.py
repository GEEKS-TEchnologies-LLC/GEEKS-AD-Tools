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
    set_user_manager, remove_user_manager, get_user_manager, ad_connection,
    search_computers, get_computer_details, move_computer_to_ou,
    get_user_dn_by_username
)
from flask import current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import Admin, DepartmentManager, UserDirectReport, DisabledUserLifecycle
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
from datetime import datetime, timezone, timedelta
from flask import session
# License validation removed - no license server available
import csv
import io
import threading
from werkzeug.utils import secure_filename
import tempfile
from flask import Response

main = Blueprint('main', __name__)
DISABLED_USER_RETENTION_DAYS = 180
DISABLED_USER_ARCHIVE_RUN_INTERVAL_SECONDS = 300
_last_disabled_user_archive_run_at = None
MAILBOX_REFRESH_INTERVAL_SECONDS = 1800
_last_mailbox_refresh_run_at = None
_mailbox_refresh_in_progress = False
_mailbox_refresh_lock = threading.Lock()

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

def _extract_parent_ou_from_dn(user_dn):
    if not user_dn or ',' not in user_dn:
        return None
    return user_dn.split(',', 1)[1]

def _calculate_moved_dn(user_dn, target_ou_dn):
    if not user_dn or ',' not in user_dn:
        return user_dn
    cn_part = user_dn.split(',', 1)[0]
    return f"{cn_part},{target_ou_dn}"

def _ad_attr_scalar(value, default=''):
    """Normalize LDAP/AD attribute values to a single scalar string."""
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        if not value:
            return default
        return _ad_attr_scalar(value[0], default=default)
    return str(value)

def _to_utc_datetime(value):
    """Normalize datetime values to timezone-aware UTC."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

def _resolve_existing_disabled_ou(config, ad_args):
    """
    Resolve the best existing Disabled Users OU.
    Prefers configured DN, but falls back to discovered OUs that contain
    'disabled users' / 'disabled user' / 'disabled' markers.
    """
    org_ous = get_organization_ous(config['ad_base_dn'])
    preferred_dn = org_ous.get('disabled_users_ou')

    ous = list_ous(**ad_args) or []
    ou_dns = [ou.get('dn') for ou in ous if ou.get('dn')]

    # Exact/normalized match for configured OU first.
    if preferred_dn:
        for dn in ou_dns:
            if dn.lower() == preferred_dn.lower():
                return dn

    # Keyword-based fallback.
    scored = []
    for dn in ou_dns:
        dn_l = dn.lower()
        score = 0
        if 'ou=disabled users' in dn_l:
            score += 100
        if 'ou=disabled user' in dn_l:
            score += 90
        if 'disabled users' in dn_l:
            score += 80
        if 'disabled user' in dn_l:
            score += 70
        if 'ou=disabled' in dn_l:
            score += 60
        if 'disabled' in dn_l:
            score += 40
        if score:
            # Prefer more specific (deeper) DN in ties.
            scored.append((score, dn.count(','), dn))

    if scored:
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return scored[0][2]

    return preferred_dn

def _resolve_existing_archive_ou(config, ad_args):
    """
    Resolve the best existing Archived Users OU.
    Prefers configured DN, then discovered OUs containing archive markers.
    """
    org_ous = get_organization_ous(config['ad_base_dn'])
    preferred_dn = org_ous.get('archive_users_ou')

    ous = list_ous(**ad_args) or []
    ou_dns = [ou.get('dn') for ou in ous if ou.get('dn')]

    if preferred_dn:
        for dn in ou_dns:
            if dn.lower() == preferred_dn.lower():
                return dn

    scored = []
    for dn in ou_dns:
        dn_l = dn.lower()
        score = 0
        if 'ou=archived users' in dn_l:
            score += 100
        if 'ou=archived user' in dn_l:
            score += 90
        if 'archived users' in dn_l:
            score += 80
        if 'archived user' in dn_l:
            score += 70
        if 'ou=archive' in dn_l:
            score += 60
        if 'archived' in dn_l or 'archive' in dn_l:
            score += 40
        if score:
            scored.append((score, dn.count(','), dn))

    if scored:
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return scored[0][2]

    return preferred_dn

def _disable_user_with_lifecycle(user_dn, ad_args, config):
    """Disable user and run offboarding lifecycle (OU move + Exchange)."""
    user_details = get_user_details(user_dn, **ad_args) or {}
    username = _ad_attr_scalar(
        user_details.get('sAMAccountName')
        or user_details.get('samAccountName')
        or user_details.get('cn')
        or user_dn.split(',')[0].replace('CN=', '')
    )
    display_name = _ad_attr_scalar(user_details.get('displayName'), default=username) or username
    email = _ad_attr_scalar(user_details.get('mail'), default='')
    original_groups = get_user_groups(user_dn, **ad_args)
    original_ou_dn = _extract_parent_ou_from_dn(user_dn)

    org_ous = get_organization_ous(config['ad_base_dn'])
    disabled_ou_dn = _resolve_existing_disabled_ou(config, ad_args)
    archive_ou_dn = _resolve_existing_archive_ou(config, ad_args)

    disable_ok, disable_msg = ad_disable_user(user_dn, **ad_args)
    if not disable_ok:
        return {'success': False, 'partial': False, 'message': disable_msg}

    current_dn = user_dn
    move_ok = True
    move_msg = ''
    if disabled_ou_dn and disabled_ou_dn.lower() not in user_dn.lower():
        move_ok, move_msg = move_user_to_ou(user_dn, disabled_ou_dn, **ad_args)
        if move_ok:
            current_dn = _calculate_moved_dn(user_dn, disabled_ou_dn)

    now = datetime.now(timezone.utc)
    record = DisabledUserLifecycle.query.filter_by(username=username).first()
    if not record:
        record = DisabledUserLifecycle(username=username, original_dn=user_dn, current_dn=current_dn)
        db.session.add(record)

    record.display_name = display_name
    record.email = email
    record.original_dn = user_dn
    record.current_dn = current_dn
    record.original_ou_dn = original_ou_dn
    record.disabled_ou_dn = disabled_ou_dn
    record.archive_ou_dn = archive_ou_dn
    record.disabled_at = now
    record.archive_after = now + timedelta(days=DISABLED_USER_RETENTION_DAYS)
    record.archived_at = None
    record.restored_at = None
    record.status = 'disabled'
    record.set_original_groups(original_groups)
    record.last_archive_error = None
    db.session.commit()

    exchange_result = _offboard_exchange_mailbox(email, username)
    partial = not move_ok
    if exchange_result.get('attempted') and not exchange_result.get('mailbox_disabled'):
        partial = True

    message_parts = [
        "User disabled.",
        f"Auto-archive scheduled after {DISABLED_USER_RETENTION_DAYS} days."
    ]
    if move_ok:
        message_parts.insert(1, "Moved to Disabled OU.")
    else:
        message_parts.insert(1, f"Could not move to Disabled OU: {move_msg}.")
    if exchange_result.get('attempted'):
        message_parts.append(f"Exchange: {exchange_result.get('message', '')}")

    result_state = 'partial' if partial else 'success'
    log_user_action(
        'disable_user',
        username,
        result_state,
        {
            'user_dn': user_dn,
            'moved_to': disabled_ou_dn if move_ok else None,
            'move_error': None if move_ok else move_msg,
            'exchange': exchange_result
        }
    )

    return {
        'success': True,
        'partial': partial,
        'message': ' '.join(message_parts),
        'archive_after': record.archive_after.isoformat(),
        'exchange': exchange_result
    }

def run_disabled_user_archive_maintenance(force=False):
    """Move users to archive OU when their retention period has elapsed."""
    global _last_disabled_user_archive_run_at

    now = datetime.now(timezone.utc)
    if (
        not force
        and _last_disabled_user_archive_run_at
        and (now - _last_disabled_user_archive_run_at).total_seconds() < DISABLED_USER_ARCHIVE_RUN_INTERVAL_SECONDS
    ):
        return

    _last_disabled_user_archive_run_at = now

    config = get_ad_config()
    if not config:
        return

    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }

    disabled_ou_dn = _resolve_existing_disabled_ou(config, ad_args)
    archive_ou_dn = _resolve_existing_archive_ou(config, ad_args)

    # Backfill lifecycle rows for disabled users that predate lifecycle tracking.
    # This guarantees "disabled >= 6 months -> archived" for existing disabled users too.
    try:
        disabled_users = search_users(
            '',
            status_filter='disabled',
            include_disabled_ou=True,
            include_archive_ou=False,
            exclude_ous=[],
            **ad_args
        )
        for user in disabled_users:
            username = _ad_attr_scalar(user.get('username'))
            if not username:
                continue
            existing = DisabledUserLifecycle.query.filter_by(username=username).first()
            if existing:
                # Keep archive OU aligned with resolved OU if missing.
                if not existing.archive_ou_dn and archive_ou_dn:
                    existing.archive_ou_dn = archive_ou_dn
                continue

            dn = _ad_attr_scalar(user.get('dn') or user.get('distinguishedName'))
            if not dn:
                continue

            disabled_since = _to_utc_datetime(user.get('whenChanged')) or now
            row = DisabledUserLifecycle(
                username=username,
                display_name=_ad_attr_scalar(user.get('displayName'), default=username),
                email=_ad_attr_scalar(user.get('mail'), default=''),
                original_dn=dn,
                current_dn=dn,
                original_ou_dn=_extract_parent_ou_from_dn(dn),
                disabled_ou_dn=disabled_ou_dn,
                archive_ou_dn=archive_ou_dn,
                disabled_at=disabled_since,
                archive_after=disabled_since + timedelta(days=DISABLED_USER_RETENTION_DAYS),
                status='disabled'
            )
            row.set_original_groups([])
            db.session.add(row)
        db.session.commit()
    except Exception as e:
        current_app.logger.warning(f"Disabled-user lifecycle backfill failed: {e}")
        db.session.rollback()

    due_records = DisabledUserLifecycle.query.filter(
        DisabledUserLifecycle.status == 'disabled',
        DisabledUserLifecycle.archive_after <= now
    ).all()

    for record in due_records:
        archive_dn = record.archive_ou_dn or archive_ou_dn
        if archive_dn:
            record.archive_ou_dn = archive_dn

        current_dn = record.current_dn
        if not current_dn:
            current_dn = get_user_dn_by_username(record.username, **ad_args)
            if not current_dn:
                record.last_archive_error = 'Could not resolve current DN for archive move.'
                continue
            record.current_dn = current_dn

        # Already archived; reconcile DB state.
        if archive_dn and archive_dn.lower() in current_dn.lower():
            record.status = 'archived'
            record.archived_at = record.archived_at or now
            record.last_archive_error = None
            continue

        details = get_user_details(current_dn, **ad_args)
        if details and details.get('userAccountControl'):
            try:
                uac = int(details.get('userAccountControl'))
                if not (uac & 2):
                    record.status = 'restored'
                    record.restored_at = now
                    record.last_archive_error = 'Skipped archive because account is enabled.'
                    continue
            except Exception:
                pass

        if not archive_dn:
            record.last_archive_error = 'Archived Users OU could not be resolved.'
            log_admin_action('user_archive_auto_move', 'failure', f"{record.username}: missing archive OU")
            continue

        ok, msg = move_user_to_ou(current_dn, archive_dn, **ad_args)
        if ok:
            record.current_dn = _calculate_moved_dn(current_dn, archive_dn)
            record.status = 'archived'
            record.archived_at = now
            record.last_archive_error = None
            log_admin_action('user_archive_auto_move', 'success', f"{record.username} moved to archive OU")
        else:
            record.last_archive_error = msg
            log_admin_action('user_archive_auto_move', 'failure', f"{record.username}: {msg}")

    if due_records:
        db.session.commit()

def _sanitize_ou_name(raw_name):
    """Allow common OU-safe characters and collapse whitespace."""
    if not raw_name:
        return ''
    cleaned = ''.join(ch for ch in str(raw_name).strip() if ch.isalnum() or ch in (' ', '-', '_', '&', '.'))
    return ' '.join(cleaned.split())

def _sanitize_group_sam(raw_name):
    """sAMAccountName-safe group token."""
    if not raw_name:
        return ''
    return ''.join(ch for ch in str(raw_name).strip() if ch.isalnum() or ch in ('-', '_', '.'))[:64]

def _parse_department_hierarchy_text(raw_text):
    """
    Parse department hierarchy text.
    Format examples:
      IT: Helpdesk, Network, Security
      Facilities: Maint | Housekeeping
      HR
    """
    hierarchy = {}
    if not raw_text:
        return hierarchy, None

    lines = [line.strip() for line in str(raw_text).splitlines()]
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            dept_raw, subs_raw = line.split(':', 1)
            dept = _sanitize_ou_name(dept_raw)
            if not dept:
                continue
            sub_tokens = []
            for token in subs_raw.replace('|', ',').split(','):
                sub = _sanitize_ou_name(token)
                if sub and sub.lower() not in [s.lower() for s in sub_tokens]:
                    sub_tokens.append(sub)
            hierarchy[dept] = sub_tokens
        else:
            dept = _sanitize_ou_name(line)
            if dept:
                hierarchy[dept] = hierarchy.get(dept, [])
    return hierarchy, None

def _parse_department_hierarchy_file(uploaded_file):
    """Parse department hierarchy from uploaded .csv/.json/.txt file."""
    if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
        return {}, "No hierarchy file uploaded."

    filename = uploaded_file.filename.lower()
    raw = uploaded_file.read()
    try:
        text = raw.decode('utf-8-sig')
    except Exception:
        return {}, "Unable to decode hierarchy file as UTF-8."

    if filename.endswith('.json'):
        try:
            payload = json.loads(text)
        except Exception as e:
            return {}, f"Invalid JSON hierarchy file: {e}"
        hierarchy = {}
        if isinstance(payload, dict):
            for dept_raw, subs in payload.items():
                dept = _sanitize_ou_name(dept_raw)
                if not dept:
                    continue
                clean_subs = []
                if isinstance(subs, list):
                    for sub_raw in subs:
                        sub = _sanitize_ou_name(sub_raw)
                        if sub and sub.lower() not in [s.lower() for s in clean_subs]:
                            clean_subs.append(sub)
                hierarchy[dept] = clean_subs
            return hierarchy, None
        if isinstance(payload, list):
            for row in payload:
                if not isinstance(row, dict):
                    continue
                dept = _sanitize_ou_name(row.get('department') or row.get('dept') or '')
                sub = _sanitize_ou_name(row.get('sub_ou') or row.get('sub') or row.get('child_ou') or '')
                if not dept:
                    continue
                hierarchy.setdefault(dept, [])
                if sub and sub.lower() not in [s.lower() for s in hierarchy[dept]]:
                    hierarchy[dept].append(sub)
            return hierarchy, None
        return {}, "JSON hierarchy must be an object or array."

    if filename.endswith('.csv'):
        try:
            reader = csv.DictReader(io.StringIO(text))
            hierarchy = {}
            for row in reader:
                if not isinstance(row, dict):
                    continue
                dept = _sanitize_ou_name(
                    row.get('department') or row.get('dept') or row.get('Department') or row.get('Dept') or ''
                )
                sub = _sanitize_ou_name(
                    row.get('sub_ou') or row.get('sub') or row.get('SubOU') or row.get('Sub OU') or row.get('child_ou') or ''
                )
                if not dept:
                    continue
                hierarchy.setdefault(dept, [])
                if sub and sub.lower() not in [s.lower() for s in hierarchy[dept]]:
                    hierarchy[dept].append(sub)
            return hierarchy, None
        except Exception as e:
            return {}, f"Invalid CSV hierarchy file: {e}"

    # Fallback: plain text parser
    return _parse_department_hierarchy_text(text)

def _is_default_ad_administrator(bind_dn):
    """Detect classic built-in Administrator bind DN."""
    if not bind_dn:
        return False
    first_rdn = str(bind_dn).split(',', 1)[0].strip().lower()
    return first_rdn in ('cn=administrator', 'cn=admin')

def _provision_delegated_admin_from_bind(
    source_admin_dn,
    new_username,
    new_password,
    new_display_name,
    new_email,
    target_users_ou,
    ad_args
):
    """
    Create delegated AD admin and copy source admin group memberships.
    Also create local Admin record for app admin role continuity.
    """
    normalized_username = _ad_attr_scalar(new_username, default='').strip()
    normalized_display = _ad_attr_scalar(new_display_name, default=normalized_username).strip() or normalized_username
    if not normalized_username or not new_password:
        return False, "New delegated admin username and password are required."

    existing_dn = get_user_dn_by_username(normalized_username, **ad_args)
    if existing_dn:
        return False, f"Delegated admin already exists: {normalized_username}"

    ok, msg, new_user_dn = ad_create_user(
        username=normalized_username,
        password=new_password,
        display_name=normalized_display,
        mail=new_email or None,
        target_ou=target_users_ou or ad_args.get('base_dn'),
        **ad_args
    )
    if not ok or not new_user_dn:
        return False, f"Failed to create delegated admin user: {msg}"

    source_groups = get_user_groups(source_admin_dn, **ad_args) or []
    copied_groups = 0
    group_errors = []
    for group_dn in source_groups:
        g_ok, g_msg = add_user_to_group(new_user_dn, group_dn, **ad_args)
        if g_ok:
            copied_groups += 1
        else:
            group_errors.append(f"{group_dn}: {g_msg}")

    admin_record = Admin.query.filter_by(username=normalized_username).first()
    if not admin_record:
        admin_record = Admin(username=normalized_username)
        admin_record.password_hash = ''  # AD-authenticated admin
        db.session.add(admin_record)
        db.session.commit()

    result_msg = f"Delegated admin {normalized_username} created. Copied {copied_groups} AD groups."
    if group_errors:
        result_msg += f" Group copy had {len(group_errors)} warnings."
    return True, result_msg

def _ensure_department_security_groups(departments, groups_ou_dn, ad_args):
    """
    Ensure one security group exists for each department.
    Group naming convention: SG-<DepartmentToken>
    """
    created = []
    skipped = []
    errors = []

    for dept in departments:
        dept_display = _sanitize_ou_name(dept)
        if not dept_display:
            continue
        sam_token = _sanitize_group_sam(dept_display.replace(' ', ''))
        if not sam_token:
            continue
        group_name = f"SG-{sam_token}"
        group_dn = f"CN={group_name},{groups_ou_dn}"
        ldap_filter = f"(|(cn={group_name})(sAMAccountName={group_name}))"

        try:
            with ad_connection(**ad_args) as conn:
                conn.search(groups_ou_dn, ldap_filter, search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
                if conn.entries:
                    skipped.append(group_name)
                    continue

                attrs = {
                    'objectClass': ['top', 'group'],
                    'sAMAccountName': group_name,
                    'groupType': -2147483646,  # Global Security Group
                    'description': f"Department security group for {dept_display}"
                }
                ok = conn.add(group_dn, attributes=attrs)
                if ok:
                    created.append(group_name)
                else:
                    errors.append(f"{group_name}: {conn.result.get('description', 'unknown LDAP error')}")
        except Exception as e:
            errors.append(f"{group_name}: {e}")

    return {
        'created': created,
        'skipped': skipped,
        'errors': errors
    }

def _ensure_lifecycle_ous_under_users(users_ou_dn, ad_args):
    """
    Ensure lifecycle OUs exist under the configured Users OU:
    - OU=Disabled Users,<Users OU>
    - OU=Archived Users,<Users OU>
    """
    if not users_ou_dn:
        return False, "Users OU is required to create lifecycle OUs.", {}

    desired = [
        ('Disabled Users', users_ou_dn),
        ('Archived Users', users_ou_dn)
    ]
    existing_dns = {ou.get('dn', '').lower() for ou in (list_ous(**ad_args) or []) if ou.get('dn')}
    created = []
    skipped = []
    errors = []

    for ou_name, parent_dn in desired:
        ou_dn = f"OU={ou_name},{parent_dn}"
        if ou_dn.lower() in existing_dns:
            skipped.append(ou_dn)
            continue
        ok, msg = create_ou(ou_name, parent_dn, **ad_args)
        if ok:
            created.append(ou_dn)
            existing_dns.add(ou_dn.lower())
        else:
            errors.append(f"{ou_dn}: {msg}")

    return len(errors) == 0, (
        f"Lifecycle OUs ready. Created {len(created)}, existing {len(skipped)}."
        if not errors else
        f"Lifecycle OU setup had {len(errors)} errors."
    ), {
        'created': created,
        'skipped': skipped,
        'errors': errors,
        'disabled_users_ou': f"OU=Disabled Users,{users_ou_dn}",
        'archive_users_ou': f"OU=Archived Users,{users_ou_dn}"
    }

def _build_department_entries_from_ous(ous, primary_users_ou):
    """
    Build top-level department + sub-OU entries from OUs under primary users OU.
    Returns list of dicts suitable for manager UI.
    """
    if not primary_users_ou:
        return []

    skip_names = {
        'sunray users', 'users', 'disabled users', 'disabled user',
        'archived users', 'archived user', 'archive users',
        'service accounts', 'internal tools', 'sunray',
        'owners', 'owner', 'administrators', 'admins',
        'managers', 'management', 'western gaming', 'racing security',
        'vendor logins', 'vendor login', 'vendors'
    }

    normalized_primary = primary_users_ou.lower()
    top_map = {}

    for ou in ous:
        ou_dn = ou.get('dn', '') if isinstance(ou, dict) else (ou.dn if hasattr(ou, 'dn') else str(ou))
        if not ou_dn:
            continue
        dn_l = ou_dn.lower()
        suffix = ',' + normalized_primary
        if not dn_l.endswith(suffix):
            continue

        relative_dn = ou_dn[:len(ou_dn) - len(suffix)]
        dn_parts = [p.strip() for p in relative_dn.split(',') if p.strip().startswith('OU=')]
        if not dn_parts:
            continue

        # DN order is leaf -> parent; reverse to get top -> leaf.
        hierarchy = [p[3:] for p in reversed(dn_parts) if len(p) > 3]
        if not hierarchy:
            continue
        top_name = hierarchy[0]
        if top_name.lower() in skip_names:
            continue

        if top_name not in top_map:
            top_map[top_name] = {
                'name': top_name,
                'dn': f"OU={top_name},{primary_users_ou}",
                'key': top_name,
                'is_sub': False,
                'parent_name': None,
                'sub_entries': {}
            }

        if len(hierarchy) > 1:
            sub_chain = hierarchy[1:]
            sub_display = ' / '.join(sub_chain)
            sub_key = f"{top_name}::{sub_display}"
            top_map[top_name]['sub_entries'][sub_key] = {
                'name': sub_display,
                'dn': ou_dn,
                'key': sub_key,
                'is_sub': True,
                'parent_name': top_name
            }

    entries = []
    for top_name in sorted(top_map.keys(), key=lambda x: x.lower()):
        top = top_map[top_name]
        entries.append({
            'name': top['name'],
            'dn': top['dn'],
            'key': top['key'],
            'is_sub': False,
            'parent_name': None
        })
        for sub_key in sorted(top['sub_entries'].keys(), key=lambda x: x.lower()):
            entries.append(top['sub_entries'][sub_key])
    return entries

def _extract_sub_department_label(user_dn, top_department_dn):
    """Extract sub-OU chain under a top-level department OU from user DN."""
    if not user_dn or not top_department_dn:
        return None
    dn_l = user_dn.lower()
    top_l = ',' + top_department_dn.lower()
    if top_l not in dn_l:
        return None
    idx = dn_l.find(top_l)
    prefix = user_dn[:idx]
    ou_parts = [p.strip() for p in prefix.split(',') if p.strip().startswith('OU=')]
    if not ou_parts:
        return None
    # Closest OU to user first; reverse for top->leaf under department.
    labels = [p[3:] for p in reversed(ou_parts)]
    return ' / '.join(labels) if labels else None

def _resolve_default_manager(ad_args):
    """
    Resolve the fallback manager from policy candidates.
    Returns dict with username/dn/display or None.
    """
    policy = _load_manager_policy()
    candidates = policy.get('default_manager_candidates') or []
    for candidate in candidates:
        identity = _resolve_ad_user_identity(candidate, ad_args)
        if identity:
            return identity
    return None


def _load_manager_policy():
    """
    Load manager policy from local, gitignored file:
    instance/manager_policy.json

    Repository default is generic and does not include org-specific rules.
    """
    policy = {
        'default_manager_candidates': [],
        'top_manager_candidates': [],
        'manager_exclusions': [],
        'manager_aliases': {},
        'forced_manager_candidates': [],
        'explicit_assignments': [],
        'dual_reports': [],
        'department_sync': {
            'exclude_employee_candidates': [],
            'department_overrides': []
        }
    }

    policy_path = os.path.join('instance', 'manager_policy.json')
    if not os.path.exists(policy_path):
        return policy
    try:
        with open(policy_path, 'r') as f:
            loaded = json.load(f) or {}
    except Exception as exc:
        current_app.logger.warning(f"Unable to load manager policy: {exc}")
        return policy

    if not isinstance(loaded, dict):
        return policy

    for key in [
        'default_manager_candidates',
        'top_manager_candidates',
        'manager_exclusions',
        'forced_manager_candidates',
        'explicit_assignments',
        'dual_reports'
    ]:
        if isinstance(loaded.get(key), list):
            policy[key] = loaded.get(key)

    if isinstance(loaded.get('manager_aliases'), dict):
        policy['manager_aliases'] = loaded.get('manager_aliases')

    if isinstance(loaded.get('department_sync'), dict):
        dept_sync = loaded.get('department_sync')
        if isinstance(dept_sync.get('exclude_employee_candidates'), list):
            policy['department_sync']['exclude_employee_candidates'] = dept_sync.get('exclude_employee_candidates')
        if isinstance(dept_sync.get('department_overrides'), list):
            policy['department_sync']['department_overrides'] = dept_sync.get('department_overrides')

    return policy

def _resolve_ad_user_identity(query_value, ad_args):
    """Resolve AD user identity by username/display string."""
    if not query_value:
        return None
    users = search_users(query_value, **ad_args) or []
    for user in users:
        username = _ad_attr_scalar(user.get('sAMAccountName') or user.get('username')).strip()
        dn = _ad_attr_scalar(user.get('distinguishedName') or user.get('dn')).strip()
        display = _ad_attr_scalar(user.get('displayName') or user.get('cn') or username).strip()
        if username and dn:
            return {'username': username, 'dn': dn, 'display': display}
    return None

def _auto_sync_manager_chain(ad_args, all_managers):
    """
    Policy-driven manager chain sync.
    Uses local policy from instance/manager_policy.json.
    """
    policy = _load_manager_policy()

    def _resolve_from_candidates(candidates):
        if isinstance(candidates, str):
            candidates = [candidates]
        for candidate in candidates or []:
            identity = _resolve_ad_user_identity(candidate, ad_args)
            if identity:
                return identity
        return None

    default_mgr = _resolve_default_manager(ad_args)
    if not default_mgr:
        return {'updated': 0, 'assigned': 0, 'skipped': 0, 'missing': 'default_manager'}

    top_mgr = None
    top_candidates = policy.get('top_manager_candidates') or []
    if top_candidates:
        top_mgr = _resolve_from_candidates(top_candidates)
        if not top_mgr:
            return {'updated': 0, 'assigned': 0, 'skipped': 0, 'missing': 'top_manager'}

    excluded_manager_names = {name.strip().lower() for name in (policy.get('manager_exclusions') or []) if isinstance(name, str)}
    updated = 0
    assigned = 0
    skipped = 0
    special_exception_usernames = set()

    def _get_employee_report(employee_username):
        # SQLite in some deployed DBs enforces a unique constraint on employee_username
        # regardless of dotted-line flag. Always resolve by employee_username first.
        return (
            UserDirectReport.query
            .filter_by(employee_username=employee_username)
            .order_by(UserDirectReport.is_dotted_line.asc(), UserDirectReport.updated_at.desc())
            .first()
        )

    def _upsert_employee_chain(
        employee_identity,
        manager_identity=None,
        outside_manager_name=None,
        department='Management',
        is_same_department=False,
        supervisor_identity=None,
        outside_supervisor_name=None
    ):
        nonlocal updated, assigned
        existing = _get_employee_report(employee_identity['username'])
        if existing:
            changed = False
            if existing.is_dotted_line:
                existing.is_dotted_line = False
                changed = True

            if manager_identity:
                if existing.manager_username != manager_identity['username']:
                    existing.manager_username = manager_identity['username']
                    changed = True
                if existing.manager_dn != manager_identity['dn']:
                    existing.manager_dn = manager_identity['dn']
                    changed = True
                if existing.is_outside_manager:
                    existing.is_outside_manager = False
                    existing.manager_display_name = None
                    changed = True
            elif outside_manager_name:
                if existing.manager_username != outside_manager_name:
                    existing.manager_username = outside_manager_name
                    changed = True
                if existing.manager_dn is not None:
                    existing.manager_dn = None
                    changed = True
                if existing.manager_display_name != outside_manager_name:
                    existing.manager_display_name = outside_manager_name
                    changed = True
                if not existing.is_outside_manager:
                    existing.is_outside_manager = True
                    changed = True

            if existing.employee_dn != employee_identity['dn']:
                existing.employee_dn = employee_identity['dn']
                changed = True
            if existing.employee_display_name != employee_identity['display']:
                existing.employee_display_name = employee_identity['display']
                changed = True
            if existing.department != department:
                existing.department = department
                changed = True
            if existing.is_same_department != is_same_department:
                existing.is_same_department = is_same_department
                changed = True

            if supervisor_identity or outside_supervisor_name:
                if not existing.is_indirect_report:
                    existing.is_indirect_report = True
                    changed = True
                if supervisor_identity:
                    if existing.supervisor_username != supervisor_identity['username']:
                        existing.supervisor_username = supervisor_identity['username']
                        changed = True
                    if existing.supervisor_dn != supervisor_identity['dn']:
                        existing.supervisor_dn = supervisor_identity['dn']
                        changed = True
                    if existing.supervisor_display_name != supervisor_identity['display']:
                        existing.supervisor_display_name = supervisor_identity['display']
                        changed = True
                    if existing.is_outside_supervisor:
                        existing.is_outside_supervisor = False
                        changed = True
                else:
                    if existing.supervisor_username != outside_supervisor_name:
                        existing.supervisor_username = outside_supervisor_name
                        changed = True
                    if existing.supervisor_dn is not None:
                        existing.supervisor_dn = None
                        changed = True
                    if existing.supervisor_display_name != outside_supervisor_name:
                        existing.supervisor_display_name = outside_supervisor_name
                        changed = True
                    if not existing.is_outside_supervisor:
                        existing.is_outside_supervisor = True
                        changed = True
            else:
                if existing.is_indirect_report:
                    existing.is_indirect_report = False
                    existing.supervisor_username = None
                    existing.supervisor_dn = None
                    existing.supervisor_display_name = None
                    existing.is_outside_supervisor = False
                    changed = True

            if changed:
                existing.updated_at = datetime.now(timezone.utc)
                updated += 1
            return

        db.session.add(UserDirectReport(
            manager_username=manager_identity['username'] if manager_identity else outside_manager_name,
            manager_dn=manager_identity['dn'] if manager_identity else None,
            manager_display_name=None if manager_identity else outside_manager_name,
            is_outside_manager=False if manager_identity else True,
            employee_username=employee_identity['username'],
            employee_dn=employee_identity['dn'],
            employee_display_name=employee_identity['display'],
            department=department,
            is_same_department=is_same_department,
            is_indirect_report=bool(supervisor_identity or outside_supervisor_name),
            supervisor_username=(
                supervisor_identity['username'] if supervisor_identity
                else (outside_supervisor_name if outside_supervisor_name else None)
            ),
            supervisor_dn=(supervisor_identity['dn'] if supervisor_identity else None),
            supervisor_display_name=(
                supervisor_identity['display'] if supervisor_identity
                else (outside_supervisor_name if outside_supervisor_name else None)
            ),
            is_outside_supervisor=False if supervisor_identity else bool(outside_supervisor_name),
            is_dotted_line=False
        ))
        assigned += 1

    # Explicit single assignments
    for rule in policy.get('explicit_assignments') or []:
        if not isinstance(rule, dict):
            continue
        employee_identity = _resolve_from_candidates(rule.get('employee_candidates'))
        if not employee_identity:
            continue
        manager_identity = _resolve_from_candidates(rule.get('manager_candidates'))
        outside_manager_name = (rule.get('outside_manager_name') or '').strip() or None
        if not manager_identity and not outside_manager_name:
            continue
        _upsert_employee_chain(
            employee_identity=employee_identity,
            manager_identity=manager_identity,
            outside_manager_name=outside_manager_name,
            department=(rule.get('department') or 'Management').strip() or 'Management',
            is_same_department=bool(rule.get('is_same_department', False)),
            supervisor_identity=_resolve_from_candidates(rule.get('supervisor_candidates')),
            outside_supervisor_name=(rule.get('outside_supervisor_name') or '').strip() or None
        )
        if rule.get('exclude_from_default_route', True):
            special_exception_usernames.add(employee_identity['username'].lower())

    # Dual reports (primary manager + supervisor manager)
    for rule in policy.get('dual_reports') or []:
        if not isinstance(rule, dict):
            continue
        primary_identity = _resolve_from_candidates(rule.get('primary_manager_candidates'))
        secondary_identity = _resolve_from_candidates(rule.get('secondary_manager_candidates'))
        if not primary_identity:
            continue

        targets = {}
        for target in rule.get('target_candidates') or []:
            target_identity = _resolve_from_candidates(target if isinstance(target, list) else [target])
            if target_identity:
                targets[target_identity['username'].lower()] = target_identity

        ou_contains_filters = [f.lower() for f in (rule.get('target_ou_contains') or []) if isinstance(f, str) and f.strip()]
        if ou_contains_filters:
            scoped_users = search_users('', status_filter='all', **ad_args) or []
            for user in scoped_users:
                user_dn = _ad_attr_scalar(user.get('distinguishedName') or user.get('dn')).strip()
                dn_l = user_dn.lower()
                if not any(token in dn_l for token in ou_contains_filters):
                    continue
                username = _ad_attr_scalar(user.get('sAMAccountName') or user.get('username')).strip()
                if not username:
                    continue
                targets[username.lower()] = {
                    'username': username,
                    'dn': user_dn,
                    'display': _ad_attr_scalar(user.get('displayName') or user.get('cn') or username)
                }

        dept_like = (rule.get('include_department_manager_like') or '').strip()
        if dept_like:
            dept_mgr = DepartmentManager.query.filter(DepartmentManager.department.ilike(f"%{dept_like}%")).first()
            if dept_mgr and dept_mgr.manager_username:
                dept_mgr_identity = _resolve_ad_user_identity(dept_mgr.manager_username, ad_args)
                if dept_mgr_identity:
                    targets[dept_mgr_identity['username'].lower()] = dept_mgr_identity

        for target_identity in targets.values():
            if target_identity['username'].lower() in {primary_identity['username'].lower(), (secondary_identity['username'].lower() if secondary_identity else '')}:
                continue
            _upsert_employee_chain(
                employee_identity=target_identity,
                manager_identity=primary_identity,
                department=(rule.get('department') or 'Management').strip() or 'Management',
                is_same_department=bool(rule.get('is_same_department', False)),
                supervisor_identity=secondary_identity
            )
            if rule.get('exclude_from_default_route', True):
                special_exception_usernames.add(target_identity['username'].lower())

    for manager_username in sorted(all_managers):
        if not manager_username:
            continue
        lower_name = manager_username.strip().lower()
        if lower_name in excluded_manager_names or lower_name in special_exception_usernames:
            skipped += 1
            continue
        if lower_name == default_mgr['username'].lower():
            skipped += 1
            continue
        if top_mgr and lower_name == top_mgr['username'].lower():
            skipped += 1
            continue

        manager_identity = _resolve_ad_user_identity(manager_username, ad_args)
        if not manager_identity:
            skipped += 1
            continue

        # Keep self-assignment impossible.
        if manager_identity['username'].lower() == default_mgr['username'].lower():
            skipped += 1
            continue

        _upsert_employee_chain(
            employee_identity=manager_identity,
            manager_identity=default_mgr,
            department='Management',
            is_same_department=False
        )

    # Optional top-manager chain (e.g., default manager reports to top manager).
    if top_mgr:
        _upsert_employee_chain(
            employee_identity=default_mgr,
            manager_identity=top_mgr,
            department='Management',
            is_same_department=False
        )

    if assigned or updated:
        db.session.commit()
    return {'updated': updated, 'assigned': assigned, 'skipped': skipped, 'missing': None}

def _auto_sync_department_direct_reports(ad_args, top_departments, dept_managers, primary_users_ou=None):
    """
    Keep primary direct reports in sync with current AD users:
    - missing department manager -> fallback to default manager from local policy
    - new users get assigned
    - removed users are cleaned up
    """
    policy = _load_manager_policy()
    default_manager = _resolve_default_manager(ad_args)
    default_missing = False

    excluded_username_tokens = {'services', 'service', 'vendor', 'vendors'}
    excluded_dn_tokens = (
        'ou=vendor',
        'ou=vendors',
        'ou=vendor logins',
        'ou=service accounts',
        'ou=internal tools'
    )
    dept_sync = policy.get('department_sync') or {}
    dept_excluded_usernames = set()
    for candidate in dept_sync.get('exclude_employee_candidates') or []:
        identity = _resolve_ad_user_identity(candidate, ad_args)
        if identity and identity.get('username'):
            dept_excluded_usernames.add(identity['username'].lower())
    dept_overrides = {}
    for override in dept_sync.get('department_overrides') or []:
        if not isinstance(override, dict):
            continue
        dept_label = (override.get('department') or '').strip()
        if not dept_label:
            continue
        identity = _resolve_ad_user_identity(override.get('employee_candidate'), ad_args)
        if identity and identity.get('username'):
            dept_overrides[identity['username'].lower()] = dept_label

    def _is_excluded_user(username, dn, display):
        dn_l = (dn or '').strip().lower()
        username_l = (username or '').strip().lower()
        display_l = (display or '').strip().lower()

        if primary_users_ou and primary_users_ou.strip().lower() not in dn_l:
            return True
        if any(token in dn_l for token in excluded_dn_tokens):
            return True
        if username_l in excluded_username_tokens or display_l in excluded_username_tokens:
            return True
        if username_l in dept_excluded_usernames:
            return True
        return False

    ad_users = search_users('', status_filter='all', **ad_args) or []
    ad_usernames = set()
    for u in ad_users:
        uname = _ad_attr_scalar(u.get('sAMAccountName') or u.get('username')).strip()
        dn = _ad_attr_scalar(u.get('distinguishedName') or u.get('dn')).strip()
        display = _ad_attr_scalar(u.get('displayName') or u.get('cn') or uname)
        if _is_excluded_user(uname, dn, display):
            continue
        if uname:
            ad_usernames.add(uname.lower())

    removed = 0
    # Remove stale primary reports for users no longer in AD.
    stale_reports = UserDirectReport.query.filter_by(is_dotted_line=False).all()
    for report in stale_reports:
        if _is_excluded_user(report.employee_username, report.employee_dn, report.employee_display_name):
            db.session.delete(report)
            removed += 1
            continue
        if (report.employee_username or '').strip().lower() not in ad_usernames:
            db.session.delete(report)
            removed += 1

    assigned = 0
    updated = 0
    for dept in top_departments:
        dept_key = dept.get('key')
        dept_name = dept.get('name') or dept_key
        dept_dn = dept.get('dn')
        if not dept_key or not dept_dn:
            continue

        dept_mgr = dept_managers.get(dept_key)
        if dept_mgr and dept_mgr.manager_username:
            manager_username = dept_mgr.manager_username
            manager_dn = dept_mgr.manager_dn
            manager_display = dept_mgr.manager_display_name
        elif default_manager:
            manager_username = default_manager['username']
            manager_dn = default_manager['dn']
            manager_display = default_manager['display']
        else:
            default_missing = True
            continue

        is_outside_manager = False if manager_dn else True
        if not is_outside_manager and manager_username:
            manager_identity = _resolve_ad_user_identity(manager_username, ad_args)
            if manager_identity:
                manager_username = manager_identity['username']
                manager_dn = manager_identity['dn']
                manager_display = manager_identity.get('display') or manager_display

        dept_users = [u for u in ad_users if dept_dn.lower() in _ad_attr_scalar(u.get('distinguishedName') or u.get('dn')).lower()]
        for user in dept_users:
            employee_username = _ad_attr_scalar(user.get('sAMAccountName') or user.get('username')).strip()
            employee_dn = _ad_attr_scalar(user.get('distinguishedName') or user.get('dn')).strip()
            employee_display = _ad_attr_scalar(user.get('displayName') or user.get('cn') or employee_username)
            if not employee_username or not employee_dn:
                continue
            if _is_excluded_user(employee_username, employee_dn, employee_display):
                existing_excluded = UserDirectReport.query.filter_by(employee_username=employee_username, is_dotted_line=False).first()
                if existing_excluded:
                    db.session.delete(existing_excluded)
                    removed += 1
                continue
            effective_department = dept_overrides.get(employee_username.lower(), dept_name)

            # Never self-assign.
            if employee_username.lower() == manager_username.lower():
                continue
            if manager_dn and employee_dn.lower() == manager_dn.lower():
                continue

            existing = UserDirectReport.query.filter_by(employee_username=employee_username, is_dotted_line=False).first()
            if existing:
                changed = False
                if existing.manager_username != manager_username:
                    existing.manager_username = manager_username
                    changed = True
                if existing.manager_dn != manager_dn:
                    existing.manager_dn = manager_dn
                    changed = True
                if existing.manager_display_name != (manager_display if is_outside_manager else None):
                    existing.manager_display_name = manager_display if is_outside_manager else None
                    changed = True
                if existing.is_outside_manager != is_outside_manager:
                    existing.is_outside_manager = is_outside_manager
                    changed = True
                if existing.department != effective_department:
                    existing.department = effective_department
                    changed = True
                if not existing.is_same_department:
                    existing.is_same_department = True
                    changed = True
                if existing.is_indirect_report:
                    existing.is_indirect_report = False
                    existing.supervisor_username = None
                    existing.supervisor_dn = None
                    existing.supervisor_display_name = None
                    existing.is_outside_supervisor = False
                    changed = True
                if changed:
                    existing.updated_at = datetime.now(timezone.utc)
                    updated += 1
            else:
                db.session.add(UserDirectReport(
                    manager_username=manager_username,
                    manager_dn=manager_dn,
                    manager_display_name=manager_display if is_outside_manager else None,
                    is_outside_manager=is_outside_manager,
                    employee_username=employee_username,
                    employee_dn=employee_dn,
                    employee_display_name=employee_display,
                    department=effective_department,
                    is_same_department=True,
                    is_dotted_line=False
                ))
                assigned += 1

    if assigned or updated or removed:
        db.session.commit()
    return {'assigned': assigned, 'updated': updated, 'removed': removed, 'default_missing': default_missing}

def _ensure_default_ou_mapping(company_name, base_dn, ad_args, user_placement_mode='single_users_ou', department_structure=None):
    """
    Create a default OU hierarchy for greenfield environments.
    Safe to run repeatedly: existing OUs are skipped.
    """
    company_ou = _sanitize_ou_name(company_name)
    if not company_ou:
        return False, "Company name is required for default OU mapping.", {}

    root_dn = f"OU={company_ou},{base_dn}"
    desired_ous = [
        (company_ou, base_dn),
        ('Users', root_dn),
        ('Computers', root_dn),
        ('Servers', root_dn),
        ('Groups', root_dn),
        ('Disabled Users', root_dn),
        ('Archived Users', root_dn),
        ('Service Accounts', root_dn),
        ('Internal Tools', root_dn)
    ]
    users_root_dn = f"OU=Users,{root_dn}"
    cleaned_departments = []
    cleaned_department_structure = {}
    if user_placement_mode == 'department_ous':
        for dept, subs in (department_structure or {}).items():
            dept_name = _sanitize_ou_name(dept)
            if not dept_name:
                continue
            if dept_name.lower() not in [d.lower() for d in cleaned_departments]:
                cleaned_departments.append(dept_name)
            cleaned_department_structure[dept_name] = []
            for sub in (subs or []):
                sub_name = _sanitize_ou_name(sub)
                if sub_name and sub_name.lower() not in [s.lower() for s in cleaned_department_structure[dept_name]]:
                    cleaned_department_structure[dept_name].append(sub_name)

        for dept_name in cleaned_departments:
            desired_ous.append((dept_name, users_root_dn))
            dept_dn = f"OU={dept_name},{users_root_dn}"
            for sub_name in cleaned_department_structure.get(dept_name, []):
                desired_ous.append((sub_name, dept_dn))

    existing_dns = {ou.get('dn', '').lower() for ou in (list_ous(**ad_args) or []) if ou.get('dn')}
    created = []
    skipped = []
    errors = []

    for ou_name, parent_dn in desired_ous:
        ou_dn = f"OU={ou_name},{parent_dn}"
        if ou_dn.lower() in existing_dns:
            skipped.append(ou_dn)
            continue
        ok, msg = create_ou(ou_name, parent_dn, **ad_args)
        if ok:
            created.append(ou_dn)
            existing_dns.add(ou_dn.lower())
        else:
            errors.append(f"{ou_dn}: {msg}")

    groups_ou_dn = f"OU=Groups,{root_dn}"
    group_results = {'created': [], 'skipped': [], 'errors': []}
    if cleaned_departments:
        group_results = _ensure_department_security_groups(cleaned_departments, groups_ou_dn, ad_args)
        errors.extend(group_results['errors'])

    mapping = {
        'primary_users_ou': users_root_dn,
        'disabled_users_ou': f"OU=Disabled Users,{root_dn}",
        'archive_users_ou': f"OU=Archived Users,{root_dn}",
        'service_accounts_ou': f"OU=Service Accounts,{root_dn}",
        'internal_tools_ou': f"OU=Internal Tools,{root_dn}",
        'primary_users_label': company_ou,
        'user_placement_mode': user_placement_mode
    }
    if cleaned_departments:
        mapping['department_user_ous'] = [f"OU={dept},{users_root_dn}" for dept in cleaned_departments]
        mapping['department_sub_ous'] = {
            dept: [f"OU={sub},OU={dept},{users_root_dn}" for sub in cleaned_department_structure.get(dept, [])]
            for dept in cleaned_departments
        }

    if errors:
        return False, f"Default OU mapping completed with errors ({len(errors)}).", {
            'created': created,
            'skipped': skipped,
            'errors': errors,
            'mapping': mapping,
            'departments': cleaned_departments,
            'department_groups': group_results,
            'department_structure': cleaned_department_structure
        }
    return True, f"Default OU mapping ready. Created {len(created)} OUs, skipped {len(skipped)} existing.", {
        'created': created,
        'skipped': skipped,
        'errors': [],
        'mapping': mapping,
        'departments': cleaned_departments,
        'department_groups': group_results,
        'department_structure': cleaned_department_structure
    }

def trigger_all_active_mailbox_refresh(force=False):
    """Refresh and persist mailbox sizes for all active users on a timed interval."""
    global _last_mailbox_refresh_run_at, _mailbox_refresh_in_progress

    now = datetime.now(timezone.utc)
    with _mailbox_refresh_lock:
        if _mailbox_refresh_in_progress:
            return
        if (
            not force
            and _last_mailbox_refresh_run_at
            and (now - _last_mailbox_refresh_run_at).total_seconds() < MAILBOX_REFRESH_INTERVAL_SECONDS
        ):
            return
        _mailbox_refresh_in_progress = True
        _last_mailbox_refresh_run_at = now

    app_obj = current_app._get_current_object()

    def _refresh_job():
        global _mailbox_refresh_in_progress
        try:
            with app_obj.app_context():
                config = get_exchange_config()
                if not config or not config.get('enabled'):
                    return

                ad_config = get_ad_config()
                if not ad_config:
                    return

                ad_args = {
                    'server': ad_config['ad_server'],
                    'port': ad_config['ad_port'],
                    'bind_user': ad_config['ad_bind_dn'],
                    'bind_password': ad_config['ad_password'],
                    'base_dn': ad_config['ad_base_dn']
                }
                users = search_users(
                    '',
                    status_filter='enabled',
                    exclude_ous=[],
                    include_disabled_ou=True,
                    include_archive_ou=True,
                    **ad_args
                )
                user_emails = list({
                    (u.get('mail') or '').strip().lower()
                    for u in users
                    if (u.get('mail') or '').strip()
                })

                mailbox_sizes = {}
                if user_emails:
                    exchange = ExchangeManager(
                        exchange_server=config['exchange_server'],
                        username=config['username'],
                        password=config['password'],
                        domain=config['domain']
                    )
                    mailbox_sizes = exchange.get_mailbox_sizes(user_emails)

                from .models import MailboxSizeCache
                cache_entry = db.session.query(MailboxSizeCache).filter_by(
                    username='__system__',
                    query='',
                    status_filter='enabled',
                    exclude_ous='__all_active__'
                ).first()
                if cache_entry:
                    cache_entry.mailbox_sizes = json.dumps(mailbox_sizes)
                    cache_entry.updated_at = datetime.now(timezone.utc)
                else:
                    cache_entry = MailboxSizeCache(
                        username='__system__',
                        query='',
                        status_filter='enabled',
                        exclude_ous='__all_active__',
                        mailbox_sizes=json.dumps(mailbox_sizes)
                    )
                    db.session.add(cache_entry)
                db.session.commit()
                current_app.logger.info(
                    f"All-active mailbox refresh complete: {len(mailbox_sizes)} cached of {len(user_emails)} users"
                )
        except Exception as e:
            db.session.rollback()
            current_app.logger.warning(f"All-active mailbox refresh failed: {e}")
        finally:
            with _mailbox_refresh_lock:
                _mailbox_refresh_in_progress = False

    threading.Thread(target=_refresh_job, daemon=True).start()

@main.before_app_request
def enforce_setup():
    try:
        run_disabled_user_archive_maintenance()
    except Exception as e:
        current_app.logger.warning(f"Disabled-user archive maintenance error: {e}")
    try:
        trigger_all_active_mailbox_refresh()
    except Exception as e:
        current_app.logger.warning(f"Mailbox refresh maintenance error: {e}")

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
            return redirect(url_for('main.unified_login'))
        
        # Check if user is admin via session role
        role = session.get('role', 'user')
        view_mode = session.get('view_mode', role)
        
        # If session says admin, allow access
        if role == 'admin' or view_mode == 'admin':
            return f(*args, **kwargs)
        
        # Check if user exists in Admin table (local admin)
        admin_record = Admin.query.filter_by(username=current_user.username).first()
        if admin_record:
            # User is in Admin table - grant admin access
            session['role'] = 'admin'
            session['view_mode'] = 'admin'
            return f(*args, **kwargs)
        
        # If AD is configured, check if user is in admin group
        config = get_ad_config()
        if config:
            try:
                is_admin_user = is_user_in_admin_group(
                    current_user.username,
                    server=config['ad_server'],
                    port=config['ad_port'],
                    bind_user=config['ad_bind_dn'],
                    bind_password=config['ad_password'],
                    base_dn=config['ad_base_dn']
                )
                if is_admin_user:
                    # Update session to reflect admin status
                    session['role'] = 'admin'
                    session['view_mode'] = 'admin'
                    return f(*args, **kwargs)
            except Exception as e:
                # If AD check fails, fall back to local admin check
                pass
        
        # Not an admin - deny access
        flash('Access denied. Administrator privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))
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
        setup_mode = request.form.get('setup_mode', 'existing')
        use_default_mapping = request.form.get('use_default_mapping') == 'on'
        company_name = request.form.get('company_name', '').strip()
        user_placement_mode = request.form.get('user_placement_mode', 'single_users_ou')
        hierarchy_input_mode = request.form.get('hierarchy_input_mode', 'manual')
        departments_raw = request.form.get('department_hierarchy_manual', '').strip()
        department_structure = {}
        parse_error = None
        if user_placement_mode == 'department_ous':
            if hierarchy_input_mode == 'file':
                department_structure, parse_error = _parse_department_hierarchy_file(
                    request.files.get('department_hierarchy_file')
                )
            else:
                department_structure, parse_error = _parse_department_hierarchy_text(departments_raw)
                # Backward compatibility: comma-separated departments from old field.
                if not department_structure and request.form.get('department_ous', '').strip():
                    fallback_depts = [d.strip() for d in request.form.get('department_ous', '').split(',') if d.strip()]
                    department_structure = {_sanitize_ou_name(d): [] for d in fallback_depts if _sanitize_ou_name(d)}
        source_is_default_admin = _is_default_ad_administrator(request.form.get('ad_bind_dn', ''))
        clone_default_admin = request.form.get('clone_default_admin') == 'on'
        delegated_admin_username = request.form.get('delegated_admin_username', '').strip()
        delegated_admin_password = request.form.get('delegated_admin_password', '')
        delegated_admin_display_name = request.form.get('delegated_admin_display_name', '').strip()
        delegated_admin_email = request.form.get('delegated_admin_email', '').strip()
        
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
        
        # Get password from secure storage for testing
        test_password = get_credential('ad_password') or request.form.get('ad_password', '')

        ad_args = {
            'server': config_data['ad_server'],
            'port': config_data['ad_port'],
            'bind_user': config_data['ad_bind_dn'],
            'bind_password': test_password,
            'base_dn': config_data['ad_base_dn']
        }
        
        ok, msg = test_ad_connection(
            server=config_data['ad_server'],
            port=config_data['ad_port'],
            bind_user=config_data['ad_bind_dn'],
            bind_password=test_password
        )
        if ok:
            if source_is_default_admin and clone_default_admin:
                if not delegated_admin_username or not delegated_admin_password:
                    flash('Delegated admin username and password are required when cloning Administrator.', 'danger')
                    return render_template('setup.html', config=config_data)

            if setup_mode != 'new':
                if not request.form.get('users_ou', '').strip():
                    flash('Existing AD setup requires manual Users OU mapping.', 'danger')
                    return render_template('setup.html', config=config_data)
                if not request.form.get('groups_ou', '').strip():
                    flash('Existing AD setup requires manual Groups OU mapping.', 'danger')
                    return render_template('setup.html', config=config_data)

            if setup_mode == 'new' and use_default_mapping:
                if user_placement_mode == 'department_ous' and parse_error:
                    flash(parse_error, 'danger')
                    return render_template('setup.html', config=config_data)
                if user_placement_mode == 'department_ous' and not department_structure:
                    flash('Please provide at least one department hierarchy entry (manual or file).', 'danger')
                    return render_template('setup.html', config=config_data)

                mapping_ok, mapping_msg, mapping_details = _ensure_default_ou_mapping(
                    company_name,
                    config_data['ad_base_dn'],
                    ad_args,
                    user_placement_mode=user_placement_mode,
                    department_structure=department_structure
                )
                if mapping_details.get('mapping'):
                    config_data['organization_ous'] = mapping_details['mapping']
                    config_data['users_ou'] = mapping_details['mapping'].get('primary_users_ou', config_data.get('users_ou', ''))
                    config_data['groups_ou'] = f"OU=Groups,OU={_sanitize_ou_name(company_name)},{config_data['ad_base_dn']}"
                if mapping_ok:
                    flash(mapping_msg, 'success')
                else:
                    flash(mapping_msg, 'warning')
                    for item in mapping_details.get('errors', [])[:5]:
                        flash(item, 'warning')
                group_info = mapping_details.get('department_groups') or {}
                if group_info.get('created') or group_info.get('skipped'):
                    flash(
                        f"Department security groups: {len(group_info.get('created', []))} created, "
                        f"{len(group_info.get('skipped', []))} existing.",
                        'info'
                    )
            elif setup_mode != 'new':
                users_ou_dn = request.form.get('users_ou', '').strip()
                lifecycle_ok, lifecycle_msg, lifecycle_details = _ensure_lifecycle_ous_under_users(users_ou_dn, ad_args)
                if 'organization_ous' not in config_data:
                    config_data['organization_ous'] = {}
                config_data['organization_ous']['primary_users_ou'] = users_ou_dn
                config_data['organization_ous']['disabled_users_ou'] = lifecycle_details.get('disabled_users_ou', '')
                config_data['organization_ous']['archive_users_ou'] = lifecycle_details.get('archive_users_ou', '')
                config_data['organization_ous']['primary_users_label'] = users_ou_dn.split('OU=')[-1].split(',')[0] if 'OU=' in users_ou_dn else 'Users'
                if lifecycle_ok:
                    flash(lifecycle_msg, 'success')
                else:
                    flash(lifecycle_msg, 'warning')
                    for item in lifecycle_details.get('errors', [])[:5]:
                        flash(item, 'warning')

            if source_is_default_admin and clone_default_admin:
                target_users_ou = config_data.get('users_ou') or request.form.get('users_ou') or config_data.get('ad_base_dn')
                clone_ok, clone_msg = _provision_delegated_admin_from_bind(
                    source_admin_dn=config_data['ad_bind_dn'],
                    new_username=delegated_admin_username,
                    new_password=delegated_admin_password,
                    new_display_name=delegated_admin_display_name or delegated_admin_username,
                    new_email=delegated_admin_email,
                    target_users_ou=target_users_ou,
                    ad_args=ad_args
                )
                if clone_ok:
                    flash(clone_msg, 'success')
                else:
                    flash(clone_msg, 'warning')

            # Set up organization_ous if users_ou is provided (manual/legacy path)
            if request.form.get('users_ou') and 'organization_ous' not in config_data:
                if 'organization_ous' not in config_data:
                    config_data['organization_ous'] = {}
                config_data['organization_ous']['primary_users_ou'] = request.form.get('users_ou')
                config_data['organization_ous']['primary_users_label'] = request.form.get('users_ou').split('OU=')[-1].split(',')[0] if 'OU=' in request.form.get('users_ou') else 'Users'

            save_ad_config(config_data)
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
            
            # Reset password in AD (prefer DN from prior lookup if available)
            user_dn = user_info.get('dn') or user_info.get('distinguishedName') or username
            success, reset_message = reset_user_password(user_dn, new_password, **{
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
                    reset_by=username,
                    method='security_question',
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
                return redirect(url_for('main.unified_login'))
            else:
                flash(f'Failed to reset password in Active Directory: {reset_message}', 'error')
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
    view_mode = request.form.get('view_mode', 'active') if request.method == 'POST' else request.args.get('view_mode', 'active')
    include_archived = request.form.get('include_archived', '0') == '1' if request.method == 'POST' else request.args.get('include_archived', '0') == '1'

    include_disabled_ou = False
    include_archive_ou = False
    if view_mode == 'disabled':
        status_filter = 'disabled'
        include_disabled_ou = True
        include_archived = False
    elif view_mode == 'archived':
        include_archive_ou = True
        include_archived = True
    
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
        users = search_users(
            query,
            status_filter=status_filter,
            exclude_ous=exclude_ous,
            include_archive_ou=include_archive_ou,
            include_disabled_ou=include_disabled_ou,
            **ad_args
        )
        log_user_action(
            'search',
            query,
            'success' if users else 'no_results',
            {
                'query': query,
                'status_filter': status_filter,
                'exclude_ous': exclude_ous,
                'view_mode': view_mode,
                'include_archived': include_archived,
                'results_count': len(users)
            }
        )
    else:
        # Show all users when no query is provided
        users = search_users(
            '',
            status_filter=status_filter,
            exclude_ous=exclude_ous,
            include_archive_ou=include_archive_ou,
            include_disabled_ou=include_disabled_ou,
            **ad_args
        )
        log_user_action(
            'search',
            'all_users',
            'success' if users else 'no_results',
            {
                'query': 'all_users',
                'status_filter': status_filter,
                'exclude_ous': exclude_ous,
                'view_mode': view_mode,
                'include_archived': include_archived,
                'results_count': len(users)
            }
        )

    # Constrain special views to their specific lifecycle OU containers.
    if view_mode == 'disabled':
        disabled_ou_dn = _resolve_existing_disabled_ou(config, ad_args)
        users = [
            u for u in users
            if (
                (disabled_ou_dn and disabled_ou_dn.lower() in (u.get('dn', '').lower()))
                or ('ou=disabled users' in (u.get('dn', '').lower()))
            )
        ]
    elif view_mode == 'archived':
        archive_ou_dn = _resolve_existing_archive_ou(config, ad_args)
        users = [
            u for u in users
            if (
                (archive_ou_dn and archive_ou_dn.lower() in (u.get('dn', '').lower()))
                or ('ou=archived users' in (u.get('dn', '').lower()))
            )
        ]

    # Attach lifecycle timing so Disabled/Archived views can show age in OU.
    usernames = [u.get('username') for u in users if u.get('username')]
    lifecycle_by_username = {}
    if usernames:
        lifecycle_rows = DisabledUserLifecycle.query.filter(
            DisabledUserLifecycle.username.in_(usernames)
        ).all()
        lifecycle_by_username = {row.username: row for row in lifecycle_rows}

    now_utc = datetime.now(timezone.utc)
    for user in users:
        disabled_since = None
        user_name = user.get('username')
        lifecycle = lifecycle_by_username.get(user_name) if user_name else None

        if lifecycle and lifecycle.disabled_at:
            disabled_since = _to_utc_datetime(lifecycle.disabled_at)
        elif user.get('accountStatus') == 'disabled':
            when_changed = user.get('whenChanged')
            if isinstance(when_changed, datetime):
                disabled_since = _to_utc_datetime(when_changed)

        user['disabled_since'] = disabled_since
        user['disabled_days'] = (now_utc - disabled_since).days if disabled_since else None
    
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
        user_stats=user_stats,
        include_archived=include_archived,
        view_mode=view_mode
    )

@main.route('/admin/users/disabled')
@login_required
@admin_required
def disabled_users_view():
    return redirect(url_for('main.user_search', view_mode='disabled'))

@main.route('/admin/users/archived')
@login_required
@admin_required
def archived_users_view():
    return redirect(url_for('main.user_search', view_mode='archived'))

@main.route('/admin/computers', methods=['GET', 'POST'])
@login_required
@admin_required
def computer_search():
    """Computer and server management page"""
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
    computer_type = request.form.get('computer_type', 'all') if request.method == 'POST' else request.args.get('computer_type', 'all')
    
    # Handle OU exclusions
    exclude_ous = []
    if request.method == 'POST':
        exclude_ous_raw = request.form.get('exclude_ous', '')
    else:
        exclude_ous_raw = request.args.get('exclude_ous', '')
    
    if exclude_ous_raw:
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
    
    computers = []
    
    # Always search for computers - if no query, search for all computers
    if query:
        computers = search_computers(query, status_filter=status_filter, exclude_ous=exclude_ous, computer_type=computer_type, **ad_args)
        log_user_action('search', f'computers: {query}', 'success' if computers else 'no_results', {'query': query, 'status_filter': status_filter, 'computer_type': computer_type, 'exclude_ous': exclude_ous, 'results_count': len(computers)})
    else:
        # Show all computers when no query is provided
        computers = search_computers('', status_filter=status_filter, exclude_ous=exclude_ous, computer_type=computer_type, **ad_args)
        log_user_action('search', 'all_computers', 'success' if computers else 'no_results', {'query': 'all_computers', 'status_filter': status_filter, 'computer_type': computer_type, 'exclude_ous': exclude_ous, 'results_count': len(computers)})
    
    # Server-side sorting
    sort_by = request.args.get('sort_by', 'name')
    sort_order = request.args.get('sort_order', 'asc')
    
    # Validate sort_by parameter
    valid_sort_fields = ['name', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'computerType', 'ou', 'accountStatus']
    if sort_by not in valid_sort_fields:
        sort_by = 'name'
    
    # Sort computers
    reverse_sort = sort_order.lower() == 'desc'
    
    # Handle empty values in sorting
    def sort_key(computer):
        value = computer.get(sort_by, '')
        if value is None:
            value = ''
        return str(value).lower()
    
    computers.sort(key=sort_key, reverse=reverse_sort)
    
    # Pagination logic
    page = int(request.args.get('page', 1))
    per_page = 50
    total_computers = len(computers)
    total_pages = (total_computers + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    computers_page = computers[start:end]
    
    # Get OUs for move computer functionality
    ous = list_ous(**ad_args)
    
    # Get computer statistics
    computer_stats = {
        'total': len(computers),
        'total_enabled': 0,
        'total_disabled': 0,
        'servers': 0,
        'workstations': 0
    }
    
    # Count computers by status and type
    for computer in computers:
        if computer.get('accountStatus') == 'enabled':
            computer_stats['total_enabled'] += 1
        else:
            computer_stats['total_disabled'] += 1
        
        if computer.get('computerType') == 'server':
            computer_stats['servers'] += 1
        else:
            computer_stats['workstations'] += 1
    
    return render_template(
        'computer_search.html', 
        computers=computers_page, 
        query=query, 
        status_filter=status_filter,
        computer_type=computer_type,
        exclude_ous=exclude_ous,
        exclude_ous_str=','.join(exclude_ous),
        ous=ous, 
        base_dn=config['ad_base_dn'],
        page=page,
        total_pages=total_pages,
        total_computers=total_computers,
        sort_by=sort_by,
        sort_order=sort_order,
        computer_stats=computer_stats
    )

@main.route('/api/computers/stats')
@login_required
@admin_required
def api_get_computer_stats():
    """API endpoint to get filtered computer statistics"""
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
        
        query = request.args.get('query', '')
        status_filter = request.args.get('status_filter', 'all')
        computer_type = request.args.get('computer_type', 'all')
        exclude_ous_raw = request.args.get('exclude_ous', '')
        
        exclude_ous = []
        if exclude_ous_raw:
            exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        
        # Search computers
        if query:
            computers = search_computers(query, status_filter=status_filter, exclude_ous=exclude_ous, computer_type=computer_type, **ad_args)
        else:
            computers = search_computers('', status_filter=status_filter, exclude_ous=exclude_ous, computer_type=computer_type, **ad_args)
        
        # Calculate statistics
        stats = {
            'total': len(computers),
            'total_enabled': 0,
            'total_disabled': 0,
            'servers': 0,
            'workstations': 0
        }
        
        for computer in computers:
            if computer.get('accountStatus') == 'enabled':
                stats['total_enabled'] += 1
            else:
                stats['total_disabled'] += 1
            
            if computer.get('computerType') == 'server':
                stats['servers'] += 1
            else:
                stats['workstations'] += 1
        
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main.route('/admin/move_computer', methods=['POST'])
@login_required
@admin_required
def move_computer_route():
    """Move a computer to a new OU"""
    try:
        data = request.get_json()
        computer_dn = data.get('computer_dn')
        new_ou_dn = data.get('new_ou_dn')
        
        if not computer_dn or not new_ou_dn:
            return jsonify({'success': False, 'error': 'Computer DN and new OU DN are required'}), 400
        
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
        
        success, message = move_computer_to_ou(computer_dn, new_ou_dn, **ad_args)
        
        if success:
            log_user_action('move_computer', computer_dn, 'success', {'new_ou': new_ou_dn})
            return jsonify({'success': True, 'message': message})
        else:
            log_user_action('move_computer', computer_dn, 'failure', {'error': message})
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main.route('/admin/bulk-move-workstations', methods=['POST'])
@login_required
@admin_required
def bulk_move_workstations():
    """Move all workstations to the Workstations OU"""
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
        
        # Target OU for workstations
        target_ou = 'OU=Workstations,OU=Sunray Computers,OU=Sunray,DC=sunray,DC=internal'
        
        # Search for all workstations (computers that are not servers)
        computers = search_computers('', status_filter='all', computer_type='workstation', exclude_ous=[], **ad_args)
        
        moved = []
        failed = []
        
        for computer in computers:
            computer_dn = computer.get('dn') or computer.get('distinguishedName')
            if not computer_dn:
                continue
            
            # Check if already in target OU
            if target_ou in computer_dn:
                continue
            
            # Move the computer
            success, message = move_computer_to_ou(computer_dn, target_ou, **ad_args)
            
            if success:
                moved.append(computer.get('name', computer_dn))
                log_user_action('move_computer', computer_dn, 'success', {'new_ou': target_ou, 'bulk': True})
            else:
                failed.append({'name': computer.get('name', computer_dn), 'error': message})
                log_user_action('move_computer', computer_dn, 'failure', {'error': message, 'bulk': True})
        
        return jsonify({
            'success': True,
            'moved_count': len(moved),
            'failed_count': len(failed),
            'moved': moved,
            'failed': failed,
            'message': f'Moved {len(moved)} workstations to {target_ou}. {len(failed)} failed.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main.route('/computer_details/<path:computer_dn>', methods=['GET'])
@login_required
@admin_required
def computer_details(computer_dn):
    """Display detailed information about a computer"""
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
    
    computer = get_computer_details(computer_dn, **ad_args)
    
    if not computer:
        flash('Computer not found.', 'danger')
        return redirect(url_for('main.computer_search'))
    
    return render_template('computer_details.html', computer=computer, branding=get_branding_config())

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
        include_archived = request.args.get('include_archived', '0') == '1'
        
        # Get all users (for accurate stats)
        all_users = search_users(
            query,
            status_filter='all',
            exclude_ous=[],
            include_archive_ou=include_archived,
            **ad_args
        )
        
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
            archive_users_ou = org_ous.get('archive_users_ou', '')
            if 'OU=Disabled Users' in dn or org_ous.get('disabled_users_ou', '') in dn:
                continue  # Always exclude disabled users OU
            if (not include_archived) and ('OU=Archived Users' in dn or archive_users_ou in dn):
                continue
            
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
                archive_users_ou = org_ous.get('archive_users_ou', '')
                if 'OU=Disabled Users' in dn or org_ous.get('disabled_users_ou', '') in dn:
                    continue
                if (not include_archived) and ('OU=Archived Users' in dn or archive_users_ou in dn):
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
                    skip_ous = ['users', 'disabled users', 'service accounts', 'internal tools', 'sunray users', 'sunray', 'racing security', 'vendor logins', 'vendor login']
                    if ou_name.lower() not in skip_ous:
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

def _offboard_exchange_mailbox(email, username):
    """
    Export mailbox to a local archive zip and disable mailbox in Exchange.
    Returns a result dict with status and messages.
    """
    result = {
        'attempted': False,
        'mailbox_found': False,
        'mailbox_exported': False,
        'mailbox_disabled': False,
        'local_archive_path': None,
        'message': ''
    }

    config = get_exchange_config()
    if not config or not config.get('enabled'):
        result['message'] = 'Exchange integration not enabled.'
        return result

    if not email:
        result['message'] = 'No email address on user; Exchange offboarding skipped.'
        return result

    result['attempted'] = True

    try:
        exchange = ExchangeManager(
            exchange_server=config['exchange_server'],
            username=config['username'],
            password=config['password'],
            domain=config['domain']
        )

        mailbox_stats = exchange.get_mailbox_stats([email])
        mailbox_present = bool(mailbox_stats and mailbox_stats.get(email.lower()))
        result['mailbox_found'] = mailbox_present

        if not mailbox_present:
            result['message'] = 'No Exchange mailbox found for this email.'
            return result

        now_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        safe_username = ''.join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in (username or 'user'))
        remote_archive_dir = f"C:\\Temp\\ExchangeArchives\\Terminations\\{safe_username}_{now_str}"

        archive_ok, archive_msg = exchange.archive_mailbox(email, remote_archive_dir, use_local_temp=True)
        if not archive_ok:
            current_app.logger.error(f"Mailbox export request failed for {email}: {archive_msg}")
            # Continue to disable mailbox even if export failed.
            disable_ok, disable_msg = exchange.remove_mailbox(email, permanent=False)
            result['mailbox_disabled'] = disable_ok
            result['message'] = (
                f"Mailbox export failed ({archive_msg}); mailbox disable "
                f"{'succeeded' if disable_ok else f'failed ({disable_msg})'}."
            )
            return result

        export_statuses = exchange.wait_for_exports_complete([email], max_wait_minutes=60, poll_interval_seconds=20)
        export_info = export_statuses.get(email, {})
        if not export_info.get('completed'):
            current_app.logger.warning(f"Mailbox export timeout for {email}: {export_info}")
            disable_ok, disable_msg = exchange.remove_mailbox(email, permanent=False)
            result['mailbox_disabled'] = disable_ok
            result['message'] = (
                f"Mailbox export timed out ({export_info.get('status', 'unknown')}); mailbox disable "
                f"{'succeeded' if disable_ok else f'failed ({disable_msg})'}."
            )
            return result

        zip_filename = f"{safe_username}_{now_str}.zip"
        zip_ok, zip_path_or_error = exchange.zip_pst_files(remote_archive_dir, zip_filename=zip_filename)
        if not zip_ok:
            current_app.logger.error(f"Mailbox zip creation failed for {email}: {zip_path_or_error}")
            disable_ok, disable_msg = exchange.remove_mailbox(email, permanent=False)
            result['mailbox_disabled'] = disable_ok
            result['message'] = (
                f"Mailbox exported but zip creation failed ({zip_path_or_error}); mailbox disable "
                f"{'succeeded' if disable_ok else f'failed ({disable_msg})'}."
            )
            return result

        download_ok, zip_bytes, download_error = exchange.download_zip_file(zip_path_or_error)
        if download_ok and zip_bytes:
            local_export_dir = os.path.join(os.path.dirname(__file__), 'mailbox_exports')
            os.makedirs(local_export_dir, exist_ok=True)
            local_zip_name = f"{safe_username}_{now_str}.zip"
            local_zip_path = os.path.join(local_export_dir, local_zip_name)
            with open(local_zip_path, 'wb') as f:
                f.write(zip_bytes)
            result['local_archive_path'] = local_zip_path
            result['mailbox_exported'] = True
        else:
            current_app.logger.error(f"Mailbox zip download failed for {email}: {download_error}")

        disable_ok, disable_msg = exchange.remove_mailbox(email, permanent=False)
        result['mailbox_disabled'] = disable_ok

        if result['mailbox_exported'] and disable_ok:
            result['message'] = f"Mailbox exported and disabled. Archive saved to {result['local_archive_path']}."
        elif result['mailbox_exported'] and not disable_ok:
            result['message'] = f"Mailbox exported, but disable failed: {disable_msg}"
        elif (not result['mailbox_exported']) and disable_ok:
            result['message'] = "Mailbox disable succeeded, but archive download failed."
        else:
            result['message'] = f"Mailbox archive download and disable both failed: {disable_msg}"

        return result

    except Exception as e:
        current_app.logger.error(f"Exchange offboarding error for {email}: {e}", exc_info=True)
        result['message'] = f"Exchange offboarding error: {str(e)}"
        return result


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
        force_refresh = request.args.get('force_refresh', '0') == '1'
        all_active = request.args.get('all_active', '0') == '1'
        emails_param = request.args.get('emails', '').strip()
        exclude_ous = [ou.strip() for ou in exclude_ous_raw.split(',') if ou.strip()]
        exclude_ous_str = exclude_ous_raw  # Keep original string for storage

        cache_lookup_username = current_user.username
        cache_lookup_query = query
        cache_lookup_status = status_filter
        cache_lookup_exclude = exclude_ous_str
        if all_active:
            cache_lookup_username = '__system__'
            cache_lookup_query = ''
            cache_lookup_status = 'enabled'
            cache_lookup_exclude = '__all_active__'

        # Fast path: return recent cache unless caller explicitly forces refresh.
        cache_entry = db.session.query(MailboxSizeCache).filter_by(
            username=cache_lookup_username,
            query=cache_lookup_query,
            status_filter=cache_lookup_status,
            exclude_ous=cache_lookup_exclude
        ).first()
        if cache_entry and not force_refresh:
            updated_at = cache_entry.updated_at
            if updated_at:
                updated_at = updated_at if updated_at.tzinfo else updated_at.replace(tzinfo=timezone.utc)
                cache_age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds()
                if cache_age_seconds < 30 * 60:
                    try:
                        mailbox_sizes = json.loads(cache_entry.mailbox_sizes or '{}')
                        return jsonify({
                            'success': True,
                            'mailbox_sizes': mailbox_sizes,
                            'cached': True,
                            'updated_at': cache_entry.updated_at.isoformat()
                        })
                    except json.JSONDecodeError:
                        pass
        
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
        
        user_emails = []
        if all_active:
            users = search_users(
                '',
                status_filter='enabled',
                exclude_ous=[],
                include_disabled_ou=True,
                include_archive_ou=True,
                **ad_args
            )
            user_emails = [user.get('mail').lower() if user.get('mail') else None for user in users if user.get('mail')]
            user_emails = [email for email in user_emails if email]
        elif emails_param:
            user_emails = [e.strip().lower() for e in emails_param.split(',') if e.strip() and '@' in e]
        else:
            # Get users with emails based on current page filter.
            users = search_users(query, status_filter=status_filter, exclude_ous=exclude_ous, **ad_args)
            user_emails = [user.get('mail').lower() if user.get('mail') else None for user in users if user.get('mail')]
            user_emails = [email for email in user_emails if email]  # Remove None values
        
        if not user_emails:
            # Store empty result in cache
            cache_entry = db.session.query(MailboxSizeCache).filter_by(
                username=cache_lookup_username,
                query=cache_lookup_query,
                status_filter=cache_lookup_status,
                exclude_ous=cache_lookup_exclude
            ).first()
            
            if cache_entry:
                cache_entry.mailbox_sizes = json.dumps({})
                cache_entry.updated_at = datetime.now(timezone.utc)
            else:
                cache_entry = MailboxSizeCache(
                    username=cache_lookup_username,
                    query=cache_lookup_query,
                    status_filter=cache_lookup_status,
                    exclude_ous=cache_lookup_exclude,
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
            username=cache_lookup_username,
            query=cache_lookup_query,
            status_filter=cache_lookup_status,
            exclude_ous=cache_lookup_exclude
        ).first()
        
        if cache_entry:
            # Update existing entry
            cache_entry.mailbox_sizes = json.dumps(mailbox_sizes)
            cache_entry.updated_at = datetime.now(timezone.utc)
        else:
            # Create new entry
            cache_entry = MailboxSizeCache(
                username=cache_lookup_username,
                query=cache_lookup_query,
                status_filter=cache_lookup_status,
                exclude_ous=cache_lookup_exclude,
                mailbox_sizes=json.dumps(mailbox_sizes)
            )
            db.session.add(cache_entry)
        
        # Also write current user's page cache so immediate UI reload is fast.
        if all_active and current_user.username != '__system__':
            user_cache = db.session.query(MailboxSizeCache).filter_by(
                username=current_user.username,
                query=query,
                status_filter=status_filter,
                exclude_ous=exclude_ous_str
            ).first()
            if user_cache:
                user_cache.mailbox_sizes = json.dumps(mailbox_sizes)
                user_cache.updated_at = datetime.now(timezone.utc)
            else:
                user_cache = MailboxSizeCache(
                    username=current_user.username,
                    query=query,
                    status_filter=status_filter,
                    exclude_ous=exclude_ous_str,
                    mailbox_sizes=json.dumps(mailbox_sizes)
                )
                db.session.add(user_cache)

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
        all_active = request.args.get('all_active', '0') == '1'
        exclude_ous_str = exclude_ous_raw  # Keep original string for lookup
        
        # Look up cached data
        if all_active:
            cache_entry = db.session.query(MailboxSizeCache).filter_by(
                username='__system__',
                query='',
                status_filter='enabled',
                exclude_ous='__all_active__'
            ).first()
        else:
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
            if ok:
                force_ok, force_msg = ad_force_password_change(user_dn, **ad_args)
                if force_ok:
                    msg = f"{msg} User will be required to change password at next sign-in."
                else:
                    msg = f"{msg} Password reset succeeded, but could not enforce next-login change: {force_msg}"
            flash(msg, 'success' if ok else 'danger')
        elif action == 'unlock':
            ok, msg = ad_unlock_user(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'enable':
            ok, msg = ad_enable_user(user_dn, **ad_args)
            flash(msg, 'success' if ok else 'danger')
        elif action == 'disable':
            result = _disable_user_with_lifecycle(user_dn, ad_args, config)
            ok = result.get('success', False)
            msg = result.get('message', 'Disable failed.')
            if ok and result.get('partial'):
                flash(msg, 'warning')
            else:
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
    
    # Fetch manager information from multiple sources
    manager_display_name = None
    manager_username = None
    manager_dn = None
    assigned_manager = None  # Manager from DepartmentManager/UserDirectReport system
    direct_reports = []  # Users who report to this user if they're a manager
    
    # First, check AD manager attribute
    ad_manager_dn = user.get('manager', [None])[0] if user.get('manager') else None
    if ad_manager_dn:
        from .ad import ad_connection
        import ldap3
        with ad_connection(**ad_args) as conn:
            if conn.search(ad_manager_dn, '(objectClass=user)', search_scope=ldap3.BASE, attributes=['displayName', 'sAMAccountName']):
                entry = conn.entries[0]
                if hasattr(entry, 'displayName') and entry.displayName:
                    manager_display_name = entry.displayName.value
                if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName:
                    manager_username = entry.sAMAccountName.value
                manager_dn = ad_manager_dn
    
    # Check for assigned manager from DepartmentManager/UserDirectReport system
    user_username = user.get('sAMAccountName', [None])[0] if user.get('sAMAccountName') else None
    if user_username:
        # Check if this user has a direct report relationship (has a manager assigned)
        direct_report = UserDirectReport.query.filter_by(employee_username=user_username).first()
        if direct_report:
            assigned_manager = {
                'username': direct_report.manager_username,
                'dn': direct_report.manager_dn,
                'display_name': direct_report.manager_display_name
            }
            # Use assigned manager if AD manager is not set, or show both
            if not manager_display_name:
                manager_display_name = direct_report.manager_display_name
                manager_username = direct_report.manager_username
                manager_dn = direct_report.manager_dn
        
        # Check if this user is a manager (has direct reports)
        direct_reports_list = UserDirectReport.query.filter_by(manager_username=user_username).all()
        if direct_reports_list:
            direct_reports = [{
                'username': dr.employee_username,
                'dn': dr.employee_dn,
                'display_name': dr.employee_display_name
            } for dr in direct_reports_list]

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
    lifecycle_info = None
    disabled_days = None
    if user_username:
        lifecycle_info = DisabledUserLifecycle.query.filter_by(username=user_username).first()
        if lifecycle_info and lifecycle_info.disabled_at:
            disabled_days = (datetime.now(timezone.utc) - lifecycle_info.disabled_at).days

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
        manager_username=manager_username,
        manager_dn=manager_dn,
        assigned_manager=assigned_manager,
        direct_reports=direct_reports,
        password_info=password_info,
        password_expired=password_expired,
        password_expiring_soon=password_expiring_soon,
        password_never_expires=password_never_expires,
        days_until_reset=days_until_reset,
        policy=policy,
        lifecycle_info=lifecycle_info,
        disabled_days=disabled_days
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
                    skip_names = ['sunray users', 'users', 'disabled users', 'disabled user',
                                 'archived users', 'archived user', 'archive users',
                                 'service accounts', 
                                 'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                                 'admins', 'managers', 'management', 'western gaming', 'racing security',
                                 'vendor logins', 'vendor login', 'vendors']
                    if ou_name_from_dn.lower() not in skip_names:
                        department_name = ou_name_from_dn
                        break
            
            # Use the extracted name or the OU name attribute
            if department_name:
                final_name = department_name
            elif ou_name:
                # Check if the OU name itself should be skipped
                skip_names = ['sunray users', 'users', 'disabled users', 'disabled user',
                             'archived users', 'archived user', 'archive users',
                             'service accounts', 
                             'internal tools', 'sunray', 'owners', 'owner', 'administrators',
                             'admins', 'managers', 'management', 'western gaming', 'racing security',
                             'vendor logins', 'vendor login', 'vendors']
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
    
    # Get departments (top-level + sub-OU entries)
    org_ous = get_organization_ous()
    primary_users_ou = org_ous.get('primary_users_ou', 'OU=Sunray Users,OU=Sunray,DC=sunray,DC=internal')
    ous = list_ous(**ad_args)
    departments = _build_department_entries_from_ous(ous, primary_users_ou)
    department_lookup = {d['key']: d for d in departments}
    top_departments = [d for d in departments if not d.get('is_sub')]

    excluded_username_tokens = {'services', 'service', 'vendor', 'vendors'}
    excluded_dn_tokens = (
        'ou=vendor',
        'ou=vendors',
        'ou=vendor logins',
        'ou=service accounts',
        'ou=internal tools'
    )

    def _is_report_excluded(report):
        employee_dn_l = (report.employee_dn or '').strip().lower()
        employee_username_l = (report.employee_username or '').strip().lower()
        employee_display_l = (report.employee_display_name or '').strip().lower()
        if primary_users_ou and primary_users_ou.strip().lower() not in employee_dn_l:
            return True
        if any(token in employee_dn_l for token in excluded_dn_tokens):
            return True
        if employee_username_l in excluded_username_tokens or employee_display_l in excluded_username_tokens:
            return True
        return False
    
    # Get existing department managers
    dept_managers = {}
    for dept_mgr in DepartmentManager.query.all():
        dept_managers[dept_mgr.department] = dept_mgr
    
    # Get all direct reports first (needed for outside managers)
    direct_reports = UserDirectReport.query.all()
    # Safety cleanup: remove legacy self-report rows.
    self_reports = []
    for report in direct_reports:
        same_username = bool(
            report.manager_username and report.employee_username and
            report.manager_username.strip().lower() == report.employee_username.strip().lower()
        )
        same_dn = bool(
            report.manager_dn and report.employee_dn and
            report.manager_dn.strip().lower() == report.employee_dn.strip().lower()
        )
        if same_username or same_dn:
            self_reports.append(report)
    if self_reports:
        for report in self_reports:
            db.session.delete(report)
        db.session.commit()
        current_app.logger.info(f"Removed {len(self_reports)} self-report direct-report rows")
        direct_reports = [r for r in direct_reports if r not in self_reports]

    # Normalize manager/supervisor usernames to canonical AD usernames
    # to avoid duplicate cards caused by case or alias variants.
    normalized_rows = 0
    for report in direct_reports:
        if report.manager_username and not report.is_outside_manager:
            mgr_identity = _resolve_ad_user_identity(report.manager_username, ad_args)
            if mgr_identity and mgr_identity.get('username') and report.manager_username != mgr_identity['username']:
                report.manager_username = mgr_identity['username']
                normalized_rows += 1
            if mgr_identity and mgr_identity.get('dn') and report.manager_dn != mgr_identity['dn']:
                report.manager_dn = mgr_identity['dn']
                normalized_rows += 1

        if report.supervisor_username and not report.is_outside_supervisor:
            sup_identity = _resolve_ad_user_identity(report.supervisor_username, ad_args)
            if sup_identity and sup_identity.get('username') and report.supervisor_username != sup_identity['username']:
                report.supervisor_username = sup_identity['username']
                normalized_rows += 1
            if sup_identity and sup_identity.get('dn') and report.supervisor_dn != sup_identity['dn']:
                report.supervisor_dn = sup_identity['dn']
                normalized_rows += 1

    if normalized_rows:
        db.session.commit()
        direct_reports = UserDirectReport.query.all()

    # Cleanup out-of-scope rows: only users under primary users OU should count,
    # and vendor/services identities should not appear in direct reports.
    excluded_reports = [r for r in direct_reports if _is_report_excluded(r)]
    if excluded_reports:
        for report in excluded_reports:
            db.session.delete(report)
        db.session.commit()
        direct_reports = [r for r in direct_reports if r not in excluded_reports]

    # Normalize legacy/bad department values that were stored as OU DNs.
    dept_normalized = 0
    primary_users_ou_l = (primary_users_ou or '').strip().lower()
    for report in direct_reports:
        dept_val = (report.department or '').strip()
        if not dept_val:
            continue
        if 'ou=' not in dept_val.lower():
            continue

        normalized_dept = None
        employee_dn_l = (report.employee_dn or '').strip().lower()
        if primary_users_ou_l and primary_users_ou_l in employee_dn_l:
            suffix = ',' + primary_users_ou_l
            idx = employee_dn_l.rfind(suffix)
            if idx > 0:
                relative = (report.employee_dn or '')[:idx]
                ou_parts = [p.strip() for p in relative.split(',') if p.strip().lower().startswith('ou=')]
                if ou_parts:
                    # closest OU to user first; we want top-level OU under primary users OU
                    top_ou = ou_parts[-1][3:] if len(ou_parts[-1]) > 3 else ''
                    if top_ou:
                        normalized_dept = top_ou

        # If still not resolved and this is a management chain row, use Management.
        if not normalized_dept and not report.is_same_department:
            normalized_dept = 'Management'

        if normalized_dept and report.department != normalized_dept:
            report.department = normalized_dept
            dept_normalized += 1

    if dept_normalized:
        db.session.commit()
        direct_reports = UserDirectReport.query.all()
    
    # Get all users from AD for dropdowns
    all_ad_users = search_users('', status_filter='all', **ad_args)
    
    # Add outside managers to the list
    outside_managers_list = []
    for report in direct_reports:
        if report.is_outside_manager and report.manager_username:
            # Check if already added
            if not any(u.get('sAMAccountName') == report.manager_username for u in outside_managers_list):
                outside_managers_list.append({
                    'sAMAccountName': report.manager_username,
                    'username': report.manager_username,
                    'displayName': report.manager_display_name or report.manager_username,
                    'cn': report.manager_display_name or report.manager_username,
                    'title': '',
                    'is_outside': True
                })
    
    # Add Board of Directors if it exists or create it
    board_exists = any('board' in (r.manager_display_name or r.manager_username or '').lower() or 'directors' in (r.manager_display_name or r.manager_username or '').lower() for r in direct_reports)
    if not board_exists:
        outside_managers_list.append({
            'sAMAccountName': 'Board of Directors',
            'username': 'Board of Directors',
            'displayName': 'Board of Directors',
            'cn': 'Board of Directors',
            'title': '',
            'is_outside': True
        })
    
    # Combine AD users with outside managers
    all_ad_users.extend(outside_managers_list)
    
    # Sort users by display name for dropdown
    all_ad_users.sort(key=lambda u: (u.get('displayName') or u.get('cn') or u.get('sAMAccountName') or '').lower())
    
    manager_policy = _load_manager_policy()
    manager_identity_cache = {}
    manager_aliases = manager_policy.get('manager_aliases') if isinstance(manager_policy.get('manager_aliases'), dict) else {}

    def _resolve_manager_identity_cached(candidate):
        key = (candidate or '').strip()
        if not key:
            return None
        cache_key = key.lower()
        if cache_key not in manager_identity_cache:
            identity = _resolve_ad_user_identity(key, ad_args)
            if not identity and cache_key in manager_aliases:
                identity = _resolve_ad_user_identity(manager_aliases[cache_key], ad_args)
            manager_identity_cache[cache_key] = identity
        return manager_identity_cache[cache_key]

    def _canonical_manager_key(username, is_outside=False):
        key = (username or '').strip()
        if not key:
            return ''
        if is_outside or key.lower() == 'board of directors':
            return key
        alias_username = manager_aliases.get(key.lower())
        if alias_username:
            return alias_username
        identity = _resolve_manager_identity_cached(key)
        return identity.get('username') if identity and identity.get('username') else key

    def _append_unique_report(grouped_reports, manager_key, report_obj):
        if not manager_key:
            return
        bucket = grouped_reports.setdefault(manager_key, [])
        if not any(existing.id == report_obj.id for existing in bucket):
            bucket.append(report_obj)

    def _build_reports_by_manager(report_rows):
        grouped = {}
        display_names = {}
        for report in report_rows:
            manager_key = _canonical_manager_key(report.manager_username, report.is_outside_manager)
            if manager_key and manager_key not in display_names:
                if report.is_outside_manager and report.manager_display_name:
                    display_names[manager_key] = report.manager_display_name
                else:
                    identity = _resolve_manager_identity_cached(manager_key)
                    display_names[manager_key] = (
                        identity.get('display') if identity and identity.get('display')
                        else (report.manager_display_name or manager_key)
                    )
            _append_unique_report(grouped, manager_key, report)

            # Also surface indirect reports under supervisor so they appear under both leaders.
            if report.is_indirect_report and report.supervisor_username:
                sup_key = _canonical_manager_key(report.supervisor_username, report.is_outside_supervisor)
                if sup_key and sup_key not in display_names:
                    if report.is_outside_supervisor and report.supervisor_display_name:
                        display_names[sup_key] = report.supervisor_display_name
                    else:
                        sup_identity = _resolve_manager_identity_cached(sup_key)
                        display_names[sup_key] = (
                            sup_identity.get('display') if sup_identity and sup_identity.get('display')
                            else (report.supervisor_display_name or sup_key)
                        )
                _append_unique_report(grouped, sup_key, report)
        return grouped, display_names

    # Group direct reports by manager and fetch manager display names from AD.
    reports_by_manager, manager_display_names = _build_reports_by_manager(direct_reports)

    # Get all managers (people who have direct reports, are department managers, or have manager/director titles)
    all_managers = set()
    manager_usernames_from_reports = set()
    for report in direct_reports:
        manager_key = _canonical_manager_key(report.manager_username, report.is_outside_manager)
        if manager_key:
            manager_usernames_from_reports.add(manager_key)
            all_managers.add(manager_key)

    # Also include employees who are managers (have their own reports)
    for report in direct_reports:
        employee_key = _canonical_manager_key(report.employee_username, False)
        if employee_key and employee_key in manager_usernames_from_reports:
            all_managers.add(employee_key)

    # Add department managers
    for dept_mgr in dept_managers.values():
        manager_key = _canonical_manager_key(dept_mgr.manager_username, False)
        if manager_key:
            all_managers.add(manager_key)

    # Add Board of Directors
    all_managers.add('Board of Directors')

    # Optionally force specific leaders into management list via local policy.
    forced_manager_candidates = manager_policy.get('forced_manager_candidates') or []
    for candidate in forced_manager_candidates:
        identity = _resolve_manager_identity_cached(candidate)
        if identity and identity.get('username'):
            all_managers.add(identity['username'])
    
    # Identify managers by title patterns in AD
    manager_title_keywords = ['manager', 'director', 'supervisor', 'lead', 'chief', 'vp', 'vice president', 'president', 'ceo', 'coo', 'cfo', 'cto', 'head', 'executive']
    for user in all_ad_users:
        if user.get('is_outside'):
            continue  # Skip outside managers, already handled
        username = user.get('sAMAccountName') or user.get('username')
        title = (user.get('title') or '').lower()
        if any(keyword in title for keyword in manager_title_keywords):
            manager_key = _canonical_manager_key(username, False)
            if manager_key:
                all_managers.add(manager_key)

    # Auto-reconcile department direct reports on page load so list stays current.
    if request.method == 'GET':
        sync_result = _auto_sync_department_direct_reports(
            ad_args,
            top_departments,
            dept_managers,
            primary_users_ou=primary_users_ou
        )
        if sync_result.get('default_missing'):
            flash('Default manager could not be resolved in AD. Department auto-sync used only explicitly mapped department managers.', 'warning')
        else:
            if sync_result.get('assigned') or sync_result.get('updated') or sync_result.get('removed'):
                flash(
                    f"Direct report auto-sync: {sync_result.get('assigned', 0)} added, "
                    f"{sync_result.get('updated', 0)} updated, {sync_result.get('removed', 0)} removed.",
                    'info'
                )
                # Refresh from DB so rendered tables reflect current state.
                direct_reports = UserDirectReport.query.all()
                reports_by_manager, manager_display_names = _build_reports_by_manager(direct_reports)
        chain_result = _auto_sync_manager_chain(ad_args, all_managers)
        if chain_result.get('missing') == 'default_manager':
            flash('Manager chain auto-sync skipped: default manager from policy was not found in AD.', 'warning')
        elif chain_result.get('missing') == 'top_manager':
            flash('Manager chain auto-sync skipped: top manager from policy was not found in AD.', 'warning')
        elif chain_result.get('assigned') or chain_result.get('updated'):
            flash(
                f"Manager chain sync: {chain_result.get('assigned', 0)} added, "
                f"{chain_result.get('updated', 0)} updated, {chain_result.get('skipped', 0)} skipped exceptions.",
                'info'
            )
            # Refresh after chain sync
            direct_reports = UserDirectReport.query.all()
            reports_by_manager, manager_display_names = _build_reports_by_manager(direct_reports)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'set_department_manager':
            department = request.form.get('department')
            manager_username = request.form.get('manager_username', '').strip()
            manager_display_name = request.form.get('dept_manager_display_name', '').strip()
            is_outside_manager = request.form.get('is_dept_outside_manager') == 'true'
            
            if not department:
                flash('Department is required.', 'danger')
                return redirect(url_for('main.manage_managers'))

            selected_dept = department_lookup.get(department, {'name': department, 'key': department})
            department_label = selected_dept.get('name', department)

            # Allow explicit "None" (unassigned manager) for department/sub-OU.
            if not manager_username:
                existing = DepartmentManager.query.filter_by(department=department).first()
                if existing:
                    db.session.delete(existing)
                    db.session.commit()
                    flash(f'Manager cleared for {department_label}.', 'success')
                else:
                    flash(f'{department_label} already has no manager assigned.', 'info')
                return redirect(url_for('main.manage_managers'))
            
            # Check if this is an outside manager (from existing records or manually entered)
            # First check if it's in our outside managers list
            is_known_outside = False
            for report in direct_reports:
                if report.is_outside_manager and report.manager_username == manager_username:
                    is_known_outside = True
                    manager_display_name = report.manager_display_name or manager_username
                    break
            
            # Also check if it's Board of Directors
            if 'board' in manager_username.lower() or 'directors' in manager_username.lower():
                is_known_outside = True
                manager_display_name = manager_display_name or 'Board of Directors'
            
            # Handle outside manager
            if is_outside_manager or is_known_outside:
                if not manager_display_name:
                    manager_display_name = manager_username
                manager_dn = None
                manager_display = manager_display_name
            else:
                # Get manager details from AD
                users = search_users(manager_username, **ad_args)
                if not users:
                    # Not found in AD - treat as outside manager
                    is_outside_manager = True
                    manager_display_name = manager_display_name or manager_username
                    manager_dn = None
                    manager_display = manager_display_name
                else:
                    manager = users[0]
                    manager_dn = manager.get('distinguishedName') or manager.get('dn')
                    manager_display = manager.get('displayName') or manager.get('cn') or manager_username
            
            # Update or create department manager
            old_manager_dn = None
            dept_mgr = DepartmentManager.query.filter_by(department=department).first()
            if dept_mgr:
                old_manager_dn = dept_mgr.manager_dn
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
            
            # Update AD manager attribute for all existing direct reports in this department
            # (only for non-outside managers, and if manager changed)
            if not is_outside_manager and manager_dn and old_manager_dn and old_manager_dn != manager_dn:
                # Manager changed - update all direct reports in this department
                dept_direct_reports = UserDirectReport.query.filter_by(department=department).all()
                updated_count = 0
                for report in dept_direct_reports:
                    # Prevent manager self-assignment in backfill updates.
                    if (
                        report.employee_username and manager_username and
                        report.employee_username.strip().lower() == manager_username.strip().lower()
                    ) or (
                        report.employee_dn and manager_dn and
                        report.employee_dn.strip().lower() == manager_dn.strip().lower()
                    ):
                        continue
                    try:
                        ok, msg = set_user_manager(report.employee_dn, manager_dn, **ad_args)
                        if ok:
                            report.manager_dn = manager_dn
                            report.manager_username = manager_username
                            updated_count += 1
                    except Exception as e:
                        current_app.logger.warning(f"Failed to update AD manager for {report.employee_username}: {e}")
                
                if updated_count > 0:
                    db.session.commit()
                    flash(f'Manager for {department_label} set to {manager_display}. Updated AD manager attribute for {updated_count} existing users.', 'success')
                else:
                    flash(f'Manager for {department_label} set to {manager_display}.', 'success')
            elif is_outside_manager:
                flash(f'Manager for {department_label} set to {manager_display} (Outside Manager).', 'success')
            else:
                flash(f'Manager for {department_label} set to {manager_display}.', 'success')
            
            return redirect(url_for('main.manage_managers'))
        
        elif action == 'assign_direct_report':
            manager_username = request.form.get('manager_username', '').strip()
            employee_username = request.form.get('employee_username')
            manager_display_name = request.form.get('manager_display_name', '').strip()
            is_outside_manager = request.form.get('is_outside_manager') == 'true'
            
            if not employee_username:
                flash('Employee is required.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # For outside managers, display name is required
            if is_outside_manager and not manager_display_name:
                flash('Manager display name is required for outside managers.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # For regular managers, username is required
            if not is_outside_manager and not manager_username:
                flash('Manager username is required.', 'danger')
                return redirect(url_for('main.manage_managers'))

            # Never allow self-report assignment.
            if manager_username and employee_username and manager_username.strip().lower() == employee_username.strip().lower():
                flash('A manager cannot be assigned as their own direct report.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get employee details from AD
            employees = search_users(employee_username, **ad_args)
            if not employees:
                flash(f'Employee user "{employee_username}" not found.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            employee = employees[0]
            employee_dn = employee.get('distinguishedName') or employee.get('dn')
            employee_display = employee.get('displayName') or employee.get('cn') or employee_username
            employee_dept = employee.get('department') or ''
            
            # Handle outside manager
            if is_outside_manager:
                # Outside manager - not in AD
                if not manager_username:
                    manager_username = manager_display_name
                manager_dn = None
                manager_display = manager_display_name
                manager_dept = ''  # Outside managers don't have departments
                is_same_dept = False
            else:
                # Regular manager - get from AD
                managers = search_users(manager_username, **ad_args)
                if not managers:
                    flash(f'Manager user "{manager_username}" not found.', 'danger')
                    return redirect(url_for('main.manage_managers'))
                
                manager = managers[0]
                manager_dn = manager.get('distinguishedName') or manager.get('dn')
                manager_display = manager.get('displayName') or manager.get('cn') or manager_username
                manager_dept = manager.get('department') or ''
                is_same_dept = (employee_dept.lower() == manager_dept.lower())
                
                # Prevent managers from assigning themselves as direct reports
                if manager_username.lower() == employee_username.lower():
                    flash('A manager cannot be assigned as their own direct report.', 'danger')
                    return redirect(url_for('main.manage_managers'))
                
                # Double-check: prevent self-assignment using DN comparison
                if manager_dn and employee_dn and manager_dn.lower() == employee_dn.lower():
                    flash('A manager cannot be assigned as their own direct report.', 'danger')
                    return redirect(url_for('main.manage_managers'))
            
            # Check if this is a dotted-line relationship
            is_dotted_line = request.form.get('is_dotted_line') == 'true'
            
            # Check if this is an indirect report (through a supervisor)
            supervisor_username = request.form.get('supervisor_username', '').strip()
            supervisor_display_name = request.form.get('supervisor_display_name', '').strip()
            is_outside_supervisor = request.form.get('is_outside_supervisor') == 'true'
            is_indirect = bool(supervisor_username or supervisor_display_name)
            supervisor_dn = None
            
            if is_outside_supervisor:
                # Outside supervisor - not in AD, use display name
                if supervisor_display_name:
                    # Use display name as identifier if no username provided
                    if not supervisor_username:
                        supervisor_username = supervisor_display_name
                else:
                    # Fallback to username if display name not provided
                    supervisor_display_name = supervisor_username
            elif supervisor_username:
                # Regular supervisor - try to find in AD
                supervisors = search_users(supervisor_username, **ad_args)
                if supervisors:
                    supervisor_dn = supervisors[0].get('distinguishedName') or supervisors[0].get('dn')
                    supervisor_display_name = supervisors[0].get('displayName') or supervisors[0].get('cn') or supervisor_username
                else:
                    # Supervisor not found in AD - treat as outside
                    is_outside_supervisor = True
                    supervisor_display_name = supervisor_username
            
            # Update or create direct report
            old_manager_dn = None
            # For dotted-line, allow multiple relationships; for primary, only one
            if is_dotted_line:
                direct_report = UserDirectReport.query.filter_by(
                    employee_username=employee_username,
                    is_dotted_line=True
                ).first()
            else:
                direct_report = UserDirectReport.query.filter_by(
                    employee_username=employee_username,
                    is_dotted_line=False
                ).first()
            
            if direct_report:
                old_manager_dn = direct_report.manager_dn
                direct_report.manager_username = manager_username
                direct_report.manager_dn = manager_dn
                direct_report.manager_display_name = manager_display if is_outside_manager else None
                direct_report.is_outside_manager = is_outside_manager
                direct_report.employee_dn = employee_dn
                direct_report.employee_display_name = employee_display
                direct_report.department = employee_dept
                direct_report.is_same_department = is_same_dept
                direct_report.is_dotted_line = is_dotted_line
                direct_report.is_indirect_report = is_indirect
                direct_report.supervisor_username = supervisor_username if is_indirect else None
                direct_report.supervisor_dn = supervisor_dn if is_indirect else None
                direct_report.supervisor_display_name = supervisor_display_name if is_indirect else None
                direct_report.is_outside_supervisor = is_outside_supervisor if is_indirect else False
                direct_report.updated_at = datetime.now(timezone.utc)
            else:
                direct_report = UserDirectReport(
                    manager_username=manager_username,
                    manager_dn=manager_dn,
                    manager_display_name=manager_display if is_outside_manager else None,
                    is_outside_manager=is_outside_manager,
                    employee_username=employee_username,
                    employee_dn=employee_dn,
                    employee_display_name=employee_display,
                    department=employee_dept,
                    is_same_department=is_same_dept,
                    is_dotted_line=is_dotted_line,
                    is_indirect_report=is_indirect,
                    supervisor_username=supervisor_username if is_indirect else None,
                    supervisor_dn=supervisor_dn if is_indirect else None,
                    supervisor_display_name=supervisor_display_name if is_indirect else None,
                    is_outside_supervisor=is_outside_supervisor if is_indirect else False
                )
                db.session.add(direct_report)
            
            # Update AD manager attribute (only for non-outside managers)
            if not is_outside_manager and manager_dn:
                try:
                    ok, msg = set_user_manager(employee_dn, manager_dn, **ad_args)
                    if not ok:
                        current_app.logger.warning(f"Failed to update AD manager for {employee_username}: {msg}")
                    flash(f'Direct report assigned: {employee_display} -> {manager_display}. AD manager attribute updated.', 'success')
                except Exception as e:
                    current_app.logger.error(f"Exception updating AD manager for {employee_username}: {e}")
                    flash(f'Direct report assigned: {employee_display} -> {manager_display}. Warning: Could not update AD manager attribute.', 'warning')
            else:
                flash(f'Direct report assigned: {employee_display} -> {manager_display} (Outside Manager).', 'success')
            
            db.session.commit()
            return redirect(url_for('main.manage_managers'))
        
        elif action == 'bulk_assign_department':
            department = request.form.get('department')
            fallback_to_department_manager = request.form.get('fallback_to_department_manager', '1') == '1'
            
            if not department:
                flash('Department is required.', 'danger')
                return redirect(url_for('main.manage_managers'))
            
            # Get department manager
            dept_mgr = DepartmentManager.query.filter_by(department=department).first()
            if not dept_mgr:
                fallback_mgr = _resolve_default_manager(ad_args)
                if not fallback_mgr:
                    flash(f'No manager assigned for {department}, and no default manager from policy could be resolved.', 'warning')
                    return redirect(url_for('main.manage_managers'))
                class _FallbackMgr:
                    pass
                dept_mgr = _FallbackMgr()
                dept_mgr.manager_username = fallback_mgr['username']
                dept_mgr.manager_dn = fallback_mgr['dn']
                dept_mgr.manager_display_name = fallback_mgr['display']
            
            # Find department OU
            dept_ou = None
            for dept in top_departments:
                if dept['key'] == department:
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
            coordinator_count = 0
            
            for user in dept_users:
                user_dn = user.get('distinguishedName') or user.get('dn')
                username = user.get('sAMAccountName') or user.get('username')
                display_name = user.get('displayName') or user.get('cn') or username
                is_indirect = False
                supervisor_username = None
                supervisor_dn = None
                supervisor_display_name = None
                is_outside_supervisor = False

                # If a sub-OU coordinator exists, keep overall manager but set coordinator as supervisor.
                sub_label = _extract_sub_department_label(user_dn, dept_ou)
                if sub_label:
                    sub_key = f"{department}::{sub_label}"
                    coordinator = DepartmentManager.query.filter_by(department=sub_key).first()
                    if coordinator and coordinator.manager_username:
                        is_indirect = True
                        supervisor_username = coordinator.manager_username
                        supervisor_dn = coordinator.manager_dn
                        supervisor_display_name = coordinator.manager_display_name
                        is_outside_supervisor = not bool(coordinator.manager_dn)
                        coordinator_count += 1
                    elif not fallback_to_department_manager:
                        skipped_count += 1
                        continue
                
                # Prevent managers from assigning themselves as direct reports
                if username.lower() == dept_mgr.manager_username.lower():
                    skipped_count += 1
                    continue
                
                # Double-check using DN comparison
                if user_dn and manager_dn and user_dn.lower() == manager_dn.lower():
                    skipped_count += 1
                    continue
                
                # Check if this user is a manager (has direct reports or is a dept manager)
                is_manager = username in all_managers
                
                # Skip managers - they should be assigned manually via cross-department assignment
                if is_manager:
                    skipped_count += 1
                    continue
                
                # For non-managers: check if already assigned, if so update (manager replacement scenario)
                existing = UserDirectReport.query.filter_by(employee_username=username, is_dotted_line=False).first()
                if existing:
                    # Manager replacement - update the assignment
                    existing.manager_username = dept_mgr.manager_username
                    existing.manager_dn = manager_dn
                    existing.department = department
                    existing.is_same_department = True
                    existing.is_indirect_report = is_indirect
                    existing.supervisor_username = supervisor_username if is_indirect else None
                    existing.supervisor_dn = supervisor_dn if is_indirect else None
                    existing.supervisor_display_name = supervisor_display_name if is_indirect else None
                    existing.is_outside_supervisor = is_outside_supervisor if is_indirect else False
                    existing.updated_at = datetime.now(timezone.utc)
                    # Update AD manager attribute
                    set_user_manager(user_dn, manager_dn, **ad_args)
                    assigned_count += 1
                    continue
                
                # Create direct report record for non-manager
                direct_report = UserDirectReport(
                    manager_username=dept_mgr.manager_username,
                    manager_dn=manager_dn,
                    employee_username=username,
                    employee_dn=user_dn,
                    employee_display_name=display_name,
                    department=department,
                    is_same_department=True,
                    is_indirect_report=is_indirect,
                    supervisor_username=supervisor_username if is_indirect else None,
                    supervisor_dn=supervisor_dn if is_indirect else None,
                    supervisor_display_name=supervisor_display_name if is_indirect else None,
                    is_outside_supervisor=is_outside_supervisor if is_indirect else False
                )
                db.session.add(direct_report)
                
                # Update AD manager attribute
                set_user_manager(user_dn, manager_dn, **ad_args)
                assigned_count += 1
            
            db.session.commit()
            flash(
                f'Bulk assignment complete: {assigned_count} non-managers assigned, '
                f'{coordinator_count} routed via sub-OU coordinators, '
                f'{skipped_count} skipped.',
                'success'
            )
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
                         top_departments=top_departments,
                         dept_managers=dept_managers,
                         reports_by_manager=reports_by_manager,
                         manager_display_names=manager_display_names,
                         all_ad_users=all_ad_users,
                         all_managers=all_managers)

@main.route('/admin/org-chart')
@login_required
@admin_required
def org_chart():
    """Display organizational chart visualization"""
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
    
    # Get all manager relationships
    all_reports = UserDirectReport.query.filter_by(is_dotted_line=False).all()  # Only primary relationships for main chart
    dotted_line_reports = UserDirectReport.query.filter_by(is_dotted_line=True).all()
    
    # Collect all unique usernames (both managers and employees)
    all_usernames = set()
    outside_managers = {}  # Track outside managers separately
    for report in all_reports:
        all_usernames.add(report.employee_username)
        if report.is_outside_manager:
            # Outside manager - store separately
            outside_managers[report.manager_username] = {
                'username': report.manager_username,
                'display_name': report.manager_display_name or report.manager_username,
                'dn': None
            }
        else:
            all_usernames.add(report.manager_username)
        if report.supervisor_username:
            all_usernames.add(report.supervisor_username)
    
    # Also include department managers
    dept_managers = DepartmentManager.query.all()
    for dept_mgr in dept_managers:
        all_usernames.add(dept_mgr.manager_username)
    
    # Build org chart data structure - initialize all nodes
    org_data = {}
    root_nodes = []  # Initialize root_nodes list
    
    # First, add outside managers to org_data
    for username, manager_info in outside_managers.items():
        org_data[username] = {
            'username': username,
            'name': manager_info['display_name'],
            'display_name': manager_info['display_name'],
            'title': '',
            'department': '',
            'dn': None,
            'children': [],
            'is_root': True,
            'is_indirect': False,
            'supervisor': None,
            'is_outside': True
        }
    
    # Then, add regular users from AD
    for username in all_usernames:
        if username in org_data:
            continue  # Skip if already added as outside manager
        
        # Try to get user details from AD
        users = search_users(username, **ad_args)
        if users:
            user = users[0]
            # Find the report entry for this user to get DN if available
            report_entry = next((r for r in all_reports if r.manager_username == username or r.employee_username == username), None)
            dept_mgr_entry = next((dm for dm in dept_managers if dm.manager_username == username), None)
            
            # Determine DN from available sources
            user_dn = ''
            if report_entry:
                if report_entry.manager_username == username:
                    user_dn = report_entry.manager_dn or ''
                elif report_entry.employee_username == username:
                    user_dn = report_entry.employee_dn
            elif dept_mgr_entry:
                user_dn = dept_mgr_entry.manager_dn
            
            org_data[username] = {
                'username': username,
                'name': user.get('cn') or username,
                'display_name': user.get('displayName') or user.get('cn') or username,
                'title': user.get('title') or '',
                'department': user.get('department') or '',
                'dn': user_dn,
                'children': [],
                'is_root': True,  # Will be updated if they report to someone
                'is_indirect': False,
                'supervisor': None,
                'is_outside': False
            }
    
    # Build parent-child relationships
    for report in all_reports:
        manager_username = report.manager_username
        employee_username = report.employee_username
        
        # Ensure both nodes exist
        if manager_username not in org_data or employee_username not in org_data:
            continue
        
        # Update employee details from report if available
        if report.employee_display_name:
            org_data[employee_username]['display_name'] = report.employee_display_name
        if report.department:
            org_data[employee_username]['department'] = report.department
        if report.is_indirect_report:
            org_data[employee_username]['is_indirect'] = True
            if report.is_outside_supervisor:
                org_data[employee_username]['supervisor'] = report.supervisor_display_name or report.supervisor_username
                org_data[employee_username]['supervisor_outside'] = True
            elif report.supervisor_username:
                org_data[employee_username]['supervisor'] = report.supervisor_username
                org_data[employee_username]['supervisor_outside'] = False
        
        # Add employee as child of manager (avoid duplicates)
        child_usernames = [c['username'] for c in org_data[manager_username]['children']]
        if employee_username not in child_usernames:
            org_data[manager_username]['children'].append(org_data[employee_username])
            org_data[employee_username]['is_root'] = False
    
    # Add dotted-line relationships (secondary reporting relationships)
    dotted_lines = []
    for report in dotted_line_reports:
        dotted_lines.append({
            'from': report.manager_username,
            'to': report.employee_username,
            'type': 'dotted'
        })
    
    # Check for Board of Directors as root node
    board_of_directors = None
    board_username = 'Board of Directors'
    
    # Look for Board of Directors in outside managers or create it
    for username, node in org_data.items():
        if 'board' in username.lower() or 'directors' in username.lower():
            board_of_directors = node
            board_username = username
            break
    
    # If Board of Directors doesn't exist, create it as a root node
    if not board_of_directors:
        board_of_directors = {
            'username': board_username,
            'name': 'Board of Directors',
            'display_name': 'Board of Directors',
            'title': '',
            'department': '',
            'dn': None,
            'children': [],
            'is_root': True,
            'is_indirect': False,
            'supervisor': None,
            'is_outside': True
        }
        org_data[board_username] = board_of_directors
    
    # Find root nodes (those who don't report to anyone in our data)
    # A root node is someone who is a manager but never appears as an employee
    employees_set = {r.employee_username for r in all_reports}
    
    # Check if anyone explicitly reports to Board of Directors
    board_reports = [r for r in all_reports if 'board' in (r.manager_display_name or r.manager_username or '').lower() or 'directors' in (r.manager_display_name or r.manager_username or '').lower()]
    
    # Only show Board if there are explicit reports to it, otherwise find actual root nodes
    if board_reports:
        # Board has explicit reports - use it as root
        root_nodes = [board_of_directors]
    else:
        # No one explicitly reports to Board - find actual root nodes (those who don't report to anyone)
        root_nodes = []
        for username, node in org_data.items():
            if username == board_username:
                continue  # Skip Board itself
            # If this person is not an employee of anyone, they're a root
            if username not in employees_set and node['children']:
                root_nodes.append(node)
            elif username not in employees_set and not node['children']:
                # Even if they have no children, if they're not an employee, they might be a root
                # Check if they're a department manager
                if any(dm.manager_username == username for dm in dept_managers):
                    root_nodes.append(node)
        
        # If still no root nodes, use all department managers
        if not root_nodes:
            for dept_mgr in dept_managers:
                if dept_mgr.manager_username in org_data:
                    org_data[dept_mgr.manager_username]['is_root'] = True
                    if org_data[dept_mgr.manager_username] not in root_nodes:
                        root_nodes.append(org_data[dept_mgr.manager_username])
        
        # If we still have no roots but have data, find all top-level managers
        if not root_nodes and org_data:
            for username, node in org_data.items():
                if node['children'] and username not in employees_set and username != board_username:
                    root_nodes.append(node)
        
        # If still no roots, just show all nodes as roots (flat structure)
        if not root_nodes:
            root_nodes = [node for username, node in org_data.items() if username != board_username]
    
    return render_template('org_chart.html',
                         org_data=org_data,
                         root_nodes=root_nodes,
                         dotted_lines=dotted_lines)

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
    portal_url = request.form.get('portal_url', '').strip()
    
    if not domain_controller:
        flash('Domain Controller is required', 'danger')
        return redirect(url_for('main.gpo_deployment'))
    if not portal_url.startswith('https://'):
        flash('Portal URL must use HTTPS.', 'danger')
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
        Set-GPOStartupScript -Name $GPO -Command "powershell.exe" -Arguments "-NoProfile -File `"$installScriptPath`" -PortalURL `"$PortalURL`""
        
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
    """Disable a user, move to Disabled OU, and start archive retention tracking."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    config = get_ad_config()
    if not config:
        message = 'AD not configured. Please complete setup first.'
        if is_ajax:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'danger')
        return redirect(request.referrer or url_for('main.user_search'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    user_dn = request.form.get('user_dn')
    if not user_dn and request.is_json:
        payload = request.get_json(silent=True) or {}
        user_dn = payload.get('user_dn')
    if not user_dn:
        if is_ajax:
            return jsonify({'success': False, 'message': 'No user specified.'}), 400
        flash('No user specified.', 'danger')
        return redirect(request.referrer or url_for('main.user_search'))

    result = _disable_user_with_lifecycle(user_dn, ad_args, config)
    if not result.get('success'):
        message = result.get('message', 'Disable failed.')
        if is_ajax:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'danger')
        return redirect(request.referrer or url_for('main.user_search'))

    if is_ajax:
        return jsonify(result)

    flash(result.get('message', 'User disabled.'), 'warning' if result.get('partial') else 'success')
    return redirect(request.referrer or url_for('main.user_search'))

@main.route('/admin/enable_user', methods=['POST'])
@login_required
@admin_required
def enable_user_route():
    """Enable a user and restore them to their original OU when available."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    config = get_ad_config()
    if not config:
        message = 'AD not configured. Please complete setup first.'
        if is_ajax:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'danger')
        return redirect(request.referrer or url_for('main.user_search'))
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    user_dn = request.form.get('user_dn')
    if not user_dn and request.is_json:
        payload = request.get_json(silent=True) or {}
        user_dn = payload.get('user_dn')
    if not user_dn:
        if is_ajax:
            return jsonify({'success': False, 'message': 'No user specified.'}), 400
        flash('No user specified.', 'danger')
        return redirect(request.referrer or url_for('main.user_search'))

    user_details = get_user_details(user_dn, **ad_args) or {}
    username = _ad_attr_scalar(
        user_details.get('sAMAccountName')
        or user_details.get('samAccountName')
        or user_details.get('cn')
        or user_dn.split(',')[0].replace('CN=', '')
    )

    ok, msg = ad_enable_user(user_dn, **ad_args)
    if not ok:
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(request.referrer or url_for('main.user_search'))

    lifecycle = DisabledUserLifecycle.query.filter_by(username=username).first()
    restore_msg = ''
    updated_dn = user_dn
    if lifecycle and lifecycle.original_ou_dn and lifecycle.original_ou_dn.lower() not in user_dn.lower():
        restore_ok, restore_detail = move_user_to_ou(user_dn, lifecycle.original_ou_dn, **ad_args)
        if restore_ok:
            updated_dn = _calculate_moved_dn(user_dn, lifecycle.original_ou_dn)
            restore_msg = ' User moved back to original OU.'
        else:
            restore_msg = f' Could not move back to original OU: {restore_detail}'

    if lifecycle:
        lifecycle.current_dn = updated_dn
        lifecycle.status = 'restored'
        lifecycle.restored_at = datetime.now(timezone.utc)
        lifecycle.last_archive_error = None
        db.session.commit()

    log_user_action('enable_user', username, 'success', {'user_dn': user_dn, 'restored_dn': updated_dn})
    message = f'User enabled successfully.{restore_msg}'
    if is_ajax:
        return jsonify({'success': True, 'message': message})
    flash(message, 'success')
    return redirect(request.referrer or url_for('main.user_search'))

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
            # Check if AD is configured - if so, prioritize AD authentication
            config = get_ad_config()
            if config:
                # Try AD authentication first (since AD is configured)
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
                    log_login(username, 'failure', {'reason': 'invalid_credentials', 'details': msg})
                    error = msg or 'Invalid credentials.'
            else:
                # AD not configured - try local admin login only
                admin = Admin.query.filter_by(username=username).first()
                if admin and admin.check_password(password):
                    login_user(admin)
                    session['role'] = 'admin'
                    session['view_mode'] = 'admin'
                    log_login(username, 'success', {'method': 'local_admin'})
                    flash('Logged in as administrator.', 'success')
                    return redirect(url_for('main.dashboard'))
                else:
                    log_login(username, 'failure', {'reason': 'invalid_credentials', 'details': msg})
                    error = msg or 'Invalid credentials.'
    
    return render_template('login.html', error=error)

@main.route('/dashboard')
@login_required
def dashboard():
    """Unified dashboard that shows admin or user view based on role and view mode"""
    role = session.get('role', 'user')
    view_mode = session.get('view_mode', role)
    
    # If role/view_mode is not admin, check if user is actually an admin
    if role != 'admin' and view_mode != 'admin':
        # First check if user exists in Admin table (local admin)
        admin_record = Admin.query.filter_by(username=current_user.username).first()
        if admin_record:
            # User is in Admin table - grant admin access
            session['role'] = 'admin'
            session['view_mode'] = 'admin'
            role = 'admin'
            view_mode = 'admin'
        else:
            # If AD is configured, check if user is in admin group
            config = get_ad_config()
            if config:
                try:
                    is_admin_user = is_user_in_admin_group(
                        current_user.username,
                        server=config['ad_server'],
                        port=config['ad_port'],
                        bind_user=config['ad_bind_dn'],
                        bind_password=config['ad_password'],
                        base_dn=config['ad_base_dn']
                    )
                    if is_admin_user:
                        # Update session to reflect admin status
                        session['role'] = 'admin'
                        session['view_mode'] = 'admin'
                        role = 'admin'
                        view_mode = 'admin'
                except Exception as e:
                    # If AD check fails, user remains as regular user
                    pass
    
    if view_mode == 'admin' or role == 'admin':
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
    from flask import request, session, has_request_context
    
    config = get_ad_config()
    if not config:
        return None
    
    # Support callers outside HTTP request context (e.g. scripts/tests).
    if has_request_context():
        debug_enabled = request.args.get('debug') == '1' or session.get('dashboard_debug')
    else:
        debug_enabled = False
    
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
        base_dn = config['ad_base_dn']
        from .ad import get_organization_ous
        org_ous = get_organization_ous(base_dn)
        primary_users_base = org_ous['primary_users_ou']
        disabled_users_ou = org_ous['disabled_users_ou']
        
        # Default excluded OUs (matching user search behavior)
        default_exclude_ous = [
            disabled_users_ou,
            org_ous.get('archive_users_ou', ''),
            org_ous['service_accounts_ou'],
            org_ous['internal_tools_ou']
        ]
        
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
        base_dn = config['ad_base_dn']
        org_ous = get_organization_ous(base_dn)
        primary_users_base = org_ous['primary_users_ou']
        disabled_users_ou = org_ous['disabled_users_ou']
        
        # Default excluded OUs (matching user search behavior)
        default_exclude_ous = [
            disabled_users_ou,
            org_ous.get('archive_users_ou', ''),
            org_ous['service_accounts_ou'],
            org_ous['internal_tools_ou']
        ]
        
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