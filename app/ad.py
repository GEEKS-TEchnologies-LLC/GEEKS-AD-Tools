import os
import json
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from collections import namedtuple
from contextlib import contextmanager

CONFIG_PATH = 'app/ad_config.json'

# --- Helper Classes & Context Managers ---

Group = namedtuple('Group', ['dn', 'name'])

@contextmanager
def ad_connection(**kwargs):
    """Context manager for handling ldap3 connections."""
    server_uri = f"ldap://{kwargs['server']}"
    server = ldap3.Server(server_uri, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=kwargs['bind_user'], password=kwargs['bind_password'], auto_bind=True, raise_exceptions=True)
    try:
        yield conn
    finally:
        conn.unbind()

# --- Configuration ---

def save_ad_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def get_ad_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def parse_ldap_error(e):
    if isinstance(e, LDAPBindError):
        return 'Invalid credentials. Please check the Bind DN and password.'
    if "Can't contact LDAP server" in str(e):
        return 'Could not connect to the LDAP server. Please check the server address and port.'
    return f'An unexpected LDAP error occurred: {e}'

# --- Core AD Functions ---

def test_ad_connection(**ad_args):
    try:
        with ad_connection(**ad_args):
            return True, 'Connection successful.'
    except LDAPException as e:
        return False, parse_ldap_error(e)

def search_users(query, **ad_args):
    users = []
    filter_str = f'(|(sAMAccountName=*{query}*)(displayName=*{query}*)(mail=*{query}*))' if query else '(objectClass=user)'
    
    with ad_connection(**ad_args) as conn:
        try:
            conn.search(ad_args['base_dn'], filter_str, search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'mail', 'distinguishedName'])
            for entry in conn.entries:
                if 'user' in entry.objectClass.value: # Filter out non-user objects
                    users.append({
                        'dn': entry.distinguishedName.value,
                        'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                        'displayName': entry.displayName.value if entry.displayName else '',
                        'mail': entry.mail.value if entry.mail else '',
                    })
        except LDAPException as e:
            print(f"Error searching users: {e}") # Log error
            return []
    return users

def get_user_details(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        if conn.search(user_dn, '(objectclass=user)', search_scope=ldap3.BASE, attributes=ldap3.ALL_ATTRIBUTES):
            entry = conn.entries[0]
            safe_attributes = {}
            for attr_name, attr_value in entry.entry_attributes_as_dict.items():
                if isinstance(attr_value, list) and len(attr_value) > 0 and isinstance(attr_value[0], bytes):
                    try:
                        safe_attributes[attr_name] = [v.decode('utf-8') for v in attr_value]
                    except UnicodeDecodeError:
                        safe_attributes[attr_name] = [v.hex() for v in attr_value]
                else:
                    safe_attributes[attr_name] = attr_value
            return safe_attributes
    return None

def create_user(username, password, display_name, mail, **ad_args):
    config = get_ad_config()
    users_ou = config.get('users_ou') if config and config.get('users_ou') else ad_args['base_dn']
    user_dn = f'CN={username},{users_ou}'
    
    attrs = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': username,
        'userPrincipalName': mail,
        'displayName': display_name,
        'mail': mail,
        'unicodePwd': f'"{password}"'.encode('utf-16-le'),
        'userAccountControl': 512 # Enabled account
    }

    with ad_connection(**ad_args) as conn:
        result = conn.add(user_dn, attributes=attrs)
        if not result:
            return False, f"Failed to create user: {conn.result['description']}"
        return True, f'User {username} created successfully.'

def update_user_attributes(user_dn, changes, **ad_args):
    with ad_connection(**ad_args) as conn:
        ldap_changes = {key: [(ldap3.MODIFY_REPLACE, [value])] if value else [(ldap3.MODIFY_DELETE, [])] for key, value in changes.items()}
        result = conn.modify(user_dn, ldap_changes)
        if not result:
            return False, f"Failed to update user: {conn.result['description']}"
        return True, "User updated successfully."

# --- User Account Control ---

def set_password(user_dn, new_password, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])]})
        if not result:
            return False, f"Failed to set password: {conn.result['description']}"
        return True, "Password has been reset successfully."

def _get_uac(conn, user_dn):
    if conn.search(user_dn, '(objectclass=user)', search_scope=ldap3.BASE, attributes=['userAccountControl']):
        return int(conn.entries[0].userAccountControl.value) if conn.entries else None
    return None

def enable_user(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        uac = _get_uac(conn, user_dn)
        if uac is None: return False, "Could not get user account status."
        new_uac = uac & ~2  # Remove ACCOUNTDISABLE flag
        result = conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
        return (True, "User enabled successfully.") if result else (False, f"Failed to enable user: {conn.result['description']}")

def disable_user(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        uac = _get_uac(conn, user_dn)
        if uac is None: return False, "Could not get user account status."
        new_uac = uac | 2  # Add ACCOUNTDISABLE flag
        result = conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
        return (True, "User disabled successfully.") if result else (False, f"Failed to disable user: {conn.result['description']}")

def unlock_user(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(user_dn, {'lockoutTime': [(ldap3.MODIFY_REPLACE, ['0'])]})
        return (True, "User unlocked successfully.") if result else (False, f"Failed to unlock user: {conn.result['description']}")

def force_password_change(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, ['0'])]})
        return (True, "User will be required to change password.") if result else (False, f"Failed to force password change: {conn.result['description']}")

def delete_user(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.delete(user_dn)
        return (True, "User deleted successfully.") if result else (False, f"Failed to delete user: {conn.result['description']}")

# --- Group Management ---

def get_user_groups(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        if conn.search(user_dn, '(objectclass=user)', attributes=['memberOf']):
            return conn.entries[0].memberOf.value if conn.entries and conn.entries[0].memberOf else []
    return []

def get_all_groups(**ad_args):
    groups = []
    base_dn = ad_args.get('base_dn')
    groups_ou = ad_args.get('groups_ou', base_dn)
    with ad_connection(**ad_args) as conn:
        conn.search(groups_ou, '(objectClass=group)', attributes=['distinguishedName', 'sAMAccountName', 'cn'])
        for entry in conn.entries:
            name = entry.cn.value if entry.cn else entry.sAMAccountName.value
            if name:
                groups.append(Group(dn=entry.distinguishedName.value, name=name))
    return sorted(groups, key=lambda g: g.name.lower())

def add_user_to_group(user_dn, group_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        return (True, "User added to group.") if result else (False, f"Failed to add user to group: {conn.result['description']}")

def remove_user_from_group(user_dn, group_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        return (True, "User removed from group.") if result else (False, f"Failed to remove user from group: {conn.result['description']}")

# --- Admin & Authentication ---

def is_user_in_admin_group(username, **ad_args):
    user_dn = f"CN={username},{ad_args['base_dn']}" # This is a simplification and might need adjustment
    admin_groups = get_admin_groups()
    try:
        member_of = get_user_groups(user_dn, **ad_args)
        for group_dn in member_of:
            for admin_group in admin_groups:
                if admin_group.lower() in group_dn.lower():
                    return True
    except LDAPException:
        return False
    return False

def authenticate_user(username, password):
    config = get_ad_config()
    if not config: return False, "AD not configured."
    
    # Step 1: Bind with service account to find the user's DN
    with ad_connection(**config) as conn:
        conn.search(config['base_dn'], f'(sAMAccountName={username})', attributes=['distinguishedName'])
        if not conn.entries:
            return False, "User not found."
        user_dn = conn.entries[0].distinguishedName.value

    # Step 2: Try to bind as the user with their password
    try:
        with ad_connection(server=config['ad_server'], bind_user=user_dn, bind_password=password):
            return True, "Authentication successful."
    except LDAPBindError:
        return False, "Invalid credentials."
    except Exception as e:
        return False, parse_ldap_error(e)

# --- Statistics and Health ---

def get_ad_statistics(**ad_args):
    stats = {
        'total_users': 0, 'enabled_users': 0, 'locked_users': 0, 'total_computers': 0, 'total_groups': 0
    }
    with ad_connection(**ad_args) as conn:
        # Get users
        conn.search(ad_args['base_dn'], '(objectClass=user)', attributes=['userAccountControl'])
        user_entries = [e for e in conn.entries if 'user' in e.objectClass.value]
        stats['total_users'] = len(user_entries)
        for entry in user_entries:
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
            if not (uac & 2): stats['enabled_users'] += 1
            if uac & 16: stats['locked_users'] += 1
        
        # Get computers
        conn.search(ad_args['base_dn'], '(objectClass=computer)', attributes=['distinguishedName'])
        stats['total_computers'] = len(conn.entries)

        # Get groups
        conn.search(ad_args['base_dn'], '(objectClass=group)', attributes=['distinguishedName'])
        stats['total_groups'] = len(conn.entries)
    return True, stats

def get_ad_health_status(**ad_args):
    return True, {'status': 'healthy', 'alerts': [], 'warnings': []}

def get_admin_groups():
    config = get_ad_config()
    if config and 'admin_groups' in config:
        return config['admin_groups']
    return ['Domain Admins']

def set_admin_groups(groups):
    config = get_ad_config() or {}
    config['admin_groups'] = groups
    save_ad_config(config)

def create_ad_group(group_name, server, port, bind_dn, password, base_dn):
    config = get_ad_config()
    groups_ou = config.get('groups_ou') if config and config.get('groups_ou') else base_dn
    ldap_url = f'ldap://{server}:{port}'
    group_dn = f'CN={group_name},{groups_ou}'
    attrs = {
        'objectClass': [b'top', b'group'],
        'sAMAccountName': [group_name.encode()]
    }
    ldif = [(k, v) for k, v in attrs.items()]
    try:
        conn = ldap3.Connection(ldap_url, user=bind_dn, password=password, auto_bind=True)
        conn.add(group_dn, attributes=attrs)
        return True, f'Group {group_name} created.'
    except LDAPException as e:
        return False, parse_ldap_error(e)

def reset_user_password(user_dn, new_password, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        with ad_connection(server=ldap_url, bind_user=bind_dn, bind_password=password):
            mod = [(ldap3.MODIFY_REPLACE, 'unicodePwd', [f'"{new_password}"'.encode('utf-16-le')])]
            conn.modify(user_dn, mod)
            return True, 'Password reset.'
    except LDAPException as e:
        return False, parse_ldap_error(e)

def get_user_groups(user_dn, **ad_args):
    ldap_url = f'ldap://{ad_args["server"]}:{ad_args["port"]}'
    try:
        with ad_connection(server=ldap_url, bind_user=ad_args['bind_dn'], bind_password=ad_args['bind_password']):
            result = conn.search_s(user_dn, ldap3.SCOPE_BASE, attrlist=['memberOf'])
            if not result:
                return []
            dn, attrs = result[0]
            groups = [g.decode() for g in attrs.get('memberOf', [])]
            return groups
    except LDAPException:
        return []

def get_ad_statistics(server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    try:
        with ad_connection(server=ldap_url, bind_user=bind_dn, bind_password=password):
            # Search for all users, computers, groups, and OUs, filtering out referrals
            user_results = [r for r in conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, '(objectClass=user)', ['userAccountControl', 'pwdLastSet']) if r[0] is not None]
            computer_results = [r for r in conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, '(objectClass=computer)', ['operatingSystem', 'userAccountControl']) if r[0] is not None]
            group_results = [r for r in conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, '(objectClass=group)', ['groupType']) if r[0] is not None]
            ou_results = [r for r in conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, '(objectClass=organizationalUnit)') if r[0] is not None]

            total_users = len(user_results)
            enabled_users = sum(1 for _, attrs in user_results if not int(attrs.get('userAccountControl', [b'0'])[0]) & 2)
            locked_users = sum(1 for _, attrs in user_results if int(attrs.get('userAccountControl', [b'0'])[0]) & 16)
            password_expired = sum(1 for _, attrs in user_results if attrs.get('pwdLastSet', [b'1'])[0] == b'0')
            
            total_computers = len(computer_results)
            os_breakdown = {}
            for _, attrs in computer_results:
                os = attrs.get('operatingSystem', [b'Unknown'])[0].decode()
                os_breakdown[os] = os_breakdown.get(os, 0) + 1
                
            total_groups = len(group_results)
            group_types = {'Security': 0, 'Distribution': 0}
            for _, attrs in group_results:
                group_type = int(attrs.get('groupType', [b'0'])[0])
                if group_type & 0x80000000: # Security group flag
                    group_types['Security'] += 1
                else:
                    group_types['Distribution'] += 1

            stats = {
                'total_users': total_users,
                'enabled_users': enabled_users,
                'locked_users': locked_users,
                'password_expired': password_expired,
                'total_computers': total_computers,
                'os_breakdown': os_breakdown,
                'total_groups': total_groups,
                'group_types': group_types,
                'total_ous': len(ou_results),
            }
            return True, stats
    except LDAPException as e:
        return False, parse_ldap_error(e)

def get_ad_health_status(server, port, bind_dn, password, base_dn):
    """Get AD health status and alerts"""
    ldap_url = f'ldap://{server}:{port}'
    health = {
        'status': 'healthy',
        'alerts': [],
        'warnings': []
    }
    
    try:
        with ad_connection(server=ldap_url, bind_user=bind_dn, bind_password=password):
            # Check for locked accounts
            locked_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16))'
            locked_count = len(conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, locked_filter))
            
            if locked_count > 10:
                health['warnings'].append(f'{locked_count} user accounts are locked')
            
            # Check for expired passwords
            expired_filter = '(&(objectClass=user)(pwdLastSet=0))'
            expired_count = len(conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, expired_filter))
            
            if expired_count > 5:
                health['warnings'].append(f'{expired_count} user passwords have expired')
            
            # Check for disabled accounts
            disabled_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
            disabled_count = len(conn.search_s(base_dn, ldap3.SCOPE_SUBTREE, disabled_filter))
            
            if disabled_count > 20:
                health['warnings'].append(f'{disabled_count} user accounts are disabled')
            
            if health['warnings']:
                health['status'] = 'warning'
            
            return True, health
            
    except LDAPException as e:
        health['status'] = 'error'
        health['alerts'].append(f'AD connection failed: {str(e)}')
        return False, health 