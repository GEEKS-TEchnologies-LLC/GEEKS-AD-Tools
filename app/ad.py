import os
import json
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from collections import namedtuple, Counter
from contextlib import contextmanager
import datetime

CONFIG_PATH = 'app/ad_config.json'

# --- Helper Classes & Context Managers ---

Group = namedtuple('Group', ['dn', 'name'])

@contextmanager
def ad_connection(**kwargs):
    """Context manager for handling ldap3 connections."""
    # Map configuration keys to expected parameter names
    server = kwargs.get('server') or kwargs.get('ad_server')
    bind_user = kwargs.get('bind_user') or kwargs.get('ad_bind_dn')
    bind_password = kwargs.get('bind_password') or kwargs.get('ad_password')
    base_dn = kwargs.get('base_dn') or kwargs.get('ad_base_dn')
    
    server_uri = f"ldap://{server}"
    server_obj = ldap3.Server(server_uri, get_info=ldap3.ALL)
    conn = ldap3.Connection(server_obj, user=bind_user, password=bind_password, auto_bind=True, raise_exceptions=True)
    try:
        yield conn
    finally:
        conn.unbind()

# --- Configuration ---

def _get_base_dn(ad_args):
    """Helper function to get base_dn with proper mapping"""
    return ad_args.get('base_dn') or ad_args.get('ad_base_dn')

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
    base_dn = _get_base_dn(ad_args)
    
    with ad_connection(**ad_args) as conn:
        try:
            conn.search(base_dn, filter_str, search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'mail', 'distinguishedName', 'objectClass'])
            
            for entry in conn.entries:
                # Check if this is a user object
                is_user = False
                if hasattr(entry, 'objectClass') and entry.objectClass.value:
                    object_classes = entry.objectClass.value
                    if isinstance(object_classes, list):
                        is_user = 'user' in object_classes and 'computer' not in object_classes
                    else:
                        is_user = 'user' in str(object_classes) and 'computer' not in str(object_classes)
                
                if is_user:
                    # Parse OU from DN - show path from user up 2 levels (immediate parent → parent's parent)
                    dn_parts = entry.distinguishedName.value.split(',')
                    ou_parts = [part[3:] for part in dn_parts if part.startswith('OU=')]
                    
                    # Show path from user up 2 levels (immediate parent → parent's parent)
                    if ou_parts:
                        if len(ou_parts) >= 2:
                            # Take the last 2 OUs and reverse them to show immediate parent first
                            immediate_parent = ou_parts[-1]  # Last OU (immediate parent)
                            parent_parent = ou_parts[-2]     # Second to last OU (parent's parent)
                            ou = f'{immediate_parent} → {parent_parent}'
                        else:
                            # Only one OU, show it
                            ou = ou_parts[0]
                    else:
                        ou = 'Domain Root'
                    
                    users.append({
                        'dn': entry.distinguishedName.value,
                        'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                        'displayName': entry.displayName.value if entry.displayName else '',
                        'mail': entry.mail.value if entry.mail else '',
                        'ou': ou
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

def create_user(username, password, display_name, mail, target_ou=None, **ad_args):
    config = get_ad_config()
    
    # Use specified OU or default to base_dn
    if target_ou:
        user_dn = f'CN={username},{target_ou}'
    else:
        user_dn = f'CN={username},{ad_args["base_dn"]}'
    
    # Try without userPrincipalName first
    attrs = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': username,
        'displayName': display_name
    }
    
    # Only add mail attribute if email is provided
    if mail and mail.strip():
        attrs['mail'] = mail

    with ad_connection(**ad_args) as conn:
        try:
            # Step 1: Create user with minimal attributes (no userPrincipalName)
            result = conn.add(user_dn, attributes=attrs)
            if not result:
                error_msg = f"Failed to create user: {conn.result['description']}"
                return False, error_msg
            
            # Step 2: Try to set password (optional)
            if password:
                try:
                    password_result = set_password(user_dn, password, **ad_args)
                    if not password_result[0]:
                        print(f"Warning: Password set failed: {password_result[1]}")
                except Exception as e:
                    print(f"Warning: Password set exception: {str(e)}")
            
            # Step 3: Try to enable the account (optional)
            try:
                enable_result = enable_user(user_dn, **ad_args)
                if not enable_result[0]:
                    print(f"Warning: Account enable failed: {enable_result[1]}")
            except Exception as e:
                print(f"Warning: Account enable exception: {str(e)}")
            
            return True, f'User {username} created successfully.'
        except Exception as e:
            error_msg = f"Exception during user creation: {str(e)}"
            return False, error_msg

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
        # Check if user is already a member
        conn.search(group_dn, '(objectClass=group)', attributes=['member'])
        if conn.entries and hasattr(conn.entries[0], 'member') and conn.entries[0].member:
            members = conn.entries[0].member.value
            if user_dn in members:
                return (True, "User is already a member of the group.")
        try:
            result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
            return (True, "User added to group.") if result else (False, f"Failed to add user to group: {conn.result['description']}")
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult:
            return (True, "User is already a member of the group.")
        except Exception as e:
            return (False, f"Error adding user to group: {e}")

def remove_user_from_group(user_dn, group_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        return (True, "User removed from group.") if result else (False, f"Failed to remove user from group: {conn.result['description']}")

# --- Admin & Authentication ---

def get_admin_groups():
    config = get_ad_config()
    return config.get('admin_groups', ['Domain Admins']) if config else ['Domain Admins']

def set_admin_groups(groups):
    config = get_ad_config() or {}
    config['admin_groups'] = groups
    save_ad_config(config)

def is_user_in_admin_group(username, **ad_args):
    # This function needs to find the user's DN first
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], f'(sAMAccountName={username})', attributes=['memberOf'])
        if not conn.entries:
            return False
        
        user_groups = conn.entries[0].memberOf.value if conn.entries[0].memberOf else []
        admin_groups = get_admin_groups()
        
        for group_dn in user_groups:
            for admin_group_cn in admin_groups:
                # Check if the admin group's CN is in the user's group DN
                if f"CN={admin_group_cn}".lower() in group_dn.lower():
                    return True
    return False

def authenticate_user(username, password):
    config = get_ad_config()
    if not config: return False, "AD not configured."
    
    ad_args = {
        'server': config['ad_server'],
        'port': config['ad_port'],
        'base_dn': config['ad_base_dn'],
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password']
    }

    # Step 1: Bind with service account to find the user's DN
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], f'(sAMAccountName={username})', attributes=['distinguishedName'])
        if not conn.entries:
            return False, "User not found."
        user_dn = conn.entries[0].distinguishedName.value

    # Step 2: Try to bind as the user with their password
    try:
        # Use a new connection with the user's real credentials
        with ldap3.Connection(conn.server, user=user_dn, password=password, auto_bind=True, raise_exceptions=True):
            return True, "Authentication successful."
    except LDAPBindError:
        return False, "Invalid credentials."
    except Exception as e:
        return False, parse_ldap_error(e)

# --- Statistics and Health ---

def get_ad_statistics(**ad_args):
    stats = {
        'total_users': 0, 'enabled_users': 0, 'locked_users': 0, 
        'total_computers': 0, 'total_groups': 0, 'total_ous': 0,
        'recent_logins': [],
        'expired_passwords': [],
        'os_breakdown': {},
        'client_os_breakdown': {},
        'server_os_breakdown': {},
        'group_types': {},
        'user_types_breakdown': {}
    }
    max_password_age_days = 90  # TODO: make dynamic from AD policy
    now = datetime.datetime.utcnow()
    user_login_info = []
    expired_pw_users = []
    from .ad import get_os_breakdown, get_group_types_for_user
    with ad_connection(**ad_args) as conn:
        # Get users
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['userAccountControl', 'objectClass', 'sAMAccountName', 'displayName', 'lastLogonTimestamp', 'pwdLastSet'])
        user_entries = [
            e for e in conn.entries
            if hasattr(e, "objectClass") and e.objectClass.value and 'user' in e.objectClass.value and 'computer' not in e.objectClass.value
        ]
        stats['total_users'] = len(user_entries)
        for entry in user_entries:
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
            if not (uac & 2): stats['enabled_users'] += 1
            if uac & 16: stats['locked_users'] += 1
            # Recent logins
            last_logon = None
            if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp.value:
                try:
                    # Convert AD timestamp to datetime
                    last_logon = datetime.datetime.utcfromtimestamp((int(entry.lastLogonTimestamp.value) - 116444736000000000) / 10000000)
                except Exception:
                    last_logon = None
            user_login_info.append({
                'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                'displayName': entry.displayName.value if entry.displayName else '',
                'lastLogon': last_logon
            })
            # Expired passwords
            pwd_last_set = None
            if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet.value:
                try:
                    pwd_last_set = datetime.datetime.utcfromtimestamp((int(entry.pwdLastSet.value) - 116444736000000000) / 10000000)
                except Exception:
                    pwd_last_set = None
            if pwd_last_set:
                days_since = (now - pwd_last_set).days
                if days_since > max_password_age_days:
                    expired_pw_users.append({
                        'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                        'displayName': entry.displayName.value if entry.displayName else '',
                        'days_since_pwd_set': days_since
                    })
        # Top 10 recent logins
        stats['recent_logins'] = sorted(
            [u for u in user_login_info if u['lastLogon']],
            key=lambda x: x['lastLogon'], reverse=True
        )[:10]
        # Expired passwords
        stats['expired_passwords'] = expired_pw_users
        # Get computers
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        stats['total_computers'] = len(conn.entries)
        # Get groups
        conn.search(ad_args['base_dn'], '(objectClass=group)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        group_dns = [e.distinguishedName.value for e in conn.entries if hasattr(e, 'distinguishedName') and e.distinguishedName]
        stats['total_groups'] = len(group_dns)
        # Get OUs
        conn.search(ad_args['base_dn'], '(objectClass=organizationalUnit)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        stats['total_ous'] = len(conn.entries)
    # Add OS breakdown and group types
    stats['os_breakdown'] = get_os_breakdown(**ad_args)
    stats['client_os_breakdown'] = get_client_os_breakdown(**ad_args)
    stats['server_os_breakdown'] = get_server_os_breakdown(**ad_args)
    stats['group_types'] = get_group_types_for_user(group_dns, **ad_args)
    stats['user_types_breakdown'] = get_user_types_breakdown(**ad_args)
    return True, stats

def get_ad_health_status(**ad_args):
    health = {'status': 'healthy', 'alerts': [], 'warnings': []}
    # This is a placeholder. A real health check would be more complex.
    try:
        with ad_connection(**ad_args):
            pass # Connection success is our basic health check for now
    except Exception as e:
        health['status'] = 'error'
        health['alerts'].append(parse_ldap_error(e))
        return False, health
    return True, health

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

# --- OU Management ---

def create_ou(ou_name, parent_dn, **ad_args):
    """Create a new Organizational Unit"""
    ou_dn = f'OU={ou_name},{parent_dn}'
    
    attrs = {
        'objectClass': ['top', 'organizationalUnit'],
        'ou': ou_name
    }
    
    with ad_connection(**ad_args) as conn:
        try:
            result = conn.add(ou_dn, attributes=attrs)
            if not result:
                return False, f"Failed to create OU: {conn.result['description']}"
            return True, f'OU {ou_name} created successfully.'
        except Exception as e:
            return False, f"Exception creating OU: {str(e)}"

def list_ous(**ad_args):
    """List all OUs in the domain"""
    ous = []
    with ad_connection(**ad_args) as conn:
        try:
            conn.search(ad_args['base_dn'], '(objectClass=organizationalUnit)', 
                       search_scope=ldap3.SUBTREE, 
                       attributes=['distinguishedName', 'ou', 'description'])
            
            for entry in conn.entries:
                ous.append({
                    'dn': entry.distinguishedName.value,
                    'name': entry.ou.value if entry.ou else '',
                    'description': entry.description.value if entry.description else ''
                })
        except Exception as e:
            print(f"Error listing OUs: {e}")
    
    return sorted(ous, key=lambda x: x['dn'])

def get_ou_tree(**ad_args):
    """Get hierarchical OU structure"""
    ous = list_ous(**ad_args)
    
    # Build tree structure
    tree = []
    ou_dict = {}
    
    for ou in ous:
        ou_dict[ou['dn']] = ou
        ou['children'] = []
    
    for ou in ous:
        parent_dn = ','.join(ou['dn'].split(',')[1:])
        if parent_dn in ou_dict:
            ou_dict[parent_dn]['children'].append(ou)
        else:
            tree.append(ou)
    
    return tree

def move_user_to_ou(user_dn, new_ou_dn, **ad_args):
    """Move a user to a different OU"""
    # Extract the CN from the user DN
    cn_part = user_dn.split(',')[0]
    new_user_dn = f'{cn_part},{new_ou_dn}'
    
    with ad_connection(**ad_args) as conn:
        try:
            result = conn.modify_dn(user_dn, cn_part, new_superior=new_ou_dn)
            if not result:
                return False, f"Failed to move user: {conn.result['description']}"
            return True, f'User moved to {new_ou_dn} successfully.'
        except Exception as e:
            return False, f"Exception moving user: {str(e)}"

def get_user_ou(user_dn, **ad_args):
    """Get the OU where a user is located"""
    with ad_connection(**ad_args) as conn:
        try:
            if conn.search(user_dn, '(objectclass=user)', search_scope=ldap3.BASE, attributes=['distinguishedName']):
                dn_parts = conn.entries[0].distinguishedName.value.split(',')
                # Find the OU part
                for i, part in enumerate(dn_parts):
                    if part.startswith('OU='):
                        return ','.join(dn_parts[i:])
                return ad_args['base_dn']
        except Exception as e:
            print(f"Error getting user OU: {e}")
    
    return ad_args['base_dn']

def get_group_types_for_user(user_groups, **ad_args):
    # user_groups: list of group DNs
    group_type_map = {
        2: 'Global Security',
        4: 'Domain Local Security',
        8: 'Universal Security',
        -2147483646: 'Global Distribution',
        -2147483644: 'Domain Local Distribution',
        -2147483640: 'Universal Distribution',
    }
    type_counts = Counter()
    with ad_connection(**ad_args) as conn:
        for group_dn in user_groups:
            if conn.search(group_dn, '(objectClass=group)', attributes=['groupType']):
                entry = conn.entries[0]
                group_type_val = entry.groupType.value if hasattr(entry, 'groupType') and entry.groupType else None
                group_type_str = group_type_map.get(group_type_val, str(group_type_val) if group_type_val else 'Unknown')
                type_counts[group_type_str] += 1
    return dict(type_counts)

def get_client_os_breakdown(**ad_args):
    # Returns a dict: { 'Windows XP': n, 'Windows 7': n, ... }
    os_versions = Counter()
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['operatingSystem'])
        for entry in conn.entries:
            os_name = entry.operatingSystem.value if hasattr(entry, 'operatingSystem') and entry.operatingSystem else 'Unknown'
            if os_name:
                if 'Windows XP' in os_name:
                    os_versions['Windows XP'] += 1
                elif 'Windows 7' in os_name:
                    os_versions['Windows 7'] += 1
                elif 'Windows 8' in os_name:
                    os_versions['Windows 8'] += 1
                elif 'Windows 10' in os_name:
                    os_versions['Windows 10'] += 1
                elif 'Windows 11' in os_name:
                    os_versions['Windows 11'] += 1
                else:
                    # Only count as Other if it's not a server OS
                    if not any(server_os in os_name for server_os in ['Windows Server 2008', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022']):
                        os_versions['Other'] += 1
            else:
                os_versions['Unknown'] += 1
    return dict(os_versions)

def get_server_os_breakdown(**ad_args):
    # Returns a dict: { 'Windows Server 2008': n, 'Windows Server 2012': n, ... }
    os_versions = Counter()
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['operatingSystem'])
        for entry in conn.entries:
            os_name = entry.operatingSystem.value if hasattr(entry, 'operatingSystem') and entry.operatingSystem else 'Unknown'
            if os_name:
                if 'Windows Server 2008' in os_name:
                    os_versions['Windows Server 2008'] += 1
                elif 'Windows Server 2012' in os_name:
                    os_versions['Windows Server 2012'] += 1
                elif 'Windows Server 2016' in os_name:
                    os_versions['Windows Server 2016'] += 1
                elif 'Windows Server 2019' in os_name:
                    os_versions['Windows Server 2019'] += 1
                elif 'Windows Server 2022' in os_name:
                    os_versions['Windows Server 2022'] += 1
    return dict(os_versions)

def get_os_breakdown(**ad_args):
    # Returns a dict: { 'Windows XP': n, 'Windows 7': n, ... }
    os_versions = Counter()
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['operatingSystem'])
        for entry in conn.entries:
            os_name = entry.operatingSystem.value if hasattr(entry, 'operatingSystem') and entry.operatingSystem else 'Unknown'
            if os_name:
                if 'Windows XP' in os_name:
                    os_versions['Windows XP'] += 1
                elif 'Windows 7' in os_name:
                    os_versions['Windows 7'] += 1
                elif 'Windows 8' in os_name:
                    os_versions['Windows 8'] += 1
                elif 'Windows 10' in os_name:
                    os_versions['Windows 10'] += 1
                elif 'Windows 11' in os_name:
                    os_versions['Windows 11'] += 1
                elif 'Windows Server 2008' in os_name:
                    os_versions['Windows Server 2008'] += 1
                elif 'Windows Server 2012' in os_name:
                    os_versions['Windows Server 2012'] += 1
                elif 'Windows Server 2016' in os_name:
                    os_versions['Windows Server 2016'] += 1
                elif 'Windows Server 2019' in os_name:
                    os_versions['Windows Server 2019'] += 1
                elif 'Windows Server 2022' in os_name:
                    os_versions['Windows Server 2022'] += 1
                else:
                    os_versions['Other'] += 1
            else:
                os_versions['Unknown'] += 1
    return dict(os_versions)

def get_user_types_breakdown(**ad_args):
    # Returns a dict: { 'Admin Users': n, 'Regular Users': n }
    admin_users = 0
    regular_users = 0
    admin_groups = get_admin_groups()
    
    with ad_connection(**ad_args) as conn:
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'memberOf'])
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
                
                if is_admin:
                    admin_users += 1
                else:
                    regular_users += 1
    
    return {
        'Admin Users': admin_users,
        'Regular Users': regular_users
    } 