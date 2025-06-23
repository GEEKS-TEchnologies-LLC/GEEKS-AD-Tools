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
            conn.search(ad_args['base_dn'], filter_str, search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'mail', 'distinguishedName', 'objectClass'])
            
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
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        return (True, "User added to group.") if result else (False, f"Failed to add user to group: {conn.result['description']}")

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
        'total_computers': 0, 'total_groups': 0, 'total_ous': 0
    }
    with ad_connection(**ad_args) as conn:
        # Get users
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['userAccountControl', 'objectClass'])
        user_entries = [
            e for e in conn.entries
            if hasattr(e, "objectClass") and e.objectClass.value and 'user' in e.objectClass.value and 'computer' not in e.objectClass.value
        ]
        stats['total_users'] = len(user_entries)
        for entry in user_entries:
            uac = entry.userAccountControl.value if entry.userAccountControl else 0
            if not (uac & 2): stats['enabled_users'] += 1
            if uac & 16: stats['locked_users'] += 1
        
        # Get computers
        conn.search(ad_args['base_dn'], '(objectClass=computer)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        stats['total_computers'] = len(conn.entries)

        # Get groups
        conn.search(ad_args['base_dn'], '(objectClass=group)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        stats['total_groups'] = len(conn.entries)
        
        # Get OUs
        conn.search(ad_args['base_dn'], '(objectClass=organizationalUnit)', search_scope=ldap3.SUBTREE, attributes=['distinguishedName'])
        stats['total_ous'] = len(conn.entries)

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