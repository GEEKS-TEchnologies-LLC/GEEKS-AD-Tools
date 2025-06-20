import os
import json
import ldap
import ldap3
from collections import namedtuple

CONFIG_PATH = 'app/ad_config.json'

def save_ad_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f)

def get_ad_config():
    """Load AD configuration from the JSON file."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def test_ad_connection(server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        conn.unbind_s()
        return True, 'Connection successful.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)

def parse_ldap_error(error_string):
    """
    Parses an ldap.LDAPError string and returns a user-friendly message.
    """
    error_string = str(error_string) 
    
    if 'Invalid credentials' in error_string:
        return 'Invalid credentials. Please check the Bind DN and password.'
    if "Can't contact LDAP server" in error_string:
        return 'Could not connect to the LDAP server. Please check the server address and port.'
    if 'SERVER_DOWN' in error_string:
        return 'The LDAP server is down or unreachable.'
    if 'NO_SUCH_OBJECT' in error_string:
        return 'The Base DN could not be found. Please check your Base DN setting.'
    if 'INAPPROPRIATE_AUTH' in error_string:
        return 'Inappropriate authentication. The server may require a different authentication method (e.g., SASL).'
    
    # Fallback for other errors
    try:
        # The error is often a dictionary string, try to parse it
        import ast
        error_dict = ast.literal_eval(error_string)
        if 'desc' in error_dict:
            return f"An LDAP error occurred: {error_dict['desc']}"
    except (ValueError, SyntaxError):
        # Not a dict string, return the raw error
        pass
        
    return f'An unexpected LDAP error occurred: {error_string}'

def get_admin_groups():
    config = get_ad_config()
    if config and 'admin_groups' in config:
        return config['admin_groups']
    return ['Domain Admins']

def set_admin_groups(groups):
    config = get_ad_config() or {}
    config['admin_groups'] = groups
    save_ad_config(config)

def is_user_in_admin_group(username, server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    admin_groups = get_admin_groups()
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        search_filter = f'(sAMAccountName={username})'
        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, ['memberOf'])
        if not result:
            return False
        user_dn, attrs = result[0]
        member_of = attrs.get('memberOf', [])
        for group_dn in member_of:
            for admin_group in admin_groups:
                if admin_group.lower() in group_dn.decode().lower():
                    return True
        return False
    except ldap.LDAPError:
        return False
    finally:
        try:
            conn.unbind_s()
        except:
            pass

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
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        conn.add_s(group_dn, ldif)
        return True, f'Group {group_name} created.'
    except ldap.ALREADY_EXISTS:
        return False, 'Group already exists.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def add_user_to_group(user_dn, group_dn, **ad_args):
    """Add a user to a group in AD."""
    with ad_connection(**ad_args) as conn:
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        if not result:
            return False, f"Failed to add user to group. Error: {conn.result['description']}"
        return True, "User added to group successfully."

def search_users(query, server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    if query:
        filter_str = f'(|(sAMAccountName=*{query}*)(displayName=*{query}*)(mail=*{query}*))'
    else:
        # If query is empty, find all user objects
        filter_str = '(objectClass=user)'
        
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        
        # Search for users and filter out referrals
        results = [r for r in conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str, ['sAMAccountName', 'displayName', 'mail', 'distinguishedName']) if r[0] is not None]
        
        users = []
        for dn, attrs in results:
            users.append({
                'dn': dn,
                'username': attrs.get('sAMAccountName', [b''])[0].decode(),
                'displayName': attrs.get('displayName', [b''])[0].decode(),
                'mail': attrs.get('mail', [b''])[0].decode(),
            })
        return users
    except ldap.LDAPError as e:
        return []
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def get_user_details(user_dn, **ad_args):
    """Get all details for a specific user from AD."""
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

def create_user(username, password, display_name, mail, server, port, bind_dn, bind_pw, base_dn):
    config = get_ad_config()
    users_ou = config.get('users_ou') if config and config.get('users_ou') else base_dn
    ldap_url = f'ldap://{server}:{port}'
    user_dn = f'CN={username},{users_ou}'
    
    attrs = {
        'objectClass': [b'top', b'person', b'organizationalPerson', b'user'],
        'sAMAccountName': [username.encode()],
        'userPrincipalName': [mail.encode()],
        'displayName': [display_name.encode()],
        'mail': [mail.encode()],
    }
    ldif = [(k, v) for k, v in attrs.items()]
    
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, bind_pw)
        conn.add_s(user_dn, ldif)
        
        # Set password
        password_mod = [(ldap.MOD_REPLACE, 'unicodePwd', [f'"{password}"'.encode('utf-16-le')])]
        conn.modify_s(user_dn, password_mod)
        
        # Enable the user (set userAccountControl to 512 for normal account)
        mod = [(ldap.MOD_REPLACE, 'userAccountControl', [b'512'])]
        conn.modify_s(user_dn, mod)
        
        return True, f'User {username} created.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def delete_user(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        conn.delete_s(user_dn)
        return True, 'User deleted.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def disable_user(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        # Set userAccountControl to 514 (disabled)
        mod = [(ldap.MOD_REPLACE, 'userAccountControl', [b'514'])]
        conn.modify_s(user_dn, mod)
        return True, 'User disabled.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def enable_user(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        # Set userAccountControl to 512 (enabled)
        mod = [(ldap.MOD_REPLACE, 'userAccountControl', [b'512'])]
        conn.modify_s(user_dn, mod)
        return True, 'User enabled.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def reset_user_password(user_dn, new_password, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        mod = [(ldap.MOD_REPLACE, 'unicodePwd', [f'"{new_password}"'.encode('utf-16-le')])]
        conn.modify_s(user_dn, mod)
        return True, 'Password reset.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def force_password_change(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        # Set pwdLastSet to 0
        mod = [(ldap.MOD_REPLACE, 'pwdLastSet', [b'0'])]
        conn.modify_s(user_dn, mod)
        return True, 'User must change password at next login.'
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def get_user_groups(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        result = conn.search_s(user_dn, ldap.SCOPE_BASE, attrlist=['memberOf'])
        if not result:
            return []
        dn, attrs = result[0]
        groups = [g.decode() for g in attrs.get('memberOf', [])]
        return groups
    except ldap.LDAPError:
        return []
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def remove_user_from_group(user_dn, group_dn, **ad_args):
    """Remove a user from a group in AD."""
    with ad_connection(**ad_args) as conn:
        result = conn.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        if not result:
            return False, f"Failed to remove user from group. Error: {conn.result['description']}"
        return True, "User removed from group successfully."

def get_ad_statistics(server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)

        # Search for all users, computers, groups, and OUs, filtering out referrals
        user_results = [r for r in conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(objectClass=user)', ['userAccountControl', 'pwdLastSet']) if r[0] is not None]
        computer_results = [r for r in conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(objectClass=computer)', ['operatingSystem', 'userAccountControl']) if r[0] is not None]
        group_results = [r for r in conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(objectClass=group)', ['groupType']) if r[0] is not None]
        ou_results = [r for r in conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(objectClass=organizationalUnit)') if r[0] is not None]

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
    except ldap.LDAPError as e:
        return False, parse_ldap_error(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def get_ad_health_status(server, port, bind_dn, password, base_dn):
    """Get AD health status and alerts"""
    ldap_url = f'ldap://{server}:{port}'
    health = {
        'status': 'healthy',
        'alerts': [],
        'warnings': []
    }
    
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        
        # Check for locked accounts
        locked_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16))'
        locked_count = len(conn.search_s(base_dn, ldap.SCOPE_SUBTREE, locked_filter))
        
        if locked_count > 10:
            health['warnings'].append(f'{locked_count} user accounts are locked')
        
        # Check for expired passwords
        expired_filter = '(&(objectClass=user)(pwdLastSet=0))'
        expired_count = len(conn.search_s(base_dn, ldap.SCOPE_SUBTREE, expired_filter))
        
        if expired_count > 5:
            health['warnings'].append(f'{expired_count} user passwords have expired')
        
        # Check for disabled accounts
        disabled_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
        disabled_count = len(conn.search_s(base_dn, ldap.SCOPE_SUBTREE, disabled_filter))
        
        if disabled_count > 20:
            health['warnings'].append(f'{disabled_count} user accounts are disabled')
        
        if health['warnings']:
            health['status'] = 'warning'
        
        return True, health
        
    except ldap.LDAPError as e:
        health['status'] = 'error'
        health['alerts'].append(f'AD connection failed: {str(e)}')
        return False, health
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def authenticate_user(username, password):
    """
    Authenticates a user against AD.
    First finds the user's DN, then attempts to bind with it.
    """
    config = get_ad_config()
    if not config:
        return False, "AD not configured."
        
    ldap_url = f"ldap://{config['ad_server']}:{config['ad_port']}"
    
    # Step 1: Bind with service account to find the user's DN
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(config['ad_bind_dn'], config['ad_password'])
    except ldap.LDAPError as e:
        # Cannot proceed if service account bind fails
        return False, f"Could not bind with service account: {parse_ldap_error(e)}"

    # Step 2: Search for the user to get their DN
    search_filter = f'(sAMAccountName={username})'
    user_dn = None
    try:
        result = conn.search_s(config['ad_base_dn'], ldap.SCOPE_SUBTREE, search_filter, ['dn'])
        if not result:
            conn.unbind_s()
            return False, "User not found."
        user_dn = result[0][0]
    except ldap.LDAPError as e:
        conn.unbind_s()
        return False, f"Error searching for user: {parse_ldap_error(e)}"
    finally:
        # Unbind the service account connection
        conn.unbind_s()

    # Step 3: Try to bind as the user with their password and the found DN
    if user_dn:
        try:
            user_conn = ldap.initialize(ldap_url)
            user_conn.simple_bind_s(user_dn, password)
            user_conn.unbind_s()
            return True, "Authentication successful."
        except ldap.LDAPError as e:
            return False, parse_ldap_error(e)
    
    return False, "Could not find user DN to authenticate."

def update_user_attributes(user_dn, changes, **ad_args):
    """Update a user's attributes in AD."""
    with ad_connection(**ad_args) as conn:
        ldap_changes = {}
        for key, value in changes.items():
            # If value is provided, replace the attribute. If empty, clear it.
            if value:
                ldap_changes[key] = [(ldap3.MODIFY_REPLACE, [value])]
            else:
                ldap_changes[key] = [(ldap3.MODIFY_DELETE, [])]
        
        result = conn.modify(user_dn, ldap_changes)
        if not result:
            return False, f"Failed to update user. Error: {conn.result['description']}"
        return True, "User updated successfully."

def get_user_groups(user_dn, **ad_args):
    """Get the groups a user is a member of."""
    with ad_connection(**ad_args) as conn:
        if conn.search(user_dn, '(objectclass=user)', attributes=['memberOf']):
            entry = conn.entries[0]
            groups = [g for g in entry.entry_attributes_as_dict.get('memberOf', [])]
            return groups
    return []

Group = namedtuple('Group', ['dn', 'name'])

def get_all_groups(**ad_args):
    """Get all groups from AD."""
    groups = []
    config = get_ad_config()
    if not config:
        return []

    base_dn = config.get('base_dn')
    groups_ou = config.get('groups_ou')
    search_base = groups_ou if groups_ou else base_dn

    with ad_connection(**ad_args) as conn:
        try:
            conn.search(search_base, '(objectClass=group)', attributes=['distinguishedName', 'sAMAccountName', 'cn'])
            for entry in conn.entries:
                # Some groups might not have a cn, fallback to sAMAccountName
                name = None
                if entry.cn:
                    name = entry.cn.value
                elif entry.sAMAccountName:
                    name = entry.sAMAccountName.value

                if name:
                    groups.append(Group(dn=entry.distinguishedName.value, name=name))
        except ldap3.LDAPException as e:
            # Handle potential exceptions during search
            print(f"LDAP search for groups failed: {e}")
            return []
    
    return sorted(groups, key=lambda g: g.name.lower()) 