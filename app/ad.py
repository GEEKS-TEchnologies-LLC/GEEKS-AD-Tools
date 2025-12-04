import os
import json
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPNoSuchObjectResult
from collections import namedtuple, Counter
from contextlib import contextmanager
import datetime
import re
import threading
import time
from functools import lru_cache

CONFIG_PATH = 'app/ad_config.json'

# --- Helper Classes & Context Managers ---

Group = namedtuple('Group', ['dn', 'name'])

# Connection pool for LDAP connections
_connection_pool = {}
_pool_lock = threading.Lock()
_pool_max_age = 300  # 5 minutes - connections older than this are closed
_pool_cleanup_interval = 60  # Cleanup every 60 seconds

def _get_connection_key(server, bind_user, bind_password):
    """Generate a unique key for connection pooling"""
    return f"{server}:{bind_user}:{hash(bind_password)}"

def _cleanup_old_connections():
    """Remove old connections from the pool"""
    current_time = time.time()
    keys_to_remove = []
    
    with _pool_lock:
        for key, (conn, created_time) in _connection_pool.items():
            if current_time - created_time > _pool_max_age:
                try:
                    conn.unbind()
                except:
                    pass
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del _connection_pool[key]

@contextmanager
def ad_connection(**kwargs):
    """Context manager for handling ldap3 connections with connection pooling."""
    # Map configuration keys to expected parameter names
    server = kwargs.get('server') or kwargs.get('ad_server')
    bind_user = kwargs.get('bind_user') or kwargs.get('ad_bind_dn')
    bind_password = kwargs.get('bind_password') or kwargs.get('ad_password')
    base_dn = kwargs.get('base_dn') or kwargs.get('ad_base_dn')
    
    # Cleanup old connections periodically
    if not hasattr(ad_connection, '_last_cleanup'):
        ad_connection._last_cleanup = 0
    
    current_time = time.time()
    if current_time - ad_connection._last_cleanup > _pool_cleanup_interval:
        _cleanup_old_connections()
        ad_connection._last_cleanup = current_time
    
    # Try to reuse connection from pool
    pool_key = _get_connection_key(server, bind_user, bind_password)
    use_pool = True  # Enable pooling by default
    pooled = False
    
    if use_pool:
        with _pool_lock:
            if pool_key in _connection_pool:
                conn, created_time = _connection_pool[pool_key]
                # Check if connection is still valid
                try:
                    if conn.bound:
                        # Connection is still good, use it
                        pooled = True
                        try:
                            yield conn
                        finally:
                            # Return connection to pool (already there)
                            pass
                        return
                    else:
                        # Connection is not bound, remove from pool
                        try:
                            conn.unbind()
                        except:
                            pass
                        del _connection_pool[pool_key]
                except:
                    # Connection is invalid, remove from pool
                    try:
                        conn.unbind()
                    except:
                        pass
                    if pool_key in _connection_pool:
                        del _connection_pool[pool_key]
    
    # Create new connection
    server_uri = f"ldap://{server}"
    server_obj = ldap3.Server(server_uri, get_info=ldap3.ALL)
    conn = ldap3.Connection(server_obj, user=bind_user, password=bind_password, auto_bind=True, raise_exceptions=True)
    
    try:
        yield conn
    except:
        # On error, don't pool the connection
        try:
            conn.unbind()
        except:
            pass
        raise
    finally:
        # Add to pool if pooling is enabled and no error occurred
        if use_pool and not pooled:
            try:
                # Check if connection is still valid before pooling
                if conn.bound:
                    with _pool_lock:
                        _connection_pool[pool_key] = (conn, time.time())
                        # Don't unbind, keep connection alive
                        return
            except:
                pass
        
        # Only unbind if not pooled
        if not pooled:
            try:
                conn.unbind()
            except:
                pass

# --- Configuration ---

def _get_base_dn(ad_args):
    """Helper function to get base_dn with proper mapping"""
    return ad_args.get('base_dn') or ad_args.get('ad_base_dn')

def save_ad_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

@lru_cache(maxsize=1)
def _get_ad_config_cached():
    """Cached version of get_ad_config - internal use only"""
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def get_ad_config():
    """Get AD configuration with caching"""
    # Clear cache if file was modified
    config = _get_ad_config_cached()
    if config is None:
        return None
    
    # Check if file was modified (simple check - in production, use file mtime)
    try:
        with open(CONFIG_PATH, 'r') as f:
            current_config = json.load(f)
        # If config changed, clear cache
        if json.dumps(current_config, sort_keys=True) != json.dumps(config, sort_keys=True):
            _get_ad_config_cached.cache_clear()
            return current_config
    except:
        pass
    
    return config

def get_organization_ous(base_dn=None):
    """
    Get organization-specific OU paths from configuration.
    Returns defaults if not configured.
    
    Args:
        base_dn: Base DN to append to OU paths (if not included in config)
        
    Returns:
        Dictionary with OU paths and labels
    """
    config = get_ad_config()
    if not config:
        base_dn = base_dn or 'DC=example,DC=com'
        return {
            'primary_users_ou': base_dn,
            'disabled_users_ou': f'OU=Disabled Users,{base_dn}',
            'service_accounts_ou': f'OU=Service Accounts,{base_dn}',
            'internal_tools_ou': f'OU=Internal Tools,{base_dn}',
            'primary_users_label': 'Users'
        }
    
    org_ous = config.get('organization_ous', {})
    base_dn = base_dn or config.get('ad_base_dn', 'DC=example,DC=com')
    
    # Helper to ensure OU path ends with base_dn
    def ensure_base_dn(ou_path):
        if not ou_path:
            return base_dn
        if base_dn.lower() in ou_path.lower():
            return ou_path
        return f'{ou_path},{base_dn}'
    
    return {
        'primary_users_ou': ensure_base_dn(org_ous.get('primary_users_ou', base_dn)),
        'disabled_users_ou': ensure_base_dn(org_ous.get('disabled_users_ou', f'OU=Disabled Users')),
        'service_accounts_ou': ensure_base_dn(org_ous.get('service_accounts_ou', f'OU=Service Accounts')),
        'internal_tools_ou': ensure_base_dn(org_ous.get('internal_tools_ou', f'OU=Internal Tools')),
        'primary_users_label': org_ous.get('primary_users_label', 'Users')
    }

def get_primary_users_base(base_dn=None):
    """Get the primary users OU base DN"""
    org_ous = get_organization_ous(base_dn)
    return org_ous['primary_users_ou']

def get_disabled_users_ou(base_dn=None):
    """Get the disabled users OU DN"""
    org_ous = get_organization_ous(base_dn)
    return org_ous['disabled_users_ou']

def get_service_accounts_ou(base_dn=None):
    """Get the service accounts OU DN"""
    org_ous = get_organization_ous(base_dn)
    return org_ous['service_accounts_ou']

def get_internal_tools_ou(base_dn=None):
    """Get the internal tools OU DN"""
    org_ous = get_organization_ous(base_dn)
    return org_ous['internal_tools_ou']

def get_primary_users_label():
    """Get the label for primary users OU"""
    org_ous = get_organization_ous()
    return org_ous['primary_users_label']

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
    
    print(f"DEBUG: search_users called with query: '{query}'")
    
    # Get filter parameters
    status_filter = ad_args.get('status_filter', 'all')  # 'all', 'enabled', 'disabled'
    exclude_ous = ad_args.get('exclude_ous', [])  # List of OUs to exclude
    
    # Escape LDAP special characters in the query, but preserve wildcards
    def escape_ldap_filter(value):
        """Escape special characters in LDAP filter, but preserve wildcards"""
        if not value:
            return value
        # Don't escape wildcards (*) - they should remain as wildcards
        # Escape: \ ( ) \0 / + < > , ; " = and space
        escaped = re.sub(r'([\\()\x00/+\x00<>,;"= ])', r'\\\1', value)
        return escaped
    
    escaped_query = escape_ldap_filter(query) if query else ''
    
    # Build the filter string
    filters = ['(objectClass=user)']
    
    # Add search query filter
    if escaped_query and escaped_query != '*':
        filters.append(f'(|(sAMAccountName=*{escaped_query}*)(displayName=*{escaped_query}*)(mail=*{escaped_query}*))')
    
    # Add status filter
    if status_filter == 'enabled':
        filters.append('(!(userAccountControl:1.2.840.113556.1.4.803:=2))')  # Not disabled
    elif status_filter == 'disabled':
        filters.append('(userAccountControl:1.2.840.113556.1.4.803:=2)')  # Disabled
    
    # Combine filters
    filter_str = '(&' + ''.join(filters) + ')'
    
    # Search within primary users OU instead of using distinguishedName filters
    base_dn = _get_base_dn(ad_args)
    org_ous = get_organization_ous(base_dn)
    primary_users_base = org_ous['primary_users_ou']
    disabled_users_ou = org_ous['disabled_users_ou']
    
    print(f"DEBUG: search_users - escaped_query: '{escaped_query}', status_filter: '{status_filter}', exclude_ous: {exclude_ous}, filter_str: '{filter_str}', primary_users_base: '{primary_users_base}'")
    
    with ad_connection(**ad_args) as conn:
        try:
            print(f"DEBUG: search_users - executing search with filter: '{filter_str}' in base: '{primary_users_base}'")
            conn.search(primary_users_base, filter_str, search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'mail', 'distinguishedName', 'objectClass', 'employeeID', 'userAccountControl'])
            print(f"DEBUG: search_users - search completed, found {len(conn.entries)} entries")
            
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
                    # Check if user is in excluded OUs
                    user_dn = entry.distinguishedName.value
                    should_exclude = False
                    
                    # Always exclude users in Disabled Users OU
                    if disabled_users_ou in user_dn or 'OU=Disabled Users' in user_dn:
                        should_exclude = True
                        print(f"DEBUG: search_users - excluding user in Disabled Users OU: {user_dn}")
                    
                    # Check additional excluded OUs
                    if exclude_ous and not should_exclude:
                        for excluded_ou in exclude_ous:
                            if excluded_ou.strip() and excluded_ou.strip() in user_dn:
                                should_exclude = True
                                print(f"DEBUG: search_users - excluding user in {excluded_ou}: {user_dn}")
                                break
                    
                    if not should_exclude:
                        dn_parts = entry.distinguishedName.value.split(',')
                        ou_parts = [part[3:] for part in dn_parts if part.startswith('OU=')]
                        primary_label = org_ous['primary_users_label']
                        if primary_label in ou_parts:
                            idx = ou_parts.index(primary_label)
                            # Take primary users OU and all OUs to the right (closer to the user), reverse for left-to-right
                            display_ous = list(reversed(ou_parts[:idx+1]))
                            ou_display = ' → '.join(display_ous)
                        else:
                            ou_display = ' → '.join(reversed(ou_parts)) if ou_parts else 'Domain Root'
                        
                        # Determine account status
                        account_status = 'enabled'
                        if hasattr(entry, 'userAccountControl') and entry.userAccountControl:
                            uac = int(entry.userAccountControl.value)
                            if uac & 2:  # ADS_UF_ACCOUNTDISABLE
                                account_status = 'disabled'
                        
                        user_data = {
                            'dn': entry.distinguishedName.value,
                            'distinguishedName': entry.distinguishedName.value,
                            'username': entry.sAMAccountName.value if entry.sAMAccountName else '',
                            'sAMAccountName': entry.sAMAccountName.value if entry.sAMAccountName else '',
                            'displayName': entry.displayName.value if entry.displayName else '',
                            'mail': entry.mail.value if entry.mail else '',
                            'employeeID': entry.employeeID.value if hasattr(entry, 'employeeID') and entry.employeeID else '',
                            'ou': ou_display,
                            'accountStatus': account_status
                        }
                        users.append(user_data)
                        print(f"DEBUG: search_users - added user: {user_data.get('displayName', 'N/A')} ({user_data.get('sAMAccountName', 'N/A')})")
        except LDAPException as e:
            print(f"Error searching users: {e}") # Log error
            return []
        except Exception as e:
            print(f"Unexpected error in search_users: {e}")
            return []
    
    return users

def get_user_details(user_dn, **ad_args):
    try:
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
    except LDAPNoSuchObjectResult as e:
        # User or OU doesn't exist (may have been moved or deleted)
        print(f"User or OU not found: {user_dn} - {e}")
        return None
    except LDAPException as e:
        print(f"LDAP error getting user details for {user_dn}: {e}")
        return None

def create_user(username, password, display_name, mail=None, target_ou=None, 
                given_name=None, surname=None, title=None, department=None, 
                telephone_number=None, user_principal_name=None, **ad_args):
    """
    Create a new Active Directory user with enhanced attributes.
    
    Args:
        username: sAMAccountName (required)
        password: Initial password (required)
        display_name: Full display name (required)
        mail: Email address (optional)
        target_ou: Target OU DN (optional, defaults to base_dn)
        given_name: First name (optional)
        surname: Last name (optional)
        title: Job title (optional)
        department: Department name (optional)
        telephone_number: Phone number (optional)
        user_principal_name: UPN format (optional, will be generated from mail if not provided)
        **ad_args: AD connection parameters
    
    Returns:
        Tuple of (success: bool, message: str, user_dn: str)
    """
    config = get_ad_config()
    
    # Use specified OU or default to base_dn
    if target_ou:
        user_dn = f'CN={display_name or username},{target_ou}'
    else:
        user_dn = f'CN={display_name or username},{ad_args["base_dn"]}'
    
    # Build user attributes
    attrs = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': username,
        'displayName': display_name,
        'name': display_name
    }
    
    # Add optional attributes
    if given_name:
        attrs['givenName'] = given_name
    if surname:
        attrs['sn'] = surname
    if title:
        attrs['title'] = title
    if department:
        attrs['department'] = department
    if telephone_number:
        attrs['telephoneNumber'] = telephone_number
    
    # Handle email and UPN
    if mail and mail.strip():
        attrs['mail'] = mail.strip()
        # Set userPrincipalName if not provided (use email as UPN)
        if not user_principal_name:
            user_principal_name = mail.strip()
    
    # Set userPrincipalName if provided
    if user_principal_name:
        attrs['userPrincipalName'] = user_principal_name.strip()

    with ad_connection(**ad_args) as conn:
        try:
            # Step 1: Create user with all attributes
            result = conn.add(user_dn, attributes=attrs)
            if not result:
                error_msg = f"Failed to create user: {conn.result['description']}"
                return False, error_msg, None
            
            # Step 2: Set password
            if password:
                try:
                    password_result = set_password(user_dn, password, **ad_args)
                    if not password_result[0]:
                        print(f"Warning: Password set failed: {password_result[1]}")
                except Exception as e:
                    print(f"Warning: Password set exception: {str(e)}")
            
            # Step 3: Enable the account
            try:
                enable_result = enable_user(user_dn, **ad_args)
                if not enable_result[0]:
                    print(f"Warning: Account enable failed: {enable_result[1]}")
            except Exception as e:
                print(f"Warning: Account enable exception: {str(e)}")
            
            return True, f'User {username} created successfully.', user_dn
        except Exception as e:
            error_msg = f"Exception during user creation: {str(e)}"
            return False, error_msg, None

def set_user_manager(user_dn, manager_dn, **ad_args):
    """
    Set the manager attribute for a user in AD.
    
    Args:
        user_dn: Distinguished name of the user
        manager_dn: Distinguished name of the manager
        **ad_args: AD connection parameters
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    with ad_connection(**ad_args) as conn:
        try:
            changes = {'manager': [(ldap3.MODIFY_REPLACE, [manager_dn])]}
            result = conn.modify(user_dn, changes)
            if not result:
                return False, f"Failed to set manager: {conn.result['description']}"
            return True, "Manager set successfully."
        except Exception as e:
            return False, f"Exception setting manager: {str(e)}"

def remove_user_manager(user_dn, **ad_args):
    """
    Remove the manager attribute for a user in AD.
    
    Args:
        user_dn: Distinguished name of the user
        **ad_args: AD connection parameters
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    with ad_connection(**ad_args) as conn:
        try:
            changes = {'manager': [(ldap3.MODIFY_DELETE, [])]}
            result = conn.modify(user_dn, changes)
            if not result:
                return False, f"Failed to remove manager: {conn.result['description']}"
            return True, "Manager removed successfully."
        except Exception as e:
            return False, f"Exception removing manager: {str(e)}"

def get_user_manager(user_dn, **ad_args):
    """
    Get the manager DN for a user.
    
    Args:
        user_dn: Distinguished name of the user
        **ad_args: AD connection parameters
    
    Returns:
        Manager DN or None
    """
    with ad_connection(**ad_args) as conn:
        try:
            conn.search(user_dn, '(objectClass=user)', search_scope=ldap3.BASE, attributes=['manager'])
            if conn.entries and hasattr(conn.entries[0], 'manager') and conn.entries[0].manager:
                return conn.entries[0].manager.value
            return None
        except Exception as e:
            print(f"Error getting manager: {e}")
            return None

def update_user_attributes(user_dn, changes, **ad_args):
    with ad_connection(**ad_args) as conn:
        # Filter out None values but allow empty strings for clearing fields
        valid_changes = {}
        for key, value in changes.items():
            if value is not None:  # Allow empty strings to clear fields
                valid_changes[key] = value.strip() if isinstance(value, str) else value
        
        if not valid_changes:
            return True, "No changes to update"
        
        print(f"DEBUG: Updating user {user_dn} with changes: {valid_changes}")
        
        # First, get the current user attributes to see what exists
        if conn.search(user_dn, '(objectClass=user)', search_scope=ldap3.BASE, attributes=list(valid_changes.keys())):
            current_attrs = conn.entries[0]
        else:
            return False, "Could not retrieve current user attributes"
        
        # Create LDAP changes dictionary - only REPLACE operations for valid values
        ldap_changes = {}
        for key, value in valid_changes.items():
            if value == "":  # Empty string - only delete if attribute exists
                if hasattr(current_attrs, key) and current_attrs[key]:
                    ldap_changes[key] = [(ldap3.MODIFY_DELETE, [])]
            else:  # Non-empty value - replace the attribute
                ldap_changes[key] = [(ldap3.MODIFY_REPLACE, [value])]
        
        if not ldap_changes:
            return True, "No changes to update"
        
        print(f"DEBUG: LDAP changes: {ldap_changes}")
        
        try:
            result = conn.modify(user_dn, ldap_changes)
            if not result:
                error_msg = f"Failed to update user: {conn.result['description']}"
                print(f"DEBUG: Update failed: {error_msg}")
                return False, error_msg
            
            print(f"DEBUG: Update successful")
            return True, "User updated successfully."
        except Exception as e:
            error_msg = f"Exception during update: {str(e)}"
            print(f"DEBUG: Update exception: {error_msg}")
            return False, error_msg

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
    """
    Delete a user from Active Directory.
    If deletion fails due to permissions, disable the user instead.
    """
    try:
        with ad_connection(**ad_args) as conn:
            result = conn.delete(user_dn)
            if result:
                return True, 'User deleted successfully.'
            else:
                return False, f'Failed to delete user: {conn.result["description"]}'
    except LDAPInsufficientAccessRightsResult:
        # If deletion fails due to insufficient rights, disable the user instead
        try:
            with ad_connection(**ad_args) as conn:
                # Get current userAccountControl
                conn.search(user_dn, '(objectClass=user)', search_scope=ldap3.BASE, attributes=['userAccountControl'])
                if conn.entries:
                    current_uac = int(conn.entries[0].userAccountControl.value)
                    # Set the disable bit
                    disable_uac = current_uac | 2
                    conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [str(disable_uac)])]})
                    return True, 'User deletion blocked by security policy. User has been disabled instead.'
                else:
                    return False, 'User not found for disable operation.'
        except Exception as e:
            return False, f'Failed to disable user: {str(e)}'
    except Exception as e:
        return False, f'Error deleting user: {str(e)}'

# --- Group Management ---

def get_user_groups(user_dn, **ad_args):
    with ad_connection(**ad_args) as conn:
        if conn.search(user_dn, '(objectclass=user)', attributes=['memberOf']):
            return conn.entries[0].memberOf.value if conn.entries and conn.entries[0].memberOf else []
    return []

@lru_cache(maxsize=1)
def _get_all_groups_cached(groups_ou_key):
    """Internal cached version - not used directly"""
    pass

def get_all_groups(**ad_args):
    """Get all groups with request-level caching"""
    try:
        from flask import g
        if hasattr(g, 'request_cache'):
            cache_key = f"groups:{ad_args.get('base_dn', '')}"
            if cache_key in g.request_cache:
                return g.request_cache[cache_key]
    except (ImportError, RuntimeError):
        pass  # Not in Flask context, skip caching
    
    groups = []
    base_dn = ad_args.get('base_dn')
    groups_ou = ad_args.get('groups_ou', base_dn)
    with ad_connection(**ad_args) as conn:
        conn.search(groups_ou, '(objectClass=group)', attributes=['distinguishedName', 'sAMAccountName', 'cn'])
        for entry in conn.entries:
            name = entry.cn.value if entry.cn else entry.sAMAccountName.value
            if name:
                groups.append(Group(dn=entry.distinguishedName.value, name=name))
    result = sorted(groups, key=lambda g: g.name.lower())
    try:
        from flask import g
        if hasattr(g, 'request_cache'):
            cache_key = f"groups:{ad_args.get('base_dn', '')}"
            g.request_cache[cache_key] = result
    except (ImportError, RuntimeError):
        pass  # Not in Flask context, skip caching
    return result

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
    try:
        with ad_connection(**ad_args) as conn:
            # Simple health check: can we bind and search the root?
            base_dn = ad_args.get('base_dn')
            if conn.search(base_dn, '(objectClass=domain)', attributes=['distinguishedName']):
                return {'status': 'healthy'}
            else:
                return {'status': 'unhealthy'}
    except Exception as e:
        return {'status': 'unhealthy', 'error': str(e)}

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
    """List all OUs in the domain with request-level caching"""
    try:
        from flask import g
        if hasattr(g, 'request_cache'):
            cache_key = f"ous:{ad_args.get('base_dn', '')}"
            if cache_key in g.request_cache:
                return g.request_cache[cache_key]
    except (ImportError, RuntimeError):
        pass  # Not in Flask context, skip caching
    
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
    
    result = sorted(ous, key=lambda x: x['dn'])
    try:
        from flask import g
        if hasattr(g, 'request_cache'):
            cache_key = f"ous:{ad_args.get('base_dn', '')}"
            g.request_cache[cache_key] = result
    except (ImportError, RuntimeError):
        pass  # Not in Flask context, skip caching
    return result

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
    from ldap3.core.exceptions import LDAPInvalidDnError
    with ad_connection(**ad_args) as conn:
        for group_dn in user_groups:
            if not group_dn or '=' not in group_dn:
                continue  # Skip invalid/empty DNs
            try:
                if conn.search(group_dn, '(objectClass=group)', attributes=['groupType']):
                    entry = conn.entries[0]
                    group_type_val = entry.groupType.value if hasattr(entry, 'groupType') and entry.groupType else None
                    group_type_str = group_type_map.get(group_type_val, str(group_type_val) if group_type_val else 'Unknown')
                    type_counts[group_type_str] += 1
            except LDAPInvalidDnError:
                continue  # Skip invalid DNs
            except Exception:
                continue  # Skip any other LDAP errors
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
        conn.search(ad_args['base_dn'], '(objectClass=user)', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName', 'memberOf', 'objectClass'])
        for entry in conn.entries:
            # Only count real users (not computer accounts)
            is_user = False
            is_computer = False
            if hasattr(entry, 'objectClass') and entry.objectClass.value:
                object_classes = entry.objectClass.value
                if isinstance(object_classes, list):
                    is_user = 'user' in object_classes
                    is_computer = 'computer' in object_classes
                else:
                    object_classes_str = str(object_classes).lower()
                    is_user = 'user' in object_classes_str
                    is_computer = 'computer' in object_classes_str
            if not is_user or is_computer:
                continue
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

def update_user_employee_id(user_dn, employee_id, **ad_args):
    """Update a user's employee ID attribute"""
    with ad_connection(**ad_args) as conn:
        try:
            result = conn.modify(user_dn, {'employeeID': [(ldap3.MODIFY_REPLACE, [employee_id])]})
            if result:
                return True, f"Employee ID updated to {employee_id}"
            else:
                return False, f"Failed to update employee ID: {conn.result['description']}"
        except Exception as e:
            return False, f"Error updating employee ID: {str(e)}" 