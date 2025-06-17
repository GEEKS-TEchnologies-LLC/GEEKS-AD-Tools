import os
import json
import ldap

CONFIG_PATH = 'app/ad_config.json'

def save_ad_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f)

def load_ad_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def test_ad_connection(server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        conn.unbind_s()
        return True, 'Connection successful.'
    except ldap.LDAPError as e:
        return False, str(e)

def get_admin_groups():
    config = load_ad_config()
    if config and 'admin_groups' in config:
        return config['admin_groups']
    return ['Domain Admins']

def set_admin_groups(groups):
    config = load_ad_config() or {}
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
    ldap_url = f'ldap://{server}:{port}'
    group_dn = f'CN={group_name},{base_dn}'
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
        return False, str(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def add_user_to_group(user_dn, group_name, server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    group_dn = f'CN={group_name},{base_dn}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        mod = [(ldap.MOD_ADD, 'member', [user_dn.encode()])]
        conn.modify_s(group_dn, mod)
        return True, f'User added to group {group_name}.'
    except ldap.LDAPError as e:
        return False, str(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def search_users(query, server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    filter_str = f'(|(sAMAccountName=*{query}*)(displayName=*{query}*)(mail=*{query}*))'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str, ['sAMAccountName', 'displayName', 'mail', 'distinguishedName'])
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

def get_user_details(user_dn, server, port, bind_dn, password):
    ldap_url = f'ldap://{server}:{port}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        result = conn.search_s(user_dn, ldap.SCOPE_BASE)
        if not result:
            return None
        dn, attrs = result[0]
        details = {k: [v.decode() for v in vals] for k, vals in attrs.items()}
        details['dn'] = dn
        return details
    except ldap.LDAPError:
        return None
    finally:
        try:
            conn.unbind_s()
        except:
            pass

def create_user(username, password, display_name, mail, server, port, bind_dn, bind_pw, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    user_dn = f'CN={display_name},{base_dn}'
    attrs = {
        'objectClass': [b'top', b'person', b'organizationalPerson', b'user'],
        'sAMAccountName': [username.encode()],
        'userPrincipalName': [mail.encode()],
        'displayName': [display_name.encode()],
        'mail': [mail.encode()],
        'userPassword': [password.encode()]
    }
    ldif = [(k, v) for k, v in attrs.items()]
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, bind_pw)
        conn.add_s(user_dn, ldif)
        # Enable the user (set userAccountControl)
        mod = [(ldap.MOD_REPLACE, 'userAccountControl', [b'512'])]
        conn.modify_s(user_dn, mod)
        return True, f'User {username} created.'
    except ldap.LDAPError as e:
        return False, str(e)
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
        return False, str(e)
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
        return False, str(e)
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
        return False, str(e)
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
        return False, str(e)
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
        return False, str(e)
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

def remove_user_from_group(user_dn, group_name, server, port, bind_dn, password, base_dn):
    ldap_url = f'ldap://{server}:{port}'
    group_dn = f'CN={group_name},{base_dn}'
    try:
        conn = ldap.initialize(ldap_url)
        conn.simple_bind_s(bind_dn, password)
        mod = [(ldap.MOD_DELETE, 'member', [user_dn.encode()])]
        conn.modify_s(group_dn, mod)
        return True, f'User removed from group {group_name}.'
    except ldap.LDAPError as e:
        return False, str(e)
    finally:
        try:
            conn.unbind_s()
        except:
            pass 