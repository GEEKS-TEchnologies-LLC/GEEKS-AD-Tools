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