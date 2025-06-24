#!/usr/bin/env python3
from app.ad import ad_connection, get_ad_config

config = get_ad_config()
base_dn = config['ad_base_dn']
admin_group_dn = 'CN=Domain Admins,CN=Users,DC=sunray,DC=internal'

with ad_connection(**config) as conn:
    # Find all users who are direct members of Domain Admins
    conn.search(base_dn, f'(&(objectClass=user)(memberOf={admin_group_dn}))', attributes=['sAMAccountName', 'displayName', 'mail'])
    print(f"Users in Domain Admins:")
    for entry in conn.entries:
        username = entry.sAMAccountName.value if entry.sAMAccountName else ''
        display_name = entry.displayName.value if entry.displayName else ''
        mail = entry.mail.value if entry.mail else ''
        print(f"- {username} | {display_name} | {mail}")
    if not conn.entries:
        print("No users found in Domain Admins.") 