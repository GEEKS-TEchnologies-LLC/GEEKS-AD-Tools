#!/usr/bin/env python3
from app.ad import ad_connection, get_ad_config

config = get_ad_config()
base_dn = config['ad_base_dn']
admin_group_dn = 'CN=Domain Admins,CN=Users,DC=sunray,DC=internal'

print("=== Method 1: Direct members of Domain Admins ===")
with ad_connection(**config) as conn:
    # Find all users who are direct members of Domain Admins
    conn.search(base_dn, f'(&(objectClass=user)(memberOf={admin_group_dn}))', attributes=['sAMAccountName', 'displayName', 'mail'])
    print(f"Direct members ({len(conn.entries)} users):")
    for entry in conn.entries:
        username = entry.sAMAccountName.value if entry.sAMAccountName else ''
        display_name = entry.displayName.value if entry.displayName else ''
        mail = entry.mail.value if entry.mail else ''
        print(f"- {username} | {display_name} | {mail}")

print("\n=== Method 2: All users, then check their groups ===")
with ad_connection(**config) as conn:
    # Get all users and check their group memberships
    conn.search(base_dn, '(objectClass=user)', attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf'])
    domain_admins = []
    for entry in conn.entries:
        if hasattr(entry, 'memberOf') and entry.memberOf:
            groups = entry.memberOf.value
            if any('CN=Domain Admins' in str(g) for g in groups):
                username = entry.sAMAccountName.value if entry.sAMAccountName else ''
                display_name = entry.displayName.value if entry.displayName else ''
                mail = entry.mail.value if entry.mail else ''
                domain_admins.append((username, display_name, mail))
    
    print(f"All Domain Admins found ({len(domain_admins)} users):")
    for username, display_name, mail in sorted(domain_admins):
        print(f"- {username} | {display_name} | {mail}")

print("\n=== Method 3: Check Domain Admins group members directly ===")
with ad_connection(**config) as conn:
    # Get the Domain Admins group and check its member attribute
    conn.search(admin_group_dn, '(objectClass=group)', attributes=['member'])
    if conn.entries and hasattr(conn.entries[0], 'member') and conn.entries[0].member:
        members = conn.entries[0].member.value
        print(f"Group members ({len(members)} entries):")
        for member in members:
            print(f"- {member}")
    else:
        print("Could not retrieve group members directly") 