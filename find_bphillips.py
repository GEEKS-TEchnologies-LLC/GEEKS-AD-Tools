#!/usr/bin/env python3
from app.ad import ad_connection, get_ad_config

config = get_ad_config()
base_dn = config['ad_base_dn']

print("=== Searching for bphillips user (all attributes) ===")
with ad_connection(**config) as conn:
    # Search for bphillips user
    conn.search(base_dn, '(sAMAccountName=bphillips)', attributes=['*'])
    
    if conn.entries:
        entry = conn.entries[0]
        print(entry)
        print("\nRaw entry attributes:")
        for attr in entry.entry_attributes:
            print(f"{attr}: {getattr(entry, attr).value}")
    else:
        print("User 'bphillips' not found in AD")

print("\n=== Alternative search for bphillips (case insensitive) ===")
with ad_connection(**config) as conn:
    # Search for any user containing 'bphillips' in their name
    conn.search(base_dn, '(|(sAMAccountName=*bphillips*)(displayName=*bphillips*)(cn=*bphillips*))', attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf'])
    
    if conn.entries:
        print(f"Found {len(conn.entries)} users matching 'bphillips':")
        for entry in conn.entries:
            username = entry.sAMAccountName.value if entry.sAMAccountName else ''
            display_name = entry.displayName.value if entry.displayName else ''
            mail = entry.mail.value if entry.mail else ''
            print(f"- {username} | {display_name} | {mail}")
    else:
        print("No users found matching 'bphillips'") 