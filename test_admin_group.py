#!/usr/bin/env python3
from app.ad import ad_connection, get_ad_config

config = get_ad_config()
username = 'Administrator'
base_dn = config['ad_base_dn']

with ad_connection(**config) as conn:
    conn.search(base_dn, f'(sAMAccountName={username})', attributes=['memberOf'])
    entry = conn.entries[0] if conn.entries else None
    if entry and entry.memberOf:
        groups = entry.memberOf.value
        print('Groups for', username)
        for g in groups:
            print(' -', g)
        print('\nIs Domain Admins present?')
        print(any('CN=Domain Admins' in g for g in groups))
    else:
        print('No groups found for', username) 