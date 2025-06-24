#!/usr/bin/env python3
from app.ad import is_user_in_admin_group, get_ad_config

config = get_ad_config()
username = 'bphillips'

print(f"Testing if {username} is recognized as admin...")
is_admin = is_user_in_admin_group(
    username,
    server=config['ad_server'],
    port=config['ad_port'],
    bind_user=config['ad_bind_dn'],
    bind_password=config['ad_password'],
    base_dn=config['ad_base_dn']
)

print(f"Result: {is_admin}")
if is_admin:
    print("✅ bphillips is now recognized as an admin!")
else:
    print("❌ bphillips is still not recognized as an admin") 