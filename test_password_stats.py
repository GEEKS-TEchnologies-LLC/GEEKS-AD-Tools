#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.views import get_password_status_stats
from app.ad import get_ad_config
from datetime import datetime, timezone, timedelta
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
import time

def test_password_stats():
    print("Testing password statistics...")
    
    # First, let's see what we get from AD directly
    config = get_ad_config()
    if not config:
        print("No AD config found")
        return
    
    print("Connecting to AD...")
    server = Server(config['ad_server'], port=int(config['ad_port']), get_info=ALL)
    conn = Connection(server, 
                     user=config['ad_bind_dn'], 
                     password=config['ad_password'], 
                     auto_bind=True)
    
    # Get a sample of entries to see objectClass values
    conn.search(config['ad_base_dn'], 
               '(objectClass=user)', 
               search_scope=SUBTREE,
               attributes=['sAMAccountName', 'objectClass'])
    
    print(f"Found {len(conn.entries)} total entries")
    
    user_count = 0
    computer_count = 0
    other_count = 0
    
    for i, entry in enumerate(conn.entries[:10]):  # Check first 10 entries
        print(f"\nEntry {i+1}:")
        print(f"  sAMAccountName: {entry.sAMAccountName.value if entry.sAMAccountName else 'None'}")
        print(f"  objectClass: {entry.objectClass.value if entry.objectClass else 'None'}")
        
        if hasattr(entry, 'objectClass') and entry.objectClass.value:
            object_classes = entry.objectClass.value
            if isinstance(object_classes, list):
                is_user = 'user' in object_classes
                is_computer = 'computer' in object_classes
            else:
                object_classes_str = str(object_classes).lower()
                is_user = 'user' in object_classes_str
                is_computer = 'computer' in object_classes_str
            
            if is_computer:
                computer_count += 1
                print(f"  -> Computer account")
            elif is_user:
                user_count += 1
                print(f"  -> User account")
            else:
                other_count += 1
                print(f"  -> Other type")
        else:
            other_count += 1
            print(f"  -> No objectClass")
    
    conn.unbind()
    
    print(f"\nSummary of first 10 entries:")
    print(f"  User accounts: {user_count}")
    print(f"  Computer accounts: {computer_count}")
    print(f"  Other: {other_count}")
    
    # Now test the actual function
    print("\n" + "="*50)
    start = time.time()
    stats = get_password_status_stats()
    end = time.time()
    
    print(f"Password stats generated in {end-start:.2f} seconds")
    
    if not stats:
        print("No stats returned")
        return
    
    print(f"Total users: {stats['total']}")
    print(f"Valid: {len(stats['valid'])}")
    print(f"Expiring soon: {len(stats['expiring_soon'])}")
    print(f"Expired: {len(stats['expired'])}")
    print(f"Never expires: {len(stats['never_expires'])}")
    print(f"Unknown: {len(stats['unknown'])}")
    
    print("\nSample usernames (first 5):")
    for category in ['valid', 'expired', 'expiring_soon']:
        usernames = [user['username'] for user in stats[category][:5]]
        print(f"{category}: {usernames}")
    
    # Check for computer accounts (should be none)
    all_usernames = []
    for category in ['valid', 'expired', 'expiring_soon', 'never_expires', 'unknown']:
        all_usernames.extend([user['username'] for user in stats[category]])
    
    computer_accounts = [name for name in all_usernames if name.endswith('$')]
    if computer_accounts:
        print(f"\nWARNING: Found {len(computer_accounts)} computer accounts: {computer_accounts[:10]}")
    else:
        print("\n✓ No computer accounts found - filtering working correctly")

if __name__ == "__main__":
    test_password_stats() 