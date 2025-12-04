#!/usr/bin/env python3
"""
Interactive script to set up secure credentials
Run this after cloning or to update credentials
"""
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app.credentials import save_credentials, migrate_from_config_files, load_credentials
import getpass

def main():
    print("=" * 60)
    print("GEEKS-AD-Tools Secure Credential Setup")
    print("=" * 60)
    print()
    
    # Try to migrate existing credentials
    print("Checking for existing credentials in config files...")
    if migrate_from_config_files():
        print("✓ Migrated existing credentials from config files")
    else:
        print("No existing credentials found in config files")
    print()
    
    # Check what's already stored
    existing = load_credentials()
    if existing:
        print(f"Found {len(existing)} existing credentials in secure storage")
        print("You can update them below or press Enter to keep existing values")
        print()
    
    credentials = {}
    
    # AD Password
    if 'ad_password' in existing:
        print(f"Current AD password: {'*' * len(existing['ad_password'])}")
    new_ad_password = getpass.getpass("Enter AD password (or press Enter to keep existing): ")
    if new_ad_password:
        credentials['ad_password'] = new_ad_password
    elif 'ad_password' in existing:
        credentials['ad_password'] = existing['ad_password']
    
    # Exchange Password
    if 'exchange_password' in existing:
        print(f"Current Exchange password: {'*' * len(existing['exchange_password'])}")
    new_exchange_password = getpass.getpass("Enter Exchange password (or press Enter to keep existing): ")
    if new_exchange_password:
        credentials['exchange_password'] = new_exchange_password
    elif 'exchange_password' in existing:
        credentials['exchange_password'] = existing['exchange_password']
    
    # AD Bind Password (from config.json)
    if 'ad_bind_password' in existing:
        print(f"Current AD bind password: {'*' * len(existing['ad_bind_password'])}")
    new_bind_password = getpass.getpass("Enter AD bind password (or press Enter to keep existing): ")
    if new_bind_password:
        credentials['ad_bind_password'] = new_bind_password
    elif 'ad_bind_password' in existing:
        credentials['ad_bind_password'] = existing['ad_bind_password']
    
    # Secret Key
    if 'secret_key' in existing:
        print(f"Current secret key: {'*' * len(existing['secret_key'])}")
    new_secret_key = getpass.getpass("Enter Flask secret key (or press Enter to keep existing): ")
    if new_secret_key:
        credentials['secret_key'] = new_secret_key
    elif 'secret_key' in existing:
        credentials['secret_key'] = existing['secret_key']
    
    # Save all credentials
    if credentials:
        if save_credentials(credentials):
            print()
            print("✓ Credentials saved securely!")
            print("✓ Credentials are encrypted and stored in .credentials.enc")
            print("✓ This file is excluded from git")
        else:
            print()
            print("✗ Error saving credentials")
            return 1
    else:
        print()
        print("No credentials to save")
    
    print()
    print("Setup complete!")
    return 0

if __name__ == '__main__':
    sys.exit(main())

