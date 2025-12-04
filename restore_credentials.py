#!/usr/bin/env python3
"""
Quick script to restore credentials from known values
Run this to restore the system after password removal
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.credentials import save_credentials

# Restore the passwords that were removed
credentials = {
    'ad_password': 'M0r6709!!$',
    'exchange_password': 'M0r6709!!$'
}

if save_credentials(credentials):
    print("✓ Credentials restored successfully!")
    print("✓ AD password: M0r6709!!$")
    print("✓ Exchange password: M0r6709!!$")
    print()
    print("Credentials are now stored securely in .credentials.enc")
    print("This file is excluded from git and encrypted")
else:
    print("✗ Error restoring credentials")
    sys.exit(1)

