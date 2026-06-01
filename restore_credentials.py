#!/usr/bin/env python3
"""
Interactive script to restore AD/Exchange credentials securely.
No secrets are hardcoded or echoed to stdout.
"""
import sys
import os
import getpass
sys.path.insert(0, os.path.dirname(__file__))

from app.credentials import save_credentials


def main():
    print("=" * 60)
    print("Restore Credentials")
    print("=" * 60)
    print("Enter values to store securely in .credentials.enc")
    print()

    ad_password = getpass.getpass("Enter AD password: ").strip()
    exchange_password = getpass.getpass("Enter Exchange password: ").strip()

    credentials = {}
    if ad_password:
        credentials["ad_password"] = ad_password
    if exchange_password:
        credentials["exchange_password"] = exchange_password

    if not credentials:
        print("No credentials entered. Nothing was changed.")
        return 1

    if save_credentials(credentials):
        print("Credentials restored successfully.")
        print("Stored securely in .credentials.enc")
        return 0

    print("Error restoring credentials")
    return 1


if __name__ == "__main__":
    sys.exit(main())
