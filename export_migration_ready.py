#!/usr/bin/env python3
"""
Migration Ready Export Script
Exports all migration-ready users grouped by department OU to CSV and XLSX formats.

Migration Ready Criteria:
- User account is enabled
- User has an email address
- User is in primary users OU (not disabled users OU)
- User is not a service account
"""

import sys
import os
import json
import csv
from datetime import datetime
from collections import defaultdict

# Add app directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("Warning: pandas not available, XLSX export will be skipped. Install with: pip install pandas openpyxl")

from app.ad import get_ad_config, search_users, ad_connection


def extract_department_from_ou(dn):
    """Extract department name from OU path."""
    if not dn:
        return "Unknown"
    
    # Parse the DN to find OU components
    parts = dn.split(',')
    ous = []
    
    for part in parts:
        part = part.strip()
        if part.startswith('OU='):
            ou_name = part.replace('OU=', '')
            # Skip generic OUs
            if ou_name.lower() not in ['users', 'disabled users', 'service accounts', 'internal tools']:
                ous.append(ou_name)
    
    if ous:
        # Return the most specific OU (first one)
        return ous[0]
    
    # If no OU found, try to extract from CN path
    for part in parts:
        if part.startswith('CN='):
            cn_name = part.replace('CN=', '')
            if cn_name.lower() not in ['users']:
                return cn_name
    
    return "Root"


def get_migration_ready_users(config):
    """Get all migration-ready users from AD."""
    ad_args = {
        'server': config['ad_server'],
        'port': int(config['ad_port']),
        'bind_user': config['ad_bind_dn'],
        'bind_password': config['ad_password'],
        'base_dn': config['ad_base_dn']
    }
    
    # Search for all enabled users
    print("Searching for enabled users...")
    users = search_users('*', status_filter='enabled', **ad_args)
    
    print(f"Found {len(users)} enabled users")
    
    # Filter for migration-ready criteria
    migration_ready = []
    for user in users:
        # Check if user has email
        email = (user.get('mail') or '').strip()
        if not email:
            continue
        
        # Get user DN to extract department
        dn = user.get('distinguishedName') or user.get('dn') or ''
        department = extract_department_from_ou(dn)
        
        # Get additional user info
        user_data = {
            'Name': user.get('displayName') or user.get('cn') or '',
            'Username': user.get('sAMAccountName') or user.get('username') or '',
            'Email': email,
            'Department': department,
            'OU Path': dn,
            'Title': user.get('title') or '',
            'Department (AD)': user.get('department') or '',
            'Company': user.get('company') or '',
            'Phone': user.get('telephoneNumber') or user.get('phone') or '',
            'Mobile': user.get('mobile') or user.get('mobilePhone') or '',
            'Enabled': 'Yes',
            'Last Logon': user.get('lastLogon') or user.get('lastLogonTimestamp') or 'Never',
        }
        
        migration_ready.append(user_data)
    
    print(f"Found {len(migration_ready)} migration-ready users (with email addresses)")
    return migration_ready


def group_by_department(users):
    """Group users by department OU."""
    grouped = defaultdict(list)
    
    for user in users:
        department = user.get('Department', 'Unknown')
        grouped[department].append(user)
    
    # Sort departments alphabetically
    return dict(sorted(grouped.items()))


def export_to_csv(users_by_dept, filename='migration_ready_by_department.csv'):
    """Export users grouped by department to CSV."""
    print(f"\nExporting to CSV: {filename}")
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Department', 'Name', 'Username', 'Email', 'Title', 
                     'Department (AD)', 'Company', 'Phone', 'Mobile', 'OU Path']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        
        writer.writeheader()
        
        for department, users in sorted(users_by_dept.items()):
            for user in sorted(users, key=lambda x: x.get('Name', '')):
                row = {'Department': department}
                row.update(user)
                writer.writerow(row)
    
    print(f"✅ CSV exported: {filename}")
    return filename


def export_to_xlsx(users_by_dept, filename='migration_ready_by_department.xlsx'):
    """Export users grouped by department to XLSX with separate sheets per department."""
    if not HAS_PANDAS:
        print("⚠️  XLSX export skipped (pandas not available)")
        return None
    
    print(f"\nExporting to XLSX: {filename}")
    
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        # Create summary sheet
        summary_data = []
        for department, users in sorted(users_by_dept.items()):
            summary_data.append({
                'Department': department,
                'User Count': len(users),
                'Users': ', '.join([u.get('Name', '') for u in users[:5]]) + 
                        ('...' if len(users) > 5 else '')
            })
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Create sheet for each department
        for department, users in sorted(users_by_dept.items()):
            # Clean department name for sheet name (Excel has 31 char limit)
            sheet_name = department[:31] if len(department) <= 31 else department[:28] + '...'
            
            df = pd.DataFrame(users)
            # Reorder columns
            column_order = ['Name', 'Username', 'Email', 'Title', 
                          'Department (AD)', 'Company', 'Phone', 'Mobile', 'OU Path']
            existing_columns = [col for col in column_order if col in df.columns]
            df = df[existing_columns]
            df.to_excel(writer, sheet_name=sheet_name, index=False)
    
    print(f"✅ XLSX exported: {filename}")
    return filename


def main():
    """Main function."""
    print("=" * 60)
    print("Migration Ready Export Tool")
    print("=" * 60)
    print()
    
    # Load AD configuration
    config = get_ad_config()
    if not config:
        print("❌ Error: AD not configured. Please configure AD first.")
        print("   Run the setup at: http://localhost:5000/setup")
        sys.exit(1)
    
    print(f"AD Server: {config['ad_server']}")
    print(f"Base DN: {config['ad_base_dn']}")
    print()
    
    # Get migration-ready users
    try:
        users = get_migration_ready_users(config)
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    if not users:
        print("❌ No migration-ready users found.")
        sys.exit(1)
    
    # Group by department
    print("\nGrouping users by department...")
    users_by_dept = group_by_department(users)
    
    print(f"\nFound {len(users_by_dept)} departments:")
    for dept, dept_users in sorted(users_by_dept.items()):
        print(f"  - {dept}: {len(dept_users)} users")
    
    # Generate filenames with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"migration_ready_by_department_{timestamp}.csv"
    xlsx_filename = f"migration_ready_by_department_{timestamp}.xlsx"
    
    # Export to CSV
    export_to_csv(users_by_dept, csv_filename)
    
    # Export to XLSX
    xlsx_file = export_to_xlsx(users_by_dept, xlsx_filename)
    
    print("\n" + "=" * 60)
    print("Export Complete!")
    print("=" * 60)
    print(f"CSV: {csv_filename}")
    if xlsx_file:
        print(f"XLSX: {xlsx_filename}")
    print()


if __name__ == '__main__':
    main()

