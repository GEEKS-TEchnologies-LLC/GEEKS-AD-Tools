#!/usr/bin/env python3
"""
Database initialization script for GEEKS-AD-Plus
This script creates the database tables and handles any database issues.
"""

import os
import sys
from app import create_app, db
from app.models import Admin, AuditLog

def init_database():
    """Initialize the database with tables and default admin if needed"""
    app = create_app()
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Check if admin exists
            admin_count = Admin.query.count()
            if admin_count == 0:
                print("ℹ️  No admin user found. You can create one through the web interface.")
            else:
                print(f"✅ Found {admin_count} admin user(s)")
                
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            print("This might be due to:")
            print("  - Database file is read-only")
            print("  - Insufficient permissions")
            print("  - Database is locked by another process")
            print("\nThe application will continue without database functionality.")
            return False
    
    return True

if __name__ == "__main__":
    print("🔧 Initializing GEEKS-AD-Plus Database...")
    success = init_database()
    if success:
        print("✅ Database initialization completed successfully!")
    else:
        print("⚠️  Database initialization completed with warnings.")
        print("The application will work but audit logging may be disabled.") 