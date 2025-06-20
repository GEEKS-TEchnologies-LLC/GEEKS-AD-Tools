#!/usr/bin/env python3
"""
GEEKS-AD-Plus Universal Build Script
Works across both dev and stable branches
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import argparse

def print_header():
    """Prints the build script header."""
    print("==================================================")
    print("GEEKS-AD-Plus Universal Build Script")
    print("==================================================")
    print(f"Python command: {get_python_command()}")
    print(f"Current branch: {get_current_branch()}")
    print(f"Platform: {get_platform()}")
    print("==================================================")

def detect_python_command():
    """Detect the correct Python command for the system"""
    if platform.system() == "Windows":
        return "python"
    else:
        # Try python3 first, then python
        try:
            result = subprocess.run(["python3", "--version"], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return "python3"
        except:
            pass
        
        try:
            result = subprocess.run(["python", "--version"], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return "python"
        except:
            pass
        
        return "python3"  # Default fallback

def detect_branch():
    """Detect the current git branch"""
    try:
        result = subprocess.run(["git", "branch", "--show-current"],
                              capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            # Fallback method
            result = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
    except Exception:
        pass
    
    return "unknown"

def main():
    parser = argparse.ArgumentParser(description="GEEKS-AD-Plus Universal Build Script")
    parser.add_argument('action', nargs='?', default='build', choices=['build', 'update', 'clean'], help="Action to perform.")
    args = parser.parse_args()

    print_header()

    if args.action == 'update':
        update_from_git()
        return
    
    if args.action == 'clean':
        clean()
        return

    log.info("Starting GEEKS-AD-Plus build process...")
    log.info(f"Build version: {get_version()}")
    log.info(f"Platform: {get_platform()}")
    log.info(f"Branch: {get_current_branch()}")

    check_prerequisites()
    create_directories()
    install_system_dependencies()
    install_python_dependencies()
    setup_database()

    log.info("Build process completed successfully.")
    print("\n==================================================")
    print("Build successful!")
    print("==================================================")

def upgrade_pip():
    log.info("Upgrading pip...")
    run_command(f"{get_pip_command()} install --upgrade pip", "Pip upgrade failed")

def install_python_dependencies():
    log.info("Installing Python dependencies...")
    python_command = get_python_command()
    run_command(f"{python_command} -m pip install --upgrade pip", "Pip upgrade failed")
    log.info("Installing requirements...")
    run_command(f"{get_pip_command()} install --upgrade -r requirements.txt", "Failed to install requirements")

def setup_database():
    log.info("Setting up database...")
    db_setup_command = f'{get_python_command()} -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"'

def get_python_command():
    """Detects the python command to use."""
    try:
        return detect_python_command()
    except Exception:
        return "python3"  # Default fallback

if __name__ == "__main__":
    main() 