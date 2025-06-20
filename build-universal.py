#!/usr/bin/env python3
"""
GEEKS-AD-Plus Universal Build Script
Works across both dev and stable branches
"""

import subprocess
import sys
import platform
from pathlib import Path
import argparse
import logging
import os
import shutil

# --- Logging Setup ---
log = logging.getLogger('GEEKS-AD-Plus-Build')
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
log.addHandler(handler)

# --- Helper Functions ---

def run_command(command, error_message, capture_output=False, can_fail=False):
    """Runs a shell command and handles success/failure."""
    log.debug(f"Running: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=not can_fail, # check=True will raise CalledProcessError on non-zero exit codes
            text=True,
            capture_output=True
        )
        if result.stdout and capture_output:
            log.debug(f"Output: {result.stdout.strip()}")
        if result.stderr and not can_fail:
             log.debug(f"Stderr: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log.error(f"{error_message}: {e}")
        log.error(f"Error output: {e.stderr.strip()}")
        if not can_fail:
            sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")
        if not can_fail:
            sys.exit(1)

def get_python_command():
    """Detects the python command to use."""
    if shutil.which("python3"):
        return "python3"
    if shutil.which("python"):
        return "python"
    log.error("Could not find a valid Python 3 installation.")
    sys.exit(1)

def get_pip_command():
    return f"{get_python_command()} -m pip"

def get_platform():
    return platform.system()

def get_current_branch():
    try:
        return run_command("git rev-parse --abbrev-ref HEAD", "Failed to get git branch", capture_output=True)
    except Exception:
        return "Unknown"

def get_version():
    try:
        with open(Path('app') / 'version.py') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().replace("'", "").replace('"', '')
    except FileNotFoundError:
        return "0.0.0"

# --- Build Steps ---

def print_header():
    """Prints the build script header."""
    print("==================================================")
    print("GEEKS-AD-Plus Universal Build Script")
    print("==================================================")
    print(f"Python command: {get_python_command()}")
    print(f"Current branch: {get_current_branch()}")
    print(f"Platform: {get_platform()}")
    print("==================================================")

def update_from_git():
    log.info("Updating files from git repository...")
    branch = get_current_branch()
    log.info(f"Current branch: {branch}")
    log.info("Fetching latest changes from remote...")
    run_command("git fetch origin", "Failed to fetch from origin")
    
    status = run_command("git status --porcelain", "Failed to get git status", capture_output=True)
    if status:
        log.warning("Local changes detected. Stashing changes...")
        run_command("git stash", "Failed to stash changes")
    
    log.info(f"Pulling latest changes from {branch}...")
    run_command(f"git pull origin {branch}", "Failed to pull changes")
    
    log.info("Git update completed successfully")

def clean():
    log.info("Cleaning up build artifacts...")
    shutil.rmtree('build', ignore_errors=True)
    shutil.rmtree('dist', ignore_errors=True)
    shutil.rmtree('app/__pycache__', ignore_errors=True)
    shutil.rmtree('GEEKS_AD_Plus.egg-info', ignore_errors=True)
    log.info("Cleanup complete.")

def check_prerequisites():
    log.info("Checking prerequisites...")
    python_command = get_python_command()
    log.info(f"Python version: {run_command(f'{python_command} --version', 'Failed to get python version', True)}")
    run_command(f"{get_pip_command()} --version", "pip is not available", capture_output=True)
    log.info("pip is available")
    run_command(f"{python_command} -m venv --help", "venv module is not available", True)
    log.info("venv module is available")

def create_directories():
    log.info("Creating build directories...")
    dirs = ['build', 'dist', 'app/logs', 'app/static', 'app/templates', 'app/branding', 'bug_reports']
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        log.debug(f"Created directory: {d}")

def install_system_dependencies():
    if get_platform() == 'Linux':
        log.info("Installing system dependencies...")
        package_manager = None
        if shutil.which("apt-get"):
            package_manager = "apt-get"
        elif shutil.which("dnf"):
            package_manager = "dnf"
        
        if not package_manager:
            log.warning("Could not detect 'apt-get' or 'dnf'. Skipping system dependency installation.")
            return

        log.info(f"Using {package_manager} package manager")
        if package_manager == "apt-get":
            run_command("sudo apt-get update", "apt-get update failed")
            run_command("sudo apt-get install -y python3-dev libldap2-dev libsasl2-dev libssl-dev", "Failed to install dev packages")
        elif package_manager == "dnf":
            run_command("sudo dnf check-update", "dnf check-update failed")
            run_command("sudo dnf install -y python3-devel openldap-devel cyrus-sasl-devel openssl-devel", "Failed to install dev packages")

def install_python_dependencies():
    log.info("Installing Python dependencies...")
    run_command(f"{get_pip_command()} install --upgrade pip", "Pip upgrade failed")
    run_command(f"{get_pip_command()} install --upgrade -r requirements.txt", "Failed to install requirements")

def handle_database_migrations():
    log.info("Handling database setup and migrations...")
    python_command = get_python_command()
    # Set the FLASK_APP environment variable for the flask commands
    env_prefix = f"FLASK_APP=app.py "
    flask_command = f"{env_prefix} {python_command} -m flask"

    # Check if the migrations directory exists
    if not os.path.exists('migrations'):
        log.info("Migrations directory not found. Initializing database migrations...")
        run_command(f"{flask_command} db init", "Failed to initialize migrations")
    
    # Generate an initial migration if none exist
    # This is safer than stamping and handles the very first run gracefully
    if not os.listdir('migrations/versions'):
        log.info("No migration versions found. Creating initial migration...")
        run_command(f"{flask_command} db migrate -m 'Initial database setup'", "Failed to create initial migration.")

    log.info("Applying database migrations...")
    run_command(f"{flask_command} db upgrade", "Failed to apply migrations")

def main():
    parser = argparse.ArgumentParser(description="GEEKS-AD-Plus Universal Build Script")
    parser.add_argument('--build', action='store_true', help="Run the full build process (default action).")
    parser.add_argument('--update', action='store_true', help="Pull the latest changes from Git.")
    parser.add_argument('--clean', action='store_true', help="Clean up build artifacts.")
    args = parser.parse_args()

    print_header()

    if args.update:
        update_from_git()
        return
    
    if args.clean:
        clean()
        return

    # Default to build if no other action is specified
    log.info("Starting GEEKS-AD-Plus build process...")
    log.info(f"Build version: {get_version()}")

    check_prerequisites()
    create_directories()
    install_system_dependencies()
    install_python_dependencies()
    handle_database_migrations()

    log.info("Build process completed successfully.")
    print("\n==================================================")
    print("Build successful!")
    print("==================================================")


if __name__ == "__main__":
    main() 