#!/bin/bash

# GEEKS-AD-Plus Linux/macOS Build Script
# This script automates the build process on Unix-like systems

set -e

echo "========================================"
echo "GEEKS-AD-Plus Linux/macOS Build Script"
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed or not in PATH"
    echo "Please install Python 3.7+ and try again"
    exit 1
fi

print_success "Python found:"
python3 --version
echo

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_error "Python 3.7+ required, found $python_version"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not available"
    echo "Please ensure pip3 is installed with Python"
    exit 1
fi

print_success "pip3 found:"
pip3 --version
echo

# Check if virtual environment tools are available
if ! python3 -c "import venv" &> /dev/null; then
    print_warning "venv module not found - installing python3-venv"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3-venv
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-venv
    elif command -v brew &> /dev/null; then
        brew install python3
    else
        print_warning "Could not install python3-venv automatically"
        print_warning "Please install it manually for your distribution"
    fi
fi

# Check if we're on Windows (WSL)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    print_warning "Detected Windows environment"
    print_warning "Credential provider build will be skipped (not supported in WSL)"
    echo
fi

# Make the script executable
chmod +x build.py

# Run the Python build script
print_status "Starting build process..."
echo

python3 build.py "$@"

if [ $? -eq 0 ]; then
    echo
    print_success "Build completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Configure your Active Directory settings in config.json"
    echo "2. Set up your environment variables in .env"
    echo "3. Run the application: python3 app.py"
    echo
else
    echo
    print_error "Build failed! Check the build.log file for details"
    exit 1
fi 