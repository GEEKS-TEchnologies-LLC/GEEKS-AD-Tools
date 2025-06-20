# GEEKS-AD-Plus

A comprehensive Linux-based web application for Active Directory password management and user administration. This system provides a secure, self-updating portal that integrates directly with Active Directory for password resets, user management, and administrative tasks. It includes a Windows Credential Provider for seamless lock screen integration.

## Quick Install

### Automated Build & Install (Recommended)

#### Universal Build (Works on all branches)
```bash
# Clone the repository
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus

# Switch to desired branch
git checkout Dev      # For development version
# OR
git checkout Stable   # For stable version

# Run universal build (handles Python detection automatically)
python3 build-universal.py

# Or use the main build script directly
python3 build.py
```

#### Windows
```bash
# Clone the repository
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus

# Switch to desired branch
git checkout Dev      # For development version
# OR
git checkout Stable   # For stable version

# Run automated build
.\build.bat

# Or use Python directly
python build.py
```

#### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus

# Switch to desired branch
git checkout Dev      # For development version
# OR
git checkout Stable   # For stable version

# Make build script executable and run
chmod +x build.sh
./build.sh

# Or use Python directly
python3 build.py
```

#### Using Makefile (Cross-platform)
```bash
# Clone the repository
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus

# Switch to desired branch
git checkout Dev      # For development version
# OR
git checkout Stable   # For stable version

# Full build and setup
make build

# Quick start (install + run)
make quick-start

# Development setup
make dev
```

### Building from Different Branches

The build system automatically detects which branch you're on and provides branch-specific information. You can build from either the `Dev` or `Stable` branch:

#### Development Branch (Latest Features)
```bash
git checkout Dev
python3 build.py
```

#### Stable Branch (Production Ready)
```bash
git checkout Stable
python3 build.py
```

#### Branch-Specific Build Commands
```bash
# Build from current branch (auto-detected)
python3 build-universal.py

# Build with specific options
python3 build.py clean    # Clean build artifacts
python3 build.py test     # Run tests only
python3 build.py package  # Create package only

# Cross-platform build
make build               # Full build
make clean              # Clean artifacts
make test               # Run tests
make package            # Create package
```

### In-Place Updates

The build system includes an update command that allows you to update your local files to the latest version from the git repository:

#### Update Commands
```bash
# Update files from git repository (current branch)
python3 build.py update

# Using Makefile
make update

# Using universal build script
python3 build-universal.py update

# Windows
.\build.bat update

# Linux/macOS
./build.sh update
```

#### Update Process
The update command will:
1. **Fetch** latest changes from the remote repository
2. **Stash** any local changes to prevent conflicts
3. **Pull** the latest changes from your current branch
4. **Restore** any stashed changes (if any existed)

#### Update Examples
```bash
# Update development branch
git checkout Dev
python3 build.py update

# Update stable branch
git checkout Stable
python3 build.py update

# Update and rebuild
python3 build.py update
python3 build.py
```

### Docker Installation
```bash
# Clone the repository
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus

# Switch to desired branch
git checkout Dev      # For development version
# OR
git checkout Stable   # For stable version

# Build and run with Docker Compose
docker-compose up -d

# Or build Docker image manually
docker build -t geeks-ad-plus .
docker run -p 5000:5000 geeks-ad-plus
```

### Legacy Installation Methods

#### Stable Branch (Manual)
```bash
curl -sSL https://raw.githubusercontent.com/manayethas/GEEKS-AD-Plus/stable/install.sh | bash
```

#### Development Branch (Manual)
```bash
curl -sSL https://raw.githubusercontent.com/manayethas/GEEKS-AD-Plus/dev/install.sh | bash
```

#### Manual Installation (No Build System)
```bash
git clone https://github.com/manayethas/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus
pip install -r requirements.txt
python app.py
```

## Build System

### Available Build Commands

#### Full Build Process
```bash
# Complete build (dependencies, database, credential provider)
python build.py

# Windows-specific
build.bat

# Linux/macOS-specific
./build.sh

# Using Makefile
make build
```

#### Individual Build Targets
```bash
# Clean build artifacts
python build.py clean
make clean

# Run tests only
python build.py test
make test

# Create distribution package
python build.py package
make package

# Update files from git repository
python build.py update
make update

# Install dependencies only
make install

# Development environment setup
make dev

# Run the application
make run
```

#### Advanced Build Options
```bash
# Production build (clean + build + test + package)
make production

# CI/CD build (clean + install + test + lint)
make ci

# Code quality checks
make lint
make format

# Security audit
make security-audit

# Performance testing
make perf-test

# Generate documentation
make docs
```

### Build Output

The build system creates:
- **Virtual Environment**: `venv/` directory with isolated dependencies
- **Build Artifacts**: `build/` directory with temporary files
- **Distribution Package**: `dist/GEEKS-AD-Plus-{version}/` with complete application
- **Windows Credential Provider**: Compiled DLL (when MSBuild available)
- **Configuration Files**: Default `config.json` and `.env` files
- **Build Log**: `build.log` with detailed build information

### Platform-Specific Features

#### Windows
- ✅ **Visual Studio Integration**: Automatic MSBuild detection and compilation
- ✅ **Credential Provider Build**: Native Windows DLL generation
- ✅ **PowerShell Scripts**: Deployment and management scripts
- ✅ **Group Policy Templates**: GPO deployment automation

#### Linux/macOS
- ✅ **Cross-platform Python**: Works on all Unix-like systems
- ✅ **Package Management**: Automatic dependency resolution
- ✅ **Container Support**: Docker and Docker Compose integration
- ✅ **CI/CD Pipeline**: GitHub Actions automation

## Features

### Core System
- ✅ **Web-based Password Reset Portal** - Secure interface for users to reset AD passwords
- ✅ **Active Directory Integration** - Direct LDAP connection with AD
- ✅ **Self-Updating System** - Automatic updates from GitHub with `run_forever.py`
- ✅ **Audit Logging** - Comprehensive logging of all actions and events
- ✅ **Bug Reporting System** - Built-in bug report collection with logs and system info
- ✅ **Automated Build System** - Complete build automation with cross-platform support

### Admin Management
- ✅ **Admin Authentication** - Separate admin login with AD group-based permissions
- ✅ **User Management** - Search, create, delete, enable/disable AD users
- ✅ **Group Management** - Configure admin groups and manage AD groups
- ✅ **Password Operations** - Reset passwords, force password changes
- ✅ **Admin Dashboard** - Centralized admin interface with statistics

### Active Directory Features
- ✅ **AD Dashboard** - Real-time statistics and health monitoring
- ✅ **User Statistics** - User counts, OU breakdowns, group memberships
- ✅ **Computer Management** - Computer counts and status
- ✅ **Health Monitoring** - AD connection status and performance metrics
- ✅ **Interactive Charts** - Visual representation of AD data using Chart.js

### Windows Integration
- ✅ **Windows Credential Provider** - C++ component for lock screen integration
- ✅ **Group Policy Deployment** - Automated deployment scripts and GPO templates
- ✅ **Install/Uninstall Scripts** - PowerShell scripts for manual deployment
- ✅ **Custom GPO Generation** - Admin portal generates deployment scripts

### Security & Compliance
- ✅ **Secure Authentication** - Admin and user authentication flows
- ✅ **Audit Trail** - Complete audit logging with export capabilities
- ✅ **Configuration Management** - Secure storage of AD credentials
- ✅ **Privacy Protection** - Sensitive data redaction in bug reports

### Future Features
- ⏳ **Multi-Factor Authentication** - SMS/email verification for password resets
- ⏳ **Password Policy Enforcement** - Custom password complexity requirements
- ⏳ **User Self-Service** - Account unlock and profile management
- ⏳ **Email Notifications** - Password change confirmations and alerts
- ⏳ **API Integration** - REST API for external system integration
- ⏳ **Mobile App** - Native mobile application for password resets
- ⏳ **Advanced Reporting** - Custom report generation and analytics
- ⏳ **Backup & Recovery** - Automated backup of configuration and data
- ⏳ **High Availability** - Load balancing and failover support
- ⏳ **Containerization** - Docker support for easy deployment

## System Requirements

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+), Windows 10+, macOS 10.14+
- **Python**: 3.7 or higher
- **Active Directory**: Windows Server 2012 R2 or higher
- **Network**: Connectivity to AD domain controller
- **Permissions**: Domain user with appropriate AD permissions
- **Build Tools**: Visual Studio Build Tools (Windows, for credential provider)

## Configuration

1. **Initial Setup**: Visit `/setup` after installation
2. **AD Configuration**: Enter domain controller details and credentials
3. **Admin Groups**: Configure which AD groups have admin access
4. **Credential Provider**: Deploy Windows Credential Provider via GPO

## File Structure

```
GEEKS-AD-Plus/
├── app/                    # Main application
│   ├── templates/         # HTML templates
│   ├── static/           # Static assets
│   ├── logs/             # Application logs
│   ├── models.py         # Database models
│   ├── views.py          # Flask routes
│   ├── ad.py            # AD integration
│   ├── audit.py         # Audit logging
│   └── bug_report.py    # Bug reporting system
├── windows-credential-provider/  # Windows Credential Provider
│   ├── credentialprovider.cpp   # Main credential provider code
│   ├── credentialprovider.h     # Header file
│   ├── dllmain.cpp             # DLL entry point
│   ├── dll.def                 # Module definition
│   ├── guid.h                  # GUID definitions
│   ├── install.ps1             # Installation script
│   ├── uninstall.ps1           # Uninstallation script
│   ├── gpo-deploy.ps1          # GPO deployment script
│   ├── GEEKS-CredentialProvider.sln  # Visual Studio solution
│   └── GEEKS-CredentialProvider.vcxproj  # Visual Studio project
├── build.py              # Main build script
├── build.bat             # Windows build script
├── build.sh              # Linux/macOS build script
├── Makefile              # Build automation
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose configuration
├── app.py               # Main application entry point
├── run_forever.py       # Auto-update script
└── requirements.txt     # Python dependencies
```

## Support

- **Documentation**: See inline code comments and templates
- **Bug Reports**: Use the built-in bug reporting system at `/bug-report`
- **Admin Interface**: Access admin features at `/admin/login`
- **Logs**: Check `app/logs/` for application logs
- **Build Logs**: Check `build.log` for build process details

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly using the build system
5. Submit a pull request

## Version History

- **v1.0.0** - Initial release with core password reset functionality
- **v1.1.0** - Added admin management and audit logging
- **v1.2.0** - Added AD dashboard and Windows Credential Provider
- **v1.3.0** - Added bug reporting system and enhanced security
- **v1.4.0** - Added comprehensive automated build system and Docker support

## Quick Reference

### Common Build Commands
```bash
# Full build (recommended for first time)
python3 build.py

# Update and rebuild
python3 build.py update && python3 build.py

# Clean and rebuild
python3 build.py clean && python3 build.py

# Development setup
make dev

# Quick start (install + run)
make quick-start

# Update from git
python3 build.py update
```

### Branch Management
```bash
# Switch to development branch
git checkout Dev
python3 build.py update

# Switch to stable branch  
git checkout Stable
python3 build.py update

# Check current branch
git branch --show-current
```

### Troubleshooting
```bash
# Clean everything and start fresh
python3 build.py clean
rm -rf venv/
python3 build.py

# Check build logs
cat build.log

# Verify installation
python3 build.py test
```



