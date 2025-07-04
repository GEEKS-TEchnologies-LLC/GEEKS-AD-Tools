# GEEKS-AD-Plus

A comprehensive Linux-based web application for Active Directory password management and user administration. This system provides a secure, self-updating portal that integrates directly with Active Directory for password resets, user management, and administrative tasks. It includes a Windows Credential Provider for seamless lock screen integration.

## Recent Updates (2025-06-27)

- **License Key Workflow & Config Safety:**
  - The system now requires valid license keys for activation. On first run, if `config.json` is missing, it is auto-created from `config.example.json`.
  - License keys are never pushed to GitHub. `config.json` is gitignored; only `config.example.json` is tracked.
  - The app will prompt for license keys via the web UI if missing or invalid, and will not start until a valid key is provided.
  - Add-on license keys now use new context variable names: `plus_license_key` (email control add-on) and `reporting_license_key` (password reset add-on).
- **Systemd Service Reliability:**
  - The app can now be reliably run as a systemd service using the virtual environment's Python.
  - Troubleshooting steps for systemd/venv issues are included at the end of this README.
- **UI/UX Improvements:**
  - High-contrast, modernized form fields and dropdowns for all admin pages.
  - Custom, searchable dropdowns for user and task type assignment.
  - Consistent dark theme and improved accessibility across the dashboard.
- **Modal and Table Fixes:**
  - Modal popups for drilldowns now have fixed headers, sticky table headers, and improved readability.
  - Table header colors and modal overlays are now high-contrast and visually consistent.
- **Audit and Log Reporting:**
  - Quick Audit Results and Recent Log Reports panes are more readable and always show the 10 most recent logs if none in the last 24h.
  - Recent Log Reports now show a table of audit events instead of raw log lines.
- **General Debugging and Robustness:**
  - Debug output added to backend logic for easier troubleshooting.
  - All changes made with error handling and user experience in mind.
- **How to View Admin Users:**
  - Use the admin dashboard's "User Drilldown" or "User Status" features and select "Admin Users" to see who has admin rights.
  - Or visit `/admin/drilldown/users?type=Admin Users` for a JSON list.

## Quick Install

### Automated Build & Install (Recommended)

#### Universal Build (Works on all branches)
```bash
# Clone the repository
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

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
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

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
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

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
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

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
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

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
curl -sSL https://raw.githubusercontent.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools/stable/install.sh | bash
```

#### Development Branch (Manual)
```bash
curl -sSL https://raw.githubusercontent.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools/dev/install.sh | bash
```

#### Manual Installation (No Build System)
```bash
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools
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
python3 build.py update

# Install system dependencies only
python3 build.py system-deps

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

### Authentication & Security
- ✅ **Unified Login System** - Single login page that automatically detects admin/user roles
- ✅ **Multiple Security Questions** - Support for 3 security questions per user with cycling
- ✅ **Password Policy Integration** - Real-time AD password policy enforcement
- ✅ **Password Status Display** - Show password expiry, last set date, and policy info
- ✅ **Secure Authentication** - Admin and user authentication flows with session management
- ✅ **View Switching** - Admins can switch between admin and user views seamlessly

### Admin Management
- ✅ **Admin Authentication** - Separate admin login with AD group-based permissions
- ✅ **User Management** - Search, create, delete, enable/disable AD users
- ✅ **Group Management** - Configure admin groups and manage AD groups
- ✅ **Password Operations** - Reset passwords, force password changes
- ✅ **Admin Dashboard** - Centralized admin interface with statistics
- ✅ **User Details View** - Comprehensive user information including password status
- ✅ **Password Info Display** - Show password expiry, policy, and status in user details

### Active Directory Features
- ✅ **AD Dashboard** - Real-time statistics and health monitoring
- ✅ **User Statistics** - User counts, OU breakdowns, group memberships
- ✅ **Computer Management** - Computer counts and status
- ✅ **Health Monitoring** - AD connection status and performance metrics
- ✅ **Interactive Charts** - Visual representation of AD data using Chart.js
- ✅ **Password Policy Display** - Show domain password policies and user compliance
- ✅ **Password Expiry Tracking** - Real-time password expiry calculations

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
- ✅ **Security Question Management** - Secure storage and validation of security questions

### User Experience
- ✅ **Modern UI/UX** - Glassmorphism design with responsive layout
- ✅ **Unified Interface** - Single login page with role-based view switching
- ✅ **Password Status Indicators** - Visual indicators for password expiry and status
- ✅ **Security Question Setup** - User-friendly security question configuration
- ✅ **Profile Management** - User profile pages with password and account information

### Future Features
- ⏳ **Multi-Factor Authentication** - SMS/email verification for password resets
- ⏳ **Advanced Password Policies** - Custom password complexity requirements
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

### License and Application Configuration
- The file `config.json` contains all application and license settings.
- **`config.json` is ignored by git and will never be pushed to GitHub.**
- A template file, `config.example.json`, is provided and tracked in the repository.
- On first run, if `config.json` does not exist, it will be created automatically from `config.example.json`.
- **You must enter your license keys in `config.json` before the application will run.**
- If you start the app without valid license keys, you will be prompted via the web UI to enter them before proceeding.
- **To purchase a license key, email [store@geeks-tech.biz](mailto:store@geeks-tech.biz).**
- *A website for purchasing license keys will be available soon.*
- The required fields are:
  - `base_license_key`: Your main GEEKS-AD-Plus license key
  - `plus_license_key`: (Optional) Add-on key for email control features
  - `reporting_license_key`: (Optional) Add-on key for password reset features

#### Example:
```json
{
  "ad_server": "localhost",
  "ad_port": 389,
  "ad_base_dn": "DC=example,DC=com",
  "ad_bind_dn": "CN=Administrator,DC=example,DC=com",
  "ad_bind_password": "",
  "admin_groups": ["Domain Admins"],
  "debug": false,
  "secret_key": "",
  "portal_url": "http://localhost:5000",
  "base_license_key": "",
  "plus_license_key": "",
  "reporting_license_key": ""
}
```

- If you update from a previous version, the system will automatically add any missing license key fields to your `config.json`.
- If you clone the repository, copy `config.example.json` to `config.json` and fill in your keys, or start the app and enter them via the web UI when prompted.

### Active Directory Setup
1. Copy `app/ad_config.example.json` to `app/ad_config.json`
2. Fill in your real AD credentials:
   - `ad_server`: Your AD server address
   - `ad_user`: Admin username (usually admin@domain.com)
   - `ad_password`: Admin password
   - `ad_base_dn`: Your domain's base DN (e.g., DC=yourdomain,DC=com)

### Branding Customization
1. Copy `app/branding_config.example.json` to `app/branding_config.json`
2. Customize your branding:
   - `company_name`: Your company name
   - `primary_color`: Primary brand color (hex code)
   - `logo_url`: Path to your logo file
   - `theme`: UI theme (dark/light/auto)

**Note:** These config files are ignored by git and will never be pushed to GitHub for security.

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
- **v1.5.0** - Added unified login system, multiple security questions, and password info display
- **v1.5.1** - Enhanced user experience with view switching and improved password status tracking

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

# Install system dependencies manually
python3 build.py system-deps

# If python-ldap fails to install
sudo apt-get install python3-dev libldap2-dev libsasl2-dev libssl-dev
source venv/bin/activate
pip install python-ldap
```

## Starting the System

After a successful build, you can start the GEEKS-AD-Plus system in several ways:

### Quick Start (Development)
```bash
# Activate virtual environment and start
source venv/bin/activate
python3 app.py

# Or use the Makefile
make run
```

### Production Start (Auto-updating)
```bash
# Start with auto-update functionality
python3 run_forever.py

# This will:
# - Start the web application on http://localhost:5000
# - Check for updates every 10 minutes
# - Automatically restart when updates are found
```

### Manual Start Options
```bash
# Basic start (development mode) - binds to 0.0.0.0:5000
python3 app.py

# Start with specific host/port
python3 app.py --host=0.0.0.0 --port=5000

# Start with debug mode
python3 app.py --debug

# Start using the virtual environment
venv/bin/python app.py
```

### Accessing the System
Once started, you can access the system at:
- **Local Access**: http://localhost:5000
- **Network Access**: http://YOUR_SERVER_IP:5000
- **Unified Login**: http://YOUR_SERVER_IP:5000/login
- **Admin Login**: http://YOUR_SERVER_IP:5000/admin/login
- **Setup Page**: http://YOUR_SERVER_IP:5000/setup

**Note**: The application binds to `0.0.0.0:5000` by default, making it accessible from any network interface.

### First-Time Setup
1. **Start the system** using one of the methods above
2. **Access the setup page** at http://localhost:5000/setup
3. **Configure Active Directory** settings
4. **Create admin account** or configure AD admin groups
5. **Test the connection** to your AD server

### System Management
```bash
# Stop the application
# Press Ctrl+C in the terminal where it's running

# Restart the application
python3 app.py

# Check if the application is running
curl http://localhost:5000
# or
curl http://YOUR_SERVER_IP:5000

# View application logs
tail -f app/logs/app.log

# Check what IP the server is bound to
netstat -tlnp | grep :5000

# Show network access information
python3 get-ip.py
# or
make network-info
```

## Dashboard & UI (2025)

- **Modern Admin Dashboard**: Black/gold Geeks Technologies branding, responsive layout
- **Unified Login Interface**: Single login page with automatic role detection
- **View Switching**: Admins can switch between admin and user views seamlessly
- **Collapsible Sidebar**: Left-justified icons/text when open, centered icons when collapsed
- **Top Bar**: Always-visible logo, gold gradient text, AD health status light (right side), user dropdown (profile/logout)
- **Stat Cards**: Total Users, Computers, Groups, OUs
- **Interactive Charts**: User Status, Server OS, Client OS, User Types (with drilldown via Chart.js)
- **Recent Log Reports**: Last 10 log lines in a dashboard card
- **Quick Audit Results**: Audit stats (total, success, failure, top actions) in a dashboard card
- **Password Status Display**: Visual indicators for password expiry and policy compliance
- **Security Question Management**: User-friendly setup and management of security questions
- **Settings Page**: For admin/config and branding (planned)
- **Fully Responsive**: Bootstrap grid, mobile-friendly

## Security & Sanitization for Open Source

- **No secrets or credentials**: All `.env`, AD config, logs, bug reports, and instance data are deleted and ignored by `.gitignore`.
- **No license keys in git**: `config.json` is always gitignored. Only `config.example.json` (with empty keys) is tracked. Never push active license keys to GitHub.
- **Safe for GitHub**: You can now push this repo publicly without leaking sensitive data.
- **How to keep it clean**: All sensitive runtime files are excluded by default. If you add new secrets/configs, add them to `.gitignore`.

## License Activation & Trial Setup

### Product ID
- The product ID for this software **must always be** `GEEKS-AD-PLUS`.
- Do not change this value in `config.json`.

### config.json Example (No Identifying Info)
```
{
  "debug": false,
  "secret_key": "",
  "portal_url": "http://localhost:5000",
  "license_key": "",
  "product_id": "GEEKS-AD-PLUS",
  "base_license_key": "",
  "plus_license_key": "",
  "reporting_license_key": "",
  "company_name": "YOUR_COMPANY_NAME",
  "contact_name": "YOUR_CONTACT_NAME",
  "email": "your@email.com",
  "phone": ""
}
```
- **Do not commit real company, contact, or email info to version control.**
- The app will prompt for this info on first run if missing.

### Trial Activation Flow
1. On first run, the app will prompt for company, contact, and email info if not present in `config.json`.
2. When you request a trial, the app will send this info to the license server at `https://license.geeks-tech.win/api/activate-trial` with the correct product ID.
3. If successful, a trial license key will be returned and saved in `config.json`.
4. The app will then validate the trial key with the license server. If valid, you will be redirected to AD setup.

**Note:**
- All license and trial validation is performed against the license server using the product ID `GEEKS-AD-PLUS`.
- If you need to reset the trial, remove the `trial_license_key` and `trial_start_date` fields from `config.json` and restart the app.

---



