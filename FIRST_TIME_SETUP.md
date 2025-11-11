# First-Time Setup Guide

This guide will walk you through setting up GEEKS-AD-Plus for the first time. Follow these steps in order to ensure a successful installation.

## Prerequisites

Before you begin, ensure you have:

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+), Windows 10+, or macOS 10.14+
- **Python**: 3.7 or higher (check with `python3 --version`)
- **Active Directory**: Windows Server 2012 R2 or higher
- **Network Access**: Connectivity to your AD domain controller
- **Permissions**: Domain user account with appropriate AD permissions for user management
- **Build Tools** (Windows only): Visual Studio Build Tools (for credential provider)

## Step 1: Clone and Prepare the Repository

### 1.1 Clone the Repository

```bash
# Clone the repository
git clone https://github.com/GEEKS-TEchnologies-LLC/GEEKS-AD-Tools.git
cd GEEKS-AD-Tools

# Switch to your desired branch
git checkout Dev      # For development version (latest features)
# OR
git checkout Stable   # For stable version (production ready)
```

### 1.2 Verify Python Installation

```bash
# Check Python version (must be 3.7 or higher)
python3 --version

# If Python is not installed:
# Ubuntu/Debian:
sudo apt-get update && sudo apt-get install python3 python3-pip

# CentOS/RHEL:
sudo yum install python3 python3-pip

# macOS:
brew install python3
```

## Step 2: Run the Automated Build

The build system will automatically:
- Create a virtual environment
- Install all Python dependencies
- Initialize the database
- Set up configuration files
- Verify the installation

### 2.1 Run the Build Script

**Linux/macOS:**
```bash
# Make the build script executable (if needed)
chmod +x build.sh

# Run the build
./build.sh

# OR use Python directly
python3 build.py
```

**Windows:**
```bash
# Run the Windows build script
.\build.bat

# OR use Python directly
python build.py
```

**Using Makefile (Cross-platform):**
```bash
make build
```

### 2.2 Port Configuration Prompt

During the build process, if `config.json` doesn't exist, you'll be prompted to enter your preferred port:

```
============================================================
Port Configuration
============================================================

Please enter preferred port (or press Enter for default 5000):
```

- **Press Enter** to use the default port 5000
- **Enter a number** (1-65535) to use a custom port
- The selected port will be saved in `config.json` as part of the `portal_url` setting

**Note**: If `config.json` already exists, the build will skip this prompt and use the existing configuration.

### 2.3 Verify Build Success

After the build completes, you should see:
- ✅ Virtual environment created in `venv/`
- ✅ All dependencies installed
- ✅ Database initialized
- ✅ Configuration files created with your selected port

If you encounter errors, see the [Troubleshooting](#troubleshooting) section below.

## Step 3: Initial Configuration

### 3.1 Configuration Files Created Automatically

The build process automatically creates:
- `config.json` - Main application configuration (from `config.example.json`)
- `app/ad_config.json` - Active Directory configuration (needs to be created manually)
- `app/database.db` - SQLite database (created automatically)

## Step 4: Start the Application

### 4.1 Start the Application

**Development Mode:**
```bash
# Activate virtual environment and start
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate      # Windows

python3 app.py
```

**Using Makefile:**
```bash
make start
```

**Production Mode (with auto-updates):**
```bash
python3 run_forever.py
```

### 4.2 Verify Application is Running

The application should start and display:
```
 * Running on http://0.0.0.0:PORT
```

Where `PORT` is the port you selected during build (or 5000 if you used the default).

Open your web browser and navigate to:
- **Local**: http://localhost:PORT
- **Network**: http://YOUR_SERVER_IP:PORT

You should see the welcome page.

**Note**: The port is read from `config.json`. If you need to change it later, edit the `portal_url` field in `config.json` and restart the application.

## Step 5: Web-Based Setup

### 5.1 Access the Welcome Page

When you first access the application, you'll see the welcome page with two main options:
1. **Configure AD** - Set up Active Directory connection
2. **Create Admin** - Create your first administrator account

### 5.2 Setup Order

You can configure AD and create an admin account in either order:

**Option A: Configure AD First (Recommended)**
- Configure AD connection first (no login required)
- Then create admin account
- Log in to access admin features

**Option B: Create Admin First**
- Create admin account first
- Log in as admin
- Configure AD (admin login required if AD is already configured)

**Note**: If AD is already configured, you must be logged in as admin to change the configuration.

### 5.3 Create Admin Account

1. Click **"Create Admin"** or navigate to: http://localhost:5000/admin/register
2. Enter:
   - **Username**: Choose an admin username
   - **Password**: Choose a strong password
3. Click **"Register"**
4. You'll be redirected to the login page

**Note**: Admin registration is only available when no admins exist. After the first admin is created, registration is disabled.

### 5.4 Configure Active Directory

1. Navigate to **"Configure AD"** or go to: http://localhost:5000/setup
   - If AD is already configured, you'll need to log in as admin first
   - If AD is not configured, you can access setup without login
2. Fill in your Active Directory details:

   **Required Fields:**
   - **AD Server**: Your domain controller address (e.g., `dc01.yourdomain.com` or `192.168.1.100`)
   - **Port**: 
     - `389` for standard LDAP
     - `636` for secure LDAPS
   - **Bind DN**: Distinguished name of the service account (e.g., `CN=Administrator,CN=Users,DC=yourdomain,DC=com`)
   - **Password**: Password for the bind DN account
   - **Base DN**: Root of your Active Directory (e.g., `DC=yourdomain,DC=com`)

   **Optional Fields:**
   - **Users OU DN**: Specific OU for users (e.g., `OU=Users,DC=yourdomain,DC=com`)
   - **Groups OU DN**: Specific OU for groups (e.g., `OU=Groups,DC=yourdomain,DC=com`)

4. Click **"Save & Test Connection"**
5. If successful, you'll see a success message and be redirected to the home page
6. If it fails, check:
   - Network connectivity to the AD server
   - Correct credentials
   - Firewall rules (ports 389/636)
   - AD server is accessible

### 5.5 Configure Admin Groups (Optional)

After AD is configured, you can set up AD group-based admin access:

1. Log in as admin
2. Navigate to Settings → Admin Groups
3. Add AD groups that should have admin access (e.g., "Domain Admins")
4. Members of these groups can log in with their AD credentials

## Step 6: Verify Installation

### 6.1 Test Basic Functionality

1. **Login Test**: Log in with your admin account
2. **AD Connection Test**: 
   - Go to Settings → AD Configuration
   - Click "Test Connection"
   - Should show "Connection successful"
3. **User Search Test**:
   - Go to Admin Dashboard → User Management
   - Search for a test user
   - Verify users are displayed correctly

### 6.2 Check Logs

View application logs to ensure everything is working:
```bash
# View recent logs
tail -f app/logs/geeks_ad_plus.log

# Or check build logs
cat build.log
```

## Step 7: Additional Configuration (Optional)

### 7.1 Organization-Specific OU Configuration

If your organization uses specific OUs, edit `app/ad_config.json`:

```json
{
  "organization_ous": {
    "primary_users_ou": "OU=Users,OU=Company",
    "disabled_users_ou": "OU=Disabled Users",
    "service_accounts_ou": "OU=Service Accounts",
    "internal_tools_ou": "OU=Internal Tools",
    "primary_users_label": "Company Users"
  }
}
```

See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) for detailed OU configuration options.

### 7.2 Branding Customization

1. Copy `app/branding_config.example.json` to `app/branding_config.json`
2. Customize:
   - Company name
   - Primary color
   - Logo URL
   - Theme (dark/light/auto)

### 7.3 Exchange Server Integration (Optional)

If you have Exchange Server 2019:

1. Log in as admin
2. Navigate to Settings → Exchange Configuration
3. Enter Exchange server details:
   - Exchange Server FQDN
   - PowerShell remoting credentials
   - Test the connection

## Troubleshooting

### Build Issues

**Problem**: `python-ldap` installation fails
```bash
# Install system dependencies first
sudo apt-get install python3-dev libldap2-dev libsasl2-dev libssl-dev  # Ubuntu/Debian
sudo yum install python3-devel openldap-devel  # CentOS/RHEL

# Then retry build
python3 build.py
```

**Problem**: Virtual environment not found
```bash
# Recreate virtual environment
rm -rf venv/
python3 build.py
```

**Problem**: Permission denied errors
```bash
# Ensure you have write permissions
chmod -R 755 .
```

### Application Startup Issues

**Problem**: Port 5000 already in use
```bash
# Find what's using port 5000
lsof -i :5000  # Linux/macOS
netstat -ano | findstr :5000  # Windows

# Kill the process or change port in app.py
```

**Problem**: Database errors
```bash
# Reinitialize database
python3 init_db.py

# Or delete and recreate
rm app/database.db
python3 init_db.py
```

### AD Connection Issues

**Problem**: "Connection failed" error
- Verify AD server address is correct
- Check network connectivity: `ping YOUR_AD_SERVER`
- Verify port is open: `telnet YOUR_AD_SERVER 389`
- Check firewall rules
- Verify bind DN format is correct
- Test credentials manually

**Problem**: "Invalid credentials" error
- Double-check bind DN format
- Verify password is correct
- Ensure account is not locked or disabled
- Check account has necessary permissions

**Problem**: Users not showing up
- Verify Base DN is correct
- Check Users OU DN if specified
- Ensure bind account has read permissions
- Check AD filters in configuration

### Configuration Issues

**Problem**: Config file not found
```bash
# Ensure config.json exists
ls -la config.json

# If missing, copy from example
cp config.example.json config.json
```

**Problem**: Changes not taking effect
- Restart the application
- Clear browser cache
- Check file permissions on config files

## Quick Reference

### Essential Commands

```bash
# Build the system
python3 build.py

# Start application (development)
source venv/bin/activate
python3 app.py

# Start application (production with auto-updates)
python3 run_forever.py

# Initialize database
python3 init_db.py

# Check application status
curl http://localhost:5000

# View logs
tail -f app/logs/geeks_ad_plus.log
```

### Important URLs

- **Home/Welcome**: http://localhost:5000
- **Setup**: http://localhost:5000/setup
- **Admin Login**: http://localhost:5000/admin/login
- **Unified Login**: http://localhost:5000/login
- **Admin Dashboard**: http://localhost:5000/admin/dashboard (after login)

### Configuration Files

- `config.json` - Main application configuration
- `app/ad_config.json` - Active Directory configuration
- `app/branding_config.json` - Branding customization
- `app/exchange_config.json` - Exchange Server configuration (if used)

## Next Steps

After successful setup:

1. **Create additional admin accounts** if needed
2. **Configure AD admin groups** for group-based access
3. **Set up security questions** for password reset functionality
4. **Review audit logging** settings
5. **Configure Exchange integration** (if applicable)
6. **Set up systemd service** for production (see `geeks-ad-plus.service`)
7. **Configure firewall rules** to allow access to port 5000
8. **Set up SSL/TLS** for production use

## Setup Verification

After completing the setup, use the **[SETUP_CHECKLIST.md](SETUP_CHECKLIST.md)** to verify that everything is working correctly.

The checklist covers:
- Build process verification
- Configuration file checks
- Application startup tests
- Web-based setup verification
- Functionality tests
- Common issues and solutions

## Getting Help

- **Documentation**: 
  - [README.md](README.md) - Main documentation
  - [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) - Advanced configuration
  - [SETUP_CHECKLIST.md](SETUP_CHECKLIST.md) - Setup verification
- **Bug Reports**: Use the built-in bug reporting system at `/bug-report`
- **Logs**: Check `app/logs/` for detailed error messages
- **Support**: Email [store@geeks-tech.biz](mailto:store@geeks-tech.biz)

## Security Notes

- **Never commit `config.json`** to version control (it's gitignored)
- **Use strong passwords** for admin accounts
- **Restrict network access** to the application in production
- **Use LDAPS (port 636)** instead of LDAP (port 389) when possible
- **Regularly update** the application using `python3 build.py update`
- **Backup configuration files** before making changes

---

**Congratulations!** You've successfully set up GEEKS-AD-Plus. The system is now ready for use.

