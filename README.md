# GEEKS-AD-Plus

> **Note:** This project is starting from zero and will be built step by step. Planned features include:
> - Enhanced auditing and logging
> - Integration with a local email server
> - Custom branding (logo, colors, organization info)
> - License key system (to be added after core features)

# Local Active Directory Password Reset Portal with Windows Credential Provider Integration

## System Overview
A Linux-based web application that interfaces with on-premises Active Directory to allow users to reset their domain passwords, with additional Windows Credential Provider integration for lock screen password resets.

## Core Components

1. Backend Server (Linux)
   - Python/Flask web server
   - Direct LDAP/LDAPS connectivity to local AD
   - SSL/TLS encryption for internal network security
   - Local logging and monitoring
   - Rate limiting to prevent abuse
   - REST API endpoints for Credential Provider

2. Local Active Directory Integration
   - Direct LDAP authentication to domain controller
   - Local AD password policy enforcement
   - Account lockout protection
   - Secure password transmission within internal network
   - Local audit logging

3. Web Interface
   - Internal network access only
   - User verification methods:
     * Security questions
     * Internal email verification
   - Password strength meter
   - Domain policy compliance checking

4. Windows Credential Provider Integration
   - Custom Windows Credential Provider (C++)
   - "Forgot Password" tile on lock screen
   - Seamless integration with Windows 10/11
   - Direct communication with backend API
   - Group Policy deployment options

## Security Considerations
- Internal HTTPS enforcement
- Input validation
- Brute force protection
- Session management
- Local audit trails
- Network segmentation (VLAN considerations)
- Encrypted communication within internal network
- Credential Provider signing requirements

## Implementation Steps
1. Set up Linux server on internal network
2. Create restricted AD service account
3. Configure direct LDAP connectivity to DC
4. Implement web interface (internal access only)
5. Add security measures
6. Develop Windows Credential Provider
   - Create Visual Studio C++ project
   - Implement ICredentialProvider interface
   - Add "Forgot Password" tile
   - Create API communication layer
   - Code signing and testing
7. Testing in isolated VLAN
8. Internal deployment
9. Group Policy deployment of Credential Provider

## Required Technologies
- Linux Server (RHEL/CentOS/Ubuntu)
- Flask + python-ldap
- Internal Web Server (Nginx/Apache)
- Internal SSL Certificates
- Local Database for audit logs
- Direct network access to Domain Controller
- Firewall rules for DC communication
- Visual Studio for Credential Provider development
- Windows SDK
- Code signing certificate for Credential Provider

## Network Requirements
- Linux server must be on same network or have routing to DC
- Proper DNS resolution for domain
- Appropriate firewall rules for LDAP/LDAPS (389/636)
- Internal certificate authority or self-signed certs
- Workstation network access to backend API

## Credential Provider Development Notes
1. Register custom credential provider:
   ```powershell
   # Registry location
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
   ```

2. Key development files:
   - credentialprovider.h
   - credentialprovider.cpp
   - guid.h
   - helpers.h
   - dll.def

3. Required interfaces:
   - ICredentialProvider
   - ICredentialProviderCredential
   - ICredentialProviderCredentialEvents

Would you like to proceed with implementing either:
1. The local AD integration components
2. The Windows Credential Provider development
3. The backend API endpoints for the Credential Provider

## Quick Install (Ubuntu/Debian)

### Stable Branch (Recommended for Production)
Run the following command on your Ubuntu/Debian server to clone this project, install requirements, and start the app with auto-update from the stable branch:

```sh
sudo apt update && sudo apt install -y python3 python3-pip git && \
  git clone https://github.com/manayethas/GEEKS-AD-Plus.git && \
  cd GEEKS-AD-Plus && \
  git checkout stable && \
  pip3 install -r requirements.txt && \
  python3 run_forever.py
```

### Development Branch (Latest Features)
For the latest development features and updates, use the dev branch:

```sh
sudo apt update && sudo apt install -y python3 python3-pip git && \
  git clone https://github.com/manayethas/GEEKS-AD-Plus.git && \
  cd GEEKS-AD-Plus && \
  git checkout dev && \
  pip3 install -r requirements.txt && \
  python3 run_forever.py
```

- The app will be available on port 5000 of your server (http://your-server-ip:5000).
- The dev branch includes the latest features but may be less stable than the stable branch.

## Versioning & Self-Updating

This app uses a version file (`app/version.py`) and a wrapper script (`run_forever.py`) to keep itself up to date with the latest release from GitHub.

- The version is tracked in `app/version.py`.
- The `run_forever.py` script runs the app, checks for updates every 10 minutes, and updates/restarts if a new version is found on the dev branch.
- The app will only stop if the system is powered off or an update is applied.

### To run with auto-update:

```sh
python3 run_forever.py
```

### Switching Between Branches

To switch from dev to stable branch (or vice versa):

```sh
git checkout stable  # or 'dev' for development branch
pip3 install -r requirements.txt
python3 run_forever.py
```

The auto-update will then check for updates from the selected branch.

## Features

- **Password Reset Portal**: Web-based interface for users to reset their AD passwords
- **Admin Management**: Complete admin interface for user and group management
- **Active Directory Integration**: Direct LDAP integration with AD
- **Audit Logging**: Comprehensive logging of all actions
- **Group Policy Deployment**: Automated deployment of Windows Credential Provider
- **Self-Updating**: Automatic updates from GitHub
- **Bug Reporting**: Built-in bug report system with log collection
- **AD Dashboard**: Real-time AD statistics and health monitoring

### Bug Reporting

The system includes a comprehensive bug reporting feature:

- **User Bug Reports**: Users can submit bug reports at `/bug-report`
- **Log Collection**: Automatically collects recent application logs and audit logs
- **System Information**: Gathers platform, version, and configuration details
- **Admin Interface**: Admins can view and download bug reports at `/admin/bug-reports`
- **Privacy**: Sensitive information like passwords is automatically redacted

Bug reports are stored locally in the `bug_reports/` directory and are excluded from version control.



