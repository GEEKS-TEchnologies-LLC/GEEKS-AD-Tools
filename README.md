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

Run the following command on your Ubuntu/Debian server to clone this project, install requirements, and start the app:

```sh
sudo apt update && sudo apt install -y python3 python3-pip git && \
  git clone https://github.com/manayethas/GEEKS-AD-Plus.git && \
  cd GEEKS-AD-Plus && \
  pip3 install -r requirements.txt && \
  python3 app.py --host=0.0.0.0 --port=5000
```

- The app will be available on port 5000 of your server (http://your-server-ip:5000).



