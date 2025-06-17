# GEEKS-AD-Plus

A comprehensive Linux-based web application for Active Directory password management and user administration. This system provides a secure, self-updating portal that integrates directly with Active Directory for password resets, user management, and administrative tasks. It includes a Windows Credential Provider for seamless lock screen integration.

## Quick Install

### Stable Branch (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/GEEKS-AD-Plus/stable/install.sh | bash
```

### Development Branch
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/GEEKS-AD-Plus/dev/install.sh | bash
```

### Manual Installation
```bash
git clone https://github.com/yourusername/GEEKS-AD-Plus.git
cd GEEKS-AD-Plus
pip install -r requirements.txt
python app.py
```

## Features

### Core System
- ✅ **Web-based Password Reset Portal** - Secure interface for users to reset AD passwords
- ✅ **Active Directory Integration** - Direct LDAP connection with AD
- ✅ **Self-Updating System** - Automatic updates from GitHub with `run_forever.py`
- ✅ **Audit Logging** - Comprehensive logging of all actions and events
- ✅ **Bug Reporting System** - Built-in bug report collection with logs and system info

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

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- **Python**: 3.7 or higher
- **Active Directory**: Windows Server 2012 R2 or higher
- **Network**: Connectivity to AD domain controller
- **Permissions**: Domain user with appropriate AD permissions

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
├── app.py               # Main application entry point
├── run_forever.py       # Auto-update script
└── requirements.txt     # Python dependencies
```

## Support

- **Documentation**: See inline code comments and templates
- **Bug Reports**: Use the built-in bug reporting system at `/bug-report`
- **Admin Interface**: Access admin features at `/admin/login`
- **Logs**: Check `app/logs/` for application logs

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Version History

- **v1.0.0** - Initial release with core password reset functionality
- **v1.1.0** - Added admin management and audit logging
- **v1.2.0** - Added AD dashboard and Windows Credential Provider
- **v1.3.0** - Added bug reporting system and enhanced security



