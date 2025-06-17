# GEEKS Credential Provider

A Windows Credential Provider that integrates with the GEEKS-AD-Plus password reset portal. This credential provider adds a "Forgot Password?" tile to the Windows lock screen that launches a browser to the password reset portal.

## Features

- **Lock Screen Integration**: Adds a "Forgot Password?" tile to Windows lock screen
- **Browser Launch**: Opens the password reset portal in the default browser
- **Secure Implementation**: Follows Windows security best practices
- **Easy Deployment**: Includes PowerShell scripts for installation and Group Policy deployment

## Requirements

- **Visual Studio 2019 or later** with C++ development tools
- **Windows 10/11** or **Windows Server 2016/2019/2022**
- **Administrator privileges** for installation
- **GEEKS-AD-Plus portal** running and accessible

## Building

### Prerequisites
1. Install Visual Studio 2019 or later with C++ development tools
2. Ensure Windows SDK is installed
3. Open Developer Command Prompt for VS

### Build Steps
```cmd
cd windows-credential-provider
msbuild GEEKS-CredentialProvider.sln /p:Configuration=Release /p:Platform=x64
```

### Build Output
- `x64/Release/GEEKS-CredentialProvider.dll` - Main credential provider
- `x64/Release/GEEKS-CredentialProvider.reg` - Registry entries

## Installation

### Manual Installation
```powershell
# Run as Administrator
.\install.ps1
```

### Uninstallation
```powershell
# Run as Administrator
.\uninstall.ps1
```

## Group Policy Deployment

### Automatic Deployment
```powershell
# Run as Administrator
.\gpo-deploy.ps1 -DomainController "dc.yourdomain.com" -GPO "GEEKS-CredentialProvider"
```

### Manual GPO Setup
1. Open Group Policy Management Console
2. Create a new GPO named "GEEKS-CredentialProvider"
3. Edit the GPO and navigate to Computer Configuration > Policies > Windows Settings > Scripts > Startup
4. Add the `install.ps1` script
5. Link the GPO to target OUs

## Configuration

### Portal URL Configuration
The credential provider is configured to launch the portal at the default URL. To customize:

1. Edit `credentialprovider.cpp` and modify the `PORTAL_URL` constant
2. Rebuild the project
3. Redeploy to target machines

### Registry Configuration
The credential provider can be configured via registry:

```
HKEY_LOCAL_MACHINE\SOFTWARE\GEEKS\CredentialProvider
- PortalURL (REG_SZ): URL of the password reset portal
- Enabled (REG_DWORD): 1 to enable, 0 to disable
```

## Troubleshooting

### Common Issues

1. **Credential Provider Not Appearing**
   - Ensure the DLL is properly registered
   - Check Windows Event Logs for errors
   - Verify the credential provider is enabled in registry

2. **Browser Not Launching**
   - Check if the portal URL is accessible
   - Verify browser permissions on lock screen
   - Test URL manually from the target machine

3. **Installation Fails**
   - Run PowerShell as Administrator
   - Check execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`
   - Verify all files are present in the installation directory

### Event Logs
Check the following event logs for errors:
- Application Log
- System Log
- Security Log

### Debug Mode
Enable debug logging by setting the registry value:
```
HKEY_LOCAL_MACHINE\SOFTWARE\GEEKS\CredentialProvider\Debug = 1
```

## Security Considerations

- The credential provider runs in a secure context
- No sensitive information is stored locally
- Browser launch is sandboxed
- Registry modifications require administrator privileges

## Support

For issues and support:
1. Check the troubleshooting section above
2. Review Windows Event Logs
3. Use the bug reporting system in the GEEKS-AD-Plus portal
4. Contact GEEKS Technologies support

## Version History

- **v1.0.0** - Initial release with basic lock screen integration
- **v1.1.0** - Added Group Policy deployment support
- **v1.2.0** - Enhanced error handling and logging
- **v1.3.0** - Added configuration options and security improvements 